use super::*;
use std::os::unix::fs::MetadataExt;

fn publish(store: &mut Repository, request: &str, artifact: &str, bytes: &[u8]) -> Outcome {
    let plan = capture(request, artifact, bytes);
    store.apply(&plan, bytes, &mut Guard::write(&plan)).unwrap()
}

fn external(
    store: &mut Repository,
    request: &str,
    expected: VersionReference,
    bytes: &[u8],
) -> Outcome {
    let plan = store
        .plan_external_edit(
            &expected.artifact_id,
            expected.clone(),
            bytes,
            provenance(request, bytes, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    store.apply(&plan, bytes, &mut Guard::write(&plan)).unwrap()
}

fn repository(f: &Fixture) -> Repository {
    let plan = capture("initial", "alpha", b"Alpha fox FOX, beta.");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    store
        .apply(&plan, b"Alpha fox FOX, beta.", &mut Guard::write(&plan))
        .unwrap();
    store
}

type Disk = BTreeMap<PathBuf, (u32, i64, i64, i64, i64, Vec<u8>)>;

fn disk(path: &Path) -> Disk {
    fn visit(base: &Path, path: &Path, result: &mut Disk) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        result.insert(
            path.strip_prefix(base).unwrap().into(),
            (
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                if metadata.is_file() {
                    fs::read(path).unwrap()
                } else {
                    Vec::new()
                },
            ),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(base, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(path, path, &mut result);
    result
}

#[test]
fn exact_historical_versions_survive_newer_conflict_and_no_change_outcomes() {
    let f = Fixture::new();
    let mut store = repository(&f);
    let first = store
        .current_reference("alpha", &mut Guard::read())
        .unwrap();
    let second = external(&mut store, "second", first.clone(), b"Current delta");
    let conflict = external(&mut store, "conflict", first.clone(), b"Secret candidate");
    assert_eq!(conflict.decision, DecisionKind::ConflictRetained);
    let unchanged = external(
        &mut store,
        "unchanged",
        second.resulting.clone(),
        b"Current delta",
    );
    assert_eq!(unchanged.decision, DecisionKind::NoChangeRetained);
    assert_eq!(
        store
            .historical(&first, &mut Guard::read())
            .unwrap()
            .content(),
        b"Alpha fox FOX, beta."
    );
    assert_eq!(
        store
            .historical(&second.resulting, &mut Guard::read())
            .unwrap()
            .content(),
        b"Current delta"
    );
    assert_eq!(
        store
            .search("fox", 64, &mut Guard::read())
            .unwrap()
            .total_matches,
        0
    );
    assert_eq!(
        store
            .search("candidate", 64, &mut Guard::read())
            .unwrap()
            .total_matches,
        0
    );
    let result = store
        .search("DELTA current", 64, &mut Guard::read())
        .unwrap();
    assert_eq!(result.total_matches, 1);
    assert_eq!(result.matches[0].reference, second.resulting);
    drop(store);
    let reopened = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(
        reopened
            .search("current delta", 64, &mut Guard::read())
            .unwrap(),
        result
    );
    assert_eq!(
        reopened
            .historical(&first, &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        first
    );
}

#[test]
fn historical_lookup_refuses_every_reference_substitution_and_never_falls_back() {
    let f = Fixture::new();
    let store = repository(&f);
    let reference = store
        .current_reference("alpha", &mut Guard::read())
        .unwrap();
    for index in 0..7 {
        let mut wrong = reference.clone();
        match index {
            0 => wrong.artifact_id = "other".into(),
            1 => wrong.version = 0,
            2 => wrong.version = 2,
            3 => wrong.content_sha256 = "d".repeat(64),
            4 => wrong.receipt_sha256 = "e".repeat(64),
            5 => wrong.content_sha256 = wrong.content_sha256.to_ascii_uppercase(),
            _ => wrong.receipt_sha256.push('\n'),
        }
        assert!(store.historical(&wrong, &mut Guard::read()).is_err());
    }
    assert!(store.current("ALPHA", &mut Guard::read()).is_err());
    assert!(store.current("../alpha", &mut Guard::read()).is_err());
}

#[test]
fn search_aliases_whole_words_first_offsets_and_order_are_deterministic() {
    let f = Fixture::new();
    let mut store = repository(&f);
    publish(&mut store, "last", "zeta", b"fox beta");
    publish(&mut store, "middle", "middle", b"beta fox");
    publish(
        &mut store,
        "substring",
        "substring",
        b"foxes betamax beta_fox caf\xc3\xa9",
    );
    let full = store.search("fox beta", 64, &mut Guard::read()).unwrap();
    assert_eq!(full.canonical_query, "beta fox");
    assert_eq!(full.total_matches, 3);
    assert!(!full.truncated);
    assert_eq!(
        full.matches
            .iter()
            .map(|h| h.reference.artifact_id.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "middle", "zeta"]
    );
    assert_eq!(
        full.matches[0].terms,
        vec![
            TermMatch {
                term: "beta".into(),
                byte_offset: 15,
                byte_length: 4
            },
            TermMatch {
                term: "fox".into(),
                byte_offset: 6,
                byte_length: 3
            },
        ]
    );
    for alias in ["BETA FOX", "\t fox  beta\r\n", "fox beta fox"] {
        assert_eq!(store.search(alias, 64, &mut Guard::read()).unwrap(), full);
    }
    let limited = store.search("fox beta", 1, &mut Guard::read()).unwrap();
    assert_eq!(limited.total_matches, 3);
    assert!(limited.truncated);
    assert_eq!(limited.matches, full.matches[..1]);
    for query in ["caf", "fo", "betafox", "missing beta"] {
        assert!(store
            .search(query, 64, &mut Guard::read())
            .unwrap()
            .matches
            .is_empty());
    }
}

#[test]
fn invalid_queries_are_rejected_before_private_io_or_resource_admission() {
    let f = Fixture::new();
    let store = repository(&f);
    let oversized = "a".repeat(MAX_SEARCH_QUERY_BYTES + 1);
    let long_term = "a".repeat(MAX_SEARCH_TERM_BYTES + 1);
    for query in [
        "",
        "  \t\r\n",
        "a*",
        "a_b",
        "a-b",
        "a|b",
        "\0",
        "é",
        "a a a a a a a a a",
        &oversized,
        &long_term,
    ] {
        let mut guard = Guard::read();
        assert!(store.search(query, 1, &mut guard).is_err(), "{query:?}");
        assert_eq!((guard.admissions, guard.checks), (0, 0));
    }
    for limit in [0, MAX_SEARCH_RESULTS + 1, usize::MAX] {
        let mut guard = Guard::read();
        assert!(store.search("fox", limit, &mut guard).is_err());
        assert_eq!((guard.admissions, guard.checks), (0, 0));
    }
    assert!(canonical_search_query(&"a".repeat(MAX_SEARCH_TERM_BYTES), 64).is_ok());
    assert!(canonical_search_query("a b c d e f g h", 64).is_ok());
}

#[test]
fn empty_owner_repository_and_failed_reads_do_not_create_or_repair_any_state() {
    let f = Fixture::new();
    let initial = capture("empty", "unused", b"");
    let store = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    let before = disk(&f.path);
    assert_eq!(
        store.search("a", 1, &mut Guard::read()).unwrap(),
        SearchResults {
            canonical_query: "a".into(),
            matches: vec![],
            total_matches: 0,
            truncated: false,
        }
    );
    assert!(store.current("unused", &mut Guard::read()).is_err());
    assert!(store
        .historical(initial.resulting(), &mut Guard::read())
        .is_err());
    assert_eq!(disk(&f.path), before);
}

#[test]
fn search_and_historical_reads_remain_byte_for_byte_read_only_after_rebuild() {
    let f = Fixture::new();
    let store = repository(&f);
    let reference = store
        .current_reference("alpha", &mut Guard::read())
        .unwrap();
    drop(store);
    let before = disk(&f.path);
    let store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    store.current("alpha", &mut Guard::read()).unwrap();
    store.historical(&reference, &mut Guard::read()).unwrap();
    store.search("fox", 1, &mut Guard::read()).unwrap();
    assert_eq!(disk(&f.path), before);
}

#[test]
fn revocation_at_every_read_compute_and_delivery_checkpoint_refuses_all_output() {
    let f = Fixture::new();
    let store = repository(&f);
    let reference = store
        .current_reference("alpha", &mut Guard::read())
        .unwrap();
    let before = disk(&f.path);
    for historical in [false, true] {
        let mut baseline = Guard::read();
        if historical {
            store.historical(&reference, &mut baseline).unwrap();
        } else {
            store.search("fox", 1, &mut baseline).unwrap();
        }
        for refuse_at in 1..=baseline.checks {
            let mut guard = Guard::read();
            guard.refuse_at = refuse_at;
            if historical {
                assert!(store.historical(&reference, &mut guard).is_err());
            } else {
                assert!(store.search("fox", 1, &mut guard).is_err());
            }
        }
    }
    assert_eq!(disk(&f.path), before);
}

#[test]
fn all_history_integrity_is_required_even_when_limit_is_already_satisfied() {
    let f = Fixture::new();
    let mut store = repository(&f);
    publish(&mut store, "unrelated", "zeta", b"Not matching");
    let source = f
        .root(&binding())
        .join("outcomes")
        .join(luma_content::sha256(b"unrelated"))
        .join("source.bin");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&source, b"Corrupted source").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
    let before = disk(&f.path);
    let reference = store.inventory(&mut Guard::read());
    assert!(reference.is_err());
    assert!(store.search("fox", 1, &mut Guard::read()).is_err());
    assert!(store.current("alpha", &mut Guard::read()).is_err());
    assert_eq!(disk(&f.path), before);
}

#[test]
fn no_query_can_cross_owner_generation_or_bypass_resource_refusal() {
    let f = Fixture::new();
    let store = repository(&f);
    let reference = store
        .current_reference("alpha", &mut Guard::read())
        .unwrap();
    let mut wrong = Guard::read();
    wrong.binding.owner_generation += 1;
    assert!(store.search("fox", 1, &mut wrong).is_err());
    assert!(store.historical(&reference, &mut wrong).is_err());
    let mut exhausted = Guard::read();
    exhausted.refuse_resources = true;
    assert!(store.search("fox", 1, &mut exhausted).is_err());
    assert!(store.historical(&reference, &mut exhausted).is_err());
    assert_eq!(exhausted.checks, 0);
}

#[test]
fn another_owner_namespace_is_never_enumerated_opened_or_used_as_fallback() {
    let f = Fixture::new();
    let store = repository(&f);
    let mut other = binding();
    other.owner = "f".repeat(64);
    std::os::unix::fs::symlink("/proc", f.root(&other)).unwrap();
    let result = store.search("fox", 1, &mut Guard::read()).unwrap();
    assert_eq!(result.total_matches, 1);
    assert!(store.current("foreign", &mut Guard::read()).is_err());
    assert!(fs::symlink_metadata(f.root(&other))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn response_byte_budget_keeps_a_deterministic_prefix_with_exact_total() {
    let f = Fixture::new();
    let query = (0..8)
        .map(|index| format!("{}{index}", "x".repeat(if index == 7 { 31 } else { 30 })))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(query.len(), MAX_SEARCH_QUERY_BYTES);
    // Six-digit offsets and maximum-length artifact IDs make the full 64-hit
    // response exceed 64KiB. Small offsets would legitimately fit all 64 hits.
    // 64 retained 100256-byte source/payload pairs remain within the 64MiB store.
    let content = format!("{}{query}", " ".repeat(100_000));
    let bytes = content.as_bytes();
    let artifact = |index| format!("{index:03}{}", "a".repeat(125));
    let initial = capture("document0", &artifact(0), bytes);
    let mut store = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    store
        .apply(&initial, bytes, &mut Guard::write(&initial))
        .unwrap();
    for index in 1..64 {
        publish(
            &mut store,
            &format!("document{index}"),
            &artifact(index),
            bytes,
        );
    }
    let result = store.search(&query, 64, &mut Guard::read()).unwrap();
    assert_eq!(result.total_matches, 64);
    assert!(result.truncated);
    assert!(!result.matches.is_empty());
    assert!(result.matches.len() < 64);
    let mut complete = result.clone();
    let mut all_matches = result.matches.clone();
    for index in all_matches.len()..64 {
        let mut hit = all_matches[0].clone();
        hit.reference = store
            .current_reference(&artifact(index), &mut Guard::read())
            .unwrap();
        all_matches.push(hit);
    }
    complete.matches = all_matches;
    complete.truncated = false;
    assert!(serde_json::to_vec(&complete).unwrap().len() > MAX_SEARCH_RESPONSE_BYTES);
    assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_SEARCH_RESPONSE_BYTES);
    for (index, hit) in result.matches.iter().enumerate() {
        assert_eq!(hit.reference.artifact_id, artifact(index));
        assert_eq!(hit.terms.len(), 8);
    }
    let small = store.search(&query, 32, &mut Guard::read()).unwrap();
    assert_eq!(small.matches, result.matches[..32]);
    assert_eq!(small.total_matches, 64);
    assert!(small.truncated);
}

#[test]
fn managed_schema_two_publications_are_historical_versions_not_intent_text() {
    use luma_content::table::{EditMetadata, Operation, TableEditRequest};
    let f = Fixture::new();
    let bytes = b"name,value\nfox,first\n";
    let initial = Plan::capture(
        binding(),
        "table",
        Format::Csv,
        bytes,
        provenance("table", bytes, EditOrigin::Managed),
    )
    .unwrap();
    let mut store = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    let first = store
        .apply(&initial, bytes, &mut Guard::write(&initial))
        .unwrap();
    let request = TableEditRequest {
        binding: binding(),
        expected: first.resulting.clone(),
        metadata: EditMetadata {
            request_id: "managed".into(),
            workflow_sha256: "d".repeat(64),
        },
        operations: vec![Operation::SetCell {
            row: 1,
            column: 1,
            value: "second".into(),
        }],
    };
    let intent = request.canonical_bytes().unwrap();
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    let second = store
        .apply(&plan, &intent, &mut Guard::write(&plan))
        .unwrap();
    assert_eq!(
        store
            .historical(&first.resulting, &mut Guard::read())
            .unwrap()
            .content(),
        bytes
    );
    assert_eq!(
        store
            .historical(&second.resulting, &mut Guard::read())
            .unwrap()
            .content(),
        b"name,value\nfox,second\n"
    );
    assert_eq!(
        store
            .search("fox second", 1, &mut Guard::read())
            .unwrap()
            .matches[0]
            .reference,
        second.resulting
    );
    for term in ["managed", "set", "operations", "first"] {
        assert_eq!(
            store
                .search(term, 1, &mut Guard::read())
                .unwrap()
                .total_matches,
            0
        );
    }
}
