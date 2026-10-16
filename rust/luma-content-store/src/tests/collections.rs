use super::*;
use std::os::unix::fs::MetadataExt;

fn disk(path: &Path) -> BTreeMap<PathBuf, (u64, i64, i64, i64, i64, Vec<u8>)> {
    fn visit(path: &Path, result: &mut BTreeMap<PathBuf, (u64, i64, i64, i64, i64, Vec<u8>)>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        result.insert(
            path.into(),
            (
                metadata.ino(),
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
                visit(&entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(path, &mut result);
    result
}

fn source(id: &str, members: Vec<VersionReference>) -> CollectionSource {
    CollectionSource {
        schema_version: 1,
        kind: "luma-explicit-collection-v1".into(),
        collection_id: id.into(),
        name: format!("Collection {id}"),
        members,
    }
}

fn repository(f: &Fixture) -> Repository {
    let initial = capture("initial", "alpha", b"Original alpha");
    let mut repo = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    repo.apply(&initial, b"Original alpha", &mut Guard::write(&initial))
        .unwrap();
    repo
}

fn propose(
    repo: &Repository,
    request: &str,
    source: &CollectionSource,
    expected: Option<VersionReference>,
) -> Plan {
    let bytes = source.canonical_bytes().unwrap();
    repo.plan_collection(
        source,
        expected,
        provenance(request, &bytes, EditOrigin::External),
        &mut Guard::read(),
    )
    .unwrap()
}

fn publish(
    repo: &mut Repository,
    request: &str,
    source: &CollectionSource,
    expected: Option<VersionReference>,
) -> Outcome {
    let plan = propose(repo, request, source, expected);
    repo.apply_collection(
        &plan,
        &source.canonical_bytes().unwrap(),
        &mut Guard::write(&plan),
    )
    .unwrap()
}

#[test]
fn collections_are_typed_immutable_exact_sources_and_rebuild_without_an_index() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let member = repo.current_reference("alpha", &mut Guard::read()).unwrap();
    let source = source("work", vec![member.clone()]);
    let outcome = publish(&mut repo, "collection", &source, None);
    assert_eq!(outcome.source_kind, SourceKind::CollectionIntent);
    assert_eq!(outcome.decision, DecisionKind::Published);
    let retained = repo.retained("collection", &mut Guard::read()).unwrap();
    assert_eq!(retained.source, source.canonical_bytes().unwrap());
    assert_eq!(
        repo.current("collection.work", &mut Guard::read())
            .unwrap()
            .content(),
        retained.source
    );
    let collection = repo.collection_current("work", &mut Guard::read()).unwrap();
    assert_eq!(collection.reference, outcome.resulting);
    assert_eq!(collection.source, source);
    let memberships = repo
        .collections_for_member(&member, 0, 32, &mut Guard::read())
        .unwrap();
    assert_eq!(memberships.collections, vec![outcome.resulting.clone()]);
    drop(repo);
    let repo = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(
        repo.collection_current("work", &mut Guard::read()).unwrap(),
        collection
    );
    assert_eq!(
        repo.collections_for_member(&member, 0, 32, &mut Guard::read())
            .unwrap(),
        memberships
    );
    assert_eq!(
        repo.collection_page(&outcome.resulting, 0, 32, &mut Guard::read())
            .unwrap()
            .members,
        vec![member]
    );
}

#[test]
fn collection_edit_noop_conflict_and_exact_replay_use_existing_atomic_journal() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let original = source("work", vec![]);
    let first = publish(&mut repo, "first", &original, None);
    let mut changed = original.clone();
    changed.name = "Changed".into();
    let second = publish(&mut repo, "second", &changed, Some(first.resulting.clone()));
    assert_eq!(second.resulting.version, 2);
    let noop = propose(&repo, "noop", &changed, Some(second.resulting.clone()));
    assert_eq!(noop.decision(), DecisionKind::NoChangeRetained);
    let bytes = changed.canonical_bytes().unwrap();
    let applied = repo
        .apply_collection(&noop, &bytes, &mut Guard::write(&noop))
        .unwrap();
    let replay = repo
        .apply_collection(&noop, &bytes, &mut Guard::write(&noop))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(applied.sequence, replay.sequence);
    let mut stale = original.clone();
    stale.name = "Stale edit".into();
    let conflict = publish(&mut repo, "conflict", &stale, Some(first.resulting.clone()));
    assert_eq!(conflict.decision, DecisionKind::ConflictRetained);
    assert_eq!(
        repo.collection_current("work", &mut Guard::read())
            .unwrap()
            .source,
        changed
    );
    assert_eq!(
        repo.collection_page(&first.resulting, 0, 32, &mut Guard::read())
            .unwrap()
            .name,
        original.name
    );
    assert_eq!(repo.inventory(&mut Guard::read()).unwrap().len(), 5);
}

#[test]
fn membership_is_historical_not_latest_or_transitive_and_emptying_preserves_history() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let old = repo.current_reference("alpha", &mut Guard::read()).unwrap();
    let edit = repo
        .plan_external_edit(
            "alpha",
            old.clone(),
            b"New alpha",
            provenance("edit", b"New alpha", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let newer = repo
        .apply(&edit, b"New alpha", &mut Guard::write(&edit))
        .unwrap()
        .resulting;
    let first = publish(
        &mut repo,
        "first",
        &source("inner", vec![old.clone()]),
        None,
    );
    publish(
        &mut repo,
        "outer",
        &source("outer", vec![first.resulting.clone()]),
        None,
    );
    assert_eq!(
        repo.collections_for_member(&old, 0, 32, &mut Guard::read())
            .unwrap()
            .total_collections,
        1
    );
    assert_eq!(
        repo.collections_for_member(&newer, 0, 32, &mut Guard::read())
            .unwrap()
            .total_collections,
        0
    );
    publish(
        &mut repo,
        "empty",
        &source("inner", vec![]),
        Some(first.resulting.clone()),
    );
    assert_eq!(
        repo.collections_for_member(&old, 0, 32, &mut Guard::read())
            .unwrap()
            .total_collections,
        0
    );
    assert_eq!(
        repo.collection_page(&first.resulting, 0, 32, &mut Guard::read())
            .unwrap()
            .members,
        vec![old]
    );
}

#[test]
fn structural_contract_rejects_aliases_unknown_fields_and_ambiguous_members() {
    let good = source("work", vec![]);
    let bytes = good.canonical_bytes().unwrap();
    assert_eq!(CollectionSource::from_canonical(&bytes).unwrap(), good);
    let mut space = bytes.clone();
    space.push(b' ');
    assert!(CollectionSource::from_canonical(&space).is_err());
    let mut unknown = serde_json::to_value(&good).unwrap();
    unknown["authority"] = serde_json::json!(true);
    assert!(CollectionSource::from_canonical(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(CollectionSource::from_canonical(b"{\"collection_id\":\"work\",\"kind\":\"luma-explicit-collection-v1\",\"members\":[],\"name\":\"Collection work\",\"schema_version\":1,\"schema_version\":1}").is_err());
    for id in ["", "../work", "work.foo", "_work", " work", "a/b"] {
        assert!(source(id, vec![]).canonical_bytes().is_err());
    }
    for name in ["", " padded", "tail ", "bad\nname", "bad\u{0085}name"] {
        let mut bad = good.clone();
        bad.name = name.into();
        assert!(bad.canonical_bytes().is_err());
    }
    let mut bad = good.clone();
    bad.schema_version = 2;
    assert!(bad.canonical_bytes().is_err());
    bad = good.clone();
    bad.kind = "semantic-collection".into();
    assert!(bad.canonical_bytes().is_err());
    bad = good.clone();
    bad.name = "a".repeat(257);
    assert!(bad.canonical_bytes().is_err());
    bad = good;
    bad.collection_id = "a".repeat(65);
    assert!(bad.canonical_bytes().is_err());
    assert!(
        CollectionSource::from_canonical(&vec![b' '; MAX_COLLECTION_SOURCE_BYTES + 1]).is_err()
    );
}

#[test]
fn member_sort_duplicates_hashes_and_count_bounds_are_strict() {
    let reference = capture("source", "alpha", b"a").resulting().clone();
    assert!(source("work", vec![reference.clone(), reference.clone()])
        .canonical_bytes()
        .is_err());
    let mut beta = reference.clone();
    beta.artifact_id = "beta".into();
    assert!(source("work", vec![beta, reference.clone()])
        .canonical_bytes()
        .is_err());
    for index in 0..5 {
        let mut bad = reference.clone();
        match index {
            0 => bad.version = 0,
            1 => bad.content_sha256 = "0".repeat(64),
            2 => bad.receipt_sha256 = "G".repeat(64),
            3 => bad.artifact_id = "../alpha".into(),
            _ => bad.receipt_sha256 = "f".repeat(63),
        }
        assert!(source("work", vec![bad]).canonical_bytes().is_err());
    }
    let members: Vec<_> = (0..=64)
        .map(|index| {
            let mut member = reference.clone();
            member.artifact_id = format!("member-{index:03}");
            member
        })
        .collect();
    assert!(source("work", members[..64].to_vec())
        .canonical_bytes()
        .is_ok());
    assert!(source("work", members).canonical_bytes().is_err());
}

#[test]
fn chronological_validation_never_borrows_future_or_retained_candidate_authority() {
    let member = capture("member", "member", b"future content");
    let collection = source("work", vec![member.resulting().clone()]);
    let bytes = collection.canonical_bytes().unwrap();
    let proposal = Plan::collection(
        None,
        binding(),
        &collection,
        None,
        provenance("collection", &bytes, EditOrigin::External),
    )
    .unwrap();
    let mut history = crate::collections::CollectionHistory::new();
    assert!(history.observe(&proposal, &bytes, &mut || Ok(())).is_err());
    // A later real publication does not retroactively make the refused earlier
    // transition valid; reconstructing in sequence must refuse at that point.
    history
        .observe(&member, b"future content", &mut || Ok(()))
        .unwrap();
    history.observe(&proposal, &bytes, &mut || Ok(())).unwrap();
    let mut denied = crate::collections::CollectionHistory::new();
    let mut checks = 0;
    assert!(denied
        .observe(&member, b"future content", &mut || {
            checks += 1;
            Err("revoked before history processing".into())
        })
        .is_err());
    assert_eq!(checks, 1);
}

#[test]
fn forged_future_and_other_owner_members_are_refused_even_through_generic_apply() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let genuine = repo.current_reference("alpha", &mut Guard::read()).unwrap();
    for index in 0..5 {
        let mut bad = genuine.clone();
        match index {
            0 => bad.version += 1,
            1 => bad.artifact_id = "missing".into(),
            2 => bad.content_sha256 = "d".repeat(64),
            3 => bad.receipt_sha256 = "e".repeat(64),
            _ => {
                let mut owner = binding();
                owner.owner_generation += 1;
                bad = Plan::capture(
                    owner,
                    "alpha",
                    Format::Utf8Text,
                    b"Original alpha",
                    provenance("other-owner", b"Original alpha", EditOrigin::Managed),
                )
                .unwrap()
                .resulting()
                .clone();
            }
        }
        let source = source(&format!("bad{index}"), vec![bad]);
        let bytes = source.canonical_bytes().unwrap();
        let prov = provenance(&format!("bad{index}"), &bytes, EditOrigin::External);
        assert!(repo
            .plan_collection(&source, None, prov.clone(), &mut Guard::read())
            .is_err());
        // Even bypassing the convenience method cannot publish schema-4
        // invalid members through ordinary Repository::apply.
        let plan = Plan::collection(None, binding(), &source, None, prov).unwrap();
        assert!(repo.apply(&plan, &bytes, &mut Guard::write(&plan)).is_err());
    }
    assert_eq!(repo.inventory(&mut Guard::read()).unwrap().len(), 1);
}

#[test]
fn retained_conflict_candidate_is_never_a_member_version() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let first = repo.current("alpha", &mut Guard::read()).unwrap();
    let base = first.reference().unwrap();
    let edit = repo
        .plan_external_edit(
            "alpha",
            base.clone(),
            b"second",
            provenance("second", b"second", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repo.apply(&edit, b"second", &mut Guard::write(&edit))
        .unwrap();
    let candidate = match luma_content::compare_external_edit(
        &repo.current("alpha", &mut Guard::read()).unwrap(),
        &base,
        &binding(),
        b"candidate",
        provenance("conflict", b"candidate", EditOrigin::External),
    )
    .unwrap()
    {
        luma_content::EditDecision::Conflict { candidate, .. } => candidate,
        _ => panic!("expected retained conflict"),
    };
    let conflict = repo
        .plan_external_edit(
            "alpha",
            base,
            b"candidate",
            provenance("conflict", b"candidate", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repo.apply(&conflict, b"candidate", &mut Guard::write(&conflict))
        .unwrap();
    let bytes = serde_json::to_value(candidate).unwrap();
    let mut fake = first.reference().unwrap();
    fake.content_sha256 = bytes["content_sha256"].as_str().unwrap().into();
    let source = source("bad", vec![fake]);
    let bytes = source.canonical_bytes().unwrap();
    assert!(repo
        .plan_collection(
            &source,
            None,
            provenance("bad", &bytes, EditOrigin::External),
            &mut Guard::read()
        )
        .is_err());
}

#[test]
fn generic_json_names_do_not_create_or_poison_typed_collections() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let bytes = b"not a collection";
    let generic = capture("ordinary", "collection.fake", bytes);
    repo.apply(&generic, bytes, &mut Guard::write(&generic))
        .unwrap();
    assert!(repo.collection_current("fake", &mut Guard::read()).is_err());
    let genuine = publish(&mut repo, "genuine", &source("real", vec![]), None);
    assert_eq!(
        repo.collection_current("real", &mut Guard::read())
            .unwrap()
            .reference,
        genuine.resulting
    );
    let bytes = source("fake", vec![]).canonical_bytes().unwrap();
    assert!(repo
        .plan_collection(
            &source("fake", vec![]),
            None,
            provenance("collision", &bytes, EditOrigin::External),
            &mut Guard::read()
        )
        .is_err());
    let overwrite = repo
        .plan_external_edit(
            "collection.real",
            genuine.resulting.clone(),
            b"{}",
            provenance("overwrite", b"{}", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    assert!(repo
        .apply(&overwrite, b"{}", &mut Guard::write(&overwrite))
        .is_err());
    assert_eq!(
        repo.collection_current("real", &mut Guard::read())
            .unwrap()
            .reference,
        genuine.resulting
    );
}

#[test]
fn collection_paging_is_exact_bounded_and_reverse_queries_are_sorted() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let alpha = repo.current_reference("alpha", &mut Guard::read()).unwrap();
    for id in ["zulu", "bravo", "alpha"] {
        publish(
            &mut repo,
            &format!("collection-{id}"),
            &source(id, vec![alpha.clone()]),
            None,
        );
    }
    let first = repo
        .collections_for_member(&alpha, 0, 2, &mut Guard::read())
        .unwrap();
    assert_eq!(
        first
            .collections
            .iter()
            .map(|r| r.artifact_id.as_str())
            .collect::<Vec<_>>(),
        vec!["collection.alpha", "collection.bravo"]
    );
    assert_eq!(first.next_offset, Some(2));
    assert_eq!(first.total_collections, 3);
    let second = repo
        .collections_for_member(&alpha, 2, 2, &mut Guard::read())
        .unwrap();
    assert_eq!(second.collections[0].artifact_id, "collection.zulu");
    assert_eq!(second.next_offset, None);
    let current = repo
        .collection_current("alpha", &mut Guard::read())
        .unwrap();
    assert_eq!(
        repo.collection_page(&current.reference, 1, 32, &mut Guard::read())
            .unwrap()
            .members,
        vec![]
    );
    for (offset, limit) in [(2, 1), (0, 0), (0, 33), (257, 1), (usize::MAX, 32)] {
        assert!(repo
            .collection_page(&current.reference, offset, limit, &mut Guard::read())
            .is_err());
    }
    for (offset, limit) in [(4, 1), (0, 0), (0, 33), (usize::MAX, 1)] {
        assert!(repo
            .collections_for_member(&alpha, offset, limit, &mut Guard::read())
            .is_err());
    }
    let mut forged = current.reference.clone();
    forged.receipt_sha256 = "f".repeat(64);
    assert!(repo
        .collection_page(&forged, 0, 32, &mut Guard::read())
        .is_err());
    assert!(repo
        .collections_for_member(&forged, 0, 32, &mut Guard::read())
        .is_err());
}

#[test]
fn collection_mutation_refuses_changed_source_base_owner_and_provenance() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let initial = source("work", vec![]);
    let first = publish(&mut repo, "first", &initial, None);
    let mut changed = initial.clone();
    changed.name = "Changed".into();
    let proposal = propose(&repo, "edit", &changed, Some(first.resulting.clone()));
    assert!(repo
        .apply_collection(
            &proposal,
            &initial.canonical_bytes().unwrap(),
            &mut Guard::write(&proposal)
        )
        .is_err());
    let mut forged = first.resulting.clone();
    forged.receipt_sha256 = "d".repeat(64);
    let bytes = changed.canonical_bytes().unwrap();
    assert!(repo
        .plan_collection(
            &changed,
            Some(forged),
            provenance("forged", &bytes, EditOrigin::External),
            &mut Guard::read()
        )
        .is_err());
    assert!(repo
        .plan_collection(
            &changed,
            Some(first.resulting.clone()),
            provenance("managed", &bytes, EditOrigin::Managed),
            &mut Guard::read()
        )
        .is_err());
    let mut wrong = Guard::read();
    wrong.binding.owner_generation += 1;
    assert!(repo.collection_current("work", &mut wrong).is_err());
    let mut other = changed.clone();
    other.name = "Concurrent".into();
    publish(&mut repo, "concurrent", &other, Some(first.resulting));
    assert!(repo
        .apply_collection(&proposal, &bytes, &mut Guard::write(&proposal))
        .is_err());
}

#[test]
fn empty_initial_collection_can_create_repo_but_nonempty_capture_cannot() {
    let f = Fixture::new();
    let initial = source("initial", vec![]);
    let bytes = initial.canonical_bytes().unwrap();
    let plan = Plan::collection_capture(
        binding(),
        &initial,
        provenance("first", &bytes, EditOrigin::External),
    )
    .unwrap();
    let mut repo = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    repo.apply_collection(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    assert_eq!(
        repo.collection_current("initial", &mut Guard::read())
            .unwrap()
            .source,
        initial
    );
    let reference = capture("member", "member", b"a").resulting().clone();
    let nonempty = source("nonempty", vec![reference]);
    let bytes = nonempty.canonical_bytes().unwrap();
    assert!(Plan::collection_capture(
        binding(),
        &nonempty,
        provenance("nonempty", &bytes, EditOrigin::External)
    )
    .is_err());
}

#[test]
fn every_read_and_write_boundary_can_refuse_without_committing_or_mutating() {
    let f = Fixture::new();
    let mut repo = repository(&f);
    let alpha = repo.current_reference("alpha", &mut Guard::read()).unwrap();
    let collection = source("work", vec![alpha.clone()]);
    let plan = propose(&repo, "collection", &collection, None);
    let bytes = collection.canonical_bytes().unwrap();
    let mut revoked = Guard::write(&plan);
    revoked.refuse_at = 4;
    assert!(repo.apply_collection(&plan, &bytes, &mut revoked).is_err());
    assert_eq!(repo.inventory(&mut Guard::read()).unwrap().len(), 1);
    repo.apply_collection(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    let current = repo.collection_current("work", &mut Guard::read()).unwrap();
    let before = disk(&f.path);
    for operation in 0..3 {
        let mut guard = Guard::read();
        guard.refuse_at = 4;
        let refused = match operation {
            0 => repo.collection_current("work", &mut guard).is_err(),
            1 => repo
                .collection_page(&current.reference, 0, 32, &mut guard)
                .is_err(),
            _ => repo
                .collections_for_member(&alpha, 0, 32, &mut guard)
                .is_err(),
        };
        assert!(refused);
    }
    let mut no_budget = Guard::read();
    no_budget.refuse_resources = true;
    assert!(repo.collection_current("work", &mut no_budget).is_err());
    assert_eq!(before, disk(&f.path));
}
