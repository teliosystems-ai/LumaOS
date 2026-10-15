use super::*;
use luma_content::table::{EditMetadata, Operation, TableEditRequest};

fn initial(f: &Fixture) -> (Repository, Outcome) {
    let bytes = b"name,value\r\na,1\r\n";
    let plan = Plan::capture(
        binding(),
        "table",
        Format::Csv,
        bytes,
        provenance("initial", bytes, EditOrigin::Managed),
    )
    .unwrap();
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    let first = store.apply(&plan, bytes, &mut Guard::write(&plan)).unwrap();
    (store, first)
}

fn edit(reference: VersionReference, request: &str, value: &str) -> TableEditRequest {
    TableEditRequest {
        binding: binding(),
        expected: reference,
        metadata: EditMetadata {
            request_id: request.into(),
            workflow_sha256: "e".repeat(64),
        },
        operations: vec![Operation::SetCell {
            row: 1,
            column: 1,
            value: value.into(),
        }],
    }
}

#[test]
fn managed_intent_and_generated_csv_have_separate_exact_provenance() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let request = edit(first.resulting, "managed", "2");
    let source = request.canonical_bytes().unwrap();
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    assert_eq!(plan.source_kind(), SourceKind::ManagedTableIntent);
    assert_eq!(plan.source_bytes(), source.len() as u64);
    assert_eq!(
        plan.storage_bytes(),
        source.len() as u64 + plan.payload.len() as u64 + MAX_RECORD
    );
    assert!(store
        .apply(&plan, b"name,value\na,2\n", &mut Guard::write(&plan))
        .is_err());
    let result = store
        .apply(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    assert_eq!(result.resulting.version, 2);
    assert_eq!(result.source_kind, SourceKind::ManagedTableIntent);
    let retained = store.retained("managed", &mut Guard::read()).unwrap();
    assert_eq!(retained.source, source);
    let version = luma_content::reopen(&retained.payload, &binding()).unwrap();
    assert_eq!(version.content(), b"name,value\na,2\n");
    assert_eq!(
        version.receipt().provenance.source_sha256,
        luma_content::sha256(version.content())
    );
    assert_ne!(
        version.receipt().provenance.source_sha256,
        result.source_sha256
    );
    drop(store);
    let store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(
        store.retained("managed", &mut Guard::read()).unwrap(),
        retained
    );
    let legacy = fs::read(
        f.root(&binding())
            .join("outcomes")
            .join(luma_content::sha256(b"initial"))
            .join("record.json"),
    )
    .unwrap();
    assert!(!String::from_utf8(legacy).unwrap().contains("source_kind"));
}

#[test]
fn stale_positional_intent_is_retained_without_running_invalid_current_positions() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let newer = edit(first.resulting.clone(), "newer", "2");
    let plan = store.plan_table_edit(&newer, &mut Guard::read()).unwrap();
    let latest = store
        .apply(
            &plan,
            &newer.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    let mut stale = edit(first.resulting, "stale", "3");
    // Valid globally bounded position, nonexistent in this two-row table.
    stale.operations = vec![Operation::DeleteRow { index: 9999 }];
    let plan = store.plan_table_edit(&stale, &mut Guard::read()).unwrap();
    assert_eq!(plan.decision(), DecisionKind::ConflictRetained);
    store
        .apply(
            &plan,
            &stale.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    assert_eq!(
        store
            .current("table", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        latest.resulting
    );
    assert_eq!(
        store.retained("stale", &mut Guard::read()).unwrap().source,
        stale.canonical_bytes().unwrap()
    );
    drop(store);
    let store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 3);
}

#[test]
fn managed_no_change_retains_intent_without_advancing_version() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let request = edit(first.resulting.clone(), "same", "1");
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    assert_eq!(plan.decision(), DecisionKind::NoChangeRetained);
    let result = store
        .apply(
            &plan,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    assert_eq!(result.resulting, first.resulting);
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 2);
    assert_eq!(
        store.retained("same", &mut Guard::read()).unwrap().source,
        request.canonical_bytes().unwrap()
    );
}

#[test]
fn managed_every_durable_phase_resumes_or_replays_one_outcome() {
    for fail_at in 1..=6 {
        let f = Fixture::new();
        let (mut store, first) = initial(&f);
        let request = edit(first.resulting, "managed", "2");
        let source = request.canonical_bytes().unwrap();
        let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
        let mut observed = 0;
        assert!(store
            .apply_with_hook(&plan, &source, &mut Guard::write(&plan), |_| {
                observed += 1;
                if observed == fail_at {
                    Err("fixture interrupted".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(store);
        let mut store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
        assert_eq!(
            store.inventory(&mut Guard::read()).unwrap().len(),
            1 + usize::from(fail_at >= 5)
        );
        let result = store
            .apply(&plan, &source, &mut Guard::write(&plan))
            .unwrap();
        assert_eq!(result.replayed, fail_at >= 5);
        assert_eq!(result.resulting.version, 2);
        assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 2);
    }
}

#[test]
fn managed_proposal_refuses_concurrent_version_and_conflicting_replay() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let request = edit(first.resulting.clone(), "managed", "2");
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    let newer = edit(first.resulting, "newer", "3");
    let newer_plan = store.plan_table_edit(&newer, &mut Guard::read()).unwrap();
    store
        .apply(
            &newer_plan,
            &newer.canonical_bytes().unwrap(),
            &mut Guard::write(&newer_plan),
        )
        .unwrap();
    assert!(store
        .apply(
            &plan,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&plan)
        )
        .is_err());
    let conflict = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    assert_eq!(conflict.decision(), DecisionKind::ConflictRetained);
    store
        .apply(
            &conflict,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&conflict),
        )
        .unwrap();
    assert!(store
        .apply(
            &plan,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&plan)
        )
        .is_err());
    assert!(store
        .apply(&conflict, b"{}", &mut Guard::write(&conflict))
        .is_err());
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 3);
}

#[test]
fn managed_every_authorization_checkpoint_refuses_or_leaves_exact_committed_outcome() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let request = edit(first.resulting, "count", "2");
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    let mut guard = Guard::write(&plan);
    store
        .apply(&plan, &request.canonical_bytes().unwrap(), &mut guard)
        .unwrap();
    let checks = guard.checks;
    drop(store);
    for refuse_at in 1..=checks {
        let f = Fixture::new();
        let (mut store, first) = initial(&f);
        let request = edit(first.resulting, "count", "2");
        let source = request.canonical_bytes().unwrap();
        let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
        let mut guard = Guard::write(&plan);
        guard.refuse_at = refuse_at;
        assert!(store.apply(&plan, &source, &mut guard).is_err());
        drop(store);
        let mut store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
        let inventory = store.inventory(&mut Guard::read()).unwrap();
        assert!(inventory.len() == 1 || inventory.len() == 2);
        if inventory.len() == 2 {
            assert_eq!(
                store.retained("count", &mut Guard::read()).unwrap().source,
                source
            );
            assert!(
                store
                    .apply(&plan, &source, &mut Guard::write(&plan))
                    .unwrap()
                    .replayed
            );
        }
    }
}

#[test]
fn managed_intent_larger_than_content_bound_survives_reconstruction() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let mut request = edit(first.resulting, "large-intent", "2");
    request.operations = (0..luma_content::table::MAX_OPERATIONS)
        .map(|_| Operation::SetCell {
            row: 1,
            column: 1,
            value: "\"".repeat(luma_content::MAX_CSV_FIELD_BYTES),
        })
        .collect();
    let source = request.canonical_bytes().unwrap();
    assert!(source.len() > luma_content::MAX_CONTENT_BYTES);
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    assert!(plan.storage_bytes() < 24 * 1024 * 1024);
    store
        .apply(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    drop(store);
    let store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(
        store
            .retained("large-intent", &mut Guard::read())
            .unwrap()
            .source,
        source
    );
}

#[test]
fn managed_record_schema_downgrade_and_resealed_intent_substitution_are_refused() {
    for downgrade in [true, false] {
        let f = Fixture::new();
        let (mut store, first) = initial(&f);
        let request = edit(first.resulting, "managed", "2");
        let source = request.canonical_bytes().unwrap();
        let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
        store
            .apply(&plan, &source, &mut Guard::write(&plan))
            .unwrap();
        drop(store);
        let directory = f
            .root(&binding())
            .join("outcomes")
            .join(luma_content::sha256(b"managed"));
        let record_path = directory.join("record.json");
        let mut record: Record = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        if downgrade {
            record.schema_version = 1;
            record.plan.schema_version = 1;
            record.plan.source_kind = None;
        } else {
            let mut changed = request.clone();
            changed.operations = vec![Operation::SetCell {
                row: 1,
                column: 1,
                value: "3".into(),
            }];
            let changed_source = changed.canonical_bytes().unwrap();
            let source_path = directory.join("source.bin");
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&source_path, &changed_source).unwrap();
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o400)).unwrap();
            record.plan.source_sha256 = luma_content::sha256(&changed_source);
            record.plan.source_bytes = changed_source.len() as u64;
            record.plan.provenance.source_sha256 = record.plan.source_sha256.clone();
        }
        // Recomputing the untrusted hash cannot substitute another operation for
        // the existing resulting version in append-only reconstruction.
        record.review_sha256 = luma_content::sha256(&serde_json::to_vec(&record.plan).unwrap());
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(Repository::open_at(&f.path, &binding(), &mut Guard::read()).is_err());
    }
}

#[test]
fn reconstructed_replay_plan_is_exact_input_data_not_fresh_mutation_authority() {
    let f = Fixture::new();
    let (mut store, first) = initial(&f);
    let request = edit(first.resulting, "managed", "2");
    let source = request.canonical_bytes().unwrap();
    assert!(store
        .replay_plan("managed", &source, &mut Guard::read())
        .unwrap()
        .is_none());
    let plan = store.plan_table_edit(&request, &mut Guard::read()).unwrap();
    store
        .apply(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    let replay = store
        .replay_plan("managed", &source, &mut Guard::read())
        .unwrap()
        .unwrap();
    assert_eq!(replay, plan);
    assert_eq!(replay.artifact_id(), "table");
    assert_eq!(replay.format(), Format::Csv);
    assert_eq!(replay.expected(), Some(&request.expected));
    assert_eq!(replay.provenance().request_id, request.metadata.request_id);
    assert!(store.apply(&replay, &source, &mut Guard::read()).is_err());
    assert!(store
        .replay_plan("managed", b"{}", &mut Guard::read())
        .is_err());
    let mut revoked = Guard::read();
    revoked.refuse_at = 1;
    assert!(store.replay_plan("managed", &source, &mut revoked).is_err());
    let replayed = store
        .apply(&replay, &source, &mut Guard::write(&replay))
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 2);
    let next = edit(replayed.resulting.clone(), "later", "3");
    let next_plan = store.plan_table_edit(&next, &mut Guard::read()).unwrap();
    let later = store
        .apply(
            &next_plan,
            &next.canonical_bytes().unwrap(),
            &mut Guard::write(&next_plan),
        )
        .unwrap();
    assert_eq!(later.resulting.version, 3);
    let historical = store
        .replay_plan("managed", &source, &mut Guard::read())
        .unwrap()
        .unwrap();
    let historical_outcome = store
        .apply(&historical, &source, &mut Guard::write(&historical))
        .unwrap();
    assert!(historical_outcome.replayed);
    assert_eq!(historical_outcome.resulting.version, 2);
    assert_eq!(
        store
            .current("table", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        later.resulting
    );
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 3);
}
