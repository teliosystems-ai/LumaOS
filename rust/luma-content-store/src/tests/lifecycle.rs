use super::*;
use serde_json::json;

fn repository() -> (Fixture, Repository, Plan) {
    let f = Fixture::new();
    let plan = capture("first", "document", b"private original");
    let mut repo = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    repo.apply(&plan, b"private original", &mut Guard::write(&plan))
        .unwrap();
    (f, repo, plan)
}
fn request(repo: &Repository, id: &str, operation: LifecycleOperation) -> LifecycleRequest {
    LifecycleRequest {
        schema_version: 1,
        binding: binding(),
        request_id: id.into(),
        workflow_sha256: "c".repeat(64),
        expected: repo
            .lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        operation,
        retention: RetentionPolicy::UntilExplicitRestoreNoPurge,
    }
}
fn execute(repo: &mut Repository, request: &LifecycleRequest) -> Outcome {
    let plan = repo.plan_lifecycle(request, &mut Guard::read()).unwrap();
    assert_eq!(plan.lifecycle_request(), Some(request));
    repo.apply(
        &plan,
        &request.canonical_bytes().unwrap(),
        &mut Guard::write(&plan),
    )
    .unwrap()
}

#[test]
fn trash_is_versioned_non_erasing_and_explicit_inspection_survives_reopen() {
    let (f, mut repo, initial) = repository();
    let original = repo.retained("first", &mut Guard::read()).unwrap();
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    let result = execute(&mut repo, &req);
    assert_eq!(result.decision, DecisionKind::Trashed);
    assert_eq!(result.resulting, *initial.resulting());
    assert!(repo.current("document", &mut Guard::read()).is_err());
    assert!(repo
        .historical(initial.resulting(), &mut Guard::read())
        .is_err());
    assert_eq!(
        repo.search("private", 10, &mut Guard::read())
            .unwrap()
            .total_matches,
        0
    );
    assert!(repo
        .search_selected(
            &[initial.resulting().clone()],
            "private",
            10,
            &mut Guard::read()
        )
        .is_err());
    assert!(repo
        .semantic_search_selected(
            &[initial.resulting().clone()],
            "private",
            10,
            2,
            &mut Guard::read()
        )
        .is_err());
    let status = repo
        .lifecycle_status("document", &mut Guard::read())
        .unwrap();
    assert_eq!(status.status, LifecycleStatus::Trashed);
    assert!(status.revision > req.expected.revision);
    assert_eq!(
        repo.trash_version(&status, &mut Guard::read())
            .unwrap()
            .content(),
        b"private original"
    );
    assert!(repo.retained("first", &mut Guard::read()).is_err());
    let snapshot = repo.snapshot(None, &mut Guard::read()).unwrap();
    assert_eq!(snapshot.records[0].1.payload, original.payload);
    assert_eq!(snapshot.records[0].2, original.source);
    drop(repo);
    let repo = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        status
    );
    assert!(repo.current("document", &mut Guard::read()).is_err());
}

#[test]
fn restore_keeps_content_reference_but_advances_exact_revision_and_blocks_aba() {
    let (_f, mut repo, initial) = repository();
    let old = request(&repo, "trash", LifecycleOperation::Trash);
    let reviewed = repo.plan_lifecycle(&old, &mut Guard::read()).unwrap();
    execute(&mut repo, &old);
    let restore = request(&repo, "restore", LifecycleOperation::Restore);
    assert_eq!(
        execute(&mut repo, &restore).decision,
        DecisionKind::Restored
    );
    let live = repo
        .lifecycle_status("document", &mut Guard::read())
        .unwrap();
    assert_eq!(live.version, *initial.resulting());
    assert_ne!(live, old.expected);
    assert!(repo
        .trash_version(&restore.expected, &mut Guard::read())
        .is_err());
    let mut stale = old.clone();
    stale.request_id = "stale-preview".into();
    assert_eq!(
        execute(&mut repo, &stale).decision,
        DecisionKind::ConflictRetained
    );
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        live
    );
    // Exact old request replay is evidence, not another toggle.
    let replay = repo
        .apply(
            &reviewed,
            &old.canonical_bytes().unwrap(),
            &mut Guard::write(&reviewed),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        live
    );
}

#[test]
fn reviewed_plan_cannot_cross_a_new_trash_restore_generation() {
    let (_f, mut repo, _) = repository();
    let stale = request(&repo, "reviewed-earlier", LifecycleOperation::Trash);
    let plan = repo.plan_lifecycle(&stale, &mut Guard::read()).unwrap();
    let trash = request(&repo, "other-trash", LifecycleOperation::Trash);
    execute(&mut repo, &trash);
    let restore = request(&repo, "other-restore", LifecycleOperation::Restore);
    execute(&mut repo, &restore);
    assert!(repo
        .apply(
            &plan,
            &stale.canonical_bytes().unwrap(),
            &mut Guard::write(&plan)
        )
        .is_err());
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap()
            .status,
        LifecycleStatus::Live
    );
}

#[test]
fn repeat_trash_and_restore_are_retained_noops_not_lifetime_renewal() {
    let (_f, mut repo, _) = repository();
    let restore = request(&repo, "already-live", LifecycleOperation::Restore);
    assert_eq!(
        execute(&mut repo, &restore).decision,
        DecisionKind::NoChangeRetained
    );
    let trash = request(&repo, "trash", LifecycleOperation::Trash);
    execute(&mut repo, &trash);
    let before = repo
        .lifecycle_status("document", &mut Guard::read())
        .unwrap();
    let noop = request(&repo, "already-trash", LifecycleOperation::Trash);
    assert_eq!(
        execute(&mut repo, &noop).decision,
        DecisionKind::NoChangeRetained
    );
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        before
    );
    let mut changed = noop.clone();
    changed.operation = LifecycleOperation::Restore;
    assert!(repo.plan_lifecycle(&changed, &mut Guard::read()).is_err());
}

#[test]
fn trash_reserves_identity_against_capture_external_and_managed_updates() {
    let (_f, mut repo, initial) = repository();
    let edit = repo
        .plan_external_edit(
            "document",
            initial.resulting().clone(),
            b"edit",
            provenance("edit", b"edit", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let trash = request(&repo, "trash", LifecycleOperation::Trash);
    execute(&mut repo, &trash);
    assert!(repo
        .apply(&edit, b"edit", &mut Guard::write(&edit))
        .is_err());
    let capture = capture("recapture", "document", b"new");
    assert!(repo
        .apply(&capture, b"new", &mut Guard::write(&capture))
        .is_err());
    assert!(repo
        .plan_external_edit(
            "document",
            initial.resulting().clone(),
            b"edit",
            provenance("edit-new", b"edit", EditOrigin::External),
            &mut Guard::read()
        )
        .is_err());
    assert!(repo
        .trash_version(&trash.expected, &mut Guard::read())
        .is_err());
}

#[test]
fn independent_boundary_revocation_at_every_precommit_cut_retains_evidence() {
    for cut in [1, 2, 4, 12, 32] {
        let (_f, mut repo, _) = repository();
        let req = request(&repo, "trash", LifecycleOperation::Trash);
        let plan = repo.plan_lifecycle(&req, &mut Guard::read()).unwrap();
        let mut guard = Guard::write(&plan);
        guard.refuse_at = cut;
        assert!(repo
            .apply(&plan, &req.canonical_bytes().unwrap(), &mut guard)
            .is_err());
        assert_eq!(
            repo.lifecycle_status("document", &mut Guard::read())
                .unwrap(),
            req.expected
        );
    }
}

#[test]
fn durable_prepare_and_lost_rename_ack_use_same_live_checked_publication_contract() {
    let (_f, mut repo, _) = repository();
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    let plan = repo.plan_lifecycle(&req, &mut Guard::read()).unwrap();
    let bytes = req.canonical_bytes().unwrap();
    let mut guard = Guard::write(&plan);
    let mut held = repo.prepare(&plan, &bytes, &mut guard).unwrap();
    let commitment = held.commitment().clone();
    assert_ne!(
        commitment.base_head_sha256(),
        commitment.outcome_head_sha256()
    );
    assert_eq!(
        record_lifecycle_request(held.record_bytes()).unwrap(),
        Some(req.clone())
    );
    guard.refuse_at = guard.checks + 1;
    assert!(held.recheck(&mut guard).is_err());
    assert!(held.publish(&mut Guard::write(&plan)).is_err());
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap(),
        req.expected
    );
    let held = repo
        .prepare(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    assert!(held
        .publish_with_hook(&mut Guard::write(&plan), |phase| {
            if matches!(phase, Phase::Renamed) {
                Err("fixture lost acknowledgment".into())
            } else {
                Ok(())
            }
        })
        .is_err());
    assert_eq!(
        repo.lifecycle_status("document", &mut Guard::read())
            .unwrap()
            .status,
        LifecycleStatus::Trashed
    );
    assert!(
        repo.apply(&plan, &bytes, &mut Guard::write(&plan))
            .unwrap()
            .replayed
    );
}

#[test]
fn schema5_integrity_and_metadata_routing_reject_rehashed_unknown_or_mutated_intents() {
    let (_f, mut repo, _) = repository();
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    let plan = repo.plan_lifecycle(&req, &mut Guard::read()).unwrap();
    let bytes = req.canonical_bytes().unwrap();
    let held = repo
        .prepare(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    let record = held.record_bytes().to_vec();
    drop(held);
    let duplicate = [b"{\"schema_version\":5,".as_slice(), &record[1..]].concat();
    assert!(record_lifecycle_request(&duplicate).is_err());
    for index in 0..7 {
        let mut value: Record = serde_json::from_slice(&record).unwrap();
        match index {
            0 => value.schema_version = 4,
            1 => value.plan.source_kind = Some(SourceKind::Content),
            2 => value.plan.lifecycle.as_mut().unwrap().request.binding.owner = "d".repeat(64),
            3 => {
                value.plan.lifecycle.as_mut().unwrap().request.operation =
                    LifecycleOperation::Restore
            }
            4 => value.plan.lifecycle.as_mut().unwrap().observed.state_sha256 = "0".repeat(64),
            5 => value.plan.resulting.version += 1,
            _ => {
                let observed = &mut value.plan.lifecycle.as_mut().unwrap().observed;
                observed.version.artifact_id = "different-target".into();
                value.plan.resulting = observed.version.clone();
                value.plan.observed = Some(observed.version.clone());
            }
        }
        value.review_sha256 = luma_content::sha256(&serde_json::to_vec(&value.plan).unwrap());
        assert!(record_lifecycle_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(repo
        .apply(&plan, &changed, &mut Guard::write(&plan))
        .is_err());
}

#[test]
fn mutation_of_retained_lifecycle_payload_fences_reopen_and_backup() {
    use std::os::unix::fs::PermissionsExt;
    let (f, mut repo, _) = repository();
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    execute(&mut repo, &req);
    let path = f
        .root(&binding())
        .join("outcomes")
        .join(luma_content::sha256(b"trash"))
        .join("source.bin");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(repo
        .lifecycle_status("document", &mut Guard::read())
        .is_err());
    assert!(repo.review_backup_data(&mut Guard::read()).is_err());
    drop(repo);
    assert!(Repository::open_at(&f.path, &binding(), &mut Guard::read()).is_err());
}

#[test]
fn collections_keep_immutable_members_but_never_discover_trashed_member_or_collection() {
    let (_f, mut repo, initial) = repository();
    let source = CollectionSource {
        schema_version: 1,
        kind: "luma-explicit-collection-v1".into(),
        collection_id: "project".into(),
        name: "Project".into(),
        members: vec![initial.resulting().clone()],
    };
    let bytes = source.canonical_bytes().unwrap();
    let plan = repo
        .plan_collection(
            &source,
            None,
            provenance("collection", &bytes, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repo.apply_collection(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    let collection = plan.resulting().clone();
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    execute(&mut repo, &req);
    assert!(repo
        .collection_current("project", &mut Guard::read())
        .is_err());
    assert!(repo
        .collection_page(&collection, 0, 10, &mut Guard::read())
        .is_err());
    assert!(repo
        .collections_for_member(initial.resulting(), 0, 10, &mut Guard::read())
        .is_err());
    assert!(repo
        .search_collection(&collection, "private", 10, &mut Guard::read())
        .is_err());
    assert!(repo
        .semantic_search_collection(&collection, "private", 10, 2, &mut Guard::read())
        .is_err());
    let restore = request(&repo, "untrash", LifecycleOperation::Restore);
    execute(&mut repo, &restore);
    assert_eq!(
        repo.collection_current("project", &mut Guard::read())
            .unwrap()
            .source,
        source
    );
    let mut trash = request(&repo, "trash-collection", LifecycleOperation::Trash);
    trash.expected = repo
        .lifecycle_status(&collection.artifact_id, &mut Guard::read())
        .unwrap();
    execute(&mut repo, &trash);
    assert!(repo
        .collection_current("project", &mut Guard::read())
        .is_err());
    assert!(repo
        .search_collection(&collection, "private", 10, &mut Guard::read())
        .is_err());
}

#[test]
fn backup_and_fresh_owner_replay_preserve_trash_and_remap_every_revision() {
    let (_f, mut repo, _) = repository();
    let noop = request(&repo, "inert-restore", LifecycleOperation::Restore);
    assert_eq!(
        execute(&mut repo, &noop).decision,
        DecisionKind::NoChangeRetained
    );
    let trash = request(&repo, "trash", LifecycleOperation::Trash);
    execute(&mut repo, &trash);
    let restore = request(&repo, "restore", LifecycleOperation::Restore);
    execute(&mut repo, &restore);
    let trash = request(&repo, "trash-again", LifecycleOperation::Trash);
    execute(&mut repo, &trash);
    let archive = super::backup::backup(&repo);
    inspect_backup_data(archive.bytes()).unwrap();
    let target = OwnerBinding {
        installation: "d".repeat(64),
        owner: "e".repeat(64),
        owner_generation: 1,
    };
    let plan = plan_restore_data_checked_versions(
        archive.bytes(),
        &target,
        "recovery",
        &"9".repeat(64),
        &"f".repeat(64),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(plan.review().schema_version, 2);
    assert_eq!(plan.review().workflow_sha256, "f".repeat(64));
    assert_eq!(plan.review().published_outcomes, 4);
    assert_eq!(plan.review().inert_committed_outcomes, 1);
    assert_eq!(plan.mappings().len(), 1);
    let f = Fixture::new();
    let mut restored = None;
    for (step, source) in plan.steps() {
        let mut guard = Guard::write(step);
        if restored.is_none() {
            restored = Some(Repository::create_at(&f.path, step, &mut guard).unwrap());
        }
        let store = restored.as_mut().unwrap();
        store.apply(step, source, &mut guard).unwrap();
        if let Some(request) = step.lifecycle_request() {
            assert_eq!(request.binding, target);
            assert_ne!(request.expected, trash.expected);
        }
    }
    let store = restored.unwrap();
    let mut reader = Guard::read();
    reader.binding = target;
    assert!(store.current("document", &mut reader).is_err());
    let state = store.lifecycle_status("document", &mut reader).unwrap();
    assert_eq!(state.status, LifecycleStatus::Trashed);
    assert_eq!(
        store.trash_version(&state, &mut reader).unwrap().content(),
        b"private original"
    );
}

#[test]
fn old_records_keep_their_original_canonical_shape_and_new_requests_are_closed() {
    let (_f, repo, _) = repository();
    let snapshot = repo.snapshot(None, &mut Guard::read()).unwrap();
    let record = serde_json::to_vec(&snapshot.records[0].0).unwrap();
    assert!(!String::from_utf8(record.clone())
        .unwrap()
        .contains("lifecycle"));
    assert_eq!(record_lifecycle_request(&record).unwrap(), None);
    let req = request(&repo, "trash", LifecycleOperation::Trash);
    for field in ["operation", "retention"] {
        let mut value = serde_json::to_value(&req).unwrap();
        value[field] = json!("arbitrary");
        assert!(serde_json::from_value::<LifecycleRequest>(value).is_err());
    }
    let mut wrong = req.clone();
    wrong.binding.owner_generation += 1;
    assert!(repo.plan_lifecycle(&wrong, &mut Guard::read()).is_err());
    let mut wrong = req;
    wrong.expected.revision = 0;
    assert!(wrong.validate().is_err());
}
