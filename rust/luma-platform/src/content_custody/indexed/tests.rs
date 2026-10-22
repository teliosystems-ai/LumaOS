//! Pure exact projection/counter fixtures, not installed C/PAM/TPM proofs.
use super::*;
fn selected() -> Selection {
    let binding = OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 3,
    };
    let physical = PhysicalInventory {
        regular_files: 1,
        directories: 2,
        logical_bytes: 512,
        allocated_bytes: 12288,
        incomplete_objects: 0,
    };
    Selection {
        owner: OwnerHeadV2::empty_data(&binding, physical.clone()).unwrap(),
        physical,
        leaf: None,
        descriptor_sha256: "c".repeat(64),
    }
}
fn leaf(binding: &OwnerBinding, pending: bool) -> Leaf {
    serde_json::from_value(serde_json::json!({"schema_version":2,"binding":binding,"current_generation":null,"current_job":null,"preparation":if pending{serde_json::json!({"sha256":"d".repeat(64),"bytes":64})}else{serde_json::Value::Null}})).unwrap()
}
#[test]
fn selection_digest_does_not_relabel_owner_results_for_unrelated_global_events() {
    let mut data = selected();
    let expected = selection_sha256(&data).unwrap();
    data.descriptor_sha256 = "d".repeat(64);
    assert_eq!(selection_sha256(&data).unwrap(), expected);
    data.leaf = Some(leaf(&data.owner.binding, false));
    assert_ne!(selection_sha256(&data).unwrap(), expected);
}
#[test]
fn selection_digest_binds_actual_pending_preparation_and_owner_generation() {
    let mut data = selected();
    data.leaf = Some(leaf(&data.owner.binding, false));
    let expected = selection_sha256(&data).unwrap();
    data.leaf = Some(leaf(&data.owner.binding, true));
    assert_ne!(selection_sha256(&data).unwrap(), expected);
    let mut changed = selected();
    let mut binding = changed.owner.binding.clone();
    binding.owner_generation += 1;
    changed.owner = OwnerHeadV2::empty_data(&binding, changed.physical.clone()).unwrap();
    assert_ne!(
        selection_sha256(&changed).unwrap(),
        selection_sha256(&selected()).unwrap()
    );
}
#[test]
fn cumulative_private_read_debits_precede_work_and_cannot_reset_each_page() {
    let mut remaining = 32770;
    reserve_read(&mut remaining, 16385).unwrap();
    reserve_read(&mut remaining, 16385).unwrap();
    assert_eq!(remaining, 0);
    assert!(reserve_read(&mut remaining, 1).is_err());
    assert_eq!(remaining, 0);
    let mut tiny = 1;
    assert!(reserve_read(&mut tiny, 16385).is_err());
    assert_eq!(tiny, 1);
    assert!(reserve_read(&mut tiny, 0).is_err());
    assert!(reserve_read(&mut tiny, 16386).is_err());
    assert_eq!(tiny, 1);
}

fn original_data() -> (Input, Audit, super::super::protocol::TypedOperationSource) {
    let binding = selected().owner.binding;
    let input = Input {
        schema_version: 1,
        login: "alice".into(),
        binding: binding.clone(),
        request_id: "1".repeat(32),
        operation: Operation::Status {},
    };
    let profile = input.profile().unwrap();
    let usage = content_index::scope::original_usage(
        &profile,
        "8:6",
        &binding,
        &input.sha256().unwrap(),
        true,
    )
    .unwrap();
    let audit = Audit {
        subject: binding.owner.clone(),
        subject_generation: binding.owner_generation,
        grant_id: "fixture-index-reader".into(),
        grant_version: 1,
        checkpoint_head: "2".repeat(64),
        operation_id: Some("3".repeat(32)),
        usage,
    };
    audit.validate().unwrap();
    let source = super::super::protocol::TypedOperationSource {
        schema_version: 1,
        request_sha256: "4".repeat(64),
        purpose: SourcePurpose::IndexRead,
        profile,
        storage_device: "8:6".into(),
        binding,
        worker_pid: 123,
        worker_start: 456,
        worker_label: "luma-acquisition (enforce)".into(),
        lease: crate::resources::Token {
            lease_id: "5".repeat(32),
            generation: 1,
            manager_epoch: "6".repeat(32),
        },
    };
    (input, audit, source)
}
#[test]
fn original_source_gate_joins_subject_owner_finite_read_profile_and_actual_domain() {
    let (input, audit, source) = original_data();
    let mut checks = 0;
    let mut live = || {
        checks += 1;
        Ok(())
    };
    let mut original =
        super::super::protocol::software_worker_operation(&audit, source.clone(), &mut live);
    assert_eq!(
        require_original_source(&mut original, &input, &source.profile).unwrap(),
        audit.usage
    );
    drop(original);
    assert_eq!(checks, 2);
    for field in 0..6 {
        let mut changed_audit = audit.clone();
        let mut changed_source = source.clone();
        match field {
            0 => changed_audit.subject = "f".repeat(64),
            1 => changed_audit.subject_generation += 1,
            2 => changed_source.binding.owner_generation += 1,
            3 => changed_source.worker_label = "unconfined".into(),
            4 => changed_source.purpose = SourcePurpose::Select,
            _ => changed_audit.operation_id = None,
        }
        let mut live = || Ok(());
        let mut original = super::super::protocol::software_worker_operation(
            &changed_audit,
            changed_source,
            &mut live,
        );
        assert!(require_original_source(&mut original, &input, &source.profile).is_err());
    }
}
#[test]
fn actual_index_entry_refuses_borrowed_purpose_and_revoked_original_before_private_open() {
    let (input, audit, mut source) = original_data();
    let bytes = input.canonical_bytes().unwrap();
    source.purpose = SourcePurpose::Select;
    let mut live = || Ok(());
    let mut original = super::super::protocol::software_worker_operation(&audit, source, &mut live);
    assert!(with_index(&mut original, &bytes, |_, _| -> Result<()> {
        panic!("wrong-purpose entry reached private delivery")
    })
    .is_err());
    let (_, audit, source) = original_data();
    let mut revoked = || Err("explicit fixture original session revoked".into());
    let mut original =
        super::super::protocol::software_worker_operation(&audit, source, &mut revoked);
    assert!(with_index(&mut original, &bytes, |_, _| -> Result<()> {
        panic!("revoked entry reached private delivery")
    })
    .is_err());
}

#[test]
fn actual_cursor_scope_accepts_only_exact_current_artifact_lifecycle_corpus_maps() {
    let head = selected().owner;
    let (mut input, _, _) = original_data();
    input.operation = Operation::Advance {
        job_id: "1".repeat(32),
        expected_job_sha256: "2".repeat(64),
    };
    let profile = input.profile().unwrap();
    // This helper compares selected DATA only. The production Gate brackets it
    // with real original session/C/resource/builder checks, never this fixture.
    for root in [
        &head.roots.artifacts,
        &head.roots.lifecycle,
        &head.roots.corpus,
    ] {
        boundary::selected_read_map(&head, &input, &profile, root).unwrap();
    }
    for root in [
        &head.roots.history,
        &head.roots.requests,
        &head.roots.collections,
        &head.roots.segments,
        &head.roots.pending,
        &head.roots.retained,
    ] {
        assert!(boundary::selected_read_map(&head, &input, &profile, root).is_err());
    }
    let foreign =
        MapRoot::empty(&head.binding, luma_content_store::v2::MapKind::IndexTerms).unwrap();
    assert!(boundary::selected_read_map(&head, &input, &profile, &foreign).is_err());
    let mut changed = head.roots.corpus.clone();
    changed.entry_count = 1;
    assert!(boundary::selected_read_map(&head, &input, &profile, &changed).is_err());
    changed = head.roots.corpus.clone();
    changed.binding.owner_generation += 1;
    assert!(boundary::selected_read_map(&head, &input, &profile, &changed).is_err());
    let effect = input.effect_profile(&"a".repeat(64)).unwrap();
    assert!(boundary::selected_read_map(&head, &input, &effect, &head.roots.corpus).is_err());
    input.binding.owner_generation += 1;
    assert!(boundary::selected_read_map(&head, &input, &profile, &head.roots.corpus).is_err());
}

#[test]
fn status_does_not_authorize_private_source_map_cursor() {
    let head = selected().owner;
    let (input, _, _) = original_data();
    let profile = input.profile().unwrap();
    for root in head.roots.all() {
        assert!(boundary::selected_read_map(&head, &input, &profile, root).is_err());
    }
}
