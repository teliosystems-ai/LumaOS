//! Same genuine fixture and actual filesystem/checkpoint code as the initial
//! consumer. Software attribution is not native PAM, TPM or confinement proof.
use super::super::super::backend::Backend;
use super::super::super::resume as restart;
use super::*;

fn retired() -> (Fixture, PageStore) {
    let fixture = Fixture::new();
    fixture.memory.0.borrow_mut().fault = Fault::Old;
    assert!(fixture.dispatch().is_err());
    let pages = fixture.pages();
    let proposal = super::super::super::retired::review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    let (audit, source) = fixture.source(true, &proposal, 2);
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    super::super::super::retired::retire(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        proposal["review_sha256"].as_str().unwrap(),
        &mut authority,
    )
    .unwrap();
    drop(authority);
    (fixture, pages)
}
fn proposal(fixture: &Fixture, pages: &PageStore) -> serde_json::Value {
    restart::review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap()
}
fn source(
    fixture: &Fixture,
    proposal: &serde_json::Value,
    number: u64,
) -> (Audit, TypedAdminOperationSource) {
    let (audit, mut source) = fixture.source(false, proposal, number);
    source.paged_control.as_mut().unwrap().attempt_sha256 =
        Some(proposal["attempt_sha256"].as_str().unwrap().into());
    (audit, source)
}
#[test]
fn actual_fresh_resume_selects_both_jobs_and_retains_every_failed_slot_with_one_new_dispatch() {
    let (fixture, pages) = retired();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    assert_eq!((before.files, before.directories), (8, 7));
    let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
    let failed = controls.read(0, &mut || Ok(())).unwrap().bytes().to_vec();
    drop(controls);
    let proposal = proposal(&fixture, &pages);
    let (audit, source) = source(&fixture, &proposal, 3);
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    let current = restart::begin(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut authority,
    )
    .unwrap();
    assert_eq!(
        fixture.memory.0.borrow().calls,
        2,
        "one rejected initial dispatch plus one new original dispatch"
    );
    let storage = current.descriptor.storage.as_ref().unwrap();
    assert_eq!(storage.jobs.as_ref().unwrap().entries(), 2);
    assert_eq!(storage.locations.entries, 1);
    assert_eq!(
        (
            storage.post_allocation.files,
            storage.post_allocation.directories
        ),
        (14, 8)
    );
    assert_eq!(
        current.pages.inventory(&mut || Ok(())).unwrap(),
        storage.post_allocation
    );
    assert!(storage.post_allocation.allocated_bytes > before.allocated_bytes);
    let controls = cells::Files::observe(&current.pages, &mut || Ok(())).unwrap();
    assert_eq!(controls.read(0, &mut || Ok(())).unwrap().bytes(), failed);
    assert!(matches!(
        control::PendingFrame::from_frame(controls.read(2, &mut || Ok(())).unwrap().bytes())
            .unwrap(),
        control::PendingFrame::Completed { .. }
    ));
    assert!(Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err());
}
#[test]
fn lost_resumed_reply_uses_actual_new_checkpoint_and_fresh_recovery_without_redispatch() {
    let (fixture, pages) = retired();
    let proposal = proposal(&fixture, &pages);
    let (audit, source) = source(&fixture, &proposal, 3);
    fixture.memory.0.borrow_mut().fault = Fault::Lost;
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    assert!(restart::begin(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut authority
    )
    .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    let pages = fixture.pages();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    let recovery = restart::recovery_review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    let (audit, source) = fixture.source(true, &recovery, 4);
    let mut recovery_check = || Ok(());
    let mut original = software_admin_operation(&audit, source, &mut recovery_check);
    let current = restart::reconcile(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        recovery["review_sha256"].as_str().unwrap(),
        &mut original,
    )
    .unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    assert_eq!(current.pages.inventory(&mut || Ok(())).unwrap(), before);
}
#[test]
fn old_or_third_resumed_outcome_retains_all_evidence_and_never_retries_dispatch() {
    for fault in [Fault::Old, Fault::Third] {
        let (fixture, pages) = retired();
        let proposal = proposal(&fixture, &pages);
        let (audit, source) = source(&fixture, &proposal, 3);
        fixture.memory.0.borrow_mut().fault = fault;
        let mut check = || Ok(());
        let mut authority = software_admin_operation(&audit, source, &mut check);
        assert!(restart::begin(
            fixture.memory.clone(),
            fixture.files(),
            pages,
            fixture.binding.clone(),
            proposal["window_intent_sha256"].as_str().unwrap(),
            &mut authority
        )
        .is_err());
        let pages = fixture.pages();
        let before = pages.inventory(&mut || Ok(())).unwrap();
        let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
        let pending = controls.read(2, &mut || Ok(())).unwrap().bytes().to_vec();
        assert!(restart::recovery_review(
            &mut fixture.memory.clone(),
            &fixture.files(),
            &pages,
            &fixture.binding,
            &mut || Ok(())
        )
        .is_err());
        assert!(restart::review(
            &mut fixture.memory.clone(),
            &fixture.files(),
            &pages,
            &fixture.binding,
            &mut || Ok(())
        )
        .is_err());
        assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), pending);
        assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 2);
    }
}
#[test]
fn fresh_resume_cannot_reuse_failed_retirement_or_wrong_scope_and_preserves_original_deadline() {
    let (fixture, pages) = retired();
    let proposal = proposal(&fixture, &pages);
    let before = pages.inventory(&mut || Ok(())).unwrap();
    for case in 0..5 {
        let (mut audit, mut source) = source(&fixture, &proposal, 3);
        match case {
            0 => audit.operation_id = Some(format!("{:032x}", 1)),
            1 => audit.operation_id = Some(format!("{:032x}", 2)),
            2 => source.paged_control.as_mut().unwrap().attempt_sha256 = Some("dd".repeat(32)),
            3 => {
                source
                    .paged_control
                    .as_mut()
                    .unwrap()
                    .expected_selected_descriptor_sha256 = Some("dd".repeat(32))
            }
            _ => {}
        }
        let mut check = || {
            if case == 4 {
                Err("explicit software original restart revoked".into())
            } else {
                Ok(())
            }
        };
        let mut authority = software_admin_operation(&audit, source, &mut check);
        assert!(restart::begin(
            fixture.memory.clone(),
            fixture.files(),
            fixture.pages(),
            fixture.binding.clone(),
            proposal["window_intent_sha256"].as_str().unwrap(),
            &mut authority
        )
        .is_err());
        assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 1);
    }
}

#[test]
fn actual_cold_direct_backend_reopens_first_and_resumed_completed_cuts_without_hash_fallback() {
    let fixture = Fixture::new();
    let initial = fixture.intent();
    let current = fixture.dispatch().unwrap();
    let mut backend = Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        backend.descriptor().bytes().unwrap(),
        current.descriptor.bytes().unwrap()
    );
    backend.live(&mut || Ok(())).unwrap();
    let (audit, initial_source) = fixture.source(false, &initial, 2);
    let mut check = || Ok(());
    let mut original = software_admin_operation(&audit, initial_source, &mut check);
    let mut operation = COperation::Admin(&mut original);
    assert!(
        backend
            .lookup(
                &current.descriptor.roots.owners,
                b"not-an-empty-owner-claim",
                &mut operation
            )
            .is_err(),
        "Pending is unavailable, not an authenticated empty owner map"
    );
    let (fixture, pages) = retired();
    let proposal = proposal(&fixture, &pages);
    let (audit, source) = source(&fixture, &proposal, 3);
    let mut check = || Ok(());
    let mut original = software_admin_operation(&audit, source, &mut check);
    let current = restart::begin(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut original,
    )
    .unwrap();
    let mut backend = Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        backend.descriptor().bytes().unwrap(),
        current.descriptor.bytes().unwrap()
    );
    let OperationData::BootstrapProgress {
        previous_retirement: Some(hash),
        ..
    } = &current.descriptor.operation
    else {
        panic!("actual retained first attempt required")
    };
    let mut operation = COperation::Admin(&mut original);
    assert!(!backend
        .read_immutable(hash, slots::Kind::Record, &mut operation)
        .unwrap()
        .is_empty());
}

#[test]
fn cold_direct_backend_refuses_uncertain_old_third_and_retired_cuts_without_adoption() {
    for fault in [Fault::Old, Fault::Lost, Fault::Third] {
        let fixture = Fixture::new();
        fixture.memory.0.borrow_mut().fault = fault;
        assert!(fixture.dispatch().is_err());
        let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
        assert!(Backend::open(
            fixture.memory.clone(),
            fixture.files(),
            fixture.binding.clone(),
            &mut || Ok(())
        )
        .is_err());
        assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 1);
    }
    let (fixture, pages) = retired();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    assert!(Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(())
    )
    .is_err());
    assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
}

#[test]
fn direct_backend_poison_is_monotone_after_actual_nv_or_original_control_changes() {
    let fixture = Fixture::new();
    let current = fixture.dispatch().unwrap();
    let mut backend = Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    let selected = fixture.memory.0.borrow().head;
    fixture.memory.0.borrow_mut().head = [0xdd; 32];
    assert!(backend.live(&mut || Ok(())).is_err());
    fixture.memory.0.borrow_mut().head = selected;
    assert!(
        backend.live(&mut || Ok(())).is_err(),
        "restored byte equality cannot revive the old fenced handle"
    );
    let mut backend = Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    let controls = cells::Files::observe(&current.pages, &mut || Ok(())).unwrap();
    let complete = controls.read(2, &mut || Ok(())).unwrap();
    let control::PendingFrame::Completed { pending } =
        control::PendingFrame::from_frame(complete.bytes()).unwrap()
    else {
        panic!("actual completed source required")
    };
    controls
        .rewrite(
            &complete,
            &control::PendingFrame::Prepared { pending }.frame().unwrap(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(backend.live(&mut || Ok(())).is_err());
    let changed = controls.read(2, &mut || Ok(())).unwrap();
    controls
        .rewrite(&changed, complete.bytes(), &mut || Ok(()))
        .unwrap();
    assert!(backend.live(&mut || Ok(())).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}
