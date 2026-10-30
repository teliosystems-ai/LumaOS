//! Actual joins of the closed direct worker-original publisher over a real
//! bootstrapped C cut. Original worker attribution, resources and NV are
//! explicit software fixtures, not installed qualification.
use super::super::super::super::super::protocol::{
    software_worker_operation, TypedOperationSource,
};
use super::super::super::backend::Backend;
use super::progress_cases::{open, proposal, step, ContentGuard};
use super::*;
use luma_content::{EditOrigin, Format, Provenance};
use luma_content_store::{Plan, Repository};

/// One retained legacy owner row, published in the original journal and the
/// actual content repository, then copied into C by two direct windows.
pub(super) struct Owner {
    pub(super) binding: OwnerBinding,
    pub(super) plan: Plan,
    pub(super) repository: Repository,
    pub(super) wanted: VerifiedState,
}
pub(super) fn provenance(request_id: &str, body: &[u8], origin: EditOrigin) -> Provenance {
    Provenance {
        request_id: request_id.into(),
        workflow_sha256: "44".repeat(32),
        source_sha256: hash(body),
        origin,
    }
}
pub(super) fn attribution(binding: &OwnerBinding, review: &str, number: u64) -> (String, Audit) {
    let profile = format!("content-v1-write-1-{}-{}", "77".repeat(32), review);
    let usage = crate::content_governed::custody_usage(&profile, "8:1", binding, review).unwrap();
    let audit = Audit {
        subject: binding.owner.clone(),
        subject_generation: binding.owner_generation,
        grant_id: "explicit-software-direct-worker-owner".into(),
        grant_version: 1,
        checkpoint_head: "33".repeat(32),
        operation_id: Some(format!("{number:032x}")),
        usage,
    };
    (profile, audit)
}
pub(super) fn worker(
    binding: &OwnerBinding,
    profile: String,
    commitment: &[u8],
) -> TypedOperationSource {
    TypedOperationSource {
        schema_version: 1,
        request_sha256: hash(commitment),
        purpose: SourcePurpose::Publish,
        profile,
        storage_device: "8:1".into(),
        binding: binding.clone(),
        worker_pid: std::process::id(),
        worker_start: 1,
        worker_label: "software-fixed-worker".into(),
        lease: crate::resources::Token {
            lease_id: "88".repeat(16),
            generation: 1,
            manager_epoch: "99".repeat(16),
        },
    }
}
pub(super) fn cold(fixture: &Fixture) -> Result<Backend<Memory>> {
    Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
}
pub(super) fn ready(fixture: &Fixture) -> (Owner, Backend<Memory>) {
    let binding = OwnerBinding {
        installation: fixture.binding.installation.clone(),
        owner: "22".repeat(32),
        owner_generation: 1,
    };
    let body = b"real retained owner bytes before the direct worker publisher";
    let plan = Plan::capture(
        binding.clone(),
        "document",
        Format::Utf8Text,
        body,
        provenance("direct-worker-existing-owner", body, EditOrigin::Managed),
    )
    .unwrap();
    let mut guard = ContentGuard {
        owner: binding.clone(),
        review: plan.review_sha256().into(),
    };
    let mut repository = Repository::create_at(&fixture.data, &plan, &mut guard).unwrap();
    let held = repository.prepare(&plan, body, &mut guard).unwrap();
    let commitment = held.commitment().canonical_bytes().unwrap();
    let record = held.record_bytes().to_vec();
    let (profile, audit) = attribution(&binding, plan.review_sha256(), 40);
    let mut legacy = fixture.store();
    let wanted = legacy
        .publish(
            &commitment,
            &record,
            &profile,
            "8:1",
            &audit,
            &mut || Ok(()),
        )
        .unwrap();
    drop(legacy);
    held.publish(&mut guard).unwrap();
    assert_eq!(repository.verified_state(&mut guard).unwrap(), wanted);
    fixture.dispatch().unwrap();
    let mut backend = open(fixture);
    let proposal = proposal(fixture, &mut backend, 2);
    let current = step(fixture, backend, &proposal, 3).unwrap();
    assert_eq!(current.descriptor().phase.state, bootstrap::State::Ready);
    assert_eq!(current.descriptor().roots.owners.entry_count, 1);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
    (
        Owner {
            binding,
            plan,
            repository,
            wanted,
        },
        current,
    )
}

#[test]
fn actual_v1_publication_is_one_worker_dispatch_and_cold_reopen_replays_its_lineage() {
    let fixture = Fixture::new();
    let (mut owner, current) = ready(&fixture);
    let base = current.descriptor().clone();
    let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
    let body = b"second owner version selected only by the direct worker publisher";
    let mut guard = ContentGuard {
        owner: owner.binding.clone(),
        review: owner.plan.review_sha256().into(),
    };
    let edit = owner
        .repository
        .plan_external_edit(
            "document",
            owner.plan.resulting().clone(),
            body,
            provenance("direct-worker-second", body, EditOrigin::External),
            &mut guard,
        )
        .unwrap();
    guard.review = edit.review_sha256().into();
    let held = owner.repository.prepare(&edit, body, &mut guard).unwrap();
    let commitment = held.commitment().canonical_bytes().unwrap();
    let record = held.record_bytes().to_vec();
    let expected = held.commitment().outcome_state();
    let (profile, audit) = attribution(&owner.binding, edit.review_sha256(), 41);
    let source = worker(&owner.binding, profile.clone(), &commitment);
    let mut check = || Ok(());
    let state = current
        .publish_v1_direct(
            &commitment,
            &record,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(state, expected);
    assert_eq!(state.outcome_count, owner.wanted.outcome_count + 1);
    assert_eq!(
        fixture.memory.0.borrow().calls,
        4,
        "exactly one worker NV dispatch after the three bootstrap selections"
    );
    let after = fixture.pages().inventory(&mut || Ok(())).unwrap();
    assert!(after.files > before.files && after.allocated_bytes > before.allocated_bytes);
    held.publish(&mut guard).unwrap();
    assert_eq!(owner.repository.verified_state(&mut guard).unwrap(), state);
    let reopened = cold(&fixture).unwrap();
    let published = reopened.descriptor().clone();
    assert!(matches!(
        published.operation,
        OperationData::V1Publication { .. }
    ));
    assert_eq!(published.sequence, base.sequence + 1);
    assert_eq!(published.previous_nv_head, base.selected_nv_head);
    assert_eq!(published.roots.owners.entry_count, 1);
    assert_ne!(published.roots.owners, base.roots.owners);
    assert_eq!(
        tpm::decode::<32>(&published.selected_nv_head).unwrap(),
        fixture.memory.0.borrow().head,
        "the cold reader selected exactly the actual worker-advanced NV"
    );
    assert_ne!(
        tpm::decode::<32>(&base.selected_nv_head).unwrap(),
        fixture.memory.0.borrow().head,
        "the worker dispatch advanced actual NV from the bootstrap base"
    );
    assert_eq!(fixture.memory.0.borrow().calls, 4);
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), after);
    // A retry of the selected outcome over the cold cut is the exact outcome
    // without allocation or another NV dispatch.
    let source = worker(&owner.binding, profile, &commitment);
    let mut check = || Ok(());
    let retried = reopened
        .publish_v1_direct(
            &commitment,
            &record,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(retried, state);
    assert_eq!(fixture.memory.0.borrow().calls, 4, "no retry dispatch");
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), after);
    assert_eq!(cold(&fixture).unwrap().descriptor(), &published);
}

#[test]
fn actual_cold_reopened_v1_chain_publishes_and_replays_each_selected_lineage() {
    let fixture = Fixture::new();
    let (mut owner, current) = ready(&fixture);
    let mut guard = ContentGuard {
        owner: owner.binding.clone(),
        review: owner.plan.review_sha256().into(),
    };
    let mut resulting = owner.plan.resulting().clone();
    let mut state = owner.wanted.clone();
    let mut previous = current.descriptor().clone();
    drop(current);
    for (number, body) in [
        &b"second owner version over the bootstrap cut"[..],
        &b"third owner version over a cold-reopened V1 cut"[..],
    ]
    .into_iter()
    .enumerate()
    {
        let edit = owner
            .repository
            .plan_external_edit(
                "document",
                resulting.clone(),
                body,
                provenance(
                    &format!("direct-worker-chain-{number}"),
                    body,
                    EditOrigin::External,
                ),
                &mut guard,
            )
            .unwrap();
        guard.review = edit.review_sha256().into();
        let held = owner.repository.prepare(&edit, body, &mut guard).unwrap();
        let commitment = held.commitment().canonical_bytes().unwrap();
        let record = held.record_bytes().to_vec();
        let expected = held.commitment().outcome_state();
        let (profile, audit) =
            attribution(&owner.binding, edit.review_sha256(), 41 + number as u64);
        let source = worker(&owner.binding, profile, &commitment);
        let mut check = || Ok(());
        let next = cold(&fixture)
            .unwrap()
            .publish_v1_direct(
                &commitment,
                &record,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .unwrap();
        assert_eq!(next, expected);
        assert_eq!(next.outcome_count, state.outcome_count + 1);
        assert_eq!(fixture.memory.0.borrow().calls, 4 + number as u64);
        held.publish(&mut guard).unwrap();
        assert_eq!(owner.repository.verified_state(&mut guard).unwrap(), next);
        let after = fixture.pages().inventory(&mut || Ok(())).unwrap();
        let selected = cold(&fixture).unwrap().descriptor().clone();
        let OperationData::V1Publication { binding, .. } = &selected.operation else {
            panic!("cold reader selected a different event class");
        };
        assert_eq!(binding, &owner.binding);
        assert_eq!(selected.sequence, previous.sequence + 1);
        assert_eq!(selected.previous_nv_head, previous.selected_nv_head);
        assert_eq!(
            tpm::decode::<32>(&selected.selected_nv_head).unwrap(),
            fixture.memory.0.borrow().head
        );
        assert_eq!(fixture.memory.0.borrow().calls, 4 + number as u64);
        assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), after);
        resulting = edit.resulting().clone();
        state = next;
        previous = selected;
    }
    assert!(matches!(
        previous.operation,
        OperationData::V1Publication { .. }
    ));
    assert_eq!(state.outcome_count, owner.wanted.outcome_count + 2);
}

#[test]
fn actual_revoked_or_substituted_worker_original_is_refused_before_allocation_or_nv() {
    let fixture = Fixture::new();
    let (mut owner, current) = ready(&fixture);
    drop(current);
    let body = b"second owner version refused under substituted worker originals";
    let mut guard = ContentGuard {
        owner: owner.binding.clone(),
        review: owner.plan.review_sha256().into(),
    };
    let edit = owner
        .repository
        .plan_external_edit(
            "document",
            owner.plan.resulting().clone(),
            body,
            provenance("direct-worker-refused", body, EditOrigin::External),
            &mut guard,
        )
        .unwrap();
    guard.review = edit.review_sha256().into();
    let held = owner.repository.prepare(&edit, body, &mut guard).unwrap();
    let commitment = held.commitment().canonical_bytes().unwrap();
    let record = held.record_bytes().to_vec();
    let expected = held.commitment().outcome_state();
    let (profile, audit) = attribution(&owner.binding, edit.review_sha256(), 41);
    let source = worker(&owner.binding, profile, &commitment);
    let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
    let mut revoked = || -> Result<()> { Err("explicit original worker revocation".into()) };
    assert!(open(&fixture)
        .publish_v1_direct(
            &commitment,
            &record,
            &mut software_worker_operation(&audit, source.clone(), &mut revoked),
        )
        .is_err());
    let mut purpose = source.clone();
    purpose.purpose = SourcePurpose::Select;
    let mut binding = source.clone();
    binding.binding.owner = "23".repeat(32);
    let (_, stale) = attribution(&owner.binding, owner.plan.review_sha256(), 41);
    let mut anonymous = audit.clone();
    anonymous.operation_id = None;
    for (audit, source) in [
        (&audit, purpose),
        (&audit, binding),
        (&stale, source.clone()),
        (&anonymous, source.clone()),
    ] {
        let mut check = || Ok(());
        assert!(open(&fixture)
            .publish_v1_direct(
                &commitment,
                &record,
                &mut software_worker_operation(audit, source, &mut check),
            )
            .is_err());
    }
    assert_eq!(fixture.memory.0.borrow().calls, 3);
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), before);
    let mut check = || Ok(());
    let state = open(&fixture)
        .publish_v1_direct(
            &commitment,
            &record,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(state, expected);
    assert_eq!(fixture.memory.0.borrow().calls, 4);
    drop(held);
}

#[test]
fn actual_worker_nv_faults_are_fenced_without_redispatch_or_content_adoption() {
    for fault in [Fault::Old, Fault::Lost, Fault::Third] {
        let fixture = Fixture::new();
        let (mut owner, current) = ready(&fixture);
        let body = b"second owner version under an uncertain worker NV reply";
        let mut guard = ContentGuard {
            owner: owner.binding.clone(),
            review: owner.plan.review_sha256().into(),
        };
        let edit = owner
            .repository
            .plan_external_edit(
                "document",
                owner.plan.resulting().clone(),
                body,
                provenance("direct-worker-fault", body, EditOrigin::External),
                &mut guard,
            )
            .unwrap();
        guard.review = edit.review_sha256().into();
        let held = owner.repository.prepare(&edit, body, &mut guard).unwrap();
        let commitment = held.commitment().canonical_bytes().unwrap();
        let record = held.record_bytes().to_vec();
        drop(held);
        let (profile, audit) = attribution(&owner.binding, edit.review_sha256(), 41);
        let source = worker(&owner.binding, profile, &commitment);
        let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
        fixture.memory.0.borrow_mut().fault = fault;
        let mut check = || Ok(());
        assert!(current
            .publish_v1_direct(
                &commitment,
                &record,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, 4);
        let after = fixture.pages().inventory(&mut || Ok(())).unwrap();
        assert!(
            after.files > before.files && after.allocated_bytes > before.allocated_bytes,
            "all new content is allocated before the sole dispatch"
        );
        assert!(cold(&fixture).is_err());
        assert_eq!(fixture.memory.0.borrow().calls, 4, "no redispatch");
        assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), after);
        assert_eq!(
            owner.repository.verified_state(&mut guard).unwrap(),
            owner.wanted,
            "an unselected C transition never publishes repository content"
        );
    }
}
