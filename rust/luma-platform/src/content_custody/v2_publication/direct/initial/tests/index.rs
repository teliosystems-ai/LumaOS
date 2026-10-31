//! Actual first index job Start reservations and job selections of the closed
//! direct worker over a real migrated V2 owner in a real bootstrapped C cut and
//! its real v2 object store. The builder identity, original worker attribution,
//! resources and NV are explicit software fixtures, not the installed image
//! builder or installed qualification.
use super::super::super::super::super::protocol::{
    software_worker_operation, OriginalCOperation, TypedOperationSource,
};
use super::migration_cases::{migrated, Migrated};
use super::worker_cases::cold;
use super::*;
use crate::content_checkpoint::custody::indexed::{
    selection_data_sha256, TransitionBase, TransitionReview,
};
use crate::content_checkpoint::custody::v2_publication::index::effects::CurrentBuilder;
use crate::content_index::request;
use crate::content_index::scope::original_usage;
use crate::content_index::state::Job;
use luma_content_store::corpus_index::{BuilderIdentity, CorpusIndexLimits};
use luma_content_store::v2::{BlobObjectPlan, IoBudget, Mutation, PhysicalInventory};
use luma_content_store::DecisionKind;

/// Inventory walks and blob reads are read-only admissions.
fn read() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
/// The first job's canonical bytes and blob reference, computed independently
/// of the module under test from the documented first-job recipe.
fn first_job(
    input: &request::Input,
    head: &OwnerHeadV2,
    builder: &BuilderIdentity,
) -> (Vec<u8>, luma_content_store::v2::BlobReference) {
    let selection = selection_data_sha256(head, None).unwrap();
    let bytes = Job::beginning_data(input, head, builder, &selection)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let planned = BlobObjectPlan::data(&input.binding, &bytes, || Ok(())).unwrap();
    let reference = planned.reference().clone();
    (bytes, reference)
}

/// A fixed software builder identity, re-proved only by the original check.
struct Fixed(BuilderIdentity);
impl CurrentBuilder for Fixed {
    fn identity(&self) -> &BuilderIdentity {
        &self.0
    }
    fn check(&self, original: &mut OriginalCOperation<'_>) -> Result<()> {
        original.check()
    }
}
fn builder() -> Fixed {
    Fixed(BuilderIdentity {
        source_sha256: "d".repeat(64),
        runtime_sha256: "e".repeat(64),
    })
}
fn start(binding: &OwnerBinding, head: &OwnerHeadV2, id: &str) -> request::Input {
    request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding.clone(),
        request_id: id.repeat(32),
        operation: request::Operation::Start {
            expected_owner_sha256: head.sha256().unwrap(),
            expected_selection_sha256: selection_data_sha256(head, None).unwrap(),
            job_id: "2".repeat(32),
            dimensions: 8,
            limits: CorpusIndexLimits {
                read_bytes: 128 * 1024 * 1024,
                write_bytes: 64 * 1024 * 1024,
                source_bytes: 4 * 1024 * 1024,
                postings: 65536,
                floating_operations: 100_000_000,
            },
        },
    }
}

/// The original worker effect for one Start, computed independently of the
/// module under test from the documented first-job transition review recipe
/// over the owner head the request expects.
fn original(
    input: &request::Input,
    head: &OwnerHeadV2,
    builder: &BuilderIdentity,
    number: u64,
) -> (Audit, TypedOperationSource) {
    let selection = selection_data_sha256(head, None).unwrap();
    let job = Job::beginning_data(input, head, builder, &selection).unwrap();
    let core = Job::beginning_review_data(input, head, builder, &selection).unwrap();
    let bytes = job.canonical_bytes().unwrap();
    let planned = BlobObjectPlan::data(&input.binding, &bytes, || Ok(())).unwrap();
    let objects = planned.write_set(|| Ok(())).unwrap();
    let review = TransitionReview::data(
        input,
        TransitionBase {
            owner: head,
            job: None,
            selection_sha256: &selection,
            builder,
        },
        core,
        planned.reference().clone(),
        objects,
    )
    .unwrap()
    .review_sha256;
    let profile = input.effect_profile(&review).unwrap();
    let source_sha256 = input.sha256().unwrap();
    let audit = Audit {
        subject: input.binding.owner.clone(),
        subject_generation: input.binding.owner_generation,
        grant_id: "explicit-software-direct-index-start".into(),
        grant_version: 1,
        checkpoint_head: "33".repeat(32),
        operation_id: Some(format!("{number:032x}")),
        usage: original_usage(&profile, "8:1", &input.binding, &source_sha256, false).unwrap(),
    };
    let source = TypedOperationSource {
        schema_version: 1,
        request_sha256: hash(format!("software index Start rpc {number}").as_bytes()),
        purpose: SourcePurpose::IndexPrepare,
        profile,
        storage_device: "8:1".into(),
        binding: input.binding.clone(),
        worker_pid: std::process::id(),
        worker_start: 1,
        worker_label: "luma-acquisition (enforce)".into(),
        lease: crate::resources::Token {
            lease_id: "88".repeat(16),
            generation: 1,
            manager_epoch: "99".repeat(16),
        },
    };
    (audit, source)
}

/// Each migrated owner costs a real bounded migration, so one owner first
/// proves every refusal leaves C untouched and then takes the reservation.
/// The same owner then proves every job-selection refusal leaves C and the
/// store untouched, and takes the selection.
#[test]
fn actual_index_start_refuses_substitutes_before_nv_then_one_dispatch_cold_reopen_replays() {
    let fixture = Fixture::new();
    let Migrated {
        owner,
        store,
        mut authority,
        head,
        ..
    } = migrated(&fixture, true);
    assert_eq!(
        head.roots.pending.entry_count, 1,
        "migration keeps only its legacy pending marker"
    );
    assert!(
        Job::start_warning(&head).is_some(),
        "the original approves a warned Start review"
    );
    let current = builder();
    let input = start(&owner.binding, &head, "1");
    let (audit, source) = original(&input, &head, &current.0, 500);
    let mut publish = source.clone();
    publish.purpose = SourcePurpose::Publish;
    let mut label = source.clone();
    label.worker_label = "software-fixed-worker".into();
    let mut anonymous = audit.clone();
    anonymous.operation_id = None;
    // A self-consistent Start that expects a different owner head than the
    // one C selects.
    let other = OwnerHeadV2::empty_data(&owner.binding, PhysicalInventory::default()).unwrap();
    assert_ne!(other.sha256().unwrap(), head.sha256().unwrap());
    let stale = start(&owner.binding, &other, "1");
    let (stale_audit, stale_source) = original(&stale, &other, &current.0, 501);
    let cases = [
        (&input, audit.clone(), publish, true),
        (&input, audit.clone(), label, true),
        (&input, anonymous, source.clone(), true),
        (&stale, stale_audit, stale_source, true),
        (&input, audit.clone(), source.clone(), false),
    ];
    for (input, audit, source, live) in cases {
        let calls = fixture.memory.0.borrow().calls;
        let mut check = || {
            if live {
                Ok(())
            } else {
                Err("software original revoked".into())
            }
        };
        assert!(cold(&fixture)
            .unwrap()
            .reserve_index_start_direct(
                input,
                &current,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
    }
    let before = cold(&fixture).unwrap();
    let base = before.descriptor().clone();
    assert!(matches!(
        base.operation,
        OperationData::OwnerMigration { .. }
    ));
    assert_eq!(base.roots.index_generations.entry_count, 0);
    let calls = fixture.memory.0.borrow().calls;
    let mut check = || Ok(());
    let reservation = before
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 1,
        "one NV dispatch per Start"
    );
    let reopened = cold(&fixture).expect("cold reopen replays the selected Start reservation");
    let selected = reopened.descriptor();
    match &selected.operation {
        OperationData::IndexJobReservation {
            binding,
            input_sha256,
            reservation: retained,
            original_authority,
            ..
        } => {
            assert_eq!(binding, &owner.binding);
            assert_eq!(input_sha256, &input.sha256().unwrap());
            assert_eq!(retained, &reservation);
            assert_eq!(original_authority, &audit);
        }
        _ => panic!("cold reopen did not select the Start reservation"),
    }
    assert_eq!(selected.sequence, base.sequence + 1);
    assert_eq!(selected.roots.owners, base.roots.owners);
    assert_eq!(selected.roots.index_generations.entry_count, 1);
    // A second first job over the C-selected reservation is refused before NV.
    let again = start(&owner.binding, &head, "3");
    let (audit, source) = original(&again, &head, &current.0, 502);
    let mut check = || Ok(());
    assert!(reopened
        .reserve_index_start_direct(
            &again,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    cold(&fixture).expect("the refused Start leaves the selected reservation");
    // The reserved first job becomes the selected job under a new original.
    // Every substitute is refused before any store write or NV dispatch.
    let (job_bytes, job) = first_job(&input, &head, &current.0);
    let stored = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    let (audit, source) = original(&input, &head, &current.0, 503);
    let (reused_audit, reused_source) = original(&input, &head, &current.0, 500);
    let (again_audit, again_source) = original(&again, &head, &current.0, 504);
    let substituted = Fixed(BuilderIdentity {
        source_sha256: "f".repeat(64),
        runtime_sha256: "e".repeat(64),
    });
    let mut publish = source.clone();
    publish.purpose = SourcePurpose::Publish;
    let cases: [(&request::Input, &Fixed, Audit, TypedOperationSource, bool); 5] = [
        (&input, &current, reused_audit, reused_source, true),
        (&input, &substituted, audit.clone(), source.clone(), true),
        (&again, &current, again_audit, again_source, true),
        (&input, &current, audit.clone(), publish, true),
        (&input, &current, audit.clone(), source.clone(), false),
    ];
    for (input, builder, audit, source, live) in cases {
        let mut check = || {
            if live {
                Ok(())
            } else {
                Err("software original revoked".into())
            }
        };
        assert!(cold(&fixture)
            .unwrap()
            .select_index_start_direct(
                &store,
                input,
                builder,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert_eq!(
            fixture.memory.0.borrow().calls,
            calls + 1,
            "refused before NV"
        );
        assert_eq!(
            store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
            stored,
            "refused before any store write"
        );
    }
    let before = cold(&fixture).unwrap();
    let reserved = before.descriptor().clone();
    let mut check = || Ok(());
    let selection = before
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 2,
        "one NV dispatch per job selection"
    );
    let after = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    assert!(
        after.regular_files > stored.regular_files
            && after.allocated_bytes > stored.allocated_bytes
            && after.incomplete_objects == stored.incomplete_objects,
        "the job blob is complete in the store before the sole dispatch"
    );
    assert_eq!(
        store.read_blob(&job, read(), &mut authority).unwrap(),
        job_bytes
    );
    let reopened = cold(&fixture).expect("cold reopen replays the selected job selection");
    let selected = reopened.descriptor();
    match &selected.operation {
        OperationData::IndexJobSelection {
            binding,
            input_sha256,
            selection: retained,
            original_authority,
            ..
        } => {
            assert_eq!(binding, &owner.binding);
            assert_eq!(input_sha256, &input.sha256().unwrap());
            assert_eq!(retained, &selection);
            assert_eq!(original_authority, &audit);
        }
        _ => panic!("cold reopen did not select the job selection"),
    }
    assert_eq!(selected.sequence, reserved.sequence + 1);
    assert_ne!(
        selected.roots.owners, reserved.roots.owners,
        "the owner leaf takes the measured store accounting"
    );
    assert_eq!(
        selected.roots.owners.entry_count,
        reserved.roots.owners.entry_count
    );
    assert_ne!(
        selected.roots.index_generations,
        reserved.roots.index_generations
    );
    assert_eq!(selected.roots.index_generations.entry_count, 1);
    // Neither a second selection nor a second Start is accepted over the
    // selected job, and the store does not change.
    let (audit, source) = original(&input, &head, &current.0, 505);
    let mut check = || Ok(());
    assert!(reopened
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    let (audit, source) = original(&again, &head, &current.0, 506);
    let mut check = || Ok(());
    assert!(cold(&fixture)
        .unwrap()
        .reserve_index_start_direct(
            &again,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls + 2);
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        after
    );
    cold(&fixture).expect("the refused attempts leave the selected job");
}

/// A crashed selection can leave the job blob in the store with nothing
/// selected. The store then differs from the C-selected owner accounting, so
/// a retry is refused before any further store write or NV dispatch and the
/// reservation stays selected. Reconciling such an attempt is later G3 work.
#[test]
fn actual_index_job_selection_over_a_store_ahead_of_c_is_refused_before_nv() {
    let fixture = Fixture::new();
    let Migrated {
        owner,
        store,
        mut authority,
        head,
        ..
    } = migrated(&fixture, true);
    let current = builder();
    let input = start(&owner.binding, &head, "1");
    let (audit, source) = original(&input, &head, &current.0, 800);
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    // The interrupted attempt's only effect: the exact job blob, no C event.
    let (job_bytes, job) = first_job(&input, &head, &current.0);
    let written = store
        .prepare_blob(
            &job_bytes,
            IoBudget {
                read_bytes: 1024 * 1024,
                write_bytes: 1024 * 1024,
                new_files: 16,
            },
            &Mutation {
                review_sha256: "cc".repeat(32),
                decision: DecisionKind::Published,
                source_bytes: job_bytes.len() as u64,
            },
            &mut authority,
        )
        .unwrap();
    assert_eq!(written, job);
    let ahead = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    let calls = fixture.memory.0.borrow().calls;
    let (audit, source) = original(&input, &head, &current.0, 801);
    let mut check = || Ok(());
    assert!(cold(&fixture)
        .unwrap()
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        ahead
    );
    let reopened = cold(&fixture).expect("the refused selection leaves the reservation");
    assert!(matches!(
        reopened.descriptor().operation,
        OperationData::IndexJobReservation { .. }
    ));
}

/// Old and third-NV dispatch faults are the shared fenced dispatch already
/// exercised on the worker and migration routes; the index route keeps the
/// lost actual reply, where NV advanced and nothing may be adopted.
#[test]
fn actual_index_start_lost_nv_reply_is_fenced_without_adoption() {
    let fixture = Fixture::new();
    let Migrated { owner, head, .. } = migrated(&fixture, true);
    let current = builder();
    let input = start(&owner.binding, &head, "1");
    let (audit, source) = original(&input, &head, &current.0, 700);
    let calls = fixture.memory.0.borrow().calls;
    let backend = cold(&fixture).unwrap();
    fixture.memory.0.borrow_mut().fault = Fault::Lost;
    let mut check = || Ok(());
    assert!(backend
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert!(cold(&fixture).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1, "no redispatch");
}
