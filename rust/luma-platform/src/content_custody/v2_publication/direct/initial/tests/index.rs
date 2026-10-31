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
use luma_content_store::{Access, Boundary, DecisionKind, ResourceBudget};
use std::path::Path;

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

/// The actual path of one object in the owner's single v2 store.
fn object_path(fixture: &Fixture, sha256: &str) -> PathBuf {
    let roots: Vec<PathBuf> = fs::read_dir(&fixture.data)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("v2-"))
        })
        .collect();
    assert_eq!(roots.len(), 1, "one v2 store under the fixture data");
    roots[0]
        .join("objects")
        .join(&sha256[..2])
        .join(&sha256[2..4])
        .join(sha256)
}
/// Whether the object holds all of its bytes, as it does right after its last
/// part is written and before it is synchronized.
fn written(path: &Path, bytes: u32) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.len() == u64::from(bytes))
}
/// A crash right after one object's last write: every later check refuses, so
/// that object is complete and nothing after it is written.
struct Interrupted<'a, B> {
    inner: &'a mut B,
    path: PathBuf,
    bytes: u32,
}
impl<B: Boundary> Boundary for Interrupted<'_, B> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        self.inner.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        if written(&self.path, self.bytes) {
            return Err("software crash after a reserved job member".into());
        }
        self.inner.check(access)
    }
}

/// Crashed selections can leave members of the reserved job blob in the
/// store with nothing selected. One crash leaves only the first member; the
/// actual worker under a new original is then revoked right after it writes
/// the last. Each retry walks the store, admits it as the C-selected
/// accounting plus complete reserved members, re-reads those members and
/// writes only the missing ones. The reservation's own original is refused,
/// and the final retry reconciles with one NV dispatch and nothing more
/// written. Partial and foreign members are refused before NV; the pure
/// attribution test covers them, since no retry may adopt or remove them.
#[test]
fn actual_index_job_selection_reconciles_complete_members_of_interrupted_attempts() {
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
    let (reserved_audit, reserved_source) = (audit.clone(), source.clone());
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let calls = fixture.memory.0.borrow().calls;
    let (job_bytes, job) = first_job(&input, &head, &current.0);
    let members = BlobObjectPlan::data(&input.binding, &job_bytes, || Ok(()))
        .unwrap()
        .write_set(|| Ok(()))
        .unwrap();
    assert_eq!(members.len(), 3, "one chunk, one group and the blob index");
    let paths: Vec<PathBuf> = members
        .iter()
        .map(|member| object_path(&fixture, &member.sha256))
        .collect();
    assert!(paths.iter().all(|path| !path.exists()));
    let stored = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    // The first crash's only effect: the first member, complete, no C event.
    assert!(store
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
            &mut Interrupted {
                inner: &mut authority,
                path: paths[0].clone(),
                bytes: members[0].bytes,
            },
        )
        .is_err());
    assert!(written(&paths[0], members[0].bytes) && !paths[1].exists() && !paths[2].exists());
    let ahead = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    assert_eq!(ahead.regular_files, stored.regular_files + 1);
    assert_eq!(ahead.incomplete_objects, stored.incomplete_objects);
    // The reservation's own original never selects, even over its members.
    let mut check = || Ok(());
    assert!(cold(&fixture)
        .unwrap()
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&reserved_audit, reserved_source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        ahead,
        "refused before any store write"
    );
    // The actual worker reuses the first member, writes the other two and is
    // revoked right after the last one: the blob is complete, nothing selected.
    let (audit, source) = original(&input, &head, &current.0, 801);
    let last = (paths[2].clone(), members[2].bytes);
    let mut check = || {
        if written(&last.0, last.1) {
            Err("software original revoked after the last reserved member".into())
        } else {
            Ok(())
        }
    };
    assert!(cold(&fixture)
        .unwrap()
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls, "revoked before NV");
    let complete = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    assert_eq!(complete.regular_files, stored.regular_files + 3);
    assert_eq!(complete.incomplete_objects, stored.incomplete_objects);
    assert_eq!(
        store.read_blob(&job, read(), &mut authority).unwrap(),
        job_bytes
    );
    let before = cold(&fixture).expect("the interrupted attempts leave the reservation");
    let reserved = before.descriptor().clone();
    assert!(matches!(
        reserved.operation,
        OperationData::IndexJobReservation { .. }
    ));
    // A new original reconciles: one dispatch, every member re-read, none
    // rewritten, and the cold reader replays the selection.
    let (audit, source) = original(&input, &head, &current.0, 802);
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
        calls + 1,
        "one NV dispatch per job selection"
    );
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        complete,
        "nothing more is written"
    );
    assert_eq!(
        store.read_blob(&job, read(), &mut authority).unwrap(),
        job_bytes
    );
    let reopened = cold(&fixture).expect("cold reopen replays the reconciled job selection");
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
        _ => panic!("cold reopen did not select the reconciled job selection"),
    }
    assert_eq!(selected.sequence, reserved.sequence + 1);
    assert_ne!(selected.roots.owners, reserved.roots.owners);
    assert_ne!(
        selected.roots.index_generations,
        reserved.roots.index_generations
    );
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
