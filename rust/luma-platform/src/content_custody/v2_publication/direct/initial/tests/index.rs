//! Actual first index job Start reservations, job selections, first phase
//! preparations and prepared window runs of the closed direct worker over a
//! real migrated V2 owner in a real bootstrapped C cut and its real v2 object
//! store. The builder identity, original worker attribution, planning boundary,
//! resources and NV are explicit software fixtures, not the installed image
//! builder or installed qualification.
use super::super::super::super::super::protocol::{
    software_worker_operation, OriginalCOperation, TypedOperationSource,
};
use super::super::super::backend::{verify_index_phase, verify_index_preparation, Backend};
use super::super::super::reader::observe;
use super::migration_cases::{migrated, Migrated, BODY};
use super::progress_cases::ContentGuard;
use super::worker_cases::{attribution, cold, provenance, worker};
use super::*;
use crate::content_checkpoint::custody::indexed::{
    selection_data_sha256, TransitionBase, TransitionReview,
};
use crate::content_checkpoint::custody::v2_publication::index::effects::CurrentBuilder;
use crate::content_index::scope::original_usage;
use crate::content_index::state::Job;
use crate::content_index::{phase, request};
use luma_content::{EditOrigin, Format};
use luma_content_store::corpus_index::job::accounted::{
    CapturedPageMeasurements, PageAccountingBoundary, PageDebitCommitment, PageReserve,
};
use luma_content_store::corpus_index::job::covariance::projection::vectors::generation::audit::{
    AuditCommitment, AuditProgress, GenerationAuditBoundary,
};
use luma_content_store::corpus_index::job::covariance::projection::vectors::generation::{
    CurrentGenerationBoundary, GenerationCommitment, GenerationJob, GenerationManifest,
    GenerationPublicationBoundary, GenerationReview,
};
use luma_content_store::corpus_index::job::covariance::projection::vectors::{
    VectorBoundary, VectorCommitment, VectorProgress, VectorRequest,
};
use luma_content_store::corpus_index::job::covariance::projection::{
    ProjectionBoundary, ProjectionCommitment, ProjectionProgress, ProjectionRequest,
};
use luma_content_store::corpus_index::job::covariance::{
    CovarianceBoundary, CovarianceCommitment, CovarianceProgress, CovarianceRequest,
};
use luma_content_store::corpus_index::job::statistics::{
    StatisticsBoundary, StatisticsCommitment, StatisticsProgress, StatisticsRequest,
};
use luma_content_store::corpus_index::job::{
    CorpusIndexJobBoundary, IngestCommitment, IngestProgress, IngestRequest,
};
use luma_content_store::corpus_index::{
    BuilderIdentity, CorpusContent, CorpusIndexBoundary, CorpusIndexLimits, CorpusRecord,
};
use luma_content_store::v2::{
    BlobObjectPlan, IoBudget, MapRoot, Mutation, ObjectStore, PhysicalInventory,
};
use luma_content_store::{Access, Boundary, DecisionKind, Plan, Repository, ResourceBudget};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
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
    effect(
        input,
        &review,
        "explicit-software-direct-index-start",
        &format!("software index Start rpc {number}"),
        number,
    )
}
/// One original worker effect over an exact reviewed request: the finite
/// profile, usage and source all bind that request and review.
fn effect(
    input: &request::Input,
    review: &str,
    grant: &str,
    rpc: &str,
    number: u64,
) -> (Audit, TypedOperationSource) {
    let profile = input.effect_profile(review).unwrap();
    let source_sha256 = input.sha256().unwrap();
    let audit = Audit {
        subject: input.binding.owner.clone(),
        subject_generation: input.binding.owner_generation,
        grant_id: grant.into(),
        grant_version: 1,
        checkpoint_head: "33".repeat(32),
        operation_id: Some(format!("{number:032x}")),
        usage: original_usage(&profile, "8:1", &input.binding, &source_sha256, false).unwrap(),
    };
    let source = TypedOperationSource {
        schema_version: 1,
        request_sha256: hash(rpc.as_bytes()),
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
/// The reconciled selection is then an ordinary selected cut: the first phase
/// prepares over it and a brand-new owner's first V1 publication is dispatched
/// over that preparation, which stays charged. The prepared window then runs
/// over the V1's advanced cut and resolves the charge. Each migrated owner costs
/// a real bounded migration, so this owner carries those steps too.
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
    let first = Job::beginning_data(
        &input,
        &head,
        &current.0,
        &selection_data_sha256(&head, None).unwrap(),
    )
    .unwrap();
    let step_input = step(&owner.binding, &first, "4");
    let planned = plan(&store, &first, &step_input);
    let grant = "explicit-software-direct-index-phase";
    let (audit, source) = effect(
        &step_input,
        &planned.review().unwrap().review_sha256,
        grant,
        "software index phase rpc 803",
        803,
    );
    let mut check = || Ok(());
    reopened
        .prepare_index_direct(
            &step_input,
            &planned,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let prepared = cold(&fixture).expect("a preparation replays over the reconciled selection");
    let preparation = prepared.descriptor().clone();
    assert!(matches!(
        preparation.operation,
        OperationData::IndexPreparation { .. }
    ));
    let calls = fixture.memory.0.borrow().calls;
    publish_second_owner(&fixture, prepared, 804);
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 1,
        "one NV dispatch for the V1 publication"
    );
    let published = cold(&fixture).expect("cold V1 replay continues a selected preparation");
    let after = published.descriptor().clone();
    assert!(matches!(
        after.operation,
        OperationData::V1Publication { .. }
    ));
    assert_eq!(after.sequence, preparation.sequence + 1);
    assert_eq!(after.previous_nv_head, preparation.selected_nv_head);
    assert_eq!(
        after.roots.owners.entry_count,
        preparation.roots.owners.entry_count + 1
    );
    assert_eq!(
        after.roots.index_generations,
        preparation.roots.index_generations
    );
    // The preparation stays charged over the V1: a second one is refused.
    let other = step(&owner.binding, &first, "5");
    let other_plan = plan(&store, &first, &other);
    let (audit, source) = effect(
        &other,
        &other_plan.review().unwrap().review_sha256,
        grant,
        "software index phase rpc 805",
        805,
    );
    let mut check = || Ok(());
    let refusal = published
        .prepare_index_direct(
            &other,
            &other_plan,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .err()
        .expect("the selected preparation stays charged over the V1 publication");
    assert!(refusal.to_string().contains("must remain charged"));
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    // The cut advanced past the preparation, not its owner or accounting, so
    // its window still runs under a new original and replays over the V1.
    let (audit, source) = effect(
        &step_input,
        &planned.review().unwrap().review_sha256,
        grant,
        "software index phase run rpc 806",
        806,
    );
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .run_index_phase_direct(
            &store,
            &first,
            &step_input,
            plan(&store, &first, &step_input),
            &mut Sources {
                binding: step_input.binding.clone(),
            },
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 2,
        "one NV dispatch for the window"
    );
    let ran = cold(&fixture).expect("cold reopen replays a window run over the V1");
    assert!(matches!(
        ran.descriptor().operation,
        OperationData::IndexPhaseSelection { .. }
    ));
    assert_eq!(ran.descriptor().sequence, after.sequence + 1);
    assert_ne!(ran.descriptor().roots.owners, after.roots.owners);
    assert_ne!(
        ran.descriptor().roots.index_generations,
        after.roots.index_generations
    );
    // The reader checks the selected frame and the one before it, so damage to
    // the V1 under the selected run is refused with no repair or dispatch. Its
    // change time cannot be restored, so this ends the fixture.
    let slot = &after.storage.as_ref().unwrap().descriptor_slot;
    damage(&fixture, &slot.job, slot.number);
    let refusal = cold(&fixture)
        .err()
        .expect("a damaged previous frame refuses the cold reader")
        .to_string();
    assert!(refusal.contains("sealed tail inode change-time differs"));
    assert_eq!(fixture.memory.0.borrow().calls, calls + 2);
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

fn refused() -> luma_content_store::Result<()> {
    Err("software planning guard refuses every effect and later phase".into())
}
/// A read-only software planning boundary over the exact C-selected first job
/// and one Step request. It admits only finite owner inspection of that job's
/// own corpus and builder, and refuses every effect and later phase.
struct Guard<'a> {
    job: &'a Job,
    input: &'a request::Input,
}
impl Guard<'_> {
    fn ingestion(&self) -> luma_content_store::Result<&IngestRequest> {
        Ok(self.job.lineage()?.ingestion.0)
    }
}
impl Boundary for Guard<'_> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if binding != &self.job.source_owner.binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("software planning guard admits only finite owner reads".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        if !matches!(access, Access::Inspect { binding } if binding == &self.job.source_owner.binding)
        {
            return Err("software planning guard cannot mutate, recover or substitute".into());
        }
        Ok(())
    }
}
impl CorpusIndexBoundary for Guard<'_> {
    fn current_corpus(&mut self, root: &MapRoot) -> luma_content_store::Result<()> {
        if root != &self.ingestion()?.corpus || root != &self.job.source_owner.roots.corpus {
            return Err("software planning guard refuses a substituted corpus".into());
        }
        Ok(())
    }
    fn current_builder(
        &mut self,
        root: &MapRoot,
        identity: &BuilderIdentity,
    ) -> luma_content_store::Result<()> {
        self.current_corpus(root)?;
        if identity != &self.ingestion()?.builder || identity != &self.job.builder {
            return Err("software planning guard refuses a substituted builder".into());
        }
        Ok(())
    }
    fn current_index_generation(&mut self, _: &MapRoot, _: &str) -> luma_content_store::Result<()> {
        refused()
    }
    fn current_candidate(
        &mut self,
        root: &MapRoot,
        record: &CorpusRecord,
    ) -> luma_content_store::Result<()> {
        self.current_corpus(root)?;
        record.validate()
    }
}
impl CorpusIndexJobBoundary for Guard<'_> {
    fn current_job(
        &mut self,
        request: &IngestRequest,
        progress: &IngestProgress,
    ) -> luma_content_store::Result<()> {
        if self.job.lineage()?.ingestion != (request, progress) {
            return Err("software planning guard refuses a substituted ingestion".into());
        }
        Ok(())
    }
    fn verify_ingest_allocations(
        &mut self,
        _: &IngestCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl StatisticsBoundary for Guard<'_> {
    fn current_statistics(
        &mut self,
        _: &StatisticsRequest,
        _: &StatisticsProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_statistics_allocations(
        &mut self,
        _: &StatisticsCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl CovarianceBoundary for Guard<'_> {
    fn current_covariance(
        &mut self,
        _: &CovarianceRequest,
        _: &CovarianceProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_covariance_allocations(
        &mut self,
        _: &CovarianceCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl ProjectionBoundary for Guard<'_> {
    fn current_projection(
        &mut self,
        _: &ProjectionRequest,
        _: &ProjectionProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_projection_allocations(
        &mut self,
        _: &ProjectionCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl VectorBoundary for Guard<'_> {
    fn current_vectors(
        &mut self,
        _: &VectorRequest,
        _: &VectorProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_vector_allocations(
        &mut self,
        _: &VectorCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl GenerationAuditBoundary for Guard<'_> {
    fn current_generation_audit(
        &mut self,
        _: &GenerationJob,
        _: &AuditProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_audit_reservations(&mut self, _: &AuditCommitment) -> luma_content_store::Result<()> {
        refused()
    }
}
impl GenerationPublicationBoundary for Guard<'_> {
    fn verify_original_phase_provenance(
        &mut self,
        _: &GenerationJob,
        _: &AuditProgress,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn reserve_generation(&mut self, _: &GenerationReview) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_generation_allocations(
        &mut self,
        _: &GenerationCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn release_generation_after_selection(
        &mut self,
        _: &GenerationCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl CurrentGenerationBoundary for Guard<'_> {
    fn current_generation(&mut self, _: &GenerationManifest) -> luma_content_store::Result<()> {
        refused()
    }
}
impl PageAccountingBoundary for Guard<'_> {
    fn reserve_pages(&mut self, _: &PageReserve) -> luma_content_store::Result<()> {
        refused()
    }
    fn observe_pages(
        &mut self,
        _: &PageDebitCommitment,
        _: &CapturedPageMeasurements,
    ) -> luma_content_store::Result<()> {
        refused()
    }
    fn verify_pages(&mut self, _: &PageDebitCommitment) -> luma_content_store::Result<()> {
        refused()
    }
    fn release_pages_after_selection(
        &mut self,
        _: &PageDebitCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl phase::NativeIndexBoundary for Guard<'_> {
    fn current_native_job(&mut self, job: &Job) -> Result<()> {
        if job != self.job {
            return Err("software planning guard refuses a substituted job".into());
        }
        Ok(())
    }
    fn current_native_operation(&mut self, input: &request::Input) -> Result<()> {
        if input != self.input {
            return Err("software planning guard refuses a substituted request".into());
        }
        Ok(())
    }
    fn current_plan_review(&mut self, _: &request::Input, _: &str) -> Result<()> {
        refused()
    }
}
/// The migrated owner's one retained artifact, returned only for its exact
/// immutable digest and length after an owner inspection.
struct Sources {
    binding: OwnerBinding,
}
impl CorpusContent for Sources {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        boundary: &mut B,
    ) -> luma_content_store::Result<Vec<u8>> {
        boundary.check(Access::Inspect {
            binding: &self.binding,
        })?;
        if record.reference.content_sha256 != luma_content::sha256(BODY)
            || record.content_bytes != BODY.len() as u64
        {
            return Err("software source holds only the retained owner artifact".into());
        }
        Ok(BODY.to_vec())
    }
}
/// A source lost after the window's writes: the store re-verification that
/// reads it fails, so the attempt ends with every write ahead of C.
struct Stopped;
impl CorpusContent for Stopped {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        _: &CorpusRecord,
        _: &mut B,
    ) -> luma_content_store::Result<Vec<u8>> {
        Err("software source lost after the window writes".into())
    }
}
/// One ingestion Step over the exact selected first job.
fn step(binding: &OwnerBinding, job: &Job, id: &str) -> request::Input {
    request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding.clone(),
        request_id: id.repeat(32),
        operation: request::Operation::Step {
            job_id: "2".repeat(32),
            expected_job_sha256: job.sha256().unwrap(),
            window: request::Window {
                maximum: 1,
                read_bytes: 16 * 1024 * 1024,
                write_bytes: 16 * 1024 * 1024,
            },
        },
    }
}
/// The reconstructed ingestion plan of one Step, made by the real planner
/// over the real store under the read-only software guard.
fn plan(store: &ObjectStore, job: &Job, input: &request::Input) -> phase::Plan {
    phase::plan(
        store,
        job,
        input,
        &mut Sources {
            binding: input.binding.clone(),
        },
        &mut Guard { job, input },
    )
    .unwrap()
}

/// The exact selected descriptor location of the current cut.
fn selected_location(fixture: &Fixture) -> slots::SealedReference {
    let cut = observe(
        &mut fixture.memory.clone(),
        &fixture.pages(),
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    match cut.cell() {
        control::Cell::Selected { descriptor, .. } => descriptor.clone(),
        _ => panic!("the selected cut has no selected control cell"),
    }
}
/// The retained body of one selected preparation.
fn retained(descriptor: &mut Descriptor) -> ([&mut String; 3], &mut RecordRef, &mut Audit) {
    match &mut descriptor.operation {
        OperationData::IndexPreparation {
            request_sha256,
            input_sha256,
            source_sha256,
            preparation,
            original_authority,
            ..
        } => (
            [request_sha256, input_sha256, source_sha256],
            preparation,
            original_authority,
        ),
        _ => panic!("the forged candidate is not a phase preparation"),
    }
}
/// The retained body of one selected phase selection.
fn ran(descriptor: &mut Descriptor) -> ([&mut String; 3], &mut RecordRef, &mut Audit) {
    match &mut descriptor.operation {
        OperationData::IndexPhaseSelection {
            request_sha256,
            input_sha256,
            source_sha256,
            selection,
            original_authority,
            ..
        } => (
            [request_sha256, input_sha256, source_sha256],
            selection,
            original_authority,
        ),
        _ => panic!("the forged candidate is not a phase selection"),
    }
}
/// One candidate at one location, refused by the cold verifier.
fn refuses(
    fixture: &Fixture,
    candidate: &Descriptor,
    location: &slots::SealedReference,
    reason: &str,
) {
    let refusal = verify_index_preparation(&fixture.pages(), candidate, location, &mut || Ok(()))
        .err()
        .expect("the cold verifier refuses this candidate")
        .to_string();
    assert!(refusal.contains(reason), "{refusal}");
}
/// One candidate at one location, refused by the cold phase-selection verifier.
fn refuses_run(
    fixture: &Fixture,
    candidate: &Descriptor,
    location: &slots::SealedReference,
    reason: &str,
) {
    let refusal = verify_index_phase(&fixture.pages(), candidate, location, &mut || Ok(()))
        .err()
        .expect("the cold verifier refuses this candidate")
        .to_string();
    assert!(refusal.contains(reason), "{refusal}");
}
/// One forged copy of a selected descriptor. Sealing recomputes its event
/// digest and NV continuation and its location commits its own frame, so the
/// refusal is of the forged field and not of those.
fn sealed(
    selected: &Descriptor,
    location: &slots::SealedReference,
    change: impl FnOnce(&mut Descriptor),
) -> (Descriptor, slots::SealedReference) {
    let mut candidate = selected.clone();
    change(&mut candidate);
    let candidate = candidate.seal().unwrap();
    let mut location = location.clone();
    location.slot = candidate.storage.as_ref().unwrap().descriptor_slot.clone();
    location.sha256 = hash(&candidate.slot_frame().unwrap());
    (candidate, location)
}
fn forged(
    fixture: &Fixture,
    selected: &Descriptor,
    location: &slots::SealedReference,
    reason: &str,
    change: impl FnOnce(&mut Descriptor),
) {
    let (candidate, location) = sealed(selected, location, change);
    refuses(fixture, &candidate, &location, reason);
}
/// Forged candidates reach the cold verifier directly, since no selected C cut
/// can carry one to the reader: selecting it would take re-sealed slots, control
/// cells and NV. The honest cut is the control, so each refusal is its forgery's.
fn refuse_forged_preparations(
    fixture: &Fixture,
    selected: &Descriptor,
    location: &slots::SealedReference,
    job: &Descriptor,
    job_location: &slots::SealedReference,
) {
    verify_index_preparation(&fixture.pages(), selected, location, &mut || Ok(()))
        .expect("the honest selected preparation is the control");
    let exact = "is not its exact selected descriptor location";
    let lineage = "does not continue the exact authenticated old cut";
    let lost = "lost the exact selected previous descriptor address";
    let body = "substitutes exact checkpointed source/attribution/before tuple";
    let layout = "differs from its deterministic reviewed layout";
    let unsealed = "sealed tail data hash or exact EOF differs";
    let job_storage = job.storage.as_ref().unwrap();
    let forge = |reason: &str, change: &dyn Fn(&mut Descriptor)| {
        forged(fixture, selected, location, reason, change)
    };
    let mut absent = selected.clone();
    absent.storage = None;
    refuses(
        fixture,
        &absent.seal().unwrap(),
        location,
        "has no selected storage",
    );
    let mut short = location.clone();
    short.bytes -= 1;
    refuses(fixture, selected, &short, exact);
    let mut substituted = location.clone();
    substituted.sha256 = "ab".repeat(32);
    refuses(fixture, selected, &substituted, exact);
    let mut moved = location.clone();
    moved.slot.number += 1;
    refuses(fixture, selected, &moved, exact);
    let mut stale = location.clone();
    stale.sealed_ctime_nanoseconds ^= 1;
    refuses(
        fixture,
        selected,
        &stale,
        "sealed tail inode change-time differs from selected immutable seal",
    );
    forge(exact, &|candidate| {
        let storage = candidate.storage.as_mut().unwrap();
        storage.schema_version = 1;
        storage.jobs = None;
        storage.parent_allocation = None;
    });
    // Only bootstrap progress may be sequence one, so this cannot be sealed and
    // the verifier's own validation refuses it.
    let mut first = selected.clone();
    first.sequence = 1;
    first.global_ordinal = first.legacy.events + 2;
    first.previous_descriptor_sha256 = None;
    refuses(
        fixture,
        &first,
        location,
        "event/NV/ordinal continuation differs",
    );
    refuses(
        fixture,
        job,
        job_location,
        "refuses a different semantic event class",
    );
    forge(lost, &|candidate| {
        candidate.previous_descriptor_sha256 = Some("ab".repeat(32));
    });
    forge(lost, &|candidate| {
        candidate.storage.as_mut().unwrap().locations = job_storage.locations.clone();
    });
    forge(lineage, &|candidate| {
        candidate.previous_descriptor_sha256 = job.previous_descriptor_sha256.clone();
    });
    forge(lineage, &|candidate| {
        candidate.sequence += 1;
        candidate.global_ordinal += 1;
    });
    forge(lineage, &|candidate| {
        candidate.previous_nv_head = "ab".repeat(32);
    });
    forge(lineage, &|candidate| {
        candidate.legacy.journal_sha256 = "ab".repeat(32);
    });
    forge("unrelated C roots", &|candidate| {
        candidate.roots.owners.page.as_mut().unwrap().sha256 = "ab".repeat(32);
    });
    forge("role CAS differs", &|candidate| {
        candidate.roots.index_generations = job.roots.index_generations.clone();
    });
    for field in 0..3 {
        forge(body, &|candidate| {
            *retained(candidate).0[field] = "ab".repeat(32);
        });
    }
    forge(body, &|candidate| {
        retained(candidate).2.checkpoint_head = "ab".repeat(32);
    });
    forge("no selected immutable record address", &|candidate| {
        retained(candidate).1.sha256 = "ab".repeat(32);
    });
    forge("record complete bytes changed", &|candidate| {
        retained(candidate).1.bytes -= 1;
    });
    forge(layout, &|candidate| {
        let controls = &mut candidate.storage.as_mut().unwrap().controls;
        controls.cells[0].instance_id = "ab".repeat(32);
    });
    forge(layout, &|candidate| {
        candidate.storage.as_mut().unwrap().descriptor_slot.job = "ab".repeat(32);
    });
    forge("no selected allocation manifest", &|candidate| {
        candidate.storage.as_mut().unwrap().jobs = job_storage.jobs.clone();
    });
    // The closure reads the forged frame's own sealed location before it
    // reaches the delta and inventory checks, so a frame that is not the one on
    // disk stops there. The honest cut over a disturbed store reaches them.
    forge(unsealed, &|candidate| {
        candidate.storage.as_mut().unwrap().post_allocation.files += 1;
    });
    forge(unsealed, &|candidate| {
        candidate.storage.as_mut().unwrap().parent_allocation = None;
    });
}
/// The same closure over the selected event that resolves a preparation. The
/// honest cut is the control. Its record names the store's next job and
/// candidate; those are selected DATA, so no forgery of them can be replayed
/// from C alone and none is listed here. Both after roles are read back against
/// the canonical retained data first, so only a root with those exact values and
/// a different tree reaches the whole-root comparison, and that takes selected
/// pages no forged frame has.
fn refuse_forged_runs(
    fixture: &Fixture,
    selected: &Descriptor,
    location: &slots::SealedReference,
    prepared: &Descriptor,
    prepared_location: &slots::SealedReference,
) {
    verify_index_phase(&fixture.pages(), selected, location, &mut || Ok(()))
        .expect("the honest selected phase selection is the control");
    let exact = "is not its exact selected descriptor location";
    let lineage = "does not continue the exact authenticated old cut";
    let lost = "lost the exact selected previous descriptor address";
    let body = "substitutes exact checkpointed source/attribution/before tuple";
    let role = "role CAS differs";
    let layout = "differs from its deterministic reviewed layout";
    let unsealed = "sealed tail data hash or exact EOF differs";
    let prepared_storage = prepared.storage.as_ref().unwrap();
    let forge = |reason: &str, change: &dyn Fn(&mut Descriptor)| {
        let (candidate, location) = sealed(selected, location, change);
        refuses_run(fixture, &candidate, &location, reason);
    };
    let mut absent = selected.clone();
    absent.storage = None;
    refuses_run(
        fixture,
        &absent.seal().unwrap(),
        location,
        "has no selected storage",
    );
    let mut short = location.clone();
    short.bytes -= 1;
    refuses_run(fixture, selected, &short, exact);
    let mut substituted = location.clone();
    substituted.sha256 = "ab".repeat(32);
    refuses_run(fixture, selected, &substituted, exact);
    refuses_run(
        fixture,
        prepared,
        prepared_location,
        "refuses a different semantic event class",
    );
    forge(lost, &|candidate| {
        candidate.previous_descriptor_sha256 = Some("ab".repeat(32));
    });
    forge(lost, &|candidate| {
        candidate.storage.as_mut().unwrap().locations = prepared_storage.locations.clone();
    });
    forge(lineage, &|candidate| {
        candidate.previous_descriptor_sha256 = prepared.previous_descriptor_sha256.clone();
    });
    forge(lineage, &|candidate| {
        candidate.sequence += 1;
        candidate.global_ordinal += 1;
    });
    forge(lineage, &|candidate| {
        candidate.previous_nv_head = "ab".repeat(32);
    });
    forge("no selected semantic page address", &|candidate| {
        candidate.roots.owners.page.as_mut().unwrap().sha256 = "ab".repeat(32);
    });
    forge("unrelated C roots", &|candidate| {
        let mut signers = candidate.roots.owners.clone();
        signers.kind = map::Kind::Signers;
        candidate.roots.signers = signers;
    });
    forge(role, &|candidate| {
        candidate.roots.owners = prepared.roots.owners.clone();
    });
    forge(role, &|candidate| {
        candidate.roots.index_generations = prepared.roots.index_generations.clone();
    });
    forge(body, &|candidate| {
        *ran(candidate).0[0] = "ab".repeat(32);
    });
    forge("retained owner/preparation/input", &|candidate| {
        *ran(candidate).0[1] = "ab".repeat(32);
    });
    forge(body, &|candidate| {
        *ran(candidate).0[2] = "ab".repeat(32);
    });
    forge(body, &|candidate| {
        ran(candidate).2.checkpoint_head = "ab".repeat(32);
    });
    forge("no selected immutable record address", &|candidate| {
        ran(candidate).1.sha256 = "ab".repeat(32);
    });
    forge("record complete bytes changed", &|candidate| {
        ran(candidate).1.bytes -= 1;
    });
    forge(layout, &|candidate| {
        let controls = &mut candidate.storage.as_mut().unwrap().controls;
        controls.cells[0].instance_id = "ab".repeat(32);
    });
    forge(layout, &|candidate| {
        candidate.storage.as_mut().unwrap().descriptor_slot.job = "ab".repeat(32);
    });
    forge("no selected allocation manifest", &|candidate| {
        candidate.storage.as_mut().unwrap().jobs = prepared_storage.jobs.clone();
    });
    forge(unsealed, &|candidate| {
        candidate.storage.as_mut().unwrap().post_allocation.files += 1;
    });
    forge(unsealed, &|candidate| {
        candidate.storage.as_mut().unwrap().parent_allocation = None;
    });
}
/// One disturbed store, refused by the verifier and the cold reader with no
/// repair or dispatch.
fn disturbed(
    fixture: &Fixture,
    selected: &Descriptor,
    location: &slots::SealedReference,
    reason: &str,
) {
    let calls = fixture.memory.0.borrow().calls;
    refuses(fixture, selected, location, reason);
    let refusal = cold(fixture)
        .err()
        .expect("a disturbed store refuses the cold reader")
        .to_string();
    assert!(refusal.contains(reason), "{refusal}");
    assert_eq!(fixture.memory.0.borrow().calls, calls);
}
/// One torn page a crash left behind, a member of no selected cut.
fn partial_page(fixture: &Fixture) {
    let leaf = fixture.pages().root.join("pages").join("cd").join("cd");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&leaf)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(leaf.join(format!("cdcd{}", "ab".repeat(30))))
        .unwrap()
        .write_all_at(b"partial", 0)
        .unwrap();
}
/// Flips one byte of one sealed retained member in place.
fn damage(fixture: &Fixture, job: &str, number: u32) {
    let member = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            fixture
                .pages()
                .root
                .join("tails")
                .join(job)
                .join(format!("{number:08x}")),
        )
        .unwrap();
    let mut byte = [0u8];
    member.read_exact_at(&mut byte, 0).unwrap();
    member.write_all_at(&[!byte[0]], 0).unwrap();
}
/// A brand-new second owner's first V1 publication over the current cut. The
/// migrated owner's data directory also holds the v2 object store, so this
/// owner has its own content repository.
fn publish_second_owner(fixture: &Fixture, current: Backend<Memory>, number: u64) {
    let binding = OwnerBinding {
        installation: fixture.binding.installation.clone(),
        owner: "55".repeat(32),
        owner_generation: 1,
    };
    let body = b"a second owner's first version over a selected index preparation";
    let capture = Plan::capture(
        binding.clone(),
        "document",
        Format::Utf8Text,
        body,
        provenance("direct-index-second-owner", body, EditOrigin::Managed),
    )
    .unwrap();
    let mut guard = ContentGuard {
        owner: binding.clone(),
        review: capture.review_sha256().into(),
    };
    let data = fixture.data.with_extension("second-owner");
    fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
    let mut repository = Repository::create_at(&data, &capture, &mut guard).unwrap();
    let held = repository.prepare(&capture, body, &mut guard).unwrap();
    let commitment = held.commitment().canonical_bytes().unwrap();
    let record = held.record_bytes().to_vec();
    let expected = held.commitment().outcome_state();
    let (profile, audit) = attribution(&binding, capture.review_sha256(), number);
    let source = worker(&binding, profile, &commitment);
    let mut check = || Ok(());
    let state = current
        .publish_v1_direct(
            &commitment,
            &record,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(state, expected);
    held.publish(&mut guard).unwrap();
    assert_eq!(repository.verified_state(&mut guard).unwrap(), state);
    drop(repository);
    fs::remove_dir_all(&data).unwrap();
}

/// The selected first job's first ingestion phase is prepared under a new
/// original over the exact reconstructed plan. Every substitute is refused
/// before NV and leaves C and the store untouched; the preparation takes one
/// dispatch, writes nothing to the store, and the cold reader replays it. A
/// second preparation over the C-selected one is refused. Forged candidates
/// of the selected cut are then each refused by the cold verifier with nothing
/// changed. A window attempt that stops after its writes stays ahead of C with
/// no dispatch, the preparation still charged and its retry refused, and a torn
/// page, an unreviewed attempt and a damaged sealed member each refuse the
/// verifier and the cold reader.
#[test]
fn actual_index_phase_preparation_refuses_substitutes_before_nv_then_one_dispatch_cold_reopen_replays(
) {
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
    let (audit, source) = original(&input, &head, &current.0, 900);
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let (audit, source) = original(&input, &head, &current.0, 901);
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let calls = fixture.memory.0.borrow().calls;
    let stored = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    let job = Job::beginning_data(
        &input,
        &head,
        &current.0,
        &selection_data_sha256(&head, None).unwrap(),
    )
    .unwrap();
    let step_input = step(&owner.binding, &job, "4");
    let planned = plan(&store, &job, &step_input);
    let review = planned.review().unwrap();
    assert_eq!(review.base_sha256, job.sha256().unwrap());
    assert_eq!(review.input_sha256, step_input.sha256().unwrap());
    let grant = "explicit-software-direct-index-phase";
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase rpc 902",
        902,
    );
    let (reused_audit, reused_source) = original(&input, &head, &current.0, 901);
    let mut publish = source.clone();
    publish.purpose = SourcePurpose::Publish;
    let (stale_audit, stale_source) = effect(
        &step_input,
        &"ab".repeat(32),
        grant,
        "software index phase rpc 904",
        904,
    );
    // A plan of another Step over the same job, under an original that binds
    // this Step to that plan's review.
    let other = step(&owner.binding, &job, "5");
    let other_plan = plan(&store, &job, &other);
    let other_review = other_plan.review().unwrap();
    let (other_audit, other_source) = effect(
        &step_input,
        &other_review.review_sha256,
        grant,
        "software index phase rpc 905",
        905,
    );
    let cases: [(&phase::Plan, Audit, TypedOperationSource, bool); 5] = [
        (&planned, reused_audit, reused_source, true),
        (&planned, audit.clone(), publish, true),
        (&planned, stale_audit, stale_source, true),
        (&other_plan, other_audit, other_source, true),
        (&planned, audit.clone(), source.clone(), false),
    ];
    for (planned, audit, source, live) in cases {
        let mut check = || {
            if live {
                Ok(())
            } else {
                Err("software original revoked".into())
            }
        };
        assert!(cold(&fixture)
            .unwrap()
            .prepare_index_direct(
                &step_input,
                planned,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
        assert_eq!(
            store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
            stored,
            "refused before any store write"
        );
    }
    let before = cold(&fixture).expect("the refused preparations leave the selected job");
    let selected_job = before.descriptor().clone();
    let job_location = selected_location(&fixture);
    assert!(matches!(
        selected_job.operation,
        OperationData::IndexJobSelection { .. }
    ));
    let mut check = || Ok(());
    let preparation = before
        .prepare_index_direct(
            &step_input,
            &planned,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 1,
        "one NV dispatch per phase preparation"
    );
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        stored,
        "a preparation writes nothing to the store"
    );
    let reopened = cold(&fixture).expect("cold reopen replays the selected phase preparation");
    let selected = reopened.descriptor().clone();
    match &selected.operation {
        OperationData::IndexPreparation {
            binding,
            input_sha256,
            preparation: retained,
            original_authority,
            ..
        } => {
            assert_eq!(binding, &owner.binding);
            assert_eq!(input_sha256, &step_input.sha256().unwrap());
            assert_eq!(retained, &preparation);
            assert_eq!(original_authority, &audit);
        }
        _ => panic!("cold reopen did not select the phase preparation"),
    }
    assert_eq!(selected.sequence, selected_job.sequence + 1);
    assert_eq!(selected.roots.owners, selected_job.roots.owners);
    assert_ne!(
        selected.roots.index_generations,
        selected_job.roots.index_generations
    );
    assert_eq!(selected.roots.index_generations.entry_count, 1);
    // The unresolved preparation stays charged: a second one is refused.
    let (audit, source) = effect(
        &other,
        &other_review.review_sha256,
        grant,
        "software index phase rpc 903",
        903,
    );
    let mut check = || Ok(());
    assert!(reopened
        .prepare_index_direct(
            &other,
            &other_plan,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        stored
    );
    cold(&fixture).expect("the refused preparation leaves the selected one");
    let location = selected_location(&fixture);
    let charged = fixture.pages().inventory(&mut || Ok(())).unwrap();
    refuse_forged_preparations(&fixture, &selected, &location, &selected_job, &job_location);
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    assert_eq!(
        fixture.pages().inventory(&mut || Ok(())).unwrap(),
        charged,
        "a refused forgery allocates nothing"
    );
    cold(&fixture).expect("the forged candidates leave the selected preparation");
    // Its source is lost only after the writes, so they stay ahead of C and the
    // retry is refused. Nothing can select them, so this ends the store's use.
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase run rpc 906",
        906,
    );
    let mut check = || Ok(());
    let refusal = cold(&fixture)
        .unwrap()
        .run_index_phase_direct(
            &store,
            &job,
            &step_input,
            plan(&store, &job, &step_input),
            &mut Stopped,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .err()
        .expect("a lost source stops the attempt")
        .to_string();
    assert!(
        refusal.contains("lost after the window writes"),
        "{refusal}"
    );
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 1,
        "stopped before NV"
    );
    let ahead = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    assert!(ahead.regular_files > stored.regular_files);
    assert_eq!(ahead.incomplete_objects, stored.incomplete_objects);
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase run rpc 907",
        907,
    );
    let mut check = || Ok(());
    let mut after = cold(&fixture).expect("the stopped attempt leaves the selected preparation");
    let mut operation = software_worker_operation(&audit, source, &mut check);
    assert_eq!(
        after
            .selected_index_state(&step_input, &mut operation)
            .unwrap(),
        (Some(first_job(&input, &head, &current.0).1), true, stored),
        "the whole preparation stays charged over the old accounting"
    );
    let refusal = after
        .run_index_phase_direct(
            &store,
            &job,
            &step_input,
            plan(&store, &job, &step_input),
            &mut Sources {
                binding: step_input.binding.clone(),
            },
            &mut operation,
        )
        .err()
        .expect("the store ahead of C refuses the retry")
        .to_string();
    assert!(
        refusal.contains("differs from C's accounting at writer begin"),
        "{refusal}"
    );
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        ahead,
        "the refused retry writes nothing"
    );
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), charged);
    cold(&fixture).expect("the refused retry leaves the selected preparation");
    // The closure's checks run last first, since an earlier one hides the next.
    // The last two cannot be undone, so this ends the fixture.
    partial_page(&fixture);
    disturbed(
        &fixture,
        &selected,
        &location,
        "actual complete physical closure differs from its selected exact delta",
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(fixture.pages().root.join("attempts").join("cd".repeat(32)))
        .unwrap();
    disturbed(
        &fixture,
        &selected,
        &location,
        "selected C parent delta lost its actual current after observation",
    );
    let slot = &selected.storage.as_ref().unwrap().descriptor_slot;
    damage(&fixture, &slot.job, 0);
    disturbed(
        &fixture,
        &selected,
        &location,
        "sealed tail inode change-time differs from selected immutable seal",
    );
}

/// The selected preparation's one window runs under a new original for the
/// same Step. Every substitute, a run with no preparation and a base that is
/// not the selected job are refused before NV with the store untouched. The
/// honest run writes the window, the next job and the candidate, then one
/// dispatch selects them together with the measured accounting and resolves
/// the preparation; the cold reader replays it. The same run over the new cut
/// is refused, and forged candidates of it are each refused by the cold
/// verifier with nothing changed.
#[test]
fn actual_index_phase_run_refuses_substitutes_before_nv_then_one_dispatch_resolves_the_preparation()
{
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
    let (audit, source) = original(&input, &head, &current.0, 900);
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .reserve_index_start_direct(
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let (audit, source) = original(&input, &head, &current.0, 901);
    let mut check = || Ok(());
    cold(&fixture)
        .unwrap()
        .select_index_start_direct(
            &store,
            &input,
            &current,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let job = Job::beginning_data(
        &input,
        &head,
        &current.0,
        &selection_data_sha256(&head, None).unwrap(),
    )
    .unwrap();
    let step_input = step(&owner.binding, &job, "4");
    let review = plan(&store, &job, &step_input).review().unwrap();
    let grant = "explicit-software-direct-index-phase";
    let content = |input: &request::Input| Sources {
        binding: input.binding.clone(),
    };
    let calls = fixture.memory.0.borrow().calls;
    let stored = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    // No window runs before C selected a preparation.
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase run rpc 910",
        910,
    );
    let mut check = || Ok(());
    let refusal = cold(&fixture)
        .unwrap()
        .run_index_phase_direct(
            &store,
            &job,
            &step_input,
            plan(&store, &job, &step_input),
            &mut content(&step_input),
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .err()
        .expect("no window runs without a selected preparation")
        .to_string();
    assert!(
        refusal.contains("requires an unresolved preparation over the exact selected job"),
        "{refusal}"
    );
    assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase rpc 902",
        902,
    );
    let (prepared_audit, prepared_source) = (audit.clone(), source.clone());
    let mut check = || Ok(());
    let preparation = cold(&fixture)
        .unwrap()
        .prepare_index_direct(
            &step_input,
            &plan(&store, &job, &step_input),
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    let calls = fixture.memory.0.borrow().calls;
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase run rpc 903",
        903,
    );
    let mut publish = source.clone();
    publish.purpose = SourcePurpose::Publish;
    let (stale_audit, stale_source) = effect(
        &step_input,
        &"ab".repeat(32),
        grant,
        "software index phase run rpc 904",
        904,
    );
    // A genuine original of another Step over the same job, which C never
    // prepared.
    let other = step(&owner.binding, &job, "5");
    let other_review = plan(&store, &job, &other).review().unwrap();
    let (other_audit, other_source) = effect(
        &other,
        &other_review.review_sha256,
        grant,
        "software index phase run rpc 905",
        905,
    );
    // A valid job of another id, which C never selected.
    let mut foreign = input.clone();
    match &mut foreign.operation {
        request::Operation::Start { job_id, .. } => *job_id = "3".repeat(32),
        _ => panic!("the first request is a Start"),
    }
    let foreign = Job::beginning_data(
        &foreign,
        &head,
        &current.0,
        &selection_data_sha256(&head, None).unwrap(),
    )
    .unwrap();
    let cases: [(
        &Job,
        &request::Input,
        Audit,
        TypedOperationSource,
        bool,
        &str,
    ); 6] = [
        (
            &job,
            &step_input,
            prepared_audit,
            prepared_source,
            true,
            "requires a new original operation",
        ),
        (
            &job,
            &step_input,
            audit.clone(),
            publish,
            true,
            "differs from the actual original index source",
        ),
        (
            &job,
            &step_input,
            stale_audit,
            stale_source,
            true,
            "genuine original IndexPrepare purpose/source",
        ),
        (
            &job,
            &other,
            other_audit,
            other_source,
            true,
            "differs from the C-selected preparation owner/input/review",
        ),
        (
            &job,
            &step_input,
            audit.clone(),
            source.clone(),
            false,
            "software original revoked",
        ),
        (
            &foreign,
            &step_input,
            audit.clone(),
            source.clone(),
            true,
            "base differs from the C-selected job blob",
        ),
    ];
    for (base, planned, audit, source, live, reason) in cases {
        let mut check = || {
            if live {
                Ok(())
            } else {
                Err("software original revoked".into())
            }
        };
        let refusal = cold(&fixture)
            .unwrap()
            .run_index_phase_direct(
                &store,
                base,
                planned,
                plan(&store, &job, planned),
                &mut content(planned),
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .err()
            .expect("the substituted run is refused")
            .to_string();
        assert!(refusal.contains(reason), "{refusal}");
        assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
        assert_eq!(
            store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
            stored,
            "refused before any store write"
        );
    }
    let before = cold(&fixture).expect("the refused runs leave the selected preparation");
    let prepared = before.descriptor().clone();
    let prepared_location = selected_location(&fixture);
    assert!(matches!(
        prepared.operation,
        OperationData::IndexPreparation { .. }
    ));
    let mut check = || Ok(());
    let selection = before
        .run_index_phase_direct(
            &store,
            &job,
            &step_input,
            plan(&store, &job, &step_input),
            &mut content(&step_input),
            &mut software_worker_operation(&audit, source.clone(), &mut check),
        )
        .unwrap();
    assert_ne!(selection, preparation);
    assert_eq!(
        fixture.memory.0.borrow().calls,
        calls + 1,
        "one NV dispatch per window run"
    );
    let written = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    assert!(written.regular_files > stored.regular_files);
    assert_eq!(written.incomplete_objects, stored.incomplete_objects);
    let mut reopened = cold(&fixture).expect("cold reopen replays the selected window run");
    let selected = reopened.descriptor().clone();
    match &selected.operation {
        OperationData::IndexPhaseSelection {
            binding,
            input_sha256,
            selection: retained,
            original_authority,
            ..
        } => {
            assert_eq!(binding, &owner.binding);
            assert_eq!(input_sha256, &step_input.sha256().unwrap());
            assert_eq!(retained, &selection);
            assert_eq!(original_authority, &audit);
        }
        _ => panic!("cold reopen did not select the window run"),
    }
    assert_eq!(selected.sequence, prepared.sequence + 1);
    assert_ne!(selected.roots.owners, prepared.roots.owners);
    assert_ne!(
        selected.roots.index_generations,
        prepared.roots.index_generations
    );
    assert_eq!(selected.roots.index_generations.entry_count, 1);
    // One event selected the next job and the measured accounting and resolved
    // the charge. The next job reaches a test only through its selected reference.
    let mut check = || Ok(());
    let (next, charged, physical) = reopened
        .selected_index_state(
            &step_input,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .unwrap();
    assert!(!charged, "the event resolves the preparation");
    assert_eq!(physical, written, "C selects the measured inventory");
    let next = next.expect("the selected leaf names the next job");
    let advanced = Job::parse(&store.read_blob(&next, read(), &mut authority).unwrap()).unwrap();
    assert_eq!(advanced.sha256().unwrap(), next.sha256);
    assert_eq!(advanced.job_id, job.job_id);
    assert_ne!(next.sha256, job.sha256().unwrap());
    // The window is not repeatable: the preparation it consumed is gone.
    let (audit, source) = effect(
        &step_input,
        &review.review_sha256,
        grant,
        "software index phase run rpc 906",
        906,
    );
    let mut check = || Ok(());
    let refusal = reopened
        .run_index_phase_direct(
            &store,
            &job,
            &step_input,
            plan(&store, &job, &step_input),
            &mut content(&step_input),
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .err()
        .expect("a resolved preparation does not run twice")
        .to_string();
    assert!(
        refusal.contains("requires an unresolved preparation over the exact selected job"),
        "{refusal}"
    );
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    assert_eq!(
        store.inventory(read(), &mut authority, |_| Ok(())).unwrap(),
        written
    );
    let location = selected_location(&fixture);
    let pages = fixture.pages().inventory(&mut || Ok(())).unwrap();
    refuse_forged_runs(
        &fixture,
        &selected,
        &location,
        &prepared,
        &prepared_location,
    );
    assert_eq!(fixture.memory.0.borrow().calls, calls + 1);
    assert_eq!(
        fixture.pages().inventory(&mut || Ok(())).unwrap(),
        pages,
        "a refused forgery allocates nothing"
    );
    cold(&fixture).expect("the forged candidates leave the selected run");
}
