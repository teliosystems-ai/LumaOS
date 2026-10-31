//! Actual first index job Start reservations, job selections and first phase
//! preparations of the closed direct worker over a real migrated V2 owner in a
//! real bootstrapped C cut and its real v2 object store. The builder identity,
//! original worker attribution, planning boundary, resources and NV are
//! explicit software fixtures, not the installed image builder or installed
//! qualification.
use super::super::super::super::super::protocol::{
    software_worker_operation, OriginalCOperation, TypedOperationSource,
};
use super::migration_cases::{migrated, Migrated, BODY};
use super::worker_cases::cold;
use super::*;
use crate::content_checkpoint::custody::indexed::{
    selection_data_sha256, TransitionBase, TransitionReview,
};
use crate::content_checkpoint::custody::v2_publication::index::effects::CurrentBuilder;
use crate::content_index::scope::original_usage;
use crate::content_index::state::Job;
use crate::content_index::{phase, request};
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

/// The selected first job's first ingestion phase is prepared under a new
/// original over the exact reconstructed plan. Every substitute is refused
/// before NV and leaves C and the store untouched; the preparation takes one
/// dispatch, writes nothing to the store, and the cold reader replays it. A
/// second preparation over the C-selected one is refused.
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
    let selected = reopened.descriptor();
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
}
