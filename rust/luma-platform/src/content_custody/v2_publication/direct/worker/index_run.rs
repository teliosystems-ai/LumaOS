//! The selected preparation's one window runs under a NEW original operation
//! for the same Step. C replays the selected preparation over the reconstructed
//! plan; the actual worker then writes the window's objects, the next job and
//! the candidate under one retained owner writer and re-verifies them from the
//! store. Only then is one C event built that resolves the preparation: it
//! selects the next job and the measured accounting together. The store
//! writes are DATA until that event is NV-selected.
//!
//! The store must equal the C-selected accounting when the writer begins. A
//! failed attempt keeps the preparation's full liability charged; metadata
//! objects derive from measured effects, so a retry cannot attribute them in
//! advance, and reconciling such an attempt is later work.
//!
//! A Publish runs the same way and also writes the generation manifest, which
//! the event names beside the next job. Only a Publish carries the fixed
//! builder, and its provenance walks the C history back to the job's start.
use super::index_preparation::View;
use super::index_selection::{observation_budget, read_budget, selected_transition, SelectedClass};
use super::*;
use crate::content_checkpoint::custody::v2_publication::index::effects;
use crate::content_index::observed::{self, IndexMetadataBoundary, MetadataWriteSet};
use crate::content_index::phase::NativeIndexBoundary;
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
    BuilderIdentity, CorpusContent, CorpusIndexBoundary, CorpusRecord,
};
use luma_content_store::v2::{
    AppendCommitment, AppendWriterBoundary, BlobReference, HeldNamespaceObservation,
    HeldWriterObservation, IoBudget, MapRoot, ObjectStore, ObjectWriteSpec, OwnerBoundary,
    PhysicalInventory,
};
use luma_content_store::{Access, Boundary, DecisionKind, ResourceBudget};
use std::fs::File;
use std::os::unix::fs::MetadataExt;

#[path = "index_chain.rs"]
mod chain;

fn refused() -> luma_content_store::Result<()> {
    Err("index phase run refuses this boundary for its selected window".into())
}

/// The one commitment a window reaches. The store binds it after writing and again
/// after replay, so the replay must name what the writer recorded. Its totals hold
/// the reviewed charge, and what C selects as physical truth is the inventory
/// measured later. This is logical accounting and not a kernel witness.
#[derive(Default)]
struct WindowCommitment(Option<String>);
impl WindowCommitment {
    fn bind(&mut self, commitment: &[u8]) -> luma_content_store::Result<()> {
        let commitment = hash(commitment);
        match &self.0 {
            None => self.0 = Some(commitment),
            Some(first) if *first == commitment => {}
            Some(_) => return Err("index phase run commitment changed before selection".into()),
        }
        Ok(())
    }
}

/// The actual C point and original worker that every content-store bound
/// re-observes, with the one reviewed window it may run. There is no default
/// success: a phase, recovery or owner append with no opened boundary below is
/// refused, and each reservation below is the exact one the C-selected preparation
/// charged.
struct Current<'a, 'b, 'c, 's, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    original: &'b mut OriginalCOperation<'c>,
    store: &'s ObjectStore,
    binding: OwnerBinding,
    head: RecordRef,
    physical: PhysicalInventory,
    job: &'s Job,
    input: &'s request::Input,
    review: &'s phase::WindowReview,
    objects: &'s [ObjectWriteSpec],
    write: IoBudget,
    namespace: Option<HeldNamespaceObservation>,
    held: Option<HeldWriterObservation>,
    objects_reserved: bool,
    extension: Option<MetadataWriteSet>,
    reserve: Option<PageReserve>,
    debit: Option<PageDebitCommitment>,
    commitment: WindowCommitment,
    builder: Option<&'s dyn effects::CurrentBuilder>,
    provenance: bool,
}
impl<A: Checkpoint> Current<'_, '_, '_, '_, A> {
    fn live(&mut self) -> Result<()> {
        self.original.check()?;
        self.backend.live(&mut || self.original.check())
    }
    fn exact(&mut self, head: &OwnerHeadV2, review: &str) -> luma_content_store::Result<()> {
        self.current_owner_head(head)?;
        if review != self.review.core_review_sha256 {
            return Err("index phase run writer changes its selected review".into());
        }
        Ok(())
    }
    fn ingestion(&self) -> luma_content_store::Result<&IngestRequest> {
        Ok(self.job.lineage()?.ingestion.0)
    }
    /// Binds this window's commitment to the object set C charged, which
    /// `reserve_index_objects` proved equal to the preparation's.
    fn bind_window(&mut self, commitment: &[u8]) -> luma_content_store::Result<()> {
        self.live()?;
        if !self.objects_reserved {
            return Err("index phase run commitment precedes its reserved objects".into());
        }
        self.commitment.bind(commitment)
    }
}
impl<A: Checkpoint> Boundary for Current<'_, '_, '_, '_, A> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        let additional = self
            .write
            .write_bytes
            .checked_add(u64::from(self.write.new_files) * 8192)
            .ok_or("index phase run physical reserve overflow")?;
        if *binding != self.binding
            || budget.tasks != 1
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 512 * 1024 * 1024
            || budget.write_bytes > self.write.write_bytes
            || budget.additional_storage_bytes > additional
        {
            return Err("index phase run exceeds its bounded original admission".into());
        }
        self.live()
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        self.live()?;
        let exact = match access {
            Access::Inspect { binding } => *binding == self.binding,
            Access::Mutate {
                binding,
                review_sha256,
                decision,
                source_bytes,
                storage_bytes,
            } => {
                // The metadata writer reviews its blobs as its own source.
                let metadata = self.extension.as_ref().and_then(|value| {
                    value
                        .next_job
                        .bytes
                        .checked_add(value.candidate.bytes)?
                        .checked_add(
                            value
                                .generation
                                .as_ref()
                                .map_or(0, |manifest| manifest.bytes),
                        )
                });
                *binding == self.binding
                    && decision == DecisionKind::Published
                    && review_sha256 == self.review.core_review_sha256
                    && (source_bytes == self.review.source_bytes || Some(source_bytes) == metadata)
                    && storage_bytes <= self.write.write_bytes
            }
            Access::Recover { .. } => false,
        };
        if !exact {
            return Err("index phase run access differs from its selected window".into());
        }
        self.live()
    }
}
impl<A: Checkpoint> OwnerBoundary for Current<'_, '_, '_, '_, A> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> luma_content_store::Result<()> {
        self.live()?;
        let bytes = head.canonical_bytes()?;
        if head.binding != self.binding
            || hash(&bytes) != self.head.sha256
            || bytes.len() as u64 != self.head.bytes
        {
            return Err("index phase run head is not the actual C-selected V2 owner".into());
        }
        Ok(())
    }
    fn current_physical_accounting(
        &mut self,
        head: &OwnerHeadV2,
    ) -> luma_content_store::Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.physical.clone())
    }
    fn verify_prepared_allocations(
        &mut self,
        _: &AppendCommitment,
    ) -> luma_content_store::Result<()> {
        Err("index phase run never prepares an owner append".into())
    }
}
impl<A: Checkpoint> AppendWriterBoundary for Current<'_, '_, '_, '_, A> {
    fn begin_writer(
        &mut self,
        head: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> luma_content_store::Result<()> {
        self.exact(head, review_sha256)?;
        if self.held.is_some() {
            return Err("index phase run repeats its observed writer".into());
        }
        let store = self.store;
        if store.inventory(read_budget(), self, |_| Ok(()))? != self.physical {
            return Err("actual v2 store differs from C's accounting at writer begin".into());
        }
        let namespace = self
            .namespace
            .take()
            .ok_or("index phase run writer has no observed namespace")?;
        let held = store.observe_existing_writer(
            &namespace,
            writer.try_clone()?,
            std::process::id(),
            observation_budget(),
            self,
        );
        self.namespace = Some(namespace);
        self.held = Some(held?);
        self.exact(head, review_sha256)
    }
    fn check_writer(
        &mut self,
        head: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> luma_content_store::Result<()> {
        self.exact(head, review_sha256)?;
        let inode = writer.metadata()?.ino();
        let (namespace, held) = match (self.namespace.take(), self.held.take()) {
            (Some(namespace), Some(held)) => (namespace, held),
            (namespace, held) => {
                self.namespace = namespace;
                self.held = held;
                return Err("index phase run writer was never observed".into());
            }
        };
        let same = inode == held.data().root.inode;
        let store = self.store;
        let result = if same {
            store.check_existing_writer(&namespace, &held, observation_budget(), self)
        } else {
            Err("index phase run observed writer changed".into())
        };
        self.namespace = Some(namespace);
        self.held = Some(held);
        result?;
        self.exact(head, review_sha256)
    }
}
impl<A: Checkpoint> CorpusIndexBoundary for Current<'_, '_, '_, '_, A> {
    fn current_corpus(&mut self, root: &MapRoot) -> luma_content_store::Result<()> {
        self.live()?;
        if root != &self.ingestion()?.corpus || root != &self.job.source_owner.roots.corpus {
            return Err("index phase run refuses a substituted corpus".into());
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
            return Err("index phase run refuses a substituted builder".into());
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
impl<A: Checkpoint> CorpusIndexJobBoundary for Current<'_, '_, '_, '_, A> {
    fn current_job(
        &mut self,
        request: &IngestRequest,
        progress: &IngestProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.ingestion != (request, progress) {
            return Err("index phase run refuses a substituted ingest job".into());
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
impl<A: Checkpoint> StatisticsBoundary for Current<'_, '_, '_, '_, A> {
    fn current_statistics(
        &mut self,
        request: &StatisticsRequest,
        progress: &StatisticsProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.statistics != Some((request, progress)) {
            return Err("index phase run refuses a substituted statistics job".into());
        }
        Ok(())
    }
    fn verify_statistics_allocations(
        &mut self,
        _: &StatisticsCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl<A: Checkpoint> CovarianceBoundary for Current<'_, '_, '_, '_, A> {
    fn current_covariance(
        &mut self,
        request: &CovarianceRequest,
        progress: &CovarianceProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.covariance != Some((request, progress)) {
            return Err("index phase run refuses a substituted covariance job".into());
        }
        Ok(())
    }
    fn verify_covariance_allocations(
        &mut self,
        value: &CovarianceCommitment,
    ) -> luma_content_store::Result<()> {
        self.current_covariance(&value.request, &value.base)?;
        if value.review.sha256()? != self.review.core_review_sha256
            || value.review.write_charge > self.review.maximum_write_bytes
        {
            return Err("index phase run covariance commitment differs from its review".into());
        }
        self.bind_window(&value.canonical_bytes()?)
    }
}
impl<A: Checkpoint> ProjectionBoundary for Current<'_, '_, '_, '_, A> {
    fn current_projection(
        &mut self,
        request: &ProjectionRequest,
        progress: &ProjectionProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.projection != Some((request, progress)) {
            return Err("index phase run refuses a substituted projection job".into());
        }
        Ok(())
    }
    fn verify_projection_allocations(
        &mut self,
        value: &ProjectionCommitment,
    ) -> luma_content_store::Result<()> {
        self.current_projection(&value.request, &value.base)?;
        if value.review.sha256()? != self.review.core_review_sha256
            || value.review.write_charge > self.review.maximum_write_bytes
        {
            return Err("index phase run projection commitment differs from its review".into());
        }
        self.bind_window(&value.canonical_bytes()?)
    }
}
impl<A: Checkpoint> VectorBoundary for Current<'_, '_, '_, '_, A> {
    fn current_vectors(
        &mut self,
        request: &VectorRequest,
        progress: &VectorProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.vectors != Some((request, progress)) {
            return Err("index phase run refuses a substituted vector job".into());
        }
        Ok(())
    }
    fn verify_vector_allocations(
        &mut self,
        value: &VectorCommitment,
    ) -> luma_content_store::Result<()> {
        self.current_vectors(&value.request, &value.base)?;
        // The canonical form proves the next totals do not fall below the base.
        let commitment = value.canonical_bytes()?;
        if value.review_sha256 != self.review.core_review_sha256
            || value.next.totals.write_bytes - value.base.totals.write_bytes
                > self.review.maximum_write_bytes
        {
            return Err("index phase run vector commitment differs from its review".into());
        }
        self.bind_window(&commitment)
    }
}
impl<A: Checkpoint> GenerationAuditBoundary for Current<'_, '_, '_, '_, A> {
    fn current_generation_audit(
        &mut self,
        job: &GenerationJob,
        progress: &AuditProgress,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if self.job.lineage()?.audit != Some((job, progress)) {
            return Err("index phase run refuses a substituted audit job".into());
        }
        Ok(())
    }
    /// An Audit window writes no objects, so what it binds is the empty set C charged.
    fn verify_audit_reservations(
        &mut self,
        value: &AuditCommitment,
    ) -> luma_content_store::Result<()> {
        self.current_generation_audit(&value.job, &value.base)?;
        if value.review_sha256 != self.review.core_review_sha256 {
            return Err("index phase run audit commitment differs from its review".into());
        }
        self.bind_window(&value.canonical_bytes()?)
    }
}
impl<A: Checkpoint> GenerationPublicationBoundary for Current<'_, '_, '_, '_, A> {
    /// Publication binds the audited job to the C history that selected every
    /// job before it, under this installation's fixed builder. A plain window
    /// run has no builder, so it is refused. Each call re-proves the C point
    /// live, so the history cannot change between plan and replay and one walk
    /// serves both.
    fn verify_original_phase_provenance(
        &mut self,
        job: &GenerationJob,
        audit: &AuditProgress,
    ) -> luma_content_store::Result<()> {
        self.current_generation_audit(job, audit)?;
        let Some(builder) = self.builder else {
            return refused();
        };
        if !self.provenance {
            self.verify_chain(builder)?;
            self.provenance = true;
        }
        self.live()
    }
    fn reserve_generation(&mut self, review: &GenerationReview) -> luma_content_store::Result<()> {
        self.live()?;
        if !self.provenance
            || !self.objects_reserved
            || review.sha256()? != self.review.core_review_sha256
        {
            return Err(
                "index phase run generation review differs from its selected window".into(),
            );
        }
        Ok(())
    }
    fn verify_generation_allocations(
        &mut self,
        value: &GenerationCommitment,
    ) -> luma_content_store::Result<()> {
        self.current_generation_audit(&value.job, &value.audit)?;
        if !self.provenance
            || value.review.sha256()? != self.review.core_review_sha256
            || value.review.write_charge > self.review.maximum_write_bytes
        {
            return Err("index phase run generation commitment differs from its review".into());
        }
        self.bind_window(&value.canonical_bytes()?)
    }
    fn release_generation_after_selection(
        &mut self,
        _: &GenerationCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl<A: Checkpoint> CurrentGenerationBoundary for Current<'_, '_, '_, '_, A> {
    fn current_generation(&mut self, _: &GenerationManifest) -> luma_content_store::Result<()> {
        refused()
    }
}
impl<A: Checkpoint> PageAccountingBoundary for Current<'_, '_, '_, '_, A> {
    /// The C-selected preparation is the durable ceiling this trait requires:
    /// it was charged before any write and stays charged on every failure.
    fn reserve_pages(&mut self, reserve: &PageReserve) -> luma_content_store::Result<()> {
        self.live()?;
        reserve.canonical_bytes()?;
        let inventoried = reserve.pages.iter().all(|page| {
            self.objects
                .iter()
                .any(|object| object.sha256 == page.sha256 && u64::from(object.bytes) == page.bytes)
        });
        if !self.objects_reserved
            || self.reserve.is_some()
            || reserve.binding != self.binding
            || reserve.review_sha256 != self.review.core_review_sha256
            || reserve.source_bytes != self.review.source_bytes
            || reserve.maximum_storage_bytes != self.review.maximum_write_bytes
            || !inventoried
        {
            return Err("index phase run page reserve differs from its preparation".into());
        }
        self.reserve = Some(reserve.clone());
        self.live()
    }
    fn observe_pages(
        &mut self,
        value: &PageDebitCommitment,
        captured: &CapturedPageMeasurements,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        value.canonical_bytes()?;
        if Some(&value.reserve) != self.reserve.as_ref()
            || self.debit.is_some()
            || captured.reserve_sha256() != hash(&value.reserve.canonical_bytes()?)
            || captured.pages() != value.pages
        {
            return Err("index phase run page debit differs from its measurements".into());
        }
        self.debit = Some(value.clone());
        self.live()
    }
    fn verify_pages(&mut self, value: &PageDebitCommitment) -> luma_content_store::Result<()> {
        self.live()?;
        if self.debit.as_ref() != Some(value) {
            return Err("index phase run page debit changed before selection".into());
        }
        self.live()
    }
    fn release_pages_after_selection(
        &mut self,
        _: &PageDebitCommitment,
    ) -> luma_content_store::Result<()> {
        refused()
    }
}
impl<A: Checkpoint> NativeIndexBoundary for Current<'_, '_, '_, '_, A> {
    fn current_native_job(&mut self, job: &Job) -> Result<()> {
        self.live()?;
        if job != self.job {
            return Err("index phase run refuses a substituted native job".into());
        }
        Ok(())
    }
    fn current_native_operation(&mut self, input: &request::Input) -> Result<()> {
        self.live()?;
        if input != self.input {
            return Err("index phase run refuses a substituted native operation".into());
        }
        Ok(())
    }
    fn current_plan_review(&mut self, input: &request::Input, review_sha256: &str) -> Result<()> {
        self.current_native_operation(input)?;
        if review_sha256 != self.review.core_review_sha256 {
            return Err("index phase run refuses a substituted plan review".into());
        }
        Ok(())
    }
}
impl<A: Checkpoint> IndexMetadataBoundary for Current<'_, '_, '_, '_, A> {
    fn reserve_index_objects(
        &mut self,
        input: &request::Input,
        base: &Job,
        owner: &OwnerHeadV2,
        review: &phase::WindowReview,
        objects: &[ObjectWriteSpec],
    ) -> Result<()> {
        self.current_native_operation(input)?;
        self.current_native_job(base)?;
        self.current_owner_head(owner)?;
        if review != self.review || objects != self.objects || self.objects_reserved {
            return Err("index phase run objects differ from its preparation".into());
        }
        self.objects_reserved = true;
        self.live()
    }
    fn reserve_index_metadata(
        &mut self,
        input: &request::Input,
        base: &Job,
        extension: &MetadataWriteSet,
    ) -> Result<()> {
        self.current_native_operation(input)?;
        self.current_native_job(base)?;
        extension.canonical_bytes()?;
        let maximum = &self.review.metadata_maximum;
        if !self.objects_reserved
            || self.extension.is_some()
            || extension.input_sha256 != self.review.input_sha256
            || extension.base_sha256 != self.review.base_sha256
            || extension.review_sha256 != self.review.core_review_sha256
            || extension.native_review_sha256 != self.review.review_sha256
            || extension.object_writes > maximum.object_writes
            || extension.read_bytes > maximum.read_bytes
            || extension.write_bytes > maximum.write_bytes
            || extension.new_files > maximum.new_files
        {
            return Err("index phase run metadata exceeds its selected window".into());
        }
        self.extension = Some(extension.clone());
        self.live()
    }
    fn check_index_metadata(
        &mut self,
        input: &request::Input,
        base: &Job,
        extension: &MetadataWriteSet,
    ) -> Result<()> {
        self.current_native_operation(input)?;
        self.current_native_job(base)?;
        if self.extension.as_ref() != Some(extension) {
            return Err("index phase run metadata changed after its reservation".into());
        }
        self.live()
    }
}

impl<A: Checkpoint> Backend<A> {
    /// Runs the selected preparation's one window and NV-selects its result
    /// for the actual original worker. The plan is never trusted: C replays
    /// the selected preparation over it first.
    pub(in crate::content_checkpoint::custody::v2_publication) fn run_index_phase_direct<
        C: CorpusContent,
    >(
        self,
        store: &ObjectStore,
        base: &Job,
        input: &request::Input,
        plan: phase::Plan,
        content: &mut C,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        self.run_selected(store, base, input, plan, content, None, original)
    }
    /// Runs the selected Publish preparation and NV-selects the generation it
    /// writes. Publication alone needs the fixed builder: provenance walks the
    /// C history that selected every job before the audited one.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::content_checkpoint::custody::v2_publication) fn publish_index_generation_direct<
        C: CorpusContent,
    >(
        self,
        store: &ObjectStore,
        base: &Job,
        input: &request::Input,
        plan: phase::Plan,
        content: &mut C,
        builder: &dyn effects::CurrentBuilder,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        if !matches!(input.operation, request::Operation::Publish { .. }) {
            return Err(
                "index generation publication requires the exact prepared Publish request".into(),
            );
        }
        self.run_selected(store, base, input, plan, content, Some(builder), original)
    }
    #[allow(clippy::too_many_arguments)]
    fn run_selected<C: CorpusContent>(
        mut self,
        store: &ObjectStore,
        base: &Job,
        input: &request::Input,
        plan: phase::Plan,
        content: &mut C,
        builder: Option<&dyn effects::CurrentBuilder>,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        let token = run(
            &mut self, store, base, input, plan, content, builder, original,
        )?;
        let expected = match &token.outcome {
            Completed::IndexPhaseSelection(reference) => reference.clone(),
            _ => return Err("index phase run built a different completion class".into()),
        };
        match super::storage::publish(self, token, original)? {
            Completed::IndexPhaseSelection(reference) if reference == expected => Ok(reference),
            _ => Err(
                "closed index phase-run consumer received a different semantic completion".into(),
            ),
        }
    }
    /// The job, unresolved preparation and accounting this cut selects.
    pub(in crate::content_checkpoint::custody::v2_publication) fn selected_index_state(
        &mut self,
        input: &request::Input,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<(Option<BlobReference>, bool, PhysicalInventory)> {
        effects::selected_index_state(
            &mut View {
                backend: self,
                remaining: READ_BUDGET,
            },
            input,
            original,
        )
    }
    /// The generation this cut selects, if a Publish selected one.
    pub(in crate::content_checkpoint::custody::v2_publication) fn selected_index_generation(
        &mut self,
        input: &request::Input,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Option<BlobReference>> {
        effects::selected_index_generation(
            &mut View {
                backend: self,
                remaining: READ_BUDGET,
            },
            input,
            original,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn run<A: Checkpoint, C: CorpusContent>(
    backend: &mut Backend<A>,
    store: &ObjectStore,
    base: &Job,
    input: &request::Input,
    plan: phase::Plan,
    content: &mut C,
    builder: Option<&dyn effects::CurrentBuilder>,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedTransition> {
    backend.descriptor.phase.require_ready()?;
    original.check()?;
    if original.source_binding().purpose != SourcePurpose::IndexPrepare
        || original.source_binding().binding != input.binding
    {
        return Err("index phase run differs from the actual original index source".into());
    }
    let verified = effects::verify_index_phase_selection(
        &mut View {
            backend: &mut *backend,
            remaining: READ_BUDGET,
        },
        input,
        &plan,
        original,
    )?;
    let review = plan.review()?;
    // The exact envelope the observed writer admits. The preparation's liability
    // binds the reserved objects and the measured inventory, not this envelope.
    let write = IoBudget {
        read_bytes: review
            .maximum_read_bytes
            .checked_add(review.metadata_maximum.read_bytes)
            .ok_or("index phase run read ceiling overflow")?,
        write_bytes: review
            .maximum_write_bytes
            .checked_add(review.metadata_maximum.write_bytes)
            .ok_or("index phase run write ceiling overflow")?,
        new_files: 32768,
    };
    // Every store bound below re-proves the same NV cut and live original.
    let (next_job, candidate, generation, extension_sha256, physical_after) = {
        let mut current = Current {
            backend: &mut *backend,
            original: &mut *original,
            store,
            binding: input.binding.clone(),
            head: verified.head_ref().clone(),
            physical: verified.physical().clone(),
            job: base,
            input,
            review: &review,
            objects: verified.objects(),
            write,
            namespace: None,
            held: None,
            objects_reserved: false,
            extension: None,
            reserve: None,
            debit: None,
            commitment: WindowCommitment::default(),
            builder,
            provenance: false,
        };
        // Later jobs are not re-derivable from C alone: the selected reference
        // resolves the caller's base through the store.
        if base.sha256()? != review.base_sha256
            || store.read_blob(verified.job()?, read_budget(), &mut current)?
                != base.canonical_bytes()?
        {
            return Err("index phase run base differs from the C-selected job blob".into());
        }
        current.namespace = Some(store.observe_namespace(observation_budget(), &mut current)?);
        let prepared = observed::prepare_index_observed(
            store,
            verified.head(),
            base,
            input,
            plan,
            &mut current,
        )?;
        let metadata = prepared.prepare_metadata(base, input, &mut current)?;
        let commitment = prepared.commitment();
        let next =
            phase::verify_phase_data(store, base, input, &commitment, content, &mut current)?;
        let manifest = observed::generation_bytes(&next)?;
        let generation_differs = match (&metadata.generation, &manifest) {
            (None, None) => false,
            (Some(reference), Some(bytes)) => {
                store.read_blob(reference, read_budget(), &mut current)? != *bytes
            }
            _ => true,
        };
        if store.read_blob(&metadata.next_job, read_budget(), &mut current)?
            != next.canonical_bytes()?
            || store.read_blob(&metadata.candidate, read_budget(), &mut current)?
                != commitment.canonical_bytes()?
            || generation_differs
        {
            return Err("actual index metadata read-back differs from the verified window".into());
        }
        let extension = current
            .extension
            .clone()
            .ok_or("index phase run lost its metadata write set")?;
        let objects = [verified.objects(), extension.objects.as_slice()].concat();
        store.synchronize_objects(&objects, read_budget(), &mut current)?;
        let after = store.inventory(read_budget(), &mut current, |_| Ok(()))?;
        prepared.check(&mut current)?;
        drop(prepared);
        current.live()?;
        (
            metadata.next_job,
            metadata.candidate,
            metadata.generation,
            metadata.extension_sha256,
            after,
        )
    };
    let parts = verified
        .finish(
            &mut View {
                backend: &mut *backend,
                remaining: READ_BUDGET,
            },
            &next_job,
            &candidate,
            generation.as_ref(),
            &extension_sha256,
            &physical_after,
            original,
        )?
        .into_parts();
    selected_transition(backend, parts, input, original, SelectedClass::Phase)
}

#[cfg(test)]
mod commitment_tests {
    use super::WindowCommitment;

    #[test]
    fn a_window_commitment_cannot_change_between_writing_and_replay() {
        let mut window = WindowCommitment::default();
        window.bind(b"written").unwrap();
        window.bind(b"written").unwrap();
        assert_eq!(
            window.bind(b"replayed").unwrap_err().to_string(),
            "index phase run commitment changed before selection"
        );
    }
}
