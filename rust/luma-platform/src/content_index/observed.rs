//! Actual retained writer callbacks around every original index boundary call.
//! This does not replace C's exact preregistration or physical creation proofs.
use super::phase::{Commitment, NativeIndexBoundary, Plan, Prepared};
use super::state::Job;
use super::*;
use luma_content_store::v2::{
    AppendWriterBoundary, IoBudget, ObjectStore, ObservedObjectWriter, OwnerBoundary,
};
use luma_content_store::{Access, Boundary, ResourceBudget};
mod metadata;
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
use luma_content_store::corpus_index::{CorpusIndexBoundary, CorpusRecord};
use luma_content_store::v2::head::OwnerHeadV2;
use luma_content_store::v2::MapRoot;
pub(crate) use metadata::IndexMetadataBoundary;

struct Checked<'a, 'b, B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> {
    inner: &'a mut B,
    writer: &'a ObservedObjectWriter<'b>,
}
macro_rules! forward{
    ($name:ident($($arg:ident:$ty:ty),*) )=>{
        fn $name(&mut self,$($arg:$ty),*)->Result<()>{
            self.writer.check(self.inner)?;
            self.inner.$name($($arg),*)?;
            self.writer.check(self.inner)
        }
    };
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> Boundary
    for Checked<'_, '_, B>
{
    forward!(admit(binding:&OwnerBinding,budget:ResourceBudget));
    forward!(check(access:Access<'_>));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> CorpusIndexBoundary
    for Checked<'_, '_, B>
{
    forward!(current_corpus(root:&MapRoot));
    forward!(current_builder(root:&MapRoot,identity:&BuilderIdentity));
    forward!(current_index_generation(root:&MapRoot,manifest_sha256:&str));
    forward!(current_candidate(root:&MapRoot,record:&CorpusRecord));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> CorpusIndexJobBoundary
    for Checked<'_, '_, B>
{
    forward!(current_job(request:&IngestRequest,progress:&IngestProgress));
    forward!(verify_ingest_allocations(value:&IngestCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> StatisticsBoundary
    for Checked<'_, '_, B>
{
    forward!(current_statistics(request:&StatisticsRequest,progress:&StatisticsProgress));
    forward!(verify_statistics_allocations(value:&StatisticsCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> CovarianceBoundary
    for Checked<'_, '_, B>
{
    forward!(current_covariance(request:&CovarianceRequest,progress:&CovarianceProgress));
    forward!(verify_covariance_allocations(value:&CovarianceCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> ProjectionBoundary
    for Checked<'_, '_, B>
{
    forward!(current_projection(request:&ProjectionRequest,progress:&ProjectionProgress));
    forward!(verify_projection_allocations(value:&ProjectionCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> VectorBoundary
    for Checked<'_, '_, B>
{
    forward!(current_vectors(request:&VectorRequest,progress:&VectorProgress));
    forward!(verify_vector_allocations(value:&VectorCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> GenerationAuditBoundary
    for Checked<'_, '_, B>
{
    forward!(current_generation_audit(job:&GenerationJob,progress:&AuditProgress));
    forward!(verify_audit_reservations(value:&AuditCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> GenerationPublicationBoundary
    for Checked<'_, '_, B>
{
    forward!(verify_original_phase_provenance(job:&GenerationJob,audit:&AuditProgress));
    forward!(reserve_generation(review:&GenerationReview));
    forward!(verify_generation_allocations(value:&GenerationCommitment));
    forward!(release_generation_after_selection(value:&GenerationCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> CurrentGenerationBoundary
    for Checked<'_, '_, B>
{
    forward!(current_generation(manifest:&GenerationManifest));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> PageAccountingBoundary
    for Checked<'_, '_, B>
{
    forward!(reserve_pages(reserve:&PageReserve));
    forward!(observe_pages(value:&PageDebitCommitment,captured:&CapturedPageMeasurements));
    forward!(verify_pages(value:&PageDebitCommitment));
    forward!(release_pages_after_selection(value:&PageDebitCommitment));
}
impl<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary> NativeIndexBoundary
    for Checked<'_, '_, B>
{
    forward!(current_native_job(job:&Job));
    forward!(current_native_operation(input:&request::Input));
    forward!(current_plan_review(input:&request::Input,review_sha256:&str));
}

/// An unselected preparation. No inner writer/Prepared extraction exists;
/// dropping it keeps all uncertain C reservations and immutable files retained.
// Constructed only by index-run, which awaits the C index publisher.
#[allow(dead_code)]
pub(crate) struct ObservedPreparation<'a> {
    writer: ObservedObjectWriter<'a>,
    prepared: Prepared,
    review: phase::WindowReview,
    metadata: metadata::MetadataAttempt,
}
#[allow(dead_code)]
impl ObservedPreparation<'_> {
    pub(crate) fn commitment(&self) -> Commitment {
        self.prepared.commitment()
    }
    pub(crate) fn check<B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary>(
        &self,
        b: &mut B,
    ) -> Result<()> {
        self.writer.check(b)
    }
    pub(crate) fn acknowledge_selected<
        B: NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary,
    >(
        self,
        next: &Job,
        input: &request::Input,
        b: &mut B,
    ) -> Result<()> {
        self.metadata.require_complete()?;
        self.writer.check(b)?;
        self.prepared.acknowledge_selected(
            next,
            input,
            &mut Checked {
                inner: b,
                writer: &self.writer,
            },
        )?;
        self.writer.check(b)
    }
}

#[allow(dead_code)]
pub(crate) fn prepare_index_observed<'a, B: IndexMetadataBoundary>(
    store: &'a ObjectStore,
    actual_owner: &OwnerHeadV2,
    base: &Job,
    input: &request::Input,
    plan: Plan,
    b: &mut B,
) -> Result<ObservedPreparation<'a>> {
    base.check_request(input)?;
    b.current_native_operation(input)?;
    b.current_native_job(base)?;
    b.current_owner_head(actual_owner)?;
    if actual_owner.binding != base.source_owner.binding
        || actual_owner.roots.corpus != base.source_owner.roots.corpus
    {
        return Err("index writer no longer has the actual current source corpus/owner".into());
    }
    let review = plan.review()?;
    let mutation = plan.mutation()?;
    b.current_plan_review(input, &review.core_review_sha256)?;
    let objects = plan.planned_objects(|| {
        b.current_native_job(base)?;
        b.current_native_operation(input)?;
        b.current_plan_review(input, &review.core_review_sha256)
    })?;
    if luma_content::sha256(&serde_json::to_vec(&objects)?) != review.planned_objects_sha256 {
        return Err("native exact object inventory differs from reviewed envelope".into());
    }
    b.reserve_index_objects(input, base, actual_owner, &review, &objects)?;
    let writer = store.prepare_index_observed(
        actual_owner,
        &mutation,
        IoBudget {
            read_bytes: review
                .maximum_read_bytes
                .checked_add(review.metadata_maximum.read_bytes)
                .ok_or("native complete read ceiling overflow")?,
            write_bytes: review
                .maximum_write_bytes
                .checked_add(review.metadata_maximum.write_bytes)
                .ok_or("native complete write ceiling overflow")?,
            new_files: 32768,
        },
        b,
    )?;
    let prepared = phase::prepare(
        store,
        base,
        input,
        plan,
        &mutation,
        &mut Checked {
            inner: b,
            writer: &writer,
        },
    )?;
    writer.check(b)?;
    Ok(ObservedPreparation {
        writer,
        prepared,
        review,
        metadata: metadata::MetadataAttempt::new(),
    })
}
