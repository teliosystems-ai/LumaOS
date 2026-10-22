//! Closed native phase candidates and independent semantic replay. These
//! functions never select C state, mint authority or release an uncertain hold.
use super::state::{Job, Stage};
use super::*;
use luma_content_store::corpus_index::storage::IndexReadStore;
use luma_content_store::corpus_index::{
    job::{
        self,
        accounted::{self, AccountedIngestCommitment, PageAccountingBoundary},
        covariance::{
            self,
            projection::{
                self,
                vectors::{
                    self,
                    generation::{
                        self,
                        audit::{self, AuditCommitment},
                        CurrentGenerationBoundary, GenerationCommitment,
                        GenerationPublicationBoundary,
                    },
                    VectorCommitment,
                },
                ProjectionCommitment,
            },
            CovarianceCommitment,
        },
        statistics::{
            self,
            accounted::{self as statistics_accounted, AccountedStatisticsCommitment},
        },
    },
    CorpusContent,
};
use luma_content_store::v2::ObjectStore;

/// All methods are mandatory: implementations must refresh the genuine
/// original paired grants/UTC/worker lease and the exact current protected job.
pub(crate) trait NativeIndexBoundary:
    GenerationPublicationBoundary + CurrentGenerationBoundary + PageAccountingBoundary
{
    fn current_native_job(&mut self, job: &Job) -> Result<()>;
    fn current_native_operation(&mut self, input: &request::Input) -> Result<()>;
    fn current_plan_review(&mut self, input: &request::Input, review_sha256: &str) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "phase",
    content = "commitment",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum Commitment {
    Ingest(AccountedIngestCommitment),
    Statistics(AccountedStatisticsCommitment),
    Covariance(CovarianceCommitment),
    Projection(ProjectionCommitment),
    Vectors(VectorCommitment),
    Audit(AuditCommitment),
    Publish(GenerationCommitment),
}
impl Commitment {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Ingest(c) => {
                c.canonical_bytes()?;
            }
            Self::Statistics(c) => {
                c.canonical_bytes()?;
            }
            Self::Covariance(c) => {
                c.canonical_bytes()?;
            }
            Self::Projection(c) => {
                c.canonical_bytes()?;
            }
            Self::Vectors(c) => {
                c.canonical_bytes()?;
            }
            Self::Audit(c) => {
                c.canonical_bytes()?;
            }
            Self::Publish(c) => {
                c.canonical_bytes()?;
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_COMMITMENT {
            return Err("native phase candidate exceeds bounded immutable record".into());
        }
        Ok(bytes)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_COMMITMENT)?;
        value.canonical_bytes()?;
        Ok(value)
    }
    // Commitment digests and successor data are consumed by the C index publisher.
    #[allow(dead_code)]
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    #[allow(dead_code)]
    pub(crate) fn review_sha256(&self) -> Result<String> {
        self.canonical_bytes()?;
        Ok(match self {
            Self::Ingest(c) => c.accounting.reserve.review_sha256.clone(),
            Self::Statistics(c) => c.accounting.reserve.review_sha256.clone(),
            Self::Covariance(c) => c.review.sha256()?,
            Self::Projection(c) => c.review.sha256()?,
            Self::Vectors(c) => c.review_sha256.clone(),
            Self::Audit(c) => c.review_sha256.clone(),
            Self::Publish(c) => c.review.sha256()?,
        })
    }
    /// Exact CAS/protocol validation only. C MUST additionally perform the
    /// independent full semantic and physical verification below before use.
    #[allow(dead_code)]
    pub(crate) fn next_data(&self, base: &Job, input: &request::Input) -> Result<Job> {
        self.canonical_bytes()?;
        base.check_request(input)?;
        let window = match &input.operation {
            request::Operation::Step { window, .. } => Some(window),
            request::Operation::Publish { .. } if matches!(self, Self::Publish(_)) => None,
            _ => return Err("phase candidate does not match requested native operation".into()),
        };
        let stage = match (&base.stage, self) {
            (Stage::Ingest { request, progress }, Self::Ingest(c))
                if c.semantic.request == *request && c.semantic.base == *progress =>
            {
                let w = window.ok_or("ingestion window missing")?;
                if c.semantic.maximum_documents as u16 != w.maximum
                    || c.semantic.window_limits != ingest_window(base, progress, w)?
                {
                    return Err("ingestion candidate changes reviewed window".into());
                }
                Stage::Ingest {
                    request: request.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Statistics { request, progress }, Self::Statistics(c))
                if c.semantic.request == *request && c.semantic.base == *progress =>
            {
                let w = window.ok_or("statistics window missing")?;
                if w.maximum != 4096
                    || c.semantic.window_read_bytes != w.read_bytes
                    || c.semantic.window_write_bytes != w.write_bytes
                {
                    return Err("statistics candidate changes fixed reviewed window".into());
                }
                Stage::Statistics {
                    request: request.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Covariance { request, progress }, Self::Covariance(c))
                if c.request == *request && c.base == *progress =>
            {
                let w = window.ok_or("covariance window missing")?;
                if c.review.maximum_documents as u16 != w.maximum
                    || c.review.window_read_bytes != w.read_bytes
                    || c.review.window_write_bytes != w.write_bytes
                {
                    return Err("covariance candidate changes reviewed window".into());
                }
                Stage::Covariance {
                    request: request.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Projection { request, progress }, Self::Projection(c))
                if c.request == *request && c.base == *progress =>
            {
                let w = window.ok_or("projection window missing")?;
                if c.review.maximum_pair_visits != w.maximum
                    || c.review.window_read_bytes != w.read_bytes
                    || c.review.window_write_bytes != w.write_bytes
                {
                    return Err("projection candidate changes reviewed window".into());
                }
                Stage::Projection {
                    request: request.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Vectors { request, progress }, Self::Vectors(c))
                if c.request == *request && c.base == *progress =>
            {
                let w = window.ok_or("vector window missing")?;
                if c.maximum_documents as u16 != w.maximum
                    || c.window_read_bytes != w.read_bytes
                    || c.window_write_bytes != w.write_bytes
                {
                    return Err("vector candidate changes reviewed window".into());
                }
                Stage::Vectors {
                    request: request.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Audit { job, progress }, Self::Audit(c))
                if c.job == *job && c.base == *progress =>
            {
                let w = window.ok_or("audit window missing")?;
                if c.maximum != w.maximum
                    || c.window_read_bytes != w.read_bytes
                    || w.write_bytes != 0
                {
                    return Err("audit candidate changes reviewed window".into());
                }
                Stage::Audit {
                    job: job.clone(),
                    progress: c.next.clone(),
                }
            }
            (Stage::Audit { job, progress }, Self::Publish(c))
                if c.job == *job && c.audit == *progress =>
            {
                if !matches!(input.operation, request::Operation::Publish { .. }) {
                    return Err(
                        "publication requires explicit independently reviewed publish action"
                            .into(),
                    );
                }
                Stage::Published {
                    manifest: c.manifest.clone(),
                }
            }
            _ => return Err("candidate does not extend the exact selected native phase".into()),
        };
        if stage == base.stage {
            return Err("native index candidate makes no progress".into());
        }
        base.next_data(input, stage)
    }
}

/// Called by the C-side independent replay boundary, never by treating a
/// worker receipt, hash or an already-completed effect as current authority.
#[allow(dead_code)]
pub(crate) fn verify_phase_data<B: NativeIndexBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    base: &Job,
    input: &request::Input,
    candidate: &Commitment,
    content: &mut C,
    b: &mut B,
) -> Result<Job> {
    b.current_native_operation(input)?;
    b.current_native_job(base)?;
    let next = candidate.next_data(base, input)?;
    b.current_plan_review(input, &candidate.review_sha256()?)?;
    match candidate {
        Commitment::Ingest(c) => accounted::verify_accounted_ingestion_data(store, c, content, b)?,
        Commitment::Statistics(c) => {
            statistics_accounted::verify_accounted_statistics_data(store, c, b)?
        }
        Commitment::Covariance(c) => covariance::verify_covariance_data(store, c, content, b)?,
        Commitment::Projection(c) => projection::verify_projection_data(store, c, b)?,
        Commitment::Vectors(c) => vectors::verify_vectors_data(store, c, content, b)?,
        Commitment::Audit(c) => audit::verify_audit_data(store, c, b)?,
        Commitment::Publish(c) => generation::verify_generation_data(store, c, b)?,
    }
    b.current_native_job(base)?;
    b.current_native_operation(input)?;
    Ok(next)
}

enum PlanData {
    Ingest(accounted::AccountedIngestPlan),
    Statistics(statistics_accounted::AccountedStatisticsPlan),
    Covariance(covariance::CovariancePlan),
    Projection(projection::ProjectionPlan),
    Vectors(vectors::VectorPlan),
    Audit(AuditCommitment),
    Publish(generation::GenerationPlan),
}
pub(crate) struct Plan {
    base_sha256: String,
    input_sha256: String,
    builder: BuilderIdentity,
    inner: PlanData,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataMaximum {
    pub(crate) object_writes: u32,
    pub(crate) read_bytes: u64,
    pub(crate) write_bytes: u64,
    pub(crate) new_files: u32,
}
impl MetadataMaximum {
    pub(crate) fn compiled() -> Self {
        Self {
            object_writes: 256,
            read_bytes: 256 * 32768,
            write_bytes: 256 * 131072,
            new_files: 256 * 3,
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self != &Self::compiled() {
            return Err(
                "native metadata maximum is not the exact reviewed compiled ceiling".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowReview {
    pub(crate) schema_version: u32,
    pub(crate) input_sha256: String,
    pub(crate) base_sha256: String,
    pub(crate) phase: String,
    pub(crate) review_sha256: String,
    pub(crate) core_review_sha256: String,
    pub(crate) planned_objects_sha256: String,
    pub(crate) builder: BuilderIdentity,
    pub(crate) policy_sha256: String,
    pub(crate) metadata_maximum: MetadataMaximum,
    pub(crate) source_bytes: u64,
    pub(crate) maximum_read_bytes: u64,
    pub(crate) maximum_write_bytes: u64,
}
impl WindowReview {
    fn digest(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-native-index-window-review-v2",
            self.schema_version,
            &self.input_sha256,
            &self.base_sha256,
            &self.phase,
            &self.core_review_sha256,
            &self.planned_objects_sha256,
            &self.builder,
            &self.policy_sha256,
            &self.metadata_maximum,
            self.source_bytes,
            self.maximum_read_bytes,
            self.maximum_write_bytes,
        ))?))
    }
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.input_sha256,
            &self.base_sha256,
            &self.review_sha256,
            &self.core_review_sha256,
            &self.planned_objects_sha256,
        ] {
            hash(value)?;
        }
        self.builder.validate()?;
        self.metadata_maximum.validate()?;
        if self.schema_version != 2
            || self.policy_sha256 != super::policy::sha256()?
            || !matches!(
                self.phase.as_str(),
                "ingest"
                    | "statistics"
                    | "covariance"
                    | "projection"
                    | "vectors"
                    | "audit"
                    | "publish"
            )
            || self.maximum_read_bytes == 0
            || self.maximum_read_bytes > 128 * 1024 * 1024
            || self.maximum_write_bytes > 128 * 1024 * 1024
            || self.source_bytes > 64 * 1024 * 1024
            || self.review_sha256 != self.digest()?
        {
            return Err("native index reviewed envelope does not bind exact source/plan/builder/metadata maximum".into());
        }
        Ok(())
    }
}
impl Plan {
    /// Complete deterministic DATA inventory of derivative objects. C must
    /// independently reconstruct it before reserving; this is not a creator
    /// proof. Metadata derived from measured effects has its separate exact
    /// preregistration extension after preparation, before metadata writes.
    pub(crate) fn planned_objects(
        &self,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<luma_content_store::v2::ObjectWriteSpec>> {
        use luma_content_store::v2::ObjectWriteSpec;
        check()?;
        let values = match &self.inner {
            PlanData::Ingest(value) => value
                .reserve()
                .pages
                .iter()
                .map(|p| {
                    Ok(ObjectWriteSpec {
                        sha256: p.sha256.clone(),
                        bytes: u32::try_from(p.bytes)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            PlanData::Statistics(value) => value
                .reserve()
                .pages
                .iter()
                .map(|p| {
                    Ok(ObjectWriteSpec {
                        sha256: p.sha256.clone(),
                        bytes: u32::try_from(p.bytes)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            PlanData::Covariance(value) => value.planned_objects(&mut check)?,
            PlanData::Projection(value) => value.planned_objects(&mut check)?,
            PlanData::Vectors(value) => value.planned_objects(&mut check)?,
            PlanData::Publish(value) => value.planned_objects(&mut check)?,
            PlanData::Audit(_) => Vec::new(),
        };
        let mut seen = std::collections::BTreeMap::new();
        let mut result = Vec::new();
        for value in values {
            check()?;
            value.validate()?;
            if let Some(old) = seen.insert(value.sha256.clone(), value.bytes) {
                if old != value.bytes {
                    return Err("phase write-set has inconsistent duplicate object length".into());
                }
            } else {
                result.push(value);
            }
        }
        check()?;
        Ok(result)
    }
    pub(crate) fn review(&self) -> Result<WindowReview> {
        let (phase, review_sha256, source_bytes, maximum_read_bytes, maximum_write_bytes) =
            match &self.inner {
                PlanData::Ingest(v) => (
                    "ingest",
                    v.reserve().review_sha256.clone(),
                    v.reserve().source_bytes,
                    v.semantic().window_limits.read_bytes,
                    v.reserve().maximum_storage_bytes,
                ),
                PlanData::Statistics(v) => (
                    "statistics",
                    v.reserve().review_sha256.clone(),
                    0,
                    v.semantic().window_read_bytes,
                    v.reserve().maximum_storage_bytes,
                ),
                PlanData::Covariance(v) => {
                    let r = v.review();
                    (
                        "covariance",
                        r.sha256()?,
                        r.source_bytes,
                        r.window_read_bytes,
                        r.window_write_bytes,
                    )
                }
                PlanData::Projection(v) => {
                    let r = v.review();
                    (
                        "projection",
                        r.sha256()?,
                        0,
                        r.window_read_bytes,
                        r.window_write_bytes,
                    )
                }
                PlanData::Vectors(v) => {
                    let c = v.commitment();
                    (
                        "vectors",
                        c.review_sha256.clone(),
                        c.source_bytes,
                        c.window_read_bytes,
                        c.window_write_bytes,
                    )
                }
                PlanData::Audit(v) => ("audit", v.review_sha256.clone(), 0, v.window_read_bytes, 0),
                PlanData::Publish(v) => {
                    let r = v.review();
                    ("publish", r.sha256()?, 0, r.read_charge, r.write_charge)
                }
            };
        hash(&review_sha256)?;
        let planned_objects_sha256 =
            luma_content::sha256(&serde_json::to_vec(&self.planned_objects(|| Ok(()))?)?);
        let mut result = WindowReview {
            schema_version: 2,
            input_sha256: self.input_sha256.clone(),
            base_sha256: self.base_sha256.clone(),
            phase: phase.into(),
            review_sha256: String::new(),
            core_review_sha256: review_sha256,
            planned_objects_sha256,
            builder: self.builder.clone(),
            policy_sha256: super::policy::sha256()?,
            metadata_maximum: MetadataMaximum::compiled(),
            source_bytes,
            maximum_read_bytes,
            maximum_write_bytes,
        };
        result.review_sha256 = result.digest()?;
        result.validate()?;
        Ok(result)
    }
    #[allow(dead_code)]
    pub(crate) fn mutation(&self) -> Result<luma_content_store::v2::Mutation> {
        let review = self.review()?;
        Ok(luma_content_store::v2::Mutation {
            review_sha256: review.core_review_sha256,
            decision: luma_content_store::DecisionKind::Published,
            source_bytes: review.source_bytes,
        })
    }
}

fn ingest_window(
    base: &Job,
    progress: &job::IngestProgress,
    window: &request::Window,
) -> Result<CorpusIndexLimits> {
    let left = |cap: u64, used: u64| {
        cap.checked_sub(used)
            .ok_or("index cumulative reservation already exceeds reviewed job")
    };
    let limits = CorpusIndexLimits {
        read_bytes: window.read_bytes,
        write_bytes: window.write_bytes,
        source_bytes: left(base.limits.source_bytes, progress.totals.source_bytes)?
            .min(4 * 1024 * 1024),
        postings: left(base.limits.postings, progress.totals.postings)?.min(4 * 16384),
        floating_operations: left(base.limits.floating_operations, progress.totals.work)?,
    };
    limits.validate()?;
    Ok(limits)
}
pub(crate) fn plan<B: NativeIndexBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    base: &Job,
    input: &request::Input,
    content: &mut C,
    b: &mut B,
) -> Result<Plan> {
    base.check_request(input)?;
    b.current_native_operation(input)?;
    b.current_native_job(base)?;
    let value = match (&base.stage, &input.operation) {
        (Stage::Ingest { request, progress }, request::Operation::Step { window, .. }) => {
            PlanData::Ingest(accounted::account_ingestion_plan(
                job::plan_ingestion_window(
                    store,
                    request,
                    progress,
                    usize::from(window.maximum),
                    ingest_window(base, progress, window)?,
                    content,
                    b,
                )?,
            )?)
        }
        (Stage::Statistics { request, progress }, request::Operation::Step { window, .. }) => {
            if window.maximum != 4096 {
                return Err("statistics has one fixed4096-posting maximum".into());
            }
            PlanData::Statistics(statistics_accounted::account_statistics_plan(
                statistics::plan_statistics_window(
                    store,
                    request,
                    progress,
                    window.read_bytes,
                    window.write_bytes,
                    b,
                )?,
            )?)
        }
        (Stage::Covariance { request, progress }, request::Operation::Step { window, .. }) => {
            PlanData::Covariance(covariance::plan_covariance_window(
                store,
                request,
                progress,
                usize::from(window.maximum),
                window.read_bytes,
                window.write_bytes,
                content,
                b,
            )?)
        }
        (Stage::Projection { request, progress }, request::Operation::Step { window, .. }) => {
            PlanData::Projection(projection::plan_projection_window(
                store,
                request,
                progress,
                usize::from(window.maximum),
                window.read_bytes,
                window.write_bytes,
                b,
            )?)
        }
        (Stage::Vectors { request, progress }, request::Operation::Step { window, .. }) => {
            PlanData::Vectors(vectors::plan_vector_window(
                store,
                request,
                progress,
                usize::from(window.maximum),
                window.read_bytes,
                window.write_bytes,
                content,
                b,
            )?)
        }
        (Stage::Audit { job, progress }, request::Operation::Step { window, .. }) => {
            if window.write_bytes != 0 {
                return Err("independent audit phase cannot write owner objects".into());
            }
            PlanData::Audit(audit::plan_audit_window(
                store,
                job,
                progress,
                usize::from(window.maximum),
                window.read_bytes,
                b,
            )?)
        }
        (Stage::Audit { job, progress }, request::Operation::Publish { .. }) => {
            PlanData::Publish(generation::plan_generation(store, job, progress, b)?)
        }
        _ => return Err("requested work does not match actual protected index phase".into()),
    };
    b.current_native_job(base)?;
    b.current_native_operation(input)?;
    Ok(Plan {
        base_sha256: base.sha256()?,
        input_sha256: input.sha256()?,
        builder: base.builder.clone(),
        inner: value,
    })
}

// Phase preparation and selection acknowledgement run only under index-run,
// which awaits the C index publisher.
#[allow(dead_code)]
pub(crate) enum Prepared {
    Ingest(accounted::PreparedAccountedIngest),
    Statistics(statistics_accounted::PreparedAccountedStatistics),
    Covariance(covariance::PreparedCovariance),
    Projection(projection::PreparedProjection),
    Vectors(vectors::PreparedVectors),
    Audit(audit::PreparedAudit),
    Publish(generation::PreparedGeneration),
}
#[allow(dead_code)]
impl Prepared {
    pub(crate) fn commitment(&self) -> Commitment {
        match self {
            Self::Ingest(v) => Commitment::Ingest(v.commitment().clone()),
            Self::Statistics(v) => Commitment::Statistics(v.commitment().clone()),
            Self::Covariance(v) => Commitment::Covariance(v.commitment().clone()),
            Self::Projection(v) => Commitment::Projection(v.commitment().clone()),
            Self::Vectors(v) => Commitment::Vectors(v.commitment().clone()),
            Self::Audit(v) => Commitment::Audit(v.commitment().clone()),
            Self::Publish(v) => Commitment::Publish(v.commitment().clone()),
        }
    }
    /// This call is not a publisher. The independent actual C selection must
    /// already name this complete next job before any unused hold is released.
    pub(crate) fn acknowledge_selected<B: NativeIndexBoundary>(
        &self,
        next: &Job,
        input: &request::Input,
        b: &mut B,
    ) -> Result<()> {
        b.current_native_operation(input)?;
        b.current_native_job(next)?;
        match self {
            Self::Ingest(v) => v.acknowledge_selected(b)?,
            Self::Statistics(v) => v.acknowledge_selected(b)?,
            Self::Covariance(v) => v.acknowledge_selected(b)?,
            Self::Projection(v) => v.acknowledge_selected(b)?,
            Self::Vectors(v) => v.acknowledge_selected(b)?,
            Self::Audit(v) => v.acknowledge_selected(b)?,
            Self::Publish(v) => v.acknowledge_selected(b)?,
        }
        b.current_native_job(next)?;
        b.current_native_operation(input)
    }
}

#[allow(dead_code)]
pub(crate) fn prepare<B: NativeIndexBoundary>(
    store: &ObjectStore,
    base: &Job,
    input: &request::Input,
    plan: Plan,
    mutation: &luma_content_store::v2::Mutation,
    b: &mut B,
) -> Result<Prepared> {
    base.check_request(input)?;
    b.current_native_operation(input)?;
    b.current_native_job(base)?;
    let actual = plan.mutation()?;
    b.current_plan_review(input, &actual.review_sha256)?;
    if plan.base_sha256 != base.sha256()?
        || plan.input_sha256 != input.sha256()?
        || actual.review_sha256 != mutation.review_sha256
        || actual.decision != mutation.decision
        || actual.source_bytes != mutation.source_bytes
    {
        return Err("native phase plan/mutation differs before any physical dispatch".into());
    }
    let prepared = match plan.inner {
        PlanData::Ingest(v) => Prepared::Ingest(accounted::prepare_accounted_ingestion(
            store, &v, mutation, b,
        )?),
        PlanData::Statistics(v) => Prepared::Statistics(
            statistics_accounted::prepare_accounted_statistics(store, &v, mutation, b)?,
        ),
        PlanData::Covariance(v) => {
            Prepared::Covariance(covariance::prepare_covariance(store, &v, mutation, b)?)
        }
        PlanData::Projection(v) => {
            Prepared::Projection(projection::prepare_projection(store, &v, mutation, b)?)
        }
        PlanData::Vectors(v) => {
            Prepared::Vectors(vectors::prepare_vectors(store, &v, mutation, b)?)
        }
        PlanData::Audit(v) => Prepared::Audit(audit::prepare_audit(&v, mutation, b)?),
        PlanData::Publish(v) => {
            Prepared::Publish(generation::prepare_generation(store, &v, mutation, b)?)
        }
    };
    prepared.commitment().next_data(base, input)?;
    b.current_native_job(base)?;
    b.current_native_operation(input)?;
    Ok(prepared)
}

#[cfg(test)]
mod review_tests {
    use super::*;
    fn audit_review() -> WindowReview {
        let mut result = WindowReview {
            schema_version: 2,
            input_sha256: "a".repeat(64),
            base_sha256: "b".repeat(64),
            phase: "audit".into(),
            review_sha256: String::new(),
            core_review_sha256: "c".repeat(64),
            planned_objects_sha256: luma_content::sha256(b"[]"),
            builder: BuilderIdentity {
                source_sha256: "d".repeat(64),
                runtime_sha256: "e".repeat(64),
            },
            policy_sha256: super::super::policy::sha256().unwrap(),
            metadata_maximum: MetadataMaximum::compiled(),
            source_bytes: 0,
            maximum_read_bytes: 65536,
            maximum_write_bytes: 0,
        };
        result.review_sha256 = result.digest().unwrap();
        result
    }
    #[test]
    fn metadata_only_audit_requires_distinct_explicit_complete_native_review() {
        let value = audit_review();
        value.validate().unwrap();
        assert_ne!(value.review_sha256, value.core_review_sha256);
        assert_eq!(value.maximum_write_bytes, 0);
        assert_eq!(value.metadata_maximum.write_bytes, 32 * 1024 * 1024);
        let mut changed = value.clone();
        changed.metadata_maximum.write_bytes = 0;
        changed.review_sha256 = changed.digest().unwrap();
        assert!(changed.validate().is_err());
        changed = value;
        changed.review_sha256 = changed.core_review_sha256.clone();
        assert!(changed.validate().is_err());
    }
    #[test]
    fn native_review_binds_original_source_builder_inventory_and_every_ceiling() {
        let value = audit_review();
        for field in 0..9 {
            let mut changed = value.clone();
            match field {
                0 => changed.input_sha256 = "f".repeat(64),
                1 => changed.base_sha256 = "f".repeat(64),
                2 => changed.core_review_sha256 = "f".repeat(64),
                3 => changed.planned_objects_sha256 = "f".repeat(64),
                4 => changed.builder.runtime_sha256 = "f".repeat(64),
                5 => changed.maximum_read_bytes += 1,
                6 => changed.maximum_write_bytes += 1,
                7 => changed.source_bytes += 1,
                _ => changed.policy_sha256 = "f".repeat(64),
            }
            assert!(changed.validate().is_err());
        }
        let mut changed = value;
        changed.metadata_maximum.new_files += 1;
        changed.review_sha256 = changed.digest().unwrap();
        assert!(changed.validate().is_err());
        let mut changed = audit_review();
        changed.policy_sha256 = "f".repeat(64);
        changed.review_sha256 = changed.digest().unwrap();
        assert!(changed.validate().is_err());
    }
}
