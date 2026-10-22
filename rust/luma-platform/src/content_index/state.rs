//! Exact persisted build DATA. Advancing a phase is a deterministic transition
//! from the independently selected whole previous record, never from a caller
//! phase/cursor or the apparent presence of generated files.
use super::*;
use luma_content_store::corpus_index::job::{
    covariance::{
        projection::{
            vectors::{
                generation::{
                    audit::{AuditPhase, AuditProgress},
                    GenerationJob, GenerationManifest,
                },
                VectorProgress, VectorRequest,
            },
            ProjectionProgress, ProjectionRequest,
        },
        CovarianceProgress, CovarianceRequest,
    },
    statistics::{StatisticsProgress, StatisticsRequest},
    IngestProgress, IngestRequest, IngestTotals,
};
use luma_content_store::v2::head::OwnerHeadV2;

const JOB_DOMAIN: &str = "luma-native-owner-corpus-job-v2";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    pub(crate) schema_version: u32,
    pub(crate) domain: String,
    pub(crate) job_id: String,
    pub(crate) start_request_sha256: String,
    pub(crate) source_owner: OwnerHeadV2,
    pub(crate) builder: BuilderIdentity,
    pub(crate) dimensions: u16,
    pub(crate) limits: CorpusIndexLimits,
    pub(crate) revision: u64,
    pub(crate) previous_job_sha256: Option<String>,
    pub(crate) last_request_id: String,
    pub(crate) stage: Stage,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Stage {
    Ingest {
        request: IngestRequest,
        progress: IngestProgress,
    },
    Statistics {
        request: StatisticsRequest,
        progress: StatisticsProgress,
    },
    Covariance {
        request: CovarianceRequest,
        progress: CovarianceProgress,
    },
    Projection {
        request: ProjectionRequest,
        progress: ProjectionProgress,
    },
    Vectors {
        request: VectorRequest,
        progress: VectorProgress,
    },
    Audit {
        job: GenerationJob,
        progress: AuditProgress,
    },
    Published {
        manifest: GenerationManifest,
    },
    Retained {
        previous_stage_sha256: String,
        preparation_sha256: String,
        retained_inventory_sha256: String,
        review_sha256: String,
    },
}

impl Stage {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Ingest { .. } => "ingest",
            Self::Statistics { .. } => "statistics",
            Self::Covariance { .. } => "covariance",
            Self::Projection { .. } => "projection",
            Self::Vectors { .. } => "vectors",
            Self::Audit { .. } => "audit",
            Self::Published { .. } => "published",
            Self::Retained { .. } => "retained",
        }
    }
    pub(crate) fn totals(&self) -> Option<IngestTotals> {
        match self {
            Self::Ingest { progress, .. } => Some(progress.totals),
            Self::Statistics { progress, .. } => Some(progress.totals),
            Self::Covariance { progress, .. } => Some(progress.totals),
            Self::Projection { progress, .. } => Some(progress.totals),
            Self::Vectors { progress, .. } => Some(progress.totals),
            Self::Audit { progress, .. } => Some(progress.totals),
            Self::Published { manifest } => Some(manifest.totals),
            Self::Retained { .. } => None,
        }
    }
    fn ingestion(&self) -> Option<&IngestRequest> {
        match self {
            Self::Ingest { request, .. } => Some(request),
            Self::Statistics { request, .. } => Some(&request.ingestion),
            Self::Covariance { request, .. } => Some(&request.statistics.ingestion),
            Self::Projection { request, .. } => Some(&request.covariance.statistics.ingestion),
            Self::Vectors { request, .. } => {
                Some(&request.projection.covariance.statistics.ingestion)
            }
            Self::Audit { job, .. } => {
                Some(&job.request.projection.covariance.statistics.ingestion)
            }
            Self::Published { .. } | Self::Retained { .. } => None,
        }
    }
    pub(crate) fn complete(&self) -> Result<bool> {
        Ok(match self {
            Self::Ingest { request, progress } => progress.complete(request)?,
            Self::Statistics { progress, .. } => progress.complete,
            Self::Covariance { progress, .. } => progress.complete,
            Self::Projection { progress, .. } => progress.cursor.complete,
            Self::Vectors { progress, .. } => progress.complete,
            Self::Audit { progress, .. } => progress.phase == AuditPhase::Complete,
            Self::Published { .. } | Self::Retained { .. } => true,
        })
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Ingest { request, progress } => {
                progress.canonical_bytes(request)?;
            }
            Self::Statistics { request, progress } => {
                progress.canonical_bytes(request)?;
            }
            Self::Covariance { request, progress } => {
                progress.canonical_bytes(request)?;
            }
            Self::Projection { request, progress } => {
                progress.canonical_bytes(request)?;
            }
            Self::Vectors { request, progress } => {
                progress.canonical_bytes(request)?;
            }
            Self::Audit { job, progress } => {
                progress.canonical_bytes(job)?;
            }
            Self::Published { manifest } => {
                manifest.canonical_bytes()?;
            }
            Self::Retained {
                previous_stage_sha256,
                preparation_sha256,
                retained_inventory_sha256,
                review_sha256,
            } => {
                hash(previous_stage_sha256)?;
                hash(preparation_sha256)?;
                hash(retained_inventory_sha256)?;
                hash(review_sha256)?;
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_JOB {
            return Err("native index phase exceeds immutable job record bound".into());
        }
        Ok(bytes)
    }
}

impl Job {
    pub(crate) fn beginning_review_data(
        input: &request::Input,
        owner: &OwnerHeadV2,
        builder: &BuilderIdentity,
        selected_sha256: &str,
    ) -> Result<String> {
        let candidate = Self::beginning_data(input, owner, builder, selected_sha256)?;
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-native-index-start-review-v2",
            input.sha256()?,
            owner.sha256()?,
            selected_sha256,
            builder,
            candidate.sha256()?,
        ))?))
    }
    fn identity_sha256(&self) -> Result<String> {
        identity_sha256(
            &self.job_id,
            &self.start_request_sha256,
            &self.source_owner,
            &self.builder,
            self.dimensions,
            self.limits,
        )
    }
    fn expected_ingestion(&self) -> Result<IngestRequest> {
        Ok(IngestRequest {
            schema_version: 1,
            job_sha256: self.identity_sha256()?,
            corpus: self.source_owner.roots.corpus.clone(),
            builder: self.builder.clone(),
            limits: self.limits,
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        identifier(&self.job_id)?;
        identifier(&self.last_request_id)?;
        hash(&self.start_request_sha256)?;
        self.source_owner.validate()?;
        self.builder.validate()?;
        self.limits.validate()?;
        self.stage.canonical_bytes()?;
        if self.schema_version != 2
            || self.domain != JOB_DOMAIN
            || self.dimensions == 0
            || usize::from(self.dimensions) > luma_content_store::corpus_index::MAX_DIMENSIONS
            || self.limits.write_bytes == 0
            || self.revision == 0
            || (self.revision == 1) != self.previous_job_sha256.is_none()
        {
            return Err("native index job identity/revision/dimension contract differs".into());
        }
        if let Some(previous) = &self.previous_job_sha256 {
            hash(previous)?;
        }
        if let Some(ingestion) = self.stage.ingestion() {
            if *ingestion != self.expected_ingestion()? {
                return Err(
                    "native index phase replaces its original owner/corpus/builder/limits".into(),
                );
            }
        }
        let projection = match &self.stage {
            Stage::Projection { request, .. } => Some(request),
            Stage::Vectors { request, .. } => Some(&request.projection),
            Stage::Audit { job, .. } => Some(&job.request.projection),
            _ => None,
        };
        if projection.is_some_and(|p| p.requested_dimensions != self.dimensions) {
            return Err("native index phase replaces original reviewed dimensions".into());
        }
        if let Stage::Published { manifest } = &self.stage {
            if manifest.corpus != self.source_owner.roots.corpus
                || manifest.builder != self.builder
                || manifest.dimensions as u16 > self.dimensions
            {
                return Err("published index descriptor differs from original job source".into());
            }
        }
        if self.revision == 1
            && !matches!(&self.stage,Stage::Ingest{request,progress} if *progress==IngestProgress::beginning(request)?)
        {
            return Err(
                "initial native index job must start at genuine empty ingestion progress".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_JOB {
            return Err("whole native index job exceeds1MiB".into());
        }
        Ok(bytes)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_JOB)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    /// Pure reconstruction. Runtime must independently supply the actual C
    /// owner/selection and fixed image builder, and select the result under CAS.
    pub(crate) fn beginning_data(
        input: &request::Input,
        owner: &OwnerHeadV2,
        builder: &BuilderIdentity,
        selected_sha256: &str,
    ) -> Result<Self> {
        input.validate()?;
        owner.validate()?;
        builder.validate()?;
        hash(selected_sha256)?;
        let request::Operation::Start {
            expected_owner_sha256,
            expected_selection_sha256,
            job_id,
            dimensions,
            limits,
        } = &input.operation
        else {
            return Err("not an index start request".into());
        };
        if input.binding != owner.binding
            || *expected_owner_sha256 != owner.sha256()?
            || expected_selection_sha256 != selected_sha256
            || owner.roots.pending.entry_count != 0
        {
            return Err("index start source/owner/selected generation changed or requires preparation recovery".into());
        }
        let start_request_sha256 = input.sha256()?;
        let request = IngestRequest {
            schema_version: 1,
            job_sha256: identity_sha256(
                job_id,
                &start_request_sha256,
                owner,
                builder,
                *dimensions,
                *limits,
            )?,
            corpus: owner.roots.corpus.clone(),
            builder: builder.clone(),
            limits: *limits,
        };
        let stage = Stage::Ingest {
            progress: IngestProgress::beginning(&request)?,
            request,
        };
        let value = Self {
            schema_version: 2,
            domain: JOB_DOMAIN.into(),
            job_id: job_id.clone(),
            start_request_sha256,
            source_owner: owner.clone(),
            builder: builder.clone(),
            dimensions: *dimensions,
            limits: *limits,
            revision: 1,
            previous_job_sha256: None,
            last_request_id: input.request_id.clone(),
            stage,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn check_request(&self, input: &request::Input) -> Result<()> {
        self.validate()?;
        input.validate()?;
        let (id, expected) = match &input.operation {
            request::Operation::Step {
                job_id,
                expected_job_sha256,
                ..
            }
            | request::Operation::Advance {
                job_id,
                expected_job_sha256,
            }
            | request::Operation::Publish {
                job_id,
                expected_job_sha256,
            }
            | request::Operation::Retain {
                job_id,
                expected_job_sha256,
                ..
            } => (job_id, expected_job_sha256),
            _ => return Err("request does not address a selected build job".into()),
        };
        if input.binding != self.source_owner.binding
            || *id != self.job_id
            || *expected != self.sha256()?
            || input.request_id == self.last_request_id
        {
            return Err("index job CAS/owner/request changed; fresh review is required".into());
        }
        Ok(())
    }
    pub(super) fn next_data(&self, input: &request::Input, stage: Stage) -> Result<Self> {
        self.check_request(input)?;
        let mut next = self.clone();
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or("index revision overflow")?;
        next.previous_job_sha256 = Some(self.sha256()?);
        next.last_request_id = input.request_id.clone();
        next.stage = stage;
        next.validate()?;
        Ok(next)
    }
    pub(crate) fn advance_data(&self, input: &request::Input) -> Result<Self> {
        self.check_request(input)?;
        if !matches!(input.operation, request::Operation::Advance { .. })
            || !self.stage.complete()?
        {
            return Err("phase advance requires exact completed current phase".into());
        }
        let stage =
            match &self.stage {
                Stage::Ingest { request, progress } => {
                    let request = StatisticsRequest {
                        schema_version: 1,
                        ingestion: request.clone(),
                        ingested: progress.clone(),
                    };
                    Stage::Statistics {
                        progress: StatisticsProgress::beginning(&request)?,
                        request,
                    }
                }
                Stage::Statistics { request, progress } => {
                    let request = CovarianceRequest {
                        schema_version: 1,
                        statistics: request.clone(),
                        selected_statistics: progress.clone(),
                    };
                    Stage::Covariance {
                        progress: CovarianceProgress::beginning(&request)?,
                        request,
                    }
                }
                Stage::Covariance { request, progress } => {
                    let request = ProjectionRequest {
                        schema_version: 1,
                        covariance: request.clone(),
                        selected_covariance: progress.clone(),
                        requested_dimensions: self.dimensions,
                    };
                    Stage::Projection {
                        progress: ProjectionProgress::beginning(&request)?,
                        request,
                    }
                }
                Stage::Projection { request, progress } => {
                    let request = VectorRequest {
                        schema_version: 1,
                        projection: request.clone(),
                        selected_projection: progress.clone(),
                    };
                    Stage::Vectors {
                        progress: VectorProgress::beginning(&request)?,
                        request,
                    }
                }
                Stage::Vectors { request, progress } => {
                    let job = GenerationJob {
                        schema_version: 1,
                        request: request.clone(),
                        progress: progress.clone(),
                    };
                    Stage::Audit {
                        progress: AuditProgress::beginning(&job)?,
                        job,
                    }
                }
                Stage::Audit { .. } => return Err(
                    "complete audit requires separately reviewed publication, not another advance"
                        .into(),
                ),
                Stage::Published { .. } | Stage::Retained { .. } => {
                    return Err("terminal index job cannot be restarted or adopted".into())
                }
            };
        self.next_data(input, stage)
    }
    pub(crate) fn advance_review_data(&self, input: &request::Input) -> Result<String> {
        let candidate = self.advance_data(input)?;
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-native-index-advance-review-v2",
            input.sha256()?,
            self.sha256()?,
            candidate.sha256()?,
        ))?))
    }
}

fn identity_sha256(
    job_id: &str,
    start_request_sha256: &str,
    source_owner: &OwnerHeadV2,
    builder: &BuilderIdentity,
    dimensions: u16,
    limits: CorpusIndexLimits,
) -> Result<String> {
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        JOB_DOMAIN,
        job_id,
        start_request_sha256,
        source_owner,
        builder,
        dimensions,
        limits,
    ))?))
}

/// Exact ancestor DATA projected from one whole C-selected job. These borrows
/// do not refresh selection or authorize using an ancestor on its own.
pub(crate) struct Lineage<'a> {
    pub(crate) ingestion: (&'a IngestRequest, &'a IngestProgress),
    pub(crate) statistics: Option<(&'a StatisticsRequest, &'a StatisticsProgress)>,
    pub(crate) covariance: Option<(&'a CovarianceRequest, &'a CovarianceProgress)>,
    pub(crate) projection: Option<(&'a ProjectionRequest, &'a ProjectionProgress)>,
    pub(crate) vectors: Option<(&'a VectorRequest, &'a VectorProgress)>,
    pub(crate) audit: Option<(&'a GenerationJob, &'a AuditProgress)>,
}
impl Job {
    pub(crate) fn lineage(&self) -> Result<Lineage<'_>> {
        self.validate()?;
        let (ingestion, statistics, covariance, projection, vectors, audit) = match &self.stage {
            Stage::Ingest { request, progress } => {
                ((request, progress), None, None, None, None, None)
            }
            Stage::Statistics { request, progress } => (
                (&request.ingestion, &request.ingested),
                Some((request, progress)),
                None,
                None,
                None,
                None,
            ),
            Stage::Covariance { request, progress } => (
                (&request.statistics.ingestion, &request.statistics.ingested),
                Some((&request.statistics, &request.selected_statistics)),
                Some((request, progress)),
                None,
                None,
                None,
            ),
            Stage::Projection { request, progress } => (
                (
                    &request.covariance.statistics.ingestion,
                    &request.covariance.statistics.ingested,
                ),
                Some((
                    &request.covariance.statistics,
                    &request.covariance.selected_statistics,
                )),
                Some((&request.covariance, &request.selected_covariance)),
                Some((request, progress)),
                None,
                None,
            ),
            Stage::Vectors { request, progress } => (
                (
                    &request.projection.covariance.statistics.ingestion,
                    &request.projection.covariance.statistics.ingested,
                ),
                Some((
                    &request.projection.covariance.statistics,
                    &request.projection.covariance.selected_statistics,
                )),
                Some((
                    &request.projection.covariance,
                    &request.projection.selected_covariance,
                )),
                Some((&request.projection, &request.selected_projection)),
                Some((request, progress)),
                None,
            ),
            Stage::Audit { job, progress } => (
                (
                    &job.request.projection.covariance.statistics.ingestion,
                    &job.request.projection.covariance.statistics.ingested,
                ),
                Some((
                    &job.request.projection.covariance.statistics,
                    &job.request.projection.covariance.selected_statistics,
                )),
                Some((
                    &job.request.projection.covariance,
                    &job.request.projection.selected_covariance,
                )),
                Some((&job.request.projection, &job.request.selected_projection)),
                Some((&job.request, &job.progress)),
                Some((job, progress)),
            ),
            Stage::Published { .. } | Stage::Retained { .. } => {
                return Err("terminal job is not current build-phase authority".into())
            }
        };
        Ok(Lineage {
            ingestion,
            statistics,
            covariance,
            projection,
            vectors,
            audit,
        })
    }

    /// Terminal DATA only. The C publisher must independently prove that the
    /// reviewed pending preparation and retained physical inventory are current
    /// and fully charged. Nothing here purges bytes, adopts a page or releases
    /// a physical reservation on an unknown outcome.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retain_data(&self, input: &request::Input) -> Result<Self> {
        self.check_request(input)?;
        let request::Operation::Retain {
            preparation_sha256,
            retained_inventory_sha256,
            review_sha256,
            ..
        } = &input.operation
        else {
            return Err("not an explicit index retention request".into());
        };
        if matches!(self.stage, Stage::Published { .. } | Stage::Retained { .. }) {
            return Err("terminal index job cannot be retained again".into());
        }
        let previous_stage_sha256 = luma_content::sha256(&self.stage.canonical_bytes()?);
        let expected = retention_review_sha256(
            &self.source_owner.binding,
            &self.job_id,
            &self.sha256()?,
            preparation_sha256,
            retained_inventory_sha256,
        )?;
        if *review_sha256 != expected {
            return Err(
                "index retention requires exact current independently reviewed disposition".into(),
            );
        }
        self.next_data(
            input,
            Stage::Retained {
                previous_stage_sha256,
                preparation_sha256: preparation_sha256.clone(),
                retained_inventory_sha256: retained_inventory_sha256.clone(),
                review_sha256: review_sha256.clone(),
            },
        )
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn retention_review_sha256(
    binding: &OwnerBinding,
    job_id: &str,
    job_sha256: &str,
    preparation_sha256: &str,
    retained_inventory_sha256: &str,
) -> Result<String> {
    binding.validate()?;
    identifier(job_id)?;
    hash(job_sha256)?;
    hash(preparation_sha256)?;
    hash(retained_inventory_sha256)?;
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-native-index-retain-only-v2",
        binding,
        job_id,
        job_sha256,
        preparation_sha256,
        retained_inventory_sha256,
    ))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (request::Input, OwnerHeadV2, BuilderIdentity) {
        let binding = OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 1,
        };
        let owner = OwnerHeadV2::empty_data(
            &binding,
            luma_content_store::v2::PhysicalInventory::default(),
        )
        .unwrap();
        let input = request::Input {
            schema_version: 1,
            login: "admin".into(),
            binding,
            request_id: "1".repeat(32),
            operation: request::Operation::Start {
                expected_owner_sha256: owner.sha256().unwrap(),
                expected_selection_sha256: "c".repeat(64),
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
        };
        (
            input,
            owner,
            BuilderIdentity {
                source_sha256: "d".repeat(64),
                runtime_sha256: "e".repeat(64),
            },
        )
    }
    fn advance(job: &Job, mut input: request::Input, id: char) -> request::Input {
        input.request_id = id.to_string().repeat(32);
        input.operation = request::Operation::Advance {
            job_id: job.job_id.clone(),
            expected_job_sha256: job.sha256().unwrap(),
        };
        input
    }
    #[test]
    fn exact_selected_source_and_deterministic_phase_advance() {
        let (input, owner, builder) = fixture();
        let job = Job::beginning_data(&input, &owner, &builder, &"c".repeat(64)).unwrap();
        assert_eq!(Job::parse(&job.canonical_bytes().unwrap()).unwrap(), job);
        assert!(Job::beginning_data(&input, &owner, &builder, &"f".repeat(64)).is_err());
        let next_input = advance(&job, input.clone(), '3');
        let statistics = job.advance_data(&next_input).unwrap();
        assert!(matches!(statistics.stage, Stage::Statistics { .. }));
        assert_eq!(statistics.previous_job_sha256, Some(job.sha256().unwrap()));
        let covariance = statistics
            .advance_data(&advance(&statistics, input.clone(), '4'))
            .unwrap();
        assert!(matches!(covariance.stage, Stage::Covariance { .. }));
        let projection = covariance
            .advance_data(&advance(&covariance, input.clone(), '5'))
            .unwrap();
        assert!(matches!(projection.stage, Stage::Projection { .. }));
        assert!(projection
            .advance_data(&advance(&projection, input.clone(), '6'))
            .is_err());
        assert!(statistics.advance_data(&next_input).is_err());
        let lineage = projection.lineage().unwrap();
        assert_eq!(lineage.ingestion.0, job.lineage().unwrap().ingestion.0);
        assert!(lineage.covariance.is_some());
        assert!(lineage.projection.is_some());
        assert!(lineage.vectors.is_none());
    }
    #[test]
    fn persisted_job_cannot_relabel_source_builder_limits_or_revision() {
        let (input, owner, builder) = fixture();
        let job = Job::beginning_data(&input, &owner, &builder, &"c".repeat(64)).unwrap();
        let mut changed = job.clone();
        changed.builder.runtime_sha256 = "f".repeat(64);
        assert!(changed.validate().is_err());
        changed = job.clone();
        changed.dimensions = 7;
        assert!(changed.validate().is_err());
        changed = job.clone();
        changed.limits.read_bytes += 1;
        assert!(changed.validate().is_err());
        changed = job.clone();
        changed.revision = 2;
        assert!(changed.validate().is_err());
        changed = job.clone();
        changed.source_owner.binding.owner_generation += 1;
        assert!(changed.validate().is_err());
        let mut stale = advance(&job, input, '3');
        stale.binding.owner_generation += 1;
        assert!(job.advance_data(&stale).is_err());
    }
    #[test]
    fn canonical_job_rejects_duplicate_unknown_and_unselected_phase() {
        let (input, owner, builder) = fixture();
        let job = Job::beginning_data(&input, &owner, &builder, &"c".repeat(64)).unwrap();
        let bytes = job.canonical_bytes().unwrap();
        let duplicated = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"revision\":1",
            "\"revision\":1,\"revision\":1",
            1,
        );
        assert!(Job::parse(duplicated.as_bytes()).is_err());
        let mut changed = serde_json::to_value(&job).unwrap();
        changed["stage"]["selected"] = true.into();
        assert!(Job::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut request = advance(&job, input, '3');
        request.operation = request::Operation::Publish {
            job_id: job.job_id.clone(),
            expected_job_sha256: job.sha256().unwrap(),
        };
        assert!(job.advance_data(&request).is_err());
    }

    #[test]
    fn exact_retention_is_terminal_data_not_adoption_purge_or_reservation_release() {
        let (mut input, owner, builder) = fixture();
        let job = Job::beginning_data(&input, &owner, &builder, &"c".repeat(64)).unwrap();
        input.request_id = "3".repeat(32);
        let preparation = "d".repeat(64);
        let inventory = "e".repeat(64);
        input.operation = request::Operation::Retain {
            job_id: job.job_id.clone(),
            expected_job_sha256: job.sha256().unwrap(),
            preparation_sha256: preparation.clone(),
            retained_inventory_sha256: inventory.clone(),
            review_sha256: retention_review_sha256(
                &owner.binding,
                &job.job_id,
                &job.sha256().unwrap(),
                &preparation,
                &inventory,
            )
            .unwrap(),
        };
        let retained = job.retain_data(&input).unwrap();
        assert!(matches!(retained.stage, Stage::Retained { .. }));
        assert_eq!(retained.source_owner, job.source_owner);
        assert!(retained.lineage().is_err());
        assert!(retained
            .advance_data(&advance(&retained, input.clone(), '4'))
            .is_err());
        if let request::Operation::Retain {
            retained_inventory_sha256,
            ..
        } = &mut input.operation
        {
            *retained_inventory_sha256 = "f".repeat(64);
        }
        assert!(job.retain_data(&input).is_err());
    }
}
