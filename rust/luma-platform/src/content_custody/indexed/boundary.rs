//! Mandatory current C, original Read, fixed builder and live-source gates.
use super::*;
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

pub(super) struct Gate<'s, 'a, 'b, 'c, A: Checkpoint> {
    pub(super) shared: &'s Shared<'a, 'b, A>,
    pub(super) client: &'s RefCell<Client<'c>>,
}

/// Pure scope comparison only; Gate surrounds it with fresh original Read,
/// current C selection, owner/physical CAS and immutable builder checks.
pub(super) fn selected_read_map(
    head: &OwnerHeadV2,
    input: &Input,
    profile: &str,
    root: &MapRoot,
) -> Result<()> {
    head.validate()?;
    input.validate()?;
    root.validate()?;
    let selected = content_index::request::parse_profile(profile)?;
    content_index::scope::verify_input(profile, &input.canonical_bytes()?)?;
    if input.binding != head.binding
        || root.binding != head.binding
        || !matches!(selected.mode, Mode::Review | Mode::Query)
        || ![
            &head.roots.artifacts,
            &head.roots.lifecycle,
            &head.roots.corpus,
        ]
        .contains(&root)
    {
        return Err(
            "index cursor is not an exact selected source-proof map for this Read purpose".into(),
        );
    }
    // The other six owner maps are not inputs to this read-only index API.
    // Phase walkers separately bind their corpus cursor via current_corpus;
    // derived job/generation spans never supply a caller-selected MapRoot.
    Ok(())
}
impl<A: Checkpoint> Gate<'_, '_, '_, '_, A> {
    pub(super) fn current(
        &mut self,
        check: impl FnOnce(&Current<'_, '_, A>) -> Result<()>,
    ) -> Result<()> {
        let mut c = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant current index scope")?;
        c.check()?;
        check(&c)?;
        c.check()
    }
    pub(super) fn head(&mut self) -> Result<OwnerHeadV2> {
        let mut c = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant current index owner")?;
        c.check()?;
        Ok(c.head.clone())
    }
    #[allow(dead_code)]
    pub(super) fn job(&mut self) -> Result<Job> {
        let mut c = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant current index job")?;
        c.check()?;
        Ok(c.job
            .as_ref()
            .ok_or("no current C-selected index job")?
            .clone())
    }
    fn deny_effect(&mut self) -> Result<()> {
        self.current(|_| {
            Err("query/review IndexRead cannot reserve, approve, release or publish effects".into())
        })
    }
}
impl<A: Checkpoint> Boundary for Gate<'_, '_, '_, '_, A> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.current(|c| {
            if binding != &c.head.binding
                || budget.tasks != 1
                || budget.memory_bytes > 192 * 1024 * 1024
                || budget.read_bytes > c.original.audit().usage.input_bytes
                || budget.write_bytes != 0
                || budget.additional_storage_bytes != 0
            {
                return Err("index read exceeds original finite readonly resources".into());
            }
            Ok(())
        })
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current(|c| {
            if !matches!(access,Access::Inspect{binding} if binding==&c.head.binding) {
                return Err("IndexRead cannot mutate/recover or substitute owner".into());
            }
            Ok(())
        })
    }
}
impl<A: Checkpoint> luma_content_store::v2::cursor::MapCursorBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.current(|c| selected_read_map(&c.head, &c.input, &c.profile, root))
    }
}
impl<A: Checkpoint> CurrentOwnerReadBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.current(|c| {
            if head != &c.head {
                return Err("index source proof does not use current C-selected owner".into());
            }
            Ok(())
        })
    }
}
impl<A: Checkpoint> CorpusIndexBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        self.current(|c| {
            if root != &c.head.roots.corpus {
                return Err("index uses stale/foreign corpus root".into());
            }
            Ok(())
        })
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        self.current(|c| {
            if root != &c.head.roots.corpus || builder != c.builder.identity() {
                return Err("index does not use actual immutable image builder/runtime".into());
            }
            Ok(())
        })
    }
    fn current_index_generation(&mut self, root: &MapRoot, sha: &str) -> Result<()> {
        self.current(|c| {
            if root != &c.head.roots.corpus
                || c.leaf
                    .as_ref()
                    .and_then(|v| v.current_generation.as_ref())
                    .map(|v| v.sha256.as_str())
                    != Some(sha)
            {
                return Err("index generation is not the actual current C selection".into());
            }
            Ok(())
        })
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        record.validate()?;
        let selected = super::proof(self, &record.reference)?;
        let head = self.head()?;
        if selected.verify_data_for_head(&head)?.corpus != *record {
            return Err(
                "index candidate not exact currently live C corpus/artifact/lifecycle tuple".into(),
            );
        }
        self.current_corpus(root)
    }
}
macro_rules! selected_phase {
    ($method:ident,$request:ty,$progress:ty,$field:ident) => {
        fn $method(&mut self, request: &$request, progress: &$progress) -> Result<()> {
            self.current(|c| {
                let job = c.job.as_ref().ok_or("no actual C-selected build job")?;
                if job.source_owner.roots.corpus != c.head.roots.corpus
                    || job.builder != *c.builder.identity()
                    || job.lineage()?.$field != Some((request, progress))
                {
                    return Err(
                        "index phase/base does not match actual selected job lineage".into(),
                    );
                }
                Ok(())
            })
        }
    };
}
impl<A: Checkpoint> CorpusIndexJobBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_job(&mut self, r: &IngestRequest, p: &IngestProgress) -> Result<()> {
        self.current(|c| {
            let job = c.job.as_ref().ok_or("no actual current ingestion job")?;
            if job.source_owner.roots.corpus != c.head.roots.corpus
                || job.builder != *c.builder.identity()
                || job.lineage()?.ingestion != (r, p)
            {
                return Err("ingestion lineage is not current C-selected owner/job".into());
            }
            Ok(())
        })
    }
    fn verify_ingest_allocations(&mut self, _: &IngestCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> StatisticsBoundary for Gate<'_, '_, '_, '_, A> {
    selected_phase!(
        current_statistics,
        StatisticsRequest,
        StatisticsProgress,
        statistics
    );
    fn verify_statistics_allocations(&mut self, _: &StatisticsCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> CovarianceBoundary for Gate<'_, '_, '_, '_, A> {
    selected_phase!(
        current_covariance,
        CovarianceRequest,
        CovarianceProgress,
        covariance
    );
    fn verify_covariance_allocations(&mut self, _: &CovarianceCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> ProjectionBoundary for Gate<'_, '_, '_, '_, A> {
    selected_phase!(
        current_projection,
        ProjectionRequest,
        ProjectionProgress,
        projection
    );
    fn verify_projection_allocations(&mut self, _: &ProjectionCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> VectorBoundary for Gate<'_, '_, '_, '_, A> {
    selected_phase!(current_vectors, VectorRequest, VectorProgress, vectors);
    fn verify_vector_allocations(&mut self, _: &VectorCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> GenerationAuditBoundary for Gate<'_, '_, '_, '_, A> {
    selected_phase!(
        current_generation_audit,
        GenerationJob,
        AuditProgress,
        audit
    );
    fn verify_audit_reservations(&mut self, _: &AuditCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> GenerationPublicationBoundary for Gate<'_, '_, '_, '_, A> {
    fn verify_original_phase_provenance(
        &mut self,
        job: &GenerationJob,
        audit: &AuditProgress,
    ) -> Result<()> {
        self.current_generation_audit(job, audit)?;
        self.current(|c|{if !matches!(&c.job.as_ref().ok_or("no selected generation provenance")?.stage,Stage::Audit{job:actual,progress} if actual==job&&progress==audit)||!c.job.as_ref().unwrap().stage.complete()?{return Err("publication review has no actual C-selected complete phase/audit lineage".into());}Ok(())})
    }
    fn reserve_generation(&mut self, _: &GenerationReview) -> Result<()> {
        self.deny_effect()
    }
    fn verify_generation_allocations(&mut self, _: &GenerationCommitment) -> Result<()> {
        self.deny_effect()
    }
    fn release_generation_after_selection(&mut self, _: &GenerationCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> CurrentGenerationBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_generation(&mut self, manifest: &GenerationManifest) -> Result<()> {
        manifest.canonical_bytes()?;
        self.current_corpus(&manifest.corpus)?;
        self.current_builder(&manifest.corpus, &manifest.builder)?;
        self.current_index_generation(&manifest.corpus, &manifest.sha256()?)
    }
}
impl<A: Checkpoint> PageAccountingBoundary for Gate<'_, '_, '_, '_, A> {
    fn reserve_pages(&mut self, _: &PageReserve) -> Result<()> {
        self.deny_effect()
    }
    fn observe_pages(
        &mut self,
        _: &PageDebitCommitment,
        _: &CapturedPageMeasurements,
    ) -> Result<()> {
        self.deny_effect()
    }
    fn verify_pages(&mut self, _: &PageDebitCommitment) -> Result<()> {
        self.deny_effect()
    }
    fn release_pages_after_selection(&mut self, _: &PageDebitCommitment) -> Result<()> {
        self.deny_effect()
    }
}
impl<A: Checkpoint> phase::NativeIndexBoundary for Gate<'_, '_, '_, '_, A> {
    fn current_native_job(&mut self, job: &Job) -> Result<()> {
        self.current(|c| {
            if c.job.as_ref() != Some(job)
                || job.source_owner.roots.corpus != c.head.roots.corpus
                || job.builder != *c.builder.identity()
            {
                return Err("native job is not current C-selected exact lineage/builder".into());
            }
            Ok(())
        })
    }
    fn current_native_operation(&mut self, input: &Input) -> Result<()> {
        self.current(|c| {
            if input != &c.input {
                return Err("native input is not the actual original IndexRead source".into());
            }
            Ok(())
        })
    }
    fn current_plan_review(&mut self, _: &Input, _: &str) -> Result<()> {
        self.deny_effect()
    }
}
