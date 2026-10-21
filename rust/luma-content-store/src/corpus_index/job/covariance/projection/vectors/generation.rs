//! Whole-chain generation construction. Immutable descriptors are DATA until a
//! genuine independently replayed current C publication selects them.
use super::*;
pub mod audit;
pub mod query;
use std::cell::Cell;

const GENERATION_PROFILE: &str = "luma-selected-corpus-generation-v2";
const MAX_JOB_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationJob {
    pub schema_version: u32,
    pub request: VectorRequest,
    pub progress: VectorProgress,
}
impl GenerationJob {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.progress.canonical_bytes(&self.request)?;
        if self.schema_version != 1 || !self.progress.complete {
            return Err("generation requires exact complete vector/source/phase closure".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_JOB_BYTES {
            return Err("whole generation job exceeds finite immutable record".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    fn corpus(&self) -> &MapRoot {
        self.request.corpus()
    }
    fn statistics(&self) -> (&StatisticsRequest, &StatisticsProgress) {
        (
            &self.request.projection.covariance.statistics,
            &self.request.projection.covariance.selected_statistics,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationFeature {
    pub term: String,
    pub documents: u32,
    pub idf_bits: u64,
    pub projection_bits: Vec<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationModel {
    pub schema_version: u32,
    pub job_sha256: String,
    pub features: Vec<GenerationFeature>,
}
impl GenerationModel {
    fn canonical_bytes(&self, job: &GenerationJob) -> Result<Vec<u8>> {
        job.canonical_bytes()?;
        let (_, statistics) = job.statistics();
        let top = &statistics
            .frequencies
            .as_ref()
            .ok_or("selected DF missing")?
            .top;
        let dimensions = usize::from(
            job.progress
                .dimensions
                .ok_or("complete vectors omit actual dimensions")?,
        );
        if self.schema_version != 1
            || self.job_sha256 != job.sha256()?
            || self.features.len() != top.len()
        {
            return Err("generation model substitutes whole selected job/features".into());
        }
        for (feature, expected) in self.features.iter().zip(top) {
            if feature.term != expected.term
                || feature.documents != expected.documents
                || feature.idf_bits
                    != crate::corpus_index::build::idf(job.corpus().entry_count, expected.documents)
                        .to_bits()
                || feature.projection_bits.len() != dimensions
                || feature
                    .projection_bits
                    .iter()
                    .any(|bits| !f64::from_bits(*bits).is_finite())
            {
                return Err("generation model differs from exact DF/basis shape".into());
            }
        }
        for i in 0..dimensions {
            for j in 0..dimensions {
                let dot: f64 = self
                    .features
                    .iter()
                    .map(|f| {
                        f64::from_bits(f.projection_bits[i]) * f64::from_bits(f.projection_bits[j])
                    })
                    .sum();
                if !dot.is_finite() || (dot - if i == j { 1.0 } else { 0.0 }).abs() > 1e-7 {
                    return Err("selected generation basis is not finite/orthonormal".into());
                }
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 256 * 1024 {
            return Err("compact generation model exceeds fixed profile".into());
        }
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationManifest {
    pub schema_version: u32,
    pub profile: String,
    pub corpus: MapRoot,
    pub builder: BuilderIdentity,
    pub job: BlobReference,
    pub model: BlobReference,
    pub audit_sha256: String,
    pub records: Option<VectorNode>,
    pub coordinates: Option<VectorNode>,
    pub dimensions: u8,
    pub features: u16,
    pub vocabulary: u64,
    pub totals: IngestTotals,
}
impl GenerationManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        corpus(&self.corpus)?;
        self.builder.validate()?;
        self.job.validate()?;
        self.model.validate()?;
        hash(&self.audit_sha256)?;
        if self.schema_version != 2
            || self.profile != GENERATION_PROFILE
            || self.job.binding != self.corpus.binding
            || self.model.binding != self.corpus.binding
            || self.job.bytes == 0
            || self.job.bytes > MAX_JOB_BYTES as u64
            || self.model.bytes == 0
            || self.model.bytes > 256 * 1024
            || usize::from(self.dimensions) > MAX_DIMENSIONS
            || usize::from(self.features) > MAX_FEATURES
            || self.dimensions as u16 > self.features
            || self.vocabulary > self.totals.postings
            || self.totals.source_bytes > MAX_INDEX_SOURCE_BYTES
            || self.totals.postings > MAX_INDEX_POSTINGS
        {
            return Err(
                "generation manifest substitutes finite current corpus/model/chain bindings".into(),
            );
        }
        for root in [&self.records, &self.coordinates] {
            match root {
                None if self.corpus.entry_count == 0 => (),
                Some(node)
                    if node.first == 0
                        && u64::from(node.count) == self.corpus.entry_count
                        && node.height <= 8 =>
                {
                    hash(&node.sha256)?
                }
                _ => {
                    return Err(
                        "generation manifest omits exact complete proof/coordinate coverage".into(),
                    )
                }
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 {
            return Err("selected generation manifest exceeds16KiB".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    fn check_job(&self, job: &GenerationJob) -> Result<()> {
        self.canonical_bytes()?;
        job.canonical_bytes()?;
        self.totals.validate(&job.request.limits())?;
        let (_, statistics) = job.statistics();
        let frequencies = statistics
            .frequencies
            .as_ref()
            .ok_or("complete statistics missing")?;
        if self.job.sha256 != job.sha256()?
            || self.job.bytes != job.canonical_bytes()?.len() as u64
            || self.corpus != *job.corpus()
            || self.builder
                != job
                    .request
                    .projection
                    .covariance
                    .statistics
                    .ingestion
                    .builder
            || self.records != job.progress.root
            || self.coordinates != job.progress.coordinates.root
            || Some(self.dimensions) != job.progress.dimensions
            || usize::from(self.features) != frequencies.top.len()
            || self.vocabulary != frequencies.vocabulary
            || self.totals.source_bytes != job.progress.totals.source_bytes
            || self.totals.postings != job.progress.totals.postings
        {
            return Err("manifest differs from actual whole completed phase chain".into());
        }
        Ok(())
    }
}
/// Runtime implementations must bind both the original current audit and the
/// complete independently replayed phase chain to real protected C history and
/// fixed builder, not a supplied valid hash, historical receipt or caller flag.
pub trait GenerationPublicationBoundary: audit::GenerationAuditBoundary {
    fn verify_original_phase_provenance(
        &mut self,
        job: &GenerationJob,
        audit: &audit::AuditProgress,
    ) -> Result<()>;
    fn reserve_generation(&mut self, review: &GenerationReview) -> Result<()>;
    fn verify_generation_allocations(&mut self, value: &GenerationCommitment) -> Result<()>;
    fn release_generation_after_selection(&mut self, value: &GenerationCommitment) -> Result<()>;
}
/// A genuine fresh Read/C selection, distinct from expired build authorization.
/// There is no default and no hash-only implementation in this library.
pub trait CurrentGenerationBoundary: CorpusIndexBoundary {
    fn current_generation(&mut self, manifest: &GenerationManifest) -> Result<()>;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationReview {
    pub schema_version: u32,
    pub job_sha256: String,
    pub audit_sha256: String,
    pub model_sha256: String,
    pub model_bytes: u64,
    pub read_charge: u64,
    pub write_charge: u64,
    pub work_charge: u64,
}
impl GenerationReview {
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            GENERATION_PROFILE,
            self,
        ))?))
    }
}
pub struct GenerationPlan {
    job: GenerationJob,
    audit: audit::AuditProgress,
    review: GenerationReview,
    job_bytes: Vec<u8>,
    model_bytes: Vec<u8>,
}
impl GenerationPlan {
    pub fn review(&self) -> &GenerationReview {
        &self.review
    }
    fn manifest_data(
        &self,
        job_ref: BlobReference,
        model_ref: BlobReference,
    ) -> Result<GenerationManifest> {
        let (_, stats) = self.job.statistics();
        let frequency = stats.frequencies.as_ref().ok_or("selected DF missing")?;
        let manifest = GenerationManifest {
            schema_version: 2,
            profile: GENERATION_PROFILE.into(),
            corpus: self.job.corpus().clone(),
            builder: self
                .job
                .request
                .projection
                .covariance
                .statistics
                .ingestion
                .builder
                .clone(),
            job: job_ref,
            model: model_ref,
            audit_sha256: self.review.audit_sha256.clone(),
            records: self.job.progress.root.clone(),
            coordinates: self.job.progress.coordinates.root.clone(),
            dimensions: self
                .job
                .progress
                .dimensions
                .ok_or("complete vector dimensions absent")?,
            features: u16::try_from(frequency.top.len())?,
            vocabulary: frequency.vocabulary,
            totals: self.audit.totals.plus(&IngestTotals {
                read_bytes: self.review.read_charge,
                write_bytes: self.review.write_charge,
                source_bytes: 0,
                postings: 0,
                work: self.review.work_charge,
            })?,
        };
        manifest.canonical_bytes()?;
        Ok(manifest)
    }
    pub fn planned_objects(
        &self,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<crate::v2::ObjectWriteSpec>> {
        check()?;
        let job_plan = crate::v2::BlobObjectPlan::data(
            &self
                .job
                .request
                .projection
                .covariance
                .statistics
                .ingestion
                .corpus
                .binding,
            &self.job_bytes,
            &mut check,
        )?;
        let model_plan = crate::v2::BlobObjectPlan::data(
            &self
                .job
                .request
                .projection
                .covariance
                .statistics
                .ingestion
                .corpus
                .binding,
            &self.model_bytes,
            &mut check,
        )?;
        let manifest =
            self.manifest_data(job_plan.reference().clone(), model_plan.reference().clone())?;
        let manifest_bytes = manifest.canonical_bytes()?;
        let mut seen = std::collections::BTreeMap::<&str, &[u8]>::new();
        let mut result = Vec::new();
        for plan in [&job_plan, &model_plan] {
            for object in plan.objects() {
                check()?;
                if let Some(prior) = seen.get(object.sha256()) {
                    if *prior != object.bytes() {
                        return Err("generation write-set hash collision".into());
                    }
                } else {
                    seen.insert(object.sha256(), object.bytes());
                    let spec = object.specification();
                    spec.validate()?;
                    result.push(spec);
                }
            }
        }
        let manifest_sha = manifest.sha256()?;
        if let Some(prior) = seen.get(manifest_sha.as_str()) {
            if *prior != manifest_bytes {
                return Err("generation manifest collides with blob data".into());
            }
        } else {
            let spec = crate::v2::ObjectWriteSpec {
                sha256: manifest_sha,
                bytes: u32::try_from(manifest_bytes.len())?,
            };
            spec.validate()?;
            result.push(spec);
        }
        check()?;
        Ok(result)
    }
}
fn build_model<B: GenerationPublicationBoundary>(
    store: &dyn IndexReadStore,
    job: &GenerationJob,
    selected_audit: &audit::AuditProgress,
    b: &mut B,
) -> Result<GenerationModel> {
    let mut live = audit::Current {
        job,
        base: selected_audit,
        b,
    };
    live.current()?;
    let projection = &job.request.selected_projection;
    let reference = projection
        .state
        .as_ref()
        .ok_or("complete projection lacks actual physical basis state")?;
    let bytes = store.read_blob(
        reference,
        IoBudget {
            read_bytes: blob_read_credit(reference.bytes)?,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let state = super::super::decode(&job.request.projection, &projection.cursor, &bytes)?;
    let features = job.request.projection.covariance.features()?;
    if state.basis.len() != features.len() {
        return Err("actual basis rows differ from exact completed DF features".into());
    }
    let model = GenerationModel {
        schema_version: 1,
        job_sha256: job.sha256()?,
        features: features
            .iter()
            .zip(state.basis)
            .map(|((term, documents), row)| GenerationFeature {
                term: term.clone(),
                documents: *documents,
                idf_bits: crate::corpus_index::build::idf(job.corpus().entry_count, *documents)
                    .to_bits(),
                projection_bits: row.iter().map(|v| v.to_bits()).collect(),
            })
            .collect(),
    };
    model.canonical_bytes(job)?;
    live.current()?;
    Ok(model)
}
pub fn plan_generation<B: GenerationPublicationBoundary>(
    store: &dyn IndexReadStore,
    job: &GenerationJob,
    selected_audit: &audit::AuditProgress,
    b: &mut B,
) -> Result<GenerationPlan> {
    let job_bytes = job.canonical_bytes()?;
    let audit_bytes = selected_audit.canonical_bytes(job)?;
    if selected_audit.phase != audit::AuditPhase::Complete {
        return Err(
            "generation publication requires actual complete selected independent closure audit"
                .into(),
        );
    }
    audit::Current {
        job,
        base: selected_audit,
        b,
    }
    .current()?;
    b.verify_original_phase_provenance(job, selected_audit)?;
    let projection = job
        .request
        .selected_projection
        .state
        .as_ref()
        .ok_or("complete projection has no actual state")?;
    let read_charge = blob_read_credit(projection.bytes)?
        .checked_mul(2)
        .and_then(|v| v.checked_add(blob_read_credit(job_bytes.len() as u64).ok()?))
        .and_then(|v| v.checked_add(blob_read_credit(256 * 1024).ok()?))
        .and_then(|v| {
            v.checked_add(
                (object_count(job_bytes.len()).ok()? + object_count(256 * 1024).ok()? + 2)
                    * RUN_PAGE_READ,
            )
        })
        .ok_or("generation read reserve overflow")?;
    if read_charge > job.request.limits().read_bytes - selected_audit.totals.read_bytes {
        return Err("final generation cannot reserve independent model/job verification".into());
    }
    let work_charge = 2
        * job.request.projection.n()? as u64
        * u64::from(
            job.progress
                .dimensions
                .ok_or("actual vector dimensions absent")?,
        )
        .pow(2);
    if work_charge > job.request.limits().floating_operations - selected_audit.totals.work {
        return Err("generation model verification exceeds remaining actual work budget before reconstruction".into());
    }
    let model_bytes = build_model(store, job, selected_audit, b)?.canonical_bytes(job)?;
    let objects = object_count(job_bytes.len())?
        .checked_add(object_count(model_bytes.len())?)
        .and_then(|n| n.checked_add(1))
        .ok_or("generation object reserve overflow")?;
    let write_charge = objects
        .checked_mul(PAGE_WRITE)
        .ok_or("generation write reserve overflow")?;
    if write_charge > job.request.limits().write_bytes - selected_audit.totals.write_bytes {
        return Err(
            "final generation cannot reserve actual immutable descriptor/model/job writes".into(),
        );
    }
    let review = GenerationReview {
        schema_version: 1,
        job_sha256: job.sha256()?,
        audit_sha256: luma_content::sha256(&audit_bytes),
        model_sha256: luma_content::sha256(&model_bytes),
        model_bytes: model_bytes.len() as u64,
        read_charge,
        write_charge,
        work_charge,
    };
    audit::Current {
        job,
        base: selected_audit,
        b,
    }
    .current()?;
    Ok(GenerationPlan {
        job: job.clone(),
        audit: selected_audit.clone(),
        review,
        job_bytes,
        model_bytes,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationCommitment {
    pub job: GenerationJob,
    pub audit: audit::AuditProgress,
    pub review: GenerationReview,
    pub manifest: GenerationManifest,
}
impl GenerationCommitment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.manifest.check_job(&self.job)?;
        self.audit.canonical_bytes(&self.job)?;
        if self.audit.phase != audit::AuditPhase::Complete
            || self.review.schema_version != 1
            || self.review.job_sha256 != self.job.sha256()?
            || self.review.audit_sha256
                != luma_content::sha256(&self.audit.canonical_bytes(&self.job)?)
            || self.manifest.audit_sha256 != self.review.audit_sha256
            || self.review.model_sha256 != self.manifest.model.sha256
            || self.review.model_bytes != self.manifest.model.bytes
            || self.review.read_charge > 64 * 1024 * 1024
            || self.review.write_charge > 32 * 1024 * 1024
            || self.manifest.totals
                != self.audit.totals.plus(&IngestTotals {
                    read_bytes: self.review.read_charge,
                    write_bytes: self.review.write_charge,
                    source_bytes: 0,
                    postings: 0,
                    work: self.review.work_charge,
                })?
        {
            return Err(
                "generation candidate substitutes exact completed audit/job/model/accounting"
                    .into(),
            );
        }
        self.manifest.totals.validate(&self.job.request.limits())?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("generation publication candidate exceeds bounded envelope".into());
        }
        Ok(bytes)
    }
}
pub struct PreparedGeneration {
    value: GenerationCommitment,
    release_started: Cell<bool>,
}
impl PreparedGeneration {
    pub fn commitment(&self) -> &GenerationCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: GenerationPublicationBoundary + CurrentGenerationBoundary>(
        &self,
        b: &mut B,
    ) -> Result<()> {
        b.check(Access::Inspect {
            binding: &self.value.manifest.corpus.binding,
        })?;
        b.current_generation(&self.value.manifest)?;
        if self.release_started.replace(true) {
            return Err(
                "generation reservation release already dispatched; reconcile uncertainty".into(),
            );
        }
        b.release_generation_after_selection(&self.value)?;
        b.current_generation(&self.value.manifest)
    }
}
pub fn prepare_generation<B: GenerationPublicationBoundary>(
    store: &ObjectStore,
    plan: &GenerationPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedGeneration> {
    if mutation.review_sha256 != plan.review.sha256()?
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != 0
    {
        return Err(
            "final generation mutation differs from exact reviewed complete job/model".into(),
        );
    }
    audit::Current {
        job: &plan.job,
        base: &plan.audit,
        b,
    }
    .current()?;
    b.verify_original_phase_provenance(&plan.job, &plan.audit)?;
    b.check(Access::Mutate {
        binding: &plan.job.corpus().binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: 0,
        storage_bytes: plan.review.write_charge,
    })?;
    b.reserve_generation(&plan.review)?;
    // This adapter permits only this original independently reviewed effect;
    // traversal remains bound to the actual current audit before every write.
    struct Writer<'a, B: GenerationPublicationBoundary> {
        job: &'a GenerationJob,
        audit: &'a audit::AuditProgress,
        b: &'a mut B,
    }
    impl<B: GenerationPublicationBoundary> Boundary for Writer<'_, B> {
        fn admit(
            &mut self,
            binding: &luma_content::OwnerBinding,
            budget: ResourceBudget,
        ) -> Result<()> {
            if binding != &self.job.corpus().binding {
                return Err("generation writer owner substitution".into());
            }
            audit::Current {
                job: self.job,
                base: self.audit,
                b: self.b,
            }
            .current()?;
            self.b.admit(binding, budget)?;
            audit::Current {
                job: self.job,
                base: self.audit,
                b: self.b,
            }
            .current()
        }
        fn check(&mut self, access: Access<'_>) -> Result<()> {
            audit::Current {
                job: self.job,
                base: self.audit,
                b: self.b,
            }
            .current()?;
            self.b.check(access)?;
            audit::Current {
                job: self.job,
                base: self.audit,
                b: self.b,
            }
            .current()
        }
    }
    let mut live = Writer {
        job: &plan.job,
        audit: &plan.audit,
        b,
    };
    let objects = object_count(plan.job_bytes.len())? + object_count(plan.model_bytes.len())? + 1;
    let budget = IoBudget {
        read_bytes: objects * RUN_PAGE_READ,
        write_bytes: plan.review.write_charge,
        new_files: u32::try_from(objects * 3)?,
    };
    let job_ref = store.prepare_blob(&plan.job_bytes, budget, mutation, &mut live)?;
    let model_ref = store.prepare_blob(&plan.model_bytes, budget, mutation, &mut live)?;
    let manifest = plan.manifest_data(job_ref, model_ref)?;
    let manifest_bytes = manifest.canonical_bytes()?;
    if store.prepare_page(
        &manifest_bytes,
        IoBudget {
            read_bytes: RUN_PAGE_READ,
            write_bytes: MAX_INDEX_PAGE_BYTES as u64,
            new_files: 3,
        },
        mutation,
        &mut live,
    )? != manifest.sha256()?
    {
        return Err("actual generation manifest writer changed reviewed output".into());
    }
    let value = GenerationCommitment {
        job: plan.job.clone(),
        audit: plan.audit.clone(),
        review: plan.review.clone(),
        manifest,
    };
    value.canonical_bytes()?;
    b.verify_generation_allocations(&value)?;
    audit::Current {
        job: &value.job,
        base: &value.audit,
        b,
    }
    .current()?;
    Ok(PreparedGeneration {
        value,
        release_started: Cell::new(false),
    })
}
pub fn verify_generation_data<B: GenerationPublicationBoundary>(
    store: &dyn IndexReadStore,
    value: &GenerationCommitment,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let plan = plan_generation(store, &value.job, &value.audit, b)?;
    if plan.review != value.review {
        return Err(
            "generation candidate differs from independently reconstructed full model/job/audit"
                .into(),
        );
    }
    let mut live = audit::Current {
        job: &value.job,
        base: &value.audit,
        b,
    };
    let job = store.read_blob(
        &value.manifest.job,
        IoBudget {
            read_bytes: blob_read_credit(value.manifest.job.bytes)?,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let model = store.read_blob(
        &value.manifest.model,
        IoBudget {
            read_bytes: blob_read_credit(value.manifest.model.bytes)?,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    if job != plan.job_bytes || model != plan.model_bytes {
        return Err(
            "physical generation model/job differs from exact independent reconstruction".into(),
        );
    }
    let manifest = store.read_page(
        &value.manifest.sha256()?,
        IoBudget {
            read_bytes: RUN_PAGE_READ,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    if manifest != value.manifest.canonical_bytes()? {
        return Err("physical generation manifest differs".into());
    }
    live.current()?;
    b.verify_generation_allocations(value)?;
    audit::Current {
        job: &value.job,
        base: &value.audit,
        b,
    }
    .current()
}

#[cfg(test)]
mod tests;
