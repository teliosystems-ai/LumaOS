//! Exact metadata extension after real measured phase preparation. The C-owned
//! reservation is mandatory before any owner job/candidate object is written.
use super::*;
use luma_content_store::v2::{BlobObjectPlan, BlobReference, Mutation, ObjectWriteSpec};

pub(super) struct MetadataAttempt {
    started: std::cell::Cell<bool>,
    completed: std::cell::Cell<bool>,
}
impl MetadataAttempt {
    pub(super) fn new() -> Self {
        Self {
            started: std::cell::Cell::new(false),
            completed: std::cell::Cell::new(false),
        }
    }
    fn begin(&self) -> Result<()> {
        if self.started.replace(true) {
            return Err(
                "metadata preparation already attempted; retain and reconcile original C liability"
                    .into(),
            );
        }
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        if !self.started.get() || self.completed.replace(true) {
            return Err("metadata completion has no unique actual preparation".into());
        }
        Ok(())
    }
    pub(super) fn require_complete(&self) -> Result<()> {
        if !self.completed.get() {
            return Err("metadata not synchronized; no selected phase acknowledgement".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataWriteSet {
    pub schema_version: u32,
    pub input_sha256: String,
    pub base_sha256: String,
    pub review_sha256: String,
    pub native_review_sha256: String,
    pub next_job: BlobReference,
    pub candidate: BlobReference,
    pub objects: Vec<ObjectWriteSpec>,
    pub object_writes: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub new_files: u32,
}
impl MetadataWriteSet {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        for value in [
            &self.input_sha256,
            &self.base_sha256,
            &self.review_sha256,
            &self.native_review_sha256,
        ] {
            hash(value)?;
        }
        self.next_job.validate()?;
        self.candidate.validate()?;
        if self.schema_version != 1
            || self.next_job.binding != self.candidate.binding
            || self.next_job.bytes > MAX_JOB as u64
            || self.candidate.bytes > MAX_COMMITMENT as u64
            || self.objects.is_empty()
            || self.objects.len() > 256
            || self.object_writes < self.objects.len() as u32
            || self.object_writes > 256
            || self.read_bytes != u64::from(self.object_writes) * 32768
            || self.write_bytes != u64::from(self.object_writes) * 131072
            || self.new_files != self.object_writes * 3
        {
            return Err("index metadata extension exceeds closed exact shape".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for object in &self.objects {
            object.validate()?;
            if !seen.insert(&object.sha256) {
                return Err("index metadata extension repeats object".into());
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 64 * 1024 {
            return Err("index metadata extension exceeds C reservation record".into());
        }
        Ok(bytes)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}

/// Implementations must anchor the exact extension under the original current
/// C preparation/worker/lease and independently verify physical headroom.
/// Neither DATA possession nor an advisory writer lock supplies this authority.
pub(crate) trait IndexMetadataBoundary:
    NativeIndexBoundary + OwnerBoundary + AppendWriterBoundary
{
    fn reserve_index_objects(
        &mut self,
        input: &request::Input,
        base: &Job,
        owner: &OwnerHeadV2,
        review: &phase::WindowReview,
        objects: &[ObjectWriteSpec],
    ) -> Result<()>;
    fn reserve_index_metadata(
        &mut self,
        input: &request::Input,
        base: &Job,
        extension: &MetadataWriteSet,
    ) -> Result<()>;
    fn check_index_metadata(
        &mut self,
        input: &request::Input,
        base: &Job,
        extension: &MetadataWriteSet,
    ) -> Result<()>;
}

/// Real synchronized metadata DATA, not C selection or successful publication.
// Produced only for index-run, which awaits the C index publisher.
#[allow(dead_code)]
pub(crate) struct PreparedMetadata {
    pub next_job: BlobReference,
    pub candidate: BlobReference,
    pub extension_sha256: String,
}

#[allow(dead_code)]
impl ObservedPreparation<'_> {
    pub(crate) fn prepare_metadata<B: IndexMetadataBoundary>(
        &self,
        base: &Job,
        input: &request::Input,
        b: &mut B,
    ) -> Result<PreparedMetadata> {
        self.metadata.begin()?;
        self.writer.check(b)?;
        b.current_native_job(base)?;
        b.current_native_operation(input)?;
        let candidate = self.prepared.commitment();
        let next = candidate.next_data(base, input)?;
        let review_sha256 = candidate.review_sha256()?;
        self.review.validate()?;
        if review_sha256 != self.writer.review_sha256()
            || review_sha256 != self.review.core_review_sha256
            || self.review.input_sha256 != input.sha256()?
            || self.review.base_sha256 != base.sha256()?
        {
            return Err("metadata candidate changes retained original review".into());
        }
        let job_bytes = next.canonical_bytes()?;
        let candidate_bytes = candidate.canonical_bytes()?;
        let mut refresh = || {
            self.writer.check(b)?;
            b.current_native_job(base)?;
            b.current_native_operation(input)?;
            b.current_plan_review(input, &review_sha256)
        };
        let job_plan = BlobObjectPlan::data(&next.source_owner.binding, &job_bytes, &mut refresh)?;
        let candidate_plan =
            BlobObjectPlan::data(&next.source_owner.binding, &candidate_bytes, &mut refresh)?;
        let mut unique = std::collections::BTreeMap::new();
        let mut objects = Vec::new();
        for object in job_plan.objects().chain(candidate_plan.objects()) {
            refresh()?;
            if let Some(old) = unique.insert(object.sha256(), object.bytes()) {
                if old != object.bytes() {
                    return Err("metadata content-address collision changes bytes".into());
                }
            } else {
                objects.push(object.specification());
            }
        }
        let object_writes =
            u32::try_from(job_plan.objects().count() + candidate_plan.objects().count())?;
        let extension = MetadataWriteSet {
            schema_version: 1,
            input_sha256: input.sha256()?,
            base_sha256: base.sha256()?,
            review_sha256: review_sha256.clone(),
            native_review_sha256: self.review.review_sha256.clone(),
            next_job: job_plan.reference().clone(),
            candidate: candidate_plan.reference().clone(),
            objects,
            object_writes,
            read_bytes: u64::from(object_writes) * 32768,
            write_bytes: u64::from(object_writes) * 131072,
            new_files: object_writes * 3,
        };
        let extension_sha256 = extension.sha256()?;
        let maximum = &self.review.metadata_maximum;
        if extension.object_writes > maximum.object_writes
            || extension.read_bytes > maximum.read_bytes
            || extension.write_bytes > maximum.write_bytes
            || extension.new_files > maximum.new_files
        {
            return Err("exact metadata exceeds original reviewed native hold".into());
        }
        self.writer.check(b)?;
        // Actual C preregistration MUST succeed before prepare_blob can create
        // even a single private chunk or derived index object.
        b.reserve_index_metadata(input, base, &extension)?;
        let mutation = Mutation {
            review_sha256,
            decision: luma_content_store::DecisionKind::Published,
            source_bytes: job_bytes.len() as u64 + candidate_bytes.len() as u64,
        };
        let prepare = |bytes: &[u8],
                       plan: &BlobObjectPlan<'_>,
                       b: &mut B|
         -> Result<BlobReference> {
            let count = plan.objects().count() as u64;
            let budget = IoBudget {
                read_bytes: count
                    .checked_mul(32 * 1024)
                    .ok_or("metadata read reserve overflow")?
                    .max(1),
                write_bytes: count
                    .checked_mul(128 * 1024)
                    .ok_or("metadata write reserve overflow")?,
                new_files: u32::try_from(
                    count
                        .checked_mul(3)
                        .ok_or("metadata inode reserve overflow")?,
                )?,
            };
            let actual = self.writer.prepare_blob(bytes, budget, &mutation, b, |b| {
                b.current_native_operation(input)?;
                b.current_native_job(base)?;
                b.current_plan_review(input, &extension.review_sha256)?;
                b.check_index_metadata(input, base, &extension)
            })?;
            if actual != *plan.reference() {
                return Err("actual metadata encoder differs from exact preregistered plan".into());
            }
            Ok(actual)
        };
        let next_job = prepare(&job_bytes, &job_plan, b)?;
        let candidate = prepare(&candidate_bytes, &candidate_plan, b)?;
        b.check_index_metadata(input, base, &extension)?;
        self.writer.check(b)?;
        self.metadata.complete()?;
        Ok(PreparedMetadata {
            next_job,
            candidate,
            extension_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn extension() -> MetadataWriteSet {
        let binding = OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 1,
        };
        let bytes = b"bounded canonical metadata";
        let plan = BlobObjectPlan::data(&binding, bytes, || Ok(())).unwrap();
        let object_writes = u32::try_from(plan.objects().count() * 2).unwrap();
        MetadataWriteSet {
            schema_version: 1,
            input_sha256: "c".repeat(64),
            base_sha256: "d".repeat(64),
            review_sha256: "e".repeat(64),
            native_review_sha256: "f".repeat(64),
            next_job: plan.reference().clone(),
            candidate: plan.reference().clone(),
            objects: plan.write_set(|| Ok(())).unwrap(),
            object_writes,
            read_bytes: u64::from(object_writes) * 32768,
            write_bytes: u64::from(object_writes) * 131072,
            new_files: object_writes * 3,
        }
    }
    #[test]
    fn exact_metadata_inventory_is_closed_bounded_owner_bound_data() {
        let value = extension();
        assert!(value.canonical_bytes().unwrap().len() < 64 * 1024);
        let mut changed = value.clone();
        changed.candidate.binding.owner_generation += 1;
        assert!(changed.canonical_bytes().is_err());
        changed = value.clone();
        changed.objects.push(changed.objects[0].clone());
        assert!(changed.canonical_bytes().is_err());
        changed = value.clone();
        changed.objects[0].bytes = 16385;
        assert!(changed.canonical_bytes().is_err());
        changed = value.clone();
        changed.objects.clear();
        assert!(changed.canonical_bytes().is_err());
        changed = value.clone();
        changed.next_job.bytes = MAX_JOB as u64 + 1;
        assert!(changed.canonical_bytes().is_err());
        let mut changed = value;
        changed.schema_version = 2;
        assert!(changed.canonical_bytes().is_err());
    }
    #[test]
    fn metadata_extension_digest_binds_original_input_base_review_and_inventory() {
        let value = extension();
        let expected = value.sha256().unwrap();
        let mut changed = value.clone();
        changed.input_sha256 = "f".repeat(64);
        assert_ne!(changed.sha256().unwrap(), expected);
        changed = value.clone();
        changed.base_sha256 = "f".repeat(64);
        assert_ne!(changed.sha256().unwrap(), expected);
        changed = value.clone();
        changed.review_sha256 = "f".repeat(64);
        assert_ne!(changed.sha256().unwrap(), expected);
        changed = value;
        changed.objects[0].bytes -= 1;
        assert_ne!(changed.sha256().unwrap(), expected);
    }
    #[test]
    fn original_metadata_attempt_is_one_shot_and_acknowledgement_requires_real_completion() {
        let attempt = MetadataAttempt::new();
        assert!(attempt.require_complete().is_err());
        assert!(attempt.complete().is_err());
        attempt.begin().unwrap();
        assert!(attempt.require_complete().is_err());
        assert!(attempt.begin().is_err());
        attempt.complete().unwrap();
        attempt.require_complete().unwrap();
        assert!(attempt.begin().is_err());
        assert!(attempt.complete().is_err());
        let failed = MetadataAttempt::new();
        failed.begin().unwrap();
        assert!(failed.begin().is_err());
        assert!(failed.require_complete().is_err());
    }
    #[test]
    fn metadata_cost_preserves_ordered_reuse_work_and_cannot_reset_original_hold() {
        let value = extension();
        assert!(value.object_writes as usize > value.objects.len());
        for field in 0..4 {
            let mut changed = value.clone();
            match field {
                0 => changed.object_writes -= 1,
                1 => changed.read_bytes -= 1,
                2 => changed.write_bytes -= 1,
                _ => changed.new_files -= 1,
            }
            assert!(changed.canonical_bytes().is_err());
        }
        let mut changed = value;
        changed.object_writes = 257;
        changed.read_bytes = 257 * 32768;
        changed.write_bytes = 257 * 131072;
        changed.new_files = 257 * 3;
        assert!(changed.canonical_bytes().is_err());
    }
}
