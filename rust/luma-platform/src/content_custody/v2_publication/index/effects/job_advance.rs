//! C-owned records of one metadata-only phase advance. The next job is
//! reconstructed from the selected job and the current fixed builder; no
//! worker JSON, review hash or job bytes are accepted as input. An advance
//! writes one job blob and no window objects, so it has its own reservation
//! and selection in place of a phase preparation.
use super::*;
use crate::content_checkpoint::custody::indexed::{
    selection_data_sha256, TransitionBase, TransitionReview,
};
use crate::content_index::state::Job;
use luma_content_store::corpus_index::BuilderIdentity;
use luma_content_store::v2::BlobObjectPlan;

const RESERVATION_DOMAIN: &str = "luma-c-index-job-advance-v1";
const SELECTION_DOMAIN: &str = "luma-c-index-advance-selection-v1";

/// A closed Advance reservation, not a grant, writer Go or selected job. It is
/// prepared only over a C-selected job with no unresolved preparation. A
/// failed/expired attempt retains this FULL liability until a distinct actual
/// recovery transition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct JobAdvance {
    schema_version: u32,
    domain: String,
    base: Base,
    input: request::Input,
    transition: TransitionReview,
    liability: policy::Liability,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl JobAdvance {
    /// The exact next job and transition review from the selected leaf, owner
    /// and job. The caller's job binds to the leaf by its full hash.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn transition_data(
        base: &Base,
        leaf: &Leaf,
        owner: &OwnerHeadV2,
        job: &Job,
        input: &request::Input,
        builder: &BuilderIdentity,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<TransitionReview> {
        check()?;
        base.validate()?;
        input.validate()?;
        if !matches!(input.operation, request::Operation::Advance { .. }) {
            return Err("job advance requires an exact Advance request".into());
        }
        if base.binding != input.binding
            || base.index_sha256.as_deref() != Some(leaf.sha256()?.as_str())
            || leaf.has_preparation()
            || owner.binding != base.binding
            || owner.sha256()? != base.owner_sha256
            || owner.history.segments != base.segments
        {
            return Err(
                "index job advance replaces current owner/input or an unresolved leaf".into(),
            );
        }
        let selected = leaf
            .current_job
            .as_ref()
            .ok_or("index job advance has no selected current job")?;
        if selected.sha256 != job.sha256()?
            || job.source_owner.roots.corpus != owner.roots.corpus
            || job.builder != *builder
        {
            return Err(
                "index job advance is not over the exact C-selected lineage/builder".into(),
            );
        }
        let selection = selection_data_sha256(owner, Some(leaf))?;
        let next = job.advance_data(input)?;
        let core = job.advance_review_data(input)?;
        let bytes = next.canonical_bytes()?;
        let planned = BlobObjectPlan::data(&input.binding, &bytes, &mut *check)?;
        let objects = planned.write_set(&mut *check)?;
        let transition = TransitionReview::data(
            input,
            TransitionBase {
                owner,
                job: Some(job),
                selection_sha256: &selection,
                builder,
            },
            core,
            planned.reference().clone(),
            objects,
        )?;
        check()?;
        Ok(transition)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn data(
        base: &Base,
        leaf: &Leaf,
        owner: &OwnerHeadV2,
        job: &Job,
        input: &request::Input,
        builder: &BuilderIdentity,
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let transition = Self::transition_data(base, leaf, owner, job, input, builder, check)?;
        original.validate(input, &transition.review_sha256)?;
        let liability = policy::Policy::metadata_liability(&transition.objects)?;
        // The leaf has no preparation, so nothing else is charged. Existing
        // raw allocations already count as actual data.
        let capacity = policy::Policy::compiled().admit_data(
            &base.physical,
            base.segments,
            [],
            &liability,
            check,
        )?;
        let value = Self {
            schema_version: 1,
            domain: RESERVATION_DOMAIN.into(),
            base: base.clone(),
            input: input.clone(),
            transition,
            liability,
            capacity,
            original: original.clone(),
        };
        value.validate_data()?;
        check()?;
        Ok(value)
    }
    fn validate_data(&self) -> Result<()> {
        self.base.validate()?;
        self.input.validate()?;
        self.transition.validate()?;
        self.original
            .validate(&self.input, &self.transition.review_sha256)?;
        self.capacity.validate_data()?;
        // The compiled metadata arithmetic over the exact write set, never a
        // caller's sum, is the full liability of this reservation.
        let liability = policy::Policy::metadata_liability(&self.transition.objects)?;
        let capacity = policy::Policy::compiled().admit_data(
            &self.base.physical,
            self.base.segments,
            [],
            &liability,
            &mut || Ok(()),
        )?;
        let request::Operation::Advance {
            expected_job_sha256,
            ..
        } = &self.input.operation
        else {
            return Err("index job advance record is not an exact Advance request".into());
        };
        if self.schema_version != 1
            || self.domain != RESERVATION_DOMAIN
            || self.base.binding != self.input.binding
            || self.base.index_sha256.is_none()
            || self.transition.input_sha256 != self.input.sha256()?
            || self.transition.base_owner_sha256 != self.base.owner_sha256
            || self.transition.base_job_sha256.as_ref() != Some(expected_job_sha256)
            || self.transition.operation != self.input.mode().name()
            || self.transition.next_job.binding != self.input.binding
            || self.liability != liability
            || self.capacity != capacity
        {
            return Err("index job advance record changes exact before/review/quota DATA".into());
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C job advance exceeds fixed 64 KiB record".into());
        }
        Ok(bytes)
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, PREPARATION_BYTES as usize)?;
        value.validate_data()?;
        Ok(value)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn replay_data(
        &self,
        base: &Base,
        leaf: &Leaf,
        owner: &OwnerHeadV2,
        job: &Job,
        input: &request::Input,
        builder: &BuilderIdentity,
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.validate_data()?;
        let expected = Self::data(base, leaf, owner, job, input, builder, original, check)?;
        if self != &expected {
            return Err(
                "independent C job advance replay differs from exact selected job/builder/plan"
                    .into(),
            );
        }
        check()
    }
    /// What cold replay can prove without a store: this record is closed over
    /// the selected owner and leaf. Its builder is its own retained DATA, which
    /// proves exact closure, never that it is the current image.
    pub(super) fn replay_shape(&self, base: &Base, leaf: &Leaf, owner: &OwnerHeadV2) -> Result<()> {
        self.validate_data()?;
        let job = leaf
            .current_job
            .as_ref()
            .ok_or("index job advance replay has no selected current job")?;
        if self.base != *base
            || leaf.has_preparation()
            || self.transition.base_job_sha256.as_deref() != Some(job.sha256.as_str())
            || self.transition.selection_sha256 != selection_data_sha256(owner, Some(leaf))?
        {
            return Err(
                "cold C job advance replay differs from the exact selected owner/leaf".into(),
            );
        }
        Ok(())
    }
    pub(super) fn base(&self) -> &Base {
        &self.base
    }
    pub(super) fn input(&self) -> &request::Input {
        &self.input
    }
    pub(super) fn builder(&self) -> &BuilderIdentity {
        &self.transition.builder
    }
    pub(super) fn original(&self) -> &Attribution {
        &self.original
    }
    pub(super) fn transition(&self) -> &TransitionReview {
        &self.transition
    }
    pub(super) fn liability(&self) -> &policy::Liability {
        &self.liability
    }
    /// The exact next job bytes, reconstructed again from the selected job;
    /// they must plan to the reserved reference and write set.
    pub(super) fn job_bytes(
        &self,
        job: &Job,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        self.validate_data()?;
        if self.transition.base_job_sha256.as_deref() != Some(job.sha256()?.as_str()) {
            return Err("reserved next job is rebuilt only from its reserved job".into());
        }
        let bytes = job.advance_data(&self.input)?.canonical_bytes()?;
        let planned = BlobObjectPlan::data(&self.input.binding, &bytes, &mut *check)?;
        if planned.reference() != &self.transition.next_job
            || planned.write_set(&mut *check)? != self.transition.objects
        {
            return Err("rebuilt next job differs from the reserved reference/write set".into());
        }
        check()?;
        Ok(bytes)
    }
}

/// The C-selected next job: the reserved blob was written once by the store
/// writer under a new original operation and its physical delta stays inside
/// the reserved liability. It is selected job DATA, never a writer Go, a
/// window grant or permission to resume.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct AdvanceSelection {
    schema_version: u32,
    domain: String,
    base: Base,
    reservation: RecordRef,
    next_job: BlobReference,
    physical_after: PhysicalInventory,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl AdvanceSelection {
    pub(super) fn data(
        base: &Base,
        reservation: &JobAdvance,
        reservation_ref: &RecordRef,
        leaf: &Leaf,
        physical_after: &PhysicalInventory,
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        let capacity = Self::capacity_data(base, physical_after)?;
        let value = Self {
            schema_version: 1,
            domain: SELECTION_DOMAIN.into(),
            base: base.clone(),
            reservation: reservation_ref.clone(),
            next_job: reservation.transition.next_job.clone(),
            physical_after: physical_after.clone(),
            capacity,
            original: original.clone(),
        };
        value.validate_against(reservation, reservation_ref, leaf)?;
        check()?;
        Ok(value)
    }
    /// Once the next job is selected its liability is actual data: nothing
    /// else is retained or requested over the measured inventory.
    fn capacity_data(
        base: &Base,
        physical_after: &PhysicalInventory,
    ) -> Result<policy::CapacitySummary> {
        policy::Policy::compiled().admit_data(
            physical_after,
            base.segments,
            [],
            &policy::Liability::default(),
            &mut || Ok(()),
        )
    }
    fn validate_data(&self) -> Result<()> {
        self.base.validate()?;
        self.next_job.validate()?;
        self.capacity.validate_data()?;
        if self.schema_version != 1
            || self.domain != SELECTION_DOMAIN
            || self.base.index_sha256.is_none()
            || self.reservation.bytes == 0
            || self.reservation.bytes > PREPARATION_BYTES
            || self.next_job.binding != self.base.binding
            || self.next_job.bytes == 0
            || self.next_job.bytes > JOB_BYTES
            || self.capacity != Self::capacity_data(&self.base, &self.physical_after)?
        {
            return Err("index advance selection record changes exact base/job/quota DATA".into());
        }
        Ok(())
    }
    /// Binds this selection to the exact reservation it consumes and to the
    /// C-selected leaf that names that reservation.
    pub(super) fn validate_against(
        &self,
        reservation: &JobAdvance,
        reservation_ref: &RecordRef,
        leaf: &Leaf,
    ) -> Result<()> {
        self.validate_data()?;
        reservation.validate_data()?;
        let bytes = reservation.bytes()?;
        if reservation_ref.sha256 != hash(&bytes) || reservation_ref.bytes != bytes.len() as u64 {
            return Err("index advance selection names a different reservation record".into());
        }
        // The reservation event changed only the leaf's preparation field.
        let mut prepared_over = leaf.clone();
        let selected = prepared_over.preparation.take();
        let reserved = &reservation.base;
        let transition = &reservation.transition;
        self.original
            .validate(&reservation.input, &transition.review_sha256)?;
        let before = &reserved.physical;
        let after = &self.physical_after;
        let liability = &reservation.liability;
        let grew = |after: u64, before: u64, limit: u64| {
            after
                .checked_sub(before)
                .map_or(false, |delta| delta <= limit)
        };
        if self.reservation != *reservation_ref
            || selected.as_ref() != Some(reservation_ref)
            || leaf.current_job.as_ref().map(|job| job.sha256.as_str())
                != transition.base_job_sha256.as_deref()
            || reserved.index_sha256.as_deref() != Some(prepared_over.sha256()?.as_str())
            || self.base.index_sha256.as_deref() != Some(leaf.sha256()?.as_str())
            || self.base.binding != reserved.binding
            || self.base.owner_sha256 != reserved.owner_sha256
            || self.base.segments != reserved.segments
            || self.base.physical != *before
            || self.next_job != transition.next_job
            || self.original.effect.operation_id.is_none()
            || self.original.effect.operation_id == reservation.original.effect.operation_id
            || !grew(
                after.allocated_bytes,
                before.allocated_bytes,
                liability.allocated_bytes,
            )
            || !grew(
                after.regular_files,
                before.regular_files,
                liability.regular_files,
            )
            || !grew(after.directories, before.directories, liability.directories)
            || after.logical_bytes < before.logical_bytes
            || after.incomplete_objects != before.incomplete_objects
        {
            return Err(
                "index advance selection is not the reserved job inside its reserved liability"
                    .into(),
            );
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C advance selection exceeds fixed 64 KiB record".into());
        }
        Ok(bytes)
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, PREPARATION_BYTES as usize)?;
        value.validate_data()?;
        Ok(value)
    }
    pub(super) fn base(&self) -> &Base {
        &self.base
    }
    pub(super) fn reservation(&self) -> &RecordRef {
        &self.reservation
    }
    pub(super) fn next_job(&self) -> &BlobReference {
        &self.next_job
    }
    pub(super) fn physical_after(&self) -> &PhysicalInventory {
        &self.physical_after
    }
    pub(super) fn original(&self) -> &Attribution {
        &self.original
    }
}
