//! C-owned Start reservation DATA and independent replay. The first job blob
//! is reconstructed from the selected owner and the fixed builder; no worker
//! JSON, review hash or job bytes are accepted as input.
use super::*;
use crate::content_checkpoint::custody::indexed::{
    selection_data_sha256, TransitionBase, TransitionReview,
};
use crate::content_index::state::Job;
use luma_content_store::corpus_index::BuilderIdentity;
use luma_content_store::v2::BlobObjectPlan;

const RESERVATION_DOMAIN: &str = "luma-c-index-job-reservation-v1";

/// A closed Start reservation, not a grant, writer Go or selected job. It is
/// prepared only where no index leaf is C-selected. A failed/expired attempt
/// retains this FULL liability until a distinct actual recovery transition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct JobReservation {
    schema_version: u32,
    domain: String,
    base: Base,
    input: request::Input,
    transition: TransitionReview,
    liability: policy::Liability,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl JobReservation {
    /// The exact first job and transition review from selected owner DATA.
    pub(super) fn transition_data(
        base: &Base,
        owner: &OwnerHeadV2,
        input: &request::Input,
        builder: &BuilderIdentity,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<TransitionReview> {
        check()?;
        base.validate()?;
        input.validate()?;
        if !matches!(input.operation, request::Operation::Start { .. }) {
            return Err("job reservation requires an exact Start request".into());
        }
        if base.binding != input.binding
            || base.index_sha256.is_some()
            || owner.binding != base.binding
            || owner.sha256()? != base.owner_sha256
            || owner.history.segments != base.segments
        {
            return Err(
                "index job reservation replaces current owner/input or a selected index leaf"
                    .into(),
            );
        }
        let selection = selection_data_sha256(owner, None)?;
        let next = Job::beginning_data(input, owner, builder, &selection)?;
        let core = Job::beginning_review_data(input, owner, builder, &selection)?;
        let bytes = next.canonical_bytes()?;
        let planned = BlobObjectPlan::data(&input.binding, &bytes, &mut *check)?;
        let objects = planned.write_set(&mut *check)?;
        let transition = TransitionReview::data(
            input,
            TransitionBase {
                owner,
                job: None,
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
    pub(super) fn data(
        base: &Base,
        owner: &OwnerHeadV2,
        input: &request::Input,
        builder: &BuilderIdentity,
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let transition = Self::transition_data(base, owner, input, builder, check)?;
        original.validate(input, &transition.review_sha256)?;
        let liability = policy::Policy::metadata_liability(&transition.objects)?;
        // No index leaf is selected, so no earlier preparation can be pending.
        // Existing raw allocations already count as actual data.
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
        if self.schema_version != 1
            || self.domain != RESERVATION_DOMAIN
            || !matches!(self.input.operation, request::Operation::Start { .. })
            || self.base.binding != self.input.binding
            || self.base.index_sha256.is_some()
            || self.transition.input_sha256 != self.input.sha256()?
            || self.transition.base_owner_sha256 != self.base.owner_sha256
            || self.transition.base_job_sha256.is_some()
            || self.transition.operation != self.input.mode().name()
            || self.transition.next_job.binding != self.input.binding
            || self.liability != liability
            || self.capacity != capacity
        {
            return Err(
                "index job reservation record changes exact before/review/quota DATA".into(),
            );
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C job reservation exceeds fixed 64 KiB record".into());
        }
        Ok(bytes)
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, PREPARATION_BYTES as usize)?;
        value.validate_data()?;
        Ok(value)
    }
    pub(super) fn replay_data(
        &self,
        base: &Base,
        owner: &OwnerHeadV2,
        input: &request::Input,
        builder: &BuilderIdentity,
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.validate_data()?;
        let expected = Self::data(base, owner, input, builder, original, check)?;
        if self != &expected {
            return Err(
                "independent C job reservation replay differs from exact selected owner/builder/plan"
                    .into(),
            );
        }
        check()
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
    /// The exact first job bytes, reconstructed again from the reserved owner
    /// and builder; they must plan to the reserved reference and write set.
    pub(super) fn job_bytes(
        &self,
        owner: &OwnerHeadV2,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        self.validate_data()?;
        if owner.binding != self.base.binding
            || owner.sha256()? != self.base.owner_sha256
            || owner.history.segments != self.base.segments
        {
            return Err("reserved first job is rebuilt only from its reserved owner".into());
        }
        let selection = selection_data_sha256(owner, None)?;
        let bytes = Job::beginning_data(&self.input, owner, &self.transition.builder, &selection)?
            .canonical_bytes()?;
        let planned = BlobObjectPlan::data(&self.input.binding, &bytes, &mut *check)?;
        if planned.reference() != &self.transition.next_job
            || planned.write_set(&mut *check)? != self.transition.objects
        {
            return Err("rebuilt first job differs from the reserved reference/write set".into());
        }
        check()?;
        Ok(bytes)
    }
}

const SELECTION_DOMAIN: &str = "luma-c-index-job-selection-v1";

/// The C-selected first job: the reserved blob was written once by the store
/// writer under a new original operation and its physical delta stays inside
/// the reserved liability. It is selected job DATA, never a writer Go, a
/// phase grant or permission to resume.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct JobSelection {
    schema_version: u32,
    domain: String,
    base: Base,
    reservation: RecordRef,
    job: BlobReference,
    physical_after: PhysicalInventory,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl JobSelection {
    pub(super) fn data(
        base: &Base,
        reservation: &JobReservation,
        reservation_ref: &RecordRef,
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
            job: reservation.transition.next_job.clone(),
            physical_after: physical_after.clone(),
            capacity,
            original: original.clone(),
        };
        value.validate_against(reservation, reservation_ref)?;
        check()?;
        Ok(value)
    }
    /// Once the job is selected its liability is actual data: nothing else is
    /// retained or requested over the measured inventory.
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
        self.job.validate()?;
        self.capacity.validate_data()?;
        if self.schema_version != 1
            || self.domain != SELECTION_DOMAIN
            || self.base.index_sha256.is_none()
            || self.reservation.bytes == 0
            || self.reservation.bytes > PREPARATION_BYTES
            || self.job.binding != self.base.binding
            || self.capacity != Self::capacity_data(&self.base, &self.physical_after)?
        {
            return Err("index job selection record changes exact base/job/quota DATA".into());
        }
        Ok(())
    }
    /// Binds this selection to the exact reservation it consumes.
    pub(super) fn validate_against(
        &self,
        reservation: &JobReservation,
        reservation_ref: &RecordRef,
    ) -> Result<()> {
        self.validate_data()?;
        reservation.validate_data()?;
        let bytes = reservation.bytes()?;
        if reservation_ref.sha256 != hash(&bytes) || reservation_ref.bytes != bytes.len() as u64 {
            return Err("index job selection names a different reservation record".into());
        }
        let reserved = &reservation.base;
        let leaf = Leaf {
            schema_version: 2,
            binding: reserved.binding.clone(),
            current_generation: None,
            current_job: None,
            preparation: Some(reservation_ref.clone()),
        };
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
            || self.base.binding != reserved.binding
            || self.base.owner_sha256 != reserved.owner_sha256
            || self.base.segments != reserved.segments
            || self.base.physical != *before
            || self.base.index_sha256.as_deref() != Some(leaf.sha256()?.as_str())
            || self.job != transition.next_job
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
                "index job selection is not the reserved job inside its reserved liability".into(),
            );
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C job selection exceeds fixed 64 KiB record".into());
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
    pub(super) fn job(&self) -> &BlobReference {
        &self.job
    }
    pub(super) fn physical_after(&self) -> &PhysicalInventory {
        &self.physical_after
    }
    pub(super) fn original(&self) -> &Attribution {
        &self.original
    }
}
