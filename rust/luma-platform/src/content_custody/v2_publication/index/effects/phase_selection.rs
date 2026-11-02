//! The C-selected outcome of one prepared index window. The record is selected
//! DATA, never a writer Go, a next window grant or permission to resume.
use super::*;
use crate::content_index::MAX_COMMITMENT;
use luma_content_store::v2::BlobReference;

const SELECTION_DOMAIN: &str = "luma-c-index-phase-selection-v1";

/// One prepared Step window after its exact objects, next job and candidate
/// were written under a new original operation and its physical delta stayed
/// inside the prepared liability. Publishing this record resolves the
/// preparation: the measured inventory replaces the charge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PhaseSelection {
    schema_version: u32,
    domain: String,
    base: Base,
    preparation: RecordRef,
    next_job: BlobReference,
    candidate: BlobReference,
    extension_sha256: String,
    physical_after: PhysicalInventory,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl PhaseSelection {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn data(
        base: &Base,
        preparation: &Preparation,
        preparation_ref: &RecordRef,
        leaf: &Leaf,
        next_job: &BlobReference,
        candidate: &BlobReference,
        extension_sha256: &str,
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
            preparation: preparation_ref.clone(),
            next_job: next_job.clone(),
            candidate: candidate.clone(),
            extension_sha256: extension_sha256.into(),
            physical_after: physical_after.clone(),
            capacity,
            original: original.clone(),
        };
        value.validate_against(preparation, preparation_ref, leaf)?;
        check()?;
        Ok(value)
    }
    /// Once the window is selected its liability is actual data: nothing else
    /// is retained or requested over the measured inventory.
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
        self.candidate.validate()?;
        digest(&self.extension_sha256)?;
        self.capacity.validate_data()?;
        if self.schema_version != 1
            || self.domain != SELECTION_DOMAIN
            || self.base.index_sha256.is_none()
            || self.preparation.bytes == 0
            || self.preparation.bytes > PREPARATION_BYTES
            || self.next_job.binding != self.base.binding
            || self.candidate.binding != self.base.binding
            || self.next_job.bytes == 0
            || self.next_job.bytes > JOB_BYTES
            || self.candidate.bytes == 0
            || self.candidate.bytes > MAX_COMMITMENT as u64
            || self.capacity != Self::capacity_data(&self.base, &self.physical_after)?
        {
            return Err("index phase selection record changes exact base/job/quota DATA".into());
        }
        Ok(())
    }
    /// Binds this selection to the exact preparation it consumes and to the
    /// C-selected leaf that names that preparation.
    pub(super) fn validate_against(
        &self,
        preparation: &Preparation,
        preparation_ref: &RecordRef,
        leaf: &Leaf,
    ) -> Result<()> {
        self.validate_data()?;
        preparation.validate_data()?;
        let bytes = preparation.bytes()?;
        if preparation_ref.sha256 != hash(&bytes) || preparation_ref.bytes != bytes.len() as u64 {
            return Err("index phase selection names a different preparation record".into());
        }
        // The preparation event changed only the leaf's preparation field.
        let mut prepared_over = leaf.clone();
        let selected = prepared_over.preparation.take();
        let prepared = &preparation.base;
        self.original
            .validate(&preparation.input, &preparation.review.review_sha256)?;
        let before = &prepared.physical;
        let after = &self.physical_after;
        let liability = &preparation.liability;
        let grew = |after: u64, before: u64, limit: u64| {
            after
                .checked_sub(before)
                .map_or(false, |delta| delta <= limit)
        };
        if self.preparation != *preparation_ref
            || selected.as_ref() != Some(preparation_ref)
            || leaf.current_job.as_ref().map(|job| job.sha256.as_str())
                != Some(preparation.review.base_sha256.as_str())
            || prepared.index_sha256.as_deref() != Some(prepared_over.sha256()?.as_str())
            || self.base.index_sha256.as_deref() != Some(leaf.sha256()?.as_str())
            || self.base.binding != prepared.binding
            || self.base.owner_sha256 != prepared.owner_sha256
            || self.base.segments != prepared.segments
            || self.base.physical != *before
            || self.original.effect.operation_id.is_none()
            || self.original.effect.operation_id == preparation.original.effect.operation_id
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
                "index phase selection is not the prepared window inside its prepared liability"
                    .into(),
            );
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C phase selection exceeds fixed 64 KiB record".into());
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
    pub(super) fn preparation(&self) -> &RecordRef {
        &self.preparation
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
