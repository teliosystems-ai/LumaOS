//! C-owned Index preparation DATA and independent replay. No value returned
//! by this module is writer Go, an original-operation context or a selected
//! checkpoint. The direct worker publisher must persist/read back every part
//! and anchor the typed event before owner writes are permitted.
use super::*;
use crate::content_index::{phase, policy, request};
use luma_content_store::v2::{ObjectWriteSpec, PhysicalInventory};

#[path = "effects/inventory.rs"]
mod inventory;
use inventory::{InventoryPlan, InventoryRoot};

// The semantic proof awaits its only consumer, the direct C index publisher;
// it is neither dispatched nor yet exercised by the publisher's tests.
#[allow(dead_code)]
#[path = "effects/verification.rs"]
mod verification;
#[allow(unused_imports)]
pub(in crate::content_checkpoint::custody::v2_publication) use verification::{
    verify_index_preparation, PreparationView, VerifiedIndexPreparation,
};

const PREPARATION_DOMAIN: &str = "luma-c-index-preparation-v1";

/// Exact selected before-DATA. In particular, reservations are NOT allocated
/// files and may not be added to these actual physical counters.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Base {
    binding: OwnerBinding,
    descriptor_sha256: String,
    nv_head: String,
    owner_sha256: String,
    physical: PhysicalInventory,
    segments: u64,
    index_sha256: Option<String>,
}
impl Base {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        for value in [&self.descriptor_sha256, &self.nv_head, &self.owner_sha256] {
            digest(value)?;
        }
        if let Some(value) = &self.index_sha256 {
            digest(value)?;
        }
        policy::Policy::compiled().admit_data(
            &self.physical,
            self.segments,
            [],
            &policy::Liability::default(),
            &mut || Ok(()),
        )?;
        Ok(())
    }
}

/// Historical attribution ONLY. The original ephemeral context, not these
/// serialized fields, proves the independently held current Read/Write pair.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attribution {
    rpc_sha256: String,
    profile: String,
    storage_device: String,
    worker_pid: u32,
    worker_start: u64,
    worker_label: String,
    lease: crate::resources::Token,
    paired_read: crate::finite_grants::Use,
    effect: Audit,
}
impl Attribution {
    fn validate(&self, input: &request::Input, review_sha256: &str) -> Result<()> {
        digest(&self.rpc_sha256)?;
        let expected = input.effect_profile(review_sha256)?;
        self.effect.validate()?;
        let source = input.sha256()?;
        if self.profile != expected
            || self.worker_pid == 0
            || self.worker_start == 0
            || self.worker_label != "luma-acquisition (enforce)"
            || self.lease.generation == 0
            || self.lease.lease_id.len() != 32
            || tpm::decode::<16>(&self.lease.lease_id).is_err()
            || self.lease.manager_epoch.len() != 32
            || tpm::decode::<16>(&self.lease.manager_epoch).is_err()
            || self.effect.operation_id.is_none()
            || self.effect.subject != input.binding.owner
            || self.effect.subject_generation != input.binding.owner_generation
            || self.paired_read
                != crate::content_index::scope::original_usage(
                    &self.profile,
                    &self.storage_device,
                    &input.binding,
                    &source,
                    true,
                )?
            || self.effect.usage
                != crate::content_index::scope::original_usage(
                    &self.profile,
                    &self.storage_device,
                    &input.binding,
                    &source,
                    false,
                )?
        {
            return Err(
                "index preparation historical tuple changes original source/pair/worker/lease"
                    .into(),
            );
        }
        Ok(())
    }
}

/// A closed reservation record, not a grant, writer Go or selected event. A
/// failed/expired attempt retains this FULL liability until a distinct actual
/// RecoverResource transition independently reconciles all observed effects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema_version: u32,
    domain: String,
    base: Base,
    input: request::Input,
    review: phase::WindowReview,
    inventory: InventoryRoot,
    liability: policy::Liability,
    capacity: policy::CapacitySummary,
    original: Attribution,
}
impl Preparation {
    fn data(
        base: &Base,
        input: &request::Input,
        review: &phase::WindowReview,
        objects: &[ObjectWriteSpec],
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<(Self, InventoryPlan)> {
        check()?;
        base.validate()?;
        input.validate()?;
        review.validate()?;
        original.validate(input, &review.review_sha256)?;
        let job = match &input.operation {
            request::Operation::Step {
                expected_job_sha256,
                ..
            }
            | request::Operation::Publish {
                expected_job_sha256,
                ..
            } => expected_job_sha256,
            _ => return Err("phase preparation requires an exact Step or Publish plan".into()),
        };
        if base.binding != input.binding
            || review.input_sha256 != input.sha256()?
            || review.base_sha256 != *job
            || (review.phase == "publish")
                != matches!(input.operation, request::Operation::Publish { .. })
        {
            return Err("index preparation replaces current owner/input/job/phase".into());
        }
        let inventory = InventoryPlan::data(&input.binding, objects, check)?;
        if inventory.root().inventory_sha256() != review.planned_objects_sha256 {
            return Err(
                "index preparation changes independently reconstructed ordered write inventory"
                    .into(),
            );
        }
        let liability = policy::Policy::preview_liability(review, objects)?;
        // A previous preparation is fenced by the selected leaf BEFORE this
        // constructor. Existing raw allocations already count as actual data.
        let capacity = policy::Policy::compiled().admit_data(
            &base.physical,
            base.segments,
            [],
            &liability,
            check,
        )?;
        let value = Self {
            schema_version: 1,
            domain: PREPARATION_DOMAIN.into(),
            base: base.clone(),
            input: input.clone(),
            review: review.clone(),
            inventory: inventory.root().clone(),
            liability,
            capacity,
            original: original.clone(),
        };
        value.validate_data()?;
        check()?;
        Ok((value, inventory))
    }
    fn validate_data(&self) -> Result<()> {
        self.base.validate()?;
        self.input.validate()?;
        self.review.validate()?;
        self.inventory.validate(&self.input.binding)?;
        self.original
            .validate(&self.input, &self.review.review_sha256)?;
        self.capacity.validate_data()?;
        // Check the record's closed accounting shape even before the actual
        // independently reopened ordered inventory is available to replay.
        // This must match the compiled preview arithmetic, never caller sums.
        let count = u64::from(self.inventory.object_count());
        let metadata = &self.review.metadata_maximum;
        let expected_liability = policy::Liability {
            allocated_bytes: count
                .checked_mul(131072)
                .ok_or("preparation object hold overflow")?
                .max(self.review.maximum_write_bytes)
                .checked_add(metadata.write_bytes)
                .filter(|n| *n <= 128 * 1024 * 1024)
                .ok_or("preparation derivative and metadata exceed unchanged Write ceiling")?,
            regular_files: count + u64::from(metadata.object_writes),
            directories: (count + u64::from(metadata.object_writes)) * 2,
            segments: 0,
        };
        if self.liability != expected_liability {
            return Err(
                "preparation record understates its exact derivative/metadata liability".into(),
            );
        }
        let job = match &self.input.operation {
            request::Operation::Step {
                expected_job_sha256,
                ..
            }
            | request::Operation::Publish {
                expected_job_sha256,
                ..
            } => expected_job_sha256,
            _ => return Err("reservation contains an unsupported phase operation".into()),
        };
        let capacity = policy::Policy::compiled().admit_data(
            &self.base.physical,
            self.base.segments,
            [],
            &self.liability,
            &mut || Ok(()),
        )?;
        if self.schema_version != 1
            || self.domain != PREPARATION_DOMAIN
            || self.base.binding != self.input.binding
            || self.review.input_sha256 != self.input.sha256()?
            || self.review.base_sha256 != *job
            || self.review.planned_objects_sha256 != self.inventory.inventory_sha256()
            || (self.review.phase == "publish")
                != matches!(self.input.operation, request::Operation::Publish { .. })
            || self.capacity != capacity
        {
            return Err(
                "index preparation record changes exact before/review/closure/quota DATA".into(),
            );
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PREPARATION_BYTES {
            return Err("C preparation exceeds fixed 64 KiB record".into());
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, PREPARATION_BYTES as usize)?;
        value.validate_data()?;
        Ok(value)
    }
    fn replay_data(
        &self,
        base: &Base,
        input: &request::Input,
        review: &phase::WindowReview,
        objects: &[ObjectWriteSpec],
        original: &Attribution,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.validate_data()?;
        let (expected, _) = Self::data(base, input, review, objects, original, check)?;
        if self != &expected {
            return Err("independent C preparation replay differs from exact selected source/plan/reservation".into());
        }
        check()
    }
}

/// Retention preserves the complete reservation. This closed DATA transition
/// cannot release resources, certify a caller's inventory or authorize cleanup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RetainedPreparation {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    preparation: RecordRef,
    input: request::Input,
    liability: policy::Liability,
    original: Attribution,
}
impl RetainedPreparation {
    fn data(
        preparation: &Preparation,
        input: &request::Input,
        original: &Attribution,
    ) -> Result<Self> {
        preparation.validate_data()?;
        input.validate()?;
        let bytes = preparation.bytes()?;
        let reference = RecordRef {
            sha256: hash(&bytes),
            bytes: bytes.len() as u64,
        };
        let (job, base, expected, review) = match &input.operation {
            request::Operation::Retain {
                job_id,
                expected_job_sha256,
                preparation_sha256,
                review_sha256,
                ..
            } => (
                job_id,
                expected_job_sha256,
                preparation_sha256,
                review_sha256,
            ),
            _ => return Err("retention requires a distinct explicit finite Retain request".into()),
        };
        let old_job = match &preparation.input.operation {
            request::Operation::Step { job_id, .. }
            | request::Operation::Publish { job_id, .. } => job_id,
            _ => return Err("retention source is not a phase preparation".into()),
        };
        original.validate(input, review)?;
        if input.binding != preparation.base.binding
            || job != old_job
            || *base != preparation.review.base_sha256
            || *expected != reference.sha256
        {
            return Err(
                "Retain changes exact owner/job/preparation; no resource liability may be released"
                    .into(),
            );
        }
        let value = Self {
            schema_version: 1,
            domain: "luma-c-index-retained-preparation-v1".into(),
            binding: input.binding.clone(),
            preparation: reference,
            input: input.clone(),
            liability: preparation.liability.clone(),
            original: original.clone(),
        };
        value.validate_against(preparation)?;
        Ok(value)
    }
    fn validate_against(&self, preparation: &Preparation) -> Result<()> {
        preparation.validate_data()?;
        self.input.validate()?;
        self.binding.validate()?;
        let bytes = preparation.bytes()?;
        let review = match &self.input.operation {
            request::Operation::Retain {
                preparation_sha256,
                expected_job_sha256,
                job_id,
                review_sha256,
                ..
            } if *preparation_sha256 == hash(&bytes)
                && *expected_job_sha256 == preparation.review.base_sha256 =>
            {
                let old = match &preparation.input.operation {
                    request::Operation::Step { job_id, .. }
                    | request::Operation::Publish { job_id, .. } => job_id,
                    _ => return Err("invalid retained source phase".into()),
                };
                if job_id != old {
                    return Err("Retain substitutes the prepared job".into());
                }
                review_sha256
            }
            _ => return Err("Retain substitutes exact prepared current job/record".into()),
        };
        self.original.validate(&self.input, review)?;
        if self.schema_version != 1
            || self.domain != "luma-c-index-retained-preparation-v1"
            || self.binding != preparation.base.binding
            || self.input.binding != self.binding
            || self.preparation.sha256 != hash(&bytes)
            || self.preparation.bytes != bytes.len() as u64
            || self.liability != preparation.liability
        {
            return Err("retention cannot discard or reduce the full prepared liability".into());
        }
        Ok(())
    }
    fn bytes(&self, preparation: &Preparation) -> Result<Vec<u8>> {
        self.validate_against(preparation)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > PREPARATION_BYTES {
            return Err("retention exceeds fixed C record bound".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "effects/tests.rs"]
mod tests;
