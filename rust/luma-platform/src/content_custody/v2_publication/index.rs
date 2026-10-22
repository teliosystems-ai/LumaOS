//! The exact current C index projection. All returned values describe selected
//! DATA; no serialized leaf, job, preparation or hash authorizes publication.
use super::*;
use luma_content_store::v2::{BlobReference, PhysicalInventory};
#[cfg(test)]
#[path = "index/effects.rs"]
pub(in crate::content_checkpoint::custody::v2_publication) mod effects;

const LEAF_BYTES: usize = 8192;
const JOB_BYTES: u64 = 1024 * 1024;
const GENERATION_BYTES: u64 = 16 * 1024;
const PREPARATION_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct Leaf {
    pub(in crate::content_checkpoint::custody) schema_version: u32,
    pub(in crate::content_checkpoint::custody) binding: OwnerBinding,
    pub(in crate::content_checkpoint::custody) current_generation: Option<BlobReference>,
    pub(in crate::content_checkpoint::custody) current_job: Option<BlobReference>,
    pub(super) preparation: Option<RecordRef>,
}
impl Leaf {
    pub(in crate::content_checkpoint::custody) fn has_preparation(&self) -> bool {
        self.preparation.is_some()
    }
    fn validate(&self, binding: &OwnerBinding) -> Result<()> {
        self.binding.validate()?;
        binding.validate()?;
        if self.schema_version != 2 || &self.binding != binding {
            return Err("selected C index leaf replaces its owner generation/schema".into());
        }
        for (reference, limit) in [
            (&self.current_generation, GENERATION_BYTES),
            (&self.current_job, JOB_BYTES),
        ] {
            if let Some(reference) = reference {
                reference.validate()?;
                if &reference.binding != binding || reference.bytes == 0 || reference.bytes > limit
                {
                    return Err(
                        "selected C index reference changes owner or its closed record bound"
                            .into(),
                    );
                }
            }
        }
        if let Some(reference) = &self.preparation {
            reference.validate()?;
            if reference.bytes > PREPARATION_BYTES {
                return Err(
                    "C index staging reservation exceeds its closed independent record bound"
                        .into(),
                );
            }
        }
        if serde_json::to_vec(self)?.len() > LEAF_BYTES {
            return Err("selected C index leaf exceeds its immutable record bound".into());
        }
        Ok(())
    }
    fn parse(bytes: &[u8], binding: &OwnerBinding) -> Result<Self> {
        let value: Self = canonical(bytes, LEAF_BYTES)?;
        value.validate(binding)?;
        Ok(value)
    }
    pub(in crate::content_checkpoint::custody) fn sha256(&self) -> Result<String> {
        self.validate(&self.binding)?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
}

// The C map stores one bounded indirect reference, not three duplicated blob
// descriptors or a worker's asserted current selection. The leaf record is in
// the independent C namespace and is fully rehashed on every read.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema_version: u32,
    binding: OwnerBinding,
    record: RecordRef,
}
impl Reference {
    fn parse(bytes: &[u8], binding: &OwnerBinding) -> Result<Self> {
        let value: Self = canonical(bytes, map::MAX_VALUE_BYTES)?;
        value.binding.validate()?;
        value.record.validate()?;
        if value.schema_version != 2
            || &value.binding != binding
            || value.record.bytes > LEAF_BYTES as u64
        {
            return Err("C index map reference changes owner generation/schema/leaf bound".into());
        }
        Ok(value)
    }
}

/// Constructed only by actual current C selection below. It has no decoder,
/// authority conversion, write method or cached original-operation guard.
pub(in crate::content_checkpoint::custody) struct Selection {
    pub(in crate::content_checkpoint::custody) owner: OwnerHeadV2,
    pub(in crate::content_checkpoint::custody) physical: PhysicalInventory,
    pub(in crate::content_checkpoint::custody) leaf: Option<Leaf>,
    pub(in crate::content_checkpoint::custody) descriptor_sha256: String,
}

impl<A: Checkpoint> PagedStore<A> {
    pub(in crate::content_checkpoint::custody) fn selected_index(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Selection> {
        self.live(check)?;
        self.descriptor.phase.require_ready()?;
        let selected_before = self.selected.clone();
        let (owner, physical) = match self.selected_owner(binding, check)? {
            SelectedOwner::Paged { head, physical } => (head, physical),
            SelectedOwner::Legacy { .. } => {
                return Err("corpus indexing requires a genuinely C-selected paged owner".into())
            }
        };
        let root = self.descriptor.roots.index_generations.clone();
        if root.kind != map::Kind::IndexGenerations || root.binding != self.descriptor.binding {
            return Err("index selection substitutes a different C map/custody".into());
        }
        let leaf = self
            .value(&root, owner_key(binding)?.as_bytes(), check)?
            .map(|bytes| -> Result<Leaf> {
                let reference = Reference::parse(&bytes, binding)?;
                let bytes = self.pages.read_record(&reference.record.sha256, check)?;
                if bytes.len() as u64 != reference.record.bytes {
                    return Err("C index leaf record differs from its full selected length".into());
                }
                Leaf::parse(&bytes, binding)
            })
            .transpose()?;
        self.live(check)?;
        if self.selected != selected_before {
            return Err("C selection changed during index projection".into());
        }
        match self.selected_owner(binding, check)? {
            SelectedOwner::Paged {
                head: again,
                physical: measured,
            } if again == owner && measured == physical => (),
            _ => {
                return Err(
                    "current owner/physical selection changed during index projection".into(),
                )
            }
        }
        self.live(check)?;
        Ok(Selection {
            owner,
            physical,
            leaf,
            descriptor_sha256: self.selected.descriptor_sha256.clone(),
        })
    }
}

#[cfg(test)]
#[path = "index/tests.rs"]
mod tests;
