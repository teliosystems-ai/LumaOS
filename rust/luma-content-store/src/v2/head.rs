//! Exact owner state DATA. Only an independently selected current C cut can
//! make this descriptor usable; neither a hash nor an absent file does so.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerRoots {
    pub artifacts: MapRoot,
    pub history: MapRoot,
    pub requests: MapRoot,
    pub collections: MapRoot,
    pub lifecycle: MapRoot,
    pub segments: MapRoot,
    pub pending: MapRoot,
    pub retained: MapRoot,
    pub corpus: MapRoot,
}
impl OwnerRoots {
    pub fn empty(binding: &OwnerBinding) -> Result<Self> {
        Ok(Self {
            artifacts: MapRoot::empty(binding, MapKind::Artifacts)?,
            history: MapRoot::empty(binding, MapKind::History)?,
            requests: MapRoot::empty(binding, MapKind::Requests)?,
            collections: MapRoot::empty(binding, MapKind::Collections)?,
            lifecycle: MapRoot::empty(binding, MapKind::Lifecycle)?,
            segments: MapRoot::empty(binding, MapKind::Segments)?,
            pending: MapRoot::empty(binding, MapKind::Pending)?,
            retained: MapRoot::empty(binding, MapKind::Retained)?,
            corpus: MapRoot::empty(binding, MapKind::Corpus)?,
        })
    }
    pub fn all(&self) -> [&MapRoot; 9] {
        [
            &self.artifacts,
            &self.history,
            &self.requests,
            &self.collections,
            &self.lifecycle,
            &self.segments,
            &self.pending,
            &self.retained,
            &self.corpus,
        ]
    }
    pub fn validate(&self, binding: &OwnerBinding) -> Result<()> {
        for (root, kind) in self.all().into_iter().zip([
            MapKind::Artifacts,
            MapKind::History,
            MapKind::Requests,
            MapKind::Collections,
            MapKind::Lifecycle,
            MapKind::Segments,
            MapKind::Pending,
            MapKind::Retained,
            MapKind::Corpus,
        ]) {
            root.validate()?;
            if root.binding != *binding || root.kind != kind {
                return Err("v2 owner root has a different owner, generation or map role".into());
            }
        }
        if self.artifacts.entry_count != self.lifecycle.entry_count
            || self.corpus.entry_count > self.artifacts.entry_count
            || self.collections.entry_count > self.artifacts.entry_count
        {
            return Err("v2 owner current/lifecycle/corpus counts are inconsistent".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryCursor {
    pub outcomes: u64,
    pub segments: u64,
    pub last_segment: Option<BlobReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationProvenance {
    pub legacy: crate::VerifiedState,
    pub legacy_identity_sha256: String,
    pub retained_inventory_sha256: String,
}
/// Protected cumulative physical counters. New operations must obtain actual
/// held-file allocation deltas; this summary is not a substitute for them or an
/// admission lease. Damaged/unknown accounting requires explicit reconciliation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalAccounting {
    pub observed: PhysicalInventory,
    pub observation_sha256: String,
    pub descriptor_reserve_bytes: u64,
    pub descriptor_reserve_inodes: u64,
}
impl PhysicalAccounting {
    pub fn from_observation(observed: PhysicalInventory) -> Result<Self> {
        let value = Self {
            observation_sha256: luma_content::sha256(&serde_json::to_vec(&observed)?),
            observed,
            descriptor_reserve_bytes: 32768,
            descriptor_reserve_inodes: 3,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        digest(&self.observation_sha256)?;
        if self.observation_sha256 != luma_content::sha256(&serde_json::to_vec(&self.observed)?)
            || self.descriptor_reserve_bytes != 32768
            || self.descriptor_reserve_inodes != 3
            || self.observed.regular_files > 4_194_304
            || self.observed.directories > 65794
            || self.observed.incomplete_objects > self.observed.regular_files
        {
            return Err("v2 physical observation/reservation summary is inconsistent".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerHeadV2 {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub history: HistoryCursor,
    pub roots: OwnerRoots,
    pub migration: Option<MigrationProvenance>,
    pub physical: PhysicalAccounting,
}
impl OwnerHeadV2 {
    /// Pure explicit initial DATA, not permission to initialize or adopt storage.
    pub fn empty_data(binding: &OwnerBinding, observed: PhysicalInventory) -> Result<Self> {
        let value = Self {
            schema_version: 2,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            history: HistoryCursor {
                outcomes: 0,
                segments: 0,
                last_segment: None,
            },
            roots: OwnerRoots::empty(binding)?,
            migration: None,
            physical: PhysicalAccounting::from_observation(observed)?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.roots.validate(&self.binding)?;
        self.physical.validate()?;
        if self.schema_version != 2
            || self.domain != DOMAIN
            || self.history.outcomes > MAX_MAP_ENTRIES
            || self.history.segments > MAX_SEGMENTS
            || self.history.outcomes != self.roots.requests.entry_count
            || self.history.segments != self.roots.segments.entry_count
            || (self.history.outcomes == 0) != (self.history.segments == 0)
            || self.history.segments > self.history.outcomes
        {
            return Err("v2 owner history/global map counts differ".into());
        }
        match &self.history.last_segment {
            None if self.history.segments == 0 => {}
            Some(reference) if self.history.segments > 0 => {
                reference.validate()?;
                if reference.binding != self.binding
                    || reference.bytes == 0
                    || reference.bytes > 8192
                {
                    return Err("v2 last segment descriptor owner/size differs".into());
                }
            }
            _ => return Err("v2 owner last segment/history mismatch".into()),
        }
        if let Some(migration) = &self.migration {
            migration.legacy.validate()?;
            digest(&migration.legacy_identity_sha256)?;
            digest(&migration.retained_inventory_sha256)?;
            if migration.legacy.binding != self.binding
                || migration.legacy.outcome_count > self.history.outcomes
            {
                return Err("v2 migration provenance retargets or loses legacy outcomes".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("v2 owner head exceeds one bounded page".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_PAGE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}
