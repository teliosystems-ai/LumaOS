//! Exact per-job allocation manifests. This module verifies physical DATA; it
//! cannot authenticate a principal, select C or dispatch a checkpoint. A native
//! publisher must join the observed result to its independently reconstructed
//! semantic operation and the exact current job-index CAS.
use super::super::super::paged::slots::{
    self, Directory, NamespaceObservation, Plan, Reference, SealedReference,
};
use super::super::*;

const DOMAIN: &str = "luma-c-reviewed-job-allocation-v4";
const MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::content_checkpoint::custody::v2_publication) enum Role {
    SemanticPage,
    SemanticRecord,
    LocationIndex,
    JobIndex,
    Manifest,
    Descriptor,
    ClosingControl,
}
impl Role {
    fn accepts(self, kind: slots::Kind) -> bool {
        match self {
            Self::SemanticRecord | Self::Manifest => kind == slots::Kind::Record,
            Self::ClosingControl => kind == slots::Kind::Control,
            _ => kind == slots::Kind::Page,
        }
    }
    fn metadata(self) -> bool {
        matches!(
            self,
            Self::LocationIndex | Self::JobIndex | Self::Manifest | Self::Descriptor
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(in crate::content_checkpoint::custody::v2_publication) enum Disposition {
    Available,
    Sealed {
        value: SealedReference,
    },
    /// Full bytes/hash are committed by an authenticated direct ancestor. Not
    /// placing the self/index hash here prevents a descriptor/index hash cycle.
    BoundMetadata,
    /// Retains the exact never-written inode/extents; does not free or reuse it.
    RetiredUnwritten {
        operation_sha256: String,
        review_sha256: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody::v2_publication) struct Member {
    pub slot: Reference,
    pub role: Role,
    pub disposition: Disposition,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody::v2_publication) struct Manifest {
    pub schema_version: u32,
    pub domain: String,
    pub binding: map::CustodyBinding,
    pub job: String,
    pub base_descriptor_sha256: String,
    pub original_request_sha256: String,
    pub review_sha256: String,
    pub source_sha256: String,
    pub previous: Option<SealedReference>,
    pub own_slot: u32,
    pub layout: Plan,
    pub namespace: NamespaceObservation,
    pub members: Vec<Member>,
    pub allocated_bytes: u64,
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        for value in [
            &self.job,
            &self.base_descriptor_sha256,
            &self.original_request_sha256,
            &self.review_sha256,
            &self.source_sha256,
        ] {
            digest(value)?;
        }
        self.layout.validate()?;
        digest(&self.namespace.identity_sha256)?;
        if self.schema_version != 4
            || self.domain != DOMAIN
            || self.layout.schema_version != 4
            || self.layout.binding != self.binding
            || self.layout.job != self.job
            || self.members.len() != self.layout.slots()? as usize
            || self.own_slot >= self.layout.slots()?
            || self.namespace.inode == 0
            || self.namespace.mount == 0
            || self.namespace.identity_inode == 0
            || self.namespace.inode == self.namespace.identity_inode
            || !(0..1_000_000_000).contains(&self.namespace.ctime_nanoseconds)
            || self.namespace.identity_bytes != serde_json::to_vec(&self.layout)?.len() as u64
            || self.namespace.identity_sha256 != hash(&serde_json::to_vec(&self.layout)?)
            || self.namespace.identity_bytes > slots::PLAN_BYTES as u64
            || self.namespace.identity_allocated_bytes < self.namespace.identity_bytes
        {
            return Err("job manifest changes its exact reviewed layout/namespace/identity".into());
        }
        let mut inodes = BTreeSet::new();
        let mut markers = BTreeSet::new();
        inodes.insert(self.namespace.inode);
        inodes.insert(self.namespace.identity_inode);
        let mut total = self
            .namespace
            .allocated_bytes
            .checked_add(self.namespace.identity_allocated_bytes)
            .ok_or("job namespace accounting overflow")?;
        for (index, member) in self.members.iter().enumerate() {
            member.slot.validate(&self.layout)?;
            if member.slot.number != index as u32
                || member.slot.device != self.namespace.device
                || member.slot.mount != self.namespace.mount
                || !member.role.accepts(member.slot.kind)
                || !inodes.insert(member.slot.inode)
                || !markers.insert(&member.slot.instance_id)
            {
                return Err(
                    "job manifest omits, repeats, aliases or changes a reviewed physical member"
                        .into(),
                );
            }
            total = total
                .checked_add(member.slot.allocated_bytes)
                .ok_or("job slot accounting overflow")?;
            match &member.disposition {
                Disposition::Sealed { value } => {
                    value.validate(&self.layout)?;
                    if value.slot != member.slot || member.role.metadata() {
                        return Err("job sealed data changes its selected role/inode".into());
                    }
                }
                Disposition::BoundMetadata if !member.role.metadata() => {
                    return Err("ordinary data cannot claim ancestor-only metadata binding".into())
                }
                Disposition::RetiredUnwritten {
                    operation_sha256,
                    review_sha256,
                } => {
                    digest(operation_sha256)?;
                    digest(review_sha256)?;
                }
                _ => {}
            }
        }
        let own = &self.members[self.own_slot as usize];
        if own.role != Role::Manifest
            || own.disposition != Disposition::BoundMetadata
            || total != self.allocated_bytes
            || total > 24 * 1024 * 1024 * 1024
        {
            return Err(
                "job manifest self-location or full measured ownership totals differ".into(),
            );
        }
        if let Some(previous) = &self.previous {
            previous.validate(&self.layout)?;
            let old = &self.members[previous.slot.number as usize];
            if previous.slot.kind != slots::Kind::Record
                || previous.slot.number == self.own_slot
                || old.slot != previous.slot
                || old.role != Role::Manifest
                || old.disposition != Disposition::BoundMetadata
            {
                return Err(
                    "job manifest overwrites/reuses its previous immutable descriptor".into(),
                );
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_BYTES
            || bytes.len() as u64 > self.members[self.own_slot as usize].slot.capacity
        {
            return Err("job manifest exceeds its exact existing record allocation".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_BYTES)?;
        if value.canonical_bytes()? != bytes {
            return Err("noncanonical job manifest".into());
        }
        Ok(value)
    }
    pub fn closed(&self) -> Result<bool> {
        self.validate()?;
        Ok(self
            .members
            .iter()
            .all(|member| !matches!(member.disposition, Disposition::Available)))
    }
    pub fn validate_successor(
        &self,
        previous: &Self,
        previous_location: &SealedReference,
    ) -> Result<()> {
        self.validate()?;
        previous.validate()?;
        previous_location.validate(&previous.layout)?;
        if previous_location.slot != previous.members[previous.own_slot as usize].slot
            || previous_location.sha256 != hash(&previous.canonical_bytes()?)
            || previous_location.bytes != previous.canonical_bytes()?.len() as u64
            || self.previous.as_ref() != Some(previous_location)
            || self.binding != previous.binding
            || self.job != previous.job
            || self.layout != previous.layout
            || self.namespace != previous.namespace
            || self.allocated_bytes != previous.allocated_bytes
            || self.original_request_sha256 == previous.original_request_sha256
            || self.base_descriptor_sha256 == previous.base_descriptor_sha256
        {
            return Err("job successor lacks its exact immutable previous manifest/fresh reviewed C operation".into());
        }
        for (before, after) in previous.members.iter().zip(&self.members) {
            if before.slot != after.slot
                || before.role != after.role
                || (!matches!(before.disposition, Disposition::Available) && before != after)
            {
                return Err("job successor redirects, reactivates or edits an already consumed physical member".into());
            }
        }
        Ok(())
    }
}

/// Actual held-name/xattr/full-byte observations. No decoded constructor,
/// Serialize or Checkpoint capability; this is not an authorization proof.
pub(in crate::content_checkpoint::custody::v2_publication) struct ObservedManifest {
    manifest: Manifest,
    location: SealedReference,
    physical: paged::PhysicalInventory,
}
impl ObservedManifest {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn location(&self) -> &SealedReference {
        &self.location
    }
    pub fn physical(&self) -> &paged::PhysicalInventory {
        &self.physical
    }
}
pub(in crate::content_checkpoint::custody::v2_publication) fn observe(
    pages: &PageStore,
    location: &SealedReference,
    metadata: &BTreeMap<u32, SealedReference>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<ObservedManifest> {
    check()?;
    let directory = Directory::at_reference(pages, &location.slot, check)?;
    let bytes = directory.read(location, check)?;
    let manifest = Manifest::from_canonical(&bytes)?;
    if manifest.binding != *pages.binding()
        || manifest.layout != *directory.plan()
        || location.slot != manifest.members[manifest.own_slot as usize].slot
        || metadata.get(&manifest.own_slot) != Some(location)
        || directory.observe_namespace(check)? != manifest.namespace
    {
        return Err("actual job manifest is not its exact complete held physical namespace".into());
    }
    let mut physical = paged::PhysicalInventory {
        files: 1,
        directories: 1,
        logical_bytes: manifest.namespace.identity_bytes,
        allocated_bytes: manifest.namespace.allocated_bytes
            + manifest.namespace.identity_allocated_bytes,
        interrupted_files: 0,
    };
    let mut consumed = BTreeSet::new();
    for member in &manifest.members {
        check()?;
        let length = match &member.disposition {
            Disposition::Available | Disposition::RetiredUnwritten { .. } => {
                directory.require_unfilled(&member.slot, check)?;
                0
            }
            Disposition::Sealed { value } => directory.read(value, check)?.len() as u64,
            Disposition::BoundMetadata => {
                let value = metadata
                    .get(&member.slot.number)
                    .ok_or("selected metadata member lacks its exact full ancestor-bound seal")?;
                if value.slot != member.slot || !consumed.insert(member.slot.number) {
                    return Err("metadata member redirects/reuses a physical slot".into());
                }
                directory.read(value, check)?.len() as u64
            }
        };
        let (actual, allocated, _) = directory.observe_allocation(&member.slot, check)?;
        if actual != length {
            return Err("actual job member length differs from its verified disposition".into());
        }
        physical.files = physical
            .files
            .checked_add(1)
            .ok_or("job file counter overflow")?;
        if length == 0 {
            physical.interrupted_files = physical
                .interrupted_files
                .checked_add(1)
                .ok_or("job zero-length counter overflow")?;
        }
        physical.logical_bytes = physical
            .logical_bytes
            .checked_add(length)
            .ok_or("job logical counter overflow")?;
        physical.allocated_bytes = physical
            .allocated_bytes
            .checked_add(allocated)
            .ok_or("job allocated counter overflow")?;
    }
    if consumed.len() != metadata.len()
        || physical.allocated_bytes != manifest.allocated_bytes
        || directory.observe_namespace(check)? != manifest.namespace
        || directory.read(location, check)? != bytes
    {
        return Err(
            "job physical accounting/metadata closure changed or includes an unclaimed member"
                .into(),
        );
    }
    check()?;
    Ok(ObservedManifest {
        manifest,
        location: location.clone(),
        physical,
    })
}
