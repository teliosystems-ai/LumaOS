//! Paged C selection and one-dispatch publication. This is a separate native
//! format; immutable bytes, historical audits and a prepared file never grant
//! permission to extend C or adopt a current owner.
use super::paged::{PageStore, PAGE_BYTES};
use super::protocol::{OriginalCAdminOperation, OriginalCOperation, SourcePurpose};
use super::*;
use luma_content_store::v2::custody_map as map;
use luma_content_store::v2::head::OwnerHeadV2;

const DOMAIN: &str = "luma-native-content-custody-paged-v3";
const CONTROL_BYTES: usize = 64 * 1024;
const SUFFIX_LIMIT: u64 = 256;
const READ_BUDGET: u64 = 32 * 1024 * 1024;
// The direct publisher carries C-only fields and accessors that its native
// activation consumes; under test it is exercised without that activation.
#[path = "v2_publication/admin_review.rs"]
mod admin_review;
#[allow(dead_code)]
#[cfg(test)]
#[path = "v2_publication/direct.rs"]
mod direct;

#[path = "v2_publication/bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::{
    begin_bootstrap, initial_recovery_review, legacy_bootstrap_review, resume_retired_bootstrap,
    retire_initial_bootstrap, retired_bootstrap_review,
};
// Control cells, location maps and typed-event semantics are staged for the
// native direct C publisher, which is still compiled only under test.
#[cfg_attr(not(test), allow(dead_code))]
#[path = "v2_publication/control.rs"]
mod control;
#[path = "v2_publication/index.rs"]
pub(in crate::content_checkpoint::custody) mod index;
#[cfg_attr(not(test), allow(dead_code))]
#[path = "v2_publication/locations.rs"]
mod locations;
#[path = "v2_publication/parent_allocation.rs"]
mod parent_allocation;
#[cfg_attr(not(test), allow(dead_code))]
#[path = "v2_publication/semantic.rs"]
mod semantic;

/// Only borrows the protocol's independently constructed original-operation
/// contexts. Worker leases and Admin provenance stay disjoint; neither can be
/// decoded, cached as a permission or replaced by an OwnerBinding-shaped value.
enum COperation<'a, 'b> {
    #[cfg_attr(not(test), allow(dead_code))]
    Worker(&'a mut OriginalCOperation<'b>),
    Admin(&'a mut OriginalCAdminOperation<'b>),
}
impl COperation<'_, '_> {
    fn check(&mut self) -> Result<()> {
        match self {
            Self::Worker(value) => value.check(),
            Self::Admin(value) => value.check(),
        }
    }
    fn audit(&self) -> &Audit {
        match self {
            Self::Worker(value) => value.audit(),
            Self::Admin(value) => value.audit(),
        }
    }
    fn source_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Worker(value) => Ok(serde_json::to_vec(&(
                "luma-c-original-worker-source-v1",
                value.source_binding(),
            ))?),
            Self::Admin(value) => Ok(serde_json::to_vec(&(
                "luma-c-original-admin-source-v1",
                value.source_binding(),
            ))?),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LegacyCut {
    journal_sha256: String,
    journal_bytes: u64,
    events: u64,
    nv_head: String,
}
impl LegacyCut {
    fn validate(&self) -> Result<()> {
        digest(&self.journal_sha256)?;
        digest(&self.nv_head)?;
        if self.journal_bytes == 0
            || self.journal_bytes > MAX_JOURNAL as u64
            || self.events > MAX_EVENTS as u64
        {
            return Err("invalid retained legacy C cut".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Roots {
    owners: map::Root,
    recipients: map::Root,
    signers: map::Root,
    unavailable: map::Root,
    restore_reservations: map::Root,
    archive_inventory: map::Root,
    index_generations: map::Root,
}
impl Roots {
    fn empty(binding: &map::CustodyBinding) -> Result<Self> {
        Ok(Self {
            owners: map::Root::empty_data(binding, map::Kind::OwnerStates)?,
            recipients: map::Root::empty_data(binding, map::Kind::Recipients)?,
            signers: map::Root::empty_data(binding, map::Kind::Signers)?,
            unavailable: map::Root::empty_data(binding, map::Kind::Unavailable)?,
            restore_reservations: map::Root::empty_data(binding, map::Kind::RestoreReservations)?,
            archive_inventory: map::Root::empty_data(binding, map::Kind::ArchiveInventory)?,
            index_generations: map::Root::empty_data(binding, map::Kind::IndexGenerations)?,
        })
    }
    fn validate(&self, binding: &map::CustodyBinding) -> Result<()> {
        for (root, kind) in [
            (&self.owners, map::Kind::OwnerStates),
            (&self.recipients, map::Kind::Recipients),
            (&self.signers, map::Kind::Signers),
            (&self.unavailable, map::Kind::Unavailable),
            (&self.restore_reservations, map::Kind::RestoreReservations),
            (&self.archive_inventory, map::Kind::ArchiveInventory),
            (&self.index_generations, map::Kind::IndexGenerations),
        ] {
            root.validate()?;
            if root.binding != *binding || root.kind != kind {
                return Err("paged C root substitutes authority or role".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecordRef {
    sha256: String,
    bytes: u64,
}
impl RecordRef {
    fn validate(&self) -> Result<()> {
        digest(&self.sha256)?;
        if self.bytes == 0 || self.bytes > super::paged::FILE_BYTES as u64 {
            return Err("paged C immutable record reference exceeds bound".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LegacyRecordClosure {
    legacy_journal_sha256: String,
    legacy_owner_record_count: u64,
    latest_suffix: Option<RecordRef>,
    suffix_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
enum OwnerLeaf {
    V1 {
        state: VerifiedState,
        records: LegacyRecordClosure,
        migration_prefix: Option<RecordRef>,
    },
    V2 {
        binding: OwnerBinding,
        head: RecordRef,
        physical: luma_content_store::v2::PhysicalInventory,
    },
}
impl OwnerLeaf {
    fn validate(&self, installation: &str, legacy: &LegacyCut) -> Result<()> {
        match self {
            Self::V1 {
                state,
                records,
                migration_prefix,
            } => {
                state.validate()?;
                if state.binding.installation != installation
                    || records.legacy_journal_sha256 != legacy.journal_sha256
                    || records.legacy_owner_record_count > 256
                    || records.suffix_count > SUFFIX_LIMIT
                    || records
                        .legacy_owner_record_count
                        .checked_add(records.suffix_count)
                        != Some(state.outcome_count)
                    || (records.latest_suffix.is_none()) != (records.suffix_count == 0)
                {
                    return Err("tagged V1 C record closure differs from selected owner".into());
                }
                if let Some(reference) = &records.latest_suffix {
                    reference.validate()?;
                }
                if let Some(reference) = migration_prefix {
                    reference.validate()?;
                }
            }
            Self::V2 {
                binding,
                head,
                physical,
            } => {
                binding.validate()?;
                head.validate()?;
                if binding.installation != installation || head.bytes > PAGE_BYTES as u64 {
                    return Err("tagged V2 owner head binding/size differs".into());
                }
                if physical.regular_files > 4_194_304
                    || physical.directories > 65794
                    || physical.incomplete_objects > physical.regular_files
                {
                    return Err(
                        "tagged V2 physical accounting exceeds closed owner namespace bounds"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordNode {
    schema_version: u32,
    binding: OwnerBinding,
    legacy_journal_sha256: String,
    sequence: u64,
    previous: Option<RecordRef>,
    publication: Publication,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum OperationData {
    BootstrapProgress {
        previous_retirement: Option<String>,
        review_sha256: String,
        window_intent_sha256: String,
        request_sha256: String,
        source_sha256: String,
        original_authority: Audit,
    },
    V1Publication {
        binding: OwnerBinding,
        request_sha256: String,
        source_sha256: String,
        event: RecordRef,
        original_authority: Audit,
    },
    IndexPreparation {
        binding: OwnerBinding,
        request_sha256: String,
        input_sha256: String,
        source_sha256: String,
        preparation: RecordRef,
        original_authority: Audit,
    },
    // Awaits its only producer, the direct C index publisher.
    #[cfg(test)]
    IndexJobReservation {
        binding: OwnerBinding,
        request_sha256: String,
        input_sha256: String,
        source_sha256: String,
        reservation: RecordRef,
        original_authority: Audit,
    },
}
/// One closed historical index Write effect: the exact owner generation, a
/// bounded C record and the unchanged original finite envelope.
fn validate_index_effect(
    binding: &OwnerBinding,
    hashes: [&String; 3],
    record: &RecordRef,
    original_authority: &Audit,
) -> Result<()> {
    binding.validate()?;
    for value in hashes {
        digest(value)?;
    }
    record.validate()?;
    original_authority.validate()?;
    let usage = &original_authority.usage;
    if record.bytes > 64 * 1024
        || original_authority.operation_id.is_none()
        || original_authority.subject != binding.owner
        || original_authority.subject_generation != binding.owner_generation
        || usage.action != crate::finite_grants::Action::Write
        || usage.selector.kind != crate::finite_grants::Kind::Artifact
        || usage.selector.id != "native-content-index-build-v2"
        || usage.selector.generation != binding.owner_generation
        || usage.units != 1
        || usage.input_bytes > 256 * 1024 * 1024
        || usage.output_bytes > 128 * 1024 * 1024
    {
        return Err("index preparation changes its closed historical owner/effect record".into());
    }
    Ok(())
}
impl OperationData {
    fn validate(&self) -> Result<()> {
        match self {
            Self::BootstrapProgress {
                previous_retirement,
                review_sha256,
                window_intent_sha256,
                request_sha256,
                source_sha256,
                original_authority,
            } => {
                if let Some(attempt) = previous_retirement {
                    digest(attempt)?;
                }
                digest(review_sha256)?;
                digest(window_intent_sha256)?;
                digest(request_sha256)?;
                digest(source_sha256)?;
                original_authority.validate()?;
                if original_authority.operation_id.is_none()
                    || original_authority.usage.selector.id != "content-custody-paged-bootstrap-v3"
                    || original_authority.usage.selector.digest != *window_intent_sha256
                    || original_authority.usage.action
                        != crate::finite_grants::Action::ProvisionResource
                {
                    return Err(
                        "paged migration lacks exact historical reviewed Admin scope".into(),
                    );
                }
            }
            Self::V1Publication {
                binding,
                request_sha256,
                source_sha256,
                event,
                original_authority,
            } => {
                binding.validate()?;
                digest(request_sha256)?;
                digest(source_sha256)?;
                event.validate()?;
                original_authority.validate()?;
            }
            Self::IndexPreparation {
                binding,
                request_sha256,
                input_sha256,
                source_sha256,
                preparation,
                original_authority,
            } => validate_index_effect(
                binding,
                [request_sha256, input_sha256, source_sha256],
                preparation,
                original_authority,
            )?,
            #[cfg(test)]
            Self::IndexJobReservation {
                binding,
                request_sha256,
                input_sha256,
                source_sha256,
                reservation,
                original_authority,
            } => validate_index_effect(
                binding,
                [request_sha256, input_sha256, source_sha256],
                reservation,
                original_authority,
            )?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema_version: u32,
    domain: String,
    binding: map::CustodyBinding,
    sequence: u64,
    global_ordinal: u64,
    previous_descriptor_sha256: Option<String>,
    previous_nv_head: String,
    event_sha256: String,
    selected_nv_head: String,
    legacy: LegacyCut,
    roots: Roots,
    phase: bootstrap::Phase,
    storage: Option<StorageSelection>,
    operation: OperationData,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StorageSelection {
    schema_version: u32,
    controls: super::paged::cells::Selection,
    locations: locations::Root,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jobs: Option<locations::JobRoot>,
    descriptor_slot: super::paged::slots::Reference,
    post_allocation: super::paged::PhysicalInventory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_allocation: Option<parent_allocation::Delta>,
}
impl StorageSelection {
    fn validate(&self, binding: &map::CustodyBinding) -> Result<()> {
        self.controls.validate()?;
        self.locations.validate()?;
        self.descriptor_slot.validate_data()?;
        if let Some(delta) = &self.parent_allocation {
            delta.validate()?;
            if self.schema_version != 2 {
                return Err(
                    "parent allocation delta requires the closed direct job profile".into(),
                );
            }
        }
        let profile = match self.schema_version {
            1 => self.jobs.is_none(),
            2 => match &self.jobs {
                Some(jobs) => {
                    jobs.validate()?;
                    jobs.binding() == binding
                }
                None => false,
            },
            _ => false,
        };
        if !profile
            || self.controls.binding != *binding
            || self.locations.binding != *binding
            || self.descriptor_slot.kind != super::paged::slots::Kind::Page
            || self.post_allocation.files == 0
            || self.post_allocation.logical_bytes > 24 * 1024 * 1024 * 1024
            || self.post_allocation.allocated_bytes > 24 * 1024 * 1024 * 1024
            || self.post_allocation.interrupted_files != 0
        {
            return Err("direct-slot storage field substitutes C binding, descriptor capacity or physical admission data".into());
        }
        Ok(())
    }
}
impl Descriptor {
    #[cfg_attr(not(test), allow(dead_code))]
    fn slot_frame(&self) -> Result<Vec<u8>> {
        if self.storage.is_none() {
            return Err("hash-addressed descriptor cannot impersonate direct-slot storage".into());
        }
        let bytes = self.bytes()?;
        let header = b"LUMACDESCv3!\n";
        if bytes.len() > PAGE_BYTES - header.len() - 4 {
            return Err("direct-slot descriptor exceeds its fixed allocated frame".into());
        }
        let mut frame = vec![0_u8; PAGE_BYTES];
        frame[..header.len()].copy_from_slice(header);
        frame[header.len()..header.len() + 4]
            .copy_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
        frame[header.len() + 4..header.len() + 4 + bytes.len()].copy_from_slice(&bytes);
        Ok(frame)
    }
    #[cfg_attr(not(test), allow(dead_code))]
    fn from_slot_frame(frame: &[u8]) -> Result<Self> {
        let header = b"LUMACDESCv3!\n";
        let start = header.len() + 4;
        if frame.len() != PAGE_BYTES || &frame[..header.len()] != header {
            return Err("invalid exact direct-slot descriptor frame".into());
        }
        let length = u32::from_be_bytes(frame[header.len()..start].try_into()?) as usize;
        if length == 0
            || length > PAGE_BYTES - start
            || frame[start + length..].iter().any(|n| *n != 0)
        {
            return Err("direct-slot descriptor length/padding differs".into());
        }
        let value: Self = canonical(&frame[start..start + length], PAGE_BYTES)?;
        value.validate()?;
        if value.storage.is_none() || value.slot_frame()? != frame {
            return Err("descriptor frame is not the closed direct-slot format".into());
        }
        Ok(value)
    }
    fn event_digest(&self) -> Result<[u8; 32]> {
        Ok(sha2::Sha256::digest(serde_json::to_vec(&(
            "luma-native-content-custody-paged-event-v3",
            &self.binding,
            self.sequence,
            self.global_ordinal,
            &self.previous_descriptor_sha256,
            &self.previous_nv_head,
            &self.legacy,
            &self.roots,
            &self.phase,
            &self.storage,
            &self.operation,
        ))?)
        .into())
    }
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.legacy.validate()?;
        self.roots.validate(&self.binding)?;
        self.operation.validate()?;
        self.phase.validate(&self.legacy, &self.roots)?;
        if let Some(storage) = &self.storage {
            storage.validate(&self.binding)?;
        }
        if let OperationData::BootstrapProgress {
            review_sha256,
            previous_retirement,
            ..
        } = &self.operation
        {
            if self.sequence != 1 && previous_retirement.is_some() {
                return Err("only an initial bootstrap dispatch can reference a prior first-dispatch retirement".into());
            }
            if *review_sha256 != self.phase.review_sha256 {
                return Err("C bootstrap event substitutes stable reviewed source".into());
            }
            if self.phase.state == bootstrap::State::Ready
                && self
                    .roots
                    .all()
                    .iter()
                    .enumerate()
                    .any(|(i, root)| root.entry_count != self.phase.expected_counts[i])
            {
                return Err(
                    "C bootstrap completion does not cover every selected role projection".into(),
                );
            }
        } else {
            self.phase.require_ready()?;
        }
        digest(&self.previous_nv_head)?;
        digest(&self.event_sha256)?;
        digest(&self.selected_nv_head)?;
        if self.schema_version != 3
            || self.domain != DOMAIN
            || self.sequence == 0
            || self.global_ordinal
                != self
                    .legacy
                    .events
                    .checked_add(1)
                    .and_then(|v| v.checked_add(self.sequence))
                    .ok_or("paged C global ordinal overflow")?
            || (self.sequence == 1) != self.previous_descriptor_sha256.is_none()
            || (self.sequence == 1
                && (!matches!(self.operation, OperationData::BootstrapProgress { .. })
                    || self.phase.state != bootstrap::State::Pending))
            || bundle::hex(&self.event_digest()?) != self.event_sha256
            || bundle::hex(&tpm::extend_value(
                tpm::decode(&self.previous_nv_head)?,
                self.event_digest()?,
            )) != self.selected_nv_head
        {
            return Err("paged C descriptor event/NV/ordinal continuation differs".into());
        }
        if let Some(previous) = &self.previous_descriptor_sha256 {
            digest(previous)?;
        }
        if self.sequence == 1 && self.previous_nv_head != self.legacy.nv_head {
            return Err("paged C bootstrap does not extend retained legacy NV cut".into());
        }
        Ok(())
    }
    fn seal(mut self) -> Result<Self> {
        let event = self.event_digest()?;
        self.event_sha256 = bundle::hex(&event);
        self.selected_nv_head = bundle::hex(&tpm::extend_value(
            tpm::decode(&self.previous_nv_head)?,
            event,
        ));
        self.validate()?;
        Ok(self)
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > PAGE_BYTES {
            return Err("native paged descriptor exceeds one bounded page".into());
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema_version: u32,
    descriptor_sha256: String,
    nv_head: String,
}
impl Selector {
    fn for_descriptor(value: &Descriptor) -> Result<Self> {
        Ok(Self {
            schema_version: 3,
            descriptor_sha256: hash(&value.bytes()?),
            nv_head: value.selected_nv_head.clone(),
        })
    }
    fn validate(&self) -> Result<()> {
        digest(&self.descriptor_sha256)?;
        digest(&self.nv_head)?;
        if !matches!(self.schema_version, 1 | 3) {
            return Err("invalid native C selector".into());
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
}

/// The first transition retains a genuine independently selected legacy cut,
/// not a fabricated empty paged descriptor. Schema 1 selectors are accepted
/// only inside this private prepared-base envelope, never by the paged opener.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
enum BaseSnapshot {
    Legacy {
        binding: map::CustodyBinding,
        cut: LegacyCut,
    },
    Paged {
        descriptor: Descriptor,
    },
}
impl BaseSnapshot {
    fn selector(&self) -> Result<Selector> {
        match self {
            Self::Legacy { binding, cut } => {
                binding.validate()?;
                cut.validate()?;
                Ok(Selector {
                    schema_version: 1,
                    descriptor_sha256: hash(&self.bytes()?),
                    nv_head: cut.nv_head.clone(),
                })
            }
            Self::Paged { descriptor } => Selector::for_descriptor(descriptor),
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > CONTROL_BYTES {
            return Err("prepared C base exceeds its closed bound".into());
        }
        Ok(bytes)
    }
    fn binding(&self) -> &map::CustodyBinding {
        match self {
            Self::Legacy { binding, .. } => binding,
            Self::Paged { descriptor } => &descriptor.binding,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: u32,
    attempt: String,
    base: Selector,
    next: Selector,
    event_sha256: String,
    operation_sha256: String,
}
impl Pending {
    fn bytes(&self) -> Result<Vec<u8>> {
        digest(&self.attempt)?;
        self.base.validate()?;
        self.next.validate()?;
        digest(&self.event_sha256)?;
        digest(&self.operation_sha256)?;
        if self.schema_version != 3
            || self.base == self.next
            || bundle::hex(&tpm::extend_value(
                tpm::decode(&self.base.nv_head)?,
                tpm::decode(&self.event_sha256)?,
            )) != self.next.nv_head
        {
            return Err("paged pending cut is not one exact existing C extension".into());
        }
        Ok(serde_json::to_vec(self)?)
    }
    fn validate_descriptors(&self, base: &Descriptor, next: &Descriptor) -> Result<()> {
        self.bytes()?;
        base.validate()?;
        next.validate()?;
        if Selector::for_descriptor(base)? != self.base
            || Selector::for_descriptor(next)? != self.next
            || next.binding != base.binding
            || next.legacy != base.legacy
            || next.sequence
                != base
                    .sequence
                    .checked_add(1)
                    .ok_or("C descriptor sequence overflow")?
            || next.previous_descriptor_sha256.as_ref() != Some(&self.base.descriptor_sha256)
            || next.previous_nv_head != self.base.nv_head
            || next.event_sha256 != self.event_sha256
            || hash(&serde_json::to_vec(&next.operation)?) != self.operation_sha256
        {
            return Err(
                "paged prepared descriptor substitutes base, roots or semantic operation".into(),
            );
        }
        if matches!(next.operation, OperationData::BootstrapProgress { .. }) {
            base.phase.require_successor(&next.phase)?;
        } else if base.phase != next.phase {
            return Err("ordinary C publication changes global bootstrap provenance".into());
        }
        Ok(())
    }
    fn validate_base(&self, base: &BaseSnapshot, next: &Descriptor) -> Result<()> {
        match base {
            BaseSnapshot::Paged { descriptor } => self.validate_descriptors(descriptor, next),
            BaseSnapshot::Legacy { binding, cut } => {
                self.bytes()?;
                next.validate()?;
                if self.base != base.selector()?
                    || self.next != Selector::for_descriptor(next)?
                    || next.binding != *binding
                    || next.legacy != *cut
                    || next.sequence != 1
                    || next.previous_descriptor_sha256.is_some()
                    || next.previous_nv_head != cut.nv_head
                    || next.event_sha256 != self.event_sha256
                    || hash(&serde_json::to_vec(&next.operation)?) != self.operation_sha256
                    || next.phase.state != bootstrap::State::Pending
                    || next.phase.copied_entries != 0
                    || next.roots != Roots::empty(binding)?
                {
                    return Err("initial C transition substitutes genuine legacy base or empty maintenance state".into());
                }
                Ok(())
            }
        }
    }
}

/// Only independent replay inside this module can produce a publication
/// token. It is neither Clone nor Deserialize, and cannot accept arbitrary roots.
struct VerifiedSemanticDelta {
    base: Selector,
    next: Descriptor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SelectedOwner {
    Legacy {
        state: VerifiedState,
    },
    Paged {
        head: OwnerHeadV2,
        physical: luma_content_store::v2::PhysicalInventory,
    },
}

pub(crate) struct PagedStore<A: Checkpoint> {
    anchor: A,
    legacy_files: Files,
    pages: PageStore,
    selected: Selector,
    descriptor: Descriptor,
    poisoned: bool,
}
impl PagedStore<super::super::ContentAnchor> {
    pub(crate) fn installed(check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        let anchor = super::super::ContentAnchor::installed()?;
        let binding = map::CustodyBinding {
            installation: anchor.installation().into(),
            sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
        };
        let files = Files::installed();
        validate_genesis_at(&files.root, &binding.installation, anchor.genesis_event())?;
        Self::open(anchor, files, binding, check)
    }

    /// Explicit reconciliation does not call advance, replay a dispatch or
    /// synthesize missing stages. An independently authenticated NEW original
    /// Admin operation must approve the exact complete pending-data review.
    pub(crate) fn reconcile_pending(
        expected_review: &str,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<Self> {
        authority.check()?;
        let anchor = super::super::ContentAnchor::installed()?;
        let binding = map::CustodyBinding {
            installation: anchor.installation().into(),
            sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
        };
        Self::reconcile_from_anchor(
            anchor,
            Files::installed(),
            binding,
            expected_review,
            authority,
        )
    }
}
impl<A: Checkpoint> PagedStore<A> {
    fn reconcile_from_anchor(
        mut anchor: A,
        files: Files,
        binding: map::CustodyBinding,
        expected_review: &str,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<Self> {
        digest(expected_review)?;
        authority.check()?;
        let audit = authority.audit();
        audit.validate()?;
        if audit.operation_id.is_none()
            || audit.usage.action != crate::finite_grants::Action::RecoverResource
            || audit.usage.selector.id != "content-custody-paged-reconcile-v3"
            || audit.usage.selector.digest != expected_review
        {
            return Err("paged reconciliation requires its separate fresh exact original Admin recovery scope".into());
        }
        validate_genesis_at(
            &files.root,
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256)?,
        )?;
        let pages = PageStore::open(&files.root, binding.clone(), &mut || authority.check())?;
        let bytes = pages.read("pending.json", CONTROL_BYTES, &mut || authority.check())?;
        let pending: Pending = canonical(&bytes, CONTROL_BYTES)?;
        pending.bytes()?;
        let source = authority.source_binding();
        let control = source
            .paged_control
            .clone()
            .ok_or("paged reconciliation lacks authenticated control DATA")?;
        control.validate()?;
        let opaque = tpm::decode::<16>(&source.job)?;
        if source.command != "content-custody-paged-reconcile"
            || source.installation != binding.installation
            || opaque == [0; 16]
            || source.job != bundle::hex(&opaque)
            || control.attempt_sha256.as_deref() != Some(pending.attempt.as_str())
            || control.expected_selected_descriptor_sha256.as_deref()
                != Some(pending.base.descriptor_sha256.as_str())
        {
            return Err("paged reconciliation changes original Admin command, installation or exact pending attempt".into());
        }
        let prefix = format!("attempts/{}", pending.attempt);
        if pages.read(
            &format!("{prefix}/prepared.json"),
            CONTROL_BYTES,
            &mut || authority.check(),
        )? != bytes
        {
            return Err("pending recovery does not match immutable original prepared cut".into());
        }
        let dispatch = serde_json::to_vec(&(
            "luma-paged-c-single-dispatch-intent-v3",
            hash(&pending.bytes()?),
        ))?;
        if pages.read(&format!("{prefix}/dispatch.json"), 4096, &mut || {
            authority.check()
        })? != dispatch
        {
            return Err(
                "pending recovery has no exact original preallocated dispatch intent".into(),
            );
        }
        let base: BaseSnapshot = canonical(
            &pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, &mut || {
                authority.check()
            })?,
            CONTROL_BYTES,
        )?;
        let next: Descriptor = canonical(
            &pages.read(&format!("{prefix}/next.json"), PAGE_BYTES, &mut || {
                authority.check()
            })?,
            PAGE_BYTES,
        )?;
        pending.validate_base(&base, &next)?;
        if base.binding() != &binding
            || pages.read_page(&pending.next.descriptor_sha256, &mut || authority.check())?
                != next.bytes()?
        {
            return Err(
                "pending C recovery substitutes sealed identity or staged descriptor object".into(),
            );
        }
        let actual = anchor.read()?;
        let selected: Selector = canonical(
            &pages.read("selected.json", 4096, &mut || authority.check())?,
            4096,
        )?;
        selected.validate()?;
        let review = hash(&serde_json::to_vec(&(
            "luma-paged-c-reconciliation-v3",
            &binding,
            &pending,
            &base,
            &next,
            bundle::hex(&actual),
            &selected,
        ))?);
        if review != expected_review
            || control.expected_window_sha256 != review
            || control.stable_review_sha256 != next.phase.review_sha256
        {
            return Err("actual pending C state changed after the independently reviewed recovery observation".into());
        }
        authority.check()?;
        pages.inventory(&mut || authority.check())?;
        if actual == tpm::decode(&pending.base.nv_head)? {
            if selected != pending.base {
                return Err("old C NV does not match exact original selected descriptor; preserve uncertainty".into());
            }
            if matches!(base, BaseSnapshot::Legacy { .. }) {
                return Err("initial C dispatch remains at original legacy NV; use the separate exact initial-retirement review and fresh operation, never reopen legacy or redispatch the old event".into());
            }
            // The dispatch-intent marker is not a successful/attempted TPM
            // receipt. Actual unchanged NV can retire this exact stage only.
            pages.rename(
                "pending.json",
                &format!("{prefix}/retired.json"),
                false,
                &mut || authority.check(),
            )?;
            if pages.read(
                &format!("{prefix}/retired.json"),
                CONTROL_BYTES,
                &mut || authority.check(),
            )? != pending.bytes()?
                || anchor.read()? != actual
            {
                return Err("unchanged C retirement readback differs".into());
            }
        } else if actual == tpm::decode(&pending.next.nv_head)? {
            if selected == pending.base {
                if pages.read(&format!("{prefix}/selector.json"), 4096, &mut || {
                    authority.check()
                })? != pending.next.bytes()?
                {
                    return Err(
                        "advanced C NV has no exact preallocated selector; no regeneration".into(),
                    );
                }
                pages.rename(
                    &format!("{prefix}/selector.json"),
                    "selected.json",
                    true,
                    &mut || authority.check(),
                )?;
            } else if selected != pending.next {
                return Err("advanced C NV has neither reviewed selected descriptor".into());
            }
            if pages.read("selected.json", 4096, &mut || authority.check())?
                != pending.next.bytes()?
                || anchor.read()? != actual
            {
                return Err("C recovery selected/NV readback differs".into());
            }
            pages.rename(
                "pending.json",
                &format!("{prefix}/completed.json"),
                false,
                &mut || authority.check(),
            )?;
            if pages.read(
                &format!("{prefix}/completed.json"),
                CONTROL_BYTES,
                &mut || authority.check(),
            )? != pending.bytes()?
                || anchor.read()? != actual
            {
                return Err("advanced C completion readback differs".into());
            }
        } else {
            return Err(
                "actual C NV matches neither exact prepared head; do not adopt, retry or reset"
                    .into(),
            );
        }
        authority.check()?;
        Self::open(anchor, files, binding, &mut || authority.check())
    }
}
impl<A: Checkpoint> PagedStore<A> {
    fn open(
        anchor: A,
        files: Files,
        binding: map::CustodyBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        if super::format::probe(&files, check)? != super::format::Layout::Paged {
            return Err("paged C opener cannot adopt a legacy or absent namespace".into());
        }
        let pages = PageStore::open(&files.root, binding.clone(), check)?;
        pages.require_hash_controls_empty()?;
        if !pages.absent("pending.json")? {
            return Err(
                "paged C publication is pending; explicit exact reconciliation required".into(),
            );
        }
        let selected: Selector = canonical(&pages.read("selected.json", 4096, check)?, 4096)?;
        selected.validate()?;
        if selected.schema_version != 3 {
            return Err("a prepared legacy base selector is not a selected paged authority".into());
        }
        let descriptor: Descriptor = canonical(
            &pages.read_page(&selected.descriptor_sha256, check)?,
            PAGE_BYTES,
        )?;
        descriptor.validate()?;
        if descriptor.storage.is_some() {
            return Err("direct-slot C requires its closed control-cell opener, never the hashed-file parser".into());
        }
        if descriptor.binding != binding || Selector::for_descriptor(&descriptor)? != selected {
            return Err("paged selected descriptor differs from sealed C identity".into());
        }
        let mut store = Self {
            anchor,
            legacy_files: files,
            pages,
            selected,
            descriptor,
            poisoned: false,
        };
        store.legacy(check)?;
        store.pages.inventory(check)?;
        store.live(check)?;
        Ok(store)
    }
    fn live(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        if self.poisoned {
            return Err("paged C writer is fenced after uncertain publication".into());
        }
        check()?;
        self.pages.check()?;
        self.pages.require_hash_controls_empty()?;
        let actual_nv = self.anchor.read()?;
        if !self.pages.absent("pending.json")?
            || self.pages.read("selected.json", 4096, check)? != self.selected.bytes()?
            || self
                .pages
                .read_page(&self.selected.descriptor_sha256, check)?
                != self.descriptor.bytes()?
            || actual_nv != tpm::decode(&self.selected.nv_head)?
        {
            self.poisoned = true;
            return Err("paged C exact selector/NV changed; no legacy fallback".into());
        }
        check()
    }
    fn legacy(&self, check: &mut impl FnMut() -> Result<()>) -> Result<(Journal, Validated)> {
        let bytes = self.legacy_files.read(JOURNAL, check)?;
        if bytes.len() as u64 != self.descriptor.legacy.journal_bytes
            || hash(&bytes) != self.descriptor.legacy.journal_sha256
        {
            return Err("retained original legacy journal changed under paged C selection".into());
        }
        let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
        journal.require_identity(
            &self.descriptor.binding.installation,
            tpm::decode(&self.descriptor.binding.sealed_genesis_sha256)?,
        )?;
        let state = journal.validate()?;
        if journal.events.len() as u64 != self.descriptor.legacy.events
            || bundle::hex(&state.checkpoint) != self.descriptor.legacy.nv_head
        {
            return Err(
                "retained legacy journal data does not reconstruct exact bootstrap cut".into(),
            );
        }
        Ok((journal, state))
    }
    fn context(&self, review: Option<String>) -> map::Context {
        map::Context {
            binding: self.descriptor.binding.clone(),
            selected_descriptor_sha256: self.selected.descriptor_sha256.clone(),
            selected_nv_head: self.selected.nv_head.clone(),
            review_sha256: review,
        }
    }
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        let context = self.context(None);
        let key = root.key(literal)?;
        let proof = map::lookup(
            root,
            &key,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut ReadIo { store: self, check },
        )?;
        if proof.key != key {
            return Err("C lookup proof substitutes requested logical key".into());
        }
        proof.verify_data(root)
    }
    fn raw_owner_leaf(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Option<OwnerLeaf>> {
        binding.validate()?;
        if binding.installation != self.descriptor.binding.installation {
            return Err("cross-installation paged C owner".into());
        }
        let root = self.descriptor.roots.owners.clone();
        let leaf = self
            .value(&root, owner_key(binding)?.as_bytes(), check)?
            .map(|bytes| canonical::<OwnerLeaf>(&bytes, map::MAX_VALUE_BYTES))
            .transpose()?;
        if let Some(value) = &leaf {
            value.validate(&binding.installation, &self.descriptor.legacy)?;
            let selected_binding = match value {
                OwnerLeaf::V1 { state, .. } => &state.binding,
                OwnerLeaf::V2 { binding, .. } => binding,
            };
            if selected_binding != binding {
                return Err("paged owner leaf substitutes a different generation".into());
            }
        }
        Ok(leaf)
    }
    fn owner_leaf(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Option<OwnerLeaf>> {
        let leaf = self.raw_owner_leaf(binding, check)?;
        let unavailable = self.descriptor.roots.unavailable.clone();
        if self
            .value(&unavailable, owner_key(binding)?.as_bytes(), check)?
            .is_some()
        {
            return Err("paged C owner is protected as unavailable".into());
        }
        Ok(leaf)
    }
    pub(crate) fn selected_owner(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<SelectedOwner> {
        self.live(check)?;
        self.descriptor.phase.require_ready()?;
        let selected = match self.owner_leaf(binding, check)? {
            None => SelectedOwner::Legacy {
                state: VerifiedState::empty(binding)?,
            },
            Some(OwnerLeaf::V1 { state, records, .. }) => {
                self.records(&state, &records, check)?;
                SelectedOwner::Legacy { state }
            }
            Some(OwnerLeaf::V2 {
                binding: _,
                head,
                physical,
            }) => {
                let bytes = self.pages.read_record(&head.sha256, check)?;
                if bytes.len() as u64 != head.bytes {
                    return Err("selected V2 owner head length differs".into());
                }
                let head = OwnerHeadV2::from_canonical(&bytes)?;
                if head.binding != *binding {
                    return Err("selected V2 head changes owner".into());
                }
                SelectedOwner::Paged { head, physical }
            }
        };
        self.live(check)?;
        Ok(selected)
    }
    // V1 paged publication is driven only by the direct C publisher.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn selected_v1(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        match self.selected_owner(binding, check)? {
            SelectedOwner::Legacy { state } => Ok(state),
            SelectedOwner::Paged { .. } => {
                Err("V2 selected owner refuses legacy worker and legacy publication".into())
            }
        }
    }
    fn records(
        &self,
        state: &VerifiedState,
        closure: &LegacyRecordClosure,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<Vec<u8>>> {
        OwnerLeaf::V1 {
            state: state.clone(),
            records: closure.clone(),
            migration_prefix: None,
        }
        .validate(&state.binding.installation, &self.descriptor.legacy)?;
        let (_, legacy) = self.legacy(check)?;
        let mut records = legacy
            .records
            .get(&owner_key(&state.binding)?)
            .cloned()
            .unwrap_or_default();
        if records.len() as u64 != closure.legacy_owner_record_count {
            return Err("tagged V1 baseline record count changed".into());
        }
        let mut next = closure.latest_suffix.clone();
        let mut nodes = Vec::new();
        for expected in (1..=closure.suffix_count).rev() {
            check()?;
            let reference = next.ok_or("V1 record chain ends before selected count")?;
            reference.validate()?;
            let bytes = self.pages.read_record(&reference.sha256, check)?;
            if bytes.len() as u64 != reference.bytes {
                return Err("V1 record chain object length differs".into());
            }
            let node: RecordNode = canonical(&bytes, super::paged::FILE_BYTES)?;
            let held = node.publication.validate()?;
            if node.schema_version != 3
                || node.binding != state.binding
                || node.legacy_journal_sha256 != closure.legacy_journal_sha256
                || node.sequence != expected
                || held.binding != state.binding
                || held.base_outcome_count != closure.legacy_owner_record_count + expected - 1
            {
                return Err(
                    "V1 selected immutable record chain is discontinuous/cross-owner".into(),
                );
            }
            next = node.previous.clone();
            nodes.push(node);
        }
        if next.is_some() {
            return Err("V1 record chain has an unselected predecessor".into());
        }
        for node in nodes.into_iter().rev() {
            let held = node.publication.validate()?;
            let before =
                luma_content_store::canonical_record_history_head(&state.binding, &records)?;
            if before != held.base_head_sha256 {
                return Err("V1 record chain does not extend actual canonical baseline".into());
            }
            records.push(node.publication.record.into_bytes());
            if luma_content_store::canonical_record_history_head(&state.binding, &records)?
                != held.outcome_head_sha256
            {
                return Err("V1 record chain canonical history extension differs".into());
            }
        }
        if luma_content_store::canonical_record_history_head(&state.binding, &records)?
            != state.head_sha256
        {
            return Err("selected V1 head is not exact retained canonical record closure".into());
        }
        check()?;
        Ok(records)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn publication_history(
        &self,
        binding: &OwnerBinding,
        closure: &LegacyRecordClosure,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<Publication>> {
        let (journal, _) = self.legacy(check)?;
        let mut result = Vec::new();
        for event in journal.events {
            let entry = match event {
                Event::Publication(value) => Some(value),
                Event::RestorePublication(value) => Some(value.entry),
                _ => None,
            };
            if let Some(entry) = entry {
                if entry.validate()?.binding == *binding {
                    result.push(entry);
                }
            }
        }
        let mut next = closure.latest_suffix.clone();
        let mut suffix = Vec::new();
        for sequence in (1..=closure.suffix_count).rev() {
            let reference = next.ok_or("V1 publication suffix missing")?;
            let bytes = self.pages.read_record(&reference.sha256, check)?;
            if bytes.len() as u64 != reference.bytes {
                return Err("V1 publication suffix length differs".into());
            }
            let node: RecordNode = canonical(&bytes, super::paged::FILE_BYTES)?;
            if node.schema_version != 3
                || node.binding != *binding
                || node.sequence != sequence
                || node.legacy_journal_sha256 != closure.legacy_journal_sha256
            {
                return Err("V1 publication suffix binding/order differs".into());
            }
            node.publication.validate()?;
            next = node.previous;
            suffix.push(node.publication);
        }
        if next.is_some() {
            return Err("V1 publication suffix contains hidden prefix".into());
        }
        result.extend(suffix.into_iter().rev());
        if result.len() > 256 {
            return Err("V1 canonical publication history bound exceeded".into());
        }
        Ok(result)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn exact_v1_authority(
        &mut self,
        held: &HeldPublication,
        authority: &mut OriginalCOperation<'_>,
    ) -> Result<()> {
        self.descriptor.phase.require_ready()?;
        authority.check()?;
        let source = authority.source_binding();
        let audit = authority.audit();
        audit.validate()?;
        if source.purpose != SourcePurpose::Publish
            || source.binding != held.binding
            || audit.subject != held.binding.owner
            || audit.subject_generation != held.binding.owner_generation
            || audit.operation_id.is_none()
            || audit.usage
                != crate::content_governed::custody_usage(
                    &source.profile,
                    &source.storage_device,
                    &held.binding,
                    &held.review_sha256,
                )?
        {
            return Err(
                "paged publication is not the exact original live owner/source/finite effect"
                    .into(),
            );
        }
        self.live(&mut || authority.check())
    }

    #[allow(dead_code)]
    pub(crate) fn preparation_cut_v1(
        &mut self,
        binding: &OwnerBinding,
        request_id: &str,
        review: &str,
        authority: &mut OriginalCOperation<'_>,
    ) -> Result<PreparationCut> {
        let source = authority.source_binding();
        let audit = authority.audit();
        audit.validate()?;
        if !matches!(
            source.purpose,
            SourcePurpose::PreparationCut | SourcePurpose::Publish
        ) || source.binding != *binding
            || audit.subject != binding.owner
            || audit.subject_generation != binding.owner_generation
            || audit.operation_id.is_none()
            || audit.usage
                != crate::content_governed::custody_usage(
                    &source.profile,
                    &source.storage_device,
                    binding,
                    review,
                )?
        {
            return Err("paged preparation cut lacks exact original finite owner operation".into());
        }
        let current = self.selected_v1(binding, &mut || authority.check())?;
        let leaf = self.owner_leaf(binding, &mut || authority.check())?;
        let mut prior_base = None;
        if let Some(OwnerLeaf::V1 {
            records,
            migration_prefix,
            ..
        }) = leaf
        {
            if migration_prefix.is_some() {
                return Err(
                    "V1 mutation is fenced by an exact C-selected owner migration prefix".into(),
                );
            }
            for entry in self.publication_history(binding, &records, &mut || authority.check())? {
                let held = entry.validate()?;
                if held.request_id == request_id {
                    if held.review_sha256 != review
                        || entry.profile != authority.source_binding().profile
                        || entry.storage_device != authority.source_binding().storage_device
                        || entry.original_authority.usage != authority.audit().usage
                    {
                        return Err("paged retry substitutes source/request/review".into());
                    }
                    if held.outcome() == current {
                        prior_base = Some(held.base());
                    }
                }
            }
        }
        self.live(&mut || authority.check())?;
        Ok(PreparationCut {
            current,
            prior_base,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn publish_v1(
        &mut self,
        commitment: &[u8],
        record: &[u8],
        authority: &mut OriginalCOperation<'_>,
    ) -> Result<VerifiedState> {
        let held = HeldPublication::parse(commitment)?;
        self.exact_v1_authority(&held, authority)?;
        let leaf = self.owner_leaf(&held.binding, &mut || authority.check())?;
        let (current, closure) = match leaf {
            Some(OwnerLeaf::V1 {
                state,
                records,
                migration_prefix,
            }) => {
                if migration_prefix.is_some() {
                    return Err(
                        "V1 publication cannot bypass an active C-selected owner migration".into(),
                    );
                }
                (state, records)
            }
            Some(OwnerLeaf::V2 { .. }) => {
                return Err("V2 owner cannot be rewritten with V1 publication".into())
            }
            None => (
                VerifiedState::empty(&held.binding)?,
                LegacyRecordClosure {
                    legacy_journal_sha256: self.descriptor.legacy.journal_sha256.clone(),
                    legacy_owner_record_count: 0,
                    latest_suffix: None,
                    suffix_count: 0,
                },
            ),
        };
        let history =
            self.publication_history(&held.binding, &closure, &mut || authority.check())?;
        if let Some(prior) = history.iter().find(|entry| {
            entry
                .validate()
                .is_ok_and(|h| h.request_id == held.request_id)
        }) {
            let original = prior.validate()?;
            if current != held.outcome()
                || original.review_sha256 != held.review_sha256
                || original.decision != held.decision
                || original.resulting != held.resulting
                || prior.record.as_bytes() != record
                || prior.original_authority.usage != authority.audit().usage
                || original
                    .members
                    .iter()
                    .zip(&held.members)
                    .any(|(a, b)| a.name != b.name || a.bytes != b.bytes || a.sha256 != b.sha256)
            {
                return Err("paged V1 retry substitutes protected immutable publication".into());
            }
            self.live(&mut || authority.check())?;
            return Ok(current);
        }
        if held.already_published || current != held.base() {
            return Err("paged V1 append does not extend exact selected owner".into());
        }
        let publication = Publication {
            schema_version: 1,
            purpose: "luma-content-custody-publication-v1".into(),
            commitment: std::str::from_utf8(commitment)?.into(),
            record: std::str::from_utf8(record)?.into(),
            profile: authority.source_binding().profile.clone(),
            storage_device: authority.source_binding().storage_device.clone(),
            original_authority: authority.audit().clone(),
        };
        publication.validate()?;
        let semantic = self.verify_typed_event(
            Event::Publication(publication.clone()),
            &mut COperation::Worker(authority),
        )?;
        if semantic.base != self.selected
            || semantic.binding.as_ref() != Some(&held.binding)
            || semantic.state.owners.get(&owner_key(&held.binding)?) != Some(&held.outcome())
        {
            return Err(
                "paged append lost independently reconstructed original event/base/outcome".into(),
            );
        }
        let sequence = closure
            .suffix_count
            .checked_add(1)
            .ok_or("V1 suffix overflow")?;
        if sequence > SUFFIX_LIMIT {
            return Err("V1 suffix limit remains unchanged; use explicit owner migration".into());
        }
        let node = RecordNode {
            schema_version: 3,
            binding: held.binding.clone(),
            legacy_journal_sha256: closure.legacy_journal_sha256.clone(),
            sequence,
            previous: closure.latest_suffix.clone(),
            publication,
        };
        let bytes = serde_json::to_vec(&node)?;
        self.pages
            .admit_writes(16 * 1024 * 1024, 16, 8, &mut || authority.check())?;
        let record_sha = self.pages.write_record(&bytes, &mut || authority.check())?;
        let reference = RecordRef {
            sha256: record_sha,
            bytes: bytes.len() as u64,
        };
        let next_leaf = OwnerLeaf::V1 {
            state: held.outcome(),
            migration_prefix: None,
            records: LegacyRecordClosure {
                latest_suffix: Some(reference.clone()),
                suffix_count: sequence,
                ..closure
            },
        };
        next_leaf.validate(&held.binding.installation, &self.descriptor.legacy)?;
        let root = self.descriptor.roots.owners.clone();
        let literal = owner_key(&held.binding)?;
        let before = self.value(&root, literal.as_bytes(), &mut || authority.check())?;
        let edits = [map::Edit {
            key: root.key(literal.as_bytes())?,
            expected_value_sha256: before.as_ref().map(|v| hash(v)),
            value: Some(serde_json::to_vec(&next_leaf)?),
        }];
        let context = self.context(Some(held.review_sha256.clone()));
        let next_root = map::prepare_update(
            &root,
            &edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 64 * 1024 * 1024,
                new_files: 8192,
            },
            &mut WriteIo {
                store: self,
                authority,
            },
        )?;
        map::verify_update(
            &root,
            &next_root,
            &edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut ReadIo {
                store: self,
                check: &mut || authority.check(),
            },
        )?;
        let mut roots = self.descriptor.roots.clone();
        roots.owners = next_root;
        let next = Descriptor {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: self.descriptor.binding.clone(),
            sequence: self
                .descriptor
                .sequence
                .checked_add(1)
                .ok_or("C descriptor sequence overflow")?,
            global_ordinal: self
                .descriptor
                .global_ordinal
                .checked_add(1)
                .ok_or("C ordinal overflow")?,
            previous_descriptor_sha256: Some(self.selected.descriptor_sha256.clone()),
            previous_nv_head: self.selected.nv_head.clone(),
            event_sha256: String::new(),
            selected_nv_head: String::new(),
            legacy: self.descriptor.legacy.clone(),
            roots,
            phase: self.descriptor.phase.clone(),
            storage: self.descriptor.storage.clone(),
            operation: OperationData::V1Publication {
                binding: held.binding.clone(),
                request_sha256: authority.source_binding().request_sha256.clone(),
                source_sha256: semantic.source_sha256,
                event: reference,
                original_authority: authority.audit().clone(),
            },
        }
        .seal()?;
        self.commit_verified(
            VerifiedSemanticDelta {
                base: self.selected.clone(),
                next,
            },
            &mut COperation::Worker(authority),
        )?;
        Ok(held.outcome())
    }

    fn commit_verified(
        &mut self,
        delta: VerifiedSemanticDelta,
        authority: &mut COperation<'_, '_>,
    ) -> Result<()> {
        self.live(&mut || authority.check())?;
        if delta.base != self.selected {
            return Err("prepared semantic delta no longer extends actual selected C cut".into());
        }
        let next_selector = Selector::for_descriptor(&delta.next)?;
        let attempt = hash(&serde_json::to_vec(&(
            "luma-paged-c-attempt-v3",
            &self.selected,
            &next_selector,
            authority.audit(),
            authority.source_bytes()?,
        ))?);
        let pending = Pending {
            schema_version: 3,
            attempt: attempt.clone(),
            base: self.selected.clone(),
            next: next_selector.clone(),
            event_sha256: delta.next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&delta.next.operation)?),
        };
        pending.validate_descriptors(&self.descriptor, &delta.next)?;
        self.pages
            .admit_writes(16 * 1024 * 1024, 16, 8, &mut || authority.check())?;
        self.pages
            .create_attempt(&attempt, &mut || authority.check())?;
        let prefix = format!("attempts/{attempt}");
        for (name, bytes) in [
            (
                "base.json",
                BaseSnapshot::Paged {
                    descriptor: self.descriptor.clone(),
                }
                .bytes()?,
            ),
            ("next.json", delta.next.bytes()?),
            ("prepared.json", pending.bytes()?),
            ("selector.json", next_selector.bytes()?),
            (
                "dispatch.json",
                serde_json::to_vec(&(
                    "luma-paged-c-single-dispatch-intent-v3",
                    hash(&pending.bytes()?),
                ))?,
            ),
        ] {
            self.pages
                .create_member(&format!("{prefix}/{name}"), &bytes, &mut || {
                    authority.check()
                })?;
        }
        if self
            .pages
            .write_page(&delta.next.bytes()?, &mut || authority.check())?
            != next_selector.descriptor_sha256
        {
            return Err("staged descriptor hash differs before NV".into());
        }
        self.pages
            .create_member("pending.json", &pending.bytes()?, &mut || authority.check())?;
        // No call on this object can redispatch after this point, irrespective
        // of whether the sole extend failed before/after reaching the TPM.
        self.poisoned = true;
        authority.check()?;
        if self.anchor.read()? != tpm::decode(&pending.base.nv_head)?
            || self
                .pages
                .read("selected.json", 4096, &mut || authority.check())?
                != pending.base.bytes()?
            || self
                .pages
                .read("pending.json", CONTROL_BYTES, &mut || authority.check())?
                != pending.bytes()?
            || self
                .pages
                .read(&format!("{prefix}/base.json"), CONTROL_BYTES, &mut || {
                    authority.check()
                })?
                != (BaseSnapshot::Paged {
                    descriptor: self.descriptor.clone(),
                })
                .bytes()?
            || self.pages.read(
                &format!("{prefix}/prepared.json"),
                CONTROL_BYTES,
                &mut || authority.check(),
            )? != pending.bytes()?
            || self
                .pages
                .read(&format!("{prefix}/dispatch.json"), 4096, &mut || {
                    authority.check()
                })?
                != serde_json::to_vec(&(
                    "luma-paged-c-single-dispatch-intent-v3",
                    hash(&pending.bytes()?),
                ))?
            || self
                .pages
                .read(&format!("{prefix}/next.json"), PAGE_BYTES, &mut || {
                    authority.check()
                })?
                != delta.next.bytes()?
            || self
                .pages
                .read(&format!("{prefix}/selector.json"), 4096, &mut || {
                    authority.check()
                })?
                != next_selector.bytes()?
        {
            return Err("preallocated C publication changed before sole dispatch".into());
        }
        authority.check()?;
        let expected = tpm::decode(&next_selector.nv_head)?;
        if self.anchor.advance(
            tpm::decode(&pending.base.nv_head)?,
            delta.next.event_digest()?,
        )? != expected
        {
            return Err("paged C dispatch returned a different selected NV head".into());
        }
        authority.check()?;
        self.pages.rename(
            &format!("{prefix}/selector.json"),
            "selected.json",
            true,
            &mut || authority.check(),
        )?;
        if self
            .pages
            .read("selected.json", 4096, &mut || authority.check())?
            != next_selector.bytes()?
            || self.anchor.read()? != expected
        {
            return Err("paged C publication readback differs after sole dispatch".into());
        }
        self.pages.rename(
            "pending.json",
            &format!("{prefix}/completed.json"),
            false,
            &mut || authority.check(),
        )?;
        if self.pages.read(
            &format!("{prefix}/completed.json"),
            CONTROL_BYTES,
            &mut || authority.check(),
        )? != pending.bytes()?
        {
            return Err("paged C terminal stage readback differs".into());
        }
        self.selected = next_selector;
        self.descriptor = delta.next;
        self.poisoned = false;
        self.live(&mut || authority.check())
    }
}

struct ReadIo<'a, A: Checkpoint, F: FnMut() -> Result<()>> {
    store: &'a mut PagedStore<A>,
    check: &'a mut F,
}
impl<A: Checkpoint, F: FnMut() -> Result<()>> map::CustodyIo for ReadIo<'_, A, F> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if budget.write_bytes != 0 || budget.new_files != 0 {
            return Err("C read adapter cannot admit writes".into());
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        if context != &self.store.context(context.review_sha256.clone()) {
            return Err("C map callback selection context changed".into());
        }
        self.store.live(self.check)
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("C page read bound changed".into());
        }
        self.store.pages.read_page(sha, self.check)
    }
    fn write_page(&mut self, _: &map::Context, _: &[u8]) -> Result<()> {
        Err("readonly C adapter refuses page effects".into())
    }
}

struct WriteIo<'a, 'b, 'c, A: Checkpoint> {
    store: &'a mut PagedStore<A>,
    authority: &'b mut OriginalCOperation<'c>,
}
impl<A: Checkpoint> map::CustodyIo for WriteIo<'_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        self.check_current(context)?;
        if context.review_sha256.is_none() {
            return Err("native C write requires exact original reviewed operation".into());
        }
        self.store.pages.admit_writes(
            256 * 1024 * 1024,
            u64::from(budget.new_files) + 16,
            65536,
            &mut || self.authority.check(),
        )
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        self.authority.check()?;
        if context != &self.store.context(context.review_sha256.clone()) {
            return Err("native C write selection context changed".into());
        }
        let source = self.authority.source_binding();
        let review = context
            .review_sha256
            .as_deref()
            .ok_or("native C write has no exact review")?;
        if source.purpose != SourcePurpose::Publish
            || self.authority.audit().usage
                != crate::content_governed::custody_usage(
                    &source.profile,
                    &source.storage_device,
                    &source.binding,
                    review,
                )?
        {
            return Err(
                "native C callback review/source differs from actual original finite grant".into(),
            );
        }
        self.store.live(&mut || self.authority.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("native C read bound changed".into());
        }
        self.store
            .pages
            .read_page(sha, &mut || self.authority.check())
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        self.store
            .pages
            .write_page(bytes, &mut || self.authority.check())?;
        self.check_current(context)
    }
}

struct AdminWriteIo<'a, 'b, 'c, A: Checkpoint> {
    store: &'a mut PagedStore<A>,
    authority: &'b mut OriginalCAdminOperation<'c>,
}
impl<A: Checkpoint> map::CustodyIo for AdminWriteIo<'_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        self.check_current(context)?;
        self.store.pages.admit_writes(
            256 * 1024 * 1024,
            u64::from(budget.new_files) + 16,
            65536,
            &mut || self.authority.check(),
        )
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        self.authority.check()?;
        let source = self.authority.source_binding();
        super::admin_scope(&source.command, &source.usage)?;
        if context != &self.store.context(context.review_sha256.clone())
            || source.installation != self.store.descriptor.binding.installation
            || source.usage != self.authority.audit().usage
            || context.review_sha256.as_deref() != Some(source.usage.selector.digest.as_str())
        {
            return Err("paged Admin map callback differs from actual original installation/source/review/scope".into());
        }
        self.store.live(&mut || self.authority.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("paged Admin page bound changed".into());
        }
        self.store
            .pages
            .read_page(sha, &mut || self.authority.check())
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        self.store
            .pages
            .write_page(bytes, &mut || self.authority.check())?;
        self.check_current(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn audit() -> Audit {
        use crate::finite_grants::{Action, Kind, Selector, Use};
        Audit {
            subject: "22".repeat(32),
            subject_generation: 1,
            grant_id: "paged-data-fixture".into(),
            grant_version: 1,
            checkpoint_head: "33".repeat(32),
            operation_id: Some("11".repeat(16)),
            usage: Use {
                action: Action::ProvisionResource,
                selector: Selector {
                    kind: Kind::Resource,
                    id: "content-custody-paged-bootstrap-v3".into(),
                    generation: 1,
                    digest: "44".repeat(32),
                },
                input_bytes: 0,
                output_bytes: 8192,
                units: 1,
            },
        }
    }
    pub(super) fn initial() -> Descriptor {
        let binding = map::CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "55".repeat(32),
        };
        let journal = Journal::empty(
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256).unwrap(),
        )
        .unwrap();
        let legacy = LegacyCut {
            journal_sha256: hash(&journal.bytes().unwrap()),
            journal_bytes: journal.bytes().unwrap().len() as u64,
            events: 0,
            nv_head: bundle::hex(&journal.validate().unwrap().checkpoint),
        };
        let phase = bootstrap::Blueprint::verified_legacy(&binding, &legacy, &journal)
            .unwrap()
            .initial_phase()
            .unwrap();
        Descriptor {
            schema_version: 3,
            domain: DOMAIN.into(),
            roots: Roots::empty(&binding).unwrap(),
            binding,
            sequence: 1,
            global_ordinal: 2,
            previous_descriptor_sha256: None,
            previous_nv_head: legacy.nv_head.clone(),
            event_sha256: String::new(),
            selected_nv_head: String::new(),
            phase: phase.clone(),
            storage: None,
            legacy,
            operation: OperationData::BootstrapProgress {
                previous_retirement: None,
                review_sha256: phase.review_sha256,
                window_intent_sha256: "44".repeat(32),
                request_sha256: "66".repeat(32),
                source_sha256: "77".repeat(32),
                original_authority: audit(),
            },
        }
        .seal()
        .unwrap()
    }
    fn successor(base: &Descriptor) -> Descriptor {
        let selected = Selector::for_descriptor(base).unwrap();
        Descriptor {
            sequence: 2,
            global_ordinal: 3,
            previous_descriptor_sha256: Some(selected.descriptor_sha256),
            previous_nv_head: selected.nv_head,
            phase: bootstrap::Phase {
                state: bootstrap::State::Ready,
                ..base.phase.clone()
            },
            operation: OperationData::BootstrapProgress {
                previous_retirement: None,
                review_sha256: base.phase.review_sha256.clone(),
                window_intent_sha256: "44".repeat(32),
                request_sha256: "66".repeat(32),
                source_sha256: "77".repeat(32),
                original_authority: audit(),
            },
            ..base.clone()
        }
        .seal()
        .unwrap()
    }
    #[test]
    fn descriptor_counts_every_actual_nv_extension_and_joins_all_seven_roles() {
        let first = initial();
        first.validate().unwrap();
        assert_eq!(first.global_ordinal, 2);
        let second = successor(&first);
        assert_eq!(second.global_ordinal, 3);
        assert_eq!(
            tpm::decode::<32>(&second.selected_nv_head).unwrap(),
            tpm::extend_value(
                tpm::decode(&first.selected_nv_head).unwrap(),
                second.event_digest().unwrap()
            )
        );
        let mut bad = second.clone();
        bad.global_ordinal += 1;
        assert!(bad.validate().is_err());
        let mut bad = second.clone();
        bad.roots.signers = bad.roots.recipients.clone();
        assert!(bad.validate().is_err());
        let mut bad = second.clone();
        bad.binding.sealed_genesis_sha256 = "99".repeat(32);
        assert!(bad.validate().is_err());
        let mut bad = first.clone();
        bad.previous_nv_head = "99".repeat(32);
        assert!(bad.seal().is_err());
    }
    #[test]
    fn event_preimage_excludes_selected_nv_but_not_operation_roots_or_base() {
        let first = initial();
        let second = successor(&first);
        let event = second.event_digest().unwrap();
        let mut changed = second.clone();
        changed.selected_nv_head = "aa".repeat(32);
        changed.event_sha256 = "bb".repeat(32);
        assert_eq!(event, changed.event_digest().unwrap());
        assert!(changed.validate().is_err());
        let mut changed = second.clone();
        changed.previous_nv_head = "cc".repeat(32);
        assert_ne!(event, changed.event_digest().unwrap());
        let mut changed = second.clone();
        if let OperationData::BootstrapProgress { source_sha256, .. } = &mut changed.operation {
            *source_sha256 = "dd".repeat(32);
        }
        assert_ne!(event, changed.event_digest().unwrap());
    }
    #[test]
    fn pending_is_exact_one_descriptor_and_never_a_dispatch_success_receipt() {
        let base = initial();
        let next = successor(&base);
        let pending = Pending {
            schema_version: 3,
            attempt: "aa".repeat(32),
            base: Selector::for_descriptor(&base).unwrap(),
            next: Selector::for_descriptor(&next).unwrap(),
            event_sha256: next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&next.operation).unwrap()),
        };
        pending.validate_descriptors(&base, &next).unwrap();
        let mut bad = pending.clone();
        bad.base.nv_head = "bb".repeat(32);
        assert!(bad.bytes().is_err());
        let mut bad = pending.clone();
        bad.next = bad.base.clone();
        assert!(bad.bytes().is_err());
        let mut bad = pending.clone();
        bad.operation_sha256 = "cc".repeat(32);
        assert!(bad.validate_descriptors(&base, &next).is_err());
        let mut bad = next.clone();
        bad.legacy.journal_sha256 = "dd".repeat(32);
        let bad = bad.seal().unwrap();
        assert!(pending.validate_descriptors(&base, &bad).is_err());
    }
    #[test]
    fn initial_prepare_retains_real_legacy_base_and_cannot_adopt_a_fabricated_paged_cut() {
        let next = initial();
        let base = BaseSnapshot::Legacy {
            binding: next.binding.clone(),
            cut: next.legacy.clone(),
        };
        let pending = Pending {
            schema_version: 3,
            attempt: "aa".repeat(32),
            base: base.selector().unwrap(),
            next: Selector::for_descriptor(&next).unwrap(),
            event_sha256: next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&next.operation).unwrap()),
        };
        pending.validate_base(&base, &next).unwrap();
        assert_eq!(pending.base.schema_version, 1);
        let fabricated = BaseSnapshot::Paged {
            descriptor: next.clone(),
        };
        assert!(pending.validate_base(&fabricated, &next).is_err());
        let mut changed = next.clone();
        changed.phase.copied_entries = 1;
        assert!(pending.validate_base(&base, &changed).is_err());
        let mut changed = base.clone();
        if let BaseSnapshot::Legacy { cut, .. } = &mut changed {
            cut.nv_head = "ee".repeat(32);
        }
        assert!(pending.validate_base(&changed, &next).is_err());
        let mut changed = next.clone();
        changed.phase.state = bootstrap::State::Ready;
        assert!(changed.seal().is_err());
    }
    #[test]
    fn ordinary_publication_cannot_bypass_pending_phase_or_reset_completed_provenance() {
        let pending = initial();
        let ready = successor(&pending);
        let ordinary = OperationData::V1Publication {
            binding: OwnerBinding {
                installation: pending.binding.installation.clone(),
                owner: "22".repeat(32),
                owner_generation: 1,
            },
            request_sha256: "66".repeat(32),
            source_sha256: "77".repeat(32),
            event: RecordRef {
                sha256: "88".repeat(32),
                bytes: 100,
            },
            original_authority: audit(),
        };
        let mut bad = pending.clone();
        bad.operation = ordinary.clone();
        assert!(bad.seal().is_err());
        let mut next = Descriptor {
            sequence: 3,
            global_ordinal: 4,
            previous_descriptor_sha256: Some(
                Selector::for_descriptor(&ready).unwrap().descriptor_sha256,
            ),
            previous_nv_head: ready.selected_nv_head.clone(),
            operation: ordinary,
            ..ready.clone()
        };
        next = next.seal().unwrap();
        let cut = Pending {
            schema_version: 3,
            attempt: "aa".repeat(32),
            base: Selector::for_descriptor(&ready).unwrap(),
            next: Selector::for_descriptor(&next).unwrap(),
            event_sha256: next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&next.operation).unwrap()),
        };
        cut.validate_descriptors(&ready, &next).unwrap();
        next.phase.review_sha256 = "ee".repeat(32);
        let next = next.seal().unwrap();
        let changed = Pending {
            next: Selector::for_descriptor(&next).unwrap(),
            event_sha256: next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&next.operation).unwrap()),
            ..cut
        };
        assert!(changed.validate_descriptors(&ready, &next).is_err());
    }
    #[test]
    fn canonical_control_data_rejects_duplicate_unknown_or_trailing_fields() {
        let descriptor = initial();
        let bytes = descriptor.bytes().unwrap();
        assert_eq!(
            canonical::<Descriptor>(&bytes, PAGE_BYTES).unwrap(),
            descriptor
        );
        let mut trailing = bytes.clone();
        trailing.push(b'\n');
        assert!(canonical::<Descriptor>(&trailing, PAGE_BYTES).is_err());
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen(
            "\"schema_version\":3",
            "\"schema_version\":3,\"schema_version\":3",
            1,
        );
        assert!(canonical::<Descriptor>(duplicate.as_bytes(), PAGE_BYTES).is_err());
        let unknown = text.replacen(
            "\"schema_version\":3",
            "\"schema_version\":3,\"authority\":true",
            1,
        );
        assert!(canonical::<Descriptor>(unknown.as_bytes(), PAGE_BYTES).is_err());
    }
    #[test]
    fn tagged_v1_record_closure_cannot_lose_legacy_count_or_be_a_v2_owner() {
        let descriptor = initial();
        let binding = OwnerBinding {
            installation: descriptor.binding.installation.clone(),
            owner: "22".repeat(32),
            owner_generation: 1,
        };
        let state = VerifiedState::empty(&binding).unwrap();
        let closure = LegacyRecordClosure {
            legacy_journal_sha256: descriptor.legacy.journal_sha256.clone(),
            legacy_owner_record_count: 0,
            latest_suffix: None,
            suffix_count: 0,
        };
        let leaf = OwnerLeaf::V1 {
            state: state.clone(),
            records: closure.clone(),
            migration_prefix: None,
        };
        leaf.validate(&binding.installation, &descriptor.legacy)
            .unwrap();
        let mut changed = closure.clone();
        changed.suffix_count = 1;
        assert!(OwnerLeaf::V1 {
            state: state.clone(),
            records: changed,
            migration_prefix: None,
        }
        .validate(&binding.installation, &descriptor.legacy)
        .is_err());
        let mut changed = closure;
        changed.legacy_journal_sha256 = "aa".repeat(32);
        assert!(OwnerLeaf::V1 {
            state,
            records: changed,
            migration_prefix: None,
        }
        .validate(&binding.installation, &descriptor.legacy)
        .is_err());
    }
}
