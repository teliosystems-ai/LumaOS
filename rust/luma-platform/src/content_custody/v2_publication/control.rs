//! Bounded permanently allocated control-cell DATA. A caller must obtain the
//! actual NV from the existing held ContentAnchor and retain fresh original
//! authorization; neither these bytes nor this matcher creates authority.
use super::super::paged::slots::SealedReference;
use super::*;

const DOMAIN: &str = "luma-c-direct-slot-control-v3";
const MAGIC: &[u8] = b"LUMACCTRLv3!\n";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Cell {
    Empty {
        schema_version: u32,
        domain: String,
        binding: map::CustodyBinding,
    },
    Selected {
        schema_version: u32,
        domain: String,
        binding: map::CustodyBinding,
        ordinal: u64,
        nv_head: String,
        descriptor: SealedReference,
    },
}
impl Cell {
    pub fn empty_data(binding: &map::CustodyBinding) -> Result<Self> {
        binding.validate()?;
        Ok(Self::Empty {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: binding.clone(),
        })
    }
    fn binding(&self) -> &map::CustodyBinding {
        match self {
            Self::Empty { binding, .. } | Self::Selected { binding, .. } => binding,
        }
    }
    fn validate(&self) -> Result<()> {
        self.binding().validate()?;
        match self {
            Self::Empty {
                schema_version,
                domain,
                ..
            } => {
                if *schema_version != 3 || domain != DOMAIN {
                    return Err("invalid empty control-cell DATA".into());
                }
            }
            Self::Selected {
                schema_version,
                domain,
                ordinal,
                nv_head,
                descriptor,
                ..
            } => {
                descriptor.validate_data()?;
                digest(nv_head)?;
                if *schema_version != 3
                    || domain != DOMAIN
                    || *ordinal == 0
                    || descriptor.bytes != PAGE_BYTES as u64
                    || descriptor.slot.kind != super::super::paged::slots::Kind::Page
                {
                    return Err("invalid direct-slot selector DATA".into());
                }
            }
        }
        Ok(())
    }
    pub fn frame(&self) -> Result<Vec<u8>> {
        self.validate()?;
        frame(self)
    }
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_frame(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn for_descriptor(descriptor: &Descriptor, reference: SealedReference) -> Result<Self> {
        let storage = descriptor
            .storage
            .as_ref()
            .ok_or("descriptor has no selected direct-slot storage field")?;
        descriptor.validate()?;
        reference.validate_data()?;
        let frame = descriptor.slot_frame()?;
        if storage.descriptor_slot != reference.slot
            || reference.sha256 != hash(&frame)
            || reference.bytes != frame.len() as u64
        {
            return Err("selector does not reference the exact C-event-bound self slot and complete descriptor frame".into());
        }
        let value = Self::Selected {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: descriptor.binding.clone(),
            ordinal: descriptor.global_ordinal,
            nv_head: descriptor.selected_nv_head.clone(),
            descriptor: reference,
        };
        value.validate()?;
        Ok(value)
    }
}

fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    let start = MAGIC.len() + 4;
    if bytes.is_empty() || bytes.len() > CONTROL_BYTES - start {
        return Err("control-cell data exceeds its fixed allocation".into());
    }
    let mut result = vec![0_u8; CONTROL_BYTES];
    result[..MAGIC.len()].copy_from_slice(MAGIC);
    result[MAGIC.len()..start].copy_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    result[start..start + bytes.len()].copy_from_slice(&bytes);
    Ok(result)
}
fn parse_frame<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8]) -> Result<T> {
    let start = MAGIC.len() + 4;
    if bytes.len() != CONTROL_BYTES || &bytes[..MAGIC.len()] != MAGIC {
        return Err("control-cell frame has wrong fixed size or profile".into());
    }
    let length = u32::from_be_bytes(bytes[MAGIC.len()..start].try_into()?) as usize;
    if length == 0
        || length > CONTROL_BYTES - start
        || bytes[start + length..].iter().any(|n| *n != 0)
    {
        return Err("control-cell frame is partial or has nonzero tail bytes".into());
    }
    canonical(&bytes[start..start + length], CONTROL_BYTES)
}

pub(super) trait Reader {
    fn check(&mut self) -> Result<()>;
    fn read_descriptor(&mut self, reference: &SealedReference) -> Result<Vec<u8>>;
    fn read_descriptor_original(
        &mut self,
        reference: &SealedReference,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>>;
}
/// Pure proof matching, not a ContentAnchor or permission token. Exactly one
/// of the TWO closed selector cells must match the actual provided NV. Missing,
/// damaged, duplicate-current and both-empty states fail rather than fall back.
pub(super) fn select(
    binding: &map::CustodyBinding,
    actual_nv: [u8; 32],
    cells: [&Cell; 2],
    reader: &mut impl Reader,
) -> Result<(usize, Descriptor)> {
    select_checked(binding, actual_nv, cells, reader, None)
}
fn select_checked(
    binding: &map::CustodyBinding,
    actual_nv: [u8; 32],
    cells: [&Cell; 2],
    reader: &mut impl Reader,
    mut original: Option<&mut COperation<'_, '_>>,
) -> Result<(usize, Descriptor)> {
    binding.validate()?;
    if let Some(original) = original.as_deref_mut() {
        original.check()?;
    }
    reader.check()?;
    let nv = bundle::hex(&actual_nv);
    digest(&nv)?;
    let mut current = None;
    for (index, cell) in cells.iter().enumerate() {
        cell.validate()?;
        if cell.binding() != binding {
            return Err("selector cells cross the independently sealed C binding".into());
        }
        if let Cell::Selected { nv_head, .. } = cell {
            if nv_head == &nv {
                if current.replace(index).is_some() {
                    return Err(
                        "both selector cells claim current C; preserve ambiguous controls".into(),
                    );
                }
            }
        }
    }
    let index = current.ok_or(
        "neither closed selector cell matches actual C; no empty or old-journal authority",
    )?;
    let Cell::Selected {
        ordinal,
        nv_head,
        descriptor: reference,
        ..
    } = cells[index]
    else {
        return Err("selected control unexpectedly empty".into());
    };
    reader.check()?;
    let bytes = match original.as_deref_mut() {
        Some(original) => reader.read_descriptor_original(reference, original)?,
        None => reader.read_descriptor(reference)?,
    };
    if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
        return Err("current selector descriptor is incomplete or hash-substituted".into());
    }
    let descriptor = Descriptor::from_slot_frame(&bytes)?;
    if descriptor.binding != *binding
        || descriptor.global_ordinal != *ordinal
        || descriptor.selected_nv_head != *nv_head
        || descriptor
            .storage
            .as_ref()
            .ok_or("direct descriptor lost storage proof")?
            .descriptor_slot
            != reference.slot
    {
        return Err(
            "actual NV selector does not bind full typed descriptor and its own preallocated slot"
                .into(),
        );
    }
    reader.check()?;
    if let Some(original) = original.as_deref_mut() {
        original.check()?;
    }
    Ok((index, descriptor))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Base {
    Legacy {
        binding: map::CustodyBinding,
        cut: LegacyCut,
    },
    Slot {
        index: u8,
        cell: Cell,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingCell {
    pub schema_version: u32,
    pub domain: String,
    pub binding: map::CustodyBinding,
    pub base: Base,
    pub inactive_index: u8,
    pub next: Cell,
    pub event_sha256: String,
    pub operation_sha256: String,
}
impl PendingCell {
    pub fn frame(&self) -> Result<Vec<u8>> {
        self.validate_data()?;
        frame(self)
    }
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_frame(bytes)?;
        value.validate_data()?;
        Ok(value)
    }
    fn validate_data(&self) -> Result<()> {
        self.binding.validate()?;
        self.next.validate()?;
        digest(&self.event_sha256)?;
        digest(&self.operation_sha256)?;
        if self.schema_version != 3
            || self.domain != "luma-c-direct-slot-pending-v3"
            || self.inactive_index > 1
            || self.next.binding() != &self.binding
        {
            return Err("invalid closed direct-slot pending control DATA".into());
        }
        let old_nv = match &self.base {
            Base::Legacy { binding, cut } => {
                binding.validate()?;
                cut.validate()?;
                if binding != &self.binding {
                    return Err("pending first slot cut changes sealed C binding".into());
                }
                cut.nv_head.as_str()
            }
            Base::Slot { index, cell } => {
                cell.validate()?;
                if *index > 1 || *index == self.inactive_index || cell.binding() != &self.binding {
                    return Err("pending operation would overwrite current selector cell".into());
                }
                match cell {
                    Cell::Selected { nv_head, .. } => nv_head,
                    Cell::Empty { .. } => {
                        return Err("empty control DATA is not a paged base authority".into())
                    }
                }
            }
        };
        let next_nv = match &self.next {
            Cell::Selected { nv_head, .. } => nv_head,
            Cell::Empty { .. } => return Err("pending next cell is empty DATA".into()),
        };
        if bundle::hex(&tpm::extend_value(
            tpm::decode(old_nv)?,
            tpm::decode(&self.event_sha256)?,
        )) != *next_nv
        {
            return Err(
                "pending direct controls do not describe one exact existing C extension".into(),
            );
        }
        Ok(())
    }
    pub fn verify_descriptors(&self, base: Option<&Descriptor>, next: &Descriptor) -> Result<()> {
        self.validate_data()?;
        next.validate()?;
        if next.binding != self.binding
            || next.event_sha256 != self.event_sha256
            || hash(&serde_json::to_vec(&next.operation)?) != self.operation_sha256
            || Cell::for_descriptor(
                next,
                match &self.next {
                    Cell::Selected { descriptor, .. } => descriptor.clone(),
                    _ => return Err("pending new descriptor reference absent".into()),
                },
            )? != self.next
        {
            return Err(
                "pending controls substitute exact next operation, storage or descriptor".into(),
            );
        }
        match (&self.base, base) {
            (Base::Legacy { binding, cut }, None) => {
                if next.binding != *binding
                    || next.legacy != *cut
                    || next.sequence != 1
                    || next.previous_descriptor_sha256.is_some()
                    || next.previous_nv_head != cut.nv_head
                    || next.phase.state != bootstrap::State::Pending
                    || next.phase.copied_entries != 0
                    || next.roots != Roots::empty(binding)?
                    || !matches!(next.operation, OperationData::BootstrapProgress { .. })
                {
                    return Err("initial direct cut does not extend genuine legacy into zero-row maintenance".into());
                }
            }
            (
                Base::Slot {
                    cell:
                        Cell::Selected {
                            descriptor: reference,
                            ..
                        },
                    ..
                },
                Some(base),
            ) => {
                base.validate()?;
                if Cell::for_descriptor(base, reference.clone())?
                    != match &self.base {
                        Base::Slot { cell, .. } => cell.clone(),
                        _ => return Err("slot base lost".into()),
                    }
                    || next.binding != base.binding
                    || next.legacy != base.legacy
                    || next.sequence
                        != base
                            .sequence
                            .checked_add(1)
                            .ok_or("slot descriptor sequence overflow")?
                    || next.previous_descriptor_sha256.as_ref() != Some(&reference.sha256)
                    || next.previous_nv_head != base.selected_nv_head
                    || next
                        .storage
                        .as_ref()
                        .ok_or("next control identities absent")?
                        .controls
                        != base
                            .storage
                            .as_ref()
                            .ok_or("base control identities absent")?
                            .controls
                {
                    return Err(
                        "pending direct cut does not extend exact currently selected descriptor"
                            .into(),
                    );
                }
                if matches!(next.operation, OperationData::BootstrapProgress { .. }) {
                    base.phase.require_successor(&next.phase)?;
                } else if base.phase != next.phase {
                    return Err("ordinary slot publication changes bootstrap provenance".into());
                }
            }
            _ => return Err("pending control base parser/descriptor mismatch; no adoption".into()),
        }
        Ok(())
    }
}

/// Empty is initialization DATA only. A malformed/torn pending frame never
/// decodes to Empty and cannot authorize reopening the old writer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialRetirement {
    pub schema_version: u32,
    pub domain: String,
    pub pending: PendingCell,
    pub cells: [Cell; 2],
    pub review_sha256: String,
    pub recovery_request_sha256: String,
    pub recovery_source_sha256: String,
    pub original_recovery: Audit,
}
impl InitialRetirement {
    pub fn validate_data(&self) -> Result<()> {
        self.pending.validate_data()?;
        self.original_recovery.validate()?;
        for value in [
            &self.review_sha256,
            &self.recovery_request_sha256,
            &self.recovery_source_sha256,
        ] {
            digest(value)?;
        }
        let Base::Legacy { binding, cut } = &self.pending.base else {
            return Err(
                "direct initial retirement cannot retire a selected paged operation".into(),
            );
        };
        if self.schema_version != 4
            || self.domain != "luma-c-direct-initial-retirement-v4"
            || self.pending.next != self.cells[self.pending.inactive_index as usize]
            || self.original_recovery.operation_id.is_none()
            || self.original_recovery.usage.action != crate::finite_grants::Action::RecoverResource
            || self.original_recovery.usage.selector.kind != crate::finite_grants::Kind::Resource
            || self.original_recovery.usage.selector.id != "content-custody-paged-reconcile-v3"
            || self.original_recovery.usage.selector.generation != 1
            || self.original_recovery.usage.selector.digest != self.review_sha256
            || self.original_recovery.usage.input_bytes != 0
            || self.original_recovery.usage.output_bytes != 8192
            || self.original_recovery.usage.units != 1
        {
            return Err("invalid original reviewed direct retirement DATA".into());
        }
        for cell in &self.cells {
            cell.validate()?;
            if cell.binding() != binding
                || matches!(cell,Cell::Selected{nv_head,..} if nv_head==&cut.nv_head)
            {
                return Err(
                    "direct initial retirement changes binding or discards a current C selector"
                        .into(),
                );
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum PendingFrame {
    Empty {
        schema_version: u32,
        domain: String,
        binding: map::CustodyBinding,
    },
    Prepared {
        pending: PendingCell,
    },
    Completed {
        pending: PendingCell,
    },
    RetiredInitial {
        retirement: InitialRetirement,
    },
}
impl PendingFrame {
    pub fn empty_data(binding: &map::CustodyBinding) -> Result<Self> {
        binding.validate()?;
        Ok(Self::Empty {
            schema_version: 3,
            domain: "luma-c-fixed-pending-frame-v3".into(),
            binding: binding.clone(),
        })
    }
    pub fn frame(&self) -> Result<Vec<u8>> {
        self.validate()?;
        frame(self)
    }
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_frame(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Empty {
                schema_version,
                domain,
                binding,
            } => {
                binding.validate()?;
                if *schema_version != 3 || domain != "luma-c-fixed-pending-frame-v3" {
                    return Err("invalid initialized pending control DATA".into());
                }
            }
            Self::Prepared { pending } | Self::Completed { pending } => pending.validate_data()?,
            Self::RetiredInitial { retirement } => retirement.validate_data()?,
        }
        Ok(())
    }
}

/// Holds physical readback snapshots rather than serializable authority. It
/// contains no Checkpoint, so preparation cannot dispatch NV by itself.
pub(super) struct StagedControls {
    #[allow(dead_code)]
    pub current_index: Option<usize>,
    pub pending: PendingCell,
    #[allow(dead_code)]
    pub cells: [Cell; 2],
    snapshots: [super::super::paged::cells::Snapshot; 3],
}
impl StagedControls {
    pub fn check(
        &self,
        files: &super::super::paged::cells::Files<'_>,
        original: &mut COperation<'_, '_>,
    ) -> Result<()> {
        original.check()?;
        for (index, expected) in self.snapshots.iter().enumerate() {
            let actual = files.read(index, &mut || original.check())?;
            if actual.sha256() != expected.sha256() || actual.bytes() != expected.bytes() {
                return Err("prepared fixed controls changed before original dispatch".into());
            }
        }
        original.check()
    }
}

/// Writes only the fixed pending inode and the inactive selector inode. The
/// current selector is retained byte-for-byte. No new file, rename, truncate,
/// allocation, Checkpoint or generic semantic callback is available here.
/// The native publisher still must verify independent semantics/reservations
/// before a separate one-dispatch authority step can consume this observation.
pub(super) fn stage(
    files: &super::super::paged::cells::Files<'_>,
    pending: PendingCell,
    base: Option<&Descriptor>,
    next: &Descriptor,
    actual_nv: [u8; 32],
    reader: &mut impl Reader,
    original: &mut COperation<'_, '_>,
) -> Result<StagedControls> {
    original.check()?;
    pending.verify_descriptors(base, next)?;
    let storage = next
        .storage
        .as_ref()
        .ok_or("new direct descriptor lacks storage proof")?;
    if &storage.controls != files.selection() {
        return Err("staged controls differ from exact next C-event-bound inodes".into());
    }
    let snapshots = [
        files.read(0, &mut || original.check())?,
        files.read(1, &mut || original.check())?,
        files.read(2, &mut || original.check())?,
    ];
    let mut cells = [
        Cell::from_frame(snapshots[0].bytes())?,
        Cell::from_frame(snapshots[1].bytes())?,
    ];
    let previous = PendingFrame::from_frame(snapshots[2].bytes())?;
    let current_index = match (&pending.base, base) {
        (Base::Legacy { binding, cut }, None) => {
            if tpm::decode::<32>(&cut.nv_head)? != actual_nv
                || cells
                    .iter()
                    .any(|cell| !matches!(cell, Cell::Empty { .. }) || cell.binding() != binding)
                || !matches!(&previous,PendingFrame::Empty{binding:old,..} if old==binding)
            {
                return Err("first direct preparation is not exact original legacy NV and initialized controls".into());
            }
            None
        }
        (Base::Slot { index, cell }, Some(base)) => {
            if base
                .storage
                .as_ref()
                .ok_or("current descriptor lacks control identities")?
                .controls
                != *files.selection()
            {
                return Err("current C descriptor does not select the held control inodes".into());
            }
            let (observed, selected) = select_checked(
                &pending.binding,
                actual_nv,
                [&cells[0], &cells[1]],
                reader,
                Some(&mut *original),
            )?;
            if observed != *index as usize
                || &cells[observed] != cell
                || selected.bytes()? != base.bytes()?
            {
                return Err("direct preparation changed actual selected base".into());
            }
            let PendingFrame::Completed { pending: old } = previous else {
                return Err(
                    "current direct C selection lost its exact prior pending record".into(),
                );
            };
            if old.next != cells[observed] || old.event_sha256 != base.event_sha256 {
                return Err(
                    "current direct C selection does not complete the prior fixed pending record"
                        .into(),
                );
            }
            Some(observed)
        }
        _ => return Err("direct preparation base mismatch".into()),
    };
    let next_reference = match &pending.next {
        Cell::Selected { descriptor, .. } => descriptor,
        _ => return Err("next direct selector is empty".into()),
    };
    reader.check()?;
    if reader.read_descriptor_original(next_reference, original)? != next.slot_frame()? {
        return Err(
            "preallocated next descriptor did not fully read back before control staging".into(),
        );
    }
    original.check()?;
    let pending_frame = PendingFrame::Prepared {
        pending: pending.clone(),
    }
    .frame()?;
    let after_pending = files.rewrite(&snapshots[2], &pending_frame, &mut || original.check())?;
    let index = pending.inactive_index as usize;
    let after_next = files.rewrite(&snapshots[index], &pending.next.frame()?, &mut || {
        original.check()
    })?;
    let final_snapshots = [
        files.read(0, &mut || original.check())?,
        files.read(1, &mut || original.check())?,
        after_pending,
    ];
    if final_snapshots[index].bytes() != after_next.bytes() {
        return Err("inactive direct selector differs after durable preparation".into());
    }
    if let Some(current) = current_index {
        if final_snapshots[current].bytes() != snapshots[current].bytes() {
            return Err("preparation modified the currently selected control cell".into());
        }
    }
    cells[index] = pending.next.clone();
    // Keep the final snapshots in fixed index order; a subsequent current-NV
    // check must still be obtained from the original existing checkpoint.
    let staged = StagedControls {
        current_index,
        pending,
        cells,
        snapshots: final_snapshots,
    };
    staged.check(files, original)?;
    Ok(staged)
}

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
