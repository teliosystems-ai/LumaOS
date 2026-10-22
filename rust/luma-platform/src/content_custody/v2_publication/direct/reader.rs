//! Current-C fixed-control and immutable-slot reader. Mutable control bytes
//! select no authority by themselves: the actual existing anchor must select
//! one whole descriptor committing the observed control inode identities.
use super::super::super::paged::{cells, slots};
use super::super::*;

struct RawSlots<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    check: &'b mut F,
}
impl<F: FnMut() -> Result<()>> control::Reader for RawSlots<'_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read_descriptor(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        control::Reader::check(self)?;
        if reference.slot.kind != slots::Kind::Page || reference.bytes != PAGE_BYTES as u64 {
            return Err("current direct descriptor is not its exact fixed page frame".into());
        }
        let directory = slots::Directory::at_reference(self.pages, &reference.slot, self.check)?;
        let bytes = directory.read(reference, self.check)?;
        control::Reader::check(self)?;
        Ok(bytes)
    }
    fn read_descriptor_original(
        &mut self,
        reference: &slots::SealedReference,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>> {
        let pages = self.pages;
        let check = &mut self.check;
        let mut live = || -> Result<()> {
            original.check()?;
            check()?;
            pages.check()?;
            original.check()
        };
        let directory = slots::Directory::at_reference(pages, &reference.slot, &mut live)?;
        let bytes = directory.read(reference, &mut live)?;
        live()?;
        Ok(bytes)
    }
}
impl<F: FnMut() -> Result<()>> locations::Io for RawSlots<'_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        locations::Io::check(self)?;
        let directory = slots::Directory::at_reference(self.pages, &reference.slot, self.check)?;
        let bytes = directory.read(reference, self.check)?;
        locations::Io::check(self)?;
        Ok(bytes)
    }
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("current direct runtime reader cannot allocate/seal index nodes".into())
    }
}

/// Fresh observed current C DATA, not a product grant or original operation.
/// There is no decoder or caller-supplied descriptor constructor.
pub(in crate::content_checkpoint::custody) struct ObservedCut {
    index: usize,
    descriptor: Descriptor,
    cell: control::Cell,
    pending: control::PendingFrame,
}
impl ObservedCut {
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn cell(&self) -> &control::Cell {
        &self.cell
    }
    pub fn pending(&self) -> &control::PendingFrame {
        &self.pending
    }
    pub fn review_sha256(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&(
            "luma-direct-c-control-observation-v3",
            self.index,
            &self.cell,
            &self.pending,
            self.descriptor.bytes()?,
        ))?))
    }
    pub fn completed_read(self) -> Result<ReadSelection> {
        let control::PendingFrame::Completed { pending } = &self.pending else {
            return Err(
                "direct C controls retain uncertain dispatch; fresh exact reconciliation required"
                    .into(),
            );
        };
        if pending.next != self.cell || pending.event_sha256 != self.descriptor.event_sha256 {
            return Err("completed pending controls do not bind actual selected C".into());
        }
        let storage = self
            .descriptor
            .storage
            .as_ref()
            .ok_or("selected direct descriptor lacks storage")?;
        Ok(ReadSelection {
            binding: self.descriptor.binding.clone(),
            descriptor_sha256: hash(&self.descriptor.slot_frame()?),
            nv: self.descriptor.selected_nv_head.clone(),
            locations: storage.locations.clone(),
        })
    }
}

pub(in crate::content_checkpoint::custody) fn observe<A: Checkpoint>(
    anchor: &mut A,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<ObservedCut> {
    binding.validate()?;
    check()?;
    pages.check()?;
    if pages.binding() != binding {
        return Err("direct current reader differs from independently sealed C binding".into());
    }
    let controls = cells::Files::observe(pages, check)?;
    let first = controls.read(0, check)?;
    let second = controls.read(1, check)?;
    let pending_bytes = controls.read(2, check)?;
    let cells = [
        control::Cell::from_frame(first.bytes())?,
        control::Cell::from_frame(second.bytes())?,
    ];
    let pending_frame = control::PendingFrame::from_frame(pending_bytes.bytes())?;
    let actual = anchor.read()?;
    check()?;
    let (index, descriptor) = control::select(
        binding,
        actual,
        [&cells[0], &cells[1]],
        &mut RawSlots { pages, check },
    )?;
    let storage = descriptor
        .storage
        .as_ref()
        .ok_or("current descriptor has no direct storage")?;
    if &storage.controls != controls.selection() {
        return Err("actual selected C does not commit observed fixed control inodes".into());
    }
    let pending = match &pending_frame {
        control::PendingFrame::Empty { .. } | control::PendingFrame::RetiredInitial { .. } => {
            return Err("selected direct C has no exact original dispatch record".into())
        }
        control::PendingFrame::Prepared { pending }
        | control::PendingFrame::Completed { pending } => pending,
    };
    if pending.binding != *binding {
        return Err("pending controls cross sealed C binding".into());
    }
    let base = match &pending.base {
        control::Base::Legacy { .. } => None,
        control::Base::Slot { cell, .. } => {
            let control::Cell::Selected {
                descriptor: reference,
                ..
            } = cell
            else {
                return Err("pending base cell is empty".into());
            };
            Some(Descriptor::from_slot_frame(
                &control::Reader::read_descriptor(&mut RawSlots { pages, check }, reference)?,
            )?)
        }
    };
    let control::Cell::Selected {
        descriptor: next_reference,
        ..
    } = &pending.next
    else {
        return Err("pending next cell is empty".into());
    };
    let next = Descriptor::from_slot_frame(&control::Reader::read_descriptor(
        &mut RawSlots { pages, check },
        next_reference,
    )?)?;
    pending.verify_descriptors(base.as_ref(), &next)?;
    let base_matches = match &pending.base {
        control::Base::Legacy { cut, .. } => bundle::hex(&actual) == cut.nv_head,
        control::Base::Slot { cell, .. } => cell == &cells[index],
    };
    if pending.next != cells[index] && !base_matches {
        return Err("current C matches neither exact pending cut".into());
    }
    if matches!(&pending_frame, control::PendingFrame::Completed { .. })
        && pending.next != cells[index]
    {
        return Err("completed pending record does not match actual new C".into());
    }
    check()?;
    if anchor.read()? != actual
        || controls.read(0, check)?.bytes() != first.bytes()
        || controls.read(1, check)?.bytes() != second.bytes()
        || controls.read(2, check)?.bytes() != pending_bytes.bytes()
    {
        return Err("actual direct C/control observation changed before completion".into());
    }
    Ok(ObservedCut {
        index,
        descriptor,
        cell: cells[index].clone(),
        pending: pending_frame,
    })
}

/// Constructible only through the actual completed control/NV join above.
/// No proposed-node witness or filesystem hash resolver is a runtime fallback.
pub(in crate::content_checkpoint::custody) struct ReadSelection {
    binding: map::CustodyBinding,
    descriptor_sha256: String,
    nv: String,
    locations: locations::Root,
}
impl ReadSelection {
    pub fn check_data(
        &self,
        binding: &map::CustodyBinding,
        descriptor_sha256: &str,
        nv: &str,
    ) -> Result<()> {
        self.locations.validate()?;
        if &self.binding != binding
            || self.locations.binding != *binding
            || self.descriptor_sha256 != descriptor_sha256
            || self.nv != nv
        {
            return Err("direct runtime selection differs from actual C cut".into());
        }
        Ok(())
    }
    pub fn read<A: Checkpoint>(
        &self,
        anchor: &mut A,
        pages: &PageStore,
        sha: &str,
        kind: slots::Kind,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        digest(sha)?;
        check()?;
        pages.check()?;
        if pages.binding() != &self.binding
            || !matches!(kind, slots::Kind::Page | slots::Kind::Record)
        {
            return Err("direct current object read changes binding or capacity class".into());
        }
        let expected = tpm::decode(&self.nv)?;
        let mut live = || -> Result<()> {
            check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during direct current object read".into());
            }
            check()
        };
        live()?;
        let mut io = RawSlots {
            pages,
            check: &mut live,
        };
        let reference = locations::lookup(&self.locations, sha, &mut io)?
            .ok_or("current C does not select requested immutable object; no resolver fallback")?;
        if reference.slot.kind != kind || reference.sha256 != sha {
            return Err("current immutable object substitutes class/hash".into());
        }
        let bytes = locations::Io::read(&mut io, &reference)?;
        live()?;
        Ok(bytes)
    }
}
#[cfg(test)]
#[path = "reader/tests.rs"]
mod tests;
