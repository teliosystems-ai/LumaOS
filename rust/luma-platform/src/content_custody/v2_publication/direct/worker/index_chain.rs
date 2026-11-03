//! The C history walk behind a Publish. From the current descriptor back to
//! the job's Start, every event that selected a job for this owner must derive
//! that job again from the one before it, and the newest must be the audited
//! job. Each earlier descriptor is the full frame its successor committed to.
//! The walk is bounded: a longer history refuses publication, and compacting
//! it is later work.
use super::*;

const MAX_EVENTS: u64 = 4096;
/// Descriptor frames and the selection records they name. Store blobs are
/// bounded by each read's own budget.
const CHAIN_READ_BUDGET: u64 = 4 * READ_BUDGET;

impl<A: Checkpoint> Current<'_, '_, '_, '_, A> {
    pub(super) fn verify_chain(&mut self, builder: &dyn effects::CurrentBuilder) -> Result<()> {
        self.live()?;
        builder.check(self.original)?;
        let identity = builder.identity().clone();
        if identity != self.job.builder {
            return Err("index provenance builder differs from the audited job's".into());
        }
        let mut remaining = CHAIN_READ_BUDGET;
        let mut descriptor = self.backend.descriptor.clone();
        let mut later: Option<(Vec<u8>, effects::ChainLink)> = None;
        for _ in 0..MAX_EVENTS {
            self.live()?;
            if let Some(link) = self.link(&descriptor, &mut remaining)? {
                let store = self.store;
                let bytes = store.read_blob(link.job(), read_budget(), self)?;
                let job = Job::parse(&bytes)?;
                match &later {
                    None => {
                        if bytes != self.job.canonical_bytes()? {
                            return Err("index provenance does not end at the audited job".into());
                        }
                    }
                    Some((next, newer)) => {
                        let candidate = match newer.candidate() {
                            Some(reference) => {
                                Some(store.read_blob(reference, read_budget(), self)?)
                            }
                            None => None,
                        };
                        let original = &mut *self.original;
                        if newer.next(&job, candidate.as_deref(), &identity, &mut || {
                            original.check()
                        })? != *next
                        {
                            return Err(
                                "index provenance job is not derived from the job before it".into(),
                            );
                        }
                    }
                }
                if link.starts() {
                    let original = &mut *self.original;
                    if link.first(&job.source_owner, &identity, &mut || original.check())? != bytes
                    {
                        return Err("index provenance Start does not derive its first job".into());
                    }
                    return self.live();
                }
                later = Some((bytes, link));
            }
            descriptor = self.previous(&descriptor, &mut remaining)?;
        }
        Err("index provenance exceeds its bounded C history".into())
    }
    /// The job-selecting event this descriptor records for this owner, if any.
    fn link(
        &mut self,
        descriptor: &Descriptor,
        remaining: &mut u64,
    ) -> Result<Option<effects::ChainLink>> {
        let mut view = View {
            backend: &mut *self.backend,
            remaining: *remaining,
        };
        let original = &mut *self.original;
        let link = match &descriptor.operation {
            OperationData::IndexJobSelection {
                binding, selection, ..
            } if *binding == self.binding => {
                effects::ChainLink::start(&mut view, binding, selection, original)?
            }
            OperationData::IndexPhaseSelection {
                binding, selection, ..
            } if *binding == self.binding => {
                effects::ChainLink::window(&mut view, binding, selection, original)?
            }
            OperationData::IndexAdvanceSelection {
                binding, selection, ..
            } if *binding == self.binding => {
                effects::ChainLink::advance(&mut view, binding, selection, original)?
            }
            _ => return Ok(None),
        };
        *remaining = view.remaining;
        Ok(Some(link))
    }
    /// The descriptor before this one: the exact full frame it committed to,
    /// one sequence and one global ordinal earlier, under the same cut.
    fn previous(&mut self, current: &Descriptor, remaining: &mut u64) -> Result<Descriptor> {
        let sha = current
            .previous_descriptor_sha256
            .as_ref()
            .ok_or("index provenance reached the first descriptor before the job's Start")?;
        *remaining = remaining
            .checked_sub(PAGE_BYTES as u64)
            .ok_or("index provenance C read budget exhausted before I/O")?;
        let frame = self.backend.read_immutable(
            sha,
            slots::Kind::Page,
            &mut COperation::Worker(&mut *self.original),
        )?;
        if hash(&frame) != *sha {
            return Err("index provenance descriptor frame changed".into());
        }
        let previous = Descriptor::from_slot_frame(&frame)?;
        if previous.binding != current.binding
            || previous.legacy != current.legacy
            || previous.phase != current.phase
            || previous.sequence.checked_add(1) != Some(current.sequence)
            || previous.global_ordinal.checked_add(1) != Some(current.global_ordinal)
            || previous.selected_nv_head != current.previous_nv_head
        {
            return Err(
                "index provenance does not continue the exact authenticated C history".into(),
            );
        }
        Ok(previous)
    }
}
