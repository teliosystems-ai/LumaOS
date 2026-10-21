//! Additional mandatory observer callbacks for the actual retained writer OFD.
//! Advisory flock alone is not creator/exclusion/publication authority. Native
//! callers still need original C preregistration, current worker/lease/grants,
//! independently observed physical baseline/delta and actual C publication.
use super::*;

/// No default implementation or serialized permission. `begin_writer` runs
/// after original resource admission and before any preparation write; every
/// subsequent guarded private operation retains both original boundary checks
/// and these checks on the exact borrowed, retained OFD.
pub trait AppendWriterBoundary {
    fn begin_writer(
        &mut self,
        base: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> Result<()>;
    fn check_writer(
        &mut self,
        base: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> Result<()>;
}

pub struct ObservedPreparedOwnerAppend<'a, 'b, W: AppendWriterBoundary> {
    prepared: PreparedOwnerAppend<'a>,
    observer: &'b mut W,
}
impl<W: AppendWriterBoundary> ObservedPreparedOwnerAppend<'_, '_, W> {
    /// This unselected commitment is DATA, not successful publication.
    pub fn commitment(&self) -> &AppendCommitment {
        self.prepared.commitment()
    }
    pub fn check_observation(&mut self) -> Result<()> {
        self.observer.check_writer(
            &self.prepared.commitment.base,
            &self.prepared.commitment.review_sha256,
            &self.prepared._writer,
        )
    }
    pub fn acknowledge_selected(
        mut self,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerHeadV2> {
        self.check_observation()?;
        let head = self.prepared.selected_data(boundary)?;
        self.check_observation()?;
        Ok(head)
    }
}

struct Observed<'a, B: OwnerBoundary, W: AppendWriterBoundary> {
    boundary: &'a mut B,
    observer: &'a mut W,
    base: &'a OwnerHeadV2,
    review: &'a str,
    writer: &'a File,
    begun: bool,
}
impl<B: OwnerBoundary, W: AppendWriterBoundary> Observed<'_, B, W> {
    fn observed(&mut self) -> Result<()> {
        if !self.begun {
            return Err("writer observation not begun under original resource admission".into());
        }
        self.observer
            .check_writer(self.base, self.review, self.writer)
    }
    fn if_begun(&mut self) -> Result<()> {
        // Before admission, only original selected-head/physical lookups are
        // performed by the unchanged engine. No preparation write occurs.
        if self.begun {
            self.observed()?;
        }
        Ok(())
    }
}
impl<B: OwnerBoundary, W: AppendWriterBoundary> Boundary for Observed<'_, B, W> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.boundary.admit(binding, budget)?;
        if !self.begun {
            self.observer
                .begin_writer(self.base, self.review, self.writer)?;
            self.begun = true;
        }
        self.observed()?;
        self.boundary.check(Access::Inspect { binding })?;
        self.observed()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.observed()?;
        self.boundary.check(access)?;
        self.observed()
    }
}
impl<B: OwnerBoundary, W: AppendWriterBoundary> OwnerBoundary for Observed<'_, B, W> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.if_begun()?;
        self.boundary.current_owner_head(head)?;
        self.if_begun()
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.if_begun()?;
        let physical = self.boundary.current_physical_accounting(head)?;
        self.if_begun()?;
        Ok(physical)
    }
    fn verify_prepared_allocations(&mut self, commitment: &AppendCommitment) -> Result<()> {
        self.if_begun()?;
        self.boundary.verify_prepared_allocations(commitment)?;
        self.if_begun()
    }
}
impl<'a> OwnerRepository<'a> {
    pub fn prepare_append_observed<'b, W: AppendWriterBoundary>(
        &self,
        proposal: &OwnerPlan,
        budget: IoBudget,
        boundary: &mut impl OwnerBoundary,
        observer: &'b mut W,
    ) -> Result<ObservedPreparedOwnerAppend<'a, 'b, W>> {
        self.check_append_proposal(proposal, boundary)?;
        let writer = self.store.acquire_writer()?;
        let commitment = {
            let mut checked = Observed {
                boundary,
                observer: &mut *observer,
                base: &self.head,
                review: proposal.review_sha256(),
                writer: &writer,
                begun: false,
            };
            let commitment = self.prepare_append_data(proposal, budget, &mut checked)?;
            checked.observed()?;
            commitment
        };
        Ok(ObservedPreparedOwnerAppend {
            prepared: PreparedOwnerAppend {
                store: self.store,
                _writer: writer,
                commitment,
            },
            observer,
        })
    }
}
