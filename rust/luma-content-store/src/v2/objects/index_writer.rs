//! One actual owner-root writer OFD retained for a complete index preparation.
//! The OFD is advisory/exclusion DATA, never a creator, grant or publication.
use super::*;
use crate::v2::head::OwnerHeadV2;
use crate::v2::owner::{AppendWriterBoundary, OwnerBoundary};

pub struct ObservedObjectWriter<'a> {
    store: &'a ObjectStore,
    head: OwnerHeadV2,
    review_sha256: String,
    writer: File,
}
impl ObservedObjectWriter<'_> {
    /// This method refreshes the real supplied original boundary and the
    /// independently received SAME-OFD observer. No serialized success is used.
    pub fn check<B: OwnerBoundary + AppendWriterBoundary>(&self, boundary: &mut B) -> Result<()> {
        boundary.current_owner_head(&self.head)?;
        boundary.check(Access::Inspect {
            binding: &self.head.binding,
        })?;
        self.store.check()?;
        if !same(&self.writer, &self.store.root)? {
            return Err("index preparation writer namespace changed".into());
        }
        boundary.check_writer(&self.head, &self.review_sha256, &self.writer)?;
        self.store.check()?;
        boundary.current_owner_head(&self.head)
    }
    pub fn review_sha256(&self) -> &str {
        &self.review_sha256
    }
    pub fn head(&self) -> &OwnerHeadV2 {
        &self.head
    }
    /// Additional bytes use this SAME retained writer, never reacquire a lock.
    /// `authorize` must verify the independently preregistered exact metadata
    /// inventory at every actual boundary; it cannot mint original admission.
    pub fn prepare_blob<B: OwnerBoundary + AppendWriterBoundary>(
        &self,
        bytes: &[u8],
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut B,
        authorize: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<BlobReference> {
        if mutation.review_sha256 != self.review_sha256 {
            return Err("metadata changes original preparation review".into());
        }
        struct Checked<'a, 'b, B, F> {
            writer: &'a ObservedObjectWriter<'b>,
            inner: &'a mut B,
            authorize: F,
        }
        impl<B: OwnerBoundary + AppendWriterBoundary, F: FnMut(&mut B) -> Result<()>> Boundary
            for Checked<'_, '_, B, F>
        {
            fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
                self.writer.check(self.inner)?;
                (self.authorize)(self.inner)?;
                self.inner.admit(binding, budget)?;
                (self.authorize)(self.inner)?;
                self.writer.check(self.inner)
            }
            fn check(&mut self, access: Access<'_>) -> Result<()> {
                self.writer.check(self.inner)?;
                (self.authorize)(self.inner)?;
                self.inner.check(access)?;
                (self.authorize)(self.inner)?;
                self.writer.check(self.inner)
            }
        }
        self.check(boundary)?;
        let result = self.store.prepare_blob(
            bytes,
            budget,
            mutation,
            &mut Checked {
                writer: self,
                inner: boundary,
                authorize,
            },
        )?;
        self.check(boundary)?;
        Ok(result)
    }
}
impl ObjectStore {
    /// The caller must already hold C's durable complete write-set/metadata
    /// reservation. Original admission precedes SAME-OFD registration, and no
    /// object is created by acquiring this handle. Drop never releases C holds.
    pub fn prepare_index_observed<'a, B: OwnerBoundary + AppendWriterBoundary>(
        &'a self,
        head: &OwnerHeadV2,
        mutation: &Mutation,
        budget: IoBudget,
        boundary: &mut B,
    ) -> Result<ObservedObjectWriter<'a>> {
        head.validate()?;
        mutation.validate()?;
        budget.validate()?;
        if head.binding != self.binding
            || mutation.decision != DecisionKind::Published
            || budget.write_bytes == 0
        {
            return Err(
                "index writer requires exact current owner and finite derivative-write scope"
                    .into(),
            );
        }
        boundary.current_owner_head(head)?;
        {
            let mut admitted = Guard::new(boundary, &head.binding, budget, Some(mutation))?;
            admitted.check()?;
        }
        boundary.current_owner_head(head)?;
        let writer = self.acquire_writer()?;
        boundary.begin_writer(head, &mutation.review_sha256, &writer)?;
        let value = ObservedObjectWriter {
            store: self,
            head: head.clone(),
            review_sha256: mutation.review_sha256.clone(),
            writer,
        };
        value.check(boundary)?;
        Ok(value)
    }
}
