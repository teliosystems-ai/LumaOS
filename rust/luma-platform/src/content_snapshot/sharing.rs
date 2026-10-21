//! Borrowed composition of the EXISTING original Export operation. This does
//! not admit a session, select C, sign a receipt or expose a product endpoint.
//! Source and CMS callbacks use the same mutable context, never two sessions.
use super::{backup_crypto, scope, StageBoundary};
use crate::Result;
use luma_content::OwnerBinding;
use luma_content_store::v2::backup::{
    SnapshotBoundary, SnapshotBudget, SnapshotIntent, SnapshotMode, SnapshotReview,
};
use luma_content_store::v2::head::OwnerHeadV2;
use luma_content_store::v2::{AppendCommitment, OwnerBoundary, PhysicalInventory};
use luma_content_store::{Access, Boundary, ResourceBudget};
use std::cell::RefCell;
use std::fs::File;

/// A stack-borrowed bridge only. The concrete B must already retain the genuine
/// original Export-purpose authentication, independent finite pair, current C,
/// recipient registry and one live resource lease. The immutable request is DATA.
pub(super) struct SharedExport<'a, B: SnapshotBoundary + StageBoundary> {
    input: &'a scope::Input,
    boundary: RefCell<&'a mut B>,
}
impl<'a, B: SnapshotBoundary + StageBoundary> SharedExport<'a, B> {
    pub(super) fn new(input: &'a scope::Input, boundary: &'a mut B) -> Result<Self> {
        input.canonical_bytes()?;
        let review = input
            .review
            .as_ref()
            .ok_or("shared snapshot export requires its exact prior review")?;
        if input.mode != SnapshotMode::Export {
            return Err("shared snapshot bridge is only the original Export operation".into());
        }
        boundary.current_owner_head(&input.intent.head)?;
        boundary.check_snapshot(
            &input.intent,
            SnapshotMode::Export,
            Some(&review.review_sha256),
        )?;
        Ok(Self {
            input,
            boundary: RefCell::new(boundary),
        })
    }
    pub(super) fn split(&self) -> (Source<'_, 'a, B>, Stage<'_, 'a, B>) {
        (Source { shared: self }, Stage { shared: self })
    }
    fn with<T>(&self, callback: impl FnOnce(&mut B) -> Result<T>) -> Result<T> {
        let mut held = self
            .boundary
            .try_borrow_mut()
            .map_err(|_| "reentrant original snapshot operation refused")?;
        callback(&mut **held)
    }
    fn intent(&self, intent: &SnapshotIntent) -> Result<()> {
        if intent != &self.input.intent {
            return Err("shared original snapshot intent substituted".into());
        }
        Ok(())
    }
    fn head(&self, head: &OwnerHeadV2) -> Result<()> {
        if head != &self.input.intent.head {
            return Err("shared original snapshot owner head substituted".into());
        }
        Ok(())
    }
    fn binding(&self, binding: &OwnerBinding) -> Result<()> {
        if binding != &self.input.intent.head.binding {
            return Err("shared original snapshot owner binding substituted".into());
        }
        Ok(())
    }
    fn review(&self, review: &SnapshotReview) -> Result<()> {
        if self.input.review.as_ref() != Some(review) {
            return Err("shared original snapshot review substituted".into());
        }
        Ok(())
    }
    fn crypto(&self, request: &backup_crypto::CryptoRequest) -> Result<()> {
        if request.operation != backup_crypto::CryptoOperation::Encrypt
            || request.recipients != self.input.recipients
        {
            return Err(
                "shared snapshot crypto operation or governed recipients substituted".into(),
            );
        }
        Ok(())
    }
}

/// Only the existing source pipeline receives this facade; it cannot create a
/// second authentication/resource context or retain a cached current decision.
pub(super) struct Source<'s, 'a, B: SnapshotBoundary + StageBoundary> {
    shared: &'s SharedExport<'a, B>,
}
impl<B: SnapshotBoundary + StageBoundary> Boundary for Source<'_, '_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.shared.binding(binding)?;
        self.shared.with(|b| Boundary::admit(b, binding, budget))
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.shared.binding(match access {
            Access::Inspect { binding }
            | Access::Mutate { binding, .. }
            | Access::Recover { binding, .. } => binding,
        })?;
        self.shared.with(|b| Boundary::check(b, access))
    }
}
impl<B: SnapshotBoundary + StageBoundary> OwnerBoundary for Source<'_, '_, B> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.shared.head(head)?;
        self.shared.with(|b| b.current_owner_head(head))
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.shared.head(head)?;
        self.shared.with(|b| b.current_physical_accounting(head))
    }
    fn verify_prepared_allocations(&mut self, commitment: &AppendCommitment) -> Result<()> {
        self.shared
            .with(|b| b.verify_prepared_allocations(commitment))
    }
}
impl<B: SnapshotBoundary + StageBoundary> SnapshotBoundary for Source<'_, '_, B> {
    fn admit_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        budget: SnapshotBudget,
    ) -> Result<()> {
        self.shared.intent(intent)?;
        if mode != SnapshotMode::Export || budget != self.shared.input.budget {
            return Err("shared snapshot source admission changed original finite request".into());
        }
        self.shared.with(|b| b.admit_snapshot(intent, mode, budget))
    }
    fn check_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        review_sha256: Option<&str>,
    ) -> Result<()> {
        self.shared.intent(intent)?;
        let expected = self
            .shared
            .input
            .review
            .as_ref()
            .map(|r| r.review_sha256.as_str());
        if mode != SnapshotMode::Export || review_sha256 != expected {
            return Err("shared snapshot check changed original Export/review selector".into());
        }
        self.shared
            .with(|b| b.check_snapshot(intent, mode, review_sha256))
    }
    fn verify_snapshot_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.shared.head(head)?;
        self.shared.with(|b| b.verify_snapshot_head(head))
    }
}

/// Only CMS staging receives this facade. Encryption is still governed by B's
/// genuine existing CryptoBoundary; this bridge never authenticates a sender.
pub(super) struct Stage<'s, 'a, B: SnapshotBoundary + StageBoundary> {
    shared: &'s SharedExport<'a, B>,
}
impl<B: SnapshotBoundary + StageBoundary> backup_crypto::CryptoBoundary for Stage<'_, '_, B> {
    fn admit(
        &mut self,
        request: &backup_crypto::CryptoRequest,
        budget: backup_crypto::CryptoBudget,
    ) -> Result<()> {
        self.shared.crypto(request)?;
        self.shared
            .with(|b| backup_crypto::CryptoBoundary::admit(b, request, budget))
    }
    fn check(&mut self, request: &backup_crypto::CryptoRequest) -> Result<()> {
        self.shared.crypto(request)?;
        self.shared
            .with(|b| backup_crypto::CryptoBoundary::check(b, request))
    }
}
impl<B: SnapshotBoundary + StageBoundary> StageBoundary for Stage<'_, '_, B> {
    fn current_snapshot_stage(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        directory: &File,
    ) -> Result<()> {
        self.shared.intent(intent)?;
        self.shared.review(review)?;
        self.shared
            .with(|b| b.current_snapshot_stage(intent, review, directory))
    }
    fn admit_snapshot_output(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        maximum_bytes: u64,
        maximum_files: u32,
    ) -> Result<()> {
        self.shared.intent(intent)?;
        self.shared.review(review)?;
        if maximum_bytes == 0 || maximum_bytes > self.shared.input.budget.output_bytes {
            return Err("shared snapshot stage exceeds original output reservation".into());
        }
        self.shared
            .with(|b| b.admit_snapshot_output(intent, review, maximum_bytes, maximum_files))
    }
}

#[cfg(test)]
mod tests;
