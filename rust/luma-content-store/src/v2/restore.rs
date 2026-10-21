//! Bounded fresh-owner restore DATA and preparation. Old origin snapshots are
//! never converted into a local current-owner boundary. Only the existing C
//! job selector and actual original Admin/grants/lease permit each new window.
use super::backup::{PartCommitment, SnapshotPages, SnapshotPart, WholeSnapshotManifest};
use super::head::OwnerHeadV2;
use super::owner_segment::StoredOutcome;
use super::*;
use serde::{Deserialize, Serialize};

pub mod completion;
mod import;
mod read;
pub mod replay;
#[cfg(test)]
mod tests;
pub use import::{
    plan_import_part, prepare_import_part, ImportPartPlan, PreparedImportCommitment,
    PreparedImportPart,
};
pub use read::{read_snapshot_outcome, SnapshotReadBoundary};

pub const RESTORE_PROFILE: &str = "luma-windowed-fresh-owner-snapshot-restore-v1";
pub const IMPORT_MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
pub const IMPORT_MAX_WRITE_BYTES: u64 = 4 * 1024 * 1024;
pub const IMPORT_MAX_NEW_FILES: u32 = 256;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreStage {
    Importing,
    Replaying,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImportProgress {
    pub next_part: u32,
    pub objects: u64,
    pub raw_bytes: u64,
    pub incomplete_objects: u64,
    pub stream_sha256: String,
    pub previous_plaintext_sha256: Option<String>,
    pub last_object_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreReservations {
    pub reservation_sha256: String,
    pub publication_tail: u32,
    pub terminal_tail: u32,
    pub reserved_bytes: u64,
    pub reserved_inodes: u64,
}
impl RestoreReservations {
    fn validate(&self, complete: bool) -> Result<()> {
        digest(&self.reservation_sha256)?;
        if self.publication_tail != if complete { 0 } else { 2 }
            || self.terminal_tail != u32::from(!complete)
            || (!complete
                && (self.reserved_bytes == 0
                    || self.reserved_inodes
                        < u64::from(self.publication_tail + self.terminal_tail)))
        {
            return Err("restore window/terminal reservations are incomplete".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestorePrefix {
    pub schema_version: u32,
    pub profile: String,
    pub job_sha256: String,
    pub manifest_sha256: String,
    pub target: OwnerHeadV2,
    pub request_namespace: String,
    pub stage: RestoreStage,
    pub origin_namespace_sha256: String,
    pub job_namespace_sha256: String,
    pub import: ImportProgress,
    pub next_source_ordinal: u64,
    pub published_versions: u64,
    pub lifecycle_outcomes: u64,
    pub inert_outcomes: u64,
    pub verified_final_artifacts: u64,
    pub mappings: MapRoot,
    pub source_lifecycle: MapRoot,
    pub reservations: RestoreReservations,
}
impl RestorePrefix {
    pub fn validate(&self, manifest: &WholeSnapshotManifest) -> Result<()> {
        manifest.validate()?;
        self.target.validate()?;
        for value in [
            &self.job_sha256,
            &self.manifest_sha256,
            &self.origin_namespace_sha256,
            &self.job_namespace_sha256,
            &self.import.stream_sha256,
        ] {
            digest(value)?;
        }
        if let Some(value) = &self.import.previous_plaintext_sha256 {
            digest(value)?;
        }
        if let Some(value) = &self.import.last_object_sha256 {
            digest(value)?;
        }
        self.mappings.validate()?;
        self.source_lifecycle.validate()?;
        let processed = self
            .published_versions
            .checked_add(self.lifecycle_outcomes)
            .and_then(|n| n.checked_add(self.inert_outcomes))
            .ok_or("restore prefix count overflow")?;
        let origin = &manifest.intent.head;
        if self.schema_version != 1
            || self.profile != RESTORE_PROFILE
            || self.manifest_sha256 != manifest.sha256()?
            || self.target.binding.installation == origin.binding.installation
            || self.target.binding.owner == origin.binding.owner
            || self.request_namespace.is_empty()
            || self.request_namespace.len() > 64
            || !self.request_namespace.as_bytes()[0].is_ascii_alphanumeric()
            || !self
                .request_namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.mappings.kind != MapKind::RestoreMappings
            || self.source_lifecycle.kind != MapKind::RestoreSourceLifecycle
            || self.mappings.binding != self.target.binding
            || self.source_lifecycle.binding != self.target.binding
            || self.next_source_ordinal
                != processed
                    .checked_add(1)
                    .ok_or("restore source ordinal overflow")?
            || processed > origin.history.outcomes
            || self.target.history.outcomes
                != self
                    .published_versions
                    .checked_add(self.lifecycle_outcomes)
                    .ok_or("restore target count overflow")?
            || self.mappings.entry_count != self.published_versions
            || self.source_lifecycle.entry_count != self.target.roots.artifacts.entry_count
            || self.verified_final_artifacts > self.source_lifecycle.entry_count
            || self.import.next_part > manifest.part_count
            || self.import.objects > manifest.review.object_count
            || self.import.raw_bytes > manifest.review.object_bytes
            || self.import.incomplete_objects > manifest.review.inventory.incomplete_objects
            || (self.import.objects == 0) != (self.import.last_object_sha256.is_none())
            || (self.import.next_part == 0) != (self.import.previous_plaintext_sha256.is_none())
        {
            return Err("restore prefix retargets or loses exact bounded progress".into());
        }
        if self.stage == RestoreStage::Importing {
            if processed != 0
                || self.target.history.outcomes != 0
                || self.mappings.entry_count != 0
                || self.source_lifecycle.entry_count != 0
            {
                return Err(
                    "restore cannot replay before complete authenticated origin import".into(),
                );
            }
        } else if self.import.next_part != manifest.part_count
            || self.import.objects != manifest.review.object_count
            || self.import.raw_bytes != manifest.review.object_bytes
            || self.import.incomplete_objects != manifest.review.inventory.incomplete_objects
            || self.import.stream_sha256 != manifest.review.stream_sha256
            || self.import.previous_plaintext_sha256.as_ref()
                != Some(&manifest.last_plaintext_sha256)
        {
            return Err("restore replay lacks complete ordered origin import".into());
        }
        if self.stage == RestoreStage::Complete
            && (processed != origin.history.outcomes
                || self.verified_final_artifacts != self.source_lifecycle.entry_count
                || self.source_lifecycle.entry_count != origin.roots.artifacts.entry_count
                || self.published_versions != origin.roots.history.entry_count
                || self.target.roots.collections.entry_count
                    != origin.roots.collections.entry_count
                || self.target.roots.corpus.entry_count != origin.roots.corpus.entry_count)
        {
            return Err(
                "whole restore terminal state lacks complete semantic/current coverage".into(),
            );
        }
        self.reservations
            .validate(self.stage == RestoreStage::Complete)?;
        Ok(())
    }
    pub fn canonical_bytes(&self, manifest: &WholeSnapshotManifest) -> Result<Vec<u8>> {
        self.validate(manifest)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("restore prefix exceeds one bounded page".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self, manifest: &WholeSnapshotManifest) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes(manifest)?))
    }
    pub fn from_canonical(bytes: &[u8], manifest: &WholeSnapshotManifest) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_PAGE_BYTES)?;
        value.validate(manifest)?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreWindowKind {
    ImportPart,
    ReplayOutcome,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreWindowReview {
    pub schema_version: u32,
    pub profile: String,
    pub kind: RestoreWindowKind,
    pub job_sha256: String,
    pub manifest_sha256: String,
    pub prefix_sha256: String,
    pub target_head_sha256: String,
    pub proposed_data_sha256: String,
    pub source_ordinal: Option<u64>,
    pub part: Option<PartCommitment>,
    pub source_record_sha256: Option<String>,
    pub target_plan_sha256: Option<String>,
    pub review_sha256: String,
}
impl RestoreWindowReview {
    pub fn validate(&self, manifest: &WholeSnapshotManifest, prefix: &RestorePrefix) -> Result<()> {
        prefix.validate(manifest)?;
        digest(&self.review_sha256)?;
        digest(&self.proposed_data_sha256)?;
        if self.schema_version != 1
            || self.profile != RESTORE_PROFILE
            || self.job_sha256 != prefix.job_sha256
            || self.manifest_sha256 != manifest.sha256()?
            || self.prefix_sha256 != prefix.sha256(manifest)?
            || self.target_head_sha256 != prefix.target.sha256()?
        {
            return Err("restore window review differs from exact selected job/target".into());
        }
        match self.kind {
            RestoreWindowKind::ImportPart => {
                let part = self
                    .part
                    .as_ref()
                    .ok_or("restore import lacks exact authenticated part")?;
                part.validate()?;
                if prefix.stage != RestoreStage::Importing
                    || part.number != prefix.import.next_part
                    || self.source_ordinal.is_some()
                    || self.source_record_sha256.is_some()
                    || self.target_plan_sha256.is_some()
                {
                    return Err("invalid closed import window review".into());
                }
            }
            RestoreWindowKind::ReplayOutcome => {
                if prefix.stage != RestoreStage::Replaying
                    || self.source_ordinal != Some(prefix.next_source_ordinal)
                    || self.part.is_some()
                    || prefix.next_source_ordinal > manifest.intent.head.history.outcomes
                {
                    return Err("invalid closed chronological replay review".into());
                }
                digest(
                    self.source_record_sha256
                        .as_deref()
                        .ok_or("restore replay record commitment missing")?,
                )?;
                if let Some(value) = &self.target_plan_sha256 {
                    digest(value)?;
                }
            }
            RestoreWindowKind::Complete => {
                if prefix.stage != RestoreStage::Replaying
                    || prefix.next_source_ordinal != manifest.intent.head.history.outcomes + 1
                    || self.part.is_some()
                    || self.source_ordinal.is_some()
                    || self.source_record_sha256.is_some()
                    || self.target_plan_sha256.is_some()
                {
                    return Err("invalid closed whole-restore completion review".into());
                }
            }
        }
        let mut value = self.clone();
        value.review_sha256.clear();
        if luma_content::sha256(&serde_json::to_vec(&value)?) != self.review_sha256
            || serde_json::to_vec(self)?.len() > MAX_PAGE_BYTES
        {
            return Err("restore window canonical review commitment differs".into());
        }
        Ok(())
    }
    fn finish(&mut self, manifest: &WholeSnapshotManifest, prefix: &RestorePrefix) -> Result<()> {
        self.review_sha256.clear();
        self.review_sha256 = luma_content::sha256(&serde_json::to_vec(self)?);
        self.validate(manifest, prefix)
    }
}
/// Actual authority remains outside all serialized progress/review values.
/// Implementations must positively verify the installed encrypted OS volume,
/// fixed C-selected job namespace and original thirty-second Standard session.
pub trait RestoreBoundary: OwnerBoundary + SnapshotReadBoundary {
    fn current_restore_prefix(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
    ) -> Result<()>;
    fn standard_admin_window(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        review: Option<&RestoreWindowReview>,
    ) -> Result<()>;
    fn retain_original_ciphertext(
        &mut self,
        manifest: &WholeSnapshotManifest,
        through_part: u32,
    ) -> Result<()>;
    fn verify_origin_namespace(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        store: &ObjectStore,
    ) -> Result<()>;
    /// Independently compare actual held namespace creations and physical
    /// reservations with this original reviewed window. A serialized counter
    /// cannot implement the native observation or select the proposed prefix.
    fn verify_prepared_import(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        review: &RestoreWindowReview,
        commitment: &PreparedImportCommitment,
        store: &ObjectStore,
    ) -> Result<()>;
}
/// Validates immutable DATA once for this borrowed operation. It contains no
/// C/principal/session/grant/UTC/resource observation and is not transferable
/// authority. Every I/O still calls all original live boundary methods.
struct CheckedWindow<'a> {
    manifest: &'a WholeSnapshotManifest,
    prefix: &'a RestorePrefix,
    review: Option<&'a RestoreWindowReview>,
}
impl<'a> CheckedWindow<'a> {
    fn new(
        manifest: &'a WholeSnapshotManifest,
        prefix: &'a RestorePrefix,
        review: Option<&'a RestoreWindowReview>,
    ) -> Result<Self> {
        manifest.validate()?;
        prefix.validate(manifest)?;
        if let Some(review) = review {
            review.validate(manifest, prefix)?;
        }
        Ok(Self {
            manifest,
            prefix,
            review,
        })
    }
    fn current<B: RestoreBoundary>(&self, b: &mut B) -> Result<()> {
        b.authenticated_snapshot(self.manifest)?;
        b.current_restore_prefix(self.manifest, self.prefix)?;
        b.current_owner_head(&self.prefix.target)?;
        b.standard_admin_window(self.manifest, self.prefix, self.review)
    }
}
fn live<B: RestoreBoundary>(
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    review: Option<&RestoreWindowReview>,
    b: &mut B,
) -> Result<()> {
    CheckedWindow::new(manifest, prefix, review)?.current(b)
}
