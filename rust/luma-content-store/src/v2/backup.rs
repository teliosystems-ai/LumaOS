//! Whole owner snapshots are inert DATA until the existing independent C origin
//! signer authenticates the complete measured manifest. A part, hash, progress
//! value or successful decryption never authenticates a complete snapshot.
use super::head::OwnerHeadV2;
use super::*;
use serde::{Deserialize, Serialize};

mod directory;
mod part;
mod pipeline;
#[cfg(test)]
mod tests;
pub use directory::{PartCommitment, PartDirectoryRef, SnapshotPages};
pub use part::{SnapshotObject, SnapshotPart, SnapshotPartHeader};
pub use pipeline::{
    export_snapshot, review_snapshot, SnapshotBoundary, SnapshotBudget, SnapshotMode, SnapshotSink,
};

pub const SNAPSHOT_PROFILE: &str = "luma-owner-whole-segmented-snapshot-v1";
pub const MAX_SNAPSHOT_PART_BYTES: usize = 1024 * 1024;
pub const MAX_SNAPSHOT_PARTS: u32 = 131072;
pub const MAX_SNAPSHOT_OBJECTS: u64 = 4_194_303;
pub const MAX_SNAPSHOT_RAW_BYTES: u64 = MAX_SNAPSHOT_OBJECTS * MAX_PAGE_BYTES as u64;
pub const MAX_PART_OBJECTS: usize = 32;
pub const MAX_CANONICAL_PART_BYTES: usize = MAX_PART_OBJECTS * MAX_PAGE_BYTES + MAX_PAGE_BYTES + 20;
pub const MAX_SNAPSHOT_CIPHERTEXT_BYTES: u64 =
    MAX_SNAPSHOT_RAW_BYTES + MAX_SNAPSHOT_PARTS as u64 * (MAX_PAGE_BYTES as u64 + 20 + 65536);
pub const MAX_SNAPSHOT_DIRECTORY_BYTES: u64 = (4096 + 128 + 4 + 1) * MAX_PAGE_BYTES as u64;
pub const MAX_SNAPSHOT_PACKAGE_OVERHEAD: u64 = MAX_SNAPSHOT_DIRECTORY_BYTES + 65556;
pub const MAX_SNAPSHOT_EXPORT_BYTES: u64 =
    MAX_SNAPSHOT_CIPHERTEXT_BYTES + MAX_SNAPSHOT_PACKAGE_OVERHEAD;
pub const MAX_SNAPSHOT_READ_BYTES: u64 = 72 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIntent {
    pub schema_version: u32,
    pub profile: String,
    pub snapshot_id: String,
    pub head: OwnerHeadV2,
    pub head_sha256: String,
    pub recipient_generation: u64,
    pub recipients_sha256: String,
    pub origin_spki_sha256: String,
}
impl SnapshotIntent {
    pub fn validate(&self) -> Result<()> {
        self.head.validate()?;
        for value in [
            &self.snapshot_id,
            &self.head_sha256,
            &self.recipients_sha256,
            &self.origin_spki_sha256,
        ] {
            digest(value)?;
        }
        if self.schema_version != 1
            || self.profile != SNAPSHOT_PROFILE
            || self.head_sha256 != self.head.sha256()?
            || self.recipient_generation == 0
        {
            return Err("invalid exact whole-snapshot intent".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        bounded(self, MAX_PAGE_BYTES)
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReview {
    pub schema_version: u32,
    pub profile: String,
    pub intent_sha256: String,
    pub inventory: PhysicalInventory,
    pub object_count: u64,
    pub object_bytes: u64,
    pub stream_sha256: String,
    pub review_sha256: String,
}
impl SnapshotReview {
    pub fn validate(&self, intent: &SnapshotIntent) -> Result<()> {
        intent.validate()?;
        digest(&self.stream_sha256)?;
        digest(&self.review_sha256)?;
        let complete = self
            .object_count
            .checked_sub(self.inventory.incomplete_objects)
            .ok_or("snapshot incomplete-object count exceeds inventory")?;
        if self.schema_version != 1
            || self.profile != SNAPSHOT_PROFILE
            || self.intent_sha256 != intent.sha256()?
            || self.object_count > MAX_SNAPSHOT_OBJECTS
            || self.object_bytes > MAX_SNAPSHOT_RAW_BYTES
            || self.object_bytes
                > self
                    .object_count
                    .checked_mul(MAX_PAGE_BYTES as u64)
                    .ok_or("snapshot raw byte capacity overflow")?
            || self.object_bytes < complete
            || self.inventory.regular_files.checked_sub(1) != Some(self.object_count)
            || self.inventory.logical_bytes < self.object_bytes
            || self.inventory.logical_bytes - self.object_bytes > MAX_PAGE_BYTES as u64
            || self.inventory.directories < 2
            || self.inventory.directories > 65794
            || self.inventory.incomplete_objects > self.object_count
        {
            return Err("snapshot review loses exact complete inventory coverage".into());
        }
        let mut unsigned = self.clone();
        unsigned.review_sha256.clear();
        if luma_content::sha256(&bounded(&unsigned, MAX_PAGE_BYTES)?) != self.review_sha256 {
            return Err("snapshot review digest differs".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, intent: &SnapshotIntent) -> Result<Vec<u8>> {
        self.validate(intent)?;
        bounded(self, MAX_PAGE_BYTES)
    }
    fn finish(&mut self, intent: &SnapshotIntent) -> Result<()> {
        self.review_sha256.clear();
        self.review_sha256 = luma_content::sha256(&bounded(self, MAX_PAGE_BYTES)?);
        self.validate(intent)
    }
}

/// Whole measured manifest DATA. The native receipt must independently bind
/// these exact bytes to original Export authority and the provisioned C signer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WholeSnapshotManifest {
    pub schema_version: u32,
    pub profile: String,
    pub intent: SnapshotIntent,
    pub review: SnapshotReview,
    pub parts: PartDirectoryRef,
    pub part_count: u32,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub last_plaintext_sha256: String,
}
impl WholeSnapshotManifest {
    pub fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.review.validate(&self.intent)?;
        self.parts.validate()?;
        digest(&self.last_plaintext_sha256)?;
        if self.schema_version != 1
            || self.profile != SNAPSHOT_PROFILE
            || self.parts.first != 0
            || self.part_count == 0
            || self.part_count > MAX_SNAPSHOT_PARTS
            || u64::from(self.part_count)
                != ((self.review.object_count + MAX_PART_OBJECTS as u64 - 1)
                    / MAX_PART_OBJECTS as u64)
                    .max(1)
            || self.parts.count != self.part_count
            || self.parts.objects != self.review.object_count
            || self.parts.plaintext_bytes != self.plaintext_bytes
            || self.parts.ciphertext_bytes != self.ciphertext_bytes
            || self.plaintext_bytes
                < self
                    .review
                    .object_bytes
                    .checked_add(u64::from(self.part_count) * 20)
                    .ok_or("snapshot plaintext framing size overflow")?
            || self.plaintext_bytes
                > self.review.object_bytes
                    + u64::from(self.part_count) * (MAX_PAGE_BYTES as u64 + 20)
            || self.ciphertext_bytes > self.plaintext_bytes + u64::from(self.part_count) * 65536
            || self.ciphertext_bytes > MAX_SNAPSHOT_CIPHERTEXT_BYTES
        {
            return Err("whole snapshot manifest has incomplete ordered part coverage".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        bounded(self, MAX_PAGE_BYTES)
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
fn bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("segmented snapshot canonical metadata exceeds bound".into());
    }
    Ok(bytes)
}
pub(super) fn seed(intent: &SnapshotIntent) -> Result<String> {
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-whole-snapshot-object-stream-v1",
        intent.sha256()?,
    ))?))
}
pub(super) fn extend(previous: &str, object: &SnapshotObject) -> Result<String> {
    digest(previous)?;
    object.validate()?;
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-whole-snapshot-object-stream-step-v1",
        previous,
        object,
    ))?))
}
