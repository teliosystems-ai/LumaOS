//! Bounded immutable v2 data foundations. These APIs never select a current
//! content/custody head, authenticate a receipt, migrate an owner or publish an
//! index. Production callers must independently supply selected roots and a
//! genuinely live [`crate::Boundary`]. Unselected/partial objects are retained.
use crate::{Access, Boundary, DecisionKind, ResourceBudget, Result};
use luma_content::OwnerBinding;
use serde::{Deserialize, Serialize};

pub mod custody;
mod map;
mod objects;
mod page;
mod segment;
pub use map::{LookupProof, MapEdit, MapRoot};
pub use objects::{Allocation, BlobReference, ObjectStore, PhysicalInventory};
pub use page::{MapKind, PageRef};
pub use segment::{SealedSegment, SegmentDescriptor, SegmentInput};

pub const DOMAIN: &str = "luma-editable-content-store-v2";
pub const MAX_PAGE_BYTES: usize = 16 * 1024;
pub const MAX_MAP_ENTRIES: u64 = 1_048_576;
pub const MAX_MAP_HEIGHT: u8 = 8;
pub const MAX_MAP_EDITS: usize = 256;
pub const MAX_VALUE_BYTES: usize = 1024;
pub const MAX_SEGMENT_OUTCOMES: usize = 256;
pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SEGMENTS: u64 = 4096;

/// A finite resource ceiling, not evidence that resources have been reserved.
#[derive(Clone, Copy, Debug)]
pub struct IoBudget {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub new_files: u32,
}
impl IoBudget {
    pub fn validate(&self) -> Result<()> {
        if self.read_bytes == 0
            || self.read_bytes > 512 * 1024 * 1024
            || self.write_bytes > 256 * 1024 * 1024
            || self.new_files > 32768
            || (self.write_bytes == 0) != (self.new_files == 0)
        {
            return Err("invalid finite v2 I/O budget".into());
        }
        Ok(())
    }
}

/// Original reviewed effect metadata. This is data passed to the real Boundary;
/// possession or deserialization is never permission to write immutable objects.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub review_sha256: String,
    pub decision: DecisionKind,
    pub source_bytes: u64,
}
impl Mutation {
    fn validate(&self) -> Result<()> {
        digest(&self.review_sha256)?;
        if self.source_bytes > MAX_SEGMENT_BYTES {
            return Err("v2 mutation source exceeds segment bound".into());
        }
        Ok(())
    }
}

pub(super) fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value.bytes().all(|b| b == b'0')
    {
        return Err("invalid nonzero canonical SHA256".into());
    }
    Ok(())
}
pub(super) fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid v2 identifier".into());
    }
    Ok(())
}
pub(super) fn canonical<T: Serialize + for<'de> Deserialize<'de>>(
    bytes: &[u8],
    limit: usize,
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("v2 canonical input exceeds bound".into());
    }
    let parsed: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&parsed)? != bytes {
        return Err("v2 requires exact closed canonical bytes".into());
    }
    Ok(parsed)
}
pub(super) struct Guard<'a, B: Boundary> {
    boundary: &'a mut B,
    binding: &'a OwnerBinding,
    budget: IoBudget,
    mutation: Option<&'a Mutation>,
    read: u64,
    written: u64,
    files: u32,
}
impl<'a, B: Boundary> Guard<'a, B> {
    fn new(
        boundary: &'a mut B,
        binding: &'a OwnerBinding,
        budget: IoBudget,
        mutation: Option<&'a Mutation>,
    ) -> Result<Self> {
        binding.validate()?;
        budget.validate()?;
        if let Some(value) = mutation {
            value.validate()?;
        }
        if mutation.is_none() && budget.write_bytes != 0 {
            return Err("read admission cannot reserve v2 writes".into());
        }
        boundary.admit(
            binding,
            ResourceBudget {
                memory_bytes: 192 * 1024 * 1024,
                tasks: 1,
                read_bytes: budget.read_bytes,
                write_bytes: budget.write_bytes,
                additional_storage_bytes: budget
                    .write_bytes
                    .checked_add(u64::from(budget.new_files) * 8192)
                    .ok_or("v2 physical reservation overflow")?,
            },
        )?;
        let mut value = Self {
            boundary,
            binding,
            budget,
            mutation,
            read: 0,
            written: 0,
            files: 0,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&mut self) -> Result<()> {
        self.boundary.check(Access::Inspect {
            binding: self.binding,
        })?;
        if let Some(value) = self.mutation {
            self.boundary.check(Access::Mutate {
                binding: self.binding,
                review_sha256: &value.review_sha256,
                decision: value.decision,
                source_bytes: value.source_bytes,
                storage_bytes: self.budget.write_bytes,
            })?;
        }
        Ok(())
    }
    fn read(&mut self, bytes: u64) -> Result<()> {
        self.check()?;
        self.read = self.read.checked_add(bytes).ok_or("v2 read overflow")?;
        if self.read > self.budget.read_bytes {
            return Err("v2 read budget exhausted".into());
        }
        Ok(())
    }
    fn write(&mut self, bytes: u64) -> Result<()> {
        self.check()?;
        if self.mutation.is_none() {
            return Err("v2 write requires original effect boundary".into());
        }
        self.written = self.written.checked_add(bytes).ok_or("v2 write overflow")?;
        self.files = self.files.checked_add(1).ok_or("v2 file overflow")?;
        if self.written > self.budget.write_bytes || self.files > self.budget.new_files {
            return Err("v2 write/file budget exhausted".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
