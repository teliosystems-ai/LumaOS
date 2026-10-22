//! Ephemeral provenance of actual C-produced index DATA. No entry authenticates
//! a principal, renews a grant or replaces current C/lease/output checks.
use super::*;
use crate::content_index::request::Input;
use crate::service::content_output::{Descriptor, IndexProof};
use std::sync::{Mutex, OnceLock};

const COUNT: usize = 64;
const BYTES: usize = 256 * 1024;
const TTL_MS: u64 = 25_000;

#[derive(Serialize)]
struct Key {
    audit: Audit,
    source_sha256: String,
    profile: String,
    binding: OwnerBinding,
    lease: crate::resources::Token,
}
impl Key {
    fn descriptor(descriptor: &Descriptor, audit: &Audit) -> Result<Self> {
        audit.validate()?;
        let input = descriptor
            .index_source()?
            .ok_or("index output lacks exact canonical source")?;
        if audit.usage != descriptor.usage()?
            || audit.subject != input.binding.owner
            || audit.subject_generation != input.binding.owner_generation
            || audit.operation_id.is_none()
        {
            return Err(
                "index output differs from actual original finite owner attribution".into(),
            );
        }
        Ok(Self {
            audit: audit.clone(),
            source_sha256: input.sha256()?,
            profile: descriptor.profile.clone(),
            binding: descriptor.binding.clone(),
            lease: descriptor.lease.clone(),
        })
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.audit.validate()?;
        self.binding.validate()?;
        digest(&self.source_sha256)?;
        if !crate::workflow_resource::token_valid(&self.lease) {
            return Err("index producer lease malformed".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 4096 {
            return Err("index producer key exceeds bounded memory".into());
        }
        Ok(bytes)
    }
}
struct Entry {
    key: Vec<u8>,
    selection: String,
    result: String,
    until_ms: u64,
}
impl Entry {
    fn size(&self) -> usize {
        self.key.len() + self.selection.len() + self.result.len() + 64
    }
}
#[derive(Default)]
struct Registry {
    entries: BTreeMap<String, Entry>,
    bytes: usize,
}
impl Registry {
    fn prune(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.until_ms > now);
        self.bytes = self.entries.values().map(Entry::size).sum();
    }
    fn remember(&mut self, key: &Key, selection: &str, result: &str, now: u64) -> Result<()> {
        digest(selection)?;
        digest(result)?;
        let key = key.bytes()?;
        let id = hash(&key);
        self.prune(now);
        if let Some(old) = self.entries.get(&id) {
            if old.key != key || old.selection != selection || old.result != result {
                return Err(
                    "one original index operation cannot relabel changed selection/results".into(),
                );
            }
            return Ok(()); // Reobservation never renews the data retention TTL.
        }
        let entry = Entry {
            key,
            selection: selection.into(),
            result: result.into(),
            until_ms: now
                .checked_add(TTL_MS)
                .ok_or("index producer data TTL overflow")?,
        };
        if self.entries.len() >= COUNT
            || self
                .bytes
                .checked_add(entry.size())
                .map_or(true, |n| n > BYTES)
        {
            return Err("index producer observation storage exhausted; no private output".into());
        }
        self.bytes += entry.size();
        self.entries.insert(id, entry);
        Ok(())
    }
    fn require(&mut self, key: &Key, selection: &str, result: &str, now: u64) -> Result<()> {
        let key = key.bytes()?;
        self.prune(now);
        let entry = self
            .entries
            .get(&hash(&key))
            .ok_or("actual C index result missing/expired; fresh Read required")?;
        if entry.key != key || entry.selection != selection || entry.result != result {
            return Err("private index output differs from actually C-produced DATA".into());
        }
        Ok(())
    }
}
fn registry() -> &'static Mutex<Registry> {
    static VALUE: OnceLock<Mutex<Registry>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(Registry::default()))
}

pub(super) fn remember(
    original: &mut protocol::OriginalCOperation<'_>,
    input: &Input,
    selection_sha256: &str,
    result: &serde_json::Value,
) -> Result<()> {
    original.check()?;
    let source = original.source_binding();
    if source.purpose != protocol::SourcePurpose::IndexRead
        || source.binding != input.binding
        || source.worker_label != "luma-acquisition (enforce)"
    {
        return Err(
            "index producer data requires the actual original index worker operation".into(),
        );
    }
    let output = serde_json::to_vec(result)?;
    if output.is_empty() || output.len() as u64 > original.audit().usage.output_bytes {
        return Err("actual index result exceeds original finite output".into());
    }
    let descriptor = Descriptor {
        profile: source.profile.clone(),
        storage_device: source.storage_device.clone(),
        binding: source.binding.clone(),
        lease: source.lease.clone(),
        output_sha256: hash(&output),
        paged_head_sha256: None,
        paged_source: None,
        index: Some(IndexProof {
            selection_sha256: selection_sha256.into(),
            source: String::from_utf8(input.canonical_bytes()?)?,
        }),
    };
    let key = Key::descriptor(&descriptor, original.audit())?;
    registry()
        .lock()
        .map_err(|_| "index producer registry poisoned")?
        .remember(
            &key,
            selection_sha256,
            &descriptor.output_sha256,
            crate::resource_manager::now()?,
        )?;
    original.check()
}

pub(super) fn require(
    descriptor: &Descriptor,
    audit: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let key = Key::descriptor(descriptor, audit)?;
    let proof = descriptor
        .index
        .as_ref()
        .ok_or("actual index producer selection missing")?;
    registry()
        .lock()
        .map_err(|_| "index producer registry poisoned")?
        .require(
            &key,
            &proof.selection_sha256,
            &descriptor.output_sha256,
            crate::resource_manager::now()?,
        )?;
    check()
}

#[cfg(test)]
#[path = "indexed_output/tests.rs"]
pub(super) mod tests;
