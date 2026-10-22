//! Bounded actual-C producer provenance DATA, never cached authorization.
//! Lost/restarted/expired observations cannot be adopted from disk or JSON.
use super::*;
use std::collections::BTreeMap;
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
    fn descriptor(
        descriptor: &crate::service::content_output::Descriptor,
        audit: &Audit,
    ) -> Result<Self> {
        let page = descriptor
            .page_source()?
            .ok_or("C Page provenance requires exact paged source")?;
        page.check_original(audit)?;
        Ok(Self {
            audit: audit.clone(),
            source_sha256: page.source_sha256().into(),
            profile: page.profile().into(),
            binding: page.binding().clone(),
            lease: descriptor.lease.clone(),
        })
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.audit.validate()?;
        self.binding.validate()?;
        digest(&self.source_sha256)?;
        if !crate::workflow_resource::token_valid(&self.lease) {
            return Err("C Page observation lease malformed".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 4096 {
            return Err("C Page observation key exceeds fixed bound".into());
        }
        Ok(bytes)
    }
}
struct Entry {
    key: Vec<u8>,
    head: String,
    result: String,
    until_ms: u64,
}
impl Entry {
    fn size(&self) -> usize {
        self.key.len() + self.head.len() + self.result.len() + 64
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
    fn remember(&mut self, key: &Key, head: &str, result: &str, now: u64) -> Result<()> {
        digest(head)?;
        digest(result)?;
        let key = key.bytes()?;
        let id = hash(&key);
        self.prune(now);
        if let Some(old) = self.entries.get(&id) {
            if old.key != key || old.head != head || old.result != result {
                return Err(
                    "same original Page cannot relabel different result/current head".into(),
                );
            }
            // A repeated exact observation does NOT renew its resource TTL.
            return Ok(());
        }
        let entry = Entry {
            key,
            head: head.into(),
            result: result.into(),
            until_ms: now
                .checked_add(TTL_MS)
                .ok_or("C Page observation deadline overflow")?,
        };
        if self.entries.len() >= COUNT
            || self
                .bytes
                .checked_add(entry.size())
                .map_or(true, |bytes| bytes > BYTES)
        {
            return Err("C Page producer observation capacity exhausted; no private output".into());
        }
        self.bytes += entry.size();
        self.entries.insert(id, entry);
        Ok(())
    }
    fn require(&mut self, key: &Key, head: &str, result: &str, now: u64) -> Result<()> {
        let key = key.bytes()?;
        self.prune(now);
        let found = self
            .entries
            .get(&hash(&key))
            .ok_or("actual C Page producer observation missing/expired; fresh Read required")?;
        if found.key != key || found.head != head || found.result != result {
            return Err(
                "output metadata/result differs from actually observed C-produced Page".into(),
            );
        }
        Ok(())
    }
}
fn registry() -> &'static Mutex<Registry> {
    static VALUE: OnceLock<Mutex<Registry>> = OnceLock::new();
    VALUE.get_or_init(|| Mutex::new(Registry::default()))
}
pub(super) fn remember<A: Checkpoint>(
    current: &mut Current<'_, '_, A>,
    result: &serde_json::Value,
) -> Result<()> {
    current.check()?;
    current.source.validate_result(result)?;
    let key = Key {
        audit: current.original.audit().clone(),
        source_sha256: current.source.source_sha256().into(),
        profile: current.source.profile().into(),
        binding: current.source.binding().clone(),
        lease: current.original.source_binding().lease.clone(),
    };
    registry()
        .lock()
        .map_err(|_| "C Page producer observation registry poisoned")?
        .remember(
            &key,
            &current.head.sha256()?,
            &hash(&serde_json::to_vec(result)?),
            crate::resource_manager::now()?,
        )?;
    current.check()
}
pub(super) fn require(
    descriptor: &crate::service::content_output::Descriptor,
    audit: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let key = Key::descriptor(descriptor, audit)?;
    let head = descriptor
        .paged_head_sha256
        .as_ref()
        .ok_or("C Page output head missing")?;
    registry()
        .lock()
        .map_err(|_| "C Page producer observation registry poisoned")?
        .require(
            &key,
            head,
            &descriptor.output_sha256,
            crate::resource_manager::now()?,
        )?;
    check()
}
#[cfg(test)]
#[path = "record/tests.rs"]
mod tests;
