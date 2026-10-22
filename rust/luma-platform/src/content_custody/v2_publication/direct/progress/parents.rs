//! Retained directory observations for exact progress preparation. Only the
//! existing attempts parent may grow; every other existing directory's block
//! count must remain unchanged. All comparisons use named AND retained FDs.
use super::super::super::parent_allocation::{Delta, Observation, MAX_GROWTH};
use super::*;
use crate::content_checkpoint::PersistentDirectory;
use std::os::unix::fs::MetadataExt;
struct Parent {
    name: &'static str,
    pin: PersistentDirectory,
    before: Observation,
}
pub(super) struct Parents(Vec<Parent>);
fn observation(
    pin: &PersistentDirectory,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Observation> {
    check()?;
    pin.check()?;
    let named = PersistentDirectory::open(&pin.path)?;
    let before = pin.file.metadata()?;
    let current = named.metadata()?;
    let mount = PersistentDirectory::mount(&pin.file)?;
    if file_identity(&before) != file_identity(&current)
        || before.blocks() != current.blocks()
        || PersistentDirectory::mount(&named)? != mount
    {
        return Err("existing direct parent changed its named/held physical observation".into());
    }
    let value = Observation {
        device: before.dev(),
        inode: before.ino(),
        mount,
        allocated_bytes: before
            .blocks()
            .checked_mul(512)
            .ok_or("direct parent blocks overflow")?,
        ctime_seconds: before.ctime(),
        ctime_nanoseconds: before.ctime_nsec(),
    };
    pin.check()?;
    check()?;
    Ok(value)
}
impl Parents {
    pub fn capture(pages: &PageStore, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        pages.check()?;
        let mut held = Vec::with_capacity(6);
        for name in ["", "pages", "records", "attempts", "controls", "tails"] {
            let pin = PersistentDirectory::capture(&pages.root.join(name))?;
            let before = observation(&pin, check)?;
            held.push(Parent { name, pin, before });
        }
        pages.check()?;
        check()?;
        Ok(Self(held))
    }
    pub fn finish(&self, check: &mut impl FnMut() -> Result<()>) -> Result<Delta> {
        let mut delta = None;
        for parent in &self.0 {
            let after = observation(&parent.pin, check)?;
            if parent.name == "attempts" {
                let value = Delta {
                    schema_version: 4,
                    domain: "luma-c-direct-attempts-parent-allocation-v4".into(),
                    before: parent.before.clone(),
                    after,
                };
                value.validate()?;
                delta = Some(value);
            } else if parent.before.device != after.device
                || parent.before.inode != after.inode
                || parent.before.mount != after.mount
                || parent.before.allocated_bytes != after.allocated_bytes
            {
                return Err("an unreviewed existing C directory changed allocated blocks".into());
            }
        }
        check()?;
        delta.ok_or_else(|| "exact direct attempts parent observation missing".into())
    }
}
pub(super) fn verify_after(
    pages: &PageStore,
    delta: &Delta,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    delta.validate()?;
    let pin = PersistentDirectory::capture(&pages.root.join("attempts"))?;
    if observation(&pin, check)? != delta.after {
        return Err("selected C parent delta lost its actual current after observation".into());
    }
    pages.check()?;
    check()
}
pub(super) fn growth_budget() -> u64 {
    MAX_GROWTH
}
