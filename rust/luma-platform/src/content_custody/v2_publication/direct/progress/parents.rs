//! Retained directory observations for exact progress preparation. Only the
//! existing tails parent may grow; every other existing directory's block
//! count must remain unchanged. All comparisons use named AND retained FDs.
use super::super::super::parent_allocation::{Delta, Observation, GROWING, MAX_GROWTH};
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
            if parent.name == GROWING {
                delta = Some(Delta::grown(parent.before.clone(), after)?);
            } else if parent.before.device != after.device
                || parent.before.inode != after.inode
                || parent.before.mount != after.mount
                || parent.before.allocated_bytes != after.allocated_bytes
            {
                return Err("an unreviewed existing C directory changed allocated blocks".into());
            }
        }
        check()?;
        delta.ok_or_else(|| "exact direct tails parent observation missing".into())
    }
}
pub(super) fn verify_after(
    pages: &PageStore,
    delta: &Delta,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    delta.validate()?;
    let pin = PersistentDirectory::capture(&pages.root.join(GROWING))?;
    if observation(&pin, check)? != delta.after {
        return Err("selected C parent delta lost its actual current after observation".into());
    }
    pages.check()?;
    check()
}
pub(super) fn growth_budget() -> u64 {
    MAX_GROWTH
}
#[cfg(test)]
mod tests {
    //! Real disposable-filesystem tests, not installed custody qualification.
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            assert!(Path::new("/.dockerenv").is_file());
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let base = PathBuf::from(
                std::env::var("LUMA_STORAGE_TEST_ROOT")
                    .expect("explicit disposable ext4 data root required"),
            );
            let path = base.join(format!(
                "luma-tpm-direct-parents-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            assert_eq!(std::fs::canonicalize(&path).unwrap(), path);
            Self(path)
        }
        fn pages(&self) -> PageStore {
            PageStore::create(
                &self.0,
                luma_content_store::v2::custody_map::CustodyBinding {
                    installation: "11".repeat(32),
                    sealed_genesis_sha256: "22".repeat(32),
                },
                &mut || Ok(()),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(Path::new("/.dockerenv").is_file());
            assert_eq!(std::fs::canonicalize(&self.0).unwrap(), self.0);
            assert!(self
                .0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("luma-tpm-direct-parents-"));
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    /// One ext4 block holds about 56 job names, so 64 cross into the next.
    fn job_names(pages: &PageStore, parent: &str) {
        for number in 0..64_u32 {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(pages.root.join(parent).join(format!("{number:064x}")))
                .unwrap();
        }
    }
    #[test]
    fn actual_job_namespaces_grow_only_the_reviewed_tails_parent() {
        let fixture = Fixture::new();
        let pages = fixture.pages();
        let mut check = || -> Result<()> { Ok(()) };
        let parents = Parents::capture(&pages, &mut check).unwrap();
        job_names(&pages, GROWING);
        let delta = parents.finish(&mut check).unwrap();
        assert!(delta.after.allocated_bytes > delta.before.allocated_bytes);
        verify_after(&pages, &delta, &mut check).unwrap();
        let parents = Parents::capture(&pages, &mut check).unwrap();
        job_names(&pages, "attempts");
        assert_eq!(
            parents.finish(&mut check).unwrap_err().to_string(),
            "an unreviewed existing C directory changed allocated blocks"
        );
    }
}
