//! Three permanently allocated control inodes. These files are mutable DATA;
//! only their exact C-selected identity and the existing ContentAnchor can
//! identify a current selector. A failed rewrite poisons this handle, and a
//! future opener cannot interpret damaged/empty bytes as an empty authority.
use super::*;
use std::cell::Cell;
use std::io::{Seek, SeekFrom};

pub(in crate::content_checkpoint::custody) const BYTES: usize = 64 * 1024;
const NAMES: [&str; 3] = ["selector-0", "selector-1", "pending"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct Reference {
    pub index: u8,
    pub device: u64,
    pub inode: u64,
    pub mount: u64,
    pub allocated_bytes: u64,
    pub instance_id: String,
}
impl Reference {
    pub fn validate(&self) -> Result<()> {
        digest(&self.instance_id)?;
        if self.index > 2
            || self.inode == 0
            || self.mount == 0
            || self.allocated_bytes < BYTES as u64
            || self.allocated_bytes > BYTES as u64 + 64 * 1024
            || self.allocated_bytes % 512 != 0
        {
            return Err("invalid fixed control-cell physical identity DATA".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct Selection {
    pub schema_version: u32,
    pub domain: String,
    pub binding: luma_content_store::v2::custody_map::CustodyBinding,
    pub cells: [Reference; 3],
}
impl Selection {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 3 || self.domain != "luma-c-fixed-control-inodes-v3" {
            return Err("invalid closed fixed control selection DATA".into());
        }
        for (index, reference) in self.cells.iter().enumerate() {
            reference.validate()?;
            if reference.index as usize != index
                || self.cells[..index].iter().any(|old| {
                    old.device == reference.device && old.inode == reference.inode
                        || old.instance_id == reference.instance_id
                })
            {
                return Err("fixed control identities are reordered or aliased".into());
            }
        }
        Ok(())
    }
}

/// A readback observation, deliberately not a deserializable permission.
pub(in crate::content_checkpoint::custody) struct Snapshot {
    index: usize,
    identity: fs::Metadata,
    bytes: Vec<u8>,
}
impl Snapshot {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> String {
        hash(&self.bytes)
    }
}

pub(in crate::content_checkpoint::custody) struct Files<'a> {
    pages: &'a PageStore,
    selection: Selection,
    directory: PersistentDirectory,
    files: [File; 3],
    poisoned: Cell<bool>,
}

/// Physical inventory counts allocations without interpreting their mutable
/// bytes as a selected head. Partial allocation remains charged/interrupted.
pub(super) fn validate_file(
    file: &File,
    path: &Path,
    pages: &PageStore,
    expected: Option<&Reference>,
) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > BYTES as u64
        || metadata.dev() != pages.pin.identity.0
        || PersistentDirectory::mount(file)? != pages.pin.mount
    {
        return Err("fixed C control is not its bounded root-only same-mount inode".into());
    }
    let parent = MemberParent::capture(path)?;
    let named = parent.open(path, libc::O_RDONLY, 0)?;
    if file_identity(&metadata) != file_identity(&named.metadata()?)
        || PersistentDirectory::mount(&named)? != pages.pin.mount
    {
        return Err("fixed C control name no longer selects the held inode".into());
    }
    if let Some(reference) = expected {
        reference.validate()?;
        if metadata.len() != BYTES as u64
            || metadata.dev() != reference.device
            || metadata.ino() != reference.inode
            || reference.mount != pages.pin.mount
            || metadata.blocks().checked_mul(512) != Some(reference.allocated_bytes)
            || slots::instance(file)? != reference.instance_id
            || slots::instance(&named)? != reference.instance_id
        {
            return Err("fixed C control differs from exact selected allocated inode".into());
        }
    }
    parent.check()
}
impl<'a> Files<'a> {
    /// Observe bounded physical identities only. The result is not current C:
    /// a separate actual NV/descriptor join must commit exactly these observed
    /// inodes before any caller may treat them as selected controls.
    pub fn observe(pages: &'a PageStore, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        pages.check()?;
        check()?;
        let path = pages.root.join("controls");
        let directory = PersistentDirectory::capture(&path)?;
        if names(&path, 3)?
            != vec![
                "pending".to_string(),
                "selector-0".to_string(),
                "selector-1".to_string(),
            ]
        {
            return Err(
                "fixed control observation requires all and only three existing inodes".into(),
            );
        }
        let mut observed = Vec::with_capacity(3);
        for (index, name) in NAMES.iter().enumerate() {
            check()?;
            directory.check()?;
            let target = path.join(name);
            let file = MemberParent::capture(&target)?.open(&target, libc::O_RDONLY, 0)?;
            validate_file(&file, &target, pages, None)?;
            let metadata = file.metadata()?;
            if metadata.len() != BYTES as u64 {
                return Err("fixed control observation refuses a partial allocation".into());
            }
            let reference = Reference {
                index: index as u8,
                device: metadata.dev(),
                inode: metadata.ino(),
                mount: pages.pin.mount,
                allocated_bytes: metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or("control observation block overflow")?,
                instance_id: slots::instance(&file)?,
            };
            validate_file(&file, &target, pages, Some(&reference))?;
            observed.push(reference);
        }
        let selection = Selection {
            schema_version: 3,
            domain: "luma-c-fixed-control-inodes-v3".into(),
            binding: pages.binding.clone(),
            cells: observed
                .try_into()
                .map_err(|_| "observed control count changed")?,
        };
        directory.check()?;
        check()?;
        Self::open(pages, selection, check)
    }
    /// Exclusive initial creation is possible only before selecting the new
    /// control identities. It never reopens/adopts a partial previous attempt.
    pub fn create(
        pages: &'a PageStore,
        initial: [&[u8]; 3],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        pages.check()?;
        check()?;
        if initial.iter().any(|bytes| bytes.len() != BYTES) {
            return Err("fixed control initialization requires three complete frames".into());
        }
        let path = pages.root.join("controls");
        let directory = PersistentDirectory::capture(&path)?;
        if !names(&path, 3)?.is_empty() {
            return Err("fixed controls already exist or are partial; no adoption".into());
        }
        let mut observed = Vec::with_capacity(3);
        for (index, name) in NAMES.iter().enumerate() {
            pages.check()?;
            check()?;
            directory.check()?;
            pages.reserve_create(BYTES as u64, false)?;
            let target = path.join(name);
            let parent = MemberParent::capture(&target)?;
            let mut file =
                parent.open(&target, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600)?;
            validate_file(&file, &target, pages, None)?;
            let instance_id = slots::create_instance(&file)?;
            physical::allocate(&file, BYTES, check)?;
            for block in initial[index].chunks(4096) {
                pages.check()?;
                check()?;
                directory.check()?;
                validate_file(&file, &target, pages, None)?;
                file.write_all(block)?;
            }
            file.sync_all()?;
            parent.file.sync_all()?;
            let metadata = file.metadata()?;
            let reference = Reference {
                index: index as u8,
                device: metadata.dev(),
                inode: metadata.ino(),
                mount: pages.pin.mount,
                allocated_bytes: metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or("control block count overflow")?,
                instance_id,
            };
            validate_file(&file, &target, pages, Some(&reference))?;
            pages.allocation_completed()?;
            observed.push(reference);
        }
        directory.file.sync_all()?;
        let selection = Selection {
            schema_version: 3,
            domain: "luma-c-fixed-control-inodes-v3".into(),
            binding: pages.binding.clone(),
            cells: observed
                .try_into()
                .map_err(|_| "control identity count changed")?,
        };
        let opened = Self::open(pages, selection, check)?;
        for (index, wanted) in initial.iter().enumerate() {
            if opened.read(index, check)?.bytes() != *wanted {
                return Err("fixed control complete initialization readback differs".into());
            }
        }
        Ok(opened)
    }
    /// The caller must obtain Selection from an actual current C descriptor or
    /// the independently held pre-dispatch preparation, never mutable filenames.
    pub fn open(
        pages: &'a PageStore,
        selection: Selection,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        selection.validate()?;
        pages.check()?;
        check()?;
        if selection.binding != *pages.binding() {
            return Err("fixed controls cross independent C identity".into());
        }
        let path = pages.root.join("controls");
        let directory = PersistentDirectory::capture(&path)?;
        if names(&path, 3)?
            != vec![
                "pending".to_string(),
                "selector-0".to_string(),
                "selector-1".to_string(),
            ]
        {
            return Err("fixed controls are incomplete or have unknown namespace members".into());
        }
        let mut opened = Vec::with_capacity(3);
        for (index, name) in NAMES.iter().enumerate() {
            check()?;
            directory.check()?;
            let member = path.join(name);
            let file = MemberParent::capture(&member)?.open(&member, libc::O_RDWR, 0)?;
            validate_file(&file, &member, pages, Some(&selection.cells[index]))?;
            opened.push(file);
        }
        let files = Self {
            pages,
            selection,
            directory,
            files: opened
                .try_into()
                .map_err(|_| "fixed control fd count changed")?,
            poisoned: Cell::new(false),
        };
        files.check(check)?;
        Ok(files)
    }
    pub fn selection(&self) -> &Selection {
        &self.selection
    }
    fn path(&self, index: usize) -> Result<PathBuf> {
        Ok(self
            .pages
            .root
            .join("controls")
            .join(NAMES.get(index).ok_or("invalid fixed control index")?))
    }
    fn check(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.pages.check()?;
        self.directory.check()?;
        if self.poisoned.get() {
            return Err(
                "uncertain fixed control write requires fresh explicit reconciliation".into(),
            );
        }
        if self.directory.mount != self.pages.pin.mount
            || self.directory.identity.0 != self.pages.pin.identity.0
        {
            return Err("fixed control directory crossed protected C backing mount".into());
        }
        for (index, file) in self.files.iter().enumerate() {
            validate_file(
                file,
                &self.path(index)?,
                self.pages,
                Some(&self.selection.cells[index]),
            )?;
        }
        check()
    }
    // During a bounded read the other two controls are checked at the whole
    // operation boundaries. Every individual I/O still joins fresh original
    // authority and this exact retained/named inode, including mount and xattr.
    fn check_member(&self, index: usize, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.pages.check()?;
        self.directory.check()?;
        if self.poisoned.get()
            || self.directory.mount != self.pages.pin.mount
            || self.directory.identity.0 != self.pages.pin.identity.0
        {
            return Err("fixed control read lost its held protected directory".into());
        }
        let file = self.files.get(index).ok_or("invalid fixed control index")?;
        validate_file(
            file,
            &self.path(index)?,
            self.pages,
            Some(&self.selection.cells[index]),
        )?;
        check()
    }
    pub fn read(&self, index: usize, check: &mut impl FnMut() -> Result<()>) -> Result<Snapshot> {
        self.check(check)?;
        let source = self.files.get(index).ok_or("invalid fixed control index")?;
        let before = source.metadata()?;
        let mut file = source.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0_u8; BYTES];
        for block in bytes.chunks_mut(4096) {
            self.check_member(index, check)?;
            if file_identity(&file.metadata()?) != file_identity(&before) {
                return Err("fixed control changed during bounded read".into());
            }
            file.read_exact(block)?;
            self.check_member(index, check)?;
        }
        let mut extra = [0_u8; 1];
        if file.read(&mut extra)? != 0 || file_identity(&file.metadata()?) != file_identity(&before)
        {
            return Err("fixed control changed length or identity during complete read".into());
        }
        self.check(check)?;
        Ok(Snapshot {
            index,
            identity: before,
            bytes,
        })
    }
    /// Compare/readback is bounded but not a kernel CAS. The existing C flock
    /// excludes other product writers. External mutation or original revocation
    /// preserves uncertainty; this method never retries/truncates/replaces.
    pub fn rewrite(
        &self,
        expected: &Snapshot,
        next: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Snapshot> {
        if next.len() != BYTES {
            return Err("fixed control rewrite is not one whole bounded frame".into());
        }
        let current = self.read(expected.index, check)?;
        if file_identity(&current.identity) != file_identity(&expected.identity)
            || current.bytes != expected.bytes
        {
            return Err("fixed control changed after reviewed preparation".into());
        }
        check()?;
        let source = self
            .files
            .get(expected.index)
            .ok_or("invalid fixed control index")?;
        let mut file = source.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        self.poisoned.set(true);
        let operation = (|| -> Result<()> {
            for block in next.chunks(4096) {
                check()?;
                self.pages.check()?;
                self.directory.check()?;
                validate_file(
                    &file,
                    &self.path(expected.index)?,
                    self.pages,
                    Some(&self.selection.cells[expected.index]),
                )?;
                file.write_all(block)?;
                check()?;
            }
            file.sync_all()?;
            validate_file(
                &file,
                &self.path(expected.index)?,
                self.pages,
                Some(&self.selection.cells[expected.index]),
            )?;
            check()
        })();
        operation?;
        self.poisoned.set(false);
        let result = self.read(expected.index, check);
        match result {
            Ok(snapshot) if snapshot.bytes == next => Ok(snapshot),
            Ok(_) => {
                self.poisoned.set(true);
                Err("fixed control full-frame write readback differs".into())
            }
            Err(error) => {
                self.poisoned.set(true);
                Err(error)
            }
        }
    }
}
#[cfg(test)]
#[path = "cells/tests.rs"]
mod tests;
