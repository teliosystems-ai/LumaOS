//! Exact immutable storage for the separately versioned C paged namespace.
//! No opener adopts a missing namespace, selects NV, or repairs partial bytes.
use super::super::PersistentDirectory;
use super::*;
use std::cell::RefCell;
use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
// Exact cells and slots back the direct C publisher; native slot allocation
// and physical tails are not yet joined to the production service.
#[cfg_attr(not(test), allow(dead_code))]
#[path = "paged/cells.rs"]
pub(super) mod cells;
#[cfg_attr(not(test), allow(dead_code))]
#[path = "paged/slots.rs"]
pub(super) mod slots;

pub(super) const NAME: &str = "paged-v3";
pub(super) const PAGE_BYTES: usize = 16 * 1024;
pub(super) const FILE_BYTES: usize = 1024 * 1024;
const CONTROL_BYTES: usize = 64 * 1024;
const MAX_PAGES: u64 = 1_048_576;
const MAX_ATTEMPTS: u64 = 1_048_576;
const MAX_ALLOCATED: u64 = 24 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema_version: u32,
    purpose: String,
    binding: luma_content_store::v2::custody_map::CustodyBinding,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalInventory {
    pub files: u64,
    pub directories: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub interrupted_files: u64,
}
impl PhysicalInventory {
    fn add(&mut self, metadata: &fs::Metadata, directory: bool) -> Result<()> {
        if directory {
            self.directories = self
                .directories
                .checked_add(1)
                .ok_or("C directory inventory overflow")?;
        } else {
            self.files = self
                .files
                .checked_add(1)
                .ok_or("C file inventory overflow")?;
            self.logical_bytes = self
                .logical_bytes
                .checked_add(metadata.len())
                .ok_or("C logical inventory overflow")?;
            if metadata.len() == 0 {
                self.interrupted_files = self
                    .interrupted_files
                    .checked_add(1)
                    .ok_or("C interrupted file count overflow")?;
            }
        }
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(
                metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or("C allocated block overflow")?,
            )
            .ok_or("C inventory allocation overflow")?;
        if self.files > MAX_PAGES + MAX_ATTEMPTS * 8 + 8
            || self.directories > MAX_ATTEMPTS + 2 * 65536 + 8
            || self.logical_bytes > MAX_ALLOCATED
            || self.allocated_bytes > MAX_ALLOCATED
        {
            return Err("paged C finite namespace capacity exhausted; no purge/adoption".into());
        }
        Ok(())
    }
}
struct WriteAdmission {
    remaining_bytes: u64,
    remaining_files: u64,
    remaining_directories: u64,
    poisoned: bool,
}
pub(crate) struct PageStore {
    pub(super) root: PathBuf,
    pin: PersistentDirectory,
    children: Vec<PersistentDirectory>,
    binding: luma_content_store::v2::custody_map::CustodyBinding,
    identity: Vec<u8>,
    identity_pin: File,
    identity_metadata: fs::Metadata,
    writes: RefCell<Option<WriteAdmission>>,
}
fn prefix(value: &str) -> Result<()> {
    if value.len() != 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical paged C prefix".into());
    }
    Ok(())
}
fn regular(metadata: &fs::Metadata, bound: usize) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o400
        || metadata.len() > bound as u64
    {
        return Err("paged C member is not bounded immutable root-owned0400".into());
    }
    Ok(())
}
fn names(path: &Path, limit: usize) -> Result<Vec<String>> {
    if limit > 256 {
        return Err("large C directory must use constant-memory streaming inventory".into());
    }
    if fs::canonicalize(path)? != path {
        return Err("paged C inventory path alias".into());
    }
    let before = fs::symlink_metadata(path)?;
    let mut output = BTreeSet::new();
    for item in fs::read_dir(path)? {
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| "nonUTF8 C member")?;
        valid_name(&name)?;
        if output.len() >= limit || !output.insert(name) {
            return Err("paged C directory entry bound/uniqueness invalid".into());
        }
    }
    if file_identity(&before) != file_identity(&fs::symlink_metadata(path)?) {
        return Err("paged C directory changed during inventory".into());
    }
    Ok(output.into_iter().collect())
}
fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
    {
        return Err("noncanonical bounded C directory entry".into());
    }
    Ok(())
}
fn visit_names(path: &Path, limit: usize, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
    if fs::canonicalize(path)? != path {
        return Err("paged C streaming inventory path alias".into());
    }
    let before = fs::symlink_metadata(path)?;
    for (index, item) in fs::read_dir(path)?.enumerate() {
        if index >= limit {
            return Err("paged C streaming directory count exceeded".into());
        }
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| "nonUTF8 C directory entry")?;
        valid_name(&name)?;
        visit(&name)?;
    }
    if file_identity(&before) != file_identity(&fs::symlink_metadata(path)?) {
        return Err("paged C directory changed during streaming inventory".into());
    }
    Ok(())
}
impl PageStore {
    /// Called only by the independently reconstructed legacy migration path.
    /// create_dir is exclusive; a previous partial directory always refuses.
    pub(super) fn create(
        base: &Path,
        binding: luma_content_store::v2::custody_map::CustodyBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        check()?;
        let root = base.join(NAME);
        let parent = MemberParent::capture(&root)?;
        parent.check()?;
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        parent.file.sync_all()?;
        check()?;
        for name in ["pages", "records", "attempts", "controls", "tails"] {
            fs::DirBuilder::new().mode(0o700).create(root.join(name))?;
            File::open(root.join(name))?.sync_all()?;
        }
        File::open(&root)?.sync_all()?;
        let identity = serde_json::to_vec(&Identity {
            schema_version: 3,
            purpose: "luma-content-paged-namespace-v3".into(),
            binding: binding.clone(),
        })?;
        Self::create_file_at(&root.join("identity.json"), &identity, check)?;
        Self::open(base, binding, check)
    }
    pub(super) fn open(
        base: &Path,
        binding: luma_content_store::v2::custody_map::CustodyBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        check()?;
        let root = base.join(NAME);
        let pin = PersistentDirectory::capture(&root)?;
        let path = root.join("identity.json");
        let parent = MemberParent::capture(&path)?;
        let identity_pin = parent.open(&path, libc::O_RDONLY, 0)?;
        let identity_metadata = parent.member(&identity_pin, 4096)?;
        let expected = serde_json::to_vec(&Identity {
            schema_version: 3,
            purpose: "luma-content-paged-namespace-v3".into(),
            binding: binding.clone(),
        })?;
        let children = ["pages", "records", "attempts", "controls", "tails"]
            .into_iter()
            .map(|name| PersistentDirectory::capture(&root.join(name)))
            .collect::<Result<Vec<_>>>()?;
        let store = Self {
            root,
            pin,
            children,
            binding,
            identity: expected,
            identity_pin,
            identity_metadata,
            writes: RefCell::new(None),
        };
        if store.read("identity.json", 4096, check)? != store.identity {
            return Err("paged C namespace identity bytes differ; no adoption".into());
        }
        store.check()?;
        check()?;
        Ok(store)
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn binding(&self) -> &luma_content_store::v2::custody_map::CustodyBinding {
        &self.binding
    }
    pub(super) fn require_hash_controls_empty(&self) -> Result<()> {
        self.check()?;
        if !names(&self.root.join("controls"), 3)?.is_empty()
            || fs::read_dir(self.root.join("tails"))?
                .next()
                .transpose()?
                .is_some()
        {
            return Err("fixed direct-slot control evidence exists; hashed C opener cannot adopt or ignore it".into());
        }
        Ok(())
    }
    pub(super) fn check(&self) -> Result<()> {
        self.pin.check()?;
        if fs::canonicalize(&self.root)? != self.root {
            return Err("paged C root alias changed".into());
        }
        if file_identity(&self.identity_pin.metadata()?) != file_identity(&self.identity_metadata)
            || file_identity(&fs::symlink_metadata(self.root.join("identity.json"))?)
                != file_identity(&self.identity_metadata)
        {
            return Err("paged C held identity changed".into());
        }
        let allowed = [
            "attempts",
            "identity.json",
            "pages",
            "records",
            "pending.json",
            "selected.json",
            "controls",
            "tails",
        ];
        if names(&self.root, allowed.len())?
            .iter()
            .any(|n| !allowed.contains(&n.as_str()))
        {
            return Err("unknown paged C root member".into());
        }
        for current in &self.children {
            current.check()?;
            if current.mount != self.pin.mount || current.identity.0 != self.pin.identity.0 {
                return Err("paged C namespace crossed installed mount".into());
            }
        }
        Ok(())
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 256
            || name.split('/').any(|n| {
                n.is_empty()
                    || n == "."
                    || n == ".."
                    || !n
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            })
        {
            return Err("invalid closed paged C relative member".into());
        }
        Ok(self.root.join(name))
    }
    pub(super) fn read(
        &self,
        name: &str,
        bound: usize,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        if bound == 0 || bound > FILE_BYTES {
            return Err("paged C read bound invalid".into());
        }
        self.check()?;
        check()?;
        let path = self.path(name)?;
        let parent = MemberParent::capture(&path)?;
        let mut file = parent.open(&path, libc::O_RDONLY, 0)?;
        let before = parent.member(&file, bound as u64)?;
        if before.len() == 0 {
            return Err("interrupted paged C member is not selectable data".into());
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        let mut block = [0; 4096];
        loop {
            self.check()?;
            check()?;
            parent.check()?;
            if fs::canonicalize(path.parent().ok_or("C member no parent")?)?
                != path.parent().ok_or("C member no parent")?
            {
                return Err("C member parent alias changed".into());
            }
            let current = parent.open(&path, libc::O_RDONLY, 0)?;
            if file_identity(&parent.member(&file, bound as u64)?) != file_identity(&before)
                || file_identity(&parent.member(&current, bound as u64)?) != file_identity(&before)
            {
                return Err("paged C immutable member changed before read".into());
            }
            let capacity = (before.len() as usize)
                .saturating_sub(bytes.len())
                .min(block.len())
                .max(1);
            let count = file.read(&mut block[..capacity])?;
            check()?;
            if count == 0 {
                break;
            }
            if bytes.len() + count > before.len() as usize {
                return Err("paged C immutable member grew".into());
            }
            bytes.extend_from_slice(&block[..count]);
        }
        if bytes.len() as u64 != before.len()
            || file_identity(&parent.member(&file, bound as u64)?) != file_identity(&before)
            || file_identity(&parent.member(&parent.open(&path, libc::O_RDONLY, 0)?, bound as u64)?)
                != file_identity(&before)
        {
            return Err("paged C readback identity differs".into());
        }
        self.check()?;
        check()?;
        Ok(bytes)
    }
    fn create_file_at(
        path: &Path,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if bytes.is_empty() || bytes.len() > FILE_BYTES {
            return Err("paged C immutable file size invalid".into());
        }
        check()?;
        let parent = MemberParent::capture(path)?;
        let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(parent.file.as_raw_fd(), &mut status) } != 0
            || status.f_favail < 2
            || status
                .f_bavail
                .checked_mul(status.f_frsize)
                .ok_or("C free capacity overflow")?
                < bytes.len() as u64 + 16 * 1024 * 1024
        {
            return Err("C physical space/inodes unavailable before allocation".into());
        }
        let mut file = parent.open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o400)?;
        parent.member(&file, 0)?;
        // Allocation precedes bytes. Errors leave charged zero/partial files.
        physical::allocate(&file, bytes.len(), check)?;
        for block in bytes.chunks(4096) {
            check()?;
            parent.check()?;
            file.write_all(block)?;
            check()?;
        }
        file.sync_all()?;
        parent.file.sync_all()?;
        parent.check()?;
        check()?;
        if file_identity(&parent.member(&file, bytes.len() as u64)?)
            != file_identity(
                &parent.member(&parent.open(path, libc::O_RDONLY, 0)?, bytes.len() as u64)?,
            )
        {
            return Err("paged C created immutable member substituted".into());
        }
        Ok(())
    }
    /// The caller must first prove actual current C selection/original authority.
    /// A complete measured inventory, not caller counters, seeds the finite
    /// admission. This cold admission is intentionally bounded and never purges.
    pub(super) fn admit_writes(
        &self,
        bytes: u64,
        files: u64,
        directories: u64,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if bytes == 0
            || files == 0
            || bytes > 256 * 1024 * 1024
            || files > 32768
            || directories > 65536
        {
            return Err("invalid native paged C write reservation".into());
        }
        let actual = self.inventory(check)?;
        if actual.interrupted_files != 0 {
            return Err("paged C has interrupted immutable allocation evidence; explicit reconciliation required before new writes".into());
        }
        if actual
            .allocated_bytes
            .checked_add(bytes)
            .map_or(true, |v| v > MAX_ALLOCATED)
            || actual
                .logical_bytes
                .checked_add(bytes)
                .map_or(true, |v| v > MAX_ALLOCATED)
            || actual
                .files
                .checked_add(files)
                .map_or(true, |v| v > MAX_PAGES + MAX_ATTEMPTS * 8 + 8)
            || actual
                .directories
                .checked_add(directories)
                .map_or(true, |v| v > MAX_ATTEMPTS + 2 * 65536 + 8)
        {
            return Err("paged C reservation exceeds measured physical namespace policy".into());
        }
        if self.writes.borrow().as_ref().is_some_and(|a| a.poisoned) {
            return Err("uncertain native C allocation requires explicit reconciliation, not another admission".into());
        }
        *self.writes.borrow_mut() = Some(WriteAdmission {
            remaining_bytes: bytes,
            remaining_files: files,
            remaining_directories: directories,
            poisoned: false,
        });
        Ok(())
    }
    fn reserve_create(&self, bytes: u64, directory: bool) -> Result<()> {
        let mut held = self.writes.borrow_mut();
        let a = held
            .as_mut()
            .ok_or("paged C create has no measured current-authority reservation")?;
        let charge = bytes
            .checked_add(4095)
            .map(|v| v / 4096 * 4096)
            .and_then(|v| v.checked_add(4096))
            .ok_or("paged C allocation charge overflow")?;
        if a.poisoned
            || a.remaining_bytes < charge
            || if directory {
                a.remaining_directories == 0
            } else {
                a.remaining_files == 0
            }
        {
            return Err("paged C allocation reservation exhausted before create".into());
        }
        a.remaining_bytes -= charge;
        if directory {
            a.remaining_directories -= 1;
        } else {
            a.remaining_files -= 1;
        }
        a.poisoned = true;
        Ok(())
    }
    fn allocation_completed(&self) -> Result<()> {
        let mut held = self.writes.borrow_mut();
        held.as_mut().ok_or("missing paged C reservation")?.poisoned = false;
        Ok(())
    }
    pub(super) fn create_member(
        &self,
        name: &str,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check()?;
        self.reserve_create(bytes.len() as u64, false)?;
        Self::create_file_at(&self.path(name)?, bytes, check)?;
        if self.read(name, FILE_BYTES, check)? != bytes {
            return Err("paged C synchronized readback differs".into());
        }
        self.allocation_completed()
    }
    pub(super) fn page_name(hash: &str) -> Result<String> {
        digest(hash)?;
        Ok(format!("pages/{}/{}/{}", &hash[..2], &hash[2..4], hash))
    }
    pub(super) fn read_page(
        &self,
        hash: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let bytes = self.read(&Self::page_name(hash)?, PAGE_BYTES, check)?;
        if super::hash(&bytes) != hash {
            return Err("paged C page hash differs".into());
        }
        Ok(bytes)
    }
    pub(super) fn write_page(
        &self,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<String> {
        self.write_object("pages", bytes, PAGE_BYTES, check)
    }
    pub(super) fn read_record(
        &self,
        hash: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        digest(hash)?;
        let bytes = self.read(
            &format!("records/{}/{}/{}", &hash[..2], &hash[2..4], hash),
            FILE_BYTES,
            check,
        )?;
        if super::hash(&bytes) != hash {
            return Err("C immutable record hash differs".into());
        }
        Ok(bytes)
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn write_record(
        &self,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<String> {
        self.write_object("records", bytes, FILE_BYTES, check)
    }
    fn write_object(
        &self,
        tree: &str,
        bytes: &[u8],
        bound: usize,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<String> {
        if !matches!(tree, "pages" | "records") || bytes.is_empty() || bytes.len() > bound {
            return Err("paged C object size/tree invalid".into());
        }
        let hash = super::hash(bytes);
        self.check()?;
        check()?;
        for relative in [
            format!("{tree}/{}", &hash[..2]),
            format!("{tree}/{}/{}", &hash[..2], &hash[2..4]),
        ] {
            let path = self.path(&relative)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.reserve_create(4096, true)?;
                    fs::DirBuilder::new().mode(0o700).create(&path)?;
                    File::open(path.parent().ok_or("C prefix no parent")?)?.sync_all()?;
                    self.allocation_completed()?;
                }
                Err(e) => return Err(e.into()),
            }
            let held = PersistentDirectory::capture(&path)?;
            held.check()?;
            if held.mount != self.pin.mount {
                return Err("C page prefix mount differs".into());
            }
        }
        let name = format!("{tree}/{}/{}/{}", &hash[..2], &hash[2..4], hash);
        match fs::symlink_metadata(self.path(&name)?) {
            Ok(_) => {
                if self.read(&name, bound, check)? != bytes {
                    return Err("C existing object differs; no overwrite".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.create_member(&name, bytes, check)?
            }
            Err(e) => return Err(e.into()),
        }
        self.check()?;
        check()?;
        Ok(hash)
    }
    pub(super) fn create_attempt(
        &self,
        id: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        digest(id)?;
        self.check()?;
        check()?;
        self.reserve_create(4096, true)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(self.path(&format!("attempts/{id}"))?)?;
        File::open(self.root.join("attempts"))?.sync_all()?;
        check()?;
        self.allocation_completed()
    }
    pub(super) fn absent(&self, name: &str) -> Result<bool> {
        self.check()?;
        match fs::symlink_metadata(self.path(name)?) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.into()),
        }
    }
    /// Rename only already allocated files; never allocate or regenerate bytes
    /// after an NV dispatch. All source/destination paths remain fixed namespace.
    pub(super) fn rename(
        &self,
        from: &str,
        to: &str,
        replace: bool,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check()?;
        check()?;
        let source = self.path(from)?;
        let destination = self.path(to)?;
        let a = MemberParent::capture(&source)?;
        let b = MemberParent::capture(&destination)?;
        let source_name = std::ffi::CString::new(
            source
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("C source name")?,
        )?;
        let target_name = std::ffi::CString::new(
            destination
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("C target name")?,
        )?;
        if unsafe {
            libc::renameat2(
                a.file.as_raw_fd(),
                source_name.as_ptr(),
                b.file.as_raw_fd(),
                target_name.as_ptr(),
                if replace { 0 } else { libc::RENAME_NOREPLACE },
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        a.file.sync_all()?;
        b.file.sync_all()?;
        a.check()?;
        b.check()?;
        self.check()?;
        check()
    }
    /// Complete bounded physical audit, including interrupted allocations. It
    /// supplies accounting only and cannot select a head or discard evidence.
    pub(super) fn inventory(
        &self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PhysicalInventory> {
        self.check()?;
        let mut total = PhysicalInventory::default();
        let root_before = fs::symlink_metadata(&self.root)?;
        total.add(&root_before, true)?;
        for name in names(&self.root, 8)? {
            check()?;
            let path = self.root.join(&name);
            let metadata = fs::symlink_metadata(&path)?;
            match name.as_str() {
                "identity.json" | "selected.json" | "pending.json" => {
                    regular(&metadata, CONTROL_BYTES)?;
                    total.add(&metadata, false)?;
                }
                "pages" | "records" => {
                    let bound = if name == "pages" {
                        PAGE_BYTES
                    } else {
                        FILE_BYTES
                    };
                    let before = file_identity(&metadata);
                    total.add(&metadata, true)?;
                    for first in names(&path, 256)? {
                        prefix(&first)?;
                        let a = path.join(&first);
                        let apin = PersistentDirectory::capture(&a)?;
                        apin.check()?;
                        let ameta = fs::symlink_metadata(&a)?;
                        total.add(&ameta, true)?;
                        for second in names(&a, 256)? {
                            prefix(&second)?;
                            let b = a.join(&second);
                            let bpin = PersistentDirectory::capture(&b)?;
                            bpin.check()?;
                            let bmeta = fs::symlink_metadata(&b)?;
                            total.add(&bmeta, true)?;
                            visit_names(&b, MAX_PAGES as usize, |hash| {
                                check()?;
                                digest(&hash)?;
                                if !hash.starts_with(&format!("{first}{second}")) {
                                    return Err("C misplaced immutable object".into());
                                }
                                let member = b.join(&hash);
                                let parent = MemberParent::capture(&member)?;
                                let file = parent.open(&member, libc::O_RDONLY, 0)?;
                                let metadata = parent.member(&file, bound as u64)?;
                                total.add(&metadata, false)?;
                                if metadata.len() != 0
                                    && super::hash(&self.read(
                                        &format!("{name}/{first}/{second}/{hash}"),
                                        bound,
                                        check,
                                    )?) != hash
                                {
                                    total.interrupted_files = total
                                        .interrupted_files
                                        .checked_add(1)
                                        .ok_or("C damaged allocation count overflow")?;
                                }
                                parent.check()?;
                                Ok(())
                            })?;
                            if file_identity(&bmeta) != file_identity(&fs::symlink_metadata(&b)?) {
                                return Err("C page leaf changed during inventory".into());
                            }
                            bpin.check()?;
                        }
                        if file_identity(&ameta) != file_identity(&fs::symlink_metadata(&a)?) {
                            return Err("C first object prefix changed during inventory".into());
                        }
                        apin.check()?;
                    }
                    if before != file_identity(&fs::symlink_metadata(&path)?) {
                        return Err("C page prefixes changed during inventory".into());
                    }
                }
                "attempts" => {
                    total.add(&metadata, true)?;
                    let before = file_identity(&metadata);
                    visit_names(&path, MAX_ATTEMPTS as usize, |id| {
                        check()?;
                        digest(&id)?;
                        let attempt = path.join(&id);
                        let pin = PersistentDirectory::capture(&attempt)?;
                        pin.check()?;
                        let before = fs::symlink_metadata(&attempt)?;
                        total.add(&before, true)?;
                        let allowed = [
                            "base.json",
                            "next.json",
                            "prepared.json",
                            "selector.json",
                            "dispatch.json",
                            "completed.json",
                            "retired.json",
                        ];
                        let members = names(&attempt, allowed.len())?;
                        let completed = members.iter().any(|name| name == "completed.json");
                        let retired = members.iter().any(|name| name == "retired.json");
                        if completed && retired {
                            return Err(
                                "paged C attempt has contradictory terminal evidence".into()
                            );
                        }
                        if !completed && !retired {
                            total.interrupted_files = total
                                .interrupted_files
                                .checked_add(1)
                                .ok_or("C interrupted attempt count overflow")?;
                        }
                        for member in members {
                            if !allowed.contains(&member.as_str()) {
                                return Err("unknown C attempt member".into());
                            }
                            let member = attempt.join(member);
                            let parent = MemberParent::capture(&member)?;
                            let file = parent.open(&member, libc::O_RDONLY, 0)?;
                            let metadata = parent.member(&file, CONTROL_BYTES as u64)?;
                            total.add(&metadata, false)?;
                        }
                        if file_identity(&before) != file_identity(&fs::symlink_metadata(&attempt)?)
                        {
                            return Err("C attempt changed during inventory".into());
                        }
                        pin.check()?;
                        Ok(())
                    })?;
                    if before != file_identity(&fs::symlink_metadata(&path)?) {
                        return Err("C attempts changed during inventory".into());
                    }
                }
                "controls" => {
                    let before = file_identity(&metadata);
                    total.add(&metadata, true)?;
                    for name in names(&path, 3)? {
                        if !["selector-0", "selector-1", "pending"].contains(&name.as_str()) {
                            return Err("unknown fixed C control-cell member".into());
                        }
                        let member = path.join(&name);
                        let parent = MemberParent::capture(&member)?;
                        let file = parent.open(&member, libc::O_RDONLY, 0)?;
                        let observed = file.metadata()?;
                        cells::validate_file(&file, &member, self, None)?;
                        total.add(&observed, false)?;
                    }
                    if before != file_identity(&fs::symlink_metadata(&path)?) {
                        return Err(
                            "C fixed control-cell namespace changed during inventory".into()
                        );
                    }
                }
                "tails" => {
                    let before = file_identity(&metadata);
                    total.add(&metadata, true)?;
                    visit_names(&path, MAX_ATTEMPTS as usize, |job| {
                        check()?;
                        digest(job)?;
                        let directory = path.join(job);
                        let pin = PersistentDirectory::capture(&directory)?;
                        let initial = fs::symlink_metadata(&directory)?;
                        total.add(&initial, true)?;
                        let identity = directory.join("identity.json");
                        let parent = MemberParent::capture(&identity)?;
                        let file = parent.open(&identity, libc::O_RDONLY, 0)?;
                        let metadata = parent.member(&file, slots::PLAN_BYTES as u64)?;
                        total.add(&metadata, false)?;
                        let bytes = self.read(
                            &format!("tails/{job}/identity.json"),
                            slots::PLAN_BYTES,
                            check,
                        )?;
                        let plan: slots::Plan = canonical(&bytes, slots::PLAN_BYTES)?;
                        plan.validate()?;
                        if plan.job != job || plan.binding != self.binding {
                            return Err(
                                "physical tail inventory changes exact job or C binding".into()
                            );
                        }
                        visit_names(&directory, usize::try_from(plan.slots()?)? + 1, |name| {
                            check()?;
                            if name == "identity.json" {
                                return Ok(());
                            }
                            if name.len() != 8
                                || !name
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            {
                                return Err("physical tail inventory has unknown member".into());
                            }
                            let number = u32::from_str_radix(name, 16)?;
                            plan.spec(number)?;
                            let member = directory.join(name);
                            let parent = MemberParent::capture(&member)?;
                            let file = parent.open(&member, libc::O_RDONLY, 0)?;
                            let metadata = file.metadata()?;
                            if !metadata.is_file()
                                || metadata.uid() != 0
                                || metadata.nlink() != 1
                                || ![0o400, 0o600].contains(&(metadata.mode() & 0o7777))
                                || metadata.len() > plan.capacity(number)?
                                || metadata.dev() != self.pin.identity.0
                                || PersistentDirectory::mount(&file)? != self.pin.mount
                                || file_identity(
                                    &parent.open(&member, libc::O_RDONLY, 0)?.metadata()?,
                                ) != file_identity(&metadata)
                            {
                                return Err("physical tail inventory member inode/mode/length/mount differs".into());
                            }
                            total.add(&metadata, false)?;
                            slots::instance(&file)?;
                            parent.check()?;
                            Ok(())
                        })?;
                        if file_identity(&initial)
                            != file_identity(&fs::symlink_metadata(&directory)?)
                        {
                            return Err(
                                "physical tail namespace changed during complete inventory".into(),
                            );
                        }
                        pin.check()?;
                        Ok(())
                    })?;
                    if before != file_identity(&fs::symlink_metadata(&path)?) {
                        return Err("physical tail jobs changed during inventory".into());
                    }
                }
                _ => return Err("unknown C paged layout member".into()),
            }
        }
        if file_identity(&root_before) != file_identity(&fs::symlink_metadata(&self.root)?) {
            return Err("C paged inventory changed".into());
        }
        self.check()?;
        check()?;
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "luma-paged-inventory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            assert_eq!(fs::canonicalize(&path).unwrap(), path);
            Self(path)
        }
        fn file(&self, name: &str) {
            let path = self.0.join(name);
            let file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.set_permissions(fs::Permissions::from_mode(0o400))
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only this fresh private test directory, no recursive deletion or
            // followed links. Every fixture-created child is a file or empty.
            for entry in fs::read_dir(&self.0).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    fs::remove_dir(&path).unwrap();
                } else {
                    fs::remove_file(&path).unwrap();
                }
            }
            fs::remove_dir(&self.0).unwrap();
        }
    }
    #[test]
    fn streaming_inventory_enforces_count_before_callback_without_collecting_large_names() {
        let fixture = Fixture::new();
        for index in 0..8 {
            fixture.file(&format!("{index:064x}"));
        }
        let mut seen = BTreeSet::new();
        visit_names(&fixture.0, 8, |name| {
            assert!(seen.insert(name.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 8);
        let mut callbacks = 0;
        assert!(visit_names(&fixture.0, 4, |_| {
            callbacks += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(callbacks, 4);
        assert!(names(&fixture.0, 257).is_err());
        assert!(MAX_ATTEMPTS >= 100_000);
    }
    #[test]
    fn invalid_name_and_directory_alias_refuse_before_data_callback() {
        let fixture = Fixture::new();
        fixture.file(&"a".repeat(65));
        let mut callbacks = 0;
        assert!(visit_names(&fixture.0, 4, |_| {
            callbacks += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(callbacks, 0);
        for invalid in ["", ".", "..", "x/y", "x:y", "é"] {
            assert!(valid_name(invalid).is_err());
        }
        let alias = fixture.0.join("alias");
        std::os::unix::fs::symlink(&fixture.0, &alias).unwrap();
        assert!(visit_names(&alias, 4, |_| {
            callbacks += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(callbacks, 0);
    }
    #[test]
    fn streaming_complete_result_refuses_observed_directory_change() {
        let fixture = Fixture::new();
        fixture.file("original");
        let mut changed = false;
        assert!(visit_names(&fixture.0, 16, |_| {
            if !changed {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(fixture.0.join("changed"))?;
                changed = true;
            }
            Ok(())
        })
        .is_err());
    }
    #[test]
    fn private_file_shape_and_allocated_interruption_are_data_not_selectable_authority() {
        let fixture = Fixture::new();
        fixture.file("member");
        let path = fixture.0.join("member");
        let metadata = fs::symlink_metadata(&path).unwrap();
        regular(&metadata, 1).unwrap();
        let mut inventory = PhysicalInventory::default();
        inventory.add(&metadata, false).unwrap();
        assert_eq!(inventory.interrupted_files, 1);
        assert_eq!(inventory.files, 1);
        fs::hard_link(&path, fixture.0.join("second")).unwrap();
        assert!(regular(&fs::symlink_metadata(&path).unwrap(), 1).is_err());
        fs::remove_file(fixture.0.join("second")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(regular(&fs::symlink_metadata(&path).unwrap(), 1).is_err());
        let mut exhausted = PhysicalInventory {
            files: MAX_PAGES + MAX_ATTEMPTS * 8 + 8,
            ..PhysicalInventory::default()
        };
        assert!(exhausted.add(&metadata, false).is_err());
    }
}
