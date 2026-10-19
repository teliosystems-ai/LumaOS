//! Physical admission for C's existing closed namespace. Counts include
//! interrupted files and allocated extents past EOF; none are discarded here.
use super::*;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::unix::fs::MetadataExt;

const MAX_ENTRIES: usize = 32;
const MAX_BYTES: u64 = 24 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Inventory {
    entries: usize,
    logical_bytes: u64,
    allocated_bytes: u64,
    maximum_entries: usize,
    maximum_logical_bytes: u64,
    maximum_allocated_bytes: u64,
    interrupted_members_counted: bool,
    capacity_is_not_authority: bool,
    history_continuation_implemented: bool,
}
impl Inventory {
    fn empty() -> Self {
        Self {
            entries: 0,
            logical_bytes: 0,
            allocated_bytes: 0,
            maximum_entries: MAX_ENTRIES,
            maximum_logical_bytes: MAX_BYTES,
            maximum_allocated_bytes: MAX_BYTES,
            interrupted_members_counted: true,
            capacity_is_not_authority: true,
            history_continuation_implemented: false,
        }
    }
    fn add(&mut self, bytes: u64, allocated: u64) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or("C namespace count overflow")?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(bytes)
            .ok_or("C logical byte overflow")?;
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(allocated)
            .ok_or("C allocated byte overflow")?;
        self.require_fit(0, 0, 0)
    }
    fn require_fit(&self, entries: usize, bytes: u64, allocated: u64) -> Result<()> {
        if self
            .entries
            .checked_add(entries)
            .map_or(true, |n| n > MAX_ENTRIES)
            || self
                .logical_bytes
                .checked_add(bytes)
                .map_or(true, |n| n > MAX_BYTES)
            || self
                .allocated_bytes
                .checked_add(allocated)
                .map_or(true, |n| n > MAX_BYTES)
        {
            return Err(
                "C private namespace physical capacity exhausted; preserve all retained evidence"
                    .into(),
            );
        }
        Ok(())
    }
}

fn member_limit(directory: &str, name: &str) -> Result<Option<u64>> {
    let limit = match (directory, name) {
        ("", "sealed" | ".enrollment-prepared") => return Ok(None),
        ("", JOURNAL | PUBLISHED) => MAX_JOURNAL as u64,
        ("", PREPARED) => MAX_FILE as u64,
        (
            "",
            "genesis.json"
            | ".parent-intent.json"
            | ".parent-name.json"
            | ".parent-dispatched.json"
            | ".parent-reconciled.json",
        ) => 4096,
        ("sealed" | ".enrollment-prepared", "anchor.json" | "nv-dispatched.json") => 4096,
        ("sealed" | ".enrollment-prepared", "nv-auth.cred") => 20 * 1024,
        ("sealed", "receipt-signer.json") => 16384,
        _ => return Err("unknown C private namespace member; preserve evidence".into()),
    };
    Ok(Some(limit))
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(directory: &File, check: &mut impl FnMut() -> Result<()>) -> Result<Vec<String>> {
    check()?;
    // A fresh open description prevents readdir from sharing a retained
    // descriptor's offset. No /proc/self/fd traversal or caller path is used.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            b".\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = DirectoryStream(raw);
    let mut result = BTreeSet::new();
    loop {
        check()?;
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_str()?;
        if name == "." || name == ".." {
            continue;
        }
        if result.len() >= MAX_ENTRIES || !result.insert(name.to_string()) {
            return Err("C private namespace entry bound exceeded".into());
        }
    }
    check()?;
    Ok(result.into_iter().collect())
}

fn metadata(directory: &File, name: &str) -> Result<libc::stat> {
    let name = CString::new(name)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut value,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}
fn identity(value: &libc::stat) -> (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64, i64, i64) {
    (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_blocks,
        value.st_mtime,
        value.st_mtime_nsec,
        value.st_ctime,
        value.st_ctime_nsec,
    )
}
fn inspect_directory(
    parent: &MemberParent,
    directory: &str,
    inventory: &mut Inventory,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    parent.check()?;
    let before = file_identity(&parent.file.metadata()?);
    let members = names(&parent.file, check)?;
    let mut captured = Vec::new();
    for name in &members {
        check()?;
        parent.check()?;
        let limit = member_limit(directory, name)?;
        let value = metadata(&parent.file, name)?;
        if value.st_uid != 0
            || value.st_dev != parent.identity.0
            || value.st_size < 0
            || value.st_blocks < 0
        {
            return Err("C namespace member ownership, volume or physical size differs".into());
        }
        let allocated = (value.st_blocks as u64)
            .checked_mul(512)
            .ok_or("C block accounting overflow")?;
        if let Some(limit) = limit {
            if value.st_mode & libc::S_IFMT != libc::S_IFREG
                || value.st_mode & 0o7777 != 0o400
                || value.st_nlink != 1
                || value.st_size as u64 > limit
            {
                return Err("C namespace contains an unsafe or oversized retained member".into());
            }
            let held = parent.open(&parent.path.join(name), libc::O_PATH, 0)?;
            let retained = parent.member(&held, limit)?;
            if (
                retained.dev(),
                retained.ino(),
                retained.len(),
                retained.blocks(),
                retained.mode(),
                retained.uid(),
                retained.gid(),
                retained.nlink(),
            ) != (
                value.st_dev,
                value.st_ino,
                value.st_size as u64,
                value.st_blocks as u64,
                value.st_mode,
                value.st_uid,
                value.st_gid,
                value.st_nlink,
            ) {
                return Err("C retained member mount or identity changed during inventory".into());
            }
            inventory.add(value.st_size as u64, allocated)?;
        } else {
            if value.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_mode & 0o7777 != 0o700 {
                return Err("C namespace contains a substituted private directory".into());
            }
            inventory.add(0, allocated)?;
            let child = MemberParent::capture(&parent.path.join(name).join("anchor.json"))?;
            if (child.identity.0, child.identity.1) != (value.st_dev, value.st_ino) {
                return Err("C private child directory changed before inventory".into());
            }
            inspect_directory(&child, name, inventory, check)?;
        }
        captured.push((name, identity(&value)));
        check()?;
    }
    if names(&parent.file, check)? != members || file_identity(&parent.file.metadata()?) != before {
        return Err("C private namespace changed during complete inventory".into());
    }
    for (name, expected) in captured {
        check()?;
        if identity(&metadata(&parent.file, name)?) != expected {
            return Err("C retained member changed during complete inventory".into());
        }
    }
    parent.check()?;
    check()
}

pub(super) fn inspect(files: &Files, check: &mut impl FnMut() -> Result<()>) -> Result<Inventory> {
    let parent = MemberParent::capture(&files.root.join(JOURNAL))?;
    let mut result = Inventory::empty();
    let blocks = parent
        .file
        .metadata()?
        .blocks()
        .checked_mul(512)
        .ok_or("C root block accounting overflow")?;
    result.allocated_bytes = blocks;
    result.require_fit(0, 0, 0)?;
    inspect_directory(&parent, "", &mut result, check)?;
    Ok(result)
}

fn rounded(bytes: u64, unit: u64) -> Result<u64> {
    if unit == 0 {
        return Err("C filesystem allocation unit unavailable".into());
    }
    bytes
        .checked_add(unit - 1)
        .and_then(|n| n.checked_div(unit))
        .and_then(|n| n.checked_mul(unit))
        .ok_or_else(|| "C allocation rounding overflow".into())
}
pub(super) fn admit(
    files: &Files,
    name: &str,
    bytes: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (directory, member) = match name.split_once('/') {
        Some((directory, member)) if !member.contains('/') => (directory, member),
        None => ("", name),
        _ => return Err("C create requires one exact closed member".into()),
    };
    if member_limit(directory, member)?.map_or(true, |limit| bytes == 0 || bytes as u64 > limit) {
        return Err("C creation exceeds its exact closed member byte bound".into());
    }
    let inventory = inspect(files, check)?;
    let parent = MemberParent::capture(&files.root.join(name))?;
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    check()?;
    if unsafe { libc::fstatvfs(parent.file.as_raw_fd(), &mut status) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let allocated = rounded(bytes as u64, status.f_frsize)?;
    let headroom = status
        .f_frsize
        .checked_mul(2)
        .ok_or("C metadata headroom overflow")?;
    inventory.require_fit(1, bytes as u64, allocated)?;
    if status
        .f_bavail
        .checked_mul(status.f_frsize)
        .ok_or("C free byte overflow")?
        < allocated
            .checked_add(headroom)
            .ok_or("C required free byte overflow")?
        || status.f_favail < 2
    {
        return Err("C data allocation or inode headroom unavailable before preparation".into());
    }
    parent.check()?;
    check()
}

pub(super) fn allocate(
    file: &File,
    bytes: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let length = i64::try_from(bytes)?;
    if length <= 0
        || unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, length) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // Physical extents exist before private data writes. Failed writes keep
    // their allocated extents in the closed inventory, including zero EOF.
    file.sync_all()?;
    check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_caps_count_allocated_past_eof_and_reject_arithmetic_overflow() {
        let mut value = Inventory::empty();
        value.add(0, MAX_BYTES).unwrap();
        assert!(value.require_fit(1, 1, 1).is_err());
        let mut value = Inventory::empty();
        value.add(MAX_BYTES, 0).unwrap();
        assert!(value.require_fit(1, 1, 0).is_err());
        assert!(value.require_fit(usize::MAX, 0, 0).is_err());
        assert!(value.require_fit(0, u64::MAX, 0).is_err());
        assert_eq!(rounded(4097, 4096).unwrap(), 8192);
        assert!(rounded(u64::MAX, 4096).is_err());
        assert!(rounded(1, 0).is_err());
    }
    #[test]
    fn private_names_are_closed_and_include_retained_commissioning_evidence() {
        for name in [
            ".parent-intent.json",
            ".parent-name.json",
            ".parent-dispatched.json",
            ".parent-reconciled.json",
            "genesis.json",
        ] {
            assert_eq!(member_limit("", name).unwrap(), Some(4096));
        }
        assert_eq!(member_limit("", PREPARED).unwrap(), Some(MAX_FILE as u64));
        assert_eq!(
            member_limit("sealed", "receipt-signer.json").unwrap(),
            Some(16384)
        );
        for (dir, name) in [
            ("", "arbitrary-attempt"),
            ("sealed", "history.json"),
            ("other", "anchor.json"),
            ("", "../history.json"),
        ] {
            assert!(member_limit(dir, name).is_err());
        }
    }
}
