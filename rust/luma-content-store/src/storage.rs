use crate::{Boundary, Plan, Repository, Result, MAX_REPOSITORY_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) fn check_private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || if directory {
            !m.is_dir() || m.mode() & 0o7777 != 0o700
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err("content-store member is not private and unlinked".into());
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 || stat.f_type != 0xef53 {
        return Err("content store requires local ext4".into());
    }
    Ok(())
}

pub(super) fn base(path: &Path) -> Result<File> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err("content-store base must be canonical and absolute".into());
    }
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
            return Err("unsafe content-store path ancestor".into());
        }
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    check_private(&file, true)?;
    Ok(file)
}

use std::os::unix::fs::OpenOptionsExt;

pub(super) fn open(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn directory(dir: &File, name: &str) -> Result<File> {
    let file = open(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    check_private(&file, true)?;
    if file.metadata()?.dev() != dir.metadata()?.dev() {
        return Err("content-store crossed a filesystem".into());
    }
    Ok(file)
}

pub(super) fn mkdir(dir: &File, name: &str) -> Result<File> {
    let c = CString::new(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all()?;
    directory(dir, name)
}

pub(super) fn names(dir: &File, limit: usize) -> Result<Vec<String>> {
    let mut result = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        if result.len() == limit {
            return Err("content-store namespace capacity exceeded".into());
        }
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| "invalid content-store member name")?;
        result.insert(name);
    }
    Ok(result.into_iter().collect())
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Pin(u64, u64, u64, i64, i64, i64, i64, u32);
fn pin(m: &fs::Metadata) -> Pin {
    Pin(
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
    )
}

pub(super) fn read(
    dir: &File,
    name: &str,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    check()?;
    let mut file = open(dir, name, libc::O_RDONLY, 0)?;
    check_private(&file, false)?;
    let before = file.metadata()?;
    if before.mode() & 0o7777 != 0o400 || before.len() > limit {
        return Err("content-store file mode or byte bound invalid".into());
    }
    let mut bytes = Vec::new();
    let mut block = [0_u8; 32 * 1024];
    loop {
        check()?;
        let capacity = limit
            .saturating_sub(bytes.len() as u64)
            .saturating_add(1)
            .min(block.len() as u64) as usize;
        let count = file.read(&mut block[..capacity])?;
        check()?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > limit {
            return Err("content-store read exceeds bound".into());
        }
        bytes.extend_from_slice(&block[..count]);
    }
    if bytes.len() as u64 != before.len()
        || pin(&before) != pin(&file.metadata()?)
        || pin(&before) != pin(&open(dir, name, libc::O_RDONLY, 0)?.metadata()?)
    {
        return Err("content-store member changed during read".into());
    }
    check()?;
    Ok(bytes)
}

pub(super) fn write(
    dir: &File,
    name: &str,
    bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let mut file = open(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o400,
    )?;
    for block in bytes.chunks(32 * 1024) {
        check()?;
        file.write_all(block)?;
    }
    check()?;
    file.sync_all()?;
    dir.sync_all()?;
    check()
}

pub(super) fn reserve(root: &File, bytes: u64) -> Result<()> {
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(root.as_raw_fd(), &mut v) } != 0
        || v.f_bavail
            .checked_mul(v.f_frsize)
            .ok_or("free-space overflow")?
            < bytes
                .checked_add(16 * 1024 * 1024)
                .ok_or("storage reserve overflow")?
        || bytes > MAX_REPOSITORY_BYTES
    {
        return Err("content-store storage reserve unavailable".into());
    }
    Ok(())
}

pub(super) fn rename(
    from: &File,
    to: &File,
    name: &str,
    check: &mut impl FnMut() -> Result<()>,
    after_rename: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let name = CString::new(name)?;
    check()?;
    if unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    after_rename()?;
    to.sync_all()?;
    from.sync_all()?;
    check()
}

pub(super) fn repository_check(
    repository: &Repository,
    plan: Option<&Plan>,
    boundary: &mut impl Boundary,
) -> Result<()> {
    boundary.check(crate::Access::Inspect {
        binding: &repository.binding,
    })?;
    if let Some(plan) = plan {
        boundary.check(plan.access())?;
    }
    for (parent, name, pinned) in [
        (&repository.base, repository.name.as_str(), &repository.root),
        (&repository.root, "pending", &repository.pending),
        (&repository.root, "outcomes", &repository.outcomes),
    ] {
        check_private(parent, true)?;
        check_private(pinned, true)?;
        let current = directory(parent, name)?.metadata()?;
        let expected = pinned.metadata()?;
        if (current.dev(), current.ino()) != (expected.dev(), expected.ino()) {
            return Err("content-store namespace changed during operation".into());
        }
    }
    crate::recovery::layout(&repository.root)?;
    if let Some(pinned) = &repository.quarantine {
        check_private(pinned, true)?;
        let actual = directory(&repository.root, "quarantine")?.metadata()?;
        let expected = pinned.metadata()?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            return Err("content-store quarantine namespace changed during operation".into());
        }
    } else if names(&repository.root, 4)?
        .iter()
        .any(|name| name == "quarantine")
    {
        return Err("content-store gained an unreviewed quarantine namespace".into());
    }
    Ok(())
}
