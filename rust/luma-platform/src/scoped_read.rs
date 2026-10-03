//! Descriptor-relative, no-symlink file reads for a previously admitted root.
//! The caller must authorize the current principal and grant before each use.
use crate::Result;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_PATH_BYTES: usize = 1024;
const MAX_COMPONENTS: usize = 32;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_READ_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    pub device: u64,
    pub inode: u64,
}

pub(crate) fn open_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err("scoped root is not a directory".into());
    }
    Ok(directory)
}

pub(crate) fn identity(directory: &File) -> Result<RootIdentity> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err("scoped root is not a directory".into());
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn components(relative: &str) -> Result<Vec<CString>> {
    if relative.is_empty()
        || relative.len() > MAX_PATH_BYTES
        || relative.starts_with('/')
        || relative.contains('\\')
    {
        return Err("unsafe scoped relative path".into());
    }
    let mut result = Vec::new();
    for part in relative.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.len() > MAX_COMPONENT_BYTES
            || part.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err("unsafe scoped path component".into());
        }
        result.push(CString::new(part)?);
        if result.len() > MAX_COMPONENTS {
            return Err("scoped path has too many components".into());
        }
    }
    Ok(result)
}

fn open_at(parent: &File, name: &CString, directory: bool) -> Result<File> {
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn read_relative(
    root: &File,
    expected: RootIdentity,
    relative: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    if limit == 0 || limit > MAX_READ_BYTES || identity(root)? != expected {
        return Err("scoped root identity or read limit mismatch".into());
    }
    let parts = components(relative)?;
    let mut directory = root.try_clone()?;
    for part in &parts[..parts.len() - 1] {
        directory = open_at(&directory, part, true)?;
        if !directory.metadata()?.is_dir() {
            return Err("scoped path component is not a directory".into());
        }
    }
    let mut file = open_at(&directory, parts.last().ok_or("empty scoped path")?, false)?;
    let initial = file.metadata()?;
    if !initial.is_file() || initial.len() > limit {
        return Err("scoped source is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let final_metadata = file.metadata()?;
    if bytes.len() as u64 != initial.len()
        || initial.dev() != final_metadata.dev()
        || initial.ino() != final_metadata.ino()
        || initial.len() != final_metadata.len()
        || initial.mtime() != final_metadata.mtime()
        || initial.mtime_nsec() != final_metadata.mtime_nsec()
        || initial.ctime() != final_metadata.ctime()
        || initial.ctime_nsec() != final_metadata.ctime_nsec()
    {
        return Err("scoped source changed during read".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn nested_descriptor_read_rejects_escape_links_and_changed_root_identity() {
        let base = std::env::temp_dir().join(format!("luma-scoped-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let root = base.join("grant");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/invoices.csv"), b"private fixture").unwrap();
        fs::write(base.join("outside.csv"), b"outside").unwrap();
        let directory = open_directory(&root).unwrap();
        let expected = identity(&directory).unwrap();
        assert_eq!(
            read_relative(&directory, expected, "nested/invoices.csv", 64).unwrap(),
            b"private fixture"
        );
        assert!(read_relative(&directory, expected, "nested/invoices.csv", 4).is_err());
        assert!(read_relative(
            &directory,
            RootIdentity {
                device: expected.device,
                inode: expected.inode + 1
            },
            "nested/invoices.csv",
            64,
        )
        .is_err());
        for path in [
            "../outside.csv",
            "/etc/passwd",
            "nested//invoices.csv",
            "nested/./invoices.csv",
            "nested/../invoices.csv",
            "nested\\invoices.csv",
            "nested/invoices.csv\0",
        ] {
            assert!(
                read_relative(&directory, expected, path, 64).is_err(),
                "{path:?}"
            );
        }
        std::os::unix::fs::symlink(base.join("outside.csv"), root.join("linked.csv")).unwrap();
        std::os::unix::fs::symlink(&base, root.join("linked-dir")).unwrap();
        assert!(read_relative(&directory, expected, "linked.csv", 64).is_err());
        assert!(read_relative(&directory, expected, "linked-dir/outside.csv", 64).is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn special_files_and_invalid_limits_are_denied_without_blocking() {
        let base = std::env::temp_dir().join(format!("luma-scoped-special-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let directory = open_directory(&base).unwrap();
        let expected = identity(&directory).unwrap();
        let fifo = CString::new(base.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read_relative(&directory, expected, "pipe", 64).is_err());
        assert!(read_relative(&directory, expected, "pipe", 0).is_err());
        assert!(read_relative(&directory, expected, "pipe", MAX_READ_BYTES + 1).is_err());
        fs::remove_dir_all(&base).unwrap();
    }
}
