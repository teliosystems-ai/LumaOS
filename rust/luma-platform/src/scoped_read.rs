//! Descriptor-relative, no-symlink file reads for a previously admitted root.
//! The caller must authorize the current principal and grant before each use.
use crate::Result;
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootIdentity {
    pub device: u64,
    pub inode: u64,
}

/// Exact externally enrolled source identity. This is inert review data, not a
/// grant. The live source retains every directory and file descriptor and must
/// be checked against this identity after current principal authorization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceIdentity {
    pub root: String,
    pub relative: String,
    pub root_identity: RootIdentity,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified_seconds: i64,
    pub modified_nanos: i64,
    pub changed_seconds: i64,
    pub changed_nanos: i64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub sha256: String,
}

pub(crate) struct Source {
    ancestry: Vec<(File, CString, RootIdentity)>,
    root: File,
    directories: Vec<(File, CString, RootIdentity)>,
    parent: File,
    leaf: CString,
    file: File,
    expected: SourceIdentity,
    limit: u64,
}

fn same_file(metadata: &std::fs::Metadata, expected: &SourceIdentity) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode
        && metadata.len() == expected.bytes
        && metadata.mtime() == expected.modified_seconds
        && metadata.mtime_nsec() == expected.modified_nanos
        && metadata.ctime() == expected.changed_seconds
        && metadata.ctime_nsec() == expected.changed_nanos
        && metadata.uid() == expected.uid
        && metadata.gid() == expected.gid
        && metadata.mode() == expected.mode
}

fn source_directory(parent: Option<&File>, name: &CString) -> Result<File> {
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe {
        match parent {
            Some(parent) => libc::openat(parent.as_raw_fd(), name.as_ptr(), flags),
            None => libc::open(name.as_ptr(), flags),
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_dir() {
        return Err("scoped source directory is invalid".into());
    }
    Ok(file)
}

impl Source {
    pub(crate) fn open(root: &Path, relative: &str, limit: u64) -> Result<Self> {
        let mut source = Self::open_metadata(root, relative, limit)?;
        let bytes = source.read()?;
        source.expected.sha256 = crate::artifacts::digest(&bytes);
        source.recheck()?;
        Ok(source)
    }

    pub(crate) fn bind(expected: &SourceIdentity, limit: u64) -> Result<Self> {
        if !crate::artifacts::hash(&expected.sha256) {
            return Err("invalid enrolled source digest".into());
        }
        let mut source = Self::open_metadata(Path::new(&expected.root), &expected.relative, limit)?;
        source.expected.sha256 = expected.sha256.clone();
        if &source.expected != expected {
            return Err("enrolled source metadata changed".into());
        }
        source.recheck()?;
        Ok(source)
    }

    fn open_metadata(root: &Path, relative: &str, limit: u64) -> Result<Self> {
        if limit == 0 || limit > MAX_READ_BYTES {
            return Err("scoped source bound is invalid".into());
        }
        let root_name = root.to_str().ok_or("scoped root encoding is invalid")?;
        if !root_name.starts_with('/') || root_name == "/" || root_name.ends_with('/') {
            return Err("scoped source requires a finite absolute folder".into());
        }
        let mut directory = source_directory(None, &CString::new("/")?)?;
        let mut ancestry = Vec::new();
        for part in components(&root_name[1..])? {
            let child = source_directory(Some(&directory), &part)?;
            ancestry.push((directory, part, identity(&child)?));
            directory = child;
        }
        let root = directory;
        let root_identity = identity(&root)?;
        let parts = components(relative)?;
        let mut directory = root.try_clone()?;
        let mut directories = Vec::new();
        for part in &parts[..parts.len() - 1] {
            let child = source_directory(Some(&directory), part)?;
            directories.push((directory, part.clone(), identity(&child)?));
            directory = child;
        }
        let leaf = parts.last().ok_or("empty scoped source")?.clone();
        let file = open_at(&directory, &leaf, false)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > limit
        {
            return Err("scoped source is not a bounded independent regular file".into());
        }
        let expected = SourceIdentity {
            root: root_name.into(),
            relative: relative.into(),
            root_identity,
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            sha256: String::new(),
        };
        let source = Self {
            ancestry,
            root,
            directories,
            parent: directory,
            leaf,
            file,
            expected,
            limit,
        };
        source.recheck()?;
        Ok(source)
    }

    pub(crate) fn identity(&self) -> &SourceIdentity {
        &self.expected
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        for (parent, name, expected) in self.ancestry.iter().chain(self.directories.iter()) {
            if identity(&source_directory(Some(parent), name)?)? != *expected {
                return Err("scoped source folder was replaced".into());
            }
        }
        if identity(&self.root)? != self.expected.root_identity
            || !same_file(&self.file.metadata()?, &self.expected)
            || !same_file(
                &open_at(&self.parent, &self.leaf, false)?.metadata()?,
                &self.expected,
            )
        {
            return Err("scoped source target changed".into());
        }
        Ok(())
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>> {
        use std::io::{Seek, SeekFrom};
        self.recheck()?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(self.limit + 1).read_to_end(&mut bytes)?;
        self.recheck()?;
        if bytes.len() as u64 != self.expected.bytes
            || (!self.expected.sha256.is_empty()
                && crate::artifacts::digest(&bytes) != self.expected.sha256)
        {
            return Err("scoped source content changed".into());
        }
        Ok(bytes)
    }
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
    fn enrolled_source_fences_identical_leaf_folder_and_content_replacement() {
        for mode in 0..4 {
            let base = std::env::temp_dir().join(format!(
                "luma-enrolled-source-{mode}-{}",
                std::process::id()
            ));
            fs::create_dir(&base).unwrap();
            fs::create_dir(base.join("folder")).unwrap();
            fs::create_dir(base.join("folder/nested")).unwrap();
            fs::write(base.join("folder/nested/source.csv"), b"private fixture").unwrap();
            let source = Source::open(&base.join("folder"), "nested/source.csv", 64).unwrap();
            let enrolled = source.identity().clone();
            assert_eq!(
                Source::bind(&enrolled, 64).unwrap().read().unwrap(),
                b"private fixture"
            );
            match mode {
                0 => {
                    fs::rename(base.join("folder/nested/source.csv"), base.join("old.csv"))
                        .unwrap();
                    fs::write(base.join("folder/nested/source.csv"), b"private fixture").unwrap();
                }
                1 => {
                    fs::rename(base.join("folder/nested"), base.join("old-nested")).unwrap();
                    fs::create_dir(base.join("folder/nested")).unwrap();
                    fs::write(base.join("folder/nested/source.csv"), b"private fixture").unwrap();
                }
                2 => {
                    fs::rename(base.join("folder"), base.join("old-folder")).unwrap();
                    fs::create_dir(base.join("folder")).unwrap();
                    fs::create_dir(base.join("folder/nested")).unwrap();
                    fs::write(base.join("folder/nested/source.csv"), b"private fixture").unwrap();
                }
                3 => {
                    fs::write(base.join("folder/nested/source.csv"), b"changed fixture").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(source.recheck().is_err());
            assert!(source.read().is_err());
            assert!(Source::bind(&enrolled, 64).is_err());
            fs::remove_dir_all(base).unwrap();
        }
    }
    #[test]
    fn source_binding_never_reads_before_enrolled_content_authorization() {
        let base = std::env::temp_dir().join(format!("luma-enrolled-bind-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::write(base.join("source.csv"), b"fixture").unwrap();
        let source = Source::open(&base, "source.csv", 64).unwrap();
        let mut enrolled = source.identity().clone();
        enrolled.sha256 = "a".repeat(64);
        let bound = Source::bind(&enrolled, 64).unwrap();
        assert!(bound.read().is_err());
        fs::hard_link(base.join("source.csv"), base.join("alias.csv")).unwrap();
        assert!(Source::open(&base, "alias.csv", 64).is_err());
        assert!(source.recheck().is_err());
        fs::remove_dir_all(base).unwrap();
    }

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
