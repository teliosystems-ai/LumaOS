//! Actual kernel AF_UNIX feature admission, not a loaded-policy attestation.
//! No profile label, source checksum, regular file or environment override can
//! substitute for the kernel securityfs capability and its pinned namespace.
use crate::Result;
use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const SECURITYFS: u64 = 0x7363_6673;
const SYSFS: u64 = 0x6265_6572;
const COMPONENTS: [&str; 7] = [
    "sys", "kernel", "security", "apparmor", "features", "network", "af_unix",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}
impl Identity {
    fn capture(metadata: &Metadata, directory: bool) -> Result<Self> {
        if (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
            || metadata.uid() != 0
            || metadata.mode() & 0o7022 != 0
            || (!directory && metadata.nlink() != 1)
        {
            return Err("unsafe kernel backup feature inode type/ownership/mode".into());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        })
    }
}

struct Node {
    file: File,
    identity: Identity,
}

pub(super) struct KernelUnix {
    nodes: Vec<Node>,
}

fn filesystem(file: &File, expected: u64) -> Result<()> {
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.f_type as u64 != expected {
        return Err("backup Unix admission requires actual kernel sysfs/securityfs".into());
    }
    Ok(())
}

fn open(parent: &File, name: &str, directory: bool) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn root() -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?)
}

fn enabled(bytes: &[u8]) -> Result<()> {
    if bytes != b"yes\n" {
        return Err("kernel fine-grained Unix mediation absent/ambiguous; backup refused".into());
    }
    Ok(())
}

fn read_feature(file: &File) -> Result<()> {
    filesystem(file, SECURITYFS)?;
    let before = Identity::capture(&file.metadata()?, false)?;
    let mut bytes = [0_u8; 17];
    let mut count = 0;
    let mut reader = file;
    while count < bytes.len() {
        let read = reader.read(&mut bytes[count..])?;
        if read == 0 {
            break;
        }
        count += read;
    }
    enabled(&bytes[..count])?;
    if Identity::capture(&file.metadata()?, false)? != before {
        return Err("kernel Unix feature changed during bounded observation".into());
    }
    Ok(())
}

impl KernelUnix {
    pub(super) fn capture() -> Result<Self> {
        let first = root()?;
        let identity = Identity::capture(&first.metadata()?, true)?;
        let mut nodes = Vec::with_capacity(COMPONENTS.len() + 1);
        nodes.push(Node {
            file: first,
            identity,
        });
        for (index, name) in COMPONENTS.iter().enumerate() {
            let directory = index + 1 != COMPONENTS.len();
            let parent = &nodes.last().ok_or("kernel feature root pin absent")?.file;
            let file = open(parent, name, directory)?;
            filesystem(&file, if index < 2 { SYSFS } else { SECURITYFS })?;
            let identity = Identity::capture(&file.metadata()?, directory)?;
            nodes.push(Node { file, identity });
        }
        let witness = Self { nodes };
        witness.check()?;
        Ok(witness)
    }
    /// Reopens the fixed path component-by-component and compares every held
    /// inode before reading. No symlink or detached old feature file is trusted.
    pub(super) fn check(&self) -> Result<()> {
        if self.nodes.len() != COMPONENTS.len() + 1 {
            return Err("incomplete kernel Unix feature witness".into());
        }
        let mut current = root()?;
        if Identity::capture(&current.metadata()?, true)? != self.nodes[0].identity
            || Identity::capture(&self.nodes[0].file.metadata()?, true)? != self.nodes[0].identity
        {
            return Err("kernel feature root namespace changed".into());
        }
        for (index, name) in COMPONENTS.iter().enumerate() {
            let directory = index + 1 != COMPONENTS.len();
            let next = open(&current, name, directory)?;
            let saved = &self.nodes[index + 1];
            let magic = if index < 2 { SYSFS } else { SECURITYFS };
            filesystem(&next, magic)?;
            filesystem(&saved.file, magic)?;
            if Identity::capture(&next.metadata()?, directory)? != saved.identity
                || Identity::capture(&saved.file.metadata()?, directory)? != saved.identity
            {
                return Err("kernel Unix feature path or held inode changed".into());
            }
            current = next;
        }
        read_feature(&current)?;
        if Identity::capture(&current.metadata()?, false)?
            != self
                .nodes
                .last()
                .ok_or("kernel Unix feature pin absent")?
                .identity
        {
            return Err("kernel Unix feature identity changed after read".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_canonical_kernel_yes_is_admitted() {
        enabled(b"yes\n").unwrap();
        for bytes in [
            b"yes".as_slice(),
            b"no\n",
            b"Y\n",
            b"1\n",
            b" yes\n",
            b"yes\nyes\n",
            b"yes\n\0",
            b"yes\nextra",
            b"",
            b"yes\r\n",
        ] {
            assert!(enabled(bytes).is_err());
        }
    }
    #[test]
    fn regular_files_and_procfs_never_substitute_for_kernel_securityfs() {
        let file = File::open("/proc/self/status").unwrap();
        assert!(filesystem(&file, SECURITYFS).is_err());
        assert!(read_feature(&file).is_err());
        let root = root().unwrap();
        assert!(filesystem(&root, SECURITYFS).is_err());
        assert!(read_feature(&root).is_err());
    }
    #[test]
    fn fixed_component_opening_refuses_proc_self_symlink_without_following() {
        let proc = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/proc")
            .unwrap();
        assert!(open(&proc, "self", true).is_err());
        assert!(open(&proc, "self", false).is_err());
    }
    #[test]
    fn an_incomplete_witness_never_defaults_to_enabled() {
        assert!(KernelUnix { nodes: vec![] }.check().is_err());
    }
}
