//! Fixed-worker open-file-description configuration exclusions. A received FD
//! is a live kernel exclusion, not a grant, PAM proof or resource allocation.
use super::{Result, Worker};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "/run/luma-hardware";
const MAGIC: &[u8; 16] = b"LUMAHWLOCKv1!!!!";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Shared,
    Exclusive,
}

pub(crate) struct Locks {
    path: PathBuf,
    directory: File,
    identity: (u64, u64),
}
pub(crate) struct Held {
    file: File,
    directory: File,
    path: PathBuf,
    directory_identity: (u64, u64),
    identity: (u64, u64),
    worker: Worker,
    mode: Mode,
}

fn identity(file: &File) -> Result<(u64, u64)> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 0
    {
        return Err("hardware exclusion is not its closed root-owned empty inode".into());
    }
    Ok((meta.dev(), meta.ino()))
}
fn name(worker: Worker) -> &'static str {
    match worker {
        Worker::Model => "worker-model.lock",
        Worker::Acquisition => "worker-acquisition.lock",
    }
}
fn lock(file: &File, mode: Mode) -> Result<bool> {
    let mut record: libc::flock = unsafe { zeroed() };
    record.l_type = match mode {
        Mode::Shared => libc::F_RDLCK as i16,
        Mode::Exclusive => libc::F_WRLCK as i16,
    };
    record.l_whence = libc::SEEK_SET as i16;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &record) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EACCES)
    ) {
        Ok(false)
    } else {
        Err(error.into())
    }
}
fn query(file: &File) -> Result<i16> {
    let mut record: libc::flock = unsafe { zeroed() };
    record.l_type = libc::F_RDLCK as i16;
    record.l_whence = libc::SEEK_SET as i16;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_GETLK, &mut record) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if record.l_type == libc::F_WRLCK as i16
        && (record.l_pid != -1 || record.l_start != 0 || record.l_len != 0)
    {
        return Err("hardware exclusion is not a complete OFD writer lock".into());
    }
    Ok(record.l_type)
}
impl Locks {
    #[cfg(test)]
    pub(crate) fn for_test(path: &Path) -> Result<Self> {
        let locks = Self::at(path)?;
        locks.initialize()?;
        Ok(locks)
    }
    pub(crate) fn provision() -> Result<Self> {
        match std::fs::DirBuilder::new().mode(0o700).create(DIRECTORY) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error.into()),
        }
        let locks = Self::installed()?;
        locks.initialize()?;
        Ok(locks)
    }
    pub(crate) fn installed() -> Result<Self> {
        Self::at(Path::new(DIRECTORY))
    }
    fn at(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)?;
        let meta = directory.metadata()?;
        if meta.uid() != 0 || !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
            return Err("hardware exclusion directory is not root-private".into());
        }
        Ok(Self {
            path: path.into(),
            identity: (meta.dev(), meta.ino()),
            directory,
        })
    }
    fn current(&self) -> Result<()> {
        let current = Self::at(&self.path)?;
        if current.identity != self.identity {
            return Err("hardware exclusion directory was replaced".into());
        }
        Ok(())
    }
    fn open(&self, worker: Worker, create: bool) -> Result<File> {
        self.current()?;
        let name = std::ffi::CString::new(name(worker))?;
        if create {
            let descriptor = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL,
                    0o600,
                )
            };
            if descriptor >= 0 {
                let file = unsafe { File::from_raw_fd(descriptor) };
                identity(&file)?;
                file.sync_all()?;
                self.directory.sync_all()?;
                return Ok(file);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error().into());
            }
        }
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_RDWR,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        identity(&file)?;
        Ok(file)
    }
    pub(crate) fn initialize(&self) -> Result<()> {
        for worker in [Worker::Model, Worker::Acquisition] {
            let _ = self.open(worker, true)?;
        }
        Ok(())
    }
    fn acquire(&self, worker: Worker, mode: Mode) -> Result<Option<Held>> {
        let file = self.open(worker, false)?;
        let identity = identity(&file)?;
        if !lock(&file, mode)? {
            return Ok(None);
        }
        let held = Held {
            file,
            directory: self.directory.try_clone()?,
            path: self.path.clone(),
            directory_identity: self.identity,
            identity,
            worker,
            mode,
        };
        held.check()?;
        Ok(Some(held))
    }
    pub(crate) fn shared(&self, worker: Worker) -> Result<Option<Held>> {
        self.acquire(worker, Mode::Shared)
    }
    pub(crate) fn exclusive(&self, worker: Worker) -> Result<Option<Held>> {
        self.acquire(worker, Mode::Exclusive)
    }

    /// Receive exactly the Manager's same exclusive open-file-description.
    /// The caller independently verifies the live broker/transaction envelope.
    pub(crate) fn receive(
        &self,
        socket: &UnixStream,
        worker: Worker,
        binding: &[u8; 32],
    ) -> Result<Held> {
        socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
        let mut payload = [0u8; 48];
        let mut control = [0usize; 16];
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let count = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
            )
        };
        let mut descriptors = Vec::new();
        let mut unknown = false;
        if count >= 0 {
            let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            while !header.is_null() {
                let current = unsafe { &*header };
                if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
                    let base = unsafe { libc::CMSG_LEN(0) } as usize;
                    if current.cmsg_len < base || (current.cmsg_len - base) % size_of::<i32>() != 0
                    {
                        unknown = true;
                        break;
                    }
                    let length = (current.cmsg_len - base) / size_of::<i32>();
                    for index in 0..length {
                        let fd = unsafe {
                            std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<i32>().add(index),
                            )
                        };
                        if fd >= 0 {
                            descriptors.push(unsafe { File::from_raw_fd(fd) });
                        } else {
                            unknown = true;
                        }
                    }
                } else {
                    unknown = true;
                }
                header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            }
        }
        if count != payload.len() as isize
            || unknown
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
            || &payload[..16] != MAGIC
            || &payload[16..] != binding
            || descriptors.len() != 1
        {
            return Err(
                "hardware handoff is truncated, substituted or has extra descriptors".into(),
            );
        }
        let file = descriptors
            .pop()
            .ok_or("hardware handoff descriptor absent")?;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC == 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                != libc::O_RDWR
        {
            return Err("hardware handoff descriptor flags changed".into());
        }
        let held = Held {
            identity: identity(&file)?,
            file,
            directory: self.directory.try_clone()?,
            path: self.path.clone(),
            directory_identity: self.identity,
            worker,
            mode: Mode::Exclusive,
        };
        held.check()?;
        Ok(held)
    }
}
impl Held {
    pub(crate) fn check(&self) -> Result<()> {
        let actual = Locks::at(&self.path)?;
        let held_directory = self.directory.metadata()?;
        if actual.identity != self.directory_identity
            || (held_directory.dev(), held_directory.ino()) != self.directory_identity
            || identity(&self.file)? != self.identity
            || identity(&actual.open(self.worker, false)?)? != self.identity
        {
            return Err("hardware live exclusion directory/file identity changed".into());
        }
        if self.mode == Mode::Exclusive {
            // An independent FD sees the writer, while this exact OFD sees no
            // conflicting writer. No lock is acquired/renewed by validation.
            if query(&actual.open(self.worker, false)?)? != libc::F_WRLCK as i16
                || query(&self.file)? != libc::F_UNLCK as i16
            {
                return Err("hardware handoff does not hold the original exclusive OFD".into());
            }
        }
        Ok(())
    }
    pub(crate) fn send(&self, socket: &UnixStream, binding: &[u8; 32]) -> Result<()> {
        socket.set_write_timeout(Some(std::time::Duration::from_millis(250)))?;
        self.check()?;
        if self.mode != Mode::Exclusive {
            return Err("only the Manager's exclusive configuration OFD can be handed off".into());
        }
        let mut payload = Vec::from(MAGIC.as_slice());
        payload.extend_from_slice(binding);
        let mut control = [0usize; 16];
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err("hardware handoff ancillary layout is unavailable".into());
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), self.file.as_raw_fd());
        }
        if unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }
            != payload.len() as isize
        {
            return Err("hardware handoff descriptor transfer was not exact; no redispatch".into());
        }
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "luma-hardware-ofd-{}",
                crate::resources::random_id().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn locks(&self) -> Locks {
            let locks = Locks::at(&self.0).unwrap();
            locks.initialize().unwrap();
            locks
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn actual_kernel_shared_admission_and_exclusive_configuration_exclude_each_other() {
        let fixture = Fixture::new();
        let locks = fixture.locks();
        let first = locks.shared(Worker::Model).unwrap().unwrap();
        let second = locks.shared(Worker::Model).unwrap().unwrap();
        assert!(locks.exclusive(Worker::Model).unwrap().is_none());
        drop(first);
        assert!(locks.exclusive(Worker::Model).unwrap().is_none());
        drop(second);
        let exclusive = locks.exclusive(Worker::Model).unwrap().unwrap();
        exclusive.check().unwrap();
        assert!(locks.shared(Worker::Model).unwrap().is_none());
        assert!(locks.shared(Worker::Acquisition).unwrap().is_some());
        drop(exclusive);
        assert!(locks.shared(Worker::Model).unwrap().is_some());
    }
    #[test]
    fn actual_scm_rights_preserves_exclusion_after_issuing_manager_descriptor_closes() {
        let fixture = Fixture::new();
        let locks = fixture.locks();
        let exclusive = locks.exclusive(Worker::Model).unwrap().unwrap();
        let (left, right) = UnixStream::pair().unwrap();
        left.set_write_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        right
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        exclusive.send(&left, &[1; 32]).unwrap();
        let received = locks.receive(&right, Worker::Model, &[1; 32]).unwrap();
        drop(exclusive);
        received.check().unwrap();
        assert!(locks.shared(Worker::Model).unwrap().is_none());
        drop(received);
        assert!(locks.shared(Worker::Model).unwrap().is_some());
    }
    #[test]
    fn actual_process_death_releases_only_the_last_received_ofd_reference() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        const CHILD: &str = "LUMA_HARDWARE_OFD_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            // The re-executed test process receives the actual SCM_RIGHTS FD,
            // not an inherited/reopened description or a simulated owner.
            let path = PathBuf::from(path);
            let locks = Locks::at(&path).unwrap();
            let mut socket = UnixStream::connect(path.join("death.sock")).unwrap();
            let held = locks.receive(&socket, Worker::Model, &[7; 32]).unwrap();
            held.check().unwrap();
            socket.write_all(b"H").unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut stop = [0u8; 1];
            let _ = socket.read_exact(&mut stop);
            drop(held);
            return;
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let fixture = Fixture::new();
        let locks = fixture.locks();
        let held = locks.exclusive(Worker::Model).unwrap().unwrap();
        let listener = UnixListener::bind(fixture.0.join("death.sock")).unwrap();
        let test_name = concat!(
            module_path!(),
            "::actual_process_death_releases_only_the_last_received_ofd_reference"
        )
        .split_once("::")
        .unwrap()
        .1;
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--test-threads=1"])
                .env(CHILD, &fixture.0)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut ready = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 3000) }, 1);
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        held.send(&socket, &[7; 32]).unwrap();
        let mut ack = [0u8; 1];
        socket.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"H");
        drop(held);
        assert!(locks.shared(Worker::Model).unwrap().is_none());
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(socket.read(&mut ack).unwrap(), 0);
        assert!(locks.shared(Worker::Model).unwrap().is_some());
    }
    #[test]
    fn exact_binding_or_worker_substitution_closes_received_fd_without_minting_a_lock() {
        for variant in 0..2 {
            let fixture = Fixture::new();
            let locks = fixture.locks();
            let exclusive = locks.exclusive(Worker::Model).unwrap().unwrap();
            let (left, right) = UnixStream::pair().unwrap();
            exclusive.send(&left, &[1; 32]).unwrap();
            assert!(locks
                .receive(
                    &right,
                    if variant == 0 {
                        Worker::Model
                    } else {
                        Worker::Acquisition
                    },
                    if variant == 0 { &[2; 32] } else { &[1; 32] }
                )
                .is_err());
            drop(exclusive);
            assert!(locks.shared(Worker::Model).unwrap().is_some());
        }
    }
    #[test]
    fn unlocked_reopened_same_inode_is_not_a_live_handoff() {
        let fixture = Fixture::new();
        let locks = fixture.locks();
        let exclusive = locks.exclusive(Worker::Model).unwrap().unwrap();
        let file = locks.open(Worker::Model, false).unwrap();
        let wrong = Held {
            identity: identity(&file).unwrap(),
            file,
            directory: locks.directory.try_clone().unwrap(),
            path: locks.path.clone(),
            directory_identity: locks.identity,
            worker: Worker::Model,
            mode: Mode::Exclusive,
        };
        assert!(wrong.check().is_err());
        drop(exclusive);
        assert!(wrong.check().is_err());
        assert!(locks.shared(Worker::Model).unwrap().is_some());
    }
    #[test]
    fn replaced_or_aliased_lock_inode_is_fenced_without_releasing_the_old_exclusion() {
        let fixture = Fixture::new();
        let locks = fixture.locks();
        let exclusive = locks.exclusive(Worker::Model).unwrap().unwrap();
        fs::rename(
            fixture.0.join(name(Worker::Model)),
            fixture.0.join("old.lock"),
        )
        .unwrap();
        let _new = locks.open(Worker::Model, true).unwrap();
        assert!(exclusive.check().is_err());
        fs::remove_file(fixture.0.join(name(Worker::Acquisition))).unwrap();
        std::os::unix::fs::symlink(
            fixture.0.join("old.lock"),
            fixture.0.join(name(Worker::Acquisition)),
        )
        .unwrap();
        assert!(locks.shared(Worker::Acquisition).is_err());
    }
}
