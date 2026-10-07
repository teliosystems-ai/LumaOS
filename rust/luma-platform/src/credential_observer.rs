//! Read-only kernel credential observation. This protocol never conveys a role,
//! a session, a grant, a password, or a caller-selected filesystem path.
use crate::Result;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const DIRECTORY: &str = "/run/luma-peer-observer";
const SOCKET: &str = "/run/luma-peer-observer/credentials.sock";
const BUDGET: Duration = Duration::from_secs(2);
const FRAME: usize = 44;
const MAGIC: &[u8; 4] = b"LCO1";
const MAX_THREADS: usize = 32;

fn field<'a>(text: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}:");
    let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values.next().ok_or("missing kernel observer field")?.trim();
    if values.next().is_some() {
        return Err("ambiguous kernel observer field".into());
    }
    Ok(value)
}

fn ids(status: &str, name: &str, expected: u32) -> Result<()> {
    let values: Vec<_> = field(status, name)?.split_whitespace().collect();
    if values.len() != 4 || values.iter().any(|v| *v != expected.to_string()) {
        return Err("current real/effective/saved/filesystem credentials differ".into());
    }
    Ok(())
}

fn kernel_text(path: &Path, maximum: u64) -> Result<String> {
    bounded_text(path, maximum, 0x9fa0)
}

fn bounded_text(path: &Path, maximum: u64, magic: libc::c_long) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    descriptor_text(file, maximum, magic)
}

fn descriptor_text(mut file: File, maximum: u64, magic: libc::c_long) -> Result<String> {
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != magic
        || !file.metadata()?.is_file()
    {
        return Err("credential observer requires the expected kernel filesystem".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err("kernel credential observation exceeds bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn handle_pid(pin: &File) -> Result<i32> {
    if !crate::resource_manager::pidfd_alive(pin)? {
        return Err("credential target exited".into());
    }
    let text = kernel_text(
        &Path::new("/proc/self/fdinfo").join(pin.as_raw_fd().to_string()),
        4096,
    )?;
    let value = field(&text, "Pid")?;
    let pid: i32 = value.parse()?;
    if pid <= 0 || value != pid.to_string() {
        return Err("descriptor is not a live visible process handle".into());
    }
    Ok(pid)
}

pub(crate) fn kernel_check(pin: &File, uid: u32, gid: u32) -> Result<()> {
    let deadline = Instant::now() + BUDGET;
    let pid = handle_pid(pin)?;
    let path = Path::new("/proc").join(pid.to_string()).join("task");
    let inventory = task_inventory(&path)?;
    let mut threads = Vec::new();
    for tid in &inventory {
        let thread = path.join(tid.to_string());
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&thread)?;
        let mut filesystem: libc::statfs = unsafe { zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type != 0x9fa0
            || !directory.metadata()?.is_dir()
        {
            return Err("caller thread observation requires kernel procfs".into());
        }
        threads.push((*tid, directory));
    }
    // A retained pidfd and both exit checks fence PID reuse. Do not infer UID
    // from /proc/PID ownership: non-dumpable processes may have root-owned proc.
    // Credentials are per-thread. Pin the original task directories: a recycled
    // TID cannot replace a vanished thread while retaining the same numeric set.
    for _ in 0..2 {
        for (tid, directory) in &threads {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    b"status\0".as_ptr().cast(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let status = descriptor_text(unsafe { File::from_raw_fd(fd) }, 65_536, 0x9fa0)?;
            ids(&status, "Uid", uid)?;
            ids(&status, "Gid", gid)?;
            let named = fs::symlink_metadata(path.join(tid.to_string()))?;
            let retained = directory.metadata()?;
            if field(&status, "Tgid")? != pid.to_string()
                || field(&status, "Pid")? != tid.to_string()
                || !named.is_dir()
                || (named.dev(), named.ino()) != (retained.dev(), retained.ino())
                || handle_pid(pin)? != pid
                || Instant::now() >= deadline
            {
                return Err("credential target thread generation changed".into());
            }
        }
        if task_inventory(&path)? != inventory
            || handle_pid(pin)? != pid
            || Instant::now() >= deadline
        {
            return Err("credential target task set changed".into());
        }
    }
    Ok(())
}

fn task_inventory(path: &Path) -> Result<BTreeSet<i32>> {
    let mut threads = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid kernel task name")?;
        let tid: i32 = name.parse()?;
        if tid <= 0
            || name != tid.to_string()
            || !threads.insert(tid)
            || threads.len() > MAX_THREADS
        {
            return Err("caller task inventory exceeds the fixed supported bound".into());
        }
    }
    if threads.is_empty() {
        return Err("caller task inventory is unavailable".into());
    }
    Ok(threads)
}

fn status_confinement(status: &str, mask: u64) -> Result<()> {
    ids(status, "Uid", 0)?;
    ids(status, "Gid", 0)?;
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = field(status, name)?;
        let actual = u64::from_str_radix(value, 16)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || actual & !mask != 0
            || (matches!(name, "CapInh" | "CapAmb") && actual != 0)
        {
            return Err("observer endpoint capability boundary differs".into());
        }
    }
    if field(status, "NoNewPrivs")? != "1" || field(status, "Seccomp")? != "2" {
        return Err("observer endpoint enforcement unavailable".into());
    }
    Ok(())
}

fn security_label(socket: &UnixStream, expected: &str) -> Result<()> {
    let mut bytes = [0u8; 128];
    let mut length = bytes.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length == 0
        || length as usize > bytes.len()
    {
        return Err("observer endpoint security label unavailable".into());
    }
    let bytes = &bytes[..length as usize];
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes != expected.as_bytes() {
        return Err("observer endpoint security label differs".into());
    }
    Ok(())
}

struct Endpoint {
    pin: File,
    pid: i32,
    observer: bool,
}
impl Endpoint {
    fn capture(socket: &UnixStream, observer: bool) -> Result<Self> {
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != size_of::<libc::ucred>()
            || credentials.uid != 0
            || credentials.gid != 0
            || credentials.pid <= 0
        {
            return Err("observer endpoint is not a root kernel peer".into());
        }
        let endpoint = Self {
            pin: crate::service::peer_pidfd(socket)?,
            pid: credentials.pid,
            observer,
        };
        endpoint.check(socket)?;
        Ok(endpoint)
    }
    fn check(&self, socket: &UnixStream) -> Result<()> {
        let (profile, unit, mask) = if self.observer {
            ("luma-peer-observer", "luma-peer-observer.service", 0)
        } else {
            ("luma-admin", "luma-admin.service", 1)
        };
        security_label(socket, &format!("{profile} (enforce)"))?;
        if handle_pid(&self.pin)? != self.pid {
            return Err("observer endpoint process handle differs".into());
        }
        // Admin's hidden proc view cannot reopen a different non-dumpable
        // root process. For the observer, freshly transferred kernel metadata
        // descriptors below supply this proof without widening that proc view.
        if self.observer {
            return Ok(());
        }
        let process = Path::new("/proc").join(self.pid.to_string());
        for _ in 0..2 {
            status_confinement(&kernel_text(&process.join("status"), 65_536)?, mask)?;
            if kernel_text(&process.join("cgroup"), 4096)? != format!("0::/system.slice/{unit}\n")
                || kernel_text(&process.join("attr/current"), 128)?.trim()
                    != format!("{profile} (enforce)")
                || handle_pid(&self.pin)? != self.pid
            {
                return Err("observer endpoint installed generation differs".into());
            }
        }
        Ok(())
    }
}

fn wait(socket: &UnixStream, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or("credential observer deadline exceeded")?;
        let timeout = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events,
            revents: 0,
        };
        let count = unsafe { libc::poll(&mut poll, 1, timeout) };
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if count <= 0
            || Instant::now() >= deadline
            || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
            || poll.revents & events == 0
        {
            return Err("credential observer unavailable or timed out".into());
        }
        return Ok(());
    }
}

fn send(
    socket: &UnixStream,
    bytes: &[u8; FRAME],
    pin: Option<&File>,
    deadline: Instant,
) -> Result<()> {
    let pins: Vec<_> = pin.into_iter().collect();
    send_handles(socket, bytes, &pins, deadline)
}

fn send_handles(
    socket: &UnixStream,
    bytes: &[u8; FRAME],
    pins: &[&File],
    deadline: Instant,
) -> Result<()> {
    if pins.len() > 6 {
        return Err("observer descriptor bundle exceeds bound".into());
    }
    let mut control = [0usize; 8];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: FRAME,
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !pins.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE((pins.len() * size_of::<i32>()) as u32) } as usize;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((pins.len() * size_of::<i32>()) as u32) as usize;
            for (index, pin) in pins.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header)
                        .add(index * size_of::<i32>())
                        .cast::<i32>(),
                    pin.as_raw_fd(),
                );
            }
        }
    }
    loop {
        wait(socket, libc::POLLOUT, deadline)?;
        let count = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if count < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        if count != FRAME as isize || Instant::now() >= deadline {
            return Err("credential observer packet write failed".into());
        }
        return Ok(());
    }
}

fn receive(socket: &UnixStream, deadline: Instant) -> Result<([u8; FRAME], Vec<File>)> {
    loop {
        wait(socket, libc::POLLIN, deadline)?;
        let mut bytes = [0u8; FRAME];
        // Aligned, bounded ancillary storage. Every installed descriptor is
        // immediately RAII-owned, including rejected/truncated packets.
        let mut control = [0usize; 32];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: FRAME,
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        let count = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if count < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut descriptors = Vec::new();
        let mut invalid = false;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let value = unsafe { &*header };
            let base = unsafe { libc::CMSG_LEN(0) } as usize;
            let offset = header as usize - message.msg_control as usize;
            if value.cmsg_len < base || value.cmsg_len > message.msg_controllen - offset {
                return Err("invalid observer ancillary range".into());
            }
            let length = value.cmsg_len - base;
            if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
                if length % size_of::<i32>() != 0 {
                    invalid = true;
                }
                for index in 0..length / size_of::<i32>() {
                    let fd = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header)
                                .add(index * size_of::<i32>())
                                .cast::<i32>(),
                        )
                    };
                    descriptors.push(unsafe { File::from_raw_fd(fd) });
                }
            } else {
                invalid = true;
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        if count != FRAME as isize
            || invalid
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || Instant::now() >= deadline
        {
            return Err("invalid credential observer packet".into());
        }
        return Ok((bytes, descriptors));
    }
}

fn packet(uid: u32, gid: u32) -> Result<[u8; FRAME]> {
    let mut bytes = [0u8; FRAME];
    bytes[..4].copy_from_slice(MAGIC);
    File::open("/dev/urandom")?.read_exact(&mut bytes[4..36])?;
    bytes[36..40].copy_from_slice(&uid.to_be_bytes());
    bytes[40..44].copy_from_slice(&gid.to_be_bytes());
    Ok(bytes)
}

fn request(bytes: &[u8; FRAME], descriptors: &[File]) -> Result<(u32, u32)> {
    let uid = u32::from_be_bytes(bytes[36..40].try_into()?);
    let gid = u32::from_be_bytes(bytes[40..44].try_into()?);
    if &bytes[..4] != MAGIC || descriptors.len() != 1 || uid != 1001 || gid == 0 || gid >= 65534 {
        return Err("unsupported credential observation request".into());
    }
    Ok((uid, gid))
}

fn seqpacket() -> Result<UnixStream> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // UnixStream is only an owning AF_UNIX descriptor here. All IO uses
    // sendmsg/recvmsg; record boundaries are never flattened by Read/Write.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn address(path: &str) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.as_bytes().contains(&0) {
        return Err("invalid observer socket path".into());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *target = byte as libc::c_char;
    }
    let length = (size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    Ok((address, length))
}

fn connect(path: &str, deadline: Instant) -> Result<UnixStream> {
    let socket = seqpacket()?;
    let (address, length) = address(path)?;
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    wait(&socket, libc::POLLOUT, deadline)?;
    Ok(socket)
}

fn protected_path(path: &Path, socket: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let valid_type = if socket {
        metadata.file_type().is_socket() && metadata.nlink() == 1
    } else {
        metadata.is_dir()
    };
    let mode = if socket { 0o600 } else { 0o700 };
    if !valid_type || metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o7777 != mode
    {
        return Err("unsafe credential observer runtime path".into());
    }
    Ok(())
}

pub(crate) fn check(pin: &File, uid: u32, gid: u32) -> Result<()> {
    protected_path(Path::new(DIRECTORY), false)?;
    protected_path(Path::new(SOCKET), true)?;
    let deadline = Instant::now() + BUDGET;
    let socket = connect(SOCKET, deadline)?;
    let endpoint = Endpoint::capture(&socket, true)?;
    let bytes = packet(uid, gid)?;
    handle_pid(pin)?;
    send(&socket, &bytes, Some(pin), deadline)?;
    let (reply, descriptors) = receive(&socket, deadline)?;
    if reply != bytes || descriptors.len() != 6 {
        return Err("credential observation reply substituted".into());
    }
    verify_proof(endpoint.pid, descriptors)?;
    endpoint.check(&socket)?;
    handle_pid(pin)?;
    if Instant::now() >= deadline {
        return Err("credential observer deadline exceeded".into());
    }
    Ok(())
}

fn resource_bounds() -> Result<()> {
    let path = Path::new("/sys/fs/cgroup/system.slice/luma-peer-observer.service");
    for (name, expected) in [
        ("memory.max", "67108864"),
        ("memory.swap.max", "0"),
        ("pids.max", "4"),
    ] {
        if bounded_text(&path.join(name), 128, 0x63677270)?.trim() != expected {
            return Err("credential observer resource boundary differs".into());
        }
    }
    Ok(())
}

fn handle(socket: &UnixStream) -> Result<()> {
    let deadline = Instant::now() + BUDGET;
    let endpoint = Endpoint::capture(socket, false)?;
    let (bytes, descriptors) = receive(socket, deadline)?;
    let (uid, gid) = request(&bytes, &descriptors)?;
    kernel_check(&descriptors[0], uid, gid)?;
    endpoint.check(socket)?;
    kernel_check(&descriptors[0], uid, gid)?;
    let proof = proof_files()?;
    send_handles(socket, &bytes, &proof.iter().collect::<Vec<_>>(), deadline)
}

fn proof_paths(pid: i32) -> Vec<String> {
    let cgroup = "/sys/fs/cgroup/system.slice/luma-peer-observer.service";
    vec![
        format!("/proc/{pid}/status"),
        format!("/proc/{pid}/cgroup"),
        format!("/proc/{pid}/attr/current"),
        format!("{cgroup}/memory.max"),
        format!("{cgroup}/memory.swap.max"),
        format!("{cgroup}/pids.max"),
    ]
}

fn proof_files() -> Result<Vec<File>> {
    // Only these six public, read-only kernel metadata objects can leave the
    // observer. No path supplied in a request is ever opened or transferred.
    let pid = unsafe { libc::getpid() };
    let files = proof_paths(pid)
        .iter()
        .map(|path| -> Result<File> {
            Ok(OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)?)
        })
        .collect::<Result<Vec<_>>>()?;
    status_confinement(&kernel_text(Path::new("/proc/self/status"), 65_536)?, 0)?;
    if kernel_text(Path::new("/proc/self/cgroup"), 4096)?
        != "0::/system.slice/luma-peer-observer.service\n"
        || kernel_text(Path::new("/proc/self/attr/current"), 128)?.trim()
            != "luma-peer-observer (enforce)"
    {
        return Err("observer confinement changed before metadata transfer".into());
    }
    resource_bounds()?;
    Ok(files)
}

fn verify_proof(pid: i32, files: Vec<File>) -> Result<()> {
    if files.len() != 6 {
        return Err("observer kernel proof bundle differs".into());
    }
    let mut text = Vec::new();
    for (index, (expected, file)) in proof_paths(pid).iter().zip(files).enumerate() {
        let target = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if target != Path::new(expected)
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                != libc::O_RDONLY
        {
            return Err("observer metadata descriptor provenance differs".into());
        }
        let (limit, magic) = if index < 3 {
            (65_536, 0x9fa0)
        } else {
            (128, 0x63677270)
        };
        // A duplicate with an advanced offset must not hide kernel fields.
        if unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
            return Err("observer metadata descriptor cannot be rewound".into());
        }
        text.push(descriptor_text(file, limit, magic)?);
    }
    status_confinement(&text[0], 0)?;
    if field(&text[0], "Tgid")? != pid.to_string()
        || text[1] != "0::/system.slice/luma-peer-observer.service\n"
        || text[2].trim() != "luma-peer-observer (enforce)"
        || text[3].trim() != "67108864"
        || text[4].trim() != "0"
        || text[5].trim() != "4"
    {
        return Err("observer live kernel confinement proof differs".into());
    }
    Ok(())
}

pub(crate) fn serve() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    status_confinement(&kernel_text(Path::new("/proc/self/status"), 65_536)?, 0)?;
    if kernel_text(Path::new("/proc/self/attr/current"), 128)?.trim()
        != "luma-peer-observer (enforce)"
        || kernel_text(Path::new("/proc/self/cgroup"), 4096)?
            != "0::/system.slice/luma-peer-observer.service\n"
    {
        return Err("credential observer is not the installed confined service".into());
    }
    resource_bounds()?;
    protected_path(Path::new(DIRECTORY), false)?;
    let listener = seqpacket()?;
    let (address, length) = address(SOCKET)?;
    // A stale protected socket is left for the service manager's runtime
    // directory cleanup. Do not unlink a live or unproved listener on restart.
    if unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))?;
    protected_path(Path::new(SOCKET), true)?;
    if unsafe { libc::listen(listener.as_raw_fd(), 8) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    loop {
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if fd < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(io::Error::last_os_error().into());
        }
        let socket = unsafe { UnixStream::from_raw_fd(fd) };
        // Fixed one-query connections, serial bounded handling, no raw metadata
        // in errors/logs. Missing or damaged observations close without success.
        let _ = handle(&socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (UnixStream, UnixStream) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        unsafe {
            (
                UnixStream::from_raw_fd(fds[0]),
                UnixStream::from_raw_fd(fds[1]),
            )
        }
    }
    fn self_pin(socket: &UnixStream) -> File {
        crate::service::peer_pidfd(socket).unwrap()
    }

    #[test]
    fn current_credentials_require_all_four_exact_unambiguous_ids() {
        ids("Uid: 1001\t1001\t1001\t1001\n", "Uid", 1001).unwrap();
        for value in [
            "",
            "Uid: 1001 1001 1001\n",
            "Uid: 1001 0 1001 1001\n",
            "Uid: 1001 1001 0 1001\n",
            "Uid: 1001 1001 1001 0\n",
            "Uid: 01001 1001 1001 1001\n",
            "Uid: 1001 1001 1001 1001\nUid: 1001 1001 1001 1001\n",
        ] {
            assert!(ids(value, "Uid", 1001).is_err());
        }
        assert!(ids("Gid: 1001 1001 1001 0\n", "Gid", 1001).is_err());
    }

    #[test]
    fn installed_endpoint_requires_zero_observer_caps_and_current_root_ids() {
        let status = "Uid: 0 0 0 0\nGid: 0 0 0 0\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\nCapEff: 0000000000000000\nCapBnd: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1\nSeccomp: 2\n";
        status_confinement(status, 0).unwrap();
        for old in [
            "Uid: 0 0 0 0",
            "Gid: 0 0 0 0",
            "NoNewPrivs: 1",
            "Seccomp: 2",
            "CapBnd: 0000000000000000",
            "CapAmb: 0000000000000000",
        ] {
            let replacement = match old {
                "Uid: 0 0 0 0" => "Uid: 0 1001 0 0",
                "Gid: 0 0 0 0" => "Gid: 0 0 0 1001",
                "NoNewPrivs: 1" => "NoNewPrivs: 0",
                "Seccomp: 2" => "Seccomp: 0",
                "CapBnd: 0000000000000000" => "CapBnd: 0000000000080000",
                _ => "CapAmb: 0000000000000001",
            };
            assert!(status_confinement(&status.replace(old, replacement), 0).is_err());
        }
    }

    #[test]
    fn real_kernel_handle_and_received_cloexec_descriptor_are_observed() {
        let (client, server) = pair();
        let pin = self_pin(&client);
        let deadline = Instant::now() + BUDGET;
        let bytes = packet(1001, 1001).unwrap();
        send(&client, &bytes, Some(&pin), deadline).unwrap();
        let (received, descriptors) = receive(&server, deadline).unwrap();
        assert_eq!(received, bytes);
        request(&received, &descriptors).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(descriptors[0].as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        kernel_check(&descriptors[0], unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        })
        .unwrap();
        assert!(kernel_check(&descriptors[0], 65533, 65533).is_err());
        send(&server, &received, None, deadline).unwrap();
        let (reply, fds) = receive(&client, deadline).unwrap();
        assert_eq!(reply, bytes);
        assert!(fds.is_empty());
    }

    #[test]
    fn ordinary_descriptor_unknown_version_root_and_missing_handle_are_denied() {
        let bytes = packet(1001, 1001).unwrap();
        assert!(request(&bytes, &[]).is_err());
        assert!(request(&packet(0, 0).unwrap(), &[File::open("/dev/null").unwrap()]).is_err());
        let mut old = bytes;
        old[3] = b'0';
        assert!(request(&old, &[File::open("/dev/null").unwrap()]).is_err());
        assert!(kernel_check(&File::open("/dev/null").unwrap(), 1001, 1001).is_err());
    }

    #[test]
    fn truncated_oversized_and_expired_packets_do_not_observe_or_succeed() {
        for size in [0usize, FRAME - 1, FRAME + 1, FRAME * 2] {
            let (client, server) = pair();
            let bytes = vec![0u8; size];
            assert_eq!(
                unsafe {
                    libc::send(
                        client.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        size,
                        libc::MSG_NOSIGNAL,
                    )
                },
                size as isize
            );
            assert!(receive(&server, Instant::now() + BUDGET).is_err());
        }
        let (client, server) = pair();
        assert!(receive(&server, Instant::now() + Duration::from_millis(10)).is_err());
        assert!(send(&client, &packet(1001, 1001).unwrap(), None, Instant::now()).is_err());
    }

    #[test]
    fn unconfined_root_endpoint_is_not_an_installed_observer_or_admin() {
        let (client, _) = pair();
        assert!(Endpoint::capture(&client, true).is_err());
        assert!(Endpoint::capture(&client, false).is_err());
    }

    #[test]
    fn proof_bundle_transfers_only_bounded_cloexec_kernel_metadata() {
        let (client, server) = pair();
        let pid = unsafe { libc::getpid() };
        let status_path = format!("/proc/{pid}/status");
        let files = (0..6)
            .map(|_| File::open(&status_path).unwrap())
            .collect::<Vec<_>>();
        let bytes = packet(1001, 1001).unwrap();
        send_handles(
            &client,
            &bytes,
            &files.iter().collect::<Vec<_>>(),
            Instant::now() + BUDGET,
        )
        .unwrap();
        let (received, descriptors) = receive(&server, Instant::now() + BUDGET).unwrap();
        assert_eq!(received, bytes);
        assert_eq!(descriptors.len(), 6);
        for file in &descriptors {
            assert_ne!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            assert_eq!(
                fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap(),
                Path::new(&status_path)
            );
        }
        // Six real procfs descriptors are insufficient: exact ordered paths,
        // root credentials, enforcing label, cgroup and bounds are all required.
        assert!(verify_proof(pid, descriptors).is_err());
        assert!(verify_proof(pid, vec![File::open(&status_path).unwrap()]).is_err());
        assert!(verify_proof(
            pid,
            (0..6).map(|_| File::open("/dev/null").unwrap()).collect()
        )
        .is_err());
        assert!(send_handles(
            &client,
            &bytes,
            &vec![&files[0]; 7],
            Instant::now() + BUDGET
        )
        .is_err());
    }

    #[test]
    fn extra_and_truncated_ancillary_handles_are_closed_on_refusal() {
        for count in [2usize, 100] {
            let (client, server) = pair();
            let source = File::open("/dev/null").unwrap();
            let fds = vec![source.as_raw_fd(); count];
            let bytes = packet(1001, 1001).unwrap();
            let mut control = [0usize; 64];
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: FRAME,
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE((count * size_of::<i32>()) as u32) } as usize;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN((count * size_of::<i32>()) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    count * size_of::<i32>(),
                );
                assert_eq!(
                    libc::sendmsg(client.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                    FRAME as isize
                );
            }
            if count == 2 {
                let (received, descriptors) = receive(&server, Instant::now() + BUDGET).unwrap();
                assert_eq!(descriptors.len(), 2);
                assert!(request(&received, &descriptors).is_err());
                drop(descriptors);
            } else {
                assert!(receive(&server, Instant::now() + BUDGET).is_err());
            }
            // The same connection remains usable after rejection; malformed
            // ancillary data cannot leak into the next bounded receive.
            send(&client, &bytes, None, Instant::now() + BUDGET).unwrap();
            assert!(receive(&server, Instant::now() + BUDGET)
                .unwrap()
                .1
                .is_empty());
        }
    }

    #[test]
    #[ignore = "isolated disposable container descriptor census with a 64-FD ceiling"]
    fn kernel_fd_census() {
        assert!(Path::new("/.dockerenv").is_file());
        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let census = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = census();
        for _ in 0..16 {
            extra_and_truncated_ancillary_handles_are_closed_on_refusal();
            proof_bundle_transfers_only_bounded_cloexec_kernel_metadata();
            assert_eq!(
                census(),
                before,
                "rejected ancillary/proof descriptors leaked"
            );
        }
    }

    #[test]
    #[ignore = "isolated disposable container bounded live task census"]
    fn kernel_task_inventory_limit() {
        use std::sync::{Arc, Barrier};
        assert!(Path::new("/.dockerenv").is_file());
        let (client, _server) = pair();
        let pin = self_pin(&client);
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        kernel_check(&pin, uid, gid).unwrap();
        let barrier = Arc::new(Barrier::new(MAX_THREADS + 1));
        let threads = (0..MAX_THREADS)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    barrier.wait();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert!(kernel_check(&pin, uid, gid).is_err());
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        kernel_check(&pin, uid, gid).unwrap();
    }

    #[test]
    #[ignore = "requires disposable root container with credential-drop capabilities"]
    fn kernel_credential_change() {
        use std::io::{Read, Write};
        use std::process::Command;
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory =
            std::env::temp_dir().join(format!("luma-observer-kernel-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("observer.sock");
        let listener = seqpacket().unwrap();
        let (address, length) = address(path.to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe {
                libc::bind(
                    listener.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    length,
                )
            },
            0
        );
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "credential_observer::tests::kernel_credential_child",
                "--nocapture",
            ])
            .env("LUMA_OBSERVER_KERNEL_SOCKET", &path)
            .spawn()
            .unwrap();
        wait(&listener, libc::POLLIN, Instant::now() + BUDGET).unwrap();
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let mut socket = unsafe { UnixStream::from_raw_fd(fd) };
        socket.set_read_timeout(Some(BUDGET)).unwrap();
        socket.set_write_timeout(Some(BUDGET)).unwrap();
        let pin = self_pin(&socket);
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [1]);
        kernel_check(&pin, 0, 0).unwrap();
        let pid = handle_pid(&pin).unwrap();
        socket.write_all(&[2]).unwrap();
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [3]);
        assert!(kernel_check(&pin, 0, 0).is_err());
        kernel_check(&pin, 1001, 1001).unwrap();
        // Non-dumpable task directory ownership varies across the supported
        // kernels. The actual four-field credential check above is the proof.
        assert!(fs::metadata(format!("/proc/{pid}")).unwrap().is_dir());
        let (client, server) = pair();
        let bytes = packet(1001, 1001).unwrap();
        send(&client, &bytes, Some(&pin), Instant::now() + BUDGET).unwrap();
        let (received, descriptors) = receive(&server, Instant::now() + BUDGET).unwrap();
        let (uid, gid) = request(&received, &descriptors).unwrap();
        kernel_check(&descriptors[0], uid, gid).unwrap();
        socket.write_all(&[4]).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(kernel_check(&pin, 1001, 1001).is_err());
        assert!(kernel_check(&descriptors[0], uid, gid).is_err());
        drop(socket);
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    #[ignore = "child of kernel_credential_change only"]
    fn kernel_credential_child() {
        use std::io::{Read, Write};
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let path = std::env::var("LUMA_OBSERVER_KERNEL_SOCKET").unwrap();
        assert!(path.starts_with("/tmp/luma-observer-kernel-"));
        let mut socket = connect(&path, Instant::now() + BUDGET).unwrap();
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(BUDGET)).unwrap();
        socket.set_write_timeout(Some(BUDGET)).unwrap();
        socket.write_all(&[1]).unwrap();
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [2]);
        unsafe {
            assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
            assert_eq!(libc::setresgid(1001, 1001, 1001), 0);
            assert_eq!(libc::setresuid(1001, 1001, 1001), 0);
            assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
        }
        socket.write_all(&[3]).unwrap();
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [4]);
    }
}
