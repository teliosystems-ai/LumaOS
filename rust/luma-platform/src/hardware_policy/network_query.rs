//! Closed data exchanged with the independent, query-only cgroup-BPF helper.
//! An attached program is necessary readback, not a grant or proof that all
//! other network/LSM layers permit traffic.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const SOCKET: &str = "/run/luma-hardware/query.sock";
pub(crate) const MAX_REQUEST: usize = 512;
pub(crate) const MAX_REPLY: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub nonce: String,
    pub boot: String,
    #[serde(with = "resources::decimal")]
    pub device: u64,
    #[serde(with = "resources::decimal")]
    pub inode: u64,
    pub worker: Worker,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || crate::tpm::decode::<32>(&self.nonce)? == [0; 32]
            || !generation(&self.boot)
            || self.device == 0
            || self.inode == 0
            || serde_json::to_vec(self)?.len() > MAX_REQUEST
        {
            return Err("invalid closed BPF-query cgroup-generation request".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Direction {
    pub direct_flags: u32,
    pub direct_ids: Vec<u32>,
    pub effective_flags: u32,
    pub effective_ids: Vec<u32>,
}
impl Direction {
    fn validate(&self) -> Result<()> {
        // cgroup attachment flags are NONE, ALLOW_OVERRIDE or ALLOW_MULTI.
        // REPLACE is a mutation argument, not a stored attachment state.
        if !matches!(self.direct_flags, 0 | 1 | 2) || !matches!(self.effective_flags, 0 | 1 | 2) {
            return Err("unknown cgroup-BPF attachment flags".into());
        }
        for ids in [&self.direct_ids, &self.effective_ids] {
            if ids.is_empty()
                || ids.len() > 32
                || ids.iter().any(|id| *id == 0)
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
            {
                return Err(
                    "absent, duplicated or oversized cgroup-BPF attachment readback".into(),
                );
            }
        }
        if self
            .direct_ids
            .iter()
            .any(|id| !self.effective_ids.contains(id))
        {
            return Err("direct worker BPF policy is detached from its effective path".into());
        }
        Ok(())
    }
    fn ancestors(&self) -> Vec<u32> {
        let mut ids = self
            .effective_ids
            .iter()
            .copied()
            .filter(|id| !self.direct_ids.contains(id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }
    fn preserved_ancestors(&self, next: &Self) -> bool {
        self.effective_flags == next.effective_flags && self.ancestors() == next.ancestors()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    pub schema_version: u32,
    pub nonce: String,
    pub boot: String,
    #[serde(with = "resources::decimal")]
    pub device: u64,
    #[serde(with = "resources::decimal")]
    pub inode: u64,
    pub worker: Worker,
    pub ingress: Direction,
    pub egress: Direction,
}
impl Reply {
    pub(crate) fn validate(&self, request: &Request) -> Result<()> {
        request.validate()?;
        if self.schema_version != 1
            || self.nonce != request.nonce
            || self.boot != request.boot
            || self.device != request.device
            || self.inode != request.inode
            || self.worker != request.worker
            || serde_json::to_vec(self)?.len() > MAX_REPLY
        {
            return Err(
                "BPF-query reply substitutes its kernel cgroup generation or challenge".into(),
            );
        }
        self.ingress.validate()?;
        self.egress.validate()
    }
    pub(crate) fn preserved_ancestors(&self, next: &Self) -> Result<()> {
        if self.boot != next.boot
            || self.device != next.device
            || self.inode != next.inode
            || self.worker != next.worker
            || !self.ingress.preserved_ancestors(&next.ingress)
            || !self.egress.preserved_ancestors(&next.egress)
        {
            return Err("network policy changed or lost another ancestor BPF filter".into());
        }
        Ok(())
    }
}

fn kernel_text(path: &Path, maximum: u64) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x9fa0
        || !file.metadata()?.is_file()
    {
        return Err("BPF-query sender identity is not observed through kernel procfs".into());
    }
    let mut text = String::new();
    file.take(maximum + 1).read_to_string(&mut text)?;
    if text.len() as u64 > maximum {
        return Err("BPF-query kernel sender observation exceeds bound".into());
    }
    Ok(text)
}
fn field<'a>(text: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}:");
    let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .ok_or("missing BPF-query sender kernel field")?
        .trim();
    if values.next().is_some() {
        return Err("duplicate BPF-query sender kernel field".into());
    }
    Ok(value)
}
#[cfg(test)]
fn sender_status(status: &str) -> Result<()> {
    helper_status(status, "0000000000081000")
}
fn helper_status(status: &str, bounding: &str) -> Result<()> {
    for name in ["Uid", "Gid"] {
        if field(status, name)?.split_whitespace().collect::<Vec<_>>() != ["0", "0", "0", "0"] {
            return Err("BPF-query sender credentials are not currently root".into());
        }
    }
    if field(status, "NoNewPrivs")? != "1" || field(status, "Seccomp")? != "2" {
        return Err("BPF-query sender privilege confinement is absent".into());
    }
    for name in ["CapPrm", "CapEff", "CapInh", "CapAmb", "CapBnd"] {
        let expected = if name == "CapBnd" {
            bounding
        } else {
            "0000000000000000"
        };
        if field(status, name)? != expected {
            return Err("BPF-query sender did not drop query/authentication capabilities".into());
        }
    }
    Ok(())
}
fn sender(credentials: libc::ucred, pin: &File) -> Result<()> {
    authenticate_sender(
        credentials,
        pin,
        &HelperIdentity {
            executable: "/usr/libexec/luma-os/hardware-bpf-query",
            commandline: "/usr/libexec/luma-os/hardware-bpf-query\0",
            profile: "luma-hardware-query (enforce)\n",
            unit_prefix: "0::/system.slice/luma-hardware-query@",
            bounding: "0000000000081000",
        },
    )
}
pub(super) struct HelperIdentity {
    pub executable: &'static str,
    pub commandline: &'static str,
    pub profile: &'static str,
    pub unit_prefix: &'static str,
    pub bounding: &'static str,
}
pub(super) fn pid_for_handle(pin: &File) -> Result<u32> {
    if !crate::resource_manager::pidfd_alive(pin)? {
        return Err("kernel process handle is not live".into());
    }
    let fdinfo = kernel_text(
        &Path::new("/proc/self/fdinfo").join(pin.as_raw_fd().to_string()),
        4096,
    )?;
    let value = field(&fdinfo, "Pid")?;
    let pid = value.parse::<u32>()?;
    if pid == 0 || value != pid.to_string() {
        return Err("descriptor is not a visible actual kernel process handle".into());
    }
    Ok(pid)
}
pub(super) fn authenticate_sender(
    credentials: libc::ucred,
    pin: &File,
    helper: &HelperIdentity,
) -> Result<()> {
    if credentials.pid <= 1
        || credentials.uid != 0
        || credentials.gid != 0
        || !crate::resource_manager::pidfd_alive(pin)?
    {
        return Err("BPF-query response lacks an actual live root helper sender".into());
    }
    if pid_for_handle(pin)? != credentials.pid as u32 {
        return Err("BPF-query kernel-attached pidfd belongs to another response sender".into());
    }
    crate::credential_observer::kernel_check(pin, 0, 0)?;
    let process = Path::new("/proc").join(credentials.pid.to_string());
    let cgroup = kernel_text(&process.join("cgroup"), 4096)?;
    let instance = cgroup
        .strip_prefix(helper.unit_prefix)
        .and_then(|value| value.strip_suffix(".service\n"))
        .ok_or("BPF-query sender is not the fixed socket-activated helper unit")?;
    if instance.is_empty()
        || instance.len() > 192
        || !instance
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:\\".contains(&byte))
    {
        return Err("BPF-query sender unit instance is not canonical".into());
    }
    let installed = fs::symlink_metadata(helper.executable)?;
    let actual = fs::metadata(process.join("exe"))?;
    if !installed.is_file()
        || installed.uid() != 0
        || installed.mode() & 0o022 != 0
        || (installed.dev(), installed.ino()) != (actual.dev(), actual.ino())
    {
        return Err("BPF-query sender is not the immutable installed fixed helper".into());
    }
    for _ in 0..2 {
        helper_status(
            &kernel_text(&process.join("status"), 65536)?,
            helper.bounding,
        )?;
        if kernel_text(&process.join("attr/current"), 128)? != helper.profile
            || kernel_text(&process.join("cmdline"), 256)? != helper.commandline
            || kernel_text(&process.join("cgroup"), 4096)? != cgroup
            || !crate::resource_manager::pidfd_alive(pin)?
        {
            return Err("BPF-query actual response sender generation changed".into());
        }
    }
    Ok(())
}
pub(super) fn ready(socket: &UnixStream, event: i16, deadline: Instant) -> Result<()> {
    let millis = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or("BPF-query transport deadline elapsed")?
        .as_millis()
        .min(i32::MAX as u128)
        .max(1) as i32;
    let mut fd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: event,
        revents: 0,
    };
    if unsafe { libc::poll(&mut fd, 1, millis) } != 1
        || fd.revents & event == 0
        || fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("BPF-query transport readiness failed or timed out".into());
    }
    Ok(())
}

/// The systemd activation listener's SO_PEERCRED is PID1, not the helper.
/// Authenticate the actual reply using kernel SCM_CREDENTIALS + SCM_PIDFD;
/// unsupported Linux kernels refuse, with no recycled-PID fallback.
pub(crate) fn query(
    cgroup: &File,
    worker: Worker,
    budget: &super::sd_bus::Budget,
) -> Result<Reply> {
    budget.check()?;
    let metadata = cgroup.metadata()?;
    let request = Request {
        schema_version: 1,
        nonce: format!("{}{}", resources::random_id()?, resources::random_id()?),
        boot: current_boot()?,
        device: metadata.dev(),
        inode: metadata.ino(),
        worker,
    };
    request.validate()?;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || unsafe { libc::fstatfs(cgroup.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x63677270
    {
        return Err("BPF-query target is not an actual protected cgroup-v2 directory".into());
    }
    let directory = fs::symlink_metadata("/run/luma-hardware")?;
    let endpoint = fs::symlink_metadata(SOCKET)?;
    if !directory.is_dir()
        || directory.uid() != 0
        || directory.mode() & 0o7777 != 0o700
        || !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.mode() & 0o7777 != 0o600
    {
        return Err("BPF-query fixed root endpoint permissions differ".into());
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let socket = unsafe { UnixStream::from_raw_fd(raw) };
    for option in [libc::SO_PASSCRED, 76] {
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                option,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err("BPF-query requires kernel credential and pidfd ancillary delivery".into());
        }
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as u16;
    for (destination, source) in address.sun_path.iter_mut().zip(SOCKET.bytes()) {
        *destination = source as libc::c_char;
    }
    let deadline = Instant::now() + Duration::from_micros(budget.remaining_usec()?);
    if unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            (size_of::<libc::sa_family_t>() + SOCKET.len() + 1) as libc::socklen_t,
        )
    } != 0
    {
        return Err("BPF-query fixed socket connection failed; no retry".into());
    }
    let listener = crate::service::credentials(&socket)?;
    if listener.pid != 1 || listener.uid != 0 || listener.gid != 0 {
        return Err("BPF-query listener is not native systemd PID1".into());
    }
    let bytes = serde_json::to_vec(&request)?;
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut ancillary = [0usize; 8];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err("BPF-query descriptor ancillary layout unavailable".into());
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), cgroup.as_raw_fd());
    }
    ready(&socket, libc::POLLOUT, deadline)?;
    if unsafe { libc::sendmsg(raw, &message, libc::MSG_NOSIGNAL) } != bytes.len() as isize {
        return Err("BPF-query descriptor send was not exact; no retry".into());
    }
    let (bytes, credentials, pin) = receive(&socket, deadline)?;
    sender(credentials, &pin)?;
    budget.check()?;
    let reply: Reply = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&reply)? != bytes {
        return Err("BPF-query response is not exact canonical typed data".into());
    }
    reply.validate(&request)?;
    if current_boot()? != request.boot || Instant::now() >= deadline {
        return Err("BPF-query observation crossed its actual boot or deadline".into());
    }
    sender(credentials, &pin)?;
    if unsafe { libc::send(raw, b"1".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) } != 1 {
        return Err("BPF-query sender acknowledgement failed".into());
    }
    Ok(reply)
}

pub(super) fn receive(
    socket: &UnixStream,
    deadline: Instant,
) -> Result<(Vec<u8>, libc::ucred, File)> {
    ready(socket, libc::POLLIN, deadline)?;
    let mut bytes = [0u8; MAX_REPLY + 1];
    let mut ancillary = [0usize; 32];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary);
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    let mut credentials = None;
    let mut pin = None;
    let mut malformed = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let length = unsafe { (*header).cmsg_len };
        let payload = length.saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
        if level == libc::SOL_SOCKET
            && kind == libc::SCM_CREDENTIALS
            && payload == size_of::<libc::ucred>()
        {
            let value =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
            if credentials.replace(value).is_some() {
                malformed = true;
            }
        } else if level == libc::SOL_SOCKET && (kind == 4 || kind == libc::SCM_RIGHTS) {
            if payload == 0 || payload % size_of::<i32>() != 0 {
                malformed = true;
            }
            for offset in 0..payload / size_of::<i32>() {
                let fd = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(offset))
                };
                if fd < 0 {
                    malformed = true;
                    continue;
                }
                let file = unsafe { File::from_raw_fd(fd) };
                if kind == 4 && payload == size_of::<i32>() && pin.is_none() {
                    pin = Some(file);
                } else {
                    malformed = true;
                }
            }
        } else {
            malformed = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if count <= 0
        || count as usize > MAX_REPLY
        || malformed
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    {
        return Err(
            "BPF-query response is truncated or lacks exact kernel sender ancillary data".into(),
        );
    }
    let credentials = credentials.ok_or("BPF-query response has no kernel credentials")?;
    let pin = pin.ok_or("BPF-query response has no kernel attached actual sender pidfd")?;
    Ok((bytes[..count as usize].to_vec(), credentials, pin))
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
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let left = unsafe { UnixStream::from_raw_fd(fds[0]) };
        let right = unsafe { UnixStream::from_raw_fd(fds[1]) };
        for option in [libc::SO_PASSCRED, 76] {
            let enabled: libc::c_int = 1;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        left.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&enabled as *const libc::c_int).cast(),
                        size_of::<libc::c_int>() as libc::socklen_t,
                    )
                },
                0
            );
        }
        (left, right)
    }
    #[test]
    fn actual_kernel_passpidfd_pins_the_response_process_but_does_not_bless_an_unconfined_fixture()
    {
        use std::os::unix::process::CommandExt;
        const CHILD: &str = "LUMA_HARDWARE_QUERY_SENDER_FIXTURE";
        if std::env::var_os(CHILD).is_some() {
            let socket = unsafe { UnixStream::from_raw_fd(3) };
            assert_eq!(
                unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
            let payload = b"kernel-sender-transport-only";
            assert_eq!(
                unsafe {
                    libc::send(
                        3,
                        payload.as_ptr().cast(),
                        payload.len(),
                        libc::MSG_NOSIGNAL,
                    )
                },
                payload.len() as isize
            );
            ready(
                &socket,
                libc::POLLIN,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            let mut ack = [0u8; 1];
            assert_eq!(unsafe { libc::recv(3, ack.as_mut_ptr().cast(), 1, 0) }, 1);
            assert_eq!(&ack, b"1");
            return;
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let (receiver, child_socket) = pair();
        let raw = child_socket.as_raw_fd();
        let name=concat!(module_path!(),"::actual_kernel_passpidfd_pins_the_response_process_but_does_not_bless_an_unconfined_fixture").split_once("::").unwrap().1;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--test-threads=1"])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if raw != 3 && libc::dup2(raw, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = Child(command.spawn().unwrap());
        drop(child_socket);
        let (payload, credentials, pin) =
            receive(&receiver, Instant::now() + Duration::from_secs(3)).unwrap();
        assert_eq!(payload, b"kernel-sender-transport-only");
        assert_eq!(credentials.pid, child.0.id() as i32);
        let info = kernel_text(
            &Path::new("/proc/self/fdinfo").join(pin.as_raw_fd().to_string()),
            4096,
        )
        .unwrap();
        assert_eq!(field(&info, "Pid").unwrap(), child.0.id().to_string());
        assert_ne!(
            unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(crate::resource_manager::pidfd_alive(&pin).unwrap());
        // This transport fixture is deliberately not an installed AA helper.
        // Kernel UID/pidfd evidence alone cannot pass production authorization.
        assert!(sender(credentials, &pin).is_err());
        assert_eq!(
            unsafe {
                libc::send(
                    receiver.as_raw_fd(),
                    b"1".as_ptr().cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            },
            1
        );
        assert!(child.0.wait().unwrap().success());
        assert!(!crate::resource_manager::pidfd_alive(&pin).unwrap());
    }
    #[test]
    fn unexpected_actual_rights_and_kernel_pidfd_are_closed_on_transport_refusal() {
        let (receiver, sender) = pair();
        let file = File::open("/dev/null").unwrap();
        let count = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        let mut byte = [b'x'];
        let mut vector = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut ancillary = [0usize; 8];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), file.as_raw_fd());
        }
        assert_eq!(
            unsafe { libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
            1
        );
        assert!(receive(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        assert_eq!(count(), before);
    }
    #[test]
    fn response_sender_must_have_dropped_both_authentication_and_query_capabilities() {
        let status="Uid:\t0 0 0 0\nGid:\t0 0 0 0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000081000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        sender_status(status).unwrap();
        for name in [
            "Uid",
            "Gid",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Seccomp",
        ] {
            let line = status
                .lines()
                .find(|line| line.starts_with(&format!("{name}:")))
                .unwrap();
            assert!(sender_status(&status.replace(&format!("{line}\n"), "")).is_err());
            assert!(sender_status(&format!("{status}{line}\n")).is_err());
            assert!(sender_status(&status.replace(line, &format!("{name}: invalid"))).is_err());
        }
        for (old, new) in [
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000001000"),
            ("CapPrm:\t0000000000000000", "CapPrm:\t0000000000080000"),
            ("CapBnd:\t0000000000081000", "CapBnd:\t0000000000081001"),
            ("Uid:\t0 0 0 0", "Uid:\t0 0 1 0"),
            ("Gid:\t0 0 0 0", "Gid:\t0 0 0 1"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("Seccomp:\t2", "Seccomp:\t0"),
        ] {
            assert!(sender_status(&status.replace(old, new)).is_err());
        }
    }
    fn request() -> Request {
        Request {
            schema_version: 1,
            nonce: "23".repeat(32),
            boot: "12".repeat(16),
            device: 29,
            inode: 402,
            worker: Worker::Model,
        }
    }
    fn direction() -> Direction {
        Direction {
            direct_flags: 2,
            direct_ids: vec![7],
            effective_flags: 0,
            effective_ids: vec![3, 7],
        }
    }
    fn reply(request: &Request) -> Reply {
        Reply {
            schema_version: 1,
            nonce: request.nonce.clone(),
            boot: request.boot.clone(),
            device: request.device,
            inode: request.inode,
            worker: request.worker,
            ingress: direction(),
            egress: direction(),
        }
    }
    #[test]
    fn exact_query_wire_order_and_decimal_strings_match_the_fixed_c_helper() {
        let request = request();
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json,format!("{{\"schema_version\":1,\"nonce\":\"{}\",\"boot\":\"{}\",\"device\":\"29\",\"inode\":\"402\",\"worker\":\"model\"}}",request.nonce,request.boot));
        request.validate().unwrap();
        reply(&request).validate(&request).unwrap();
        for bad in [
            json.replace("\"29\"", "29"),
            json.replace("\"402\"", "\"0402\""),
            json.replace("\"model\"", "\"/sys/fs/cgroup/arbitrary\""),
            json.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            ),
        ] {
            assert!(serde_json::from_str::<Request>(&bad).is_err());
        }
    }
    #[test]
    fn detached_empty_ambiguous_or_substituted_bpf_readback_is_never_success() {
        let request = request();
        for variant in 0..12 {
            let mut result = reply(&request);
            match variant {
                0 => result.nonce = "45".repeat(32),
                1 => result.boot = "67".repeat(16),
                2 => result.device += 1,
                3 => result.inode += 1,
                4 => result.worker = Worker::Acquisition,
                5 => result.ingress.direct_ids.clear(),
                6 => result.egress.effective_ids.clear(),
                7 => result.ingress.direct_ids = vec![7, 7],
                8 => result.egress.effective_ids = vec![0, 7],
                9 => result.ingress.effective_ids = vec![3, 8],
                10 => result.egress.direct_flags = 4,
                _ => result.ingress.effective_ids = (1..34).collect(),
            }
            assert!(result.validate(&request).is_err(), "{variant}");
        }
    }
    #[test]
    fn own_program_replacement_does_not_authorize_removing_other_ancestor_filters() {
        let request = request();
        let before = reply(&request);
        let mut after = before.clone();
        after.ingress.direct_ids = vec![9];
        after.ingress.effective_ids = vec![3, 9];
        before.preserved_ancestors(&after).unwrap();
        for variant in 0..4 {
            let mut changed = after.clone();
            match variant {
                0 => changed.ingress.effective_ids = vec![9],
                1 => changed.egress.effective_ids = vec![4, 7],
                2 => changed.egress.effective_flags = 2,
                _ => changed.inode += 1,
            }
            assert!(before.preserved_ancestors(&changed).is_err());
        }
    }
}
