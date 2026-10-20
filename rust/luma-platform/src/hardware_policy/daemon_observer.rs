//! Fresh, fixed-role read-only daemon observations from the independent
//! SYS_PTRACE observer. No observation creates a PAM session, grant, resource
//! allocation or hardware permission. The real sender and target are pinned
//! using kernel descriptors; no caller-selected path or command crosses IPC.
use super::network_query::{authenticate_sender, pid_for_handle, ready, receive, HelperIdentity};
use super::sd_bus::Budget;
use super::*;
use std::fs::{self, File};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const DIRECTORY: &str = "/run/luma-hardware-daemon-observer";
const SOCKET: &str = "/run/luma-hardware-daemon-observer/observe.sock";
const MAX_REQUEST: usize = 512;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Role {
    SystemdManager,
    SystemBus,
    PowerProfiles,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub pid: u32,
    #[serde(with = "resources::decimal")]
    pub start_ticks: u64,
    pub uid: u32,
    pub gid: u32,
    #[serde(with = "resources::decimal")]
    pub exe_dev: u64,
    #[serde(with = "resources::decimal")]
    pub exe_inode: u64,
    pub exe_sha256: String,
    pub cgroup: String,
    pub boot: String,
}
impl Proof {
    fn validate(&self, role: Role) -> Result<()> {
        digest(&self.exe_sha256)?;
        if self.pid == 0
            || self.start_ticks == 0
            || self.exe_dev == 0
            || self.exe_inode == 0
            || !generation(&self.boot)
        {
            return Err(
                "daemon observation has no actual process/executable/boot generation".into(),
            );
        }
        let valid = match role {
            Role::SystemdManager => {
                self.pid == 1
                    && self.uid == 0
                    && self.gid == 0
                    && self.cgroup == "0::/init.scope\n"
                    && self.exe_sha256
                        == "b472aadf808bef87c0eb203056a77cb64bd268b71b756306013a53de68a94173"
            }
            Role::SystemBus => {
                self.pid > 1
                    && self.uid != 0
                    && self.gid != 0
                    && self.cgroup == "0::/system.slice/dbus.service\n"
                    && self.exe_sha256
                        == "8c479f1fcddfd6693c736ce541da0955f6752834bdeeef4b928e27f5e974c247"
            }
            Role::PowerProfiles => {
                self.pid > 1
                    && self.uid == 0
                    && self.gid == 0
                    && self.cgroup == "0::/system.slice/power-profiles-daemon.service\n"
                    && self.exe_sha256
                        == "9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a"
            }
        };
        if !valid {
            return Err("daemon observation does not match its closed supported image role".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    nonce: String,
    boot: String,
    #[serde(with = "resources::decimal")]
    deadline_ms: u64,
    role: Role,
}
impl Request {
    fn validate(&self, now: u64) -> Result<()> {
        if self.schema_version != 1
            || crate::tpm::decode::<32>(&self.nonce)? == [0; 32]
            || !generation(&self.boot)
            || self.deadline_ms <= now
            || self.deadline_ms - now > 1000
            || serde_json::to_vec(self)?.len() > MAX_REQUEST
        {
            return Err("daemon observer request exceeds original role/boot/deadline bound".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u32,
    nonce: String,
    boot: String,
    #[serde(with = "resources::decimal")]
    deadline_ms: u64,
    role: Role,
    proof: Proof,
}
impl Reply {
    fn validate(&self, request: &Request, pid: u32) -> Result<()> {
        if self.schema_version != 1
            || self.nonce != request.nonce
            || self.boot != request.boot
            || self.deadline_ms != request.deadline_ms
            || self.role != request.role
            || self.proof.boot != request.boot
            || self.proof.pid != pid
        {
            return Err(
                "daemon observer reply substitutes its actual challenge, role or process handle"
                    .into(),
            );
        }
        self.proof.validate(request.role)
    }
}

fn connect(deadline: Instant) -> Result<UnixStream> {
    let directory = fs::symlink_metadata(DIRECTORY)?;
    let endpoint = fs::symlink_metadata(SOCKET)?;
    if !directory.is_dir()
        || directory.uid() != 0
        || directory.gid() != 0
        || directory.mode() & 0o7777 != 0o700
        || !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.gid() != 0
        || endpoint.mode() & 0o7777 != 0o600
    {
        return Err("fixed daemon observer namespace is not private root ownership".into());
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
            return Err("daemon observer requires actual kernel credential/pidfd delivery".into());
        }
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as u16;
    for (to, from) in address.sun_path.iter_mut().zip(SOCKET.bytes()) {
        *to = from as libc::c_char;
    }
    if unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            (size_of::<libc::sa_family_t>() + SOCKET.len() + 1) as libc::socklen_t,
        )
    } != 0
    {
        return Err("fixed daemon observer connection failed; no retry".into());
    }
    let peer = crate::service::credentials(&socket)?;
    if peer.pid != 1 || peer.uid != 0 || peer.gid != 0 {
        return Err("daemon observer activation listener is not native PID1".into());
    }
    ready(&socket, libc::POLLOUT, deadline)?;
    Ok(socket)
}
fn send(socket: &UnixStream, request: &Request, pin: &File, deadline: Instant) -> Result<()> {
    let bytes = serde_json::to_vec(request)?;
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
        return Err("daemon observer pidfd ancillary layout unavailable".into());
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), pin.as_raw_fd());
    }
    ready(socket, libc::POLLOUT, deadline)?;
    if unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }
        != bytes.len() as isize
    {
        return Err("daemon observer pidfd transfer was not exact; no retry".into());
    }
    Ok(())
}

pub(crate) fn verify(role: Role, pin: &File, budget: &Budget) -> Result<Proof> {
    budget.check()?;
    let pid = pid_for_handle(pin)?;
    let remaining = budget.remaining_usec()?;
    let now = crate::resource_manager::now()?;
    let request = Request {
        schema_version: 1,
        nonce: format!("{}{}", resources::random_id()?, resources::random_id()?),
        boot: current_boot()?,
        deadline_ms: now
            .checked_add(remaining / 1000)
            .ok_or("daemon observation deadline overflow")?,
        role,
    };
    request.validate(now)?;
    let deadline = Instant::now() + Duration::from_micros(budget.remaining_usec()?);
    let socket = connect(deadline)?;
    send(&socket, &request, pin, deadline)?;
    let (bytes, credentials, sender_pin) = receive(&socket, deadline)?;
    let helper = HelperIdentity {
        executable: "/usr/libexec/luma-os/hardware-daemon-observer",
        commandline: "/usr/libexec/luma-os/hardware-daemon-observer\0",
        profile: "luma-hardware-daemon-observer (enforce)\n",
        unit_prefix: "0::/system.slice/luma-hardware-daemon-observer@",
        bounding: "0000000000080000",
    };
    authenticate_sender(credentials, &sender_pin, &helper)?;
    let reply: Reply = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&reply)? != bytes {
        return Err("daemon observer reply is not canonical closed data".into());
    }
    reply.validate(&request, pid)?;
    request.validate(crate::resource_manager::now()?)?;
    if pid_for_handle(pin)? != pid || current_boot()? != request.boot {
        return Err("daemon target exited or boot changed during observation".into());
    }
    budget.check()?;
    authenticate_sender(credentials, &sender_pin, &helper)?;
    if unsafe {
        libc::send(
            socket.as_raw_fd(),
            b"1".as_ptr().cast(),
            1,
            libc::MSG_NOSIGNAL,
        )
    } != 1
    {
        return Err("daemon observer current sender acknowledgement failed".into());
    }
    budget.check()?;
    Ok(reply.proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            nonce: "12".repeat(32),
            boot: "23".repeat(16),
            deadline_ms: 2000,
            role: Role::PowerProfiles,
        }
    }
    fn proof() -> Proof {
        Proof {
            pid: 42,
            start_ticks: 17,
            uid: 0,
            gid: 0,
            exe_dev: 4,
            exe_inode: 8,
            exe_sha256: "9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a".into(),
            cgroup: "0::/system.slice/power-profiles-daemon.service\n".into(),
            boot: "23".repeat(16),
        }
    }
    #[test]
    fn exact_observer_wire_has_no_pid_path_command_or_portable_authority() {
        let request = request();
        request.validate(1000).unwrap();
        assert_eq!(serde_json::to_string(&request).unwrap(),format!("{{\"schema_version\":1,\"nonce\":\"{}\",\"boot\":\"{}\",\"deadline_ms\":\"2000\",\"role\":\"power-profiles\"}}",request.nonce,request.boot));
        let mut changed = request.clone();
        changed.deadline_ms = 2001;
        assert!(changed.validate(1000).is_err());
        changed = request.clone();
        changed.deadline_ms = 1000;
        assert!(changed.validate(1000).is_err());
        let json = serde_json::to_string(&request).unwrap();
        for bad in [
            json.replace("\"role\":", "\"pid\":42,\"role\":"),
            json.replace("power-profiles", "/proc/42/exe"),
            json.replace("\"2000\"", "2000"),
            json.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            ),
        ] {
            assert!(serde_json::from_str::<Request>(&bad).is_err());
        }
    }
    #[test]
    fn actual_role_process_and_executable_generations_cannot_be_substituted() {
        let request = request();
        let reply = Reply {
            schema_version: 1,
            nonce: request.nonce.clone(),
            boot: request.boot.clone(),
            deadline_ms: request.deadline_ms,
            role: request.role,
            proof: proof(),
        };
        reply.validate(&request, 42).unwrap();
        for variant in 0..12 {
            let mut changed = reply.clone();
            match variant {
                0 => changed.nonce = "34".repeat(32),
                1 => changed.deadline_ms += 1,
                2 => changed.role = Role::SystemdManager,
                3 => changed.proof.pid = 43,
                4 => changed.proof.start_ticks = 0,
                5 => changed.proof.uid = 1000,
                6 => changed.proof.gid = 1000,
                7 => changed.proof.exe_inode = 0,
                8 => changed.proof.exe_dev = 0,
                9 => changed.proof.exe_sha256 = "ab".repeat(32),
                10 => changed.proof.cgroup = "0::/user.slice/arbitrary.service\n".into(),
                _ => changed.proof.boot = "45".repeat(16),
            }
            assert!(changed.validate(&request, 42).is_err(), "{variant}");
        }
    }
}
