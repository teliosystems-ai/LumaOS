//! In-process fixed local bus transport. This layer carries no PAM, grant,
//! Admin-journal or hardware authority. Callers retain their original budget
//! and bind actual service generations before and after any typed operation.
use super::daemon_observer::{self, Proof, Role};
use crate::Result;
use std::ffi::{c_char, c_int, c_void, CString};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::ptr;

const SOCKET: &str = "/run/dbus/system_bus_socket";
const DAEMON: &str = "org.freedesktop.DBus";
#[repr(C)]
struct Error {
    name: *const c_char,
    message: *const c_char,
    owned: c_int,
}
#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
extern "C" {
    fn sd_bus_new(bus: *mut *mut c_void) -> c_int;
    fn sd_bus_set_address(bus: *mut c_void, address: *const c_char) -> c_int;
    fn sd_bus_set_bus_client(bus: *mut c_void, value: c_int) -> c_int;
    fn sd_bus_set_allow_interactive_authorization(bus: *mut c_void, value: c_int) -> c_int;
    fn sd_bus_negotiate_fds(bus: *mut c_void, value: c_int) -> c_int;
    fn sd_bus_set_method_call_timeout(bus: *mut c_void, usec: u64) -> c_int;
    fn sd_bus_start(bus: *mut c_void) -> c_int;
    fn sd_bus_close_unref(bus: *mut c_void) -> *mut c_void;
    fn sd_bus_get_fd(bus: *mut c_void) -> c_int;
    fn sd_bus_message_new_method_call(
        bus: *mut c_void,
        message: *mut *mut c_void,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
    ) -> c_int;
    fn sd_bus_message_set_auto_start(message: *mut c_void, value: c_int) -> c_int;
    fn sd_bus_message_set_allow_interactive_authorization(
        message: *mut c_void,
        value: c_int,
    ) -> c_int;
    fn sd_bus_message_unref(message: *mut c_void) -> *mut c_void;
    fn sd_bus_message_append_basic(
        message: *mut c_void,
        kind: c_char,
        value: *const c_void,
    ) -> c_int;
    fn sd_bus_message_open_container(
        message: *mut c_void,
        kind: c_char,
        contents: *const c_char,
    ) -> c_int;
    fn sd_bus_message_close_container(message: *mut c_void) -> c_int;
    fn sd_bus_message_enter_container(
        message: *mut c_void,
        kind: c_char,
        contents: *const c_char,
    ) -> c_int;
    fn sd_bus_message_exit_container(message: *mut c_void) -> c_int;
    fn sd_bus_message_read_basic(message: *mut c_void, kind: c_char, value: *mut c_void) -> c_int;
    fn sd_bus_message_at_end(message: *mut c_void, complete: c_int) -> c_int;
    fn sd_bus_message_get_type(message: *mut c_void, kind: *mut u8) -> c_int;
    fn sd_bus_message_get_sender(message: *mut c_void) -> *const c_char;
    fn sd_bus_call(
        bus: *mut c_void,
        message: *mut c_void,
        usec: u64,
        error: *mut Error,
        reply: *mut *mut c_void,
    ) -> c_int;
    fn sd_bus_error_free(error: *mut Error) -> *mut Error;
    #[cfg(test)]
    fn sd_bus_message_seal(message: *mut c_void, cookie: u64, timeout_usec: u64) -> c_int;
    #[cfg(test)]
    fn sd_bus_message_rewind(message: *mut c_void, complete: c_int) -> c_int;
    #[cfg(test)]
    fn sd_bus_set_fd(bus: *mut c_void, input: c_int, output: c_int) -> c_int;
}
fn checked(value: c_int) -> Result<c_int> {
    if value < 0 {
        Err(std::io::Error::from_raw_os_error(-value).into())
    } else {
        Ok(value)
    }
}
fn text(value: &str, maximum: usize) -> Result<CString> {
    if value.len() > maximum || value.bytes().any(|value| value < 0x20 || value > 0x7e) {
        return Err("hardware bus text exceeds its inert ASCII bound".into());
    }
    Ok(CString::new(value)?)
}
unsafe fn copied(value: *const c_char, maximum: usize) -> Result<String> {
    if value.is_null() {
        return Err("hardware bus omitted a required string".into());
    }
    let mut bytes = Vec::new();
    for offset in 0..=maximum {
        let byte = unsafe { *value.add(offset) } as u8;
        if byte == 0 {
            return Ok(String::from_utf8(bytes)?);
        }
        if offset == maximum || !(0x20..=0x7e).contains(&byte) {
            return Err("hardware bus string exceeds its ASCII bound".into());
        }
        bytes.push(byte);
    }
    Err("hardware bus string is unterminated".into())
}
fn clock() -> Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0
        || now.tv_sec < 0
        || !(0..1_000_000_000).contains(&now.tv_nsec)
    {
        return Err("hardware bus suspend-aware clock unavailable".into());
    }
    Ok((now.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(now.tv_nsec as u64))
        .ok_or("hardware bus clock overflow")?)
}
pub(crate) struct Budget {
    deadline: u64,
}
impl Budget {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            deadline: clock()?
                .checked_add(1_000_000_000)
                .ok_or("hardware bus deadline overflow")?,
        })
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.remaining_usec().map(|_| ())
    }
    pub(crate) fn remaining_usec(&self) -> Result<u64> {
        let remaining = self
            .deadline
            .checked_sub(clock()?)
            .ok_or("original hardware operation deadline expired")?
            / 1000;
        if remaining == 0 || remaining > 1_000_000 {
            return Err("original hardware operation budget expired or changed".into());
        }
        Ok(remaining)
    }
}
type Node = (u64, u64, u32, u32, u32);
fn node(path: &Path, socket: bool) -> Result<Node> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o7000 != 0
        || if socket {
            !metadata.file_type().is_socket()
        } else {
            !metadata.is_dir() || metadata.mode() & 0o022 != 0
        }
    {
        return Err("fixed system-bus namespace is not root-protected".into());
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    ))
}
fn process_start(pid: u32) -> Result<u64> {
    let path = format!("/proc/{pid}/stat");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x9fa0
    {
        return Err("bus process identity is not actual procfs".into());
    }
    use std::io::Read;
    let mut bytes = String::new();
    (&mut file).take(4097).read_to_string(&mut bytes)?;
    if bytes.len() > 4096 || !bytes.starts_with(&format!("{pid} (")) {
        return Err("bus process stat is malformed".into());
    }
    let tail = bytes
        .rsplit_once(") ")
        .ok_or("bus process stat has no comm boundary")?
        .1;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 || matches!(fields[0], "Z" | "X" | "x") {
        return Err("bus process is absent or exited".into());
    }
    let start = fields[19].parse::<u64>()?;
    if start == 0 {
        return Err("bus process start generation is zero".into());
    }
    Ok(start)
}
pub(crate) struct Bus {
    raw: *mut c_void,
    socket: Node,
    peer: libc::ucred,
    peer_start: u64,
    bus_id: String,
    pidfd: File,
    listener: Proof,
    daemon: Option<(File, Proof)>,
}
pub(crate) struct Message<'bus> {
    raw: *mut c_void,
    bus: &'bus Bus,
    destination: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pub unique_name: String,
    pub pid: u32,
    pub uid: u32,
    pub start_ticks: u64,
}
impl Bus {
    pub(crate) fn open(budget: &Budget) -> Result<Self> {
        budget.check()?;
        for path in ["/", "/run", "/run/dbus"] {
            node(Path::new(path), false)?;
        }
        let socket = node(Path::new(SOCKET), true)?;
        let mut raw = ptr::null_mut();
        checked(unsafe { sd_bus_new(&mut raw) })?;
        if raw.is_null() {
            return Err("system bus allocation missing".into());
        }
        let setup = (|| -> Result<(libc::ucred, u64, File, Proof)> {
            checked(unsafe {
                sd_bus_set_address(
                    raw,
                    b"unix:path=/run/dbus/system_bus_socket\0".as_ptr().cast(),
                )
            })?;
            checked(unsafe { sd_bus_set_bus_client(raw, 1) })?;
            checked(unsafe { sd_bus_negotiate_fds(raw, 0) })?;
            checked(unsafe { sd_bus_set_allow_interactive_authorization(raw, 0) })?;
            checked(unsafe { sd_bus_set_method_call_timeout(raw, budget.remaining_usec()?) })?;
            checked(unsafe { sd_bus_start(raw) })?;
            budget.check()?;
            let fd = checked(unsafe { sd_bus_get_fd(raw) })?;
            let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut size,
                )
            } != 0
                || size as usize != std::mem::size_of::<libc::ucred>()
                || peer.pid < 1
            {
                return Err("system bus peer credentials unavailable".into());
            }
            let start = process_start(peer.pid as u32)?;
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid, 0) } as c_int;
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let pidfd = unsafe { File::from_raw_fd(descriptor) };
            // Socket activation can legitimately retain PID1 as SO_PEERCRED.
            // It is not evidence that PID1 is the actual message-bus daemon.
            let listener = daemon_observer::verify(
                if peer.pid == 1 {
                    Role::SystemdManager
                } else {
                    Role::SystemBus
                },
                &pidfd,
                budget,
            )?;
            if listener.pid != peer.pid as u32
                || listener.start_ticks != start
                || listener.uid != peer.uid
                || listener.gid != peer.gid
            {
                return Err(
                    "system-bus listener differs from fresh privileged read-only observation"
                        .into(),
                );
            }
            Ok((peer, start, pidfd, listener))
        })();
        let (peer, peer_start, pidfd, listener) = match setup {
            Ok(value) => value,
            Err(error) => {
                unsafe { sd_bus_close_unref(raw) };
                return Err(error);
            }
        };
        let mut bus = Self {
            raw,
            socket,
            peer,
            peer_start,
            pidfd,
            listener,
            daemon: None,
            bus_id: String::new(),
        };
        let mut request = bus.method(DAEMON, "/org/freedesktop/DBus", DAEMON, "GetId")?;
        let mut reply = request.call(budget)?;
        let id = reply.read_string(32)?;
        reply.end()?;
        if id.len() != 32
            || !id.bytes().all(|value| value.is_ascii_hexdigit())
            || id == "0".repeat(32)
        {
            return Err("system bus ID is not a nonzero fixed generation".into());
        }
        drop(reply);
        drop(request);
        bus.bus_id = id;
        let scalar = |member: &str| -> Result<u32> {
            let mut request = bus.method(DAEMON, "/org/freedesktop/DBus", DAEMON, member)?;
            request.append_string(DAEMON)?;
            let mut reply = request.call(budget)?;
            let result = reply.read_u32()?;
            reply.end()?;
            Ok(result)
        };
        let pid = scalar("GetConnectionUnixProcessID")?;
        let uid = scalar("GetConnectionUnixUser")?;
        if pid <= 1 {
            return Err(
                "the actual system-bus daemon cannot be inferred from the PID1 socket listener"
                    .into(),
            );
        }
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as c_int;
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let daemon_fd = unsafe { File::from_raw_fd(descriptor) };
        let daemon = daemon_observer::verify(Role::SystemBus, &daemon_fd, budget)?;
        if daemon.pid != pid
            || daemon.uid != uid
            || daemon.start_ticks != process_start(pid)?
            || daemon.boot != bus.listener.boot
        {
            return Err(
                "actual bus-name credentials differ from the fresh pinned daemon process".into(),
            );
        }
        bus.daemon = Some((daemon_fd, daemon));
        bus.verify_proofs(budget)?;
        Ok(bus)
    }
    pub(crate) fn check(&self, budget: &Budget) -> Result<()> {
        budget.check()?;
        if node(Path::new(SOCKET), true)? != self.socket
            || process_start(self.peer.pid as u32)? != self.peer_start
        {
            return Err("system bus socket/daemon generation changed".into());
        }
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, 0) } != 0 {
            return Err("original system bus daemon exited or is unobserved".into());
        }
        let fd = checked(unsafe { sd_bus_get_fd(self.raw) })?;
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
            || peer.pid != self.peer.pid
            || peer.uid != self.peer.uid
            || peer.gid != self.peer.gid
        {
            return Err("actual system-bus connection changed peer identity".into());
        }
        if let Some((descriptor, expected)) = &self.daemon {
            let mut poll = libc::pollfd {
                fd: descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 0) } != 0
                || process_start(expected.pid)? != expected.start_ticks
            {
                return Err("actual system-bus daemon exited or changed generation".into());
            }
        }
        budget.check()
    }
    /// Fresh executable/role observations belong to each complete adapter
    /// callback, not a cache from pre-PAM discovery. Low-level calls retain
    /// local held-peer/pidfd/unique-sender checks without activating a helper
    /// for every individual typed field in the same original budget.
    pub(crate) fn verify_proofs(&self, budget: &Budget) -> Result<()> {
        self.check(budget)?;
        let listener = daemon_observer::verify(
            if self.peer.pid == 1 {
                Role::SystemdManager
            } else {
                Role::SystemBus
            },
            &self.pidfd,
            budget,
        )?;
        if listener != self.listener {
            return Err("actual system-bus listener executable/credentials changed".into());
        }
        if let Some((descriptor, expected)) = &self.daemon {
            if expected.pid == listener.pid {
                if expected != &listener {
                    return Err("system-bus listener and daemon observations disagree".into());
                }
            } else if daemon_observer::verify(Role::SystemBus, descriptor, budget)? != *expected {
                return Err("actual system-bus daemon executable/credentials changed".into());
            }
        }
        self.check(budget)
    }
    pub(crate) fn generation(&self) -> &str {
        &self.bus_id
    }
    pub(crate) fn method<'a>(
        &'a self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<Message<'a>> {
        if destination != DAEMON && !unique(destination) {
            return Err(
                "hardware bus calls require a pinned unique destination or the bus daemon".into(),
            );
        }
        let destination_c = text(destination, 128)?;
        let path = text(path, 256)?;
        let interface = text(interface, 128)?;
        let member = text(member, 64)?;
        let mut raw = ptr::null_mut();
        checked(unsafe {
            sd_bus_message_new_method_call(
                self.raw,
                &mut raw,
                destination_c.as_ptr(),
                path.as_ptr(),
                interface.as_ptr(),
                member.as_ptr(),
            )
        })?;
        if raw.is_null() {
            return Err("hardware bus method allocation missing".into());
        }
        let message = Message {
            raw,
            bus: self,
            destination: destination.into(),
        };
        checked(unsafe { sd_bus_message_set_auto_start(raw, 0) })?;
        checked(unsafe { sd_bus_message_set_allow_interactive_authorization(raw, 0) })?;
        Ok(message)
    }
    pub(crate) fn owner(&self, service: &str, budget: &Budget) -> Result<Owner> {
        if !matches!(
            service,
            "net.hadess.PowerProfiles"
                | "org.freedesktop.UPower.PowerProfiles"
                | "org.freedesktop.systemd1"
        ) {
            return Err("service is outside the compiled hardware bus allowlist".into());
        }
        self.check(budget)?;
        let mut lookup = self.method(DAEMON, "/org/freedesktop/DBus", DAEMON, "GetNameOwner")?;
        lookup.append_string(service)?;
        let mut reply = lookup.call(budget)?;
        let unique_name = reply.read_string(128)?;
        reply.end()?;
        if !unique(&unique_name) {
            return Err("hardware service owner is not an actual unique bus generation".into());
        }
        let scalar = |method: &str| -> Result<u32> {
            let mut request = self.method(DAEMON, "/org/freedesktop/DBus", DAEMON, method)?;
            request.append_string(&unique_name)?;
            let mut reply = request.call(budget)?;
            let value = reply.read_u32()?;
            reply.end()?;
            Ok(value)
        };
        let pid = scalar("GetConnectionUnixProcessID")?;
        let uid = scalar("GetConnectionUnixUser")?;
        if pid < 1 {
            return Err("hardware daemon has no actual process owner".into());
        }
        let owner = Owner {
            unique_name,
            pid,
            uid,
            start_ticks: process_start(pid)?,
        };
        self.check(budget)?;
        Ok(owner)
    }
    pub(crate) fn check_owner(&self, service: &str, owner: &Owner, budget: &Budget) -> Result<()> {
        if self.owner(service, budget)? != *owner {
            return Err("hardware service unique owner/process generation changed".into());
        }
        Ok(())
    }
    pub(crate) fn property<'a>(
        &'a self,
        owner: &Owner,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget,
    ) -> Result<Message<'a>> {
        let mut request = self.method(
            &owner.unique_name,
            path,
            "org.freedesktop.DBus.Properties",
            "Get",
        )?;
        request.append_string(interface)?;
        request.append_string(name)?;
        request.call(budget)
    }
    #[cfg(test)]
    pub(crate) fn fixture() -> Result<Self> {
        // Actual libsystemd codec over an owned anonymous pair: no system/user
        // bus, daemon, name lookup, role observation or effect is contacted.
        use std::os::fd::IntoRawFd;
        let mut raw = ptr::null_mut();
        checked(unsafe { sd_bus_new(&mut raw) })?;
        if raw.is_null() {
            return Err("fixture bus allocation absent".into());
        }
        let setup = (|| -> Result<()> {
            let (left, _right) = std::os::unix::net::UnixStream::pair()?;
            left.set_nonblocking(true)?;
            let descriptor = left.into_raw_fd();
            let result = unsafe { sd_bus_set_fd(raw, descriptor, descriptor) };
            if result < 0 {
                unsafe { libc::close(descriptor) };
            }
            checked(result)?;
            checked(unsafe { sd_bus_start(raw) })?;
            Ok(())
        })();
        if let Err(error) = setup {
            unsafe { sd_bus_close_unref(raw) };
            return Err(error);
        }
        Ok(Self {
            raw,
            socket: (0, 0, 0, 0, 0),
            peer: libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            },
            peer_start: 0,
            bus_id: String::new(),
            pidfd: File::open("/dev/null")?,
            listener: Proof {
                pid: 0,
                start_ticks: 0,
                uid: 0,
                gid: 0,
                exe_dev: 0,
                exe_inode: 0,
                exe_sha256: String::new(),
                cgroup: String::new(),
                boot: String::new(),
            },
            daemon: None,
        })
    }
}
fn unique(value: &str) -> bool {
    value.starts_with(':')
        && value.len() <= 128
        && value[1..].split('.').count() >= 2
        && value[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|value| value.is_ascii_digit()))
}
impl Drop for Bus {
    fn drop(&mut self) {
        unsafe { sd_bus_close_unref(self.raw) };
    }
}
impl<'a> Message<'a> {
    #[cfg(test)]
    pub(crate) fn freeze_fixture(&mut self) -> Result<()> {
        checked(unsafe { sd_bus_message_seal(self.raw, 1, 1_000_000) })?;
        checked(unsafe { sd_bus_message_rewind(self.raw, 1) })?;
        Ok(())
    }
    pub(crate) fn call(&mut self, budget: &Budget) -> Result<Message<'a>> {
        self.bus.check(budget)?;
        let mut error = Error {
            name: ptr::null(),
            message: ptr::null(),
            owned: 0,
        };
        let mut raw = ptr::null_mut();
        let result = unsafe {
            sd_bus_call(
                self.bus.raw,
                self.raw,
                budget.remaining_usec()?,
                &mut error,
                &mut raw,
            )
        };
        unsafe { sd_bus_error_free(&mut error) };
        if result < 0 {
            if !raw.is_null() {
                unsafe { sd_bus_message_unref(raw) };
            }
            return Err(std::io::Error::from_raw_os_error(-result).into());
        }
        if raw.is_null() {
            return Err("hardware bus call returned no reply".into());
        }
        let reply = Message {
            raw,
            bus: self.bus,
            destination: String::new(),
        };
        let mut kind = 0;
        checked(unsafe { sd_bus_message_get_type(raw, &mut kind) })?;
        if kind != 2 || unsafe { copied(sd_bus_message_get_sender(raw), 128) }? != self.destination
        {
            return Err("hardware bus reply type or unique sender differs".into());
        }
        self.bus.check(budget)?;
        Ok(reply)
    }
    fn append(&mut self, kind: u8, value: *const c_void) -> Result<()> {
        checked(unsafe { sd_bus_message_append_basic(self.raw, kind as c_char, value) })?;
        Ok(())
    }
    pub(crate) fn append_string(&mut self, value: &str) -> Result<()> {
        let value = text(value, 256)?;
        self.append(b's', value.as_ptr().cast())
    }
    pub(crate) fn append_bool(&mut self, value: bool) -> Result<()> {
        let value = if value { 1i32 } else { 0i32 };
        self.append(b'b', (&value as *const i32).cast())
    }
    pub(crate) fn append_u8(&mut self, value: u8) -> Result<()> {
        self.append(b'y', (&value as *const u8).cast())
    }
    pub(crate) fn append_u32(&mut self, value: u32) -> Result<()> {
        self.append(b'u', (&value as *const u32).cast())
    }
    pub(crate) fn append_i32(&mut self, value: i32) -> Result<()> {
        self.append(b'i', (&value as *const i32).cast())
    }
    pub(crate) fn open(&mut self, kind: u8, contents: &str) -> Result<()> {
        let contents = text(contents, 128)?;
        checked(unsafe {
            sd_bus_message_open_container(self.raw, kind as c_char, contents.as_ptr())
        })?;
        Ok(())
    }
    pub(crate) fn close(&mut self) -> Result<()> {
        checked(unsafe { sd_bus_message_close_container(self.raw) })?;
        Ok(())
    }
    pub(crate) fn enter(&mut self, kind: u8, contents: &str) -> Result<bool> {
        let contents = text(contents, 128)?;
        Ok(checked(unsafe {
            sd_bus_message_enter_container(self.raw, kind as c_char, contents.as_ptr())
        })? > 0)
    }
    pub(crate) fn exit(&mut self) -> Result<()> {
        checked(unsafe { sd_bus_message_exit_container(self.raw) })?;
        Ok(())
    }
    pub(crate) fn at_end(&self) -> Result<bool> {
        Ok(checked(unsafe { sd_bus_message_at_end(self.raw, 0) })? > 0)
    }
    pub(crate) fn end(&self) -> Result<()> {
        if checked(unsafe { sd_bus_message_at_end(self.raw, 1) })? != 1 {
            return Err("hardware bus reply has trailing or unclosed data".into());
        }
        Ok(())
    }
    fn read(&mut self, kind: u8, value: *mut c_void) -> Result<()> {
        if checked(unsafe { sd_bus_message_read_basic(self.raw, kind as c_char, value) })? != 1 {
            return Err("hardware bus reply omitted a required typed value".into());
        }
        Ok(())
    }
    pub(crate) fn read_string(&mut self, maximum: usize) -> Result<String> {
        if maximum > 4096 {
            return Err("hardware bus string limit exceeds compiled bound".into());
        }
        let mut value = ptr::null();
        self.read(b's', (&mut value as *mut *const c_char).cast())?;
        unsafe { copied(value, maximum) }
    }
    pub(crate) fn read_object_path(&mut self) -> Result<String> {
        let mut value = ptr::null();
        self.read(b'o', (&mut value as *mut *const c_char).cast())?;
        unsafe { copied(value, 256) }
    }
    #[cfg(test)]
    pub(crate) fn read_bool(&mut self) -> Result<bool> {
        let mut value = 0i32;
        self.read(b'b', (&mut value as *mut i32).cast())?;
        if value != 0 && value != 1 {
            return Err("hardware bus boolean differs".into());
        }
        Ok(value == 1)
    }
    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        let mut value = 0u8;
        self.read(b'y', (&mut value as *mut u8).cast())?;
        Ok(value)
    }
    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        let mut value = 0u32;
        self.read(b'u', (&mut value as *mut u32).cast())?;
        Ok(value)
    }
    pub(crate) fn read_i32(&mut self) -> Result<i32> {
        let mut value = 0i32;
        self.read(b'i', (&mut value as *mut i32).cast())?;
        Ok(value)
    }
}
impl Drop for Message<'_> {
    fn drop(&mut self) {
        unsafe { sd_bus_message_unref(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_suspend_aware_budget_never_resets_or_accepts_expiry() {
        let budget = Budget::new().unwrap();
        assert!(budget.remaining_usec().unwrap() <= 1_000_000);
        assert!(Budget {
            deadline: clock().unwrap() - 1
        }
        .check()
        .is_err());
        assert!(Budget {
            deadline: clock().unwrap() + 2_000_000_000
        }
        .check()
        .is_err());
    }
    #[test]
    fn unique_names_and_inert_text_are_bounded_not_well_known_approval() {
        for value in [":1.2", ":99.123456"] {
            assert!(unique(value));
        }
        for value in [
            "org.freedesktop.UPower.PowerProfiles",
            ":",
            ":1",
            ":1.",
            ":a.2",
            ":1.-2",
            ":1.2\n",
        ] {
            assert!(!unique(value));
        }
        assert!(text("line\n", 128).is_err());
        assert!(text("\0", 128).is_err());
        assert!(text(&"x".repeat(129), 128).is_err());
    }
    #[test]
    fn actual_library_message_container_round_trip_has_no_bus_or_effect() {
        let dummy = Bus::fixture().unwrap();
        let mut message = dummy
            .method(DAEMON, "/org/freedesktop/DBus", DAEMON, "GetId")
            .unwrap();
        message.append_string("unit.slice").unwrap();
        message.append_bool(true).unwrap();
        message.open(b'a', "(sv)").unwrap();
        message.open(b'r', "sv").unwrap();
        message.append_string("IPAddressDeny").unwrap();
        message.open(b'v', "a(iayu)").unwrap();
        message.open(b'a', "(iayu)").unwrap();
        message.open(b'r', "iayu").unwrap();
        message.append_i32(libc::AF_INET).unwrap();
        message.open(b'a', "y").unwrap();
        for byte in [0u8; 4] {
            message.append_u8(byte).unwrap();
        }
        message.close().unwrap();
        message.append_u32(0).unwrap();
        message.close().unwrap();
        message.close().unwrap();
        message.close().unwrap();
        message.close().unwrap();
        message.close().unwrap();
        message.freeze_fixture().unwrap();
        assert_eq!(message.read_string(64).unwrap(), "unit.slice");
        assert!(message.read_bool().unwrap());
        assert!(message.enter(b'a', "(sv)").unwrap());
        assert!(message.enter(b'r', "sv").unwrap());
        assert_eq!(message.read_string(64).unwrap(), "IPAddressDeny");
        assert!(message.enter(b'v', "a(iayu)").unwrap());
        assert!(message.enter(b'a', "(iayu)").unwrap());
        assert!(message.enter(b'r', "iayu").unwrap());
        assert_eq!(message.read_i32().unwrap(), libc::AF_INET);
        assert!(message.enter(b'a', "y").unwrap());
        for _ in 0..4 {
            assert_eq!(message.read_u8().unwrap(), 0);
        }
        assert!(message.at_end().unwrap());
        message.exit().unwrap();
        assert_eq!(message.read_u32().unwrap(), 0);
        message.exit().unwrap();
        assert!(message.at_end().unwrap());
        message.exit().unwrap();
        message.exit().unwrap();
        message.exit().unwrap();
        assert!(message.at_end().unwrap());
        message.exit().unwrap();
        message.end().unwrap();
        assert!(message.read_string(1).is_err());
    }
}
