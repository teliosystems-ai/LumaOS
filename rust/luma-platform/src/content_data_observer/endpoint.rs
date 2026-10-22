//! Exact actual kernel peer pins, not received JSON credentials or a PID reopen.
use super::*;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
pub(super) struct Peer {
    pin: File,
    pid: i32,
    start: u64,
    label: String,
    kernel: Option<kernel_unix::KernelUnix>,
}
fn start(pid: i32) -> Result<u64> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(format!("/proc/{pid}/stat"))?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 || fs.f_type != 0x9fa0 {
        return Err("observer generation requires genuine procfs".into());
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text)?;
    if text.len() > 4096 || !text.starts_with(&format!("{pid} (")) {
        return Err("observer process stat malformed".into());
    }
    let token = text
        .rsplit_once(") ")
        .ok_or("observer process stat terminator absent")?
        .1
        .split_ascii_whitespace()
        .nth(19)
        .ok_or("observer process start absent")?;
    let value: u64 = token.parse()?;
    if value == 0 || value.to_string() != token {
        return Err("observer process start noncanonical".into());
    }
    Ok(value)
}
fn label(socket: &UnixStream) -> Result<String> {
    let mut data = [0u8; 256];
    let mut size = data.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            data.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size == 0
        || size as usize > data.len()
    {
        return Err("observer peer security label unavailable".into());
    }
    let bytes = &data[..size as usize];
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    Ok(std::str::from_utf8(bytes)?.into())
}
impl Peer {
    pub(super) fn capture(socket: &UnixStream, expected: &str) -> Result<Self> {
        let kernel = kernel_unix::KernelUnix::capture()?;
        let mut peer = Self::pin(socket, expected)?;
        peer.kernel = Some(kernel);
        peer.check(socket)?;
        Ok(peer)
    }
    fn pin(socket: &UnixStream, expected: &str) -> Result<Self> {
        let peer = crate::service::credentials(socket)?;
        if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 || label(socket)? != expected {
            return Err("observer requires exact current root enforcing kernel peer".into());
        }
        let pin = crate::service::peer_pidfd(socket)?;
        if !crate::resource_manager::pidfd_alive(&pin)? {
            return Err("observer peer exited before capture".into());
        }
        let result = Self {
            pin,
            pid: peer.pid,
            start: start(peer.pid)?,
            label: expected.into(),
            kernel: None,
        };
        result.check(socket)?;
        Ok(result)
    }
    pub(super) fn check(&self, socket: &UnixStream) -> Result<()> {
        if let Some(kernel) = &self.kernel {
            kernel.check()?;
        }
        let current = crate::service::credentials(socket)?;
        if (current.pid, current.uid, current.gid) != (self.pid, 0, 0)
            || !crate::resource_manager::pidfd_alive(&self.pin)?
            || start(self.pid)? != self.start
            || label(socket)? != self.label
        {
            return Err("observer original kernel peer/label/start generation changed".into());
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn software_fixture(socket: &UnixStream) -> Result<Self> {
        // Retain the REAL disposable socket peer's label/IDs/pidfd/start. This
        // does not claim that an unconfined fixture is the product C profile.
        Self::pin(socket, &label(socket)?)
    }
}
