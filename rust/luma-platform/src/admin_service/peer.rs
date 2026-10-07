//! A live connection creator, not a current-credential proof or role grant.
use super::*;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

const HANDLE_LIMIT: u64 = 4096;

fn handle_pid(text: &str, expected: i32) -> Result<()> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let value = values
        .next()
        .ok_or("missing Admin peer handle identity")?
        .trim();
    if expected <= 0 || value != expected.to_string() || values.next().is_some() {
        return Err("Admin peer handle does not bind the connection creator".into());
    }
    Ok(())
}

fn inspect(pin: &File, expected: i32) -> Result<()> {
    let path = format!("/proc/self/fdinfo/{}", pin.as_raw_fd());
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != 0x9fa0
        || !file.metadata()?.is_file()
    {
        return Err("Admin peer handle requires kernel procfs metadata".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(HANDLE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > HANDLE_LIMIT {
        return Err("oversized Admin peer handle observation".into());
    }
    handle_pid(std::str::from_utf8(&bytes)?, expected)
}

// No caller-provided PID, serialization, cloning or process-handle reopening.
pub(crate) struct Peer {
    credentials: libc::ucred,
    pin: File,
    stream: UnixStream,
    fenced: Cell<bool>,
}

struct Observation<'a> {
    peer: &'a Peer,
    completed: bool,
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.peer.fenced.set(true);
        }
    }
}

impl Peer {
    pub(crate) fn capture(stream: &UnixStream) -> Result<Self> {
        let credentials = credentials(stream)?;
        if credentials.uid != HUMAN {
            return Err("Admin service peer denied".into());
        }
        Self::bind(stream, credentials)
    }

    fn bind(stream: &UnixStream, credentials: libc::ucred) -> Result<Self> {
        let bound = Self {
            credentials,
            pin: crate::service::peer_pidfd(stream)?,
            stream: stream.try_clone()?,
            fenced: Cell::new(false),
        };
        bound.check()?;
        Ok(bound)
    }

    pub(crate) fn uid(&self) -> u32 {
        self.credentials.uid
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.fenced.get() {
            return Err("Admin peer observation is fenced".into());
        }
        let result = self.current();
        if result.is_err() {
            self.fenced.set(true);
        }
        result
    }

    fn current(&self) -> Result<()> {
        if !crate::resource_manager::pidfd_alive(&self.pin)? {
            return Err("Admin connection creator exited".into());
        }
        inspect(&self.pin, self.credentials.pid)?;
        let now = credentials(&self.stream)?;
        if (now.pid, now.uid, now.gid)
            != (
                self.credentials.pid,
                self.credentials.uid,
                self.credentials.gid,
            )
        {
            return Err("Admin connection identity changed".into());
        }
        let mut poll = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0
            || poll.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
            || !crate::resource_manager::pidfd_alive(&self.pin)?
        {
            return Err("Admin peer disconnected or became unverifiable".into());
        }
        Ok(())
    }

    pub(crate) fn observe<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut observation = Observation {
            peer: self,
            completed: false,
        };
        self.check()?;
        let result = read();
        self.check()?;
        observation.completed = true;
        // A normal policy/authentication denial is not transport loss. The
        // live peer may receive the existing generic, non-authorizing denial.
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> (Peer, UnixStream) {
        let (server, client) = UnixStream::pair().unwrap();
        let peer = Peer::bind(&server, credentials(&server).unwrap()).unwrap();
        (peer, client)
    }

    #[test]
    fn process_handle_identity_is_exact_positive_and_unambiguous() {
        handle_pid("pos:\t0\nPid:\t100\nNSpid:\t100\n", 100).unwrap();
        for text in [
            "",
            "Pid: -1\n",
            "Pid: 0100\n",
            "Pid: +100\n",
            "Pid: 100 2\n",
            "Pid: 101\n",
            "Pid: 100\nPid: 100\n",
        ] {
            assert!(handle_pid(text, 100).is_err());
        }
        assert!(handle_pid("Pid: 0\n", 0).is_err());
    }

    #[test]
    fn live_socket_handle_is_cloexec_and_normal_denial_does_not_fake_disconnect() {
        let (peer, _client) = bound();
        peer.check().unwrap();
        for fd in [peer.pin.as_raw_fd(), peer.stream.as_raw_fd()] {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        assert!(peer
            .observe(|| -> Result<()> { Err("policy denied".into()) })
            .is_err());
        peer.check().unwrap();
        assert_eq!(peer.observe(|| Ok(7)).unwrap(), 7);
    }

    #[test]
    fn disconnect_before_or_during_projection_and_panic_are_sticky() {
        let (peer, client) = bound();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(peer
            .observe(|| -> Result<()> { panic!("disconnected peer reached reader") })
            .is_err());
        assert!(peer.check().is_err());
        let (peer, client) = bound();
        assert!(peer
            .observe(|| {
                drop(client);
                Ok(7)
            })
            .is_err());
        assert!(peer.check().is_err());
        let (peer, _client) = bound();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = peer.observe(|| -> Result<()> { panic!("injected projection panic") });
        }))
        .is_err());
        assert!(peer.check().is_err());
    }
}
