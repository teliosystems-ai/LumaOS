//! Polling supervision of the one owned model child. Not a resource lease,
//! protected generation, readiness claim or arbitrary descendant sandbox.
use super::*;
use std::os::fd::FromRawFd;
use std::process::Child;
use std::time::Duration;

const POLL: Duration = Duration::from_millis(500);

pub(super) struct Fence {
    hashes: (Option<String>, Option<String>),
    trial: Option<Vec<u8>>,
}

impl Fence {
    pub(super) fn capture(state: &Path, p: &Profile) -> Result<Self> {
        let selection = serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id}))?;
        let key = activation_bytes(&state.join("model-auth/api-key"), 64)?
            .ok_or("model runtime credential missing")?;
        if key.len() != 64 || !key.iter().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid model runtime credential; preserve state".into());
        }
        let hashes = validation::worker_hashes(state)?;
        if hashes
            != (
                Some(bundle::hex(&Sha256::digest(&selection))),
                Some(bundle::hex(&Sha256::digest(&key))),
            )
        {
            return Err("model runtime configuration changed or is not canonical".into());
        }
        let mut fence = Self {
            hashes,
            trial: validation::record_bytes(state)?,
        };
        fence.check(state, p)?;
        Ok(fence)
    }

    pub(super) fn check(&mut self, state: &Path, p: &Profile) -> Result<()> {
        recovery_disablement_absent(state)?;
        validation::worker_admission(state, p)?;
        let trial = validation::record_bytes(state)?;
        if trial
            .as_ref()
            .map_or(false, |bytes| self.trial.as_ref() != Some(bytes))
        {
            return Err("model validation trial changed during runtime".into());
        }
        if validation::worker_hashes(state)? != self.hashes {
            return Err("model runtime inputs changed during supervision".into());
        }
        // Recheck around bounded observations. Root completion may remove the
        // initial trial; it must never later reappear or be substituted. Root is
        // trusted here: absence is not a protected receipt or generation proof.
        recovery_disablement_absent(state)?;
        validation::worker_admission(state, p)?;
        if validation::record_bytes(state)? != trial
            || validation::worker_hashes(state)? != self.hashes
        {
            return Err("model runtime fence changed during observation".into());
        }
        self.trial = trial;
        Ok(())
    }
}

fn arm_parent_death(command: &mut Command) {
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            // Only async-signal-safe syscalls run here. The direct child is a
            // fixed non-setid, capability-free runtime, with no credential
            // changes after this hook. Forked descendants do not inherit this
            // kernel setting; the installed unit retains control-group killing.
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Parent death before registration otherwise has no notification.
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
}

struct OwnedRuntime {
    pidfd: File,
    reaped: bool,
}

impl OwnedRuntime {
    fn pin(child: &Child) -> Result<Self> {
        // The single-threaded native service has default SIGCHLD handling and
        // no other child reaper. Do not wait before obtaining this stable handle.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        if fd < 0 {
            return Err("model PID-handle unavailable; parent-death/unit teardown required".into());
        }
        Ok(Self {
            pidfd: unsafe { File::from_raw_fd(fd as i32) },
            reaped: false,
        })
    }

    fn observe(&mut self, flags: libc::c_int) -> Result<Option<bool>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                flags,
            )
        } != 0
        {
            return Err("model child observation/reap failed; termination unconfirmed".into());
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        if ![libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED].contains(&info.si_code) {
            return Err("unexpected model child observation; no cleanup claim".into());
        }
        self.reaped = true;
        Ok(Some(
            info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0,
        ))
    }

    fn poll(&mut self) -> Result<Option<bool>> {
        self.observe(libc::WEXITED | libc::WNOHANG)
    }

    fn terminate(&mut self) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        // Signal and reap through the exact kernel handle, never a stored PID,
        // process-group kill, host enumeration or unrelated service control.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err("owned model child termination failed; no cleanup claim".into());
            }
        }
        self.observe(libc::WEXITED)?
            .ok_or("owned model child reap missing; no cleanup claim")?;
        Ok(())
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate();
        }
    }
}

pub(super) fn run(command: &mut Command, mut check: impl FnMut() -> Result<()>) -> Result<()> {
    check()?;
    require_waitable_children()?;
    arm_parent_death(command);
    let child = command.spawn()?;
    // Failure to pin is a startup failure, not permission to fall back to PID
    // signaling. The sole production caller returns to main and exits; the
    // already-armed parent-death signal/unit teardown handles that uncertainty.
    let mut owned = OwnedRuntime::pin(&child)?;
    loop {
        if check().is_err() {
            owned.terminate()?;
            return Err("model supervision fence failed; owned child reaped; readiness/resource return not proven".into());
        }
        if let Some(success) = owned.poll()? {
            return if success {
                Ok(())
            } else {
                Err("owned model runtime exited unsuccessfully".into())
            };
        }
        // Detection has a scheduling/observation interval; never claim an
        // atomic boundary or a wall-clock cleanup deadline for blocked I/O.
        std::thread::sleep(POLL);
    }
}

fn require_waitable_children() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction != libc::SIG_DFL
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err("model supervisor requires default waitable-child handling".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_pid_handle_never_signals_or_reaps_another_owned_process() {
        require_waitable_children().unwrap();
        let mut first = Command::new("/bin/true").spawn().unwrap();
        let mut owned = OwnedRuntime::pin(&first).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(owned.pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(first.wait().unwrap().success()); // deliberate wait-ownership loss, fixture only
        let mut other = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        assert!(owned.poll().is_err());
        assert!(owned.terminate().is_err());
        drop(owned); // retries through the completed handle, never another PID
        let untouched = other.try_wait().unwrap().is_none();
        other.kill().unwrap();
        other.wait().unwrap();
        assert!(untouched);
    }
}
