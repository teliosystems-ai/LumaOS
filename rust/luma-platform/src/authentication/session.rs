//! Process-local PAM session lifetime. Never a role, wire token or UTC grant.
use crate::Result;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const WINDOW_NS: u64 = 30_000_000_000;
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Clock {
    boot: [u8; 16],
    process: u32,
    uid: u32,
    boottime_ns: u64,
}

fn boot_id(bytes: &[u8]) -> Result<[u8; 16]> {
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return Err("local session boot identity unavailable".into());
    }
    let mut result = [0u8; 16];
    let mut digits = 0;
    for (index, &byte) in bytes[..36].iter().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return Err("local session boot identity is not canonical".into());
            }
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err("local session boot identity is not canonical".into()),
        };
        result[digits / 2] = (result[digits / 2] << 4) | nibble;
        digits += 1;
    }
    if result == [0; 16] {
        return Err("local session boot identity is uninitialized".into());
    }
    Ok(result)
}

fn current_boot() -> Result<[u8; 16]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(BOOT_ID)?;
    let metadata = file.metadata()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != 0x9fa0
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("local session requires the kernel boot identity".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(38).read_to_end(&mut bytes)?;
    boot_id(&bytes)
}

impl Clock {
    fn read() -> Result<Self> {
        let boot = current_boot()?;
        let process = std::process::id();
        let uid = unsafe { libc::geteuid() };
        let mut time: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
            || time.tv_sec < 0
            || !(0..1_000_000_000).contains(&time.tv_nsec)
        {
            return Err("local session suspend-aware clock unavailable".into());
        }
        let boottime_ns = (time.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(time.tv_nsec as u64))
            .ok_or("local session clock overflow")?;
        if current_boot()? != boot
            || std::process::id() != process
            || unsafe { libc::geteuid() } != uid
        {
            return Err("local session context changed during observation".into());
        }
        Ok(Self {
            boot,
            process,
            uid,
            boottime_ns,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Active,
    Expired,
    Closed,
    Fenced,
}

// An ordering boundary, not authentication or a transferable capability. Both
// endpoints are captured inside the same protected process from kernel clocks.
pub(super) struct Boundary {
    clock: Clock,
}

impl Boundary {
    pub(super) fn capture() -> Result<Self> {
        Self::at(Clock::read()?)
    }

    fn at(clock: Clock) -> Result<Self> {
        if clock.boot == [0; 16] || clock.process == 0 || clock.uid != 0 {
            return Err("authentication ordering requires its protected process".into());
        }
        Ok(Self { clock })
    }

    pub(super) fn require_later(&self, exchange: &Self) -> Result<()> {
        if exchange.clock.boot != self.clock.boot
            || exchange.clock.process != self.clock.process
            || exchange.clock.uid != self.clock.uid
            || exchange.clock.boottime_ns <= self.clock.boottime_ns
        {
            return Err("fresh PAM exchange must start after the governed login boundary".into());
        }
        Ok(())
    }
}

// There is deliberately no Clone, Deserialize, renewal or restoration method.
// Authentication owns construction; each native request obtains fresh PAM.
pub(super) struct Lifetime {
    issued: Clock,
    deadline_ns: u64,
    last_ns: Cell<u64>,
    phase: Cell<Phase>,
}

struct Observation<'a> {
    lifetime: &'a Lifetime,
    completed: bool,
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.lifetime.fence();
        }
    }
}

impl Lifetime {
    pub(super) fn start() -> Result<Self> {
        Self::at(Clock::read()?)
    }

    pub(super) fn boundary(&self) -> Boundary {
        Boundary { clock: self.issued }
    }

    fn at(issued: Clock) -> Result<Self> {
        if issued.boot == [0; 16] || issued.process == 0 || issued.uid != 0 {
            return Err("local session requires its protected authentication process".into());
        }
        let deadline_ns = issued
            .boottime_ns
            .checked_add(WINDOW_NS)
            .ok_or("local session expiry overflow")?;
        Ok(Self {
            issued,
            deadline_ns,
            last_ns: Cell::new(issued.boottime_ns),
            phase: Cell::new(Phase::Active),
        })
    }

    fn check_at(&self, observed: Result<Clock>) -> Result<()> {
        if self.phase.get() != Phase::Active {
            return Err("local authenticated session is closed; authenticate again".into());
        }
        let result = (|| -> Result<()> {
            let now = observed?;
            if now.boot != self.issued.boot
                || now.process != self.issued.process
                || now.uid != self.issued.uid
                || now.boottime_ns < self.last_ns.get()
            {
                return Err("local authenticated session context changed".into());
            }
            if now.boottime_ns >= self.deadline_ns {
                self.phase.set(Phase::Expired);
                return Err("local authenticated session expired".into());
            }
            self.last_ns.set(now.boottime_ns);
            Ok(())
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }

    pub(super) fn check(&self) -> Result<()> {
        self.check_at(Clock::read())
    }

    fn fence(&self) {
        if self.phase.get() == Phase::Active {
            self.phase.set(Phase::Fenced);
        }
    }

    pub(super) fn close(&self) {
        if self.phase.get() == Phase::Active {
            self.phase.set(Phase::Closed);
        }
    }

    pub(super) fn observe<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.observe_with(|| self.check(), read)
    }

    fn observe_with<T>(
        &self,
        mut current: impl FnMut() -> Result<()>,
        read: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut observation = Observation {
            lifetime: self,
            completed: false,
        };
        current()?;
        let result = read()?;
        current()?;
        observation.completed = true;
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn expired_fixture() -> Result<Self> {
        let mut lifetime = Self::start()?;
        lifetime.deadline_ns = lifetime.issued.boottime_ns;
        Ok(lifetime)
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(ns: u64) -> Clock {
        Clock {
            boot: [1; 16],
            process: 100,
            uid: 0,
            boottime_ns: ns,
        }
    }

    #[test]
    fn exchange_ordering_is_strict_and_bound_to_the_original_boot_process_and_uid() {
        let before = Boundary::at(clock(100)).unwrap();
        before
            .require_later(&Boundary::at(clock(101)).unwrap())
            .unwrap();
        for ns in [0, 99, 100] {
            assert!(before
                .require_later(&Boundary::at(clock(ns)).unwrap())
                .is_err());
        }
        for fault in ["boot", "process", "uid"] {
            let mut changed = clock(101);
            match fault {
                "boot" => changed.boot = [2; 16],
                "process" => changed.process += 1,
                "uid" => changed.uid = 1001,
                _ => unreachable!(),
            }
            assert!(before.require_later(&Boundary { clock: changed }).is_err());
        }
    }

    #[test]
    fn ordering_capture_refuses_uninitialized_and_unprotected_contexts() {
        for fault in ["boot", "process", "uid"] {
            let mut changed = clock(100);
            match fault {
                "boot" => changed.boot = [0; 16],
                "process" => changed.process = 0,
                "uid" => changed.uid = 1001,
                _ => unreachable!(),
            }
            assert!(Boundary::at(changed).is_err());
        }
        let before = Boundary::capture().unwrap();
        let budget = Lifetime::start().unwrap();
        before.require_later(&budget.boundary()).unwrap();
        budget.check().unwrap();
    }

    #[test]
    fn exact_nanosecond_expiry_counts_sleep_and_never_extends_on_use() {
        let lifetime = Lifetime::at(clock(7)).unwrap();
        lifetime.check_at(Ok(clock(7 + WINDOW_NS - 1))).unwrap();
        assert_eq!(lifetime.deadline_ns, 7 + WINDOW_NS);
        assert!(lifetime.check_at(Ok(clock(7 + WINDOW_NS))).is_err());
        assert_eq!(lifetime.phase.get(), Phase::Expired);
        assert!(lifetime.check_at(Ok(clock(7))).is_err());
        lifetime.close();
        assert_eq!(lifetime.phase.get(), Phase::Expired);
        let sleeping = Lifetime::at(clock(10)).unwrap();
        assert!(sleeping.check_at(Ok(clock(10 + WINDOW_NS * 4))).is_err());
    }

    #[test]
    fn missing_clock_regression_reboot_fork_and_privilege_loss_are_sticky() {
        for fault in ["missing", "regression", "boot", "process", "uid"] {
            let lifetime = Lifetime::at(clock(100)).unwrap();
            lifetime.check_at(Ok(clock(101))).unwrap();
            let mut now = clock(102);
            match fault {
                "regression" => now.boottime_ns = 100,
                "boot" => now.boot = [2; 16],
                "process" => now.process += 1,
                "uid" => now.uid = 1001,
                "missing" => (),
                _ => unreachable!(),
            }
            let observation = if fault == "missing" {
                Err("injected clock observation failure".into())
            } else {
                Ok(now)
            };
            assert!(lifetime.check_at(observation).is_err(), "{fault}");
            assert_eq!(lifetime.phase.get(), Phase::Fenced);
            assert!(lifetime.check_at(Ok(clock(103))).is_err());
        }
    }

    #[test]
    fn explicit_logout_is_idempotent_and_cannot_be_renewed_or_reopened() {
        let lifetime = Lifetime::at(clock(1)).unwrap();
        lifetime.close();
        lifetime.close();
        assert_eq!(lifetime.phase.get(), Phase::Closed);
        assert!(lifetime.check_at(Ok(clock(1))).is_err());
        assert!(lifetime
            .observe_with(|| lifetime.check_at(Ok(clock(1))), || Ok(1))
            .is_err());
        assert_eq!(lifetime.phase.get(), Phase::Closed);
    }

    #[test]
    fn failed_or_panicking_principal_projection_cannot_leave_a_session_active() {
        let lifetime = Lifetime::at(clock(1)).unwrap();
        assert!(lifetime
            .observe_with(
                || lifetime.check_at(Ok(clock(1))),
                || -> Result<()> { Err("principal changed".into()) }
            )
            .is_err());
        assert_eq!(lifetime.phase.get(), Phase::Fenced);
        let lifetime = Lifetime::at(clock(1)).unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lifetime.observe_with(
                || lifetime.check_at(Ok(clock(1))),
                || -> Result<()> { panic!("injected failed principal projection") },
            );
        }))
        .is_err());
        assert_eq!(lifetime.phase.get(), Phase::Fenced);
    }

    #[test]
    fn expiry_during_projection_never_returns_a_successful_identity() {
        let lifetime = Lifetime::at(clock(1)).unwrap();
        let checks = Cell::new(0);
        assert!(lifetime
            .observe_with(
                || {
                    checks.set(checks.get() + 1);
                    lifetime.check_at(Ok(clock(if checks.get() == 1 { 1 } else { WINDOW_NS + 1 })))
                },
                || Ok(serde_json::json!({"uid":1001})),
            )
            .is_err());
        assert_eq!(checks.get(), 2);
        assert_eq!(lifetime.phase.get(), Phase::Expired);
        let lifetime = Lifetime::at(clock(1)).unwrap();
        assert!(lifetime
            .observe_with(
                || lifetime.check_at(Ok(clock(WINDOW_NS + 1))),
                || -> Result<()> { panic!("expired session reached a principal reader") },
            )
            .is_err());
    }

    #[test]
    fn lifetime_construction_refuses_uninitialized_context_and_overflow() {
        for issued in [
            Clock {
                boot: [0; 16],
                ..clock(1)
            },
            Clock {
                process: 0,
                ..clock(1)
            },
            Clock {
                uid: 1001,
                ..clock(1)
            },
            clock(u64::MAX - WINDOW_NS + 1),
        ] {
            assert!(Lifetime::at(issued).is_err());
        }
        let last = Lifetime::at(clock(u64::MAX - WINDOW_NS)).unwrap();
        last.check_at(Ok(clock(u64::MAX - 1))).unwrap();
        assert!(last.check_at(Ok(clock(u64::MAX))).is_err());
    }

    #[test]
    fn boot_identity_is_bounded_canonical_nonzero_and_kernel_clock_is_live() {
        let value = b"01234567-89ab-cdef-0123-456789abcdef\n";
        assert_eq!(
            boot_id(value).unwrap(),
            [1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239]
        );
        for bad in [
            b"00000000-0000-0000-0000-000000000000\n".as_slice(),
            b"01234567-89AB-cdef-0123-456789abcdef\n",
            b"01234567_89ab-cdef-0123-456789abcdef\n",
            b"01234567-89ab-cdef-0123-456789abcdef",
            b"01234567-89ab-cdef-0123-456789abcdef\n\n",
        ] {
            assert!(boot_id(bad).is_err());
        }
        let before = Clock::read().unwrap();
        let after = Clock::read().unwrap();
        assert_eq!(before.boot, after.boot);
        assert_eq!(before.process, std::process::id());
        assert_eq!(before.uid, unsafe { libc::geteuid() });
        assert!(after.boottime_ns >= before.boottime_ns);
        Lifetime::start().unwrap().check().unwrap();
    }
}
