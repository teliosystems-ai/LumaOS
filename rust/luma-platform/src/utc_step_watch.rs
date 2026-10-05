//! Linux clock-step notification for the UTC source composition.
//! Owns a nonblocking, close-on-exec cancel-on-set timer; never sets a clock.
//! Notification supplements clock comparisons, not clock/rate qualification,
//! suspend lifecycle delivery, process approval, protected history or authority.
#![cfg_attr(not(test), allow(dead_code))]
use crate::Result;
use std::fs::File;
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd};

// The protocol already refuses measurements beyond 2100. Expiration or any
// unexpected timer result fences rather than rearming/resetting the observer.
const DEADLINE: libc::time_t = 4_102_444_800;

pub(crate) struct StepWatch {
    timer: File,
    fenced: bool,
}

impl StepWatch {
    pub(crate) fn arm() -> Result<Self> {
        let mut now: libc::timespec = unsafe { zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if now.tv_sec < 0 || now.tv_sec >= DEADLINE {
            return Err("UTC step watch clock is outside supported coordinates".into());
        }
        let mut watch = Self::arm_at(DEADLINE)?;
        watch.check()?;
        Ok(watch)
    }

    fn arm_at(deadline: libc::time_t) -> Result<Self> {
        if deadline <= 0 {
            return Err("UTC step watch cannot be disarmed".into());
        }
        let descriptor = unsafe {
            libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // Acquire ownership before arming, so every error closes this descriptor.
        let timer = unsafe { File::from_raw_fd(descriptor) };
        let mut specification: libc::itimerspec = unsafe { zeroed() };
        specification.it_value.tv_sec = deadline;
        if unsafe {
            libc::timerfd_settime(
                timer.as_raw_fd(),
                libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
                &specification,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self {
            timer,
            fenced: false,
        })
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        if self.fenced {
            return Err("UTC step watch requires reviewed reconstruction".into());
        }
        let mut expirations = 0u64;
        // No retry on EINTR: denying an observation is safer than unbounded work.
        let length = unsafe {
            libc::read(
                self.timer.as_raw_fd(),
                (&mut expirations as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        let error = if length < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        self.accept_read(length, error.as_ref().and_then(io::Error::raw_os_error))
    }

    fn accept_read(&mut self, length: libc::ssize_t, error: Option<i32>) -> Result<()> {
        if self.fenced {
            return Err("UTC step watch requires reviewed reconstruction".into());
        }
        if length == -1 && error == Some(libc::EAGAIN) {
            return Ok(());
        }
        self.fenced = true;
        if length == -1 && error == Some(libc::ECANCELED) {
            return Err("UTC kernel reported a realtime clock discontinuity".into());
        }
        // Expiration, short/zero reads, interrupted/failed syscalls and malformed
        // outcomes all deny. Consuming a notification never makes the watch live.
        Err("UTC step watch expired or became unverifiable".into())
    }

    #[cfg(test)]
    pub(crate) fn expired_fixture() -> Result<Self> {
        // Changes only this owned timer, NEVER the host clock. Wait for its
        // actual expiration readiness, not a scheduler-dependent immediate read.
        let watch = Self::arm_at(1)?;
        let mut pending = libc::pollfd {
            fd: watch.timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pending, 1, 1000) } != 1 || pending.revents != libc::POLLIN {
            return Err("owned timer expiration fixture did not become ready".into());
        }
        Ok(watch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_watch_is_nonblocking_cloexec_and_armed_cancel_on_set() {
        let mut watch = StepWatch::arm().unwrap();
        let descriptor = watch.timer.as_raw_fd();
        let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(status_flags >= 0 && descriptor_flags >= 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{descriptor}")).unwrap();
        let field = |name: &str| {
            info.lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        assert_eq!(field("clockid:"), Some("0")); // CLOCK_REALTIME, not an alarm clock.
        assert_eq!(field("settime flags:"), Some("03"));
        let mut state: libc::itimerspec = unsafe { zeroed() };
        assert_eq!(unsafe { libc::timerfd_gettime(descriptor, &mut state) }, 0);
        assert!(state.it_value.tv_sec > 0);
        assert_eq!(state.it_interval.tv_sec, 0);
        assert_eq!(state.it_interval.tv_nsec, 0);
        watch.check().unwrap();
        watch.check().unwrap();
        assert!(!watch.fenced);
        assert!(StepWatch::arm_at(0).is_err());
    }

    #[test]
    fn canceled_read_fences_even_after_the_kernel_notification_is_consumed() {
        let mut watch = StepWatch::arm().unwrap();
        // Inject a read OUTCOME, not a kernel clock change. This is not an
        // executed ECANCELED delivery or a step-and-restore attack qualification.
        assert_eq!(
            watch
                .accept_read(-1, Some(libc::ECANCELED))
                .unwrap_err()
                .to_string(),
            "UTC kernel reported a realtime clock discontinuity"
        );
        assert!(watch.accept_read(-1, Some(libc::EAGAIN)).is_err());
        assert!(watch.check().is_err());
    }

    #[test]
    fn only_exact_would_block_result_is_live() {
        for (length, error) in [
            (0, None),
            (1, None),
            (7, None),
            (8, None),
            (-1, Some(libc::EINTR)),
            (-1, Some(libc::EBADF)),
            (-1, None),
            (8, Some(libc::EAGAIN)),
            (-2, Some(libc::EAGAIN)),
        ] {
            let mut watch = StepWatch::arm().unwrap();
            assert!(watch.accept_read(length, error).is_err());
            assert!(watch.fenced);
            assert!(watch.accept_read(-1, Some(libc::EAGAIN)).is_err());
        }
    }

    #[test]
    fn actual_timer_expiration_is_a_sticky_denial_without_clock_mutation() {
        let mut watch = StepWatch::expired_fixture().unwrap();
        assert!(watch.check().is_err());
        assert!(watch.fenced);
        // read consumed the expiration count, but there is no auto-rearm.
        assert!(watch.check().is_err());
    }

    #[test]
    fn failed_descriptor_read_is_sticky_and_does_not_fall_back_to_wall_time() {
        let mut watch = StepWatch {
            timer: File::open("/dev/null").unwrap(),
            fenced: false,
        };
        assert!(watch.check().is_err());
        assert!(watch.check().is_err());
    }
}
