//! Linux measurement-stream boundary, NOT a grant API.
//! Non-fixture construction requires the immutable-runtime endpoint admission.
//! History, source qualification and human acquisition remain separate checks.
#![cfg_attr(not(test), allow(dead_code))]
use crate::{
    utc_policy::ApprovedPolicy,
    utc_protocol::{self, ProducerEpoch, ProducerRound, SourceData},
    Result,
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;

const MAX_FRAME_SIZE: usize = utc_protocol::MAX_ENVELOPE_SIZE;
pub(crate) const DRAIN_LIMIT: usize = 8;

fn bounded_text(path: &str) -> Result<String> {
    let mut value = String::new();
    File::open(path)?.take(16_385).read_to_string(&mut value)?;
    if value.len() > 16_384 {
        return Err("UTC process observation exceeded bound".into());
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessObservation {
    start_ticks: u64,
    executable_device: u64,
    executable_inode: u64,
    profile: String,
    cgroup: String,
    controls: Vec<String>,
}

fn process_observation(pid: i32, uid: u32, gid: u32) -> Result<ProcessObservation> {
    let prefix = format!("/proc/{pid}");
    let stat = bounded_text(&format!("{prefix}/stat"))?;
    let open = stat.find('(').ok_or("invalid UTC process stat")?;
    let close = stat
        .rfind(')')
        .filter(|end| *end > open)
        .ok_or("invalid UTC process stat")?;
    if stat[..open].trim().parse::<i32>()? != pid {
        return Err("UTC process PID changed".into());
    }
    let start_ticks = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or("missing UTC process start")?
        .parse()?;
    let status = bounded_text(&format!("{prefix}/status"))?;
    let field = |name: &str| -> Result<&str> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .ok_or_else(|| "missing UTC process controls".into())
    };
    for (name, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let values = field(name)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if values != vec![expected; 4] {
            return Err("UTC process credentials changed".into());
        }
    }
    let controls = [
        "CapInh:",
        "CapPrm:",
        "CapEff:",
        "CapBnd:",
        "CapAmb:",
        "NoNewPrivs:",
        "Seccomp:",
    ]
    .iter()
    .map(|name| field(name).map(str::to_owned))
    .collect::<Result<Vec<_>>>()?;
    let executable = fs::metadata(format!("{prefix}/exe"))?;
    if !executable.is_file() {
        return Err("UTC producer executable is not regular".into());
    }
    Ok(ProcessObservation {
        start_ticks,
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
        profile: bounded_text(&format!("{prefix}/attr/current"))?,
        cgroup: bounded_text(&format!("{prefix}/cgroup"))?,
        controls,
    })
}

struct PinnedProcess {
    pid: i32,
    uid: u32,
    gid: u32,
    pidfd: File,
    observation: ProcessObservation,
}
impl PinnedProcess {
    fn capture(pid: i32, uid: u32, gid: u32) -> Result<Self> {
        if pid <= 0 {
            return Err("invalid UTC producer PID".into());
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let pidfd = unsafe { File::from_raw_fd(i32::try_from(fd)?) };
        live(&pidfd)?;
        let observation = process_observation(pid, uid, gid)?;
        let peer = Self {
            pid,
            uid,
            gid,
            pidfd,
            observation,
        };
        peer.recheck()?;
        Ok(peer)
    }
    fn recheck(&self) -> Result<()> {
        live(&self.pidfd)?;
        if process_observation(self.pid, self.uid, self.gid)? != self.observation {
            return Err("UTC producer process or runtime changed".into());
        }
        live(&self.pidfd)
    }
    fn matches(&self, credentials: libc::ucred) -> bool {
        credentials.pid == self.pid && credentials.uid == self.uid && credentials.gid == self.gid
    }
}
fn live(pidfd: &File) -> Result<()> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let count = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count != 0 || descriptor.revents != 0 {
        return Err("UTC producer has exited or is unavailable".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Capture {
    boot_ms: u64,
    mono_ms: u64,
    real_ms: i64,
}
fn clock_ms(clock: libc::clockid_t) -> Result<u64> {
    let mut value: libc::timespec = unsafe { zeroed() };
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if value.tv_nsec < 0 || value.tv_nsec >= 1_000_000_000 {
        return Err("invalid UTC capture nanoseconds".into());
    }
    u64::try_from(value.tv_sec)?
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(value.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| "UTC capture clock overflow".into())
}
fn capture_clocks() -> Result<Capture> {
    let before = clock_ms(libc::CLOCK_BOOTTIME)?;
    let mono_ms = clock_ms(libc::CLOCK_MONOTONIC)?;
    let real_ms = i64::try_from(clock_ms(libc::CLOCK_REALTIME)?)?;
    let boot_ms = clock_ms(libc::CLOCK_BOOTTIME)?;
    if boot_ms < before || boot_ms - before > 2 || boot_ms < mono_ms {
        return Err("UTC receiver clock capture is inconsistent or delayed".into());
    }
    Ok(Capture {
        boot_ms,
        mono_ms,
        real_ms,
    })
}
pub(crate) fn kernel_boot() -> Result<[u8; 16]> {
    let value = bounded_text("/proc/sys/kernel/random/boot_id")?;
    let bytes = value.trim_end_matches('\n').as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|i| bytes[*i] != b'-') {
        return Err("invalid UTC kernel boot identity".into());
    }
    let digits: Vec<u8> = bytes
        .iter()
        .enumerate()
        .filter_map(|(i, value)| (![8, 13, 18, 23].contains(&i)).then_some(*value))
        .collect();
    let mut boot = [0; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        boot[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    if boot == [0; 16] {
        return Err("uninitialized UTC kernel boot identity".into());
    }
    Ok(boot)
}

// State validation supplements the kernel check; all numeric inputs remain data.
struct Cursor {
    epoch: ProducerEpoch,
    barrier_ms: u64,
    sequence: u64,
    previous: Option<Capture>,
    samples: [Option<SourceData>; 3],
    lost: [bool; 3],
}
impl Cursor {
    fn new(epoch: ProducerEpoch, barrier_ms: u64) -> Result<Self> {
        if epoch.boot_id == [0; 16]
            || epoch.process_generation == 0
            || epoch.source_clock_generation == 0
            || epoch.policy_digest != ApprovedPolicy::fixed()?.digest()
        {
            return Err("uninitialized UTC receiver epoch".into());
        }
        Ok(Self {
            epoch,
            barrier_ms,
            sequence: 0,
            previous: None,
            samples: [None; 3],
            lost: [false; 3],
        })
    }
    fn accept(&mut self, round: &ProducerRound, now: Capture) -> Result<()> {
        if round.epoch != self.epoch
            || round.sequence <= self.sequence
            || round.captured_boottime_ms < self.barrier_ms
        {
            return Err("UTC stream epoch, replay or acquisition barrier mismatch".into());
        }
        validate_capture(round, now)?;
        if let Some(old) = self.previous {
            let boot_delta = round
                .captured_boottime_ms
                .checked_sub(old.boot_ms)
                .ok_or("UTC stream boot regression")?;
            let mono_delta = round
                .captured_monotonic_ms
                .checked_sub(old.mono_ms)
                .ok_or("UTC stream monotonic regression")?;
            let rate = (u128::from(boot_delta) * 100).div_ceil(999_900) + 4;
            if boot_delta.abs_diff(mono_delta) > 4
                || ((i128::from(round.captured_realtime_ms) - i128::from(old.real_ms))
                    - i128::from(boot_delta))
                .unsigned_abs()
                    > rate
            {
                return Err("UTC stream suspend or realtime discontinuity".into());
            }
        }
        let mut samples = self.samples;
        let mut lost = self.lost;
        for (index, sample) in round.sources.iter().copied().enumerate() {
            match sample {
                SourceData::Unavailable { operator } if usize::from(operator) == index + 1 => {
                    lost[index] = true;
                }
                SourceData::Measured {
                    operator,
                    sequence,
                    observed_boottime_ms,
                    ..
                } if usize::from(operator) == index + 1 => {
                    if sequence == 0
                        || observed_boottime_ms < self.barrier_ms
                        || observed_boottime_ms > round.captured_boottime_ms
                    {
                        return Err("UTC sample sequence or acquisition timing mismatch".into());
                    }
                    if let Some(SourceData::Measured {
                        sequence: old_sequence,
                        observed_boottime_ms: old_ms,
                        ..
                    }) = samples[index]
                    {
                        if sequence < old_sequence
                            || (sequence == old_sequence
                                && (sample != samples[index].unwrap() || lost[index]))
                            || (sequence > old_sequence && observed_boottime_ms <= old_ms)
                        {
                            return Err(
                                "UTC source replay, re-aging or restoration of lost sample".into(),
                            );
                        }
                    }
                    samples[index] = Some(sample);
                    lost[index] = false;
                }
                _ => return Err("UTC stream source inventory mismatch".into()),
            }
        }
        self.samples = samples;
        self.lost = lost;
        self.sequence = round.sequence;
        self.previous = Some(Capture {
            boot_ms: round.captured_boottime_ms,
            mono_ms: round.captured_monotonic_ms,
            real_ms: round.captured_realtime_ms,
        });
        Ok(())
    }
}

// Control buffers are native-word aligned. The kernel installs SCM_RIGHTS FDs
// even when we will reject the datagram; close EVERY delivered FD before denial.
fn ancillary(message: &libc::msghdr) -> Result<libc::ucred> {
    let mut credentials = None;
    let mut invalid = false;
    let start = message.msg_control as usize;
    let end = start
        .checked_add(message.msg_controllen)
        .ok_or("UTC ancillary buffer overflow")?;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let address = header as usize;
        if address < start || address > end || end - address < size_of::<libc::cmsghdr>() {
            return Err("invalid UTC ancillary header range".into());
        }
        let value = unsafe { &*header };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        if value.cmsg_len < base || value.cmsg_len > end - address {
            return Err("invalid UTC ancillary size".into());
        }
        let length = value.cmsg_len - base;
        let data = unsafe { libc::CMSG_DATA(header) };
        if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
            invalid = true;
            for index in 0..length / size_of::<i32>() {
                let fd = unsafe {
                    std::ptr::read_unaligned(data.add(index * size_of::<i32>()).cast::<i32>())
                };
                if fd >= 0 {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        } else if value.cmsg_level == libc::SOL_SOCKET
            && value.cmsg_type == libc::SCM_CREDENTIALS
            && length == size_of::<libc::ucred>()
            && credentials.is_none()
        {
            credentials = Some(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
        } else {
            invalid = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if invalid || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err("UTC ancillary, descriptor or truncated datagram refused".into());
    }
    credentials.ok_or_else(|| "missing kernel UTC sender credentials".into())
}

pub(crate) fn configure(socket: &UnixDatagram) -> Result<()> {
    let flag: i32 = 1;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&flag as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    socket.set_nonblocking(true)?;
    Ok(())
}

pub(crate) fn receive(socket: &UnixDatagram) -> Result<Option<(ProducerRound, libc::ucred)>> {
    let mut bytes = [0; MAX_FRAME_SIZE];
    let mut control = [0usize; 32];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    let length = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error.into());
    }
    let credentials = ancillary(&message)?;
    if length <= 0 || length as usize > MAX_FRAME_SIZE {
        return Err("UTC datagram frame size mismatch".into());
    }
    let round =
        utc_protocol::decode_envelope(&bytes[..length as usize], credentials.pid, credentials.uid)?;
    validate_capture(&round, capture_clocks()?)?;
    Ok(Some((round, credentials)))
}

pub(crate) struct Receiver {
    socket: UnixDatagram,
    peer: PinnedProcess,
    cursor: Cursor,
    fenced: bool,
    admission: Option<crate::utc_runtime::Admission>,
    initial: Option<ProducerRound>,
    boundary: Option<crate::utc_runtime::Boundary>,
}
impl Receiver {
    pub(crate) fn acquisition_boundary(
        &mut self,
        suspend_generation: u64,
    ) -> Result<(crate::utc_step_watch::StepWatch, crate::utc_keeper::Clock)> {
        if self.fenced {
            return Err("UTC acquisition is fenced".into());
        }
        if let Some(mut boundary) = self.boundary.take() {
            self.recheck_peer()?;
            boundary.watch.check()?;
            boundary.clock.suspend_generation = suspend_generation;
            return Ok((boundary.watch, boundary.clock));
        }
        #[cfg(test)]
        if self.admission.is_none() {
            return Ok((
                crate::utc_step_watch::StepWatch::arm()?,
                Self::clock(suspend_generation)?,
            ));
        }
        self.fenced = true;
        Err("UTC acquisition boundary absent or already consumed".into())
    }
    fn recheck_peer(&self) -> Result<()> {
        self.peer.recheck()?;
        if let Some(admission) = &self.admission {
            admission.recheck(self.peer.pid)?;
        }
        self.peer.recheck()
    }

    pub(crate) fn runtime_digest(&mut self) -> Result<&str> {
        if self.fenced {
            return Err("UTC runtime admission is fenced".into());
        }
        if let Err(error) = self.recheck_peer() {
            self.fenced = true;
            return Err(error);
        }
        self.admission
            .as_ref()
            .map(|admission| admission.digest())
            .ok_or_else(|| "UTC fixture has no production runtime admission".into())
    }

    pub(crate) fn admitted(
        socket: UnixDatagram,
        credentials: libc::ucred,
        round: ProducerRound,
        barrier_ms: u64,
        admission: crate::utc_runtime::Admission,
        mut boundary: crate::utc_runtime::Boundary,
    ) -> Result<Self> {
        let peer = PinnedProcess::capture(credentials.pid, credentials.uid, credentials.gid)?;
        if round.epoch.boot_id != kernel_boot()? {
            return Err("UTC receiver boot mismatch".into());
        }
        let mut cursor = Cursor::new(round.epoch, barrier_ms)?;
        admission.recheck(peer.pid)?;
        boundary.watch.check()?;
        cursor.accept(&round, capture_clocks()?)?;
        let receiver = Self {
            socket,
            peer,
            cursor,
            fenced: false,
            admission: Some(admission),
            initial: Some(round),
            boundary: Some(boundary),
        };
        receiver.recheck_peer()?;
        validate_capture(receiver.initial.as_ref().unwrap(), capture_clocks()?)?;
        Ok(receiver)
    }
    pub(crate) fn epoch(&self) -> ProducerEpoch {
        self.cursor.epoch
    }

    pub(crate) fn clock(suspend_generation: u64) -> Result<crate::utc_keeper::Clock> {
        let now = capture_clocks()?;
        Ok(crate::utc_keeper::Clock {
            boottime_ms: now.boot_ms,
            monotonic_ms: now.mono_ms,
            realtime_ms: now.real_ms,
            suspend_generation,
        })
    }

    pub(crate) fn recheck_quiet(&mut self) -> Result<()> {
        let result = (|| {
            if self.fenced {
                return Err("UTC measurement stream is fenced".into());
            }
            self.recheck_peer()?;
            let mut pending = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pending, 1, 0) } != 0 || pending.revents != 0 {
                return Err("UTC stream changed during candidate evaluation".into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Raw numeric attachment exists only in isolated source fixtures.
    #[cfg(test)]
    pub(crate) fn attach(
        socket: UnixDatagram,
        pid: i32,
        uid: u32,
        gid: u32,
        epoch: ProducerEpoch,
    ) -> Result<Self> {
        let peer = PinnedProcess::capture(pid, uid, gid)?;
        if epoch.boot_id != kernel_boot()? {
            return Err("UTC receiver boot mismatch".into());
        }
        configure(&socket)?;
        let barrier = capture_clocks()?
            .boot_ms
            .checked_add(1)
            .ok_or("UTC acquisition barrier overflow")?;
        let cursor = Cursor::new(epoch, barrier)?;
        peer.recheck()?;
        Ok(Self {
            socket,
            peer,
            cursor,
            fenced: false,
            admission: None,
            initial: None,
            boundary: None,
        })
    }
    pub(crate) fn poll(&mut self) -> Result<Vec<ProducerRound>> {
        if self.fenced {
            return Err("UTC measurement stream requires reviewed reconstruction".into());
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Vec<ProducerRound>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
        self.recheck_peer()?;
        let mut rounds = Vec::with_capacity(DRAIN_LIMIT);
        if let Some(first) = self.initial.take() {
            rounds.push(first);
        }
        for _ in rounds.len()..DRAIN_LIMIT {
            let Some((round, credentials)) = receive(&self.socket)? else {
                self.recheck_peer()?;
                for round in &rounds {
                    validate_capture(round, capture_clocks()?)?;
                }
                if std::time::Instant::now() > deadline {
                    return Err("UTC stream drain deadline exceeded".into());
                }
                return Ok(rounds);
            };
            if !self.peer.matches(credentials) {
                return Err("UTC datagram sender is not the pinned producer".into());
            }
            self.recheck_peer()?;
            self.cursor.accept(&round, capture_clocks()?)?;
            if std::time::Instant::now() > deadline {
                return Err("UTC stream drain deadline exceeded".into());
            }
            rounds.push(round);
        }
        let mut pending = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pending, 1, 0) } != 0 || pending.revents != 0 {
            return Err("UTC stream queued batch exceeded drain bound".into());
        }
        self.recheck_peer()?;
        for round in &rounds {
            validate_capture(round, capture_clocks()?)?;
        }
        if std::time::Instant::now() > deadline {
            return Err("UTC stream drain deadline exceeded".into());
        }
        Ok(rounds)
    }
}
fn validate_capture(round: &ProducerRound, now: Capture) -> Result<()> {
    if now.boot_ms < now.mono_ms || now.real_ms < 0 {
        return Err("invalid UTC receiver capture".into());
    }
    let age = now
        .boot_ms
        .checked_sub(round.captured_boottime_ms)
        .filter(|age| *age <= 999)
        .ok_or("UTC stream capture is future-dated or stale")?;
    let mono_age = now
        .mono_ms
        .checked_sub(round.captured_monotonic_ms)
        .ok_or("UTC stream monotonic capture is future-dated")?;
    // Two bracketed captures plus quantisation. No claim to detect every
    // tiny step/suspend or prove the approved absolute rate envelope.
    let allowed = (u128::from(age) * 100).div_ceil(999_900) + 4;
    if age.abs_diff(mono_age) > 4
        || ((i128::from(now.real_ms) - i128::from(round.captured_realtime_ms)) - i128::from(age))
            .unsigned_abs()
            > allowed
    {
        return Err("UTC producer and receiver clocks disagree".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_fixture_never_reports_an_admitted_runtime_digest() {
        let (socket, _) = UnixDatagram::pair().unwrap();
        let mut expected = epoch();
        expected.boot_id = kernel_boot().unwrap();
        let mut receiver = Receiver::attach(
            socket,
            std::process::id() as i32,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
            expected,
        )
        .unwrap();
        assert!(receiver.runtime_digest().is_err());
        receiver.fenced = true;
        assert!(receiver.runtime_digest().is_err());
        assert!(receiver.acquisition_boundary(0).is_err());
    }
    fn epoch() -> ProducerEpoch {
        ProducerEpoch {
            boot_id: [1; 16],
            process_generation: 7,
            source_clock_generation: 1,
            policy_digest: ApprovedPolicy::fixed().unwrap().digest(),
        }
    }
    fn clock(now: u64) -> Capture {
        Capture {
            boot_ms: now,
            mono_ms: now,
            real_ms: 1_000_000 + now as i64,
        }
    }
    fn round(sequence: u64, now: u64) -> ProducerRound {
        ProducerRound {
            epoch: epoch(),
            sequence,
            captured_boottime_ms: now,
            captured_monotonic_ms: now,
            captured_realtime_ms: 1_000_000 + now as i64,
            sources: [1, 2, 3].map(|operator| SourceData::Measured {
                operator,
                sequence,
                observed_boottime_ms: now,
                utc: crate::utc_bounds::Interval::new(
                    1_000_000 + now as i64,
                    1_000_100 + now as i64,
                )
                .unwrap(),
            }),
        }
    }
    #[test]
    fn accepts_new_rounds_and_unchanged_samples_without_reaging() {
        let mut cursor = Cursor::new(epoch(), 1000).unwrap();
        let first = round(1, 1000);
        cursor.accept(&first, clock(1001)).unwrap();
        let mut next = round(2, 1002);
        next.sources = first.sources;
        cursor.accept(&next, clock(1003)).unwrap();
        assert_eq!(cursor.sequence, 2);
    }
    #[test]
    fn every_epoch_component_and_old_acquisition_barrier_refuse() {
        for component in 0..5 {
            let mut cursor = Cursor::new(epoch(), 1000).unwrap();
            let mut r = round(1, 1000);
            match component {
                0 => r.epoch.boot_id[0] ^= 1,
                1 => r.epoch.process_generation += 1,
                2 => r.epoch.source_clock_generation += 1,
                3 => r.epoch.policy_digest[0] ^= 1,
                4 => r.captured_boottime_ms = 999,
                _ => unreachable!(),
            }
            assert!(cursor.accept(&r, clock(1001)).is_err());
            assert_eq!(cursor.sequence, 0);
        }
    }
    #[test]
    fn stale_future_and_capture_disagreement_refuse() {
        for variant in 0..5 {
            let mut cursor = Cursor::new(epoch(), 1000).unwrap();
            let mut now = clock(1001);
            match variant {
                0 => now = clock(2000),
                1 => now = clock(999),
                2 => now.mono_ms += 5,
                3 => now.real_ms += 10,
                4 => now.real_ms -= 10,
                _ => unreachable!(),
            }
            assert!(cursor.accept(&round(1, 1000), now).is_err());
        }
        Cursor::new(epoch(), 1000)
            .unwrap()
            .accept(&round(1, 1000), clock(1999))
            .unwrap();
    }
    #[test]
    fn replay_reaging_timestamp_regression_and_inventory_refuse() {
        for variant in 0..5 {
            let mut cursor = Cursor::new(epoch(), 1000).unwrap();
            let first = round(2, 1000);
            cursor.accept(&first, clock(1001)).unwrap();
            let mut r = round(3, 1002);
            match variant {
                0 => r.sequence = 2,
                1 => {
                    if let SourceData::Measured { sequence, .. } = &mut r.sources[0] {
                        *sequence = 2;
                    }
                }
                2 => {
                    if let SourceData::Measured {
                        observed_boottime_ms,
                        ..
                    } = &mut r.sources[0]
                    {
                        *observed_boottime_ms = 1000;
                    }
                }
                3 => r.sources.swap(0, 1),
                4 => {
                    if let SourceData::Measured {
                        observed_boottime_ms,
                        ..
                    } = &mut r.sources[0]
                    {
                        *observed_boottime_ms = 999;
                    }
                }
                _ => unreachable!(),
            }
            assert!(cursor.accept(&r, clock(1003)).is_err());
            assert_eq!(cursor.sequence, 2);
        }
    }
    #[test]
    fn unavailable_sample_cannot_be_restored_with_old_identity() {
        let mut cursor = Cursor::new(epoch(), 1000).unwrap();
        let first = round(1, 1000);
        cursor.accept(&first, clock(1001)).unwrap();
        let mut missing = round(2, 1002);
        missing.sources[0] = SourceData::Unavailable { operator: 1 };
        cursor.accept(&missing, clock(1003)).unwrap();
        let mut old = round(3, 1004);
        old.sources[0] = first.sources[0];
        assert!(cursor.accept(&old, clock(1005)).is_err());
        cursor.accept(&round(3, 1004), clock(1005)).unwrap();
    }
    #[test]
    fn stream_clock_regression_step_and_suspend_refuse() {
        for variant in 0..3 {
            let mut cursor = Cursor::new(epoch(), 1000).unwrap();
            cursor.accept(&round(1, 1005), clock(1006)).unwrap();
            let mut r = round(2, 1010);
            let mut now = clock(1011);
            match variant {
                0 => {
                    r.captured_monotonic_ms = 1000;
                    now.mono_ms = 1001;
                }
                1 => {
                    r.captured_realtime_ms += 10;
                    now.real_ms += 10;
                }
                2 => {
                    r.captured_boottime_ms = 1004;
                    r.captured_monotonic_ms = 1004;
                    r.captured_realtime_ms = 1_001_004;
                    now = clock(1005);
                }
                _ => unreachable!(),
            }
            assert!(cursor.accept(&r, now).is_err());
        }
    }
    #[test]
    fn process_observation_matches_kernel_and_bad_credentials_refuse() {
        let pid = std::process::id() as i32;
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let peer = PinnedProcess::capture(pid, uid, gid).unwrap();
        peer.recheck().unwrap();
        assert!(peer.matches(libc::ucred { pid, uid, gid }));
        assert!(!peer.matches(libc::ucred {
            pid: pid + 1,
            uid,
            gid
        }));
        assert!(PinnedProcess::capture(pid, uid.wrapping_add(1), gid).is_err());
        assert!(PinnedProcess::capture(0, uid, gid).is_err());
    }
    #[test]
    fn changed_process_runtime_fingerprints_and_uninitialized_epochs_refuse() {
        let pid = std::process::id() as i32;
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        for variant in 0..5 {
            let mut peer = PinnedProcess::capture(pid, uid, gid).unwrap();
            match variant {
                0 => peer.observation.start_ticks += 1,
                1 => peer.observation.executable_inode ^= 1,
                2 => peer.observation.profile.push('x'),
                3 => peer.observation.cgroup.push('x'),
                4 => peer.observation.controls[2].push('x'),
                _ => unreachable!(),
            }
            assert!(peer.recheck().is_err());
        }
        for variant in 0..4 {
            let mut expected = epoch();
            match variant {
                0 => expected.boot_id.fill(0),
                1 => expected.process_generation = 0,
                2 => expected.source_clock_generation = 0,
                3 => expected.policy_digest.fill(0),
                _ => unreachable!(),
            }
            assert!(Cursor::new(expected, 1000).is_err());
        }
    }
    #[test]
    fn clock_consistency_is_rechecked_at_return_not_just_parse() {
        let r = round(1, 1000);
        assert!(validate_capture(&r, clock(1999)).is_ok());
        assert!(validate_capture(&r, clock(2000)).is_err());
        let mut now = clock(1001);
        now.real_ms += 10;
        assert!(validate_capture(&r, now).is_err());
    }
    fn fixture_round(sequence: u64) -> ProducerRound {
        // Synthetic fixture intervals, NOT NTS-derived UTC or authorization.
        let now = capture_clocks().unwrap();
        let mut bytes = [0; 232];
        bytes[..8].copy_from_slice(b"LUMAUTC1");
        bytes[8..40].copy_from_slice(&ApprovedPolicy::fixed().unwrap().digest());
        bytes[40..56].copy_from_slice(&kernel_boot().unwrap());
        for (offset, value) in [
            (56, 7),
            (64, 1),
            (72, sequence),
            (80, now.boot_ms),
            (88, now.mono_ms),
            (96, now.real_ms as u64),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for index in 0..3 {
            let start = 112 + 40 * index;
            bytes[start] = index as u8 + 1;
            bytes[start + 1] = 1;
            for (offset, value) in [
                (8, sequence),
                (16, now.boot_ms),
                (24, now.real_ms as u64),
                (32, now.real_ms as u64 + 100),
            ] {
                bytes[start + offset..start + offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        utc_protocol::decode(&bytes).unwrap()
    }
    fn packet(sequence: u64) -> Vec<u8> {
        utc_protocol::fixture_encode(
            &fixture_round(sequence),
            unsafe { libc::getpid() },
            unsafe { libc::getuid() },
        )
    }
    fn send_rights(socket: &UnixDatagram, bytes: &[u8], count: usize) {
        let file = File::open("/dev/null").unwrap();
        let mut control = [0usize; 36];
        let mut vector = libc::iovec {
            iov_base: bytes.as_ptr() as *mut _,
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE((count * size_of::<i32>()) as u32) } as usize;
        assert!(message.msg_controllen <= size_of_val(&control));
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((count * size_of::<i32>()) as u32) as usize;
            let data = libc::CMSG_DATA(header);
            for index in 0..count {
                std::ptr::write_unaligned(
                    data.add(index * size_of::<i32>()).cast(),
                    file.as_raw_fd(),
                );
            }
            assert_eq!(
                libc::sendmsg(socket.as_raw_fd(), &message, 0),
                bytes.len() as isize
            );
        }
    }
    #[test]
    #[ignore = "owned child of the isolated UTC datagram fixture only"]
    fn kernel_sender_child() {
        use std::io::{BufRead, Write};
        let destination = std::env::var("LUMA_UTC_RECEIVER_FIXTURE_SOCKET").unwrap();
        let socket = UnixDatagram::unbound().unwrap();
        socket.connect(destination).unwrap();
        println!("UTC_SENDER_READY");
        io::stdout().flush().unwrap();
        let mut sequence = 0;
        let mut saved = Vec::new();
        for command in io::stdin().lock().lines() {
            let command = command.unwrap();
            if command == "exit" {
                return;
            }
            if command == "exec" {
                use std::os::unix::process::CommandExt;
                println!("UTC_SENT");
                io::stdout().flush().unwrap();
                let failure = std::process::Command::new("/bin/sleep").arg("60").exec();
                panic!("owned executable replacement failed: {failure}");
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
            if command == "replay" {
                socket.send(&saved).unwrap();
            } else {
                let count = match command.as_str() {
                    "two" | "invalidation" => 2,
                    "loss-restored" => 3,
                    "flood" => 9,
                    _ => 1,
                };
                for index in 0..count {
                    if index > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    sequence += 1;
                    let mut round = fixture_round(sequence);
                    if command == "invalidation" && index == 1 {
                        round.epoch.source_clock_generation = 2;
                    }
                    if (command == "loss-restored" && index == 1) || command == "lost" {
                        round.sources[1] = SourceData::Unavailable { operator: 2 };
                        round.sources[2] = SourceData::Unavailable { operator: 3 };
                    }
                    if command == "empty" {
                        round.sources =
                            [1, 2, 3].map(|operator| SourceData::Unavailable { operator });
                    }
                    if command == "reage" {
                        if let SourceData::Measured {
                            sequence: ref mut sample,
                            ..
                        } = round.sources[0]
                        {
                            *sample = sequence - 1;
                        }
                    }
                    let pid = unsafe { libc::getpid() } + i32::from(command == "wrong-pid-claim");
                    let uid = unsafe { libc::getuid() } ^ u32::from(command == "wrong-caller");
                    let bytes = utc_protocol::fixture_encode(&round, pid, uid);
                    match command.as_str() {
                        "rights" => send_rights(&socket, &bytes, 1),
                        "truncated-rights" => send_rights(&socket, &bytes, 63),
                        "oversize" => {
                            let mut extra = bytes.to_vec();
                            extra.resize(MAX_FRAME_SIZE + 1, 0);
                            socket.send(&extra).unwrap();
                        }
                        "truncated" => {
                            socket.send(&bytes[..bytes.len() - 1]).unwrap();
                        }
                        _ => {
                            socket.send(&bytes).unwrap();
                        }
                    }
                    saved = bytes;
                }
            }
            println!("UTC_SENT");
            io::stdout().flush().unwrap();
        }
    }
    struct ChildSender {
        child: std::process::Child,
        output: io::BufReader<std::process::ChildStdout>,
    }
    impl ChildSender {
        fn start(path: &std::path::Path) -> Self {
            use std::process::{Command, Stdio};
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "utc_receiver::tests::kernel_sender_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("LUMA_UTC_RECEIVER_FIXTURE_SOCKET", path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let output = io::BufReader::new(child.stdout.take().unwrap());
            let mut sender = Self { child, output };
            sender.wait_marker("UTC_SENDER_READY");
            sender
        }
        fn wait_marker(&mut self, marker: &str) {
            use std::io::BufRead;
            for _ in 0..8 {
                let mut line = String::new();
                assert!(self.output.read_line(&mut line).unwrap() > 0);
                if line.contains(marker) {
                    return;
                }
            }
            panic!("missing owned sender marker");
        }
        fn command(&mut self, command: &str) {
            use std::io::Write;
            writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
            self.child.stdin.as_mut().unwrap().flush().unwrap();
            if command != "exit" {
                self.wait_marker("UTC_SENT");
            }
        }
    }
    impl Drop for ChildSender {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    struct SocketDirectory(std::path::PathBuf);
    impl SocketDirectory {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("luma-utc-receiver-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for SocketDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("measurement.sock"));
            let _ = fs::remove_dir(&self.0);
        }
    }
    #[test]
    #[ignore = "isolated Linux pidfd/datagram fixture with owned helper processes"]
    fn kernel_datagram_boundary() {
        for variant in [
            "single",
            "two",
            "loss-restored",
            "invalidation",
            "wrong-pid",
            "wrong-pid-claim",
            "wrong-caller",
            "dead",
            "exec",
            "replay",
            "reage",
            "rights",
            "truncated-rights",
            "oversize",
            "truncated",
            "flood",
        ] {
            let directory = SocketDirectory::new();
            let path = directory.0.join("measurement.sock");
            let socket = UnixDatagram::bind(&path).unwrap();
            let mut sender = ChildSender::start(&path);
            let mut expected = epoch();
            expected.boot_id = kernel_boot().unwrap();
            let mut receiver = Receiver::attach(
                socket,
                sender.child.id() as i32,
                unsafe { libc::getuid() },
                unsafe { libc::getgid() },
                expected,
            )
            .unwrap();
            assert!(receiver.poll().unwrap().is_empty()); // No cached result or fabricated time.
            if variant == "wrong-pid" {
                std::thread::sleep(std::time::Duration::from_millis(2));
                UnixDatagram::unbound()
                    .unwrap()
                    .send_to(&packet(1), &path)
                    .unwrap();
            } else {
                sender.command(
                    if variant == "dead"
                        || variant == "exec"
                        || variant == "replay"
                        || variant == "reage"
                    {
                        "single"
                    } else {
                        variant
                    },
                );
            }
            if variant == "dead" {
                sender.command("exit");
                assert!(sender.child.wait().unwrap().success());
            }
            if variant == "exec" {
                sender.command("exec");
                // Helper exec includes loader work under the container's CPU
                // quota. This is a bounded fixture synchronization wait, not
                // an increase to receiver/heartbeat production deadlines.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while fs::read_link(format!("/proc/{}/exe", sender.child.id())).unwrap()
                    == std::env::current_exe().unwrap()
                {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            let descriptors = fs::read_dir("/proc/self/fd").unwrap().count();
            let result = receiver.poll();
            if ["single", "two", "loss-restored", "replay", "reage"].contains(&variant) {
                let measured = result.unwrap();
                assert_eq!(
                    measured.len(),
                    match variant {
                        "two" => 2,
                        "loss-restored" => 3,
                        _ => 1,
                    }
                );
                assert_eq!(measured[0].sequence, 1);
                assert_eq!(measured.last().unwrap().sequence, measured.len() as u64);
                if variant == "loss-restored" {
                    assert!(matches!(
                        measured[1].sources[1],
                        SourceData::Unavailable { operator: 2 }
                    ));
                    assert!(matches!(
                        measured[2].sources[1],
                        SourceData::Measured { .. }
                    ));
                }
                assert!(receiver.poll().unwrap().is_empty());
                if variant == "replay" || variant == "reage" {
                    sender.command(variant);
                    assert!(receiver.poll().is_err());
                    assert!(receiver.fenced);
                }
            } else {
                assert!(result.is_err(), "unexpected admission for {variant}");
                if variant == "exec" {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        "UTC producer process or runtime changed"
                    );
                } else if variant == "wrong-pid-claim" || variant == "wrong-caller" {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        "invalid UTC envelope context or caller"
                    );
                }
                assert!(receiver.fenced);
                assert!(receiver.poll().is_err()); // Sticky until explicitly reconstructed.
            }
            if variant == "rights" || variant == "truncated-rights" {
                assert_eq!(
                    fs::read_dir("/proc/self/fd").unwrap().count(),
                    descriptors,
                    "received FD leak"
                );
            }
            println!("UTC_KERNEL_CASE_PASSED {variant}");
        }
    }

    #[test]
    #[ignore = "isolated Linux receiver-to-keeper fixture with owned processes"]
    fn kernel_keeper_composition() {
        use crate::{utc_keeper::State, utc_stream::Stream};
        for variant in [
            "two",
            "quiet",
            "loss-restored",
            "lost",
            "startup-empty",
            "rights",
            "dead",
            "notify",
            "history",
            "expired-watch",
            "expired-current",
        ] {
            let directory = SocketDirectory::new();
            let path = directory.0.join("measurement.sock");
            let socket = UnixDatagram::bind(&path).unwrap();
            let mut sender = ChildSender::start(&path);
            let mut expected = epoch();
            expected.boot_id = kernel_boot().unwrap();
            let receiver = Receiver::attach(
                socket,
                sender.child.id() as i32,
                unsafe { libc::getuid() },
                unsafe { libc::getgid() },
                expected,
            )
            .unwrap();
            let floor = if variant == "history" {
                4_102_444_800_000
            } else {
                0
            };
            let mut stream = Stream::attach(receiver, floor, 3).unwrap();
            assert!(stream.poll().unwrap().is_none());
            assert_eq!(stream.state(), State::Acquiring);
            sender.command(match variant {
                "two" | "loss-restored" | "lost" | "rights" => variant,
                "startup-empty" => "empty",
                _ => "single",
            });
            if variant == "dead" {
                sender.command("exit");
                assert!(sender.child.wait().unwrap().success());
            }
            if variant == "notify" {
                stream.invalidate();
            }
            if variant == "expired-watch" {
                stream.expire_watch_fixture();
            }
            if variant == "lost" || variant == "startup-empty" {
                assert!(stream.poll().unwrap().is_none());
                assert_eq!(stream.state(), State::Acquiring);
                sender.command("single");
                assert!(stream.poll().unwrap().is_some());
                assert_eq!(stream.state(), State::Bounded);
                sender.command("lost");
                assert!(stream.poll().is_err());
                assert_eq!(stream.state(), State::Fenced);
            } else if variant == "two" || variant == "quiet" || variant == "expired-current" {
                let first = stream.poll().unwrap().unwrap();
                assert_eq!(stream.state(), State::Bounded);
                if variant == "quiet" {
                    std::thread::sleep(std::time::Duration::from_millis(3));
                    let later = stream.poll().unwrap().unwrap();
                    assert!(later.endpoints().1 > first.endpoints().1);
                }
                if variant == "expired-current" {
                    stream.expire_watch_fixture();
                } else {
                    sender.command("lost");
                }
                assert!(stream.poll().is_err());
                assert_eq!(stream.state(), State::Fenced);
            } else {
                assert!(stream.poll().is_err(), "unexpected candidate for {variant}");
                assert_eq!(
                    stream.state(),
                    if variant == "history" {
                        State::ReconciliationRequired
                    } else {
                        State::Fenced
                    }
                );
            }
            if variant != "dead" {
                sender.command("single");
            }
            assert!(stream.poll().is_err());
            println!("UTC_COMPOSITION_CASE_PASSED {variant}");
        }
    }

    #[test]
    #[ignore = "isolated Linux final-queue recheck fixture"]
    fn kernel_final_queue_recheck() {
        let directory = SocketDirectory::new();
        let path = directory.0.join("measurement.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        let mut sender = ChildSender::start(&path);
        let mut expected = epoch();
        expected.boot_id = kernel_boot().unwrap();
        let mut receiver = Receiver::attach(
            socket,
            sender.child.id() as i32,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
            expected,
        )
        .unwrap();
        receiver.recheck_quiet().unwrap();
        sender.command("single");
        assert!(receiver.recheck_quiet().is_err());
        assert!(receiver.poll().is_err());
    }

    #[test]
    #[ignore = "isolated Linux shared-history/UTC fixture with fake checkpoint only"]
    fn kernel_shared_history_composition() {
        for variant in [
            "quiet",
            "raw-history-delivery",
            "delivery-binding-change",
            "history-ahead",
            "catalog-change",
            "floor-change",
            "pending",
            "enrollment-change",
            "missing-payload",
            "tpm-epoch",
            "anchor-unavailable",
            "queued-during-history",
            "delayed-history",
            "payload-during-history",
        ] {
            let directory = SocketDirectory::new();
            let path = directory.0.join("measurement.sock");
            let socket = UnixDatagram::bind(&path).unwrap();
            let mut sender = ChildSender::start(&path);
            let mut expected = epoch();
            expected.boot_id = kernel_boot().unwrap();
            let receiver = Receiver::attach(
                socket,
                sender.child.id() as i32,
                unsafe { libc::getuid() },
                unsafe { libc::getgid() },
                expected,
            )
            .unwrap();
            crate::admin_governance::fixture_bound_utc_history(receiver, variant, |command| {
                sender.command(command)
            });
            println!("UTC_SHARED_HISTORY_CASE_PASSED {variant}");
        }
    }
}
