//! Protected, local UTC keeper delivery. Wire intervals are evidence; only an
//! immutable, enforcing peer and a current semantic history binding admit them.
use super::{Observation, Stream};
use crate::{
    admin_governance::HistoryBinding,
    bundle,
    utc_bounds::Interval,
    utc_history::Statement,
    utc_receiver::Receiver,
    utc_runtime::{Deployment, Endpoint},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

const ROOT: &str = "/run/luma-utc-control";
const QUERY: &str = "/run/luma-utc-control/query.sock";
const CONTROL: &str = "/run/luma-utc-control/control.sock";
const READY: &str = "/run/luma-utc/seed-ready";
const MAX_FRAME: usize = 4096;
const BUDGET: Duration = Duration::from_millis(250);
const MAX_SEED_WIDTH: i64 = 300_000;

#[path = "utc_provider/recovery.rs"]
mod recovery;
pub(crate) use recovery::{
    recovery_deliver_seed, recovery_reacquire, recovery_reacquire_proposal, recovery_seed_proposal,
    RecoveryClient,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    schema_version: u32,
    nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u32,
    nonce: String,
    instance: String,
    sequence: u64,
    captured_boottime_ms: u64,
    captured_monotonic_ms: u64,
    context: Statement,
    earliest_ms: i64,
    latest_ms: i64,
}

/// An approximate certificate-bootstrap seed, never timed-role authority.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seed {
    pub(crate) schema_version: u32,
    pub(crate) earliest_ms: i64,
    pub(crate) latest_ms: i64,
    pub(crate) independent_source: String,
    pub(crate) review_reference: String,
}
impl Seed {
    fn validate(&self, floor: i64) -> Result<()> {
        if self.schema_version != 1
            || self.earliest_ms < floor
            || self.earliest_ms < 0
            || self.latest_ms > 4_102_444_800_000
            || self
                .latest_ms
                .checked_sub(self.earliest_ms)
                .filter(|width| (0..=MAX_SEED_WIDTH).contains(width))
                .is_none()
            || [
                self.independent_source.as_str(),
                self.review_reference.as_str(),
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.bytes().any(|b| !(32..=126).contains(&b)))
        {
            return Err("UTC seed requires bounded independent-clock provenance and review".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    schema_version: u32,
    nonce: String,
    instance: String,
    history_binding: String,
    history_floor_ms: i64,
    seed: Seed,
    reviewed_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlReply {
    schema_version: u32,
    nonce: String,
    instance: String,
    result: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", content = "request", deny_unknown_fields)]
enum ControlRequest {
    Inspect(Query),
    Seed(Control),
}

fn random() -> Result<String> {
    let mut bytes = [0u8; 32];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) } != bytes.len() as isize
        || bytes == [0; 32]
    {
        return Err("UTC operation nonce unavailable".into());
    }
    Ok(bundle::hex(&bytes))
}
fn nonce(value: &str) -> Result<()> {
    if crate::tpm::decode::<32>(value)? == [0; 32] {
        return Err("UTC operation nonce is zero".into());
    }
    Ok(())
}
fn frame<T: Serialize>(socket: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("UTC local frame exceeds its bound".into());
    }
    socket.write_all(&(bytes.len() as u32).to_be_bytes())?;
    socket.write_all(&bytes)?;
    socket.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}
fn read_frame<T: for<'a> Deserialize<'a>>(socket: &mut UnixStream) -> Result<T> {
    let mut prefix = [0; 4];
    socket.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("UTC local frame length is invalid".into());
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes)?;
    let mut trailing = [0u8; 1];
    if socket.read(&mut trailing)? != 0 {
        return Err("UTC local request contains trailing or concatenated frames".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn socket_budget(socket: &UnixStream) -> Result<()> {
    socket.set_read_timeout(Some(BUDGET))?;
    socket.set_write_timeout(Some(BUDGET))?;
    Ok(())
}
fn credentials(socket: &UnixStream, label: &str) -> Result<libc::ucred> {
    credentials_any(socket, &[label])
}
fn credentials_any(socket: &UnixStream, labels: &[&str]) -> Result<libc::ucred> {
    let mut value: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut value as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
        || !protected_peer_ids(value.uid, value.gid, value.pid)
    {
        return Err("UTC local endpoint requires its original protected root peer".into());
    }
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
        return Err("UTC peer enforcing label unavailable".into());
    }
    let bytes = &bytes[..length as usize];
    if !approved_peer_label(bytes, labels) {
        return Err("UTC peer does not have its approved enforcing profile".into());
    }
    Ok(value)
}
fn protected_peer_ids(uid: u32, gid: u32, pid: i32) -> bool {
    uid == 0 && gid == 0 && pid > 0
}
fn approved_peer_label(bytes: &[u8], labels: &[&str]) -> bool {
    labels
        .iter()
        .any(|label| bytes.strip_suffix(&[0]).unwrap_or(bytes) == label.as_bytes())
}

#[derive(PartialEq, Eq)]
struct Identity(u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self(
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
}
struct Release {
    files: Vec<crate::utc_runtime::Pin>,
    mode: crate::utc_runtime::Mode,
}
impl Release {
    fn installed() -> Result<Self> {
        Self::from_mode(crate::utc_runtime::Mode::installed()?)
    }
    fn recovery() -> Result<Self> {
        Self::from_mode(crate::utc_runtime::Mode::recovery()?)
    }
    fn from_mode(mode: crate::utc_runtime::Mode) -> Result<Self> {
        mode.recheck()?;
        let (profile, profile_bytes, service, service_bytes, caller_profile, caller_bytes) =
            match &mode {
                crate::utc_runtime::Mode::Installed => (
                    "/etc/apparmor.d/luma-utc-keeper",
                    include_bytes!("../../../native/image/overlay/etc/apparmor.d/luma-utc-keeper")
                        .as_slice(),
                    "/usr/lib/systemd/system/luma-utc-keeper.service",
                    include_bytes!("../../../native/image/utc/luma-utc-keeper.service").as_slice(),
                    "/etc/apparmor.d/luma-granted-client",
                    Some(
                        include_bytes!(
                            "../../../native/image/overlay/etc/apparmor.d/luma-granted-client"
                        )
                        .as_slice(),
                    ),
                ),
                crate::utc_runtime::Mode::Recovery(_) => (
                    "/etc/apparmor.d/luma-utc-recovery-keeper",
                    include_bytes!(
                        "../../../native/image/overlay/etc/apparmor.d/luma-utc-recovery-keeper"
                    )
                    .as_slice(),
                    "/usr/lib/systemd/system/luma-utc-recovery-keeper.service",
                    include_bytes!("../../../native/image/utc/luma-utc-recovery-keeper.service")
                        .as_slice(),
                    "/etc/apparmor.d/luma-recovery",
                    None,
                ),
            };
        let release = Self {
            files: vec![
                crate::utc_runtime::Pin::immutable(
                    "/usr/libexec/luma-os/luma-platform",
                    64 * 1024 * 1024,
                    None,
                )?,
                crate::utc_runtime::Pin::immutable(profile, 32 * 1024, Some(profile_bytes))?,
                crate::utc_runtime::Pin::immutable(service, 32 * 1024, Some(service_bytes))?,
                crate::utc_runtime::Pin::immutable(caller_profile, 32 * 1024, caller_bytes)?,
            ],
            mode,
        };
        release.recheck()?;
        Ok(release)
    }
    fn recheck(&self) -> Result<()> {
        self.mode.recheck()?;
        for file in &self.files {
            file.immutable_recheck()?;
        }
        self.mode.recheck()
    }
}
fn endpoint(path: &str) -> Result<Identity> {
    let parent = fs::symlink_metadata(ROOT)?;
    let m = fs::symlink_metadata(path)?;
    if !parent.is_dir()
        || parent.uid() != 0
        || parent.gid() != 0
        || parent.mode() & 0o7777 != 0o700
        || !m.file_type().is_socket()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
    {
        return Err("UTC local socket protections differ".into());
    }
    Ok(Identity::of(&m))
}
fn binding_digest(binding: &HistoryBinding) -> String {
    let mut hash = Sha256::new();
    hash.update(b"luma-utc-live-history-binding-v1\0");
    hash.update(format!("{binding:?}").as_bytes());
    bundle::hex(&hash.finalize())
}

/// A single kernel dispatch coordinate shared by the UTC projection and the
/// original authenticated accounts. Only this client can capture it in
/// production. It carries no clock setter, PAM proof, restoration or wire form.
pub(crate) struct ProjectionClock {
    boottime_ns: u64,
    monotonic_ms: u64,
    process: u32,
    euid: u32,
    sampled_instant: Instant,
}
impl ProjectionClock {
    pub(crate) fn boottime_ns(&self) -> u64 {
        self.boottime_ns
    }
    pub(crate) fn process(&self) -> u32 {
        self.process
    }
    pub(crate) fn euid(&self) -> u32 {
        self.euid
    }
    fn kernel_ns(clock: libc::clockid_t) -> Result<u64> {
        let mut value: libc::timespec = unsafe { zeroed() };
        if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        u64::try_from(value.tv_sec)?
            .checked_mul(1_000_000_000)
            .and_then(|ns| {
                u64::try_from(value.tv_nsec)
                    .ok()
                    .filter(|ns| *ns < 1_000_000_000)
                    .and_then(|fraction| ns.checked_add(fraction))
            })
            .ok_or_else(|| "UTC dispatch kernel clock is invalid or overflowed".into())
    }
    fn capture() -> Result<Self> {
        let before = Self::kernel_ns(libc::CLOCK_BOOTTIME)?;
        let monotonic_ns = Self::kernel_ns(libc::CLOCK_MONOTONIC)?;
        let process = std::process::id();
        let euid = unsafe { libc::geteuid() };
        let sampled_instant = Instant::now();
        let boottime_ns = Self::kernel_ns(libc::CLOCK_BOOTTIME)?;
        if boottime_ns < before || boottime_ns - before > 2_000_000 || boottime_ns < monotonic_ns {
            return Err("UTC dispatch kernel clock bracket was delayed or inconsistent".into());
        }
        Ok(Self {
            boottime_ns,
            monotonic_ms: monotonic_ns / 1_000_000,
            process,
            euid,
            sampled_instant,
        })
    }
    fn coordinate(&self) -> crate::utc_keeper::Clock {
        crate::utc_keeper::Clock {
            boottime_ms: self.boottime_ns / 1_000_000,
            monotonic_ms: self.monotonic_ms,
            realtime_ms: 0,
            suspend_generation: 0,
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture(boottime_ns: u64, process: u32, euid: u32) -> Self {
        Self {
            boottime_ns,
            monotonic_ms: boottime_ns / 1_000_000,
            process,
            euid,
            sampled_instant: Instant::now(),
        }
    }
}

// This is owned only by the admitted live client, never restored from a wire
// observation. Every local projection keeps the ORIGINAL query capture and
// deadline; checking a sample again cannot restart its freshness budget.
struct DeliverySample {
    history: String,
    instance: String,
    sequence: u64,
    context: Statement,
    raw: Interval,
    captured_boottime_ms: u64,
    captured_monotonic_ms: u64,
    last_clock: crate::utc_keeper::Clock,
    last_projection_ns: Option<u64>,
    delivered_context: Statement,
    delivered_utc: Interval,
    deadline: Instant,
}
impl DeliverySample {
    fn require_deadline(&self, now: Instant) -> Result<()> {
        if now >= self.deadline {
            return Err("UTC local projection exhausted its original query deadline".into());
        }
        Ok(())
    }
    fn require_binding(
        &self,
        history: &str,
        generation: Option<&(String, Statement)>,
        sequence: u64,
        previous: &Observation,
    ) -> Result<()> {
        let mut expected = self.context.clone();
        expected.floor_ms = 0;
        if self.history != history
            || self.sequence == 0
            || self.sequence != sequence
            || generation.map(|(instance, context)| (instance.as_str(), context))
                != Some((self.instance.as_str(), &expected))
            || previous.context() != &self.delivered_context
            || previous.interval() != self.delivered_utc
        {
            return Err("UTC local projection does not match its last admitted delivery".into());
        }
        Ok(())
    }
    fn project(
        &self,
        initial: crate::utc_keeper::Clock,
        now: crate::utc_keeper::Clock,
        floor_ms: i64,
    ) -> Result<Observation> {
        self.context.validate()?;
        if self.context.floor_ms != self.raw.endpoints().0
            || now.boottime_ms < self.last_clock.boottime_ms
            || now.monotonic_ms < self.last_clock.monotonic_ms
            || now.suspend_generation != initial.suspend_generation
            || self.last_clock.suspend_generation != initial.suspend_generation
        {
            return Err("UTC local projection crossed its admitted clock state".into());
        }
        for (boot, mono) in [
            (initial.boottime_ms, initial.monotonic_ms),
            (self.captured_boottime_ms, self.captured_monotonic_ms),
            (self.last_clock.boottime_ms, self.last_clock.monotonic_ms),
        ] {
            let boot_elapsed = now
                .boottime_ms
                .checked_sub(boot)
                .ok_or("UTC local projection boot clock regressed")?;
            let mono_elapsed = now
                .monotonic_ms
                .checked_sub(mono)
                .ok_or("UTC local projection monotonic clock regressed")?;
            if boot_elapsed.abs_diff(mono_elapsed) > 2 {
                return Err("UTC local projection crossed suspend or a clock discontinuity".into());
            }
        }
        let epoch = crate::utc_bounds::Epoch {
            boot_id: crate::tpm::decode::<16>(&self.context.boot_id)?,
            provider_generation: self.context.process_generation,
            clock_generation: self.context.source_clock_generation,
            policy_digest: crate::tpm::decode::<32>(&self.context.policy_sha256)?,
        };
        let utc = crate::utc_bounds::project(
            crate::utc_bounds::Measurement {
                operator: 1,
                utc: self.raw,
                observed_boottime_ms: self.captured_boottime_ms,
                epoch,
            },
            now.boottime_ms,
            epoch,
            crate::utc_bounds::Policy {
                max_age_ms: 250,
                max_width_ms: 500,
                drift_ppm: 100,
            },
        )?;
        if utc.endpoints().0 < floor_ms || utc.endpoints().1 - utc.endpoints().0 > 500 {
            return Err("UTC local projection exceeded its protected floor or width".into());
        }
        let mut context = self.context.clone();
        context.floor_ms = utc.endpoints().0;
        Ok(Observation { context, utc })
    }
    fn finish_projection(
        &mut self,
        initial: crate::utc_keeper::Clock,
        floor_ms: i64,
        coordinate: &ProjectionClock,
        finish: impl FnOnce(&ProjectionClock) -> Result<()>,
    ) -> Result<Observation> {
        // Instant was captured BEFORE the final BOOTTIME read in a bracket no
        // longer than 2ms. Apply that full outward margin to the original query
        // deadline rather than reading another clock after the shared point.
        self.require_deadline(
            coordinate
                .sampled_instant
                .checked_add(Duration::from_millis(2))
                .ok_or("UTC dispatch query deadline coordinate overflowed")?,
        )?;
        if self
            .last_projection_ns
            .is_some_and(|previous| coordinate.boottime_ns() < previous)
        {
            return Err("UTC dispatch nanosecond coordinate regressed".into());
        }
        let now = coordinate.coordinate();
        let mut result = self.project(initial, now, floor_ms)?;
        // Integer-millisecond projection already rounds drift outwards. Include
        // the shared coordinate's fractional millisecond too, using the ORIGINAL
        // capture: neither a validity check nor total freshness may round down.
        let age_ms = now
            .boottime_ms
            .checked_sub(self.captured_boottime_ms)
            .ok_or("UTC dispatch predates its original capture")?;
        let age_ns =
            u128::from(age_ms) * 1_000_000 + u128::from(coordinate.boottime_ns() % 1_000_000);
        let real_upper_ns = age_ns + (age_ns * 100).div_ceil(999_900);
        if real_upper_ns > 250_000_000 {
            return Err("UTC dispatch exhausted its original full-nanosecond sample age".into());
        }
        let upper = self
            .raw
            .endpoints()
            .1
            .checked_add(i64::try_from(real_upper_ns.div_ceil(1_000_000))?)
            .ok_or("UTC dispatch outward projection overflowed")?
            .max(result.interval().endpoints().1);
        let lower = result.interval().endpoints().0;
        if upper - lower > 500 {
            return Err("UTC dispatch fractional projection exceeded its approved width".into());
        }
        result.utc = Interval::new(lower, upper)?;
        finish(coordinate)?;
        self.last_clock = now;
        self.last_projection_ns = Some(coordinate.boottime_ns());
        self.delivered_context = result.context().clone();
        self.delivered_utc = result.interval();
        Ok(result)
    }
}

/// A live protected transport, deliberately not Clone/Serialize. The caller
/// brackets each use with semantic HistoryReader checks and current principal
/// checks; neither a saved response nor a caller timestamp can build this.
pub(crate) struct Client {
    release: Release,
    endpoint: Identity,
    peer: Option<(i32, File)>,
    history: Option<String>,
    generation: Option<(String, Statement)>,
    last_sequence: u64,
    sample: Option<DeliverySample>,
    process: u32,
    watch: crate::utc_step_watch::StepWatch,
    initial: crate::utc_keeper::Clock,
    fenced: bool,
}
impl Client {
    pub(crate) fn installed() -> Result<Self> {
        Self::with_release(Release::installed()?)
    }
    fn recovery() -> Result<Self> {
        Self::with_release(Release::recovery()?)
    }
    fn with_release(release: Release) -> Result<Self> {
        crate::require_root()?;
        let watch = crate::utc_step_watch::StepWatch::arm()?;
        let initial = Receiver::clock(0)?;
        Ok(Self {
            release,
            endpoint: endpoint(QUERY)?,
            peer: None,
            history: None,
            generation: None,
            last_sequence: 0,
            sample: None,
            process: std::process::id(),
            watch,
            initial,
            fenced: false,
        })
    }
    pub(crate) fn current(&mut self, binding: &HistoryBinding) -> Result<Observation> {
        if self.fenced {
            return Err("UTC client is fenced; explicit reconstruction required".into());
        }
        let result = self.current_inner(binding);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn current_inner(&mut self, binding: &HistoryBinding) -> Result<Observation> {
        self.watch.check()?;
        let deadline = Instant::now() + BUDGET;
        self.release.recheck()?;
        if endpoint(QUERY)? != self.endpoint {
            return Err("UTC query socket changed".into());
        }
        let history = binding_digest(binding);
        if self.history.as_ref().is_some_and(|old| old != &history) {
            return Err("UTC client's shared history changed".into());
        }
        let before = Receiver::clock(0)?;
        let mut socket = UnixStream::connect(QUERY)?;
        socket_budget(&socket)?;
        let peer = credentials(&socket, self.release.mode.keeper_label())?;
        if let Some((pid, pin)) = &self.peer {
            if peer.pid != *pid || !crate::resource_manager::pidfd_alive(pin)? {
                return Err("UTC keeper process generation changed".into());
            }
        } else {
            self.peer = Some((peer.pid, crate::service::peer_pidfd(&socket)?));
        }
        let request = Query {
            schema_version: 1,
            nonce: random()?,
        };
        frame(&mut socket, &request)?;
        let reply: Reply = read_frame(&mut socket)?;
        credentials(&socket, self.release.mode.keeper_label())?;
        let now = Receiver::clock(0)?;
        if reply.schema_version != 1
            || reply.nonce != request.nonce
            || reply.sequence <= self.last_sequence
            || Instant::now() >= deadline
            || reply.captured_boottime_ms < before.boottime_ms
            || reply.captured_boottime_ms > now.boottime_ms
            || reply.captured_monotonic_ms < before.monotonic_ms
            || reply.captured_monotonic_ms > now.monotonic_ms
            || now
                .boottime_ms
                .saturating_sub(before.boottime_ms)
                .abs_diff(now.monotonic_ms.saturating_sub(before.monotonic_ms))
                > 2
            || now
                .boottime_ms
                .checked_sub(self.initial.boottime_ms)
                .ok_or("UTC boot clock regressed")?
                .abs_diff(
                    now.monotonic_ms
                        .checked_sub(self.initial.monotonic_ms)
                        .ok_or("UTC monotonic clock regressed")?,
                )
                > 2
            || reply.context.boot_id != bundle::hex(&crate::utc_receiver::kernel_boot()?)
        {
            return Err("UTC response is stale, replayed or crossed a clock boundary".into());
        }
        nonce(&reply.instance)?;
        reply.context.validate()?;
        let utc = Interval::new(reply.earliest_ms, reply.latest_ms)?;
        if reply.context.floor_ms != utc.endpoints().0
            || utc.endpoints().1 - utc.endpoints().0 > 500
        {
            return Err("UTC delivered interval differs from its actual observation".into());
        }
        let mut generation = reply.context.clone();
        generation.floor_ms = 0;
        if self
            .generation
            .as_ref()
            .is_some_and(|old| old != &(reply.instance.clone(), generation.clone()))
        {
            return Err("UTC keeper or source generation changed".into());
        }
        self.release.recheck()?;
        if endpoint(QUERY)? != self.endpoint
            || !crate::resource_manager::pidfd_alive(
                &self.peer.as_ref().ok_or("UTC peer missing")?.1,
            )?
        {
            return Err("UTC peer changed during delivery".into());
        }
        self.watch.check()?;
        let final_clock = Receiver::clock(0)?;
        let epoch = crate::utc_bounds::Epoch {
            boot_id: crate::tpm::decode::<16>(&reply.context.boot_id)?,
            provider_generation: reply.context.process_generation,
            clock_generation: reply.context.source_clock_generation,
            policy_digest: crate::tpm::decode::<32>(&reply.context.policy_sha256)?,
        };
        let utc = crate::utc_bounds::project(
            crate::utc_bounds::Measurement {
                operator: 1,
                utc,
                observed_boottime_ms: reply.captured_boottime_ms,
                epoch,
            },
            final_clock.boottime_ms,
            epoch,
            crate::utc_bounds::Policy {
                max_age_ms: 250,
                max_width_ms: 500,
                drift_ppm: 100,
            },
        )?;
        if utc.endpoints().0 < binding.floor_ms()
            || utc.endpoints().1 - utc.endpoints().0 > 500
            || Instant::now() >= deadline
        {
            return Err("UTC delivery exceeded protected floor, width or deadline".into());
        }
        self.history = Some(history.clone());
        self.generation = Some((reply.instance.clone(), generation));
        self.last_sequence = reply.sequence;
        let raw = Interval::new(reply.earliest_ms, reply.latest_ms)?;
        let mut context = reply.context.clone();
        context.floor_ms = utc.endpoints().0;
        self.sample = Some(DeliverySample {
            history,
            instance: reply.instance,
            sequence: reply.sequence,
            context: reply.context,
            raw,
            captured_boottime_ms: reply.captured_boottime_ms,
            captured_monotonic_ms: reply.captured_monotonic_ms,
            last_clock: final_clock,
            last_projection_ns: None,
            delivered_context: context.clone(),
            delivered_utc: utc,
            deadline,
        });
        Ok(Observation { context, utc })
    }
    pub(crate) fn recheck(
        &mut self,
        binding: &HistoryBinding,
        previous: &Observation,
    ) -> Result<Observation> {
        let current = self.current(binding)?;
        let mut expected = current.context().clone();
        expected.floor_ms = previous.context().floor_ms;
        if &expected != previous.context() {
            self.fenced = true;
            return Err("UTC observation crossed a protected generation boundary".into());
        }
        Ok(current)
    }

    /// Finish account/catalog checks with a projection of the SAME private
    /// query sample. No IPC, pathname reads, caller clock, re-acquisition or
    /// renewed age is involved. The caller must still own current history and
    /// evaluate every finite validity/aging constraint against this result.
    /// Its completion callback validates original PAM deadlines at the SAME
    /// sealed nanosecond coordinate without another file, clock or IPC read.
    pub(crate) fn project_after_checks(
        &mut self,
        binding: &HistoryBinding,
        previous: &Observation,
        finish: impl FnOnce(&ProjectionClock) -> Result<()>,
    ) -> Result<Observation> {
        if self.fenced {
            return Err("UTC client is fenced; explicit reconstruction required".into());
        }
        let result = self.project_after_checks_inner(binding, previous, finish);
        if result.is_err() {
            self.fenced = true;
            self.sample = None;
        }
        result
    }
    fn project_after_checks_inner(
        &mut self,
        binding: &HistoryBinding,
        previous: &Observation,
        finish: impl FnOnce(&ProjectionClock) -> Result<()>,
    ) -> Result<Observation> {
        if std::process::id() != self.process || unsafe { libc::geteuid() } != 0 {
            return Err("UTC local projection left its original protected process".into());
        }
        let sample = self
            .sample
            .as_ref()
            .ok_or("UTC client has no admitted query sample")?;
        let history = binding_digest(binding);
        if self.history.as_deref() != Some(history.as_str()) {
            return Err("UTC local projection changed its shared history".into());
        }
        sample.require_binding(
            &history,
            self.generation.as_ref(),
            self.last_sequence,
            previous,
        )?;
        sample.require_deadline(Instant::now())?;
        self.watch.check()?;
        let peer = &self
            .peer
            .as_ref()
            .ok_or("UTC local projection lacks its admitted peer")?
            .1;
        if !crate::resource_manager::pidfd_alive(peer)? {
            return Err("UTC local projection keeper exited".into());
        }
        // Receiver::clock performs only kernel clock_gettime calls, not file
        // reads. Its bounded bracket rejects scheduling delay and uses realtime
        // solely as a discontinuity coordinate, never as UTC or a seed.
        let first = Receiver::clock(0)?;
        sample.project(self.initial, first, binding.floor_ms())?;
        self.watch.check()?;
        if !crate::resource_manager::pidfd_alive(peer)? {
            return Err("UTC local projection keeper exited during observation".into());
        }
        let coordinate = ProjectionClock::capture()?;
        let now = coordinate.coordinate();
        if now.boottime_ms < first.boottime_ms
            || now.monotonic_ms < first.monotonic_ms
            || coordinate.process() != self.process
            || coordinate.euid() != 0
        {
            return Err("UTC local projection expired or changed context during dispatch".into());
        }
        let sample = self
            .sample
            .as_mut()
            .ok_or("UTC admitted sample disappeared")?;
        sample.finish_projection(self.initial, binding.floor_ms(), &coordinate, finish)
    }
}

fn listener(path: &str) -> Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    endpoint(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// The keeper has no TPM/history password or OS-account access. Only its fixed
/// NTS producer gets network access; ptrace permission is read-only and limited
/// by AppArmor to that producer's metadata, never process mutation.
pub(crate) fn serve() -> Result<()> {
    serve_release(Release::installed()?)
}
pub(crate) fn serve_recovery() -> Result<()> {
    serve_release(Release::recovery()?)
}
fn serve_release(release: Release) -> Result<()> {
    crate::require_root()?;
    if fs::read_to_string("/proc/self/attr/current")?
        != format!("{}\n", release.mode.keeper_label())
        || fs::read_to_string("/proc/self/cgroup")? != release.mode.keeper_cgroup()
    {
        return Err("UTC keeper must run in its enforcing installed unit".into());
    }
    release.recheck()?;
    let measurements = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/luma-utc")?;
    let m = measurements.metadata()?;
    if m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o700
        || unsafe { libc::fchown(measurements.as_raw_fd(), 0, crate::utc_runtime::PRODUCER_ID) }
            != 0
        || unsafe { libc::fchmod(measurements.as_raw_fd(), 0o710) } != 0
    {
        return Err("UTC supervisor runtime directory was not freshly provisioned".into());
    }
    let queries = listener(QUERY)?;
    let controls = listener(CONTROL)?;
    let instance = random()?;
    let mut stream: Option<Stream> = None;
    let mut pending: Option<Endpoint> = None;
    let mut sequence = 0u64;
    let mut seeded = false;
    loop {
        release.recheck()?;
        if let Some(endpoint) = pending.take() {
            match endpoint
                .acquire()
                .and_then(|receiver| Stream::assemble(receiver, 0, 0))
            {
                Ok(value) => stream = Some(value),
                Err(_) => {
                    stream = None;
                }
            }
        }
        if let Some(value) = stream.as_mut() {
            if value.poll().is_err() {
                value.invalidate();
            }
        }
        if let Ok((mut socket, _)) = queries.accept() {
            let result = (|| {
                socket_budget(&socket)?;
                credentials_any(&socket, release.mode.query_labels())?;
                let request: Query = read_frame(&mut socket)?;
                nonce(&request.nonce)?;
                if request.schema_version != 1 {
                    return Err("UTC query schema differs".into());
                }
                let value = stream
                    .as_mut()
                    .ok_or("UTC keeper requires independently reviewed seed")?;
                if value.poll()?.is_none() {
                    return frame(
                        &mut socket,
                        &serde_json::json!({"schema_version":1,
                        "nonce":request.nonce,"state":"acquiring","timed_authority":false}),
                    );
                }
                let runtime = value.receiver.runtime_digest()?.to_owned();
                let clock = Receiver::clock(0)?;
                let utc = value
                    .candidate_after_history()?
                    .ok_or("UTC keeper lost quorum")?;
                let after = Receiver::clock(0)?;
                let capture_span = after
                    .boottime_ms
                    .checked_sub(clock.boottime_ms)
                    .filter(|span| *span <= 10)
                    .ok_or("UTC delivery capture exceeded bound")?;
                // The stream sampled its estimate inside this bracket. Move
                // the lower end conservatively back to the advertised capture
                // coordinate instead of double-counting the delivery elapsed
                // time, and include outward elapsed/clock-read quantization.
                let expansion = i64::try_from(capture_span)?
                    + 2
                    + i64::try_from((u128::from(capture_span) * 100).div_ceil(999_900))?;
                let utc = Interval::new(
                    utc.endpoints()
                        .0
                        .checked_sub(expansion)
                        .ok_or("UTC delivery lower bound underflow")?,
                    utc.endpoints().1,
                )?;
                if utc.endpoints().1 - utc.endpoints().0 > 500 {
                    return Err("UTC delivery uncertainty exceeded approved width".into());
                }
                sequence = sequence
                    .checked_add(1)
                    .ok_or("UTC delivery sequence exhausted")?;
                let producer = value.batch.producer;
                let reply = Reply {
                    schema_version: 1,
                    nonce: request.nonce,
                    instance: instance.clone(),
                    sequence,
                    captured_boottime_ms: clock.boottime_ms,
                    captured_monotonic_ms: clock.monotonic_ms,
                    context: Statement {
                        floor_ms: utc.endpoints().0,
                        policy_sha256: bundle::hex(&producer.policy_digest),
                        boot_id: bundle::hex(&producer.boot_id),
                        process_generation: producer.process_generation,
                        source_clock_generation: producer.source_clock_generation,
                        keeper_generation: value.batch.keeper.epoch().clock_generation,
                        runtime_sha256: runtime,
                    },
                    earliest_ms: utc.endpoints().0,
                    latest_ms: utc.endpoints().1,
                };
                value.receiver.recheck_quiet()?;
                frame(&mut socket, &reply)
            })();
            if result.is_err() {
                if let Some(value) = stream.as_mut() {
                    value.invalidate();
                }
            }
        }
        if let Ok((mut socket, _)) = controls.accept() {
            let result = (|| {
                socket_budget(&socket)?;
                credentials(&socket, release.mode.control_label())?;
                let request: Control = match read_frame::<ControlRequest>(&mut socket)? {
                    ControlRequest::Inspect(request) => {
                        nonce(&request.nonce)?;
                        if request.schema_version != 1 {
                            return Err("UTC control schema differs".into());
                        }
                        return frame(
                            &mut socket,
                            &ControlReply {
                                schema_version: 1,
                                nonce: request.nonce,
                                instance: instance.clone(),
                                result: if seeded {
                                    "acquisition-already-started"
                                } else {
                                    "seed-required"
                                }
                                .into(),
                            },
                        );
                    }
                    ControlRequest::Seed(request) => request,
                };
                nonce(&request.nonce)?;
                nonce(&request.history_binding)?;
                request.seed.validate(request.history_floor_ms)?;
                if seeded
                    || request.schema_version != 1
                    || request.instance != instance
                    || request.reviewed_sha256
                        != seed_review(&request.seed, &request.history_binding, &instance)?
                {
                    return Err(
                        "UTC acquisition requires exact independent seed review and a fresh keeper"
                            .into(),
                    );
                }
                let seed_ms = request
                    .seed
                    .earliest_ms
                    .checked_add((request.seed.latest_ms - request.seed.earliest_ms) / 2)
                    .ok_or("UTC seed overflows")?;
                let time = libc::timespec {
                    tv_sec: seed_ms / 1000,
                    tv_nsec: (seed_ms % 1000) * 1_000_000,
                };
                if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                seeded = true;
                let deployment = match &release.mode {
                    crate::utc_runtime::Mode::Installed => Deployment::installed()?,
                    crate::utc_runtime::Mode::Recovery(_) => Deployment::recovery()?,
                };
                pending = Some(Endpoint::bind(deployment)?);
                let mut ready = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(READY)?;
                ready.write_all(serde_json::to_string(&request)?.as_bytes())?;
                ready.sync_all()?;
                File::open("/run/luma-utc")?.sync_all()?;
                frame(
                    &mut socket,
                    &ControlReply {
                        schema_version: 1,
                        nonce: request.nonce,
                        instance: instance.clone(),
                        result: "acquisition-started-not-time-authority".into(),
                    },
                )
            })();
            if result.is_err() {
                if let Some(value) = stream.as_mut() {
                    value.invalidate();
                }
            }
        }
        let mut polls = [
            libc::pollfd {
                fd: queries.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: controls.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 50) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

pub(crate) fn seed_review(seed: &Seed, history: &str, instance: &str) -> Result<String> {
    nonce(history)?;
    nonce(instance)?;
    seed.validate(0)?;
    let mut digest = Sha256::new();
    digest.update(b"luma-independent-utc-seed-review-v1\0");
    digest.update(history.as_bytes());
    digest.update(instance.as_bytes());
    digest.update(serde_json::to_vec(seed)?);
    Ok(bundle::hex(&digest.finalize()))
}

fn control_inspect() -> Result<ControlReply> {
    let release = Release::installed()?;
    control_inspect_release(&release)
}
fn control_inspect_release(release: &Release) -> Result<ControlReply> {
    release.recheck()?;
    let original = endpoint(CONTROL)?;
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    let peer = credentials(&socket, release.mode.keeper_label())?.pid;
    let pin = crate::service::peer_pidfd(&socket)?;
    let request = Query {
        schema_version: 1,
        nonce: random()?,
    };
    let expected = request.nonce.clone();
    frame(&mut socket, &ControlRequest::Inspect(request))?;
    let reply: ControlReply = read_frame(&mut socket)?;
    if reply.schema_version != 1
        || reply.nonce != expected
        || !matches!(
            reply.result.as_str(),
            "seed-required" | "acquisition-already-started"
        )
        || credentials(&socket, release.mode.keeper_label())?.pid != peer
        || !crate::resource_manager::pidfd_alive(&pin)?
        || endpoint(CONTROL)? != original
    {
        return Err("UTC supervisor inspection crossed a generation boundary".into());
    }
    nonce(&reply.instance)?;
    release.recheck()?;
    Ok(reply)
}
fn restart_review(binding: &HistoryBinding, reply: &ControlReply) -> Result<String> {
    nonce(&reply.instance)?;
    let mut digest = Sha256::new();
    digest.update(b"luma-reviewed-fixed-utc-supervisor-restart-v1\0");
    digest.update(binding_digest(binding).as_bytes());
    digest.update(reply.instance.as_bytes());
    digest.update(reply.result.as_bytes());
    Ok(bundle::hex(&digest.finalize()))
}
pub(crate) fn reacquire_proposal(binding: &HistoryBinding) -> Result<serde_json::Value> {
    let reply = control_inspect()?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"explicit-fixed-utc-supervisor-restart",
        "instance":reply.instance,"state":reply.result,
        "reviewed_sha256":restart_review(binding,&reply)?,
        "new_independent_seed_required":true,"timed_authority":false}),
    )
}
pub(crate) fn reacquire_admin(
    account: &crate::authentication::AuthenticatedAccount,
    binding: &HistoryBinding,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    account.observe(|identity| {
        if identity["uid"].as_u64() != Some(1001) {
            return Err("UTC recovery requires original Admin".into());
        }
        restart_fixed(binding, instance, reviewed)
    })
}
pub(crate) fn reacquire_custody(
    custody: &crate::admin_governance::SeedCustody<'_>,
    binding: &HistoryBinding,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    custody.observe(|| restart_fixed(binding, instance, reviewed))
}
fn restart_fixed(binding: &HistoryBinding, instance: &str, reviewed: &str) -> Result<()> {
    restart_fixed_release(&Release::installed()?, binding, instance, reviewed)
}
fn restart_fixed_release(
    release: &Release,
    binding: &HistoryBinding,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    crate::require_root()?;
    release.recheck()?;
    let (helper_path, profile_path, profile_bytes) = match &release.mode {
        crate::utc_runtime::Mode::Installed => (
            "/usr/libexec/luma-os/luma-utc-restart",
            "/etc/apparmor.d/luma-utc-restart",
            include_bytes!("../../../native/image/overlay/etc/apparmor.d/luma-utc-restart")
                .as_slice(),
        ),
        crate::utc_runtime::Mode::Recovery(_) => (
            "/usr/libexec/luma-os/luma-utc-recovery-restart",
            "/etc/apparmor.d/luma-utc-recovery-restart",
            include_bytes!(
                "../../../native/image/overlay/etc/apparmor.d/luma-utc-recovery-restart"
            )
            .as_slice(),
        ),
    };
    let helper = crate::utc_runtime::Pin::immutable(helper_path, 1024 * 1024, None)?;
    let profile = crate::utc_runtime::Pin::immutable(profile_path, 32 * 1024, Some(profile_bytes))?;
    let reply = control_inspect_release(release)?;
    if reply.instance != instance || restart_review(binding, &reply)? != reviewed {
        return Err("UTC restart requires exact current instance and shared-history review".into());
    }
    let (mut parent, child) = UnixStream::pair()?;
    let child_fd = child.as_raw_fd();
    let mut command = Command::new(helper_path);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if child_fd != 3 && libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    helper.immutable_recheck()?;
    profile.immutable_recheck()?;
    let mut process = command.spawn()?;
    drop(child);
    // Canonical closed JSON has one fixed operation and an audit digest. The
    // inherited connection's original kernel peer is the authority boundary,
    // not the digest or an assertion of root/role/previous authentication.
    let request =
        format!("{{\"operation\":\"restart-fixed-utc\",\"reviewed_sha256\":\"{reviewed}\"}}");
    if let Err(error) = parent
        .write_all(&(request.len() as u32).to_be_bytes())
        .and_then(|_| parent.write_all(request.as_bytes()))
        .and_then(|_| parent.shutdown(std::net::Shutdown::Write))
    {
        let _ = process.kill();
        let _ = process.wait();
        return Err(error.into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process.try_wait()? {
            if !status.success() {
                return Err(
                    "UTC restart outcome is refused/uncertain; inspect without automatic retry"
                        .into(),
                );
            }
            helper.immutable_recheck()?;
            profile.immutable_recheck()?;
            release.recheck()?;
            let after = control_inspect_release(release)?;
            if after.instance == instance || after.result != "seed-required" {
                return Err("UTC restart did not prove a new fenced seed-required instance".into());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = process.kill();
            let _ = process.wait();
            return Err(
                "UTC restart acknowledgment is uncertain; never automatically retry".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn seed_proposal(binding: &HistoryBinding, seed: &Seed) -> Result<serde_json::Value> {
    crate::require_root()?;
    let release = Release::installed()?;
    seed_proposal_release(&release, binding, seed)
}
fn seed_proposal_release(
    release: &Release,
    binding: &HistoryBinding,
    seed: &Seed,
) -> Result<serde_json::Value> {
    release.recheck()?;
    let original = endpoint(CONTROL)?;
    seed.validate(binding.floor_ms())?;
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    credentials(&socket, release.mode.keeper_label())?;
    let request = Query {
        schema_version: 1,
        nonce: random()?,
    };
    let expected_nonce = request.nonce.clone();
    let expected_peer = credentials(&socket, release.mode.keeper_label())?.pid;
    let pin = crate::service::peer_pidfd(&socket)?;
    frame(&mut socket, &ControlRequest::Inspect(request))?;
    let reply: ControlReply = read_frame(&mut socket)?;
    if reply.schema_version != 1
        || reply.nonce != expected_nonce
        || reply.result != "seed-required"
        || credentials(&socket, release.mode.keeper_label())?.pid != expected_peer
        || !crate::resource_manager::pidfd_alive(&pin)?
        || endpoint(CONTROL)? != original
    {
        return Err("UTC seed requires a fresh protected keeper instance".into());
    }
    nonce(&reply.instance)?;
    release.recheck()?;
    Ok(
        serde_json::json!({ "schema_version": 1, "kind": "independent-utc-certificate-bootstrap",
        "instance": reply.instance, "seed": seed, "history_floor_ms": binding.floor_ms(),
        "reviewed_sha256": seed_review(seed, &binding_digest(binding), &reply.instance)?,
        "timed_authority": false }),
    )
}

/// Called only by the reviewed local Admin composition after current original
/// principal/PAM and full semantic history validation. Success is bootstrap
/// evidence, not UTC authority; uncertain delivery is not automatically retried.
pub(crate) fn deliver_seed(
    account: &crate::authentication::AuthenticatedAccount,
    binding: &HistoryBinding,
    seed: &Seed,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    account.observe(|identity| {
        if identity["uid"].as_u64() != Some(1001) {
            return Err("UTC bootstrap requires the original local Admin".into());
        }
        seed_transport(binding, seed, instance, reviewed)
    })
}

pub(crate) fn deliver_seed_custody(
    custody: &crate::admin_governance::SeedCustody<'_>,
    binding: &HistoryBinding,
    seed: &Seed,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    custody.observe(|| seed_transport(binding, seed, instance, reviewed))
}

fn seed_transport(
    binding: &HistoryBinding,
    seed: &Seed,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    crate::require_root()?;
    let release = Release::installed()?;
    seed_transport_release(&release, binding, seed, instance, reviewed)
}
fn seed_transport_release(
    release: &Release,
    binding: &HistoryBinding,
    seed: &Seed,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    release.recheck()?;
    let original = endpoint(CONTROL)?;
    seed.validate(binding.floor_ms())?;
    nonce(instance)?;
    let history = binding_digest(binding);
    if reviewed != seed_review(seed, &history, instance)? {
        return Err("UTC seed review changed".into());
    }
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    let peer = credentials(&socket, release.mode.keeper_label())?;
    let pin = crate::service::peer_pidfd(&socket)?;
    let request = Control {
        schema_version: 1,
        nonce: random()?,
        instance: instance.into(),
        history_binding: history.clone(),
        history_floor_ms: binding.floor_ms(),
        seed: seed.clone(),
        reviewed_sha256: reviewed.into(),
    };
    let nonce = request.nonce.clone();
    frame(&mut socket, &ControlRequest::Seed(request))?;
    let reply: ControlReply = read_frame(&mut socket)?;
    if reply.schema_version != 1
        || reply.nonce != nonce
        || reply.instance != instance
        || reply.result != "acquisition-started-not-time-authority"
        || credentials(&socket, release.mode.keeper_label())?.pid != peer.pid
        || !crate::resource_manager::pidfd_alive(&pin)?
        || endpoint(CONTROL)? != original
    {
        return Err("UTC seed delivery outcome is uncertain; inspect without retry".into());
    }
    release.recheck()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_root_machine_query_is_not_seed_control_or_nonroot_authority() {
        let mode = crate::utc_runtime::Mode::Installed;
        assert!(protected_peer_ids(0, 0, 1));
        for (uid, gid, pid) in [(1001, 0, 1), (0, 1001, 1), (0, 0, 0), (0, 0, -1)] {
            assert!(!protected_peer_ids(uid, gid, pid));
        }
        assert!(approved_peer_label(b"unconfined", mode.query_labels()));
        assert!(approved_peer_label(b"unconfined\0", mode.query_labels()));
        for label in [
            b"other (enforce)".as_slice(),
            b"unconfined (enforce)",
            b"unconfined\0extra",
        ] {
            assert!(!approved_peer_label(label, mode.query_labels()));
        }
        assert!(!approved_peer_label(b"unconfined", &[mode.control_label()]));
        for wire in [
            br#"{"schema_version":1,"nonce":"aa","seed":{}}"#.as_slice(),
            br#"{"schema_version":1,"nonce":"aa","history_floor_ms":1}"#,
        ] {
            assert!(serde_json::from_slice::<Query>(wire).is_err());
        }
    }
    fn projection_clock(boot: u64, mono: u64) -> crate::utc_keeper::Clock {
        crate::utc_keeper::Clock {
            boottime_ms: boot,
            monotonic_ms: mono,
            realtime_ms: 0,
            suspend_generation: 0,
        }
    }
    fn projection_sample(lower: i64, upper: i64) -> DeliverySample {
        let raw = Interval::new(lower, upper).unwrap();
        let context = Statement {
            floor_ms: lower,
            policy_sha256: bundle::hex(
                &crate::utc_policy::ApprovedPolicy::fixed().unwrap().digest(),
            ),
            boot_id: "ab".repeat(16),
            process_generation: 3,
            source_clock_generation: 4,
            keeper_generation: 5,
            runtime_sha256: "cd".repeat(32),
        };
        DeliverySample {
            history: "ef".repeat(32),
            instance: "12".repeat(32),
            sequence: 7,
            context: context.clone(),
            raw,
            captured_boottime_ms: 1_000,
            captured_monotonic_ms: 900,
            last_clock: projection_clock(1_000, 900),
            last_projection_ns: None,
            delivered_context: context,
            delivered_utc: raw,
            deadline: Instant::now() + BUDGET,
        }
    }
    fn delivered(sample: &DeliverySample) -> Observation {
        Observation {
            context: sample.delivered_context.clone(),
            utc: sample.delivered_utc,
        }
    }
    fn generation(sample: &DeliverySample) -> (String, Statement) {
        let mut context = sample.context.clone();
        context.floor_ms = 0;
        (sample.instance.clone(), context)
    }
    #[test]
    fn projection_and_authentication_completion_share_the_exact_nanosecond_coordinate() {
        let mut sample = projection_sample(200_000, 200_010);
        let mut coordinate = ProjectionClock::fixture(1_020_000_007, 123, 0);
        coordinate.monotonic_ms = 920;
        let called = std::cell::Cell::new(false);
        let observed = sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |actual| {
                assert!(std::ptr::eq(actual, &coordinate));
                assert_eq!(actual.boottime_ns(), 1_020_000_007);
                assert_eq!(actual.process(), 123);
                assert_eq!(actual.euid(), 0);
                called.set(true);
                Ok(())
            })
            .unwrap();
        assert!(called.get());
        assert_eq!(observed.interval().endpoints(), (200_019, 200_031));
        assert_eq!(sample.last_clock.boottime_ms, 1_020);
        assert_eq!(sample.last_clock.monotonic_ms, 920);
        assert_eq!(sample.delivered_utc, observed.interval());
        assert_eq!(sample.delivered_context, *observed.context());
        assert_eq!(sample.captured_boottime_ms, 1_000);
    }
    #[test]
    fn failed_exact_pam_deadline_completion_cannot_publish_or_advance_the_projection() {
        let mut sample = projection_sample(200_000, 200_010);
        let previous = delivered(&sample);
        let mut coordinate = ProjectionClock::fixture(1_020_000_007, 123, 0);
        coordinate.monotonic_ms = 920;
        let deadline_ns = coordinate.boottime_ns();
        assert!(sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |actual| {
                if actual.boottime_ns() >= deadline_ns {
                    return Err("original PAM fixed deadline reached".into());
                }
                Ok(())
            },)
            .is_err());
        assert_eq!(sample.last_clock.boottime_ms, 1_000);
        assert_eq!(sample.delivered_context, *previous.context());
        assert_eq!(sample.delivered_utc, previous.interval());
        // Full nanoseconds, not a rounded millisecond, distinguish the final
        // valid coordinate from exact expiry in the completion callback.
        coordinate.boottime_ns -= 1;
        sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |actual| {
                if actual.boottime_ns() >= deadline_ns {
                    return Err("original PAM fixed deadline reached".into());
                }
                Ok(())
            })
            .unwrap();
    }
    #[test]
    fn shared_coordinate_completion_preserves_outward_query_deadline_and_utc_age() {
        let mut sample = projection_sample(200_000, 200_010);
        let mut coordinate = ProjectionClock::fixture(1_020_000_007, 123, 0);
        coordinate.monotonic_ms = 920;
        coordinate.sampled_instant = sample.deadline - Duration::from_millis(2);
        let called = std::cell::Cell::new(false);
        assert!(sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| {
                called.set(true);
                Ok(())
            },)
            .is_err());
        assert!(!called.get());
        assert_eq!(sample.delivered_utc.endpoints(), (200_000, 200_010));
        coordinate.sampled_instant -= Duration::from_nanos(1);
        sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| Ok(()))
            .unwrap();
        coordinate.boottime_ns = 1_250_000_000;
        coordinate.monotonic_ms = 1_150;
        assert!(sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| {
                called.set(true);
                Ok(())
            },)
            .is_err());
        assert!(!called.get());
    }
    #[test]
    fn fractional_dispatch_coordinate_rounds_outwards_and_never_hides_expiry_or_total_age() {
        let mut sample = projection_sample(200_000, 200_010);
        let mut coordinate = ProjectionClock::fixture(1_020_999_999, 123, 0);
        coordinate.monotonic_ms = 920;
        let observed = sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| Ok(()))
            .unwrap();
        assert_eq!(observed.interval().endpoints(), (200_019, 200_032));
        assert!(!observed.interval().within(199_000, 200_032).unwrap());
        // Regressing within the same integer millisecond is not concealed by
        // the protocol's millisecond timestamp representation.
        coordinate.boottime_ns -= 1;
        assert!(sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| Ok(()),)
            .is_err());
        let mut sample = projection_sample(200_000, 200_010);
        coordinate.boottime_ns = 1_249_980_000;
        coordinate.monotonic_ms = 1_149;
        assert!(sample
            .project(projection_clock(900, 800), coordinate.coordinate(), 199_000,)
            .is_ok());
        assert!(sample
            .finish_projection(projection_clock(900, 800), 199_000, &coordinate, |_| Ok(()),)
            .is_err());
    }
    #[test]
    fn local_projection_shifts_grant_expiry_after_final_account_reads() {
        let sample = projection_sample(200_000, 200_010);
        let previous = delivered(&sample);
        assert!(previous.interval().within(199_000, 200_020).unwrap());
        let current = sample
            .project(
                projection_clock(900, 800),
                projection_clock(1_020, 920),
                199_000,
            )
            .unwrap();
        assert_eq!(current.interval().endpoints(), (200_019, 200_031));
        assert_eq!(current.context().floor_ms, 200_019);
        assert!(!current.interval().within(199_000, 200_020).unwrap());
        assert!(current.interval().within(199_000, 200_032).unwrap());
    }
    #[test]
    fn repeated_local_projection_never_restarts_sample_age_or_query_deadline() {
        let mut sample = projection_sample(200_000, 200_010);
        let deadline = sample.deadline;
        let first = sample
            .project(
                projection_clock(900, 800),
                projection_clock(1_200, 1_100),
                199_000,
            )
            .unwrap();
        sample.last_clock = projection_clock(1_200, 1_100);
        sample.delivered_context = first.context().clone();
        sample.delivered_utc = first.interval();
        let second = sample
            .project(
                projection_clock(900, 800),
                projection_clock(1_249, 1_149),
                199_000,
            )
            .unwrap();
        assert_eq!(second.interval().endpoints(), (200_248, 200_260));
        assert_eq!(sample.captured_boottime_ms, 1_000);
        assert_eq!(sample.captured_monotonic_ms, 900);
        assert_eq!(sample.raw.endpoints(), (200_000, 200_010));
        assert_eq!(sample.deadline, deadline);
        assert!(sample
            .project(
                projection_clock(900, 800),
                projection_clock(1_250, 1_150),
                199_000
            )
            .is_err());
        assert!(sample
            .project(
                projection_clock(900, 800),
                projection_clock(1_400, 1_300),
                199_000
            )
            .is_err());
        sample
            .require_deadline(deadline - Duration::from_nanos(1))
            .unwrap();
        assert!(sample.require_deadline(deadline).is_err());
        assert!(sample
            .require_deadline(deadline + Duration::from_nanos(1))
            .is_err());
    }
    #[test]
    fn local_projection_requires_exact_history_generation_sequence_and_last_result() {
        let sample = projection_sample(200_000, 200_010);
        let previous = delivered(&sample);
        let original = generation(&sample);
        sample
            .require_binding(&sample.history, Some(&original), sample.sequence, &previous)
            .unwrap();
        assert!(sample
            .require_binding(
                &"aa".repeat(32),
                Some(&original),
                sample.sequence,
                &previous
            )
            .is_err());
        assert!(sample
            .require_binding(&sample.history, None, sample.sequence, &previous)
            .is_err());
        for sequence in [0, sample.sequence - 1, sample.sequence + 1] {
            assert!(sample
                .require_binding(&sample.history, Some(&original), sequence, &previous)
                .is_err());
        }
        for component in 0..8 {
            let mut changed = generation(&sample);
            match component {
                0 => changed.0 = "34".repeat(32),
                1 => changed.1.floor_ms = 1,
                2 => changed.1.policy_sha256 = "56".repeat(32),
                3 => changed.1.boot_id = "78".repeat(16),
                4 => changed.1.process_generation += 1,
                5 => changed.1.source_clock_generation += 1,
                6 => changed.1.keeper_generation += 1,
                7 => changed.1.runtime_sha256 = "90".repeat(32),
                _ => unreachable!(),
            }
            assert!(sample
                .require_binding(&sample.history, Some(&changed), sample.sequence, &previous)
                .is_err());
        }
        let changed = Observation {
            context: sample.delivered_context.clone(),
            utc: Interval::new(200_000, 200_011).unwrap(),
        };
        assert!(sample
            .require_binding(&sample.history, Some(&original), sample.sequence, &changed)
            .is_err());
        let mut changed = delivered(&sample);
        changed.context.keeper_generation += 1;
        assert!(sample
            .require_binding(&sample.history, Some(&original), sample.sequence, &changed)
            .is_err());
    }
    #[test]
    fn local_projection_rejects_suspend_regression_and_changed_clock_generation() {
        let sample = projection_sample(200_000, 200_010);
        let initial = projection_clock(900, 800);
        for now in [
            projection_clock(999, 900),
            projection_clock(1_000, 899),
            projection_clock(1_050, 920),
            projection_clock(1_020, 950),
        ] {
            assert!(sample.project(initial, now, 199_000).is_err());
        }
        let mut now = projection_clock(1_020, 920);
        now.suspend_generation = 1;
        assert!(sample.project(initial, now, 199_000).is_err());
        let mut sample = projection_sample(200_000, 200_010);
        sample.last_clock = projection_clock(1_100, 1_000);
        assert!(sample
            .project(initial, projection_clock(1_099, 999), 199_000)
            .is_err());
        // A discontinuity before the latest sample still contradicts the
        // client's original acquisition coordinate, even when sample-local
        // elapsed boot and monotonic clocks now agree.
        assert!(sample
            .project(
                projection_clock(800, 800),
                projection_clock(1_101, 1_001),
                199_000
            )
            .is_err());
    }
    #[test]
    fn local_projection_rejects_width_floor_overflow_and_invalid_original_context() {
        let initial = projection_clock(900, 800);
        let now = projection_clock(1_020, 920);
        let sample = projection_sample(200_000, 200_500);
        assert!(sample.project(initial, now, 199_000).is_err());
        let sample = projection_sample(200_000, 200_010);
        assert!(sample.project(initial, now, 200_020).is_err());
        let mut sample = projection_sample(200_000, 200_010);
        sample.raw = Interval::new(200_000, i64::MAX).unwrap();
        assert!(sample.project(initial, now, 199_000).is_err());
        let mut sample = projection_sample(200_000, 200_010);
        sample.context.floor_ms += 1;
        assert!(sample.project(initial, now, 199_000).is_err());
        let mut sample = projection_sample(200_000, 200_010);
        sample.context.process_generation = 0;
        assert!(sample.project(initial, now, 199_000).is_err());
        let mut sample = projection_sample(200_000, 200_010);
        sample.captured_monotonic_ms = u64::MAX;
        assert!(sample.project(initial, now, 199_000).is_err());
    }
    #[test]
    fn seeds_require_independent_review_bounds_and_floor() {
        let seed = Seed {
            schema_version: 1,
            earliest_ms: 1_000_000,
            latest_ms: 1_000_100,
            independent_source: "independent custodian clock".into(),
            review_reference: "ceremony-123".into(),
        };
        seed.validate(1_000_000).unwrap();
        assert!(seed.validate(1_000_001).is_err());
        for variant in 0..7 {
            let mut changed = seed.clone();
            match variant {
                0 => changed.schema_version = 2,
                1 => changed.latest_ms = changed.earliest_ms - 1,
                2 => changed.latest_ms = changed.earliest_ms + MAX_SEED_WIDTH + 1,
                3 => changed.independent_source.clear(),
                4 => changed.review_reference.clear(),
                5 => changed.independent_source.push('\n'),
                6 => changed.earliest_ms = -1,
                _ => unreachable!(),
            }
            assert!(changed.validate(0).is_err());
        }
        assert_ne!(
            seed_review(&seed, &"ab".repeat(32), &"ef".repeat(32)).unwrap(),
            seed_review(&seed, &"cd".repeat(32), &"ef".repeat(32)).unwrap()
        );
    }
    #[test]
    fn local_protocol_is_closed_and_bounded() {
        assert!(serde_json::from_str::<Query>(
            r#"{"schema_version":1,"nonce":"x","trusted":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Query>(
            r#"{"schema_version":1,"schema_version":1,"nonce":"x"}"#
        )
        .is_err());
        let (mut left, mut right) = UnixStream::pair().unwrap();
        left.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(read_frame::<Query>(&mut right).is_err());
    }
}
