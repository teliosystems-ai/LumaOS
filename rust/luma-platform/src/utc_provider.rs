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
        || value.uid != 0
        || value.gid != 0
        || value.pid <= 0
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
    if !labels
        .iter()
        .any(|label| bytes.strip_suffix(&[0]).unwrap_or(bytes) == label.as_bytes())
    {
        return Err("UTC peer does not have its approved enforcing profile".into());
    }
    Ok(value)
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
}
impl Release {
    fn installed() -> Result<Self> {
        crate::platform::require_installed()?;
        Ok(Self {
            files: vec![
                crate::utc_runtime::Pin::immutable(
                    "/usr/libexec/luma-os/luma-platform",
                    64 * 1024 * 1024,
                    None,
                )?,
                crate::utc_runtime::Pin::immutable(
                    "/etc/apparmor.d/luma-utc-keeper",
                    32 * 1024,
                    Some(include_bytes!(
                        "../../../native/image/overlay/etc/apparmor.d/luma-utc-keeper"
                    )),
                )?,
                crate::utc_runtime::Pin::immutable(
                    "/usr/lib/systemd/system/luma-utc-keeper.service",
                    32 * 1024,
                    Some(include_bytes!(
                        "../../../native/image/utc/luma-utc-keeper.service"
                    )),
                )?,
                crate::utc_runtime::Pin::immutable(
                    "/etc/apparmor.d/luma-granted-client",
                    32 * 1024,
                    Some(include_bytes!(
                        "../../../native/image/overlay/etc/apparmor.d/luma-granted-client"
                    )),
                )?,
            ],
        })
    }
    fn recheck(&self) -> Result<()> {
        for file in &self.files {
            file.immutable_recheck()?;
        }
        Ok(())
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
    watch: crate::utc_step_watch::StepWatch,
    initial: crate::utc_keeper::Clock,
    fenced: bool,
}
impl Client {
    pub(crate) fn installed() -> Result<Self> {
        crate::require_root()?;
        let watch = crate::utc_step_watch::StepWatch::arm()?;
        let initial = Receiver::clock(0)?;
        Ok(Self {
            release: Release::installed()?,
            endpoint: endpoint(QUERY)?,
            peer: None,
            history: None,
            generation: None,
            last_sequence: 0,
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
        let peer = credentials(&socket, "luma-utc-keeper (enforce)")?;
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
        credentials(&socket, "luma-utc-keeper (enforce)")?;
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
        self.history = Some(history);
        self.generation = Some((reply.instance, generation));
        self.last_sequence = reply.sequence;
        let mut context = reply.context;
        context.floor_ms = utc.endpoints().0;
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
    crate::require_root()?;
    let release = Release::installed()?;
    if fs::read_to_string("/proc/self/attr/current")? != "luma-utc-keeper (enforce)\n"
        || fs::read_to_string("/proc/self/cgroup")? != "0::/system.slice/luma-utc-keeper.service\n"
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
                credentials_any(
                    &socket,
                    &["luma-admin (enforce)", "luma-granted-client (enforce)"],
                )?;
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
                credentials(&socket, "luma-admin (enforce)")?;
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
                let deployment = Deployment::installed()?;
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
    let original = endpoint(CONTROL)?;
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    let peer = credentials(&socket, "luma-utc-keeper (enforce)")?.pid;
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
        || credentials(&socket, "luma-utc-keeper (enforce)")?.pid != peer
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
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    crate::require_root()?;
    let helper = crate::utc_runtime::Pin::immutable(
        "/usr/libexec/luma-os/luma-utc-restart",
        1024 * 1024,
        None,
    )?;
    let profile = crate::utc_runtime::Pin::immutable(
        "/etc/apparmor.d/luma-utc-restart",
        32 * 1024,
        Some(include_bytes!(
            "../../../native/image/overlay/etc/apparmor.d/luma-utc-restart"
        )),
    )?;
    let reply = control_inspect()?;
    if reply.instance != instance || restart_review(binding, &reply)? != reviewed {
        return Err("UTC restart requires exact current instance and shared-history review".into());
    }
    let (mut parent, child) = UnixStream::pair()?;
    let child_fd = child.as_raw_fd();
    let mut command = Command::new("/usr/libexec/luma-os/luma-utc-restart");
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
            let after = control_inspect()?;
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
    let original = endpoint(CONTROL)?;
    seed.validate(binding.floor_ms())?;
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    credentials(&socket, "luma-utc-keeper (enforce)")?;
    let request = Query {
        schema_version: 1,
        nonce: random()?,
    };
    let expected_nonce = request.nonce.clone();
    let expected_peer = credentials(&socket, "luma-utc-keeper (enforce)")?.pid;
    let pin = crate::service::peer_pidfd(&socket)?;
    frame(&mut socket, &ControlRequest::Inspect(request))?;
    let reply: ControlReply = read_frame(&mut socket)?;
    if reply.schema_version != 1
        || reply.nonce != expected_nonce
        || reply.result != "seed-required"
        || credentials(&socket, "luma-utc-keeper (enforce)")?.pid != expected_peer
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
    let original = endpoint(CONTROL)?;
    seed.validate(binding.floor_ms())?;
    nonce(instance)?;
    let history = binding_digest(binding);
    if reviewed != seed_review(seed, &history, instance)? {
        return Err("UTC seed review changed".into());
    }
    let mut socket = UnixStream::connect(CONTROL)?;
    socket_budget(&socket)?;
    let peer = credentials(&socket, "luma-utc-keeper (enforce)")?;
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
        || credentials(&socket, "luma-utc-keeper (enforce)")?.pid != peer.pid
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
