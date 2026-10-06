//! Resource authority inside the existing broker. Only the fixed CPU serving
//! and acquisition groups are controllable; no caller-selected PID or budget.
use crate::{
    model,
    resources::{self, Domain, Owner, Reservation, State, Store, Token},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const CGROUP: &str = "/sys/fs/cgroup/lumamodel.slice";
const LEAF: &str = "/lumamodel.slice/luma-model.service";
const HOST: &str = "host-memory";
const PIDS: &str = "worker-processes";
const LEASE_MS: u64 = 10_000;
pub(crate) const ACQUISITION_MEMORY: u64 = 512 * 1024 * 1024;

pub(crate) mod history;
pub(crate) mod recovery;
pub(crate) mod requests;
pub(crate) use requests::request_migration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Model,
    Acquisition,
}
impl Kind {
    fn peer(uid: u32) -> Result<Self> {
        match uid {
            989 => Ok(Self::Model),
            0 => Ok(Self::Acquisition),
            _ => Err("unsupported resource worker identity".into()),
        }
    }
    fn domain(self) -> &'static str {
        match self {
            Self::Model => "serving-executions",
            Self::Acquisition => "acquisition-executions",
        }
    }
    fn tasks(self) -> u64 {
        match self {
            Self::Model => 64,
            Self::Acquisition => 16,
        }
    }
    fn leaf(self) -> &'static str {
        match self {
            Self::Model => LEAF,
            Self::Acquisition => "/lumaacquisition.slice/luma-acquisition.service",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    // CLOCK_BOOTTIME milliseconds. This envelope never grants UTC authority.
    #[serde(with = "resources::decimal")]
    pub deadline: u64,
    pub action: String,
    pub idempotency_key: Option<String>,
    pub profile: Option<String>,
    pub lease: Option<Token>,
    pub review: Option<String>,
    pub storage_device: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    pub result: String,
    pub lease: Option<Token>,
    pub status: Option<serde_json::Value>,
}

pub(crate) fn now() -> Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return Err("resource monotonic clock unavailable".into());
    }
    (time.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|s| s.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| "resource deadline overflow".into())
}

fn safe_text(path: &Path, maximum: u64) -> Result<String> {
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?
        .take(maximum + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > maximum {
        return Err("oversized resource observation".into());
    }
    Ok(text)
}

fn number(text: &str) -> Result<u64> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid resource counter".into());
    }
    Ok(text.parse()?)
}

fn fields(text: &str) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().ok_or("missing resource counter")?;
        let value = number(parts.next().ok_or("missing resource value")?)?;
        if parts.next().is_some() || result.insert(key.into(), value).is_some() {
            return Err("duplicate or invalid resource observation".into());
        }
    }
    Ok(result)
}

fn descriptor(directory: &File, name: &str, write: bool, is_directory: bool) -> Result<File> {
    // Every name is an internal single component, never client-controlled.
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err("invalid resource component".into());
    }
    let name = CString::new(name)?;
    let flags = libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if is_directory { libc::O_DIRECTORY } else { 0 }
        | if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    if m.uid() != 0
        || m.mode() & 0o022 != 0
        || (is_directory && !m.is_dir())
        || (!is_directory && !m.is_file())
    {
        return Err("unsafe resource control ownership or type".into());
    }
    Ok(file)
}

struct Group(File, Kind);
impl Group {
    fn open() -> Result<Self> {
        Self::for_kind(Kind::Model)
    }
    fn for_kind(kind: Kind) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(match kind {
                Kind::Model => CGROUP,
                Kind::Acquisition => "/sys/fs/cgroup/lumaacquisition.slice",
            })?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let m = file.metadata()?;
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
            || stat.f_type != 0x63677270
            || m.uid() != 0
            || m.mode() & 0o022 != 0
        {
            return Err("trusted cgroup v2 worker slice unavailable".into());
        }
        Ok(Self(file, kind))
    }
    fn identity(&self) -> Result<(u64, u64)> {
        let m = self.0.metadata()?;
        Ok((m.dev(), m.ino()))
    }
    fn read(&self, name: &str) -> Result<String> {
        let mut text = String::new();
        descriptor(&self.0, name, false, false)?
            .take(4097)
            .read_to_string(&mut text)?;
        if text.len() > 4096 {
            return Err("oversized cgroup observation".into());
        }
        Ok(text)
    }
    fn write(&self, name: &str, value: &str) -> Result<()> {
        let mut file = descriptor(&self.0, name, true, false)?;
        // A controller write is one command, not a filesystem publication.
        let count = file.write(value.as_bytes())?;
        if count != value.len() {
            return Err("partial cgroup command; preserve reservation".into());
        }
        Ok(())
    }
    fn current(&self) -> Result<u64> {
        number(&self.read("memory.current")?)
    }
    fn populated(&self) -> Result<bool> {
        match fields(&self.read("cgroup.events")?)?.get("populated") {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err("invalid cgroup population".into()),
        }
    }
    fn kill(&self) -> Result<()> {
        self.write("cgroup.kill", "1")
    }
    fn reclaim_idle(&self) -> Result<()> {
        if self.populated()? {
            return Err("idle reclaim cannot target live execution".into());
        }
        let amount = self.current()?.min(16 * 1024 * 1024);
        if amount == 0 {
            return Ok(());
        }
        let mut control = descriptor(&self.0, "memory.reclaim", true, false)?;
        let value = amount.to_string();
        match control.write(value.as_bytes()) {
            Ok(count) if count == value.len() => Ok(()),
            // The kernel may reclaim fewer bytes than requested. This is not a
            // release receipt; only the following memory.current read counts.
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => Ok(()),
            Ok(_) => Err("partial idle reclaim command".into()),
            Err(error) => Err(error.into()),
        }
    }
    fn oom(&self) -> Result<u64> {
        Ok(*fields(&self.read("memory.events")?)?
            .get("oom_kill")
            .ok_or("missing OOM counter")?)
    }
    fn leaf(&self) -> Result<Self> {
        Ok(Self(
            descriptor(
                &self.0,
                match self.1 {
                    Kind::Model => "luma-model.service",
                    Kind::Acquisition => "luma-acquisition.service",
                },
                false,
                true,
            )?,
            self.1,
        ))
    }
    fn verify_limits(&self, memory: u64, storage: &str) -> Result<()> {
        let limit = number(&self.read("memory.max")?)?;
        let tasks = number(&self.read("pids.max")?)?;
        if limit != memory
            || number(&self.read("memory.swap.max")?)? != 0
            || tasks == 0
            || tasks > self.1.tasks()
            || number(&self.read("memory.oom.group")?)? != 1
        {
            return Err("worker resource ceilings not enforced".into());
        }
        let cpu = self.read("cpu.max")?;
        let parts: Vec<_> = cpu.split_whitespace().collect();
        if parts.len() != 2
            || number(parts[0])?
                > number(parts[1])?
                    .checked_mul(2)
                    .ok_or("CPU ceiling overflow")?
            || number(parts[0])? == 0
            || number(parts[1])? == 0
        {
            return Err("worker CPU ceiling not enforced".into());
        }
        verify_io(&self.read("io.max")?, storage)?;
        Ok(())
    }
}

fn verify_io(text: &str, device: &str) -> Result<()> {
    let mut matches = 0;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(device) {
            continue;
        }
        matches += 1;
        let mut limits = BTreeMap::new();
        for part in parts {
            let (key, value) = part.split_once('=').ok_or("invalid IO ceiling")?;
            if limits.insert(key, value).is_some() {
                return Err("duplicate IO ceiling".into());
            }
        }
        for key in ["rbps", "wbps"] {
            let value = number(limits.get(key).ok_or("missing IO ceiling")?)?;
            if value == 0 || value > 64 * 1024 * 1024 {
                return Err("unbounded worker IO".into());
            }
        }
    }
    if matches != 1 {
        return Err("model storage IO ceiling unavailable".into());
    }
    Ok(())
}

pub(crate) fn storage_device(path: &Path) -> Result<String> {
    crate::storage_io::device_for_path(path)
}

fn valid_storage(device: &str) -> bool {
    let Some((major, minor)) = device.split_once(':') else {
        return false;
    };
    let canonical = |value: &str| {
        value
            .parse::<u32>()
            .map_or(false, |n| n.to_string() == value)
    };
    canonical(major) && canonical(minor) && major != "0"
}

fn acquisition_binding(profile: &model::Profile, device: &str) -> Result<String> {
    if !valid_storage(device) {
        return Err("invalid acquisition storage identity".into());
    }
    Ok(crate::bundle::hex(&Sha256::digest(serde_json::to_vec(&(
        "acquisition-v1",
        profile,
        device,
    ))?)))
}

fn reservation_plan(kind: Kind, memory: u64) -> Vec<Reservation> {
    let mut reservations = vec![
        Reservation {
            domain: HOST.into(),
            loading: memory,
            serving: memory,
        },
        Reservation {
            domain: PIDS.into(),
            loading: kind.tasks(),
            serving: kind.tasks(),
        },
        Reservation {
            domain: kind.domain().into(),
            loading: 1,
            serving: 1,
        },
    ];
    reservations.sort_by(|a, b| a.domain.cmp(&b.domain));
    reservations
}

fn start_ticks(stat: &str) -> Result<u64> {
    let (_, rest) = stat.rsplit_once(") ").ok_or("invalid process identity")?;
    let parts: Vec<_> = rest.split_whitespace().collect();
    if parts.len() < 20 || matches!(parts[0], "Z" | "X" | "x") {
        return Err("dead or invalid lease owner".into());
    }
    let ticks = number(parts[19])?;
    if ticks == 0 {
        return Err("invalid process generation".into());
    }
    Ok(ticks)
}

fn boot_identity() -> Result<String> {
    let boot = safe_text(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let text = boot
        .strip_suffix('\n')
        .ok_or("invalid kernel boot identity")?;
    if text.len() != 36
        || !text.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid kernel boot identity".into());
    }
    Ok(text.into())
}

fn drainage_generation(owner: &Owner, boot: &str, identity: (u64, u64)) -> Result<()> {
    // CPU-only volatile allocations cannot survive a new kernel boot. During
    // the same boot, emptiness of a replacement cgroup says nothing about the
    // recorded physical allocation; keep its full charge until a reboot.
    if owner.boot == boot && (owner.cgroup_device, owner.cgroup_inode) != identity {
        return Err("recorded worker cgroup generation is unavailable".into());
    }
    Ok(())
}

fn owner(pid: u32, uid: u32, group: &Group) -> Result<Owner> {
    let kind = Kind::peer(uid)?;
    if pid == 0 || group.1 != kind {
        return Err("invalid resource owner".into());
    }
    let path = format!("/proc/{pid}");
    let before = start_ticks(&safe_text(&Path::new(&path).join("stat"), 4096)?)?;
    if safe_text(&Path::new(&path).join("cgroup"), 4096)? != format!("0::{}\n", kind.leaf())
        || fs::metadata(&path)?.uid() != uid
    {
        return Err("peer is not in the fixed isolated worker unit".into());
    }
    if kind == Kind::Acquisition
        && safe_text(&Path::new(&path).join("attr/current"), 128)? != "luma-acquisition (enforce)\n"
    {
        return Err("acquisition peer confinement is not enforcing".into());
    }
    let boot = boot_identity()?;
    let (device, inode) = group.identity()?;
    if start_ticks(&safe_text(&Path::new(&path).join("stat"), 4096)?)? != before {
        return Err("resource owner changed during observation".into());
    }
    let limits = safe_text(&Path::new(&path).join("limits"), 8192)?;
    let locked = limits
        .lines()
        .find(|line| line.starts_with("Max locked memory"))
        .ok_or("missing pinned-memory ceiling")?;
    let fields: Vec<_> = locked.split_whitespace().collect();
    if fields.len() != 6 || fields[3] != "0" || fields[4] != "0" || fields[5] != "bytes" {
        return Err("CPU worker pinned memory is not disabled".into());
    }
    Ok(Owner {
        uid,
        pid,
        start_ticks: before,
        boot,
        cgroup_device: device,
        cgroup_inode: inode,
    })
}

fn inventory() -> Result<BTreeMap<String, Domain>> {
    let total = model::memory(&safe_text(Path::new("/proc/meminfo"), 16_384)?, "MemTotal")?;
    // Fixed platform reserve, including manual controls, plus 20 percent of RAM.
    let reserve = protected_reserve(total);
    let enter = total
        .checked_sub(reserve / 4)
        .ok_or("insufficient protected RAM")?;
    let exit = total
        .checked_sub(reserve / 2)
        .ok_or("insufficient protected RAM")?;
    Ok(BTreeMap::from([
        (HOST.into(), Domain::new(total, reserve, enter, exit)?),
        (PIDS.into(), Domain::new(80, 0, 80, 64)?),
        (Kind::Model.domain().into(), Domain::new(1, 0, 1, 0)?),
        (Kind::Acquisition.domain().into(), Domain::new(1, 0, 1, 0)?),
    ]))
}

fn native_outstanding(ledger: &resources::Ledger) -> Result<()> {
    // A generic, structurally valid ledger is not necessarily implementable by
    // this native adapter. Never skip an unknown draining owner or underbudget
    // a restored worker. Released history stays intact for reviewed retention.
    for lease in ledger.leases.iter().filter(|l| l.state != State::Released) {
        let kind = Kind::peer(lease.owner.uid)?;
        let memory = match kind {
            Kind::Model => model::resource_binding_profile(&lease.binding)?.memory_limit(),
            Kind::Acquisition => {
                if lease.binding.len() != 64
                    || !lease
                        .binding
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("unsupported saved acquisition binding".into());
                }
                ACQUISITION_MEMORY
            }
        };
        if lease.reservations != reservation_plan(kind, memory) {
            return Err("saved resource plan differs from native enforcement policy".into());
        }
    }
    Ok(())
}

fn protected_reserve(total: u64) -> u64 {
    (total / 5).max(1024 * 1024 * 1024)
}

pub(crate) fn check_loading(total: u64, available: u64, peak: u64, owned: u64) -> Result<()> {
    let reserve = protected_reserve(total);
    if available > total || owned > peak || reserve >= total || peak > total - reserve {
        return Err("loading peak exceeds protected host domain".into());
    }
    let used = total - available;
    let unmanaged = used - used.min(owned);
    let needed = (peak - owned)
        .checked_add(reserve - reserve.min(unmanaged))
        .ok_or("loading reserve overflow")?;
    if available < needed {
        return Err("physical loading peak and protected reserve do not fit".into());
    }
    Ok(())
}

pub(crate) struct Manager {
    store: Store,
    group: Group,
    acquisition: Group,
    oom: u64,
    acquisition_oom: u64,
    owners: BTreeMap<String, File>,
    acquisition_bindings: BTreeMap<String, (model::Profile, String)>,
    requests: requests::Gate,
}

pub(crate) fn fence_unavailable() -> Result<()> {
    // Startup failure has no live manager object. Attempt both trusted fixed
    // groups without resetting state or claiming that any allocation drained.
    let results: Vec<_> = [Kind::Model, Kind::Acquisition]
        .into_iter()
        .map(|kind| {
            Group::for_kind(kind).and_then(|group| {
                let freeze = group.write("cgroup.freeze", "1");
                let kill = group.kill();
                freeze?;
                kill
            })
        })
        .collect();
    for result in results {
        result?;
    }
    Ok(())
}

impl Manager {
    pub(crate) fn fence_on_fault(&self) -> Result<()> {
        // These controls are opened relative to the already pinned worker slice.
        // Do not discover a replacement or infer that reservations are released.
        let results = [
            self.group.write("cgroup.freeze", "1"),
            self.group.kill(),
            self.acquisition.write("cgroup.freeze", "1"),
            self.acquisition.kill(),
        ];
        for result in results {
            result?;
        }
        Ok(())
    }

    pub(crate) fn open() -> Result<Self> {
        let group = Group::open()?;
        let acquisition = Group::for_kind(Kind::Acquisition)?;
        let mut store = Store::open(Path::new(resources::DIRECTORY))?;
        native_outstanding(&store.read()?)?;
        store.transact(|l| l.restart(resources::random_id()?, inventory()?))?;
        let requests = requests::Gate::open(&store)?;
        let oom = group.oom()?;
        let acquisition_oom = acquisition.oom()?;
        let mut manager = Self {
            store,
            group,
            acquisition,
            oom,
            acquisition_oom,
            owners: BTreeMap::new(),
            acquisition_bindings: BTreeMap::new(),
            requests,
        };
        manager.maintain()?;
        Ok(manager)
    }

    pub(crate) fn maintain(&mut self) -> Result<()> {
        let cancellations = self.requests.maintain(&self.store.read()?, now()?)?;
        self.requests.persist(&self.store, false)?;
        for token in cancellations {
            self.store
                .transact(|ledger| ledger.revoke(&token, "inference-request-fenced"))?;
        }
        for kind in [Kind::Model, Kind::Acquisition] {
            let group = match kind {
                Kind::Model => &self.group,
                Kind::Acquisition => &self.acquisition,
            };
            if Group::for_kind(kind)?.identity()? != group.identity()? {
                self.store
                    .transact(|l| l.quarantine(kind.domain(), "cgroup-replaced"))?;
                return Err("worker slice identity changed; preserve state".into());
            }
        }
        let ledger = self.store.read()?;
        native_outstanding(&ledger)?;
        let retained = self.retained(&ledger, None)?;
        let pids = number(&self.group.read("pids.current")?)?
            .checked_add(number(&self.acquisition.read("pids.current")?)?)
            .ok_or("worker process accounting overflow")?;
        let info = safe_text(Path::new("/proc/meminfo"), 16_384)?;
        let total = model::memory(&info, "MemTotal")?;
        let available = model::memory(&info, "MemAvailable")?;
        if available > total {
            return Err("invalid host RAM observation".into());
        }
        let oom = self.group.oom()?;
        let acquisition_oom = self.acquisition.oom()?;
        let time = now()?;
        self.store.observe(|l| {
            l.expire(time);
            if oom != self.oom {
                l.quarantine(Kind::Model.domain(), "worker-oom")?;
            }
            if acquisition_oom != self.acquisition_oom {
                l.quarantine(Kind::Acquisition.domain(), "worker-oom")?;
            }
            if total != l.domains[HOST].capacity {
                l.quarantine(HOST, "host-capacity-changed")?;
            }
            let reserve = l.domains[HOST].reserve;
            // The physical used observation includes OS usage, so subtract only
            // its configured reserve before the ledger adds that reserve once.
            let used = total - available;
            l.observe(HOST, used - used.min(reserve), retained)?;
            l.observe(PIDS, pids, 0)?;
            // These are execution-slot quotas, not additional physical bytes.
            // The ledger's charge is authoritative; an awaiting-admission
            // helper is not an already accepted execution slot.
            l.observe(Kind::Model.domain(), 0, 0)?;
            l.observe(Kind::Acquisition.domain(), 0, 0)?;
            if available < reserve / 4 {
                l.quarantine(HOST, "critical-host-pressure")?;
            }
            Ok(())
        })?;
        self.oom = oom;
        self.acquisition_oom = acquisition_oom;
        let ledger = self.store.read()?;
        let active: Vec<_> = ledger
            .leases
            .iter()
            .filter(|l| l.state == State::Active)
            .cloned()
            .collect();
        for lease in active {
            let kind = Kind::peer(lease.owner.uid)?;
            let group = match kind {
                Kind::Model => &self.group,
                Kind::Acquisition => &self.acquisition,
            };
            let live = owner(lease.owner.pid, lease.owner.uid, group);
            let pinned = self
                .owners
                .get(&lease.token.lease_id)
                .map_or(false, |fd| pidfd_alive(fd).unwrap_or(false));
            if !pinned || live.as_ref().map_or(true, |o| o != &lease.owner) {
                self.store
                    .transact(|l| l.revoke(&lease.token, "owner-lost"))?;
            } else {
                let (memory, storage, valid) = match kind {
                    Kind::Model => {
                        let profile = model::resource_binding_profile(&lease.binding)?;
                        (
                            profile.memory_limit(),
                            storage_device(Path::new("/var"))?,
                            model::resource_profile(&profile.id).is_ok(),
                        )
                    }
                    Kind::Acquisition => {
                        let (profile, device) = self
                            .acquisition_bindings
                            .get(&lease.token.lease_id)
                            .ok_or("missing acquisition generation binding")?;
                        (
                            ACQUISITION_MEMORY,
                            device.clone(),
                            acquisition_binding(profile, device)? == lease.binding,
                        )
                    }
                };
                if !valid
                    || number(&group.read("memory.max")?)? != memory
                    || group.leaf()?.verify_limits(memory, &storage).is_err()
                {
                    self.store
                        .transact(|l| l.quarantine(kind.domain(), "resource-enforcement-lost"))?;
                }
            }
        }
        for kind in [Kind::Model, Kind::Acquisition] {
            let ledger = self.store.read()?;
            let draining: Vec<_> = ledger
                .leases
                .iter()
                .filter(|l| {
                    l.state == State::Draining && Kind::peer(l.owner.uid).ok() == Some(kind)
                })
                .cloned()
                .collect();
            let boot = boot_identity()?;
            let group = match kind {
                Kind::Model => &self.group,
                Kind::Acquisition => &self.acquisition,
            };
            let identity = group.identity()?;
            if draining
                .iter()
                .any(|l| drainage_generation(&l.owner, &boot, identity).is_err())
            {
                self.store
                    .transact(|l| l.quarantine(kind.domain(), "cgroup-generation-lost"))?;
                return Err("old allocation generation cannot be observed; reboot required".into());
            }
            if !draining.is_empty() && group.populated()? {
                group.write("cgroup.freeze", "1")?;
                group.kill()?;
            }
            if !group.populated()? {
                let remaining = self.retained(&ledger, Some(kind))?;
                // File-cache charges can survive process exit. Keep them explicitly
                // accounted rather than equating cgroup emptiness with zero bytes.
                for lease in draining {
                    self.store.transact(|l| {
                        l.finish_draining(
                            &lease.token,
                            &BTreeMap::from([
                                (HOST.into(), remaining),
                                (PIDS.into(), 0),
                                (kind.domain().into(), 0),
                            ]),
                        )
                    })?;
                    self.owners.remove(&lease.token.lease_id);
                    self.acquisition_bindings.remove(&lease.token.lease_id);
                }
                group.write("cgroup.freeze", "0")?;
                let ledger = self.store.read()?;
                if (ledger.domains[HOST].pressure
                    || ledger.domains[kind.domain()].pressure
                    || kind == Kind::Acquisition && group.current()? > 0)
                    && ledger.leases.iter().all(|l| {
                        l.state == State::Released || Kind::peer(l.owner.uid).ok() != Some(kind)
                    })
                {
                    group.reclaim_idle()?;
                    let retained = self.retained(&ledger, None)?;
                    self.store
                        .observe(|l| l.observe(HOST, l.domains[HOST].observed, retained))?;
                }
            }
        }
        Ok(())
    }

    fn retained(&self, ledger: &resources::Ledger, drained: Option<Kind>) -> Result<u64> {
        let mut total = 0u64;
        for kind in [Kind::Model, Kind::Acquisition] {
            if drained == Some(kind)
                || ledger.leases.iter().all(|l| {
                    l.state == State::Released || Kind::peer(l.owner.uid).ok() != Some(kind)
                })
            {
                let group = match kind {
                    Kind::Model => &self.group,
                    Kind::Acquisition => &self.acquisition,
                };
                total = total
                    .checked_add(group.current()?)
                    .ok_or("retained cache accounting overflow")?;
            }
        }
        Ok(total)
    }

    pub(crate) fn handle(
        &mut self,
        r: &Request,
        peer: libc::ucred,
        pinned: Option<File>,
    ) -> Result<Response> {
        validate(r, peer.uid, now()?)?;
        if matches!(
            r.action.as_str(),
            "resource-request-status"
                | "resource-request-archive"
                | "resource-request-recovery-status"
                | "resource-request-recover"
        ) {
            crate::platform::require_installed()?;
            if peer.pid <= 0 || !pidfd_alive(pinned.as_ref().ok_or("missing history peer handle")?)?
            {
                return Err("request history maintenance requires live installed root".into());
            }
        }
        self.maintain()?;
        let time = now()?;
        validate(r, peer.uid, time)?;
        let mut token = None;
        let mut status = None;
        match r.action.as_str() {
            "resource-acquire" => {
                let pin = pinned.ok_or("missing kernel peer process handle")?;
                if !pidfd_alive(&pin)? {
                    return Err("resource peer has exited".into());
                }
                let kind = Kind::peer(peer.uid)?;
                let group = match kind {
                    Kind::Model => &self.group,
                    Kind::Acquisition => &self.acquisition,
                };
                let id = r.profile.as_deref().ok_or("missing resource profile")?;
                let (profile, memory, storage) = match kind {
                    Kind::Model => {
                        let profile = model::resource_profile(id)?;
                        let memory = profile.memory_limit();
                        (profile, memory, storage_device(Path::new("/var"))?)
                    }
                    Kind::Acquisition => (
                        model::profile(id)?,
                        ACQUISITION_MEMORY,
                        r.storage_device
                            .clone()
                            .ok_or("missing acquisition storage identity")?,
                    ),
                };
                let binding = match kind {
                    Kind::Model => profile.resource_binding()?,
                    Kind::Acquisition => acquisition_binding(&profile, &storage)?,
                };
                let owner = owner(peer.pid.try_into()?, peer.uid, group)?;
                if self.store.owner_retired(&owner)? {
                    return Err("resource owner belongs to a retired allocation generation".into());
                }
                group.leaf()?.verify_limits(memory, &storage)?;
                let ledger = self.store.read()?;
                if ledger.leases.iter().any(|l| {
                    l.state != State::Released && l.owner != owner && l.owner.uid == peer.uid
                }) {
                    return Err("worker cgroup has an outstanding allocation".into());
                }
                let available = model::memory(
                    &safe_text(Path::new("/proc/meminfo"), 16_384)?,
                    "MemAvailable",
                )?;
                let replay = ledger.leases.iter().any(|l| {
                    l.owner == owner && Some(l.request.as_str()) == r.idempotency_key.as_deref()
                });
                if !replay {
                    let processes = group.leaf()?.read("cgroup.procs")?;
                    let listed: Result<Vec<u64>> = processes.lines().map(number).collect();
                    if listed? != vec![u64::from(owner.pid)]
                        || number(&group.read("pids.current")?)? != 1
                    {
                        return Err("unleased processes or descendants occupy worker domain".into());
                    }
                    let current = group.current()?;
                    if current > memory {
                        return Err("retained worker charges exceed selected peak".into());
                    }
                    let total = ledger.domains[HOST].capacity;
                    check_loading(total, available, memory, current)?;
                    // The parent ceiling includes cache reparented from earlier
                    // worker cgroups. Leaf limits alone would miss those bytes.
                    group.write("memory.max", &memory.to_string())?;
                    if number(&group.read("memory.max")?)? != memory {
                        return Err("whole worker domain memory ceiling unavailable".into());
                    }
                }
                // Both loading and serving are bounded by the enforced full
                // worker ceiling. No shrink is inferred from reported readiness.
                let reservations = reservation_plan(kind, memory);
                let retained = self.retained(&ledger, None)?;
                let credit = if replay { 0 } else { group.current()? };
                token = Some(self.store.transact(|l| {
                    if !replay {
                        l.observe(HOST, l.domains[HOST].observed, retained)?;
                    }
                    l.admit_reusing_retained(
                        owner,
                        r.idempotency_key
                            .clone()
                            .ok_or("missing resource idempotency key")?,
                        binding,
                        reservations,
                        time,
                        time.checked_add(LEASE_MS)
                            .ok_or("lease deadline overflow")?,
                        &BTreeMap::from([(HOST.into(), credit)]),
                    )
                })?);
                let admitted = token.as_ref().ok_or("missing admitted resource token")?;
                self.owners.insert(admitted.lease_id.clone(), pin);
                if kind == Kind::Acquisition {
                    self.acquisition_bindings
                        .insert(admitted.lease_id.clone(), (profile, storage));
                }
            }
            "resource-renew" => {
                if !pidfd_alive(&pinned.ok_or("missing kernel peer process handle")?)? {
                    return Err("resource peer has exited".into());
                }
                let group = match Kind::peer(peer.uid)? {
                    Kind::Model => &self.group,
                    Kind::Acquisition => &self.acquisition,
                };
                let owner = owner(peer.pid.try_into()?, peer.uid, group)?;
                let t = r.lease.as_ref().ok_or("missing lease")?;
                self.store.transact(|l| {
                    l.renew(
                        t,
                        &owner,
                        time,
                        time.checked_add(LEASE_MS)
                            .ok_or("lease deadline overflow")?,
                    )
                })?;
                token = Some(t.clone());
            }
            "resource-revoke" => {
                self.store.transact(|l| {
                    l.revoke(r.lease.as_ref().ok_or("missing lease")?, "operator-revoked")
                })?;
                self.maintain()?;
                let ledger = self.store.read()?;
                let lease = ledger
                    .leases
                    .iter()
                    .find(|l| Some(&l.token) == r.lease.as_ref())
                    .ok_or("revoked resource receipt unavailable")?;
                status = Some(serde_json::json!({"state":lease.state,
                    "cleanup_complete":lease.state==State::Released,"domains":ledger.domains}));
            }
            "resource-reconcile" => {
                if self.group.populated()? || self.acquisition.populated()? {
                    return Err("worker descendants not drained".into());
                }
                self.store.transact(|l| {
                    l.clear_quarantine(r.review.as_deref().ok_or("missing review")?, inventory()?)
                })?;
            }
            "resource-status" => {
                let ledger = self.store.read()?;
                let outstanding:Vec<_>=ledger.leases.iter().filter(|l|l.state!=State::Released)
                    .map(|l|serde_json::json!({"lease":l.token,"owner":l.owner,"state":l.state,"reason":l.reason})).collect();
                if outstanding.len() > 16 {
                    return Err("resource status exceeds supported worker inventory".into());
                }
                status = Some(
                    serde_json::json!({"review":ledger.review()?,"domains":ledger.domains,
                    "generation":ledger.generation.to_string(),"active":ledger.leases.iter().filter(|l|l.state==State::Active).count(),
                    "draining":ledger.leases.iter().filter(|l|l.state==State::Draining).count(),
                    "receipts":ledger.leases.len(),"archives":ledger.archives,"outstanding":outstanding,
                    "workers":{"model_populated":self.group.populated()?,"acquisition_populated":self.acquisition.populated()?,
                        "acquisition_retained_bytes":self.acquisition.current()?.to_string()}}),
                );
            }
            "resource-archive" => {
                if self.group.populated()?
                    || self.acquisition.populated()?
                    || !self.owners.is_empty()
                    || self.requests.occupied()
                {
                    return Err("resource archival requires an observed empty worker domain".into());
                }
                let reference = self.store.archive(
                    r.review.as_deref().ok_or("missing review")?,
                    resources::random_id()?,
                )?;
                status = Some(serde_json::json!({"archive":reference,"generation_preserved":true}));
            }
            "resource-request-status" => {
                self.requests.persist(&self.store, true)?;
                status = Some(self.requests.retention_status(&self.store)?);
            }
            "resource-request-archive" => {
                status = Some(
                    self.requests.archive_requests(
                        &self.store,
                        r.review
                            .as_deref()
                            .ok_or("missing request archive review")?,
                    )?,
                );
            }
            "resource-request-recovery-status" | "resource-request-recover" => {
                crate::platform::require_installed()?;
                let pin = pinned.ok_or("missing history maintenance peer handle")?;
                if !pidfd_alive(&pin)?
                    || self.group.populated()?
                    || self.acquisition.populated()?
                    || !self.owners.is_empty()
                {
                    return Err(
                        "request recovery requires live root and drained worker groups".into(),
                    );
                }
                self.requests.persist(&self.store, true)?;
                status = Some(if r.action == "resource-request-recover" {
                    self.requests.recover_stage_checked(
                        &self.store,
                        r.review.as_deref().ok_or("missing recovery review")?,
                        || {
                            if !pidfd_alive(&pin)? || self.group.populated()? || self.acquisition.populated()?
                                || Group::open()?.identity()? != self.group.identity()?
                                || Group::for_kind(Kind::Acquisition)?.identity()? != self.acquisition.identity()?
                                || now()? >= r.deadline
                            {
                                return Err("request stage recovery lost peer, deadline or empty worker identity".into());
                            }
                            Ok(())
                        },
                    )?
                } else {
                    self.requests.stage_recovery_status(&self.store)?
                });
            }
            _ => return Err("unsupported resource operation".into()),
        }
        if now()? >= r.deadline {
            return Err("resource response deadline expired".into());
        }
        Ok(Response {
            schema_version: 1,
            request_id: r.request_id.clone(),
            caller: peer.uid,
            result: "ok".into(),
            lease: token,
            status,
        })
    }
}

pub(crate) fn pidfd_alive(fd: &File) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err("unverifiable resource process handle".into());
    }
    Ok(result == 0)
}

fn validate(r: &Request, uid: u32, time: u64) -> Result<()> {
    if r.schema_version != 1
        || r.caller != uid
        || r.request_id.is_empty()
        || r.request_id.len() > 64
        || !r
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || r.deadline <= time
        || r.deadline - time > 5000
    {
        return Err("resource envelope denied".into());
    }
    let allowed = match r.action.as_str() {
        "resource-acquire" => {
            (uid == 989 && r.storage_device.is_none()
                || uid == 0 && r.storage_device.as_deref().map_or(false, valid_storage))
                && r.profile.is_some()
                && r.lease.is_none()
                && r.review.is_none()
                && r.idempotency_key.as_ref().map_or(false, |key| {
                    !key.is_empty()
                        && key.len() <= 64
                        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
        "resource-renew" => {
            (uid == 989 || uid == 0)
                && r.profile.is_none()
                && r.storage_device.is_none()
                && r.lease.is_some()
                && r.review.is_none()
                && r.idempotency_key.is_none()
        }
        "resource-revoke" => {
            uid == 0
                && r.profile.is_none()
                && r.storage_device.is_none()
                && r.lease.is_some()
                && r.review.is_none()
                && r.idempotency_key.is_none()
        }
        "resource-reconcile"
        | "resource-archive"
        | "resource-request-archive"
        | "resource-request-recover" => {
            uid == 0
                && r.profile.is_none()
                && r.storage_device.is_none()
                && r.lease.is_none()
                && r.review.is_some()
                && r.idempotency_key.is_none()
        }
        "resource-status" | "resource-request-status" | "resource-request-recovery-status" => {
            uid == 0
                && r.profile.is_none()
                && r.storage_device.is_none()
                && r.lease.is_none()
                && r.review.is_none()
                && r.idempotency_key.is_none()
        }
        _ => false,
    };
    if !allowed {
        return Err("resource method or peer denied".into());
    }
    Ok(())
}

pub(crate) struct WorkerLease {
    token: Token,
    heartbeat: Heartbeat,
}

struct Heartbeat {
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
    deadline: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

pub(super) fn request(action: &str) -> Result<Request> {
    Ok(Request {
        schema_version: 1,
        request_id: resources::random_id()?,
        caller: unsafe { libc::geteuid() },
        deadline: now()?
            .checked_add(4000)
            .ok_or("resource envelope deadline overflow")?,
        action: action.into(),
        idempotency_key: None,
        profile: None,
        lease: None,
        review: None,
        storage_device: None,
    })
}

impl WorkerLease {
    pub(crate) fn acquire(profile: &str) -> Result<Self> {
        Self::acquire_with_storage(profile, None)
    }
    pub(crate) fn acquire_acquisition(profile: &str, target: &Path) -> Result<Self> {
        Self::acquire_with_storage(profile, Some(storage_device(target)?))
    }
    fn acquire_with_storage(profile: &str, storage: Option<String>) -> Result<Self> {
        let mut r = request("resource-acquire")?;
        r.storage_device = storage;
        r.profile = Some(profile.into());
        r.idempotency_key = Some(r.request_id.clone());
        let response = crate::service::resource_exchange(&r)?;
        if response.status.is_some() {
            return Err("unexpected resource admission response".into());
        }
        let token = response
            .lease
            .ok_or("resource admission supplied no lease")?;
        if token.generation == 0
            || token.lease_id.len() != 32
            || token.manager_epoch.len() != 32
            || !token
                .lease_id
                .bytes()
                .chain(token.manager_epoch.bytes())
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid resource fencing token".into());
        }
        let heartbeat_token = token.clone();
        let initial_deadline = r
            .deadline
            .checked_sub(4000)
            .and_then(|t| t.checked_add(LEASE_MS))
            .ok_or("initial resource deadline overflow")?;
        let heartbeat = Heartbeat::start_with_deadline(
            std::time::Duration::from_secs(2),
            initial_deadline,
            move || renew_token(&heartbeat_token),
        )?;
        Ok(Self { token, heartbeat })
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.heartbeat.check()?;
        renew_token(&self.token)
    }
    pub(crate) fn check_local(&self) -> Result<()> {
        self.heartbeat.check()
    }
}

impl Heartbeat {
    #[cfg(test)]
    fn start(
        cadence: std::time::Duration,
        renew: impl Fn() -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        let deadline = now()?
            .checked_add(LEASE_MS)
            .ok_or("heartbeat deadline overflow")?;
        Self::start_with_deadline(cadence, deadline, renew)
    }
    fn start_with_deadline(
        cadence: std::time::Duration,
        initial_deadline: u64,
        renew: impl Fn() -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        if cadence.is_zero() || cadence > std::time::Duration::from_millis(LEASE_MS / 2) {
            return Err("invalid resource heartbeat cadence".into());
        }
        let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        if now()? >= initial_deadline {
            return Err("initial lease already expired".into());
        }
        let deadline = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(initial_deadline));
        let heartbeat_deadline = std::sync::Arc::clone(&deadline);
        let stop = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let heartbeat_failed = std::sync::Arc::clone(&failed);
        let heartbeat_stop = std::sync::Arc::clone(&stop);
        let heartbeat = std::thread::Builder::new()
            .name("luma-resource-lease".into())
            .spawn(move || loop {
                let (mutex, wake) = &*heartbeat_stop;
                let stopped = match mutex.lock() {
                    Ok(value) => value,
                    Err(_) => {
                        heartbeat_failed.store(true, std::sync::atomic::Ordering::Release);
                        return;
                    }
                };
                let waited = wake.wait_timeout_while(stopped, cadence, |stopped| !*stopped);
                let stopped = match waited {
                    Ok((value, _)) => value,
                    Err(_) => {
                        heartbeat_failed.store(true, std::sync::atomic::Ordering::Release);
                        return;
                    }
                };
                if *stopped {
                    return;
                }
                drop(stopped);
                if heartbeat_failed.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                let attempt = now().and_then(|t| {
                    t.checked_add(LEASE_MS)
                        .ok_or("heartbeat deadline overflow".into())
                });
                let until = match attempt {
                    Ok(until) => until,
                    Err(_) => {
                        heartbeat_failed.store(true, std::sync::atomic::Ordering::Release);
                        return;
                    }
                };
                if renew().is_err() || now().map_or(true, |t| t >= until) {
                    heartbeat_failed.store(true, std::sync::atomic::Ordering::Release);
                    return;
                }
                heartbeat_deadline.store(until, std::sync::atomic::Ordering::Release);
            })?;
        Ok(Self {
            failed,
            stop,
            thread: Some(heartbeat),
            deadline,
        })
    }
    fn check(&self) -> Result<()> {
        if now().map_or(true, |t| {
            t >= self.deadline.load(std::sync::atomic::Ordering::Acquire)
        }) || self.failed.load(std::sync::atomic::Ordering::Acquire)
            || self
                .thread
                .as_ref()
                .map_or(true, |heartbeat| heartbeat.is_finished())
        {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
            return Err("resource heartbeat failed; execution fenced".into());
        }
        Ok(())
    }
}

fn renew_token(token: &Token) -> Result<()> {
    let mut r = request("resource-renew")?;
    r.lease = Some(token.clone());
    let response = crate::service::resource_exchange(&r)?;
    if response.status.is_some() || response.lease.as_ref() != Some(token) {
        return Err("resource lease acknowledgement substituted".into());
    }
    Ok(())
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        let (mutex, wake) = &*self.stop;
        match mutex.lock() {
            Ok(mut stop) => {
                *stop = true;
                wake.notify_all();
            }
            Err(error) => {
                *error.into_inner() = true;
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                wake.notify_all();
            }
        }
        if let Some(heartbeat) = self.thread.take() {
            let _ = heartbeat.join();
        }
        // No release request: process exit is not a physical drainage receipt.
        // The broker alone observes the whole cgroup before returning capacity.
    }
}

pub(crate) fn client(action: &str, argument: Option<&str>) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let mut r = request(action)?;
    match action {
        "resource-status" | "resource-request-status" | "resource-request-recovery-status"
            if argument.is_none() =>
        {
            ()
        }
        "resource-reconcile"
        | "resource-archive"
        | "resource-request-archive"
        | "resource-request-recover" => r.review = Some(argument.ok_or("missing review")?.into()),
        _ => return Err("unsupported resource maintenance operation".into()),
    }
    println!(
        "{}",
        serde_json::to_string(&crate::service::resource_exchange(&r)?)?
    );
    Ok(())
}

pub(crate) fn acquisition_status() -> Result<serde_json::Value> {
    let r = request("resource-status")?;
    crate::service::resource_exchange(&r)?
        .status
        .ok_or_else(|| "missing resource status".into())
}

pub(crate) fn revoke(id: &str, generation: &str, epoch: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let mut r = request("resource-revoke")?;
    if id.len() != 32
        || epoch.len() != 32
        || !id
            .bytes()
            .chain(epoch.bytes())
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid resource fencing token".into());
    }
    r.lease = Some(Token {
        lease_id: id.into(),
        generation: number(generation)?,
        manager_epoch: epoch.into(),
    });
    println!(
        "{}",
        serde_json::to_string(&crate::service::resource_exchange(&r)?)?
    );
    Ok(())
}

pub(crate) fn migrate() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let _idle = model::resource_idle()?;
    let group = Group::open()?;
    if group.populated()? || Group::for_kind(Kind::Acquisition)?.populated()? {
        return Err("model cgroup not idle; no resource migration".into());
    }
    resources::initialize(Path::new(resources::DIRECTORY))
}

pub(crate) fn initialize_live() -> Result<()> {
    crate::platform::require_live()?;
    let file = File::open("/var")?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 || stat.f_type != 0x01021994 {
        return Err("live resource initialization requires volatile tmpfs /var".into());
    }
    if Group::open()?.populated()? || Group::for_kind(Kind::Acquisition)?.populated()? {
        return Err("live resource domains are already populated".into());
    }
    // This explicit, live-only oneshot runs once per volatile filesystem.
    // initialize refuses an existing directory; broker restart never resets it.
    resources::initialize(Path::new(resources::DIRECTORY))
}

fn migration_store() -> Result<Store> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if Group::open()?.populated()? || Group::for_kind(Kind::Acquisition)?.populated()? {
        return Err("resource migration requires both worker slices empty".into());
    }
    // The lifetime ledger lock also requires the broker stopped. Existing
    // missing/damaged state is never initialized by the reviewed migration.
    Store::open(Path::new(resources::DIRECTORY))
}

pub(crate) fn migration_status() -> Result<()> {
    let store = migration_store()?;
    let ledger = store.read()?;
    println!(
        "{}",
        serde_json::json!({"review":ledger.review()?,"generation":ledger.generation.to_string(),
        "domains":ledger.domains,"proposed":inventory()?})
    );
    Ok(())
}

pub(crate) fn migrate_reviewed(review: &str) -> Result<()> {
    crate::require_root()?;
    let _idle = model::resource_idle()?;
    let mut store = migration_store()?;
    store.transact(|l| l.migrate_inventory(review, resources::random_id()?, inventory()?))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_deadline_fences_blocked_renewal_and_cannot_be_reenabled_by_late_ack() {
        let (started, received) = std::sync::mpsc::channel();
        let (resume, waiting) = std::sync::mpsc::channel();
        let waiting = std::sync::Mutex::new(waiting);
        let heartbeat = Heartbeat::start(std::time::Duration::from_millis(5), move || {
            started.send(()).map_err(|_| "heartbeat fixture closed")?;
            waiting
                .lock()
                .map_err(|_| "heartbeat fixture poisoned")?
                .recv_timeout(std::time::Duration::from_secs(2))
                .map_err(|_| "heartbeat fixture timed out")?;
            Ok(())
        })
        .unwrap();
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        heartbeat
            .deadline
            .store(0, std::sync::atomic::Ordering::Release);
        assert!(heartbeat.check().is_err());
        resume.send(()).unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !heartbeat.thread.as_ref().unwrap().is_finished() {
            assert!(std::time::Instant::now() < until);
            std::thread::yield_now();
        }
        assert!(
            heartbeat
                .deadline
                .load(std::sync::atomic::Ordering::Acquire)
                > 0
        );
        assert!(heartbeat.check().is_err());
        drop(heartbeat);
    }
    #[test]
    fn unsupported_saved_owners_plans_and_bindings_refuse_without_mutating_receipts() {
        let mut l = resources::Ledger::fresh_for_test();
        let gib = 1024 * 1024 * 1024;
        l.restart(
            "first-epoch".into(),
            BTreeMap::from([
                (
                    HOST.into(),
                    Domain::new(16 * gib, gib, 15 * gib, 14 * gib).unwrap(),
                ),
                (PIDS.into(), Domain::new(80, 0, 80, 64).unwrap()),
                (
                    Kind::Model.domain().into(),
                    Domain::new(1, 0, 1, 0).unwrap(),
                ),
                (
                    Kind::Acquisition.domain().into(),
                    Domain::new(1, 0, 1, 0).unwrap(),
                ),
            ]),
        )
        .unwrap();
        let owner = Owner {
            uid: 0,
            pid: 1,
            start_ticks: 1,
            boot: "boot-one".into(),
            cgroup_device: 1,
            cgroup_inode: 1,
        };
        l.admit(
            owner,
            "acquisition".into(),
            "a".repeat(64),
            reservation_plan(Kind::Acquisition, ACQUISITION_MEMORY),
            1,
            100,
        )
        .unwrap();
        native_outstanding(&l).unwrap();
        for draining in [false, true] {
            let mut changed = l.clone();
            if draining {
                changed.leases[0].state = State::Draining;
            }
            changed.leases[0].owner.uid = 990;
            let preserved = changed.clone();
            assert!(native_outstanding(&changed).is_err());
            assert_eq!(changed, preserved);
        }
        let mut changed = l.clone();
        changed.leases[0].reservations[0].loading -= 1;
        assert!(native_outstanding(&changed).is_err());
        changed = l.clone();
        changed.leases[0].binding = "A".repeat(64);
        assert!(native_outstanding(&changed).is_err());
        let p = model::profile("qwen3-1-7b-q4-k-m").unwrap();
        changed = l.clone();
        changed.leases[0].owner.uid = 989;
        changed.leases[0].binding = p.resource_binding().unwrap();
        changed.leases[0].reservations = reservation_plan(Kind::Model, p.memory_limit());
        native_outstanding(&changed).unwrap();
        changed.leases[0].binding = "b".repeat(64);
        assert!(native_outstanding(&changed).is_err());
        // Released receipts are preserved, not reinterpreted as executions.
        changed.leases[0].state = State::Released;
        native_outstanding(&changed).unwrap();
        assert_eq!(changed.leases.len(), 1);
        assert_eq!(changed.generation, l.generation);
    }

    #[test]
    fn acquisition_and_serving_share_physical_bytes_but_not_failure_slots() {
        let mut l = resources::Ledger::fresh_for_test();
        l.restart(
            "first-epoch".into(),
            BTreeMap::from([
                (HOST.into(), Domain::new(1000, 100, 950, 800).unwrap()),
                (PIDS.into(), Domain::new(80, 0, 80, 64).unwrap()),
                (
                    Kind::Model.domain().into(),
                    Domain::new(1, 0, 1, 0).unwrap(),
                ),
                (
                    Kind::Acquisition.domain().into(),
                    Domain::new(1, 0, 1, 0).unwrap(),
                ),
            ]),
        )
        .unwrap();
        let model_owner = Owner {
            uid: 989,
            pid: 1,
            start_ticks: 1,
            boot: "boot-one".into(),
            cgroup_device: 1,
            cgroup_inode: 1,
        };
        let acquisition_owner = Owner {
            uid: 0,
            pid: 2,
            cgroup_inode: 2,
            ..model_owner.clone()
        };
        let model = l
            .admit(
                model_owner.clone(),
                "model".into(),
                "a".repeat(64),
                reservation_plan(Kind::Model, 600),
                1,
                100,
            )
            .unwrap();
        let acquisition = l
            .admit(
                acquisition_owner,
                "acquisition".into(),
                "b".repeat(64),
                reservation_plan(Kind::Acquisition, 100),
                1,
                100,
            )
            .unwrap();
        assert_eq!(l.charged(HOST).unwrap(), 700);
        assert_eq!(l.charged(PIDS).unwrap(), 80);
        let before = l.clone();
        assert!(l
            .admit(
                model_owner.clone(),
                "extra".into(),
                "a".repeat(64),
                reservation_plan(Kind::Model, 1),
                1,
                100
            )
            .is_err());
        assert_eq!(l, before);
        l.quarantine(Kind::Acquisition.domain(), "acquisition-oom")
            .unwrap();
        l.assert_active(&model, &model_owner, 2).unwrap();
        assert_eq!(l.charged(HOST).unwrap(), 700);
        l.finish_draining(
            &acquisition,
            &BTreeMap::from([
                (HOST.into(), 20),
                (PIDS.into(), 0),
                (Kind::Acquisition.domain().into(), 0),
            ]),
        )
        .unwrap();
        assert_eq!(l.charged(HOST).unwrap(), 620);
        l.assert_active(&model, &model_owner, 2).unwrap();
    }

    #[test]
    fn acquisition_storage_is_canonical_and_cryptographically_bound_to_the_profile() {
        let p = model::profile("qwen3-4b-q4-k-m").unwrap();
        let b = acquisition_binding(&p, "253:0").unwrap();
        assert_ne!(b, acquisition_binding(&p, "253:1").unwrap());
        assert_ne!(b, p.resource_binding().unwrap());
        assert_ne!(
            b,
            acquisition_binding(&model::profile("qwen3-1-7b-q4-k-m").unwrap(), "253:0").unwrap()
        );
        for storage in [
            "0:1",
            "0253:0",
            "253:00",
            "253:-1",
            "253:0:1",
            "4294967296:0",
            "253:0\n",
        ] {
            assert!(acquisition_binding(&p, storage).is_err());
        }
        let mut r = request("resource-acquire").unwrap();
        r.caller = 0;
        r.profile = Some(p.id);
        r.idempotency_key = Some("fixed-request".into());
        assert!(validate(&r, 0, now().unwrap()).is_err());
        r.storage_device = Some("253:0".into());
        validate(&r, 0, now().unwrap()).unwrap();
        r.caller = 989;
        assert!(validate(&r, 989, now().unwrap()).is_err());
    }
    #[test]
    fn replacement_group_never_proves_same_boot_drainage_and_reboot_is_explicit() {
        let boot = boot_identity().unwrap();
        let prior = Owner {
            uid: 989,
            pid: 1,
            start_ticks: 1,
            boot: boot.clone(),
            cgroup_device: 2,
            cgroup_inode: 3,
        };
        drainage_generation(&prior, &boot, (2, 3)).unwrap();
        assert!(drainage_generation(&prior, &boot, (2, 4)).is_err());
        assert!(drainage_generation(&prior, &boot, (4, 3)).is_err());
        drainage_generation(&prior, "different-kernel-boot", (4, 5)).unwrap();
    }

    #[test]
    fn heartbeat_renews_during_loading_and_drop_interrupts_wait_without_release() {
        let (sent, received) = std::sync::mpsc::channel();
        let heartbeat = Heartbeat::start(std::time::Duration::from_millis(10), move || {
            sent.send(())
                .map_err(|_| "heartbeat observer disconnected")?;
            Ok(())
        })
        .unwrap();
        for _ in 0..3 {
            received
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            heartbeat.check().unwrap();
        }
        drop(heartbeat);
        while received.try_recv().is_ok() {}
        assert_eq!(
            received
                .recv_timeout(std::time::Duration::from_millis(50))
                .unwrap_err(),
            std::sync::mpsc::RecvTimeoutError::Disconnected
        );
        let heartbeat = Heartbeat::start(std::time::Duration::from_secs(5), || Ok(())).unwrap();
        let before = std::time::Instant::now();
        drop(heartbeat);
        assert!(before.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn heartbeat_refusal_panic_and_invalid_schedule_fence_execution() {
        assert!(Heartbeat::start(std::time::Duration::ZERO, || Ok(())).is_err());
        assert!(Heartbeat::start(std::time::Duration::from_secs(6), || Ok(())).is_err());
        for panic in [false, true] {
            let heartbeat = Heartbeat::start(std::time::Duration::from_millis(1), move || {
                assert!(!panic, "injected renewal panic");
                Err("injected generation refusal".into())
            })
            .unwrap();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while heartbeat.check().is_ok() && std::time::Instant::now() < until {
                std::thread::yield_now();
            }
            assert!(heartbeat.check().is_err());
        }
    }
    #[test]
    fn counters_and_process_generations_fail_closed() {
        for bad in ["", "max", "-1", "1.0", "1\n2", "18446744073709551616"] {
            assert!(number(bad).is_err());
        }
        assert_eq!(number("18446744073709551615\n").unwrap(), u64::MAX);
        assert!(fields("populated 0\npopulated 1\n").is_err());
        assert!(fields("populated 1 junk\n").is_err());
        assert!(start_ticks("1 (dead) Z 0").is_err());
        assert!(start_ticks("malformed").is_err());
        assert_eq!(
            start_ticks(&safe_text(Path::new("/proc/self/stat"), 4096).unwrap()).unwrap(),
            start_ticks(&safe_text(Path::new("/proc/self/stat"), 4096).unwrap()).unwrap()
        );
    }

    #[test]
    fn physical_loading_checks_preserve_reserve_and_do_not_count_owned_cache_twice() {
        let gib = 1024 * 1024 * 1024;
        check_loading(4 * gib, 3 * gib, 5 * gib / 2, 0).unwrap();
        assert!(check_loading(3 * gib, 2 * gib, 5 * gib / 2, 0).is_err());
        assert!(check_loading(4 * gib, gib, 5 * gib / 2, 0).is_err());
        check_loading(4 * gib, 2 * gib, 5 * gib / 2, gib).unwrap();
        assert!(check_loading(4 * gib, 5 * gib, 5 * gib / 2, 0).is_err());
        assert!(check_loading(4 * gib, 3 * gib, 5 * gib / 2, 3 * gib).is_err());
    }
    #[test]
    fn resource_protocol_limits_each_peer_to_its_exact_methods() {
        let mut r = Request {
            schema_version: 1,
            request_id: "one".into(),
            caller: 989,
            deadline: 110,
            action: "resource-acquire".into(),
            idempotency_key: Some("stable".into()),
            profile: Some("qwen3-4b-q4-k-m".into()),
            lease: None,
            review: None,
            storage_device: None,
        };
        validate(&r, 989, 100).unwrap();
        for uid in [0, 988, 990, 1000] {
            assert!(validate(&r, uid, 100).is_err());
        }
        r.deadline = 100;
        assert!(validate(&r, 989, 100).is_err());
        r.deadline = 5101;
        assert!(validate(&r, 989, 100).is_err());
        r.deadline = 110;
        r.review = Some("a".repeat(64));
        assert!(validate(&r, 989, 100).is_err());
        r.profile = None;
        r.idempotency_key = None;
        r.caller = 0;
        r.action = "resource-reconcile".into();
        validate(&r, 0, 100).unwrap();
        r.caller = 989;
        assert!(validate(&r, 989, 100).is_err());
        let mut value = serde_json::to_value(&r).unwrap();
        value["path"] = serde_json::json!("/sys/fs/cgroup");
        assert!(serde_json::from_value::<Request>(value).is_err());
    }

    #[test]
    fn io_limits_bind_the_actual_storage_device_and_reject_missing_or_unbounded_values() {
        verify_io(
            "253:0 rbps=67108864 wbps=67108864 riops=max wiops=max\n",
            "253:0",
        )
        .unwrap();
        for text in [
            "",
            "253:1 rbps=1 wbps=1",
            "253:0 rbps=max wbps=1",
            "253:0 rbps=1",
            "253:0 rbps=0 wbps=1",
            "253:0 rbps=1 wbps=67108865",
            "253:0 rbps=1 rbps=1 wbps=1",
            "253:0 rbps=1 wbps=1\n253:0 rbps=1 wbps=1",
        ] {
            assert!(verify_io(text, "253:0").is_err());
        }
    }
    #[test]
    fn boot_time_is_monotonic_and_real_cgroup_files_are_bounded() {
        assert!(now().unwrap() > 0);
        let before = now().unwrap();
        assert!(now().unwrap() >= before);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open("/sys/fs/cgroup")
            .unwrap();
        let group = Group(file, Kind::Model);
        let controllers = group.read("cgroup.controllers").unwrap();
        assert!(controllers.len() <= 4096);
        assert!(descriptor(&group.0, "../cgroup.kill", true, false).is_err());
        assert!(descriptor(&group.0, "", false, false).is_err());
    }
}
