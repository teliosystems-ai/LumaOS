//! Resource authority inside the existing broker. Only the fixed CPU worker
//! cgroup is controllable; callers cannot select a cgroup, PID, device or budget.
use crate::{
    model,
    resources::{self, Domain, Owner, Reservation, State, Store, Token},
    Result,
};
use serde::{Deserialize, Serialize};
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

struct Group(File);
impl Group {
    fn open() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(CGROUP)?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let m = file.metadata()?;
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
            || stat.f_type != 0x63677270
            || m.uid() != 0
            || m.mode() & 0o022 != 0
        {
            return Err("trusted cgroup v2 worker slice unavailable".into());
        }
        Ok(Self(file))
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
        Ok(Self(descriptor(
            &self.0,
            "luma-model.service",
            false,
            true,
        )?))
    }
    fn verify_limits(&self, memory: u64) -> Result<()> {
        let limit = number(&self.read("memory.max")?)?;
        let tasks = number(&self.read("pids.max")?)?;
        if limit != memory
            || number(&self.read("memory.swap.max")?)? != 0
            || tasks == 0
            || tasks > 64
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
        let device = fs::metadata("/var")?.dev();
        // Pure extraction from the kernel-reported dev_t; no pointer access.
        let identity = unsafe { format!("{}:{}", libc::major(device), libc::minor(device)) };
        verify_io(&self.read("io.max")?, &identity)?;
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
    if pid == 0 || uid != 989 {
        return Err("invalid resource owner".into());
    }
    let path = format!("/proc/{pid}");
    let before = start_ticks(&safe_text(&Path::new(&path).join("stat"), 4096)?)?;
    if safe_text(&Path::new(&path).join("cgroup"), 4096)? != format!("0::{LEAF}\n")
        || fs::metadata(&path)?.uid() != uid
    {
        return Err("peer is not in the fixed isolated worker unit".into());
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
        (PIDS.into(), Domain::new(64, 0, 64, 48)?),
    ]))
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
    oom: u64,
    owners: BTreeMap<String, File>,
}

impl Manager {
    pub(crate) fn fence_on_fault(&self) -> Result<()> {
        // These controls are opened relative to the already pinned worker slice.
        // Do not discover a replacement or infer that reservations are released.
        let frozen = self.group.write("cgroup.freeze", "1");
        let killed = self.group.kill();
        killed?;
        frozen
    }

    pub(crate) fn open() -> Result<Self> {
        let group = Group::open()?;
        let mut store = Store::open(Path::new(resources::DIRECTORY))?;
        store.transact(|l| l.restart(resources::random_id()?, inventory()?))?;
        let oom = group.oom()?;
        let mut manager = Self {
            store,
            group,
            oom,
            owners: BTreeMap::new(),
        };
        manager.maintain()?;
        Ok(manager)
    }

    pub(crate) fn maintain(&mut self) -> Result<()> {
        if Group::open()?.identity()? != self.group.identity()? {
            self.store
                .transact(|l| l.quarantine(HOST, "cgroup-replaced"))?;
            return Err("worker slice identity changed; preserve state".into());
        }
        let current = self.group.current()?;
        let pids = number(&self.group.read("pids.current")?)?;
        let info = safe_text(Path::new("/proc/meminfo"), 16_384)?;
        let total = model::memory(&info, "MemTotal")?;
        let available = model::memory(&info, "MemAvailable")?;
        if available > total {
            return Err("invalid host RAM observation".into());
        }
        let oom = self.group.oom()?;
        let time = now()?;
        self.store.observe(|l| {
            l.expire(time);
            if oom != self.oom {
                l.quarantine(HOST, "worker-oom")?;
            }
            if total != l.domains[HOST].capacity {
                l.quarantine(HOST, "host-capacity-changed")?;
            }
            let reserve = l.domains[HOST].reserve;
            // The physical used observation includes OS usage, so subtract only
            // its configured reserve before the ledger adds that reserve once.
            let used = total - available;
            let outstanding = l.leases.iter().any(|lease| lease.state != State::Released);
            l.observe(
                HOST,
                used - used.min(reserve),
                if outstanding { 0 } else { current },
            )?;
            l.observe(PIDS, pids, 0)?;
            if available < reserve / 4 {
                l.quarantine(HOST, "critical-host-pressure")?;
            }
            Ok(())
        })?;
        self.oom = oom;
        let ledger = self.store.read()?;
        let active: Vec<_> = ledger
            .leases
            .iter()
            .filter(|l| l.state == State::Active)
            .cloned()
            .collect();
        for lease in active {
            let live = owner(lease.owner.pid, lease.owner.uid, &self.group);
            let pinned = self
                .owners
                .get(&lease.token.lease_id)
                .map_or(false, |fd| pidfd_alive(fd).unwrap_or(false));
            if !pinned || live.as_ref().map_or(true, |o| o != &lease.owner) {
                self.store
                    .transact(|l| l.revoke(&lease.token, "owner-lost"))?;
            } else {
                let profile = model::resource_binding_profile(&lease.binding)?;
                if model::resource_profile(&profile.id).is_err()
                    || number(&self.group.read("memory.max")?)? != profile.memory_limit()
                    || self
                        .group
                        .leaf()?
                        .verify_limits(profile.memory_limit())
                        .is_err()
                {
                    self.store
                        .transact(|l| l.quarantine(HOST, "resource-enforcement-lost"))?;
                }
            }
        }
        let ledger = self.store.read()?;
        let draining: Vec<_> = ledger
            .leases
            .iter()
            .filter(|l| l.state == State::Draining)
            .cloned()
            .collect();
        let boot = boot_identity()?;
        let identity = self.group.identity()?;
        if draining
            .iter()
            .any(|l| drainage_generation(&l.owner, &boot, identity).is_err())
        {
            self.store
                .transact(|l| l.quarantine(HOST, "cgroup-generation-lost"))?;
            return Err("old allocation generation cannot be observed; reboot required".into());
        }
        if !draining.is_empty() && self.group.populated()? {
            self.group.write("cgroup.freeze", "1")?;
            self.group.kill()?;
        }
        if !self.group.populated()? {
            let remaining = self.group.current()?;
            // File-cache charges can survive process exit. Keep them explicitly
            // accounted rather than equating cgroup emptiness with zero bytes.
            for lease in draining {
                self.store.transact(|l| {
                    l.finish_draining(
                        &lease.token,
                        &BTreeMap::from([(HOST.into(), remaining), (PIDS.into(), 0)]),
                    )
                })?;
                self.owners.remove(&lease.token.lease_id);
            }
            self.group.write("cgroup.freeze", "0")?;
            let ledger = self.store.read()?;
            if ledger.domains[HOST].pressure
                && ledger.leases.iter().all(|l| l.state == State::Released)
            {
                self.group.reclaim_idle()?;
                let retained = self.group.current()?;
                self.store
                    .observe(|l| l.observe(HOST, l.domains[HOST].observed, retained))?;
            }
        }
        Ok(())
    }

    pub(crate) fn handle(
        &mut self,
        r: &Request,
        peer: libc::ucred,
        pinned: Option<File>,
    ) -> Result<Response> {
        validate(r, peer.uid, now()?)?;
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
                let profile = model::resource_profile(
                    r.profile.as_deref().ok_or("missing resource profile")?,
                )?;
                let owner = owner(peer.pid.try_into()?, peer.uid, &self.group)?;
                if self.store.owner_retired(&owner)? {
                    return Err("resource owner belongs to a retired allocation generation".into());
                }
                self.group.leaf()?.verify_limits(profile.memory_limit())?;
                let ledger = self.store.read()?;
                if ledger
                    .leases
                    .iter()
                    .any(|l| l.state != State::Released && l.owner != owner)
                {
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
                    let processes = self.group.leaf()?.read("cgroup.procs")?;
                    let listed: Result<Vec<u64>> = processes.lines().map(number).collect();
                    if listed? != vec![u64::from(owner.pid)]
                        || number(&self.group.read("pids.current")?)? != 1
                    {
                        return Err("unleased processes or descendants occupy worker domain".into());
                    }
                    let current = self.group.current()?;
                    if current > profile.memory_limit() {
                        return Err("retained worker charges exceed selected peak".into());
                    }
                    let total = ledger.domains[HOST].capacity;
                    check_loading(total, available, profile.memory_limit(), current)?;
                    // The parent ceiling includes cache reparented from earlier
                    // worker cgroups. Leaf limits alone would miss those bytes.
                    self.group
                        .write("memory.max", &profile.memory_limit().to_string())?;
                    if number(&self.group.read("memory.max")?)? != profile.memory_limit() {
                        return Err("whole worker domain memory ceiling unavailable".into());
                    }
                }
                // Both loading and serving are bounded by the enforced full
                // worker ceiling. No shrink is inferred from reported readiness.
                let reservations = vec![
                    Reservation {
                        domain: HOST.into(),
                        loading: profile.memory_limit(),
                        serving: profile.memory_limit(),
                    },
                    Reservation {
                        domain: PIDS.into(),
                        loading: 64,
                        serving: 64,
                    },
                ];
                token = Some(self.store.transact(|l| {
                    if !replay {
                        let retained = self.group.current()?;
                        l.observe(HOST, l.domains[HOST].observed, retained)?;
                    }
                    let credit = l.domains[HOST].retained;
                    l.admit_reusing_retained(
                        owner,
                        r.idempotency_key
                            .clone()
                            .ok_or("missing resource idempotency key")?,
                        profile.resource_binding()?,
                        reservations,
                        time,
                        time.checked_add(LEASE_MS)
                            .ok_or("lease deadline overflow")?,
                        &BTreeMap::from([(HOST.into(), credit)]),
                    )
                })?);
                let admitted = token.as_ref().ok_or("missing admitted resource token")?;
                self.owners.insert(admitted.lease_id.clone(), pin);
            }
            "resource-renew" => {
                if !pidfd_alive(&pinned.ok_or("missing kernel peer process handle")?)? {
                    return Err("resource peer has exited".into());
                }
                let owner = owner(peer.pid.try_into()?, peer.uid, &self.group)?;
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
                if self.group.populated()? {
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
                    "receipts":ledger.leases.len(),"archives":ledger.archives,"outstanding":outstanding}),
                );
            }
            "resource-archive" => {
                if self.group.populated()? || !self.owners.is_empty() {
                    return Err("resource archival requires an observed empty worker domain".into());
                }
                let reference = self.store.archive(
                    r.review.as_deref().ok_or("missing review")?,
                    resources::random_id()?,
                )?;
                status = Some(serde_json::json!({"archive":reference,"generation_preserved":true}));
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
            uid == 989
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
            uid == 989
                && r.profile.is_none()
                && r.lease.is_some()
                && r.review.is_none()
                && r.idempotency_key.is_none()
        }
        "resource-revoke" => {
            uid == 0
                && r.profile.is_none()
                && r.lease.is_some()
                && r.review.is_none()
                && r.idempotency_key.is_none()
        }
        "resource-reconcile" | "resource-archive" => {
            uid == 0
                && r.profile.is_none()
                && r.lease.is_none()
                && r.review.is_some()
                && r.idempotency_key.is_none()
        }
        "resource-status" => {
            uid == 0
                && r.profile.is_none()
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
}

fn request(action: &str) -> Result<Request> {
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
    })
}

impl WorkerLease {
    pub(crate) fn acquire(profile: &str) -> Result<Self> {
        let mut r = request("resource-acquire")?;
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
        let heartbeat = Heartbeat::start(std::time::Duration::from_secs(2), move || {
            renew_token(&heartbeat_token)
        })?;
        Ok(Self { token, heartbeat })
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.heartbeat.check()?;
        renew_token(&self.token)
    }
}

impl Heartbeat {
    fn start(
        cadence: std::time::Duration,
        renew: impl Fn() -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        if cadence.is_zero() || cadence > std::time::Duration::from_millis(LEASE_MS / 2) {
            return Err("invalid resource heartbeat cadence".into());
        }
        let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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
                if renew().is_err() {
                    heartbeat_failed.store(true, std::sync::atomic::Ordering::Release);
                    return;
                }
            })?;
        Ok(Self {
            failed,
            stop,
            thread: Some(heartbeat),
        })
    }
    fn check(&self) -> Result<()> {
        if self.failed.load(std::sync::atomic::Ordering::Acquire)
            || self
                .thread
                .as_ref()
                .map_or(true, |heartbeat| heartbeat.is_finished())
        {
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
        "resource-status" if argument.is_none() => (),
        "resource-reconcile" | "resource-archive" => {
            r.review = Some(argument.ok_or("missing review")?.into())
        }
        _ => return Err("unsupported resource maintenance operation".into()),
    }
    println!(
        "{}",
        serde_json::to_string(&crate::service::resource_exchange(&r)?)?
    );
    Ok(())
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
    if group.populated()? {
        return Err("model cgroup not idle; no resource migration".into());
    }
    resources::initialize(Path::new(resources::DIRECTORY))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let group = Group(file);
        let controllers = group.read("cgroup.controllers").unwrap();
        assert!(controllers.len() <= 4096);
        assert!(descriptor(&group.0, "../cgroup.kill", true, false).is_err());
        assert!(descriptor(&group.0, "", false, false).is_err());
    }
}
