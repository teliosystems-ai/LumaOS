//! Fixed C/Index memory split. The durable Index lease reserves 512 MiB;
//! worker and C each have an independently observed 256 MiB hard ceiling.
//! Raising the C parent is possible only through Manager after real admission.
//! Lowering retains the whole lease until the worker drained and C returned
//! to its ordinary 128 MiB hard/current bound. No serialized token is authority.
use super::*;

pub(crate) const CUSTODY_LEAF: &str =
    "/system.slice/system-lumacustody.slice/luma-content-custody.service";
const PARENT: &str = "/sys/fs/cgroup/system.slice/system-lumacustody.slice";
const CHILD: &str = "luma-content-custody.service";
const BASE: u64 = 128 * 1024 * 1024;
pub(super) const INDEX_WORKER: u64 = 256 * 1024 * 1024;
const INDEX_C: u64 = 256 * 1024 * 1024;
fn cap_text(value: u64) -> Result<String> {
    if !matches!(value, BASE | INDEX_C) {
        return Err("unsupported C hard cap transition".into());
    }
    Ok(value.to_string())
}
fn drain_ready(cap: u64, current: u64, lowering: bool) -> Result<bool> {
    if cap != if lowering { BASE } else { INDEX_C } || current > cap {
        return Err("C retained memory drain changes its selected hard/current bound".into());
    }
    Ok(current <= BASE)
}

fn controls(mut read: impl FnMut(&str) -> Result<String>, cap: u64, child: bool) -> Result<u64> {
    if number(&read("memory.max")?)? != cap
        || number(&read("memory.swap.max")?)? != 0
        || number(&read("pids.max")?)? != 2
        || read("cpu.max")?.trim() != "25000 100000"
        || (child && number(&read("memory.oom.group")?)? != 1)
        || number(&read("pids.current")?)? > 2
    {
        return Err("fixed C parent/child resource enforcement differs".into());
    }
    let current = number(&read("memory.current")?)?;
    if current > cap {
        return Err("C actual charged memory exceeds its selected hard bound".into());
    }
    Ok(current)
}

struct HeldGroup {
    directory: File,
    path: std::path::PathBuf,
    identity: (u64, u64),
}
impl HeldGroup {
    fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = directory.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type != 0x63677270
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("C memory split requires the actual protected cgroup2 directory".into());
        }
        let result = Self {
            directory,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let named = fs::symlink_metadata(&self.path)?;
        let held = self.directory.metadata()?;
        if !named.is_dir()
            || named.uid() != 0
            || named.mode() & 0o022 != 0
            || (named.dev(), named.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
        {
            return Err("C memory enforcement namespace generation changed".into());
        }
        Ok(())
    }
    fn read(&self, name: &str) -> Result<String> {
        self.check()?;
        let file = self.control(name, false)?;
        let identity = file.metadata()?;
        let mut text = String::new();
        (&file).take(4097).read_to_string(&mut text)?;
        if text.len() > 4096 {
            return Err("C cgroup evidence exceeds fixed bound".into());
        }
        let named = self.control(name, false)?.metadata()?;
        if (identity.dev(), identity.ino()) != (named.dev(), named.ino()) {
            return Err("C kernel control file changed during held read".into());
        }
        self.check()?;
        Ok(text)
    }
    fn control(&self, name: &str, write: bool) -> Result<File> {
        let file = descriptor(&self.directory, name, write, false)?;
        let metadata = file.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type != 0x63677270
            || metadata.dev() != self.identity.0
        {
            return Err("C control file is not in the held actual kernel cgroup2 namespace".into());
        }
        Ok(file)
    }
    fn set_cap(&self, value: u64) -> Result<()> {
        let text = cap_text(value)?;
        self.check()?;
        let mut file = self.control("memory.max", true)?;
        let before = file.metadata()?;
        if file.write(text.as_bytes())? != text.len() {
            return Err("partial C hard cap command; retain full liability".into());
        }
        self.check()?;
        let named = self.control("memory.max", false)?.metadata()?;
        if (before.dev(), before.ino()) != (named.dev(), named.ino()) {
            return Err("C hard cap held control replaced; retain full liability".into());
        }
        if number(&self.read("memory.max")?)? != value {
            return Err("C hard cap readback differs; retain full liability".into());
        }
        Ok(())
    }
}

/// Only a retained original Manager generation can hold this nonserialized
/// allowance. After a restart an already raised parent refuses automatic use.
struct CProcess {
    pid: u32,
    start: u64,
    pin: File,
}
impl CProcess {
    fn capture(child: &HeldGroup) -> Result<Self> {
        let listed = child
            .read("cgroup.procs")?
            .lines()
            .map(number)
            .collect::<Result<Vec<_>>>()?;
        if listed.len() != 1 || listed[0] == 0 {
            return Err("Index requires one actual fixed C process before raising memory".into());
        }
        let pid: u32 = listed[0].try_into()?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pin = unsafe { File::from_raw_fd(fd.try_into()?) };
        let path = Path::new("/proc").join(pid.to_string());
        let start = peer::custody_generation(|name, maximum| safe_text(&path.join(name), maximum))?;
        let result = Self { pid, start, pin };
        result.check(child)?;
        Ok(result)
    }
    fn check(&self, child: &HeldGroup) -> Result<()> {
        if !pidfd_alive(&self.pin)?
            || child
                .read("cgroup.procs")?
                .lines()
                .map(number)
                .collect::<Result<Vec<_>>>()?
                != vec![u64::from(self.pid)]
        {
            return Err("C memory allowance process set changed".into());
        }
        let path = Path::new("/proc").join(self.pid.to_string());
        if peer::custody_generation(|name, maximum| safe_text(&path.join(name), maximum))?
            != self.start
            || !pidfd_alive(&self.pin)?
        {
            return Err("C memory allowance process generation changed".into());
        }
        Ok(())
    }
}
struct Charge {
    token: Token,
    child: (u64, u64),
    process: CProcess,
    lowering: bool,
}
pub(super) struct CustodyMemory {
    parent: HeldGroup,
    charge: Option<Charge>,
}
impl CustodyMemory {
    pub(super) fn open() -> Result<Self> {
        let result = Self {
            parent: HeldGroup::open(Path::new(PARENT))?,
            charge: None,
        };
        // Never adopt a pre-existing raised cap after manager restart. The
        // retained ledger is left intact for explicit governed reconciliation.
        result.baseline()?;
        Ok(result)
    }
    fn topology(&self) -> Result<Option<HeldGroup>> {
        self.parent.check()?;
        if !self.parent.read("cgroup.procs")?.trim().is_empty() {
            return Err("unattributed process occupies C parent slice".into());
        }
        let mut children = 0usize;
        for entry in fs::read_dir(&self.parent.path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("aliased C parent member".into());
            }
            if kind.is_dir() {
                if entry.file_name() != CHILD || children != 0 {
                    return Err("unknown child occupies C memory reservation".into());
                }
                children += 1;
            }
        }
        self.parent.check()?;
        let child = if children == 1 {
            Some(HeldGroup::open(&self.parent.path.join(CHILD))?)
        } else {
            None
        };
        if let Some(child) = &child {
            controls(|name| child.read(name), INDEX_C, true)?;
            // A child cgroup could otherwise hide memory/processes below the
            // fixed service name while still passing the aggregate counters.
            for entry in fs::read_dir(&child.path)? {
                let kind = entry?.file_type()?;
                if kind.is_dir() || kind.is_symlink() {
                    return Err("unexpected descendant under fixed C service".into());
                }
            }
            child.check()?;
        }
        Ok(child)
    }
    pub(super) fn baseline(&self) -> Result<()> {
        if self.charge.is_some() {
            return Err("ordinary C work cannot borrow an Index memory allowance".into());
        }
        self.topology()?;
        controls(|name| self.parent.read(name), BASE, false)?;
        Ok(())
    }
    fn admitted<'a>(
        ledger: &'a resources::Ledger,
        token: &Token,
        active: bool,
    ) -> Result<&'a resources::Lease> {
        let lease = ledger
            .leases
            .iter()
            .find(|l| &l.token == token)
            .ok_or("C split lost durable Index liability")?;
        if token.manager_epoch != ledger.manager_epoch
            || (active && lease.state != State::Active)
            || (!active && !matches!(lease.state, State::Active | State::Draining))
            || lease.owner.uid != 0
            || lease.output_fenced && active
            || lease.reservations
                != reservation_plan_for(
                    Kind::Acquisition,
                    ACQUISITION_MEMORY,
                    Kind::Acquisition.tasks(),
                )
            || active && lease.deadline_ms <= now()?
        {
            return Err("C split is not covered by the exact current full Index lease".into());
        }
        Ok(lease)
    }
    pub(super) fn begin(&mut self, ledger: &resources::Ledger, token: &Token) -> Result<()> {
        Self::admitted(ledger, token, true)?;
        self.baseline()?;
        let child = self
            .topology()?
            .ok_or("Index cannot raise memory for an absent C service")?;
        // Manager has already pinned the exact Index worker, source profile,
        // original principal and admitted this durable lease before this call.
        let process = CProcess::capture(&child)?;
        self.charge = Some(Charge {
            token: token.clone(),
            child: child.identity,
            process,
            lowering: false,
        });
        self.parent.set_cap(INDEX_C)?;
        self.check(ledger, token)
    }
    pub(super) fn owns(&self, token: &Token) -> bool {
        self.charge.as_ref().is_some_and(|c| &c.token == token)
    }
    pub(super) fn check(&self, ledger: &resources::Ledger, token: &Token) -> Result<()> {
        Self::admitted(ledger, token, true)?;
        let charge = self
            .charge
            .as_ref()
            .filter(|c| &c.token == token && !c.lowering)
            .ok_or("Index lacks its original C memory allowance")?;
        let child = self
            .topology()?
            .ok_or("C child generation disappeared during Index work")?;
        if child.identity != charge.child {
            return Err("C child was replaced during original Index generation".into());
        }
        charge.process.check(&child)?;
        controls(|name| self.parent.read(name), INDEX_C, false)?;
        Ok(())
    }
    /// Called only after Manager proves the exact worker group unpopulated.
    /// False retains the ENTIRE 512 MiB lease, not a guessed residual charge.
    pub(super) fn finish(
        &mut self,
        ledger: &resources::Ledger,
        token: &Token,
        worker: &Group,
    ) -> Result<bool> {
        let lease = Self::admitted(ledger, token, false)?;
        if worker.1 != Kind::Acquisition
            || worker.identity()? != (lease.owner.cgroup_device, lease.owner.cgroup_inode)
            || worker.populated()?
        {
            return Err("C allowance cannot drain before the exact retained worker group".into());
        }
        let charge = self
            .charge
            .as_ref()
            .filter(|c| &c.token == token)
            .ok_or("C drain lost original Index allowance")?;
        let child = self
            .topology()?
            .ok_or("C child generation cannot be observed for Index drain")?;
        if child.identity != charge.child {
            return Err("C child replaced before full Index drain".into());
        }
        charge.process.check(&child)?;
        let cap = if charge.lowering { BASE } else { INDEX_C };
        let current = controls(|name| self.parent.read(name), cap, false)?;
        if !drain_ready(cap, current, charge.lowering)? {
            return Ok(false);
        }
        // Record the attempted narrowing before writing. A failed/partial
        // narrowing never clears the retained charge or adopts a new cap.
        self.charge
            .as_mut()
            .ok_or("C drain allowance vanished")?
            .lowering = true;
        self.parent.set_cap(BASE)?;
        controls(|name| self.parent.read(name), BASE, false)?;
        if worker.populated()? {
            return Err("Index worker reappeared during C hard cap narrowing".into());
        }
        self.charge = None;
        self.baseline()?;
        Ok(true)
    }
    pub(super) fn maintain(&self, ledger: &resources::Ledger) -> Result<()> {
        if let Some(charge) = &self.charge {
            Self::admitted(ledger, &charge.token, false)?;
            let child = self
                .topology()?
                .ok_or("retained C memory child disappeared")?;
            if child.identity != charge.child {
                return Err("retained C memory child generation changed".into());
            }
            charge.process.check(&child)?;
            controls(
                |name| self.parent.read(name),
                if charge.lowering { BASE } else { INDEX_C },
                false,
            )?;
            Ok(())
        } else {
            self.baseline()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observed(cap: u64) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("memory.max", cap.to_string()),
            ("memory.swap.max", "0".into()),
            ("pids.max", "2".into()),
            ("pids.current", "1".into()),
            ("cpu.max", "25000 100000".into()),
            ("memory.oom.group", "1".into()),
            ("memory.current", "67108864".into()),
        ])
    }
    #[test]
    fn exact_closed_parent_and_child_caps_refuse_weakened_kernel_observations() {
        for cap in [BASE, INDEX_C] {
            let values = observed(cap);
            controls(|n| Ok(values[n].clone()), cap, true).unwrap();
            for (field, value) in [
                ("memory.max", "max"),
                ("memory.swap.max", "1"),
                ("pids.max", "3"),
                ("cpu.max", "50000 100000"),
                ("pids.current", "3"),
                ("memory.oom.group", "0"),
                ("memory.current", "536870912"),
            ] {
                let mut changed = values.clone();
                changed.insert(field, value.into());
                assert!(
                    controls(|n| Ok(changed[n].clone()), cap, true).is_err(),
                    "{field}"
                );
            }
        }
        assert!(controls(|n| Ok(observed(INDEX_C)[n].clone()), BASE, false).is_err());
        assert_eq!(INDEX_WORKER + INDEX_C, ACQUISITION_MEMORY);
    }
    #[test]
    fn ordinary_filesystem_cannot_impersonate_the_fixed_kernel_memory_controller() {
        assert!(HeldGroup::open(Path::new("/tmp")).is_err());
    }
    #[test]
    fn no_release_or_arbitrary_cap_from_retained_or_ambiguous_drain_data() {
        assert_eq!(cap_text(BASE).unwrap(), "134217728");
        assert_eq!(cap_text(INDEX_C).unwrap(), "268435456");
        for cap in [0, BASE - 1, BASE + 1, INDEX_C - 1, INDEX_C + 1, u64::MAX] {
            assert!(cap_text(cap).is_err());
        }
        assert!(!drain_ready(INDEX_C, BASE + 1, false).unwrap());
        assert!(!drain_ready(INDEX_C, INDEX_C, false).unwrap());
        assert!(drain_ready(INDEX_C, BASE, false).unwrap());
        assert!(drain_ready(BASE, BASE, true).unwrap());
        assert!(drain_ready(BASE, BASE + 1, true).is_err());
        assert!(drain_ready(BASE, 0, false).is_err());
        assert!(drain_ready(INDEX_C, 0, true).is_err());
    }
    fn lease_data() -> (resources::Ledger, Token) {
        let mut ledger = resources::Ledger::fresh_for_test();
        let gib = 1024 * 1024 * 1024;
        ledger
            .restart(
                "memory-fixture".into(),
                BTreeMap::from([
                    (
                        HOST.into(),
                        Domain::new(16 * gib, gib, 15 * gib, 14 * gib).unwrap(),
                    ),
                    (PIDS.into(), Domain::new(80, 0, 80, 64).unwrap()),
                    (
                        Kind::Acquisition.domain().into(),
                        Domain::new(1, 0, 1, 0).unwrap(),
                    ),
                ]),
            )
            .unwrap();
        let at = now().unwrap();
        let token = ledger
            .admit(
                Owner {
                    uid: 0,
                    pid: 1,
                    start_ticks: 1,
                    boot: "fixture-boot".into(),
                    cgroup_device: 1,
                    cgroup_inode: 1,
                },
                "memory-request".into(),
                "a".repeat(64),
                reservation_plan_for(
                    Kind::Acquisition,
                    ACQUISITION_MEMORY,
                    Kind::Acquisition.tasks(),
                ),
                at,
                at + 30_000,
            )
            .unwrap();
        (ledger, token)
    }
    #[test]
    fn exact_full_lease_data_required_no_epoch_generation_or_partial_plan_adoption() {
        // These are data-boundary tests, not installed original-client proofs.
        let (ledger, token) = lease_data();
        CustodyMemory::admitted(&ledger, &token, true).unwrap();
        for field in 0..7 {
            let mut changed = ledger.clone();
            match field {
                0 => changed.manager_epoch = "other-epoch".into(),
                1 => changed.leases[0].token.generation += 1,
                2 => changed.leases[0].owner.uid = 989,
                3 => changed.leases[0].reservations[0].loading -= 1,
                4 => changed.leases[0].reservations.pop().map(|_| ()).unwrap(),
                5 => changed.leases[0].deadline_ms = 1,
                6 => changed.leases[0].output_fenced = true,
                _ => unreachable!(),
            }
            assert!(
                CustodyMemory::admitted(&changed, &token, true).is_err(),
                "field {field}"
            );
        }
        let mut changed = ledger.clone();
        changed.revoke(&token, "fixture-revoked").unwrap();
        assert!(CustodyMemory::admitted(&changed, &token, true).is_err());
        CustodyMemory::admitted(&changed, &token, false).unwrap();
        changed
            .finish_draining(
                &token,
                &BTreeMap::from([
                    (HOST.into(), 0),
                    (PIDS.into(), 0),
                    (Kind::Acquisition.domain().into(), 0),
                ]),
            )
            .unwrap();
        assert!(CustodyMemory::admitted(&changed, &token, false).is_err());
    }
}
