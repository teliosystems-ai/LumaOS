//! Fixed cgroup-v2 policy controls. All paths and writable attributes are
//! compiled here. Descriptors pin the actual worker generation; neither a
//! plan nor an adapter name can request an arbitrary filesystem write.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const CGROUP_MAGIC: u64 = 0x63677270;
const MAX_MEMORY: u64 = 4_831_838_208;
const MAX_IO: u64 = 64 * 1024 * 1024;

pub(crate) struct Control {
    directory: File,
    worker: Worker,
    identity: (u64, u64),
    boot: String,
    profile: Option<crate::model::Profile>,
    storage: String,
    capability: String,
}

fn root(worker: Worker) -> &'static str {
    match worker {
        Worker::Model => "/sys/fs/cgroup/lumamodel.slice",
        Worker::Acquisition => "/sys/fs/cgroup/lumaacquisition.slice",
    }
}
fn canonical_number(text: &str) -> Result<u64> {
    let value = text.parse::<u64>()?;
    if value.to_string() != text {
        return Err("noncanonical cgroup number".into());
    }
    Ok(value)
}
fn line(text: &str) -> Result<&str> {
    text.strip_suffix('\n')
        .filter(|value| !value.contains('\n') && !value.contains('\r'))
        .ok_or_else(|| "cgroup attribute is not one canonical line".into())
}
fn number(text: &str) -> Result<u64> {
    canonical_number(line(text)?)
}
fn fixed_file(directory: &File, name: &str, write: bool) -> Result<File> {
    if !matches!(
        name,
        "cpu.max"
            | "cpu.weight"
            | "memory.max"
            | "memory.swap.max"
            | "memory.oom.group"
            | "pids.max"
            | "cgroup.controllers"
            | "cgroup.subtree_control"
            | "cgroup.events"
            | "io.max"
    ) {
        return Err("attribute is not in the compiled hardware adapter".into());
    }
    let name = std::ffi::CString::new(name)?;
    let flags = (if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    }) | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || unsafe { libc::fstatfs(fd, &mut filesystem) } != 0
        || filesystem.f_type as u64 != CGROUP_MAGIC
    {
        return Err("hardware control is not a protected cgroup-v2 attribute".into());
    }
    Ok(file)
}
fn read(directory: &File, name: &str) -> Result<String> {
    let mut bytes = String::new();
    fixed_file(directory, name, false)?
        .take(8193)
        .read_to_string(&mut bytes)?;
    if bytes.len() > 8192 || bytes.contains('\0') {
        return Err("hardware cgroup observation exceeds its bound".into());
    }
    Ok(bytes)
}
fn cpu(text: &str) -> Result<Setting> {
    let parts = line(text)?.split(' ').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err("CPU quota is not the compiled fixed-period policy".into());
    }
    let setting = Setting::CpuQuota {
        quota_us: canonical_number(parts[0])?,
        period_us: canonical_number(parts[1])?,
    };
    setting.validate()?;
    Ok(setting)
}
fn storage(text: &str, device: &str) -> Result<Setting> {
    if text.is_empty() || !text.ends_with('\n') {
        return Err("whole-disk IO policy is absent or truncated".into());
    }
    let mut devices = std::collections::BTreeSet::new();
    let mut selected = None;
    for record in text.lines() {
        let mut parts = record.split(' ');
        let actual = parts.next().ok_or("IO policy device absent")?;
        let mut fields = BTreeMap::new();
        if !devices.insert(actual) {
            return Err("duplicate IO policy device".into());
        }
        for part in parts {
            let (key, value) = part.split_once('=').ok_or("malformed IO policy")?;
            if !matches!(key, "rbps" | "wbps" | "riops" | "wiops")
                || fields.insert(key, value).is_some()
                || (value != "max" && canonical_number(value).is_err())
            {
                return Err("unknown or duplicate IO policy field".into());
            }
        }
        if fields.len() != 4 {
            return Err("incomplete IO policy record".into());
        }
        if actual == device {
            // This adapter deliberately cannot alter IOPS or other devices.
            // Non-default IOPS need a different qualified policy contract.
            if fields["riops"] != "max" || fields["wiops"] != "max" {
                return Err("whole-disk adapter cannot assume another IOPS policy".into());
            }
            let setting = Setting::StorageRate {
                device: device.into(),
                read_bytes_per_second: canonical_number(fields["rbps"])?,
                write_bytes_per_second: canonical_number(fields["wbps"])?,
            };
            setting.validate()?;
            selected = Some(setting);
        }
    }
    selected.ok_or_else(|| "exact native whole-disk IO ceiling is not installed".into())
}

impl Control {
    pub(crate) fn open(worker: Worker) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root(worker))?;
        let metadata = directory.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type as u64 != CGROUP_MAGIC
        {
            return Err("fixed worker is not a protected kernel cgroup-v2 directory".into());
        }
        let boot = current_boot()?;
        let profile = if worker == Worker::Model {
            Some(crate::model::selected_resource_profile()?)
        } else {
            None
        };
        let storage = crate::storage_io::device_for_path(Path::new("/var"))?;
        let capability = Self::capability(&directory, worker, profile.as_ref(), &storage)?;
        let control = Self {
            identity: (metadata.dev(), metadata.ino()),
            directory,
            worker,
            boot,
            profile,
            storage,
            capability,
        };
        control.check()?;
        Ok(control)
    }

    fn capability(
        directory: &File,
        worker: Worker,
        profile: Option<&crate::model::Profile>,
        storage: &str,
    ) -> Result<String> {
        let controllers = read(directory, "cgroup.controllers")?;
        let subtree = read(directory, "cgroup.subtree_control")?;
        let swap = number(&read(directory, "memory.swap.max")?)?;
        let oom = number(&read(directory, "memory.oom.group")?)?;
        let tasks = number(&read(directory, "pids.max")?)?;
        if swap != 0
            || oom > 1
            || match worker {
                Worker::Model => tasks != 64,
                Worker::Acquisition => ![4, 16, 32, 64].contains(&tasks),
            }
        {
            return Err("fixed worker non-policy safety limits are not enforced".into());
        }
        for required in ["cpu", "memory", "io", "pids"] {
            if !controllers
                .split_whitespace()
                .any(|value| value == required)
                || !subtree.split_whitespace().any(|value| value == required)
            {
                return Err("required fixed worker controller is not enabled".into());
            }
        }
        hash(&(
            "luma-native-cgroup-capability-v1",
            worker,
            controllers,
            subtree,
            swap,
            oom,
            tasks,
            storage,
            profile.map(|value| value.resource_binding()).transpose()?,
            fs::read_to_string("/proc/sys/kernel/osrelease")?,
        ))
    }

    pub(crate) fn check(&self) -> Result<()> {
        let current = fs::symlink_metadata(root(self.worker))?;
        if current.dev() != self.identity.0
            || current.ino() != self.identity.1
            || !current.is_dir()
            || current.uid() != 0
            || current.mode() & 0o022 != 0
            || current_boot()? != self.boot
            || Self::capability(
                &self.directory,
                self.worker,
                self.profile.as_ref(),
                &self.storage,
            )? != self.capability
            || crate::storage_io::device_for_path(Path::new("/var"))? != self.storage
        {
            return Err(
                "fixed worker device, capability, storage or boot generation changed".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn target(&self, adapter: Adapter, resource: ResourceBinding) -> Result<Target> {
        if !matches!(
            adapter,
            Adapter::CpuQuota | Adapter::CpuWeight | Adapter::MemoryProfile | Adapter::StorageRate
        ) {
            return Err("adapter is not a fixed cgroup scalar controller".into());
        }
        self.check()?;
        let target = Target {
            adapter,
            worker: Some(self.worker),
            identity_sha256: handoff::worker_identity(self.worker)?,
            capability_sha256: self.capability.clone(),
            adapter_sha256: hash(&(
                "luma-native-cgroup-adapter-source-v1",
                adapter.id(),
                include_bytes!("cgroup.rs").as_slice(),
            ))?,
            boot: self.boot.clone(),
            generation: self.identity.1,
            resource: Some(resource),
        };
        target.validate()?;
        Ok(target)
    }

    /// Pins only the compiled parent directory. The network adapter must add
    /// its own daemon/filter capability proof and cannot choose another path.
    pub(super) fn network_base(&self, resource: ResourceBinding) -> Result<Target> {
        let mut target = self.target(Adapter::CpuWeight, resource)?;
        target.adapter = Adapter::WorkerNetwork;
        target.validate()?;
        Ok(target)
    }
    pub(super) fn descriptor(&self) -> &File {
        &self.directory
    }
    pub(super) fn worker(&self) -> Worker {
        self.worker
    }

    pub(crate) fn observe(&self, adapter: Adapter) -> Result<Setting> {
        self.check()?;
        let setting = match adapter {
            Adapter::CpuQuota => cpu(&read(&self.directory, "cpu.max")?)?,
            Adapter::CpuWeight => Setting::CpuWeight {
                weight: number(&read(&self.directory, "cpu.weight")?)?,
            },
            Adapter::MemoryProfile => {
                let profile = self
                    .profile
                    .as_ref()
                    .ok_or("only the drained admitted model has a memory profile")?;
                Setting::MemoryProfile {
                    profile: profile.id.clone(),
                    bytes: number(&read(&self.directory, "memory.max")?)?,
                }
            }
            Adapter::StorageRate => storage(&read(&self.directory, "io.max")?, &self.storage)?,
            _ => return Err("adapter is not a fixed cgroup scalar controller".into()),
        };
        setting.validate()?;
        Ok(setting)
    }

    pub(super) fn drained(&self) -> Result<()> {
        let text = read(&self.directory, "cgroup.events")?;
        let mut seen = false;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("populated ") {
                if seen || value != "0" {
                    return Err("memory controller requires actual complete worker drainage".into());
                }
                seen = true;
            }
        }
        if !seen {
            return Err("worker drainage observation is unavailable".into());
        }
        Ok(())
    }

    /// Called only inside HardwareSession::dispatch or current-NV cleanup,
    /// with the original live Manager handoff checked on both sides. No grant
    /// is reconstructed here and no target or setting is supplied by a model.
    pub(crate) fn compare_write(
        &self,
        transition: &Transition,
        write: WriteKind,
        handoff: &crate::service::hardware::Handoff,
    ) -> Result<Observation> {
        let intent = &transition.intent;
        intent.validate()?;
        let resource = intent
            .target
            .resource
            .clone()
            .ok_or("worker resource binding absent")?;
        if self.target(intent.target.adapter, resource)? != intent.target {
            return Err("committed policy substitutes the actual fixed worker capability".into());
        }
        let check_handoff = || match write {
            WriteKind::Apply => handoff.check(intent),
            WriteKind::Restore => handoff.check_restore(intent),
        };
        check_handoff()?;
        let (expected, replacement) = match write {
            WriteKind::Apply => (&intent.before, &intent.after),
            WriteKind::Restore => (&intent.after, &intent.before),
        };
        let actual = self.observe(intent.target.adapter)?;
        if write == WriteKind::Restore
            && transition.phase == Phase::Prepared
            && actual == intent.before
        {
            check_handoff()?;
            return Ok(Observation {
                target: intent.target.clone(),
                setting: actual,
                observed_ms: crate::resource_manager::now()?,
                enforcement_sha256: hash(&(
                    "luma-native-cgroup-prepared-baseline-observed-no-write-v1",
                    &intent.target,
                    &intent.before,
                ))?,
            });
        }
        if actual != *expected {
            return Err("hardware policy observed external drift; exact undo is fenced".into());
        }
        let (attribute, command) = match replacement {
            Setting::CpuQuota {
                quota_us,
                period_us,
            } => ("cpu.max", format!("{quota_us} {period_us}")),
            Setting::CpuWeight { weight } => ("cpu.weight", weight.to_string()),
            Setting::MemoryProfile { profile, bytes } => {
                self.drained()?;
                let selected = self
                    .profile
                    .as_ref()
                    .ok_or("memory selection is not the admitted model")?;
                if profile != &selected.id
                    || *bytes < selected.memory_limit()
                    || *bytes > MAX_MEMORY
                    || (write == WriteKind::Apply && *bytes != selected.memory_limit())
                {
                    return Err("memory policy cannot select weights or expand current admitted profile authority".into());
                }
                ("memory.max", bytes.to_string())
            }
            Setting::StorageRate {
                device,
                read_bytes_per_second,
                write_bytes_per_second,
            } => {
                if device != &self.storage
                    || *read_bytes_per_second > MAX_IO
                    || *write_bytes_per_second > MAX_IO
                {
                    return Err(
                        "IO policy substitutes its exact bounded native backing disk".into(),
                    );
                }
                (
                    "io.max",
                    format!("{device} rbps={read_bytes_per_second} wbps={write_bytes_per_second}"),
                )
            }
            _ => return Err("setting is not owned by this fixed cgroup adapter".into()),
        };
        // One command and no retry. A short write/error/readback mismatch is
        // an outstanding committed physical obligation, never success.
        check_handoff()?;
        let mut control = fixed_file(&self.directory, attribute, true)?;
        if control.write(command.as_bytes())? != command.len() {
            return Err(
                "partial cgroup hardware command; preserve obligation and resource charges".into(),
            );
        }
        if self.observe(intent.target.adapter)? != *replacement {
            return Err(
                "cgroup hardware command did not read back exactly; do not redispatch".into(),
            );
        }
        if intent.target.adapter == Adapter::MemoryProfile {
            self.drained()?;
        }
        check_handoff()?;
        Ok(Observation {
            target: intent.target.clone(),
            setting: replacement.clone(),
            observed_ms: crate::resource_manager::now()?,
            enforcement_sha256: hash(&(
                "luma-native-cgroup-actual-readback-v1",
                &intent.target,
                replacement,
                attribute,
                &command,
            ))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_hardware_policy_is_fixed_period_bounded_and_not_an_arbitrary_command() {
        for valid in ["1000 100000\n", "200000 100000\n"] {
            cpu(valid).unwrap();
        }
        for invalid in [
            "max 100000\n",
            "0 100000\n",
            "200001 100000\n",
            "1 10\n",
            "01000 100000\n",
            "1000  100000\n",
            "1000 100000",
            "1000 100000\n1 1\n",
            "1000\t100000\n",
        ] {
            assert!(cpu(invalid).is_err(), "{invalid:?}");
        }
    }
    #[test]
    fn whole_disk_policy_rejects_ambiguous_unknown_or_unbounded_controls() {
        let valid = "8:0 rbps=67108864 wbps=1048576 riops=max wiops=max\n";
        let expected = Setting::StorageRate {
            device: "8:0".into(),
            read_bytes_per_second: MAX_IO,
            write_bytes_per_second: 1048576,
        };
        assert_eq!(storage(valid, "8:0").unwrap(), expected);
        for invalid in [
            valid.replace("67108864", "max"),
            valid.replace("67108864", "67108865"),
            valid.replace("riops=max", "riops=1"),
            valid.replace("wiops=max", "wiops=max other=1"),
            format!("{valid}{valid}"),
            valid.replace("rbps=67108864", "rbps=67108864 rbps=1"),
            valid.replace("1048576", "01048576"),
            valid.replace("8:0", "8:1"),
            valid.trim_end().into(),
            valid.replace(" wiops=max", ""),
        ] {
            assert!(storage(&invalid, "8:0").is_err(), "{invalid:?}");
        }
    }
}
