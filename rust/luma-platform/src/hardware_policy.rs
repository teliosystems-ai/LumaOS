//! Typed hardware lifecycle reconstructed from the existing protected Admin
//! journal. Records describe committed obligations, never portable permission.
use crate::{finite_grants, resources, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const MAX_POLICIES: usize = 128;
pub(crate) const MAX_LIFETIME_MS: u64 = 20_000;
pub(crate) const CLEANUP_GRACE_MS: u64 = 5_000;

pub(crate) mod backlight;
pub(crate) mod cgroup;
pub(crate) mod console;
pub(crate) mod console_input;
pub(crate) mod daemon_observer;
pub(crate) mod exclusion;
pub(crate) mod handoff;
pub(crate) mod image;
pub(crate) mod network;
pub(crate) mod network_query;
pub(crate) mod power;
pub(crate) mod sd_bus;

pub(crate) fn current_boot() -> Result<String> {
    use std::io::Read;
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/sys/kernel/random/boot_id")?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x9fa0
    {
        return Err("hardware boot identity is not the actual kernel procfs source".into());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(65).read_to_end(&mut bytes)?;
    if bytes.len() != 37
        || bytes[36] != b'\n'
        || [8, 13, 18, 23]
            .into_iter()
            .any(|position| bytes[position] != b'-')
        || bytes[..36].iter().enumerate().any(|(position, byte)| {
            ![8, 13, 18, 23].contains(&position)
                && !(byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
    {
        return Err("hardware kernel boot identity is not canonical".into());
    }
    let value = bytes[..36]
        .iter()
        .filter(|byte| **byte != b'-')
        .map(|byte| char::from(*byte))
        .collect::<String>();
    if !generation(&value) {
        return Err("hardware kernel boot identity is zero".into());
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WriteKind {
    Apply,
    Restore,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Worker {
    Model,
    Acquisition,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Adapter {
    CpuQuota,
    CpuWeight,
    MemoryProfile,
    StorageRate,
    Backlight,
    WorkerNetwork,
    PowerProfiles,
}
impl Adapter {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::CpuQuota => "native-cgroup-cpu-quota-v1",
            Self::CpuWeight => "native-cgroup-cpu-weight-v1",
            Self::MemoryProfile => "native-admitted-memory-profile-v1",
            Self::StorageRate => "native-cgroup-storage-rate-v1",
            Self::Backlight => "native-qualified-backlight-v1",
            Self::WorkerNetwork => "native-systemd-cgroup-ip-filter-v1",
            Self::PowerProfiles => "native-power-profiles-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NetworkProfile {
    UnrestrictedBaseline,
    DenyAll,
    LoopbackOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PowerProfile {
    PowerSaver,
    Balanced,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Setting {
    CpuQuota {
        quota_us: u64,
        period_us: u64,
    },
    CpuWeight {
        weight: u64,
    },
    MemoryProfile {
        profile: String,
        bytes: u64,
    },
    StorageRate {
        device: String,
        read_bytes_per_second: u64,
        write_bytes_per_second: u64,
    },
    Backlight {
        brightness: u32,
        maximum: u32,
    },
    WorkerNetwork {
        profile: NetworkProfile,
    },
    PowerProfiles {
        profile: PowerProfile,
    },
}
impl Setting {
    pub(crate) fn adapter(&self) -> Adapter {
        match self {
            Self::CpuQuota { .. } => Adapter::CpuQuota,
            Self::CpuWeight { .. } => Adapter::CpuWeight,
            Self::MemoryProfile { .. } => Adapter::MemoryProfile,
            Self::StorageRate { .. } => Adapter::StorageRate,
            Self::Backlight { .. } => Adapter::Backlight,
            Self::WorkerNetwork { .. } => Adapter::WorkerNetwork,
            Self::PowerProfiles { .. } => Adapter::PowerProfiles,
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::CpuQuota {
                quota_us,
                period_us,
            } => *period_us == 100_000 && (1_000..=200_000).contains(quota_us),
            Self::CpuWeight { weight } => (1..=10_000).contains(weight),
            Self::MemoryProfile { profile, bytes } => {
                matches!(profile.as_str(), "qwen3-4b-q4-k-m" | "qwen3-1-7b-q4-k-m")
                    && (1024 * 1024..=64 * 1024 * 1024 * 1024).contains(bytes)
            }
            Self::StorageRate {
                device,
                read_bytes_per_second,
                write_bytes_per_second,
            } => {
                block_identity(device)
                    && (1..=64 * 1024 * 1024).contains(read_bytes_per_second)
                    && (1..=64 * 1024 * 1024).contains(write_bytes_per_second)
            }
            Self::Backlight {
                brightness,
                maximum,
            } => (1..=1_000_000).contains(maximum) && brightness <= maximum,
            Self::WorkerNetwork { .. } | Self::PowerProfiles { .. } => true,
        };
        if !valid {
            return Err("hardware setting is outside its closed compiled adapter bounds".into());
        }
        Ok(())
    }
}

fn block_identity(value: &str) -> bool {
    let Some((major, minor)) = value.split_once(':') else {
        return false;
    };
    let decimal = |part: &str| {
        part.parse::<u32>()
            .is_ok_and(|value| value.to_string() == part)
    };
    decimal(major) && decimal(minor) && major != "0"
}
fn digest(value: &str) -> Result<()> {
    if crate::tpm::decode::<32>(value)? == [0; 32] {
        return Err("hardware binding requires an exact nonzero digest".into());
    }
    Ok(())
}
fn generation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value != "0".repeat(32)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceBinding {
    pub manager_epoch: String,
    pub lease: Option<resources::Token>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub adapter: Adapter,
    pub worker: Option<Worker>,
    pub identity_sha256: String,
    pub capability_sha256: String,
    pub adapter_sha256: String,
    pub boot: String,
    #[serde(with = "resources::decimal")]
    pub generation: u64,
    pub resource: Option<ResourceBinding>,
}
impl Target {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.identity_sha256,
            &self.capability_sha256,
            &self.adapter_sha256,
        ] {
            digest(value)?;
        }
        if !generation(&self.boot) || self.generation == 0 {
            return Err(
                "hardware target requires exact device, boot and resource generations".into(),
            );
        }
        let global = matches!(self.adapter, Adapter::Backlight | Adapter::PowerProfiles);
        if global != self.worker.is_none() || global != self.resource.is_none() {
            return Err("hardware target substitutes a global device or fixed worker".into());
        }
        if let Some(resource) = &self.resource {
            if !generation(&resource.manager_epoch) {
                return Err("hardware target lacks its actual worker-manager epoch".into());
            }
            if let Some(lease) = &resource.lease {
                if !generation(&lease.lease_id)
                    || !generation(&lease.manager_epoch)
                    || lease.manager_epoch != resource.manager_epoch
                    || lease.generation == 0
                {
                    return Err(
                        "hardware target substitutes its admitted worker lease generation".into(),
                    );
                }
            }
        }
        if self.adapter == Adapter::MemoryProfile
            && (self.worker != Some(Worker::Model)
                || self
                    .resource
                    .as_ref()
                    .is_some_and(|value| value.lease.is_some()))
        {
            return Err(
                "memory policy requires the drained model generation, never an active allocation"
                    .into(),
            );
        }
        Ok(())
    }
    pub(crate) fn key(&self) -> Result<String> {
        self.validate()?;
        hash(&(
            "luma-native-hardware-policy-target-v1",
            self.adapter,
            self.worker,
            &self.identity_sha256,
        ))
    }
}

pub(crate) fn hash(value: &impl Serialize) -> Result<String> {
    Ok(crate::bundle::hex(&Sha256::digest(serde_json::to_vec(
        value,
    )?)))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub schema_version: u32,
    pub transaction: String,
    pub subject: String,
    pub subject_generation: u64,
    pub apply_grant: String,
    pub restore_grant: String,
    pub target: Target,
    pub expected_revision: u64,
    pub before: Setting,
    pub after: Setting,
    #[serde(with = "resources::decimal")]
    pub lifetime_ms: u64,
    pub cleanup: String,
}
impl Plan {
    pub(crate) fn validate(&self) -> Result<()> {
        digest(&self.subject)?;
        self.target.validate()?;
        self.before.validate()?;
        self.after.validate()?;
        if self.schema_version != 1
            || !crate::admin_roles::identifier(&self.transaction)
            || !crate::admin_roles::identifier(&self.apply_grant)
            || !crate::admin_roles::identifier(&self.restore_grant)
            || self.apply_grant == self.restore_grant
            || self.subject_generation == 0
            || self.expected_revision >= u64::MAX - 4
            || self.lifetime_ms == 0
            || self.lifetime_ms > MAX_LIFETIME_MS
            || self.cleanup
                != "restore-exact-before-only-if-same-generation-and-still-exact-applied-value"
            || self.before.adapter() != self.target.adapter
            || self.after.adapter() != self.target.adapter
            || self.before == self.after
        {
            return Err("hardware intent requires an exact finite changed policy and bounded precommitted cleanup".into());
        }
        if matches!(
            self.after,
            Setting::WorkerNetwork {
                profile: NetworkProfile::UnrestrictedBaseline
            }
        ) || matches!(self.after, Setting::Backlight { brightness: 0, .. })
        {
            return Err(
                "hardware policy cannot grant unrestricted network or extinguish manual display"
                    .into(),
            );
        }
        match (&self.before, &self.after) {
            (
                Setting::Backlight {
                    maximum: before, ..
                },
                Setting::Backlight { maximum: after, .. },
            ) if before != after => {
                return Err("backlight capability changed inside the proposed policy".into());
            }
            (
                Setting::StorageRate { device: before, .. },
                Setting::StorageRate { device: after, .. },
            ) if before != after => {
                return Err("storage policy substitutes a backing device".into());
            }
            (
                Setting::MemoryProfile {
                    profile: before,
                    bytes: before_bytes,
                },
                Setting::MemoryProfile {
                    profile: after,
                    bytes: after_bytes,
                },
            ) if before != after || after_bytes > before_bytes || *before_bytes > 4_831_838_208 => {
                return Err("memory hardware policy cannot select another model or expand its admitted envelope".into());
            }
            _ => (),
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        hash(&("luma-native-hardware-policy-plan-v1", self))
    }
    pub(crate) fn usage(&self, action: finite_grants::Action) -> Result<finite_grants::Use> {
        if !matches!(
            action,
            finite_grants::Action::ApplyHardware | finite_grants::Action::RestoreHardware
        ) {
            return Err("hardware intent supplies only its exact apply/restore scopes".into());
        }
        let usage = finite_grants::Use {
            action,
            selector: finite_grants::Selector {
                kind: finite_grants::Kind::Hardware,
                id: self.target.adapter.id().into(),
                generation: self.target.generation,
                digest: self.digest()?,
            },
            input_bytes: 65_536,
            output_bytes: 65_536,
            units: 1,
        };
        usage.validate()?;
        Ok(usage)
    }

    pub(crate) fn start(&self, created_ms: u64) -> Result<Intent> {
        self.validate()?;
        let intent = Intent {
            schema_version: self.schema_version,
            transaction: self.transaction.clone(),
            subject: self.subject.clone(),
            subject_generation: self.subject_generation,
            apply_grant: self.apply_grant.clone(),
            restore_grant: self.restore_grant.clone(),
            target: self.target.clone(),
            expected_revision: self.expected_revision,
            before: self.before.clone(),
            after: self.after.clone(),
            created_ms,
            deadline_ms: created_ms
                .checked_add(self.lifetime_ms)
                .ok_or("hardware activation deadline overflow")?,
            cleanup: self.cleanup.clone(),
        };
        intent.validate()?;
        Ok(intent)
    }
}

/// The actual activation window is chosen only inside the original hardware
/// PAM ceremony, then committed before any device write. Grants name the
/// one-use stable Plan; neither a review delay nor a retry renews this window.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub schema_version: u32,
    pub transaction: String,
    pub subject: String,
    pub subject_generation: u64,
    pub apply_grant: String,
    pub restore_grant: String,
    pub target: Target,
    pub expected_revision: u64,
    pub before: Setting,
    pub after: Setting,
    #[serde(with = "resources::decimal")]
    pub created_ms: u64,
    #[serde(with = "resources::decimal")]
    pub deadline_ms: u64,
    pub cleanup: String,
}
impl Intent {
    pub(crate) fn plan(&self) -> Result<Plan> {
        Ok(Plan {
            schema_version: self.schema_version,
            transaction: self.transaction.clone(),
            subject: self.subject.clone(),
            subject_generation: self.subject_generation,
            apply_grant: self.apply_grant.clone(),
            restore_grant: self.restore_grant.clone(),
            target: self.target.clone(),
            expected_revision: self.expected_revision,
            before: self.before.clone(),
            after: self.after.clone(),
            lifetime_ms: self
                .deadline_ms
                .checked_sub(self.created_ms)
                .ok_or("hardware activation precedes its creation")?,
            cleanup: self.cleanup.clone(),
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.created_ms == 0 || self.deadline_ms.checked_add(CLEANUP_GRACE_MS).is_none() {
            return Err("hardware intent has no finite committed activation/cleanup window".into());
        }
        self.plan()?.validate()
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        self.plan()?.digest()
    }
    pub(crate) fn usage(&self, action: finite_grants::Action) -> Result<finite_grants::Use> {
        self.validate()?;
        self.plan()?.usage(action)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub target: Target,
    pub setting: Setting,
    #[serde(with = "resources::decimal")]
    pub observed_ms: u64,
    pub enforcement_sha256: String,
}

/// The exact external daemon generation to which a mutating message may have
/// been delivered. A timeout is not cancellation and does not retire this
/// obligation. This is recorded before sending, never inferred from readback.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchWitness {
    pub pid: u32,
    #[serde(with = "resources::decimal")]
    pub start_ticks: u64,
    pub unique_name: String,
    pub exe_sha256: String,
}
impl DispatchWitness {
    pub(crate) fn validate(&self) -> Result<()> {
        digest(&self.exe_sha256)?;
        if self.pid == 0
            || self.start_ticks == 0
            || self.unique_name.len() > 255
            || !self.unique_name.starts_with(':')
            || self.unique_name.len() < 4
            || !self.unique_name[1..]
                .bytes()
                .all(|value| value.is_ascii_digit() || value == b'.')
            || self.unique_name[1..].split('.').any(|part| part.is_empty())
        {
            return Err(
                "hardware external dispatch lacks an exact pinned unique daemon generation".into(),
            );
        }
        Ok(())
    }
    /// A new connection cannot cancel an older daemon request. Recovery must
    /// prove that the actual old process generation cannot execute it later.
    pub(crate) fn require_exited(&self, original_boot: &str) -> Result<()> {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::OpenOptionsExt;
        self.validate()?;
        if current_boot()? != original_boot {
            return Ok(());
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error.into())
            };
        }
        let pin = unsafe { std::fs::File::from_raw_fd(fd as i32) };
        let mut poll = libc::pollfd {
            fd: pin.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if poll.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/{}/stat", self.pid))?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type as u64 != 0x9fa0
        {
            return Err("dispatch retirement is not actual kernel procfs".into());
        }
        let mut text = String::new();
        Read::by_ref(&mut file)
            .take(4097)
            .read_to_string(&mut text)?;
        if text.len() > 4096 || !text.starts_with(&format!("{} (", self.pid)) {
            return Err("dispatch retirement process generation is malformed".into());
        }
        let fields = text
            .rsplit_once(") ")
            .ok_or("dispatch process comm is malformed")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.len() < 20 {
            return Err("dispatch process start generation absent".into());
        }
        let start = fields[19].parse::<u64>()?;
        if start != 0 && start != self.start_ticks {
            return Ok(());
        }
        Err("ambiguous daemon dispatch remains live; preserve obligation until that exact daemon exits or the machine reboots".into())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dispatch {
    pub kind: WriteKind,
    pub witness: Option<DispatchWitness>,
    #[serde(with = "resources::decimal")]
    pub started_ms: u64,
}
impl Observation {
    pub(crate) fn validate(&self) -> Result<()> {
        self.target.validate()?;
        self.setting.validate()?;
        digest(&self.enforcement_sha256)?;
        if self.observed_ms == 0 || self.setting.adapter() != self.target.adapter {
            return Err("hardware observation does not bind actual adapter state".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FenceReason {
    ExternalDrift,
    GenerationChanged,
    AuthorizationLost,
    DeadlineExpired,
    PartialWrite,
    VerificationFailed,
    Disconnected,
    AuthorityUnavailable,
    ResourceLost,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reconciliation {
    BaselineObserved,
    ExternalStateRetained,
    DeviceUnavailable,
}

/// Human-reviewed reconciliation semantics. Fresh physical observation time
/// and readback evidence are supplied by the native controller at execution,
/// never used as a stopwatch that makes a pre-approved finite grant unusable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewedObservation {
    pub target: Target,
    pub setting: Setting,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconciliationPlan {
    pub schema_version: u32,
    pub transaction: String,
    pub expected_revision: u64,
    pub disposition: Reconciliation,
    pub observation: Option<ReviewedObservation>,
}
impl ReconciliationPlan {
    pub(crate) fn usage(&self, intent: &Intent) -> Result<finite_grants::Use> {
        intent.validate()?;
        if self.schema_version != 1
            || self.transaction != intent.transaction
            || self.expected_revision <= intent.expected_revision
            || self.expected_revision == u64::MAX
        {
            return Err(
                "reconciliation review substitutes its original transaction or revision".into(),
            );
        }
        match (&self.disposition,&self.observation) {
            (Reconciliation::DeviceUnavailable,None)=>(),
            (Reconciliation::BaselineObserved|Reconciliation::ExternalStateRetained,Some(observation))=>{
                observation.target.validate()?;observation.setting.validate()?;
                if observation.target.key()?!=intent.target.key()?
                    || observation.setting.adapter()!=observation.target.adapter
                    || (self.disposition==Reconciliation::BaselineObserved && observation.setting!=intent.before) {
                    return Err("reconciliation review substitutes a device or unobserved baseline".into());
                }
            }
            _=>return Err("reconciliation review must explicitly retain observed state or actual device absence".into()),
        }
        let target = self
            .observation
            .as_ref()
            .map_or(&intent.target, |value| &value.target);
        let usage = finite_grants::Use {
            action: finite_grants::Action::RestoreHardware,
            selector: finite_grants::Selector {
                kind: finite_grants::Kind::Hardware,
                id: target.adapter.id().into(),
                generation: target.generation,
                digest: hash(&("luma-native-hardware-reconciliation-plan-v1", intent, self))?,
            },
            input_bytes: 65_536,
            output_bytes: 65_536,
            units: 1,
        };
        usage.validate()?;
        Ok(usage)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Event {
    Prepare {
        intent: Intent,
    },
    DispatchStarted {
        transaction: String,
        expected_revision: u64,
        dispatch: Dispatch,
    },
    Applied {
        transaction: String,
        expected_revision: u64,
        observation: Observation,
    },
    Restored {
        transaction: String,
        expected_revision: u64,
        observation: Observation,
    },
    Fenced {
        transaction: String,
        expected_revision: u64,
        reason: FenceReason,
    },
    Reconciled {
        transaction: String,
        expected_revision: u64,
        disposition: Reconciliation,
        observation: Option<Observation>,
    },
}
impl Event {
    pub(crate) fn transaction(&self) -> &str {
        match self {
            Self::Prepare { intent } => &intent.transaction,
            Self::DispatchStarted { transaction, .. }
            | Self::Applied { transaction, .. }
            | Self::Restored { transaction, .. }
            | Self::Fenced { transaction, .. }
            | Self::Reconciled { transaction, .. } => transaction,
        }
    }
    pub(crate) fn activity(&self) -> &'static str {
        match self {
            Self::Prepare { .. } => "admin.hardware.prepare",
            Self::DispatchStarted { .. } => "admin.hardware.dispatch_started",
            Self::Applied { .. } => "admin.hardware.apply_observed",
            Self::Restored { .. } => "admin.hardware.restore_observed",
            Self::Fenced { .. } => "admin.hardware.fence",
            Self::Reconciled { .. } => "admin.hardware.reconcile",
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::admin_roles::identifier(self.transaction()) {
            return Err("invalid hardware transaction identity".into());
        }
        match self {
            Self::Prepare { intent } => intent.validate(),
            Self::DispatchStarted {
                expected_revision,
                dispatch,
                ..
            } => {
                if *expected_revision == 0
                    || *expected_revision == u64::MAX
                    || dispatch.started_ms == 0
                {
                    return Err(
                        "hardware dispatch witness has no actual finite revision/time".into(),
                    );
                }
                if let Some(witness) = &dispatch.witness {
                    witness.validate()?;
                }
                Ok(())
            }
            Self::Applied {
                expected_revision,
                observation,
                ..
            }
            | Self::Restored {
                expected_revision,
                observation,
                ..
            } => {
                if *expected_revision == 0 || *expected_revision == u64::MAX {
                    return Err("invalid hardware revision".into());
                }
                observation.validate()
            }
            Self::Fenced {
                expected_revision, ..
            }
            | Self::Reconciled {
                expected_revision,
                observation: None,
                ..
            } => {
                if *expected_revision == 0 || *expected_revision == u64::MAX {
                    return Err("invalid hardware revision".into());
                }
                Ok(())
            }
            Self::Reconciled {
                expected_revision,
                observation: Some(observation),
                ..
            } => {
                if *expected_revision == 0 || *expected_revision == u64::MAX {
                    return Err("invalid hardware revision".into());
                }
                observation.validate()
            }
        }
    }

    pub(crate) fn uses(
        &self,
        state: &State,
        recovery_grant: Option<&str>,
    ) -> Result<Vec<(String, finite_grants::Use)>> {
        let intent = match self {
            Self::Prepare { intent } => intent,
            _ => {
                &state
                    .transactions
                    .get(self.transaction())
                    .ok_or("hardware event has no prepared intent")?
                    .intent
            }
        };
        if let Self::Reconciled {
            transaction,
            expected_revision,
            disposition,
            observation,
        } = self
        {
            let grant = recovery_grant
                .filter(|value| crate::admin_roles::identifier(value))
                .ok_or("hardware reconciliation requires a fresh explicit Restore grant")?;
            let usage = ReconciliationPlan {
                schema_version: 1,
                transaction: transaction.clone(),
                expected_revision: *expected_revision,
                disposition: *disposition,
                observation: observation.as_ref().map(|value| ReviewedObservation {
                    target: value.target.clone(),
                    setting: value.setting.clone(),
                }),
            }
            .usage(intent)?;
            return Ok(vec![(grant.into(), usage)]);
        }
        if recovery_grant.is_some() {
            return Err("ordinary hardware events cannot substitute restoration grants".into());
        }
        Ok(vec![
            (
                intent.apply_grant.clone(),
                intent.usage(finite_grants::Action::ApplyHardware)?,
            ),
            (
                intent.restore_grant.clone(),
                intent.usage(finite_grants::Action::RestoreHardware)?,
            ),
        ])
    }
}

/// Historical authorization attribution inside the authenticated Admin event.
/// Only the native owned session may construct it at the live commit boundary.
/// Parsing these bytes is never sufficient to execute a hardware operation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authorization {
    pub subject: String,
    pub subject_generation: u64,
    pub context: crate::utc_history::Statement,
    pub lower_ms: i64,
    pub upper_ms: i64,
    pub uses: Vec<(String, finite_grants::Use)>,
}
impl Authorization {
    pub(crate) fn validate(&self) -> Result<()> {
        digest(&self.subject)?;
        self.context.validate()?;
        if self.subject_generation == 0
            || self.lower_ms != self.context.floor_ms
            || self.upper_ms < self.lower_ms
            || self.upper_ms - self.lower_ms > 500
            || self.upper_ms > 4_102_444_800_000
            || self.uses.is_empty()
            || self.uses.len() > 2
        {
            return Err("hardware event has invalid finite UTC/subject attribution".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for (id, usage) in &self.uses {
            if !crate::admin_roles::identifier(id) || !ids.insert(id) {
                return Err("hardware attribution reuses or substitutes a finite grant".into());
            }
            usage.validate()?;
        }
        Ok(())
    }
    pub(crate) fn check(&self, catalog: &crate::admin_roles::Catalog, event: &Event) -> Result<()> {
        self.validate()?;
        event.validate()?;
        let recovery = matches!(event, Event::Reconciled { .. }).then(|| self.uses[0].0.as_str());
        if self.uses != event.uses(&catalog.hardware_policies, recovery)? {
            return Err(
                "hardware event changes its exact independent finite apply/restore scopes".into(),
            );
        }
        let identity =
            serde_json::json!({"principal":self.subject,"generation":self.subject_generation});
        let interval = crate::utc_bounds::Interval::new(self.lower_ms, self.upper_ms)?;
        for (id, usage) in &self.uses {
            catalog
                .grants
                .get(id)
                .ok_or("hardware event grant was not issued")?
                .authorize(catalog, &identity, interval, usage)?;
        }
        if let Event::Prepare { intent } = event {
            if self.subject != intent.subject
                || self.subject_generation != intent.subject_generation
            {
                return Err("hardware preparation substitutes the actual grant subject".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Prepared,
    Applied,
    Restored,
    Fenced,
    Reconciled,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transition {
    pub intent: Intent,
    pub revision: u64,
    pub phase: Phase,
    pub observation: Option<Observation>,
    pub fence: Option<FenceReason>,
    pub reconciliation: Option<Reconciliation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dispatches: Vec<Dispatch>,
}
impl Transition {
    pub(crate) fn ambiguous_external_dispatch(&self) -> Option<&DispatchWitness> {
        let last = self.dispatches.last()?;
        let incomplete = match last.kind {
            WriteKind::Apply => {
                self.observation.is_none()
                    && !matches!(self.phase, Phase::Restored | Phase::Reconciled)
            }
            WriteKind::Restore => !matches!(self.phase, Phase::Restored | Phase::Reconciled),
        };
        if incomplete {
            last.witness.as_ref()
        } else {
            None
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub transactions: BTreeMap<String, Transition>,
}
impl State {
    pub(crate) fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
    pub(crate) fn apply(&mut self, event: &Event) -> Result<()> {
        event.validate()?;
        if let Event::Prepare { intent } = event {
            if self.transactions.len() >= MAX_POLICIES
                || self.transactions.contains_key(&intent.transaction)
            {
                return Err(
                    "hardware policy history is exhausted or transaction identity was reused"
                        .into(),
                );
            }
            let target = intent.target.key()?;
            let mut prior: Option<&Transition> = None;
            for (transaction, value) in &self.transactions {
                value.intent.validate()?;
                if transaction != &value.intent.transaction
                    || value.revision <= value.intent.expected_revision
                {
                    return Err("invalid retained hardware transaction identity or revision".into());
                }
                if value.intent.target.key()? == target
                    && prior.map_or(true, |old| old.revision < value.revision)
                {
                    prior = Some(value);
                }
            }
            if prior
                .is_some_and(|value| !matches!(value.phase, Phase::Restored | Phase::Reconciled))
                || intent.expected_revision != prior.map_or(0, |value| value.revision)
            {
                return Err("hardware target has an outstanding policy or stale revision".into());
            }
            self.transactions.insert(
                intent.transaction.clone(),
                Transition {
                    intent: intent.clone(),
                    revision: intent.expected_revision + 1,
                    phase: Phase::Prepared,
                    observation: None,
                    fence: None,
                    reconciliation: None,
                    dispatches: Vec::new(),
                },
            );
            return Ok(());
        }
        let current = self
            .transactions
            .get(event.transaction())
            .ok_or("unknown hardware transaction")?;
        let mut next = current.clone();
        let expected = match event {
            Event::DispatchStarted {
                expected_revision,
                dispatch,
                ..
            } => {
                let external = matches!(
                    current.intent.target.adapter,
                    Adapter::PowerProfiles | Adapter::WorkerNetwork
                );
                if external!=dispatch.witness.is_some()
                    || dispatch.witness.as_ref().is_some_and(|witness|match current.intent.target.adapter {
                        Adapter::PowerProfiles=>witness.pid<=1 || witness.exe_sha256!="9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a",
                        Adapter::WorkerNetwork=>witness.pid!=1 || witness.exe_sha256!="b472aadf808bef87c0eb203056a77cb64bd268b71b756306013a53de68a94173",
                        _=>true,
                    })
                    || dispatch.started_ms<current.intent.created_ms
                    || dispatch.started_ms>current.intent.deadline_ms+if dispatch.kind==WriteKind::Restore {CLEANUP_GRACE_MS}else{0}
                    || current.dispatches.iter().any(|old|old.kind==dispatch.kind)
                    || match dispatch.kind {
                        WriteKind::Apply=>current.phase!=Phase::Prepared || !current.dispatches.is_empty(),
                        WriteKind::Restore=>current.phase!=Phase::Applied || current.dispatches.len()!=1,
                    } {
                    return Err("hardware dispatch cannot replay, substitute daemon generation, or escape its original finite phase".into());
                }
                next.dispatches.push(dispatch.clone());
                *expected_revision
            }
            Event::Applied {
                expected_revision,
                observation,
                ..
            } => {
                if current.phase != Phase::Prepared
                    || current.dispatches.last().map(|value| value.kind) != Some(WriteKind::Apply)
                    || current
                        .dispatches
                        .last()
                        .is_some_and(|value| observation.observed_ms < value.started_ms)
                    || observation.target != current.intent.target
                    || observation.setting != current.intent.after
                    || observation.observed_ms < current.intent.created_ms
                    || observation.observed_ms > current.intent.deadline_ms
                {
                    return Err("hardware apply observation substitutes its prepared target, state or lifetime".into());
                }
                next.phase = Phase::Applied;
                next.observation = Some(observation.clone());
                *expected_revision
            }
            Event::Restored {
                expected_revision,
                observation,
                ..
            } => {
                if !matches!(current.phase, Phase::Prepared | Phase::Applied)
                    || (current.phase == Phase::Prepared
                        && current
                            .dispatches
                            .iter()
                            .any(|value| value.witness.is_some()))
                    || (current.phase == Phase::Applied
                        && current.dispatches.last().map(|value| value.kind)
                            != Some(WriteKind::Restore))
                    || current
                        .dispatches
                        .last()
                        .is_some_and(|value| observation.observed_ms < value.started_ms)
                    || observation.target != current.intent.target
                    || observation.setting != current.intent.before
                    || observation.observed_ms < current.intent.created_ms
                    || current
                        .observation
                        .as_ref()
                        .is_some_and(|prior| observation.observed_ms < prior.observed_ms)
                    || observation.observed_ms > current.intent.deadline_ms + CLEANUP_GRACE_MS
                {
                    return Err("hardware restore observation lacks the exact original target/baseline/cleanup window".into());
                }
                next.phase = Phase::Restored;
                next.observation = Some(observation.clone());
                *expected_revision
            }
            Event::Fenced {
                expected_revision,
                reason,
                ..
            } => {
                if matches!(
                    current.phase,
                    Phase::Restored | Phase::Reconciled | Phase::Fenced
                ) {
                    return Err("terminal hardware policy cannot be refenced or revived".into());
                }
                next.phase = Phase::Fenced;
                next.fence = Some(*reason);
                *expected_revision
            }
            Event::Reconciled {
                expected_revision,
                disposition,
                observation,
                ..
            } => {
                if !matches!(
                    current.phase,
                    Phase::Prepared | Phase::Applied | Phase::Fenced
                ) {
                    return Err("only an outstanding hardware policy can be reconciled".into());
                }
                match (disposition, observation) {
                    (Reconciliation::DeviceUnavailable, None) => (),
                    (Reconciliation::BaselineObserved, Some(observed)) if observed.target.key()? == current.intent.target.key()? && observed.setting == current.intent.before => (),
                    (Reconciliation::ExternalStateRetained, Some(observed)) if observed.target.key()? == current.intent.target.key()? => (),
                    _ => return Err("hardware reconciliation substitutes the selected device or observed disposition".into()),
                }
                next.phase = Phase::Reconciled;
                next.observation = observation.clone();
                next.reconciliation = Some(*disposition);
                *expected_revision
            }
            Event::Prepare { .. } => return Err("hardware preparation dispatch mismatch".into()),
        };
        if expected != current.revision {
            return Err("hardware policy revision changed before journal transition".into());
        }
        next.revision = expected
            .checked_add(1)
            .ok_or("hardware policy revision exhausted")?;
        self.transactions.insert(event.transaction().into(), next);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        admin_roles::{Catalog, Command},
        finite_grants::{Action, Assignment, Constraints, Grant},
    };

    pub(crate) fn intent() -> Intent {
        Intent {
            schema_version: 1,
            transaction: "cpu-policy-one".into(),
            subject: "cd".repeat(32),
            subject_generation: 1,
            apply_grant: "apply-hardware-one".into(),
            restore_grant: "restore-hardware-one".into(),
            target: Target {
                adapter: Adapter::CpuQuota,
                worker: Some(Worker::Model),
                identity_sha256: "23".repeat(32),
                capability_sha256: "34".repeat(32),
                adapter_sha256: "45".repeat(32),
                boot: "12".repeat(16),
                generation: 3,
                resource: Some(ResourceBinding {
                    manager_epoch: "56".repeat(16),
                    lease: None,
                }),
            },
            expected_revision: 0,
            before: Setting::CpuQuota {
                quota_us: 100_000,
                period_us: 100_000,
            },
            after: Setting::CpuQuota {
                quota_us: 50_000,
                period_us: 100_000,
            },
            created_ms: 1000,
            deadline_ms: 21_000,
            cleanup: "restore-exact-before-only-if-same-generation-and-still-exact-applied-value"
                .into(),
        }
    }
    fn observation(intent: &Intent, restored: bool, observed_ms: u64) -> Observation {
        Observation {
            target: intent.target.clone(),
            setting: if restored {
                intent.before.clone()
            } else {
                intent.after.clone()
            },
            observed_ms,
            enforcement_sha256: "67".repeat(32),
        }
    }
    fn prepared() -> State {
        let mut state = State::default();
        state.apply(&Event::Prepare { intent: intent() }).unwrap();
        state
    }
    fn dispatch(state: &mut State, kind: WriteKind, started_ms: u64) -> u64 {
        let intent = intent();
        let revision = state.transactions[&intent.transaction].revision;
        state
            .apply(&Event::DispatchStarted {
                transaction: intent.transaction.clone(),
                expected_revision: revision,
                dispatch: Dispatch {
                    kind,
                    witness: None,
                    started_ms,
                },
            })
            .unwrap();
        state.transactions[&intent.transaction].revision
    }
    fn authorization(intent: &Intent) -> Authorization {
        Authorization {
            subject: intent.subject.clone(),
            subject_generation: 1,
            context: crate::utc_history::Statement {
                floor_ms: 3000,
                policy_sha256: crate::utc_history::policy_digest().unwrap(),
                boot_id: intent.target.boot.clone(),
                process_generation: 1,
                source_clock_generation: 1,
                keeper_generation: 1,
                runtime_sha256: "78".repeat(32),
            },
            lower_ms: 3000,
            upper_ms: 3100,
            uses: Event::Prepare {
                intent: intent.clone(),
            }
            .uses(&State::default(), None)
            .unwrap(),
        }
    }
    fn catalog(intent: &Intent) -> Catalog {
        let mut catalog = Catalog::initial();
        catalog
            .apply(&Command::AdoptPrincipals {
                registry: serde_json::from_value(serde_json::json!({
            "schema_version":1,"installation":"ab".repeat(32),"principals":[
                {"id":intent.subject,"generation":1,"login":"human","uid":1001,"enabled":true}]}))
                .unwrap(),
            })
            .unwrap();
        catalog
            .apply(&Command::CheckpointAccounts {
                commitments: BTreeMap::from([(intent.subject.clone(), "89".repeat(32))]),
            })
            .unwrap();
        for activity in [
            Action::InspectHardware,
            Action::ApplyHardware,
            Action::RestoreHardware,
        ] {
            catalog
                .apply(&Command::RegisterActivity {
                    activity: activity.activity().into(),
                })
                .unwrap();
        }
        catalog
            .apply(&Command::DefineRole {
                name: "Hardware".into(),
                activities: vec![
                    "hardware.apply".into(),
                    "hardware.inspect".into(),
                    "hardware.restore".into(),
                ],
                expected_version: 0,
            })
            .unwrap();
        catalog
            .apply(&Command::AssignRole {
                assignment: Assignment {
                    id: "hardware-operator".into(),
                    subject: intent.subject.clone(),
                    subject_generation: 1,
                    role: "Hardware".into(),
                    role_version: 1,
                    version: 1,
                    not_before_ms: 1000,
                    expires_ms: 10_000,
                    revoked: false,
                },
            })
            .unwrap();
        for (id, usage) in authorization(intent).uses {
            catalog
                .apply(&Command::IssueGrant {
                    grant: Grant {
                        id,
                        assignment: "hardware-operator".into(),
                        assignment_version: 1,
                        subject: intent.subject.clone(),
                        subject_generation: 1,
                        action: usage.action,
                        selector: usage.selector,
                        constraints: Constraints {
                            max_input_bytes: usage.input_bytes,
                            max_output_bytes: usage.output_bytes,
                            max_units: 1,
                        },
                        version: 1,
                        not_before_ms: 2000,
                        expires_ms: 9000,
                        revoked: false,
                    },
                })
                .unwrap();
        }
        catalog
    }

    #[test]
    fn exact_apply_restore_and_subsequent_revision_form_a_single_cas_chain() {
        let intent = intent();
        let mut state = prepared();
        assert_eq!(state.transactions[&intent.transaction].revision, 1);
        let revision = dispatch(&mut state, WriteKind::Apply, 1100);
        state
            .apply(&Event::Applied {
                transaction: intent.transaction.clone(),
                expected_revision: revision,
                observation: observation(&intent, false, 1500),
            })
            .unwrap();
        let revision = dispatch(&mut state, WriteKind::Restore, 1800);
        state
            .apply(&Event::Restored {
                transaction: intent.transaction.clone(),
                expected_revision: revision,
                observation: observation(&intent, true, 2000),
            })
            .unwrap();
        let mut next = intent.clone();
        next.transaction = "cpu-policy-two".into();
        next.expected_revision = 5;
        state
            .apply(&Event::Prepare {
                intent: next.clone(),
            })
            .unwrap();
        assert_eq!(state.transactions[&next.transaction].revision, 6);
        assert_eq!(
            state.transactions[&intent.transaction].phase,
            Phase::Restored
        );
    }

    #[test]
    fn finite_grants_bind_one_stable_plan_not_an_unusable_approval_stopwatch() {
        let intent = intent();
        let plan = intent.plan().unwrap();
        let late = plan.start(1_000_000).unwrap();
        assert_eq!(intent.digest().unwrap(), late.digest().unwrap());
        assert_eq!(
            intent.usage(Action::ApplyHardware).unwrap(),
            late.usage(Action::ApplyHardware).unwrap()
        );
        assert_eq!(late.deadline_ms - late.created_ms, MAX_LIFETIME_MS);
        let mut state = prepared();
        assert!(state.apply(&Event::Prepare { intent: late }).is_err());
        for variant in 0..6 {
            let mut changed = plan.clone();
            match variant {
                0 => changed.lifetime_ms -= 1,
                1 => changed.transaction = "another-one-use-plan".into(),
                2 => changed.expected_revision += 1,
                3 => changed.subject_generation += 1,
                4 => {
                    changed.after = Setting::CpuQuota {
                        quota_us: 25_000,
                        period_us: 100_000,
                    }
                }
                _ => changed.restore_grant = "substituted-restore".into(),
            }
            assert_ne!(changed.digest().unwrap(), plan.digest().unwrap());
        }
        assert!(plan.start(0).is_err());
        assert!(plan.start(u64::MAX - MAX_LIFETIME_MS).is_err());
    }

    #[test]
    fn global_devices_never_claim_a_worker_resource_epoch_or_allocation() {
        let mut target = intent().target;
        target.adapter = Adapter::Backlight;
        target.worker = None;
        target.resource = None;
        target.validate().unwrap();
        target.resource = Some(ResourceBinding {
            manager_epoch: "34".repeat(16),
            lease: None,
        });
        assert!(target.validate().is_err());
        target = intent().target;
        target.resource = None;
        assert!(target.validate().is_err());
    }

    #[test]
    fn lost_apply_ack_can_restore_only_the_committed_baseline() {
        let intent = intent();
        let mut state = prepared();
        state
            .apply(&Event::Restored {
                transaction: intent.transaction.clone(),
                expected_revision: 1,
                observation: observation(&intent, true, 2000),
            })
            .unwrap();
        assert_eq!(
            state.transactions[&intent.transaction].phase,
            Phase::Restored
        );
    }

    #[test]
    fn every_apply_binding_or_time_substitution_is_atomic_refusal() {
        let intent = intent();
        for variant in 0..13 {
            let mut state = prepared();
            dispatch(&mut state, WriteKind::Apply, 1100);
            let before = state.clone();
            let mut observed = observation(&intent, false, 1500);
            let mut revision = 2;
            match variant {
                0 => observed.target.boot = "ab".repeat(16),
                1 => observed.target.generation += 1,
                2 => observed.target.resource.as_mut().unwrap().manager_epoch = "cd".repeat(16),
                3 => observed.target.identity_sha256 = "ef".repeat(32),
                4 => observed.target.capability_sha256 = "ab".repeat(32),
                5 => observed.target.adapter_sha256 = "bc".repeat(32),
                6 => observed.target.worker = Some(Worker::Acquisition),
                7 => observed.setting = intent.before.clone(),
                8 => observed.observed_ms = 999,
                9 => observed.observed_ms = intent.deadline_ms + 1,
                10 => observed.enforcement_sha256 = "00".repeat(32),
                11 => revision = 0,
                _ => revision = 3,
            }
            assert!(
                state
                    .apply(&Event::Applied {
                        transaction: intent.transaction.clone(),
                        expected_revision: revision,
                        observation: observed
                    })
                    .is_err(),
                "variant {variant}"
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn restore_never_accepts_an_earlier_observation_or_external_value() {
        let intent = intent();
        for variant in 0..5 {
            let mut state = prepared();
            let revision = dispatch(&mut state, WriteKind::Apply, 1100);
            state
                .apply(&Event::Applied {
                    transaction: intent.transaction.clone(),
                    expected_revision: revision,
                    observation: observation(&intent, false, 2000),
                })
                .unwrap();
            let revision = dispatch(&mut state, WriteKind::Restore, 2100);
            let before = state.clone();
            let mut observed = observation(&intent, true, 2500);
            match variant {
                0 => observed.observed_ms = 1999,
                1 => observed.observed_ms = intent.deadline_ms + CLEANUP_GRACE_MS + 1,
                2 => observed.setting = intent.after.clone(),
                3 => observed.target.boot = "ef".repeat(16),
                _ => observed.target.generation += 1,
            }
            assert!(state
                .apply(&Event::Restored {
                    transaction: intent.transaction.clone(),
                    expected_revision: revision,
                    observation: observed
                })
                .is_err());
            assert_eq!(state, before);
        }
    }

    #[test]
    fn outstanding_policy_blocks_same_device_after_boot_or_generation_change() {
        let intent = intent();
        let mut state = prepared();
        for variant in 0..3 {
            let mut changed = intent.clone();
            changed.transaction = "new-policy".into();
            changed.expected_revision = 1;
            match variant {
                0 => changed.target.boot = "ef".repeat(16),
                1 => changed.target.generation += 1,
                _ => changed.target.resource.as_mut().unwrap().manager_epoch = "cd".repeat(16),
            }
            assert!(state.apply(&Event::Prepare { intent: changed }).is_err());
        }
    }

    #[test]
    fn fenced_uncertainty_cannot_restore_reapply_or_revive_from_a_receipt() {
        let intent = intent();
        let mut state = prepared();
        state
            .apply(&Event::Fenced {
                transaction: intent.transaction.clone(),
                expected_revision: 1,
                reason: FenceReason::ExternalDrift,
            })
            .unwrap();
        let before = state.clone();
        for event in [
            Event::Applied {
                transaction: intent.transaction.clone(),
                expected_revision: 2,
                observation: observation(&intent, false, 2000),
            },
            Event::Restored {
                transaction: intent.transaction.clone(),
                expected_revision: 2,
                observation: observation(&intent, true, 2000),
            },
            Event::Fenced {
                transaction: intent.transaction.clone(),
                expected_revision: 2,
                reason: FenceReason::DeadlineExpired,
            },
        ] {
            assert!(state.apply(&event).is_err());
            assert_eq!(state, before);
        }
    }

    #[test]
    fn explicit_reconciliation_retains_external_state_instead_of_guessing_restore() {
        let intent = intent();
        let mut state = prepared();
        let mut current = observation(&intent, false, 4000);
        current.target.boot = "ab".repeat(16);
        current.target.generation += 1;
        current.setting = Setting::CpuQuota {
            quota_us: 75_000,
            period_us: 100_000,
        };
        state
            .apply(&Event::Reconciled {
                transaction: intent.transaction.clone(),
                expected_revision: 1,
                disposition: Reconciliation::ExternalStateRetained,
                observation: Some(current.clone()),
            })
            .unwrap();
        let committed = &state.transactions[&intent.transaction];
        assert_eq!(committed.phase, Phase::Reconciled);
        assert_eq!(committed.observation, Some(current));
    }

    #[test]
    fn reconciliation_does_not_substitute_device_or_unobserved_baseline() {
        let intent = intent();
        for variant in 0..4 {
            let mut state = prepared();
            let mut observed = Some(observation(&intent, true, 2000));
            let mut disposition = Reconciliation::BaselineObserved;
            match variant {
                0 => observed.as_mut().unwrap().target.identity_sha256 = "ab".repeat(32),
                1 => observed.as_mut().unwrap().setting = intent.after.clone(),
                2 => observed = None,
                _ => disposition = Reconciliation::DeviceUnavailable,
            }
            let before = state.clone();
            assert!(state
                .apply(&Event::Reconciled {
                    transaction: intent.transaction.clone(),
                    expected_revision: 1,
                    disposition,
                    observation: observed
                })
                .is_err());
            assert_eq!(state, before);
        }
        let mut state = prepared();
        state
            .apply(&Event::Reconciled {
                transaction: intent.transaction,
                expected_revision: 1,
                disposition: Reconciliation::DeviceUnavailable,
                observation: None,
            })
            .unwrap();
    }

    #[test]
    fn all_three_hardware_actions_are_distinct_from_every_other_authority() {
        let intent = intent();
        for action in [
            Action::Read,
            Action::Infer,
            Action::StartWorker,
            Action::AcquireResource,
            Action::ExecuteGenerated,
            Action::InspectHardware,
        ] {
            assert!(intent.usage(action).is_err());
        }
        let apply = intent.usage(Action::ApplyHardware).unwrap();
        let restore = intent.usage(Action::RestoreHardware).unwrap();
        assert_ne!(apply, restore);
        assert_eq!(apply.selector.digest, restore.selector.digest);
    }

    #[test]
    fn catalog_hardware_mutation_requires_both_actual_finite_grants() {
        let intent = intent();
        let mut catalog = catalog(&intent);
        let authorization = authorization(&intent);
        catalog
            .apply(&Command::HardwarePolicyEvent {
                event: Event::Prepare {
                    intent: intent.clone(),
                },
                authorization,
            })
            .unwrap();
        assert_eq!(
            catalog.hardware_policies.transactions[&intent.transaction].phase,
            Phase::Prepared
        );
    }

    #[test]
    fn recorded_authority_is_replayed_against_exact_prior_role_grant_and_interval() {
        let intent = intent();
        for variant in 0..12 {
            let mut catalog = catalog(&intent);
            let mut authorization = authorization(&intent);
            match variant {
                0 => catalog.grants.get_mut(&intent.apply_grant).unwrap().revoked = true,
                1 => {
                    catalog
                        .grants
                        .get_mut(&intent.restore_grant)
                        .unwrap()
                        .revoked = true
                }
                2 => {
                    catalog
                        .assignments
                        .get_mut("hardware-operator")
                        .unwrap()
                        .revoked = true
                }
                3 => catalog.roles.get_mut("Hardware").unwrap().version += 1,
                4 => authorization.subject = "ef".repeat(32),
                5 => authorization.subject_generation += 1,
                6 => authorization.uses.pop().map(|_| ()).unwrap(),
                7 => authorization.uses.swap(0, 1),
                8 => authorization.uses[0].1.selector.digest = "ab".repeat(32),
                9 => authorization.lower_ms = 1999,
                10 => authorization.upper_ms = 9000,
                _ => authorization.uses[1].0 = authorization.uses[0].0.clone(),
            }
            let before = catalog.clone();
            assert!(
                catalog
                    .apply(&Command::HardwarePolicyEvent {
                        event: Event::Prepare {
                            intent: intent.clone()
                        },
                        authorization
                    })
                    .is_err(),
                "variant {variant}"
            );
            assert_eq!(catalog, before);
        }
    }

    #[test]
    fn cleanup_grant_is_not_replaced_when_original_apply_scope_expires() {
        let intent = intent();
        let state = prepared();
        let event = Event::Restored {
            transaction: intent.transaction.clone(),
            expected_revision: 1,
            observation: observation(&intent, true, 2000),
        };
        assert!(event.uses(&state, Some("fresh-grant")).is_err());
        let scopes = event.uses(&state, None).unwrap();
        assert_eq!(scopes[0].0, intent.apply_grant);
        assert_eq!(scopes[1].0, intent.restore_grant);
        let event = Event::Reconciled {
            transaction: intent.transaction.clone(),
            expected_revision: 1,
            disposition: Reconciliation::DeviceUnavailable,
            observation: None,
        };
        assert!(event.uses(&state, None).is_err());
        let fresh = event.uses(&state, Some("fresh-reconcile")).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_ne!(fresh[0].1.selector.digest, intent.digest().unwrap());
    }

    #[test]
    fn memory_profile_requires_an_admitted_drained_model_generation() {
        let mut intent = intent();
        intent.target.adapter = Adapter::MemoryProfile;
        intent.before = Setting::MemoryProfile {
            profile: "qwen3-4b-q4-k-m".into(),
            bytes: 4 * 1024 * 1024 * 1024,
        };
        intent.after = Setting::MemoryProfile {
            profile: "qwen3-4b-q4-k-m".into(),
            bytes: 2 * 1024 * 1024 * 1024,
        };
        intent.validate().unwrap();
        let original = intent.after.clone();
        intent.after = Setting::MemoryProfile {
            profile: "qwen3-1-7b-q4-k-m".into(),
            bytes: 2 * 1024 * 1024 * 1024,
        };
        assert!(intent.validate().is_err());
        intent.after = Setting::MemoryProfile {
            profile: "qwen3-4b-q4-k-m".into(),
            bytes: 5 * 1024 * 1024 * 1024,
        };
        assert!(intent.validate().is_err());
        intent.after = original;
        let original_before = intent.before.clone();
        intent.before = Setting::MemoryProfile {
            profile: "qwen3-4b-q4-k-m".into(),
            bytes: 5 * 1024 * 1024 * 1024,
        };
        assert!(intent.validate().is_err());
        intent.before = original_before;
        intent.target.worker = Some(Worker::Acquisition);
        assert!(intent.validate().is_err());
        intent.target.worker = Some(Worker::Model);
        let resource = intent.target.resource.as_mut().unwrap();
        resource.lease = Some(resources::Token {
            lease_id: "ab".repeat(16),
            manager_epoch: resource.manager_epoch.clone(),
            generation: 1,
        });
        assert!(intent.validate().is_err());
    }

    #[test]
    fn reconciliation_grants_bind_reviewed_semantics_not_fresh_observation_stopwatches() {
        let intent = intent();
        let mut state = State::default();
        state
            .apply(&Event::Prepare {
                intent: intent.clone(),
            })
            .unwrap();
        let first = observation(&intent, true, 1100);
        let event = Event::Reconciled {
            transaction: intent.transaction.clone(),
            expected_revision: 1,
            disposition: Reconciliation::BaselineObserved,
            observation: Some(first.clone()),
        };
        let usage = event.uses(&state, Some("fresh-reconcile-one")).unwrap();
        let plan = ReconciliationPlan {
            schema_version: 1,
            transaction: intent.transaction.clone(),
            expected_revision: 1,
            disposition: Reconciliation::BaselineObserved,
            observation: Some(ReviewedObservation {
                target: first.target,
                setting: first.setting,
            }),
        };
        assert_eq!(usage[0].1, plan.usage(&intent).unwrap());
        let mut later = event.clone();
        if let Event::Reconciled {
            observation: Some(value),
            ..
        } = &mut later
        {
            value.observed_ms = 2200;
            value.enforcement_sha256 = "ab".repeat(32);
        }
        assert_eq!(
            usage,
            later.uses(&state, Some("fresh-reconcile-one")).unwrap()
        );
        let mut changed = plan.clone();
        changed.expected_revision += 1;
        assert_ne!(usage[0].1, changed.usage(&intent).unwrap());
        changed = plan.clone();
        changed.observation.as_mut().unwrap().target.generation += 1;
        assert_ne!(usage[0].1, changed.usage(&intent).unwrap());
        changed = plan.clone();
        changed.observation.as_mut().unwrap().setting = intent.after.clone();
        assert!(changed.usage(&intent).is_err());
        changed = plan;
        changed.disposition = Reconciliation::DeviceUnavailable;
        assert!(changed.usage(&intent).is_err());
    }

    #[test]
    fn dispatch_is_durable_single_attempt_and_cannot_clear_a_queued_external_effect() {
        let mut intent = intent();
        intent.target.adapter = Adapter::PowerProfiles;
        intent.target.worker = None;
        intent.target.resource = None;
        intent.before = Setting::PowerProfiles {
            profile: PowerProfile::Balanced,
        };
        intent.after = Setting::PowerProfiles {
            profile: PowerProfile::PowerSaver,
        };
        let mut state = State::default();
        state
            .apply(&Event::Prepare {
                intent: intent.clone(),
            })
            .unwrap();
        assert!(state
            .apply(&Event::Applied {
                transaction: intent.transaction.clone(),
                expected_revision: 1,
                observation: observation(&intent, false, 1400)
            })
            .is_err());
        let event = Event::DispatchStarted {
            transaction: intent.transaction.clone(),
            expected_revision: 1,
            dispatch: Dispatch {
                kind: WriteKind::Apply,
                started_ms: 1200,
                witness: Some(DispatchWitness {
                    pid: 23,
                    start_ticks: 19,
                    unique_name: ":1.42".into(),
                    exe_sha256: "9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a"
                        .into(),
                }),
            },
        };
        state.apply(&event).unwrap();
        let current = state.clone();
        assert!(state.apply(&event).is_err());
        assert_eq!(state, current);
        assert!(state.transactions[&intent.transaction]
            .ambiguous_external_dispatch()
            .is_some());
        assert!(state
            .apply(&Event::Restored {
                transaction: intent.transaction.clone(),
                expected_revision: 2,
                observation: observation(&intent, true, 1500)
            })
            .is_err());
        assert_eq!(state, current);
        state
            .apply(&Event::Applied {
                transaction: intent.transaction.clone(),
                expected_revision: 2,
                observation: observation(&intent, false, 1400),
            })
            .unwrap();
        assert!(state.transactions[&intent.transaction]
            .ambiguous_external_dispatch()
            .is_none());
        let mut restore = event;
        if let Event::DispatchStarted {
            dispatch,
            expected_revision,
            ..
        } = &mut restore
        {
            *expected_revision = 3;
            dispatch.kind = WriteKind::Restore;
            dispatch.started_ms = 1600;
        }
        state.apply(&restore).unwrap();
        assert!(state.transactions[&intent.transaction]
            .ambiguous_external_dispatch()
            .is_some());
        assert!(state.apply(&restore).is_err());
        state
            .apply(&Event::Restored {
                transaction: intent.transaction.clone(),
                expected_revision: 4,
                observation: observation(&intent, true, 1700),
            })
            .unwrap();
        assert!(state.transactions[&intent.transaction]
            .ambiguous_external_dispatch()
            .is_none());
    }

    #[test]
    fn actual_process_death_not_a_baseline_receipt_retires_a_daemon_dispatch_generation() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        struct Child<'a>(&'a mut std::process::Child);
        impl Drop for Child<'_> {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Child(&mut child);
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.0.id())).unwrap();
        let start = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let witness = DispatchWitness {
            pid: child.0.id(),
            start_ticks: start,
            unique_name: ":1.42".into(),
            exe_sha256: "12".repeat(32),
        };
        let boot = current_boot().unwrap();
        assert!(witness.require_exited(&boot).is_err());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        witness.require_exited(&boot).unwrap();
    }

    #[test]
    fn compiled_bounds_never_admit_raw_paths_performance_or_unbounded_values() {
        for setting in [
            Setting::CpuQuota {
                quota_us: 0,
                period_us: 100_000,
            },
            Setting::CpuQuota {
                quota_us: 200_001,
                period_us: 100_000,
            },
            Setting::CpuWeight { weight: 0 },
            Setting::CpuWeight { weight: 10001 },
            Setting::MemoryProfile {
                profile: "caller-chosen".into(),
                bytes: 1024 * 1024,
            },
            Setting::StorageRate {
                device: "/dev/sda".into(),
                read_bytes_per_second: 1,
                write_bytes_per_second: 1,
            },
            Setting::StorageRate {
                device: "008:0".into(),
                read_bytes_per_second: 1,
                write_bytes_per_second: 1,
            },
            Setting::Backlight {
                brightness: 101,
                maximum: 100,
            },
        ] {
            assert!(setting.validate().is_err());
        }
        assert!(serde_json::from_str::<PowerProfile>("\"performance\"").is_err());
        assert!(serde_json::from_str::<Adapter>("\"register-write\"").is_err());
    }

    #[test]
    fn lifetime_and_safety_contract_cannot_be_extended_or_silently_nooped() {
        for variant in 0..7 {
            let mut intent = intent();
            match variant {
                0 => intent.deadline_ms = intent.created_ms,
                1 => intent.deadline_ms += 1,
                2 => intent.before = intent.after.clone(),
                3 => intent.restore_grant = intent.apply_grant.clone(),
                4 => intent.cleanup = "always-restore".into(),
                5 => intent.target.boot = "00".repeat(16),
                _ => intent.expected_revision = u64::MAX - 4,
            }
            assert!(intent.validate().is_err());
        }
    }

    #[test]
    fn duplicate_json_fields_and_unknown_policy_members_are_refused() {
        let intent = intent();
        let bytes = serde_json::to_string(&intent).unwrap();
        let doubled = bytes.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(serde_json::from_str::<Intent>(&doubled).is_err());
        let unknown = bytes.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"shell\":\"true\"",
            1,
        );
        assert!(serde_json::from_str::<Intent>(&unknown).is_err());
        assert_eq!(serde_json::from_str::<Intent>(&bytes).unwrap(), intent);
    }
}
