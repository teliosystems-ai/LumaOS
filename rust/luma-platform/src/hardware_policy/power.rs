//! Pinned Ubuntu PPD0.21 direct local-bus adapter. No powerprofilesctl, shell,
//! child after PAM, daemon activation, performance profile or profile hold.
//! The current Admin lock plus image writer mediation serializes product
//! writes; D-Bus exposes no atomic compare-and-set against trusted OS changes.
use super::daemon_observer::{self, Proof, Role};
use super::sd_bus::{Budget, Bus, Message, Owner};
use super::{
    current_boot, hash, Adapter, Observation, Phase, PowerProfile, Result, Setting, Target,
    Transition, WriteKind,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const SERVICE: &str = "org.freedesktop.UPower.PowerProfiles";
const LEGACY: &str = "net.hadess.PowerProfiles";
const PATH: &str = "/org/freedesktop/UPower/PowerProfiles";
const EXECUTABLE: &str = "/usr/libexec/power-profiles-daemon";
const EXECUTABLE_SHA: &str = "9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a";
type FileIdentity = (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);
fn identity(metadata: &fs::Metadata) -> Result<FileIdentity> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o755
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err("power daemon is not the bounded protected executable".into());
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}
fn require_process(
    proof: &Proof,
    owner: &Owner,
    executable: &FileIdentity,
    boot: &str,
) -> Result<()> {
    if proof.pid != owner.pid
        || proof.start_ticks != owner.start_ticks
        || proof.uid != 0
        || proof.gid != 0
        || proof.boot != boot
        || proof.exe_dev != executable.0
        || proof.exe_inode != executable.1
        || proof.exe_sha256 != EXECUTABLE_SHA
        || proof.cgroup != "0::/system.slice/power-profiles-daemon.service\n"
    {
        return Err(
            "actual power-profile daemon role/executable/credentials/unit binding differs".into(),
        );
    }
    Ok(())
}
fn profile_name(profile: PowerProfile) -> &'static str {
    match profile {
        PowerProfile::Balanced => "balanced",
        PowerProfile::PowerSaver => "power-saver",
    }
}
fn selected(value: &str) -> Result<PowerProfile> {
    match value {
        "balanced" => Ok(PowerProfile::Balanced),
        "power-saver" => Ok(PowerProfile::PowerSaver),
        _ => Err(
            "active power profile is outside the supported balanced/power-saver contract".into(),
        ),
    }
}
fn write_decision(
    phase: Phase,
    kind: WriteKind,
    before: &Setting,
    after: &Setting,
    observed: &Setting,
) -> Result<bool> {
    if !matches!(
        (before, after),
        (Setting::PowerProfiles { .. }, Setting::PowerProfiles { .. })
    ) || before == after
    {
        return Err("power transition is not a distinct exact typed pair".into());
    }
    if kind == WriteKind::Apply && phase != Phase::Prepared
        || kind == WriteKind::Restore && !matches!(phase, Phase::Prepared | Phase::Applied)
    {
        return Err("power-profile write is outside its exact prepared/applied lifecycle".into());
    }
    let unwritten = kind == WriteKind::Restore && phase == Phase::Prepared && observed == before;
    if !unwritten
        && observed
            != match kind {
                WriteKind::Apply => before,
                WriteKind::Restore => after,
            }
    {
        return Err("power-profile external drift prevents exact apply/undo; no retry".into());
    }
    Ok(unwritten)
}
fn require_dispatch(
    transition: &Transition,
    kind: WriteKind,
    witness: &super::DispatchWitness,
    unwritten: bool,
) -> Result<()> {
    if unwritten {
        if transition.phase != Phase::Prepared || !transition.dispatches.is_empty() {
            return Err("power baseline cannot erase a possibly queued external dispatch".into());
        }
        return Ok(());
    }
    let expected = match kind {
        WriteKind::Apply => 1,
        WriteKind::Restore => 2,
    };
    if transition.dispatches.len() != expected
        || kind == WriteKind::Restore && transition.phase != Phase::Applied
        || transition
            .dispatches
            .iter()
            .any(|dispatch| dispatch.witness.as_ref() != Some(witness))
        || transition.dispatches.last().map(|dispatch| dispatch.kind) != Some(kind)
    {
        return Err(
            "power Set lacks its exact one-use durable dispatch and current pinned daemon witness"
                .into(),
        );
    }
    Ok(())
}
fn enter(message: &mut Message<'_>, kind: u8, signature: &str) -> Result<()> {
    if !message.enter(kind, signature)? {
        return Err("power property omitted its exact typed container".into());
    }
    Ok(())
}
fn get_string(bus: &Bus, owner: &Owner, name: &str, budget: &Budget) -> Result<String> {
    let mut reply = bus.property(owner, PATH, SERVICE, name, budget)?;
    enter(&mut reply, b'v', "s")?;
    let result = reply.read_string(128)?;
    reply.exit()?;
    reply.end()?;
    budget.check()?;
    Ok(result)
}
fn profile_maps(message: &mut Message<'_>) -> Result<Vec<BTreeMap<String, String>>> {
    enter(message, b'v', "aa{sv}")?;
    enter(message, b'a', "a{sv}")?;
    let mut profiles = Vec::new();
    while !message.at_end()? {
        if profiles.len() >= 3 {
            return Err("power profile list exceeds its closed bound".into());
        }
        enter(message, b'a', "{sv}")?;
        let mut fields = BTreeMap::new();
        while !message.at_end()? {
            if fields.len() >= 4 {
                return Err("power profile dictionary exceeds its closed bound".into());
            }
            enter(message, b'e', "sv")?;
            let name = message.read_string(32)?;
            if !matches!(
                name.as_str(),
                "Profile" | "Driver" | "CpuDriver" | "PlatformDriver"
            ) || fields.contains_key(&name)
            {
                return Err("unknown or duplicate power-profile capability".into());
            }
            enter(message, b'v', "s")?;
            let value = message.read_string(128)?;
            message.exit()?;
            message.exit()?;
            fields.insert(name, value);
        }
        message.exit()?;
        profiles.push(fields);
    }
    message.exit()?;
    message.exit()?;
    message.end()?;
    validate_profiles(&profiles)?;
    Ok(profiles)
}
fn validate_profiles(profiles: &[BTreeMap<String, String>]) -> Result<()> {
    if !(2..=3).contains(&profiles.len()) {
        return Err("power daemon does not expose the required two bounded profiles".into());
    }
    for (index, fields) in profiles.iter().enumerate() {
        let name = fields.get("Profile").ok_or("power profile name absent")?;
        if name != ["power-saver", "balanced", "performance"][index]
            || fields.len() < 2
            || fields.len() > 4
        {
            return Err("power profile identity/order/driver capabilities differ".into());
        }
        let mut actual_driver = false;
        for (key, value) in fields {
            if key == "Profile" {
                continue;
            }
            if !matches!(key.as_str(), "Driver" | "CpuDriver" | "PlatformDriver")
                || !matches!(
                    value.as_str(),
                    "intel_pstate" | "amd_pstate" | "platform_profile" | "multiple" | ""
                )
            {
                return Err(
                    "power profile driver is not qualified; no fallback backend is adopted".into(),
                );
            }
            actual_driver |= matches!(
                value.as_str(),
                "intel_pstate" | "amd_pstate" | "platform_profile"
            );
        }
        if !actual_driver {
            return Err("power profile has no supported actual hardware driver".into());
        }
    }
    Ok(())
}
fn profiles(bus: &Bus, owner: &Owner, budget: &Budget) -> Result<Vec<BTreeMap<String, String>>> {
    let mut reply = bus.property(owner, PATH, SERVICE, "Profiles", budget)?;
    let value = profile_maps(&mut reply)?;
    budget.check()?;
    Ok(value)
}
fn no_holds(bus: &Bus, owner: &Owner, budget: &Budget) -> Result<()> {
    let mut reply = bus.property(owner, PATH, SERVICE, "ActiveProfileHolds", budget)?;
    enter(&mut reply, b'v', "aa{sv}")?;
    enter(&mut reply, b'a', "a{sv}")?;
    if !reply.at_end()? {
        return Err(
            "power profile holds already own global state; no side effect is admitted".into(),
        );
    }
    reply.exit()?;
    reply.exit()?;
    reply.end()?;
    budget.check()
}
pub(crate) struct Control<'image> {
    image: &'image super::image::Image,
    bus: Bus,
    owner: Owner,
    executable: File,
    executable_identity: FileIdentity,
    pidfd: File,
    process: Proof,
    boot: String,
    target: Target,
    profiles: Vec<BTreeMap<String, String>>,
}
impl<'image> Control<'image> {
    pub(crate) fn open(image: &'image super::image::Image) -> Result<Self> {
        let budget = Budget::new()?;
        image.check()?;
        budget.check()?;
        for parent in ["/", "/usr", "/usr/libexec"] {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
                return Err("power daemon ancestor is not protected".into());
            }
        }
        let mut executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(EXECUTABLE)?;
        let executable_identity = identity(&executable.metadata()?)?;
        let mut body = Vec::new();
        (&mut executable)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 != executable_identity.2
            || crate::bundle::hex(&Sha256::digest(&body)) != EXECUTABLE_SHA
            || identity(&executable.metadata()?)? != executable_identity
        {
            return Err("actual power daemon bytes differ from pinned Ubuntu0.21-1ubuntu3".into());
        }
        budget.check()?;
        let bus = Bus::open(&budget)?;
        let owner = bus.owner(SERVICE, &budget)?;
        if owner.uid != 0 || bus.owner(LEGACY, &budget)? != owner {
            return Err(
                "power-profile aliases do not share the same actual root daemon generation".into(),
            );
        }
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, owner.pid, 0) } as i32;
        if pidfd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pidfd = unsafe { File::from_raw_fd(pidfd) };
        if get_string(&bus, &owner, "Version", &budget)? != "0.21" {
            return Err("power daemon API version differs from pinned0.21".into());
        }
        let profiles = profiles(&bus, &owner, &budget)?;
        no_holds(&bus, &owner, &budget)?;
        let boot = current_boot()?;
        let process = daemon_observer::verify(Role::PowerProfiles, &pidfd, &budget)?;
        require_process(&process, &owner, &executable_identity, &boot)?;
        let target = Target {
            adapter: Adapter::PowerProfiles,
            worker: None,
            resource: None,
            identity_sha256: hash(&("luma-fixed-native-power-profile-slot-v1", SERVICE))?,
            capability_sha256: hash(&(
                "luma-actual-pinned-power-profile-capability-v1",
                EXECUTABLE_SHA,
                "0.21-1ubuntu3",
                &profiles,
                &owner.unique_name,
                owner.pid,
                owner.uid,
                bus.generation(),
                &image.closure_sha256,
            ))?,
            adapter_sha256: hash(&(
                "luma-native-power-profile-adapter-source-v1",
                include_bytes!("power.rs").as_slice(),
                include_bytes!("sd_bus.rs").as_slice(),
            ))?,
            boot: boot.clone(),
            generation: owner.start_ticks,
        };
        target.validate()?;
        let result = Self {
            image,
            bus,
            owner,
            executable,
            executable_identity,
            pidfd,
            process,
            boot,
            target,
            profiles,
        };
        result.observe_with(&budget)?;
        result.verify_proofs(&budget)?;
        Ok(result)
    }
    fn check(&self, budget: &Budget) -> Result<()> {
        budget.check()?;
        self.image.check()?;
        if current_boot()? != self.boot
            || identity(&self.executable.metadata()?)? != self.executable_identity
            || identity(&fs::symlink_metadata(EXECUTABLE)?)? != self.executable_identity
        {
            return Err("power daemon boot or held executable changed".into());
        }
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, 0) } != 0 {
            return Err("original power daemon exited or is unobserved".into());
        }
        self.bus.check_owner(SERVICE, &self.owner, budget)?;
        self.bus.check_owner(LEGACY, &self.owner, budget)?;
        if get_string(&self.bus, &self.owner, "Version", budget)? != "0.21"
            || profiles(&self.bus, &self.owner, budget)? != self.profiles
        {
            return Err("power profile runtime capabilities changed".into());
        }
        budget.check()
    }
    fn verify_proofs(&self, budget: &Budget) -> Result<()> {
        self.check(budget)?;
        self.bus.verify_proofs(budget)?;
        let process = daemon_observer::verify(Role::PowerProfiles, &self.pidfd, budget)?;
        require_process(&process, &self.owner, &self.executable_identity, &self.boot)?;
        if process != self.process {
            return Err("actual power daemon changed executable/credentials despite retained PID generation".into());
        }
        self.check(budget)
    }
    fn observe_with(&self, budget: &Budget) -> Result<Setting> {
        self.check(budget)?;
        no_holds(&self.bus, &self.owner, budget)?;
        let profile = selected(&get_string(
            &self.bus,
            &self.owner,
            "ActiveProfile",
            budget,
        )?)?;
        budget.check()?;
        Ok(Setting::PowerProfiles { profile })
    }
    pub(crate) fn target(&self) -> Result<Target> {
        let budget = Budget::new()?;
        self.verify_proofs(&budget)?;
        let target = self.target.clone();
        self.verify_proofs(&budget)?;
        Ok(target)
    }
    pub(crate) fn dispatch_witness(&self) -> Result<Option<super::DispatchWitness>> {
        let budget = Budget::new()?;
        self.verify_proofs(&budget)?;
        Ok(Some(self.witness()))
    }
    fn witness(&self) -> super::DispatchWitness {
        super::DispatchWitness {
            pid: self.owner.pid,
            start_ticks: self.owner.start_ticks,
            unique_name: self.owner.unique_name.clone(),
            exe_sha256: self.process.exe_sha256.clone(),
        }
    }
    pub(crate) fn observe(&self) -> Result<Setting> {
        let budget = Budget::new()?;
        self.verify_proofs(&budget)?;
        let observed = self.observe_with(&budget)?;
        self.verify_proofs(&budget)?;
        Ok(observed)
    }
    pub(crate) fn compare_write(
        &self,
        transition: &Transition,
        kind: WriteKind,
    ) -> Result<Observation> {
        let budget = Budget::new()?;
        transition.intent.validate()?;
        self.verify_proofs(&budget)?;
        let intent = &transition.intent;
        if intent.target != self.target {
            return Err(
                "power-profile target is not the exact live daemon generation/capability".into(),
            );
        }
        let observed = self.observe_with(&budget)?;
        let replacement = match kind {
            WriteKind::Apply => &intent.after,
            WriteKind::Restore => &intent.before,
        };
        let unwritten = write_decision(
            transition.phase,
            kind,
            &intent.before,
            &intent.after,
            &observed,
        )?;
        require_dispatch(transition, kind, &self.witness(), unwritten)?;
        let Setting::PowerProfiles { profile } = replacement else {
            return Err("power replacement belongs to another adapter".into());
        };
        if !unwritten {
            self.check(&budget)?;
            no_holds(&self.bus, &self.owner, &budget)?;
            let mut request = self.bus.method(
                &self.owner.unique_name,
                PATH,
                "org.freedesktop.DBus.Properties",
                "Set",
            )?;
            request.append_string(SERVICE)?;
            request.append_string("ActiveProfile")?;
            request.open(b'v', "s")?;
            request.append_string(profile_name(*profile))?;
            request.close()?;
            // Exactly one Set, addressed to the held unique owner. A failed or
            // late reply never causes redispatch; cleanup remains committed.
            request.call(&budget)?.end()?;
        }
        let actual = self.observe_with(&budget)?;
        if actual != *replacement {
            return Err("power profile did not read back exactly; preserve obligation".into());
        }
        self.verify_proofs(&budget)?;
        let observation = Observation {
            target: self.target.clone(),
            setting: actual,
            observed_ms: crate::resource_manager::now()?,
            enforcement_sha256: hash(&(
                if unwritten {
                    "luma-power-prepared-baseline-observed-no-write-v1"
                } else {
                    "luma-power-one-unique-owner-set-exact-readback-v1"
                },
                &intent.target,
                replacement,
            ))?,
        };
        observation.validate()?;
        budget.check()?;
        Ok(observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn advertised() -> Vec<BTreeMap<String, String>> {
        ["power-saver", "balanced", "performance"]
            .into_iter()
            .map(|profile| {
                BTreeMap::from([
                    ("Profile".into(), profile.into()),
                    ("Driver".into(), "intel_pstate".into()),
                ])
            })
            .collect()
    }
    fn advertised_message<'a>(
        bus: &'a Bus,
        profiles: &[BTreeMap<String, String>],
        trailing: bool,
    ) -> Message<'a> {
        let mut message = bus
            .method(":1.23", PATH, "org.freedesktop.DBus.Properties", "Get")
            .unwrap();
        message.open(b'v', "aa{sv}").unwrap();
        message.open(b'a', "a{sv}").unwrap();
        for fields in profiles {
            message.open(b'a', "{sv}").unwrap();
            for (key, value) in fields {
                message.open(b'e', "sv").unwrap();
                message.append_string(key).unwrap();
                message.open(b'v', "s").unwrap();
                message.append_string(value).unwrap();
                message.close().unwrap();
                message.close().unwrap();
            }
            message.close().unwrap();
        }
        message.close().unwrap();
        message.close().unwrap();
        if trailing {
            message.append_string("extra").unwrap();
        }
        message.freeze_fixture().unwrap();
        message
    }
    #[test]
    fn actual_library_profiles_codec_accepts_only_whole_closed_capability_shape() {
        let bus = Bus::fixture().unwrap();
        for count in [2, 3] {
            let profiles = advertised()[..count].to_vec();
            let mut message = advertised_message(&bus, &profiles, false);
            assert_eq!(profile_maps(&mut message).unwrap(), profiles);
        }
        for count in [0, 1, 4] {
            let mut profiles = advertised();
            profiles.resize_with(count, || {
                BTreeMap::from([
                    ("Profile".into(), "balanced".into()),
                    ("Driver".into(), "intel_pstate".into()),
                ])
            });
            let mut message = advertised_message(&bus, &profiles, false);
            assert!(profile_maps(&mut message).is_err());
        }
        let mut message = advertised_message(&bus, &advertised(), true);
        assert!(profile_maps(&mut message).is_err());
        let mut profiles = advertised();
        profiles[0].insert("Unknown".into(), "intel_pstate".into());
        let mut message = advertised_message(&bus, &profiles, false);
        assert!(profile_maps(&mut message).is_err());
        let mut message = bus
            .method(":1.23", PATH, "org.freedesktop.DBus.Properties", "Get")
            .unwrap();
        message.open(b'v', "s").unwrap();
        message.append_string("not a profile array").unwrap();
        message.close().unwrap();
        message.freeze_fixture().unwrap();
        assert!(profile_maps(&mut message).is_err());
    }
    #[test]
    fn only_balanced_or_power_saver_can_be_selected_or_restored() {
        assert_eq!(selected("balanced").unwrap(), PowerProfile::Balanced);
        assert_eq!(selected("power-saver").unwrap(), PowerProfile::PowerSaver);
        for profile in [
            "performance",
            "",
            "Balanced",
            "balanced\n",
            "balanced;reboot",
        ] {
            assert!(selected(profile).is_err());
        }
    }
    #[test]
    fn exact_power_compare_and_prepared_only_baseline_cleanup() {
        let before = Setting::PowerProfiles {
            profile: PowerProfile::Balanced,
        };
        let after = Setting::PowerProfiles {
            profile: PowerProfile::PowerSaver,
        };
        let wrong = Setting::Backlight {
            brightness: 10,
            maximum: 100,
        };
        assert!(
            !write_decision(Phase::Prepared, WriteKind::Apply, &before, &after, &before).unwrap()
        );
        assert!(
            !write_decision(Phase::Applied, WriteKind::Restore, &before, &after, &after).unwrap()
        );
        assert!(
            !write_decision(Phase::Prepared, WriteKind::Restore, &before, &after, &after).unwrap()
        );
        assert!(write_decision(
            Phase::Prepared,
            WriteKind::Restore,
            &before,
            &after,
            &before
        )
        .unwrap());
        assert!(
            write_decision(Phase::Applied, WriteKind::Restore, &before, &after, &before).is_err()
        );
        assert!(
            write_decision(Phase::Prepared, WriteKind::Apply, &before, &after, &after).is_err()
        );
        for phase in [
            Phase::Prepared,
            Phase::Applied,
            Phase::Restored,
            Phase::Fenced,
            Phase::Reconciled,
        ] {
            for kind in [WriteKind::Apply, WriteKind::Restore] {
                assert!(write_decision(phase, kind, &before, &after, &wrong).is_err());
            }
        }
        for phase in [
            Phase::Applied,
            Phase::Restored,
            Phase::Fenced,
            Phase::Reconciled,
        ] {
            assert!(write_decision(phase, WriteKind::Apply, &before, &after, &before).is_err());
        }
        for phase in [Phase::Restored, Phase::Fenced, Phase::Reconciled] {
            assert!(write_decision(phase, WriteKind::Restore, &before, &after, &after).is_err());
        }
        assert!(
            write_decision(Phase::Prepared, WriteKind::Apply, &before, &before, &before).is_err()
        );
        assert!(
            write_decision(Phase::Prepared, WriteKind::Apply, &before, &wrong, &before).is_err()
        );
    }
    #[test]
    fn queued_or_interrupted_external_dispatch_never_becomes_baseline_success_or_new_send() {
        let mut transition = super::super::Transition {
            intent: super::super::tests::intent(),
            revision: 1,
            phase: Phase::Prepared,
            observation: None,
            fence: None,
            reconciliation: None,
            dispatches: Vec::new(),
        };
        let witness = super::super::DispatchWitness {
            pid: 23,
            start_ticks: 42,
            unique_name: ":1.23".into(),
            exe_sha256: EXECUTABLE_SHA.into(),
        };
        require_dispatch(&transition, WriteKind::Restore, &witness, true).unwrap();
        assert!(require_dispatch(&transition, WriteKind::Apply, &witness, false).is_err());
        transition.dispatches.push(super::super::Dispatch {
            kind: WriteKind::Apply,
            witness: Some(witness.clone()),
            started_ms: 1,
        });
        require_dispatch(&transition, WriteKind::Apply, &witness, false).unwrap();
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, true).is_err());
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
        transition.phase = Phase::Applied;
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
        transition.dispatches.push(super::super::Dispatch {
            kind: WriteKind::Restore,
            witness: Some(witness.clone()),
            started_ms: 2,
        });
        require_dispatch(&transition, WriteKind::Restore, &witness, false).unwrap();
        assert!(require_dispatch(&transition, WriteKind::Apply, &witness, false).is_err());
        let mut other = witness.clone();
        other.start_ticks += 1;
        assert!(require_dispatch(&transition, WriteKind::Restore, &other, false).is_err());
        transition.dispatches[0].witness = None;
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
    }
    #[test]
    fn actual_driver_profiles_are_closed_ordered_nonduplicate_and_bounded() {
        validate_profiles(&advertised()).unwrap();
        validate_profiles(&advertised()[..2]).unwrap();
        let mut profiles = advertised();
        profiles.swap(0, 1);
        assert!(validate_profiles(&profiles).is_err());
        let mut profiles = advertised();
        profiles[1].insert("Driver".into(), "placeholder".into());
        assert!(validate_profiles(&profiles).is_err());
        let mut profiles = advertised();
        profiles[1].remove("Driver");
        assert!(validate_profiles(&profiles).is_err());
        let mut profiles = advertised();
        profiles[1].insert("Unexpected".into(), "intel_pstate".into());
        assert!(validate_profiles(&profiles).is_err());
        let mut profiles = advertised();
        profiles[1].insert("Driver".into(), "multiple".into());
        profiles[1].insert("CpuDriver".into(), "amd_pstate".into());
        profiles[1].insert("PlatformDriver".into(), "platform_profile".into());
        validate_profiles(&profiles).unwrap();
        assert!(validate_profiles(&advertised()[..1]).is_err());
    }
    #[test]
    fn daemon_observation_must_bind_role_digest_inode_boot_and_actual_owner() {
        let owner = Owner {
            unique_name: ":1.23".into(),
            pid: 234,
            uid: 0,
            start_ticks: 567,
        };
        let executable = (1, 2, 100, 0, 0, 0o100755, 1, 0, 0, 0, 0);
        let boot = "a".repeat(32);
        let proof = Proof {
            pid: 234,
            start_ticks: 567,
            uid: 0,
            gid: 0,
            exe_dev: 1,
            exe_inode: 2,
            exe_sha256: EXECUTABLE_SHA.into(),
            cgroup: "0::/system.slice/power-profiles-daemon.service\n".into(),
            boot: boot.clone(),
        };
        require_process(&proof, &owner, &executable, &boot).unwrap();
        for index in 0..9 {
            let mut changed = proof.clone();
            match index {
                0 => changed.pid += 1,
                1 => changed.start_ticks += 1,
                2 => changed.uid = 1000,
                3 => changed.gid = 1000,
                4 => changed.exe_dev += 1,
                5 => changed.exe_inode += 1,
                6 => changed.exe_sha256 = "b".repeat(64),
                7 => changed.cgroup = "0::/system.slice/other.service\n".into(),
                _ => changed.boot = "b".repeat(32),
            }
            assert!(require_process(&changed, &owner, &executable, &boot).is_err());
        }
    }
}
