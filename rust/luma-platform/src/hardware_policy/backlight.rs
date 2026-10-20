//! One qualified logical intel_backlight/i915 slot. All paths/attributes are
//! compiled, actual sysfs objects are held, and every write is an exact
//! current-Admin transition. Sysfs offers no atomic cross-writer CAS: drift
//! fences the obligation; root/firmware changes are not silently overwritten
//! by retries or guessed cleanup.
use super::sd_bus::Budget;
use super::{
    current_boot, hash, Adapter, Observation, Phase, Result, Setting, Target, Transition, WriteKind,
};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const CLASS: &str = "/sys/class/backlight/intel_backlight";
const DRIVER: &str = "/sys/bus/pci/drivers/i915";
const SYSFS: u64 = 0x62656572;
type Identity = (u64, u64, u32, u32, u32);
fn identity(info: &fs::Metadata) -> Identity {
    (info.dev(), info.ino(), info.uid(), info.gid(), info.mode())
}
fn protected(file: &File, directory: bool) -> Result<Identity> {
    let info = file.metadata()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if info.uid() != 0
        || info.gid() != 0
        || info.mode() & 0o7022 != 0
        || directory != info.is_dir()
        || !directory && !info.is_file()
        || unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != SYSFS
    {
        return Err("backlight control is not an actual protected root-only sysfs object".into());
    }
    Ok(identity(&info))
}
struct Held {
    file: File,
    path: PathBuf,
    identity: Identity,
    directory: bool,
}
impl Held {
    fn open(path: &Path, directory: bool, write: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(write).custom_flags(
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        );
        let file = options.open(path)?;
        let identity = protected(&file, directory)?;
        let result = Self {
            file,
            path: path.into(),
            identity,
            directory,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        if protected(&self.file, self.directory)? != self.identity
            || identity(&fs::symlink_metadata(&self.path)?) != self.identity
        {
            return Err("held backlight sysfs inode/path/permissions changed".into());
        }
        Ok(())
    }
    fn read(&self) -> Result<String> {
        self.check()?;
        let mut bytes = [0u8; 65];
        let count = self.file.read_at(&mut bytes, 0)?;
        if count == 0
            || count > 64
            || !bytes[..count].ends_with(b"\n")
            || bytes[..count - 1].contains(&b'\n')
            || bytes[..count].contains(&0)
        {
            return Err("backlight sysfs value is absent, truncated or outside its bound".into());
        }
        self.check()?;
        Ok(std::str::from_utf8(&bytes[..count])?.into())
    }
}
fn scalar(text: &str) -> Result<u32> {
    let body = text
        .strip_suffix('\n')
        .ok_or("backlight scalar is truncated")?;
    let value = body.parse::<u32>()?;
    if value.to_string() != body || value > 1_000_000 {
        return Err("backlight scalar is not canonical and bounded".into());
    }
    Ok(value)
}
fn pci_hex(text: &str, length: usize) -> Result<&str> {
    let body = text
        .strip_suffix('\n')
        .ok_or("backlight PCI identity is truncated")?;
    if body.len() != length + 2
        || !body.starts_with("0x")
        || !body[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("backlight PCI identity is not canonical".into());
    }
    Ok(body)
}
fn physical_path(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().ok_or("backlight path is not ASCII")?;
    let (gpu, tail) = text
        .split_once("/drm/")
        .ok_or("backlight is not an exposed DRM device")?;
    if !gpu.starts_with("/sys/devices/pci")
        || gpu.len() > 256
        || !gpu
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/:._-".contains(&byte))
    {
        return Err("backlight PCI topology is outside its compiled family".into());
    }
    let fields = tail.split('/').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[2] != "intel_backlight"
        || !fields[0].starts_with("card")
        || fields[0][4..].is_empty()
        || !fields[0][4..].bytes().all(|byte| byte.is_ascii_digit())
        || !fields[1].starts_with(&format!("{}-eDP-", fields[0]))
        || !fields[1][fields[0].len() + 5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || fields[1][fields[0].len() + 5..].is_empty()
    {
        return Err("only the qualified Intel eDP backlight path is supported".into());
    }
    Ok(PathBuf::from(gpu))
}
fn write_decision(
    phase: Phase,
    kind: WriteKind,
    before: &Setting,
    after: &Setting,
    observed: &Setting,
) -> Result<bool> {
    let (
        Setting::Backlight {
            brightness: prior,
            maximum,
        },
        Setting::Backlight {
            brightness: next,
            maximum: next_maximum,
        },
    ) = (before, after)
    else {
        return Err("backlight transition is not an exact typed pair".into());
    };
    if *maximum == 0
        || *maximum > 1_000_000
        || maximum != next_maximum
        || prior > maximum
        || next > maximum
        || *next == 0
        || before == after
    {
        return Err("backlight transition exceeds its non-extinguishing closed capability".into());
    }
    if kind == WriteKind::Apply && phase != Phase::Prepared
        || kind == WriteKind::Restore && !matches!(phase, Phase::Prepared | Phase::Applied)
    {
        return Err("backlight write is outside its exact prepared/applied lifecycle".into());
    }
    let unwritten = kind == WriteKind::Restore && phase == Phase::Prepared && observed == before;
    let expected = match kind {
        WriteKind::Apply => before,
        WriteKind::Restore => after,
    };
    if !unwritten && observed != expected {
        return Err("backlight external drift prevents exact apply/undo; do not retry".into());
    }
    Ok(unwritten)
}
pub(crate) struct Control<'image> {
    image: &'image super::image::Image,
    resolved: PathBuf,
    gpu: PathBuf,
    held: Vec<Held>,
    boot: String,
    target: Target,
    maximum: u32,
    capabilities: Vec<(PathBuf, String)>,
}
impl<'image> Control<'image> {
    pub(crate) fn open(image: &'image super::image::Image) -> Result<Self> {
        let budget = Budget::new()?;
        image.check()?;
        budget.check()?;
        let class = Held::open(Path::new("/sys/class/backlight"), true, false)?;
        let link = fs::symlink_metadata(CLASS)?;
        if !link.file_type().is_symlink() || link.uid() != 0 {
            return Err("fixed backlight class entry is not the actual kernel link".into());
        }
        let resolved = fs::canonicalize(CLASS)?;
        let gpu = physical_path(&resolved)?;
        if fs::canonicalize(gpu.join("driver"))? != Path::new(DRIVER) {
            return Err("fixed backlight is not driven by actual i915".into());
        }
        let mut held = vec![class];
        for ancestor in resolved
            .ancestors()
            .take_while(|path| *path != Path::new("/"))
        {
            held.push(Held::open(ancestor, true, false)?);
        }
        held.push(Held::open(Path::new(DRIVER), true, false)?);
        for name in [
            "vendor",
            "device",
            "subsystem_vendor",
            "subsystem_device",
            "class",
        ] {
            held.push(Held::open(&gpu.join(name), false, false)?);
        }
        for name in [
            "brightness",
            "actual_brightness",
            "max_brightness",
            "type",
            "bl_power",
        ] {
            held.push(Held::open(
                &resolved.join(name),
                false,
                name == "brightness",
            )?);
        }
        let attribute = |path: &Path| -> Result<String> {
            held.iter()
                .find(|member| member.path == path)
                .ok_or("required held backlight attribute missing")?
                .read()
        };
        let vendor = attribute(&gpu.join("vendor"))?;
        if pci_hex(&vendor, 4)? != "0x8086" {
            return Err("backlight vendor is not Intel".into());
        }
        let device = attribute(&gpu.join("device"))?;
        pci_hex(&device, 4)?;
        let subvendor = attribute(&gpu.join("subsystem_vendor"))?;
        pci_hex(&subvendor, 4)?;
        let subdevice = attribute(&gpu.join("subsystem_device"))?;
        pci_hex(&subdevice, 4)?;
        let class_id = attribute(&gpu.join("class"))?;
        if !pci_hex(&class_id, 6)?.starts_with("0x03") {
            return Err("backlight PCI device is not a display controller".into());
        }
        let kind = attribute(&resolved.join("type"))?;
        if kind != "raw\n" {
            return Err("backlight does not expose the qualified raw i915 interface".into());
        }
        let maximum = scalar(&attribute(&resolved.join("max_brightness"))?)?;
        if maximum == 0 {
            return Err("backlight has no nonzero bounded maximum".into());
        }
        let directory = held
            .iter()
            .find(|member| member.path == resolved && member.directory)
            .ok_or("backlight directory pin missing")?;
        let boot = current_boot()?;
        let target = Target {
            adapter: Adapter::Backlight,
            worker: None,
            resource: None,
            identity_sha256: hash(&(
                "luma-fixed-native-backlight-slot-v1",
                "intel_backlight",
                "i915",
            ))?,
            capability_sha256: hash(&(
                "luma-actual-native-backlight-capability-v1",
                &resolved,
                &gpu,
                &vendor,
                &device,
                &subvendor,
                &subdevice,
                &class_id,
                &kind,
                maximum,
                &image.closure_sha256,
                held.iter()
                    .map(|member| (&member.path, member.identity))
                    .collect::<Vec<_>>(),
            ))?,
            adapter_sha256: hash(&(
                "luma-native-backlight-adapter-source-v1",
                include_bytes!("backlight.rs").as_slice(),
                include_bytes!("sd_bus.rs").as_slice(),
            ))?,
            boot: boot.clone(),
            generation: directory.identity.1,
        };
        let capabilities = [
            ("vendor", vendor),
            ("device", device),
            ("subsystem_vendor", subvendor),
            ("subsystem_device", subdevice),
            ("class", class_id),
        ]
        .into_iter()
        .map(|(name, value)| (gpu.join(name), value))
        .collect();
        target.validate()?;
        let result = Self {
            image,
            resolved,
            gpu,
            held,
            boot,
            target,
            maximum,
            capabilities,
        };
        result.check(&budget)?;
        result.observe_with(&budget)?;
        Ok(result)
    }
    fn check(&self, budget: &Budget) -> Result<()> {
        budget.check()?;
        self.image.check()?;
        if current_boot()? != self.boot
            || fs::canonicalize(CLASS)? != self.resolved
            || fs::canonicalize(self.gpu.join("driver"))? != Path::new(DRIVER)
        {
            return Err("backlight boot/device/driver generation changed".into());
        }
        for member in &self.held {
            member.check()?;
        }
        for (path, expected) in &self.capabilities {
            if self
                .held
                .iter()
                .find(|member| member.path == *path)
                .ok_or("backlight capability pin missing")?
                .read()?
                != *expected
            {
                return Err("actual backlight PCI capability changed".into());
            }
        }
        if self.read("type")? != "raw\n" || scalar(&self.read("max_brightness")?)? != self.maximum {
            return Err("backlight capabilities changed".into());
        }
        budget.check()
    }
    fn read(&self, name: &str) -> Result<String> {
        self.held
            .iter()
            .find(|member| member.path == self.resolved.join(name))
            .ok_or("closed backlight attribute absent")?
            .read()
    }
    fn observe_with(&self, budget: &Budget) -> Result<Setting> {
        self.check(budget)?;
        let brightness = scalar(&self.read("brightness")?)?;
        let actual = scalar(&self.read("actual_brightness")?)?;
        if brightness > self.maximum || actual != brightness || self.read("bl_power")? != "0\n" {
            return Err(
                "backlight is blanked, quantized, drifting or unqualified for exact readback"
                    .into(),
            );
        }
        budget.check()?;
        Ok(Setting::Backlight {
            brightness,
            maximum: self.maximum,
        })
    }
    pub(crate) fn target(&self) -> Result<Target> {
        let budget = Budget::new()?;
        self.check(&budget)?;
        Ok(self.target.clone())
    }
    pub(crate) fn dispatch_witness(&self) -> Result<Option<super::DispatchWitness>> {
        self.check(&Budget::new()?)?;
        Ok(None)
    }
    pub(crate) fn observe(&self) -> Result<Setting> {
        self.observe_with(&Budget::new()?)
    }
    pub(crate) fn compare_write(
        &self,
        transition: &Transition,
        kind: WriteKind,
    ) -> Result<Observation> {
        let budget = Budget::new()?;
        transition.intent.validate()?;
        self.check(&budget)?;
        let intent = &transition.intent;
        if intent.target != self.target {
            return Err(
                "committed backlight target is not the current pinned device generation".into(),
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
        if !unwritten {
            let Setting::Backlight {
                brightness,
                maximum,
            } = replacement
            else {
                return Err("backlight replacement has another adapter type".into());
            };
            if *maximum != self.maximum
                || *brightness > self.maximum
                || kind == WriteKind::Apply && *brightness == 0
            {
                return Err("backlight replacement exceeds reviewed capability or extinguishes manual display".into());
            }
            self.check(&budget)?;
            let member = self
                .held
                .iter()
                .find(|member| member.path == self.resolved.join("brightness"))
                .ok_or("backlight writer pin missing")?;
            let command = format!("{brightness}\n");
            // One actual sysfs store, no retry. Kernel driver stalls cannot be
            // forcibly cancelled in process; late/partial results remain an
            // outstanding obligation rather than a successful observation.
            if member.file.write_at(command.as_bytes(), 0)? != command.len() {
                return Err("partial backlight store; preserve committed obligation".into());
            }
            budget.check()?;
        }
        let actual = self.observe_with(&budget)?;
        if actual != *replacement {
            return Err("backlight write did not read back exactly; preserve obligation".into());
        }
        self.check(&budget)?;
        let observation = Observation {
            target: self.target.clone(),
            setting: actual,
            observed_ms: crate::resource_manager::now()?,
            enforcement_sha256: hash(&(
                if unwritten {
                    "luma-backlight-prepared-baseline-observed-no-write-v1"
                } else {
                    "luma-backlight-single-store-exact-readback-v1"
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
    #[test]
    fn only_canonical_bounded_backlight_attributes_are_accepted() {
        for value in ["0\n", "1\n", "1000000\n"] {
            scalar(value).unwrap();
        }
        for value in [
            "",
            "1",
            "01\n",
            "+1\n",
            "-1\n",
            "1000001\n",
            "1\n2\n",
            "1 \n",
        ] {
            assert!(scalar(value).is_err());
        }
        assert_eq!(pci_hex("0x8086\n", 4).unwrap(), "0x8086");
        for value in ["8086\n", "0X8086\n", "0x8086", "0x808g\n"] {
            assert!(pci_hex(value, 4).is_err());
        }
    }
    #[test]
    fn exact_intel_edp_family_refuses_other_devices_or_escaping_paths() {
        for path in [
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card0/card0-eDP-1/intel_backlight",
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card12/card12-eDP-2/intel_backlight",
        ] {
            physical_path(Path::new(path)).unwrap();
        }
        for path in [
            "/tmp/intel_backlight",
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card0/card1-eDP-1/intel_backlight",
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card0/card0-HDMI-1/intel_backlight",
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card0/card0-eDP-/intel_backlight",
            "/sys/devices/pci0000:00/0000:00:02.0/drm/card0/card0-eDP-1/intel_backlight/other",
        ] {
            assert!(physical_path(Path::new(path)).is_err());
        }
    }
    #[test]
    fn ordinary_fixture_file_never_substitutes_for_kernel_sysfs() {
        let file = File::open("/dev/null").unwrap();
        assert!(protected(&file, false).is_err());
    }
    #[test]
    fn exact_compare_and_undo_never_adopts_external_or_wrong_phase_state() {
        let before = Setting::Backlight {
            brightness: 40,
            maximum: 100,
        };
        let after = Setting::Backlight {
            brightness: 70,
            maximum: 100,
        };
        let drift = Setting::Backlight {
            brightness: 50,
            maximum: 100,
        };
        assert!(
            !write_decision(Phase::Prepared, WriteKind::Apply, &before, &after, &before).unwrap()
        );
        assert!(
            !write_decision(Phase::Prepared, WriteKind::Restore, &before, &after, &after).unwrap()
        );
        assert!(
            !write_decision(Phase::Applied, WriteKind::Restore, &before, &after, &after).unwrap()
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
        for phase in [
            Phase::Prepared,
            Phase::Applied,
            Phase::Restored,
            Phase::Fenced,
            Phase::Reconciled,
        ] {
            for kind in [WriteKind::Apply, WriteKind::Restore] {
                assert!(write_decision(phase, kind, &before, &after, &drift).is_err());
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
        for next in [
            Setting::Backlight {
                brightness: 0,
                maximum: 100,
            },
            Setting::Backlight {
                brightness: 101,
                maximum: 100,
            },
            Setting::Backlight {
                brightness: 70,
                maximum: 101,
            },
            before.clone(),
        ] {
            assert!(
                write_decision(Phase::Prepared, WriteKind::Apply, &before, &next, &before).is_err()
            );
        }
    }
}
