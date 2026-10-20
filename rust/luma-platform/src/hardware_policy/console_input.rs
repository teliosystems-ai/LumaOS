//! Closed original-terminal input and immutable transient-unit staging. These
//! JSON values carry requested semantics only, never a PAM session or grant.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) const MAX_INPUT: usize = 65_536;
const ROOT: &str = "/run/luma-hardware/requests";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inspection {
    pub schema_version: u32,
    pub adapter: Adapter,
    pub worker: Option<Worker>,
    pub boot: String,
}
impl Inspection {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !generation(&self.boot)
            || matches!(self.adapter, Adapter::Backlight | Adapter::PowerProfiles)
                != self.worker.is_none()
            || (self.adapter == Adapter::MemoryProfile && self.worker != Some(Worker::Model))
        {
            return Err("hardware inspection is not a fixed adapter/current-boot request".into());
        }
        Ok(())
    }
    pub(crate) fn usage(&self) -> Result<finite_grants::Use> {
        self.validate()?;
        let usage = finite_grants::Use {
            action: finite_grants::Action::InspectHardware,
            selector: finite_grants::Selector {
                kind: finite_grants::Kind::Hardware,
                id: self.adapter.id().into(),
                // Version of this compiled discovery contract, not a guessed
                // physical device generation before native discovery.
                generation: 1,
                digest: hash(&("luma-native-hardware-inspection-request-v1", self))?,
            },
            input_bytes: 65_536,
            output_bytes: 65_536,
            units: 1,
        };
        usage.validate()?;
        Ok(usage)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Task {
    ReviewInspection {
        inspection: Inspection,
    },
    Inspect {
        inspection: Inspection,
        grant: String,
    },
    ReviewPlan {
        plan: Plan,
    },
    Apply {
        plan: Plan,
    },
    ReviewReconciliation {
        inspection: Inspection,
        grant: String,
        transaction: String,
        disposition: Reconciliation,
    },
    Reconcile {
        plan: ReconciliationPlan,
        grant: String,
    },
}
impl Task {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::ReviewInspection { inspection } => inspection.validate(),
            Self::Inspect { inspection, grant } => {
                inspection.validate()?;
                grant_id(grant)
            }
            Self::ReviewPlan { plan } | Self::Apply { plan } => plan.validate(),
            Self::ReviewReconciliation {
                inspection,
                grant,
                transaction,
                ..
            } => {
                inspection.validate()?;
                grant_id(grant)?;
                grant_id(transaction)
            }
            Self::Reconcile { plan, grant } => {
                grant_id(grant)?;
                grant_id(&plan.transaction)?;
                if plan.schema_version != 1
                    || plan.expected_revision == 0
                    || plan.expected_revision == u64::MAX
                {
                    return Err(
                        "reconciliation console input has no exact reviewed revision".into(),
                    );
                }
                Ok(())
            }
        }
    }
    pub(crate) fn cleanup_transaction(&self) -> Option<&str> {
        match self {
            Self::Apply { plan } => Some(&plan.transaction),
            _ => None,
        }
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_INPUT {
            return Err("hardware terminal input exceeds fixed bound".into());
        }
        let task: Self = serde_json::from_slice(bytes)?;
        task.validate()?;
        Ok(task)
    }
}
fn grant_id(value: &str) -> Result<()> {
    if !crate::admin_roles::identifier(value) {
        return Err("invalid literal hardware grant or transaction identifier".into());
    }
    Ok(())
}
fn login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub schema_version: u32,
    pub unit: String,
    pub login: String,
    pub task: Task,
}
impl Envelope {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || !generation(&self.unit) || !login(&self.login) {
            return Err("hardware staged input substitutes its original unit or login".into());
        }
        self.task.validate()
    }
}
type Identity = (u64, u64, u64, u32, u32, u32, u64);
fn file_identity(metadata: &fs::Metadata) -> Result<Identity> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_INPUT as u64
    {
        return Err("hardware input is not a bounded immutable private root inode".into());
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
    ))
}
fn directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("hardware staging directory is not private root ownership".into());
    }
    Ok(file)
}
pub(crate) struct Stage {
    root: PathBuf,
    path: PathBuf,
    directory: File,
    file: File,
    parent_identity: (u64, u64),
    identity: Identity,
    sha256: String,
    pub envelope: Envelope,
    owned: bool,
}
impl Stage {
    pub(crate) fn capture(login: &str, task: Task) -> Result<Self> {
        task.validate()?;
        directory(Path::new("/run/luma-hardware"))?;
        match fs::DirBuilder::new().mode(0o700).create(ROOT) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error.into()),
        }
        Self::capture_at(Path::new(ROOT), login, task)
    }
    fn capture_at(root: &Path, login: &str, task: Task) -> Result<Self> {
        directory(root)?;
        if fs::read_dir(root)?.take(17).count() >= 16 {
            return Err(
                "hardware staging inventory is full; inspect stale owned units before cleanup"
                    .into(),
            );
        }
        let envelope = Envelope {
            schema_version: 1,
            unit: resources::random_id()?,
            login: login.into(),
            task,
        };
        envelope.validate()?;
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > MAX_INPUT {
            return Err("hardware envelope exceeds fixed staging bound".into());
        }
        let path = root.join(&envelope.unit);
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let file_path = path.join("input.json");
        let result = (|| -> Result<Self> {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&file_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            let parent = directory(&path)?;
            parent.sync_all()?;
            directory(root)?.sync_all()?;
            let metadata = parent.metadata()?;
            let stage = Self {
                root: root.into(),
                path: path.clone(),
                parent_identity: (metadata.dev(), metadata.ino()),
                directory: parent,
                identity: file_identity(&file.metadata()?)?,
                file,
                sha256: hash(&envelope)?,
                envelope,
                owned: true,
            };
            stage.check()?;
            Ok(stage)
        })();
        if result.is_err() {
            let _ = fs::remove_file(file_path);
            let _ = fs::remove_dir(path);
        }
        result
    }
    pub(crate) fn current(login: &str) -> Result<Self> {
        let text = fs::read_to_string("/proc/self/cgroup")?;
        let unit = text
            .strip_prefix("0::/system.slice/luma-hardware-")
            .and_then(|value| value.strip_suffix(".service\n"))
            .filter(|value| generation(value))
            .ok_or("hardware input is not in its actual fixed transient unit")?;
        Self::open_at(Path::new(ROOT), unit, login)
    }
    fn open_at(root: &Path, unit: &str, login: &str) -> Result<Self> {
        if !generation(unit) || !self::login(login) {
            return Err("invalid staged unit/login identity".into());
        }
        directory(root)?;
        let path = root.join(unit);
        let parent = directory(&path)?;
        let metadata = parent.metadata()?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("input.json"))?;
        let identity = file_identity(&file.metadata()?)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_INPUT as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != identity.2 {
            return Err("hardware staged input changed or exceeded bound".into());
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        envelope.validate()?;
        if envelope.unit != unit
            || envelope.login != login
            || serde_json::to_vec(&envelope)? != bytes
        {
            return Err(
                "hardware input is noncanonical or belongs to another original unit/login".into(),
            );
        }
        let stage = Self {
            root: root.into(),
            path,
            parent_identity: (metadata.dev(), metadata.ino()),
            directory: parent,
            file,
            identity,
            sha256: hash(&envelope)?,
            envelope,
            owned: false,
        };
        stage.check()?;
        Ok(stage)
    }
    pub(crate) fn check(&self) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let named = directory(&self.path)?.metadata()?;
        let held = self.directory.metadata()?;
        if (named.dev(), named.ino()) != self.parent_identity
            || (held.dev(), held.ino()) != self.parent_identity
            || file_identity(&fs::symlink_metadata(self.path.join("input.json"))?)? != self.identity
            || file_identity(&self.file.metadata()?)? != self.identity
        {
            return Err("hardware staged input's owned directory/inode changed".into());
        }
        let mut bytes = vec![0u8; self.identity.2 as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = self.file.read_at(&mut bytes[offset..], offset as u64)?;
            if count == 0 {
                return Err("hardware staged input truncated".into());
            }
            offset += count;
        }
        if crate::bundle::hex(&Sha256::digest(&bytes)) != self.sha256
            || serde_json::to_vec(&self.envelope)? != bytes
        {
            return Err("hardware original typed input bytes changed".into());
        }
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if self.owned && self.check().is_ok() {
            let _ = fs::remove_file(self.path.join("input.json"));
            let _ = fs::remove_dir(&self.path);
            if let Ok(root) = directory(&self.root) {
                let _ = root.sync_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn task() -> Task {
        Task::ReviewInspection {
            inspection: Inspection {
                schema_version: 1,
                adapter: Adapter::CpuQuota,
                worker: Some(Worker::Model),
                boot: "12".repeat(16),
            },
        }
    }
    #[test]
    fn inspection_cannot_be_reinterpreted_as_an_apply_or_another_worker_or_boot() {
        let Task::ReviewInspection { inspection } = task() else {
            unreachable!()
        };
        let usage = inspection.usage().unwrap();
        assert_eq!(usage.action, finite_grants::Action::InspectHardware);
        let mut changed = inspection.clone();
        changed.worker = Some(Worker::Acquisition);
        assert_ne!(usage, changed.usage().unwrap());
        changed = inspection.clone();
        changed.boot = "34".repeat(16);
        assert_ne!(usage, changed.usage().unwrap());
        changed = inspection;
        changed.worker = None;
        assert!(changed.usage().is_err());
    }
    #[test]
    fn closed_console_input_refuses_unknown_and_duplicate_authority_members() {
        let bytes = serde_json::to_string(&task()).unwrap();
        Task::parse(bytes.as_bytes()).unwrap();
        for bad in [
            bytes.replace("\"operation\":", "\"principal\":\"admin\",\"operation\":"),
            bytes.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            ),
            bytes.replace("cpu-quota", "raw-sysfs"),
            bytes.replace("\"model\"", "\"/tmp/device\""),
        ] {
            assert!(Task::parse(bad.as_bytes()).is_err());
        }
        assert!(Task::parse(&vec![b' '; MAX_INPUT + 1]).is_err());
        assert!(task().cleanup_transaction().is_none());
    }
    #[test]
    fn actual_staging_is_immutable_exact_unit_login_and_preserves_substitution() {
        let root = std::env::temp_dir().join(format!(
            "luma-hardware-input-{}",
            resources::random_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _root = Root(root.clone());
        let stage = Stage::capture_at(&root, "admin", task()).unwrap();
        let receiver = Stage::open_at(&root, &stage.envelope.unit, "admin").unwrap();
        assert_eq!(receiver.envelope, stage.envelope);
        assert!(Stage::open_at(&root, &stage.envelope.unit, "other").is_err());
        let path = stage.path.clone();
        fs::rename(path.join("input.json"), path.join("original.json")).unwrap();
        fs::write(
            path.join("input.json"),
            serde_json::to_vec(&stage.envelope).unwrap(),
        )
        .unwrap();
        fs::set_permissions(path.join("input.json"), fs::Permissions::from_mode(0o400)).unwrap();
        assert!(stage.check().is_err());
        assert!(receiver.check().is_err());
        drop(receiver);
        drop(stage);
        assert!(path.join("original.json").exists());
        assert!(path.join("input.json").exists());
    }
}
