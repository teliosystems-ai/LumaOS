//! Independent TPM-anchored paired resource authority. An ordinary backup is
//! never selected by age, checksum, or convenience. The current NV value alone
//! selects an exact prepared closure; repair is explicit and retains damage.
use super::*;
use std::cell::RefCell;
use std::os::unix::fs::MetadataExt;

const MAX_MANIFEST: u64 = 65_536;
const MAX_MEMBERS: usize = 130;
const MAX_OBJECTS: usize = 4096;
// The complete supported closure is 128 archives plus two hot members, each
// bounded by 8MiB. A 2GiB ceiling leaves room for this closure and transitions.
const MAX_BACKUP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) type Shared = RefCell<Authority>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    name: String,
    sha256: String,
    #[serde(with = "decimal")]
    length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    schema_version: u32,
    installation: String,
    #[serde(with = "decimal")]
    sequence: u64,
    previous: String,
    nonce: String,
    members: Vec<Member>,
}
impl Manifest {
    pub(crate) fn event(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }
    fn head(&self) -> Result<[u8; 32]> {
        Ok(tpm::extend_value(
            tpm::decode(&self.previous)?,
            self.event()?,
        ))
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.sequence == 0
            || tpm::decode::<32>(&self.installation)? == [0; 32]
            || tpm::decode::<16>(&self.nonce)? == [0; 16]
            || self.members.len() < 2
            || self.members.len() > MAX_MEMBERS
        {
            return Err("invalid resource checkpoint manifest".into());
        }
        tpm::decode::<32>(&self.previous)?;
        let mut names = BTreeSet::new();
        for m in &self.members {
            if !member_name(&m.name)
                || !names.insert(&m.name)
                || m.length == 0
                || m.length > MAX_BYTES
                || tpm::decode::<32>(&m.sha256)? == [0; 32]
            {
                return Err("invalid paired resource closure member".into());
            }
        }
        if self.members.windows(2).any(|w| w[0].name >= w[1].name)
            || !names.contains(&"ledger.json".to_string())
            || !names.contains(&"requests.json".to_string())
        {
            return Err("resource checkpoint lacks an ordered complete pair".into());
        }
        Ok(())
    }
}

fn member_name(name: &str) -> bool {
    if matches!(name, "ledger.json" | "requests.json") {
        return true;
    }
    let suffix = name
        .strip_prefix("archive-")
        .or_else(|| name.strip_prefix("requests-archive-"));
    let Some((generation, hash)) = suffix
        .and_then(|s| s.strip_suffix(".json"))
        .and_then(|s| s.split_once('-'))
    else {
        return false;
    };
    generation
        .parse::<u64>()
        .is_ok_and(|v| v > 0 && v.to_string() == generation)
        && tpm::decode::<32>(hash).is_ok()
}

fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}

fn exact_read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
        || before.len() > maximum
    {
        return Err("unsafe checkpoint file inode".into());
    }
    let bytes = tpm::private_read(path, maximum)?;
    let after = fs::symlink_metadata(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
        )
    };
    if identity(&before) != identity(&after) || bytes.len() as u64 != before.len() {
        return Err("checkpoint bytes changed during inspection".into());
    }
    Ok(bytes)
}

fn decode(path: &Path) -> Result<Manifest> {
    let bytes = exact_read(path, MAX_MANIFEST)?;
    let value: Manifest = serde_json::from_slice(&bytes)?;
    value.validate()?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical checkpoint manifest".into());
    }
    Ok(value)
}

fn create(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("checkpoint parent absent")?)?.sync_all()?;
    Ok(())
}

struct DirectoryPin {
    path: PathBuf,
    file: File,
}
impl DirectoryPin {
    fn new(path: &Path) -> Result<Self> {
        tpm::private_directory(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let pin = Self {
            path: path.into(),
            file,
        };
        pin.check()?;
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        tpm::private_directory(&self.path)?;
        let current = fs::symlink_metadata(&self.path)?;
        let retained = self.file.metadata()?;
        if !retained.is_dir()
            || retained.uid() != 0
            || retained.mode() & 0o077 != 0
            || (current.dev(), current.ino()) != (retained.dev(), retained.ino())
        {
            return Err("protected recovery directory identity changed".into());
        }
        Ok(())
    }
}

fn member_inventory(path: &Path) -> Result<serde_json::Value> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(serde_json::Value::Null),
        Err(e) => return Err(e.into()),
    };
    let bytes = exact_read(path, MAX_BYTES)?;
    let after = fs::symlink_metadata(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
            m.uid(),
            m.nlink(),
        )
    };
    if identity(&before) != identity(&after) {
        return Err("resource member identity changed during recovery review".into());
    }
    Ok(
        serde_json::json!({"sha256":hash(&bytes),"device":after.dev().to_string(),
        "inode":after.ino().to_string(),"bytes":after.len().to_string(),
        "ctime":after.ctime().to_string(),"ctime_ns":after.ctime_nsec().to_string(),
        "mode":after.mode().to_string(),"uid":after.uid().to_string(),
        "links":after.nlink().to_string()}),
    )
}

/// Capture and validate the complete durable pair, not request bytes cached in
/// the broker or a volatile resource telemetry overlay.
fn closure(
    directory: &Path,
    replacement: Option<(&str, &[u8])>,
    mut visit: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<Vec<Member>> {
    tpm::private_directory(directory)?;
    let read = |name: &str| -> Result<Vec<u8>> {
        match replacement {
            Some((target, bytes)) if name == target => Ok(bytes.to_vec()),
            _ => exact_read(&directory.join(name), MAX_BYTES),
        }
    };
    let ledger_bytes = read("ledger.json")?;
    let ledger: Ledger = serde_json::from_slice(&ledger_bytes)?;
    ledger.validate()?;
    if serde_json::to_vec(&ledger)? != ledger_bytes {
        return Err("noncanonical checkpoint ledger".into());
    }
    let request_bytes = read("requests.json")?;
    let request_members =
        crate::resource_manager::requests::checkpoint_members(directory, &request_bytes)?;
    let mut values = BTreeMap::new();
    for (name, bytes) in [
        ("ledger.json", ledger_bytes),
        ("requests.json", request_bytes),
    ] {
        visit(name, &bytes)?;
        values.insert(
            name.to_string(),
            Member {
                name: name.into(),
                sha256: hash(&bytes),
                length: bytes.len() as u64,
            },
        );
    }
    for (i, reference) in ledger.archives.iter().enumerate() {
        let bytes = read(&reference.name())?;
        let archived: Ledger = serde_json::from_slice(&bytes)?;
        archived.validate()?;
        if hash(&bytes) != reference.sha256
            || serde_json::to_vec(&archived)? != bytes
            || archived.generation != reference.through_generation
            || archived.archives != ledger.archives[..i]
            || archived.leases.is_empty()
            || archived.leases.iter().any(|l| l.state != State::Released)
        {
            return Err("invalid checkpoint resource archive closure".into());
        }
        let name = reference.name();
        visit(&name, &bytes)?;
        values.insert(
            name.clone(),
            Member {
                name,
                sha256: hash(&bytes),
                length: bytes.len() as u64,
            },
        );
    }
    for (name, digest) in request_members {
        let bytes = read(&name)?;
        if hash(&bytes) != digest {
            return Err("request closure changed during capture".into());
        }
        visit(&name, &bytes)?;
        let member = Member {
            name: name.clone(),
            sha256: digest,
            length: bytes.len() as u64,
        };
        if values.insert(name, member).is_some() {
            return Err("duplicate paired closure member".into());
        }
    }
    if values.len() > MAX_MEMBERS {
        return Err("checkpoint closure capacity exhausted".into());
    }
    Ok(values.into_values().collect())
}

pub(crate) struct Authority {
    directory: PathBuf,
    identity: (u64, u64),
    anchor: Box<dyn tpm::Checkpoint>,
    manifest: Manifest,
    poisoned: bool,
}
impl Authority {
    pub(crate) fn prepare_genesis(
        directory: &Path,
        resources: &Path,
        installation: &str,
    ) -> Result<Manifest> {
        // Explicit enrollment creates only a new private paired directory. An
        // existing preparation is never overwritten, completed or retried here.
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory.join("objects"))?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory.join("records"))?;
        File::open(directory)?.sync_all()?;
        File::open(directory.parent().ok_or("checkpoint parent absent")?)?.sync_all()?;
        let manifest = Self::stage(directory, installation, 1, [0; 32], resources, None)?;
        create(
            &directory.join("prepared.json"),
            &serde_json::to_vec(&manifest)?,
            0o600,
        )?;
        Ok(manifest)
    }

    pub(crate) fn genesis_proposal(
        resources: &Path,
        installation: &str,
    ) -> Result<serde_json::Value> {
        tpm::decode::<32>(installation)?;
        let members = closure(resources, None, |_, _| Ok(()))?;
        let review = hash(&serde_json::to_vec(&(installation, &members))?);
        Ok(
            serde_json::json!({"schema_version":1,"installation":installation,
            "review_sha256":review,"members":members,"tpm_write":false,
            "automatic_retry":false}),
        )
    }

    pub(crate) fn prepared_genesis(
        directory: &Path,
        resources: &Path,
        installation: &str,
    ) -> Result<Manifest> {
        let manifest = decode(&directory.join("prepared.json"))?;
        if manifest.installation != installation
            || manifest.sequence != 1
            || manifest.previous != "0".repeat(64)
            || closure(resources, None, |_, _| Ok(()))? != manifest.members
        {
            return Err("paired genesis differs from exact installation/resource closure".into());
        }
        validate_backups(directory, &manifest)?;
        Ok(manifest)
    }

    pub(crate) fn complete_genesis(
        directory: &Path,
        resources: &Path,
        installation: &str,
        anchor: &mut dyn tpm::Checkpoint,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let manifest = Self::prepared_genesis(directory, resources, installation)?;
        if anchor.read()? != manifest.head()? {
            return Err("resource genesis NV does not bind the prepared pair".into());
        }
        check()?;
        if Self::prepared_genesis(directory, resources, installation)? != manifest {
            return Err("prepared resource genesis changed before confirmation".into());
        }
        create(
            &directory.join("head.json"),
            &serde_json::to_vec(&manifest)?,
            0o600,
        )?;
        if decode(&directory.join("head.json"))? != manifest || anchor.read()? != manifest.head()? {
            return Err("resource genesis confirmation uncertain".into());
        }
        check()?;
        fs::remove_file(directory.join("prepared.json"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn open(
        directory: &Path,
        resources: &Path,
        installation: &str,
        mut anchor: Box<dyn tpm::Checkpoint>,
    ) -> Result<Self> {
        tpm::private_directory(directory)?;
        tpm::private_directory(&directory.join("objects"))?;
        // Even a complete post-extend preparation requires reviewed repair.
        match fs::symlink_metadata(directory.join("prepared.json")) {
            Ok(_) => return Err("paired checkpoint interrupted; explicit recovery required".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let manifest = decode(&directory.join("head.json"))?;
        if manifest.installation != installation || anchor.read()? != manifest.head()? {
            return Err("resource pair rolled back or checkpoint identity changed".into());
        }
        let metadata = fs::symlink_metadata(directory)?;
        let mut authority = Self {
            directory: directory.into(),
            identity: (metadata.dev(), metadata.ino()),
            anchor,
            manifest,
            poisoned: false,
        };
        authority.verify(resources)?;
        Ok(authority)
    }

    fn stage(
        directory: &Path,
        installation: &str,
        sequence: u64,
        previous: [u8; 32],
        resources: &Path,
        replacement: Option<(&str, &[u8])>,
    ) -> Result<Manifest> {
        tpm::private_directory(&directory.join("objects"))?;
        let mut count = 0usize;
        let mut total = 0u64;
        for entry in fs::read_dir(directory.join("objects"))? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("non-ASCII checkpoint backup name")?;
            tpm::decode::<32>(name)?;
            let bytes = exact_read(&entry.path(), MAX_BYTES)?;
            if hash(&bytes) != name {
                return Err("checkpoint backup digest mismatch".into());
            }
            count = count
                .checked_add(1)
                .ok_or("checkpoint inventory overflow")?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("checkpoint byte inventory overflow")?;
            if count > MAX_OBJECTS || total > MAX_BACKUP_BYTES {
                return Err(
                    "checkpoint backup capacity exhausted; reviewed retention required".into(),
                );
            }
        }
        let members = closure(resources, replacement, |_name, bytes| {
            let sha256 = hash(&bytes);
            let path = directory.join("objects").join(&sha256);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    if exact_read(&path, MAX_BYTES)? != bytes {
                        return Err("checkpoint backup conflict".into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    count = count
                        .checked_add(1)
                        .ok_or("checkpoint inventory overflow")?;
                    total = total
                        .checked_add(bytes.len() as u64)
                        .ok_or("checkpoint byte inventory overflow")?;
                    if count > MAX_OBJECTS || total > MAX_BACKUP_BYTES {
                        return Err("checkpoint backup capacity exhausted; preserve state".into());
                    }
                    create(&path, &bytes, 0o400)?;
                }
                Err(e) => return Err(e.into()),
            }
            Ok(())
        })?;
        let manifest = Manifest {
            schema_version: 1,
            installation: installation.into(),
            sequence,
            previous: bundle::hex(&previous),
            nonce: random_id()?,
            members,
        };
        manifest.validate()?;
        tpm::private_directory(&directory.join("records"))?;
        if fs::read_dir(directory.join("records"))?.count() >= MAX_OBJECTS {
            return Err("checkpoint record retention capacity exhausted".into());
        }
        create(
            &directory
                .join("records")
                .join(bundle::hex(&manifest.head()?)),
            &serde_json::to_vec(&manifest)?,
            0o400,
        )?;
        Ok(manifest)
    }

    fn check(&mut self) -> Result<()> {
        if self.poisoned {
            return Err("resource checkpoint authority is fenced".into());
        }
        let result = (|| {
            tpm::private_directory(&self.directory)?;
            let metadata = fs::symlink_metadata(&self.directory)?;
            if (metadata.dev(), metadata.ino()) != self.identity
                || decode(&self.directory.join("head.json"))? != self.manifest
                || self.anchor.read()? != self.manifest.head()?
            {
                return Err("paired checkpoint authority changed".into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn verify(&mut self, resources: &Path) -> Result<()> {
        self.check()?;
        let result = (|| {
            for member in &self.manifest.members {
                let bytes = exact_read(&resources.join(&member.name), MAX_BYTES)?;
                if bytes.len() as u64 != member.length || hash(&bytes) != member.sha256 {
                    return Err("paired resource closure differs from protected head".into());
                }
            }
            self.check()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn verify_pair(&mut self, resources: &Path) -> Result<()> {
        self.check()?;
        let result = (|| {
            for member in self
                .manifest
                .members
                .iter()
                .filter(|m| matches!(m.name.as_str(), "ledger.json" | "requests.json"))
            {
                let bytes = exact_read(&resources.join(&member.name), MAX_BYTES)?;
                if bytes.len() as u64 != member.length || hash(&bytes) != member.sha256 {
                    return Err("hot pair differs from the protected resource head".into());
                }
            }
            self.check()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn publish(
        &mut self,
        resources: &Path,
        name: &str,
        bytes: &[u8],
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if !matches!(name, "ledger.json" | "requests.json") {
            return Err("checkpoint publication target is not a pair member".into());
        }
        self.verify(resources)?;
        let result = (|| {
            let next = Self::stage(
                &self.directory,
                &self.manifest.installation,
                self.manifest
                    .sequence
                    .checked_add(1)
                    .ok_or("checkpoint sequence exhausted")?,
                self.manifest.head()?,
                resources,
                Some((name, bytes)),
            )?;
            create(
                &self.directory.join("prepared.json"),
                &serde_json::to_vec(&next)?,
                0o600,
            )?;
            self.verify(resources)?;
            if decode(&self.directory.join("prepared.json"))? != next {
                return Err("prepared resource pair changed".into());
            }
            let wanted = next.head()?;
            if self.anchor.advance(self.manifest.head()?, next.event()?)? != wanted {
                return Err("resource NV outcome uncertain; preserve preparation".into());
            }
            // The durable prepared closure precedes NV. No success can escape
            // until the exact pair and every referenced archive read back.
            publish(&resources.join(name), bytes)?;
            for member in &next.members {
                let actual = exact_read(&resources.join(&member.name), MAX_BYTES)?;
                if actual.len() as u64 != member.length || hash(&actual) != member.sha256 {
                    return Err("post-extend paired publication differs".into());
                }
            }
            if self.anchor.read()? != wanted {
                return Err("protected pair changed before confirmation".into());
            }
            platform::write_atomic(
                &self.directory.join("head.json"),
                &serde_json::to_vec(&next)?,
                0o600,
            )?;
            if decode(&self.directory.join("head.json"))? != next || self.anchor.read()? != wanted {
                return Err("checkpoint confirmation uncertain".into());
            }
            fs::remove_file(self.directory.join("prepared.json"))?;
            File::open(&self.directory)?.sync_all()?;
            self.manifest = next;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn recovery_review(
        directory: &Path,
        resources: &Path,
        installation: &str,
        anchor: &mut dyn tpm::Checkpoint,
    ) -> Result<serde_json::Value> {
        let (manifest, source) = selected(directory, installation, anchor)?;
        validate_backups(directory, &manifest)?;
        let evidence = damage_inventory(resources, &manifest)?;
        let review = hash(&serde_json::to_vec(&(
            manifest.clone(),
            source.clone(),
            evidence.clone(),
        ))?);
        Ok(
            serde_json::json!({"schema_version":1,"review_sha256":review,
            "checkpoint_head":bundle::hex(&manifest.head()?),"sequence":manifest.sequence.to_string(),
            "manifest":source,"damaged_members":evidence,"resources_released":false,
            "service_restart":false,"automatic_retry":false}),
        )
    }

    fn unreferenced(&mut self, resources: &Path, names: &[String]) -> Result<serde_json::Value> {
        if names.is_empty() || names.len() > 64 || names.windows(2).any(|w| w[0] >= w[1]) {
            return Err(
                "checkpoint retention requires one to 64 unique sorted backup digests".into(),
            );
        }
        self.verify(resources)?;
        match fs::symlink_metadata(self.directory.join("prepared.json")) {
            Ok(_) => return Err("interrupted checkpoint forbids backup disposition".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut members = BTreeMap::new();
        for name in names {
            let record = name.strip_prefix("record-");
            let digest = record.unwrap_or(name);
            tpm::decode::<32>(digest)?;
            if record.is_some() && digest == bundle::hex(&self.manifest.head()?) {
                return Err("current protected recovery record cannot be deleted".into());
            }
            if record.is_none() && self.manifest.members.iter().any(|m| &m.sha256 == name) {
                return Err("current protected closure backup cannot be deleted".into());
            }
            let path = self
                .directory
                .join(if record.is_some() {
                    "records"
                } else {
                    "objects"
                })
                .join(digest);
            let m = fs::symlink_metadata(&path)?;
            if record.is_some() {
                let manifest = decode(&path)?;
                if bundle::hex(&manifest.head()?) != digest {
                    return Err("retained checkpoint record digest mismatch".into());
                }
            } else {
                let bytes = exact_read(&path, MAX_BYTES)?;
                if hash(&bytes) != *name {
                    return Err("unreferenced checkpoint backup digest mismatch".into());
                }
                // A historical recovery record remains evidence until its own
                // separately reviewed disposition. Do not strand its closure.
                for (index, entry) in fs::read_dir(self.directory.join("records"))?.enumerate() {
                    if index >= MAX_OBJECTS {
                        return Err("checkpoint record scan bound exceeded".into());
                    }
                    let manifest = decode(&entry?.path())?;
                    if manifest.members.iter().any(|member| &member.sha256 == name) {
                        return Err(
                            "retained checkpoint history still references this backup".into()
                        );
                    }
                }
            }
            members.insert(
                name.clone(),
                serde_json::json!({"device":m.dev().to_string(),
                "inode":m.ino().to_string(),"bytes":m.len().to_string(),
                "ctime":m.ctime().to_string(),"ctime_ns":m.ctime_nsec().to_string()}),
            );
        }
        self.check()?;
        Ok(
            serde_json::json!({"checkpoint_head":bundle::hex(&self.manifest.head()?),"members":members}),
        )
    }

    pub(crate) fn retention_proposal(
        &mut self,
        resources: &Path,
        names: &[String],
    ) -> Result<serde_json::Value> {
        let inventory = self.unreferenced(resources, names)?;
        Ok(
            serde_json::json!({"schema_version":1,"review_sha256":hash(&serde_json::to_vec(&inventory)?),
            "inventory":inventory,"referenced_bytes_deleted":false,"resources_released":false}),
        )
    }

    pub(crate) fn delete_unreferenced(
        &mut self,
        resources: &Path,
        names: &[String],
        review: &str,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        check()?;
        let expected = self.unreferenced(resources, names)?;
        if hash(&serde_json::to_vec(&expected)?) != review {
            return Err("stale checkpoint backup retention review".into());
        }
        check()?;
        if self.unreferenced(resources, names)? != expected {
            return Err("checkpoint backup retention identity changed".into());
        }
        let mut removed = Vec::new();
        for name in names {
            check()?;
            let current = self.unreferenced(resources, std::slice::from_ref(name))?;
            if current["checkpoint_head"] != expected["checkpoint_head"]
                || current["members"][name] != expected["members"][name]
            {
                return Err("checkpoint backup changed before disposition".into());
            }
            check()?;
            self.check()?;
            let record = name.strip_prefix("record-");
            let path = self
                .directory
                .join(if record.is_some() {
                    "records"
                } else {
                    "objects"
                })
                .join(record.unwrap_or(name));
            let m = fs::symlink_metadata(&path)?;
            let identity = serde_json::json!({"device":m.dev().to_string(),"inode":m.ino().to_string(),
                "bytes":m.len().to_string(),"ctime":m.ctime().to_string(),"ctime_ns":m.ctime_nsec().to_string()});
            if identity != expected["members"][name] {
                return Err("checkpoint backup inode changed at unlink boundary".into());
            }
            fs::remove_file(&path)?;
            File::open(path.parent().ok_or("checkpoint retention parent absent")?)?.sync_all()?;
            match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("checkpoint backup disposition uncertain".into()),
            }
            removed.push(name.clone());
        }
        check()?;
        self.check()?;
        Ok(
            serde_json::json!({"schema_version":1,"deleted_unreferenced_backups":removed,
            "referenced_bytes_deleted":false,"resources_released":false}),
        )
    }

    pub(crate) fn recover(
        directory: &Path,
        resources: &Path,
        installation: &str,
        anchor: &mut dyn tpm::Checkpoint,
        review: &str,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        let pins = [
            DirectoryPin::new(directory)?,
            DirectoryPin::new(resources)?,
            DirectoryPin::new(&directory.join("objects"))?,
            DirectoryPin::new(&directory.join("records"))?,
            DirectoryPin::new(directory.parent().ok_or("checkpoint parent absent")?)?,
        ];
        let check_directories = || -> Result<()> {
            for pin in &pins {
                pin.check()?;
            }
            Ok(())
        };
        check()?;
        check_directories()?;
        let prior = Self::recovery_review(directory, resources, installation, anchor)?;
        if prior["review_sha256"].as_str() != Some(review) {
            return Err("stale protected pair recovery review".into());
        }
        let (manifest, _) = selected(directory, installation, anchor)?;
        check()?;
        check_directories()?;
        if Self::recovery_review(directory, resources, installation, anchor)? != prior {
            return Err("paired recovery evidence changed after authorization".into());
        }
        let incident = resources.join(format!("checkpoint-incident-{}", random_id()?));
        fs::DirBuilder::new().mode(0o700).create(&incident)?;
        File::open(resources)?.sync_all()?;
        let incident_pin = DirectoryPin::new(&incident)?;
        for name in ["head.json", "prepared.json"] {
            match fs::symlink_metadata(directory.join(name)) {
                Ok(_) => create(
                    &incident.join(name),
                    &exact_read(&directory.join(name), MAX_MANIFEST)?,
                    0o600,
                )?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        for member in &manifest.members {
            check()?;
            check_directories()?;
            incident_pin.check()?;
            let path = resources.join(&member.name);
            let backup = exact_read(&directory.join("objects").join(&member.sha256), MAX_BYTES)?;
            if backup.len() as u64 != member.length
                || hash(&backup) != member.sha256
                || anchor.read()? != manifest.head()?
            {
                return Err("anchored recovery snapshot changed".into());
            }
            check_directories()?;
            if member_inventory(&path)? != prior["damaged_members"][&member.name] {
                return Err("resource member changed after recovery review".into());
            }
            let mut unchanged = false;
            match fs::symlink_metadata(&path) {
                Ok(m) => {
                    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o600
                    {
                        return Err("unsafe damaged member cannot be implicitly replaced".into());
                    }
                    // Retain exact damaged bytes before replacement. The
                    // reviewed original inode identity is checked separately.
                    let bytes = exact_read(&path, MAX_BYTES)?;
                    unchanged = bytes == backup;
                    check()?;
                    check_directories()?;
                    incident_pin.check()?;
                    if member_inventory(&path)? != prior["damaged_members"][&member.name] {
                        return Err("damaged resource member changed after review".into());
                    }
                    if !unchanged {
                        create(&incident.join(&member.name), &bytes, 0o600)?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            check()?;
            if anchor.read()? != manifest.head()? {
                return Err("NV changed before exact resource repair".into());
            }
            check_directories()?;
            incident_pin.check()?;
            // Authentication and TPM observation may block. Recheck the exact
            // reviewed inode or absence after both, at the replacement boundary.
            if member_inventory(&path)? != prior["damaged_members"][&member.name] {
                return Err("reviewed resource identity changed at repair boundary".into());
            }
            if unchanged {
                continue;
            }
            platform::write_atomic(&path, &backup, 0o600)?;
            check_directories()?;
            if exact_read(&path, MAX_BYTES)? != backup {
                return Err("resource repair readback uncertain".into());
            }
        }
        check()?;
        check_directories()?;
        if closure(resources, None, |_, _| Ok(()))? != manifest.members
            || anchor.read()? != manifest.head()?
        {
            return Err("restored closure does not equal the protected pair".into());
        }
        platform::write_atomic(
            &directory.join("head.json"),
            &serde_json::to_vec(&manifest)?,
            0o600,
        )?;
        check_directories()?;
        if decode(&directory.join("head.json"))? != manifest || anchor.read()? != manifest.head()? {
            return Err("paired repair confirmation uncertain".into());
        }
        // Preserve interrupted intent, rather than converting a missing reply
        // into permission to dispatch the extend again.
        match fs::symlink_metadata(directory.join("prepared.json")) {
            Ok(_) => {
                fs::remove_file(directory.join("prepared.json"))?;
                File::open(directory)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        check()?;
        check_directories()?;
        Ok(
            serde_json::json!({"schema_version":1,"checkpoint_head":bundle::hex(&manifest.head()?),
            "restored_exact_pair":true,"incident":incident.file_name().and_then(|s|s.to_str()),
            "resources_released":false,"services_restarted":false,"new_authority_dispatched":false}),
        )
    }
}

fn selected(
    directory: &Path,
    installation: &str,
    anchor: &mut dyn tpm::Checkpoint,
) -> Result<(Manifest, String)> {
    tpm::private_directory(directory)?;
    let nv = anchor.read()?;
    // The protected NV value supplies the lookup key. Missing/damaged mutable
    // pointers cannot select a stale immutable recovery record by themselves.
    let record = format!("records/{}", bundle::hex(&nv));
    let mut candidates = Vec::new();
    for name in ["head.json", "prepared.json", record.as_str()] {
        match fs::symlink_metadata(directory.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        if let Ok(manifest) = decode(&directory.join(name)) {
            if manifest.installation == installation && manifest.head()? == nv {
                candidates.push((manifest, name.into()));
            }
        }
    }
    let Some((first, _)) = candidates.first() else {
        return Err("no resource closure authenticated by current TPM head".into());
    };
    if candidates.iter().any(|(manifest, _)| manifest != first) {
        return Err("conflicting resource closures match the current protected head".into());
    }
    Ok(candidates.remove(0))
}

fn validate_backups(directory: &Path, manifest: &Manifest) -> Result<()> {
    for member in &manifest.members {
        let bytes = exact_read(&directory.join("objects").join(&member.sha256), MAX_BYTES)?;
        if bytes.len() as u64 != member.length || hash(&bytes) != member.sha256 {
            return Err("protected checkpoint backup closure damaged".into());
        }
    }
    Ok(())
}

fn damage_inventory(resources: &Path, manifest: &Manifest) -> Result<serde_json::Value> {
    tpm::private_directory(resources)?;
    let mut observed = BTreeMap::new();
    for member in &manifest.members {
        let value = member_inventory(&resources.join(&member.name))?;
        observed.insert(member.name.clone(), value);
    }
    Ok(serde_json::to_value(observed)?)
}

fn usage(
    action: crate::finite_grants::Action,
    id: &str,
    review: &str,
    units: u64,
) -> Result<crate::finite_grants::Use> {
    let value = crate::finite_grants::Use {
        action,
        selector: crate::finite_grants::Selector {
            kind: crate::finite_grants::Kind::Resource,
            id: id.into(),
            generation: 1,
            digest: review.into(),
        },
        input_bytes: 0,
        output_bytes: MAX_MANIFEST,
        units,
    };
    value.validate()?;
    Ok(value)
}

/// All mutation ceremonies retain real physical exclusion and require both
/// an exact finite grant and the freshly authenticated original product Admin.
/// Unix root and possession of the existing TPM owner secret are insufficient.
pub(crate) fn command(args: &[String]) -> Result<()> {
    use crate::resource_checkpoint::{self, Provisioner, ResourceAnchor};
    use crate::tpm::Checkpoint;
    let login = args
        .get(1)
        .ok_or("resource checkpoint command requires LOGIN")?;
    let (_, _, installation) = crate::admin_governance::current_principal(login)?;
    let guard = crate::resource_manager::recovery::shutdown_guard()?;
    let resources = Path::new(DIRECTORY);
    tpm::private_read(&resources.join("ledger.lock"), 0)?;
    let _lock = tpm::exclusive_lock(&resources.join("ledger.lock"))?;
    let root = Path::new(resource_checkpoint::DIRECTORY);
    let paired = root.join("paired");
    let report=match args {
        [mode,_] if mode=="resource-checkpoint-prepare-review"=> {
            guard.check()?;
            let report=Authority::genesis_proposal(resources,&installation)?;
            guard.check()?;
            let review=report["review_sha256"].as_str().ok_or("genesis review absent")?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-prepare",review,1)?})
        },
        [mode,_,grant,review] if mode=="resource-checkpoint-prepare"=> {
            let scope=usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-prepare",review,1)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary| {
                let resource_pin = DirectoryPin::new(resources)?;
                boundary.require_admin()?;guard.check()?;
                if Authority::genesis_proposal(resources,&installation)?["review_sha256"].as_str()!=Some(review.as_str()) {
                    return Err("resource genesis preparation review changed".into());
                }
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Checkpoint)?;
                resource_pin.check()?;
                match fs::symlink_metadata(root) {
                    Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{
                        fs::DirBuilder::new().mode(0o700).create(root)?;
                        File::open(root.parent().ok_or("resource checkpoint parent absent")?)?.sync_all()?;
                    },
                    Err(e)=>return Err(e.into()),Ok(_)=>tpm::private_directory(root)?,
                }
                let root_pin = DirectoryPin::new(root)?;
                boundary.require_admin()?;guard.check()?;
                resource_pin.check()?;root_pin.check()?;
                if Authority::genesis_proposal(resources,&installation)?["review_sha256"].as_str()!=Some(review.as_str()) {
                    return Err("resource genesis changed after effect authorization".into());
                }
                let manifest=Authority::prepare_genesis(&paired,resources,&installation)?;
                resource_pin.check()?;root_pin.check()?;
                if hash(&serde_json::to_vec(&(&installation,&manifest.members))?) != *review {
                    return Err("prepared resource closure differs from the approved genesis review".into());
                }
                let report=serde_json::json!({"prepared_pair":true,"genesis_event":bundle::hex(&manifest.event()?),
                    "tpm_write":false,"resources_released":false});
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;
                Ok(report)
            })?
        },
        [mode,_] if mode=="resource-checkpoint-enroll-review"=> {
            let manifest=Authority::prepared_genesis(&paired,resources,&installation)?;
            let mut provisioner=Provisioner::local()?;
            let report=provisioner.proposal(&installation,manifest.event()?)?;
            guard.check()?;
            let review=report["review_sha256"].as_str().ok_or("resource enrollment review absent")?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-enroll",review,1)?})
        },
        [mode,_,grant,review] if mode=="resource-checkpoint-enroll"=> {
            let manifest=Authority::prepared_genesis(&paired,resources,&installation)?;
            let scope=usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-enroll",review,1)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary| {
                boundary.require_admin()?;guard.check()?;
                let owner=crate::authentication::existing_owner()?;
                let secret=crate::sealed_credential::Secret::generate()?;
                let provisioner=Provisioner::local()?;
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Checkpoint)?;
                let mut check=|| {
                    boundary.require_admin()?;guard.check()?;
                    if Authority::prepared_genesis(&paired,resources,&installation)?!=manifest {
                        return Err("paired genesis changed at resource enrollment dispatch".into());
                    }
                    Ok(())
                };
                let enrollment=provisioner.prepare(&installation,manifest.event()?,review,&owner,&secret,&mut check)?;
                let mut anchor=enrollment.commit(&owner,&secret,&mut check)?;
                if anchor.genesis_event()!=manifest.event()? {return Err("sealed resource genesis differs from reviewed pair".into());}
                Authority::complete_genesis(&paired,resources,&installation,&mut anchor,||{
                    boundary.require_admin()?;guard.check()
                })?;
                let report=serde_json::json!({"enrolled":true,"checkpoint_head":bundle::hex(&anchor.read()?),
                    "resources_released":false,"services_restarted":false,"physical_qualification":false});
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;
                Ok(report)
            })?
        },
        [mode,_] if mode=="resource-checkpoint-parent-review"=> {
            Authority::prepared_genesis(&paired,resources,&installation)?;
            let report=resource_checkpoint::parent_pending_report()?;
            let review=report["review_sha256"].as_str().ok_or("parent continuation review absent")?;
            guard.check()?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-parent-continue",review,1)?})
        },
        [mode,_,grant,review] if mode=="resource-checkpoint-parent-continue"=> {
            let manifest=Authority::prepared_genesis(&paired,resources,&installation)?;
            let scope=usage(crate::finite_grants::Action::ProvisionResource,"resource-checkpoint-parent-continue",review,1)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary|{
                boundary.require_admin()?;guard.check()?;
                let owner=crate::authentication::existing_owner()?;
                let secret=crate::sealed_credential::Secret::generate()?;
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Checkpoint)?;
                let mut check=||{
                    boundary.require_admin()?;guard.check()?;
                    if Authority::prepared_genesis(&paired,resources,&installation)?!=manifest {
                        return Err("paired genesis changed at parent continuation".into());
                    }
                    Ok(())
                };
                let enrollment=resource_checkpoint::continue_parent(&installation,manifest.event()?,review,&secret,&mut check)?;
                let mut anchor=enrollment.commit(&owner,&secret,&mut check)?;
                if anchor.genesis_event()!=manifest.event()? {return Err("continued resource genesis differs from reviewed pair".into());}
                Authority::complete_genesis(&paired,resources,&installation,&mut anchor,||{boundary.require_admin()?;guard.check()})?;
                let report=serde_json::json!({"enrolled":true,"parent_persistence_retry":false,
                    "checkpoint_head":bundle::hex(&anchor.read()?),"resources_released":false});
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;Ok(report)
            })?
        },
        [mode,_] if mode=="resource-checkpoint-pending-review"=> {
            let report=resource_checkpoint::pending_report()?;
            let review=report["review_sha256"].as_str().ok_or("pending enrollment review absent")?;
            guard.check()?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::RecoverResource,"resource-checkpoint-finalize",review,1)?})
        },
        [mode,_,grant,review] if mode=="resource-checkpoint-finalize"=> {
            let manifest=Authority::prepared_genesis(&paired,resources,&installation)?;
            let scope=usage(crate::finite_grants::Action::RecoverResource,"resource-checkpoint-finalize",review,1)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary|{
                boundary.require_admin()?;guard.check()?;
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Recovery)?;
                let mut anchor=resource_checkpoint::finalize_pending(&installation,manifest.event()?,review,||{
                    boundary.require_admin()?;guard.check()?;
                    if Authority::prepared_genesis(&paired,resources,&installation)?!=manifest {
                        return Err("pending resource genesis changed".into());
                    }Ok(())
                })?;
                if anchor.genesis_event()!=manifest.event()? {return Err("confirmed resource genesis differs from reviewed pair".into());}
                Authority::complete_genesis(&paired,resources,&installation,&mut anchor,||{boundary.require_admin()?;guard.check()})?;
                let report=serde_json::json!({"enrollment_finalized":true,"nv_write_retry":false,
                    "checkpoint_head":bundle::hex(&anchor.read()?),"resources_released":false});
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;Ok(report)
            })?
        },
        [mode,_] if mode=="resource-checkpoint-recovery-review"=> {
            let mut anchor=ResourceAnchor::installed()?;
            if anchor.installation()!=installation {return Err("resource authority installation differs from Admin".into());}
            let report=Authority::recovery_review(&paired,resources,&installation,&mut anchor)?;
            let review=report["review_sha256"].as_str().ok_or("resource recovery review absent")?;
            guard.check()?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::RecoverResource,"resource-checkpoint-recovery",review,1)?})
        },
        [mode,_,grant,review] if mode=="resource-checkpoint-recover"=> {
            let mut anchor=ResourceAnchor::installed()?;
            if anchor.installation()!=installation {return Err("resource authority installation differs from Admin".into());}
            let scope=usage(crate::finite_grants::Action::RecoverResource,"resource-checkpoint-recovery",review,1)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary|{
                boundary.require_admin()?;guard.check()?;
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Recovery)?;
                let report=Authority::recover(&paired,resources,&installation,&mut anchor,review,||{
                    boundary.require_admin()?;guard.check()
                })?;
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;Ok(report)
            })?
        },
        [mode,_,names @ ..] if mode=="resource-checkpoint-gc-review"&&!names.is_empty()=> {
            let anchor=ResourceAnchor::installed()?;
            let mut authority=Authority::open(&paired,resources,&installation,Box::new(anchor))?;
            let report=authority.retention_proposal(resources,names)?;
            let review=report["review_sha256"].as_str().ok_or("checkpoint retention review absent")?;
            guard.check()?;
            serde_json::json!({"proposal":report,"usage":usage(crate::finite_grants::Action::Retain,"resource-checkpoint-retention",review,names.len() as u64)?})
        },
        [mode,_,grant,review,names @ ..] if mode=="resource-checkpoint-gc"&&!names.is_empty()=> {
            let anchor=ResourceAnchor::installed()?;
            let mut authority=Authority::open(&paired,resources,&installation,Box::new(anchor))?;
            let scope=usage(crate::finite_grants::Action::Retain,"resource-checkpoint-retention",review,names.len() as u64)?;
            crate::admin_governance::with_grant(login,grant,&scope,|boundary|{
                boundary.require_admin()?;guard.check()?;
                let pending=boundary.effect_begin(review,crate::policy_decisions::EffectKind::Retention)?;
                let report=authority.delete_unreferenced(resources,names,review,||{boundary.require_admin()?;guard.check()})?;
                boundary.effect_complete(pending,&hash(&serde_json::to_vec(&report)?))?;Ok(report)
            })?
        },
        _=>return Err("expected typed resource-checkpoint prepare/enroll/pending/recovery/gc ceremony; no reset or ownership takeover".into()),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    struct Memory {
        head: Rc<Cell<[u8; 32]>>,
        writes: Rc<Cell<usize>>,
        lost: bool,
    }
    impl tpm::Checkpoint for Memory {
        fn read(&mut self) -> Result<[u8; 32]> {
            Ok(self.head.get())
        }
        fn clock(&mut self) -> Result<tpm::Clock> {
            Ok(tpm::Clock {
                milliseconds: 1,
                reset_count: 0,
                restart_count: 0,
            })
        }
        fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
            if self.head.get() != expected {
                return Err("fixture head conflict".into());
            }
            let next = tpm::extend_value(expected, event);
            self.head.set(next);
            self.writes.set(self.writes.get() + 1);
            if self.lost {
                Err("fixture lost reply".into())
            } else {
                Ok(next)
            }
        }
    }
    struct Fixture {
        root: PathBuf,
        resources: PathBuf,
        paired: PathBuf,
        installation: String,
        head: Rc<Cell<[u8; 32]>>,
        writes: Rc<Cell<usize>>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("luma-paired-checkpoint-{}", random_id().unwrap()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let resources = root.join("resources");
            initialize(&resources).unwrap();
            let paired = root.join("paired");
            let installation = "a1".repeat(32);
            let manifest = Authority::prepare_genesis(&paired, &resources, &installation).unwrap();
            let head = Rc::new(Cell::new(manifest.head().unwrap()));
            let writes = Rc::new(Cell::new(0));
            let f = Self {
                root,
                resources,
                paired,
                installation,
                head,
                writes,
            };
            Authority::complete_genesis(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
                || Ok(()),
            )
            .unwrap();
            f
        }
        fn anchor(&self, lost: bool) -> Memory {
            Memory {
                head: self.head.clone(),
                writes: self.writes.clone(),
                lost,
            }
        }
        fn open(&self, lost: bool) -> Authority {
            Authority::open(
                &self.paired,
                &self.resources,
                &self.installation,
                Box::new(self.anchor(lost)),
            )
            .unwrap()
        }
        fn next(&self) -> Vec<u8> {
            let mut ledger: Ledger =
                serde_json::from_slice(&fs::read(self.resources.join("ledger.json")).unwrap())
                    .unwrap();
            ledger
                .restart(
                    "a".repeat(32),
                    BTreeMap::from([("host".into(), Domain::new(1000, 100, 950, 800).unwrap())]),
                )
                .unwrap();
            serde_json::to_vec(&ledger).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn exact_paired_publish_rejects_whole_filesystem_rollback_against_live_head() {
        let f = Fixture::new();
        let old_head = fs::read(f.paired.join("head.json")).unwrap();
        let old_ledger = fs::read(f.resources.join("ledger.json")).unwrap();
        let mut a = f.open(false);
        a.publish(&f.resources, "ledger.json", &f.next(), |p, b| {
            platform::write_atomic(p, b, 0o600)
        })
        .unwrap();
        assert_eq!(f.writes.get(), 1);
        fs::remove_file(f.paired.join("records").join(bundle::hex(&f.head.get()))).unwrap();
        drop(a);
        platform::write_atomic(&f.resources.join("ledger.json"), &old_ledger, 0o600).unwrap();
        platform::write_atomic(&f.paired.join("head.json"), &old_head, 0o600).unwrap();
        assert!(Authority::open(
            &f.paired,
            &f.resources,
            &f.installation,
            Box::new(f.anchor(false))
        )
        .is_err());
        assert!(Authority::recovery_review(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false)
        )
        .is_err());
        assert_eq!(f.writes.get(), 1);
    }

    #[test]
    fn missing_mutable_head_is_recovered_only_through_nv_addressed_immutable_record() {
        let f = Fixture::new();
        fs::remove_file(f.paired.join("head.json")).unwrap();
        let p = Authority::recovery_review(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false),
        )
        .unwrap();
        assert!(p["manifest"].as_str().unwrap().starts_with("records/"));
        Authority::recover(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false),
            p["review_sha256"].as_str().unwrap(),
            || Ok(()),
        )
        .unwrap();
        f.open(false).verify(&f.resources).unwrap();
        assert_eq!(f.writes.get(), 0);
    }

    #[test]
    fn lost_extend_reply_is_not_retried_and_explicit_recovery_selects_only_current_nv() {
        let f = Fixture::new();
        let wanted = f.next();
        let mut a = f.open(true);
        assert!(a
            .publish(&f.resources, "ledger.json", &wanted, |p, b| {
                platform::write_atomic(p, b, 0o600)
            })
            .is_err());
        assert_eq!(f.writes.get(), 1);
        assert!(a
            .publish(&f.resources, "ledger.json", &wanted, |_, _| panic!(
                "no redispatch"
            ))
            .is_err());
        drop(a);
        assert!(Authority::open(
            &f.paired,
            &f.resources,
            &f.installation,
            Box::new(f.anchor(false))
        )
        .is_err());
        let proposal = Authority::recovery_review(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false),
        )
        .unwrap();
        assert!(Authority::recover(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false),
            &"f".repeat(64),
            || Ok(())
        )
        .is_err());
        let receipt = Authority::recover(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false),
            proposal["review_sha256"].as_str().unwrap(),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(receipt["resources_released"], false);
        assert_eq!(fs::read(f.resources.join("ledger.json")).unwrap(), wanted);
        assert_eq!(f.writes.get(), 1);
        f.open(false).verify(&f.resources).unwrap();
    }

    #[test]
    fn publication_damage_and_empty_hot_files_are_reconstructed_without_empty_authority() {
        for missing in [false, true] {
            let f = Fixture::new();
            let wanted = f.next();
            let mut a = f.open(false);
            assert!(a
                .publish(&f.resources, "ledger.json", &wanted, |_, _| Err(
                    "fixture publication failure".into()
                ))
                .is_err());
            if missing {
                fs::remove_file(f.resources.join("requests.json")).unwrap();
            } else {
                platform::write_atomic(&f.resources.join("ledger.json"), b"", 0o600).unwrap();
            }
            let proposal = Authority::recovery_review(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
            )
            .unwrap();
            Authority::recover(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
                proposal["review_sha256"].as_str().unwrap(),
                || Ok(()),
            )
            .unwrap();
            assert_eq!(fs::read(f.resources.join("ledger.json")).unwrap(), wanted);
            f.open(false).verify(&f.resources).unwrap();
        }
    }

    #[test]
    fn recovery_refuses_substitution_during_final_authority_observation() {
        // Existing damaged, previously absent, and already correct targets all
        // retain their reviewed identity; correct bytes alone do not authorize
        // replacing a different inode observed during authentication.
        for (missing, correct) in [(false, false), (true, false), (false, true)] {
            let f = Fixture::new();
            let path = f.resources.join("ledger.json");
            if missing {
                fs::remove_file(&path).unwrap();
            } else if !correct {
                platform::write_atomic(&path, b"reviewed damage", 0o600).unwrap();
            }
            let proposal = Authority::recovery_review(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
            )
            .unwrap();
            let mut calls = 0;
            let mut substituted = false;
            let replacement = if missing {
                b"unreviewed new target".to_vec()
            } else {
                fs::read(&path).unwrap()
            };
            let result = Authority::recover(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
                proposal["review_sha256"].as_str().unwrap(),
                || {
                    calls += 1;
                    if calls == if missing { 4 } else { 5 } {
                        platform::write_atomic(&path, &replacement, 0o600)?;
                        substituted = true;
                    }
                    Ok(())
                },
            );
            assert!(substituted, "fixture must exercise the final observation");
            assert!(result.is_err());
            assert_eq!(fs::read(&path).unwrap(), replacement);
            assert_eq!(f.writes.get(), 0);
        }
    }

    #[test]
    fn recovery_refuses_private_directory_replacement_during_authorization() {
        for replace_resources in [true, false] {
            let f = Fixture::new();
            let proposal = Authority::recovery_review(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
            )
            .unwrap();
            let path = if replace_resources {
                &f.resources
            } else {
                &f.paired
            };
            let retained = f.root.join("retained-directory");
            let mut calls = 0;
            let mut substituted = false;
            let result = Authority::recover(
                &f.paired,
                &f.resources,
                &f.installation,
                &mut f.anchor(false),
                proposal["review_sha256"].as_str().unwrap(),
                || {
                    calls += 1;
                    if calls == 3 {
                        fs::rename(path, &retained)?;
                        fs::DirBuilder::new().mode(0o700).create(path)?;
                        substituted = true;
                    }
                    Ok(())
                },
            );
            assert!(substituted);
            assert!(result.is_err());
            assert_eq!(fs::read_dir(path).unwrap().count(), 0);
            assert_eq!(f.writes.get(), 0);
        }
    }

    #[test]
    fn damaged_backups_wrong_installation_and_linked_files_never_become_authority() {
        let f = Fixture::new();
        assert!(Authority::recovery_review(
            &f.paired,
            &f.resources,
            &"b1".repeat(32),
            &mut f.anchor(false)
        )
        .is_err());
        let manifest = decode(&f.paired.join("head.json")).unwrap();
        let path = f.paired.join("objects").join(&manifest.members[0].sha256);
        fs::hard_link(&path, f.root.join("alias")).unwrap();
        assert!(Authority::recovery_review(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false)
        )
        .is_err());
        fs::remove_file(f.root.join("alias")).unwrap();
        platform::write_atomic(&path, b"corrupt", 0o400).unwrap();
        assert!(Authority::recovery_review(
            &f.paired,
            &f.resources,
            &f.installation,
            &mut f.anchor(false)
        )
        .is_err());
        assert_eq!(f.writes.get(), 0);
    }

    #[test]
    fn backup_retention_refuses_current_closure_and_retains_bytes_on_revocation() {
        let f = Fixture::new();
        let mut a = f.open(false);
        let current = decode(&f.paired.join("head.json")).unwrap().members[0]
            .sha256
            .clone();
        assert!(a.retention_proposal(&f.resources, &[current]).is_err());
        let bytes = b"redundant backup";
        let name = hash(bytes);
        create(&f.paired.join("objects").join(&name), bytes, 0o400).unwrap();
        let names = vec![name.clone()];
        let p = a.retention_proposal(&f.resources, &names).unwrap();
        assert!(a
            .delete_unreferenced(
                &f.resources,
                &names,
                p["review_sha256"].as_str().unwrap(),
                || Err("revoked".into())
            )
            .is_err());
        assert_eq!(
            fs::read(f.paired.join("objects").join(&name)).unwrap(),
            bytes
        );
        a.delete_unreferenced(
            &f.resources,
            &names,
            p["review_sha256"].as_str().unwrap(),
            || Ok(()),
        )
        .unwrap();
        assert!(!f.paired.join("objects").join(&name).exists());
        assert_eq!(f.writes.get(), 0);
    }
}
