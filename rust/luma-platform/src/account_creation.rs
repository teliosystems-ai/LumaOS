//! Private, governed creation proposals. Initial accounts remain locked until
//! protected password-aging establishment and explicit governed activation.
use crate::{
    account_deletion::Change, bundle, principal, sealed_credential::PrivateBuffer, tpm, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const FILES: [&str; 5] = ["gshadow", "group", "shadow", "passwd", "registry"];
pub(crate) const HOME: &str = "/var/home";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub transaction: String,
    pub principal: principal::Principal,
    pub registry_before: principal::Registry,
    pub registry_after: principal::Registry,
    pub home_nonce: String,
    pub credential_after: String,
    pub files: BTreeMap<String, Change>,
}

impl Intent {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::admin_roles::identifier(&self.transaction)
            || self.transaction == "admin-bootstrap-v1"
            || !(1000..60000).contains(&self.principal.uid)
            || self.registry_before.append_account(&self.principal)? != self.registry_after
            || self
                .files
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != FILES.into_iter().collect()
            || tpm::decode::<32>(&self.home_nonce)? == [0; 32]
            || tpm::decode::<32>(&self.credential_after)? == [0; 32]
        {
            return Err("invalid account creation intent".into());
        }
        for (name, change) in &self.files {
            if tpm::decode::<32>(&change.before)? == [0; 32]
                || tpm::decode::<32>(&change.after)? == [0; 32]
                || change.before == change.after
                || !matches!(change.mode, 0o600 | 0o640 | 0o644)
                || (name.ends_with("shadow") && change.mode == 0o644)
                || (name == "registry" && (change.mode != 0o600 || change.gid != 0))
            {
                return Err("invalid account creation file manifest".into());
            }
        }
        Ok(())
    }
    fn marker(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "installation":self.registry_before.installation(),"transaction":self.transaction,
            "principal":self.principal,"nonce":self.home_nonce}))?)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Transition {
    pub intent: Intent,
    pub phase: crate::account_transition::Phase,
}

fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    if bytes == [0; 32] {
        return Err("account entropy unavailable".into());
    }
    Ok(bundle::hex(&bytes))
}

enum Contents {
    Private(PrivateBuffer),
    Registry(Vec<u8>),
}
impl Contents {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Private(bytes) => bytes.bytes(),
            Self::Registry(bytes) => bytes,
        }
    }
}
fn read_file(path: &Path, name: &str) -> Result<(Contents, principal::FilePin)> {
    if name == "registry" {
        let (bytes, pin) = principal::registry_file(path)?;
        Ok((Contents::Registry(bytes), pin))
    } else {
        let (bytes, pin) = principal::account_file(path, name.ends_with("shadow"))?;
        Ok((Contents::Private(bytes), pin))
    }
}

fn rows(input: &[u8], count: usize) -> Result<Vec<Vec<&str>>> {
    if input.is_empty() || !input.ends_with(b"\n") || input.iter().any(|&b| b == 0 || b == b'\r') {
        return Err("incomplete account creation source".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid account encoding")?;
    let mut names = BTreeSet::new();
    let mut result = vec![];
    for row in text.split_inclusive('\n') {
        let fields: Vec<_> = row[..row.len() - 1].split(':').collect();
        if fields.len() != count || fields[0].is_empty() || !names.insert(fields[0]) {
            return Err("ambiguous account creation source".into());
        }
        result.push(fields);
    }
    Ok(result)
}

fn vacancy(
    before: &BTreeMap<String, Contents>,
    registry: &principal::Registry,
    name: &str,
) -> Result<u32> {
    let mut reserved = BTreeSet::from([1001]);
    for record in registry.principals() {
        if record.login == name {
            return Err("account name remains reserved in installation history".into());
        }
        reserved.insert(record.uid);
    }
    let mut passwd_ids = BTreeSet::new();
    for (file, count) in [("passwd", 7), ("shadow", 9), ("group", 4), ("gshadow", 4)] {
        for row in rows(before[file].bytes(), count)? {
            if row[0] == name {
                return Err("account or group name already exists".into());
            }
            if file == "passwd" {
                let uid = row[2].parse::<u32>()?;
                if !passwd_ids.insert(uid) {
                    return Err("duplicate account uid".into());
                }
                reserved.insert(uid);
                reserved.insert(row[3].parse::<u32>()?);
            } else if file == "group" {
                reserved.insert(row[2].parse::<u32>()?);
            }
        }
    }
    (1000..60000)
        .find(|uid| !reserved.contains(uid))
        .ok_or_else(|| "account uid capacity exhausted".into())
}

fn append(before: &[u8], pieces: &[&[u8]]) -> Result<Contents> {
    let size = before.len() + pieces.iter().map(|p| p.len()).sum::<usize>();
    let mut bytes = PrivateBuffer::new(size)?;
    bytes.bytes_mut()[..before.len()].copy_from_slice(before);
    let mut offset = before.len();
    for piece in pieces {
        bytes.bytes_mut()[offset..offset + piece.len()].copy_from_slice(piece);
        offset += piece.len();
    }
    Ok(Contents::Private(bytes))
}

fn replacements(
    before: &BTreeMap<String, Contents>,
    intent: &Intent,
    crypt: &[u8],
) -> Result<BTreeMap<String, Contents>> {
    crate::account_password::validate_hash(crypt)?;
    let name = &intent.principal.login;
    if vacancy(before, &intent.registry_before, name)? != intent.principal.uid {
        return Err("account uid no longer matches the reserved vacant selection".into());
    }
    let uid = intent.principal.uid;
    let passwd = format!("{name}:x:{uid}:{uid}:Luma local user:/home/{name}:/bin/bash\n");
    let group = format!("{name}:x:{uid}:\n");
    let gshadow = format!("{name}:!::\n");
    let prefix = format!("{name}:!");
    Ok(BTreeMap::from([
        (
            "passwd".into(),
            append(before["passwd"].bytes(), &[passwd.as_bytes()])?,
        ),
        (
            "group".into(),
            append(before["group"].bytes(), &[group.as_bytes()])?,
        ),
        (
            "gshadow".into(),
            append(before["gshadow"].bytes(), &[gshadow.as_bytes()])?,
        ),
        (
            "shadow".into(),
            append(
                before["shadow"].bytes(),
                &[prefix.as_bytes(), crypt, b":0:0:99999:7:::\n"],
            )?,
        ),
        (
            "registry".into(),
            Contents::Registry(serde_json::to_vec(&intent.registry_after)?),
        ),
    ]))
}

type Identity = (u64, u64, u32, u32, u32);
fn identity(metadata: &fs::Metadata) -> Identity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    identity(a) == identity(b)
        && a.len() == b.len()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
struct Directory {
    path: PathBuf,
    file: File,
    identity: Identity,
}
impl Directory {
    fn capture(path: &Path, private: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & if private { 0o077 } else { 0o022 } != 0 {
            return Err("unsafe creation directory".into());
        }
        let directory = Self {
            path: path.into(),
            file,
            identity: identity(&metadata),
        };
        directory.recheck()?;
        Ok(directory)
    }
    fn recheck(&self) -> Result<()> {
        if identity(&self.file.metadata()?) != self.identity
            || identity(&fs::symlink_metadata(&self.path)?) != self.identity
        {
            return Err("creation directory replaced".into());
        }
        Ok(())
    }
}

struct Home {
    path: PathBuf,
    directory: File,
    identity: Identity,
    marker: File,
    marker_metadata: fs::Metadata,
    marker_bytes: Vec<u8>,
    published: bool,
}
impl Home {
    fn capture(path: &Path, intent: &Intent, published: bool) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != intent.principal.uid
            || metadata.gid() != intent.principal.uid
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("creation home ownership or permissions differ".into());
        }
        let mut marker = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path.join(".luma-creation.json"))?;
        let meta = marker.metadata()?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
            || meta.len() > 4096
        {
            return Err("invalid retained creation home marker".into());
        }
        let mut marker_bytes = vec![0; meta.len() as usize];
        marker.read_exact(&mut marker_bytes)?;
        let mut excess = [0];
        if marker.read(&mut excess)? != 0 {
            return Err("creation home marker grew".into());
        }
        if marker_bytes != intent.marker()? || !same_file(&meta, &marker.metadata()?) {
            return Err("creation home marker differs".into());
        }
        let home = Self {
            path: path.into(),
            directory,
            identity: identity(&metadata),
            marker,
            marker_metadata: meta,
            marker_bytes,
            published,
        };
        home.recheck()?;
        Ok(home)
    }
    fn recheck(&self) -> Result<()> {
        if identity(&self.directory.metadata()?) != self.identity
            || identity(&fs::symlink_metadata(&self.path)?) != self.identity
            || !same_file(&self.marker_metadata, &self.marker.metadata()?)
            || !same_file(
                &self.marker_metadata,
                &fs::symlink_metadata(self.path.join(".luma-creation.json"))?,
            )
        {
            return Err("creation home or marker replaced".into());
        }
        let mut bytes = vec![];
        let observed = self.marker.metadata()?;
        let mut marker = self.marker.try_clone()?;
        use std::io::{Seek, SeekFrom};
        marker.seek(SeekFrom::Start(0))?;
        marker.take(4097).read_to_end(&mut bytes)?;
        if bytes != self.marker_bytes
            || !same_file(&observed, &self.marker.metadata()?)
            || !same_file(
                &observed,
                &fs::symlink_metadata(self.path.join(".luma-creation.json"))?,
            )
        {
            return Err("creation home marker changed".into());
        }
        let entries = fs::read_dir(&self.path)?
            .take(2)
            .collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() != 1 {
            return Err("creation home contains unapproved state".into());
        }
        Ok(())
    }
}

pub(crate) struct Guard {
    directory: Directory,
    registry_directory: Directory,
    homes: Directory,
    registry_path: PathBuf,
    lock: File,
    lock_identity: Identity,
    before: BTreeMap<String, Contents>,
    after: BTreeMap<String, Contents>,
    source: BTreeMap<String, principal::FilePin>,
    evidence: Vec<principal::FilePin>,
    home: Option<Home>,
    published: usize,
    pub intent: Intent,
}

impl Guard {
    pub(crate) fn new(
        registry_path: &Path,
        account_directory: &Path,
        homes: &Path,
        name: &str,
        transaction: &str,
        crypt: &crate::account_password::Hash,
    ) -> Result<Self> {
        let registry = principal::RegistryBinding::capture(registry_path)?;
        let mut before = BTreeMap::new();
        let mut pins = vec![];
        let mut files = BTreeMap::new();
        for file in FILES {
            let path = if file == "registry" {
                registry_path.to_path_buf()
            } else {
                account_directory.join(file)
            };
            let (bytes, pin) = read_file(&path, file)?;
            let meta = pin.descriptor()?.metadata()?;
            files.insert(
                file.into(),
                Change {
                    before: hash(bytes.bytes()),
                    after: String::new(),
                    mode: meta.mode() & 0o777,
                    gid: meta.gid(),
                },
            );
            before.insert(file.into(), bytes);
            pins.push(pin);
        }
        let record = principal::Principal {
            id: random_id()?,
            generation: 1,
            login: name.into(),
            uid: vacancy(&before, registry.current()?, name)?,
            enabled: true,
        };
        let mut intent = Intent {
            transaction: transaction.into(),
            principal: record.clone(),
            registry_before: registry.current()?.clone(),
            registry_after: registry.current()?.append_account(&record)?,
            home_nonce: random_id()?,
            credential_after: String::new(),
            files,
        };
        let after = replacements(&before, &intent, crypt.bytes()?)?;
        for file in FILES {
            intent
                .files
                .get_mut(file)
                .ok_or("missing creation file")?
                .after = hash(after[file].bytes());
        }
        intent.credential_after = principal::rows_commitment(
            intent.registry_before.installation(),
            &record,
            principal::account_rows_digest(
                after["passwd"].bytes(),
                after["shadow"].bytes(),
                &record,
                true,
            )?,
        )?;
        intent.validate()?;
        drop(before);
        let guard = Self::capture(
            registry_path,
            account_directory,
            homes,
            &intent,
            None,
            Some(after),
        )?;
        for pin in pins {
            pin.recheck()?;
        }
        registry.current()?;
        Ok(guard)
    }

    fn capture(
        registry_path: &Path,
        account_directory: &Path,
        homes: &Path,
        intent: &Intent,
        staged: Option<&Path>,
        new_after: Option<BTreeMap<String, Contents>>,
    ) -> Result<Self> {
        intent.validate()?;
        let directory = Directory::capture(account_directory, false)?;
        let registry_directory = Directory::capture(
            registry_path.parent().ok_or("missing registry directory")?,
            true,
        )?;
        let homes = Directory::capture(homes, false)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(account_directory.join("migration.lock"))?;
        let meta = lock.metadata()?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
            || meta.len() != 0
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err("creation migration lock unavailable or unsafe".into());
        }
        let lock_identity = identity(&meta);
        let (mut before, mut after, mut source, mut evidence) =
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), vec![]);
        let mut published = 0;
        let mut unpublished = false;
        let home = if let Some(path) = staged {
            tpm::private_directory(path)?;
            let (bytes, pin) = principal::private_document(&path.join("intent.json"), 128 * 1024)?;
            if bytes != serde_json::to_vec(intent)?
                || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
            {
                return Err("creation intent changed".into());
            }
            evidence.push(pin);
            let destination = homes.path.join(&intent.principal.login);
            match fs::symlink_metadata(&destination) {
                Ok(_) => Some(Home::capture(&destination, intent, true)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Some(Home::capture(&path.join("home"), intent, false)?)
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            match fs::symlink_metadata(homes.path.join(&intent.principal.login)) {
                Ok(_) => return Err("account home already exists".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            None
        };
        for file in FILES {
            let path = if file == "registry" {
                registry_path.to_path_buf()
            } else {
                account_directory.join(file)
            };
            let (bytes, pin) = read_file(&path, file)?;
            let meta = pin.descriptor()?.metadata()?;
            let change = &intent.files[file];
            if meta.mode() & 0o777 != change.mode || meta.gid() != change.gid {
                return Err("creation source permissions changed".into());
            }
            let digest = hash(bytes.bytes());
            if digest == change.after {
                if unpublished || !home.as_ref().is_some_and(|home| home.published) {
                    return Err("unapproved creation publication order".into());
                }
                published += 1;
            } else if digest == change.before {
                unpublished = true;
            } else {
                return Err("creation source is outside its approved before/after states".into());
            }
            source.insert(file.into(), pin);
            if let Some(stage) = staged {
                for (suffix, expected, selected) in [
                    ("before", &change.before, &mut before),
                    ("after", &change.after, &mut after),
                ] {
                    let (bytes, pin) = read_file(&stage.join(format!("{file}.{suffix}")), file)?;
                    if hash(bytes.bytes()) != *expected
                        || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
                    {
                        return Err("retained creation evidence differs".into());
                    }
                    selected.insert(file.into(), bytes);
                    evidence.push(pin);
                }
            } else {
                before.insert(file.into(), bytes);
            }
        }
        let parsed: principal::Registry = serde_json::from_slice(before["registry"].bytes())?;
        if parsed != intent.registry_before {
            return Err("creation registry baseline differs".into());
        }
        if let Some(proposed) = new_after {
            if staged.is_some() {
                return Err("creation capture cannot combine new and retained evidence".into());
            }
            after = proposed;
        }
        let parsed = rows(
            after
                .get("shadow")
                .ok_or("missing creation shadow replacement")?
                .bytes(),
            9,
        )?;
        let selected = parsed
            .iter()
            .find(|row| row[0] == intent.principal.login)
            .ok_or("missing staged creation credential")?;
        let crypt = selected[1]
            .strip_prefix('!')
            .ok_or("creation credential must remain locked")?;
        let derived = replacements(&before, intent, crypt.as_bytes())?;
        for file in FILES {
            if hash(derived[file].bytes()) != intent.files[file].after
                || derived[file].bytes() != after[file].bytes()
            {
                return Err("creation modifies unrelated identity records".into());
            }
        }
        if principal::rows_commitment(
            intent.registry_before.installation(),
            &intent.principal,
            principal::account_rows_digest(
                after["passwd"].bytes(),
                after["shadow"].bytes(),
                &intent.principal,
                true,
            )?,
        )? != intent.credential_after
        {
            return Err("creation credential commitment differs".into());
        }
        let guard = Self {
            directory,
            registry_directory,
            homes,
            registry_path: registry_path.into(),
            lock,
            lock_identity,
            before,
            after,
            source,
            evidence,
            home,
            published,
            intent: intent.clone(),
        };
        guard.recheck()?;
        Ok(guard)
    }

    pub(crate) fn retained(
        registry_path: &Path,
        account_directory: &Path,
        homes: &Path,
        intent: &Intent,
    ) -> Result<Self> {
        let stage = account_directory.join(format!("account-creation-{}", intent.transaction));
        Self::capture(
            registry_path,
            account_directory,
            homes,
            intent,
            Some(&stage),
            None,
        )
    }

    fn path(&self) -> PathBuf {
        self.directory
            .path
            .join(format!("account-creation-{}", self.intent.transaction))
    }
    fn authority_recheck(&self) -> Result<()> {
        self.directory.recheck()?;
        self.registry_directory.recheck()?;
        self.homes.recheck()?;
        let meta = fs::symlink_metadata(self.directory.path.join("migration.lock"))?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
            || meta.len() != 0
            || identity(&meta) != self.lock_identity
            || identity(&self.lock.metadata()?) != self.lock_identity
        {
            return Err("creation migration lock changed".into());
        }
        for pin in &self.evidence {
            pin.recheck()?;
        }
        if let Some(home) = &self.home {
            home.recheck()?;
        }
        Ok(())
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.authority_recheck()?;
        for pin in self.source.values() {
            pin.recheck()?;
        }
        Ok(())
    }
    pub(crate) fn complete(&self) -> Result<()> {
        self.recheck()?;
        if self.published != FILES.len() || !self.home.as_ref().is_some_and(|home| home.published) {
            return Err(
                "creation completion requires the home and all identity publications".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn unpublished(&self) -> Result<()> {
        self.recheck()?;
        if self.published != 0 || self.home.as_ref().is_some_and(|home| home.published) {
            return Err("creation publication precedes its committed permission".into());
        }
        Ok(())
    }

    pub(crate) fn stage(&self, mut authorize: impl FnMut() -> Result<()>) -> Result<()> {
        self.recheck()?;
        authorize()?;
        if !self.evidence.is_empty() {
            return Ok(());
        }
        let count = fs::read_dir(&self.directory.path)?.try_fold(0usize, |count, entry| {
            let name = entry?.file_name();
            Ok::<_, std::io::Error>(
                count
                    + usize::from(
                        name.as_encoded_bytes().starts_with(b"account-creation-")
                            || name.as_encoded_bytes().starts_with(b".creation-proposal-"),
                    ),
            )
        })?;
        if count >= 128 {
            return Err("creation proposal retention exhausted; preserve evidence".into());
        }
        let temporary_name = format!(
            ".creation-proposal-{}-{}",
            self.intent.transaction,
            random_id()?
        );
        let temporary = self.directory.path.join(&temporary_name);
        fs::DirBuilder::new().mode(0o700).create(&temporary)?;
        let stage = Directory::capture(&temporary, true)?;
        for file in FILES {
            for (suffix, bytes) in [("before", &self.before[file]), ("after", &self.after[file])] {
                write_new(&temporary.join(format!("{file}.{suffix}")), bytes.bytes())?;
            }
        }
        write_new(
            &temporary.join("intent.json"),
            &serde_json::to_vec(&self.intent)?,
        )?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(temporary.join("home"))?;
        write_new(
            &temporary.join("home/.luma-creation.json"),
            &self.intent.marker()?,
        )?;
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(temporary.join("home"))?;
        if unsafe {
            libc::fchown(
                home.as_raw_fd(),
                self.intent.principal.uid,
                self.intent.principal.uid,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        home.sync_all()?;
        stage.file.sync_all()?;
        authorize()?;
        self.recheck()?;
        stage.recheck()?;
        let source = std::ffi::CString::new(temporary_name)?;
        let destination =
            std::ffi::CString::new(format!("account-creation-{}", self.intent.transaction))?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.directory.file.as_raw_fd(),
                source.as_ptr(),
                self.directory.file.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.file.sync_all()?;
        self.recheck()
    }

    pub(crate) fn publish(
        &self,
        file: &str,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        self.recheck()?;
        authorize()?;
        let path = self.path();
        let stage = Directory::capture(&path, true)?;
        if file == "home" {
            let home = self.home.as_ref().ok_or("missing retained creation home")?;
            if home.published {
                return Ok(false);
            }
            if self.published != 0 {
                return Err("home publication must precede account records".into());
            }
            home.recheck()?;
            authorize()?;
            self.recheck()?;
            stage.recheck()?;
            let target = std::ffi::CString::new(self.intent.principal.login.as_str())?;
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    stage.file.as_raw_fd(),
                    b"home\0".as_ptr().cast::<libc::c_char>(),
                    self.homes.file.as_raw_fd(),
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            stage.file.sync_all()?;
            self.homes.file.sync_all()?;
            let published = Home::capture(
                &self.homes.path.join(&self.intent.principal.login),
                &self.intent,
                true,
            )?;
            if published.identity != home.identity {
                return Err("published home inode differs".into());
            }
            self.directory.recheck()?;
            self.registry_directory.recheck()?;
            self.homes.recheck()?;
            for pin in self.source.values() {
                pin.recheck()?;
            }
            for pin in &self.evidence {
                pin.recheck()?;
            }
            return Ok(true);
        }
        let index = FILES
            .iter()
            .position(|&name| name == file)
            .ok_or("unknown creation publication file")?;
        if index < self.published {
            return Ok(false);
        }
        if index != self.published || !self.home.as_ref().is_some_and(|home| home.published) {
            return Err("creation requires ordered retained publication".into());
        }
        let next_name = format!("{file}.next");
        let next_path = path.join(&next_name);
        let mut next = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&next_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&next_path)?,
            Err(error) => return Err(error.into()),
        };
        let original = next.metadata()?;
        let bytes = self.after[file].bytes();
        let change = &self.intent.files[file];
        if !original.is_file()
            || original.uid() != 0
            || original.nlink() != 1
            || original.len() > bytes.len() as u64
            || (original.mode() & 0o7777 != 0o600
                && (original.mode() & 0o7777 != change.mode || original.gid() != change.gid))
            || ((file.ends_with("shadow") || file == "registry") && original.mode() & 0o007 != 0)
            || !same_file(&original, &fs::symlink_metadata(&next_path)?)
        {
            return Err("unsafe creation dispatch file".into());
        }
        let length = original.len() as usize;
        let mut retained = if file == "registry" {
            Contents::Registry(vec![0; bytes.len()])
        } else {
            Contents::Private(PrivateBuffer::new(bytes.len())?)
        };
        let destination = match &mut retained {
            Contents::Registry(bytes) => bytes.as_mut_slice(),
            Contents::Private(bytes) => bytes.bytes_mut(),
        };
        next.read_exact(&mut destination[..length])?;
        if retained.bytes()[..length] != bytes[..length]
            || !same_file(&original, &next.metadata()?)
            || !same_file(&original, &fs::symlink_metadata(&next_path)?)
        {
            return Err("conflicting interrupted creation dispatch; preserve state".into());
        }
        self.recheck()?;
        next.write_all(&bytes[length..])?;
        if unsafe { libc::fchown(next.as_raw_fd(), 0, change.gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        next.set_permissions(fs::Permissions::from_mode(change.mode))?;
        next.sync_all()?;
        stage.file.sync_all()?;
        authorize()?;
        self.recheck()?;
        stage.recheck()?;
        let (retained, pin) = read_file(&next_path, file)?;
        if retained.bytes() != bytes
            || !same_file(&next.metadata()?, &pin.descriptor()?.metadata()?)
        {
            return Err("creation dispatch changed".into());
        }
        self.recheck()?;
        pin.recheck()?;
        let source = std::ffi::CString::new(next_name)?;
        let target = std::ffi::CString::new(if file == "registry" {
            "registry.json"
        } else {
            file
        })?;
        let directory = if file == "registry" {
            &self.registry_directory
        } else {
            &self.directory
        };
        if unsafe {
            libc::renameat(
                stage.file.as_raw_fd(),
                source.as_ptr(),
                directory.file.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        stage.file.sync_all()?;
        directory.file.sync_all()?;
        self.authority_recheck()?;
        for (name, pin) in &self.source {
            if name != file {
                pin.recheck()?;
            }
        }
        let path = if file == "registry" {
            self.registry_path.clone()
        } else {
            self.directory.path.join(file)
        };
        let (published, pin) = read_file(&path, file)?;
        if published.bytes() != bytes
            || !same_file(&next.metadata()?, &pin.descriptor()?.metadata()?)
        {
            return Err("published creation inode or bytes differ".into());
        }
        pin.recheck()?;
        Ok(true)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn retained_intent(
    account_directory: &Path,
    transaction: &str,
) -> Result<Option<Intent>> {
    if !crate::admin_roles::identifier(transaction) || transaction == "admin-bootstrap-v1" {
        return Err("invalid creation transaction".into());
    }
    let path = account_directory.join(format!("account-creation-{transaction}"));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    tpm::private_directory(&path)?;
    let bytes = tpm::private_read(&path.join("intent.json"), 128 * 1024)?;
    let intent: Intent = serde_json::from_slice(&bytes)?;
    intent.validate()?;
    if intent.transaction != transaction || serde_json::to_vec(&intent)? != bytes {
        return Err("retained creation intent differs".into());
    }
    Ok(Some(intent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "luma-account-creation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            principal::initialize(
                &root.join("principals"),
                &[("human", 1001), ("retired", 1000)],
            )
            .unwrap();
            for name in ["identity", "homes"] {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(root.join(name))
                    .unwrap();
            }
            for (name, bytes, mode) in [
                (
                    "passwd",
                    "human:x:1001:1001:Human:/home/human:/bin/bash\n",
                    0o644,
                ),
                ("shadow", "human:$6$fixture$one:20000:0:99999:7:::\n", 0o640),
                ("group", "human:x:1001:\nreserved:x:1002:\n", 0o644),
                ("gshadow", "human:!::\nreserved:!::\n", 0o640),
            ] {
                crate::platform::write_atomic(
                    &root.join("identity").join(name),
                    bytes.as_bytes(),
                    mode,
                )
                .unwrap();
            }
            Self(root)
        }
        fn registry(&self) -> PathBuf {
            self.0.join("principals/registry.json")
        }
        fn identity(&self) -> PathBuf {
            self.0.join("identity")
        }
        fn homes(&self) -> PathBuf {
            self.0.join("homes")
        }
        fn crypt() -> crate::account_password::Hash {
            let mut secret = PrivateBuffer::new(1025).unwrap();
            let value = b"Strong new account fixture secret 2026";
            secret.bytes_mut()[..value.len()].copy_from_slice(value);
            crate::account_password::Password::fixture(&secret)
                .unwrap()
                .hash()
                .unwrap()
        }
        fn staged(&self) -> Intent {
            let guard = Guard::new(
                &self.registry(),
                &self.identity(),
                &self.homes(),
                "newhuman",
                "create-one",
                &Self::crypt(),
            )
            .unwrap();
            guard.stage(|| Ok(())).unwrap();
            guard.intent.clone()
        }
        fn retained(&self, intent: &Intent) -> Guard {
            Guard::retained(&self.registry(), &self.identity(), &self.homes(), intent).unwrap()
        }
        fn publish_prefix(&self, intent: &Intent, count: usize) {
            for name in ["home"].into_iter().chain(FILES).take(count) {
                assert!(self.retained(intent).publish(name, || Ok(())).unwrap());
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn home_and_five_files_resume_in_exact_order_preserving_installation_history() {
        let f = Fixture::new();
        let intent = f.staged();
        assert_eq!(intent.principal.uid, 1003);
        assert_eq!(
            retained_intent(&f.identity(), "create-one").unwrap(),
            Some(intent.clone())
        );
        let baseline = principal::registry_file(&f.registry()).unwrap().0;
        for (index, name) in ["home"].into_iter().chain(FILES).enumerate() {
            let guard = f.retained(&intent);
            assert!(guard.complete().is_err());
            if name == "home" {
                assert!(guard.publish("gshadow", || Ok(())).is_err());
            }
            if name != "registry" {
                assert!(guard.publish("registry", || Ok(())).is_err());
            }
            assert!(guard.publish(name, || Ok(())).unwrap());
            assert!(guard.recheck().is_err());
            drop(guard);
            let resumed = f.retained(&intent);
            assert!(!resumed.publish(name, || Ok(())).unwrap());
            assert_eq!(resumed.complete().is_ok(), index == 5);
            for earlier in FILES.iter().take(index.min(4)) {
                assert!(resumed.after[*earlier]
                    .bytes()
                    .starts_with(resumed.before[*earlier].bytes()));
            }
            if name != "registry" {
                assert_eq!(principal::registry_file(&f.registry()).unwrap().0, baseline);
            }
        }
        let final_registry = principal::RegistryBinding::capture(&f.registry()).unwrap();
        assert_eq!(final_registry.current().unwrap(), &intent.registry_after);
        assert_eq!(
            &intent.registry_after.principals()[..2],
            intent.registry_before.principals()
        );
        let guard = f.retained(&intent);
        let record = rows(guard.after["shadow"].bytes(), 9)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(record[0], "newhuman");
        assert!(record[1].starts_with("!$y$j9T$"));
        assert_eq!(&record[2..], &["0", "0", "99999", "7", "", "", ""]);
        assert_eq!(
            fs::symlink_metadata(f.homes().join("newhuman"))
                .unwrap()
                .uid(),
            1003
        );
    }

    #[test]
    fn reserved_names_path_injection_and_duplicate_sources_refuse_before_retention() {
        let f = Fixture::new();
        let hash = Fixture::crypt();
        for name in [
            "human",
            "retired",
            "reserved",
            "../escape",
            "a:b",
            "new\nhuman",
            "Human",
            "",
        ] {
            assert!(Guard::new(
                &f.registry(),
                &f.identity(),
                &f.homes(),
                name,
                "create-one",
                &hash
            )
            .is_err());
        }
        crate::platform::write_atomic(&f.identity().join("passwd"),b"human:x:1001:1001:Human:/home/human:/bin/bash\nalias:x:1001:1001:Alias:/home/alias:/bin/bash\n",0o644).unwrap();
        assert!(Guard::new(
            &f.registry(),
            &f.identity(),
            &f.homes(),
            "newhuman",
            "create-one",
            &hash
        )
        .is_err());
        assert!(retained_intent(&f.identity(), "create-one")
            .unwrap()
            .is_none());
    }

    #[test]
    fn original_descriptors_and_private_evidence_fence_publication() {
        for fault in [
            "source",
            "intent",
            "after",
            "before",
            "marker",
            "marker-in-place",
            "home-owner",
            "home-extra",
            "directory",
        ] {
            let f = Fixture::new();
            let intent = f.staged();
            let guard = f.retained(&intent);
            let stage = guard.path();
            match fault {
                "source" => crate::platform::write_atomic(
                    &f.identity().join("group"),
                    guard.before["group"].bytes(),
                    0o644,
                )
                .unwrap(),
                "intent" => crate::platform::write_atomic(
                    &stage.join("intent.json"),
                    &serde_json::to_vec(&intent).unwrap(),
                    0o600,
                )
                .unwrap(),
                "after" => {
                    crate::platform::write_atomic(&stage.join("shadow.after"), b"changed\n", 0o600)
                        .unwrap()
                }
                "before" => {
                    crate::platform::write_atomic(&stage.join("group.before"), b"changed\n", 0o600)
                        .unwrap()
                }
                "marker" => crate::platform::write_atomic(
                    &stage.join("home/.luma-creation.json"),
                    &intent.marker().unwrap(),
                    0o600,
                )
                .unwrap(),
                "marker-in-place" => OpenOptions::new()
                    .write(true)
                    .open(stage.join("home/.luma-creation.json"))
                    .unwrap()
                    .write_all(&intent.marker().unwrap())
                    .unwrap(),
                "home-owner" => {
                    let file = File::open(stage.join("home")).unwrap();
                    assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 0) }, 0);
                }
                "home-extra" => write_new(&stage.join("home/unapproved"), b"state").unwrap(),
                "directory" => {
                    fs::rename(&stage, stage.with_extension("retained")).unwrap();
                    fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(guard.publish("home", || Ok(())).is_err(), "{fault}");
            assert!(!f.homes().join("newhuman").exists());
        }
    }

    #[test]
    fn exact_interrupted_file_prefix_resumes_but_conflicts_remain_untouched() {
        for (index, name) in FILES.into_iter().enumerate() {
            for conflict in [false, true] {
                let f = Fixture::new();
                let intent = f.staged();
                f.publish_prefix(&intent, index + 1);
                let guard = f.retained(&intent);
                let prefix = &guard.after[name].bytes()[..guard.after[name].bytes().len() / 2];
                let mut retained = PrivateBuffer::new(prefix.len()).unwrap();
                retained.bytes_mut().copy_from_slice(prefix);
                if conflict {
                    retained.bytes_mut()[0] ^= 1;
                }
                let path = guard.path().join(format!("{name}.next"));
                write_new(&path, retained.bytes()).unwrap();
                if conflict {
                    assert!(guard.publish(name, || Ok(())).is_err());
                    let (found, _) = principal::account_file(&path, true).unwrap();
                    assert_eq!(found.bytes(), retained.bytes());
                    assert_eq!(
                        hash(
                            read_file(
                                &if name == "registry" {
                                    f.registry()
                                } else {
                                    f.identity().join(name)
                                },
                                name
                            )
                            .unwrap()
                            .0
                            .bytes()
                        ),
                        intent.files[name].before
                    );
                } else {
                    assert!(guard.publish(name, || Ok(())).unwrap());
                }
            }
        }
    }

    #[test]
    fn every_dispatch_revalidates_before_rename_and_retains_retryable_preparation() {
        for (index, name) in ["home"].into_iter().chain(FILES).enumerate() {
            let f = Fixture::new();
            let intent = f.staged();
            f.publish_prefix(&intent, index);
            let guard = f.retained(&intent);
            let mut calls = 0;
            assert!(guard
                .publish(name, || {
                    calls += 1;
                    if calls == 2 {
                        Err("fixture expired authority".into())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert_eq!(calls, 2);
            guard.recheck().unwrap();
            drop(guard);
            assert!(f.retained(&intent).publish(name, || Ok(())).unwrap());
        }
    }

    #[test]
    fn interrupted_group_readable_shadow_cannot_expand_into_an_unapproved_group() {
        let f = Fixture::new();
        let intent = f.staged();
        f.publish_prefix(&intent, 3);
        let guard = f.retained(&intent);
        let prefix = &guard.after["shadow"].bytes()[..24];
        let path = guard.path().join("shadow.next");
        write_new(&path, prefix).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 77) }, 0);
        file.set_permissions(fs::Permissions::from_mode(0o640))
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(guard.publish("shadow", || Ok(())).is_err());
        assert!(same_file(&metadata, &file.metadata().unwrap()));
        assert_eq!(
            principal::account_file(&path, true).unwrap().0.bytes(),
            prefix
        );
        guard.recheck().unwrap();
    }

    #[test]
    fn private_staging_preserves_interrupted_evidence_and_refuses_capacity_exhaustion() {
        let f = Fixture::new();
        let plan = Guard::new(
            &f.registry(),
            &f.identity(),
            &f.homes(),
            "newhuman",
            "create-one",
            &Fixture::crypt(),
        )
        .unwrap();
        let mut calls = 0;
        assert!(plan
            .stage(|| {
                calls += 1;
                if calls == 2 {
                    Err("fixture lost authority".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(retained_intent(&f.identity(), "create-one")
            .unwrap()
            .is_none());
        let temporary = fs::read_dir(f.identity())
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                path.file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(b".creation-proposal-")
                    .then_some(path)
            })
            .collect::<Vec<_>>();
        assert_eq!(temporary.len(), 1);
        assert_eq!(
            fs::symlink_metadata(&temporary[0]).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            principal::account_file(&temporary[0].join("shadow.after"), true)
                .unwrap()
                .0
                .bytes(),
            plan.after["shadow"].bytes()
        );
        for i in 1..128 {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(f.identity().join(format!("account-creation-retained-{i}")))
                .unwrap();
        }
        assert!(plan.stage(|| Ok(())).is_err());
        assert!(temporary[0].join("shadow.after").exists());
        assert!(!f.homes().join("newhuman").exists());
        assert!(retained_intent(&f.identity(), "create-one")
            .unwrap()
            .is_none());
    }

    #[test]
    fn registry_extension_is_exact_and_catalog_cannot_enable_unaged_accounts() {
        use crate::admin_roles::{Catalog, Command};
        let f = Fixture::new();
        let intent = f.staged();
        let mut catalog = Catalog::initial();
        catalog
            .apply(&Command::AdoptPrincipals {
                registry: intent.registry_before.clone(),
            })
            .unwrap();
        let commitments = intent
            .registry_before
            .principals()
            .iter()
            .map(|p| (p.id.clone(), "ab".repeat(32)))
            .collect();
        catalog
            .apply(&Command::CheckpointAccounts { commitments })
            .unwrap();
        let baseline = catalog.principal_registry.clone();
        let prepare = Command::PrepareAccountCreation {
            intent: intent.clone(),
        };
        let permit = Command::PermitAccountCreation {
            transaction: "create-one".into(),
        };
        let complete = Command::CompleteAccountCreation {
            transaction: "create-one".into(),
        };
        assert!(catalog.apply(&complete).is_err());
        catalog.apply(&prepare).unwrap();
        assert!(!catalog.accepts_registry(&intent.registry_after).unwrap());
        assert!(catalog.apply(&prepare).is_err());
        catalog.apply(&permit).unwrap();
        assert!(catalog.accepts_registry(&intent.registry_after).unwrap());
        catalog.apply(&complete).unwrap();
        assert_eq!(catalog.principal_registry, baseline);
        assert_eq!(catalog.registry().unwrap(), &intent.registry_after);
        assert!(!catalog.principal_states[&intent.principal.id].enabled);
        assert!(catalog.needs_password_aging.contains(&intent.principal.id));
        assert!(catalog
            .apply(&Command::AdvancePrincipal {
                principal: intent.principal.id.clone(),
                expected_generation: 1,
                enabled: true
            })
            .is_err());
        assert!(catalog
            .resolve_principal(&intent.registry_after.identity(&intent.principal))
            .is_err());
        let mut mutated = serde_json::to_value(&intent).unwrap();
        mutated["registry_after"]["principals"][0]["login"] = serde_json::json!("replacement");
        assert!(serde_json::from_value::<Intent>(mutated)
            .unwrap()
            .validate()
            .is_err());
    }
}
