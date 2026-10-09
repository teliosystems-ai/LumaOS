//! Governed non-Admin deletion. Each fresh owned continuation publishes one
//! exact file; private before/after evidence survives every partial state.
use crate::{bundle, principal, sealed_credential::PrivateBuffer, tpm, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const FILES: [&str; 4] = ["shadow", "gshadow", "group", "passwd"];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Change {
    pub before: String,
    pub after: String,
    pub mode: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub transaction: String,
    pub installation: String,
    pub principal: String,
    pub expected_generation: u64,
    pub credential_before: String,
    pub files: BTreeMap<String, Change>,
}

impl Intent {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::admin_roles::identifier(&self.transaction)
            || self.transaction == "admin-bootstrap-v1"
            || self.expected_generation == 0
            || self.expected_generation == u64::MAX
            || self.installation == self.principal
            || self
                .files
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != FILES.into_iter().collect()
        {
            return Err("invalid account deletion intent".into());
        }
        for value in [&self.installation, &self.principal, &self.credential_before] {
            if tpm::decode::<32>(value)? == [0; 32] {
                return Err("empty deletion identity or credential commitment".into());
            }
        }
        for (name, change) in &self.files {
            if !matches!(change.mode, 0o600 | 0o640 | 0o644)
                || (name.ends_with("shadow") && change.mode == 0o644)
                || tpm::decode::<32>(&change.before)? == [0; 32]
                || tpm::decode::<32>(&change.after)? == [0; 32]
                || change.before == change.after
            {
                return Err("invalid deletion file commitment or permissions".into());
            }
        }
        Ok(())
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

// The returned slices borrow locked input, including all gshadow passwords.
// No copied credential is placed in a pageable String or diagnostic.
fn rows(input: &[u8], fields: usize) -> Result<Vec<Vec<&str>>> {
    if input.is_empty() || input.len() > 16384 || !input.ends_with(b"\n") {
        return Err("incomplete or oversized identity records".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid identity encoding")?;
    let mut names = BTreeSet::new();
    let mut result = vec![];
    for row in text.split_inclusive('\n') {
        let columns: Vec<_> = row[..row.len() - 1].split(':').collect();
        if columns.len() != fields
            || columns[0].is_empty()
            || !names.insert(columns[0])
            || row.bytes().any(|b| b == 0 || b == b'\r')
        {
            return Err("invalid or duplicate identity record".into());
        }
        result.push(columns);
    }
    Ok(result)
}

fn remove_account(input: &[u8], name: &str, fields: usize) -> Result<PrivateBuffer> {
    let parsed = rows(input, fields)?;
    if parsed.iter().filter(|row| row[0] == name).count() != 1 {
        return Err("deletion requires an unambiguous existing account".into());
    }
    let text = std::str::from_utf8(input)?;
    let retained: Vec<_> = text
        .split_inclusive('\n')
        .filter(|row| row.split(':').next() != Some(name))
        .collect();
    let mut output = PrivateBuffer::new(retained.iter().map(|row| row.len()).sum())?;
    let mut offset = 0;
    for row in retained {
        output.bytes_mut()[offset..offset + row.len()].copy_from_slice(row.as_bytes());
        offset += row.len();
    }
    Ok(output)
}

fn member_list(value: &str) -> Result<Vec<&str>> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    let members: Vec<_> = value.split(',').collect();
    if members.iter().any(|name| name.is_empty())
        || members.iter().copied().collect::<BTreeSet<_>>().len() != members.len()
    {
        return Err("ambiguous group membership".into());
    }
    Ok(members)
}

fn remove_groups(input: &[u8], name: &str, secret: bool, gid: u32) -> Result<PrivateBuffer> {
    let parsed = rows(input, 4)?;
    let mut selected = false;
    // References only: group passwords still borrow the private input buffer.
    let mut pieces: Vec<&[u8]> = vec![];
    for row in parsed {
        let lists = if secret { vec![2, 3] } else { vec![3] };
        let memberships = lists
            .iter()
            .map(|&column| member_list(row[column]))
            .collect::<Result<Vec<_>>>()?;
        if row[0] == name {
            if memberships.iter().flatten().any(|member| *member != name)
                || (!secret && row[2].parse::<u32>()? != gid)
            {
                return Err("deletion cannot remove a shared or mismatched private group".into());
            }
            selected = true;
            continue;
        }
        if !secret && row[2].parse::<u32>()? == gid {
            return Err("ambiguous private group gid".into());
        }
        for (column, value) in row.iter().enumerate() {
            if column > 0 {
                pieces.push(b":");
            }
            if let Some(index) = lists.iter().position(|&index| index == column) {
                let mut first = true;
                for member in &memberships[index] {
                    if *member != name {
                        if !first {
                            pieces.push(b",");
                        }
                        pieces.push(member.as_bytes());
                        first = false;
                    }
                }
            } else {
                pieces.push(value.as_bytes());
            }
        }
        pieces.push(b"\n");
    }
    if !selected {
        return Err("missing account private group".into());
    }
    let mut output = PrivateBuffer::new(pieces.iter().map(|piece| piece.len()).sum())?;
    let mut offset = 0;
    for piece in pieces {
        output.bytes_mut()[offset..offset + piece.len()].copy_from_slice(piece);
        offset += piece.len();
    }
    Ok(output)
}

fn transform(
    before: &BTreeMap<String, PrivateBuffer>,
    record: &principal::Principal,
) -> Result<BTreeMap<String, PrivateBuffer>> {
    let passwd = rows(before["passwd"].bytes(), 7)?;
    let mut uids = BTreeSet::new();
    for row in &passwd {
        if !uids.insert(row[2].parse::<u32>()?) {
            return Err("ambiguous local account uid".into());
        }
        row[3].parse::<u32>()?;
    }
    let target = passwd
        .iter()
        .find(|row| row[0] == record.login)
        .ok_or("missing deletion account")?;
    let gid: u32 = target[3].parse()?;
    if gid != record.uid
        || passwd
            .iter()
            .any(|row| row[0] != record.login && row[3].parse::<u32>().ok() == Some(gid))
    {
        return Err("deletion requires an unshared account-owned primary group".into());
    }
    Ok(BTreeMap::from([
        (
            "passwd".into(),
            remove_account(before["passwd"].bytes(), &record.login, 7)?,
        ),
        (
            "shadow".into(),
            remove_account(before["shadow"].bytes(), &record.login, 9)?,
        ),
        (
            "group".into(),
            remove_groups(before["group"].bytes(), &record.login, false, gid)?,
        ),
        (
            "gshadow".into(),
            remove_groups(before["gshadow"].bytes(), &record.login, true, gid)?,
        ),
    ]))
}

type DirectoryIdentity = (u64, u64, u32, u32, u32);
fn directory_identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    directory_identity(left) == directory_identity(right)
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(crate) struct Guard {
    registry: principal::RegistryBinding,
    identity: PathBuf,
    directory: File,
    directory_identity: DirectoryIdentity,
    lock: File,
    lock_identity: (u64, u64),
    source: BTreeMap<String, principal::FilePin>,
    evidence: RefCell<Vec<principal::FilePin>>,
    before: BTreeMap<String, PrivateBuffer>,
    after: BTreeMap<String, PrivateBuffer>,
    published: usize,
    pub intent: Intent,
}

impl Guard {
    fn capture(registry_path: &Path, identity: &Path, intent: Intent) -> Result<Self> {
        intent.validate()?;
        let registry = principal::RegistryBinding::capture(registry_path)?;
        let current = registry.current()?;
        let record = current
            .principal(&intent.principal)
            .filter(|record| record.enabled && record.uid != 1001)
            .ok_or(
                "deletion cannot remove the original Admin or an unknown installation account",
            )?;
        if current.installation() != intent.installation {
            return Err("deletion belongs to another installation".into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(identity)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("unsafe identity publication directory".into());
        }
        let directory_identity = directory_identity(&metadata);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(identity.join("migration.lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != 0
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err("identity publication lock unavailable or unsafe".into());
        }
        let lock_identity = (metadata.dev(), metadata.ino());
        let path = identity.join(format!("account-deletion-{}", intent.transaction));
        let staged = match fs::symlink_metadata(&path) {
            Ok(_) => {
                tpm::private_directory(&path)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let (mut before, mut after, mut source, mut evidence) =
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), vec![]);
        let mut published = 0;
        let mut unpublished = false;
        if staged {
            let (bytes, pin) = principal::account_file(&path.join("intent.json"), true)?;
            if bytes.bytes() != serde_json::to_vec(&intent)?
                || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
            {
                return Err("retained deletion intent differs".into());
            }
            evidence.push(pin);
        }
        for name in FILES {
            let (bytes, pin) =
                principal::account_file(&identity.join(name), name.ends_with("shadow"))?;
            let metadata = pin.descriptor()?.metadata()?;
            let change = &intent.files[name];
            if metadata.mode() & 0o777 != change.mode || metadata.gid() != change.gid {
                return Err("identity file permissions changed".into());
            }
            let digest = hash(bytes.bytes());
            if digest == change.after {
                if unpublished || !staged {
                    return Err("unapproved deletion publication order".into());
                }
                published += 1;
            } else if digest == change.before {
                unpublished = true;
            } else {
                return Err("identity file is outside the approved before/after states".into());
            }
            source.insert(name.into(), pin);
            if staged {
                for (suffix, expected, selected) in [
                    ("before", &change.before, &mut before),
                    ("after", &change.after, &mut after),
                ] {
                    let (bytes, pin) =
                        principal::account_file(&path.join(format!("{name}.{suffix}")), true)?;
                    if hash(bytes.bytes()) != *expected
                        || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
                    {
                        return Err("retained deletion evidence differs".into());
                    }
                    selected.insert(name.into(), bytes);
                    evidence.push(pin);
                }
            } else {
                before.insert(name.into(), bytes);
            }
        }
        let digest = principal::account_rows_digest(
            before["passwd"].bytes(),
            before["shadow"].bytes(),
            record,
            true,
        )?;
        if principal::rows_commitment(current.installation(), record, digest)?
            != intent.credential_before
        {
            return Err("deletion credential differs from its checkpoint".into());
        }
        let derived = transform(&before, record)?;
        for name in FILES {
            if hash(derived[name].bytes()) != intent.files[name].after
                || (staged && derived[name].bytes() != after[name].bytes())
            {
                return Err("deletion changes unrelated records or group authority".into());
            }
        }
        if !staged {
            after = derived;
        }
        let guard = Self {
            registry,
            identity: identity.into(),
            directory,
            directory_identity,
            lock,
            lock_identity,
            source,
            evidence: RefCell::new(evidence),
            before,
            after,
            published,
            intent,
        };
        guard.recheck()?;
        Ok(guard)
    }

    pub(crate) fn prepare(
        registry_path: &Path,
        identity: &Path,
        target: &str,
        generation: u64,
        transaction: &str,
    ) -> Result<Self> {
        let registry = principal::RegistryBinding::capture(registry_path)?;
        let current = registry.current()?;
        let record = current
            .account(target)
            .filter(|record| record.enabled && record.uid != 1001)
            .ok_or("deletion requires an installed non-Admin account")?;
        let mut before = BTreeMap::new();
        let mut pins = vec![];
        let mut files = BTreeMap::new();
        for name in FILES {
            let (bytes, pin) =
                principal::account_file(&identity.join(name), name.ends_with("shadow"))?;
            let metadata = pin.descriptor()?.metadata()?;
            files.insert(
                name.into(),
                Change {
                    before: hash(bytes.bytes()),
                    after: String::new(),
                    mode: metadata.mode() & 0o777,
                    gid: metadata.gid(),
                },
            );
            before.insert(name.into(), bytes);
            pins.push(pin);
        }
        let after = transform(&before, record)?;
        for name in FILES {
            files.get_mut(name).ok_or("missing deletion file")?.after = hash(after[name].bytes());
        }
        let intent = Intent {
            transaction: transaction.into(),
            installation: current.installation().into(),
            principal: record.id.clone(),
            expected_generation: generation,
            credential_before: principal::rows_commitment(
                current.installation(),
                record,
                principal::account_rows_digest(
                    before["passwd"].bytes(),
                    before["shadow"].bytes(),
                    record,
                    true,
                )?,
            )?,
            files,
        };
        let guard = Self::capture(registry_path, identity, intent)?;
        for pin in pins {
            pin.recheck()?;
        }
        registry.current()?;
        Ok(guard)
    }

    pub(crate) fn retained(registry_path: &Path, identity: &Path, intent: &Intent) -> Result<Self> {
        let guard = Self::capture(registry_path, identity, intent.clone())?;
        if guard.evidence.borrow().len() != 9 {
            return Err("deletion requires its complete retained evidence".into());
        }
        Ok(guard)
    }

    fn path(&self) -> PathBuf {
        self.identity
            .join(format!("account-deletion-{}", self.intent.transaction))
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        self.authority_recheck()?;
        for pin in self.source.values() {
            pin.recheck()?;
        }
        Ok(())
    }

    fn authority_recheck(&self) -> Result<()> {
        self.registry.current()?;
        if directory_identity(&self.directory.metadata()?) != self.directory_identity
            || directory_identity(&fs::symlink_metadata(&self.identity)?) != self.directory_identity
        {
            return Err("identity publication directory changed".into());
        }
        let metadata = fs::symlink_metadata(self.identity.join("migration.lock"))?;
        let held = self.lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != 0
            || (metadata.dev(), metadata.ino()) != self.lock_identity
            || (held.dev(), held.ino()) != self.lock_identity
        {
            return Err("identity publication lock changed".into());
        }
        for pin in self.evidence.borrow().iter() {
            pin.recheck()?;
        }
        Ok(())
    }

    pub(crate) fn complete(&self) -> Result<()> {
        self.recheck()?;
        if self.published != FILES.len() {
            return Err("deletion completion requires every exact published file".into());
        }
        Ok(())
    }

    pub(crate) fn stage(&self) -> Result<()> {
        self.recheck()?;
        if !self.evidence.borrow().is_empty() {
            return Ok(());
        }
        let retained = fs::read_dir(&self.identity)?.try_fold(0usize, |count, entry| {
            let name = entry?.file_name();
            Ok::<_, std::io::Error>(
                count
                    + usize::from(
                        name.as_encoded_bytes().starts_with(b"account-deletion-")
                            || name.as_encoded_bytes().starts_with(b".deletion-proposal-"),
                    ),
            )
        })?;
        if retained >= 128 {
            return Err("deletion evidence retention exhausted; preserve state".into());
        }
        let mut nonce = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let temporary_name = format!(
            ".deletion-proposal-{}-{}",
            self.intent.transaction,
            bundle::hex(&nonce)
        );
        let temporary = self.identity.join(&temporary_name);
        fs::DirBuilder::new().mode(0o700).create(&temporary)?;
        tpm::private_directory(&temporary)?;
        let temporary_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let temporary_identity = directory_identity(&temporary_directory.metadata()?);
        for name in FILES {
            for (suffix, bytes) in [("before", &self.before[name]), ("after", &self.after[name])] {
                write_new(&temporary.join(format!("{name}.{suffix}")), bytes.bytes())?;
            }
        }
        write_new(
            &temporary.join("intent.json"),
            &serde_json::to_vec(&self.intent)?,
        )?;
        temporary_directory.sync_all()?;
        self.recheck()?;
        if directory_identity(&fs::symlink_metadata(&temporary)?) != temporary_identity {
            return Err("deletion proposal directory replaced before retention".into());
        }
        let source = std::ffi::CString::new(temporary_name)?;
        let target =
            std::ffi::CString::new(format!("account-deletion-{}", self.intent.transaction))?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.directory.as_raw_fd(),
                source.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        let mut pins = vec![];
        let (bytes, pin) = principal::account_file(&self.path().join("intent.json"), true)?;
        if bytes.bytes() != serde_json::to_vec(&self.intent)?
            || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
        {
            return Err("retained deletion intent changed during staging".into());
        }
        pins.push(pin);
        for name in FILES {
            for (suffix, expected) in [("before", &self.before[name]), ("after", &self.after[name])]
            {
                let (bytes, pin) =
                    principal::account_file(&self.path().join(format!("{name}.{suffix}")), true)?;
                if bytes.bytes() != expected.bytes()
                    || pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600
                {
                    return Err("deletion evidence changed during staging".into());
                }
                pins.push(pin);
            }
        }
        *self.evidence.borrow_mut() = pins;
        self.recheck()
    }

    /// This method is reachable only through a fresh owning Admin composition.
    /// A returned intent, receipt, Unix uid or private file is not authority.
    pub(crate) fn publish(
        &self,
        name: &str,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        if !FILES.contains(&name) {
            return Err("unknown deletion publication file".into());
        }
        self.recheck()?;
        authorize()?;
        let index = FILES
            .iter()
            .position(|&file| file == name)
            .ok_or("unknown deletion file")?;
        if index < self.published {
            return Ok(false);
        }
        if index != self.published || self.evidence.borrow().len() != 9 {
            return Err(
                "deletion requires retained evidence and shadow-first publication order".into(),
            );
        }
        let path = self.path();
        let stage = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        tpm::private_directory(&path)?;
        let metadata = stage.metadata()?;
        let next = format!("{name}.next");
        let next_path = path.join(&next);
        let change = &self.intent.files[name];
        let mut file = match OpenOptions::new()
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
        let original = file.metadata()?;
        if !original.is_file()
            || original.uid() != 0
            || original.nlink() != 1
            || original.len() > self.after[name].bytes().len() as u64
            || !matches!(original.mode() & 0o777, 0o600 | 0o640 | 0o644)
            || (name.ends_with("shadow") && original.mode() & 0o007 != 0)
            || !same_file(&original, &fs::symlink_metadata(&next_path)?)
        {
            return Err("unsafe deletion dispatch file".into());
        }
        let length = original.len() as usize;
        let mut retained = PrivateBuffer::new(self.after[name].bytes().len())?;
        file.read_exact(&mut retained.bytes_mut()[..length])?;
        if retained.bytes()[..length] != self.after[name].bytes()[..length]
            || !same_file(&original, &file.metadata()?)
            || !same_file(&original, &fs::symlink_metadata(&next_path)?)
        {
            return Err("interrupted deletion dispatch differs; preserve state".into());
        }
        self.recheck()?;
        // A fresh owned continuation may finish only the exact known prefix.
        // Conflicting bytes are retained, never truncated or silently replaced.
        file.write_all(&self.after[name].bytes()[length..])?;
        if unsafe { libc::fchown(file.as_raw_fd(), 0, change.gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        file.set_permissions(fs::Permissions::from_mode(change.mode))?;
        file.sync_all()?;
        stage.sync_all()?;
        authorize()?;
        self.recheck()?;
        if directory_identity(&fs::symlink_metadata(&path)?) != directory_identity(&metadata) {
            return Err("deletion stage directory replaced".into());
        }
        let (bytes, pin) = principal::account_file(&next_path, name.ends_with("shadow"))?;
        let held = file.metadata()?;
        let selected = pin.descriptor()?.metadata()?;
        if bytes.bytes() != self.after[name].bytes()
            || !same_file(&held, &selected)
            || held.nlink() != 1
        {
            return Err("deletion dispatch changed before publication".into());
        }
        self.recheck()?;
        pin.recheck()?;
        // No observations after dispatch may reuse old whole-file account pins.
        let source = std::ffi::CString::new(next)?;
        let target = std::ffi::CString::new(name)?;
        if unsafe {
            libc::renameat(
                stage.as_raw_fd(),
                source.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        stage.sync_all()?;
        self.authority_recheck()?;
        for (other, pin) in &self.source {
            if other != name {
                pin.recheck()?;
            }
        }
        let (bytes, published_pin) =
            principal::account_file(&self.identity.join(name), name.ends_with("shadow"))?;
        let published = published_pin.descriptor()?.metadata()?;
        let held = file.metadata()?;
        if hash(bytes.bytes()) != change.after
            || !same_file(&published, &held)
            || published.mode() & 0o777 != change.mode
            || published.gid() != change.gid
        {
            return Err("deletion publication differs after dispatch".into());
        }
        published_pin.recheck()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "luma-account-deletion-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            principal::initialize(
                &path.join("principals"),
                &[("human", 1001), ("otherhuman", 1002)],
            )
            .unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("identity"))
                .unwrap();
            for (name, bytes, mode) in [
                ("passwd", "human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n", 0o644),
                ("shadow", "human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n", 0o640),
                ("group", "human:x:1001:\notherhuman:x:1002:\nshared:x:1200:human,otherhuman\n", 0o644),
                ("gshadow", "human:!::\notherhuman:!::\nshared:$6$private$group:otherhuman,human:human,otherhuman\n", 0o640),
            ] { crate::platform::write_atomic(&path.join("identity").join(name), bytes.as_bytes(), mode).unwrap(); }
            Self(path)
        }
        fn registry(&self) -> PathBuf {
            self.0.join("principals/registry.json")
        }
        fn identity(&self) -> PathBuf {
            self.0.join("identity")
        }
        fn plan(&self) -> Guard {
            Guard::prepare(
                &self.registry(),
                &self.identity(),
                "otherhuman",
                2,
                "delete-one",
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn exact_four_file_deletion_survives_every_partial_prefix_and_preserves_registry() {
        let f = Fixture::new();
        let baseline = tpm::private_read(&f.registry(), 65536).unwrap();
        let plan = f.plan();
        let intent = plan.intent.clone();
        assert!(plan.complete().is_err());
        assert!(plan.publish("shadow", || Ok(())).is_err());
        plan.stage().unwrap();
        plan.recheck().unwrap();
        assert!(plan.publish("passwd", || Ok(())).is_err());
        drop(plan);
        for (index, name) in FILES.into_iter().enumerate() {
            let guard = Guard::retained(&f.registry(), &f.identity(), &intent).unwrap();
            assert_eq!(guard.published, index);
            assert!(guard.complete().is_err());
            assert!(guard.publish(name, || Ok(())).unwrap());
            assert!(guard.recheck().is_err());
            drop(guard);
            let next = Guard::retained(&f.registry(), &f.identity(), &intent).unwrap();
            assert!(!next.publish(name, || Ok(())).unwrap());
            assert_eq!(next.published, index + 1);
            assert_eq!(next.complete().is_ok(), index == 3);
            assert_eq!(
                fs::symlink_metadata(f.identity().join(name))
                    .unwrap()
                    .mode()
                    & 0o777,
                intent.files[name].mode
            );
        }
        assert_eq!(tpm::private_read(&f.registry(), 65536).unwrap(), baseline);
        assert_eq!(
            fs::read_to_string(f.identity().join("group")).unwrap(),
            "human:x:1001:\nshared:x:1200:human\n"
        );
        let (secret, _) = principal::account_file(&f.identity().join("gshadow"), true).unwrap();
        assert_eq!(
            secret.bytes(),
            b"human:!::\nshared:$6$private$group:human:human\n"
        );
    }

    #[test]
    fn changed_sources_or_evidence_never_publish_and_shared_groups_refuse() {
        for fault in [
            "source",
            "evidence",
            "shared-group",
            "shared-gid",
            "duplicate",
            "wrong-intent",
        ] {
            let f = Fixture::new();
            if fault == "shared-group" {
                crate::platform::write_atomic(
                    &f.identity().join("group"),
                    b"human:x:1001:\notherhuman:x:1002:human\n",
                    0o644,
                )
                .unwrap();
                assert!(Guard::prepare(
                    &f.registry(),
                    &f.identity(),
                    "otherhuman",
                    1,
                    "delete-one"
                )
                .is_err());
                continue;
            }
            if fault == "shared-gid" {
                crate::platform::write_atomic(&f.identity().join("passwd"), b"human:x:1001:1002:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n", 0o644).unwrap();
                assert!(Guard::prepare(
                    &f.registry(),
                    &f.identity(),
                    "otherhuman",
                    1,
                    "delete-one"
                )
                .is_err());
                continue;
            }
            if fault == "duplicate" {
                crate::platform::write_atomic(
                    &f.identity().join("group"),
                    b"human:x:1001:\notherhuman:x:1002:\nhuman:x:1003:\n",
                    0o644,
                )
                .unwrap();
                assert!(Guard::prepare(
                    &f.registry(),
                    &f.identity(),
                    "otherhuman",
                    1,
                    "delete-one"
                )
                .is_err());
                continue;
            }
            let guard = f.plan();
            let mut intent = guard.intent.clone();
            guard.stage().unwrap();
            match fault {
                "source" => crate::platform::write_atomic(
                    &f.identity().join("group"),
                    b"human:x:1001:\notherhuman:x:1002:\n",
                    0o644,
                )
                .unwrap(),
                "evidence" => crate::platform::write_atomic(
                    &guard.path().join("group.after"),
                    b"human:x:1001:\n",
                    0o600,
                )
                .unwrap(),
                "wrong-intent" => intent.principal = "fe".repeat(32),
                _ => unreachable!(),
            }
            if fault != "wrong-intent" {
                assert!(guard.publish("shadow", || Ok(())).is_err());
            }
            drop(guard);
            assert!(Guard::retained(&f.registry(), &f.identity(), &intent).is_err());
        }
    }

    #[test]
    fn revoked_authorization_retains_dispatch_and_exact_fresh_continuation_resumes() {
        let f = Fixture::new();
        let guard = f.plan();
        guard.stage().unwrap();
        let intent = guard.intent.clone();
        let mut calls = 0;
        assert!(guard
            .publish("shadow", || {
                calls += 1;
                if calls == 2 {
                    Err("revoked".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(calls, 2);
        guard.recheck().unwrap();
        assert!(guard.path().join("shadow.next").exists());
        drop(guard);
        let next = Guard::retained(&f.registry(), &f.identity(), &intent).unwrap();
        assert!(next.publish("shadow", || Ok(())).unwrap());
    }

    #[test]
    fn empty_and_exact_prefix_dispatches_resume_without_truncating_private_evidence() {
        for length in [0, 7] {
            let f = Fixture::new();
            let guard = f.plan();
            guard.stage().unwrap();
            let intent = guard.intent.clone();
            write_new(
                &guard.path().join("shadow.next"),
                &guard.after["shadow"].bytes()[..length],
            )
            .unwrap();
            let inode = fs::symlink_metadata(guard.path().join("shadow.next"))
                .unwrap()
                .ino();
            drop(guard);
            let fresh = Guard::retained(&f.registry(), &f.identity(), &intent).unwrap();
            assert!(fresh.publish("shadow", || Ok(())).unwrap());
            assert_eq!(
                fs::symlink_metadata(f.identity().join("shadow"))
                    .unwrap()
                    .ino(),
                inode
            );
        }
    }

    #[test]
    fn interrupted_proposals_remain_private_and_retention_is_bounded() {
        let f = Fixture::new();
        let interrupted = f.identity().join(".deletion-proposal-interrupted");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&interrupted)
            .unwrap();
        write_new(
            &interrupted.join("shadow.after"),
            b"private interrupted evidence",
        )
        .unwrap();
        let guard = f.plan();
        guard.stage().unwrap();
        assert_eq!(
            fs::symlink_metadata(interrupted.join("shadow.after"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let intent = guard.intent.clone();
        drop(guard);
        Guard::retained(&f.registry(), &f.identity(), &intent)
            .unwrap()
            .recheck()
            .unwrap();
        let f = Fixture::new();
        for index in 0..128 {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(f.identity().join(format!(".deletion-proposal-{index}")))
                .unwrap();
        }
        let guard = f.plan();
        assert!(guard.stage().is_err());
        assert!(!guard.path().exists());
        assert_eq!(
            fs::read_dir(f.identity())
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".deletion-proposal-"))
                .count(),
            128
        );
    }

    #[test]
    fn rejects_admin_unsafe_paths_out_of_order_states_and_corrupt_dispatch() {
        let f = Fixture::new();
        for (target, transaction, generation) in [
            ("human", "delete", 1),
            ("otherhuman", "../escape", 1),
            ("otherhuman", "delete", 0),
            ("otherhuman", "delete", u64::MAX),
        ] {
            assert!(Guard::prepare(
                &f.registry(),
                &f.identity(),
                target,
                generation,
                transaction
            )
            .is_err());
        }
        let guard = f.plan();
        guard.stage().unwrap();
        let intent = guard.intent.clone();
        assert!(guard.publish("../passwd", || Ok(())).is_err());
        write_new(
            &guard.path().join("shadow.next"),
            b"conflicting private state\n",
        )
        .unwrap();
        assert!(guard.publish("shadow", || Ok(())).is_err());
        crate::platform::write_atomic(
            &f.identity().join("passwd"),
            guard.after["passwd"].bytes(),
            0o644,
        )
        .unwrap();
        drop(guard);
        assert!(Guard::retained(&f.registry(), &f.identity(), &intent).is_err());
    }
}
