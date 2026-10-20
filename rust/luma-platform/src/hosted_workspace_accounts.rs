//! Exact one-account transition for the distinct hosted workspace profile.
//! Secret rows stay in locked buffers and root-only staged files. This is a
//! filesystem transaction/witness, never a TPM journal or Linux product grant.
use super::{canonical, Request, GROUP, GSHADOW, PASSWD, SHADOW};
use crate::{principal, sealed_credential::PrivateBuffer, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ORDER: [&str; 4] = ["gshadow", "group", "shadow", "passwd"];
type Identity = (u64, u64, u32, u32, u32);
fn identity(value: &std::fs::Metadata) -> Identity {
    (
        value.dev(),
        value.ino(),
        value.uid(),
        value.gid(),
        value.mode(),
    )
}
fn baseline(name: &str) -> Result<&'static [u8]> {
    Ok(match name {
        "passwd" => PASSWD,
        "group" => GROUP,
        "shadow" => SHADOW,
        "gshadow" => GSHADOW,
        _ => return Err("unknown hosted account member".into()),
    })
}
fn mode(name: &str) -> u32 {
    if name.ends_with("shadow") {
        0o600
    } else {
        0o644
    }
}

fn validate_after(member: &str, bytes: &[u8], request: &Request) -> Result<()> {
    let tail = bytes
        .strip_prefix(baseline(member)?)
        .ok_or("hosted account baseline prefix changed")?;
    let name = &request.login;
    let expected = match member {
        "passwd" => format!("{name}:x:1000:1000:Luma local user:/home/{name}:/bin/bash\n"),
        "group" => format!("{name}:x:1000:\n"),
        "gshadow" => format!("{name}:!::\n"),
        "shadow" => {
            let prefix = format!("{name}:");
            let suffix = format!(":{}:0:90:7:::\n", request.protected_utc_day);
            let credential = tail
                .strip_prefix(prefix.as_bytes())
                .and_then(|value| value.strip_suffix(suffix.as_bytes()))
                .ok_or("hosted account credential/aging row differs")?;
            crate::account_password::validate_hash(credential)?;
            return Ok(());
        }
        _ => return Err("unknown hosted account replacement".into()),
    };
    if tail != expected.as_bytes() {
        return Err("hosted account replacement is not the exact one-account delta".into());
    }
    Ok(())
}

struct Directory {
    path: PathBuf,
    file: File,
    original: Identity,
}
impl Directory {
    fn open(path: &Path, private: bool) -> Result<Self> {
        for ancestor in path.ancestors() {
            let info = std::fs::symlink_metadata(ancestor)?;
            if !info.is_dir() || info.uid() != 0 || info.mode() & 0o7022 != 0 {
                return Err("hosted account directory has an unsafe ancestor".into());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let original = identity(&file.metadata()?);
        if private && original.4 & 0o077 != 0 {
            return Err("hosted private account directory is exposed".into());
        }
        let value = Self {
            path: path.into(),
            file,
            original,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if identity(&self.file.metadata()?) != self.original
            || identity(&std::fs::symlink_metadata(&self.path)?) != self.original
        {
            return Err("hosted account directory was replaced".into());
        }
        Ok(())
    }
    fn write_new(&self, name: &str, data: &[u8], permissions: u32) -> Result<()> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err("hosted private member name differs".into());
        }
        self.check()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(permissions)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join(name))?;
        file.set_permissions(std::fs::Permissions::from_mode(permissions))?;
        file.write_all(data)?;
        file.sync_all()?;
        self.file.sync_all()?;
        self.check()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Change {
    before: String,
    after: String,
    mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    request_sha256: String,
    files: BTreeMap<String, Change>,
    home_device: u64,
    home_inode: u64,
}

pub(super) struct Transaction {
    accounts: Directory,
    state: Directory,
    request_sha: String,
    record: Record,
    after: BTreeMap<String, PrivateBuffer>,
    pins: Vec<principal::FilePin>,
    home_path: PathBuf,
}

fn appended(before: &[u8], parts: &[&[u8]]) -> Result<PrivateBuffer> {
    let length = parts.iter().try_fold(before.len(), |length, part| {
        length
            .checked_add(part.len())
            .ok_or("hosted account row length overflow")
    })?;
    let mut result = PrivateBuffer::new(length)?;
    result.bytes_mut()[..before.len()].copy_from_slice(before);
    let mut offset = before.len();
    for part in parts {
        result.bytes_mut()[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    Ok(result)
}

impl Transaction {
    // Pre-stage recovery is a distinct explicit operation. It may initialize
    // only the original reserved account when no guest transaction ever began.
    pub(super) fn require_unstarted(
        accounts: &Path,
        state: &Path,
        request: &Request,
    ) -> Result<()> {
        let directory = Directory::open(accounts, false)?;
        match std::fs::symlink_metadata(state) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(
                    "existing or damaged account stage must be retained and inspected".into(),
                )
            }
        }
        let homes = accounts
            .parent()
            .ok_or("account root missing")?
            .join("home");
        Directory::open(&homes, false)?.check()?;
        match std::fs::symlink_metadata(homes.join(&request.login)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("first account cannot adopt any existing home".into()),
        }
        for member in ORDER {
            let (bytes, pin) =
                principal::account_file(&accounts.join(member), member.ends_with("shadow"))?;
            let metadata = pin.descriptor()?.metadata()?;
            if bytes.bytes() != baseline(member)?
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != mode(member)
            {
                return Err(
                    "account pre-stage recovery requires every untouched exact baseline".into(),
                );
            }
            match std::fs::symlink_metadata(accounts.join(format!(".luma-workspace-{member}"))) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(
                        "account pre-stage recovery found a retained publication temporary".into(),
                    )
                }
            }
            pin.recheck()?;
        }
        directory.check()
    }

    pub(super) fn prepare(
        accounts: &Path,
        state: &Path,
        request: &Request,
        crypt: &crate::account_password::Hash,
        mut live: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        live()?;
        Self::require_unstarted(accounts, state, request)?;
        let accounts = Directory::open(accounts, false)?;
        for member in ORDER {
            match std::fs::symlink_metadata(accounts.path.join(format!(".luma-workspace-{member}")))
            {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(
                        "unowned hosted account publication temporary already exists".into(),
                    )
                }
            }
        }
        let parent = Directory::open(
            state
                .parent()
                .ok_or("missing hosted account state parent")?,
            true,
        )?;
        // Existing state is never overwritten or adopted, even for an identical
        // login. Interrupted execution is inspected explicitly through recover.
        std::fs::DirBuilder::new().mode(0o700).create(state)?;
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700))?;
        parent.file.sync_all()?;
        parent.check()?;
        let state = Directory::open(state, true)?;
        if unsafe { libc::flock(state.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("hosted first-account transaction is already owned".into());
        }
        let request_bytes = canonical(request)?;
        let request_sha = luma_content::sha256(&request_bytes);
        state.write_new("intent.json", &request_bytes, 0o600)?;
        let name = &request.login;
        let passwd = format!("{name}:x:1000:1000:Luma local user:/home/{name}:/bin/bash\n");
        let group = format!("{name}:x:1000:\n");
        let gshadow = format!("{name}:!::\n");
        let shadow_prefix = format!("{name}:");
        let shadow_age = format!(":{}:0:90:7:::\n", request.protected_utc_day);
        let crypt = crypt.bytes()?;
        let mut after = BTreeMap::new();
        let mut source_pins = vec![];
        let mut pins = vec![];
        let mut files = BTreeMap::new();
        for member in ORDER {
            live()?;
            let (source, pin) =
                principal::account_file(&accounts.path.join(member), member.ends_with("shadow"))?;
            let metadata = pin.descriptor()?.metadata()?;
            if source.bytes() != baseline(member)?
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != mode(member)
            {
                return Err(
                    "hosted first-account source is not the immutable empty-account baseline"
                        .into(),
                );
            }
            let pieces: Vec<&[u8]> = match member {
                "passwd" => vec![passwd.as_bytes()],
                "group" => vec![group.as_bytes()],
                "gshadow" => vec![gshadow.as_bytes()],
                "shadow" => vec![shadow_prefix.as_bytes(), crypt, shadow_age.as_bytes()],
                _ => unreachable!(),
            };
            let replacement = appended(source.bytes(), &pieces)?;
            validate_after(member, replacement.bytes(), request)?;
            files.insert(
                member.into(),
                Change {
                    before: luma_content::sha256(source.bytes()),
                    after: luma_content::sha256(replacement.bytes()),
                    mode: mode(member),
                },
            );
            state.write_new(member, replacement.bytes(), mode(member))?;
            let (staged, staged_pin) =
                principal::account_file(&state.path.join(member), member.ends_with("shadow"))?;
            if staged.bytes() != replacement.bytes() {
                return Err("staged hosted account replacement changed".into());
            }
            after.insert(member.into(), replacement);
            source_pins.push(pin);
            pins.push(staged_pin);
            accounts.check()?;
            live()?;
        }
        let home_path = accounts
            .path
            .parent()
            .ok_or("hosted account root missing")?
            .join("home")
            .join(&request.login);
        let homes = Directory::open(
            home_path.parent().ok_or("hosted home parent missing")?,
            false,
        )?;
        match std::fs::symlink_metadata(&home_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("first account cannot adopt or replace an existing home".into()),
        }
        let staged_home = state.path.join("home");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&staged_home)?;
        let home = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staged_home)?;
        home.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        if unsafe { libc::fchown(home.as_raw_fd(), 1000, 1000) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        home.sync_all()?;
        state.file.sync_all()?;
        homes.check()?;
        let home_metadata = home.metadata()?;
        let record = Record {
            schema_version: 1,
            request_sha256: request_sha.clone(),
            files,
            home_device: home_metadata.dev(),
            home_inode: home_metadata.ino(),
        };
        state.write_new("transition.json", &canonical(&record)?, 0o600)?;
        for pin in &source_pins {
            pin.recheck()?;
        }
        for pin in &pins {
            pin.recheck()?;
        }
        live()?;
        Ok(Self {
            accounts,
            state,
            request_sha,
            record,
            after,
            pins,
            home_path,
        })
    }

    pub(super) fn publish(&mut self, mut live: impl FnMut() -> Result<()>) -> Result<()> {
        self.publish_from(0, false, &mut live)
    }

    // This path is invoked only by a separate explicit repair operation. It
    // neither restarts the original worker nor manufactures a fresh password.
    pub(super) fn finish_interrupted(
        &mut self,
        mut live: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let prefix = self.require_prefix()?;
        if prefix == ORDER.len() {
            self.require_complete()?;
            match std::fs::symlink_metadata(self.state.path.join("files-complete")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => self
                    .state
                    .write_new("files-complete", self.request_sha.as_bytes(), 0o600)?,
                Ok(_) => {
                    self.observation()?;
                }
                Err(error) => return Err(error.into()),
            }
            return live();
        }
        self.publish_from(prefix, true, &mut live)
    }

    fn publish_from(
        &mut self,
        prefix: usize,
        repair: bool,
        mut live: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        live()?;
        if self.require_home(true).is_err() {
            if prefix != 0 {
                return Err("partially published account lost its exact owned home".into());
            }
            self.require_home(false)?;
            let source = std::ffi::CString::new(
                self.state.path.join("home").as_os_str().as_encoded_bytes(),
            )?;
            let destination =
                std::ffi::CString::new(self.home_path.as_os_str().as_encoded_bytes())?;
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            self.state.file.sync_all()?;
            File::open(
                self.home_path
                    .parent()
                    .ok_or("hosted home parent missing")?,
            )?
            .sync_all()?;
        }
        self.require_home(true)?;
        for member in ORDER.into_iter().skip(prefix) {
            live()?;
            self.accounts.check()?;
            self.state.check()?;
            for pin in &self.pins {
                pin.recheck()?;
            }
            self.require_prefix()?;
            let (current, pin) = principal::account_file(
                &self.accounts.path.join(member),
                member.ends_with("shadow"),
            )?;
            if luma_content::sha256(current.bytes()) != self.record.files[member].before {
                return Err("hosted account publication no longer has its exact baseline".into());
            }
            let temporary = format!(".luma-workspace-{member}");
            // A synchronized complete temporary from this exact prepared
            // intent can be resumed only by the separate repair operation.
            let retained =
                repair && self.publication_temporary(self.require_prefix()?)? == Some(member);
            if !retained {
                self.accounts
                    .write_new(&temporary, self.after[member].bytes(), mode(member))?;
            }
            let (temporary_bytes, temporary_pin) = principal::account_file(
                &self.accounts.path.join(&temporary),
                member.ends_with("shadow"),
            )?;
            if temporary_bytes.bytes() != self.after[member].bytes() {
                return Err("account publication temporary changed".into());
            }
            live()?;
            self.require_prefix()?;
            pin.recheck()?;
            temporary_pin.recheck()?;
            // No rollback is inferred if rename/fsync fails. The retained exact
            // before/after record makes the prefix observable on explicit repair.
            std::fs::rename(
                self.accounts.path.join(&temporary),
                self.accounts.path.join(member),
            )?;
            self.accounts.file.sync_all()?;
            self.require_prefix()?;
            live()?;
        }
        self.require_complete()?;
        self.state
            .write_new("files-complete", self.request_sha.as_bytes(), 0o600)?;
        live()
    }

    fn require_prefix(&self) -> Result<usize> {
        let mut count = 0;
        let mut before_seen = false;
        for member in ORDER {
            let (bytes, pin) = principal::account_file(
                &self.accounts.path.join(member),
                member.ends_with("shadow"),
            )?;
            let change = &self.record.files[member];
            let digest = luma_content::sha256(bytes.bytes());
            let metadata = pin.descriptor()?.metadata()?;
            if metadata.gid() != 0 || metadata.mode() & 0o7777 != change.mode {
                return Err("hosted account metadata changed outside its exact transaction".into());
            }
            if digest == change.after && !before_seen {
                count += 1;
            } else if digest == change.before {
                before_seen = true;
            } else {
                return Err(
                    "hosted account state is not an exact applied transaction prefix".into(),
                );
            }
            pin.recheck()?;
        }
        Ok(count)
    }

    fn publication_temporary(&self, prefix: usize) -> Result<Option<&'static str>> {
        let mut retained = None;
        for (index, member) in ORDER.into_iter().enumerate() {
            let path = self.accounts.path.join(format!(".luma-workspace-{member}"));
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            if index != prefix || retained.is_some() {
                return Err("account temporary is not the unique next prepared publication".into());
            }
            let (bytes, pin) = principal::account_file(&path, member.ends_with("shadow"))?;
            let metadata = pin.descriptor()?.metadata()?;
            if bytes.bytes() != self.after[member].bytes()
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != mode(member)
            {
                return Err("damaged account publication temporary retained; explicit forensic repair required".into());
            }
            pin.recheck()?;
            retained = Some(member);
        }
        Ok(retained)
    }

    pub(super) fn require_complete(&self) -> Result<()> {
        self.accounts.check()?;
        self.state.check()?;
        for pin in &self.pins {
            pin.recheck()?;
        }
        self.require_home(true)?;
        if self.require_prefix()? != ORDER.len() {
            return Err(
                "hosted account publication is incomplete; explicit repair remains required".into(),
            );
        }
        self.publication_temporary(ORDER.len())?;
        Ok(())
    }

    fn require_home(&self, published: bool) -> Result<()> {
        let path = if published {
            self.home_path.clone()
        } else {
            self.state.path.join("home")
        };
        let info = std::fs::symlink_metadata(path)?;
        if !info.is_dir()
            || info.dev() != self.record.home_device
            || info.ino() != self.record.home_inode
            || info.uid() != 1000
            || info.gid() != 1000
            || info.mode() & 0o7777 != 0o700
        {
            return Err("prepared hosted account home identity/ownership changed".into());
        }
        Ok(())
    }

    pub(super) fn mark_pam_verified(&self, mut live: impl FnMut() -> Result<()>) -> Result<()> {
        live()?;
        self.require_complete()?;
        if self.observation()?["pam_verified_once"] != true {
            self.state
                .write_new("pam-verified", self.request_sha.as_bytes(), 0o600)?;
        }
        self.require_complete()?;
        live()
    }

    pub(super) fn recover(
        accounts: &Path,
        state: &Path,
        request: &Request,
        mut live: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        live()?;
        let accounts = Directory::open(accounts, false)?;
        let state = Directory::open(state, true)?;
        if unsafe { libc::flock(state.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("original hosted account worker may still own its transaction".into());
        }
        let (intent, intent_pin) = principal::account_file(&state.path.join("intent.json"), true)?;
        if intent.bytes() != canonical(request)? {
            return Err("repair cannot adopt another first-account intent".into());
        }
        let request_sha = luma_content::sha256(intent.bytes());
        let (record_bytes, record_pin) =
            principal::account_file(&state.path.join("transition.json"), true)?;
        let record: Record = serde_json::from_slice(record_bytes.bytes())?;
        if record.schema_version != 1
            || record.request_sha256 != request_sha
            || record.files.len() != 4
            || canonical(&record)? != record_bytes.bytes()
        {
            return Err("retained hosted account transition identity differs".into());
        }
        let mut after = BTreeMap::new();
        let mut pins = vec![intent_pin, record_pin];
        for member in ORDER {
            let change = record
                .files
                .get(member)
                .ok_or("retained account member missing")?;
            let (replacement, pin) =
                principal::account_file(&state.path.join(member), member.ends_with("shadow"))?;
            validate_after(member, replacement.bytes(), request)?;
            let metadata = pin.descriptor()?.metadata()?;
            if change.before != luma_content::sha256(baseline(member)?)
                || change.after != luma_content::sha256(replacement.bytes())
                || change.before == change.after
                || change.mode != mode(member)
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != mode(member)
            {
                return Err(
                    "retained account replacement differs from the prepared transition".into(),
                );
            }
            after.insert(member.into(), replacement);
            pins.push(pin);
            live()?;
        }
        let home_path = accounts
            .path
            .parent()
            .ok_or("hosted account root missing")?
            .join("home")
            .join(&request.login);
        let transaction = Self {
            accounts,
            state,
            request_sha,
            record,
            after,
            pins,
            home_path,
        };
        transaction.require_prefix()?;
        transaction.publication_temporary(transaction.require_prefix()?)?;
        live()?;
        Ok(transaction)
    }

    pub(super) fn observation(&self) -> Result<serde_json::Value> {
        self.accounts.check()?;
        self.state.check()?;
        for pin in &self.pins {
            pin.recheck()?;
        }
        let prefix = self.require_prefix()?;
        self.publication_temporary(prefix)?;
        let marker = |name: &str| -> Result<bool> {
            match principal::account_file(&self.state.path.join(name), true) {
                Ok((bytes, pin)) => {
                    if bytes.bytes() != self.request_sha.as_bytes() {
                        return Err("hosted account completion marker differs".into());
                    }
                    pin.recheck()?;
                    Ok(true)
                }
                Err(error) => match std::fs::symlink_metadata(self.state.path.join(name)) {
                    Err(value) if value.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    _ => Err(error),
                },
            }
        };
        let files_complete = marker("files-complete")?;
        let pam_verified = marker("pam-verified")?;
        if prefix > 0 || files_complete || pam_verified {
            self.require_home(true)?;
        } else {
            let staged = self.require_home(false).is_ok();
            let published = self.require_home(true).is_ok();
            if staged == published {
                return Err("hosted home has no unique prepared/published identity".into());
            }
        }
        if (files_complete || pam_verified) && prefix != 4 || pam_verified && !files_complete {
            return Err("hosted account marker/file state is inconsistent".into());
        }
        // The witness stays in the authenticated private status channel and
        // host CNG journal. It is not a verifier, public approval hash or grant.
        let account_state = if files_complete {
            self.require_complete()?;
            luma_content::sha256(&canonical(&self.record)?)
        } else {
            "0".repeat(64)
        };
        Ok(
            serde_json::json!({"applied_file_count":prefix,"files_complete":files_complete,
            "pam_verified_once":pam_verified,"bootstrap_request_sha256":self.request_sha,
            "account_state_sha256":account_state}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "account-file fixture requires disposable root container"
            );
            assert!(
                Path::new("/.dockerenv").is_file(),
                "never run account-file fixtures against an installed host"
            );
            let path = PathBuf::from(format!(
                "/run/luma-workspace-account-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            for directory in ["etc", "home", "state"] {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path.join(directory))
                    .unwrap();
            }
            let etc = Directory::open(&path.join("etc"), true).unwrap();
            for member in ORDER {
                etc.write_new(member, baseline(member).unwrap(), mode(member))
                    .unwrap();
            }
            Self(path)
        }
        fn prepare(&self) -> Transaction {
            let mut secret = PrivateBuffer::new(1025).unwrap();
            let value = b"fixture-secret-only-1234!";
            secret.bytes_mut()[..value.len()].copy_from_slice(value);
            let password = crate::account_password::Password::fixture(&secret).unwrap();
            let hash = password.hash().unwrap();
            Transaction::prepare(
                &self.0.join("etc"),
                &self.0.join("state/bootstrap"),
                &request(),
                &hash,
                || Ok(()),
            )
            .unwrap()
        }
        fn recover(&self) -> Result<Transaction> {
            Transaction::recover(
                &self.0.join("etc"),
                &self.0.join("state/bootstrap"),
                &request(),
                || Ok(()),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(self
                .0
                .to_string_lossy()
                .starts_with("/run/luma-workspace-account-fixture-"));
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn request() -> Request {
        Request {
            schema_version: 1,
            profile: super::super::PROFILE.into(),
            nonce: "11".repeat(32),
            installation: "22".repeat(32),
            release_sha256: "33".repeat(32),
            runtime_manifest_sha256: "44".repeat(32),
            profile_sha256: "55".repeat(32),
            actor_sid_sha256: "66".repeat(32),
            login: "alice".into(),
            uid: 1000,
            gid: 1000,
            account_generation: 1,
            protected_utc_day: 20746,
            utc_proof_sha256: "77".repeat(32),
        }
    }
    #[test]
    fn fresh_exact_publication_retains_separate_pam_boundary_and_owned_home() {
        let fixture = Fixture::new();
        let mut transaction = fixture.prepare();
        assert_eq!(transaction.observation().unwrap()["applied_file_count"], 0);
        assert_eq!(
            transaction.observation().unwrap()["account_state_sha256"],
            "0".repeat(64)
        );
        transaction.publish(|| Ok(())).unwrap();
        let observation = transaction.observation().unwrap();
        assert_eq!(observation["applied_file_count"], 4);
        assert_eq!(observation["files_complete"], true);
        assert_eq!(observation["pam_verified_once"], false);
        assert_ne!(observation["account_state_sha256"], "0".repeat(64));
        transaction.mark_pam_verified(|| Ok(())).unwrap();
        assert_eq!(
            transaction.observation().unwrap()["pam_verified_once"],
            true
        );
        let home = std::fs::symlink_metadata(fixture.0.join("home/alice")).unwrap();
        assert_eq!(
            (home.uid(), home.gid(), home.mode() & 0o7777),
            (1000, 1000, 0o700)
        );
        drop(transaction);
        assert_eq!(
            fixture.recover().unwrap().observation().unwrap()["files_complete"],
            true
        );
    }
    #[test]
    fn interruption_is_exactly_observable_without_retry_or_name_adoption() {
        let fixture = Fixture::new();
        let mut transaction = fixture.prepare();
        let mut count = 0;
        assert!(transaction
            .publish(|| {
                count += 1;
                if count == 4 {
                    Err("interrupted after first account rename".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(transaction.observation().unwrap()["applied_file_count"], 1);
        assert!(transaction.require_complete().is_err());
        assert!(transaction.mark_pam_verified(|| Ok(())).is_err());
        drop(transaction);
        let mut recovered = fixture.recover().unwrap();
        assert_eq!(recovered.observation().unwrap()["applied_file_count"], 1);
        assert_eq!(recovered.observation().unwrap()["files_complete"], false);
        assert!(!fixture.0.join("state/bootstrap/pam-verified").exists());
        recovered.finish_interrupted(|| Ok(())).unwrap();
        assert_eq!(recovered.observation().unwrap()["files_complete"], true);
        assert_eq!(recovered.observation().unwrap()["pam_verified_once"], false);
    }
    #[test]
    fn complete_temporary_requires_explicit_repair_and_unknown_bytes_are_retained() {
        let fixture = Fixture::new();
        let mut transaction = fixture.prepare();
        let mut count = 0;
        assert!(transaction
            .publish(|| {
                count += 1;
                if count == 3 {
                    Err("interrupted before account rename".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(transaction.observation().unwrap()["applied_file_count"], 0);
        assert!(fixture.0.join("etc/.luma-workspace-gshadow").is_file());
        drop(transaction);
        let mut recovered = fixture.recover().unwrap();
        recovered.finish_interrupted(|| Ok(())).unwrap();
        assert_eq!(recovered.observation().unwrap()["files_complete"], true);
        assert!(!fixture.0.join("etc/.luma-workspace-gshadow").exists());
        let fixture = Fixture::new();
        let transaction = fixture.prepare();
        let damaged = fixture.0.join("etc/.luma-workspace-gshadow");
        std::fs::write(&damaged, b"unknown partial bytes").unwrap();
        std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(transaction);
        assert!(fixture.recover().is_err());
        assert_eq!(std::fs::read(&damaged).unwrap(), b"unknown partial bytes");
    }
    #[test]
    fn mixed_out_of_order_accounts_ambiguous_markers_and_changed_intent_refuse() {
        let fixture = Fixture::new();
        let transaction = fixture.prepare();
        let after = transaction.after["passwd"].bytes();
        std::fs::write(fixture.0.join("etc/passwd"), after).unwrap();
        assert!(transaction.observation().is_err());
        drop(transaction);
        assert!(fixture.recover().is_err());
        let mut changed = request();
        changed.login = "bob".into();
        assert!(Transaction::recover(
            &fixture.0.join("etc"),
            &fixture.0.join("state/bootstrap"),
            &changed,
            || Ok(())
        )
        .is_err());
    }
    #[test]
    fn replacement_never_adds_admin_groups_unlocked_root_or_weaker_password_aging() {
        let request = request();
        for member in ORDER {
            assert!(validate_after(member, baseline(member).unwrap(), &request).is_err());
        }
        let mut passwd = PASSWD.to_vec();
        passwd.extend_from_slice(b"alice:x:1000:0:Luma local user:/home/alice:/bin/bash\n");
        assert!(validate_after("passwd", &passwd, &request).is_err());
        let mut group = GROUP.to_vec();
        group.extend_from_slice(b"alice:x:1000:\nsudo:x:27:alice\n");
        assert!(validate_after("group", &group, &request).is_err());
        let mut shadow = SHADOW.to_vec();
        shadow.extend_from_slice(b"alice:!:20746:0:90:7:::\n");
        assert!(validate_after("shadow", &shadow, &request).is_err());
    }
    #[test]
    fn explicit_unstarted_repair_requires_total_absence_and_every_exact_baseline() {
        let fixture = Fixture::new();
        let accounts = fixture.0.join("etc");
        let state = fixture.0.join("state/bootstrap");
        Transaction::require_unstarted(&accounts, &state, &request()).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(Transaction::require_unstarted(&accounts, &state, &request()).is_err());
        std::fs::remove_dir(&state).unwrap();
        std::fs::create_dir(fixture.0.join("home/alice")).unwrap();
        assert!(Transaction::require_unstarted(&accounts, &state, &request()).is_err());
        std::fs::remove_dir(fixture.0.join("home/alice")).unwrap();
        std::fs::write(
            accounts.join("passwd"),
            b"root:x:0:0:changed:/root:/bin/bash\n",
        )
        .unwrap();
        assert!(Transaction::require_unstarted(&accounts, &state, &request()).is_err());
        assert!(!state.exists());
    }
}
