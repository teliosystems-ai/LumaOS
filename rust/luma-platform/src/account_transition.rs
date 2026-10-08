//! Exact shadow-file publication for governed, existing-account lock changes.
//! Intent is inert data. Only the owning Admin continuation may stage/publish;
//! uncertain TPM preparation never licenses filesystem publication.
use crate::{bundle, principal, sealed_credential::PrivateBuffer, tpm, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub transaction: String,
    pub installation: String,
    pub principal: String,
    pub expected_generation: u64,
    pub locked: bool,
    pub passwd_sha256: String,
    pub shadow_before_sha256: String,
    pub shadow_after_sha256: String,
    pub credential_before: String,
    pub credential_after: String,
}

impl Intent {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::admin_roles::identifier(&self.transaction)
            || self.transaction == "admin-bootstrap-v1"
            || self.expected_generation == 0
            || self.expected_generation == u64::MAX
            || self.installation == self.principal
            || self.shadow_before_sha256 == self.shadow_after_sha256
            || self.credential_before == self.credential_after
        {
            return Err("invalid account lock transition".into());
        }
        for value in [
            &self.installation,
            &self.principal,
            &self.passwd_sha256,
            &self.shadow_before_sha256,
            &self.shadow_after_sha256,
            &self.credential_before,
            &self.credential_after,
        ] {
            if tpm::decode::<32>(value)? == [0; 32] {
                return Err("empty account transition commitment".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Prepared,
    PublicationPermitted,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transition {
    pub intent: Intent,
    pub phase: Phase,
}

fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}

// Every plaintext/hash row remains in locked, nondumpable memory. Diagnostics
// deliberately omit the row, hash and affected account name.
fn changed_shadow(input: &[u8], name: &str, locked: bool) -> Result<PrivateBuffer> {
    if input.is_empty() || !input.ends_with(b"\n") {
        return Err("shadow publication requires complete newline-terminated records".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid account encoding")?;
    let mut offset = 0;
    let mut selected = None;
    for row in text.split_inclusive('\n') {
        let fields: Vec<_> = row.trim_end_matches('\n').split(':').collect();
        if fields.len() != 9 {
            return Err("invalid shadow record".into());
        }
        if fields[0] == name {
            if selected.is_some() {
                return Err("ambiguous shadow record".into());
            }
            let value = fields[1];
            let unlocked = value.strip_prefix('!').unwrap_or(value);
            if unlocked.is_empty()
                || unlocked.starts_with(['!', '*'])
                || !unlocked.starts_with('$')
                || value.starts_with('!') == locked
            {
                return Err(
                    "lock transition requires a usable credential and changed lock state".into(),
                );
            }
            selected = Some(offset + name.len() + 1);
        }
        offset += row.len();
    }
    let offset = selected.ok_or("missing shadow record")?;
    let length = if locked {
        input.len() + 1
    } else {
        input.len() - 1
    };
    let mut output = PrivateBuffer::new(length)?;
    output.bytes_mut()[..offset].copy_from_slice(&input[..offset]);
    if locked {
        output.bytes_mut()[offset] = b'!';
        output.bytes_mut()[offset + 1..].copy_from_slice(&input[offset..]);
    } else {
        output.bytes_mut()[offset..].copy_from_slice(&input[offset + 1..]);
    }
    Ok(output)
}

/// Nonserializable lifetime guard over the original directory, migration lock
/// and account descriptors. A plan cannot be reconstructed from JSON alone.
pub(crate) struct Guard {
    identity: PathBuf,
    directory: File,
    directory_identity: (u64, u64, u32, u32, u32),
    lock: File,
    lock_identity: (u64, u64),
    passwd: principal::FilePin,
    shadow: principal::FilePin,
    before: PrivateBuffer,
    after: PrivateBuffer,
    mode: u32,
    gid: u32,
    staged: RefCell<Option<[principal::FilePin; 2]>>,
    pub intent: Intent,
}

impl Guard {
    pub(crate) fn prepare(
        registry_path: &Path,
        identity: &Path,
        target: &str,
        expected_generation: u64,
        transaction: &str,
        locked: bool,
    ) -> Result<Self> {
        let registry = principal::RegistryBinding::capture(registry_path)?;
        let current = registry.current()?;
        let principal = current
            .account(target)
            .filter(|record| record.enabled && record.uid != 1001)
            .ok_or("lock changes require an installed non-Admin principal")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(identity)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("unsafe account publication directory".into());
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
            return Err("account publication lock unavailable or unsafe".into());
        }
        let lock_identity = (metadata.dev(), metadata.ino());
        let (passwd_bytes, passwd) = principal::account_file(&identity.join("passwd"), false)?;
        let (before, shadow) = principal::account_file(&identity.join("shadow"), true)?;
        let after = changed_shadow(before.bytes(), target, locked)?;
        let old =
            principal::account_rows_digest(passwd_bytes.bytes(), before.bytes(), principal, true)?;
        let new =
            principal::account_rows_digest(passwd_bytes.bytes(), after.bytes(), principal, true)?;
        let metadata = fs::symlink_metadata(identity.join("shadow"))?;
        let intent = Intent {
            transaction: transaction.into(),
            installation: current.installation().into(),
            principal: principal.id.clone(),
            expected_generation,
            locked,
            passwd_sha256: hash(passwd_bytes.bytes()),
            shadow_before_sha256: hash(before.bytes()),
            shadow_after_sha256: hash(after.bytes()),
            credential_before: principal::rows_commitment(current.installation(), principal, old)?,
            credential_after: principal::rows_commitment(current.installation(), principal, new)?,
        };
        intent.validate()?;
        registry.current()?;
        let result = Self {
            identity: identity.into(),
            directory,
            directory_identity,
            lock,
            lock_identity,
            passwd,
            shadow,
            before,
            after,
            mode: metadata.mode() & 0o777,
            gid: metadata.gid(),
            staged: RefCell::new(None),
            intent,
        };
        result.recheck()?;
        Ok(result)
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        self.source_recheck()?;
        if let Some(pins) = &*self.staged.borrow() {
            for pin in pins {
                pin.recheck()?;
            }
        }
        Ok(())
    }

    fn source_recheck(&self) -> Result<()> {
        self.directory_recheck()?;
        self.passwd.recheck()?;
        self.shadow.recheck()?;
        Ok(())
    }

    pub(crate) fn retain_stage(&self) -> Result<()> {
        if self.staged.borrow().is_some() {
            return self.recheck();
        }
        self.source_recheck()?;
        let path = self.stage_path();
        tpm::private_directory(&path)?;
        let (intent, intent_pin) = principal::account_file(&path.join("intent.json"), true)?;
        if intent_pin.descriptor()?.metadata()?.mode() & 0o777 != 0o600 {
            return Err("staged account intent must remain private".into());
        }
        let (shadow, shadow_pin) = principal::account_file(&path.join("shadow.new"), true)?;
        if intent.bytes() != serde_json::to_vec(&self.intent)?
            || shadow.bytes() != self.after.bytes()
        {
            return Err("staged account transition differs from anchored intent".into());
        }
        *self.staged.borrow_mut() = Some([intent_pin, shadow_pin]);
        self.recheck()
    }

    fn directory_recheck(&self) -> Result<()> {
        if directory_identity(&self.directory.metadata()?) != self.directory_identity
            || directory_identity(&fs::symlink_metadata(&self.identity)?) != self.directory_identity
        {
            return Err("account publication directory changed".into());
        }
        let metadata = fs::symlink_metadata(self.identity.join("migration.lock"))?;
        let held = self.lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != 0
            || (metadata.dev(), metadata.ino()) != self.lock_identity
            || (held.dev(), held.ino()) != self.lock_identity
        {
            return Err("account publication lock changed".into());
        }
        Ok(())
    }

    /// Stage only after reviewed governed authorization, before TPM intent
    /// preparation. Existing exact bytes are preserved; conflicts never reset.
    pub(crate) fn stage(&self) -> Result<()> {
        self.recheck()?;
        let path = self.stage_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => tpm::private_directory(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
        tpm::private_directory(&path)?;
        self.write_stage(&path.join("shadow.new"), self.after.bytes())?;
        self.write_stage(
            &path.join("intent.json"),
            &serde_json::to_vec(&self.intent)?,
        )?;
        File::open(&path)?.sync_all()?;
        self.directory.sync_all()?;
        self.retain_stage()
    }

    fn write_stage(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)?,
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > bytes.len() as u64
        {
            return Err("unsafe or oversized staged account file".into());
        }
        let length = metadata.len() as usize;
        let mut retained = PrivateBuffer::new(bytes.len())?;
        file.read_exact(&mut retained.bytes_mut()[..length])?;
        // Only fresh review of the exact protected inputs may complete an
        // interrupted exact prefix. Conflicting bytes are never truncated.
        if retained.bytes()[..length] != bytes[..length] {
            return Err("retained account publication differs; preserve state".into());
        }
        let current = fs::symlink_metadata(path)?;
        if file_identity(&metadata) != file_identity(&file.metadata()?)
            || file_identity(&metadata) != file_identity(&current)
        {
            return Err("staged account file changed during observation".into());
        }
        self.recheck()?;
        file.write_all(&bytes[length..])?;
        file.sync_all()?;
        Ok(())
    }

    fn stage_path(&self) -> PathBuf {
        self.identity
            .join(format!("account-transition-{}", self.intent.transaction))
    }

    /// Called only after the owning continuation observes a committed exact
    /// PublicationPermitted event. No journal/JSON receipt alone invokes it.
    pub(crate) fn publish(&self, mut authorize: impl FnMut() -> Result<()>) -> Result<()> {
        self.recheck()?;
        let path = self.stage_path();
        tpm::private_directory(&path)?;
        if tpm::private_read(&path.join("intent.json"), 8192)? != serde_json::to_vec(&self.intent)?
        {
            return Err("publication intent differs from anchored transition".into());
        }
        let (bytes, staged) = principal::account_file(&path.join("shadow.new"), true)?;
        if bytes.bytes() != self.after.bytes()
            || hash(self.before.bytes()) != self.intent.shadow_before_sha256
        {
            return Err("publication bytes differ from anchored transition".into());
        }
        authorize()?;
        staged.recheck()?;
        self.recheck()?;
        let file = staged.descriptor()?;
        if unsafe { libc::fchown(file.as_raw_fd(), 0, self.gid) } != 0 {
            return Err("cannot preserve shadow ownership".into());
        }
        file.set_permissions(fs::Permissions::from_mode(self.mode))?;
        file.sync_all()?;
        authorize()?;
        self.source_recheck()?;
        if let Some(pins) = &*self.staged.borrow() {
            pins[0].recheck()?;
        }
        let held = file.metadata()?;
        let current = fs::symlink_metadata(path.join("shadow.new"))?;
        if directory_identity(&held) != directory_identity(&current)
            || held.len() != current.len()
            || held.nlink() != 1
            || current.nlink() != 1
            || held.mtime() != current.mtime()
            || held.mtime_nsec() != current.mtime_nsec()
            || held.ctime() != current.ctime()
            || held.ctime_nsec() != current.ctime_nsec()
        {
            return Err("prepared shadow descriptor replaced before publication".into());
        }
        let stage_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let source = b"shadow.new\0";
        let destination = b"shadow\0";
        if unsafe {
            libc::renameat(
                stage_directory.as_raw_fd(),
                source.as_ptr().cast(),
                self.directory.as_raw_fd(),
                destination.as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        stage_directory.sync_all()?;
        self.directory_recheck()?;
        self.passwd.recheck()?;
        let (published, _) = principal::account_file(&self.identity.join("shadow"), true)?;
        if hash(published.bytes()) != self.intent.shadow_after_sha256 {
            return Err("shadow publication changed; explicit reconciliation required".into());
        }
        Ok(())
    }
}

fn directory_identity(metadata: &fs::Metadata) -> (u64, u64, u32, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

fn file_identity(
    metadata: &fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.len(),
        metadata.nlink(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

/// Read-only original-handle guard used at completion and already-published
/// recovery. Retained intent and exact whole-file digests must agree.
pub(crate) struct Published {
    registry: principal::RegistryBinding,
    passwd: principal::FilePin,
    shadow: principal::FilePin,
    intent_file: principal::FilePin,
    intent_path: PathBuf,
    intent_bytes: Vec<u8>,
}

impl Published {
    pub(crate) fn capture(registry_path: &Path, identity: &Path, intent: &Intent) -> Result<Self> {
        intent.validate()?;
        let registry = principal::RegistryBinding::capture(registry_path)?;
        let current = registry.current()?;
        let record = current
            .principal(&intent.principal)
            .ok_or("unknown publication principal")?;
        if current.installation() != intent.installation || record.uid == 1001 {
            return Err("publication belongs to another installation or Admin".into());
        }
        let (passwd_bytes, passwd) = principal::account_file(&identity.join("passwd"), false)?;
        let (shadow_bytes, shadow) = principal::account_file(&identity.join("shadow"), true)?;
        if hash(passwd_bytes.bytes()) != intent.passwd_sha256
            || hash(shadow_bytes.bytes()) != intent.shadow_after_sha256
            || principal::rows_commitment(
                current.installation(),
                record,
                principal::account_rows_digest(
                    passwd_bytes.bytes(),
                    shadow_bytes.bytes(),
                    record,
                    true,
                )?,
            )? != intent.credential_after
        {
            return Err(
                "account publication is incomplete or differs from reviewed transition".into(),
            );
        }
        let path = identity.join(format!("account-transition-{}", intent.transaction));
        tpm::private_directory(&path)?;
        let intent_path = path.join("intent.json");
        let intent_bytes = tpm::private_read(&intent_path, 8192)?;
        if intent_bytes != serde_json::to_vec(intent)? {
            return Err("retained publication intent differs".into());
        }
        let (_, intent_file) = principal::account_file(&intent_path, true)?;
        let result = Self {
            registry,
            passwd,
            shadow,
            intent_file,
            intent_path,
            intent_bytes,
        };
        result.recheck()?;
        Ok(result)
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        self.registry.current()?;
        self.passwd.recheck()?;
        self.shadow.recheck()?;
        self.intent_file.recheck()?;
        if tpm::private_read(&self.intent_path, 8192)? != self.intent_bytes {
            return Err("retained account intent replaced".into());
        }
        Ok(())
    }
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
                "luma-account-transition-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("identity"))
                .unwrap();
            principal::initialize(
                &path.join("principals"),
                &[("human", 1001), ("otherhuman", 1002)],
            )
            .unwrap();
            for (name, bytes) in [
                ("passwd", "human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n"),
                ("shadow", "human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n"),
            ] { crate::platform::write_atomic(&path.join("identity").join(name), bytes.as_bytes(), 0o600).unwrap(); }
            Self(path)
        }
        fn registry(&self) -> PathBuf {
            self.0.join("principals/registry.json")
        }
        fn identity(&self) -> PathBuf {
            self.0.join("identity")
        }
        fn plan(&self, generation: u64, request: &str, locked: bool) -> Guard {
            Guard::prepare(
                &self.registry(),
                &self.identity(),
                "otherhuman",
                generation,
                request,
                locked,
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
    fn lock_then_unlock_preserves_other_rows_and_requires_exact_completion() {
        let fixture = Fixture::new();
        let original = fs::read(fixture.identity().join("shadow")).unwrap();
        let guard = fixture.plan(1, "lock-one", true);
        assert!(
            Published::capture(&fixture.registry(), &fixture.identity(), &guard.intent).is_err()
        );
        guard.stage().unwrap();
        guard.stage().unwrap();
        guard.publish(|| Ok(())).unwrap();
        let locked = fs::read(fixture.identity().join("shadow")).unwrap();
        assert!(std::str::from_utf8(&locked)
            .unwrap()
            .contains("otherhuman:!$6$fixture$two:"));
        assert!(
            locked.starts_with(&original[..original.iter().position(|&b| b == b'\n').unwrap() + 1])
        );
        Published::capture(&fixture.registry(), &fixture.identity(), &guard.intent)
            .unwrap()
            .recheck()
            .unwrap();
        assert!(guard.recheck().is_err());
        drop(guard);
        let guard = fixture.plan(2, "unlock-one", false);
        guard.stage().unwrap();
        guard.publish(|| Ok(())).unwrap();
        assert_eq!(
            fs::read(fixture.identity().join("shadow")).unwrap(),
            original
        );
        Published::capture(&fixture.registry(), &fixture.identity(), &guard.intent).unwrap();
    }

    #[test]
    fn changed_records_lock_contention_and_failed_authorization_never_publish() {
        let fixture = Fixture::new();
        let guard = fixture.plan(1, "lock-two", true);
        assert!(Guard::prepare(
            &fixture.registry(),
            &fixture.identity(),
            "otherhuman",
            1,
            "other",
            true
        )
        .is_err());
        guard.stage().unwrap();
        let before = fs::read(fixture.identity().join("shadow")).unwrap();
        assert!(guard.publish(|| Err("authorization lost".into())).is_err());
        assert_eq!(fs::read(fixture.identity().join("shadow")).unwrap(), before);
        crate::platform::write_atomic(
            &fixture.identity().join("passwd"),
            b"otherhuman:x:1002:1002:Changed:/home/otherhuman:/bin/bash\n",
            0o600,
        )
        .unwrap();
        assert!(guard.recheck().is_err());
        assert!(guard.publish(|| Ok(())).is_err());
        assert_eq!(fs::read(fixture.identity().join("shadow")).unwrap(), before);
    }

    #[test]
    fn invalid_lock_states_and_secret_free_intent() {
        for row in [
            "otherhuman::0:0:0:0:::\n",
            "otherhuman:*:0:0:0:0:::\n",
            "otherhuman:!!$6$a$b:0:0:0:0:::\n",
            "otherhuman:!$6$a$b:0:0:0:0:::\n",
            "otherhuman:$6$a$b:0:0:0:0:::",
        ] {
            assert!(changed_shadow(row.as_bytes(), "otherhuman", true).is_err());
        }
        let fixture = Fixture::new();
        assert!(Guard::prepare(
            &fixture.registry(),
            &fixture.identity(),
            "human",
            1,
            "bad",
            true
        )
        .is_err());
        let guard = fixture.plan(1, "lock-three", true);
        let bytes = serde_json::to_string(&guard.intent).unwrap();
        assert!(!bytes.contains("$6$"));
        assert!(!bytes.contains("otherhuman"));
        assert!(changed_shadow(b"otherhuman:$6$a$b:0:0:0:0:::\n", "otherhuman", false).is_err());
    }

    #[test]
    fn exact_partial_staging_is_reviewably_resumable_but_conflicts_are_retained() {
        let fixture = Fixture::new();
        let guard = fixture.plan(1, "partial-lock", true);
        let stage = guard.stage_path();
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        let path = stage.join("shadow.new");
        crate::platform::write_atomic(&path, &guard.after.bytes()[..7], 0o600).unwrap();
        let intent = serde_json::to_vec(&guard.intent).unwrap();
        crate::platform::write_atomic(&stage.join("intent.json"), &intent[..9], 0o600).unwrap();
        guard.stage().unwrap();
        assert_eq!(
            principal::account_file(&path, true).unwrap().0.bytes(),
            guard.after.bytes()
        );
        assert_eq!(
            tpm::private_read(&stage.join("intent.json"), 8192).unwrap(),
            intent
        );
        crate::platform::write_atomic(&path, b"conflict", 0o600).unwrap();
        assert!(guard.stage().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"conflict");
        assert!(guard.publish(|| Ok(())).is_err());
    }

    #[test]
    fn publication_refuses_revocation_after_permission_and_preserves_resumable_bytes() {
        let fixture = Fixture::new();
        let guard = fixture.plan(1, "revoked-lock", true);
        guard.stage().unwrap();
        guard.retain_stage().unwrap();
        let inode = fs::symlink_metadata(fixture.identity().join("shadow"))
            .unwrap()
            .ino();
        let mut checks = 0;
        assert!(guard
            .publish(|| {
                checks += 1;
                if checks == 2 {
                    Err("revoked at final dispatch".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(checks, 2);
        assert_eq!(
            fs::symlink_metadata(fixture.identity().join("shadow"))
                .unwrap()
                .ino(),
            inode
        );
        let intent = guard.intent.clone();
        drop(guard);
        let fresh = fixture.plan(1, "revoked-lock", true);
        assert_eq!(fresh.intent, intent);
        fresh.retain_stage().unwrap();
        fresh.publish(|| Ok(())).unwrap();
        Published::capture(&fixture.registry(), &fixture.identity(), &intent).unwrap();
    }
}
