//! Installation-scoped local principal binding, not an Admin role or capability.
//! Root-controlled metadata is not a TPM-anchored enrollment/recovery service.
use crate::{bundle, sealed_credential::PrivateBuffer, tpm, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const REGISTRY: &str = "/var/lib/luma-os/principals/registry.json";
pub const IDENTITY: &str = "/var/lib/luma-os/identity";
const MAX_ACCOUNT_BYTES: usize = 16 * 1024;
const MAX_REGISTRY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Principal {
    pub id: String,
    pub generation: u64,
    pub login: String,
    pub uid: u32,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    schema_version: u32,
    installation: String,
    principals: Vec<Principal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_recovery: Option<crate::admin_recovery::Verifier>,
}

fn login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn validate(registry: &Registry) -> Result<()> {
    tpm::decode::<32>(&registry.installation)?;
    if registry.schema_version != 1
        || registry.principals.is_empty()
        || registry.principals.len() > 128
    {
        return Err("invalid local principal registry".into());
    }
    let (mut ids, mut names, mut uids) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for p in &registry.principals {
        tpm::decode::<32>(&p.id)?;
        if !login(&p.login)
            || !(1000..65534).contains(&p.uid)
            || p.generation == 0
            || p.id == registry.installation
            || !ids.insert(&p.id)
            || !names.insert(&p.login)
            || !uids.insert(p.uid)
        {
            return Err("invalid or duplicate local principal".into());
        }
    }
    if let Some(verifier) = &registry.admin_recovery {
        let admin = registry
            .bootstrap_admin()
            .filter(|record| record.enabled)
            .ok_or("recovery verifier requires an enabled original Admin")?;
        verifier.validate(&registry.installation, &admin.id)?;
        if verifier.generation != 1 {
            return Err("installer recovery verifier must start at generation one".into());
        }
    }
    Ok(())
}

impl Registry {
    pub(crate) fn append_account(&self, record: &Principal) -> Result<Self> {
        if record.generation != 1
            || !record.enabled
            || record.uid == 1001
            || crate::tpm::decode::<32>(&record.id)? == [0; 32]
        {
            return Err(
                "new accounts require a fresh enabled installation identity at generation one"
                    .into(),
            );
        }
        let mut next = self.clone();
        next.principals.push(record.clone());
        next.validate()?;
        if serde_json::to_vec(&next)?.len() > MAX_REGISTRY_BYTES as usize {
            return Err("principal registry capacity exhausted".into());
        }
        Ok(next)
    }

    pub(crate) fn recovery_verifier(&self) -> Option<&crate::admin_recovery::Verifier> {
        self.admin_recovery.as_ref()
    }

    pub(crate) fn installation(&self) -> &str {
        &self.installation
    }

    pub(crate) fn bootstrap_admin(&self) -> Option<&Principal> {
        self.principals.iter().find(|record| record.uid == 1001)
    }

    pub(crate) fn principals(&self) -> &[Principal] {
        &self.principals
    }

    pub(crate) fn principal(&self, id: &str) -> Option<&Principal> {
        self.principals.iter().find(|record| record.id == id)
    }

    pub(crate) fn account(&self, name: &str) -> Option<&Principal> {
        self.principals.iter().find(|record| record.login == name)
    }

    pub(crate) fn identity(&self, record: &Principal) -> serde_json::Value {
        serde_json::json!({"installation":self.installation,"principal":record.id,
            "generation":record.generation,"login":record.login,"uid":record.uid})
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate(self)
    }

    pub(crate) fn binds(
        &self,
        installation: &str,
        principal: &str,
        generation: u64,
        name: &str,
        uid: u32,
    ) -> bool {
        self.installation == installation
            && self.principals.iter().any(|record| {
                record.id == principal
                    && record.generation == generation
                    && record.login == name
                    && record.uid == uid
                    && record.enabled
            })
    }
}

fn random_id() -> Result<String> {
    let mut random = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(bundle::hex(&random))
}

/// Fresh installation only; never reset a missing registry during runtime.
pub(crate) fn initialize_with_recovery(
    directory: &Path,
    accounts: &[(&str, u32)],
    credential: &crate::admin_recovery::Credential,
) -> Result<()> {
    initialize_at(directory, accounts, Some(credential))
}

fn initialize_at(
    directory: &Path,
    accounts: &[(&str, u32)],
    credential: Option<&crate::admin_recovery::Credential>,
) -> Result<()> {
    crate::require_root()?;
    let mut registry = Registry {
        schema_version: 1,
        installation: random_id()?,
        principals: vec![],
        admin_recovery: None,
    };
    for &(name, uid) in accounts {
        registry.principals.push(Principal {
            id: random_id()?,
            generation: 1,
            login: name.into(),
            uid,
            enabled: true,
        });
    }
    if let Some(credential) = credential {
        let admin = registry
            .bootstrap_admin()
            .ok_or("installer recovery requires original Admin")?;
        registry.admin_recovery = Some(crate::admin_recovery::Verifier::create(
            credential,
            &registry.installation,
            &admin.id,
            1,
        )?);
    }
    validate(&registry)?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    tpm::private_directory(directory)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("registry.json"))?;
    file.write_all(&serde_json::to_vec(&registry)?)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    File::open(directory.parent().ok_or("missing principal parent")?)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl DirectoryIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
        }
    }
}

// Keep the original descriptors open for the whole observation. Metadata alone
// cannot prevent an unlinked inode number being reused for replacement state.
// CLOEXEC prevents the PAM helper from inheriting registry or shadow handles.
pub(crate) struct FilePin {
    path: PathBuf,
    file: File,
    parent: File,
    identity: FileIdentity,
    directory: DirectoryIdentity,
}

impl FilePin {
    pub(crate) fn descriptor(&self) -> Result<File> {
        self.recheck()?;
        Ok(self.file.try_clone()?)
    }
    fn open(path: &Path, limit: u64, private: bool, shadow: bool) -> Result<Self> {
        let parent_path = path.parent().ok_or("missing local identity directory")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)?;
        let directory = parent.metadata()?;
        if !directory.is_dir()
            || directory.uid() != 0
            || directory.mode() & if private { 0o077 } else { 0o022 } != 0
        {
            return Err("unsafe local identity directory".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
            || (shadow && metadata.mode() & 0o007 != 0)
            || metadata.len() == 0
            || metadata.len() > limit
        {
            return Err("unsafe or oversized local identity state".into());
        }
        let pin = Self {
            path: path.into(),
            file,
            parent,
            identity: FileIdentity::of(&metadata),
            directory: DirectoryIdentity::of(&directory),
        };
        pin.recheck()?;
        Ok(pin)
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        if FileIdentity::of(&self.file.metadata()?) != self.identity
            || FileIdentity::of(&fs::symlink_metadata(&self.path)?) != self.identity
            || DirectoryIdentity::of(&self.parent.metadata()?) != self.directory
            || DirectoryIdentity::of(&fs::symlink_metadata(
                self.path
                    .parent()
                    .ok_or("missing local identity directory")?,
            )?) != self.directory
        {
            return Err("local identity state replaced or changed; authenticate again".into());
        }
        Ok(())
    }

    fn complete_read(&mut self) -> Result<()> {
        let mut excess = [0];
        if self.file.read(&mut excess)? != 0 {
            return Err("local identity state grew during observation".into());
        }
        self.recheck()
    }
}

fn registry_observation(path: &Path) -> Result<(Registry, FilePin)> {
    let mut pin = FilePin::open(path, MAX_REGISTRY_BYTES, true, false)?;
    let mut bytes = vec![0; pin.identity.length as usize];
    pin.file.read_exact(&mut bytes)?;
    pin.complete_read()?;
    let registry = serde_json::from_slice(&bytes)?;
    validate(&registry)?;
    Ok((registry, pin))
}

fn registry(path: &Path) -> Result<Registry> {
    Ok(registry_observation(path)?.0)
}

pub(crate) fn registry_file(path: &Path) -> Result<(Vec<u8>, FilePin)> {
    let (bytes, pin) = private_document(path, MAX_REGISTRY_BYTES)?;
    let registry: Registry = serde_json::from_slice(&bytes)?;
    registry.validate()?;
    Ok((bytes, pin))
}

pub(crate) fn private_document(path: &Path, limit: u64) -> Result<(Vec<u8>, FilePin)> {
    let mut pin = FilePin::open(path, limit, true, false)?;
    let mut bytes = vec![0; pin.identity.length as usize];
    pin.file.read_exact(&mut bytes)?;
    pin.complete_read()?;
    Ok((bytes, pin))
}

/// A pinned inert registry observation, not authentication or an authority token.
/// The Admin adapter must independently bind its snapshot into verified TPM
/// history and recheck the same observation at its final writer boundary.
pub(crate) struct RegistryBinding {
    path: PathBuf,
    snapshot: Registry,
    pin: FilePin,
    fenced: Cell<bool>,
}

impl RegistryBinding {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let (snapshot, pin) = registry_observation(path)?;
        Ok(Self {
            path: path.into(),
            snapshot,
            pin,
            fenced: Cell::new(false),
        })
    }

    pub(crate) fn current(&self) -> Result<&Registry> {
        if self.fenced.get() {
            return Err("principal registry observation is fenced".into());
        }
        let result = (|| {
            self.pin.recheck()?;
            if registry(&self.path)? != self.snapshot {
                return Err("principal registry changed during governance".into());
            }
            self.pin.recheck()?;
            Ok(&self.snapshot)
        })();
        if result.is_err() {
            self.fenced.set(true);
        }
        result
    }
}

pub(crate) fn installation_at(path: &Path) -> Result<String> {
    Ok(registry(path)?.installation)
}

pub(crate) fn account_file(path: &Path, shadow: bool) -> Result<(PrivateBuffer, FilePin)> {
    let mut pin = FilePin::open(path, MAX_ACCOUNT_BYTES as u64, false, shadow)?;
    // Shadow contents never enter a pageable Vec/String or diagnostic. The
    // existing locked, nondumpable buffer wipes itself on every return path.
    let mut bytes = PrivateBuffer::new(pin.identity.length as usize)?;
    pin.file.read_exact(bytes.bytes_mut())?;
    pin.complete_read()?;
    Ok((bytes, pin))
}

fn account_observation(identity: &Path, principal: &Principal) -> Result<([u8; 32], [FilePin; 2])> {
    let (passwd, passwd_pin) = account_file(&identity.join("passwd"), false)?;
    let (shadow, shadow_pin) = account_file(&identity.join("shadow"), true)?;
    let digest = account_rows_digest(passwd.bytes(), shadow.bytes(), principal, false)?;
    passwd_pin.recheck()?;
    shadow_pin.recheck()?;
    Ok((digest, [passwd_pin, shadow_pin]))
}

pub(crate) fn account_rows_digest(
    passwd: &[u8],
    shadow: &[u8],
    principal: &Principal,
    allow_locked: bool,
) -> Result<[u8; 32]> {
    let passwd_text = std::str::from_utf8(passwd).map_err(|_| "invalid local account encoding")?;
    let shadow_text = std::str::from_utf8(shadow).map_err(|_| "invalid local account encoding")?;
    let mut account = None;
    let mut matching_uid = 0;
    for row in passwd_text.lines() {
        let fields: Vec<&str> = row.split(':').collect();
        if fields.len() != 7 {
            return Err("invalid local passwd record".into());
        }
        let uid: u32 = fields[2].parse().map_err(|_| "invalid local account uid")?;
        if uid == principal.uid {
            matching_uid += 1;
        }
        if fields[0] == principal.login {
            if account.is_some()
                || uid != principal.uid
                || fields[1] != "x"
                || !matches!(fields[6], "/bin/bash" | "/bin/sh")
                || fields[5] != format!("/home/{}", principal.login)
            {
                return Err("local principal/account identity mismatch".into());
            }
            let _: u32 = fields[3].parse().map_err(|_| "invalid local account gid")?;
            account = Some(row);
        }
    }
    if matching_uid != 1 {
        return Err("missing or ambiguous local uid".into());
    }
    let mut credential = None;
    for row in shadow_text.lines() {
        let fields: Vec<&str> = row.split(':').collect();
        if fields.len() != 9 {
            return Err("invalid local shadow record".into());
        }
        if fields[0] == principal.login {
            if credential.is_some()
                || fields[1].is_empty()
                || (!allow_locked && fields[1].starts_with('!'))
                || fields[1].starts_with('*')
            {
                return Err("missing, locked or ambiguous local credential".into());
            }
            credential = Some(row);
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-local-account-observation-v1\0");
    digest.update(account.ok_or("missing local account")?.as_bytes());
    digest.update(b"\0");
    digest.update(credential.ok_or("missing local credential")?.as_bytes());
    Ok(digest.finalize().into())
}

pub(crate) fn rows_commitment(
    installation: &str,
    principal: &Principal,
    digest: [u8; 32],
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"luma-account-credential-checkpoint-v1\0");
    hash.update(crate::tpm::decode::<32>(installation)?);
    hash.update(crate::tpm::decode::<32>(&principal.id)?);
    hash.update(principal.uid.to_be_bytes());
    hash.update(digest);
    Ok(bundle::hex(&hash.finalize()))
}

/// Nonserializable account observation. It is NOT evidence of PAM success;
/// only authentication.rs may combine it with a successful PAM exchange.
pub(crate) struct AccountBinding {
    registry_path: PathBuf,
    identity: PathBuf,
    installation: String,
    principal: Principal,
    account_digest: [u8; 32],
    pins: [FilePin; 3],
    invalidated: Cell<bool>,
}

impl AccountBinding {
    // A commitment to the protected rows, not a password hash, PAM result or
    // capability. Installation/principal separation prevents cross-user replay.
    pub(crate) fn credential_commitment(&self) -> Result<String> {
        self.current_uid()?;
        let commitment = rows_commitment(&self.installation, &self.principal, self.account_digest)?;
        self.current_uid()?;
        Ok(commitment)
    }

    /// Inert identity projection, never proof of authentication or a role grant.
    pub(crate) fn identity(&self) -> Result<serde_json::Value> {
        self.current_uid()?;
        Ok(serde_json::json!({"installation":self.installation,
            "principal":self.principal.id,"generation":self.principal.generation,
            "login":self.principal.login,"uid":self.principal.uid}))
    }

    pub fn capture(registry_path: &Path, identity: &Path, name: &str) -> Result<Self> {
        let (registry, registry_pin) = registry_observation(registry_path)?;
        let principal = registry
            .principals
            .iter()
            .find(|p| p.login == name && p.enabled)
            .ok_or("local principal is missing or disabled")?
            .clone();
        let (digest, [passwd_pin, shadow_pin]) = account_observation(identity, &principal)?;
        let binding = Self {
            registry_path: registry_path.into(),
            identity: identity.into(),
            installation: registry.installation,
            principal,
            account_digest: digest,
            pins: [registry_pin, passwd_pin, shadow_pin],
            invalidated: Cell::new(false),
        };
        binding.recheck_pins()?;
        Ok(binding)
    }

    pub fn current_uid(&self) -> Result<u32> {
        if self.invalidated.get() {
            return Err("local authentication observation was invalidated".into());
        }
        let result = self.revalidate();
        if result.is_err() {
            self.invalidated.set(true);
        }
        result
    }

    fn revalidate(&self) -> Result<u32> {
        self.recheck_pins()?;
        let current = registry(&self.registry_path)?;
        if current.installation != self.installation
            || !current
                .principals
                .iter()
                .any(|p| p == &self.principal && p.enabled)
            || account_observation(&self.identity, &self.principal)?.0 != self.account_digest
        {
            return Err("local principal or credential changed; authenticate again".into());
        }
        self.recheck_pins()?;
        Ok(self.principal.uid)
    }

    fn recheck_pins(&self) -> Result<()> {
        for pin in &self.pins {
            pin.recheck()?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub fn initialize(directory: &Path, accounts: &[(&str, u32)]) -> Result<()> {
    initialize_at(directory, accounts, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("luma-principal-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join("identity"))
                .unwrap();
            for (file, bytes) in [
                ("passwd", "human:x:1001:1001:Human:/home/human:/bin/bash\n"),
                ("shadow", "human:$6$public$fixture:20000:0:99999:7:::\n"),
            ] {
                crate::platform::write_atomic(
                    &root.join("identity").join(file),
                    bytes.as_bytes(),
                    0o600,
                )
                .unwrap();
            }
            initialize(&root.join("principals"), &[("human", 1001)]).unwrap();
            Self(root)
        }
        fn path(&self) -> PathBuf {
            self.0.join("principals/registry.json")
        }
        fn binding(&self) -> AccountBinding {
            AccountBinding::capture(&self.path(), &self.0.join("identity"), "human").unwrap()
        }
        fn change(&self, edit: impl FnOnce(&mut Registry)) {
            let mut value = registry(&self.path()).unwrap();
            edit(&mut value);
            crate::platform::write_atomic(
                &self.path(),
                &serde_json::to_vec(&value).unwrap(),
                0o600,
            )
            .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for directory in [self.0.join("identity"), self.0.join("principals")] {
                for entry in fs::read_dir(&directory).unwrap() {
                    fs::remove_file(entry.unwrap().path()).unwrap();
                }
                fs::remove_dir(directory).unwrap();
            }
            fs::remove_dir(&self.0).unwrap();
        }
    }

    #[test]
    fn credential_commitments_separate_installations_principals_and_exact_rows() {
        let fixture = Fixture::new("credential-commitment");
        let binding = fixture.binding();
        let first = binding.credential_commitment().unwrap();
        assert_eq!(first.len(), 64);
        assert!(!first.contains("$6$"));
        assert_eq!(first, fixture.binding().credential_commitment().unwrap());
        fixture.change(|registry| registry.installation = "ab".repeat(32));
        assert!(binding.credential_commitment().is_err());
        let second = fixture.binding().credential_commitment().unwrap();
        assert_ne!(first, second);
        fixture.change(|registry| registry.principals[0].id = "cd".repeat(32));
        let third = fixture.binding().credential_commitment().unwrap();
        assert_ne!(second, third);
        let shadow = fixture.0.join("identity/shadow");
        crate::platform::write_atomic(&shadow, b"human:$6$public$new:20000:0:99999:7:::\n", 0o600)
            .unwrap();
        assert_ne!(third, fixture.binding().credential_commitment().unwrap());
    }

    #[test]
    fn registry_checkpoint_observation_is_pinned_and_sticky_after_restoration() {
        let fixture = Fixture::new("registry-checkpoint-pin");
        let binding = RegistryBinding::capture(&fixture.path()).unwrap();
        let original = binding.current().unwrap().clone();
        crate::platform::write_atomic(
            &fixture.path(),
            &serde_json::to_vec(&original).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(binding.current().is_err());
        assert_eq!(
            RegistryBinding::capture(&fixture.path())
                .unwrap()
                .current()
                .unwrap(),
            &original
        );
        assert!(binding.current().is_err());
    }

    #[test]
    fn registry_binding_requires_exact_enabled_installation_principal_generation_and_account() {
        let fixture = Fixture::new("registry-exact-identity");
        let mut registry = registry(&fixture.path()).unwrap();
        let principal = registry.principals[0].clone();
        let binds = |registry: &Registry| {
            registry.binds(
                &registry.installation,
                &principal.id,
                principal.generation,
                &principal.login,
                principal.uid,
            )
        };
        assert!(binds(&registry));
        assert!(!registry.binds(
            &"ab".repeat(32),
            &principal.id,
            principal.generation,
            &principal.login,
            principal.uid
        ));
        assert!(!registry.binds(
            &registry.installation,
            &"ab".repeat(32),
            principal.generation,
            &principal.login,
            principal.uid
        ));
        assert!(!registry.binds(
            &registry.installation,
            &principal.id,
            2,
            &principal.login,
            principal.uid
        ));
        assert!(!registry.binds(
            &registry.installation,
            &principal.id,
            principal.generation,
            "other",
            principal.uid
        ));
        assert!(!registry.binds(
            &registry.installation,
            &principal.id,
            principal.generation,
            &principal.login,
            1002
        ));
        registry.principals[0].enabled = false;
        assert!(!binds(&registry));
    }

    #[test]
    fn installation_ids_are_random_stable_private_and_never_silently_reset() {
        let a = Fixture::new("installation-a");
        let b = Fixture::new("installation-b");
        let first = registry(&a.path()).unwrap();
        let other = registry(&b.path()).unwrap();
        assert_ne!(first.installation, other.installation);
        assert_ne!(first.principals[0].id, other.principals[0].id);
        assert_eq!(a.binding().current_uid().unwrap(), 1001);
        assert_eq!(fs::metadata(a.path()).unwrap().mode() & 0o777, 0o600);
        assert!(initialize(&a.0.join("principals"), &[("human", 1001)]).is_err());
        fs::remove_file(a.path()).unwrap();
        assert!(AccountBinding::capture(&a.path(), &a.0.join("identity"), "human").is_err());
        assert!(!a.path().exists());
    }

    #[test]
    fn fresh_installer_verifier_is_bound_and_legacy_installations_have_no_recovery_fallback() {
        let fixture = Fixture::new("installer-recovery");
        let legacy = registry(&fixture.path()).unwrap();
        assert!(legacy.recovery_verifier().is_none());
        assert!(serde_json::to_value(&legacy)
            .unwrap()
            .get("admin_recovery")
            .is_none());
        let credential = crate::admin_recovery::Credential::fixture(0x42);
        let directory = fixture.0.join("recovery-principals");
        initialize_with_recovery(&directory, &[("user", 1000), ("human", 1001)], &credential)
            .unwrap();
        let installed = registry(&directory.join("registry.json")).unwrap();
        let verifier = installed.recovery_verifier().unwrap();
        verifier
            .validate(
                installed.installation(),
                &installed.bootstrap_admin().unwrap().id,
            )
            .unwrap();
        verifier.verify(&credential).unwrap();
        assert_eq!(verifier.generation, 1);
        assert!(initialize_with_recovery(&directory, &[("human", 1001)], &credential).is_err());
        let mut wrong = installed.clone();
        wrong.principals[1].id = "cd".repeat(32);
        assert!(wrong.validate().is_err());
        let mut wrong = installed.clone();
        wrong.principals[1].enabled = false;
        assert!(wrong.validate().is_err());
        let mut wrong = serde_json::to_value(&installed).unwrap();
        wrong["admin_recovery"]["generation"] = serde_json::json!(2);
        assert!(serde_json::from_value::<Registry>(wrong)
            .unwrap()
            .validate()
            .is_err());
        assert!(!fs::read_to_string(directory.join("registry.json"))
            .unwrap()
            .contains(&"42".repeat(32)));
        fs::remove_file(directory.join("registry.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn disable_generation_principal_and_installation_changes_revoke_observation() {
        let fixture = Fixture::new("generation");
        let original = fs::read(fixture.path()).unwrap();
        for choice in 0..4 {
            crate::platform::write_atomic(&fixture.path(), &original, 0o600).unwrap();
            let bound = fixture.binding();
            fixture.change(|r| match choice {
                0 => r.principals[0].enabled = false,
                1 => r.principals[0].generation += 1,
                2 => r.principals[0].id = "aa".repeat(32),
                _ => r.installation = "bb".repeat(32),
            });
            assert!(bound.current_uid().is_err());
        }
    }

    #[test]
    fn identical_registry_passwd_and_shadow_replacement_requires_fresh_binding() {
        let fixture = Fixture::new("identical-replacement");
        for path in [
            fixture.path(),
            fixture.0.join("identity/passwd"),
            fixture.0.join("identity/shadow"),
        ] {
            let binding = fixture.binding();
            let original = fs::read(&path).unwrap();
            crate::platform::write_atomic(&path, &original, 0o600).unwrap();
            assert!(binding.current_uid().is_err());
            assert!(binding.identity().is_err());
            assert_eq!(fixture.binding().current_uid().unwrap(), 1001);
            crate::platform::write_atomic(&path, &original, 0o600).unwrap();
            assert!(binding.current_uid().is_err());
        }
    }

    #[test]
    fn pinned_metadata_detects_restored_in_place_bytes_and_permissions() {
        let fixture = Fixture::new("restored-in-place");
        for path in [
            fixture.path(),
            fixture.0.join("identity/passwd"),
            fixture.0.join("identity/shadow"),
        ] {
            let binding = fixture.binding();
            let original = fs::read(&path).unwrap();
            let inode = fs::metadata(&path).unwrap().ino();
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            file.write_all(&vec![b'x'; original.len()]).unwrap();
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&original).unwrap();
            file.sync_all().unwrap();
            // Force a distinct visible timestamp without relying on the test
            // filesystem's clock resolution or a scheduling delay.
            let metadata = file.metadata().unwrap();
            let times = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: metadata.mtime() + 1,
                    tv_nsec: 0,
                },
            ];
            assert_eq!(
                unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
                0
            );
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert!(binding.current_uid().is_err());
            assert_eq!(fixture.binding().current_uid().unwrap(), 1001);
            let fresh = fixture.binding();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(fresh.current_uid().is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(fresh.current_uid().is_err());
        }
    }

    #[test]
    fn parent_replacement_cannot_transfer_authority_by_reusing_the_same_files() {
        let fixture = Fixture::new("parent-replacement");
        for directory in [fixture.0.join("principals"), fixture.0.join("identity")] {
            let binding = fixture.binding();
            let retained = fixture.0.join("retained-directory");
            fs::rename(&directory, &retained).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            for entry in fs::read_dir(&retained).unwrap() {
                let entry = entry.unwrap();
                fs::rename(entry.path(), directory.join(entry.file_name())).unwrap();
            }
            assert!(binding.current_uid().is_err());
            assert_eq!(fixture.binding().current_uid().unwrap(), 1001);
            fs::remove_dir(&directory).unwrap_err(); // State must still be retained.
            fs::remove_dir(&retained).unwrap();
            assert!(binding.current_uid().is_err());
        }
    }

    #[test]
    fn descriptors_are_cloexec_and_rechecks_bind_names_not_just_open_files() {
        let fixture = Fixture::new("descriptor-pins");
        let binding = fixture.binding();
        for pin in &binding.pins {
            for descriptor in [&pin.file, &pin.parent] {
                let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
                assert!(flags >= 0);
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
            }
            pin.recheck().unwrap();
        }
        let path = fixture.0.join("identity/shadow");
        let (_, pin) = account_file(&path, true).unwrap();
        let retained = fixture.0.join("identity/retained-shadow");
        fs::rename(&path, &retained).unwrap();
        crate::platform::write_atomic(&path, &fs::read(&retained).unwrap(), 0o600).unwrap();
        assert!(pin.recheck().is_err());
        assert!(binding.current_uid().is_err());
        assert_eq!(fixture.binding().current_uid().unwrap(), 1001);
        fs::remove_file(&path).unwrap();
        fs::rename(&retained, &path).unwrap();
        assert!(binding.current_uid().is_err());
    }

    #[test]
    fn unrelated_directory_entries_do_not_revoke_an_unchanged_binding() {
        let fixture = Fixture::new("unrelated-directory-entry");
        let binding = fixture.binding();
        for directory in [fixture.0.join("principals"), fixture.0.join("identity")] {
            let path = directory.join("unrelated");
            crate::platform::write_atomic(&path, b"not account authority", 0o600).unwrap();
            assert_eq!(binding.current_uid().unwrap(), 1001);
            fs::remove_file(path).unwrap();
            assert_eq!(binding.current_uid().unwrap(), 1001);
        }
    }

    #[test]
    fn credential_rotation_lock_and_account_substitution_revoke_observation() {
        let fixture = Fixture::new("credentials");
        let shadow = fixture.0.join("identity/shadow");
        let original = fs::read(&shadow).unwrap();
        for bytes in [
            b"human:$6$public$changed:20000:0:99999:7:::\n".as_slice(),
            b"human:!$6$public$fixture:20000:0:99999:7:::\n",
            b"human:$6$public$fixture:20001:0:99999:7:::\n",
        ] {
            crate::platform::write_atomic(&shadow, &original, 0o600).unwrap();
            let bound = fixture.binding();
            crate::platform::write_atomic(&shadow, bytes, 0o600).unwrap();
            assert!(bound.current_uid().is_err());
        }
        crate::platform::write_atomic(&shadow, &original, 0o600).unwrap();
        let bound = fixture.binding();
        crate::platform::write_atomic(
            &fixture.0.join("identity/passwd"),
            b"human:x:1001:1001:Human:/home/other:/bin/bash\n",
            0o600,
        )
        .unwrap();
        assert!(bound.current_uid().is_err());
    }

    #[test]
    fn duplicate_local_uid_and_shadow_identity_are_refused() {
        let fixture = Fixture::new("duplicates");
        let passwd = fixture.0.join("identity/passwd");
        let original = fs::read(&passwd).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"another:x:1001:1001:Alias:/home/another:/bin/bash\n");
        crate::platform::write_atomic(&passwd, &changed, 0o600).unwrap();
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
        crate::platform::write_atomic(&passwd, &original, 0o600).unwrap();
        let shadow = fixture.0.join("identity/shadow");
        let bytes = fs::read(&shadow).unwrap();
        crate::platform::write_atomic(&shadow, &[bytes.clone(), bytes].concat(), 0o600).unwrap();
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
    }

    #[test]
    fn unsafe_linked_public_and_oversized_account_state_is_refused() {
        let fixture = Fixture::new("unsafe");
        let bound = fixture.binding();
        let shadow = fixture.0.join("identity/shadow");
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(bound.current_uid().is_err());
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&shadow, fixture.0.join("identity/alias")).unwrap();
        assert!(bound.current_uid().is_err());
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
        fs::remove_file(fixture.0.join("identity/alias")).unwrap();
        fs::rename(&shadow, fixture.0.join("identity/original")).unwrap();
        symlink(fixture.0.join("identity/original"), &shadow).unwrap();
        assert!(bound.current_uid().is_err());
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
        fs::remove_file(&shadow).unwrap();
        crate::platform::write_atomic(&shadow, &vec![b'x'; MAX_ACCOUNT_BYTES + 1], 0o600).unwrap();
        assert!(bound.current_uid().is_err());
        assert!(
            AccountBinding::capture(&fixture.path(), &fixture.0.join("identity"), "human").is_err()
        );
    }

    #[test]
    fn closed_registry_rejects_unknown_fields_duplicates_and_invalid_principals() {
        let fixture = Fixture::new("schema");
        let bytes = fs::read_to_string(fixture.path()).unwrap();
        for changed in [
            bytes.replacen('{', "{\"role\":\"Admin\",", 1),
            bytes.replacen('{', "{\"schema_version\":1,", 1),
        ] {
            assert!(serde_json::from_str::<Registry>(&changed).is_err());
        }
        for uid in [0, 990, 65534] {
            let mut value: Registry = serde_json::from_str(&bytes).unwrap();
            value.principals[0].uid = uid;
            assert!(validate(&value).is_err());
        }
        let mut value: Registry = serde_json::from_str(&bytes).unwrap();
        value.principals.push(value.principals[0].clone());
        assert!(validate(&value).is_err());
        value.principals.pop();
        value.principals[0].generation = 0;
        assert!(validate(&value).is_err());
    }
}
