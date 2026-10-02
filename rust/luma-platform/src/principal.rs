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

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Principal {
    id: String,
    generation: u64,
    login: String,
    uid: u32,
    enabled: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: u32,
    installation: String,
    principals: Vec<Principal>,
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
    Ok(())
}

fn random_id() -> Result<String> {
    let mut random = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(bundle::hex(&random))
}

/// Fresh installation only; never reset a missing registry during runtime.
pub fn initialize(directory: &Path, accounts: &[(&str, u32)]) -> Result<()> {
    crate::require_root()?;
    let mut registry = Registry {
        schema_version: 1,
        installation: random_id()?,
        principals: vec![],
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

fn registry(path: &Path) -> Result<Registry> {
    let result = serde_json::from_slice(&tpm::private_read(path, MAX_REGISTRY_BYTES)?)?;
    validate(&result)?;
    Ok(result)
}

fn account_file(path: &Path, shadow: bool) -> Result<PrivateBuffer> {
    let parent = fs::symlink_metadata(path.parent().ok_or("missing identity directory")?)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("unsafe local identity directory".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || (shadow && before.mode() & 0o007 != 0)
        || before.len() == 0
        || before.len() > MAX_ACCOUNT_BYTES as u64
    {
        return Err("unsafe or oversized local account database".into());
    }
    // Shadow contents never enter a pageable Vec/String or diagnostic. The
    // existing locked, nondumpable buffer wipes itself on every return path.
    let mut bytes = PrivateBuffer::new(before.len() as usize)?;
    file.read_exact(bytes.bytes_mut())?;
    let mut excess = [0];
    if file.read(&mut excess)? != 0 {
        return Err("local account database grew during observation".into());
    }
    let after = file.metadata()?;
    if (
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err("local account database changed during observation".into());
    }
    Ok(bytes)
}

fn account_digest(identity: &Path, principal: &Principal) -> Result<[u8; 32]> {
    let passwd = account_file(&identity.join("passwd"), false)?;
    let shadow = account_file(&identity.join("shadow"), true)?;
    let passwd_text =
        std::str::from_utf8(passwd.bytes()).map_err(|_| "invalid local account encoding")?;
    let shadow_text =
        std::str::from_utf8(shadow.bytes()).map_err(|_| "invalid local account encoding")?;
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
                || fields[1].starts_with('!')
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

/// Nonserializable account observation. It is NOT evidence of PAM success;
/// only authentication.rs may combine it with a successful PAM exchange.
pub(crate) struct AccountBinding {
    registry_path: PathBuf,
    identity: PathBuf,
    installation: String,
    principal: Principal,
    account_digest: [u8; 32],
    invalidated: Cell<bool>,
}

impl AccountBinding {
    /// Inert identity projection, never proof of authentication or a role grant.
    pub(crate) fn identity(&self) -> Result<serde_json::Value> {
        self.current_uid()?;
        Ok(serde_json::json!({"installation":self.installation,
            "principal":self.principal.id,"generation":self.principal.generation,
            "login":self.principal.login,"uid":self.principal.uid}))
    }

    pub fn capture(registry_path: &Path, identity: &Path, name: &str) -> Result<Self> {
        let registry = registry(registry_path)?;
        let principal = registry
            .principals
            .iter()
            .find(|p| p.login == name && p.enabled)
            .ok_or("local principal is missing or disabled")?
            .clone();
        let digest = account_digest(identity, &principal)?;
        Ok(Self {
            registry_path: registry_path.into(),
            identity: identity.into(),
            installation: registry.installation,
            principal,
            account_digest: digest,
            invalidated: Cell::new(false),
        })
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
        let current = registry(&self.registry_path)?;
        if current.installation != self.installation
            || !current
                .principals
                .iter()
                .any(|p| p == &self.principal && p.enabled)
            || account_digest(&self.identity, &self.principal)? != self.account_digest
        {
            return Err("local principal or credential changed; authenticate again".into());
        }
        Ok(self.principal.uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
