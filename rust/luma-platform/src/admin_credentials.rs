//! Fixed-path native sealed delivery for the local checkpoint.
//! Configuration is inert metadata; the image-owned PCR key, signed boot policy,
//! authenticated TPM unsealing and NV authentication establish the boundary.
use crate::{bundle, owner_credential, sealed_credential::Secret, tpm, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/admin";
pub(crate) const PUBLIC_KEY: &str = "/usr/share/luma-os/admin-pcr-public.pem";
pub(crate) const BOOT_SIGNATURE: &str = "/run/systemd/tpm2-pcr-signature.json";

pub(crate) fn prepared(
    deployment: &str,
    parent_name: &[u8; 34],
    public: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":3,
        "profile":tpm::PROFILE,"index":0x01804c41u32,
        "nv_name":bundle::hex(&tpm::checkpoint_name()),"parent_name":bundle::hex(parent_name),
        "deployment":deployment,
        "pcr_public_key_sha256":bundle::hex(&Sha256::digest(public)),
        "sealed_credential_sha256":bundle::hex(&Sha256::digest(blob))}))?;
    configuration(&bytes)?;
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema_version: u32,
    profile: String,
    pub(crate) index: u32,
    pub(crate) nv_name: String,
    pub(crate) parent_name: String,
    pub(crate) deployment: String,
    pcr_public_key_sha256: String,
    sealed_credential_sha256: String,
}

fn configuration(bytes: &[u8]) -> Result<Configuration> {
    let config: Configuration = serde_json::from_slice(bytes)?;
    if config.schema_version != 3 || config.profile != tpm::PROFILE || config.index != 0x01804c41 {
        return Err(
            "native sealed local Admin configuration v3 required; no legacy fallback".into(),
        );
    }
    let name = tpm::decode::<34>(&config.nv_name)?;
    if name[..2] != [0, 0x0b] {
        return Err("invalid Admin NV Name algorithm".into());
    }
    if name != tpm::checkpoint_name() || tpm::decode::<34>(&config.parent_name)?[..2] != [0, 0x0b] {
        return Err("checkpoint or credential parent Name differs from enrolled profile".into());
    }
    tpm::decode::<32>(&config.deployment)?;
    tpm::decode::<32>(&config.pcr_public_key_sha256)?;
    tpm::decode::<32>(&config.sealed_credential_sha256)?;
    Ok(config)
}

/// Public inputs are not secrets, but neither may be replaced by a writable
/// file, symlink, hard link or a caller-selected key. The helper authenticates
/// the signature; root ownership alone does not make signature bytes valid.
pub(crate) fn public_input(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let parent = fs::symlink_metadata(path.parent().ok_or("missing public input parent")?)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("unsafe Admin public input directory".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > limit
    {
        return Err("unsafe or oversized Admin public input".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || after.nlink() != 1
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Admin public input changed during read".into());
    }
    Ok(bytes)
}

pub(crate) fn load_at<F>(
    directory: &Path,
    public_path: &Path,
    signature_path: &Path,
    decrypt: F,
) -> Result<(Configuration, Secret)>
where
    F: FnOnce(&str, &[u8; 34], &[u8], &[u8], &[u8]) -> Result<Secret>,
{
    let config_path = directory.join("anchor.json");
    let config_bytes = tpm::private_read(&config_path, 4096)?;
    let config = configuration(&config_bytes)?;
    let public = public_input(public_path, 4096)?;
    let blob = tpm::private_read(&directory.join("nv-auth.cred"), 16 * 1024)?;
    let stored_parent = tpm::private_read(&directory.join("parent.name"), 34)?;
    let signature = public_input(signature_path, 16 * 1024)?;
    if blob.is_empty()
        || bundle::hex(&Sha256::digest(&public)) != config.pcr_public_key_sha256
        || bundle::hex(&Sha256::digest(&blob)) != config.sealed_credential_sha256
        || stored_parent != tpm::decode::<34>(&config.parent_name)?
    {
        return Err("Admin sealed credential or image PCR signer digest mismatch".into());
    }
    let parent_name = tpm::decode::<34>(&config.parent_name)?;
    let secret = decrypt(&config.deployment, &parent_name, &public, &blob, &signature)?;
    // Do not accept a different enrollment/boot-policy snapshot after a slow
    // helper invocation. All plaintext remains in Secret's locked mapping.
    if tpm::private_read(&config_path, 4096)? != config_bytes
        || tpm::private_read(&directory.join("nv-auth.cred"), 16 * 1024)? != blob
        || tpm::private_read(&directory.join("parent.name"), 34)? != stored_parent
        || public_input(public_path, 4096)? != public
        || public_input(signature_path, 16 * 1024)? != signature
    {
        return Err("Admin sealed delivery inputs changed; retry only after review".into());
    }
    Ok((config, secret))
}

pub(crate) fn load() -> Result<(Configuration, Secret)> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    load_at(
        Path::new(DIRECTORY),
        Path::new(PUBLIC_KEY),
        Path::new(BOOT_SIGNATURE),
        owner_credential::unseal,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{platform, sealed_credential};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn fixture(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("luma-credentials-{label}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        platform::write_atomic(&dir.join("key.pem"), b"public fixture", 0o644).unwrap();
        platform::write_atomic(&dir.join("signature.json"), b"signed fixture", 0o644).unwrap();
        platform::write_atomic(&dir.join("nv-auth.cred"), b"ciphertext fixture", 0o600).unwrap();
        platform::write_atomic(
            &dir.join("parent.name"),
            &tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap(),
            0o600,
        )
        .unwrap();
        let config = serde_json::json!({"schema_version":3,"profile":"local-tpm2",
            "index":0x01804c41u32,"nv_name":bundle::hex(&tpm::checkpoint_name()),
            "parent_name":format!("000b{}", "22".repeat(32)),
            "deployment":"ab".repeat(32),
            "pcr_public_key_sha256":bundle::hex(&Sha256::digest(b"public fixture")),
            "sealed_credential_sha256":bundle::hex(&Sha256::digest(b"ciphertext fixture"))});
        platform::write_atomic(
            &dir.join("anchor.json"),
            &serde_json::to_vec(&config).unwrap(),
            0o600,
        )
        .unwrap();
        dir
    }
    fn cleanup(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }
    fn load_fixture<F>(dir: &Path, decrypt: F) -> Result<(Configuration, Secret)>
    where
        F: FnOnce(&str, &[u8; 34], &[u8], &[u8], &[u8]) -> Result<Secret>,
    {
        load_at(
            dir,
            &dir.join("key.pem"),
            &dir.join("signature.json"),
            decrypt,
        )
    }
    fn unopened(_: &str, _: &[u8; 34], _: &[u8], _: &[u8], _: &[u8]) -> Result<Secret> {
        panic!("invalid input must not invoke decrypt")
    }

    #[test]
    fn exact_inputs_delivered_without_plaintext_file() {
        let dir = fixture("inputs");
        let (config, secret) = load_fixture(&dir, |deployment, parent, public, blob, signature| {
            assert_eq!(deployment, "ab".repeat(32));
            assert_eq!(
                *parent,
                tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap()
            );
            assert_eq!(public, b"public fixture");
            assert_eq!(blob, b"ciphertext fixture");
            assert_eq!(signature, b"signed fixture");
            Secret::generate()
        })
        .unwrap();
        assert_eq!(config.index, 0x01804c41);
        assert_eq!(secret.bytes().len(), 32);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 5);
        cleanup(&dir);
    }

    #[test]
    fn closed_configuration_rejects_legacy_and_substitution() {
        let dir = fixture("config");
        let path = dir.join("anchor.json");
        let initial = fs::read(&path).unwrap();
        for (field, value) in [
            ("schema_version", serde_json::json!(1)),
            ("profile", serde_json::json!("external")),
            ("index", serde_json::json!(0x01804c42u32)),
            ("deployment", serde_json::json!("../bad")),
            ("nv_name", serde_json::json!("00".repeat(34))),
            ("parent_name", serde_json::json!("00".repeat(34))),
            ("credential_path", serde_json::json!("/tmp/plaintext")),
            (
                "sealed_credential_sha256",
                serde_json::json!("00".repeat(32)),
            ),
            ("pcr_public_key_sha256", serde_json::json!("00".repeat(32))),
        ] {
            let mut value_map: serde_json::Value = serde_json::from_slice(&initial).unwrap();
            value_map[field] = value;
            platform::write_atomic(&path, &serde_json::to_vec(&value_map).unwrap(), 0o600).unwrap();
            assert!(load_fixture(&dir, unopened).is_err(), "{field}");
        }
        let duplicate =
            String::from_utf8(initial)
                .unwrap()
                .replacen('{', "{\"schema_version\":3,", 1);
        platform::write_atomic(&path, duplicate.as_bytes(), 0o600).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        cleanup(&dir);
    }

    #[test]
    fn delivery_rechecks_every_input_after_helper_and_propagates_refusal() {
        let dir = fixture("changed");
        assert!(load_fixture(&dir, |_, _, _, _, _| Err("TPM refused".into())).is_err());
        for name in [
            "anchor.json",
            "key.pem",
            "signature.json",
            "nv-auth.cred",
            "parent.name",
        ] {
            let path = dir.join(name);
            let original = fs::read(&path).unwrap();
            assert!(load_fixture(&dir, |_, _, _, _, _| {
                let mut changed = original.clone();
                changed.push(b'\n');
                platform::write_atomic(&path, &changed, 0o600)?;
                Secret::generate()
            })
            .is_err());
            platform::write_atomic(&path, &original, 0o600).unwrap();
        }
        cleanup(&dir);
    }

    #[test]
    fn public_inputs_refuse_links_writes_empty_and_oversized_files() {
        let dir = fixture("unsafe");
        let path = dir.join("key.pem");
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let alias = dir.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        fs::remove_file(&alias).unwrap();
        fs::rename(&path, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &path).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&alias, &path).unwrap();
        for bytes in [vec![], vec![0; 4097]] {
            platform::write_atomic(&path, &bytes, 0o644).unwrap();
            assert!(load_fixture(&dir, unopened).is_err());
        }
        platform::write_atomic(&path, &original, 0o644).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(public_input(&path, 4096).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn missing_enrollment_inputs_never_use_plaintext_or_initialize_state() {
        let dir = fixture("missing");
        platform::write_atomic(&dir.join("nv-auth"), &[0x55; 32], 0o600).unwrap();
        for name in [
            "anchor.json",
            "nv-auth.cred",
            "parent.name",
            "key.pem",
            "signature.json",
        ] {
            let path = dir.join(name);
            let saved = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(load_fixture(&dir, unopened).is_err());
            assert!(!path.exists());
            assert_eq!(fs::read(dir.join("nv-auth")).unwrap(), [0x55; 32]);
            platform::write_atomic(&path, &saved, 0o600).unwrap();
        }
        let encrypted = dir.join("nv-auth.cred");
        fs::set_permissions(&encrypted, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        fs::set_permissions(&encrypted, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.join("alias");
        fs::hard_link(&encrypted, &alias).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        fs::remove_file(&alias).unwrap();
        fs::remove_file(&encrypted).unwrap();
        std::os::unix::fs::symlink(dir.join("nv-auth"), &encrypted).unwrap();
        assert!(load_fixture(&dir, unopened).is_err());
        cleanup(&dir);
    }

    #[test]
    #[ignore = "requires isolated signed-PCR credential-delivery fixture"]
    fn emulator_sealed_delivery() {
        let dir = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let mode = std::env::var("LUMA_TPM_TEST_DELIVERY").unwrap();
        let public_path = dir.join("pcr-public.pem");
        let signature_path = dir.join("pcr-signature.json");
        let public = public_input(&public_path, 4096).unwrap();
        let deployment = "ab".repeat(32);
        if mode == "seal" {
            let secret = Secret::generate().unwrap();
            let blob =
                sealed_credential::fixture_seal(&dir, &deployment, &public, &secret).unwrap();
            platform::write_atomic(&dir.join("nv-auth.cred"), &blob, 0o600).unwrap();
            platform::write_atomic(
                &dir.join("parent.name"),
                &tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap(),
                0o600,
            )
            .unwrap();
            let config = serde_json::json!({"schema_version":3,"profile":"local-tpm2",
                "index":0x01804c41u32,"nv_name":bundle::hex(&tpm::checkpoint_name()),
                "parent_name":format!("000b{}", "22".repeat(32)),
                "deployment":deployment,"pcr_public_key_sha256":bundle::hex(&Sha256::digest(&public)),
                "sealed_credential_sha256":bundle::hex(&Sha256::digest(&blob))});
            platform::write_atomic(
                &dir.join("anchor.json"),
                &serde_json::to_vec(&config).unwrap(),
                0o600,
            )
            .unwrap();
            // Public digest only; the random plaintext is never persisted even
            // in this fixture. Success modes compare the recovered secret.
            platform::write_atomic(
                &dir.join("secret.sha256"),
                bundle::hex(&Sha256::digest(secret.bytes())).as_bytes(),
                0o600,
            )
            .unwrap();
        }
        let result = load_at(
            &dir,
            &public_path,
            &signature_path,
            |deployment, _, public, blob, signature| {
                sealed_credential::fixture_unseal(&dir, deployment, public, blob, signature)
            },
        );
        match mode.as_str() {
            "seal" | "allow" => {
                let (_, secret) = result.unwrap();
                assert_eq!(
                    bundle::hex(&Sha256::digest(secret.bytes())).as_bytes(),
                    tpm::private_read(&dir.join("secret.sha256"), 64).unwrap()
                );
                assert_eq!(
                    fs::read_dir(&dir)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_name() == "nv-auth")
                        .count(),
                    0
                );
            }
            "deny" => assert!(result.is_err()),
            _ => panic!("unknown fixture mode"),
        }
        // No test transport can enter the installed product loader.
        assert!(load().is_err());
    }
}
