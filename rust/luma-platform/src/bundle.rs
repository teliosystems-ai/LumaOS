use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_MANIFEST: u64 = 65536;
const TRUST: &str = "/usr/share/luma-os/release.pub";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub release: String,
    pub sequence: u64,
    pub environment: String,
    pub architecture: String,
    pub ubuntu: String,
    pub edition: String,
    pub root_hash: String,
    pub root_bytes: u64,
    pub hash_bytes: u64,
    pub artifacts: Vec<Artifact>,
}

pub struct VerifiedBundle {
    pub manifest: Manifest,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) inert_trust: Option<Vec<u8>>,
    snapshot: crate::staging::Snapshot,
}

impl VerifiedBundle {
    pub fn path(&self, name: &str) -> Result<PathBuf> {
        if !self.manifest.artifacts.iter().any(|a| a.name == name) {
            return Err("artifact absent from signed inventory".into());
        }
        Ok(self.snapshot.path().join(name))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_manifest(m: &Manifest) -> Result<()> {
    if m.schema_version != 1
        || !matches!(m.environment.as_str(), "lab" | "production")
        || m.architecture != "amd64"
        || m.ubuntu != "24.04"
        || !matches!(m.edition.as_str(), "desktop" | "headless")
        || m.sequence == 0
        || m.sequence > i64::MAX as u64
        || m.release.is_empty()
        || m.release.len() > 64
        || !m
            .release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        || !is_hash(&m.root_hash)
        || m.root_bytes < 512 * 1024 * 1024
        || m.root_bytes > 32 * 1024 * 1024 * 1024
        || m.root_bytes % 4096 != 0
        || m.hash_bytes == 0
        || m.hash_bytes > 512 * 1024 * 1024
        || m.hash_bytes % 4096 != 0
    {
        return Err("invalid or unsupported release manifest".into());
    }
    let required: BTreeSet<&str> = [
        "root.ext4",
        "root.verity",
        "slot-a.efi",
        "slot-b.efi",
        "bootloader.efi",
        "secureboot.cer",
    ]
    .into_iter()
    .collect();
    let names: BTreeSet<&str> = m.artifacts.iter().map(|a| a.name.as_str()).collect();
    if m.artifacts.len() != required.len() || names != required {
        return Err("closed artifact inventory mismatch".into());
    }
    for a in &m.artifacts {
        let maximum = match a.name.as_str() {
            "root.ext4" => 32 * 1024 * 1024 * 1024,
            "root.verity" => 512 * 1024 * 1024,
            "slot-a.efi" | "slot-b.efi" => 256 * 1024 * 1024,
            "bootloader.efi" => 16 * 1024 * 1024,
            "secureboot.cer" => 16 * 1024,
            _ => return Err("unsupported release artifact".into()),
        };
        if a.bytes == 0 || a.bytes > maximum || !is_hash(&a.sha256) {
            return Err("invalid artifact bounds".into());
        }
        if (a.name == "root.ext4" && a.bytes != m.root_bytes)
            || (a.name == "root.verity" && a.bytes != m.hash_bytes)
        {
            return Err("root geometry mismatch".into());
        }
    }
    Ok(())
}

fn open_member(dir: &File, name: &str) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err("bundle member must be a regular file".into());
    }
    Ok(file)
}

fn read_bounded(mut file: File, limit: u64) -> Result<Vec<u8>> {
    if file.metadata()?.len() > limit {
        return Err("oversized bundle metadata".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("bundle metadata grew beyond limit".into());
    }
    Ok(bytes)
}

pub fn private_dir(prefix: &str) -> Result<PathBuf> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    // /run is deliberately small on systemd hosts. Live media supplies a
    // volatile /var, while installed updates use encrypted persistent /var.
    let parent = Path::new("/var/lib/luma-os/staging");
    if !parent.exists() {
        fs::create_dir(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(parent)?;
    use std::os::unix::fs::MetadataExt;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("unsafe platform staging directory".into());
    }
    let path = parent.join(format!("{prefix}-{}", hex(&random)));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

pub fn verify(source: &Path) -> Result<VerifiedBundle> {
    // Live production media carries only inert, externally signed initial
    // evidence. It cannot ask the installed Admin journal for timed authority
    // or turn a missing installed enrollment into a static-key fallback.
    if crate::platform::live()? {
        let preview: Manifest = serde_json::from_slice(&initial_preview(source)?)?;
        if inert_live_verification(&preview.environment, true)? {
            return verify_initial(source);
        }
    }
    verify_with(source, |bytes, signature| {
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        if manifest.environment == "production"
            || (crate::platform::require_installed().is_ok()
                && crate::admin_governance::release_authority_optional()?.is_some())
        {
            crate::release_trust::verify_installed_release(bytes, signature)
        } else {
            verify_lab_signature(bytes, signature)
        }
    })
}

fn inert_live_verification(environment: &str, live: bool) -> Result<bool> {
    match environment {
        "production" => Ok(live),
        "lab" => Ok(false),
        _ => Err("unknown bundle verification environment".into()),
    }
}

fn verify_lab_signature(bytes: &[u8], signature: &[u8]) -> Result<()> {
    crate::platform::require_laboratory_image()?;
    let trust = crate::admin_credentials::public_input(Path::new(TRUST), 4096)?;
    let der = crate::release_trust::public_der(&trust)?;
    crate::release_trust::verify_der(&der, bytes, signature)
}

pub(crate) fn verify_initial(source: &Path) -> Result<VerifiedBundle> {
    crate::platform::require_live()?;
    let mut staged_trust = None;
    let mut production_image = None;
    let mut verified = verify_with(source, |bytes, signature| {
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        if manifest.environment == "production" {
            let image = crate::platform::RecoveryImage::current()?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(source)?;
            let trust_bytes = read_bounded(open_member(&directory, "release-trust.json")?, 16384)?;
            let trust: crate::release_trust::SignedTrust = serde_json::from_slice(&trust_bytes)?;
            crate::release_trust::verify_inert_release(&trust, bytes, signature)?;
            image.recheck()?;
            production_image = Some(image);
            staged_trust = Some(trust_bytes);
            Ok(())
        } else {
            verify_lab_signature(bytes, signature)
        }
    })?;
    if let Some(image) = production_image {
        // Artifact hashing/snapshotting can block. The original authenticated
        // live root, firmware state and UKI intent must still be unchanged.
        image.recheck()?;
    }
    verified.inert_trust = staged_trust;
    Ok(verified)
}

/// UI/resource planning only. The installer later compares these exact bytes
/// with the privately snapshotted, cryptographically verified manifest.
pub(crate) fn initial_preview(source: &Path) -> Result<Vec<u8>> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(source)?;
    let bytes = read_bounded(open_member(&directory, "release.json")?, MAX_MANIFEST)?;
    validate_manifest(&serde_json::from_slice(&bytes)?)?;
    Ok(bytes)
}

pub(crate) fn verify_recovery(
    source: &Path,
    state: &crate::release_trust::State,
    interval: crate::utc_bounds::Interval,
) -> Result<VerifiedBundle> {
    verify_with(source, |bytes, signature| {
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        crate::release_trust::repair_identity(state, &manifest)?;
        if let Some(pending) = &state.pending {
            if pending.candidate.manifest == manifest
                && (pending.candidate.manifest_json.as_bytes() != bytes
                    || pending.candidate.signature_hex != hex(signature))
            {
                return Err(
                    "prepared repair must retry exact originally admitted signed bytes".into(),
                );
            }
        }
        crate::release_trust::verify_current_release(&state.trust, bytes, signature, interval)?;
        Ok(())
    })
}

fn verify_with(
    source: &Path,
    validate_signature: impl FnOnce(&[u8], &[u8]) -> Result<()>,
) -> Result<VerifiedBundle> {
    crate::require_root()?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(source)?;
    let bytes = read_bounded(open_member(&dir, "release.json")?, MAX_MANIFEST)?;
    let signature = read_bounded(open_member(&dir, "release.sig")?, 64)?;
    if signature.len() != 64 {
        return Err("invalid Ed25519 signature length".into());
    }
    let m: Manifest = serde_json::from_slice(&bytes)?;
    validate_manifest(&m)?;
    let verified = VerifiedBundle {
        manifest: m,
        manifest_bytes: bytes.clone(),
        signature: signature.clone(),
        inert_trust: None,
        snapshot: crate::staging::Snapshot::create()?,
    };
    // Verification inputs and every consumed artifact become private snapshots.
    for (name, content) in [
        ("release.json", bytes.as_slice()),
        ("release.sig", signature.as_slice()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(verified.snapshot.path().join(name))?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    validate_signature(&bytes, &signature)?;
    // Live /var is memory-backed. Admit measured sparse-copy allocation, not
    // the logical ext4 image size (which exceeds a small live VM's tmpfs).
    // Retain source descriptors, verify their bytes, then rehash while copying;
    // a source mutation between passes cannot become a VerifiedBundle.
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for a in &verified.manifest.artifacts {
        let mut input = open_member(&dir, &a.name)?;
        total = total
            .checked_add(process_member(&mut input, a, None)?)
            .ok_or("snapshot allocation overflow")?;
        input.seek(SeekFrom::Start(0))?;
        inputs.push(input);
    }
    verified.snapshot.admit(total)?;
    for (a, input) in verified.manifest.artifacts.iter().zip(&mut inputs) {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(verified.snapshot.path().join(&a.name))?;
        process_member(input, a, Some(&mut output))?;
        output.set_len(a.bytes)?;
        output.sync_all()?;
    }
    File::open(verified.snapshot.path())?.sync_all()?;
    Ok(verified)
}

fn process_member(
    input: &mut File,
    artifact: &Artifact,
    mut output: Option<&mut File>,
) -> Result<u64> {
    if input.metadata()?.len() != artifact.bytes {
        return Err("artifact size mismatch".into());
    }
    let mut hash = Sha256::new();
    let mut remaining = artifact.bytes;
    let mut allocation = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let request = remaining.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..request])?;
        hash.update(&buffer[..request]);
        if buffer[..request].iter().all(|v| *v == 0) {
            if let Some(file) = output.as_mut() {
                file.seek(SeekFrom::Current(request as i64))?;
            }
        } else {
            allocation = allocation
                .checked_add((request as u64 + 4095) / 4096 * 4096)
                .ok_or("snapshot allocation overflow")?;
            if let Some(file) = output.as_mut() {
                file.write_all(&buffer[..request])?;
            }
        }
        remaining -= request as u64;
    }
    if input.read(&mut buffer[..1])? != 0 || hex(&hash.finalize()) != artifact.sha256 {
        return Err("artifact digest mismatch or trailing bytes".into());
    }
    Ok(allocation)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_measurement_is_byte_verified_and_source_mutation_is_refused() {
        let dir = std::env::temp_dir().join(format!("luma-measure-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let input_path = dir.join("input");
        let output_path = dir.join("output");
        let mut bytes = vec![0u8; 2 * 1024 * 1024];
        bytes.extend(vec![1u8; 5000]);
        fs::write(&input_path, &bytes).unwrap();
        let artifact = Artifact {
            name: "fixture".into(),
            bytes: bytes.len() as u64,
            sha256: hex(&Sha256::digest(&bytes)),
        };
        let mut input = File::open(&input_path).unwrap();
        assert_eq!(process_member(&mut input, &artifact, None).unwrap(), 8192);
        input.seek(SeekFrom::Start(0)).unwrap();
        let mut output = File::create(&output_path).unwrap();
        assert_eq!(
            process_member(&mut input, &artifact, Some(&mut output)).unwrap(),
            8192
        );
        output.set_len(artifact.bytes).unwrap();
        assert_eq!(fs::read(&output_path).unwrap(), bytes);
        bytes[0] = 1;
        fs::write(&input_path, &bytes).unwrap();
        input.seek(SeekFrom::Start(0)).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        assert!(process_member(&mut input, &artifact, Some(&mut output)).is_err());
        fs::remove_file(input_path).unwrap();
        fs::remove_file(output_path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    fn fixture() -> Manifest {
        let root_bytes = 1024 * 1024 * 1024;
        let hash_bytes = 16 * 1024 * 1024;
        Manifest {
            schema_version: 1,
            release: "alpha-1".into(),
            sequence: 1,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
            root_hash: "a".repeat(64),
            root_bytes,
            hash_bytes,
            artifacts: [
                "root.ext4",
                "root.verity",
                "slot-a.efi",
                "slot-b.efi",
                "bootloader.efi",
                "secureboot.cer",
            ]
            .iter()
            .map(|n| Artifact {
                name: n.to_string(),
                bytes: if *n == "root.ext4" {
                    root_bytes
                } else if *n == "root.verity" {
                    hash_bytes
                } else {
                    4096
                },
                sha256: "b".repeat(64),
            })
            .collect(),
        }
    }
    #[test]
    fn accepts_exact_lab_inventory() {
        validate_manifest(&fixture()).unwrap();
    }
    #[test]
    fn inert_verification_is_live_production_only_not_an_installed_fallback() {
        assert!(inert_live_verification("production", true).unwrap());
        assert!(!inert_live_verification("production", false).unwrap());
        assert!(!inert_live_verification("lab", true).unwrap());
        assert!(!inert_live_verification("lab", false).unwrap());
        for unknown in ["", "production-override", "LAB"] {
            assert!(inert_live_verification(unknown, true).is_err());
        }
    }
    #[test]
    fn production_and_lab_boot_members_have_closed_individual_bounds() {
        for environment in ["lab", "production"] {
            let mut original = fixture();
            original.environment = environment.into();
            validate_manifest(&original).unwrap();
            for (name, maximum) in [
                ("slot-a.efi", 256 * 1024 * 1024),
                ("slot-b.efi", 256 * 1024 * 1024),
                ("bootloader.efi", 16 * 1024 * 1024),
                ("secureboot.cer", 16 * 1024),
            ] {
                let mut changed = original.clone();
                let member = changed
                    .artifacts
                    .iter_mut()
                    .find(|a| a.name == name)
                    .unwrap();
                member.bytes = maximum;
                validate_manifest(&changed).unwrap();
                changed
                    .artifacts
                    .iter_mut()
                    .find(|a| a.name == name)
                    .unwrap()
                    .bytes += 1;
                assert!(validate_manifest(&changed).is_err(), "{environment}/{name}");
            }
        }
    }
    #[test]
    fn rejects_duplicate_traversal_or_missing_artifacts() {
        for bad in ["../root.ext4", "/etc/shadow", "root.verity"] {
            let mut m = fixture();
            m.artifacts[0].name = bad.into();
            assert!(validate_manifest(&m).is_err());
        }
        let mut m = fixture();
        m.artifacts.pop();
        assert!(validate_manifest(&m).is_err());
    }
    #[test]
    fn rejects_wrong_environment_geometry_and_hash() {
        let mut m = fixture();
        m.environment = "caller-selected".into();
        assert!(validate_manifest(&m).is_err());
        let mut m = fixture();
        m.root_bytes = u64::MAX;
        assert!(validate_manifest(&m).is_err());
        let mut m = fixture();
        m.root_hash = "G".repeat(64);
        assert!(validate_manifest(&m).is_err());
    }
    #[test]
    fn rejects_duplicate_and_unknown_json_fields() {
        let bytes = serde_json::to_string(&fixture()).unwrap();
        let duplicate = bytes.replacen("{", "{\"sequence\":2,", 1);
        assert!(serde_json::from_str::<Manifest>(&duplicate).is_err());
        let unknown = bytes.replacen("{", "{\"shell\":\"sh\",", 1);
        assert!(serde_json::from_str::<Manifest>(&unknown).is_err());
    }
}
