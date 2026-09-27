use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_MANIFEST: u64 = 65536;
const TRUST: &str = "/usr/share/luma-os/release.pub";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    directory: PathBuf,
}

impl VerifiedBundle {
    pub fn path(&self, name: &str) -> Result<PathBuf> {
        if !self.manifest.artifacts.iter().any(|a| a.name == name) {
            return Err("artifact absent from signed inventory".into());
        }
        Ok(self.directory.join(name))
    }
}

impl Drop for VerifiedBundle {
    fn drop(&mut self) {
        // Only the private, newly allocated directory created by verify().
        let _ = fs::remove_dir_all(&self.directory);
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
        || m.environment != "lab"
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
        if a.bytes == 0 || a.bytes > 32 * 1024 * 1024 * 1024 || !is_hash(&a.sha256) {
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
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
        directory: private_dir("bundle")?,
    };
    // Verification inputs and every consumed artifact become private snapshots.
    fs::write(verified.directory.join("release.json"), &bytes)?;
    fs::write(verified.directory.join("release.sig"), signature)?;
    let status = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .args([
            "pkeyutl", "-verify", "-pubin", "-inkey", TRUST, "-rawin", "-in",
        ])
        .arg(verified.directory.join("release.json"))
        .arg("-sigfile")
        .arg(verified.directory.join("release.sig"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("release signature verification failed".into());
    }
    for a in &verified.manifest.artifacts {
        let mut input = open_member(&dir, &a.name)?;
        if input.metadata()?.len() != a.bytes {
            return Err("artifact size mismatch".into());
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(verified.directory.join(&a.name))?;
        let mut hash = Sha256::new();
        let mut remaining = a.bytes;
        let mut buffer = [0u8; 1024 * 1024];
        while remaining > 0 {
            let request = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..request])?;
            hash.update(&buffer[..request]);
            if buffer[..request].iter().all(|v| *v == 0) {
                output.seek(SeekFrom::Current(request as i64))?;
            } else {
                output.write_all(&buffer[..request])?;
            }
            remaining -= request as u64;
        }
        if input.read(&mut buffer[..1])? != 0 || hex(&hash.finalize()) != a.sha256 {
            return Err("artifact digest mismatch or trailing bytes".into());
        }
        output.set_len(a.bytes)?;
        output.sync_all()?;
    }
    File::open(&verified.directory)?.sync_all()?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        m.environment = "production".into();
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
