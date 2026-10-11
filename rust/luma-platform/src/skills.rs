//! Read-only admission of an image-owned closed skill registry.
//! A valid registry describes a workflow; it grants no effect or execution.
use crate::{bundle, workflow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const REGISTRY: &str = "/usr/share/luma-os/skills/registry.json";
const SIGNATURE: &str = "/usr/share/luma-os/skills/registry.sig";
const TRUST: &str = "/usr/share/luma-os/skills/skills.pub";
const GRAPH: &str = "/usr/share/luma-os/workflows/file-to-artifact-v1.json";
const MAX_REGISTRY: u64 = 4096;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Skill {
    id: String,
    input_types: Vec<String>,
    output_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: u32,
    environment: String,
    profile: String,
    workflow_sha256: String,
    skills: Vec<Skill>,
}

fn expected_skills() -> Vec<Skill> {
    [
        ("file-read", &[][..], "text"),
        ("deterministic-calculate", &["text"][..], "report"),
        ("artifact-write", &["report"][..], "artifact"),
    ]
    .into_iter()
    .map(|(id, inputs, output)| Skill {
        id: id.into(),
        input_types: inputs.iter().map(|s| (*s).into()).collect(),
        output_type: output.into(),
    })
    .collect()
}

struct Member {
    path: PathBuf,
    file: File,
    parent: std::fs::Metadata,
    before: std::fs::Metadata,
    bytes: Vec<u8>,
    limit: u64,
}
fn same_member(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
fn read_bounded(path: &Path, limit: u64) -> Result<Member> {
    let parent_path = path
        .parent()
        .ok_or("missing skill registry member parent")?;
    let parent = std::fs::symlink_metadata(parent_path)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("skill registry parent must be root-owned and not writable by others".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > limit
    {
        return Err("invalid or oversized skill registry member".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len()
        || !same_member(&metadata, &file.metadata()?)
        || !same_member(&metadata, &std::fs::symlink_metadata(path)?)
        || !same_member(&parent, &std::fs::symlink_metadata(parent_path)?)
    {
        return Err("skill registry member changed during read".into());
    }
    Ok(Member {
        path: path.into(),
        file,
        parent,
        before: metadata,
        bytes,
        limit,
    })
}
impl Member {
    fn recheck(&self) -> Result<()> {
        let observed = read_bounded(&self.path, self.limit)?;
        if !same_member(&self.before, &self.file.metadata()?)
            || !same_member(&self.before, &observed.before)
            || !same_member(&self.parent, &observed.parent)
            || self.bytes != observed.bytes
        {
            return Err(
                "skill registry namespace or exact member changed during verification".into(),
            );
        }
        Ok(())
    }
}

fn sealed_snapshot(name: &str, bytes: &[u8]) -> Result<File> {
    let name = CString::new(name)?;
    // No CLOEXEC: OpenSSL reads this same sealed descriptor by /proc/self/fd.
    // No file is written to persistent storage or an attacker-writable path.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

fn validate_registry(bytes: &[u8], graph: &[u8]) -> Result<serde_json::Value> {
    validate_profile(bytes, graph, false)
}
pub(crate) fn validate_governed(bytes: &[u8], graph: &[u8]) -> Result<serde_json::Value> {
    validate_profile(bytes, graph, true)
}
fn validate_profile(bytes: &[u8], graph: &[u8], governed: bool) -> Result<serde_json::Value> {
    if bytes.len() > MAX_REGISTRY as usize || graph.len() > 65536 {
        return Err("closed registry/graph exceeds its finite content bounds".into());
    }
    let registry: Registry = serde_json::from_slice(bytes)?;
    let digest = bundle::hex(&Sha256::digest(graph));
    if registry.schema_version != if governed { 2 } else { 1 }
        || if governed {
            !matches!(registry.environment.as_str(), "lab" | "production")
        } else {
            registry.environment != "lab"
        }
        || registry.profile != "file-to-artifact-v1"
        || registry.workflow_sha256 != digest
        || registry.skills != expected_skills()
    {
        return Err("unsupported or unbound signed skill registry".into());
    }
    let workflow = workflow::validate_bytes(graph)?;
    if workflow["profile"] != registry.profile {
        return Err("signed skill workflow profile mismatch".into());
    }
    Ok(serde_json::json!({
        "schema_version":registry.schema_version,"environment":registry.environment,"profile":registry.profile,
        "workflow_sha256":digest,"workflow_fingerprint":workflow["fingerprint"],
        "skills":registry.skills.iter().map(|skill| &skill.id).collect::<Vec<_>>(),
        "signed_registry_admitted":true,"legacy_lab_registry":!governed,
        "effect_executed":false,"gate_closing":false,
        "native_invoice_execution_supported":workflow::invoice_execution_supported(graph)?
    }))
}

fn verify_files(
    registry: &Path,
    signature: &Path,
    trust: &Path,
    graph: &Path,
) -> Result<serde_json::Value> {
    let registry_member = read_bounded(registry, MAX_REGISTRY)?;
    let signature_member = read_bounded(signature, 64)?;
    let bytes = &registry_member.bytes;
    let signature_bytes = &signature_member.bytes;
    if signature_bytes.len() != 64 {
        return Err("invalid Ed25519 skill signature length".into());
    }
    // The public key's authority still depends on its fixed location inside
    // the verity-protected image. Snapshot all three inputs so OpenSSL cannot
    // reopen a changed pathname after the bounded no-follow reads.
    let trust_member = read_bounded(trust, 512)?;
    let message_fd = sealed_snapshot("luma-skill-registry", bytes)?;
    let signature_fd = sealed_snapshot("luma-skill-signature", signature_bytes)?;
    let trust_fd = sealed_snapshot("luma-skill-trust", &trust_member.bytes)?;
    let status = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("PATH", "/usr/bin")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(format!("/proc/self/fd/{}", trust_fd.as_raw_fd()))
        .args(["-rawin", "-in"])
        .arg(format!("/proc/self/fd/{}", message_fd.as_raw_fd()))
        .arg("-sigfile")
        .arg(format!("/proc/self/fd/{}", signature_fd.as_raw_fd()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("skill registry signature verification failed".into());
    }
    // The workflow is image-owned; its exact bytes are bound by the signed
    // digest and it must separately pass the closed native DAG validator.
    let graph_member = read_bounded(graph, 64 * 1024)?;
    let result = validate_registry(bytes, &graph_member.bytes)?;
    registry_member.recheck()?;
    signature_member.recheck()?;
    trust_member.recheck()?;
    graph_member.recheck()?;
    Ok(result)
}

pub(crate) fn admission() -> Result<serde_json::Value> {
    crate::platform::require_production_activation()?;
    let image: serde_json::Value =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    let environment = image
        .get("environment")
        .and_then(serde_json::Value::as_str)
        .filter(|value| matches!(*value, "lab" | "production"))
        .ok_or("skill registry requires an explicit immutable image environment")?;
    let registry = read_bounded(Path::new(REGISTRY), MAX_REGISTRY)?;
    let graph = read_bounded(Path::new(GRAPH), 65536)?;
    let profile: Registry = serde_json::from_slice(&registry.bytes)?;
    if profile.environment != environment {
        return Err("skill registry and immutable OS image environments differ".into());
    }
    if profile.schema_version == 1 {
        validate_registry(&registry.bytes, &graph.bytes)?;
        if crate::admin_governance::skill_trust_present()? {
            return Err(
                "anchored skill trust cannot fall back to legacy laboratory registry".into(),
            );
        }
        let verified = verify_files(
            Path::new(REGISTRY),
            Path::new(SIGNATURE),
            Path::new(TRUST),
            Path::new(GRAPH),
        )?;
        if crate::admin_governance::skill_trust_present()? {
            return Err("skill trust anchored while verifying legacy laboratory package".into());
        }
        Ok(verified)
    } else {
        let mut value = validate_governed(&registry.bytes, &graph.bytes)?;
        let authority =
            crate::skill_trust::verify_installed(&registry.bytes, &graph.bytes, || {
                registry.recheck()?;
                graph.recheck()
            })?;
        value
            .as_object_mut()
            .ok_or("closed registry result must be an object")?
            .extend(
                authority
                    .as_object()
                    .ok_or("skill authority result must be an object")?
                    .clone(),
            );
        Ok(value)
    }
}

pub fn status() -> Result<()> {
    println!("{}", admission()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn verifier_snapshot_cannot_be_rewritten_after_sealing() {
        let mut snapshot = sealed_snapshot("luma-test", b"fixed bytes").unwrap();
        assert!(snapshot.write_all(b"replacement").is_err());
        let mut contents = Vec::new();
        snapshot.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"fixed bytes");
    }

    #[test]
    fn public_members_refuse_links_writable_bytes_and_detached_namespace_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("luma-skill-member-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("registry.json");
        fs::write(&path, b"bounded public fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let original = read_bounded(&path, 64).unwrap();
        original.recheck().unwrap();
        fs::hard_link(&path, dir.join("hard-link")).unwrap();
        assert!(read_bounded(&path, 64).is_err());
        assert!(original.recheck().is_err());
        fs::remove_file(dir.join("hard-link")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_bounded(&path, 64).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before_replacement = read_bounded(&path, 64).unwrap();
        fs::rename(&path, dir.join("retained-original")).unwrap();
        fs::write(&path, b"bounded public fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(before_replacement.recheck().is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.join("retained-original"), &path).unwrap();
        assert!(read_bounded(&path, 64).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_bounded(&dir.join("retained-original"), 64).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn closed_registry_requires_bound_graph_and_exact_descriptors() {
        let graph = include_bytes!(
            "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
        );
        let mut registry = Registry {
            schema_version: 1,
            environment: "lab".into(),
            profile: "file-to-artifact-v1".into(),
            workflow_sha256: bundle::hex(&Sha256::digest(graph)),
            skills: expected_skills(),
        };
        let bytes = serde_json::to_vec(&registry).unwrap();
        assert_eq!(
            validate_registry(&bytes, graph).unwrap()["effect_executed"],
            false
        );
        registry.skills[0].output_type = "artifact".into();
        assert!(validate_registry(&serde_json::to_vec(&registry).unwrap(), graph).is_err());
        registry.skills = expected_skills();
        assert!(validate_registry(&serde_json::to_vec(&registry).unwrap(), b"{}").is_err());
        let mut unknown = bytes.clone();
        unknown.splice(1..1, b"\"authority\":true,".iter().copied());
        assert!(validate_registry(&unknown, graph).is_err());
    }

    #[test]
    fn governed_registry_is_closed_environment_bound_and_has_no_legacy_downgrade() {
        let graph = include_bytes!(
            "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
        );
        let mut registry = Registry {
            schema_version: 2,
            environment: "production".into(),
            profile: "file-to-artifact-v1".into(),
            workflow_sha256: bundle::hex(&Sha256::digest(graph)),
            skills: expected_skills(),
        };
        let bytes = serde_json::to_vec(&registry).unwrap();
        let value = validate_governed(&bytes, graph).unwrap();
        assert_eq!(value["environment"], "production");
        assert_eq!(value["legacy_lab_registry"], false);
        assert!(validate_registry(&bytes, graph).is_err());
        registry.environment = "lab".into();
        validate_governed(&serde_json::to_vec(&registry).unwrap(), graph).unwrap();
        registry.schema_version = 1;
        assert!(validate_governed(&serde_json::to_vec(&registry).unwrap(), graph).is_err());
        registry.environment = "production".into();
        assert!(validate_registry(&serde_json::to_vec(&registry).unwrap(), graph).is_err());
        registry.schema_version = 2;
        registry.skills.reverse();
        assert!(validate_governed(&serde_json::to_vec(&registry).unwrap(), graph).is_err());
        assert!(validate_governed(&vec![b' '; 4097], graph).is_err());
    }

    #[test]
    fn signature_tamper_and_symlink_are_denied() {
        let dir = std::env::temp_dir().join(format!("luma-skills-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let graph_bytes = include_bytes!(
            "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
        );
        let registry = Registry {
            schema_version: 1,
            environment: "lab".into(),
            profile: "file-to-artifact-v1".into(),
            workflow_sha256: bundle::hex(&Sha256::digest(graph_bytes)),
            skills: expected_skills(),
        };
        let key = dir.join("private.key");
        let pubkey = dir.join("skills.pub");
        let data = dir.join("registry.json");
        let sig = dir.join("registry.sig");
        let graph = dir.join("graph.json");
        fs::write(&data, serde_json::to_vec(&registry).unwrap()).unwrap();
        fs::write(&graph, graph_bytes).unwrap();
        assert!(Command::new("/usr/bin/openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout", "-out"])
            .arg(&pubkey)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(&key)
            .arg("-in")
            .arg(&data)
            .arg("-out")
            .arg(&sig)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        let verified = verify_files(&data, &sig, &pubkey, &graph);
        assert!(verified.is_ok(), "{verified:?}");
        let original_signature = fs::read(&sig).unwrap();
        let mut altered_signature = original_signature.clone();
        altered_signature[0] ^= 1;
        fs::write(&sig, altered_signature).unwrap();
        assert!(verify_files(&data, &sig, &pubkey, &graph).is_err());
        fs::write(&sig, original_signature).unwrap();
        let other_key = dir.join("other.key");
        let other_pubkey = dir.join("other.pub");
        assert!(Command::new("/usr/bin/openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&other_key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&other_key)
            .args(["-pubout", "-out"])
            .arg(&other_pubkey)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(verify_files(&data, &sig, &other_pubkey, &graph).is_err());
        fs::write(&graph, b"{}").unwrap();
        assert!(verify_files(&data, &sig, &pubkey, &graph).is_err());
        fs::write(&graph, graph_bytes).unwrap();
        fs::write(&data, b"{}").unwrap();
        assert!(verify_files(&data, &sig, &pubkey, &graph).is_err());
        fs::remove_file(&data).unwrap();
        std::os::unix::fs::symlink(&graph, &data).unwrap();
        assert!(verify_files(&data, &sig, &pubkey, &graph).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
