//! Read-only admission of one image-owned, laboratory-signed skill registry.
//! A valid registry describes a workflow; it grants no effect or execution.
use crate::{bundle, workflow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err("invalid or oversized skill registry member".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("skill registry member changed during read".into());
    }
    Ok(bytes)
}

fn validate_registry(bytes: &[u8], graph: &[u8]) -> Result<serde_json::Value> {
    let registry: Registry = serde_json::from_slice(bytes)?;
    let digest = bundle::hex(&Sha256::digest(graph));
    if registry.schema_version != 1
        || registry.environment != "lab"
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
        "schema_version":1,"environment":"lab","profile":registry.profile,
        "workflow_sha256":digest,"workflow_fingerprint":workflow["fingerprint"],
        "skills":registry.skills.iter().map(|skill| &skill.id).collect::<Vec<_>>(),
        "signed_registry_admitted":true,"effect_executed":false,"gate_closing":false
    }))
}

fn verify_files(
    registry: &Path,
    signature: &Path,
    trust: &Path,
    graph: &Path,
) -> Result<serde_json::Value> {
    let bytes = read_bounded(registry, MAX_REGISTRY)?;
    let signature_bytes = read_bounded(signature, 64)?;
    if signature_bytes.len() != 64 {
        return Err("invalid Ed25519 skill signature length".into());
    }
    // These paths are fixed within the image's verity-protected root. The
    // bounded, no-follow reads reject malformed members before OpenSSL uses
    // its own file API; this is not a mutable-directory verification API.
    let _ = read_bounded(trust, 512)?;
    let status = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("PATH", "/usr/bin")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(trust)
        .args(["-rawin", "-in"])
        .arg(registry)
        .arg("-sigfile")
        .arg(signature)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("skill registry signature verification failed".into());
    }
    // The workflow is image-owned; its exact bytes are bound by the signed
    // digest and it must separately pass the closed native DAG validator.
    let graph = read_bounded(graph, 64 * 1024)?;
    validate_registry(&bytes, &graph)
}

pub fn status() -> Result<()> {
    let result = verify_files(
        Path::new(REGISTRY),
        Path::new(SIGNATURE),
        Path::new(TRUST),
        Path::new(GRAPH),
    )?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
