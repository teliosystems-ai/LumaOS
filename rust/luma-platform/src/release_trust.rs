//! Public release trust and monotonic release admission reconstructed by the
//! shared Admin TPM journal. Signed files and serialized receipts are not
//! capabilities. No new TPM namespace, production private key or clock fallback.
use crate::{
    bundle::{self, Manifest},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const MAX_TRUST: usize = 16384;
const ED25519_SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Key {
    pub id: String,
    pub public_key_hex: String,
    pub purpose: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trust {
    pub schema_version: u32,
    pub environment: String,
    pub version: u64,
    pub root_sha256: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub keys: Vec<Key>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedTrust {
    pub trust: Trust,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRelease {
    pub manifest: Manifest,
    // Exact signed bytes: a deserialized manifest alone must never substitute
    // an equivalent JSON representation for the signature input.
    pub manifest_json: String,
    pub signature_hex: String,
    pub signer: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Confirmed,
    Fallback,
    Abandoned,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    pub prior: Manifest,
    pub candidate: SignedRelease,
    pub trust_version: u64,
    pub trust_sha256: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct State {
    pub trust: SignedTrust,
    pub floor: u64,
    pub acknowledged: Option<Manifest>,
    pub pending: Option<Admission>,
    pub retained: Option<Manifest>,
}

fn validity(start: i64, end: i64) -> Result<()> {
    if start <= 0
        || end > 4_102_444_800_000
        || end <= start
        || end
            .checked_sub(start)
            .map_or(true, |v| v > 366 * 86_400_000)
    {
        return Err("release trust validity must be finite, positive and at most 366 days".into());
    }
    Ok(())
}

impl SignedTrust {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        // Value object maps sort keys recursively, so public ceremony tools
        // reproduce the canonical input without Rust declaration ordering.
        Ok(serde_json::to_vec(&serde_json::to_value(&self.trust)?)?)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let t = &self.trust;
        if t.schema_version != 1
            || !matches!(t.environment.as_str(), "lab" | "production")
            || t.version == 0
            || t.version > i64::MAX as u64
            || t.keys.is_empty()
            || t.keys.len() > 64
            || serde_json::to_vec(self)?.len() > MAX_TRUST
        {
            return Err("invalid release trust schema/environment/version/bounds".into());
        }
        crate::tpm::decode::<32>(&t.root_sha256)?;
        crate::tpm::decode::<64>(&self.signature_hex)?;
        validity(t.not_before_ms, t.expires_ms)?;
        let mut ids = BTreeSet::new();
        let mut public = BTreeSet::new();
        for key in &t.keys {
            if !crate::admin_roles::identifier(&key.id)
                || key.purpose != "os-release"
                || !ids.insert(&key.id)
                || !public.insert(&key.public_key_hex)
                || crate::tpm::decode::<32>(&key.public_key_hex)? == [0; 32]
            {
                return Err(
                    "release key must have a unique fixed ID/public key and os-release purpose"
                        .into(),
                );
            }
            validity(key.not_before_ms, key.expires_ms)?;
            if t.environment == "production" {
                let mut delegated = ED25519_SPKI.to_vec();
                delegated.extend_from_slice(&crate::tpm::decode::<32>(&key.public_key_hex)?);
                if bundle::hex(&Sha256::digest(&delegated)) == t.root_sha256 {
                    return Err("offline production trust root cannot also be a delegated OS release signing key".into());
                }
            }
            if key.not_before_ms < t.not_before_ms || key.expires_ms > t.expires_ms {
                return Err("release key validity escapes root-authorized bundle".into());
            }
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(
            &serde_json::to_value(self)?,
        )?)))
    }
    pub(crate) fn verify_root(&self) -> Result<()> {
        self.validate()?;
        let path = match self.trust.environment.as_str() {
            "lab" => "/usr/share/luma-os/release.pub",
            "production" => "/usr/share/luma-os/production-release-root.pub",
            _ => return Err("unsupported release root environment".into()),
        };
        let root = public_file(Path::new(path))?;
        self.verify_root_bytes(&root)
    }
    fn verify_root_bytes(&self, root: &[u8]) -> Result<()> {
        self.validate()?;
        let der = public_der(&root)?;
        if self.trust.root_sha256 != bundle::hex(&Sha256::digest(&der)) {
            return Err(
                "release trust does not bind the independently provisioned immutable root".into(),
            );
        }
        verify_der(
            &der,
            &self.signing_bytes()?,
            &crate::tpm::decode::<64>(&self.signature_hex)?,
        )
    }
    fn key(&self, id: &str) -> Result<&Key> {
        self.trust
            .keys
            .iter()
            .find(|k| k.id == id && !k.revoked)
            .ok_or_else(|| "unknown or revoked release signer".into())
    }
    pub(crate) fn check_time(&self, interval: crate::utc_bounds::Interval) -> Result<()> {
        if !interval.within(self.trust.not_before_ms, self.trust.expires_ms)? {
            return Err("release trust is outside the entire protected UTC interval".into());
        }
        Ok(())
    }
}

impl SignedRelease {
    pub(crate) fn validate(&self) -> Result<()> {
        bundle::validate_manifest(&self.manifest)?;
        crate::tpm::decode::<64>(&self.signature_hex)?;
        if !crate::admin_roles::identifier(&self.signer)
            || self.manifest_json.is_empty()
            || self.manifest_json.len() > 65536
            || serde_json::from_str::<Manifest>(&self.manifest_json)? != self.manifest
        {
            return Err(
                "release admission must bind exact signed manifest bytes and signer".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn verify(&self, trust: &SignedTrust) -> Result<()> {
        self.validate()?;
        if self.manifest.environment != trust.trust.environment {
            return Err("release environment differs from its root-authorized trust".into());
        }
        let key = trust.key(&self.signer)?;
        let mut der = ED25519_SPKI.to_vec();
        der.extend_from_slice(&crate::tpm::decode::<32>(&key.public_key_hex)?);
        verify_der(
            &der,
            self.manifest_json.as_bytes(),
            &crate::tpm::decode::<64>(&self.signature_hex)?,
        )
    }
    pub(crate) fn check_time(
        &self,
        trust: &SignedTrust,
        interval: crate::utc_bounds::Interval,
    ) -> Result<()> {
        trust.check_time(interval)?;
        let key = trust.key(&self.signer)?;
        if !interval.within(key.not_before_ms, key.expires_ms)? {
            return Err("release signer is outside the entire protected UTC interval".into());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(bundle::hex(&Sha256::digest(self.manifest_json.as_bytes())))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedRelease {
    pub schema_version: u32,
    pub trust: SignedTrust,
    pub manifest_json: String,
    pub signature_hex: String,
}
impl StagedRelease {
    pub(crate) fn release(&self) -> Result<SignedRelease> {
        self.trust.verify_root()?;
        self.parse_verified_root()
    }
    fn parse_verified_root(&self) -> Result<SignedRelease> {
        if self.schema_version != 1 {
            return Err("invalid inert release staging schema".into());
        }
        if self.trust.trust.environment != "production" {
            return Err("inert staging requires production purpose-separated root trust".into());
        }
        let signature = crate::tpm::decode::<64>(&self.signature_hex)?;
        signed_release_verified_root(&self.trust, self.manifest_json.as_bytes(), &signature)
    }
}

pub(crate) fn publish(state: &mut Option<State>, expected: u64, next: &SignedTrust) -> Result<()> {
    next.validate()?;
    let previous = state.as_ref();
    if expected != previous.map_or(0, |s| s.trust.trust.version)
        || next.trust.version
            != expected
                .checked_add(1)
                .ok_or("release trust version exhausted")?
    {
        return Err("release trust publication has a stale/nonconsecutive version".into());
    }
    if let Some(old) = previous {
        if old.trust.trust.environment != next.trust.environment
            || old.trust.trust.root_sha256 != next.trust.root_sha256
        {
            return Err("release trust cannot replace its provisioned root or environment".into());
        }
        for key in &old.trust.trust.keys {
            let replacement = next
                .trust
                .keys
                .iter()
                .find(|k| k.id == key.id)
                .ok_or("release trust must retain historical key identities and revocations")?;
            if key.public_key_hex != replacement.public_key_hex
                || key.purpose != replacement.purpose
                || (key.revoked && !replacement.revoked)
            {
                return Err("release trust cannot reuse an ID/key or undo revocation".into());
            }
        }
    }
    let mut new = previous.cloned().unwrap_or(State {
        trust: next.clone(),
        floor: 0,
        acknowledged: None,
        pending: None,
        retained: None,
    });
    new.trust = next.clone();
    *state = Some(new);
    Ok(())
}

pub(crate) fn prepare(
    state: &mut Option<State>,
    expected_floor: u64,
    admission: &Admission,
) -> Result<()> {
    admission.candidate.validate()?;
    bundle::validate_manifest(&admission.prior)?;
    let s = state
        .as_mut()
        .ok_or("release trust must be anchored before admission")?;
    if s.pending.is_some()
        || s.floor != expected_floor
        || admission.trust_version != s.trust.trust.version
        || admission.trust_sha256 != s.trust.digest()?
        || admission.prior.environment != s.trust.trust.environment
        || admission.candidate.manifest.environment != s.trust.trust.environment
        || admission.candidate.manifest.sequence <= s.floor.max(admission.prior.sequence)
        || admission.candidate.manifest.edition != admission.prior.edition
        || admission.candidate.manifest.root_bytes != admission.prior.root_bytes
        || admission.candidate.manifest.hash_bytes != admission.prior.hash_bytes
        || s.acknowledged
            .as_ref()
            .is_some_and(|m| m != &admission.prior)
    {
        return Err("release admission conflicts with floor, pending transaction, geometry, edition or acknowledged identity".into());
    }
    s.trust.key(&admission.candidate.signer)?;
    s.floor = admission.candidate.manifest.sequence;
    s.acknowledged = Some(admission.prior.clone());
    s.pending = Some(admission.clone());
    Ok(())
}

pub(crate) fn initialize(state: &mut Option<State>, release: &SignedRelease) -> Result<()> {
    release.validate()?;
    let s = state
        .as_mut()
        .ok_or("initial release requires anchored public trust")?;
    if s.floor != 0
        || s.acknowledged.is_some()
        || s.pending.is_some()
        || s.retained.is_some()
        || release.manifest.environment != s.trust.trust.environment
    {
        return Err("initial release cannot reset or replace existing release authority".into());
    }
    s.trust.key(&release.signer)?;
    s.floor = release.manifest.sequence;
    s.acknowledged = Some(release.manifest.clone());
    Ok(())
}

pub(crate) fn resolve(
    state: &mut Option<State>,
    candidate_digest: &str,
    outcome: Outcome,
) -> Result<()> {
    crate::tpm::decode::<32>(candidate_digest)?;
    let s = state.as_mut().ok_or("missing release authority")?;
    let admission = s
        .pending
        .as_ref()
        .ok_or("no release transaction to resolve")?;
    if admission.candidate.digest()? != candidate_digest
        || s.floor != admission.candidate.manifest.sequence
    {
        return Err(
            "release recovery must select its exact admitted candidate and unchanged floor".into(),
        );
    }
    match outcome {
        Outcome::Confirmed => {
            s.trust.key(&admission.candidate.signer)?;
            s.retained = Some(admission.prior.clone());
            s.acknowledged = Some(admission.candidate.manifest.clone());
        }
        Outcome::Fallback | Outcome::Abandoned => s.acknowledged = Some(admission.prior.clone()),
    }
    // The admission floor never follows a fallback to its older sequence.
    s.pending = None;
    Ok(())
}

pub(crate) fn check_live(
    command: &crate::admin_roles::Command,
    state: &Option<State>,
    interval: crate::utc_bounds::Interval,
) -> Result<()> {
    use crate::admin_roles::Command as C;
    match command {
        C::PublishReleaseTrust { bundle, .. } => {
            bundle.verify_root()?;
            bundle.check_time(interval)
        }
        C::PrepareRelease { admission, .. } => {
            let s = state.as_ref().ok_or("missing anchored release trust")?;
            s.trust.verify_root()?;
            admission.candidate.verify(&s.trust)?;
            admission.candidate.check_time(&s.trust, interval)?;
            crate::platform::check_governance_manifest(&admission.prior)
        }
        C::InitializeRelease { release } => {
            let s = state
                .as_ref()
                .ok_or("initial release requires anchored public trust")?;
            s.trust.verify_root()?;
            release.verify(&s.trust)?;
            release.check_time(&s.trust, interval)?;
            crate::platform::check_governance_manifest(&release.manifest)
        }
        C::ResolveRelease {
            candidate_sha256,
            outcome,
        } => {
            let s = state.as_ref().ok_or("missing release authority")?;
            let a = s.pending.as_ref().ok_or("no release transaction")?;
            if a.candidate.digest()? != *candidate_sha256 {
                return Err("release resolution digest differs".into());
            }
            if *outcome == Outcome::Confirmed {
                s.trust.verify_root()?;
                a.candidate.verify(&s.trust)?;
                a.candidate.check_time(&s.trust, interval)?;
                crate::platform::check_governance_manifest(&a.candidate.manifest)
            } else {
                crate::platform::check_governance_manifest(&a.prior)
            }
        }
        _ => Ok(()),
    }
}

pub(crate) fn is_command(command: &crate::admin_roles::Command) -> bool {
    matches!(
        command,
        crate::admin_roles::Command::PublishReleaseTrust { .. }
            | crate::admin_roles::Command::PrepareRelease { .. }
            | crate::admin_roles::Command::ResolveRelease { .. }
            | crate::admin_roles::Command::InitializeRelease { .. }
    )
}

pub(crate) fn check_command_time(
    command: &crate::admin_roles::Command,
    state: &Option<State>,
    interval: crate::utc_bounds::Interval,
) -> Result<()> {
    use crate::admin_roles::Command as C;
    match command {
        C::PublishReleaseTrust { bundle, .. } => bundle.check_time(interval),
        C::PrepareRelease { admission, .. } => admission.candidate.check_time(
            &state.as_ref().ok_or("missing release trust")?.trust,
            interval,
        ),
        C::InitializeRelease { release } => release.check_time(
            &state.as_ref().ok_or("missing release trust")?.trust,
            interval,
        ),
        C::ResolveRelease {
            outcome: Outcome::Confirmed,
            ..
        } => {
            let s = state.as_ref().ok_or("missing release trust")?;
            s.pending
                .as_ref()
                .ok_or("missing release transaction")?
                .candidate
                .check_time(&s.trust, interval)
        }
        _ => Ok(()),
    }
}

pub(crate) fn verify_installed_release(bytes: &[u8], signature: &[u8]) -> Result<()> {
    let (state, interval) = crate::admin_governance::release_authority()?;
    let s =
        state.ok_or("production release requires provisioned root and anchored release trust")?;
    verify_current_release(&s.trust, bytes, signature, interval)?;
    Ok(())
}

fn signed_release(trust: &SignedTrust, bytes: &[u8], signature: &[u8]) -> Result<SignedRelease> {
    trust.verify_root()?;
    signed_release_verified_root(trust, bytes, signature)
}

fn signed_release_verified_root(
    trust: &SignedTrust,
    bytes: &[u8],
    signature: &[u8],
) -> Result<SignedRelease> {
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    let mut matched = None;
    for key in &trust.trust.keys {
        if key.revoked {
            continue;
        }
        let release = SignedRelease {
            manifest: manifest.clone(),
            manifest_json: String::from_utf8(bytes.to_vec())?,
            signature_hex: bundle::hex(signature),
            signer: key.id.clone(),
        };
        if release.verify(trust).is_ok() {
            if matched.is_some() {
                return Err("release signature ambiguously matches multiple keys".into());
            }
            matched = Some(release);
        }
    }
    matched.ok_or_else(|| "release signature lacks one exact root-authorized signer".into())
}

/// Structural/signature validation only. This deliberately returns no timed
/// authority and is usable solely for approved inert initial installation.
pub(crate) fn verify_inert_release(
    trust: &SignedTrust,
    bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    if trust.trust.environment != "production" {
        return Err("inert production staging requires production root trust".into());
    }
    signed_release(trust, bytes, signature)?;
    Ok(())
}

pub(crate) fn verify_current_release(
    trust: &SignedTrust,
    bytes: &[u8],
    signature: &[u8],
    interval: crate::utc_bounds::Interval,
) -> Result<SignedRelease> {
    let release = signed_release(trust, bytes, signature)?;
    release.check_time(trust, interval)?;
    Ok(release)
}

pub(crate) fn repair_identity(state: &State, manifest: &Manifest) -> Result<()> {
    bundle::validate_manifest(manifest)?;
    let anchored = state.acknowledged.as_ref() == Some(manifest)
        || state.retained.as_ref() == Some(manifest)
        || state
            .pending
            .as_ref()
            .is_some_and(|p| &p.prior == manifest || &p.candidate.manifest == manifest);
    if !anchored
        || manifest.environment != state.trust.trust.environment
        || manifest.sequence > state.floor
    {
        return Err(
            "repair image is not an exact retained, acknowledged or prepared TPM identity".into(),
        );
    }
    if let Some(pending) = &state.pending {
        if &pending.candidate.manifest == manifest
            && (pending.trust_version != state.trust.trust.version
                || pending.trust_sha256 != state.trust.digest()?)
        {
            return Err("prepared repair identity was invalidated by trust rotation".into());
        }
    }
    Ok(())
}

pub(crate) fn check_bundle_admission(
    bundle: &crate::bundle::VerifiedBundle,
    state: &State,
) -> Result<()> {
    let pending = state
        .pending
        .as_ref()
        .ok_or("Admin must prepare the exact release before slot writes")?;
    if pending.candidate.manifest != bundle.manifest
        || pending.candidate.manifest_json.as_bytes() != bundle.manifest_bytes
        || pending.candidate.signature_hex != bundle::hex(&bundle.signature)
        || pending.trust_version != state.trust.trust.version
        || pending.trust_sha256 != state.trust.digest()?
        || bundle.manifest.sequence != state.floor
    {
        return Err(
            "update does not match the current exact TPM-anchored release admission".into(),
        );
    }
    pending.candidate.verify(&state.trust)
}

pub(crate) fn check_effect_time(
    state: &State,
    interval: crate::utc_bounds::Interval,
) -> Result<()> {
    let admission = state
        .pending
        .as_ref()
        .ok_or("no current exact release admission")?;
    if admission.trust_version != state.trust.trust.version
        || admission.trust_sha256 != state.trust.digest()?
    {
        return Err(
            "release trust rotated after admission; resolve and re-admit at a higher sequence"
                .into(),
        );
    }
    admission.candidate.check_time(&state.trust, interval)
}

fn public_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() == 0 || m.len() > 4096 {
        return Err("release root must be a bounded root-owned immutable image file".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len() {
        return Err("release root changed during observation".into());
    }
    Ok(bytes)
}

fn sealed(name: &str, bytes: &[u8]) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    f.seek(SeekFrom::Start(0))?;
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(f)
}

pub(crate) fn public_der(pem: &[u8]) -> Result<Vec<u8>> {
    let key = sealed("luma-release-root", pem)?;
    let output = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("PATH", "/usr/bin")
        .args(["pkey", "-pubin", "-in"])
        .arg(format!("/proc/self/fd/{}", key.as_raw_fd()))
        .args(["-outform", "DER"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success()
        || output.stdout.len() != 44
        || !output.stdout.starts_with(&ED25519_SPKI)
    {
        return Err("release root must be an exact Ed25519 public key".into());
    }
    Ok(output.stdout)
}

pub(crate) fn verify_der(key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if key.len() != 44
        || !key.starts_with(&ED25519_SPKI)
        || signature.len() != 64
        || message.is_empty()
    {
        return Err("invalid Ed25519 release verification input".into());
    }
    let key = sealed("luma-release-key", key)?;
    let message = sealed("luma-release-message", message)?;
    let signature = sealed("luma-release-signature", signature)?;
    let status = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("PATH", "/usr/bin")
        .args(["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey"])
        .arg(format!("/proc/self/fd/{}", key.as_raw_fd()))
        .args(["-rawin", "-in"])
        .arg(format!("/proc/self/fd/{}", message.as_raw_fd()))
        .arg("-sigfile")
        .arg(format!("/proc/self/fd/{}", signature.as_raw_fd()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Ed25519 release signature rejected".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(sequence: u64) -> Manifest {
        let root_bytes = 512 * 1024 * 1024;
        let hash_bytes = 8 * 1024 * 1024;
        Manifest {
            schema_version: 1,
            release: format!("release-{sequence}"),
            sequence,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
            root_hash: "1".repeat(64),
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
            .map(|name| bundle::Artifact {
                name: (*name).into(),
                bytes: match *name {
                    "root.ext4" => root_bytes,
                    "root.verity" => hash_bytes,
                    _ => 4096,
                },
                sha256: "2".repeat(64),
            })
            .collect(),
        }
    }
    fn trust() -> SignedTrust {
        SignedTrust {
            trust: Trust {
                schema_version: 1,
                environment: "lab".into(),
                version: 1,
                root_sha256: "3".repeat(64),
                not_before_ms: 100,
                expires_ms: 1_000_000,
                keys: vec![Key {
                    id: "releaseKey".into(),
                    public_key_hex: "4".repeat(64),
                    purpose: "os-release".into(),
                    not_before_ms: 100,
                    expires_ms: 999_000,
                    revoked: false,
                }],
            },
            signature_hex: "5".repeat(128),
        }
    }
    fn release(sequence: u64) -> SignedRelease {
        let m = manifest(sequence);
        SignedRelease {
            manifest_json: serde_json::to_string(&m).unwrap(),
            manifest: m,
            signature_hex: "6".repeat(128),
            signer: "releaseKey".into(),
        }
    }
    fn initialized() -> Option<State> {
        let mut s = None;
        publish(&mut s, 0, &trust()).unwrap();
        initialize(&mut s, &release(10)).unwrap();
        s
    }
    fn admission(s: &Option<State>, sequence: u64) -> Admission {
        let s = s.as_ref().unwrap();
        Admission {
            prior: s.acknowledged.clone().unwrap(),
            candidate: release(sequence),
            trust_version: s.trust.trust.version,
            trust_sha256: s.trust.digest().unwrap(),
        }
    }
    #[test]
    fn initial_anchor_is_once_only_and_cannot_reset_floor() {
        let mut s = initialized();
        assert_eq!(s.as_ref().unwrap().floor, 10);
        assert!(initialize(&mut s, &release(1)).is_err());
        assert_eq!(s.as_ref().unwrap().acknowledged, Some(manifest(10)));
    }
    #[test]
    fn fallback_and_abandon_never_decrease_admission_floor() {
        for outcome in [Outcome::Fallback, Outcome::Abandoned] {
            let mut s = initialized();
            let a = admission(&s, 12);
            prepare(&mut s, 10, &a).unwrap();
            assert_eq!(s.as_ref().unwrap().floor, 12);
            resolve(&mut s, &a.candidate.digest().unwrap(), outcome).unwrap();
            assert_eq!(s.as_ref().unwrap().floor, 12);
            assert_eq!(s.as_ref().unwrap().acknowledged, Some(manifest(10)));
            let lower = admission(&s, 11);
            assert!(prepare(&mut s, 12, &lower).is_err());
            let higher = admission(&s, 13);
            prepare(&mut s, 12, &higher).unwrap();
        }
    }
    #[test]
    fn confirmed_candidate_retains_exact_prior_and_retires_pending() {
        let mut s = initialized();
        let a = admission(&s, 12);
        prepare(&mut s, 10, &a).unwrap();
        resolve(&mut s, &a.candidate.digest().unwrap(), Outcome::Confirmed).unwrap();
        let s = s.unwrap();
        assert_eq!(s.floor, 12);
        assert_eq!(s.acknowledged, Some(manifest(12)));
        assert_eq!(s.retained, Some(manifest(10)));
        assert!(s.pending.is_none());
    }
    #[test]
    fn rotation_preserves_identities_and_revocations_irreversibly() {
        let mut s = initialized();
        let mut next = trust();
        next.trust.version = 2;
        next.trust.keys[0].revoked = true;
        next.trust.keys.push(Key {
            id: "replacement".into(),
            public_key_hex: "7".repeat(64),
            purpose: "os-release".into(),
            not_before_ms: 100,
            expires_ms: 999_000,
            revoked: false,
        });
        publish(&mut s, 1, &next).unwrap();
        let mut bad = next.clone();
        bad.trust.version = 3;
        bad.trust.keys[0].revoked = false;
        assert!(publish(&mut s, 2, &bad).is_err());
        bad = next.clone();
        bad.trust.version = 3;
        bad.trust.keys.remove(0);
        assert!(publish(&mut s, 2, &bad).is_err());
        bad = next.clone();
        bad.trust.version = 3;
        bad.trust.keys[0].public_key_hex = "8".repeat(64);
        assert!(publish(&mut s, 2, &bad).is_err());
        bad = next.clone();
        bad.trust.version = 3;
        bad.trust.root_sha256 = "9".repeat(64);
        assert!(publish(&mut s, 2, &bad).is_err());
        assert_eq!(s.as_ref().unwrap().trust, next);
    }
    #[test]
    fn pending_revocation_fences_confirm_but_preserves_safe_fallback() {
        let mut s = initialized();
        let a = admission(&s, 12);
        prepare(&mut s, 10, &a).unwrap();
        let mut next = trust();
        next.trust.version = 2;
        next.trust.keys[0].revoked = true;
        publish(&mut s, 1, &next).unwrap();
        assert!(resolve(&mut s, &a.candidate.digest().unwrap(), Outcome::Confirmed).is_err());
        assert!(check_effect_time(
            s.as_ref().unwrap(),
            crate::utc_bounds::Interval::new(200, 201).unwrap()
        )
        .is_err());
        resolve(&mut s, &a.candidate.digest().unwrap(), Outcome::Fallback).unwrap();
        assert_eq!(s.as_ref().unwrap().floor, 12);
    }
    #[test]
    fn prepare_rejects_geometry_environment_identity_and_version_changes_atomically() {
        let original = initialized();
        let a = admission(&original, 12);
        for case in 0..7 {
            let mut s = original.clone();
            let mut bad = a.clone();
            match case {
                0 => bad.prior.sequence = 9,
                1 => bad.trust_version = 2,
                2 => bad.trust_sha256 = "a".repeat(64),
                3 => {
                    bad.candidate.manifest.environment = "production".into();
                    bad.candidate.manifest_json =
                        serde_json::to_string(&bad.candidate.manifest).unwrap();
                }
                4 => {
                    bad.candidate.manifest.edition = "desktop".into();
                    bad.candidate.manifest_json =
                        serde_json::to_string(&bad.candidate.manifest).unwrap();
                }
                5 => {
                    bad.candidate.manifest.root_bytes *= 2;
                    bad.candidate.manifest_json =
                        serde_json::to_string(&bad.candidate.manifest).unwrap();
                }
                _ => bad.candidate.signer = "unknown".into(),
            }
            assert!(prepare(&mut s, 10, &bad).is_err(), "case {case}");
            assert_eq!(s, original);
        }
    }
    #[test]
    fn pending_is_not_replaced_and_digest_resolution_is_exact() {
        let mut s = initialized();
        let a = admission(&s, 12);
        prepare(&mut s, 10, &a).unwrap();
        let saved = s.clone();
        assert!(prepare(&mut s, 12, &a).is_err());
        assert!(resolve(&mut s, &"a".repeat(64), Outcome::Abandoned).is_err());
        assert_eq!(s, saved);
    }
    #[test]
    fn exact_signed_json_and_closed_fields_cannot_be_substituted() {
        let mut r = release(12);
        r.manifest_json = r.manifest_json.replace("release-12", "release-13");
        assert!(r.validate().is_err());
        let encoded = serde_json::to_string(&trust()).unwrap();
        let duplicate = encoded.replacen("{", "{\"signature_hex\":\"x\",", 1);
        assert!(serde_json::from_str::<SignedTrust>(&duplicate).is_err());
        let extra = encoded.replacen("{", "{\"admin_override\":true,", 1);
        assert!(serde_json::from_str::<SignedTrust>(&extra).is_err());
    }
    #[test]
    fn protected_interval_edges_and_expiry_are_exact() {
        let t = trust();
        let r = release(12);
        for (low, high, accepted) in [
            (100, 100, true),
            (99, 100, false),
            (998_999, 998_999, true),
            (998_999, 999_000, false),
        ] {
            assert_eq!(
                r.check_time(&t, crate::utc_bounds::Interval::new(low, high).unwrap())
                    .is_ok(),
                accepted
            );
        }
    }
    #[test]
    fn production_root_and_delegated_release_purposes_are_separated() {
        let mut t = trust();
        t.trust.environment = "production".into();
        let mut der = ED25519_SPKI.to_vec();
        der.extend_from_slice(&crate::tpm::decode::<32>(&t.trust.keys[0].public_key_hex).unwrap());
        t.trust.root_sha256 = bundle::hex(&Sha256::digest(der));
        assert!(t.validate().is_err());
        t.trust.environment = "lab".into();
        t.validate().unwrap();
        t.trust.keys[0].purpose = "model-pack-manifest".into();
        assert!(t.validate().is_err());
    }
    fn generated_key() -> (Vec<u8>, Vec<u8>) {
        let output = Command::new("/usr/bin/openssl")
            .env_clear()
            .env("PATH", "/usr/bin")
            .args(["genpkey", "-algorithm", "ED25519"])
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        let private = output.stdout;
        let fd = sealed("luma-test-signing-key", &private).unwrap();
        let out = Command::new("/usr/bin/openssl")
            .env_clear()
            .env("PATH", "/usr/bin")
            .args(["pkey", "-in"])
            .arg(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .arg("-pubout")
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        (private, out.stdout)
    }
    fn sign(private: &[u8], message: &[u8]) -> Vec<u8> {
        let key = sealed("luma-test-signing-key", private).unwrap();
        let data = sealed("luma-test-signed-message", message).unwrap();
        let out = Command::new("/usr/bin/openssl")
            .env_clear()
            .env("PATH", "/usr/bin")
            .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(format!("/proc/self/fd/{}", key.as_raw_fd()))
            .arg("-in")
            .arg(format!("/proc/self/fd/{}", data.as_raw_fd()))
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 64);
        out.stdout
    }
    #[test]
    fn real_ed25519_root_release_rotation_revocation_and_tamper() {
        let (root_private, root_public) = generated_key();
        let (key_private, key_public) = generated_key();
        let mut t = trust();
        t.trust.root_sha256 = bundle::hex(&Sha256::digest(public_der(&root_public).unwrap()));
        t.trust.keys[0].public_key_hex = bundle::hex(&public_der(&key_public).unwrap()[12..]);
        t.signature_hex = bundle::hex(&sign(&root_private, &t.signing_bytes().unwrap()));
        t.verify_root_bytes(&root_public).unwrap();
        let mut r = release(12);
        r.signature_hex = bundle::hex(&sign(&key_private, r.manifest_json.as_bytes()));
        r.verify(&t).unwrap();
        let mut changed = t.clone();
        changed.trust.version = 2;
        assert!(changed.verify_root_bytes(&root_public).is_err());
        let mut changed = r.clone();
        changed.manifest.root_hash = "b".repeat(64);
        changed.manifest_json = serde_json::to_string(&changed.manifest).unwrap();
        assert!(changed.verify(&t).is_err());
        t.trust.version = 2;
        t.trust.keys[0].revoked = true;
        t.signature_hex = bundle::hex(&sign(&root_private, &t.signing_bytes().unwrap()));
        t.verify_root_bytes(&root_public).unwrap();
        assert!(r.verify(&t).is_err());
        let (_, wrong_root) = generated_key();
        assert!(t.verify_root_bytes(&wrong_root).is_err());
    }
    #[test]
    fn inert_staging_real_signatures_preserve_exact_bytes_but_never_create_timed_activation() {
        let (root_private, root_public) = generated_key();
        let (delegate_private, delegate_public) = generated_key();
        let mut t = trust();
        t.trust.environment = "production".into();
        t.trust.root_sha256 = bundle::hex(&Sha256::digest(public_der(&root_public).unwrap()));
        t.trust.keys[0].public_key_hex = bundle::hex(&public_der(&delegate_public).unwrap()[12..]);
        t.signature_hex = bundle::hex(&sign(&root_private, &t.signing_bytes().unwrap()));
        t.verify_root_bytes(&root_public).unwrap();
        let mut manifest = manifest(10);
        manifest.environment = "production".into();
        let bytes = serde_json::to_string_pretty(&manifest).unwrap();
        let mut staged = StagedRelease {
            schema_version: 1,
            trust: t,
            manifest_json: bytes.clone(),
            signature_hex: bundle::hex(&sign(&delegate_private, bytes.as_bytes())),
        };
        let release = staged.parse_verified_root().unwrap();
        assert_eq!(release.manifest_json, bytes);
        release
            .check_time(
                &staged.trust,
                crate::utc_bounds::Interval::new(200, 201).unwrap(),
            )
            .unwrap();
        assert!(release
            .check_time(
                &staged.trust,
                crate::utc_bounds::Interval::new(999_000, 999_001).unwrap()
            )
            .is_err());
        // Finite activation refusal does not turn structural offline staging
        // into a wall-clock fallback; its output still supplies no UTC value.
        staged.parse_verified_root().unwrap();
        staged.manifest_json = staged.manifest_json.replace("release-10", "release-11");
        assert!(staged.parse_verified_root().is_err());
        staged.manifest_json = bytes;
        staged.signature_hex = "0".repeat(128);
        assert!(staged.parse_verified_root().is_err());
    }
    #[test]
    fn retained_repair_identity_cannot_lower_floor_substitute_metadata_or_reuse_changed_pending_trust(
    ) {
        let mut value = initialized();
        let first = admission(&value, 12);
        prepare(&mut value, 10, &first).unwrap();
        let state = value.as_ref().unwrap();
        repair_identity(state, &first.prior).unwrap();
        repair_identity(state, &first.candidate.manifest).unwrap();
        let floor = state.floor;
        let mut changed = first.candidate.manifest.clone();
        changed.root_hash = "e".repeat(64);
        assert!(repair_identity(state, &changed).is_err());
        assert!(repair_identity(state, &manifest(9)).is_err());
        assert!(repair_identity(state, &manifest(13)).is_err());
        let mut rotated = state.clone();
        rotated.trust.trust.version += 1;
        assert!(repair_identity(&rotated, &first.candidate.manifest).is_err());
        repair_identity(&rotated, &first.prior).unwrap();
        resolve(
            &mut value,
            &first.candidate.digest().unwrap(),
            Outcome::Confirmed,
        )
        .unwrap();
        let state = value.as_ref().unwrap();
        repair_identity(state, &first.prior).unwrap();
        repair_identity(state, &first.candidate.manifest).unwrap();
        assert_eq!(state.floor, floor);
        assert_eq!(state.retained.as_ref(), Some(&first.prior));
    }
}
