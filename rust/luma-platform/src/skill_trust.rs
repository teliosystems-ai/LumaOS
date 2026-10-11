//! Purpose-separated skill registry trust in the existing Admin TPM journal.
//! Historical reductions retain facts; only live reconstruction admits work.
use crate::{bundle, release_trust, utc_bounds::Interval, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

const DOMAIN: &str = "skill-registry";
const ROLE: &str = "skill-registry-signer";
const POLICY: &str = "closed-file-to-artifact-v1";
const MAX_BUNDLE: usize = 32768;
const ED25519_SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(value)?)))
}
fn hash(value: &str) -> bool {
    crate::artifacts::hash(value)
}
fn validity(start: i64, end: i64) -> Result<()> {
    if start <= 0 || end <= start || end > 4_102_444_800_000 || end.checked_sub(start).is_none() {
        return Err("skill trust validity must be positive and finite".into());
    }
    Ok(())
}
fn finite(start: i64, end: i64) -> Result<()> {
    validity(start, end)?;
    if end - start > 366 * 86_400_000 {
        return Err("skill trust interval exceeds 366 days".into());
    }
    Ok(())
}
fn environment(value: &str) -> bool {
    matches!(value, "lab" | "production")
}
fn key_der(public: &str) -> Result<Vec<u8>> {
    let key = crate::tpm::decode::<32>(public)?;
    if key == [0; 32] || bundle::hex(&key) != public {
        return Err("skill signer requires a canonical nonzero Ed25519 public key".into());
    }
    let mut der = ED25519_SPKI.to_vec();
    der.extend_from_slice(&key);
    Ok(der)
}
fn fingerprint(der: &[u8]) -> String {
    bundle::hex(&Sha256::digest(der))
}
fn signature(value: &str) -> Result<[u8; 64]> {
    let bytes = crate::tpm::decode::<64>(value)?;
    if bundle::hex(&bytes) != value {
        return Err("skill signature requires canonical lowercase hexadecimal".into());
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootPolicy {
    pub schema_version: u32,
    pub environment: String,
    pub domain: String,
    pub purpose: String,
    pub root_sha256: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub separated_key_sha256: Vec<String>,
}
impl RootPolicy {
    fn validate(&self) -> Result<()> {
        validity(self.not_before_ms, self.expires_ms)?;
        let distinct: BTreeSet<_> = self.separated_key_sha256.iter().collect();
        if self.schema_version != 1
            || !environment(&self.environment)
            || self.domain != DOMAIN
            || self.purpose != DOMAIN
            || !hash(&self.root_sha256)
            || self.separated_key_sha256.len() > 128
            || distinct.len() != self.separated_key_sha256.len()
            || self
                .separated_key_sha256
                .iter()
                .any(|key| !hash(key) || key == &self.root_sha256)
        {
            return Err("invalid independently provisioned skill root policy".into());
        }
        Ok(())
    }
    fn contains(&self, trust: &Trust) -> Result<()> {
        self.validate()?;
        if trust.environment != self.environment
            || trust.root_sha256 != self.root_sha256
            || trust.not_before_ms < self.not_before_ms
            || trust.expires_ms > self.expires_ms
        {
            return Err(
                "skill bundle escapes its immutable root environment or effective validity".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Key {
    pub id: String,
    pub public_key_hex: String,
    pub role: String,
    pub purpose: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub revoked: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trust {
    pub schema_version: u32,
    pub environment: String,
    pub domain: String,
    pub purpose: String,
    pub policy: String,
    pub version: u64,
    pub previous_sha256: String,
    pub root_sha256: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub keys: Vec<Key>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedTrust {
    pub trust: Trust,
    pub signature_hex: String,
}
impl SignedTrust {
    pub(crate) fn validate(&self) -> Result<()> {
        let trust = &self.trust;
        finite(trust.not_before_ms, trust.expires_ms)?;
        signature(&self.signature_hex)?;
        let mut ids = BTreeSet::new();
        let mut public = BTreeSet::new();
        if trust.schema_version != 1
            || !environment(&trust.environment)
            || trust.domain != DOMAIN
            || trust.purpose != DOMAIN
            || trust.policy != POLICY
            || trust.version == 0
            || trust.version > i64::MAX as u64
            || !hash(&trust.previous_sha256)
            || !hash(&trust.root_sha256)
            || trust.keys.is_empty()
            || trust.keys.len() > 64
            || serde_json::to_vec(self)?.len() > MAX_BUNDLE
        {
            return Err("invalid bounded purpose-separated skill trust bundle".into());
        }
        for key in &trust.keys {
            finite(key.not_before_ms, key.expires_ms)?;
            let der = key_der(&key.public_key_hex)?;
            if !crate::admin_roles::identifier(&key.id)
                || key.role != ROLE
                || key.purpose != DOMAIN
                || !ids.insert(&key.id)
                || !public.insert(&key.public_key_hex)
                || fingerprint(&der) == trust.root_sha256
                || key.not_before_ms < trust.not_before_ms
                || key.expires_ms > trust.expires_ms
            {
                return Err(
                    "skill leaf identity/purpose/role/validity is invalid or reuses its root"
                        .into(),
                );
            }
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
    fn key(&self, id: &str) -> Result<&Key> {
        self.trust
            .keys
            .iter()
            .find(|key| key.id == id && !key.revoked)
            .ok_or_else(|| "unknown or revoked skill registry signer".into())
    }
    fn root(&self, release: &Option<release_trust::State>) -> Result<()> {
        self.validate()?;
        let (key_path, policy_path) = if self.trust.environment == "production" {
            (
                "/usr/share/luma-os/production-skill-root.pub",
                "/usr/share/luma-os/production-skill-root-policy.json",
            )
        } else {
            (
                "/usr/share/luma-os/skill-trust-root.pub",
                "/usr/share/luma-os/skill-trust-root-policy.json",
            )
        };
        let policy: RootPolicy = serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new(policy_path),
            32768,
        )?)?;
        policy.contains(&self.trust)?;
        let root = release_trust::public_der(&crate::admin_credentials::public_input(
            Path::new(key_path),
            4096,
        )?)?;
        if fingerprint(&root) != policy.root_sha256 {
            return Err("skill root DER differs from immutable root policy".into());
        }
        let mut prohibited = policy
            .separated_key_sha256
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for other in [
            "/usr/share/luma-os/release.pub",
            "/usr/share/luma-os/production-release-root.pub",
            "/usr/share/luma-os/model-catalog.pub",
            "/usr/share/luma-os/model-pack-root.pub",
        ] {
            if let Some(key) = optional_public(other)? {
                prohibited.insert(fingerprint(&release_trust::public_der(&key)?));
            }
        }
        let opposite = if self.trust.environment == "production" {
            "/usr/share/luma-os/skill-trust-root.pub"
        } else {
            "/usr/share/luma-os/production-skill-root.pub"
        };
        if let Some(key) = optional_public(opposite)? {
            prohibited.insert(fingerprint(&release_trust::public_der(&key)?));
        }
        if self.trust.environment == "production" {
            if let Some(key) = optional_public("/usr/share/luma-os/skills/skills.pub")? {
                prohibited.insert(fingerprint(&release_trust::public_der(&key)?));
            }
        }
        if let Some(os) = release {
            prohibited.insert(os.trust.trust.root_sha256.clone());
            for key in &os.trust.trust.keys {
                prohibited.insert(fingerprint(&key_der(&key.public_key_hex)?));
            }
        }
        check_separation(&self.trust, &prohibited)?;
        release_trust::verify_der(
            &root,
            &serde_json::to_vec(&self.trust)?,
            &crate::tpm::decode::<64>(&self.signature_hex)?,
        )
    }
    fn check_time(&self, interval: Interval) -> Result<()> {
        if !interval.within(self.trust.not_before_ms, self.trust.expires_ms)? {
            return Err("skill trust excludes the entire protected UTC interval".into());
        }
        Ok(())
    }
}
fn optional_public(path: &str) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(Some(crate::admin_credentials::public_input(
            Path::new(path),
            4096,
        )?)),
    }
}
fn check_separation(trust: &Trust, prohibited: &BTreeSet<String>) -> Result<()> {
    if prohibited.contains(&trust.root_sha256)
        || trust
            .keys
            .iter()
            .map(|key| key_der(&key.public_key_hex))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|key| prohibited.contains(&fingerprint(key)))
    {
        return Err(
            "skill registry root/leaf reuses another environment or OS/model signing identity"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryAdmission {
    pub schema_version: u32,
    pub environment: String,
    pub domain: String,
    pub purpose: String,
    pub policy: String,
    pub sequence: u64,
    pub trust_version: u64,
    pub trust_sha256: String,
    pub registry_sha256: String,
    pub workflow_sha256: String,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub signer: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    pub metadata: RegistryAdmission,
    pub signature_hex: String,
}
impl Admission {
    pub(crate) fn validate(&self) -> Result<()> {
        let meta = &self.metadata;
        finite(meta.not_before_ms, meta.expires_ms)?;
        signature(&self.signature_hex)?;
        if meta.schema_version != 1
            || !environment(&meta.environment)
            || meta.domain != DOMAIN
            || meta.purpose != DOMAIN
            || meta.policy != POLICY
            || meta.sequence == 0
            || meta.sequence > i64::MAX as u64
            || meta.trust_version == 0
            || !hash(&meta.trust_sha256)
            || !hash(&meta.registry_sha256)
            || !hash(&meta.workflow_sha256)
            || !crate::admin_roles::identifier(&meta.signer)
            || serde_json::to_vec(self)?.len() > 4096
        {
            return Err("invalid finite signed skill registry admission metadata".into());
        }
        Ok(())
    }
    fn binding(&self, trust: &SignedTrust) -> Result<()> {
        self.validate()?;
        trust.validate()?;
        let meta = &self.metadata;
        let key = trust.key(&meta.signer)?;
        if meta.environment != trust.trust.environment
            || meta.trust_version != trust.trust.version
            || meta.trust_sha256 != trust.digest()?
            || meta.not_before_ms < key.not_before_ms
            || meta.expires_ms > key.expires_ms
        {
            return Err("registry admission does not bind the exact current skill trust and contained leaf validity".into());
        }
        Ok(())
    }
    fn verify(&self, trust: &SignedTrust) -> Result<()> {
        self.binding(trust)?;
        release_trust::verify_der(
            &key_der(&trust.key(&self.metadata.signer)?.public_key_hex)?,
            &serde_json::to_vec(&self.metadata)?,
            &crate::tpm::decode::<64>(&self.signature_hex)?,
        )
    }
    fn check_time(&self, trust: &SignedTrust, interval: Interval) -> Result<()> {
        trust.check_time(interval)?;
        let key = trust.key(&self.metadata.signer)?;
        if !interval.within(key.not_before_ms, key.expires_ms)?
            || !interval.within(self.metadata.not_before_ms, self.metadata.expires_ms)?
        {
            return Err(
                "registry signer/admission excludes the entire protected UTC interval".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct State {
    pub trust: SignedTrust,
    pub floor: u64,
    pub current: Option<Admission>,
}
pub(crate) fn publish(state: &mut Option<State>, expected: u64, next: &SignedTrust) -> Result<()> {
    next.validate()?;
    let prior = state.as_ref();
    if expected != prior.map_or(0, |state| state.trust.trust.version)
        || next.trust.version
            != expected
                .checked_add(1)
                .ok_or("skill trust version exhausted")?
        || next.trust.previous_sha256
            != prior
                .map(|state| state.trust.digest())
                .transpose()?
                .unwrap_or("0".repeat(64))
    {
        return Err(
            "skill trust publication requires the exact current version and predecessor".into(),
        );
    }
    if let Some(prior) = prior {
        if next.trust.environment != prior.trust.trust.environment
            || next.trust.root_sha256 != prior.trust.trust.root_sha256
        {
            return Err(
                "skill publication cannot replace the provisioned root or environment".into(),
            );
        }
        for key in &prior.trust.trust.keys {
            let replacement = next
                .trust
                .keys
                .iter()
                .find(|candidate| candidate.id == key.id)
                .ok_or("skill trust must retain historical signer identities")?;
            if key.public_key_hex != replacement.public_key_hex
                || (key.revoked && !replacement.revoked)
            {
                return Err("skill signer identity reuse or revocation reversal refused".into());
            }
        }
    }
    let mut next_state = prior.cloned().unwrap_or(State {
        trust: next.clone(),
        floor: 0,
        current: None,
    });
    next_state.trust = next.clone();
    *state = Some(next_state);
    Ok(())
}
pub(crate) fn admit(
    state: &mut Option<State>,
    expected_floor: u64,
    admission: &Admission,
) -> Result<()> {
    let current = state
        .as_mut()
        .ok_or("skill trust must be anchored before registry admission")?;
    admission.binding(&current.trust)?;
    if expected_floor != current.floor
        || admission.metadata.sequence < current.floor
        || (admission.metadata.sequence == current.floor
            && current.current.as_ref() != Some(admission))
    {
        return Err("skill registry admission lowers a floor, changes a same-sequence digest or uses a stale review".into());
    }
    current.floor = admission.metadata.sequence;
    current.current = Some(admission.clone());
    Ok(())
}
fn current(state: &State) -> Result<&Admission> {
    let admission = state
        .current
        .as_ref()
        .ok_or("no committed skill registry admission")?;
    admission.binding(&state.trust)?;
    if admission.metadata.sequence != state.floor {
        return Err("skill registry admission differs from its current monotonic floor".into());
    }
    Ok(admission)
}
fn production_release(environment: &str, release: &Option<release_trust::State>) -> Result<()> {
    if environment == "production" {
        let release = release
            .as_ref()
            .ok_or("production skills require activated anchored OS release authority")?;
        if release.trust.trust.environment != "production" {
            return Err("production skills cannot use laboratory OS release authority".into());
        }
        crate::platform::check_governance_manifest(
            release
                .acknowledged
                .as_ref()
                .ok_or("production skills require acknowledged release activation")?,
        )?;
    }
    Ok(())
}
fn immutable_content(admission: &Admission) -> Result<()> {
    let registry = crate::admin_credentials::public_input(
        Path::new("/usr/share/luma-os/skills/registry.json"),
        4096,
    )?;
    let graph = crate::admin_credentials::public_input(
        Path::new("/usr/share/luma-os/workflows/file-to-artifact-v1.json"),
        65536,
    )?;
    crate::skills::validate_governed(&registry, &graph)?;
    if fingerprint(&registry) != admission.metadata.registry_sha256
        || fingerprint(&graph) != admission.metadata.workflow_sha256
    {
        return Err(
            "skill registry admission differs from exact immutable registry/graph bytes".into(),
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&registry)?;
    if value["environment"] != admission.metadata.environment {
        return Err("registry and signed admission environments differ".into());
    }
    Ok(())
}
pub(crate) fn is_command(command: &crate::admin_roles::Command) -> bool {
    matches!(
        command,
        crate::admin_roles::Command::PublishSkillTrust { .. }
            | crate::admin_roles::Command::AdmitSkillRegistry { .. }
    )
}
pub(crate) fn check_live(
    command: &crate::admin_roles::Command,
    state: &Option<State>,
    release: &Option<release_trust::State>,
    interval: Interval,
) -> Result<()> {
    match command {
        crate::admin_roles::Command::PublishSkillTrust { bundle, .. } => {
            production_release(&bundle.trust.environment, release)?;
            bundle.root(release)?;
            bundle.check_time(interval)
        }
        crate::admin_roles::Command::AdmitSkillRegistry { admission, .. } => {
            let state = state
                .as_ref()
                .ok_or("skill registry admission requires anchored trust")?;
            production_release(&admission.metadata.environment, release)?;
            state.trust.root(release)?;
            admission.verify(&state.trust)?;
            immutable_content(admission)?;
            admission.check_time(&state.trust, interval)
        }
        _ => Ok(()),
    }
}
pub(crate) fn check_command_time(
    command: &crate::admin_roles::Command,
    state: &Option<State>,
    interval: Interval,
) -> Result<()> {
    match command {
        crate::admin_roles::Command::PublishSkillTrust { bundle, .. } => {
            bundle.check_time(interval)
        }
        crate::admin_roles::Command::AdmitSkillRegistry { admission, .. } => admission.check_time(
            &state.as_ref().ok_or("missing skill trust")?.trust,
            interval,
        ),
        _ => Ok(()),
    }
}
pub(crate) fn verify_installed(
    registry: &[u8],
    graph: &[u8],
    mut recheck_content: impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    crate::platform::require_production_activation()?;
    let first = crate::admin_governance::skill_authority()?;
    let state = first
        .0
        .as_ref()
        .ok_or("governed registry requires committed skill trust")?;
    let admission = current(state)?;
    production_release(&admission.metadata.environment, &first.2)?;
    state.trust.root(&first.2)?;
    admission.verify(&state.trust)?;
    if fingerprint(registry) != admission.metadata.registry_sha256
        || fingerprint(graph) != admission.metadata.workflow_sha256
    {
        return Err("current governed skill registry/graph digest changed".into());
    }
    let content = crate::skills::validate_governed(registry, graph)?;
    if content["environment"] != admission.metadata.environment {
        return Err("governed registry environment differs from current signed admission".into());
    }
    recheck_content()?;
    let last = crate::admin_governance::skill_authority()?;
    if first.0 != last.0 || first.2 != last.2 {
        return Err(
            "skill/OS release authority changed during immutable package verification".into(),
        );
    }
    admission.check_time(&state.trust, last.1)?;
    Ok(
        serde_json::json!({"skill_trust_version":state.trust.trust.version,"skill_registry_sequence":state.floor,
        "signing_purpose":DOMAIN,"signing_role":ROLE,"environment":admission.metadata.environment,
        "authority_restored":false,"effect_grant":false,"gate_closing":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trust() -> SignedTrust {
        SignedTrust {
            trust: Trust {
                schema_version: 1,
                environment: "lab".into(),
                domain: DOMAIN.into(),
                purpose: DOMAIN.into(),
                policy: POLICY.into(),
                version: 1,
                previous_sha256: "0".repeat(64),
                root_sha256: "2".repeat(64),
                not_before_ms: 1000,
                expires_ms: 10000,
                keys: vec![Key {
                    id: "skill-a".into(),
                    public_key_hex: "1".repeat(64),
                    role: ROLE.into(),
                    purpose: DOMAIN.into(),
                    not_before_ms: 1100,
                    expires_ms: 9000,
                    revoked: false,
                }],
            },
            signature_hex: "3".repeat(128),
        }
    }
    fn admission(trust: &SignedTrust, sequence: u64) -> Admission {
        Admission {
            metadata: RegistryAdmission {
                schema_version: 1,
                environment: trust.trust.environment.clone(),
                domain: DOMAIN.into(),
                purpose: DOMAIN.into(),
                policy: POLICY.into(),
                sequence,
                trust_version: trust.trust.version,
                trust_sha256: trust.digest().unwrap(),
                registry_sha256: "4".repeat(64),
                workflow_sha256: "5".repeat(64),
                not_before_ms: 1200,
                expires_ms: 8000,
                signer: "skill-a".into(),
            },
            signature_hex: "6".repeat(128),
        }
    }
    fn policy() -> RootPolicy {
        RootPolicy {
            schema_version: 1,
            environment: "lab".into(),
            domain: DOMAIN.into(),
            purpose: DOMAIN.into(),
            root_sha256: "2".repeat(64),
            not_before_ms: 500,
            expires_ms: 11000,
            separated_key_sha256: vec!["7".repeat(64)],
        }
    }
    #[test]
    fn immutable_root_policy_contains_bundle_and_rejects_reuse_wrong_domain_or_environment() {
        let t = trust();
        let p = policy();
        p.contains(&t.trust).unwrap();
        let mut wrong = p.clone();
        wrong.environment = "production".into();
        assert!(wrong.contains(&t.trust).is_err());
        wrong = p.clone();
        wrong.root_sha256 = "8".repeat(64);
        assert!(wrong.contains(&t.trust).is_err());
        wrong = p.clone();
        wrong.not_before_ms = 1001;
        assert!(wrong.contains(&t.trust).is_err());
        wrong = p.clone();
        wrong.expires_ms = 9999;
        assert!(wrong.contains(&t.trust).is_err());
        wrong = p.clone();
        wrong.purpose = "os-release-manifest".into();
        assert!(wrong.validate().is_err());
        wrong = p.clone();
        wrong.separated_key_sha256.push(wrong.root_sha256.clone());
        assert!(wrong.validate().is_err());
        wrong = p.clone();
        wrong.separated_key_sha256.push("7".repeat(64));
        assert!(wrong.validate().is_err());
        assert!(
            serde_json::from_str::<RootPolicy>(r#"{"schema_version":1,"schema_version":1}"#)
                .is_err()
        );
    }
    #[test]
    fn closed_skill_purpose_role_identity_and_unknown_fields_are_not_effect_authority() {
        let t = trust();
        t.validate().unwrap();
        let mut wrong = t.clone();
        wrong.trust.keys[0].purpose = "model-pack-manifest".into();
        assert!(wrong.validate().is_err());
        wrong = t.clone();
        wrong.trust.keys[0].role = "Admin".into();
        assert!(wrong.validate().is_err());
        wrong = t.clone();
        wrong.trust.keys.push(wrong.trust.keys[0].clone());
        assert!(wrong.validate().is_err());
        wrong = t.clone();
        wrong.trust.root_sha256 =
            fingerprint(&key_der(&wrong.trust.keys[0].public_key_hex).unwrap());
        assert!(wrong.validate().is_err());
        wrong = t.clone();
        wrong.trust.keys[0].not_before_ms = 999;
        assert!(wrong.validate().is_err());
        wrong = t.clone();
        wrong.signature_hex = "A".repeat(128);
        assert!(wrong.validate().is_err());
        let mut value = serde_json::to_value(t).unwrap();
        value["trust"]["grant_effect"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<SignedTrust>(value).is_err());
    }
    #[test]
    fn historical_publication_is_monotonic_retains_revocations_and_does_not_consult_live_clock() {
        let t = trust();
        let mut state = None;
        publish(&mut state, 0, &t).unwrap();
        assert!(publish(&mut state, 0, &t).is_err());
        let mut next = t.clone();
        next.trust.version = 2;
        next.trust.previous_sha256 = t.digest().unwrap();
        next.trust.keys[0].revoked = true;
        publish(&mut state, 1, &next).unwrap();
        assert!(next
            .check_time(Interval::new(20000, 20010).unwrap())
            .is_err());
        let mut third = next.clone();
        third.trust.version = 3;
        third.trust.previous_sha256 = next.digest().unwrap();
        third.trust.keys[0].revoked = false;
        assert!(publish(&mut state, 2, &third).is_err());
        third.trust.keys[0].revoked = true;
        third.trust.keys[0].public_key_hex = "9".repeat(64);
        assert!(publish(&mut state, 2, &third).is_err());
        third = next.clone();
        third.trust.version = 3;
        third.trust.previous_sha256 = next.digest().unwrap();
        third.trust.root_sha256 = "9".repeat(64);
        assert!(publish(&mut state, 2, &third).is_err());
        assert_eq!(state.unwrap().trust, next);
    }
    #[test]
    fn finite_admission_floor_exact_replay_and_changed_trust_fences_are_complete() {
        let t = trust();
        let first = admission(&t, 5);
        let mut state = None;
        assert!(admit(&mut state, 0, &first).is_err());
        publish(&mut state, 0, &t).unwrap();
        admit(&mut state, 0, &first).unwrap();
        current(state.as_ref().unwrap()).unwrap();
        admit(&mut state, 5, &first).unwrap();
        let mut changed = first.clone();
        changed.metadata.registry_sha256 = "7".repeat(64);
        assert!(admit(&mut state, 5, &changed).is_err());
        assert!(admit(&mut state, 5, &admission(&t, 4)).is_err());
        assert!(admit(&mut state, 0, &admission(&t, 6)).is_err());
        let mut next = t.clone();
        next.trust.version = 2;
        next.trust.previous_sha256 = t.digest().unwrap();
        publish(&mut state, 1, &next).unwrap();
        assert!(current(state.as_ref().unwrap()).is_err());
        assert!(admit(&mut state, 5, &admission(&next, 5)).is_err());
        admit(&mut state, 5, &admission(&next, 6)).unwrap();
        current(state.as_ref().unwrap()).unwrap();
        let mut revoked = next.clone();
        revoked.trust.version = 3;
        revoked.trust.previous_sha256 = next.digest().unwrap();
        revoked.trust.keys[0].revoked = true;
        publish(&mut state, 2, &revoked).unwrap();
        assert!(current(state.as_ref().unwrap()).is_err());
        assert!(admission(&revoked, 7).binding(&revoked).is_err());
    }
    #[test]
    fn entire_current_interval_must_fit_root_bundle_leaf_and_admission() {
        let t = trust();
        let a = admission(&t, 1);
        a.check_time(&t, Interval::new(1200, 7999).unwrap())
            .unwrap();
        for (lower, upper) in [(1199, 1200), (7999, 8000), (10000, 10001)] {
            assert!(a
                .check_time(&t, Interval::new(lower, upper).unwrap())
                .is_err());
        }
        let mut wrong = a.clone();
        wrong.metadata.environment = "production".into();
        assert!(wrong.binding(&t).is_err());
        wrong = a.clone();
        wrong.metadata.expires_ms = 9001;
        assert!(wrong.binding(&t).is_err());
        wrong = a.clone();
        wrong.metadata.trust_sha256 = "9".repeat(64);
        assert!(wrong.binding(&t).is_err());
    }
    #[test]
    fn immutable_separation_fences_os_model_environment_root_and_leaf_reuse() {
        let t = trust();
        check_separation(&t.trust, &BTreeSet::new()).unwrap();
        for forbidden in [
            t.trust.root_sha256.clone(),
            fingerprint(&key_der(&t.trust.keys[0].public_key_hex).unwrap()),
        ] {
            assert!(check_separation(&t.trust, &[forbidden].into_iter().collect()).is_err());
        }
    }
    #[test]
    fn real_signatures_bind_exact_trust_and_admission_metadata() {
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("luma-skill-trust-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let generate = |name: &str| {
            let private = dir.join(format!("{name}.key"));
            let public = dir.join(format!("{name}.pub"));
            assert!(Command::new("/usr/bin/openssl")
                .env_clear()
                .args(["genpkey", "-algorithm", "ED25519", "-out"])
                .arg(&private)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
            assert!(Command::new("/usr/bin/openssl")
                .env_clear()
                .args(["pkey", "-in"])
                .arg(&private)
                .args(["-pubout", "-out"])
                .arg(&public)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
            (
                private,
                release_trust::public_der(&fs::read(public).unwrap()).unwrap(),
            )
        };
        let sign = |private: &Path, bytes: &[u8]| {
            let data = dir.join("message");
            let signed = dir.join("signature");
            fs::write(&data, bytes).unwrap();
            assert!(Command::new("/usr/bin/openssl")
                .env_clear()
                .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
                .arg(private)
                .arg("-in")
                .arg(data)
                .arg("-out")
                .arg(&signed)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
            fs::read(signed).unwrap()
        };
        let (root_private, root_der) = generate("root");
        let (leaf_private, leaf_der) = generate("leaf");
        let mut t = trust();
        t.trust.root_sha256 = fingerprint(&root_der);
        t.trust.keys[0].public_key_hex = bundle::hex(&leaf_der[12..]);
        let bytes = serde_json::to_vec(&t.trust).unwrap();
        t.signature_hex = bundle::hex(&sign(&root_private, &bytes));
        release_trust::verify_der(&root_der, &bytes, &signature(&t.signature_hex).unwrap())
            .unwrap();
        let mut tampered = t.trust.clone();
        tampered.version = 2;
        assert!(release_trust::verify_der(
            &root_der,
            &serde_json::to_vec(&tampered).unwrap(),
            &signature(&t.signature_hex).unwrap()
        )
        .is_err());
        let mut a = admission(&t, 1);
        a.signature_hex = bundle::hex(&sign(
            &leaf_private,
            &serde_json::to_vec(&a.metadata).unwrap(),
        ));
        a.verify(&t).unwrap();
        a.metadata.registry_sha256 = "7".repeat(64);
        assert!(a.verify(&t).is_err());
        a = admission(&t, 1);
        a.signature_hex = bundle::hex(&sign(
            &root_private,
            &serde_json::to_vec(&a.metadata).unwrap(),
        ));
        assert!(a.verify(&t).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
