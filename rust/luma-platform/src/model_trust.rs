//! Frozen model-distribution formats and public-only live trust verification.
//! Signed artifacts remain inert until original Admin/custodian authorization
//! and the existing TPM journal commit their exact monotonic checkpoints.
use crate::{
    admin_roles::{Catalog, Command},
    bundle,
    utc_bounds::Interval,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

pub(crate) const MAX_TRUST: usize = 1024 * 1024;
pub(crate) const MAX_CATALOG: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE: usize = 1024 * 1024;
const SAFE: u64 = (1 << 53) - 1;
const DOMAIN: &str = "luma-models";
const SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

macro_rules! record {
    ($name:ident { $($(#[$fieldmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name { $($(#[$fieldmeta])* pub $field: $ty),* }
    }
}
fn ascii(text: &str, maximum: usize) -> Result<()> {
    if text.is_empty()
        || text.trim() != text
        || text.len() > maximum
        || !text.bytes().all(|b| (32..=126).contains(&b))
    {
        return Err("model metadata requires bounded trimmed printable ASCII".into());
    }
    Ok(())
}
fn environment(value: &str) -> Result<()> {
    if !matches!(value, "lab" | "production") {
        return Err("model environment must be lab or production".into());
    }
    Ok(())
}
fn positive(value: u64) -> Result<()> {
    if value == 0 || value > SAFE {
        return Err("model integer is outside the positive interoperable range".into());
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if !crate::artifacts::hash(value) {
        return Err("model metadata requires a lowercase SHA256 digest".into());
    }
    Ok(())
}
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    fn domain(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> Result<()> {
        *nodes += 1;
        if depth > 16 || *nodes > 65536 {
            return Err("model JSON exceeds structural bounds".into());
        }
        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) => (),
            serde_json::Value::String(s) if s.bytes().all(|b| (32..=126).contains(&b)) => (),
            serde_json::Value::Number(n)
                if n.as_i64().is_some_and(|v| v.unsigned_abs() <= SAFE)
                    || n.as_u64().is_some_and(|v| v <= SAFE) =>
            {
                ()
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    domain(item, depth + 1, nodes)?;
                }
            }
            serde_json::Value::Object(items) => {
                for (key, item) in items {
                    domain(&serde_json::Value::String(key.clone()), depth + 1, nodes)?;
                    domain(item, depth + 1, nodes)?;
                }
            }
            _ => return Err(
                "model JSON canonical domain excludes floats, unsafe integers and non-ASCII text"
                    .into(),
            ),
        }
        Ok(())
    }
    domain(&value, 1, &mut 0)?;
    Ok(serde_json::to_vec(&value)?)
}
pub(crate) fn parse<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("model artifact exceeds its closed byte bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if canonical(&value)? != bytes {
        return Err(
            "model artifact must have exact canonical ASCII bytes and unique fields".into(),
        );
    }
    Ok(value)
}
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(bundle::hex(&Sha256::digest(canonical(value)?)))
}
pub(crate) fn digest_command(command: &Command) -> Result<String> {
    let mut value = serde_json::to_value(command)?;
    match command {
        Command::RecordModelCatalogApproval { .. } => {
            let a = value["approval"]
                .as_object_mut()
                .ok_or("missing approval intent")?;
            a.remove("approved_at");
            a.remove("approval_decision_receipt_sha256");
        }
        Command::RecordModelCatalogSigning { .. } => {
            value["statement"]
                .as_object_mut()
                .ok_or("missing signing intent")?
                .remove("signed_at");
        }
        _ => (),
    }
    digest(&value)
}
pub(crate) fn utc_timestamp(ms: i64) -> Result<String> {
    if ms < 0 {
        return Err("model decisions require positive protected UTC".into());
    }
    let days = ms.div_euclid(86_400_000);
    let seconds = ms.rem_euclid(86_400_000) / 1000;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    );
    timestamp(&text)?;
    Ok(text)
}
pub(crate) fn timestamp(text: &str) -> Result<i64> {
    let b = text.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err("model timestamps require exact second-precision UTC".into());
    }
    let number = |start: usize, end: usize| -> Result<i64> {
        if !b[start..end].iter().all(u8::is_ascii_digit) {
            return Err("invalid UTC timestamp digits".into());
        }
        Ok(std::str::from_utf8(&b[start..end])?.parse()?)
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year < 1 || day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err("invalid Gregorian UTC timestamp".into());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let total = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Ok((total * 86400 + hour * 3600 + minute * 60 + second) * 1000)
}
fn dates(start: &str, end: &str) -> Result<(i64, i64)> {
    let (start, end) = (timestamp(start)?, timestamp(end)?);
    if end <= start {
        return Err("model lifecycle interval must be nonempty".into());
    }
    Ok((start, end))
}
fn live(start: &str, end: &str, revoked: Option<&str>, interval: Interval) -> Result<()> {
    let (start, mut end) = dates(start, end)?;
    if let Some(revoked) = revoked {
        end = end.min(timestamp(revoked)?);
    }
    if !interval.within(start, end)? {
        return Err("model trust is not valid for the complete protected UTC interval".into());
    }
    Ok(())
}
fn effective(end: &str, revoked: Option<&str>) -> Result<i64> {
    Ok(timestamp(end)?.min(revoked.map(timestamp).transpose()?.unwrap_or(i64::MAX)))
}
pub(crate) fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
pub(crate) fn decode64<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N.div_ceil(3) * 4 {
        return Err("model signature/public key has invalid base64 length".into());
    }
    let mut out = Vec::new();
    for c in text.as_bytes().chunks_exact(4) {
        let mut n = 0u32;
        for b in c {
            let v = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err("invalid model base64".into()),
            };
            n = (n << 6) | u32::from(v);
        }
        out.push((n >> 16) as u8);
        if c[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if c[3] != b'=' {
            out.push(n as u8);
        }
    }
    if out.len() != N || base64(&out) != text {
        return Err("model base64 must be canonical".into());
    }
    Ok(out.try_into().map_err(|_| "model base64 size")?)
}
fn role(purpose: &str) -> Result<&'static str> {
    Ok(match purpose {
        "model-pack-manifest" => "model-pack-signer",
        "model-pack-execution-certification" | "model-pack-interactive-certification" => {
            "model-pack-certification-signer"
        }
        "model-profile-catalog-lab" => "model-profile-catalog-lab-signer",
        "model-profile-catalog-production" => "model-profile-catalog-production-signer",
        _ => return Err("unknown model signing purpose".into()),
    })
}
fn key_fingerprint(public: &[u8; 32]) -> String {
    let mut der = SPKI.to_vec();
    der.extend(public);
    bundle::hex(&Sha256::digest(der))
}
record!(RootAnchor {key_id:String,environment:String,trust_domain:String,public_key:String,not_before:String,not_after:String,revoked_at:Option<String>});
record!(RootPolicy {schema_version:u32,trust_domain:String,accepted_trust_policy_versions:Vec<String>,accepted_catalog_policy_versions:Vec<String>,roots:Vec<RootAnchor>,separated_key_sha256:Vec<String>});
impl RootPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.trust_domain != DOMAIN
            || self.roots.is_empty()
            || self.roots.len() > 32
        {
            return Err("invalid independently provisioned model roots".into());
        }
        for values in [
            &self.accepted_trust_policy_versions,
            &self.accepted_catalog_policy_versions,
        ] {
            if values.is_empty() || values.len() > 32 || values.windows(2).any(|v| v[0] >= v[1]) {
                return Err(
                    "model policy versions must be finite, nonempty and canonically ordered".into(),
                );
            }
            for v in values {
                ascii(v, 256)?;
            }
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for root in &self.roots {
            ascii(&root.key_id, 256)?;
            environment(&root.environment)?;
            if root.trust_domain != DOMAIN
                || !ids.insert(&root.key_id)
                || !keys.insert(decode64::<32>(&root.public_key)?)
            {
                return Err("model roots cannot reuse IDs, keys or domains".into());
            }
            let (start, end) = dates(&root.not_before, &root.not_after)?;
            if root
                .revoked_at
                .as_ref()
                .is_some_and(|v| timestamp(v).map_or(true, |t| t < start || t >= end))
            {
                return Err("invalid model root revocation".into());
            }
        }
        if self.separated_key_sha256.len() > 1024
            || self.separated_key_sha256.windows(2).any(|v| v[0] >= v[1])
        {
            return Err(
                "model separated public keys must be bounded unique ordered digests".into(),
            );
        }
        for h in &self.separated_key_sha256 {
            hash(h)?;
        }
        Ok(())
    }
    pub(crate) fn current() -> Result<Self> {
        let policy: Self = parse(
            &crate::admin_credentials::public_input(
                Path::new("/usr/share/luma-os/model-roots.json"),
                MAX_TRUST as u64,
            )?,
            MAX_TRUST,
        )?;
        policy.validate()?;
        Ok(policy)
    }
}
record!(TrustKey {environment:String,key_id:String,not_after:String,not_before:String,public_key:String,public_key_encoding:String,purposes:Vec<String>,revocation_reason:Option<String>,revoked_at:Option<String>,role:String});
record!(TrustBundle {artifact_type:String,bundle_sequence:u64,environment:String,issued_at:String,keys:Vec<TrustKey>,not_after:String,not_before:String,policy_version:String,previous_bundle_sha256:Option<String>,root_key_id:String,schema_version:u32,trust_domain:String});
record!(SignedTrust {
    bundle: TrustBundle,
    schema_version: u32,
    signature: String,
    signature_algorithm: String,
    signature_encoding: String
});
impl SignedTrust {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_TRUST)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let b = &self.bundle;
        environment(&b.environment)?;
        positive(b.bundle_sequence)?;
        if self.schema_version != 1
            || b.schema_version != 1
            || self.signature_algorithm != "Ed25519"
            || self.signature_encoding != "base64"
            || b.artifact_type != "luma-os-signing-trust-bundle"
            || b.trust_domain != DOMAIN
            || b.keys.is_empty()
            || b.keys.len() > 256
            || canonical(self)?.len() > MAX_TRUST
        {
            return Err("invalid frozen model trust schema/domain/bounds".into());
        }
        decode64::<64>(&self.signature)?;
        ascii(&b.policy_version, 256)?;
        ascii(&b.root_key_id, 256)?;
        if b.bundle_sequence == 1 {
            if b.previous_bundle_sha256.is_some() {
                return Err("genesis model trust cannot carry a predecessor".into());
            }
        } else {
            hash(
                b.previous_bundle_sha256
                    .as_deref()
                    .ok_or("model trust predecessor missing")?,
            )?;
        }
        let (start, end) = dates(&b.not_before, &b.not_after)?;
        let issued = timestamp(&b.issued_at)?;
        if issued < start || issued >= end {
            return Err("model trust issue time escapes validity".into());
        }
        let mut ids = BTreeSet::new();
        let mut public = BTreeSet::new();
        let mut previous = None;
        for k in &b.keys {
            ascii(&k.key_id, 256)?;
            let (ks, ke) = dates(&k.not_before, &k.not_after)?;
            if k.environment != b.environment
                || ks < start
                || ke > end
                || k.public_key_encoding != "raw-ed25519-base64"
                || !ids.insert(&k.key_id)
                || !public.insert(decode64::<32>(&k.public_key)?)
                || previous.is_some_and(|v: &str| v >= k.key_id.as_str())
                || k.purposes.is_empty()
                || k.purposes.windows(2).any(|v| v[0] >= v[1])
            {
                return Err("model leaf identity/order/environment/validity mismatch".into());
            }
            previous = Some(k.key_id.as_str());
            for p in &k.purposes {
                if role(p)? != k.role
                    || (p == "model-profile-catalog-lab" && b.environment != "lab")
                    || (p == "model-profile-catalog-production" && b.environment != "production")
                {
                    return Err("model leaf role/purpose/environment mismatch".into());
                }
            }
            if k.revoked_at.is_some() != k.revocation_reason.is_some() {
                return Err("model revocation time and reason must be paired".into());
            }
            if let Some(v) = &k.revoked_at {
                let t = timestamp(v)?;
                if t < ks || t >= ke {
                    return Err("model revocation escapes leaf validity".into());
                }
                ascii(
                    k.revocation_reason
                        .as_deref()
                        .ok_or("missing revocation reason")?,
                    256,
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest(self)
    }
    fn root_with(&self, policy: &RootPolicy, interval: Interval) -> Result<()> {
        self.validate()?;
        policy.validate()?;
        let b = &self.bundle;
        if !policy
            .accepted_trust_policy_versions
            .contains(&b.policy_version)
        {
            return Err("model trust policy is not independently accepted".into());
        }
        let root = policy
            .roots
            .iter()
            .find(|r| {
                r.key_id == b.root_key_id
                    && r.environment == b.environment
                    && r.trust_domain == b.trust_domain
            })
            .ok_or("model bundle does not select an independently provisioned root")?;
        let (start, end) = dates(&b.not_before, &b.not_after)?;
        if start < timestamp(&root.not_before)?
            || end > effective(&root.not_after, root.revoked_at.as_deref())?
        {
            return Err("model bundle escapes root effective validity".into());
        }
        live(
            &root.not_before,
            &root.not_after,
            root.revoked_at.as_deref(),
            interval,
        )?;
        live(
            &root.not_before,
            &root.not_after,
            root.revoked_at.as_deref(),
            Interval::new(timestamp(&b.issued_at)?, timestamp(&b.issued_at)?)?,
        )?;
        self.check_time(interval)?;
        let public = decode64::<32>(&root.public_key)?;
        let roots = policy
            .roots
            .iter()
            .map(|r| decode64::<32>(&r.public_key))
            .collect::<Result<Vec<_>>>()?;
        if policy
            .separated_key_sha256
            .contains(&key_fingerprint(&public))
            || b.keys.iter().any(|k| {
                decode64::<32>(&k.public_key).map_or(true, |key| {
                    roots.contains(&key)
                        || policy.separated_key_sha256.contains(&key_fingerprint(&key))
                })
            })
        {
            return Err("model root/leaf reuses a separated environment or OS/skill key".into());
        }
        let mut der = SPKI.to_vec();
        der.extend(public);
        crate::release_trust::verify_der(&der, &canonical(b)?, &decode64::<64>(&self.signature)?)
    }
    pub(crate) fn check_root(&self, interval: Interval) -> Result<()> {
        self.root_with(&RootPolicy::current()?, interval)
    }
    pub(crate) fn check_time(&self, interval: Interval) -> Result<()> {
        live(
            &self.bundle.not_before,
            &self.bundle.not_after,
            None,
            interval,
        )?;
        if timestamp(&self.bundle.issued_at)? > interval.endpoints().0 {
            return Err("model trust is issued after protected UTC".into());
        }
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        key_id: &str,
        purpose: &str,
        message: &[u8],
        signature: &[u8],
        interval: Interval,
    ) -> Result<()> {
        self.verify_with_policy(
            &RootPolicy::current()?,
            key_id,
            purpose,
            message,
            signature,
            interval,
        )
    }
    fn verify_with_policy(
        &self,
        policy: &RootPolicy,
        key_id: &str,
        purpose: &str,
        message: &[u8],
        signature: &[u8],
        interval: Interval,
    ) -> Result<()> {
        self.root_with(policy, interval)?;
        self.verify_leaf(key_id, purpose, message, signature, interval)
    }
    pub(crate) fn check_key_time(
        &self,
        key_id: &str,
        purpose: &str,
        interval: Interval,
    ) -> Result<()> {
        let key = self
            .bundle
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or("unknown model signing key")?;
        if role(purpose)? != key.role || !key.purposes.iter().any(|p| p == purpose) {
            return Err("wrong model signing role/purpose".into());
        }
        live(
            &key.not_before,
            &key.not_after,
            key.revoked_at.as_deref(),
            interval,
        )
    }
    fn verify_leaf(
        &self,
        key_id: &str,
        purpose: &str,
        message: &[u8],
        signature: &[u8],
        interval: Interval,
    ) -> Result<()> {
        self.check_key_time(key_id, purpose, interval)?;
        let key = self
            .bundle
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or("unknown model signing key")?;
        let mut der = SPKI.to_vec();
        der.extend(decode64::<32>(&key.public_key)?);
        crate::release_trust::verify_der(&der, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trust() -> SignedTrust {
        SignedTrust {
            schema_version: 1,
            signature_algorithm: "Ed25519".into(),
            signature_encoding: "base64".into(),
            signature: base64(&[1; 64]),
            bundle: TrustBundle {
                artifact_type: "luma-os-signing-trust-bundle".into(),
                schema_version: 1,
                trust_domain: DOMAIN.into(),
                environment: "lab".into(),
                bundle_sequence: 1,
                previous_bundle_sha256: None,
                root_key_id: "model-root".into(),
                policy_version: "trust-policy-v1".into(),
                issued_at: "2026-10-12T00:00:01Z".into(),
                not_before: "2026-10-12T00:00:00Z".into(),
                not_after: "2026-10-13T00:00:00Z".into(),
                keys: vec![TrustKey {
                    environment: "lab".into(),
                    key_id: "pack-a".into(),
                    public_key: base64(&[2; 32]),
                    public_key_encoding: "raw-ed25519-base64".into(),
                    role: "model-pack-signer".into(),
                    purposes: vec!["model-pack-manifest".into()],
                    not_before: "2026-10-12T00:00:01Z".into(),
                    not_after: "2026-10-12T23:59:59Z".into(),
                    revoked_at: None,
                    revocation_reason: None,
                }],
            },
        }
    }
    #[test]
    fn exact_reference_canonical_domain_rejects_duplicates_floats_unicode_and_unsafe_numbers() {
        let trust = trust();
        let bytes = canonical(&trust).unwrap();
        assert_eq!(SignedTrust::parse(&bytes).unwrap(), trust);
        let duplicate =
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen("{", "{\"schema_version\":1,", 1);
        assert!(SignedTrust::parse(duplicate.as_bytes()).is_err());
        let mut padded = bytes.clone();
        padded.push(b'\n');
        assert!(SignedTrust::parse(&padded).is_err());
        for value in [
            serde_json::json!({"x":1.0}),
            serde_json::json!({"x":9007199254740992u64}),
            serde_json::json!({"x":"é"}),
            serde_json::json!({"x":"\n"}),
        ] {
            assert!(canonical(&value).is_err());
        }
        let mut unknown = serde_json::to_value(trust).unwrap();
        unknown["bundle"]["takeover"] = true.into();
        assert!(SignedTrust::parse(&canonical(&unknown).unwrap()).is_err());
    }
    #[test]
    fn exact_utc_and_base64_encodings_are_closed_and_interoperable() {
        assert_eq!(timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(timestamp("2000-02-29T12:34:56Z").unwrap(), 951827696000);
        for invalid in [
            "2026-02-29T00:00:00Z",
            "2026-10-12T24:00:00Z",
            "2026-10-12T00:00:60Z",
            "2026-10-12T00:00:00+00:00",
            "2026-10-12T00:00:00.0Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(timestamp(invalid).is_err());
        }
        for value in [[0; 32], [1; 32], [255; 32]] {
            assert_eq!(decode64::<32>(&base64(&value)).unwrap(), value);
        }
        let text = base64(&[1; 32]);
        for bad in [
            format!("{text}\n"),
            text.replace('=', "A"),
            text.replace('A', "-"),
        ] {
            assert!(decode64::<32>(&bad).is_err());
        }
    }
    #[test]
    fn trust_checkpoint_compare_and_swap_predecessor_and_environment_are_atomic() {
        let first = trust();
        let mut state = None;
        publish(&mut state, 0, &first).unwrap();
        let before = state.clone();
        let mut next = first.clone();
        next.bundle.bundle_sequence = 2;
        next.bundle.previous_bundle_sha256 = Some(first.digest().unwrap());
        for case in 0..4 {
            let mut wrong = next.clone();
            match case {
                0 => wrong.bundle.previous_bundle_sha256 = Some("7".repeat(64)),
                1 => wrong.bundle.environment = "production".into(),
                2 => wrong.bundle.bundle_sequence = 3,
                _ => {
                    wrong.bundle.keys[0].purposes =
                        vec!["model-pack-interactive-certification".into()]
                }
            };
            assert!(publish(&mut state, 1, &wrong).is_err());
            assert_eq!(state, before);
        }
        publish(&mut state, 1, &next).unwrap();
        assert_eq!(state.as_ref().unwrap().trust.bundle.bundle_sequence, 2);
        assert!(publish(&mut state, 0, &first).is_err());
    }
    #[test]
    fn historical_model_key_identity_and_revocation_are_irreversible_across_rotation() {
        let mut first = trust();
        first.bundle.keys[0].revoked_at = Some("2026-10-12T00:00:05Z".into());
        first.bundle.keys[0].revocation_reason = Some("fixture-compromise".into());
        let mut state = None;
        publish(&mut state, 0, &first).unwrap();
        let before = state.clone();
        let mut next = first.clone();
        next.bundle.bundle_sequence = 2;
        next.bundle.previous_bundle_sha256 = Some(first.digest().unwrap());
        for case in 0..6 {
            let mut wrong = next.clone();
            match case {
                0 => wrong.bundle.keys[0].public_key = base64(&[3; 32]),
                1 => wrong.bundle.keys[0].key_id = "pack-new".into(),
                2 => {
                    wrong.bundle.keys[0].revoked_at = None;
                    wrong.bundle.keys[0].revocation_reason = None;
                }
                3 => wrong.bundle.keys[0].revoked_at = Some("2026-10-12T00:00:06Z".into()),
                4 => {
                    wrong.bundle.keys[0].role = "model-pack-certification-signer".into();
                    wrong.bundle.keys[0].purposes =
                        vec!["model-pack-execution-certification".into()];
                }
                _ => {
                    let mut alias = wrong.bundle.keys[0].clone();
                    alias.key_id = "pack-b".into();
                    wrong.bundle.keys.push(alias);
                }
            }
            let error = publish(&mut state, 1, &wrong).unwrap_err();
            if case == 2 {
                assert!(error
                    .to_string()
                    .contains("model key revocation cannot be removed"));
            }
            assert_eq!(state, before);
        }
        next.bundle.keys[0].revoked_at = Some("2026-10-12T00:00:04Z".into());
        publish(&mut state, 1, &next).unwrap();
        let mut later = next.clone();
        later.bundle.bundle_sequence = 3;
        later.bundle.previous_bundle_sha256 = Some(next.digest().unwrap());
        later.bundle.keys[0].revoked_at = None;
        later.bundle.keys[0].revocation_reason = None;
        assert!(publish(&mut state, 2, &later)
            .unwrap_err()
            .to_string()
            .contains("model key revocation cannot be removed"));
    }
    #[test]
    fn real_root_and_leaf_ed25519_signatures_preserve_purpose_expiry_and_separation() {
        use std::{fs, process::Command as Process};
        let dir =
            std::env::temp_dir().join(format!("luma-model-trust-crypto-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let run = |args: &[&str]| {
            assert!(Process::new("/usr/bin/openssl")
                .env_clear()
                .env("PATH", "/usr/bin")
                .current_dir(&dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success());
        };
        for name in ["root", "leaf"] {
            run(&[
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                &format!("{name}.key"),
            ]);
            run(&[
                "pkey",
                "-in",
                &format!("{name}.key"),
                "-pubout",
                "-out",
                &format!("{name}.pub"),
            ]);
        }
        let root =
            crate::release_trust::public_der(&fs::read(dir.join("root.pub")).unwrap()).unwrap();
        let leaf =
            crate::release_trust::public_der(&fs::read(dir.join("leaf.pub")).unwrap()).unwrap();
        let mut value = trust();
        value.bundle.keys[0].public_key = base64(&leaf[12..]);
        fs::write(dir.join("trust.json"), canonical(&value.bundle).unwrap()).unwrap();
        run(&[
            "pkeyutl",
            "-sign",
            "-inkey",
            "root.key",
            "-rawin",
            "-in",
            "trust.json",
            "-out",
            "trust.sig",
        ]);
        value.signature = base64(&fs::read(dir.join("trust.sig")).unwrap());
        let policy = RootPolicy {
            schema_version: 1,
            trust_domain: DOMAIN.into(),
            accepted_trust_policy_versions: vec!["trust-policy-v1".into()],
            accepted_catalog_policy_versions: vec!["catalog-policy-v1".into()],
            roots: vec![RootAnchor {
                key_id: "model-root".into(),
                environment: "lab".into(),
                trust_domain: DOMAIN.into(),
                public_key: base64(&root[12..]),
                not_before: "2026-10-11T00:00:00Z".into(),
                not_after: "2026-10-14T00:00:00Z".into(),
                revoked_at: None,
            }],
            separated_key_sha256: vec![],
        };
        let start = timestamp("2026-10-12T00:00:02Z").unwrap();
        let interval = Interval::new(start, start + 10).unwrap();
        value.root_with(&policy, interval).unwrap();
        fs::write(dir.join("manifest.json"), b"exact signed model bytes").unwrap();
        run(&[
            "pkeyutl",
            "-sign",
            "-inkey",
            "leaf.key",
            "-rawin",
            "-in",
            "manifest.json",
            "-out",
            "manifest.sig",
        ]);
        let signature = fs::read(dir.join("manifest.sig")).unwrap();
        value
            .verify_with_policy(
                &policy,
                "pack-a",
                "model-pack-manifest",
                b"exact signed model bytes",
                &signature,
                interval,
            )
            .unwrap();
        for (purpose, message) in [
            (
                "model-profile-catalog-lab",
                &b"exact signed model bytes"[..],
            ),
            ("model-pack-manifest", &b"changed signed model bytes"[..]),
        ] {
            assert!(value
                .verify_with_policy(&policy, "pack-a", purpose, message, &signature, interval)
                .is_err());
        }
        assert!(value
            .root_with(
                &policy,
                Interval::new(
                    timestamp("2026-10-13T00:00:00Z").unwrap(),
                    timestamp("2026-10-13T00:00:00Z").unwrap()
                )
                .unwrap()
            )
            .is_err());
        let mut separated = policy.clone();
        separated
            .separated_key_sha256
            .push(key_fingerprint(&leaf[12..].try_into().unwrap()));
        assert!(value.root_with(&separated, interval).is_err());
        let mut changed = value.clone();
        changed.bundle.keys[0].public_key = base64(&root[12..]);
        assert!(changed.root_with(&policy, interval).is_err());
        let mut production = value.clone();
        production.bundle.environment = "production".into();
        production.bundle.keys[0].environment = "production".into();
        production.bundle.keys[0].role = "model-profile-catalog-production-signer".into();
        production.bundle.keys[0].purposes = vec!["model-profile-catalog-production".into()];
        let mut production_policy = policy.clone();
        production_policy.roots[0].environment = "production".into();
        fs::write(
            dir.join("trust.json"),
            canonical(&production.bundle).unwrap(),
        )
        .unwrap();
        run(&[
            "pkeyutl",
            "-sign",
            "-inkey",
            "root.key",
            "-rawin",
            "-in",
            "trust.json",
            "-out",
            "trust.sig",
        ]);
        production.signature = base64(&fs::read(dir.join("trust.sig")).unwrap());
        let (catalog, mut admission, packs) = production_fixture(&production);
        let envelope = Envelope::parse(admission.envelope_json.as_bytes()).unwrap();
        fs::write(
            dir.join("catalog.json"),
            canonical(&envelope.statement).unwrap(),
        )
        .unwrap();
        run(&[
            "pkeyutl",
            "-sign",
            "-inkey",
            "leaf.key",
            "-rawin",
            "-in",
            "catalog.json",
            "-out",
            "catalog.sig",
        ]);
        let mut envelope = envelope;
        envelope.signature = base64(&fs::read(dir.join("catalog.sig")).unwrap());
        admission.envelope_json = String::from_utf8(canonical(&envelope).unwrap()).unwrap();
        let now = timestamp("2026-10-12T00:00:10Z").unwrap();
        let current = Interval::new(now, now + 10).unwrap();
        verify_catalog_with_policy(
            &catalog,
            &admission,
            current,
            &packs,
            &production_policy,
            Some(&machine_fixture()),
        )
        .unwrap();
        for case in 0..12 {
            let mut stale = catalog.clone();
            let mut proof = packs.clone();
            let mut candidate = admission.clone();
            match case {
                0 => stale.assignments.get_mut("assignment-1").unwrap().revoked = true,
                1 => stale
                    .principal_states
                    .insert(
                        "2".repeat(64),
                        crate::admin_roles::PrincipalState {
                            generation: 2,
                            enabled: true,
                        },
                    )
                    .map(|_| ())
                    .unwrap_or(()),
                2 => {
                    stale.model_approvals.clear();
                }
                3 => proof[0].state = 2,
                4 => proof[0].runtime_tuple.device = "cuda".into(),
                5 => {
                    let mut e = Envelope::parse(candidate.envelope_json.as_bytes()).unwrap();
                    e.signature = base64(&[0; 64]);
                    candidate.envelope_json = String::from_utf8(canonical(&e).unwrap()).unwrap();
                }
                6 => {
                    stale.model_trust.as_mut().unwrap().trust.bundle.keys[0].revoked_at =
                        Some("2026-10-12T00:00:09Z".into())
                }
                7 => stale
                    .assignment_receipts
                    .insert("assignment-2".into(), "0".repeat(64))
                    .map(|_| ())
                    .unwrap_or(()),
                8 => proof[0].qualifications.clear(),
                9 => proof[0].qualifications[0].release_manifest_sha256 = "0".repeat(64),
                10 => proof[0].qualifications[0].model_profile_sha256 = "0".repeat(64),
                _ => proof[0].qualifications[0].hardware.total_memory_bytes += 1024,
            }
            assert!(verify_catalog_with_policy(
                &stale,
                &candidate,
                current,
                &proof,
                &production_policy,
                Some(&machine_fixture())
            )
            .is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }
    fn production_fixture(trust: &SignedTrust) -> (Catalog, Admission, Vec<PackVerification>) {
        let tuple = RuntimeTuple {
            os_family: "Linux".into(),
            architecture: "amd64".into(),
            backend: "llama.cpp".into(),
            backend_version: "b11100".into(),
            device: "cpu".into(),
        };
        let profile = ModelProfile {
            availability: "available".into(),
            certification_state: "execution-certified".into(),
            context_tokens: 2048,
            development_state: "development-tested".into(),
            execution_mode: "cpu".into(),
            install_bytes: 64,
            kind: "model".into(),
            load_reservations: vec![Reservation {
                domain: "host".into(),
                bytes: 1024,
            }],
            minimum_accelerator_memory_bytes: 0,
            minimum_host_ram_bytes: 2048,
            model_pack_manifest_sha256: "6".repeat(64),
            parameter_active_max: 4,
            parameter_active_min: 4,
            parameter_total: 4,
            profile_id: "qwen-test".into(),
            remote_fallback: false,
            runtime_tuple_sha256: tuple.digest().unwrap(),
            serve_reservations: vec![Reservation {
                domain: "host".into(),
                bytes: 1024,
            }],
            storage_peak_bytes: 128,
            verification_state: "verified".into(),
        };
        let models = ModelCatalog {
            catalog_id: "production-test".into(),
            profiles: vec![
                SelectableProfile::Manual(ManualProfile {
                    kind: "manual-only".into(),
                    profile_id: "manual-only".into(),
                    remote_fallback: false,
                }),
                SelectableProfile::Model(profile),
            ],
            schema_version: 1,
        };
        models.validate().unwrap();
        let request = ReleaseRequest {
            artifact_type: "model-profile-catalog-release-request".into(),
            catalog_id: models.catalog_id.clone(),
            catalog_sequence: 1,
            catalog_sha256: models.digest().unwrap(),
            environment: "production".into(),
            not_after: "2026-10-13T00:00:00Z".into(),
            not_before: "2026-10-12T00:00:00Z".into(),
            policy_version: "catalog-policy-v1".into(),
            purpose: "model-profile-catalog-production".into(),
            release_id: "production-test".into(),
            schema_version: 1,
            signature_algorithm: "Ed25519".into(),
            signer_key_id: trust.bundle.keys[0].key_id.clone(),
            signing_activity: "model-catalog.sign.production".into(),
            signing_assignment_id: "assignment-4".into(),
            signing_assignment_receipt_sha256: "4".repeat(64),
            signing_principal_id: "4".repeat(64),
        };
        let activities = [
            "model-catalog.approve.license",
            "model-catalog.approve.release",
            "model-catalog.approve.security",
            "model-catalog.sign.production",
        ];
        let mut catalog = Catalog::initial();
        let principals=(1..=4).map(|i|serde_json::json!({"id":i.to_string().repeat(64),"generation":1,"login":format!("custodian{i}"),"uid":1000+i,"enabled":true})).collect::<Vec<_>>();
        catalog.principal_registry=Some(serde_json::from_value(serde_json::json!({"schema_version":1,"installation":"9".repeat(64),"principals":principals})).unwrap());
        let start = timestamp(&request.not_before).unwrap();
        let end = timestamp(&request.not_after).unwrap();
        for (index, activity) in activities.iter().enumerate() {
            let i = index + 1;
            let subject = i.to_string().repeat(64);
            let role = format!("custody-{i}");
            let id = format!("assignment-{i}");
            catalog.roles.insert(
                role.clone(),
                crate::admin_roles::Role {
                    name: role.clone(),
                    activities: vec![activity.to_string()],
                    version: 1,
                },
            );
            catalog.assignments.insert(
                id.clone(),
                crate::finite_grants::Assignment {
                    id: id.clone(),
                    subject: subject.clone(),
                    subject_generation: 1,
                    role,
                    role_version: 1,
                    version: 1,
                    not_before_ms: start,
                    expires_ms: end,
                    revoked: false,
                },
            );
            catalog
                .assignment_receipts
                .insert(id, i.to_string().repeat(64));
            catalog.account_commitments.insert(subject, "a".repeat(64));
        }
        let approvals = activities[..3]
            .iter()
            .enumerate()
            .map(|(index, activity)| {
                let i = index + 1;
                Approval {
                    activity: activity.to_string(),
                    approved_at: "2026-10-12T00:00:03Z".into(),
                    approval_decision_receipt_sha256: format!("{:064x}", i + 100),
                    assignment_id: format!("assignment-{i}"),
                    assignment_receipt_sha256: i.to_string().repeat(64),
                    catalog_sha256: request.catalog_sha256.clone(),
                    decision: "approved".into(),
                    principal_id: i.to_string().repeat(64),
                    release_request_sha256: request.digest().unwrap(),
                    release_id: request.release_id.clone(),
                }
            })
            .collect::<Vec<_>>();
        let mut statement = serde_json::to_value(&request).unwrap();
        let object = statement.as_object_mut().unwrap();
        object.insert("artifact_type".into(), "model-profile-catalog".into());
        object.insert(
            "approval_set_sha256".into(),
            digest(&serde_json::json!({"approvals":approvals,"schema_version":1}))
                .unwrap()
                .into(),
        );
        object.insert(
            "release_request_sha256".into(),
            request.digest().unwrap().into(),
        );
        object.insert("signed_at".into(), "2026-10-12T00:00:04Z".into());
        let statement: Statement = serde_json::from_value(statement).unwrap();
        for approval in &approvals {
            catalog.model_approvals.insert(
                approval.approval_decision_receipt_sha256.clone(),
                approval.clone(),
            );
        }
        catalog
            .model_signings
            .insert(statement.digest().unwrap(), statement.clone());
        catalog.model_trust = Some(State {
            trust: trust.clone(),
            floor: 0,
            current: None,
        });
        let release = bundle::Manifest {
            schema_version: 1,
            release: request.release_id.clone(),
            sequence: 1,
            environment: "production".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
            root_hash: "b".repeat(64),
            root_bytes: 512 * 1024 * 1024,
            hash_bytes: 4096,
            artifacts: vec![],
        };
        catalog.release = Some(crate::release_trust::State {
            trust: crate::release_trust::SignedTrust {
                trust: crate::release_trust::Trust {
                    schema_version: 1,
                    environment: "production".into(),
                    version: 1,
                    root_sha256: "8".repeat(64),
                    not_before_ms: start,
                    expires_ms: end,
                    keys: vec![],
                },
                signature_hex: "7".repeat(128),
            },
            floor: 1,
            acknowledged: Some(release),
            pending: None,
            retained: None,
        });
        let envelope = Envelope {
            approvals,
            schema_version: 1,
            signature: base64(&[1; 64]),
            signature_encoding: "base64".into(),
            statement,
        };
        envelope.validate().unwrap();
        let evidence = QualificationEvidence {
            schema_version: 1,
            level: "execution".into(),
            installation_sha256: catalog.registry().unwrap().installation().into(),
            release_manifest_sha256: digest(
                catalog
                    .release
                    .as_ref()
                    .unwrap()
                    .acknowledged
                    .as_ref()
                    .unwrap(),
            )
            .unwrap(),
            model_profile_sha256: match &models.profiles[1] {
                SelectableProfile::Model(p) => p.digest().unwrap(),
                _ => unreachable!(),
            },
            runtime_tuple_sha256: tuple.digest().unwrap(),
            hardware: machine_fixture(),
            test_report_sha256: "c".repeat(64),
        };
        let evidence_sha256 = digest(&evidence).unwrap();
        (
            catalog,
            Admission {
                catalog_json: String::from_utf8(canonical(&models).unwrap()).unwrap(),
                envelope_json: String::from_utf8(canonical(&envelope).unwrap()).unwrap(),
                trust_sha256: trust.digest().unwrap(),
            },
            vec![PackVerification {
                manifest_sha256: "6".repeat(64),
                runtime_tuple: tuple,
                state: 3,
                evidence_sha256: Some(evidence_sha256),
                signing_keys: vec![],
                qualifications: vec![evidence],
            }],
        )
    }
    fn machine_fixture() -> MachineTuple {
        MachineTuple {
            cpu_vendor: "GenuineIntel".into(),
            cpu_family: 6,
            cpu_model: 154,
            cpu_stepping: 3,
            features: vec!["avx".into(), "sse2".into()],
            logical_cpus: 2,
            total_memory_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
    #[test]
    fn qualification_kernel_observer_is_closed_exact_homogeneous_and_unambiguous() {
        let block="processor : 0\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 154\nstepping : 3\nflags : sse2 avx\n";
        let cpu = format!(
            "{block}\n{}",
            block.replace("processor : 0", "processor : 1")
        );
        assert_eq!(
            MachineTuple::observe(&cpu, "MemTotal: 16777216 kB\n").unwrap(),
            machine_fixture()
        );
        for invalid in [
            cpu.replace("processor : 1", "processor : 0"),
            cpu.replace("flags : sse2 avx", "flags : avx avx"),
            cpu.replacen("model : 154", "model : 155", 1),
            cpu.replacen("cpu family : 6", "cpu family : +6", 1),
            cpu.replacen("stepping : 3", "stepping : 3\nstepping : 3", 1),
            cpu.replace("vendor_id : GenuineIntel\n", ""),
        ] {
            assert!(MachineTuple::observe(&invalid, "MemTotal: 16777216 kB\n").is_err());
        }
        for invalid in [
            "MemTotal: 16777216 MB\n",
            "MemTotal: 1 kB\nMemTotal: 1 kB\n",
            "MemTotal: -1 kB\n",
            "MemTotal: 18446744073709551615 kB\n",
            "",
        ] {
            assert!(MachineTuple::observe(&cpu, invalid).is_err());
        }
    }
    #[test]
    fn qualification_descriptor_is_exact_certificate_digest_bound_not_opaque_evidence() {
        let evidence = QualificationEvidence {
            schema_version: 1,
            level: "execution".into(),
            installation_sha256: "9".repeat(64),
            release_manifest_sha256: "1".repeat(64),
            model_profile_sha256: "2".repeat(64),
            runtime_tuple_sha256: "3".repeat(64),
            hardware: machine_fixture(),
            test_report_sha256: "4".repeat(64),
        };
        let certificate = CertificationRecord {
            level: "execution".into(),
            pack_manifest_sha256: "5".repeat(64),
            runtime_tuple_sha256: evidence.runtime_tuple_sha256.clone(),
            evidence_sha256: digest(&evidence).unwrap(),
            signer_key_id: "qualified-key".into(),
        };
        QualificationEvidence::parse(&canonical(&evidence).unwrap(), &certificate).unwrap();
        let mut altered = evidence.clone();
        altered.hardware.logical_cpus += 1;
        assert!(QualificationEvidence::parse(&canonical(&altered).unwrap(), &certificate).is_err());
        let mut foreign = certificate.clone();
        foreign.level = "interactive".into();
        assert!(QualificationEvidence::parse(&canonical(&evidence).unwrap(), &foreign).is_err());
        assert!(QualificationEvidence::parse(b"{}", &certificate).is_err());
    }
}

record!(ModelIdentity {architecture:String,identity:String,parameter_class:String,total_parameters:u64,active_parameters_min:u64,active_parameters_max:u64,quantization:String,required_features:Vec<String>,source:String});
record!(Context {
    maximum_tokens: u64,
    template_sha256: String
});
record!(Blob {role:String,path:String,sha256:String,size_bytes:u64,#[serde(default,skip_serializing_if="Option::is_none")] shard_index:Option<u64>});
record!(RuntimeTuple {
    os_family: String,
    architecture: String,
    backend: String,
    backend_version: String,
    device: String
});
impl RuntimeTuple {
    pub(crate) fn validate(&self) -> Result<()> {
        for v in [
            &self.os_family,
            &self.architecture,
            &self.backend,
            &self.backend_version,
            &self.device,
        ] {
            ascii(v, 512)?;
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}
record!(InstallationProfile {
    profile_id: String,
    runtime_tuple_sha256: String,
    execution_mode: String,
    minimum_host_ram_bytes: u64,
    minimum_accelerator_memory_bytes: u64,
    minimum_model_storage_bytes: u64,
    maximum_context_tokens: u64
});
record!(License {identifier:String,evaluation:String,redistribution:String,files:Vec<String>});
record!(PackManifest {schema_version:u32,canonicalization:String,signature_algorithm:String,pack_id:String,pack_version:String,model:ModelIdentity,context:Context,blobs:Vec<Blob>,runtime_tuples:Vec<RuntimeTuple>,installation_profiles:Vec<InstallationProfile>,license:License,network_default:String,signer_key_id:String});
fn relative(value: &str) -> Result<()> {
    ascii(value, 1024)?;
    if value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
    {
        return Err("model pack paths must be normalized relative POSIX paths".into());
    }
    Ok(())
}
impl PackManifest {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_TRUST)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 2
            || self.canonicalization != "RFC8785-ASCII-v1"
            || self.signature_algorithm != "Ed25519"
            || self.network_default != "deny"
        {
            return Err("unsupported frozen v2 model manifest/signature/network policy".into());
        }
        for v in [
            &self.pack_id,
            &self.pack_version,
            &self.signer_key_id,
            &self.model.architecture,
            &self.model.identity,
            &self.model.parameter_class,
            &self.model.quantization,
            &self.license.identifier,
        ] {
            ascii(v, 512)?;
        }
        ascii(&self.model.source, 1024)?;
        for n in [
            self.model.total_parameters,
            self.model.active_parameters_min,
            self.model.active_parameters_max,
            self.context.maximum_tokens,
        ] {
            positive(n)?;
        }
        if self.model.active_parameters_min > self.model.active_parameters_max
            || self.model.active_parameters_max > self.model.total_parameters
            || self.model.required_features.is_empty()
            || self
                .model
                .required_features
                .windows(2)
                .any(|v| v[0] >= v[1])
        {
            return Err("invalid model parameter bounds or canonical required features".into());
        }
        for v in &self.model.required_features {
            ascii(v, 512)?;
        }
        hash(&self.context.template_sha256)?;
        if self.blobs.is_empty() || self.blobs.len() > 4096 {
            return Err("model pack blob inventory is empty or oversized".into());
        }
        let mut paths = BTreeSet::new();
        let mut license_paths = BTreeSet::new();
        let mut shards = 0;
        let mut tokenizer = 0;
        let mut template = 0;
        let mut size = 0u64;
        for b in &self.blobs {
            relative(&b.path)?;
            hash(&b.sha256)?;
            positive(b.size_bytes)?;
            size = size
                .checked_add(b.size_bytes)
                .filter(|s| *s <= SAFE)
                .ok_or("model pack storage overflow")?;
            if !paths.insert(&b.path) {
                return Err("duplicate model blob path".into());
            }
            if b.role == "license" {
                if !b.path.starts_with("licenses/") {
                    return Err("license blob outside licenses namespace".into());
                }
                license_paths.insert(&b.path);
            } else if b.path != format!("blobs/sha256/{}", b.sha256) {
                return Err("model content blob outside digest namespace".into());
            }
            match b.role.as_str() {
                "model" => {
                    if b.shard_index != Some(shards) {
                        return Err("model shards must be contiguous and ordered from zero".into());
                    }
                    shards += 1;
                }
                "tokenizer" => tokenizer += 1,
                "template" => {
                    template += 1;
                    if b.sha256 != self.context.template_sha256 {
                        return Err("model context template digest mismatch".into());
                    }
                }
                "license" | "auxiliary" => (),
                _ => return Err("unknown model blob role".into()),
            }
            if b.role != "model" && b.shard_index.is_some() {
                return Err("non-model blob cannot carry shard index".into());
            }
        }
        if shards == 0 || tokenizer != 1 || template != 1 {
            return Err("model pack requires shards and exactly one tokenizer/template".into());
        }
        if self.runtime_tuples.is_empty()
            || self.runtime_tuples.len() > 256
            || self.installation_profiles.is_empty()
            || self.installation_profiles.len() > 256
        {
            return Err("model runtime/profile list is empty or oversized".into());
        }
        let tuples = self
            .runtime_tuples
            .iter()
            .map(RuntimeTuple::digest)
            .collect::<Result<BTreeSet<_>>>()?;
        if tuples.len() != self.runtime_tuples.len() {
            return Err("duplicate model runtime tuple".into());
        }
        let mut ids = BTreeSet::new();
        for p in &self.installation_profiles {
            ascii(&p.profile_id, 512)?;
            hash(&p.runtime_tuple_sha256)?;
            positive(p.minimum_host_ram_bytes)?;
            positive(p.minimum_model_storage_bytes)?;
            positive(p.maximum_context_tokens)?;
            if !ids.insert(&p.profile_id)
                || !tuples.contains(&p.runtime_tuple_sha256)
                || p.minimum_model_storage_bytes < size
                || p.maximum_context_tokens > self.context.maximum_tokens
                || p.minimum_accelerator_memory_bytes > SAFE
                || !matches!(p.execution_mode.as_str(), "cpu" | "cuda")
                || (p.execution_mode == "cpu" && p.minimum_accelerator_memory_bytes != 0)
                || (p.execution_mode == "cuda" && p.minimum_accelerator_memory_bytes == 0)
            {
                return Err("model install profile understates storage/context or mismatches runtime/memory mode".into());
            }
        }
        if !matches!(
            self.license.evaluation.as_str(),
            "approved" | "denied" | "pending"
        ) || !matches!(
            self.license.redistribution.as_str(),
            "approved" | "denied" | "pending" | "not-applicable"
        ) || self.license.files.is_empty()
        {
            return Err("invalid model license decision".into());
        }
        let mut declared = BTreeSet::new();
        for v in &self.license.files {
            relative(v)?;
            if !declared.insert(v) {
                return Err("duplicate model license file".into());
            }
        }
        if declared != license_paths {
            return Err("model license files do not exactly match declared license blobs".into());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest(self)
    }
    pub(crate) fn check_signature(
        &self,
        trust: &SignedTrust,
        signature: &[u8],
        interval: Interval,
    ) -> Result<()> {
        self.validate()?;
        if self.license.evaluation != "approved" {
            return Err("model evaluation license is not approved".into());
        }
        trust.verify(
            &self.signer_key_id,
            "model-pack-manifest",
            &canonical(self)?,
            signature,
            interval,
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackVerification {
    pub manifest_sha256: String,
    pub runtime_tuple: RuntimeTuple,
    pub state: u8,
    pub evidence_sha256: Option<String>,
    pub signing_keys: Vec<(String, String)>,
    pub qualifications: Vec<QualificationEvidence>,
}
// This native adjunct does not change the frozen certificate wire. Its exact
// canonical bytes are authenticated by the certificate's existing evidence
// digest. It is external public data because placing final-root qualification
// inside that same verity root would create a cryptographic self-reference.
record!(MachineTuple {cpu_vendor:String,cpu_family:u64,cpu_model:u64,cpu_stepping:u64,features:Vec<String>,logical_cpus:u64,total_memory_bytes:u64});
impl MachineTuple {
    fn validate(&self) -> Result<()> {
        ascii(&self.cpu_vendor, 32)?;
        positive(self.cpu_family)?;
        positive(self.logical_cpus)?;
        positive(self.total_memory_bytes)?;
        if self.cpu_family > 65535
            || self.cpu_model > 65535
            || self.cpu_stepping > 65535
            || self.logical_cpus > 65536
            || self.features.is_empty()
            || self.features.len() > 512
            || self.features.windows(2).any(|v| v[0] >= v[1])
        {
            return Err("unsupported or noncanonical qualification machine tuple".into());
        }
        for feature in &self.features {
            if feature.is_empty()
                || feature.len() > 64
                || !feature
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err("unsupported CPU qualification feature".into());
            }
        }
        Ok(())
    }
    fn observe(cpu: &str, memory: &str) -> Result<Self> {
        if cpu.is_empty()
            || cpu.len() > 4 * 1024 * 1024
            || memory.len() > 128 * 1024
            || !cpu.is_ascii()
            || !memory.is_ascii()
        {
            return Err("oversized or unsupported kernel hardware observation".into());
        }
        let mut processors = BTreeSet::new();
        let mut homogeneous = None;
        for block in cpu.split("\n\n").filter(|v| !v.trim().is_empty()) {
            let mut fields = std::collections::BTreeMap::new();
            for line in block.lines() {
                let (key, value) = line.split_once(':').ok_or("malformed CPU observation")?;
                let key = key.trim();
                if matches!(
                    key,
                    "processor" | "vendor_id" | "cpu family" | "model" | "stepping" | "flags"
                ) && fields.insert(key, value.trim()).is_some()
                {
                    return Err("duplicate CPU qualification observation".into());
                }
            }
            let get = |key| {
                fields
                    .get(key)
                    .copied()
                    .ok_or("required x86 CPU observation is absent")
            };
            let number = |key| -> Result<u64> {
                let value = get(key)?;
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("ambiguous CPU observation integer".into());
                }
                Ok(value.parse()?)
            };
            if !processors.insert(number("processor")?) {
                return Err("duplicate logical processor observation".into());
            }
            let raw = get("flags")?
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let features = raw.iter().cloned().collect::<BTreeSet<_>>();
            if features.len() != raw.len() {
                return Err("duplicate CPU feature observation".into());
            }
            let observed = (
                get("vendor_id")?.to_owned(),
                number("cpu family")?,
                number("model")?,
                number("stepping")?,
                features.into_iter().collect::<Vec<_>>(),
            );
            match &homogeneous {
                Some(expected) if *expected != observed => {
                    return Err(
                        "heterogeneous CPUs need separately qualified native support".into(),
                    )
                }
                None => homogeneous = Some(observed),
                _ => (),
            }
        }
        let mut total = None;
        for line in memory.lines() {
            if let Some(value) = line.strip_prefix("MemTotal:") {
                if total.is_some() {
                    return Err("duplicate memory total observation".into());
                }
                let fields = value.split_whitespace().collect::<Vec<_>>();
                if fields.len() != 2
                    || fields[1] != "kB"
                    || fields[0].is_empty()
                    || !fields[0].bytes().all(|b| b.is_ascii_digit())
                {
                    return Err("unsupported memory observation units".into());
                }
                total = Some(
                    fields[0]
                        .parse::<u64>()?
                        .checked_mul(1024)
                        .ok_or("memory observation overflow")?,
                );
            }
        }
        let (cpu_vendor, cpu_family, cpu_model, cpu_stepping, features) =
            homogeneous.ok_or("CPU qualification observation absent")?;
        let value = Self {
            cpu_vendor,
            cpu_family,
            cpu_model,
            cpu_stepping,
            features,
            logical_cpus: processors.len() as u64,
            total_memory_bytes: total.ok_or("memory qualification observation absent")?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn current() -> Result<Self> {
        if !cfg!(target_arch = "x86_64") {
            return Err(
                "native qualification currently supports exact x86_64 CPU tuples only".into(),
            );
        }
        use std::{
            io::Read,
            os::unix::{fs::OpenOptionsExt, io::AsRawFd},
        };
        let read = |path: &str, limit: u64| -> Result<String> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)?;
            let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // fstatfs initializes only the owned output object using an open
            // descriptor. No pointer is retained and no caller path is trusted.
            if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if unsafe { fs.assume_init() }.f_type != 0x9fa0 || !file.metadata()?.is_file() {
                return Err(
                    "hardware observation is not an actual procfs regular descriptor".into(),
                );
            }
            let mut bytes = Vec::new();
            file.take(limit + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Err("kernel hardware observation exceeds bound".into());
            }
            Ok(String::from_utf8(bytes)?)
        };
        Self::observe(
            &read("/proc/cpuinfo", 4 * 1024 * 1024)?,
            &read("/proc/meminfo", 128 * 1024)?,
        )
    }
}
record!(QualificationEvidence {
    schema_version: u32,
    level: String,
    installation_sha256: String,
    release_manifest_sha256: String,
    model_profile_sha256: String,
    runtime_tuple_sha256: String,
    hardware: MachineTuple,
    test_report_sha256: String
});
impl QualificationEvidence {
    pub(crate) fn parse(bytes: &[u8], certificate: &CertificationRecord) -> Result<Self> {
        let value: Self = parse(bytes, 65536)?;
        value.validate()?;
        certificate.validate()?;
        if value.level != certificate.level
            || value.runtime_tuple_sha256 != certificate.runtime_tuple_sha256
            || digest(&value)? != certificate.evidence_sha256
        {
            return Err(
                "qualification evidence does not match its actual signed certificate".into(),
            );
        }
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || !matches!(self.level.as_str(), "execution" | "interactive") {
            return Err("unsupported native qualification evidence".into());
        }
        for value in [
            &self.installation_sha256,
            &self.release_manifest_sha256,
            &self.model_profile_sha256,
            &self.runtime_tuple_sha256,
            &self.test_report_sha256,
        ] {
            hash(value)?;
        }
        self.hardware.validate()
    }
    pub(crate) fn check(
        &self,
        release: &bundle::Manifest,
        profile: &ModelProfile,
        hardware: &MachineTuple,
        installation: &str,
    ) -> Result<()> {
        self.validate()?;
        if self.installation_sha256 != installation
            || self.release_manifest_sha256 != digest(release)?
            || self.model_profile_sha256 != profile.digest()?
            || self.runtime_tuple_sha256 != profile.runtime_tuple_sha256
            || &self.hardware != hardware
        {
            return Err("model qualification is not for this exact installation, acknowledged image, profile, runtime and measured machine".into());
        }
        Ok(())
    }
}
record!(CertificationRecord {
    level: String,
    pack_manifest_sha256: String,
    runtime_tuple_sha256: String,
    evidence_sha256: String,
    signer_key_id: String
});
impl CertificationRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        if !matches!(self.level.as_str(), "execution" | "interactive") {
            return Err("unknown model certification level".into());
        }
        hash(&self.pack_manifest_sha256)?;
        hash(&self.runtime_tuple_sha256)?;
        hash(&self.evidence_sha256)?;
        ascii(&self.signer_key_id, 512)
    }
    pub(crate) fn apply(
        &self,
        verification: &PackVerification,
        trust: &SignedTrust,
        signature: &[u8],
        interval: Interval,
    ) -> Result<PackVerification> {
        self.validate()?;
        let state = if self.level == "execution" { 3 } else { 4 };
        if verification.state < 2
            || state <= verification.state
            || (state == 4 && verification.state < 3)
            || self.pack_manifest_sha256 != verification.manifest_sha256
            || self.runtime_tuple_sha256 != verification.runtime_tuple.digest()?
        {
            return Err(
                "model certification cannot skip lifecycle stages or float across tuples".into(),
            );
        }
        let purpose = if state == 3 {
            "model-pack-execution-certification"
        } else {
            "model-pack-interactive-certification"
        };
        trust.verify(
            &self.signer_key_id,
            purpose,
            &canonical(self)?,
            signature,
            interval,
        )?;
        let mut signing_keys = verification.signing_keys.clone();
        signing_keys.push((self.signer_key_id.clone(), purpose.into()));
        Ok(PackVerification {
            manifest_sha256: verification.manifest_sha256.clone(),
            runtime_tuple: verification.runtime_tuple.clone(),
            state,
            evidence_sha256: Some(self.evidence_sha256.clone()),
            signing_keys,
            qualifications: verification.qualifications.clone(),
        })
    }
}
record!(Reservation {
    domain: String,
    bytes: u64
});
record!(ModelProfile {availability:String,certification_state:String,context_tokens:u64,development_state:String,execution_mode:String,install_bytes:u64,kind:String,load_reservations:Vec<Reservation>,minimum_accelerator_memory_bytes:u64,minimum_host_ram_bytes:u64,model_pack_manifest_sha256:String,parameter_active_max:u64,parameter_active_min:u64,parameter_total:u64,profile_id:String,remote_fallback:bool,runtime_tuple_sha256:String,serve_reservations:Vec<Reservation>,storage_peak_bytes:u64,verification_state:String});
record!(ManualProfile {
    kind: String,
    profile_id: String,
    remote_fallback: bool
});
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum SelectableProfile {
    Manual(ManualProfile),
    Model(ModelProfile),
}
impl SelectableProfile {
    fn id(&self) -> &str {
        match self {
            Self::Manual(p) => &p.profile_id,
            Self::Model(p) => &p.profile_id,
        }
    }
}
record!(ModelCatalog {catalog_id:String,profiles:Vec<SelectableProfile>,schema_version:u32});
impl ModelProfile {
    pub(crate) fn digest(&self) -> Result<String> {
        digest(self)
    }
    fn validate(&self) -> Result<()> {
        ascii(&self.profile_id, 256)?;
        hash(&self.model_pack_manifest_sha256)?;
        hash(&self.runtime_tuple_sha256)?;
        for v in [
            self.parameter_total,
            self.parameter_active_min,
            self.parameter_active_max,
            self.context_tokens,
            self.install_bytes,
            self.storage_peak_bytes,
            self.minimum_host_ram_bytes,
        ] {
            positive(v)?;
        }
        if self.profile_id == "manual-only"
            || self.kind != "model"
            || self.remote_fallback
            || self.parameter_active_min > self.parameter_active_max
            || self.parameter_active_max > self.parameter_total
            || self.storage_peak_bytes < self.install_bytes
            || self.minimum_accelerator_memory_bytes > SAFE
            || !matches!(self.execution_mode.as_str(), "cpu" | "cuda")
        {
            return Err("invalid model profile parameter/storage/mode/fallback policy".into());
        }
        for reservations in [&self.load_reservations, &self.serve_reservations] {
            let mut domains = BTreeSet::new();
            let mut previous = None;
            for r in reservations {
                positive(r.bytes)?;
                if !matches!(r.domain.as_str(), "host" | "accelerator")
                    || !domains.insert(&r.domain)
                    || previous.is_some_and(|d: &str| d >= r.domain.as_str())
                {
                    return Err("model reservations require unique canonical memory domains".into());
                }
                previous = Some(r.domain.as_str());
                let limit = if r.domain == "host" {
                    self.minimum_host_ram_bytes
                } else {
                    self.minimum_accelerator_memory_bytes
                };
                if r.bytes > limit {
                    return Err("model profile understates phase reservation".into());
                }
            }
            if !domains.contains(&"host".to_owned())
                || (self.execution_mode == "cpu" && domains.len() != 1)
                || (self.execution_mode == "cuda"
                    && (domains.len() != 2 || self.minimum_accelerator_memory_bytes == 0))
            {
                return Err("model profile memory domains mismatch execution mode".into());
            }
        }
        if self.execution_mode == "cpu" && self.minimum_accelerator_memory_bytes != 0 {
            return Err("CPU profile cannot require accelerator memory".into());
        }
        if !matches!(self.availability.as_str(), "available" | "unavailable")
            || !matches!(self.verification_state.as_str(), "verified" | "unverified")
            || !matches!(
                self.development_state.as_str(),
                "untested" | "development-tested"
            )
            || !matches!(
                self.certification_state.as_str(),
                "not-certified" | "execution-certified" | "interactive-certified"
            )
            || (self.certification_state != "not-certified"
                && (self.verification_state != "verified"
                    || self.development_state != "development-tested"))
        {
            return Err("model profile claims an invalid lifecycle state".into());
        }
        Ok(())
    }
}
impl ModelCatalog {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_CATALOG)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ascii(&self.catalog_id, 256)?;
        if self.schema_version != 1 || self.profiles.is_empty() || self.profiles.len() > 256 {
            return Err("invalid frozen model profile catalog bounds/schema".into());
        }
        let mut previous = None;
        let mut manual = 0;
        for p in &self.profiles {
            if previous.is_some_and(|id: &str| id >= p.id()) {
                return Err("model catalog profiles must have unique canonical IDs".into());
            }
            previous = Some(p.id());
            match p {
                SelectableProfile::Manual(p) => {
                    manual += 1;
                    if p.kind != "manual-only" || p.profile_id != "manual-only" || p.remote_fallback
                    {
                        return Err("invalid explicit manual-only model profile".into());
                    }
                }
                SelectableProfile::Model(p) => p.validate()?,
            }
        }
        if manual != 1 {
            return Err("model catalog requires exactly one manual-only profile".into());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        digest(self)
    }
}

record!(ReleaseRequest {
    artifact_type: String,
    catalog_id: String,
    catalog_sequence: u64,
    catalog_sha256: String,
    environment: String,
    not_after: String,
    not_before: String,
    policy_version: String,
    purpose: String,
    release_id: String,
    schema_version: u32,
    signature_algorithm: String,
    signer_key_id: String,
    signing_activity: String,
    signing_assignment_id: String,
    signing_assignment_receipt_sha256: String,
    signing_principal_id: String
});
record!(Approval {
    activity: String,
    approved_at: String,
    approval_decision_receipt_sha256: String,
    assignment_id: String,
    assignment_receipt_sha256: String,
    catalog_sha256: String,
    decision: String,
    principal_id: String,
    release_request_sha256: String,
    release_id: String
});
record!(Statement {
    approval_set_sha256: String,
    artifact_type: String,
    catalog_id: String,
    catalog_sequence: u64,
    catalog_sha256: String,
    environment: String,
    not_after: String,
    not_before: String,
    policy_version: String,
    purpose: String,
    release_id: String,
    release_request_sha256: String,
    schema_version: u32,
    signature_algorithm: String,
    signed_at: String,
    signer_key_id: String,
    signing_activity: String,
    signing_assignment_id: String,
    signing_assignment_receipt_sha256: String,
    signing_principal_id: String
});
record!(SigningIntent {
    approval_set_sha256: String,
    artifact_type: String,
    catalog_id: String,
    catalog_sequence: u64,
    catalog_sha256: String,
    environment: String,
    not_after: String,
    not_before: String,
    policy_version: String,
    purpose: String,
    release_id: String,
    release_request_sha256: String,
    schema_version: u32,
    signature_algorithm: String,
    signer_key_id: String,
    signing_activity: String,
    signing_assignment_id: String,
    signing_assignment_receipt_sha256: String,
    signing_principal_id: String
});
impl SigningIntent {
    pub(crate) fn at(&self, time: String) -> Result<Statement> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or("signing intent missing")?
            .insert("signed_at".into(), time.into());
        let statement: Statement = serde_json::from_value(value)?;
        statement.validate()?;
        Ok(statement)
    }
}
fn signing_activity(env: &str) -> Result<&'static str> {
    environment(env)?;
    Ok(if env == "production" {
        "model-catalog.sign.production"
    } else {
        "model-catalog.sign.lab"
    })
}
fn purpose(env: &str) -> Result<&'static str> {
    environment(env)?;
    Ok(if env == "production" {
        "model-profile-catalog-production"
    } else {
        "model-profile-catalog-lab"
    })
}
fn approval_activities(env: &str) -> Result<BTreeSet<&'static str>> {
    environment(env)?;
    Ok(if env == "production" {
        [
            "model-catalog.approve.license",
            "model-catalog.approve.release",
            "model-catalog.approve.security",
        ]
        .into_iter()
        .collect()
    } else {
        ["model-catalog.approve.lab-release"].into_iter().collect()
    })
}
impl ReleaseRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.artifact_type != "model-profile-catalog-release-request"
            || self.schema_version != 1
            || self.signature_algorithm != "Ed25519"
            || self.purpose != purpose(&self.environment)?
            || self.signing_activity != signing_activity(&self.environment)?
        {
            return Err("invalid model release-request schema/purpose/activity".into());
        }
        positive(self.catalog_sequence)?;
        hash(&self.catalog_sha256)?;
        hash(&self.signing_assignment_receipt_sha256)?;
        for v in [
            &self.catalog_id,
            &self.policy_version,
            &self.release_id,
            &self.signer_key_id,
            &self.signing_assignment_id,
            &self.signing_principal_id,
        ] {
            ascii(v, 256)?;
        }
        dates(&self.not_before, &self.not_after)?;
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}
impl Approval {
    pub(crate) fn validate(&self) -> Result<()> {
        for v in [
            &self.activity,
            &self.principal_id,
            &self.assignment_id,
            &self.release_id,
        ] {
            ascii(v, 256)?;
        }
        for h in [
            &self.assignment_receipt_sha256,
            &self.approval_decision_receipt_sha256,
            &self.release_request_sha256,
            &self.catalog_sha256,
        ] {
            hash(h)?;
        }
        timestamp(&self.approved_at)?;
        if self.decision != "approved" {
            return Err("model catalog approval must be an explicit approved decision".into());
        }
        Ok(())
    }
    pub(crate) fn check_request(&self, request: &ReleaseRequest) -> Result<()> {
        self.validate()?;
        request.validate()?;
        if !approval_activities(&request.environment)?.contains(self.activity.as_str())
            || self.release_id != request.release_id
            || self.catalog_sha256 != request.catalog_sha256
            || self.release_request_sha256 != request.digest()?
            || self.principal_id == request.signing_principal_id
        {
            return Err(
                "model approval does not bind the exact request or independent activity/principal"
                    .into(),
            );
        }
        Ok(())
    }
}
impl Statement {
    pub(crate) fn request(&self) -> Result<ReleaseRequest> {
        let mut value = serde_json::to_value(self)?;
        let obj = value.as_object_mut().ok_or("model statement object")?;
        for key in ["approval_set_sha256", "release_request_sha256", "signed_at"] {
            obj.remove(key);
        }
        obj.insert(
            "artifact_type".into(),
            "model-profile-catalog-release-request".into(),
        );
        Ok(serde_json::from_value(value)?)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.artifact_type != "model-profile-catalog" {
            return Err("unknown signed model catalog statement".into());
        }
        let request = self.request()?;
        request.validate()?;
        hash(&self.approval_set_sha256)?;
        hash(&self.release_request_sha256)?;
        let (start, end) = dates(&self.not_before, &self.not_after)?;
        let signed = timestamp(&self.signed_at)?;
        if signed < start || signed >= end || self.release_request_sha256 != request.digest()? {
            return Err("model statement signing time or exact request mismatch".into());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}
record!(Envelope {approvals:Vec<Approval>,schema_version:u32,signature:String,signature_encoding:String,statement:Statement});
impl Envelope {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse(bytes, MAX_ENVELOPE)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.statement.validate()?;
        decode64::<64>(&self.signature)?;
        if self.schema_version != 1
            || self.signature_encoding != "base64"
            || self.approvals.is_empty()
        {
            return Err("invalid model catalog signature envelope".into());
        }
        let mut principals = BTreeSet::new();
        let mut activities = BTreeSet::new();
        let mut previous = None;
        let request = self.statement.request()?;
        for a in &self.approvals {
            a.check_request(&request)?;
            let order = (&a.activity, &a.principal_id);
            if !principals.insert(&a.principal_id)
                || !activities.insert(a.activity.as_str())
                || previous.is_some_and(|v| v >= order)
                || timestamp(&a.approved_at)? > timestamp(&self.statement.signed_at)?
            {
                return Err("model approval quorum is duplicate, unordered, non-independent or after signing".into());
            }
            previous = Some(order);
        }
        if activities != approval_activities(&self.statement.environment)? {
            return Err("model approval quorum does not match environment".into());
        }
        let approvals = serde_json::json!({"approvals":self.approvals,"schema_version":1});
        if digest(&approvals)? != self.statement.approval_set_sha256 {
            return Err("model statement does not bind exact canonical approval set".into());
        }
        Ok(())
    }
}
record!(Admission {
    catalog_json: String,
    envelope_json: String,
    trust_sha256: String
});
impl Admission {
    pub(crate) fn validate(&self) -> Result<()> {
        hash(&self.trust_sha256)?;
        let catalog = ModelCatalog::parse(self.catalog_json.as_bytes())?;
        let envelope = Envelope::parse(self.envelope_json.as_bytes())?;
        if catalog.catalog_id != envelope.statement.catalog_id
            || catalog.digest()? != envelope.statement.catalog_sha256
        {
            return Err("model catalog does not bind exact signed identity/bytes".into());
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
pub(crate) fn publish(
    state: &mut Option<State>,
    expected: u64,
    bundle: &SignedTrust,
) -> Result<()> {
    bundle.validate()?;
    let current = state.as_ref();
    let sequence = current.map_or(0, |s| s.trust.bundle.bundle_sequence);
    if sequence == expected && sequence == bundle.bundle.bundle_sequence {
        if current.is_some_and(|s| s.trust == *bundle) {
            return Ok(());
        }
        return Err("model trust digest forks an anchored sequence".into());
    }
    if sequence != expected
        || bundle.bundle.bundle_sequence
            != expected
                .checked_add(1)
                .ok_or("model trust sequence overflow")?
    {
        return Err("model trust compare-and-swap sequence mismatch".into());
    }
    if let Some(old) = current {
        if old.trust.bundle.environment != bundle.bundle.environment
            || bundle.bundle.previous_bundle_sha256.as_deref() != Some(old.trust.digest()?.as_str())
        {
            return Err("model trust environment/predecessor mismatch".into());
        }
        // Retained public leaves are durable tombstones in the same anchored
        // history, not revivable identifiers. They remain bounded by the
        // frozen bundle's key inventory ceiling; no separate NV is allocated.
        for prior in &old.trust.bundle.keys {
            let next = bundle
                .bundle
                .keys
                .iter()
                .find(|key| key.key_id == prior.key_id)
                .ok_or("model trust rotation drops historical key identity/revocation tombstone")?;
            if next.public_key != prior.public_key
                || next.environment != prior.environment
                || next.role != prior.role
                || next.purposes != prior.purposes
            {
                return Err("model trust rotation reuses historical key identity for another material/purpose".into());
            }
            if let Some(revoked) = &prior.revoked_at {
                let prior_time = timestamp(revoked)?;
                let next_time = next
                    .revoked_at
                    .as_deref()
                    .map(timestamp)
                    .transpose()?
                    .ok_or("model key revocation cannot be removed")?;
                if next_time > prior_time {
                    return Err(
                        "model key revocation is irreversible and cannot be postponed".into(),
                    );
                }
            }
        }
    }
    let mut next = current.cloned().unwrap_or(State {
        trust: bundle.clone(),
        floor: 0,
        current: None,
    });
    next.trust = bundle.clone();
    *state = Some(next);
    Ok(())
}
pub(crate) fn admit(state: &mut Option<State>, expected: u64, admission: &Admission) -> Result<()> {
    admission.validate()?;
    let value = state
        .as_mut()
        .ok_or("model trust must be committed before catalog admission")?;
    let envelope = Envelope::parse(admission.envelope_json.as_bytes())?;
    let sequence = envelope.statement.catalog_sequence;
    if expected != value.floor
        || admission.trust_sha256 != value.trust.digest()?
        || envelope.statement.environment != value.trust.bundle.environment
        || sequence < value.floor
        || (value.floor == 0 && sequence != 1)
    {
        return Err("model catalog trust/environment/CAS floor mismatch".into());
    }
    if sequence == value.floor
        && value
            .current
            .as_ref()
            .map_or(true, |old| old.catalog_json != admission.catalog_json)
    {
        return Err("model catalog digest forks an anchored sequence".into());
    }
    value.floor = sequence;
    value.current = Some(admission.clone());
    Ok(())
}
pub(crate) fn check_custodian(
    catalog: &Catalog,
    principal: &str,
    assignment: &str,
    receipt: &str,
    activity: &str,
    interval: Interval,
) -> Result<()> {
    let record = catalog
        .assignments
        .get(assignment)
        .ok_or("unknown model custodian assignment")?;
    let role = catalog
        .roles
        .get(&record.role)
        .ok_or("unknown model custodian role")?;
    let p = catalog
        .registry()?
        .principal(principal)
        .ok_or("unknown model custodian principal")?;
    let state = catalog.principal_states.get(principal);
    if record.subject != principal
        || record.revoked
        || role.version != record.role_version
        || !role.activities.iter().any(|v| v == activity)
        || !p.enabled
        || state.is_some_and(|s| !s.enabled)
        || state.map_or(p.generation, |s| s.generation) != record.subject_generation
        || catalog.deleted_principals.contains(principal)
        || catalog.needs_password_aging.contains(principal)
        || !catalog.account_commitments.contains_key(principal)
        || catalog
            .assignment_receipts
            .get(assignment)
            .map(String::as_str)
            != Some(receipt)
        || !interval.within(record.not_before_ms, record.expires_ms)?
    {
        return Err("model custody requires exact current finite principal/role/assignment and actual checkpointed receipt".into());
    }
    if let Some(day) = catalog.password_day(principal) {
        if !interval.within(
            i64::from(day) * 86_400_000,
            (i64::from(day) + 90) * 86_400_000,
        )? {
            return Err("model custodian password aging is outside protected UTC".into());
        }
    }
    Ok(())
}
pub(crate) fn verify_catalog(
    catalog: &Catalog,
    admission: &Admission,
    interval: Interval,
    packs: &[PackVerification],
) -> Result<ModelCatalog> {
    let hardware = if catalog
        .model_trust
        .as_ref()
        .is_some_and(|s| s.trust.bundle.environment == "production")
    {
        Some(MachineTuple::current()?)
    } else {
        None
    };
    verify_catalog_with_policy(
        catalog,
        admission,
        interval,
        packs,
        &RootPolicy::current()?,
        hardware.as_ref(),
    )
}
fn verify_catalog_with_policy(
    catalog: &Catalog,
    admission: &Admission,
    interval: Interval,
    packs: &[PackVerification],
    policy: &RootPolicy,
    hardware: Option<&MachineTuple>,
) -> Result<ModelCatalog> {
    admission.validate()?;
    let state = catalog
        .model_trust
        .as_ref()
        .ok_or("model trust is not TPM-anchored")?;
    if admission.trust_sha256 != state.trust.digest()? {
        return Err("model catalog was invalidated by trust rotation".into());
    }
    check_separation_with_policy(catalog, &state.trust, policy)?;
    let profiles = ModelCatalog::parse(admission.catalog_json.as_bytes())?;
    let envelope = Envelope::parse(admission.envelope_json.as_bytes())?;
    let statement = &envelope.statement;
    state.trust.root_with(policy, interval)?;
    if !policy
        .accepted_catalog_policy_versions
        .contains(&statement.policy_version)
        || statement.environment != state.trust.bundle.environment
    {
        return Err("model catalog policy/environment mismatch".into());
    }
    let release = catalog
        .release
        .as_ref()
        .and_then(|s| s.acknowledged.as_ref())
        .ok_or("model catalog requires an acknowledged OS release")?;
    if statement.release_id != release.release || statement.environment != release.environment {
        return Err("model catalog signature belongs to another OS release".into());
    }
    check_catalog_time(&envelope, interval)?;
    for a in &envelope.approvals {
        if catalog
            .model_approvals
            .get(&a.approval_decision_receipt_sha256)
            != Some(a)
        {
            return Err(
                "model approval lacks exact independently authenticated decision event".into(),
            );
        }
        check_custodian(
            catalog,
            &a.principal_id,
            &a.assignment_id,
            &a.assignment_receipt_sha256,
            &a.activity,
            Interval::new(timestamp(&a.approved_at)?, timestamp(&a.approved_at)?)?,
        )?;
        check_custodian(
            catalog,
            &a.principal_id,
            &a.assignment_id,
            &a.assignment_receipt_sha256,
            &a.activity,
            interval,
        )?;
    }
    if catalog.model_signings.get(&statement.digest()?) != Some(statement) {
        return Err("model signing lacks exact authenticated custodian event".into());
    }
    check_custodian(
        catalog,
        &statement.signing_principal_id,
        &statement.signing_assignment_id,
        &statement.signing_assignment_receipt_sha256,
        &statement.signing_activity,
        Interval::new(
            timestamp(&statement.signed_at)?,
            timestamp(&statement.signed_at)?,
        )?,
    )?;
    check_custodian(
        catalog,
        &statement.signing_principal_id,
        &statement.signing_assignment_id,
        &statement.signing_assignment_receipt_sha256,
        &statement.signing_activity,
        interval,
    )?;
    let bytes = canonical(statement)?;
    let signature = decode64::<64>(&envelope.signature)?;
    state.trust.verify_leaf(
        &statement.signer_key_id,
        &statement.purpose,
        &bytes,
        &signature,
        Interval::new(
            timestamp(&statement.signed_at)?,
            timestamp(&statement.signed_at)?,
        )?,
    )?;
    state.trust.verify_with_policy(
        policy,
        &statement.signer_key_id,
        &statement.purpose,
        &bytes,
        &signature,
        interval,
    )?;
    let mut available = 0;
    for p in &profiles.profiles {
        if let SelectableProfile::Model(p) = p {
            if p.availability == "available" {
                available += 1;
                let verification = packs
                    .iter()
                    .find(|v| {
                        v.manifest_sha256 == p.model_pack_manifest_sha256
                            && v.runtime_tuple
                                .digest()
                                .is_ok_and(|d| d == p.runtime_tuple_sha256)
                    })
                    .ok_or("available model profile lacks exact verified pack/runtime tuple")?;
                let required = match p.certification_state.as_str() {
                    "execution-certified" => 3,
                    "interactive-certified" => 4,
                    _ => 2,
                };
                if p.verification_state != "verified"
                    || p.development_state != "development-tested"
                    || verification.state < required
                    || verification.state > 4
                    || (statement.environment == "production" && required < 3)
                    || (verification.state >= 3
                        && verification
                            .evidence_sha256
                            .as_ref()
                            .map_or(true, |v| hash(v).is_err()))
                {
                    return Err("model catalog available profile lacks its exact loadable/certified evidence state".into());
                }
                if statement.environment == "production" {
                    let hardware = hardware.ok_or(
                        "production certification needs actual kernel machine observation",
                    )?;
                    if verification.qualifications.len() != usize::from(required - 2) {
                        return Err("production model lacks complete externally signed exact-image qualification chain".into());
                    }
                    for (index, evidence) in verification.qualifications.iter().enumerate() {
                        if evidence.level
                            != if index == 0 {
                                "execution"
                            } else {
                                "interactive"
                            }
                        {
                            return Err(
                                "production qualification chain skips or repeats a lifecycle stage"
                                    .into(),
                            );
                        }
                        evidence.check(release, p, hardware, catalog.registry()?.installation())?;
                    }
                    if verification
                        .qualifications
                        .last()
                        .map(digest)
                        .transpose()?
                        .as_ref()
                        != verification.evidence_sha256.as_ref()
                    {
                        return Err("production qualification evidence differs from final signed certificate".into());
                    }
                }
            }
        }
    }
    if available == 0 {
        return Err("signed model catalog requires an available verified model profile".into());
    }
    Ok(profiles)
}
fn check_catalog_time(envelope: &Envelope, interval: Interval) -> Result<()> {
    live(
        &envelope.statement.not_before,
        &envelope.statement.not_after,
        None,
        interval,
    )?;
    let lower = interval.endpoints().0;
    if timestamp(&envelope.statement.signed_at)? > lower
        || envelope
            .approvals
            .iter()
            .any(|a| timestamp(&a.approved_at).map_or(true, |t| t > lower))
    {
        return Err("model signing/approval time is in the protected future".into());
    }
    Ok(())
}
pub(crate) fn current_catalog(
    catalog: &Catalog,
    interval: Interval,
    packs: &[PackVerification],
) -> Result<ModelCatalog> {
    let state = catalog
        .model_trust
        .as_ref()
        .ok_or("model trust is not anchored")?;
    let admission = state
        .current
        .as_ref()
        .ok_or("model catalog is not admitted")?;
    if Envelope::parse(admission.envelope_json.as_bytes())?
        .statement
        .catalog_sequence
        != state.floor
    {
        return Err("model catalog no longer binds the exact anchored floor".into());
    }
    verify_catalog(catalog, admission, interval, packs)
}
pub(crate) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::PublishModelTrust { .. }
            | Command::AdmitModelCatalog { .. }
            | Command::RecordModelCatalogApproval { .. }
            | Command::RecordModelCatalogSigning { .. }
    )
}
pub(crate) fn check_command_time(
    command: &Command,
    state: &Option<State>,
    interval: Interval,
) -> Result<()> {
    match command {
        Command::PublishModelTrust { bundle, .. } => bundle.check_time(interval),
        Command::AdmitModelCatalog { admission, .. } => {
            state
                .as_ref()
                .ok_or("missing model trust")?
                .trust
                .check_time(interval)?;
            check_catalog_time(
                &Envelope::parse(admission.envelope_json.as_bytes())?,
                interval,
            )
        }
        Command::RecordModelCatalogApproval { request, approval } => {
            live(&request.not_before, &request.not_after, None, interval)?;
            if timestamp(&approval.approved_at)? > interval.endpoints().0 {
                return Err("model approval time is in the protected future".into());
            }
            Ok(())
        }
        Command::RecordModelCatalogSigning { statement } => {
            live(&statement.not_before, &statement.not_after, None, interval)?;
            if timestamp(&statement.signed_at)? > interval.endpoints().0 {
                return Err("model signing time is in the protected future".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
fn decision_time(at: &str, interval: Interval) -> Result<()> {
    let at = timestamp(at)?;
    let (lower, upper) = interval.endpoints();
    if at > lower || upper.checked_sub(at).map_or(true, |age| age >= 30_000) {
        return Err("model custody execution time no longer binds its original bounded protected UTC exchange".into());
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct TimeProof {
    policy: RootPolicy,
    catalog: Catalog,
    command: Command,
    keys: Vec<(String, String)>,
    retained: bool,
}
impl TimeProof {
    pub(crate) fn capture(
        catalog: &Catalog,
        command: &Command,
        packs: &[PackVerification],
    ) -> Result<Self> {
        let mut keys = packs
            .iter()
            .flat_map(|p| p.signing_keys.iter().cloned())
            .collect::<Vec<_>>();
        if let Command::AdmitModelCatalog { admission, .. } = command {
            let e = Envelope::parse(admission.envelope_json.as_bytes())?;
            keys.push((e.statement.signer_key_id, e.statement.purpose));
        }
        if let Command::RecordModelCatalogSigning { statement } = command {
            keys.push((statement.signer_key_id.clone(), statement.purpose.clone()));
        }
        Ok(Self {
            policy: RootPolicy::current()?,
            catalog: catalog.clone(),
            command: command.clone(),
            keys,
            retained: false,
        })
    }
    pub(crate) fn retain_original(
        &mut self,
        proof: &crate::admin_governance::RetainedModelDecision,
    ) -> Result<()> {
        proof.accepts(&self.command)?;
        self.retained = true;
        Ok(())
    }
    pub(crate) fn check(&self, interval: Interval) -> Result<()> {
        check_command_time(&self.command, &self.catalog.model_trust, interval)?;
        if !self.retained {
            match &self.command {
                Command::RecordModelCatalogApproval { approval, .. } => {
                    decision_time(&approval.approved_at, interval)?
                }
                Command::RecordModelCatalogSigning { statement } => {
                    decision_time(&statement.signed_at, interval)?
                }
                _ => (),
            }
        }
        let trust = match &self.command {
            Command::PublishModelTrust { bundle, .. } => bundle,
            _ => {
                &self
                    .catalog
                    .model_trust
                    .as_ref()
                    .ok_or("model trust is not anchored")?
                    .trust
            }
        };
        trust.check_time(interval)?;
        let root = self
            .policy
            .roots
            .iter()
            .find(|r| {
                r.key_id == trust.bundle.root_key_id && r.environment == trust.bundle.environment
            })
            .ok_or("model root removed")?;
        live(
            &root.not_before,
            &root.not_after,
            root.revoked_at.as_deref(),
            interval,
        )?;
        for (key, purpose) in &self.keys {
            trust.check_key_time(key, purpose, interval)?;
        }
        match &self.command {
            Command::RecordModelCatalogApproval { approval, .. } => check_custodian(
                &self.catalog,
                &approval.principal_id,
                &approval.assignment_id,
                &approval.assignment_receipt_sha256,
                &approval.activity,
                interval,
            )?,
            Command::RecordModelCatalogSigning { statement } => {
                check_custodian(
                    &self.catalog,
                    &statement.signing_principal_id,
                    &statement.signing_assignment_id,
                    &statement.signing_assignment_receipt_sha256,
                    &statement.signing_activity,
                    interval,
                )?;
                check_signing_approvals(&self.catalog, statement, interval)?;
            }
            Command::AdmitModelCatalog { admission, .. } => {
                let e = Envelope::parse(admission.envelope_json.as_bytes())?;
                for a in &e.approvals {
                    check_custodian(
                        &self.catalog,
                        &a.principal_id,
                        &a.assignment_id,
                        &a.assignment_receipt_sha256,
                        &a.activity,
                        interval,
                    )?;
                }
                let s = &e.statement;
                check_custodian(
                    &self.catalog,
                    &s.signing_principal_id,
                    &s.signing_assignment_id,
                    &s.signing_assignment_receipt_sha256,
                    &s.signing_activity,
                    interval,
                )?;
            }
            _ => (),
        }
        Ok(())
    }
}

pub(crate) fn check_live(
    catalog: &Catalog,
    command: &Command,
    interval: Interval,
) -> Result<Vec<PackVerification>> {
    check_command_time(command, &catalog.model_trust, interval)?;
    if is_command(command) {
        let trust = match command {
            Command::PublishModelTrust { bundle, .. } => bundle,
            _ => {
                &catalog
                    .model_trust
                    .as_ref()
                    .ok_or("missing anchored model trust")?
                    .trust
            }
        };
        check_separation(catalog, trust)?;
        if let Some(release) = catalog
            .release
            .as_ref()
            .and_then(|s| s.acknowledged.as_ref())
        {
            if release.environment != trust.bundle.environment {
                return Err("model trust crosses the acknowledged release environment".into());
            }
        }
    }
    match command {
        Command::PublishModelTrust {
            bundle,
            expected_sequence,
        } => {
            bundle.check_root(interval)?;
            let mut state = catalog.model_trust.clone();
            publish(&mut state, *expected_sequence, bundle)?;
            Ok(vec![])
        }
        Command::AdmitModelCatalog { admission, .. } => {
            let trust = &catalog
                .model_trust
                .as_ref()
                .ok_or("missing model trust")?
                .trust;
            let profiles = ModelCatalog::parse(admission.catalog_json.as_bytes())?;
            let packs = crate::model::verify_catalog_packs(&profiles, trust, interval)?;
            verify_catalog(catalog, admission, interval, &packs)?;
            Ok(packs)
        }
        Command::RecordModelCatalogApproval { approval, .. } => {
            let trust = &catalog
                .model_trust
                .as_ref()
                .ok_or("missing model trust")?
                .trust;
            trust.check_root(interval)?;
            check_custodian(
                catalog,
                &approval.principal_id,
                &approval.assignment_id,
                &approval.assignment_receipt_sha256,
                &approval.activity,
                interval,
            )?;
            Ok(vec![])
        }
        Command::RecordModelCatalogSigning { statement } => {
            let trust = &catalog
                .model_trust
                .as_ref()
                .ok_or("missing model trust")?
                .trust;
            trust.check_root(interval)?;
            trust.check_key_time(&statement.signer_key_id, &statement.purpose, interval)?;
            check_custodian(
                catalog,
                &statement.signing_principal_id,
                &statement.signing_assignment_id,
                &statement.signing_assignment_receipt_sha256,
                &statement.signing_activity,
                interval,
            )?;
            check_signing_approvals(catalog, statement, interval)?;
            Ok(vec![])
        }
        _ => Ok(vec![]),
    }
}
fn check_separation(catalog: &Catalog, trust: &SignedTrust) -> Result<()> {
    check_separation_with_policy(catalog, trust, &RootPolicy::current()?)
}
fn check_separation_with_policy(
    catalog: &Catalog,
    trust: &SignedTrust,
    policy: &RootPolicy,
) -> Result<()> {
    let mut prohibited = BTreeSet::new();
    if let Some(release) = &catalog.release {
        prohibited.insert(release.trust.trust.root_sha256.clone());
        for k in &release.trust.trust.keys {
            prohibited.insert(key_fingerprint(&crate::tpm::decode::<32>(
                &k.public_key_hex,
            )?));
        }
    }
    if let Some(skills) = &catalog.skill_trust {
        prohibited.insert(skills.trust.trust.root_sha256.clone());
        for k in &skills.trust.trust.keys {
            prohibited.insert(key_fingerprint(&crate::tpm::decode::<32>(
                &k.public_key_hex,
            )?));
        }
    }
    let root = policy
        .roots
        .iter()
        .find(|r| r.key_id == trust.bundle.root_key_id && r.environment == trust.bundle.environment)
        .ok_or("unknown model root")?;
    if prohibited.contains(&key_fingerprint(&decode64::<32>(&root.public_key)?))
        || trust.bundle.keys.iter().any(|k| {
            decode64::<32>(&k.public_key)
                .map_or(true, |v| prohibited.contains(&key_fingerprint(&v)))
        })
    {
        return Err(
            "model custody cannot reuse actual current OS or skill signing roots/leaves".into(),
        );
    }
    Ok(())
}
pub(crate) fn check_model_separation(catalog: &Catalog, trust: &SignedTrust) -> Result<()> {
    check_separation(catalog, trust)
}
fn check_signing_approvals(
    catalog: &Catalog,
    statement: &Statement,
    interval: Interval,
) -> Result<()> {
    let request = statement.request()?;
    let mut approvals = catalog
        .model_approvals
        .values()
        .filter(|a| a.release_request_sha256 == statement.release_request_sha256)
        .cloned()
        .collect::<Vec<_>>();
    approvals.sort_by(|a, b| (&a.activity, &a.principal_id).cmp(&(&b.activity, &b.principal_id)));
    if approvals.len() != approval_activities(&statement.environment)?.len()
        || digest(&serde_json::json!({"approvals":approvals,"schema_version":1}))?
            != statement.approval_set_sha256
    {
        return Err("model signer lacks exact independently checkpointed approval quorum".into());
    }
    let mut principals = BTreeSet::new();
    let mut activities = BTreeSet::new();
    for a in approvals {
        a.check_request(&request)?;
        if !principals.insert(a.principal_id.clone())
            || !activities.insert(a.activity.clone())
            || timestamp(&a.approved_at)? > timestamp(&statement.signed_at)?
        {
            return Err("model signing quorum is non-independent or later than actual signing authorization".into());
        }
        check_custodian(
            catalog,
            &a.principal_id,
            &a.assignment_id,
            &a.assignment_receipt_sha256,
            &a.activity,
            interval,
        )?;
    }
    if activities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != approval_activities(&statement.environment)?
    {
        return Err("model signing activities do not match exact quorum".into());
    }
    Ok(())
}
