//! Fixed owner-approved UTC source/bounds policy. Policy bytes are NOT authority.
//! No external policy path, provider override, or host clock/service mutation.
#![cfg_attr(not(test), allow(dead_code))] // Live publisher/service integration remains pending.
use crate::{utc_bounds::Policy, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub(crate) const POLICY_BYTES: &[u8] =
    include_bytes!("../../../native/image/utc/approved-policy.json");

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Operator {
    id: u8,
    name: String,
    hostname: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    approved_on: String,
    operators: Vec<Operator>,
    minimum_operators: usize,
    max_age_ms: u64,
    max_width_ms: u64,
    rate_error_ppm: u32,
    offline_authorization: String,
    leap_action: String,
}

pub(crate) struct ApprovedPolicy {
    digest: [u8; 32],
}

impl ApprovedPolicy {
    pub(crate) fn fixed() -> Result<Self> {
        parse(POLICY_BYTES)
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn bounds(&self) -> Policy {
        Policy {
            max_age_ms: 180_000,
            max_width_ms: 500,
            drift_ppm: 100,
        }
    }
}

// This parser is not an API for policy substitution. Even valid JSON must
// match both the exact approved semantics AND the immutable compiled bytes.
fn parse(bytes: &[u8]) -> Result<ApprovedPolicy> {
    if bytes.len() > 4_096 {
        return Err("UTC policy exceeds fixed bounds".into());
    }
    let doc: Document = serde_json::from_slice(bytes)?;
    let operators = [
        Operator {
            id: 1,
            name: "Cloudflare".into(),
            hostname: "time.cloudflare.com".into(),
        },
        Operator {
            id: 2,
            name: "Netnod".into(),
            hostname: "nts.netnod.se".into(),
        },
        Operator {
            id: 3,
            name: "PTB".into(),
            hostname: "ptbtime1.ptb.de".into(),
        },
    ];
    if doc.schema_version != 1
        || doc.approved_on != "2026-10-05"
        || doc.operators != operators
        || doc.minimum_operators != 2
        || doc.max_age_ms != 180_000
        || doc.max_width_ms != 500
        || doc.rate_error_ppm != 100
        || doc.offline_authorization != "deny"
        || doc.leap_action != "fence"
        || bytes != POLICY_BYTES
    {
        return Err("UTC policy is not the fixed owner-approved policy".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"luma-native-approved-utc-policy-v1\0");
    hash.update(bytes);
    Ok(ApprovedPolicy {
        digest: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_policy_has_stable_domain_separated_digest_and_bounds() {
        let policy = ApprovedPolicy::fixed().unwrap();
        assert_eq!(policy.digest(), ApprovedPolicy::fixed().unwrap().digest());
        assert_ne!(
            policy.digest().as_slice(),
            Sha256::digest(POLICY_BYTES).as_slice()
        );
        assert_eq!(policy.bounds().max_age_ms, 180_000);
        assert_eq!(policy.bounds().max_width_ms, 500);
        assert_eq!(policy.bounds().drift_ppm, 100);
    }
    #[test]
    fn no_unknown_fields_or_looser_bounds_offline_mode_or_provider_substitution() {
        let original = std::str::from_utf8(POLICY_BYTES).unwrap();
        for (from, to) in [
            ("180000", "180001"),
            ("500,", "501,"),
            ("\"rate_error_ppm\": 100", "\"rate_error_ppm\": 99"),
            ("\"minimum_operators\": 2", "\"minimum_operators\": 1"),
            ("\"deny\"", "\"allow\""),
            ("\"fence\"", "\"smear\""),
            ("time.cloudflare.com", "example.com"),
            (
                "\"schema_version\": 1,",
                "\"schema_version\": 1, \"trusted\": true,",
            ),
            (
                "\"schema_version\": 1,",
                "\"schema_version\": 1, \"schema_version\": 1,",
            ),
            ("\"id\": 2", "\"id\": 1"),
        ] {
            let changed = original.replace(from, to);
            assert_ne!(changed, original);
            assert!(parse(changed.as_bytes()).is_err());
        }
        assert!(parse(&[b' '; 4_097]).is_err());
        assert!(parse(b"{}").is_err());
    }
    #[test]
    fn reordered_or_reformatted_bytes_cannot_replace_pinned_policy() {
        let doc: serde_json::Value = serde_json::from_slice(POLICY_BYTES).unwrap();
        let compact = serde_json::to_vec(&doc).unwrap();
        assert!(parse(&compact).is_err());
        let mut changed = POLICY_BYTES.to_vec();
        changed.push(b'\n');
        assert!(parse(&changed).is_err());
    }
}
