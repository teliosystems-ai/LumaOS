//! Immutable build provenance projection, never a caller-minted UTC authority.
//! Cryptography is reverified during source/build/package admission. Runtime
//! requires the actual readonly records pinned in its complete release inventory
//! and compares their closed contents against this compiled reviewed identity.
use crate::Result;
use serde::Deserialize;

const PROVENANCE: &[u8] = include_bytes!("../../../../native/image/utc/reviewed-release.json");
const SOURCE_INPUTS: &[u8] =
    include_bytes!("../../../../native/image/utc/reviewed-source-inputs.json");

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Signature {
    url: String,
    sha256: String,
    bytes: u64,
    signer_fingerprint: String,
    primary_fingerprint: String,
    hash_algorithm: String,
    signature_class: String,
    created_unix: u64,
    key_sha256: String,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Provenance {
    schema_version: u32,
    upstream: String,
    version: String,
    url: String,
    sha256: String,
    bytes: u64,
    signature_verified: bool,
    signature: Signature,
    verification: String,
    source_review: String,
    qualification: String,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceFiles {
    #[serde(rename = "ntp_core.c")]
    ntp_core: String,
    #[serde(rename = "ntp_auth.c")]
    ntp_auth: String,
    #[serde(rename = "nts_ntp_client.c")]
    nts_ntp_client: String,
    #[serde(rename = "nts_ke_session.c")]
    nts_ke_session: String,
    #[serde(rename = "Makefile.in")]
    makefile: String,
    #[serde(rename = "tls_gnutls.c")]
    tls_gnutls: String,
    #[serde(rename = "sys_linux.c")]
    sys_linux: String,
    #[serde(rename = "local.c")]
    local: String,
    #[serde(rename = "publisher.c")]
    publisher: String,
    #[serde(rename = "publisher.h")]
    publisher_header: String,
    #[serde(rename = "chrony_hook.c")]
    chrony_hook: String,
    #[serde(rename = "chrony_hook.h")]
    chrony_hook_header: String,
    #[serde(rename = "luma_policy_digest.h")]
    policy_header: String,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceInputs {
    schema_version: u32,
    upstream_version: String,
    qualification: String,
    upstream_archive_sha256: String,
    policy_digest: String,
    files: SourceFiles,
}

pub(super) fn validate(role: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 32768 {
        return Err("UTC dependency provenance exceeds its bound".into());
    }
    let matches = match role {
        "provenance" => {
            serde_json::from_slice::<Provenance>(bytes)?
                == serde_json::from_slice::<Provenance>(PROVENANCE)?
        }
        "source_inputs" => {
            serde_json::from_slice::<SourceInputs>(bytes)?
                == serde_json::from_slice::<SourceInputs>(SOURCE_INPUTS)?
        }
        _ => return Err("UTC dependency provenance role is not admitted".into()),
    };
    if !matches {
        return Err(
            "UTC dependency provenance differs from compiled authenticated release/source review"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compiled_release_and_source_identities_accept_only_the_reviewed_real_tuple() {
        validate("provenance", PROVENANCE).unwrap();
        validate("source_inputs", SOURCE_INPUTS).unwrap();
        let source: SourceInputs = serde_json::from_slice(SOURCE_INPUTS).unwrap();
        assert_eq!(
            source.policy_digest,
            crate::bundle::hex(&crate::utc_policy::ApprovedPolicy::fixed().unwrap().digest())
        );
        for role in ["seed", "caller_approved", "library"] {
            assert!(validate(role, PROVENANCE).is_err());
        }
        assert!(validate("provenance", SOURCE_INPUTS).is_err());
        assert!(validate("source_inputs", PROVENANCE).is_err());
    }

    #[test]
    fn release_refuses_unsigned_numeric_claims_wrong_key_subkey_digest_version_and_caller_approval()
    {
        for choice in 0..12 {
            let mut value: serde_json::Value = serde_json::from_slice(PROVENANCE).unwrap();
            match choice {
                0 => value["signature_verified"] = json!(false),
                1 => value["signature_verified"] = json!(1),
                2 => value["version"] = json!("4.8"),
                3 => value["schema_version"] = json!(1),
                4 => value["sha256"] = json!("ab".repeat(32)),
                5 => value["signature"]["signer_fingerprint"] = json!("cd".repeat(20)),
                6 => value["signature"]["primary_fingerprint"] = json!("cd".repeat(20)),
                7 => value["signature"]["hash_algorithm"] = json!("SHA1"),
                8 => value["signature"]["key_sha256"] = json!("ab".repeat(32)),
                9 => value["signature"]["created_unix"] = json!(0),
                10 => value["approved"] = json!(true),
                11 => value["signature"]["qualification"] = json!("certified"),
                _ => unreachable!(),
            }
            assert!(
                validate("provenance", &serde_json::to_vec(&value).unwrap()).is_err(),
                "choice {choice}"
            );
        }
        let text = std::str::from_utf8(PROVENANCE).unwrap();
        assert!(validate(
            "provenance",
            text.replacen(
                "\"signature_verified\":true",
                "\"signature_verified\":true,\"signature_verified\":true",
                1
            )
            .as_bytes()
        )
        .is_err());
        assert!(validate(
            "provenance",
            text.replacen(
                "\"hash_algorithm\":\"SHA512\"",
                "\"hash_algorithm\":\"SHA512\",\"hash_algorithm\":\"SHA512\"",
                1
            )
            .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn source_refuses_each_changed_omitted_duplicate_extra_or_unreviewed_hook_file() {
        let original: serde_json::Value = serde_json::from_slice(SOURCE_INPUTS).unwrap();
        for name in original["files"].as_object().unwrap().keys() {
            let mut changed = original.clone();
            changed["files"][name] = json!("ab".repeat(32));
            assert!(validate("source_inputs", &serde_json::to_vec(&changed).unwrap()).is_err());
            changed["files"].as_object_mut().unwrap().remove(name);
            assert!(validate("source_inputs", &serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut extra = original;
        extra["files"]["unreviewed.c"] = json!("ab".repeat(32));
        assert!(validate("source_inputs", &serde_json::to_vec(&extra).unwrap()).is_err());
        let text = std::str::from_utf8(SOURCE_INPUTS).unwrap();
        assert!(validate(
            "source_inputs",
            text.replacen("\"files\":{", "\"files\":{\"publisher.c\":\"ab\",", 1)
                .as_bytes()
        )
        .is_err());
        assert!(validate("source_inputs", &vec![b' '; 32769]).is_err());
        assert!(validate("source_inputs", b"").is_err());
    }
}
