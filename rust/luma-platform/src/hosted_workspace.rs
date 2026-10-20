//! Separate Windows workspace account protocol. Public requests contain no
//! password/verifier. A Windows actor binding is never Linux PAM authority.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
#[path = "hosted_workspace_accounts.rs"]
mod accounts;
#[path = "hosted_workspace_worker.rs"]
mod worker;

pub(crate) fn command(arguments: &[String]) -> Result<()> {
    worker::command(arguments)
}

pub(crate) fn drain(request_sha: &str) -> Result<()> {
    crate::hosted_windows::drain_profile(
        "luma-hosted-workspace-bootstrap.service",
        "/sys/fs/cgroup/lumahosted.slice/luma-hosted-workspace-bootstrap.service",
        PROFILE,
        request_sha,
    )
}

const PROFILE: &str = "luma-windows-hosted-workspace-v1";
const PURPOSE_SECONDS: u32 = 30;
const CPU_SECONDS: u32 = 25;
const DRAIN_SECONDS: u32 = 5;
const PASSWD: &[u8] = b"root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n";
const GROUP: &[u8] = b"root:x:0:\nnogroup:x:65534:\n";
const SHADOW: &[u8] = b"root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n";
const GSHADOW: &[u8] = b"root:!::\nnogroup:!::\n";
const PAM: &[u8] = b"# Local Linux password/account verification, not a product Admin role.\nauth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so nodelay\naccount required /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n";
const NSS: &[u8] = b"passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\n";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    profile: String,
    nonce: String,
    installation: String,
    release_sha256: String,
    runtime_manifest_sha256: String,
    profile_sha256: String,
    actor_sid_sha256: String,
    login: String,
    uid: u32,
    gid: u32,
    account_generation: u32,
    protected_utc_day: u32,
    utc_proof_sha256: String,
}

fn login(value: &str) -> bool {
    !matches!(value, "root" | "nobody" | "nogroup")
        && (1..=31).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Every field/value in this protocol is ASCII. A BTreeMap guarantees the
    // same sorted member order independently of serde_json's feature flags.
    let fields: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(serde_json::to_value(value)?)?;
    let mut result = serde_json::to_vec(&fields)?;
    result.push(b'\n');
    Ok(result)
}

fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > 32768 {
        return Err("workspace public request exceeds its fixed bound".into());
    }
    let request: Request = serde_json::from_slice(bytes)?;
    for value in [
        &request.nonce,
        &request.installation,
        &request.release_sha256,
        &request.runtime_manifest_sha256,
        &request.profile_sha256,
        &request.actor_sid_sha256,
        &request.utc_proof_sha256,
    ] {
        crate::hosted_fence::digest(value)?;
    }
    if request.schema_version != 1
        || request.profile != PROFILE
        || !login(&request.login)
        || request.uid != 1000
        || request.gid != 1000
        || request.account_generation != 1
        || !(1..=2_932_896).contains(&request.protected_utc_day)
        || canonical(&request)? != bytes
    {
        return Err("workspace request changes its canonical one-account/UTC binding".into());
    }
    Ok(request)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    profile: String,
    runtime: String,
    runtime_manifest_sha256: String,
    default_uid: u32,
    wsl_flags: u32,
    account_uid: u32,
    account_gid: u32,
    account_generation: u32,
    password_max_age_days: u32,
    bootstrap_purpose_seconds: u32,
    bootstrap_cpu_seconds: u32,
    drain_seconds: u32,
    memory_max_bytes: u64,
    memory_swap_max_bytes: u64,
    tasks_max: u32,
    cpu_quota_usec: u32,
    cpu_period_usec: u32,
    account_baselines: BTreeMap<String, String>,
    pam_sha256: String,
    nss_sha256: String,
}

fn profile(runtime: &str) -> Result<Profile> {
    crate::hosted_fence::digest(runtime)?;
    Ok(Profile {
        schema_version: 3,
        profile: PROFILE.into(),
        runtime: "luma-windows-manual-workspace-v1".into(),
        runtime_manifest_sha256: runtime.into(),
        default_uid: 65534,
        wsl_flags: 0,
        account_uid: 1000,
        account_gid: 1000,
        account_generation: 1,
        password_max_age_days: 90,
        bootstrap_purpose_seconds: PURPOSE_SECONDS,
        bootstrap_cpu_seconds: CPU_SECONDS,
        drain_seconds: DRAIN_SECONDS,
        memory_max_bytes: 268435456,
        memory_swap_max_bytes: 0,
        tasks_max: 8,
        cpu_quota_usec: 100000,
        cpu_period_usec: 100000,
        account_baselines: [
            ("passwd", PASSWD),
            ("group", GROUP),
            ("shadow", SHADOW),
            ("gshadow", GSHADOW),
        ]
        .into_iter()
        .map(|(name, bytes)| (name.into(), luma_content::sha256(bytes)))
        .collect(),
        pam_sha256: luma_content::sha256(PAM),
        nss_sha256: luma_content::sha256(NSS),
    })
}

fn validate_profile(bytes: &[u8], request: &Request) -> Result<Profile> {
    if bytes.is_empty()
        || bytes.len() > 32768
        || luma_content::sha256(bytes) != request.profile_sha256
    {
        return Err("workspace profile differs from its publisher-bound request".into());
    }
    let value: Profile = serde_json::from_slice(bytes)?;
    if canonical(&value)? != bytes
        || canonical(&value)? != canonical(&profile(&request.runtime_manifest_sha256)?)?
    {
        return Err("workspace profile changes the fixed reviewed account/resource policy".into());
    }
    Ok(value)
}

pub(crate) fn contract() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin().take(32769).read_to_end(&mut bytes)?;
    let request = parse(&bytes)?;
    // Profile hash is intentionally not verified by a data-only contract: no
    // publisher input or installed filesystem is consulted by this command.
    let profile_bytes = canonical(&profile(&request.runtime_manifest_sha256)?)?;
    validate_profile(&profile_bytes, &request)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"profile":PROFILE,
        "request_sha256":luma_content::sha256(&bytes),"login":request.login,
        "uid":1000,"gid":1000,"account_generation":1,"purpose_seconds":PURPOSE_SECONDS,
        "cpu_seconds":CPU_SECONDS,"drain_seconds":DRAIN_SECONDS,"password_max_age_days":90,
        "account_created":false,"pam_authenticated":false,"health_qualified":false,
        "authority_returned":false,"production_qualified":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            profile: PROFILE.into(),
            nonce: "11".repeat(32),
            installation: "22".repeat(32),
            release_sha256: "33".repeat(32),
            runtime_manifest_sha256: "44".repeat(32),
            profile_sha256: "55".repeat(32),
            actor_sid_sha256: "66".repeat(32),
            login: "alice".into(),
            uid: 1000,
            gid: 1000,
            account_generation: 1,
            protected_utc_day: 20746,
            utc_proof_sha256: "77".repeat(32),
        }
    }
    #[test]
    fn exact_request_binds_first_account_not_windows_sid_as_pam() {
        let bytes = canonical(&request()).unwrap();
        parse(&bytes).unwrap();
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains("password"));
        for (key, bad) in [
            ("uid", serde_json::json!(0)),
            ("gid", serde_json::json!(1001)),
            ("account_generation", serde_json::json!(2)),
            ("protected_utc_day", serde_json::json!(0)),
            ("protected_utc_day", serde_json::json!(true)),
            ("login", serde_json::json!("root")),
            ("login", serde_json::json!("nobody")),
            ("actor_sid_sha256", serde_json::json!("00".repeat(32))),
            ("password", serde_json::json!("not allowed")),
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value[key] = bad;
            assert!(parse(&canonical(&value).unwrap()).is_err(), "{key}");
        }
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        let duplicate = String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"uid\":1000,", 1);
        assert!(parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn no_existing_name_uid_reuse_or_noncanonical_login() {
        for value in [
            "root",
            "nobody",
            "nogroup",
            "",
            "Alice",
            "../alice",
            "alice:name",
            "alice\n",
            "a b",
        ] {
            assert!(!login(value), "{value}");
        }
        assert!(login("a"));
        assert!(login("alice-01_x"));
        assert!(!login(&"a".repeat(32)));
    }
    #[test]
    fn profile_keeps_original_canary_and_exact_pam_nss_baselines() {
        let mut request = request();
        let profile = profile(&request.runtime_manifest_sha256).unwrap();
        let bytes = canonical(&profile).unwrap();
        request.profile_sha256 = luma_content::sha256(&bytes);
        validate_profile(&bytes, &request).unwrap();
        assert_eq!(profile.bootstrap_cpu_seconds + profile.drain_seconds, 30);
        assert_eq!(profile.default_uid, 65534);
        assert_eq!(profile.wsl_flags, 0);
        assert_eq!(profile.account_baselines.len(), 4);
        assert!(!PAM.windows(7).any(|part| part == b"include"));
        for (key, replacement) in [
            ("bootstrap_purpose_seconds", serde_json::json!(300)),
            ("default_uid", serde_json::json!(1000)),
            ("password_max_age_days", serde_json::json!(99999)),
            ("wsl_flags", serde_json::json!(1)),
            ("pam_sha256", serde_json::json!("11".repeat(32))),
            ("unknown", serde_json::json!(false)),
        ] {
            let mut value = serde_json::to_value(&profile).unwrap();
            value[key] = replacement;
            let bytes = canonical(&value).unwrap();
            request.profile_sha256 = luma_content::sha256(&bytes);
            assert!(validate_profile(&bytes, &request).is_err(), "{key}");
        }
    }
}
