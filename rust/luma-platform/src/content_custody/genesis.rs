//! Original commissioning DATA whose exact SHA is the protected initial event.
//! Matching a mutable header to another mutable header is not this proof.
use super::*;
const NAME: &str = "genesis.json";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: String,
    inode: String,
    uid: u32,
    #[serde(rename = "gid")]
    _gid: u32,
    mode: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema_version: u32,
    kind: String,
    installation: String,
    namespace: String,
    identity: Identity,
    domains: Vec<serde_json::Value>,
}
pub(super) fn validate(bytes: &[u8], installation: &str, genesis: [u8; 32]) -> Result<()> {
    digest(installation)?;
    if bytes.is_empty() || bytes.len() > 4096 || genesis == [0; 32] {
        return Err("original content genesis statement exceeds fixed bounds".into());
    }
    // Struct parsing rejects duplicate/unknown fields. Value re-encoding then
    // enforces the exact sorted canonical descriptor used at commissioning.
    let statement: Statement = serde_json::from_slice(bytes)?;
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let protected: [u8; 32] = Sha256::digest(bytes).into();
    if serde_json::to_vec(&value)? != bytes
        || statement.schema_version != 1
        || statement.kind != "luma-content-explicit-empty-genesis-v1"
        || statement.namespace != "/var/lib/luma-os/content-store"
        || statement.installation != installation
        || !statement.domains.is_empty()
        || statement.identity.uid != 0
        || statement.identity.mode != (libc::S_IFDIR | 0o700)
        || protected != genesis
    {
        return Err(
            "original content genesis does not bind exact protected namespace and installation"
                .into(),
        );
    }
    for number in [&statement.identity.device, &statement.identity.inode] {
        let parsed: u64 = number.parse()?;
        if parsed == 0 || parsed.to_string() != *number {
            return Err("original genesis identity is not canonical".into());
        }
    }
    // GID is descriptive: mode0700 grants it no access. Its exact original
    // value remains included in the protected statement, not normalized.
    Ok(())
}
pub(crate) fn validate_genesis_at(
    root: &std::path::Path,
    installation: &str,
    genesis: [u8; 32],
) -> Result<()> {
    let bytes = super::super::immutable(&root.join(NAME), 4096)?;
    validate(&bytes, installation, genesis)
}
pub(crate) fn retain_genesis_statement(
    installation: &str,
    genesis: [u8; 32],
    statement: &serde_json::Value,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let bytes = serde_json::to_vec(statement)?;
    validate(&bytes, installation, genesis)?;
    let files = Files::installed();
    match fs::symlink_metadata(files.root.join(NAME)) {
        Ok(_) => {
            if files.read(NAME, check)? != bytes {
                return Err("different retained genesis proof must be preserved".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            files.create(NAME, &bytes, check)?
        }
        Err(error) => return Err(error.into()),
    }
    if files.read(NAME, check)? != bytes {
        return Err("retained genesis proof changed during explicit publication".into());
    }
    check()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn statement() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":"luma-content-explicit-empty-genesis-v1",
            "installation":"11".repeat(32),"namespace":"/var/lib/luma-os/content-store",
            "identity":{"device":"2049","inode":"32","uid":0,"gid":27,"mode":libc::S_IFDIR|0o700},"domains":[]})
    }
    #[test]
    fn original_genesis_hash_rejects_coordinated_mutable_header_installation_substitution() {
        let original = statement();
        let bytes = serde_json::to_vec(&original).unwrap();
        let protected: [u8; 32] = Sha256::digest(&bytes).into();
        validate(&bytes, &"11".repeat(32), protected).unwrap();
        let mut changed = original.clone();
        changed["installation"] = "12".repeat(32).into();
        assert!(validate(
            &serde_json::to_vec(&changed).unwrap(),
            &"12".repeat(32),
            protected
        )
        .is_err());
        assert!(validate(&bytes, &"12".repeat(32), protected).is_err());
        for (field, replacement) in [
            ("namespace", serde_json::json!("/tmp/adopt")),
            ("domains", serde_json::json!(["adopt-old-data"])),
            ("kind", serde_json::json!("generic")),
        ] {
            let mut changed = original.clone();
            changed[field] = replacement;
            let bytes = serde_json::to_vec(&changed).unwrap();
            let own: [u8; 32] = Sha256::digest(&bytes).into();
            assert!(validate(&bytes, &"11".repeat(32), own).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(b'\n');
        assert!(validate(&changed, &"11".repeat(32), protected).is_err());
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"domains\":[]",
            "\"domains\":[],\"domains\":[]",
            1,
        );
        assert!(validate(duplicate.as_bytes(), &"11".repeat(32), protected).is_err());
    }
}
