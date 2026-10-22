//! Exact finite scope DATA. Reconstruction does not authenticate its subject,
//! make an old grant current, or imply permission to read private source bytes.
use super::*;
use crate::finite_grants as grants;
#[path = "scope/admission.rs"]
mod admission;
pub(crate) use admission::pair;

const SOURCE_READ: u64 = 128 * 1024 * 1024;
const PHASE_READ: u64 = 256 * 1024 * 1024;
const PHASE_WRITE: u64 = 128 * 1024 * 1024;

fn device(value: &str) -> Result<()> {
    let (major, minor) = value
        .split_once(':')
        .ok_or("missing exact index block device")?;
    if major == "0"
        || [major, minor]
            .iter()
            .any(|v| v.parse::<u32>().map_or(true, |n| n.to_string() != *v))
    {
        return Err("native index requires canonical installed block-backed storage".into());
    }
    Ok(())
}
fn digest(profile: &str, installation: &str, storage: &str) -> Result<String> {
    request::parse_profile(profile)?;
    hash(installation)?;
    device(storage)?;
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-native-index-acquisition-v2",
        installation,
        profile,
        storage,
    ))?))
}
pub(crate) fn binding(profile: &str, storage: &str) -> Result<String> {
    digest(profile, &crate::artifacts::installation()?, storage)
}

fn usage_at(profile: &str, digest: String, read: bool) -> Result<grants::Use> {
    let selected = request::parse_profile(profile)?;
    let read = read || !selected.mode.mutates();
    let (action, kind, id, input_bytes, output_bytes) = if read {
        (
            grants::Action::Read,
            grants::Kind::File,
            match selected.mode {
                request::Mode::Status => "native-content-index-inspect-v2",
                request::Mode::Query => "native-content-index-query-v2",
                _ => "native-content-index-source-v2",
            },
            if selected.mode == request::Mode::Status {
                4 * 1024 * 1024
            } else {
                SOURCE_READ
            },
            MAX_OUTPUT,
        )
    } else if selected.mode == request::Mode::Retain {
        (
            grants::Action::Retain,
            grants::Kind::Artifact,
            "native-content-index-retain-v2",
            PHASE_READ,
            MAX_OUTPUT,
        )
    } else {
        (
            grants::Action::Write,
            grants::Kind::Artifact,
            "native-content-index-build-v2",
            PHASE_READ,
            PHASE_WRITE,
        )
    };
    let value = grants::Use {
        action,
        selector: grants::Selector {
            kind,
            id: id.into(),
            generation: selected.generation,
            digest,
        },
        input_bytes,
        output_bytes,
        units: 1,
    };
    value.validate()?;
    Ok(value)
}
pub(crate) fn acquisition_usage(profile: &str) -> Result<grants::Use> {
    usage_at(
        profile,
        binding(
            profile,
            &crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        )?,
        false,
    )
}
#[allow(dead_code)]
pub(crate) fn paired_read_usage(profile: &str) -> Result<grants::Use> {
    usage_at(
        profile,
        binding(
            profile,
            &crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        )?,
        true,
    )
}
pub(crate) fn original_usage(
    profile: &str,
    storage: &str,
    owner: &OwnerBinding,
    source_sha256: &str,
    read: bool,
) -> Result<grants::Use> {
    owner.validate()?;
    let selected = request::parse_profile(profile)?;
    if selected.generation != owner.owner_generation || selected.source != source_sha256 {
        return Err("index original scope differs from exact request/owner generation".into());
    }
    usage_at(
        profile,
        digest(profile, &owner.installation, storage)?,
        read,
    )
}
pub(crate) fn verify_input(profile: &str, bytes: &[u8]) -> Result<request::Input> {
    let input = request::Input::parse(bytes)?;
    let selected = request::parse_profile(profile)?;
    if selected.source != input.sha256()?
        || selected.generation != input.binding.owner_generation
        || !(selected.mode == input.mode()
            || (selected.mode == request::Mode::Review && input.mode().mutates()))
    {
        // Avoid interpreting any label, caller flag or a profile with a valid
        // digest for different bytes as the actual typed request.
        return Err("native index bytes differ from exact canonical profile".into());
    }
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(mode: &str) -> String {
        format!("{PREFIX}{mode}-7-{}-{}", "a".repeat(64), "a".repeat(64))
    }
    fn owner() -> OwnerBinding {
        OwnerBinding {
            installation: "b".repeat(64),
            owner: "c".repeat(64),
            owner_generation: 7,
        }
    }
    #[test]
    fn source_read_never_implied_by_build_or_retention() {
        for mode in ["start", "step", "advance", "publish", "retain"] {
            let p = profile(mode);
            let read = original_usage(&p, "253:1", &owner(), &"a".repeat(64), true).unwrap();
            let effect = original_usage(&p, "253:1", &owner(), &"a".repeat(64), false).unwrap();
            assert_eq!(read.action, grants::Action::Read);
            assert_eq!(read.selector.kind, grants::Kind::File);
            assert_ne!(read.selector.id, effect.selector.id);
            assert_eq!(
                effect.action,
                if mode == "retain" {
                    grants::Action::Retain
                } else {
                    grants::Action::Write
                }
            );
            assert_eq!(read.selector.digest, effect.selector.digest);
        }
    }
    #[test]
    fn exact_storage_generation_and_source_join_without_authority() {
        let p = profile("query");
        let base = original_usage(&p, "253:1", &owner(), &"a".repeat(64), false).unwrap();
        assert_eq!(base.action, grants::Action::Read);
        assert_eq!(base.selector.id, "native-content-index-query-v2");
        let changed = original_usage(&p, "253:2", &owner(), &"a".repeat(64), false).unwrap();
        assert_ne!(base.selector.digest, changed.selector.digest);
        for storage in ["0:1", "0253:1", "253:01", "253:1:2", "253:-1"] {
            assert!(original_usage(&p, storage, &owner(), &"a".repeat(64), false).is_err());
        }
        let mut stale = owner();
        stale.owner_generation += 1;
        assert!(original_usage(&p, "253:1", &stale, &"a".repeat(64), false).is_err());
        assert!(original_usage(&p, "253:1", &owner(), &"d".repeat(64), false).is_err());
    }
}
