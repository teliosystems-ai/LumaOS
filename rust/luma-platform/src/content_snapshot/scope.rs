//! Exact segmented-snapshot request and finite-pair DATA. These checks do not
//! authenticate a session, acquire resources, select C or authorize export.
use crate::{
    artifacts, authentication::SessionPurpose, backup_crypto, finite_grants as grants, Result,
};
use luma_content_store::v2::backup::{
    SnapshotBudget, SnapshotIntent, SnapshotMode, SnapshotReview,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "snapshot-v1-";
pub(crate) const MAX_REQUEST: usize = 65536;
pub(super) fn nonzero_hash(value: &str) -> bool {
    artifacts::hash(value) && value.bytes().any(|b| b != b'0')
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) schema_version: u32,
    pub(crate) login: String,
    pub(crate) intent: SnapshotIntent,
    pub(crate) mode: SnapshotMode,
    pub(crate) budget: SnapshotBudget,
    pub(crate) review: Option<SnapshotReview>,
    pub(crate) recipients: backup_crypto::RecipientPins,
    pub(crate) owner_certificate_der_hex: String,
    pub(crate) offline_admin_certificate_der_hex: String,
}
fn certificate(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 16384
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("snapshot certificate must be bounded canonical DER hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
impl Input {
    pub(crate) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.budget.validate(self.mode)?;
        self.recipients.validate()?;
        if self.schema_version != 1
            || self.login.is_empty()
            || self.login.len() > 32
            || !self.login.as_bytes()[0].is_ascii_lowercase()
            || !self
                .login
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            || self.intent.recipients_sha256
                != artifacts::digest(&serde_json::to_vec(&self.recipients)?)
        {
            return Err("snapshot input loses exact owner or recipient binding".into());
        }
        match (self.mode, &self.review) {
            (SnapshotMode::Review, None) => (),
            (SnapshotMode::Export, Some(review)) => {
                review.validate(&self.intent)?;
                let reads = review
                    .object_count
                    .checked_mul(512)
                    .and_then(|n| n.checked_add(review.object_bytes))
                    .and_then(|n| n.checked_add(128 * 1024 * 1024))
                    .ok_or("snapshot reviewed read accounting overflow")?;
                if review.object_count > self.budget.maximum_objects
                    || reads > self.budget.read_bytes
                {
                    return Err("snapshot review exceeds the original finite source budget".into());
                }
            }
            _ => {
                return Err("snapshot mode requires its exact reviewed or unreviewed input".into())
            }
        }
        self.recipient_data()?;
        Ok(())
    }
    pub(crate) fn recipient_data(&self) -> Result<backup_crypto::Recipients> {
        backup_crypto::Recipients::new(
            &certificate(&self.owner_certificate_der_hex)?,
            &certificate(&self.offline_admin_certificate_der_hex)?,
            self.recipients.clone(),
        )
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_REQUEST {
            return Err("snapshot input exceeds fixed transport".into());
        }
        Ok(bytes)
    }
    pub(crate) fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST {
            return Err("invalid bounded snapshot input".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if value.canonical_bytes()? != bytes {
            return Err("snapshot input must use exact canonical transport".into());
        }
        Ok(value)
    }
    pub(crate) fn profile(&self) -> Result<String> {
        let bytes = self.canonical_bytes()?;
        let mode = match self.mode {
            SnapshotMode::Review => "review",
            SnapshotMode::Export => "export",
        };
        let output = match self.mode {
            SnapshotMode::Review => grants::SNAPSHOT_MAX_REVIEW_BYTES,
            SnapshotMode::Export => self.budget.output_bytes,
        };
        let profile = format!(
            "{PREFIX}{mode}-{}-{}-{output}-{}",
            self.intent.head.binding.owner_generation,
            self.budget.read_bytes,
            artifacts::digest(&bytes)
        );
        parse_profile(&profile)?;
        Ok(profile)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile<'a> {
    pub(crate) mode: SnapshotMode,
    pub(crate) generation: u64,
    pub(crate) read_bytes: u64,
    pub(crate) output_bytes: u64,
    pub(crate) source_sha256: &'a str,
}
pub(crate) fn parse_profile(id: &str) -> Result<Profile<'_>> {
    let mut fields = id
        .strip_prefix(PREFIX)
        .ok_or("unknown snapshot profile")?
        .split('-');
    let mode = match fields.next() {
        Some("review") => SnapshotMode::Review,
        Some("export") => SnapshotMode::Export,
        _ => return Err("unknown snapshot operation".into()),
    };
    let mut number = || -> Result<u64> {
        let text = fields.next().ok_or("missing finite snapshot quantity")?;
        let value: u64 = text.parse()?;
        if value == 0 || value.to_string() != text {
            return Err("noncanonical snapshot quantity".into());
        }
        Ok(value)
    };
    let generation = number()?;
    let read_bytes = number()?;
    let output_bytes = number()?;
    let source_sha256 = fields.next().ok_or("missing snapshot source commitment")?;
    if fields.next().is_some()
        || !nonzero_hash(source_sha256)
        || read_bytes < 128 * 1024 * 1024
        || read_bytes > grants::SNAPSHOT_MAX_READ_BYTES
        || (mode == SnapshotMode::Review && output_bytes != grants::SNAPSHOT_MAX_REVIEW_BYTES)
        || (mode == SnapshotMode::Export
            && (output_bytes <= luma_content_store::v2::backup::MAX_SNAPSHOT_PACKAGE_OVERHEAD
                || output_bytes > luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES))
    {
        return Err("snapshot profile exceeds its exact closed bounds".into());
    }
    Ok(Profile {
        mode,
        generation,
        read_bytes,
        output_bytes,
        source_sha256,
    })
}
pub(crate) fn uses(profile: &str, device: &str, installation: &str) -> Result<[grants::Use; 2]> {
    let parsed = parse_profile(profile)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("snapshot storage identity absent")?;
    if !nonzero_hash(installation)
        || major == "0"
        || [major, minor]
            .iter()
            .any(|s| s.parse::<u32>().map_or(true, |v| v.to_string() != *s))
    {
        return Err("snapshot requires exact installed block storage and installation".into());
    }
    let digest = artifacts::digest(&serde_json::to_vec(&(
        "luma-segmented-snapshot-finite-pair-v1",
        installation,
        device,
        profile,
    ))?);
    let read = grants::Use {
        action: grants::Action::Read,
        selector: grants::Selector {
            kind: grants::Kind::File,
            id: grants::SNAPSHOT_READ_ID.into(),
            generation: parsed.generation,
            digest,
        },
        input_bytes: parsed.read_bytes,
        output_bytes: grants::SNAPSHOT_MAX_REVIEW_BYTES,
        units: 1,
    };
    let export = grants::Use {
        action: grants::Action::Export,
        selector: grants::Selector {
            kind: grants::Kind::Artifact,
            id: grants::SNAPSHOT_EXPORT_ID.into(),
            ..read.selector.clone()
        },
        input_bytes: parsed.read_bytes,
        output_bytes: parsed.output_bytes,
        units: 1,
    };
    read.validate()?;
    export.validate()?;
    Ok([read, export])
}
/// Structural comparison only: the caller must independently authenticate the
/// original Export session and continuously validate both grants and its lease.
pub(crate) fn export_pair(
    profile: &str,
    device: &str,
    installation: &str,
    actual: &[(String, grants::Use)],
    requested: &grants::Use,
    purpose: SessionPurpose,
) -> Result<usize> {
    if purpose != SessionPurpose::Export
        || actual.len() != 2
        || actual[0].0 == actual[1].0
        || actual
            .iter()
            .any(|(id, _)| !crate::admin_roles::identifier(id))
    {
        return Err("snapshot requires distinct original Export-purpose finite grants".into());
    }
    let [read, export] = uses(profile, device, installation)?;
    let reader = actual
        .iter()
        .position(|(_, usage)| usage == &read)
        .ok_or("exact snapshot read grant absent")?;
    let exporter = 1 - reader;
    if actual[exporter].1 != export || requested != &export {
        return Err("snapshot acquisition substitutes a finite pair or target".into());
    }
    Ok(exporter)
}

#[cfg(test)]
#[path = "scope/tests.rs"]
pub(super) mod tests;
