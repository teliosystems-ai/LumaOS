//! Bounded, deterministic editable-content contracts shared by native and Windows clients.
//!
//! This library performs no IO and establishes no caller identity, grant, durable commit,
//! signature or clock authority. Callers must authorize the owner and hold a storage
//! transaction while comparing and publishing versions. A proposed version is not a commit.
//! Only UTF-8 text, JSON and CSV are supported, not office document formats.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub mod animation;
mod canonical;
pub mod diagram;
pub mod document;
pub mod rendered;
pub mod spreadsheet;
pub mod table;

pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = MAX_CONTENT_BYTES * 6 + 8192;
pub const MAX_CSV_ROWS: usize = 10_001;
pub const MAX_CSV_COLUMNS: usize = 32;
pub const MAX_CSV_FIELD_BYTES: usize = 4096;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_NODES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    InvalidUtf8,
    InvalidText,
    InvalidJson,
    InvalidCsv,
    InvalidEdit,
    InvalidBinding,
    InvalidIdentifier,
    InvalidProvenance,
    OwnerMismatch,
    InvalidReceipt,
    HashMismatch,
    NonCanonical,
    InvalidEnvelope,
    VersionOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bounds => "content or structural bound exceeded",
            Self::InvalidUtf8 => "content is not UTF-8",
            Self::InvalidText => "unsupported text control, BOM or line ending",
            Self::InvalidJson => "invalid, duplicate-key or unsupported JSON",
            Self::InvalidCsv => "invalid, ragged or unsupported CSV",
            Self::InvalidEdit => "invalid table edit, position, shape or format",
            Self::InvalidBinding => "invalid installation, owner or generation binding",
            Self::InvalidIdentifier => "invalid stable artifact identifier",
            Self::InvalidProvenance => "invalid provenance or original byte digest",
            Self::OwnerMismatch => "installation, owner or generation mismatch",
            Self::InvalidReceipt => "invalid version receipt",
            Self::HashMismatch => "content or receipt digest mismatch",
            Self::NonCanonical => "serialized content is not canonical",
            Self::InvalidEnvelope => "invalid serialized artifact envelope",
            Self::VersionOverflow => "artifact version exhausted",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Utf8Text,
    Json,
    Csv,
}

impl Format {
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Utf8Text => "text/plain; charset=utf-8",
            Self::Json => "application/json",
            Self::Csv => "text/csv; charset=utf-8",
        }
    }
}

/// An already-authorized binding, not proof of authorization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerBinding {
    pub installation: String,
    pub owner: String,
    pub owner_generation: u64,
}

impl OwnerBinding {
    pub fn validate(&self) -> Result<()> {
        if !nonzero_digest(&self.installation)
            || !nonzero_digest(&self.owner)
            || self.owner_generation == 0
        {
            return Err(Error::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EditOrigin {
    Managed,
    External,
}

/// All fields describe supplied provenance. No field is a signature or authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub request_id: String,
    pub workflow_sha256: String,
    /// SHA-256 of the exact original input, before format canonicalization.
    pub source_sha256: String,
    pub origin: EditOrigin,
}

impl Provenance {
    fn validate(&self) -> Result<()> {
        if !identifier(&self.request_id)
            || !nonzero_digest(&self.workflow_sha256)
            || !nonzero_digest(&self.source_sha256)
        {
            return Err(Error::InvalidProvenance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionReference {
    pub artifact_id: String,
    pub version: u64,
    pub content_sha256: String,
    pub receipt_sha256: String,
}

impl VersionReference {
    fn validate(&self) -> Result<()> {
        if !identifier(&self.artifact_id)
            || self.version == 0
            || !nonzero_digest(&self.content_sha256)
            || !nonzero_digest(&self.receipt_sha256)
        {
            return Err(Error::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub artifact_id: String,
    pub version: u64,
    pub previous: Option<VersionReference>,
    pub format: Format,
    pub media_type: String,
    pub content_sha256: String,
    pub content_bytes: u64,
    pub original_bytes: u64,
    pub provenance: Provenance,
}

impl Receipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::InvalidReceipt)
    }

    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.provenance.validate()?;
        if self.schema_version != 1
            || !identifier(&self.artifact_id)
            || self.version == 0
            || !nonzero_digest(&self.content_sha256)
            || (self.content_bytes == 0 && self.format != Format::Utf8Text)
            || self.content_bytes > MAX_CONTENT_BYTES as u64
            || (self.original_bytes == 0 && self.format != Format::Utf8Text)
            || (self.format == Format::Utf8Text
                && (self.original_bytes == 0) != (self.content_bytes == 0))
            || self.original_bytes > MAX_CONTENT_BYTES as u64
            || self.media_type != self.format.media_type()
        {
            return Err(Error::InvalidReceipt);
        }
        match &self.previous {
            None if self.version == 1 => {}
            Some(previous) => {
                previous.validate()?;
                if previous.artifact_id != self.artifact_id
                    || previous.version.checked_add(1) != Some(self.version)
                {
                    return Err(Error::InvalidReceipt);
                }
            }
            _ => return Err(Error::InvalidReceipt),
        }
        Ok(())
    }
}

/// Private fields prevent callers from mutating captured content in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactVersion {
    receipt: Receipt,
    content: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    receipt: Receipt,
    receipt_sha256: String,
    content: String,
}

impl ArtifactVersion {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_bytes()
    }

    pub fn reference(&self) -> Result<VersionReference> {
        Ok(VersionReference {
            artifact_id: self.receipt.artifact_id.clone(),
            version: self.receipt.version,
            content_sha256: self.receipt.content_sha256.clone(),
            receipt_sha256: sha256(&self.receipt.canonical_bytes()?),
        })
    }

    /// Canonical untrusted transport, not a signature or a durable publication.
    pub fn canonical_envelope(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let envelope = Envelope {
            receipt: self.receipt.clone(),
            receipt_sha256: self.reference()?.receipt_sha256,
            content: self.content.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| Error::InvalidEnvelope)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        self.receipt.validate()?;
        if self.content.len() as u64 != self.receipt.content_bytes
            || sha256(self.content.as_bytes()) != self.receipt.content_sha256
        {
            return Err(Error::HashMismatch);
        }
        if canonical::content(self.receipt.format, self.content.as_bytes())? != self.content {
            return Err(Error::NonCanonical);
        }
        Ok(())
    }
}

/// The original exact source is identified by provenance; canonical bytes are separately hashed.
pub fn capture(
    binding: OwnerBinding,
    artifact_id: &str,
    format: Format,
    source: &[u8],
    provenance: Provenance,
) -> Result<ArtifactVersion> {
    binding.validate()?;
    if !identifier(artifact_id) {
        return Err(Error::InvalidIdentifier);
    }
    let captured = capture_content(&binding, artifact_id, format, source, provenance)?;
    make_version(binding, artifact_id, 1, None, captured)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapturedContent {
    pub binding: OwnerBinding,
    pub artifact_id: String,
    pub format: Format,
    pub content: String,
    pub content_sha256: String,
    pub original_bytes: u64,
    pub provenance: Provenance,
}

impl CapturedContent {
    /// Canonical representation of a preserved, uncommitted edit candidate.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.binding.validate()?;
        if !identifier(&self.artifact_id) {
            return Err(Error::InvalidIdentifier);
        }
        self.provenance.validate()?;
        if (self.original_bytes == 0 && self.format != Format::Utf8Text)
            || (self.format == Format::Utf8Text
                && (self.original_bytes == 0) != self.content.is_empty())
            || self.original_bytes > MAX_CONTENT_BYTES as u64
        {
            return Err(Error::InvalidProvenance);
        }
        if sha256(self.content.as_bytes()) != self.content_sha256 {
            return Err(Error::HashMismatch);
        }
        if canonical::content(self.format, self.content.as_bytes())? != self.content {
            return Err(Error::NonCanonical);
        }
        serde_json::to_vec(self).map_err(|_| Error::InvalidEnvelope)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditDecision {
    NoChange {
        current: VersionReference,
        observed_source_sha256: String,
    },
    /// Must still be published using a storage transaction comparing `previous`.
    NewVersion(ArtifactVersion),
    /// Candidate is retained by the caller, never merged or assigned a committed version.
    Conflict {
        expected: VersionReference,
        current: VersionReference,
        candidate: CapturedContent,
    },
}

/// Compare an external editor save against its exact exported base reference.
///
/// A stale base always conflicts, even if its content happens to equal current bytes.
/// Different artifact IDs are invalid, not candidates for implicit retargeting.
pub fn compare_external_edit(
    current: &ArtifactVersion,
    expected: &VersionReference,
    authorized_binding: &OwnerBinding,
    source: &[u8],
    provenance: Provenance,
) -> Result<EditDecision> {
    current.validate()?;
    authorized_binding.validate()?;
    if &current.receipt.binding != authorized_binding {
        return Err(Error::OwnerMismatch);
    }
    expected.validate()?;
    if expected.artifact_id != current.receipt.artifact_id {
        return Err(Error::InvalidIdentifier);
    }
    if provenance.origin != EditOrigin::External {
        return Err(Error::InvalidProvenance);
    }
    let candidate = capture_content(
        authorized_binding,
        &current.receipt.artifact_id,
        current.receipt.format,
        source,
        provenance,
    )?;
    let reference = current.reference()?;
    if expected != &reference {
        return Ok(EditDecision::Conflict {
            expected: expected.clone(),
            current: reference,
            candidate,
        });
    }
    if candidate.content == current.content {
        return Ok(EditDecision::NoChange {
            current: reference,
            observed_source_sha256: candidate.provenance.source_sha256,
        });
    }
    let version = current
        .receipt
        .version
        .checked_add(1)
        .ok_or(Error::VersionOverflow)?;
    Ok(EditDecision::NewVersion(make_version(
        current.receipt.binding.clone(),
        &current.receipt.artifact_id,
        version,
        Some(reference),
        candidate,
    )?))
}

/// Strict reopen checks canonical transport, exact ownership, metadata and immutable bytes.
/// It cannot authenticate provenance/history without caller-supplied trusted catalog state.
pub fn reopen(bytes: &[u8], authorized_binding: &OwnerBinding) -> Result<ArtifactVersion> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Bounds);
    }
    authorized_binding.validate()?;
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEnvelope)?;
    if &envelope.receipt.binding != authorized_binding {
        return Err(Error::OwnerMismatch);
    }
    let version = ArtifactVersion {
        receipt: envelope.receipt,
        content: envelope.content,
    };
    version.validate()?;
    if envelope.receipt_sha256 != version.reference()?.receipt_sha256 {
        return Err(Error::HashMismatch);
    }
    if version.canonical_envelope()? != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(version)
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capture_content(
    binding: &OwnerBinding,
    artifact_id: &str,
    format: Format,
    source: &[u8],
    provenance: Provenance,
) -> Result<CapturedContent> {
    if (source.is_empty() && format != Format::Utf8Text) || source.len() > MAX_CONTENT_BYTES {
        return Err(Error::Bounds);
    }
    provenance.validate()?;
    if provenance.source_sha256 != sha256(source) {
        return Err(Error::InvalidProvenance);
    }
    let content = canonical::content(format, source)?;
    Ok(CapturedContent {
        binding: binding.clone(),
        artifact_id: artifact_id.into(),
        format,
        content_sha256: sha256(content.as_bytes()),
        content,
        original_bytes: source.len() as u64,
        provenance,
    })
}

fn make_version(
    binding: OwnerBinding,
    artifact_id: &str,
    version: u64,
    previous: Option<VersionReference>,
    captured: CapturedContent,
) -> Result<ArtifactVersion> {
    if captured.binding != binding || captured.artifact_id != artifact_id {
        return Err(Error::OwnerMismatch);
    }
    let result = ArtifactVersion {
        receipt: Receipt {
            schema_version: 1,
            binding,
            artifact_id: artifact_id.into(),
            version,
            previous,
            format: captured.format,
            media_type: captured.format.media_type().into(),
            content_sha256: captured.content_sha256,
            content_bytes: captured.content.len() as u64,
            original_bytes: captured.original_bytes,
            provenance: captured.provenance,
        },
        content: captured.content,
    };
    result.validate()?;
    Ok(result)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && value != "."
        && value != ".."
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn nonzero_digest(value: &str) -> bool {
    digest_valid(value) && value.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
mod tests;
