//! Portable `.luma-sheet.json` workbooks for the declared Luma spreadsheet
//! engine. This is not XLSX/ODS or LibreOffice/Excel compatibility.
//!
//! Reopen recalculates real typed formulas and verifies the cached preview.
//! Origin envelopes and their hashes are descriptive immutable DATA, never
//! current ownership, a signature, a file grant or authority to publish edits.
use crate::{
    spreadsheet, ArtifactVersion, Envelope, Error, Format, OwnerBinding, Result, VersionReference,
};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "luma-editable-spreadsheet-workbook-v1";
pub const EXTENSION: &str = ".luma-sheet.json";
/// The existing native binary export transport already has a 16-MiB ceiling.
/// No content, engine, row, column or expression limit is increased here.
pub const MAX_WORKBOOK_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedSource {
    schema_version: u32,
    engine: String,
    source: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workbook {
    schema_version: u32,
    profile: String,
    origin: Envelope,
    origin_envelope_sha256: String,
    canonical_source: String,
    source_sha256: String,
    values: Vec<Vec<spreadsheet::Value>>,
    canonical_csv: String,
    csv_sha256: String,
    evaluation_steps: usize,
    source_changed: bool,
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::InvalidEnvelope)
}
fn calculate(bytes: &[u8]) -> Result<spreadsheet::Calculation> {
    spreadsheet::calculate(bytes).map_err(|_| Error::InvalidEdit)
}
fn managed(version: &ArtifactVersion) -> Result<spreadsheet::Calculation> {
    if version.receipt().format != Format::Json {
        return Err(Error::InvalidEnvelope);
    }
    let source: ManagedSource =
        serde_json::from_slice(version.content()).map_err(|_| Error::InvalidEnvelope)?;
    if source.schema_version != 1 || source.engine != "spreadsheet" {
        return Err(Error::InvalidEnvelope);
    }
    // Reconstruct the closed wrapper as well as every nested source cell. An
    // internally tagged unit cell cannot silently discard caller properties.
    if crate::canonical::content(Format::Json, &encode(&source)?)?.as_bytes() != version.content() {
        return Err(Error::NonCanonical);
    }
    calculate(&encode(&source.source)?)
}
fn envelope(version: &ArtifactVersion) -> Result<Envelope> {
    serde_json::from_slice(&version.canonical_envelope()?).map_err(|_| Error::InvalidEnvelope)
}

impl Workbook {
    /// Export DATA from an actual reopened version. The caller must separately
    /// authorize the exact current source and every byte of file delivery.
    pub fn from_artifact(version: &ArtifactVersion) -> Result<Self> {
        let original = managed(version)?;
        Self::with_source(version, &original, original.canonical_source.as_bytes())
    }
    fn with_source(
        version: &ArtifactVersion,
        original: &spreadsheet::Calculation,
        bytes: &[u8],
    ) -> Result<Self> {
        let current = calculate(bytes)?;
        let origin_bytes = version.canonical_envelope()?;
        let value = Self {
            schema_version: 1,
            profile: PROFILE.into(),
            origin: envelope(version)?,
            origin_envelope_sha256: crate::sha256(&origin_bytes),
            source_changed: current.canonical_source != original.canonical_source,
            canonical_source: current.canonical_source,
            source_sha256: current.source_sha256,
            values: current.values,
            canonical_csv: current.canonical_csv,
            csv_sha256: current.csv_sha256,
            evaluation_steps: current.evaluation_steps,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(ArtifactVersion, spreadsheet::Calculation)> {
        if self.schema_version != 1 || self.profile != PROFILE {
            return Err(Error::InvalidEnvelope);
        }
        let origin_bytes = encode(&self.origin)?;
        if origin_bytes.len() > crate::MAX_ENVELOPE_BYTES
            || crate::sha256(&origin_bytes) != self.origin_envelope_sha256
        {
            return Err(Error::HashMismatch);
        }
        // This verifies envelope integrity against its own CLAIMED binding.
        // It cannot establish that the copied origin is currently authorized.
        let origin = crate::reopen(&origin_bytes, &self.origin.receipt.binding)?;
        let original = managed(&origin)?;
        let actual = calculate(self.canonical_source.as_bytes())?;
        if actual.canonical_source != self.canonical_source
            || actual.source_sha256 != self.source_sha256
            || actual.values != self.values
            || actual.canonical_csv != self.canonical_csv
            || actual.csv_sha256 != self.csv_sha256
            || actual.evaluation_steps != self.evaluation_steps
            || self.source_changed != (actual.canonical_source != original.canonical_source)
        {
            return Err(Error::HashMismatch);
        }
        Ok((origin, actual))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.is_empty() || bytes.len() > MAX_WORKBOOK_BYTES {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
    /// Bounded strict typed DATA reopen, with independent real recalculation.
    /// No path, application, external URL, macro or shell is opened/executed.
    pub fn reopen_data(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_WORKBOOK_BYTES {
            return Err(Error::Bounds);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEnvelope)?;
        if value.canonical_bytes()? != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn recalculate_data(&self) -> Result<spreadsheet::Calculation> {
        Ok(self.validate()?.1)
    }
    pub fn origin_reference_data(&self) -> Result<VersionReference> {
        self.validate()?.0.reference()
    }
    pub fn origin_binding_data(&self) -> Result<OwnerBinding> {
        Ok(self.validate()?.0.receipt().binding.clone())
    }
    pub fn source_changed(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.source_changed)
    }
    /// Edit the declared AST and recompute all derived fields. The original
    /// immutable base is retained; this is a proposed external edit only.
    pub fn edit_data(&self, source: &[u8]) -> Result<Self> {
        let (origin, _) = self.validate()?;
        let original = managed(&origin)?;
        Self::with_source(&origin, &original, source)
    }
    /// The managed source for a NEW explicitly reviewed workflow/publication.
    /// This does not create a version or make the old origin current again.
    pub fn managed_source_data(&self) -> Result<Vec<u8>> {
        let calculation = self.recalculate_data()?;
        let source: serde_json::Value =
            serde_json::from_str(&calculation.canonical_source).map_err(|_| Error::InvalidJson)?;
        Ok(crate::canonical::content(
            Format::Json,
            &encode(&ManagedSource {
                schema_version: 1,
                engine: "spreadsheet".into(),
                source,
            })?,
        )?
        .into_bytes())
    }
}

#[cfg(test)]
mod tests;
