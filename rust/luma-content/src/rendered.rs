//! Managed rendering proposals bind editable source and a reproducible result.
//! Actual publication, authorization and workflow completion belong to the caller.
use crate::{
    canonical, capture_content, identifier, make_version, nonzero_digest, sha256, ArtifactVersion,
    EditOrigin, Error, Format, OwnerBinding, Provenance, Result, VersionReference,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    Spreadsheet,
    Document,
    Diagram,
    Animation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub binding: OwnerBinding,
    pub artifact_id: String,
    pub expected: Option<VersionReference>,
    pub metadata: crate::table::EditMetadata,
    pub engine: Engine,
    /// Exact submitted JSON text, retained even when equivalent canonical forms exist.
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    pub engine: Engine,
    pub implementation: String,
    pub canonical_source_sha256: String,
    pub output_sha256: String,
    pub output_bytes: u64,
    pub media_type: String,
}

#[derive(Clone, Debug)]
pub enum Decision {
    Published(ArtifactVersion),
    NoChange(VersionReference),
    Conflict(VersionReference),
}

impl Request {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if !identifier(&self.artifact_id)
            || !identifier(&self.metadata.request_id)
            || !nonzero_digest(&self.metadata.workflow_sha256)
            || self.source.is_empty()
            || self.source.len() > crate::MAX_CONTENT_BYTES
        {
            return Err(Error::InvalidProvenance);
        }
        if let Some(expected) = &self.expected {
            expected.validate()?;
            if expected.artifact_id != self.artifact_id {
                return Err(Error::InvalidIdentifier);
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::InvalidJson)?;
        if bytes.len() > crate::table::MAX_REQUEST_BYTES {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
}

/// Returns the immutable editable JSON wrapper and the exact result commitment.
/// The engine discriminator is inside the versioned content, not mutable metadata.
pub fn prepare(request: &Request) -> Result<(String, Derivation)> {
    request.validate()?;
    let (source, implementation, output, media_type) = match request.engine {
        Engine::Spreadsheet => {
            let value = crate::spreadsheet::calculate(request.source.as_bytes())
                .map_err(|_| Error::InvalidEdit)?;
            (
                value.canonical_source,
                value.engine,
                value.canonical_csv.into_bytes(),
                "text/csv; charset=utf-8",
            )
        }
        Engine::Document => {
            let value = crate::document::render(request.source.as_bytes())
                .map_err(|_| Error::InvalidEdit)?;
            (
                value.canonical_source,
                value.engine,
                value.canonical_html.into_bytes(),
                "text/html; charset=utf-8",
            )
        }
        Engine::Diagram => {
            let value = crate::diagram::render(request.source.as_bytes())
                .map_err(|_| Error::InvalidEdit)?;
            (
                value.canonical_source,
                value.engine,
                value.canonical_svg.into_bytes(),
                "image/svg+xml",
            )
        }
        Engine::Animation => {
            let value = crate::animation::render(request.source.as_bytes())?;
            let output = serde_json::to_vec(&value.frames).map_err(|_| Error::InvalidJson)?;
            (
                value.canonical_source,
                value.engine,
                output,
                "application/vnd.luma.sampled-svg-frames+json",
            )
        }
    };
    let wrapper = serde_json::to_vec(&serde_json::json!({"schema_version":1,
        "engine":request.engine,"source":serde_json::from_str::<serde_json::Value>(&source)
            .map_err(|_| Error::InvalidJson)?}))
    .map_err(|_| Error::InvalidJson)?;
    let content = canonical::content(Format::Json, &wrapper)?;
    Ok((
        content,
        Derivation {
            engine: request.engine,
            implementation: implementation.into(),
            canonical_source_sha256: sha256(source.as_bytes()),
            output_sha256: sha256(&output),
            output_bytes: output.len() as u64,
            media_type: media_type.into(),
        },
    ))
}

/// Stale bases retain the exact intent without changing the current head. A
/// source/formula edit publishes even if its rendered output is byte-identical.
pub fn apply(
    current: Option<&ArtifactVersion>,
    request: &Request,
) -> Result<(Decision, Derivation)> {
    let (source, derivation) = prepare(request)?;
    let provenance = Provenance {
        request_id: request.metadata.request_id.clone(),
        workflow_sha256: request.metadata.workflow_sha256.clone(),
        source_sha256: sha256(source.as_bytes()),
        origin: EditOrigin::Managed,
    };
    let candidate = capture_content(
        &request.binding,
        &request.artifact_id,
        Format::Json,
        source.as_bytes(),
        provenance,
    )?;
    let decision = if let Some(current) = current {
        current.validate()?;
        if current.receipt.binding != request.binding
            || current.receipt.artifact_id != request.artifact_id
            || current.receipt.format != Format::Json
        {
            return Err(Error::OwnerMismatch);
        }
        let prior: serde_json::Value =
            serde_json::from_str(&current.content).map_err(|_| Error::InvalidJson)?;
        if prior.get("schema_version") != Some(&serde_json::json!(1))
            || prior.get("engine")
                != Some(&serde_json::to_value(request.engine).map_err(|_| Error::InvalidJson)?)
        {
            return Err(Error::InvalidEdit);
        }
        let expected = request.expected.as_ref().ok_or(Error::InvalidReceipt)?;
        let current_reference = current.reference()?;
        if expected != &current_reference {
            Decision::Conflict(current_reference)
        } else if current.content == candidate.content {
            Decision::NoChange(current_reference)
        } else {
            Decision::Published(make_version(
                request.binding.clone(),
                &request.artifact_id,
                current
                    .receipt
                    .version
                    .checked_add(1)
                    .ok_or(Error::VersionOverflow)?,
                Some(current_reference),
                candidate,
            )?)
        }
    } else {
        if request.expected.is_some() {
            return Err(Error::InvalidReceipt);
        }
        Decision::Published(make_version(
            request.binding.clone(),
            &request.artifact_id,
            1,
            None,
            candidate,
        )?)
    };
    Ok((decision, derivation))
}
