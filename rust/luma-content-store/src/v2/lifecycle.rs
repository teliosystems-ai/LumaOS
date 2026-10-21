//! V2 lifecycle revisions extend the global v2 ordinal. Legacy request/schema
//! limits remain unchanged; their exact state digests are retained on migration.
use super::*;
use crate::{LifecycleOperation, LifecycleStatus, RetentionPolicy};
use luma_content::{ArtifactVersion, EditOrigin, Provenance, VersionReference};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleState {
    pub version: VersionReference,
    pub revision: u64,
    pub state_sha256: String,
    pub status: LifecycleStatus,
}
impl LifecycleState {
    pub fn validate(&self) -> Result<()> {
        crate::collections::reference(&self.version)?;
        digest(&self.state_sha256)?;
        if self.revision == 0 || self.revision > MAX_MAP_ENTRIES {
            return Err("v2 lifecycle global revision invalid".into());
        }
        Ok(())
    }
    pub(super) fn legacy(value: &crate::LifecycleReference) -> Result<Self> {
        value.validate()?;
        let state = Self {
            version: value.version.clone(),
            revision: value.revision,
            state_sha256: value.state_sha256.clone(),
            status: value.status,
        };
        state.validate()?;
        Ok(state)
    }
    pub(super) fn wire(&self) -> crate::LifecycleReference {
        crate::LifecycleReference {
            version: self.version.clone(),
            revision: self.revision,
            state_sha256: self.state_sha256.clone(),
            status: self.status,
        }
    }
    pub(super) fn advance(
        binding: &OwnerBinding,
        record: &crate::Record,
        status: LifecycleStatus,
        legacy: bool,
    ) -> Result<Self> {
        let value = if legacy {
            Self::legacy(&crate::lifecycle::advanced(binding, record, status)?)?
        } else {
            Self {
                version: record.plan.resulting.clone(),
                revision: record.sequence,
                status,
                state_sha256: luma_content::sha256(&serde_json::to_vec(&(
                    "luma-versioned-trash-state-v2",
                    binding,
                    record.sequence,
                    &record.review_sha256,
                    &record.plan.resulting,
                    status,
                ))?),
            }
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequestV2 {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub request_id: String,
    pub workflow_sha256: String,
    pub expected: LifecycleState,
    pub operation: LifecycleOperation,
    pub retention: RetentionPolicy,
}
impl LifecycleRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        identifier(&self.request_id)?;
        digest(&self.workflow_sha256)?;
        self.expected.validate()?;
        if self.schema_version != 2 {
            return Err("v2 lifecycle requires its distinct request schema".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > crate::MAX_RECORD as usize {
            return Err("v2 lifecycle source exceeds record bound".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, crate::MAX_RECORD as usize)?;
        value.validate()?;
        Ok(value)
    }
    pub(super) fn wire(&self) -> crate::LifecycleRequest {
        crate::LifecycleRequest {
            schema_version: 2,
            binding: self.binding.clone(),
            request_id: self.request_id.clone(),
            workflow_sha256: self.workflow_sha256.clone(),
            expected: self.expected.wire(),
            operation: self.operation,
            retention: self.retention,
        }
    }
}
pub(super) fn plan(
    current: &ArtifactVersion,
    observed: &LifecycleState,
    request: &LifecycleRequestV2,
) -> Result<crate::Plan> {
    request.validate()?;
    observed.validate()?;
    if current.receipt().binding != request.binding
        || current.reference()? != observed.version
        || request.expected.version.artifact_id != observed.version.artifact_id
    {
        return Err("v2 lifecycle does not target the exact retained artifact".into());
    }
    let source = request.canonical_bytes()?;
    let payload = current.canonical_envelope()?;
    let desired = if request.operation == LifecycleOperation::Trash {
        LifecycleStatus::Trashed
    } else {
        LifecycleStatus::Live
    };
    let decision = if request.expected != *observed {
        DecisionKind::ConflictRetained
    } else if desired == observed.status {
        DecisionKind::NoChangeRetained
    } else if desired == LifecycleStatus::Trashed {
        DecisionKind::Trashed
    } else {
        DecisionKind::Restored
    };
    let data = crate::PlanData {
        schema_version: 6,
        binding: request.binding.clone(),
        artifact_id: observed.version.artifact_id.clone(),
        format: current.receipt().format,
        provenance: Provenance {
            request_id: request.request_id.clone(),
            workflow_sha256: request.workflow_sha256.clone(),
            source_sha256: luma_content::sha256(&source),
            origin: EditOrigin::External,
        },
        observed: Some(observed.version.clone()),
        expected: Some(request.expected.version.clone()),
        decision,
        resulting: observed.version.clone(),
        source_sha256: luma_content::sha256(&source),
        source_bytes: source.len() as u64,
        payload_sha256: luma_content::sha256(&payload),
        payload_bytes: payload.len() as u64,
        source_kind: Some(crate::SourceKind::LifecycleIntent),
        derivation: None,
        lifecycle: Some(crate::lifecycle::Transition {
            request: request.wire(),
            observed: observed.wire(),
        }),
    };
    let review = luma_content::sha256(&serde_json::to_vec(&data)?);
    Ok(crate::Plan {
        data,
        payload,
        review,
    })
}
pub(super) fn rebuild(
    current: &ArtifactVersion,
    observed: &LifecycleState,
    data: &crate::PlanData,
    source: &[u8],
) -> Result<crate::Plan> {
    let request = LifecycleRequestV2::from_canonical(source)?;
    if data.schema_version != 6 || data.source_kind != Some(crate::SourceKind::LifecycleIntent) {
        return Err("v2 lifecycle record schema mismatch".into());
    }
    let rebuilt = plan(current, observed, &request)?;
    if &rebuilt.data != data {
        return Err("v2 lifecycle record does not reconstruct its exact current state".into());
    }
    Ok(rebuilt)
}

pub(super) fn validate_record_data(
    binding: &OwnerBinding,
    record: &crate::Record,
    source: &[u8],
    payload: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let data = &record.plan;
    let transition = data
        .lifecycle
        .as_ref()
        .ok_or("v2 lifecycle transition absent")?;
    let request = LifecycleRequestV2::from_canonical(source)?;
    let observed = LifecycleState {
        version: transition.observed.version.clone(),
        revision: transition.observed.revision,
        state_sha256: transition.observed.state_sha256.clone(),
        status: transition.observed.status,
    };
    observed.validate()?;
    let current = luma_content::reopen(payload, binding)?;
    check()?;
    let rebuilt = plan(&current, &observed, &request)?;
    if record.schema_version != 6
        || data.binding != *binding
        || rebuilt.data != *data
        || rebuilt.payload != payload
        || rebuilt.review != record.review_sha256
    {
        return Err("v2 lifecycle canonical metadata/member commitment differs".into());
    }
    check()
}
