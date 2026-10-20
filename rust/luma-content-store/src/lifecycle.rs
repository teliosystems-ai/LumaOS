//! Versioned logical trash. No expiry, erasure, grant or authority is inferred.
//! Immutable bytes and earlier versions remain protected history; restoring is
//! a new exact-reviewed effect, never replay of a copied deletion receipt.
use crate::*;
use luma_content::EditOrigin;

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleStatus {
    Live,
    Trashed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleOperation {
    Trash,
    Restore,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPolicy {
    UntilExplicitRestoreNoPurge,
}

/// Descriptive exact CAS selector. It is not a capability or current authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReference {
    pub version: VersionReference,
    pub revision: u64,
    pub state_sha256: String,
    pub status: LifecycleStatus,
}
impl LifecycleReference {
    pub fn validate(&self) -> Result<()> {
        collections::reference(&self.version)?;
        if self.revision == 0
            || self.revision > MAX_OUTCOMES as u64
            || !hash(&self.state_sha256)
            || self.state_sha256.bytes().all(|b| b == b'0')
        {
            return Err("invalid exact lifecycle revision or state digest".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub request_id: String,
    pub workflow_sha256: String,
    pub expected: LifecycleReference,
    pub operation: LifecycleOperation,
    pub retention: RetentionPolicy,
}
impl LifecycleRequest {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.expected.validate()?;
        if self.schema_version != 1
            || !identifier(&self.request_id)
            || !hash(&self.workflow_sha256)
            || self.workflow_sha256.bytes().all(|b| b == b'0')
        {
            return Err("invalid closed lifecycle request identity".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err("lifecycle request exceeds fixed bound".into());
        }
        Ok(bytes)
    }
    pub fn artifact_id(&self) -> &str {
        &self.expected.version.artifact_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn provenance(&self) -> Result<Provenance> {
        Ok(Provenance {
            request_id: self.request_id.clone(),
            workflow_sha256: self.workflow_sha256.clone(),
            source_sha256: luma_content::sha256(&self.canonical_bytes()?),
            origin: EditOrigin::External,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    pub request: LifecycleRequest,
    pub observed: LifecycleReference,
}

pub(super) fn validate_data(data: &PlanData) -> Result<()> {
    match &data.lifecycle {
        None if matches!(
            (data.schema_version, data.source_kind),
            (1, None)
                | (2, Some(SourceKind::ManagedTableIntent))
                | (3, Some(SourceKind::ManagedRenderIntent))
                | (4, Some(SourceKind::CollectionIntent))
        ) && !matches!(
            data.decision,
            DecisionKind::Trashed | DecisionKind::Restored
        ) =>
        {
            Ok(())
        }
        Some(value)
            if data.schema_version == 5
                && data.source_kind == Some(SourceKind::LifecycleIntent) =>
        {
            let request = &value.request;
            request.validate()?;
            value.observed.validate()?;
            let source = request.canonical_bytes()?;
            let desired = match request.operation {
                LifecycleOperation::Trash => LifecycleStatus::Trashed,
                LifecycleOperation::Restore => LifecycleStatus::Live,
            };
            let decision = if request.expected != value.observed {
                DecisionKind::ConflictRetained
            } else if value.observed.status == desired {
                DecisionKind::NoChangeRetained
            } else if desired == LifecycleStatus::Trashed {
                DecisionKind::Trashed
            } else {
                DecisionKind::Restored
            };
            if data.binding != request.binding
                || data.artifact_id != request.artifact_id()
                || value.observed.version.artifact_id != request.artifact_id()
                || data.provenance != request.provenance()?
                || data.source_bytes != source.len() as u64
                || data.source_sha256 != luma_content::sha256(&source)
                || data.observed.as_ref() != Some(&value.observed.version)
                || data.expected.as_ref() != Some(&request.expected.version)
                || data.resulting != value.observed.version
                || data.decision != decision
                || data.derivation.is_some()
            {
                return Err(
                    "lifecycle metadata differs from its exact request/state/decision".into(),
                );
            }
            Ok(())
        }
        _ => Err("lifecycle data and history schema are inconsistent".into()),
    }
}

/// Closed canonical record inspection for independent native custody routing.
/// No record bytes, digest, request or status establishes live permission.
pub fn record_lifecycle_request(bytes: &[u8]) -> Result<Option<LifecycleRequest>> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
        return Err("lifecycle record bound exceeded".into());
    }
    let record: Record = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&record)? != bytes
        || record.schema_version != record.plan.schema_version
        || record.sequence == 0
        || record.sequence > MAX_OUTCOMES as u64
        || record.review_sha256 != luma_content::sha256(&serde_json::to_vec(&record.plan)?)
    {
        return Err("lifecycle record is not an exact canonical self-commitment".into());
    }
    validate_data(&record.plan)?;
    Ok(record.plan.lifecycle.map(|value| value.request))
}

pub(super) fn advanced(
    binding: &OwnerBinding,
    record: &Record,
    status: LifecycleStatus,
) -> Result<LifecycleReference> {
    let value = LifecycleReference {
        version: record.plan.resulting.clone(),
        revision: record.sequence,
        status,
        state_sha256: luma_content::sha256(&serde_json::to_vec(&(
            "luma-versioned-trash-state-v1",
            binding,
            record.sequence,
            &record.review_sha256,
            &record.plan.resulting,
            status,
        ))?),
    };
    value.validate()?;
    Ok(value)
}

impl Plan {
    pub(super) fn lifecycle(
        current: &ArtifactVersion,
        observed: &LifecycleReference,
        request: &LifecycleRequest,
    ) -> Result<Self> {
        request.validate()?;
        observed.validate()?;
        if current.receipt().binding != request.binding
            || current.reference()? != observed.version
            || request.artifact_id() != observed.version.artifact_id
        {
            return Err("lifecycle target is not its exact owner-local retained head".into());
        }
        let payload = current.canonical_envelope()?;
        let source = request.canonical_bytes()?;
        let desired = match request.operation {
            LifecycleOperation::Trash => LifecycleStatus::Trashed,
            LifecycleOperation::Restore => LifecycleStatus::Live,
        };
        let decision = if request.expected != *observed {
            DecisionKind::ConflictRetained
        } else if observed.status == desired {
            DecisionKind::NoChangeRetained
        } else if desired == LifecycleStatus::Trashed {
            DecisionKind::Trashed
        } else {
            DecisionKind::Restored
        };
        let data = PlanData {
            schema_version: 5,
            binding: request.binding.clone(),
            artifact_id: request.artifact_id().into(),
            format: current.receipt().format,
            provenance: request.provenance()?,
            observed: Some(observed.version.clone()),
            expected: Some(request.expected.version.clone()),
            decision,
            resulting: observed.version.clone(),
            source_sha256: luma_content::sha256(&source),
            source_bytes: source.len() as u64,
            payload_sha256: luma_content::sha256(&payload),
            payload_bytes: payload.len() as u64,
            source_kind: Some(SourceKind::LifecycleIntent),
            derivation: None,
            lifecycle: Some(Transition {
                request: request.clone(),
                observed: observed.clone(),
            }),
        };
        validate_data(&data)?;
        let bytes = serde_json::to_vec(&data)?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err("lifecycle plan exceeds fixed record bound".into());
        }
        Ok(Self {
            data,
            payload,
            review: luma_content::sha256(&bytes),
        })
    }
    pub fn lifecycle_request(&self) -> Option<&LifecycleRequest> {
        self.data.lifecycle.as_ref().map(|value| &value.request)
    }
}

impl Snapshot {
    pub(super) fn require_live(&self, artifact: &str) -> Result<()> {
        if self
            .lifecycle
            .get(artifact)
            .is_some_and(|state| state.status == LifecycleStatus::Trashed)
        {
            return Err(
                "artifact is in versioned trash; explicit trash inspection/restore required".into(),
            );
        }
        Ok(())
    }
    pub(super) fn check_lifecycle_plan(&self, plan: &Plan) -> Result<()> {
        if let Some(value) = &plan.data.lifecycle {
            if self.lifecycle.get(plan.artifact_id()) != Some(&value.observed) {
                return Err("lifecycle changed since exact proposal review; review anew".into());
            }
        } else {
            self.require_live(plan.artifact_id())?;
        }
        Ok(())
    }
}

impl Repository {
    pub fn lifecycle_status(
        &self,
        artifact: &str,
        boundary: &mut impl Boundary,
    ) -> Result<LifecycleReference> {
        if !identifier(artifact) {
            return Err("invalid lifecycle artifact identifier".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let result = self
            .snapshot(None, boundary)?
            .lifecycle
            .remove(artifact)
            .ok_or("published lifecycle target unavailable")?;
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }
    pub fn plan_lifecycle(
        &self,
        request: &LifecycleRequest,
        boundary: &mut impl Boundary,
    ) -> Result<Plan> {
        request.validate()?;
        if request.binding != self.binding {
            return Err("lifecycle request owner differs".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        if let Some((_, plan, source)) = snapshot
            .records
            .iter()
            .find(|(record, _, _)| record.plan.provenance.request_id == request.request_id)
        {
            if source != &request.canonical_bytes()? || plan.lifecycle_request() != Some(request) {
                return Err(
                    "lifecycle request identifier was already used for different input".into(),
                );
            }
            storage::repository_check(self, None, boundary)?;
            return Ok(plan.clone());
        }
        let current = snapshot
            .current
            .get(request.artifact_id())
            .ok_or("published lifecycle target unavailable")?;
        let observed = snapshot
            .lifecycle
            .get(request.artifact_id())
            .ok_or("lifecycle head unavailable")?;
        let plan = Plan::lifecycle(current, observed, request)?;
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }
    /// Only explicit current-trash inspection may return these retained bytes.
    /// The composition root must admit its separately selected exact Read scope.
    pub fn trash_version(
        &self,
        expected: &LifecycleReference,
        boundary: &mut impl Boundary,
    ) -> Result<ArtifactVersion> {
        expected.validate()?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        if expected.status != LifecycleStatus::Trashed
            || snapshot.lifecycle.get(&expected.version.artifact_id) != Some(expected)
        {
            return Err("trash inspection requires the exact current trashed revision".into());
        }
        let result = snapshot
            .current
            .get(&expected.version.artifact_id)
            .ok_or("trash head unavailable")?
            .clone();
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }
}
