//! Durable local-ext4 storage for bounded editable-content contracts.
//!
//! This crate does not authenticate identities, issue finite grants, acquire a
//! kernel resource lease, sign data or establish rollback-resistant authority.
//! Every caller must supply a real [`Boundary`] that enforces those independent
//! requirements continuously. There is deliberately no default implementation.
//! The v1 [`Repository`] is exclusively locked for its lifetime. Its outcomes are
//! committed by a no-replace directory rename, with their exact source retained.
//! Partial preparation is never erased or overwritten; an incompatible partial
//! write requires separately authorized, exact reviewed quarantine recovery.
//! [`v2`] separately provides immutable, unselected paged-map/segment data
//! foundations. It is not a current-root publisher, migration or custody adapter.
#![cfg(target_os = "linux")]

use luma_content::{
    ArtifactVersion, EditDecision, Format, OwnerBinding, Provenance, VersionReference,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

mod backup;
mod collections;
pub mod corpus_index;
mod lifecycle;
mod publication;
mod queries;
mod recovery;
mod restore;
mod semantic;
mod state;
mod storage;
pub mod v2;
pub use backup::{
    inspect_backup_data, inspect_backup_data_checked, BackupArea, BackupAreaReview, BackupBoundary,
    BackupBudget, BackupDirectory, BackupInspection, BackupManifest, BackupMember, BackupNamespace,
    BackupReview, ContentBackup, MAX_BACKUP_MANIFEST_BYTES, MAX_BACKUP_REVIEW_BYTES,
    MAX_CONTENT_BACKUP_BYTES,
};
pub use collections::{
    CollectionMemberships, CollectionPage, CollectionSource, CollectionVersion,
    MAX_COLLECTION_MEMBERS, MAX_COLLECTION_PAGE, MAX_COLLECTION_SOURCE_BYTES,
};
pub use lifecycle::{
    record_lifecycle_request, LifecycleOperation, LifecycleReference, LifecycleRequest,
    LifecycleStatus, RetentionPolicy,
};
pub use publication::{
    canonical_record_history_head, PreparedPublication, PublicationCommitment, PublicationMember,
};
pub use queries::{
    canonical_search_query, canonical_search_selection, CollectionSearchResults, SearchHit,
    SearchResults, SelectedSearchResults, TermMatch, MAX_SEARCH_QUERY_BYTES,
    MAX_SEARCH_RESPONSE_BYTES, MAX_SEARCH_RESULTS, MAX_SEARCH_SELECTION, MAX_SEARCH_TERMS,
    MAX_SEARCH_TERM_BYTES,
};
pub use recovery::{
    PreparationDirectory, PreparationDirectoryIdentity, PreparationFileIdentity, PreparationMember,
    PreparationRecoveryOutcome, PreparationReview, MAX_PREPARATION_REVIEW_BYTES,
    MAX_QUARANTINED_PREPARATIONS,
};
pub use restore::{
    plan_restore_data_checked, plan_restore_data_checked_versions, RestoreMapping, RestorePlan,
    RestoreReview, RestoreStepReview, MAX_RESTORE_REVIEW_BYTES,
};
pub use semantic::{
    validate_semantic_query, SemanticCollectionResults, SemanticHit, SemanticResults,
    MAX_SEMANTIC_DIMENSIONS, MAX_SEMANTIC_FEATURES, MAX_SEMANTIC_VOCABULARY,
};
pub use state::VerifiedState;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MAX_REPOSITORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_OUTCOMES: usize = 256;
pub const MAX_PENDING: usize = 16;
pub const MAX_DOMAINS: usize = 1024;
const MAX_RECORD: u64 = 8192;
const MAX_PAYLOAD: u64 = luma_content::MAX_ENVELOPE_BYTES as u64;
const MAX_SOURCE: u64 = luma_content::table::MAX_REQUEST_BYTES as u64;

/// A fixed requested budget, not proof that it has been reserved or enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceBudget {
    pub memory_bytes: u64,
    pub tasks: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub additional_storage_bytes: u64,
}

impl ResourceBudget {
    fn inspection() -> Self {
        Self {
            memory_bytes: 256 * 1024 * 1024,
            tasks: 1,
            read_bytes: 256 * 1024 * 1024,
            write_bytes: 0,
            additional_storage_bytes: 0,
        }
    }
    fn mutation(bytes: u64) -> Self {
        Self {
            write_bytes: bytes + 8192,
            additional_storage_bytes: bytes + 8192,
            ..Self::inspection()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionKind {
    Published,
    ConflictRetained,
    NoChangeRetained,
    Trashed,
    Restored,
}

/// Identifies what the retained exact input means, not an execution permission.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Content,
    ManagedTableIntent,
    ManagedRenderIntent,
    CollectionIntent,
    LifecycleIntent,
}

/// Inspect and mutation authority are independent. Mutation checks must also
/// validate the exact review, requested effect, live owner and current lease.
#[derive(Clone, Copy, Debug)]
pub enum Access<'a> {
    Inspect {
        binding: &'a OwnerBinding,
    },
    Mutate {
        binding: &'a OwnerBinding,
        review_sha256: &'a str,
        decision: DecisionKind,
        source_bytes: u64,
        storage_bytes: u64,
    },
    Recover {
        binding: &'a OwnerBinding,
        review_sha256: &'a str,
        retained_bytes: u64,
    },
}

/// Downstream production adapters must enforce genuine current identity,
/// account generation, finite Read/effect grants and a live resource lease.
/// `admit` is called before private I/O; `check` is repeated between bounded
/// reads/writes and before/after commit. Returning Ok is a security decision by
/// the caller, never an authorization judgment made by this data/storage crate.
pub trait Boundary {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()>;
    fn check(&mut self, access: Access<'_>) -> Result<()>;
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema_version: u32,
    format: String,
    binding: OwnerBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PlanData {
    schema_version: u32,
    binding: OwnerBinding,
    artifact_id: String,
    format: Format,
    provenance: Provenance,
    observed: Option<VersionReference>,
    expected: Option<VersionReference>,
    decision: DecisionKind,
    resulting: VersionReference,
    source_sha256: String,
    source_bytes: u64,
    payload_sha256: String,
    payload_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_kind: Option<SourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    derivation: Option<luma_content::rendered::Derivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lifecycle: Option<lifecycle::Transition>,
}

/// Immutable, source-bound proposal. It is not a grant, lease or commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    data: PlanData,
    payload: Vec<u8>,
    review: String,
}

impl Plan {
    pub fn capture(
        binding: OwnerBinding,
        artifact: &str,
        format: Format,
        source: &[u8],
        provenance: Provenance,
    ) -> Result<Self> {
        Self::build(None, binding, artifact, format, None, source, provenance)
    }
    fn build(
        current: Option<&ArtifactVersion>,
        binding: OwnerBinding,
        artifact: &str,
        format: Format,
        expected: Option<VersionReference>,
        source: &[u8],
        provenance: Provenance,
    ) -> Result<Self> {
        let observed = current.map(ArtifactVersion::reference).transpose()?;
        let (decision, resulting, payload) = match current {
            None => {
                if expected.is_some() {
                    return Err("initial capture cannot have an external base".into());
                }
                let version = luma_content::capture(
                    binding.clone(),
                    artifact,
                    format,
                    source,
                    provenance.clone(),
                )?;
                (
                    DecisionKind::Published,
                    version.reference()?,
                    version.canonical_envelope()?,
                )
            }
            Some(current) => {
                if current.receipt().artifact_id != artifact || current.receipt().format != format {
                    return Err("external edit cannot retarget artifact or format".into());
                }
                let expected = expected
                    .as_ref()
                    .ok_or("external edit requires its exact base reference")?;
                match luma_content::compare_external_edit(
                    current,
                    expected,
                    &binding,
                    source,
                    provenance.clone(),
                )? {
                    EditDecision::NewVersion(version) => (
                        DecisionKind::Published,
                        version.reference()?,
                        version.canonical_envelope()?,
                    ),
                    EditDecision::Conflict {
                        current, candidate, ..
                    } => (
                        DecisionKind::ConflictRetained,
                        current,
                        candidate.canonical_bytes()?,
                    ),
                    EditDecision::NoChange {
                        current: reference, ..
                    } => (
                        DecisionKind::NoChangeRetained,
                        reference,
                        current.canonical_envelope()?,
                    ),
                }
            }
        };
        if payload.len() as u64 > MAX_PAYLOAD {
            return Err("content-store payload bound exceeded".into());
        }
        let data = PlanData {
            schema_version: 1,
            binding,
            artifact_id: artifact.into(),
            format,
            provenance,
            observed,
            expected,
            decision,
            resulting,
            source_sha256: luma_content::sha256(source),
            source_bytes: source.len() as u64,
            payload_sha256: luma_content::sha256(&payload),
            payload_bytes: payload.len() as u64,
            source_kind: None,
            derivation: None,
            lifecycle: None,
        };
        let bytes = serde_json::to_vec(&data)?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err("content-store plan bound exceeded".into());
        }
        Ok(Self {
            data,
            payload,
            review: luma_content::sha256(&bytes),
        })
    }
    /// Review a deterministic managed edit without publishing it. The retained
    /// source is the canonical inert request, not a fabricated external save.
    pub fn managed_table(
        current: &ArtifactVersion,
        request: &luma_content::table::TableEditRequest,
    ) -> Result<Self> {
        let source = request.canonical_bytes()?;
        let (decision, resulting, payload) = match luma_content::table::apply(current, request)? {
            luma_content::table::Decision::NewVersion { version, .. } => (
                DecisionKind::Published,
                version.reference()?,
                version.canonical_envelope()?,
            ),
            luma_content::table::Decision::NoChange {
                current: reference, ..
            } => (
                DecisionKind::NoChangeRetained,
                reference,
                current.canonical_envelope()?,
            ),
            luma_content::table::Decision::Conflict {
                current: reference, ..
            } => (
                DecisionKind::ConflictRetained,
                reference,
                current.canonical_envelope()?,
            ),
        };
        let data = PlanData {
            schema_version: 2,
            binding: request.binding.clone(),
            artifact_id: request.expected.artifact_id.clone(),
            format: Format::Csv,
            // This is provenance of the inert intent. Published version receipts
            // separately bind the exact generated canonical CSV source bytes.
            provenance: Provenance {
                request_id: request.metadata.request_id.clone(),
                workflow_sha256: request.metadata.workflow_sha256.clone(),
                source_sha256: luma_content::sha256(&source),
                origin: luma_content::EditOrigin::Managed,
            },
            observed: Some(current.reference()?),
            expected: Some(request.expected.clone()),
            decision,
            resulting,
            source_sha256: luma_content::sha256(&source),
            source_bytes: source.len() as u64,
            payload_sha256: luma_content::sha256(&payload),
            payload_bytes: payload.len() as u64,
            source_kind: Some(SourceKind::ManagedTableIntent),
            derivation: None,
            lifecycle: None,
        };
        let bytes = serde_json::to_vec(&data)?;
        if bytes.len() as u64 > MAX_RECORD || payload.len() as u64 > MAX_PAYLOAD {
            return Err("managed-table proposal exceeds fixed bound".into());
        }
        Ok(Self {
            data,
            payload,
            review: luma_content::sha256(&bytes),
        })
    }
    /// Recalculate a managed source under the exact versioned engine contract.
    /// The immutable JSON version stores the editable source; source.bin retains
    /// the complete submitted intent, and the review binds the generated result.
    pub fn managed_render(
        current: Option<&ArtifactVersion>,
        request: &luma_content::rendered::Request,
    ) -> Result<Self> {
        let source = request.canonical_bytes()?;
        let (decision, derivation) = luma_content::rendered::apply(current, request)?;
        let (decision, resulting, payload) = match decision {
            luma_content::rendered::Decision::Published(version) => (
                DecisionKind::Published,
                version.reference()?,
                version.canonical_envelope()?,
            ),
            luma_content::rendered::Decision::NoChange(reference) => (
                DecisionKind::NoChangeRetained,
                reference,
                current.ok_or("missing render base")?.canonical_envelope()?,
            ),
            luma_content::rendered::Decision::Conflict(reference) => (
                DecisionKind::ConflictRetained,
                reference,
                current.ok_or("missing render base")?.canonical_envelope()?,
            ),
        };
        let data = PlanData {
            schema_version: 3,
            binding: request.binding.clone(),
            artifact_id: request.artifact_id.clone(),
            format: Format::Json,
            provenance: Provenance {
                request_id: request.metadata.request_id.clone(),
                workflow_sha256: request.metadata.workflow_sha256.clone(),
                source_sha256: luma_content::sha256(&source),
                origin: luma_content::EditOrigin::Managed,
            },
            observed: current.map(ArtifactVersion::reference).transpose()?,
            expected: request.expected.clone(),
            decision,
            resulting,
            source_sha256: luma_content::sha256(&source),
            source_bytes: source.len() as u64,
            payload_sha256: luma_content::sha256(&payload),
            payload_bytes: payload.len() as u64,
            source_kind: Some(SourceKind::ManagedRenderIntent),
            derivation: Some(derivation),
            lifecycle: None,
        };
        let bytes = serde_json::to_vec(&data)?;
        if bytes.len() as u64 > MAX_RECORD || payload.len() as u64 > MAX_PAYLOAD {
            return Err("managed render proposal exceeds fixed bound".into());
        }
        Ok(Self {
            data,
            payload,
            review: luma_content::sha256(&bytes),
        })
    }
    fn rebuild(current: Option<&ArtifactVersion>, data: &PlanData, source: &[u8]) -> Result<Self> {
        lifecycle::validate_data(data)?;
        match (data.schema_version, data.source_kind) {
            (1, None) => Self::build(
                current,
                data.binding.clone(),
                &data.artifact_id,
                data.format,
                data.expected.clone(),
                source,
                data.provenance.clone(),
            ),
            (2, Some(SourceKind::ManagedTableIntent)) => {
                if source.len() as u64 > MAX_SOURCE {
                    return Err("managed-table intent exceeds fixed bound".into());
                }
                let request: luma_content::table::TableEditRequest =
                    serde_json::from_slice(source)?;
                if request.canonical_bytes()? != source {
                    return Err("managed-table intent is not exact canonical input".into());
                }
                Self::managed_table(
                    current.ok_or("managed edit has no prior artifact")?,
                    &request,
                )
            }
            (3, Some(SourceKind::ManagedRenderIntent)) => {
                let request: luma_content::rendered::Request = serde_json::from_slice(source)?;
                if request.canonical_bytes()? != source {
                    return Err("render intent is not exact canonical input".into());
                }
                Self::managed_render(current, &request)
            }
            (4, Some(SourceKind::CollectionIntent)) => {
                let collection = CollectionSource::from_canonical(source)?;
                Self::collection(
                    current,
                    data.binding.clone(),
                    &collection,
                    data.expected.clone(),
                    data.provenance.clone(),
                )
            }
            (5, Some(SourceKind::LifecycleIntent)) => {
                let transition = data
                    .lifecycle
                    .as_ref()
                    .ok_or("lifecycle transition absent")?;
                if transition.request.canonical_bytes()? != source {
                    return Err("lifecycle source differs from its exact typed request".into());
                }
                Self::lifecycle(
                    current.ok_or("lifecycle retained head absent")?,
                    &transition.observed,
                    &transition.request,
                )
            }
            _ => Err("unsupported content-store plan schema or source kind".into()),
        }
    }
    pub fn binding(&self) -> &OwnerBinding {
        &self.data.binding
    }
    pub fn request_id(&self) -> &str {
        &self.data.provenance.request_id
    }
    pub fn artifact_id(&self) -> &str {
        &self.data.artifact_id
    }
    pub fn format(&self) -> Format {
        self.data.format
    }
    pub fn provenance(&self) -> &Provenance {
        &self.data.provenance
    }
    pub fn expected(&self) -> Option<&VersionReference> {
        self.data.expected.as_ref()
    }
    pub fn review_sha256(&self) -> &str {
        &self.review
    }
    pub fn decision(&self) -> DecisionKind {
        self.data.decision
    }
    pub fn resulting(&self) -> &VersionReference {
        &self.data.resulting
    }
    pub fn source_bytes(&self) -> u64 {
        self.data.source_bytes
    }
    pub fn source_kind(&self) -> SourceKind {
        self.data.source_kind.unwrap_or(SourceKind::Content)
    }
    pub fn derivation(&self) -> Option<&luma_content::rendered::Derivation> {
        self.data.derivation.as_ref()
    }
    pub fn storage_bytes(&self) -> u64 {
        // Conservative logical-file bound including the full record allowance,
        // not an ext4 block reservation or a claim of exact physical usage.
        self.data.source_bytes + self.data.payload_bytes + MAX_RECORD
    }
    pub fn access(&self) -> Access<'_> {
        Access::Mutate {
            binding: self.binding(),
            review_sha256: &self.review,
            decision: self.decision(),
            source_bytes: self.source_bytes(),
            storage_bytes: self.storage_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    sequence: u64,
    review_sha256: String,
    plan: PlanData,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub sequence: u64,
    pub request_id: String,
    pub review_sha256: String,
    pub decision: DecisionKind,
    pub resulting: VersionReference,
    pub source_sha256: String,
    pub source_kind: SourceKind,
    pub replayed: bool,
}

/// Authorized bytes, not an export grant or trusted version authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    pub outcome: Outcome,
    pub payload: Vec<u8>,
    pub source: Vec<u8>,
}

struct Snapshot {
    records: Vec<(Record, Plan, Vec<u8>)>,
    current: BTreeMap<String, ArtifactVersion>,
    lifecycle: BTreeMap<String, LifecycleReference>,
    pending: Vec<String>,
    bytes: u64,
    quarantine_sha256: String,
    quarantined: Vec<String>,
}

/// Shared reconstruction for live storage and portable backup data. A failed
/// observation poisons this instance; callers cannot skip a damaged record and
/// continue a different history using the same partially observed state.
struct HistoryReconstruction {
    current: BTreeMap<String, ArtifactVersion>,
    lifecycle: BTreeMap<String, LifecycleReference>,
    requests: BTreeSet<String>,
    collection_history: collections::CollectionHistory,
    count: u64,
    poisoned: bool,
}

impl HistoryReconstruction {
    fn new() -> Self {
        Self {
            current: BTreeMap::new(),
            lifecycle: BTreeMap::new(),
            requests: BTreeSet::new(),
            collection_history: collections::CollectionHistory::new(),
            count: 0,
            poisoned: false,
        }
    }

    fn observe(
        &mut self,
        binding: &OwnerBinding,
        record: &Record,
        payload: &[u8],
        source: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Plan> {
        if self.poisoned {
            return Err("content history reconstruction is fenced after a refused record".into());
        }
        self.poisoned = true;
        check()?;
        binding.validate()?;
        let source_limit = match (record.schema_version, record.plan.source_kind) {
            (1, None) => luma_content::MAX_CONTENT_BYTES as u64,
            (2, Some(SourceKind::ManagedTableIntent))
            | (3, Some(SourceKind::ManagedRenderIntent)) => MAX_SOURCE,
            (4, Some(SourceKind::CollectionIntent)) => MAX_COLLECTION_SOURCE_BYTES as u64,
            (5, Some(SourceKind::LifecycleIntent)) => MAX_RECORD,
            _ => return Err("content history schema or source kind mismatch".into()),
        };
        if record.schema_version != record.plan.schema_version
            || record.plan.binding != *binding
            || self.count >= MAX_OUTCOMES as u64
            || record.sequence != self.count + 1
            || self.requests.contains(&record.plan.provenance.request_id)
            || serde_json::to_vec(record)?.len() as u64 > MAX_RECORD
        {
            return Err("content outcome sequence, request or canonical identity mismatch".into());
        }
        if payload.len() as u64 > MAX_PAYLOAD
            || source.len() as u64 > source_limit
            || record.plan.payload_bytes != payload.len() as u64
            || record.plan.source_bytes != source.len() as u64
            || record.plan.payload_sha256 != luma_content::sha256(payload)
            || record.plan.source_sha256 != luma_content::sha256(source)
        {
            return Err(
                "content outcome payload or exact original-source integrity mismatch".into(),
            );
        }
        check()?;
        let prior = self.current.get(&record.plan.artifact_id);
        lifecycle::validate_data(&record.plan)?;
        if let Some(transition) = &record.plan.lifecycle {
            if self.lifecycle.get(&record.plan.artifact_id) != Some(&transition.observed) {
                return Err("lifecycle record does not extend its exact revision".into());
            }
        } else if self
            .lifecycle
            .get(&record.plan.artifact_id)
            .is_some_and(|value| value.status == LifecycleStatus::Trashed)
        {
            return Err("ordinary content publication targets a trashed identity".into());
        }
        if prior.map(ArtifactVersion::reference).transpose()? != record.plan.observed {
            return Err("content outcome does not extend its exact observed base".into());
        }
        let rebuilt = Plan::rebuild(prior, &record.plan, source)?;
        if rebuilt.data != record.plan
            || rebuilt.payload != payload
            || rebuilt.review != record.review_sha256
        {
            return Err("content outcome provenance or decision cannot be reconstructed".into());
        }
        self.collection_history.observe(&rebuilt, source, check)?;
        check()?;
        if rebuilt.decision() == DecisionKind::Published {
            self.current.insert(
                record.plan.artifact_id.clone(),
                luma_content::reopen(payload, binding)?,
            );
        }
        if matches!(
            rebuilt.decision(),
            DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
        ) {
            let status = if rebuilt.decision() == DecisionKind::Trashed {
                LifecycleStatus::Trashed
            } else {
                LifecycleStatus::Live
            };
            self.lifecycle.insert(
                record.plan.artifact_id.clone(),
                lifecycle::advanced(binding, record, status)?,
            );
        }
        self.requests
            .insert(record.plan.provenance.request_id.clone());
        self.count += 1;
        self.poisoned = false;
        Ok(rebuilt)
    }
}

/// One owner-generation namespace. No cross-owner deduplication or fallback.
pub struct Repository {
    base: File,
    name: String,
    root: File,
    pending: File,
    outcomes: File,
    quarantine: Option<File>,
    binding: OwnerBinding,
    expected_state: Option<VerifiedState>,
}

pub fn domain_name(binding: &OwnerBinding) -> Result<String> {
    binding.validate()?;
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-editable-content-store-v1",
        binding,
    ))?))
}

fn identity(binding: &OwnerBinding) -> Identity {
    Identity {
        schema_version: 1,
        format: "luma-editable-content-store-v1".into(),
        binding: binding.clone(),
    }
}

fn outcome(record: &Record, replayed: bool) -> Outcome {
    Outcome {
        sequence: record.sequence,
        request_id: record.plan.provenance.request_id.clone(),
        review_sha256: record.review_sha256.clone(),
        decision: record.plan.decision,
        resulting: record.plan.resulting.clone(),
        source_sha256: record.plan.source_sha256.clone(),
        source_kind: record.plan.source_kind.unwrap_or(SourceKind::Content),
        replayed,
    }
}

impl Repository {
    /// Namespace creation is itself covered by this exact initial mutation;
    /// inspection authority alone never permits creation or automatic repair.
    pub fn create_at(base: &Path, initial: &Plan, boundary: &mut impl Boundary) -> Result<Self> {
        if initial.data.observed.is_some()
            || initial.data.expected.is_some()
            || initial.data.resulting.version != 1
            || initial.decision() != DecisionKind::Published
        {
            return Err("repository creation requires an initial capture proposal".into());
        }
        boundary.admit(
            initial.binding(),
            ResourceBudget::mutation(initial.storage_bytes()),
        )?;
        boundary.check(Access::Inspect {
            binding: initial.binding(),
        })?;
        boundary.check(initial.access())?;
        let base = storage::base(base)?;
        lock(&base)?;
        let names = storage::names(&base, MAX_DOMAINS)?;
        if names.len() >= MAX_DOMAINS {
            return Err("content-store domain capacity exhausted".into());
        }
        if names.iter().any(|n| !hash(n)) {
            return Err("unexpected content-store domain namespace member".into());
        }
        let name = domain_name(initial.binding())?;
        if names.contains(&name) {
            return Err("repository already exists; open and inspect instead of replacing".into());
        }
        storage::reserve(&base, initial.storage_bytes())?;
        boundary.check(initial.access())?;
        let root = storage::mkdir(&base, &name)?;
        lock(&root)?;
        let mut check = || {
            boundary.check(Access::Inspect {
                binding: initial.binding(),
            })?;
            boundary.check(initial.access())
        };
        check()?;
        let pending = storage::mkdir(&root, "pending")?;
        check()?;
        let outcomes = storage::mkdir(&root, "outcomes")?;
        storage::write(
            &root,
            "identity.json",
            &serde_json::to_vec(&identity(initial.binding()))?,
            &mut check,
        )?;
        root.sync_all()?;
        base.sync_all()?;
        check()?;
        if unsafe { libc::flock(base.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            base,
            name,
            root,
            pending,
            outcomes,
            quarantine: None,
            binding: initial.binding().clone(),
            expected_state: None,
        })
    }

    pub fn open_at(
        base: &Path,
        binding: &OwnerBinding,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        binding.validate()?;
        boundary.admit(binding, ResourceBudget::inspection())?;
        boundary.check(Access::Inspect { binding })?;
        let base = storage::base(base)?;
        let name = domain_name(binding)?;
        let root = storage::directory(&base, &name)?;
        lock(&root)?;
        recovery::layout(&root)?;
        let quarantine = if storage::names(&root, 4)?
            .iter()
            .any(|name| name == "quarantine")
        {
            Some(storage::directory(&root, "quarantine")?)
        } else {
            None
        };
        let bytes = storage::read(&root, "identity.json", MAX_RECORD, &mut || {
            boundary.check(Access::Inspect { binding })
        })?;
        if bytes != serde_json::to_vec(&identity(binding))? {
            return Err("content-store identity or canonical format mismatch".into());
        }
        let result = Self {
            pending: storage::directory(&root, "pending")?,
            outcomes: storage::directory(&root, "outcomes")?,
            quarantine,
            base,
            name,
            root,
            binding: binding.clone(),
            expected_state: None,
        };
        result.snapshot(None, boundary)?;
        Ok(result)
    }

    fn snapshot(&self, plan: Option<&Plan>, boundary: &mut impl Boundary) -> Result<Snapshot> {
        self.snapshot_for_state(plan, boundary, self.expected_state.as_ref())
    }

    fn snapshot_for_state(
        &self,
        plan: Option<&Plan>,
        boundary: &mut impl Boundary,
        expected_state: Option<&VerifiedState>,
    ) -> Result<Snapshot> {
        let (quarantined_bytes, quarantine_sha256, quarantined) =
            recovery::validate_quarantine(self, plan, boundary)?;
        let mut check = || storage::repository_check(self, plan, boundary);
        check()?;
        recovery::layout(&self.root)?;
        let identity_bytes = storage::read(&self.root, "identity.json", MAX_RECORD, &mut check)?;
        if identity_bytes != serde_json::to_vec(&identity(&self.binding))? {
            return Err("content-store identity changed".into());
        }
        let pending = storage::names(&self.pending, MAX_PENDING)?;
        let names = storage::names(&self.outcomes, MAX_OUTCOMES)?;
        if pending.iter().chain(names.iter()).any(|n| !hash(n)) {
            return Err("unknown content-store transaction member".into());
        }
        if pending.iter().any(|n| names.contains(n)) {
            return Err("content outcome also exists in preparation; preserve evidence".into());
        }
        let mut total = quarantined_bytes;
        let mut raw = BTreeMap::new();
        for name in names {
            check()?;
            let dir = storage::directory(&self.outcomes, &name)?;
            if storage::names(&dir, 3)? != ["payload.json", "record.json", "source.bin"] {
                return Err("incomplete committed content outcome".into());
            }
            let record_bytes = storage::read(
                &dir,
                "record.json",
                MAX_RECORD.min(MAX_REPOSITORY_BYTES - total),
                &mut check,
            )?;
            total += record_bytes.len() as u64;
            let record: Record = serde_json::from_slice(&record_bytes)?;
            if serde_json::to_vec(&record)? != record_bytes
                || record.schema_version != record.plan.schema_version
                || !matches!(
                    (record.plan.schema_version, record.plan.source_kind),
                    (1, None)
                        | (2, Some(SourceKind::ManagedTableIntent))
                        | (3, Some(SourceKind::ManagedRenderIntent))
                        | (4, Some(SourceKind::CollectionIntent))
                        | (5, Some(SourceKind::LifecycleIntent))
                )
                || record.plan.binding != self.binding
                || name != luma_content::sha256(record.plan.provenance.request_id.as_bytes())
            {
                return Err("content outcome canonical identity mismatch".into());
            }
            let payload = storage::read(
                &dir,
                "payload.json",
                MAX_PAYLOAD.min(MAX_REPOSITORY_BYTES - total),
                &mut check,
            )?;
            total += payload.len() as u64;
            let source = storage::read(
                &dir,
                "source.bin",
                (match record.plan.source_kind {
                    None => luma_content::MAX_CONTENT_BYTES as u64,
                    Some(SourceKind::ManagedTableIntent | SourceKind::ManagedRenderIntent) => {
                        MAX_SOURCE
                    }
                    Some(SourceKind::CollectionIntent) => MAX_COLLECTION_SOURCE_BYTES as u64,
                    Some(SourceKind::LifecycleIntent) => MAX_RECORD,
                    Some(SourceKind::Content) => {
                        return Err("explicit legacy source kind forbidden".into())
                    }
                })
                .min(MAX_REPOSITORY_BYTES - total),
                &mut check,
            )?;
            total += source.len() as u64;
            if record.plan.payload_bytes != payload.len() as u64
                || record.plan.payload_sha256 != luma_content::sha256(&payload)
                || record.plan.source_bytes != source.len() as u64
                || record.plan.source_sha256 != luma_content::sha256(&source)
            {
                return Err(
                    "content outcome payload or exact original-source integrity mismatch".into(),
                );
            }
            if raw
                .insert(record.sequence, (record, payload, source))
                .is_some()
            {
                return Err("duplicate content outcome sequence".into());
            }
        }
        // Pending bytes remain bounded and visible but never become authority.
        for name in &pending {
            check()?;
            let dir = storage::directory(&self.pending, name)?;
            for member in storage::names(&dir, 3)? {
                let limit = match member.as_str() {
                    "record.json" => MAX_RECORD,
                    "payload.json" => MAX_PAYLOAD,
                    "source.bin" => MAX_SOURCE,
                    _ => return Err("unknown pending content member; preserve state".into()),
                };
                total += storage::read(
                    &dir,
                    &member,
                    limit.min(MAX_REPOSITORY_BYTES - total),
                    &mut check,
                )?
                .len() as u64;
            }
        }
        let mut records = Vec::new();
        let mut history = HistoryReconstruction::new();
        for (_, (record, payload, source)) in raw {
            let rebuilt = history.observe(&self.binding, &record, &payload, &source, &mut check)?;
            records.push((record, rebuilt, source));
        }
        check()?;
        let snapshot = Snapshot {
            records,
            current: history.current,
            lifecycle: history.lifecycle,
            pending,
            bytes: total,
            quarantine_sha256,
            quarantined,
        };
        state::check_expected(
            expected_state,
            &VerifiedState::from_snapshot(&self.binding, &snapshot)?,
        )?;
        Ok(snapshot)
    }

    pub fn current(&self, artifact: &str, boundary: &mut impl Boundary) -> Result<ArtifactVersion> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let mut snapshot = self.snapshot(None, boundary)?;
        snapshot.require_live(artifact)?;
        let version = snapshot
            .current
            .remove(artifact)
            .ok_or("current content artifact unavailable")?;
        storage::repository_check(self, None, boundary)?;
        Ok(version)
    }

    pub fn inventory(&self, boundary: &mut impl Boundary) -> Result<Vec<Outcome>> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let result = self
            .snapshot(None, boundary)?
            .records
            .into_iter()
            .map(|(r, _, _)| outcome(&r, false))
            .collect();
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    pub fn retained(&self, request: &str, boundary: &mut impl Boundary) -> Result<Retained> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        let (record, plan, source) = snapshot
            .records
            .iter()
            .find(|(r, _, _)| r.plan.provenance.request_id == request)
            .ok_or("retained content outcome unavailable")?;
        snapshot.require_live(plan.artifact_id())?;
        storage::repository_check(self, None, boundary)?;
        Ok(Retained {
            outcome: outcome(&record, false),
            payload: plan.payload.clone(),
            source: source.clone(),
        })
    }

    /// Recover a fully reconstructed immutable proposal for exact-input replay.
    /// The caller must also compare its operation's artifact, format, expected
    /// reference and provenance before reuse. This inspection does not restore
    /// a session, grant, resource lease, or permission to redispatch an effect.
    pub fn replay_plan(
        &self,
        request: &str,
        source: &[u8],
        boundary: &mut impl Boundary,
    ) -> Result<Option<Plan>> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        let prior = snapshot
            .records
            .iter()
            .find(|(record, _, _)| record.plan.provenance.request_id == request);
        let plan = match prior {
            Some((_, plan, prior_source)) => {
                if plan.lifecycle_request().is_none() {
                    snapshot.require_live(plan.artifact_id())?;
                }
                if prior_source != source {
                    return Err("content request replay changed exact retained input".into());
                }
                Some(plan.clone())
            }
            None => None,
        };
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }

    pub fn plan_external_edit(
        &self,
        artifact: &str,
        expected: VersionReference,
        source: &[u8],
        provenance: Provenance,
        boundary: &mut impl Boundary,
    ) -> Result<Plan> {
        let current = self.current(artifact, boundary)?;
        let plan = Plan::build(
            Some(&current),
            self.binding.clone(),
            artifact,
            current.receipt().format,
            Some(expected),
            source,
            provenance,
        )?;
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }

    /// Review positional operations against the live immutable CSV version.
    /// A stale request is retained as a conflict, never replayed on new rows.
    pub fn plan_table_edit(
        &self,
        request: &luma_content::table::TableEditRequest,
        boundary: &mut impl Boundary,
    ) -> Result<Plan> {
        if request.binding != self.binding {
            return Err("managed-table request owner mismatch".into());
        }
        let current = self.current(&request.expected.artifact_id, boundary)?;
        let plan = Plan::managed_table(&current, request)?;
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }

    pub fn plan_render(
        &self,
        request: &luma_content::rendered::Request,
        boundary: &mut impl Boundary,
    ) -> Result<Plan> {
        if request.binding != self.binding {
            return Err("managed render request owner mismatch".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        snapshot.require_live(&request.artifact_id)?;
        let plan = Plan::managed_render(snapshot.current.get(&request.artifact_id), request)?;
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }

    /// Publication requires exclusive access even inside a single process. The
    /// directory flock alone would not serialize threads sharing one handle.
    ///
    /// ```compile_fail,E0596
    /// use luma_content_store::{Boundary, Plan, Repository};
    /// fn cannot_publish_shared(repo: &Repository, plan: &Plan, b: &mut impl Boundary) {
    ///     let _ = repo.apply(plan, b"source", b);
    /// }
    /// ```
    pub fn apply(
        &mut self,
        plan: &Plan,
        source: &[u8],
        boundary: &mut impl Boundary,
    ) -> Result<Outcome> {
        self.apply_with_hook(plan, source, boundary, |_| Ok(()))
    }

    fn apply_with_hook(
        &mut self,
        plan: &Plan,
        source: &[u8],
        boundary: &mut impl Boundary,
        mut hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<Outcome> {
        let prepared = self.prepare_with_hook(plan, source, boundary, &mut hook)?;
        prepared.publish_with_hook(boundary, &mut hook)
    }

    /// Synchronize an exact immutable preparation while retaining this
    /// repository's exclusive borrow and lock. This is data, never custody
    /// authorization. Dropping the returned handle retains bytes unmodified.
    pub fn prepare<'repository>(
        &'repository mut self,
        plan: &Plan,
        source: &[u8],
        boundary: &mut impl Boundary,
    ) -> Result<PreparedPublication<'repository>> {
        self.prepare_with_hook(plan, source, boundary, |_| Ok(()))
    }

    fn prepare_with_hook<'repository>(
        &'repository mut self,
        plan: &Plan,
        source: &[u8],
        boundary: &mut impl Boundary,
        mut hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<PreparedPublication<'repository>> {
        if plan.binding() != &self.binding
            || source.len() as u64 != plan.source_bytes()
            || luma_content::sha256(source) != plan.data.source_sha256
        {
            return Err("content proposal owner or exact source changed".into());
        }
        boundary.admit(
            &self.binding,
            ResourceBudget::mutation(plan.storage_bytes()),
        )?;
        storage::repository_check(self, Some(plan), boundary)?;
        let snapshot = self.snapshot(Some(plan), boundary)?;
        if let Some((record, prior, prior_source)) = snapshot
            .records
            .iter()
            .find(|(r, _, _)| r.plan.provenance.request_id == plan.request_id())
        {
            if prior != plan || prior_source != source {
                return Err("content request replay conflicts with its immutable outcome".into());
            }
            storage::repository_check(self, Some(plan), boundary)?;
            let directory = storage::directory(
                &self.outcomes,
                &luma_content::sha256(plan.request_id().as_bytes()),
            )?;
            for name in ["record.json", "payload.json", "source.bin"] {
                storage::repository_check(self, Some(plan), boundary)?;
                storage::open(&directory, name, libc::O_RDONLY, 0)?.sync_all()?;
            }
            directory.sync_all()?;
            self.outcomes.sync_all()?;
            self.pending.sync_all()?;
            self.root.sync_all()?;
            storage::repository_check(self, Some(plan), boundary)?;
            return PreparedPublication::capture(
                self,
                plan,
                source,
                record.clone(),
                directory,
                &snapshot,
                true,
                boundary,
            );
        }
        if snapshot.records.len() == MAX_OUTCOMES {
            return Err("content outcome capacity exhausted; no automatic eviction".into());
        }
        snapshot.check_lifecycle_plan(plan)?;
        let rebuilt = Plan::rebuild(
            snapshot.current.get(&plan.data.artifact_id),
            &plan.data,
            source,
        )?;
        if &rebuilt != plan {
            return Err("content base changed since exact proposal review".into());
        }
        let mut collection_history = collections::CollectionHistory::new();
        for (_, prior, prior_source) in &snapshot.records {
            collection_history.observe(prior, prior_source, &mut || {
                storage::repository_check(self, Some(plan), boundary)
            })?;
        }
        collection_history.observe(plan, source, &mut || {
            storage::repository_check(self, Some(plan), boundary)
        })?;
        let name = luma_content::sha256(plan.request_id().as_bytes());
        if snapshot.quarantined.contains(&name) {
            return Err("content request was explicitly retired; use a fresh request ID".into());
        }
        if snapshot.pending.iter().any(|p| p != &name) {
            return Err("another content preparation requires recovery; preserve it".into());
        }
        let record = Record {
            schema_version: plan.data.schema_version,
            sequence: snapshot.records.len() as u64 + 1,
            review_sha256: plan.review.clone(),
            plan: plan.data.clone(),
        };
        let record_bytes = serde_json::to_vec(&record)?;
        if record_bytes.len() as u64 > MAX_RECORD {
            return Err("content record exceeds fixed bound".into());
        }
        let existing = if snapshot.pending.contains(&name) {
            Some(storage::directory(&self.pending, &name)?)
        } else {
            None
        };
        let members = existing
            .as_ref()
            .map(|dir| storage::names(dir, 3))
            .transpose()?
            .unwrap_or_default();
        let mut existing_bytes = 0_u64;
        for (member, bytes) in [
            ("record.json", record_bytes.as_slice()),
            ("payload.json", plan.payload.as_slice()),
            ("source.bin", source),
        ] {
            if members.iter().any(|m| m == member) {
                let mut check = || storage::repository_check(self, Some(plan), boundary);
                let prior = storage::read(
                    existing.as_ref().ok_or("missing prepared directory")?,
                    member,
                    bytes.len() as u64,
                    &mut check,
                )?;
                if prior != bytes {
                    return Err(
                        "partial or changed content preparation requires separate recovery".into(),
                    );
                }
                existing_bytes += prior.len() as u64;
            }
        }
        let additional = additional_charge(
            snapshot.bytes,
            record_bytes.len() as u64 + plan.payload.len() as u64 + source.len() as u64,
            existing_bytes,
        )?;
        storage::reserve(&self.root, additional)?;
        let mut check = || storage::repository_check(self, Some(plan), boundary);
        check()?;
        let dir = if let Some(dir) = existing {
            dir
        } else {
            storage::mkdir(&self.pending, &name)?
        };
        for (member, bytes) in [
            ("record.json", record_bytes.as_slice()),
            ("payload.json", plan.payload.as_slice()),
            ("source.bin", source),
        ] {
            check()?;
            if members.iter().any(|m| m == member) {
                if storage::read(&dir, member, bytes.len() as u64, &mut check)? != bytes {
                    return Err(
                        "partial or changed content preparation requires separate recovery".into(),
                    );
                }
            } else {
                storage::write(&dir, member, bytes, &mut check)?;
            }
            storage::open(&dir, member, libc::O_RDONLY, 0)?.sync_all()?;
            hook(Phase::MemberSynced)?;
        }
        dir.sync_all()?;
        self.pending.sync_all()?;
        hook(Phase::Prepared)?;
        check()?;
        drop(check);
        PreparedPublication::capture(self, plan, source, record, dir, &snapshot, false, boundary)
    }
}

fn hash(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn additional_charge(used: u64, planned: u64, existing: u64) -> Result<u64> {
    let additional = planned
        .checked_sub(existing)
        .ok_or("prepared content accounting overflow")?;
    if used
        .checked_add(additional)
        .ok_or("content capacity overflow")?
        > MAX_REPOSITORY_BYTES
    {
        return Err("content repository capacity exhausted".into());
    }
    Ok(additional)
}
fn lock(root: &File) -> Result<()> {
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("content repository is busy".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Phase {
    MemberSynced,
    Prepared,
    Renamed,
    Committed,
}

#[cfg(test)]
mod tests;
