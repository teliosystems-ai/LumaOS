//! Durable local-ext4 storage for bounded editable-content contracts.
//!
//! This crate does not authenticate identities, issue finite grants, acquire a
//! kernel resource lease, sign data or establish rollback-resistant authority.
//! Every caller must supply a real [`Boundary`] that enforces those independent
//! requirements continuously. There is deliberately no default implementation.
//! A repository is exclusively locked for its lifetime. Immutable outcomes are
//! committed by a no-replace directory rename, with their exact source retained.
//! Partial preparation is never erased or overwritten; an incompatible partial
//! write requires separately authorized operator recovery outside this API.
#![cfg(target_os = "linux")]

use luma_content::{
    ArtifactVersion, EditDecision, Format, OwnerBinding, Provenance, VersionReference,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

mod storage;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MAX_REPOSITORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_OUTCOMES: usize = 256;
pub const MAX_PENDING: usize = 16;
pub const MAX_DOMAINS: usize = 1024;
const MAX_RECORD: u64 = 8192;
const MAX_PAYLOAD: u64 = luma_content::MAX_ENVELOPE_BYTES as u64;

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
    pub fn binding(&self) -> &OwnerBinding {
        &self.data.binding
    }
    pub fn request_id(&self) -> &str {
        &self.data.provenance.request_id
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
    pub fn storage_bytes(&self) -> u64 {
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
    pending: Vec<String>,
    bytes: u64,
}

/// One owner-generation namespace. No cross-owner deduplication or fallback.
pub struct Repository {
    base: File,
    name: String,
    root: File,
    pending: File,
    outcomes: File,
    binding: OwnerBinding,
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
            binding: initial.binding().clone(),
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
        if storage::names(&root, 3)? != ["identity.json", "outcomes", "pending"] {
            return Err("incomplete or unknown content-store layout; preserve state".into());
        }
        let bytes = storage::read(&root, "identity.json", MAX_RECORD, &mut || {
            boundary.check(Access::Inspect { binding })
        })?;
        if bytes != serde_json::to_vec(&identity(binding))? {
            return Err("content-store identity or canonical format mismatch".into());
        }
        let result = Self {
            pending: storage::directory(&root, "pending")?,
            outcomes: storage::directory(&root, "outcomes")?,
            base,
            name,
            root,
            binding: binding.clone(),
        };
        result.snapshot(None, boundary)?;
        Ok(result)
    }

    fn snapshot(&self, plan: Option<&Plan>, boundary: &mut impl Boundary) -> Result<Snapshot> {
        let mut check = || storage::repository_check(self, plan, boundary);
        check()?;
        if storage::names(&self.root, 3)? != ["identity.json", "outcomes", "pending"] {
            return Err("content-store layout changed; preserve state".into());
        }
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
        let mut total = 0_u64;
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
                || record.schema_version != 1
                || record.plan.schema_version != 1
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
                (luma_content::MAX_CONTENT_BYTES as u64).min(MAX_REPOSITORY_BYTES - total),
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
                    "source.bin" => luma_content::MAX_CONTENT_BYTES as u64,
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
        let mut current = BTreeMap::new();
        let mut records = Vec::new();
        let mut requests = BTreeSet::new();
        for (index, (sequence, (record, payload, source))) in raw.into_iter().enumerate() {
            check()?;
            if sequence != index as u64 + 1
                || !requests.insert(record.plan.provenance.request_id.clone())
            {
                return Err("content outcome sequence or request identity discontinuity".into());
            }
            let prior = current.get(&record.plan.artifact_id);
            if prior.map(ArtifactVersion::reference).transpose()? != record.plan.observed {
                return Err("content outcome does not extend its exact observed base".into());
            }
            let rebuilt = Plan::build(
                prior,
                self.binding.clone(),
                &record.plan.artifact_id,
                record.plan.format,
                record.plan.expected.clone(),
                &source,
                record.plan.provenance.clone(),
            )?;
            if rebuilt.data != record.plan
                || rebuilt.payload != payload
                || rebuilt.review != record.review_sha256
            {
                return Err(
                    "content outcome provenance or decision cannot be reconstructed".into(),
                );
            }
            if rebuilt.decision() == DecisionKind::Published {
                current.insert(
                    record.plan.artifact_id.clone(),
                    luma_content::reopen(&payload, &self.binding)?,
                );
            }
            records.push((record, rebuilt, source));
        }
        check()?;
        Ok(Snapshot {
            records,
            current,
            pending,
            bytes: total,
        })
    }

    pub fn current(&self, artifact: &str, boundary: &mut impl Boundary) -> Result<ArtifactVersion> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let version = self
            .snapshot(None, boundary)?
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
        let (record, plan, source) = self
            .snapshot(None, boundary)?
            .records
            .into_iter()
            .find(|(r, _, _)| r.plan.provenance.request_id == request)
            .ok_or("retained content outcome unavailable")?;
        storage::repository_check(self, None, boundary)?;
        Ok(Retained {
            outcome: outcome(&record, false),
            payload: plan.payload,
            source,
        })
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
            return Ok(outcome(record, true));
        }
        if snapshot.records.len() == MAX_OUTCOMES {
            return Err("content outcome capacity exhausted; no automatic eviction".into());
        }
        let rebuilt = Plan::build(
            snapshot.current.get(&plan.data.artifact_id),
            self.binding.clone(),
            &plan.data.artifact_id,
            plan.data.format,
            plan.data.expected.clone(),
            source,
            plan.data.provenance.clone(),
        )?;
        if &rebuilt != plan {
            return Err("content base changed since exact proposal review".into());
        }
        let name = luma_content::sha256(plan.request_id().as_bytes());
        if snapshot.pending.iter().any(|p| p != &name) {
            return Err("another content preparation requires recovery; preserve it".into());
        }
        let record = Record {
            schema_version: 1,
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
        for (member, bytes) in [
            ("record.json", record_bytes.as_slice()),
            ("payload.json", plan.payload.as_slice()),
            ("source.bin", source),
        ] {
            if storage::read(&dir, member, bytes.len() as u64, &mut check)? != bytes {
                return Err("prepared content changed before atomic commit".into());
            }
        }
        check()?;
        storage::rename(&self.pending, &self.outcomes, &name, &mut check, || {
            hook(Phase::Renamed)
        })?;
        self.root.sync_all()?;
        hook(Phase::Committed)?;
        check()?;
        Ok(outcome(&record, false))
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
