//! Pure fresh-owner replay planning. No filesystem, authentication or authority.
//!
//! The exact archived history is validated before generating new proposals.
//! Only published versions are replayed. Other retained evidence stays in the
//! original archive; it is counted, never promoted, extracted or discarded.
use crate::{
    backup, collections::CollectionHistory, BackupArea, CollectionSource, DecisionKind, Plan,
    Result, SourceKind, MAX_OUTCOMES, MAX_REPOSITORY_BYTES,
};
use luma_content::{ArtifactVersion, EditOrigin, OwnerBinding, Provenance, VersionReference};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RESTORE_REVIEW_BYTES: usize = 64 * 1024;
const PROFILE: &str = "luma-fresh-owner-content-restore-v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreMapping {
    pub origin: VersionReference,
    pub target: VersionReference,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreStepReview {
    pub request_id: String,
    pub review_sha256: String,
}

/// Bounded descriptive review, never a restore permit. Full reference mappings
/// are separately available from the non-deserializable plan and committed here.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreReview {
    pub schema_version: u32,
    pub profile: String,
    pub origin: OwnerBinding,
    pub target: OwnerBinding,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub manifest_sha256: String,
    pub origin_head_sha256: String,
    pub workflow_sha256: String,
    pub request_namespace: String,
    pub published_outcomes: u64,
    pub inert_committed_outcomes: u64,
    pub inert_pending_directories: u64,
    pub inert_quarantined_directories: u64,
    pub planned_storage_bytes: u64,
    pub mappings_sha256: String,
    pub steps: Vec<RestoreStepReview>,
    pub review_sha256: String,
}

impl RestoreReview {
    /// Validate bounded descriptive DATA, not archive contents, origin custody
    /// or permission. Installed workers must independently rebuild the plan.
    pub fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        self.target.validate()?;
        let total = self
            .published_outcomes
            .checked_add(self.inert_committed_outcomes)
            .ok_or("restore outcome count overflow")?;
        if self.schema_version != 1
            || self.profile != PROFILE
            || self.origin.installation == self.target.installation
            || self.origin.owner == self.target.owner
            || !namespace(&self.request_namespace)
            || self.archive_bytes <= 20
            || self.archive_bytes > crate::MAX_CONTENT_BACKUP_BYTES as u64
            || total > MAX_OUTCOMES as u64
            || self.published_outcomes != self.steps.len() as u64
            || self.inert_pending_directories > crate::MAX_PENDING as u64
            || self.inert_quarantined_directories > crate::MAX_QUARANTINED_PREPARATIONS as u64
            || self.planned_storage_bytes > MAX_REPOSITORY_BYTES
            || (self.published_outcomes == 0 && self.planned_storage_bytes != 0)
            || self.planned_storage_bytes < self.published_outcomes * crate::MAX_RECORD
        {
            return Err("restore review identity or bounded counts differ".into());
        }
        for pin in [
            &self.archive_sha256,
            &self.manifest_sha256,
            &self.origin_head_sha256,
            &self.workflow_sha256,
            &self.mappings_sha256,
            &self.review_sha256,
        ] {
            if !digest(pin) {
                return Err("restore review requires exact nonzero digests".into());
            }
        }
        let prefix = format!("{}.", self.request_namespace);
        let mut previous = 0_u64;
        for step in &self.steps {
            let suffix = step
                .request_id
                .strip_prefix(&prefix)
                .ok_or("restore step belongs to another request namespace")?;
            let sequence: u64 = suffix.parse()?;
            if sequence <= previous
                || sequence > total
                || suffix != sequence.to_string()
                || !digest(&step.review_sha256)
            {
                return Err("restore step identity, order or review digest differs".into());
            }
            previous = sequence;
        }
        if serde_json::to_vec(self)?.len() > MAX_RESTORE_REVIEW_BYTES {
            return Err("fresh-owner restore review exceeds fixed bound".into());
        }
        let mut unsigned = self.clone();
        unsigned.review_sha256.clear();
        if luma_content::sha256(&serde_json::to_vec(&unsigned)?) != self.review_sha256 {
            return Err("restore review commitment differs".into());
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        self.review_sha256.clear();
        self.review_sha256 = luma_content::sha256(&serde_json::to_vec(self)?);
        self.validate()
    }
}

struct Step<'a> {
    plan: Plan,
    source: Cow<'a, [u8]>,
}

/// In-memory validated replay proposals borrowing the supplied archive. This
/// token deliberately has no Clone/Deserialize/Serialize implementation. A
/// caller must separately retain encrypted evidence and enforce current Admin,
/// target-owner, finite grant, resource and independent custody boundaries.
pub struct RestorePlan<'a> {
    review: RestoreReview,
    mappings: Vec<RestoreMapping>,
    steps: Vec<Step<'a>>,
}

impl RestorePlan<'_> {
    pub fn review(&self) -> &RestoreReview {
        &self.review
    }
    pub fn mappings(&self) -> &[RestoreMapping] {
        &self.mappings
    }
    pub fn steps(&self) -> impl ExactSizeIterator<Item = (&Plan, &[u8])> {
        self.steps.iter().map(|s| (&s.plan, s.source.as_ref()))
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && value.bytes().any(|c| c != b'0')
}

fn namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn mapped(reference: &VersionReference, mappings: &[RestoreMapping]) -> Result<VersionReference> {
    mappings
        .iter()
        .find(|m| &m.origin == reference)
        .map(|m| m.target.clone())
        .ok_or_else(|| "restore reference is not an earlier published exact version".into())
}

/// Fully validate archived DATA, then replay every published historical version
/// chronologically under genuinely fresh installation and owner identifiers.
/// Generated plans remain DATA, not permission to publish or restore ownership.
pub fn plan_restore_data_checked<'a>(
    archive: &'a [u8],
    target: &OwnerBinding,
    request_namespace: &str,
    restore_graph_sha: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<RestorePlan<'a>> {
    check()?;
    target.validate()?;
    if !namespace(request_namespace) || !digest(restore_graph_sha) {
        return Err("invalid fresh restore request namespace or workflow digest".into());
    }
    let (inspection, outcomes) = backup::inspect_parts(archive, check)?;
    let origin = &inspection.manifest.binding;
    if target.installation == origin.installation || target.owner == origin.owner {
        return Err(
            "restore requires independently provisioned fresh installation and owner".into(),
        );
    }
    let mut current: BTreeMap<String, ArtifactVersion> = BTreeMap::new();
    let mut history = CollectionHistory::new();
    let mut mappings = Vec::new();
    let mut steps = Vec::new();
    let mut storage = 0_u64;
    let mut inert = 0_u64;
    let archived_requests: BTreeSet<_> = outcomes
        .iter()
        .map(|o| o.record.plan.provenance.request_id.clone())
        .collect();
    for outcome in outcomes {
        check()?;
        let old = &outcome.record.plan;
        if old.decision != DecisionKind::Published {
            inert += 1;
            continue;
        }
        if steps.len() >= MAX_OUTCOMES {
            return Err("restore publication count exceeds repository bound".into());
        }
        let request_id = format!("{request_namespace}.{}", outcome.record.sequence);
        if archived_requests.contains(&request_id) {
            return Err("restore cannot reuse an archived request identity".into());
        }
        let existing = current.get(&old.artifact_id);
        let expected = old
            .expected
            .as_ref()
            .map(|r| mapped(r, &mappings))
            .transpose()?;
        let provenance = |source: &[u8]| Provenance {
            request_id: request_id.clone(),
            workflow_sha256: restore_graph_sha.into(),
            source_sha256: luma_content::sha256(source),
            origin: EditOrigin::External,
        };
        let (plan, source) = match old.source_kind.unwrap_or(SourceKind::Content) {
            SourceKind::Content => (
                Plan::build(
                    existing,
                    target.clone(),
                    &old.artifact_id,
                    old.format,
                    expected,
                    outcome.source,
                    provenance(outcome.source),
                )?,
                Cow::Borrowed(outcome.source),
            ),
            SourceKind::ManagedTableIntent => {
                let mut request: luma_content::table::TableEditRequest =
                    serde_json::from_slice(outcome.source)?;
                request.binding = target.clone();
                request.expected = mapped(&request.expected, &mappings)?;
                request.metadata.request_id = request_id.clone();
                request.metadata.workflow_sha256 = restore_graph_sha.into();
                let source = request.canonical_bytes()?;
                let plan =
                    Plan::managed_table(existing.ok_or("restore table base missing")?, &request)?;
                (plan, Cow::Owned(source))
            }
            SourceKind::ManagedRenderIntent => {
                let mut request: luma_content::rendered::Request =
                    serde_json::from_slice(outcome.source)?;
                request.binding = target.clone();
                request.expected = expected;
                request.metadata.request_id = request_id.clone();
                request.metadata.workflow_sha256 = restore_graph_sha.into();
                let source = request.canonical_bytes()?;
                (
                    Plan::managed_render(existing, &request)?,
                    Cow::Owned(source),
                )
            }
            SourceKind::CollectionIntent => {
                let mut collection = CollectionSource::from_canonical(outcome.source)?;
                collection.members = collection
                    .members
                    .iter()
                    .map(|r| mapped(r, &mappings))
                    .collect::<Result<Vec<_>>>()?;
                let source = collection.canonical_bytes()?;
                let plan = Plan::collection(
                    existing,
                    target.clone(),
                    &collection,
                    expected,
                    provenance(&source),
                )?;
                (plan, Cow::Owned(source))
            }
        };
        check()?;
        let rebuilt = luma_content::reopen(&plan.payload, target)?;
        let archived = luma_content::reopen(outcome.payload, origin)?;
        if plan.decision() != DecisionKind::Published
            || plan.resulting().artifact_id != old.resulting.artifact_id
            || plan.resulting().version != old.resulting.version
            || (plan.source_kind() != SourceKind::CollectionIntent
                && rebuilt.content() != archived.content())
        {
            return Err("restore replay changed published version semantics".into());
        }
        history.observe(&plan, source.as_ref(), check)?;
        storage = storage
            .checked_add(plan.storage_bytes())
            .ok_or("restore storage overflow")?;
        if storage > MAX_REPOSITORY_BYTES {
            return Err("fresh restore would exceed bounded target repository storage".into());
        }
        mappings.push(RestoreMapping {
            origin: old.resulting.clone(),
            target: plan.resulting().clone(),
        });
        current.insert(plan.artifact_id().into(), rebuilt);
        steps.push(Step { plan, source });
    }
    if steps.is_empty() {
        return Err("backup contains no published content to restore".into());
    }
    let count_area = |area| {
        inspection
            .manifest
            .directories
            .iter()
            .filter(|d| d.area == area)
            .count() as u64
    };
    let mut review = RestoreReview {
        schema_version: 1,
        profile: PROFILE.into(),
        origin: origin.clone(),
        target: target.clone(),
        archive_sha256: inspection.archive_sha256,
        archive_bytes: inspection.archive_bytes,
        manifest_sha256: inspection.manifest_sha256,
        origin_head_sha256: inspection.manifest.committed_head_sha256.clone(),
        workflow_sha256: restore_graph_sha.into(),
        request_namespace: request_namespace.into(),
        published_outcomes: steps.len() as u64,
        inert_committed_outcomes: inert,
        inert_pending_directories: count_area(BackupArea::Pending),
        inert_quarantined_directories: count_area(BackupArea::Quarantined),
        planned_storage_bytes: storage,
        mappings_sha256: luma_content::sha256(&serde_json::to_vec(&mappings)?),
        steps: steps
            .iter()
            .map(|s| RestoreStepReview {
                request_id: s.plan.request_id().into(),
                review_sha256: s.plan.review_sha256().into(),
            })
            .collect(),
        review_sha256: String::new(),
    };
    review.finish()?;
    check()?;
    Ok(RestorePlan {
        review,
        mappings,
        steps,
    })
}
