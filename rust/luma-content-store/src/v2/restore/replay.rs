//! One chronological source outcome per fresh original Standard window. This
//! code derives real target OwnerPlans and bounded auxiliary-map CAS changes;
//! neither the proposal nor its eventual prepared objects select a C head.
use super::super::lifecycle::LifecycleState;
use super::*;
use crate::{LifecycleStatus, SourceKind, VersionReference};
use luma_content::{EditOrigin, Provenance};
#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;

pub trait ReplayBoundary: RestoreBoundary {
    fn verify_job_namespace(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        store: &ObjectStore,
    ) -> Result<()>;
    fn verify_prepared_replay(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        review: &RestoreWindowReview,
        commitment: &PreparedReplayCommitment,
        job_store: &ObjectStore,
    ) -> Result<()>;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Mapping {
    origin: VersionReference,
    target: VersionReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceState {
    state: LifecycleState,
    collection: bool,
    final_match: bool,
}
/// Finite original-window work declaration, not a lease or permission. The
/// source/job multipliers cover this implementation's sequential guarded read
/// passes; the target ceiling covers one real plan/prepare/reconstruction lane.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayBudget {
    pub source_read_bytes: u64,
    pub job_read_bytes: u64,
    pub job_write_bytes: u64,
    pub job_new_files: u32,
    pub target_read_bytes: u64,
    pub target_write_bytes: u64,
    pub target_new_files: u32,
}
impl ReplayBudget {
    pub fn validate(&self) -> Result<()> {
        self.source().validate()?;
        self.job().validate()?;
        self.target().validate()?;
        let read = self
            .source_read_bytes
            .checked_mul(2)
            .and_then(|n| {
                self.job_read_bytes
                    .checked_mul(3)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(self.target_read_bytes))
            .ok_or("restore replay aggregate read overflow")?;
        if self.source_read_bytes > 64 * 1024 * 1024
            || self.job_read_bytes > 64 * 1024 * 1024
            || self.job_write_bytes == 0
            || self.job_write_bytes > 16 * 1024 * 1024
            || self.job_new_files == 0
            || self.job_new_files > 2048
            || self.target_write_bytes > 64 * 1024 * 1024
            || self.target_read_bytes != 512 * 1024 * 1024
            || self.target_new_files > 8192
            || read > 1024 * 1024 * 1024
        {
            return Err("restore replay exceeds reviewed finite one-outcome work profile".into());
        }
        Ok(())
    }
    fn source(&self) -> IoBudget {
        IoBudget {
            read_bytes: self.source_read_bytes,
            write_bytes: 0,
            new_files: 0,
        }
    }
    fn job(&self) -> IoBudget {
        IoBudget {
            read_bytes: self.job_read_bytes,
            write_bytes: self.job_write_bytes,
            new_files: self.job_new_files,
        }
    }
    fn job_read(&self) -> IoBudget {
        IoBudget {
            read_bytes: self.job_read_bytes,
            write_bytes: 0,
            new_files: 0,
        }
    }
    fn target(&self) -> IoBudget {
        IoBudget {
            read_bytes: self.target_read_bytes,
            write_bytes: self.target_write_bytes,
            new_files: self.target_new_files,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayProposal {
    pub schema_version: u32,
    pub prefix_sha256: String,
    pub source_ordinal: u64,
    pub source_record_sha256: String,
    pub workflow_sha256: String,
    pub target_plan_sha256: Option<String>,
    pub mappings: MapRoot,
    pub source_lifecycle: MapRoot,
    pub published_versions: u64,
    pub lifecycle_outcomes: u64,
    pub inert_outcomes: u64,
    pub verified_final_artifacts: u64,
    pub reservations: RestoreReservations,
    pub budget: ReplayBudget,
}
impl ReplayProposal {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        digest(&self.prefix_sha256)?;
        digest(&self.source_record_sha256)?;
        digest(&self.workflow_sha256)?;
        if let Some(value) = &self.target_plan_sha256 {
            digest(value)?;
        }
        self.mappings.validate()?;
        self.source_lifecycle.validate()?;
        self.reservations.validate(false)?;
        self.budget.validate()?;
        if self.schema_version != 1
            || self.source_ordinal == 0
            || self.source_ordinal > MAX_MAP_ENTRIES
            || self.mappings.kind != MapKind::RestoreMappings
            || self.source_lifecycle.kind != MapKind::RestoreSourceLifecycle
            || self.mappings.binding != self.source_lifecycle.binding
        {
            return Err("invalid closed restore replay proposal".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("restore replay proposal exceeds one page".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}
pub struct ReplayPlan {
    review: RestoreWindowReview,
    proposal: ReplayProposal,
    target_plan: Option<OwnerPlan>,
    mapping_edit: Vec<MapEdit>,
    state_edit: Vec<MapEdit>,
}
impl ReplayPlan {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
    pub fn proposal(&self) -> &ReplayProposal {
        &self.proposal
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedReplayCommitment {
    pub review_sha256: String,
    pub proposal: ReplayProposal,
    pub target_append: Option<AppendCommitment>,
    pub newly_allocated_job: PhysicalInventory,
    pub next: RestorePrefix,
}
pub struct PreparedReplay<'a> {
    job: &'a ObjectStore,
    _job_writer: std::fs::File,
    target: Option<PreparedOwnerAppend<'a>>,
    review: RestoreWindowReview,
    commitment: PreparedReplayCommitment,
}
impl PreparedReplay<'_> {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
    pub fn commitment(&self) -> &PreparedReplayCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected(
        self,
        manifest: &WholeSnapshotManifest,
        b: &mut impl ReplayBoundary,
    ) -> Result<RestorePrefix> {
        live(manifest, &self.commitment.next, None, b)?;
        b.verify_job_namespace(manifest, &self.commitment.next, self.job)?;
        b.retain_original_ciphertext(manifest, manifest.part_count)?;
        if let Some(target) = self.target {
            if target.acknowledge_selected(b)? != self.commitment.next.target {
                return Err("C selected a different restored target head".into());
            }
        }
        Ok(self.commitment.next)
    }
}
struct Job<'a, B: ReplayBoundary> {
    b: &'a mut B,
    manifest: &'a WholeSnapshotManifest,
    prefix: &'a RestorePrefix,
    store: &'a ObjectStore,
    review: Option<&'a RestoreWindowReview>,
}
impl<B: ReplayBoundary> Boundary for Job<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.check_live()?;
        if binding != &self.prefix.target.binding {
            return Err("restore auxiliary job retargets target binding".into());
        }
        self.b.admit(binding, budget)?;
        self.check_live()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.check_live()?;
        self.b.check(access)?;
        self.check_live()
    }
}
impl<B: ReplayBoundary> Job<'_, B> {
    fn check_live(&mut self) -> Result<()> {
        live(self.manifest, self.prefix, self.review, self.b)?;
        self.b
            .verify_job_namespace(self.manifest, self.prefix, self.store)
    }
}
fn state_key(root: &MapRoot, job: &str, artifact: &str) -> Result<String> {
    identifier(artifact)?;
    root.key(&serde_json::to_vec(&(job, artifact))?)
}
fn mapping_key(root: &MapRoot, job: &str, reference: &VersionReference) -> Result<String> {
    crate::collections::reference(reference)?;
    root.key(&serde_json::to_vec(&(job, reference))?)
}
fn read_state<B: Boundary>(
    store: &ObjectStore,
    root: &MapRoot,
    job: &str,
    artifact: &str,
    g: &mut Guard<'_, B>,
) -> Result<Option<(SourceState, Vec<u8>)>> {
    store
        .get_map(root, &state_key(root, job, artifact)?, g)?
        .map(|bytes| {
            let value: SourceState = canonical(&bytes, MAX_VALUE_BYTES)?;
            value.state.validate()?;
            if value.state.version.artifact_id != artifact {
                return Err("restore source-state map retargets artifact".into());
            }
            Ok((value, bytes))
        })
        .transpose()
}
fn mapped<B: Boundary>(
    store: &ObjectStore,
    root: &MapRoot,
    job: &str,
    reference: &VersionReference,
    g: &mut Guard<'_, B>,
) -> Result<VersionReference> {
    let bytes = store
        .get_map(root, &mapping_key(root, job, reference)?, g)?
        .ok_or("restore dependency has not been genuinely published in an earlier window")?;
    let value: Mapping = canonical(&bytes, MAX_VALUE_BYTES)?;
    crate::collections::reference(&value.target)?;
    if value.origin != *reference
        || value.origin.artifact_id != value.target.artifact_id
        || value.origin.version != value.target.version
    {
        return Err("restore mapping changes artifact/version identity".into());
    }
    Ok(value.target)
}
fn ro(budget: IoBudget) -> Result<()> {
    budget.validate()?;
    if budget.write_bytes != 0 || budget.new_files != 0 {
        return Err("restore planning cannot admit writes".into());
    }
    Ok(())
}

pub fn plan_replay_outcome<B: ReplayBoundary>(
    origin: &ObjectStore,
    job: &ObjectStore,
    target: &OwnerRepository<'_>,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    workflow_sha256: &str,
    reservations: RestoreReservations,
    budget: ReplayBudget,
    b: &mut B,
) -> Result<ReplayPlan> {
    budget.validate()?;
    let source_budget = budget.source();
    let job_budget = budget.job_read();
    live(manifest, prefix, None, b)?;
    digest(workflow_sha256)?;
    ro(source_budget)?;
    ro(job_budget)?;
    reservations.validate(false)?;
    if prefix.stage != RestoreStage::Replaying
        || prefix.next_source_ordinal > manifest.intent.head.history.outcomes
        || target.head() != &prefix.target
    {
        return Err("restore replay does not extend exact current source/target cut".into());
    }
    b.verify_origin_namespace(manifest, prefix, origin)?;
    b.verify_job_namespace(manifest, prefix, job)?;
    let outcome = read_snapshot_outcome(
        origin,
        manifest,
        prefix,
        prefix.next_source_ordinal,
        source_budget,
        b,
    )?;
    let record: crate::Record = canonical(&outcome.record, crate::MAX_RECORD as usize)?;
    let data = &record.plan;
    let mut jb = Job {
        b,
        manifest,
        prefix,
        store: job,
        review: None,
    };
    let mut jg = Guard::new(&mut jb, &prefix.target.binding, job_budget, None)?;
    let before = read_state(
        job,
        &prefix.source_lifecycle,
        &prefix.job_sha256,
        &data.artifact_id,
        &mut jg,
    )?;
    if before.as_ref().map(|(s, _)| &s.state.version) != data.observed.as_ref() {
        return Err("archived observation does not extend chronological source state".into());
    }
    if data.source_kind != Some(SourceKind::LifecycleIntent)
        && before
            .as_ref()
            .is_some_and(|(s, _)| s.state.status == LifecycleStatus::Trashed)
    {
        return Err("archived content overwrites a trashed identity".into());
    }
    let mut sb = read::source_boundary(manifest, prefix, None, jg.boundary.b);
    let mut sg = Guard::new(&mut sb, &manifest.intent.head.binding, source_budget, None)?;
    let current = data
        .observed
        .as_ref()
        .map(|reference| {
            origin
                .historical_value(&manifest.intent.head, reference, &mut sg)
                .and_then(|value| origin.version(&value, &mut sg))
        })
        .transpose()?;
    if data.source_kind == Some(SourceKind::CollectionIntent) {
        if before.as_ref().is_some_and(|(s, _)| !s.collection) {
            return Err("archived collection collides with generic identity".into());
        }
        let collection = crate::CollectionSource::from_canonical(&outcome.source)?;
        for member in &collection.members {
            sg.check()?;
            origin.historical_value(&manifest.intent.head, member, &mut sg)?;
        }
    } else if data.source_kind != Some(SourceKind::LifecycleIntent)
        && before.as_ref().is_some_and(|(s, _)| s.collection)
    {
        return Err("archived generic content overwrites typed collection".into());
    }
    let rebuilt = if record.schema_version == 6 {
        super::super::lifecycle::rebuild(
            current
                .as_ref()
                .ok_or("archived lifecycle payload absent")?,
            &before
                .as_ref()
                .ok_or("archived lifecycle state absent")?
                .0
                .state,
            data,
            &outcome.source,
        )?
    } else {
        if data.lifecycle.as_ref().is_some_and(|t| {
            before.as_ref().map(|(s, _)| s.state.wire()) != Some(t.observed.clone())
        }) {
            return Err(
                "archived legacy lifecycle revision differs from chronological source state".into(),
            );
        }
        crate::Plan::rebuild(current.as_ref(), data, &outcome.source)?
    };
    if rebuilt.data != *data
        || rebuilt.payload != outcome.payload
        || rebuilt.review != record.review_sha256
    {
        return Err("archived outcome fails genuine engine reconstruction".into());
    }
    let request_id = format!("{}.{}", prefix.request_namespace, record.sequence);
    identifier(&request_id)?;
    if origin
        .get_map(
            &manifest.intent.head.roots.requests,
            &manifest
                .intent
                .head
                .roots
                .requests
                .key(request_id.as_bytes())?,
            &mut sg,
        )?
        .is_some()
    {
        return Err("restore request identity reuses archived request".into());
    }
    let meaningful = matches!(
        data.decision,
        DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
    );
    let mut next_state = before.as_ref().map(|(s, _)| s.clone());
    if meaningful {
        let status = if data.decision == DecisionKind::Trashed {
            LifecycleStatus::Trashed
        } else {
            LifecycleStatus::Live
        };
        let legacy = manifest
            .intent
            .head
            .migration
            .as_ref()
            .is_some_and(|m| record.sequence <= m.legacy.outcome_count);
        let state =
            LifecycleState::advance(&manifest.intent.head.binding, &record, status, legacy)?;
        let (final_value, final_state) =
            origin.current_value(&manifest.intent.head, &data.artifact_id, &mut sg)?;
        let collection = if data.decision == DecisionKind::Published {
            data.source_kind == Some(SourceKind::CollectionIntent)
        } else {
            before
                .as_ref()
                .ok_or("lifecycle source type absent")?
                .0
                .collection
        };
        next_state = Some(SourceState {
            final_match: state == final_state && final_value.collection == collection,
            state,
            collection,
        });
    }
    sg.check()?;
    drop(sg);
    drop(sb);
    // The source and job guards are intentionally sequential; neither derives
    // a local current-owner observation for the foreign archived installation.
    let expected = if meaningful {
        data.expected
            .as_ref()
            .map(|reference| {
                mapped(
                    job,
                    &prefix.mappings,
                    &prefix.job_sha256,
                    reference,
                    &mut jg,
                )
            })
            .transpose()?
    } else {
        None
    };
    if data.source_kind == Some(SourceKind::CollectionIntent) {
        let collection = crate::CollectionSource::from_canonical(&outcome.source)?;
        for member in &collection.members {
            mapped(job, &prefix.mappings, &prefix.job_sha256, member, &mut jg)?;
            if read_state(
                job,
                &prefix.source_lifecycle,
                &prefix.job_sha256,
                &member.artifact_id,
                &mut jg,
            )?
            .map_or(true, |(s, _)| s.state.status != LifecycleStatus::Live)
            {
                return Err(
                    "archived collection dependency was not live at its chronological window"
                        .into(),
                );
            }
        }
    }
    jg.check()?;
    drop(jg);
    drop(jb);
    let provenance = |source: &[u8]| Provenance {
        request_id: request_id.clone(),
        workflow_sha256: workflow_sha256.into(),
        source_sha256: luma_content::sha256(source),
        origin: EditOrigin::External,
    };
    let target_plan = if !meaningful {
        None
    } else {
        Some(match data.source_kind.unwrap_or(SourceKind::Content) {
            SourceKind::Content => match expected {
                Some(expected) => target.plan_external_edit(
                    &data.artifact_id,
                    expected,
                    &outcome.source,
                    provenance(&outcome.source),
                    b,
                )?,
                None => target.plan_capture(
                    &data.artifact_id,
                    data.format,
                    &outcome.source,
                    provenance(&outcome.source),
                    b,
                )?,
            },
            SourceKind::ManagedTableIntent => {
                let mut request: luma_content::table::TableEditRequest =
                    serde_json::from_slice(&outcome.source)?;
                request.binding = prefix.target.binding.clone();
                request.expected = expected.ok_or("restored table expected mapping missing")?;
                request.metadata.request_id = request_id.clone();
                request.metadata.workflow_sha256 = workflow_sha256.into();
                target.plan_managed_table(&request, b)?
            }
            SourceKind::ManagedRenderIntent => {
                let mut request: luma_content::rendered::Request =
                    serde_json::from_slice(&outcome.source)?;
                request.binding = prefix.target.binding.clone();
                request.expected = expected;
                request.metadata.request_id = request_id.clone();
                request.metadata.workflow_sha256 = workflow_sha256.into();
                target.plan_managed_render(&request, b)?
            }
            SourceKind::CollectionIntent => {
                let mut collection = crate::CollectionSource::from_canonical(&outcome.source)?;
                let mut job_boundary = Job {
                    b,
                    manifest,
                    prefix,
                    store: job,
                    review: None,
                };
                let mut guard =
                    Guard::new(&mut job_boundary, &prefix.target.binding, job_budget, None)?;
                collection.members = collection
                    .members
                    .iter()
                    .map(|r| mapped(job, &prefix.mappings, &prefix.job_sha256, r, &mut guard))
                    .collect::<Result<Vec<_>>>()?;
                guard.check()?;
                drop(guard);
                drop(job_boundary);
                let source = collection.canonical_bytes()?;
                target.plan_collection(&collection, expected, provenance(&source), b)?
            }
            SourceKind::LifecycleIntent => {
                let old_request = data
                    .lifecycle
                    .as_ref()
                    .ok_or("archived lifecycle request missing")?;
                let request = super::super::lifecycle::LifecycleRequestV2 {
                    schema_version: 2,
                    binding: prefix.target.binding.clone(),
                    request_id: request_id.clone(),
                    workflow_sha256: workflow_sha256.into(),
                    expected: target.lifecycle_status(&data.artifact_id, b)?,
                    operation: old_request.request.operation,
                    retention: old_request.request.retention,
                };
                target.plan_lifecycle(&request, b)?
            }
        })
    };
    if let Some(plan) = &target_plan {
        if plan.decision() != data.decision
            || plan.resulting().artifact_id != data.resulting.artifact_id
            || plan.resulting().version != data.resulting.version
        {
            return Err(
                "restored engine changes archived publication/visibility/version semantics".into(),
            );
        }
        if data.source_kind != Some(SourceKind::CollectionIntent) {
            let version = luma_content::reopen(&plan.payload, &prefix.target.binding)?;
            let old = luma_content::reopen(&outcome.payload, &manifest.intent.head.binding)?;
            if version.content() != old.content() {
                return Err("restored artifact content differs from archived engine output".into());
            }
        }
    }
    let mut jb = Job {
        b,
        manifest,
        prefix,
        store: job,
        review: None,
    };
    let mut jg = Guard::new(&mut jb, &prefix.target.binding, job_budget, None)?;
    let mut mapping_edit = Vec::new();
    let mut state_edit = Vec::new();
    if data.decision == DecisionKind::Published {
        let mapping = Mapping {
            origin: data.resulting.clone(),
            target: target_plan
                .as_ref()
                .ok_or("published replay lacks actual target plan")?
                .resulting()
                .clone(),
        };
        let key = mapping_key(&prefix.mappings, &prefix.job_sha256, &mapping.origin)?;
        if job.get_map(&prefix.mappings, &key, &mut jg)?.is_some() {
            return Err("restore mapping attempts to reuse prior publication".into());
        }
        let bytes = serde_json::to_vec(&mapping)?;
        if bytes.len() > MAX_VALUE_BYTES {
            return Err("restore mapping exceeds bounded map value".into());
        }
        mapping_edit.push(MapEdit {
            key,
            expected_value_sha256: None,
            value: Some(bytes),
        });
    }
    if meaningful {
        let bytes = serde_json::to_vec(
            next_state
                .as_ref()
                .ok_or("source state missing after meaningful replay")?,
        )?;
        if bytes.len() > MAX_VALUE_BYTES {
            return Err("restore chronological state exceeds bounded map value".into());
        }
        state_edit.push(MapEdit {
            key: state_key(
                &prefix.source_lifecycle,
                &prefix.job_sha256,
                &data.artifact_id,
            )?,
            expected_value_sha256: before
                .as_ref()
                .map(|(_, bytes)| luma_content::sha256(bytes)),
            value: Some(bytes),
        });
    }
    let mappings = if mapping_edit.is_empty() {
        prefix.mappings.clone()
    } else {
        job.preview_map_inner(&prefix.mappings, &mapping_edit, &mut jg)?
    };
    let source_lifecycle = if state_edit.is_empty() {
        prefix.source_lifecycle.clone()
    } else {
        job.preview_map_inner(&prefix.source_lifecycle, &state_edit, &mut jg)?
    };
    jg.check()?;
    drop(jg);
    drop(jb);
    let verified_final_artifacts = prefix
        .verified_final_artifacts
        .checked_sub(u64::from(
            before.as_ref().is_some_and(|(s, _)| s.final_match),
        ))
        .and_then(|n| {
            n.checked_add(u64::from(
                next_state.as_ref().is_some_and(|s| s.final_match),
            ))
        })
        .ok_or("restore final coverage counter overflow")?;
    let proposal = ReplayProposal {
        schema_version: 1,
        prefix_sha256: prefix.sha256(manifest)?,
        source_ordinal: record.sequence,
        source_record_sha256: luma_content::sha256(&outcome.record),
        workflow_sha256: workflow_sha256.into(),
        target_plan_sha256: target_plan.as_ref().map(|p| p.review_sha256().into()),
        mappings,
        source_lifecycle,
        published_versions: prefix.published_versions
            + u64::from(data.decision == DecisionKind::Published),
        lifecycle_outcomes: prefix.lifecycle_outcomes
            + u64::from(matches!(
                data.decision,
                DecisionKind::Trashed | DecisionKind::Restored
            )),
        inert_outcomes: prefix.inert_outcomes + u64::from(!meaningful),
        verified_final_artifacts,
        reservations,
        budget,
    };
    let mut review = RestoreWindowReview {
        schema_version: 1,
        profile: RESTORE_PROFILE.into(),
        kind: RestoreWindowKind::ReplayOutcome,
        job_sha256: prefix.job_sha256.clone(),
        manifest_sha256: manifest.sha256()?,
        prefix_sha256: prefix.sha256(manifest)?,
        target_head_sha256: prefix.target.sha256()?,
        proposed_data_sha256: proposal.sha256()?,
        source_ordinal: Some(record.sequence),
        part: None,
        source_record_sha256: Some(proposal.source_record_sha256.clone()),
        target_plan_sha256: proposal.target_plan_sha256.clone(),
        review_sha256: String::new(),
    };
    review.finish(manifest, prefix)?;
    live(manifest, prefix, Some(&review), b)?;
    Ok(ReplayPlan {
        review,
        proposal,
        target_plan,
        mapping_edit,
        state_edit,
    })
}

pub fn prepare_replay<'a, B: ReplayBoundary>(
    job: &'a ObjectStore,
    target: &OwnerRepository<'a>,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    plan: ReplayPlan,
    b: &mut B,
) -> Result<PreparedReplay<'a>> {
    plan.proposal.budget.validate()?;
    let job_budget = plan.proposal.budget.job();
    let target_budget = plan.proposal.budget.target();
    plan.review.validate(manifest, prefix)?;
    live(manifest, prefix, Some(&plan.review), b)?;
    if plan.proposal.sha256()? != plan.review.proposed_data_sha256
        || target.head() != &prefix.target
    {
        return Err("restore replay proposal or current target changed".into());
    }
    b.verify_job_namespace(manifest, prefix, job)?;
    let job_writer = job.acquire_writer()?;
    let target_append = plan
        .target_plan
        .as_ref()
        .map(|p| target.prepare_append(p, target_budget, b))
        .transpose()?;
    let next_target = target_append
        .as_ref()
        .map(|p| p.commitment().next.clone())
        .unwrap_or_else(|| prefix.target.clone());
    let mutation = Mutation {
        review_sha256: plan.review.review_sha256.clone(),
        decision: plan
            .target_plan
            .as_ref()
            .map(|p| p.decision())
            .unwrap_or(DecisionKind::NoChangeRetained),
        source_bytes: 0,
    };
    let mut jb = Job {
        b,
        manifest,
        prefix,
        store: job,
        review: Some(&plan.review),
    };
    let mut jg = Guard::new(&mut jb, &prefix.target.binding, job_budget, Some(&mutation))?;
    let mappings = if plan.mapping_edit.is_empty() {
        prefix.mappings.clone()
    } else {
        job.edit_map(&prefix.mappings, &plan.mapping_edit, &mut jg)?
    };
    let source_lifecycle = if plan.state_edit.is_empty() {
        prefix.source_lifecycle.clone()
    } else {
        job.edit_map(&prefix.source_lifecycle, &plan.state_edit, &mut jg)?
    };
    if mappings != plan.proposal.mappings || source_lifecycle != plan.proposal.source_lifecycle {
        return Err("prepared restore maps differ from reviewed logical proposal".into());
    }
    jg.check()?;
    let newly_allocated_job = jg.allocations.clone();
    drop(jg);
    drop(jb);
    let mut next = prefix.clone();
    next.target = next_target;
    next.next_source_ordinal = prefix
        .next_source_ordinal
        .checked_add(1)
        .ok_or("restore chronological ordinal overflow")?;
    next.mappings = mappings;
    next.source_lifecycle = source_lifecycle;
    next.published_versions = plan.proposal.published_versions;
    next.lifecycle_outcomes = plan.proposal.lifecycle_outcomes;
    next.inert_outcomes = plan.proposal.inert_outcomes;
    next.verified_final_artifacts = plan.proposal.verified_final_artifacts;
    next.reservations = plan.proposal.reservations.clone();
    next.validate(manifest)?;
    let commitment = PreparedReplayCommitment {
        review_sha256: plan.review.review_sha256.clone(),
        proposal: plan.proposal,
        target_append: target_append.as_ref().map(|p| p.commitment().clone()),
        newly_allocated_job,
        next,
    };
    b.verify_prepared_replay(manifest, prefix, &plan.review, &commitment, job)?;
    live(manifest, prefix, Some(&plan.review), b)?;
    Ok(PreparedReplay {
        job,
        _job_writer: job_writer,
        target: target_append,
        review: plan.review,
        commitment,
    })
}

/// Independently rebuild the source engine, target proposal, immutable target
/// append and both exact auxiliary-map CAS paths from the still-current cut.
/// This returns unselected DATA only. The boundary's prepared-replay method
/// must observe physical creations/reservations, not call this function again.
pub fn verify_prepared_replay_data<B: ReplayBoundary>(
    origin: &ObjectStore,
    job: &ObjectStore,
    target: &OwnerRepository<'_>,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    review: &RestoreWindowReview,
    commitment: &PreparedReplayCommitment,
    expected_workflow_sha256: &str,
    b: &mut B,
) -> Result<RestorePrefix> {
    live(manifest, prefix, Some(review), b)?;
    review.validate(manifest, prefix)?;
    commitment.next.validate(manifest)?;
    if commitment.review_sha256 != review.review_sha256
        || commitment.proposal.sha256()? != review.proposed_data_sha256
        || commitment.proposal.workflow_sha256 != expected_workflow_sha256
    {
        return Err("prepared replay differs from independently selected workflow/review".into());
    }
    b.verify_prepared_replay(manifest, prefix, review, commitment, job)?;
    let plan = plan_replay_outcome(
        origin,
        job,
        target,
        manifest,
        prefix,
        expected_workflow_sha256,
        commitment.proposal.reservations.clone(),
        commitment.proposal.budget,
        b,
    )?;
    if plan.review != *review || plan.proposal != commitment.proposal {
        return Err("prepared replay does not reconstruct exact logical proposal".into());
    }
    let next_target = match (&plan.target_plan, &commitment.target_append) {
        (Some(proposal), Some(append)) => {
            if append.base != prefix.target || append.review_sha256 != proposal.review_sha256() {
                return Err(
                    "restored target append differs from independently reconstructed OwnerPlan"
                        .into(),
                );
            }
            let budget = IoBudget {
                read_bytes: plan.proposal.budget.target_read_bytes,
                write_bytes: 0,
                new_files: 0,
            };
            verify_append_data(target.store, append, budget, b)?
        }
        (None, None) => prefix.target.clone(),
        _ => return Err("inert source outcome cannot acquire a target publication".into()),
    };
    let mut jb = Job {
        b,
        manifest,
        prefix,
        store: job,
        review: Some(review),
    };
    let mut guard = Guard::new(
        &mut jb,
        &prefix.target.binding,
        plan.proposal.budget.job_read(),
        None,
    )?;
    let mappings = if plan.mapping_edit.is_empty() {
        prefix.mappings.clone()
    } else {
        job.verify_map_inner(&prefix.mappings, &plan.mapping_edit, &mut guard)?
    };
    let source_lifecycle = if plan.state_edit.is_empty() {
        prefix.source_lifecycle.clone()
    } else {
        job.verify_map_inner(&prefix.source_lifecycle, &plan.state_edit, &mut guard)?
    };
    if mappings != plan.proposal.mappings || source_lifecycle != plan.proposal.source_lifecycle {
        return Err("prepared replay changed unrelated auxiliary state or lost map objects".into());
    }
    guard.check()?;
    drop(guard);
    drop(jb);
    let mut expected = prefix.clone();
    expected.target = next_target;
    expected.next_source_ordinal = prefix
        .next_source_ordinal
        .checked_add(1)
        .ok_or("restore source ordinal overflow")?;
    expected.mappings = mappings;
    expected.source_lifecycle = source_lifecycle;
    expected.published_versions = plan.proposal.published_versions;
    expected.lifecycle_outcomes = plan.proposal.lifecycle_outcomes;
    expected.inert_outcomes = plan.proposal.inert_outcomes;
    expected.verified_final_artifacts = plan.proposal.verified_final_artifacts;
    expected.reservations = plan.proposal.reservations;
    expected.validate(manifest)?;
    if expected != commitment.next {
        return Err("prepared replay changes unrelated job/prefix/target fields".into());
    }
    b.retain_original_ciphertext(manifest, manifest.part_count)?;
    live(manifest, prefix, Some(review), b)?;
    Ok(expected)
}
