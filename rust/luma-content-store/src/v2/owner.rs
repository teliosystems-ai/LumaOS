//! Selected owner operations. A supplied descriptor is never adopted as a head:
//! every private step retains the caller's genuine C/current authority boundary.
use super::head::{OwnerHeadV2, PhysicalAccounting};
use super::lifecycle::{LifecycleRequestV2, LifecycleState};
use super::owner_segment::{Locator, Member, StoredOutcome};
use super::*;
use crate::{LifecycleStatus, Plan, Provenance, VersionReference};
use luma_content::{ArtifactVersion, Format};
use std::fs::File;

pub trait OwnerBoundary: Boundary {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()>;
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory>;
    /// Must join real original fixed-worker creation observations, current
    /// reservations, held file identities/blocks and actual C counters. JSON
    /// counters or a copied commitment alone cannot implement this check.
    fn verify_prepared_allocations(&mut self, commitment: &AppendCommitment) -> Result<()>;
}
pub(super) struct Selected<'a, B: OwnerBoundary> {
    pub boundary: &'a mut B,
    pub head: &'a OwnerHeadV2,
}
impl<B: OwnerBoundary> Boundary for Selected<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.boundary.current_owner_head(self.head)?;
        self.boundary.admit(binding, budget)?;
        self.boundary.current_owner_head(self.head)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.boundary.current_owner_head(self.head)?;
        self.boundary.check(access)?;
        self.boundary.current_owner_head(self.head)
    }
}
pub(super) fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ValueRef {
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactValue {
    pub reference: VersionReference,
    pub payload: BlobReference,
    pub collection: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectionValue {
    pub reference: VersionReference,
    pub source: BlobReference,
}

/// A reviewed exact proposal, not a grant or a selected publication. There is no
/// Deserialize or Clone implementation for rebuilding a live held operation.
pub struct OwnerPlan {
    pub(super) base_sha256: String,
    pub(super) record: crate::Record,
    pub(super) source: Vec<u8>,
    pub(super) payload: Vec<u8>,
    review_sha256: String,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Review<'a> {
    schema_version: u32,
    domain: &'static str,
    base_head_sha256: &'a str,
    ordinal: u64,
    artifact_id: &'a str,
    request_id: &'a str,
    decision: DecisionKind,
    record_sha256: String,
    source_sha256: String,
    payload_sha256: String,
}
impl OwnerPlan {
    fn new(head: &OwnerHeadV2, plan: Plan, source: &[u8]) -> Result<Self> {
        let record = crate::Record {
            schema_version: plan.data.schema_version,
            sequence: head
                .history
                .outcomes
                .checked_add(1)
                .ok_or("v2 ordinal overflow")?,
            review_sha256: plan.review,
            plan: plan.data,
        };
        let mut value = Self {
            base_sha256: head.sha256()?,
            record,
            source: source.to_vec(),
            payload: plan.payload,
            review_sha256: String::new(),
        };
        value.review_sha256 = luma_content::sha256(&value.review_bytes()?);
        Ok(value)
    }
    pub fn review_bytes(&self) -> Result<Vec<u8>> {
        let value = Review {
            schema_version: 2,
            domain: "luma-owner-append-review-v2",
            base_head_sha256: &self.base_sha256,
            ordinal: self.record.sequence,
            artifact_id: &self.record.plan.artifact_id,
            request_id: &self.record.plan.provenance.request_id,
            decision: self.record.plan.decision,
            record_sha256: luma_content::sha256(&serde_json::to_vec(&self.record)?),
            source_sha256: luma_content::sha256(&self.source),
            payload_sha256: luma_content::sha256(&self.payload),
        };
        Ok(serde_json::to_vec(&value)?)
    }
    pub fn review_sha256(&self) -> &str {
        &self.review_sha256
    }
    pub fn decision(&self) -> DecisionKind {
        self.record.plan.decision
    }
    pub fn resulting(&self) -> &VersionReference {
        &self.record.plan.resulting
    }
    pub fn request_id(&self) -> &str {
        &self.record.plan.provenance.request_id
    }
    pub fn canonical_record(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.record)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppendCommitment {
    pub schema_version: u32,
    pub domain: String,
    pub base: OwnerHeadV2,
    pub next: OwnerHeadV2,
    pub review_sha256: String,
    pub member: BlobReference,
    pub head_object_sha256: String,
    pub physical_before: PhysicalInventory,
    pub physical_after: PhysicalInventory,
}
impl AppendCommitment {
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;
        self.next.validate()?;
        digest(&self.review_sha256)?;
        digest(&self.head_object_sha256)?;
        self.member.validate()?;
        if self.schema_version != 2
            || self.domain != "luma-owner-append-commitment-v2"
            || self.base.binding != self.next.binding
            || self.member.binding != self.base.binding
            || self.next.history.outcomes
                != self
                    .base
                    .history
                    .outcomes
                    .checked_add(1)
                    .ok_or("v2 append count overflow")?
            || self.next.migration != self.base.migration
            || self.head_object_sha256 != self.next.sha256()?
        {
            return Err("v2 append commitment retargets, resets or skips state".into());
        }
        physical_transition(
            &self.physical_before,
            &self.next.physical.observed,
            &self.physical_after,
        )?;
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 65536 {
            return Err("v2 append commitment exceeds fixed bound".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 65536)?;
        value.validate()?;
        Ok(value)
    }
}
/// Independently replay an UNSELECTED candidate under the genuine CURRENT base.
/// Every changed map path/value and its physical object must already exist.
/// Successful verification returns DATA, not publication/NV permission.
pub fn verify_append_data(
    store: &ObjectStore,
    commitment: &AppendCommitment,
    budget: IoBudget,
    boundary: &mut impl OwnerBoundary,
) -> Result<OwnerHeadV2> {
    commitment.validate()?;
    boundary.current_owner_head(&commitment.base)?;
    if boundary.current_physical_accounting(&commitment.base)? != commitment.physical_before {
        return Err("v2 append physical base no longer matches actual C accounting".into());
    }
    boundary.verify_prepared_allocations(commitment)?;
    let mut selected = Selected {
        boundary,
        head: &commitment.base,
    };
    let mut guard = Guard::new(&mut selected, &commitment.base.binding, budget, None)?;
    let member: Member = canonical(&store.get_blob(&commitment.member, &mut guard)?, 8192)?;
    let record_bytes = store.get_blob(&member.record, &mut guard)?;
    let source = store.get_blob(&member.source, &mut guard)?;
    let payload = store.get_blob(&member.payload, &mut guard)?;
    let record: crate::Record = canonical(&record_bytes, crate::MAX_RECORD as usize)?;
    if member.ordinal != record.sequence || member.request_id != record.plan.provenance.request_id {
        return Err("v2 candidate member retargets canonical outcome".into());
    }
    store.check_append_preparations(
        &commitment.base,
        &record.plan.provenance.request_id,
        &mut guard,
    )?;
    let rebuilt = store.reconstruct(&commitment.base, &record, &source, &payload, &mut guard)?;
    let plan = OwnerPlan::new(&commitment.base, rebuilt, &source)?;
    if plan.review_sha256() != commitment.review_sha256 {
        return Err("v2 candidate differs from exact reviewed base/operation".into());
    }
    let mut expected = commitment.base.clone();
    store.apply_record_mode(
        &mut expected,
        &record,
        &source,
        &payload,
        &member.payload,
        &member.source,
        false,
        true,
        &mut guard,
    )?;
    store.verify_owner_extension(
        &commitment.base,
        &commitment.next,
        &commitment.member,
        &member,
        &mut guard,
    )?;
    expected.roots.requests = commitment.next.roots.requests.clone();
    expected.roots.segments = commitment.next.roots.segments.clone();
    expected.history = commitment.next.history.clone();
    expected.physical = commitment.next.physical.clone();
    if expected != commitment.next
        || store.read_object(&commitment.head_object_sha256, MAX_PAGE_BYTES, &mut guard)?
            != commitment.next.canonical_bytes()?
    {
        return Err(
            "v2 candidate changes unrelated semantic state or has missing head bytes".into(),
        );
    }
    guard.check()?;
    Ok(expected)
}
/// Keeps the actual owner writer OFD until independent C publication or loss.
/// Drop does not select a head, erase files, release a reservation or retry NV.
pub struct PreparedOwnerAppend<'a> {
    store: &'a ObjectStore,
    _writer: File,
    commitment: AppendCommitment,
}
impl PreparedOwnerAppend<'_> {
    pub fn commitment(&self) -> &AppendCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected(self, boundary: &mut impl OwnerBoundary) -> Result<OwnerHeadV2> {
        boundary.current_owner_head(&self.commitment.next)?;
        if boundary.current_physical_accounting(&self.commitment.next)?
            != self.commitment.physical_after
        {
            return Err("v2 selected physical accounting differs from held publication".into());
        }
        let mut selected = Selected {
            boundary,
            head: &self.commitment.next,
        };
        let mut guard = Guard::new(
            &mut selected,
            &self.commitment.next.binding,
            read_budget(),
            None,
        )?;
        if self.store.read_object(
            &self.commitment.head_object_sha256,
            MAX_PAGE_BYTES,
            &mut guard,
        )? != self.commitment.next.canonical_bytes()?
        {
            return Err("v2 selected owner descriptor changed".into());
        }
        guard.check()?;
        Ok(self.commitment.next.clone())
    }
}
pub struct OwnerRepository<'a> {
    pub(super) store: &'a ObjectStore,
    pub(super) head: OwnerHeadV2,
}
impl<'a> OwnerRepository<'a> {
    pub fn at_selected(
        store: &'a ObjectStore,
        head: &OwnerHeadV2,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<Self> {
        head.validate()?;
        if store.binding != head.binding {
            return Err("v2 selected owner and physical namespace differ".into());
        }
        boundary.current_owner_head(head)?;
        let mut selected = Selected { boundary, head };
        let mut guard = Guard::new(&mut selected, &head.binding, read_budget(), None)?;
        if head.history.segments > 0 {
            let segment = store.owner_segment(
                head.history
                    .last_segment
                    .as_ref()
                    .ok_or("v2 last segment missing")?,
                &mut guard,
            )?;
            if segment.last_ordinal != head.history.outcomes
                || segment.requests_after != head.roots.requests
                || segment.segment_number + 1 != head.history.segments
            {
                return Err("v2 aggregate selected history differs".into());
            }
        }
        for root in head.roots.all() {
            if let Some(page) = &root.page {
                let bytes = store.read_object(&page.sha256, MAX_PAGE_BYTES, &mut guard)?;
                super::page::Page::decode(&bytes, &head.binding, root.kind, page)?;
            }
        }
        guard.check()?;
        Ok(Self {
            store,
            head: head.clone(),
        })
    }
    pub fn head(&self) -> &OwnerHeadV2 {
        &self.head
    }
    fn inspect<B: OwnerBoundary, T>(
        &self,
        boundary: &mut B,
        operation: impl FnOnce(&ObjectStore, &OwnerHeadV2, &mut Guard<'_, Selected<'_, B>>) -> Result<T>,
    ) -> Result<T> {
        let mut selected = Selected {
            boundary,
            head: &self.head,
        };
        let mut guard = Guard::new(&mut selected, &self.head.binding, read_budget(), None)?;
        let result = operation(self.store, &self.head, &mut guard)?;
        guard.check()?;
        Ok(result)
    }
    pub fn current(
        &self,
        artifact: &str,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<ArtifactVersion> {
        self.inspect(boundary, |store, head, guard| {
            let (value, state) = store.current_value(head, artifact, guard)?;
            if state.status != LifecycleStatus::Live {
                return Err("v2 artifact is in versioned trash".into());
            }
            store.version(&value, guard)
        })
    }
    pub fn lifecycle_status(
        &self,
        artifact: &str,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<LifecycleState> {
        self.inspect(boundary, |store, head, guard| {
            Ok(store.current_value(head, artifact, guard)?.1)
        })
    }
    pub fn historical(
        &self,
        reference: &VersionReference,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<ArtifactVersion> {
        self.inspect(boundary, |store, head, guard| {
            if store
                .current_value(head, &reference.artifact_id, guard)?
                .1
                .status
                != LifecycleStatus::Live
            {
                return Err("v2 historical read requires an ordinary live identity".into());
            }
            store
                .historical_value(head, reference, guard)
                .and_then(|v| store.version(&v, guard))
        })
    }
    pub fn trash_version(
        &self,
        reference: &VersionReference,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<ArtifactVersion> {
        self.inspect(boundary, |store, head, guard| {
            if store
                .current_value(head, &reference.artifact_id, guard)?
                .1
                .status
                != LifecycleStatus::Trashed
            {
                return Err("v2 explicit trash read requires a currently trashed identity".into());
            }
            store
                .historical_value(head, reference, guard)
                .and_then(|v| store.version(&v, guard))
        })
    }
    pub fn outcome_at(
        &self,
        ordinal: u64,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<StoredOutcome> {
        self.inspect(boundary, |store, head, guard| {
            store.owner_outcome(head, ordinal, guard)
        })
    }
    pub fn visit_outcomes(
        &self,
        first: u64,
        maximum: u32,
        boundary: &mut impl OwnerBoundary,
        mut visitor: impl FnMut(StoredOutcome) -> Result<()>,
    ) -> Result<u64> {
        if first == 0 || maximum == 0 || maximum as usize > MAX_SEGMENT_OUTCOMES {
            return Err("v2 chronological window bound invalid".into());
        }
        self.inspect(boundary, |store, head, guard| {
            let end = first
                .checked_add(u64::from(maximum))
                .ok_or("v2 outcome window overflow")?
                .min(head.history.outcomes + 1);
            if first > end {
                return Err("v2 outcome window starts after selected history".into());
            }
            for ordinal in first..end {
                let value = store.owner_outcome(head, ordinal, guard)?;
                guard.check()?;
                visitor(value)?;
                guard.check()?;
            }
            Ok(end)
        })
    }
    pub fn plan_capture(
        &self,
        artifact: &str,
        format: Format,
        source: &[u8],
        provenance: Provenance,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let plan = Plan::capture(
            self.head.binding.clone(),
            artifact,
            format,
            source,
            provenance,
        )?;
        self.plan_existing(plan, source, boundary)
    }
    pub fn plan_external_edit(
        &self,
        artifact: &str,
        expected: VersionReference,
        source: &[u8],
        provenance: Provenance,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let current = self.current(artifact, boundary)?;
        let plan = Plan::build(
            Some(&current),
            self.head.binding.clone(),
            artifact,
            current.receipt().format,
            Some(expected),
            source,
            provenance,
        )?;
        self.plan_existing(plan, source, boundary)
    }
    pub fn plan_managed_table(
        &self,
        request: &luma_content::table::TableEditRequest,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let current = self.current(&request.expected.artifact_id, boundary)?;
        self.plan_existing(
            Plan::managed_table(&current, request)?,
            &request.canonical_bytes()?,
            boundary,
        )
    }
    pub fn plan_managed_render(
        &self,
        request: &luma_content::rendered::Request,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let current = self.inspect(boundary, |store, head, guard| {
            store
                .optional_current(head, &request.artifact_id, guard)
                .and_then(|v| v.map(|v| store.version(&v, guard)).transpose())
        })?;
        self.plan_existing(
            Plan::managed_render(current.as_ref(), request)?,
            &request.canonical_bytes()?,
            boundary,
        )
    }
    pub fn plan_collection(
        &self,
        source: &crate::CollectionSource,
        expected: Option<VersionReference>,
        provenance: Provenance,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let artifact = source.artifact_id()?;
        let current = self.inspect(boundary, |store, head, guard| {
            store
                .optional_current(head, &artifact, guard)
                .and_then(|v| v.map(|v| store.version(&v, guard)).transpose())
        })?;
        self.plan_existing(
            Plan::collection(
                current.as_ref(),
                self.head.binding.clone(),
                source,
                expected,
                provenance,
            )?,
            &source.canonical_bytes()?,
            boundary,
        )
    }
    pub fn plan_lifecycle(
        &self,
        request: &LifecycleRequestV2,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let plan = self.inspect(boundary, |store, head, guard| {
            let (value, state) =
                store.current_value(head, &request.expected.version.artifact_id, guard)?;
            super::lifecycle::plan(&store.version(&value, guard)?, &state, request)
        })?;
        self.plan_existing(plan, &request.canonical_bytes()?, boundary)
    }
    fn plan_existing(
        &self,
        plan: Plan,
        source: &[u8],
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerPlan> {
        let proposal = OwnerPlan::new(&self.head, plan, source)?;
        self.inspect(boundary, |store, head, guard| {
            store.reconstruct(
                head,
                &proposal.record,
                &proposal.source,
                &proposal.payload,
                guard,
            )?;
            Ok(())
        })?;
        Ok(proposal)
    }
    pub fn prepare_append(
        &self,
        proposal: &OwnerPlan,
        budget: IoBudget,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<PreparedOwnerAppend<'a>> {
        if proposal.base_sha256 != self.head.sha256()?
            || proposal.review_sha256 != luma_content::sha256(&proposal.review_bytes()?)
        {
            return Err("v2 append proposal has a different exact selected base".into());
        }
        boundary.current_owner_head(&self.head)?;
        let writer = self.store.acquire_writer()?;
        let before = boundary.current_physical_accounting(&self.head)?;
        let mutation = Mutation {
            review_sha256: proposal.review_sha256.clone(),
            decision: proposal.record.plan.decision,
            source_bytes: proposal.source.len() as u64,
        };
        let mut selected = Selected {
            boundary,
            head: &self.head,
        };
        let mut guard = Guard::new(&mut selected, &self.head.binding, budget, Some(&mutation))?;
        self.store
            .check_append_preparations(&self.head, proposal.request_id(), &mut guard)?;
        self.store.reconstruct(
            &self.head,
            &proposal.record,
            &proposal.source,
            &proposal.payload,
            &mut guard,
        )?;
        let record_bytes = proposal.canonical_record()?;
        let payload = self.store.put_blob(&proposal.payload, &mut guard)?;
        let source = self.store.put_blob(&proposal.source, &mut guard)?;
        let mut next = self.head.clone();
        self.store.apply_record(
            &mut next,
            &proposal.record,
            &proposal.source,
            &proposal.payload,
            &payload,
            &source,
            false,
            &mut guard,
        )?;
        let (requests, segments, last, count) = self.store.extend_owner_segment(
            &self.head,
            SegmentInput {
                ordinal: proposal.record.sequence,
                record: &record_bytes,
                source: &proposal.source,
                payload: &proposal.payload,
            },
            &mut guard,
        )?;
        next.roots.requests = requests;
        next.roots.segments = segments;
        next.history = super::head::HistoryCursor {
            outcomes: proposal.record.sequence,
            segments: count,
            last_segment: Some(last),
        };
        next.physical =
            PhysicalAccounting::from_observation(add_physical(&before, &guard.allocations)?)?;
        let head_object_sha256 = self
            .store
            .write_object(&next.canonical_bytes()?, &mut guard)?;
        let key = next.roots.requests.key(proposal.request_id().as_bytes())?;
        let bytes = self
            .store
            .get_map(&next.roots.requests, &key, &mut guard)?
            .ok_or("v2 prepared request missing")?;
        let locator: Locator = canonical(&bytes, MAX_VALUE_BYTES)?;
        let commitment = AppendCommitment {
            schema_version: 2,
            domain: "luma-owner-append-commitment-v2".into(),
            base: self.head.clone(),
            next,
            review_sha256: proposal.review_sha256.clone(),
            member: locator.member,
            head_object_sha256,
            physical_before: before.clone(),
            physical_after: add_physical(&before, &guard.allocations)?,
        };
        commitment.validate()?;
        guard.check()?;
        Ok(PreparedOwnerAppend {
            store: self.store,
            _writer: writer,
            commitment,
        })
    }
}
pub(super) fn add_physical(
    before: &PhysicalInventory,
    delta: &PhysicalInventory,
) -> Result<PhysicalInventory> {
    Ok(PhysicalInventory {
        regular_files: before
            .regular_files
            .checked_add(delta.regular_files)
            .ok_or("v2 physical file overflow")?,
        directories: before
            .directories
            .checked_add(delta.directories)
            .ok_or("v2 physical directory overflow")?,
        logical_bytes: before
            .logical_bytes
            .checked_add(delta.logical_bytes)
            .ok_or("v2 physical logical byte overflow")?,
        allocated_bytes: before
            .allocated_bytes
            .checked_add(delta.allocated_bytes)
            .ok_or("v2 physical allocated byte overflow")?,
        incomplete_objects: before
            .incomplete_objects
            .checked_add(delta.incomplete_objects)
            .ok_or("v2 retained incomplete count overflow")?,
    })
}
pub(super) fn physical_transition(
    before: &PhysicalInventory,
    observed: &PhysicalInventory,
    after: &PhysicalInventory,
) -> Result<()> {
    for value in [before, observed, after] {
        if value.regular_files > 4_194_304
            || value.directories > 65794
            || value.incomplete_objects > value.regular_files
        {
            return Err("v2 actual physical counters exceed the finite namespace profile".into());
        }
    }
    for (lower, upper) in [(before, observed), (observed, after)] {
        if lower.regular_files > upper.regular_files
            || lower.directories > upper.directories
            || lower.logical_bytes > upper.logical_bytes
            || lower.allocated_bytes > upper.allocated_bytes
            || lower.incomplete_objects != upper.incomplete_objects
        {
            return Err("v2 append physical counters lose retained allocations".into());
        }
    }
    if after.regular_files - observed.regular_files > 1
        || after.directories - observed.directories > 2
        || after.logical_bytes - observed.logical_bytes > MAX_PAGE_BYTES as u64
        || after.allocated_bytes - observed.allocated_bytes > 32768
    {
        return Err("v2 owner descriptor exceeds actual precommitted reserve".into());
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn actual_physical_tail_is_bounded_without_fabricating_sparse_allocation_rules() {
    // Pure counter-shape validation, not an accounting reservation or a claim
    // that these synthetic counters were measured from an actual namespace.
    let observed = PhysicalInventory {
        regular_files: 4_194_304,
        directories: 65794,
        logical_bytes: 0,
        allocated_bytes: 8192,
        incomplete_objects: 1,
    };
    assert!(physical_transition(&observed, &observed, &observed).is_ok());
    let mut after = observed.clone();
    after.regular_files += 1;
    assert!(physical_transition(&observed, &observed, &after).is_err());
    after = observed.clone();
    after.directories += 1;
    assert!(physical_transition(&observed, &observed, &after).is_err());
    let before = PhysicalInventory {
        regular_files: 1,
        incomplete_objects: 2,
        ..observed.clone()
    };
    let middle = PhysicalInventory {
        regular_files: 2,
        incomplete_objects: 2,
        ..observed.clone()
    };
    let valid_after = PhysicalInventory {
        regular_files: 3,
        incomplete_objects: 2,
        ..observed.clone()
    };
    assert!(physical_transition(&before, &middle, &valid_after).is_err());
    after = observed.clone();
    after.allocated_bytes -= 1;
    assert!(physical_transition(&observed, &observed, &after).is_err());
    after = observed.clone();
    after.incomplete_objects = 0;
    assert!(physical_transition(&observed, &observed, &after).is_err());
}

impl ObjectStore {
    pub(super) fn value<T: Serialize + for<'de> Deserialize<'de>, B: Boundary>(
        &self,
        root: &MapRoot,
        key: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<Option<T>> {
        self.get_map(root, key, guard)?
            .map(|bytes| {
                let reference: ValueRef = canonical(&bytes, MAX_VALUE_BYTES)?;
                digest(&reference.sha256)?;
                canonical(
                    &self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?,
                    MAX_PAGE_BYTES,
                )
            })
            .transpose()
    }
    pub(super) fn set_value<T: Serialize, B: Boundary>(
        &self,
        root: &MapRoot,
        key: String,
        value: Option<&T>,
        verify: bool,
        guard: &mut Guard<'_, B>,
    ) -> Result<MapRoot> {
        let previous = self.get_map(root, &key, guard)?;
        let value = value
            .map(|v| -> Result<Vec<u8>> {
                let bytes = serde_json::to_vec(v)?;
                if bytes.len() > MAX_PAGE_BYTES {
                    return Err("v2 semantic value exceeds one page".into());
                }
                let sha = luma_content::sha256(&bytes);
                if verify {
                    if self.read_object(&sha, MAX_PAGE_BYTES, guard)? != bytes {
                        return Err("v2 semantic value missing before selection".into());
                    }
                } else {
                    self.write_object(&bytes, guard)?;
                }
                Ok(serde_json::to_vec(&ValueRef { sha256: sha })?)
            })
            .transpose()?;
        if previous == value {
            return Ok(root.clone());
        }
        let edit = MapEdit {
            key,
            expected_value_sha256: previous.as_ref().map(|v| luma_content::sha256(v)),
            value,
        };
        if verify {
            self.verify_map_inner(root, &[edit], guard)
        } else {
            self.edit_map(root, &[edit], guard)
        }
    }
    pub(super) fn optional_current<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        artifact: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<Option<ArtifactValue>> {
        identifier(artifact)?;
        let value: Option<ArtifactValue> = self.value(
            &head.roots.artifacts,
            &head.roots.artifacts.key(artifact.as_bytes())?,
            guard,
        )?;
        if let Some(value) = &value {
            if value.reference.artifact_id != artifact {
                return Err("v2 current map retargets artifact".into());
            }
            crate::collections::reference(&value.reference)?;
            value.payload.validate()?;
        }
        Ok(value)
    }
    pub(super) fn current_value<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        artifact: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<(ArtifactValue, LifecycleState)> {
        let value = self
            .optional_current(head, artifact, guard)?
            .ok_or("v2 current artifact unavailable")?;
        let state: LifecycleState = self
            .value(
                &head.roots.lifecycle,
                &head.roots.lifecycle.key(artifact.as_bytes())?,
                guard,
            )?
            .ok_or("v2 artifact lifecycle missing")?;
        state.validate()?;
        if state.version != value.reference {
            return Err("v2 artifact and lifecycle versions differ".into());
        }
        Ok((value, state))
    }
    pub(super) fn historical_value<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        reference: &VersionReference,
        guard: &mut Guard<'_, B>,
    ) -> Result<ArtifactValue> {
        crate::collections::reference(reference)?;
        let value: ArtifactValue = self
            .value(
                &head.roots.history,
                &head.roots.history.key(&serde_json::to_vec(reference)?)?,
                guard,
            )?
            .ok_or("v2 exact historical reference unavailable")?;
        if value.reference != *reference {
            return Err("v2 history retargets exact reference".into());
        }
        Ok(value)
    }
    pub(super) fn version<B: Boundary>(
        &self,
        value: &ArtifactValue,
        guard: &mut Guard<'_, B>,
    ) -> Result<ArtifactVersion> {
        let version = luma_content::reopen(&self.get_blob(&value.payload, guard)?, &self.binding)?;
        if version.reference()? != value.reference {
            return Err("v2 immutable artifact payload/reference mismatch".into());
        }
        Ok(version)
    }
    pub(super) fn reconstruct<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        record: &crate::Record,
        source: &[u8],
        payload: &[u8],
        guard: &mut Guard<'_, B>,
    ) -> Result<Plan> {
        segment::validate_record(
            &self.binding,
            &SegmentInput {
                ordinal: record.sequence,
                record: &serde_json::to_vec(record)?,
                source,
                payload,
            },
            &mut || guard.check(),
        )?;
        if record.sequence != head.history.outcomes + 1 {
            return Err("v2 semantic record does not extend selected global history".into());
        }
        let data = &record.plan;
        let current = self.optional_current(head, &data.artifact_id, guard)?;
        let state = if current.is_some() {
            Some(self.current_value(head, &data.artifact_id, guard)?.1)
        } else {
            None
        };
        if current.as_ref().map(|v| &v.reference) != data.observed.as_ref() {
            return Err(
                "v2 semantic observed version differs from current selected artifact".into(),
            );
        }
        if data.source_kind != Some(crate::SourceKind::LifecycleIntent)
            && state
                .as_ref()
                .is_some_and(|s| s.status == LifecycleStatus::Trashed)
        {
            return Err("v2 content cannot overwrite a trashed identity".into());
        }
        let version = current
            .as_ref()
            .map(|v| self.version(v, guard))
            .transpose()?;
        if data.source_kind == Some(crate::SourceKind::CollectionIntent) {
            let collection = crate::CollectionSource::from_canonical(source)?;
            if current.as_ref().is_some_and(|v| !v.collection) {
                return Err("v2 collection ID collides with generic content".into());
            }
            if let Some(expected) = &data.expected {
                if !self.historical_value(head, expected, guard)?.collection {
                    return Err("v2 collection base is not a genuine published collection".into());
                }
            }
            for member in &collection.members {
                self.historical_value(head, member, guard)?;
                if self
                    .current_value(head, &member.artifact_id, guard)?
                    .1
                    .status
                    != LifecycleStatus::Live
                {
                    return Err("v2 collection includes a trashed identity".into());
                }
            }
        } else if data.source_kind != Some(crate::SourceKind::LifecycleIntent)
            && current.as_ref().is_some_and(|v| v.collection)
        {
            return Err("v2 typed collection cannot be overwritten as generic content".into());
        }
        let rebuilt = if record.schema_version == 6 {
            super::lifecycle::rebuild(
                version
                    .as_ref()
                    .ok_or("v2 lifecycle retained payload missing")?,
                state.as_ref().ok_or("v2 lifecycle state missing")?,
                data,
                source,
            )?
        } else {
            if let Some(transition) = &data.lifecycle {
                if state.as_ref().map(LifecycleState::wire) != Some(transition.observed.clone()) {
                    return Err(
                        "v2 legacy lifecycle revision does not extend exact selected state".into(),
                    );
                }
            }
            Plan::rebuild(version.as_ref(), data, source)?
        };
        if rebuilt.data != *data
            || rebuilt.payload != payload
            || rebuilt.review != record.review_sha256
        {
            return Err("v2 outcome does not replay the actual declared engine".into());
        }
        guard.check()?;
        Ok(rebuilt)
    }
    pub(super) fn apply_record<B: Boundary>(
        &self,
        head: &mut OwnerHeadV2,
        record: &crate::Record,
        source_bytes: &[u8],
        payload_bytes: &[u8],
        payload: &BlobReference,
        source: &BlobReference,
        legacy: bool,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        self.apply_record_mode(
            head,
            record,
            source_bytes,
            payload_bytes,
            payload,
            source,
            legacy,
            false,
            guard,
        )
    }
    pub(super) fn apply_record_mode<B: Boundary>(
        &self,
        head: &mut OwnerHeadV2,
        record: &crate::Record,
        source_bytes: &[u8],
        payload_bytes: &[u8],
        payload: &BlobReference,
        source: &BlobReference,
        legacy: bool,
        verify: bool,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        let data = &record.plan;
        let artifact = &data.artifact_id;
        if data.decision == DecisionKind::Published {
            let value = ArtifactValue {
                reference: data.resulting.clone(),
                payload: payload.clone(),
                collection: data.source_kind == Some(crate::SourceKind::CollectionIntent),
            };
            head.roots.artifacts = self.set_value(
                &head.roots.artifacts,
                head.roots.artifacts.key(artifact.as_bytes())?,
                Some(&value),
                verify,
                guard,
            )?;
            let key = head
                .roots
                .history
                .key(&serde_json::to_vec(&data.resulting)?)?;
            if self.get_map(&head.roots.history, &key, guard)?.is_some() {
                return Err("v2 new publication reuses an exact historical version".into());
            }
            head.roots.history =
                self.set_value(&head.roots.history, key, Some(&value), verify, guard)?;
            if value.collection {
                let collection = crate::CollectionSource::from_canonical(source_bytes)?;
                head.roots.collections = self.set_value(
                    &head.roots.collections,
                    head.roots
                        .collections
                        .key(collection.collection_id.as_bytes())?,
                    Some(&CollectionValue {
                        reference: data.resulting.clone(),
                        source: source.clone(),
                    }),
                    verify,
                    guard,
                )?;
            }
        }
        if matches!(
            data.decision,
            DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
        ) {
            let status = if data.decision == DecisionKind::Trashed {
                LifecycleStatus::Trashed
            } else {
                LifecycleStatus::Live
            };
            let state = LifecycleState::advance(&self.binding, record, status, legacy)?;
            head.roots.lifecycle = self.set_value(
                &head.roots.lifecycle,
                head.roots.lifecycle.key(artifact.as_bytes())?,
                Some(&state),
                verify,
                guard,
            )?;
            let key = head.roots.corpus.corpus_key(artifact)?;
            let before = self.get_map(&head.roots.corpus, &key, guard)?;
            let after = if status == LifecycleStatus::Trashed {
                None
            } else {
                let version = luma_content::reopen(payload_bytes, &self.binding)?;
                Some(
                    crate::corpus_index::CorpusRecord {
                        schema_version: 1,
                        reference: data.resulting.clone(),
                        format: version.receipt().format,
                        content_bytes: version.content().len() as u64,
                        lifecycle_revision: state.revision,
                        lifecycle_state_sha256: state.state_sha256,
                    }
                    .canonical_bytes()?,
                )
            };
            if before != after {
                let edit = MapEdit {
                    key,
                    expected_value_sha256: before.as_ref().map(|b| luma_content::sha256(b)),
                    value: after,
                };
                head.roots.corpus = if verify {
                    self.verify_map_inner(&head.roots.corpus, &[edit], guard)?
                } else {
                    self.edit_map(&head.roots.corpus, &[edit], guard)?
                };
            }
        }
        guard.check()
    }
}
