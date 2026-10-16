//! Explicit owner-local collections rebuilt from immutable published content.
//!
//! Membership is an exact historical reference, not a grant, live link,
//! transitive inclusion, semantic classification, or cross-owner capability.
//! Typed collection transactions contain closed canonical JSON; an ordinary
//! JSON artifact with a similar name is never inferred to be a collection.
//! There is no additional mutable index, head, repair, or background execution.
use crate::{storage, Boundary, DecisionKind, Outcome, Plan, Repository, ResourceBudget, Result};
use luma_content::{ArtifactVersion, EditOrigin, Format, Provenance, VersionReference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_COLLECTION_MEMBERS: usize = 64;
pub const MAX_COLLECTION_SOURCE_BYTES: usize = 32_768;
pub const MAX_COLLECTION_PAGE: usize = 32;
const PREFIX: &str = "collection.";
const KIND: &str = "luma-explicit-collection-v1";

/// Editable source. Members must be strictly ordered by artifact ID, with at
/// most one exact version per artifact. Empty membership explicitly empties the
/// collection; it does not delete retained history or the stable identifier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSource {
    pub schema_version: u32,
    pub kind: String,
    pub collection_id: String,
    pub name: String,
    pub members: Vec<VersionReference>,
}

impl CollectionSource {
    pub fn artifact_id(&self) -> Result<String> {
        identifier(&self.collection_id)?;
        Ok(format!("{PREFIX}{}", self.collection_id))
    }

    /// Pure structural validation, not proof that member references exist.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.artifact_id()?;
        if self.schema_version != 1
            || self.kind != KIND
            || self.name.is_empty()
            || self.name.len() > 256
            || self.name.trim() != self.name
            || self.name.chars().any(char::is_control)
            || self.members.len() > MAX_COLLECTION_MEMBERS
        {
            return Err("invalid bounded explicit collection source".into());
        }
        let mut previous: Option<&str> = None;
        for member in &self.members {
            reference(member)?;
            if previous.is_some_and(|id| id >= member.artifact_id.as_str()) {
                return Err("collection members must be unique and sorted by artifact ID".into());
            }
            previous = Some(&member.artifact_id);
        }
        // serde_json::Value uses the same sorted-map representation as the
        // generic content contract; source and published canonical JSON agree.
        let bytes = serde_json::to_vec(&serde_json::to_value(self)?)?;
        if bytes.len() > MAX_COLLECTION_SOURCE_BYTES {
            return Err("explicit collection source byte bound exceeded".into());
        }
        Ok(bytes)
    }

    /// Reject unknown/duplicate fields, whitespace aliases, alternate number
    /// spellings, and noncanonical ordering instead of silently dropping input.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_COLLECTION_SOURCE_BYTES {
            return Err("explicit collection source byte bound exceeded".into());
        }
        let source: Self = serde_json::from_slice(bytes)?;
        if source.canonical_bytes()? != bytes {
            return Err("collection input must be exact canonical typed JSON".into());
        }
        Ok(source)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionVersion {
    pub reference: VersionReference,
    pub source: CollectionSource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionPage {
    pub collection: VersionReference,
    pub collection_id: String,
    pub name: String,
    pub members: Vec<VersionReference>,
    pub total_members: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionMemberships {
    pub member: VersionReference,
    pub collections: Vec<VersionReference>,
    pub total_collections: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
}

pub(crate) struct CollectionHistory {
    published: Vec<VersionReference>,
    versions: Vec<CollectionVersion>,
    latest: BTreeMap<String, CollectionVersion>,
    occupied: std::collections::BTreeSet<String>,
}

impl CollectionHistory {
    pub(crate) fn new() -> Self {
        Self {
            published: Vec::new(),
            versions: Vec::new(),
            latest: BTreeMap::new(),
            occupied: std::collections::BTreeSet::new(),
        }
    }

    /// Validate in immutable transaction order, before making this outcome
    /// available to later transactions. This also runs before a new commit.
    pub(crate) fn observe(
        &mut self,
        plan: &Plan,
        source: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if plan.source_kind() == crate::SourceKind::CollectionIntent {
            let collection = CollectionSource::from_canonical(source)?;
            let artifact = collection.artifact_id()?;
            if plan.artifact_id() != artifact
                || plan.format() != Format::Json
                || plan.provenance().origin != EditOrigin::External
                || plan.data.observed
                    != self
                        .latest
                        .get(&collection.collection_id)
                        .map(|v| v.reference.clone())
            {
                return Err(
                    "typed collection transaction identity or observed base mismatch".into(),
                );
            }
            match (self.latest.get(&collection.collection_id), plan.expected()) {
                (None, None) => {}
                (Some(_), Some(base))
                    if base.artifact_id == artifact
                        && self.versions.iter().any(|v| v.reference == *base) => {}
                _ => {
                    return Err(
                        "typed collection base is not an earlier published collection".into(),
                    )
                }
            }
            check_members(&collection, &self.published, check)?;
            if plan.decision() == DecisionKind::Published {
                let version = CollectionVersion {
                    reference: plan.resulting().clone(),
                    source: collection,
                };
                self.latest
                    .insert(version.source.collection_id.clone(), version.clone());
                self.versions.push(version);
            }
        } else if self
            .latest
            .values()
            .any(|v| v.reference.artifact_id == plan.artifact_id())
        {
            return Err("a typed collection cannot be overwritten by generic content".into());
        }
        if plan.decision() == DecisionKind::Published {
            self.published.push(plan.resulting().clone());
            self.occupied.insert(plan.artifact_id().into());
        }
        check()
    }
}

impl Plan {
    /// Initial empty collection proposal for creating a repository. Nonempty
    /// membership requires an existing repository and `plan_collection`.
    pub fn collection_capture(
        binding: luma_content::OwnerBinding,
        source: &CollectionSource,
        provenance: Provenance,
    ) -> Result<Self> {
        if !source.members.is_empty() {
            return Err("initial collection capture cannot reference unpublished members".into());
        }
        Self::collection(None, binding, source, None, provenance)
    }

    pub(crate) fn collection(
        current: Option<&ArtifactVersion>,
        binding: luma_content::OwnerBinding,
        source: &CollectionSource,
        expected: Option<VersionReference>,
        provenance: Provenance,
    ) -> Result<Self> {
        if provenance.origin != EditOrigin::External {
            return Err("typed collection requires explicit external-source provenance".into());
        }
        let mut plan = Self::build(
            current,
            binding,
            &source.artifact_id()?,
            Format::Json,
            expected,
            &source.canonical_bytes()?,
            provenance,
        )?;
        plan.data.schema_version = 4;
        plan.data.source_kind = Some(crate::SourceKind::CollectionIntent);
        let metadata = serde_json::to_vec(&plan.data)?;
        if metadata.len() as u64 > crate::MAX_RECORD {
            return Err("typed collection proposal metadata bound exceeded".into());
        }
        plan.review = luma_content::sha256(&metadata);
        Ok(plan)
    }
}

impl Repository {
    /// Review creation/edit against the current collection, retaining ordinary
    /// exact-source conflict/no-op outcomes through the existing transaction.
    /// A supplied stale base must itself be a genuine published collection.
    pub fn plan_collection(
        &self,
        source: &CollectionSource,
        expected: Option<VersionReference>,
        provenance: Provenance,
        boundary: &mut impl Boundary,
    ) -> Result<Plan> {
        source.canonical_bytes()?;
        if provenance.origin != EditOrigin::External {
            return Err("explicit collection edits require external-source provenance".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let state = self.collection_state(None, boundary)?;
        check_members(source, &state.published, &mut || {
            storage::repository_check(self, None, boundary)
        })?;
        let artifact = source.artifact_id()?;
        let current = state.latest.get(&source.collection_id);
        if current.is_none() && state.occupied.contains(&artifact) {
            return Err("collection stable ID collides with an existing generic artifact".into());
        }
        match (current, &expected) {
            (None, None) => {}
            (Some(_), Some(base))
                if base.artifact_id == artifact
                    && state.versions.iter().any(|v| v.reference == *base) => {}
            _ => return Err("collection edit requires its exact genuine published base".into()),
        }
        let current = current
            .map(|v| self.historical(&v.reference, boundary))
            .transpose()?;
        let plan = Plan::collection(
            current.as_ref(),
            self.binding.clone(),
            source,
            expected,
            provenance,
        )?;
        storage::repository_check(self, None, boundary)?;
        Ok(plan)
    }

    /// Recheck collection semantics immediately before ordinary atomic apply.
    /// Exclusive `&mut self` and the repository lock span both validation and
    /// publication. Retained request replay remains exact and idempotent.
    pub fn apply_collection(
        &mut self,
        plan: &Plan,
        source: &[u8],
        boundary: &mut impl Boundary,
    ) -> Result<Outcome> {
        let collection = CollectionSource::from_canonical(source)?;
        if plan.binding() != &self.binding
            || plan.artifact_id() != collection.artifact_id()?
            || plan.format() != Format::Json
            || plan.source_kind() != crate::SourceKind::CollectionIntent
            || plan.provenance().origin != EditOrigin::External
            || plan.source_bytes() != source.len() as u64
            || plan.provenance().source_sha256 != luma_content::sha256(source)
        {
            return Err("collection proposal owner, source, or type mismatch".into());
        }
        boundary.admit(
            &self.binding,
            ResourceBudget::mutation(plan.storage_bytes()),
        )?;
        let state = self.collection_state(Some(plan), boundary)?;
        check_members(&collection, &state.published, &mut || {
            storage::repository_check(self, Some(plan), boundary)
        })?;
        if let Some(base) = plan.expected() {
            if base.artifact_id != plan.artifact_id()
                || !state.versions.iter().any(|v| v.reference == *base)
            {
                return Err(
                    "collection proposal base is not a genuine published collection".into(),
                );
            }
        }
        storage::repository_check(self, Some(plan), boundary)?;
        self.apply(plan, source, boundary)
    }

    pub fn collection_current(
        &self,
        collection_id: &str,
        boundary: &mut impl Boundary,
    ) -> Result<CollectionVersion> {
        identifier(collection_id)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let version = self
            .collection_state(None, boundary)?
            .latest
            .remove(collection_id)
            .ok_or("current explicit collection unavailable")?;
        storage::repository_check(self, None, boundary)?;
        Ok(version)
    }

    /// Exact immutable paging. The reference/offset are public selectors, never
    /// reusable authority; each call requires a fresh current Boundary.
    pub fn collection_page(
        &self,
        expected: &VersionReference,
        offset: usize,
        limit: usize,
        boundary: &mut impl Boundary,
    ) -> Result<CollectionPage> {
        reference(expected)?;
        page_bounds(offset, limit)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let version = self
            .collection_state(None, boundary)?
            .versions
            .into_iter()
            .find(|v| v.reference == *expected)
            .ok_or("exact published collection version unavailable")?;
        let total_members = version.source.members.len();
        let end = page_end(offset, limit, total_members)?;
        let result = CollectionPage {
            collection: version.reference,
            collection_id: version.source.collection_id,
            name: version.source.name,
            members: version.source.members[offset..end].to_vec(),
            total_members,
            offset,
            next_offset: (end < total_members).then_some(end),
        };
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    /// Deterministic owner-local reverse membership in latest collections only.
    /// Older member versions are not silently replaced by their current heads.
    pub fn collections_for_member(
        &self,
        member: &VersionReference,
        offset: usize,
        limit: usize,
        boundary: &mut impl Boundary,
    ) -> Result<CollectionMemberships> {
        reference(member)?;
        page_bounds(offset, limit)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let state = self.collection_state(None, boundary)?;
        if !state.published.contains(member) {
            return Err("collection membership requires a genuine published member".into());
        }
        let mut collections = Vec::new();
        for version in state.latest.into_values() {
            storage::repository_check(self, None, boundary)?;
            if version.source.members.contains(member) {
                collections.push(version.reference);
            }
        }
        let total_collections = collections.len();
        let end = page_end(offset, limit, total_collections)?;
        let result = CollectionMemberships {
            member: member.clone(),
            collections: collections[offset..end].to_vec(),
            total_collections,
            offset,
            next_offset: (end < total_collections).then_some(end),
        };
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    fn collection_state(
        &self,
        plan: Option<&Plan>,
        boundary: &mut impl Boundary,
    ) -> Result<CollectionHistory> {
        let snapshot = self.snapshot(plan, boundary)?;
        let mut state = CollectionHistory::new();
        // Records are sequence-verified by snapshot. Only earlier published
        // references may be members, so future/candidate/self-version forgeries
        // cannot become valid after an unrelated later publication.
        for (_, proposal, source) in snapshot.records {
            storage::repository_check(self, plan, boundary)?;
            state.observe(&proposal, &source, &mut || {
                storage::repository_check(self, plan, boundary)
            })?;
            storage::repository_check(self, plan, boundary)?;
        }
        storage::repository_check(self, plan, boundary)?;
        Ok(state)
    }
}

fn check_members(
    source: &CollectionSource,
    published: &[VersionReference],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    for member in &source.members {
        check()?;
        if !published.contains(member) {
            return Err(
                "collection member is not an exact earlier published owner-local version".into(),
            );
        }
    }
    check()
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid bounded stable collection ID".into());
    }
    Ok(())
}

fn reference(value: &VersionReference) -> Result<()> {
    if value.artifact_id.is_empty()
        || value.artifact_id.len() > 128
        || !value.artifact_id.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || value.version == 0
        || [&value.content_sha256, &value.receipt_sha256]
            .iter()
            .any(|digest| !crate::hash(digest) || digest.bytes().all(|byte| byte == b'0'))
    {
        return Err("invalid bounded explicit collection reference".into());
    }
    Ok(())
}

fn page_bounds(offset: usize, limit: usize) -> Result<()> {
    if offset > crate::MAX_OUTCOMES || !(1..=MAX_COLLECTION_PAGE).contains(&limit) {
        return Err("explicit collection page bound exceeded".into());
    }
    Ok(())
}

fn page_end(offset: usize, limit: usize, total: usize) -> Result<usize> {
    if offset > total {
        return Err("explicit collection page offset exceeds exact result".into());
    }
    Ok((offset + limit).min(total))
}
