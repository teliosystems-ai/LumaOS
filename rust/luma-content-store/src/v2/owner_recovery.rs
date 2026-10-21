//! Explicit non-erasing retirement of migrated preparations. Read metadata or
//! an old prefix never authorizes recovery, selection, or a new content effect.
use super::head::{OwnerHeadV2, PhysicalAccounting};
use super::migration::{SourceArea, SourceEntry};
use super::owner::{add_physical, Selected, ValueRef};
use super::page::{Body, Page};
use super::*;
use std::collections::BTreeMap;
use std::fs::File;

const PROFILE: &str = "luma-owner-preparation-retirement-v2";
const RETIRED: &str = "luma-owner-retired-request-v2";
const MAX_PENDING_ENTRIES: u64 = (crate::MAX_PENDING as u64) * 4 + 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingPreparation {
    pub transaction_sha256: String,
    pub entries: Vec<PendingEntry>,
    pub retained_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingEntry {
    pub entry: SourceEntry,
    pub bytes: BlobReference,
}
impl PendingPreparation {
    fn validate(&self, binding: &OwnerBinding) -> Result<()> {
        digest(&self.transaction_sha256)?;
        if self.entries.is_empty() || self.entries.len() > 4 {
            return Err("invalid bounded pending preparation".into());
        }
        let mut previous = None;
        let mut bytes = 0_u64;
        let mut directory = 0;
        for value in &self.entries {
            validate_raw(value, binding)?;
            if value.entry.area != SourceArea::Pending
                || value.entry.transaction.as_deref() != Some(&self.transaction_sha256)
            {
                return Err("pending preparation retargets transaction".into());
            }
            let key = value.entry.key()?;
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err("pending preparation repeats or reorders members".into());
            }
            previous = Some(key);
            if value.entry.member.is_none() {
                directory += 1;
            } else {
                bytes = bytes
                    .checked_add(value.bytes.bytes)
                    .ok_or("pending byte count overflow")?;
            }
        }
        if directory != 1 || bytes != self.retained_bytes || bytes > crate::MAX_REPOSITORY_BYTES {
            return Err("pending preparation directory/byte count differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReview {
    pub schema_version: u32,
    pub profile: String,
    pub binding: OwnerBinding,
    pub base_head_sha256: String,
    pub pending_root_sha256: String,
    pub target: PendingPreparation,
    pub review_sha256: String,
}
impl RecoveryReview {
    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut value = self.clone();
        value.review_sha256.clear();
        let bytes = serde_json::to_vec(&value)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("preparation review exceeds one page".into());
        }
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        digest(&self.base_head_sha256)?;
        digest(&self.pending_root_sha256)?;
        digest(&self.review_sha256)?;
        self.target.validate(&self.binding)?;
        if self.schema_version != 2
            || self.profile != PROFILE
            || luma_content::sha256(&self.unsigned_bytes()?) != self.review_sha256
        {
            return Err("preparation review canonical commitment differs".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("preparation review too large".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_PAGE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Retirement {
    schema_version: u32,
    profile: String,
    binding: OwnerBinding,
    base_head_sha256: String,
    transaction_sha256: String,
    review_sha256: String,
    entries_sha256: String,
    retained_bytes: u64,
}
impl Retirement {
    fn of(review: &RecoveryReview) -> Result<Self> {
        review.validate()?;
        Ok(Self {
            schema_version: 2,
            profile: PROFILE.into(),
            binding: review.binding.clone(),
            base_head_sha256: review.base_head_sha256.clone(),
            transaction_sha256: review.target.transaction_sha256.clone(),
            review_sha256: review.review_sha256.clone(),
            entries_sha256: luma_content::sha256(&serde_json::to_vec(&review.target.entries)?),
            retained_bytes: review.target.retained_bytes,
        })
    }
    fn validate(&self, binding: &OwnerBinding, transaction: &str) -> Result<()> {
        self.binding.validate()?;
        for value in [
            &self.base_head_sha256,
            &self.transaction_sha256,
            &self.review_sha256,
            &self.entries_sha256,
        ] {
            digest(value)?;
        }
        if self.schema_version != 2
            || self.profile != PROFILE
            || &self.binding != binding
            || self.transaction_sha256 != transaction
            || self.retained_bytes > crate::MAX_REPOSITORY_BYTES
        {
            return Err("retired preparation selector differs".into());
        }
        Ok(())
    }
}
fn retired_key(root: &MapRoot, transaction: &str) -> Result<String> {
    digest(transaction)?;
    root.key(&serde_json::to_vec(&(RETIRED, transaction))?)
}
fn validate_raw(value: &PendingEntry, binding: &OwnerBinding) -> Result<()> {
    value.entry.validate()?;
    value.bytes.validate()?;
    if &value.bytes.binding != binding
        || value.entry.member.is_none() && value.bytes.bytes != 0
        || value.entry.member.is_some()
            && (value.bytes.bytes != value.entry.identity.bytes
                || value.entry.sha256.as_ref() != Some(&value.bytes.sha256))
    {
        return Err("retained preparation raw commitment differs".into());
    }
    Ok(())
}

struct PendingScan {
    values: BTreeMap<String, PendingPreparation>,
    marker: bool,
    count: u64,
    previous: Option<String>,
}
impl ObjectStore {
    fn pending_page<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        reference: &PageRef,
        scan: &mut PendingScan,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        let page = Page::decode(
            &self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?,
            &self.binding,
            MapKind::Pending,
            reference,
        )?;
        match page.body {
            Body::Branch { children } => {
                for child in children {
                    self.pending_page(head, &child, scan, guard)?;
                }
            }
            Body::Leaf { entries } => {
                for entry in entries {
                    guard.check()?;
                    if scan.previous.as_ref().is_some_and(|old| old >= &entry.key)
                        || scan.count >= MAX_PENDING_ENTRIES
                    {
                        return Err(
                            "pending map repeats or exceeds legacy preparation profile".into()
                        );
                    }
                    scan.previous = Some(entry.key.clone());
                    scan.count += 1;
                    let metadata: ValueRef = canonical(&entry.value, MAX_VALUE_BYTES)?;
                    let value: PendingEntry = canonical(
                        &self.read_object(&metadata.sha256, MAX_PAGE_BYTES, guard)?,
                        MAX_PAGE_BYTES,
                    )?;
                    validate_raw(&value, &head.binding)?;
                    if value.entry.area != SourceArea::Pending
                        || head.roots.pending.key(&value.entry.key()?)? != entry.key
                    {
                        return Err("pending map metadata has unknown role/key".into());
                    }
                    let retained: PendingEntry = self
                        .value(
                            &head.roots.retained,
                            &head.roots.retained.key(&value.entry.key()?)?,
                            guard,
                        )?
                        .ok_or("pending map lost retained original metadata")?;
                    if retained != value {
                        return Err("pending map differs from retained immutable original".into());
                    }
                    if let Some(transaction) = &value.entry.transaction {
                        if !scan.values.contains_key(transaction)
                            && scan.values.len() >= crate::MAX_PENDING
                        {
                            return Err("pending transactions exceed unchanged legacy limit".into());
                        }
                        let preparation =
                            scan.values.entry(transaction.clone()).or_insert_with(|| {
                                PendingPreparation {
                                    transaction_sha256: transaction.clone(),
                                    entries: Vec::new(),
                                    retained_bytes: 0,
                                }
                            });
                        if preparation.entries.len() >= 4 {
                            return Err(
                                "pending transaction exceeds original member profile".into()
                            );
                        }
                        if value.entry.member.is_some() {
                            preparation.retained_bytes = preparation
                                .retained_bytes
                                .checked_add(value.bytes.bytes)
                                .ok_or("pending retained bytes overflow")?;
                        }
                        preparation.entries.push(value);
                    } else {
                        if value.entry.member.is_some() || scan.marker {
                            return Err("pending map has malformed area marker".into());
                        }
                        scan.marker = true;
                    }
                }
            }
        }
        guard.check()
    }
    fn pending_preparations<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        guard: &mut Guard<'_, B>,
    ) -> Result<BTreeMap<String, PendingPreparation>> {
        if head.roots.pending.entry_count > MAX_PENDING_ENTRIES {
            return Err("unknown expanded pending preparation profile".into());
        }
        let mut scan = PendingScan {
            values: BTreeMap::new(),
            marker: false,
            count: 0,
            previous: None,
        };
        if let Some(page) = &head.roots.pending.page {
            self.pending_page(head, page, &mut scan, guard)?;
        }
        if scan.count != head.roots.pending.entry_count || scan.count > 0 && !scan.marker {
            return Err("pending map full coverage or area marker differs".into());
        }
        for preparation in scan.values.values_mut() {
            let mut entries = std::mem::take(&mut preparation.entries)
                .into_iter()
                .map(|entry| Ok((entry.entry.key()?, entry)))
                .collect::<Result<Vec<_>>>()?;
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            preparation.entries = entries.into_iter().map(|(_, entry)| entry).collect();
            preparation.validate(&head.binding)?;
        }
        Ok(scan.values)
    }
    pub(super) fn check_append_preparations<B: Boundary>(
        &self,
        head: &OwnerHeadV2,
        request: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        if !self.pending_preparations(head, guard)?.is_empty() {
            return Err("retained pending preparation requires explicit fresh recovery before content mutation".into());
        }
        let transaction = luma_content::sha256(request.as_bytes());
        let retired: Option<Retirement> = self.value(
            &head.roots.retained,
            &retired_key(&head.roots.retained, &transaction)?,
            guard,
        )?;
        if let Some(value) = retired {
            value.validate(&head.binding, &transaction)?;
            return Err("content request was explicitly retired; choose a fresh request ID".into());
        }
        let original_key = serde_json::to_vec(&(
            SourceArea::Quarantine,
            Some(transaction.clone()),
            None::<String>,
        ))?;
        let original: Option<PendingEntry> = self.value(
            &head.roots.retained,
            &head.roots.retained.key(&original_key)?,
            guard,
        )?;
        if let Some(value) = original {
            validate_raw(&value, &head.binding)?;
            if value.entry.area != SourceArea::Quarantine
                || value.entry.transaction.as_deref() != Some(&transaction)
                || value.entry.member.is_some()
            {
                return Err("quarantine selector contains unknown retained metadata".into());
            }
            return Err("legacy quarantined request remains permanently retired".into());
        }
        guard.check()
    }
}

pub fn review_owner_recovery(
    store: &ObjectStore,
    head: &OwnerHeadV2,
    transaction_sha256: &str,
    boundary: &mut impl OwnerBoundary,
) -> Result<RecoveryReview> {
    head.validate()?;
    require_owner_namespace(store, head)?;
    digest(transaction_sha256)?;
    boundary.current_owner_head(head)?;
    let mut selected = Selected { boundary, head };
    let mut guard = Guard::new(
        &mut selected,
        &head.binding,
        super::owner::read_budget(),
        None,
    )?;
    let review = review_inner(store, head, transaction_sha256, &mut guard)?;
    guard.check()?;
    Ok(review)
}
fn review_inner<B: Boundary>(
    store: &ObjectStore,
    head: &OwnerHeadV2,
    transaction: &str,
    guard: &mut Guard<'_, B>,
) -> Result<RecoveryReview> {
    let target = store
        .pending_preparations(head, guard)?
        .remove(transaction)
        .ok_or("exact pending transaction absent; never guess a replacement")?;
    for value in &target.entries {
        let bytes = store.get_blob(&value.bytes, guard)?;
        if value.entry.member.is_none() && !bytes.is_empty()
            || value.entry.member.is_some()
                && (bytes.len() as u64 != value.entry.identity.bytes
                    || value.entry.sha256.as_ref() != Some(&luma_content::sha256(&bytes)))
        {
            return Err("pending recovery original bytes are corrupt".into());
        }
    }
    let mut review = RecoveryReview {
        schema_version: 2,
        profile: PROFILE.into(),
        binding: head.binding.clone(),
        base_head_sha256: head.sha256()?,
        pending_root_sha256: head.roots.pending.sha256()?,
        target,
        review_sha256: String::new(),
    };
    review.review_sha256 = luma_content::sha256(&review.unsigned_bytes()?);
    review.canonical_bytes()?;
    Ok(review)
}

pub trait OwnerRecoveryBoundary: OwnerBoundary {
    /// Join original held worker creation observations, actual before-head and
    /// after-head allocation measurements, C counters and reserved tail; never
    /// accept JSON counters or a copied review as those observations.
    fn verify_recovery_allocations(&mut self, commitment: &RecoveryCommitment) -> Result<()>;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommitment {
    pub schema_version: u32,
    pub profile: String,
    pub review: RecoveryReview,
    pub base: OwnerHeadV2,
    pub next: OwnerHeadV2,
    pub head_object_sha256: String,
    pub physical_before: PhysicalInventory,
    pub physical_after: PhysicalInventory,
}
impl RecoveryCommitment {
    pub fn validate(&self) -> Result<()> {
        self.review.validate()?;
        self.base.validate()?;
        self.next.validate()?;
        digest(&self.head_object_sha256)?;
        if self.schema_version != 2
            || self.profile != PROFILE
            || self.review.base_head_sha256 != self.base.sha256()?
            || self.review.binding != self.base.binding
            || self.base.binding != self.next.binding
            || self.review.pending_root_sha256 != self.base.roots.pending.sha256()?
            || self.head_object_sha256 != self.next.sha256()?
        {
            return Err("preparation recovery commitment changes exact owner/base".into());
        }
        super::owner::physical_transition(
            &self.physical_before,
            &self.next.physical.observed,
            &self.physical_after,
        )?;
        let mut allowed = self.base.clone();
        allowed.roots.pending = self.next.roots.pending.clone();
        allowed.roots.retained = self.next.roots.retained.clone();
        allowed.physical = self.next.physical.clone();
        if allowed != self.next
            || self
                .base
                .roots
                .pending
                .entry_count
                .checked_sub(self.review.target.entries.len() as u64)
                != Some(self.next.roots.pending.entry_count)
            || self.base.roots.retained.entry_count.checked_add(1)
                != Some(self.next.roots.retained.entry_count)
        {
            return Err(
                "preparation recovery changes unrelated history or loses raw evidence".into(),
            );
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 65536 {
            return Err("preparation recovery commitment too large".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 65536)?;
        value.validate()?;
        Ok(value)
    }
}
pub struct PreparedOwnerRecovery<'a> {
    store: &'a ObjectStore,
    _writer: File,
    commitment: RecoveryCommitment,
}
impl PreparedOwnerRecovery<'_> {
    pub fn commitment(&self) -> &RecoveryCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected(self, boundary: &mut impl OwnerBoundary) -> Result<OwnerHeadV2> {
        boundary.current_owner_head(&self.commitment.next)?;
        if boundary.current_physical_accounting(&self.commitment.next)?
            != self.commitment.physical_after
        {
            return Err("recovery actual selected accounting differs".into());
        }
        let head = &self.commitment.next;
        let mut selected = Selected { boundary, head };
        let mut guard = Guard::new(
            &mut selected,
            &head.binding,
            super::owner::read_budget(),
            None,
        )?;
        if self.store.read_object(
            &self.commitment.head_object_sha256,
            MAX_PAGE_BYTES,
            &mut guard,
        )? != head.canonical_bytes()?
        {
            return Err("recovery actual selected bytes differ".into());
        }
        guard.check()?;
        Ok(head.clone())
    }
}
pub fn prepare_owner_recovery<'a>(
    store: &'a ObjectStore,
    head: &OwnerHeadV2,
    review: &RecoveryReview,
    budget: IoBudget,
    boundary: &mut impl OwnerRecoveryBoundary,
) -> Result<PreparedOwnerRecovery<'a>> {
    review.validate()?;
    head.validate()?;
    require_owner_namespace(store, head)?;
    if review.base_head_sha256 != head.sha256()? {
        return Err("recovery review has stale selected base".into());
    }
    boundary.current_owner_head(head)?;
    let writer = store.acquire_writer()?;
    let before = boundary.current_physical_accounting(head)?;
    let mut selected = Selected { boundary, head };
    let mut guard = Guard::new_recovery(
        &mut selected,
        &head.binding,
        budget,
        &review.review_sha256,
        review.target.retained_bytes,
    )?;
    if review_inner(store, head, &review.target.transaction_sha256, &mut guard)? != *review {
        return Err("recovery source review changed".into());
    }
    let mut next = apply_recovery(store, head, review, false, &mut guard)?;
    next.physical =
        PhysicalAccounting::from_observation(add_physical(&before, &guard.allocations)?)?;
    let head_object_sha256 = store.write_object(&next.canonical_bytes()?, &mut guard)?;
    let commitment = RecoveryCommitment {
        schema_version: 2,
        profile: PROFILE.into(),
        review: review.clone(),
        base: head.clone(),
        next,
        head_object_sha256,
        physical_before: before.clone(),
        physical_after: add_physical(&before, &guard.allocations)?,
    };
    commitment.canonical_bytes()?;
    guard.check()?;
    Ok(PreparedOwnerRecovery {
        store,
        _writer: writer,
        commitment,
    })
}
pub fn verify_owner_recovery_data(
    store: &ObjectStore,
    commitment: &RecoveryCommitment,
    budget: IoBudget,
    boundary: &mut impl OwnerRecoveryBoundary,
) -> Result<OwnerHeadV2> {
    commitment.validate()?;
    require_owner_namespace(store, &commitment.base)?;
    boundary.current_owner_head(&commitment.base)?;
    if boundary.current_physical_accounting(&commitment.base)? != commitment.physical_before {
        return Err("recovery actual physical base changed".into());
    }
    boundary.verify_recovery_allocations(commitment)?;
    let review = &commitment.review;
    let head = &commitment.base;
    let mut selected = Selected { boundary, head };
    let mut guard = Guard::new_recovery(
        &mut selected,
        &head.binding,
        budget,
        &review.review_sha256,
        review.target.retained_bytes,
    )?;
    if review_inner(store, head, &review.target.transaction_sha256, &mut guard)? != *review {
        return Err("recovery independent source review differs".into());
    }
    let mut next = apply_recovery(store, head, review, true, &mut guard)?;
    next.physical = commitment.next.physical.clone();
    if next != commitment.next
        || store.read_object(&commitment.head_object_sha256, MAX_PAGE_BYTES, &mut guard)?
            != next.canonical_bytes()?
    {
        return Err("recovery independently reconstructed state differs".into());
    }
    guard.check()?;
    Ok(next)
}
fn require_owner_namespace(store: &ObjectStore, head: &OwnerHeadV2) -> Result<()> {
    if store.binding != head.binding {
        return Err("preparation recovery received a different owner namespace".into());
    }
    Ok(())
}
fn apply_recovery<B: Boundary>(
    store: &ObjectStore,
    head: &OwnerHeadV2,
    review: &RecoveryReview,
    verify: bool,
    guard: &mut Guard<'_, B>,
) -> Result<OwnerHeadV2> {
    let mut next = head.clone();
    let mut edits = Vec::new();
    for value in &review.target.entries {
        let key = head.roots.pending.key(&value.entry.key()?)?;
        let old = store
            .get_map(&head.roots.pending, &key, guard)?
            .ok_or("reviewed pending index entry disappeared")?;
        edits.push(MapEdit {
            key,
            expected_value_sha256: Some(luma_content::sha256(&old)),
            value: None,
        });
    }
    edits.sort_by(|a, b| a.key.cmp(&b.key));
    next.roots.pending = if verify {
        store.verify_map_inner(&head.roots.pending, &edits, guard)?
    } else {
        store.edit_map(&head.roots.pending, &edits, guard)?
    };
    let key = retired_key(&head.roots.retained, &review.target.transaction_sha256)?;
    if store.get_map(&head.roots.retained, &key, guard)?.is_some() {
        return Err("pending request already has a retirement record".into());
    }
    next.roots.retained = store.set_value(
        &head.roots.retained,
        key,
        Some(&Retirement::of(review)?),
        verify,
        guard,
    )?;
    Ok(next)
}

#[cfg(test)]
#[path = "owner_recovery/tests.rs"]
mod tests;
