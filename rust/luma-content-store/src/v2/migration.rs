//! Side-by-side, bounded legacy migration. A prefix is C-selected progress DATA,
//! never a selected owner head, a publication receipt or permission to resume.
use super::head::{MigrationProvenance, OwnerHeadV2, PhysicalAccounting};
use super::owner::add_physical;
use super::owner_segment::{Locator, Member};
use super::*;
use crate::{Repository, VerifiedState};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

const DOMAIN_MIGRATION: &str = "luma-owner-migration-v2";
const MAX_INVENTORY: usize = 2048;
const MAX_WINDOWS: usize = 16;
const MAX_RETAINED_WINDOW: usize = 32;
const MAX_CONTROL: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub device: u64,
    pub inode: u64,
    pub mount_id: u64,
    pub bytes: u64,
    pub allocated_bytes: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub modified_seconds: i64,
    pub modified_nanos: i64,
    pub changed_seconds: i64,
    pub changed_nanos: i64,
}
impl SourceIdentity {
    fn capture(file: &File) -> Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            mount_id: mount(file)?,
            bytes: m.len(),
            allocated_bytes: m
                .blocks()
                .checked_mul(512)
                .ok_or("migration allocation overflow")?,
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            links: m.nlink(),
            modified_seconds: m.mtime(),
            modified_nanos: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanos: m.ctime_nsec(),
        })
    }
    fn validate(&self, directory: bool) -> Result<()> {
        let filetype = self.mode & libc::S_IFMT;
        if self.device == 0
            || self.inode == 0
            || self.mount_id == 0
            || self.allocated_bytes % 512 != 0
            || self.links == 0
            || !(0..1_000_000_000).contains(&self.modified_nanos)
            || !(0..1_000_000_000).contains(&self.changed_nanos)
            || if directory {
                filetype != libc::S_IFDIR || self.mode & 0o7777 != 0o700
            } else {
                filetype != libc::S_IFREG || self.mode & 0o7777 != 0o400 || self.links != 1
            }
        {
            return Err("migration source identity has invalid private inode shape".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceArea {
    Root,
    Outcomes,
    Pending,
    Quarantine,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceEntry {
    pub area: SourceArea,
    pub transaction: Option<String>,
    pub member: Option<String>,
    pub identity: SourceIdentity,
    pub sha256: Option<String>,
}
impl SourceEntry {
    pub(super) fn key(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.area,
            &self.transaction,
            &self.member,
        ))?)
    }
    pub(super) fn validate(&self) -> Result<()> {
        if let Some(name) = &self.transaction {
            digest(name)?;
        }
        if let Some(member) = &self.member {
            if !matches!(
                member.as_str(),
                "identity.json" | "record.json" | "source.bin" | "payload.json"
            ) {
                return Err("unknown migration source member".into());
            }
        }
        match (&self.area, &self.transaction, &self.member) {
            (SourceArea::Root, None, None) | (SourceArea::Root, None, Some(_)) => {
                if self.member.as_deref().is_some_and(|m| m != "identity.json") {
                    return Err("migration root contains unknown member".into());
                }
            }
            (SourceArea::Root, _, _) => return Err("migration root transaction forbidden".into()),
            (_, None, Some(_)) => return Err("migration area file lacks transaction".into()),
            (_, Some(_), Some(member)) if member == "identity.json" => {
                return Err("transaction identity member forbidden".into());
            }
            _ => {}
        }
        self.identity.validate(self.member.is_none())?;
        match (&self.sha256, &self.member) {
            (Some(hash), Some(_)) => digest(hash)?,
            (None, None) => {}
            _ => return Err("migration source hash/type mismatch".into()),
        }
        if self.member.is_some() && self.identity.bytes > crate::MAX_PAYLOAD {
            return Err("migration source exceeds legacy member bound".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationReview {
    pub schema_version: u32,
    pub domain: String,
    pub legacy: VerifiedState,
    pub legacy_identity_sha256: String,
    pub inventory_sha256: String,
    pub inventory: Vec<SourceEntry>,
    pub source_bytes: u64,
}
impl MigrationReview {
    pub fn validate(&self) -> Result<()> {
        self.legacy.validate()?;
        digest(&self.legacy_identity_sha256)?;
        digest(&self.inventory_sha256)?;
        if self.schema_version != 2
            || self.domain != DOMAIN_MIGRATION
            || self.inventory.is_empty()
            || self.inventory.len() > MAX_INVENTORY
            || self.source_bytes > crate::MAX_REPOSITORY_BYTES + crate::MAX_RECORD
            || self.inventory_sha256 != luma_content::sha256(&serde_json::to_vec(&self.inventory)?)
        {
            return Err("migration review inventory/bounds differ".into());
        }
        let mut previous = None;
        let mut bytes = 0_u64;
        let mut identity = 0;
        let root = self
            .inventory
            .iter()
            .find(|entry| {
                entry.area == SourceArea::Root
                    && entry.transaction.is_none()
                    && entry.member.is_none()
            })
            .ok_or("migration source root identity absent")?;
        for entry in &self.inventory {
            entry.validate()?;
            if entry.identity.device != root.identity.device
                || entry.identity.mount_id != root.identity.mount_id
            {
                return Err(
                    "migration source traverses a different filesystem or bind mount".into(),
                );
            }
            let key = entry.key()?;
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err("migration source entries are not strictly ordered".into());
            }
            previous = Some(key);
            if entry.member.is_some() {
                bytes = bytes
                    .checked_add(entry.identity.bytes)
                    .ok_or("migration bytes overflow")?;
            }
            if entry.area == SourceArea::Root && entry.member.as_deref() == Some("identity.json") {
                identity += 1;
                if entry.sha256.as_ref() != Some(&self.legacy_identity_sha256) {
                    return Err("migration legacy identity hash differs".into());
                }
            }
        }
        if bytes != self.source_bytes || identity != 1 {
            return Err("migration inventory totals/identity differ".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_CONTROL {
            return Err("migration review too large".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_CONTROL)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationPrefix {
    pub schema_version: u32,
    pub domain: String,
    pub review_sha256: String,
    pub next_outcome: u64,
    pub next_retained_entry: u32,
    pub head: OwnerHeadV2,
    pub head_object_sha256: String,
    pub physical_after: PhysicalInventory,
    pub complete: bool,
}
impl MigrationPrefix {
    pub fn validate(&self, review: &MigrationReview) -> Result<()> {
        review.validate()?;
        self.head.validate()?;
        digest(&self.review_sha256)?;
        digest(&self.head_object_sha256)?;
        let complete = self.next_outcome == review.legacy.outcome_count + 1
            && self.next_retained_entry as usize == review.inventory.len();
        if self.schema_version != 2
            || self.domain != DOMAIN_MIGRATION
            || self.review_sha256 != review.sha256()?
            || self.head.binding != review.legacy.binding
            || self.next_outcome != self.head.history.outcomes + 1
            || self.next_outcome > review.legacy.outcome_count + 1
            || self.next_retained_entry as usize > review.inventory.len()
            || (self.next_outcome <= review.legacy.outcome_count && self.next_retained_entry != 0)
            || self.complete != complete
            || self.head_object_sha256 != self.head.sha256()?
            || self.head.roots.retained.entry_count != u64::from(self.next_retained_entry)
        {
            return Err("migration prefix cursor/head/review differs".into());
        }
        let pending = review.inventory[..self.next_retained_entry as usize]
            .iter()
            .filter(|e| e.area == SourceArea::Pending)
            .count() as u64;
        if self.head.roots.pending.entry_count != pending {
            return Err("migration prefix loses pending source membership".into());
        }
        let provenance = MigrationProvenance {
            legacy: review.legacy.clone(),
            legacy_identity_sha256: review.legacy_identity_sha256.clone(),
            retained_inventory_sha256: review.inventory_sha256.clone(),
        };
        if self.head.migration != if complete { Some(provenance) } else { None } {
            return Err("migration provenance appears before full source retention".into());
        }
        validate_physical(&self.head.physical.observed, &self.physical_after)?;
        Ok(())
    }
    pub fn canonical_bytes(&self, review: &MigrationReview) -> Result<Vec<u8>> {
        self.validate(review)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_CONTROL {
            return Err("migration prefix too large".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8], review: &MigrationReview) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_CONTROL)?;
        value.validate(review)?;
        Ok(value)
    }
}

pub trait MigrationBoundary: Boundary {
    fn current_legacy_state(&mut self, expected: &VerifiedState) -> Result<()>;
    /// Must resolve actual current C progress (or explicitly reserved fresh
    /// namespace) and protected physical counters. Absence never permits adopt.
    fn current_migration_prefix(
        &mut self,
        review: &MigrationReview,
        prefix: Option<&MigrationPrefix>,
    ) -> Result<PhysicalInventory>;
    fn verify_migration_allocations(
        &mut self,
        commitment: &MigrationWindowCommitment,
    ) -> Result<()>;
}

struct Live<'a, B: MigrationBoundary> {
    boundary: &'a mut B,
    legacy: &'a VerifiedState,
    progress: Option<(
        &'a MigrationReview,
        Option<&'a MigrationPrefix>,
        &'a PhysicalInventory,
    )>,
}
impl<B: MigrationBoundary> Live<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.boundary.current_legacy_state(self.legacy)?;
        if let Some((review, prefix, physical)) = self.progress {
            if self.boundary.current_migration_prefix(review, prefix)? != *physical {
                return Err("migration protected progress/accounting changed".into());
            }
        }
        Ok(())
    }
}
impl<B: MigrationBoundary> Boundary for Live<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.current()?;
        self.boundary.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.boundary.check(access)?;
        self.current()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RetainedSource {
    entry: SourceEntry,
    bytes: BlobReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationStep {
    pub head: OwnerHeadV2,
    pub member: BlobReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationWindowCommitment {
    pub schema_version: u32,
    pub domain: String,
    pub review_sha256: String,
    pub previous: Option<MigrationPrefix>,
    pub next: MigrationPrefix,
    pub steps: Vec<MigrationStep>,
    pub retained: Vec<BlobReference>,
    pub physical_before: PhysicalInventory,
}
impl MigrationWindowCommitment {
    pub fn validate(&self, review: &MigrationReview) -> Result<()> {
        self.next.validate(review)?;
        if let Some(prefix) = &self.previous {
            prefix.validate(review)?;
            if prefix.complete {
                return Err("completed migration cannot resume".into());
            }
        }
        let first = self.previous.as_ref().map_or(1, |p| p.next_outcome);
        let retained = self.previous.as_ref().map_or(0, |p| p.next_retained_entry);
        if self.schema_version != 2
            || self.domain != DOMAIN_MIGRATION
            || self.review_sha256 != review.sha256()?
            || self.steps.len() > MAX_WINDOWS
            || self.retained.len() > MAX_RETAINED_WINDOW
            || self.steps.is_empty() && self.retained.is_empty()
            || self.next.next_outcome != first + self.steps.len() as u64
            || self.next.next_retained_entry != retained + self.retained.len() as u32
            || self
                .previous
                .as_ref()
                .is_some_and(|p| p.physical_after != self.physical_before)
        {
            return Err("migration window replay/cursor/bounds mismatch".into());
        }
        for (offset, step) in self.steps.iter().enumerate() {
            step.head.validate()?;
            step.member.validate()?;
            if step.head.binding != review.legacy.binding
                || step.head.history.outcomes != first + offset as u64
                || step.head.migration.is_some()
                || step.member.binding != review.legacy.binding
            {
                return Err("migration chronological step differs".into());
            }
        }
        for reference in &self.retained {
            reference.validate()?;
            if reference.binding != review.legacy.binding {
                return Err("migration retained owner differs".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, review: &MigrationReview) -> Result<Vec<u8>> {
        self.validate(review)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_CONTROL {
            return Err("migration window exceeds control budget".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8], review: &MigrationReview) -> Result<Self> {
        let value: Self = canonical(bytes, MAX_CONTROL)?;
        value.validate(review)?;
        Ok(value)
    }
}

pub struct PreparedMigrationWindow<'a> {
    _writer: File,
    _source: &'a Repository,
    store: &'a ObjectStore,
    commitment: MigrationWindowCommitment,
}
impl PreparedMigrationWindow<'_> {
    pub fn commitment(&self) -> &MigrationWindowCommitment {
        &self.commitment
    }
    pub fn acknowledge_prefix(
        self,
        review: &MigrationReview,
        boundary: &mut impl MigrationBoundary,
    ) -> Result<MigrationPrefix> {
        self.commitment.validate(review)?;
        if self.commitment.next.complete {
            return Err(
                "final migration requires actual selected OwnerBoundary acknowledgement".into(),
            );
        }
        boundary.current_legacy_state(&review.legacy)?;
        if boundary.current_migration_prefix(review, Some(&self.commitment.next))?
            != self.commitment.next.physical_after
        {
            return Err("migration actual selected prefix/accounting differ".into());
        }
        let before = self.commitment.next.physical_after.clone();
        let mut live = Live {
            boundary,
            legacy: &review.legacy,
            progress: Some((review, Some(&self.commitment.next), &before)),
        };
        let mut guard = Guard::new(
            &mut live,
            &review.legacy.binding,
            super::owner::read_budget(),
            None,
        )?;
        if self.store.read_object(
            &self.commitment.next.head_object_sha256,
            MAX_PAGE_BYTES,
            &mut guard,
        )? != self.commitment.next.head.canonical_bytes()?
        {
            return Err("migration selected prefix head changed".into());
        }
        guard.check()?;
        Ok(self.commitment.next.clone())
    }
    pub fn acknowledge_owner(
        self,
        review: &MigrationReview,
        boundary: &mut impl OwnerBoundary,
    ) -> Result<OwnerHeadV2> {
        self.commitment.validate(review)?;
        if !self.commitment.next.complete {
            return Err("incomplete migration cannot become selected owner state".into());
        }
        let head = &self.commitment.next.head;
        boundary.current_owner_head(head)?;
        if boundary.current_physical_accounting(head)? != self.commitment.next.physical_after {
            return Err("final migration C physical accounting differs".into());
        }
        let mut selected = super::owner::Selected { boundary, head };
        let mut guard = Guard::new(
            &mut selected,
            &head.binding,
            super::owner::read_budget(),
            None,
        )?;
        if self.store.read_object(
            &self.commitment.next.head_object_sha256,
            MAX_PAGE_BYTES,
            &mut guard,
        )? != head.canonical_bytes()?
        {
            return Err("final migration selected bytes differ".into());
        }
        guard.check()?;
        Ok(head.clone())
    }
}

/// Exact independently inspected source DATA; not permission to begin migration.
pub fn review_migration(
    source: &Repository,
    expected: &VerifiedState,
    boundary: &mut impl MigrationBoundary,
) -> Result<MigrationReview> {
    expected.validate()?;
    if source.binding != expected.binding {
        return Err("migration legacy owner differs".into());
    }
    let mut live = Live {
        boundary,
        legacy: expected,
        progress: None,
    };
    let mut guard = Guard::new(
        &mut live,
        &expected.binding,
        super::owner::read_budget(),
        None,
    )?;
    let (_, review) = inspect_source(source, expected, &mut guard)?;
    Ok(review)
}

/// Reserve and prepare one finite fresh-authentication window. The actual old
/// Repository remains locked and selected; all new files are side-by-side.
pub fn prepare_migration_window<'a>(
    source: &'a Repository,
    store: &'a ObjectStore,
    review: &MigrationReview,
    previous: Option<&MigrationPrefix>,
    maximum_outcomes: usize,
    maximum_retained: usize,
    budget: IoBudget,
    boundary: &mut impl MigrationBoundary,
) -> Result<PreparedMigrationWindow<'a>> {
    validate_window_inputs(
        source,
        store,
        review,
        previous,
        maximum_outcomes,
        maximum_retained,
    )?;
    let before = boundary.current_migration_prefix(review, previous)?;
    let writer = store.acquire_writer()?;
    if previous.is_none() {
        let mut inspect = Live {
            boundary,
            legacy: &review.legacy,
            progress: Some((review, None, &before)),
        };
        let mut found = false;
        let inventory = store.inventory(
            IoBudget {
                read_bytes: MAX_PAGE_BYTES as u64,
                write_bytes: 0,
                new_files: 0,
            },
            &mut inspect,
            |_| {
                found = true;
                Ok(())
            },
        )?;
        if found
            || inventory != before
            || inventory.regular_files != 1
            || inventory.directories != 2
            || inventory.incomplete_objects != 0
        {
            return Err(
                "migration target is not the exact freshly reserved empty namespace".into(),
            );
        }
    }
    let identity_bytes = review
        .inventory
        .iter()
        .find(|e| e.area == SourceArea::Root && e.member.as_deref() == Some("identity.json"))
        .ok_or("legacy identity missing")?
        .identity
        .bytes;
    let mutation = Mutation {
        review_sha256: review.sha256()?,
        decision: DecisionKind::Published,
        source_bytes: review
            .source_bytes
            .checked_sub(identity_bytes)
            .ok_or("migration source total smaller than identity")?,
    };
    let mut live = Live {
        boundary,
        legacy: &review.legacy,
        progress: Some((review, previous, &before)),
    };
    let mut guard = Guard::new(&mut live, &review.legacy.binding, budget, Some(&mutation))?;
    let (snapshot, actual) = inspect_source(source, &review.legacy, &mut guard)?;
    if actual != *review {
        return Err("migration source changed since exact review".into());
    }
    let mut head = initial_head(store, review, previous, &before, &mut guard)?;
    let start = head.history.outcomes as usize;
    let end = (start + maximum_outcomes).min(snapshot.records.len());
    let mut steps = Vec::new();
    for (record, plan, bytes) in &snapshot.records[start..end] {
        guard.check()?;
        store.reconstruct(&head, record, bytes, &plan.payload, &mut guard)?;
        let payload = store.put_blob(&plan.payload, &mut guard)?;
        let source_ref = store.put_blob(bytes, &mut guard)?;
        let old = head.clone();
        store.apply_record(
            &mut head,
            record,
            bytes,
            &plan.payload,
            &payload,
            &source_ref,
            true,
            &mut guard,
        )?;
        let (requests, segments, last, count) = store.extend_owner_segment(
            &old,
            SegmentInput {
                ordinal: record.sequence,
                record: &serde_json::to_vec(record)?,
                source: bytes,
                payload: &plan.payload,
            },
            &mut guard,
        )?;
        head.roots.requests = requests;
        head.roots.segments = segments;
        head.history = super::head::HistoryCursor {
            outcomes: record.sequence,
            segments: count,
            last_segment: Some(last),
        };
        let locator: Locator = canonical(
            &store
                .get_map(
                    &head.roots.requests,
                    &head
                        .roots
                        .requests
                        .key(record.plan.provenance.request_id.as_bytes())?,
                    &mut guard,
                )?
                .ok_or("migration request missing")?,
            MAX_VALUE_BYTES,
        )?;
        steps.push(MigrationStep {
            head: head.clone(),
            member: locator.member,
        });
    }
    let first = previous.map_or(0, |p| p.next_retained_entry) as usize;
    let stop = if head.history.outcomes == review.legacy.outcome_count {
        (first + maximum_retained).min(review.inventory.len())
    } else {
        first
    };
    let mut retained = Vec::new();
    for entry in &review.inventory[first..stop] {
        let bytes = read_entry(source, entry, &mut guard)?;
        let reference = store.put_blob(&bytes, &mut guard)?;
        retain(store, &mut head, entry, &reference, false, &mut guard)?;
        retained.push(reference);
    }
    if steps.is_empty() && retained.is_empty() {
        return Err("migration window makes no bounded progress".into());
    }
    let complete =
        head.history.outcomes == review.legacy.outcome_count && stop == review.inventory.len();
    if complete {
        verify_final_state(store, &head, &snapshot, review, &mut guard)?;
        head.migration = Some(MigrationProvenance {
            legacy: review.legacy.clone(),
            legacy_identity_sha256: review.legacy_identity_sha256.clone(),
            retained_inventory_sha256: review.inventory_sha256.clone(),
        });
    }
    head.physical =
        PhysicalAccounting::from_observation(add_physical(&before, &guard.allocations)?)?;
    let head_object_sha256 = store.write_object(&head.canonical_bytes()?, &mut guard)?;
    let next = MigrationPrefix {
        schema_version: 2,
        domain: DOMAIN_MIGRATION.into(),
        review_sha256: review.sha256()?,
        next_outcome: head.history.outcomes + 1,
        next_retained_entry: stop as u32,
        head,
        head_object_sha256,
        physical_after: add_physical(&before, &guard.allocations)?,
        complete,
    };
    let commitment = MigrationWindowCommitment {
        schema_version: 2,
        domain: DOMAIN_MIGRATION.into(),
        review_sha256: review.sha256()?,
        previous: previous.cloned(),
        next,
        steps,
        retained,
        physical_before: before.clone(),
    };
    commitment.canonical_bytes(review)?;
    verify_source_unchanged(source, review, &mut guard)?;
    guard.check()?;
    Ok(PreparedMigrationWindow {
        _writer: writer,
        _source: source,
        store,
        commitment,
    })
}

/// Independently reconstruct every changed semantic path and retained byte.
/// Verification neither updates C nor turns a prefix into selected owner state.
pub fn verify_migration_window_data(
    source: &Repository,
    store: &ObjectStore,
    review: &MigrationReview,
    commitment: &MigrationWindowCommitment,
    budget: IoBudget,
    boundary: &mut impl MigrationBoundary,
) -> Result<MigrationPrefix> {
    commitment.validate(review)?;
    validate_window_inputs(
        source,
        store,
        review,
        commitment.previous.as_ref(),
        MAX_WINDOWS,
        MAX_RETAINED_WINDOW,
    )?;
    let before = boundary.current_migration_prefix(review, commitment.previous.as_ref())?;
    if before != commitment.physical_before {
        return Err("migration physical base changed".into());
    }
    boundary.verify_migration_allocations(commitment)?;
    let mut live = Live {
        boundary,
        legacy: &review.legacy,
        progress: Some((review, commitment.previous.as_ref(), &before)),
    };
    let mut guard = Guard::new(&mut live, &review.legacy.binding, budget, None)?;
    let (snapshot, actual) = inspect_source(source, &review.legacy, &mut guard)?;
    if actual != *review {
        return Err("migration original source differs".into());
    }
    let mut head = initial_head(
        store,
        review,
        commitment.previous.as_ref(),
        &before,
        &mut guard,
    )?;
    for step in &commitment.steps {
        let (record, plan, source_bytes) = snapshot
            .records
            .get(head.history.outcomes as usize)
            .ok_or("migration step exceeds legacy history")?;
        let member: Member = canonical(&store.get_blob(&step.member, &mut guard)?, 8192)?;
        if member.ordinal != record.sequence
            || member.request_id != record.plan.provenance.request_id
            || store.get_blob(&member.record, &mut guard)? != serde_json::to_vec(record)?
            || store.get_blob(&member.source, &mut guard)? != *source_bytes
            || store.get_blob(&member.payload, &mut guard)? != plan.payload
        {
            return Err(
                "migration step did not retain exact original record/source/payload".into(),
            );
        }
        store.reconstruct(&head, record, source_bytes, &plan.payload, &mut guard)?;
        let old = head.clone();
        store.apply_record_mode(
            &mut head,
            record,
            source_bytes,
            &plan.payload,
            &member.payload,
            &member.source,
            true,
            true,
            &mut guard,
        )?;
        store.verify_owner_extension(&old, &step.head, &step.member, &member, &mut guard)?;
        head.roots.requests = step.head.roots.requests.clone();
        head.roots.segments = step.head.roots.segments.clone();
        head.history = step.head.history.clone();
        if head != step.head {
            return Err("migration step substitutes unrelated semantic state".into());
        }
    }
    let first = commitment
        .previous
        .as_ref()
        .map_or(0, |p| p.next_retained_entry) as usize;
    for (entry, reference) in review.inventory[first..first + commitment.retained.len()]
        .iter()
        .zip(&commitment.retained)
    {
        if store.get_blob(reference, &mut guard)? != read_entry(source, entry, &mut guard)? {
            return Err("migration retained source bytes changed".into());
        }
        retain(store, &mut head, entry, reference, true, &mut guard)?;
    }
    if commitment.next.complete {
        verify_final_state(store, &head, &snapshot, review, &mut guard)?;
        head.migration = Some(MigrationProvenance {
            legacy: review.legacy.clone(),
            legacy_identity_sha256: review.legacy_identity_sha256.clone(),
            retained_inventory_sha256: review.inventory_sha256.clone(),
        });
    }
    head.physical = commitment.next.head.physical.clone();
    if head != commitment.next.head
        || store.read_object(
            &commitment.next.head_object_sha256,
            MAX_PAGE_BYTES,
            &mut guard,
        )? != head.canonical_bytes()?
    {
        return Err("migration final head differs from independently reconstructed window".into());
    }
    verify_source_unchanged(source, review, &mut guard)?;
    guard.check()?;
    Ok(commitment.next.clone())
}

fn validate_window_inputs(
    source: &Repository,
    store: &ObjectStore,
    review: &MigrationReview,
    previous: Option<&MigrationPrefix>,
    outcomes: usize,
    retained: usize,
) -> Result<()> {
    review.validate()?;
    if source.binding != review.legacy.binding
        || store.binding != review.legacy.binding
        || outcomes > MAX_WINDOWS
        || retained > MAX_RETAINED_WINDOW
        || outcomes == 0 && retained == 0
    {
        return Err("migration source/target/finite window differs".into());
    }
    if let Some(prefix) = previous {
        prefix.validate(review)?;
        if prefix.complete {
            return Err("migration already complete".into());
        }
    }
    Ok(())
}
fn initial_head<B: Boundary>(
    store: &ObjectStore,
    review: &MigrationReview,
    previous: Option<&MigrationPrefix>,
    before: &PhysicalInventory,
    guard: &mut Guard<'_, B>,
) -> Result<OwnerHeadV2> {
    if let Some(prefix) = previous {
        if prefix.physical_after != *before
            || store.read_object(&prefix.head_object_sha256, MAX_PAGE_BYTES, guard)?
                != prefix.head.canonical_bytes()?
        {
            return Err("migration protected prefix bytes/accounting differ".into());
        }
        Ok(prefix.head.clone())
    } else {
        // The genuine C callback and held fresh-writer observation establish
        // this BEFORE-counter selector. The independent verifier must not scan
        // prepared files and pretend they were present in the original base.
        if before.regular_files != 1 || before.directories != 2 || before.incomplete_objects != 0 {
            return Err("migration original namespace was not empty".into());
        }
        OwnerHeadV2::empty_data(&review.legacy.binding, before.clone())
    }
}
fn retain<B: Boundary>(
    store: &ObjectStore,
    head: &mut OwnerHeadV2,
    entry: &SourceEntry,
    bytes: &BlobReference,
    verify: bool,
    guard: &mut Guard<'_, B>,
) -> Result<()> {
    if entry.member.is_some()
        && (bytes.bytes != entry.identity.bytes || Some(&bytes.sha256) != entry.sha256.as_ref())
        || entry.member.is_none() && bytes.bytes != 0
    {
        return Err("migration raw retention byte commitment differs".into());
    }
    let value = RetainedSource {
        entry: entry.clone(),
        bytes: bytes.clone(),
    };
    for pending in [false, true] {
        if pending && entry.area != SourceArea::Pending {
            continue;
        }
        let root = if pending {
            &mut head.roots.pending
        } else {
            &mut head.roots.retained
        };
        let key = root.key(&entry.key()?)?;
        if store.get_map(root, &key, guard)?.is_some() {
            return Err("migration source member already retained".into());
        }
        *root = store.set_value(root, key, Some(&value), verify, guard)?;
    }
    Ok(())
}
fn verify_final_state<B: Boundary>(
    store: &ObjectStore,
    head: &OwnerHeadV2,
    snapshot: &crate::Snapshot,
    review: &MigrationReview,
    guard: &mut Guard<'_, B>,
) -> Result<()> {
    if head.history.outcomes != snapshot.records.len() as u64
        || head.roots.artifacts.entry_count != snapshot.current.len() as u64
        || head.roots.lifecycle.entry_count != snapshot.lifecycle.len() as u64
    {
        return Err("migration lost legacy semantic state".into());
    }
    for (artifact, version) in &snapshot.current {
        let (value, state) = store.current_value(head, artifact, guard)?;
        if value.reference != version.reference()?
            || store.version(&value, guard)? != *version
            || state.wire()
                != *snapshot
                    .lifecycle
                    .get(artifact)
                    .ok_or("legacy lifecycle missing")?
        {
            return Err("migration alters current payload or legacy lifecycle hash".into());
        }
    }
    // Closing migration is bounded by the unchanged legacy256/64MiB profile.
    // Reopen ALL original outcomes and retained sources once before selection;
    // a previously verified window does not excuse later loss or bit corruption.
    for (record, plan, source) in &snapshot.records {
        let copied = store.owner_outcome(head, record.sequence, guard)?;
        if copied.record != serde_json::to_vec(record)?
            || copied.source != *source
            || copied.payload != plan.payload
        {
            return Err("migration completion lost original historical bytes".into());
        }
    }
    for entry in &review.inventory {
        let retained: RetainedSource = store
            .value(
                &head.roots.retained,
                &head.roots.retained.key(&entry.key()?)?,
                guard,
            )?
            .ok_or("migration original retention missing")?;
        if retained.entry != *entry || retained.bytes.binding != head.binding {
            return Err("migration retention metadata differs from reviewed original".into());
        }
        let bytes = store.get_blob(&retained.bytes, guard)?;
        if entry.member.is_none() && !bytes.is_empty()
            || entry.member.is_some()
                && (bytes.len() as u64 != entry.identity.bytes
                    || entry.sha256.as_ref() != Some(&luma_content::sha256(&bytes)))
        {
            return Err("migration retained original bytes are missing or corrupt".into());
        }
        if entry.area == SourceArea::Pending {
            let pending: RetainedSource = store
                .value(
                    &head.roots.pending,
                    &head.roots.pending.key(&entry.key()?)?,
                    guard,
                )?
                .ok_or("migration pending retention missing")?;
            if pending != retained {
                return Err("migration pending metadata retargets retained original".into());
            }
        }
    }
    guard.check()
}
fn validate_physical(observed: &PhysicalInventory, after: &PhysicalInventory) -> Result<()> {
    if observed.regular_files > after.regular_files
        || observed.directories > after.directories
        || observed.logical_bytes > after.logical_bytes
        || observed.allocated_bytes > after.allocated_bytes
        || observed.incomplete_objects != after.incomplete_objects
        || after.regular_files - observed.regular_files > 1
        || after.directories - observed.directories > 2
        || after.logical_bytes - observed.logical_bytes > MAX_PAGE_BYTES as u64
        || after.allocated_bytes - observed.allocated_bytes > 32768
        || after.regular_files > 4_194_304
        || after.directories > 65794
    {
        return Err("migration descriptor exceeds original physical reserve".into());
    }
    Ok(())
}

fn mount(file: &File) -> Result<u64> {
    let mut value: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            b"\0".as_ptr().cast(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            0x1000,
            &mut value,
        )
    } != 0
        || value.stx_mask & 0x1000 == 0
        || value.stx_mnt_id == 0
    {
        return Err("migration requires actual held mount identity".into());
    }
    Ok(value.stx_mnt_id)
}
fn source_check<B: Boundary>(source: &Repository, guard: &mut Guard<'_, B>) -> Result<()> {
    guard.check()?;
    crate::storage::repository_check(source, None, guard.boundary)?;
    guard.check()
}
fn read_source<B: Boundary>(
    source: &Repository,
    dir: &File,
    name: &str,
    guard: &mut Guard<'_, B>,
) -> Result<(Vec<u8>, SourceIdentity)> {
    source_check(source, guard)?;
    let mut file = crate::storage::open(dir, name, libc::O_RDONLY, 0)?;
    crate::storage::check_private(&file, false)?;
    let before = SourceIdentity::capture(&file)?;
    before.validate(false)?;
    if before.bytes > crate::MAX_PAYLOAD || before.mount_id != mount(&source.root)? {
        return Err("migration source size/mount differs".into());
    }
    let check = |file: &File| -> Result<()> {
        if SourceIdentity::capture(file)? != before
            || SourceIdentity::capture(&crate::storage::open(dir, name, libc::O_RDONLY, 0)?)?
                != before
        {
            return Err("migration source changed while held".into());
        }
        Ok(())
    };
    let mut bytes = Vec::with_capacity(before.bytes as usize);
    let mut block = [0_u8; 4096];
    while (bytes.len() as u64) < before.bytes {
        source_check(source, guard)?;
        check(&file)?;
        let capacity = (before.bytes - bytes.len() as u64).min(block.len() as u64) as usize;
        guard.read(capacity as u64)?;
        let n = file.read(&mut block[..capacity])?;
        source_check(source, guard)?;
        check(&file)?;
        if n == 0 {
            return Err("migration source truncated".into());
        }
        bytes.extend_from_slice(&block[..n]);
    }
    guard.read(1)?;
    if file.read(&mut block[..1])? != 0 {
        return Err("migration source grew".into());
    }
    source_check(source, guard)?;
    check(&file)?;
    Ok((bytes, before))
}
fn source_directory(
    source: &Repository,
    area: &SourceArea,
    transaction: Option<&str>,
) -> Result<File> {
    let area_file = match area {
        SourceArea::Root => source.root.try_clone()?,
        SourceArea::Outcomes => source.outcomes.try_clone()?,
        SourceArea::Pending => source.pending.try_clone()?,
        SourceArea::Quarantine => source
            .quarantine
            .as_ref()
            .ok_or("legacy quarantine absent")?
            .try_clone()?,
    };
    if let Some(name) = transaction {
        digest(name)?;
        crate::storage::directory(&area_file, name)
    } else {
        Ok(area_file)
    }
}
fn read_entry<B: Boundary>(
    source: &Repository,
    entry: &SourceEntry,
    guard: &mut Guard<'_, B>,
) -> Result<Vec<u8>> {
    entry.validate()?;
    source_check(source, guard)?;
    let dir = source_directory(source, &entry.area, entry.transaction.as_deref())?;
    let (bytes, identity) = if let Some(name) = &entry.member {
        read_source(source, &dir, name, guard)?
    } else {
        (Vec::new(), SourceIdentity::capture(&dir)?)
    };
    if identity != entry.identity
        || entry
            .sha256
            .as_ref()
            .is_some_and(|h| *h != luma_content::sha256(&bytes))
    {
        return Err("migration source inventory entry changed".into());
    }
    source_check(source, guard)?;
    Ok(bytes)
}
fn inspect_source<B: Boundary>(
    source: &Repository,
    expected: &VerifiedState,
    guard: &mut Guard<'_, B>,
) -> Result<(crate::Snapshot, MigrationReview)> {
    source_check(source, guard)?;
    // The existing fully validating legacy reader is bounded at64MiB. Debit
    // its entire ceiling BEFORE it performs any private read, not afterward.
    guard.read(crate::MAX_REPOSITORY_BYTES + crate::MAX_RECORD)?;
    let snapshot = source.snapshot_for_state(None, guard.boundary, Some(expected))?;
    if VerifiedState::from_snapshot(&source.binding, &snapshot)? != *expected {
        return Err("migration legacy cut differs".into());
    }
    let mut inventory = Vec::new();
    for area in [
        SourceArea::Root,
        SourceArea::Outcomes,
        SourceArea::Pending,
        SourceArea::Quarantine,
    ] {
        if area == SourceArea::Quarantine && source.quarantine.is_none() {
            continue;
        }
        source_check(source, guard)?;
        let dir = source_directory(source, &area, None)?;
        let before = SourceIdentity::capture(&dir)?;
        before.validate(true)?;
        inventory.push(SourceEntry {
            area: area.clone(),
            transaction: None,
            member: None,
            identity: before.clone(),
            sha256: None,
        });
        if area == SourceArea::Root {
            let (bytes, identity) = read_source(source, &dir, "identity.json", guard)?;
            inventory.push(SourceEntry {
                area: area.clone(),
                transaction: None,
                member: Some("identity.json".into()),
                identity,
                sha256: Some(luma_content::sha256(&bytes)),
            });
        } else {
            for transaction in crate::storage::names(
                &dir,
                if area == SourceArea::Outcomes {
                    crate::MAX_OUTCOMES
                } else {
                    crate::MAX_PENDING
                },
            )? {
                digest(&transaction)?;
                let sub = source_directory(source, &area, Some(&transaction))?;
                let sub_before = SourceIdentity::capture(&sub)?;
                sub_before.validate(true)?;
                inventory.push(SourceEntry {
                    area: area.clone(),
                    transaction: Some(transaction.clone()),
                    member: None,
                    identity: sub_before.clone(),
                    sha256: None,
                });
                for name in crate::storage::names(&sub, 3)? {
                    if !matches!(name.as_str(), "record.json" | "source.bin" | "payload.json") {
                        return Err("unknown legacy retained file".into());
                    }
                    let (bytes, identity) = read_source(source, &sub, &name, guard)?;
                    inventory.push(SourceEntry {
                        area: area.clone(),
                        transaction: Some(transaction.clone()),
                        member: Some(name),
                        identity,
                        sha256: Some(luma_content::sha256(&bytes)),
                    });
                }
                if SourceIdentity::capture(&sub)? != sub_before
                    || SourceIdentity::capture(&source_directory(
                        source,
                        &area,
                        Some(&transaction),
                    )?)? != sub_before
                {
                    return Err("legacy source subdirectory changed".into());
                }
            }
        }
        if SourceIdentity::capture(&dir)? != before
            || SourceIdentity::capture(&source_directory(source, &area, None)?)? != before
        {
            return Err("legacy source directory changed".into());
        }
    }
    let mut keyed = inventory
        .into_iter()
        .map(|entry| Ok((entry.key()?, entry)))
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let inventory = keyed
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    let source_bytes =
        inventory
            .iter()
            .filter(|e| e.member.is_some())
            .try_fold(0_u64, |total, e| {
                total
                    .checked_add(e.identity.bytes)
                    .ok_or("migration inventory bytes overflow")
            })?;
    let review = MigrationReview {
        schema_version: 2,
        domain: DOMAIN_MIGRATION.into(),
        legacy: expected.clone(),
        legacy_identity_sha256: luma_content::sha256(&serde_json::to_vec(&crate::identity(
            &source.binding,
        ))?),
        inventory_sha256: luma_content::sha256(&serde_json::to_vec(&inventory)?),
        inventory,
        source_bytes,
    };
    review.canonical_bytes()?;
    source_check(source, guard)?;
    Ok((snapshot, review))
}

fn verify_source_unchanged<B: Boundary>(
    source: &Repository,
    review: &MigrationReview,
    guard: &mut Guard<'_, B>,
) -> Result<()> {
    // Every byte was already read/hash-checked through the held source namespace
    // at window entry. Keep the original repository lock and recheck the full
    // closed namespace and exact inode/mount/ctime/length tuple before delivery.
    // This is not a second private read charged after consumption, nor a claim
    // that root/firmware can never change a file after this observation.
    source_check(source, guard)?;
    crate::recovery::layout(&source.root)?;
    for area in [
        SourceArea::Root,
        SourceArea::Outcomes,
        SourceArea::Pending,
        SourceArea::Quarantine,
    ] {
        if area == SourceArea::Quarantine && source.quarantine.is_none() {
            if review.inventory.iter().any(|entry| entry.area == area) {
                return Err("migration quarantine disappeared".into());
            }
            continue;
        }
        let directory = source_directory(source, &area, None)?;
        let top = review
            .inventory
            .iter()
            .find(|entry| {
                entry.area == area && entry.transaction.is_none() && entry.member.is_none()
            })
            .ok_or("migration area absent from review")?;
        if SourceIdentity::capture(&directory)? != top.identity {
            return Err("migration area changed".into());
        }
        if area == SourceArea::Root {
            continue;
        }
        let mut names = review
            .inventory
            .iter()
            .filter(|entry| {
                entry.area == area && entry.transaction.is_some() && entry.member.is_none()
            })
            .map(|entry| {
                entry
                    .transaction
                    .clone()
                    .ok_or("migration transaction absent")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        names.sort();
        if crate::storage::names(
            &directory,
            if area == SourceArea::Outcomes {
                crate::MAX_OUTCOMES
            } else {
                crate::MAX_PENDING
            },
        )? != names
        {
            return Err("migration area membership changed".into());
        }
        for name in names {
            let sub = source_directory(source, &area, Some(&name))?;
            let mut files = review
                .inventory
                .iter()
                .filter(|entry| entry.area == area && entry.transaction.as_deref() == Some(&name))
                .filter_map(|entry| entry.member.clone())
                .collect::<Vec<_>>();
            files.sort();
            if crate::storage::names(&sub, 3)? != files {
                return Err("migration transaction membership changed".into());
            }
        }
    }
    for entry in &review.inventory {
        source_check(source, guard)?;
        let directory = source_directory(source, &entry.area, entry.transaction.as_deref())?;
        let held = if let Some(name) = &entry.member {
            crate::storage::open(&directory, name, libc::O_RDONLY, 0)?
        } else {
            directory
        };
        crate::storage::check_private(&held, entry.member.is_none())?;
        if SourceIdentity::capture(&held)? != entry.identity {
            return Err("migration source inode changed after hashing".into());
        }
    }
    source_check(source, guard)
}

#[cfg(test)]
#[path = "migration/tests.rs"]
mod tests;
