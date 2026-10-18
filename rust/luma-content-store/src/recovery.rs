//! Explicit retirement of exact reviewed, uncommitted preparation bytes.
//!
//! No source is guessed, no content version is published, and no byte is
//! deleted. The original directory is moved by a no-replace rename into a
//! bounded owner-generation quarantine. A caller-retained review is the exact
//! recovery receipt input; it is not rollback authority or an authorization.
use crate::{storage, Access, Boundary, Plan, Repository, ResourceBudget, Result};
use luma_content::OwnerBinding;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub const MAX_QUARANTINED_PREPARATIONS: usize = 16;
pub const MAX_PREPARATION_REVIEW_BYTES: usize = 32_768;

/// Stable directory identity; directory timestamps change on approved rename.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationDirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
}

/// Exact regular-file identity, including timestamps and link count.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub links: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationMember {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub identity: PreparationFileIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationDirectory {
    pub name: String,
    pub identity: PreparationDirectoryIdentity,
    pub members: Vec<PreparationMember>,
}

/// All uncommitted inventories and the reconstructed committed-history digest
/// are reviewed together. This does not interpret a partial record as a plan.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationReview {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub outcome_count: u64,
    pub outcome_head_sha256: String,
    pub target: String,
    pub pending: Vec<PreparationDirectory>,
    pub quarantined: Vec<PreparationDirectory>,
    pub review_sha256: String,
}

#[derive(Serialize)]
struct ReviewData<'a> {
    purpose: &'static str,
    schema_version: u32,
    binding: &'a OwnerBinding,
    outcome_count: u64,
    outcome_head_sha256: &'a str,
    target: &'a str,
    pending: &'a [PreparationDirectory],
    quarantined: &'a [PreparationDirectory],
}

impl PreparationReview {
    /// Expected data only; a review/checksum does not establish custody.
    pub fn base_state(&self) -> Result<crate::VerifiedState> {
        self.validate()?;
        let state = crate::VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.outcome_count,
            head_sha256: self.outcome_head_sha256.clone(),
            quarantine_sha256: inventory_digest(&self.binding, &self.quarantined)?,
        };
        state.validate()?;
        Ok(state)
    }
    /// Exact candidate retirement data, never permission to perform the rename.
    pub fn retired_state(&self) -> Result<crate::VerifiedState> {
        self.validate()?;
        let target = self
            .pending
            .iter()
            .find(|entry| entry.name == self.target)
            .ok_or("reviewed retirement target missing")?;
        let mut entries = self.quarantined.clone();
        entries.push(target.clone());
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let state = crate::VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.outcome_count,
            head_sha256: self.outcome_head_sha256.clone(),
            quarantine_sha256: inventory_digest(&self.binding, &entries)?,
        };
        state.validate()?;
        Ok(state)
    }
    fn digest(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&ReviewData {
            purpose: "luma-content-preparation-quarantine-v1",
            schema_version: self.schema_version,
            binding: &self.binding,
            outcome_count: self.outcome_count,
            outcome_head_sha256: &self.outcome_head_sha256,
            target: &self.target,
            pending: &self.pending,
            quarantined: &self.quarantined,
        })?))
    }

    /// Structural integrity only, never proof of approval, identity or custody.
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1
            || !crate::hash(&self.target)
            || !crate::hash(&self.outcome_head_sha256)
            || self.outcome_count > crate::MAX_OUTCOMES as u64
            || self.pending.len() > crate::MAX_PENDING
            || self.quarantined.len() >= MAX_QUARANTINED_PREPARATIONS
            || !self.pending.iter().any(|entry| entry.name == self.target)
            || self
                .quarantined
                .iter()
                .any(|entry| entry.name == self.target)
        {
            return Err("content preparation review is invalid or exceeds its bound".into());
        }
        for entries in [&self.pending, &self.quarantined] {
            let mut prior: Option<&str> = None;
            for entry in entries {
                if !crate::hash(&entry.name)
                    || prior.is_some_and(|name| name >= entry.name.as_str())
                    || entry.identity.mode & 0o7777 != 0o700
                    || entry.members.len() > 3
                {
                    return Err("content preparation directory review is invalid".into());
                }
                prior = Some(&entry.name);
                let mut prior_member: Option<&str> = None;
                for member in &entry.members {
                    if prior_member.is_some_and(|name| name >= member.name.as_str())
                        || member.bytes > member_limit(&member.name)?
                        || !crate::hash(&member.sha256)
                        || member.identity.mode & 0o7777 != 0o400
                        || member.identity.links != 1
                    {
                        return Err("content preparation member review is invalid".into());
                    }
                    prior_member = Some(&member.name);
                }
            }
        }
        if self.pending.iter().any(|pending| {
            self.quarantined
                .iter()
                .any(|saved| saved.name == pending.name)
        }) {
            return Err("content preparation review has overlapping namespaces".into());
        }
        if self.review_sha256 != self.digest()?
            || serde_json::to_vec(self)?.len() > MAX_PREPARATION_REVIEW_BYTES
        {
            return Err("content preparation review digest or byte bound is invalid".into());
        }
        Ok(())
    }

    pub fn retained_bytes(&self) -> Result<u64> {
        self.pending
            .iter()
            .find(|entry| entry.name == self.target)
            .ok_or_else(|| "review target preparation unavailable".into())
            .and_then(directory_bytes)
    }
}

/// A receipt for one exact reviewed retirement, not a publication or export.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparationRecoveryOutcome {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub review_sha256: String,
    pub preparation: String,
    pub retained_bytes: u64,
    pub replayed: bool,
    pub evidence_preserved: bool,
    pub committed_outcomes_unchanged: bool,
    pub rollback_authority: bool,
}

fn member_limit(name: &str) -> Result<u64> {
    match name {
        "record.json" => Ok(crate::MAX_RECORD),
        "payload.json" => Ok(crate::MAX_PAYLOAD),
        "source.bin" => Ok(crate::MAX_SOURCE),
        _ => Err("unknown preparation member; preserve evidence".into()),
    }
}

fn directory_identity(metadata: &Metadata) -> PreparationDirectoryIdentity {
    PreparationDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode(),
    }
}

fn file_identity(metadata: &Metadata) -> PreparationFileIdentity {
    PreparationFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn directory_bytes(directory: &PreparationDirectory) -> Result<u64> {
    directory.members.iter().try_fold(0_u64, |sum, member| {
        sum.checked_add(member.bytes)
            .ok_or_else(|| "preparation byte accounting overflow".into())
    })
}

fn inspect_member(
    directory: &File,
    name: &str,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<PreparationMember> {
    check()?;
    let mut file = storage::open(directory, name, libc::O_RDONLY, 0)?;
    storage::check_private(&file, false)?;
    let before = file.metadata()?;
    let identity = file_identity(&before);
    if before.mode() & 0o7777 != 0o400 || before.len() > limit {
        return Err("preparation member mode or byte bound invalid".into());
    }
    let mut bytes = Vec::new();
    let mut block = [0_u8; 32 * 1024];
    loop {
        check()?;
        let capacity = limit
            .saturating_sub(bytes.len() as u64)
            .saturating_add(1)
            .min(block.len() as u64) as usize;
        let count = file.read(&mut block[..capacity])?;
        check()?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > limit {
            return Err("preparation member exceeds bounded inspection".into());
        }
        bytes.extend_from_slice(&block[..count]);
    }
    let current = storage::open(directory, name, libc::O_RDONLY, 0)?;
    let after = file.metadata()?;
    if before.len() != bytes.len() as u64
        || after.len() != before.len()
        || identity != file_identity(&after)
        || identity != file_identity(&current.metadata()?)
        || current.metadata()?.len() != before.len()
    {
        return Err("preparation member identity changed during inspection".into());
    }
    check()?;
    Ok(PreparationMember {
        name: name.into(),
        bytes: bytes.len() as u64,
        sha256: luma_content::sha256(&bytes),
        identity,
    })
}

fn inventory(
    repository: &Repository,
    parent: &File,
    limit: usize,
    plan: Option<&Plan>,
    boundary: &mut impl Boundary,
) -> Result<Vec<PreparationDirectory>> {
    let mut check = || storage::repository_check(repository, plan, boundary);
    check()?;
    storage::check_private(parent, true)?;
    let names = storage::names(parent, limit)?;
    let mut result = Vec::new();
    let mut total = 0_u64;
    for name in &names {
        check()?;
        if !crate::hash(name) {
            return Err("unknown preparation namespace member; preserve evidence".into());
        }
        let dir = storage::directory(parent, name)?;
        let before = directory_identity(&dir.metadata()?);
        let members = storage::names(&dir, 3)?;
        let mut inspected = Vec::new();
        for member in &members {
            check()?;
            let inspected_member = inspect_member(
                &dir,
                member,
                member_limit(member)?.min(crate::MAX_REPOSITORY_BYTES - total),
                &mut check,
            )?;
            total += inspected_member.bytes;
            inspected.push(inspected_member);
        }
        check()?;
        if storage::names(&dir, 3)? != members
            || before != directory_identity(&dir.metadata()?)
            || before != directory_identity(&storage::directory(parent, name)?.metadata()?)
        {
            return Err("preparation directory changed during inspection".into());
        }
        result.push(PreparationDirectory {
            name: name.clone(),
            identity: before,
            members: inspected,
        });
    }
    check()?;
    if storage::names(parent, limit)? != names {
        return Err("preparation namespace changed during inspection".into());
    }
    Ok(result)
}

// Files were fully hashed by the initial inventory. Recheck their pinned
// kernel identities immediately before rename without charging a fifth full
// repository read. Data mutation changes ctime even if mtime is restored.
fn check_inventory_identity(
    repository: &Repository,
    parent: &File,
    entries: &[PreparationDirectory],
    limit: usize,
    boundary: &mut impl Boundary,
) -> Result<()> {
    storage::repository_check(repository, None, boundary)?;
    if storage::names(parent, limit)?
        != entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>()
    {
        return Err("reviewed preparation namespace changed before retirement".into());
    }
    for entry in entries {
        storage::repository_check(repository, None, boundary)?;
        let dir = storage::directory(parent, &entry.name)?;
        if directory_identity(&dir.metadata()?) != entry.identity
            || storage::names(&dir, 3)?
                != entry
                    .members
                    .iter()
                    .map(|member| member.name.clone())
                    .collect::<Vec<_>>()
        {
            return Err("reviewed preparation directory changed before retirement".into());
        }
        for member in &entry.members {
            storage::repository_check(repository, None, boundary)?;
            let file = storage::open(&dir, &member.name, libc::O_RDONLY, 0)?;
            storage::check_private(&file, false)?;
            let metadata = file.metadata()?;
            if file_identity(&metadata) != member.identity || metadata.len() != member.bytes {
                return Err("reviewed preparation member changed before retirement".into());
            }
        }
    }
    storage::repository_check(repository, None, boundary)
}

fn retire_directory(
    pending: &File,
    quarantine: &File,
    name: &str,
    check: &mut impl FnMut() -> Result<()>,
    renamed: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let name = CString::new(name)?;
    check()?;
    if unsafe {
        libc::renameat2(
            pending.as_raw_fd(),
            name.as_ptr(),
            quarantine.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    renamed()?;
    check()?;
    quarantine.sync_all()?;
    check()?;
    pending.sync_all()?;
    check()
}

/// Both legacy and recovery-capable layouts are exact, closed namespaces.
pub(super) fn layout(root: &File) -> Result<()> {
    let names = storage::names(root, 4)?;
    if names == ["identity.json", "outcomes", "pending"]
        || names == ["identity.json", "outcomes", "pending", "quarantine"]
    {
        Ok(())
    } else {
        Err("incomplete or unknown content-store layout; preserve state".into())
    }
}

fn quarantine_inventory(
    repository: &Repository,
    plan: Option<&Plan>,
    boundary: &mut impl Boundary,
) -> Result<Vec<PreparationDirectory>> {
    storage::repository_check(repository, plan, boundary)?;
    let Some(quarantine) = repository.quarantine.as_ref() else {
        return Ok(Vec::new());
    };
    let pin = directory_identity(&quarantine.metadata()?);
    let entries = inventory(
        repository,
        quarantine,
        MAX_QUARANTINED_PREPARATIONS,
        plan,
        boundary,
    )?;
    storage::repository_check(repository, plan, boundary)?;
    if pin != directory_identity(&storage::directory(&repository.root, "quarantine")?.metadata()?) {
        return Err("quarantine namespace identity changed".into());
    }
    Ok(entries)
}

/// Account and validate quarantined forensic bytes in every ordinary snapshot.
pub(super) fn validate_quarantine(
    repository: &Repository,
    plan: Option<&Plan>,
    boundary: &mut impl Boundary,
) -> Result<(u64, String, Vec<String>)> {
    let inventory = quarantine_inventory(repository, plan, boundary)?;
    let bytes = inventory
        .iter()
        .try_fold(0_u64, |total, entry| -> Result<u64> {
            if storage::names(&repository.pending, crate::MAX_PENDING)?.contains(&entry.name)
                || storage::names(&repository.outcomes, crate::MAX_OUTCOMES)?.contains(&entry.name)
            {
                return Err("quarantined preparation also exists in a live namespace".into());
            }
            total
                .checked_add(directory_bytes(entry)?)
                .filter(|value| *value <= crate::MAX_REPOSITORY_BYTES)
                .ok_or_else(|| "quarantine byte capacity exhausted".into())
        })?;
    let digest = inventory_digest(&repository.binding, &inventory)?;
    Ok((
        bytes,
        digest,
        inventory.iter().map(|entry| entry.name.clone()).collect(),
    ))
}

pub(super) fn inventory_digest(
    binding: &OwnerBinding,
    inventory: &[PreparationDirectory],
) -> Result<String> {
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-content-verified-quarantine-inventory-v1",
        binding,
        inventory,
    ))?))
}

struct RecoveryBoundary<'a, B> {
    inner: &'a mut B,
    review: &'a PreparationReview,
    retained_bytes: u64,
}

impl<B: Boundary> Boundary for RecoveryBoundary<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.inner.admit(binding, budget)
    }

    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.inner.check(access)?;
        self.inner.check(Access::Recover {
            binding: &self.review.binding,
            review_sha256: &self.review.review_sha256,
            retained_bytes: self.retained_bytes,
        })
    }
}

impl Repository {
    fn preparation_review_state(
        &self,
        review: &PreparationReview,
        boundary: &mut impl Boundary,
        candidate_transition: bool,
    ) -> Result<bool> {
        review.validate()?;
        if review.binding != self.binding {
            return Err("preparation review cannot cross owner or generation".into());
        }
        // Only the actual Recover path can compare this reviewed candidate
        // transition. Ordinary read-only previews retain their selected cut.
        let pending = inventory(self, &self.pending, crate::MAX_PENDING, None, boundary)?;
        let quarantined = quarantine_inventory(self, None, boundary)?;
        let before = pending == review.pending && quarantined == review.quarantined;
        let expected_candidate = if before {
            review.base_state()?
        } else {
            review.retired_state()?
        };
        if candidate_transition {
            let base = review.base_state()?;
            let retired = review.retired_state()?;
            if self
                .expected_state
                .as_ref()
                .is_some_and(|cut| cut != &base && cut != &retired)
            {
                return Err(
                    "selected content state is outside exact reviewed recovery transition".into(),
                );
            }
        }
        let snapshot = if candidate_transition {
            self.snapshot_for_state(None, boundary, Some(&expected_candidate))?
        } else {
            self.snapshot(None, boundary)?
        };
        let records: Vec<_> = snapshot
            .records
            .iter()
            .map(|(record, _, _)| record)
            .collect();
        if snapshot.records.len() as u64 != review.outcome_count
            || luma_content::sha256(&serde_json::to_vec(&(
                "luma-content-verified-outcome-history-v1",
                &self.binding,
                records,
            ))?) != review.outcome_head_sha256
        {
            return Err("committed content head changed since preparation review".into());
        }
        if pending == review.pending && quarantined == review.quarantined {
            return Ok(false);
        }
        let mut expected_pending = review.pending.clone();
        let position = expected_pending
            .iter()
            .position(|entry| entry.name == review.target)
            .ok_or("review target preparation unavailable")?;
        let target = expected_pending.remove(position);
        let mut expected_quarantined = review.quarantined.clone();
        expected_quarantined.push(target);
        expected_quarantined.sort_by(|left, right| left.name.cmp(&right.name));
        if pending != expected_pending || quarantined != expected_quarantined {
            return Err("preparation inventory changed; preserve and review again".into());
        }
        Ok(true)
    }

    /// Validate an externally retained review against exact current state under
    /// Read authority alone. Both the original and already-retired state are
    /// accepted; no directory, file, receipt, or new authority is created.
    pub fn check_preparation_review(
        &self,
        review: &PreparationReview,
        boundary: &mut impl Boundary,
    ) -> Result<()> {
        review.validate()?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        self.preparation_review_state(review, boundary, false)?;
        storage::repository_check(self, None, boundary)
    }

    /// Review only. Missing/unknown/damaged committed data is never repaired.
    pub fn review_preparation(
        &self,
        target: &str,
        boundary: &mut impl Boundary,
    ) -> Result<PreparationReview> {
        if !crate::hash(target) {
            return Err("preparation target must be its exact lowercase hash".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        let records: Vec<_> = snapshot
            .records
            .iter()
            .map(|(record, _, _)| record)
            .collect();
        let head = luma_content::sha256(&serde_json::to_vec(&(
            "luma-content-verified-outcome-history-v1",
            &self.binding,
            records,
        ))?);
        let pending = inventory(self, &self.pending, crate::MAX_PENDING, None, boundary)?;
        let quarantined = quarantine_inventory(self, None, boundary)?;
        let mut review = PreparationReview {
            schema_version: 1,
            binding: self.binding.clone(),
            outcome_count: snapshot.records.len() as u64,
            outcome_head_sha256: head,
            target: target.into(),
            pending,
            quarantined,
            review_sha256: String::new(),
        };
        review.review_sha256 = review.digest()?;
        review.validate()?;
        storage::repository_check(self, None, boundary)?;
        Ok(review)
    }

    /// Retire exactly one reviewed uncommitted preparation without deletion.
    /// Every retry needs fresh live Read/recovery authority for the same review.
    pub fn recover_preparation(
        &mut self,
        review: &PreparationReview,
        boundary: &mut impl Boundary,
    ) -> Result<PreparationRecoveryOutcome> {
        self.recover_preparation_with_hook(review, boundary, |_| Ok(()))
    }

    pub(super) fn recover_preparation_with_hook(
        &mut self,
        review: &PreparationReview,
        boundary: &mut impl Boundary,
        mut hook: impl FnMut(RecoveryPhase) -> Result<()>,
    ) -> Result<PreparationRecoveryOutcome> {
        review.validate()?;
        if review.binding != self.binding {
            return Err("preparation recovery cannot cross owner or generation".into());
        }
        let retained_bytes = review.retained_bytes()?;
        boundary.admit(
            &self.binding,
            ResourceBudget {
                write_bytes: 4096,
                additional_storage_bytes: 4096,
                ..ResourceBudget::inspection()
            },
        )?;
        let mut guarded = RecoveryBoundary {
            inner: boundary,
            review,
            retained_bytes,
        };
        storage::repository_check(self, None, &mut guarded)?;
        let replayed = self.preparation_review_state(review, &mut guarded, true)?;
        let mut expected_pending = review.pending.clone();
        let target_position = expected_pending
            .iter()
            .position(|entry| entry.name == review.target)
            .ok_or("review target preparation unavailable")?;
        let expected_target = expected_pending.remove(target_position);
        let mut expected_quarantined = review.quarantined.clone();
        expected_quarantined.push(expected_target.clone());
        expected_quarantined.sort_by(|left, right| left.name.cmp(&right.name));
        // A retry does not restore an old grant or advance an old content head.
        // The quarantined exact directory is evidence of this same rename.
        let quarantine = if let Some(quarantine) = self.quarantine.as_ref() {
            quarantine.try_clone()?
        } else {
            if replayed {
                return Err("quarantine receipt namespace disappeared".into());
            }
            storage::repository_check(self, None, &mut guarded)?;
            storage::reserve(&self.root, 4096)?;
            let created = storage::mkdir(&self.root, "quarantine")?;
            self.quarantine = Some(created);
            self.quarantine
                .as_ref()
                .ok_or("created quarantine pin unavailable")?
                .try_clone()?
        };
        hook(RecoveryPhase::NamespaceReady)?;
        let quarantine_pin = directory_identity(&quarantine.metadata()?);
        let mut check = || -> Result<()> {
            storage::repository_check(self, None, &mut guarded)?;
            if quarantine_pin
                != directory_identity(&storage::directory(&self.root, "quarantine")?.metadata()?)
            {
                return Err("recovery quarantine namespace changed".into());
            }
            Ok(())
        };
        check()?;
        // Establish the new destination namespace durably before removing a
        // source entry. Syncing only after rename could lose the new parent
        // link while retaining removal from the old directory after power loss.
        quarantine.sync_all()?;
        check()?;
        self.root.sync_all()?;
        check()?;
        if !replayed {
            let target = storage::directory(&self.pending, &review.target)?;
            for member in &expected_target.members {
                storage::repository_check(self, None, &mut guarded)?;
                storage::open(&target, &member.name, libc::O_RDONLY, 0)?.sync_all()?;
                storage::repository_check(self, None, &mut guarded)?;
            }
            target.sync_all()?;
            storage::repository_check(self, None, &mut guarded)?;
            self.pending.sync_all()?;
            storage::repository_check(self, None, &mut guarded)?;
            // Recheck every reviewed member's full inode/timestamp pin before
            // rename. Whole-byte inventories before and after the effect plus
            // both verified snapshots read at most four repository capacities.
            check_inventory_identity(
                self,
                &self.pending,
                &review.pending,
                crate::MAX_PENDING,
                &mut guarded,
            )?;
            check_inventory_identity(
                self,
                &quarantine,
                &review.quarantined,
                MAX_QUARANTINED_PREPARATIONS,
                &mut guarded,
            )?;
            let mut check = || {
                storage::repository_check(self, None, &mut guarded)?;
                if quarantine_pin
                    != directory_identity(
                        &storage::directory(&self.root, "quarantine")?.metadata()?,
                    )
                {
                    return Err("recovery quarantine namespace changed".into());
                }
                Ok(())
            };
            retire_directory(
                &self.pending,
                &quarantine,
                &review.target,
                &mut check,
                || hook(RecoveryPhase::Renamed),
            )?;
        }
        storage::repository_check(self, None, &mut guarded)?;
        // Revalidate every retained byte after rename and before acknowledgment.
        if inventory(self, &self.pending, crate::MAX_PENDING, None, &mut guarded)?
            != expected_pending
            || quarantine_inventory(self, None, &mut guarded)? != expected_quarantined
        {
            return Err("recovery evidence changed before durable acknowledgment".into());
        }
        let wanted = review.retired_state()?;
        let snapshot = self.snapshot_for_state(None, &mut guarded, Some(&wanted))?;
        if snapshot.records.len() as u64 != review.outcome_count {
            return Err("committed content history changed during recovery".into());
        }
        let records: Vec<_> = snapshot
            .records
            .iter()
            .map(|(record, _, _)| record)
            .collect();
        if luma_content::sha256(&serde_json::to_vec(&(
            "luma-content-verified-outcome-history-v1",
            &self.binding,
            records,
        ))?) != review.outcome_head_sha256
        {
            return Err("committed content head changed during recovery".into());
        }
        storage::repository_check(self, None, &mut guarded)?;
        quarantine.sync_all()?;
        storage::repository_check(self, None, &mut guarded)?;
        self.pending.sync_all()?;
        storage::repository_check(self, None, &mut guarded)?;
        self.root.sync_all()?;
        hook(RecoveryPhase::Committed)?;
        storage::repository_check(self, None, &mut guarded)?;
        Ok(PreparationRecoveryOutcome {
            schema_version: 1,
            binding: self.binding.clone(),
            review_sha256: review.review_sha256.clone(),
            preparation: review.target.clone(),
            retained_bytes,
            replayed,
            evidence_preserved: true,
            committed_outcomes_unchanged: true,
            rollback_authority: false,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryPhase {
    NamespaceReady,
    Renamed,
    Committed,
}
