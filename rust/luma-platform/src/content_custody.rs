//! Protected content history. File digests are data commitments; only the
//! separately enrolled content checkpoint and a fresh original-client guard
//! authorize a transition. An uncertain TPM dispatch is never retried here.
use super::{file_identity, MemberParent, DIRECTORY};
use crate::{
    bundle,
    finite_grants::Audit,
    tpm::{self, Checkpoint},
    Result,
};
use luma_content::{OwnerBinding, VersionReference};
use luma_content_store::{
    DecisionKind, PreparationDirectoryIdentity, PreparationFileIdentity, VerifiedState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

const MAX_JOURNAL: usize = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 1024;
const MAX_FILE: usize = 2 * MAX_JOURNAL + 65536;
const JOURNAL: &str = "history.json";
const PREPARED: &str = "history.prepared.json";
const PUBLISHED: &str = "history.publish.json";

#[path = "content_custody/admin.rs"]
mod admin;
#[path = "content_custody/backup.rs"]
mod backup;
#[path = "content_custody/bootstrap.rs"]
mod bootstrap;
#[path = "content_custody/capacity.rs"]
mod capacity;
pub(crate) use capacity::policy as restore_capacity_policy;
#[path = "content_custody/genesis.rs"]
mod genesis;
#[path = "content_custody/lifecycle.rs"]
mod lifecycle;
#[path = "content_custody/protocol.rs"]
mod protocol;
#[path = "content_custody/recipients.rs"]
mod recipients;
#[path = "content_custody/restore.rs"]
mod restore;
#[path = "content_custody/retire.rs"]
mod retire;
pub(crate) use retire::{
    command as retire_command, prepare_stdin as prepare_retirement_stdin,
    read_request as read_retirement_request, verify_staged as verify_retirement_stage,
};
#[path = "content_custody/signer.rs"]
mod signer;
pub(crate) use admin::command;
#[cfg(test)]
pub(crate) use backup::test_signed_receipt;
pub(crate) use backup::verify_stdin as verify_backup_receipt_stdin;
pub(crate) use backup::Receipt as BackupReceipt;
pub(crate) use bootstrap::command as bootstrap_command;
pub(crate) use genesis::{retain_genesis_statement, validate_genesis_at};
pub(crate) use protocol::{
    backup_cut, backup_receipt, check_output, preparation_cut, publish, quarantine, recovery_cut,
    restore_preparation_cut, restore_publish, restore_start, restore_status, run, selected,
    GuardRequest,
};
pub(crate) use recipients::{
    command as recipients_command, read_request as read_recipient_request,
    verify_staged as verify_recipient_stage, MAX_REQUEST as MAX_RECIPIENT_REQUEST,
};
pub(crate) use signer::signer_command;
pub(crate) fn admin_scope(command: &str, usage: &crate::finite_grants::Use) -> Result<()> {
    if matches!(command, retire::INSPECT | retire::RETIRE) {
        retire::scope(command, usage)
    } else if command == "content-backup-recipients-enroll" {
        recipients::scope(command, usage)
    } else {
        signer::admin_scope(command, usage)
    }
}
#[cfg(test)]
#[path = "content_custody/integration_tests.rs"]
mod integration_tests;
pub(crate) fn verify_broker(socket: &std::os::unix::net::UnixStream) -> Result<()> {
    protocol::peer_label(socket, "luma-broker (enforce)")
}

fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}
fn digest(value: &str) -> Result<()> {
    if tpm::decode::<32>(value)? == [0; 32] {
        return Err("empty content custody digest".into());
    }
    Ok(())
}
fn canonical<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("content custody data exceeds its closed bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical content custody data".into());
    }
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Namespace {
    name: String,
    identity: PreparationDirectoryIdentity,
    mount_id: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    name: String,
    bytes: u64,
    sha256: String,
    identity: PreparationFileIdentity,
    mount_id: u64,
}

/// A strict transport copy, deliberately not a store PreparedPublication token.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldPublication {
    schema_version: u32,
    purpose: String,
    binding: OwnerBinding,
    request_id: String,
    review_sha256: String,
    decision: DecisionKind,
    resulting: VersionReference,
    base_outcome_count: u64,
    outcome_count: u64,
    base_head_sha256: String,
    outcome_head_sha256: String,
    quarantine_sha256: String,
    already_published: bool,
    namespaces: Vec<Namespace>,
    directory: PreparationDirectoryIdentity,
    directory_mount_id: u64,
    members: Vec<Member>,
}
impl HeldPublication {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 32768)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        let expected = if self.already_published {
            self.base_outcome_count
        } else {
            self.base_outcome_count
                .checked_add(1)
                .ok_or("content count overflow")?
        };
        if self.schema_version != 1
            || self.purpose != "luma-content-held-publication-v1"
            || self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self.request_id.as_bytes()[0].is_ascii_alphanumeric()
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || self.outcome_count != expected
            || self.outcome_count == 0
            || self.outcome_count > 256
            || self.directory_mount_id == 0
            || self.namespaces.len() < 4
            || self.namespaces.len() > 5
            || self.members.len() != 3
        {
            return Err("invalid exact held content publication".into());
        }
        for value in [
            &self.review_sha256,
            &self.base_head_sha256,
            &self.outcome_head_sha256,
            &self.quarantine_sha256,
            &self.resulting.content_sha256,
            &self.resulting.receipt_sha256,
        ] {
            digest(value)?;
        }
        if self.resulting.artifact_id.is_empty()
            || self.resulting.artifact_id.len() > 128
            || self.resulting.version == 0
            || (self.already_published && self.base_head_sha256 != self.outcome_head_sha256)
        {
            return Err("invalid resulting content reference or replay cut".into());
        }
        let names = ["base", "owner", "pending", "outcomes", "quarantine"];
        for (index, namespace) in self.namespaces.iter().enumerate() {
            if namespace.name != names[index] || namespace.mount_id != self.directory_mount_id {
                return Err("held content namespace order or mount differs".into());
            }
            directory(&namespace.identity)?;
        }
        directory(&self.directory)?;
        for (member, name) in self
            .members
            .iter()
            .zip(["payload.json", "record.json", "source.bin"])
        {
            if member.name != name
                || member.mount_id != self.directory_mount_id
                || member.identity.owner != 0
                || member.identity.mode & 0o177777 != 0o100400
                || member.identity.links != 1
                || member.identity.inode == 0
                || member.identity.device != self.directory.device
                || member.bytes > 24 * 1024 * 1024
                || !(0..1_000_000_000).contains(&member.identity.modified_nanoseconds)
                || !(0..1_000_000_000).contains(&member.identity.changed_nanoseconds)
            {
                return Err("invalid exact held content member".into());
            }
            digest(&member.sha256)?;
        }
        if self.members[1].bytes == 0 || self.members[1].bytes > 8192 {
            return Err("held content record exceeds canonical record bound".into());
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> &OwnerBinding {
        &self.binding
    }
    pub(crate) fn base(&self) -> VerifiedState {
        VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.base_outcome_count,
            head_sha256: self.base_head_sha256.clone(),
            quarantine_sha256: self.quarantine_sha256.clone(),
        }
    }
    pub(crate) fn outcome(&self) -> VerifiedState {
        VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.outcome_count,
            head_sha256: self.outcome_head_sha256.clone(),
            quarantine_sha256: self.quarantine_sha256.clone(),
        }
    }
}
fn directory(value: &PreparationDirectoryIdentity) -> Result<()> {
    if value.owner != 0 || value.inode == 0 || value.mode & 0o177777 != 0o040700 {
        return Err("unsafe held content directory identity".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    schema_version: u32,
    purpose: String,
    commitment: String,
    record: String,
    profile: String,
    storage_device: String,
    original_authority: Audit,
}
impl Publication {
    fn validate(&self) -> Result<HeldPublication> {
        if self.schema_version != 1
            || self.purpose != "luma-content-custody-publication-v1"
            || self.record.len() > 8192
        {
            return Err("invalid protected content publication event".into());
        }
        let held = HeldPublication::parse(self.commitment.as_bytes())?;
        self.original_authority.validate()?;
        let is_restore = self.profile.starts_with(crate::content_restore::PREFIX);
        if is_restore {
            restore::authority(
                &self.profile,
                &self.storage_device,
                &held.binding,
                &self.original_authority,
            )?;
        }
        if !is_restore
            && (self.original_authority.subject != held.binding.owner
                || self.original_authority.subject_generation != held.binding.owner_generation
                || self.original_authority.usage
                    != crate::content_governed::custody_usage(
                        &self.profile,
                        &self.storage_device,
                        &held.binding,
                        &held.review_sha256,
                    )?
                || self.original_authority.usage.selector.id != "native-content-store-v1"
                || self.original_authority.usage.selector.generation
                    != held.binding.owner_generation
                || self.original_authority.operation_id.is_none())
        {
            return Err(
                "content event is not bound to its original finite principal/review".into(),
            );
        }
        use crate::finite_grants::Action;
        let action = match held.decision {
            DecisionKind::Published => Action::Write,
            DecisionKind::ConflictRetained | DecisionKind::NoChangeRetained => Action::Retain,
        };
        if self.original_authority.usage.action != action
            || held.already_published
            || hash(self.record.as_bytes()) != held.members[1].sha256
            || self.record.len() as u64 != held.members[1].bytes
        {
            return Err("content publication record, action or ordinal differs".into());
        }
        // These are comparisons only, never a Value-based replacement for the
        // store's closed canonical Record/history validator below.
        let record: serde_json::Value = serde_json::from_str(&self.record)?;
        let plan = &record["plan"];
        if record["sequence"].as_u64() != Some(held.outcome_count)
            || record["review_sha256"].as_str() != Some(&held.review_sha256)
            || plan["provenance"]["request_id"].as_str() != Some(&held.request_id)
            || serde_json::from_value::<OwnerBinding>(plan["binding"].clone())? != held.binding
            || serde_json::from_value::<VersionReference>(plan["resulting"].clone())?
                != held.resulting
            || serde_json::from_value::<DecisionKind>(plan["decision"].clone())? != held.decision
            || plan["source_bytes"].as_u64() != Some(held.members[2].bytes)
            || plan["source_sha256"].as_str() != Some(&held.members[2].sha256)
            || plan["payload_bytes"].as_u64() != Some(held.members[0].bytes)
            || plan["payload_sha256"].as_str() != Some(&held.members[0].sha256)
        {
            return Err("held publication disagrees with its exact canonical Record fields".into());
        }
        Ok(held)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "entry",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum Event {
    RestoreRetired(retire::Retirement),
    RestoreStart(restore::Start),
    RestorePublication(restore::Publication),
    Backup(backup::Body),
    Publication(Publication),
    ReceiptSigner(signer::Enrollment),
    Quarantine(Quarantine),
    Recipients(recipients::Enrollment),
}
impl Event {
    fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(&(
            "luma-content-custody-event-v1",
            self,
        ))?)
        .into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Quarantine {
    schema_version: u32,
    purpose: String,
    review: luma_content_store::PreparationReview,
    profile: String,
    storage_device: String,
    original_authority: Audit,
}
impl Quarantine {
    fn validate(&self) -> Result<()> {
        self.review.validate()?;
        self.original_authority.validate()?;
        if self.schema_version != 1
            || self.purpose != "luma-content-custody-quarantine-v1"
            || self.original_authority.subject != self.review.binding.owner
            || self.original_authority.subject_generation != self.review.binding.owner_generation
            || self.original_authority.operation_id.is_none()
            || self.original_authority.usage
                != crate::content_governed::custody_usage(
                    &self.profile,
                    &self.storage_device,
                    &self.review.binding,
                    &self.review.review_sha256,
                )?
            || self.original_authority.usage.selector.id != "native-content-recovery-v1"
            || self.original_authority.usage.action != crate::finite_grants::Action::Retain
        {
            return Err(
                "quarantine event differs from its exact original reviewed retention scope".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparationCut {
    pub current: VerifiedState,
    pub prior_base: Option<VerifiedState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    purpose: String,
    installation: String,
    genesis_event: String,
    events: Vec<Event>,
}
struct Validated {
    checkpoint: [u8; 32],
    owners: BTreeMap<String, VerifiedState>,
    records: BTreeMap<String, Vec<Vec<u8>>>,
    signer: Option<signer::Enrollment>,
    recipients: BTreeMap<String, recipients::Enrollment>,
    restores: BTreeMap<String, restore::Start>,
    retired: BTreeSet<String>,
}
fn owner_key(binding: &OwnerBinding) -> Result<String> {
    Ok(luma_content_store::domain_name(binding)?)
}
impl Journal {
    fn require_identity(&self, installation: &str, genesis: [u8; 32]) -> Result<()> {
        if self.installation != installation || self.genesis_event != bundle::hex(&genesis) {
            return Err(
                "content journal metadata differs from independently sealed installation/genesis"
                    .into(),
            );
        }
        Ok(())
    }
    fn empty(installation: &str, genesis: [u8; 32]) -> Result<Self> {
        digest(installation)?;
        if genesis == [0; 32] {
            return Err("empty content genesis".into());
        }
        Ok(Self {
            schema_version: 1,
            purpose: "luma-content-custody-history-v1".into(),
            installation: installation.into(),
            genesis_event: bundle::hex(&genesis),
            events: Vec::new(),
        })
    }
    fn validate(&self) -> Result<Validated> {
        digest(&self.installation)?;
        digest(&self.genesis_event)?;
        if self.schema_version != 1
            || self.purpose != "luma-content-custody-history-v1"
            || self.events.len() > MAX_EVENTS
        {
            return Err("invalid protected content journal".into());
        }
        let mut validated = Validated {
            checkpoint: tpm::extend_value([0; 32], tpm::decode(&self.genesis_event)?),
            owners: BTreeMap::new(),
            records: BTreeMap::new(),
            signer: None,
            recipients: BTreeMap::new(),
            restores: BTreeMap::new(),
            retired: BTreeSet::new(),
        };
        let mut requests = BTreeSet::new();
        let mut backup_jobs = BTreeSet::new();
        for event in &self.events {
            let publication = match event {
                Event::RestoreRetired(value) => {
                    retire::validate_event(value, &self.installation, &mut validated)?;
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::RestoreStart(value) => {
                    restore::start_event(value, &self.installation, &mut validated)?;
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::RestorePublication(value) => {
                    restore::publication_event(value, &validated)?;
                    &value.entry
                }
                Event::Backup(body) => {
                    backup::validate_event(body, &self.installation, &validated)?;
                    if !backup_jobs.insert(body.job()?) {
                        return Err(
                            "protected backup history repeats an original export job".into()
                        );
                    }
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::Recipients(enrollment) => {
                    enrollment.validate(&self.installation)?;
                    let key = owner_key(&enrollment.request.binding)?;
                    let previous = validated
                        .recipients
                        .get(&key)
                        .map_or(0, |value| value.generation);
                    if enrollment.request.expected_generation != previous {
                        return Err("recipient event has discontinuous custody generation".into());
                    }
                    validated.recipients.insert(key, enrollment.clone());
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::Quarantine(quarantine) => {
                    quarantine.validate()?;
                    if quarantine.review.binding.installation != self.installation {
                        return Err("cross-installation protected quarantine".into());
                    }
                    let key = owner_key(&quarantine.review.binding)?;
                    restore::ordinary_publication(
                        &quarantine.review.binding,
                        "quarantine",
                        &validated,
                    )?;
                    let current = match validated.owners.get(&key) {
                        Some(value) => value.clone(),
                        None => VerifiedState::empty(&quarantine.review.binding)?,
                    };
                    if current != quarantine.review.base_state()? {
                        return Err(
                            "quarantine event does not extend exact protected owner cut".into()
                        );
                    }
                    validated
                        .owners
                        .insert(key, quarantine.review.retired_state()?);
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::ReceiptSigner(enrollment) => {
                    enrollment.validate(&self.installation)?;
                    if validated.signer.is_some() {
                        return Err("receipt signer already enrolled; key replacement requires a separate reviewed rotation".into());
                    }
                    validated.signer = Some(enrollment.clone());
                    validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
                    continue;
                }
                Event::Publication(publication) => {
                    let held = publication.validate()?;
                    restore::ordinary_publication(&held.binding, &publication.profile, &validated)?;
                    publication
                }
            };
            let held = publication.validate()?;
            if held.binding.installation != self.installation {
                return Err("cross-installation content history".into());
            }
            let key = owner_key(&held.binding)?;
            let base = match validated.owners.get(&key) {
                Some(state) => state.clone(),
                None => VerifiedState::empty(&held.binding)?,
            };
            if base != held.base() || !requests.insert((key.clone(), held.request_id.clone())) {
                return Err(
                    "content checkpoint history is discontinuous or reuses a request".into(),
                );
            }
            let records = validated.records.entry(key.clone()).or_default();
            records.push(publication.record.as_bytes().to_vec());
            if luma_content_store::canonical_record_history_head(&held.binding, records)?
                != held.outcome_head_sha256
            {
                return Err(
                    "content event does not extend the exact anchored canonical record history"
                        .into(),
                );
            }
            validated.owners.insert(key, held.outcome());
            validated.checkpoint = tpm::extend_value(validated.checkpoint, event.digest()?);
        }
        Ok(validated)
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_JOURNAL {
            return Err(
                "protected content journal capacity exhausted; no truncation or reset".into(),
            );
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    schema_version: u32,
    purpose: String,
    before_sha256: String,
    before_checkpoint: String,
    after_checkpoint: String,
    previous: Journal,
    next: Journal,
}
impl Prepared {
    fn validate(&self, current: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let before = &self.previous;
        let before_bytes = before.bytes()?;
        if current != before_bytes && current != self.next.bytes()? {
            return Err("current content journal matches neither reviewed prepared cut".into());
        }
        let before_state = before.validate()?;
        let after_state = self.next.validate()?;
        if self.schema_version != 1
            || self.purpose != "luma-content-custody-prepared-v1"
            || hash(&before_bytes) != self.before_sha256
            || bundle::hex(&before_state.checkpoint) != self.before_checkpoint
            || bundle::hex(&after_state.checkpoint) != self.after_checkpoint
            || self.next.installation != before.installation
            || self.next.genesis_event != before.genesis_event
            || self.next.events.len() != before.events.len() + 1
            || serde_json::to_vec(&self.next.events[..before.events.len()])?
                != serde_json::to_vec(&before.events)?
        {
            return Err(
                "prepared content authority cut is not the exact one-event continuation".into(),
            );
        }
        Ok((before_state.checkpoint, after_state.checkpoint))
    }
}

/// All operations use held, root-owned, same-mount private parent descriptors.
/// Staging survives a refused checkpoint and is never cleaned up automatically.
pub(crate) struct Files {
    root: PathBuf,
}
impl Files {
    fn installed() -> Self {
        Self {
            root: PathBuf::from(DIRECTORY),
        }
    }
    fn read(&self, name: &str, check: &mut impl FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        let path = self.root.join(name);
        let parent = MemberParent::capture(&path)?;
        let mut file = parent.open(&path, libc::O_RDONLY, 0)?;
        let before = parent.member(&file, MAX_FILE as u64)?;
        if before.len() == 0 {
            return Err("empty protected content member".into());
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        let mut chunk = [0u8; 32768];
        loop {
            check()?;
            parent.check()?;
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            if bytes
                .len()
                .checked_add(count)
                .map_or(true, |v| v > MAX_FILE)
            {
                return Err("oversized protected content member".into());
            }
            bytes.extend_from_slice(&chunk[..count]);
            check()?;
        }
        let current = parent.open(&path, libc::O_RDONLY, 0)?;
        if bytes.len() as u64 != before.len()
            || file_identity(&before) != file_identity(&parent.member(&file, before.len())?)
            || file_identity(&before) != file_identity(&parent.member(&current, before.len())?)
        {
            return Err("protected content history changed while captured".into());
        }
        check()?;
        parent.check()?;
        Ok(bytes)
    }
    fn absent(&self, name: &str) -> Result<()> {
        super::absent(&self.root.join(name))
    }
    fn create(
        &self,
        name: &str,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_FILE {
            return Err("protected content staging exceeds bound".into());
        }
        check()?;
        let path = self.root.join(name);
        let parent = MemberParent::capture(&path)?;
        let mut file = parent.open(&path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o400)?;
        parent.member(&file, 0)?;
        for chunk in bytes.chunks(32768) {
            check()?;
            parent.check()?;
            file.write_all(chunk)?;
            check()?;
        }
        file.sync_all()?;
        check()?;
        parent.file.sync_all()?;
        check()?;
        if self.read(name, check)? != bytes {
            return Err("protected content staging readback differs".into());
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        let path = self.root.join(from);
        let parent = MemberParent::capture(&path)?;
        let source = std::ffi::CString::new(from)?;
        let target = std::ffi::CString::new(to)?;
        parent.check()?;
        if unsafe {
            libc::renameat(
                parent.file.as_raw_fd(),
                source.as_ptr(),
                parent.file.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        check()?;
        parent.file.sync_all()?;
        check()?;
        parent.check()
    }
    fn retire(&self, name: &str, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        let path = self.root.join(name);
        let parent = MemberParent::capture(&path)?;
        let name = std::ffi::CString::new(name)?;
        if unsafe { libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        check()?;
        parent.file.sync_all()?;
        check()?;
        parent.check()
    }
}

/// Only the explicit empty-namespace Admin enrollment calls this function.
/// A runtime opener never synthesizes this file, including for an empty store.
pub(crate) fn initialize_empty(
    anchor: &mut super::ContentAnchor,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    validate_genesis_at(
        std::path::Path::new(DIRECTORY),
        anchor.installation(),
        anchor.genesis_event(),
    )?;
    check()?;
    let empty = Journal::empty(anchor.installation(), anchor.genesis_event())?;
    let wanted = empty.bytes()?;
    let files = Files::installed();
    files.absent(PREPARED)?;
    files.absent(PUBLISHED)?;
    if anchor.read()? != empty.validate()?.checkpoint {
        return Err("empty content journal cannot adopt advanced authority".into());
    }
    match fs::symlink_metadata(files.root.join(JOURNAL)) {
        Ok(_) => {
            if files.read(JOURNAL, check)? != wanted {
                return Err("existing content journal is not exact enrolled empty genesis".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            files.create(JOURNAL, &wanted, check)?
        }
        Err(error) => return Err(error.into()),
    }
    check()?;
    if anchor.read()? != empty.validate()?.checkpoint {
        return Err("content authority changed during empty journal enrollment".into());
    }
    Ok(())
}

/// Genuine Admin status consumes the already authenticated independently
/// pinned C anchor. It never synthesizes history or admits a pending cut.
pub(crate) fn status_with_anchor(
    anchor: super::ContentAnchor,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    check()?;
    let installation = anchor.installation().to_string();
    let genesis = anchor.genesis_event();
    let mut store = Store::from_anchor(anchor, Files::installed(), check)?;
    if store.journal.installation != installation
        || store.journal.genesis_event != bundle::hex(&genesis)
    {
        return Err("content status journal differs from authenticated sealed genesis".into());
    }
    store.status_data(check)
}

pub(crate) struct Store<A: Checkpoint> {
    anchor: A,
    files: Files,
    journal: Journal,
    bytes: Vec<u8>,
    state: Validated,
    poisoned: bool,
    genesis_proof: Option<Vec<u8>>,
}
impl Store<super::ContentAnchor> {
    pub(crate) fn installed(check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        let anchor = super::ContentAnchor::installed()?;
        Self::from_anchor(anchor, Files::installed(), check)
    }
    fn from_anchor(
        anchor: super::ContentAnchor,
        files: Files,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let installation = anchor.installation().to_string();
        let genesis = anchor.genesis_event();
        let mut store = Self::open(anchor, files, check)?;
        store.journal.require_identity(&installation, genesis)?;
        validate_genesis_at(&store.files.root, &installation, genesis)?;
        let proof = store.files.read("genesis.json", check)?;
        genesis::validate(&proof, &installation, genesis)?;
        store.genesis_proof = Some(proof);
        store.live(check)?;
        Ok(store)
    }
}
impl<A: Checkpoint> Store<A> {
    fn status_data(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<serde_json::Value> {
        self.live(check)?;
        let lifecycle = lifecycle::Assessment::capture(&self.journal, &self.bytes, &self.state)?;
        let lifecycle_sha256 = lifecycle.sha256()?;
        let status = serde_json::json!({"schema_version":1,"installation":self.journal.installation,
            "genesis_event":self.journal.genesis_event,"checkpoint_head":bundle::hex(&self.state.checkpoint),
            "events":self.journal.events.len(),"owner_domains":self.state.owners.len(),
            "journal_sha256":hash(&self.bytes),"pending":false,"content_bytes_changed":false,
            "lifecycle_assessment":lifecycle,"lifecycle_assessment_sha256":lifecycle_sha256,
            "authority_returned":false,"production_qualified":false});
        if serde_json::to_vec(&status)?.len() > 8192 {
            return Err("custody status exceeds its existing finite Admin output bound".into());
        }
        self.live(check)?;
        Ok(status)
    }
    pub(crate) fn preparation_cut(
        &mut self,
        binding: &OwnerBinding,
        profile: &str,
        device: &str,
        request_id: &str,
        review: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PreparationCut> {
        audit.validate()?;
        if audit.subject != binding.owner
            || audit.subject_generation != binding.owner_generation
            || audit.operation_id.is_none()
            || audit.usage
                != crate::content_governed::custody_usage(profile, device, binding, review)?
            || audit.usage.selector.id != "native-content-store-v1"
            || !matches!(
                audit.usage.action,
                crate::finite_grants::Action::Write | crate::finite_grants::Action::Retain
            )
        {
            return Err(
                "publication reconciliation requires its exact original current effect proof"
                    .into(),
            );
        }
        let current = self.selected(binding, check)?;
        let mut prior_base = None;
        for event in &self.journal.events {
            if let Event::Publication(entry) = event {
                let held = entry.validate()?;
                if held.binding == *binding && held.request_id == request_id {
                    if held.review_sha256 != review
                        || entry.profile != profile
                        || entry.storage_device != device
                        || entry.original_authority.usage != audit.usage
                    {
                        return Err("publication retry substitutes a different original request/source/review".into());
                    }
                    if held.outcome() == current {
                        prior_base = Some(held.base());
                    }
                }
            }
        }
        self.live(check)?;
        Ok(PreparationCut {
            current,
            prior_base,
        })
    }
    pub(crate) fn recovery_cut(
        &mut self,
        review: &luma_content_store::PreparationReview,
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PreparationCut> {
        let event = Quarantine {
            schema_version: 1,
            purpose: "luma-content-custody-quarantine-v1".into(),
            review: review.clone(),
            profile: profile.into(),
            storage_device: device.into(),
            original_authority: audit.clone(),
        };
        event.validate()?;
        let current = self.selected(&review.binding, check)?;
        let base = review.base_state()?;
        let wanted = review.retired_state()?;
        if current == base {
            return Ok(PreparationCut {
                current,
                prior_base: None,
            });
        }
        let prior=self.journal.events.iter().any(|entry|matches!(entry,Event::Quarantine(value) if value.review==*review && value.profile==profile && value.storage_device==device && value.original_authority.usage==audit.usage));
        if current != wanted || !prior {
            return Err("recovery retry is not the exact previously anchored retirement".into());
        }
        self.live(check)?;
        Ok(PreparationCut {
            current,
            prior_base: Some(base),
        })
    }
    pub(crate) fn quarantine(
        &mut self,
        review: &luma_content_store::PreparationReview,
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        let cut = self.recovery_cut(review, profile, device, audit, check)?;
        let wanted = review.retired_state()?;
        if cut.current == wanted {
            self.live(check)?;
            return Ok(wanted);
        }
        let event = Quarantine {
            schema_version: 1,
            purpose: "luma-content-custody-quarantine-v1".into(),
            review: review.clone(),
            profile: profile.into(),
            storage_device: device.into(),
            original_authority: audit.clone(),
        };
        self.commit(Event::Quarantine(event), check)?;
        self.live(check)?;
        Ok(wanted)
    }
    fn open(mut anchor: A, files: Files, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        files.absent(PREPARED)?;
        files.absent(PUBLISHED)?;
        let bytes = files.read(JOURNAL, check)?;
        let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
        let state = journal.validate()?;
        check()?;
        if anchor.read()? != state.checkpoint {
            return Err(
                "content history rollback or unmatched TPM head; explicit reconciliation required"
                    .into(),
            );
        }
        check()?;
        Ok(Self {
            anchor,
            files,
            journal,
            bytes,
            state,
            poisoned: false,
            genesis_proof: None,
        })
    }
    fn live(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        if self.poisoned {
            return Err("content writer is fenced; exact pending reconciliation required".into());
        }
        check()?;
        if let Some(expected) = &self.genesis_proof {
            if self.files.read("genesis.json", check)? != *expected {
                self.poisoned = true;
                return Err(
                    "original commissioning proof changed during protected operation".into(),
                );
            }
        }
        self.files.absent(PREPARED)?;
        self.files.absent(PUBLISHED)?;
        if self.files.read(JOURNAL, check)? != self.bytes
            || self.anchor.read()? != self.state.checkpoint
        {
            self.poisoned = true;
            return Err("current protected content cut changed".into());
        }
        check()
    }
    pub(crate) fn selected(
        &mut self,
        binding: &OwnerBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        binding.validate()?;
        if retire::principal_unavailable(binding, &self.state)? {
            return Err("content owner is protected as unavailable after reviewed restore retirement; provision an independent fresh owner".into());
        }
        if binding.installation != self.journal.installation {
            return Err("content owner belongs to a different installation".into());
        }
        self.live(check)?;
        let result = match self.state.owners.get(&owner_key(binding)?) {
            Some(state) => state.clone(),
            None => VerifiedState::empty(binding)?,
        };
        self.live(check)?;
        Ok(result)
    }
    pub(crate) fn publish(
        &mut self,
        commitment: &[u8],
        record: &[u8],
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        self.live(check)?;
        let held = HeldPublication::parse(commitment)?;
        if held.already_published {
            return self.acknowledge_replay(&held, record, profile, device, audit, check);
        }
        let current = self.selected(&held.binding, check)?;
        if current != held.base() {
            let cut = self.preparation_cut(
                &held.binding,
                profile,
                device,
                &held.request_id,
                &held.review_sha256,
                audit,
                check,
            )?;
            if cut.prior_base.as_ref() == Some(&held.base()) && cut.current == held.outcome() {
                return self
                    .acknowledge_anchored_pending(&held, record, profile, device, audit, check);
            }
            return Err(
                "held content publication does not extend current protected owner cut".into(),
            );
        }
        let publication = Publication {
            schema_version: 1,
            purpose: "luma-content-custody-publication-v1".into(),
            commitment: std::str::from_utf8(commitment)?.into(),
            record: std::str::from_utf8(record)?.into(),
            profile: profile.into(),
            storage_device: device.into(),
            original_authority: audit.clone(),
        };
        publication.validate()?;
        self.commit(Event::Publication(publication), check)?;
        Ok(held.outcome())
    }
    fn commit(&mut self, entry: Event, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.live(check)?;
        let event = entry.digest()?;
        let mut next = self.journal.clone();
        next.events.push(entry);
        let next_bytes = next.bytes()?;
        let next_state = next.validate()?;
        // Promises are reconstructed from the same protected candidate cut.
        // Refuse before creating PREPARED or attempting any TPM dispatch.
        capacity::admit(&next, &next_state)?;
        let prepared = Prepared {
            schema_version: 1,
            purpose: "luma-content-custody-prepared-v1".into(),
            before_sha256: hash(&self.bytes),
            before_checkpoint: bundle::hex(&self.state.checkpoint),
            after_checkpoint: bundle::hex(&next_state.checkpoint),
            previous: self.journal.clone(),
            next,
        };
        let bytes = serde_json::to_vec(&prepared)?;
        prepared.validate(&self.bytes)?;
        self.files.create(PREPARED, &bytes, check)?;
        // No later call through this object can repeat a dispatch, even if a
        // readback or fresh principal check refuses after the TPM succeeded.
        self.poisoned = true;
        check()?;
        if self.files.read(JOURNAL, check)? != self.bytes
            || self.files.read(PREPARED, check)? != bytes
            || self.anchor.read()? != self.state.checkpoint
        {
            return Err("prepared protected cut changed before dispatch".into());
        }
        check()?;
        if self.anchor.advance(self.state.checkpoint, event)? != next_state.checkpoint {
            return Err(
                "protected content dispatch outcome differs; retain pending evidence".into(),
            );
        }
        check()?;
        self.files.create(PUBLISHED, &next_bytes, check)?;
        self.files.rename(PUBLISHED, JOURNAL, check)?;
        if self.files.read(JOURNAL, check)? != next_bytes
            || self.anchor.read()? != next_state.checkpoint
        {
            return Err("published protected cut differs; retain pending evidence".into());
        }
        self.files.retire(PREPARED, check)?;
        self.journal = prepared.next;
        self.bytes = next_bytes;
        self.state = next_state;
        self.poisoned = false;
        self.live(check)?;
        Ok(())
    }
    fn acknowledge_replay(
        &mut self,
        held: &HeldPublication,
        record: &[u8],
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        audit.validate()?;
        if audit.subject != held.binding.owner
            || audit.subject_generation != held.binding.owner_generation
            || audit.usage
                != crate::content_governed::custody_usage(
                    profile,
                    device,
                    &held.binding,
                    &held.review_sha256,
                )?
            || audit.operation_id.is_none()
            || self.selected(&held.binding, check)? != held.outcome()
        {
            return Err("content replay authority or current protected outcome differs".into());
        }
        self.acknowledge_anchored_pending(held, record, profile, device, audit, check)
    }
    fn acknowledge_anchored_pending(
        &mut self,
        held: &HeldPublication,
        record: &[u8],
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        if self.selected(&held.binding, check)? != held.outcome()
            || audit.usage
                != crate::content_governed::custody_usage(
                    profile,
                    device,
                    &held.binding,
                    &held.review_sha256,
                )?
            || audit.subject != held.binding.owner
            || audit.subject_generation != held.binding.owner_generation
            || audit.operation_id.is_none()
        {
            return Err(
                "previously anchored publication lacks its current exact original effect proof"
                    .into(),
            );
        }
        let prior = self
            .journal
            .events
            .iter()
            .filter_map(|entry| match entry {
                Event::Publication(value) => Some(value),
                _ => None,
            })
            .find(|entry| {
                HeldPublication::parse(entry.commitment.as_bytes()).is_ok_and(|value| {
                    value.binding == held.binding && value.request_id == held.request_id
                })
            })
            .ok_or("content replay has no protected publication")?;
        let original = prior.validate()?;
        if original.review_sha256 != held.review_sha256
            || original.decision != held.decision
            || original.resulting != held.resulting
            || prior.record.as_bytes() != record
            || original
                .members
                .iter()
                .zip(&held.members)
                .any(|(a, b)| a.name != b.name || a.bytes != b.bytes || a.sha256 != b.sha256)
            || prior.original_authority.usage != audit.usage
        {
            return Err(
                "content replay substitutes a different reviewed immutable publication".into(),
            );
        }
        self.live(check)?;
        Ok(held.outcome())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_history_is_exact_genesis_not_a_reconstructed_disk_head() {
        let journal = Journal::empty(&"12".repeat(32), [7; 32]).unwrap();
        let bytes = journal.bytes().unwrap();
        let parsed: Journal = canonical(&bytes, MAX_JOURNAL).unwrap();
        assert_eq!(
            parsed.validate().unwrap().checkpoint,
            tpm::extend_value([0; 32], [7; 32])
        );
        for mutated in [
            bytes.iter().copied().chain([b' ']).collect::<Vec<_>>(),
            b"{}".to_vec(),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen(
                    "\"schema_version\":1",
                    "\"schema_version\":1,\"schema_version\":1",
                    1,
                )
                .into_bytes(),
            String::from_utf8(bytes)
                .unwrap()
                .replacen("\"events\":[]", "\"events\":[],\"trusted\":true", 1)
                .into_bytes(),
        ] {
            assert!(canonical::<Journal>(&mutated, MAX_JOURNAL).is_err());
        }
        assert!(Journal::empty(&"00".repeat(32), [7; 32]).is_err());
        assert!(Journal::empty(&"12".repeat(32), [0; 32]).is_err());
    }
    #[test]
    fn sealed_installation_and_genesis_are_required_even_when_empty_head_is_unchanged() {
        let journal = Journal::empty(&"12".repeat(32), [7; 32]).unwrap();
        let head = journal.validate().unwrap().checkpoint;
        journal.require_identity(&"12".repeat(32), [7; 32]).unwrap();
        let mut tampered = journal.clone();
        tampered.installation = "13".repeat(32);
        // The head fold intentionally starts at the independently sealed
        // genesis. Every installed opener must also bind its descriptive
        // header to that authenticated identity; a checksum alone cannot.
        assert_eq!(tampered.validate().unwrap().checkpoint, head);
        assert!(tampered
            .require_identity(&"12".repeat(32), [7; 32])
            .is_err());
        assert!(journal.require_identity(&"12".repeat(32), [8; 32]).is_err());
    }
    #[test]
    fn pending_cannot_promote_an_empty_equal_or_substituted_continuation() {
        let old = Journal::empty(&"12".repeat(32), [7; 32]).unwrap();
        let bytes = old.bytes().unwrap();
        let pending = Prepared {
            schema_version: 1,
            purpose: "luma-content-custody-prepared-v1".into(),
            before_sha256: hash(&bytes),
            before_checkpoint: bundle::hex(&old.validate().unwrap().checkpoint),
            after_checkpoint: bundle::hex(&old.validate().unwrap().checkpoint),
            previous: old.clone(),
            next: old,
        };
        assert!(pending.validate(&bytes).is_err());
        assert!(pending.validate(b"{}").is_err());
    }
}
