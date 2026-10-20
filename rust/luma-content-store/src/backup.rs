//! Bounded plaintext backup DATA, never restoration or installation authority.
//!
//! Export creation requires independent live Read and Export boundaries. The
//! archive has a closed canonical manifest followed by exact raw member bytes;
//! there is no pathname extraction, filesystem import, key material, signature,
//! credential, grant, session, or production-enablement operation in this module.
use crate::{
    storage, Access, Boundary, HistoryReconstruction, Plan, PreparationDirectoryIdentity,
    PreparationFileIdentity, Record, Repository, ResourceBudget, Result,
};
use luma_content::{OwnerBinding, VersionReference};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

const MAGIC: &[u8; 16] = b"LUMACONTENTBK01\n";
const PREFIX_BYTES: usize = MAGIC.len() + 4;
pub const MAX_BACKUP_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_BACKUP_REVIEW_BYTES: usize = 8192;
pub const MAX_CONTENT_BACKUP_BYTES: usize =
    PREFIX_BYTES + MAX_BACKUP_MANIFEST_BYTES + crate::MAX_REPOSITORY_BYTES as usize;
const DATA_OFFSET: usize = PREFIX_BYTES + MAX_BACKUP_MANIFEST_BYTES;
const FORMAT: &str = "luma-content-data-backup-v1";

/// Requested fixed bounds, not evidence that resources have been reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupBudget {
    pub memory_bytes: u64,
    pub read_bytes: u64,
    pub archive_bytes: u64,
    pub tasks: u32,
}

/// A genuine independent finite Export boundary must be supplied by the
/// composition root. Neither a checksum nor a Read grant implements this trait.
/// Reviewed export always supplies `Some` with the exact previously reviewed
/// manifest, including before private reads. `None` is not used to create an
/// export and must never be interpreted as a wildcard by an installed adapter.
/// The caller must separately revalidate authority during external delivery.
pub trait BackupBoundary {
    fn admit(&mut self, binding: &OwnerBinding, budget: BackupBudget) -> Result<()>;
    fn check(&mut self, binding: &OwnerBinding, manifest_sha256: Option<&str>) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum BackupArea {
    Committed,
    Pending,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupMember {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub source_identity: PreparationFileIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupDirectory {
    pub area: BackupArea,
    pub name: String,
    pub source_identity: PreparationDirectoryIdentity,
    pub members: Vec<BackupMember>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupNamespace {
    pub root: PreparationDirectoryIdentity,
    pub committed: PreparationDirectoryIdentity,
    pub pending: PreparationDirectoryIdentity,
    pub quarantined: Option<PreparationDirectoryIdentity>,
}

/// Archived ownership and inode metadata are descriptive DATA only. They do not
/// authorize recreating an installation, mapping an account or adopting a head.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub format: String,
    pub binding: OwnerBinding,
    pub source_namespace: BackupNamespace,
    pub committed_outcomes: u64,
    pub committed_head_sha256: String,
    pub directories: Vec<BackupDirectory>,
    pub data_bytes: u64,
}

/// Fully reconstructed DATA inspection. No checksum is a signature or a permit.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupInspection {
    pub manifest: BackupManifest,
    pub manifest_sha256: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub current: Vec<VersionReference>,
    pub authority_returned: bool,
    pub filesystem_changed: bool,
    pub restore_permitted: bool,
}

/// Exact prior Read-only review. It contains metadata and commitments, not raw
/// member bytes, transferable Export authority, or a restore permission.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupReview {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub source_namespace: BackupNamespace,
    pub committed_outcomes: u64,
    pub committed_head_sha256: String,
    pub data_bytes: u64,
    pub areas: Vec<BackupAreaReview>,
    pub manifest_sha256: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub review_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupAreaReview {
    pub area: BackupArea,
    pub directories: u64,
    pub members: u64,
    pub bytes: u64,
    pub sha256: String,
}

fn area_review(directories: &[BackupDirectory], area: BackupArea) -> Result<BackupAreaReview> {
    let entries = directories
        .iter()
        .filter(|entry| entry.area == area)
        .collect::<Vec<_>>();
    let mut members = 0_u64;
    let mut bytes = 0_u64;
    for entry in &entries {
        members = members
            .checked_add(entry.members.len() as u64)
            .ok_or("backup review member count overflow")?;
        for member in &entry.members {
            bytes = bytes
                .checked_add(member.bytes)
                .ok_or("backup review byte count overflow")?;
        }
    }
    Ok(BackupAreaReview {
        area,
        directories: entries.len() as u64,
        members,
        bytes,
        sha256: luma_content::sha256(&serde_json::to_vec(&entries)?),
    })
}

impl BackupReview {
    fn digest(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-content-data-backup-review-v1",
            self.schema_version,
            &self.binding,
            &self.source_namespace,
            self.committed_outcomes,
            &self.committed_head_sha256,
            self.data_bytes,
            &self.areas,
            &self.manifest_sha256,
            &self.archive_sha256,
            self.archive_bytes,
        ))?))
    }

    fn from_inspection(inspection: &BackupInspection) -> Result<Self> {
        let mut result = Self {
            schema_version: 1,
            binding: inspection.manifest.binding.clone(),
            source_namespace: inspection.manifest.source_namespace.clone(),
            committed_outcomes: inspection.manifest.committed_outcomes,
            committed_head_sha256: inspection.manifest.committed_head_sha256.clone(),
            data_bytes: inspection.manifest.data_bytes,
            areas: [
                BackupArea::Committed,
                BackupArea::Pending,
                BackupArea::Quarantined,
            ]
            .into_iter()
            .map(|area| area_review(&inspection.manifest.directories, area))
            .collect::<Result<Vec<_>>>()?,
            manifest_sha256: inspection.manifest_sha256.clone(),
            archive_sha256: inspection.archive_sha256.clone(),
            archive_bytes: inspection.archive_bytes,
            review_sha256: String::new(),
        };
        result.review_sha256 = result.digest()?;
        result.validate()?;
        Ok(result)
    }

    /// Pure structural/hash consistency, never authentication or authorization.
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        validate_namespace(&self.source_namespace)?;
        let header_bytes = self
            .archive_bytes
            .checked_sub(self.data_bytes)
            .and_then(|n| n.checked_sub(PREFIX_BYTES as u64))
            .ok_or("content backup review byte accounting underflow")?;
        if self.schema_version != 1
            || self.committed_outcomes > crate::MAX_OUTCOMES as u64
            || !crate::hash(&self.committed_head_sha256)
            || !crate::hash(&self.archive_sha256)
            || !crate::hash(&self.manifest_sha256)
            || self.data_bytes > crate::MAX_REPOSITORY_BYTES
            || header_bytes == 0
            || header_bytes > MAX_BACKUP_MANIFEST_BYTES as u64
            || self.archive_bytes > MAX_CONTENT_BACKUP_BYTES as u64
            || self.areas.len() != 3
        {
            return Err("content backup review is invalid or exceeds its fixed bounds".into());
        }
        let mut total = 0_u64;
        for (index, (expected, limit)) in [
            (BackupArea::Committed, crate::MAX_OUTCOMES),
            (BackupArea::Pending, crate::MAX_PENDING),
            (BackupArea::Quarantined, crate::MAX_QUARANTINED_PREPARATIONS),
        ]
        .into_iter()
        .enumerate()
        {
            let area = &self.areas[index];
            if area.area != expected
                || area.directories > limit as u64
                || area.members > area.directories * 3
                || area.bytes > crate::MAX_REPOSITORY_BYTES
                || !crate::hash(&area.sha256)
                || (area.directories == 0
                    && (area.bytes != 0
                        || area.members != 0
                        || area.sha256 != luma_content::sha256(b"[]")))
                || (index == 0
                    && (area.directories != self.committed_outcomes
                        || area.members != area.directories * 3))
                || (index == 2
                    && self.source_namespace.quarantined.is_none()
                    && area.directories != 0)
            {
                return Err("content backup review area commitment is invalid".into());
            }
            total = total
                .checked_add(area.bytes)
                .ok_or("content backup review byte count overflow")?;
        }
        if total != self.data_bytes
            || self.review_sha256 != self.digest()?
            || serde_json::to_vec(self)?.len() > MAX_BACKUP_REVIEW_BYTES
        {
            return Err("content backup review digest or compact byte bound is invalid".into());
        }
        Ok(())
    }
}

/// Authorized in-memory plaintext. There is deliberately no save/extract/import
/// method. A later encrypted transport must enforce its own live delivery scope.
pub struct ContentBackup {
    bytes: Vec<u8>,
    inspection: BackupInspection,
}

impl ContentBackup {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn manifest(&self) -> &BackupManifest {
        &self.inspection.manifest
    }
    pub fn inspection(&self) -> &BackupInspection {
        &self.inspection
    }
    pub fn sha256(&self) -> &str {
        &self.inspection.archive_sha256
    }
}

fn member_limit(name: &str) -> Result<u64> {
    match name {
        "record.json" => Ok(crate::MAX_RECORD),
        "payload.json" => Ok(crate::MAX_PAYLOAD),
        "source.bin" => Ok(crate::MAX_SOURCE),
        _ => Err("unknown backup member; no pathname extraction is supported".into()),
    }
}

fn directory_identity(m: &Metadata) -> PreparationDirectoryIdentity {
    PreparationDirectoryIdentity {
        device: m.dev(),
        inode: m.ino(),
        owner: m.uid(),
        group: m.gid(),
        mode: m.mode(),
    }
}

fn file_identity(m: &Metadata) -> PreparationFileIdentity {
    PreparationFileIdentity {
        device: m.dev(),
        inode: m.ino(),
        owner: m.uid(),
        group: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        modified_seconds: m.mtime(),
        modified_nanoseconds: m.mtime_nsec(),
        changed_seconds: m.ctime(),
        changed_nanoseconds: m.ctime_nsec(),
    }
}

fn validate_namespace(namespace: &BackupNamespace) -> Result<()> {
    for identity in [&namespace.root, &namespace.committed, &namespace.pending]
        .into_iter()
        .chain(namespace.quarantined.as_ref())
    {
        if identity.mode != (libc::S_IFDIR | 0o700)
            || identity.device != namespace.root.device
            || identity.owner != namespace.root.owner
        {
            return Err("content backup source namespace identity is invalid".into());
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &BackupManifest) -> Result<()> {
    manifest.binding.validate()?;
    if manifest.schema_version != 1
        || manifest.format != FORMAT
        || manifest.committed_outcomes > crate::MAX_OUTCOMES as u64
        || !crate::hash(&manifest.committed_head_sha256)
        || manifest.data_bytes > crate::MAX_REPOSITORY_BYTES
        || manifest.directories.len()
            > crate::MAX_OUTCOMES + crate::MAX_PENDING + crate::MAX_QUARANTINED_PREPARATIONS
    {
        return Err("content backup manifest schema or capacity is invalid".into());
    }
    let namespace = &manifest.source_namespace;
    validate_namespace(namespace)?;
    let mut prior = None;
    let mut seen = BTreeSet::new();
    let mut counts = [0_usize; 3];
    let mut total = 0_u64;
    for directory in &manifest.directories {
        let key = (directory.area, directory.name.as_str());
        let area = match directory.area {
            BackupArea::Committed => 0,
            BackupArea::Pending => 1,
            BackupArea::Quarantined => 2,
        };
        counts[area] += 1;
        if !crate::hash(&directory.name)
            || prior.is_some_and(|previous| previous >= key)
            || !seen.insert(directory.name.as_str())
            || directory.source_identity.mode != (libc::S_IFDIR | 0o700)
            || directory.source_identity.device != namespace.root.device
            || directory.source_identity.owner != namespace.root.owner
            || (directory.area == BackupArea::Quarantined && namespace.quarantined.is_none())
            || directory.members.len() > 3
        {
            return Err("content backup directory identity or ordering is invalid".into());
        }
        prior = Some(key);
        if directory.area == BackupArea::Committed
            && directory
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>()
                != ["payload.json", "record.json", "source.bin"]
        {
            return Err("content backup committed outcome has missing or extra members".into());
        }
        let mut previous_member: Option<&str> = None;
        for member in &directory.members {
            if previous_member.is_some_and(|previous| previous >= member.name.as_str())
                || member.bytes > member_limit(&member.name)?
                || !crate::hash(&member.sha256)
                || member.source_identity.mode != (libc::S_IFREG | 0o400)
                || member.source_identity.links != 1
                || member.source_identity.owner != directory.source_identity.owner
                || member.source_identity.device != directory.source_identity.device
                || !(0..1_000_000_000).contains(&member.source_identity.modified_nanoseconds)
                || !(0..1_000_000_000).contains(&member.source_identity.changed_nanoseconds)
            {
                return Err(
                    "content backup member identity, ordering or byte bound is invalid".into(),
                );
            }
            previous_member = Some(&member.name);
            total = total
                .checked_add(member.bytes)
                .filter(|value| *value <= crate::MAX_REPOSITORY_BYTES)
                .ok_or("content backup total byte capacity exceeded")?;
        }
    }
    if counts[0] != manifest.committed_outcomes as usize
        || counts[1] > crate::MAX_PENDING
        || counts[2] > crate::MAX_QUARANTINED_PREPARATIONS
        || total != manifest.data_bytes
    {
        return Err("content backup inventory count or byte accounting mismatch".into());
    }
    if serde_json::to_vec(manifest)?.len() > MAX_BACKUP_MANIFEST_BYTES {
        return Err("content backup manifest exceeds fixed serialized bound".into());
    }
    Ok(())
}

pub(super) struct BorrowedOutcome<'a> {
    pub(super) record: Record,
    pub(super) payload: &'a [u8],
    pub(super) source: &'a [u8],
}

fn reconstructed<'a>(
    manifest: &BackupManifest,
    bytes: &'a [u8],
    offset: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(String, Vec<VersionReference>, Vec<BorrowedOutcome<'a>>)> {
    let mut at = offset;
    let mut raw = BTreeMap::new();
    for directory in &manifest.directories {
        check()?;
        let mut record = None;
        let mut payload = None;
        let mut source = None;
        for member in &directory.members {
            check()?;
            let end = at
                .checked_add(usize::try_from(member.bytes)?)
                .ok_or("backup member offset overflow")?;
            let data = bytes
                .get(at..end)
                .ok_or("content backup member is truncated")?;
            if luma_content::sha256(data) != member.sha256 {
                return Err("content backup member digest mismatch".into());
            }
            check()?;
            if directory.area == BackupArea::Committed {
                match member.name.as_str() {
                    "record.json" => {
                        let parsed: Record = serde_json::from_slice(data)?;
                        if serde_json::to_vec(&parsed)? != data
                            || directory.name
                                != luma_content::sha256(
                                    parsed.plan.provenance.request_id.as_bytes(),
                                )
                        {
                            return Err("content backup canonical outcome identity mismatch".into());
                        }
                        record = Some(parsed);
                    }
                    "payload.json" => payload = Some(data),
                    "source.bin" => source = Some(data),
                    _ => return Err("content backup committed member not supported".into()),
                }
            }
            at = end;
        }
        if directory.area == BackupArea::Committed {
            let record = record.ok_or("content backup committed record missing")?;
            let sequence = record.sequence;
            if raw
                .insert(
                    sequence,
                    BorrowedOutcome {
                        record,
                        payload: payload.ok_or("content backup committed payload missing")?,
                        source: source.ok_or("content backup committed source missing")?,
                    },
                )
                .is_some()
            {
                return Err("content backup has a duplicate committed sequence".into());
            }
        }
    }
    if at != bytes.len() || at.checked_sub(offset) != Some(manifest.data_bytes as usize) {
        return Err("content backup contains missing, trailing or unaccounted bytes".into());
    }
    let mut history = HistoryReconstruction::new();
    for outcome in raw.values() {
        check()?;
        let _plan: Plan = history.observe(
            &manifest.binding,
            &outcome.record,
            outcome.payload,
            outcome.source,
            check,
        )?;
    }
    let records = raw
        .values()
        .map(|outcome| &outcome.record)
        .collect::<Vec<_>>();
    let head = luma_content::sha256(&serde_json::to_vec(&(
        "luma-content-verified-outcome-history-v1",
        &manifest.binding,
        records,
    ))?);
    let current = history
        .current
        .iter()
        .filter(|(artifact, _)| {
            history
                .lifecycle
                .get(*artifact)
                .is_some_and(|state| state.status == crate::LifecycleStatus::Live)
        })
        .map(|(_, version)| version)
        .map(|version| version.reference())
        .collect::<luma_content::Result<Vec<_>>>()?;
    check()?;
    Ok((head, current, raw.into_values().collect()))
}

/// Strict pure inspection of an already supplied archive. Successful parsing
/// never authenticates its source or authorizes extraction/restoration.
pub fn inspect_backup_data(bytes: &[u8]) -> Result<BackupInspection> {
    inspect_checked(bytes, &mut || Ok(()))
}

/// Inspection with live caller-owned cancellation/authorization checkpoints.
/// The callback grants no restoration authority, and no permissive adapter is
/// supplied. Both pure and governed inspection use the same reconstruction.
pub fn inspect_backup_data_checked(
    bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<BackupInspection> {
    check()?;
    let inspection = inspect_checked(bytes, check)?;
    check()?;
    Ok(inspection)
}

fn inspect_checked(
    bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<BackupInspection> {
    Ok(inspect_parts(bytes, check)?.0)
}

pub(super) fn inspect_parts<'a>(
    bytes: &'a [u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(BackupInspection, Vec<BorrowedOutcome<'a>>)> {
    if bytes.len() < PREFIX_BYTES
        || bytes.len() > MAX_CONTENT_BACKUP_BYTES
        || &bytes[..MAGIC.len()] != MAGIC
    {
        return Err("content backup magic or complete byte bound is invalid".into());
    }
    let length = u32::from_be_bytes(bytes[MAGIC.len()..PREFIX_BYTES].try_into()?) as usize;
    if length == 0 || length > MAX_BACKUP_MANIFEST_BYTES {
        return Err("content backup manifest length exceeds fixed bound".into());
    }
    let data_at = PREFIX_BYTES
        .checked_add(length)
        .ok_or("content backup manifest offset overflow")?;
    let encoded = bytes
        .get(PREFIX_BYTES..data_at)
        .ok_or("content backup manifest is truncated")?;
    let manifest: BackupManifest = serde_json::from_slice(encoded)?;
    validate_manifest(&manifest)?;
    if serde_json::to_vec(&manifest)? != encoded {
        return Err("content backup manifest is not exact canonical typed JSON".into());
    }
    let (head, current, outcomes) = reconstructed(&manifest, bytes, data_at, check)?;
    if head != manifest.committed_head_sha256 {
        return Err("content backup reconstructed committed head mismatch".into());
    }
    check()?;
    let result = BackupInspection {
        manifest,
        manifest_sha256: luma_content::sha256(encoded),
        archive_sha256: luma_content::sha256(bytes),
        archive_bytes: bytes.len() as u64,
        current,
        authority_returned: false,
        filesystem_changed: false,
        restore_permitted: false,
    };
    check()?;
    Ok((result, outcomes))
}

struct ExportBoundary<'a, R, E> {
    reader: &'a mut R,
    exporter: &'a mut E,
    binding: &'a OwnerBinding,
    manifest_sha256: &'a str,
}

impl<R: Boundary, E: BackupBoundary> Boundary for ExportBoundary<'_, R, E> {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.reader.admit(owner, budget)?;
        self.exporter
            .check(self.binding, Some(self.manifest_sha256))
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.reader.check(access)?;
        self.exporter
            .check(self.binding, Some(self.manifest_sha256))
    }
}

fn append_member(
    directory: &File,
    name: &str,
    archive: &mut Vec<u8>,
    total: &mut u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<BackupMember> {
    check()?;
    let mut file = storage::open(directory, name, libc::O_RDONLY, 0)?;
    storage::check_private(&file, false)?;
    let before = file.metadata()?;
    let pin = file_identity(&before);
    let limit = member_limit(name)?.min(
        crate::MAX_REPOSITORY_BYTES
            .checked_sub(*total)
            .ok_or("backup accounting overflow")?,
    );
    if before.mode() & 0o7777 != 0o400 || before.len() > limit {
        return Err("content backup source member mode or byte capacity invalid".into());
    }
    let start = archive.len();
    let mut block = [0_u8; 32 * 1024];
    loop {
        check()?;
        let capacity = limit
            .saturating_sub((archive.len() - start) as u64)
            .saturating_add(1)
            .min(block.len() as u64) as usize;
        let count = file.read(&mut block[..capacity])?;
        check()?;
        if count == 0 {
            break;
        }
        if (archive.len() - start) as u64 + count as u64 > limit {
            return Err("content backup source exceeds reviewed read bound".into());
        }
        archive.extend_from_slice(&block[..count]);
    }
    let after = file.metadata()?;
    let current = storage::open(directory, name, libc::O_RDONLY, 0)?.metadata()?;
    if pin != file_identity(&after)
        || pin != file_identity(&current)
        || before.len() != after.len()
        || before.len() != current.len()
        || before.len() != (archive.len() - start) as u64
    {
        return Err("content backup source changed during bounded read".into());
    }
    *total += before.len();
    check()?;
    Ok(BackupMember {
        name: name.into(),
        bytes: before.len(),
        sha256: luma_content::sha256(&archive[start..]),
        source_identity: pin,
    })
}

fn capture_area(
    repository: &Repository,
    parent: &File,
    area: BackupArea,
    limit: usize,
    directories: &mut Vec<BackupDirectory>,
    archive: &mut Vec<u8>,
    total: &mut u64,
    boundary: &mut impl Boundary,
) -> Result<()> {
    let mut check = || storage::repository_check(repository, None, boundary);
    check()?;
    let names = storage::names(parent, limit)?;
    for name in &names {
        check()?;
        if !crate::hash(name) {
            return Err("unknown content backup transaction name".into());
        }
        let directory = storage::directory(parent, name)?;
        let pin = directory_identity(&directory.metadata()?);
        let names = storage::names(&directory, 3)?;
        let mut members = Vec::new();
        for member in &names {
            members.push(append_member(
                &directory, member, archive, total, &mut check,
            )?);
        }
        if storage::names(&directory, 3)? != names
            || directory_identity(&directory.metadata()?) != pin
            || directory_identity(&storage::directory(parent, name)?.metadata()?) != pin
        {
            return Err("content backup directory changed during capture".into());
        }
        directories.push(BackupDirectory {
            area,
            name: name.clone(),
            source_identity: pin,
            members,
        });
    }
    check()?;
    if storage::names(parent, limit)? != names {
        return Err("content backup area changed during capture".into());
    }
    Ok(())
}

fn recheck_sources(
    repository: &Repository,
    manifest: &BackupManifest,
    boundary: &mut impl Boundary,
) -> Result<()> {
    let actual = BackupNamespace {
        root: directory_identity(&repository.root.metadata()?),
        committed: directory_identity(&repository.outcomes.metadata()?),
        pending: directory_identity(&repository.pending.metadata()?),
        quarantined: repository
            .quarantine
            .as_ref()
            .map(|file| file.metadata().map(|m| directory_identity(&m)))
            .transpose()?,
    };
    if actual != manifest.source_namespace {
        return Err("content backup source namespace changed before return".into());
    }
    for (area, parent, limit) in [
        (
            BackupArea::Committed,
            Some(&repository.outcomes),
            crate::MAX_OUTCOMES,
        ),
        (
            BackupArea::Pending,
            Some(&repository.pending),
            crate::MAX_PENDING,
        ),
        (
            BackupArea::Quarantined,
            repository.quarantine.as_ref(),
            crate::MAX_QUARANTINED_PREPARATIONS,
        ),
    ] {
        storage::repository_check(repository, None, boundary)?;
        let entries = manifest
            .directories
            .iter()
            .filter(|entry| entry.area == area)
            .collect::<Vec<_>>();
        let Some(parent) = parent else {
            if entries.is_empty() {
                continue;
            }
            return Err("content backup quarantine namespace disappeared".into());
        };
        if storage::names(parent, limit)?
            != entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        {
            return Err("content backup inventory changed before return".into());
        }
        for entry in entries {
            storage::repository_check(repository, None, boundary)?;
            let directory = storage::directory(parent, &entry.name)?;
            if directory_identity(&directory.metadata()?) != entry.source_identity
                || storage::names(&directory, 3)?
                    != entry
                        .members
                        .iter()
                        .map(|member| member.name.clone())
                        .collect::<Vec<_>>()
            {
                return Err("content backup directory changed before return".into());
            }
            for member in &entry.members {
                storage::repository_check(repository, None, boundary)?;
                let file = storage::open(&directory, &member.name, libc::O_RDONLY, 0)?;
                storage::check_private(&file, false)?;
                let metadata = file.metadata()?;
                if file_identity(&metadata) != member.source_identity
                    || metadata.len() != member.bytes
                {
                    return Err("content backup member changed before return".into());
                }
            }
        }
    }
    storage::repository_check(repository, None, boundary)
}

fn check_area(
    directories: &[BackupDirectory],
    area: BackupArea,
    expected: Option<&BackupReview>,
) -> Result<()> {
    if let Some(expected) = expected {
        if expected.areas.iter().find(|entry| entry.area == area)
            != Some(&area_review(directories, area)?)
        {
            return Err("content backup inventory differs from its exact prior review".into());
        }
    }
    Ok(())
}

// Private capture may temporarily hold plaintext to reconstruct canonical
// history. A review returns only commitments and drops this entire buffer.
// Only backup_data, with independent Export authority, returns the bytes.
fn capture_backup(
    repository: &Repository,
    boundary: &mut impl Boundary,
    expected: Option<&BackupReview>,
) -> Result<(Vec<u8>, BackupInspection)> {
    storage::repository_check(repository, None, boundary)?;
    let identity_bytes = storage::read(
        &repository.root,
        "identity.json",
        crate::MAX_RECORD,
        &mut || storage::repository_check(repository, None, boundary),
    )?;
    if identity_bytes != serde_json::to_vec(&crate::identity(&repository.binding))? {
        return Err("content backup repository identity mismatch".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(MAX_CONTENT_BACKUP_BYTES)?;
    bytes.resize(DATA_OFFSET, 0);
    let mut directories = Vec::new();
    let mut total = 0_u64;
    let source_namespace = BackupNamespace {
        root: directory_identity(&repository.root.metadata()?),
        committed: directory_identity(&repository.outcomes.metadata()?),
        pending: directory_identity(&repository.pending.metadata()?),
        quarantined: repository
            .quarantine
            .as_ref()
            .map(|file| file.metadata().map(|m| directory_identity(&m)))
            .transpose()?,
    };
    if expected.is_some_and(|review| review.source_namespace != source_namespace) {
        return Err("content backup namespace differs from exact prior review".into());
    }
    capture_area(
        repository,
        &repository.outcomes,
        BackupArea::Committed,
        crate::MAX_OUTCOMES,
        &mut directories,
        &mut bytes,
        &mut total,
        boundary,
    )?;
    check_area(&directories, BackupArea::Committed, expected)?;
    capture_area(
        repository,
        &repository.pending,
        BackupArea::Pending,
        crate::MAX_PENDING,
        &mut directories,
        &mut bytes,
        &mut total,
        boundary,
    )?;
    check_area(&directories, BackupArea::Pending, expected)?;
    if let Some(quarantine) = repository.quarantine.as_ref() {
        capture_area(
            repository,
            quarantine,
            BackupArea::Quarantined,
            crate::MAX_QUARANTINED_PREPARATIONS,
            &mut directories,
            &mut bytes,
            &mut total,
            boundary,
        )?;
        check_area(&directories, BackupArea::Quarantined, expected)?;
    }
    let count = directories
        .iter()
        .filter(|entry| entry.area == BackupArea::Committed)
        .count() as u64;
    // The head is computed from the actual canonical record bytes below,
    // never guessed from a caller-supplied plan or an external authority.
    let mut at = DATA_OFFSET;
    let mut records = BTreeMap::new();
    for directory in &directories {
        for member in &directory.members {
            storage::repository_check(repository, None, boundary)?;
            let end = at
                .checked_add(usize::try_from(member.bytes)?)
                .ok_or("backup member offset overflow")?;
            if directory.area == BackupArea::Committed && member.name == "record.json" {
                let data = bytes
                    .get(at..end)
                    .ok_or("captured backup member unavailable")?;
                let record: Record = serde_json::from_slice(data)?;
                if serde_json::to_vec(&record)? != data
                    || records.insert(record.sequence, record).is_some()
                {
                    return Err("captured backup record is noncanonical or duplicate".into());
                }
            }
            at = end;
        }
    }
    let ordered = records.values().collect::<Vec<_>>();
    let head = luma_content::sha256(&serde_json::to_vec(&(
        "luma-content-verified-outcome-history-v1",
        &repository.binding,
        ordered,
    ))?);
    let manifest = BackupManifest {
        schema_version: 1,
        format: FORMAT.into(),
        binding: repository.binding.clone(),
        source_namespace,
        committed_outcomes: count,
        committed_head_sha256: head,
        directories,
        data_bytes: total,
    };
    validate_manifest(&manifest)?;
    let encoded = serde_json::to_vec(&manifest)?;
    let data_at = PREFIX_BYTES + encoded.len();
    let original_length = bytes.len();
    bytes.copy_within(DATA_OFFSET..original_length, data_at);
    bytes.truncate(data_at + usize::try_from(total)?);
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()..PREFIX_BYTES].copy_from_slice(&u32::try_from(encoded.len())?.to_be_bytes());
    bytes[PREFIX_BYTES..data_at].copy_from_slice(&encoded);
    let inspection = inspect_checked(&bytes, &mut || {
        storage::repository_check(repository, None, boundary)
    })?;
    let quarantined = inspection
        .manifest
        .directories
        .iter()
        .filter(|directory| directory.area == BackupArea::Quarantined)
        .map(|directory| crate::PreparationDirectory {
            name: directory.name.clone(),
            identity: directory.source_identity.clone(),
            members: directory
                .members
                .iter()
                .map(|member| crate::PreparationMember {
                    name: member.name.clone(),
                    bytes: member.bytes,
                    sha256: member.sha256.clone(),
                    identity: member.source_identity.clone(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    repository.check_selected_state(&crate::VerifiedState {
        binding: inspection.manifest.binding.clone(),
        outcome_count: inspection.manifest.committed_outcomes,
        head_sha256: inspection.manifest.committed_head_sha256.clone(),
        quarantine_sha256: crate::recovery::inventory_digest(
            &inspection.manifest.binding,
            &quarantined,
        )?,
    })?;
    if let Some(expected) = expected {
        if &BackupReview::from_inspection(&inspection)? != expected {
            return Err("content backup changed since its exact prior Read-only review".into());
        }
    }
    recheck_sources(repository, &inspection.manifest, boundary)?;
    Ok((bytes, inspection))
}

impl Repository {
    /// Exact metadata/digest review under live Read authority. No archive bytes
    /// are returned, no Export authority is inferred, and no file is created.
    pub fn review_backup_data(&self, reader: &mut impl Boundary) -> Result<BackupReview> {
        reader.admit(&self.binding, ResourceBudget::inspection())?;
        let (plaintext, inspection) = capture_backup(self, reader, None)?;
        let review = BackupReview::from_inspection(&inspection)?;
        drop(plaintext);
        storage::repository_check(self, None, reader)?;
        Ok(review)
    }

    /// Export exact previously reviewed plaintext DATA into memory. Both live
    /// boundaries span every checkpoint; review/hash text is never authority.
    pub fn backup_data(
        &self,
        expected: &BackupReview,
        reader: &mut impl Boundary,
        exporter: &mut impl BackupBoundary,
    ) -> Result<ContentBackup> {
        expected.validate()?;
        if expected.binding != self.binding {
            return Err("content backup review cannot cross owner or generation".into());
        }
        let budget = BackupBudget {
            memory_bytes: 256 * 1024 * 1024,
            read_bytes: 256 * 1024 * 1024,
            archive_bytes: expected.archive_bytes,
            tasks: 1,
        };
        exporter.admit(&self.binding, budget)?;
        exporter.check(&self.binding, Some(&expected.manifest_sha256))?;
        let mut guarded = ExportBoundary {
            reader,
            exporter,
            binding: &self.binding,
            manifest_sha256: &expected.manifest_sha256,
        };
        guarded.admit(&self.binding, ResourceBudget::inspection())?;
        let (bytes, inspection) = capture_backup(self, &mut guarded, Some(expected))?;
        storage::repository_check(self, None, &mut guarded)?;
        guarded
            .exporter
            .check(&self.binding, Some(&inspection.manifest_sha256))?;
        Ok(ContentBackup { bytes, inspection })
    }
}
