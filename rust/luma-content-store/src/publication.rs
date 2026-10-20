//! Held-descriptor preparation and explicit publication of the same algorithm.
//! Commitments describe synchronized bytes, not a grant, TPM receipt, custody
//! signature, workflow proof or permission to publish after revocation.
use crate::*;
use std::os::unix::fs::{FileExt, MetadataExt};

/// Exact immutable member metadata. A serialized copy is descriptive data only.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PublicationMember {
    name: String,
    bytes: u64,
    sha256: String,
    identity: PreparationFileIdentity,
    mount_id: u64,
}
impl PublicationMember {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn identity(&self) -> &PreparationFileIdentity {
        &self.identity
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Namespace {
    name: String,
    identity: PreparationDirectoryIdentity,
    mount_id: u64,
}

/// Closed canonical data describing the exact prepared operation and current
/// immutable history. Hashing or storing it never establishes current custody.
/// There is deliberately no Deserialize implementation or authority flag.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PublicationCommitment {
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
    members: Vec<PublicationMember>,
}
impl PublicationCommitment {
    pub fn binding(&self) -> &OwnerBinding {
        &self.binding
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn review_sha256(&self) -> &str {
        &self.review_sha256
    }
    pub fn base_head_sha256(&self) -> &str {
        &self.base_head_sha256
    }
    pub fn outcome_head_sha256(&self) -> &str {
        &self.outcome_head_sha256
    }
    pub fn quarantine_sha256(&self) -> &str {
        &self.quarantine_sha256
    }
    pub fn already_published(&self) -> bool {
        self.already_published
    }
    pub fn members(&self) -> &[PublicationMember] {
        &self.members
    }
    pub fn base_state(&self) -> VerifiedState {
        VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.base_outcome_count,
            head_sha256: self.base_head_sha256.clone(),
            quarantine_sha256: self.quarantine_sha256.clone(),
        }
    }
    pub fn outcome_state(&self) -> VerifiedState {
        VerifiedState {
            binding: self.binding.clone(),
            outcome_count: self.outcome_count,
            head_sha256: self.outcome_head_sha256.clone(),
            quarantine_sha256: self.quarantine_sha256.clone(),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 32_768 {
            return Err("publication commitment exceeds closed metadata bound".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}

/// A synchronized preparation retains exclusive access to its repository and
/// all exact file descriptors. It is neither transferable serialized authority
/// nor proof that an external content checkpoint has committed these bytes.
/// Callers must independently admit any required custody BEFORE publish, while
/// this type independently rechecks the supplied current Boundary throughout.
/// Drop never publishes, erases, retires, retries or releases another lease.
///
/// A JSON record cannot reconstruct this held capability:
/// ```compile_fail
/// fn from_json(bytes: &[u8]) -> luma_content_store::PreparedPublication<'static> {
///     serde_json::from_slice(bytes).unwrap()
/// }
/// ```
/// It cannot be cloned for a second publication attempt:
/// ```compile_fail
/// fn clone_prepared(prepared: luma_content_store::PreparedPublication<'_>) {
///     let _ = prepared.clone();
/// }
/// ```
pub struct PreparedPublication<'repository> {
    repository: &'repository mut Repository,
    plan: Plan,
    source: Vec<u8>,
    record: Record,
    record_bytes: Vec<u8>,
    directory: File,
    files: Vec<File>,
    commitment: PublicationCommitment,
    pending_names: Vec<String>,
    published: bool,
    fenced: bool,
}

fn directory_identity(metadata: &std::fs::Metadata) -> PreparationDirectoryIdentity {
    PreparationDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode(),
    }
}
fn file_identity(metadata: &std::fs::Metadata) -> PreparationFileIdentity {
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
fn mount(file: &File) -> Result<u64> {
    let mut value: libc::statx = unsafe { std::mem::zeroed() };
    let empty = std::ffi::CString::new("")?;
    const MASK: u32 = 0x1000;
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            MASK,
            &mut value,
        )
    } != 0
        || value.stx_mask & MASK == 0
        || value.stx_mnt_id == 0
    {
        return Err("held publication requires actual kernel mount identity".into());
    }
    Ok(value.stx_mnt_id)
}
fn namespace(name: &str, file: &File) -> Result<Namespace> {
    storage::check_private(file, true)?;
    Ok(Namespace {
        name: name.into(),
        identity: directory_identity(&file.metadata()?),
        mount_id: mount(file)?,
    })
}
fn namespaces(repository: &Repository) -> Result<Vec<Namespace>> {
    let mut result = vec![
        namespace("base", &repository.base)?,
        namespace("owner", &repository.root)?,
        namespace("pending", &repository.pending)?,
        namespace("outcomes", &repository.outcomes)?,
    ];
    if let Some(file) = &repository.quarantine {
        result.push(namespace("quarantine", file)?);
    }
    Ok(result)
}
pub(super) fn history_head<'a>(
    binding: &OwnerBinding,
    records: impl Iterator<Item = &'a Record>,
) -> Result<String> {
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-content-verified-outcome-history-v1",
        binding,
        records.collect::<Vec<_>>(),
    ))?))
}

/// Reproduce the exact full-history commitment from bounded canonical records.
/// This validates record syntax, ownership, ordering and self-commitments ONLY.
/// Without the original sources and payloads it cannot replay engines, validate
/// decisions, authenticate a worker or establish that any record was anchored.
/// A custody journal may use it for records it independently admitted, never to
/// adopt an arbitrary self-consistent history found on disk or in a backup.
pub fn canonical_record_history_head(
    binding: &OwnerBinding,
    records: &[Vec<u8>],
) -> Result<String> {
    binding.validate()?;
    if records.len() > MAX_OUTCOMES {
        return Err("canonical record history exceeds outcome bound".into());
    }
    fn identifier(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }
    fn digest(value: &str) -> bool {
        crate::hash(value) && value.bytes().any(|byte| byte != b'0')
    }
    fn reference(value: &VersionReference, artifact: &str) -> bool {
        value.artifact_id == artifact
            && value.version > 0
            && digest(&value.content_sha256)
            && digest(&value.receipt_sha256)
    }
    let mut parsed = Vec::with_capacity(records.len());
    let mut requests = BTreeSet::new();
    let mut lifecycle = BTreeMap::<String, LifecycleReference>::new();
    for (index, bytes) in records.iter().enumerate() {
        if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
            return Err("canonical record exceeds fixed byte bound".into());
        }
        let record: Record = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&record)? != *bytes {
            return Err("record history requires exact canonical bytes".into());
        }
        let data = &record.plan;
        let source_limit = match (record.schema_version, data.source_kind) {
            (1, None) => luma_content::MAX_CONTENT_BYTES as u64,
            (2, Some(SourceKind::ManagedTableIntent))
            | (3, Some(SourceKind::ManagedRenderIntent)) => MAX_SOURCE,
            (4, Some(SourceKind::CollectionIntent)) => MAX_COLLECTION_SOURCE_BYTES as u64,
            (5, Some(SourceKind::LifecycleIntent)) => MAX_RECORD,
            _ => return Err("record history schema and source kind differ".into()),
        };
        if data.schema_version != record.schema_version
            || data.binding != *binding
            || record.sequence != index as u64 + 1
            || !identifier(&data.artifact_id)
            || !identifier(&data.provenance.request_id)
            || !requests.insert(data.provenance.request_id.clone())
            || !digest(&data.provenance.workflow_sha256)
            || !digest(&data.source_sha256)
            || data.source_sha256 != data.provenance.source_sha256
            || !digest(&data.payload_sha256)
            || data.source_bytes > source_limit
            || data.payload_bytes == 0
            || data.payload_bytes > MAX_PAYLOAD
            || !reference(&data.resulting, &data.artifact_id)
            || data
                .observed
                .as_ref()
                .is_some_and(|value| !reference(value, &data.artifact_id))
            || data
                .expected
                .as_ref()
                .is_some_and(|value| !reference(value, &data.artifact_id))
            || (record.schema_version == 3) != data.derivation.is_some()
            || record.review_sha256 != luma_content::sha256(&serde_json::to_vec(data)?)
        {
            return Err("record history sequence, metadata or self-commitment differs".into());
        }
        crate::lifecycle::validate_data(data)?;
        if let Some(transition) = &data.lifecycle {
            if lifecycle.get(&data.artifact_id) != Some(&transition.observed) {
                return Err(
                    "canonical history lifecycle revision does not extend its prior record".into(),
                );
            }
        } else if lifecycle
            .get(&data.artifact_id)
            .is_some_and(|state| state.status == LifecycleStatus::Trashed)
        {
            return Err("canonical history overwrites a trashed identity".into());
        }
        if matches!(
            data.decision,
            DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
        ) {
            lifecycle.insert(
                data.artifact_id.clone(),
                crate::lifecycle::advanced(
                    binding,
                    &record,
                    if data.decision == DecisionKind::Trashed {
                        LifecycleStatus::Trashed
                    } else {
                        LifecycleStatus::Live
                    },
                )?,
            );
        }
        parsed.push(record);
    }
    history_head(binding, parsed.iter())
}

impl<'repository> PreparedPublication<'repository> {
    pub(super) fn capture(
        repository: &'repository mut Repository,
        plan: &Plan,
        source: &[u8],
        record: Record,
        directory: File,
        snapshot: &Snapshot,
        replayed: bool,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        storage::repository_check(repository, Some(plan), boundary)?;
        let record_bytes = serde_json::to_vec(&record)?;
        let base_head = history_head(
            &repository.binding,
            snapshot.records.iter().map(|(record, _, _)| record),
        )?;
        let next_head = if replayed {
            base_head.clone()
        } else {
            history_head(
                &repository.binding,
                snapshot
                    .records
                    .iter()
                    .map(|(record, _, _)| record)
                    .chain(std::iter::once(&record)),
            )?
        };
        let mut members = Vec::new();
        let mut files = Vec::new();
        for (name, bytes) in [
            ("payload.json", plan.payload.as_slice()),
            ("record.json", record_bytes.as_slice()),
            ("source.bin", source),
        ] {
            storage::repository_check(repository, Some(plan), boundary)?;
            let file = storage::open(&directory, name, libc::O_RDONLY, 0)?;
            storage::check_private(&file, false)?;
            let metadata = file.metadata()?;
            if metadata.mode() & 0o7777 != 0o400 || metadata.len() != bytes.len() as u64 {
                return Err("prepared member mode or exact length differs".into());
            }
            members.push(PublicationMember {
                name: name.into(),
                bytes: bytes.len() as u64,
                sha256: luma_content::sha256(bytes),
                identity: file_identity(&metadata),
                mount_id: mount(&file)?,
            });
            files.push(file);
        }
        let commitment = PublicationCommitment {
            schema_version: 1,
            purpose: "luma-content-held-publication-v1".into(),
            binding: repository.binding.clone(),
            request_id: plan.request_id().into(),
            review_sha256: plan.review_sha256().into(),
            decision: plan.decision(),
            resulting: plan.resulting().clone(),
            base_outcome_count: snapshot.records.len() as u64,
            outcome_count: snapshot.records.len() as u64 + u64::from(!replayed),
            base_head_sha256: base_head,
            outcome_head_sha256: next_head,
            quarantine_sha256: snapshot.quarantine_sha256.clone(),
            already_published: replayed,
            namespaces: namespaces(repository)?,
            directory: directory_identity(&directory.metadata()?),
            directory_mount_id: mount(&directory)?,
            members,
        };
        commitment.canonical_bytes()?;
        let pending_names = if replayed {
            snapshot.pending.clone()
        } else {
            vec![luma_content::sha256(plan.request_id().as_bytes())]
        };
        let mut prepared = Self {
            repository,
            plan: plan.clone(),
            source: source.to_vec(),
            record,
            record_bytes,
            directory,
            files,
            commitment,
            pending_names,
            published: replayed,
            fenced: true,
        };
        prepared.verify_files(boundary)?;
        prepared.fenced = false;
        Ok(prepared)
    }

    /// Read-only data already captured under the caller's Boundary. This does
    /// not perform a new filesystem read or renew a prior authorization.
    pub fn commitment(&self) -> &PublicationCommitment {
        &self.commitment
    }

    /// Exact bounded canonical record already captured under the Boundary.
    /// This data is neither a fresh descriptor check nor custody authorization.
    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }

    fn expected(&self, name: &str) -> Result<&[u8]> {
        match name {
            "payload.json" => Ok(&self.plan.payload),
            "record.json" => Ok(&self.record_bytes),
            "source.bin" => Ok(&self.source),
            _ => Err("unknown fixed publication member".into()),
        }
    }
    fn check(&self, boundary: &mut impl Boundary) -> Result<()> {
        storage::repository_check(self.repository, Some(&self.plan), boundary)?;
        if namespaces(self.repository)? != self.commitment.namespaces {
            return Err("publication namespace inode or mount changed".into());
        }
        Ok(())
    }
    fn verify_files(&self, boundary: &mut impl Boundary) -> Result<()> {
        self.check(boundary)?;
        let parent = if self.published {
            &self.repository.outcomes
        } else {
            &self.repository.pending
        };
        let name = luma_content::sha256(self.plan.request_id().as_bytes());
        let current = storage::directory(parent, &name)?;
        for directory in [&self.directory, &current] {
            storage::check_private(directory, true)?;
            if directory_identity(&directory.metadata()?) != self.commitment.directory
                || mount(directory)? != self.commitment.directory_mount_id
            {
                return Err("held prepared directory was replaced or remounted".into());
            }
            if storage::names(directory, 3)? != ["payload.json", "record.json", "source.bin"] {
                return Err(
                    "prepared publication does not contain exactly three immutable members".into(),
                );
            }
        }
        for (file, member) in self.files.iter().zip(&self.commitment.members) {
            self.check(boundary)?;
            let expected = self.expected(&member.name)?;
            let named = storage::open(&self.directory, &member.name, libc::O_RDONLY, 0)?;
            for candidate in [file, &named] {
                storage::check_private(candidate, false)?;
                let metadata = candidate.metadata()?;
                if file_identity(&metadata) != member.identity
                    || metadata.len() != member.bytes
                    || mount(candidate)? != member.mount_id
                {
                    return Err("held immutable publication member identity changed".into());
                }
            }
            let mut offset = 0usize;
            let mut buffer = [0u8; 32 * 1024];
            while offset < expected.len() {
                self.check(boundary)?;
                let length = (expected.len() - offset).min(buffer.len());
                let count = file.read_at(&mut buffer[..length], offset as u64)?;
                self.check(boundary)?;
                if count == 0 || buffer[..count] != expected[offset..offset + count] {
                    return Err("held prepared publication bytes changed".into());
                }
                offset += count;
            }
            self.check(boundary)?;
            if file.read_at(&mut buffer[..1], offset as u64)? != 0 {
                return Err("held prepared publication grew beyond exact source commitment".into());
            }
            let named = storage::open(&self.directory, &member.name, libc::O_RDONLY, 0)?;
            for candidate in [file, &named] {
                let metadata = candidate.metadata()?;
                if file_identity(&metadata) != member.identity
                    || metadata.len() != member.bytes
                    || mount(candidate)? != member.mount_id
                {
                    return Err(
                        "prepared publication changed during exact held-file verification".into(),
                    );
                }
            }
            self.check(boundary)?;
        }
        self.check(boundary)
    }

    /// Fresh live admission and full current history/retirement/held-file
    /// validation. Any failure permanently fences this particular handle.
    pub fn recheck(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        if self.fenced {
            return Err("prepared publication handle is permanently fenced".into());
        }
        self.fenced = true;
        boundary.admit(
            &self.repository.binding,
            ResourceBudget::mutation(self.plan.storage_bytes()),
        )?;
        self.check(boundary)?;
        let snapshot = self.repository.snapshot(Some(&self.plan), boundary)?;
        if snapshot.records.len() as u64 != self.commitment.base_outcome_count
            || history_head(
                &self.repository.binding,
                snapshot.records.iter().map(|(record, _, _)| record),
            )? != self.commitment.base_head_sha256
            || snapshot.quarantine_sha256 != self.commitment.quarantine_sha256
            || snapshot.pending != self.pending_names
        {
            return Err(
                "publication base history, retirement evidence or preparation namespace changed"
                    .into(),
            );
        }
        self.verify_files(boundary)?;
        self.fenced = false;
        Ok(())
    }

    /// Consume this held preparation through the caller's current independent
    /// authorization. No custody authority is inferred from its commitment.
    /// Errors after rename retain an unacknowledged committed outcome; errors
    /// before rename retain the preparation for fresh authorized reconciliation.
    pub fn publish(self, boundary: &mut impl Boundary) -> Result<Outcome> {
        self.publish_with_hook(boundary, |_| Ok(()))
    }
    pub(super) fn publish_with_hook(
        mut self,
        boundary: &mut impl Boundary,
        mut hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<Outcome> {
        self.recheck(boundary)?;
        self.fenced = true;
        if !self.published {
            let name = luma_content::sha256(self.plan.request_id().as_bytes());
            let mut check = || self.check(boundary);
            storage::rename(
                &self.repository.pending,
                &self.repository.outcomes,
                &name,
                &mut check,
                || hook(Phase::Renamed),
            )?;
            self.published = true;
            self.repository.root.sync_all()?;
            hook(Phase::Committed)?;
        }
        self.verify_files(boundary)?;
        let wanted = self.commitment.outcome_state();
        self.repository
            .snapshot_for_state(Some(&self.plan), boundary, Some(&wanted))?;
        self.check(boundary)?;
        Ok(outcome(&self.record, self.commitment.already_published))
    }
}
