//! Explicit local archive export and disposition. Evidence is not custody,
//! authentication, a remote-storage attestation, or permission to delete.
use super::*;
use crate::finite_grants::{Action, Audit, Kind, Selector};
use crate::utc_stream::Observation;
use std::io::Read;

const MAX_LOCAL: u64 = 16 * 1024;
const MAX_DOMAINS: usize = 1024;
const MIN_GRACE: u64 = 3600;
const MAX_GRACE: u64 = 30 * 86400;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
    sha256: String,
}
fn meta(m: &fs::Metadata, sha256: &str) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        modified: m.mtime(),
        modified_ns: m.mtime_nsec(),
        changed: m.ctime(),
        changed_ns: m.ctime_nsec(),
        sha256: sha256.into(),
    }
}
impl Identity {
    fn validate(&self, max: u64) -> Result<()> {
        if self.inode == 0
            || self.uid != 0
            || self.gid != 0
            || self.mode & 0o7777 != 0o400
            || self.length == 0
            || self.length > max
            || !io::hash(&self.sha256)
        {
            return Err("invalid immutable policy history identity".into());
        }
        Ok(())
    }
}
fn read(directory: &File, name: &str, max: u64) -> Result<(Vec<u8>, Identity)> {
    let file = io::open_at(directory, name, libc::O_RDONLY, 0)?;
    let before = file.metadata()?;
    let mut bytes = Vec::new();
    (&file)
        .take(max.checked_add(1).ok_or("policy history bound overflow")?)
        .read_to_end(&mut bytes)?;
    let digest = io::digest(&bytes);
    let identity = meta(&before, &digest);
    identity.validate(max)?;
    if before.nlink() != 1
        || bytes.len() as u64 != before.len()
        || meta(&file.metadata()?, &digest) != identity
        || meta(
            &io::open_at(directory, name, libc::O_RDONLY, 0)?.metadata()?,
            &digest,
        ) != identity
    {
        return Err("policy history member changed while reading".into());
    }
    Ok((bytes, identity))
}
fn recheck(directory: &File, name: &str, expected: &Identity) -> Result<()> {
    let file = io::open_at(directory, name, libc::O_RDONLY, 0)?;
    let observed = file.metadata()?;
    if !observed.is_file()
        || observed.nlink() != 1
        || meta(&observed, &expected.sha256) != *expected
    {
        return Err("policy history exact inode changed before dispatch".into());
    }
    Ok(())
}
fn canonical<T: Serialize + for<'a> Deserialize<'a>>(
    dir: &File,
    name: &str,
) -> Result<(T, Identity)> {
    let (bytes, identity) = read(dir, name, MAX_LOCAL)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical policy history record; preserve it".into());
    }
    Ok((value, identity))
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(io::digest(&serde_json::to_vec(value)?))
}
fn grace(seconds: u64) -> Result<i64> {
    if !(MIN_GRACE..=MAX_GRACE).contains(&seconds) {
        return Err("explicit policy archive grace must be one hour to thirty days".into());
    }
    Ok(i64::try_from(
        seconds.checked_mul(1000).ok_or("archive grace overflow")?,
    )?)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    installation: String,
    operation_id: String,
    name: String,
    identity: Identity,
    original_subjects: Vec<Subject>,
}
impl Snapshot {
    fn validate(&self) -> Result<()> {
        self.identity.validate(MAX_ARCHIVE)?;
        let (op, sha) = archive_name(&self.name)?;
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || !id(&self.operation_id)
            || op != self.operation_id
            || sha != self.identity.sha256
            || self.original_subjects.len() > 64
            || self
                .original_subjects
                .iter()
                .any(|s| !io::hash(&s.principal) || s.generation == 0)
            || self
                .original_subjects
                .windows(2)
                .any(|s| (&s[0].principal, s[0].generation) >= (&s[1].principal, s[1].generation))
        {
            return Err("invalid exact archive snapshot".into());
        }
        Ok(())
    }
    fn scope(&self, action: Action) -> Result<Use> {
        self.validate()?;
        let use_ = Use {
            action,
            selector: Selector {
                kind: if action == Action::Retain {
                    Kind::Resource
                } else {
                    Kind::Artifact
                },
                id: "policy-archive".into(),
                generation: 1,
                digest: digest(&("luma-policy-archive-effect-v1", self, action))?,
            },
            input_bytes: self.identity.length + 4 * MAX_LOCAL,
            output_bytes: if action == Action::Export {
                self.identity.length
            } else {
                MAX_LOCAL
            },
            units: 1,
        };
        use_.validate()?;
        Ok(use_)
    }
}
fn target(store: &Store, op: &str) -> Result<(Snapshot, Vec<u8>, Archive)> {
    if !id(op) {
        return Err("invalid fixed archive operation".into());
    }
    let matches: Vec<_> = io::names(&store.archives, MAX_ARCHIVES)?
        .into_iter()
        .filter(|n| archive_name(n).is_ok_and(|(operation, _)| operation == op))
        .collect();
    if matches.len() != 1 {
        return Err("exact retained policy archive unavailable".into());
    }
    let name = &matches[0];
    let (bytes, identity) = read(&store.archives, name, MAX_ARCHIVE)?;
    let archive: Archive = serde_json::from_slice(&bytes)?;
    archive.validate()?;
    if archive.installation != store.installation
        || archive.operation_id != op
        || serde_json::to_vec(&archive)? != bytes
    {
        return Err("retained archive identity or canonical content differs".into());
    }
    // Never dispose unresolved effects, even inside a terminal denied operation.
    if archive.records.iter().any(|r|matches!(r.payload,Payload::OperationFinished {outcome:OperationOutcome::Uncertain}|Payload::EffectFinished {outcome:OperationOutcome::Uncertain,..}))
        || archive.records.iter().filter(|r|matches!(r.payload,Payload::EffectStarted {..})).any(|start|!archive.records.iter().any(|r|matches!(&r.payload,Payload::EffectFinished {begin_id,outcome:OperationOutcome::Completed,..} if begin_id==&start.record_id))) {
        return Err("pending or uncertain policy evidence must remain local".into());
    }
    let snapshot = Snapshot {
        schema_version: 1,
        installation: store.installation.clone(),
        operation_id: op.into(),
        name: name.clone(),
        identity,
        original_subjects: archive
            .records
            .iter()
            .filter_map(|r| {
                if let Payload::Decision { decision } = &r.payload {
                    decision.subject.as_ref()
                } else {
                    None
                }
            })
            .map(|s| (s.principal.clone(), s.generation))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|(principal, generation)| Subject {
                principal,
                generation,
            })
            .collect(),
    };
    snapshot.validate()?;
    Ok((snapshot, bytes, archive))
}
fn no_originals(store: &Store, archive: &Archive) -> Result<()> {
    let names = io::names(&store.root, MAX_RECORDS + 5)?;
    if archive
        .records
        .iter()
        .any(|r| names.contains(&format!("record-{}.json", r.record_id)))
    {
        return Err("complete original archive retention before disposition".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportAck {
    schema_version: u32,
    snapshot: Snapshot,
    audit: Audit,
    observed: Timestamp,
    stdout_delivery_complete: bool,
    remote_storage_attested: bool,
}
impl ExportAck {
    fn validate(&self) -> Result<()> {
        self.snapshot.validate()?;
        self.audit.validate()?;
        self.observed.validate()?;
        if self.schema_version != 1
            || !self.stdout_delivery_complete
            || self.remote_storage_attested
            || self.audit.usage != self.snapshot.scope(Action::Export)?
        {
            return Err("invalid local archive export acknowledgment".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Mark {
    schema_version: u32,
    snapshot: Snapshot,
    ack: ExportAck,
    ack_identity: Identity,
    grace_seconds: u64,
    observed: Timestamp,
    audit: Audit,
}
impl Mark {
    fn scope(&self) -> Result<Use> {
        let use_ = Use {
            action: Action::Retain,
            selector: Selector {
                kind: Kind::Resource,
                id: "policy-archive-mark".into(),
                generation: 1,
                digest: digest(&(
                    "luma-policy-archive-mark-v1",
                    &self.snapshot,
                    &self.ack,
                    &self.ack_identity,
                    self.grace_seconds,
                ))?,
            },
            input_bytes: self.snapshot.identity.length + 4 * MAX_LOCAL,
            output_bytes: MAX_LOCAL,
            units: 1,
        };
        use_.validate()?;
        Ok(use_)
    }
    fn validate(&self) -> Result<()> {
        self.snapshot.validate()?;
        self.ack.validate()?;
        self.ack_identity.validate(MAX_LOCAL)?;
        self.observed.validate()?;
        grace(self.grace_seconds)?;
        self.audit.validate()?;
        if self.schema_version != 1
            || self.snapshot != self.ack.snapshot
            || self.ack_identity.sha256 != digest(&self.ack)?
            || self.audit.usage != self.scope()?
        {
            return Err("archive grace mark changed exact acknowledged target".into());
        }
        Ok(())
    }
    fn not_before(&self) -> Result<i64> {
        self.observed
            .upper_ms
            .checked_add(grace(self.grace_seconds)?)
            .ok_or_else(|| "archive grace deadline overflow".into())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct DeletePlan {
    schema_version: u32,
    mark: Mark,
    mark_identity: Identity,
    domain: (u64, u64),
}
impl DeletePlan {
    fn validate(&self) -> Result<()> {
        self.mark.validate()?;
        self.mark_identity.validate(MAX_LOCAL)?;
        if self.schema_version != 1
            || self.domain.1 == 0
            || self.mark_identity.sha256 != digest(&self.mark)?
        {
            return Err("invalid archive disposition plan".into());
        }
        Ok(())
    }
    fn scope(&self) -> Result<Use> {
        self.validate()?;
        let use_ = Use {
            action: Action::Delete,
            selector: Selector {
                kind: Kind::Artifact,
                id: "policy-archive".into(),
                generation: 1,
                digest: digest(&("luma-policy-archive-delete-v1", self))?,
            },
            input_bytes: self.mark.snapshot.identity.length + 4 * MAX_LOCAL,
            output_bytes: MAX_LOCAL,
            units: 1,
        };
        use_.validate()?;
        Ok(use_)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Evidence {
    Export {
        ack: ExportAck,
    },
    Mark {
        mark: Mark,
    },
    Delete {
        plan: DeletePlan,
        observed: Timestamp,
    },
    Cleanup {
        plan: Box<CleanupPlan>,
    },
}
impl Evidence {
    pub(super) fn authorization(&self) -> Result<(EffectKind, Use, Option<&Audit>)> {
        Ok(match self {
            Self::Export { ack } => (
                EffectKind::ArtifactExport,
                ack.snapshot.scope(Action::Export)?,
                Some(&ack.audit),
            ),
            Self::Mark { mark } => (EffectKind::Retention, mark.scope()?, Some(&mark.audit)),
            Self::Delete { plan, .. } => (EffectKind::Deletion, plan.scope()?, None),
            Self::Cleanup { plan } => (EffectKind::Retention, plan.scope()?, None),
        })
    }
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Export { ack } => ack.validate(),
            Self::Mark { mark } => mark.validate(),
            Self::Delete { plan, observed } => {
                plan.validate()?;
                observed.validate()?;
                if observed.lower_ms < plan.mark.not_before()? {
                    return Err("archive deletion evidence precedes protected grace".into());
                }
                Ok(())
            }
            Self::Cleanup { plan } => plan.validate(),
        }
    }
}

pub(super) fn validate_directory(directory: &File) -> Result<()> {
    validate_history_directory(directory, true).map(|_| ())
}
fn validate_history_directory(directory: &File, allow_retired: bool) -> Result<u64> {
    io::private_directory(directory)?;
    let mut bytes = 0u64;
    for op in io::names(directory, MAX_DOMAINS + 1)? {
        if op == "retired" && allow_retired {
            bytes = bytes
                .checked_add(validate_history_directory(
                    &io::child_directory(directory, "retired")?,
                    false,
                )?)
                .ok_or("aggregate policy history size overflow")?;
            continue;
        }
        if !id(&op) {
            return Err("unknown policy history domain; preserve it".into());
        }
        let child = io::child_directory(directory, &op)?;
        if child.metadata()?.dev() != directory.metadata()?.dev() {
            return Err("policy history changed filesystem".into());
        }
        for name in io::names(&child, 5)? {
            if !matches!(
                name.as_str(),
                "ack.json" | "mark.json" | "intent.json" | "done.json" | "cleanup.json"
            ) {
                return Err("unknown policy history evidence".into());
            }
            let file = io::open_at(&child, &name, libc::O_RDONLY, 0)?;
            let m = file.metadata()?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != 0
                || m.gid() != 0
                || m.mode() & 0o7777 != 0o400
                || m.len() > MAX_LOCAL
            {
                return Err("unsafe policy history evidence; preserve it".into());
            }
            bytes = bytes
                .checked_add(m.len())
                .ok_or("policy history storage overflow")?;
            if bytes > 64 * 1024 * 1024 {
                return Err("policy history storage bound exceeded".into());
            }
        }
    }
    if bytes > 64 * 1024 * 1024 {
        return Err("aggregate policy history bound exceeded".into());
    }
    Ok(bytes)
}
struct History<'a> {
    store: &'a Store,
    op: String,
    directory: File,
    identity: (u64, u64),
    parent: File,
    retired: bool,
}
impl<'a> History<'a> {
    fn open(store: &'a Store, op: &str, create: bool) -> Result<Self> {
        if !id(op) {
            return Err("invalid policy history domain".into());
        }
        let names = io::names(&store.history, MAX_DOMAINS + 1)?;
        let retired_parent = if names.iter().any(|n| n == "retired") {
            Some(io::child_directory(&store.history, "retired")?)
        } else {
            None
        };
        let retired = retired_parent
            .as_ref()
            .map(|p| io::names(p, MAX_DOMAINS).map(|v| v.iter().any(|n| n == op)))
            .transpose()?
            .unwrap_or(false);
        if retired && names.iter().any(|n| n == op) {
            return Err("duplicate active and retired policy history".into());
        }
        let parent = if retired {
            retired_parent.unwrap()
        } else {
            store.history.try_clone()?
        };
        let directory = if names.iter().any(|name| name == op) {
            io::child_directory(&store.history, op)?
        } else if retired {
            io::child_directory(&parent, op)?
        } else {
            if !create || names.len() >= MAX_DOMAINS {
                return Err("policy history domain absent or capacity exhausted".into());
            }
            let _lock = store.lock()?;
            let directory = io::mkdir_at(&store.history, op)?;
            directory.sync_all()?;
            store.history.sync_all()?;
            directory
        };
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("policy history operation busy".into());
        }
        let m = directory.metadata()?;
        let result = Self {
            store,
            op: op.into(),
            directory,
            identity: (m.dev(), m.ino()),
            parent,
            retired,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let _root_guard = self.store.lock()?;
        io::private_directory(&self.directory)?;
        let expected_parent = if self.retired {
            io::child_directory(&self.store.history, "retired")?
        } else {
            self.store.history.try_clone()?
        };
        let actual_parent = self.parent.metadata()?;
        let expected_meta = expected_parent.metadata()?;
        if (actual_parent.dev(), actual_parent.ino()) != (expected_meta.dev(), expected_meta.ino())
        {
            return Err("policy history parent replaced".into());
        }
        let current = io::child_directory(&self.parent, &self.op)?.metadata()?;
        if (current.dev(), current.ino()) != self.identity
            || current.dev() != self.store.history.metadata()?.dev()
        {
            return Err("policy history operation directory replaced".into());
        }
        Ok(())
    }
    fn has(&self, name: &str) -> Result<bool> {
        self.check()?;
        Ok(io::names(&self.directory, 5)?.iter().any(|n| n == name))
    }
    fn publish<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        self.check()?;
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > MAX_LOCAL {
            return Err("policy history evidence exceeds bound".into());
        }
        if self.has(name)? {
            if io::read_member(&self.directory, name, MAX_LOCAL)? != bytes {
                return Err("policy history existing evidence differs; preserve it".into());
            }
            return Ok(());
        }
        let _quota_guard = self.store.lock()?;
        if validate_history_directory(&self.store.history, true)?
            .checked_add(bytes.len() as u64)
            .ok_or("aggregate policy history write overflow")?
            > 64 * 1024 * 1024
        {
            return Err("policy history quota exhausted before staging".into());
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.directory.as_raw_fd(), &mut space) } != 0
            || space
                .f_bavail
                .checked_mul(space.f_frsize)
                .ok_or("policy history free space overflow")?
                < bytes.len() as u64 + 16 * 1024 * 1024
        {
            return Err("policy history storage reserve unavailable".into());
        }
        io::write_member(&self.directory, name, &bytes, 0o400)?;
        self.directory.sync_all()?;
        self.store.history.sync_all()?;
        drop(_quota_guard);
        self.check()
    }
    fn ack(&self) -> Result<(ExportAck, Identity)> {
        let (ack, identity) = canonical::<ExportAck>(&self.directory, "ack.json")?;
        ack.validate()?;
        if ack.snapshot.operation_id != self.op
            || ack.snapshot.installation != self.store.installation
        {
            return Err("foreign archive export acknowledgment".into());
        }
        Ok((ack, identity))
    }
    fn mark(&self) -> Result<(Mark, Identity)> {
        let (mark, identity) = canonical::<Mark>(&self.directory, "mark.json")?;
        mark.validate()?;
        let (ack, ack_identity) = self.ack()?;
        if mark.ack != ack || mark.ack_identity != ack_identity {
            return Err("archive grace acknowledgment changed".into());
        }
        Ok((mark, identity))
    }
    fn plan(&self) -> Result<DeletePlan> {
        let (mark, mark_identity) = self.mark()?;
        let plan = DeletePlan {
            schema_version: 1,
            mark,
            mark_identity,
            domain: self.identity,
        };
        plan.validate()?;
        Ok(plan)
    }
}

fn inspection(login: &str, op: &str) -> Result<Use> {
    if !id(op) {
        return Err("invalid archive operation selector".into());
    }
    let (_, principal, installation) = crate::admin_governance::current_principal(login)?;
    let use_ = Use {
        action: Action::Read,
        selector: Selector {
            kind: Kind::File,
            id: "policy-archive-inspect".into(),
            generation: principal.generation,
            digest: digest(&(
                "luma-policy-archive-inspection-v1",
                installation,
                principal.id,
                principal.generation,
                op,
            ))?,
        },
        input_bytes: 0,
        output_bytes: MAX_ARCHIVE + 4 * MAX_LOCAL,
        units: 1,
    };
    use_.validate()?;
    Ok(use_)
}
fn guard_scope(
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    expected: &Use,
) -> Result<Audit> {
    boundary.check()?;
    let audit = boundary.audit()?;
    if audit.usage != *expected {
        return Err("archive dispatcher exact scope differs".into());
    }
    Ok(audit)
}
fn finish(
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    pending: PendingEffect,
    evidence: Evidence,
) -> Result<()> {
    pending.complete_evidence(boundary.operation_id(), evidence)?;
    boundary.check()
}
fn mark_template(
    snapshot: Snapshot,
    ack: ExportAck,
    ack_identity: Identity,
    seconds: u64,
) -> Result<(String, Use)> {
    grace(seconds)?;
    if snapshot != ack.snapshot {
        return Err("archive inode changed since export acknowledgment".into());
    }
    let review = digest(&(
        "luma-policy-archive-mark-v1",
        &snapshot,
        &ack,
        &ack_identity,
        seconds,
    ))?;
    let use_ = Use {
        action: Action::Retain,
        selector: Selector {
            kind: Kind::Resource,
            id: "policy-archive-mark".into(),
            generation: 1,
            digest: review.clone(),
        },
        input_bytes: snapshot.identity.length + 4 * MAX_LOCAL,
        output_bytes: MAX_LOCAL,
        units: 1,
    };
    use_.validate()?;
    Ok((review, use_))
}
fn export_checked(
    store: &Store,
    snapshot: &Snapshot,
    bytes: &[u8],
    output: &mut impl std::io::Write,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    if bytes.len() as u64 != snapshot.identity.length
        || io::digest(bytes) != snapshot.identity.sha256
    {
        return Err("archive export bytes differ from reviewed snapshot".into());
    }
    for block in bytes.chunks(32768) {
        check()?;
        recheck(&store.archives, &snapshot.name, &snapshot.identity)?;
        output.write_all(block)?;
    }
    check()?;
    recheck(&store.archives, &snapshot.name, &snapshot.identity)?;
    output.flush()?;
    check()?;
    Ok(())
}
fn delete_checked(
    history: &History<'_>,
    plan: &DeletePlan,
    mut observe: impl FnMut() -> Result<Observation>,
    after_unlink: impl FnOnce() -> Result<()>,
) -> Result<Evidence> {
    plan.validate()?;
    history.check()?;
    if history.plan()? != *plan {
        return Err("archive deletion plan changed".into());
    }
    let (snapshot, _, archive) = target(history.store, &history.op)?;
    if snapshot != plan.mark.snapshot {
        return Err("archive changed after reviewed grace".into());
    }
    no_originals(history.store, &archive)?;
    if history.has("done.json")? {
        return Err("archive deletion already has a confirmed outcome".into());
    }
    let first = observe()?;
    if first.interval().endpoints().0 < plan.mark.not_before()? {
        return Err("protected archive grace has not elapsed".into());
    }
    history.publish("intent.json", plan)?;
    if history.plan()? != *plan {
        return Err("archive deletion evidence changed after preparation".into());
    }
    let (_, _, current) = target(history.store, &history.op)?;
    no_originals(history.store, &current)?;
    let observed = Timestamp::observed(&observe()?)?;
    if observed.lower_ms < plan.mark.not_before()? {
        return Err("protected archive grace changed before dispatch".into());
    }
    history.check()?;
    recheck(&history.directory, "ack.json", &plan.mark.ack_identity)?;
    recheck(&history.directory, "mark.json", &plan.mark_identity)?;
    recheck(
        &history.store.archives,
        &plan.mark.snapshot.name,
        &plan.mark.snapshot.identity,
    )?;
    let name = std::ffi::CString::new(plan.mark.snapshot.name.clone())?;
    if unsafe { libc::unlinkat(history.store.archives.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    history.store.archives.sync_all()?;
    after_unlink()?;
    if io::names(&history.store.archives, MAX_ARCHIVES)?.contains(&plan.mark.snapshot.name) {
        return Err("archive unlink outcome uncertain".into());
    }
    Ok(Evidence::Delete {
        plan: plan.clone(),
        observed,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CleanupPlan {
    schema_version: u32,
    installation: String,
    operation_id: String,
    domain: (u64, u64),
    files: BTreeMap<String, Identity>,
    done: Option<Evidence>,
}
impl CleanupPlan {
    fn validate(&self) -> Result<()> {
        if let Some(done) = &self.done {
            done.validate()?;
        }
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || !id(&self.operation_id)
            || self.domain.1 == 0
            || (self.done.is_none() && !self.files.is_empty())
            || (self.done.is_some()
                && (self.files.len() != 4
                    || self
                        .files
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                        != BTreeSet::from(["ack.json", "mark.json", "intent.json", "done.json"])))
        {
            return Err("cleanup cannot remove incomplete or uncertain archive evidence".into());
        }
        match &self.done {
            Some(Evidence::Delete { plan, .. })
                if plan.mark.snapshot.operation_id == self.operation_id
                    && plan.mark.snapshot.installation == self.installation
                    && plan.domain == self.domain => {}
            None if self.files.is_empty() => {}
            _ => return Err("cleanup lacks exact completed archive deletion".into()),
        }
        for value in self.files.values() {
            value.validate(MAX_LOCAL)?;
        }
        if let Some(Evidence::Delete { plan, .. }) = &self.done {
            for (name, value) in [
                ("ack.json", serde_json::to_vec(&plan.mark.ack)?),
                ("mark.json", serde_json::to_vec(&plan.mark)?),
                ("intent.json", serde_json::to_vec(plan)?),
                (
                    "done.json",
                    serde_json::to_vec(self.done.as_ref().unwrap())?,
                ),
            ] {
                if self.files[name].sha256 != io::digest(&value)
                    || self.files[name].length != value.len() as u64
                {
                    return Err("cleanup outcome does not preserve exact removed bytes".into());
                }
            }
        }
        Ok(())
    }
    fn scope(&self) -> Result<Use> {
        self.validate()?;
        let use_ = Use {
            action: Action::Retain,
            selector: Selector {
                kind: Kind::Resource,
                id: "policy-archive-history".into(),
                generation: 1,
                digest: digest(&("luma-policy-archive-history-cleanup-v1", self))?,
            },
            input_bytes: self.files.values().map(|v| v.length).sum(),
            output_bytes: MAX_LOCAL,
            units: if self.done.is_some() { 6 } else { 1 },
        };
        use_.validate()?;
        Ok(use_)
    }
}
fn cleanup_plan(history: &History<'_>) -> Result<CleanupPlan> {
    history.check()?;
    if history.has("cleanup.json")? {
        let (plan, _) = canonical::<CleanupPlan>(&history.directory, "cleanup.json")?;
        plan.validate()?;
        if plan.installation != history.store.installation
            || plan.operation_id != history.op
            || plan.domain != history.identity
        {
            return Err("foreign exact cleanup intent".into());
        }
        for name in io::names(&history.directory, 5)? {
            if name == "cleanup.json" {
                continue;
            }
            let expected = plan
                .files
                .get(&name)
                .ok_or("unknown surviving cleanup evidence")?;
            let (_, identity) = read(&history.directory, &name, MAX_LOCAL)?;
            if identity != *expected {
                return Err("surviving cleanup evidence changed".into());
            }
        }
        if !history.retired
            && plan
                .files
                .keys()
                .any(|name| !history.has(name).unwrap_or(false))
        {
            return Err("active cleanup intent has missing evidence".into());
        }
        if let Some(Evidence::Delete { plan: deleted, .. }) = &plan.done {
            if io::names(&history.store.archives, MAX_ARCHIVES)?
                .contains(&deleted.mark.snapshot.name)
            {
                return Err("disposed archive resurrected".into());
            }
        }
        return Ok(plan);
    }
    if history.retired && io::names(&history.directory, 5)?.is_empty() {
        return Ok(CleanupPlan {
            schema_version: 1,
            installation: history.store.installation.clone(),
            operation_id: history.op.clone(),
            domain: history.identity,
            files: BTreeMap::new(),
            done: None,
        });
    }
    let (done, _) = canonical::<Evidence>(&history.directory, "done.json")?;
    let (intent, _) = canonical::<DeletePlan>(&history.directory, "intent.json")?;
    let plan = history.plan()?;
    if intent != plan
        || !matches!(&done,Evidence::Delete {plan:done_plan,..} if done_plan==&plan)
        || io::names(&history.store.archives, MAX_ARCHIVES)?.contains(&plan.mark.snapshot.name)
    {
        return Err("archive history still pending, changed or physically present".into());
    }
    let mut files = BTreeMap::new();
    for name in ["ack.json", "mark.json", "intent.json", "done.json"] {
        let (_, identity) = read(&history.directory, name, MAX_LOCAL)?;
        files.insert(name.into(), identity);
    }
    let result = CleanupPlan {
        schema_version: 1,
        installation: history.store.installation.clone(),
        operation_id: history.op.clone(),
        domain: history.identity,
        files,
        done: Some(done),
    };
    result.validate()?;
    Ok(result)
}
fn cleanup_checked(
    history: &mut History<'_>,
    plan: &CleanupPlan,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    if cleanup_plan(history)? != *plan {
        return Err("archive cleanup exact evidence changed".into());
    }
    if plan.done.is_none() {
        return Ok(());
    }
    history.publish("cleanup.json", plan)?;
    check()?;
    if !history.retired {
        let retired = if io::names(&history.store.history, MAX_DOMAINS + 1)?
            .iter()
            .any(|n| n == "retired")
        {
            io::child_directory(&history.store.history, "retired")?
        } else {
            let _lock = history.store.lock()?;
            let d = io::mkdir_at(&history.store.history, "retired")?;
            history.store.history.sync_all()?;
            d
        };
        if io::names(&retired, MAX_DOMAINS)?.len() >= MAX_DOMAINS {
            return Err("retired history capacity exhausted; complete exact cleanup first".into());
        }
        history.check()?;
        let name = std::ffi::CString::new(history.op.as_str())?;
        if unsafe {
            libc::renameat2(
                history.parent.as_raw_fd(),
                name.as_ptr(),
                retired.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        history.parent.sync_all()?;
        retired.sync_all()?;
        history.parent = retired;
        history.retired = true;
        history.check()?;
    }
    // Full removed bytes remain bound in cleanup.json and later in the typed
    // durable effect outcome. Missing expected members are resumable only in
    // the retired namespace, never an unresolved active operation.
    for (name, identity) in &plan.files {
        check()?;
        history.check()?;
        if !history.has(name)? {
            continue;
        }
        recheck(&history.directory, name, identity)?;
        let name = std::ffi::CString::new(name.as_str())?;
        if unsafe { libc::unlinkat(history.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        history.directory.sync_all()?;
    }
    Ok(())
}
fn cleanup_finalize(
    history: &History<'_>,
    plan: &CleanupPlan,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    history.check()?;
    if !history.retired {
        return Err("cleanup finalization requires retired namespace".into());
    }
    let names = io::names(&history.directory, 5)?;
    if plan.done.is_some() {
        if names != vec!["cleanup.json".to_owned()] {
            return Err("archive cleanup is not exactly drained".into());
        }
        let (value, identity) = canonical::<CleanupPlan>(&history.directory, "cleanup.json")?;
        if value != *plan {
            return Err("cleanup finalization exact intent changed".into());
        }
        check()?;
        history.check()?;
        recheck(&history.directory, "cleanup.json", &identity)?;
        let name = std::ffi::CString::new("cleanup.json")?;
        if unsafe { libc::unlinkat(history.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        history.directory.sync_all()?;
    } else if !names.is_empty() {
        return Err("empty retired cleanup has new evidence".into());
    }
    check()?;
    history.check()?;
    if !io::names(&history.directory, 5)?.is_empty() {
        return Err("retired cleanup directory gained evidence".into());
    }
    let name = std::ffi::CString::new(history.op.clone())?;
    if unsafe {
        libc::unlinkat(
            history.parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    history.parent.sync_all()?;
    Ok(())
}
fn outcomes(history: &History<'_>) -> Result<serde_json::Value> {
    history.check()?;
    if history.retired || history.has("cleanup.json")? {
        let plan = cleanup_plan(history)?;
        let confirmed = plan.done.is_some();
        return Ok(
            serde_json::json!({"operation_id":history.op,"export_ack":plan.files.get("ack.json").map(|v|&v.sha256),"mark_sha256":plan.files.get("mark.json").map(|v|&v.sha256),"deletion_intent":confirmed,"confirmed_deletion":confirmed,"cleanup_phase":if history.retired{"retired"}else{"prepared"},"confirmation_available":confirmed,"remote_storage_attested":false,"automatic_delete":false,"receipt_authority":false}),
        );
    }
    let ack = if history.has("ack.json")? {
        Some(history.ack()?.1.sha256)
    } else {
        None
    };
    let mark = if history.has("mark.json")? {
        Some(history.mark()?.1.sha256)
    } else {
        None
    };
    let intent = if history.has("intent.json")? {
        let (value, _) = canonical::<DeletePlan>(&history.directory, "intent.json")?;
        value.validate()?;
        if value != history.plan()? {
            return Err("deletion intent differs from current exact history".into());
        }
        Some(value)
    } else {
        None
    };
    let confirmed =
        if history.has("done.json")? {
            let (value, _) = canonical::<Evidence>(&history.directory, "done.json")?;
            value.validate()?;
            match value {
                Evidence::Delete { plan, .. }
                    if Some(&plan) == intent.as_ref()
                        && plan.domain == history.identity
                        && !io::names(&history.store.archives, MAX_ARCHIVES)?
                            .contains(&plan.mark.snapshot.name) =>
                {
                    true
                }
                _ => return Err(
                    "reported deletion lacks exact canonical completed outcome and archive absence"
                        .into(),
                ),
            }
        } else {
            false
        };
    history.check()?;
    Ok(
        serde_json::json!({"operation_id":history.op,"export_ack":ack,"mark_sha256":mark,"deletion_intent":intent.is_some(),"confirmed_deletion":confirmed,"confirmation_available":confirmed,"cleanup_phase":"active","remote_storage_attested":false,"automatic_delete":false,"receipt_authority":false}),
    )
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if args.len() < 3 {
        return Err("policy archive command requires current login and exact operation".into());
    }
    let verb = args[0].as_str();
    let op = if verb == "policy-archive-review" {
        args.get(2)
    } else {
        args.get(3)
    }
    .ok_or("missing exact archive operation")?;
    let read_use = inspection(&args[1], op)?;
    if verb == "policy-archive-review" && args.len() == 3 {
        println!(
            "{}",
            serde_json::json!({"usage":read_use,"archive_read":false,"grant_issued":false})
        );
        return Ok(());
    }
    let store = Store::installed()?;
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &read_use, |reader| {
        reader.check()?;
        match verb {
            "policy-archive-export-proposal" if args.len()==4=>{let(snapshot,_,_)=target(&store,op)?;reader.check()?;Ok(Some(serde_json::json!({"review_sha256":digest(&snapshot)?,"usage":snapshot.scope(Action::Export)?,"snapshot":snapshot,"remote_storage_attested":false})))},
            "policy-archive-export" if args.len()==6=>{
                let(snapshot,bytes,_)=target(&store,op)?;let usage=snapshot.scope(Action::Export)?;if args[5]!=digest(&snapshot)?{return Err("archive export review changed".into());}
                crate::admin_governance::with_grant(&args[1],&args[4],&usage,|boundary|{
                    reader.check()?;let audit=guard_scope(boundary,&usage)?;let pending=boundary.effect_begin(&args[5],EffectKind::ArtifactExport)?;
                    let history=History::open(&store,op,true)?;
                    if history.has("intent.json")? || history.has("mark.json")? {return Err("archive already has a disposition intent; inspect preserved state".into());}
                    let mut output=crate::service::granted_gateway::export_writer()?;export_checked(&store,&snapshot,&bytes,&mut output,||{reader.stream_check(&pending)?;boundary.stream_check(&pending)})?;
                    let ack=ExportAck {schema_version:1,snapshot:snapshot.clone(),audit,observed:Timestamp::observed(&boundary.observation()?)?,stdout_delivery_complete:true,remote_storage_attested:false};ack.validate()?;
                    finish(boundary,pending,Evidence::Export {ack:ack.clone()})?;
                    // Only a confirmed delivery may create the local ack. An
                    // older exact ack is retained rather than rewritten.
                    if history.has("ack.json")? {if history.ack()?.0.snapshot!=snapshot{return Err("existing archive acknowledgment names different bytes".into());}}else{reader.check()?;boundary.check()?;history.publish("ack.json",&ack)?;}
                    boundary.check()?;Ok(())
                })?;Ok(None)
            },
            "policy-archive-dispose-proposal" if args.len()==6=>{
                let(snapshot,_,archive)=target(&store,op)?;no_originals(&store,&archive)?;let history=History::open(&store,op,false)?;let(ack,identity)=history.ack()?;if args[4]!=identity.sha256{return Err("archive export acknowledgment changed".into());}let seconds=args[5].parse::<u64>()?;if seconds.to_string()!=args[5]{return Err("archive grace must be canonical seconds".into());}let(review,usage)=mark_template(snapshot,ack,identity,seconds)?;reader.check()?;Ok(Some(serde_json::json!({"review_sha256":review,"usage":usage,"grace_seconds":seconds,"automatic_delete":false,"remote_storage_attested":false})))
            },
            "policy-archive-dispose-mark" if args.len()==8=>{
                let(snapshot,_,archive)=target(&store,op)?;no_originals(&store,&archive)?;let history=History::open(&store,op,false)?;let(ack,identity)=history.ack()?;if args[5]!=identity.sha256{return Err("archive acknowledgment changed".into());}let seconds=args[6].parse::<u64>()?;if seconds.to_string()!=args[6]{return Err("archive grace must be canonical seconds".into());}let(review,usage)=mark_template(snapshot.clone(),ack.clone(),identity.clone(),seconds)?;if args[7]!=review{return Err("archive disposition review changed".into());}
                crate::admin_governance::with_grant(&args[1],&args[4],&usage,|boundary|{reader.check()?;let audit=guard_scope(boundary,&usage)?;let pending=boundary.effect_begin(&review,EffectKind::Retention)?;
                    let(_,_,archive)=target(&store,op)?;no_originals(&store,&archive)?;let observed=Timestamp::observed(&boundary.observation()?)?;recheck(&store.archives,&snapshot.name,&snapshot.identity)?;recheck(&history.directory,"ack.json",&identity)?;
                    let mark=Mark {schema_version:1,snapshot,ack,ack_identity:identity,grace_seconds:seconds,observed,audit};mark.validate()?;history.publish("mark.json",&mark)?;finish(boundary,pending,Evidence::Mark {mark:mark.clone()})?;Ok(serde_json::json!({"mark_sha256":digest(&mark)?,"not_before_ms":mark.not_before()?,"automatic_delete":false}))
                }).map(Some)
            },
            "policy-archive-delete-proposal" if args.len()==5=>{let history=History::open(&store,op,false)?;let plan=history.plan()?;if args[4]!=plan.mark_identity.sha256{return Err("archive mark changed".into());}let(snapshot,_,archive)=target(&store,op)?;if snapshot!=plan.mark.snapshot{return Err("archive target changed".into());}no_originals(&store,&archive)?;reader.check()?;Ok(Some(serde_json::json!({"review_sha256":digest(&plan)?,"usage":plan.scope()?,"not_before_ms":plan.mark.not_before()?})))},
            "policy-archive-delete" if args.len()==7=>{let history=History::open(&store,op,false)?;let plan=history.plan()?;if args[5]!=plan.mark_identity.sha256 || args[6]!=digest(&plan)?{return Err("archive deletion review changed".into());}let usage=plan.scope()?;
                crate::admin_governance::with_grant(&args[1],&args[4],&usage,|boundary|{reader.check()?;guard_scope(boundary,&usage)?;let pending=boundary.effect_begin(&args[6],EffectKind::Deletion)?;
                    let evidence=delete_checked(&history,&plan,||{reader.check()?;boundary.observation()},||Ok(()))?;
                    finish(boundary,pending,evidence.clone())?;reader.check()?;boundary.check()?;history.publish("done.json",&evidence)?;boundary.check()?;Ok(serde_json::json!({"operation_id":op,"archive_deleted":true,"cleanup_requires_separate_finite_grant":true,"receipt_authority":false}))
                }).map(Some)
            },
            "policy-archive-cleanup-proposal" if args.len()==4=>{let history=History::open(&store,op,false)?;let plan=cleanup_plan(&history)?;reader.check()?;Ok(Some(serde_json::json!({"review_sha256":digest(&plan)?,"usage":plan.scope()?,"completed_outcome_preserved_in_policy_records":true})))},
            "policy-archive-cleanup" if args.len()==6=>{let mut history=History::open(&store,op,false)?;let plan=cleanup_plan(&history)?;if args[5]!=digest(&plan)?{return Err("archive cleanup review changed".into());}let usage=plan.scope()?;
                crate::admin_governance::with_grant(&args[1],&args[4],&usage,|boundary|{reader.check()?;guard_scope(boundary,&usage)?;let pending=boundary.effect_begin(&args[5],EffectKind::Retention)?;cleanup_checked(&mut history,&plan,||{reader.check()?;boundary.check()})?;let evidence=Evidence::Cleanup{plan:Box::new(plan.clone())};finish(boundary,pending,evidence.clone())?;let pending=boundary.effect_begin("archive-cleanup-finalize",EffectKind::Retention)?;cleanup_finalize(&history,&plan,||{reader.check()?;boundary.check()})?;finish(boundary,pending,evidence)?;Ok(serde_json::json!({"operation_id":op,"history_disposed":true,"automatic_purge":false}))}).map(Some)
            },
            "policy-archive-outcomes" if args.len()==4=>{let history=History::open(&store,op,false)?;let result=outcomes(&history)?;reader.check()?;Ok(Some(result))},
            _=>Err("expected closed policy-archive review/export-proposal/export/dispose-proposal/dispose-mark/delete-proposal/delete/cleanup-proposal/cleanup/outcomes command".into())
        }
    })?;
    if let Some(result) = result {
        println!("{result}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let base =
                std::env::var("LUMA_STORAGE_TEST_ROOT").expect("isolated ext4 storage required");
            let path = Path::new(&base).join(format!(
                "luma-policy-history-{label}-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> Rc<Store> {
            Rc::new(Store::open(&self.0, &"ab".repeat(32)).unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn usage() -> Use {
        Use {
            action: Action::Read,
            selector: Selector {
                kind: Kind::File,
                id: "history-test".into(),
                generation: 1,
                digest: "12".repeat(32),
            },
            input_bytes: 0,
            output_bytes: 8192,
            units: 1,
        }
    }
    fn retained(store: Rc<Store>, outcome: OperationOutcome, remove: bool) -> String {
        let mut operation =
            Operation::begin(store.clone(), &[("test-read".into(), usage())]).unwrap();
        let op = operation.id().to_owned();
        operation
            .decisions(vec![Decision::unavailable(
                "test-read",
                &usage(),
                Reason::AuthenticationUnavailable,
            )
            .unwrap()])
            .unwrap();
        operation.finish(outcome).unwrap();
        let archive = store.retention_input(&op).unwrap();
        let (_, bytes, _) = archive_review(&archive).unwrap();
        store.archive(&archive, &bytes).unwrap();
        if remove {
            for record in &archive.records {
                store.unlink_archived(record, &archive).unwrap();
            }
        }
        op
    }
    fn timestamp(lower: i64) -> Timestamp {
        Timestamp {
            context: crate::utc_history::Statement {
                floor_ms: lower,
                policy_sha256: crate::utc_history::policy_digest().unwrap(),
                boot_id: "12".repeat(16),
                process_generation: 1,
                source_clock_generation: 1,
                keeper_generation: 1,
                runtime_sha256: "34".repeat(32),
            },
            lower_ms: lower,
            upper_ms: lower + 200,
        }
    }
    fn observation(lower: i64) -> Observation {
        let t = timestamp(lower);
        Observation::fixture(
            t.context,
            crate::utc_bounds::Interval::new(t.lower_ms, t.upper_ms).unwrap(),
        )
    }
    fn audit(usage: Use) -> Audit {
        Audit {
            subject: "cd".repeat(32),
            subject_generation: 1,
            grant_id: "exact-history".into(),
            grant_version: 1,
            checkpoint_head: "ef".repeat(32),
            operation_id: Some("56".repeat(16)),
            usage,
        }
    }
    fn mark(history: &History<'_>) -> DeletePlan {
        let (snapshot, _, _) = target(history.store, &history.op).unwrap();
        let ack = ExportAck {
            schema_version: 1,
            audit: audit(snapshot.scope(Action::Export).unwrap()),
            snapshot: snapshot.clone(),
            observed: timestamp(1000),
            stdout_delivery_complete: true,
            remote_storage_attested: false,
        };
        history.publish("ack.json", &ack).unwrap();
        let (_, ack_identity) = history.ack().unwrap();
        let (_, usage) = mark_template(
            snapshot.clone(),
            ack.clone(),
            ack_identity.clone(),
            MIN_GRACE,
        )
        .unwrap();
        let mark = Mark {
            schema_version: 1,
            snapshot,
            ack,
            ack_identity,
            grace_seconds: MIN_GRACE,
            observed: timestamp(2000),
            audit: audit(usage),
        };
        mark.validate().unwrap();
        history.publish("mark.json", &mark).unwrap();
        history.plan().unwrap()
    }
    #[test]
    fn exact_archive_streams_only_reviewed_bytes_and_delivery_failure_has_no_ack() {
        let fixture = Fixture::new("export");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let (snapshot, bytes, _) = target(&store, &op).unwrap();
        let history = History::open(&store, &op, true).unwrap();
        let mut output = Vec::new();
        let mut checks = 0;
        export_checked(&store, &snapshot, &bytes, &mut output, || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(output, bytes);
        assert!(checks >= 3);
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "receiver gone",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(export_checked(&store, &snapshot, &bytes, &mut Broken, || Ok(())).is_err());
        assert!(!history.has("ack.json").unwrap());
        let mut altered = snapshot.clone();
        altered.identity.inode += 1;
        assert!(export_checked(&store, &altered, &bytes, &mut Vec::new(), || Ok(())).is_err());
        let uncertain = retained(store.clone(), OperationOutcome::Uncertain, true);
        assert!(target(&store, &uncertain).is_err());
    }
    #[test]
    fn grace_requires_entire_fresh_interval_and_exact_originals_drained() {
        let fixture = Fixture::new("grace");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, false);
        let history = History::open(&store, &op, true).unwrap();
        let plan = mark(&history);
        let deadline = plan.mark.not_before().unwrap();
        assert!(delete_checked(&history, &plan, || Ok(observation(deadline)), || Ok(())).is_err());
        let archive = store.retention_input(&op).unwrap();
        for record in &archive.records {
            store.unlink_archived(record, &archive).unwrap();
        }
        assert!(
            delete_checked(&history, &plan, || Ok(observation(deadline - 1)), || Ok(())).is_err()
        );
        assert!(!history.has("intent.json").unwrap());
        let evidence =
            delete_checked(&history, &plan, || Ok(observation(deadline)), || Ok(())).unwrap();
        evidence.validate().unwrap();
        assert!(target(&store, &op).is_err());
        assert!(history.has("intent.json").unwrap());
        history.publish("done.json", &evidence).unwrap();
        assert!(cleanup_plan(&history).is_ok());
    }
    #[test]
    fn interrupted_physical_delete_preserves_intent_and_cannot_claim_confirmed_cleanup() {
        let fixture = Fixture::new("uncertain-delete");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let history = History::open(&store, &op, true).unwrap();
        let plan = mark(&history);
        let deadline = plan.mark.not_before().unwrap();
        assert!(delete_checked(
            &history,
            &plan,
            || Ok(observation(deadline)),
            || Err("simulated after-unlink loss".into())
        )
        .is_err());
        assert!(history.has("intent.json").unwrap());
        assert!(!history.has("done.json").unwrap());
        assert!(cleanup_plan(&history).is_err());
        assert!(delete_checked(&history, &plan, || Ok(observation(deadline)), || Ok(())).is_err());
    }
    #[test]
    fn changed_archive_inode_and_symlink_or_extra_wire_fields_refuse() {
        let fixture = Fixture::new("substitute");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let history = History::open(&store, &op, true).unwrap();
        let plan = mark(&history);
        let deadline = plan.mark.not_before().unwrap();
        let path = fixture.0.join("archives").join(&plan.mark.snapshot.name);
        let saved = fixture.0.join("saved.json");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert!(target(&store, &op).is_err());
        assert!(delete_checked(&history, &plan, || Ok(observation(deadline)), || Ok(())).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&saved, &path).unwrap();
        let mut wire = serde_json::to_value(&plan).unwrap();
        wire["caller_time"] = deadline.into();
        assert!(serde_json::from_value::<DeletePlan>(wire).is_err());
        let mut counterfeit = plan.clone();
        counterfeit.mark.ack.remote_storage_attested = true;
        assert!(counterfeit.validate().is_err());
        let empty = "90".repeat(16);
        let active = History::open(&store, &empty, true).unwrap();
        assert!(cleanup_plan(&active).is_err());
    }
    #[test]
    fn completed_cleanup_resumes_exact_retired_members_and_preserves_full_typed_outcome() {
        let fixture = Fixture::new("cleanup");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let mut history = History::open(&store, &op, true).unwrap();
        let deletion = mark(&history);
        let evidence = delete_checked(
            &history,
            &deletion,
            || Ok(observation(deletion.mark.not_before().unwrap())),
            || Ok(()),
        )
        .unwrap();
        history.publish("done.json", &evidence).unwrap();
        let plan = cleanup_plan(&history).unwrap();
        let original = digest(&plan).unwrap();
        let mut checks = 0;
        assert!(cleanup_checked(&mut history, &plan, || {
            checks += 1;
            if checks == 3 {
                Err("simulated cleanup interruption".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(history.retired);
        assert!(history.has("cleanup.json").unwrap());
        assert_eq!(digest(&cleanup_plan(&history).unwrap()).unwrap(), original);
        drop(history);
        let mut reopened = History::open(&store, &op, false).unwrap();
        assert!(reopened.retired);
        cleanup_checked(&mut reopened, &plan, || Ok(())).unwrap();
        assert_eq!(
            io::names(&reopened.directory, 5).unwrap(),
            vec!["cleanup.json"]
        );
        let typed = Evidence::Cleanup {
            plan: Box::new(plan.clone()),
        };
        typed.validate().unwrap();
        let encoded = serde_json::to_vec(&typed).unwrap();
        assert!(encoded.len() as u64 <= MAX_LOCAL);
        assert_eq!(serde_json::from_slice::<Evidence>(&encoded).unwrap(), typed);
        cleanup_finalize(&reopened, &plan, || Ok(())).unwrap();
        assert!(History::open(&store, &op, false).is_err());
        assert!(store.inventory().unwrap().is_empty());
    }
    #[test]
    fn final_cleanup_interruption_keeps_empty_retired_recoverable_but_never_active_empty() {
        let fixture = Fixture::new("finalize");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let mut history = History::open(&store, &op, true).unwrap();
        let deletion = mark(&history);
        let evidence = delete_checked(
            &history,
            &deletion,
            || Ok(observation(deletion.mark.not_before().unwrap())),
            || Ok(()),
        )
        .unwrap();
        history.publish("done.json", &evidence).unwrap();
        let plan = cleanup_plan(&history).unwrap();
        cleanup_checked(&mut history, &plan, || Ok(())).unwrap();
        let mut checks = 0;
        assert!(cleanup_finalize(&history, &plan, || {
            checks += 1;
            if checks == 3 {
                Err("final directory commit unavailable".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(io::names(&history.directory, 5).unwrap().is_empty());
        let narrow = cleanup_plan(&history).unwrap();
        assert!(narrow.done.is_none());
        assert_eq!(narrow.scope().unwrap().units, 1);
        cleanup_finalize(&history, &narrow, || Ok(())).unwrap();
    }
    #[test]
    fn reported_confirmed_deletion_requires_canonical_outcome_and_exact_physical_absence() {
        let fixture = Fixture::new("outcome-report");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let history = History::open(&store, &op, true).unwrap();
        let plan = mark(&history);
        history.publish("intent.json", &plan).unwrap();
        assert_eq!(outcomes(&history).unwrap()["confirmed_deletion"], false);
        io::write_member(&history.directory, "done.json", b"{partial", 0o400).unwrap();
        assert!(outcomes(&history).is_err());
        fs::remove_file(fixture.0.join("history").join(&op).join("done.json")).unwrap();
        let counterfeit = Evidence::Delete {
            plan: plan.clone(),
            observed: timestamp(plan.mark.not_before().unwrap()),
        };
        history.publish("done.json", &counterfeit).unwrap();
        assert!(outcomes(&history).is_err());
        fs::remove_file(fixture.0.join("history").join(&op).join("done.json")).unwrap();
        let actual = delete_checked(
            &history,
            &plan,
            || Ok(observation(plan.mark.not_before().unwrap())),
            || Ok(()),
        )
        .unwrap();
        history.publish("done.json", &actual).unwrap();
        assert_eq!(outcomes(&history).unwrap()["confirmed_deletion"], true);
    }
    #[test]
    fn partial_retired_cleanup_reports_preserved_confirmed_copy_not_missing_file_presence() {
        let fixture = Fixture::new("retired-report");
        let store = fixture.store();
        let op = retained(store.clone(), OperationOutcome::Denied, true);
        let mut history = History::open(&store, &op, true).unwrap();
        let plan = mark(&history);
        let actual = delete_checked(
            &history,
            &plan,
            || Ok(observation(plan.mark.not_before().unwrap())),
            || Ok(()),
        )
        .unwrap();
        history.publish("done.json", &actual).unwrap();
        let cleanup = cleanup_plan(&history).unwrap();
        let mut calls = 0;
        assert!(cleanup_checked(&mut history, &cleanup, || {
            calls += 1;
            if calls == 3 {
                Err("interrupted after first unlink".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(history.retired);
        let reported = outcomes(&history).unwrap();
        assert_eq!(reported["confirmed_deletion"], true);
        assert_eq!(reported["cleanup_phase"], "retired");
    }
}
