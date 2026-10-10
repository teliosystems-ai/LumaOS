//! Durable coordinator for the closed, installed-root laboratory invoice DAG.
//! Snapshot input is not a folder grant; checkpoints are not product authority.
use crate::{
    artifact_catalog as catalog, artifacts as io, calculation, resources, scoped_read, skills,
    sqlite::Connection, workflow_resource, Result,
};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

const DIRECTORY: &str = "/var/lib/luma-os/workflow-runs";
const GOVERNED_DIRECTORY: &str = "/var/lib/luma-os/workflow-invoice-domains";
#[path = "workflow_dag.rs"]
pub(crate) mod dag;
#[path = "workflow_history.rs"]
pub(crate) mod history;
#[path = "workflow_recovery.rs"]
pub(crate) mod recovery;
const MAX_RUNS: usize = 256;
const MAX_OBJECTS: usize = 512;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OBJECT: u64 = 2 * 1024 * 1024;
const SCHEMA: &[&str] = &[
    "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), installation TEXT NOT NULL CHECK(length(installation)=64)) STRICT",
    "CREATE TABLE runs (request_id TEXT PRIMARY KEY, plan TEXT NOT NULL, current_stage INTEGER NOT NULL CHECK(current_stage BETWEEN 0 AND 5)) STRICT",
    "CREATE TABLE checkpoints (sequence INTEGER PRIMARY KEY CHECK(sequence>0), request_id TEXT NOT NULL REFERENCES runs(request_id), stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 5), canonical TEXT NOT NULL, UNIQUE(request_id,stage)) STRICT",
    "CREATE TRIGGER checkpoint_no_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT,'immutable checkpoint'); END",
    "CREATE TRIGGER checkpoint_no_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT,'retained checkpoint'); END",
    "CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity BEGIN SELECT RAISE(ABORT,'immutable installation'); END",
    "CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity BEGIN SELECT RAISE(ABORT,'immutable installation'); END",
    "CREATE TRIGGER runs_no_delete BEFORE DELETE ON runs BEGIN SELECT RAISE(ABORT,'retained run'); END",
    "CREATE TRIGGER runs_next BEFORE UPDATE ON runs WHEN NEW.request_id<>OLD.request_id OR NEW.plan<>OLD.plan OR NOT ((OLD.current_stage<4 AND NEW.current_stage=OLD.current_stage+1) OR (OLD.current_stage<3 AND NEW.current_stage=5)) BEGIN SELECT RAISE(ABORT,'invalid workflow transition'); END",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    environment: String,
    installation: String,
    request_id: String,
    artifact_id: String,
    expected_version: u64,
    workflow_sha256: String,
    source_sha256: String,
    source_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<PrincipalOwner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history_epoch: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrincipalOwner {
    principal: String,
    generation: u64,
}
impl Plan {
    fn validate(&self, installation: &str) -> Result<()> {
        if self.schema_version != 1
            || self.environment != "lab"
            || self.installation != installation
            || !io::hash(installation)
            || !io::identifier(&self.request_id)
            || !io::identifier(&self.artifact_id)
            || self.expected_version >= 1024
            || !io::hash(&self.workflow_sha256)
            || !io::hash(&self.source_sha256)
            || self.source_bytes == 0
            || self.source_bytes > 1024 * 1024
            || self
                .history_epoch
                .is_some_and(|epoch| epoch == 0 || epoch == u64::MAX)
        {
            return Err("invalid native invoice workflow plan".into());
        }
        if let Some(owner) = &self.authority {
            if crate::tpm::decode::<32>(&owner.principal)? == [0; 32] || owner.generation == 0 {
                return Err("invalid governed workflow owner".into());
            }
        }
        Ok(())
    }
    fn scope_digest(&self) -> Result<String> {
        let mut proposal = self.clone();
        proposal.authority = None;
        digest(&proposal)
    }
    fn check_owner(&self, boundary: &mut crate::admin_governance::GrantBoundary<'_>) -> Result<()> {
        boundary.check()?;
        let owner = self.authority.as_ref().ok_or(
            "laboratory workflow cannot become governed authority; preserve it and create a new request",
        )?;
        if owner.principal != boundary.subject()?
            || owner.generation != boundary.subject_generation()?
        {
            return Err("workflow owner or principal generation changed".into());
        }
        history::check_epoch(
            history::Domain::Invoice,
            &owner.principal,
            self.history_epoch.unwrap_or(0),
        )?;
        Ok(())
    }
    fn effect_id(&self) -> Result<String> {
        let mut bytes = b"luma-native-workflow-invoice-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(io::digest(&bytes))
    }
    fn commit<'a>(&'a self, effect: &'a str) -> catalog::InvoiceCommit<'a> {
        catalog::InvoiceCommit {
            installation: &self.installation,
            request_id: effect,
            artifact_id: &self.artifact_id,
            expected_version: self.expected_version,
            workflow_sha256: &self.workflow_sha256,
            source_sha256: &self.source_sha256,
        }
    }
    fn receipt(&self, effect: &str, bytes: &[u8]) -> Result<serde_json::Value> {
        if let Some(owner) = &self.authority {
            catalog::owned_invoice_receipt(
                &self.commit(effect),
                &owner.principal,
                owner.generation,
                bytes,
            )
        } else {
            catalog::invoice_receipt(&self.commit(effect), bytes)
        }
    }
    fn committed(&self, effect: &str, bytes: &[u8]) -> Result<catalog::InvoiceOutcome> {
        if let Some(owner) = &self.authority {
            catalog::committed_owned_invoice(
                &self.commit(effect),
                &owner.principal,
                owner.generation,
                bytes,
            )
        } else {
            catalog::committed_invoice(&self.commit(effect), bytes)
        }
    }
    fn publish(
        &self,
        effect: &str,
        bytes: &[u8],
        replay: bool,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        if let Some(owner) = &self.authority {
            catalog::commit_owned_invoice(
                &self.commit(effect),
                &owner.principal,
                owner.generation,
                bytes,
                replay,
                check,
            )
        } else {
            catalog::commit_invoice(&self.commit(effect), bytes, replay, check)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    stage: u32,
    plan_sha256: String,
    previous_sha256: String,
    report_sha256: String,
    receipt: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_lease: Option<resources::Token>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_operation_id: Option<String>,
}
enum TraceEvent {
    Begin {
        id: String,
        kind: crate::policy_decisions::EffectKind,
    },
    Complete {
        id: String,
        receipt: String,
    },
}
fn trace_begin(
    trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    id: &str,
    kind: crate::policy_decisions::EffectKind,
) -> Result<()> {
    trace(TraceEvent::Begin {
        id: id.into(),
        kind,
    })
}
fn trace_complete(
    trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    id: &str,
    receipt: &str,
) -> Result<()> {
    trace(TraceEvent::Complete {
        id: id.into(),
        receipt: receipt.into(),
    })
}
fn calculation_begin(
    trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    request: &str,
    stage: &str,
) -> Result<()> {
    use crate::policy_decisions::EffectKind;
    for (suffix, kind) in [
        ("worker", EffectKind::WorkerAdmission),
        ("resource", EffectKind::ResourceAdmission),
        ("calculate", EffectKind::Calculation),
    ] {
        trace_begin(trace, &format!("{request}.{stage}.{suffix}"), kind)?;
    }
    Ok(())
}
fn calculation_complete(
    trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    request: &str,
    stage: &str,
    result: &workflow_resource::Calculation,
) -> Result<()> {
    let receipt = digest(&(&result.lease, io::digest(&result.report)))?;
    for suffix in ["resource", "worker", "calculate"] {
        trace_complete(trace, &format!("{request}.{stage}.{suffix}"), &receipt)?;
    }
    Ok(())
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(io::digest(&serde_json::to_vec(value)?))
}
fn state(stage: u32) -> &'static str {
    match stage {
        0 => "prepared",
        1 => "source-read",
        2 => "calculated",
        3 => "applying",
        4 => "completed",
        5 => "cancelled",
        _ => "unknown",
    }
}

struct Transaction<'a>(&'a Connection, bool);
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.0.exec("ROLLBACK;");
        }
    }
}
impl Transaction<'_> {
    fn commit(mut self) -> Result<()> {
        self.0.exec("COMMIT;")?;
        self.1 = true;
        Ok(())
    }
}

struct Store {
    // SQLite closes before the exclusive directory lock is released.
    db: Connection,
    root: File,
    root_path: std::path::PathBuf,
    objects: File,
    pending: File,
    installation: String,
    domain_owner: Option<DomainOwner>,
    domain_owner_file: Option<File>,
    calculator: fn(&[u8], &mut dyn FnMut() -> Result<()>) -> Result<workflow_resource::Calculation>,
    calculation_check: fn(&workflow_resource::Calculation, &[u8], &str) -> Result<()>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DomainOwner {
    schema_version: u32,
    installation: String,
    principal: String,
}
pub(crate) fn initialize(path: &Path, installation: &str) -> Result<()> {
    initialize_domain(path, installation, None)
}
fn initialize_governed(path: &Path, installation: &str, principal: &str) -> Result<()> {
    if path.file_name().and_then(|name| name.to_str())
        != Some(io::digest(principal.as_bytes()).as_str())
        || !io::hash(principal)
    {
        return Err("governed invoice initializer requires its exact principal namespace".into());
    }
    initialize_domain(path, installation, Some(principal))
}
fn initialize_domain(path: &Path, installation: &str, principal: Option<&str>) -> Result<()> {
    if !io::hash(installation) {
        return Err("invalid workflow installation".into());
    }
    let parent = path.parent().ok_or("missing workflow parent")?;
    catalog::safe_path(parent)?;
    let parent_fd = scoped_read::open_directory(parent)?;
    catalog::ext4(&parent_fd)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("workflow initialization busy".into());
    }
    io::mkdir_at(&root, "objects")?;
    io::mkdir_at(&root, "pending")?;
    if let Some(principal) = principal {
        io::write_member(
            &root,
            "owner.json",
            &serde_json::to_vec(&DomainOwner {
                schema_version: 1,
                installation: installation.into(),
                principal: principal.into(),
            })?,
            0o400,
        )?;
    }
    io::write_member(&root, "metadata.sqlite3", b"", 0o600)?;
    let db = Connection::open(&path.join("metadata.sqlite3"))?;
    if db.query("PRAGMA journal_mode=WAL", &[], 1)? != [vec!["wal".to_owned()]] {
        return Err("workflow WAL unavailable".into());
    }
    db.exec("PRAGMA max_page_count=4096;")?;
    db.exec("PRAGMA application_id=1280788306;")?;
    db.exec("PRAGMA user_version=1;")?;
    db.exec("BEGIN IMMEDIATE;")?;
    let tx = Transaction(&db, false);
    for sql in SCHEMA {
        db.exec(sql)?;
    }
    db.query("INSERT INTO identity VALUES(1,?)", &[installation], 0)?;
    root.sync_all()?;
    tx.commit()?;
    drop(db);
    root.sync_all()?;
    parent_fd.sync_all()?;
    drop(root);
    drop(Store::open(path, installation)?);
    Ok(())
}
impl Store {
    fn open(path: &Path, installation: &str) -> Result<Self> {
        catalog::safe_path(path)?;
        let root = scoped_read::open_directory(path)?;
        io::private_directory(&root)?;
        catalog::ext4(&root)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("workflow coordinator is busy; cancellation was not accepted".into());
        }
        let names = io::names(&root, 6)?;
        let mut domain_owner_file = None;
        let domain_owner = if names.contains(&"owner.json".into()) {
            let file = io::open_at(&root, "owner.json", libc::O_RDONLY, 0)?;
            let bytes = io::read_member(&root, "owner.json", 4096)?;
            let owner: DomainOwner = serde_json::from_slice(&bytes)?;
            if file.metadata()?.mode() & 0o7777 != 0o400
                || serde_json::to_vec(&owner)? != bytes
                || owner.schema_version != 1
                || owner.installation != installation
                || !io::hash(&owner.principal)
                || path.file_name().and_then(|name| name.to_str())
                    != Some(io::digest(owner.principal.as_bytes()).as_str())
            {
                return Err(
                    "invoice domain owner marker differs from its actual namespace/installation"
                        .into(),
                );
            }
            domain_owner_file = Some(file);
            Some(owner)
        } else {
            None
        };
        if !names.contains(&"metadata.sqlite3".into())
            || !names.contains(&"objects".into())
            || !names.contains(&"pending".into())
        {
            return Err("incomplete workflow store; preserve state".into());
        }
        for name in names {
            match name.as_str() {
                "objects" | "pending" => (),
                "owner.json" => (),
                "metadata.sqlite3" | "metadata.sqlite3-wal" => {
                    io::read_member(&root, &name, 16 * 1024 * 1024)?;
                }
                "metadata.sqlite3-shm" => {
                    io::read_member(&root, &name, 65536)?;
                }
                _ => return Err("unknown workflow member; preserve state".into()),
            }
        }
        let objects = io::child_directory(&root, "objects")?;
        let pending = io::child_directory(&root, "pending")?;
        if objects.metadata()?.dev() != root.metadata()?.dev()
            || pending.metadata()?.dev() != root.metadata()?.dev()
        {
            return Err("workflow objects filesystem mismatch".into());
        }
        let db = Connection::open(&path.join("metadata.sqlite3"))?;
        if db.query("PRAGMA journal_mode", &[], 1)? != [vec!["wal".to_owned()]]
            || db.query("PRAGMA page_size", &[], 1)? != [vec!["4096".to_owned()]]
            || db.query("PRAGMA application_id", &[], 1)? != [vec!["1280788306".to_owned()]]
            || db.query("PRAGMA user_version", &[], 1)? != [vec!["1".to_owned()]]
            || db.query("SELECT installation FROM identity", &[], 1)?
                != [vec![installation.to_owned()]]
        {
            return Err("workflow store format/installation mismatch".into());
        }
        let mut actual = db
            .query(
                "SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                &[],
                SCHEMA.len(),
            )?
            .into_iter()
            .map(|r| r[0].clone())
            .collect::<Vec<_>>();
        let mut expected = SCHEMA.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        actual.sort();
        expected.sort();
        if actual != expected
            || db.query("PRAGMA quick_check", &[], 1)? != [vec!["ok".to_owned()]]
            || !db.query("PRAGMA foreign_key_check", &[], 1)?.is_empty()
        {
            return Err("workflow schema/integrity mismatch".into());
        }
        db.exec("PRAGMA max_page_count=4096;")?;
        let result = Self {
            root_path: path.into(),
            db,
            root,
            objects,
            pending,
            installation: installation.into(),
            domain_owner,
            domain_owner_file,
            calculator: workflow_resource::calculate_checked,
            calculation_check: workflow_resource::Calculation::recheck,
        };
        result.inventory()?;
        Ok(result)
    }
    fn require_owner(&self, principal: &str) -> Result<()> {
        catalog::safe_path(&self.root_path)?;
        if scoped_read::identity(&scoped_read::open_directory(&self.root_path)?)?
            != scoped_read::identity(&self.root)?
        {
            return Err("governed invoice domain detached from its actual namespace".into());
        }
        let expected = self.domain_owner.as_ref().filter(|owner| owner.principal == principal).ok_or("invoice namespace has no exact governed owner; do not adopt laboratory or old unowned history")?;
        let file = io::open_at(&self.root, "owner.json", libc::O_RDONLY, 0)?;
        let retained = self
            .domain_owner_file
            .as_ref()
            .ok_or("invoice owner descriptor missing")?
            .metadata()?;
        let named = file.metadata()?;
        if named.mode() & 0o7777 != 0o400
            || named.nlink() != 1
            || retained.nlink() != 1
            || (
                retained.dev(),
                retained.ino(),
                retained.len(),
                retained.ctime(),
                retained.ctime_nsec(),
                retained.mtime(),
                retained.mtime_nsec(),
            ) != (
                named.dev(),
                named.ino(),
                named.len(),
                named.ctime(),
                named.ctime_nsec(),
                named.mtime(),
                named.mtime_nsec(),
            )
            || io::read_member(&self.root, "owner.json", 4096)? != serde_json::to_vec(expected)?
        {
            return Err("invoice governed owner marker changed".into());
        }
        Ok(())
    }
    fn current_plan_owner(&self, plan: &Plan) -> Result<()> {
        if let Some(owner) = &self.domain_owner {
            self.require_owner(&owner.principal)?;
            if plan
                .authority
                .as_ref()
                .map(|owner| owner.principal.as_str())
                != Some(owner.principal.as_str())
            {
                return Err("invoice immutable plan differs from governed domain owner".into());
            }
        }
        Ok(())
    }
    fn object(&self, hash: &str) -> Result<Vec<u8>> {
        if !io::hash(hash) {
            return Err("invalid workflow object identity".into());
        }
        let bytes = io::read_member(&self.objects, hash, MAX_OBJECT)?;
        if io::digest(&bytes) != hash {
            return Err("workflow object corruption; preserve state".into());
        }
        Ok(bytes)
    }
    fn inventory(&self) -> Result<()> {
        let mut bytes = 0u64;
        for name in io::names(&self.objects, MAX_OBJECTS)? {
            bytes += self.object(&name)?.len() as u64;
            if bytes > MAX_BYTES {
                return Err("workflow object capacity exhausted".into());
            }
        }
        let objects = io::names(&self.objects, MAX_OBJECTS)?;
        let pending = io::names(&self.pending, MAX_OBJECTS)?;
        if objects.len() + pending.len() > MAX_OBJECTS {
            return Err("workflow file capacity exhausted".into());
        }
        for name in pending {
            if !io::hash(&name) || objects.contains(&name) {
                return Err("unknown/conflicting workflow preparation; preserve state".into());
            }
            bytes += io::read_member(&self.pending, &name, MAX_OBJECT)?.len() as u64;
            if bytes > MAX_BYTES {
                return Err("workflow preparation capacity exhausted".into());
            }
        }
        for row in self
            .db
            .query("SELECT request_id FROM runs", &[], MAX_RUNS)?
        {
            self.load(&row[0])?;
        }
        let rows = self.db.query(
            "SELECT sequence FROM checkpoints ORDER BY sequence",
            &[],
            MAX_RUNS * 5,
        )?;
        for (index, row) in rows.iter().enumerate() {
            if row != &[((index + 1) as u64).to_string()] {
                return Err("workflow checkpoint sequence discontinuity".into());
            }
        }
        Ok(())
    }
    fn load(&self, request: &str) -> Result<(Plan, Checkpoint)> {
        if let Some(owner) = &self.domain_owner {
            self.require_owner(&owner.principal)?;
        }
        if !io::identifier(request) {
            return Err("invalid workflow request".into());
        }
        let row = self.db.query(
            "SELECT plan,current_stage FROM runs WHERE request_id=?",
            &[request],
            1,
        )?;
        let row = row.first().ok_or("workflow run not found")?;
        let plan: Plan = serde_json::from_str(&row[0])?;
        plan.validate(&self.installation)?;
        self.current_plan_owner(&plan)?;
        if serde_json::to_string(&plan)? != row[0]
            || plan.request_id != request
            || self.object(&plan.source_sha256)?.len() as u64 != plan.source_bytes
        {
            return Err("workflow plan/source mismatch".into());
        }
        let checkpoints = self.db.query(
            "SELECT stage,canonical FROM checkpoints WHERE request_id=? ORDER BY sequence",
            &[request],
            5,
        )?;
        let mut previous: Option<Checkpoint> = None;
        for entry in checkpoints {
            let checkpoint: Checkpoint = serde_json::from_str(&entry[1])?;
            let valid_stage = match previous.as_ref() {
                None => checkpoint.stage == 0,
                Some(p) => {
                    (p.stage < 4 && checkpoint.stage == p.stage + 1)
                        || (p.stage < 3 && checkpoint.stage == 5)
                }
            };
            let expected_previous = match previous.as_ref() {
                Some(p) => digest(p)?,
                None => digest(&plan)?,
            };
            if serde_json::to_string(&checkpoint)? != entry[1]
                || checkpoint.stage.to_string() != entry[0]
                || !valid_stage
                || checkpoint.plan_sha256 != digest(&plan)?
                || checkpoint.previous_sha256 != expected_previous
                || checkpoint
                    .resource_lease
                    .as_ref()
                    .map_or(false, |token| !workflow_resource::token_valid(token))
                || checkpoint.policy_operation_id.as_ref().is_some_and(|id| {
                    id.len() != 32
                        || !id
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            {
                return Err("workflow checkpoint chain mismatch".into());
            }
            if (2..=4).contains(&checkpoint.stage) {
                let report = self.object(&checkpoint.report_sha256)?;
                let effect = plan.effect_id()?;
                let expected = plan.receipt(&effect, &report)?;
                if (checkpoint.stage == 4 && checkpoint.receipt.as_ref() != Some(&expected))
                    || (checkpoint.stage != 4 && checkpoint.receipt.is_some())
                {
                    return Err("workflow artifact receipt mismatch".into());
                }
                if let Some(p) = previous.as_ref().filter(|p| p.stage >= 2) {
                    if p.report_sha256 != checkpoint.report_sha256
                        || p.resource_lease != checkpoint.resource_lease
                    {
                        return Err("workflow report changed across checkpoints".into());
                    }
                }
            } else if checkpoint.receipt.is_some()
                || (checkpoint.stage != 5 && checkpoint.resource_lease.is_some())
                || (checkpoint.stage != 5 && !checkpoint.report_sha256.is_empty())
                || (checkpoint.stage == 5
                    && checkpoint.report_sha256
                        != previous
                            .as_ref()
                            .ok_or("missing cancelled predecessor")?
                            .report_sha256)
                || (checkpoint.stage == 5
                    && checkpoint.resource_lease
                        != previous
                            .as_ref()
                            .ok_or("missing cancelled predecessor")?
                            .resource_lease)
            {
                return Err("unexpected workflow checkpoint result".into());
            }
            previous = Some(checkpoint);
        }
        let last = previous.ok_or("workflow checkpoint missing")?;
        if last.stage.to_string() != row[1] {
            return Err("workflow current checkpoint differs from history".into());
        }
        Ok((plan, last))
    }
    fn put_object(&self, content: &[u8], mut check: impl FnMut() -> Result<()>) -> Result<String> {
        check()?;
        if content.is_empty() || content.len() as u64 > MAX_OBJECT {
            return Err("workflow object size denied".into());
        }
        let hash = io::digest(content);
        let names = io::names(&self.objects, MAX_OBJECTS)?;
        if names.contains(&hash) {
            if self.object(&hash)? != content {
                return Err("workflow object conflict".into());
            }
        } else {
            let mut total = 0u64;
            for name in &names {
                total += self.object(name)?.len() as u64;
            }
            let preparations = io::names(&self.pending, MAX_OBJECTS)?;
            for name in &preparations {
                total += io::read_member(&self.pending, name, MAX_OBJECT)?.len() as u64;
            }
            let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
            if !preparations.contains(&hash) {
                if names.len() + preparations.len() >= MAX_OBJECTS
                    || total + content.len() as u64 > MAX_BYTES
                    || unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut space) } != 0
                    || space
                        .f_bavail
                        .checked_mul(space.f_frsize)
                        .ok_or("workflow capacity overflow")?
                        < content.len() as u64 + 16 * 1024 * 1024
                {
                    return Err("workflow storage capacity/reserve exhausted".into());
                }
                check()?;
                io::write_member(&self.pending, &hash, content, 0o400)?;
                self.pending.sync_all()?;
            }
            // Complete exact preparations can resume; partial bytes are fenced.
            if io::read_member(&self.pending, &hash, MAX_OBJECT)? != content {
                return Err(
                    "partial workflow object requires explicit review; preserve bytes".into(),
                );
            }
            io::open_at(&self.pending, &hash, libc::O_RDONLY, 0)?.sync_all()?;
            self.pending.sync_all()?;
            let name = CString::new(hash.as_str())?;
            check()?;
            if unsafe {
                libc::renameat2(
                    self.pending.as_raw_fd(),
                    name.as_ptr(),
                    self.objects.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err("workflow object publication uncertain; reinspect".into());
            }
            self.objects.sync_all()?;
            self.pending.sync_all()?;
        }
        io::open_at(&self.objects, &hash, libc::O_RDONLY, 0)?.sync_all()?;
        self.objects.sync_all()?;
        self.root.sync_all()?;
        check()?;
        Ok(hash)
    }
    fn prepare(
        &self,
        plan: &Plan,
        source: &[u8],
        authorize: impl FnMut(&Plan) -> Result<()>,
    ) -> Result<bool> {
        self.prepare_traced(plan, source, authorize, None, &mut |_| Ok(()))
    }
    fn prepare_traced(
        &self,
        plan: &Plan,
        source: &[u8],
        mut authorize: impl FnMut(&Plan) -> Result<()>,
        operation: Option<&str>,
        trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    ) -> Result<bool> {
        plan.validate(&self.installation)?;
        let mut authorize = |plan: &Plan| -> Result<()> {
            authorize(plan)?;
            self.current_plan_owner(plan)
        };
        if plan.authority.is_some() && operation.is_none() {
            return Err(
                "governed workflow requires its live audited operation, not laboratory callbacks"
                    .into(),
            );
        }
        if io::digest(source) != plan.source_sha256 || source.len() as u64 != plan.source_bytes {
            return Err("workflow proposed source mismatch".into());
        }
        authorize(plan)?;
        if !self
            .db
            .query(
                "SELECT request_id FROM runs WHERE request_id=?",
                &[&plan.request_id],
                1,
            )?
            .is_empty()
        {
            let (old, _) = self.load(&plan.request_id)?;
            if old != *plan {
                return Err("workflow preparation idempotency conflict".into());
            }
            authorize(plan)?;
            self.root.sync_all()?;
            authorize(plan)?;
            return Ok(true);
        }
        if self
            .db
            .query("SELECT request_id FROM runs", &[], MAX_RUNS)?
            .len()
            >= MAX_RUNS
        {
            return Err("workflow run capacity exhausted".into());
        }
        authorize(plan)?;
        calculation_begin(trace, &plan.request_id, "prepare")?;
        let validation = (self.calculator)(source, &mut || authorize(plan))?;
        authorize(plan)?;
        (self.calculation_check)(&validation, source, &plan.installation)?;
        authorize(plan)?;
        calculation_complete(trace, &plan.request_id, "prepare", &validation)?;
        let snapshot_id = format!("{}.snapshot", plan.request_id);
        trace_begin(
            trace,
            &snapshot_id,
            crate::policy_decisions::EffectKind::Snapshot,
        )?;
        self.put_object(source, || authorize(plan))?;
        trace_complete(
            trace,
            &snapshot_id,
            &digest(&(plan.source_sha256.as_str(), plan.source_bytes))?,
        )?;
        let checkpoint = Checkpoint {
            stage: 0,
            plan_sha256: digest(plan)?,
            previous_sha256: digest(plan)?,
            report_sha256: String::new(),
            receipt: None,
            resource_lease: None,
            policy_operation_id: operation.map(str::to_owned),
        };
        let checkpoint_id = format!("{}.prepare.checkpoint", plan.request_id);
        trace_begin(
            trace,
            &checkpoint_id,
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        self.db.exec("BEGIN IMMEDIATE;")?;
        let tx = Transaction(&self.db, false);
        self.db.query(
            "INSERT INTO runs VALUES(?,?,0)",
            &[&plan.request_id, &serde_json::to_string(plan)?],
            0,
        )?;
        self.insert(plan, &checkpoint)?;
        authorize(plan)?;
        (self.calculation_check)(&validation, source, &plan.installation)?;
        self.root.sync_all()?;
        authorize(plan)?;
        tx.commit()?;
        self.root.sync_all()?;
        authorize(plan)?;
        trace_complete(trace, &checkpoint_id, &digest(&checkpoint)?)?;
        Ok(false)
    }
    fn insert(&self, plan: &Plan, checkpoint: &Checkpoint) -> Result<()> {
        self.db.query(
            "INSERT INTO checkpoints(request_id,stage,canonical) VALUES(?,?,?)",
            &[
                &plan.request_id,
                &checkpoint.stage.to_string(),
                &serde_json::to_string(checkpoint)?,
            ],
            0,
        )?;
        Ok(())
    }
    fn transition(
        &self,
        plan: &Plan,
        previous: &Checkpoint,
        next: &Checkpoint,
        mut authorize: impl FnMut(&Plan) -> Result<()>,
    ) -> Result<()> {
        if self.load(&plan.request_id)? != (plan.clone(), previous.clone()) {
            return Err("workflow changed before checkpoint commit".into());
        }
        let mut authorize = |plan: &Plan| -> Result<()> {
            authorize(plan)?;
            self.current_plan_owner(plan)
        };
        self.db.exec("BEGIN IMMEDIATE;")?;
        let tx = Transaction(&self.db, false);
        self.db.query(
            "UPDATE runs SET current_stage=? WHERE request_id=? AND current_stage=?",
            &[
                &next.stage.to_string(),
                &plan.request_id,
                &previous.stage.to_string(),
            ],
            0,
        )?;
        if self.db.query("SELECT changes()", &[], 1)? != [vec!["1".to_owned()]] {
            return Err("workflow checkpoint compare-exchange conflict".into());
        }
        self.insert(plan, next)?;
        authorize(plan)?;
        self.root.sync_all()?;
        authorize(plan)?;
        tx.commit()?;
        self.root.sync_all()?;
        authorize(plan)?;
        Ok(())
    }
    fn status(&self, request: &str) -> Result<serde_json::Value> {
        let (plan, checkpoint) = self.load(request)?;
        Ok(
            serde_json::json!({"schema_version":1,"environment":"lab","request_id":request,
            "state":state(checkpoint.stage),"plan":plan,"review_sha256":digest(&checkpoint)?,
            "resource_lease":checkpoint.resource_lease,
            "resource_provenance":if checkpoint.resource_lease.is_some() { "broker-receipt" }
                else if checkpoint.report_sha256.is_empty() { "not-calculated" } else { "legacy-unavailable" },
            "effect_request_id":plan.effect_id()?,"receipt":checkpoint.receipt,
            "cancellation_allowed":checkpoint.stage < 3 || checkpoint.stage == 5,
            "input_kind":"operator-stdin-snapshot","product_admin_active":false,
            "governed_owner":plan.authority,
            "folder_grant":false,"gate_closing":false}),
        )
    }
    fn cancel(
        &self,
        request: &str,
        review: &str,
        authorize: impl FnMut(&Plan) -> Result<()>,
    ) -> Result<()> {
        self.cancel_traced(request, review, authorize, None)
    }
    fn cancel_traced(
        &self,
        request: &str,
        review: &str,
        mut authorize: impl FnMut(&Plan) -> Result<()>,
        operation: Option<&str>,
    ) -> Result<()> {
        let (plan, previous) = self.load(request)?;
        let mut authorize = |plan: &Plan| -> Result<()> {
            authorize(plan)?;
            self.current_plan_owner(plan)
        };
        if plan.authority.is_some() && operation.is_none() {
            return Err("governed cancellation requires its live audited operation".into());
        }
        if !io::hash(review)
            || (digest(&previous)? != review
                && !(previous.stage == 5 && previous.previous_sha256 == review))
        {
            return Err("workflow changed since cancellation review".into());
        }
        authorize(&plan)?;
        if previous.stage == 5 {
            self.root.sync_all()?;
            return Ok(());
        }
        if previous.stage >= 3 {
            return Err(
                "artifact outcome may be committed; cancellation refused, reconcile instead".into(),
            );
        }
        let mut next = previous.clone();
        next.stage = 5;
        next.previous_sha256 = digest(&previous)?;
        next.policy_operation_id = operation.map(str::to_owned);
        self.transition(&plan, &previous, &next, authorize)
    }
    fn advance(
        &self,
        request: &str,
        review: &str,
        authorize: impl FnMut(&Plan) -> Result<()>,
        effect: impl FnMut(
            &Plan,
            &[u8],
            bool,
            &mut dyn FnMut() -> Result<()>,
        ) -> Result<serde_json::Value>,
    ) -> Result<()> {
        self.advance_traced(request, review, authorize, effect, None, &mut |_| Ok(()))
    }
    fn advance_traced(
        &self,
        request: &str,
        review: &str,
        mut authorize: impl FnMut(&Plan) -> Result<()>,
        mut effect: impl FnMut(
            &Plan,
            &[u8],
            bool,
            &mut dyn FnMut() -> Result<()>,
        ) -> Result<serde_json::Value>,
        operation: Option<&str>,
        trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    ) -> Result<()> {
        let (plan, previous) = self.load(request)?;
        if plan.authority.is_some() && operation.is_none() {
            return Err("governed continuation requires its live audited operation".into());
        }
        let mut authorize = |plan: &Plan| -> Result<()> {
            authorize(plan)?;
            self.current_plan_owner(plan)
        };
        let current_review = digest(&previous)?;
        let retry_previous_step =
            (1..=4).contains(&previous.stage) && previous.previous_sha256 == review;
        let retry_publication = previous.stage == 4
            && self
                .db
                .query(
                    "SELECT canonical FROM checkpoints WHERE request_id=? AND stage=3",
                    &[request],
                    1,
                )?
                .first()
                .map(|row| serde_json::from_str::<Checkpoint>(&row[0]))
                .transpose()?
                .map(|p| p.previous_sha256 == review)
                .unwrap_or(false);
        if !io::hash(review)
            || (current_review != review && !retry_previous_step && !retry_publication)
        {
            return Err("workflow changed since checkpoint review".into());
        }
        authorize(&plan)?;
        // Lost checkpoint acknowledgement must not advance an additional node.
        if current_review != review && previous.stage < 3 {
            self.root.sync_all()?;
            return Ok(());
        }
        if previous.stage == 5 {
            return Err("workflow cancelled; use a new authorized request".into());
        }
        let mut next = previous.clone();
        next.stage += 1;
        next.previous_sha256 = digest(&previous)?;
        next.policy_operation_id = operation.map(str::to_owned);
        match previous.stage {
            0 => {
                let id = format!("{request}.source.checkpoint");
                trace_begin(trace, &id, crate::policy_decisions::EffectKind::Checkpoint)?;
                self.object(&plan.source_sha256)?;
                self.transition(&plan, &previous, &next, &mut authorize)?;
                trace_complete(trace, &id, &digest(&next)?)?;
            }
            1 => {
                let source = self.object(&plan.source_sha256)?;
                authorize(&plan)?;
                calculation_begin(trace, request, "run")?;
                let result = (self.calculator)(&source, &mut || authorize(&plan))?;
                authorize(&plan)?;
                (self.calculation_check)(&result, &source, &plan.installation)?;
                calculation_complete(trace, request, "run", &result)?;
                next.report_sha256 = self.put_object(&result.report, || authorize(&plan))?;
                next.resource_lease = Some(result.lease.clone());
                let id = format!("{request}.calculated.checkpoint");
                trace_begin(trace, &id, crate::policy_decisions::EffectKind::Checkpoint)?;
                self.transition(&plan, &previous, &next, |plan| {
                    authorize(plan)?;
                    (self.calculation_check)(&result, &source, &plan.installation)
                })?;
                trace_complete(trace, &id, &digest(&next)?)?;
            }
            2 => {
                // Applying is durable BEFORE crossing the artifact boundary.
                let id = format!("{request}.applying.checkpoint");
                trace_begin(trace, &id, crate::policy_decisions::EffectKind::Checkpoint)?;
                self.transition(&plan, &previous, &next, &mut authorize)?;
                trace_complete(trace, &id, &digest(&next)?)?;
                self.finish(&plan, &next, &mut authorize, &mut effect, operation, trace)?;
            }
            3 => {
                self.finish(
                    &plan,
                    &previous,
                    &mut authorize,
                    &mut effect,
                    operation,
                    trace,
                )?;
            }
            4 => {
                let bytes = self.object(&previous.report_sha256)?;
                let result = effect(&plan, &bytes, true, &mut || {
                    self.check_current(&plan, &previous)?;
                    authorize(&plan)
                })?;
                if previous.receipt.as_ref() != Some(&result) {
                    return Err("workflow replay receipt changed".into());
                }
                self.root.sync_all()?;
            }
            _ => return Err("unsupported workflow stage".into()),
        }
        Ok(())
    }
    fn check_current(&self, plan: &Plan, checkpoint: &Checkpoint) -> Result<()> {
        if self.load(&plan.request_id)? != (plan.clone(), checkpoint.clone()) {
            return Err("workflow authority/checkpoint changed before effect".into());
        }
        Ok(())
    }
    fn finish(
        &self,
        plan: &Plan,
        applying: &Checkpoint,
        authorize: &mut impl FnMut(&Plan) -> Result<()>,
        effect: &mut impl FnMut(
            &Plan,
            &[u8],
            bool,
            &mut dyn FnMut() -> Result<()>,
        ) -> Result<serde_json::Value>,
        operation: Option<&str>,
        trace: &mut impl FnMut(TraceEvent) -> Result<()>,
    ) -> Result<()> {
        let bytes = self.object(&applying.report_sha256)?;
        let source = self.object(&plan.source_sha256)?;
        authorize(plan)?;
        let calculation = workflow_resource::Calculation {
            report: bytes.clone(),
            lease: applying.resource_lease.clone().ok_or(
                "workflow publication lacks its original resource provenance; retain and use a new request",
            )?,
        };
        authorize(plan)?;
        (self.calculation_check)(&calculation, &source, &plan.installation)?;
        let result = effect(plan, &bytes, false, &mut || {
            self.check_current(plan, applying)?;
            authorize(plan)?;
            (self.calculation_check)(&calculation, &source, &plan.installation)
        })?;
        let effect_id = plan.effect_id()?;
        if result != plan.receipt(&effect_id, &bytes)? {
            return Err("artifact boundary returned an unbound receipt".into());
        }
        let completed = Checkpoint {
            stage: 4,
            plan_sha256: applying.plan_sha256.clone(),
            previous_sha256: digest(applying)?,
            report_sha256: applying.report_sha256.clone(),
            receipt: Some(result),
            resource_lease: applying.resource_lease.clone(),
            policy_operation_id: operation.map(str::to_owned),
        };
        let id = format!("{}.completed.checkpoint", plan.request_id);
        trace_begin(trace, &id, crate::policy_decisions::EffectKind::Checkpoint)?;
        self.transition(plan, applying, &completed, |plan| {
            authorize(plan)?;
            (self.calculation_check)(&calculation, &source, &plan.installation)
        })?;
        trace_complete(trace, &id, &digest(&completed)?)
    }

    fn reconciliation_input(
        &self,
        request: &str,
    ) -> Result<(Plan, Checkpoint, Checkpoint, Vec<u8>)> {
        let (plan, current) = self.load(request)?;
        if !matches!(current.stage, 3 | 4) {
            return Err(
                "only applying/completed workflows admit committed-outcome reconciliation".into(),
            );
        }
        let row = self.db.query(
            "SELECT canonical FROM checkpoints WHERE request_id=? AND stage=3",
            &[request],
            1,
        )?;
        let applying: Checkpoint =
            serde_json::from_str(&row.first().ok_or("applying checkpoint missing")?[0])?;
        let report = self.object(&applying.report_sha256)?;
        // The immutable original report and exact committed receipt prove the
        // historical outcome. Verification does not rerun the calculator or
        // manufacture a replacement resource lease after withdrawal/recovery.
        let effect = plan.effect_id()?;
        plan.receipt(&effect, &report)?;
        Ok((plan, current, applying, report))
    }

    fn reconciliation_review(
        plan: &Plan,
        applying: &Checkpoint,
        receipt: &serde_json::Value,
    ) -> Result<String> {
        let mut bytes = b"luma-native-workflow-acknowledgement-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&serde_json::json!({
            "plan_sha256":digest(plan)?,"applying_sha256":digest(applying)?,"receipt":receipt
        }))?);
        Ok(io::digest(&bytes))
    }

    fn acknowledge_committed(
        &self,
        request: &str,
        review: &str,
        committed_proof: impl FnMut(&Plan, &[u8]) -> Result<serde_json::Value>,
    ) -> Result<bool> {
        self.acknowledge_traced(request, review, committed_proof, None)
    }
    fn acknowledge_traced(
        &self,
        request: &str,
        review: &str,
        mut committed_proof: impl FnMut(&Plan, &[u8]) -> Result<serde_json::Value>,
        operation: Option<&str>,
    ) -> Result<bool> {
        let (plan, current, applying, report) = self.reconciliation_input(request)?;
        if plan.authority.is_some() && operation.is_none() {
            return Err("governed acknowledgement requires its live audited operation".into());
        }
        let receipt = committed_proof(&plan, &report)?;
        let effect = plan.effect_id()?;
        if receipt != plan.receipt(&effect, &report)? {
            return Err("reconciliation proof is not the bound artifact receipt".into());
        }
        if !io::hash(review) || Self::reconciliation_review(&plan, &applying, &receipt)? != review {
            return Err("workflow or committed outcome changed since reconciliation review".into());
        }
        if current.stage == 4 {
            self.check_current(&plan, &current)?;
            if current.receipt.as_ref() != Some(&committed_proof(&plan, &report)?) {
                return Err("completed reconciliation proof changed".into());
            }
            self.root.sync_all()?;
            return Ok(true);
        }
        let completed = Checkpoint {
            stage: 4,
            plan_sha256: applying.plan_sha256.clone(),
            previous_sha256: digest(&applying)?,
            report_sha256: applying.report_sha256.clone(),
            receipt: Some(receipt.clone()),
            resource_lease: applying.resource_lease.clone(),
            policy_operation_id: operation.map(str::to_owned),
        };
        self.transition(&plan, &current, &completed, |p| {
            self.check_current(p, &completed)?;
            if committed_proof(p, &report)? != receipt {
                return Err("committed artifact proof changed before acknowledgement".into());
            }
            Ok(())
        })?;
        Ok(false)
    }
}
fn authorize(plan: &Plan) -> Result<()> {
    let admission = skills::admission()?;
    let installed = crate::workflow::Executable::installed()?;
    if io::installation()? != plan.installation
        || admission["workflow_sha256"] != plan.workflow_sha256
        || admission["native_invoice_execution_supported"] != true
        || !crate::workflow::legacy_invoice_execution_supported(&serde_json::to_vec(
            &installed.graph,
        )?)?
    {
        return Err("native workflow installation or current signed graph changed".into());
    }
    Ok(())
}
pub fn initialize_installed() -> Result<()> {
    initialize(Path::new(DIRECTORY), &io::installation()?)?;
    let parent = scoped_read::open_directory(Path::new("/var/lib/luma-os"))?;
    io::mkdir_at(&parent, "workflow-invoice-domains")?.sync_all()?;
    parent.sync_all()?;
    Ok(())
}
pub fn prepare(request: &str, artifact: &str, expected: &str) -> Result<()> {
    let installation = io::installation()?;
    let admission = skills::admission()?;
    let source = calculation::source_stdin()?;
    let version = expected.parse::<u64>()?;
    if version.to_string() != expected {
        return Err("noncanonical workflow expected version".into());
    }
    let plan = Plan {
        schema_version: 1,
        environment: "lab".into(),
        installation: installation.clone(),
        request_id: request.into(),
        artifact_id: artifact.into(),
        expected_version: version,
        workflow_sha256: admission["workflow_sha256"]
            .as_str()
            .ok_or("workflow digest missing")?
            .into(),
        source_sha256: io::digest(&source),
        source_bytes: source.len() as u64,
        authority: None,
        history_epoch: None,
    };
    let store = Store::open(Path::new(DIRECTORY), &installation)?;
    let replayed = store.prepare(&plan, &source, authorize)?;
    let mut status = store.status(request)?;
    status["replayed"] = replayed.into();
    println!("{status}");
    Ok(())
}
pub fn status(request: &str) -> Result<()> {
    println!(
        "{}",
        Store::open(Path::new(DIRECTORY), &io::installation()?)?.status(request)?
    );
    Ok(())
}
pub fn store_status() -> Result<()> {
    let store = Store::open(Path::new(DIRECTORY), &io::installation()?)?;
    let mut pending = Vec::new();
    for name in io::names(&store.pending, MAX_OBJECTS)? {
        let bytes = io::read_member(&store.pending, &name, MAX_OBJECT)?;
        pending.push(serde_json::json!({"object_sha256":name,"bytes":bytes.len(),"observed_sha256":io::digest(&bytes),"preserved":true}));
    }
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"environment":"lab","runs":store.db.query("SELECT request_id FROM runs",&[],MAX_RUNS)?.len(),"pending":pending,"gate_closing":false})
    );
    Ok(())
}
pub fn cancel(request: &str, review: &str) -> Result<()> {
    let store = Store::open(Path::new(DIRECTORY), &io::installation()?)?;
    // Cancellation only reduces authority. A withdrawn workflow must not make
    // it impossible to cancel a prepared run; installation checks still apply.
    store.cancel(request, review, |plan| {
        if io::installation()? != plan.installation {
            return Err("workflow cancellation installation changed".into());
        }
        Ok(())
    })?;
    println!("{}", store.status(request)?);
    Ok(())
}
pub fn advance(request: &str, review: &str) -> Result<()> {
    let store = Store::open(Path::new(DIRECTORY), &io::installation()?)?;
    store.advance(
        request,
        review,
        authorize,
        |plan, report, replay_only, check| {
            let effect = plan.effect_id()?;
            catalog::commit_invoice(&plan.commit(&effect), report, replay_only, check)
        },
    )?;
    println!("{}", store.status(request)?);
    Ok(())
}

pub fn reconcile(request: &str, review: Option<&str>) -> Result<()> {
    let store = Store::open(Path::new(DIRECTORY), &io::installation()?)?;
    let (plan, current, applying, report) = store.reconciliation_input(request)?;
    let effect = plan.effect_id()?;
    // Fixed lock order: coordinator, then catalog. This observer has no publish
    // method and remains alive through acknowledgement/transaction close.
    let proof = catalog::committed_invoice(&plan.commit(&effect), &report)?;
    let receipt = proof.recheck()?;
    let expected_review = Store::reconciliation_review(&plan, &applying, &receipt)?;
    let replayed = if let Some(review) = review {
        Some(store.acknowledge_committed(request, review, |p, _| {
            if io::installation()? != p.installation {
                return Err("workflow reconciliation installation changed".into());
            }
            proof.recheck()
        })?)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"environment":"lab","request_id":request,
        "observation":"verified-committed-receipt","previous_state":state(current.stage),
        "state":store.status(request)?["state"],"review_sha256":expected_review,
        "receipt":receipt,"replayed":replayed,"effect_executed":false,
        "product_admin_active":false,"gate_closing":false})
    );
    Ok(())
}

fn governed_use(
    plan: &Plan,
    action: crate::finite_grants::Action,
) -> Result<crate::finite_grants::Use> {
    use crate::finite_grants::{Action, Kind, Selector, Use};
    let (kind, id, generation, commitment, input_bytes, output_bytes) = match action {
        Action::Execute | Action::Resume | Action::Cancel => (
            Kind::Workflow,
            plan.request_id.clone(),
            1,
            plan.scope_digest()?,
            plan.source_bytes,
            MAX_OBJECT,
        ),
        Action::Calculate => (
            Kind::Calculation,
            "invoice-v1".into(),
            1,
            plan.source_sha256.clone(),
            plan.source_bytes,
            MAX_OBJECT,
        ),
        Action::Write => (
            Kind::Artifact,
            plan.artifact_id.clone(),
            plan.expected_version
                .checked_add(1)
                .ok_or("workflow artifact generation overflow")?,
            plan.scope_digest()?,
            MAX_OBJECT,
            MAX_OBJECT,
        ),
        Action::StartWorker | Action::AcquireResource => (
            if action == Action::StartWorker {
                Kind::Worker
            } else {
                Kind::Resource
            },
            if action == Action::StartWorker {
                "invoice-helper".into()
            } else {
                "invoice-helper-pool".into()
            },
            1,
            digest(&(
                plan.scope_digest()?,
                "invoice-v1",
                crate::resource_manager::storage_device(Path::new("/var"))?,
                512u64 * 1024 * 1024,
                16u32,
                30u32,
            ))?,
            plan.source_bytes,
            MAX_OBJECT,
        ),
        _ => return Err("unsupported workflow effect scope".into()),
    };
    let usage = Use {
        action,
        selector: Selector {
            kind,
            id,
            generation,
            digest: commitment,
        },
        input_bytes,
        output_bytes,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}

fn proposed_plan(request: &str, artifact: &str, expected: &str, source: &[u8]) -> Result<Plan> {
    let installation = io::installation()?;
    let version = expected.parse::<u64>()?;
    if version.to_string() != expected {
        return Err("noncanonical expected artifact version".into());
    }
    let admission = skills::admission()?;
    let plan = Plan {
        schema_version: 1,
        environment: "lab".into(),
        installation: installation.clone(),
        request_id: request.into(),
        artifact_id: artifact.into(),
        expected_version: version,
        workflow_sha256: admission["workflow_sha256"]
            .as_str()
            .ok_or("workflow digest missing")?
            .into(),
        source_sha256: io::digest(source),
        source_bytes: source.len() as u64,
        authority: None,
        history_epoch: None,
    };
    plan.validate(&installation)?;
    authorize(&plan)?;
    Ok(plan)
}

/// A review is an inert exact scope description. It cannot execute, publish,
/// reserve resources or become a grant by being passed back on stdin.
fn operator_snapshot(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(path);
    let parent = path.parent().ok_or("missing private input parent")?;
    if parent.parent() != Some(Path::new("/run/luma-granted-client/requests"))
        || parent
            .file_name()
            .and_then(|v| v.to_str())
            .map_or(true, |v| {
                v.len() != 32
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
    {
        return Err("workflow input must be an owned launcher snapshot, not a folder grant".into());
    }
    crate::tpm::private_directory(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o400
        || before.len() == 0
        || before.len() > 1024 * 1024
    {
        return Err("unsafe operator snapshot".into());
    }
    let key = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut bytes = Vec::new();
    (&mut file).take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || key(&file.metadata()?) != key(&before)
        || key(&std::fs::symlink_metadata(path)?) != key(&before)
    {
        return Err("operator snapshot changed during admission".into());
    }
    Ok(bytes)
}

pub(crate) fn governed_review(
    request: &str,
    artifact: &str,
    expected: &str,
    epoch: &str,
    snapshot: &str,
) -> Result<()> {
    let source = operator_snapshot(snapshot)?;
    let mut plan = proposed_plan(request, artifact, expected, &source)?;
    plan.history_epoch = history::epoch_argument(epoch)?;
    println!(
        "{}",
        serde_json::json!({"plan":plan,"input_kind":"operator-stdin-snapshot",
        "execute":governed_use(&plan,crate::finite_grants::Action::Execute)?,
        "calculate":governed_use(&plan,crate::finite_grants::Action::Calculate)?,
        "worker":governed_use(&plan,crate::finite_grants::Action::StartWorker)?,
        "resource":governed_use(&plan,crate::finite_grants::Action::AcquireResource)?,
        "write":governed_use(&plan,crate::finite_grants::Action::Write)?,
        "resume":governed_use(&plan,crate::finite_grants::Action::Resume)?,
        "cancel":governed_use(&plan,crate::finite_grants::Action::Cancel)?,
        "effect_executed":false,"grant_issued":false})
    );
    Ok(())
}

struct GovernedTrace<'b, 's> {
    boundary: std::cell::RefCell<&'b mut crate::admin_governance::GrantBoundary<'s>>,
    pending: std::cell::RefCell<
        std::collections::BTreeMap<String, crate::policy_decisions::PendingEffect>,
    >,
}
impl GovernedTrace<'_, '_> {
    fn check(&self, plan: &Plan) -> Result<()> {
        plan.check_owner(&mut self.boundary.borrow_mut())?;
        authorize(plan)
    }
    fn event(&self, event: TraceEvent) -> Result<()> {
        match event {
            TraceEvent::Begin { id, kind } => {
                if self.pending.borrow().contains_key(&id) {
                    return Err("duplicate live workflow effect admission".into());
                }
                let pending = self.boundary.borrow_mut().effect_begin(&id, kind)?;
                self.pending.borrow_mut().insert(id, pending);
                Ok(())
            }
            TraceEvent::Complete { id, receipt } => {
                let pending = self
                    .pending
                    .borrow_mut()
                    .remove(&id)
                    .ok_or("workflow outcome lacks its actual pending effect")?;
                self.boundary
                    .borrow_mut()
                    .effect_complete(pending, &receipt)
            }
        }
    }
}
fn governed_path(principal: &str) -> Result<std::path::PathBuf> {
    if crate::tpm::decode::<32>(principal)? == [0; 32] {
        return Err("invalid governed workflow domain".into());
    }
    catalog::safe_path(Path::new(GOVERNED_DIRECTORY))?;
    Ok(Path::new(GOVERNED_DIRECTORY).join(io::digest(principal.as_bytes())))
}
struct InvoiceRecovery {
    store: Store,
    plan: Plan,
    request: String,
}
fn recovery_open(
    principal: &str,
    generation: u64,
    request: &str,
) -> Result<Box<dyn recovery::Run>> {
    let store = Store::open(&governed_path(principal)?, &io::installation()?)?;
    store.require_owner(principal)?;
    let (plan, _) = store.load(request)?;
    let owner = plan
        .authority
        .as_ref()
        .ok_or("laboratory run cannot be adopted by recovery")?;
    if owner.principal != principal || owner.generation != generation {
        return Err(
            "recovery target does not match the actual immutable invoice owner/generation".into(),
        );
    }
    Ok(Box::new(InvoiceRecovery {
        store,
        plan,
        request: request.into(),
    }))
}
impl recovery::Run for InvoiceRecovery {
    fn epoch(&self) -> u64 {
        self.plan.history_epoch.unwrap_or(0)
    }
    fn scope(&self, action: crate::finite_grants::Action) -> Result<crate::finite_grants::Use> {
        let owner = self
            .plan
            .authority
            .as_ref()
            .ok_or("missing retained invoice owner")?;
        recovery::disposition_scope(
            history::Domain::Invoice,
            &owner.principal,
            owner.generation,
            &self.request,
            &self.plan,
            action,
        )
    }
    fn evidence(&self) -> Result<serde_json::Value> {
        let mut status = self.store.status(&self.request)?;
        let (_, checkpoint) = self.store.load(&self.request)?;
        status["cancel_allowed"] = matches!(checkpoint.stage, 0 | 1 | 2 | 5).into();
        status["cancel"] = serde_json::to_value(self.scope(crate::finite_grants::Action::Cancel)?)?;
        status["resume"] = serde_json::to_value(self.scope(crate::finite_grants::Action::Resume)?)?;
        if matches!(checkpoint.stage, 3 | 4) {
            let committed = (|| -> Result<serde_json::Value> {
                let (plan, _, applying, report) = self.store.reconciliation_input(&self.request)?;
                let proof = plan.committed(&plan.effect_id()?, &report)?;
                let receipt = proof.recheck()?;
                Ok(
                    serde_json::json!({"review_sha256":Store::reconciliation_review(&plan,&applying,&receipt)?,"committed_receipt":receipt,"effect_executed":false}),
                )
            })();
            match committed {
                Ok(value) => status["committed_outcome"] = value,
                Err(error) => {
                    status["committed_outcome"] = serde_json::Value::Null;
                    status["uncertain_reason"] = error.to_string().into();
                }
            }
        }
        status["disposition_only"] = true.into();
        Ok(status)
    }
    fn cancel(
        &self,
        review: &str,
        operation: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.store.cancel_traced(
            &self.request,
            review,
            |plan| {
                if plan != &self.plan {
                    return Err("retained cancellation plan changed".into());
                }
                check()
            },
            Some(operation),
        )?;
        check()?;
        let mut status = self.store.status(&self.request)?;
        status["disposition_only"] = true.into();
        status["effect_executed"] = false.into();
        Ok(status)
    }
    fn reconcile(
        &self,
        review: &str,
        operation: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        check()?;
        let (plan, _, _, report) = self.store.reconciliation_input(&self.request)?;
        if plan != self.plan {
            return Err("retained reconciliation plan changed".into());
        }
        let proof = plan.committed(&plan.effect_id()?, &report)?;
        let replayed = self.store.acknowledge_traced(
            &self.request,
            review,
            |plan, _| {
                if plan != &self.plan {
                    return Err("retained reconciliation owner changed".into());
                }
                check()?;
                proof.recheck()
            },
            Some(operation),
        )?;
        check()?;
        let mut status = self.store.status(&self.request)?;
        status["replayed"] = replayed.into();
        status["disposition_only"] = true.into();
        status["effect_executed"] = false.into();
        Ok(status)
    }
}
pub(crate) fn closed_history(
    principal: &str,
    generation: u64,
    epoch: u64,
) -> Result<history::Input> {
    let path = governed_path(principal)?;
    let store = Store::open(&path, &io::installation()?)?;
    let (semantic_sha256, count) = closed_evidence(&store, principal, generation, epoch)?;
    let root = store.root.try_clone()?;
    drop(store);
    Ok(history::Input {
        root,
        path,
        semantic_sha256,
        runs: count,
    })
}
fn closed_evidence(
    store: &Store,
    principal: &str,
    generation: u64,
    epoch: u64,
) -> Result<(String, usize)> {
    store.require_owner(principal)?;
    let pending = io::names(&store.pending, MAX_OBJECTS)?;
    let rows = store.db.query(
        "SELECT request_id,plan,current_stage FROM runs ORDER BY request_id",
        &[],
        MAX_RUNS,
    )?;
    if rows.is_empty() && pending.is_empty() {
        return Err("empty invoice history has no terminal evidence to retire".into());
    }
    for row in &rows {
        let (plan, checkpoint) = store.load(&row[0])?;
        let owner = plan
            .authority
            .as_ref()
            .ok_or("laboratory history cannot become a governed retirement target")?;
        if owner.principal != principal
            || owner.generation > generation
            || plan.history_epoch.unwrap_or(0) != epoch
            || !matches!(checkpoint.stage, 4 | 5)
        {
            return Err("invoice history contains another owner, epoch or nonterminal workflow; preserve state".into());
        }
        if checkpoint.stage == 4 {
            let report = store.object(&checkpoint.report_sha256)?;
            plan.committed(&plan.effect_id()?, &report)?.recheck()?;
        }
    }
    let checkpoints = store.db.query(
        "SELECT sequence,request_id,stage,canonical FROM checkpoints ORDER BY sequence",
        &[],
        MAX_RUNS * 5,
    )?;
    let semantic_sha256 = digest(&(
        "invoice-closed-history-v2",
        &store.installation,
        principal,
        generation,
        epoch,
        &rows,
        &checkpoints,
    ))?;
    let count = rows.len();
    Ok((semantic_sha256, count))
}
fn governed_login_store(login: &str) -> Result<Store> {
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let principal = registry
        .current()?
        .account(login)
        .ok_or("unknown governed workflow principal")?
        .id
        .clone();
    history::active_epoch(history::Domain::Invoice, &principal)?;
    let store = Store::open(&governed_path(&principal)?, &io::installation()?)?;
    store.require_owner(&principal)?;
    Ok(store)
}
fn governed_owned_store(plan: &Plan, trace: &GovernedTrace<'_, '_>) -> Result<Store> {
    trace.check(plan)?;
    let owner = plan
        .authority
        .as_ref()
        .ok_or("governed workflow owner is missing")?;
    let path = governed_path(&owner.principal)?;
    let parent = scoped_read::open_directory(Path::new(GOVERNED_DIRECTORY))?;
    io::private_directory(&parent)?;
    catalog::ext4(&parent)?;
    if unsafe { libc::flock(parent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("governed workflow domain initialization busy".into());
    }
    let names = io::names(&parent, MAX_RUNS)?;
    if names.iter().any(|name| !io::hash(name)) {
        return Err("damaged governed workflow domain namespace; preserve state".into());
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if names.len() >= MAX_RUNS {
                return Err("governed workflow domain capacity exhausted".into());
            }
            trace.check(plan)?;
            initialize_governed(&path, &plan.installation, &owner.principal)?;
            trace.check(plan)?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    let store = Store::open(&path, &plan.installation)?;
    store.require_owner(&owner.principal)?;
    Ok(store)
}

pub(crate) fn governed_prepare(args: &[String]) -> Result<()> {
    if args.len() != 11 {
        return Err("expected owned workflow-governed-prepare LOGIN EXECUTE-GRANT CALCULATE-GRANT WORKER-GRANT RESOURCE-GRANT REQUEST ARTIFACT EXPECTED-VERSION HISTORY-EPOCH SNAPSHOT (use granted-run with CSV stdin)".into());
    }
    let source = operator_snapshot(&args[10])?;
    let mut plan = proposed_plan(&args[6], &args[7], &args[8], &source)?;
    plan.history_epoch = history::epoch_argument(&args[9])?;
    let uses = vec![
        (
            args[2].clone(),
            governed_use(&plan, crate::finite_grants::Action::Execute)?,
        ),
        (
            args[3].clone(),
            governed_use(&plan, crate::finite_grants::Action::Calculate)?,
        ),
        (
            args[4].clone(),
            governed_use(&plan, crate::finite_grants::Action::StartWorker)?,
        ),
        (
            args[5].clone(),
            governed_use(&plan, crate::finite_grants::Action::AcquireResource)?,
        ),
    ];
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        plan.authority = Some(PrincipalOwner {
            principal: boundary.subject()?.into(),
            generation: boundary.subject_generation()?,
        });
        let operation = boundary.operation_id().to_owned();
        let trace = GovernedTrace {
            boundary: std::cell::RefCell::new(boundary),
            pending: std::cell::RefCell::new(std::collections::BTreeMap::new()),
        };
        let domain_id = format!("{}.domain", plan.request_id);
        trace.event(TraceEvent::Begin {
            id: domain_id.clone(),
            kind: crate::policy_decisions::EffectKind::Checkpoint,
        })?;
        let store = governed_owned_store(&plan, &trace)?;
        trace.event(TraceEvent::Complete {
            id: domain_id,
            receipt: digest(&(&plan.installation, &plan.authority))?,
        })?;
        let replayed = store.prepare_traced(
            &plan,
            &source,
            |plan| trace.check(plan),
            Some(&operation),
            &mut |event| trace.event(event),
        )?;
        let mut status = store.status(&plan.request_id)?;
        status["replayed"] = replayed.into();
        Ok(status)
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn governed_advance(args: &[String]) -> Result<()> {
    if args.len() != 9 {
        return Err("expected workflow-governed-advance LOGIN RESUME-GRANT CALCULATE-GRANT WORKER-GRANT RESOURCE-GRANT WRITE-GRANT REQUEST REVIEW-SHA256".into());
    }
    let store = governed_login_store(&args[1])?;
    let (plan, checkpoint) = store.load(&args[7])?;
    let mut uses = vec![(
        args[2].clone(),
        governed_use(&plan, crate::finite_grants::Action::Resume)?,
    )];
    // Source/checkpoint transitions do not borrow publication or calculation
    // authority. A saved checkpoint never stands in for either live grant.
    if matches!(checkpoint.stage, 1 | 2 | 3) {
        uses.push((
            args[3].clone(),
            governed_use(&plan, crate::finite_grants::Action::Calculate)?,
        ));
        uses.push((
            args[5].clone(),
            governed_use(&plan, crate::finite_grants::Action::AcquireResource)?,
        ));
    }
    if checkpoint.stage == 1 {
        uses.push((
            args[4].clone(),
            governed_use(&plan, crate::finite_grants::Action::StartWorker)?,
        ));
    }
    if matches!(checkpoint.stage, 2 | 3 | 4) {
        uses.push((
            args[6].clone(),
            governed_use(&plan, crate::finite_grants::Action::Write)?,
        ));
    }
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        plan.check_owner(boundary)?;
        let operation = boundary.operation_id().to_owned();
        let trace = GovernedTrace {
            boundary: std::cell::RefCell::new(boundary),
            pending: std::cell::RefCell::new(std::collections::BTreeMap::new()),
        };
        store.advance_traced(
            &args[7],
            &args[8],
            |plan| trace.check(plan),
            |plan, report, replay_only, check| {
                let effect = plan.effect_id()?;
                let id = format!("{}.artifact", plan.request_id);
                trace.event(TraceEvent::Begin {
                    id: id.clone(),
                    kind: if replay_only {
                        crate::policy_decisions::EffectKind::Recovery
                    } else {
                        crate::policy_decisions::EffectKind::ArtifactPublication
                    },
                })?;
                let receipt = plan.publish(&effect, report, replay_only, check)?;
                trace.event(TraceEvent::Complete {
                    id,
                    receipt: digest(&receipt)?,
                })?;
                Ok(receipt)
            },
            Some(&operation),
            &mut |event| trace.event(event),
        )?;
        store.status(&args[7])
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn governed_cancel(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected workflow-governed-cancel LOGIN CANCEL-GRANT REQUEST REVIEW-SHA256".into(),
        );
    }
    let store = governed_login_store(&args[1])?;
    let (plan, _) = store.load(&args[3])?;
    let usage = governed_use(&plan, crate::finite_grants::Action::Cancel)?;
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let operation = boundary.operation_id().to_owned();
        let pending = boundary.effect_begin(
            &format!("{}.cancel", args[3]),
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        store.cancel_traced(
            &args[3],
            &args[4],
            |plan| plan.check_owner(boundary),
            Some(&operation),
        )?;
        boundary.effect_complete(pending, &digest(&store.load(&args[3])?.1)?)?;
        store.status(&args[3])
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn governed_reconcile(args: &[String]) -> Result<()> {
    let reviewed = if args.len() == 4 {
        None
    } else if args.len() == 6 && args[4] == "--publish-committed" {
        Some(args[5].as_str())
    } else {
        return Err("expected workflow-governed-reconcile LOGIN RESUME-GRANT REQUEST [--publish-committed REVIEW-SHA256]".into());
    };
    let store = governed_login_store(&args[1])?;
    let (plan, _) = store.load(&args[3])?;
    let usage = governed_use(&plan, crate::finite_grants::Action::Resume)?;
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        plan.check_owner(boundary)?;
        let (plan, _, applying, report) = store.reconciliation_input(&args[3])?;
        let effect = plan.effect_id()?;
        let proof = plan.committed(&effect, &report)?;
        let receipt = proof.recheck()?;
        let review = Store::reconciliation_review(&plan, &applying, &receipt)?;
        let replayed = reviewed
            .map(|review| -> Result<bool> {
                let operation = boundary.operation_id().to_owned();
                let pending = boundary.effect_begin(
                    &format!("{}.recover", args[3]),
                    crate::policy_decisions::EffectKind::Recovery,
                )?;
                let replayed = store.acknowledge_traced(
                    &args[3],
                    review,
                    |plan, _| {
                        plan.check_owner(boundary)?;
                        proof.recheck()
                    },
                    Some(&operation),
                )?;
                boundary.effect_complete(pending, &digest(&store.load(&args[3])?.1)?)?;
                Ok(replayed)
            })
            .transpose()?;
        plan.check_owner(boundary)?;
        Ok(
            serde_json::json!({"request_id":args[3],"review_sha256":review,
            "receipt":receipt,"replayed":replayed,"effect_executed":false,
            "state":store.status(&args[3])?["state"]}),
        )
    })?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn terminal_history_requires_safe_run_state_and_preserves_unpublished_partial_preparations() {
        let fixture = Fixture::owned("terminal-pending");
        let store = fixture.open();
        let principal = "c".repeat(64);
        assert!(closed_evidence(&store, &principal, 1, 0).is_err());
        let partial_name = "d".repeat(64);
        io::write_member(&store.pending, &partial_name, b"partial bytes", 0o400).unwrap();
        io::write_member(&store.pending, &"e".repeat(64), b"", 0o400).unwrap();
        store.inventory().unwrap();
        let (_, count) = closed_evidence(&store, &principal, 1, 0).unwrap();
        assert_eq!(count, 0);
        let (mut plan, source) = plan();
        plan.authority = Some(PrincipalOwner {
            principal: principal.clone(),
            generation: 1,
        });
        store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"f".repeat(32)),
                &mut |_| Ok(()),
            )
            .unwrap();
        assert!(closed_evidence(&store, &principal, 2, 0).is_err());
        store
            .cancel_traced(
                &plan.request_id,
                &review(&store),
                |_| Ok(()),
                Some(&"f".repeat(32)),
            )
            .unwrap();
        assert_eq!(closed_evidence(&store, &principal, 2, 0).unwrap().1, 1);
        assert!(closed_evidence(&store, &"b".repeat(64), 2, 0).is_err());
        assert!(closed_evidence(&store, &principal, 2, 1).is_err());
        assert_eq!(
            io::read_member(&store.pending, &partial_name, MAX_OBJECT).unwrap(),
            b"partial bytes"
        );
        assert_eq!(store.object(&plan.source_sha256).unwrap(), source);
    }
    #[test]
    fn zero_run_invoice_history_requires_an_exact_installer_created_principal_owner_marker() {
        let fixture = Fixture::new("unowned-zero-run");
        let store = fixture.open();
        io::write_member(&store.pending, &"d".repeat(64), b"unpublished", 0o400).unwrap();
        assert!(closed_evidence(&store, &"c".repeat(64), 1, 0).is_err());
        assert!(initialize_governed(
            &fixture.0.join("unbound"),
            &store.installation,
            &"c".repeat(64)
        )
        .is_err());
        assert!(!fixture.0.join("unbound").exists());
        let owned = Fixture::owned("owner-zero-run");
        let store = owned.open();
        io::write_member(&store.pending, &"d".repeat(64), b"", 0o400).unwrap();
        assert_eq!(closed_evidence(&store, &"c".repeat(64), 1, 0).unwrap().1, 0);
        assert!(closed_evidence(&store, &"e".repeat(64), 1, 0).is_err());
        let bytes = io::read_member(&store.root, "owner.json", 4096).unwrap();
        fs::rename(
            owned.0.join(&owned.1).join("owner.json"),
            owned.0.join(&owned.1).join("owner.prior"),
        )
        .unwrap();
        io::write_member(&store.root, "owner.json", &bytes, 0o400).unwrap();
        assert!(store.require_owner(&"c".repeat(64)).is_err());
        assert!(closed_evidence(&store, &"c".repeat(64), 1, 0).is_err());
    }
    #[test]
    fn governed_trace_is_issued_before_real_calculation_and_links_checkpoint_without_legacy_rewrite(
    ) {
        let fixture = Fixture::new("trace");
        let store = fixture.open();
        let (plan, source) = plan();
        let seen = std::cell::RefCell::new(Vec::new());
        let mut trace = |event| {
            seen.borrow_mut().push(match event {
                TraceEvent::Begin { id, kind } => format!("begin:{id}:{kind:?}"),
                TraceEvent::Complete { id, receipt } => {
                    assert!(io::hash(&receipt));
                    format!("complete:{id}")
                }
            });
            Ok(())
        };
        store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"c".repeat(32)),
                &mut trace,
            )
            .unwrap();
        assert_eq!(
            store.load("run-1").unwrap().1.policy_operation_id,
            Some("c".repeat(32))
        );
        let seen = seen.borrow();
        assert!(seen[0].contains("prepare.worker"));
        assert!(seen[1].contains("prepare.resource"));
        assert!(seen[2].contains("prepare.calculate"));
        assert!(seen.iter().any(|event| event == "complete:run-1.snapshot"));
        assert!(seen
            .last()
            .unwrap()
            .contains("complete:run-1.prepare.checkpoint"));
        drop(seen);
        let prior = store.status("run-1").unwrap();
        store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"d".repeat(32)),
                &mut |_| panic!("exact prepare replay must admit no worker or mutate checkpoint"),
            )
            .unwrap();
        assert_eq!(store.status("run-1").unwrap(), prior);
    }
    #[test]
    fn denied_effect_audit_before_worker_never_launches_or_stages_and_lost_ack_retains_checkpoint()
    {
        let fixture = Fixture::new("trace-denied");
        let mut store = fixture.open();
        let (plan, source) = plan();
        store.calculator = |_, _| panic!("worker cannot launch before its durable admission");
        assert!(store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"c".repeat(32)),
                &mut |_| Err("policy evidence unavailable".into())
            )
            .is_err());
        assert!(store.load("run-1").is_err());
        assert!(io::names(&store.objects, 1).unwrap().is_empty());
        assert!(io::names(&store.pending, 1).unwrap().is_empty());
        drop(store);
        let store = fixture.open();
        assert!(store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"c".repeat(32)),
                &mut |event| {
                    if matches!(event,TraceEvent::Complete{id,..} if id=="run-1.prepare.checkpoint")
                    {
                        Err("checkpoint outcome acknowledgement lost".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert_eq!(store.load("run-1").unwrap().1.stage, 0);
    }
    #[test]
    fn original_calculation_receipt_is_required_and_retry_never_launches_a_worker() {
        let f = Fixture::new("original-calculation");
        let mut store = f.open();
        let (plan, bytes) = plan();
        store.prepare(&plan, &bytes, |_| Ok(())).unwrap();
        for _ in 0..2 {
            store
                .advance("run-1", &review(&store), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        let lease = store.load("run-1").unwrap().1.resource_lease.unwrap();
        store.calculator = |_, _| panic!("publication must use the original generation");
        store
            .advance(
                "run-1",
                &review(&store),
                |_| Ok(()),
                |plan, bytes, _, check| {
                    check()?;
                    receipt(plan, bytes)
                },
            )
            .unwrap();
        assert_eq!(store.load("run-1").unwrap().1.resource_lease, Some(lease));
        let token = ack_review(&store);
        assert!(store
            .acknowledge_committed("run-1", &token, receipt)
            .unwrap());
    }

    #[test]
    fn object_admission_is_rechecked_after_pending_sync_before_rename() {
        let f = Fixture::new("object-rename-admission");
        let store = f.open();
        let bytes = b"bounded exact operator snapshot";
        let hash = io::digest(bytes);
        assert!(store
            .put_object(bytes, || {
                if io::names(&store.pending, MAX_OBJECTS)?.contains(&hash) {
                    Err("grant changed after private object preparation".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(io::names(&store.objects, MAX_OBJECTS).unwrap().is_empty());
        assert_eq!(
            io::read_member(&store.pending, &hash, MAX_OBJECT).unwrap(),
            bytes
        );
        assert!(store
            .db
            .query("SELECT request_id FROM runs", &[], MAX_RUNS)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn denied_worker_boundary_leaves_no_checkpoint_or_source_object() {
        let f = Fixture::new("worker-boundary-denial");
        let mut store = f.open();
        store.calculator = |_, check| {
            check()?;
            panic!("denied worker cannot execute")
        };
        let (plan, bytes) = plan();
        let calls = Cell::new(0);
        assert!(store
            .prepare(&plan, &bytes, |_| {
                calls.set(calls.get() + 1);
                if calls.get() >= 3 {
                    Err("grant expired before owned worker".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(store.load("run-1").is_err());
        assert!(io::names(&store.objects, MAX_OBJECTS).unwrap().is_empty());
    }

    #[test]
    fn governed_scopes_bind_exact_source_target_and_operation_without_rewriting_legacy_bytes() {
        use crate::finite_grants::Action;
        let (mut plan, _) = plan();
        let original = serde_json::to_vec(&plan).unwrap();
        let original_effect = plan.effect_id().unwrap();
        assert!(!String::from_utf8(original.clone())
            .unwrap()
            .contains("authority"));
        let usage = governed_use(&plan, Action::Write).unwrap();
        assert_eq!(usage.selector.generation, 1);
        let scope = plan.scope_digest().unwrap();
        plan.authority = Some(PrincipalOwner {
            principal: "ab".repeat(32),
            generation: 7,
        });
        assert_eq!(plan.scope_digest().unwrap(), scope);
        assert_ne!(plan.effect_id().unwrap(), original_effect);
        plan.expected_version = 1;
        assert_ne!(
            governed_use(&plan, Action::Write).unwrap().selector,
            usage.selector
        );
        assert!(governed_use(&plan, Action::Infer).is_err());
        plan.source_sha256 = "cd".repeat(32);
        assert_ne!(plan.scope_digest().unwrap(), scope);
    }
    #[test]
    fn retired_invoice_namespace_epoch_changes_authority_scope_and_effect_without_rewriting_initial_bytes(
    ) {
        let (mut plan, _) = plan();
        let original = serde_json::to_vec(&plan).unwrap();
        assert!(!String::from_utf8(original.clone())
            .unwrap()
            .contains("history_epoch"));
        let scope = plan.scope_digest().unwrap();
        let effect = plan.effect_id().unwrap();
        let usage = governed_use(&plan, crate::finite_grants::Action::Execute).unwrap();
        plan.history_epoch = Some(1);
        assert_ne!(plan.scope_digest().unwrap(), scope);
        assert_ne!(plan.effect_id().unwrap(), effect);
        assert_ne!(
            governed_use(&plan, crate::finite_grants::Action::Execute)
                .unwrap()
                .selector,
            usage.selector
        );
        let epoch_one = plan.effect_id().unwrap();
        plan.history_epoch = Some(2);
        assert_ne!(plan.effect_id().unwrap(), epoch_one);
        plan.history_epoch = None;
        assert_eq!(serde_json::to_vec(&plan).unwrap(), original);
    }
    #[test]
    fn orphan_invoice_disposition_requires_new_scope_and_revocation_preserves_source_without_worker_dispatch(
    ) {
        use recovery::Run;
        let fixture = Fixture::owned("orphan-disposition");
        let mut store = fixture.open();
        let (mut plan, source) = plan();
        plan.authority = Some(PrincipalOwner {
            principal: "c".repeat(64),
            generation: 1,
        });
        store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"d".repeat(32)),
                &mut |_| Ok(()),
            )
            .unwrap();
        store.calculator =
            |_, _| panic!("disposition cannot launch calculation or acquire a lease");
        let before = store.object(&plan.source_sha256).unwrap();
        let review = review(&store);
        let run = InvoiceRecovery {
            store,
            plan: plan.clone(),
            request: plan.request_id.clone(),
        };
        assert_ne!(
            run.scope(crate::finite_grants::Action::Cancel)
                .unwrap()
                .selector,
            governed_use(&plan, crate::finite_grants::Action::Cancel)
                .unwrap()
                .selector
        );
        assert!(run
            .cancel(&review, &"e".repeat(32), &mut || Err(
                "fresh current generation grant revoked".into()
            ))
            .is_err());
        assert_eq!(run.store.load(&plan.request_id).unwrap().1.stage, 0);
        assert_eq!(run.store.object(&plan.source_sha256).unwrap(), before);
        let result = run
            .cancel(&review, &"e".repeat(32), &mut || Ok(()))
            .unwrap();
        assert_eq!(result["state"], "cancelled");
        assert_eq!(run.store.object(&plan.source_sha256).unwrap(), before);
        assert!(run.cancel(&review, &"f".repeat(32), &mut || Ok(())).is_ok());
        assert!(run
            .reconcile(&review, &"f".repeat(32), &mut || Ok(()))
            .is_err());
        assert!(run
            .store
            .advance_traced(
                &plan.request_id,
                &review,
                |_| Err("old execution authority is withdrawn".into()),
                |_, _, _, _| panic!("no artifact redispatch"),
                Some(&"f".repeat(32)),
                &mut |_| Ok(())
            )
            .is_err());
    }
    #[test]
    fn applying_orphan_invoice_cannot_cancel_or_invent_committed_outcome() {
        use recovery::Run;
        let fixture = Fixture::owned("orphan-applying");
        let store = fixture.open();
        let (mut plan, source) = plan();
        plan.authority = Some(PrincipalOwner {
            principal: "c".repeat(64),
            generation: 1,
        });
        store
            .prepare_traced(
                &plan,
                &source,
                |_| Ok(()),
                Some(&"d".repeat(32)),
                &mut |_| Ok(()),
            )
            .unwrap();
        for _ in 0..2 {
            let review = review(&store);
            store
                .advance_traced(
                    &plan.request_id,
                    &review,
                    |_| Ok(()),
                    |_, _, _, _| panic!("pre-applying stages cannot publish"),
                    Some(&"e".repeat(32)),
                    &mut |_| Ok(()),
                )
                .unwrap();
        }
        let applying_review = review(&store);
        assert!(store
            .advance_traced(
                &plan.request_id,
                &applying_review,
                |_| Ok(()),
                |_, _, _, _| Err("publication outcome unavailable".into()),
                Some(&"e".repeat(32)),
                &mut |_| Ok(())
            )
            .is_err());
        let review = review(&store);
        let run = InvoiceRecovery {
            store,
            plan: plan.clone(),
            request: plan.request_id.clone(),
        };
        assert!(run
            .cancel(&review, &"f".repeat(32), &mut || Ok(()))
            .is_err());
        assert!(run
            .reconcile(&review, &"f".repeat(32), &mut || Ok(()))
            .is_err());
        assert_eq!(run.store.load(&plan.request_id).unwrap().1.stage, 3);
        assert_eq!(run.store.object(&plan.source_sha256).unwrap(), source);
    }
    #[test]
    fn failed_resource_calculation_never_advances_or_crosses_the_artifact_boundary() {
        let f = Fixture::new("resource-failure");
        let (plan, bytes) = plan();
        let mut store = f.open();
        store.prepare(&plan, &bytes, |_| Ok(())).unwrap();
        store
            .advance(
                "run-1",
                &review(&store),
                |_| Ok(()),
                |_, _, _, _| panic!("effect before calculation"),
            )
            .unwrap();
        let before = store.load("run-1").unwrap();
        store.calculator = |_, _| Err("resource generation unavailable".into());
        assert!(store
            .advance(
                "run-1",
                &review(&store),
                |_| Ok(()),
                |_, _, _, _| panic!("unleased effect")
            )
            .is_err());
        assert_eq!(store.load("run-1").unwrap(), before);
        let source_members = io::names(&store.objects, MAX_OBJECTS).unwrap();
        assert_eq!(source_members, vec![plan.source_sha256]);
    }
    #[test]
    fn exact_prepare_replay_does_not_start_another_worker_and_legacy_bytes_stay_canonical() {
        let f = Fixture::new("resource-replay");
        let (plan, bytes) = plan();
        let mut store = f.open();
        store.prepare(&plan, &bytes, |_| Ok(())).unwrap();
        store.calculator = |_, _| panic!("replay must not allocate another physical generation");
        assert!(store.prepare(&plan, &bytes, |_| Ok(())).unwrap());
        let legacy = serde_json::json!({"stage":2,"plan_sha256":"a".repeat(64),
            "previous_sha256":"b".repeat(64),"report_sha256":"c".repeat(64),"receipt":null});
        let old: Checkpoint = serde_json::from_value(legacy.clone()).unwrap();
        assert!(old.resource_lease.is_none());
        assert_eq!(serde_json::to_value(old).unwrap(), legacy);
    }
    #[test]
    fn failed_preparation_resource_proof_leaves_no_run_or_pending_source() {
        let f = Fixture::new("resource-prepare-failure");
        let (plan, bytes) = plan();
        let mut store = f.open();
        store.calculator = |_, _| Err("resource acknowledgement lost".into());
        assert!(store.prepare(&plan, &bytes, |_| Ok(())).is_err());
        assert!(store.load("run-1").is_err());
        assert!(io::names(&store.objects, MAX_OBJECTS).unwrap().is_empty());
        assert!(io::names(&store.pending, MAX_OBJECTS).unwrap().is_empty());
    }
    struct Fixture(std::path::PathBuf, String);
    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("luma-workflow-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            initialize(&root.join("runs"), &"a".repeat(64)).unwrap();
            Self(root, "runs".into())
        }
        fn owned(label: &str) -> Self {
            let mut fixture = Self::new(label);
            let principal = "c".repeat(64);
            fixture.1 = io::digest(principal.as_bytes());
            initialize_governed(&fixture.0.join(&fixture.1), &"a".repeat(64), &principal).unwrap();
            fixture
        }
        fn open(&self) -> Store {
            let mut store = Store::open(&self.0.join(&self.1), &"a".repeat(64)).unwrap();
            // This fixture exercises coordinator persistence, not the installed
            // systemd/lease boundary. The production constructor always uses it.
            store.calculator = |source, check| {
                check()?;
                Ok(workflow_resource::Calculation {
                    report: calculation::report_bytes(source)?,
                    lease: resources::Token {
                        lease_id: "a".repeat(32),
                        manager_epoch: "b".repeat(32),
                        generation: 1,
                    },
                })
            };
            store.calculation_check = |result, source, installation| {
                if installation != "a".repeat(64)
                    || result.report != calculation::report_bytes(source)?
                    || !workflow_resource::token_valid(&result.lease)
                {
                    return Err("synthetic coordinator computation identity changed".into());
                }
                Ok(())
            };
            store
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn plan() -> (Plan, Vec<u8>) {
        let source = b"invoice_date,amount,currency\n2026-10-01,3.25,USD\n".to_vec();
        (
            Plan {
                schema_version: 1,
                environment: "lab".into(),
                installation: "a".repeat(64),
                request_id: "run-1".into(),
                artifact_id: "summary".into(),
                expected_version: 0,
                workflow_sha256: "b".repeat(64),
                source_sha256: io::digest(&source),
                source_bytes: source.len() as u64,
                authority: None,
                history_epoch: None,
            },
            source,
        )
    }
    fn review(s: &Store) -> String {
        s.status("run-1").unwrap()["review_sha256"]
            .as_str()
            .unwrap()
            .into()
    }
    fn receipt(p: &Plan, bytes: &[u8]) -> Result<serde_json::Value> {
        let id = p.effect_id()?;
        catalog::invoice_receipt(&p.commit(&id), bytes)
    }
    #[test]
    fn resource_fence_during_prepare_or_calculation_creates_no_new_checkpoint_or_report() {
        let f = Fixture::new("resource-before-checkpoint");
        let (plan, bytes) = plan();
        let mut store = f.open();
        store.calculation_check = |_, _, _| Err("calculation generation fenced".into());
        assert!(store.prepare(&plan, &bytes, |_| Ok(())).is_err());
        assert!(store
            .db
            .query("SELECT request_id FROM runs", &[], 1)
            .unwrap()
            .is_empty());
        assert!(io::names(&store.objects, 1).unwrap().is_empty());
        drop(store);
        let store = f.open();
        store.prepare(&plan, &bytes, |_| Ok(())).unwrap();
        store
            .advance("run-1", &review(&store), |_| Ok(()), |_, _, _, _| panic!())
            .unwrap();
        drop(store);
        let mut store = f.open();
        store.calculation_check = |_, _, _| Err("calculation generation fenced".into());
        let before = review(&store);
        assert!(store
            .advance(
                "run-1",
                &before,
                |_| Ok(()),
                |_, _, _, _| { panic!("no effect before a verified calculation checkpoint") }
            )
            .is_err());
        assert_eq!(review(&store), before);
        assert_eq!(store.load("run-1").unwrap().1.stage, 1);
        assert_eq!(io::names(&store.objects, 2).unwrap(), [plan.source_sha256]);
    }

    #[test]
    fn generation_fences_at_effect_and_after_commit_preserve_applying_for_reconciliation() {
        thread_local! { static FENCED: Cell<bool> = const { Cell::new(false) }; }
        let f = Fixture::new("resource-effect-fence");
        let (plan, bytes) = plan();
        let mut store = f.open();
        store.prepare(&plan, &bytes, |_| Ok(())).unwrap();
        for _ in 0..2 {
            store
                .advance("run-1", &review(&store), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        store.calculation_check = |_, _, _| {
            FENCED.with(|fenced| {
                if fenced.get() {
                    Err("broker calculation generation fenced".into())
                } else {
                    Ok(())
                }
            })
        };
        let effects = Cell::new(0);
        assert!(store
            .advance(
                "run-1",
                &review(&store),
                |_| Ok(()),
                |p, report, _, check| {
                    FENCED.with(|fenced| fenced.set(true));
                    check()?;
                    effects.set(effects.get() + 1);
                    receipt(p, report)
                }
            )
            .is_err());
        assert_eq!(effects.get(), 0);
        assert_eq!(store.load("run-1").unwrap().1.stage, 3);
        FENCED.with(|fenced| fenced.set(false));
        assert!(store
            .advance(
                "run-1",
                &review(&store),
                |_| Ok(()),
                |p, report, _, check| {
                    check()?;
                    effects.set(effects.get() + 1);
                    FENCED.with(|fenced| fenced.set(true));
                    receipt(p, report)
                }
            )
            .is_err());
        assert_eq!(effects.get(), 1);
        assert_eq!(store.load("run-1").unwrap().1.stage, 3);
        FENCED.with(|fenced| fenced.set(false));
        let review = ack_review(&store);
        assert!(!store
            .acknowledge_committed("run-1", &review, receipt)
            .unwrap());
        assert_eq!(effects.get(), 1);
        assert_eq!(store.load("run-1").unwrap().1.stage, 4);
    }

    #[test]
    fn durable_steps_exact_prepare_replay_and_completed_boundary_verification() {
        let f = Fixture::new("steps");
        let (plan, bytes) = plan();
        assert!(!f.open().prepare(&plan, &bytes, |_| Ok(())).unwrap());
        assert!(f.open().prepare(&plan, &bytes, |_| Ok(())).unwrap());
        let effects = Cell::new(0);
        for expected in [1, 2, 4, 4] {
            let s = f.open();
            s.advance(
                "run-1",
                &review(&s),
                |_| Ok(()),
                |p, b, replay, check| {
                    check()?;
                    effects.set(effects.get() + 1);
                    assert_eq!(replay, expected == 4 && effects.get() == 2);
                    receipt(p, b)
                },
            )
            .unwrap();
            assert_eq!(s.load("run-1").unwrap().1.stage, expected);
        }
        assert_eq!(effects.get(), 2);
    }
    #[test]
    fn cancellation_stale_reviews_changed_plans_and_ownership_fail_closed() {
        for steps in 0..3 {
            let f = Fixture::new(&format!("cancel-{steps}"));
            let (p, b) = plan();
            let s = f.open();
            s.prepare(&p, &b, |_| Ok(())).unwrap();
            let stale = review(&s);
            assert!(f.open_error());
            for _ in 0..steps {
                s.advance(
                    "run-1",
                    &review(&s),
                    |_| Ok(()),
                    |_, _, _, _| panic!("effect before calculation"),
                )
                .unwrap();
            }
            if steps > 0 {
                assert!(s.cancel("run-1", &stale, |_| Ok(())).is_err());
            }
            s.cancel("run-1", &review(&s), |_| Ok(())).unwrap();
            s.cancel("run-1", &review(&s), |_| Ok(())).unwrap();
            assert!(s
                .advance(
                    "run-1",
                    &review(&s),
                    |_| Ok(()),
                    |_, _, _, _| panic!("cancelled effect")
                )
                .is_err());
            let mut changed = p.clone();
            changed.artifact_id = "other".into();
            assert!(s.prepare(&changed, &b, |_| Ok(())).is_err());
        }
    }
    impl Fixture {
        fn open_error(&self) -> bool {
            Store::open(&self.0.join("runs"), &"a".repeat(64)).is_err()
        }
    }
    #[test]
    fn uncertain_effect_or_lost_completion_stays_applying_and_never_accepts_cancel() {
        let f = Fixture::new("uncertain");
        let (p, b) = plan();
        let s = f.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        for _ in 0..2 {
            s.advance("run-1", &review(&s), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        assert!(s
            .advance(
                "run-1",
                &review(&s),
                |_| Ok(()),
                |_, _, _, check| {
                    check()?;
                    Err("lost artifact acknowledgement".into())
                }
            )
            .is_err());
        assert_eq!(s.load("run-1").unwrap().1.stage, 3);
        assert!(s.cancel("run-1", &review(&s), |_| Ok(())).is_err());
        drop(s);
        let s = f.open();
        s.advance(
            "run-1",
            &review(&s),
            |_| Ok(()),
            |p, b, _, check| {
                check()?;
                receipt(p, b)
            },
        )
        .unwrap();
        assert_eq!(s.load("run-1").unwrap().1.stage, 4);
    }
    #[test]
    fn revocation_wrong_effect_result_and_corrupt_object_never_complete() {
        let f = Fixture::new("revocation");
        let (p, b) = plan();
        let s = f.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        assert!(s
            .advance(
                "run-1",
                &review(&s),
                |_| Err("revoked".into()),
                |_, _, _, _| panic!()
            )
            .is_err());
        for _ in 0..2 {
            s.advance("run-1", &review(&s), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        assert!(s
            .advance(
                "run-1",
                &review(&s),
                |_| Ok(()),
                |_, _, _, check| {
                    check()?;
                    Ok(serde_json::json!({"forged":true}))
                }
            )
            .is_err());
        assert_eq!(s.load("run-1").unwrap().1.stage, 3);
        let source = f.0.join("runs/objects").join(&p.source_sha256);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(source, b"tampered").unwrap();
        assert!(s.load("run-1").is_err());
    }
    #[test]
    fn checkpoint_history_and_format_are_not_silently_rewritten() {
        let f = Fixture::new("schema");
        let (p, b) = plan();
        let s = f.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        assert!(s.db.exec("DELETE FROM checkpoints;").is_err());
        assert!(s.db.exec("UPDATE checkpoints SET canonical='{}';").is_err());
        assert!(s.db.exec("UPDATE runs SET current_stage=4;").is_err());
        s.db.exec("PRAGMA user_version=2;").unwrap();
        drop(s);
        assert!(f.open_error());
    }
    #[test]
    fn lost_step_and_cancel_acknowledgements_replay_without_advancing_extra_nodes() {
        let f = Fixture::new("step-retry");
        let (p, b) = plan();
        let s = f.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        for expected in [1, 2, 4] {
            let prior = review(&s);
            for _ in 0..2 {
                s.advance(
                    "run-1",
                    &prior,
                    |_| Ok(()),
                    |p, b, _, check| {
                        check()?;
                        receipt(p, b)
                    },
                )
                .unwrap();
                assert_eq!(s.load("run-1").unwrap().1.stage, expected);
            }
        }
        let other = Fixture::new("cancel-retry");
        let s = other.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        let before = review(&s);
        s.cancel("run-1", &before, |_| Ok(())).unwrap();
        s.cancel("run-1", &before, |_| Ok(())).unwrap();
        assert_eq!(s.load("run-1").unwrap().1.stage, 5);
    }
    #[test]
    fn commit_time_revocation_rolls_back_a_pure_checkpoint_without_dispatch() {
        let f = Fixture::new("checkpoint-revocation");
        let (p, b) = plan();
        let s = f.open();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        let before = review(&s);
        let calls = Cell::new(0);
        assert!(s
            .advance(
                "run-1",
                &before,
                |_| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err("revoked at checkpoint commit".into())
                    } else {
                        Ok(())
                    }
                },
                |_, _, _, _| panic!("effect must not execute")
            )
            .is_err());
        assert_eq!(review(&s), before);
        assert_eq!(s.load("run-1").unwrap().1.stage, 0);
    }

    fn applying_fixture(s: &Store) {
        let (p, b) = plan();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        for _ in 0..2 {
            s.advance("run-1", &review(s), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        assert!(s
            .advance(
                "run-1",
                &review(s),
                |_| Ok(()),
                |_, _, _, check| {
                    check()?;
                    Err("committed outcome acknowledgement lost".into())
                }
            )
            .is_err());
    }
    fn ack_review(s: &Store) -> String {
        let (p, _, applying, report) = s.reconciliation_input("run-1").unwrap();
        Store::reconciliation_review(&p, &applying, &receipt(&p, &report).unwrap()).unwrap()
    }

    #[test]
    fn committed_acknowledgement_requires_review_and_replays_without_new_checkpoint() {
        let f = Fixture::new("acknowledgement");
        let s = f.open();
        applying_fixture(&s);
        assert!(s
            .acknowledge_committed("run-1", &review(&s), receipt)
            .is_err());
        let token = ack_review(&s);
        assert!(!s.acknowledge_committed("run-1", &token, receipt).unwrap());
        assert_eq!(s.load("run-1").unwrap().1.stage, 4);
        assert!(s.acknowledge_committed("run-1", &token, receipt).unwrap());
        assert_eq!(
            s.db.query(
                "SELECT stage FROM checkpoints WHERE request_id='run-1'",
                &[],
                5
            )
            .unwrap()
            .len(),
            5
        );
    }
    #[test]
    fn absent_unbound_or_changed_commit_proof_cannot_acknowledge_completion() {
        let f = Fixture::new("ack-denials");
        let s = f.open();
        applying_fixture(&s);
        let token = ack_review(&s);
        assert!(s
            .acknowledge_committed("run-1", &token, |_, _| Err("no verified receipt".into()))
            .is_err());
        assert!(s
            .acknowledge_committed("run-1", &token, |_, _| Ok(
                serde_json::json!({"forged":true})
            ))
            .is_err());
        let calls = Cell::new(0);
        assert!(s
            .acknowledge_committed("run-1", &token, |p, b| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("receipt/object changed before checkpoint commit".into())
                } else {
                    receipt(p, b)
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
        assert_eq!(s.load("run-1").unwrap().1.stage, 3);
        assert_eq!(ack_review(&s), token);
    }
    #[test]
    fn preparation_and_cancellation_are_not_past_commit_evidence() {
        let f = Fixture::new("ack-stage");
        let s = f.open();
        let (p, b) = plan();
        s.prepare(&p, &b, |_| Ok(())).unwrap();
        for _ in 0..2 {
            assert!(s
                .acknowledge_committed("run-1", &review(&s), |_, _| panic!(
                    "proof must not be requested before applying"
                ))
                .is_err());
            s.advance("run-1", &review(&s), |_| Ok(()), |_, _, _, _| panic!())
                .unwrap();
        }
        s.cancel("run-1", &review(&s), |_| Ok(())).unwrap();
        assert!(s.reconciliation_input("run-1").is_err());
    }
}
