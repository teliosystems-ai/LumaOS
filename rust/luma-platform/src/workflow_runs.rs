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
        {
            return Err("invalid native invoice workflow plan".into());
        }
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
    objects: File,
    pending: File,
    installation: String,
    calculator: fn(&[u8]) -> Result<workflow_resource::Calculation>,
    calculation_check: fn(&workflow_resource::Calculation, &[u8], &str) -> Result<()>,
}
pub(crate) fn initialize(path: &Path, installation: &str) -> Result<()> {
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
        let names = io::names(&root, 5)?;
        if !names.contains(&"metadata.sqlite3".into())
            || !names.contains(&"objects".into())
            || !names.contains(&"pending".into())
        {
            return Err("incomplete workflow store; preserve state".into());
        }
        for name in names {
            match name.as_str() {
                "objects" | "pending" => (),
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
            db,
            root,
            objects,
            pending,
            installation: installation.into(),
            calculator: workflow_resource::calculate,
            calculation_check: workflow_resource::Calculation::recheck,
        };
        result.inventory()?;
        Ok(result)
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
            {
                return Err("workflow checkpoint chain mismatch".into());
            }
            if (2..=4).contains(&checkpoint.stage) {
                let report = self.object(&checkpoint.report_sha256)?;
                let effect = plan.effect_id()?;
                let expected = catalog::invoice_receipt(&plan.commit(&effect), &report)?;
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
    fn put_object(&self, content: &[u8]) -> Result<String> {
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
        Ok(hash)
    }
    fn prepare(
        &self,
        plan: &Plan,
        source: &[u8],
        mut authorize: impl FnMut(&Plan) -> Result<()>,
    ) -> Result<bool> {
        plan.validate(&self.installation)?;
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
        let validation = (self.calculator)(source)?;
        authorize(plan)?;
        (self.calculation_check)(&validation, source, &plan.installation)?;
        self.put_object(source)?;
        let checkpoint = Checkpoint {
            stage: 0,
            plan_sha256: digest(plan)?,
            previous_sha256: digest(plan)?,
            report_sha256: String::new(),
            receipt: None,
            resource_lease: None,
        };
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
        tx.commit()?;
        self.root.sync_all()?;
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
        tx.commit()?;
        self.root.sync_all()?;
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
            "folder_grant":false,"gate_closing":false}),
        )
    }
    fn cancel(
        &self,
        request: &str,
        review: &str,
        mut authorize: impl FnMut(&Plan) -> Result<()>,
    ) -> Result<()> {
        let (plan, previous) = self.load(request)?;
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
        self.transition(&plan, &previous, &next, authorize)
    }
    fn advance(
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
    ) -> Result<()> {
        let (plan, previous) = self.load(request)?;
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
        match previous.stage {
            0 => {
                self.object(&plan.source_sha256)?;
                self.transition(&plan, &previous, &next, &mut authorize)?;
            }
            1 => {
                let source = self.object(&plan.source_sha256)?;
                let result = (self.calculator)(&source)?;
                (self.calculation_check)(&result, &source, &plan.installation)?;
                next.report_sha256 = self.put_object(&result.report)?;
                next.resource_lease = Some(result.lease.clone());
                self.transition(&plan, &previous, &next, |plan| {
                    authorize(plan)?;
                    (self.calculation_check)(&result, &source, &plan.installation)
                })?;
            }
            2 => {
                // Applying is durable BEFORE crossing the artifact boundary.
                self.transition(&plan, &previous, &next, &mut authorize)?;
                self.finish(&plan, &next, &mut authorize, &mut effect)?;
            }
            3 => {
                self.finish(&plan, &previous, &mut authorize, &mut effect)?;
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
    ) -> Result<()> {
        let bytes = self.object(&applying.report_sha256)?;
        let source = self.object(&plan.source_sha256)?;
        let calculation = (self.calculator)(&source)?;
        if calculation.report != bytes {
            return Err("workflow deterministic report differs from source".into());
        }
        (self.calculation_check)(&calculation, &source, &plan.installation)?;
        let result = effect(plan, &bytes, false, &mut || {
            self.check_current(plan, applying)?;
            authorize(plan)?;
            (self.calculation_check)(&calculation, &source, &plan.installation)
        })?;
        let effect_id = plan.effect_id()?;
        if result != catalog::invoice_receipt(&plan.commit(&effect_id), &bytes)? {
            return Err("artifact boundary returned an unbound receipt".into());
        }
        let completed = Checkpoint {
            stage: 4,
            plan_sha256: applying.plan_sha256.clone(),
            previous_sha256: digest(applying)?,
            report_sha256: applying.report_sha256.clone(),
            receipt: Some(result),
            resource_lease: applying.resource_lease.clone(),
        };
        self.transition(plan, applying, &completed, |plan| {
            authorize(plan)?;
            (self.calculation_check)(&calculation, &source, &plan.installation)
        })
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
        if (self.calculator)(&self.object(&plan.source_sha256)?)?.report != report {
            return Err("reconciliation report differs from its bound source".into());
        }
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
        mut committed_proof: impl FnMut(&Plan, &[u8]) -> Result<serde_json::Value>,
    ) -> Result<bool> {
        let (plan, current, applying, report) = self.reconciliation_input(request)?;
        let receipt = committed_proof(&plan, &report)?;
        let effect = plan.effect_id()?;
        if receipt != catalog::invoice_receipt(&plan.commit(&effect), &report)? {
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
    if io::installation()? != plan.installation
        || admission["workflow_sha256"] != plan.workflow_sha256
        || admission["native_invoice_execution_supported"] != true
    {
        return Err("native workflow installation or current signed graph changed".into());
    }
    Ok(())
}
pub fn initialize_installed() -> Result<()> {
    initialize(Path::new(DIRECTORY), &io::installation()?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
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
        store.calculator = |_| Err("resource generation unavailable".into());
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
        store.calculator = |_| panic!("replay must not allocate another physical generation");
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
        store.calculator = |_| Err("resource acknowledgement lost".into());
        assert!(store.prepare(&plan, &bytes, |_| Ok(())).is_err());
        assert!(store.load("run-1").is_err());
        assert!(io::names(&store.objects, MAX_OBJECTS).unwrap().is_empty());
        assert!(io::names(&store.pending, MAX_OBJECTS).unwrap().is_empty());
    }
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("luma-workflow-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            initialize(&root.join("runs"), &"a".repeat(64)).unwrap();
            Self(root)
        }
        fn open(&self) -> Store {
            let mut store = Store::open(&self.0.join("runs"), &"a".repeat(64)).unwrap();
            // This fixture exercises coordinator persistence, not the installed
            // systemd/lease boundary. The production constructor always uses it.
            store.calculator = |source| {
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
