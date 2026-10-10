//! Governed execution of every admitted closed file-to-artifact DAG topology.
//! Durable checkpoints and receipts describe outcomes, never future authority.
use crate::{
    artifact_catalog as catalog, artifacts as io,
    finite_grants::{Action, Kind as ScopeKind, Selector, Use},
    scoped_read::{self, Source, SourceIdentity},
    sqlite::Connection,
    workflow::{Executable, Kind},
    workflow_resource, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const DIRECTORY: &str = "/var/lib/luma-os/workflow-dags";
const INPUT_DIRECTORY: &str = "/var/lib/luma-os/workflow-inputs";
const MAX_RUNS: usize = 128;
const MAX_EVENTS: usize = MAX_RUNS * 130;
const MAX_OBJECTS: usize = 1024;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OBJECT: u64 = 2 * 1024 * 1024;
const SCHEMA: &[&str] = &[
    "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), installation TEXT NOT NULL CHECK(length(installation)=64)) STRICT",
    "CREATE TABLE runs (request_id TEXT PRIMARY KEY, plan TEXT NOT NULL) STRICT",
    "CREATE TABLE events (sequence INTEGER PRIMARY KEY CHECK(sequence>0), request_id TEXT NOT NULL REFERENCES runs(request_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 129), canonical TEXT NOT NULL, UNIQUE(request_id,ordinal)) STRICT",
    "CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity BEGIN SELECT RAISE(ABORT,'immutable identity'); END",
    "CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity BEGIN SELECT RAISE(ABORT,'retained identity'); END",
    "CREATE TRIGGER runs_no_update BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'immutable plan'); END",
    "CREATE TRIGGER runs_no_delete BEFORE DELETE ON runs BEGIN SELECT RAISE(ABORT,'retained plan'); END",
    "CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END",
    "CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'retained event'); END",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Target {
    artifact_id: String,
    expected_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposal {
    schema_version: u32,
    request_id: String,
    workflow_sha256: String,
    inputs: BTreeMap<String, SourceIdentity>,
    targets: BTreeMap<String, Target>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    principal: String,
    generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    installation: String,
    proposal: Proposal,
    graph: crate::workflow::Graph,
    order: Vec<String>,
    storage_device: String,
    owner: Option<Owner>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Output {
    Text {
        sha256: String,
        bytes: u64,
    },
    Report {
        sha256: String,
        bytes: u64,
        input_sha256: String,
        lease: crate::resources::Token,
    },
    Artifact {
        receipt: serde_json::Value,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Applying,
    Completed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Event {
    schema_version: u32,
    ordinal: u32,
    plan_sha256: String,
    previous_sha256: String,
    node: String,
    phase: Phase,
    output: Option<Output>,
    policy_operation_id: String,
}

struct Run {
    plan: Plan,
    event: Event,
    cursor: usize,
    outputs: BTreeMap<String, Output>,
}
fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(io::digest(&serde_json::to_vec(value)?))
}
fn audit_id(request: &str, node: &str, phase: &str) -> Result<String> {
    hash(&("luma-native-dag-audit-v1", request, node, phase))
}
fn scope_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn operation_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn input_root(root: &str) -> bool {
    root.strip_prefix(&format!("{INPUT_DIRECTORY}/"))
        .is_some_and(io::hash)
}

impl Proposal {
    fn validate(&self, graph: &Executable) -> Result<()> {
        if self.schema_version != 1
            || !io::identifier(&self.request_id)
            || self.workflow_sha256 != graph.sha256
        {
            return Err("DAG proposal identity differs from its signed installed graph".into());
        }
        let mut inputs = Vec::new();
        let mut targets = Vec::new();
        let mut artifact_ids = std::collections::BTreeSet::new();
        for node in &graph.graph.nodes {
            match node.kind {
                Kind::FileRead => {
                    inputs.push(node.id.clone());
                    let input = self
                        .inputs
                        .get(&node.id)
                        .ok_or("DAG input binding is missing")?;
                    if input.bytes == 0
                        || input.bytes > 1024 * 1024
                        || !io::hash(&input.sha256)
                        || !input_root(&input.root)
                    {
                        return Err("DAG input size or content identity is invalid".into());
                    }
                    Source::bind(input, 1024 * 1024)?.recheck()?;
                }
                Kind::ArtifactWrite => {
                    targets.push(node.id.clone());
                    let target = self
                        .targets
                        .get(&node.id)
                        .ok_or("DAG output binding is missing")?;
                    if !io::identifier(&target.artifact_id)
                        || target.expected_version >= 1024
                        || !artifact_ids.insert(&target.artifact_id)
                    {
                        return Err(
                            "DAG target version or distinct output identity is invalid".into()
                        );
                    }
                }
                Kind::DeterministicCalculate => (),
            }
        }
        inputs.sort();
        targets.sort();
        if inputs != self.inputs.keys().cloned().collect::<Vec<_>>()
            || targets != self.targets.keys().cloned().collect::<Vec<_>>()
        {
            return Err(
                "DAG proposal contains missing or undeclared source/target bindings".into(),
            );
        }
        Ok(())
    }
}

impl Plan {
    fn validate(&self, installation: &str) -> Result<Executable> {
        let owner = self
            .owner
            .as_ref()
            .ok_or("durable DAG plan lacks its governed owner")?;
        if self.schema_version != 1
            || self.installation != installation
            || !io::hash(installation)
            || crate::tpm::decode::<32>(&owner.principal)? == [0; 32]
            || owner.generation == 0
        {
            return Err("DAG plan installation or principal binding is invalid".into());
        }
        let graph = Executable::from_bytes(&serde_json::to_vec(&self.graph)?)?;
        if graph.order != self.order {
            return Err("DAG plan topology differs from its checkpoint".into());
        }
        let stored = Executable {
            graph: graph.graph,
            order: graph.order,
            sha256: self.proposal.workflow_sha256.clone(),
        };
        // Loading old evidence does not re-enrol a current source or require a
        // live provider. Only its own closed graph and inert bindings are checked.
        if !io::hash(&stored.sha256)
            || !io::identifier(&self.proposal.request_id)
            || self.proposal.schema_version != 1
            || self.proposal.inputs.len() > 64
            || self.proposal.targets.len() > 64
        {
            return Err("DAG plan proposal is malformed".into());
        }
        for input in self.proposal.inputs.values() {
            if !io::hash(&input.sha256)
                || input.bytes == 0
                || input.bytes > 1024 * 1024
                || !input_root(&input.root)
            {
                return Err("DAG stored source identity is malformed".into());
            }
        }
        for target in self.proposal.targets.values() {
            if !io::identifier(&target.artifact_id) || target.expected_version >= 1024 {
                return Err("DAG stored target is malformed".into());
            }
        }
        let mut inputs = stored
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == Kind::FileRead)
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        let mut targets = stored
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == Kind::ArtifactWrite)
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        inputs.sort();
        targets.sort();
        let distinct_targets = self
            .proposal
            .targets
            .values()
            .map(|target| &target.artifact_id)
            .collect::<std::collections::BTreeSet<_>>();
        if inputs != self.proposal.inputs.keys().cloned().collect::<Vec<_>>()
            || targets != self.proposal.targets.keys().cloned().collect::<Vec<_>>()
            || distinct_targets.len() != targets.len()
        {
            return Err("DAG stored source or output topology differs".into());
        }
        if !self
            .storage_device
            .split_once(':')
            .is_some_and(|(major, minor)| {
                major
                    .parse::<u32>()
                    .is_ok_and(|value| value > 0 && value.to_string() == major)
                    && minor
                        .parse::<u32>()
                        .is_ok_and(|value| value.to_string() == minor)
            })
        {
            return Err("DAG stored device identity is malformed".into());
        }
        Ok(stored)
    }
    fn authorize_base(
        &self,
        boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    ) -> Result<()> {
        boundary.check()?;
        let owner = self
            .owner
            .as_ref()
            .ok_or("DAG requires its original governed owner")?;
        if boundary.subject()? != owner.principal
            || boundary.subject_generation()? != owner.generation
            || io::installation()? != self.installation
            || crate::resource_manager::storage_device(Path::new("/var"))? != self.storage_device
        {
            return Err(
                "DAG principal, installation or physical storage generation changed".into(),
            );
        }
        let graph = Executable::installed()?;
        if graph.sha256 != self.proposal.workflow_sha256
            || graph.graph != self.graph
            || graph.order != self.order
        {
            return Err("DAG signed graph changed; saved checkpoints confer no authority".into());
        }
        boundary.check()
    }
    fn authorize(&self, boundary: &mut crate::admin_governance::GrantBoundary<'_>) -> Result<()> {
        self.authorize_base(boundary)?;
        for input in self.proposal.inputs.values() {
            if input.root
                != format!(
                    "{INPUT_DIRECTORY}/{}",
                    io::digest(self.owner()?.principal.as_bytes())
                )
                || input.uid != boundary.subject_uid()?
            {
                return Err(
                    "DAG source is outside the authenticated principal input domain".into(),
                );
            }
            Source::bind(input, 1024 * 1024)?.recheck()?;
        }
        boundary.check()
    }
    fn scope_digest(&self) -> Result<String> {
        hash(&(&self.installation, &self.proposal, &self.storage_device))
    }
    fn owner(&self) -> Result<&Owner> {
        self.owner
            .as_ref()
            .ok_or_else(|| "DAG owner is missing".into())
    }
    fn effect_id(&self, node: &str) -> Result<String> {
        hash(&("luma-native-dag-artifact-v1", self, node))
    }
    fn commit<'a>(
        &'a self,
        node: &str,
        input: &'a str,
        effect: &'a str,
    ) -> Result<catalog::InvoiceCommit<'a>> {
        let target = self
            .proposal
            .targets
            .get(node)
            .ok_or("DAG output target is missing")?;
        Ok(catalog::InvoiceCommit {
            installation: &self.installation,
            request_id: effect,
            artifact_id: &target.artifact_id,
            expected_version: target.expected_version,
            workflow_sha256: &self.proposal.workflow_sha256,
            source_sha256: input,
        })
    }
    fn usage(&self, action: Action, node: Option<&str>, input: Option<(&str, u64)>) -> Result<Use> {
        let (kind, id, generation, digest, input_bytes, output_bytes) = match action {
            Action::Execute | Action::Resume | Action::Cancel => (
                ScopeKind::Workflow,
                self.proposal.request_id.clone(),
                1,
                self.scope_digest()?,
                0,
                MAX_OBJECT,
            ),
            Action::Read => {
                let node = node.ok_or("missing read node")?;
                let source = self.proposal.inputs.get(node).ok_or("unknown read node")?;
                (
                    ScopeKind::File,
                    node.into(),
                    1,
                    hash(source)?,
                    source.bytes,
                    source.bytes,
                )
            }
            Action::Calculate => {
                let (digest, size) = input.ok_or("missing calculation input")?;
                (
                    ScopeKind::Calculation,
                    node.ok_or("missing calculation node")?.into(),
                    1,
                    digest.into(),
                    size,
                    MAX_OBJECT,
                )
            }
            Action::Write => {
                let node = node.ok_or("missing output node")?;
                let target = self
                    .proposal
                    .targets
                    .get(node)
                    .ok_or("unknown output node")?;
                (
                    ScopeKind::Artifact,
                    target.artifact_id.clone(),
                    target.expected_version + 1,
                    self.scope_digest()?,
                    MAX_OBJECT,
                    MAX_OBJECT,
                )
            }
            Action::StartWorker | Action::AcquireResource => {
                let (input, size) = input.ok_or("missing worker input")?;
                let kind = if action == Action::StartWorker {
                    ScopeKind::Worker
                } else {
                    ScopeKind::Resource
                };
                let id = if action == Action::StartWorker {
                    "invoice-helper"
                } else {
                    "invoice-helper-pool"
                };
                (
                    kind,
                    id.into(),
                    1,
                    hash(&(
                        self.scope_digest()?,
                        node,
                        input,
                        &self.storage_device,
                        "invoice-batch-v1",
                        512u64 * 1024 * 1024,
                        16u32,
                        30u32,
                    ))?,
                    size,
                    MAX_OBJECT,
                )
            }
            _ => return Err("unsupported closed DAG scope".into()),
        };
        let usage = Use {
            action,
            selector: Selector {
                kind,
                id,
                generation,
                digest,
            },
            input_bytes,
            output_bytes,
            units: 1,
        };
        usage.validate()?;
        Ok(usage)
    }
}

struct Store {
    db: Connection,
    root: File,
    objects: File,
    pending: File,
    installation: String,
    principal: String,
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

pub(crate) fn initialize(path: &Path, installation: &str) -> Result<()> {
    if !io::hash(installation) {
        return Err("invalid DAG installation".into());
    }
    let parent = path.parent().ok_or("DAG store parent is missing")?;
    catalog::safe_path(parent)?;
    let parent_fd = scoped_read::open_directory(parent)?;
    catalog::ext4(&parent_fd)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("DAG initialization busy".into());
    }
    io::mkdir_at(&root, "objects")?;
    io::mkdir_at(&root, "pending")?;
    io::write_member(&root, "metadata.sqlite3", b"", 0o600)?;
    let db = Connection::open(&path.join("metadata.sqlite3"))?;
    if db.query("PRAGMA journal_mode=WAL", &[], 1)? != [vec!["wal".to_owned()]] {
        return Err("DAG WAL unavailable".into());
    }
    db.exec("PRAGMA max_page_count=8192;")?;
    db.exec("PRAGMA application_id=1280788307;")?;
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
        let principal = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| io::hash(name))
            .ok_or("DAG store requires its exact principal security domain")?;
        catalog::safe_path(path)?;
        let root = scoped_read::open_directory(path)?;
        io::private_directory(&root)?;
        catalog::ext4(&root)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("DAG coordinator busy; no cancellation accepted".into());
        }
        let names = io::names(&root, 5)?;
        for required in ["metadata.sqlite3", "objects", "pending"] {
            if !names.iter().any(|name| name == required) {
                return Err("DAG store incomplete; preserve state".into());
            }
        }
        for name in names {
            match name.as_str() {
                "objects" | "pending" => (),
                "metadata.sqlite3" | "metadata.sqlite3-wal" => {
                    io::read_member(&root, &name, 32 * 1024 * 1024)?;
                }
                "metadata.sqlite3-shm" => {
                    io::read_member(&root, &name, 65536)?;
                }
                _ => return Err("unknown DAG store member".into()),
            }
        }
        let objects = io::child_directory(&root, "objects")?;
        let pending = io::child_directory(&root, "pending")?;
        if objects.metadata()?.dev() != root.metadata()?.dev()
            || pending.metadata()?.dev() != root.metadata()?.dev()
        {
            return Err("DAG object filesystem mismatch".into());
        }
        let db = Connection::open(&path.join("metadata.sqlite3"))?;
        for (query, expected) in [
            ("PRAGMA journal_mode", "wal"),
            ("PRAGMA page_size", "4096"),
            ("PRAGMA application_id", "1280788307"),
            ("PRAGMA user_version", "1"),
        ] {
            if db.query(query, &[], 1)? != [vec![expected.to_owned()]] {
                return Err("DAG store format mismatch".into());
            }
        }
        if db.query("SELECT installation FROM identity", &[], 1)? != [vec![installation.to_owned()]]
        {
            return Err("DAG installation mismatch".into());
        }
        let mut actual = db
            .query(
                "SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                &[],
                SCHEMA.len(),
            )?
            .into_iter()
            .map(|row| row[0].clone())
            .collect::<Vec<_>>();
        let mut expected = SCHEMA.iter().map(|sql| sql.to_string()).collect::<Vec<_>>();
        actual.sort();
        expected.sort();
        if actual != expected
            || db.query("PRAGMA quick_check", &[], 1)? != [vec!["ok".to_owned()]]
            || !db.query("PRAGMA foreign_key_check", &[], 1)?.is_empty()
        {
            return Err("DAG schema/integrity mismatch; preserve state".into());
        }
        db.exec("PRAGMA max_page_count=8192;")?;
        let store = Self {
            db,
            root,
            objects,
            pending,
            installation: installation.into(),
            principal: principal.into(),
        };
        store.inventory()?;
        Ok(store)
    }
    fn object(&self, digest: &str) -> Result<Vec<u8>> {
        if !io::hash(digest) {
            return Err("invalid DAG object identity".into());
        }
        let bytes = io::read_member(&self.objects, digest, MAX_OBJECT)?;
        if io::digest(&bytes) != digest {
            return Err("DAG object corruption; preserve state".into());
        }
        Ok(bytes)
    }
    fn inventory(&self) -> Result<()> {
        let objects = io::names(&self.objects, MAX_OBJECTS)?;
        let pending = io::names(&self.pending, MAX_OBJECTS)?;
        if objects.len() + pending.len() > MAX_OBJECTS {
            return Err("DAG object capacity exhausted".into());
        }
        let mut total = 0u64;
        for name in objects {
            total = total
                .checked_add(self.object(&name)?.len() as u64)
                .ok_or("DAG capacity overflow")?;
        }
        for name in pending {
            if !io::hash(&name) {
                return Err("unknown DAG preparation".into());
            }
            total = total
                .checked_add(io::read_member(&self.pending, &name, MAX_OBJECT)?.len() as u64)
                .ok_or("DAG capacity overflow")?;
        }
        if total > MAX_BYTES {
            return Err("DAG storage capacity exhausted".into());
        }
        for row in self
            .db
            .query("SELECT request_id FROM runs", &[], MAX_RUNS)?
        {
            self.load(&row[0])?;
        }
        for (index, row) in self
            .db
            .query(
                "SELECT sequence FROM events ORDER BY sequence",
                &[],
                MAX_EVENTS,
            )?
            .iter()
            .enumerate()
        {
            if row != &[(index + 1).to_string()] {
                return Err("DAG global checkpoint sequence discontinuity".into());
            }
        }
        Ok(())
    }
    fn put(&self, bytes: &[u8], mut check: impl FnMut() -> Result<()>) -> Result<String> {
        check()?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_OBJECT {
            return Err("DAG object bound exceeded".into());
        }
        let digest = io::digest(bytes);
        let names = io::names(&self.objects, MAX_OBJECTS)?;
        if names.contains(&digest) {
            if self.object(&digest)? != bytes {
                return Err("DAG object conflict".into());
            }
            check()?;
            return Ok(digest);
        }
        let pending = io::names(&self.pending, MAX_OBJECTS)?;
        if !pending.contains(&digest) {
            let mut total = 0u64;
            for name in &names {
                total += self.object(name)?.len() as u64;
            }
            for name in &pending {
                total += io::read_member(&self.pending, name, MAX_OBJECT)?.len() as u64;
            }
            let mut free: libc::statvfs = unsafe { std::mem::zeroed() };
            if names.len() + pending.len() >= MAX_OBJECTS
                || total + bytes.len() as u64 > MAX_BYTES
                || unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut free) } != 0
                || free
                    .f_bavail
                    .checked_mul(free.f_frsize)
                    .ok_or("DAG reserve overflow")?
                    < bytes.len() as u64 + 16 * 1024 * 1024
            {
                return Err("DAG capacity/reserve exhausted".into());
            }
            check()?;
            io::write_member(&self.pending, &digest, bytes, 0o400)?;
            self.pending.sync_all()?;
        }
        if io::read_member(&self.pending, &digest, MAX_OBJECT)? != bytes {
            return Err("DAG partial object preparation; preserve bytes".into());
        }
        io::open_at(&self.pending, &digest, libc::O_RDONLY, 0)?.sync_all()?;
        self.pending.sync_all()?;
        check()?;
        let name = CString::new(digest.as_str())?;
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
            return Err("DAG object publication uncertain; reinspect".into());
        }
        self.objects.sync_all()?;
        self.pending.sync_all()?;
        self.root.sync_all()?;
        check()?;
        Ok(digest)
    }
    fn load(&self, request: &str) -> Result<Run> {
        if !io::identifier(request) {
            return Err("invalid DAG request".into());
        }
        let rows = self
            .db
            .query("SELECT plan FROM runs WHERE request_id=?", &[request], 1)?;
        let row = rows.first().ok_or("DAG run not found")?;
        let plan: Plan = serde_json::from_str(&row[0])?;
        let graph = plan.validate(&self.installation)?;
        if serde_json::to_string(&plan)? != row[0]
            || plan.proposal.request_id != request
            || plan.owner.as_ref().map(|owner| owner.principal.as_str())
                != Some(self.principal.as_str())
        {
            return Err("DAG plan canonical identity or security domain differs".into());
        }
        let mut previous: Option<Event> = None;
        let mut outputs = BTreeMap::new();
        let mut cursor = 0usize;
        for row in self.db.query(
            "SELECT ordinal,canonical FROM events WHERE request_id=? ORDER BY ordinal",
            &[request],
            130,
        )? {
            let event: Event = serde_json::from_str(&row[1])?;
            let ordinal = previous.as_ref().map_or(0, |event| event.ordinal + 1);
            let preceding = previous
                .as_ref()
                .map(hash)
                .transpose()?
                .unwrap_or(hash(&plan)?);
            if event.schema_version != 1
                || event.ordinal != ordinal
                || event.ordinal.to_string() != row[0]
                || serde_json::to_string(&event)? != row[1]
                || event.plan_sha256 != hash(&plan)?
                || event.previous_sha256 != preceding
                || !operation_id(&event.policy_operation_id)
            {
                return Err("DAG checkpoint chain differs".into());
            }
            if let Some(last) = &previous {
                if last.phase == Phase::Cancelled || cursor == graph.order.len() {
                    return Err("DAG transition after terminal state".into());
                }
            }
            match event.phase {
                Phase::Prepared => {
                    if ordinal != 0 || !event.node.is_empty() || event.output.is_some() {
                        return Err("invalid prepared DAG checkpoint".into());
                    }
                }
                Phase::Cancelled => {
                    if ordinal == 0
                        || previous
                            .as_ref()
                            .is_some_and(|event| event.phase == Phase::Applying)
                        || !event.node.is_empty()
                        || event.output.is_some()
                    {
                        return Err("invalid DAG cancellation".into());
                    }
                }
                Phase::Applying => {
                    if ordinal == 0
                        || event.node != graph.order[cursor]
                        || graph.node(&event.node)?.kind != Kind::ArtifactWrite
                        || event.output.is_some()
                        || previous
                            .as_ref()
                            .is_some_and(|event| event.phase == Phase::Applying)
                    {
                        return Err("invalid applying DAG checkpoint".into());
                    }
                }
                Phase::Completed => {
                    if ordinal == 0 || event.node != graph.order[cursor] {
                        return Err("DAG node completion order differs".into());
                    }
                    let node = graph.node(&event.node)?;
                    let output = event
                        .output
                        .as_ref()
                        .ok_or("DAG completed node lacks output")?;
                    match (node.kind, output) {
                        (Kind::FileRead, Output::Text { sha256, bytes }) => {
                            let input = plan
                                .proposal
                                .inputs
                                .get(&node.id)
                                .ok_or("DAG source missing")?;
                            if sha256 != &input.sha256
                                || bytes != &input.bytes
                                || self.object(sha256)?.len() as u64 != *bytes
                            {
                                return Err("DAG source checkpoint differs".into());
                            }
                        }
                        (
                            Kind::DeterministicCalculate,
                            Output::Report {
                                sha256,
                                bytes,
                                input_sha256,
                                lease,
                            },
                        ) => {
                            let batch = self.batch(node, &outputs)?;
                            let report = self.object(sha256)?;
                            if report.len() as u64 != *bytes
                                || input_sha256 != &io::digest(&batch)
                                || !workflow_resource::token_valid(lease)
                                || serde_json::from_slice::<serde_json::Value>(&report)?
                                    ["source_sha256"]
                                    != *input_sha256
                            {
                                return Err("DAG calculated checkpoint differs".into());
                            }
                        }
                        (Kind::ArtifactWrite, Output::Artifact { receipt }) => {
                            if previous.as_ref().map(|event| event.phase) != Some(Phase::Applying) {
                                return Err("DAG artifact lacked its applying checkpoint".into());
                            }
                            let (input, report, _) = self.report(node, &outputs)?;
                            let effect = plan.effect_id(&node.id)?;
                            if &catalog::owned_invoice_receipt(
                                &plan.commit(&node.id, &input, &effect)?,
                                &plan.owner()?.principal,
                                plan.owner()?.generation,
                                &report,
                            )? != receipt
                            {
                                return Err("DAG artifact receipt differs".into());
                            }
                        }
                        _ => return Err("DAG checkpoint output type differs".into()),
                    }
                    outputs.insert(node.id.clone(), output.clone());
                    cursor += 1;
                }
            }
            previous = Some(event);
        }
        let event = previous.ok_or("DAG checkpoint missing")?;
        Ok(Run {
            plan,
            event,
            cursor,
            outputs,
        })
    }
    fn batch(
        &self,
        node: &crate::workflow::Node,
        outputs: &BTreeMap<String, Output>,
    ) -> Result<Vec<u8>> {
        let mut sources = BTreeMap::new();
        for dependency in &node.dependencies {
            let Some(Output::Text { sha256, .. }) = outputs.get(dependency) else {
                return Err("DAG calculation dependency is not completed text".into());
            };
            sources.insert(dependency.clone(), self.object(sha256)?);
        }
        workflow_resource::batch_bytes(&sources)
    }
    fn report(
        &self,
        node: &crate::workflow::Node,
        outputs: &BTreeMap<String, Output>,
    ) -> Result<(String, Vec<u8>, crate::resources::Token)> {
        let Some(Output::Report {
            sha256,
            input_sha256,
            lease,
            ..
        }) = outputs.get(&node.dependencies[0])
        else {
            return Err("DAG publication dependency is not completed report".into());
        };
        Ok((input_sha256.clone(), self.object(sha256)?, lease.clone()))
    }
    fn persist(
        &self,
        plan: &Plan,
        previous: Option<&Event>,
        event: &Event,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        plan.validate(&self.installation)?;
        if plan.owner()?.principal != self.principal {
            return Err("DAG checkpoint belongs to another principal domain".into());
        }
        check()?;
        if let Some(previous) = previous {
            if self.load(&plan.proposal.request_id)?.event != *previous {
                return Err("DAG checkpoint compare-exchange conflict".into());
            }
        }
        self.db.exec("BEGIN IMMEDIATE;")?;
        let tx = Transaction(&self.db, false);
        if previous.is_none() {
            if self
                .db
                .query("SELECT request_id FROM runs", &[], MAX_RUNS)?
                .len()
                >= MAX_RUNS
            {
                return Err("DAG run capacity exhausted".into());
            }
            self.db.query(
                "INSERT INTO runs VALUES(?,?)",
                &[&plan.proposal.request_id, &serde_json::to_string(plan)?],
                0,
            )?;
        }
        self.db.query(
            "INSERT INTO events(request_id,ordinal,canonical) VALUES(?,?,?)",
            &[
                &plan.proposal.request_id,
                &event.ordinal.to_string(),
                &serde_json::to_string(event)?,
            ],
            0,
        )?;
        let proposed = self.load(&plan.proposal.request_id)?;
        if proposed.plan != *plan || proposed.event != *event {
            return Err("DAG proposed checkpoint failed semantic replay".into());
        }
        check()?;
        self.root.sync_all()?;
        check()?;
        tx.commit()?;
        self.root.sync_all()?;
        check()?;
        Ok(())
    }
    fn status(&self, request: &str) -> Result<serde_json::Value> {
        let run = self.load(request)?;
        let state = if run.event.phase == Phase::Cancelled {
            "cancelled"
        } else if run.cursor == run.plan.order.len() {
            "completed"
        } else if run.event.phase == Phase::Applying {
            "applying"
        } else {
            "ready"
        };
        Ok(
            serde_json::json!({"schema_version":1,"request_id":request,"plan":run.plan,"checkpoint":run.event,
            "completed_nodes":run.cursor,"state":state,"review_sha256":hash(&(&run.plan,&run.event))?,"effect_executed":false,"gate_closing":false}),
        )
    }
    fn replayed_review(&self, run: &Run, review: &str, cancel: bool) -> Result<bool> {
        if hash(&(&run.plan, &run.event))? == review {
            return Ok(false);
        }
        for row in self.db.query(
            "SELECT canonical FROM events WHERE request_id=? ORDER BY ordinal",
            &[&run.plan.proposal.request_id],
            130,
        )? {
            let prior: Event = serde_json::from_str(&row[0])?;
            if hash(&(&run.plan, &prior))? != review {
                continue;
            }
            let difference = run
                .event
                .ordinal
                .checked_sub(prior.ordinal)
                .ok_or("DAG replay ordinal regression")?;
            let terminal = if cancel {
                run.event.phase == Phase::Cancelled && difference == 1
            } else {
                run.event.phase == Phase::Completed
                    && (difference == 1
                        || (difference == 2
                            && run
                                .plan
                                .validate(&self.installation)?
                                .node(&run.event.node)?
                                .kind
                                == Kind::ArtifactWrite))
            };
            if terminal {
                return Ok(true);
            }
            return Err("DAG stale review is not the exact acknowledged transition".into());
        }
        Err("DAG review does not name a retained checkpoint".into())
    }
}

fn next_event(
    plan: &Plan,
    previous: Option<&Event>,
    node: &str,
    phase: Phase,
    output: Option<Output>,
    operation: &str,
) -> Result<Event> {
    if !operation_id(operation) {
        return Err("DAG requires its actual policy operation correlation".into());
    }
    Ok(Event {
        schema_version: 1,
        ordinal: previous.map_or(0, |event| event.ordinal + 1),
        plan_sha256: hash(plan)?,
        previous_sha256: previous.map(hash).transpose()?.unwrap_or(hash(plan)?),
        node: node.into(),
        phase,
        output,
        policy_operation_id: operation.into(),
    })
}

fn snapshot<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    // The fixed launcher, not a caller-selected arbitrary root pathname, owns
    // this bounded immutable request. JSON identity and grants remain inert.
    let path = Path::new(path);
    let parent = path.parent().ok_or("missing DAG request parent")?;
    if parent.parent() != Some(Path::new("/run/luma-granted-client/requests"))
        || parent
            .file_name()
            .and_then(|name| name.to_str())
            .map_or(true, |name| !operation_id(name))
    {
        return Err("DAG input requires its fixed owned launcher snapshot".into());
    }
    crate::tpm::private_directory(parent)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o400
        || before.len() == 0
        || before.len() > 128 * 1024
    {
        return Err("unsafe DAG request snapshot".into());
    }
    let key = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let mut bytes = Vec::new();
    (&mut file).take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || key(&file.metadata()?) != key(&before)
        || key(&fs::symlink_metadata(path)?) != key(&before)
    {
        return Err("DAG request snapshot changed".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    proposal: Proposal,
    grants: BTreeMap<String, String>,
}
fn grant(grants: &BTreeMap<String, String>, key: &str, usage: Use) -> Result<(String, Use)> {
    let id = grants.get(key).ok_or("missing exact DAG grant")?;
    if !scope_id(id) {
        return Err("malformed DAG grant identifier".into());
    }
    Ok((id.clone(), usage))
}

fn domain(principal: &str) -> Result<std::path::PathBuf> {
    if crate::tpm::decode::<32>(principal)? == [0; 32] {
        return Err("invalid DAG security domain".into());
    }
    let root = Path::new(DIRECTORY);
    catalog::safe_path(root)?;
    let directory = scoped_read::open_directory(root)?;
    io::private_directory(&directory)?;
    catalog::ext4(&directory)?;
    Ok(root.join(principal))
}
fn login_store(login: &str) -> Result<Store> {
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let principal = registry
        .current()?
        .account(login)
        .ok_or("unknown DAG principal")?
        .id
        .clone();
    Store::open(&domain(&principal)?, &io::installation()?)
}
fn owned_store(
    plan: &Plan,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<Store> {
    plan.authorize(boundary)?;
    let owner = plan.owner.as_ref().ok_or("missing DAG owner")?;
    let path = domain(&owner.principal)?;
    let parent = scoped_read::open_directory(Path::new(DIRECTORY))?;
    if unsafe { libc::flock(parent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("DAG domain initializer busy".into());
    }
    let names = io::names(&parent, MAX_RUNS)?;
    if names.iter().any(|name| !io::hash(name)) {
        return Err("damaged DAG domain namespace; preserve state".into());
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if names.len() >= MAX_RUNS {
                return Err("DAG domain capacity exhausted".into());
            }
            plan.authorize(boundary)?;
            initialize(&path, &plan.installation)?;
            plan.authorize(boundary)?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    Store::open(&path, &plan.installation)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        root: std::path::PathBuf,
        plan: Plan,
        sources: BTreeMap<String, Vec<u8>>,
    }
    impl Fixture {
        fn new(label: &str) -> Self {
            let base = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("luma-dag-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let principal = "a".repeat(64);
            let root = base.join(&principal);
            initialize(&root, &"b".repeat(64)).unwrap();
            let graph:crate::workflow::Graph=serde_json::from_value(serde_json::json!({"schema_version":1,"profile":"file-to-artifact-v1","graph_id":"branch-join",
                "nodes":[
                    {"id":"left","kind":"file-read","dependencies":[],"input_types":[],"output_type":"text"},
                    {"id":"right","kind":"file-read","dependencies":[],"input_types":[],"output_type":"text"},
                    {"id":"branch","kind":"deterministic-calculate","dependencies":["right"],"input_types":["text"],"output_type":"report"},
                    {"id":"merge","kind":"deterministic-calculate","dependencies":["left","right"],"input_types":["text","text"],"output_type":"report"},
                    {"id":"first","kind":"artifact-write","dependencies":["branch"],"input_types":["report"],"output_type":"artifact"},
                    {"id":"second","kind":"artifact-write","dependencies":["merge"],"input_types":["report"],"output_type":"artifact"}
                ]})).unwrap();
            let executable = Executable::from_bytes(&serde_json::to_vec(&graph).unwrap()).unwrap();
            let sources: BTreeMap<String, Vec<u8>> = BTreeMap::from([
                (
                    "left".into(),
                    b"invoice_date,amount,currency\n2026-10-01,1.25,USD\n".to_vec(),
                ),
                (
                    "right".into(),
                    b"invoice_date,amount,currency\n2026-10-02,2.00,USD\n".to_vec(),
                ),
            ]);
            // Synthetic persistence fixture only: no installed PAM, file grant,
            // physical resource lease or protected UTC is asserted by this test.
            let inputs = sources
                .iter()
                .enumerate()
                .map(|(index, (node, bytes))| {
                    (
                        node.clone(),
                        SourceIdentity {
                            root: format!("{INPUT_DIRECTORY}/{}", io::digest(principal.as_bytes())),
                            relative: format!("{node}.csv"),
                            root_identity: scoped_read::RootIdentity {
                                device: 1,
                                inode: 1,
                            },
                            device: 1,
                            inode: index as u64 + 2,
                            bytes: bytes.len() as u64,
                            modified_seconds: 1,
                            modified_nanos: 0,
                            changed_seconds: 1,
                            changed_nanos: 0,
                            uid: 1001,
                            gid: 1001,
                            mode: 0o100600,
                            sha256: io::digest(bytes),
                        },
                    )
                })
                .collect();
            let plan = Plan {
                schema_version: 1,
                installation: "b".repeat(64),
                proposal: Proposal {
                    schema_version: 1,
                    request_id: "branch-run".into(),
                    workflow_sha256: executable.sha256,
                    inputs,
                    targets: BTreeMap::from([
                        (
                            "first".into(),
                            Target {
                                artifact_id: "branch-report".into(),
                                expected_version: 0,
                            },
                        ),
                        (
                            "second".into(),
                            Target {
                                artifact_id: "merged-report".into(),
                                expected_version: 0,
                            },
                        ),
                    ]),
                },
                graph,
                order: executable.order,
                storage_device: "253:0".into(),
                owner: Some(Owner {
                    principal,
                    generation: 1,
                }),
            };
            Self {
                root,
                plan,
                sources,
            }
        }
        fn open(&self) -> Store {
            Store::open(&self.root, &self.plan.installation).unwrap()
        }
        fn prepare(&self) {
            let store = self.open();
            let event =
                next_event(&self.plan, None, "", Phase::Prepared, None, &"c".repeat(32)).unwrap();
            store.persist(&self.plan, None, &event, || Ok(())).unwrap();
        }
        fn one(&self) -> Phase {
            let store = self.open();
            let run = store.load("branch-run").unwrap();
            let graph = self.plan.validate(&self.plan.installation).unwrap();
            let node = graph.node(&self.plan.order[run.cursor]).unwrap();
            let output = match node.kind {
                Kind::FileRead => {
                    let bytes = &self.sources[&node.id];
                    Output::Text {
                        sha256: store.put(bytes, || Ok(())).unwrap(),
                        bytes: bytes.len() as u64,
                    }
                }
                Kind::DeterministicCalculate => {
                    let batch = store.batch(node, &run.outputs).unwrap();
                    let report = workflow_resource::fixture_batch_report(&batch).unwrap();
                    Output::Report {
                        sha256: store.put(&report, || Ok(())).unwrap(),
                        bytes: report.len() as u64,
                        input_sha256: io::digest(&batch),
                        lease: crate::resources::Token {
                            lease_id: "d".repeat(32),
                            manager_epoch: "e".repeat(32),
                            generation: 1,
                        },
                    }
                }
                Kind::ArtifactWrite => {
                    let applying = next_event(
                        &self.plan,
                        Some(&run.event),
                        &node.id,
                        Phase::Applying,
                        None,
                        &"c".repeat(32),
                    )
                    .unwrap();
                    store
                        .persist(&self.plan, Some(&run.event), &applying, || Ok(()))
                        .unwrap();
                    let (input, report, _) = store.report(node, &run.outputs).unwrap();
                    let effect = self.plan.effect_id(&node.id).unwrap();
                    Output::Artifact {
                        receipt: catalog::owned_invoice_receipt(
                            &self.plan.commit(&node.id, &input, &effect).unwrap(),
                            &self.plan.owner().unwrap().principal,
                            1,
                            &report,
                        )
                        .unwrap(),
                    }
                }
            };
            let current = store.load("branch-run").unwrap();
            let event = next_event(
                &self.plan,
                Some(&current.event),
                &node.id,
                Phase::Completed,
                Some(output),
                &"c".repeat(32),
            )
            .unwrap();
            store
                .persist(&self.plan, Some(&current.event), &event, || Ok(()))
                .unwrap();
            store.load("branch-run").unwrap().event.phase
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(self.root.parent().unwrap()).unwrap();
        }
    }
    #[test]
    fn branched_joined_signed_types_execute_in_exact_order_and_replay_no_extra_node() {
        let fixture = Fixture::new("branches");
        fixture.prepare();
        for index in 0..fixture.plan.order.len() {
            let prior = fixture.open().load("branch-run").unwrap();
            let review = hash(&(&prior.plan, &prior.event)).unwrap();
            assert_eq!(fixture.one(), Phase::Completed);
            let store = fixture.open();
            let current = store.load("branch-run").unwrap();
            assert_eq!(current.cursor, index + 1);
            assert!(store.replayed_review(&current, &review, false).unwrap());
            assert_eq!(store.load("branch-run").unwrap().cursor, index + 1);
        }
        let store = fixture.open();
        let run = store.load("branch-run").unwrap();
        assert_eq!(store.status("branch-run").unwrap()["state"], "completed");
        assert_eq!(run.outputs.len(), 6);
        let graph = fixture.plan.validate(&fixture.plan.installation).unwrap();
        let merge = graph.node("merge").unwrap();
        let Output::Report { sha256, .. } = &run.outputs[&merge.id] else {
            panic!("typed report");
        };
        let report: serde_json::Value =
            serde_json::from_slice(&store.object(sha256).unwrap()).unwrap();
        assert_eq!(report["groups"][0]["total"], "3.25");
        assert!(store.db.exec("DELETE FROM events").is_err());
        assert!(store.db.exec("UPDATE runs SET plan='{}'").is_err());
    }
    #[test]
    fn checkpoint_revocation_corruption_and_cross_principal_domain_never_adopt_state() {
        let fixture = Fixture::new("refusals");
        fixture.prepare();
        let store = fixture.open();
        let run = store.load("branch-run").unwrap();
        let event = next_event(
            &fixture.plan,
            Some(&run.event),
            "",
            Phase::Cancelled,
            None,
            &"c".repeat(32),
        )
        .unwrap();
        assert!(store
            .persist(&fixture.plan, Some(&run.event), &event, || Err(
                "revoked".into()
            ))
            .is_err());
        assert_eq!(store.load("branch-run").unwrap().event, run.event);
        let mut other = fixture.plan.clone();
        other.owner.as_mut().unwrap().principal = "f".repeat(64);
        assert!(store
            .persist(&other, Some(&run.event), &event, || Ok(()))
            .is_err());
        assert!(store.replayed_review(&run, &"f".repeat(64), false).is_err());
        store
            .persist(&fixture.plan, Some(&run.event), &event, || Ok(()))
            .unwrap();
        let cancelled = store.load("branch-run").unwrap();
        assert!(store
            .replayed_review(&cancelled, &hash(&(&run.plan, &run.event)).unwrap(), true)
            .unwrap());
        assert_eq!(store.status("branch-run").unwrap()["state"], "cancelled");
        let further = next_event(
            &fixture.plan,
            Some(&event),
            "",
            Phase::Cancelled,
            None,
            &"c".repeat(32),
        )
        .unwrap();
        // Invalid transitions must be rejected before commit, not discovered
        // only after corrupting the retained chain.
        assert!(store
            .persist(&fixture.plan, Some(&event), &further, || Ok(()))
            .is_err());
    }
    #[test]
    fn applying_uncertainty_is_retained_and_cancellation_cannot_hide_it() {
        let fixture = Fixture::new("applying");
        fixture.prepare();
        for _ in 0..4 {
            fixture.one();
        }
        let store = fixture.open();
        let run = store.load("branch-run").unwrap();
        let node = &fixture.plan.order[run.cursor];
        let applying = next_event(
            &fixture.plan,
            Some(&run.event),
            node,
            Phase::Applying,
            None,
            &"c".repeat(32),
        )
        .unwrap();
        store
            .persist(&fixture.plan, Some(&run.event), &applying, || Ok(()))
            .unwrap();
        let cancel = next_event(
            &fixture.plan,
            Some(&applying),
            "",
            Phase::Cancelled,
            None,
            &"c".repeat(32),
        )
        .unwrap();
        assert!(store
            .persist(&fixture.plan, Some(&applying), &cancel, || Ok(()))
            .is_err());
        assert_eq!(store.status("branch-run").unwrap()["state"], "applying");
        drop(store);
        assert_eq!(fixture.open().load("branch-run").unwrap().event, applying);
    }
}
pub(crate) fn initialize_installed() -> Result<()> {
    let path = Path::new(DIRECTORY);
    let parent = path.parent().ok_or("missing DAG domain parent")?;
    catalog::safe_path(parent)?;
    let parent_fd = scoped_read::open_directory(parent)?;
    catalog::ext4(&parent_fd)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    io::private_directory(&root)?;
    root.sync_all()?;
    parent_fd.sync_all()?;
    Ok(())
}
pub(crate) fn source_review(root: &str, relative: &str) -> Result<()> {
    // Ordinary DAC applies in the invoking human process. This enrolment tool
    // is deliberately not a privileged launcher action and issues no grant.
    if unsafe { libc::geteuid() } == 0 {
        return Err("source enrolment must run as the human owner without root".into());
    }
    if !input_root(root) {
        return Err(
            "source enrolment requires its explicitly provisioned workflow input domain".into(),
        );
    }
    let source = Source::open(Path::new(root), relative, 1024 * 1024)?;
    if source.identity().uid != unsafe { libc::geteuid() } {
        return Err("source enrolment must name the human's own file".into());
    }
    println!(
        "{}",
        serde_json::json!({"source":source.identity(),"file_scope_digest":hash(source.identity())?,"grant_issued":false})
    );
    Ok(())
}

pub(crate) fn review(path: &str) -> Result<()> {
    let request: Request = snapshot(path)?;
    let graph = Executable::installed()?;
    request.proposal.validate(&graph)?;
    let plan = Plan {
        schema_version: 1,
        installation: io::installation()?,
        proposal: request.proposal,
        graph: graph.graph,
        order: graph.order,
        storage_device: crate::resource_manager::storage_device(Path::new("/var"))?,
        owner: None,
    };
    let mut reads = BTreeMap::new();
    let mut writes = BTreeMap::new();
    for id in plan.proposal.inputs.keys() {
        reads.insert(id, plan.usage(Action::Read, Some(id), None)?);
    }
    for id in plan.proposal.targets.keys() {
        writes.insert(id, plan.usage(Action::Write, Some(id), None)?);
    }
    println!(
        "{}",
        serde_json::json!({"proposal":plan.proposal,"installation":plan.installation,"storage_device":plan.storage_device,
        "execute":plan.usage(Action::Execute,None,None)?,"resume":plan.usage(Action::Resume,None,None)?,"cancel":plan.usage(Action::Cancel,None,None)?,
        "reads":reads,"writes":writes,"calculation_scopes_available_after_exact_source_checkpoint":true,"grant_issued":false,"effect_executed":false})
    );
    Ok(())
}

pub(crate) fn prepare(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("expected workflow-dag-prepare LOGIN REQUEST-SNAPSHOT".into());
    }
    let request: Request = snapshot(&args[2])?;
    let graph = Executable::installed()?;
    request.proposal.validate(&graph)?;
    let mut plan = Plan {
        schema_version: 1,
        installation: io::installation()?,
        proposal: request.proposal,
        graph: graph.graph,
        order: graph.order,
        storage_device: crate::resource_manager::storage_device(Path::new("/var"))?,
        owner: None,
    };
    let uses = vec![grant(
        &request.grants,
        "execute",
        plan.usage(Action::Execute, None, None)?,
    )?];
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        plan.owner = Some(Owner {
            principal: boundary.subject()?.into(),
            generation: boundary.subject_generation()?,
        });
        plan.authorize(boundary)?;
        let domain_pending = boundary.effect_begin(
            &format!("{}.domain", plan.proposal.request_id),
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let store = owned_store(&plan, boundary)?;
        boundary.effect_complete(domain_pending, &hash(&(&plan.installation, &plan.owner))?)?;
        if !store
            .db
            .query(
                "SELECT request_id FROM runs WHERE request_id=?",
                &[&plan.proposal.request_id],
                1,
            )?
            .is_empty()
        {
            if store.load(&plan.proposal.request_id)?.plan != plan {
                return Err("DAG preparation idempotency conflict".into());
            }
            plan.authorize(boundary)?;
            return store.status(&plan.proposal.request_id);
        }
        let pending = boundary.effect_begin(
            &format!("{}.prepare", plan.proposal.request_id),
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let event = next_event(
            &plan,
            None,
            "",
            Phase::Prepared,
            None,
            boundary.operation_id(),
        )?;
        store.persist(&plan, None, &event, || plan.authorize(boundary))?;
        boundary.effect_complete(pending, &hash(&event)?)?;
        store.status(&plan.proposal.request_id)
    })?;
    println!("{result}");
    Ok(())
}

fn node_inputs(plan: &Plan, node: &crate::workflow::Node) -> Result<Vec<String>> {
    let graph = plan.validate(&plan.installation)?;
    match node.kind {
        Kind::FileRead => Ok(vec![node.id.clone()]),
        Kind::DeterministicCalculate => Ok(node.dependencies.clone()),
        Kind::ArtifactWrite => Ok(graph.node(&node.dependencies[0])?.dependencies.clone()),
    }
}

pub(crate) fn status(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err("expected workflow-dag-status LOGIN GRANTS-SNAPSHOT REQUEST".into());
    }
    let grants: BTreeMap<String, String> = snapshot(&args[2])?;
    let store = login_store(&args[1])?;
    let run = store.load(&args[3])?;
    let uses = vec![grant(
        &grants,
        "resume",
        run.plan.usage(Action::Resume, None, None)?,
    )?];
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        run.plan.authorize_base(boundary)?;
        let mut result = store.status(&args[3])?;
        if run.cursor < run.plan.order.len() && run.event.phase != Phase::Cancelled {
            let graph = run.plan.validate(&run.plan.installation)?;
            let node = graph.node(&run.plan.order[run.cursor])?;
            if node.kind != Kind::FileRead {
                let calculation = if node.kind == Kind::ArtifactWrite {
                    graph.node(&node.dependencies[0])?
                } else {
                    node
                };
                let bytes = store.batch(calculation, &run.outputs)?;
                let input = (io::digest(&bytes), bytes.len() as u64);
                result["calculation_node"] = calculation.id.clone().into();
                result["calculate"] = serde_json::to_value(run.plan.usage(
                    Action::Calculate,
                    Some(&calculation.id),
                    Some((&input.0, input.1)),
                )?)?;
                result["worker"] = serde_json::to_value(run.plan.usage(
                    Action::StartWorker,
                    Some(&calculation.id),
                    Some((&input.0, input.1)),
                )?)?;
                result["resource"] = serde_json::to_value(run.plan.usage(
                    Action::AcquireResource,
                    Some(&calculation.id),
                    Some((&input.0, input.1)),
                )?)?;
            }
        }
        Ok(result)
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn advance(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected workflow-dag-advance LOGIN GRANTS-SNAPSHOT REQUEST REVIEW-SHA256".into(),
        );
    }
    let grants: BTreeMap<String, String> = snapshot(&args[2])?;
    let store = login_store(&args[1])?;
    let run = store.load(&args[3])?;
    if run.event.phase == Phase::Cancelled {
        return Err("cancelled DAG cannot execute".into());
    }
    let mut uses = vec![grant(
        &grants,
        "resume",
        run.plan.usage(Action::Resume, None, None)?,
    )?];
    if store
        .replayed_review(&run, &args[4], false)
        .unwrap_or(false)
    {
        let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
            run.plan.authorize_base(boundary)?;
            if !store.replayed_review(&store.load(&args[3])?, &args[4], false)? {
                return Err("DAG acknowledged transition changed".into());
            }
            let mut result = store.status(&args[3])?;
            result["replayed"] = true.into();
            Ok(result)
        })?;
        println!("{result}");
        return Ok(());
    }
    if run.cursor == run.plan.order.len() {
        let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
            run.plan.authorize(boundary)?;
            if hash(&(&run.plan, &run.event))? != args[4] {
                return Err("completed DAG review changed".into());
            }
            store.status(&args[3])
        })?;
        println!("{result}");
        return Ok(());
    }
    let graph = run.plan.validate(&run.plan.installation)?;
    let node = graph.node(&run.plan.order[run.cursor])?;
    for input in node_inputs(&run.plan, node)? {
        uses.push(grant(
            &grants,
            &format!("read.{input}"),
            run.plan.usage(Action::Read, Some(&input), None)?,
        )?);
    }
    let calculation_node = if node.kind == Kind::ArtifactWrite {
        Some(graph.node(&node.dependencies[0])?)
    } else if node.kind == Kind::DeterministicCalculate {
        Some(node)
    } else {
        None
    };
    let batch = calculation_node
        .map(|node| store.batch(node, &run.outputs))
        .transpose()?;
    if let Some(bytes) = &batch {
        let input = (io::digest(bytes), bytes.len() as u64);
        for (action, prefix) in [
            (Action::Calculate, "calculate"),
            (Action::StartWorker, "worker"),
            (Action::AcquireResource, "resource"),
        ] {
            let calculation = calculation_node.ok_or("DAG calculation scope is missing")?;
            uses.push(grant(
                &grants,
                &format!("{prefix}.{}", calculation.id),
                run.plan
                    .usage(action, Some(&calculation.id), Some((&input.0, input.1)))?,
            )?);
        }
    }
    if node.kind == Kind::ArtifactWrite {
        uses.push(grant(
            &grants,
            &format!("write.{}", node.id),
            run.plan.usage(Action::Write, Some(&node.id), None)?,
        )?);
    }
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        run.plan.authorize(boundary)?;
        if hash(&(&run.plan, &run.event))? != args[4] {
            return Err("DAG checkpoint review changed".into());
        }
        let operation = boundary.operation_id().to_owned();
        let output = match node.kind {
            Kind::FileRead => {
                let input = run
                    .plan
                    .proposal
                    .inputs
                    .get(&node.id)
                    .ok_or("DAG source missing")?;
                let source = Source::bind(input, 1024 * 1024)?;
                let pending = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "read")?,
                    crate::policy_decisions::EffectKind::Snapshot,
                )?;
                run.plan.authorize(boundary)?;
                source.recheck()?;
                let bytes = source.read()?;
                run.plan.authorize(boundary)?;
                source.recheck()?;
                let digest = store.put(&bytes, || {
                    run.plan.authorize(boundary)?;
                    source.recheck()
                })?;
                boundary.effect_complete(pending, &hash(&(source.identity(), &digest))?)?;
                Output::Text {
                    sha256: digest,
                    bytes: bytes.len() as u64,
                }
            }
            Kind::DeterministicCalculate => {
                let bytes = batch.as_ref().ok_or("DAG batch missing")?;
                let worker = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "worker")?,
                    crate::policy_decisions::EffectKind::WorkerAdmission,
                )?;
                let resource = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "resource")?,
                    crate::policy_decisions::EffectKind::ResourceAdmission,
                )?;
                let calculation = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "calculate")?,
                    crate::policy_decisions::EffectKind::Calculation,
                )?;
                let result = workflow_resource::calculate_batch_checked(bytes, &mut || {
                    run.plan.authorize(boundary)
                })?;
                workflow_resource::recheck_batch_report(
                    &result.lease,
                    &io::digest(bytes),
                    &result.report,
                    &run.plan.installation,
                )?;
                let digest = store.put(&result.report, || {
                    run.plan.authorize(boundary)?;
                    workflow_resource::recheck_batch_report(
                        &result.lease,
                        &io::digest(bytes),
                        &result.report,
                        &run.plan.installation,
                    )
                })?;
                let outcome = hash(&(&result.lease, &digest, &io::digest(bytes)))?;
                boundary.effect_complete(resource, &outcome)?;
                boundary.effect_complete(worker, &outcome)?;
                boundary.effect_complete(calculation, &outcome)?;
                Output::Report {
                    sha256: digest,
                    bytes: result.report.len() as u64,
                    input_sha256: io::digest(bytes),
                    lease: result.lease,
                }
            }
            Kind::ArtifactWrite => {
                let (input, report, _historical_lease) = store.report(node, &run.outputs)?;
                let effect = run.plan.effect_id(&node.id)?;
                if run.event.phase != Phase::Applying {
                    let pending = boundary.effect_begin(
                        &audit_id(&args[3], &node.id, "applying")?,
                        crate::policy_decisions::EffectKind::Checkpoint,
                    )?;
                    let applying = next_event(
                        &run.plan,
                        Some(&run.event),
                        &node.id,
                        Phase::Applying,
                        None,
                        &operation,
                    )?;
                    store.persist(&run.plan, Some(&run.event), &applying, || {
                        run.plan.authorize(boundary)
                    })?;
                    boundary.effect_complete(pending, &hash(&applying)?)?;
                }
                let bytes = batch.as_ref().ok_or("DAG publication batch missing")?;
                let worker = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "worker")?,
                    crate::policy_decisions::EffectKind::WorkerAdmission,
                )?;
                let resource = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "resource")?,
                    crate::policy_decisions::EffectKind::ResourceAdmission,
                )?;
                let calculation = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "calculate")?,
                    crate::policy_decisions::EffectKind::Calculation,
                )?;
                let recomputed = workflow_resource::calculate_batch_checked(bytes, &mut || {
                    run.plan.authorize(boundary)
                })?;
                if recomputed.report != report || io::digest(bytes) != input {
                    return Err("fresh leased DAG publication computation differs from its retained checkpoint".into());
                }
                let outcome = hash(&(&recomputed.lease, &input, &io::digest(&report)))?;
                boundary.effect_complete(resource, &outcome)?;
                boundary.effect_complete(worker, &outcome)?;
                boundary.effect_complete(calculation, &outcome)?;
                let pending = boundary.effect_begin(
                    &effect,
                    crate::policy_decisions::EffectKind::ArtifactPublication,
                )?;
                let receipt = catalog::commit_owned_invoice(
                    &run.plan.commit(&node.id, &input, &effect)?,
                    &run.plan.owner()?.principal,
                    run.plan.owner()?.generation,
                    &report,
                    false,
                    || {
                        run.plan.authorize(boundary)?;
                        workflow_resource::recheck_batch_report(
                            &recomputed.lease,
                            &input,
                            &report,
                            &run.plan.installation,
                        )
                    },
                )?;
                boundary.effect_complete(pending, &hash(&receipt)?)?;
                Output::Artifact { receipt }
            }
        };
        let current = store.load(&args[3])?;
        let pending = boundary.effect_begin(
            &audit_id(&args[3], &node.id, "checkpoint")?,
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let next = next_event(
            &run.plan,
            Some(&current.event),
            &node.id,
            Phase::Completed,
            Some(output.clone()),
            &operation,
        )?;
        store.persist(&run.plan, Some(&current.event), &next, || {
            run.plan.authorize(boundary)?;
            match &output {
                Output::Report {
                    input_sha256,
                    lease,
                    sha256,
                    ..
                } => workflow_resource::recheck_batch_report(
                    lease,
                    input_sha256,
                    &store.object(sha256)?,
                    &run.plan.installation,
                ),
                Output::Artifact { receipt } => {
                    let (input, report, _) = store.report(node, &run.outputs)?;
                    let effect = run.plan.effect_id(&node.id)?;
                    if catalog::committed_owned_invoice(
                        &run.plan.commit(&node.id, &input, &effect)?,
                        &run.plan.owner()?.principal,
                        run.plan.owner()?.generation,
                        &report,
                    )?
                    .recheck()?
                        != *receipt
                    {
                        return Err("DAG committed outcome changed".into());
                    }
                    Ok(())
                }
                Output::Text { .. } => Ok(()),
            }
        })?;
        boundary.effect_complete(pending, &hash(&next)?)?;
        store.status(&args[3])
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn cancel(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected workflow-dag-cancel LOGIN GRANTS-SNAPSHOT REQUEST REVIEW-SHA256".into(),
        );
    }
    let grants: BTreeMap<String, String> = snapshot(&args[2])?;
    let store = login_store(&args[1])?;
    let run = store.load(&args[3])?;
    let uses = vec![grant(
        &grants,
        "cancel",
        run.plan.usage(Action::Cancel, None, None)?,
    )?];
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        run.plan.authorize_base(boundary)?;
        if store.replayed_review(&run, &args[4], true)? {
            let mut result = store.status(&args[3])?;
            result["replayed"] = true.into();
            return Ok(result);
        }
        if run.event.phase == Phase::Cancelled {
            return store.status(&args[3]);
        }
        if run.event.phase == Phase::Applying || run.cursor == run.plan.order.len() {
            return Err(
                "applying or completed DAG cannot be cancelled; reconcile exact outcomes".into(),
            );
        }
        let pending = boundary.effect_begin(
            &format!("{}.cancel", args[3]),
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let event = next_event(
            &run.plan,
            Some(&run.event),
            "",
            Phase::Cancelled,
            None,
            boundary.operation_id(),
        )?;
        store.persist(&run.plan, Some(&run.event), &event, || {
            run.plan.authorize_base(boundary)
        })?;
        boundary.effect_complete(pending, &hash(&event)?)?;
        store.status(&args[3])
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn reconcile(args: &[String]) -> Result<()> {
    let reviewed = if args.len() == 4 {
        None
    } else if args.len() == 6 && args[4] == "--publish-committed" {
        Some(args[5].as_str())
    } else {
        return Err("expected workflow-dag-reconcile LOGIN GRANTS-SNAPSHOT REQUEST [--publish-committed REVIEW-SHA256]".into());
    };
    let grants: BTreeMap<String, String> = snapshot(&args[2])?;
    let store = login_store(&args[1])?;
    let run = store.load(&args[3])?;
    let graph = run.plan.validate(&run.plan.installation)?;
    let (applying, node, replayed) = if run.event.phase == Phase::Applying {
        (
            run.event.clone(),
            graph.node(&run.plan.order[run.cursor])?,
            false,
        )
    } else if run.event.phase == Phase::Completed
        && graph.node(&run.event.node)?.kind == Kind::ArtifactWrite
    {
        let rows = store.db.query(
            "SELECT canonical FROM events WHERE request_id=? AND ordinal=?",
            &[&args[3], &(run.event.ordinal - 1).to_string()],
            1,
        )?;
        let previous: Event =
            serde_json::from_str(&rows.first().ok_or("DAG applying predecessor missing")?[0])?;
        if previous.phase != Phase::Applying || previous.node != run.event.node {
            return Err("DAG completion lacks its exact applying predecessor".into());
        }
        (previous, graph.node(&run.event.node)?, true)
    } else {
        return Err(
            "DAG recovery requires its retained applying or acknowledged artifact checkpoint"
                .into(),
        );
    };
    let uses = vec![grant(
        &grants,
        "resume",
        run.plan.usage(Action::Resume, None, None)?,
    )?];
    let result = crate::admin_governance::with_grants(&args[1], &uses, |boundary| {
        run.plan.authorize_base(boundary)?;
        let (input, report, _) = store.report(node, &run.outputs)?;
        let effect = run.plan.effect_id(&node.id)?;
        let proof = catalog::committed_owned_invoice(
            &run.plan.commit(&node.id, &input, &effect)?,
            &run.plan.owner()?.principal,
            run.plan.owner()?.generation,
            &report,
        )?;
        let receipt = proof.recheck()?;
        let review = hash(&(
            "luma-native-dag-committed-outcome-v1",
            &run.plan,
            &applying,
            &receipt,
        ))?;
        if let Some(reviewed) = reviewed {
            if reviewed != review {
                return Err("DAG committed-outcome review changed".into());
            }
            if !replayed {
                let pending = boundary.effect_begin(
                    &audit_id(&args[3], &node.id, "recover")?,
                    crate::policy_decisions::EffectKind::Recovery,
                )?;
                let event = next_event(
                    &run.plan,
                    Some(&run.event),
                    &node.id,
                    Phase::Completed,
                    Some(Output::Artifact {
                        receipt: receipt.clone(),
                    }),
                    boundary.operation_id(),
                )?;
                store.persist(&run.plan, Some(&run.event), &event, || {
                    run.plan.authorize_base(boundary)?;
                    if proof.recheck()? != receipt {
                        return Err("DAG committed outcome changed during acknowledgement".into());
                    }
                    Ok(())
                })?;
                boundary.effect_complete(pending, &hash(&event)?)?;
            }
        }
        Ok(
            serde_json::json!({"request_id":args[3],"review_sha256":review,"committed_receipt":receipt,"acknowledged":reviewed.is_some(),"replayed":replayed,"effect_executed":false,"state":store.status(&args[3])?["state"]}),
        )
    })?;
    println!("{result}");
    Ok(())
}
