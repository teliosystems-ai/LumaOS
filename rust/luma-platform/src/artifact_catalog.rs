//! Native WAL metadata plus immutable, domain-local content objects (ADR-0003).
//! Current entry points require installed root; product grants remain separate.
use crate::{
    artifacts as io, calculation, scoped_read, skills, sqlite::Connection, workflow_resource,
    Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

const DIRECTORY: &str = "/var/lib/luma-os/artifact-catalog";
mod domains;
mod gc;
mod gc_cli;
mod owned_effects;
pub(crate) use domains::{commit_owned_invoice, committed_owned_invoice, owned_invoice_receipt};
pub(crate) use gc_cli::command as gc_command;
pub(crate) use owned_effects::command as owned_effects_command;
const MAX_CONTENT: u64 = 2 * 1024 * 1024;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 1024;
const MAX_FILES: usize = 2048;
const SCHEMA: &[&str] = &[
    "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL CHECK(schema_version=1), installation TEXT NOT NULL CHECK(length(installation)=64), domain TEXT NOT NULL CHECK(domain='local-root')) STRICT",
    "CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY, current_version INTEGER NOT NULL CHECK(current_version>0)) STRICT",
    "CREATE TABLE versions (artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id), version INTEGER NOT NULL CHECK(version>0), content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64), content_bytes INTEGER NOT NULL CHECK(content_bytes>0 AND content_bytes<=2097152), PRIMARY KEY(artifact_id,version)) STRICT",
    "CREATE TABLE receipts (sequence INTEGER PRIMARY KEY CHECK(sequence>0), request_id TEXT NOT NULL UNIQUE, artifact_id TEXT NOT NULL, version INTEGER NOT NULL, canonical TEXT NOT NULL, UNIQUE(artifact_id,version), FOREIGN KEY(artifact_id,version) REFERENCES versions(artifact_id,version)) STRICT",
    "CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT,'append-only receipt'); END",
    "CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT,'append-only receipt'); END",
    "CREATE TRIGGER versions_no_update BEFORE UPDATE ON versions BEGIN SELECT RAISE(ABORT,'immutable version'); END",
    "CREATE TRIGGER versions_no_delete BEFORE DELETE ON versions BEGIN SELECT RAISE(ABORT,'immutable version'); END",
    "CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity BEGIN SELECT RAISE(ABORT,'immutable identity'); END",
    "CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity BEGIN SELECT RAISE(ABORT,'immutable identity'); END",
    "CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON artifacts BEGIN SELECT RAISE(ABORT,'retained artifact'); END",
    "CREATE TRIGGER artifacts_next_version BEFORE UPDATE ON artifacts WHEN NEW.artifact_id<>OLD.artifact_id OR NEW.current_version<>OLD.current_version+1 BEGIN SELECT RAISE(ABORT,'invalid artifact progression'); END",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    environment: String,
    installation: String,
    owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_generation: Option<u64>,
    request_id: String,
    artifact_id: String,
    expected_version: u64,
    version: u64,
    workflow_sha256: String,
    source_sha256: String,
    content_sha256: String,
    content_bytes: u64,
    filename: String,
    media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_lease: Option<crate::resources::Token>,
}

impl Receipt {
    fn validate(&self, installation: &str) -> Result<()> {
        self.validate_owner(installation, "local-root")
    }

    fn validate_owner(&self, installation: &str, owner: &str) -> Result<()> {
        if self.schema_version != 1
            || self.environment
                != if owner == "local-root" {
                    "lab"
                } else {
                    "installed"
                }
            || self.owner != owner
            || if owner == "local-root" {
                self.owner_generation.is_some()
            } else {
                !io::hash(owner)
                    || owner == "0".repeat(64)
                    || self.owner_generation.map_or(true, |g| g == 0)
            }
            || self.installation != installation
            || !io::hash(installation)
            || !io::identifier(&self.request_id)
            || !io::identifier(&self.artifact_id)
            || self.expected_version >= MAX_RECORDS as u64
            || self.version != self.expected_version + 1
            || !io::hash(&self.workflow_sha256)
            || !io::hash(&self.source_sha256)
            || !io::hash(&self.content_sha256)
            || self.content_bytes == 0
            || self.content_bytes > MAX_CONTENT
            || self.filename != "invoice-summary.json"
            || self.media_type != "application/json"
            || self
                .resource_lease
                .as_ref()
                .is_some_and(|t| !workflow_resource::token_valid(t))
        {
            return Err("invalid native artifact catalog receipt".into());
        }
        Ok(())
    }
}

pub(crate) fn ext4(root: &File) -> Result<()> {
    let mut observation: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut observation) } != 0
        || observation.f_type != 0xef53
    {
        return Err("authoritative artifact catalog requires local ext4".into());
    }
    Ok(())
}

pub(crate) fn safe_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err("artifact catalog requires a canonical absolute path".into());
    }
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err("unsafe artifact catalog path ancestor".into());
        }
    }
    Ok(())
}

fn layout(root: &File) -> Result<()> {
    let names = io::names(root, 7)?;
    for required in ["metadata.sqlite3", "objects", "pending", "retained"] {
        if !names.iter().any(|n| n == required) {
            return Err("incomplete artifact catalog; preserve state".into());
        }
    }
    for name in names {
        match name.as_str() {
            "objects" | "pending" | "retained" => {}
            "gc" => {
                let directory = io::child_directory(root, "gc")?;
                if directory.metadata()?.dev() != root.metadata()?.dev() {
                    return Err("artifact GC must share the catalog filesystem".into());
                }
                gc::validate_sidecar(&directory)?;
            }
            "metadata.sqlite3" | "metadata.sqlite3-wal" => {
                io::read_member(root, &name, 16 * 1024 * 1024)?;
            }
            "metadata.sqlite3-shm" => {
                io::read_member(root, &name, 65536)?;
            }
            _ => return Err("unknown artifact catalog member; preserve state".into()),
        }
    }
    Ok(())
}

pub(crate) fn initialize(path: &Path, installation: &str) -> Result<()> {
    initialize_domain(path, installation, "local-root")
}

fn domain_schema(owner: &str) -> Vec<String> {
    SCHEMA
        .iter()
        .map(|s| {
            if owner == "local-root" {
                s.to_string()
            } else {
                s.replace("CHECK(schema_version=1)", "CHECK(schema_version=2)")
                    .replace("CHECK(domain='local-root')", "CHECK(length(domain)=64)")
            }
        })
        .collect()
}

fn initialize_domain(path: &Path, installation: &str, owner: &str) -> Result<()> {
    if !io::hash(installation) {
        return Err("invalid artifact catalog installation".into());
    }
    let parent = path.parent().ok_or("missing artifact catalog parent")?;
    safe_path(parent)?;
    let parent_fd = scoped_read::open_directory(parent)?;
    ext4(&parent_fd)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("artifact catalog initialization is busy".into());
    }
    for name in ["objects", "pending", "retained", "gc"] {
        io::mkdir_at(&root, name)?;
    }
    io::write_member(&root, "metadata.sqlite3", b"", 0o600)?;
    let db = Connection::open(&path.join("metadata.sqlite3"))?;
    if db.query("PRAGMA journal_mode=WAL", &[], 1)? != [vec!["wal".to_owned()]] {
        return Err("artifact catalog WAL unavailable".into());
    }
    db.exec("PRAGMA max_page_count=4096;")?;
    db.exec("PRAGMA application_id=1280658753;")?;
    db.exec(if owner == "local-root" {
        "PRAGMA user_version=1;"
    } else {
        "PRAGMA user_version=2;"
    })?;
    db.exec("BEGIN IMMEDIATE;")?;
    for statement in domain_schema(owner) {
        db.exec(&statement)?;
    }
    let version = if owner == "local-root" { "1" } else { "2" };
    let domain = if owner == "local-root" {
        owner.to_owned()
    } else {
        io::digest(owner.as_bytes())
    };
    db.query(
        "INSERT INTO identity VALUES(1,?,?,?)",
        &[version, installation, &domain],
        0,
    )?;
    root.sync_all()?;
    db.exec("COMMIT;")?;
    drop(db);
    root.sync_all()?;
    parent_fd.sync_all()?;
    drop(root);
    // The same admission checks apply to newly created and restored catalogs.
    drop(Catalog::open_domain(path, installation, owner)?);
    Ok(())
}

struct Catalog {
    // Close SQLite (including its WAL) before releasing the directory lock.
    db: Connection,
    root: File,
    objects: File,
    pending: File,
    retained: File,
    installation: String,
    owner: String,
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

#[derive(Clone, Copy)]
enum Phase {
    TemporarySynced,
    ObjectSynced,
    MetadataInserted,
    Committed,
}

fn legacy_proposal(snapshot: &io::LegacyArtifact, installation: &str) -> Result<Receipt> {
    let source = &snapshot.receipt;
    source.validate(installation, &source.request_id)?;
    let report: serde_json::Value = serde_json::from_slice(&snapshot.content)?;
    if report["source_sha256"] != source.source_sha256 {
        return Err("legacy report source provenance mismatch".into());
    }
    let mut identity = b"luma-artifact-legacy-import-v1\0".to_vec();
    identity.extend(serde_json::to_vec(source)?);
    let mapped = io::digest(&identity);
    let receipt = Receipt {
        schema_version: 1,
        environment: "lab".into(),
        installation: installation.into(),
        owner: "local-root".into(),
        owner_generation: None,
        request_id: mapped.clone(),
        artifact_id: mapped,
        expected_version: 0,
        version: 1,
        workflow_sha256: source.workflow_sha256.clone(),
        source_sha256: source.source_sha256.clone(),
        content_sha256: source.content_sha256.clone(),
        content_bytes: source.content_bytes,
        filename: source.filename.clone(),
        media_type: source.media_type.clone(),
        resource_lease: source.resource_lease.clone(),
    };
    receipt.validate(installation)?;
    Ok(receipt)
}

impl Catalog {
    fn import_legacy(
        &self,
        source: &io::LegacySource,
        request: &str,
        review: &str,
        authorize: impl FnMut(&Receipt) -> Result<()>,
    ) -> Result<(Receipt, bool)> {
        self.import_legacy_with_hook(source, request, review, authorize, |_| Ok(()))
    }

    fn import_legacy_with_hook(
        &self,
        source: &io::LegacySource,
        request: &str,
        review: &str,
        mut authorize: impl FnMut(&Receipt) -> Result<()>,
        hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<(Receipt, bool)> {
        if !io::identifier(request) || !io::hash(review) {
            return Err("invalid legacy import review".into());
        }
        if source.device()? != self.root.metadata()?.dev() {
            return Err("legacy source must share the catalog's private filesystem".into());
        }
        let snapshot = source.snapshot(request)?;
        if snapshot.receipt.review()? != review {
            return Err("legacy artifact changed since import review".into());
        }
        let receipt = legacy_proposal(&snapshot, &self.installation)?;
        let replay = self.publish_with_hook(
            &receipt,
            &snapshot.content,
            |proposal| {
                if source.snapshot(request)? != snapshot {
                    return Err(
                        "legacy source changed during import; retain catalog preparation".into(),
                    );
                }
                authorize(proposal)
            },
            hook,
        )?;
        Ok((receipt, replay))
    }

    fn open(path: &Path, installation: &str) -> Result<Self> {
        Self::open_domain(path, installation, "local-root")
    }

    fn open_domain(path: &Path, installation: &str, owner: &str) -> Result<Self> {
        safe_path(path)?;
        let root = scoped_read::open_directory(path)?;
        io::private_directory(&root)?;
        ext4(&root)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("artifact catalog is busy".into());
        }
        layout(&root)?;
        let objects = io::child_directory(&root, "objects")?;
        let pending = io::child_directory(&root, "pending")?;
        let retained = io::child_directory(&root, "retained")?;
        for child in [&objects, &pending, &retained] {
            if child.metadata()?.dev() != root.metadata()?.dev() {
                return Err("artifact catalog members must share one filesystem".into());
            }
        }
        let db = Connection::open(&path.join("metadata.sqlite3"))?;
        if db.query("PRAGMA journal_mode", &[], 1)? != [vec!["wal".to_owned()]]
            || db.query("PRAGMA page_size", &[], 1)? != [vec!["4096".to_owned()]]
            || db.query("PRAGMA application_id", &[], 1)? != [vec!["1280658753".to_owned()]]
            || db.query("PRAGMA user_version", &[], 1)?
                != [vec![if owner == "local-root" {
                    "1".to_owned()
                } else {
                    "2".to_owned()
                }]]
            || db.query(
                "SELECT schema_version,installation,domain FROM identity",
                &[],
                1,
            )? != [vec![
                if owner == "local-root" {
                    "1".to_owned()
                } else {
                    "2".to_owned()
                },
                installation.to_owned(),
                if owner == "local-root" {
                    owner.to_owned()
                } else {
                    io::digest(owner.as_bytes())
                },
            ]]
        {
            return Err("unsupported artifact catalog format or installation".into());
        }
        let mut expected = domain_schema(owner);
        expected.sort();
        let mut actual = db
            .query(
                "SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                &[],
                SCHEMA.len(),
            )?
            .into_iter()
            .map(|r| r[0].clone())
            .collect::<Vec<_>>();
        actual.sort();
        if actual != expected
            || db.query("PRAGMA quick_check", &[], 1)? != [vec!["ok".to_owned()]]
            || !db.query("PRAGMA foreign_key_check", &[], 1)?.is_empty()
        {
            return Err("artifact catalog schema or integrity failure".into());
        }
        db.exec("PRAGMA max_page_count=4096;")?;
        let result = Self {
            db,
            root,
            objects,
            pending,
            retained,
            installation: installation.into(),
            owner: owner.into(),
        };
        result.inventory()?;
        Ok(result)
    }

    fn inventory(&self) -> Result<(Vec<(u64, Receipt)>, Vec<String>, u64)> {
        let rows = self.db.query("SELECT r.sequence,r.request_id,r.artifact_id,r.version,r.canonical,v.content_sha256,v.content_bytes FROM receipts r JOIN versions v ON r.artifact_id=v.artifact_id AND r.version=v.version ORDER BY r.sequence", &[], MAX_RECORDS)?;
        let mut receipts = Vec::new();
        for row in rows {
            let receipt: Receipt = serde_json::from_str(&row[4])?;
            receipt.validate_owner(&self.installation, &self.owner)?;
            if serde_json::to_string(&receipt)? != row[4]
                || receipt.request_id != row[1]
                || receipt.artifact_id != row[2]
                || receipt.version.to_string() != row[3]
                || receipt.content_sha256 != row[5]
                || receipt.content_bytes.to_string() != row[6]
            {
                return Err("artifact catalog receipt/version mismatch".into());
            }
            receipts.push((row[0].parse()?, receipt));
        }
        if receipts
            .iter()
            .enumerate()
            .any(|(index, (sequence, _))| *sequence != index as u64 + 1)
        {
            return Err("artifact receipt sequence discontinuity".into());
        }
        if self.db.query("SELECT count(*) FROM versions", &[], 1)?
            != [vec![receipts.len().to_string()]]
            || self.db.query("SELECT count(*) FROM receipts", &[], 1)?
                != [vec![receipts.len().to_string()]]
        {
            return Err("artifact catalog has unreceipted versions".into());
        }
        for row in self.db.query(
            "SELECT artifact_id,current_version FROM artifacts",
            &[],
            MAX_RECORDS,
        )? {
            let versions = receipts
                .iter()
                .filter(|(_, r)| r.artifact_id == row[0])
                .map(|(_, r)| r.version)
                .collect::<BTreeSet<_>>();
            let current: u64 = row[1].parse()?;
            if current == 0 || current > MAX_RECORDS as u64 || versions != (1..=current).collect() {
                return Err("artifact catalog version chain incomplete".into());
            }
        }
        let mut total = 0;
        let mut orphans = Vec::new();
        let names = io::names(&self.objects, MAX_FILES)?;
        for name in &names {
            if !io::hash(name) {
                return Err("invalid artifact object identity".into());
            }
            let bytes = io::read_member(&self.objects, name, MAX_CONTENT)?;
            total += bytes.len() as u64;
            if total > MAX_BYTES || io::digest(&bytes) != *name {
                return Err("artifact object integrity or capacity failure".into());
            }
            if !receipts.iter().any(|(_, r)| &r.content_sha256 == name) {
                orphans.push(name.clone());
            }
        }
        for (_, receipt) in &receipts {
            if !names.contains(&receipt.content_sha256)
                || io::read_member(&self.objects, &receipt.content_sha256, MAX_CONTENT)?.len()
                    as u64
                    != receipt.content_bytes
            {
                return Err("committed artifact object is missing or invalid".into());
            }
        }
        let mut preparations = 0;
        let mut preparation_ids = BTreeSet::new();
        for dir in [&self.pending, &self.retained] {
            for request in io::names(dir, MAX_FILES)? {
                if !io::identifier(&request)
                    || !preparation_ids.insert(request.clone())
                    || receipts.iter().any(|(_, r)| r.request_id == request)
                {
                    return Err("invalid artifact preparation identity".into());
                }
                total += io::read_member(dir, &request, MAX_CONTENT)?.len() as u64;
                preparations += 1;
                if total > MAX_BYTES {
                    return Err("artifact preparation capacity failure".into());
                }
            }
        }
        if names.len() + preparations > MAX_FILES {
            return Err("artifact file capacity exhausted".into());
        }
        Ok((receipts, orphans, total))
    }

    fn rename(&self, from: &File, to: &File, source: &str, target: &str) -> Result<()> {
        let source = CString::new(source)?;
        let target = CString::new(target)?;
        if unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                source.as_ptr(),
                to.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("artifact object publication requires reinspection".into());
        }
        to.sync_all()?;
        from.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    fn publish(
        &self,
        receipt: &Receipt,
        bytes: &[u8],
        authorize: impl FnMut(&Receipt) -> Result<()>,
    ) -> Result<bool> {
        self.publish_with_hook(receipt, bytes, authorize, |_| Ok(()))
    }

    fn publish_with_hook(
        &self,
        receipt: &Receipt,
        bytes: &[u8],
        mut authorize: impl FnMut(&Receipt) -> Result<()>,
        mut hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<bool> {
        receipt.validate_owner(&self.installation, &self.owner)?;
        if receipt.content_bytes != bytes.len() as u64
            || receipt.content_sha256 != io::digest(bytes)
        {
            return Err("artifact catalog proposed content mismatch".into());
        }
        authorize(receipt)?;
        let (records, _, total) = self.inventory()?;
        if let Some((_, previous)) = records
            .iter()
            .find(|(_, r)| r.request_id == receipt.request_id)
        {
            if previous != receipt {
                return Err("artifact catalog idempotency conflict".into());
            }
            authorize(receipt)?;
            io::open_at(&self.objects, &receipt.content_sha256, libc::O_RDONLY, 0)?.sync_all()?;
            self.objects.sync_all()?;
            self.root.sync_all()?;
            authorize(receipt)?;
            return Ok(true);
        }
        if io::names(&self.retained, MAX_FILES)?.contains(&receipt.request_id) {
            return Err("retained artifact request cannot be reused".into());
        }
        let current = self.db.query(
            "SELECT current_version FROM artifacts WHERE artifact_id=?",
            &[&receipt.artifact_id],
            1,
        )?;
        let expected = receipt.expected_version.to_string();
        if (current.is_empty() && receipt.expected_version != 0)
            || (!current.is_empty() && current != [vec![expected.clone()]])
        {
            return Err("artifact catalog version conflict".into());
        }
        if records.len() >= MAX_RECORDS {
            return Err("artifact catalog record capacity exhausted".into());
        }
        let objects = io::names(&self.objects, MAX_FILES)?;
        let pending = io::names(&self.pending, MAX_FILES)?;
        if !objects.contains(&receipt.content_sha256) {
            if !pending.contains(&receipt.request_id) {
                if total + receipt.content_bytes > MAX_BYTES
                    || objects.len() + pending.len() + io::names(&self.retained, MAX_FILES)?.len()
                        >= MAX_FILES
                {
                    return Err("artifact catalog storage capacity exhausted".into());
                }
                let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut space) } != 0
                    || space
                        .f_bavail
                        .checked_mul(space.f_frsize)
                        .ok_or("artifact space overflow")?
                        < receipt.content_bytes + 16 * 1024 * 1024
                {
                    return Err("insufficient artifact catalog storage reserve".into());
                }
                authorize(receipt)?;
                io::write_member(&self.pending, &receipt.request_id, bytes, 0o400)?;
                self.pending.sync_all()?;
            }
            if io::read_member(&self.pending, &receipt.request_id, MAX_CONTENT)? != bytes {
                return Err("partial artifact preparation requires reviewed retention".into());
            }
            io::open_at(&self.pending, &receipt.request_id, libc::O_RDONLY, 0)?.sync_all()?;
            self.pending.sync_all()?;
            hook(Phase::TemporarySynced)?;
            authorize(receipt)?;
            self.rename(
                &self.pending,
                &self.objects,
                &receipt.request_id,
                &receipt.content_sha256,
            )?;
        } else if pending.contains(&receipt.request_id) {
            return Err(
                "artifact preparation conflicts with existing object; retain for review".into(),
            );
        }
        if io::read_member(&self.objects, &receipt.content_sha256, MAX_CONTENT)? != bytes {
            return Err("artifact object changed before metadata commit".into());
        }
        io::open_at(&self.objects, &receipt.content_sha256, libc::O_RDONLY, 0)?.sync_all()?;
        self.objects.sync_all()?;
        hook(Phase::ObjectSynced)?;
        self.db.exec("BEGIN IMMEDIATE;")?;
        let transaction = Transaction(&self.db, false);
        if receipt.expected_version == 0 {
            self.db.query(
                "INSERT INTO artifacts VALUES(?,1)",
                &[&receipt.artifact_id],
                0,
            )?;
        } else {
            // Directory lock serializes this service's reads and writes.
            self.db.query("UPDATE artifacts SET current_version=current_version+1 WHERE artifact_id=? AND current_version=?", &[&receipt.artifact_id, &expected], 0)?;
            if self.db.query("SELECT changes()", &[], 1)? != [vec!["1".to_owned()]] {
                return Err("artifact changed before version commit".into());
            }
        }
        let version = receipt.version.to_string();
        let count = receipt.content_bytes.to_string();
        self.db.query(
            "INSERT INTO versions VALUES(?,?,?,?)",
            &[
                &receipt.artifact_id,
                &version,
                &receipt.content_sha256,
                &count,
            ],
            0,
        )?;
        let canonical = serde_json::to_string(receipt)?;
        self.db.query(
            "INSERT INTO receipts(request_id,artifact_id,version,canonical) VALUES(?,?,?,?)",
            &[
                &receipt.request_id,
                &receipt.artifact_id,
                &version,
                &canonical,
            ],
            0,
        )?;
        hook(Phase::MetadataInserted)?;
        authorize(receipt)?;
        // WAL/SHM namespace entries must be durable before the WAL commit.
        self.root.sync_all()?;
        authorize(receipt)?;
        transaction.commit()?;
        hook(Phase::Committed)?;
        self.root.sync_all()?;
        Ok(false)
    }

    fn retain(&self, request: &str, review: &str) -> Result<()> {
        self.retain_checked(request, review, || Ok(()))
    }

    fn retain_checked(
        &self,
        request: &str,
        review: &str,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if !io::identifier(request) || !io::hash(review) {
            return Err("invalid artifact retention review".into());
        }
        self.inventory()?;
        let already = io::names(&self.retained, MAX_FILES)?
            .iter()
            .any(|r| r == request);
        let dir = if already {
            &self.retained
        } else {
            &self.pending
        };
        let bytes = io::read_member(dir, request, MAX_CONTENT)?;
        if self.review(request, &bytes)? != review {
            return Err("artifact preparation changed since review".into());
        }
        check()?;
        if !already {
            self.rename(&self.pending, &self.retained, request, request)?;
        }
        io::open_at(&self.retained, request, libc::O_RDONLY, 0)?.sync_all()?;
        self.retained.sync_all()?;
        self.pending.sync_all()?;
        self.root.sync_all()?;
        check()?;
        Ok(())
    }

    fn review(&self, request: &str, bytes: &[u8]) -> Result<String> {
        Ok(io::digest(&serde_json::to_vec(
            &serde_json::json!({"installation":self.installation,"domain":self.owner,"request_id":request,"bytes":bytes.len(),"sha256":io::digest(bytes)}),
        )?))
    }

    fn status(&self) -> Result<serde_json::Value> {
        let (records, orphans, bytes) = self.inventory()?;
        let mut pending = Vec::new();
        for request in io::names(&self.pending, MAX_FILES)? {
            let bytes = io::read_member(&self.pending, &request, MAX_CONTENT)?;
            pending.push(serde_json::json!({"request_id":request,"bytes":bytes.len(),"retain_review_sha256":self.review(&request,&bytes)?}));
        }
        Ok(
            serde_json::json!({"schema_version":1,"environment":"lab","domain":"local-root","journal_mode":"wal","synchronous":"full","records":records.iter().map(|(sequence,receipt)| serde_json::json!({"sequence":sequence,"receipt":receipt})).collect::<Vec<_>>(),"orphans":orphans,"pending":pending,"retained":io::names(&self.retained,MAX_FILES)?,"storage_bytes":bytes,"product_admin_active":false,"rollback_protected":false,"gate_closing":false}),
        )
    }
}

fn authorize(receipt: &Receipt) -> Result<()> {
    if io::installation()? != receipt.installation
        || skills::admission()?["workflow_sha256"] != receipt.workflow_sha256
    {
        return Err("artifact catalog installation or signed workflow changed".into());
    }
    Ok(())
}

/// Typed in-process artifact boundary for the native laboratory coordinator.
/// It confers no principal grant and opens no caller-selected catalog path.
pub(crate) struct InvoiceCommit<'a> {
    pub installation: &'a str,
    pub request_id: &'a str,
    pub artifact_id: &'a str,
    pub expected_version: u64,
    pub workflow_sha256: &'a str,
    pub source_sha256: &'a str,
}

pub(crate) fn invoice_receipt(
    commit: &InvoiceCommit<'_>,
    bytes: &[u8],
) -> Result<serde_json::Value> {
    let receipt = Receipt {
        schema_version: 1,
        environment: "lab".into(),
        installation: commit.installation.into(),
        owner: "local-root".into(),
        owner_generation: None,
        request_id: commit.request_id.into(),
        artifact_id: commit.artifact_id.into(),
        expected_version: commit.expected_version,
        version: commit
            .expected_version
            .checked_add(1)
            .ok_or("workflow version overflow")?,
        workflow_sha256: commit.workflow_sha256.into(),
        source_sha256: commit.source_sha256.into(),
        content_sha256: io::digest(bytes),
        content_bytes: bytes.len() as u64,
        filename: "invoice-summary.json".into(),
        media_type: "application/json".into(),
        resource_lease: None,
    };
    receipt.validate(commit.installation)?;
    if serde_json::from_slice::<serde_json::Value>(bytes)?["source_sha256"] != commit.source_sha256
    {
        return Err("workflow report provenance differs from its source".into());
    }
    Ok(serde_json::to_value(receipt)?)
}

pub(crate) fn commit_invoice(
    commit: &InvoiceCommit<'_>,
    bytes: &[u8],
    replay_only: bool,
    mut coordinator_check: impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    if io::installation()? != commit.installation {
        return Err("workflow artifact installation changed".into());
    }
    let expected = invoice_receipt(commit, bytes)?;
    let receipt: Receipt = serde_json::from_value(expected.clone())?;
    let catalog = Catalog::open(Path::new(DIRECTORY), commit.installation)?;
    if replay_only && !catalog.inventory()?.0.iter().any(|(_, r)| r == &receipt) {
        return Err("completed workflow lacks its exact artifact receipt; preserve state".into());
    }
    catalog.publish(&receipt, bytes, |proposal| {
        authorize(proposal)?;
        coordinator_check()
    })?;
    Ok(expected)
}

/// A verified past outcome, never authority to publish or redispatch. Keep this
/// guard alive through the coordinator acknowledgement so catalog ownership
/// spans both the observation and its final recheck.
pub(crate) struct InvoiceOutcome {
    catalog: Catalog,
    expected: Receipt,
}
impl InvoiceOutcome {
    pub(crate) fn recheck(&self) -> Result<serde_json::Value> {
        if !self
            .catalog
            .inventory()?
            .0
            .iter()
            .any(|(_, r)| r == &self.expected)
        {
            return Err("no exact committed invoice receipt; outcome remains uncertain".into());
        }
        Ok(serde_json::to_value(&self.expected)?)
    }
}

pub(crate) fn committed_invoice(
    commit: &InvoiceCommit<'_>,
    bytes: &[u8],
) -> Result<InvoiceOutcome> {
    if io::installation()? != commit.installation {
        return Err("invoice reconciliation installation changed".into());
    }
    let expected = serde_json::from_value(invoice_receipt(commit, bytes)?)?;
    let proof = InvoiceOutcome {
        catalog: Catalog::open(Path::new(DIRECTORY), commit.installation)?,
        expected,
    };
    proof.recheck()?;
    Ok(proof)
}

pub fn initialize_installed() -> Result<()> {
    initialize(Path::new(DIRECTORY), &io::installation()?)?;
    domains::initialize_base()
}
pub fn status() -> Result<()> {
    println!(
        "{}",
        Catalog::open(Path::new(DIRECTORY), &io::installation()?)?.status()?
    );
    Ok(())
}
pub fn publish_invoice(request: &str, artifact: &str, expected: &str) -> Result<()> {
    let result = invoice_publication(
        request,
        artifact,
        expected,
        workflow_resource::calculate,
        workflow_resource::Calculation::recheck,
    )?;
    println!("{result}");
    Ok(())
}

pub(crate) fn invoice_publication(
    request: &str,
    artifact: &str,
    expected: &str,
    calculate: impl FnOnce(&[u8]) -> Result<workflow_resource::Calculation>,
    mut recheck: impl FnMut(&workflow_resource::Calculation, &[u8], &str) -> Result<()>,
) -> Result<serde_json::Value> {
    let expected_version = expected.parse::<u64>()?;
    if !io::identifier(request)
        || !io::identifier(artifact)
        || expected_version.to_string() != expected
        || expected_version >= MAX_RECORDS as u64
    {
        return Err("invalid or noncanonical artifact publication identity".into());
    }
    let installation = io::installation()?;
    let admission = skills::admission()?;
    let source = calculation::source_stdin()?;
    let result = calculate(&source)?;
    let bytes = &result.report;
    let mut receipt = Receipt {
        schema_version: 1,
        environment: "lab".into(),
        installation,
        owner: "local-root".into(),
        owner_generation: None,
        request_id: request.into(),
        artifact_id: artifact.into(),
        expected_version,
        version: expected_version
            .checked_add(1)
            .ok_or("artifact version overflow")?,
        workflow_sha256: admission["workflow_sha256"]
            .as_str()
            .ok_or("missing signed workflow")?
            .into(),
        source_sha256: io::digest(&source),
        content_sha256: io::digest(bytes),
        content_bytes: bytes.len() as u64,
        filename: "invoice-summary.json".into(),
        media_type: "application/json".into(),
        resource_lease: Some(result.lease.clone()),
    };
    let catalog = Catalog::open(Path::new(DIRECTORY), &receipt.installation)?;
    if let Some((_, previous)) = catalog
        .inventory()?
        .0
        .iter()
        .find(|(_, r)| r.request_id == request)
    {
        receipt.resource_lease = previous.resource_lease.clone();
    }
    let replayed = catalog.publish(&receipt, bytes, |receipt| {
        authorize(receipt)?;
        recheck(&result, &source, &receipt.installation)
    })?;
    Ok(serde_json::json!({"receipt":receipt,"replayed":replayed,
        "calculation_lease":result.lease,"gate_closing":false}))
}
pub fn read(artifact: &str, version: &str) -> Result<()> {
    let catalog = Catalog::open(Path::new(DIRECTORY), &io::installation()?)?;
    let (records, _, _) = catalog.inventory()?;
    let receipt = records
        .iter()
        .find(|(_, r)| r.artifact_id == artifact && r.version.to_string() == version)
        .ok_or("artifact version not found")?;
    let bytes = io::read_member(&catalog.objects, &receipt.1.content_sha256, MAX_CONTENT)?;
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}
pub fn retain(request: &str, review: &str) -> Result<()> {
    let installation = io::installation()?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &installation)?;
    if io::installation()? != installation {
        return Err("artifact installation changed before retention".into());
    }
    catalog.retain(request, review)?;
    println!(
        "{}",
        serde_json::json!({"request_id":request,"state":"retained","gate_closing":false})
    );
    Ok(())
}

fn export_usage(receipt: &Receipt) -> Result<crate::finite_grants::Use> {
    use crate::finite_grants::{Action, Kind, Selector, Use};
    let usage = Use {
        action: Action::Export,
        selector: Selector {
            kind: Kind::Artifact,
            id: receipt.artifact_id.clone(),
            generation: receipt.version,
            digest: io::digest(&serde_json::to_vec(receipt)?),
        },
        input_bytes: 0,
        output_bytes: receipt.content_bytes,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}

pub(crate) fn governed_export_review(artifact: &str, version: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &io::installation()?)?;
    let (records, _, _) = catalog.inventory()?;
    let receipt = records
        .iter()
        .find(|(_, r)| r.artifact_id == artifact && r.version.to_string() == version)
        .ok_or("artifact version not found")?;
    println!(
        "{}",
        serde_json::json!({"usage":export_usage(&receipt.1)?,
        "receipt":receipt.1,"content_exported":false,"grant_issued":false})
    );
    Ok(())
}

pub(crate) fn governed_export(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err("expected artifact-governed-export LOGIN EXPORT-GRANT ARTIFACT VERSION".into());
    }
    let catalog = Catalog::open(Path::new(DIRECTORY), &io::installation()?)?;
    let (records, _, _) = catalog.inventory()?;
    let receipt = records
        .iter()
        .find(|(_, r)| r.artifact_id == args[3] && r.version.to_string() == args[4])
        .ok_or("artifact version not found")?
        .1
        .clone();
    let usage = export_usage(&receipt)?;
    crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let pending = boundary.effect_begin(
            &receipt.request_id,
            crate::policy_decisions::EffectKind::ArtifactExport,
        )?;
        let bytes = io::read_member(&catalog.objects, &receipt.content_sha256, MAX_CONTENT)?;
        if bytes.len() as u64 != receipt.content_bytes
            || io::digest(&bytes) != receipt.content_sha256
        {
            return Err("artifact export content changed".into());
        }
        let mut output = crate::service::granted_gateway::export_writer()?;
        for block in bytes.chunks(32 * 1024) {
            boundary.stream_check(&pending)?;
            output.write_all(block)?;
        }
        output.flush()?;
        boundary.check()?;
        if !catalog.inventory()?.0.iter().any(|(_, r)| r == &receipt) {
            return Err("artifact export outcome uncertain; preserve destination bytes".into());
        }
        boundary.effect_complete(pending, &io::digest(&serde_json::to_vec(&receipt)?))?;
        Ok(())
    })
}

pub(crate) fn governed_retain(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected artifact-governed-retain LOGIN RETENTION-GRANT REQUEST REVIEW-SHA256".into(),
        );
    }
    let installation = io::installation()?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &installation)?;
    catalog.inventory()?;
    let already = io::names(&catalog.retained, MAX_FILES)?.contains(&args[3]);
    let bytes = io::read_member(
        if already {
            &catalog.retained
        } else {
            &catalog.pending
        },
        &args[3],
        MAX_CONTENT,
    )?;
    let review = catalog.review(&args[3], &bytes)?;
    if args[4] != review {
        return Err("artifact retention review changed".into());
    }
    use crate::finite_grants::{Action, Kind, Selector, Use};
    let usage = Use {
        action: Action::Retain,
        selector: Selector {
            kind: Kind::Artifact,
            id: args[3].clone(),
            generation: 1,
            digest: review.clone(),
        },
        input_bytes: bytes.len() as u64,
        output_bytes: 0,
        units: 1,
    };
    crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let pending =
            boundary.effect_begin(&args[3], crate::policy_decisions::EffectKind::Retention)?;
        catalog.retain_checked(&args[3], &review, || {
            boundary.check()?;
            if io::installation()? != installation {
                return Err("retention installation changed".into());
            }
            Ok(())
        })?;
        boundary.effect_complete(pending, &review)
    })?;
    println!(
        "{}",
        serde_json::json!({"request_id":args[3],"state":"retained",
        "review_sha256":review,"bytes_preserved":true,"content_deleted":false})
    );
    Ok(())
}

pub fn legacy_inspect(request: &str) -> Result<()> {
    let installation = io::installation()?;
    // Fixed lock order: legacy source, then destination catalog. No initialization.
    let source = io::LegacySource::open(Path::new(io::DIRECTORY), &installation)?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &installation)?;
    if source.device()? != catalog.root.metadata()?.dev() {
        return Err("legacy source and catalog filesystem mismatch".into());
    }
    let snapshot = source.snapshot(request)?;
    let proposal = legacy_proposal(&snapshot, &installation)?;
    println!(
        "{}",
        serde_json::json!({"source_request_id":request,"review_sha256":snapshot.receipt.review()?,
        "source_receipt":snapshot.receipt,"catalog_proposal":proposal,"source_preserved":true,
        "effect_executed":false,"environment":"lab","gate_closing":false})
    );
    Ok(())
}

pub fn import_legacy(request: &str, review: &str) -> Result<()> {
    let installation = io::installation()?;
    let source = io::LegacySource::open(Path::new(io::DIRECTORY), &installation)?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &installation)?;
    let (receipt, replayed) = catalog.import_legacy(&source, request, review, authorize)?;
    println!(
        "{}",
        serde_json::json!({"source_request_id":request,"source_review_sha256":review,
        "receipt":receipt,"replayed":replayed,"source_preserved":true,"gate_closing":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    pub(super) struct Fixture {
        pub(super) path: PathBuf,
        parent: PathBuf,
    }
    impl Fixture {
        pub(super) fn new(label: &str) -> Self {
            let root = std::env::var("LUMA_STORAGE_TEST_ROOT").expect(
                "catalog tests require a private ext4 container volume via LUMA_STORAGE_TEST_ROOT",
            );
            let parent =
                Path::new(&root).join(format!("luma-catalog-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
            let path = parent.join("catalog");
            initialize(&path, &"a".repeat(64)).unwrap();
            Self { path, parent }
        }
        fn open(&self) -> Catalog {
            Catalog::open(&self.path, &"a".repeat(64)).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.parent).unwrap();
        }
    }
    fn proposal(request: &str, artifact: &str, expected: u64) -> (Receipt, Vec<u8>) {
        let source = include_bytes!("../../../examples/invoices.csv");
        let bytes = calculation::report_bytes(source).unwrap();
        (
            Receipt {
                schema_version: 1,
                environment: "lab".into(),
                installation: "a".repeat(64),
                owner: "local-root".into(),
                owner_generation: None,
                request_id: request.into(),
                artifact_id: artifact.into(),
                expected_version: expected,
                version: expected + 1,
                workflow_sha256: "b".repeat(64),
                source_sha256: io::digest(source),
                content_sha256: io::digest(&bytes),
                content_bytes: bytes.len() as u64,
                filename: "invoice-summary.json".into(),
                media_type: "application/json".into(),
                resource_lease: None,
            },
            bytes,
        )
    }

    fn legacy_fixture(f: &Fixture, request: &str) -> (std::path::PathBuf, io::Receipt, Vec<u8>) {
        let path = f.parent.join("legacy");
        io::initialize(&path, &"a".repeat(64)).unwrap();
        let (proposal, bytes) = proposal(request, "unused", 0);
        let receipt = io::Receipt {
            schema_version: 1,
            installation: proposal.installation,
            request_id: request.into(),
            authenticated_uid: 0,
            workflow_sha256: proposal.workflow_sha256,
            source_sha256: proposal.source_sha256,
            content_sha256: proposal.content_sha256,
            content_bytes: proposal.content_bytes,
            filename: proposal.filename,
            media_type: proposal.media_type,
            version: 1,
            resource_lease: None,
        };
        let root = scoped_read::open_directory(&path).unwrap();
        let committed = io::child_directory(&root, "committed").unwrap();
        let pair = io::mkdir_at(&committed, request).unwrap();
        io::write_member(&pair, "report.json", &bytes, 0o400).unwrap();
        io::write_member(
            &pair,
            "receipt.json",
            &serde_json::to_vec(&receipt).unwrap(),
            0o400,
        )
        .unwrap();
        pair.sync_all().unwrap();
        committed.sync_all().unwrap();
        root.sync_all().unwrap();
        (path, receipt, bytes)
    }

    #[test]
    fn resource_provenance_preserves_old_canonical_receipts_and_refuses_bad_tokens() {
        let (mut receipt, _) = proposal("request-1", "invoices", 0);
        let old = serde_json::to_vec(&receipt).unwrap();
        assert!(!std::str::from_utf8(&old)
            .unwrap()
            .contains("resource_lease"));
        let decoded: Receipt = serde_json::from_slice(&old).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), old);
        receipt.resource_lease = Some(crate::resources::Token {
            lease_id: "c".repeat(32),
            manager_epoch: "d".repeat(32),
            generation: 1,
        });
        receipt.validate(&"a".repeat(64)).unwrap();
        let encoded = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            serde_json::from_slice::<Receipt>(&encoded).unwrap(),
            receipt
        );
        receipt.resource_lease.as_mut().unwrap().manager_epoch = "x".repeat(32);
        assert!(receipt.validate(&"a".repeat(64)).is_err());
    }

    #[test]
    fn output_fence_before_commit_rolls_back_receipts_and_versions_but_keeps_object() {
        let f = Fixture::new("result-fence");
        let (mut receipt, bytes) = proposal("request-1", "invoices", 0);
        receipt.resource_lease = Some(crate::resources::Token {
            lease_id: "c".repeat(32),
            manager_epoch: "d".repeat(32),
            generation: 1,
        });
        let fenced = Cell::new(false);
        assert!(f
            .open()
            .publish_with_hook(
                &receipt,
                &bytes,
                |_| {
                    if fenced.get() {
                        Err("broker generation fenced".into())
                    } else {
                        Ok(())
                    }
                },
                |phase| {
                    if matches!(phase, Phase::MetadataInserted) {
                        fenced.set(true);
                    }
                    Ok(())
                }
            )
            .is_err());
        let catalog = f.open();
        let (records, orphans, _) = catalog.inventory().unwrap();
        assert!(records.is_empty());
        assert_eq!(orphans, [receipt.content_sha256.clone()]);
        assert!(catalog
            .db
            .query("SELECT current_version FROM artifacts", &[], 1)
            .unwrap()
            .is_empty());
        assert!(!catalog.publish(&receipt, &bytes, |_| Ok(())).unwrap());
        assert_eq!(catalog.inventory().unwrap().0[0].1, receipt);
    }

    #[test]
    fn committed_outcome_guard_requires_exact_receipt_keeps_ownership_and_rechecks_bytes() {
        let f = Fixture::new("outcome-guard");
        let (receipt, bytes) = proposal("outcome-request", "outcome-artifact", 0);
        {
            let proof = InvoiceOutcome {
                catalog: f.open(),
                expected: receipt.clone(),
            };
            assert!(proof.recheck().is_err());
        }
        f.open().publish(&receipt, &bytes, |_| Ok(())).unwrap();
        {
            let mut wrong = receipt.clone();
            wrong.artifact_id = "wrong-target".into();
            let proof = InvoiceOutcome {
                catalog: f.open(),
                expected: wrong,
            };
            assert!(proof.recheck().is_err());
        }
        {
            let proof = InvoiceOutcome {
                catalog: f.open(),
                expected: receipt.clone(),
            };
            assert_eq!(
                proof.recheck().unwrap(),
                serde_json::to_value(&receipt).unwrap()
            );
            assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        }
        let (later, bytes) = proposal("outcome-later", "outcome-artifact", 1);
        f.open().publish(&later, &bytes, |_| Ok(())).unwrap();
        let proof = InvoiceOutcome {
            catalog: f.open(),
            expected: receipt.clone(),
        };
        assert_eq!(
            proof.recheck().unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
        let object = f.path.join("objects").join(&receipt.content_sha256);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&object, b"tampered after observation").unwrap();
        assert!(proof.recheck().is_err());
    }

    #[test]
    fn reviewed_legacy_import_preserves_source_and_maps_stable_independent_identity() {
        let f = Fixture::new("legacy-copy");
        let (path, legacy, bytes) = legacy_fixture(&f, "request-1");
        let source = io::LegacySource::open(&path, &"a".repeat(64)).unwrap();
        let snapshot = source.snapshot("request-1").unwrap();
        let catalog = f.open();
        let (receipt, replay) = catalog
            .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
            .unwrap();
        assert!(!replay);
        assert_eq!(receipt.artifact_id, receipt.request_id);
        assert_ne!(receipt.artifact_id, receipt.content_sha256);
        assert_ne!(receipt.artifact_id, legacy.request_id);
        assert_eq!(receipt.source_sha256, legacy.source_sha256);
        assert_eq!(source.snapshot("request-1").unwrap().content, bytes);
        assert!(source.snapshot("request-1").unwrap() == snapshot);
        assert!(
            catalog
                .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
                .unwrap()
                .1
        );
        assert_eq!(catalog.inventory().unwrap().0.len(), 1);
        let (update, updated_bytes) = proposal("update-imported", &receipt.artifact_id, 1);
        catalog
            .publish(&update, &updated_bytes, |_| Ok(()))
            .unwrap();
        let (repeated, replayed) = catalog
            .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
            .unwrap();
        assert!(replayed);
        assert_eq!(repeated, receipt);
        assert_eq!(catalog.inventory().unwrap().0.len(), 2);
        assert_eq!(
            catalog
                .db
                .query(
                    "SELECT current_version FROM artifacts WHERE artifact_id=?",
                    &[&receipt.artifact_id],
                    1
                )
                .unwrap(),
            [vec!["2".to_owned()]]
        );
        assert!(io::LegacySource::open(&path, &"a".repeat(64)).is_err());
    }

    #[test]
    fn legacy_import_interruption_retries_or_replays_without_duplicate_receipts() {
        for (label, phase) in [("legacy-object", 0), ("legacy-sql", 1), ("legacy-ack", 2)] {
            let f = Fixture::new(label);
            let (path, legacy, _) = legacy_fixture(&f, "request-1");
            let source = io::LegacySource::open(&path, &"a".repeat(64)).unwrap();
            assert!(f
                .open()
                .import_legacy_with_hook(
                    &source,
                    "request-1",
                    &legacy.review().unwrap(),
                    |_| Ok(()),
                    |p| {
                        if matches!(
                            (phase, p),
                            (0, Phase::ObjectSynced)
                                | (1, Phase::MetadataInserted)
                                | (2, Phase::Committed)
                        ) {
                            Err("interrupted import".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            let catalog = f.open();
            assert_eq!(
                catalog.inventory().unwrap().0.len(),
                usize::from(phase == 2)
            );
            assert_eq!(
                catalog
                    .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
                    .unwrap()
                    .1,
                phase == 2
            );
            assert_eq!(catalog.inventory().unwrap().0.len(), 1);
            assert_eq!(source.snapshot("request-1").unwrap().receipt, legacy);
        }
    }

    #[test]
    fn legacy_import_wrong_review_pending_source_revocation_and_conflicts_are_denied() {
        let f = Fixture::new("legacy-denials");
        let (path, legacy, bytes) = legacy_fixture(&f, "request-1");
        let source = io::LegacySource::open(&path, &"a".repeat(64)).unwrap();
        let catalog = f.open();
        assert!(catalog
            .import_legacy(&source, "request-1", &"f".repeat(64), |_| Ok(()))
            .is_err());
        assert!(catalog.inventory().unwrap().0.is_empty());
        let calls = Cell::new(0);
        assert!(catalog
            .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("revoked before import commit".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
        assert!(catalog.inventory().unwrap().0.is_empty());
        let root = scoped_read::open_directory(&path).unwrap();
        let pending = io::child_directory(&root, "pending").unwrap();
        io::mkdir_at(&pending, "unfinished").unwrap();
        assert!(source.snapshot("request-1").is_err());
        assert!(catalog
            .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
            .is_err());
        // This is a private fixture, not source-store cleanup by the importer.
        fs::remove_dir(path.join("pending/unfinished")).unwrap();
        let mut conflict =
            legacy_proposal(&source.snapshot("request-1").unwrap(), &"a".repeat(64)).unwrap();
        conflict.source_sha256 = "c".repeat(64);
        catalog.publish(&conflict, &bytes, |_| Ok(())).unwrap();
        assert!(catalog
            .import_legacy(&source, "request-1", &legacy.review().unwrap(), |_| Ok(()))
            .is_err());
    }

    #[test]
    fn source_changed_during_import_and_false_report_provenance_never_commit() {
        let f = Fixture::new("legacy-change");
        let (path, legacy, _) = legacy_fixture(&f, "request-1");
        let source = io::LegacySource::open(&path, &"a".repeat(64)).unwrap();
        let catalog = f.open();
        let report = path.join("committed/request-1/report.json");
        assert!(catalog
            .import_legacy_with_hook(
                &source,
                "request-1",
                &legacy.review().unwrap(),
                |_| Ok(()),
                |p| {
                    if matches!(p, Phase::ObjectSynced) {
                        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
                        fs::write(&report, b"tampered").unwrap();
                    }
                    Ok(())
                }
            )
            .is_err());
        assert!(catalog.inventory().unwrap().0.is_empty());
        assert_eq!(catalog.inventory().unwrap().1, [legacy.content_sha256]);
        let other = Fixture::new("legacy-provenance");
        let (path, mut receipt, _) = legacy_fixture(&other, "request-1");
        receipt.source_sha256 = "c".repeat(64);
        let file = path.join("committed/request-1/receipt.json");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&file, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let source = io::LegacySource::open(&path, &"a".repeat(64)).unwrap();
        assert!(other
            .open()
            .import_legacy(&source, "request-1", &receipt.review().unwrap(), |_| Ok(()))
            .is_err());
    }

    #[test]
    fn versions_exact_replay_deduplication_and_compare_exchange_are_durable() {
        let f = Fixture::new("versions");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        assert!(!f.open().publish(&r, &bytes, |_| Ok(())).unwrap());
        assert!(f.open().publish(&r, &bytes, |_| Ok(())).unwrap());
        let (next, _) = proposal("request-2", "invoice", 1);
        f.open().publish(&next, &bytes, |_| Ok(())).unwrap();
        let (other, _) = proposal("request-3", "other", 0);
        f.open().publish(&other, &bytes, |_| Ok(())).unwrap();
        let (stale, _) = proposal("request-4", "invoice", 1);
        assert!(f.open().publish(&stale, &bytes, |_| Ok(())).is_err());
        let catalog = f.open();
        let (records, orphans, total) = catalog.inventory().unwrap();
        assert_eq!(records.len(), 3);
        assert!(orphans.is_empty());
        assert_eq!(total, bytes.len() as u64);
        assert_eq!(io::names(&catalog.objects, MAX_FILES).unwrap().len(), 1);
        assert!(catalog.publish(&r, &bytes, |_| Ok(())).unwrap());
        let mut conflict = r.clone();
        conflict.source_sha256 = "c".repeat(64);
        assert!(catalog.publish(&conflict, &bytes, |_| Ok(())).is_err());
    }

    #[test]
    fn object_before_transaction_and_rollback_leave_only_verified_orphans() {
        for (label, phase) in [("object", 0), ("transaction", 1)] {
            let f = Fixture::new(label);
            let (r, bytes) = proposal("request-1", "invoice", 0);
            assert!(f
                .open()
                .publish_with_hook(
                    &r,
                    &bytes,
                    |_| Ok(()),
                    |p| {
                        if matches!(
                            (phase, p),
                            (0, Phase::ObjectSynced) | (1, Phase::MetadataInserted)
                        ) {
                            Err("interrupted".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            let catalog = f.open();
            let (records, orphans, _) = catalog.inventory().unwrap();
            assert!(records.is_empty());
            assert_eq!(orphans, [r.content_sha256.clone()]);
            assert!(catalog
                .db
                .query("SELECT * FROM artifacts", &[], 1)
                .unwrap()
                .is_empty());
            assert!(!catalog.publish(&r, &bytes, |_| Ok(())).unwrap());
        }
    }

    #[test]
    fn lost_commit_ack_replays_one_atomic_receipt_and_checks_current_authority() {
        let f = Fixture::new("ack");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        assert!(f
            .open()
            .publish_with_hook(
                &r,
                &bytes,
                |_| Ok(()),
                |p| {
                    if matches!(p, Phase::Committed) {
                        Err("lost acknowledgement".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert!(f
            .open()
            .publish(&r, &bytes, |_| Err("revoked".into()))
            .is_err());
        assert!(f.open().publish(&r, &bytes, |_| Ok(())).unwrap());
        assert_eq!(f.open().inventory().unwrap().0.len(), 1);
        let calls = Cell::new(0);
        assert!(f
            .open()
            .publish(&r, &bytes, |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("revoked while checking replay".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn revocation_rolls_back_metadata_and_preserves_object_for_review() {
        let f = Fixture::new("revocation");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        let inserted = Cell::new(false);
        assert!(f
            .open()
            .publish_with_hook(
                &r,
                &bytes,
                |_| {
                    if inserted.get() {
                        Err("revoked before metadata commit".into())
                    } else {
                        Ok(())
                    }
                },
                |phase| {
                    if matches!(phase, Phase::MetadataInserted) {
                        inserted.set(true);
                    }
                    Ok(())
                }
            )
            .is_err());
        assert!(inserted.get());
        assert!(f.open().inventory().unwrap().0.is_empty());
        assert_eq!(f.open().inventory().unwrap().1, [r.content_sha256]);
    }

    #[test]
    fn revocation_after_pending_sync_refuses_object_rename_and_preserves_exact_bytes() {
        let f = Fixture::new("pending-rename-revocation");
        let (receipt, bytes) = proposal("request-1", "invoice", 0);
        let synced = Cell::new(false);
        let catalog = f.open();
        assert!(catalog
            .publish_with_hook(
                &receipt,
                &bytes,
                |_| {
                    if synced.get() {
                        Err("revoked before object rename".into())
                    } else {
                        Ok(())
                    }
                },
                |phase| {
                    if matches!(phase, Phase::TemporarySynced) {
                        synced.set(true);
                    }
                    Ok(())
                }
            )
            .is_err());
        assert!(synced.get());
        assert_eq!(
            io::read_member(&catalog.pending, &receipt.request_id, MAX_CONTENT).unwrap(),
            bytes
        );
        assert!(io::names(&catalog.objects, MAX_FILES).unwrap().is_empty());
        assert!(catalog.inventory().unwrap().0.is_empty());
    }

    #[test]
    fn synced_preparation_retries_and_partial_bytes_require_reviewed_retention() {
        let f = Fixture::new("preparation");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        assert!(f
            .open()
            .publish_with_hook(
                &r,
                &bytes,
                |_| Ok(()),
                |p| {
                    if matches!(p, Phase::TemporarySynced) {
                        Err("interrupted".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert!(!f.open().publish(&r, &bytes, |_| Ok(())).unwrap());
        let catalog = f.open();
        io::write_member(&catalog.pending, "partial", b"part", 0o400).unwrap();
        let review = catalog.review("partial", b"part").unwrap();
        assert!(catalog.retain("partial", &"f".repeat(64)).is_err());
        catalog.retain("partial", &review).unwrap();
        catalog.retain("partial", &review).unwrap();
        assert_eq!(
            io::read_member(&catalog.retained, "partial", MAX_CONTENT).unwrap(),
            b"part"
        );
        let (other, _) = proposal("partial", "other", 0);
        assert!(catalog.publish(&other, &bytes, |_| Ok(())).is_err());
        let (other, _) = proposal("new-request", "other", 0);
        catalog.publish(&other, &bytes, |_| Ok(())).unwrap();
    }

    #[test]
    fn retention_denial_preserves_preparation_and_post_rename_denial_preserves_evidence() {
        let f = Fixture::new("retention-boundaries");
        let catalog = f.open();
        io::write_member(&catalog.pending, "partial", b"part", 0o400).unwrap();
        let review = catalog.review("partial", b"part").unwrap();
        assert!(catalog
            .retain_checked("partial", &review, || Err("grant revoked".into()))
            .is_err());
        assert_eq!(
            io::read_member(&catalog.pending, "partial", MAX_CONTENT).unwrap(),
            b"part"
        );
        let calls = Cell::new(0);
        assert!(catalog
            .retain_checked("partial", &review, || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("expired after rename; inspect exact retained evidence".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(
            io::read_member(&catalog.retained, "partial", MAX_CONTENT).unwrap(),
            b"part"
        );
        catalog
            .retain_checked("partial", &review, || Ok(()))
            .unwrap();
    }

    #[test]
    fn export_scope_binds_complete_receipt_and_exact_output_bound() {
        let (mut receipt, _) = proposal("export-one", "invoice", 0);
        let original = export_usage(&receipt).unwrap();
        assert_eq!(original.output_bytes, receipt.content_bytes);
        assert_eq!(original.input_bytes, 0);
        assert_eq!(original.selector.generation, receipt.version);
        receipt.request_id = "different-outcome".into();
        assert_ne!(
            export_usage(&receipt).unwrap().selector.digest,
            original.selector.digest
        );
    }

    #[test]
    fn database_triggers_refuse_receipt_version_identity_and_history_mutation() {
        let f = Fixture::new("append-only");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        let catalog = f.open();
        catalog.publish(&r, &bytes, |_| Ok(())).unwrap();
        for statement in [
            "DELETE FROM receipts",
            "UPDATE receipts SET canonical='altered'",
            "DELETE FROM versions",
            "UPDATE versions SET content_bytes=1",
            "DELETE FROM identity",
            "UPDATE identity SET installation='altered'",
            "DELETE FROM artifacts",
            "UPDATE artifacts SET current_version=4",
        ] {
            assert!(catalog.db.exec(statement).is_err(), "{statement}");
        }
        assert_eq!(catalog.inventory().unwrap().0.len(), 1);
    }

    #[test]
    fn unsafe_objects_missing_bytes_schema_identity_and_concurrent_access_fail_closed() {
        let f = Fixture::new("unsafe");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        assert!(Catalog::open(&f.path, &"c".repeat(64)).is_err());
        let catalog = f.open();
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        catalog.publish(&r, &bytes, |_| Ok(())).unwrap();
        drop(catalog);
        let object = f.path.join("objects").join(&r.content_sha256);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&object, b"tampered").unwrap();
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        fs::remove_file(&object).unwrap();
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        symlink("../metadata.sqlite3", &object).unwrap();
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        fs::remove_file(&object).unwrap();
        fs::write(&object, &bytes).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
        let catalog = f.open();
        catalog.db.exec("DROP TRIGGER receipts_no_delete;").unwrap();
        drop(catalog);
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
        assert!(initialize(&f.path, &"a".repeat(64)).is_err());
    }

    #[test]
    fn non_ext4_symlink_paths_and_linked_metadata_are_refused_before_use() {
        let proc = scoped_read::open_directory(Path::new("/proc")).unwrap();
        assert!(ext4(&proc).is_err());
        assert!(initialize(Path::new("/proc/luma-never-created"), &"a".repeat(64)).is_err());
        let f = Fixture::new("unsafe-path");
        let alias = f.parent.join("alias");
        symlink(&f.path, &alias).unwrap();
        assert!(Catalog::open(&alias, &"a".repeat(64)).is_err());
        fs::hard_link(f.path.join("metadata.sqlite3"), f.parent.join("linked-db")).unwrap();
        assert!(Catalog::open(&f.path, &"a".repeat(64)).is_err());
    }

    #[test]
    fn offline_copy_preserves_versions_and_unknown_format_is_not_migrated() {
        let f = Fixture::new("offline-copy");
        let (r, bytes) = proposal("request-1", "invoice", 0);
        f.open().publish(&r, &bytes, |_| Ok(())).unwrap();
        let copy = f.parent.join("restored");
        fs::DirBuilder::new().mode(0o700).create(&copy).unwrap();
        fs::copy(
            f.path.join("metadata.sqlite3"),
            copy.join("metadata.sqlite3"),
        )
        .unwrap();
        fs::set_permissions(
            copy.join("metadata.sqlite3"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let root = scoped_read::open_directory(&copy).unwrap();
        for name in ["objects", "pending", "retained"] {
            io::mkdir_at(&root, name).unwrap();
        }
        fs::copy(
            f.path.join("objects").join(&r.content_sha256),
            copy.join("objects").join(&r.content_sha256),
        )
        .unwrap();
        fs::set_permissions(
            copy.join("objects").join(&r.content_sha256),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let restored = Catalog::open(&copy, &"a".repeat(64)).unwrap();
        assert_eq!(restored.inventory().unwrap().0[0].1, r);
        let (next, _) = proposal("request-2", "invoice", 1);
        restored.publish(&next, &bytes, |_| Ok(())).unwrap();
        assert_eq!(restored.inventory().unwrap().0.len(), 2);
        drop(restored);
        assert_eq!(f.open().inventory().unwrap().0.len(), 1);
        assert!(Catalog::open(&copy, &"b".repeat(64)).is_err());
        let restored = Catalog::open(&copy, &"a".repeat(64)).unwrap();
        restored.db.exec("PRAGMA user_version=2;").unwrap();
        drop(restored);
        assert!(Catalog::open(&copy, &"a".repeat(64)).is_err());
        assert!(initialize(&copy, &"a".repeat(64)).is_err());
        let db = Connection::open(&copy.join("metadata.sqlite3")).unwrap();
        assert_eq!(
            db.query("PRAGMA user_version", &[], 1).unwrap(),
            [vec!["2".to_owned()]]
        );
    }
}
