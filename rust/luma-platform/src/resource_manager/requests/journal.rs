//! Private durable request receipts under the existing resource-store lock.
//! Archive publication precedes the hot cut; uncertain writes poison admission.
use super::*;
use crate::{bundle, platform, tpm};
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;

const FILE: &str = "requests.json";
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVES: usize = 64;
const MAX_FILES: usize = 128;
const MAX_DIRECTORY_ENTRIES: usize = 512;

pub(super) mod optional_decimal {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> std::result::Result<S::Ok, S::Error> {
        v.map(|n| n.to_string()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<u64>, D::Error> {
        let Some(text) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let value = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom(
                "noncanonical optional request count",
            ));
        }
        Ok(Some(value))
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Archive {
    #[serde(with = "resources::decimal")]
    batch: u64,
    sha256: String,
}
impl Archive {
    fn name(&self) -> String {
        format!("requests-archive-{}-{}.json", self.batch, self.sha256)
    }

    fn stage_reference(name: &str) -> Result<Self> {
        let (batch, hash) = name
            .strip_prefix(".requests-stage-requests-archive-")
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(|s| s.split_once('-'))
            .ok_or("unknown request archive preparation name; preserve state")?;
        let reference = Self {
            batch: batch.parse()?,
            sha256: hash.into(),
        };
        if reference.batch == 0
            || !digest_valid(hash)
            || format!(".requests-stage-{}", reference.name()) != name
        {
            return Err("noncanonical request archive preparation name".into());
        }
        Ok(reference)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Origin {
    FreshResourceState {},
    ReviewedLegacyMigration {
        ledger_review: String,
        manager_epoch: String,
        #[serde(with = "resources::decimal")]
        generation: u64,
    },
}
impl Default for Origin {
    fn default() -> Self {
        Self::FreshResourceState {}
    }
}

#[derive(Default)]
pub(super) struct Retention {
    origin: Origin,
    archives: Vec<Archive>,
    pub(super) retired: BTreeSet<String>,
    published: Option<String>,
    pub(super) poisoned: bool,
    authority_lost: std::cell::Cell<bool>,
}
impl Retention {
    pub(super) fn check(&self) -> Result<()> {
        if self.poisoned || self.authority_lost.get() {
            return Err(
                "request publication uncertain; preserve state and restart authority".into(),
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    origin: Origin,
    archives: Vec<Archive>,
    records: Vec<Record>,
}
#[derive(Serialize)]
struct SnapshotRef<'a> {
    schema_version: u32,
    origin: &'a Origin,
    archives: &'a [Archive],
    records: &'a [Record],
}

fn digest(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}

#[derive(Serialize, PartialEq, Eq)]
struct StageIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
    sha256: String,
}

fn stage_identity(path: &Path) -> Result<StageIdentity> {
    tpm::private_directory(path.parent().ok_or("stage parent missing")?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() > MAX_BYTES
    {
        return Err("unsafe request recovery stage".into());
    }
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or("request recovery stage length overflow")?;
        if length > MAX_BYTES {
            return Err("request recovery stage grew beyond its bound".into());
        }
        hasher.update(&buffer[..count]);
    }
    let sha256 = bundle::hex(&hasher.finalize());
    let identity = |m: &fs::Metadata| StageIdentity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        modified: m.mtime(),
        modified_ns: m.mtime_nsec(),
        changed: m.ctime(),
        changed_ns: m.ctime_nsec(),
        sha256: sha256.clone(),
    };
    if length != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&fs::symlink_metadata(path)?)
    {
        return Err("request recovery stage changed during inspection".into());
    }
    Ok(identity(&before))
}

fn preserve_stage(
    directory: &Path,
    source: &str,
    destination: &str,
    identity: &StageIdentity,
) -> Result<()> {
    let source_path = directory.join(source);
    if stage_identity(&source_path)? != *identity {
        return Err("request recovery stage changed before preservation".into());
    }
    File::open(&source_path)?.sync_all()?;
    let from = CString::new(source_path.as_os_str().as_bytes())?;
    let to = CString::new(directory.join(destination).as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let retained = stage_identity(&directory.join(destination))?;
    if retained.device != identity.device
        || retained.inode != identity.inode
        || retained.length != identity.length
        || retained.sha256 != identity.sha256
        || source_path.try_exists()?
    {
        return Err("request stage preservation outcome uncertain".into());
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn validate_records(records: &[Record]) -> Result<BTreeSet<String>> {
    if records.len() > MAX_RECEIPTS {
        return Err("request receipt inventory exhausted".into());
    }
    let mut nonces = BTreeSet::new();
    let mut outstanding = 0;
    for record in records {
        if !nonce_valid(&record.nonce)
            || !nonces.insert(record.nonce.clone())
            || !nonce_valid(&record.worker.lease_id)
            || !nonce_valid(&record.worker.manager_epoch)
            || record.worker.generation == 0
            || record.caller.pid == 0
            || record.caller.start == 0
            || !matches!(record.caller.uid, 0 | 990)
            || record.caller.uid == 990 && record.input_digest.is_none()
            || record.caller.boot.is_empty()
            || record.caller.boot.len() > 128
            || !record
                .caller
                .boot
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || record.profile.is_empty()
            || record.profile.len() > 128
            || !record
                .profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || record.limit == 0
            || record.limit > MAX_OUTPUT
            || record.context != 2048
            || record.until == 0
            || record
                .input_digest
                .as_deref()
                .map_or(false, |value| !digest_valid(value))
        {
            return Err("invalid durable inference identity or budget; preserve state".into());
        }
        let prepared = record.prompt.is_none() && record.token_digest.is_none();
        let admitted = record.prompt.map_or(false, |p| {
            p > 0
                && p.checked_add(record.limit)
                    .map_or(false, |v| v <= record.context)
        }) && record.token_digest.as_deref().map_or(false, digest_valid);
        let no_result = record.output.is_none() && record.result_digest.is_none();
        let valid = match record.phase {
            Phase::Preparing => prepared && no_result,
            Phase::Admitted => admitted && no_result,
            Phase::Completed => {
                admitted
                    && record.output.map_or(false, |n| n > 0 && n <= record.limit)
                    && record.result_digest.as_deref().map_or(false, digest_valid)
            }
            Phase::Draining | Phase::Released => (prepared || admitted) && no_result,
        };
        if !valid {
            return Err("inconsistent durable inference transition; preserve state".into());
        }
        outstanding += usize::from(!matches!(record.phase, Phase::Completed | Phase::Released));
    }
    if outstanding > 1 {
        return Err("durable inference slot capacity exceeded".into());
    }
    Ok(nonces)
}

fn decode(bytes: &[u8]) -> Result<Snapshot> {
    let snapshot: Snapshot = serde_json::from_slice(bytes)?;
    if snapshot.schema_version != 1
        || serde_json::to_vec(&snapshot)? != bytes
        || snapshot.archives.len() > MAX_ARCHIVES
    {
        return Err("noncanonical or unsupported inference journal; preserve state".into());
    }
    if let Origin::ReviewedLegacyMigration {
        ledger_review,
        manager_epoch,
        generation,
    } = &snapshot.origin
    {
        if !digest_valid(ledger_review)
            || !(nonce_valid(manager_epoch) || manager_epoch.is_empty() && *generation == 0)
        {
            return Err("invalid request journal migration provenance".into());
        }
    }
    for (index, reference) in snapshot.archives.iter().enumerate() {
        if reference.batch != index as u64 + 1 || !digest_valid(&reference.sha256) {
            return Err("invalid request archive chain".into());
        }
    }
    validate_records(&snapshot.records)?;
    Ok(snapshot)
}

pub(crate) fn initialize(directory: &Path) -> Result<()> {
    initialize_with_origin(directory, &Origin::default())
}

fn initialize_with_origin(directory: &Path, origin: &Origin) -> Result<()> {
    tpm::private_directory(directory)?;
    // Exclusive creation only. An uncertain prior creation is never overwritten.
    let bytes = serde_json::to_vec(&SnapshotRef {
        schema_version: 1,
        origin,
        archives: &[],
        records: &[],
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(FILE))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn inventory(
    directory: &Path,
    references: &[Archive],
    origin: &Origin,
) -> Result<BTreeSet<String>> {
    let mut count = 0;
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            return Err("private request directory inspection limit exceeded".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid private request filename")?;
        if let Some(suffix) = name.strip_prefix(".requests-retained-") {
            count += 1;
            let (hash, review) = suffix
                .split_once('-')
                .ok_or("invalid retained request incident name")?;
            let review = review
                .strip_suffix(".json")
                .ok_or("invalid retained request incident suffix")?;
            if !digest_valid(hash)
                || !digest_valid(review)
                || stage_identity(&entry.path())?.sha256 != hash
            {
                return Err("retained request incident mismatch".into());
            }
        } else if name.starts_with(".requests-stage-") {
            count += 1;
            tpm::private_read(&entry.path(), MAX_BYTES)?;
        } else if let Some(suffix) = name.strip_prefix("requests-archive-") {
            count += 1;
            let (batch, hash) = suffix
                .split_once('-')
                .ok_or("invalid request archive filename")?;
            let reference = Archive {
                batch: batch.parse()?,
                sha256: hash
                    .strip_suffix(".json")
                    .ok_or("invalid request archive suffix")?
                    .into(),
            };
            if reference.batch == 0 || !digest_valid(&reference.sha256) || reference.name() != name
            {
                return Err("noncanonical request archive filename".into());
            }
            let bytes = tpm::private_read(&entry.path(), MAX_BYTES)?;
            let snapshot = decode(&bytes)?;
            if digest(&bytes) != reference.sha256
                || snapshot.records.is_empty()
                || snapshot.archives.len() as u64 + 1 != reference.batch
                || snapshot
                    .records
                    .iter()
                    .any(|r| !matches!(r.phase, Phase::Completed | Phase::Released))
            {
                return Err("request archive has mismatched or outstanding receipts".into());
            }
        }
        if count > MAX_FILES {
            return Err("retained request file inventory exhausted".into());
        }
    }
    let mut retired = BTreeSet::new();
    for (index, reference) in references.iter().enumerate() {
        let bytes = tpm::private_read(&directory.join(reference.name()), MAX_BYTES)?;
        if digest(&bytes) != reference.sha256 {
            return Err("request archive digest mismatch".into());
        }
        let snapshot = decode(&bytes)?;
        if snapshot.origin != *origin
            || snapshot.archives != references[..index]
            || snapshot.records.is_empty()
            || snapshot
                .records
                .iter()
                .any(|r| !matches!(r.phase, Phase::Completed | Phase::Released))
        {
            return Err("request archive predecessor or terminal state mismatch".into());
        }
        for record in snapshot.records {
            if !retired.insert(record.nonce) {
                return Err("duplicate retired inference identity".into());
            }
        }
    }
    Ok(retired)
}

impl Gate {
    pub(in crate::resource_manager) fn open(store: &Store) -> Result<Self> {
        let directory = store.request_directory()?;
        let bytes = tpm::private_read(&directory.join(FILE), MAX_BYTES)?;
        let snapshot = decode(&bytes)?;
        let retired = inventory(directory, &snapshot.archives, &snapshot.origin)?;
        if snapshot.records.iter().any(|r| retired.contains(&r.nonce)) {
            return Err("hot inference nonce already retired".into());
        }
        let gate = Self {
            records: snapshot.records,
            retention: Retention {
                origin: snapshot.origin,
                archives: snapshot.archives,
                retired,
                published: Some(digest(&bytes)),
                poisoned: false,
                authority_lost: std::cell::Cell::new(false),
            },
        };
        gate.verify_loaded(store)?;
        Ok(gate)
    }

    // This witness belongs only to the current locked authority. A restored
    // pathname or journal cannot revive a generation after observed loss.
    fn verify_durable(&self, store: &Store, expected: &str) -> Result<StageIdentity> {
        self.retention.check()?;
        let result = (|| -> Result<StageIdentity> {
            let directory = store.request_directory()?;
            let observed = stage_identity(&directory.join(FILE))?;
            if observed.sha256 != expected {
                return Err("request journal changed outside authority; preserve state".into());
            }
            store.request_directory()?;
            Ok(observed)
        })();
        if result.is_err() {
            self.retention.authority_lost.set(true);
        }
        result
    }

    fn verify_loaded(&self, store: &Store) -> Result<StageIdentity> {
        let expected = self
            .retention
            .published
            .as_deref()
            .ok_or("request journal not loaded")?;
        self.verify_durable(store, expected)
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        self.retention.check()?;
        let nonces = validate_records(&self.records)?;
        if nonces.iter().any(|n| self.retention.retired.contains(n)) {
            return Err("inference identity collides with retained history".into());
        }
        let bytes = serde_json::to_vec(&SnapshotRef {
            schema_version: 1,
            origin: &self.retention.origin,
            archives: &self.retention.archives,
            records: &self.records,
        })?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("private inference journal capacity exhausted".into());
        }
        Ok(bytes)
    }

    pub(in crate::resource_manager) fn persist(
        &mut self,
        store: &Store,
        acknowledge: bool,
    ) -> Result<()> {
        self.persist_with(store, acknowledge, |path, bytes| {
            platform::write_atomic(path, bytes, 0o600)
        })
    }

    fn persist_with(
        &mut self,
        store: &Store,
        acknowledge: bool,
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let bytes = self.bytes()?;
        let next = digest(&bytes);
        let published = self
            .retention
            .published
            .as_deref()
            .ok_or("request journal not loaded")?;
        let result = (|| -> Result<()> {
            self.verify_durable(store, published)?;
            if next == published && !acknowledge {
                return Ok(());
            }
            let directory = store.request_directory()?;
            let path = directory.join(FILE);
            if next == published {
                File::open(&path)?.sync_all()?;
                File::open(directory)?.sync_all()?;
            } else {
                publish(&path, &bytes)?;
            }
            self.verify_durable(store, &next)?;
            Ok(())
        })();
        if result.is_err() {
            self.retention.poisoned = true;
        }
        result?;
        self.retention.published = Some(next);
        Ok(())
    }

    pub(in crate::resource_manager) fn retention_status(
        &self,
        store: &Store,
    ) -> Result<serde_json::Value> {
        self.verify_loaded(store)?;
        let bytes = self.bytes()?;
        let epoch = store.read()?.manager_epoch;
        let review = digest(&serde_json::to_vec(&(epoch, digest(&bytes)))?);
        Ok(
            serde_json::json!({"review": review, "hot_receipts": self.records.len(),
            "origin": self.retention.origin,
            "hot_limit": MAX_RECEIPTS, "archives": self.retention.archives,
            "input_binding_required": true,
            "input_bound_hot_receipts": self.records.iter().filter(|r| r.input_digest.is_some()).count(),
            "legacy_unbound_hot_receipts": self.records.iter().filter(|r| r.input_digest.is_none()).count(),
            "archive_limit": MAX_ARCHIVES, "retired_nonces": self.retention.retired.len(),
            "archivable": !self.occupied() && !self.records.is_empty() && self.retention.archives.len() < MAX_ARCHIVES,
            "worker_resources_released": false, "automatic_deletion": false}),
        )
    }

    pub(in crate::resource_manager) fn archive_requests(
        &mut self,
        store: &Store,
        review: &str,
    ) -> Result<serde_json::Value> {
        self.archive_with(store, review, |gate, store| gate.persist(store, true))
    }

    pub(in crate::resource_manager) fn export_chunk(
        &self,
        store: &Store,
        r: &super::super::history::Request,
    ) -> Result<super::super::history::Chunk> {
        self.verify_loaded(store)?;
        let reference = self
            .retention
            .archives
            .iter()
            .find(|a| a.batch == r.batch && a.sha256 == r.sha256)
            .ok_or("export requires an exact referenced immutable archive")?;
        let bytes = self.export_bytes(store, reference)?;
        // Canonical request identities and digests contain only ASCII. Never
        // split arbitrary UTF-8 or provide an export of an unvalidated orphan.
        if digest(&bytes) != reference.sha256
            || !bytes.is_ascii()
            || r.offset >= bytes.len() as u64
            || r.offset % super::super::history::CHUNK_BYTES != 0
        {
            return Err("request archive export digest, encoding or offset mismatch".into());
        }
        let end = r
            .offset
            .checked_add(super::super::history::CHUNK_BYTES)
            .ok_or("request export offset overflow")?
            .min(bytes.len() as u64);
        Ok(super::super::history::Chunk {
            batch: reference.batch,
            sha256: reference.sha256.clone(),
            offset: r.offset,
            next_offset: end,
            total_bytes: bytes.len() as u64,
            data: String::from_utf8(bytes[r.offset as usize..end as usize].to_vec())?,
            worker_resources_released: false,
        })
    }

    fn export_bytes(&self, store: &Store, reference: &Archive) -> Result<Vec<u8>> {
        let result = (|| -> Result<Vec<u8>> {
            let directory = store.request_directory()?;
            let path = directory.join(reference.name());
            let before = stage_identity(&path)?;
            let bytes = tpm::private_read(&path, MAX_BYTES)?;
            let snapshot = decode(&bytes)?;
            if before.sha256 != reference.sha256
                || digest(&bytes) != reference.sha256
                || snapshot.origin != self.retention.origin
                || snapshot.archives != self.retention.archives[..(reference.batch - 1) as usize]
                || snapshot.records.is_empty()
                || snapshot
                    .records
                    .iter()
                    .any(|r| !matches!(r.phase, Phase::Completed | Phase::Released))
                || stage_identity(&path)? != before
            {
                return Err("request archive export provenance mismatch".into());
            }
            self.verify_loaded(store)?;
            Ok(bytes)
        })();
        if result.is_err() {
            self.retention.authority_lost.set(true);
        }
        result
    }

    fn recovery_candidate(&self, store: &Store) -> Result<Option<(String, StageIdentity, String)>> {
        let hot = self.verify_loaded(store)?;
        let bytes = self.bytes()?;
        let ledger = store.read()?;
        if self.occupied() || ledger.leases.iter().any(|l| l.state != State::Released) {
            return Err("request stage recovery requires terminal requests and released physical generations".into());
        }
        let directory = store.request_directory()?;
        if digest(&bytes) != hot.sha256 {
            return Err("request journal changed before recovery review".into());
        }
        inventory(directory, &self.retention.archives, &self.retention.origin)?;
        let mut candidates = BTreeMap::new();
        for (index, entry) in fs::read_dir(directory)?.enumerate() {
            if index >= MAX_DIRECTORY_ENTRIES {
                return Err("request recovery directory inspection limit exceeded".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid request recovery filename")?;
            if !name.starts_with(".requests-stage-") {
                continue;
            }
            let reference = Archive::stage_reference(name)?;
            if reference.batch > self.retention.archives.len() as u64 + 1
                || reference.batch > MAX_ARCHIVES as u64
            {
                return Err("request preparation names an unavailable future batch".into());
            }
            let identity = stage_identity(&entry.path())?;
            if identity.sha256 == reference.sha256 {
                // A complete stage remains evidence for exact retry or review;
                // its presence alone never proves a durable hot-journal cut.
                continue;
            }
            candidates.insert(name.to_string(), identity);
        }
        let Some((source, identity)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let review = digest(&serde_json::to_vec(&(
            "retain-interrupted-request-stage-v2",
            store.recovery_binding()?,
            hot,
            &source,
            &identity,
        ))?);
        Ok(Some((source, identity, review)))
    }

    pub(in crate::resource_manager) fn stage_recovery_status(
        &self,
        store: &Store,
    ) -> Result<serde_json::Value> {
        Ok(match self.recovery_candidate(store)? {
            Some((source, identity, review)) => {
                serde_json::json!({"recoverable":true,"review":review,
                "stage":source,"stage_sha256":identity.sha256,"stage_bytes":identity.length.to_string(),
                "worker_resources_released":false,"evidence_deleted":false})
            }
            None => serde_json::json!({"recoverable":false,"review":null,
                "worker_resources_released":false,"evidence_deleted":false}),
        })
    }

    pub(in crate::resource_manager) fn recover_stage_checked(
        &mut self,
        store: &Store,
        review: &str,
        mut observe: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.recover_stage_with(store, review, |directory, source, destination, identity| {
            observe()?;
            preserve_stage(directory, source, destination, identity)?;
            observe()
        })
    }

    #[cfg(test)]
    fn recover_stage(&mut self, store: &Store, review: &str) -> Result<serde_json::Value> {
        self.recover_stage_with(store, review, preserve_stage)
    }

    fn recover_stage_with(
        &mut self,
        store: &Store,
        review: &str,
        preserve: impl FnOnce(&Path, &str, &str, &StageIdentity) -> Result<()>,
    ) -> Result<serde_json::Value> {
        let (source, identity, current) = self
            .recovery_candidate(store)?
            .ok_or("no interrupted request archive preparation")?;
        if current != review {
            return Err("stale request stage recovery review".into());
        }
        let destination = format!(".requests-retained-{}-{}.json", identity.sha256, current);
        let result = preserve(store.request_directory()?, &source, &destination, &identity);
        if result.is_err() {
            self.retention.poisoned = true;
        }
        result?;
        Ok(
            serde_json::json!({"retained":destination,"sha256":identity.sha256,
            "retained_bytes":identity.length.to_string(),"worker_resources_released":false,
            "evidence_deleted":false,"hot_history_preserved":true}),
        )
    }

    fn archive_with(
        &mut self,
        store: &Store,
        review: &str,
        cut: impl FnOnce(&mut Self, &Store) -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.persist(store, true)?;
        if self.retention_status(store)?["review"].as_str() != Some(review)
            || self.occupied()
            || self.records.is_empty()
            || self.retention.archives.len() >= MAX_ARCHIVES
        {
            return Err(
                "stale request archival review, outstanding requests or exhausted retention".into(),
            );
        }
        let directory = store.request_directory()?;
        inventory(directory, &self.retention.archives, &self.retention.origin)?;
        let bytes = self.bytes()?;
        let reference = Archive {
            batch: self.retention.archives.len() as u64 + 1,
            sha256: digest(&bytes),
        };
        let path = directory.join(reference.name());
        let stage = directory.join(format!(".requests-stage-{}", reference.name()));
        let count = fs::read_dir(directory)?.try_fold(0usize, |count, entry| -> Result<usize> {
            let name = entry?.file_name();
            let name = name.to_str().ok_or("invalid request filename")?;
            Ok(count
                + usize::from(
                    name.starts_with("requests-archive-")
                        || name.starts_with(".requests-stage-")
                        || name.starts_with(".requests-retained-"),
                ))
        })?;
        if count >= MAX_FILES && !path.try_exists()? && !stage.try_exists()? {
            return Err("retained request file inventory exhausted".into());
        }
        let publication = (|| -> Result<()> {
            if path.try_exists()? {
                if tpm::private_read(&path, MAX_BYTES)? != bytes {
                    return Err("conflicting request archive".into());
                }
                File::open(&path)?.sync_all()?;
            } else {
                let mut file = match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&stage)
                {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if tpm::private_read(&stage, MAX_BYTES)? != bytes {
                            return Err("incomplete request archive stage; preserve bytes".into());
                        }
                        OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(&stage)?
                    }
                    Err(e) => return Err(e.into()),
                };
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                let from = CString::new(stage.as_os_str().as_bytes())?;
                let to = CString::new(path.as_os_str().as_bytes())?;
                if unsafe {
                    libc::renameat2(
                        libc::AT_FDCWD,
                        from.as_ptr(),
                        libc::AT_FDCWD,
                        to.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            File::open(directory)?.sync_all()?;
            if stage_identity(&path)?.sha256 != reference.sha256 {
                return Err("request archive publication readback differs; preserve state".into());
            }
            self.verify_loaded(store)?;
            Ok(())
        })();
        if publication.is_err() {
            self.retention.poisoned = true;
        }
        publication?;
        // A crash before this cut leaves an immutable orphan and all hot receipts.
        // A crash after the cut reconstructs tombstones only from the cited chain.
        let nonces = validate_records(&self.records)?;
        self.retention.archives.push(reference.clone());
        self.records.clear();
        let cut_result = cut(self, store);
        if cut_result.is_err() {
            self.retention.poisoned = true;
        }
        cut_result?;
        self.retention.retired.extend(nonces);
        Ok(serde_json::json!({"archive":reference,"hot_receipts":"0",
            "worker_resources_released":false,"receipts_preserved":true,"nonces_retired":true}))
    }
}

fn migration_review(store: &Store) -> Result<String> {
    let directory = store.request_directory()?;
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            return Err("request migration directory inspection limit exceeded".into());
        }
        let name = entry?.file_name();
        let name = name.to_str().ok_or("invalid request migration filename")?;
        if name.starts_with("requests.")
            || name.starts_with("requests-")
            || name.starts_with(".requests-")
        {
            return Err(
                "existing or interrupted request history; no missing-state migration".into(),
            );
        }
    }
    let ledger = store.read()?;
    if ledger.leases.iter().any(|l| l.state != State::Released) {
        return Err("request history migration requires released physical generations".into());
    }
    Ok(digest(&serde_json::to_vec(&(
        "legacy-request-history-unavailable",
        ledger.review()?,
    ))?))
}

pub(crate) fn request_migration(review: Option<&str>) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let _operation = model::resource_recovery_exclusion()?;
    let _idle = model::resource_idle()?;
    let mut store = super::super::migration_store()?;
    let observed = migration_review(&store)?;
    if let Some(expected) = review {
        if observed != expected {
            return Err("stale request history migration review".into());
        }
        // Recheck empty trusted groups under both model and resource exclusions.
        if Group::open()?.populated()? || Group::for_kind(Kind::Acquisition)?.populated()? {
            return Err("worker appeared during request history migration".into());
        }
        migrate_store_with(&mut store, expected, initialize_with_origin)?;
        let gate = Gate::open(&store)?;
        println!("{}", gate.retention_status(&store)?);
    } else {
        println!(
            "{}",
            serde_json::json!({"review": observed,
            "legacy_request_receipts": "unavailable-before-upgrade",
            "physical_history_preserved": true, "worker_resources_released": false})
        );
    }
    Ok(())
}

fn migrate_store_with(
    store: &mut Store,
    review: &str,
    initialize_history: impl FnOnce(&Path, &Origin) -> Result<()>,
) -> Result<()> {
    if migration_review(store)? != review {
        return Err("stale request history migration review".into());
    }
    let prior = store.read()?;
    let prior_review = prior.review()?;
    let origin = Origin::ReviewedLegacyMigration {
        ledger_review: prior_review.clone(),
        manager_epoch: prior.manager_epoch,
        generation: prior.generation,
    };
    // Rotate authority only. The lifetime store exclusion spans both publications.
    // Failure before exclusive history creation leaves a changed review and no
    // usable request store; failure afterwards leaves provenance, never a reset.
    store.transact(|ledger| {
        if ledger.review()? != prior_review
            || ledger.leases.iter().any(|l| l.state != State::Released)
        {
            return Err("request history migration lost physical exclusion".into());
        }
        // A never-started empty ledger has no authority epoch to retire. Keep
        // it uninitialized; normal broker startup alone establishes inventory.
        if !ledger.manager_epoch.is_empty() {
            ledger.manager_epoch = resources::random_id()?;
        }
        Ok(())
    })?;
    initialize_history(store.request_directory()?, &origin)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{admit, begin, finish, fixture, reserve};
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Fixture {
        directory: PathBuf,
        store: Store,
        gate: Gate,
        worker: Token,
        caller: Caller,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "luma-request-journal-{}",
                resources::random_id().unwrap()
            ));
            resources::initialize(&directory).unwrap();
            let mut store = Store::open(&directory).unwrap();
            let (_, ledger, worker, caller) = fixture();
            store
                .transact(|current| {
                    *current = ledger;
                    Ok(())
                })
                .unwrap();
            let gate = Gate::open(&store).unwrap();
            Self {
                directory,
                store,
                gate,
                worker,
                caller,
            }
        }
        fn prepare(&mut self, nonce: u64) {
            reserve(&mut self.gate, &self.caller, &begin(&self.worker, nonce)).unwrap();
            self.gate.persist(&self.store, true).unwrap();
        }
        fn complete(&mut self, nonce: u64) {
            self.prepare(nonce);
            self.gate
                .admit(&self.caller, &admit(&self.worker, nonce, 10), 3)
                .unwrap();
            self.gate.persist(&self.store, true).unwrap();
            self.gate
                .finish(&self.caller, &finish(&self.worker, nonce, 10, 1), 4)
                .unwrap();
            self.gate.persist(&self.store, true).unwrap();
        }
        fn review(&self) -> String {
            self.gate.retention_status(&self.store).unwrap()["review"]
                .as_str()
                .unwrap()
                .into()
        }
        fn archive(&mut self) -> serde_json::Value {
            self.gate
                .archive_requests(&self.store, &self.review())
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[test]
    fn every_acknowledged_phase_is_canonical_durable_without_text_or_pid_handles() {
        let mut f = Fixture::new();
        f.caller.start = u64::MAX;
        f.prepare(1);
        let raw = tpm::private_read(&f.directory.join(FILE), MAX_BYTES).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["records"][0]["caller"]["start"], u64::MAX.to_string());
        assert_eq!(value["records"][0]["limit"], "128");
        assert!(value["records"][0].get("pin").is_none());
        assert!(value["records"][0].get("text").is_none());
        assert!(value["records"][0].get("messages").is_none());
        let opened = Gate::open(&f.store).unwrap();
        assert_eq!(opened.records[0].phase, Phase::Preparing);
        assert!(opened.records[0].pin.is_none());
        f.gate
            .admit(&f.caller, &admit(&f.worker, 1, 10), 3)
            .unwrap();
        f.gate.persist(&f.store, true).unwrap();
        assert_eq!(
            Gate::open(&f.store).unwrap().records[0].phase,
            Phase::Admitted
        );
        f.gate
            .finish(&f.caller, &finish(&f.worker, 1, 10, 1), 4)
            .unwrap();
        assert!(f.gate.records[0].pin.is_none());
        f.gate.persist(&f.store, true).unwrap();
        let receipt = f.gate.records[0].receipt();
        assert_eq!(Gate::open(&f.store).unwrap().records[0].receipt(), receipt);
        assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
    }

    #[test]
    fn restart_never_rehydrates_a_live_caller_or_releases_reserved_bytes() {
        let mut f = Fixture::new();
        f.prepare(1);
        let mut restored = Gate::open(&f.store).unwrap();
        let ledger = f.store.read().unwrap();
        assert_eq!(
            restored
                .maintain_with(&ledger, 3, |_| panic!("must not reconstruct PID from disk"))
                .unwrap(),
            vec![f.worker.clone()]
        );
        restored.persist(&f.store, true).unwrap();
        assert_eq!(
            Gate::open(&f.store).unwrap().records[0].phase,
            Phase::Draining
        );
        assert!(restored.occupied());
        assert_eq!(ledger.charged("host").unwrap(), 5000);
    }

    #[test]
    fn publication_failure_before_and_after_commit_poison_all_mutating_paths() {
        for after in [false, true] {
            let mut f = Fixture::new();
            reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).unwrap();
            assert!(f
                .gate
                .persist_with(&f.store, true, |path, bytes| {
                    if after {
                        platform::write_atomic(path, bytes, 0o600)?;
                    }
                    Err("injected lost publication acknowledgement".into())
                })
                .is_err());
            assert!(f.gate.persist(&f.store, true).is_err());
            assert!(f
                .gate
                .maintain_with(&f.store.read().unwrap(), 3, |_| Ok(true))
                .is_err());
            assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 2)).is_err());
            assert!(f.gate.archive_requests(&f.store, &"0".repeat(64)).is_err());
            assert!(f.gate.occupied());
            let restored = Gate::open(&f.store).unwrap();
            assert_eq!(restored.records.len(), usize::from(after));
            assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
        }
    }

    #[test]
    fn reviewed_hot_cut_preserves_generation_capacity_receipts_and_retired_nonces() {
        let mut f = Fixture::new();
        for nonce in 1..=MAX_RECEIPTS as u64 {
            f.complete(nonce);
        }
        assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 257)).is_err());
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let archive = f.archive();
        assert_eq!(archive["worker_resources_released"], false);
        assert_eq!(f.gate.retention.retired.len(), MAX_RECEIPTS);
        assert!(f.gate.records.is_empty());
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).is_err());
        f.gate = Gate::open(&f.store).unwrap();
        assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 256)).is_err());
        f.complete(257);
        f.archive();
        let restored = Gate::open(&f.store).unwrap();
        assert_eq!(restored.retention.retired.len(), 257);
        assert_eq!(restored.retention.archives.len(), 2);
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
    }

    #[test]
    fn stale_reviews_active_preparing_and_draining_requests_never_archive() {
        let mut f = Fixture::new();
        let empty = f.review();
        assert!(f.gate.archive_requests(&f.store, &empty).is_err());
        f.prepare(1);
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        f.gate
            .admit(&f.caller, &admit(&f.worker, 1, 10), 3)
            .unwrap();
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        f.gate
            .cancel(&f.caller, &format!("{:032x}", 1), &f.worker)
            .unwrap();
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        f.store
            .transact(|l| {
                l.revoke(&f.worker, "test")?;
                l.finish_draining(&f.worker, &BTreeMap::from([("host".into(), 25)]))
            })
            .unwrap();
        f.gate
            .maintain_with(&f.store.read().unwrap(), 4, |_| Ok(true))
            .unwrap();
        f.gate.persist(&f.store, true).unwrap();
        assert!(f.gate.archive_requests(&f.store, &empty).is_err());
        let current = f.review();
        f.store
            .transact(|l| {
                l.manager_epoch = "d".repeat(32);
                Ok(())
            })
            .unwrap();
        assert!(f.gate.archive_requests(&f.store, &current).is_err());
        f.archive();
    }

    #[test]
    fn damaged_missing_or_noncanonical_journals_are_retained_never_initialized() {
        let mut f = Fixture::new();
        f.complete(1);
        let path = f.directory.join(FILE);
        let original = fs::read(&path).unwrap();
        for damaged in [
            b"{".to_vec(),
            [original.as_slice(), b"\n"].concat(),
            b"{}".to_vec(),
        ] {
            fs::write(&path, &damaged).unwrap();
            assert!(Gate::open(&f.store).is_err());
            assert_eq!(fs::read(&path).unwrap(), damaged);
            assert!(initialize(&f.directory).is_err());
        }
        fs::remove_file(&path).unwrap();
        assert!(Gate::open(&f.store).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn malformed_phases_counts_identities_duplicates_and_extra_fields_are_denied() {
        let mut f = Fixture::new();
        f.complete(1);
        let canonical: serde_json::Value =
            serde_json::from_slice(&f.gate.bytes().unwrap()).unwrap();
        for (field, invalid) in [
            ("limit", serde_json::json!("0128")),
            ("limit", serde_json::json!(128)),
            ("output", serde_json::json!("129")),
            ("context", serde_json::json!("2049")),
            ("phase", serde_json::json!("preparing")),
            ("result_digest", serde_json::json!("x")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut changed = canonical.clone();
            changed["records"][0][field] = invalid;
            if let Ok(snapshot) = serde_json::from_value::<Snapshot>(changed) {
                assert!(decode(&serde_json::to_vec(&snapshot).unwrap()).is_err());
            }
        }
        let mut injected_handle = canonical.clone();
        injected_handle["records"][0]["pin"] = serde_json::json!(0);
        assert!(decode(&serde_json::to_vec(&injected_handle).unwrap()).is_err());
        let mut changed = canonical;
        let duplicate = changed["records"][0].clone();
        changed["records"].as_array_mut().unwrap().push(duplicate);
        let snapshot = serde_json::from_value::<Snapshot>(changed).unwrap();
        assert!(decode(&serde_json::to_vec(&snapshot).unwrap()).is_err());
    }

    #[test]
    fn unsafe_links_modes_and_oversized_state_refuse_without_replacement() {
        let f = Fixture::new();
        let path = f.directory.join(FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Gate::open(&f.store).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, f.directory.join("unexpected-link")).unwrap();
        assert!(Gate::open(&f.store).is_err());
        fs::remove_file(f.directory.join("unexpected-link")).unwrap();
        fs::rename(&path, f.directory.join("original")).unwrap();
        std::os::unix::fs::symlink("original", &path).unwrap();
        assert!(Gate::open(&f.store).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(f.directory.join("original"), &path).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(Gate::open(&f.store).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_BYTES + 1);
    }

    #[test]
    fn externally_changed_journal_poisoning_cannot_be_overwritten_by_an_exact_replay() {
        let mut f = Fixture::new();
        f.complete(1);
        fs::write(f.directory.join(FILE), b"{").unwrap();
        assert!(f.gate.persist(&f.store, true).is_err());
        assert!(f.gate.retention.poisoned);
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), b"{");
    }

    fn assert_fenced(f: &mut Fixture) {
        assert!(f.gate.occupied());
        assert!(f.gate.retention.check().is_err());
        assert!(f.gate.retention_status(&f.store).is_err());
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        assert!(f.gate.persist(&f.store, false).is_err());
        assert!(f.gate.persist(&f.store, true).is_err());
        assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 2)).is_err());
        assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
    }

    #[test]
    fn unchanged_maintenance_detects_external_hot_edits_and_restoration_does_not_revive() {
        for malformed in [false, true] {
            let mut f = Fixture::new();
            f.complete(1);
            let path = f.directory.join(FILE);
            let original = fs::read(&path).unwrap();
            let changed = if malformed {
                b"{".to_vec()
            } else {
                let mut snapshot = decode(&original).unwrap();
                snapshot.records.clear();
                serde_json::to_vec(&snapshot).unwrap()
            };
            platform::write_atomic(&path, &changed, 0o600).unwrap();
            assert!(f
                .gate
                .persist_with(&f.store, false, |_, _| panic!(
                    "unchanged cycle cannot publish"
                ))
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), changed);
            platform::write_atomic(&path, &original, 0o600).unwrap();
            assert_fenced(&mut f);
            let fresh = Gate::open(&f.store).unwrap();
            assert_eq!(fresh.records[0].phase, Phase::Completed);
            assert_eq!(fresh.records.len(), 1);
        }
    }

    #[test]
    fn successful_publication_must_read_back_the_intended_receipts_before_acknowledgement() {
        for wrong in [false, true] {
            let mut f = Fixture::new();
            let original = fs::read(f.directory.join(FILE)).unwrap();
            reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).unwrap();
            let intended = f.gate.bytes().unwrap();
            assert!(f
                .gate
                .persist_with(&f.store, true, |path, _| {
                    if wrong {
                        platform::write_atomic(path, b"{", 0o600)?;
                    }
                    Ok(())
                })
                .is_err());
            assert!(f.gate.retention.poisoned);
            assert_eq!(
                fs::read(f.directory.join(FILE)).unwrap(),
                if wrong { b"{".to_vec() } else { original }
            );
            // Even a later exact durable repair does not authorize this session.
            platform::write_atomic(&f.directory.join(FILE), &intended, 0o600).unwrap();
            assert_fenced(&mut f);
            let fresh = Gate::open(&f.store).unwrap();
            assert_eq!(fresh.records[0].phase, Phase::Preparing);
            assert!(fresh.records[0].pin.is_none());
        }
    }

    #[test]
    fn loaded_hot_custody_checks_modes_links_missing_and_oversized_state_without_overwrite() {
        for fault in [
            "mode", "setuid", "hardlink", "symlink", "missing", "size", "fifo",
        ] {
            let mut f = Fixture::new();
            f.complete(1);
            let path = f.directory.join(FILE);
            let original = fs::read(&path).unwrap();
            let saved = f.directory.join("saved-private-request");
            match fault {
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "setuid" => fs::set_permissions(&path, fs::Permissions::from_mode(0o4600)).unwrap(),
                "hardlink" => fs::hard_link(&path, &saved).unwrap(),
                "symlink" | "missing" | "fifo" => {
                    fs::rename(&path, &saved).unwrap();
                    if fault == "symlink" {
                        std::os::unix::fs::symlink(&saved, &path).unwrap();
                    } else if fault == "fifo" {
                        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                }
                "size" => OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(MAX_BYTES + 1)
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(f.gate.retention_status(&f.store).is_err(), "{fault}");
            assert!(f.gate.retention.authority_lost.get(), "{fault}");
            assert_eq!(f.gate.records.len(), 1);
            if matches!(fault, "symlink" | "fifo") {
                fs::remove_file(&path).unwrap();
            }
            if matches!(fault, "symlink" | "missing" | "fifo") {
                fs::rename(&saved, &path).unwrap();
            } else if fault == "hardlink" {
                fs::remove_file(&saved).unwrap();
            }
            platform::write_atomic(&path, &original, 0o600).unwrap();
            assert_fenced(&mut f);
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }

    #[test]
    fn unchanged_cycles_validate_shared_exclusion_and_publication_rechecks_it_after_writing() {
        for during_publication in [false, true] {
            let mut f = Fixture::new();
            let lock = f.directory.join("ledger.lock");
            let saved = f.directory.join("saved-private-lock");
            if during_publication {
                reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).unwrap();
                assert!(f
                    .gate
                    .persist_with(&f.store, true, |path, bytes| {
                        platform::write_atomic(path, bytes, 0o600)?;
                        fs::rename(&lock, &saved)?;
                        platform::write_atomic(&lock, b"", 0o600)
                    })
                    .is_err());
            } else {
                fs::rename(&lock, &saved).unwrap();
                platform::write_atomic(&lock, b"", 0o600).unwrap();
                assert!(f.gate.persist(&f.store, false).is_err());
            }
            assert!(f.gate.retention.poisoned);
            assert!(f.gate.occupied());
            fs::remove_file(&lock).unwrap();
            fs::rename(&saved, &lock).unwrap();
            assert!(f.gate.persist(&f.store, false).is_err());
            assert!(f.store.read().is_err());
            let ledger: resources::Ledger =
                serde_json::from_slice(&fs::read(f.directory.join("ledger.json")).unwrap())
                    .unwrap();
            assert_eq!(ledger.charged("host").unwrap(), 5000);
        }
    }

    fn export_request(f: &Fixture) -> super::super::super::history::Request {
        let reference = &f.gate.retention.archives[0];
        super::super::super::history::Request {
            schema_version: 1,
            request_id: "export".into(),
            caller: 0,
            deadline: 4000,
            action: "resource-request-export".into(),
            batch: reference.batch,
            sha256: reference.sha256.clone(),
            offset: 0,
        }
    }

    #[test]
    fn status_recovery_and_export_observe_hot_damage_and_fence_restored_authority() {
        for path in ["status", "recovery", "export"] {
            let mut f = Fixture::new();
            f.complete(1);
            f.archive();
            let request = export_request(&f);
            let hot = f.directory.join(FILE);
            let original = fs::read(&hot).unwrap();
            platform::write_atomic(&hot, b"{", 0o600).unwrap();
            assert!(match path {
                "status" => f.gate.retention_status(&f.store).map(|_| ()),
                "recovery" => f.gate.stage_recovery_status(&f.store).map(|_| ()),
                "export" => f.gate.export_chunk(&f.store, &request).map(|_| ()),
                _ => unreachable!(),
            }
            .is_err());
            assert_eq!(fs::read(&hot).unwrap(), b"{");
            platform::write_atomic(&hot, &original, 0o600).unwrap();
            assert_fenced(&mut f);
            assert!(f.gate.export_chunk(&f.store, &request).is_err());
            assert_eq!(f.gate.retention.retired.len(), 1);
            assert!(f.gate.records.is_empty());
        }
    }

    #[test]
    fn export_custody_damage_fences_but_invalid_offsets_and_references_do_not() {
        for fault in ["bytes", "missing", "mode", "hardlink"] {
            let mut f = Fixture::new();
            f.complete(1);
            f.archive();
            let request = export_request(&f);
            let path = f.directory.join(f.gate.retention.archives[0].name());
            let original = fs::read(&path).unwrap();
            let mut invalid = export_request(&f);
            invalid.offset = 1;
            assert!(f.gate.export_chunk(&f.store, &invalid).is_err());
            invalid.offset = 0;
            invalid.sha256 = "0".repeat(64);
            assert!(f.gate.export_chunk(&f.store, &invalid).is_err());
            assert!(f.gate.retention.check().is_ok());
            assert!(f.gate.export_chunk(&f.store, &request).is_ok());
            match fault {
                "bytes" => fs::write(&path, b"{").unwrap(),
                "missing" => fs::remove_file(&path).unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "hardlink" => {
                    fs::hard_link(&path, f.directory.join("saved-private-archive")).unwrap()
                }
                _ => unreachable!(),
            }
            assert!(f.gate.export_chunk(&f.store, &request).is_err());
            assert!(f.gate.retention.authority_lost.get());
            platform::write_atomic(&path, &original, 0o600).unwrap();
            assert!(f.gate.export_chunk(&f.store, &request).is_err());
            assert_fenced(&mut f);
            assert_eq!(f.gate.retention.retired.len(), 1);
        }
    }

    #[test]
    fn orphan_publication_preserves_hot_authority_and_exact_reviewed_retry_is_safe() {
        let mut f = Fixture::new();
        f.complete(1);
        let bytes = f.gate.bytes().unwrap();
        let reference = Archive {
            batch: 1,
            sha256: digest(&bytes),
        };
        let path = f.directory.join(reference.name());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        f.gate = Gate::open(&f.store).unwrap();
        assert_eq!(f.gate.records.len(), 1);
        assert!(f.gate.retention.retired.is_empty());
        f.archive();
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert_eq!(Gate::open(&f.store).unwrap().retention.retired.len(), 1);
    }

    #[test]
    fn incomplete_archive_stage_refuses_and_never_cuts_hot_receipts() {
        let mut f = Fixture::new();
        f.complete(1);
        let bytes = f.gate.bytes().unwrap();
        let reference = Archive {
            batch: 1,
            sha256: digest(&bytes),
        };
        let stage = f
            .directory
            .join(format!(".requests-stage-{}", reference.name()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .unwrap();
        file.write_all(b"{").unwrap();
        file.sync_all().unwrap();
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        assert!(f.gate.retention.poisoned);
        let restored = Gate::open(&f.store).unwrap();
        assert_eq!(restored.records.len(), 1);
        assert!(restored.retention.archives.is_empty());
        assert_eq!(fs::read(stage).unwrap(), b"{");
    }

    #[test]
    fn lost_hot_cut_acknowledgement_reconstructs_only_the_durable_side_of_the_cut() {
        for after in [false, true] {
            let mut f = Fixture::new();
            f.complete(1);
            let review = f.review();
            assert!(f
                .gate
                .archive_with(&f.store, &review, |gate, store| {
                    gate.persist_with(store, true, |path, bytes| {
                        if after {
                            platform::write_atomic(path, bytes, 0o600)?;
                        }
                        Err("injected uncertain archival cut".into())
                    })
                })
                .is_err());
            assert!(f.gate.retention.poisoned);
            assert!(f.gate.occupied());
            f.gate = Gate::open(&f.store).unwrap();
            assert_eq!(f.gate.records.len(), usize::from(!after));
            assert_eq!(f.gate.retention.archives.len(), usize::from(after));
            assert_eq!(f.gate.retention.retired.len(), usize::from(after));
            if !after {
                f.archive();
            }
            assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).is_err());
            assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
        }
    }

    #[test]
    fn legacy_origin_is_durable_and_does_not_invent_pre_upgrade_request_receipts() {
        let f = Fixture::new();
        fs::remove_file(f.directory.join(FILE)).unwrap();
        let ledger = f.store.read().unwrap();
        let origin = Origin::ReviewedLegacyMigration {
            ledger_review: ledger.review().unwrap(),
            manager_epoch: ledger.manager_epoch.clone(),
            generation: ledger.generation,
        };
        initialize_with_origin(&f.directory, &origin).unwrap();
        let restored = Gate::open(&f.store).unwrap();
        assert!(restored.records.is_empty());
        assert!(restored.retention.archives.is_empty());
        assert!(restored.retention.origin == origin);
        assert!(initialize_with_origin(&f.directory, &origin).is_err());
        assert_eq!(f.store.read().unwrap().generation, ledger.generation);
        assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
    }

    #[test]
    fn corrupt_missing_or_reordered_archive_chain_refuses() {
        let mut f = Fixture::new();
        f.complete(1);
        f.archive();
        f.complete(2);
        f.archive();
        let path = f.directory.join(f.gate.retention.archives[0].name());
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, b"{").unwrap();
        assert!(Gate::open(&f.store).is_err());
        fs::remove_file(&path).unwrap();
        assert!(Gate::open(&f.store).is_err());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        assert!(Gate::open(&f.store).is_ok());
        f.gate.retention.archives.swap(0, 1);
        fs::write(f.directory.join(FILE), f.gate.bytes().unwrap()).unwrap();
        assert!(Gate::open(&f.store).is_err());
    }

    #[test]
    fn bounded_archive_inventory_never_evicts_old_receipts() {
        let mut f = Fixture::new();
        for nonce in 1..=MAX_ARCHIVES as u64 {
            f.complete(nonce);
            f.archive();
        }
        f.complete(MAX_ARCHIVES as u64 + 1);
        let before = fs::read(f.directory.join(FILE)).unwrap();
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), before);
        let restored = Gate::open(&f.store).unwrap();
        assert_eq!(restored.retention.archives.len(), MAX_ARCHIVES);
        assert_eq!(restored.retention.retired.len(), MAX_ARCHIVES);
        assert!(
            serde_json::to_vec(&restored.retention_status(&f.store).unwrap())
                .unwrap()
                .len()
                < 16000
        );
    }

    fn partial_stage(f: &Fixture, bytes: &[u8]) -> std::path::PathBuf {
        let current = f.gate.bytes().unwrap();
        let reference = Archive {
            batch: f.gate.retention.archives.len() as u64 + 1,
            sha256: digest(&current),
        };
        let path = f
            .directory
            .join(format!(".requests-stage-{}", reference.name()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        path
    }
    fn release_worker(f: &mut Fixture) {
        f.store
            .transact(|l| {
                l.revoke(&f.worker, "test")?;
                l.finish_draining(&f.worker, &BTreeMap::from([("host".into(), 25)]))
            })
            .unwrap();
    }
    fn recovery_review(f: &Fixture) -> String {
        f.gate.stage_recovery_status(&f.store).unwrap()["review"]
            .as_str()
            .unwrap()
            .into()
    }

    #[test]
    fn referenced_archive_export_is_exact_bounded_and_never_releases_resources() {
        let mut f = Fixture::new();
        for nonce in 1..=5 {
            f.complete(nonce);
        }
        let bytes = f.gate.bytes().unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let archive = f.archive();
        let hash = archive["archive"]["sha256"].as_str().unwrap();
        let mut r = super::super::super::history::Request {
            schema_version: 1,
            request_id: "export".into(),
            caller: 0,
            deadline: 4000,
            action: "resource-request-export".into(),
            batch: 1,
            sha256: hash.into(),
            offset: 0,
        };
        let mut exported = Vec::new();
        loop {
            let c = f.gate.export_chunk(&f.store, &r).unwrap();
            assert!(c.data.len() <= 2048);
            assert!(!c.worker_resources_released);
            exported.extend_from_slice(c.data.as_bytes());
            r.offset = c.next_offset;
            if r.offset == c.total_bytes {
                break;
            }
        }
        assert_eq!(exported, bytes);
        assert!(f.gate.export_chunk(&f.store, &r).is_err());
        r.offset = 1;
        assert!(f.gate.export_chunk(&f.store, &r).is_err());
        r.offset = 0;
        r.sha256 = "0".repeat(64);
        assert!(f.gate.export_chunk(&f.store, &r).is_err());
        r.sha256 = hash.into();
        r.batch = 2;
        assert!(f.gate.export_chunk(&f.store, &r).is_err());
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
    }

    #[test]
    fn partial_stage_recovery_retains_inode_bytes_hot_history_and_physical_receipts() {
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        let stage = partial_stage(&f, b"{");
        let inode = fs::metadata(&stage).unwrap().ino();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let hot = fs::read(f.directory.join(FILE)).unwrap();
        let review = recovery_review(&f);
        let result = f.gate.recover_stage(&f.store, &review).unwrap();
        let retained = f.directory.join(result["retained"].as_str().unwrap());
        assert_eq!(fs::read(&retained).unwrap(), b"{");
        assert_eq!(fs::metadata(&retained).unwrap().ino(), inode);
        assert!(!stage.exists());
        assert_eq!(result["evidence_deleted"], false);
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        assert!(f.gate.recover_stage(&f.store, &review).is_err());
        f.gate = Gate::open(&f.store).unwrap();
        assert!(f.gate.retention.retired.is_empty());
        f.archive();
        assert_eq!(f.gate.retention.retired.len(), 1);
        assert_eq!(fs::read(retained).unwrap(), b"{");
    }

    #[test]
    fn older_request_stages_survive_journal_advance_hot_cut_and_restart_without_nonce_revival() {
        for after_cut in [false, true] {
            let mut f = Fixture::new();
            f.complete(1);
            let stage = partial_stage(&f, b"{\"interrupted\":");
            let original = stage_identity(&stage).unwrap();
            f.complete(2);
            if after_cut {
                f.archive();
            }
            release_worker(&mut f);
            f.gate = Gate::open(&f.store).unwrap();
            let hot = fs::read(f.directory.join(FILE)).unwrap();
            let physical = fs::read(f.directory.join("ledger.json")).unwrap();
            let retired = f.gate.retention.retired.clone();
            let references = serde_json::to_vec(&f.gate.retention.archives).unwrap();
            let result = f
                .gate
                .recover_stage(&f.store, &recovery_review(&f))
                .unwrap();
            let retained = f.directory.join(result["retained"].as_str().unwrap());
            let observed = stage_identity(&retained).unwrap();
            assert_eq!(observed.inode, original.inode);
            assert_eq!(observed.device, original.device);
            assert_eq!(observed.sha256, original.sha256);
            assert_eq!(fs::read(retained).unwrap(), b"{\"interrupted\":");
            assert!(!stage.exists());
            assert_eq!(result["worker_resources_released"], false);
            assert_eq!(result["evidence_deleted"], false);
            assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
            assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
            f.gate = Gate::open(&f.store).unwrap();
            assert_eq!(f.gate.retention.retired, retired);
            assert_eq!(
                serde_json::to_vec(&f.gate.retention.archives).unwrap(),
                references
            );
            assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 25);
            if after_cut {
                for nonce in [1, 2] {
                    assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, nonce)).is_err());
                }
            } else {
                assert_eq!(f.gate.records.len(), 2);
                f.archive();
                assert_eq!(f.gate.retention.retired.len(), 2);
            }
        }
    }

    #[test]
    fn exhausted_archive_chain_with_empty_hot_journal_still_preserves_older_evidence() {
        let mut f = Fixture::new();
        f.complete(1);
        let stage = partial_stage(&f, b"{");
        f.complete(2);
        f.archive();
        for nonce in 3..=MAX_ARCHIVES as u64 + 1 {
            f.complete(nonce);
            f.archive();
        }
        release_worker(&mut f);
        f.gate = Gate::open(&f.store).unwrap();
        assert!(f.gate.records.is_empty());
        assert_eq!(f.gate.retention.archives.len(), MAX_ARCHIVES);
        assert_eq!(f.gate.retention.retired.len(), MAX_ARCHIVES + 1);
        let hot = fs::read(f.directory.join(FILE)).unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let result = f
            .gate
            .recover_stage(&f.store, &recovery_review(&f))
            .unwrap();
        assert!(!stage.exists());
        assert_eq!(
            fs::read(f.directory.join(result["retained"].as_str().unwrap())).unwrap(),
            b"{"
        );
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        assert_eq!(f.gate.retention.archives.len(), MAX_ARCHIVES);
        assert_eq!(
            Gate::open(&f.store).unwrap().retention.retired.len(),
            MAX_ARCHIVES + 1
        );
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
    }

    #[test]
    fn request_recovery_reviews_bind_both_durable_authority_inodes_and_unpublished_state() {
        for file in [FILE, "ledger.json"] {
            let mut f = Fixture::new();
            f.complete(1);
            release_worker(&mut f);
            let stage = partial_stage(&f, b"{");
            let review = recovery_review(&f);
            let path = f.directory.join(file);
            let before = fs::read(&path).unwrap();
            let inode = fs::metadata(&path).unwrap().ino();
            platform::write_atomic(&path, &before, 0o600).unwrap();
            assert_ne!(fs::metadata(&path).unwrap().ino(), inode);
            assert!(f.gate.recover_stage(&f.store, &review).is_err());
            assert!(stage.exists());
            assert!(!f.gate.retention.poisoned);
            assert_eq!(fs::read(&path).unwrap(), before);
            f.gate
                .recover_stage(&f.store, &recovery_review(&f))
                .unwrap();
        }
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        let stage = partial_stage(&f, b"{");
        let review = recovery_review(&f);
        let original = f.gate.records[0].result_digest.clone();
        f.gate.records[0].result_digest = Some("e".repeat(64));
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        assert!(f.gate.recover_stage(&f.store, &review).is_err());
        assert!(stage.exists());
        assert!(!f.gate.retention.poisoned);
        f.gate.records[0].result_digest = original;
        f.gate.recover_stage(&f.store, &review).unwrap();
    }

    #[test]
    fn recovery_selects_one_stable_candidate_and_preserves_complete_older_stages() {
        let mut f = Fixture::new();
        f.complete(1);
        let complete = partial_stage(&f, &f.gate.bytes().unwrap());
        let complete_bytes = fs::read(&complete).unwrap();
        f.complete(2);
        let first = partial_stage(&f, b"first");
        f.complete(3);
        let second = partial_stage(&f, b"second");
        release_worker(&mut f);
        let mut expected = vec![first, second];
        expected.sort();
        for (index, source) in expected.iter().enumerate() {
            let status = f.gate.stage_recovery_status(&f.store).unwrap();
            assert_eq!(
                status["stage"],
                source.file_name().unwrap().to_str().unwrap()
            );
            assert_eq!(status, f.gate.stage_recovery_status(&f.store).unwrap());
            let original = fs::read(source).unwrap();
            let result = f
                .gate
                .recover_stage(&f.store, status["review"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                fs::read(f.directory.join(result["retained"].as_str().unwrap())).unwrap(),
                original
            );
            assert!(!source.exists());
            if index == 0 {
                assert!(expected[1].exists());
            }
            assert_eq!(fs::read(&complete).unwrap(), complete_bytes);
        }
        assert_eq!(
            f.gate.stage_recovery_status(&f.store).unwrap()["recoverable"],
            false
        );
        assert_eq!(f.gate.records.len(), 3);
        assert!(f.gate.retention.retired.is_empty());
    }

    #[test]
    fn unknown_noncanonical_and_future_request_stage_names_refuse_without_mutation() {
        for name in [
            ".requests-stage-unknown".into(),
            format!(".requests-stage-requests-archive-0-{}.json", "a".repeat(64)),
            format!(
                ".requests-stage-requests-archive-01-{}.json",
                "a".repeat(64)
            ),
            format!(".requests-stage-requests-archive-2-{}.json", "a".repeat(64)),
            format!(".requests-stage-requests-archive-1-{}.json", "A".repeat(64)),
            format!(
                ".requests-stage-requests-archive-{}-{}.json",
                u64::MAX,
                "a".repeat(64)
            ),
        ] {
            let mut f = Fixture::new();
            f.complete(1);
            release_worker(&mut f);
            let stage = partial_stage(&f, b"{");
            let review = recovery_review(&f);
            let unknown = f.directory.join(name);
            fs::rename(&stage, &unknown).unwrap();
            let hot = fs::read(f.directory.join(FILE)).unwrap();
            let physical = fs::read(f.directory.join("ledger.json")).unwrap();
            assert!(f.gate.stage_recovery_status(&f.store).is_err());
            assert!(f.gate.recover_stage(&f.store, &review).is_err());
            assert_eq!(fs::read(unknown).unwrap(), b"{");
            assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
            assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
            assert!(!f.gate.retention.poisoned);
        }
        assert_eq!(
            Archive::stage_reference(&format!(
                ".requests-stage-requests-archive-{}-{}.json",
                u64::MAX,
                "a".repeat(64)
            ))
            .unwrap()
            .batch,
            u64::MAX
        );
    }

    #[test]
    fn stage_recovery_reviews_bind_bytes_inode_and_physical_generation() {
        for change in 0..3 {
            let mut f = Fixture::new();
            f.complete(1);
            release_worker(&mut f);
            let stage = partial_stage(&f, b"{");
            let review = recovery_review(&f);
            match change {
                0 => fs::write(&stage, b"changed").unwrap(),
                1 => {
                    fs::rename(&stage, f.directory.join("preserved-test-stage")).unwrap();
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&stage)
                        .unwrap();
                    file.write_all(b"{").unwrap();
                }
                _ => f
                    .store
                    .transact(|l| {
                        l.manager_epoch = "d".repeat(32);
                        Ok(())
                    })
                    .unwrap(),
            }
            assert!(f.gate.recover_stage(&f.store, &review).is_err());
            assert!(stage.exists());
            assert!(!f.gate.retention.poisoned);
        }
    }

    #[test]
    fn stage_recovery_never_repairs_a_complete_stage_or_outstanding_worker() {
        let mut f = Fixture::new();
        f.complete(1);
        let bytes = f.gate.bytes().unwrap();
        let stage = partial_stage(&f, &bytes);
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        release_worker(&mut f);
        assert_eq!(
            f.gate.stage_recovery_status(&f.store).unwrap()["recoverable"],
            false
        );
        assert!(f.gate.recover_stage(&f.store, &"0".repeat(64)).is_err());
        assert_eq!(fs::read(&stage).unwrap(), bytes);
        f.archive();
        assert!(!stage.exists());
    }

    #[test]
    fn recovery_lost_ack_before_or_after_rename_poison_and_restart_preserves_both_outcomes() {
        for after in [false, true] {
            let mut f = Fixture::new();
            f.complete(1);
            release_worker(&mut f);
            let stage = partial_stage(&f, b"{");
            let review = recovery_review(&f);
            assert!(f
                .gate
                .recover_stage_with(&f.store, &review, |dir, source, destination, identity| {
                    if after {
                        preserve_stage(dir, source, destination, identity)?;
                    }
                    Err("injected stage preservation lost acknowledgement".into())
                })
                .is_err());
            assert!(f.gate.retention.poisoned);
            assert!(f.gate.recover_stage(&f.store, &review).is_err());
            f.gate = Gate::open(&f.store).unwrap();
            assert_eq!(stage.exists(), !after);
            assert_eq!(
                f.gate.stage_recovery_status(&f.store).unwrap()["recoverable"],
                !after
            );
            if !after {
                f.gate.recover_stage(&f.store, &review).unwrap();
            }
            f.archive();
            assert_eq!(f.gate.retention.retired.len(), 1);
        }
    }

    #[test]
    fn unsafe_recovery_stage_links_and_modes_never_move_or_overwrite_bytes() {
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        let stage = partial_stage(&f, b"{");
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&stage, f.directory.join("unsafe-stage-link")).unwrap();
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        fs::remove_file(f.directory.join("unsafe-stage-link")).unwrap();
        fs::rename(&stage, f.directory.join("original-stage")).unwrap();
        std::os::unix::fs::symlink("original-stage", &stage).unwrap();
        assert!(f.gate.stage_recovery_status(&f.store).is_err());
        assert_eq!(fs::read(f.directory.join("original-stage")).unwrap(), b"{");
    }

    #[test]
    fn damaged_retained_incidents_refuse_restart_without_deleting_evidence() {
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        partial_stage(&f, b"{");
        let review = recovery_review(&f);
        let result = f.gate.recover_stage(&f.store, &review).unwrap();
        let retained = f.directory.join(result["retained"].as_str().unwrap());
        fs::write(&retained, b"modified").unwrap();
        assert!(Gate::open(&f.store).is_err());
        assert_eq!(fs::read(retained).unwrap(), b"modified");
    }

    #[test]
    fn retained_incidents_count_toward_the_archive_limit_without_eviction() {
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        for index in 0..MAX_FILES - 1 {
            let name = format!(".requests-retained-{}-{index:064x}.json", digest(b"{"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(f.directory.join(name))
                .unwrap();
            file.write_all(b"{").unwrap();
        }
        partial_stage(&f, b"{");
        let review = recovery_review(&f);
        f.gate.recover_stage(&f.store, &review).unwrap();
        let hot = fs::read(f.directory.join(FILE)).unwrap();
        assert!(f.gate.archive_requests(&f.store, &f.review()).is_err());
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
        assert_eq!(fs::read_dir(&f.directory).unwrap().count(), MAX_FILES + 3);
        f.gate = Gate::open(&f.store).unwrap();
        assert!(f.gate.retention.retired.is_empty());
    }

    #[test]
    fn trusted_recovery_observation_failure_before_and_after_move_poison_without_history_loss() {
        for fail_at in [1, 2] {
            let mut f = Fixture::new();
            f.complete(1);
            release_worker(&mut f);
            let stage = partial_stage(&f, b"{");
            let review = recovery_review(&f);
            let mut calls = 0;
            let hot = fs::read(f.directory.join(FILE)).unwrap();
            assert!(f
                .gate
                .recover_stage_checked(&f.store, &review, || {
                    calls += 1;
                    if calls == fail_at {
                        return Err("injected trusted empty-group observation failure".into());
                    }
                    Ok(())
                })
                .is_err());
            assert_eq!(calls, fail_at);
            assert!(f.gate.retention.poisoned);
            assert_eq!(stage.exists(), fail_at == 1);
            assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
            assert_eq!(Gate::open(&f.store).unwrap().records.len(), 1);
        }
    }

    #[test]
    fn stage_preservation_never_replaces_an_existing_destination() {
        let mut f = Fixture::new();
        f.complete(1);
        release_worker(&mut f);
        let stage = partial_stage(&f, b"{");
        let identity = stage_identity(&stage).unwrap();
        let collision = f.directory.join("preserved-collision");
        fs::write(&collision, b"prior evidence").unwrap();
        assert!(preserve_stage(
            &f.directory,
            stage.file_name().unwrap().to_str().unwrap(),
            "preserved-collision",
            &identity
        )
        .is_err());
        assert_eq!(fs::read(stage).unwrap(), b"{");
        assert_eq!(fs::read(collision).unwrap(), b"prior evidence");
    }

    #[test]
    fn missing_history_migration_denies_outstanding_state_and_retained_artifacts() {
        let mut f = Fixture::new();
        assert!(migration_review(&f.store).is_err());
        fs::remove_file(f.directory.join(FILE)).unwrap();
        assert!(migration_review(&f.store).is_err());
        f.store
            .transact(|l| {
                l.revoke(&f.worker, "test")?;
                l.finish_draining(&f.worker, &BTreeMap::from([("host".into(), 25)]))
            })
            .unwrap();
        let review = migration_review(&f.store).unwrap();
        let stage = f.directory.join(".requests-stage-interrupted");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .unwrap();
        file.write_all(b"{").unwrap();
        assert!(migration_review(&f.store).is_err());
        assert_eq!(fs::read(stage).unwrap(), b"{");
        assert!(!review.is_empty());
    }

    #[test]
    fn reviewed_legacy_migration_rotates_only_epoch_and_retains_physical_history() {
        let mut f = Fixture::new();
        fs::remove_file(f.directory.join(FILE)).unwrap();
        let active_bytes = fs::read(f.directory.join("ledger.json")).unwrap();
        assert!(migrate_store_with(&mut f.store, &"0".repeat(64), initialize_with_origin).is_err());
        assert_eq!(
            fs::read(f.directory.join("ledger.json")).unwrap(),
            active_bytes
        );
        f.store
            .transact(|l| {
                l.revoke(&f.worker, "test")?;
                l.finish_draining(&f.worker, &BTreeMap::from([("host".into(), 25)]))
            })
            .unwrap();
        let review = migration_review(&f.store).unwrap();
        let mut prior = f.store.read().unwrap();
        assert!(migrate_store_with(&mut f.store, &"0".repeat(64), initialize_with_origin).is_err());
        migrate_store_with(&mut f.store, &review, initialize_with_origin).unwrap();
        let current = f.store.read().unwrap();
        assert_ne!(prior.manager_epoch, current.manager_epoch);
        prior.manager_epoch = current.manager_epoch.clone();
        assert_eq!(prior, current);
        let gate = Gate::open(&f.store).unwrap();
        assert!(gate.records.is_empty());
        assert!(matches!(
            gate.retention.origin,
            Origin::ReviewedLegacyMigration { .. }
        ));
        assert!(migrate_store_with(&mut f.store, &review, initialize_with_origin).is_err());
    }

    #[test]
    fn legacy_virgin_ledger_migration_does_not_invent_physical_inventory_or_authority() {
        let mut f = Fixture::new();
        fs::remove_file(f.directory.join(FILE)).unwrap();
        f.store
            .transact(|ledger| {
                *ledger = resources::Ledger::fresh_for_test();
                Ok(())
            })
            .unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let review = migration_review(&f.store).unwrap();
        migrate_store_with(&mut f.store, &review, initialize_with_origin).unwrap();
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        let gate = Gate::open(&f.store).unwrap();
        assert!(gate.records.is_empty());
        assert!(matches!(gate.retention.origin,
            Origin::ReviewedLegacyMigration { generation: 0, ref manager_epoch, .. } if manager_epoch.is_empty()));
    }

    #[test]
    fn interrupted_legacy_history_creation_never_silently_resets_or_reuses_the_review() {
        for after in [false, true] {
            let mut f = Fixture::new();
            fs::remove_file(f.directory.join(FILE)).unwrap();
            f.store
                .transact(|l| {
                    l.revoke(&f.worker, "test")?;
                    l.finish_draining(&f.worker, &BTreeMap::from([("host".into(), 25)]))
                })
                .unwrap();
            let review = migration_review(&f.store).unwrap();
            assert!(
                migrate_store_with(&mut f.store, &review, |directory, origin| {
                    if after {
                        initialize_with_origin(directory, origin)?;
                    }
                    Err("injected history creation acknowledgement loss".into())
                })
                .is_err()
            );
            assert!(migrate_store_with(&mut f.store, &review, initialize_with_origin).is_err());
            assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 25);
            if after {
                assert!(Gate::open(&f.store).unwrap().records.is_empty());
                assert!(migration_review(&f.store).is_err());
            } else {
                assert!(Gate::open(&f.store).is_err());
                let fresh = migration_review(&f.store).unwrap();
                assert_ne!(review, fresh);
                migrate_store_with(&mut f.store, &fresh, initialize_with_origin).unwrap();
            }
        }
    }

    #[test]
    fn request_maintenance_envelopes_are_root_only_and_reject_unrelated_fields() {
        let time = now().unwrap();
        let mut request = super::super::super::request("resource-request-status").unwrap();
        super::super::super::validate(&request, 0, time).unwrap();
        request.action = "resource-request-archive".into();
        assert!(super::super::super::validate(&request, 0, time).is_err());
        request.review = Some("a".repeat(64));
        super::super::super::validate(&request, 0, time).unwrap();
        for uid in [989, 990] {
            request.caller = uid;
            assert!(super::super::super::validate(&request, uid, time).is_err());
        }
        request.caller = 0;
        request.profile = Some("arbitrary".into());
        assert!(super::super::super::validate(&request, 0, time).is_err());
        request.profile = None;
        request.action = "resource-request-recover".into();
        super::super::super::validate(&request, 0, time).unwrap();
        request.action = "resource-request-recovery-status".into();
        assert!(super::super::super::validate(&request, 0, time).is_err());
        request.review = None;
        super::super::super::validate(&request, 0, time).unwrap();
        for uid in [989, 990, 1000] {
            request.caller = uid;
            assert!(super::super::super::validate(&request, uid, time).is_err());
        }
    }

    #[test]
    fn directory_inspection_is_bounded_even_for_unrelated_private_files() {
        let f = Fixture::new();
        for index in 0..MAX_DIRECTORY_ENTRIES {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(f.directory.join(format!("unrelated-{index}")))
                .unwrap();
        }
        assert!(Gate::open(&f.store).is_err());
        assert_eq!(
            fs::read_dir(&f.directory).unwrap().count(),
            MAX_DIRECTORY_ENTRIES + 3
        );
    }

    #[test]
    fn input_binding_is_durable_and_changed_preparing_replay_never_changes_state() {
        let mut f = Fixture::new();
        f.prepare(1);
        let hot = fs::read(f.directory.join(FILE)).unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let opened = Gate::open(&f.store).unwrap();
        assert_eq!(
            opened.records[0].input_digest.as_deref(),
            Some("e".repeat(64).as_str())
        );
        assert_eq!(opened.records[0].receipt()["input_digest"], "e".repeat(64));
        let mut changed = begin(&f.worker, 1);
        if let Message::Begin { input_digest, .. } = &mut changed {
            *input_digest = "f".repeat(64);
        }
        assert!(reserve(&mut f.gate, &f.caller, &changed).is_err());
        f.gate.persist(&f.store, true).unwrap();
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), hot);
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
    }

    #[test]
    fn reference_uid_is_durable_but_restart_never_reconstructs_its_caller_handle() {
        let mut f = Fixture::new();
        f.caller.uid = 990;
        f.prepare(1);
        let raw = fs::read(f.directory.join(FILE)).unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let mut restored = Gate::open(&f.store).unwrap();
        assert_eq!(restored.bytes().unwrap(), raw);
        assert_eq!(restored.records[0].caller.uid, 990);
        assert!(restored.records[0].pin.is_none());
        let mut root = f.caller.clone();
        root.uid = 0;
        assert!(restored.admit(&root, &admit(&f.worker, 1, 10), 3).is_err());
        assert_eq!(
            restored
                .maintain_with(&f.store.read().unwrap(), 3, |_| panic!(
                    "restart may not recover a PID handle"
                ))
                .unwrap(),
            vec![f.worker.clone()]
        );
        restored.persist(&f.store, true).unwrap();
        assert_eq!(restored.records[0].phase, Phase::Draining);
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
    }

    #[test]
    fn unsupported_or_unbound_reference_uid_refuses_without_rewriting_evidence() {
        let mut f = Fixture::new();
        f.complete(1);
        let root_bytes = f.gate.bytes().unwrap();
        assert!(!String::from_utf8(root_bytes.clone())
            .unwrap()
            .contains("\"uid\""));
        for uid in [989, 988, 1000] {
            let mut malformed: Snapshot = serde_json::from_slice(&root_bytes).unwrap();
            malformed.records[0].caller.uid = uid;
            let malformed = serde_json::to_vec(&malformed).unwrap();
            fs::write(f.directory.join(FILE), &malformed).unwrap();
            assert!(Gate::open(&f.store).is_err());
            assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), malformed);
        }
        let mut malformed: Snapshot = serde_json::from_slice(&root_bytes).unwrap();
        malformed.records[0].caller.uid = 990;
        malformed.records[0].input_digest = None;
        let malformed = serde_json::to_vec(&malformed).unwrap();
        fs::write(f.directory.join(FILE), &malformed).unwrap();
        assert!(Gate::open(&f.store).is_err());
        assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), malformed);
        fs::write(f.directory.join(FILE), &root_bytes).unwrap();
        assert_eq!(Gate::open(&f.store).unwrap().bytes().unwrap(), root_bytes);
    }

    #[test]
    fn older_unbound_receipts_remain_canonical_fenced_and_cannot_be_blessed_by_replay() {
        for admitted in [false, true] {
            let mut f = Fixture::new();
            f.prepare(1);
            if admitted {
                f.gate
                    .admit(&f.caller, &admit(&f.worker, 1, 10), 3)
                    .unwrap();
            }
            // Construct the actual old canonical wire bytes: the optional new
            // field is omitted, not represented by a fabricated digest/null.
            f.gate.records[0].input_digest = None;
            f.gate.persist(&f.store, true).unwrap();
            let legacy = fs::read(f.directory.join(FILE)).unwrap();
            assert!(!String::from_utf8(legacy.clone())
                .unwrap()
                .contains("input_digest"));
            let mut restored = Gate::open(&f.store).unwrap();
            assert_eq!(restored.bytes().unwrap(), legacy);
            assert_eq!(
                restored.records[0].receipt()["input_digest"],
                serde_json::Value::Null
            );
            assert!(reserve(&mut restored, &f.caller, &begin(&f.worker, 1)).is_err());
            assert!(restored
                .admit(&f.caller, &admit(&f.worker, 1, 10), 4)
                .is_err());
            assert!(restored
                .finish(&f.caller, &finish(&f.worker, 1, 10, 1), 4)
                .is_err());
            assert_eq!(restored.bytes().unwrap(), legacy);
            let status = restored.retention_status(&f.store).unwrap();
            assert_eq!(status["legacy_unbound_hot_receipts"], 1);
            assert_eq!(status["input_bound_hot_receipts"], 0);
            let ledger = f.store.read().unwrap();
            assert_eq!(
                restored
                    .maintain_with(&ledger, 4, |_| panic!("no saved PID may be revived"))
                    .unwrap(),
                vec![f.worker.clone()]
            );
            restored.persist(&f.store, true).unwrap();
            assert_eq!(restored.records[0].phase, Phase::Draining);
            assert_eq!(f.store.read().unwrap().charged("host").unwrap(), 5000);
        }
    }

    #[test]
    fn older_terminal_archive_bytes_and_retired_nonce_fences_survive_input_upgrade() {
        let mut f = Fixture::new();
        f.complete(1);
        f.gate.records[0].input_digest = None;
        f.gate.persist(&f.store, true).unwrap();
        let legacy = f.gate.bytes().unwrap();
        let physical = fs::read(f.directory.join("ledger.json")).unwrap();
        let archived = f.archive();
        let reference = f.gate.retention.archives[0].clone();
        assert_eq!(
            fs::read(f.directory.join(reference.name())).unwrap(),
            legacy
        );
        f.gate = Gate::open(&f.store).unwrap();
        assert!(reserve(&mut f.gate, &f.caller, &begin(&f.worker, 1)).is_err());
        assert_eq!(fs::read(f.directory.join("ledger.json")).unwrap(), physical);
        assert_eq!(archived["worker_resources_released"], false);
    }

    #[test]
    fn malformed_durable_input_bindings_refuse_without_rewriting_history() {
        let mut f = Fixture::new();
        f.complete(1);
        let baseline: serde_json::Value = serde_json::from_slice(&f.gate.bytes().unwrap()).unwrap();
        for bad in [
            serde_json::json!("a"),
            serde_json::json!("A".repeat(64)),
            serde_json::json!(7),
            serde_json::Value::Null,
        ] {
            let mut changed = baseline.clone();
            changed["records"][0]["input_digest"] = bad;
            let raw = match serde_json::from_value::<Snapshot>(changed.clone()) {
                Ok(snapshot) => serde_json::to_vec(&snapshot).unwrap(),
                Err(_) => serde_json::to_vec(&changed).unwrap(),
            };
            // An explicitly null field is noncanonical, whereas genuine old
            // history omits it. Test its raw representation separately.
            let raw = if changed["records"][0]["input_digest"].is_null() {
                let bound = String::from_utf8(f.gate.bytes().unwrap()).unwrap();
                bound
                    .replace(
                        &format!("\"input_digest\":\"{}\"", "e".repeat(64)),
                        "\"input_digest\":null",
                    )
                    .into_bytes()
            } else {
                raw
            };
            fs::write(f.directory.join(FILE), &raw).unwrap();
            assert!(Gate::open(&f.store).is_err());
            assert_eq!(fs::read(f.directory.join(FILE)).unwrap(), raw);
        }
    }
}
