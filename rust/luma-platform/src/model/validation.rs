//! Durable reconfiguration trial fence. This is not a RAM lease, product
//! authorization, continuous worker monitor or protected anti-replay ledger.
use super::*;

pub(super) const PENDING: &str = "model-validation.pending";
const LEASE: &str = "model-validation.lock";
const MAX_RECORD: u64 = 8192;
type Hashes = (Option<String>, Option<String>, Option<String>);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    incident_id: String,
    controller_pid: u32,
    controller_start_ticks: u64,
    boot_id: String,
    lease_device: u64,
    lease_inode: u64,
    candidate: String,
    candidate_sha256: String,
    catalog_sha256: String,
    hashes: Hashes,
}

fn bounded_proc(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("oversized model controller observation".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn start_ticks(pid: u32) -> Result<u64> {
    let stat = bounded_proc(&format!("/proc/{pid}/stat"))?;
    if stat.split_once(' ').map(|(value, _)| value) != Some(pid.to_string().as_str()) {
        return Err("model controller PID observation changed".into());
    }
    let close = stat.rfind(')').ok_or("invalid model controller stat")?;
    let ticks: u64 = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or("model controller start observation missing")?
        .parse()?;
    if ticks == 0 {
        return Err("invalid model controller start observation".into());
    }
    Ok(ticks)
}

fn boot_id() -> Result<String> {
    let value = bounded_proc("/proc/sys/kernel/random/boot_id")?;
    let bytes = tpm::decode::<16>(&value.trim().replace('-', ""))?;
    if bytes == [0; 16] {
        return Err("invalid model validation boot observation".into());
    }
    Ok(bundle::hex(&bytes))
}

pub(super) fn record_bytes(state: &Path) -> Result<Option<Vec<u8>>> {
    let bytes = activation_bytes(&state.join(PENDING), MAX_RECORD)?;
    if bytes.is_some() && fs::symlink_metadata(state.join(PENDING))?.mode() & 0o7777 != 0o644 {
        return Err("unsafe model validation record mode; preserve state".into());
    }
    Ok(bytes)
}

fn decode(bytes: &[u8], resolve: &impl Fn(&str) -> Result<Profile>) -> Result<Record> {
    let record: Record = serde_json::from_slice(bytes)
        .map_err(|_| "invalid model validation record; preserve state")?;
    let candidate = resolve(&record.candidate)?;
    if serde_json::to_vec(&record)? != bytes
        || record.schema_version != 1
        || record.controller_pid == 0
        || record.controller_pid > i32::MAX as u32
        || record.controller_start_ticks == 0
        || record.lease_inode == 0
        || tpm::decode::<16>(&record.incident_id).is_err()
        || tpm::decode::<16>(&record.boot_id).is_err()
        || record.boot_id == "00".repeat(16)
        || candidate.id != record.candidate
        || candidate.sha256 != record.candidate_sha256
        || record.catalog_sha256 != bundle::hex(&Sha256::digest(CATALOG.as_bytes()))
        || [&record.hashes.0, &record.hashes.1, &record.hashes.2]
            .iter()
            .any(|h| h.as_ref().map_or(true, |h| tpm::decode::<32>(h).is_err()))
    {
        return Err("model validation catalog or canonical binding changed; preserve state".into());
    }
    Ok(record)
}

fn lock_file(state: &Path, initialize: bool) -> Result<File> {
    let parent = fs::symlink_metadata(state)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("unsafe model validation lock directory".into());
    }
    let path = state.join(LEASE);
    if initialize {
        crate::require_root()?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(created) => {
                created.set_permissions(fs::Permissions::from_mode(0o644))?;
                created.sync_all()?;
                File::open(state)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error.into()),
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(initialize)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    checked_lock(state, &file)?;
    Ok(file)
}

fn checked_lock(state: &Path, file: &File) -> Result<()> {
    let opened = file.metadata()?;
    let path = fs::symlink_metadata(state.join(LEASE))?;
    if !opened.is_file()
        || !path.is_file()
        || opened.uid() != 0
        || opened.nlink() != 1
        || opened.mode() & 0o7777 != 0o644
        || opened.len() != 0
        || (
            opened.dev(),
            opened.ino(),
            opened.ctime(),
            opened.ctime_nsec(),
        ) != (path.dev(), path.ino(), path.ctime(), path.ctime_nsec())
    {
        return Err("unsafe or replaced model validation lock; preserve state".into());
    }
    Ok(())
}

fn query_lock(file: &File) -> Result<Option<u32>> {
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if lock.l_type == libc::F_UNLCK as libc::c_short {
        return Ok(None);
    }
    if lock.l_type != libc::F_WRLCK as libc::c_short
        || lock.l_pid <= 0
        || lock.l_start != 0
        || lock.l_len != 0
    {
        return Err("unexpected model validation lock holder; preserve state".into());
    }
    Ok(Some(lock.l_pid as u32))
}

fn hashes(state: &Path) -> Result<Hashes> {
    let (selection, environment, key) = activation_snapshot(state)?;
    Ok((
        activation_digest(&selection),
        activation_digest(&environment),
        activation_digest(&key),
    ))
}

pub(super) fn worker_hashes(state: &Path) -> Result<(Option<String>, Option<String>)> {
    // The isolated worker must not gain read access to the reference service's
    // private environment. Its own two runtime inputs are sufficient here;
    // the root controller/recovery review verifies the full three-file tuple.
    Ok((
        activation_digest(&activation_bytes(
            &state.join("model-selection.json"),
            4096,
        )?),
        activation_digest(&activation_bytes(&state.join("model-auth/api-key"), 64)?),
    ))
}

fn consistent_current(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<(Hashes, Option<Profile>)> {
    let (selection, environment, key) = activation_snapshot(state)?;
    let snapshot = PriorBackup {
        schema_version: 1,
        candidate: String::new(),
        selection,
        environment,
        key,
    };
    let current = prior_restore_profile(&snapshot, resolve)?;
    if let Some(p) = &current {
        verify_file(&state.join("models").join(format!("{}.gguf", p.id)), p)?;
    }
    let before = (
        activation_digest(&snapshot.selection),
        activation_digest(&snapshot.environment),
        activation_digest(&snapshot.key),
    );
    if hashes(state)? != before {
        return Err("model configuration changed during validation review".into());
    }
    Ok((before, current))
}

pub(super) struct Guard {
    state: PathBuf,
    lease: File,
    bytes: Vec<u8>,
    record: Record,
}

impl Guard {
    pub(super) fn begin(state: &Path, p: &Profile) -> Result<Self> {
        crate::require_root()?;
        match fs::symlink_metadata(state.join(PENDING)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("model validation pending; preserve state".into()),
        }
        let lease = lock_file(state, true)?;
        // An incomplete record cannot identify a POSIX lock's owning process.
        // This companion OFD flock excludes recovery for the whole controller
        // lifetime, including that partial-publication window. It is not a RAM
        // reservation or a generation, and never replaces the PID-bound lock.
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("model validation/recovery lease is already active".into());
        }
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        if unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_SETLK, &lock) } != 0 {
            return Err("model validation controller already active".into());
        }
        let (snapshot, current) = consistent_current(state, &|id| {
            if id != p.id {
                return Err("model validation candidate changed".into());
            }
            Ok(p.clone())
        })?;
        if current.is_none() {
            return Err("model validation candidate missing".into());
        }
        let mut incident = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut incident)?;
        let metadata = lease.metadata()?;
        let record = Record {
            schema_version: 1,
            incident_id: bundle::hex(&incident),
            controller_pid: std::process::id(),
            controller_start_ticks: start_ticks(std::process::id())?,
            boot_id: boot_id()?,
            lease_device: metadata.dev(),
            lease_inode: metadata.ino(),
            candidate: p.id.clone(),
            candidate_sha256: p.sha256.clone(),
            catalog_sha256: bundle::hex(&Sha256::digest(CATALOG.as_bytes())),
            hashes: snapshot,
        };
        let bytes = serde_json::to_vec(&record)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join(PENDING))?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(state)?.sync_all()?;
        let guard = Self {
            state: state.to_path_buf(),
            lease,
            bytes,
            record,
        };
        guard.check(p)?;
        Ok(guard)
    }

    pub(super) fn check(&self, p: &Profile) -> Result<()> {
        // POSIX process locks are dropped by closing ANY descriptor for their
        // inode in the owning process. Never reopen/clone the lease here. The
        // private Guard alone owns that FD; subprocesses do not inherit its lock.
        checked_lock(&self.state, &self.lease)?;
        let metadata = self.lease.metadata()?;
        if self.record.controller_pid != std::process::id()
            || self.record.controller_start_ticks != start_ticks(std::process::id())?
            || self.record.boot_id != boot_id()?
            || (metadata.dev(), metadata.ino())
                != (self.record.lease_device, self.record.lease_inode)
            || p.id != self.record.candidate
            || p.sha256 != self.record.candidate_sha256
            || hashes(&self.state)? != self.record.hashes
            || record_bytes(&self.state)?.as_deref() != Some(self.bytes.as_slice())
        {
            return Err("model validation controller/configuration binding changed".into());
        }
        Ok(())
    }

    pub(super) fn complete(self, p: &Profile) -> Result<()> {
        activation_records_absent(&self.state)?;
        quarantine_absent(&self.state)?;
        self.check(p)?;
        fs::remove_file(self.state.join(PENDING))?;
        File::open(&self.state)?.sync_all()?;
        Ok(())
    }
    // Deliberately no cleanup Drop. Return/error/SIGKILL closes the kernel lock,
    // but leaves durable trial bytes for explicit installed-root review.
}

pub(super) fn worker_admission(state: &Path, p: &Profile) -> Result<()> {
    activation_records_absent(state)?;
    quarantine_absent(state)?;
    let Some(bytes) = record_bytes(state)? else {
        return Ok(());
    };
    let record = decode(&bytes, &|id| {
        if id != p.id {
            return Err("model validation candidate changed".into());
        }
        Ok(p.clone())
    })?;
    if record.controller_pid == std::process::id() {
        return Err("model worker cannot be its validation controller".into());
    }
    let lease = lock_file(state, false)?;
    let metadata = lease.metadata()?;
    if (metadata.dev(), metadata.ino()) != (record.lease_device, record.lease_inode)
        || record.boot_id != boot_id()?
        || query_lock(&lease)? != Some(record.controller_pid)
        || start_ticks(record.controller_pid)? != record.controller_start_ticks
        || worker_hashes(state)? != (record.hashes.0.clone(), record.hashes.2.clone())
    {
        return Err(
            "model validation abandoned or configuration changed; reviewed recovery required"
                .into(),
        );
    }
    // Freshly recheck after proc/config observations. This gates startup, not
    // continuous operation or death between the final observation and exec.
    activation_records_absent(state)?;
    quarantine_absent(state)?;
    checked_lock(state, &lease)?;
    if query_lock(&lease)? != Some(record.controller_pid)
        || record.boot_id != boot_id()?
        || start_ticks(record.controller_pid)? != record.controller_start_ticks
        || record_bytes(state)?.as_deref() != Some(bytes.as_slice())
        || worker_hashes(state)? != (record.hashes.0, record.hashes.2)
    {
        return Err("model validation changed before worker admission".into());
    }
    Ok(())
}

pub(super) struct Observation {
    pub(super) review: String,
    pub(super) current: Option<Profile>,
    pub(super) archive: String,
    bytes: Vec<u8>,
    hashes: Hashes,
    identity: Option<FileIdentity>,
}

pub(super) fn inspect(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<Observation> {
    independent_typed_owner(state, resolve)?;
    let lease = recovery_lock(state)?;
    inspect_locked(state, resolve, &lease)
}

fn independent_typed_owner(state: &Path, resolve: &impl Fn(&str) -> Result<Profile>) -> Result<()> {
    activation_records_absent(state)?;
    let bytes = record_bytes(state)?.ok_or("no retained model validation")?;
    let record = decode(&bytes, resolve)?;
    // Do not open/close the POSIX inode in its possible owning process. Real
    // maintenance enters through the independently acquired operation lock.
    if record.controller_pid == std::process::id() {
        return Err("validation belongs to this process; preserve state".into());
    }
    Ok(())
}

fn recovery_lock(state: &Path) -> Result<File> {
    // Public maintenance holds independently acquired operation/runtime locks.
    // Do not create/rebind a missing or unsafe persistent inode as recovery.
    let lease = lock_file(state, false)?;
    if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(
            "model validation controller/recovery is live or uncertain; preserve state".into(),
        );
    }
    checked_recovery_lock(state, &lease)?;
    Ok(lease)
}

fn checked_recovery_lock(state: &Path, lease: &File) -> Result<()> {
    checked_lock(state, lease)?;
    if query_lock(lease)?.is_some() {
        return Err("model validation controller/lock is live or uncertain; preserve state".into());
    }
    Ok(())
}

fn inspect_locked(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
    lease: &File,
) -> Result<Observation> {
    activation_records_absent(state)?;
    let bytes = record_bytes(state)?.ok_or("no retained model validation")?;
    let record = decode(&bytes, resolve)?;
    let metadata = lease.metadata()?;
    if (metadata.dev(), metadata.ino()) != (record.lease_device, record.lease_inode) {
        return Err("model validation controller/lock is live or uncertain; preserve state".into());
    }
    checked_recovery_lock(state, lease)?;
    let (current_hashes, current) = consistent_current(state, resolve)?;
    activation_records_absent(state)?;
    checked_recovery_lock(state, lease)?;
    if record_bytes(state)?.as_deref() != Some(bytes.as_slice()) || hashes(state)? != current_hashes
    {
        return Err("model validation changed during recovery inspection".into());
    }
    let archive = format!(
        "model-validation.retained.{}",
        bundle::hex(&Sha256::digest(&bytes))
    );
    if let Some(retained) =
        checked_activation_bytes_with_mode(&state.join(&archive), MAX_RECORD, 0, 0o077)?
    {
        if retained != bytes {
            return Err("model validation retention conflict; preserve state".into());
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-model-abandoned-validation-review-v1\0");
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&current_hashes)?);
    if let Some(p) = &current {
        digest.update(p.sha256.as_bytes());
    }
    Ok(Observation {
        review: bundle::hex(&digest.finalize()),
        current,
        archive,
        bytes,
        hashes: current_hashes,
        identity: None,
    })
}

pub(super) fn retain_abandoned(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<String> {
    tpm::decode::<32>(reviewed)?;
    independent_typed_owner(state, resolve)?;
    let lease = recovery_lock(state)?;
    let observed = inspect_locked(state, resolve, &lease)?;
    if observed.review != reviewed {
        return Err("model validation review changed; preserve state".into());
    }
    retain_bytes(state, &observed.archive, &observed.bytes)?;
    let current = inspect_locked(state, resolve, &lease)?;
    if current.review != observed.review
        || current.hashes != observed.hashes
        || checked_activation_bytes_with_mode(&state.join(&observed.archive), MAX_RECORD, 0, 0o077)?
            .as_deref()
            != Some(observed.bytes.as_slice())
    {
        return Err("model validation changed after retention; preserve state".into());
    }
    checked_recovery_lock(state, &lease)?;
    activation_records_absent(state)?;
    if record_bytes(state)?.as_deref() != Some(observed.bytes.as_slice())
        || hashes(state)? != observed.hashes
    {
        return Err("model validation/configuration changed before clearance".into());
    }
    fs::remove_file(state.join(PENDING))?;
    File::open(state)?.sync_all()?;
    Ok(observed.archive)
}

fn retain_bytes(state: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let archive = state.join(name);
    match checked_activation_bytes_with_mode(&archive, MAX_RECORD, 0, 0o077)? {
        Some(retained) if retained == bytes => (),
        Some(_) => return Err("model validation retention conflict; preserve state".into()),
        None => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&archive)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?
        .sync_all()?;
    File::open(state)?.sync_all()?;
    if checked_activation_bytes_with_mode(&archive, MAX_RECORD, 0, 0o077)?.as_deref() != Some(bytes)
    {
        return Err("model validation retention changed; preserve state".into());
    }
    Ok(())
}

type FileIdentity = (u64, u64, i64, i64);

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn incomplete_bytes(state: &Path) -> Result<(Vec<u8>, FileIdentity)> {
    let before = fs::symlink_metadata(state.join(PENDING))?;
    let bytes = record_bytes(state)?.ok_or("no retained model validation")?;
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Err(error) if error.is_eof() => (),
        _ => return Err("model validation is not incomplete JSON; preserve state".into()),
    }
    let after = fs::symlink_metadata(state.join(PENDING))?;
    if file_identity(&before) != file_identity(&after) {
        return Err("incomplete model validation changed during inspection".into());
    }
    Ok((bytes, file_identity(&after)))
}

fn inspect_incomplete_locked(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
    lease: &File,
) -> Result<Observation> {
    activation_records_absent(state)?;
    checked_recovery_lock(state, lease)?;
    let (bytes, identity) = incomplete_bytes(state)?;
    let (current_hashes, current) = consistent_current(state, resolve)?;
    activation_records_absent(state)?;
    checked_recovery_lock(state, lease)?;
    if incomplete_bytes(state)? != (bytes.clone(), identity) || hashes(state)? != current_hashes {
        return Err("incomplete model validation/configuration changed during inspection".into());
    }
    let archive = format!(
        "model-validation.retained.{}",
        bundle::hex(&Sha256::digest(&bytes))
    );
    if let Some(retained) =
        checked_activation_bytes_with_mode(&state.join(&archive), MAX_RECORD, 0, 0o077)?
    {
        if retained != bytes {
            return Err("model validation retention conflict; preserve state".into());
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-model-incomplete-validation-review-v1\0");
    digest.update(CATALOG.as_bytes());
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&identity)?);
    let metadata = lease.metadata()?;
    digest.update(serde_json::to_vec(&(metadata.dev(), metadata.ino()))?);
    digest.update(serde_json::to_vec(&current_hashes)?);
    if let Some(p) = &current {
        digest.update(p.sha256.as_bytes());
    }
    Ok(Observation {
        review: bundle::hex(&digest.finalize()),
        current,
        archive,
        bytes,
        hashes: current_hashes,
        identity: Some(identity),
    })
}

pub(super) fn inspect_incomplete(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<Observation> {
    activation_records_absent(state)?;
    let lease = recovery_lock(state)?;
    inspect_incomplete_locked(state, resolve, &lease)
}

pub(super) fn retain_incomplete(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<String> {
    tpm::decode::<32>(reviewed)?;
    activation_records_absent(state)?;
    let lease = recovery_lock(state)?;
    let observed = inspect_incomplete_locked(state, resolve, &lease)?;
    if observed.review != reviewed {
        return Err("incomplete model validation review changed; preserve state".into());
    }
    retain_bytes(state, &observed.archive, &observed.bytes)?;
    let current = inspect_incomplete_locked(state, resolve, &lease)?;
    if current.review != observed.review
        || current.hashes != observed.hashes
        || checked_activation_bytes_with_mode(&state.join(&observed.archive), MAX_RECORD, 0, 0o077)?
            .as_deref()
            != Some(observed.bytes.as_slice())
    {
        return Err("incomplete model validation changed after retention; preserve state".into());
    }
    checked_recovery_lock(state, &lease)?;
    activation_records_absent(state)?;
    if incomplete_bytes(state)?
        != (
            observed.bytes.clone(),
            observed
                .identity
                .ok_or("incomplete validation identity missing")?,
        )
        || hashes(state)? != observed.hashes
    {
        return Err("incomplete model validation/configuration changed before clearance".into());
    }
    fs::remove_file(state.join(PENDING))?;
    File::open(state)?.sync_all()?;
    Ok(observed.archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    const WEIGHTS: &[u8] = b"private tiny validation weight fixture";
    fn fixture_profile() -> Profile {
        let mut p = catalog().unwrap().models.remove(0);
        p.bytes = WEIGHTS.len() as u64;
        p.sha256 = bundle::hex(&Sha256::digest(WEIGHTS));
        p
    }
    fn fixture(label: &str) -> (PathBuf, PathBuf, Profile) {
        let root =
            std::env::temp_dir().join(format!("luma-validation-{label}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let state = root.join(STATE);
        fs::create_dir_all(state.join("models")).unwrap();
        for dir in [&root, state.parent().unwrap(), &state] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let p = fixture_profile();
        fs::write(state.join("models").join(format!("{}.gguf", p.id)), WEIGHTS).unwrap();
        write_candidate_config(&state, &p).unwrap();
        (root, state, p)
    }
    fn cleanup(root: &Path, state: &Path, p: &Profile) {
        for entry in fs::read_dir(state).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(digest) = name.strip_prefix("model-validation.retained.") {
                tpm::decode::<32>(digest).unwrap();
                fs::remove_file(entry.path()).unwrap();
            }
        }
        for name in [
            PENDING,
            LEASE,
            ACTIVATION,
            PRIOR_BACKUP,
            QUARANTINE,
            "model-disabled",
            "child.ready",
            "model-selection.json",
            REFERENCE_ENV,
            "model-auth/api-key",
            "alias",
            "displaced.lock",
            "displaced.pending",
            "model-runtime.lock",
        ] {
            let path = state.join(name);
            if path.symlink_metadata().is_ok() {
                fs::remove_file(path).unwrap();
            }
        }
        fs::remove_file(state.join("models").join(format!("{}.gguf", p.id))).unwrap();
        fs::remove_dir(state.join("models")).unwrap();
        fs::remove_dir(state.join("model-auth")).unwrap();
        fs::remove_dir(state).unwrap();
        fs::remove_dir(state.parent().unwrap()).unwrap();
        let leaf = root.join("leaf-fixture");
        if leaf.exists() {
            fs::remove_file(leaf).unwrap();
        }
        let worker = root.join("worker-fixture");
        if worker.exists() {
            for name in [
                "leaf.ready",
                "result",
                "controller.request",
                "forbidden.spawn",
            ] {
                let path = worker.join(name);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
            fs::remove_dir(worker).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn helper(root: &Path, action: &str, isolated: bool) -> OwnedChild {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "model::validation::tests::owned_process_helper",
                "--nocapture",
            ])
            .env("LUMA_VALIDATION_TEST_ROOT", root)
            .env("LUMA_VALIDATION_TEST_ACTION", action)
            .stdout(Stdio::null());
        if isolated {
            unsafe {
                command.pre_exec(|| {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(989) != 0
                        || libc::setuid(989) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        OwnedChild(command.spawn().unwrap())
    }
    fn controller(root: &Path, state: &Path) -> OwnedChild {
        holder(root, state, "hold")
    }
    fn holder(root: &Path, state: &Path, action: &str) -> OwnedChild {
        let mut child = helper(root, action, false);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !state.join("child.ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "controller exited before ready"
            );
            assert!(
                std::time::Instant::now() < until,
                "controller readiness timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child
    }
    fn probe(root: &Path, admitted: bool) {
        let mut child = helper(root, if admitted { "admit" } else { "deny" }, true);
        assert!(child.0.wait().unwrap().success());
    }
    #[test]
    #[ignore = "owned child of model validation process-boundary fixtures only"]
    fn owned_process_helper() {
        let root = PathBuf::from(
            std::env::var_os("LUMA_VALIDATION_TEST_ROOT").expect("owned fixture root required"),
        );
        let action =
            std::env::var("LUMA_VALIDATION_TEST_ACTION").expect("owned fixture action required");
        let state = root.join(STATE);
        let p = fixture_profile();
        match action.as_str() {
            "hold" | "hold-partial" | "hold-complete" | "hold-exit" | "exit" => {
                let guard = Guard::begin(&state, &p).unwrap();
                if action == "hold-partial" {
                    fs::write(state.join(PENDING), b"{").unwrap();
                }
                fs::write(state.join("child.ready"), b"ready").unwrap();
                if action == "hold-complete" || action == "hold-exit" {
                    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    while !root.join("worker-fixture/controller.request").exists() {
                        assert!(
                            std::time::Instant::now() < until,
                            "owned controller request timed out"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    if action == "hold-complete" {
                        guard.complete(&p).unwrap();
                        return;
                    }
                } else if action != "exit" {
                    std::thread::sleep(std::time::Duration::from_secs(15));
                }
                drop(guard);
            }
            "admit" | "deny" => {
                assert_eq!(unsafe { libc::geteuid() }, 989);
                // The worker's admission must not require the reference-only
                // environment or a writable descriptor for the root lease.
                assert!(File::open(state.join(REFERENCE_ENV)).is_err());
                assert!(OpenOptions::new()
                    .write(true)
                    .open(state.join(LEASE))
                    .is_err());
                assert_eq!(worker_admission(&state, &p).is_ok(), action == "admit");
            }
            "legacy-posix" | "unknown-ofd" => {
                let lease = lock_file(&state, true).unwrap();
                let mut lock: libc::flock = unsafe { std::mem::zeroed() };
                lock.l_type = libc::F_WRLCK as _;
                lock.l_whence = libc::SEEK_SET as _;
                let command = if action == "legacy-posix" {
                    libc::F_SETLK
                } else {
                    libc::F_OFD_SETLK
                };
                assert_eq!(unsafe { libc::fcntl(lease.as_raw_fd(), command, &lock) }, 0);
                fs::write(state.join("child.ready"), b"ready").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(15));
                drop(lease);
            }
            "flock-denied" => {
                let lease = lock_file(&state, false).unwrap();
                assert_ne!(
                    unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                    0
                );
            }
            "archive-denied" => {
                assert_eq!(unsafe { libc::geteuid() }, 989);
                let archive = fs::read_dir(&state)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("model-validation.retained.")
                    })
                    .unwrap();
                assert!(File::open(&archive).is_err());
                assert!(fs::remove_file(&archive).is_err());
            }
            "supervise" | "supervise-success" | "supervise-failure" | "supervise-death" => {
                assert_eq!(unsafe { libc::geteuid() }, 989);
                assert!(File::open(state.join(REFERENCE_ENV)).is_err());
                let runtime = runtime_lock(&root, false).unwrap();
                let verified =
                    verified_file(&state.join("models").join(format!("{}.gguf", p.id)), &p)
                        .unwrap();
                let mut fence = supervision::Fence::capture(&state, &p).unwrap();
                let leaf_action = match action.as_str() {
                    "supervise-success" => "leaf-success",
                    "supervise-failure" => "leaf-failure",
                    _ => "leaf-hold",
                };
                let mut leaf = Command::new(root.join("leaf-fixture"));
                leaf.arg(leaf_action)
                    .env("LUMA_VALIDATION_TEST_ROOT", &root)
                    .env(
                        "LUMA_VALIDATION_LEAF_WEIGHT_FD",
                        verified.as_raw_fd().to_string(),
                    )
                    .env(
                        "LUMA_VALIDATION_LEAF_RUNTIME_FD",
                        runtime.as_raw_fd().to_string(),
                    )
                    .stdout(Stdio::null());
                inherit_runtime_files(&mut leaf, &verified, &runtime);
                let result = supervision::run(&mut leaf, || fence.check(&state, &p));
                fs::write(
                    root.join("worker-fixture/result"),
                    if result.is_ok() {
                        &b"success"[..]
                    } else {
                        &b"refused"[..]
                    },
                )
                .unwrap();
                assert_eq!(result.is_ok(), action == "supervise-success");
            }
            "wait-ignored" | "wait-no-cldwait" => {
                let mut setting: libc::sigaction = unsafe { std::mem::zeroed() };
                setting.sa_sigaction = if action == "wait-ignored" {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                if action == "wait-no-cldwait" {
                    setting.sa_flags = libc::SA_NOCLDWAIT;
                }
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &setting, std::ptr::null_mut()) },
                    0
                );
                let marker = std::ffi::CString::new(
                    root.join("worker-fixture/forbidden.spawn")
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                let mut leaf = Command::new("/bin/true");
                unsafe {
                    leaf.pre_exec(move || {
                        let fd = libc::open(
                            marker.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                            0o600,
                        );
                        if fd < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(fd);
                        Ok(())
                    });
                }
                assert!(supervision::run(&mut leaf, || Ok(())).is_err());
                assert!(!root.join("worker-fixture/forbidden.spawn").exists());
            }
            "death-probe" => {
                assert_eq!(unsafe { libc::geteuid() }, 989);
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
                    0
                );
                let worker = supervised(&root, "supervise-death");
                let leaf: libc::pid_t = fs::read_to_string(root.join("worker-fixture/leaf.ready"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let leaf_start = start_ticks(leaf as u32).unwrap();
                assert!(leaf > 0 && leaf as u32 != std::process::id());
                assert!(runtime_lock(&root, false).is_err());
                drop(worker); // kill/reap only the owned supervisor
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut status: libc::c_int = 0;
                loop {
                    let reaped = unsafe { libc::waitpid(leaf, &mut status, libc::WNOHANG) };
                    if reaped == leaf {
                        break;
                    }
                    assert_eq!(reaped, 0, "owned descendant wait failed");
                    assert_eq!(start_ticks(leaf as u32).unwrap(), leaf_start);
                    assert!(
                        std::time::Instant::now() < until,
                        "owned child parent-death reap timed out"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                assert!(!root.join("worker-fixture/result").exists());
                drop(runtime_lock(&root, false).unwrap());
            }
            _ => panic!("unknown owned fixture action"),
        }
    }

    fn supervision_fixture(label: &str) -> (PathBuf, PathBuf, Profile) {
        let (root, state, p) = fixture(label);
        let worker = root.join("worker-fixture");
        fs::create_dir(&worker).unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
        command("/usr/bin/chown", &["989:989", worker.to_str().unwrap()]).unwrap();
        // Compile only the captured static C leaf, in this fresh disposable
        // root. No environment-selected executable or production path override.
        let leaf = root.join("leaf-fixture");
        let mut compiler = Command::new("/usr/bin/cc")
            .args([
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-x",
                "c",
                "-",
                "-o",
                leaf.to_str().unwrap(),
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("TMPDIR", std::env::temp_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(
                include_str!("../../../../native/tests/model_supervision_fixture.c").as_bytes(),
            )
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
        drop(runtime_lock(&root, true).unwrap());
        (root, state, p)
    }

    fn supervised(root: &Path, action: &str) -> OwnedChild {
        let mut child = helper(root, action, unsafe { libc::geteuid() } == 0);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !fs::read_to_string(root.join("worker-fixture/leaf.ready")).map_or(false, |value| {
            value.ends_with('\n') && value.trim().parse::<u32>().map_or(false, |pid| pid > 0)
        }) {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "owned supervisor exited before leaf readiness"
            );
            assert!(
                std::time::Instant::now() < until,
                "owned leaf readiness timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child
    }

    fn await_supervised_refusal(root: &Path, mut child: OwnedChild) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "owned supervisor refusal timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(root.join("worker-fixture/result")).unwrap(),
            b"refused"
        );
        drop(runtime_lock(root, false).unwrap());
    }

    #[test]
    fn supervisor_refuses_non_waitable_child_policy_before_spawning() {
        for action in ["wait-ignored", "wait-no-cldwait"] {
            let (root, state, p) = supervision_fixture(action);
            let mut child = helper(&root, action, true);
            assert!(child.0.wait().unwrap().success());
            assert!(!root.join("worker-fixture/forbidden.spawn").exists());
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_observes_normal_and_failed_owned_runtime_exit_with_verified_descriptors() {
        for action in ["supervise-success", "supervise-failure"] {
            let (root, state, p) = supervision_fixture(action);
            let mut child = helper(&root, action, true);
            assert!(child.0.wait().unwrap().success());
            assert_eq!(
                fs::read(root.join("worker-fixture/result")).unwrap(),
                if action == "supervise-success" {
                    &b"success"[..]
                } else {
                    &b"refused"[..]
                }
            );
            drop(runtime_lock(&root, false).unwrap());
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_refuses_initial_disablement_uncertain_state_and_wrong_selected_profile() {
        for label in [
            "disabled",
            "quarantine",
            "activation",
            "orphan",
            "partial",
            "missing-key",
            "invalid-key",
            "profile",
        ] {
            let (root, state, mut p) = fixture(&format!("supervision-initial-{label}"));
            match label {
                "disabled" => fs::write(state.join("model-disabled"), b"independent").unwrap(),
                "quarantine" => publish_quarantine(&state, &p, RestartStage::Health).unwrap(),
                "activation" => fs::write(state.join(ACTIVATION), b"uncertain").unwrap(),
                "orphan" => fs::write(state.join(PRIOR_BACKUP), b"uncertain").unwrap(),
                "partial" => fs::write(state.join(PENDING), b"{").unwrap(),
                "missing-key" => fs::remove_file(state.join("model-auth/api-key")).unwrap(),
                "invalid-key" => {
                    fs::write(state.join("model-auth/api-key"), b"never-echo").unwrap()
                }
                "profile" => p.id = catalog().unwrap().models[1].id.clone(),
                _ => unreachable!(),
            }
            assert!(supervision::Fence::capture(&state, &p).is_err());
            if label == "profile" {
                p = fixture_profile();
            }
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_terminates_existing_worker_on_independent_fences_or_runtime_input_change() {
        for label in [
            "disabled",
            "quarantine",
            "activation",
            "orphan",
            "selection",
            "key",
            "partial",
        ] {
            let (root, state, p) = supervision_fixture(&format!("supervision-change-{label}"));
            let child = supervised(&root, "supervise");
            assert!(runtime_lock(&root, false).is_err());
            let before_weights =
                fs::read(state.join("models").join(format!("{}.gguf", p.id))).unwrap();
            match label {
                "disabled" => fs::write(state.join("model-disabled"), b"independent").unwrap(),
                "quarantine" => publish_quarantine(&state, &p, RestartStage::Health).unwrap(),
                "activation" => fs::write(state.join(ACTIVATION), b"uncertain").unwrap(),
                "orphan" => fs::write(state.join(PRIOR_BACKUP), b"uncertain").unwrap(),
                "selection" => fs::write(state.join("model-selection.json"), b"changed").unwrap(),
                "key" => fs::write(state.join("model-auth/api-key"), b"never-echo").unwrap(),
                "partial" => fs::write(state.join(PENDING), b"{").unwrap(),
                _ => unreachable!(),
            }
            await_supervised_refusal(&root, child);
            assert_eq!(
                fs::read(state.join("models").join(format!("{}.gguf", p.id))).unwrap(),
                before_weights
            );
            assert!(supervision::Fence::capture(&state, &p).is_err());
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_terminates_existing_trial_worker_after_controller_exit_and_sigkill() {
        for label in ["normal", "kill"] {
            let (root, state, p) = supervision_fixture(&format!("supervision-controller-{label}"));
            let mut controller = holder(
                &root,
                &state,
                if label == "normal" {
                    "hold-exit"
                } else {
                    "hold"
                },
            );
            let child = supervised(&root, "supervise");
            let original = record_bytes(&state).unwrap().unwrap();
            if label == "normal" {
                fs::write(root.join("worker-fixture/controller.request"), b"exit").unwrap();
                assert!(controller.0.wait().unwrap().success());
            }
            drop(controller);
            await_supervised_refusal(&root, child);
            assert_eq!(record_bytes(&state).unwrap().unwrap(), original);
            assert!(!state.join(QUARANTINE).exists()); // worker cannot invent private quarantine
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_survives_verified_trial_completion_and_continues_watching_fences() {
        let (root, state, p) = supervision_fixture("supervision-completion");
        let mut controller = holder(&root, &state, "hold-complete");
        let mut child = supervised(&root, "supervise");
        fs::write(root.join("worker-fixture/controller.request"), b"complete").unwrap();
        assert!(controller.0.wait().unwrap().success());
        assert!(record_bytes(&state).unwrap().is_none());
        std::thread::sleep(std::time::Duration::from_millis(1200));
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(!root.join("worker-fixture/result").exists());
        assert!(runtime_lock(&root, false).is_err());
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        await_supervised_refusal(&root, child);
        assert!(state.join(QUARANTINE).exists());
        cleanup(&root, &state, &p);
    }

    #[test]
    fn supervisor_refuses_substituted_valid_trial_and_unexpected_new_trial() {
        for typed in [true, false] {
            let (root, state, p) = supervision_fixture(if typed {
                "supervision-substitute"
            } else {
                "supervision-new-trial"
            });
            let controller = if typed {
                Some(controller(&root, &state))
            } else {
                None
            };
            let child = supervised(&root, "supervise");
            let guard = if typed {
                let mut record =
                    decode(&record_bytes(&state).unwrap().unwrap(), &|_| Ok(p.clone())).unwrap();
                record.incident_id = "01".repeat(16);
                fs::write(state.join(PENDING), serde_json::to_vec(&record).unwrap()).unwrap();
                None
            } else {
                Some(Guard::begin(&state, &p).unwrap())
            };
            probe(&root, true); // otherwise valid startup, but not this worker's bound trial
            await_supervised_refusal(&root, child);
            assert!(state.join(PENDING).exists());
            drop(guard);
            drop(controller);
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn supervisor_death_kills_and_reaps_its_owned_direct_child_without_host_pid_search() {
        let (root, state, p) = supervision_fixture("supervision-parent-death");
        let mut child = helper(&root, "death-probe", true);
        assert!(child.0.wait().unwrap().success());
        cleanup(&root, &state, &p);
    }

    #[test]
    fn supervisor_unwind_kills_owned_child_before_releasing_inherited_runtime_lock() {
        let (root, state, p) = supervision_fixture("supervision-unwind");
        let runtime = runtime_lock(&root, false).unwrap();
        let verified =
            verified_file(&state.join("models").join(format!("{}.gguf", p.id)), &p).unwrap();
        let mut leaf = Command::new("/bin/sleep");
        leaf.arg("15").stdout(Stdio::null());
        inherit_runtime_files(&mut leaf, &verified, &runtime);
        let calls = std::cell::Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            supervision::run(&mut leaf, || {
                calls.set(calls.get() + 1);
                if calls.get() > 1 {
                    panic!("owned supervisor fixture unwind");
                }
                Ok(())
            })
        }));
        assert!(result.is_err());
        drop(runtime);
        drop(runtime_lock(&root, false).unwrap());
        cleanup(&root, &state, &p);
    }

    #[test]
    fn live_controller_allows_only_bound_worker_and_blocks_ordinary_activation_and_recovery() {
        let (root, state, p) = fixture("live");
        let child = controller(&root, &state);
        probe(&root, true);
        assert!(activation_absent(&state).is_err());
        assert!(inspect(&state, &|_| Ok(p.clone())).is_err());
        assert!(begin_activation(&state, &p).is_err());
        let record = decode(&record_bytes(&state).unwrap().unwrap(), &|_| Ok(p.clone())).unwrap();
        assert_eq!(record.controller_pid, child.0.id());
        drop(child);
        probe(&root, false);
        cleanup(&root, &state, &p);
    }

    #[test]
    fn controller_exit_and_sigkill_leave_durable_trial_for_reviewed_private_retention() {
        for label in ["exit", "kill"] {
            let (root, state, p) = fixture(label);
            if label == "exit" {
                let mut child = helper(&root, "exit", false);
                assert!(child.0.wait().unwrap().success());
            } else {
                drop(controller(&root, &state));
            }
            let before = record_bytes(&state).unwrap().unwrap();
            let config = activation_snapshot(&state).unwrap();
            probe(&root, false);
            fs::write(state.join("model-disabled"), b"independent disablement").unwrap();
            publish_quarantine(&state, &p, RestartStage::Health).unwrap();
            let observed = inspect(&state, &|_| Ok(p.clone())).unwrap();
            assert!(retain_abandoned(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
            let archive = retain_abandoned(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
            assert_eq!(fs::read(state.join(&archive)).unwrap(), before);
            assert_eq!(
                fs::symlink_metadata(state.join(archive)).unwrap().mode() & 0o777,
                0o600
            );
            assert!(record_bytes(&state).unwrap().is_none());
            assert_eq!(activation_snapshot(&state).unwrap(), config);
            assert!(state.join("model-disabled").exists() && state.join(QUARANTINE).exists());
            probe(&root, false); // independent quarantine remains a fence
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn guard_completion_requires_unchanged_bindings_and_preserves_trial_on_error() {
        let (root, state, p) = fixture("complete");
        let guard = Guard::begin(&state, &p).unwrap();
        probe(&root, true);
        assert!(inspect(&state, &|_| Ok(p.clone())).is_err());
        guard.complete(&p).unwrap();
        assert!(record_bytes(&state).unwrap().is_none());
        probe(&root, true);
        let guard = Guard::begin(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"changed reference settings").unwrap();
        assert!(guard.complete(&p).is_err());
        assert!(state.join(PENDING).exists());
        probe(&root, false);
        cleanup(&root, &state, &p);
    }

    #[test]
    fn worker_refuses_changed_boot_pid_start_pin_runtime_inputs_and_substituted_lease() {
        for label in [
            "boot",
            "pid",
            "start",
            "pin",
            "selection",
            "key",
            "lease",
            "quarantine",
            "activation",
        ] {
            let (root, state, p) = fixture(label);
            let child = controller(&root, &state);
            let bytes = record_bytes(&state).unwrap().unwrap();
            let mut record = decode(&bytes, &|_| Ok(p.clone())).unwrap();
            match label {
                "boot" => record.boot_id = "01".repeat(16),
                "pid" => record.controller_pid = std::process::id(),
                "start" => record.controller_start_ticks += 1,
                "pin" => record.candidate_sha256 = "00".repeat(32),
                "selection" => fs::write(state.join("model-selection.json"), b"changed").unwrap(),
                "key" => fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap(),
                "lease" => {
                    fs::rename(state.join(LEASE), state.join("displaced.lock")).unwrap();
                    let _replacement = lock_file(&state, true).unwrap();
                }
                "quarantine" => publish_quarantine(&state, &p, RestartStage::Health).unwrap(),
                "activation" => fs::write(state.join(ACTIVATION), b"uncertain").unwrap(),
                _ => unreachable!(),
            }
            if matches!(label, "boot" | "pid" | "start" | "pin") {
                fs::write(state.join(PENDING), serde_json::to_vec(&record).unwrap()).unwrap();
            }
            probe(&root, false);
            drop(child);
            assert!(state.join(PENDING).exists());
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn recovery_refuses_stale_config_bad_weights_and_changed_state_after_blocking_resolve() {
        let (root, state, p) = fixture("recovery-review");
        drop(controller(&root, &state));
        let observed = inspect(&state, &|_| Ok(p.clone())).unwrap();
        fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap();
        fs::write(
            state.join(REFERENCE_ENV),
            reference_environment(&p, &"b".repeat(64)),
        )
        .unwrap();
        assert!(retain_abandoned(&state, &observed.review, &|_| Ok(p.clone())).is_err());
        let fresh = inspect(&state, &|_| Ok(p.clone())).unwrap();
        fs::write(
            state.join("models").join(format!("{}.gguf", p.id)),
            b"corrupt",
        )
        .unwrap();
        assert!(retain_abandoned(&state, &fresh.review, &|_| Ok(p.clone())).is_err());
        fs::write(state.join("models").join(format!("{}.gguf", p.id)), WEIGHTS).unwrap();
        assert!(inspect(&state, &|_| {
            fs::write(state.join(ACTIVATION), b"changed while resolving")?;
            Ok(p.clone())
        })
        .is_err());
        assert!(state.join(PENDING).exists() && !state.join(observed.archive).exists());
        cleanup(&root, &state, &p);
    }

    #[test]
    fn recovery_can_retain_after_manual_restoration_and_retry_exact_archive() {
        let (root, state, p) = fixture("manual-retry");
        drop(controller(&root, &state));
        for name in ["model-selection.json", REFERENCE_ENV, "model-auth/api-key"] {
            fs::remove_file(state.join(name)).unwrap();
        }
        let observed = inspect(&state, &|_| Ok(p.clone())).unwrap();
        assert!(observed.current.is_none());
        fs::write(state.join(&observed.archive), &observed.bytes).unwrap();
        fs::set_permissions(
            state.join(&observed.archive),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let archive = retain_abandoned(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
        assert_eq!(fs::read(state.join(archive)).unwrap(), observed.bytes);
        assert_eq!(activation_snapshot(&state).unwrap(), (None, None, None));
        cleanup(&root, &state, &p);
    }

    #[test]
    fn incomplete_trial_retention_preserves_private_bytes_settings_and_independent_fences() {
        for (label, bytes, manual) in [
            (
                "incomplete-selected",
                &b"{\"opaque\":\"never-echo"[..],
                false,
            ),
            ("incomplete-manual", &b"{"[..], true),
            ("incomplete-empty", &b""[..], false),
        ] {
            let (root, state, p) = fixture(label);
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), bytes).unwrap();
            if manual {
                for name in ["model-selection.json", REFERENCE_ENV, "model-auth/api-key"] {
                    fs::remove_file(state.join(name)).unwrap();
                }
            }
            let before = activation_snapshot(&state).unwrap();
            let lease = file_identity(&fs::symlink_metadata(state.join(LEASE)).unwrap());
            fs::write(state.join("model-disabled"), b"independent disablement").unwrap();
            publish_quarantine(&state, &p, RestartStage::Health).unwrap();
            let quarantine = fs::read(state.join(QUARANTINE)).unwrap();
            let observed = inspect_incomplete(&state, &|_| Ok(p.clone())).unwrap();
            assert_eq!(observed.current.is_none(), manual);
            assert!(retain_incomplete(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
            let archive = retain_incomplete(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
            assert_eq!(fs::read(state.join(&archive)).unwrap(), bytes);
            assert_eq!(
                fs::symlink_metadata(state.join(&archive)).unwrap().mode() & 0o7777,
                0o600
            );
            assert!(record_bytes(&state).unwrap().is_none());
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            assert_eq!(
                file_identity(&fs::symlink_metadata(state.join(LEASE)).unwrap()),
                lease
            );
            assert_eq!(fs::read(state.join(QUARANTINE)).unwrap(), quarantine);
            assert!(state.join("model-disabled").exists());
            let mut child = helper(&root, "archive-denied", true);
            assert!(child.0.wait().unwrap().success());
            verify_file(&state.join("models").join(format!("{}.gguf", p.id)), &p).unwrap();
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_refuses_complete_malformed_unsafe_and_missing_records_without_disclosure() {
        for label in [
            "complete",
            "null",
            "malformed",
            "mode",
            "linked",
            "symlink",
            "oversized",
            "missing",
        ] {
            let (root, state, p) = fixture(&format!("incomplete-record-{label}"));
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), b"{").unwrap();
            match label {
                "complete" => {
                    fs::write(state.join(PENDING), b"{\"future\":\"never-echo\"}").unwrap()
                }
                "null" => fs::write(state.join(PENDING), b"null").unwrap(),
                "malformed" => fs::write(state.join(PENDING), b"{\"never-echo\":!}").unwrap(),
                "mode" => {
                    fs::set_permissions(state.join(PENDING), fs::Permissions::from_mode(0o666))
                        .unwrap()
                }
                "linked" => fs::hard_link(state.join(PENDING), state.join("alias")).unwrap(),
                "symlink" => {
                    fs::rename(state.join(PENDING), state.join("alias")).unwrap();
                    std::os::unix::fs::symlink(state.join("alias"), state.join(PENDING)).unwrap();
                }
                "oversized" => fs::write(state.join(PENDING), vec![b' '; 8193]).unwrap(),
                "missing" => fs::remove_file(state.join(PENDING)).unwrap(),
                _ => unreachable!(),
            }
            let error = inspect_incomplete(&state, &|_| Ok(p.clone()))
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("never-echo"));
            assert!(retain_incomplete(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
            assert_eq!(
                state.join(PENDING).symlink_metadata().is_ok(),
                label != "missing"
            );
            assert!(!fs::read_dir(&state).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("model-validation.retained.")));
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_refuses_missing_or_unsafe_persistent_lease_without_rebinding() {
        for label in ["missing", "mode", "linked", "symlink", "nonempty"] {
            let (root, state, p) = fixture(&format!("incomplete-lease-{label}"));
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), b"{").unwrap();
            match label {
                "missing" => fs::remove_file(state.join(LEASE)).unwrap(),
                "mode" => fs::set_permissions(state.join(LEASE), fs::Permissions::from_mode(0o666))
                    .unwrap(),
                "linked" => fs::hard_link(state.join(LEASE), state.join("alias")).unwrap(),
                "symlink" => {
                    fs::rename(state.join(LEASE), state.join("alias")).unwrap();
                    std::os::unix::fs::symlink(state.join("alias"), state.join(LEASE)).unwrap();
                }
                "nonempty" => fs::write(state.join(LEASE), b"uncertain").unwrap(),
                _ => unreachable!(),
            }
            assert!(inspect_incomplete(&state, &|_| Ok(p.clone())).is_err());
            assert!(retain_incomplete(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
            assert_eq!(
                state.join(LEASE).symlink_metadata().is_ok(),
                label != "missing"
            );
            assert_eq!(fs::read(state.join(PENDING)).unwrap(), b"{");
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_refuses_live_controller_legacy_posix_and_unknown_ofd_holders() {
        for action in ["hold-partial", "legacy-posix", "unknown-ofd"] {
            let (root, state, p) = fixture(&format!("incomplete-holder-{action}"));
            let child = holder(&root, &state, action);
            if action != "hold-partial" {
                fs::write(state.join(PENDING), b"{").unwrap();
            }
            assert!(inspect_incomplete(&state, &|_| Ok(p.clone())).is_err());
            assert!(retain_incomplete(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
            assert_eq!(fs::read(state.join(PENDING)).unwrap(), b"{");
            if action == "hold-partial" {
                probe(&root, false);
            }
            drop(child);
            let observed = inspect_incomplete(&state, &|_| Ok(p.clone())).unwrap();
            retain_incomplete(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_review_refuses_changed_settings_weights_record_and_lease_identity() {
        for label in ["settings", "weights", "record", "lease"] {
            let (root, state, p) = fixture(&format!("incomplete-stale-{label}"));
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), b"{").unwrap();
            let observed = inspect_incomplete(&state, &|_| Ok(p.clone())).unwrap();
            match label {
                "settings" => {
                    fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap();
                    fs::write(
                        state.join(REFERENCE_ENV),
                        reference_environment(&p, &"b".repeat(64)),
                    )
                    .unwrap();
                }
                "weights" => fs::write(
                    state.join("models").join(format!("{}.gguf", p.id)),
                    b"corrupt",
                )
                .unwrap(),
                "record" => {
                    fs::rename(state.join(PENDING), state.join("displaced.pending")).unwrap();
                    fs::write(state.join(PENDING), b"{").unwrap();
                }
                "lease" => {
                    fs::rename(state.join(LEASE), state.join("displaced.lock")).unwrap();
                    drop(lock_file(&state, true).unwrap());
                }
                _ => unreachable!(),
            }
            assert!(retain_incomplete(&state, &observed.review, &|_| Ok(p.clone())).is_err());
            assert!(state.join(PENDING).exists() && !state.join(observed.archive).exists());
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_archive_retry_refuses_conflicting_public_linked_and_oversized_copies() {
        for label in [
            "exact",
            "conflict",
            "public",
            "linked",
            "symlink",
            "oversized",
        ] {
            let (root, state, p) = fixture(&format!("incomplete-archive-{label}"));
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), b"{").unwrap();
            let observed = inspect_incomplete(&state, &|_| Ok(p.clone())).unwrap();
            let archive = state.join(&observed.archive);
            fs::write(&archive, b"{").unwrap();
            fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
            match label {
                "exact" => (),
                "conflict" => fs::write(&archive, b"conflicting evidence").unwrap(),
                "public" => {
                    fs::set_permissions(&archive, fs::Permissions::from_mode(0o644)).unwrap()
                }
                "linked" => fs::hard_link(&archive, state.join("alias")).unwrap(),
                "symlink" => {
                    fs::rename(&archive, state.join("alias")).unwrap();
                    std::os::unix::fs::symlink(state.join("alias"), &archive).unwrap();
                }
                "oversized" => fs::write(&archive, vec![b' '; 8193]).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::read(&archive).unwrap();
            let result = retain_incomplete(&state, &observed.review, &|_| Ok(p.clone()));
            assert_eq!(result.is_ok(), label == "exact");
            assert_eq!(state.join(PENDING).exists(), label != "exact");
            assert_eq!(fs::read(&archive).unwrap(), before);
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn incomplete_trial_rechecks_identity_and_pending_state_after_private_retention() {
        for label in ["identity", "activation"] {
            let (root, state, p) = fixture(&format!("incomplete-after-retention-{label}"));
            drop(lock_file(&state, true).unwrap());
            fs::write(state.join(PENDING), b"{").unwrap();
            let observed = inspect_incomplete(&state, &|_| Ok(p.clone())).unwrap();
            let changed = std::cell::Cell::new(false);
            assert!(retain_incomplete(&state, &observed.review, &|_| {
                if state.join(&observed.archive).exists() && !changed.replace(true) {
                    if label == "identity" {
                        fs::rename(state.join(PENDING), state.join("displaced.pending"))?;
                        fs::write(state.join(PENDING), b"{")?;
                    } else {
                        fs::write(state.join(ACTIVATION), b"uncertain")?;
                    }
                }
                Ok(p.clone())
            })
            .is_err());
            assert!(changed.get() && state.join(PENDING).exists());
            assert_eq!(fs::read(state.join(observed.archive)).unwrap(), b"{");
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn recovery_exclusive_flock_covers_blocking_reviews_and_retention_for_both_record_types() {
        for typed in [true, false] {
            let (root, state, p) = fixture(if typed {
                "exclusive-typed"
            } else {
                "exclusive-incomplete"
            });
            if typed {
                drop(controller(&root, &state));
            } else {
                drop(lock_file(&state, true).unwrap());
                fs::write(state.join(PENDING), b"{").unwrap();
            }
            let calls = std::cell::Cell::new(0);
            let resolve = |_: &str| {
                let count = calls.get();
                calls.set(count + 1);
                // Typed maintenance decodes once before opening the possible
                // owning POSIX inode. Subsequent locked reviews must exclude peers.
                if !typed || count > 0 {
                    let mut child = helper(&root, "flock-denied", false);
                    assert!(child.0.wait().unwrap().success());
                }
                Ok(p.clone())
            };
            let observed = if typed {
                inspect(&state, &resolve)
            } else {
                inspect_incomplete(&state, &resolve)
            }
            .unwrap();
            calls.set(0);
            if typed {
                retain_abandoned(&state, &observed.review, &resolve)
            } else {
                retain_incomplete(&state, &observed.review, &resolve)
            }
            .unwrap();
            assert!(calls.get() >= 2);
            let lease = recovery_lock(&state).unwrap();
            assert!(Guard::begin(&state, &p).is_err());
            assert!(!state.join(PENDING).exists());
            drop(lease);
            cleanup(&root, &state, &p);
        }
    }

    #[test]
    fn unsafe_trial_and_retention_records_remain_fenced_without_overwrite() {
        for label in [
            "partial",
            "unknown",
            "public",
            "symlink",
            "hardlink",
            "oversized",
            "catalog",
            "archive",
        ] {
            let (root, state, p) = fixture(&format!("unsafe-{label}"));
            drop(controller(&root, &state));
            let observed = inspect(&state, &|_| Ok(p.clone())).unwrap();
            match label {
                "partial" => fs::write(state.join(PENDING), b"{").unwrap(),
                "unknown" => {
                    fs::write(state.join(PENDING), b"{\"secret\":\"never-echo\"}").unwrap()
                }
                "public" => {
                    fs::set_permissions(state.join(PENDING), fs::Permissions::from_mode(0o666))
                        .unwrap()
                }
                "symlink" => {
                    fs::rename(state.join(PENDING), state.join("alias")).unwrap();
                    std::os::unix::fs::symlink(state.join("alias"), state.join(PENDING)).unwrap();
                }
                "hardlink" => fs::hard_link(state.join(PENDING), state.join("alias")).unwrap(),
                "oversized" => fs::write(state.join(PENDING), vec![b' '; 8193]).unwrap(),
                "catalog" => {
                    let mut record = decode(&observed.bytes, &|_| Ok(p.clone())).unwrap();
                    record.catalog_sha256 = "00".repeat(32);
                    fs::write(state.join(PENDING), serde_json::to_vec(&record).unwrap()).unwrap();
                }
                "archive" => {
                    fs::write(
                        state.join(&observed.archive),
                        b"conflicting retained evidence",
                    )
                    .unwrap();
                    fs::set_permissions(
                        state.join(&observed.archive),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            probe(&root, false);
            let error = retain_abandoned(&state, &observed.review, &|_| Ok(p.clone()))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("never-echo"));
            assert!(fs::symlink_metadata(state.join(PENDING)).is_ok());
            cleanup(&root, &state, &p);
        }
    }
}
