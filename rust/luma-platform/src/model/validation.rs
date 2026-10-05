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

fn record_bytes(state: &Path) -> Result<Option<Vec<u8>>> {
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

fn worker_hashes(state: &Path) -> Result<(Option<String>, Option<String>)> {
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
}

pub(super) fn inspect(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<Observation> {
    activation_records_absent(state)?;
    let bytes = record_bytes(state)?.ok_or("no retained model validation")?;
    let record = decode(&bytes, resolve)?;
    // Do not open/close the POSIX inode in its possible owning process. Real
    // maintenance enters through the independently acquired operation lock.
    if record.controller_pid == std::process::id() {
        return Err("validation belongs to this process; preserve state".into());
    }
    let lease = lock_file(state, false)?;
    let metadata = lease.metadata()?;
    if (metadata.dev(), metadata.ino()) != (record.lease_device, record.lease_inode)
        || query_lock(&lease)?.is_some()
    {
        return Err("model validation controller/lock is live or uncertain; preserve state".into());
    }
    let (current_hashes, current) = consistent_current(state, resolve)?;
    activation_records_absent(state)?;
    checked_lock(state, &lease)?;
    if query_lock(&lease)?.is_some()
        || record_bytes(state)?.as_deref() != Some(bytes.as_slice())
        || hashes(state)? != current_hashes
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
    })
}

pub(super) fn retain_abandoned(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<String> {
    tpm::decode::<32>(reviewed)?;
    let observed = inspect(state, resolve)?;
    if observed.review != reviewed {
        return Err("model validation review changed; preserve state".into());
    }
    let archive = state.join(&observed.archive);
    match checked_activation_bytes_with_mode(&archive, MAX_RECORD, 0, 0o077)? {
        Some(bytes) if bytes == observed.bytes => (),
        Some(_) => return Err("model validation retention conflict; preserve state".into()),
        None => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&archive)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&observed.bytes)?;
            file.sync_all()?;
        }
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?
        .sync_all()?;
    File::open(state)?.sync_all()?;
    let current = inspect(state, resolve)?;
    if current.review != observed.review
        || current.hashes != observed.hashes
        || checked_activation_bytes_with_mode(&archive, MAX_RECORD, 0, 0o077)?.as_deref()
            != Some(observed.bytes.as_slice())
    {
        return Err("model validation changed after retention; preserve state".into());
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
        let mut child = helper(root, "hold", false);
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
            "hold" | "exit" => {
                let guard = Guard::begin(&state, &p).unwrap();
                fs::write(state.join("child.ready"), b"ready").unwrap();
                if action == "hold" {
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
            _ => panic!("unknown owned fixture action"),
        }
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
