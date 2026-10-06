//! Pinned image-owned model admission and atomic, bounded HTTPS acquisition.
//! A model is data, never an executable or an authority to perform OS effects.
use crate::{bundle, disk::command, platform, tpm, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const CATALOG: &str = include_str!("../../../native/image/model-catalog.json");
const VAR: &str = "/var";
const STATE: &str = "lib/luma-os";
const RUNTIME: &str = "/usr/libexec/luma-os/llama/llama-server";
const ACTIVATION: &str = "model-activation.pending";
const PRIOR_BACKUP: &str = "model-activation.prior";
const MAX_PRIOR_BACKUP: u64 = 40_000;
const ROLLBACK: &str = "model-rollback.json";
const MAX_ROLLBACK: u64 = MAX_PRIOR_BACKUP + 4096;
const QUARANTINE: &str = "model-quarantine.json";
const REFERENCE_ENV: &str = "model-reference.env";

mod layout;
mod supervision;
mod validation;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    publisher: String,
    parameters: u64,
    active_parameters: u64,
    license: String,
    url: String,
    bytes: u64,
    sha256: String,
    minimum_ram_bytes: u64,
    minimum_available_bytes: u64,
    context_tokens: u32,
    memory_max_bytes: u64,
    layout: layout::Shape,
    #[cfg(test)]
    #[serde(skip)]
    fixture_verifier: Option<fn(&Path, &Profile) -> Result<()>>,
}

impl Profile {
    #[cfg(test)]
    fn with_fixture_verifier(mut self) -> Self {
        assert!(
            self.bytes <= 1024 * 1024,
            "only tiny unit fixture profiles may inject verification"
        );
        self.fixture_verifier = Some(|at, p| verified_file(at, p).map(drop));
        self
    }
    pub(crate) fn memory_limit(&self) -> u64 {
        self.memory_max_bytes
    }
    pub(crate) fn context_limit(&self) -> u64 {
        u64::from(self.context_tokens)
    }
    pub(crate) fn resource_binding(&self) -> Result<String> {
        Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(self)?)))
    }
}

pub(crate) fn resource_binding_profile(binding: &str) -> Result<Profile> {
    for p in catalog()?.models {
        if p.resource_binding()? == binding {
            return Ok(p);
        }
    }
    Err("resource lease profile is not in the pinned catalog".into())
}

pub(crate) fn resource_catalog_binding() -> Result<String> {
    catalog()?;
    Ok(bundle::hex(&Sha256::digest(CATALOG.as_bytes())))
}

pub(crate) fn resource_profile(id: &str) -> Result<Profile> {
    let p = selected()?;
    if p.id != id {
        return Err("resource profile differs from installed selection".into());
    }
    let state = Path::new(VAR).join(STATE);
    recovery_disablement_absent(&state)?;
    activation_records_absent(&state)?;
    quarantine_absent(&state)?;
    validation::worker_admission(&state, &p)?;
    Ok(p)
}

pub(crate) fn resource_idle() -> Result<File> {
    runtime_lock(Path::new(VAR), false)
}

pub(crate) fn resource_recovery_exclusion() -> Result<File> {
    operation_lock(Path::new(VAR))
}

/// Offline recovery creates only an absent exclusion inode. An existing inode,
/// including a concurrent publication, is never replaced or adopted as success.
pub(crate) fn recover_missing_runtime_lock() -> Result<File> {
    create_missing_runtime_lock(Path::new(VAR))
}

fn create_missing_runtime_lock(var: &Path) -> Result<File> {
    crate::require_root()?;
    let state = var.join(STATE);
    let parent = fs::symlink_metadata(&state)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("unsafe model runtime lock directory".into());
    }
    let created = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(state.join("model-runtime.lock"))?;
    // Take the exclusion before publishing its durable acknowledgement. Failure
    // leaves the inode intact; a new invocation must inspect, never recreate it.
    if unsafe { libc::flock(created.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("new runtime exclusion is uncertain; preserve inode".into());
    }
    created.set_permissions(fs::Permissions::from_mode(0o644))?;
    created.sync_all()?;
    File::open(&state)?.sync_all()?;
    Ok(created)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: u32,
    environment: String,
    runtime: String,
    models: Vec<Profile>,
}

fn catalog() -> Result<Catalog> {
    let c: Catalog = serde_json::from_str(CATALOG)?;
    if c.schema_version != 1
        || c.environment != "lab"
        || c.runtime != "llama.cpp-b11100-cpu-amd64"
        || c.models.is_empty()
    {
        return Err("unsupported image-owned model catalog".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for p in &c.models {
        p.layout.validate()?;
        layout::Inventory::for_profile(p)?;
        if !ids.insert(&p.id)
            || p.id.is_empty()
            || p.id.len() > 64
            || !p
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !p.url.starts_with("https://huggingface.co/Qwen/")
            || p.sha256.len() != 64
            || !p.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || p.bytes == 0
            || p.bytes > 64 * 1024 * 1024 * 1024
            || p.active_parameters > p.parameters
            || p.context_tokens != 2048
            || p.minimum_ram_bytes <= p.memory_max_bytes
            || p.minimum_available_bytes <= p.bytes
        {
            return Err("invalid model profile".into());
        }
    }
    Ok(c)
}

pub fn profile(id: &str) -> Result<Profile> {
    catalog()?
        .models
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "model is not in this signed image's catalog".into())
}

pub fn list() -> Result<()> {
    println!("manual-only: no weights, no inference service");
    for p in catalog()?.models {
        println!(
            "{}: {} total/{} active parameters; {} bytes download; CPU; RAM >= {}; context {}; {}",
            p.id,
            p.parameters,
            p.active_parameters,
            p.bytes,
            p.minimum_ram_bytes,
            p.context_tokens,
            p.license
        );
    }
    println!("Catalog is laboratory authority, not production model certification. No cloud inference fallback.");
    Ok(())
}

pub(crate) fn memory(info: &str, name: &str) -> Result<u64> {
    let fields: Vec<_> = info
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .ok_or("missing memory observation")?
        .split_whitespace()
        .collect();
    if fields.len() != 3 || fields[2] != "kB" {
        return Err("invalid memory observation".into());
    }
    fields[1]
        .parse::<u64>()?
        .checked_mul(1024)
        .ok_or_else(|| "memory overflow".into())
}

/// The process may have less RAM than /proc/meminfo reports. Require every
/// finite cgroup-v2 ancestor limit to fit the selected worker's MemoryMax.
/// This checks capacity, not a reservation or a pressure prediction.
fn cgroup_path(text: &str) -> Result<&str> {
    if text.len() > 4096 {
        return Err("oversized cgroup observation".into());
    }
    let mut paths = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = paths.next().ok_or("unified cgroup path unavailable")?;
    if paths.next().is_some() || !path.starts_with('/') || path.len() > 1024 {
        return Err("invalid unified cgroup path".into());
    }
    let path = Path::new(path);
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("unsafe unified cgroup path".into());
    }
    Ok(path.to_str().ok_or("non-UTF-8 unified cgroup path")?)
}

fn cgroup_limit_at(root: &Path, path: &str) -> Result<u64> {
    let mut directory = root.to_path_buf();
    let mut limit = u64::MAX;
    let mut observe = |directory: &Path| -> Result<()> {
        if !fs::symlink_metadata(directory)?.is_dir() {
            return Err("unsafe cgroup directory".into());
        }
        let file = directory.join("memory.max");
        let metadata = match fs::symlink_metadata(&file) {
            Ok(m) => m,
            Err(error) if directory == root && error.kind() == std::io::ErrorKind::NotFound => {
                // The real initial cgroup-v2 root has no memory.max. Accept
                // this kernel representation only on a verified cgroup2 fs;
                // nested missing controls and ordinary fixtures still refuse.
                let handle = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .open(directory)?;
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatfs(handle.as_raw_fd(), &mut stat) } != 0
                    || stat.f_type != 0x63677270
                {
                    return Err("missing cgroup root memory limit".into());
                }
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            return Err("unsafe cgroup memory limit".into());
        }
        let mut value = String::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(file)?
            .take(33)
            .read_to_string(&mut value)?;
        if value.len() > 32 {
            return Err("oversized cgroup memory limit".into());
        }
        let value = value.strip_suffix('\n').unwrap_or(&value);
        if value != "max" {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid cgroup memory limit".into());
            }
            let current: u64 = value.parse()?;
            if current == 0 {
                return Err("zero cgroup memory limit".into());
            }
            limit = limit.min(current);
        }
        Ok(())
    };
    observe(&directory)?;
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => (),
            Component::Normal(part) => {
                directory.push(part);
                observe(&directory)?;
            }
            _ => return Err("unsafe unified cgroup path".into()),
        }
    }
    Ok(limit)
}

fn effective_memory_limit() -> Result<u64> {
    let mut observed = String::new();
    File::open("/proc/self/cgroup")?
        .take(4097)
        .read_to_string(&mut observed)?;
    let path = cgroup_path(&observed)?;
    cgroup_limit_at(Path::new("/sys/fs/cgroup"), path)
}

fn admit_cgroup(p: &Profile, limit: u64) -> Result<()> {
    if limit < p.memory_max_bytes {
        return Err(format!(
            "{} cannot be admitted: effective cgroup memory limit {limit} is below worker MemoryMax {}",
            p.id, p.memory_max_bytes
        )
        .into());
    }
    Ok(())
}

fn admit_with_space(
    p: &Profile,
    total: u64,
    available: u64,
    free: u64,
    cpus: usize,
    required_free: u64,
) -> Result<()> {
    crate::resource_manager::check_loading(total, available, p.memory_max_bytes, 0)?;
    if total < p.minimum_ram_bytes
        || available < p.minimum_available_bytes
        || cpus < 2
        || free < required_free
    {
        return Err(format!("{} cannot be admitted: total RAM {total}, available {available}, free storage {free}, CPUs {cpus}; select a smaller profile or manual-only", p.id).into());
    }
    Ok(())
}

fn admit(p: &Profile, total: u64, available: u64, free: u64, cpus: usize) -> Result<()> {
    admit_with_space(
        p,
        total,
        available,
        free,
        cpus,
        p.bytes
            .checked_add(2 * 1024 * 1024 * 1024)
            .ok_or("space overflow")?,
    )
}

fn available_space(at: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(at.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(name.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| "space overflow".into())
}

pub fn check(p: &Profile, free: u64) -> Result<()> {
    let info = fs::read_to_string("/proc/meminfo")?;
    admit_cgroup(p, effective_memory_limit()?)?;
    admit(
        p,
        memory(&info, "MemTotal")?,
        memory(&info, "MemAvailable")?,
        free,
        std::thread::available_parallelism()?.get(),
    )
}

fn check_cached(p: &Profile, free: u64) -> Result<()> {
    let info = fs::read_to_string("/proc/meminfo")?;
    admit_cgroup(p, effective_memory_limit()?)?;
    admit_with_space(
        p,
        memory(&info, "MemTotal")?,
        memory(&info, "MemAvailable")?,
        free,
        std::thread::available_parallelism()?.get(),
        2 * 1024 * 1024 * 1024,
    )
}

pub fn choose(id: Option<&str>, free: u64) -> Result<Option<Profile>> {
    let selected = match id {
        Some(value) => value.to_string(),
        None => {
            list()?;
            println!("Select model ID (or type manual-only):");
            platform::console_line(false)?
        }
    };
    if selected == "manual-only" {
        return Ok(None);
    }
    let p = profile(&selected)?;
    check(&p, free)?;
    println!("Selected {}. Installation downloads {} bytes over HTTPS from the publisher and verifies SHA-256. License: {}. Model output is untrusted.", p.id, p.bytes, p.license);
    Ok(Some(p))
}

fn safe_dir(at: &Path) -> Result<()> {
    fs::create_dir_all(at)?;
    let m = fs::symlink_metadata(at)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("model state directory must be root-owned and non-writable by others".into());
    }
    Ok(())
}

fn open_regular(at: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(at)?;
    if !f.metadata()?.is_file() {
        return Err("model must be a regular file".into());
    }
    Ok(f)
}

#[cfg(test)]
fn verified_file(at: &Path, p: &Profile) -> Result<File> {
    verified_file_checked(at, p, || Ok(()))
}

fn verified_file_checked(
    at: &Path,
    p: &Profile,
    mut check: impl FnMut() -> Result<()>,
) -> Result<File> {
    check()?;
    let mut f = open_regular(at)?;
    let before = f.metadata()?;
    if before.len() != p.bytes {
        return Err("model byte count mismatch".into());
    }
    if before.uid() != 0 || before.nlink() != 1 || before.mode() & 0o022 != 0 {
        return Err("unsafe model ownership, links or mode".into());
    }
    let mut hash = Sha256::new();
    let mut remaining = p.bytes;
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        check()?;
        let n = f.read(&mut buffer)?;
        check()?;
        if n == 0 || n as u64 > remaining {
            return Err("model changed during verification".into());
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if f.read(&mut [0u8; 1])? != 0 || bundle::hex(&hash.finalize()) != p.sha256 {
        return Err("model SHA-256 mismatch".into());
    }
    let after = f.metadata()?;
    if before.len() != after.len()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || after.nlink() != 1
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("model metadata changed during verification".into());
    }
    f.seek(SeekFrom::Start(0))?;
    check()?;
    Ok(f)
}

/// Both the digest and layout come from this same pinned descriptor while the
/// caller's worker lease remains live. No unleased production verifier exists.
fn verified_runtime_file(
    at: &Path,
    p: &Profile,
    mut check: impl FnMut() -> Result<()>,
) -> Result<File> {
    let mut file = verified_file_checked(at, p, &mut check)?;
    let before = file.metadata()?;
    let inventory = layout::verify(&mut file, p, &mut check)?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || after.nlink() != 1
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("model metadata changed during layout verification".into());
    }
    file.seek(SeekFrom::Start(0))?;
    check()?;
    eprintln!(
        "Verified CPU allocation inventory: {}",
        serde_json::to_string(&inventory)?
    );
    Ok(file)
}

fn verify_file(at: &Path, p: &Profile) -> Result<()> {
    #[cfg(test)]
    if let Some(verifier) = p.fixture_verifier {
        return verifier(at, p);
    }
    crate::acquisition::verify_path(at, p)
}

/// Single local worker exclusion, not a resource-manager lease or generation.
/// The root-owned persistent inode must never be unlinked/replaced as cleanup:
/// the kernel releases the advisory lock when the last inherited FD closes.
fn runtime_lock(var: &Path, initialize: bool) -> Result<File> {
    let state = var.join(STATE);
    let parent = fs::symlink_metadata(&state)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("unsafe model runtime lock directory".into());
    }
    let path = state.join("model-runtime.lock");
    if initialize {
        crate::require_root()?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(created) => {
                created.set_permissions(fs::Permissions::from_mode(0o644))?;
                created.sync_all()?;
                File::open(&state)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    let lock = open_regular(&path)?;
    let metadata = lock.metadata()?;
    if metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o644
        || metadata.len() != 0
    {
        return Err("unsafe model runtime lock; preserve state".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("model runtime or activation is already active".into());
    }
    Ok(lock)
}

/// Only the two reviewed descriptors cross exec. Rust otherwise opens them
/// CLOEXEC; clear that bit in the child/exec boundary, never globally at open.
fn inherit_runtime_files(command: &mut Command, model: &File, lock: &File) {
    let descriptors = [model.as_raw_fd(), lock.as_raw_fd()];
    unsafe {
        command.pre_exec(move || {
            for fd in descriptors {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

struct Temporary {
    path: PathBuf,
    identity: Option<(u64, u64)>,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        // The parent descriptor and Command's stdout clone are dropped before
        // this guard. An independent open description must take the inherited
        // writer lock before cleanup. PID observation alone cannot prove that
        // every inherited writer descriptor has gone away.
        let cleanup = || -> Result<()> {
            let identity = self.identity.ok_or("partial file was not created")?;
            let file = open_regular(&self.path)?;
            let metadata = file.metadata()?;
            if (metadata.dev(), metadata.ino()) != identity
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err("partial writer or identity uncertain; preserve acquisition".into());
            }
            let named = fs::symlink_metadata(&self.path)?;
            if !named.is_file() || (named.dev(), named.ino()) != identity {
                return Err("partial path changed; preserve acquisition".into());
            }
            fs::remove_file(&self.path)?;
            File::open(self.path.parent().ok_or("missing partial parent")?)?.sync_all()?;
            Ok(())
        };
        // Uncertain output remains for reviewed, descriptor-fenced orphan
        // reconciliation. Drop cannot convert a failure into a cleanup receipt.
        let _ = cleanup();
    }
}

fn confine_acquisition(process: &mut Command, max_bytes: u64) -> Result<()> {
    if max_bytes == 0 || max_bytes >= libc::RLIM_INFINITY {
        return Err("model acquisition requires a finite nonzero byte ceiling".into());
    }
    unsafe {
        process.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(988) != 0
                || libc::setuid(988) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Also bound output at the kernel, even for chunked transfer without
            // a Content-Length and on curl versions predating streaming limits.
            let limit = libc::rlimit {
                rlim_cur: max_bytes,
                rlim_max: max_bytes,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

fn fetch(at: &Path, p: &Profile, mut check: impl FnMut() -> Result<()>) -> Result<()> {
    check()?;
    // Parent is root-only for writing. curl runs without root, supplementary
    // groups, ambient environment, stdin, proxy credentials or configuration.
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut temporary = Temporary {
        path: at.with_extension(format!("partial-{}", bundle::hex(&random))),
        identity: None,
    };
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&temporary.path)?;
    let metadata = file.metadata()?;
    temporary.identity = Some((metadata.dev(), metadata.ino()));
    // This open-file-description lock is inherited by curl's stdout. Even if
    // the owner dies before curl handles PDEATHSIG, cleanup cannot race it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("cannot lock model acquisition".into());
    }
    let mut process = Command::new("/usr/bin/curl");
    process
        .args([
            "-q",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "20",
            "--max-time",
            "3600",
            "--max-filesize",
            &p.bytes.to_string(),
            "--url",
            &p.url,
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::inherit());
    confine_acquisition(&mut process, p.bytes)?;
    let started = crate::resource_manager::now()?;
    let deadline = started
        .checked_add(3_620_000)
        .ok_or("download deadline overflow")?;
    let mut reported = 0;
    // The supervisor appends SIGKILL parent-death registration after the
    // credential-changing hook above, pins the exact child, and reaps it before
    // returning on an observation/deadline failure. No saved-PID fallback.
    let result = supervision::run(&mut process, || {
        check()?;
        let time = crate::resource_manager::now()?;
        if time >= deadline {
            return Err("model acquisition deadline expired".into());
        }
        let metadata = file.metadata()?;
        if metadata.len() > p.bytes
            || Some((metadata.dev(), metadata.ino())) != temporary.identity
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err("model acquisition output fence failed".into());
        }
        let elapsed = time
            .checked_sub(started)
            .ok_or("download clock regressed")?
            / 1000;
        if elapsed / 15 > reported {
            reported = elapsed / 15;
            println!(
                "Model download: {} / {} bytes ({}s)",
                metadata.len(),
                p.bytes,
                elapsed
            );
        }
        Ok(())
    });
    if let Err(error) = result {
        return Err(format!("model download failed: {error}; no model was activated; uncertain partials remain fenced").into());
    }
    println!("Verifying model bytes and SHA-256...");
    file.sync_all()?;
    verified_runtime_file(&temporary.path, p, &mut check)?;
    check()?;
    fs::set_permissions(&temporary.path, fs::Permissions::from_mode(0o444))?;
    fs::rename(&temporary.path, at)?;
    File::open(at.parent().ok_or("missing model directory")?)?.sync_all()?;
    Ok(())
}

fn operation_lock(var: &Path) -> Result<File> {
    let state = var.join(STATE);
    safe_dir(&state)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(state.join("model.lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("unsafe model operation lock".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another model operation is running".into());
    }
    Ok(lock)
}

pub fn provision(var: &Path, p: &Profile) -> Result<()> {
    crate::require_root()?;
    let _lock = operation_lock(var)?;
    provision_locked(var, p)
}

fn provision_locked(var: &Path, p: &Profile) -> Result<()> {
    prepare_model(var, p)?;
    activate_cached(var, p)
}

/// Acquire and verify only image-cataloged data. The selected worker may stay
/// active while this runs; no credential, environment or selection is changed.
fn prepare_model(var: &Path, p: &Profile) -> Result<()> {
    crate::acquisition::run(var, p, "prepare")
}

pub(crate) fn supervise_owned_controller(
    command: &mut Command,
    check: impl FnMut() -> Result<()>,
) -> Result<()> {
    supervision::run(command, check)
}

pub(crate) fn verify_acquired_model(
    var: &Path,
    p: &Profile,
    check: impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut parent = var.to_path_buf();
    for name in ["lib", "luma-os", "models"] {
        parent.push(name);
        let metadata = fs::symlink_metadata(&parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("unsafe contained verification directory".into());
        }
    }
    verified_runtime_file(
        &var.join(STATE)
            .join("models")
            .join(format!("{}.gguf", p.id)),
        p,
        check,
    )
    .map(drop)
}

pub(crate) fn prepare_model_contents(
    var: &Path,
    p: &Profile,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let state = var.join(STATE);
    activation_absent(&state)?;
    let models = state.join("models");
    safe_dir(&models)?;
    reconcile_downloads(&models, &catalog()?.models)?;
    platform::ensure_model_identities(var)?;
    let file = models.join(format!("{}.gguf", p.id));
    match fs::symlink_metadata(&file) {
        Ok(_) => {
            check_acquisition(p, available_space(&models)?, true)?;
            verified_runtime_file(&file, p, &mut check)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check_acquisition(p, available_space(&models)?, false)?;
            println!("Downloading {} ({} bytes)...", p.id, p.bytes);
            fetch(&file, p, &mut check)?;
        }
        Err(error) => return Err(error.into()),
    }
    check()?;
    Ok(())
}

fn acquisition_admission(
    p: &Profile,
    total: u64,
    free: u64,
    cpus: usize,
    cached: bool,
) -> Result<()> {
    // Acquiring bytes is not concurrent admission of another serving model.
    // The broker reserves the acquisition worker's bounded physical peak;
    // retain installation feasibility checks without borrowing serving RAM.
    crate::resource_manager::check_loading(total, total, p.memory_max_bytes, 0)?;
    let required = (if cached { 0 } else { p.bytes })
        .checked_add(2 * 1024 * 1024 * 1024)
        .ok_or("acquisition space overflow")?;
    if total < p.minimum_ram_bytes || cpus < 2 || free < required {
        return Err("model acquisition profile or storage does not fit".into());
    }
    Ok(())
}

fn check_acquisition(p: &Profile, free: u64, cached: bool) -> Result<()> {
    if effective_memory_limit()? < crate::resource_manager::ACQUISITION_MEMORY {
        return Err("acquisition ancestry is smaller than its admitted worker budget".into());
    }
    let info = fs::read_to_string("/proc/meminfo")?;
    acquisition_admission(
        p,
        memory(&info, "MemTotal")?,
        free,
        std::thread::available_parallelism()?.get(),
        cached,
    )
}

fn activate_cached(var: &Path, p: &Profile) -> Result<()> {
    activate_cached_with(var, p, |_, _| Ok(()))
}

fn activate_cached_with<T>(
    var: &Path,
    p: &Profile,
    before_publication: impl FnOnce(&Path, &Profile) -> Result<T>,
) -> Result<T> {
    // Excludes a concurrently started/manual worker for the whole activation,
    // including credential/selection writes. Released before systemd restart.
    let _runtime = runtime_lock(var, true)?;
    let state = var.join(STATE);
    activation_absent(&state)?;
    let models = state.join("models");
    safe_dir(&models)?;
    check_cached(p, available_space(&models)?)?;
    verify_file(&models.join(format!("{}.gguf", p.id)), p)?;
    // All worker-visible activation writes follow a durable pending fence.
    // A crash or failed write preserves it for explicit review.
    let activation = begin_activation(&state, p)?;
    write_candidate_config(&state, p)?;
    // For installed reconfiguration, publish the durable validation trial
    // before clearing the activation fence. Other provisioning callers have
    // no managed restart/readiness sequence and do not manufacture a trial.
    let trial = before_publication(&state, p)?;
    finish_activation(&state, p, &activation)?;
    println!("MODEL FILES INSTALLED AND VERIFIED: {}. Runtime readiness is checked separately after reconfiguration or at installed-system boot; no production certification implied.", p.id);
    Ok(trial)
}

fn write_candidate_config(state: &Path, p: &Profile) -> Result<()> {
    let auth = state.join("model-auth");
    safe_dir(&auth)?;
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o750))?;
    command(
        "/usr/bin/chown",
        &["0:989", auth.to_str().ok_or("invalid auth path")?],
    )?;
    let key_path = auth.join("api-key");
    let token = if let Some(bytes) = activation_bytes(&key_path, 64)? {
        let token = String::from_utf8(bytes)?;
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid model credential; preserve state".into());
        }
        token
    } else {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let s = bundle::hex(&bytes);
        platform::write_atomic(&key_path, s.as_bytes(), 0o640)?;
        s
    };
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640))?;
    command(
        "/usr/bin/chown",
        &["0:989", key_path.to_str().ok_or("invalid auth path")?],
    )?;
    let env = state.join(REFERENCE_ENV);
    platform::write_atomic(&env, &reference_environment(p, &token), 0o640)?;
    fs::set_permissions(&env, fs::Permissions::from_mode(0o640))?;
    command(
        "/usr/bin/chown",
        &["0:990", env.to_str().ok_or("invalid environment path")?],
    )?;
    let selection = state.join("model-selection.json");
    platform::write_atomic(
        &selection,
        &serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id}))?,
        0o644,
    )?;
    fs::set_permissions(&selection, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Only image-catalog acquisition temporaries are eligible, never selected
/// GGUFs, credentials, runtime files, or unknown entries. Caller holds model.lock.
fn reconcile_downloads(models: &Path, profiles: &[Profile]) -> Result<usize> {
    let parent = fs::symlink_metadata(models)?;
    if !parent.is_dir() || parent.uid() != unsafe { libc::geteuid() } || parent.mode() & 0o022 != 0
    {
        return Err("unsafe model cleanup directory".into());
    }
    let mut pending = Vec::new();
    let parent_mount = crate::staging::mount_id(models)?;
    for (count, entry) in fs::read_dir(models)?.enumerate() {
        if count >= 64 {
            return Err("model cleanup inventory limit exceeded".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid model cache filename")?;
        if profiles.iter().any(|p| name == format!("{}.gguf", p.id)) {
            continue;
        }
        let (id, suffix) = name
            .split_once(".partial-")
            .ok_or("unknown model cache entry; retained")?;
        let p = profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("unknown partial model; retained")?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid partial model name; retained".into());
        }
        let path = entry.path();
        let file = open_regular(&path)?;
        let m = file.metadata()?;
        if m.uid() != parent.uid()
            || m.nlink() != 1
            || m.dev() != parent.dev()
            || m.len() > p.bytes
            || m.mode() & 0o022 != 0
            || crate::staging::mount_id(&path)? != parent_mount
        {
            return Err("unsafe partial model; retained".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("partial model still has a writer; retry cleanup later".into());
        }
        pending.push((path, file));
    }
    // Keep every descriptor/lock until the complete inventory has been checked.
    for (path, _) in &pending {
        fs::remove_file(path)?;
    }
    File::open(models)?.sync_all()?;
    Ok(pending.len())
}

pub fn clean() -> Result<usize> {
    crate::require_root()?;
    let var = Path::new(VAR);
    let _lock = operation_lock(var)?;
    let models = var.join(STATE).join("models");
    if !models.try_exists()? {
        return Ok(0);
    }
    reconcile_downloads(&models, &catalog()?.models)
}

fn selected() -> Result<Profile> {
    let state = Path::new(VAR).join(STATE);
    selected_at(&state)
}

fn selected_at(state: &Path) -> Result<Profile> {
    let mut text = String::new();
    let file = open_regular(&state.join("model-selection.json"))?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        return Err("unsafe model selection ownership, links or permissions".into());
    }
    file.take(4097).read_to_string(&mut text)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Selection {
        schema_version: u32,
        id: String,
    }
    let s: Selection = serde_json::from_str(&text)?;
    if text.len() > 4096 || s.schema_version != 1 {
        return Err("invalid model selection".into());
    }
    profile(&s.id)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Activation {
    schema_version: u32,
    candidate: String,
    prior_selection_sha256: Option<String>,
    prior_env_sha256: Option<String>,
    prior_key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_backup_sha256: Option<String>,
}

// Contains the local model API credential. Never print or return this record.
// It is root-private recovery material, not a catalog or Admin grant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriorBackup {
    schema_version: u32,
    candidate: String,
    selection: Option<Vec<u8>>,
    environment: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

fn prior_backup_bytes(state: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(state.join(PRIOR_BACKUP)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => checked_activation_bytes_with_mode(
            &state.join(PRIOR_BACKUP),
            MAX_PRIOR_BACKUP,
            0,
            0o077,
        ),
    }
}

fn decode_prior_backup(bytes: &[u8]) -> Result<PriorBackup> {
    let backup: PriorBackup = serde_json::from_slice(bytes)
        .map_err(|_| "invalid private model prior backup; preserve state")?;
    if serde_json::to_vec(&backup)? != bytes
        || backup.schema_version != 1
        || backup.selection.as_ref().is_some_and(|v| v.len() > 4096)
        || backup.environment.as_ref().is_some_and(|v| v.len() > 4096)
        || backup.key.as_ref().is_some_and(|v| v.len() > 64)
    {
        return Err("invalid model prior backup; preserve state".into());
    }
    profile(&backup.candidate)?;
    Ok(backup)
}

fn bound_prior_backup(state: &Path, record: &Activation) -> Result<Option<PriorBackup>> {
    let Some(bytes) = prior_backup_bytes(state)? else {
        // Cleanup removes the backup before the marker. A crash here retains
        // the marker; explicit unchanged/candidate publication remains usable,
        // but restoration is unavailable. Never invent lost prior bytes.
        return Ok(None);
    };
    if record.schema_version != 2
        || record.prior_backup_sha256.as_deref()
            != Some(bundle::hex(&Sha256::digest(&bytes)).as_str())
    {
        return Err("model prior backup does not bind the pending activation".into());
    }
    let backup = decode_prior_backup(&bytes)?;
    if backup.candidate != record.candidate
        || activation_digest(&backup.selection) != record.prior_selection_sha256
        || activation_digest(&backup.environment) != record.prior_env_sha256
        || activation_digest(&backup.key) != record.prior_key_sha256
    {
        return Err("model prior backup does not reproduce retained hashes".into());
    }
    Ok(Some(backup))
}

fn activation_absent(state: &Path) -> Result<()> {
    activation_records_absent(state)?;
    quarantine_absent(state)?;
    match fs::symlink_metadata(state.join(validation::PENDING)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("model validation pending; reviewed reconciliation required".into()),
    }
}

fn quarantine_absent(state: &Path) -> Result<()> {
    match fs::symlink_metadata(state.join(QUARANTINE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("model quarantined; reviewed reconciliation required".into()),
    }
}

fn recovery_disablement_absent(state: &Path) -> Result<()> {
    match fs::symlink_metadata(state.join("model-disabled")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("model recovery disablement is present or uncertain; preserve state".into()),
    }
}

fn activation_records_absent(state: &Path) -> Result<()> {
    for name in [ACTIVATION, PRIOR_BACKUP] {
        match fs::symlink_metadata(state.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err("model activation pending; reviewed reconciliation required".into())
            }
        }
    }
    Ok(())
}

fn checked_activation_bytes(path: &Path, max: u64, owner: u32) -> Result<Option<Vec<u8>>> {
    checked_activation_bytes_with_mode(path, max, owner, 0o022)
}

fn checked_activation_bytes_with_mode(
    path: &Path,
    max: u64,
    owner: u32,
    forbidden: u32,
) -> Result<Option<Vec<u8>>> {
    let original = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !original.is_file()
        || original.uid() != owner
        || original.nlink() != 1
        || original.mode() & forbidden != 0
        || original.len() > max
    {
        return Err("unsafe model activation file; preserve state".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != original.dev() || opened.ino() != original.ino() {
        return Err("model activation file changed during open".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(max + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != original.len()
        || after.len() != original.len()
        || after.uid() != original.uid()
        || after.gid() != original.gid()
        || after.mode() != original.mode()
        || after.mtime() != original.mtime()
        || after.mtime_nsec() != original.mtime_nsec()
        || after.ctime() != original.ctime()
        || after.ctime_nsec() != original.ctime_nsec()
    {
        return Err("model activation file changed during read".into());
    }
    Ok(Some(bytes))
}

fn activation_bytes(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    checked_activation_bytes(path, max, 0)
}

fn activation_digest(bytes: &Option<Vec<u8>>) -> Option<String> {
    bytes
        .as_ref()
        .map(|value| bundle::hex(&Sha256::digest(value)))
}

fn reference_environment(p: &Profile, token: &str) -> Vec<u8> {
    format!("LUMA_MODEL_ENDPOINT=http://127.0.0.1:8081/v1\nLUMA_MODEL_NAME={}\nLUMA_MODEL_API_KEY={token}\n", p.id).into_bytes()
}

fn activation_snapshot(
    state: &Path,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
    Ok((
        activation_bytes(&state.join("model-selection.json"), 4096)?,
        activation_bytes(&state.join(REFERENCE_ENV), 4096)?,
        activation_bytes(&state.join("model-auth/api-key"), 64)?,
    ))
}

struct PriorRunning {
    profile: Profile,
    hashes: (Option<String>, Option<String>, Option<String>),
}

fn prior_snapshot_at(state: &Path) -> Result<PriorRunning> {
    activation_absent(state)?;
    let profile = selected_at(state)?;
    let (selection, env, key) = activation_snapshot(state)?;
    let key_bytes = key.as_deref().ok_or("running model credential missing")?;
    let token = std::str::from_utf8(key_bytes)?;
    let expected_selection =
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":profile.id}))?;
    let expected_env = reference_environment(&profile, token);
    if token.len() != 64
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || selection.as_deref() != Some(expected_selection.as_slice())
        || env.as_deref() != Some(expected_env.as_slice())
    {
        return Err("running model configuration inconsistent; preserve state".into());
    }
    Ok(PriorRunning {
        profile,
        hashes: (
            activation_digest(&selection),
            activation_digest(&env),
            activation_digest(&key),
        ),
    })
}

/// A nonzero `is-active` result conflates ordinary inactivity, failed units
/// and manager/query errors. Only an exact, loaded service state is usable
/// before a stop request that may need prior-worker recovery.
fn model_unit_running(success: bool, output: &[u8]) -> Result<bool> {
    if !success || output.len() > 256 {
        return Err("model service status unavailable; active model preserved".into());
    }
    let mut load = None;
    let mut active = None;
    let mut sub = None;
    for line in std::str::from_utf8(output)?.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            if load.replace(value).is_some() {
                return Err("duplicate model service load state".into());
            }
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            if active.replace(value).is_some() {
                return Err("duplicate model service active state".into());
            }
        } else if let Some(value) = line.strip_prefix("SubState=") {
            if sub.replace(value).is_some() {
                return Err("duplicate model service substate".into());
            }
        } else {
            return Err("unexpected model service status output".into());
        }
    }
    match (load, active, sub) {
        (Some("loaded"), Some("active"), Some("running")) => Ok(true),
        (Some("loaded"), Some("inactive"), Some("dead")) => Ok(false),
        _ => Err("model service state uncertain; active model preserved".into()),
    }
}

fn running_prior(var: &Path) -> Result<Option<PriorRunning>> {
    if model_service_running()? {
        Ok(Some(prior_snapshot_at(&var.join(STATE))?))
    } else {
        Ok(None)
    }
}

fn model_service_running() -> Result<bool> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--all",
            "--property=LoadState,ActiveState,SubState",
            "--no-pager",
            "luma-model.service",
        ])
        .output()?;
    model_unit_running(output.status.success(), &output.stdout)
}

fn restore_prior(var: &Path, prior: PriorRunning) -> Result<()> {
    let state = var.join(STATE);
    {
        let _runtime = runtime_lock(var, false)?;
        activation_absent(&state)?;
        match fs::symlink_metadata(state.join("model-disabled")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("model recovery disablement is active; preserve state".into()),
        }
        let current = prior_snapshot_at(&state)?;
        if current.profile.id != prior.profile.id || current.hashes != prior.hashes {
            return Err("prior model configuration changed; preserve state".into());
        }
        verify_file(
            &state
                .join("models")
                .join(format!("{}.gguf", prior.profile.id)),
            &prior.profile,
        )?;
    }
    command(
        "/usr/bin/systemctl",
        &["reset-failed", "luma-model.service"],
    )?;
    command("/usr/bin/systemctl", &["restart", "luma-model.service"])?;
    Ok(())
}

fn begin_activation(state: &Path, p: &Profile) -> Result<Activation> {
    activation_absent(state)?;
    begin_activation_records(state, p)
}

// Normal callers pass activation_absent above. The sole quarantine-tolerant
// caller is reviewed completed rollback under both locks; this record-writing
// helper never removes quarantine or permits ordinary startup through it.
fn begin_activation_records(state: &Path, p: &Profile) -> Result<Activation> {
    activation_records_absent(state)?;
    validate_rollback_slot(state)?;
    let (selection, env, key) = activation_snapshot(state)?;
    let backup = PriorBackup {
        schema_version: 1,
        candidate: p.id.clone(),
        selection,
        environment: env,
        key,
    };
    let bytes = serde_json::to_vec(&backup)?;
    if bytes.len() as u64 > MAX_PRIOR_BACKUP {
        return Err("oversized prior model backup".into());
    }
    // Save and sync before publishing the marker or changing worker-visible
    // files. A crash/partial write leaves an orphan fence, not a new activation.
    let mut saved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state.join(PRIOR_BACKUP))?;
    saved.write_all(&bytes)?;
    saved.sync_all()?;
    File::open(state)?.sync_all()?;
    if prior_backup_bytes(state)?.as_deref() != Some(bytes.as_slice()) {
        return Err("model prior backup changed during preparation".into());
    }
    let (selection, env, key) = activation_snapshot(state)?;
    if selection != backup.selection || env != backup.environment || key != backup.key {
        return Err("prior model changed during backup; preserve orphan state".into());
    }
    let record = Activation {
        schema_version: 2,
        candidate: p.id.clone(),
        prior_selection_sha256: activation_digest(&selection),
        prior_env_sha256: activation_digest(&env),
        prior_key_sha256: activation_digest(&key),
        prior_backup_sha256: Some(bundle::hex(&Sha256::digest(&bytes))),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state.join(ACTIVATION))?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    File::open(state)?.sync_all()?;
    Ok(record)
}

struct ActivationObservation {
    record: Activation,
    marker: Vec<u8>,
    phase: &'static str,
    candidate_consistent: bool,
    review: String,
    hashes: (Option<String>, Option<String>, Option<String>),
    backup_digest: Option<String>,
    restore_available: bool,
}

fn observe_activation(
    state: &Path,
    p: &Profile,
    verify_weight: bool,
) -> Result<ActivationObservation> {
    let marker =
        activation_bytes(&state.join(ACTIVATION), 4096)?.ok_or("no pending model activation")?;
    let record: Activation = serde_json::from_slice(&marker)?;
    if serde_json::to_vec(&record)? != marker
        || !matches!(
            (record.schema_version, record.prior_backup_sha256.is_some()),
            (1, false) | (2, true)
        )
        || record.candidate != p.id
        || [
            &record.prior_selection_sha256,
            &record.prior_env_sha256,
            &record.prior_key_sha256,
            &record.prior_backup_sha256,
        ]
        .into_iter()
        .flatten()
        .any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("invalid retained model activation; preserve state".into());
    }
    let backup = bound_prior_backup(state, &record)?;
    let backup_digest = backup.as_ref().and(record.prior_backup_sha256.clone());
    let (selection, env, key) = activation_snapshot(state)?;
    let hashes = (
        activation_digest(&selection),
        activation_digest(&env),
        activation_digest(&key),
    );
    let unchanged = hashes.0 == record.prior_selection_sha256
        && hashes.1 == record.prior_env_sha256
        && hashes.2 == record.prior_key_sha256;
    let token = key
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let candidate = if let (Some(selection), Some(env), Some(token)) =
        (selection.as_deref(), env.as_deref(), token)
    {
        token.len() == 64
            && token.bytes().all(|b| b.is_ascii_hexdigit())
            && selection == serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id}))?
            && env == reference_environment(p, token)
            && (!verify_weight
                || verify_file(&state.join("models").join(format!("{}.gguf", p.id)), p).is_ok())
    } else {
        false
    };
    let phase = if unchanged {
        "unchanged_prior_state"
    } else if candidate {
        "consistent_candidate_committed"
    } else {
        "partial_or_conflicting_state"
    };
    let mut digest = Sha256::new();
    digest.update(b"luma-model-activation-review-v1\0");
    digest.update(&marker);
    digest.update(serde_json::to_vec(&hashes)?);
    digest.update(phase.as_bytes());
    digest.update(p.sha256.as_bytes());
    if record.schema_version == 2 {
        // Preserve schema-1 review semantics for existing retained markers.
        digest.update(serde_json::to_vec(&backup_digest)?);
    }
    Ok(ActivationObservation {
        record,
        marker,
        phase,
        candidate_consistent: candidate,
        review: bundle::hex(&digest.finalize()),
        hashes,
        backup_digest,
        restore_available: backup.is_some(),
    })
}

fn clear_activation(state: &Path, observation: &ActivationObservation) -> Result<()> {
    if activation_digest(&prior_backup_bytes(state)?) != observation.backup_digest {
        return Err("model prior backup changed before clearance; preserve state".into());
    }
    let (selection, env, key) = activation_snapshot(state)?;
    if (
        activation_digest(&selection),
        activation_digest(&env),
        activation_digest(&key),
    ) != observation.hashes
    {
        return Err("model configuration changed before clearance; preserve state".into());
    }
    if activation_bytes(&state.join(ACTIVATION), 4096)? != Some(observation.marker.clone()) {
        return Err("model activation marker changed; preserve state".into());
    }
    // Delete only the exact validated recovery file. Remove it first so every
    // interruption still leaves a marker that the existing review can inspect.
    if observation.backup_digest.is_some() {
        fs::remove_file(state.join(PRIOR_BACKUP))?;
        File::open(state)?.sync_all()?;
    }
    fs::remove_file(state.join(ACTIVATION))?;
    File::open(state)?.sync_all()?;
    Ok(())
}

fn finish_activation(state: &Path, p: &Profile, record: &Activation) -> Result<()> {
    let observation = observe_activation(state, p, false)?;
    if observation.record != *record || !observation.candidate_consistent {
        return Err("model activation files inconsistent; preserve pending marker".into());
    }
    retain_completed_prior(state, p, &observation)?;
    clear_activation(state, &observation)
}

fn reviewed_clear_activation(state: &Path, p: &Profile, mode: &str, reviewed: &str) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let expected_phase = match mode {
        "--abort-unchanged" => "unchanged_prior_state",
        "--publish-committed" => "consistent_candidate_committed",
        _ => return Err("unsupported model activation reconciliation".into()),
    };
    let observed = observe_activation(state, p, true)?;
    if observed.phase != expected_phase || observed.review != reviewed {
        return Err("model activation review differs or state is not safely clearable".into());
    }
    let current = observe_activation(state, p, true)?;
    if current.review != observed.review || current.phase != expected_phase {
        return Err("model activation changed after review".into());
    }
    if mode == "--publish-committed" {
        retain_completed_prior(state, p, &current)?;
    }
    clear_activation(state, &current)
}

fn reviewed_complete_candidate(state: &Path, p: &Profile, reviewed: &str) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let observed = observe_activation(state, p, true)?;
    if observed.phase != "partial_or_conflicting_state" || observed.review != reviewed {
        return Err("model activation review differs or candidate is not partial".into());
    }
    verify_file(&state.join("models").join(format!("{}.gguf", p.id)), p)?;
    let current = observe_activation(state, p, true)?;
    if current.phase != observed.phase || current.review != observed.review {
        return Err("model activation changed after review".into());
    }
    write_candidate_config(state, p)?;
    finish_activation(state, p, &current.record)
}

fn prior_restore_profile(
    backup: &PriorBackup,
    resolve: impl FnOnce(&str) -> Result<Profile>,
) -> Result<Option<Profile>> {
    match (&backup.selection, &backup.environment, &backup.key) {
        (None, None, None) => Ok(None),
        (Some(selection), Some(env), Some(key)) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Selection {
                schema_version: u32,
                id: String,
            }
            let selected: Selection = serde_json::from_slice(selection)
                .map_err(|_| "invalid saved prior model selection; preserve state")?;
            let prior = resolve(&selected.id)?;
            let token = std::str::from_utf8(key)?;
            if selected.schema_version != 1
                || prior.id != selected.id
                || *selection
                    != serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":prior.id}))?
                || token.len() != 64
                || !token.bytes().all(|b| b.is_ascii_hexdigit())
                || *env != reference_environment(&prior, token)
            {
                return Err("prior model configuration is not consistent; preserve state".into());
            }
            Ok(Some(prior))
        }
        _ => Err("mixed or legacy prior configuration cannot be restored by this path".into()),
    }
}

fn restore_config_file(
    path: &Path,
    bytes: &Option<Vec<u8>>,
    mode: u32,
    group: Option<&str>,
) -> Result<()> {
    // Missing means exact removal of one previously inspected file, never a
    // directory, model weight, disablement marker or recursive cleanup.
    activation_bytes(path, 4096)?;
    if let Some(bytes) = bytes {
        platform::write_atomic(path, bytes, 0o600)?;
        // Do not let the maintenance process's restrictive umask silently
        // make restored credentials/environments unreadable by their service.
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        if let Some(group) = group {
            command(
                "/usr/bin/chown",
                &[group, path.to_str().ok_or("invalid model path")?],
            )?;
        }
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
            .sync_all()?;
    } else {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    File::open(path.parent().ok_or("missing model config parent")?)?.sync_all()?;
    Ok(())
}

fn write_prior_configuration(state: &Path, backup: &PriorBackup) -> Result<()> {
    let auth = state.join("model-auth");
    let auth_present = match fs::symlink_metadata(&auth) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if backup.key.is_some() || auth_present {
        safe_dir(&auth)?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o750))?;
        command(
            "/usr/bin/chown",
            &["0:989", auth.to_str().ok_or("invalid model auth path")?],
        )?;
        restore_config_file(&auth.join("api-key"), &backup.key, 0o640, Some("0:989"))?;
    }
    restore_config_file(
        &state.join(REFERENCE_ENV),
        &backup.environment,
        0o640,
        Some("0:990"),
    )?;
    restore_config_file(
        &state.join("model-selection.json"),
        &backup.selection,
        0o644,
        None,
    )
}

fn reviewed_restore_configuration(
    state: &Path,
    candidate: &Profile,
    reviewed: &str,
    resolve: impl FnOnce(&str) -> Result<Profile>,
) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let observed = observe_activation(state, candidate, true)?;
    if observed.review != reviewed {
        return Err("model restoration review changed; inspect again".into());
    }
    let backup = bound_prior_backup(state, &observed.record)?
        .ok_or("no retained prior model bytes; restoration unavailable")?;
    let prior = prior_restore_profile(&backup, resolve)?;
    if let Some(prior) = &prior {
        verify_file(
            &state.join("models").join(format!("{}.gguf", prior.id)),
            prior,
        )?;
    }
    let current = observe_activation(state, candidate, true)?;
    if current.review != observed.review {
        return Err("model activation changed before restoration".into());
    }
    write_prior_configuration(state, &backup)?;
    // Retain both records across every failed write. An explicit retry starts
    // with a NEW review of its partially restored state; no automatic replay.
    let restored = observe_activation(state, candidate, true)?;
    if restored.record != observed.record || restored.phase != "unchanged_prior_state" {
        return Err("prior model restoration did not reproduce the saved hashes".into());
    }
    if let Some(prior) = &prior {
        verify_file(
            &state.join("models").join(format!("{}.gguf", prior.id)),
            prior,
        )?;
    }
    clear_activation(state, &restored)
}

fn observe_orphan_backup(state: &Path) -> Result<(String, bool)> {
    match fs::symlink_metadata(state.join(ACTIVATION)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("pending marker requires activation reconciliation".into()),
    }
    let bytes = prior_backup_bytes(state)?.ok_or("no retained model activation state")?;
    let backup = decode_prior_backup(&bytes)?;
    let (selection, env, key) = activation_snapshot(state)?;
    let unchanged = selection == backup.selection && env == backup.environment && key == backup.key;
    let mut digest = Sha256::new();
    digest.update(b"luma-model-orphan-prior-review-v1\0");
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&(
        activation_digest(&selection),
        activation_digest(&env),
        activation_digest(&key),
    ))?);
    Ok((bundle::hex(&digest.finalize()), unchanged))
}

fn reviewed_discard_orphan_backup(state: &Path, reviewed: &str) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let before = observe_orphan_backup(state)?;
    if !before.1 || before.0 != reviewed || observe_orphan_backup(state)? != before {
        return Err("orphan prior backup differs from unchanged state; preserve bytes".into());
    }
    fs::remove_file(state.join(PRIOR_BACKUP))?;
    File::open(state)?.sync_all()?;
    Ok(())
}

pub fn activation_reconcile(action: Option<(&str, &str)>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let _runtime = runtime_lock(var, false)?;
    let state = var.join(STATE);
    if activation_bytes(&state.join(ACTIVATION), 4096)?.is_none() {
        let (review, unchanged) = observe_orphan_backup(&state)?;
        match action {
            Some(("--discard-orphan-backup", reviewed)) => {
                reviewed_discard_orphan_backup(&state, reviewed)?;
                println!(
                    "{}",
                    serde_json::json!({"schema_version":1,"orphan_backup_removed":true,
                    "configuration_changed":false,"worker_started":false,"reservation":false})
                );
            }
            None => println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":"orphan_prior_backup",
                "review_sha256":review,"discardable":unchanged,"worker_started":false,"mutation_performed":false})
            ),
            _ => return Err("orphan backup permits only reviewed unchanged-state discard".into()),
        }
        return Ok(());
    }
    let marker =
        activation_bytes(&state.join(ACTIVATION), 4096)?.ok_or("no pending model activation")?;
    let record: Activation = serde_json::from_slice(&marker)?;
    let p = profile(&record.candidate)?;
    let observation = observe_activation(&state, &p, true)?;
    match action {
        Some(("--restore-prior", reviewed)) => {
            reviewed_restore_configuration(&state, &p, reviewed, profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"cleared":true,
                "phase":"prior_configuration_restored","worker_started":false,"reservation":false})
            );
        }
        Some(("--complete-candidate", reviewed)) => {
            reviewed_complete_candidate(&state, &p, reviewed)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"cleared":true,
                "phase":"partial_candidate_completed","worker_started":false,
                "reservation":false})
            );
        }
        Some((mode, reviewed)) => {
            reviewed_clear_activation(&state, &p, mode, reviewed)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"cleared":true,
                "phase":observation.phase,"worker_started":false,"reservation":false})
            );
        }
        None => {
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":observation.phase,
                "candidate":p.id,"review_sha256":observation.review,
                "prior_backup_available":observation.restore_available,
                "worker_started":false,"mutation_performed":false,
                "clearable":observation.phase != "partial_or_conflicting_state",
                "completion_requires_write":observation.phase == "partial_or_conflicting_state"})
            );
        }
    }
    Ok(())
}

// One root-private completed-activation undo record. It carries credentials;
// neither this data nor its hashes are a resource lease, TPM anchor or grant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedRollback {
    schema_version: u32,
    catalog_sha256: String,
    completed_profile: String,
    completed_weight_sha256: String,
    completed_marker_sha256: String,
    completed_hashes: (Option<String>, Option<String>, Option<String>),
    prior: PriorBackup,
}

fn rollback_bytes(state: &Path) -> Result<Option<Vec<u8>>> {
    checked_activation_bytes_with_mode(&state.join(ROLLBACK), MAX_ROLLBACK, 0, 0o077)
}

fn decode_rollback(bytes: &[u8]) -> Result<CompletedRollback> {
    let record: CompletedRollback = serde_json::from_slice(bytes)
        .map_err(|_| "invalid private completed model rollback record; preserve state")?;
    let hashes = [
        record.completed_hashes.0.as_ref(),
        record.completed_hashes.1.as_ref(),
        record.completed_hashes.2.as_ref(),
        Some(&record.completed_weight_sha256),
        Some(&record.completed_marker_sha256),
        Some(&record.catalog_sha256),
    ];
    if serde_json::to_vec(&record)? != bytes
        || record.schema_version != 1
        || record.completed_profile != record.prior.candidate
        || hashes.iter().any(|hash| {
            hash.map_or(true, |hash| {
                hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
    {
        return Err("invalid completed model rollback record; preserve state".into());
    }
    decode_prior_backup(&serde_json::to_vec(&record.prior)?)?;
    Ok(record)
}

fn validate_rollback_slot(state: &Path) -> Result<()> {
    if let Some(bytes) = rollback_bytes(state)? {
        decode_rollback(&bytes)?;
    }
    Ok(())
}

fn retain_completed_prior(
    state: &Path,
    p: &Profile,
    observed: &ActivationObservation,
) -> Result<()> {
    let Some(prior) = bound_prior_backup(state, &observed.record)? else {
        // Existing markers and interrupted backup cleanup cannot invent bytes.
        return Ok(());
    };
    if !observed.candidate_consistent || observed.record.candidate != p.id {
        return Err("cannot retain rollback for inconsistent candidate files".into());
    }
    if let Some(existing) = rollback_bytes(state)? {
        // A single bounded slot replaces only inspected safe, canonical data.
        // Unsafe or unknown state is not overwritten to make activation pass.
        decode_rollback(&existing)?;
    }
    let record = CompletedRollback {
        schema_version: 1,
        catalog_sha256: bundle::hex(&Sha256::digest(CATALOG.as_bytes())),
        completed_profile: p.id.clone(),
        completed_weight_sha256: p.sha256.clone(),
        completed_marker_sha256: bundle::hex(&Sha256::digest(&observed.marker)),
        completed_hashes: observed.hashes.clone(),
        prior,
    };
    let bytes = serde_json::to_vec(&record)?;
    if bytes.len() as u64 > MAX_ROLLBACK {
        return Err("oversized completed model rollback record".into());
    }
    platform::write_atomic(&state.join(ROLLBACK), &bytes, 0o600)?;
    if rollback_bytes(state)?.as_deref() != Some(bytes.as_slice())
        || observe_activation(state, p, false)?.review != observed.review
    {
        return Err("model state changed while retaining completed rollback".into());
    }
    Ok(())
}

struct RollbackObservation {
    record: CompletedRollback,
    bytes: Vec<u8>,
    completed: Profile,
    prior: Option<Profile>,
    phase: &'static str,
    review: String,
    restorable: bool,
}

fn observe_rollback(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<RollbackObservation> {
    activation_records_absent(state)?;
    let bytes = rollback_bytes(state)?.ok_or("no completed model rollback record")?;
    let record = decode_rollback(&bytes)?;
    let completed = resolve(&record.completed_profile)?;
    if record.catalog_sha256 != bundle::hex(&Sha256::digest(CATALOG.as_bytes()))
        || completed.id != record.completed_profile
        || completed.sha256 != record.completed_weight_sha256
    {
        return Err("completed model catalog pin changed; rollback requires investigation".into());
    }
    let (selection, env, key) = activation_snapshot(state)?;
    let hashes = (
        activation_digest(&selection),
        activation_digest(&env),
        activation_digest(&key),
    );
    let prior = prior_restore_profile(&record.prior, resolve);
    let prior_valid = prior.as_ref().is_ok_and(|prior| {
        prior.as_ref().map_or(true, |prior| {
            verify_file(
                &state.join("models").join(format!("{}.gguf", prior.id)),
                prior,
            )
            .is_ok()
        })
    });
    let phase = if hashes != record.completed_hashes {
        "completed_configuration_changed"
    } else if !prior_valid {
        "prior_configuration_or_weights_unavailable"
    } else {
        "completed_configuration_restorable"
    };
    let prior = prior.unwrap_or(None);
    let mut digest = Sha256::new();
    digest.update(b"luma-model-completed-rollback-review-v1\0");
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&hashes)?);
    digest.update(phase.as_bytes());
    digest.update(completed.sha256.as_bytes());
    if let Some(prior) = &prior {
        digest.update(prior.sha256.as_bytes());
    }
    Ok(RollbackObservation {
        record,
        bytes,
        completed,
        prior,
        phase,
        review: bundle::hex(&digest.finalize()),
        restorable: phase == "completed_configuration_restorable",
    })
}

fn reviewed_completed_rollback(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let observed = observe_rollback(state, resolve)?;
    if observed.review != reviewed || !observed.restorable {
        return Err("completed model rollback review changed or restoration is unavailable".into());
    }
    // Re-observe after possibly blocking weight verification, before any fence
    // or configuration write. The installed wrapper holds both kernel locks.
    let current = observe_rollback(state, resolve)?;
    if current.review != observed.review || !current.restorable {
        return Err("completed model state changed before rollback".into());
    }
    // Retains the PRE-ROLLBACK candidate bytes. If restoration is interrupted,
    // existing activation reconciliation can explicitly restore this state;
    // it must never automatically replay or pretend rollback finished.
    let activation = begin_activation_records(state, &observed.completed)?;
    if (
        activation.prior_selection_sha256.clone(),
        activation.prior_env_sha256.clone(),
        activation.prior_key_sha256.clone(),
    ) != observed.record.completed_hashes
        || rollback_bytes(state)?.as_deref() != Some(observed.bytes.as_slice())
    {
        return Err("completed model state changed during fence creation; preserve state".into());
    }
    write_prior_configuration(state, &observed.record.prior)?;
    let (selection, env, key) = activation_snapshot(state)?;
    if selection != observed.record.prior.selection
        || env != observed.record.prior.environment
        || key != observed.record.prior.key
    {
        return Err("completed model rollback did not reproduce exact saved settings".into());
    }
    if let Some(prior) = &observed.prior {
        verify_file(
            &state.join("models").join(format!("{}.gguf", prior.id)),
            prior,
        )?;
    }
    if rollback_bytes(state)?.as_deref() != Some(observed.bytes.as_slice()) {
        return Err("completed model rollback changed before consumption; preserve fence".into());
    }
    let restored = observe_activation(state, &observed.completed, false)?;
    if restored.record != activation
        || restored.hashes
            != (
                activation_digest(&observed.record.prior.selection),
                activation_digest(&observed.record.prior.environment),
                activation_digest(&observed.record.prior.key),
            )
    {
        return Err("rollback marker or restored configuration changed; preserve state".into());
    }
    // Consume this exact one-step record BEFORE releasing the fence. A crash
    // here still keeps the pre-rollback backup and requires explicit recovery.
    fs::remove_file(state.join(ROLLBACK))?;
    File::open(state)?.sync_all()?;
    clear_activation(state, &restored)
}

pub fn rollback_reconcile(action: Option<(&str, &str)>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let _runtime = runtime_lock(var, false)?;
    let state = var.join(STATE);
    match action {
        Some(("--restore-prior", reviewed)) => {
            reviewed_completed_rollback(&state, reviewed, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,
                "prior_configuration_restored":true,"rollback_record_consumed":true,
                "worker_started":false,"readiness_proven":false,"reservation":false})
            );
        }
        None => {
            let observed = observe_rollback(&state, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,
                "phase":observed.phase,"candidate":observed.completed.id,
                "prior_model":observed.prior.as_ref().map(|prior| &prior.id),
                "manual_only_target":observed.restorable && observed.prior.is_none(),
                "review_sha256":observed.review,"restorable":observed.restorable,
                "worker_started":false,"mutation_performed":false})
            );
        }
        _ => return Err("unsupported completed model rollback action".into()),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RestartStage {
    Reload,
    Restart,
    Health,
    Worker,
    Reference,
    Validation,
}

struct RestartFailure {
    stage: RestartStage,
    error: Box<dyn std::error::Error>,
}

fn checked_restart_steps(
    mut step: impl FnMut(RestartStage) -> Result<()>,
) -> std::result::Result<(), RestartFailure> {
    for stage in [
        RestartStage::Reload,
        RestartStage::Restart,
        RestartStage::Health,
        RestartStage::Worker,
        RestartStage::Reference,
    ] {
        step(stage).map_err(|error| RestartFailure { stage, error })?;
    }
    Ok(())
}

fn finish_reconfiguration(
    restart: impl FnOnce() -> std::result::Result<(), RestartFailure>,
    fence: impl FnOnce(RestartStage) -> Result<()>,
    stop: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let Err(failure) = restart() else {
        return Ok(());
    };
    // Publish before requesting stop, so failure/on-failure restart/next boot
    // cannot silently start a new worker. Still try stop if publication fails;
    // neither a stop request nor this local fence proves resources returned.
    let quarantine = match fence(failure.stage) {
        Ok(()) => "durable model quarantine published".to_owned(),
        Err(error) => format!("model quarantine publication failed; preserve state: {error}"),
    };
    let stopped = match stop() {
        Ok(()) => "worker stop requested".to_owned(),
        Err(error) => format!("worker stop request failed: {error}"),
    };
    Err(format!("{}; failed model reconfiguration stage {:?}; {quarantine}; {stopped}; no rollback or readiness claimed",
        failure.error, failure.stage).into())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Quarantine {
    schema_version: u32,
    incident_id: String,
    candidate: String,
    candidate_sha256: String,
    catalog_sha256: String,
    failed_stage: RestartStage,
}

fn publish_quarantine(state: &Path, candidate: &Profile, failed_stage: RestartStage) -> Result<()> {
    safe_dir(state)?;
    let mut incident = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut incident)?;
    let record = Quarantine {
        schema_version: 1,
        incident_id: bundle::hex(&incident),
        candidate: candidate.id.clone(),
        candidate_sha256: candidate.sha256.clone(),
        catalog_sha256: bundle::hex(&Sha256::digest(CATALOG.as_bytes())),
        failed_stage,
    };
    // Never overwrite unknown or existing state; even a partial record fences
    // normal activation/startup. Do not persist exception text or credentials.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state.join(QUARANTINE))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let bytes = serde_json::to_vec(&record)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(state)?.sync_all()?;
    if quarantine_bytes(state)?.as_deref() != Some(bytes.as_slice()) {
        return Err("model quarantine changed during publication; preserve state".into());
    }
    Ok(())
}

fn quarantine_bytes(state: &Path) -> Result<Option<Vec<u8>>> {
    checked_activation_bytes_with_mode(&state.join(QUARANTINE), 4096, 0, 0o077)
}

struct QuarantineObservation {
    record: Quarantine,
    bytes: Vec<u8>,
    hashes: (Option<String>, Option<String>, Option<String>),
    current_profile: Option<Profile>,
    phase: &'static str,
    review: String,
    clearable: bool,
}

fn observe_quarantine(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<QuarantineObservation> {
    activation_records_absent(state)?;
    let bytes = quarantine_bytes(state)?.ok_or("no retained model quarantine")?;
    let record: Quarantine = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid retained model quarantine; preserve state")?;
    let candidate = resolve(&record.candidate)?;
    if serde_json::to_vec(&record)? != bytes
        || record.schema_version != 1
        || record.incident_id.len() != 32
        || !record.incident_id.bytes().all(|b| b.is_ascii_hexdigit())
        || candidate.id != record.candidate
        || candidate.sha256 != record.candidate_sha256
        || record.catalog_sha256 != bundle::hex(&Sha256::digest(CATALOG.as_bytes()))
    {
        return Err("model quarantine catalog or canonical record changed; preserve state".into());
    }
    let (selection, environment, key) = activation_snapshot(state)?;
    let snapshot = PriorBackup {
        schema_version: 1,
        candidate: record.candidate.clone(),
        selection,
        environment,
        key,
    };
    let hashes = (
        activation_digest(&snapshot.selection),
        activation_digest(&snapshot.environment),
        activation_digest(&snapshot.key),
    );
    let current = prior_restore_profile(&snapshot, resolve);
    let valid = current.as_ref().is_ok_and(|current| {
        current.as_ref().map_or(true, |p| {
            verify_file(&state.join("models").join(format!("{}.gguf", p.id)), p).is_ok()
        })
    });
    // Weight verification can block. Freshly recheck both pending fences, the
    // quarantine and exact config before forming a usable review/clearance.
    activation_records_absent(state)?;
    let (selection, environment, key) = activation_snapshot(state)?;
    if selection != snapshot.selection
        || environment != snapshot.environment
        || key != snapshot.key
        || quarantine_bytes(state)?.as_deref() != Some(bytes.as_slice())
    {
        return Err("model quarantine or configuration changed during inspection".into());
    }
    let current_profile = current.unwrap_or(None);
    let phase = if !valid {
        "configuration_or_weights_unavailable"
    } else if current_profile.is_none() {
        "manual_only_configuration"
    } else {
        "consistent_selected_configuration"
    };
    let mut digest = Sha256::new();
    digest.update(b"luma-model-quarantine-review-v1\0");
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&hashes)?);
    digest.update(phase.as_bytes());
    if let Some(p) = &current_profile {
        digest.update(p.sha256.as_bytes());
    }
    Ok(QuarantineObservation {
        record,
        bytes,
        hashes,
        current_profile,
        phase,
        review: bundle::hex(&digest.finalize()),
        clearable: valid,
    })
}

fn reviewed_clear_quarantine(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<()> {
    tpm::decode::<32>(reviewed)?;
    let observed = observe_quarantine(state, resolve)?;
    if !observed.clearable || observed.review != reviewed {
        return Err(
            "model quarantine review changed or current configuration is not clearable".into(),
        );
    }
    let current = observe_quarantine(state, resolve)?;
    if !current.clearable || current.review != observed.review {
        return Err("model quarantine changed after review".into());
    }
    activation_records_absent(state)?;
    let (selection, environment, key) = activation_snapshot(state)?;
    if (
        activation_digest(&selection),
        activation_digest(&environment),
        activation_digest(&key),
    ) != current.hashes
        || quarantine_bytes(state)?.as_deref() != Some(current.bytes.as_slice())
    {
        return Err("model quarantine/configuration changed before clearance".into());
    }
    fs::remove_file(state.join(QUARANTINE))?;
    File::open(state)?.sync_all()?;
    Ok(())
}

struct IncompleteQuarantineObservation {
    bytes: Vec<u8>,
    identity: (u64, u64, i64, i64),
    hashes: (Option<String>, Option<String>, Option<String>),
    current_profile: Option<Profile>,
    archive: String,
    review: String,
}

fn incomplete_quarantine_bytes(state: &Path) -> Result<(Vec<u8>, (u64, u64, i64, i64))> {
    let before = fs::symlink_metadata(state.join(QUARANTINE))?;
    let bytes = quarantine_bytes(state)?.ok_or("no retained model quarantine")?;
    // An interrupted exclusive write can leave empty/truncated JSON. Complete
    // JSON (including unknown future schemas) and other malformed data require
    // their own policy; this path must never reinterpret or discard them.
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Err(error) if error.is_eof() => (),
        _ => return Err("quarantine is not incomplete JSON; preserve state".into()),
    }
    let after = fs::symlink_metadata(state.join(QUARANTINE))?;
    let identity = |m: &fs::Metadata| (m.dev(), m.ino(), m.ctime(), m.ctime_nsec());
    if identity(&before) != identity(&after) {
        return Err("incomplete quarantine changed during inspection".into());
    }
    Ok((bytes, identity(&after)))
}

fn observe_incomplete_quarantine(
    state: &Path,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<IncompleteQuarantineObservation> {
    activation_records_absent(state)?;
    let (bytes, identity) = incomplete_quarantine_bytes(state)?;
    let (selection, environment, key) = activation_snapshot(state)?;
    let snapshot = PriorBackup {
        schema_version: 1,
        candidate: String::new(),
        selection,
        environment,
        key,
    };
    let current_profile = prior_restore_profile(&snapshot, resolve)?;
    if let Some(p) = &current_profile {
        verify_file(&state.join("models").join(format!("{}.gguf", p.id)), p)?;
    }
    activation_records_absent(state)?;
    let (selection, environment, key) = activation_snapshot(state)?;
    if (selection, environment, key)
        != (
            snapshot.selection.clone(),
            snapshot.environment.clone(),
            snapshot.key.clone(),
        )
        || incomplete_quarantine_bytes(state)? != (bytes.clone(), identity)
    {
        return Err("incomplete quarantine/configuration changed during inspection".into());
    }
    let hashes = (
        activation_digest(&snapshot.selection),
        activation_digest(&snapshot.environment),
        activation_digest(&snapshot.key),
    );
    let archive = format!(
        "model-quarantine.retained.{}",
        bundle::hex(&Sha256::digest(&bytes))
    );
    if let Some(retained) =
        checked_activation_bytes_with_mode(&state.join(&archive), 4096, 0, 0o077)?
    {
        if retained != bytes {
            return Err("incomplete quarantine retention conflict; preserve state".into());
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-model-incomplete-quarantine-review-v1\0");
    digest.update(CATALOG.as_bytes());
    digest.update(&bytes);
    digest.update(serde_json::to_vec(&identity)?);
    digest.update(serde_json::to_vec(&hashes)?);
    if let Some(p) = &current_profile {
        digest.update(p.sha256.as_bytes());
    }
    Ok(IncompleteQuarantineObservation {
        bytes,
        identity,
        hashes,
        current_profile,
        archive,
        review: bundle::hex(&digest.finalize()),
    })
}

fn reviewed_retain_incomplete_quarantine(
    state: &Path,
    reviewed: &str,
    resolve: &impl Fn(&str) -> Result<Profile>,
) -> Result<String> {
    tpm::decode::<32>(reviewed)?;
    let observed = observe_incomplete_quarantine(state, resolve)?;
    if observed.review != reviewed {
        return Err("incomplete quarantine review changed; preserve state".into());
    }
    let archive = state.join(&observed.archive);
    match checked_activation_bytes_with_mode(&archive, 4096, 0, 0o077)? {
        Some(bytes) if bytes == observed.bytes => (),
        Some(_) => return Err("incomplete quarantine retention conflict; preserve state".into()),
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
    // Re-sync an existing exact archive too: a retry must not depend on whether
    // a previous controller reached fsync. Preserve any partial/conflicting
    // archive and keep the original startup fence on retention errors. A later
    // directory-sync failure after unlink has an uncertain clearance outcome;
    // the retained private bytes are never deleted by this path.
    let retained = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?;
    retained.sync_all()?;
    File::open(state)?.sync_all()?;
    if checked_activation_bytes_with_mode(&archive, 4096, 0, 0o077)?.as_deref()
        != Some(observed.bytes.as_slice())
    {
        return Err("incomplete quarantine retention changed; preserve state".into());
    }
    let current = observe_incomplete_quarantine(state, resolve)?;
    if current.review != observed.review {
        return Err("incomplete quarantine changed after retention; preserve state".into());
    }
    activation_records_absent(state)?;
    let (selection, environment, key) = activation_snapshot(state)?;
    if (
        activation_digest(&selection),
        activation_digest(&environment),
        activation_digest(&key),
    ) != current.hashes
        || incomplete_quarantine_bytes(state)? != (current.bytes, current.identity)
        || checked_activation_bytes_with_mode(&archive, 4096, 0, 0o077)?.as_deref()
            != Some(observed.bytes.as_slice())
    {
        return Err("incomplete quarantine/configuration changed before clearance".into());
    }
    fs::remove_file(state.join(QUARANTINE))?;
    File::open(state)?.sync_all()?;
    Ok(observed.archive)
}

pub fn quarantine_reconcile(action: Option<(&str, &str)>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let _runtime = runtime_lock(var, false)?;
    let state = var.join(STATE);
    match action {
        Some(("--inspect-incomplete", "")) => {
            let observed = observe_incomplete_quarantine(&state, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,
                "phase":"incomplete_json_quarantine", "review_sha256":observed.review,
                "retention_file":observed.archive,
                "current_model":observed.current_profile.as_ref().map(|p| &p.id),
                "manual_only":observed.current_profile.is_none(),
                "worker_started":false,"mutation_performed":false})
            );
        }
        Some(("--retain-incomplete", reviewed)) => {
            let archive = reviewed_retain_incomplete_quarantine(&state, reviewed, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"quarantine_cleared":true,
                "retention_file":archive,"worker_started":false,"readiness_proven":false,
                "reservation":false})
            );
        }
        Some(("--clear-consistent", reviewed)) => {
            reviewed_clear_quarantine(&state, reviewed, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"quarantine_cleared":true,
                "worker_started":false,"readiness_proven":false,"reservation":false})
            );
        }
        None => {
            let observed = observe_quarantine(&state, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":observed.phase,
                "failed_stage":observed.record.failed_stage,"candidate":observed.record.candidate,
                "incident_id":observed.record.incident_id,
                "current_model":observed.current_profile.as_ref().map(|p| &p.id),
                "manual_only":observed.clearable && observed.current_profile.is_none(),
                "review_sha256":observed.review,"clearable":observed.clearable,
                "worker_started":false,"mutation_performed":false})
            );
        }
        _ => return Err("unsupported model quarantine reconciliation".into()),
    }
    Ok(())
}

pub fn validation_reconcile(action: Option<(&str, &str)>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let _runtime = runtime_lock(var, false)?;
    let state = var.join(STATE);
    match action {
        Some(("--inspect-incomplete", "")) => {
            let observed = validation::inspect_incomplete(&state, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":"incomplete_validation_json",
                "review_sha256":observed.review,"retention_file":observed.archive,
                "current_model":observed.current.as_ref().map(|p| &p.id),
                "manual_only":observed.current.is_none(),"worker_started":false,"mutation_performed":false})
            );
        }
        Some(("--retain-incomplete", reviewed)) => {
            let archive = validation::retain_incomplete(&state, reviewed, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"validation_cleared":true,
                "retention_file":archive,"worker_started":false,"readiness_proven":false,"reservation":false})
            );
        }
        None => {
            let observed = validation::inspect(&state, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":"abandoned_validation",
                "review_sha256":observed.review,"retention_file":observed.archive,
                "current_model":observed.current.as_ref().map(|p| &p.id),
                "manual_only":observed.current.is_none(),"worker_started":false,"mutation_performed":false})
            );
        }
        Some(("--retain-abandoned", reviewed)) => {
            let archive = validation::retain_abandoned(&state, reviewed, &profile)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"validation_cleared":true,
                "retention_file":archive,"worker_started":false,"readiness_proven":false,"reservation":false})
            );
        }
        _ => return Err("unsupported model validation reconciliation".into()),
    }
    Ok(())
}

fn legacy_configuration_at(state: &Path) -> Result<Profile> {
    activation_absent(state)?;
    let p = selected_at(state)?;
    let selection = activation_bytes(&state.join("model-selection.json"), 4096)?
        .ok_or("legacy model selection missing")?;
    if selection != serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id}))? {
        return Err("legacy model selection is not canonical; preserve state".into());
    }
    let key = activation_bytes(&state.join("model-auth/api-key"), 64)?
        .ok_or("legacy model credential missing")?;
    let token = std::str::from_utf8(&key)?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid legacy model credential; preserve state".into());
    }
    let expected = reference_environment(&p, token);
    let legacy_dir = state.join("reference");
    let directory = fs::symlink_metadata(&legacy_dir)?;
    if !directory.is_dir()
        || directory.uid() != 990
        || directory.gid() != 990
        || directory.mode() & 0o7777 != 0o700
    {
        return Err("unsafe legacy reference directory; preserve state".into());
    }
    let legacy_file = legacy_dir.join("model.env");
    let legacy = checked_activation_bytes(&legacy_file, 4096, 990)?
        .ok_or("legacy reference environment missing")?;
    let metadata = fs::symlink_metadata(&legacy_file)?;
    if metadata.gid() != 990 || metadata.mode() & 0o7777 != 0o600 || legacy != expected {
        return Err("legacy reference environment differs; preserve state".into());
    }
    if let Some(current) = activation_bytes(&state.join(REFERENCE_ENV), 4096)? {
        if current != expected {
            return Err("root-owned reference environment differs; preserve state".into());
        }
    }
    Ok(p)
}

fn migrate_legacy_at(var: &Path, expected: &Profile) -> Result<()> {
    let state = var.join(STATE);
    let current = legacy_configuration_at(&state)?;
    if current.id != expected.id {
        return Err("legacy model selection changed; preserve state".into());
    }
    let _runtime = runtime_lock(var, true)?;
    let token = activation_bytes(&state.join("model-auth/api-key"), 64)?
        .ok_or("legacy model credential missing")?;
    let token = std::str::from_utf8(&token)?;
    let activation = begin_activation(&state, expected)?;
    let env = state.join(REFERENCE_ENV);
    platform::write_atomic(&env, &reference_environment(expected, token), 0o640)?;
    fs::set_permissions(&env, fs::Permissions::from_mode(0o640))?;
    command(
        "/usr/bin/chown",
        &["0:990", env.to_str().ok_or("invalid environment path")?],
    )?;
    finish_activation(&state, expected, &activation)
}

/// Explicit migration of one legacy installed model; no boot-time fallback to
/// the worker-writable environment and no automatic clearing of a crash fence.
pub fn migrate_legacy() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let p = legacy_configuration_at(&var.join(STATE))?;
    verify_file(
        &var.join(STATE)
            .join("models")
            .join(format!("{}.gguf", p.id)),
        &p,
    )?;
    command("/usr/bin/systemctl", &["stop", "luma-model.service"])?;
    migrate_legacy_at(var, &p)?;
    command("/usr/bin/systemctl", &["daemon-reload"])?;
    command(
        "/usr/bin/systemctl",
        &["reset-failed", "luma-model.service"],
    )?;
    command(
        "/usr/bin/systemctl",
        &["restart", "luma-model.service", "luma-reference.service"],
    )?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"legacy_model_migrated":p.id,
        "legacy_file_removed":false,"worker_restart_requested":true})
    );
    Ok(())
}

/// Advisory model preflight. Cached-byte verification uses a temporary broker
/// lease, but reserves no future serving capacity and changes no model settings.
fn preflight_at(
    var: &Path,
    p: &Profile,
    admit: impl FnOnce(&Profile, u64, bool) -> Result<()>,
) -> Result<()> {
    let state = var.join(STATE);
    activation_absent(&state)?;
    validate_rollback_slot(&state)?;
    let metadata = fs::symlink_metadata(&state)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("unsafe model preflight state directory".into());
    }
    let models = state.join("models");
    let target = match fs::symlink_metadata(&models) {
        Ok(m) if m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 => models.as_path(),
        Ok(_) => return Err("unsafe model cache directory; active model preserved".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => state.as_path(),
        Err(error) => return Err(error.into()),
    };
    let cached = match fs::symlink_metadata(models.join(format!("{}.gguf", p.id))) {
        Ok(_) => {
            verify_file(&models.join(format!("{}.gguf", p.id)), p)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    admit(p, available_space(target)?, cached)
}

fn check_preflight(p: &Profile, free: u64, cached: bool) -> Result<()> {
    if cached {
        check_cached(p, free)
    } else {
        check(p, free)
    }
}

fn install_after_preflight<P>(
    preflight: impl FnOnce() -> Result<()>,
    prepare: impl FnOnce() -> Result<Option<P>>,
    stop: impl FnOnce() -> Result<()>,
    activate: impl FnOnce() -> Result<()>,
    restart: impl FnOnce() -> Result<()>,
    recover: impl FnOnce(P) -> Result<()>,
) -> Result<()> {
    preflight()?;
    let prior = prepare()?;
    if let Err(error) = stop() {
        return if let Some(prior) = prior {
            match recover(prior) {
                Ok(()) => Err(format!(
                    "{error}; unchanged prior model restart requested after failed stop"
                )
                .into()),
                Err(recovery) => Err(format!(
                    "{error}; prior model not restarted after failed stop: {recovery}"
                )
                .into()),
            }
        } else {
            Err(error)
        };
    }
    if let Err(error) = activate() {
        return if let Some(prior) = prior {
            match recover(prior) {
                Ok(()) => Err(format!(
                    "{error}; unchanged prior model restart requested after failed activation"
                )
                .into()),
                Err(recovery) => Err(format!(
                    "{error}; prior model not restarted automatically: {recovery}"
                )
                .into()),
            }
        } else {
            Err(error)
        };
    }
    restart()
}

pub fn install_check(id: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let p = profile(id)?;
    preflight_at(Path::new(VAR), &p, check_preflight)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"model":p.id,
        "preflight_admitted":true,"reservation":false,
        "reservation_scope":"future_serving_capacity",
        "cached_verification":"temporary_acquisition_lease_if_cached",
        "activation_guaranteed":false,"gate_closing":false})
    );
    Ok(())
}

pub fn install(id: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let p = profile(id)?;
    let _lock = operation_lock(Path::new(VAR))?;
    let trial = std::cell::RefCell::new(None);
    install_after_preflight(
        || preflight_at(Path::new(VAR), &p, check_preflight),
        || {
            prepare_model(Path::new(VAR), &p)?;
            check_cached(
                &p,
                available_space(&Path::new(VAR).join(STATE).join("models"))?,
            )?;
            running_prior(Path::new(VAR))
        },
        || command("/usr/bin/systemctl", &["stop", "luma-model.service"]).map(|_| ()),
        || {
            let guard = activate_cached_with(Path::new(VAR), &p, validation::Guard::begin)?;
            *trial.borrow_mut() = Some(guard);
            Ok(())
        },
        || {
            let trial = trial
                .borrow_mut()
                .take()
                .ok_or("model validation controller missing")?;
            finish_reconfiguration(
                || {
                    checked_restart_steps(|stage| match stage {
                        RestartStage::Reload => {
                            command("/usr/bin/systemctl", &["daemon-reload"]).map(|_| ())
                        }
                        RestartStage::Restart => command(
                            "/usr/bin/systemctl",
                            &["restart", "luma-model.service", "luma-reference.service"],
                        )
                        .map(|_| ()),
                        // A successful systemd job is not listener readiness.
                        RestartStage::Health => command(
                            "/usr/bin/python3",
                            &["-I", "/usr/libexec/luma-os/model-health.py"],
                        )
                        .map(|_| ()),
                        RestartStage::Worker => {
                            trial.check(&p)?;
                            if !model_service_running()? {
                                return Err(
                                    "model listener responded but selected worker is not running"
                                        .into(),
                                );
                            }
                            Ok(())
                        }
                        RestartStage::Reference => command(
                            "/usr/bin/systemctl",
                            &["is-active", "--quiet", "luma-reference.service"],
                        )
                        .map(|_| ()),
                        RestartStage::Validation => Err("unexpected validation step".into()),
                    })?;
                    trial.complete(&p).map_err(|error| RestartFailure {
                        stage: RestartStage::Validation,
                        error,
                    })
                },
                |stage| publish_quarantine(&Path::new(VAR).join(STATE), &p, stage),
                || command("/usr/bin/systemctl", &["stop", "luma-model.service"]).map(|_| ()),
            )
        },
        |prior| restore_prior(Path::new(VAR), prior),
    )
}

pub fn unit() -> Result<()> {
    let p = selected()?;
    println!(
        "[Service]\nMemoryMax={}\nMemoryHigh={}",
        p.memory_max_bytes,
        p.memory_max_bytes * 7 / 8
    );
    Ok(())
}

pub fn serve() -> Result<()> {
    if unsafe { libc::geteuid() } != 989 {
        return Err("model runtime requires isolated luma-model identity".into());
    }
    platform::require_installed()?;
    let runtime = runtime_lock(Path::new(VAR), false)?;
    recovery_disablement_absent(&Path::new(VAR).join(STATE))?;
    activation_records_absent(&Path::new(VAR).join(STATE))?;
    quarantine_absent(&Path::new(VAR).join(STATE))?;
    let p = selected()?;
    validation::worker_admission(&Path::new(VAR).join(STATE), &p)?;
    admit_cgroup(&p, effective_memory_limit()?)?;
    let lease = crate::resource_manager::WorkerLease::acquire(&p.id)?;
    let file = Path::new(VAR)
        .join(STATE)
        .join("models")
        .join(format!("{}.gguf", p.id));
    let verified = verified_runtime_file(&file, &p, || lease.check_local())?;
    lease.check()?;
    // The runtime opens this exact verified inode, not the mutable catalog
    // filename again. This does not defend against a hostile root writing the
    // same inode in place; root is outside this application's trust boundary.
    let descriptor = format!("/proc/self/fd/{}", verified.as_raw_fd());
    let info = fs::read_to_string("/proc/meminfo")?;
    if memory(&info, "MemTotal")? < p.minimum_ram_bytes
        || memory(&info, "MemAvailable")? < p.minimum_available_bytes
    {
        return Err(
            "insufficient memory at model activation; manual operation remains available".into(),
        );
    }
    // Verification/admission may block; recheck the trial controller and all
    // pending/quarantine fences immediately before spawning the owned runtime.
    validation::worker_admission(&Path::new(VAR).join(STATE), &p)?;
    let mut fence = supervision::Fence::capture(&Path::new(VAR).join(STATE), &p)?;
    let mut command = Command::new(RUNTIME);
    command
        .args([
            "--model",
            &descriptor,
            "--alias",
            &p.id,
            "--host",
            "127.0.0.1",
            "--port",
            "8081",
            "--ctx-size",
            &p.context_tokens.to_string(),
            "--parallel",
            "1",
            "--threads",
            "2",
            "--threads-batch",
            "2",
            "--n-gpu-layers",
            "0",
            "--device",
            "none",
            "--no-kv-offload",
            "--no-op-offload",
            "--cache-type-k",
            "f16",
            "--cache-type-v",
            "f16",
            "--cache-ram",
            "0",
            "--no-cache-prompt",
            "--no-cache-idle-slots",
            "--ctx-checkpoints",
            "0",
            "--no-repack",
            "--batch-size",
            "256",
            "--ubatch-size",
            "128",
            "--threads-http",
            "2",
            "--fit",
            "off",
            "--load-mode",
            "mmap",
            "--lazy-mode",
            "off",
            "--no-cont-batching",
            "--no-kv-unified",
            "--no-mmproj",
            "--api-key-file",
            "/var/lib/luma-os/model-auth/api-key",
            "--no-webui",
            "--jinja",
            "--no-warmup",
            "--no-context-shift",
            "--n-predict",
            "256",
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LD_LIBRARY_PATH", "/usr/libexec/luma-os/llama");
    inherit_runtime_files(&mut command, &verified, &runtime);
    supervision::run(&mut command, || {
        fence.check(&Path::new(VAR).join(STATE), &p)?;
        lease.check()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_runtime_lock_creation_is_exclusive_and_never_replaces_evidence() {
        let directory =
            std::env::temp_dir().join(format!("luma-runtime-recovery-{}", std::process::id()));
        fs::create_dir_all(directory.join(STATE)).unwrap();
        let lock = create_missing_runtime_lock(&directory).unwrap();
        let path = directory.join(STATE).join("model-runtime.lock");
        let original = fs::metadata(&path).unwrap();
        assert_eq!(original.mode() & 0o7777, 0o644);
        assert_eq!(original.len(), 0);
        assert!(create_missing_runtime_lock(&directory).is_err());
        assert!(runtime_lock(&directory, false).is_err());
        assert_eq!(fs::metadata(&path).unwrap().ino(), original.ino());
        drop(lock);
        drop(runtime_lock(&directory, false).unwrap());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(create_missing_runtime_lock(&directory).is_err());
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("/dev/null"));
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"retain uncertain bytes").unwrap();
        assert!(create_missing_runtime_lock(&directory).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"retain uncertain bytes");
        fs::remove_dir_all(directory).unwrap();
    }
    fn cleanup_fixture(label: &str) -> (PathBuf, PathBuf, Vec<Profile>) {
        let dir =
            std::env::temp_dir().join(format!("luma-download-{label}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let profiles = catalog().unwrap().models;
        let partial = dir.join(format!("{}.partial-{}", profiles[0].id, "a".repeat(32)));
        (dir, partial, profiles)
    }

    fn partial_guard(path: &Path) -> (Temporary, File) {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        let m = file.metadata().unwrap();
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        (
            Temporary {
                path: path.into(),
                identity: Some((m.dev(), m.ino())),
            },
            file,
        )
    }

    #[test]
    fn partial_guard_preserves_a_live_inherited_writer_then_reconciles() {
        let (dir, partial, profiles) = cleanup_fixture("guard-writer");
        let (guard, file) = partial_guard(&partial);
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .spawn()
            .unwrap();
        drop(file);
        drop(guard);
        let preserved = partial.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(preserved);
        assert_eq!(reconcile_downloads(&dir, &profiles).unwrap(), 1);
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn partial_guard_never_unlinks_a_replaced_or_uncreated_identity() {
        for changed in [true, false] {
            let (dir, partial, _) = cleanup_fixture(if changed {
                "guard-replaced"
            } else {
                "guard-uncreated"
            });
            let guard = if changed {
                let (guard, file) = partial_guard(&partial);
                drop(file);
                fs::rename(&partial, dir.join("owned-original")).unwrap();
                guard
            } else {
                Temporary {
                    path: partial.clone(),
                    identity: None,
                }
            };
            fs::write(&partial, b"preserve substituted path").unwrap();
            drop(guard);
            assert_eq!(fs::read(&partial).unwrap(), b"preserve substituted path");
            fs::remove_file(partial).unwrap();
            if changed {
                fs::remove_file(dir.join("owned-original")).unwrap();
            }
            fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    fn partial_guard_removes_only_the_created_drained_file() {
        let (dir, partial, _) = cleanup_fixture("guard-drained");
        let (guard, file) = partial_guard(&partial);
        drop(file);
        drop(guard);
        assert!(!partial.exists());
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn acquisition_supervision_reaps_before_return_or_unwind_and_descriptor_reuse() {
        for action in [
            "failure",
            "panic",
            "success",
            "child-failure",
            "spawn-failure",
        ] {
            let (dir, partial, profiles) = cleanup_fixture(&format!("supervised-{action}"));
            let (guard, file) = partial_guard(&partial);
            let executable = match action {
                "success" => "/bin/true",
                "child-failure" => "/bin/false",
                "spawn-failure" => "/luma-nonexistent-acquisition-test-executable",
                _ => "/bin/sleep",
            };
            let mut command = Command::new(executable);
            if matches!(action, "failure" | "panic") {
                command.arg("30");
            }
            command.stdout(Stdio::from(file.try_clone().unwrap()));
            drop(file);
            let mut checks = 0;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                supervision::run(&mut command, || {
                    checks += 1;
                    if checks > 1 {
                        match action {
                            "failure" => return Err("owned acquisition observation failed".into()),
                            "panic" => panic!("owned acquisition observation panicked"),
                            _ => (),
                        }
                    }
                    Ok(())
                })
            }));
            drop(command); // The parent's retained stdout clone is not a child.
            match (action, result) {
                ("panic", Err(_)) | ("success", Ok(Ok(()))) => (),
                ("failure" | "child-failure" | "spawn-failure", Ok(Err(_))) => (),
                _ => panic!("unexpected acquisition supervision result"),
            }
            let independent = open_regular(&partial).unwrap();
            assert_eq!(
                unsafe { libc::flock(independent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0,
                "owned child writer must be gone, including on unwind"
            );
            drop(independent);
            drop(guard);
            assert!(!partial.exists());
            assert_eq!(reconcile_downloads(&dir, &profiles).unwrap(), 0);
            fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    fn acquisition_exec_retains_death_fence_after_real_uid_drop_and_kernel_byte_limit() {
        let (dir, partial, _) = cleanup_fixture("confined-acquisition");
        let executable = dir.join("acquisition-fixture");
        let mut compiler = Command::new("/usr/bin/cc")
            .args(["-O2", "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o"])
            .arg(&executable)
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
            .write_all(include_str!("../../../native/tests/model_supervision_fixture.c").as_bytes())
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let (guard, file) = partial_guard(&partial);
        let mut command = Command::new(&executable);
        command
            .arg("acquisition-success")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(file.try_clone().unwrap()));
        // The exact production confinement function, not a test-only UID or
        // environment override, is followed by production supervisor arming.
        confine_acquisition(&mut command, 128).unwrap();
        supervision::run(&mut command, || Ok(())).unwrap();
        drop(command);
        drop(file);
        assert_eq!(fs::read(&partial).unwrap(), b"confined acquisition fixture");
        drop(guard);
        assert!(!partial.exists());
        let (guard, file) = partial_guard(&partial);
        let mut command = Command::new(&executable);
        command
            .arg("acquisition-hold")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(file.try_clone().unwrap()));
        confine_acquisition(&mut command, 128).unwrap();
        assert!(supervision::run(&mut command, || {
            if file.metadata()?.len() > 0 {
                Err("lease lost after confined download started".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        drop(command);
        drop(file);
        drop(guard);
        assert!(
            !partial.exists(),
            "UID-988 writer must be terminated before cleanup"
        );
        fs::remove_file(executable).unwrap();
        fs::remove_dir(dir).unwrap();

        let mut invalid = Command::new("/bin/true");
        assert!(confine_acquisition(&mut invalid, 0).is_err());
        assert!(confine_acquisition(&mut invalid, libc::RLIM_INFINITY).is_err());
    }

    #[test]
    fn acquisition_feasibility_separates_cache_or_download_from_serving_occupancy() {
        let p = profile("qwen3-4b-q4-k-m").unwrap();
        let reserve = 2 * 1024 * 1024 * 1024;
        acquisition_admission(&p, 8 * 1024 * 1024 * 1024, p.bytes + reserve, 2, false).unwrap();
        acquisition_admission(&p, 8 * 1024 * 1024 * 1024, reserve, 2, true).unwrap();
        assert!(acquisition_admission(&p, 8 * 1024 * 1024 * 1024, reserve, 2, false).is_err());
        assert!(
            acquisition_admission(&p, 2 * 1024 * 1024 * 1024, p.bytes + reserve, 2, false).is_err()
        );
        assert!(
            acquisition_admission(&p, 8 * 1024 * 1024 * 1024, p.bytes + reserve, 1, false).is_err()
        );
        let mut impossible = p.clone();
        impossible.bytes = u64::MAX;
        assert!(
            acquisition_admission(&impossible, 8 * 1024 * 1024 * 1024, u64::MAX, 2, false).is_err()
        );
    }

    #[test]
    fn leased_verification_rechecks_before_and_after_every_read_and_never_returns_after_fence_loss()
    {
        let (dir, path, mut profiles) = cleanup_fixture("checked-hash");
        let mut p = profiles.remove(0);
        let bytes = vec![17u8; 2 * 1024 * 1024 + 1];
        fs::write(&path, &bytes).unwrap();
        p.bytes = bytes.len() as u64;
        p.sha256 = bundle::hex(&Sha256::digest(&bytes));
        let mut checks = 0;
        assert!(verified_file_checked(&path, &p, || {
            checks += 1;
            if checks == 3 {
                Err("lease lost during read".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(checks, 3);
        let mut checks = 0;
        verified_file_checked(&path, &p, || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(checks, 8);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn orphan_download_is_removed_but_selected_model_survives() {
        let (dir, partial, profiles) = cleanup_fixture("orphan");
        fs::write(&partial, b"incomplete").unwrap();
        let model = dir.join(format!("{}.gguf", profiles[0].id));
        fs::write(&model, b"selected bytes are never cleanup targets").unwrap();
        assert_eq!(reconcile_downloads(&dir, &profiles).unwrap(), 1);
        assert!(!partial.exists());
        assert_eq!(
            fs::read(&model).unwrap(),
            b"selected bytes are never cleanup targets"
        );
        assert_eq!(reconcile_downloads(&dir, &profiles).unwrap(), 0);
        fs::remove_file(model).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn inherited_download_descriptor_fences_cleanup_after_owner_close() {
        let (dir, partial, profiles) = cleanup_fixture("writer");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&partial)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .spawn()
            .unwrap();
        drop(file);
        let denied = reconcile_downloads(&dir, &profiles).is_err();
        let preserved = partial.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(denied && preserved);
        assert_eq!(reconcile_downloads(&dir, &profiles).unwrap(), 1);
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn unsafe_download_inventory_is_retained_before_deletion() {
        for attack in ["symlink", "hardlink", "oversize", "unknown"] {
            let (dir, partial, profiles) = cleanup_fixture(attack);
            let sentinel = dir.with_extension("sentinel");
            fs::write(&sentinel, b"preserve").unwrap();
            match attack {
                "symlink" => std::os::unix::fs::symlink(&sentinel, &partial).unwrap(),
                "hardlink" => fs::hard_link(&sentinel, &partial).unwrap(),
                "oversize" => File::create(&partial)
                    .unwrap()
                    .set_len(profiles[0].bytes + 1)
                    .unwrap(),
                _ => {
                    fs::write(&partial, b"orphan").unwrap();
                    fs::write(dir.join("unknown"), b"retain").unwrap();
                }
            }
            assert!(reconcile_downloads(&dir, &profiles).is_err());
            assert!(partial.symlink_metadata().is_ok());
            assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
            fs::remove_file(partial).unwrap();
            if attack == "unknown" {
                fs::remove_file(dir.join("unknown")).unwrap();
            }
            fs::remove_file(sentinel).unwrap();
            fs::remove_dir(dir).unwrap();
        }
    }
    #[test]
    fn catalog_is_closed_and_parameter_ranges_are_explicit() {
        assert_eq!(catalog().unwrap().models.len(), 2);
        assert_eq!(
            profile("qwen3-4b-q4-k-m").unwrap().parameters,
            4_000_000_000
        );
        assert!(profile("../../etc/shadow").is_err());
        assert!(profile("gemma-unqualified").is_err());
    }
    #[test]
    fn admission_rejects_each_missing_resource() {
        let p = profile("qwen3-4b-q4-k-m").unwrap();
        admit(&p, 8_000_000_000, 5_000_000_000, 10_000_000_000, 2).unwrap();
        let reserve = 2 * 1024 * 1024 * 1024;
        assert!(admit(&p, 8_000_000_000, 5_000_000_000, reserve, 2).is_err());
        admit_with_space(&p, 8_000_000_000, 5_000_000_000, reserve, 2, reserve).unwrap();
        assert!(
            admit_with_space(&p, 8_000_000_000, 5_000_000_000, reserve - 1, 2, reserve).is_err()
        );
        for (total, available, disk, cpu) in [
            (1, 5_000_000_000, 10_000_000_000, 2),
            (8_000_000_000, 1, 10_000_000_000, 2),
            (8_000_000_000, 5_000_000_000, 1, 2),
            (8_000_000_000, 5_000_000_000, 10_000_000_000, 1),
        ] {
            assert!(admit(&p, total, available, disk, cpu).is_err());
        }
    }
    #[test]
    fn cgroup_capacity_uses_tightest_ancestor_and_exact_profile_bound() {
        let root =
            std::env::temp_dir().join(format!("luma-model-cgroup-capacity-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("parent")).unwrap();
        fs::create_dir(root.join("parent/worker")).unwrap();
        fs::write(root.join("memory.max"), b"max\n").unwrap();
        fs::write(root.join("parent/memory.max"), b"8000000000\n").unwrap();
        fs::write(root.join("parent/worker/memory.max"), b"5000000000\n").unwrap();
        let p = profile("qwen3-4b-q4-k-m").unwrap();
        assert_eq!(
            cgroup_path("0::/parent/worker\n").unwrap(),
            "/parent/worker"
        );
        assert_eq!(
            cgroup_limit_at(&root, "/parent/worker").unwrap(),
            5_000_000_000
        );
        admit_cgroup(&p, cgroup_limit_at(&root, "/parent/worker").unwrap()).unwrap();
        fs::write(root.join("parent/memory.max"), b"4000000000\n").unwrap();
        assert_eq!(
            cgroup_limit_at(&root, "/parent/worker").unwrap(),
            4_000_000_000
        );
        assert!(admit_cgroup(&p, cgroup_limit_at(&root, "/parent/worker").unwrap()).is_err());
        fs::write(root.join("parent/memory.max"), b"max\n").unwrap();
        fs::write(
            root.join("parent/worker/memory.max"),
            format!("{}\n", p.memory_max_bytes),
        )
        .unwrap();
        admit_cgroup(&p, cgroup_limit_at(&root, "/parent/worker").unwrap()).unwrap();
        for directory in [
            root.join("parent/worker"),
            root.join("parent"),
            root.clone(),
        ] {
            fs::remove_file(directory.join("memory.max")).unwrap();
            fs::remove_dir(directory).unwrap();
        }
    }
    #[test]
    fn malformed_or_substituted_cgroup_limits_fail_closed() {
        for input in [
            "",
            "1:name=/x\n",
            "0::relative\n",
            "0::/../x\n",
            "0::/x\n0::/y\n",
        ] {
            assert!(cgroup_path(input).is_err());
        }
        assert!(cgroup_path(&format!("0::/{}\n", "x".repeat(1025))).is_err());
        let root =
            std::env::temp_dir().join(format!("luma-model-cgroup-invalid-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let limit = root.join("memory.max");
        for input in [
            b"0\n".as_slice(),
            b"-1\n",
            b"1\n\n",
            b"invalid\n",
            b"999999999999999999999999999999999\n",
        ] {
            fs::write(&limit, input).unwrap();
            assert!(cgroup_limit_at(&root, "/").is_err());
        }
        fs::remove_file(&limit).unwrap();
        std::os::unix::fs::symlink(root.join("absent"), &limit).unwrap();
        assert!(cgroup_limit_at(&root, "/").is_err());
        fs::remove_file(&limit).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn read_only_install_preflight_refuses_unsafe_cache_without_creating_it() {
        let (dir, source, p) = runtime_fixture("preflight");
        let state = dir.join(STATE);
        let models = state.join("models");
        preflight_at(&dir, &p, |_, free, cached| {
            assert!(free > 0);
            assert!(!cached);
            Ok(())
        })
        .unwrap();
        assert!(!models.exists());
        std::os::unix::fs::symlink("missing", &models).unwrap();
        assert!(preflight_at(&dir, &p, |_, _, _| panic!("unsafe cache admitted")).is_err());
        fs::remove_file(&models).unwrap();
        fs::create_dir(&models).unwrap();
        fs::set_permissions(&models, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(preflight_at(&dir, &p, |_, _, _| panic!("writable cache admitted")).is_err());
        fs::set_permissions(&models, fs::Permissions::from_mode(0o700)).unwrap();
        preflight_at(&dir, &p, |_, free, cached| {
            assert!(free > 0);
            assert!(!cached);
            Ok(())
        })
        .unwrap();
        let target = models.join(format!("{}.gguf", p.id));
        fs::copy(&source, &target).unwrap();
        preflight_at(&dir, &p, |_, free, cached| {
            assert!(free > 0);
            assert!(cached);
            Ok(())
        })
        .unwrap();
        fs::write(&target, b"corrupt cached bytes").unwrap();
        assert!(preflight_at(&dir, &p, |_, _, _| panic!("corrupt cache admitted")).is_err());
        fs::remove_file(target).unwrap();
        fs::remove_dir(models).unwrap();
        remove_runtime_fixture(&dir);
    }
    #[test]
    fn predictable_refusal_cannot_stop_working_model() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        assert!(install_after_preflight(
            || {
                calls.borrow_mut().push("preflight");
                Err("insufficient capacity".into())
            },
            || {
                calls.borrow_mut().push("prepare");
                Ok(None::<&str>)
            },
            || {
                calls.borrow_mut().push("stop");
                Ok(())
            },
            || {
                calls.borrow_mut().push("activate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("restart");
                Ok(())
            },
            |_| {
                calls.borrow_mut().push("recover");
                Ok(())
            },
        )
        .is_err());
        assert_eq!(*calls.borrow(), ["preflight"]);
        calls.borrow_mut().clear();
        assert!(install_after_preflight(
            || {
                calls.borrow_mut().push("preflight");
                Ok(())
            },
            || {
                calls.borrow_mut().push("prepare");
                Err::<Option<&str>, _>("download failed".into())
            },
            || {
                calls.borrow_mut().push("stop");
                Ok(())
            },
            || {
                calls.borrow_mut().push("activate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("restart");
                Ok(())
            },
            |_| {
                calls.borrow_mut().push("recover");
                Ok(())
            },
        )
        .is_err());
        assert_eq!(*calls.borrow(), ["preflight", "prepare"]);
        calls.borrow_mut().clear();
        install_after_preflight(
            || {
                calls.borrow_mut().push("preflight");
                Ok(())
            },
            || {
                calls.borrow_mut().push("prepare");
                Ok(None::<&str>)
            },
            || {
                calls.borrow_mut().push("stop");
                Ok(())
            },
            || {
                calls.borrow_mut().push("activate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("restart");
                Ok(())
            },
            |_| {
                calls.borrow_mut().push("recover");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *calls.borrow(),
            ["preflight", "prepare", "stop", "activate", "restart"]
        );
        calls.borrow_mut().clear();
        assert!(install_after_preflight(
            || {
                calls.borrow_mut().push("preflight");
                Ok(())
            },
            || {
                calls.borrow_mut().push("prepare");
                Ok(Some("prior"))
            },
            || {
                calls.borrow_mut().push("stop");
                Ok(())
            },
            || {
                calls.borrow_mut().push("activate");
                Err("post-stop admission failed".into())
            },
            || {
                calls.borrow_mut().push("restart");
                Ok(())
            },
            |prior| {
                assert_eq!(prior, "prior");
                calls.borrow_mut().push("recover");
                Ok(())
            },
        )
        .is_err());
        assert_eq!(
            *calls.borrow(),
            ["preflight", "prepare", "stop", "activate", "recover"]
        );
    }
    #[test]
    fn failed_stop_only_requests_guarded_prior_recovery() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let error = install_after_preflight(
            || Ok(()),
            || Ok(Some("prior")),
            || {
                calls.borrow_mut().push("stop");
                Err("stop timed out".into())
            },
            || {
                calls.borrow_mut().push("activate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("restart candidate");
                Ok(())
            },
            |prior| {
                assert_eq!(prior, "prior");
                calls.borrow_mut().push("recover prior");
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stop timed out"));
        assert!(error.contains("prior model restart requested after failed stop"));
        assert_eq!(*calls.borrow(), ["stop", "recover prior"]);

        let error = install_after_preflight(
            || Ok(()),
            || Ok(Some("prior")),
            || Err("stop timed out".into()),
            || panic!("activation after failed stop"),
            || panic!("candidate restart after failed stop"),
            |_| Err("runtime lock still held".into()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stop timed out"));
        assert!(error.contains("runtime lock still held"));

        let error = install_after_preflight(
            || Ok(()),
            || Ok(None::<&str>),
            || Err("stop failed without prior worker".into()),
            || panic!("activation after failed stop"),
            || panic!("candidate restart after failed stop"),
            |_| panic!("recovery without prior worker"),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "stop failed without prior worker");
    }
    #[test]
    fn prior_worker_status_requires_exact_loaded_running_or_inactive_state() {
        assert!(model_unit_running(
            true,
            b"LoadState=loaded\nActiveState=active\nSubState=running\n"
        )
        .unwrap());
        assert!(!model_unit_running(
            true,
            b"SubState=dead\nActiveState=inactive\nLoadState=loaded\n"
        )
        .unwrap());
        for (success, output) in [
            (
                false,
                &b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"[..],
            ),
            (
                true,
                &b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n"[..],
            ),
            (
                true,
                &b"LoadState=loaded\nActiveState=failed\nSubState=failed\n"[..],
            ),
            (
                true,
                &b"LoadState=loaded\nActiveState=activating\nSubState=start\n"[..],
            ),
            (
                true,
                &b"LoadState=loaded\nActiveState=deactivating\nSubState=stop\n"[..],
            ),
            (
                true,
                &b"LoadState=loaded\nActiveState=active\nSubState=exited\n"[..],
            ),
            (true, &b"LoadState=loaded\nActiveState=inactive\n"[..]),
            (
                true,
                &b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nSubState=dead\n"[..],
            ),
            (
                true,
                &b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nExtra=1\n"[..],
            ),
            (true, &b"\xff"[..]),
        ] {
            assert!(model_unit_running(success, output).is_err());
        }
    }
    #[test]
    fn live_unified_cgroup_limit_is_observable() {
        assert!(effective_memory_limit().unwrap() > 0);
    }
    #[test]
    fn memory_observation_is_strict() {
        assert_eq!(
            memory("MemTotal: 123 kB\n", "MemTotal").unwrap(),
            123 * 1024
        );
        assert!(memory("MemTotal: 999 MB", "MemTotal").is_err());
        assert!(memory("MemTotal: 18446744073709551615 kB", "MemTotal").is_err());
    }
    #[test]
    fn verifies_real_bytes_and_rejects_wrong_digest_size_and_symlink() {
        let dir = std::env::temp_dir().join(format!("luma-model-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("model");
        fs::write(&path, b"GGUF-fixture").unwrap();
        let mut p = profile("qwen3-4b-q4-k-m").unwrap();
        p.bytes = 12;
        p.sha256 = bundle::hex(&Sha256::digest(b"GGUF-fixture"));
        p = p.with_fixture_verifier();
        verify_file(&path, &p).unwrap();
        p.sha256 = "0".repeat(64);
        assert!(verify_file(&path, &p).is_err());
        p.bytes = 11;
        assert_eq!(
            verify_file(&path, &p).unwrap_err().to_string(),
            "model byte count mismatch"
        );
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(verify_file(&link, &p).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    fn runtime_fixture(label: &str) -> (PathBuf, PathBuf, Profile) {
        let dir =
            std::env::temp_dir().join(format!("luma-model-runtime-{label}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let state = dir.join(STATE);
        fs::create_dir_all(&state).unwrap();
        let file = state.join("fixture.gguf");
        fs::write(&file, b"verified bytes").unwrap();
        let mut p = profile("qwen3-4b-q4-k-m").unwrap();
        p.bytes = 14;
        p.sha256 = bundle::hex(&Sha256::digest(b"verified bytes"));
        p = p.with_fixture_verifier();
        (dir, file, p)
    }

    fn remove_runtime_fixture(dir: &Path) {
        let state = dir.join(STATE);
        for entry in fs::read_dir(&state).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(&state).unwrap();
        fs::remove_dir(state.parent().unwrap()).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn runtime_lock_refuses_duplicates_and_activation_until_release() {
        let (dir, _, _) = runtime_fixture("exclusive");
        assert!(runtime_lock(&dir, false).is_err()); // no runtime auto-initialization
        let lock = runtime_lock(&dir, true).unwrap();
        assert!(runtime_lock(&dir, false).is_err());
        assert!(runtime_lock(&dir, true).is_err());
        drop(lock);
        runtime_lock(&dir, false).unwrap();
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn isolated_model_uid_can_lock_but_cannot_replace_root_inode() {
        let (dir, _, _) = runtime_fixture("unprivileged");
        let state = dir.join(STATE);
        for directory in [&dir, state.parent().unwrap(), &state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        runtime_lock(&dir, true).unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command
            .args([
                "-I",
                "-c",
                r#"
import fcntl, os, sys
assert os.geteuid() == 989 and os.getgroups() == []
path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
try:
    os.unlink(path)
except PermissionError:
    pass
else:
    raise RuntimeError('worker could unlink runtime lock')
try:
    os.open(path, os.O_WRONLY)
except PermissionError:
    pass
else:
    raise RuntimeError('worker could write runtime lock')
print('ISOLATED_MODEL_LOCK_PASSED')
"#,
            ])
            .arg(state.join("model-runtime.lock"));
        unsafe {
            command.pre_exec(|| {
                // Drop supplementary groups before UID: Command::uid would
                // run before this hook and make setgroups fail with EPERM.
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(989) != 0
                    || libc::setuid(989) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"ISOLATED_MODEL_LOCK_PASSED\n");
        runtime_lock(&dir, false).unwrap();
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn verified_descriptor_survives_exec_and_path_replacement() {
        let (dir, file, p) = runtime_fixture("descriptor");
        let lock = runtime_lock(&dir, true).unwrap();
        let verified = verified_file(&file, &p).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(verified.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        fs::rename(&file, file.with_extension("old")).unwrap();
        fs::write(&file, b"substituted bytes").unwrap();
        let mut command = Command::new("/bin/cat");
        command.arg(format!("/proc/self/fd/{}", verified.as_raw_fd()));
        inherit_runtime_files(&mut command, &verified, &lock);
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"verified bytes");
        // Child-only inheritance must not clear CLOEXEC in this parent.
        assert_ne!(
            unsafe { libc::fcntl(verified.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(verified_file(&file, &p).is_err());
        drop(verified);
        drop(lock);
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn worker_exec_inherits_lock_and_process_death_releases_it() {
        let (dir, file, p) = runtime_fixture("inheritance");
        let lock = runtime_lock(&dir, true).unwrap();
        let verified = verified_file(&file, &p).unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        inherit_runtime_files(&mut command, &verified, &lock);
        let mut child = command.spawn().unwrap();
        drop(lock);
        drop(verified);
        let duplicate_denied = runtime_lock(&dir, false).is_err();
        let activation_denied = runtime_lock(&dir, true).is_err();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(duplicate_denied && activation_denied);
        runtime_lock(&dir, false).unwrap();
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn runtime_lock_refuses_unsafe_metadata_and_keeps_inode() {
        use std::os::unix::fs::symlink;
        let (dir, file, _) = runtime_fixture("lock-metadata");
        let lock_path = dir.join(STATE).join("model-runtime.lock");
        runtime_lock(&dir, true).unwrap();
        let original = fs::metadata(&lock_path).unwrap().ino();
        for mode in [0o600, 0o666, 0o4644] {
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(runtime_lock(&dir, true).is_err());
            assert_eq!(fs::metadata(&lock_path).unwrap().ino(), original);
        }
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        let alias = lock_path.with_extension("alias");
        fs::hard_link(&lock_path, &alias).unwrap();
        assert!(runtime_lock(&dir, false).is_err());
        fs::remove_file(alias).unwrap();
        fs::write(&lock_path, b"unexpected").unwrap();
        assert!(runtime_lock(&dir, true).is_err());
        fs::remove_file(&lock_path).unwrap();
        symlink(&file, &lock_path).unwrap();
        assert!(runtime_lock(&dir, true).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"verified bytes");
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn verified_model_rejects_mutable_or_aliased_bytes() {
        let (dir, file, p) = runtime_fixture("model-metadata");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verified_file(&file, &p).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let alias = file.with_extension("alias");
        fs::hard_link(&file, &alias).unwrap();
        assert!(verified_file(&file, &p).is_err());
        fs::remove_file(alias).unwrap();
        verified_file(&file, &p).unwrap();
        remove_runtime_fixture(&dir);
    }

    #[test]
    fn selection_refuses_duplicate_fields_and_unsafe_metadata() {
        let (dir, _, _) = runtime_fixture("selection");
        let state = dir.join(STATE);
        let path = state.join("model-selection.json");
        let good = br#"{"schema_version":1,"id":"qwen3-4b-q4-k-m"}"#;
        fs::write(&path, good).unwrap();
        selected_at(&state).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(selected_at(&state).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&path, path.with_extension("alias")).unwrap();
        assert!(selected_at(&state).is_err());
        fs::remove_file(path.with_extension("alias")).unwrap();
        for bad in [
            br#"{"schema_version":1,"id":"qwen3-4b-q4-k-m","id":"qwen3-4b-q4-k-m"}"#.as_slice(),
            br#"{"schema_version":1,"id":"qwen3-4b-q4-k-m","authority":true}"#,
        ] {
            fs::write(&path, bad).unwrap();
            assert!(selected_at(&state).is_err());
        }
        remove_runtime_fixture(&dir);
    }

    fn activation_fixture(label: &str) -> (PathBuf, Profile) {
        let root = std::env::temp_dir().join(format!(
            "luma-model-activation-{label}-{}",
            std::process::id()
        ));
        let state = root.join(STATE);
        fs::create_dir_all(state.join("models")).unwrap();
        fs::create_dir(state.join("model-auth")).unwrap();
        let mut p = profile("qwen3-4b-q4-k-m").unwrap();
        let weights = b"small GGUF test fixture";
        p.bytes = weights.len() as u64;
        p.sha256 = bundle::hex(&Sha256::digest(weights));
        p = p.with_fixture_verifier();
        fs::write(state.join("models").join(format!("{}.gguf", p.id)), weights).unwrap();
        (root, p)
    }

    fn remove_activation_fixture(root: &Path, p: &Profile) {
        let state = root.join(STATE);
        for path in [
            state.join(ACTIVATION),
            state.join(PRIOR_BACKUP),
            state.join(ROLLBACK),
            state.join(QUARANTINE),
            state.join(REFERENCE_ENV),
            state.join("model-selection.json"),
            state.join("model-auth/api-key"),
            state.join("models").join(format!("{}.gguf", p.id)),
        ] {
            if path.symlink_metadata().is_ok() {
                fs::remove_file(path).unwrap();
            }
        }
        fs::remove_dir(state.join("models")).unwrap();
        fs::remove_dir(state.join("model-auth")).unwrap();
        fs::remove_dir(&state).unwrap();
        fs::remove_dir(state.parent().unwrap()).unwrap();
        fs::remove_dir(root).unwrap();
    }

    fn write_activation_candidate(state: &Path, p: &Profile) {
        let token = "a".repeat(64);
        fs::write(state.join("model-auth/api-key"), &token).unwrap();
        fs::write(
            state.join(REFERENCE_ENV),
            format!("LUMA_MODEL_ENDPOINT=http://127.0.0.1:8081/v1\nLUMA_MODEL_NAME={}\nLUMA_MODEL_API_KEY={token}\n", p.id),
        )
        .unwrap();
        fs::write(
            state.join("model-selection.json"),
            serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id})).unwrap(),
        )
        .unwrap();
    }

    fn write_legacy_reference(state: &Path, p: &Profile) {
        write_activation_candidate(state, p);
        let env = fs::read(state.join(REFERENCE_ENV)).unwrap();
        fs::remove_file(state.join(REFERENCE_ENV)).unwrap();
        let legacy_dir = state.join("reference");
        fs::create_dir(&legacy_dir).unwrap();
        fs::set_permissions(&legacy_dir, fs::Permissions::from_mode(0o700)).unwrap();
        command("/usr/bin/chown", &["990:990", legacy_dir.to_str().unwrap()]).unwrap();
        let legacy = legacy_dir.join("model.env");
        fs::write(&legacy, env).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
        command("/usr/bin/chown", &["990:990", legacy.to_str().unwrap()]).unwrap();
    }

    fn remove_legacy_reference(root: &Path) {
        let state = root.join(STATE);
        fs::remove_file(state.join("reference/model.env")).unwrap();
        fs::remove_dir(state.join("reference")).unwrap();
        if state.join("model-runtime.lock").exists() {
            fs::remove_file(state.join("model-runtime.lock")).unwrap();
        }
    }

    #[test]
    fn legacy_migration_requires_exact_old_state_and_publishes_root_environment() {
        let (root, p) = activation_fixture("legacy-migration");
        let state = root.join(STATE);
        write_legacy_reference(&state, &p);
        let legacy = state.join("reference/model.env");
        let expected = fs::read(&legacy).unwrap();
        fs::write(&legacy, b"untrusted legacy settings").unwrap();
        assert!(legacy_configuration_at(&state).is_err());
        assert!(state.join(REFERENCE_ENV).symlink_metadata().is_err());
        assert!(state.join("model-runtime.lock").symlink_metadata().is_err());
        fs::write(&legacy, &expected).unwrap();
        let selected = legacy_configuration_at(&state).unwrap();
        assert_eq!(selected.id, p.id);
        migrate_legacy_at(&root, &selected).unwrap();
        activation_absent(&state).unwrap();
        let current = state.join(REFERENCE_ENV);
        assert_eq!(fs::read(&current).unwrap(), expected);
        let metadata = fs::symlink_metadata(&current).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 990);
        assert_eq!(metadata.mode() & 0o777, 0o640);
        assert!(state.join("model-runtime.lock").exists());
        assert_eq!(fs::read(&legacy).unwrap(), expected);
        migrate_legacy_at(&root, &selected).unwrap();
        assert_eq!(fs::read(&current).unwrap(), expected);
        fs::write(&current, b"conflicting new settings").unwrap();
        assert!(legacy_configuration_at(&state).is_err());
        fs::write(&current, &expected).unwrap();
        fs::remove_file(&legacy).unwrap();
        std::os::unix::fs::symlink(&current, &legacy).unwrap();
        assert!(legacy_configuration_at(&state).is_err());
        remove_legacy_reference(&root);
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn pending_legacy_migration_needs_review_before_retry() {
        let (root, p) = activation_fixture("legacy-pending");
        let state = root.join(STATE);
        write_legacy_reference(&state, &p);
        let _runtime = runtime_lock(&root, true).unwrap();
        begin_activation(&state, &p).unwrap();
        assert!(legacy_configuration_at(&state).is_err());
        let observed = observe_activation(&state, &p, true).unwrap();
        assert_eq!(observed.phase, "unchanged_prior_state");
        reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).unwrap();
        drop(_runtime);
        migrate_legacy_at(&root, &p).unwrap();
        activation_absent(&state).unwrap();
        remove_legacy_reference(&root);
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn prior_worker_restart_refuses_pending_or_changed_activation() {
        let (root, p) = activation_fixture("prior-restart");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let runtime = runtime_lock(&root, true).unwrap();
        assert!(restore_prior(&root, prior_snapshot_at(&state).unwrap()).is_err());
        let prior = prior_snapshot_at(&state).unwrap();
        begin_activation(&state, &p).unwrap();
        drop(runtime);
        assert!(restore_prior(&root, prior).is_err());
        assert!(activation_absent(&state).is_err());
        let observed = observe_activation(&state, &p, true).unwrap();
        reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).unwrap();
        let prior = prior_snapshot_at(&state).unwrap();
        fs::write(state.join("model-disabled"), b"").unwrap();
        assert!(restore_prior(&root, prior).is_err());
        fs::remove_file(state.join("model-disabled")).unwrap();
        let prior = prior_snapshot_at(&state).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"changed after stop").unwrap();
        assert!(restore_prior(&root, prior).is_err());
        fs::remove_file(state.join("model-runtime.lock")).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn unchanged_activation_can_be_explicitly_aborted_without_worker_start() {
        let (root, p) = activation_fixture("unchanged");
        let state = root.join(STATE);
        begin_activation(&state, &p).unwrap();
        assert!(activation_absent(&state).is_err());
        let observed = observe_activation(&state, &p, true).unwrap();
        assert_eq!(observed.phase, "unchanged_prior_state");
        assert!(
            reviewed_clear_activation(&state, &p, "--publish-committed", &observed.review).is_err()
        );
        assert!(
            reviewed_clear_activation(&state, &p, "--abort-unchanged", &"00".repeat(32)).is_err()
        );
        reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).unwrap();
        activation_absent(&state).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn committed_candidate_requires_exact_review_and_verified_weights() {
        let (root, p) = activation_fixture("committed");
        let state = root.join(STATE);
        begin_activation(&state, &p).unwrap();
        write_activation_candidate(&state, &p);
        let observed = observe_activation(&state, &p, true).unwrap();
        assert_eq!(observed.phase, "consistent_candidate_committed");
        assert!(
            reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).is_err()
        );
        reviewed_clear_activation(&state, &p, "--publish-committed", &observed.review).unwrap();
        activation_absent(&state).unwrap();
        begin_activation(&state, &p).unwrap();
        assert!(activation_absent(&state).is_err());
        let observed = observe_activation(&state, &p, true).unwrap();
        reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn normal_activation_clears_fence_only_after_matching_selection_and_reference() {
        let (root, p) = activation_fixture("normal");
        let state = root.join(STATE);
        let record = begin_activation(&state, &p).unwrap();
        assert!(activation_absent(&state).is_err());
        write_activation_candidate(&state, &p);
        finish_activation(&state, &p, &record).unwrap();
        activation_absent(&state).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn reviewed_partial_candidate_completion_writes_consistent_state_without_worker() {
        let (root, p) = activation_fixture("complete-partial");
        let state = root.join(STATE);
        begin_activation(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"interrupted environment").unwrap();
        let observed = observe_activation(&state, &p, true).unwrap();
        assert_eq!(observed.phase, "partial_or_conflicting_state");
        assert!(reviewed_complete_candidate(&state, &p, &"00".repeat(32)).is_err());
        fs::write(state.join(REFERENCE_ENV), b"changed after review").unwrap();
        assert!(reviewed_complete_candidate(&state, &p, &observed.review).is_err());
        assert!(activation_absent(&state).is_err());
        let reviewed = observe_activation(&state, &p, true).unwrap();
        reviewed_complete_candidate(&state, &p, &reviewed.review).unwrap();
        activation_absent(&state).unwrap();
        assert_eq!(selected_at(&state).unwrap().id, p.id);
        let key = fs::read(state.join("model-auth/api-key")).unwrap();
        let env = fs::read(state.join(REFERENCE_ENV)).unwrap();
        assert_eq!(
            env,
            reference_environment(&p, std::str::from_utf8(&key).unwrap())
        );
        let key_meta = fs::symlink_metadata(state.join("model-auth/api-key")).unwrap();
        let env_meta = fs::symlink_metadata(state.join(REFERENCE_ENV)).unwrap();
        let selection_meta = fs::symlink_metadata(state.join("model-selection.json")).unwrap();
        assert_eq!(
            (key_meta.uid(), key_meta.gid(), key_meta.mode() & 0o777),
            (0, 989, 0o640)
        );
        assert_eq!(
            (env_meta.uid(), env_meta.gid(), env_meta.mode() & 0o777),
            (0, 990, 0o640)
        );
        assert_eq!(selection_meta.mode() & 0o777, 0o644);
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn partial_candidate_with_bad_weight_or_credential_keeps_fence() {
        let (root, p) = activation_fixture("bad-partial");
        let state = root.join(STATE);
        begin_activation(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"partial").unwrap();
        fs::write(
            state.join("models").join(format!("{}.gguf", p.id)),
            b"corrupt weight bytes",
        )
        .unwrap();
        let reviewed = observe_activation(&state, &p, true).unwrap();
        assert!(reviewed_complete_candidate(&state, &p, &reviewed.review).is_err());
        assert!(activation_absent(&state).is_err());
        fs::write(
            state.join("models").join(format!("{}.gguf", p.id)),
            b"small GGUF test fixture",
        )
        .unwrap();
        fs::write(state.join("model-auth/api-key"), b"bad key").unwrap();
        let reviewed = observe_activation(&state, &p, true).unwrap();
        assert!(reviewed_complete_candidate(&state, &p, &reviewed.review).is_err());
        assert!(activation_absent(&state).is_err());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn reinstall_of_consistent_selected_model_clears_fence() {
        let (root, p) = activation_fixture("same-model");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let record = begin_activation(&state, &p).unwrap();
        assert_eq!(
            observe_activation(&state, &p, true).unwrap().phase,
            "unchanged_prior_state"
        );
        finish_activation(&state, &p, &record).unwrap();
        activation_absent(&state).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn partial_or_changed_activation_remains_fenced() {
        let (root, p) = activation_fixture("partial");
        let state = root.join(STATE);
        begin_activation(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"partial environment").unwrap();
        let observed = observe_activation(&state, &p, true).unwrap();
        assert_eq!(observed.phase, "partial_or_conflicting_state");
        for mode in ["--abort-unchanged", "--publish-committed"] {
            assert!(reviewed_clear_activation(&state, &p, mode, &observed.review).is_err());
        }
        assert!(activation_absent(&state).is_err());
        write_activation_candidate(&state, &p);
        let observed = observe_activation(&state, &p, true).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"changed after review").unwrap();
        assert!(
            reviewed_clear_activation(&state, &p, "--publish-committed", &observed.review).is_err()
        );
        write_activation_candidate(&state, &p);
        fs::write(
            state.join("models").join(format!("{}.gguf", p.id)),
            b"corrupt weight bytes",
        )
        .unwrap();
        assert_eq!(
            observe_activation(&state, &p, true).unwrap().phase,
            "partial_or_conflicting_state"
        );
        assert!(activation_absent(&state).is_err());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn prior_backup_is_private_bound_and_precedes_any_candidate_write() {
        let (root, p) = activation_fixture("saved-private");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let before = activation_snapshot(&state).unwrap();
        let record = begin_activation(&state, &p).unwrap();
        assert_eq!(record.schema_version, 2);
        assert_eq!(activation_snapshot(&state).unwrap(), before);
        let saved = bound_prior_backup(&state, &record).unwrap().unwrap();
        assert_eq!((saved.selection, saved.environment, saved.key), before);
        assert_eq!(
            fs::metadata(state.join(PRIOR_BACKUP)).unwrap().mode() & 0o777,
            0o600
        );
        assert!(begin_activation(&state, &p).is_err());
        let observation = observe_activation(&state, &p, true).unwrap();
        assert!(observation.restore_available);
        // Only hashes/status are projected; secret backup fields stay private.
        assert!(!observation.review.contains(&"a".repeat(64)));
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn isolated_worker_cannot_read_or_unlink_the_private_prior_backup() {
        let (root, p) = activation_fixture("saved-dac");
        let state = root.join(STATE);
        for directory in [&root, state.parent().unwrap(), &state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_activation_candidate(&state, &p);
        begin_activation(&state, &p).unwrap();
        let mut child = Command::new("/usr/bin/python3");
        child
            .args([
                "-I",
                "-c",
                r#"
import os, stat, sys
assert os.geteuid() == 989 and os.getgroups() == []
path = sys.argv[1]
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
for action in (lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW), lambda: os.unlink(path)):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise RuntimeError('isolated worker accessed private model recovery material')
print('MODEL_PRIOR_BACKUP_DAC_PASSED')
"#,
            ])
            .arg(state.join(PRIOR_BACKUP));
        unsafe {
            child.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(989) != 0
                    || libc::setuid(989) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"MODEL_PRIOR_BACKUP_DAC_PASSED\n");
        assert!(prior_backup_bytes(&state).unwrap().is_some());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn reviewed_prior_restoration_recovers_exact_configuration_from_partial_state() {
        let (root, p) = activation_fixture("restore-prior");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let original = activation_snapshot(&state).unwrap();
        begin_activation(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"partial new environment").unwrap();
        fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap();
        let observed = observe_activation(&state, &p, true).unwrap();
        assert!(
            reviewed_restore_configuration(&state, &p, &"00".repeat(32), |_| Ok(p.clone()))
                .is_err()
        );
        reviewed_restore_configuration(&state, &p, &observed.review, |_| Ok(p.clone())).unwrap();
        activation_absent(&state).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), original);
        let auth = fs::metadata(state.join("model-auth")).unwrap();
        assert_eq!(
            (auth.uid(), auth.gid(), auth.mode() & 0o777),
            (0, 989, 0o750)
        );
        let key = fs::metadata(state.join("model-auth/api-key")).unwrap();
        assert_eq!((key.uid(), key.gid(), key.mode() & 0o777), (0, 989, 0o640));
        let env = fs::metadata(state.join(REFERENCE_ENV)).unwrap();
        assert_eq!((env.uid(), env.gid(), env.mode() & 0o777), (0, 990, 0o640));
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn restoration_uses_the_prior_profile_and_can_return_to_manual_only() {
        for manual in [false, true] {
            let (root, candidate) = activation_fixture(if manual {
                "restore-manual"
            } else {
                "restore-other"
            });
            let state = root.join(STATE);
            let mut prior = candidate.clone();
            prior.id = "qwen3-1-7b-q4-k-m".into();
            if !manual {
                fs::copy(
                    state.join("models").join(format!("{}.gguf", candidate.id)),
                    state.join("models").join(format!("{}.gguf", prior.id)),
                )
                .unwrap();
                write_activation_candidate(&state, &prior);
            }
            let original = activation_snapshot(&state).unwrap();
            begin_activation(&state, &candidate).unwrap();
            write_activation_candidate(&state, &candidate);
            let observed = observe_activation(&state, &candidate, true).unwrap();
            // Explicit restore is valid even when the candidate files committed
            // but their pending marker has not been cleared.
            reviewed_restore_configuration(&state, &candidate, &observed.review, |id| {
                assert_eq!(id, prior.id);
                Ok(prior.clone())
            })
            .unwrap();
            assert_eq!(activation_snapshot(&state).unwrap(), original);
            activation_absent(&state).unwrap();
            if !manual {
                fs::remove_file(state.join("models").join(format!("{}.gguf", prior.id))).unwrap();
            }
            remove_activation_fixture(&root, &candidate);
        }
    }

    #[test]
    fn restoration_bad_prior_weights_or_stale_review_never_changes_configuration() {
        for variant in 0..3 {
            let (root, p) = activation_fixture(&format!("restore-refused-{variant}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            begin_activation(&state, &p).unwrap();
            fs::write(state.join(REFERENCE_ENV), b"partial").unwrap();
            let observation = observe_activation(&state, &p, true).unwrap();
            match variant {
                0 => fs::write(
                    state.join("models").join(format!("{}.gguf", p.id)),
                    b"bad weights",
                )
                .unwrap(),
                1 => fs::write(state.join(REFERENCE_ENV), b"changed after review").unwrap(),
                _ => {
                    let path = state.join(PRIOR_BACKUP);
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            let before = activation_snapshot(&state).unwrap();
            assert!(
                reviewed_restore_configuration(&state, &p, &observation.review, |_| Ok(p.clone()))
                    .is_err()
            );
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            assert!(activation_absent(&state).is_err());
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn missing_or_substituted_backup_does_not_manufacture_prior_state() {
        for variant in 0..5 {
            let (root, p) = activation_fixture(&format!("restore-missing-{variant}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            begin_activation(&state, &p).unwrap();
            fs::write(state.join(REFERENCE_ENV), b"partial").unwrap();
            let observation = observe_activation(&state, &p, true).unwrap();
            let before = activation_snapshot(&state).unwrap();
            fs::remove_file(state.join(PRIOR_BACKUP)).unwrap();
            match variant {
                0 => (),
                1 => {
                    platform::write_atomic(&state.join(PRIOR_BACKUP), b"{}", 0o600).unwrap();
                }
                2 => std::os::unix::fs::symlink(
                    state.join("model-auth/api-key"),
                    state.join(PRIOR_BACKUP),
                )
                .unwrap(),
                3 => {
                    fs::set_permissions(
                        state.join("model-auth/api-key"),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                    fs::hard_link(state.join("model-auth/api-key"), state.join(PRIOR_BACKUP))
                        .unwrap();
                }
                _ => platform::write_atomic(
                    &state.join(PRIOR_BACKUP),
                    &vec![b' '; MAX_PRIOR_BACKUP as usize + 1],
                    0o600,
                )
                .unwrap(),
            }
            assert!(
                reviewed_restore_configuration(&state, &p, &observation.review, |_| Ok(p.clone()))
                    .is_err()
            );
            if variant == 3 {
                // Snapshot reads must also reject the injected nlink=2 key.
                // Check preservation, then detach only this fixture's alias.
                assert_eq!(fs::metadata(state.join(PRIOR_BACKUP)).unwrap().nlink(), 2);
                fs::remove_file(state.join(PRIOR_BACKUP)).unwrap();
            }
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            assert!(activation_absent(&state).is_err());
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn interrupted_prior_restore_requires_new_review_and_keeps_backup_until_clearance() {
        for restored_files in 1..=3 {
            let (root, p) = activation_fixture(&format!("restore-retry-{restored_files}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            let original = activation_snapshot(&state).unwrap();
            let record = begin_activation(&state, &p).unwrap();
            fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap();
            fs::write(state.join(REFERENCE_ENV), b"partial").unwrap();
            fs::write(state.join("model-selection.json"), b"{}").unwrap();
            let old_review = observe_activation(&state, &p, true).unwrap();
            let backup = bound_prior_backup(&state, &record).unwrap().unwrap();
            // Materialize the exact writes preceding each simulated crash.
            restore_config_file(
                &state.join("model-auth/api-key"),
                &backup.key,
                0o640,
                Some("0:989"),
            )
            .unwrap();
            if restored_files >= 2 {
                restore_config_file(
                    &state.join(REFERENCE_ENV),
                    &backup.environment,
                    0o640,
                    Some("0:990"),
                )
                .unwrap();
            }
            if restored_files >= 3 {
                restore_config_file(
                    &state.join("model-selection.json"),
                    &backup.selection,
                    0o644,
                    None,
                )
                .unwrap();
            }
            assert!(activation_absent(&state).is_err());
            assert!(bound_prior_backup(&state, &record).unwrap().is_some());
            assert!(
                reviewed_restore_configuration(&state, &p, &old_review.review, |_| Ok(p.clone()))
                    .is_err()
            );
            let new_review = observe_activation(&state, &p, true).unwrap();
            reviewed_restore_configuration(&state, &p, &new_review.review, |_| Ok(p.clone()))
                .unwrap();
            activation_absent(&state).unwrap();
            assert_eq!(activation_snapshot(&state).unwrap(), original);
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn orphan_backup_discard_requires_exact_unchanged_state_and_does_not_restore_files() {
        let (root, p) = activation_fixture("restore-orphan");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let original = activation_snapshot(&state).unwrap();
        begin_activation(&state, &p).unwrap();
        fs::remove_file(state.join(ACTIVATION)).unwrap(); // Pre-marker crash fixture.
        assert!(activation_absent(&state).is_err());
        let (review, unchanged) = observe_orphan_backup(&state).unwrap();
        assert!(unchanged);
        fs::write(state.join(REFERENCE_ENV), b"different").unwrap();
        assert!(reviewed_discard_orphan_backup(&state, &review).is_err());
        fs::write(state.join(REFERENCE_ENV), original.1.as_ref().unwrap()).unwrap();
        assert!(reviewed_discard_orphan_backup(&state, &"00".repeat(32)).is_err());
        reviewed_discard_orphan_backup(&state, &review).unwrap();
        activation_absent(&state).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), original);
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn backup_cleanup_interruption_and_legacy_markers_allow_only_existing_clearance() {
        for legacy in [false, true] {
            let (root, p) = activation_fixture(if legacy {
                "restore-schema1"
            } else {
                "restore-cleanup"
            });
            let state = root.join(STATE);
            let mut record = begin_activation(&state, &p).unwrap();
            fs::remove_file(state.join(PRIOR_BACKUP)).unwrap();
            if legacy {
                record.schema_version = 1;
                record.prior_backup_sha256 = None;
                platform::write_atomic(
                    &state.join(ACTIVATION),
                    &serde_json::to_vec(&record).unwrap(),
                    0o600,
                )
                .unwrap();
            }
            let observed = observe_activation(&state, &p, true).unwrap();
            assert!(!observed.restore_available);
            assert!(reviewed_restore_configuration(
                &state,
                &p,
                &observed.review,
                |_| Ok(p.clone())
            )
            .is_err());
            reviewed_clear_activation(&state, &p, "--abort-unchanged", &observed.review).unwrap();
            activation_absent(&state).unwrap();
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn backup_of_invalid_or_legacy_prior_config_cannot_be_published_as_valid_model() {
        for variant in 0..2 {
            let (root, p) = activation_fixture(&format!("restore-invalid-prior-{variant}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            if variant == 0 {
                fs::write(
                    state.join(REFERENCE_ENV),
                    b"prior configuration was already inconsistent",
                )
                .unwrap();
            } else {
                fs::remove_file(state.join(REFERENCE_ENV)).unwrap();
            }
            begin_activation(&state, &p).unwrap();
            write_activation_candidate(&state, &p);
            let observed = observe_activation(&state, &p, true).unwrap();
            let before = activation_snapshot(&state).unwrap();
            assert!(reviewed_restore_configuration(
                &state,
                &p,
                &observed.review,
                |_| Ok(p.clone())
            )
            .is_err());
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            assert!(activation_absent(&state).is_err());
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn prior_restoration_publishes_service_modes_under_restrictive_umask() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "model::tests::prior_restore_umask_child",
                "--ignored",
                "--exact",
                "--test-threads=1",
            ])
            .env("LUMA_MODEL_OWNED_UMASK_FIXTURE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[test]
    #[ignore = "owned child of the restrictive-umask model fixture only"]
    fn prior_restore_umask_child() {
        assert_eq!(
            std::env::var("LUMA_MODEL_OWNED_UMASK_FIXTURE").unwrap(),
            "1"
        );
        assert!(Path::new("/.dockerenv").is_file());
        unsafe {
            libc::umask(0o077);
        }
        let (root, p) = activation_fixture("restore-umask");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        begin_activation(&state, &p).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"partial").unwrap();
        let observation = observe_activation(&state, &p, true).unwrap();
        reviewed_restore_configuration(&state, &p, &observation.review, |_| Ok(p.clone())).unwrap();
        for (name, expected) in [
            ("model-auth/api-key", 0o640),
            (REFERENCE_ENV, 0o640),
            ("model-selection.json", 0o644),
        ] {
            assert_eq!(
                fs::metadata(state.join(name)).unwrap().mode() & 0o777,
                expected
            );
        }
        activation_absent(&state).unwrap();
        remove_activation_fixture(&root, &p);
    }

    fn completed_rollback_fixture(label: &str) -> (PathBuf, Profile, Profile) {
        let (root, completed) = activation_fixture(label);
        let state = root.join(STATE);
        let mut prior = profile("qwen3-1-7b-q4-k-m").unwrap();
        let weights = b"different small prior GGUF fixture";
        prior.bytes = weights.len() as u64;
        prior.sha256 = bundle::hex(&Sha256::digest(weights));
        prior = prior.with_fixture_verifier();
        fs::write(
            state.join("models").join(format!("{}.gguf", prior.id)),
            weights,
        )
        .unwrap();
        write_activation_candidate(&state, &prior);
        let activation = begin_activation(&state, &completed).unwrap();
        write_activation_candidate(&state, &completed);
        finish_activation(&state, &completed, &activation).unwrap();
        (root, completed, prior)
    }

    fn fixture_resolve(id: &str, completed: &Profile, prior: &Profile) -> Result<Profile> {
        match id {
            id if id == completed.id => Ok(completed.clone()),
            id if id == prior.id => Ok(prior.clone()),
            _ => Err("unknown fixture profile".into()),
        }
    }

    fn remove_completed_rollback_fixture(root: &Path, completed: &Profile, prior: &Profile) {
        fs::remove_file(
            root.join(STATE)
                .join("models")
                .join(format!("{}.gguf", prior.id)),
        )
        .unwrap();
        remove_activation_fixture(root, completed);
    }

    #[test]
    fn completed_activation_retains_one_private_bound_rollback_record() {
        let (root, completed, prior) = completed_rollback_fixture("completed-private");
        let state = root.join(STATE);
        activation_absent(&state).unwrap();
        let bytes = rollback_bytes(&state).unwrap().unwrap();
        let record = decode_rollback(&bytes).unwrap();
        assert_eq!(record.completed_profile, completed.id);
        assert_eq!(record.completed_weight_sha256, completed.sha256);
        assert_eq!(record.prior.candidate, completed.id);
        assert_eq!(
            prior_restore_profile(&record.prior, |_| Ok(prior.clone()))
                .unwrap()
                .unwrap()
                .id,
            prior.id
        );
        let metadata = fs::symlink_metadata(state.join(ROLLBACK)).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.nlink(), metadata.mode() & 0o777),
            (0, 1, 0o600)
        );
        assert_eq!(
            fs::read_dir(&state)
                .unwrap()
                .filter_map(|entry| {
                    let entry = entry.unwrap();
                    entry
                        .file_name()
                        .to_str()
                        .filter(|name| name.starts_with("model-rollback"))
                        .map(str::to_owned)
                })
                .collect::<Vec<_>>(),
            [ROLLBACK]
        );
        let observed =
            observe_rollback(&state, &|id| fixture_resolve(id, &completed, &prior)).unwrap();
        assert!(observed.restorable);
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn reviewed_completed_rollback_restores_different_profile_and_consumes_record() {
        let (root, completed, prior) = completed_rollback_fixture("completed-restore");
        let state = root.join(STATE);
        fs::write(state.join("model-disabled"), b"recovery remains disabled").unwrap();
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        let observed = observe_rollback(&state, &resolve).unwrap();
        assert!(reviewed_completed_rollback(&state, &"00".repeat(32), &resolve).is_err());
        activation_absent(&state).unwrap();
        reviewed_completed_rollback(&state, &observed.review, &resolve).unwrap();
        activation_absent(&state).unwrap();
        assert!(rollback_bytes(&state).unwrap().is_none());
        assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
        assert_eq!(
            activation_snapshot(&state).unwrap(),
            (
                observed.record.prior.selection,
                observed.record.prior.environment,
                observed.record.prior.key
            )
        );
        assert_eq!(
            fs::read(state.join("model-disabled")).unwrap(),
            b"recovery remains disabled"
        );
        for (name, mode, group) in [
            ("model-auth/api-key", 0o640, 989),
            (REFERENCE_ENV, 0o640, 990),
            ("model-selection.json", 0o644, 0),
        ] {
            let metadata = fs::metadata(state.join(name)).unwrap();
            assert_eq!(
                (metadata.mode() & 0o777, metadata.uid(), metadata.gid()),
                (mode, 0, group)
            );
        }
        verify_file(
            &state.join("models").join(format!("{}.gguf", completed.id)),
            &completed,
        )
        .unwrap();
        verify_file(
            &state.join("models").join(format!("{}.gguf", prior.id)),
            &prior,
        )
        .unwrap();
        fs::remove_file(state.join("model-disabled")).unwrap();
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn reviewed_completed_rollback_restores_manual_only_without_deleting_weights() {
        let (root, completed) = activation_fixture("completed-manual");
        let state = root.join(STATE);
        let activation = begin_activation(&state, &completed).unwrap();
        write_activation_candidate(&state, &completed);
        finish_activation(&state, &completed, &activation).unwrap();
        let resolve = |_: &str| Ok(completed.clone());
        let observed = observe_rollback(&state, &resolve).unwrap();
        assert!(observed.restorable && observed.prior.is_none());
        reviewed_completed_rollback(&state, &observed.review, &resolve).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), (None, None, None));
        activation_absent(&state).unwrap();
        verify_file(
            &state.join("models").join(format!("{}.gguf", completed.id)),
            &completed,
        )
        .unwrap();
        remove_activation_fixture(&root, &completed);
    }

    #[test]
    fn completed_rollback_refuses_stale_configuration_and_bad_prior_weights() {
        let (root, completed, prior) = completed_rollback_fixture("completed-stale");
        let state = root.join(STATE);
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        let observed = observe_rollback(&state, &resolve).unwrap();
        let original = activation_snapshot(&state).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"changed after review").unwrap();
        let changed = observe_rollback(&state, &resolve).unwrap();
        assert_eq!(changed.phase, "completed_configuration_changed");
        assert_ne!(changed.review, observed.review);
        assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
        activation_absent(&state).unwrap();
        fs::write(state.join(REFERENCE_ENV), original.1.as_ref().unwrap()).unwrap();
        let weights = state.join("models").join(format!("{}.gguf", prior.id));
        let original_weight = fs::read(&weights).unwrap();
        fs::write(&weights, b"bad prior weights").unwrap();
        assert_eq!(
            observe_rollback(&state, &resolve).unwrap().phase,
            "prior_configuration_or_weights_unavailable"
        );
        assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
        activation_absent(&state).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), original);
        fs::write(&weights, original_weight).unwrap();
        // A broken current candidate is a reason to undo; only prior weights
        // must be usable, not the model being replaced.
        fs::write(
            state.join("models").join(format!("{}.gguf", completed.id)),
            b"broken current model",
        )
        .unwrap();
        reviewed_completed_rollback(&state, &observed.review, &resolve).unwrap();
        activation_absent(&state).unwrap();
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn completed_rollback_refuses_unsafe_missing_or_substituted_records() {
        for kind in [
            "missing",
            "malformed",
            "public",
            "symlink",
            "hardlink",
            "oversized",
            "substituted",
        ] {
            let (root, completed, prior) =
                completed_rollback_fixture(&format!("completed-unsafe-{kind}"));
            let state = root.join(STATE);
            let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
            let observed = observe_rollback(&state, &resolve).unwrap();
            let original = activation_snapshot(&state).unwrap();
            let path = state.join(ROLLBACK);
            match kind {
                "missing" => fs::remove_file(&path).unwrap(),
                "malformed" => fs::write(&path, b"{}").unwrap(),
                "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(state.join("model-auth/api-key"), &path).unwrap();
                }
                "hardlink" => {
                    fs::remove_file(&path).unwrap();
                    fs::hard_link(state.join("model-auth/api-key"), &path).unwrap();
                }
                "oversized" => fs::write(&path, vec![b' '; MAX_ROLLBACK as usize + 1]).unwrap(),
                "substituted" => {
                    let mut record = decode_rollback(&observed.bytes).unwrap();
                    record.completed_marker_sha256 = "bb".repeat(32);
                    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
            activation_absent(&state).unwrap();
            if kind == "hardlink" {
                fs::remove_file(&path).unwrap();
            }
            assert_eq!(activation_snapshot(&state).unwrap(), original);
            remove_completed_rollback_fixture(&root, &completed, &prior);
        }
    }

    #[test]
    fn completed_rollback_publication_failure_retains_activation_and_unknown_archive() {
        let (root, completed) = activation_fixture("completed-publication-fail");
        let state = root.join(STATE);
        let activation = begin_activation(&state, &completed).unwrap();
        write_activation_candidate(&state, &completed);
        let path = state.join(ROLLBACK);
        fs::write(&path, b"unknown retained archive").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(finish_activation(&state, &completed, &activation).is_err());
        assert!(activation_absent(&state).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"unknown retained archive");
        assert!(bound_prior_backup(&state, &activation).unwrap().is_some());
        remove_activation_fixture(&root, &completed);
    }

    #[test]
    fn completed_rollback_publication_is_retryable_before_pending_clearance() {
        let (root, completed) = activation_fixture("completed-publication-retry");
        let state = root.join(STATE);
        let activation = begin_activation(&state, &completed).unwrap();
        write_activation_candidate(&state, &completed);
        let observed = observe_activation(&state, &completed, true).unwrap();
        assert_eq!(observed.record, activation);
        retain_completed_prior(&state, &completed, &observed).unwrap();
        let retained = rollback_bytes(&state).unwrap();
        assert!(activation_absent(&state).is_err());
        assert!(observe_rollback(&state, &|_| Ok(completed.clone())).is_err());
        reviewed_clear_activation(&state, &completed, "--publish-committed", &observed.review)
            .unwrap();
        activation_absent(&state).unwrap();
        assert_eq!(rollback_bytes(&state).unwrap(), retained);
        assert!(
            observe_rollback(&state, &|_| Ok(completed.clone()))
                .unwrap()
                .restorable
        );
        remove_activation_fixture(&root, &completed);
    }

    #[test]
    fn interrupted_completed_rollback_is_fenced_and_can_restore_pre_rollback_candidate() {
        for writes in 1..=3 {
            let (root, completed, prior) =
                completed_rollback_fixture(&format!("completed-interrupted-{writes}"));
            let state = root.join(STATE);
            let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
            let observed = observe_rollback(&state, &resolve).unwrap();
            let before = activation_snapshot(&state).unwrap();
            begin_activation(&state, &completed).unwrap();
            restore_config_file(
                &state.join("model-auth/api-key"),
                &observed.record.prior.key,
                0o640,
                Some("0:989"),
            )
            .unwrap();
            if writes >= 2 {
                restore_config_file(
                    &state.join(REFERENCE_ENV),
                    &observed.record.prior.environment,
                    0o640,
                    Some("0:990"),
                )
                .unwrap();
            }
            if writes >= 3 {
                restore_config_file(
                    &state.join("model-selection.json"),
                    &observed.record.prior.selection,
                    0o644,
                    None,
                )
                .unwrap();
            }
            assert!(observe_rollback(&state, &resolve).is_err());
            assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
            let pending = observe_activation(&state, &completed, true).unwrap();
            reviewed_restore_configuration(&state, &completed, &pending.review, |_| {
                Ok(completed.clone())
            })
            .unwrap();
            activation_absent(&state).unwrap();
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            let fresh = observe_rollback(&state, &resolve).unwrap();
            reviewed_completed_rollback(&state, &fresh.review, &resolve).unwrap();
            remove_completed_rollback_fixture(&root, &completed, &prior);
        }
    }

    #[test]
    fn interrupted_rollback_consumption_keeps_pre_rollback_recovery_bytes() {
        let (root, completed, prior) = completed_rollback_fixture("completed-consume-interrupted");
        let state = root.join(STATE);
        let observed =
            observe_rollback(&state, &|id| fixture_resolve(id, &completed, &prior)).unwrap();
        let before = activation_snapshot(&state).unwrap();
        begin_activation(&state, &completed).unwrap();
        write_prior_configuration(&state, &observed.record.prior).unwrap();
        fs::remove_file(state.join(ROLLBACK)).unwrap();
        assert!(activation_absent(&state).is_err());
        let pending = observe_activation(&state, &completed, true).unwrap();
        reviewed_restore_configuration(&state, &completed, &pending.review, |_| {
            Ok(completed.clone())
        })
        .unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), before);
        activation_absent(&state).unwrap();
        assert!(rollback_bytes(&state).unwrap().is_none());
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn completed_rollback_retention_is_bounded_to_latest_activation() {
        let (root, completed, prior) = completed_rollback_fixture("completed-replace");
        let state = root.join(STATE);
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        let old = observe_rollback(&state, &resolve).unwrap();
        let expected = activation_snapshot(&state).unwrap();
        let activation = begin_activation(&state, &completed).unwrap();
        let token = "b".repeat(64);
        fs::write(state.join("model-auth/api-key"), &token).unwrap();
        fs::write(
            state.join(REFERENCE_ENV),
            reference_environment(&completed, &token),
        )
        .unwrap();
        finish_activation(&state, &completed, &activation).unwrap();
        assert!(reviewed_completed_rollback(&state, &old.review, &resolve).is_err());
        let fresh = observe_rollback(&state, &resolve).unwrap();
        assert_ne!(fresh.bytes, old.bytes);
        assert_eq!(fresh.prior.as_ref().unwrap().id, completed.id);
        reviewed_completed_rollback(&state, &fresh.review, &resolve).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), expected);
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn completed_rollback_refuses_invalid_prior_and_changed_catalog_pin() {
        let (root, completed, prior) = completed_rollback_fixture("completed-catalog");
        let state = root.join(STATE);
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        let observed = observe_rollback(&state, &resolve).unwrap();
        let before = activation_snapshot(&state).unwrap();
        assert!(
            reviewed_completed_rollback(&state, &observed.review, &|id| {
                let mut p = resolve(id)?;
                if id == completed.id {
                    p.sha256 = "aa".repeat(32);
                }
                Ok(p)
            })
            .is_err()
        );
        let mut record = decode_rollback(&observed.bytes).unwrap();
        let mut changed_catalog = decode_rollback(&observed.bytes).unwrap();
        changed_catalog.catalog_sha256 = "aa".repeat(32);
        fs::write(
            state.join(ROLLBACK),
            serde_json::to_vec(&changed_catalog).unwrap(),
        )
        .unwrap();
        assert!(reviewed_completed_rollback(&state, &observed.review, &resolve).is_err());
        record.prior.environment = None;
        fs::write(state.join(ROLLBACK), serde_json::to_vec(&record).unwrap()).unwrap();
        let invalid = observe_rollback(&state, &resolve).unwrap();
        assert!(!invalid.restorable);
        assert!(reviewed_completed_rollback(&state, &invalid.review, &resolve).is_err());
        activation_absent(&state).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), before);
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn completed_rollback_rechecks_reviewed_configuration_at_fence_creation() {
        let (root, completed, prior) = completed_rollback_fixture("completed-fence-race");
        let state = root.join(STATE);
        let observed =
            observe_rollback(&state, &|id| fixture_resolve(id, &completed, &prior)).unwrap();
        let calls = std::cell::Cell::new(0);
        let result = reviewed_completed_rollback(&state, &observed.review, &|id| {
            calls.set(calls.get() + 1);
            if calls.get() == 4 {
                fs::write(
                    state.join(REFERENCE_ENV),
                    b"configuration changed after snapshot",
                )?;
            }
            fixture_resolve(id, &completed, &prior)
        });
        assert!(result.is_err());
        assert!(activation_absent(&state).is_err());
        assert_eq!(
            fs::read(state.join(REFERENCE_ENV)).unwrap(),
            b"configuration changed after snapshot"
        );
        assert_eq!(rollback_bytes(&state).unwrap().unwrap(), observed.bytes);
        let pending = observe_activation(&state, &completed, true).unwrap();
        assert_eq!(pending.phase, "unchanged_prior_state");
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn completed_rollback_archive_is_not_readable_or_removable_by_worker_uid() {
        let (root, completed, prior) = completed_rollback_fixture("completed-private-dac");
        let state = root.join(STATE);
        for directory in [&root, state.parent().unwrap(), &state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut child = Command::new("/usr/bin/python3");
        child
            .args([
                "-I",
                "-c",
                r#"
import os, stat, sys
assert os.geteuid() == 989 and os.getgroups() == []
path = sys.argv[1]
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
for action in (lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW), lambda: os.unlink(path)):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise RuntimeError('worker accessed private completed rollback archive')
print('MODEL_COMPLETED_ROLLBACK_DAC_PASSED')
"#,
            ])
            .arg(state.join(ROLLBACK));
        unsafe {
            child.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(989) != 0
                    || libc::setuid(989) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"MODEL_COMPLETED_ROLLBACK_DAC_PASSED\n");
        assert!(rollback_bytes(&state).unwrap().is_some());
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn legacy_marker_clearance_does_not_invent_completed_rollback_bytes() {
        let (root, completed) = activation_fixture("completed-legacy-marker");
        let state = root.join(STATE);
        let mut activation = begin_activation(&state, &completed).unwrap();
        activation.schema_version = 1;
        activation.prior_backup_sha256 = None;
        fs::remove_file(state.join(PRIOR_BACKUP)).unwrap();
        fs::write(
            state.join(ACTIVATION),
            serde_json::to_vec(&activation).unwrap(),
        )
        .unwrap();
        write_activation_candidate(&state, &completed);
        finish_activation(&state, &completed, &activation).unwrap();
        activation_absent(&state).unwrap();
        assert!(rollback_bytes(&state).unwrap().is_none());
        assert!(observe_rollback(&state, &|_| Ok(completed.clone())).is_err());
        remove_activation_fixture(&root, &completed);
    }

    #[test]
    fn unsafe_completed_rollback_slot_refuses_preflight_and_new_fence() {
        let (root, completed) = activation_fixture("completed-preflight");
        let state = root.join(STATE);
        fs::write(state.join(ROLLBACK), b"unknown retained archive").unwrap();
        fs::set_permissions(state.join(ROLLBACK), fs::Permissions::from_mode(0o600)).unwrap();
        let admitted = std::cell::Cell::new(false);
        assert!(preflight_at(&root, &completed, |_, _, _| {
            admitted.set(true);
            Ok(())
        })
        .is_err());
        assert!(!admitted.get());
        assert!(begin_activation(&state, &completed).is_err());
        activation_absent(&state).unwrap();
        assert_eq!(
            fs::read(state.join(ROLLBACK)).unwrap(),
            b"unknown retained archive"
        );
        remove_activation_fixture(&root, &completed);
    }

    #[test]
    fn private_recovery_parse_errors_never_echo_supplied_secret_values() {
        let secret = "private-model-credential-do-not-log";
        let malformed = format!(r#"{{"schema_version":"{secret}"}}"#);
        let prior_error = match decode_prior_backup(malformed.as_bytes()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("invalid private backup accepted"),
        };
        let rollback_error = match decode_rollback(malformed.as_bytes()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("invalid private rollback accepted"),
        };
        let backup = PriorBackup {
            schema_version: 1,
            candidate: "qwen3-4b-q4-k-m".into(),
            selection: Some(malformed.into_bytes()),
            environment: Some(vec![]),
            key: Some(vec![]),
        };
        let selection_error = prior_restore_profile(&backup, profile)
            .unwrap_err()
            .to_string();
        for error in [prior_error, rollback_error, selection_error] {
            assert!(!error.contains(secret));
            assert!(error.contains("preserve state"));
        }
    }

    #[test]
    fn checked_restart_stops_at_each_failed_stage_and_does_not_claim_success() {
        let stages = [
            RestartStage::Reload,
            RestartStage::Restart,
            RestartStage::Health,
            RestartStage::Worker,
            RestartStage::Reference,
        ];
        for (index, failed) in stages.into_iter().enumerate() {
            let mut called = vec![];
            let error = checked_restart_steps(|stage| {
                called.push(stage);
                if stage == failed {
                    Err("injected restart failure".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.stage, failed);
            assert_eq!(called, stages[..=index]);
        }
        let fenced = std::cell::Cell::new(false);
        let stopped = std::cell::Cell::new(false);
        assert!(finish_reconfiguration(
            || checked_restart_steps(|_| Ok(())),
            |_| {
                fenced.set(true);
                Ok(())
            },
            || {
                stopped.set(true);
                Ok(())
            }
        )
        .is_ok());
        assert!(!fenced.get() && !stopped.get());
    }

    #[test]
    fn observed_reconfiguration_failures_publish_quarantine_before_stop() {
        for failed in [
            RestartStage::Reload,
            RestartStage::Restart,
            RestartStage::Health,
            RestartStage::Worker,
            RestartStage::Reference,
        ] {
            let (root, completed, prior) =
                completed_rollback_fixture(&format!("quarantine-{failed:?}"));
            let state = root.join(STATE);
            let snapshot = activation_snapshot(&state).unwrap();
            let rollback = rollback_bytes(&state).unwrap();
            let calls = std::cell::RefCell::new(vec![]);
            let error = finish_reconfiguration(
                || {
                    checked_restart_steps(|stage| {
                        if stage == failed {
                            Err("injected-private-diagnostic-never-persist".into())
                        } else {
                            Ok(())
                        }
                    })
                },
                |stage| {
                    calls.borrow_mut().push("fence");
                    publish_quarantine(&state, &completed, stage)
                },
                || {
                    calls.borrow_mut().push("stop");
                    assert!(activation_absent(&state).is_err());
                    let observed =
                        observe_quarantine(&state, &|id| fixture_resolve(id, &completed, &prior))?;
                    assert_eq!(observed.record.failed_stage, failed);
                    assert!(!String::from_utf8_lossy(&observed.bytes)
                        .contains("injected-private-diagnostic"));
                    Ok(())
                },
            )
            .unwrap_err()
            .to_string();
            assert_eq!(*calls.borrow(), ["fence", "stop"]);
            assert!(error.contains("durable model quarantine published"));
            assert!(error.contains("no rollback or readiness claimed"));
            assert_eq!(activation_snapshot(&state).unwrap(), snapshot);
            assert_eq!(rollback_bytes(&state).unwrap(), rollback);
            let metadata = fs::metadata(state.join(QUARANTINE)).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.nlink(), metadata.mode() & 0o777),
                (0, 1, 0o600)
            );
            assert!(preflight_at(&root, &completed, |_, _, _| Ok(())).is_err());
            assert!(begin_activation(&state, &completed).is_err());
            activation_records_absent(&state).unwrap();
            remove_completed_rollback_fixture(&root, &completed, &prior);
        }
    }

    #[test]
    fn failed_quarantine_publication_still_attempts_stop_without_overwriting_unknown_state() {
        let (root, p) = activation_fixture("quarantine-publication-fail");
        let state = root.join(STATE);
        fs::write(state.join(QUARANTINE), b"unknown prior quarantine").unwrap();
        fs::set_permissions(state.join(QUARANTINE), fs::Permissions::from_mode(0o600)).unwrap();
        let stopped = std::cell::Cell::new(false);
        let error = finish_reconfiguration(
            || {
                Err(RestartFailure {
                    stage: RestartStage::Health,
                    error: "health failed".into(),
                })
            },
            |stage| publish_quarantine(&state, &p, stage),
            || {
                stopped.set(true);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(stopped.get());
        assert!(error.contains("quarantine publication failed"));
        assert_eq!(
            quarantine_bytes(&state).unwrap().unwrap(),
            b"unknown prior quarantine"
        );
        assert!(activation_absent(&state).is_err());
        assert!(observe_quarantine(&state, &|_| Ok(p.clone())).is_err());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn failed_validation_commit_is_quarantined_before_stop_and_retains_trial() {
        let (root, p) = activation_fixture("validation-commit-failure");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let trial = validation::Guard::begin(&state, &p).unwrap();
        fs::write(
            state.join(REFERENCE_ENV),
            b"changed before trial completion",
        )
        .unwrap();
        let error = finish_reconfiguration(
            || {
                trial.complete(&p).map_err(|error| RestartFailure {
                    stage: RestartStage::Validation,
                    error,
                })
            },
            |stage| {
                assert_eq!(stage, RestartStage::Validation);
                publish_quarantine(&state, &p, stage)
            },
            || {
                assert!(state.join(validation::PENDING).exists());
                assert!(quarantine_bytes(&state)?.is_some());
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Validation") && error.contains("worker stop requested"));
        let record: Quarantine =
            serde_json::from_slice(&quarantine_bytes(&state).unwrap().unwrap()).unwrap();
        assert_eq!(record.failed_stage, RestartStage::Validation);
        assert!(activation_absent(&state).is_err());
        fs::remove_file(state.join(validation::PENDING)).unwrap();
        fs::remove_file(state.join("model-validation.lock")).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn failed_stop_keeps_durable_quarantine_and_live_runtime_exclusion() {
        let (root, p) = activation_fixture("quarantine-stop-fail");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        let runtime = runtime_lock(&root, true).unwrap();
        let error = finish_reconfiguration(
            || {
                Err(RestartFailure {
                    stage: RestartStage::Worker,
                    error: "worker state failed".into(),
                })
            },
            |stage| publish_quarantine(&state, &p, stage),
            || Err("worker did not stop".into()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("worker stop request failed"));
        assert!(quarantine_bytes(&state).unwrap().is_some());
        assert!(activation_absent(&state).is_err());
        assert!(runtime_lock(&root, false).is_err());
        drop(runtime);
        let observed = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        reviewed_clear_quarantine(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
        activation_absent(&state).unwrap();
        fs::remove_file(state.join("model-runtime.lock")).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn quarantine_review_rejects_stale_configuration_and_preserves_recovery_disablement() {
        let (root, p) = activation_fixture("quarantine-review");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        fs::write(
            state.join("model-disabled"),
            b"operator recovery disablement",
        )
        .unwrap();
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        let observed = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert!(reviewed_clear_quarantine(&state, &"00".repeat(32), &|_| Ok(p.clone())).is_err());
        let token = "b".repeat(64);
        fs::write(state.join("model-auth/api-key"), &token).unwrap();
        fs::write(state.join(REFERENCE_ENV), reference_environment(&p, &token)).unwrap();
        assert!(reviewed_clear_quarantine(&state, &observed.review, &|_| Ok(p.clone())).is_err());
        let fresh = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert!(fresh.clearable);
        assert_ne!(fresh.review, observed.review);
        let before = activation_snapshot(&state).unwrap();
        reviewed_clear_quarantine(&state, &fresh.review, &|_| Ok(p.clone())).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), before);
        assert_eq!(
            fs::read(state.join("model-disabled")).unwrap(),
            b"operator recovery disablement"
        );
        fs::remove_file(state.join("model-disabled")).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn quarantine_incident_identity_prevents_old_review_reuse_for_identical_failure() {
        let (root, p) = activation_fixture("quarantine-incident");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        let first = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        reviewed_clear_quarantine(&state, &first.review, &|_| Ok(p.clone())).unwrap();
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        let next = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert_eq!(first.hashes, next.hashes);
        assert_ne!(first.record.incident_id, next.record.incident_id);
        assert_ne!(first.review, next.review);
        assert!(reviewed_clear_quarantine(&state, &first.review, &|_| Ok(p.clone())).is_err());
        assert_eq!(quarantine_bytes(&state).unwrap().unwrap(), next.bytes);
        reviewed_clear_quarantine(&state, &next.review, &|_| Ok(p.clone())).unwrap();
        remove_activation_fixture(&root, &p);
    }

    fn write_incomplete_quarantine(state: &Path, bytes: &[u8]) {
        fs::write(state.join(QUARANTINE), bytes).unwrap();
        fs::set_permissions(state.join(QUARANTINE), fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn incomplete_quarantine_retains_exact_private_bytes_and_preserves_configuration_and_disablement(
    ) {
        for (label, bytes, selected) in [
            ("empty", &b""[..], true),
            ("truncated", &b"{\"schema_version\":1,"[..], true),
            ("manual", &b"{"[..], false),
        ] {
            let (root, p) = activation_fixture(&format!("incomplete-{label}"));
            let state = root.join(STATE);
            if selected {
                write_activation_candidate(&state, &p);
            }
            write_incomplete_quarantine(&state, bytes);
            fs::write(state.join("model-disabled"), b"independent recovery").unwrap();
            let before = activation_snapshot(&state).unwrap();
            assert!(activation_absent(&state).is_err());
            assert!(observe_quarantine(&state, &|_| Ok(p.clone())).is_err());
            let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
            assert_eq!(observed.current_profile.is_some(), selected);
            assert!(!state.join(&observed.archive).exists());
            let archive =
                reviewed_retain_incomplete_quarantine(&state, &observed.review, &|_| Ok(p.clone()))
                    .unwrap();
            assert_eq!(fs::read(state.join(&archive)).unwrap(), bytes);
            let metadata = fs::symlink_metadata(state.join(&archive)).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.nlink(), metadata.mode() & 0o777),
                (0, 1, 0o600)
            );
            assert!(!state.join(QUARANTINE).exists());
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            assert!(state.join("models").join(format!("{}.gguf", p.id)).exists());
            assert_eq!(
                fs::read(state.join("model-disabled")).unwrap(),
                b"independent recovery"
            );
            assert!(
                reviewed_retain_incomplete_quarantine(&state, &observed.review, &|_| Ok(p.clone()))
                    .is_err()
            );
            fs::remove_file(state.join(archive)).unwrap();
            fs::remove_file(state.join("model-disabled")).unwrap();
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn incomplete_quarantine_rejects_complete_future_and_other_malformed_records_without_leaking_bytes(
    ) {
        for (index, bytes) in [
            &b"null"[..],
            &b"{}"[..],
            &b"{\"schema_version\":999}"[..],
            &b"[1]"[..],
            &b"garbage-secret"[..],
            &b"{\"secret\":invalid}"[..],
            &b"\xff"[..],
        ]
        .iter()
        .enumerate()
        {
            let (root, p) = activation_fixture(&format!("incomplete-rejected-{index}"));
            let state = root.join(STATE);
            write_incomplete_quarantine(&state, bytes);
            let error = observe_incomplete_quarantine(&state, &|_| Ok(p.clone()))
                .err()
                .unwrap()
                .to_string();
            assert_eq!(error, "quarantine is not incomplete JSON; preserve state");
            assert_eq!(quarantine_bytes(&state).unwrap().unwrap(), *bytes);
            assert!(activation_absent(&state).is_err());
            remove_activation_fixture(&root, &p);
        }
        let (root, p) = activation_fixture("incomplete-valid-record");
        let state = root.join(STATE);
        publish_quarantine(&state, &p, RestartStage::Restart).unwrap();
        assert!(observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).is_err());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn incomplete_quarantine_requires_fresh_exact_review_and_verified_consistent_weights() {
        let (root, p) = activation_fixture("incomplete-review");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        write_incomplete_quarantine(&state, b"{");
        let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        for digest in ["not-a-digest".to_string(), "00".repeat(32)] {
            assert!(
                reviewed_retain_incomplete_quarantine(&state, &digest, &|_| Ok(p.clone())).is_err()
            );
        }
        fs::write(state.join("model-auth/api-key"), "b".repeat(64)).unwrap();
        assert!(observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).is_err());
        fs::write(
            state.join(REFERENCE_ENV),
            reference_environment(&p, &"b".repeat(64)),
        )
        .unwrap();
        assert!(reviewed_retain_incomplete_quarantine(
            &state,
            &observed.review,
            &|_| Ok(p.clone())
        )
        .is_err());
        let fresh = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        fs::write(
            state.join("models").join(format!("{}.gguf", p.id)),
            b"corrupt",
        )
        .unwrap();
        assert!(
            reviewed_retain_incomplete_quarantine(&state, &fresh.review, &|_| Ok(p.clone()))
                .is_err()
        );
        assert!(!state.join(&observed.archive).exists());
        assert!(activation_absent(&state).is_err());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn incomplete_quarantine_file_replacement_invalidates_review_even_for_identical_bytes() {
        let (root, p) = activation_fixture("incomplete-replacement");
        let state = root.join(STATE);
        write_incomplete_quarantine(&state, b"{");
        let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        let displaced = state.join("displaced-quarantine");
        fs::rename(state.join(QUARANTINE), &displaced).unwrap();
        write_incomplete_quarantine(&state, b"{");
        let next = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert_ne!(observed.identity, next.identity);
        assert_ne!(observed.review, next.review);
        assert!(reviewed_retain_incomplete_quarantine(
            &state,
            &observed.review,
            &|_| Ok(p.clone())
        )
        .is_err());
        assert!(!state.join(next.archive).exists());
        fs::remove_file(displaced).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn incomplete_quarantine_retries_exact_private_retention_left_before_clearance() {
        let (root, p) = activation_fixture("incomplete-retry");
        let state = root.join(STATE);
        write_incomplete_quarantine(&state, b"{\"schema_version\":");
        let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        fs::write(state.join(&observed.archive), &observed.bytes).unwrap();
        fs::set_permissions(
            state.join(&observed.archive),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let again = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert_eq!(again.review, observed.review);
        let archive =
            reviewed_retain_incomplete_quarantine(&state, &observed.review, &|_| Ok(p.clone()))
                .unwrap();
        assert_eq!(fs::read(state.join(&archive)).unwrap(), observed.bytes);
        assert!(!state.join(QUARANTINE).exists());
        fs::remove_file(state.join(archive)).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn isolated_worker_cannot_read_or_remove_retained_incomplete_quarantine_bytes() {
        let (root, p) = activation_fixture("incomplete-private-dac");
        let state = root.join(STATE);
        for directory in [&root, state.parent().unwrap(), &state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_incomplete_quarantine(&state, b"{\"opaque_secret\":\"retain-privately");
        let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        let archive =
            reviewed_retain_incomplete_quarantine(&state, &observed.review, &|_| Ok(p.clone()))
                .unwrap();
        let mut child = Command::new("/usr/bin/python3");
        child
            .args([
                "-I",
                "-c",
                r#"
import os, stat, sys
assert os.geteuid() == 989 and os.getgroups() == []
path = sys.argv[1]
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
for action in (lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW), lambda: os.unlink(path)):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise RuntimeError('worker accessed or removed private retained bytes')
print('MODEL_INCOMPLETE_QUARANTINE_DAC_PASSED')
"#,
            ])
            .arg(state.join(&archive));
        unsafe {
            child.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(989) != 0
                    || libc::setuid(989) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"MODEL_INCOMPLETE_QUARANTINE_DAC_PASSED\n");
        assert_eq!(fs::read(state.join(&archive)).unwrap(), observed.bytes);
        fs::remove_file(state.join(archive)).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn incomplete_quarantine_retention_conflicts_or_unsafe_archives_keep_fence_and_evidence() {
        for label in [
            "conflict",
            "public",
            "symlink",
            "hardlink",
            "directory",
            "oversized",
        ] {
            let (root, p) = activation_fixture(&format!("incomplete-archive-{label}"));
            let state = root.join(STATE);
            write_incomplete_quarantine(&state, b"{");
            let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
            let archive = state.join(&observed.archive);
            let alias = state.join("archive-alias");
            match label {
                "symlink" => std::os::unix::fs::symlink(state.join(QUARANTINE), &archive).unwrap(),
                "directory" => fs::create_dir(&archive).unwrap(),
                _ => {
                    fs::write(
                        &archive,
                        if label == "conflict" {
                            &b"partial retention"[..]
                        } else {
                            &observed.bytes
                        },
                    )
                    .unwrap();
                    fs::set_permissions(
                        &archive,
                        fs::Permissions::from_mode(if label == "public" { 0o644 } else { 0o600 }),
                    )
                    .unwrap();
                    if label == "hardlink" {
                        fs::hard_link(&archive, &alias).unwrap();
                    }
                    if label == "oversized" {
                        fs::write(&archive, vec![b' '; 4097]).unwrap();
                    }
                }
            }
            assert!(
                reviewed_retain_incomplete_quarantine(&state, &observed.review, &|_| Ok(p.clone()))
                    .is_err()
            );
            assert_eq!(quarantine_bytes(&state).unwrap().unwrap(), observed.bytes);
            assert!(fs::symlink_metadata(&archive).is_ok());
            if alias.exists() {
                fs::remove_file(alias).unwrap();
            }
            if label == "directory" {
                fs::remove_dir(archive).unwrap();
            } else {
                fs::remove_file(archive).unwrap();
            }
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn incomplete_quarantine_rechecks_after_blocking_resolution_and_after_retention() {
        for after_retention in [false, true] {
            let (root, p) = activation_fixture(&format!("incomplete-fresh-{after_retention}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            write_incomplete_quarantine(&state, b"{");
            let observed = observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).unwrap();
            let calls = std::cell::Cell::new(0);
            let resolve = |_: &str| {
                calls.set(calls.get() + 1);
                if calls.get() == if after_retention { 2 } else { 1 } {
                    write_incomplete_quarantine(&state, b"{\"changed\":");
                }
                Ok(p.clone())
            };
            assert!(
                reviewed_retain_incomplete_quarantine(&state, &observed.review, &resolve).is_err()
            );
            assert_eq!(quarantine_bytes(&state).unwrap().unwrap(), b"{\"changed\":");
            assert_eq!(state.join(&observed.archive).exists(), after_retention);
            assert!(activation_absent(&state).is_err());
            if after_retention {
                assert_eq!(
                    fs::read(state.join(&observed.archive)).unwrap(),
                    observed.bytes
                );
                fs::remove_file(state.join(observed.archive)).unwrap();
            }
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn incomplete_quarantine_refuses_pending_activation_and_unsafe_source_metadata() {
        for label in [
            "pending",
            "backup",
            "public",
            "symlink",
            "hardlink",
            "oversized",
            "missing",
        ] {
            let (root, p) = activation_fixture(&format!("incomplete-source-{label}"));
            let state = root.join(STATE);
            write_incomplete_quarantine(&state, b"{");
            let alias = state.join("quarantine-alias");
            match label {
                "pending" => fs::write(state.join(ACTIVATION), b"uncertain").unwrap(),
                "backup" => fs::write(state.join(PRIOR_BACKUP), b"uncertain").unwrap(),
                "public" => {
                    fs::set_permissions(state.join(QUARANTINE), fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                "symlink" => {
                    fs::rename(state.join(QUARANTINE), &alias).unwrap();
                    std::os::unix::fs::symlink(&alias, state.join(QUARANTINE)).unwrap();
                }
                "hardlink" => fs::hard_link(state.join(QUARANTINE), &alias).unwrap(),
                "oversized" => fs::write(state.join(QUARANTINE), vec![b' '; 4097]).unwrap(),
                "missing" => fs::remove_file(state.join(QUARANTINE)).unwrap(),
                _ => unreachable!(),
            }
            assert!(observe_incomplete_quarantine(&state, &|_| Ok(p.clone())).is_err());
            if label != "missing" {
                assert!(fs::symlink_metadata(state.join(QUARANTINE)).is_ok());
            }
            if alias.exists() {
                fs::remove_file(alias).unwrap();
            }
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn quarantine_does_not_clear_inconsistent_configuration_or_bad_weights() {
        let (root, p) = activation_fixture("quarantine-invalid-current");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        publish_quarantine(&state, &p, RestartStage::Worker).unwrap();
        let observed = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        let weights = state.join("models").join(format!("{}.gguf", p.id));
        let original = fs::read(&weights).unwrap();
        fs::write(&weights, b"bad selected weights").unwrap();
        let bad = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert!(!bad.clearable);
        assert_eq!(bad.phase, "configuration_or_weights_unavailable");
        assert!(reviewed_clear_quarantine(&state, &observed.review, &|_| Ok(p.clone())).is_err());
        fs::write(&weights, original).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"inconsistent environment").unwrap();
        let inconsistent = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert!(!inconsistent.clearable);
        assert!(
            reviewed_clear_quarantine(&state, &inconsistent.review, &|_| Ok(p.clone())).is_err()
        );
        assert!(quarantine_bytes(&state).unwrap().is_some());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn manual_only_quarantine_clearance_does_not_materialize_a_model_or_delete_cache() {
        let (root, p) = activation_fixture("quarantine-manual");
        let state = root.join(STATE);
        publish_quarantine(&state, &p, RestartStage::Reload).unwrap();
        let observed = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
        assert!(observed.clearable && observed.current_profile.is_none());
        assert_eq!(observed.phase, "manual_only_configuration");
        reviewed_clear_quarantine(&state, &observed.review, &|_| Ok(p.clone())).unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), (None, None, None));
        verify_file(&state.join("models").join(format!("{}.gguf", p.id)), &p).unwrap();
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn reviewed_completed_rollback_under_quarantine_preserves_both_independent_fences() {
        let (root, completed, prior) = completed_rollback_fixture("quarantine-rollback");
        let state = root.join(STATE);
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        publish_quarantine(&state, &completed, RestartStage::Health).unwrap();
        let quarantine = quarantine_bytes(&state).unwrap();
        fs::write(state.join("model-disabled"), b"disabled independently").unwrap();
        let observed = observe_rollback(&state, &resolve).unwrap();
        reviewed_completed_rollback(&state, &observed.review, &resolve).unwrap();
        activation_records_absent(&state).unwrap();
        assert!(activation_absent(&state).is_err());
        assert_eq!(quarantine_bytes(&state).unwrap(), quarantine);
        assert_eq!(selected_at(&state).unwrap().id, prior.id);
        let fresh = observe_quarantine(&state, &resolve).unwrap();
        assert_eq!(fresh.current_profile.as_ref().unwrap().id, prior.id);
        reviewed_clear_quarantine(&state, &fresh.review, &resolve).unwrap();
        activation_absent(&state).unwrap();
        assert_eq!(
            fs::read(state.join("model-disabled")).unwrap(),
            b"disabled independently"
        );
        fs::remove_file(state.join("model-disabled")).unwrap();
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn pending_restoration_under_quarantine_requires_activation_review_before_clearance() {
        let (root, completed, prior) = completed_rollback_fixture("quarantine-pending");
        let state = root.join(STATE);
        let resolve = |id: &str| fixture_resolve(id, &completed, &prior);
        publish_quarantine(&state, &completed, RestartStage::Restart).unwrap();
        let quarantine = quarantine_bytes(&state).unwrap();
        let before = activation_snapshot(&state).unwrap();
        begin_activation_records(&state, &completed).unwrap();
        fs::write(state.join(REFERENCE_ENV), b"interrupted rollback write").unwrap();
        assert!(observe_quarantine(&state, &resolve).is_err());
        let pending = observe_activation(&state, &completed, true).unwrap();
        reviewed_restore_configuration(&state, &completed, &pending.review, |_| {
            Ok(completed.clone())
        })
        .unwrap();
        assert_eq!(activation_snapshot(&state).unwrap(), before);
        assert_eq!(quarantine_bytes(&state).unwrap(), quarantine);
        let fresh = observe_quarantine(&state, &resolve).unwrap();
        reviewed_clear_quarantine(&state, &fresh.review, &resolve).unwrap();
        remove_completed_rollback_fixture(&root, &completed, &prior);
    }

    #[test]
    fn quarantine_refuses_unsafe_substituted_or_unknown_records_without_mutation() {
        for kind in [
            "missing",
            "malformed",
            "public",
            "symlink",
            "hardlink",
            "oversized",
            "catalog",
            "incident",
            "unknown-stage",
            "noncanonical",
        ] {
            let (root, p) = activation_fixture(&format!("quarantine-unsafe-{kind}"));
            let state = root.join(STATE);
            write_activation_candidate(&state, &p);
            publish_quarantine(&state, &p, RestartStage::Health).unwrap();
            let observed = observe_quarantine(&state, &|_| Ok(p.clone())).unwrap();
            let before = activation_snapshot(&state).unwrap();
            let path = state.join(QUARANTINE);
            match kind {
                "missing" => fs::remove_file(&path).unwrap(),
                "malformed" => fs::write(&path, b"{}").unwrap(),
                "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(state.join("model-auth/api-key"), &path).unwrap();
                }
                "hardlink" => {
                    fs::remove_file(&path).unwrap();
                    fs::hard_link(state.join("model-auth/api-key"), &path).unwrap();
                }
                "oversized" => fs::write(&path, vec![b' '; 4097]).unwrap(),
                "catalog" => {
                    let mut record: Quarantine = serde_json::from_slice(&observed.bytes).unwrap();
                    record.catalog_sha256 = "aa".repeat(32);
                    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                "incident" => {
                    let mut record: Quarantine = serde_json::from_slice(&observed.bytes).unwrap();
                    record.incident_id = "b".repeat(32);
                    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                "unknown-stage" => {
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&observed.bytes).unwrap();
                    record["failed_stage"] = "not-approved".into();
                    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                "noncanonical" => {
                    let mut bytes = observed.bytes.clone();
                    bytes.push(b'\n');
                    fs::write(&path, bytes).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                reviewed_clear_quarantine(&state, &observed.review, &|_| Ok(p.clone())).is_err()
            );
            if kind != "missing" {
                assert!(activation_absent(&state).is_err());
            }
            if kind == "hardlink" {
                fs::remove_file(&path).unwrap();
            }
            assert_eq!(activation_snapshot(&state).unwrap(), before);
            remove_activation_fixture(&root, &p);
        }
    }

    #[test]
    fn quarantine_inspection_rechecks_after_blocking_configuration_verification() {
        let (root, p) = activation_fixture("quarantine-inspection-race");
        let state = root.join(STATE);
        write_activation_candidate(&state, &p);
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        let calls = std::cell::Cell::new(0);
        assert!(observe_quarantine(&state, &|_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                fs::write(state.join(REFERENCE_ENV), b"changed during verification")?;
            }
            Ok(p.clone())
        })
        .is_err());
        assert!(activation_absent(&state).is_err());
        assert!(quarantine_bytes(&state).unwrap().is_some());
        remove_activation_fixture(&root, &p);
    }

    #[test]
    fn isolated_worker_cannot_read_or_remove_quarantine_record() {
        let (root, p) = activation_fixture("quarantine-private-dac");
        let state = root.join(STATE);
        for directory in [&root, state.parent().unwrap(), &state] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        publish_quarantine(&state, &p, RestartStage::Health).unwrap();
        let mut child = Command::new("/usr/bin/python3");
        child
            .args([
                "-I",
                "-c",
                r#"
import os, stat, sys
assert os.geteuid() == 989 and os.getgroups() == []
path = sys.argv[1]
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
for action in (lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW), lambda: os.unlink(path)):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise RuntimeError('worker accessed quarantine contents or removed its fence')
print('MODEL_QUARANTINE_DAC_PASSED')
"#,
            ])
            .arg(state.join(QUARANTINE));
        unsafe {
            child.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(989) != 0
                    || libc::setuid(989) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"MODEL_QUARANTINE_DAC_PASSED\n");
        assert!(quarantine_bytes(&state).unwrap().is_some());
        remove_activation_fixture(&root, &p);
    }
}
