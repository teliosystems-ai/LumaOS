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
const REFERENCE_ENV: &str = "model-reference.env";

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
        if !fs::symlink_metadata(&file)?.is_file() {
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

fn verified_file(at: &Path, p: &Profile) -> Result<File> {
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
        let n = f.read(&mut buffer)?;
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
    Ok(f)
}

fn verify_file(at: &Path, p: &Profile) -> Result<()> {
    verified_file(at, p).map(drop)
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

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn fetch(at: &Path, p: &Profile) -> Result<()> {
    // Parent is root-only for writing. curl runs without root, supplementary
    // groups, ambient environment, stdin, proxy credentials or configuration.
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let temporary = Temporary(at.with_extension(format!("partial-{}", bundle::hex(&random))));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary.0)?;
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
    let max_bytes = p.bytes;
    let parent_pid = std::process::id();
    unsafe {
        process.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(988) != 0
                || libc::setuid(988) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) != 0
                || libc::getppid() as u32 != parent_pid
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "download owner exited",
                ));
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
    let mut child = process.spawn()?;
    let started = std::time::Instant::now();
    let mut reported = 0;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let elapsed = started.elapsed().as_secs();
        if elapsed / 15 > reported {
            reported = elapsed / 15;
            println!(
                "Model download: {} / {} bytes ({}s)",
                file.metadata()?.len(),
                p.bytes,
                elapsed
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    if !status.success() {
        return Err("model download failed; no model was activated; retry model-install".into());
    }
    println!("Verifying model bytes and SHA-256...");
    file.sync_all()?;
    verify_file(&temporary.0, p)?;
    fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o444))?;
    fs::rename(&temporary.0, at)?;
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
    let state = var.join(STATE);
    activation_absent(&state)?;
    let models = state.join("models");
    safe_dir(&models)?;
    reconcile_downloads(&models, &catalog()?.models)?;
    platform::ensure_model_identities(var)?;
    let file = models.join(format!("{}.gguf", p.id));
    match fs::symlink_metadata(&file) {
        Ok(_) => {
            check_cached(p, available_space(&models)?)?;
            verify_file(&file, p)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check(p, available_space(&models)?)?;
            println!("Downloading {} ({} bytes)...", p.id, p.bytes);
            fetch(&file, p)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn activate_cached(var: &Path, p: &Profile) -> Result<()> {
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
    finish_activation(&state, p, &activation)?;
    println!("MODEL FILES INSTALLED AND VERIFIED: {}. Runtime readiness is checked separately after reconfiguration or at installed-system boot; no production certification implied.", p.id);
    Ok(())
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
}

fn activation_absent(state: &Path) -> Result<()> {
    match fs::symlink_metadata(state.join(ACTIVATION)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("model activation pending; reviewed reconciliation required".into()),
    }
}

fn checked_activation_bytes(path: &Path, max: u64, owner: u32) -> Result<Option<Vec<u8>>> {
    let original = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !original.is_file()
        || original.uid() != owner
        || original.nlink() != 1
        || original.mode() & 0o022 != 0
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
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--all",
            "--property=LoadState,ActiveState,SubState",
            "--no-pager",
            "luma-model.service",
        ])
        .output()?;
    if model_unit_running(output.status.success(), &output.stdout)? {
        Ok(Some(prior_snapshot_at(&var.join(STATE))?))
    } else {
        Ok(None)
    }
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
    let (selection, env, key) = activation_snapshot(state)?;
    let record = Activation {
        schema_version: 1,
        candidate: p.id.clone(),
        prior_selection_sha256: activation_digest(&selection),
        prior_env_sha256: activation_digest(&env),
        prior_key_sha256: activation_digest(&key),
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
        || record.schema_version != 1
        || record.candidate != p.id
        || [
            &record.prior_selection_sha256,
            &record.prior_env_sha256,
            &record.prior_key_sha256,
        ]
        .into_iter()
        .flatten()
        .any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("invalid retained model activation; preserve state".into());
    }
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
    Ok(ActivationObservation {
        record,
        marker,
        phase,
        candidate_consistent: candidate,
        review: bundle::hex(&digest.finalize()),
    })
}

fn clear_activation(state: &Path, observation: &ActivationObservation) -> Result<()> {
    if activation_bytes(&state.join(ACTIVATION), 4096)? != Some(observation.marker.clone()) {
        return Err("model activation marker changed; preserve state".into());
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

pub fn activation_reconcile(action: Option<(&str, &str)>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let var = Path::new(VAR);
    let _operation = operation_lock(var)?;
    let _runtime = runtime_lock(var, false)?;
    let state = var.join(STATE);
    let marker =
        activation_bytes(&state.join(ACTIVATION), 4096)?.ok_or("no pending model activation")?;
    let record: Activation = serde_json::from_slice(&marker)?;
    let p = profile(&record.candidate)?;
    let observation = observe_activation(&state, &p, true)?;
    match action {
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
                "worker_started":false,"mutation_performed":false,
                "clearable":observation.phase != "partial_or_conflicting_state",
                "completion_requires_write":observation.phase == "partial_or_conflicting_state"})
            );
        }
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

/// Read-only, advisory preflight. Activation repeats admission after stopping
/// the managed worker; neither observation reserves RAM or storage.
fn preflight_at(
    var: &Path,
    p: &Profile,
    admit: impl FnOnce(&Profile, u64, bool) -> Result<()>,
) -> Result<()> {
    let state = var.join(STATE);
    activation_absent(&state)?;
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
        "activation_guaranteed":false,"gate_closing":false})
    );
    Ok(())
}

pub fn install(id: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let p = profile(id)?;
    let _lock = operation_lock(Path::new(VAR))?;
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
        || activate_cached(Path::new(VAR), &p),
        || {
            command("/usr/bin/systemctl", &["daemon-reload"])?;
            command(
                "/usr/bin/systemctl",
                &["restart", "luma-model.service", "luma-reference.service"],
            )?;
            // A successful systemd job is not listener readiness. Keep the
            // bounded health check independent of model-generated output.
            command(
                "/usr/bin/python3",
                &["-I", "/usr/libexec/luma-os/model-health.py"],
            )?;
            if running_prior(Path::new(VAR))?
                .as_ref()
                .map(|current| current.profile.id.as_str())
                != Some(p.id.as_str())
            {
                return Err("model listener responded but selected worker is not running".into());
            }
            command(
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "luma-reference.service"],
            )?;
            Ok(())
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
    activation_absent(&Path::new(VAR).join(STATE))?;
    let p = selected()?;
    admit_cgroup(&p, effective_memory_limit()?)?;
    let file = Path::new(VAR)
        .join(STATE)
        .join("models")
        .join(format!("{}.gguf", p.id));
    let verified = verified_file(&file, &p)?;
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
    let error = command.exec();
    Err(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cleanup_fixture(label: &str) -> (PathBuf, PathBuf, Vec<Profile>) {
        let dir =
            std::env::temp_dir().join(format!("luma-download-{label}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let profiles = catalog().unwrap().models;
        let partial = dir.join(format!("{}.partial-{}", profiles[0].id, "a".repeat(32)));
        (dir, partial, profiles)
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
        fs::write(state.join("models").join(format!("{}.gguf", p.id)), weights).unwrap();
        (root, p)
    }

    fn remove_activation_fixture(root: &Path, p: &Profile) {
        let state = root.join(STATE);
        for path in [
            state.join(ACTIVATION),
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
}
