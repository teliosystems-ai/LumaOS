//! Pinned image-owned model admission and atomic, bounded HTTPS acquisition.
//! A model is data, never an executable or an authority to perform OS effects.
use crate::{bundle, disk::command, platform, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CATALOG: &str = include_str!("../../../native/image/model-catalog.json");
const VAR: &str = "/var";
const STATE: &str = "lib/luma-os";
const RUNTIME: &str = "/usr/libexec/luma-os/llama/llama-server";

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

fn admit(p: &Profile, total: u64, available: u64, free: u64, cpus: usize) -> Result<()> {
    if total < p.minimum_ram_bytes
        || available < p.minimum_available_bytes
        || cpus < 2
        || free
            < p.bytes
                .checked_add(2 * 1024 * 1024 * 1024)
                .ok_or("space overflow")?
    {
        return Err(format!("{} cannot be admitted: total RAM {total}, available {available}, free storage {free}, CPUs {cpus}; select a smaller profile or manual-only", p.id).into());
    }
    Ok(())
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
    admit(
        p,
        memory(&info, "MemTotal")?,
        memory(&info, "MemAvailable")?,
        free,
        std::thread::available_parallelism()?.get(),
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

fn verify_file(at: &Path, p: &Profile) -> Result<()> {
    let mut f = open_regular(at)?;
    if f.metadata()?.len() != p.bytes {
        return Err("model byte count mismatch".into());
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
    Ok(())
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
    let state = var.join(STATE);
    let models = state.join("models");
    safe_dir(&models)?;
    reconcile_downloads(&models, &catalog()?.models)?;
    platform::ensure_model_identities(var)?;
    check(p, available_space(&models)?)?;
    let file = models.join(format!("{}.gguf", p.id));
    if file.try_exists()? {
        verify_file(&file, p)?;
    } else {
        println!("Downloading {} ({} bytes)...", p.id, p.bytes);
        fetch(&file, p)?;
    }
    // Activation is last. Interrupted acquisition never becomes a selection.
    let auth = state.join("model-auth");
    safe_dir(&auth)?;
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o750))?;
    command(
        "/usr/bin/chown",
        &["0:989", auth.to_str().ok_or("invalid auth path")?],
    )?;
    let key_path = auth.join("api-key");
    let token = if key_path.exists() {
        let mut s = String::new();
        open_regular(&key_path)?.take(65).read_to_string(&mut s)?;
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid model credential".into());
        }
        s
    } else {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let s = bundle::hex(&bytes);
        platform::write_atomic(&key_path, s.as_bytes(), 0o640)?;
        command(
            "/usr/bin/chown",
            &["0:989", key_path.to_str().ok_or("invalid auth path")?],
        )?;
        s
    };
    let env = state.join("reference/model.env");
    platform::write_atomic(&env, format!("LUMA_MODEL_ENDPOINT=http://127.0.0.1:8081/v1\nLUMA_MODEL_NAME={}\nLUMA_MODEL_API_KEY={token}\n",p.id).as_bytes(), 0o600)?;
    command(
        "/usr/bin/chown",
        &["990:990", env.to_str().ok_or("invalid environment path")?],
    )?;
    platform::write_atomic(
        &state.join("model-selection.json"),
        &serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":p.id}))?,
        0o644,
    )?;
    println!("MODEL INSTALLED AND VERIFIED: {}. Inference activates on installed-system boot; no production certification implied.", p.id);
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
    let mut text = String::new();
    open_regular(&state.join("model-selection.json"))?
        .take(4097)
        .read_to_string(&mut text)?;
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

pub fn install(id: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let p = profile(id)?;
    let _lock = operation_lock(Path::new(VAR))?;
    // Do not replace a running model or its authentication material.
    command("/usr/bin/systemctl", &["stop", "luma-model.service"])?;
    provision_locked(Path::new(VAR), &p)?;
    command("/usr/bin/systemctl", &["daemon-reload"])?;
    command(
        "/usr/bin/systemctl",
        &["restart", "luma-model.service", "luma-reference.service"],
    )?;
    Ok(())
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
    let p = selected()?;
    let file = Path::new(VAR)
        .join(STATE)
        .join("models")
        .join(format!("{}.gguf", p.id));
    verify_file(&file, &p)?;
    let info = fs::read_to_string("/proc/meminfo")?;
    if memory(&info, "MemTotal")? < p.minimum_ram_bytes
        || memory(&info, "MemAvailable")? < p.minimum_available_bytes
    {
        return Err(
            "insufficient memory at model activation; manual operation remains available".into(),
        );
    }
    let error = Command::new(RUNTIME)
        .args([
            "--model",
            file.to_str().ok_or("model path")?,
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
        .env("LD_LIBRARY_PATH", "/usr/libexec/luma-os/llama")
        .exec();
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
        assert!(verify_file(&path, &p).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(verify_file(&link, &p).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
