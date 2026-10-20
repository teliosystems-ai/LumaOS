//! Fixed root workspace worker and console-only PAM exchange. Entry points are
//! not published by the Windows coordinator until its independent journal and
//! owned interactive-controller ceremony has admitted the exact public bytes.
use super::{
    accounts::Transaction, parse, validate_profile, Request, CPU_SECONDS, NSS, PAM, PROFILE,
    PURPOSE_SECONDS,
};
use crate::{hosted_windows as host, sealed_credential::PrivateBuffer, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

const CGROUP: &str = "/sys/fs/cgroup/lumahosted.slice/luma-hosted-workspace-bootstrap.service";
const EXECUTABLE: &str = "/usr/libexec/luma-os/luma-platform";
const HELPER: &str = "/usr/libexec/luma-os/luma-workspace-auth-helper";
const PROFILE_PATH: &str = "/usr/share/luma-os/hosted-workspace.json";
const MANIFEST_PATH: &str = "/usr/share/luma-os/hosted-workspace-runtime.json";
const STATE: &str = "/var/lib/luma-hosted-workspace";
const TRANSACTION: &str = "/var/lib/luma-hosted-workspace/bootstrap";
const PROCFS: libc::c_long = 0x9fa0;
const CGROUP2: libc::c_long = 0x6367_7270;

fn memory_headroom(observation: &str, starting: bool) -> Result<()> {
    let mut available = None;
    for line in observation.lines() {
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            let fields = value.split_whitespace().collect::<Vec<_>>();
            if available.is_some()
                || fields.len() != 2
                || fields[1] != "kB"
                || !fields[0].bytes().all(|value| value.is_ascii_digit())
            {
                return Err("workspace kernel memory observation is ambiguous or malformed".into());
            }
            available = Some(
                fields[0]
                    .parse::<u64>()?
                    .checked_mul(1024)
                    .ok_or("workspace memory overflow")?,
            );
        }
    }
    let required = 1_073_741_824 + if starting { 268_435_456 } else { 0 };
    if available.ok_or("workspace memory observation missing")? < required {
        return Err(
            "workspace lacks observed memory headroom; no atomic reservation is inferred".into(),
        );
    }
    Ok(())
}
fn observe_headroom(starting: bool) -> Result<()> {
    memory_headroom(&host::kernel("/proc/meminfo", PROCFS, 32768)?, starting)
}

fn boottime() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0
        || !(0..1_000_000_000).contains(&value.tv_nsec)
    {
        return Err("workspace suspend-aware kernel clock unavailable".into());
    }
    let nanos = value.tv_nsec as u64;
    Ok((value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or("workspace monotonic overflow")?)
}
fn context(deadline: u64, child: Option<u32>) -> Result<()> {
    host::host_context()?;
    observe_headroom(false)?;
    crate::hosted_fence::check_current()?;
    if boottime()? >= deadline {
        return Err("original workspace worker lifetime expired".into());
    }
    let status = host::kernel("/proc/self/status", PROCFS, 32768)?;
    for name in ["Uid:", "Gid:"] {
        if host::status_field(&status, name)?
            .split_whitespace()
            .collect::<Vec<_>>()
            != ["0", "0", "0", "0"]
        {
            return Err("workspace worker retained an unexpected credential".into());
        }
    }
    for name in ["CapInh:", "CapAmb:"] {
        if host::status_field(&status, name)? != "0000000000000000" {
            return Err("workspace worker has ambient/inheritable capabilities".into());
        }
    }
    for name in ["CapPrm:", "CapEff:", "CapBnd:"] {
        if host::status_field(&status, name)? != "0000000000000001" {
            return Err("workspace worker lacks its exact chown-only capability bound".into());
        }
    }
    if host::status_field(&status, "NoNewPrivs:")? != "1"
        || host::status_field(&status, "Seccomp:")? != "2"
        || host::kernel("/proc/self/attr/current", PROCFS, 256)?
            != "luma-hosted-workspace-bootstrap (enforce)\n"
        || host::kernel("/proc/self/cgroup", PROCFS, 512)?
            != "0::/lumahosted.slice/luma-hosted-workspace-bootstrap.service\n"
    {
        return Err("workspace worker lacks its exact enforcing kernel context".into());
    }
    for (name, expected) in [
        ("memory.max", "268435456\n"),
        ("memory.swap.max", "0\n"),
        ("pids.max", "8\n"),
        ("cpu.max", "100000 100000\n"),
    ] {
        if host::kernel(&format!("{CGROUP}/{name}"), CGROUP2, 128)? != expected {
            return Err("workspace cgroup limits differ from reviewed limits".into());
        }
    }
    let mut allowed = BTreeSet::from([std::process::id()]);
    if let Some(pid) = child {
        allowed.insert(pid);
    }
    let observed = host::kernel(&format!("{CGROUP}/cgroup.procs"), CGROUP2, 1024)?;
    let mut seen = BTreeSet::new();
    for line in observed.lines() {
        let pid: u32 = line.parse()?;
        if !allowed.contains(&pid) || !seen.insert(pid) {
            return Err("workspace unit contains an unowned process".into());
        }
    }
    if !seen.contains(&std::process::id()) {
        return Err("workspace unit membership changed".into());
    }
    Ok(())
}

type Witness = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn witness(info: &std::fs::Metadata) -> Witness {
    (
        info.dev(),
        info.ino(),
        info.mode(),
        info.uid(),
        info.gid(),
        info.nlink(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}
struct Held {
    file: File,
    path: String,
    witness: Witness,
}
impl Held {
    fn open(path: &str, maximum: u64) -> Result<Self> {
        let path_value = Path::new(path);
        if !path_value.is_absolute() {
            return Err("workspace runtime path is not absolute".into());
        }
        for ancestor in path_value
            .parent()
            .ok_or("workspace runtime parent missing")?
            .ancestors()
        {
            let info = std::fs::symlink_metadata(ancestor)?;
            if !info.is_dir() || info.uid() != 0 || info.mode() & 0o7022 != 0 {
                return Err("workspace runtime ancestor is not root protected".into());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let info = file.metadata()?;
        if !info.is_file()
            || info.uid() != 0
            || info.nlink() != 1
            || info.mode() & 0o7022 != 0
            || info.len() == 0
            || info.len() > maximum
        {
            return Err("workspace runtime member is not a protected bounded file".into());
        }
        let value = Self {
            file,
            path: path.into(),
            witness: witness(&info),
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if witness(&self.file.metadata()?) != self.witness
            || witness(&std::fs::symlink_metadata(&self.path)?) != self.witness
        {
            return Err("workspace held runtime member changed".into());
        }
        Ok(())
    }
    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>> {
        self.check()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum || bytes.len() as u64 != self.witness.6 {
            return Err("workspace descriptor length changed".into());
        }
        self.check()?;
        Ok(bytes)
    }
    fn digest(&mut self, deadline: u64) -> Result<String> {
        self.check()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 32768];
        let mut read = 0u64;
        loop {
            context(deadline, None)?;
            let count = self.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(count as u64)
                .ok_or("workspace runtime length overflow")?;
            if read > self.witness.6 {
                return Err("workspace runtime grew while hashing".into());
            }
            hash.update(&buffer[..count]);
        }
        if read != self.witness.6 {
            return Err("workspace runtime shrank while hashing".into());
        }
        self.check()?;
        Ok(crate::bundle::hex(&hash.finalize()))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    bytes: u64,
    sha256: String,
    executable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    profile: String,
    files: Vec<Member>,
}
fn runtime(request: &Request, deadline: u64) -> Result<Vec<Held>> {
    let mut description = Held::open(PROFILE_PATH, 32768)?;
    validate_profile(&description.bytes(32768)?, request)?;
    let mut manifest_file = Held::open(MANIFEST_PATH, 32768)?;
    let raw = manifest_file.bytes(32768)?;
    if luma_content::sha256(&raw) != request.runtime_manifest_sha256 {
        return Err("workspace runtime manifest differs from publisher request".into());
    }
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    if manifest.schema_version != 1
        || manifest.profile != PROFILE
        || !(5..=64).contains(&manifest.files.len())
    {
        return Err("workspace runtime manifest identity/bound differs".into());
    }
    let mut held = vec![description, manifest_file];
    let mut names = BTreeSet::new();
    let mut previous = String::new();
    for member in manifest.files {
        let path = Path::new(&member.path);
        if path.is_absolute()
            || path
                .components()
                .any(|value| !matches!(value, std::path::Component::Normal(_)))
            || member.path.len() > 240
            || !member
                .path
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"_+./-".contains(&value))
            || member.path <= previous
            || !(64..=67108864).contains(&member.bytes)
        {
            return Err("workspace runtime member path/order/bound differs".into());
        }
        let absolute = format!("/{}", member.path);
        let fixed = matches!(
            absolute.as_str(),
            EXECUTABLE | HELPER | "/bin/bash" | "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"
        );
        if !fixed
            && !(member.path.starts_with("usr/lib/x86_64-linux-gnu/")
                || member.path.starts_with("usr/lib64/")
                || member.path.starts_with("lib/x86_64-linux-gnu/")
                || member.path.starts_with("lib64/"))
            || !fixed
                && (member.path.contains("/security/")
                    || !path
                        .file_name()
                        .ok_or("workspace runtime basename missing")?
                        .to_string_lossy()
                        .contains(".so"))
        {
            return Err("workspace runtime contains an unreviewed executable/module family".into());
        }
        crate::hosted_fence::digest(&member.sha256)?;
        let mut file = Held::open(&absolute, 67108864)?;
        if file.witness.6 != member.bytes
            || (file.witness.2 & 0o111 != 0) != member.executable
            || matches!(absolute.as_str(), EXECUTABLE | HELPER | "/bin/bash") && !member.executable
            || file.digest(deadline)? != member.sha256
        {
            return Err("workspace runtime bytes/mode differ from publisher closure".into());
        }
        previous = member.path.clone();
        names.insert(absolute);
        held.push(file);
    }
    if ![
        EXECUTABLE,
        HELPER,
        "/bin/bash",
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
    ]
    .iter()
    .all(|value| names.contains(*value))
    {
        return Err("workspace runtime omits its actual fixed PAM/worker closure".into());
    }
    for (path, expected) in [("/etc/pam.d/luma-admin", PAM), ("/etc/nsswitch.conf", NSS)] {
        let mut file = Held::open(path, 32768)?;
        if file.bytes(32768)? != expected {
            return Err("workspace PAM/NSS policy is not exact".into());
        }
        held.push(file);
    }
    Ok(held)
}

fn verify_pam(request: &Request, held: &[Held], deadline: u64) -> Result<()> {
    context(deadline, None)?;
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let password =
        crate::authentication::hidden_from(terminal, "Linux account password (local PAM only):")?;
    context(deadline, None)?;
    let helper = held
        .iter()
        .find(|value| value.path == HELPER)
        .ok_or("workspace helper was not held")?;
    for file in held {
        file.check()?;
    }
    let result = PrivateBuffer::new(4)?;
    let mut output = result.descriptor()?;
    let mut command = Command::new(format!("/proc/self/fd/{}", helper.file.as_raw_fd()));
    command
        .arg(&request.login)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C")
        .stdin(Stdio::from(password.descriptor()?))
        .stdout(Stdio::from(result.descriptor()?))
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            let bound = libc::rlimit {
                rlim_cur: 4,
                rlim_max: 4,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &bound) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    crate::model::supervise_owned_controller_with_pid(&mut command, |pid| {
        context(deadline, Some(pid))?;
        for file in held {
            file.check()?;
        }
        Ok(())
    })?;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = [0u8; 4];
    output.read_exact(&mut bytes)?;
    let mut extra = [0];
    if output.read(&mut extra)? != 0 || u32::from_be_bytes(bytes) != 1000 {
        return Err("actual Linux PAM identity differs from the approved nonroot account".into());
    }
    context(deadline, None)
}

fn state(create: bool) -> Result<()> {
    if create {
        match std::fs::DirBuilder::new().mode(0o700).create(STATE) {
            Ok(()) => {
                std::fs::set_permissions(STATE, std::fs::Permissions::from_mode(0o700))?;
                File::open("/var/lib")?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let info = std::fs::symlink_metadata(STATE)?;
    if !info.is_dir() || info.uid() != 0 || info.gid() != 0 || info.mode() & 0o7777 != 0o700 {
        return Err("workspace private bootstrap state is not protected".into());
    }
    Ok(())
}
fn decode(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 65536
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("workspace public request hex encoding differs".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| Ok(u8::from_str_radix(std::str::from_utf8(bytes)?, 16)?))
        .collect()
}
fn original(current: &Request, expected: &str, encoded: &str, bootstrap: bool) -> Result<Request> {
    crate::hosted_fence::digest(expected)?;
    let bytes = decode(encoded)?;
    if bytes.len() > 1024 || luma_content::sha256(&bytes) != expected {
        return Err(
            "workspace account generation differs from original host-journaled intent".into(),
        );
    }
    let original = parse(&bytes)?;
    if current.installation != original.installation
        || current.release_sha256 != original.release_sha256
        || current.runtime_manifest_sha256 != original.runtime_manifest_sha256
        || current.profile_sha256 != original.profile_sha256
        || current.actor_sid_sha256 != original.actor_sid_sha256
        || current.login != original.login
        || current.protected_utc_day < original.protected_utc_day
        || !bootstrap && current.nonce == original.nonce
        || bootstrap && crate::hosted_workspace::canonical(current)? != bytes
    {
        return Err("workspace observation/repair changes the original actor/account/release or rolls UTC backward".into());
    }
    Ok(original)
}
fn worker(
    operation: &str,
    resource: &str,
    request_sha: &str,
    original_sha: &str,
    encoded: &str,
    original_encoded: &str,
) -> Result<()> {
    crate::hosted_fence::bind(resource, request_sha)?;
    let bytes = decode(encoded)?;
    crate::hosted_fence::require_bytes(&bytes)?;
    let request = parse(&bytes)?;
    let original = original(
        &request,
        original_sha,
        original_encoded,
        operation == "bootstrap",
    )?;
    observe_headroom(true)?;
    let deadline = boottime()?
        .checked_add(u64::from(PURPOSE_SECONDS) * 1_000_000_000)
        .ok_or("workspace deadline overflow")?;
    context(deadline, None)?;
    let held = runtime(&request, deadline)?;
    state(operation == "bootstrap" || operation == "repair")?;
    let mut live = || {
        context(deadline, None)?;
        for file in &held {
            file.check()?;
        }
        Ok(())
    };
    match operation {
        "bootstrap" => {
            if original_sha != request_sha {
                return Err("first bootstrap cannot adopt another account intent".into());
            }
            let password = crate::account_password::Password::local_confirmed()?;
            live()?;
            let hash = password.hash()?;
            live()?;
            let mut transaction = Transaction::prepare(
                Path::new("/etc"),
                Path::new(TRANSACTION),
                &request,
                &hash,
                &mut live,
            )?;
            transaction.publish(&mut live)?;
            verify_pam(&request, &held, deadline)?;
            transaction.mark_pam_verified(&mut live)?;
            println!("Linux account files and independent PAM verification complete. Windows finalization and a fresh health challenge are still required.");
        }
        "repair" => {
            if request.protected_utc_day - original.protected_utc_day >= 90 {
                return Err("expired Linux password requires a separately governed password-recovery ceremony".into());
            }
            let transaction = match std::fs::symlink_metadata(TRANSACTION) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Transaction::require_unstarted(
                        Path::new("/etc"),
                        Path::new(TRANSACTION),
                        &original,
                    )?;
                    let password = crate::account_password::Password::local_confirmed()?;
                    live()?;
                    let hash = password.hash()?;
                    live()?;
                    let mut transaction = Transaction::prepare(
                        Path::new("/etc"),
                        Path::new(TRANSACTION),
                        &original,
                        &hash,
                        &mut live,
                    )?;
                    transaction.publish(&mut live)?;
                    transaction
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    let mut transaction = Transaction::recover(
                        Path::new("/etc"),
                        Path::new(TRANSACTION),
                        &original,
                        &mut live,
                    )?;
                    transaction.finish_interrupted(&mut live)?;
                    transaction
                }
            };
            verify_pam(&request, &held, deadline)?;
            transaction.mark_pam_verified(&mut live)?;
            println!("Exact interrupted account transition and independent PAM verification complete. Windows finalization and fresh health remain required.");
        }
        "status" => {
            let transaction = Transaction::recover(
                Path::new("/etc"),
                Path::new(TRANSACTION),
                &original,
                &mut live,
            )?;
            let observation = transaction.observation()?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"profile":PROFILE,"nonce":request.nonce,
                "request_sha256":request_sha,"installation":request.installation,"release_sha256":request.release_sha256,
                "runtime_manifest_sha256":request.runtime_manifest_sha256,"profile_sha256":request.profile_sha256,
                "actor_sid_sha256":request.actor_sid_sha256,"account_generation":1,"uid":1000,
                "bootstrap_request_sha256":original_sha,
                "protected_utc_day":request.protected_utc_day,"utc_proof_sha256":request.utc_proof_sha256,
                "password_age_within_90_days":request.protected_utc_day-original.protected_utc_day<90,
                "applied_file_count":observation["applied_file_count"],"account_files_complete":observation["files_complete"],
                "bootstrap_pam_verified_once":observation["pam_verified_once"],
                "account_state_sha256":observation["account_state_sha256"],
                "native_product_grant_bridge_available":false,"inference_observation":"not-requested",
                "authority_returned":false,"production_qualified":false})
            );
        }
        _ => return Err("unknown fixed workspace worker operation".into()),
    }
    live()
}

fn launch(
    operation: &str,
    resource: &str,
    request_sha: &str,
    original_sha: &str,
    encoded: &str,
    original_encoded: &str,
) -> Result<()> {
    host::host_context()?;
    observe_headroom(true)?;
    let bytes = decode(encoded)?;
    let request = parse(&bytes)?;
    original(
        &request,
        original_sha,
        original_encoded,
        operation == "bootstrap",
    )?;
    if luma_content::sha256(&bytes) != request_sha {
        return Err("workspace launch request digest differs".into());
    }
    crate::hosted_fence::prepare(resource, request_sha)?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .args(arguments(operation)?)
        .arg(EXECUTABLE)
        .arg(format!("hosted-windows-workspace-{operation}"))
        .args([
            resource,
            request_sha,
            original_sha,
            encoded,
            original_encoded,
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null());
    Err(command.exec().into())
}

fn arguments(operation: &str) -> Result<Vec<String>> {
    if !matches!(operation, "bootstrap" | "repair" | "status") {
        return Err("unknown fixed workspace launch profile".into());
    }
    let mut arguments = [
        "--quiet",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=luma-hosted-workspace-bootstrap.service",
        "--slice=lumahosted.slice",
        "--property=Requires=luma-hosted-workspace-confinement.service",
        "--property=After=luma-hosted-workspace-confinement.service",
        "--property=User=0",
        "--property=Group=0",
        "--property=SupplementaryGroups=",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=CAP_CHOWN",
        "--property=AmbientCapabilities=",
        "--property=AppArmorProfile=luma-hosted-workspace-bootstrap",
        "--property=MemoryMax=268435456",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=8",
        "--property=CPUQuota=100%",
        "--property=CPUQuotaPeriodSec=100ms",
        "--property=LimitCORE=0",
        "--property=LimitMEMLOCK=4194304",
        "--property=Restart=no",
        "--property=KillMode=control-group",
        "--property=ProtectSystem=strict",
        "--property=StateDirectory=luma-hosted-workspace",
        "--property=StateDirectoryMode=0700",
        "--property=ReadWritePaths=/etc /home",
        "--property=ProtectHome=no",
        "--property=PrivateTmp=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes",
        "--property=RestrictNamespaces=yes",
        "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=SystemCallArchitectures=native",
        "--property=SystemCallFilter=@system-service",
        "--property=StandardError=null",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    arguments.push(format!("--property=LimitCPU={CPU_SECONDS}"));
    arguments.push(format!("--property=RuntimeMaxSec={PURPOSE_SECONDS}"));
    if matches!(operation, "bootstrap" | "repair") {
        arguments.push("--pty".into());
    } else {
        arguments.push("--pipe".into());
    }
    Ok(arguments)
}

pub(super) fn command(arguments: &[String]) -> Result<()> {
    match arguments.first().map(String::as_str) {
        Some("hosted-windows-workspace-bootstrap-launch") if arguments.len() == 6 => launch(
            "bootstrap",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        Some("hosted-windows-workspace-status-launch") if arguments.len() == 6 => launch(
            "status",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        Some("hosted-windows-workspace-repair-launch") if arguments.len() == 6 => launch(
            "repair",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        Some("hosted-windows-workspace-bootstrap") if arguments.len() == 6 => worker(
            "bootstrap",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        Some("hosted-windows-workspace-status") if arguments.len() == 6 => worker(
            "status",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        Some("hosted-windows-workspace-repair") if arguments.len() == 6 => worker(
            "repair",
            &arguments[1],
            &arguments[2],
            &arguments[3],
            &arguments[4],
            &arguments[5],
        ),
        _ => Err("fixed workspace operation/resource/request tuple required".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_require_explicit_console_only_status_has_bounded_pipe() {
        for operation in ["bootstrap", "repair", "status"] {
            let arguments = arguments(operation).unwrap();
            assert_eq!(arguments.contains(&"--pty".into()), operation != "status");
            assert_eq!(arguments.contains(&"--pipe".into()), operation == "status");
            for required in [
                "--property=CapabilityBoundingSet=CAP_CHOWN",
                "--property=NoNewPrivileges=yes",
                "--property=MemoryMax=268435456",
                "--property=MemorySwapMax=0",
                "--property=TasksMax=8",
                "--property=LimitCPU=25",
                "--property=RuntimeMaxSec=30",
                "--property=KillMode=control-group",
                "--property=Restart=no",
                "--property=StateDirectory=luma-hosted-workspace",
                "--property=StateDirectoryMode=0700",
            ] {
                assert!(arguments.contains(&required.into()), "{required}");
            }
        }
        for operation in ["shell", "inference", "export", "", "bootstrap --uid root"] {
            assert!(arguments(operation).is_err());
        }
    }
    #[test]
    fn only_public_bounded_lowercase_hex_can_cross_argv() {
        assert_eq!(decode("7b7d0a").unwrap(), b"{}\n");
        for value in ["", "0", "AA", "7G", "00\n", "../etc/shadow"] {
            assert!(decode(value).is_err());
        }
        assert!(decode(&"00".repeat(32769)).is_err());
        assert!(command(&[]).is_err());
        assert!(command(&["hosted-windows-workspace-bootstrap".into()]).is_err());
        assert!(command(&[
            "arbitrary-command".into(),
            "a".into(),
            "b".into(),
            "c".into(),
            "d".into()
        ])
        .is_err());
    }
    #[test]
    fn absent_actual_kernel_confinement_cannot_create_any_account() {
        assert!(context(boottime().unwrap() + 30_000_000_000, None).is_err());
    }
    #[test]
    fn memory_observations_require_exact_units_unique_signal_and_checked_boundaries() {
        for starting in [false, true] {
            let bound = 1_048_576 + if starting { 262_144 } else { 0 };
            assert!(memory_headroom(&format!("MemAvailable: {bound} kB\n"), starting).is_ok());
            assert!(
                memory_headroom(&format!("MemAvailable: {} kB\n", bound - 1), starting).is_err()
            );
        }
        for value in [
            "",
            "MemAvailable: -1 kB\n",
            "MemAvailable: 999999999 MB\n",
            "MemAvailable: 999999999 kB extra\n",
            "MemAvailable: 9999999999999999999999 kB\n",
            "MemAvailable: 999999999 kB\nMemAvailable: 999999999 kB\n",
        ] {
            assert!(memory_headroom(value, true).is_err());
        }
    }
}
