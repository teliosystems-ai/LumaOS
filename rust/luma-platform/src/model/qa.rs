//! Isolated fixed-scenario QA, never normal serving, selection or certification.
use super::*;
use crate::{
    finite_grants::{Action, Kind, Selector, Use},
    resources::Token,
};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

pub(crate) const TASKS: u64 = 64;
const PREFIX: &str = "qa-v1-";
const ROOT: &str = "/run/luma-model-qa";
const REPORTS: &str = "/var/lib/luma-os/model-qa";
const MAX_REPORT: usize = 65536;
const CORPUS: &str = "Return exactly the single word LUMA.\n";
const BUDGET_MS: u64 = 25_000;

fn json<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    if raw.is_empty() || raw.len() > MAX_REPORT {
        return Err("QA JSON exceeds fixed bound".into());
    }
    Ok(serde_json::from_slice(raw)?)
}
fn runtime_digest() -> Result<String> {
    Ok(bundle::hex(&Sha256::digest(
        crate::admin_credentials::public_input(Path::new(RUNTIME), 64 * 1024 * 1024)?,
    )))
}
fn machine_digest() -> Result<String> {
    let identity = crate::admin_credentials::public_input(
        Path::new("/usr/share/luma-os/release-identity.json"),
        4096,
    )?;
    let cmdline = read_proc(Path::new("/proc/cmdline"), 65536)?;
    let kernel = read_proc(Path::new("/proc/sys/kernel/osrelease"), 4096)?;
    let anchored = crate::admin_governance::release_state_optional()?;
    let hardware = crate::model_trust::MachineTuple::current()?;
    Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(&(
        "luma-inert-qa-machine-v1",
        identity,
        cmdline,
        kernel,
        anchored,
        hardware,
    ))?)))
}

pub(crate) fn parse_profile(id: &str) -> Result<(&str, &str)> {
    let tail = id
        .strip_prefix(PREFIX)
        .ok_or("QA profile has a foreign purpose")?;
    for scenario in ["execution", "cancellation"] {
        if let Some(model) = tail.strip_suffix(&format!("-{scenario}")) {
            if matches!(model, "qwen3-4b-q4-k-m" | "qwen3-1-7b-q4-k-m") {
                return Ok((model, scenario));
            }
        }
    }
    Err("QA supports only exact compiled models and fixed scenarios".into())
}
fn profile_id(id: &str, scenario: &str) -> Result<String> {
    let profile = format!("{PREFIX}{id}-{scenario}");
    parse_profile(&profile)?;
    Ok(profile)
}
pub(crate) fn memory(id: &str) -> Result<u64> {
    let (model, _) = parse_profile(id)?;
    super::public_profile(model)?
        .memory_limit()
        .checked_add(256 * 1024 * 1024)
        .ok_or_else(|| "QA memory floor overflow".into())
}
pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    let (model, scenario) = parse_profile(id)?;
    Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(&(
        "luma-isolated-qa-resource-v1",
        super::public_profile(model)?.resource_binding()?,
        scenario,
        device,
        memory(id)?,
        TASKS,
    ))?)))
}
pub(crate) fn restored_memory(value: &str, device: &str) -> Result<Option<u64>> {
    for model in ["qwen3-4b-q4-k-m", "qwen3-1-7b-q4-k-m"] {
        for scenario in ["execution", "cancellation"] {
            let id = profile_id(model, scenario)?;
            if binding(&id, device)? == value {
                return Ok(Some(memory(&id)?));
            }
        }
    }
    Ok(None)
}
pub(crate) fn authority(id: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    let (model, _) = parse_profile(id)?;
    crate::admin_governance::pack_preparation_authority(&super::public_profile(model)?)
}
pub(crate) fn usage(id: &str) -> Result<Use> {
    let (model, scenario) = parse_profile(id)?;
    let p = super::public_profile(model)?;
    let runtime = crate::admin_credentials::public_input(Path::new(RUNTIME), 64 * 1024 * 1024)?;
    let digest = bundle::hex(&Sha256::digest(serde_json::to_vec(&(
        "luma-model-qa-review-v1",
        crate::artifacts::installation()?,
        p.resource_binding()?,
        scenario,
        CORPUS,
        bundle::hex(&Sha256::digest(runtime)),
        machine_digest()?,
        memory(id)?,
        TASKS,
        crate::resource_manager::storage_device(Path::new(VAR))?,
    ))?));
    let usage = Use {
        action: Action::QualifyModel,
        selector: Selector {
            kind: Kind::ModelQa,
            id: id.into(),
            generation: 1,
            digest,
        },
        input_bytes: CORPUS.len() as u64,
        output_bytes: MAX_REPORT as u64,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    dev: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl FileIdentity {
    fn current(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
struct Cached {
    path: PathBuf,
    file: File,
    pin: FileIdentity,
}
impl Cached {
    fn capture(p: &Profile) -> Result<Self> {
        super::pack_store::verify_qa_physical(p)?;
        let path = Path::new(VAR)
            .join(STATE)
            .join("models")
            .join(format!("{}.gguf", p.id));
        let file = super::verified_runtime_file(&path, p, || Ok(()))?;
        let pin = FileIdentity::current(&file.metadata()?);
        let proof = Self { path, file, pin };
        proof.check()?;
        Ok(proof)
    }
    fn check(&self) -> Result<()> {
        let named = fs::symlink_metadata(&self.path)?;
        let held = self.file.metadata()?;
        if !named.is_file()
            || FileIdentity::current(&named) != self.pin
            || FileIdentity::current(&held) != self.pin
        {
            return Err("QA original physically hashed model descriptor changed".into());
        }
        Ok(())
    }
}
pub(crate) fn review(id: &str, scenario: &str) -> Result<()> {
    let qa = profile_id(id, scenario)?;
    authority(&qa)?;
    let p = super::public_profile(id)?;
    let proof = Cached::capture(&p)?;
    proof.check()?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"qa_profile":qa,"usage":usage(&qa)?,"certified":false,"serving_admitted":false,"selection_changed":false,"authority_returned":false})
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    profile: String,
    job: String,
    model: FileIdentity,
    usage_sha256: String,
    runtime_sha256: String,
    machine_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u32,
    qa_profile: String,
    job: String,
    usage_sha256: String,
    model_sha256: String,
    profile_sha256: String,
    runtime_sha256: String,
    machine_sha256: String,
    worker: Token,
    readiness_ms: u64,
    execution_ms: u64,
    http_status: u16,
    cancellation_requested_after_nonterminal: bool,
    completion_sha256: String,
    completion: String,
    owned_runtime_reaped: bool,
    certified: bool,
    serving_admitted: bool,
    selection_changed: bool,
}
fn nonce(value: &str) -> Result<()> {
    crate::tpm::decode::<16>(value).map(drop)
}
fn job_path(job: &str) -> Result<PathBuf> {
    nonce(job)?;
    Ok(Path::new(ROOT).join(job))
}
fn read_job(job: &str, name: &str) -> Result<Vec<u8>> {
    if !matches!(name, "input.json" | "report.json") {
        return Err("QA job member is not closed".into());
    }
    crate::tpm::private_read(&job_path(job)?.join(name), MAX_REPORT as u64)
}
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > MAX_REPORT {
        return Err("QA report exceeds its bound".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("QA output parent missing")?)?.sync_all()?;
    Ok(())
}
fn validate_report(
    raw: &[u8],
    qa: &str,
    job: &str,
    scope: &str,
    p: &Profile,
    runtime: &str,
    machine: &str,
) -> Result<Report> {
    let report: Report = json(raw)?;
    let (_, scenario) = parse_profile(qa)?;
    if serde_json::to_vec(&report)? != raw
        || report.schema_version != 1
        || report.qa_profile != qa
        || report.job != job
        || report.usage_sha256 != scope
        || report.model_sha256 != p.sha256
        || report.profile_sha256 != p.resource_binding()?
        || report.runtime_sha256 != runtime
        || report.machine_sha256 != machine
        || !report.owned_runtime_reaped
        || report.certified
        || report.serving_admitted
        || report.selection_changed
        || report.completion.len() > 4096
        || (scenario == "execution"
            && (report.http_status != 200 || report.cancellation_requested_after_nonterminal))
        || (scenario == "cancellation"
            && (report.http_status != 0
                || !report.cancellation_requested_after_nonterminal
                || !report.completion.is_empty()))
        || report.completion_sha256 != bundle::hex(&Sha256::digest(report.completion.as_bytes()))
    {
        return Err("QA output is altered, unbounded or claims production authority".into());
    }
    crate::tpm::decode::<32>(&report.runtime_sha256)?;
    Ok(report)
}

fn launch_arguments(qa: &str, job: &str, model_fd: i32) -> Result<Vec<String>> {
    parse_profile(qa)?;
    nonce(job)?;
    if model_fd < 3 {
        return Err("QA requires its original retained descriptor".into());
    }
    let mut args = vec![
        "--wait".into(),
        "--collect".into(),
        "--quiet".into(),
        "--unit=luma-acquisition.service".into(),
        "--slice=lumaacquisition.slice".into(),
    ];
    for property in [
        "User=root".into(),
        "Group=root".into(),
        "NoNewPrivileges=yes".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "PrivateTmp=yes".into(),
        "PrivateDevices=yes".into(),
        "ProtectKernelTunables=yes".into(),
        "ProtectKernelModules=yes".into(),
        "ProtectControlGroups=yes".into(),
        "RestrictNamespaces=yes".into(),
        "LockPersonality=yes".into(),
        "MemoryDenyWriteExecute=yes".into(),
        "SystemCallArchitectures=native".into(),
        "SystemCallFilter=@system-service".into(),
        "SystemCallFilter=~@mount @reboot @swap @raw-io @debug".into(),
        "AppArmorProfile=luma-qa-supervisor".into(),
        "CapabilityBoundingSet=CAP_CHOWN CAP_SETUID CAP_SETGID CAP_KILL CAP_SETPCAP CAP_SYS_PTRACE"
            .into(),
        format!("MemoryMax={}", memory(qa)?),
        "MemorySwapMax=0".into(),
        "OOMPolicy=kill".into(),
        format!("TasksMax={TASKS}"),
        "CPUQuota=200%".into(),
        "LimitMEMLOCK=0".into(),
        "LimitCORE=0".into(),
        "LimitFSIZE=64K".into(),
        "DevicePolicy=closed".into(),
        "KillMode=control-group".into(),
        "TimeoutStopSec=15".into(),
        "Restart=no".into(),
        "Requires=luma-broker.service".into(),
        "After=luma-broker.service".into(),
        "BindsTo=luma-broker.service".into(),
        "Conflicts=sleep.target".into(),
        "Before=sleep.target".into(),
        "RestrictAddressFamilies=AF_UNIX AF_INET".into(),
        "IPAddressDeny=any".into(),
        "IPAddressAllow=localhost".into(),
        "StandardInput=file".into(),
        format!(
            "StandardInputFile=/proc/{}/fd/{model_fd}",
            std::process::id()
        ),
        "StandardOutput=null".into(),
        "StandardError=null".into(),
        format!("ReadWritePaths={ROOT}/{job}"),
        "InaccessiblePaths=/var/lib/luma-broker /var/lib/luma-os/admin /dev/tpm0 /dev/tpmrm0"
            .into(),
        "IOReadBandwidthMax=/var 64M".into(),
        "IOWriteBandwidthMax=/var 64M".into(),
        "RuntimeMaxSec=40".into(),
    ] {
        args.push(format!("--property={property}"));
    }
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "model-qa-worker".into(),
        qa.into(),
        job.into(),
    ]);
    Ok(args)
}
pub(crate) fn run(login: &str, grant: &str, id: &str, scenario: &str) -> Result<()> {
    let qa = profile_id(id, scenario)?;
    authority(&qa)?;
    let p = super::public_profile(id)?;
    let proof = Cached::capture(&p)?;
    let scope = usage(&qa)?;
    let runtime = runtime_digest()?;
    let machine = machine_digest()?;
    crate::admin_governance::with_model_qa_grant(login, grant, &qa, &scope, |boundary| {
        boundary.require_qa_admin()?;
        proof.check()?;
        authority(&qa)?;
        if usage(&qa)? != scope || runtime_digest()? != runtime || machine_digest()? != machine {
            return Err("QA exact reviewed native tuple changed".into());
        }
        let job = crate::resources::random_id()?;
        crate::tpm::private_directory(Path::new(ROOT))?;
        if fs::read_dir(ROOT)?.count() >= 128 {
            return Err("retained QA jobs require explicit evidence disposition".into());
        }
        let directory = job_path(&job)?;
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        write_new(
            &directory.join("input.json"),
            &serde_json::to_vec(&Input {
                schema_version: 1,
                profile: qa.clone(),
                job: job.clone(),
                model: proof.pin.clone(),
                usage_sha256: scope.selector.digest.clone(),
                runtime_sha256: runtime.clone(),
                machine_sha256: machine.clone(),
            })?,
        )?;
        let effect = boundary.effect_begin(
            &scope.selector.digest,
            crate::policy_decisions::EffectKind::ModelQa,
        )?;
        let raw = crate::service::granted_acquisition::run_qa(&qa, &scope, boundary, |check| {
            proof.check()?;
            let mut command = Command::new("/usr/bin/systemd-run");
            command
                .args(launch_arguments(&qa, &job, proof.file.as_raw_fd())?)
                .env_clear()
                .env("PATH", "/usr/bin")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            super::supervise_owned_controller(&mut command, || {
                check()?;
                proof.check()
            })?;
            proof.check()?;
            read_job(&job, "report.json")
        })?;
        boundary.require_qa_admin()?;
        proof.check()?;
        if usage(&qa)? != scope {
            return Err("QA review changed before report publication".into());
        }
        let report = validate_report(
            &raw,
            &qa,
            &job,
            &scope.selector.digest,
            &p,
            &runtime,
            &machine,
        )?;
        let mut receipt = crate::resource_manager::request("resource-output-receipt")?;
        receipt.lease = Some(report.worker.clone());
        let actual = crate::service::resource_exchange(&receipt)?
            .status
            .ok_or("QA actual committed output receipt absent")?;
        if actual["output_sha256"].as_str() != Some(bundle::hex(&Sha256::digest(&raw)).as_str()) {
            return Err("QA report differs from actual output generation receipt".into());
        }
        crate::tpm::private_directory(Path::new(REPORTS))?;
        if fs::read_dir(REPORTS)?.count() >= 128 {
            return Err("QA report retention full; preserve pending job".into());
        }
        boundary.require_qa_admin()?;
        write_new(&Path::new(REPORTS).join(format!("{job}.json")), &raw)?;
        let digest = bundle::hex(&Sha256::digest(&raw));
        boundary.effect_complete(effect, &digest)?;
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"report_sha256":digest,"report":report,"certified":false,"authority_returned":false})
        );
        Ok(())
    })
}

fn read_proc(path: &Path, limit: u64) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 || fs.f_type != 0x9fa0 {
        return Err("QA requires actual bounded kernel observations".into());
    }
    let mut text = String::new();
    (&mut file).take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err("QA kernel observation oversized".into());
    }
    Ok(text)
}
fn listening_inode(tcp: &str, port: u16) -> Result<u64> {
    let expected = format!("0100007F:{port:04X}");
    let mut result = None;
    for line in tcp.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 10 && fields[1] == expected && fields[3] == "0A" {
            if fields[7] != "988" || result.is_some() {
                return Err("QA listener ownership is ambiguous or foreign".into());
            }
            result = Some(fields[9].parse()?);
        }
    }
    result
        .filter(|inode| *inode > 0)
        .ok_or_else(|| "QA private listener unavailable".into())
}
fn runtime_confinement(label: &str) -> Result<()> {
    // Retaining the supervisor profile is required by no_new_privs. The child
    // profile adds restrictions; it never replaces or weakens that parent.
    match label.trim_end_matches('\n') {
        "luma-model-qa//&luma-qa-supervisor (enforce)"
        | "luma-qa-supervisor//&luma-model-qa (enforce)" => Ok(()),
        _ => Err("QA runtime must hold exactly both enforcing profiles".into()),
    }
}
fn endpoint(child: &mut std::process::Child, port: u16) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Err("QA runtime exited".into());
    }
    let proc = Path::new("/proc").join(child.id().to_string());
    if fs::read_link(proc.join("exe"))? != Path::new(RUNTIME) {
        return Err("QA runtime executable or UID changed".into());
    }
    let status = read_proc(&proc.join("status"), 16384)?;
    if status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .map(|value| value.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["988"; 4])
        || status
            .lines()
            .find_map(|line| line.strip_prefix("Gid:"))
            .map(|value| value.split_whitespace().collect::<Vec<_>>())
            != Some(vec!["988"; 4])
        || status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .map(str::trim)
            != Some("")
        || status
            .lines()
            .find_map(|line| line.strip_prefix("NoNewPrivs:"))
            .map(str::trim)
            != Some("1")
        || status
            .lines()
            .find_map(|line| line.strip_prefix("Seccomp:"))
            .map(str::trim)
            != Some("2")
    {
        return Err(
            "QA runtime credentials, supplementary groups or privilege filters differ".into(),
        );
    }
    for prefix in ["CapEff:", "CapPrm:", "CapAmb:", "CapInh:", "CapBnd:"] {
        if status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(str::trim)
            != Some("0000000000000000")
        {
            return Err("QA runtime child has unexpected capability authority".into());
        }
    }
    runtime_confinement(&read_proc(&proc.join("attr/current"), 4096)?)?;
    if read_proc(&proc.join("cgroup"), 4096)?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
    {
        return Err("QA runtime isolation profile/cgroup differs".into());
    }
    let inode = listening_inode(&read_proc(Path::new("/proc/net/tcp"), 1024 * 1024)?, port)?;
    if !fs::read_dir(proc.join("fd"))?.any(|entry| {
        entry
            .ok()
            .and_then(|entry| fs::read_link(entry.path()).ok())
            .map_or(false, |value| {
                value.as_os_str() == std::ffi::OsStr::new(&format!("socket:[{inode}]"))
            })
    }) {
        return Err("QA listener is not held by the actual runtime child".into());
    }
    Ok(())
}
fn http(
    port: u16,
    key: &str,
    path: &str,
    payload: Option<&serde_json::Value>,
    until: Instant,
    mut check: impl FnMut() -> Result<()>,
) -> Result<(u16, Vec<u8>)> {
    if key.len() != 64
        || !key.bytes().all(|b| b.is_ascii_hexdigit())
        || !matches!(path, "/v1/models" | "/completion")
    {
        return Err("QA HTTP request is not fixed and private".into());
    }
    let body = payload
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    if body.len() > 4096 {
        return Err("QA input exceeds fixed corpus bound".into());
    }
    let method = if payload.is_some() { "POST" } else { "GET" };
    let mut data=format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    data.extend(body);
    check()?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut sent = 0;
    while sent < data.len() {
        check()?;
        if Instant::now() >= until {
            return Err("QA request deadline exceeded".into());
        }
        match socket.write(&data[sent..]) {
            Ok(0) => return Err("QA HTTP write ended".into()),
            Ok(count) => sent += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut raw = Vec::new();
    loop {
        check()?;
        if Instant::now() >= until {
            return Err("QA request deadline exceeded".into());
        }
        let mut bytes = [0; 4096];
        match socket.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&bytes[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(error) => return Err(error.into()),
        }
        if raw.len() > MAX_REPORT {
            return Err("QA HTTP output exceeds fixed bound".into());
        }
    }
    check()?;
    let offset = raw
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("QA HTTP headers missing")?;
    if offset > 8192 {
        return Err("QA HTTP headers oversized".into());
    }
    let text = std::str::from_utf8(&raw[..offset])?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .ok_or("QA HTTP status missing")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if status.len() < 2 || !matches!(status[0], "HTTP/1.0" | "HTTP/1.1") {
        return Err("QA HTTP status differs".into());
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed QA HTTP header")?;
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "transfer-encoding" | "content-encoding" | "location"
        ) {
            return Err("QA HTTP refuses encoded or redirected responses".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate QA HTTP length".into());
            }
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let body = raw[offset + 4..].to_vec();
    if length != Some(body.len()) {
        return Err("QA HTTP body is truncated or oversized".into());
    }
    Ok((status[1].parse()?, body))
}

/// Observe one actual nonterminal generated event, cancel the in-flight
/// request, then reap only this retained Child. Partial tokens are discarded.
fn cancel_after_token(
    port: u16,
    key: &str,
    until: Instant,
    runtime: &mut Runtime,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    let payload = serde_json::to_vec(
        &serde_json::json!({"prompt":CORPUS,"n_predict":128,"temperature":0,"seed":0,"cache_prompt":false,"stream":true}),
    )?;
    let mut socket = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse()?,
        Duration::from_millis(200),
    )?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut request=format!("POST /completion HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",payload.len()).into_bytes();
    request.extend(payload);
    let mut sent = 0;
    while sent < request.len() {
        check()?;
        endpoint(&mut runtime.child, port)?;
        if Instant::now() >= until {
            return Err("QA cancellation send deadline exceeded".into());
        }
        match socket.write(&request[sent..]) {
            Ok(0) => return Err("QA cancellation request ended".into()),
            Ok(n) => sent += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(e) => return Err(e.into()),
        }
    }
    let mut raw = Vec::new();
    loop {
        check()?;
        endpoint(&mut runtime.child, port)?;
        if Instant::now() >= until {
            return Err(
                "QA cancellation did not observe an in-flight token before deadline".into(),
            );
        }
        let mut buffer = [0; 4096];
        match socket.read(&mut buffer) {
            Ok(0) => return Err("QA cancellation stream completed before cancellation".into()),
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(e) => return Err(e.into()),
        }
        if raw.len() > MAX_REPORT {
            return Err("QA cancellation stream exceeded fixed bound".into());
        }
        if let Some(headers) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            if headers > 8192
                || !raw.starts_with(b"HTTP/1.1 200 ") && !raw.starts_with(b"HTTP/1.0 200 ")
            {
                return Err("QA cancellation response is not a bounded successful stream".into());
            }
            if observed_nonterminal_token(&raw[headers + 4..])? {
                check()?;
                endpoint(&mut runtime.child, port)?;
                socket.shutdown(std::net::Shutdown::Both)?;
                runtime.stop()?;
                check()?;
                return Ok(());
            }
        }
    }
}
fn observed_nonterminal_token(raw: &[u8]) -> Result<bool> {
    #[derive(Deserialize)]
    struct Event {
        content: String,
        stop: bool,
    }
    let mut observed = false;
    for raw_line in raw.split_inclusive(|byte| *byte == b'\n') {
        if !raw_line.ends_with(b"\n") {
            continue;
        }
        let text = std::str::from_utf8(raw_line)?.trim_end_matches(['\r', '\n']);
        let Some(line) = text.strip_prefix("data: ") else {
            continue;
        };
        if line == "[DONE]" {
            return Err("QA stream finished before in-flight cancellation".into());
        }
        let event: Event = json(line.as_bytes())?;
        if event.stop {
            return Err("QA runtime already completed before cancellation".into());
        }
        if !event.content.is_empty() {
            observed = true;
        }
    }
    Ok(observed)
}

pub(crate) fn check_worker(qa: &str, device: &str, pid: u32) -> Result<()> {
    authority(qa)?;
    if crate::resource_manager::storage_device(Path::new(VAR))? != device {
        return Err("QA worker storage differs from reviewed device".into());
    }
    let command = read_proc(
        &Path::new("/proc").join(pid.to_string()).join("cmdline"),
        4096,
    )?;
    let args = command.split('\0').collect::<Vec<_>>();
    if args.len() != 5
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != "model-qa-worker"
        || args[2] != qa
        || !args[4].is_empty()
    {
        return Err("QA peer lacks exact fixed worker command".into());
    }
    nonce(args[3])?;
    let input: Input = json(&read_job(args[3], "input.json")?)?;
    if input.schema_version != 1
        || input.profile != qa
        || input.job != args[3]
        || input.runtime_sha256 != runtime_digest()?
    {
        return Err("QA peer does not hold the unchanged reviewed input".into());
    }
    crate::tpm::decode::<32>(&input.usage_sha256)?;
    crate::tpm::decode::<32>(&input.machine_sha256)?;
    // The separate actual finite principal connection reconstructs the full
    // current Use at every observation. This worker proof never reopens the
    // Admin journal recursively or replaces that actual principal check.
    Ok(())
}
pub(crate) fn check_output(qa: &str, pid: u32, token: &Token, digest: &str) -> Result<()> {
    let args = read_proc(
        &Path::new("/proc").join(pid.to_string()).join("cmdline"),
        4096,
    )?;
    let parts = args.split('\0').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "model-qa-worker"
        || parts[2] != qa
        || !parts[4].is_empty()
    {
        return Err("QA output has no actual owned supervisor".into());
    }
    let input: Input = json(&read_job(parts[3], "input.json")?)?;
    let raw = read_job(parts[3], "report.json")?;
    let (model, _) = parse_profile(qa)?;
    let report = validate_report(
        &raw,
        qa,
        parts[3],
        &input.usage_sha256,
        &super::public_profile(model)?,
        &input.runtime_sha256,
        &input.machine_sha256,
    )?;
    if &report.worker != token || bundle::hex(&Sha256::digest(&raw)) != digest {
        return Err("QA report does not match its actual output generation".into());
    }
    Ok(())
}

struct Runtime {
    child: std::process::Child,
    reaped: bool,
}
impl Runtime {
    fn stop(&mut self) -> Result<()> {
        if self.reaped {
            return Err("QA runtime cannot be reaped twice".into());
        }
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        self.child.wait()?;
        self.reaped = true;
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.stop();
        }
    }
}
pub(crate) fn worker(qa: &str, job: &str) -> Result<()> {
    crate::require_root()?;
    let (model, scenario) = parse_profile(qa)?;
    nonce(job)?;
    let p = super::public_profile(model)?;
    let input: Input = json(&read_job(job, "input.json")?)?;
    if input.schema_version != 1 || input.profile != qa || input.job != job {
        return Err("QA immutable job identity differs".into());
    }
    let weights_fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if weights_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // The successful fcntl result is a newly owned descriptor, never -1.
    let mut weights = unsafe { File::from_raw_fd(weights_fd) };
    if FileIdentity::current(&weights.metadata()?) != input.model
        || input.model.bytes != p.bytes
        || input.model.uid != 0
        || input.model.links != 1
        || input.model.mode & 0o022 != 0
        || input.model.mode & 0o004 == 0
        || input.runtime_sha256 != runtime_digest()?
    {
        return Err("QA input is not the original pinned hashed model descriptor".into());
    }
    let lease = crate::resource_manager::WorkerLease::acquire_acquisition(qa, Path::new(VAR))?;
    lease.check()?;
    super::layout::verify(&mut weights, &p, &mut || lease.check_local())?;
    weights.seek(SeekFrom::Start(0))?;
    let mut random = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let key = bundle::hex(&random);
    let name = std::ffi::CString::new("luma-qa-key")?;
    let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut keyfile = unsafe { File::from_raw_fd(raw) };
    if unsafe { libc::fchown(raw, 988, 988) } != 0 || unsafe { libc::fchmod(raw, 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    keyfile.write_all(key.as_bytes())?;
    keyfile.seek(SeekFrom::Start(0))?;
    if unsafe {
        libc::fcntl(
            raw,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let model_fd = weights.as_raw_fd();
    let key_fd = keyfile.as_raw_fd();
    let mut command = Command::new(RUNTIME);
    command
        .args([
            "--model".into(),
            format!("/proc/self/fd/{model_fd}"),
            "--ctx-size".into(),
            p.context_tokens.to_string(),
            "--threads".into(),
            "2".into(),
            "--threads-batch".into(),
            "2".into(),
            "--threads-http".into(),
            "2".into(),
            "--parallel".into(),
            "1".into(),
            "--n-gpu-layers".into(),
            "0".into(),
            "--cache-type-k".into(),
            "f16".into(),
            "--cache-type-v".into(),
            "f16".into(),
            "--host".into(),
            "127.0.0.1".into(),
            "--port".into(),
            port.to_string(),
            "--alias".into(),
            p.id.clone(),
            "--api-key-file".into(),
            format!("/proc/self/fd/{key_fd}"),
            "--no-webui".into(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .env("LD_LIBRARY_PATH", "/usr/libexec/luma-os/llama")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let parent = std::process::id();
    unsafe {
        command.pre_exec(move || {
            for capability in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(988) != 0
                || libc::setuid(988) != 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent as i32
            {
                return Err(std::io::Error::last_os_error());
            }
            for fd in [model_fd, key_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    lease.check()?;
    let started = Instant::now();
    let until = started + Duration::from_millis(BUDGET_MS);
    let mut runtime = Runtime {
        child: command.spawn()?,
        reaped: false,
    };
    loop {
        lease.check_local()?;
        if Instant::now() >= until {
            return Err("QA runtime readiness exceeded bounded operation".into());
        }
        match endpoint(&mut runtime.child, port).and_then(|_| {
            http(port, &key, "/v1/models", None, until, || {
                lease.check_local()
            })
        }) {
            Ok((200, body)) => {
                #[derive(Deserialize)]
                struct Models {
                    data: Vec<Alias>,
                }
                #[derive(Deserialize)]
                struct Alias {
                    id: String,
                }
                let value: Models = json(&body)?;
                if value.data.len() != 1 || value.data[0].id != p.id {
                    return Err("QA runtime alias differs from signed tuple".into());
                }
                break;
            }
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let readiness_ms = started.elapsed().as_millis() as u64;
    let execution = Instant::now();
    endpoint(&mut runtime.child, port)?;
    let (status, completion, cancelled) = if scenario == "cancellation" {
        cancel_after_token(port, &key, until, &mut runtime, || lease.check_local())?;
        (0, String::new(), true)
    } else {
        let (status, body) = http(
            port,
            &key,
            "/completion",
            Some(
                &serde_json::json!({"prompt":CORPUS,"n_predict":16,"temperature":0,"seed":0,"cache_prompt":false,"stream":false}),
            ),
            until,
            || {
                lease.check_local()?;
                endpoint(&mut runtime.child, port)
            },
        )?;
        #[derive(Deserialize)]
        struct Completion {
            content: String,
        }
        let response: Completion = json(&body)?;
        let completion = response.content;
        if completion.len() > 4096 {
            return Err("QA completion exceeds report bound".into());
        }
        if completion.contains(&key) {
            return Err("QA output reflected private endpoint credential".into());
        }
        runtime.stop()?;
        (status, completion, false)
    };
    lease.check_local()?;
    let report = Report {
        schema_version: 1,
        qa_profile: qa.into(),
        job: job.into(),
        usage_sha256: input.usage_sha256,
        model_sha256: p.sha256.clone(),
        profile_sha256: p.resource_binding()?,
        runtime_sha256: input.runtime_sha256,
        machine_sha256: input.machine_sha256,
        worker: lease.token().clone(),
        readiness_ms,
        execution_ms: execution.elapsed().as_millis() as u64,
        http_status: status,
        cancellation_requested_after_nonterminal: cancelled,
        completion_sha256: bundle::hex(&Sha256::digest(completion.as_bytes())),
        completion,
        owned_runtime_reaped: true,
        certified: false,
        serving_admitted: false,
        selection_changed: false,
    };
    let raw = serde_json::to_vec(&report)?;
    lease.check_local()?;
    if FileIdentity::current(&weights.metadata()?) != input.model {
        return Err("QA original consumed descriptor changed".into());
    }
    write_new(&job_path(job)?.join("report.json"), &raw)?;
    lease.complete_output(&bundle::hex(&Sha256::digest(&raw)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_requires_both_enforcing_profiles_without_foreign_stack_members() {
        for allowed in [
            "luma-model-qa//&luma-qa-supervisor (enforce)\n",
            "luma-qa-supervisor//&luma-model-qa (enforce)\n",
        ] {
            runtime_confinement(allowed).unwrap();
        }
        for refused in [
            "luma-model-qa (enforce)\n",
            "luma-qa-supervisor (enforce)\n",
            "unconfined",
            "luma-model-qa//&luma-qa-supervisor (complain)\n",
            "luma-model-qa//&luma-qa-supervisor//&foreign (enforce)\n",
        ] {
            assert!(runtime_confinement(refused).is_err());
        }
    }
    #[test]
    fn cancellation_requires_an_actual_nonterminal_token_not_a_completed_stream() {
        assert!(
            !observed_nonterminal_token(b"data: {\"content\":\"\",\"stop\":false}\n\n").unwrap()
        );
        assert!(
            observed_nonterminal_token(b"data: {\"content\":\"L\",\"stop\":false}\n\n").unwrap()
        );
        assert!(!observed_nonterminal_token(b"data: {\"content\":\"L\",\"stop\":false}").unwrap());
        for rejected in [
            &b"data: [DONE]\n\n"[..],
            &b"data: {\"content\":\"L\",\"stop\":true}\n\n"[..],
            &b"data: {\"content\":\"L\",\"stop\":false}\n\ndata: [DONE]\n\n"[..],
            &b"data: {\"content\":\"L\",\"content\":\"x\",\"stop\":false}\n\n"[..],
        ] {
            assert!(observed_nonterminal_token(rejected).is_err());
        }
    }
    #[test]
    fn reports_bind_exact_model_runtime_machine_and_never_certify_or_activate() {
        let profile = legacy_catalog().unwrap().models.remove(0);
        let qa = profile_id(&profile.id, "execution").unwrap();
        let job = "a".repeat(32);
        let scope = "b".repeat(64);
        let runtime = "c".repeat(64);
        let machine = "d".repeat(64);
        let report = Report {
            schema_version: 1,
            qa_profile: qa.clone(),
            job: job.clone(),
            usage_sha256: scope.clone(),
            model_sha256: profile.sha256.clone(),
            profile_sha256: profile.resource_binding().unwrap(),
            runtime_sha256: runtime.clone(),
            machine_sha256: machine.clone(),
            worker: Token {
                lease_id: "qa-test-lease".into(),
                generation: 1,
                manager_epoch: "test-epoch".into(),
            },
            readiness_ms: 1,
            execution_ms: 1,
            http_status: 200,
            cancellation_requested_after_nonterminal: false,
            completion_sha256: bundle::hex(&Sha256::digest(b"LUMA")),
            completion: "LUMA".into(),
            owned_runtime_reaped: true,
            certified: false,
            serving_admitted: false,
            selection_changed: false,
        };
        let validate = |value: &Report| {
            validate_report(
                &serde_json::to_vec(value).unwrap(),
                &qa,
                &job,
                &scope,
                &profile,
                &runtime,
                &machine,
            )
        };
        validate(&report).unwrap();
        for case in 0..13 {
            let mut changed = report.clone();
            match case {
                0 => changed.certified = true,
                1 => changed.serving_admitted = true,
                2 => changed.selection_changed = true,
                3 => changed.owned_runtime_reaped = false,
                4 => changed.runtime_sha256 = "e".repeat(64),
                5 => changed.machine_sha256 = "e".repeat(64),
                6 => changed.profile_sha256 = "e".repeat(64),
                7 => changed.model_sha256 = "e".repeat(64),
                8 => changed.usage_sha256 = "e".repeat(64),
                9 => changed.job = "e".repeat(32),
                10 => changed.http_status = 500,
                11 => changed.cancellation_requested_after_nonterminal = true,
                _ => changed.completion.push('x'),
            }
            assert!(validate(&changed).is_err());
        }
        let raw = serde_json::to_vec_pretty(&report).unwrap();
        assert!(validate_report(&raw, &qa, &job, &scope, &profile, &runtime, &machine).is_err());
        let cancellation = profile_id(&profile.id, "cancellation").unwrap();
        let mut cancelled = report;
        cancelled.qa_profile = cancellation.clone();
        cancelled.http_status = 0;
        cancelled.cancellation_requested_after_nonterminal = true;
        cancelled.completion.clear();
        cancelled.completion_sha256 = bundle::hex(&Sha256::digest(b""));
        validate_report(
            &serde_json::to_vec(&cancelled).unwrap(),
            &cancellation,
            &job,
            &scope,
            &profile,
            &runtime,
            &machine,
        )
        .unwrap();
        cancelled.cancellation_requested_after_nonterminal = false;
        assert!(validate_report(
            &serde_json::to_vec(&cancelled).unwrap(),
            &cancellation,
            &job,
            &scope,
            &profile,
            &runtime,
            &machine
        )
        .is_err());
    }
    #[test]
    fn scopes_are_closed_and_never_normal_inference_or_selection() {
        for model in ["qwen3-4b-q4-k-m", "qwen3-1-7b-q4-k-m"] {
            for scenario in ["execution", "cancellation"] {
                let id = profile_id(model, scenario).unwrap();
                assert_eq!(parse_profile(&id).unwrap(), (model, scenario));
            }
        }
        for id in [
            "qwen3-4b-q4-k-m",
            "qa-v1-unreviewed-execution",
            "qa-v1-qwen3-4b-q4-k-m-inference",
            "qa-v1-qwen3-4b-q4-k-m-execution-extra",
        ] {
            assert!(parse_profile(id).is_err());
        }
    }
    #[test]
    fn launch_has_only_pinned_descriptor_and_closed_scenario_budgets() {
        let id = profile_id("qwen3-4b-q4-k-m", "execution").unwrap();
        let args = launch_arguments(&id, &"ab".repeat(16), 7).unwrap();
        assert!(args.contains(&"--property=TasksMax=64".into()));
        assert!(args.iter().any(|arg| arg
            == &format!(
                "--property=StandardInputFile=/proc/{}/fd/7",
                std::process::id()
            )));
        assert!(args.contains(&"--property=IPAddressDeny=any".into()));
        assert!(!args
            .iter()
            .any(|arg| arg.contains("model-install") || arg.contains("/dev/tpmrm0 rw")));
        assert!(launch_arguments(&id, "bad", 7).is_err());
        assert!(launch_arguments(&id, &"ab".repeat(16), 0).is_err());
    }
    #[test]
    fn listener_claim_requires_loopback_exact_uid_and_one_actual_socket() {
        let text = "header\n0: 0100007F:2345 00000000:0000 0A 0:0 00:0 0 988 0 41\n";
        assert_eq!(listening_inode(text, 0x2345).unwrap(), 41);
        assert!(listening_inode(&text.replace("988", "0"), 0x2345).is_err());
        assert!(
            listening_inode(&(text.to_owned() + text.lines().nth(1).unwrap()), 0x2345).is_err()
        );
        assert!(listening_inode(text, 0x2346).is_err());
    }
}
