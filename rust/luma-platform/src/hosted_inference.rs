//! Finite Windows-owned compact inference. No guest product principal, grant,
//! network, filesystem publication or model-provided command is admitted.
use crate::{hosted_windows as host, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROFILE: &str = "luma-windows-hosted-inference-v1";
const UNIT: &str = "luma-hosted-inference.service";
const GROUP: &str = "/sys/fs/cgroup/lumahosted.slice/luma-hosted-inference.service";
const CGROUP: &str = "0::/lumahosted.slice/luma-hosted-inference.service\n";
const PRIVATE: &str = "/usr/libexec/luma-os/hosted-llama";
const EXECUTABLE: &str = "/usr/libexec/luma-os/luma-platform";
const MODEL: &str = "usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf";
const MODEL_BYTES: u64 = 2_497_280_256;
const MODEL_SHA: &str = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5";
const DESCRIPTION: &str = "usr/share/luma-os/hosted-inference.json";
const MANIFEST: &str = "usr/share/luma-os/hosted-inference-runtime.json";
const MEMORY: u64 = 4_831_838_208;
const MEMORY_RESERVE: u64 = 1_073_741_824;
const OUTPUT: usize = 1024 * 1024;
const PROCFS: libc::c_long = 0x9fa0;
const CGROUP2: libc::c_long = 0x6367_7270;

fn memory_headroom(observation: &str, starting: bool) -> Result<()> {
    let mut available = None;
    for line in observation.lines() {
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            if available.is_some() {
                return Err("duplicate kernel memory availability observation".into());
            }
            let fields = value.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 2
                || fields[1] != "kB"
                || !fields[0].bytes().all(|value| value.is_ascii_digit())
            {
                return Err("kernel memory availability is malformed".into());
            }
            available = Some(
                fields[0]
                    .parse::<u64>()?
                    .checked_mul(1024)
                    .ok_or("kernel memory availability overflow")?,
            );
        }
    }
    let required = MEMORY_RESERVE + if starting { MEMORY } else { 0 };
    if available.ok_or("kernel memory availability missing")? < required {
        return Err("hosted inference lacks observed guest memory headroom; no resource reservation is inferred".into());
    }
    Ok(())
}
fn observe_headroom(starting: bool) -> Result<()> {
    memory_headroom(&host::kernel("/proc/meminfo", PROCFS, 32768)?, starting)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    profile: String,
    nonce: String,
    model_sha256: String,
    runtime_manifest_sha256: String,
    profile_sha256: String,
    prompt: String,
    prompt_sha256: String,
    context_tokens: u32,
    max_tokens: u32,
}
fn hash(value: &str) -> bool {
    crate::tpm::decode::<32>(value).map_or(false, |value| value != [0; 32])
}
fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > 32768 {
        return Err("hosted inference request exceeds its encoded bound".into());
    }
    let value: Request = serde_json::from_slice(bytes)?;
    if value.schema_version != 1
        || value.profile != PROFILE
        || !hash(&value.nonce)
        || value.model_sha256 != MODEL_SHA
        || !hash(&value.runtime_manifest_sha256)
        || !hash(&value.profile_sha256)
        || value.prompt.is_empty()
        || value.prompt.len() > 4096
        || value.prompt.contains('\0')
        || value.prompt_sha256 != luma_content::sha256(value.prompt.as_bytes())
        || value.context_tokens != 2048
        || !(1..=512).contains(&value.max_tokens)
    {
        return Err("inference request changes its fixed model/runtime/prompt or limits".into());
    }
    Ok(value)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    profile: String,
    environment: String,
    runtime: String,
    model_path: String,
    model_bytes: u64,
    model_sha256: String,
    runtime_manifest_sha256: String,
    context_tokens: u32,
    maximum_output_tokens: u32,
    memory_max_bytes: u64,
    memory_swap_max_bytes: u64,
    tasks_max: u32,
    cpu_quota_usec: u32,
    cpu_period_usec: u32,
    runtime_cpu_seconds: u32,
    threads: u32,
}
fn validate_profile(value: &Profile, request: &Request) -> Result<()> {
    if value.schema_version != 1
        || value.profile != PROFILE
        || value.environment != "lab"
        || value.runtime != "llama.cpp-b11100-cpu-amd64-completion"
        || value.model_path != MODEL
        || value.model_bytes != MODEL_BYTES
        || value.model_sha256 != MODEL_SHA
        || value.runtime_manifest_sha256 != request.runtime_manifest_sha256
        || value.context_tokens != 2048
        || value.maximum_output_tokens != 512
        || value.memory_max_bytes != MEMORY
        || value.memory_swap_max_bytes != 0
        || value.tasks_max != 16
        || value.cpu_quota_usec != 200000
        || value.cpu_period_usec != 100000
        || value.runtime_cpu_seconds != 300
        || value.threads != 2
    {
        return Err(
            "publisher-bound inference profile differs from the exact reviewed CPU profile".into(),
        );
    }
    Ok(())
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    bytes: u64,
    sha256: String,
    executable: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    profile: String,
    files: Vec<Member>,
}

type Witness = (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64);
fn witness(info: &std::fs::Metadata) -> Witness {
    (
        info.dev(),
        info.ino(),
        info.mode(),
        info.uid(),
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
    fn open(
        path: &str,
        length: Option<u64>,
        maximum: u64,
        digest: Option<&str>,
        deadline: Instant,
    ) -> Result<Self> {
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("noncanonical inference input path".into());
        }
        let absolute = Path::new("/").join(relative);
        for parent in absolute.ancestors() {
            let info = std::fs::symlink_metadata(parent)?;
            if info.uid() != 0 || info.mode() & 0o7022 != 0 || info.file_type().is_symlink() {
                return Err(
                    "inference files require protected root-owned no-follow ancestors".into(),
                );
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&absolute)?;
        let info = file.metadata()?;
        if !info.is_file()
            || info.nlink() != 1
            || info.len() == 0
            || info.len() > maximum
            || length.map_or(false, |length| length != info.len())
        {
            return Err("inference file geometry or single-link identity differs".into());
        }
        if let Some(expected) = digest {
            let mut hash = Sha256::new();
            let mut block = [0u8; 65536];
            let mut blocks = 0usize;
            loop {
                if blocks % 256 == 0 {
                    context(None)?;
                }
                if Instant::now() >= deadline {
                    return Err("inference input hashing deadline expired".into());
                }
                let count = file.read(&mut block)?;
                if count == 0 {
                    break;
                }
                hash.update(&block[..count]);
                blocks += 1;
            }
            if crate::bundle::hex(&hash.finalize()) != expected {
                return Err("complete inference input digest differs".into());
            }
            file.seek(SeekFrom::Start(0))?;
        }
        let value = Self {
            file,
            path: absolute.to_string_lossy().into_owned(),
            witness: witness(&info),
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if witness(&self.file.metadata()?) != self.witness
            || witness(&std::fs::symlink_metadata(&self.path)?) != self.witness
        {
            return Err("held inference input changed".into());
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
        if bytes.len() > maximum {
            return Err("inference descriptor exceeds bound".into());
        }
        self.check()?;
        Ok(bytes)
    }
}
fn private_names() -> BTreeSet<String> {
    let mut names = [
        "llama-completion",
        "libllama-completion-impl.so",
        "libggml-cpu-x64.so",
    ]
    .into_iter()
    .map(|name| format!("usr/libexec/luma-os/hosted-llama/{name}"))
    .collect::<BTreeSet<_>>();
    for (stem, version) in [
        ("libllama", "0.4.1"),
        ("libllama-common", "0.4.1"),
        ("libmtmd", "0.4.1"),
        ("libggml", "0.24.0"),
        ("libggml-base", "0.24.0"),
    ] {
        for suffix in ["".to_owned(), ".0".to_owned(), format!(".{version}")] {
            names.insert(format!(
                "usr/libexec/luma-os/hosted-llama/{stem}.so{suffix}"
            ));
        }
    }
    names
}
fn inputs(request: &Request, deadline: Instant) -> Result<(Vec<Held>, Held)> {
    let mut description = Held::open(
        DESCRIPTION,
        None,
        8192,
        Some(&request.profile_sha256),
        deadline,
    )?;
    validate_profile(
        &serde_json::from_slice::<Profile>(&description.bytes(8192)?)?,
        request,
    )?;
    let mut manifest = Held::open(
        MANIFEST,
        None,
        16384,
        Some(&request.runtime_manifest_sha256),
        deadline,
    )?;
    let value: Manifest = serde_json::from_slice(&manifest.bytes(16384)?)?;
    if value.schema_version != 1
        || value.profile != PROFILE
        || value.files.is_empty()
        || value.files.len() > 64
    {
        return Err("inference runtime inventory exceeds closed bounds".into());
    }
    let allowed_private = private_names();
    let mut selected_private = BTreeSet::new();
    let mut held = vec![description, manifest];
    let mut previous = String::new();
    let mut worker = false;
    for entry in value.files {
        if entry.path <= previous
            || !hash(&entry.sha256)
            || entry.bytes < 64
            || entry.bytes > 64 * 1024 * 1024
        {
            return Err("inference runtime inventory order, member size or digest differs".into());
        }
        let private = entry.path.starts_with("usr/libexec/luma-os/hosted-llama/");
        if private {
            if !allowed_private.contains(&entry.path) {
                return Err("unapproved inference program/backend".into());
            }
            selected_private.insert(entry.path.clone());
        } else if entry.path == "usr/libexec/luma-os/luma-platform" {
            worker = true;
        } else if !["lib/", "lib64/", "usr/lib/", "usr/lib64/"]
            .iter()
            .any(|prefix| entry.path.starts_with(prefix))
        {
            return Err("inference runtime file is outside its closed library namespaces".into());
        }
        let file = Held::open(
            &entry.path,
            Some(entry.bytes),
            64 * 1024 * 1024,
            Some(&entry.sha256),
            deadline,
        )?;
        if (file.file.metadata()?.mode() & 0o111 != 0) != entry.executable {
            return Err("inference runtime executable mode differs".into());
        }
        previous = entry.path;
        held.push(file);
    }
    if !worker || selected_private != allowed_private {
        return Err("inference runtime closure is incomplete".into());
    }
    let actual = std::fs::read_dir(PRIVATE)?
        .map(|entry| {
            entry.map(|entry| {
                format!(
                    "usr/libexec/luma-os/hosted-llama/{}",
                    entry.file_name().to_string_lossy()
                )
            })
        })
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if actual != allowed_private {
        return Err("inference runtime directory contains an unapproved backend or program".into());
    }
    let model = Held::open(
        MODEL,
        Some(MODEL_BYTES),
        MODEL_BYTES,
        Some(MODEL_SHA),
        deadline,
    )?;
    Ok((held, model))
}

fn context(child: Option<u32>) -> Result<Vec<u32>> {
    crate::hosted_fence::check_current()?;
    observe_headroom(false)?;
    if unsafe { libc::getuid() } != 65534
        || unsafe { libc::geteuid() } != 65534
        || unsafe { libc::getgid() } != 65534
        || unsafe { libc::getegid() } != 65534
    {
        return Err("inference requires the exact unprivileged UID/GID".into());
    }
    let mut ids = [0; 3];
    let ptr = ids.as_mut_ptr();
    if unsafe { libc::getresuid(ptr, ptr.add(1), ptr.add(2)) } != 0
        || ids != [65534; 3]
        || unsafe { libc::getresgid(ptr, ptr.add(1), ptr.add(2)) } != 0
        || ids != [65534; 3]
    {
        return Err("inference retained a privileged saved identity".into());
    }
    let size = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if !(0..=1).contains(&size) {
        return Err("inference supplementary groups differ".into());
    }
    let mut groups = vec![0; size as usize];
    if unsafe { libc::getgroups(size, groups.as_mut_ptr()) } != size
        || groups.iter().any(|group| *group != 65534)
    {
        return Err("inference supplementary group access differs".into());
    }
    let status = host::kernel("/proc/self/status", PROCFS, 32768)?;
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if host::status_field(&status, field)? != "0000000000000000" {
            return Err("inference retains capabilities".into());
        }
    }
    if host::status_field(&status, "NoNewPrivs:")? != "1"
        || host::status_field(&status, "Seccomp:")? != "2"
        || host::kernel("/proc/self/attr/current", PROCFS, 256)?
            != "luma-hosted-inference (enforce)\n"
        || host::kernel("/proc/self/cgroup", PROCFS, 512)? != CGROUP
    {
        return Err("inference lacks its exact enforcing kernel context".into());
    }
    for (field, expected) in [
        ("memory.max", format!("{MEMORY}\n")),
        ("memory.swap.max", "0\n".into()),
        ("pids.max", "16\n".into()),
        ("cpu.max", "200000 100000\n".into()),
    ] {
        if host::kernel(&format!("{GROUP}/{field}"), CGROUP2, 128)? != expected {
            return Err("inference resource ceilings differ".into());
        }
    }
    let pids = host::kernel(&format!("{GROUP}/cgroup.procs"), CGROUP2, 512)?;
    let mut own = false;
    for pid in pids.lines() {
        let pid: u32 = pid.parse()?;
        if pid == std::process::id() {
            own = true;
        } else if Some(pid) != child {
            return Err("inference cgroup has an unrelated process".into());
        }
    }
    if !own {
        return Err("inference cgroup omits its actual worker".into());
    }
    let mut cpu: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_CPU, &mut cpu) } != 0
        || cpu.rlim_cur != 300
        || cpu.rlim_max != 300
    {
        return Err("inference CPU lifetime differs".into());
    }
    Ok(groups)
}
fn ready(file: &File, events: i16, deadline: Instant) -> Result<()> {
    loop {
        context(None)?;
        if Instant::now() >= deadline {
            return Err("inference original wall deadline expired".into());
        }
        let mut descriptor = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}
fn read(file: &mut File, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLIN, deadline)?;
        let count = bytes.len().min(4096);
        match file.read(&mut bytes[..count]) {
            Ok(0) => return Err("original inference input/ack pipe closed".into()),
            Ok(size) => bytes = &mut bytes[size..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn write(file: &mut File, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLOUT, deadline)?;
        match file.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err("original inference output pipe closed".into()),
            Ok(size) => bytes = &bytes[size..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn memory(name: &str, seal: Option<&[u8]>) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    if let Some(data) = seal {
        file.write_all(data)?;
        file.seek(SeekFrom::Start(0))?;
        if unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } != 0
        {
            return Err("cannot seal exact inference prompt".into());
        }
    }
    Ok(file)
}
fn peer_alive(input: &File, output: &File) -> Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        },
    ];
    if unsafe { libc::poll(fds.as_mut_ptr(), 2, 0) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if fds
        .iter()
        .any(|fd| fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
    {
        return Err("original inference controller disconnected; owned runtime must stop".into());
    }
    Ok(())
}
fn framed_prompt(prompt: &str) -> Vec<u8> {
    // Fixed Qwen3 ChatML DATA framing, not hidden system instructions or a CLI
    // command. The raw user bytes remain exactly bound by Request.prompt_sha256.
    // An empty thinking prefill selects the model's non-thinking answer path.
    format!("<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n")
        .into_bytes()
}
fn generate(
    request: &Request,
    files: &[Held],
    model: &Held,
    input: &File,
    transport: &File,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let prompt = memory("luma-hosted-prompt", Some(&framed_prompt(&request.prompt)))?;
    let mut output = memory("luma-hosted-output", None)?;
    let errors = memory("luma-hosted-diagnostics", None)?;
    let model_fd = model.file.as_raw_fd();
    let prompt_fd = prompt.as_raw_fd();
    let mut command = Command::new(format!("{PRIVATE}/llama-completion"));
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .env("LD_LIBRARY_PATH", PRIVATE)
        .env("GGML_BACKEND_DL_PATH", PRIVATE)
        .env("OMP_NUM_THREADS", "2")
        .args([
            "--model",
            &format!("/proc/self/fd/{model_fd}"),
            "--file",
            &format!("/proc/self/fd/{prompt_fd}"),
            "--ctx-size",
            "2048",
            "--n-predict",
            &request.max_tokens.to_string(),
            "--threads",
            "2",
            "--threads-batch",
            "2",
            "--batch-size",
            "128",
            "--ubatch-size",
            "128",
            "--n-gpu-layers",
            "0",
            "--seed",
            "0",
            "--temp",
            "0",
            "--no-conversation",
            "--no-escape",
            "--no-display-prompt",
            "--simple-io",
            "--color",
            "off",
            "--no-warmup",
            "--no-perf",
            "--log-verbosity",
            "0",
            "--no-context-shift",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(errors.try_clone()?));
    unsafe {
        command.pre_exec(move || {
            for fd in [model_fd, prompt_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let limit = libc::rlimit {
                rlim_cur: OUTPUT as u64,
                rlim_max: OUTPUT as u64,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    crate::model::supervise_owned_controller_with_pid(&mut command, |pid| {
        context(if pid == 0 { None } else { Some(pid) })?;
        peer_alive(input, transport)?;
        if Instant::now() >= deadline
            || output.metadata()?.len() > OUTPUT as u64
            || errors.metadata()?.len() > 65536
        {
            return Err("inference wall/diagnostic/output budget exceeded".into());
        }
        for file in files {
            file.check()?;
        }
        model.check()
    })?;
    context(None)?;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.take(OUTPUT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > OUTPUT || std::str::from_utf8(&bytes).is_err() {
        return Err("actual inference result is empty, oversized or invalid UTF8".into());
    }
    Ok(bytes)
}
pub(crate) fn worker(resource: &str, request_sha: &str) -> Result<()> {
    crate::hosted_fence::bind(resource, request_sha)?;
    crate::protect_memory()?;
    let groups = context(None)?;
    observe_headroom(true)?;
    host::require_network_denial()?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut input = host::pipe(0, false)?;
    let mut output = host::pipe(1, true)?;
    let mut count = [0; 4];
    read(&mut input, &mut count, deadline)?;
    let count = u32::from_be_bytes(count) as usize;
    if count == 0 || count > 32768 {
        return Err("inference request frame exceeds bound".into());
    }
    let mut bytes = vec![0; count];
    read(&mut input, &mut bytes, deadline)?;
    crate::hosted_fence::require_bytes(&bytes)?;
    let request = parse(&bytes)?;
    let (files, model) = inputs(&request, deadline)?;
    let result = generate(&request, &files, &model, &input, &output, deadline)?;
    let metadata = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"profile":PROFILE,"nonce":request.nonce,
        "request_sha256":luma_content::sha256(&bytes),"model_sha256":request.model_sha256,
        "runtime_manifest_sha256":request.runtime_manifest_sha256,"profile_sha256":request.profile_sha256,
        "prompt_sha256":request.prompt_sha256,"context_tokens":2048,"max_tokens":request.max_tokens,
        "result_sha256":luma_content::sha256(&result),"result_bytes":result.len(),"inference_executed":true,
        "uid":65534,"gid":65534,"supplementary_groups":groups,"cap_inheritable":"0000000000000000",
        "cap_permitted":"0000000000000000","cap_effective":"0000000000000000","cap_bounding":"0000000000000000",
        "cap_ambient":"0000000000000000","no_new_privileges":true,"apparmor_profile":"luma-hosted-inference",
        "cgroup":CGROUP,"memory_max_bytes":MEMORY,"memory_swap_max_bytes":0,"tasks_max":16,
        "cpu_quota_usec":200000,"cpu_period_usec":100000,"runtime_cpu_seconds":300,
        "principal_authenticated":false,"grants_admitted":false,"authority_returned":false,"committed":false,
        "workflow_executed":false,"production_qualified":false}),
    )?;
    if metadata.len() > 8192 {
        return Err("inference observation exceeds bound".into());
    }
    write(&mut output, b"LUMAWININFERv1!\n", deadline)?;
    write(
        &mut output,
        &(metadata.len() as u32).to_be_bytes(),
        deadline,
    )?;
    write(&mut output, &metadata, deadline)?;
    let mut digest = Sha256::new();
    let mut sent = 0u64;
    for chunk in result.chunks(32768) {
        for file in &files {
            file.check()?;
        }
        model.check()?;
        write(&mut output, chunk, deadline)?;
        digest.update(chunk);
        sent += chunk.len() as u64;
        let mut ack = [0; 40];
        read(&mut input, &mut ack, deadline)?;
        if u64::from_be_bytes(ack[..8].try_into()?) != sent
            || ack[8..] != digest.clone().finalize()[..]
        {
            return Err("inference acknowledgment changed exact delivered prefix".into());
        }
    }
    for file in &files {
        file.check()?;
    }
    model.check()?;
    context(None)?;
    Ok(())
}
fn arguments() -> Vec<String> {
    let mut arguments = [
        "--quiet",
        "--pipe",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=luma-hosted-inference.service",
        "--slice=lumahosted.slice",
        "--property=Requires=luma-hosted-inference-confinement.service",
        "--property=After=luma-hosted-inference-confinement.service",
        "--property=User=65534",
        "--property=Group=65534",
        "--property=SupplementaryGroups=",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=AppArmorProfile=luma-hosted-inference",
        "--property=MemoryMax=4831838208",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=16",
        "--property=CPUQuota=200%",
        "--property=CPUQuotaPeriodSec=100ms",
        "--property=LimitCPU=300",
        "--property=RuntimeMaxSec=300",
        "--property=LimitCORE=0",
        "--property=LimitMEMLOCK=0",
        "--property=Restart=no",
        "--property=KillMode=control-group",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
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
        EXECUTABLE,
        "hosted-windows-inference",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    arguments.insert(7, "--property=CPUAccounting=yes".into());
    arguments
}
pub(crate) fn launch(resource: &str, request_sha: &str) -> Result<()> {
    host::host_context()?;
    observe_headroom(true)?;
    crate::hosted_fence::prepare(resource, request_sha)?;
    Err(Command::new("/usr/bin/systemd-run")
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .args(arguments())
        .args([resource, request_sha])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .exec()
        .into())
}
pub(crate) fn drain(request_sha: &str) -> Result<()> {
    host::drain_profile(UNIT, GROUP, PROFILE, request_sha)
}

pub(crate) fn contract() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin().take(32769).read_to_end(&mut bytes)?;
    let request = parse(&bytes)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"profile":PROFILE,
        "request_sha256":luma_content::sha256(&bytes),"prompt_sha256":request.prompt_sha256,
        "model_sha256":request.model_sha256,"runtime_manifest_sha256":request.runtime_manifest_sha256,
        "profile_sha256":request.profile_sha256,"context_tokens":2048,"max_tokens":request.max_tokens,
        "purpose_seconds":300,"inference_executed":false,"authority_returned":false,"production_qualified":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_prompt_preserves_exact_user_bytes_with_no_cli_command_or_system_role() {
        let prompt = "/read /etc/shadow\nuser supplied UTF8: λ";
        assert_eq!(framed_prompt(prompt), format!("<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n").as_bytes());
        assert!(!String::from_utf8(framed_prompt(prompt))
            .unwrap()
            .contains("<|im_start|>system"));
    }
    #[test]
    fn observed_guest_headroom_is_bounded_and_not_an_atomic_reservation() {
        let start = (MEMORY + MEMORY_RESERVE) / 1024;
        let low = MEMORY_RESERVE / 1024;
        assert!(memory_headroom(&format!("MemAvailable: {start} kB\n"), true).is_ok());
        assert!(memory_headroom(&format!("MemAvailable: {} kB\n", start - 1), true).is_err());
        assert!(memory_headroom(&format!("MemAvailable: {low} kB\n"), false).is_ok());
        assert!(memory_headroom(&format!("MemAvailable: {} kB\n", low - 1), false).is_err());
        for value in [
            "",
            "MemAvailable: -1 kB\n",
            "MemAvailable: 99999999999999999999 kB\n",
            "MemAvailable: 99999999 MB\n",
            "MemAvailable: 99999999 kB extra\n",
            "MemAvailable: 99999999 kB\nMemAvailable: 99999999 kB\n",
        ] {
            assert!(memory_headroom(value, true).is_err());
        }
    }
    fn request() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"profile":PROFILE,"nonce":"11".repeat(32),"model_sha256":MODEL_SHA,
            "runtime_manifest_sha256":"22".repeat(32),"profile_sha256":"33".repeat(32),"prompt":"Hello",
            "prompt_sha256":luma_content::sha256(b"Hello"),"context_tokens":2048,"max_tokens":128})
    }
    #[test]
    fn request_is_exact_separate_finite_profile() {
        let value = request();
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        for (key, bad) in [
            ("schema_version", serde_json::json!(true)),
            (
                "profile",
                serde_json::json!("luma-windows-hosted-compute-v1"),
            ),
            ("nonce", serde_json::json!("00".repeat(32))),
            ("context_tokens", serde_json::json!(4096)),
            ("max_tokens", serde_json::json!(513)),
            ("model_sha256", serde_json::json!("11".repeat(32))),
            ("prompt", serde_json::json!("changed")),
            ("unknown", serde_json::json!(false)),
        ] {
            let mut bad_value = value.clone();
            bad_value[key] = bad;
            assert!(
                parse(&serde_json::to_vec(&bad_value).unwrap()).is_err(),
                "{key}"
            );
        }
        let bytes =
            serde_json::to_string(&value)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        assert!(parse(bytes.as_bytes()).is_err());
    }
    #[test]
    fn model_paths_and_programs_never_come_from_prompt() {
        let names = private_names();
        assert_eq!(names.len(), 18);
        assert!(names.contains("usr/libexec/luma-os/hosted-llama/libggml-cpu-x64.so"));
        assert!(!names
            .iter()
            .any(|name| name.contains("rpc") || name.ends_with("llama-server")));
        let arguments = arguments();
        for required in [
            "--property=RuntimeMaxSec=300",
            "--property=MemoryMax=4831838208",
            "--property=TasksMax=16",
            "--property=AppArmorProfile=luma-hosted-inference",
            "--property=Restart=no",
            "--property=KillMode=control-group",
        ] {
            assert!(arguments.contains(&required.to_string()));
        }
        assert_eq!(arguments.last().unwrap(), "hosted-windows-inference");
    }
    #[test]
    fn prompt_is_real_immutable_sealed_memory_not_argv() {
        let mut prompt = memory("luma-test-inference", Some(b"exact prompt")).unwrap();
        assert!(prompt.write_all(b"changed").is_err());
        assert_ne!(
            unsafe { libc::fcntl(prompt.as_raw_fd(), libc::F_GET_SEALS) } & libc::F_SEAL_WRITE,
            0
        );
        prompt.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        prompt.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exact prompt");
    }
    #[test]
    fn absent_enforcement_never_has_inference_authority() {
        if unsafe { libc::geteuid() } != 65534 {
            assert!(context(None).is_err());
        }
        assert!(host::drain_profile(
            "other",
            "/sys/fs/cgroup/other",
            PROFILE,
            "11".repeat(32).as_str()
        )
        .is_err());
    }
}
