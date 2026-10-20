//! Windows-hosted, inert data computation. Windows retains identity, grants and
//! effects. Observations here are not attestation, Linux authority or permission
//! to activate a distribution. Missing actual confinement refuses computation.
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROFILE: &str = "luma-windows-hosted-compute-v1";
const UNIT: &str = "luma-hosted-compute.service";
const GROUP: &str = "/sys/fs/cgroup/lumahosted.slice/luma-hosted-compute.service";
const CGROUP: &str = "0::/lumahosted.slice/luma-hosted-compute.service\n";
const LABEL: &str = "luma-hosted-compute (enforce)\n";
const EXECUTABLE: &str = "/usr/libexec/luma-os/luma-platform";
const MAX_FRAME: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD: usize = 2 * luma_content::MAX_ENVELOPE_BYTES + 8192;
const MEMORY: u64 = 512 * 1024 * 1024;
const PROCFS: libc::c_long = 0x9fa0;
const CGROUP2: libc::c_long = 0x6367_7270;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    profile: String,
    nonce: String,
    operation: String,
    payload: String,
    payload_sha256: String,
}
fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("hosted request frame exceeds bound".into());
    }
    let request: Request = serde_json::from_slice(bytes)?;
    if request.schema_version != 1
        || request.profile != PROFILE
        || request.payload.is_empty()
        || request.payload.len() > MAX_PAYLOAD
        || crate::tpm::decode::<32>(&request.nonce)? == [0; 32]
        || request.payload_sha256 != luma_content::sha256(request.payload.as_bytes())
    {
        return Err("hosted request differs from its exact selected input".into());
    }
    command(&request.operation)?;
    // serde's closed typed record rejects duplicate/unknown fields. Request
    // identity commits the original bytes, not a reserialized approximation.
    Ok(request)
}
fn command(operation: &str) -> Result<&'static str> {
    Ok(match operation {
        "capture" => "content-contract-capture",
        "reopen" => "content-contract-reopen",
        "spreadsheet" => "content-contract-spreadsheet",
        "document" => "content-contract-document",
        "diagram" => "content-contract-diagram",
        "animation" => "content-contract-animation",
        "collection" => "content-contract-collection",
        _ => return Err("unsupported closed hosted data operation".into()),
    })
}
pub(crate) fn filesystem(file: &File, expected: libc::c_long) -> Result<()> {
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } != 0 || info.f_type != expected {
        return Err("hosted observation requires actual kernel filesystem".into());
    }
    Ok(())
}
pub(crate) fn kernel(path: &str, magic: libc::c_long, maximum: u64) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    filesystem(&file, magic)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > maximum {
        return Err("unsafe hosted kernel observation".into());
    }
    let mut value = String::new();
    (&mut file).take(maximum + 1).read_to_string(&mut value)?;
    let current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    filesystem(&current, magic)?;
    let after = current.metadata()?;
    if value.len() as u64 > maximum
        || (before.dev(), before.ino(), before.uid(), before.mode())
            != (after.dev(), after.ino(), after.uid(), after.mode())
    {
        return Err("hosted kernel observation changed".into());
    }
    Ok(value)
}
pub(crate) fn status_field<'a>(status: &'a str, name: &str) -> Result<&'a str> {
    let mut values = status.lines().filter_map(|line| line.strip_prefix(name));
    let value = values.next().ok_or("hosted process status missing")?.trim();
    if values.next().is_some() {
        return Err("ambiguous hosted process status".into());
    }
    Ok(value)
}
fn context() -> Result<Vec<u32>> {
    crate::hosted_fence::check_current()?;
    if unsafe { libc::getuid() } != 65534
        || unsafe { libc::geteuid() } != 65534
        || unsafe { libc::getgid() } != 65534
        || unsafe { libc::getegid() } != 65534
    {
        return Err("hosted data worker requires fixed unprivileged UID/GID".into());
    }
    let mut ids = [0u32; 3];
    let pointer = ids.as_mut_ptr();
    if unsafe { libc::getresuid(pointer, pointer.add(1), pointer.add(2)) } != 0 || ids != [65534; 3]
    {
        return Err("hosted worker retained a privileged saved UID".into());
    }
    if unsafe { libc::getresgid(pointer, pointer.add(1), pointer.add(2)) } != 0 || ids != [65534; 3]
    {
        return Err("hosted worker retained a privileged saved GID".into());
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if !(0..=1).contains(&count) {
        return Err("hosted worker has supplementary access".into());
    }
    let mut groups = vec![0u32; count as usize];
    if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count
        || groups.iter().any(|group| *group != 65534)
    {
        return Err("hosted supplementary group differs".into());
    }
    let status = kernel("/proc/self/status", PROCFS, 32768)?;
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if status_field(&status, name)? != "0000000000000000" {
            return Err("hosted worker capabilities are not empty".into());
        }
    }
    if status_field(&status, "NoNewPrivs:")? != "1"
        || status_field(&status, "Seccomp:")? != "2"
        || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        || kernel("/proc/self/attr/current", PROCFS, 256)? != LABEL
        || kernel("/proc/self/cgroup", PROCFS, 512)? != CGROUP
    {
        return Err("hosted worker lacks its exact enforcing kernel context".into());
    }
    for (name, expected) in [
        ("memory.max", format!("{MEMORY}\n")),
        ("memory.swap.max", "0\n".into()),
        ("pids.max", "1\n".into()),
        ("cpu.max", "100000 100000\n".into()),
        ("cgroup.procs", format!("{}\n", std::process::id())),
    ] {
        if kernel(&format!("{GROUP}/{name}"), CGROUP2, 128)? != expected {
            return Err("hosted compute limits or exclusive cgroup ownership differ".into());
        }
    }
    let mut cpu: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_CPU, &mut cpu) } != 0
        || cpu.rlim_cur != 30
        || cpu.rlim_max != 30
    {
        return Err("hosted worker CPU lifetime differs".into());
    }
    Ok(groups)
}

pub(crate) fn require_network_denial() -> Result<()> {
    // These create no connections and send no bytes. The actual confined
    // process must be unable to create even a local or host-vsock channel.
    for family in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_VSOCK] {
        let descriptor = unsafe {
            libc::socket(
                family,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if descriptor >= 0 {
            unsafe { libc::close(descriptor) };
            return Err("hosted worker can create a prohibited network channel".into());
        }
        if !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES | libc::EPERM | libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
        ) {
            return Err("hosted network-denial observation is inconclusive".into());
        }
    }
    Ok(())
}

// New open-file descriptions of the dedicated job's FIFO endpoints avoid
// changing inherited descriptor flags. No regular-file/stdout fallback exists.
pub(crate) fn pipe(number: i32, writing: bool) -> Result<File> {
    let original = unsafe { libc::dup(number) };
    if original < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let original = unsafe { File::from_raw_fd(original) };
    let before = original.metadata()?;
    use std::os::unix::fs::FileTypeExt;
    if !before.file_type().is_fifo() {
        return Err("hosted transport requires dedicated FIFO endpoints".into());
    }
    let directory = File::open("/proc/self/fd")?;
    filesystem(&directory, PROCFS)?;
    let name = std::ffi::CString::new(number.to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            (if writing {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            }) | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let current = unsafe { File::from_raw_fd(fd) };
    let after = current.metadata()?;
    if !after.file_type().is_fifo() || (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err("hosted FIFO identity changed".into());
    }
    Ok(current)
}
fn ready(file: &File, events: i16, deadline: Instant) -> Result<()> {
    loop {
        context()?;
        if Instant::now() >= deadline {
            return Err("hosted compute wall deadline expired".into());
        }
        let mut value = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut value, 1, 100) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error().into());
        }
        if result > 0 {
            return Ok(());
        }
    }
}
fn read(file: &mut File, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLIN, deadline)?;
        let length = bytes.len().min(4096);
        match file.read(&mut bytes[..length]) {
            Ok(0) => return Err("hosted original input/acknowledgment closed".into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    context()?;
    Ok(())
}
fn write(file: &mut File, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLOUT, deadline)?;
        match file.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err("hosted original result reader closed".into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    context()?;
    Ok(())
}
pub(crate) fn worker(resource: &str, request_sha: &str) -> Result<()> {
    crate::hosted_fence::bind(resource, request_sha)?;
    crate::protect_memory()?;
    let groups = context()?;
    require_network_denial()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut input = pipe(0, false)?;
    let mut output = pipe(1, true)?;
    let mut length = [0u8; 4];
    read(&mut input, &mut length, deadline)?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("hosted frame size refused".into());
    }
    let mut bytes = vec![0; size];
    read(&mut input, &mut bytes, deadline)?;
    crate::hosted_fence::require_bytes(&bytes)?;
    let request = parse(&bytes)?;
    let result = serde_json::to_vec(&crate::content_contract::process(
        command(&request.operation)?,
        request.payload.as_bytes(),
    )?)?;
    if result.is_empty() || result.len() > MAX_FRAME {
        return Err("hosted engine result exceeds bounded frame".into());
    }
    context()?;
    let metadata = serde_json::to_vec(&serde_json::json!({"schema_version":1,"profile":PROFILE,
        "nonce":request.nonce,"operation":request.operation,"request_sha256":luma_content::sha256(&bytes),
        "payload_sha256":request.payload_sha256,"result_sha256":luma_content::sha256(&result),"result_bytes":result.len(),
        "uid":65534,"gid":65534,"supplementary_groups":groups,"cap_inheritable":"0000000000000000",
        "cap_permitted":"0000000000000000","cap_effective":"0000000000000000","cap_bounding":"0000000000000000",
        "cap_ambient":"0000000000000000","no_new_privileges":true,"apparmor_profile":"luma-hosted-compute",
        "cgroup":CGROUP,"memory_max_bytes":MEMORY,"memory_swap_max_bytes":0,"tasks_max":1,
        "cpu_quota_usec":100000,"cpu_period_usec":100000,"runtime_cpu_seconds":30,
        "principal_authenticated":false,"grants_admitted":false,"authority_returned":false,"committed":false,
        "workflow_executed":false,"production_qualified":false}))?;
    if metadata.len() > 8192 {
        return Err("hosted metadata exceeds fixed bound".into());
    }
    write(&mut output, b"LUMAWINCOMPv1!!\n", deadline)?;
    write(
        &mut output,
        &(metadata.len() as u32).to_be_bytes(),
        deadline,
    )?;
    write(&mut output, &metadata, deadline)?;
    let mut hash = Sha256::new();
    let mut cumulative = 0u64;
    for chunk in result.chunks(32768) {
        write(&mut output, chunk, deadline)?;
        hash.update(chunk);
        cumulative += chunk.len() as u64;
        let mut ack = [0u8; 40];
        read(&mut input, &mut ack, deadline)?;
        if u64::from_be_bytes(ack[..8].try_into()?) != cumulative
            || ack[8..] != hash.clone().finalize()[..]
        {
            return Err("hosted delivery acknowledgment differs from exact output prefix".into());
        }
    }
    context()?;
    Ok(())
}

pub(crate) fn host_context() -> Result<()> {
    crate::require_root()?;
    if kernel("/proc/1/comm", PROCFS, 64)? != "systemd\n"
        || !kernel("/proc/sys/kernel/osrelease", PROCFS, 256)?
            .to_ascii_lowercase()
            .contains("microsoft-standard-wsl2")
    {
        return Err("hosted launcher requires actual systemd WSL2 runtime".into());
    }
    let executable = std::fs::canonicalize(EXECUTABLE)?;
    if executable != Path::new(EXECUTABLE) || std::fs::read_link("/proc/self/exe")? != executable {
        return Err("hosted launcher must be the fixed installed executable".into());
    }
    for path in executable.ancestors() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
            return Err("hosted launcher image path is not protected".into());
        }
    }
    Ok(())
}
fn arguments() -> Vec<&'static str> {
    vec![
        "--quiet",
        "--pipe",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=luma-hosted-compute.service",
        "--slice=lumahosted.slice",
        "--property=Requires=luma-hosted-confinement.service",
        "--property=After=luma-hosted-confinement.service",
        "--property=User=65534",
        "--property=Group=65534",
        "--property=SupplementaryGroups=",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=AppArmorProfile=luma-hosted-compute",
        "--property=MemoryMax=536870912",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=1",
        "--property=CPUQuota=100%",
        "--property=CPUQuotaPeriodSec=100ms",
        "--property=LimitCPU=30",
        "--property=RuntimeMaxSec=30",
        "--property=LimitCORE=0",
        "--property=LimitMEMLOCK=0",
        "--property=Restart=no",
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
        "hosted-windows-compute",
    ]
}
pub(crate) fn launch(resource: &str, request_sha: &str) -> Result<()> {
    host_context()?;
    crate::hosted_fence::prepare(resource, request_sha)?;
    // An occupied unit refuses; never replace, restart or name-kill a possibly
    // different invocation. Windows retains its lease until drain is observed.
    let error = Command::new("/usr/bin/systemd-run")
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .args(arguments())
        .args([resource, request_sha])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .exec();
    Err(error.into())
}
pub(crate) fn drain(request_sha: &str) -> Result<()> {
    drain_profile(UNIT, GROUP, PROFILE, request_sha)
}
pub(crate) fn drain_profile(
    unit: &str,
    group: &str,
    profile: &str,
    request_sha: &str,
) -> Result<()> {
    if !matches!(
        (unit, group, profile),
        (UNIT, GROUP, PROFILE)
            | (
                "luma-hosted-inference.service",
                "/sys/fs/cgroup/lumahosted.slice/luma-hosted-inference.service",
                "luma-windows-hosted-inference-v1"
            )
    ) {
        return Err("unknown hosted drain profile".into());
    }
    host_context()?;
    crate::hosted_fence::revoke(request_sha)?;
    let hierarchy = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup")?;
    filesystem(&hierarchy, CGROUP2)?;
    let empty = match kernel(&format!("{group}/cgroup.procs"), CGROUP2, 4096) {
        Ok(value) => value.is_empty(),
        Err(error) => {
            if std::fs::symlink_metadata(group).is_ok() {
                return Err(error);
            }
            match std::fs::symlink_metadata(group) {
                Err(value) if value.kind() == std::io::ErrorKind::NotFound => true,
                _ => return Err(error),
            }
        }
    };
    let name = std::ffi::CString::new("luma-hosted-drain")?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut result = unsafe { File::from_raw_fd(fd) };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut command = Command::new("/usr/bin/systemctl");
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .args([
            "show",
            unit,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Job",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(result.try_clone()?))
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            let bound = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: 4096,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &bound) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    crate::model::supervise_owned_controller(&mut command, || {
        if Instant::now() >= deadline {
            return Err("hosted unit-state observation deadline expired".into());
        }
        filesystem(&hierarchy, CGROUP2)
    })?;
    result.seek(SeekFrom::Start(0))?;
    let mut state = String::new();
    (&mut result).take(4097).read_to_string(&mut state)?;
    if state.len() > 4096 {
        return Err("hosted unit-state observation exceeds bound".into());
    }
    let inactive = inactive_unit(&state)?;
    // A queued StartUnit can create a worker after an absent-cgroup observation.
    // The host must also observe its exact controller exit. Neither fact is a
    // workflow completion receipt or permission for a new resource generation.
    let empty = empty
        && match kernel(&format!("{group}/cgroup.procs"), CGROUP2, 4096) {
            Ok(value) => value.is_empty(),
            Err(error) => match std::fs::symlink_metadata(group) {
                Err(value) if value.kind() == std::io::ErrorKind::NotFound => true,
                _ => return Err(error),
            },
        };
    result.set_len(0)?;
    result.seek(SeekFrom::Start(0))?;
    crate::model::supervise_owned_controller(&mut command, || {
        if Instant::now() >= deadline {
            return Err("hosted repeated unit/job observation deadline expired".into());
        }
        filesystem(&hierarchy, CGROUP2)
    })?;
    result.seek(SeekFrom::Start(0))?;
    let mut repeated = String::new();
    (&mut result).take(4097).read_to_string(&mut repeated)?;
    if repeated.len() > 4096 {
        return Err("hosted repeated unit observation exceeds bound".into());
    }
    let inactive = inactive && inactive_unit(&repeated)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"profile":profile,"unit":unit,
        "cgroup_empty_or_absent":empty,"unit_inactive":inactive,"authority_returned":false,"job_completed":false})
    );
    Ok(())
}

fn inactive_unit(state: &str) -> Result<bool> {
    let mut fields = std::collections::BTreeMap::new();
    for line in state.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("malformed hosted unit-state observation")?;
        if !["LoadState", "ActiveState", "SubState", "Job"].contains(&key)
            || (value.is_empty() && key != "Job")
            || value.len() > 64
            || fields.insert(key, value).is_some()
        {
            return Err("ambiguous hosted unit-state observation".into());
        }
    }
    if fields.len() != 4 {
        return Err("incomplete hosted unit-state observation".into());
    }
    Ok(matches!(fields["LoadState"], "loaded" | "not-found")
        && matches!(fields["ActiveState"], "inactive" | "failed")
        && matches!(fields["SubState"], "dead" | "failed")
        && fields["Job"].is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_cgroup_never_substitutes_for_inactive_systemd_unit() {
        assert!(
            inactive_unit("LoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\n")
                .unwrap()
        );
        assert!(
            !inactive_unit("LoadState=loaded\nActiveState=activating\nSubState=start\nJob=\n")
                .unwrap()
        );
        assert!(
            !inactive_unit("LoadState=loaded\nActiveState=active\nSubState=running\nJob=\n")
                .unwrap()
        );
        for invalid in [
            "",
            "LoadState=not-found\n",
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nActiveState=inactive\n",
        ] {
            assert!(inactive_unit(invalid).is_err());
        }
        assert!(
            !inactive_unit("LoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=123\n")
                .unwrap()
        );
        assert!(inactive_unit("LoadState=loaded\nActiveState=inactive\nSubState=dead\n").is_err());
    }
    fn request() -> Vec<u8> {
        serde_json::to_vec(&Request {
            schema_version: 1,
            profile: PROFILE.into(),
            nonce: "ab".repeat(32),
            operation: "document".into(),
            payload: "{}".into(),
            payload_sha256: luma_content::sha256(b"{}"),
        })
        .unwrap()
    }
    #[test]
    fn closed_hosted_requests_are_data_only_and_hash_bound() {
        let bytes = request();
        parse(&bytes).unwrap();
        for (key, value) in [
            ("nonce", serde_json::json!("00".repeat(32))),
            ("schema_version", serde_json::json!(true)),
            ("operation", serde_json::json!("content-owned-apply")),
            ("payload_sha256", serde_json::json!("cd".repeat(32))),
            ("owner_authenticated", serde_json::json!(true)),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            changed[key] = value;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert!(parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn only_fixed_data_engines_and_kernel_confinement_can_run() {
        for name in [
            "capture",
            "reopen",
            "spreadsheet",
            "document",
            "diagram",
            "animation",
            "collection",
        ] {
            command(name).unwrap();
        }
        for name in [
            "shell",
            "inference",
            "native-request",
            "export",
            "install",
            "",
        ] {
            assert!(command(name).is_err());
        }
        assert!(filesystem(&File::open("/proc/self/status").unwrap(), CGROUP2).is_err());
        assert!(worker(&"ab".repeat(32), &"bc".repeat(32)).is_err());
        let args = arguments();
        for required in [
            "--property=CapabilityBoundingSet=",
            "--property=MemoryMax=536870912",
            "--property=TasksMax=1",
            "--property=AppArmorProfile=luma-hosted-compute",
            "--property=RuntimeMaxSec=30",
        ] {
            assert!(args.contains(&required));
        }
    }
}
