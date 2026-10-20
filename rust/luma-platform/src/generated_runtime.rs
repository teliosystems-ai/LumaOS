//! Finite, continuously authorized execution of a static ELF in the fixed KVM
//! guest. Payload bytes are data; neither this controller nor a host shell runs
//! them. The existing serialized helper pool owns every physical reservation.
use crate::{acquisition, artifacts as io, finite_grants, model, resource_manager, Result};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

#[path = "generated_build.rs"]
mod build;

const PREFIX: &str = "generated-v1-";
const BUILD_PREFIX: &str = "generated-build-v1-";
const MAX_EXECUTABLE: usize = 1_048_576;
const MAX_INPUT: usize = 65_536;
const MAX_REQUEST: usize = 2 * (MAX_EXECUTABLE + MAX_INPUT) + 256;
const MAX_OUTPUT: u64 = 262_144;
const OUTPUT_STREAM: usize = 32_768;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const MANIFEST: &str = "/usr/share/luma-os/generated/manifest.json";

/// A routing predicate only; no syntactically valid name grants execution.
/// Request, runtime, original PAM, finite grant and physical-generation checks
/// remain mandatory at the selected admission boundary.
pub(crate) fn is_profile(value: &str) -> bool {
    value
        .strip_prefix(PREFIX)
        .or_else(|| value.strip_prefix(BUILD_PREFIX))
        .is_some_and(io::hash)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    executable_hex: String,
    stdin_hex: String,
}

fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum * 2 || value.len() % 2 != 0 {
        return Err("generated input encoding exceeds its exact bound".into());
    }
    fn nibble(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("generated input requires canonical lowercase hex".into()),
        }
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(nibble(p[0])? * 16 + nibble(p[1])?))
        .collect()
}

fn parse_input(bytes: &[u8]) -> Result<(Input, Vec<u8>, Vec<u8>)> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("generated request exceeds the fixed admission bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    if input.schema_version != 1 || serde_json::to_vec(&input)? != bytes {
        return Err("generated request must use the exact canonical schema".into());
    }
    let executable = unhex(&input.executable_hex, MAX_EXECUTABLE)?;
    let stdin = unhex(&input.stdin_hex, MAX_INPUT)?;
    // Detailed load-segment/static-ELF checks also occur in the trusted runner,
    // before QEMU sees any payload. This gate rejects other architectures and
    // host scripts without ever attempting to execute or compile them.
    if executable.len() < 64
        || executable[..7] != *b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes([executable[16], executable[17]]) != 2
        || u16::from_le_bytes([executable[18], executable[19]]) != 62
    {
        return Err("generated execution supports only static amd64 ELF executables".into());
    }
    Ok((input, executable, stdin))
}

pub(crate) fn read_request(path: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_REQUEST as u64
    {
        return Err("generated request must be a bounded regular single-link file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let key = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if bytes.len() as u64 != before.len()
        || key(&before) != key(&after)
        || key(&before) != key(&std::fs::symlink_metadata(path)?)
    {
        return Err("generated request changed during bounded capture".into());
    }
    request_profile(&bytes)?;
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    architecture: String,
    acceleration: String,
    kernel_sha256: String,
    base_initrd_sha256: String,
    qemu_sha256: String,
    guest_init_sha256: String,
    guest_init_source_sha256: String,
    runner_sha256: String,
    memory_mib: u32,
    timeout_ms: u32,
    guest_timeout_ms: u32,
    executable_max_bytes: usize,
    input_max_bytes: usize,
    stdout_max_bytes: usize,
    stderr_max_bytes: usize,
}

fn runtime_digest() -> Result<String> {
    let mut ancestor = Path::new(MANIFEST).parent();
    while let Some(path) = ancestor {
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("generated runtime requires immutable image-owned ancestors".into());
        }
        ancestor = path.parent();
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(MANIFEST)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > 8192
    {
        return Err("generated runtime manifest is not immutable image-owned data".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(8193).read_to_end(&mut bytes)?;
    let policy: Manifest = serde_json::from_slice(&bytes)?;
    if policy.schema_version != 1
        || policy.architecture != "x86_64"
        || policy.acceleration != "kvm"
        || policy.memory_mib != 128
        || policy.timeout_ms != 15000
        || policy.guest_timeout_ms != 3000
        || policy.executable_max_bytes != MAX_EXECUTABLE
        || policy.input_max_bytes != MAX_INPUT
        || policy.stdout_max_bytes != OUTPUT_STREAM
        || policy.stderr_max_bytes != OUTPUT_STREAM
        || [
            &policy.kernel_sha256,
            &policy.base_initrd_sha256,
            &policy.qemu_sha256,
            &policy.guest_init_sha256,
            &policy.guest_init_source_sha256,
            &policy.runner_sha256,
        ]
        .iter()
        .any(|v| !io::hash(v))
    {
        return Err("generated runtime manifest differs from the fixed compiled policy".into());
    }
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(MANIFEST)?;
    if bytes.len() as u64 != m.len()
        || (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
            != (
                after.dev(),
                after.ino(),
                after.len(),
                after.ctime(),
                after.ctime_nsec(),
            )
        || (m.dev(), m.ino()) != (named.dev(), named.ino())
    {
        return Err("generated runtime manifest changed during capture".into());
    }
    Ok(io::digest(&bytes))
}

pub(crate) fn source_digest(profile: &str) -> Result<&str> {
    let digest = profile
        .strip_prefix(PREFIX)
        .or_else(|| profile.strip_prefix(BUILD_PREFIX))
        .ok_or("unknown generated runtime profile")?;
    if !io::hash(digest) {
        return Err("invalid generated request identity".into());
    }
    Ok(digest)
}

pub(crate) fn binding(profile: &str, device: &str) -> Result<String> {
    let source = source_digest(profile)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("invalid generated storage identity")?;
    if major == "0"
        || [major, minor]
            .iter()
            .any(|v| v.parse::<u32>().map_or(true, |n| n.to_string() != *v))
    {
        return Err("generated execution requires exact installed block-backed storage".into());
    }
    Ok(io::digest(&serde_json::to_vec(&(
        if profile.starts_with(BUILD_PREFIX) {
            "luma-generated-build-kvm-v1"
        } else {
            "luma-generated-kvm-v1"
        },
        io::installation()?,
        profile_runtime(profile)?,
        source,
        device,
    ))?))
}

fn anonymous(name: &str, bytes: &[u8], sealed: bool) -> Result<File> {
    let name = CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if sealed && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err("generated input descriptor sealing failed".into());
    }
    Ok(file)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GuestReceipt {
    schema_version: u32,
    execution_status: String,
    execution_value: i32,
    runtime_sha256: String,
    executable_sha256: String,
    input_sha256: String,
    stdout_hex: String,
    stderr_hex: String,
}

fn receipt(bytes: &[u8], executable: &[u8], input: &[u8], runtime: &str) -> Result<GuestReceipt> {
    if bytes.is_empty() || bytes.len() as u64 >= MAX_OUTPUT {
        return Err("generated receipt exceeds bound".into());
    }
    let value: GuestReceipt = serde_json::from_slice(bytes)?;
    if value.schema_version != 1
        || value.runtime_sha256 != runtime
        || value.executable_sha256 != io::digest(executable)
        || value.input_sha256 != io::digest(input)
        || !match value.execution_status.as_str() {
            "exit" => (0..=255).contains(&value.execution_value),
            "signal" => (1..=64).contains(&value.execution_value),
            _ => false,
        }
    {
        return Err("generated receipt does not bind the admitted guest inputs/runtime".into());
    }
    unhex(&value.stdout_hex, OUTPUT_STREAM)?;
    unhex(&value.stderr_hex, OUTPUT_STREAM)?;
    Ok(value)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: crate::resources::Token,
    guest: Guest,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Guest {
    Elf(GuestReceipt),
    Build(build::Receipt),
}

fn request_profile(bytes: &[u8]) -> Result<String> {
    if parse_input(bytes).is_ok() {
        Ok(format!("{PREFIX}{}", io::digest(bytes)))
    } else {
        build::parse(bytes)?;
        Ok(format!("{BUILD_PREFIX}{}", io::digest(bytes)))
    }
}

fn profile_runtime(profile: &str) -> Result<String> {
    source_digest(profile)?;
    if profile.starts_with(BUILD_PREFIX) {
        build::runtime_digest()
    } else {
        runtime_digest()
    }
}

fn checked_guest(profile: &str, encoded: &[u8], bytes: &[u8], runtime: &str) -> Result<Guest> {
    if profile.starts_with(BUILD_PREFIX) {
        Ok(Guest::Build(build::receipt(encoded, bytes, runtime)?))
    } else {
        let (_, executable, input) = parse_input(bytes)?;
        Ok(Guest::Elf(receipt(encoded, &executable, &input, runtime)?))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceReceipt {
    binding: String,
    output_sha256: String,
    output_domain_epochs: std::collections::BTreeMap<String, crate::resources::OutputEpoch>,
    lease: crate::resources::Token,
    state: crate::resources::State,
    physical_release_granted: bool,
}

fn verify_resource_receipt(output: &Output, value: serde_json::Value) -> Result<()> {
    let receipt: ResourceReceipt = serde_json::from_value(value)?;
    if receipt.binding != output.binding
        || receipt.lease != output.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(&output.guest)?)
        || receipt.physical_release_granted
        || receipt
            .output_domain_epochs
            .keys()
            .map(String::as_str)
            .ne(resource_manager::invoice_output_domains())
        || receipt
            .output_domain_epochs
            .values()
            .any(|epoch| epoch.0 == 0)
    {
        return Err("generated result lacks exact committed physical-domain provenance".into());
    }
    // Drainage is not reconstructed here. All terminal/active states must keep
    // the same immutable output proof; the root broker alone observes release.
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}

pub(crate) fn worker(profile: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let expected = source_digest(profile)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
    {
        return Err("generated worker requires the fixed enforcing helper pool".into());
    }
    let lease = resource_manager::WorkerLease::acquire_acquisition(profile, Path::new("/var"))?;
    lease.check()?;
    if unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS {
        return Err("generated request descriptor is not sealed".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if io::digest(&bytes) != expected {
        return Err("generated worker request differs from lease".into());
    }
    if request_profile(&bytes)? != profile {
        return Err("generated request schema differs from its admitted profile".into());
    }
    let runtime = profile_runtime(profile)?;
    let exact_binding = binding(
        profile,
        &resource_manager::storage_device(Path::new("/var"))?,
    )?;
    let mut output = anonymous("luma-generated-output", &[], false)?;
    let mut command = Command::new("/usr/bin/python3");
    let held_input;
    if profile.starts_with(BUILD_PREFIX) {
        let request = anonymous("luma-generated-request", &bytes, true)?;
        command
            .args([
                "-I",
                "/usr/libexec/luma-os/generated_build.py",
                "--request-fd",
                "0",
            ])
            .stdin(Stdio::from(request));
        held_input = None;
    } else {
        let (_, executable, input) = parse_input(&bytes)?;
        let elf = anonymous("luma-generated-executable", &executable, true)?;
        let stdin = anonymous("luma-generated-input", &input, true)?;
        let input_fd = stdin.as_raw_fd();
        command
            .args([
                "-I",
                "/usr/libexec/luma-os/generated_runtime.py",
                "--executable-fd",
                "0",
                "--input-fd",
                "3",
            ])
            .stdin(Stdio::from(elf));
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(input_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        held_input = Some(stdin);
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::null());
    let deadline = resource_manager::now()?
        .checked_add(20_000)
        .ok_or("generated worker deadline overflow")?;
    model::supervise_owned_controller(&mut command, || {
        lease.check()?;
        if resource_manager::now()? >= deadline
            || output.metadata()?.len() >= MAX_OUTPUT
            || profile_runtime(profile)? != runtime
        {
            return Err("generated runtime lost its finite resource fence".into());
        }
        Ok(())
    })?;
    drop(held_input);
    lease.check()?;
    output.seek(SeekFrom::Start(0))?;
    let mut encoded = Vec::new();
    output.take(MAX_OUTPUT + 1).read_to_end(&mut encoded)?;
    let guest = checked_guest(profile, &encoded, &bytes, &runtime)?;
    let guest_bytes = serde_json::to_vec(&guest)?;
    lease.complete_output(&io::digest(&guest_bytes))?;
    lease.check_local()?;
    let encoded_output = serde_json::to_vec(&Output {
        schema_version: 1,
        request_sha256: expected.into(),
        binding: exact_binding,
        lease: lease.token().clone(),
        guest,
    })?;
    if encoded_output.len() as u64 >= MAX_OUTPUT {
        return Err("whole generated result exceeds the admitted response bound".into());
    }
    std::io::stdout().lock().write_all(&encoded_output)?;
    Ok(())
}

/// Broker reconstruction uses the exact source identity and a conservative
/// fixed input peak, not a caller-supplied byte count or serialized grant.
pub(crate) fn acquisition_usage(profile: &str) -> Result<finite_grants::Use> {
    source_digest(profile)?;
    Ok(finite_grants::Use {
        action: finite_grants::Action::ExecuteGenerated,
        selector: finite_grants::Selector {
            kind: finite_grants::Kind::GeneratedCode,
            id: if profile.starts_with(BUILD_PREFIX) {
                build::LANGUAGE
            } else {
                "static-amd64-kvm-v1"
            }
            .into(),
            generation: 1,
            digest: binding(
                profile,
                &resource_manager::storage_device(Path::new("/var"))?,
            )?,
        },
        input_bytes: if profile.starts_with(BUILD_PREFIX) {
            build::MAX_REQUEST
        } else {
            MAX_REQUEST
        } as u64,
        output_bytes: MAX_OUTPUT,
        units: 1,
    })
}

fn usage(bytes: &[u8]) -> Result<finite_grants::Use> {
    acquisition_usage(&request_profile(bytes)?)
}

fn request_namespace_shape(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let Some(name) = value
        .strip_prefix("/run/luma-granted-client/requests/")
        .and_then(|value| value.strip_suffix("/generated.json"))
    else {
        return false;
    };
    name.len() == 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The broker reads only the launcher's bounded inert private snapshot. This
/// verifies data identity; the separate live PAM challenge supplies authority.
pub(crate) fn verify_client_request(path: &Path, profile: &str) -> Result<()> {
    let expected = source_digest(profile)?;
    if !request_namespace_shape(path) {
        return Err("generated admission requires the fixed private launcher snapshot".into());
    }
    let mut parents = Vec::new();
    let mut parent = path.parent();
    while let Some(at) = parent {
        let metadata = std::fs::symlink_metadata(at)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("generated snapshot namespace is not protected".into());
        }
        if at.starts_with("/run/luma-granted-client") && metadata.mode() & 0o7777 != 0o700 {
            return Err("generated snapshot namespace is not private".into());
        }
        parents.push((at, metadata.dev(), metadata.ino(), metadata.mode()));
        parent = at.parent();
    }
    let initial = std::fs::symlink_metadata(path)?;
    if !initial.is_file()
        || initial.uid() != 0
        || initial.gid() != 0
        || initial.nlink() != 1
        || initial.mode() & 0o7777 != 0o400
    {
        return Err("generated snapshot is not exact private regular data".into());
    }
    let bytes = read_request(
        path.to_str()
            .ok_or("generated snapshot path is not UTF-8")?,
    )?;
    let final_file = std::fs::symlink_metadata(path)?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if identity(&initial) != identity(&final_file) || io::digest(&bytes) != expected {
        return Err("generated snapshot differs from the admitted exact request".into());
    }
    for (at, device, inode, mode) in parents {
        let current = std::fs::symlink_metadata(at)?;
        if !current.is_dir()
            || current.uid() != 0
            || current.gid() != 0
            || (current.dev(), current.ino(), current.mode()) != (device, inode, mode)
        {
            return Err("generated snapshot parent was substituted".into());
        }
    }
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    match args.first().map(String::as_str) {
        Some("generated-resource-worker") if args.len() == 2 => worker(&args[1]),
        Some("generated-review") if args.len() == 2 => {
            let bytes = read_request(&args[1])?;
            println!("{}", serde_json::to_string(&usage(&bytes)?)?);
            Ok(())
        }
        Some("generated-execute") if args.len() == 4 => {
            let bytes = read_request(&args[3])?;
            let scope = usage(&bytes)?;
            crate::admin_governance::with_grant(&args[1], &args[2], &scope, |guard| {
                let expected_binding = scope.selector.digest.clone();
                let profile = request_profile(&bytes)?;
                acquisition::await_drainage()?;
                guard.check()?;
                let pending = guard.effect_begin(
                    &io::digest(&bytes),
                    crate::policy_decisions::EffectKind::GeneratedExecution,
                )?;
                // The original nonserializable PAM boundary remains on this
                // thread. The broker's pinned challenge connection joins it
                // to the exact worker lease; loss revokes and drains the held
                // cgroup generation, not merely the systemd-run process.
                let encoded = crate::service::granted_acquisition::run_generated(
                    &profile,
                    &scope,
                    guard,
                    |check| {
                        check()?;
                        let input = anonymous("luma-generated-request", &bytes, true)?;
                        let mut output = anonymous("luma-generated-output", &[], false)?;
                        let mut command = Command::new("/usr/bin/systemd-run");
                        command
                            .args(acquisition::arguments(
                                Path::new("/var"),
                                &profile,
                                "generated",
                            )?)
                            .env_clear()
                            .env("PATH", "/usr/bin")
                            .env("LC_ALL", "C")
                            .stdin(Stdio::from(input))
                            .stdout(Stdio::from(output.try_clone()?))
                            .stderr(Stdio::null());
                        let deadline = resource_manager::now()?
                            .checked_add(40_000)
                            .ok_or("generated controller deadline overflow")?;
                        model::supervise_owned_controller(&mut command, || {
                            check()?;
                            if resource_manager::now()? >= deadline
                                || output.metadata()?.len() >= MAX_OUTPUT
                                || usage(&bytes)?.selector != scope.selector
                            {
                                return Err(
                                    "generated controller authority/input fence lost".into()
                                );
                            }
                            Ok(())
                        })?;
                        acquisition::await_drainage()?;
                        check()?;
                        output.seek(SeekFrom::Start(0))?;
                        let mut encoded = Vec::new();
                        output.take(MAX_OUTPUT + 1).read_to_end(&mut encoded)?;
                        if encoded.len() as u64 >= MAX_OUTPUT {
                            return Err("generated output exceeds controller bound".into());
                        }
                        Ok(encoded)
                    },
                )?;
                guard.check()?;
                let output: Output = serde_json::from_slice(&encoded)?;
                checked_guest(
                    &profile,
                    &serde_json::to_vec(&output.guest)?,
                    &bytes,
                    &profile_runtime(&profile)?,
                )?;
                if output.schema_version != 1
                    || output.binding != expected_binding
                    || output.request_sha256 != io::digest(&bytes)
                    || !crate::workflow_resource::token_valid(&output.lease)
                {
                    return Err("generated result lacks exact request/resource provenance".into());
                }
                let mut request = resource_manager::request("resource-output-receipt")?;
                request.lease = Some(output.lease.clone());
                let value = crate::service::resource_exchange(&request)?
                    .status
                    .ok_or("generated output receipt missing")?;
                verify_resource_receipt(&output, value)?;
                guard.effect_complete(pending, &io::digest(&encoded))?;
                guard.check()?;
                println!("{}", serde_json::to_string(&output)?);
                Ok(())
            })
        }
        _ => Err(
            "generated commands accept only exact reviewed requests and current finite grants"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_profile_routing_accepts_only_closed_versioned_digest_names() {
        for prefix in [PREFIX, BUILD_PREFIX] {
            assert!(is_profile(&format!("{prefix}{}", "a".repeat(64))));
            for suffix in [
                "a".repeat(63),
                "a".repeat(65),
                "A".repeat(64),
                format!("{}x", "a".repeat(63)),
                format!("{}/extra", "a".repeat(64)),
            ] {
                assert!(!is_profile(&format!("{prefix}{suffix}")));
            }
        }
        for prefix in [
            "generated-",
            "generated-v2-",
            "generated-build-",
            "generated-build-v2-",
            "xgenerated-v1-",
        ] {
            assert!(!is_profile(&format!("{prefix}{}", "a".repeat(64))));
        }
    }
    #[test]
    fn reviewed_schema_selects_exact_separate_build_profile_before_grant_admission() {
        let raw = input();
        assert_eq!(
            request_profile(&raw).unwrap(),
            format!("{PREFIX}{}", io::digest(&raw))
        );
        let build = serde_json::json!({"schema_version": 2, "language": "c99-freestanding-tcc-v1",
            "declared_dependencies": ["luma-syscall-v1", "tinycc-libtcc1-0.9.27+git20200814.62c30a4a-1"],
            "source_hex": crate::bundle::hex(b"int main(void){return 0;}"),
            "tests": [{"stdin_hex":"", "expected_exit":0, "expected_stdout_hex":"", "expected_stderr_hex":""}]});
        // Deserialize into the closed type, then serialize its canonical order.
        let build: build::Request = serde_json::from_value(build).unwrap();
        let encoded = serde_json::to_vec(&build).unwrap();
        let profile = request_profile(&encoded).unwrap();
        assert_eq!(profile, format!("{BUILD_PREFIX}{}", io::digest(&encoded)));
        assert!(is_profile(&profile));
        assert_ne!(profile, format!("{PREFIX}{}", io::digest(&encoded)));
        assert!(request_profile(br#"{"schema_version":3}"#).is_err());
    }
    #[test]
    fn generated_live_admission_uses_only_the_launchers_private_snapshot_namespace() {
        let valid = format!(
            "/run/luma-granted-client/requests/{}/generated.json",
            "a".repeat(32)
        );
        assert!(request_namespace_shape(Path::new(&valid)));
        for wrong in [
            "/tmp/generated.json".into(),
            valid.replace("generated.json", "input.json"),
            valid.replace(&"a".repeat(32), &"A".repeat(32)),
            valid.replace(&"a".repeat(32), "short"),
            format!("{valid}/"),
            valid.replace("/requests/", "/requests/../requests/"),
            valid.replace("/generated.json", "/nested/generated.json"),
        ] {
            assert!(!request_namespace_shape(Path::new(&wrong)));
            assert!(verify_client_request(
                Path::new(&wrong),
                &format!("{PREFIX}{}", "a".repeat(64))
            )
            .is_err());
        }
        assert_eq!(MAX_REQUEST, 2_228_480);
    }
    fn input() -> Vec<u8> {
        let mut executable = vec![0; 64];
        executable[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        executable[16] = 2;
        executable[18] = 62;
        serde_json::to_vec(&Input {
            schema_version: 1,
            executable_hex: crate::bundle::hex(&executable),
            stdin_hex: String::new(),
        })
        .unwrap()
    }
    #[test]
    fn request_is_data_only_bounded_and_exactly_canonical() {
        let bytes = input();
        assert!(parse_input(&bytes).is_ok());
        let mut changed = bytes.clone();
        changed.push(b'\n');
        assert!(parse_input(&changed).is_err());
        assert!(parse_input(
            br#"{"schema_version":1,"executable_hex":"23212f62696e2f7368","stdin_hex":""}"#
        )
        .is_err());
        assert!(unhex("AA", 1).is_err());
        assert!(unhex("a", 1).is_err());
        assert!(unhex("aa", 0).is_err());
        assert!(source_digest(&format!("{PREFIX}{}", "a".repeat(64))).is_ok());
        assert!(source_digest(&format!("invoice-v1-{}", "a".repeat(64))).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["kernel"] = "/tmp/kernel".into();
        assert!(parse_input(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn guest_output_cannot_claim_a_different_runtime_or_exceed_stream_bounds() {
        let (_, elf, stdin) = parse_input(&input()).unwrap();
        let mut value = GuestReceipt {
            schema_version: 1,
            execution_status: "exit".into(),
            execution_value: 0,
            runtime_sha256: "a".repeat(64),
            executable_sha256: io::digest(&elf),
            input_sha256: io::digest(&stdin),
            stdout_hex: "aa".into(),
            stderr_hex: String::new(),
        };
        assert!(receipt(
            &serde_json::to_vec(&value).unwrap(),
            &elf,
            &stdin,
            &"a".repeat(64)
        )
        .is_ok());
        value.execution_status = "qualified".into();
        assert!(receipt(
            &serde_json::to_vec(&value).unwrap(),
            &elf,
            &stdin,
            &"a".repeat(64)
        )
        .is_err());
        value.execution_status = "signal".into();
        value.execution_value = 0;
        assert!(receipt(
            &serde_json::to_vec(&value).unwrap(),
            &elf,
            &stdin,
            &"a".repeat(64)
        )
        .is_err());
        value.execution_value = 31;
        value.stdout_hex = "aa".repeat(OUTPUT_STREAM + 1);
        assert!(receipt(
            &serde_json::to_vec(&value).unwrap(),
            &elf,
            &stdin,
            &"a".repeat(64)
        )
        .is_err());
    }
    #[test]
    fn generated_selector_never_converts_into_shell_workflow_or_export_authority() {
        let mut scope = finite_grants::Use {
            action: finite_grants::Action::ExecuteGenerated,
            selector: finite_grants::Selector {
                kind: finite_grants::Kind::GeneratedCode,
                id: "static-amd64-kvm-v1".into(),
                generation: 1,
                digest: "a".repeat(64),
            },
            input_bytes: 64,
            output_bytes: MAX_OUTPUT,
            units: 1,
        };
        assert!(scope.validate().is_ok());
        for action in [
            finite_grants::Action::Calculate,
            finite_grants::Action::Execute,
            finite_grants::Action::Export,
            finite_grants::Action::AcquireResource,
            finite_grants::Action::StartWorker,
        ] {
            scope.action = action;
            assert!(scope.validate().is_err());
        }
        scope.action = finite_grants::Action::ExecuteGenerated;
        for kind in [
            finite_grants::Kind::Calculation,
            finite_grants::Kind::Workflow,
            finite_grants::Kind::Resource,
            finite_grants::Kind::Worker,
            finite_grants::Kind::Artifact,
        ] {
            scope.selector.kind = kind;
            assert!(scope.validate().is_err());
        }
    }

    #[test]
    fn generated_receipt_requires_exact_lease_and_all_physical_domains() {
        let (_, elf, stdin) = parse_input(&input()).unwrap();
        let output = Output {
            schema_version: 1,
            request_sha256: io::digest(&input()),
            binding: "b".repeat(64),
            lease: crate::resources::Token {
                lease_id: "generated-test".into(),
                generation: 1,
                manager_epoch: "c".repeat(64),
            },
            guest: Guest::Elf(GuestReceipt {
                schema_version: 1,
                execution_status: "exit".into(),
                execution_value: 0,
                runtime_sha256: "a".repeat(64),
                executable_sha256: io::digest(&elf),
                input_sha256: io::digest(&stdin),
                stdout_hex: String::new(),
                stderr_hex: String::new(),
            }),
        };
        let epochs: std::collections::BTreeMap<_, _> = resource_manager::invoice_output_domains()
            .into_iter()
            .map(|name| (name, crate::resources::OutputEpoch(1)))
            .collect();
        let proof = serde_json::json!({
            "binding": output.binding,
            "output_sha256": io::digest(&serde_json::to_vec(&output.guest).unwrap()),
            "output_domain_epochs": epochs,
            "lease": output.lease,
            "state": "released",
            "physical_release_granted": false
        });
        assert!(verify_resource_receipt(&output, proof.clone()).is_ok());
        for state in ["active", "draining"] {
            let mut changed = proof.clone();
            changed["state"] = state.into();
            assert!(verify_resource_receipt(&output, changed).is_ok());
        }
        for (field, value) in [
            ("binding", serde_json::json!("d".repeat(64))),
            ("output_sha256", serde_json::json!("e".repeat(64))),
            ("physical_release_granted", serde_json::json!(true)),
            ("state", serde_json::json!("unknown")),
        ] {
            let mut changed = proof.clone();
            changed[field] = value;
            assert!(verify_resource_receipt(&output, changed).is_err());
        }
        let mut changed = proof.clone();
        changed["lease"]["generation"] = "2".into();
        assert!(verify_resource_receipt(&output, changed).is_err());
        for domain in resource_manager::invoice_output_domains() {
            let mut missing = proof.clone();
            missing["output_domain_epochs"]
                .as_object_mut()
                .unwrap()
                .remove(domain);
            assert!(verify_resource_receipt(&output, missing).is_err());
            let mut zero = proof.clone();
            zero["output_domain_epochs"][domain] = "0".into();
            assert!(verify_resource_receipt(&output, zero).is_err());
            let mut numeric = proof.clone();
            numeric["output_domain_epochs"][domain] = serde_json::json!(1);
            assert!(verify_resource_receipt(&output, numeric).is_err());
        }
        let mut changed = proof.clone();
        changed["output_domain_epochs"]["invented-domain"] = "1".into();
        assert!(verify_resource_receipt(&output, changed).is_err());
        let mut changed = proof;
        changed["qualification_passed"] = true.into();
        assert!(verify_resource_receipt(&output, changed).is_err());
    }
}
