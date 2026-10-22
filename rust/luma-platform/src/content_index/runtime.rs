//! Original Standard Read controller and fixed resource worker. Effect entry
//! commands are not implemented here or silently treated as readonly queries.
use super::*;
use crate::{admin_governance, resource_manager, resources};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Command, Stdio};
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

fn canonical_data(input: &request::Input) -> Result<serde_json::Value> {
    let bytes = input.canonical_bytes()?;
    Ok(
        serde_json::json!({"schema_version":1,"canonical_request":std::str::from_utf8(&bytes)?,"request_sha256":luma_content::sha256(&bytes),"authority_returned":false,"private_content_read":false,"session_lease_held":false,"effect_executed":false,"actor_authenticated":false}),
    )
}
fn scope_proposal_data(
    input: &request::Input,
    installation: &str,
    storage: &str,
) -> Result<serde_json::Value> {
    if input.binding.installation != installation {
        return Err("scope DATA has inconsistent claimed installation labels".into());
    }
    let profile = input.profile()?;
    read_mode(&profile)?;
    let mut value = canonical_data(input)?;
    let object = value
        .as_object_mut()
        .ok_or("canonical scope DATA is not an object")?;
    object.insert("profile".into(), profile.clone().into());
    object.insert("installation_verified".into(), false.into());
    object.insert("storage_device".into(), storage.into());
    object.insert(
        "usage".into(),
        serde_json::to_value(scope::original_usage(
            &profile,
            storage,
            &input.binding,
            &input.sha256()?,
            true,
        )?)?,
    );
    Ok(value)
}
/// Human-supplied DATA only. No original PAM, owner lookup, private read,
/// resource admission, C selection, grant, effect or current ACL is inferred.
pub(crate) fn pure_request_stdin(scope_proposal: bool) -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let canonical = request::Input::canonicalize(&bytes)?;
    let input = request::Input::parse(&canonical)?;
    let result = if scope_proposal {
        scope_proposal_data(
            &input,
            &input.binding.installation,
            &resource_manager::storage_device(Path::new("/var"))?,
        )?
    } else {
        canonical_data(&input)?
    };
    let mut output = serde_json::to_vec(&result)?;
    output.push(b'\n');
    if output.len() > 128 * 1024 {
        return Err("canonical/scope DATA exceeds fixed public response bound".into());
    }
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: resources::Token,
    selection_sha256: String,
    result: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    binding: String,
    output_sha256: String,
    output_domain_epochs: std::collections::BTreeMap<String, resources::OutputEpoch>,
    lease: resources::Token,
    state: resources::State,
    physical_release_granted: bool,
}

fn read_mode(profile: &str) -> Result<()> {
    if request::parse_profile(profile)?.mode.mutates() {
        return Err("index readonly controller/worker cannot execute effects".into());
    }
    Ok(())
}
fn subject(input: &request::Input, guard: &mut admin_governance::GrantBoundary<'_>) -> Result<()> {
    guard.check()?;
    let (registry, account, installation) = admin_governance::current_principal(&input.login)?;
    registry.current()?;
    if installation != input.binding.installation
        || account.id != input.binding.owner
        || account.generation != input.binding.owner_generation
        || guard.subject()? != account.id
        || guard.subject_generation()? != account.generation
        || guard.subject_uid()? != account.uid
    {
        return Err("index Read does not belong to actual current original human principal".into());
    }
    guard.check()
}
fn anonymous(name: &str, bytes: &[u8], sealed: bool) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if sealed && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err("index fixed private request sealing failed".into());
    }
    Ok(file)
}

fn verify_receipt(response: &Response, profile: &str, value: serde_json::Value) -> Result<()> {
    let selected = request::parse_profile(profile)?;
    let expected = scope::binding(
        profile,
        &resource_manager::storage_device(Path::new("/var"))?,
    )?;
    verify_receipt_data(response, &expected, selected.source, value)
}
fn verify_receipt_data(
    response: &Response,
    expected: &str,
    source: &str,
    value: serde_json::Value,
) -> Result<()> {
    let receipt: Receipt = serde_json::from_value(value)?;
    hash(&response.selection_sha256)?;
    if response.schema_version != 2
        || response.request_sha256 != source
        || response.binding != expected
        || !crate::workflow_resource::token_valid(&response.lease)
        || receipt.lease != response.lease
        || receipt.binding != response.binding
        || receipt.output_sha256 != luma_content::sha256(&serde_json::to_vec(&response.result)?)
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
        return Err(
            "index response has no exact unfenced original physical output generation".into(),
        );
    }
    match receipt.state {
        resources::State::Active | resources::State::Draining | resources::State::Released => {
            Ok(())
        }
    }
}
fn check_response(response: &Response, profile: &str) -> Result<()> {
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(response.lease.clone());
    let value = crate::service::resource_exchange(&request)?
        .status
        .ok_or("index original resource output receipt missing")?;
    verify_receipt(response, profile, value)
}
fn run(
    profile: &str,
    input: &request::Input,
    guard: &mut admin_governance::GrantBoundary<'_>,
) -> Result<Response> {
    read_mode(profile)?;
    let scope = scope::acquisition_usage(profile)?;
    let bytes = input.canonical_bytes()?;
    crate::acquisition::await_drainage()?;
    subject(input, guard)?;
    let encoded =
        crate::service::granted_acquisition::run_index(profile, &scope, guard, |check| {
            check()?;
            let request = anonymous("luma-index-request", &bytes, true)?;
            let mut output = anonymous("luma-index-output", &[], false)?;
            let mut command = Command::new("/usr/bin/systemd-run");
            command
                .args(crate::acquisition::arguments(
                    Path::new("/var"),
                    profile,
                    "index",
                )?)
                .env_clear()
                .env("PATH", "/usr/bin")
                .env("LC_ALL", "C")
                .stdin(Stdio::from(request))
                .stdout(Stdio::from(output.try_clone()?))
                .stderr(Stdio::null());
            crate::model::supervise_owned_controller(&mut command, || {
                check()?;
                if output.metadata()?.len() >= MAX_OUTPUT {
                    return Err(
                        "index private resource output exceeds original finite handoff".into(),
                    );
                }
                Ok(())
            })?;
            crate::acquisition::await_drainage_checked(&mut || check())?;
            check()?;
            output.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            output.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() as u64 >= MAX_OUTPUT {
                return Err("index resource result outside exact private bound".into());
            }
            check()?;
            Ok(bytes)
        })?;
    subject(input, guard)?;
    let response: Response = decode(&encoded, MAX_OUTPUT as usize)?;
    check_response(&response, profile)?;
    subject(input, guard)?;
    Ok(response)
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if args.first().map(String::as_str) == Some("index-resource-worker") && args.len() == 2 {
        return worker(&args[1]);
    }
    if args.len() != 4 || args[0] != "index-review" {
        return Err("expected index-review LOGIN READ-GRANT protected-index.json; effects require their separate genuine C implementation".into());
    }
    if crate::platform::production_image()? {
        crate::platform::require_production_activation()?;
    } else {
        crate::platform::require_laboratory_image()?;
    }
    if !crate::platform::content_checkpoint_required()? {
        return Err(
            "index Read requires independently enrolled C, never laboratory file fallback".into(),
        );
    }
    let input = client::original_input(Path::new(&args[3]), &args[1])?;
    let profile = input.profile()?;
    client::read_snapshot(Path::new(&args[3]), &profile, &args[1])?;
    let usage = scope::acquisition_usage(&profile)?;
    admin_governance::with_grant(&input.login, &args[2], &usage, |guard| {
        subject(&input, guard)?;
        let response = run(&profile, &input, guard)?;
        subject(&input, guard)?;
        let hash = luma_content::sha256(&serde_json::to_vec(&response.result)?);
        let source = input.canonical_bytes()?;
        // Acquire the required original-thread payload BEFORE the C output
        // guard moves delivery into its scoped authenticated child thread.
        let mut output = crate::service::granted_gateway::required_export_writer()?;
        crate::service::content_output::run_index(
            &profile,
            &input.binding,
            &response.lease,
            &hash,
            &response.selection_sha256,
            std::str::from_utf8(&source)?,
            guard,
            |proof| {
                let mut bytes = serde_json::to_vec(&response.result)?;
                bytes.push(b'\n');
                if bytes.len() as u64 >= MAX_OUTPUT {
                    return Err("index result exceeds acknowledged original handoff".into());
                }
                let mut check = || {
                    proof.check()?;
                    check_response(&response, &profile)?;
                    proof.check()
                };
                for chunk in bytes.chunks(4096) {
                    check()?;
                    output.write_checked(chunk, &mut check)?;
                    check()?;
                }
                output.finish_checked(&mut check)?;
                check()
            },
        )?;
        subject(&input, guard)
    })
}

pub(crate) fn response_limit(command: &str, bytes: &[u8]) -> Result<u64> {
    if command != "index-review" {
        return Err("only original readonly index review has a structured reply".into());
    }
    let input = request::Input::parse(bytes)?;
    read_mode(&input.profile()?)?;
    Ok(MAX_OUTPUT)
}

fn worker(profile: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    read_mode(profile)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
    {
        return Err("index worker requires exact fixed enforcing acquisition domain".into());
    }
    client::check_worker(
        profile,
        &resource_manager::storage_device(Path::new("/var"))?,
        std::process::id(),
    )?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(profile, Path::new("/var"))?;
    lease.check()?;
    if unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS {
        return Err("index resource input is not the original sealed private descriptor".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    lease.check()?;
    let input = scope::verify_input(profile, &bytes)?;
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let current = || -> Result<()> {
        lease.check()?;
        let principals = registry.current()?;
        let account = principals
            .account(&input.login)
            .ok_or("index installed local principal unavailable")?;
        // Registry is the installed baseline. Exact projected generation is
        // established only by live broker+C original finite audit; protected
        // journal updates may legitimately advance beyond this baseline.
        if principals.installation() != input.binding.installation
            || account.id != input.binding.owner
            || account.generation > input.binding.owner_generation
            || !account.enabled
        {
            return Err("index input is not the current installed local owner".into());
        }
        lease.check()
    };
    let (selection_sha256, result) = crate::content_checkpoint::custody::indexed_read(
        profile,
        &input.binding,
        lease.token(),
        &bytes,
        &mut || current(),
    )?;
    current()?;
    hash(&selection_sha256)?;
    let result_hash = luma_content::sha256(&serde_json::to_vec(&result)?);
    lease.complete_output(&result_hash)?;
    let response = Response {
        schema_version: 2,
        request_sha256: input.sha256()?,
        binding: scope::binding(
            profile,
            &resource_manager::storage_device(Path::new("/var"))?,
        )?,
        lease: lease.token().clone(),
        selection_sha256,
        result,
    };
    let encoded = serde_json::to_vec(&response)?;
    if encoded.len() as u64 >= MAX_OUTPUT {
        return Err("index resource response exceeds original finite output".into());
    }
    lease.check_local()?;
    std::io::stdout().lock().write_all(&encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests;
