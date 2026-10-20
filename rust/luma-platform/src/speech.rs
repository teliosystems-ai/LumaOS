//! Explicit offline ASR under an original finite Infer session and the existing
//! serialized acquisition lease. A transcript is reviewed input data, never an
//! effect grant or a grounded interpretation of an ambiguous reference.
use crate::{acquisition, artifacts as io, finite_grants, model, resource_manager, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) const PREFIX: &str = "speech-asr-v1-";
pub(crate) const MAX_REQUEST: usize = model::speech::MAX_AUDIO * 2 + 256;
const MAX_OUTPUT: u64 = 65536;
const WORKER: &str = "/usr/libexec/luma-os/speech/luma-asr-worker";
const MANIFEST: &str = "/usr/share/luma-os/speech/runtime.json";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    profile_id: String,
    pcm_hex: String,
}
fn parse(bytes: &[u8]) -> Result<(Input, Vec<u8>)> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("ASR request exceeds fixed audio bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)
        .map_err(|_| "ASR request is not the exact closed JSON schema")?;
    if input.schema_version != 1
        || input.profile_id != model::speech::ID
        || serde_json::to_vec(&input)? != bytes
        || input.pcm_hex.len() < 6400
        || input.pcm_hex.len() > model::speech::MAX_AUDIO * 2
        || input.pcm_hex.len() % 4 != 0
    {
        return Err("ASR requires exact canonical mono16kHz S16LE auxiliary request".into());
    }
    let mut pcm = Vec::with_capacity(input.pcm_hex.len() / 2);
    for pair in input.pcm_hex.as_bytes().chunks_exact(2) {
        let digit = |v: u8| -> Result<u8> {
            match v {
                b'0'..=b'9' => Ok(v - b'0'),
                b'a'..=b'f' => Ok(v - b'a' + 10),
                _ => Err("ASR PCM requires lowercase hex".into()),
            }
        };
        pcm.push(digit(pair[0])? * 16 + digit(pair[1])?);
    }
    if !pcm.iter().any(|b| *b != 0) {
        return Err(
            "digital silence is not an utterance; no inferred transcript is substituted".into(),
        );
    }
    Ok((input, pcm))
}
pub(crate) fn is_profile(value: &str) -> bool {
    value.strip_prefix(PREFIX).is_some_and(io::hash)
}
pub(crate) fn source_digest(value: &str) -> Result<&str> {
    value
        .strip_prefix(PREFIX)
        .filter(|s| io::hash(s))
        .ok_or_else(|| "ASR profile requires exact closed request digest".into())
}
fn profile(bytes: &[u8]) -> Result<String> {
    parse(bytes)?;
    Ok(format!("{PREFIX}{}", io::digest(bytes)))
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
pub(crate) fn read_request(path: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_REQUEST as u64
    {
        return Err("ASR input must be one bounded regular single-link file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("ASR input changed during exact bounded capture".into());
    }
    profile(&bytes)?;
    Ok(bytes)
}
pub(crate) fn verify_client_request(path: &Path, selected: &str) -> Result<()> {
    source_digest(selected)?;
    let text = path.to_str().ok_or("ASR request path encoding invalid")?;
    let nonce = text
        .strip_prefix("/run/luma-granted-client/requests/")
        .and_then(|s| s.strip_suffix("/speech.json"))
        .ok_or("ASR requires its fixed private launcher snapshot")?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("ASR request namespace is not canonical".into());
    }
    let mut ancestors = Vec::new();
    for at in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || at.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700
        {
            return Err("ASR request namespace is not protected".into());
        }
        ancestors.push((at, identity(&m)));
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o400
    {
        return Err("ASR snapshot is not exact root-private inert data".into());
    }
    if profile(&read_request(text)?)? != selected {
        return Err("ASR original client bytes differ from admitted request".into());
    }
    if identity(&m) != identity(&std::fs::symlink_metadata(path)?)
        || ancestors.iter().any(|(at, key)| {
            std::fs::symlink_metadata(at).map_or(true, |now| identity(&now) != *key)
        })
    {
        return Err("ASR original client namespace changed during capture".into());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    schema_version: u32,
    profile: String,
    runtime_source_commit: String,
    worker_sha256: String,
    engine_source_sha256: String,
    worker_source_sha256: String,
    policy_sha256: String,
    memory_max_bytes: u64,
    maximum_virtual_address_bytes: u64,
    tasks_max: u64,
    maximum_audio_bytes: usize,
    maximum_decoder_tokens: u64,
    maximum_decode_seconds: u64,
}
fn runtime() -> Result<String> {
    let bytes = crate::admin_credentials::public_input(Path::new(MANIFEST), 16384)?;
    let r: Runtime = serde_json::from_slice(&bytes)?;
    let worker = crate::admin_credentials::public_input(Path::new(WORKER), 16 * 1024 * 1024)?;
    let engine_source = crate::admin_credentials::public_input(
        Path::new("/usr/src/luma-speech/controller/asr_engine.cpp"),
        128 * 1024,
    )?;
    let worker_source = crate::admin_credentials::public_input(
        Path::new("/usr/src/luma-speech/controller/asr_worker.cpp"),
        128 * 1024,
    )?;
    validate_runtime(&r, &worker, &engine_source, &worker_source)?;
    Ok(io::digest(&bytes))
}
fn validate_runtime(
    r: &Runtime,
    worker: &[u8],
    engine_source: &[u8],
    worker_source: &[u8],
) -> Result<()> {
    if r.schema_version != 1
        || r.profile != model::speech::ID
        || r.runtime_source_commit != model::speech::SOURCE_COMMIT
        || r.engine_source_sha256 != io::digest(engine_source)
        || r.worker_source_sha256 != io::digest(worker_source)
        || r.worker_sha256 != io::digest(worker)
        || !worker.starts_with(b"\x7fELF\x02\x01\x01")
        || r.policy_sha256 != io::digest(&model::speech::policy()?)
        || r.memory_max_bytes != model::speech::MEMORY
        || r.maximum_virtual_address_bytes != model::speech::MAX_VIRTUAL
        || r.tasks_max != 16
        || r.maximum_audio_bytes != model::speech::MAX_AUDIO
        || r.maximum_decoder_tokens != model::speech::MAX_TOKENS
        || r.maximum_decode_seconds != 18
    {
        return Err("ASR runtime does not bind the closed image-owned CPU decoder".into());
    }
    Ok(())
}
pub(crate) fn binding(selected: &str, device: &str) -> Result<String> {
    source_digest(selected)?;
    let model = model::speech::public_profile()?;
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-auxiliary-asr-request-resource-v1",
        selected,
        model.resource_binding()?,
        runtime()?,
        device,
        model::speech::MAX_AUDIO,
        model::speech::MAX_TOKENS,
    ))?))
}
pub(crate) fn acquisition_usage(selected: &str) -> Result<finite_grants::Use> {
    let usage = finite_grants::Use {
        action: finite_grants::Action::Infer,
        selector: finite_grants::Selector {
            kind: finite_grants::Kind::Model,
            id: model::speech::ID.into(),
            generation: 1,
            digest: binding(
                selected,
                &resource_manager::storage_device(Path::new("/var"))?,
            )?,
        },
        input_bytes: model::speech::MAX_AUDIO as u64,
        output_bytes: MAX_OUTPUT,
        units: model::speech::MAX_TOKENS,
    };
    usage.validate()?;
    Ok(usage)
}
pub(crate) fn current() -> Result<()> {
    crate::admin_governance::current_speech_authority(&model::speech::public_profile()?)
}
pub(crate) fn check_worker(selected: &str, _device: &str, pid: u32) -> Result<()> {
    source_digest(selected)?;
    let mut cmd = Vec::new();
    File::open(Path::new("/proc").join(pid.to_string()).join("cmdline"))?
        .take(4097)
        .read_to_end(&mut cmd)?;
    let expected =
        format!("/usr/libexec/luma-os/luma-platform\0speech-resource-worker\0{selected}\0");
    if cmd != expected.as_bytes() {
        return Err("ASR resource peer lacks exact fixed worker arguments".into());
    }
    runtime()?;
    Ok(())
}
fn anonymous(name: &str, bytes: &[u8], sealed: bool) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    f.seek(SeekFrom::Start(0))?;
    if sealed && unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(f)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    schema_version: u32,
    profile_id: String,
    model_binding: String,
    runtime_sha256: String,
    audio_sha256: String,
    audio_samples: u64,
    decoder_tokens: u64,
    language: String,
    text: String,
    human_review_required: bool,
    automatic_model_handoff: bool,
}
fn transcript(
    frame: &[u8],
    pcm: &[u8],
    model: &model::speech::Profile,
    runtime: &str,
) -> Result<Transcript> {
    let text = std::str::from_utf8(frame)?;
    let (header, text) = text
        .split_once('\n')
        .ok_or("ASR worker returned no exact completion frame")?;
    let fields = header.split(' ').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != "LUMA_ASR_RESULT_V1"
        || fields[1..].iter().any(|f| {
            f.is_empty()
                || !f.bytes().all(|b| b.is_ascii_digit())
                || (f.len() > 1 && f.starts_with('0'))
        })
    {
        return Err("ASR worker completion header is not closed canonical data".into());
    }
    let tokens = fields[1].parse::<u64>()?;
    let samples = fields[2].parse::<u64>()?;
    let bytes = fields[3].parse::<usize>()?;
    if tokens >= model::speech::MAX_TOKENS
        || samples != pcm.len() as u64 / 2
        || bytes != text.len()
        || bytes > model::speech::MAX_TEXT
        || text
            .chars()
            .any(|c| (c < ' ' && c != '\n' && c != '\t') || ('\u{7f}'..='\u{9f}').contains(&c))
    {
        return Err(
            "ASR result is incomplete, exceeds decoder/audio/text bounds or contains controls"
                .into(),
        );
    }
    Ok(Transcript {
        schema_version: 1,
        profile_id: model.id.clone(),
        model_binding: model.resource_binding()?,
        runtime_sha256: runtime.into(),
        audio_sha256: io::digest(pcm),
        audio_samples: samples,
        decoder_tokens: tokens,
        language: "en".into(),
        text: text.into(),
        human_review_required: true,
        automatic_model_handoff: false,
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: crate::resources::Token,
    transcript: Transcript,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalReceipt {
    binding: String,
    output_sha256: String,
    output_domain_epochs: std::collections::BTreeMap<String, crate::resources::OutputEpoch>,
    lease: crate::resources::Token,
    state: crate::resources::State,
    physical_release_granted: bool,
}
fn check_receipt(result: &Output, value: serde_json::Value) -> Result<()> {
    let receipt: PhysicalReceipt = serde_json::from_value(value)?;
    if receipt.binding != result.binding
        || receipt.lease != result.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(&result.transcript)?)
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
        return Err("ASR result lacks exact committed physical-domain provenance".into());
    }
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}

pub(crate) fn worker(selected: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    source_digest(selected)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
        || unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS
    {
        return Err("ASR requires fixed enforcing helper pool and sealed input".into());
    }
    let lease = resource_manager::WorkerLease::acquire_acquisition(selected, Path::new("/var"))?;
    lease.check()?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if profile(&bytes)? != selected {
        return Err("ASR request differs from exact acquired generation".into());
    }
    let (_, pcm) = parse(&bytes)?;
    let model = model::speech::public_profile()?;
    let rt = runtime()?;
    let weight = model::speech::open_weight(&model)?;
    let weight_fd = weight.as_raw_fd();
    let input = anonymous("luma-speech-pcm", &pcm, true)?;
    let mut output = anonymous("luma-speech-runtime-output", &[], false)?;
    let errors = anonymous("luma-speech-runtime-errors", &[], false)?;
    let mut child = Command::new(WORKER);
    child
        .env_clear()
        .env("LUMA_SPEECH_PARENT", std::process::id().to_string())
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(errors.try_clone()?));
    unsafe {
        child.pre_exec(move || {
            if libc::dup2(weight_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for cap in 0..64 {
                let present = libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0);
                if present > 0 && libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if present < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(988, 988, 988) != 0
                || libc::setresuid(988, 988, 988) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let until = resource_manager::now()?
        .checked_add(20_000)
        .ok_or("ASR deadline overflow")?;
    model::supervise_owned_controller(&mut child, || {
        lease.check()?;
        if resource_manager::now()? >= until
            || output.metadata()?.len() > 16384
            || errors.metadata()?.len() > 8192
            || runtime()? != rt
        {
            return Err("ASR worker lost finite execution/runtime fence".into());
        }
        Ok(())
    })?;
    lease.check()?;
    output.seek(SeekFrom::Start(0))?;
    let mut frame = Vec::new();
    output.take(16385).read_to_end(&mut frame)?;
    let result = transcript(&frame, &pcm, &model, &rt)?;
    lease.complete_output(&io::digest(&serde_json::to_vec(&result)?))?;
    lease.check_local()?;
    let response = Output {
        schema_version: 1,
        request_sha256: io::digest(&bytes),
        binding: binding(
            selected,
            &resource_manager::storage_device(Path::new("/var"))?,
        )?,
        lease: lease.token().clone(),
        transcript: result,
    };
    let encoded = serde_json::to_vec(&response)?;
    if encoded.len() as u64 >= MAX_OUTPUT {
        return Err("whole ASR result exceeds response bound".into());
    }
    std::io::stdout().lock().write_all(&encoded)?;
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    match args.first().map(String::as_str) {
        Some("speech-import-resource-worker")
            if args.len() == 2 && args[1] == model::speech::ID =>
        {
            model::speech::import_worker()
        }
        Some("speech-resource-worker") if args.len() == 2 => worker(&args[1]),
        Some("speech-review") if args.len() == 2 => {
            let bytes = read_request(&args[1])?;
            current()?;
            println!(
                "{}",
                serde_json::to_string(&acquisition_usage(&profile(&bytes)?)?)?
            );
            Ok(())
        }
        Some("speech-transcribe") if args.len() == 4 => {
            let bytes = read_request(&args[3])?;
            let selected = profile(&bytes)?;
            let usage = acquisition_usage(&selected)?;
            current()?;
            crate::admin_governance::with_grant(&args[1], &args[2], &usage, |guard| {
                guard.check()?;
                current()?;
                acquisition::await_drainage()?;
                let effect = guard.effect_begin(
                    &io::digest(&bytes),
                    crate::policy_decisions::EffectKind::Inference,
                )?;
                let encoded = crate::service::granted_acquisition::run_speech(
                    &selected,
                    &usage,
                    guard,
                    |check| {
                        let input = anonymous("luma-speech-request", &bytes, true)?;
                        let mut output = anonymous("luma-speech-output", &[], false)?;
                        let mut child = Command::new("/usr/bin/systemd-run");
                        child
                            .args(acquisition::arguments(
                                Path::new("/var"),
                                &selected,
                                "speech",
                            )?)
                            .env_clear()
                            .env("PATH", "/usr/bin")
                            .env("LC_ALL", "C")
                            .stdin(Stdio::from(input))
                            .stdout(Stdio::from(output.try_clone()?))
                            .stderr(Stdio::null());
                        let until = resource_manager::now()?
                            .checked_add(40_000)
                            .ok_or("ASR controller deadline overflow")?;
                        model::supervise_owned_controller(&mut child, || {
                            check()?;
                            if resource_manager::now()? >= until
                                || output.metadata()?.len() >= MAX_OUTPUT
                            {
                                return Err("ASR controller lifetime/output bound exceeded".into());
                            }
                            Ok(())
                        })?;
                        acquisition::await_drainage()?;
                        check()?;
                        output.seek(SeekFrom::Start(0))?;
                        let mut result = Vec::new();
                        output.take(MAX_OUTPUT + 1).read_to_end(&mut result)?;
                        Ok(result)
                    },
                )?;
                guard.check()?;
                current()?;
                if encoded.len() as u64 >= MAX_OUTPUT {
                    return Err("ASR controller output exceeded whole-result bound".into());
                }
                let result: Output = serde_json::from_slice(&encoded)?;
                let (_, pcm) = parse(&bytes)?;
                if result.schema_version != 1
                    || result.request_sha256 != io::digest(&bytes)
                    || result.binding != usage.selector.digest
                    || !crate::workflow_resource::token_valid(&result.lease)
                    || result.transcript.model_binding
                        != model::speech::public_profile()?.resource_binding()?
                    || result.transcript.runtime_sha256 != runtime()?
                    || result.transcript.audio_sha256 != io::digest(&pcm)
                    || result.transcript.audio_samples != pcm.len() as u64 / 2
                    || result.transcript.profile_id != model::speech::ID
                    || result.transcript.schema_version != 1
                    || result.transcript.decoder_tokens >= model::speech::MAX_TOKENS
                    || result.transcript.text.len() > model::speech::MAX_TEXT
                    || result.transcript.text.chars().any(|c| {
                        (c < ' ' && c != '\n' && c != '\t') || ('\u{7f}'..='\u{9f}').contains(&c)
                    })
                    || !result.transcript.human_review_required
                    || result.transcript.automatic_model_handoff
                    || result.transcript.language != "en"
                {
                    return Err("ASR result differs from exact auxiliary input/runtime/generation provenance".into());
                }
                let mut request = resource_manager::request("resource-output-receipt")?;
                request.lease = Some(result.lease.clone());
                let receipt = crate::service::resource_exchange(&request)?
                    .status
                    .ok_or("ASR physical output receipt missing")?;
                check_receipt(&result, receipt)?;
                guard.effect_complete(effect, &io::digest(&encoded))?;
                guard.check()?;
                println!("{}", serde_json::to_string(&result)?);
                Ok(())
            })
        }
        _ => {
            Err("speech accepts only exact bounded requests and a fresh finite Infer grant".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_binds_independent_physical_virtual_and_audio_limits_without_authority() {
        // Inert ELF-prefixed fixture checks the projection only. Actual worker
        // ELF, decoder/resource outcomes and confinement are separate tests.
        let worker = b"\x7fELF\x02\x01\x01 inert projection fixture";
        let engine = b"actual-input-slot-engine";
        let source = b"actual-input-slot-worker";
        let value = serde_json::json!({"schema_version":1,"profile":model::speech::ID,
            "runtime_source_commit":model::speech::SOURCE_COMMIT,"worker_sha256":io::digest(worker),
            "engine_source_sha256":io::digest(engine),"worker_source_sha256":io::digest(source),
            "policy_sha256":io::digest(&model::speech::policy().unwrap()),"memory_max_bytes":536870912u64,
            "maximum_virtual_address_bytes":1073741824u64,"tasks_max":16,"maximum_audio_bytes":960000,
            "maximum_decoder_tokens":128,"maximum_decode_seconds":18});
        validate_runtime(
            &serde_json::from_value(value.clone()).unwrap(),
            worker,
            engine,
            source,
        )
        .unwrap();
        for (field, number) in [
            ("memory_max_bytes", 1073741824u64),
            ("maximum_virtual_address_bytes", 536870912),
            ("tasks_max", 17),
            ("maximum_audio_bytes", 960002),
            ("maximum_decoder_tokens", 129),
            ("maximum_decode_seconds", 19),
        ] {
            let mut changed = value.clone();
            changed[field] = serde_json::json!(number);
            assert!(validate_runtime(
                &serde_json::from_value(changed).unwrap(),
                worker,
                engine,
                source
            )
            .is_err());
        }
        assert!(validate_runtime(
            &serde_json::from_value(value.clone()).unwrap(),
            worker,
            b"changed",
            source
        )
        .is_err());
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("maximum_virtual_address_bytes");
        assert!(serde_json::from_value::<Runtime>(missing).is_err());
        let mut unknown = value;
        unknown["authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Runtime>(unknown).is_err());
    }
    fn input() -> Vec<u8> {
        serde_json::to_vec(&Input {
            schema_version: 1,
            profile_id: model::speech::ID.into(),
            pcm_hex: "0100".repeat(1600),
        })
        .unwrap()
    }
    fn model() -> model::speech::Profile {
        model::speech::Profile {
            id: model::speech::ID.into(),
            binding: model::NativeBinding {
                catalog_sha256: "1".repeat(64),
                profile_sha256: "2".repeat(64),
                manifest_sha256: "3".repeat(64),
                runtime_tuple_sha256: "4".repeat(64),
            },
            memory_bytes: model::speech::MEMORY,
            storage_peak_bytes: 512 * 1024 * 1024,
        }
    }
    #[test]
    fn asr_profile_names_are_closed_before_privileged_routing() {
        assert!(is_profile(&format!("{PREFIX}{}", "a".repeat(64))));
        for name in [
            format!("{PREFIX}{}", "A".repeat(64)),
            format!("{PREFIX}{}", "a".repeat(63)),
            format!("{PREFIX}{}/x", "a".repeat(64)),
            "speech-asr-v2-a".into(),
            model::speech::ID.into(),
        ] {
            assert!(!is_profile(&name));
            assert!(source_digest(&name).is_err());
        }
    }
    #[test]
    fn exact_pcm_request_rejects_noncanonical_metadata_and_digital_silence() {
        let bytes = input();
        let (_, pcm) = parse(&bytes).unwrap();
        assert_eq!(pcm.len(), 3200);
        assert_eq!(
            profile(&bytes).unwrap(),
            format!("{PREFIX}{}", io::digest(&bytes))
        );
        for malformed in [
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("0100", "ABCD"),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("0100", "0000"),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("schema_version\":1", "schema_version\":true"),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("\"pcm_hex\"", "\"other\""),
            format!(" {}", String::from_utf8(bytes).unwrap()),
        ] {
            assert!(parse(malformed.as_bytes()).is_err());
        }
    }
    #[test]
    fn source_audio_cannot_exceed_the_independent_sample_budget() {
        let mut value: Input = serde_json::from_slice(&input()).unwrap();
        value.pcm_hex = "0100".repeat(480000);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() <= MAX_REQUEST);
        assert!(parse(&bytes).is_ok());
        value.pcm_hex.push_str("0100");
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        value.pcm_hex = "0100".repeat(1599);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn actual_worker_frame_never_turns_partial_or_limit_output_into_transcript() {
        let (_, pcm) = parse(&input()).unwrap();
        let p = model();
        let rt = "5".repeat(64);
        let result = transcript(b"LUMA_ASR_RESULT_V1 2 1600 5\nhello", &pcm, &p, &rt).unwrap();
        assert_eq!(result.text, "hello");
        assert_eq!(result.audio_sha256, io::digest(&pcm));
        assert!(result.human_review_required);
        assert!(!result.automatic_model_handoff);
        for frame in [
            b"LUMA_ASR_RESULT_V1 128 1600 5\nhello".as_slice(),
            b"LUMA_ASR_RESULT_V1 02 1600 5\nhello",
            b"LUMA_ASR_RESULT_V1 2 1601 5\nhello",
            b"LUMA_ASR_RESULT_V1 2 1600 5\nhell",
            b"LUMA_ASR_RESULT_V1 2 1600 5\nhe\x1bll",
        ] {
            assert!(transcript(frame, &pcm, &p, &rt).is_err());
        }
    }
    #[test]
    fn whole_escaped_transcript_and_generation_receipt_fit_without_clipping() {
        let (_, pcm) = parse(&input()).unwrap();
        let text = "\t".repeat(8192);
        let frame = format!("LUMA_ASR_RESULT_V1 127 1600 {}\n{text}", text.len());
        let result = Output {
            schema_version: 1,
            request_sha256: "1".repeat(64),
            binding: "2".repeat(64),
            lease: crate::resources::Token {
                lease_id: "3".repeat(32),
                generation: u64::MAX,
                manager_epoch: "4".repeat(32),
            },
            transcript: transcript(frame.as_bytes(), &pcm, &model(), &"5".repeat(64)).unwrap(),
        };
        assert!(serde_json::to_vec(&result).unwrap().len() < MAX_OUTPUT as usize);
        let epochs = resource_manager::invoice_output_domains()
            .into_iter()
            .map(|name| (name.to_string(), serde_json::json!("1")))
            .collect::<serde_json::Map<_, _>>();
        let receipt = serde_json::json!({"binding":result.binding,"output_sha256":io::digest(&serde_json::to_vec(&result.transcript).unwrap()),
            "output_domain_epochs":epochs,"lease":result.lease,"state":"released","physical_release_granted":false});
        check_receipt(&result, receipt.clone()).unwrap();
        for key in ["binding", "output_sha256"] {
            let mut wrong = receipt.clone();
            wrong[key] = serde_json::json!("6".repeat(64));
            assert!(check_receipt(&result, wrong).is_err());
        }
        let mut wrong = receipt.clone();
        wrong["physical_release_granted"] = serde_json::json!(true);
        assert!(check_receipt(&result, wrong).is_err());
        let mut wrong = receipt;
        wrong["output_domain_epochs"] = serde_json::json!({});
        assert!(check_receipt(&result, wrong).is_err());
    }
}
