//! Bounded original-session editing. Drafts and checkpoints are data, never
//! transferable Read, resource, publication or resume authority.
use crate::{artifacts as io, finite_grants, resource_manager, Result};
use luma_content::{document, OwnerBinding, VersionReference};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

mod controller;
mod protocol;
mod worker;

pub(crate) const PREFIX: &str = "editor-v1-";
pub(crate) const MAX_REQUEST: usize = 32768;
const MAX_DOCUMENT: usize = 16384;
const MAX_COMMANDS: u32 = 64;
const MAX_FINAL_OUTPUT: usize = 65536;
const MAX_WIRE_INPUT: usize = (MAX_REQUEST + 4) * (MAX_COMMANDS as usize + 1);
const MAX_WIRE_OUTPUT: usize = (protocol::MAX_FRAME + 4) * (MAX_COMMANDS as usize + 1);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartRequest {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub session_id: String,
    pub checkpoint_artifact_id: String,
    pub document: document::Source,
    pub resume: Option<VersionReference>,
}
fn identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn reference(value: &VersionReference) -> Result<()> {
    if !identifier(&value.artifact_id)
        || value.version == 0
        || !io::hash(&value.content_sha256)
        || value.content_sha256 == "0".repeat(64)
        || !io::hash(&value.receipt_sha256)
        || value.receipt_sha256 == "0".repeat(64)
    {
        return Err("editor checkpoint reference is invalid".into());
    }
    Ok(())
}
fn source(value: &document::Source) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_DOCUMENT {
        return Err("editor source exceeds fixed memory-only draft bound".into());
    }
    document::render(&bytes)?;
    Ok(bytes)
}
impl StartRequest {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        crate::tpm::decode::<16>(&self.session_id)?;
        if self.session_id != self.session_id.to_ascii_lowercase()
            || self.session_id == "0".repeat(32)
        {
            return Err("editor requires canonical nonzero session identity".into());
        }
        if self.schema_version != 1 || !identifier(&self.checkpoint_artifact_id) {
            return Err("editor requires exact typed session/checkpoint identity".into());
        }
        source(&self.document)?;
        if let Some(expected) = &self.resume {
            reference(expected)?;
            if expected.artifact_id != self.checkpoint_artifact_id {
                return Err("resume checkpoint identity differs".into());
            }
        }
        Ok(())
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<StartRequest> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("editor request exceeds fixed bound".into());
    }
    let value: StartRequest = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(
            "editor requires exact canonical closed JSON, without duplicate/alias fields".into(),
        );
    }
    value.validate()?;
    Ok(value)
}
fn profile(bytes: &[u8]) -> Result<String> {
    parse(bytes)?;
    Ok(format!("{PREFIX}{}", io::digest(bytes)))
}
pub(crate) fn is_profile(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(io::hash)
}
pub(crate) fn source_digest(id: &str) -> Result<&str> {
    id.strip_prefix(PREFIX)
        .filter(|s| io::hash(s))
        .ok_or_else(|| "editor profile lacks exact request digest".into())
}
pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    source_digest(id)?;
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-native-editor-resource-v1",
        id,
        device,
        MAX_DOCUMENT,
        MAX_COMMANDS,
        MAX_WIRE_INPUT,
        MAX_WIRE_OUTPUT,
        MAX_FINAL_OUTPUT,
        30_000u64,
    ))?))
}
pub(crate) fn acquisition_usage(id: &str) -> Result<finite_grants::Use> {
    let usage = finite_grants::Use {
        action: finite_grants::Action::StartWorker,
        selector: finite_grants::Selector {
            kind: finite_grants::Kind::Worker,
            id: "native-editor-session-v1".into(),
            generation: 1,
            digest: binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        },
        input_bytes: MAX_WIRE_INPUT as u64,
        output_bytes: MAX_WIRE_OUTPUT as u64,
        units: MAX_COMMANDS as u64,
    };
    usage.validate()?;
    Ok(usage)
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
pub(crate) fn read_request(path: &Path) -> Result<Vec<u8>> {
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
        return Err("editor input must be bounded regular single-link data".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("editor request changed during capture".into());
    }
    parse(&bytes)?;
    Ok(bytes)
}
pub(crate) fn verify_client_request(path: &Path, id: &str) -> Result<()> {
    source_digest(id)?;
    let text = path.to_str().ok_or("editor request path encoding")?;
    let nonce = text
        .strip_prefix("/run/luma-granted-client/requests/")
        .and_then(|s| s.strip_suffix("/editor.json"))
        .ok_or("editor requires fixed private launcher snapshot")?;
    crate::tpm::decode::<16>(nonce)?;
    let mut pins = Vec::new();
    for at in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || at.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700
        {
            return Err("editor input namespace is not protected".into());
        }
        pins.push((at, identity(&m)));
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o400
        || profile(&read_request(path)?)? != id
    {
        return Err("editor launcher snapshot differs from admission".into());
    }
    if identity(&m) != identity(&std::fs::symlink_metadata(path)?)
        || pins
            .iter()
            .any(|(at, pin)| std::fs::symlink_metadata(at).map_or(true, |m| identity(&m) != *pin))
    {
        return Err("editor snapshot namespace changed".into());
    }
    Ok(())
}
pub(crate) fn check_worker(id: &str, _device: &str, pid: u32) -> Result<()> {
    source_digest(id)?;
    let mut args = Vec::new();
    File::open(Path::new("/proc").join(pid.to_string()).join("cmdline"))?
        .take(4097)
        .read_to_end(&mut args)?;
    if args
        != format!("/usr/libexec/luma-os/luma-platform\0editor-resource-worker\0{id}\0").as_bytes()
    {
        return Err("editor requires fixed exact resource-worker arguments".into());
    }
    Ok(())
}
fn original_arguments<'a>(args: &'a [&str]) -> Result<&'a str> {
    if args.len() != 7
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != "editor-run"
        || args[2].is_empty()
        || args[2].len() > 32
        || !crate::admin_roles::identifier(args[3])
        || !args[6].is_empty()
    {
        return Err("editor proof requires exact original fixed client arguments".into());
    }
    Ok(args[5])
}
pub(crate) fn check_client_arguments(
    args: &[&str],
    selected: &str,
    audit: Option<&finite_grants::Audit>,
) -> Result<()> {
    let path = Path::new(original_arguments(args)?);
    verify_client_request(path, selected)?;
    let request = parse(&read_request(path)?)?;
    if request.resume.is_some() {
        if !crate::admin_roles::identifier(args[4]) {
            return Err("resumed editor requires a separate Read grant identity".into());
        }
    } else if args[4] != "none" {
        return Err("new editor cannot borrow Read grant position".into());
    }
    if audit.is_some_and(|value| {
        value.subject != request.binding.owner
            || value.subject_generation != request.binding.owner_generation
            || value.grant_id != args[3]
            || acquisition_usage(selected).map_or(true, |usage| value.usage != usage)
    }) {
        return Err("editor Start grant is not the exact original admission scope/owner".into());
    }
    Ok(())
}
pub(crate) fn check_checkpoint_client_arguments(
    args: &[&str],
    selected: &str,
    audit: Option<&finite_grants::Audit>,
) -> Result<()> {
    let path = Path::new(original_arguments(args)?);
    let bytes = read_request(path)?;
    let editor = profile(&bytes)?;
    verify_client_request(path, &editor)?;
    let request = parse(&bytes)?;
    let expected = request
        .resume
        .as_ref()
        .ok_or("new editor has no checkpoint Read authority")?;
    let query =
        crate::content_governed::editor_checkpoint_input(args[2], &request.binding, expected)?;
    let query_profile = crate::content_governed::editor_checkpoint_profile(&query)?;
    let derived = path.with_file_name("content.json");
    if crate::content_governed::verify_client_request(&derived, &query_profile, args[2])?
        != request.binding
    {
        return Err("editor checkpoint owner differs from original Read selection".into());
    }
    if selected != query_profile
        || crate::content_governed::read_request(&derived)? != query
        || !crate::admin_roles::identifier(args[4])
        || audit.is_some_and(|value| {
            value.grant_id != args[4]
                || crate::content_governed::acquisition_usage(&query_profile)
                    .map_or(true, |usage| value.usage != usage)
        })
    {
        return Err(
            "editor checkpoint Read differs from independently authorized exact original snapshot"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub schema_version: u32,
    pub profile: String,
    pub binding: OwnerBinding,
    pub document: document::Source,
    pub source_sha256: String,
    pub previous_checkpoint: Option<VersionReference>,
}
impl Checkpoint {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(&serde_json::to_value(self)?)?)
    }
    fn new(request: &StartRequest, document: document::Source) -> Result<Self> {
        let source_sha256 = io::digest(&source(&document)?);
        Ok(Self {
            schema_version: 1,
            profile: "luma-editor-document-v1".into(),
            binding: request.binding.clone(),
            document,
            source_sha256,
            previous_checkpoint: request.resume.clone(),
        })
    }
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.profile != "luma-editor-document-v1"
            || self.source_sha256 != io::digest(&source(&self.document)?)
        {
            return Err("editor checkpoint does not bind exact typed source".into());
        }
        if let Some(expected) = &self.previous_checkpoint {
            reference(expected)?;
        }
        Ok(())
    }
}

/// Validate already-read DATA only. The production caller must first obtain
/// the exact current version through the independent C/fresh Read ceremony.
fn validate_reopened_checkpoint(
    version: &luma_content::ArtifactVersion,
    request: &StartRequest,
) -> Result<Checkpoint> {
    request.validate()?;
    let expected = request
        .resume
        .as_ref()
        .ok_or("new editor source has no resumed checkpoint reference")?;
    if version.receipt().format != luma_content::Format::Json
        || version.receipt().binding != request.binding
        || version.reference()? != *expected
    {
        return Err("editor resume requires exact JSON checkpoint owner/reference, not another content format".into());
    }
    let checkpoint: Checkpoint = serde_json::from_slice(version.content())?;
    checkpoint.validate()?;
    if checkpoint.binding != request.binding
        || checkpoint.document != request.document
        || checkpoint.canonical_bytes()? != version.content()
    {
        return Err(
            "freshly read current checkpoint differs from explicitly selected editor source".into(),
        );
    }
    Ok(checkpoint)
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    controller::command(args)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointProposal {
    schema_version: u32,
    login: String,
    request_id: String,
    start: StartRequest,
    frozen: worker::Frozen,
}
pub(crate) fn prepare(command: &str, bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.is_empty() || bytes.len() > MAX_FINAL_OUTPUT + MAX_REQUEST + 1024 {
        return Err("editor pure proposal input exceeds its fixed bound".into());
    }
    let canonical = match command {
        "editor-request" => {
            if bytes.len() > MAX_REQUEST {
                return Err("editor start request exceeds bound".into());
            }
            let request: StartRequest = serde_json::from_slice(bytes)?;
            request.validate()?;
            serde_json::to_vec(&request)?
        }
        "editor-checkpoint-request" => {
            let proposal: CheckpointProposal = serde_json::from_slice(bytes)?;
            proposal.start.validate()?;
            proposal.frozen.checkpoint.validate()?;
            let start_bytes = serde_json::to_vec(&proposal.start)?;
            if proposal.schema_version != 1
                || !identifier(&proposal.request_id)
                || proposal.frozen.schema_version != 1
                || proposal.frozen.saved
                || proposal.frozen.request_sha256 != io::digest(&start_bytes)
                || proposal.frozen.checkpoint.binding != proposal.start.binding
                || proposal.frozen.checkpoint.previous_checkpoint != proposal.start.resume
                || !io::hash(&proposal.frozen.binding)
                || !crate::workflow_resource::token_valid(&proposal.frozen.lease)
            {
                return Err("editor checkpoint proposal substitutes typed source/binding/base; no receipt is authority".into());
            }
            let content = String::from_utf8(proposal.frozen.checkpoint.canonical_bytes()?)?;
            let workflow = io::digest(&serde_json::to_vec(&(
                "luma-explicit-editor-checkpoint-proposal-v1",
                &proposal.start,
                &proposal.request_id,
                &proposal.frozen.checkpoint,
            ))?);
            let provenance = luma_content::Provenance {
                request_id: proposal.request_id,
                workflow_sha256: workflow,
                source_sha256: io::digest(content.as_bytes()),
                origin: luma_content::EditOrigin::External,
            };
            let operation = if let Some(expected) = proposal.start.resume {
                serde_json::json!({"kind":"external","artifact_id":proposal.start.checkpoint_artifact_id,"expected":expected,"content":content,"provenance":provenance})
            } else {
                serde_json::json!({"kind":"capture","artifact_id":proposal.start.checkpoint_artifact_id,"format":"json","content":content,"provenance":provenance})
            };
            crate::content_governed::canonical_request(&serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"login":proposal.login,"binding":proposal.start.binding,"operation":operation}),
            )?)?
        }
        _ => {
            return Err(
                "editor pure preparation only accepts closed start/checkpoint proposals".into(),
            )
        }
    };
    Ok(
        serde_json::json!({"schema_version":1,"request_sha256":io::digest(&canonical),"canonical_request":String::from_utf8(canonical)?,"authority_returned":false,"session_lease_held":false,"saved":false}),
    )
}
pub(crate) fn stdin(command: &str) -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_FINAL_OUTPUT + MAX_REQUEST + 1025) as u64)
        .read_to_end(&mut bytes)?;
    println!("{}", prepare(command, &bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests;
