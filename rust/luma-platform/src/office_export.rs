//! Actual fixed Office PDF export under the original Read/Export session.
//! Private sources come only from the exact independently selected C state.
//! No arbitrary Office import, caller-selected converter or plain stdout bypass.
use crate::{artifacts as io, finite_grants as grants, resource_manager, Result};
use luma_content::OwnerBinding;
use luma_content_store::{Access, Boundary, Repository, ResourceBudget, VerifiedState};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[path = "backup_confinement.rs"]
mod confinement;

/// Private closed export drivers. These names never come from a caller path,
/// executable, filter or environment; PDF keeps its original schema/framing.
/// A portable workbook driver is not implemented; `luma_content::workbook`
/// remains a pure data module without a native export command.
#[derive(Clone, Copy)]
enum Driver {
    Pdf,
}
impl Driver {
    fn command(self) -> &'static str {
        match self {
            Self::Pdf => "content-office-export",
        }
    }
    fn leaf(self) -> &'static str {
        match self {
            Self::Pdf => "content-office.json",
        }
    }
}

pub(crate) const PREFIX: &str = "office-export-v1-";
pub(crate) const MAX_REQUEST: usize = 16384;
pub(crate) const MEMORY: u64 = 1024 * 1024 * 1024;
pub(crate) const LOCKED: u64 = 0;
pub(crate) const TASKS: u64 = 32;
const MAX_META: usize = 65536;
const DIRECTORY: &str = "/var/lib/luma-os/content-store";
const READ_ID: &str = "native-content-office-read-v1";
const EXPORT_ID: &str = "native-content-office-export-v1";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const MAGIC: &[u8; 16] = b"LUMAPDFFRAME01!\n";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Review {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub state: VerifiedState,
    pub reference: luma_content::VersionReference,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub html_sha256: String,
    pub adapter_sha256: String,
    pub review_sha256: String,
}
impl Review {
    fn digest(&self) -> Result<String> {
        Ok(io::digest(&serde_json::to_vec(&(
            "luma-fixed-office-export-review-v1",
            self.schema_version,
            &self.binding,
            &self.state,
            &self.reference,
            &self.source_sha256,
            self.source_bytes,
            &self.html_sha256,
            &self.adapter_sha256,
        ))?))
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.state.validate()?;
        if self.schema_version != 1
            || self.state.binding != self.binding
            || self.state.outcome_count == 0
            || self.reference.version == 0
            || self.reference.artifact_id.is_empty()
            || self.reference.artifact_id.len() > 128
            || self.source_bytes == 0
            || self.source_bytes > luma_content::MAX_CONTENT_BYTES as u64
            || [
                &self.reference.content_sha256,
                &self.reference.receipt_sha256,
                &self.source_sha256,
                &self.html_sha256,
                &self.adapter_sha256,
            ]
            .iter()
            .any(|v| !io::hash(v) || v.bytes().all(|b| b == b'0'))
            || self.review_sha256 != self.digest()?
        {
            return Err("invalid exact Office source/adapter/C-state review".into());
        }
        Ok(())
    }
}
fn document(version: &luma_content::ArtifactVersion) -> Result<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(version.content())?;
    let object = value
        .as_object()
        .ok_or("Office source is not an editable managed document")?;
    if object.len() != 3
        || value["schema_version"] != 1
        || value["engine"] != "document"
        || !object.contains_key("source")
    {
        return Err("Office export supports only actual managed document source, not arbitrary Office/HTML imports".into());
    }
    let source = serde_json::to_vec(&value["source"])?;
    Ok(luma_content::document::render(&source)?
        .canonical_source
        .into_bytes())
}
pub(crate) fn review(
    version: &luma_content::ArtifactVersion,
    state: &VerifiedState,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Review> {
    check()?;
    state.validate()?;
    if version.receipt().binding != state.binding {
        return Err("Office review owner differs from independently selected C cut".into());
    }
    let source = document(version)?;
    let rendered = luma_content::document::render(&source)?;
    let mut review = Review {
        schema_version: 1,
        binding: state.binding.clone(),
        state: state.clone(),
        reference: version.reference()?,
        source_sha256: io::digest(&source),
        source_bytes: source.len() as u64,
        html_sha256: rendered.html_sha256,
        adapter_sha256: crate::office_adapter::installed(check)?,
        review_sha256: String::new(),
    };
    review.review_sha256 = review.digest()?;
    review.validate()?;
    check()?;
    Ok(review)
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    login: String,
    binding: OwnerBinding,
    review: Review,
}
impl Input {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.review.validate()?;
        if self.schema_version != 1
            || self.review.binding != self.binding
            || self.login.is_empty()
            || self.login.len() > 32
            || !self.login.as_bytes()[0].is_ascii_lowercase()
            || !self
                .login
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err("invalid closed original-owner Office export request".into());
        }
        Ok(())
    }
}
fn parse(bytes: &[u8], exact: bool) -> Result<Input> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("Office request exceeds fixed bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    input.validate()?;
    if exact && serde_json::to_vec(&input)? != bytes {
        return Err("Office request is not exact canonical transport".into());
    }
    Ok(input)
}

pub(crate) fn prepare_stdin() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let canonical = serde_json::to_vec(&parse(&bytes, false)?)?;
    if canonical.len() > MAX_REQUEST {
        return Err("canonical Office request exceeds fixed bound".into());
    }
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"result":{"operation":"office-request","canonical_request":String::from_utf8(canonical.clone())?,
        "request_sha256":io::digest(&canonical),"private_content_read":false},"owner_authenticated":false,
        "authority_returned":false,"committed":false,"certified":false,"gate_closing":false})
    );
    Ok(())
}

pub(crate) fn read_request(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_request_data(path)?;
    parse(&bytes, true)?;
    Ok(bytes)
}
fn read_request_data(path: &Path) -> Result<Vec<u8>> {
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
        return Err("office request must be bounded single-link regular data".into());
    }
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("office request changed during bounded capture".into());
    }
    Ok(bytes)
}

pub(crate) fn parse_profile(id: &str) -> Result<(u64, u64, &str)> {
    let suffix = id
        .strip_prefix(PREFIX)
        .ok_or("unknown office export profile")?;
    let mut fields = suffix.split('-');
    let generation = fields.next().ok_or("missing office generation")?;
    let archive = fields.next().ok_or("missing office byte count")?;
    let sha = fields.next().ok_or("missing office request digest")?;
    let number: u64 = generation.parse()?;
    let bytes: u64 = archive.parse()?;
    if number == 0
        || number.to_string() != generation
        || !io::hash(sha)
        || fields.next().is_some()
        || bytes == 0
        || bytes > luma_content::MAX_CONTENT_BYTES as u64
        || bytes.to_string() != archive
    {
        return Err("invalid exact office export profile".into());
    }
    Ok((number, bytes, sha))
}

pub(crate) fn source_digest(id: &str) -> Result<&str> {
    Ok(parse_profile(id)?.2)
}

fn profile(input: &Input, bytes: &[u8]) -> Result<String> {
    let id = format!(
        "{PREFIX}{}-{}-{}",
        input.binding.owner_generation,
        input.review.source_bytes,
        io::digest(bytes)
    );
    parse_profile(&id)?;
    Ok(id)
}

pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    parse_profile(id)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("invalid office storage identity")?;
    if major == "0"
        || [major, minor]
            .iter()
            .any(|s| s.parse::<u32>().map_or(true, |v| v.to_string() != *s))
    {
        return Err("office requires canonical installed block storage".into());
    }
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-native-content-office-export-v1",
        io::installation()?,
        id,
        device,
    ))?))
}

pub(crate) fn uses_at(
    generation: u64,
    archive_bytes: u64,
    digest: &str,
) -> Result<[grants::Use; 2]> {
    let read = grants::Use {
        action: grants::Action::Read,
        selector: grants::Selector {
            kind: grants::Kind::File,
            id: READ_ID.into(),
            generation,
            digest: digest.into(),
        },
        input_bytes: archive_bytes,
        output_bytes: 8192,
        units: 1,
    };
    let export = grants::Use {
        action: grants::Action::Export,
        selector: grants::Selector {
            kind: grants::Kind::Artifact,
            id: EXPORT_ID.into(),
            ..read.selector.clone()
        },
        input_bytes: archive_bytes,
        output_bytes: crate::office_adapter::MAX_PDF as u64,
        units: 1,
    };
    read.validate()?;
    export.validate()?;
    Ok([read, export])
}

/// Only a complete distinct Read/Export pair with the same exact request
/// binding can enter this purpose-specific controller. No subset is authority.
pub(crate) fn pair(uses: &[(String, grants::Use)], requested: &grants::Use) -> Result<usize> {
    if uses.len() != 2 || uses[0].0 == uses[1].0 {
        return Err("office requires independent Read/Export grants".into());
    }
    let reader = uses
        .iter()
        .position(|(_, u)| {
            u.action == grants::Action::Read
                && u.selector.kind == grants::Kind::File
                && u.selector.id == READ_ID
        })
        .ok_or("office exact Read grant absent")?;
    let exporter = 1 - reader;
    let r = &uses[reader].1;
    let e = &uses[exporter].1;
    for (grant, usage) in uses {
        if !crate::admin_roles::identifier(grant) {
            return Err("invalid office grant ID".into());
        }
        usage.validate()?;
    }
    if e.action != grants::Action::Export
        || e.selector.kind != grants::Kind::Artifact
        || e.selector.id != EXPORT_ID
        || e.selector.generation != r.selector.generation
        || e.selector.digest != r.selector.digest
        || e.input_bytes != r.input_bytes
        || r.input_bytes == 0
        || r.input_bytes > luma_content::MAX_CONTENT_BYTES as u64
        || r.output_bytes != 8192
        || e.output_bytes != crate::office_adapter::MAX_PDF as u64
        || r.units != 1
        || e.units != 1
        || requested != e
    {
        return Err("office acquisition differs from its complete exact Read/Export pair".into());
    }
    Ok(exporter)
}

pub(crate) fn export_pair(
    uses: &[(String, grants::Use)],
    requested: &grants::Use,
    purpose: crate::authentication::SessionPurpose,
) -> Result<usize> {
    if purpose != crate::authentication::SessionPurpose::Export {
        return Err("office Read/Export pair requires its original Export-only session".into());
    }
    pair(uses, requested)
}

pub(crate) fn acquisition_usage(id: &str) -> Result<grants::Use> {
    let (generation, archive_bytes, _) = parse_profile(id)?;
    let digest = binding(id, &resource_manager::storage_device(Path::new("/var"))?)?;
    Ok(uses_at(generation, archive_bytes, &digest)?[1].clone())
}

fn snapshot_path(path: &Path) -> bool {
    driver_snapshot_path(path, Driver::Pdf)
}
fn driver_snapshot_path(path: &Path, driver: Driver) -> bool {
    let suffix = format!("/{}", driver.leaf());
    path.to_str()
        .and_then(|p| p.strip_prefix("/run/luma-granted-client/requests/"))
        .and_then(|p| p.strip_suffix(suffix.as_str()))
        .is_some_and(|p| {
            p.len() == 32
                && p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub(crate) fn check_client_arguments(
    args: &[&str],
    id: &str,
    audit: Option<&grants::Audit>,
) -> Result<()> {
    let (generation, archive_bytes, sha) = parse_profile(id)?;
    let bytes = original_request_data(args, Driver::Pdf)?;
    let input = parse(&bytes, true)?;
    if io::digest(&bytes) != sha
        || input.login != args[2]
        || input.binding.owner_generation != generation
        || input.review.source_bytes != archive_bytes
    {
        return Err("office original command differs from exact admitted source".into());
    }
    if let Some(audit) = audit {
        audit.validate()?;
        if audit.subject != input.binding.owner
            || audit.subject_generation != generation
            || audit.grant_id != args[4]
            || audit.usage != acquisition_usage(id)?
        {
            return Err("office proof substitutes its exact current owner or Export scope".into());
        }
    }
    Ok(())
}
fn original_request_data(args: &[&str], driver: Driver) -> Result<Vec<u8>> {
    if args.len() != 9
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != driver.command()
        || !args[8].is_empty()
        || args[6] != "--export-channel"
        || args[3] == args[4]
        || !crate::admin_roles::identifier(args[3])
        || !crate::admin_roles::identifier(args[4])
        || !driver_snapshot_path(Path::new(args[5]), driver)
    {
        return Err(
            "office proof lacks exact original export command and independent grants".into(),
        );
    }
    let relay = Path::new(args[7]);
    let relay_parent = relay
        .parent()
        .ok_or("office original relay parent absent")?;
    if relay.file_name().and_then(|part| part.to_str()) != Some("output.sock")
        || relay_parent.parent() != Some(Path::new("/run/luma-granted-client/payloads"))
    {
        return Err("office proof lacks its exact original binary relay namespace".into());
    }
    crate::tpm::decode::<16>(
        relay_parent
            .file_name()
            .and_then(|part| part.to_str())
            .ok_or("office relay identity absent")?,
    )?;
    for directory in [Path::new("/run/luma-granted-client/payloads"), relay_parent] {
        crate::tpm::private_directory(directory)?;
    }
    use std::os::unix::fs::FileTypeExt;
    let relay_meta = std::fs::symlink_metadata(relay)?;
    if !relay_meta.file_type().is_socket()
        || relay_meta.uid() != 0
        || relay_meta.gid() != 0
        || relay_meta.nlink() != 1
        || relay_meta.mode() & 0o7777 != 0o600
    {
        return Err("office original binary relay inode is unsafe".into());
    }
    for parent in Path::new(args[5])
        .parent()
        .ok_or("missing office snapshot parent")?
        .ancestors()
    {
        let m = std::fs::symlink_metadata(parent)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || (parent.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700)
        {
            return Err("office proof snapshot namespace is not protected".into());
        }
    }
    let m = std::fs::symlink_metadata(args[5])?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o400
    {
        return Err("office proof snapshot is not immutable private input".into());
    }
    read_request_data(Path::new(args[5]))
}

pub(crate) fn check_worker(id: &str, device: &str, pid: u32) -> Result<()> {
    parse_profile(id)?;
    if pid == 0 || device != resource_manager::storage_device(Path::new("/var"))? {
        return Err("office worker storage identity differs".into());
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/cmdline"))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes
        != format!("/usr/libexec/luma-os/luma-platform\0content-office-resource-worker\0{id}\0")
            .as_bytes()
    {
        return Err("office worker command is not its exact fixed profile".into());
    }
    Ok(())
}

struct Live<'a> {
    input: &'a Input,
    registry: crate::principal::RegistryBinding,
    account: crate::principal::Principal,
    lease: &'a resource_manager::WorkerLease,
    confinement: confinement::KernelUnix,
    profile: &'a str,
}
impl Live<'_> {
    fn check(&self, binding: &OwnerBinding) -> Result<()> {
        self.confinement.check()?;
        if binding != &self.input.binding
            || self.account.id != binding.owner
            || self.account.generation > binding.owner_generation
            || !self.account.enabled
        {
            return Err("office current principal/generation differs".into());
        }
        self.registry.current()?;
        self.lease.check()?;
        if crate::content_checkpoint::custody::selected(self.profile, binding, self.lease.token())?
            != self.input.review.state
        {
            return Err("Office protected source state changed".into());
        }
        Ok(())
    }
}
struct Reader<'a>(&'a Live<'a>);
impl Boundary for Reader<'_> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("office Read exceeds its separately admitted store baseline".into());
        }
        self.0.check(binding)
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } => self.0.check(binding),
            _ => Err("office Read cannot mutate or retire content".into()),
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: crate::resources::Token,
    review_sha256: String,
    conversion: crate::office_adapter::ConversionReceipt,
}

fn worker(id: &str) -> Result<()> {
    let confinement = confinement::KernelUnix::capture()?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-office-export (enforce)\n"
        || unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS
    {
        return Err("office worker lacks its fixed confinement or sealed request".into());
    }
    check_worker(
        id,
        &resource_manager::storage_device(Path::new("/var"))?,
        std::process::id(),
    )?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(id, Path::new("/var"))?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let input = parse(&bytes, true)?;
    if profile(&input, &bytes)? != id {
        return Err("office sealed request differs from exact admission".into());
    }
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let account = registry
        .current()?
        .account(&input.login)
        .ok_or("office principal missing")?
        .clone();
    if registry.current()?.installation() != input.binding.installation {
        return Err("office installation differs from original current principal".into());
    }
    let live = Live {
        input: &input,
        registry,
        account,
        lease: &lease,
        confinement,
        profile: id,
    };
    live.check(&input.binding)?;
    let selected = crate::content_checkpoint::custody::selected(id, &input.binding, lease.token())?;
    if selected != input.review.state {
        return Err("Office exact protected source cut changed".into());
    }
    let mut repository =
        Repository::open_at(Path::new(DIRECTORY), &input.binding, &mut Reader(&live))?;
    repository.require_state(&selected, &mut Reader(&live))?;
    let version = repository.historical(&input.review.reference, &mut Reader(&live))?;
    let actual = review(&version, &selected, &mut || live.check(&input.binding))?;
    if actual != input.review {
        return Err(
            "Office private document or installed adapter differs from reviewed export".into(),
        );
    }
    let source = document(&version)?;
    let converted =
        crate::office_adapter::convert(&source, &input.review.adapter_sha256, &mut || {
            live.check(&input.binding)
        })?;
    let metadata = Metadata {
        schema_version: 1,
        request_sha256: io::digest(&bytes),
        binding: binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        lease: lease.token().clone(),
        review_sha256: input.review.review_sha256.clone(),
        conversion: converted.receipt,
    };
    let meta = serde_json::to_vec(&metadata)?;
    if meta.len() > MAX_META {
        return Err("office bounded PDF commitment metadata exceeds bound".into());
    }
    lease.complete_output(&io::digest(&meta))?;
    let mut output = std::io::stdout().lock();
    live.check(&input.binding)?;
    output.write_all(MAGIC)?;
    output.write_all(&(meta.len() as u32).to_be_bytes())?;
    output.write_all(&meta)?;
    for chunk in converted.bytes.chunks(32768) {
        live.check(&input.binding)?;
        output.write_all(chunk)?;
    }
    output.flush()?;
    live.check(&input.binding)
}

fn memory_file(name: &str, bytes: &[u8], sealed: bool) -> Result<File> {
    let name = CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    if sealed && unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

struct Captured {
    file: File,
    metadata: Metadata,
    at: u64,
}

fn capture(
    mut file: File,
    input: &Input,
    id: &str,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Captured> {
    check()?;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if file.metadata()?.len() > (20 + MAX_META + crate::office_adapter::MAX_PDF) as u64 {
        return Err("office worker output exceeds fixed PDF bytes bound".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("office worker output has wrong fixed framing".into());
    }
    let mut length = [0u8; 4];
    file.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_META {
        return Err("office worker commitment exceeds fixed bound".into());
    }
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)?;
    let metadata: Metadata = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&metadata)? != bytes {
        return Err("office worker metadata is not exact canonical data".into());
    }
    validate_metadata(
        &metadata,
        input,
        id,
        &binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
    )?;
    let at = 20 + length as u64;
    if file.metadata()?.len() != at + metadata.conversion.pdf_bytes {
        return Err("office PDF bytes length differs".into());
    }
    let mut hash = sha2::Sha256::new();
    use sha2::Digest;
    let mut block = [0u8; 32768];
    loop {
        check()?;
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        hash.update(&block[..count]);
    }
    if crate::bundle::hex(&hash.finalize()) != metadata.conversion.pdf_sha256 {
        return Err("office PDF bytes digest differs".into());
    }
    file.seek(SeekFrom::Start(at))?;
    check()?;
    Ok(Captured { file, metadata, at })
}

fn validate_metadata(
    metadata: &Metadata,
    input: &Input,
    id: &str,
    expected_binding: &str,
) -> Result<()> {
    let converted = &metadata.conversion;
    if metadata.schema_version != 1
        || metadata.request_sha256 != source_digest(id)?
        || metadata.binding != expected_binding
        || !crate::workflow_resource::token_valid(&metadata.lease)
        || metadata.review_sha256 != input.review.review_sha256
        || converted.schema_version != 1
        || converted.profile != "libreoffice-document-html-pdf-v1"
        || converted.adapter_sha256 != input.review.adapter_sha256
        || converted.document_source_sha256 != input.review.source_sha256
        || converted.html_sha256 != input.review.html_sha256
        || converted.pdf_bytes < 16
        || converted.pdf_bytes > crate::office_adapter::MAX_PDF as u64
        || converted.converter_exit_code != 0
        || !io::hash(&converted.pdf_sha256)
    {
        return Err(
            "Office actual output substitutes exact source, adapter, execution or admitted lease"
                .into(),
        );
    }
    Ok(())
}

fn verify_receipt(metadata: &Metadata) -> Result<()> {
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(metadata.lease.clone());
    let receipt = crate::service::resource_exchange(&request)?
        .status
        .ok_or("office resource receipt missing")?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt {
        binding: String,
        output_sha256: String,
        output_domain_epochs: std::collections::BTreeMap<String, crate::resources::OutputEpoch>,
        lease: crate::resources::Token,
        state: crate::resources::State,
        physical_release_granted: bool,
    }
    let receipt: Receipt = serde_json::from_value(receipt)?;
    if !crate::workflow_resource::token_valid(&metadata.lease)
        || receipt.binding != metadata.binding
        || receipt.lease != metadata.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(metadata)?)
        || receipt.physical_release_granted
        || receipt
            .output_domain_epochs
            .keys()
            .map(String::as_str)
            .ne(resource_manager::invoice_output_domains())
        || receipt.output_domain_epochs.values().any(|v| v.0 == 0)
    {
        return Err(
            "office PDF bytes has no matching unfenced current output-generation receipt".into(),
        );
    }
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}

fn subject(
    input: &Input,
    guard: &mut crate::admin_governance::GrantBoundary<'_>,
    pending: Option<&crate::policy_decisions::PendingEffect>,
) -> Result<()> {
    current_export_subject(&input.login, &input.binding, guard, pending)
}
fn current_export_subject(
    login: &str,
    binding: &OwnerBinding,
    guard: &mut crate::admin_governance::GrantBoundary<'_>,
    pending: Option<&crate::policy_decisions::PendingEffect>,
) -> Result<()> {
    match pending {
        Some(pending) => guard.stream_check(pending)?,
        None => guard.check()?,
    }
    if guard.session_purpose() != crate::authentication::SessionPurpose::Export
        || guard.subject()? != binding.owner
        || guard.subject_generation()? != binding.owner_generation
    {
        return Err("office current original Export principal changed".into());
    }
    let (registry, account, installation) = crate::admin_governance::current_principal(login)?;
    registry.current()?;
    if installation != binding.installation
        || account.id != binding.owner
        || account.generation != binding.owner_generation
        || !account.enabled
        || account.uid != guard.subject_uid()?
    {
        return Err("office installed current principal differs".into());
    }
    match pending {
        Some(pending) => guard.stream_check(pending),
        None => guard.check(),
    }
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    if args.first().map(String::as_str) == Some("content-office-resource-worker") && args.len() == 2
    {
        return worker(&args[1]);
    }
    let proposal = args.first().map(String::as_str) == Some("content-office-export-proposal")
        && args.len() == 3;
    let export =
        args.first().map(String::as_str) == Some("content-office-export") && args.len() == 5;
    if !proposal && !export {
        return Err("expected content-office-export-proposal LOGIN REQUEST | content-office-export LOGIN READ-GRANT EXPORT-GRANT REQUEST".into());
    }
    let bytes = read_request(Path::new(args.last().ok_or("office request absent")?))?;
    let input = parse(&bytes, true)?;
    if input.login != args[1] {
        return Err("office command login differs from request".into());
    }
    let id = profile(&input, &bytes)?;
    let digest = binding(&id, &resource_manager::storage_device(Path::new("/var"))?)?;
    let uses = uses_at(
        input.binding.owner_generation,
        input.review.source_bytes,
        &digest,
    )?;
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"request_sha256":source_digest(&id)?,"read_usage":uses[0],
            "export_usage":uses[1],"review_sha256":input.review.review_sha256,
            "review_verified_against_current_private_history":false,
            "owner_authenticated":false,"private_content_read":false,"grant_issued":false,"archive_delivered":false,"restore_permitted":false})
        );
        return Ok(());
    }
    if !snapshot_path(Path::new(&args[4])) {
        return Err("office export requires its original private launcher snapshot".into());
    }
    let uses = [
        (args[2].clone(), uses[0].clone()),
        (args[3].clone(), uses[1].clone()),
    ];
    crate::admin_governance::with_office_export_grants(&input.login, &uses, |guard| {
        subject(&input, guard, None)?;
        let pending = guard.effect_begin(
            source_digest(&id)?,
            crate::policy_decisions::EffectKind::ArtifactExport,
        )?;
        resource_manager::storage_device(Path::new("/var"))?;
        crate::acquisition::await_drainage_checked(&mut || subject(&input, guard, Some(&pending)))?;
        let mut captured = crate::service::granted_acquisition::run_office(
            &id,
            &uses[1].1,
            guard,
            &pending,
            |check| {
                check()?;
                let request = memory_file("luma-content-office-request", &bytes, true)?;
                let output = memory_file("luma-content-office-output", &[], false)?;
                let mut command = Command::new("/usr/bin/systemd-run");
                command
                    .args(crate::acquisition::arguments(
                        Path::new("/var"),
                        &id,
                        "office-export",
                    )?)
                    .env_clear()
                    .env("PATH", "/usr/bin")
                    .env("LANG", "C")
                    .env("LC_ALL", "C")
                    .stdin(Stdio::from(request))
                    .stdout(Stdio::from(output.try_clone()?))
                    .stderr(Stdio::null());
                let deadline = Instant::now() + Duration::from_secs(1800);
                // The owned pidfd reaps this controller only. On refusal the live
                // original-client socket closes and the broker revokes/kills the
                // attached exact worker lease; never stop a recycled unit by name.
                crate::model::supervise_owned_controller(&mut command, || {
                    check()?;
                    if Instant::now() >= deadline
                        || output.metadata()?.len()
                            > (20 + MAX_META + crate::office_adapter::MAX_PDF) as u64
                    {
                        return Err(
                            "office controller output/deadline bound lost; no drainage claim"
                                .into(),
                        );
                    }
                    Ok(())
                })?;
                crate::acquisition::await_drainage_checked(&mut || check())?;
                capture(output, &input, &id, check)
            },
        )?;
        subject(&input, guard, Some(&pending))?;
        verify_receipt(&captured.metadata)?;
        let mut output = crate::service::granted_gateway::required_export_writer()?;
        captured.file.seek(SeekFrom::Start(captured.at))?;
        let mut block = [0u8; 32768];
        loop {
            subject(&input, guard, Some(&pending))?;
            verify_receipt(&captured.metadata)?;
            let count = captured.file.read(&mut block)?;
            if count == 0 {
                break;
            }
            output.write_checked(&block[..count], &mut || {
                subject(&input, guard, Some(&pending))?;
                verify_receipt(&captured.metadata)
            })?;
        }
        output.finish_checked(&mut || {
            subject(&input, guard, Some(&pending))?;
            verify_receipt(&captured.metadata)
        })?;
        subject(&input, guard, Some(&pending))?;
        verify_receipt(&captured.metadata)?;
        guard.effect_complete(
            pending,
            &io::digest(&serde_json::to_vec(&captured.metadata)?),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        let binding = OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 7,
        };
        let mut state = VerifiedState::empty(&binding).unwrap();
        state.outcome_count = 1;
        state.head_sha256 = "c".repeat(64);
        let mut review = Review {
            schema_version: 1,
            binding: binding.clone(),
            state,
            reference: luma_content::VersionReference {
                artifact_id: "document".into(),
                version: 1,
                content_sha256: "d".repeat(64),
                receipt_sha256: "e".repeat(64),
            },
            source_sha256: "f".repeat(64),
            source_bytes: 42,
            html_sha256: "1".repeat(64),
            adapter_sha256: "2".repeat(64),
            review_sha256: String::new(),
        };
        review.review_sha256 = review.digest().unwrap();
        Input {
            schema_version: 1,
            login: "human".into(),
            binding,
            review,
        }
    }
    #[test]
    fn office_request_profile_is_closed_canonical_and_exactly_bound() {
        let input = fixture();
        let bytes = serde_json::to_vec(&input).unwrap();
        parse(&bytes, true).unwrap();
        let id = profile(&input, &bytes).unwrap();
        assert_eq!(
            parse_profile(&id).unwrap(),
            (7, 42, io::digest(&bytes).as_str())
        );
        for wrong in [
            id.replace("v1-", "v2-"),
            id.replace("-7-", "-07-"),
            id.replace("-42-", "-0-"),
            format!("{id}-extra"),
        ] {
            assert!(parse_profile(&wrong).is_err());
        }
        let mut value = serde_json::to_value(&input).unwrap();
        value["executable"] = "/bin/sh".into();
        assert!(parse(&serde_json::to_vec(&value).unwrap(), false).is_err());
        let mut changed = input.clone();
        changed.review.adapter_sha256 = "3".repeat(64);
        assert!(changed.validate().is_err());
        changed.review.review_sha256 = changed.review.digest().unwrap();
        changed.validate().unwrap();
        assert_ne!(
            profile(&changed, &serde_json::to_vec(&changed).unwrap()).unwrap(),
            id
        );
    }
    #[test]
    fn office_needs_both_finite_scopes_and_original_export_purpose() {
        let usage = uses_at(7, 42, &"a".repeat(64)).unwrap();
        let pair = [
            ("read-office".into(), usage[0].clone()),
            ("export-office".into(), usage[1].clone()),
        ];
        assert_eq!(
            export_pair(
                &pair,
                &usage[1],
                crate::authentication::SessionPurpose::Export
            )
            .unwrap(),
            1
        );
        assert!(export_pair(
            &pair,
            &usage[1],
            crate::authentication::SessionPurpose::Standard
        )
        .is_err());
        assert!(self::pair(&pair[..1], &usage[1]).is_err());
        for field in 0..6 {
            let mut changed = pair.clone();
            match field {
                0 => changed[1].0 = changed[0].0.clone(),
                1 => changed[1].1.selector.id = "native-content-backup-export-v1".into(),
                2 => changed[1].1.selector.generation += 1,
                3 => changed[0].1.selector.digest = "b".repeat(64),
                4 => changed[1].1.output_bytes += 1,
                _ => changed[1].1.units += 1,
            }
            assert!(self::pair(&changed, &changed[1].1).is_err());
        }
    }
    #[test]
    fn office_output_metadata_binds_actual_converter_source_and_lease_without_authority_flags() {
        let input = fixture();
        let id = profile(&input, &serde_json::to_vec(&input).unwrap()).unwrap();
        let binding = "8".repeat(64);
        let value = Metadata {
            schema_version: 1,
            request_sha256: source_digest(&id).unwrap().into(),
            binding: binding.clone(),
            lease: crate::resources::Token {
                manager_epoch: "ab".repeat(16),
                lease_id: "cd".repeat(16),
                generation: 1,
            },
            review_sha256: input.review.review_sha256.clone(),
            conversion: crate::office_adapter::ConversionReceipt {
                schema_version: 1,
                profile: "libreoffice-document-html-pdf-v1".into(),
                adapter_sha256: input.review.adapter_sha256.clone(),
                document_source_sha256: input.review.source_sha256.clone(),
                html_sha256: input.review.html_sha256.clone(),
                pdf_sha256: "7".repeat(64),
                pdf_bytes: 100,
                converter_exit_code: 0,
            },
        };
        validate_metadata(&value, &input, &id, &binding).unwrap();
        let encoded = serde_json::to_value(&value).unwrap();
        for field in [
            "authority_returned",
            "production_qualified",
            "native_qualified",
            "sender_authenticated",
        ] {
            assert!(encoded.get(field).is_none());
        }
        for field in ["adapter_sha256", "document_source_sha256", "html_sha256"] {
            let mut changed = encoded.clone();
            changed["conversion"][field] = "9".repeat(64).into();
            assert!(validate_metadata(
                &serde_json::from_value(changed).unwrap(),
                &input,
                &id,
                &binding
            )
            .is_err());
        }
        let mut changed = encoded;
        changed["conversion"]["converter_exit_code"] = 1.into();
        assert!(validate_metadata(
            &serde_json::from_value(changed).unwrap(),
            &input,
            &id,
            &binding
        )
        .is_err());
    }
}
