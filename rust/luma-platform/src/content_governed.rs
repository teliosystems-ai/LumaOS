//! Native content publication joined to the original PAM client's live grants,
//! protected UTC and broker-owned acquisition generation. Stored plans, source
//! documents and callback return values are never independent authority.
use crate::{artifacts as io, finite_grants as grants, resource_manager, Result};
use luma_content::{Format, OwnerBinding, Provenance, VersionReference};
use luma_content_store::{Access, Boundary, DecisionKind, Plan, Repository, ResourceBudget};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/content-store";
pub(crate) const MAX_REQUEST: usize = 16 * 1024 * 1024 + 32768;
const MAX_OUTPUT: u64 = 65536;
const MAX_STORAGE: u64 = 24 * 1024 * 1024;
const PREFIX: &str = "content-v1-";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    login: String,
    binding: OwnerBinding,
    operation: Operation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Capture {
        artifact_id: String,
        format: Format,
        content: String,
        provenance: Provenance,
    },
    External {
        artifact_id: String,
        expected: VersionReference,
        content: String,
        provenance: Provenance,
    },
    Table {
        request: luma_content::table::TableEditRequest,
    },
}

impl Input {
    fn source(&self) -> Result<Vec<u8>> {
        Ok(match &self.operation {
            Operation::Capture { content, .. } | Operation::External { content, .. } => {
                if content.len() > luma_content::MAX_CONTENT_BYTES {
                    return Err("native content source exceeds its format bound".into());
                }
                content.as_bytes().to_vec()
            }
            Operation::Table { request } => request.canonical_bytes()?,
        })
    }
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.login.is_empty()
            || self.login.len() > 32
            || !self.login.as_bytes()[0].is_ascii_lowercase()
            || !self
                .login
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err("invalid native content schema or human login".into());
        }
        self.source()?;
        if let Operation::Capture {
            artifact_id,
            format,
            content,
            provenance,
        } = &self.operation
        {
            Plan::capture(
                self.binding.clone(),
                artifact_id,
                *format,
                content.as_bytes(),
                provenance.clone(),
            )?;
        }
        if let Operation::External {
            artifact_id,
            expected,
            content,
            provenance,
        } = &self.operation
        {
            // Validate the untrusted source and descriptive metadata before any
            // PAM prompt; only the leased private base can validate its version.
            if expected.artifact_id != *artifact_id
                || expected.version == 0
                || !io::hash(&expected.content_sha256)
                || !io::hash(&expected.receipt_sha256)
                || provenance.origin != luma_content::EditOrigin::External
            {
                return Err("invalid external content base or origin".into());
            }
            // The stored format is private until leased inspection. JSON can
            // contain standalone CR whitespace that plain text forbids, so do
            // not assume text here. Preserve exact source/provenance validation
            // against the closed supported formats; the repository later
            // validates against the actual immutable format.
            if ![Format::Utf8Text, Format::Json, Format::Csv]
                .into_iter()
                .any(|format| {
                    Plan::capture(
                        self.binding.clone(),
                        artifact_id,
                        format,
                        content.as_bytes(),
                        provenance.clone(),
                    )
                    .is_ok()
                })
            {
                return Err(
                    "external source or provenance is invalid for every supported format".into(),
                );
            }
        }
        if let Operation::Table { request } = &self.operation {
            if request.binding != self.binding {
                return Err("managed table request substitutes the admitted owner binding".into());
            }
        }
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<Input> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("native content request exceeds its exact bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    input.validate()?;
    if serde_json::to_vec(&input)? != bytes {
        return Err("native content request must use its exact canonical schema".into());
    }
    Ok(input)
}

/// Pure transport preparation for an untrusted client. No installed paths,
/// principal registry, policy authority or resource broker are consulted.
pub(crate) fn canonical_request(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("native content request exceeds its exact bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    input.validate()?;
    let canonical = serde_json::to_vec(&input)?;
    if canonical.len() > MAX_REQUEST {
        return Err("canonical native content request exceeds its bound".into());
    }
    Ok(canonical)
}

/// Inert, bounded capture performed by the launcher before PAM or private IO.
pub(crate) fn read_request(path: &Path) -> Result<Vec<u8>> {
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
        return Err("native content request must be bounded regular single-link data".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("native content request changed during capture".into());
    }
    parse(&bytes)?;
    Ok(bytes)
}

fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Read,
    Write,
    Retain,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Retain => "retain",
        }
    }
    fn decision(decision: DecisionKind) -> Self {
        match decision {
            DecisionKind::Published => Self::Write,
            DecisionKind::ConflictRetained | DecisionKind::NoChangeRetained => Self::Retain,
        }
    }
}

struct Profile<'a> {
    mode: Mode,
    generation: u64,
    source: &'a str,
    review: &'a str,
}
fn profile(value: &str) -> Result<Profile<'_>> {
    let mut parts = value
        .strip_prefix(PREFIX)
        .ok_or("unknown native content profile")?
        .split('-');
    let mode = match parts.next() {
        Some("read") => Mode::Read,
        Some("write") => Mode::Write,
        Some("retain") => Mode::Retain,
        _ => return Err("unknown native content effect mode".into()),
    };
    let generation = parts.next().ok_or("missing native content generation")?;
    let number: u64 = generation.parse()?;
    let source = parts
        .next()
        .ok_or("missing native content source identity")?;
    let review = parts
        .next()
        .ok_or("missing native content review identity")?;
    if number == 0
        || number.to_string() != generation
        || !io::hash(source)
        || !io::hash(review)
        || parts.next().is_some()
        || (mode == Mode::Read && source != review)
    {
        return Err("invalid native content profile binding".into());
    }
    Ok(Profile {
        mode,
        generation: number,
        source,
        review,
    })
}

pub(crate) fn source_digest(value: &str) -> Result<&str> {
    Ok(profile(value)?.source)
}
fn profile_id(mode: Mode, input: &Input, bytes: &[u8], review: &str) -> Result<String> {
    let id = format!(
        "{PREFIX}{}-{}-{}-{review}",
        mode.name(),
        input.binding.owner_generation,
        io::digest(bytes)
    );
    profile(&id)?;
    Ok(id)
}

pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    profile(id)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("invalid native content storage identity")?;
    if major == "0"
        || [major, minor]
            .iter()
            .any(|part| part.parse::<u32>().map_or(true, |n| n.to_string() != *part))
    {
        return Err("native content requires the fixed installed block-backed storage".into());
    }
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-native-content-acquisition-v1",
        io::installation()?,
        id,
        device,
    ))?))
}

fn usage_at(id: &str, digest: String, inspect: bool) -> Result<grants::Use> {
    let p = profile(id)?;
    let read = inspect || p.mode == Mode::Read;
    let usage = grants::Use {
        action: if read {
            grants::Action::Read
        } else if p.mode == Mode::Write {
            grants::Action::Write
        } else {
            grants::Action::Retain
        },
        selector: grants::Selector {
            kind: if read {
                grants::Kind::File
            } else {
                grants::Kind::Artifact
            },
            id: if read {
                "native-content-inspect-v1"
            } else {
                "native-content-store-v1"
            }
            .into(),
            generation: p.generation,
            digest,
        },
        input_bytes: MAX_REQUEST as u64,
        output_bytes: MAX_OUTPUT,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}

pub(crate) fn acquisition_usage(id: &str) -> Result<grants::Use> {
    usage_at(
        id,
        binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        false,
    )
}

fn inspection_usage(id: &str) -> Result<grants::Use> {
    usage_at(
        id,
        binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        true,
    )
}

fn namespace(path: &Path) -> bool {
    path.to_str()
        .and_then(|v| v.strip_prefix("/run/luma-granted-client/requests/"))
        .and_then(|v| v.strip_suffix("/content.json"))
        .is_some_and(|v| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub(crate) fn verify_client_request(path: &Path, id: &str, login: &str) -> Result<OwnerBinding> {
    if !namespace(path) {
        return Err("native content admission requires the private launcher snapshot".into());
    }
    let mut parents = Vec::new();
    for at in path
        .parent()
        .ok_or("missing native content request namespace")?
        .ancestors()
    {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || (at.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700)
        {
            return Err("native content snapshot namespace is not protected".into());
        }
        parents.push((at, m.dev(), m.ino(), m.mode()));
    }
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o400
    {
        return Err("native content snapshot must be private immutable regular data".into());
    }
    let bytes = read_request(path)?;
    let input = parse(&bytes)?;
    let p = profile(id)?;
    if io::digest(&bytes) != p.source
        || input.binding.owner_generation != p.generation
        || input.login != login
        || identity(&before) != identity(&std::fs::symlink_metadata(path)?)
    {
        return Err("native content snapshot differs from its exact original command".into());
    }
    for (at, dev, ino, mode) in parents {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || (m.dev(), m.ino(), m.mode()) != (dev, ino, mode)
        {
            return Err("native content snapshot parent was substituted".into());
        }
    }
    Ok(input.binding)
}

pub(crate) fn check_client_arguments(
    args: &[&str],
    id: &str,
    audit: Option<&grants::Audit>,
) -> Result<()> {
    let p = profile(id)?;
    let (path, effect_grant) = if p.mode == Mode::Read {
        if args.len() != 6 || args[1] != "content-owned-review" {
            return Err("native content review command shape differs".into());
        }
        (args[4], args[3])
    } else {
        if args.len() != 8
            || args[1] != "content-owned-apply"
            || args[5] != format!("{}:{}", p.mode.name(), p.review)
        {
            return Err("native content apply command/review differs".into());
        }
        (args[6], args[4])
    };
    if args[0] != "/usr/libexec/luma-os/luma-platform"
        || args.last() != Some(&"")
        || !crate::admin_roles::identifier(effect_grant)
        || audit.is_some_and(|v| v.grant_id != effect_grant)
        || args[2].is_empty()
        || args[2].len() > 32
    {
        return Err(
            "native content proof requires its exact original finite principal command".into(),
        );
    }
    let binding = verify_client_request(Path::new(path), id, args[2])?;
    if let Some(audit) = audit {
        check_attribution(&binding, effect_grant, audit)?;
    }
    Ok(())
}

fn check_attribution(binding: &OwnerBinding, grant: &str, audit: &grants::Audit) -> Result<()> {
    audit.validate()?;
    if audit.subject != binding.owner
        || audit.subject_generation != binding.owner_generation
        || audit.grant_id != grant
        || audit.usage.selector.generation != binding.owner_generation
    {
        return Err(
            "native content broker proof substitutes the exact request owner/generation/grant"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn check_worker(id: &str, device: &str, pid: u32) -> Result<()> {
    profile(id)?;
    if device != resource_manager::storage_device(Path::new("/var"))? || pid == 0 {
        return Err("native content worker storage identity differs".into());
    }
    let path = format!("/proc/{pid}/cmdline");
    let mut raw = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?
        .take(4097)
        .read_to_end(&mut raw)?;
    let expected = format!("/usr/libexec/luma-os/luma-platform\0content-resource-worker\0{id}\0");
    if raw.len() > 4096 || raw != expected.as_bytes() {
        return Err("native content requires the exact acquisition worker command".into());
    }
    Ok(())
}

struct LiveBoundary<'a> {
    binding: &'a OwnerBinding,
    registry: crate::principal::RegistryBinding,
    account: crate::principal::Principal,
    lease: &'a resource_manager::WorkerLease,
    mode: Mode,
    review: &'a str,
}

impl LiveBoundary<'_> {
    fn current(&self, binding: &OwnerBinding) -> Result<()> {
        if binding != self.binding
            || self.account.id != binding.owner
            || self.account.generation > binding.owner_generation
            || !self.account.enabled
        {
            return Err("native content live owner/generation changed".into());
        }
        self.lease.check()?;
        self.registry.current()?;
        Ok(())
    }
}

impl Boundary for LiveBoundary<'_> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        self.current(binding)?;
        validate_budget(self.mode, budget)?;
        self.current(binding)
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } => self.current(binding),
            Access::Mutate {
                binding,
                review_sha256,
                decision,
                source_bytes,
                storage_bytes,
            } => {
                self.current(binding)?;
                if self.mode != Mode::decision(decision)
                    || self.review != review_sha256
                    || source_bytes > MAX_REQUEST as u64
                    || storage_bytes > MAX_STORAGE
                {
                    return Err(
                        "native content mutation differs from its finite exact review/lease".into(),
                    );
                }
                self.current(binding)
            }
        }
    }
}

fn validate_budget(mode: Mode, budget: ResourceBudget) -> Result<()> {
    if budget.memory_bytes > 256 * 1024 * 1024
        || budget.tasks != 1
        || budget.read_bytes > 256 * 1024 * 1024
        || budget.write_bytes > MAX_STORAGE
        || budget.additional_storage_bytes > MAX_STORAGE
        || (mode == Mode::Read && (budget.write_bytes != 0 || budget.additional_storage_bytes != 0))
    {
        return Err("native content operation exceeds the fixed acquisition profile".into());
    }
    Ok(())
}

fn plan(
    input: &Input,
    repository: Option<&Repository>,
    boundary: &mut impl Boundary,
) -> Result<Plan> {
    if let Some(repository) = repository {
        let request_id = match &input.operation {
            Operation::Capture { provenance, .. } | Operation::External { provenance, .. } => {
                provenance.request_id.as_str()
            }
            Operation::Table { request } => request.metadata.request_id.as_str(),
        };
        if let Some(prior) = repository.replay_plan(request_id, &input.source()?, boundary)? {
            validate_replay(input, &prior)?;
            return Ok(prior);
        }
    }
    Ok(match &input.operation {
        Operation::Capture {
            artifact_id,
            format,
            content,
            provenance,
        } => Plan::capture(
            input.binding.clone(),
            artifact_id,
            *format,
            content.as_bytes(),
            provenance.clone(),
        )?,
        Operation::External {
            artifact_id,
            expected,
            content,
            provenance,
        } => repository
            .ok_or("external content edit requires an existing owner repository")?
            .plan_external_edit(
                artifact_id,
                expected.clone(),
                content.as_bytes(),
                provenance.clone(),
                boundary,
            )?,
        Operation::Table { request } => repository
            .ok_or("managed table edit requires an existing owner repository")?
            .plan_table_edit(request, boundary)?,
    })
}

fn validate_replay(input: &Input, prior: &Plan) -> Result<()> {
    if prior.binding() != &input.binding {
        return Err("native content replay owner changed".into());
    }
    let matches = match &input.operation {
        Operation::Capture {
            artifact_id,
            format,
            content,
            provenance,
        } => {
            prior
                == &Plan::capture(
                    input.binding.clone(),
                    artifact_id,
                    *format,
                    content.as_bytes(),
                    provenance.clone(),
                )?
        }
        Operation::External {
            artifact_id,
            expected,
            provenance,
            ..
        } => {
            prior.source_kind() == luma_content_store::SourceKind::Content
                && prior.artifact_id() == artifact_id
                && prior.expected() == Some(expected)
                && prior.provenance() == provenance
        }
        Operation::Table { request } => {
            prior.source_kind() == luma_content_store::SourceKind::ManagedTableIntent
                && prior.artifact_id() == request.expected.artifact_id
                && prior.expected() == Some(&request.expected)
                && prior.provenance().request_id == request.metadata.request_id
                && prior.provenance().workflow_sha256 == request.metadata.workflow_sha256
        }
    };
    if !matches {
        return Err("native content replay substitutes its immutable operation metadata".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: crate::resources::Token,
    result: serde_json::Value,
}

fn worker(id: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let p = profile(id)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
    {
        return Err("native content worker requires the fixed enforcing acquisition pool".into());
    }
    check_worker(
        id,
        &resource_manager::storage_device(Path::new("/var"))?,
        std::process::id(),
    )?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(id, Path::new("/var"))?;
    lease.check()?;
    if unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS {
        return Err("native content request descriptor is not sealed".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    let input = parse(&bytes)?;
    if io::digest(&bytes) != p.source || input.binding.owner_generation != p.generation {
        return Err("native content worker input differs from its admitted profile".into());
    }
    // The helper has no TPM/Admin custody access. The original PAM controller
    // checked the journal-projected generation, and its live broker proof pins
    // this exact request/profile. Here the immutable local registry is an
    // additional substitution fence, not a replacement generation authority.
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let account = registry
        .current()?
        .account(&input.login)
        .ok_or("native content local principal missing")?
        .clone();
    let installation = registry.current()?.installation().to_string();
    if installation != input.binding.installation
        || account.id != input.binding.owner
        || account.generation > input.binding.owner_generation
        || !account.enabled
    {
        return Err("native content input is not the current installed principal".into());
    }
    let mut boundary = LiveBoundary {
        binding: &input.binding,
        registry,
        account,
        lease: &lease,
        mode: p.mode,
        review: p.review,
    };
    boundary.current(&input.binding)?;
    // This existence observation occurs only after real admission. A missing
    // repository is not repaired by inspection; only exact initial publication
    // may create it. All other storage errors preserve the original state.
    let domain = Path::new(DIRECTORY).join(luma_content_store::domain_name(&input.binding)?);
    let exists = match std::fs::symlink_metadata(domain) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut repository = if exists {
        Some(Repository::open_at(
            Path::new(DIRECTORY),
            &input.binding,
            &mut boundary,
        )?)
    } else {
        None
    };
    let proposal = plan(&input, repository.as_ref(), &mut boundary)?;
    let result = if p.mode == Mode::Read {
        let effect_mode = Mode::decision(proposal.decision());
        let effect_profile = profile_id(effect_mode, &input, &bytes, proposal.review_sha256())?;
        serde_json::json!({"schema_version":1,"approval":format!("{}:{}",effect_mode.name(),proposal.review_sha256()),"review_sha256":proposal.review_sha256(),"decision":proposal.decision(),"resulting":proposal.resulting(),"source_bytes":proposal.source_bytes(),"storage_bytes":proposal.storage_bytes(),"inspection_usage":inspection_usage(&effect_profile)?,"effect_usage":acquisition_usage(&effect_profile)?,"committed":false,"authority_returned":false,"provenance_authority":false,"workflow_executed":false})
    } else {
        if p.mode != Mode::decision(proposal.decision()) || p.review != proposal.review_sha256() {
            return Err(
                "native content base/decision differs from its exact reviewed effect".into(),
            );
        }
        if repository.is_none() {
            repository = Some(Repository::create_at(
                Path::new(DIRECTORY),
                &proposal,
                &mut boundary,
            )?);
        }
        let outcome = repository
            .as_mut()
            .ok_or("missing native content repository")?
            .apply(&proposal, &input.source()?, &mut boundary)?;
        // The storage transaction is real. Supplied workflow/provenance hashes
        // remain descriptions, not authenticated workflow execution evidence.
        serde_json::json!({"schema_version":1,"outcome":outcome,"committed":true,"authority_returned":false,"provenance_authority":false,"workflow_executed":false})
    };
    boundary.current(&input.binding)?;
    let result_bytes = serde_json::to_vec(&result)?;
    lease.complete_output(&io::digest(&result_bytes))?;
    let response = Response {
        schema_version: 1,
        request_sha256: p.source.into(),
        binding: binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        lease: lease.token().clone(),
        result,
    };
    let output = serde_json::to_vec(&response)?;
    if output.len() as u64 >= MAX_OUTPUT {
        return Err("native content response exceeds its exact bound".into());
    }
    lease.check_local()?;
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
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
        return Err("native content descriptor sealing failed".into());
    }
    Ok(file)
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
fn verify_resource(
    response: &Response,
    expected_binding: &str,
    source: &str,
    value: serde_json::Value,
) -> Result<()> {
    let receipt: ResourceReceipt = serde_json::from_value(value)?;
    if response.schema_version != 1
        || response.binding != expected_binding
        || response.request_sha256 != source
        || !crate::workflow_resource::token_valid(&response.lease)
        || receipt.binding != response.binding
        || receipt.lease != response.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(&response.result)?)
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
            "native content response lacks exact unfenced physical-generation provenance".into(),
        );
    }
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}

fn run(
    id: &str,
    bytes: &[u8],
    guard: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<Response> {
    let scope = acquisition_usage(id)?;
    crate::acquisition::await_drainage()?;
    guard.check()?;
    let encoded = crate::service::granted_acquisition::run_content(id, &scope, guard, |check| {
        check()?;
        let input = anonymous("luma-content-request", bytes, true)?;
        let mut output = anonymous("luma-content-output", &[], false)?;
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args(crate::acquisition::arguments(
                Path::new("/var"),
                id,
                "content",
            )?)
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::null());
        let deadline = resource_manager::now()?
            .checked_add(35_000)
            .ok_or("native content controller deadline overflow")?;
        crate::model::supervise_owned_controller(&mut command, || {
            check()?;
            if resource_manager::now()? >= deadline || output.metadata()?.len() >= MAX_OUTPUT {
                return Err("native content controller authority/output deadline lost".into());
            }
            Ok(())
        })?;
        crate::acquisition::await_drainage()?;
        check()?;
        output.seek(SeekFrom::Start(0))?;
        let mut encoded = Vec::new();
        output.take(MAX_OUTPUT + 1).read_to_end(&mut encoded)?;
        if encoded.is_empty() || encoded.len() as u64 >= MAX_OUTPUT {
            return Err("native content controller response exceeds its exact bound".into());
        }
        Ok(encoded)
    })?;
    guard.check()?;
    let response: Response = serde_json::from_slice(&encoded)?;
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(response.lease.clone());
    let receipt = crate::service::resource_exchange(&request)?
        .status
        .ok_or("native content resource receipt missing")?;
    verify_resource(
        &response,
        &scope.selector.digest,
        source_digest(id)?,
        receipt,
    )?;
    guard.check()?;
    Ok(response)
}

fn check_subject(
    input: &Input,
    guard: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<()> {
    guard.check()?;
    let (registry, account, installation) =
        crate::admin_governance::current_principal(&input.login)?;
    registry.current()?;
    if installation != input.binding.installation
        || account.id != input.binding.owner
        || account.generation != input.binding.owner_generation
        || guard.subject()? != account.id
        || guard.subject_generation()? != account.generation
        || guard.subject_uid()? != account.uid
    {
        return Err(
            "native content finite grant belongs to a different current human principal".into(),
        );
    }
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    // This beta integration is not production catalog rollback/recovery
    // qualification. An immutable production release cannot opt into it.
    crate::platform::require_laboratory_image()?;
    if args.first().map(String::as_str) == Some("content-resource-worker") && args.len() == 2 {
        return worker(&args[1]);
    }
    let (login, path) = match args.first().map(String::as_str) {
        Some("content-owned-inspection-review") if args.len() == 3 => (&args[1], &args[2]),
        Some("content-owned-review") if args.len() == 4 => (&args[1], &args[3]),
        Some("content-owned-apply") if args.len() == 6 => (&args[1], &args[5]),
        _ => return Err("expected content-owned-inspection-review LOGIN REQUEST | content-owned-review LOGIN READ-GRANT REQUEST | content-owned-apply LOGIN READ-GRANT EFFECT-GRANT REVIEW REQUEST".into()),
    };
    let bytes = read_request(Path::new(path))?;
    let input = parse(&bytes)?;
    if input.login != *login {
        return Err("native content request login differs from exact command".into());
    }
    let read_profile = profile_id(Mode::Read, &input, &bytes, &io::digest(&bytes))?;
    if args[0] == "content-owned-inspection-review" {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"inspection_usage":acquisition_usage(&read_profile)?,"private_content_read":false,"grant_issued":false,"committed":false})
        );
        return Ok(());
    }
    if args[0] == "content-owned-review" {
        let usage = acquisition_usage(&read_profile)?;
        return crate::admin_governance::with_grant(login, &args[2], &usage, |guard| {
            check_subject(&input, guard)?;
            let response = run(&read_profile, &bytes, guard)?;
            check_subject(&input, guard)?;
            println!("{}", response.result);
            Ok(())
        });
    }
    // The closed review token selects requested data, never authority. Both
    // current grants and the worker's independently rebuilt decision must agree.
    let (mode, review) = approval(&args[4])?;
    let id = profile_id(mode, &input, &bytes, review)?;
    let uses = [
        (args[2].clone(), inspection_usage(&id)?),
        (args[3].clone(), acquisition_usage(&id)?),
    ];
    crate::admin_governance::with_grants(login, &uses, |guard| {
        check_subject(&input, guard)?;
        let kind = if mode == Mode::Write {
            crate::policy_decisions::EffectKind::ArtifactPublication
        } else {
            crate::policy_decisions::EffectKind::Retention
        };
        let pending = guard.effect_begin(review, kind)?;
        let response = run(&id, &bytes, guard)?;
        check_subject(&input, guard)?;
        guard.effect_complete(pending, &io::digest(&serde_json::to_vec(&response)?))?;
        println!("{}", response.result);
        Ok(())
    })
}

fn approval(value: &str) -> Result<(Mode, &str)> {
    let (mode, digest) = value
        .split_once(':')
        .ok_or("native content apply requires exact write:SHA256 or retain:SHA256 approval")?;
    let mode = match mode {
        "write" => Mode::Write,
        "retain" => Mode::Retain,
        _ => return Err("native content approval effect is not closed".into()),
    };
    if !io::hash(digest) {
        return Err("native content approval requires its exact review SHA-256".into());
    }
    Ok((mode, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn input() -> Input {
        Input {
            schema_version: 1,
            login: "human".into(),
            binding: OwnerBinding {
                installation: "a".repeat(64),
                owner: "b".repeat(64),
                owner_generation: 3,
            },
            operation: Operation::Capture {
                artifact_id: "notes-one".into(),
                format: Format::Utf8Text,
                content: "hello\n".into(),
                provenance: Provenance {
                    request_id: "request-one".into(),
                    workflow_sha256: "c".repeat(64),
                    source_sha256: io::digest(b"hello\n"),
                    origin: luma_content::EditOrigin::Managed,
                },
            },
        }
    }

    #[test]
    fn inert_request_requires_exact_schema_owner_source_and_canonical_representation() {
        let good = serde_json::to_vec(&input()).unwrap();
        assert_eq!(parse(&good).unwrap().source().unwrap(), b"hello\n");
        let mut whitespace = good.clone();
        whitespace.push(b'\n');
        assert!(parse(&whitespace).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        value["authority"] = serde_json::json!(true);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        for login in ["", "root/../human", "Human", "human name"] {
            let mut bad = input();
            bad.login = login.into();
            assert!(parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut wrong = input();
        wrong.binding.owner_generation = 0;
        assert!(parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut changed = input();
        if let Operation::Capture { content, .. } = &mut changed.operation {
            *content = "substitution".into();
        }
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        assert!(parse(&vec![b' '; MAX_REQUEST + 1]).is_err());
    }

    #[test]
    fn closed_profiles_bind_exact_request_generation_review_and_effect_mode() {
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        let source = io::digest(&bytes);
        let read = profile_id(Mode::Read, &input, &bytes, &source).unwrap();
        let p = profile(&read).unwrap();
        assert_eq!(p.generation, 3);
        assert_eq!(p.source, source);
        assert_eq!(p.review, source);
        let review = "d".repeat(64);
        let write = profile_id(Mode::Write, &input, &bytes, &review).unwrap();
        assert_eq!(profile(&write).unwrap().mode, Mode::Write);
        assert_ne!(read, write);
        for value in [
            read.replace("read-3-", "read-03-"),
            read.replace("read-3-", "read-0-"),
            read.replace("read-", "delete-"),
            format!("{read}-extra"),
            read.to_uppercase(),
            format!("{PREFIX}read-3-{source}-{review}"),
        ] {
            assert!(profile(&value).is_err(), "{value}");
        }
        assert!(profile_id(Mode::Write, &input, &bytes, "caller-says-approved").is_err());
    }

    #[test]
    fn independent_read_write_and_retention_scopes_never_substitute_for_each_other() {
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        for (mode, action) in [
            (Mode::Write, grants::Action::Write),
            (Mode::Retain, grants::Action::Retain),
        ] {
            let id = profile_id(mode, &input, &bytes, &"d".repeat(64)).unwrap();
            let effect = usage_at(&id, "e".repeat(64), false).unwrap();
            let read = usage_at(&id, "e".repeat(64), true).unwrap();
            assert_eq!(effect.action, action);
            assert_eq!(read.action, grants::Action::Read);
            assert_eq!(effect.selector.kind, grants::Kind::Artifact);
            assert_eq!(read.selector.kind, grants::Kind::File);
            assert_eq!(effect.selector.digest, read.selector.digest);
            assert_eq!(effect.selector.generation, 3);
            assert_ne!(effect, read);
        }
        assert_eq!(Mode::decision(DecisionKind::Published), Mode::Write);
        assert_eq!(Mode::decision(DecisionKind::ConflictRetained), Mode::Retain);
        assert_eq!(Mode::decision(DecisionKind::NoChangeRetained), Mode::Retain);
    }

    #[test]
    fn review_tokens_are_closed_data_not_authority_or_grant_identifiers() {
        let digest = "d".repeat(64);
        assert_eq!(
            approval(&format!("write:{digest}")).unwrap(),
            (Mode::Write, digest.as_str())
        );
        assert_eq!(
            approval(&format!("retain:{digest}")).unwrap(),
            (Mode::Retain, digest.as_str())
        );
        for bad in [
            digest.clone(),
            format!("read:{digest}"),
            format!("Write:{digest}"),
            format!("write:{digest}:extra"),
            format!("write:{}", "D".repeat(64)),
            "write:true".into(),
        ] {
            assert!(approval(&bad).is_err());
        }
    }

    #[test]
    fn bounded_acquisition_budget_refuses_writes_under_read_or_unenforced_peaks() {
        let read = ResourceBudget {
            memory_bytes: 256 * 1024 * 1024,
            tasks: 1,
            read_bytes: 256 * 1024 * 1024,
            write_bytes: 0,
            additional_storage_bytes: 0,
        };
        validate_budget(Mode::Read, read).unwrap();
        let mutation = ResourceBudget {
            write_bytes: MAX_STORAGE,
            additional_storage_bytes: MAX_STORAGE,
            ..read
        };
        assert!(validate_budget(Mode::Read, mutation).is_err());
        validate_budget(Mode::Write, mutation).unwrap();
        validate_budget(Mode::Retain, mutation).unwrap();
        for excess in [
            ResourceBudget {
                memory_bytes: read.memory_bytes + 1,
                ..read
            },
            ResourceBudget { tasks: 2, ..read },
            ResourceBudget {
                read_bytes: read.read_bytes + 1,
                ..read
            },
            ResourceBudget {
                write_bytes: MAX_STORAGE + 1,
                ..read
            },
            ResourceBudget {
                additional_storage_bytes: MAX_STORAGE + 1,
                ..read
            },
        ] {
            assert!(validate_budget(Mode::Write, excess).is_err());
        }
    }

    #[test]
    fn snapshot_and_original_command_checks_refuse_nonfixed_namespaces_before_read() {
        let path = format!(
            "/run/luma-granted-client/requests/{}/content.json",
            "a".repeat(32)
        );
        assert!(namespace(Path::new(&path)));
        for bad in [
            path.replace("content.json", "input.json"),
            path.replace(&"a".repeat(32), &"A".repeat(32)),
            format!("{path}/../content.json"),
            "/tmp/content.json".into(),
        ] {
            assert!(!namespace(Path::new(&bad)));
        }
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        let id = profile_id(Mode::Read, &input, &bytes, &io::digest(&bytes)).unwrap();
        assert!(check_client_arguments(
            &[
                "/usr/libexec/luma-os/luma-platform",
                "content-owned-apply",
                "human",
                "read-one",
                "/tmp/content.json",
                ""
            ],
            &id,
            None
        )
        .is_err());
        assert!(check_client_arguments(
            &[
                "/usr/libexec/luma-os/luma-platform",
                "content-owned-review",
                "human",
                "../read-one",
                "/tmp/content.json",
                ""
            ],
            &id,
            None
        )
        .is_err());
    }

    #[test]
    fn bounded_capture_refuses_symlinks_hardlinks_empty_and_oversized_files() {
        let directory = std::env::temp_dir().join(format!(
            "luma-content-input-{}-{}",
            std::process::id(),
            crate::resources::random_id().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("request.json");
        let bytes = serde_json::to_vec(&input()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_request(&path).unwrap(), bytes);
        let link = directory.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_request(&link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&path, &link).unwrap();
        assert!(read_request(&path).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::write(&path, []).unwrap();
        assert!(read_request(&path).is_err());
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_REQUEST as u64 + 1)
            .unwrap();
        assert!(read_request(&path).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    fn resource_response() -> (Response, serde_json::Value) {
        let lease = crate::resources::Token {
            lease_id: "a".repeat(32),
            generation: 3,
            manager_epoch: "b".repeat(32),
        };
        let response = Response {
            schema_version: 1,
            request_sha256: "c".repeat(64),
            binding: "d".repeat(64),
            lease: lease.clone(),
            result: serde_json::json!({"committed":true,"outcome":"exact"}),
        };
        let receipt = serde_json::json!({"binding":response.binding,"output_sha256":io::digest(&serde_json::to_vec(&response.result).unwrap()),"output_domain_epochs":{"acquisition-executions":"1","host-memory":"2","worker-processes":"3"},"lease":lease,"state":"released","physical_release_granted":false});
        (response, receipt)
    }

    #[test]
    fn committed_response_requires_exact_lease_input_output_and_every_domain_epoch() {
        let (response, receipt) = resource_response();
        verify_resource(
            &response,
            &response.binding,
            &response.request_sha256,
            receipt.clone(),
        )
        .unwrap();
        for state in ["active", "draining", "released"] {
            let mut value = receipt.clone();
            value["state"] = serde_json::json!(state);
            verify_resource(
                &response,
                &response.binding,
                &response.request_sha256,
                value,
            )
            .unwrap();
        }
        for (path, substitution) in [
            (vec!["binding"], serde_json::json!("e".repeat(64))),
            (vec!["output_sha256"], serde_json::json!("f".repeat(64))),
            (vec!["physical_release_granted"], serde_json::json!(true)),
            (vec!["lease", "generation"], serde_json::json!(4)),
            (
                vec!["output_domain_epochs", "host-memory"],
                serde_json::json!("0"),
            ),
        ] {
            let mut value = receipt.clone();
            if path.len() == 1 {
                value[path[0]] = substitution;
            } else {
                value[path[0]][path[1]] = substitution;
            }
            assert!(verify_resource(
                &response,
                &response.binding,
                &response.request_sha256,
                value
            )
            .is_err());
        }
        let mut missing = receipt.clone();
        missing["output_domain_epochs"]
            .as_object_mut()
            .unwrap()
            .remove("worker-processes");
        assert!(verify_resource(
            &response,
            &response.binding,
            &response.request_sha256,
            missing
        )
        .is_err());
        assert!(verify_resource(
            &response,
            &"e".repeat(64),
            &response.request_sha256,
            receipt.clone()
        )
        .is_err());
        assert!(verify_resource(&response, &response.binding, &"e".repeat(64), receipt).is_err());
    }

    #[test]
    fn request_descriptors_are_sealed_and_output_remains_bounded_mutable_data() {
        let bytes = serde_json::to_vec(&input()).unwrap();
        let mut request = anonymous("test-native-content-request", &bytes, true).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(request.as_raw_fd(), libc::F_GET_SEALS) },
            SEALS
        );
        assert!(request.write_all(b"substitution").is_err());
        let output = anonymous("test-native-content-output", &[], false).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GET_SEALS) },
            0
        );
        assert_eq!(output.metadata().unwrap().len(), 0);
    }

    #[test]
    fn native_external_and_managed_requests_are_distinct_owner_bound_inert_inputs() {
        let seed = input();
        let current = luma_content::capture(
            seed.binding.clone(),
            "table-one",
            Format::Csv,
            b"name,value\none,1\n",
            Provenance {
                request_id: "table-capture".into(),
                workflow_sha256: "c".repeat(64),
                source_sha256: io::digest(b"name,value\none,1\n"),
                origin: luma_content::EditOrigin::Managed,
            },
        )
        .unwrap();
        let expected = current.reference().unwrap();
        let table = luma_content::table::TableEditRequest {
            binding: seed.binding.clone(),
            expected: expected.clone(),
            metadata: luma_content::table::EditMetadata {
                request_id: "table-edit".into(),
                workflow_sha256: "d".repeat(64),
            },
            operations: vec![luma_content::table::Operation::SetCell {
                row: 1,
                column: 1,
                value: "2".into(),
            }],
        };
        let mut managed = Input {
            schema_version: 1,
            login: seed.login.clone(),
            binding: seed.binding.clone(),
            operation: Operation::Table {
                request: table.clone(),
            },
        };
        let bytes = serde_json::to_vec(&managed).unwrap();
        assert_eq!(
            parse(&bytes).unwrap().source().unwrap(),
            table.canonical_bytes().unwrap()
        );
        managed.binding.owner_generation += 1;
        assert!(parse(&serde_json::to_vec(&managed).unwrap()).is_err());
        let source = "name,value\none,3\n";
        let mut external = Input {
            schema_version: 1,
            login: seed.login,
            binding: seed.binding,
            operation: Operation::External {
                artifact_id: "table-one".into(),
                expected,
                content: source.into(),
                provenance: Provenance {
                    request_id: "external-save".into(),
                    workflow_sha256: "e".repeat(64),
                    source_sha256: io::digest(source.as_bytes()),
                    origin: luma_content::EditOrigin::External,
                },
            },
        };
        parse(&serde_json::to_vec(&external).unwrap()).unwrap();
        if let Operation::External { expected, .. } = &mut external.operation {
            expected.artifact_id = "other-artifact".into();
        }
        assert!(parse(&serde_json::to_vec(&external).unwrap()).is_err());
    }

    #[test]
    fn external_prevalidation_does_not_assume_the_private_stored_format() {
        let seed = input();
        let content = "{\"value\":2}\r";
        let provenance = Provenance {
            request_id: "external-json-save".into(),
            workflow_sha256: "c".repeat(64),
            source_sha256: io::digest(content.as_bytes()),
            origin: luma_content::EditOrigin::External,
        };
        assert!(Plan::capture(
            seed.binding.clone(),
            "json-one",
            Format::Utf8Text,
            content.as_bytes(),
            provenance.clone()
        )
        .is_err());
        assert!(Plan::capture(
            seed.binding.clone(),
            "json-one",
            Format::Json,
            content.as_bytes(),
            provenance.clone()
        )
        .is_ok());
        let mut request = Input {
            schema_version: 1,
            login: seed.login,
            binding: seed.binding,
            operation: Operation::External {
                artifact_id: "json-one".into(),
                expected: VersionReference {
                    artifact_id: "json-one".into(),
                    version: 1,
                    content_sha256: "a".repeat(64),
                    receipt_sha256: "b".repeat(64),
                },
                content: content.into(),
                provenance,
            },
        };
        parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        if let Operation::External { provenance, .. } = &mut request.operation {
            provenance.source_sha256 = "d".repeat(64);
        }
        assert!(parse(&serde_json::to_vec(&request).unwrap()).is_err());
        if let Operation::External {
            content,
            provenance,
            ..
        } = &mut request.operation
        {
            *content = "\0".into();
            provenance.source_sha256 = io::digest(content.as_bytes());
        }
        assert!(parse(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn replay_requires_exact_original_operation_not_request_id_or_source_alone() {
        let mut request = input();
        let prior = match &request.operation {
            Operation::Capture {
                artifact_id,
                format,
                content,
                provenance,
            } => Plan::capture(
                request.binding.clone(),
                artifact_id,
                *format,
                content.as_bytes(),
                provenance.clone(),
            )
            .unwrap(),
            _ => unreachable!(),
        };
        validate_replay(&request, &prior).unwrap();
        if let Operation::Capture { artifact_id, .. } = &mut request.operation {
            *artifact_id = "other-notes".into();
        }
        assert!(validate_replay(&request, &prior).is_err());
        request = input();
        if let Operation::Capture { provenance, .. } = &mut request.operation {
            provenance.workflow_sha256 = "e".repeat(64);
        }
        assert!(validate_replay(&request, &prior).is_err());
        request = input();
        request.binding.owner_generation += 1;
        assert!(validate_replay(&request, &prior).is_err());
        request = input();
        let (artifact_id, content, provenance) = match &request.operation {
            Operation::Capture {
                artifact_id,
                content,
                provenance,
                ..
            } => (artifact_id.clone(), content.clone(), provenance.clone()),
            _ => unreachable!(),
        };
        request.operation = Operation::External {
            artifact_id,
            expected: prior.resulting().clone(),
            content,
            provenance: Provenance {
                origin: luma_content::EditOrigin::External,
                ..provenance
            },
        };
        assert!(validate_replay(&request, &prior).is_err());
    }

    #[test]
    fn content_launch_is_fixed_lease_pool_with_no_network_kvm_or_arbitrary_target() {
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        let id = profile_id(Mode::Read, &input, &bytes, &io::digest(&bytes)).unwrap();
        let args = crate::acquisition::arguments(Path::new("/var"), &id, "content").unwrap();
        assert!(args
            .iter()
            .any(|v| v == "--property=ReadWritePaths=/var/lib/luma-os/content-store"));
        assert!(args
            .iter()
            .any(|v| v == "--property=RestrictAddressFamilies=AF_UNIX"));
        assert!(args.iter().any(|v| v == "--property=MemoryMax=512M"));
        assert!(args.iter().any(|v| v == "--property=TasksMax=16"));
        assert!(args.iter().any(|v| v == "--property=LimitFSIZE=16M"));
        assert!(args
            .iter()
            .any(|v| v == "--property=CapabilityBoundingSet="));
        assert!(!args.iter().any(|v| v.contains("CAP_SETUID")
            || v.contains("CAP_SETGID")
            || v.contains("CAP_KILL")
            || v.contains("CAP_SETPCAP")));
        assert!(args.iter().any(|v| v == "content-resource-worker"));
        assert!(!args
            .iter()
            .any(|v| v.contains("/dev/kvm") || v.contains("AF_INET")));
        assert!(crate::acquisition::arguments(Path::new("/tmp"), &id, "content").is_err());
        assert!(crate::acquisition::arguments(
            Path::new("/var"),
            "content-v1-read-1-wrong",
            "content"
        )
        .is_err());
    }

    #[test]
    fn broker_attribution_requires_exact_projected_owner_generation_and_grant() {
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        let id = profile_id(Mode::Write, &input, &bytes, &"c".repeat(64)).unwrap();
        let usage = usage_at(&id, "d".repeat(64), false).unwrap();
        let audit = grants::Audit {
            subject: input.binding.owner.clone(),
            subject_generation: input.binding.owner_generation,
            grant_id: "write-one".into(),
            grant_version: 1,
            checkpoint_head: "e".repeat(64),
            operation_id: Some("f".repeat(32)),
            usage,
        };
        check_attribution(&input.binding, "write-one", &audit).unwrap();
        for altered in [
            grants::Audit {
                subject: "a".repeat(64),
                ..audit.clone()
            },
            grants::Audit {
                subject_generation: audit.subject_generation + 1,
                ..audit.clone()
            },
            grants::Audit {
                grant_id: "other-write".into(),
                ..audit.clone()
            },
            grants::Audit {
                grant_version: 2,
                ..audit.clone()
            },
            grants::Audit {
                usage: grants::Use {
                    selector: grants::Selector {
                        generation: 1,
                        ..audit.usage.selector.clone()
                    },
                    ..audit.usage.clone()
                },
                ..audit.clone()
            },
        ] {
            assert!(check_attribution(&input.binding, "write-one", &altered).is_err());
        }
    }
}
