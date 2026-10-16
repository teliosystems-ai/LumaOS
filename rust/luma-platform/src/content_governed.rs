//! Native content publication joined to the original PAM client's live grants,
//! protected UTC and broker-owned acquisition generation. Stored plans, source
//! documents and callback return values are never independent authority.
use crate::{artifacts as io, finite_grants as grants, resource_manager, Result};
use luma_content::{ArtifactVersion, Format, OwnerBinding, Provenance, VersionReference};
use luma_content_store::{Access, Boundary, DecisionKind, Plan, Repository, ResourceBudget};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/content-store";
pub(crate) const MAX_REQUEST: usize = 16 * 1024 * 1024 + 32768;
const MAX_OUTPUT: u64 = 65536;
const MAX_STORAGE: u64 = 24 * 1024 * 1024;
const MAX_PAGE_BYTES: u32 = 16384;
const MAX_QUERY_RESULTS: usize = 32;
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
    Render {
        request: luma_content::rendered::Request,
    },
    Preparation {
        target: String,
    },
    Recovery {
        review: luma_content_store::PreparationReview,
    },
    Collection {
        source: luma_content_store::CollectionSource,
        expected: Option<VersionReference>,
        provenance: Provenance,
    },
    CollectionCurrent {
        collection_id: String,
    },
    CollectionPage {
        expected: VersionReference,
        offset: usize,
        limit: usize,
    },
    CollectionsForMember {
        member: VersionReference,
        offset: usize,
        limit: usize,
    },
    Current {
        artifact_id: String,
    },
    Historical {
        expected: VersionReference,
    },
    Page {
        expected: VersionReference,
        offset: u64,
        bytes: u32,
    },
    Search {
        query: String,
        limit: usize,
    },
}

impl Input {
    fn is_query(&self) -> bool {
        matches!(
            self.operation,
            Operation::Current { .. }
                | Operation::Historical { .. }
                | Operation::Page { .. }
                | Operation::Search { .. }
                | Operation::Preparation { .. }
                | Operation::CollectionCurrent { .. }
                | Operation::CollectionPage { .. }
                | Operation::CollectionsForMember { .. }
        )
    }

    fn source(&self) -> Result<Vec<u8>> {
        Ok(match &self.operation {
            Operation::Capture { content, .. } | Operation::External { content, .. } => {
                if content.len() > luma_content::MAX_CONTENT_BYTES {
                    return Err("native content source exceeds its format bound".into());
                }
                content.as_bytes().to_vec()
            }
            Operation::Table { request } => request.canonical_bytes()?,
            Operation::Render { request } => request.canonical_bytes()?,
            Operation::Recovery { review } => serde_json::to_vec(review)?,
            Operation::Collection { source, .. } => source.canonical_bytes()?,
            Operation::Current { .. }
            | Operation::Historical { .. }
            | Operation::Page { .. }
            | Operation::Search { .. }
            | Operation::Preparation { .. }
            | Operation::CollectionCurrent { .. }
            | Operation::CollectionPage { .. }
            | Operation::CollectionsForMember { .. } => {
                return Err("native content query has no mutation source".into());
            }
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
        if !self.is_query() {
            self.source()?;
        }
        match &self.operation {
            Operation::Preparation { target } => {
                if !io::hash(target) {
                    return Err("content recovery requires an exact preparation hash".into());
                }
            }
            Operation::Recovery { review } => {
                review.validate()?;
                if review.binding != self.binding {
                    return Err("content recovery substitutes its owner binding".into());
                }
            }
            Operation::Collection {
                source,
                expected,
                provenance,
            } => {
                let bytes = source.canonical_bytes()?;
                if provenance.origin != luma_content::EditOrigin::External {
                    return Err(
                        "explicit collection source requires external descriptive provenance"
                            .into(),
                    );
                }
                let artifact = source.artifact_id()?;
                if let Some(expected) = expected {
                    validate_reference(expected)?;
                    if expected.artifact_id != artifact {
                        return Err("collection base retargets its stable ID".into());
                    }
                }
                Plan::capture(
                    self.binding.clone(),
                    &artifact,
                    Format::Json,
                    &bytes,
                    provenance.clone(),
                )?;
            }
            Operation::CollectionCurrent { collection_id } => {
                if collection_id.is_empty()
                    || collection_id.len() > 64
                    || !collection_id.as_bytes()[0].is_ascii_alphanumeric()
                    || !collection_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return Err("invalid bounded native collection ID".into());
                }
            }
            Operation::CollectionPage {
                expected,
                offset,
                limit,
            } => {
                validate_reference(expected)?;
                if *offset > luma_content_store::MAX_COLLECTION_MEMBERS
                    || *limit == 0
                    || *limit > luma_content_store::MAX_COLLECTION_PAGE
                {
                    return Err("collection page exceeds its fixed bounds".into());
                }
            }
            Operation::CollectionsForMember {
                member,
                offset,
                limit,
            } => {
                validate_reference(member)?;
                if *offset > luma_content_store::MAX_OUTCOMES
                    || *limit == 0
                    || *limit > luma_content_store::MAX_COLLECTION_PAGE
                {
                    return Err("collection membership page exceeds its fixed bounds".into());
                }
            }
            Operation::Current { artifact_id } => validate_artifact_id(artifact_id)?,
            Operation::Historical { expected } => validate_reference(expected)?,
            Operation::Page {
                expected,
                offset,
                bytes,
            } => {
                validate_reference(expected)?;
                if *bytes == 0
                    || *bytes > MAX_PAGE_BYTES
                    || *offset > luma_content::MAX_ENVELOPE_BYTES as u64
                {
                    return Err("native content page exceeds its fixed envelope bounds".into());
                }
            }
            Operation::Search { query, limit } => {
                if *limit > MAX_QUERY_RESULTS {
                    return Err("native content query exceeds its response result bound".into());
                }
                luma_content_store::canonical_search_query(query, *limit)?;
            }
            _ => {}
        }
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
        if let Operation::Render { request } = &self.operation {
            if request.binding != self.binding {
                return Err("managed render request substitutes the admitted owner binding".into());
            }
            luma_content::rendered::prepare(request)?;
        }
        Ok(())
    }
}

fn validate_artifact_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || value == "."
        || value == ".."
    {
        return Err("invalid native content artifact identifier".into());
    }
    Ok(())
}

fn validate_reference(reference: &VersionReference) -> Result<()> {
    validate_artifact_id(&reference.artifact_id)?;
    if reference.version == 0
        || [&reference.content_sha256, &reference.receipt_sha256]
            .into_iter()
            .any(|digest| !io::hash(digest) || digest.bytes().all(|b| b == b'0'))
    {
        return Err("native content query requires an exact nonzero immutable reference".into());
    }
    Ok(())
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
    Query,
    Write,
    Retain,
    Recover,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Query => "query",
            Self::Write => "write",
            Self::Retain => "retain",
            Self::Recover => "recover",
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
        Some("query") => Mode::Query,
        Some("write") => Mode::Write,
        Some("retain") => Mode::Retain,
        Some("recover") => Mode::Recover,
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
        || (matches!(mode, Mode::Read | Mode::Query) && source != review)
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

pub(crate) fn query_profile(value: &str) -> Result<bool> {
    Ok(profile(value)?.mode == Mode::Query)
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
    let read = inspect || matches!(p.mode, Mode::Read | Mode::Query);
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
            id: if p.mode == Mode::Recover && !read {
                "native-content-recovery-v1"
            } else if p.mode == Mode::Query {
                "native-content-query-v1"
            } else if read {
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
        || input.is_query() != (p.mode == Mode::Query)
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
    let (path, effect_grant) = if matches!(p.mode, Mode::Read | Mode::Query) {
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
            Access::Recover {
                binding,
                review_sha256,
                retained_bytes,
            } => {
                self.current(binding)?;
                if self.mode != Mode::Recover
                    || self.review != review_sha256
                    || retained_bytes > MAX_STORAGE
                {
                    return Err(
                        "native content recovery differs from its exact finite retention scope"
                            .into(),
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
        || (matches!(mode, Mode::Read | Mode::Query)
            && (budget.write_bytes != 0 || budget.additional_storage_bytes != 0))
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
            Operation::Render { request } => request.metadata.request_id.as_str(),
            Operation::Collection { provenance, .. } => provenance.request_id.as_str(),
            Operation::Recovery { .. } => {
                return Err("content recovery uses its dedicated review path".into())
            }
            Operation::Current { .. }
            | Operation::Historical { .. }
            | Operation::Page { .. }
            | Operation::Search { .. }
            | Operation::Preparation { .. }
            | Operation::CollectionCurrent { .. }
            | Operation::CollectionPage { .. }
            | Operation::CollectionsForMember { .. } => {
                return Err("native content query cannot construct a mutation plan".into());
            }
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
        Operation::Render { request } => match repository {
            Some(repository) => repository.plan_render(request, boundary)?,
            None => Plan::managed_render(None, request)?,
        },
        Operation::Recovery { .. } => {
            return Err("content recovery uses its dedicated review path".into())
        }
        Operation::Collection {
            source,
            expected,
            provenance,
        } => match repository {
            Some(repository) => repository.plan_collection(
                source,
                expected.clone(),
                provenance.clone(),
                boundary,
            )?,
            None => {
                if expected.is_some() {
                    return Err("initial collection cannot have a stored base".into());
                }
                Plan::collection_capture(input.binding.clone(), source, provenance.clone())?
            }
        },
        Operation::Current { .. }
        | Operation::Historical { .. }
        | Operation::Page { .. }
        | Operation::Search { .. }
        | Operation::Preparation { .. }
        | Operation::CollectionCurrent { .. }
        | Operation::CollectionPage { .. }
        | Operation::CollectionsForMember { .. } => {
            return Err("native content query cannot construct a mutation plan".into());
        }
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
        Operation::Render { request } => {
            prior.source_kind() == luma_content_store::SourceKind::ManagedRenderIntent
                && prior.artifact_id() == request.artifact_id
                && prior.expected() == request.expected.as_ref()
                && prior.provenance().request_id == request.metadata.request_id
                && prior.provenance().workflow_sha256 == request.metadata.workflow_sha256
                && prior.derivation().map(|d| d.engine) == Some(request.engine)
        }
        Operation::Collection {
            source,
            expected,
            provenance,
        } => {
            prior.source_kind() == luma_content_store::SourceKind::CollectionIntent
                && prior.artifact_id() == source.artifact_id()?
                && prior.expected() == expected.as_ref()
                && prior.provenance() == provenance
        }
        Operation::Current { .. }
        | Operation::Historical { .. }
        | Operation::Page { .. }
        | Operation::Search { .. }
        | Operation::Preparation { .. }
        | Operation::Recovery { .. } => false,
        Operation::CollectionCurrent { .. }
        | Operation::CollectionPage { .. }
        | Operation::CollectionsForMember { .. } => false,
    };
    if !matches {
        return Err("native content replay substitutes its immutable operation metadata".into());
    }
    Ok(())
}

fn version_result(
    version: &ArtifactVersion,
    page: Option<(u64, u32)>,
) -> Result<serde_json::Value> {
    let envelope = version.canonical_envelope()?;
    let mut result = serde_json::json!({
        "schema_version":1,
        "reference":version.reference()?,
        "format":version.receipt().format,
        "envelope_bytes":envelope.len(),
        "envelope_sha256":io::digest(&envelope),
        "content_delivered":false,
        "committed":false,
        "authority_returned":false,
        "provenance_authority":false,
        "workflow_executed":false,
        "production_qualified":false
    });
    if let Some((offset, bytes)) = page {
        if bytes == 0 || bytes > MAX_PAGE_BYTES || offset > envelope.len() as u64 {
            return Err("native content page lies outside the exact immutable envelope".into());
        }
        let start = usize::try_from(offset)?;
        let end = start.saturating_add(bytes as usize).min(envelope.len());
        result["encoding"] = serde_json::json!("hex");
        result["offset"] = serde_json::json!(offset);
        result["next_offset"] = serde_json::json!(end);
        result["eof"] = serde_json::json!(end == envelope.len());
        result["slice_hex"] = serde_json::json!(encode_hex(&envelope[start..end]));
        result["content_delivered"] = serde_json::json!(end > start);
    }
    Ok(result)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}

fn query(
    input: &Input,
    repository: &Repository,
    boundary: &mut impl Boundary,
) -> Result<serde_json::Value> {
    let result = match &input.operation {
        Operation::Preparation { target } => serde_json::json!({
            "schema_version":1,"review":repository.review_preparation(target, boundary)?,
            "committed":false,"authority_returned":false,"workflow_executed":false,
            "production_qualified":false
        }),
        Operation::CollectionCurrent { collection_id } => serde_json::json!({
            "schema_version":1,"collection":repository.collection_current(collection_id, boundary)?,
            "committed":false,"authority_returned":false,"semantic_classification":false,
            "membership_is_authority":false,"production_qualified":false
        }),
        Operation::CollectionPage {
            expected,
            offset,
            limit,
        } => serde_json::json!({
            "schema_version":1,"page":repository.collection_page(expected, *offset, *limit, boundary)?,
            "committed":false,"authority_returned":false,"membership_is_authority":false,
            "production_qualified":false
        }),
        Operation::CollectionsForMember {
            member,
            offset,
            limit,
        } => serde_json::json!({
            "schema_version":1,"memberships":repository.collections_for_member(member, *offset, *limit, boundary)?,
            "committed":false,"authority_returned":false,"membership_is_authority":false,
            "production_qualified":false
        }),
        Operation::Current { artifact_id } => {
            version_result(&repository.current(artifact_id, boundary)?, None)?
        }
        Operation::Historical { expected } => {
            version_result(&repository.historical(expected, boundary)?, None)?
        }
        Operation::Page {
            expected,
            offset,
            bytes,
        } => version_result(
            &repository.historical(expected, boundary)?,
            Some((*offset, *bytes)),
        )?,
        Operation::Search { query, limit } => serde_json::json!({
            "schema_version":1,
            "search":repository.search(query, *limit, boundary)?,
            "content_delivered":false,
            "committed":false,
            "authority_returned":false,
            "provenance_authority":false,
            "workflow_executed":false,
            "production_qualified":false
        }),
        _ => return Err("native content query profile cannot inspect a mutation plan".into()),
    };
    if serde_json::to_vec(&result)?.len() as u64 >= MAX_OUTPUT {
        return Err("native content query exceeds its finite output allowance".into());
    }
    Ok(result)
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
    if io::digest(&bytes) != p.source
        || input.binding.owner_generation != p.generation
        || input.is_query() != (p.mode == Mode::Query)
    {
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
    let result = if let Operation::Recovery { review } = &input.operation {
        let repository = repository
            .as_mut()
            .ok_or("content recovery requires an existing owner repository")?;
        if p.mode == Mode::Read {
            repository.check_preparation_review(review, &mut boundary)?;
            let effect_profile = profile_id(Mode::Recover, &input, &bytes, &review.review_sha256)?;
            serde_json::json!({"schema_version":1,"approval":format!("recover:{}",review.review_sha256),
                "review_sha256":review.review_sha256,"inspection_usage":inspection_usage(&effect_profile)?,
                "effect_usage":acquisition_usage(&effect_profile)?,"committed":false,
                "authority_returned":false,"workflow_executed":false,"production_qualified":false})
        } else {
            if p.mode != Mode::Recover || p.review != review.review_sha256 {
                return Err(
                    "content preparation retirement requires its exact reviewed recovery scope"
                        .into(),
                );
            }
            let outcome = repository.recover_preparation(review, &mut boundary)?;
            serde_json::json!({"schema_version":1,"recovery":outcome,"committed":true,
                "committed_catalog_changed":false,"authority_returned":false,
                "workflow_executed":false,"production_qualified":false})
        }
    } else if p.mode == Mode::Query {
        query(
            &input,
            repository
                .as_ref()
                .ok_or("native content query requires an existing owner repository")?,
            &mut boundary,
        )?
    } else {
        let proposal = plan(&input, repository.as_ref(), &mut boundary)?;
        if p.mode == Mode::Read {
            let effect_mode = Mode::decision(proposal.decision());
            let effect_profile = profile_id(effect_mode, &input, &bytes, proposal.review_sha256())?;
            serde_json::json!({"schema_version":1,"approval":format!("{}:{}",effect_mode.name(),proposal.review_sha256()),"review_sha256":proposal.review_sha256(),"decision":proposal.decision(),"resulting":proposal.resulting(),"derivation":proposal.derivation(),"source_bytes":proposal.source_bytes(),"storage_bytes":proposal.storage_bytes(),"inspection_usage":inspection_usage(&effect_profile)?,"effect_usage":acquisition_usage(&effect_profile)?,"committed":false,"authority_returned":false,"provenance_authority":false,"workflow_executed":false})
        } else {
            if p.mode != Mode::decision(proposal.decision()) || p.review != proposal.review_sha256()
            {
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
            let repository = repository
                .as_mut()
                .ok_or("missing native content repository")?;
            let source = input.source()?;
            let outcome = if matches!(input.operation, Operation::Collection { .. }) {
                repository.apply_collection(&proposal, &source, &mut boundary)?
            } else {
                repository.apply(&proposal, &source, &mut boundary)?
            };
            // The storage transaction is real. Supplied workflow/provenance hashes
            // remain descriptions, not authenticated workflow execution evidence.
            serde_json::json!({"schema_version":1,"outcome":outcome,"derivation":proposal.derivation(),"committed":true,"authority_returned":false,"provenance_authority":false,"workflow_executed":false})
        }
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

fn check_response(response: &Response, id: &str) -> Result<()> {
    let scope = acquisition_usage(id)?;
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(response.lease.clone());
    let receipt = crate::service::resource_exchange(&request)?
        .status
        .ok_or("native content resource receipt missing")?;
    verify_resource(
        response,
        &scope.selector.digest,
        source_digest(id)?,
        receipt,
    )
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
    check_response(&response, id)?;
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

/// A stalled consumer must not turn one successful check into an unbounded
/// blocking private-content delivery. No inherited open-file-description flags
/// are changed, including when the process is killed without running Drop.
struct NonblockingOutput {
    file: File,
    kind: OutputKind,
}

#[derive(Clone, Copy)]
enum OutputKind {
    Socket,
    Pipe,
    Terminal,
}

fn checked_output(fd: i32) -> Result<File> {
    let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copied < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(copied) };
    let kind = file.metadata()?.file_type();
    if !kind.is_fifo() && !kind.is_socket() && unsafe { libc::isatty(file.as_raw_fd()) } != 1 {
        return Err("native content delivery requires a nonblocking pipe, socket, or terminal; direct file export is not admitted".into());
    }
    Ok(file)
}

/// Destination-only observation, before PAM, private reads, or any effect.
/// The same descriptor is independently revalidated at actual delivery.
fn output_preflight(fd: i32) -> Result<()> {
    drop(NonblockingOutput::duplicate(fd)?);
    Ok(())
}

impl NonblockingOutput {
    fn duplicate(fd: i32) -> Result<Self> {
        let pinned = checked_output(fd)?;
        let before = pinned.metadata()?;
        let flags = unsafe { libc::fcntl(pinned.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            return Err("native content destination is not writable".into());
        }
        if before.file_type().is_socket() {
            return Ok(Self {
                file: pinned,
                kind: OutputKind::Socket,
            });
        }
        if before.file_type().is_fifo() {
            return Ok(Self {
                file: pinned,
                kind: OutputKind::Pipe,
            });
        }
        // A procfd reopen creates a fresh open-file description, unlike dup.
        // Its fixed numeric target stays pinned until both identities and the
        // original flags have been rechecked. No caller pathname is opened.
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        check_output_identity(&before, &file.metadata()?)?;
        check_output_identity(&before, &pinned.metadata()?)?;
        let reopened_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if reopened_flags < 0
            || reopened_flags & libc::O_NONBLOCK == 0
            || unsafe { libc::fcntl(pinned.as_raw_fd(), libc::F_GETFL) } != flags
            || (!before.file_type().is_fifo() && unsafe { libc::isatty(file.as_raw_fd()) } != 1)
        {
            return Err(
                "native content destination changed while opening independent nonblocking delivery"
                    .into(),
            );
        }
        Ok(Self {
            file,
            kind: OutputKind::Terminal,
        })
    }
}

fn check_output_identity(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
    let binding = |m: &std::fs::Metadata| (m.dev(), m.ino(), m.rdev(), m.mode(), m.uid(), m.gid());
    if binding(before) != binding(after) {
        return Err("native content destination substituted a different pinned descriptor".into());
    }
    Ok(())
}

impl Write for NonblockingOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.kind {
            OutputKind::Socket => {
                let count = unsafe {
                    libc::send(
                        self.file.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if count < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }
            OutputKind::Pipe => write_pipe(self.file.as_raw_fd(), bytes),
            OutputKind::Terminal => self.file.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_pipe(destination: i32, bytes: &[u8]) -> std::io::Result<usize> {
    let count = bytes.len().min(4096);
    if count == 0 {
        return Ok(0);
    }
    let mut descriptors = [-1, -1];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
    // This fresh private pipe is empty and <=4096 bytes is Linux PIPE_BUF, so
    // its nonblocking write is atomic. It never touches the inherited flags.
    if writer.write(&bytes[..count])? != count {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "private content delivery pipe failed its bounded atomic stage",
        ));
    }
    // Both endpoints are pipes: SPLICE_F_NONBLOCK applies to their waits, with
    // no regular-file/device blocking caveat. Partial/failed calls drop unsent
    // staging bytes; the outer checked writer retries only its unsent source.
    let sent = unsafe {
        libc::splice(
            reader.as_raw_fd(),
            std::ptr::null_mut(),
            destination,
            std::ptr::null_mut(),
            count,
            libc::SPLICE_F_NONBLOCK,
        )
    };
    if sent < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

fn deliver_checked(
    result: &serde_json::Value,
    output: &mut impl Write,
    mut check: impl FnMut() -> Result<()>,
    mut wait: impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(result)?;
    bytes.push(b'\n');
    if bytes.len() as u64 >= MAX_OUTPUT {
        return Err("native content delivery exceeds its finite output allowance".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut at = 0;
    while at < bytes.len() {
        check()?;
        if std::time::Instant::now() >= deadline {
            return Err("native content delivery deadline expired".into());
        }
        let end = (at + 4096).min(bytes.len());
        match output.write(&bytes[at..end]) {
            Ok(0) => return Err("native content output closed before delivery".into()),
            Ok(count) => at += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                check()?;
                wait()?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    check()?;
    // The native path passes an unbuffered descriptor, so this cannot buffer private
    // content beyond the final observation. Unit sinks exercise this fence.
    output.flush()?;
    check()
}

fn deliver_result(result: &serde_json::Value, mut check: impl FnMut() -> Result<()>) -> Result<()> {
    // Hold the ordinary stdout lock while using its unbuffered descriptor.
    let stdout = std::io::stdout();
    let _held = stdout.lock();
    let mut output = NonblockingOutput::duplicate(1)?;
    let fd = output.file.as_raw_fd();
    deliver_checked(result, &mut output, &mut check, || {
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let status = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if status < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        } else if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err("native content consumer closed its bounded output".into());
        }
        Ok(())
    })
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
    if args[0] != "content-owned-inspection-review" {
        output_preflight(1)?;
    }
    let bytes = read_request(Path::new(path))?;
    let input = parse(&bytes)?;
    if input.login != *login {
        return Err("native content request login differs from exact command".into());
    }
    if input.is_query() && args[0] == "content-owned-apply" {
        return Err("native content query cannot be applied as a mutation or retention".into());
    }
    let read_profile = profile_id(
        if input.is_query() {
            Mode::Query
        } else {
            Mode::Read
        },
        &input,
        &bytes,
        &io::digest(&bytes),
    )?;
    if args[0] == "content-owned-inspection-review" {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"inspection_usage":acquisition_usage(&read_profile)?,"query_only":input.is_query(),"private_content_read":false,"grant_issued":false,"committed":false})
        );
        return Ok(());
    }
    if args[0] == "content-owned-review" {
        let usage = acquisition_usage(&read_profile)?;
        return crate::admin_governance::with_grant(login, &args[2], &usage, |guard| {
            check_subject(&input, guard)?;
            let response = run(&read_profile, &bytes, guard)?;
            check_subject(&input, guard)?;
            deliver_result(&response.result, || {
                check_subject(&input, guard)?;
                check_response(&response, &read_profile)?;
                check_subject(&input, guard)
            })
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
        deliver_result(&response.result, || {
            check_subject(&input, guard)?;
            check_response(&response, &id)?;
            check_subject(&input, guard)
        })
    })
}

fn approval(value: &str) -> Result<(Mode, &str)> {
    let (mode, digest) = value
        .split_once(':')
        .ok_or("native content apply requires exact write:SHA256, retain:SHA256 or recover:SHA256 approval")?;
    let mode = match mode {
        "write" => Mode::Write,
        "retain" => Mode::Retain,
        "recover" => Mode::Recover,
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

    fn reference() -> VersionReference {
        VersionReference {
            artifact_id: "notes-one".into(),
            version: 1,
            content_sha256: "c".repeat(64),
            receipt_sha256: "d".repeat(64),
        }
    }

    fn query_input(operation: Operation) -> Input {
        Input {
            operation,
            ..input()
        }
    }

    #[test]
    fn collection_and_preparation_requests_are_bounded_read_only_selectors() {
        for operation in [
            Operation::CollectionCurrent {
                collection_id: "work-items".into(),
            },
            Operation::CollectionPage {
                expected: reference(),
                offset: 0,
                limit: 32,
            },
            Operation::CollectionsForMember {
                member: reference(),
                offset: 0,
                limit: 32,
            },
            Operation::Preparation {
                target: "e".repeat(64),
            },
        ] {
            let input = query_input(operation);
            let canonical = canonical_request(&serde_json::to_vec(&input).unwrap()).unwrap();
            let parsed = parse(&canonical).unwrap();
            assert!(parsed.is_query());
            assert!(parsed.source().is_err());
            let id = profile_id(Mode::Query, &parsed, &canonical, &io::digest(&canonical)).unwrap();
            assert!(query_profile(&id).unwrap());
            assert_eq!(
                usage_at(&id, "f".repeat(64), false).unwrap().action,
                grants::Action::Read
            );
        }
        for operation in [
            Operation::CollectionCurrent {
                collection_id: "../escape".into(),
            },
            Operation::CollectionPage {
                expected: reference(),
                offset: 0,
                limit: 33,
            },
            Operation::CollectionsForMember {
                member: reference(),
                offset: 0,
                limit: 0,
            },
            Operation::Preparation {
                target: "unbounded-name".into(),
            },
        ] {
            assert!(query_input(operation).validate().is_err());
        }
    }

    #[test]
    fn recovery_retention_cannot_substitute_normal_retention_scope_or_read_profile() {
        let input = input();
        let bytes = serde_json::to_vec(&input).unwrap();
        let digest = "d".repeat(64);
        let recovery = profile_id(Mode::Recover, &input, &bytes, &digest).unwrap();
        let retain = profile_id(Mode::Retain, &input, &bytes, &digest).unwrap();
        let recovered_scope = usage_at(&recovery, "e".repeat(64), false).unwrap();
        let retained_scope = usage_at(&retain, "e".repeat(64), false).unwrap();
        assert_eq!(recovered_scope.action, grants::Action::Retain);
        assert_ne!(recovered_scope, retained_scope);
        assert_ne!(recovered_scope.selector.id, retained_scope.selector.id);
        assert_eq!(
            usage_at(&recovery, "e".repeat(64), true).unwrap().action,
            grants::Action::Read
        );
        assert!(!query_profile(&recovery).unwrap());
        assert_eq!(
            approval(&format!("recover:{digest}")).unwrap().0,
            Mode::Recover
        );
        assert!(approval(&format!("Recover:{digest}")).is_err());
    }

    #[test]
    fn collection_replay_joins_exact_base_provenance_generation_and_typed_source() {
        let mut request = input();
        let source = luma_content_store::CollectionSource {
            schema_version: 1,
            kind: "luma-explicit-collection-v1".into(),
            collection_id: "work-items".into(),
            name: "Work items".into(),
            members: vec![],
        };
        let source_bytes = source.canonical_bytes().unwrap();
        let provenance = Provenance {
            request_id: "collection-one".into(),
            workflow_sha256: "c".repeat(64),
            source_sha256: io::digest(&source_bytes),
            origin: luma_content::EditOrigin::External,
        };
        let prior =
            Plan::collection_capture(request.binding.clone(), &source, provenance.clone()).unwrap();
        request.operation = Operation::Collection {
            source: source.clone(),
            expected: None,
            provenance: provenance.clone(),
        };
        let bytes = canonical_request(&serde_json::to_vec(&request).unwrap()).unwrap();
        let fresh = || parse(&bytes).unwrap();
        assert_eq!(fresh().source().unwrap(), source_bytes);
        validate_replay(&fresh(), &prior).unwrap();

        let mut changed = fresh();
        if let Operation::Collection { expected, .. } = &mut changed.operation {
            *expected = Some(prior.resulting().clone());
        }
        // A genuine reference still cannot replace the exact original None base.
        changed.validate().unwrap();
        assert!(validate_replay(&changed, &prior).is_err());

        for field in 0..4 {
            let mut changed = fresh();
            if let Operation::Collection { provenance, .. } = &mut changed.operation {
                match field {
                    0 => provenance.request_id = "another-request".into(),
                    1 => provenance.workflow_sha256 = "d".repeat(64),
                    2 => provenance.source_sha256 = "e".repeat(64),
                    _ => provenance.origin = luma_content::EditOrigin::Managed,
                }
            }
            assert!(validate_replay(&changed, &prior).is_err());
        }
        let mut changed = fresh();
        changed.binding.owner_generation += 1;
        assert!(validate_replay(&changed, &prior).is_err());
        let mut changed = fresh();
        if let Operation::Collection { source, .. } = &mut changed.operation {
            source.collection_id = "other-items".into();
        }
        assert!(validate_replay(&changed, &prior).is_err());

        // Identical JSON, immutable receipt and descriptive provenance are not
        // sufficient: an ordinary capture is not a typed collection transaction.
        let generic = Plan::capture(
            request.binding.clone(),
            &source.artifact_id().unwrap(),
            Format::Json,
            &source_bytes,
            provenance,
        )
        .unwrap();
        assert_eq!(generic.resulting(), prior.resulting());
        assert_eq!(
            generic.source_kind(),
            luma_content_store::SourceKind::Content
        );
        assert!(validate_replay(&fresh(), &generic).is_err());
        validate_replay(&fresh(), &prior).unwrap();
    }

    #[test]
    fn managed_render_prevalidation_and_replay_bind_owner_engine_and_exact_request() {
        let mut value = input();
        let request = luma_content::rendered::Request {
            binding: value.binding.clone(),
            artifact_id: "sheet-one".into(),
            expected: None,
            metadata: luma_content::table::EditMetadata {
                request_id: "render-one".into(),
                workflow_sha256: "c".repeat(64),
            },
            engine: luma_content::rendered::Engine::Spreadsheet,
            source: r#"{"schema_version":1,"rows":[[{"kind":"number","value":"2"}]]}"#.into(),
        };
        let prior = Plan::managed_render(None, &request).unwrap();
        value.operation = Operation::Render {
            request: request.clone(),
        };
        let bytes = canonical_request(&serde_json::to_vec(&value).unwrap()).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert!(!parsed.is_query());
        assert_eq!(parsed.source().unwrap(), request.canonical_bytes().unwrap());
        validate_replay(&parsed, &prior).unwrap();
        assert_eq!(
            prior.derivation().unwrap().output_sha256,
            io::digest(b"2\n")
        );
        let mut substitute = value;
        substitute.binding.owner_generation += 1;
        assert!(canonical_request(&serde_json::to_vec(&substitute).unwrap()).is_err());
        substitute.binding = request.binding.clone();
        if let Operation::Render { request } = &mut substitute.operation {
            request.engine = luma_content::rendered::Engine::Document;
            request.source = r#"{"schema_version":1,"title":"x","blocks":[]}"#.into();
        }
        assert!(validate_replay(&substitute, &prior).is_err());
    }

    #[test]
    fn query_requests_are_closed_canonical_data_with_no_mutation_source() {
        for operation in [
            Operation::Current {
                artifact_id: "notes-one".into(),
            },
            Operation::Historical {
                expected: reference(),
            },
            Operation::Page {
                expected: reference(),
                offset: 0,
                bytes: MAX_PAGE_BYTES,
            },
            Operation::Search {
                query: "HELLO world".into(),
                limit: MAX_QUERY_RESULTS,
            },
        ] {
            let input = query_input(operation);
            let bytes = serde_json::to_vec(&input).unwrap();
            let decoded = parse(&bytes).unwrap();
            assert!(decoded.is_query());
            assert!(decoded.source().is_err());
            assert_eq!(canonical_request(&bytes).unwrap(), bytes);
            let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            extra["operation"]["effect_grant"] = serde_json::json!("write-one");
            assert!(canonical_request(&serde_json::to_vec(&extra).unwrap()).is_err());
            let mut newline = bytes.clone();
            newline.push(b'\n');
            assert!(parse(&newline).is_err());
        }
    }

    #[test]
    fn query_identifier_reference_page_and_search_bounds_are_checked_before_private_io() {
        for artifact in ["", ".", "..", "/private", "../private", "a/b", "résumé"] {
            assert!(query_input(Operation::Current {
                artifact_id: artifact.into()
            })
            .validate()
            .is_err());
        }
        assert!(validate_artifact_id(&"a".repeat(129)).is_err());
        for replacement in ["0".repeat(64), "a".repeat(63), "A".repeat(64)] {
            let mut expected = reference();
            expected.content_sha256 = replacement.clone();
            assert!(query_input(Operation::Historical { expected })
                .validate()
                .is_err());
            let mut expected = reference();
            expected.receipt_sha256 = replacement;
            assert!(query_input(Operation::Historical { expected })
                .validate()
                .is_err());
        }
        let mut expected = reference();
        expected.version = 0;
        assert!(query_input(Operation::Historical { expected })
            .validate()
            .is_err());
        for (offset, bytes) in [
            (0, 0),
            (0, MAX_PAGE_BYTES + 1),
            (luma_content::MAX_ENVELOPE_BYTES as u64 + 1, 1),
            (u64::MAX, 1),
        ] {
            assert!(query_input(Operation::Page {
                expected: reference(),
                offset,
                bytes
            })
            .validate()
            .is_err());
        }
        for (query, limit) in [
            ("", 1),
            ("word", 0),
            ("word", MAX_QUERY_RESULTS + 1),
            ("hello!", 1),
            ("résumé", 1),
        ] {
            assert!(query_input(Operation::Search {
                query: query.into(),
                limit
            })
            .validate()
            .is_err());
        }
    }

    #[test]
    fn query_profile_is_exact_read_only_and_cannot_borrow_inspection_or_effect_scope() {
        let input = query_input(Operation::Current {
            artifact_id: "notes-one".into(),
        });
        let bytes = serde_json::to_vec(&input).unwrap();
        let digest = io::digest(&bytes);
        let id = profile_id(Mode::Query, &input, &bytes, &digest).unwrap();
        assert!(query_profile(&id).unwrap());
        assert_eq!(profile(&id).unwrap().review, digest);
        let scope = usage_at(&id, "e".repeat(64), false).unwrap();
        assert_eq!(scope.action, grants::Action::Read);
        assert_eq!(scope.selector.kind, grants::Kind::File);
        assert_eq!(scope.selector.id, "native-content-query-v1");
        assert_eq!(scope.output_bytes, MAX_OUTPUT);
        assert_eq!(scope, usage_at(&id, "e".repeat(64), true).unwrap());
        let inspection = profile_id(Mode::Read, &input, &bytes, &digest).unwrap();
        assert!(!query_profile(&inspection).unwrap());
        assert_ne!(scope, usage_at(&inspection, "e".repeat(64), false).unwrap());
        assert!(profile_id(Mode::Query, &input, &bytes, &"f".repeat(64)).is_err());
        assert!(approval(&format!("query:{digest}")).is_err());
        let read = ResourceBudget {
            memory_bytes: 256 * 1024 * 1024,
            tasks: 1,
            read_bytes: 256 * 1024 * 1024,
            write_bytes: 0,
            additional_storage_bytes: 0,
        };
        validate_budget(Mode::Query, read).unwrap();
        for excess in [
            ResourceBudget {
                write_bytes: 1,
                ..read
            },
            ResourceBudget {
                additional_storage_bytes: 1,
                ..read
            },
        ] {
            assert!(validate_budget(Mode::Query, excess).is_err());
        }
    }

    fn version(content: &[u8]) -> ArtifactVersion {
        let input = input();
        luma_content::capture(
            input.binding,
            "notes-one",
            Format::Utf8Text,
            content,
            Provenance {
                request_id: "query-capture".into(),
                workflow_sha256: "c".repeat(64),
                source_sha256: io::digest(content),
                origin: luma_content::EditOrigin::Managed,
            },
        )
        .unwrap()
    }

    #[test]
    fn immutable_metadata_does_not_return_content_or_advertise_approval() {
        let version = version(b"private unique content\n");
        let value = version_result(&version, None).unwrap();
        assert_eq!(
            value["reference"],
            serde_json::to_value(version.reference().unwrap()).unwrap()
        );
        assert_eq!(
            value["envelope_sha256"],
            io::digest(&version.canonical_envelope().unwrap())
        );
        assert_eq!(value["content_delivered"], false);
        for key in [
            "content",
            "slice_hex",
            "approval",
            "effect_usage",
            "inspection_usage",
        ] {
            assert!(value.get(key).is_none());
        }
        assert!(!serde_json::to_string(&value)
            .unwrap()
            .contains("private unique content"));
        for key in [
            "committed",
            "authority_returned",
            "provenance_authority",
            "workflow_executed",
            "production_qualified",
        ] {
            assert_eq!(value[key], false);
        }
    }

    #[test]
    fn exact_envelope_pages_reassemble_large_utf8_and_control_escape_content_without_ambiguity() {
        let content = format!("{}\n", "é\t=SUM(A1:A2)".repeat(6000));
        let version = version(content.as_bytes());
        let envelope = version.canonical_envelope().unwrap();
        assert!(envelope.len() > MAX_OUTPUT as usize);
        let mut rebuilt = Vec::new();
        let mut at = 0;
        loop {
            let page = version_result(&version, Some((at, MAX_PAGE_BYTES))).unwrap();
            assert_eq!(page["encoding"], "hex");
            assert_eq!(page["envelope_bytes"], envelope.len());
            assert_eq!(page["envelope_sha256"], io::digest(&envelope));
            assert_eq!(
                page["reference"],
                serde_json::to_value(version.reference().unwrap()).unwrap()
            );
            assert!(serde_json::to_vec(&page).unwrap().len() < MAX_OUTPUT as usize);
            let hex = page["slice_hex"].as_str().unwrap();
            assert!(hex.len() <= MAX_PAGE_BYTES as usize * 2);
            for pair in hex.as_bytes().chunks_exact(2) {
                rebuilt.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
            }
            at = page["next_offset"].as_u64().unwrap();
            if page["eof"] == true {
                break;
            }
        }
        assert_eq!(rebuilt, envelope);
        assert_eq!(
            luma_content::reopen(&rebuilt, &input().binding).unwrap(),
            version
        );
        let eof = version_result(&version, Some((envelope.len() as u64, 1))).unwrap();
        assert_eq!(eof["slice_hex"], "");
        assert_eq!(eof["eof"], true);
        assert_eq!(eof["content_delivered"], false);
        assert!(version_result(&version, Some((envelope.len() as u64 + 1, 1))).is_err());
        assert!(version_result(&version, Some((u64::MAX, 1))).is_err());
        assert!(version_result(&version, Some((0, 0))).is_err());
        assert!(version_result(&version, Some((0, MAX_PAGE_BYTES + 1))).is_err());
    }

    struct NoAuthority;
    impl Boundary for NoAuthority {
        fn admit(&mut self, _: &OwnerBinding, _: ResourceBudget) -> luma_content_store::Result<()> {
            panic!("a query must never enter mutation planning or source replay")
        }
        fn check(&mut self, _: Access<'_>) -> luma_content_store::Result<()> {
            panic!("a query must never enter mutation planning or source replay")
        }
    }

    #[test]
    fn every_query_is_rejected_by_mutation_planning_and_operation_replay() {
        let capture = input();
        let prior = plan(&capture, None, &mut NoAuthority).unwrap();
        for operation in [
            Operation::Current {
                artifact_id: "notes-one".into(),
            },
            Operation::Historical {
                expected: reference(),
            },
            Operation::Page {
                expected: reference(),
                offset: 0,
                bytes: 1,
            },
            Operation::Search {
                query: "word".into(),
                limit: 1,
            },
        ] {
            let query = query_input(operation);
            assert!(plan(&query, None, &mut NoAuthority).is_err());
            assert!(validate_replay(&query, &prior).is_err());
        }
    }

    struct DeliverySink {
        bytes: Vec<u8>,
        writes: usize,
        max_write: usize,
        blocked: bool,
        flush_failure: bool,
    }

    impl Write for DeliverySink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(bytes.len() <= 4096);
            self.writes += 1;
            if self.blocked {
                self.blocked = false;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let count = bytes.len().min(self.max_write);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_failure {
                Err(std::io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }

    fn sink() -> DeliverySink {
        DeliverySink {
            bytes: Vec::new(),
            writes: 0,
            max_write: 4096,
            blocked: false,
            flush_failure: false,
        }
    }

    #[test]
    fn bounded_delivery_rechecks_before_each_partial_write_and_after_flush() {
        let value = serde_json::json!({"data":"x".repeat(20000)});
        let mut output = sink();
        output.max_write = 127;
        let checks = std::cell::Cell::new(0);
        deliver_checked(
            &value,
            &mut output,
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            || panic!("a writable sink must not wait"),
        )
        .unwrap();
        let mut expected = serde_json::to_vec(&value).unwrap();
        expected.push(b'\n');
        assert_eq!(output.bytes, expected);
        assert_eq!(checks.get(), output.writes + 2);
    }

    #[test]
    fn delivery_revocation_stops_before_first_next_or_blocked_retry_byte() {
        let value = serde_json::json!({"data":"x".repeat(20000)});
        for fence in [1, 2, 4] {
            let mut output = sink();
            let checks = std::cell::Cell::new(0);
            assert!(deliver_checked(
                &value,
                &mut output,
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == fence {
                        Err("original grant expired".into())
                    } else {
                        Ok(())
                    }
                },
                || Ok(())
            )
            .is_err());
            assert_eq!(output.writes, fence - 1);
            assert_eq!(output.bytes.len(), (fence - 1) * 4096);
        }
        let mut output = sink();
        output.blocked = true;
        let checks = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        assert!(deliver_checked(
            &value,
            &mut output,
            || {
                checks.set(checks.get() + 1);
                if checks.get() >= 3 {
                    Err("consumer wait lost current authority".into())
                } else {
                    Ok(())
                }
            },
            || {
                waits.set(waits.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(waits.get(), 1);
        assert_eq!(output.writes, 1);
        assert!(output.bytes.is_empty());
    }

    #[test]
    fn delivery_refuses_oversize_closed_consumer_and_final_flush_failure() {
        let mut output = sink();
        assert!(deliver_checked(
            &serde_json::json!({"data":"x".repeat(MAX_OUTPUT as usize)}),
            &mut output,
            || panic!("oversized data must be refused before authority work"),
            || Ok(())
        )
        .is_err());
        assert_eq!(output.writes, 0);
        output.max_write = 0;
        assert!(
            deliver_checked(&serde_json::json!({}), &mut output, || Ok(()), || Ok(())).is_err()
        );
        let mut output = sink();
        output.flush_failure = true;
        let checks = std::cell::Cell::new(0);
        assert!(deliver_checked(
            &serde_json::json!({}),
            &mut output,
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            || Ok(())
        )
        .is_err());
        assert_eq!(checks.get(), output.writes + 1);
    }

    #[test]
    fn nonblocking_socket_delivery_never_changes_shared_flags() {
        let (left, mut right) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = left.as_raw_fd();
        for nonblocking in [false, true] {
            left.set_nonblocking(nonblocking).unwrap();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            {
                let mut duplicate = NonblockingOutput::duplicate(fd).unwrap();
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
                duplicate.write_all(b"exact socket").unwrap();
                let mut bytes = [0; 12];
                right.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"exact socket");
            }
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        }
        assert!(NonblockingOutput::duplicate(-1).is_err());
    }

    #[test]
    fn destination_preflight_observes_only_without_changing_shared_flags() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = socket.as_raw_fd();
        for nonblocking in [false, true] {
            socket.set_nonblocking(nonblocking).unwrap();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            output_preflight(fd).unwrap();
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        }
        let regular = anonymous("test-content-destination-preflight", &[], false).unwrap();
        let flags = unsafe { libc::fcntl(regular.as_raw_fd(), libc::F_GETFL) };
        assert!(output_preflight(regular.as_raw_fd()).is_err());
        assert_eq!(
            unsafe { libc::fcntl(regular.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        assert!(output_preflight(-1).is_err());
    }

    #[test]
    fn delivery_rejects_regular_files_and_devices_without_changing_descriptor_flags() {
        let regular = anonymous("test-content-no-direct-export", &[], false).unwrap();
        let flags = unsafe { libc::fcntl(regular.as_raw_fd(), libc::F_GETFL) };
        let error = match NonblockingOutput::duplicate(regular.as_raw_fd()) {
            Ok(_) => panic!("a direct regular-file export must not be admitted"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("direct file export is not admitted"));
        assert_eq!(
            unsafe { libc::fcntl(regular.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        let device = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let flags = unsafe { libc::fcntl(device.as_raw_fd(), libc::F_GETFL) };
        assert!(NonblockingOutput::duplicate(device.as_raw_fd()).is_err());
        assert_eq!(
            unsafe { libc::fcntl(device.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        let invalid = match NonblockingOutput::duplicate(-1) {
            Ok(_) => panic!("invalid descriptor unexpectedly duplicated"),
            Err(error) => error,
        };
        assert_eq!(
            invalid
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn nonblocking_pipe_delivery_never_changes_shared_flags_and_releases_duplicate() {
        for nonblocking in [0, libc::O_NONBLOCK] {
            let mut descriptors = [-1, -1];
            assert_eq!(
                unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | nonblocking) },
                0
            );
            let mut reader = unsafe { File::from_raw_fd(descriptors[0]) };
            let writer = unsafe { File::from_raw_fd(descriptors[1]) };
            let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
            assert!(output_preflight(reader.as_raw_fd()).is_err());
            {
                let mut duplicate = NonblockingOutput::duplicate(writer.as_raw_fd()).unwrap();
                assert_eq!(
                    unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                    flags
                );
                duplicate.write_all(b"exact bounded pipe").unwrap();
            }
            assert_eq!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                flags
            );
            drop(writer);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"exact bounded pipe");
        }
    }

    #[test]
    fn congested_pipe_and_socket_return_would_block_without_changing_inherited_flags() {
        let mut descriptors = [-1, -1];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let _reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { File::from_raw_fd(descriptors[1]) };
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        for fd in [writer.as_raw_fd(), socket.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_eq!(flags & libc::O_NONBLOCK, 0);
            let mut output = NonblockingOutput::duplicate(fd).unwrap();
            let bytes = [b'x'; 4096];
            let mut blocked = false;
            for _ in 0..4096 {
                match output.write(&bytes) {
                    Ok(count) => assert!(count > 0 && count <= bytes.len()),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        blocked = true;
                        break;
                    }
                    Err(error) => panic!("unexpected bounded delivery error: {error}"),
                }
            }
            assert!(
                blocked,
                "disposable destination did not reach bounded backpressure"
            );
            let mut checks = 0;
            assert!(deliver_checked(
                &serde_json::json!({"private":"data"}),
                &mut output,
                || {
                    checks += 1;
                    if checks >= 3 {
                        Err("grant expired under actual backpressure".into())
                    } else {
                        Ok(())
                    }
                },
                || Ok(())
            )
            .is_err());
            assert_eq!(checks, 3);
            drop(output);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        }
    }

    #[test]
    fn destination_identity_substitution_is_refused_and_tty_reopen_has_independent_flags() {
        let first = anonymous("test-output-identity-one", &[], false).unwrap();
        let second = anonymous("test-output-identity-two", &[], false).unwrap();
        assert!(
            check_output_identity(&first.metadata().unwrap(), &second.metadata().unwrap()).is_err()
        );
        check_output_identity(&first.metadata().unwrap(), &first.metadata().unwrap()).unwrap();
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
        {
            let output = NonblockingOutput::duplicate(slave.as_raw_fd()).unwrap();
            assert!(matches!(output.kind, OutputKind::Terminal));
            assert_ne!(
                unsafe { libc::fcntl(output.file.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
                0
            );
            assert_eq!(
                unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) },
                flags
            );
            check_output_identity(&slave.metadata().unwrap(), &output.file.metadata().unwrap())
                .unwrap();
        }
        assert_eq!(
            unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) },
            flags
        );
    }

    struct DisposableChild {
        pid: libc::pid_t,
        waited: bool,
    }

    impl DisposableChild {
        fn kill_and_wait(&mut self) -> i32 {
            assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
            let mut status = 0;
            loop {
                let observed = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if observed == self.pid {
                    self.waited = true;
                    return status;
                }
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted
                );
            }
        }
    }

    impl Drop for DisposableChild {
        fn drop(&mut self) {
            if !self.waited {
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
                let mut status = 0;
                loop {
                    let observed = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                    if observed == self.pid
                        || (observed < 0
                            && std::io::Error::last_os_error().kind()
                                != std::io::ErrorKind::Interrupted)
                    {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn killed_output_holder_cannot_change_surviving_parent_socket_or_pipe_flags() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut descriptors = [-1, -1];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let _reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { File::from_raw_fd(descriptors[1]) };
        for fd in [writer.as_raw_fd(), socket.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            let output = NonblockingOutput::duplicate(fd).unwrap();
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
            let mut acknowledgement = [-1, -1];
            assert_eq!(
                unsafe { libc::pipe2(acknowledgement.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let mut ready = unsafe { File::from_raw_fd(acknowledgement[0]) };
            let notify = unsafe { File::from_raw_fd(acknowledgement[1]) };
            // Construct Rust-owned state before fork. The disposable child
            // performs only async-signal-safe libc calls before SIGKILL.
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                unsafe {
                    libc::close(ready.as_raw_fd());
                    if libc::write(notify.as_raw_fd(), b"r".as_ptr().cast(), 1) != 1 {
                        libc::_exit(90);
                    }
                    loop {
                        libc::pause();
                    }
                }
            }
            let mut child = DisposableChild {
                pid: child,
                waited: false,
            };
            drop(notify);
            drop(output);
            let mut poll = libc::pollfd {
                fd: ready.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
            let mut byte = [0];
            ready.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"r");
            let status = child.kill_and_wait();
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        }
    }

    #[test]
    fn inherited_root_pipe_can_be_delivered_by_uid65534_without_procfd_reopen() {
        const CHILD: &str = "LUMA_CONTENT_DELIVERY_UID_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert_eq!(unsafe { libc::geteuid() }, 65534);
            let pinned = checked_output(2).unwrap();
            assert_eq!(pinned.metadata().unwrap().uid(), 0);
            let reopen = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
            assert_eq!(reopen.unwrap_err().raw_os_error(), Some(libc::EACCES));
            let flags = unsafe { libc::fcntl(2, libc::F_GETFL) };
            output_preflight(2).unwrap();
            let mut output = NonblockingOutput::duplicate(2).unwrap();
            output.write_all(b"restricted-pipe-ready").unwrap();
            assert_eq!(unsafe { libc::fcntl(2, libc::F_GETFL) }, flags);
            return;
        }
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "this UID-boundary fixture requires the isolated native-tools root test container"
        );
        use std::os::unix::process::CommandExt;
        let mut descriptors = [-1, -1];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { File::from_raw_fd(descriptors[1]) };
        assert_eq!(writer.metadata().unwrap().mode() & 0o777, 0o600);
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        // The root-owned compiler cache need not be traversable by nobody.
        // Copy only this disposable test executable, never product authority.
        use std::os::unix::fs::DirBuilderExt;
        let fixture = std::env::temp_dir().join(format!(
            "luma-content-delivery-{}-{}",
            std::process::id(),
            crate::resources::random_id().unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o711)
            .create(&fixture)
            .unwrap();
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o711)).unwrap();
        let executable = fixture.join("delivery-tests");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut command = Command::new(&executable);
        command.args(["--exact", "content_governed::tests::inherited_root_pipe_can_be_delivered_by_uid65534_without_procfd_reopen", "--nocapture"])
            .env(CHILD, "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(writer.try_clone().unwrap()));
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) < 0
                    || libc::setresgid(65534, 65534, 65534) < 0
                    || libc::setresuid(65534, 65534, 65534) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(command);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("disposable UID-boundary delivery child exceeded its deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        drop(writer);
        let mut bytes = Vec::new();
        reader.take(65537).read_to_end(&mut bytes).unwrap();
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(fixture).unwrap();
        assert!(
            status.success(),
            "UID-boundary child failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(bytes, b"restricted-pipe-ready");
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
            (Mode::Recover, grants::Action::Retain),
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
            if mode == Mode::Recover {
                assert_eq!(effect.selector.id, "native-content-recovery-v1");
                assert_ne!(effect.selector.id, "native-content-store-v1");
            }
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
        assert_eq!(
            approval(&format!("recover:{digest}")).unwrap(),
            (Mode::Recover, digest.as_str())
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
