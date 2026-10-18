//! Exact reviewed encrypted export. Laboratory manual recipients and genuine
//! separately governed C custody are distinct closed modes. The original PAM
//! client retains its live Read/Export pair; no worker receives TPM secrets.
use crate::{
    artifacts as io, backup_crypto as crypto, finite_grants as grants, resource_manager, Result,
};
use luma_content::OwnerBinding;
use luma_content_store::{
    Access, BackupBoundary, BackupBudget, BackupReview, Boundary, Repository, ResourceBudget,
};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[path = "content_capsule.rs"]
pub(crate) mod capsule;
#[path = "backup_confinement.rs"]
mod confinement;
pub(crate) use capsule::inspect as inspect_capsule;
pub(crate) use capsule::verify_stdin as verify_capsule_stdin;

pub(crate) const PREFIX: &str = "backup-export-v1-";
pub(crate) const MAX_REQUEST: usize = 65536;
pub(crate) const MEMORY: u64 = (256 + 704) * 1024 * 1024;
pub(crate) const LOCKED: u64 = 640 * 1024 * 1024;
pub(crate) const TASKS: u64 = 4;
const MAX_META: usize = 65536;
pub(crate) const MAX_EXPORT_BYTES: u64 =
    (20 + MAX_META + crypto::MAX_ENCRYPTED_BACKUP_BYTES) as u64;
const DIRECTORY: &str = "/var/lib/luma-os/content-store";
const READ_ID: &str = "native-content-backup-read-v1";
const EXPORT_ID: &str = "native-content-backup-export-v1";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const MAGIC: &[u8; 16] = b"LUMACMSFRAME01!\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) schema_version: u32,
    pub(crate) login: String,
    pub(crate) binding: OwnerBinding,
    pub(crate) review: BackupReview,
    pub(crate) recipient_choice: String,
    pub(crate) recipients: crypto::RecipientPins,
    pub(crate) owner_certificate_der_hex: String,
    pub(crate) offline_admin_certificate_der_hex: String,
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 16384
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("backup certificate must be bounded canonical DER hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

impl Input {
    pub(crate) fn validate(&self) -> Result<()> {
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
            return Err("invalid closed encrypted backup request".into());
        }
        self.custody_generation()?;
        self.recipient_data()?;
        Ok(())
    }
    pub(crate) fn custody_generation(&self) -> Result<Option<u64>> {
        if self.recipient_choice == "explicit-manual-laboratory-v1" {
            return Ok(None);
        }
        let value = self
            .recipient_choice
            .strip_prefix("governed-content-custody-v1-")
            .ok_or("backup must explicitly select laboratory or governed recipient custody")?;
        let generation: u64 = value.parse()?;
        if generation == 0 || generation.to_string() != value {
            return Err("backup custody generation must be canonical and positive".into());
        }
        Ok(Some(generation))
    }
    pub(crate) fn recipient_data(&self) -> Result<crypto::Recipients> {
        crypto::Recipients::new(
            &unhex(&self.owner_certificate_der_hex)?,
            &unhex(&self.offline_admin_certificate_der_hex)?,
            self.recipients.clone(),
        )
    }
}

fn parse(bytes: &[u8], exact: bool) -> Result<Input> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("backup request exceeds fixed bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    input.validate()?;
    if exact && serde_json::to_vec(&input)? != bytes {
        return Err("backup request must use exact canonical transport".into());
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
        return Err("canonical backup request exceeds fixed bound".into());
    }
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"canonical_request":String::from_utf8(canonical.clone())?,
        "request_sha256":io::digest(&canonical),"owner_authenticated":false,"private_content_read":false,
        "recipient_custody_qualified":false,"authority_returned":false,"committed":false})
    );
    Ok(())
}

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
        return Err("backup request must be bounded single-link regular data".into());
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
        return Err("backup request changed during bounded capture".into());
    }
    parse(&bytes, true)?;
    Ok(bytes)
}

pub(crate) fn parse_profile(id: &str) -> Result<(u64, u64, &str)> {
    let suffix = id
        .strip_prefix(PREFIX)
        .ok_or("unknown backup export profile")?;
    let mut fields = suffix.split('-');
    let generation = fields.next().ok_or("missing backup generation")?;
    let archive = fields.next().ok_or("missing backup byte count")?;
    let sha = fields.next().ok_or("missing backup request digest")?;
    let number: u64 = generation.parse()?;
    let bytes: u64 = archive.parse()?;
    if number == 0
        || number.to_string() != generation
        || !io::hash(sha)
        || fields.next().is_some()
        || bytes == 0
        || bytes > luma_content_store::MAX_CONTENT_BACKUP_BYTES as u64
        || bytes.to_string() != archive
    {
        return Err("invalid exact backup export profile".into());
    }
    Ok((number, bytes, sha))
}

pub(crate) fn source_digest(id: &str) -> Result<&str> {
    Ok(parse_profile(id)?.2)
}

pub(crate) fn profile(input: &Input, bytes: &[u8]) -> Result<String> {
    let id = format!(
        "{PREFIX}{}-{}-{}",
        input.binding.owner_generation,
        input.review.archive_bytes,
        io::digest(bytes)
    );
    parse_profile(&id)?;
    Ok(id)
}

pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    binding_for(id, device, &io::installation()?)
}
fn binding_for(id: &str, device: &str, installation: &str) -> Result<String> {
    parse_profile(id)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("invalid backup storage identity")?;
    if major == "0"
        || [major, minor]
            .iter()
            .any(|s| s.parse::<u32>().map_or(true, |v| v.to_string() != *s))
    {
        return Err("backup requires canonical installed block storage".into());
    }
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-lab-content-backup-export-v1",
        installation,
        id,
        device,
    ))?))
}

fn uses_at(generation: u64, archive_bytes: u64, digest: &str) -> Result<[grants::Use; 2]> {
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
        output_bytes: MAX_EXPORT_BYTES,
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
        return Err("backup requires independent Read/Export grants".into());
    }
    let reader = uses
        .iter()
        .position(|(_, u)| {
            u.action == grants::Action::Read
                && u.selector.kind == grants::Kind::File
                && u.selector.id == READ_ID
        })
        .ok_or("backup exact Read grant absent")?;
    let exporter = 1 - reader;
    let r = &uses[reader].1;
    let e = &uses[exporter].1;
    for (grant, usage) in uses {
        if !crate::admin_roles::identifier(grant) {
            return Err("invalid backup grant ID".into());
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
        || r.input_bytes > luma_content_store::MAX_CONTENT_BACKUP_BYTES as u64
        || r.output_bytes != 8192
        || e.output_bytes != MAX_EXPORT_BYTES
        || r.units != 1
        || e.units != 1
        || requested != e
    {
        return Err("backup acquisition differs from its complete exact Read/Export pair".into());
    }
    Ok(exporter)
}

pub(crate) fn export_pair(
    uses: &[(String, grants::Use)],
    requested: &grants::Use,
    purpose: crate::authentication::SessionPurpose,
) -> Result<usize> {
    if purpose != crate::authentication::SessionPurpose::Export {
        return Err("backup Read/Export pair requires its original Export-only session".into());
    }
    pair(uses, requested)
}

pub(crate) fn acquisition_usage(id: &str) -> Result<grants::Use> {
    custody_usage(
        id,
        &resource_manager::storage_device(Path::new("/var"))?,
        &io::installation()?,
    )
}
pub(crate) fn custody_usage(id: &str, device: &str, installation: &str) -> Result<grants::Use> {
    if !io::hash(installation) {
        return Err("backup custody installation digest is invalid".into());
    }
    let (generation, archive_bytes, _) = parse_profile(id)?;
    let digest = binding_for(id, device, installation)?;
    Ok(uses_at(generation, archive_bytes, &digest)?[1].clone())
}

fn snapshot_path(path: &Path) -> bool {
    path.to_str()
        .and_then(|p| p.strip_prefix("/run/luma-granted-client/requests/"))
        .and_then(|p| p.strip_suffix("/content-backup.json"))
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
    if args.len() != 9
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != "content-backup-export"
        || !args[8].is_empty()
        || args[6] != "--export-channel"
        || args[3] == args[4]
        || !crate::admin_roles::identifier(args[3])
        || !crate::admin_roles::identifier(args[4])
        || !snapshot_path(Path::new(args[5]))
    {
        return Err(
            "backup proof lacks exact original export command and independent grants".into(),
        );
    }
    let relay = Path::new(args[7]);
    let relay_parent = relay
        .parent()
        .ok_or("backup original relay parent absent")?;
    if relay.file_name().and_then(|part| part.to_str()) != Some("output.sock")
        || relay_parent.parent() != Some(Path::new("/run/luma-granted-client/payloads"))
    {
        return Err("backup proof lacks its exact original binary relay namespace".into());
    }
    crate::tpm::decode::<16>(
        relay_parent
            .file_name()
            .and_then(|part| part.to_str())
            .ok_or("backup relay identity absent")?,
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
        return Err("backup original binary relay inode is unsafe".into());
    }
    for parent in Path::new(args[5])
        .parent()
        .ok_or("missing backup snapshot parent")?
        .ancestors()
    {
        let m = std::fs::symlink_metadata(parent)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || (parent.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700)
        {
            return Err("backup proof snapshot namespace is not protected".into());
        }
    }
    let m = std::fs::symlink_metadata(args[5])?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o400
    {
        return Err("backup proof snapshot is not immutable private input".into());
    }
    let bytes = read_request(Path::new(args[5]))?;
    let input = parse(&bytes, true)?;
    if io::digest(&bytes) != sha
        || input.login != args[2]
        || input.binding.owner_generation != generation
        || input.review.archive_bytes != archive_bytes
    {
        return Err("backup original command differs from exact admitted source".into());
    }
    if let Some(audit) = audit {
        audit.validate()?;
        if audit.subject != input.binding.owner
            || audit.subject_generation != generation
            || audit.grant_id != args[4]
            || audit.usage != acquisition_usage(id)?
        {
            return Err("backup proof substitutes its exact current owner or Export scope".into());
        }
    }
    Ok(())
}

pub(crate) fn check_worker(id: &str, device: &str, pid: u32) -> Result<()> {
    parse_profile(id)?;
    if pid == 0 || device != resource_manager::storage_device(Path::new("/var"))? {
        return Err("backup worker storage identity differs".into());
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/cmdline"))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes
        != format!("/usr/libexec/luma-os/luma-platform\0content-backup-resource-worker\0{id}\0")
            .as_bytes()
    {
        return Err("backup worker command is not its exact fixed profile".into());
    }
    Ok(())
}

struct Live<'a> {
    input: &'a Input,
    registry: crate::principal::RegistryBinding,
    account: crate::principal::Principal,
    lease: &'a resource_manager::WorkerLease,
    confinement: confinement::KernelUnix,
    protected: Option<(&'a str, luma_content_store::VerifiedState)>,
}
impl Live<'_> {
    fn local_check(&self, binding: &OwnerBinding) -> Result<()> {
        self.confinement.check()?;
        if binding != &self.input.binding
            || self.account.id != binding.owner
            || self.account.generation > binding.owner_generation
            || !self.account.enabled
        {
            return Err("backup current principal/generation differs".into());
        }
        self.registry.current()?;
        self.lease.check()
    }
    fn check(&self, binding: &OwnerBinding) -> Result<()> {
        self.local_check(binding)?;
        if let Some((profile, expected)) = &self.protected {
            let actual = crate::content_checkpoint::custody::backup_cut(
                profile,
                self.input,
                self.lease.token(),
            )?;
            if &actual != expected {
                return Err("backup protected source or recipient custody changed".into());
            }
        }
        self.local_check(binding)
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
            return Err("backup Read exceeds its separately admitted store baseline".into());
        }
        self.0.check(binding)
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } => self.0.check(binding),
            _ => Err("backup Read cannot mutate or retire content".into()),
        }
    }
}
struct Exporter<'a>(&'a Live<'a>);
impl BackupBoundary for Exporter<'_> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: BackupBudget,
    ) -> luma_content_store::Result<()> {
        if budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.archive_bytes != self.0.input.review.archive_bytes
        {
            return Err("backup Export exceeds exact reviewed data/baseline".into());
        }
        self.0.check(binding)
    }
    fn check(
        &mut self,
        binding: &OwnerBinding,
        manifest: Option<&str>,
    ) -> luma_content_store::Result<()> {
        if manifest != Some(self.0.input.review.manifest_sha256.as_str()) {
            return Err("backup Export substitutes its exact reviewed manifest".into());
        }
        self.0.check(binding)
    }
}
struct Encryptor<'a>(&'a Live<'a>);
fn crypto_budget(budget: crypto::CryptoBudget) -> Result<()> {
    if budget.child_memory_bytes != 512 * 1024 * 1024
        || budget.parent_memory_bytes != 192 * 1024 * 1024
        || budget.aggregate_memory_bytes != 704 * 1024 * 1024
        || budget.aggregate_locked_bytes != LOCKED
        || budget.maximum_output_bytes != crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64
        || budget.tasks != 2
        || budget.maximum_seconds != 1800
    {
        return Err("backup crypto budget differs from actual reserved fixed profile".into());
    }
    Ok(())
}
impl crypto::CryptoBoundary for Encryptor<'_> {
    fn admit(
        &mut self,
        request: &crypto::CryptoRequest,
        budget: crypto::CryptoBudget,
    ) -> Result<()> {
        crypto_budget(budget)?;
        self.check(request)
    }
    fn check(&mut self, request: &crypto::CryptoRequest) -> Result<()> {
        if request.schema_version != 1
            || request.operation != crypto::CryptoOperation::Encrypt
            || request.input_sha256 != self.0.input.review.archive_sha256
            || request.input_bytes != self.0.input.review.archive_bytes
            || request.recipients != self.0.input.recipients
        {
            return Err("backup crypto request differs from exact live reviewed Export".into());
        }
        self.0.check(&self.0.input.binding)
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
    encryption: crypto::EncryptionCommitment,
    custody_receipt: Option<crate::content_checkpoint::custody::BackupReceipt>,
    recipient_custody_qualified: bool,
    sender_authenticated: bool,
    production_qualified: bool,
    restore_permitted: bool,
}

fn worker(id: &str) -> Result<()> {
    let confinement = confinement::KernelUnix::capture()?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-content-backup (enforce)\n"
        || unsafe { libc::fcntl(0, libc::F_GET_SEALS) } != SEALS
    {
        return Err("backup worker lacks its fixed confinement or sealed request".into());
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
    if crate::platform::production_image()? && input.custody_generation()?.is_none() {
        return Err("production backup requires explicitly governed content custody".into());
    }
    if profile(&input, &bytes)? != id {
        return Err("backup sealed request differs from exact admission".into());
    }
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let account = registry
        .current()?
        .account(&input.login)
        .ok_or("backup principal missing")?
        .clone();
    if registry.current()?.installation() != input.binding.installation {
        return Err("backup installation differs from original current principal".into());
    }
    let protected = if input.custody_generation()?.is_some() {
        Some((
            id,
            crate::content_checkpoint::custody::backup_cut(id, &input, lease.token())?,
        ))
    } else {
        None
    };
    let live = Live {
        input: &input,
        registry,
        account,
        lease: &lease,
        confinement,
        protected,
    };
    live.check(&input.binding)?;
    let mut repository =
        Repository::open_at(Path::new(DIRECTORY), &input.binding, &mut Reader(&live))?;
    if let Some((_, state)) = &live.protected {
        repository.require_state(state, &mut Reader(&live))?;
    }
    let backup = repository.backup_data(&input.review, &mut Reader(&live), &mut Exporter(&live))?;
    let encrypted =
        crypto::encrypt_backup_data(&backup, &input.recipient_data()?, &mut Encryptor(&live))?;
    let custody_receipt = if input.custody_generation()?.is_some() {
        Some(crate::content_checkpoint::custody::backup_receipt(
            id,
            &input,
            lease.token(),
            encrypted.commitment(),
            encrypted.bytes(),
            &mut || live.local_check(&input.binding),
        )?)
    } else {
        None
    };
    live.check(&input.binding)?;
    let metadata = Metadata {
        schema_version: 1,
        request_sha256: io::digest(&bytes),
        binding: binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        lease: lease.token().clone(),
        review_sha256: input.review.review_sha256.clone(),
        encryption: encrypted.commitment().clone(),
        recipient_custody_qualified: custody_receipt.is_some(),
        sender_authenticated: custody_receipt.is_some(),
        custody_receipt,
        production_qualified: false,
        restore_permitted: false,
    };
    let meta = serde_json::to_vec(&metadata)?;
    if meta.len() > MAX_META {
        return Err("backup encrypted commitment metadata exceeds bound".into());
    }
    lease.complete_output(&io::digest(&meta))?;
    let mut output = std::io::stdout().lock();
    live.check(&input.binding)?;
    output.write_all(MAGIC)?;
    output.write_all(&(meta.len() as u32).to_be_bytes())?;
    output.write_all(&meta)?;
    for chunk in encrypted.bytes().chunks(32768) {
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
    if file.metadata()?.len() > (20 + MAX_META + crypto::MAX_ENCRYPTED_BACKUP_BYTES) as u64 {
        return Err("backup worker output exceeds fixed ciphertext bound".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("backup worker output has wrong fixed framing".into());
    }
    let mut length = [0u8; 4];
    file.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_META {
        return Err("backup worker commitment exceeds fixed bound".into());
    }
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)?;
    let metadata: Metadata = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&metadata)? != bytes {
        return Err("backup worker metadata is not exact canonical data".into());
    }
    validate_metadata(
        &metadata,
        input,
        id,
        &binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
    )?;
    let at = 20 + length as u64;
    if file.metadata()?.len() != at + metadata.encryption.cms_bytes {
        return Err("backup ciphertext length differs".into());
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
    if crate::bundle::hex(&hash.finalize()) != metadata.encryption.cms_sha256 {
        return Err("backup ciphertext digest differs".into());
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
    validate_encryption(&metadata.encryption, input)?;
    if let Some(receipt) = &metadata.custody_receipt {
        receipt.check_data(input, &metadata.encryption)?;
    }
    let governed = input.custody_generation()?.is_some();
    if metadata.schema_version != 1
        || metadata.request_sha256 != source_digest(id)?
        || metadata.binding != expected_binding
        || !crate::workflow_resource::token_valid(&metadata.lease)
        || metadata.review_sha256 != input.review.review_sha256
        || metadata.custody_receipt.is_some() != governed
        || metadata.recipient_custody_qualified != governed
        || metadata.sender_authenticated != governed
        || metadata.production_qualified
        || metadata.restore_permitted
    {
        return Err(
            "backup encrypted output substitutes exact review, recipients, or authority".into(),
        );
    }
    Ok(())
}
pub(crate) fn validate_encryption(
    encryption: &crypto::EncryptionCommitment,
    input: &Input,
) -> Result<()> {
    input.validate()?;
    if encryption.schema_version != 1
        || encryption.profile != "cms-auth-enveloped-aes256gcm-rsa-oaep-sha256-two-recipients-v1"
        || encryption.archive_sha256 != input.review.archive_sha256
        || encryption.archive_bytes != input.review.archive_bytes
        || encryption.recipients != input.recipients
        || encryption.cms_bytes == 0
        || encryption.cms_bytes > crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64
        || !io::hash(&encryption.cms_sha256)
        || encryption.authenticates_sender
        || encryption.proves_both_recipients_recoverable
        || encryption.permits_restore
    {
        return Err("ciphertext commitment differs from exact reviewed encrypted data".into());
    }
    Ok(())
}

fn verify_receipt(metadata: &Metadata) -> Result<()> {
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(metadata.lease.clone());
    let receipt = crate::service::resource_exchange(&request)?
        .status
        .ok_or("backup resource receipt missing")?;
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
            "backup ciphertext has no matching unfenced current output-generation receipt".into(),
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
    match pending {
        Some(pending) => guard.stream_check(pending)?,
        None => guard.check()?,
    }
    if guard.session_purpose() != crate::authentication::SessionPurpose::Export
        || guard.subject()? != input.binding.owner
        || guard.subject_generation()? != input.binding.owner_generation
    {
        return Err("backup current original Export principal changed".into());
    }
    let (registry, account, installation) =
        crate::admin_governance::current_principal(&input.login)?;
    registry.current()?;
    if installation != input.binding.installation
        || account.id != input.binding.owner
        || account.generation != input.binding.owner_generation
        || !account.enabled
        || account.uid != guard.subject_uid()?
    {
        return Err("backup installed current principal differs".into());
    }
    match pending {
        Some(pending) => guard.stream_check(pending),
        None => guard.check(),
    }
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let production = crate::platform::production_image()?;
    if args.first().map(String::as_str) == Some("content-backup-resource-worker") && args.len() == 2
    {
        return worker(&args[1]);
    }
    let proposal = args.first().map(String::as_str) == Some("content-backup-export-proposal")
        && args.len() == 3;
    let export =
        args.first().map(String::as_str) == Some("content-backup-export") && args.len() == 5;
    if !proposal && !export {
        return Err("expected content-backup-export-proposal LOGIN REQUEST | content-backup-export LOGIN READ-GRANT EXPORT-GRANT REQUEST".into());
    }
    let bytes = read_request(Path::new(args.last().ok_or("backup request absent")?))?;
    let input = parse(&bytes, true)?;
    if production {
        crate::platform::require_production_activation()?;
        if input.custody_generation()?.is_none() {
            return Err("production export refuses manually selected laboratory recipients".into());
        }
    }
    if input.login != args[1] {
        return Err("backup command login differs from request".into());
    }
    let id = profile(&input, &bytes)?;
    let digest = binding(&id, &resource_manager::storage_device(Path::new("/var"))?)?;
    let uses = uses_at(
        input.binding.owner_generation,
        input.review.archive_bytes,
        &digest,
    )?;
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"request_sha256":source_digest(&id)?,"read_usage":uses[0],
            "export_usage":uses[1],"review_sha256":input.review.review_sha256,"recipients":input.recipients,
            "review_verified_against_current_private_history":false,"recipient_custody_qualified":false,
            "owner_authenticated":false,"private_content_read":false,"grant_issued":false,"archive_delivered":false,"restore_permitted":false})
        );
        return Ok(());
    }
    if !snapshot_path(Path::new(&args[4])) {
        return Err("backup export requires its original private launcher snapshot".into());
    }
    let uses = [
        (args[2].clone(), uses[0].clone()),
        (args[3].clone(), uses[1].clone()),
    ];
    crate::admin_governance::with_backup_export_grants(&input.login, &uses, |guard| {
        subject(&input, guard, None)?;
        let pending = guard.effect_begin(
            source_digest(&id)?,
            crate::policy_decisions::EffectKind::ArtifactExport,
        )?;
        resource_manager::storage_device(Path::new("/var"))?;
        crate::acquisition::await_drainage_checked(&mut || subject(&input, guard, Some(&pending)))?;
        let mut captured = crate::service::granted_acquisition::run_backup(
            &id,
            &uses[1].1,
            guard,
            &pending,
            |check| {
                check()?;
                let request = memory_file("luma-content-backup-request", &bytes, true)?;
                let output = memory_file("luma-content-backup-output", &[], false)?;
                let mut command = Command::new("/usr/bin/systemd-run");
                command
                    .args(crate::acquisition::arguments(
                        Path::new("/var"),
                        &id,
                        "backup-export",
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
                            > (20 + MAX_META + crypto::MAX_ENCRYPTED_BACKUP_BYTES) as u64
                    {
                        return Err(
                            "backup controller output/deadline bound lost; no drainage claim"
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
        // Governed output retains the measured portable custody receipt. Raw
        // CMS alone deliberately remains only the legacy laboratory format.
        captured
            .file
            .seek(SeekFrom::Start(if input.custody_generation()?.is_some() {
                0
            } else {
                captured.at
            }))?;
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
pub(crate) fn test_input() -> Input {
    tests::fixture()
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> Input {
        use luma_content_store::{
            BackupArea, BackupAreaReview, BackupNamespace, PreparationDirectoryIdentity,
        };
        let binding = OwnerBinding {
            installation: "ab".repeat(32),
            owner: "cd".repeat(32),
            owner_generation: 7,
        };
        let identity = PreparationDirectoryIdentity {
            device: 1,
            inode: 2,
            owner: 0,
            group: 0,
            mode: libc::S_IFDIR | 0o700,
        };
        let mut review = BackupReview {
            schema_version: 1,
            binding: binding.clone(),
            source_namespace: BackupNamespace {
                root: identity.clone(),
                committed: identity.clone(),
                pending: identity,
                quarantined: None,
            },
            committed_outcomes: 0,
            committed_head_sha256: luma_content_store::VerifiedState::empty(&binding)
                .unwrap()
                .head_sha256,
            data_bytes: 0,
            areas: [
                BackupArea::Committed,
                BackupArea::Pending,
                BackupArea::Quarantined,
            ]
            .into_iter()
            .map(|area| BackupAreaReview {
                area,
                directories: 0,
                members: 0,
                bytes: 0,
                sha256: io::digest(b"[]"),
            })
            .collect(),
            manifest_sha256: "12".repeat(32),
            archive_sha256: "34".repeat(32),
            archive_bytes: 21,
            review_sha256: String::new(),
        };
        review.review_sha256 = io::digest(
            &serde_json::to_vec(&(
                "luma-content-data-backup-review-v1",
                review.schema_version,
                &review.binding,
                &review.source_namespace,
                review.committed_outcomes,
                &review.committed_head_sha256,
                review.data_bytes,
                &review.areas,
                &review.manifest_sha256,
                &review.archive_sha256,
                review.archive_bytes,
            ))
            .unwrap(),
        );
        // These inert byte fixtures test transport/pinning only. Actual DER,
        // RSA and SPKI parsing is separately enforced in the fixed C helper.
        Input {
            schema_version: 1,
            login: "alice".into(),
            binding,
            review,
            recipient_choice: "explicit-manual-laboratory-v1".into(),
            recipients: crypto::RecipientPins {
                owner: crypto::RecipientPin {
                    certificate_sha256: io::digest(&[1]),
                    spki_sha256: "56".repeat(32),
                },
                offline_admin: crypto::RecipientPin {
                    certificate_sha256: io::digest(&[2]),
                    spki_sha256: "78".repeat(32),
                },
            },
            owner_certificate_der_hex: "01".into(),
            offline_admin_certificate_der_hex: "02".into(),
        }
    }
    #[test]
    fn transport_is_closed_canonical_bounded_and_exactly_reviewed() {
        let input = fixture();
        input.validate().unwrap();
        let bytes = serde_json::to_vec(&input).unwrap();
        assert!(parse(&bytes, true).is_ok());
        let mut pretty = bytes.clone();
        pretty.push(b'\n');
        assert!(parse(&pretty, false).is_ok());
        assert!(parse(&pretty, true).is_err());
        for key in [
            "output_path",
            "private_key",
            "restore",
            "authority",
            "session_seconds",
        ] {
            let mut value = serde_json::to_value(&input).unwrap();
            value[key] = "forged".into();
            assert!(parse(&serde_json::to_vec(&value).unwrap(), false).is_err());
        }
        for field in [
            "owner_certificate_der_hex",
            "offline_admin_certificate_der_hex",
        ] {
            let mut value = serde_json::to_value(&input).unwrap();
            value[field] = "03".into();
            assert!(parse(&serde_json::to_vec(&value).unwrap(), false).is_err());
        }
        let mut changed = input.clone();
        changed.binding.owner_generation += 1;
        assert!(changed.validate().is_err());
        let mut changed = input.clone();
        changed.review.archive_sha256 = "90".repeat(32);
        assert!(changed.validate().is_err());
        let mut changed = input.clone();
        changed.recipients.offline_admin.spki_sha256 = changed.recipients.owner.spki_sha256.clone();
        assert!(changed.validate().is_err());
        assert!(parse(&vec![b' '; MAX_REQUEST + 1], false).is_err());
        assert!(unhex("0A").is_err());
        assert!(unhex("0").is_err());
        assert!(unhex(&"00".repeat(8193)).is_err());
    }
    #[test]
    fn governed_custody_choice_is_exact_positive_generation_not_a_boolean_upgrade() {
        let mut input = fixture();
        assert_eq!(input.custody_generation().unwrap(), None);
        input.recipient_choice = "governed-content-custody-v1-7".into();
        assert_eq!(input.custody_generation().unwrap(), Some(7));
        input.validate().unwrap();
        let canonical = serde_json::to_vec(&input).unwrap();
        let governed = profile(&input, &canonical).unwrap();
        for invalid in [
            "production",
            "governed-content-custody-v1-0",
            "governed-content-custody-v1-07",
            "governed-content-custody-v1-+7",
            "governed-content-custody-v1-7-extra",
            "explicit-manual-laboratory-v1 ",
        ] {
            input.recipient_choice = invalid.into();
            assert!(input.validate().is_err(), "{invalid}");
        }
        input.recipient_choice = "explicit-manual-laboratory-v1".into();
        let laboratory = profile(&input, &serde_json::to_vec(&input).unwrap()).unwrap();
        assert_ne!(governed, laboratory);
        assert_eq!(
            MAX_EXPORT_BYTES,
            20 + MAX_META as u64 + crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64
        );
        assert!(MAX_EXPORT_BYTES > crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64);
    }
    #[test]
    fn profile_is_exact_and_cannot_borrow_standard_content_or_byte_bounds() {
        let input = fixture();
        let bytes = serde_json::to_vec(&input).unwrap();
        let id = profile(&input, &bytes).unwrap();
        assert_eq!(
            parse_profile(&id).unwrap(),
            (7, 21, io::digest(&bytes).as_str())
        );
        for suffix in [
            format!("0-21-{}", io::digest(&bytes)),
            format!("07-21-{}", io::digest(&bytes)),
            format!("7-021-{}", io::digest(&bytes)),
            format!("7-0-{}", io::digest(&bytes)),
            format!(
                "7-{}-{}",
                luma_content_store::MAX_CONTENT_BACKUP_BYTES + 1,
                io::digest(&bytes)
            ),
            format!("7-21-{}-extra", io::digest(&bytes)),
            format!("7-21-{}", io::digest(&bytes).to_uppercase()),
        ] {
            assert!(parse_profile(&format!("{PREFIX}{suffix}")).is_err());
        }
        assert!(parse_profile(&id.replacen(PREFIX, "content-v1-", 1)).is_err());
        assert!(!snapshot_path(Path::new("/tmp/content-backup.json")));
        assert!(!snapshot_path(Path::new(
            "/run/luma-granted-client/requests/abcdef/content-backup.json"
        )));
        assert!(snapshot_path(Path::new(&format!(
            "/run/luma-granted-client/requests/{}/content-backup.json",
            "ab".repeat(16)
        ))));
    }
    #[test]
    fn backup_requires_both_exact_independent_scopes_and_export_purpose() {
        use crate::authentication::SessionPurpose;
        let usages = uses_at(7, 21, &"ab".repeat(32)).unwrap();
        let uses = vec![
            ("read-backup".into(), usages[0].clone()),
            ("export-backup".into(), usages[1].clone()),
        ];
        assert_eq!(pair(&uses, &usages[1]).unwrap(), 1);
        assert_eq!(
            pair(&[uses[1].clone(), uses[0].clone()], &usages[1]).unwrap(),
            0
        );
        for purpose in [
            SessionPurpose::Standard,
            SessionPurpose::ModelImport,
            SessionPurpose::ModelActivation,
            SessionPurpose::ModelQa,
        ] {
            assert!(export_pair(&uses, &usages[1], purpose).is_err());
        }
        assert!(export_pair(&uses, &usages[1], SessionPurpose::Export).is_ok());
        assert!(pair(&uses[..1], &usages[1]).is_err());
        assert!(pair(&uses, &usages[0]).is_err());
        for field in 0..9 {
            let mut changed = uses.clone();
            match field {
                0 => changed[1].0 = changed[0].0.clone(),
                1 => changed[0].1.action = grants::Action::Write,
                2 => changed[1].1.action = grants::Action::Read,
                3 => changed[1].1.selector.kind = grants::Kind::File,
                4 => changed[1].1.selector.generation += 1,
                5 => changed[1].1.selector.digest = "cd".repeat(32),
                6 => changed[1].1.input_bytes += 1,
                7 => changed[0].1.output_bytes += 1,
                8 => changed[1].1.units += 1,
                _ => unreachable!(),
            }
            assert!(
                pair(&changed, &changed[1].1).is_err(),
                "substitution {field}"
            );
        }
        let mut changed = uses.clone();
        changed[1].1.output_bytes += 1;
        assert!(pair(&changed, &changed[1].1).is_err());
        let mut changed = uses.clone();
        changed[0].1.selector.id = "native-content-inspect-v1".into();
        assert!(pair(&changed, &changed[1].1).is_err());
    }
    #[test]
    fn crypto_budget_is_additional_not_an_unlimited_parent_or_standard_worker() {
        let budget = crypto::CryptoBudget {
            child_memory_bytes: 512 * 1024 * 1024,
            parent_memory_bytes: 192 * 1024 * 1024,
            aggregate_memory_bytes: 704 * 1024 * 1024,
            aggregate_locked_bytes: 640 * 1024 * 1024,
            maximum_output_bytes: crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64,
            tasks: 2,
            maximum_seconds: 1800,
        };
        crypto_budget(budget).unwrap();
        assert_eq!(MEMORY, 256 * 1024 * 1024 + budget.aggregate_memory_bytes);
        assert_eq!(TASKS, 4);
        for field in 0..8 {
            let mut changed = budget;
            match field {
                0 => changed.child_memory_bytes += 1,
                1 => changed.parent_memory_bytes += 1,
                2 => changed.aggregate_memory_bytes += 1,
                3 => changed.aggregate_locked_bytes = 0,
                4 => changed.maximum_output_bytes += 1,
                5 => changed.tasks += 1,
                6 => changed.maximum_seconds += 1,
                7 => changed.aggregate_locked_bytes += 1,
                _ => unreachable!(),
            }
            assert!(crypto_budget(changed).is_err());
        }
    }
    #[test]
    fn encrypted_metadata_never_turns_custody_or_self_report_into_authority() {
        let input = fixture();
        let bytes = serde_json::to_vec(&input).unwrap();
        let id = profile(&input, &bytes).unwrap();
        let digest = "90".repeat(32);
        let metadata = Metadata {
            schema_version: 1,
            request_sha256: io::digest(&bytes),
            binding: digest.clone(),
            lease: crate::resources::Token {
                manager_epoch: "ab".repeat(16),
                lease_id: "cd".repeat(16),
                generation: 1,
            },
            review_sha256: input.review.review_sha256.clone(),
            custody_receipt: None,
            encryption: crypto::EncryptionCommitment {
                schema_version: 1,
                profile: "cms-auth-enveloped-aes256gcm-rsa-oaep-sha256-two-recipients-v1".into(),
                archive_sha256: input.review.archive_sha256.clone(),
                archive_bytes: input.review.archive_bytes,
                cms_sha256: io::digest(b"ciphertext"),
                cms_bytes: 10,
                recipients: input.recipients.clone(),
                authenticates_sender: false,
                proves_both_recipients_recoverable: false,
                permits_restore: false,
            },
            recipient_custody_qualified: false,
            sender_authenticated: false,
            production_qualified: false,
            restore_permitted: false,
        };
        validate_metadata(&metadata, &input, &id, &digest).unwrap();
        for (path, replacement) in [
            ("request_sha256", serde_json::json!("ff".repeat(32))),
            ("binding", serde_json::json!("ee".repeat(32))),
            ("review_sha256", serde_json::json!("dd".repeat(32))),
            ("recipient_custody_qualified", serde_json::json!(true)),
            ("sender_authenticated", serde_json::json!(true)),
            ("production_qualified", serde_json::json!(true)),
            ("restore_permitted", serde_json::json!(true)),
        ] {
            let mut value = serde_json::to_value(&metadata).unwrap();
            value[path] = replacement;
            assert!(validate_metadata(
                &serde_json::from_value(value).unwrap(),
                &input,
                &id,
                &digest
            )
            .is_err());
        }
        for (field, value) in [
            ("authenticates_sender", serde_json::json!(true)),
            (
                "proves_both_recipients_recoverable",
                serde_json::json!(true),
            ),
            ("permits_restore", serde_json::json!(true)),
            ("cms_bytes", serde_json::json!(0)),
            ("archive_bytes", serde_json::json!(22)),
            ("profile", serde_json::json!("plaintext")),
        ] {
            let mut changed = serde_json::to_value(&metadata).unwrap();
            changed["encryption"][field] = value;
            assert!(validate_metadata(
                &serde_json::from_value(changed).unwrap(),
                &input,
                &id,
                &digest
            )
            .is_err());
        }
    }
}
