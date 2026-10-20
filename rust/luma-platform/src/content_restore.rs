//! Original-Admin, finite, leased fresh-owner restore. The independently pinned
//! origin authenticates ciphertext DATA, never the current target or authority.
use crate::sealed_credential::PrivateBuffer;
use crate::{
    artifacts as io, backup_crypto as crypto, finite_grants as grants, resource_manager, Result,
};
use luma_content::OwnerBinding;
use luma_content_store::{
    Access, Boundary, DecisionKind, Repository, ResourceBudget, RestoreReview, VerifiedState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "backup_confinement.rs"]
mod confinement;
pub(crate) const PREFIX: &str = "content-restore-v1-";
pub(crate) const MAX_REQUEST: usize = 96 * 1024;
pub(crate) const MEMORY: u64 = 960 * 1024 * 1024;
pub(crate) const LOCKED: u64 = 640 * 1024 * 1024;
pub(crate) const TASKS: u64 = 4;
const MAX_OUTPUT: usize = 96 * 1024;
const MAX_KEY: usize = 16384;
const READ_ID: &str = "native-content-restore-read-v1";
const REVIEW_ID: &str = "native-content-restore-review-v1";
const WRITE_ID: &str = "native-content-restore-write-v1";
const DIRECTORY: &str = "/var/lib/luma-os/content-store";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyRole {
    Owner,
    OfflineAdmin,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub schema_version: u32,
    pub login: String,
    pub admin: OwnerBinding,
    pub target_login: String,
    pub target: OwnerBinding,
    pub independently_selected_origin_spki_sha256: String,
    pub request_namespace: String,
    pub key_role: KeyRole,
    pub capsule_path: String,
    pub capsule_bytes: u64,
    pub capsule_sha256: String,
    pub review: Option<RestoreReview>,
}
fn login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || b"_-".contains(&v))
}
fn digest(value: &str) -> bool {
    io::hash(value) && value.bytes().any(|v| v != b'0')
}
pub(crate) fn graph_sha256() -> String {
    io::digest(b"luma-fresh-owner-custody-restore-graph-v1:verify-independent-origin;decrypt-inert-data;replay-all-published-chronologically;remap-prior-typed-references;original-admin-finite-batch;held-source;C-anchor-before-rename;fresh-same-state-read;retain-encrypted-origin-evidence")
}
fn lifecycle_graph_sha256() -> String {
    io::digest(b"luma-fresh-owner-custody-restore-graph-v2:verify-independent-origin;decrypt-inert-data;replay-published-and-logical-lifecycle-chronologically;preserve-trash-with-remapped-exact-version-and-lifecycle-revision;leave-conflicts-and-noops-inert;original-admin-finite-batch;held-source;C-anchor-before-rename;fresh-same-state-read;retain-encrypted-origin-evidence;no-purge")
}
fn review_graph_sha256(review: &RestoreReview) -> Result<String> {
    match (review.schema_version, review.profile.as_str()) {
        (1, "luma-fresh-owner-content-restore-v1") => Ok(graph_sha256()),
        (2, "luma-fresh-owner-content-restore-v2") => Ok(lifecycle_graph_sha256()),
        _ => Err("restore review has no exact image-defined replay graph".into()),
    }
}
impl Input {
    pub(crate) fn validate(&self) -> Result<()> {
        self.admin.validate()?;
        self.target.validate()?;
        if self.schema_version != 1
            || !login(&self.login)
            || !login(&self.target_login)
            || self.admin.installation != self.target.installation
            || !digest(&self.independently_selected_origin_spki_sha256)
            || !digest(&self.capsule_sha256)
            || self.capsule_bytes <= 20
            || self.capsule_bytes > crate::content_backup::MAX_EXPORT_BYTES
            || self.capsule_path.is_empty()
            || self.capsule_path.len() > 4096
            || self.capsule_path.contains('\0')
            || !Path::new(&self.capsule_path).is_absolute()
            || self.request_namespace.is_empty()
            || self.request_namespace.len() > 64
            || !self.request_namespace.as_bytes()[0].is_ascii_alphanumeric()
            || !self
                .request_namespace
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v))
        {
            return Err("invalid exact original-Admin fresh-owner restore request".into());
        }
        if let Some(review) = &self.review {
            review.validate()?;
            if review.target != self.target
                || review.workflow_sha256 != review_graph_sha256(review)?
                || review.request_namespace != self.request_namespace
                || review.published_outcomes == 0
            {
                return Err(
                    "restore write requires the exact nonempty rebuilt reviewed batch".into(),
                );
            }
        }
        Ok(())
    }
    pub(crate) fn operation(&self) -> crypto::CryptoOperation {
        match self.key_role {
            KeyRole::Owner => crypto::CryptoOperation::DecryptOwner,
            KeyRole::OfflineAdmin => crypto::CryptoOperation::DecryptOfflineAdmin,
        }
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Input> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("restore request exceeds fixed bound".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    input.validate()?;
    if serde_json::to_vec(&input)? != bytes {
        return Err("restore request is not strict canonical data".into());
    }
    Ok(input)
}
pub(crate) fn prepare_stdin() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err("restore request exceeds fixed bound".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    input.validate()?;
    let bytes = serde_json::to_vec(&input)?;
    if bytes.len() > MAX_REQUEST {
        return Err("canonical restore request exceeds fixed bound".into());
    }
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"canonical_request":String::from_utf8(bytes.clone())?,
        "semantic_request_sha256":source_digest(&profile(&input,&bytes)?)?,"private_key_read":false,"archive_decrypted":false,
        "target_content_changed":false,"grant_issued":false,"authority_returned":false})
    );
    Ok(())
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.nlink(),
        m.uid(),
        m.gid(),
        m.mode(),
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
        return Err("restore request must be bounded single-link regular data".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&file.metadata()?) != identity(&before)
        || identity(&std::fs::symlink_metadata(path)?) != identity(&before)
    {
        return Err("restore request changed during capture".into());
    }
    parse(&bytes)?;
    Ok(bytes)
}
pub(crate) fn read_capsule_for_stage(input: &Input) -> Result<Vec<u8>> {
    input.validate()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&input.capsule_path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() != input.capsule_bytes {
        return Err("original capsule snapshot bound differs".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(input.capsule_bytes)?)?;
    (&mut file)
        .take(input.capsule_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != input.capsule_bytes
        || io::digest(&bytes) != input.capsule_sha256
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(&input.capsule_path)?)
    {
        return Err("original ciphertext differs from exact declared snapshot".into());
    }
    Ok(bytes)
}
pub(crate) fn staged_path(path: &Path, leaf: &str) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    path.file_name().and_then(|v| v.to_str()) == Some(leaf)
        && parent.parent() == Some(Path::new("/run/luma-granted-client/requests"))
        && parent
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|s| s.len() == 32 && crate::tpm::decode::<16>(s).is_ok())
}
pub(crate) fn require_stage(path: &Path, leaf: &str) -> Result<()> {
    if !staged_path(path, leaf) {
        return Err("restore requires its exact original launcher snapshot".into());
    }
    for parent in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("restore staged parent is substituted".into());
        }
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o400 || m.nlink() != 1
    {
        return Err("restore snapshot is not immutable private root data".into());
    }
    Ok(())
}
pub(crate) fn parse_profile(id: &str) -> Result<(char, u64, u64, u64, u64, &str)> {
    let mut p = id
        .strip_prefix(PREFIX)
        .ok_or("unknown restore profile")?
        .split('-');
    let mode = p.next().ok_or("missing restore mode")?;
    let values = [
        p.next().ok_or("missing Admin generation")?,
        p.next().ok_or("missing target generation")?,
        p.next().ok_or("missing capsule bytes")?,
        p.next().ok_or("missing step count")?,
    ];
    let sha = p.next().ok_or("missing restore request commitment")?;
    let mut numbers = [0; 4];
    for (out, value) in numbers.iter_mut().zip(values) {
        *out = value.parse()?;
        if out.to_string() != value {
            return Err("noncanonical restore count".into());
        }
    }
    if !matches!(mode, "r" | "w")
        || numbers[0] == 0
        || numbers[1] == 0
        || numbers[2] <= 20
        || numbers[2] > crate::content_backup::MAX_EXPORT_BYTES
        || numbers[3] > 256
        || (mode == "r" && numbers[3] != 0)
        || (mode == "w" && numbers[3] == 0)
        || !digest(sha)
        || p.next().is_some()
    {
        return Err("invalid closed restore profile".into());
    }
    Ok((
        mode.chars().next().ok_or("empty mode")?,
        numbers[0],
        numbers[1],
        numbers[2],
        numbers[3],
        sha,
    ))
}
pub(crate) fn source_digest(id: &str) -> Result<&str> {
    Ok(parse_profile(id)?.5)
}
pub(crate) fn profile(input: &Input, bytes: &[u8]) -> Result<String> {
    if serde_json::to_vec(input)? != bytes {
        return Err("restore profile requires exact original canonical request".into());
    }
    let mut semantic = input.clone();
    semantic.capsule_path = "/runtime-original-snapshot/content-restore.cms".into();
    let id = format!(
        "{PREFIX}{}-{}-{}-{}-{}-{}",
        if input.review.is_some() { 'w' } else { 'r' },
        input.admin.owner_generation,
        input.target.owner_generation,
        input.capsule_bytes,
        input.review.as_ref().map_or(0, |r| r.published_outcomes),
        io::digest(&serde_json::to_vec(&semantic)?)
    );
    parse_profile(&id)?;
    Ok(id)
}
pub(crate) fn binding(id: &str, device: &str) -> Result<String> {
    binding_at(id, device, &io::installation()?)
}
pub(crate) fn binding_at(id: &str, device: &str, installation: &str) -> Result<String> {
    parse_profile(id)?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("restore storage identity missing")?;
    if !digest(installation)
        || major == "0"
        || [major, minor]
            .iter()
            .any(|s| s.parse::<u32>().map_or(true, |v| v.to_string() != *s))
    {
        return Err("restore requires exact installed block storage".into());
    }
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-original-admin-fresh-owner-restore-v1",
        installation,
        id,
        device,
    ))?))
}
fn uses_at(id: &str, device: &str, installation: &str) -> Result<[grants::Use; 2]> {
    let (mode, generation, _, bytes, steps, _) = parse_profile(id)?;
    let read = grants::Use {
        action: grants::Action::Read,
        selector: grants::Selector {
            kind: grants::Kind::File,
            id: READ_ID.into(),
            generation,
            digest: binding_at(id, device, installation)?,
        },
        input_bytes: bytes,
        output_bytes: MAX_OUTPUT as u64,
        units: 1,
    };
    let effect = grants::Use {
        action: if mode == 'r' {
            grants::Action::RecoverResource
        } else {
            grants::Action::Write
        },
        selector: grants::Selector {
            kind: if mode == 'r' {
                grants::Kind::Resource
            } else {
                grants::Kind::Artifact
            },
            id: if mode == 'r' { REVIEW_ID } else { WRITE_ID }.into(),
            ..read.selector.clone()
        },
        input_bytes: bytes,
        output_bytes: if mode == 'r' {
            MAX_OUTPUT as u64
        } else {
            64 * 1024 * 1024
        },
        units: if mode == 'r' { 1 } else { steps },
    };
    read.validate()?;
    effect.validate()?;
    Ok([read, effect])
}
pub(crate) fn acquisition_usage(id: &str) -> Result<grants::Use> {
    Ok(uses_at(
        id,
        &resource_manager::storage_device(Path::new("/var"))?,
        &io::installation()?,
    )?[1]
        .clone())
}
pub(crate) fn custody_usage(id: &str, device: &str, installation: &str) -> Result<grants::Use> {
    Ok(uses_at(id, device, installation)?[1].clone())
}
pub(crate) fn pair(
    uses: &[(String, grants::Use)],
    requested: &grants::Use,
    purpose: crate::authentication::SessionPurpose,
) -> Result<usize> {
    if purpose != crate::authentication::SessionPurpose::Standard
        || uses.len() != 2
        || uses[0].0 == uses[1].0
    {
        return Err(
            "restore requires a distinct original Standard Read/recovery-or-write pair".into(),
        );
    }
    let reader = uses
        .iter()
        .position(|(_, u)| {
            u.action == grants::Action::Read
                && u.selector.kind == grants::Kind::File
                && u.selector.id == READ_ID
        })
        .ok_or("restore finite Read absent")?;
    let effect = 1 - reader;
    let r = &uses[reader].1;
    let e = &uses[effect].1;
    for (grant, usage) in uses {
        if !crate::admin_roles::identifier(grant) {
            return Err("invalid restore grant ID".into());
        }
        usage.validate()?;
    }
    let review = e.selector.id == REVIEW_ID
        && e.action == grants::Action::RecoverResource
        && e.selector.kind == grants::Kind::Resource
        && e.units == 1
        && e.output_bytes == MAX_OUTPUT as u64;
    let write = e.selector.id == WRITE_ID
        && e.action == grants::Action::Write
        && e.selector.kind == grants::Kind::Artifact
        && (1..=256).contains(&e.units)
        && e.output_bytes == 64 * 1024 * 1024;
    if (!review && !write)
        || e != requested
        || r.units != 1
        || r.output_bytes != MAX_OUTPUT as u64
        || r.input_bytes <= 20
        || r.input_bytes > crate::content_backup::MAX_EXPORT_BYTES
        || r.input_bytes != e.input_bytes
        || r.selector.generation != e.selector.generation
        || r.selector.digest != e.selector.digest
    {
        return Err(
            "restore pair substitutes exact reviewed bytes, target, generation or batch".into(),
        );
    }
    Ok(effect)
}
pub(crate) fn check_client_arguments(
    args: &[&str],
    id: &str,
    audit: Option<&grants::Audit>,
) -> Result<()> {
    let mode = parse_profile(id)?.0;
    if args.len() != 7
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1]
            != if mode == 'r' {
                "content-restore-review"
            } else {
                "content-restore-apply"
            }
        || !args[6].is_empty()
        || !login(args[2])
        || !crate::admin_roles::identifier(args[3])
        || !crate::admin_roles::identifier(args[4])
        || args[3] == args[4]
    {
        return Err("restore proof requires its exact original Admin command".into());
    }
    require_stage(Path::new(args[5]), "content-restore.json")?;
    let bytes = read_request(Path::new(args[5]))?;
    let input = parse(&bytes)?;
    require_stage(Path::new(&input.capsule_path), "content-restore.cms")?;
    if profile(&input, &bytes)? != id || input.login != args[2] {
        return Err("restore original request/grant/actor differs".into());
    }
    if let Some(a) = audit {
        if a.subject != input.admin.owner
            || a.subject_generation != input.admin.owner_generation
            || a.grant_id != args[4]
            || a.usage
                != custody_usage(
                    id,
                    &resource_manager::storage_device(Path::new("/var"))?,
                    &input.admin.installation,
                )?
        {
            return Err("restore original finite effect attribution differs".into());
        }
    }
    Ok(())
}
pub(crate) fn original_target(
    args: &[&str],
    id: &str,
    audit: &grants::Audit,
) -> Result<OwnerBinding> {
    check_client_arguments(args, id, Some(audit))?;
    let input = parse(&read_request(Path::new(args[5]))?)?;
    let (registry, current, installation) =
        crate::admin_governance::current_principal(&input.target_login)?;
    registry.current()?;
    if current.id != input.target.owner
        || current.generation != input.target.owner_generation
        || installation != input.target.installation
    {
        return Err("restore target lifecycle changed under original Admin proof".into());
    }
    Ok(input.target)
}
pub(crate) fn check_worker(id: &str, device: &str, pid: u32) -> Result<()> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;
    let args = raw.split('\0').collect::<Vec<_>>();
    if args.len() != 5
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != "content-restore-resource-worker"
        || args[2] != id
        || !args[4].is_empty()
    {
        return Err("restore worker argv differs".into());
    }
    require_stage(Path::new(args[3]), "content-restore.json")?;
    let bytes = read_request(Path::new(args[3]))?;
    if profile(&parse(&bytes)?, &bytes)? != id
        || std::fs::read_to_string(format!("/proc/{pid}/attr/current"))?
            != "luma-content-restore (enforce)\n"
        || std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            != "0::/lumaacquisition.slice/luma-acquisition.service\n"
    {
        return Err("restore worker confinement/request differs".into());
    }
    let controls = Path::new("/sys/fs/cgroup/lumaacquisition.slice/luma-acquisition.service");
    for (name, value) in [
        ("memory.max", MEMORY.to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", TASKS.to_string()),
        ("cpu.max", "200000 100000".into()),
    ] {
        if std::fs::read_to_string(controls.join(name))?.trim() != value {
            return Err("restore worker resource controls differ".into());
        }
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for name in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
        if !status
            .lines()
            .any(|s| s == format!("{name}:\t0000000000000000"))
        {
            return Err("restore worker is not capability-free".into());
        }
    }
    binding(id, device)?;
    Ok(())
}

struct Terminal(File, libc::termios);
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.0.as_raw_fd(), libc::TCSANOW, &self.1);
        }
    }
}
fn decode_key(encoded: &[u8]) -> Result<PrivateBuffer> {
    if encoded.is_empty() || encoded.len() % 4 != 0 || encoded.len() > MAX_KEY.div_ceil(3) * 4 {
        return Err("PKCS8 base64 exceeds fixed bound".into());
    }
    let padding = encoded.iter().rev().take_while(|v| **v == b'=').count();
    if padding > 2 {
        return Err("invalid private-key padding".into());
    }
    let length = encoded.len() / 4 * 3 - padding;
    if length == 0 || length > MAX_KEY {
        return Err("private key DER exceeds fixed bound".into());
    }
    let mut key = PrivateBuffer::new(length)?;
    let mut offset = 0;
    for (index, chunk) in encoded.chunks_exact(4).enumerate() {
        let mut value = 0u32;
        for (j, b) in chunk.iter().enumerate() {
            let n = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if index == encoded.len() / 4 - 1 && j >= 4 - padding => 0,
                _ => return Err("noncanonical private-key base64".into()),
            };
            value = (value << 6) | u32::from(n);
        }
        if index == encoded.len() / 4 - 1
            && ((padding == 1 && value & 0xff != 0) || (padding == 2 && value & 0xffff != 0))
        {
            return Err("nonzero private-key base64 padding bits".into());
        }
        for shift in [16, 8, 0] {
            if offset < length {
                key.bytes_mut()[offset] = (value >> shift) as u8;
                offset += 1;
            }
        }
    }
    Ok(key)
}
fn hidden_key(check: &mut dyn FnMut() -> Result<()>) -> Result<PrivateBuffer> {
    check()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let mut saved = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut saved) } != 0 {
        return Err("restore key requires an actual controlling terminal".into());
    }
    let mut hidden = saved;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
        return Err("cannot suppress private-key echo".into());
    }
    let mut terminal = Terminal(file, saved);
    writeln!(
        terminal.0,
        "PKCS#8 DER private key, canonical base64 (hidden; never stored):"
    )?;
    terminal.0.flush()?;
    let mut encoded = PrivateBuffer::password_context(MAX_KEY.div_ceil(3) * 4 + 1)?;
    let mut at = 0;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        check()?;
        if Instant::now() >= deadline {
            return Err("private-key input expired".into());
        }
        let mut poll = libc::pollfd {
            fd: terminal.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if ready == 0 {
            continue;
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err("private-key terminal disconnected".into());
        }
        terminal
            .0
            .read_exact(&mut encoded.bytes_mut()[at..at + 1])?;
        let byte = encoded.bytes()[at];
        if matches!(byte, 3 | 4) {
            return Err("private-key input cancelled".into());
        }
        if matches!(byte, 8 | 127) {
            encoded.bytes_mut()[at] = 0;
            if at > 0 {
                at -= 1;
                encoded.bytes_mut()[at] = 0;
            }
            continue;
        }
        if matches!(byte, b'\n' | b'\r') {
            check()?;
            return decode_key(&encoded.bytes()[..at]);
        }
        if !(byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
            || at == encoded.bytes().len() - 1
        {
            return Err("private-key base64 outside fixed bound".into());
        }
        at += 1;
    }
}
fn key_from_stdin(check: &mut impl FnMut() -> Result<()>) -> Result<PrivateBuffer> {
    check()?;
    let name = std::fs::read_link("/proc/self/fd/0")?;
    if name != PathBuf::from("/memfd:luma-private-credential (deleted)") {
        return Err(
            "restore key requires its owned anonymous locked memfd, never a file or argv".into(),
        );
    }
    let mut file = File::open("/proc/self/fd/0")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_KEY as u64 {
        return Err("restore key descriptor bound differs".into());
    }
    let mut key = PrivateBuffer::new(before.len() as usize)?;
    for chunk in key.bytes_mut().chunks_mut(4096) {
        check()?;
        file.read_exact(chunk)?;
    }
    if identity(&before) != identity(&file.metadata()?) {
        return Err("private-key descriptor changed".into());
    }
    check()?;
    Ok(key)
}
struct HashedReader(File, Sha256);
impl Read for HashedReader {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(b)?;
        self.1.update(&b[..n]);
        Ok(n)
    }
}
fn capsule(
    input: &Input,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<crate::content_backup::capsule::VerifiedCiphertext> {
    require_stage(Path::new(&input.capsule_path), "content-restore.cms")?;
    check()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&input.capsule_path)?;
    let before = file.metadata()?;
    if before.len() != input.capsule_bytes {
        return Err("capsule byte count differs from exact grant".into());
    }
    let mut reader = HashedReader(file, Sha256::new());
    let capsule = crate::content_backup::inspect_capsule(
        &mut reader,
        &input.independently_selected_origin_spki_sha256,
        check,
    )?;
    if crate::bundle::hex(&reader.1.finalize()) != input.capsule_sha256
        || identity(&before) != identity(&reader.0.metadata()?)
        || identity(&before) != identity(&std::fs::symlink_metadata(&input.capsule_path)?)
    {
        return Err("capsule changed during authenticated capture".into());
    }
    check()?;
    Ok(capsule)
}
fn checked_hash(data: &[u8], check: &mut impl FnMut() -> Result<()>) -> Result<String> {
    let mut hash = Sha256::new();
    for block in data.chunks(32768) {
        check()?;
        hash.update(block);
    }
    check()?;
    Ok(crate::bundle::hex(&hash.finalize()))
}

struct Live<'a> {
    input: &'a Input,
    id: &'a str,
    lease: &'a resource_manager::WorkerLease,
    confinement: confinement::KernelUnix,
}
impl Live<'_> {
    fn check(&self) -> Result<()> {
        self.confinement.check()?;
        self.lease.check()
    }
}
struct Decryptor<'a>(&'a Live<'a>, &'a crypto::EncryptionCommitment);
impl crypto::CryptoBoundary for Decryptor<'_> {
    fn admit(&mut self, r: &crypto::CryptoRequest, b: crypto::CryptoBudget) -> Result<()> {
        if b.aggregate_memory_bytes != 704 * 1024 * 1024
            || b.aggregate_locked_bytes != LOCKED
            || b.child_memory_bytes != 512 * 1024 * 1024
            || b.parent_memory_bytes != 192 * 1024 * 1024
            || b.tasks != 2
            || b.maximum_seconds != 1800
            || b.maximum_output_bytes != luma_content_store::MAX_CONTENT_BACKUP_BYTES as u64
        {
            return Err(
                "restore crypto exceeds its separately admitted child/parent budget".into(),
            );
        }
        self.check(r)
    }
    fn check(&mut self, r: &crypto::CryptoRequest) -> Result<()> {
        if r.schema_version != 1
            || r.operation != self.0.input.operation()
            || r.input_sha256 != self.1.cms_sha256
            || r.input_bytes != self.1.cms_bytes
            || r.recipients != self.1.recipients
        {
            return Err(
                "restore crypto substitutes independently authenticated input or role".into(),
            );
        }
        self.0.check()
    }
}

struct StoreGuard<'a> {
    live: &'a Live<'a>,
    review: &'a RestoreReview,
    step: Option<&'a luma_content_store::Plan>,
    cut: VerifiedState,
}
impl StoreGuard<'_> {
    fn current(&self, binding: &OwnerBinding) -> Result<()> {
        if binding != &self.live.input.target {
            return Err("restore boundary refuses another owner".into());
        }
        self.live.check()?;
        let actual = crate::content_checkpoint::custody::selected(
            self.live.id,
            binding,
            self.live.lease.token(),
        )?;
        if actual != self.cut {
            return Err("restore independently selected current cut changed".into());
        }
        self.live.check()
    }
}
impl Boundary for StoreGuard<'_> {
    fn admit(
        &mut self,
        b: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 1024 * 1024 * 1024
            || budget.write_bytes > self.review.planned_storage_bytes + 8192
            || budget.additional_storage_bytes > self.review.planned_storage_bytes + 8192
            || budget.tasks > 1
        {
            return Err("restore store budget exceeds admitted batch".into());
        }
        self.current(b).map_err(|e| e.to_string().into())
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        let binding = match access {
            Access::Inspect { binding } => binding,
            Access::Mutate {
                binding,
                review_sha256,
                decision,
                source_bytes,
                storage_bytes,
            } => {
                let p = self.step.ok_or("restore inspection has no mutation step")?;
                if self.live.input.review.is_none()
                    || p.review_sha256() != review_sha256
                    || decision != p.decision()
                    || !matches!(
                        decision,
                        DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
                    )
                    || (matches!(decision, DecisionKind::Trashed | DecisionKind::Restored)
                        && (self.review.schema_version != 2 || p.lifecycle_request().is_none()))
                    || source_bytes != p.source_bytes()
                    || storage_bytes != p.storage_bytes()
                {
                    return Err(
                        "restore mutation differs from exact reviewed chronological step".into(),
                    );
                }
                binding
            }
            Access::Recover { .. } => {
                return Err("fresh-owner restore never repairs or adopts damaged authority".into())
            }
        };
        self.current(binding).map_err(|e| e.to_string().into())
    }
}

fn subject(input: &Input, guard: &mut crate::admin_governance::GrantBoundary<'_>) -> Result<()> {
    guard.require_admin()?;
    if guard.subject()? != input.admin.owner
        || guard.subject_generation()? != input.admin.owner_generation
        || io::installation()? != input.admin.installation
    {
        return Err("restore original Admin identity changed".into());
    }
    let (registry, target, installation) =
        crate::admin_governance::current_principal(&input.target_login)?;
    registry.current()?;
    if target.id != input.target.owner
        || target.generation != input.target.owner_generation
        || installation != input.target.installation
    {
        return Err("restore target account lifecycle changed".into());
    }
    guard.require_admin()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    request_sha256: String,
    binding: String,
    lease: crate::resources::Token,
    result: serde_json::Value,
}
fn worker(id: &str, path: &Path) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    check_worker(
        id,
        &resource_manager::storage_device(Path::new("/var"))?,
        std::process::id(),
    )?;
    require_stage(path, "content-restore.json")?;
    let bytes = read_request(path)?;
    let input = parse(&bytes)?;
    if profile(&input, &bytes)? != id {
        return Err("restore request differs from admitted profile".into());
    }
    let confinement = confinement::KernelUnix::capture()?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(id, Path::new("/var"))?;
    let live = Live {
        input: &input,
        id,
        lease: &lease,
        confinement,
    };
    live.check()?;
    let key = key_from_stdin(&mut || live.check())?;
    let capsule = capsule(&input, &mut || live.check())?;
    let mut decryptor = Decryptor(&live, &capsule.receipt.body.encryption);
    let plaintext = crypto::decrypt_backup_data(
        &capsule.ciphertext,
        &capsule.receipt.body.encryption.cms_sha256,
        &capsule.receipt.body.input.recipient_data()?,
        input.operation(),
        &key,
        &mut decryptor,
    )?;
    let data = plaintext.data_checked(&mut decryptor)?;
    if checked_hash(data, &mut || live.check())? != capsule.receipt.body.encryption.archive_sha256
        || data.len() as u64 != capsule.receipt.body.encryption.archive_bytes
    {
        return Err(
            "decrypted archive differs from independently authenticated original bytes".into(),
        );
    }
    let planner = luma_content_store::plan_restore_data_checked_versions(
        data,
        &input.target,
        &input.request_namespace,
        &graph_sha256(),
        &lifecycle_graph_sha256(),
        &mut || live.check(),
    )?;
    if planner.review().origin != capsule.receipt.body.input.binding
        || planner.review().origin_head_sha256 != capsule.receipt.body.source_state.head_sha256
    {
        return Err(
            "archive reconstructed origin differs from independently authenticated receipt".into(),
        );
    }
    let selected = crate::content_checkpoint::custody::selected(id, &input.target, lease.token())?;
    let started = if input.review.is_some() {
        let (current, started) =
            crate::content_checkpoint::custody::restore_status(id, &input, lease.token())?;
        if current != selected {
            return Err("restore current cut changed during start inspection".into());
        }
        started
    } else {
        false
    };
    if !started && selected == VerifiedState::empty(&input.target)? && exists(&input)? {
        let mut guard = StoreGuard {
            live: &live,
            review: planner.review(),
            step: None,
            cut: selected.clone(),
        };
        let mut repository = Repository::open_at(Path::new(DIRECTORY), &input.target, &mut guard)?;
        repository.require_state(&selected, &mut guard)?;
        let inventory = repository.review_backup_data(&mut guard)?;
        if inventory.committed_outcomes != 0
            || inventory
                .areas
                .iter()
                .any(|area| area.directories != 0 || area.members != 0 || area.bytes != 0)
        {
            return Err("fresh-owner restore refuses existing pending or forensic bytes; never guesses adoption".into());
        }
    }
    let result = if let Some(review) = &input.review {
        if review != planner.review() {
            return Err("rebuilt restore differs from explicitly approved full batch".into());
        }
        let cut = crate::content_checkpoint::custody::restore_start(
            id,
            &input,
            &capsule.receipt,
            lease.token(),
        )?;
        let mut completed = 0u64;
        for (plan, source) in planner.steps() {
            live.check()?;
            let cut = crate::content_checkpoint::custody::restore_preparation_cut(
                id,
                &input,
                lease.token(),
                plan.provenance().request_id.as_str(),
                plan.review_sha256(),
            )?;
            let mut boundary = StoreGuard {
                live: &live,
                review,
                step: Some(plan),
                cut: cut.current.clone(),
            };
            let mut repository = if exists(&input)? {
                Repository::open_at(Path::new(DIRECTORY), &input.target, &mut boundary)?
            } else {
                if cut.current != VerifiedState::empty(&input.target)? || completed != 0 {
                    return Err(
                        "protected restore history exists but physical target is missing".into(),
                    );
                }
                Repository::create_at(Path::new(DIRECTORY), plan, &mut boundary)?
            };
            let physical = repository.verified_state(&mut boundary)?;
            if physical != cut.current && cut.prior_base.as_ref() != Some(&physical) {
                return Err("restore physical state is neither exact protected cut nor its anchored pending predecessor".into());
            }
            repository.require_state(&physical, &mut boundary)?;
            if physical == cut.current && cut.current.outcome_count > completed {
                let outcomes = repository.inventory(&mut boundary)?;
                if outcomes
                    .get(completed as usize)
                    .map(|o| o.review_sha256.as_str())
                    != Some(plan.review_sha256())
                {
                    return Err("restore committed prefix differs from approved batch".into());
                }
                completed += 1;
                continue;
            }
            let mut held = if plan.source_kind() == luma_content_store::SourceKind::CollectionIntent
            {
                repository.prepare_collection(plan, source, &mut boundary)?
            } else {
                repository.prepare(plan, source, &mut boundary)?
            };
            held.recheck(&mut boundary)?;
            let wanted = held.commitment().outcome_state();
            let actual = crate::content_checkpoint::custody::restore_publish(
                id,
                &input,
                lease.token(),
                &held.commitment().canonical_bytes()?,
                held.record_bytes(),
            )?;
            if actual != wanted {
                return Err("restore C acknowledgement differs from held exact outcome".into());
            }
            boundary.cut = wanted.clone();
            held.publish(&mut boundary)?;
            drop(repository);
            let mut fresh =
                Repository::open_at(Path::new(DIRECTORY), &input.target, &mut boundary)?;
            fresh.require_state(&wanted, &mut boundary)?;
            fresh.verified_state(&mut boundary)?;
            completed += 1;
        }
        let final_cut =
            crate::content_checkpoint::custody::selected(id, &input.target, lease.token())?;
        if completed != review.published_outcomes
            || final_cut.outcome_count != review.published_outcomes
            || cut.binding != input.target
        {
            return Err("restore batch final independently protected count differs".into());
        }
        serde_json::json!({"schema_version":1,"restore_review_sha256":review.review_sha256,"published_outcomes":completed,
            "custody_capacity_policy":crate::content_checkpoint::custody::restore_capacity_policy(),
            "current_state":final_cut,"origin_signature_valid":true,"credentials_restored":false,"grants_restored":false,"TPM_state_restored":false,
            "original_encrypted_evidence_must_be_retained":true,"encrypted_evidence_sha256":input.capsule_sha256,
            "authority_returned":false,"production_qualified":false})
    } else {
        if selected != VerifiedState::empty(&input.target)? {
            return Err("fresh restore review refuses a nonempty protected target".into());
        }
        if exists(&input)? {
            let mut guard = StoreGuard {
                live: &live,
                review: planner.review(),
                step: None,
                cut: selected.clone(),
            };
            let mut r = Repository::open_at(Path::new(DIRECTORY), &input.target, &mut guard)?;
            r.require_state(&selected, &mut guard)?;
        }
        serde_json::json!({"schema_version":1,"restore_review":planner.review(),"origin_signature_valid":true,
            "custody_capacity_policy":crate::content_checkpoint::custody::restore_capacity_policy(),
            "archive_validated":true,"decrypted_data_delivered":false,"target_content_changed":false,"restore_permitted":false,
            "authority_returned":false,"credentials_restored":false,"encrypted_evidence_must_be_retained":true})
    };
    live.check()?;
    let result_bytes = serde_json::to_vec(&result)?;
    if result_bytes.len() > MAX_OUTPUT - 4096 {
        return Err("restore result exceeds finite bound".into());
    }
    lease.complete_output(&io::digest(&result_bytes))?;
    let output = serde_json::to_vec(&Response {
        schema_version: 1,
        request_sha256: source_digest(id)?.into(),
        binding: binding(id, &resource_manager::storage_device(Path::new("/var"))?)?,
        lease: lease.token().clone(),
        result,
    })?;
    if output.len() > MAX_OUTPUT {
        return Err("restore framed response exceeds finite output".into());
    }
    lease.check_local()?;
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    if args.first().map(String::as_str) == Some("content-restore-resource-worker")
        && args.len() == 3
    {
        return worker(&args[1], Path::new(&args[2]));
    }
    let proposal =
        args.first().map(String::as_str) == Some("content-restore-proposal") && args.len() == 3;
    let execute = matches!(
        args.first().map(String::as_str),
        Some("content-restore-review" | "content-restore-apply")
    ) && args.len() == 5;
    if !proposal && !execute {
        return Err("expected content-restore-proposal LOGIN REQUEST | content-restore-{review|apply} LOGIN READ-GRANT EFFECT-GRANT REQUEST".into());
    }
    let path = Path::new(args.last().ok_or("restore request absent")?);
    let bytes = read_request(path)?;
    let input = parse(&bytes)?;
    if input.login != args[1]
        || (!proposal && (args[0] == "content-restore-apply") != input.review.is_some())
    {
        return Err("restore command differs from explicit request mode/actor".into());
    }
    let id = profile(&input, &bytes)?;
    let device = resource_manager::storage_device(Path::new("/var"))?;
    let uses = uses_at(&id, &device, &input.admin.installation)?;
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"request_sha256":source_digest(&id)?,"read_usage":uses[0],"effect_usage":uses[1],
        "private_key_read":false,"archive_decrypted":false,"target_content_changed":false,"grant_issued":false,"authority_returned":false})
        );
        return Ok(());
    }
    require_stage(path, "content-restore.json")?;
    require_stage(Path::new(&input.capsule_path), "content-restore.cms")?;
    let uses = [
        (args[2].clone(), uses[0].clone()),
        (args[3].clone(), uses[1].clone()),
    ];
    let result = crate::admin_governance::with_grants(&input.login, &uses, |guard| {
        pair(&uses, &uses[1].1, guard.session_purpose())?;
        subject(&input, guard)?;
        let pending = guard.effect_begin(
            source_digest(&id)?,
            crate::policy_decisions::EffectKind::Recovery,
        )?;
        crate::acquisition::await_drainage_checked(&mut || subject(&input, guard))?;
        let response =
            crate::service::granted_acquisition::run_restore(&id, &uses[1].1, guard, |check| {
                let key = hidden_key(check)?;
                check()?;
                let output = memory_file()?;
                let mut command = Command::new("/usr/bin/systemd-run");
                command
                    .args(crate::acquisition::arguments(
                        Path::new("/var"),
                        &id,
                        "content-restore",
                    )?)
                    .arg(path)
                    .env_clear()
                    .env("PATH", "/usr/bin")
                    .env("LANG", "C")
                    .env("LC_ALL", "C")
                    .stdin(Stdio::from(key.descriptor()?))
                    .stdout(Stdio::from(output.try_clone()?))
                    .stderr(Stdio::null());
                let deadline = Instant::now() + Duration::from_secs(1800);
                crate::model::supervise_owned_controller(&mut command, || {
                    check()?;
                    if Instant::now() >= deadline || output.metadata()?.len() > MAX_OUTPUT as u64 {
                        return Err("restore output/deadline bound exceeded".into());
                    }
                    Ok(())
                })?;
                crate::acquisition::await_drainage_checked(&mut || check())?;
                check()?;
                let mut file = output;
                file.seek(SeekFrom::Start(0))?;
                let mut raw = Vec::new();
                file.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut raw)?;
                if raw.is_empty() || raw.len() > MAX_OUTPUT {
                    return Err("restore response outside finite bound".into());
                }
                let response: Response = serde_json::from_slice(&raw)?;
                if serde_json::to_vec(&response)? != raw
                    || response.schema_version != 1
                    || response.request_sha256 != source_digest(&id)?
                    || response.binding != binding(&id, &device)?
                {
                    return Err("restore response differs from exact original acquisition".into());
                }
                verify_output(&response)?;
                check()?;
                Ok(response)
            })?;
        subject(&input, guard)?;
        verify_output(&response)?;
        guard.effect_complete(pending, &io::digest(&serde_json::to_vec(&response.result)?))?;
        subject(&input, guard)?;
        Ok(response.result)
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn memory_file() -> Result<File> {
    let name = b"luma-content-restore-output\0";
    let fd = unsafe { libc::memfd_create(name.as_ptr().cast(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    use std::os::fd::FromRawFd;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn exists(input: &Input) -> Result<bool> {
    let path = Path::new(DIRECTORY).join(luma_content_store::domain_name(&input.target)?);
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn verify_output(response: &Response) -> Result<()> {
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(response.lease.clone());
    let receipt = crate::service::resource_exchange(&request)?
        .status
        .ok_or("restore output generation missing")?;
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
    if !crate::workflow_resource::token_valid(&response.lease)
        || receipt.binding != response.binding
        || receipt.lease != response.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(&response.result)?)
        || receipt.physical_release_granted
        || receipt
            .output_domain_epochs
            .keys()
            .map(String::as_str)
            .ne(resource_manager::invoice_output_domains())
        || receipt.output_domain_epochs.values().any(|v| v.0 == 0)
    {
        return Err("restore result lacks its exact unfenced output generation".into());
    }
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_restore_review_selects_distinct_graph_without_reinterpreting_v1() {
        // Pure request data only. The installed worker must still authenticate
        // the encrypted origin and rebuild every actual chronological step.
        for (version, name, graph) in [
            (1, "luma-fresh-owner-content-restore-v1", graph_sha256()),
            (
                2,
                "luma-fresh-owner-content-restore-v2",
                lifecycle_graph_sha256(),
            ),
        ] {
            let mut value = input();
            let mut review = RestoreReview {
                schema_version: version,
                profile: name.into(),
                origin: OwnerBinding {
                    installation: "66".repeat(32),
                    owner: "77".repeat(32),
                    owner_generation: 1,
                },
                target: value.target.clone(),
                archive_sha256: "88".repeat(32),
                archive_bytes: 4096,
                manifest_sha256: "99".repeat(32),
                origin_head_sha256: "aa".repeat(32),
                workflow_sha256: graph.clone(),
                request_namespace: value.request_namespace.clone(),
                published_outcomes: 1,
                inert_committed_outcomes: 0,
                inert_pending_directories: 0,
                inert_quarantined_directories: 0,
                planned_storage_bytes: 8192,
                mappings_sha256: "bb".repeat(32),
                steps: vec![luma_content_store::RestoreStepReview {
                    request_id: format!("{}.1", value.request_namespace),
                    review_sha256: "cc".repeat(32),
                }],
                review_sha256: String::new(),
            };
            review.review_sha256 = io::digest(&serde_json::to_vec(&review).unwrap());
            review.validate().unwrap();
            assert_eq!(review_graph_sha256(&review).unwrap(), graph);
            value.review = Some(review.clone());
            value.validate().unwrap();
            review.workflow_sha256 = if version == 1 {
                lifecycle_graph_sha256()
            } else {
                graph_sha256()
            };
            review.review_sha256.clear();
            review.review_sha256 = io::digest(&serde_json::to_vec(&review).unwrap());
            review.validate().unwrap();
            value.review = Some(review);
            assert!(value.validate().is_err());
        }
        assert_ne!(graph_sha256(), lifecycle_graph_sha256());
    }
    fn input() -> Input {
        Input {
            schema_version: 1,
            login: "admin".into(),
            admin: OwnerBinding {
                installation: "11".repeat(32),
                owner: "22".repeat(32),
                owner_generation: 7,
            },
            target_login: "restored".into(),
            target: OwnerBinding {
                installation: "11".repeat(32),
                owner: "33".repeat(32),
                owner_generation: 1,
            },
            independently_selected_origin_spki_sha256: "44".repeat(32),
            request_namespace: "restored.owner".into(),
            key_role: KeyRole::OfflineAdmin,
            capsule_path: "/tmp/original-ciphertext.cms".into(),
            capsule_bytes: 4096,
            capsule_sha256: "55".repeat(32),
            review: None,
        }
    }
    #[test]
    fn semantic_request_commits_every_restore_choice_but_not_volatile_snapshot_path() {
        let original = input();
        original.validate().unwrap();
        let expected = profile(&original, &serde_json::to_vec(&original).unwrap()).unwrap();
        let mut moved = original.clone();
        moved.capsule_path="/run/luma-granted-client/requests/0123456789abcdef0123456789abcdef/content-restore.cms".into();
        assert_eq!(
            profile(&moved, &serde_json::to_vec(&moved).unwrap()).unwrap(),
            expected
        );
        for case in 0..8 {
            let mut changed = original.clone();
            match case {
                0 => changed.capsule_sha256 = "56".repeat(32),
                1 => changed.capsule_bytes += 1,
                2 => changed.independently_selected_origin_spki_sha256 = "45".repeat(32),
                3 => changed.key_role = KeyRole::Owner,
                4 => changed.target.owner_generation += 1,
                5 => changed.target.owner = "34".repeat(32),
                6 => changed.request_namespace = "another.batch".into(),
                _ => changed.admin.owner_generation += 1,
            }
            assert_ne!(
                profile(&changed, &serde_json::to_vec(&changed).unwrap()).unwrap(),
                expected,
                "case {case}"
            );
        }
        let mut raw = serde_json::to_vec(&original).unwrap();
        raw.push(b'\n');
        assert!(parse(&raw).is_err());
        let duplicate = String::from_utf8(serde_json::to_vec(&original).unwrap())
            .unwrap()
            .replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            );
        assert!(parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn restore_pairs_are_distinct_exact_standard_scopes_not_export_or_read_alone() {
        let original = input();
        let id = profile(&original, &serde_json::to_vec(&original).unwrap()).unwrap();
        let scopes = uses_at(&id, "8:1", &original.admin.installation).unwrap();
        let uses = [
            ("restore-read".into(), scopes[0].clone()),
            ("restore-review".into(), scopes[1].clone()),
        ];
        assert_eq!(
            pair(
                &uses,
                &scopes[1],
                crate::authentication::SessionPurpose::Standard
            )
            .unwrap(),
            1
        );
        for purpose in [
            crate::authentication::SessionPurpose::Export,
            crate::authentication::SessionPurpose::ModelImport,
            crate::authentication::SessionPurpose::ModelQa,
        ] {
            assert!(pair(&uses, &scopes[1], purpose).is_err());
        }
        for case in 0..9 {
            let mut bad = uses.clone();
            match case {
                0 => bad[1].0 = bad[0].0.clone(),
                1 => bad[1].1.selector.generation += 1,
                2 => bad[1].1.selector.digest = "66".repeat(32),
                3 => bad[0].1.input_bytes += 1,
                4 => bad[0].1.output_bytes += 1,
                5 => bad[1].1.output_bytes += 1,
                6 => bad[1].1.units += 1,
                7 => bad[1].1.action = grants::Action::Read,
                _ => bad[1].1.selector.id = "Unrelated".into(),
            }
            assert!(
                pair(
                    &bad,
                    &bad[1].1,
                    crate::authentication::SessionPurpose::Standard
                )
                .is_err(),
                "case {case}"
            );
        }
        assert!(pair(
            &uses[..1],
            &scopes[0],
            crate::authentication::SessionPurpose::Standard
        )
        .is_err());
    }
    #[test]
    fn private_key_base64_is_bounded_canonical_and_never_pageable_fallback() {
        let key = decode_key(b"AQIDBA==").unwrap();
        assert_eq!(key.bytes(), [1, 2, 3, 4]);
        for bad in [
            b"".as_slice(),
            b"AQIDBA=",
            b"AQIDBA===",
            b"AQIDBB==",
            b"AQIDBA==\n",
            b"AA=A",
            b"====",
            b"AQID-B==",
        ] {
            assert!(decode_key(bad).is_err());
        }
        assert!(decode_key(&vec![b'A'; MAX_KEY.div_ceil(3) * 4 + 4]).is_err());
        for invalid in [
            "content-restore-v1-r-0-1-4096-0-",
            "content-restore-v1-r-7-0-4096-0-",
            "content-restore-v1-r-7-1-4096-1-",
            "content-restore-v1-w-7-1-4096-0-",
            "content-restore-v1-w-7-1-4096-257-",
            "content-restore-v1-r-07-1-4096-0-",
        ] {
            assert!(parse_profile(&format!("{invalid}{}", "a".repeat(64))).is_err());
        }
    }
}
