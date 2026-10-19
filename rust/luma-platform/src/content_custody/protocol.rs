//! Fixed-socket transport. Original grants are re-proved by the broker for
//! every checkpoint; serialized states and audits are never reusable authority.
use super::*;
use crate::resources::Token;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};
use std::time::{Duration, Instant};

const SOCKET: &str = "/run/luma-content-custody/control.sock";
const MAX_FRAME: usize = 256 * 1024;
const DEADLINE: Duration = Duration::from_secs(25);

#[path = "output.rs"]
mod output;
pub(crate) use output::exchange as check_output;

#[path = "../backup_confinement.rs"]
mod confinement;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardRequest {
    pub schema_version: u32,
    pub action: String,
    pub request_id: String,
    pub deadline: u64,
    pub lease: Token,
    pub profile: String,
    pub storage_device: String,
    pub binding: OwnerBinding,
    pub worker_pid: u32,
    pub worker_start: u64,
}
impl GuardRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        let now = crate::resource_manager::now()?;
        if self.schema_version != 1
            || self.action != "resource-content-custody-guard"
            || self.worker_pid == 0
            || self.worker_start == 0
            || self.deadline <= now
            || self.deadline
                > now
                    .checked_add(3000)
                    .ok_or("content guard deadline overflow")?
            || self.request_id.len() != 32
            || tpm::decode::<16>(&self.request_id).is_err()
            || self.profile.len() > 256
            || self.storage_device.len() > 32
            || self.lease.lease_id.len() > 128
            || self.lease.manager_epoch.len() > 128
        {
            return Err("invalid exact content custody guard request".into());
        }
        if self.profile.starts_with(crate::content_restore::PREFIX) {
            crate::content_restore::source_digest(&self.profile)?;
        } else if self.profile.starts_with(crate::office_export::PREFIX) {
            crate::office_export::source_digest(&self.profile)?;
        } else if self.profile.starts_with(crate::content_backup::PREFIX) {
            crate::content_backup::source_digest(&self.profile)?;
        } else {
            crate::content_governed::source_digest(&self.profile)?;
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    RestoreStatus {
        input: crate::content_restore::Input,
    },
    RestoreStart {
        input: crate::content_restore::Input,
        receipt: backup::Receipt,
    },
    RestorePreparation {
        input: crate::content_restore::Input,
        request_id: String,
        review_sha256: String,
    },
    RestorePublish {
        input: crate::content_restore::Input,
        commitment: String,
        record: String,
    },
    Select,
    BackupPrepare {
        input: crate::content_backup::Input,
    },
    BackupReceipt {
        input: crate::content_backup::Input,
        encryption: crate::backup_crypto::EncryptionCommitment,
    },
    PreparationCut {
        request_id: String,
        review_sha256: String,
    },
    RecoveryCut {
        review: luma_content_store::PreparationReview,
    },
    Quarantine {
        review: luma_content_store::PreparationReview,
    },
    Publish {
        commitment: String,
        record: String,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    profile: String,
    storage_device: String,
    binding: OwnerBinding,
    lease: Token,
    operation: Operation,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    result: String,
    request_sha256: String,
    state: VerifiedState,
    prior_base: Option<VerifiedState>,
    receipt: Option<backup::Receipt>,
    restore_started: Option<bool>,
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| "content custody transport deadline exceeded".into())
}
fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err("truncated content custody frame".into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header, deadline)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("content custody frame exceeds closed bound".into());
    }
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn write(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("content custody response exceeds bound".into());
    }
    for part in [&(bytes.len() as u32).to_be_bytes()[..], bytes] {
        let mut rest = part;
        while !rest.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            match stream.write(rest) {
                Ok(0) => return Err("content custody transport made no progress".into()),
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    remaining(deadline)?;
    Ok(())
}
pub(crate) fn peer_label(stream: &UnixStream, expected: &str) -> Result<()> {
    let mut bytes = [0u8; 256];
    let mut size = bytes.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size == 0
        || size as usize > bytes.len()
    {
        return Err("current content custody peer label unavailable".into());
    }
    let value = &bytes[..size as usize];
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    if value != expected.as_bytes() {
        return Err("content custody socket belongs to a different enforcing peer".into());
    }
    Ok(())
}
fn pidfd_alive(file: &File) -> Result<()> {
    let mut entry = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut entry, 1, 0) } != 0 || entry.revents != 0 {
        return Err("content custody worker kernel handle is no longer live".into());
    }
    Ok(())
}
fn start(pid: u32) -> Result<u64> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(format!("/proc/{pid}/stat"))?;
    let mut status: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut status) } != 0 || status.f_type != 0x9fa0 {
        return Err("worker start evidence requires genuine procfs".into());
    }
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    if value.len() > 4096 || !value.starts_with(&format!("{pid} (")) {
        return Err("invalid worker process start evidence".into());
    }
    let after = value.rsplit_once(") ").ok_or("malformed kernel stat")?.1;
    let result = after
        .split_ascii_whitespace()
        .nth(19)
        .ok_or("missing kernel process start")?
        .parse::<u64>()?;
    if result == 0 {
        return Err("empty worker start generation".into());
    }
    Ok(result)
}
fn random() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bundle::hex(&bytes))
}

fn exchange_cut(request: &Request) -> Result<PreparationCut> {
    request.binding.validate()?;
    let bytes = serde_json::to_vec(request)?;
    let deadline = Instant::now() + DEADLINE;
    let mut stream = crate::service::connect_local(SOCKET, deadline)?;
    if crate::service::credentials(&stream)?.uid != 0 {
        return Err("content custody service is not root".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    write(&mut stream, &bytes, deadline)?;
    let response: Response = canonical(&read(&mut stream, deadline)?, MAX_FRAME)?;
    response.state.validate()?;
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
        || response.state.binding != request.binding
        || response.receipt.is_some()
        || response.restore_started.is_some()
    {
        return Err("content custody response differs from exact current request".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    if let Some(base) = &response.prior_base {
        base.validate()?;
        if base.binding != response.state.binding
            || base.outcome_count > response.state.outcome_count
        {
            return Err(
                "content custody retry base is not in the exact current owner history".into(),
            );
        }
    }
    Ok(PreparationCut {
        current: response.state,
        prior_base: response.prior_base,
    })
}
fn exchange(request: &Request) -> Result<VerifiedState> {
    let cut = exchange_cut(request)?;
    if cut.prior_base.is_some() {
        return Err(
            "ordinary content custody selection cannot return a prior publication cut".into(),
        );
    }
    Ok(cut.current)
}
pub(crate) fn preparation_cut(
    profile: &str,
    binding: &OwnerBinding,
    lease: &Token,
    request_id: &str,
    review: &str,
) -> Result<PreparationCut> {
    if request_id.is_empty() || request_id.len() > 128 {
        return Err("publication reconciliation request exceeds bound".into());
    }
    digest(review)?;
    exchange_cut(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: binding.clone(),
        lease: lease.clone(),
        operation: Operation::PreparationCut {
            request_id: request_id.into(),
            review_sha256: review.into(),
        },
    })
}
pub(crate) fn recovery_cut(
    profile: &str,
    lease: &Token,
    review: &luma_content_store::PreparationReview,
) -> Result<PreparationCut> {
    review.validate()?;
    exchange_cut(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: review.binding.clone(),
        lease: lease.clone(),
        operation: Operation::RecoveryCut {
            review: review.clone(),
        },
    })
}
pub(crate) fn quarantine(
    profile: &str,
    lease: &Token,
    review: &luma_content_store::PreparationReview,
) -> Result<VerifiedState> {
    review.validate()?;
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: review.binding.clone(),
        lease: lease.clone(),
        operation: Operation::Quarantine {
            review: review.clone(),
        },
    })
}
pub(crate) fn selected(
    profile: &str,
    binding: &OwnerBinding,
    lease: &Token,
) -> Result<VerifiedState> {
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: binding.clone(),
        lease: lease.clone(),
        operation: Operation::Select,
    })
}
pub(crate) fn backup_cut(
    profile: &str,
    input: &crate::content_backup::Input,
    lease: &Token,
) -> Result<VerifiedState> {
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        binding: input.binding.clone(),
        lease: lease.clone(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        operation: Operation::BackupPrepare {
            input: input.clone(),
        },
    })
}

fn read_live(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        check()?;
        stream.set_read_timeout(Some(remaining(deadline)?.min(Duration::from_millis(100))))?;
        match stream.read(bytes) {
            Ok(0) => return Err("truncated authenticated backup custody transfer".into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
    }
    check()?;
    remaining(deadline)?;
    Ok(())
}

pub(crate) fn backup_receipt(
    profile: &str,
    input: &crate::content_backup::Input,
    lease: &Token,
    encryption: &crate::backup_crypto::EncryptionCommitment,
    ciphertext: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<backup::Receipt> {
    crate::content_backup::validate_encryption(encryption, input)?;
    if ciphertext.len() as u64 != encryption.cms_bytes || hash(ciphertext) != encryption.cms_sha256
    {
        return Err("measured custody input differs from exact encrypted output".into());
    }
    check()?;
    let request = Request {
        schema_version: 1,
        profile: profile.into(),
        binding: input.binding.clone(),
        lease: lease.clone(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        operation: Operation::BackupReceipt {
            input: input.clone(),
            encryption: encryption.clone(),
        },
    };
    let bytes = serde_json::to_vec(&request)?;
    let deadline = Instant::now() + Duration::from_secs(1800);
    let mut stream = crate::service::connect_local(SOCKET, deadline)?;
    if crate::service::credentials(&stream)?.uid != 0 {
        return Err("backup receipt service is not root".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    write(&mut stream, &bytes, deadline)?;
    for block in ciphertext.chunks(32768) {
        let mut rest = block;
        while !rest.is_empty() {
            check()?;
            stream.set_write_timeout(Some(remaining(deadline)?.min(Duration::from_millis(100))))?;
            match stream.write(rest) {
                Ok(0) => return Err("backup ciphertext transfer made no progress".into()),
                Ok(count) => rest = &rest[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut size = [0u8; 4];
    read_live(&mut stream, &mut size, deadline, check)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("backup receipt exceeds closed bound".into());
    }
    let mut reply = vec![0; size];
    read_live(&mut stream, &mut reply, deadline, check)?;
    let response: Response = canonical(&reply, MAX_FRAME)?;
    peer_label(&stream, "luma-content-custody (enforce)")?;
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
        || response.prior_base.is_some()
        || response.restore_started.is_some()
        || response.state.binding != input.binding
    {
        return Err("backup receipt response differs from exact request".into());
    }
    let receipt = response
        .receipt
        .ok_or("authenticated backup receipt missing")?;
    receipt.check_data(input, encryption)?;
    if receipt.body.source_state != response.state {
        return Err("backup receipt source cut differs".into());
    }
    check()?;
    Ok(receipt)
}

pub(crate) fn publish(
    profile: &str,
    binding: &OwnerBinding,
    lease: &Token,
    commitment: &[u8],
    record: &[u8],
) -> Result<VerifiedState> {
    HeldPublication::parse(commitment)?;
    if record.is_empty() || record.len() > 8192 {
        return Err("content custody record exceeds closed bound".into());
    }
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: binding.clone(),
        lease: lease.clone(),
        operation: Operation::Publish {
            commitment: std::str::from_utf8(commitment)?.into(),
            record: std::str::from_utf8(record)?.into(),
        },
    })
}
pub(crate) fn restore_start(
    profile: &str,
    input: &crate::content_restore::Input,
    receipt: &backup::Receipt,
    lease: &Token,
) -> Result<VerifiedState> {
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: input.target.clone(),
        lease: lease.clone(),
        operation: Operation::RestoreStart {
            input: input.clone(),
            receipt: receipt.clone(),
        },
    })
}
pub(crate) fn restore_status(
    profile: &str,
    input: &crate::content_restore::Input,
    lease: &Token,
) -> Result<(VerifiedState, bool)> {
    let request = Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: input.target.clone(),
        lease: lease.clone(),
        operation: Operation::RestoreStatus {
            input: input.clone(),
        },
    };
    let bytes = serde_json::to_vec(&request)?;
    let deadline = Instant::now() + DEADLINE;
    let mut stream = crate::service::connect_local(SOCKET, deadline)?;
    if crate::service::credentials(&stream)?.uid != 0 {
        return Err("restore status service is not root".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    write(&mut stream, &bytes, deadline)?;
    let response: Response = canonical(&read(&mut stream, deadline)?, MAX_FRAME)?;
    response.state.validate()?;
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
        || response.state.binding != input.target
        || response.prior_base.is_some()
        || response.receipt.is_some()
    {
        return Err("restore protected status differs from exact request".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    Ok((
        response.state,
        response
            .restore_started
            .ok_or("protected restore status missing")?,
    ))
}
pub(crate) fn restore_preparation_cut(
    profile: &str,
    input: &crate::content_restore::Input,
    lease: &Token,
    request_id: &str,
    review_sha256: &str,
) -> Result<PreparationCut> {
    exchange_cut(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: input.target.clone(),
        lease: lease.clone(),
        operation: Operation::RestorePreparation {
            input: input.clone(),
            request_id: request_id.into(),
            review_sha256: review_sha256.into(),
        },
    })
}
pub(crate) fn restore_publish(
    profile: &str,
    input: &crate::content_restore::Input,
    lease: &Token,
    commitment: &[u8],
    record: &[u8],
) -> Result<VerifiedState> {
    HeldPublication::parse(commitment)?;
    if record.is_empty() || record.len() > 8192 {
        return Err("restore record exceeds fixed canonical bound".into());
    }
    exchange(&Request {
        schema_version: 1,
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(std::path::Path::new("/var"))?,
        binding: input.target.clone(),
        lease: lease.clone(),
        operation: Operation::RestorePublish {
            input: input.clone(),
            commitment: std::str::from_utf8(commitment)?.into(),
            record: std::str::from_utf8(record)?.into(),
        },
    })
}
fn handle(stream: &mut UnixStream) -> Result<()> {
    let confinement = confinement::KernelUnix::capture()?;
    if peer_label(stream, "luma-granted-client (enforce)").is_ok() {
        let bytes = read(stream, Instant::now() + Duration::from_secs(3))?;
        let discriminator: serde_json::Value = serde_json::from_slice(&bytes)?;
        // Presence of a channel discriminator never falls through into Admin.
        // Each selected parser still enforces its complete canonical schema.
        if let Some(purpose) = discriminator.get("purpose") {
            if purpose.as_str() != Some(output::PURPOSE) {
                return Err("unknown closed content controller purpose".into());
            }
            return output::handle(stream, confinement, &bytes);
        }
        return handle_admin(stream, confinement, &bytes);
    }
    let mut deadline = Instant::now() + DEADLINE;
    let peer = crate::service::credentials(stream)?;
    if peer.uid != 0 || peer.pid <= 0 {
        return Err("content custody requires the original root acquisition worker".into());
    }
    let worker_label = if peer_label(stream, "luma-content-restore (enforce)").is_ok() {
        "luma-content-restore (enforce)"
    } else if peer_label(stream, "luma-content-backup (enforce)").is_ok() {
        "luma-content-backup (enforce)"
    } else if peer_label(stream, "luma-office-export (enforce)").is_ok() {
        "luma-office-export (enforce)"
    } else {
        "luma-acquisition (enforce)"
    };
    peer_label(stream, worker_label)?;
    let pin = crate::service::peer_pidfd(stream)?;
    let worker_start = start(peer.pid as u32)?;
    pidfd_alive(&pin)?;
    let bytes = read(stream, deadline)?;
    let request: Request = canonical(&bytes, MAX_FRAME)?;
    if request.schema_version != 1 {
        return Err("unsupported content custody protocol".into());
    }
    let restore_profile = request.profile.starts_with(crate::content_restore::PREFIX);
    if (worker_label == "luma-content-restore (enforce)") != restore_profile
        || (restore_profile
            && !matches!(
                request.operation,
                Operation::Select
                    | Operation::RestoreStatus { .. }
                    | Operation::RestoreStart { .. }
                    | Operation::RestorePreparation { .. }
                    | Operation::RestorePublish { .. }
            ))
        || (!restore_profile
            && matches!(
                request.operation,
                Operation::RestoreStatus { .. }
                    | Operation::RestoreStart { .. }
                    | Operation::RestorePreparation { .. }
                    | Operation::RestorePublish { .. }
            ))
    {
        return Err("restore custody operations require the exact independent secret worker and original Admin batch".into());
    }
    let backup_profile = request.profile.starts_with(crate::content_backup::PREFIX);
    if (worker_label == "luma-content-backup (enforce)") != backup_profile
        || (backup_profile
            && !matches!(
                request.operation,
                Operation::Select
                    | Operation::BackupPrepare { .. }
                    | Operation::BackupReceipt { .. }
            ))
        || (!backup_profile
            && matches!(
                request.operation,
                Operation::BackupPrepare { .. } | Operation::BackupReceipt { .. }
            ))
    {
        return Err(
            "backup custody permits only exact governed export selection and measured receipt"
                .into(),
        );
    }
    if backup_profile {
        deadline = Instant::now() + Duration::from_secs(1800);
    }
    if (worker_label == "luma-office-export (enforce)")
        != request.profile.starts_with(crate::office_export::PREFIX)
        || (request.profile.starts_with(crate::office_export::PREFIX)
            && !matches!(request.operation, Operation::Select))
    {
        return Err("Office export custody permits only exact independently authorized Read selection, never C publication".into());
    }
    let check = || -> Result<Audit> {
        confinement.check()?;
        remaining(deadline)?;
        pidfd_alive(&pin)?;
        if crate::service::credentials(stream)?.pid != peer.pid
            || start(peer.pid as u32)? != worker_start
        {
            return Err("content custody original worker changed".into());
        }
        peer_label(stream, worker_label)?;
        let guard = GuardRequest {
            schema_version: 1,
            action: "resource-content-custody-guard".into(),
            request_id: random()?,
            deadline: crate::resource_manager::now()?
                .checked_add(3000)
                .ok_or("content guard deadline overflow")?,
            lease: request.lease.clone(),
            profile: request.profile.clone(),
            storage_device: request.storage_device.clone(),
            binding: request.binding.clone(),
            worker_pid: peer.pid as u32,
            worker_start,
        };
        let audit = crate::service::content_custody_guard(&guard)?;
        remaining(deadline)?;
        pidfd_alive(&pin)?;
        Ok(audit)
    };
    let original = check()?;
    let mut live = || -> Result<()> {
        if check()? != original {
            return Err("content custody original finite audit changed".into());
        }
        Ok(())
    };
    let mut store = Store::installed(&mut live)?;
    if store.journal.installation != request.binding.installation {
        return Err("content custody request installation differs from sealed authority".into());
    }
    let mut receipt = None;
    let mut restore_started = None;
    let cut = match &request.operation {
        Operation::RestoreStatus { input } => {
            if input.target != request.binding {
                return Err("restore status target differs".into());
            }
            restore_started = Some(store.restore_status(
                input,
                &request.profile,
                &request.storage_device,
                &original,
                &mut live,
            )?);
            PreparationCut {
                current: store.selected(&request.binding, &mut live)?,
                prior_base: None,
            }
        }
        Operation::RestoreStart { input, receipt } => {
            if input.target != request.binding {
                return Err("restore start target differs".into());
            }
            PreparationCut {
                current: store.start_restore(
                    input,
                    receipt,
                    &request.profile,
                    &request.storage_device,
                    &original,
                    &mut live,
                )?,
                prior_base: None,
            }
        }
        Operation::RestorePreparation {
            input,
            request_id,
            review_sha256,
        } => {
            if input.target != request.binding {
                return Err("restore reconciliation target differs".into());
            }
            store.restore_cut(
                input,
                &request.profile,
                &request.storage_device,
                &original,
                request_id,
                review_sha256,
                &mut live,
            )?
        }
        Operation::RestorePublish {
            input,
            commitment,
            record,
        } => {
            if input.target != request.binding {
                return Err("restore publication target differs".into());
            }
            PreparationCut {
                current: store.publish_restore(
                    input,
                    commitment.as_bytes(),
                    record.as_bytes(),
                    &request.profile,
                    &request.storage_device,
                    &original,
                    &mut live,
                )?,
                prior_base: None,
            }
        }
        Operation::BackupPrepare { input } => PreparationCut {
            current: backup::prepare(
                &mut store,
                input,
                &request.profile,
                &request.storage_device,
                &original,
                &mut live,
            )?,
            prior_base: None,
        },
        Operation::BackupReceipt { input, encryption } => {
            backup::prepare(
                &mut store,
                input,
                &request.profile,
                &request.storage_device,
                &original,
                &mut live,
            )?;
            crate::content_backup::validate_encryption(encryption, input)?;
            let mut transfer = stream.try_clone()?;
            let mut digest = Sha256::new();
            let mut block = [0u8; 32768];
            let mut left = encryption.cms_bytes;
            while left > 0 {
                let count = left.min(block.len() as u64) as usize;
                read_live(&mut transfer, &mut block[..count], deadline, &mut live)?;
                digest.update(&block[..count]);
                left -= count as u64;
            }
            loop {
                live()?;
                transfer
                    .set_read_timeout(Some(remaining(deadline)?.min(Duration::from_millis(100))))?;
                match transfer.read(&mut block[..1]) {
                    Ok(0) => break,
                    Ok(_) => {
                        return Err("backup custody transfer has uncommitted trailing bytes".into())
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if bundle::hex(&digest.finalize()) != encryption.cms_sha256 {
                return Err("received ciphertext differs from measured receipt commitment".into());
            }
            receipt = Some(backup::issue(
                &mut store,
                input,
                encryption,
                &request.profile,
                &request.storage_device,
                &original,
                &mut live,
            )?);
            PreparationCut {
                current: store.selected(&request.binding, &mut live)?,
                prior_base: None,
            }
        }
        Operation::Select => PreparationCut {
            current: store.selected(&request.binding, &mut live)?,
            prior_base: None,
        },
        Operation::PreparationCut {
            request_id,
            review_sha256,
        } => store.preparation_cut(
            &request.binding,
            &request.profile,
            &request.storage_device,
            request_id,
            review_sha256,
            &original,
            &mut live,
        )?,
        Operation::RecoveryCut { review } => {
            if review.binding != request.binding {
                return Err("recovery retry belongs to another owner".into());
            }
            store.recovery_cut(
                review,
                &request.profile,
                &request.storage_device,
                &original,
                &mut live,
            )?
        }
        Operation::Quarantine { review } => {
            if review.binding != request.binding {
                return Err("quarantine belongs to another owner".into());
            }
            PreparationCut {
                current: store.quarantine(
                    review,
                    &request.profile,
                    &request.storage_device,
                    &original,
                    &mut live,
                )?,
                prior_base: None,
            }
        }
        Operation::Publish { commitment, record } => {
            let held = HeldPublication::parse(commitment.as_bytes())?;
            if held.binding() != &request.binding {
                return Err("content custody publication belongs to another owner".into());
            }
            PreparationCut {
                current: store.publish(
                    commitment.as_bytes(),
                    record.as_bytes(),
                    &request.profile,
                    &request.storage_device,
                    &original,
                    &mut live,
                )?,
                prior_base: None,
            }
        }
    };
    live()?;
    let response = Response {
        schema_version: 1,
        result: "ok".into(),
        request_sha256: hash(&bytes),
        state: cut.current,
        prior_base: cut.prior_base,
        receipt,
        restore_started,
    };
    write(stream, &serde_json::to_vec(&response)?, deadline)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdminRequest {
    schema_version: u32,
    job: String,
    command: String,
    usage: crate::finite_grants::Use,
    installation: String,
    recipients: Option<super::recipients::Request>,
    retirement: Option<super::retire::Request>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdminResponse {
    schema_version: u32,
    result: String,
    request_sha256: String,
    value: serde_json::Value,
}
pub(super) fn admin_exchange(
    command: &str,
    usage: &crate::finite_grants::Use,
    installation: &str,
    job: &str,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<serde_json::Value> {
    admin_exchange_request(command, usage, installation, job, None, None, cancel)
}
pub(super) fn admin_recipients_exchange(
    usage: &crate::finite_grants::Use,
    installation: &str,
    job: &str,
    request: super::recipients::Request,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<serde_json::Value> {
    request.validate()?;
    admin_exchange_request(
        "content-backup-recipients-enroll",
        usage,
        installation,
        job,
        Some(request),
        None,
        cancel,
    )
}
pub(super) fn admin_retirement_exchange(
    command: &str,
    usage: &crate::finite_grants::Use,
    installation: &str,
    job: &str,
    request: super::retire::Request,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<serde_json::Value> {
    admin_exchange_request(
        command,
        usage,
        installation,
        job,
        None,
        Some(request),
        cancel,
    )
}
fn admin_exchange_request(
    command: &str,
    usage: &crate::finite_grants::Use,
    installation: &str,
    job: &str,
    recipients: Option<super::recipients::Request>,
    retirement: Option<super::retire::Request>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<serde_json::Value> {
    super::admin_scope(command, usage)?;
    digest(installation)?;
    tpm::decode::<16>(job)?;
    let check = || -> Result<()> {
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            return Err("original content Admin controller fenced".into());
        }
        Ok(())
    };
    check()?;
    let request = AdminRequest {
        schema_version: 1,
        job: job.into(),
        command: command.into(),
        usage: usage.clone(),
        installation: installation.into(),
        recipients,
        retirement,
    };
    let bytes = serde_json::to_vec(&request)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut stream = crate::service::connect_local(SOCKET, deadline)?;
    if crate::service::credentials(&stream)?.uid != 0 {
        return Err("content custody Admin service is not root".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    check()?;
    write(&mut stream, &bytes, deadline)?;
    let response: AdminResponse =
        canonical(&read(&mut stream, deadline)?, usage.output_bytes as usize)?;
    check()?;
    peer_label(&stream, "luma-content-custody (enforce)")?;
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
        || !response.value.is_object()
    {
        return Err("content Admin custody response differs from exact operation".into());
    }
    Ok(response.value)
}
fn handle_admin(
    stream: &mut UnixStream,
    confinement: confinement::KernelUnix,
    bytes: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let peer = crate::service::credentials(stream)?;
    if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 {
        return Err("content custody Admin requires original bounded grant client".into());
    }
    peer_label(stream, "luma-granted-client (enforce)")?;
    let pin = crate::service::peer_pidfd(stream)?;
    let client_start = start(peer.pid as u32)?;
    pidfd_alive(&pin)?;
    let request: AdminRequest = canonical(bytes, MAX_FRAME)?;
    if request.schema_version != 1 {
        return Err("unsupported content Admin protocol".into());
    }
    super::admin_scope(&request.command, &request.usage)?;
    if (request.command == "content-backup-recipients-enroll") != request.recipients.is_some() {
        return Err("content custody Admin payload differs from exact closed ceremony".into());
    }
    if matches!(
        request.command.as_str(),
        super::retire::INSPECT | super::retire::RETIRE
    ) != request.retirement.is_some()
    {
        return Err("content Admin retirement payload differs from exact original command".into());
    }
    digest(&request.installation)?;
    let original_check = || -> Result<Audit> {
        confinement.check()?;
        remaining(deadline)?;
        pidfd_alive(&pin)?;
        if crate::service::credentials(stream)?.pid != peer.pid
            || start(peer.pid as u32)? != client_start
        {
            return Err("content custody original Admin client generation changed".into());
        }
        peer_label(stream, "luma-granted-client (enforce)")?;
        let request = crate::service::content_admin::Guard {
            schema_version: 1,
            action: "resource-content-admin-guard".into(),
            request_id: random()?,
            deadline: crate::resource_manager::now()?
                .checked_add(3000)
                .ok_or("content Admin deadline overflow")?,
            job: request.job.clone(),
            client_pid: peer.pid as u32,
            client_start,
            command: request.command.clone(),
            usage: request.usage.clone(),
        };
        let audit = crate::service::content_admin::proof(&request)?;
        remaining(deadline)?;
        pidfd_alive(&pin)?;
        Ok(audit)
    };
    let original = original_check()?;
    let mut live = || -> Result<()> {
        if original_check()? != original {
            return Err("content custody original Admin audit changed".into());
        }
        Ok(())
    };
    let mut store = Store::installed(&mut live)?;
    if store.journal.installation != request.installation {
        return Err("content custody Admin installation differs from enrolled C authority".into());
    }
    let value = if let Some(retirement) = &request.retirement {
        store.execute_retirement(retirement, &request.command, &original, &mut live)?
    } else if let Some(recipients) = &request.recipients {
        super::recipients::execute(&mut store, recipients, &original, &mut live)?
    } else {
        super::signer::execute(&mut store, &request.command, &original, &mut live)?
    };
    live()?;
    let response = AdminResponse {
        schema_version: 1,
        result: "ok".into(),
        request_sha256: hash(bytes),
        value,
    };
    let bytes = serde_json::to_vec(&response)?;
    if bytes.len() > request.usage.output_bytes as usize {
        return Err("content custody Admin response exceeds finite output bound".into());
    }
    write(stream, &bytes, deadline)
}
pub(crate) fn run() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    // The broker's genuine activated original-client proof is still mandatory
    // before any private authority input is opened, on both image variants.
    crate::platform::production_image()?;
    if fs::read_to_string("/proc/self/cgroup")? != "0::/system.slice/luma-content-custody.service\n"
        || fs::read_to_string("/proc/self/attr/current")? != "luma-content-custody (enforce)\n"
    {
        return Err("content custody requires its fixed isolated unit".into());
    }
    let runtime = std::path::Path::new(SOCKET)
        .parent()
        .ok_or("content custody runtime parent missing")?;
    let metadata = fs::symlink_metadata(runtime)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(runtime)? != runtime
    {
        return Err("content custody runtime namespace is not private and canonical".into());
    }
    super::super::absent(std::path::Path::new(SOCKET))?;
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))?;
    for accepted in listener.incoming() {
        match accepted {
            Ok(mut stream) => {
                let _ = handle(&mut stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err("content custody listener stopped unexpectedly".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_transport_refuses_zero_oversized_truncation_and_timeout() {
        for length in [0u32, MAX_FRAME as u32 + 1, 12] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(&length.to_be_bytes()).unwrap();
            drop(writer);
            assert!(read(&mut reader, Instant::now() + Duration::from_millis(100)).is_err());
        }
        let (mut reader, _writer) = UnixStream::pair().unwrap();
        assert!(read(&mut reader, Instant::now() + Duration::from_millis(10)).is_err());
    }
    #[test]
    fn ciphertext_transfer_rechecks_revocation_while_the_peer_is_idle() {
        let (mut reader, _writer) = UnixStream::pair().unwrap();
        let mut checks = 0;
        let mut check = || -> Result<()> {
            checks += 1;
            if checks >= 2 {
                return Err("explicit fixture revocation".into());
            }
            Ok(())
        };
        let mut byte = [0u8; 1];
        assert!(read_live(
            &mut reader,
            &mut byte,
            Instant::now() + Duration::from_secs(1),
            &mut check
        )
        .is_err());
        assert_eq!(checks, 2);
    }
}
