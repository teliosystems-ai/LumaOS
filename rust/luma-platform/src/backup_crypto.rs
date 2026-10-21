//! Isolated, bounded CMS encryption/decryption of inert content-backup data.
//!
//! Recipient pins and the decryption input commitment must come from genuine
//! governed custody. Checksums, certificates, successful decryption and this
//! component are not export, authenticity, rollback or restoration authority.
use crate::{sealed_credential::PrivateBuffer, Result};
#[cfg(test)]
use luma_content_store::BackupInspection;
use luma_content_store::{ContentBackup, MAX_CONTENT_BACKUP_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(not(test))]
const HELPER: &str = "/usr/libexec/luma-os/luma-backup-crypto";
const CHUNK: usize = 32768;
const MAX_CERTIFICATE: usize = 8192;
const MAX_PRIVATE_KEY: usize = 16384;
pub(crate) const MAX_ENCRYPTED_BACKUP_BYTES: usize = MAX_CONTENT_BACKUP_BYTES + 65536;
const DEADLINE: Duration = Duration::from_secs(1800);
const POLL: Duration = Duration::from_millis(100);
const ACK: u8 = 0xa7;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientPin {
    pub certificate_sha256: String,
    pub spki_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientPins {
    pub owner: RecipientPin,
    pub offline_admin: RecipientPin,
}

impl RecipientPins {
    pub(crate) fn validate(&self) -> Result<()> {
        for pin in [&self.owner, &self.offline_admin] {
            canonical_sha(&pin.certificate_sha256)?;
            canonical_sha(&pin.spki_sha256)?;
        }
        if self.owner.certificate_sha256 == self.offline_admin.certificate_sha256
            || self.owner.spki_sha256 == self.offline_admin.spki_sha256
        {
            return Err("backup recipients must have independent governed keys".into());
        }
        Ok(())
    }
}

/// Public DER certificates plus separately supplied custody commitments. The
/// constructor verifies bytes only; it does not enroll or trust either key.
pub(crate) struct Recipients {
    owner: Vec<u8>,
    offline_admin: Vec<u8>,
    pins: RecipientPins,
}

impl Recipients {
    pub(crate) fn pins(&self) -> &RecipientPins {
        &self.pins
    }
    pub(crate) fn new(owner: &[u8], offline_admin: &[u8], pins: RecipientPins) -> Result<Self> {
        pins.validate()?;
        for (bytes, pin) in [(owner, &pins.owner), (offline_admin, &pins.offline_admin)] {
            if bytes.is_empty()
                || bytes.len() > MAX_CERTIFICATE
                || luma_content::sha256(bytes) != pin.certificate_sha256
            {
                return Err("backup certificate differs from its independent custody pin".into());
            }
        }
        Ok(Self {
            owner: owner.to_vec(),
            offline_admin: offline_admin.to_vec(),
            pins,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CryptoOperation {
    Encrypt,
    DecryptOwner,
    DecryptOfflineAdmin,
}

/// Exact input and recipients checked by the live composition root. For
/// decryption the ciphertext SHA must also match a separately authenticated
/// custody receipt; accepting a self-reported SHA is not authentication.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CryptoRequest {
    pub schema_version: u32,
    pub operation: CryptoOperation,
    pub input_sha256: String,
    pub input_bytes: u64,
    pub recipients: RecipientPins,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CryptoBudget {
    pub child_memory_bytes: u64,
    pub parent_memory_bytes: u64,
    pub aggregate_memory_bytes: u64,
    pub aggregate_locked_bytes: u64,
    pub maximum_output_bytes: u64,
    pub tasks: u32,
    pub maximum_seconds: u32,
}

impl CryptoBudget {
    fn fixed(operation: CryptoOperation) -> Self {
        Self {
            child_memory_bytes: 512 * 1024 * 1024,
            parent_memory_bytes: 192 * 1024 * 1024,
            aggregate_memory_bytes: 704 * 1024 * 1024,
            aggregate_locked_bytes: 640 * 1024 * 1024,
            maximum_output_bytes: if operation == CryptoOperation::Encrypt {
                MAX_ENCRYPTED_BACKUP_BYTES as u64
            } else {
                MAX_CONTENT_BACKUP_BYTES as u64
            },
            tasks: 2,
            maximum_seconds: 1800,
        }
    }
}

/// No default or Read-only implementation. An installed adapter must bind the
/// request to current principal/session/purpose, finite Export/import grants,
/// UTC, custody generation and resource acquisition. Checks continue while the
/// helper is busy, not only between successful data chunks.
pub(crate) trait CryptoBoundary {
    fn admit(&mut self, request: &CryptoRequest, budget: CryptoBudget) -> Result<()>;
    fn check(&mut self, request: &CryptoRequest) -> Result<()>;
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptionCommitment {
    pub schema_version: u32,
    pub profile: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub cms_sha256: String,
    pub cms_bytes: u64,
    pub recipients: RecipientPins,
    pub authenticates_sender: bool,
    pub proves_both_recipients_recoverable: bool,
    pub permits_restore: bool,
}

pub(crate) struct EncryptedBackup {
    bytes: Vec<u8>,
    commitment: EncryptionCommitment,
}
impl EncryptedBackup {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn commitment(&self) -> &EncryptionCommitment {
        &self.commitment
    }
}

/// Plaintext is never a Vec, Debug value, serialized result or temporary file.
/// All pages are locked/nondumpable and wiped before release, including errors.
struct LockedData {
    pointer: *mut u8,
    length: usize,
}
impl LockedData {
    fn new(length: usize) -> Result<Self> {
        if length == 0 || length > MAX_CONTENT_BACKUP_BYTES {
            return Err("decrypted backup exceeds fixed data bound".into());
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = Self {
            pointer: pointer.cast(),
            length,
        };
        if unsafe { libc::mlock(pointer, length) } != 0
            || unsafe { libc::madvise(pointer, length, libc::MADV_DONTDUMP) } != 0
        {
            return Err("cannot lock/protect decrypted data; no pageable fallback".into());
        }
        Ok(result)
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer, self.length) }
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer, self.length) }
    }
}
impl Drop for LockedData {
    fn drop(&mut self) {
        for index in 0..self.length {
            unsafe { std::ptr::write_volatile(self.pointer.add(index), 0) };
        }
        unsafe {
            libc::munlock(self.pointer.cast(), self.length);
            libc::munmap(self.pointer.cast(), self.length);
        }
    }
}

pub(crate) struct DecryptedBackup {
    data: LockedData,
    request: CryptoRequest,
}
impl DecryptedBackup {
    pub(crate) fn data_checked<'a>(
        &'a self,
        boundary: &mut impl CryptoBoundary,
    ) -> Result<&'a [u8]> {
        boundary.check(&self.request)?;
        Ok(self.data.bytes())
    }
    /// Reconstruction inspects original archive data only. It never restores
    /// credentials, grants, sessions, TPM state, accounts, or production heads.
    #[cfg(test)]
    pub(crate) fn inspect(&self, boundary: &mut impl CryptoBoundary) -> Result<BackupInspection> {
        boundary.check(&self.request)?;
        let inspection =
            luma_content_store::inspect_backup_data_checked(self.data.bytes(), &mut || {
                boundary.check(&self.request)
            })?;
        boundary.check(&self.request)?;
        Ok(inspection)
    }
}

fn canonical_sha(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("backup commitment must be canonical SHA-256".into());
    }
    crate::tpm::decode(value)
}

fn checked_digest(
    bytes: &[u8],
    request: &CryptoRequest,
    boundary: &mut impl CryptoBoundary,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(CHUNK) {
        boundary.check(request)?;
        hash.update(chunk);
    }
    boundary.check(request)?;
    Ok(hash.finalize().into())
}

fn helper() -> PathBuf {
    #[cfg(not(test))]
    {
        PathBuf::from(HELPER)
    }
    #[cfg(test)]
    {
        Path::new(env!("OUT_DIR")).join("luma-backup-crypto")
    }
}

fn trusted_helper(at: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("backup helper must be an immutable regular executable".into());
    }
    #[cfg(not(test))]
    if metadata.uid() != 0 || metadata.mode() & 0o7000 != 0 {
        return Err("backup helper must be root-owned without special executable bits".into());
    }
    Ok(file)
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Channel<'a, B> {
    stream: UnixStream,
    deadline: Instant,
    request: &'a CryptoRequest,
    boundary: &'a mut B,
}
impl<B: CryptoBoundary> Channel<'_, B> {
    fn check(&mut self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err("backup crypto exceeded fixed wall deadline".into());
        }
        self.boundary.check(self.request)
    }
    fn read(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check()?;
            match self.stream.read(bytes) {
                Ok(0) => return Err("backup helper closed its authenticated operation".into()),
                Ok(count) => {
                    bytes = &mut bytes[count..];
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.check()
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check()?;
            match self.stream.write(bytes) {
                Ok(0) => return Err("backup helper refused input".into()),
                Ok(count) => {
                    bytes = &bytes[count..];
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.check()
    }
    fn acknowledge(&mut self) -> Result<()> {
        self.write(&[ACK])
    }
}

enum Output {
    Encrypted(Vec<u8>),
    Decrypted(LockedData),
}
impl Output {
    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Encrypted(bytes) => bytes,
            Self::Decrypted(bytes) => bytes.bytes_mut(),
        }
    }
}

fn run(
    input: &[u8],
    recipients: &Recipients,
    key: Option<&PrivateBuffer>,
    request: &CryptoRequest,
    boundary: &mut impl CryptoBoundary,
) -> Result<Output> {
    let budget = CryptoBudget::fixed(request.operation);
    boundary.admit(request, budget)?;
    boundary.check(request)?;
    let original_executable = trusted_helper(&helper())?;
    let executable_fd =
        unsafe { libc::fcntl(original_executable.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 32) };
    if executable_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let executable = unsafe { File::from_raw_fd(executable_fd) };
    drop(original_executable);
    let actual_hash = checked_digest(input, request, boundary)?;
    if actual_hash != canonical_sha(&request.input_sha256)? {
        return Err("backup differs from independently selected input commitment".into());
    }
    boundary.check(request)?;
    let (socket, child_socket) = UnixStream::pair()?;
    socket.set_read_timeout(Some(POLL))?;
    socket.set_write_timeout(Some(POLL))?;
    let inherited_key = if let Some(key) = key {
        if key.bytes().is_empty() || key.bytes().len() > MAX_PRIVATE_KEY {
            return Err("backup PKCS#8 key outside locked-input bound".into());
        }
        let descriptor = key.descriptor()?;
        let duplicate = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Some(unsafe { File::from_raw_fd(duplicate) })
    } else {
        None
    };
    // Execute the checked descriptor, not a path that can be renamed between
    // inspection and exec. The open FD remains alive until spawn completes.
    let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let key_fd = inherited_key.as_ref().map(AsRawFd::as_raw_fd);
    unsafe {
        command.pre_exec(move || {
            if let Some(fd) = key_fd {
                if libc::dup2(fd, 3) != 3 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    boundary.check(request)?;
    let mut child = Running(command.spawn()?);
    // Command retains its configured Stdio descriptors after spawn. Release
    // the parent's duplicate of the child's socket so helper failure yields
    // EOF immediately rather than hiding it until the operation deadline.
    drop(command);
    let mut channel = Channel {
        stream: socket,
        deadline: Instant::now() + DEADLINE,
        request,
        boundary,
    };
    let mut header = [0_u8; 200];
    header[..16].copy_from_slice(b"LUMACMSBACKUP01\n");
    header[16] = if request.operation == CryptoOperation::Encrypt {
        1
    } else {
        2
    };
    header[17] = match request.operation {
        CryptoOperation::Encrypt => 255,
        CryptoOperation::DecryptOwner => 0,
        CryptoOperation::DecryptOfflineAdmin => 1,
    };
    header[20..24].copy_from_slice(&(key.map_or(0, |key| key.bytes().len()) as u32).to_be_bytes());
    header[24..28].copy_from_slice(&(recipients.owner.len() as u32).to_be_bytes());
    header[28..32].copy_from_slice(&(recipients.offline_admin.len() as u32).to_be_bytes());
    header[32..40].copy_from_slice(&(input.len() as u64).to_be_bytes());
    header[40..72].copy_from_slice(&canonical_sha(&request.input_sha256)?);
    for (offset, pin) in [
        (72, &recipients.pins.owner),
        (136, &recipients.pins.offline_admin),
    ] {
        header[offset..offset + 32].copy_from_slice(&canonical_sha(&pin.certificate_sha256)?);
        header[offset + 32..offset + 64].copy_from_slice(&canonical_sha(&pin.spki_sha256)?);
    }
    channel.write(&header)?;
    channel.write(&recipients.owner)?;
    channel.write(&recipients.offline_admin)?;
    let mut input_offset = 0_usize;
    let mut output_offset = 0_usize;
    let mut output: Option<Output> = None;
    loop {
        let mut event = [0_u8; 9];
        channel.read(&mut event)?;
        let value = u64::from_be_bytes(event[1..].try_into()?);
        match event[0] {
            1 if value == 0 => channel.acknowledge()?,
            2 if output.is_none() && value > 0 && value <= CHUNK as u64 => {
                let end = input_offset
                    .checked_add(value as usize)
                    .ok_or("backup input overflow")?;
                if end > input.len() {
                    return Err("backup helper requested excess input".into());
                }
                channel.acknowledge()?;
                channel.write(&input[input_offset..end])?;
                input_offset = end;
            }
            3 if output.is_none()
                && input_offset == input.len()
                && value > 0
                && value <= budget.maximum_output_bytes =>
            {
                channel.check()?;
                output = Some(if request.operation == CryptoOperation::Encrypt {
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(value as usize)?;
                    bytes.resize(value as usize, 0);
                    Output::Encrypted(bytes)
                } else {
                    Output::Decrypted(LockedData::new(value as usize)?)
                });
                channel.acknowledge()?;
            }
            4 if output.is_some() && value > 0 && value <= CHUNK as u64 => {
                let bytes = output.as_mut().ok_or("backup output absent")?.bytes_mut();
                let end = output_offset
                    .checked_add(value as usize)
                    .ok_or("backup output overflow")?;
                if end > bytes.len() {
                    return Err("backup helper exceeded output commitment".into());
                }
                channel.acknowledge()?;
                channel.read(&mut bytes[output_offset..end])?;
                output_offset = end;
            }
            5 if output.is_some()
                && input_offset == input.len()
                && value == output_offset as u64 =>
            {
                if output
                    .as_mut()
                    .ok_or("backup output absent")?
                    .bytes_mut()
                    .len()
                    != output_offset
                {
                    return Err("backup helper returned truncated output".into());
                }
                channel.acknowledge()?;
                loop {
                    channel.check()?;
                    if let Some(status) = child.0.try_wait()? {
                        if !status.success() {
                            return Err("backup helper refused finalization".into());
                        }
                        break;
                    }
                    // A short, interruptible poll keeps authority live until
                    // the exact child has exited and private cleanup finished.
                    let mut descriptor = libc::pollfd {
                        fd: channel.stream.as_raw_fd(),
                        events: libc::POLLHUP,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
                    if result < 0
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        return Err(std::io::Error::last_os_error().into());
                    }
                }
                channel.check()?;
                return output.ok_or_else(|| "backup helper returned no output".into());
            }
            _ => return Err("backup helper violated the closed bounded protocol".into()),
        }
    }
}

pub(crate) fn encrypt_backup_data(
    backup: &ContentBackup,
    recipients: &Recipients,
    boundary: &mut impl CryptoBoundary,
) -> Result<EncryptedBackup> {
    encrypt_data(backup.bytes(), backup.sha256(), recipients, boundary)
}

pub(crate) fn encrypt_data(
    data: &[u8],
    archive_sha256: &str,
    recipients: &Recipients,
    boundary: &mut impl CryptoBoundary,
) -> Result<EncryptedBackup> {
    if data.is_empty() || data.len() > MAX_CONTENT_BACKUP_BYTES {
        return Err("backup data outside fixed archive limit".into());
    }
    let request = CryptoRequest {
        schema_version: 1,
        operation: CryptoOperation::Encrypt,
        input_sha256: archive_sha256.into(),
        input_bytes: data.len() as u64,
        recipients: recipients.pins().clone(),
    };
    let Output::Encrypted(bytes) = run(data, recipients, None, &request, boundary)? else {
        return Err("backup helper returned a different operation".into());
    };
    finish_encryption(bytes, &request, boundary)
}

/// Hash and deliver only while the exact request remains authorized. This is
/// shared by the actual helper path and deterministic terminal-revocation tests.
fn finish_encryption(
    bytes: Vec<u8>,
    request: &CryptoRequest,
    boundary: &mut impl CryptoBoundary,
) -> Result<EncryptedBackup> {
    let cipher_sha = checked_digest(&bytes, request, boundary)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let commitment = EncryptionCommitment {
        schema_version: 1,
        profile: "cms-auth-enveloped-aes256gcm-rsa-oaep-sha256-two-recipients-v1".into(),
        archive_sha256: request.input_sha256.clone(),
        archive_bytes: request.input_bytes,
        cms_sha256: cipher_sha,
        cms_bytes: bytes.len() as u64,
        recipients: request.recipients.clone(),
        authenticates_sender: false,
        proves_both_recipients_recoverable: false,
        permits_restore: false,
    };
    boundary.check(request)?;
    Ok(EncryptedBackup { bytes, commitment })
}

pub(crate) fn decrypt_backup_data(
    ciphertext: &[u8],
    expected_ciphertext_sha256: &str,
    recipients: &Recipients,
    role: CryptoOperation,
    key: &PrivateBuffer,
    boundary: &mut impl CryptoBoundary,
) -> Result<DecryptedBackup> {
    canonical_sha(expected_ciphertext_sha256)?;
    if role == CryptoOperation::Encrypt
        || ciphertext.is_empty()
        || ciphertext.len() > MAX_ENCRYPTED_BACKUP_BYTES
    {
        return Err("invalid bounded backup decryption operation".into());
    }
    let request = CryptoRequest {
        schema_version: 1,
        operation: role,
        input_sha256: expected_ciphertext_sha256.into(),
        input_bytes: ciphertext.len() as u64,
        recipients: recipients.pins.clone(),
    };
    let Output::Decrypted(data) = run(ciphertext, recipients, Some(key), &request, boundary)?
    else {
        return Err("backup helper returned a different operation".into());
    };
    boundary.check(&request)?;
    Ok(DecryptedBackup { data, request })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    // Only disposable fixtures use this boundary. It is never compiled into an
    // installed adapter and explicitly checks the expected request and budget.
    pub(crate) struct Guard {
        expected: CryptoRequest,
        pub(crate) admitted: bool,
        checks: usize,
        refuse_at: usize,
        refuse_budget: bool,
    }
    impl Guard {
        pub(crate) fn new(recipients: &Recipients, operation: CryptoOperation, input: &[u8]) -> Self {
            Self {
                expected: CryptoRequest {
                    schema_version: 1,
                    operation,
                    input_sha256: luma_content::sha256(input),
                    input_bytes: input.len() as u64,
                    recipients: recipients.pins.clone(),
                },
                admitted: false,
                checks: 0,
                refuse_at: usize::MAX,
                refuse_budget: false,
            }
        }
    }
    impl CryptoBoundary for Guard {
        fn admit(&mut self, request: &CryptoRequest, budget: CryptoBudget) -> Result<()> {
            if self.admitted
                || self.refuse_budget
                || request != &self.expected
                || budget != CryptoBudget::fixed(request.operation)
                || budget.aggregate_memory_bytes
                    != budget.child_memory_bytes + budget.parent_memory_bytes
                || budget.tasks != 2
            {
                return Err("software fixture refused exact crypto admission".into());
            }
            self.admitted = true;
            Ok(())
        }
        fn check(&mut self, request: &CryptoRequest) -> Result<()> {
            self.checks += 1;
            if !self.admitted || request != &self.expected || self.checks >= self.refuse_at {
                return Err("software fixture revoked exact crypto authorization".into());
            }
            Ok(())
        }
    }

    // Generate real disposable RSA fixtures without disk/argv key material.
    // Unlike production custody, these software keys carry no deployment trust.
    fn openssl(
        args: &[String],
        input: Option<&PrivateBuffer>,
        inherited: Option<&PrivateBuffer>,
        capacity: usize,
    ) -> PrivateBuffer {
        let output = PrivateBuffer::new(capacity).unwrap();
        let mut descriptor = output.descriptor().unwrap();
        let auxiliary = inherited.map(|key| key.descriptor().unwrap());
        let actual_args = args
            .iter()
            .map(|argument| {
                if argument == "fixture-private-descriptor" {
                    format!("/proc/self/fd/{}", auxiliary.as_ref().unwrap().as_raw_fd())
                } else {
                    argument.clone()
                }
            })
            .collect::<Vec<_>>();
        let mut command = Command::new("/usr/bin/openssl");
        command
            .env_clear()
            .env("LANG", "C")
            .env("OPENSSL_CONF", "/dev/null")
            .args(&actual_args)
            .stderr(Stdio::null())
            .stdout(Stdio::from(descriptor.try_clone().unwrap()));
        command.stdin(match input {
            Some(bytes) => Stdio::from(bytes.descriptor().unwrap()),
            None => Stdio::null(),
        });
        let inherited_fd = auxiliary.as_ref().map(AsRawFd::as_raw_fd);
        unsafe {
            command.pre_exec(move || {
                if let Some(fd) = inherited_fd {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let output_bound = libc::rlimit {
                    rlim_cur: capacity as _,
                    rlim_max: capacity as _,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &output_bound) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = Running(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "software-only OpenSSL fixture command failed"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "software-only fixture generation exceeded bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let length = descriptor.stream_position().unwrap() as usize;
        assert!(length > 0 && length <= capacity);
        let mut exact = PrivateBuffer::new(length).unwrap();
        exact.bytes_mut().copy_from_slice(&output.bytes()[..length]);
        descriptor.seek(SeekFrom::Start(0)).unwrap();
        exact
    }
    fn arguments(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).into()).collect()
    }

    pub(crate) struct KeyFixture {
        pub(crate) key: PrivateBuffer,
        pub(crate) certificate: Vec<u8>,
        pub(crate) pin: RecipientPin,
    }
    impl KeyFixture {
        pub(crate) fn new(bits: u32) -> Self {
            Self::with_usage(bits, "critical,keyEncipherment")
        }
        fn with_usage(bits: u32, usage: &str) -> Self {
            let pem = openssl(
                &arguments(&[
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    &format!("rsa_keygen_bits:{bits}"),
                ]),
                None,
                None,
                8192,
            );
            let key = openssl(
                &arguments(&[
                    "pkcs8", "-topk8", "-nocrypt", "-inform", "PEM", "-outform", "DER",
                ]),
                Some(&pem),
                None,
                8192,
            );
            let cert = openssl(
                &arguments(&[
                    "req",
                    "-new",
                    "-x509",
                    "-keyform",
                    "DER",
                    "-key",
                    "fixture-private-descriptor",
                    "-subj",
                    "/CN=disposable-software-backup-fixture",
                    "-days",
                    "1",
                    "-addext",
                    "subjectKeyIdentifier=hash",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-addext",
                    &format!("keyUsage={usage}"),
                    "-outform",
                    "DER",
                ]),
                None,
                Some(&key),
                8192,
            );
            let public_pem = openssl(
                &arguments(&["x509", "-inform", "DER", "-pubkey", "-noout"]),
                Some(&cert),
                None,
                8192,
            );
            let public = openssl(
                &arguments(&["pkey", "-pubin", "-outform", "DER"]),
                Some(&public_pem),
                None,
                8192,
            );
            Self {
                key,
                certificate: cert.bytes().to_vec(),
                pin: RecipientPin {
                    certificate_sha256: luma_content::sha256(cert.bytes()),
                    spki_sha256: luma_content::sha256(public.bytes()),
                },
            }
        }
    }

    #[test]
    fn governed_recipient_enrollment_uses_real_der_keys_usage_and_independent_pins() {
        let owner = KeyFixture::new(3072);
        let admin = KeyFixture::new(3072);
        let pins = RecipientPins {
            owner: owner.pin.clone(),
            offline_admin: admin.pin.clone(),
        };
        crate::receipt_signer::validate_recipients(
            &owner.certificate,
            &admin.certificate,
            &pins,
            || Ok(()),
        )
        .unwrap();
        let mut changed = pins.clone();
        changed.owner.spki_sha256 = "ab".repeat(32);
        assert!(crate::receipt_signer::validate_recipients(
            &owner.certificate,
            &admin.certificate,
            &changed,
            || Ok(())
        )
        .is_err());
        let mut extended = owner.certificate.clone();
        extended.push(0);
        changed = pins.clone();
        changed.owner.certificate_sha256 = luma_content::sha256(&extended);
        assert!(crate::receipt_signer::validate_recipients(
            &extended,
            &admin.certificate,
            &changed,
            || Ok(())
        )
        .is_err());
        for invalid in [
            KeyFixture::new(2048),
            KeyFixture::with_usage(3072, "critical,digitalSignature,keyEncipherment"),
        ] {
            let changed = RecipientPins {
                owner: owner.pin.clone(),
                offline_admin: invalid.pin.clone(),
            };
            assert!(crate::receipt_signer::validate_recipients(
                &owner.certificate,
                &invalid.certificate,
                &changed,
                || Ok(())
            )
            .is_err());
        }
        let same = RecipientPins {
            owner: owner.pin.clone(),
            offline_admin: owner.pin.clone(),
        };
        assert!(crate::receipt_signer::validate_recipients(
            &owner.certificate,
            &owner.certificate,
            &same,
            || Ok(())
        )
        .is_err());
        assert!(crate::receipt_signer::validate_recipients(
            &owner.certificate,
            &admin.certificate,
            &pins,
            || Err("revoked recipient ceremony".into())
        )
        .is_err());
    }

    fn data() -> Vec<u8> {
        use luma_content_store::{BackupManifest, BackupNamespace, PreparationDirectoryIdentity};
        let binding = luma_content::OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 7,
        };
        let directory = |inode| PreparationDirectoryIdentity {
            device: 1,
            inode,
            owner: 1000,
            group: 1000,
            mode: libc::S_IFDIR | 0o700,
        };
        let manifest = BackupManifest {
            schema_version: 1,
            format: "luma-content-data-backup-v1".into(),
            committed_head_sha256: luma_content::sha256(
                &serde_json::to_vec(&(
                    "luma-content-verified-outcome-history-v1",
                    &binding,
                    Vec::<serde_json::Value>::new(),
                ))
                .unwrap(),
            ),
            binding,
            source_namespace: BackupNamespace {
                root: directory(1),
                committed: directory(2),
                pending: directory(3),
                quarantined: None,
            },
            committed_outcomes: 0,
            directories: vec![],
            data_bytes: 0,
        };
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let mut data = b"LUMACONTENTBK01\n".to_vec();
        data.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        data.extend_from_slice(&encoded);
        assert!(luma_content_store::inspect_backup_data(&data).is_ok());
        data
    }

    fn tlv(bytes: &[u8], start: usize) -> (usize, usize) {
        let lead = bytes[start + 1];
        if lead < 128 {
            (start + 2, start + 2 + lead as usize)
        } else {
            let count = (lead & 127) as usize;
            let length = bytes[start + 2..start + 2 + count]
                .iter()
                .fold(0_usize, |length, byte| (length << 8) | *byte as usize);
            (start + 2 + count, start + 2 + count + length)
        }
    }
    fn first_wrapped_key(bytes: &[u8]) -> usize {
        let (ci, _) = tlv(bytes, 0);
        let (_, after_oid) = tlv(bytes, ci);
        let (explicit, _) = tlv(bytes, after_oid);
        let (auth, _) = tlv(bytes, explicit);
        let (_, after_version) = tlv(bytes, auth);
        let (recipients, _) = tlv(bytes, after_version);
        let (recipient, _) = tlv(bytes, recipients);
        let (_, after_version) = tlv(bytes, recipient);
        let (_, after_id) = tlv(bytes, after_version);
        let (_, after_algorithm) = tlv(bytes, after_id);
        tlv(bytes, after_algorithm).0
    }

    #[test]
    fn real_cms_two_recipient_roundtrip_refusals_and_no_implicit_restore() {
        let owner = KeyFixture::new(3072);
        let admin = KeyFixture::new(3072);
        let pins = RecipientPins {
            owner: owner.pin.clone(),
            offline_admin: admin.pin.clone(),
        };
        let recipients =
            Recipients::new(&owner.certificate, &admin.certificate, pins.clone()).unwrap();
        let data = data();
        let archive_sha = luma_content::sha256(&data);
        let mut export = Guard::new(&recipients, CryptoOperation::Encrypt, &data);
        let encrypted = encrypt_data(&data, &archive_sha, &recipients, &mut export).unwrap();
        let commitment = encrypted.commitment();
        assert_eq!(commitment.archive_sha256, archive_sha);
        assert_eq!(
            commitment.cms_sha256,
            luma_content::sha256(encrypted.bytes())
        );
        assert!(
            !commitment.authenticates_sender
                && !commitment.permits_restore
                && !commitment.proves_both_recipients_recoverable
        );
        for (role, key) in [
            (CryptoOperation::DecryptOwner, &owner.key),
            (CryptoOperation::DecryptOfflineAdmin, &admin.key),
        ] {
            let mut guard = Guard::new(&recipients, role, encrypted.bytes());
            let decrypted = decrypt_backup_data(
                encrypted.bytes(),
                &commitment.cms_sha256,
                &recipients,
                role,
                key,
                &mut guard,
            )
            .unwrap();
            assert_eq!(decrypted.data.bytes(), data);
            let inspected = decrypted.inspect(&mut guard).unwrap();
            assert_eq!(inspected.archive_sha256, archive_sha);
            assert!(!inspected.restore_permitted && !inspected.authority_returned);
            guard.refuse_at = guard.checks + 1;
            assert!(decrypted.inspect(&mut guard).is_err());
        }
        let mut wrong_key = Guard::new(
            &recipients,
            CryptoOperation::DecryptOfflineAdmin,
            encrypted.bytes(),
        );
        assert!(decrypt_backup_data(
            encrypted.bytes(),
            &commitment.cms_sha256,
            &recipients,
            CryptoOperation::DecryptOfflineAdmin,
            &owner.key,
            &mut wrong_key
        )
        .is_err());
        // These prefixes are guaranteed by input hashing and the fixed initial
        // protocol exchanges, unlike timing-dependent helper/exit poll counts.
        for refuse_at in [1, 4, 20] {
            let mut guard = Guard::new(&recipients, CryptoOperation::Encrypt, &data);
            guard.refuse_at = refuse_at;
            let result = encrypt_data(&data, &archive_sha, &recipients, &mut guard);
            assert!(
                result.is_err(),
                "untriggered revocation at {refuse_at}; actual checks={}",
                guard.checks
            );
            assert_eq!(
                guard.checks, refuse_at,
                "refusal must actually reach its revocation checkpoint"
            );
            assert_eq!(
                result.err().unwrap().to_string(),
                "software fixture revoked exact crypto authorization"
            );
        }
        // Exercise the SAME finalizer used above, after all helper output has
        // arrived. Its digest-completion and final-delivery checks are semantic
        // boundaries, not counts copied from another process's polling timing.
        let terminal_checks = encrypted.bytes().chunks(CHUNK).len() + 2;
        for refuse_at in [terminal_checks - 1, terminal_checks] {
            let mut guard = Guard::new(&recipients, CryptoOperation::Encrypt, &data);
            let request = guard.expected.clone();
            guard
                .admit(&request, CryptoBudget::fixed(request.operation))
                .unwrap();
            guard.refuse_at = refuse_at;
            let result = finish_encryption(encrypted.bytes().to_vec(), &request, &mut guard);
            assert!(
                result.is_err(),
                "untriggered terminal revocation at {refuse_at}; actual checks={}",
                guard.checks
            );
            assert_eq!(
                guard.checks, refuse_at,
                "terminal refusal must actually trigger"
            );
            assert_eq!(
                result.err().unwrap().to_string(),
                "software fixture revoked exact crypto authorization"
            );
        }
        let mut no_budget = Guard::new(&recipients, CryptoOperation::Encrypt, &data);
        no_budget.refuse_budget = true;
        assert!(encrypt_data(&data, &archive_sha, &recipients, &mut no_budget).is_err());
        let mut tampered = encrypted.bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        let mut guard = Guard::new(&recipients, CryptoOperation::DecryptOwner, &tampered);
        assert!(decrypt_backup_data(
            &tampered,
            &luma_content::sha256(&tampered),
            &recipients,
            CryptoOperation::DecryptOwner,
            &owner.key,
            &mut guard
        )
        .is_err());
        let mut extra = encrypted.bytes().to_vec();
        extra.push(0);
        let mut guard = Guard::new(&recipients, CryptoOperation::DecryptOwner, &extra);
        assert!(decrypt_backup_data(
            &extra,
            &luma_content::sha256(&extra),
            &recipients,
            CryptoOperation::DecryptOwner,
            &owner.key,
            &mut guard
        )
        .is_err());
        let mut wrong_cipher = encrypted.bytes().to_vec();
        let oid = [6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 1, 0x2e];
        let offset = wrong_cipher
            .windows(oid.len())
            .position(|bytes| bytes == oid)
            .unwrap();
        wrong_cipher[offset + oid.len() - 1] = 6;
        let mut guard = Guard::new(&recipients, CryptoOperation::DecryptOwner, &wrong_cipher);
        assert!(decrypt_backup_data(
            &wrong_cipher,
            &luma_content::sha256(&wrong_cipher),
            &recipients,
            CryptoOperation::DecryptOwner,
            &owner.key,
            &mut guard
        )
        .is_err());
        // CMS recipientInfos are not GCM AAD. Corrupting one wrapped key can
        // leave the other key usable: only a genuine external receipt of the
        // exact CMS digest authenticates this part of the backup container.
        let mut damaged_recipient = encrypted.bytes().to_vec();
        let wrapped = first_wrapped_key(&damaged_recipient);
        damaged_recipient[wrapped + 8] ^= 1;
        for (role, key) in [
            (CryptoOperation::DecryptOwner, &owner.key),
            (CryptoOperation::DecryptOfflineAdmin, &admin.key),
        ] {
            let mut guard = Guard::new(&recipients, role, &damaged_recipient);
            guard
                .expected
                .input_sha256
                .clone_from(&commitment.cms_sha256);
            assert!(decrypt_backup_data(
                &damaged_recipient,
                &commitment.cms_sha256,
                &recipients,
                role,
                key,
                &mut guard
            )
            .is_err());
        }
        let changed_sha = luma_content::sha256(&damaged_recipient);
        let mut owner_guard = Guard::new(
            &recipients,
            CryptoOperation::DecryptOwner,
            &damaged_recipient,
        );
        let owner_result = decrypt_backup_data(
            &damaged_recipient,
            &changed_sha,
            &recipients,
            CryptoOperation::DecryptOwner,
            &owner.key,
            &mut owner_guard,
        );
        let mut admin_guard = Guard::new(
            &recipients,
            CryptoOperation::DecryptOfflineAdmin,
            &damaged_recipient,
        );
        let admin_result = decrypt_backup_data(
            &damaged_recipient,
            &changed_sha,
            &recipients,
            CryptoOperation::DecryptOfflineAdmin,
            &admin.key,
            &mut admin_guard,
        );
        assert_ne!(owner_result.is_ok(), admin_result.is_ok());
        let mut substituted = pins.clone();
        substituted.owner.spki_sha256 = "e".repeat(64);
        let substituted =
            Recipients::new(&owner.certificate, &admin.certificate, substituted).unwrap();
        let mut guard = Guard::new(&substituted, CryptoOperation::Encrypt, &data);
        assert!(encrypt_data(&data, &archive_sha, &substituted, &mut guard).is_err());
        let weak = KeyFixture::new(2048);
        let weak_recipients = Recipients::new(
            &owner.certificate,
            &weak.certificate,
            RecipientPins {
                owner: pins.owner,
                offline_admin: weak.pin,
            },
        )
        .unwrap();
        let mut guard = Guard::new(&weak_recipients, CryptoOperation::Encrypt, &data);
        assert!(encrypt_data(&data, &archive_sha, &weak_recipients, &mut guard).is_err());
    }

    #[test]
    fn pins_are_closed_canonical_independent_data_not_authority() {
        let pin = RecipientPin {
            certificate_sha256: "a".repeat(64),
            spki_sha256: "b".repeat(64),
        };
        assert!(RecipientPins {
            owner: pin.clone(),
            offline_admin: pin.clone()
        }
        .validate()
        .is_err());
        let mut other = pin.clone();
        other.certificate_sha256 = "c".repeat(64);
        other.spki_sha256 = "d".repeat(64);
        let pins = RecipientPins {
            owner: pin,
            offline_admin: other,
        };
        assert!(pins.validate().is_ok());
        let mut uppercase = pins.clone();
        uppercase.owner.spki_sha256 = "E".repeat(64);
        assert!(uppercase.validate().is_err());
        let encoded = serde_json::to_string(&pins).unwrap();
        let unknown = encoded.replacen('{', "{\"automatic_trust\":true,", 1);
        assert!(serde_json::from_str::<RecipientPins>(&unknown).is_err());
        let duplicate = encoded.replacen(
            "\"owner\":",
            &format!(
                "\"owner\":{},\"owner\":",
                serde_json::to_string(&pins.owner).unwrap()
            ),
            1,
        );
        assert!(serde_json::from_str::<RecipientPins>(&duplicate).is_err());
        assert!(Recipients::new(b"not a pinned certificate", b"nor this", pins).is_err());
    }

    #[test]
    fn idle_helper_io_keeps_authorization_live_and_cancellable() {
        let (socket, _idle_peer) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let pins = RecipientPins {
            owner: RecipientPin {
                certificate_sha256: "a".repeat(64),
                spki_sha256: "b".repeat(64),
            },
            offline_admin: RecipientPin {
                certificate_sha256: "c".repeat(64),
                spki_sha256: "d".repeat(64),
            },
        };
        let request = CryptoRequest {
            schema_version: 1,
            operation: CryptoOperation::Encrypt,
            input_sha256: "e".repeat(64),
            input_bytes: 1,
            recipients: pins,
        };
        let mut boundary = Guard {
            expected: request.clone(),
            admitted: true,
            checks: 0,
            refuse_at: 3,
            refuse_budget: false,
        };
        let start = Instant::now();
        let mut channel = Channel {
            stream: socket,
            deadline: start + Duration::from_secs(2),
            request: &request,
            boundary: &mut boundary,
        };
        assert!(channel.read(&mut [0_u8; 9]).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(boundary.checks, 3);
    }
}
