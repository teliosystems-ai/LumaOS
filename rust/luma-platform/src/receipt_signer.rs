//! Fixed-purpose, locked-memory backup receipt signatures. The caller supplies
//! the live ceremony/Export boundary and independently enrolled public-key pin.
//! A valid signature alone is not current custody, a grant or restore authority.
use crate::{sealed_credential::PrivateBuffer, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const DOMAIN: &[u8] = b"luma-content-backup-custody-receipt-v1\0";
pub(crate) const MAX_MESSAGE: usize = 65536;
const PUBLIC_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const DEADLINE: Duration = Duration::from_secs(15);

fn helper() -> PathBuf {
    #[cfg(test)]
    {
        Path::new(env!("OUT_DIR")).join("luma-receipt-signer")
    }
    #[cfg(not(test))]
    {
        PathBuf::from("/usr/libexec/luma-os/luma-receipt-signer")
    }
}

fn message(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_MESSAGE || !bytes.starts_with(DOMAIN) {
        return Err("receipt requires its exact bounded purpose domain".into());
    }
    let payload = &bytes[DOMAIN.len()..];
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    if !value.is_object() || serde_json::to_vec(&value)? != payload {
        return Err("receipt must contain an exact canonical JSON object".into());
    }
    Ok(())
}

pub(crate) fn validate_public(public: &[u8]) -> Result<()> {
    if public.len() != 44 || !public.starts_with(PUBLIC_PREFIX) {
        return Err("receipt signer requires exact RFC8410 Ed25519 SPKI".into());
    }
    Ok(())
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Channel<'a, F> {
    stream: UnixStream,
    deadline: Instant,
    check: &'a mut F,
}
impl<F: FnMut() -> Result<()>> Channel<'_, F> {
    fn current(&mut self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err("receipt crypto deadline expired".into());
        }
        (self.check)()
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.current()?;
            let count = bytes.len().min(4096);
            match self.stream.write(&bytes[..count]) {
                Ok(0) => return Err("receipt helper closed input".into()),
                Ok(count) => bytes = &bytes[count..],
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
        self.current()
    }
    fn read(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.current()?;
            match self.stream.read(bytes) {
                Ok(0) => return Err("receipt helper refused operation".into()),
                Ok(count) => bytes = &mut bytes[count..],
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
        self.current()
    }
}

fn run(
    mode: u8,
    seed: Option<&PrivateBuffer>,
    public: &[u8],
    input: &[u8],
    signature: &[u8],
    output: &mut [u8],
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if let Some(seed) = seed {
        if seed.bytes().len() != 32 {
            return Err("receipt signing seed must be exactly 32 locked bytes".into());
        }
    }
    let path = helper();
    #[cfg(not(test))]
    {
        if std::fs::canonicalize(&path)? != path {
            return Err("receipt helper path must be canonical".into());
        }
        for parent in path
            .parent()
            .ok_or("receipt helper parent missing")?
            .ancestors()
        {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
                return Err("receipt helper ancestor is not protected".into());
            }
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("unsafe fixed receipt helper executable".into());
    }
    #[cfg(not(test))]
    if metadata.uid() != 0 {
        return Err("receipt helper must be root-owned".into());
    }
    let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 32) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let executable = unsafe { File::from_raw_fd(descriptor) };
    let inherited = if let Some(seed) = seed {
        let descriptor = seed.descriptor()?;
        let duplicate = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Some(unsafe { File::from_raw_fd(duplicate) })
    } else {
        None
    };
    let key_fd = inherited.as_ref().map(AsRawFd::as_raw_fd);
    let (socket, child_socket) = UnixStream::pair()?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if let Some(fd) = key_fd {
                if libc::dup2(fd, 3) != 3 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::close(3) != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    check()?;
    let mut child = Running(command.spawn()?);
    drop(command);
    let mut channel = Channel {
        stream: socket,
        deadline: Instant::now() + DEADLINE,
        check: &mut check,
    };
    let mut header = [0u8; 32];
    header[..16].copy_from_slice(b"LUMARECEIPT01!!\n");
    header[16] = mode;
    header[24..28].copy_from_slice(&(input.len() as u32).to_be_bytes());
    header[28..].copy_from_slice(&(public.len() as u32).to_be_bytes());
    channel.write(&header)?;
    channel.write(input)?;
    channel.write(public)?;
    channel.write(signature)?;
    channel.stream.shutdown(std::net::Shutdown::Write)?;
    channel.read(output)?;
    loop {
        channel.current()?;
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("receipt helper refused finalization".into());
            }
            let mut extra = [0u8; 1];
            if channel.stream.read(&mut extra)? != 0 {
                return Err("receipt helper returned extra output".into());
            }
            channel.current()?;
            return Ok(());
        }
        let mut descriptor = libc::pollfd {
            fd: channel.stream.as_raw_fd(),
            events: libc::POLLHUP,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, 25) } < 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

pub(crate) fn generate(check: impl FnMut() -> Result<()>) -> Result<(PrivateBuffer, Vec<u8>)> {
    let seed = PrivateBuffer::new(32)?;
    let mut public = vec![0u8; 44];
    run(1, Some(&seed), &[], &[], &[], &mut public, check)?;
    validate_public(&public)?;
    Ok((seed, public))
}
pub(crate) fn public(seed: &PrivateBuffer, check: impl FnMut() -> Result<()>) -> Result<Vec<u8>> {
    let mut public = vec![0u8; 44];
    run(2, Some(seed), &[], &[], &[], &mut public, check)?;
    validate_public(&public)?;
    Ok(public)
}
pub(crate) fn sign(
    seed: &PrivateBuffer,
    input: &[u8],
    check: impl FnMut() -> Result<()>,
) -> Result<[u8; 64]> {
    message(input)?;
    let mut signature = [0u8; 64];
    run(3, Some(seed), &[], input, &[], &mut signature, check)?;
    Ok(signature)
}
pub(crate) fn verify(
    public: &[u8],
    input: &[u8],
    signature: &[u8; 64],
    check: impl FnMut() -> Result<()>,
) -> Result<()> {
    validate_public(public)?;
    message(input)?;
    let mut verified = [0u8; 1];
    run(4, None, public, input, signature, &mut verified, check)?;
    if verified != [1] {
        return Err("receipt signature did not verify".into());
    }
    Ok(())
}

pub(crate) fn validate_recipients(
    owner_der: &[u8],
    admin_der: &[u8],
    pins: &crate::backup_crypto::RecipientPins,
    check: impl FnMut() -> Result<()>,
) -> Result<()> {
    pins.validate()?;
    if owner_der.is_empty()
        || owner_der.len() > 8192
        || admin_der.is_empty()
        || admin_der.len() > 8192
    {
        return Err("governed recipient certificates exceed fixed DER bounds".into());
    }
    let mut input = Vec::with_capacity(136 + owner_der.len() + admin_der.len());
    input.extend_from_slice(&(owner_der.len() as u32).to_be_bytes());
    input.extend_from_slice(&(admin_der.len() as u32).to_be_bytes());
    for pin in [&pins.owner, &pins.offline_admin] {
        input.extend_from_slice(&crate::tpm::decode::<32>(&pin.certificate_sha256)?);
        input.extend_from_slice(&crate::tpm::decode::<32>(&pin.spki_sha256)?);
    }
    input.extend_from_slice(owner_der);
    input.extend_from_slice(admin_der);
    let mut verified = [0u8; 1];
    run(5, None, &[], &input, &[], &mut verified, check)?;
    if verified != [1] {
        return Err("governed recipient key profile did not verify".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt() -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(br#"{"cms_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":1}"#);
        bytes
    }
    #[test]
    fn actual_locked_signer_roundtrip_and_cross_key_message_signature_refusals() {
        let (seed, key) = generate(|| Ok(())).unwrap();
        assert_eq!(key, public(&seed, || Ok(())).unwrap());
        let input = receipt();
        let signature = sign(&seed, &input, || Ok(())).unwrap();
        verify(&key, &input, &signature, || Ok(())).unwrap();
        let (_, other) = generate(|| Ok(())).unwrap();
        assert!(verify(&other, &input, &signature, || Ok(())).is_err());
        let mut changed = input.clone();
        changed[DOMAIN.len() + 15] = b'b';
        assert!(verify(&key, &changed, &signature, || Ok(())).is_err());
        let mut bad = signature;
        bad[0] ^= 1;
        assert!(verify(&key, &input, &bad, || Ok(())).is_err());
        assert!(generate(|| Err("revoked ceremony".into())).is_err());
        assert!(sign(&seed, &input, || Err("revoked Export".into())).is_err());
    }
    #[test]
    fn fixed_domain_canonical_object_and_spki_are_not_negotiable() {
        message(&receipt()).unwrap();
        for payload in [
            b"{} ".as_slice(),
            b"[]",
            b"{\"a\":1,\"a\":1}",
            b"{\"b\":1,\"a\":1}",
        ] {
            let mut input = DOMAIN.to_vec();
            input.extend(payload);
            assert!(message(&input).is_err());
        }
        assert!(message(b"unrelated-message").is_err());
        assert!(message(&vec![b'x'; MAX_MESSAGE + 1]).is_err());
        let mut fake = PUBLIC_PREFIX.to_vec();
        fake.extend([0u8; 32]);
        validate_public(&fake).unwrap();
        fake.push(0);
        assert!(validate_public(&fake).is_err());
        fake.pop();
        fake[0] ^= 1;
        assert!(validate_public(&fake).is_err());
    }
    #[test]
    fn idle_crypto_transport_keeps_live_cancellation_checks() {
        let (stream, _held) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut checks = 0;
        let mut boundary = || {
            checks += 1;
            if checks >= 3 {
                Err("revoked during helper wait".into())
            } else {
                Ok(())
            }
        };
        let mut channel = Channel {
            stream,
            deadline: Instant::now() + DEADLINE,
            check: &mut boundary,
        };
        assert!(channel.read(&mut [0u8; 1]).is_err());
        drop(channel);
        assert_eq!(checks, 3);
    }
}
