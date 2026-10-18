//! Fixed-purpose, locked-memory Windows UTC signatures. The caller supplies
//! the live publisher/enrollment boundary and independently enrolled public-key pin.
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

pub(crate) const DOMAIN: &[u8] = b"luma-windows-hosted-utc-v1";
pub(crate) const MAX_MESSAGE: usize = 4 + DOMAIN.len() + 112;
const PUBLIC_PREFIX: &[u8] = &[0x45, 0x43, 0x53, 0x31, 0x20, 0, 0, 0];
const DEADLINE: Duration = Duration::from_secs(15);

fn helper() -> PathBuf {
    #[cfg(test)]
    {
        Path::new(env!("OUT_DIR")).join("luma-utc-windows-crypto")
    }
    #[cfg(not(test))]
    {
        PathBuf::from("/usr/libexec/luma-os/luma-utc-windows-crypto")
    }
}

pub(crate) fn message(bytes: &[u8]) -> Result<()> {
    if bytes.len() != MAX_MESSAGE
        || bytes[..4] != (DOMAIN.len() as u32).to_be_bytes()
        || &bytes[4..4 + DOMAIN.len()] != DOMAIN
    {
        return Err("UTC proof requires exact binary purpose and bounds".into());
    }
    let body = &bytes[4 + DOMAIN.len()..];
    for field in body[..96].chunks_exact(32) {
        if field.iter().all(|byte| *byte == 0) {
            return Err("UTC proof has an uncommissioned zero identity".into());
        }
    }
    let lower = u64::from_be_bytes(body[96..104].try_into()?);
    let upper = u64::from_be_bytes(body[104..112].try_into()?);
    if lower == 0 || upper < lower || upper > 4_102_444_800_000 || upper - lower > 10_000 {
        return Err("UTC proof interval exceeds fixed uncertainty".into());
    }
    Ok(())
}

pub(crate) fn validate_public(public: &[u8]) -> Result<()> {
    if public.len() != 72 || !public.starts_with(PUBLIC_PREFIX) {
        return Err("UTC signer requires exact ECDSA-P256 CNG ECCPUBLICBLOB".into());
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
            return Err("UTC crypto deadline expired".into());
        }
        (self.check)()
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.current()?;
            let count = bytes.len().min(4096);
            match self.stream.write(&bytes[..count]) {
                Ok(0) => return Err("UTC helper closed input".into()),
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
                Ok(0) => return Err("UTC helper refused operation".into()),
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
            return Err("UTC signing seed must be exactly 32 locked bytes".into());
        }
    }
    let path = helper();
    #[cfg(not(test))]
    {
        if std::fs::canonicalize(&path)? != path {
            return Err("UTC helper path must be canonical".into());
        }
        for parent in path
            .parent()
            .ok_or("UTC helper parent missing")?
            .ancestors()
        {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
                return Err("UTC helper ancestor is not protected".into());
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
        return Err("unsafe fixed UTC helper executable".into());
    }
    #[cfg(not(test))]
    if metadata.uid() != 0 {
        return Err("UTC helper must be root-owned".into());
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
    header[..16].copy_from_slice(b"LUMAUTCP25601!!\n");
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
                return Err("UTC helper refused finalization".into());
            }
            let mut extra = [0u8; 1];
            if channel.stream.read(&mut extra)? != 0 {
                return Err("UTC helper returned extra output".into());
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
    let mut public = vec![0u8; 72];
    run(1, Some(&seed), &[], &[], &[], &mut public, check)?;
    validate_public(&public)?;
    Ok((seed, public))
}
pub(crate) fn public(seed: &PrivateBuffer, check: impl FnMut() -> Result<()>) -> Result<Vec<u8>> {
    let mut public = vec![0u8; 72];
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
        return Err("UTC signature did not verify".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> Vec<u8> {
        let mut bytes = (DOMAIN.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(DOMAIN);
        bytes.extend([1u8; 32]);
        bytes.extend([2u8; 32]);
        bytes.extend([3u8; 32]);
        bytes.extend(1_800_000_000_000u64.to_be_bytes());
        bytes.extend(1_800_000_000_500u64.to_be_bytes());
        bytes
    }
    #[test]
    fn actual_ephemeral_p256_locked_generate_public_sign_verify_and_substitution_refusals() {
        let (scalar, key) = generate(|| Ok(())).unwrap();
        assert_eq!(key.len(), 72);
        assert_eq!(key, public(&scalar, || Ok(())).unwrap());
        let bytes = proof();
        let signature = sign(&scalar, &bytes, || Ok(())).unwrap();
        verify(&key, &bytes, &signature, || Ok(())).unwrap();
        let (_, other) = generate(|| Ok(())).unwrap();
        assert!(verify(&other, &bytes, &signature, || Ok(())).is_err());
        for index in [
            4 + DOMAIN.len(),
            4 + DOMAIN.len() + 32,
            4 + DOMAIN.len() + 64,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(verify(&key, &changed, &signature, || Ok(())).is_err());
        }
        let mut bad = signature;
        bad[0] ^= 1;
        assert!(verify(&key, &bytes, &bad, || Ok(())).is_err());
        let mut bad = key.clone();
        bad[8..].fill(0);
        assert!(verify(&bad, &bytes, &signature, || Ok(())).is_err());
        assert!(generate(|| Err("revoked original Admin".into())).is_err());
        assert!(sign(&scalar, &bytes, || Err("stale protected UTC".into())).is_err());
    }
    #[test]
    fn exact_purpose_keyblob_interval_and_zero_identity_are_closed() {
        let bytes = proof();
        message(&bytes).unwrap();
        for index in [0, 4] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(message(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed[4 + DOMAIN.len()..4 + DOMAIN.len() + 32].fill(0);
        assert!(message(&changed).is_err());
        let mut changed = bytes.clone();
        changed.pop();
        assert!(message(&changed).is_err());
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(message(&changed).is_err());
        let mut changed = bytes.clone();
        changed[MAX_MESSAGE - 8..].copy_from_slice(&1_800_000_010_001u64.to_be_bytes());
        assert!(message(&changed).is_err());
        let mut key = PUBLIC_PREFIX.to_vec();
        key.extend([1u8; 64]);
        validate_public(&key).unwrap();
        key[0] ^= 1;
        assert!(validate_public(&key).is_err());
        assert!(validate_public(&[0; 44]).is_err());
    }
    #[test]
    fn idle_crypto_transport_cancellation_is_observed_before_read_result() {
        let (stream, _other) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let mut checks = 0;
        let mut current = || {
            checks += 1;
            if checks > 2 {
                Err("cancelled".into())
            } else {
                Ok(())
            }
        };
        let mut channel = Channel {
            stream,
            deadline: Instant::now() + Duration::from_secs(1),
            check: &mut current,
        };
        assert!(channel.read(&mut [0u8; 1]).is_err());
        assert!(checks > 2);
    }
}
