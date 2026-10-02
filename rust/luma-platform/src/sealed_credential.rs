//! TPM-only credential sealing with fixed PCR7 and signed PCR11 policy.
//! This primitive is not enrollment, Admin authorization, or signer admission.
//! The future trusted composition root must supply its governed public key,
//! deployment identity and approved boot-policy signatures.
#![cfg_attr(not(test), allow(dead_code))] // Enrollment/service integration remains pending.
use crate::{tpm, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_BLOB: usize = 16 * 1024;
const MAX_PUBLIC_KEY: usize = 4096;
const HELPER: &str = "/usr/bin/systemd-creds";

/// Anonymous, locked, nondumpable memfd mapping. No Debug/Serialize/Clone.
/// The parent keeps pages locked while the helper accesses the same memfd.
pub(crate) struct PrivateBuffer {
    file: File,
    pointer: *mut u8,
    capacity: usize,
}
impl PrivateBuffer {
    pub(crate) fn descriptor(&self) -> Result<File> {
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    pub(crate) fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_BLOB {
            return Err("credential buffer outside bound".into());
        }
        let name = b"luma-private-credential\0";
        let fd = unsafe { libc::memfd_create(name.as_ptr().cast(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(capacity as u64)?;
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = Self {
            file,
            pointer: pointer.cast(),
            capacity,
        };
        if unsafe { libc::mlock(pointer, capacity) } != 0
            || unsafe { libc::madvise(pointer, capacity, libc::MADV_DONTDUMP) } != 0
        {
            return Err("cannot lock/protect credential memory; no pageable fallback".into());
        }
        Ok(result)
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut result = Self::new(bytes.len())?;
        result.bytes_mut().copy_from_slice(bytes);
        Ok(result)
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer, self.capacity) }
    }
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer, self.capacity) }
    }
}
impl Drop for PrivateBuffer {
    fn drop(&mut self) {
        for i in 0..self.capacity {
            unsafe {
                std::ptr::write_volatile(self.pointer.add(i), 0);
            }
        }
        unsafe {
            libc::munlock(self.pointer.cast(), self.capacity);
            libc::munmap(self.pointer.cast(), self.capacity);
        }
    }
}

pub struct Secret(PrivateBuffer);
impl Secret {
    pub(crate) fn from_buffer(buffer: PrivateBuffer) -> Self {
        assert_eq!(buffer.bytes().len(), 32);
        Self(buffer)
    }
    pub fn generate() -> Result<Self> {
        crate::require_root()?;
        let mut buffer = PrivateBuffer::new(32)?;
        File::open("/dev/urandom")?.read_exact(buffer.bytes_mut())?;
        Ok(Self(buffer))
    }
    pub fn bytes(&self) -> &[u8; 32] {
        self.0
            .bytes()
            .try_into()
            .expect("fixed private credential width")
    }
}

enum Transport {
    Local,
    #[cfg(test)]
    Emulator(String),
}
impl Transport {
    fn argument(&self) -> Result<String> {
        match self {
            Self::Local => {
                tpm::probe()?; // root-owned local character device; no env/default TCTI.
                Ok("--tpm2-device=device:/dev/tpmrm0".into())
            }
            #[cfg(test)]
            Self::Emulator(value) => Ok(format!("--tpm2-device={value}")),
        }
    }
}

struct Helper(Child);
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// No shell, inherited environment, plaintext argv, stderr or stdout logging.
/// Output goes directly into locked memory; file size and elapsed time bounded.
fn execute(
    input: &PrivateBuffer,
    auxiliary: &PrivateBuffer,
    args: &[String],
    capacity: usize,
) -> Result<PrivateBuffer> {
    let mut output = PrivateBuffer::new(capacity)?;
    let inherited = auxiliary.file.as_raw_fd();
    let mut input_file = input.file.try_clone()?;
    input_file.seek(SeekFrom::Start(0))?;
    let mut command = Command::new(HELPER);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C")
        .env("SYSTEMD_LOG_LEVEL", "err")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env("TSS2_LOG", "all+NONE")
        .stdin(Stdio::from(input_file))
        .stdout(Stdio::from(output.file.try_clone()?))
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            // Only async-signal-safe syscalls after fork. Modify the child's
            // descriptor flags, never the parent's process-wide inheritance.
            let flags = libc::fcntl(inherited, libc::F_GETFD);
            let limit = libc::rlimit {
                rlim_cur: capacity as _,
                rlim_max: capacity as _,
            };
            if flags < 0
                || libc::fcntl(inherited, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                || libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Helper(command.spawn()?);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("TPM credential helper refused; no fallback".into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("TPM credential helper timed out; no fallback".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let written = output.file.stream_position()? as usize;
    if written == 0 || written > capacity {
        return Err("invalid credential helper output size".into());
    }
    // Return exact written bytes, not the preallocated zero padding.
    // Both mappings remain locked until after the copy and wipe.
    PrivateBuffer::from_bytes(&output.bytes()[..written])
}

fn name(deployment: &str) -> Result<String> {
    tpm::decode::<32>(deployment)?;
    Ok(format!("--name=luma-admin-nv-auth-{deployment}"))
}

// Bounded ciphertext decoding only; no plaintext is held in these Vecs.
pub(crate) fn decode_blob(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() > MAX_BLOB {
        return Err("credential outside bound".into());
    }
    let compact: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    if compact.is_empty() || compact.len() % 4 != 0 {
        return Err("invalid credential encoding".into());
    }
    let mut result = Vec::new();
    for (i, chunk) in compact.chunks_exact(4).enumerate() {
        let mut value = [0u8; 4];
        let padding = if chunk[2] == b'=' {
            2
        } else {
            usize::from(chunk[3] == b'=')
        };
        for j in 0..4 {
            value[j] = match chunk[j] {
                b'A'..=b'Z' => chunk[j] - b'A',
                b'a'..=b'z' => chunk[j] - b'a' + 26,
                b'0'..=b'9' => chunk[j] - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if j >= 4 - padding && i == compact.len() / 4 - 1 => 0,
                _ => return Err("invalid credential encoding".into()),
            };
        }
        if (padding == 2 && (chunk[3] != b'=' || value[1] & 15 != 0))
            || (padding == 1 && value[2] & 3 != 0)
        {
            return Err("noncanonical credential encoding".into());
        }
        result.push(value[0] << 2 | value[1] >> 4);
        if padding < 2 {
            result.push(value[1] << 4 | value[2] >> 2);
        }
        if padding == 0 {
            result.push(value[2] << 6 | value[3]);
        }
    }
    Ok(result)
}

/// Reject weaker modes before invoking the decryptor. The pinned systemd 255
/// format authenticates these headers as AAD; this filter is not cryptography.
/// The expected key must come from independently authenticated enrollment,
/// never from the blob being checked. Exact PEM bytes are intentionally pinned.
fn validate_profile(encoded: &[u8], expected_key: &[u8]) -> Result<()> {
    let data = decode_blob(encoded)?;
    validate_header(&data, expected_key)
}

fn validate_header(data: &[u8], expected_key: &[u8]) -> Result<()> {
    let field = |offset: usize, size: usize| -> Result<&[u8]> {
        data.get(offset..offset.checked_add(size).ok_or("credential overflow")?)
            .ok_or_else(|| "truncated credential header".into())
    };
    let u32_at = |offset| -> Result<usize> {
        Ok(u32::from_le_bytes(field(offset, 4)?.try_into()?) as usize)
    };
    let align = |size: usize| (size + 7) & !7;
    if expected_key.is_empty()
        || expected_key.len() > MAX_PUBLIC_KEY
        || field(0, 16)? != tpm::decode::<16>("faf7eb9341e3412ca1a436f95a29362f")?
        || u32_at(16)? != 32
        || u32_at(20)? != 1
        || u32_at(24)? != 12
        || u32_at(28)? != 16
    {
        return Err("credential is not the approved TPM-only signed-PCR profile".into());
    }
    let t = 48;
    let blob_size = u32_at(t + 12)?;
    if field(t, 8)? != (1u64 << 7).to_le_bytes()
        || field(t + 8, 2)? != 0x000bu16.to_le_bytes()
        || ![1u16.to_le_bytes(), 0x23u16.to_le_bytes()]
            .iter()
            .any(|a| Some(a.as_slice()) == data.get(t + 10..t + 12))
        || blob_size == 0
        || blob_size > MAX_BLOB
        || u32_at(t + 16)? != 32
    {
        return Err("credential has an unapproved TPM policy".into());
    }
    let p = t + align(20 + blob_size + 32);
    if field(p, 8)? != (1u64 << 11).to_le_bytes()
        || u32_at(p + 8)? != expected_key.len()
        || field(p + 12, expected_key.len())? != expected_key
    {
        return Err("credential PCR signer differs from enrolled public key".into());
    }
    // At least metadata header plus tag; complete parsing/authentication is
    // delegated to the packaged helper, not implemented a second time here.
    field(p + align(12 + expected_key.len()), 24 + 16)?;
    Ok(())
}

fn seal_with(
    transport: Transport,
    deployment: &str,
    public_key: &[u8],
    secret: &Secret,
) -> Result<Vec<u8>> {
    crate::require_root()?;
    if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY {
        return Err("PCR public key outside bound".into());
    }
    let key = PrivateBuffer::from_bytes(public_key)?;
    let args = vec![
        transport.argument()?,
        name(deployment)?,
        // "tpm2" alone ignores the supplied PCR signing key in systemd 255.
        // Pin the explicit signed-key mode and verify its output header too.
        "--with-key=tpm2-with-public-key".into(),
        "--tpm2-pcrs=7".into(),
        "--tpm2-public-key-pcrs=11".into(),
        format!("--tpm2-public-key=/proc/self/fd/{}", key.file.as_raw_fd()),
        "encrypt".into(),
        "-".into(),
        "-".into(),
    ];
    let blob = execute(&secret.0, &key, &args, MAX_BLOB)?;
    validate_profile(blob.bytes(), public_key)?;
    Ok(blob.bytes().to_vec()) // Ciphertext only; no plaintext Vec/serialization.
}

fn unseal_with(
    transport: Transport,
    deployment: &str,
    expected_public_key: &[u8],
    blob: &[u8],
    signature: &[u8],
) -> Result<Secret> {
    crate::require_root()?;
    validate_profile(blob, expected_public_key)?;
    let input = PrivateBuffer::from_bytes(blob)?;
    let signature = PrivateBuffer::from_bytes(signature)?;
    let args = vec![
        transport.argument()?,
        name(deployment)?,
        "--newline=no".into(),
        format!(
            "--tpm2-signature=/proc/self/fd/{}",
            signature.file.as_raw_fd()
        ),
        "decrypt".into(),
        "-".into(),
        "-".into(),
    ];
    let output = execute(&input, &signature, &args, 32)?;
    if output.capacity != 32 {
        return Err("unsealed credential has wrong width".into());
    }
    Ok(Secret(output))
}

pub fn seal(deployment: &str, public_key: &[u8], secret: &Secret) -> Result<Vec<u8>> {
    seal_with(Transport::Local, deployment, public_key, secret)
}
pub fn unseal(
    deployment: &str,
    expected_public_key: &[u8],
    blob: &[u8],
    signature: &[u8],
) -> Result<Secret> {
    unseal_with(
        Transport::Local,
        deployment,
        expected_public_key,
        blob,
        signature,
    )
}

#[cfg(test)]
fn fixture_transport(directory: &std::path::Path) -> Transport {
    assert!(std::path::Path::new("/.dockerenv").is_file());
    assert!(!std::path::Path::new("/dev/tpm0").exists());
    assert!(!std::path::Path::new("/dev/tpmrm0").exists());
    assert_eq!(directory.parent(), Some(std::path::Path::new("/tmp")));
    assert!(directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("luma-tpm-"));
    Transport::Emulator(format!("swtpm:path={}/tpm.sock", directory.display()))
}

#[cfg(test)]
pub(crate) fn fixture_seal(
    directory: &std::path::Path,
    deployment: &str,
    public: &[u8],
    secret: &Secret,
) -> Result<Vec<u8>> {
    seal_with(fixture_transport(directory), deployment, public, secret)
}

#[cfg(test)]
pub(crate) fn fixture_unseal(
    directory: &std::path::Path,
    deployment: &str,
    public: &[u8],
    blob: &[u8],
    signature: &[u8],
) -> Result<Secret> {
    unseal_with(
        fixture_transport(directory),
        deployment,
        public,
        blob,
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_encoding_and_closed_profile() {
        for (encoded, decoded) in [("Zg==", "f"), ("Zm8=", "fo"), ("Zm9v\r\n", "foo")] {
            assert_eq!(decode_blob(encoded.as_bytes()).unwrap(), decoded.as_bytes());
        }
        for invalid in ["", "A", "====", "Zg=A", "Zh==", "Zm9=", "Zg==AAAA", " Zg=="] {
            assert!(decode_blob(invalid.as_bytes()).is_err(), "{invalid}");
        }
        let key = b"test-public-key";
        let mut header = vec![0; 200];
        header[..16]
            .copy_from_slice(&tpm::decode::<16>("faf7eb9341e3412ca1a436f95a29362f").unwrap());
        for (offset, value) in [
            (16, 32u32),
            (20, 1),
            (24, 12),
            (28, 16),
            (60, 8),
            (64, 32),
            (120, key.len() as u32),
        ] {
            header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        header[48..56].copy_from_slice(&(1u64 << 7).to_le_bytes());
        header[56..58].copy_from_slice(&0x000bu16.to_le_bytes());
        header[58..60].copy_from_slice(&0x23u16.to_le_bytes());
        header[112..120].copy_from_slice(&(1u64 << 11).to_le_bytes());
        header[124..124 + key.len()].copy_from_slice(key);
        validate_header(&header, key).unwrap();
        assert!(validate_header(&header, b"different-key").is_err());
        for size in 0..184 {
            assert!(validate_header(&header[..size], key).is_err());
        }
        for offset in [0, 16, 20, 24, 28, 48, 56, 58, 64, 112, 120, 124] {
            let mut changed = header.clone();
            changed[offset] ^= 0x80;
            assert!(validate_header(&changed, key).is_err(), "offset {offset}");
        }
        for mode in [
            "5a1c6a86df9d4096b1d5a65e0862f19a",
            "0c7cc07b117645919c4b0bea08bc20fe",
            "af4950a849134eb1a73846304ff30c05",
            "058469daf6f54324800549da0f8ea2fb",
        ] {
            let mut changed = header.clone();
            changed[..16].copy_from_slice(&tpm::decode::<16>(mode).unwrap());
            assert!(validate_header(&changed, key).is_err());
        }
    }
    #[test]
    fn strict_domain_and_memory_bounds() {
        assert!(name(&"A".repeat(64)).is_err());
        assert!(name("../admin").is_err());
        assert!(PrivateBuffer::new(0).is_err());
        assert!(PrivateBuffer::new(MAX_BLOB + 1).is_err());
        let buffer = PrivateBuffer::from_bytes(b"test").unwrap();
        assert!(buffer.bytes() == b"test");
        assert!(
            unsafe { libc::fcntl(buffer.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0
        );
    }

    #[test]
    #[ignore = "requires private signed-PCR software-TPM fixture"]
    fn emulator_signed_credential() {
        let dir = std::path::PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        assert!(
            dir.starts_with("/tmp")
                && dir
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("luma-tpm-")
        );
        let device = format!("swtpm:path={}/tpm.sock", dir.display());
        let deployment = "ab".repeat(32);
        let generated = Secret::generate().unwrap();
        assert!(generated.bytes().len() == 32);
        let secret = Secret(
            PrivateBuffer::from_bytes(&tpm::private_read(&dir.join("auth"), 32).unwrap()).unwrap(),
        );
        let signature = std::fs::read(dir.join("pcr-signature.json")).unwrap();
        let public = std::fs::read(dir.join("pcr-public.pem")).unwrap();
        let blob_path = dir.join("credential.cred");
        match std::env::var("LUMA_TPM_TEST_SEAL").unwrap().as_str() {
            "seal" => {
                let blob = seal_with(
                    Transport::Emulator(device.clone()),
                    &deployment,
                    &public,
                    &secret,
                )
                .unwrap();
                // Product entrypoints cannot use the fixture transport or a
                // default/environment-selected TPM in this no-device container.
                assert!(seal(&deployment, &public, &secret).is_err());
                assert!(unseal(&deployment, &public, &blob, &signature).is_err());
                crate::platform::write_atomic(&blob_path, &blob, 0o600).unwrap();
                let opened = unseal_with(
                    Transport::Emulator(device.clone()),
                    &deployment,
                    &public,
                    &blob,
                    &signature,
                )
                .unwrap();
                assert!(opened.bytes() == secret.bytes());
                assert!(unseal_with(
                    Transport::Emulator(device.clone()),
                    &deployment,
                    b"untrusted replacement signer",
                    &blob,
                    &signature
                )
                .is_err());
                assert!(unseal_with(
                    Transport::Emulator(device.clone()),
                    &"cd".repeat(32),
                    &public,
                    &blob,
                    &signature
                )
                .is_err());
                let mut corrupt = blob.clone();
                let tail = corrupt.len() - 48;
                corrupt[tail] = if corrupt[tail] == b'A' { b'B' } else { b'A' };
                // Header/key admission still succeeds: this must be refused
                // by authenticated decryption, not only the format filter.
                validate_profile(&corrupt, &public).unwrap();
                assert!(unseal_with(
                    Transport::Emulator(device.clone()),
                    &deployment,
                    &public,
                    &corrupt,
                    &signature
                )
                .is_err());
                assert!(unseal_with(
                    Transport::Emulator(device),
                    &deployment,
                    &public,
                    &blob,
                    b"{}"
                )
                .is_err());
            }
            mode => {
                let blob = std::fs::read(blob_path).unwrap();
                let result = unseal_with(
                    Transport::Emulator(device),
                    &deployment,
                    &public,
                    &blob,
                    &signature,
                );
                match mode {
                    "allow" => assert!(result.unwrap().bytes() == secret.bytes()),
                    "deny" => assert!(result.is_err()),
                    _ => panic!("unknown fixture mode"),
                }
            }
        }
    }
}
