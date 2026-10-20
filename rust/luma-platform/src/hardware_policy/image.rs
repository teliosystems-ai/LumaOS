//! Before-PAM image writer-mediation verification and live inode pins. This is
//! read-only deployment evidence, never a portable hardware authorization.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = "/usr/libexec/luma-os/hardware_writer_verify.py";
const MANIFEST: &str = "/usr/share/luma-os/hardware-writer-policy.json";
const MAX_MEMBER: u64 = 1024 * 1024;
const MAX_TOTAL: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema_version: u32,
    profile: String,
    edition: String,
    manifest_sha256: String,
    closure_sha256: String,
    power_profiles_version: String,
    verified: bool,
    observation_not_authority: bool,
    installed_qualified: bool,
}
fn proof(bytes: &[u8]) -> Result<Proof> {
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or("hardware image verifier reply is truncated")?;
    let value: Proof = serde_json::from_slice(body)?;
    if value.schema_version != 1
        || value.profile != "hardware-mediated-writers-v1"
        || !matches!(value.edition.as_str(), "desktop" | "headless")
        || value.power_profiles_version != "0.21-1ubuntu3"
        || !value.verified
        || !value.observation_not_authority
        || value.installed_qualified
        || serde_json::to_vec(&serde_json::to_value(&value)?)? != body
    {
        return Err(
            "hardware image verifier returned a substituted or overclaimed contract".into(),
        );
    }
    digest(&value.manifest_sha256)?;
    digest(&value.closure_sha256)?;
    Ok(value)
}

type Identity = (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);
fn identity(metadata: &fs::Metadata) -> Result<Identity> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_MEMBER
    {
        return Err("hardware image input is not a bounded protected root-owned inode".into());
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}
struct Pin {
    path: PathBuf,
    file: File,
    identity: Identity,
    sha256: String,
}
impl Pin {
    fn open(path: &Path, expected: Option<&str>) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let result = Self {
            path: path.into(),
            identity: identity(&file.metadata()?)?,
            file,
            sha256: String::new(),
        };
        let bytes = result.bytes()?;
        let sha256 = crate::bundle::hex(&Sha256::digest(&bytes));
        if expected.is_some_and(|value| value != sha256) {
            return Err("hardware image input differs from verified exact bytes".into());
        }
        Ok(Self { sha256, ..result })
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; self.identity.2 as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = self.file.read_at(&mut bytes[offset..], offset as u64)?;
            if count == 0 {
                return Err("hardware image pinned input truncated".into());
            }
            offset += count;
        }
        if identity(&self.file.metadata()?)? != self.identity {
            return Err("hardware image input changed during read".into());
        }
        Ok(bytes)
    }
    fn check(&self) -> Result<()> {
        if identity(&fs::symlink_metadata(&self.path)?)? != self.identity
            || crate::bundle::hex(&Sha256::digest(self.bytes()?)) != self.sha256
        {
            return Err(
                "hardware image writer closure changed after before-PAM verification".into(),
            );
        }
        Ok(())
    }
}

pub(crate) struct Image {
    pins: Vec<Pin>,
    pub closure_sha256: String,
    pub manifest_sha256: String,
}

fn nonblocking<T: AsRawFd>(file: &T) -> Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0u8; 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + count > 4096 {
                    return Err("hardware verifier child output exceeded bound".into());
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
struct VerifierChild(Child);
impl Drop for VerifierChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn run_verifier() -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-B", HELPER, "--verify"])
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_AS, 128u64 * 1024 * 1024),
                (libc::RLIMIT_CPU, 2),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = VerifierChild(command.spawn()?);
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or("hardware verifier stdout unavailable")?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or("hardware verifier stderr unavailable")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let out_closed = drain(&mut stdout, &mut output)?;
        let err_closed = drain(&mut stderr, &mut errors)?;
        if let Some(status) = child.0.try_wait()? {
            if out_closed && err_closed {
                if !status.success() || !errors.is_empty() {
                    return Err("fixed read-only image writer verification refused".into());
                }
                return Ok(output);
            }
        }
        if Instant::now() >= deadline {
            return Err("fixed hardware image verifier exceeded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl Image {
    /// Call before opening PAM, a LocalAnchor, or loading sealed credentials.
    /// The only child is fixed read-only source pinned into this native binary;
    /// after this call all checks are in-process over owned protected inodes.
    pub(crate) fn preflight() -> Result<Self> {
        crate::require_root()?;
        crate::platform::require_installed()?;
        let expected = crate::bundle::hex(&Sha256::digest(include_bytes!(
            "../../../../native/image/hardware_policy.py"
        )));
        let helper = Pin::open(Path::new(HELPER), Some(&expected))?;
        let result = proof(&run_verifier()?)?;
        helper.check()?;
        let manifest = Pin::open(Path::new(MANIFEST), Some(&result.manifest_sha256))?;
        let bytes = manifest.bytes()?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)?;
        let mut names = BTreeMap::<String, String>::new();
        for section in [
            "bus_inputs",
            "ordinary_writer_inputs",
            "power_profiles_files",
            "platform_files",
        ] {
            for (name, value) in document[section]
                .as_object()
                .ok_or("verified hardware image closure section absent")?
            {
                let path = Path::new(name);
                if path.is_absolute()
                    || !matches!(path.components().next(),Some(Component::Normal(value)) if value=="usr"||value=="etc")
                    || path
                        .components()
                        .any(|value| !matches!(value, Component::Normal(_)))
                {
                    return Err(
                        "verified hardware image member is not a closed root-image relative path"
                            .into(),
                    );
                }
                let value = value
                    .as_str()
                    .ok_or("hardware image closure digest type invalid")?;
                digest(value)?;
                if names
                    .insert(name.clone(), value.into())
                    .is_some_and(|old| old != value)
                {
                    return Err("hardware image closure contains conflicting member digests".into());
                }
            }
        }
        if names.is_empty() || names.len() > 512 {
            return Err("hardware image closure inventory exceeds bound".into());
        }
        let mut total = 0;
        let mut pins = vec![helper, manifest];
        for (name, expected) in names {
            let pin = Pin::open(&Path::new("/").join(name), Some(&expected))?;
            total += pin.identity.2;
            if total > MAX_TOTAL {
                return Err("hardware image closure total exceeds bound".into());
            }
            pins.push(pin);
        }
        let image = Self {
            pins,
            closure_sha256: result.closure_sha256,
            manifest_sha256: result.manifest_sha256,
        };
        image.check()?;
        Ok(image)
    }
    pub(crate) fn check(&self) -> Result<()> {
        for pin in &self.pins {
            pin.check()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_verification_observation_cannot_claim_physical_qualification_or_authority() {
        let value = serde_json::json!({"schema_version":1,"profile":"hardware-mediated-writers-v1","edition":"headless",
            "manifest_sha256":"12".repeat(32),"closure_sha256":"23".repeat(32),"power_profiles_version":"0.21-1ubuntu3",
            "verified":true,"observation_not_authority":true,"installed_qualified":false});
        let bytes = |value: &serde_json::Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        proof(&bytes(&value)).unwrap();
        for (key, new) in [
            ("schema_version", serde_json::json!(2)),
            ("verified", serde_json::json!(false)),
            ("observation_not_authority", serde_json::json!(false)),
            ("installed_qualified", serde_json::json!(true)),
            ("power_profiles_version", serde_json::json!("latest")),
            ("manifest_sha256", serde_json::json!("00".repeat(32))),
            ("edition", serde_json::json!("current-host")),
        ] {
            let mut changed = value.clone();
            changed[key] = new;
            assert!(proof(&bytes(&changed)).is_err());
        }
        let mut extra = value.clone();
        extra["grant"] = serde_json::json!("portable-receipt");
        assert!(proof(&bytes(&extra)).is_err());
        assert!(proof(serde_json::to_string_pretty(&value).unwrap().as_bytes()).is_err());
    }
}
