// Closed internal C/U engine: profiles are compile-time private constants,
// never caller-selected paths, handles, namespace strings or authorization.
use crate::{
    admin_credentials, bundle,
    sealed_credential::{PrivateBuffer, Secret},
    tpm::{self, Checkpoint},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_CREDENTIAL: u64 = 20 * 1024;
const MAX_CONFIG: u64 = 4096;
const PUBLIC: &str = admin_credentials::PUBLIC_KEY;
const SIGNATURE: &str = admin_credentials::BOOT_SIGNATURE;


struct PersistentDirectory {
    file: File,
    parent: File,
    path: PathBuf,
    identity: (u64, u64, u32, u32, u32),
    parent_identity: (u64, u64, u32, u32, u32),
    mount: u64,
}
impl PersistentDirectory {
    fn open(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    }
    fn mount(file: &File) -> Result<u64> {
        let mut value: libc::statx = unsafe { std::mem::zeroed() };
        let empty = std::ffi::CString::new("")?;
        const MOUNT_ID: u32 = 0x1000;
        if unsafe {
            libc::statx(
                file.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                MOUNT_ID,
                &mut value,
            )
        } != 0
            || value.stx_mask & MOUNT_ID == 0
            || value.stx_mnt_id == 0
        {
            return Err(
                "content authority requires exact kernel mount identity; no fallback".into(),
            );
        }
        Ok(value.stx_mnt_id)
    }
    fn ext4(file: &File) -> Result<()> {
        let mut value: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut value) } != 0 || value.f_type != 0xef53 {
            return Err("persistent content authority requires real local ext4".into());
        }
        Ok(())
    }
    fn installed_mount(file: &File, expected: u64) -> Result<()> {
        Self::ext4(file)?;
        if Self::mount(file)? != expected {
            return Err("persistent content mount identity changed".into());
        }
        let metadata = file.metadata()?;
        let device = unsafe {
            format!(
                "{}:{}",
                libc::major(metadata.dev()),
                libc::minor(metadata.dev())
            )
        };
        let info = File::open("/proc/self/mountinfo")?;
        let mut status: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(info.as_raw_fd(), &mut status) } != 0 || status.f_type != 0x9fa0 {
            return Err(
                "content volume admission requires actual kernel procfs mount evidence".into(),
            );
        }
        let mut text = String::new();
        info.take(262145).read_to_string(&mut text)?;
        if text.is_empty() || text.len() > 262144 || text.lines().count() > 4096 {
            return Err("kernel mount inventory exceeds closed content admission bounds".into());
        }
        let mut found = false;
        let expected_id = expected.to_string();
        for line in text.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.first().copied() != Some(expected_id.as_str()) {
                continue;
            }
            let separator = fields
                .iter()
                .position(|field| *field == "-")
                .ok_or("malformed kernel mount evidence")?;
            if found
                || separator < 6
                || fields.len() != separator + 4
                || fields[2] != device
                || fields[separator + 1] != "ext4"
                || !fields[5].split(',').any(|option| option == "rw")
                || fields[5].split(',').any(|option| option == "ro")
            {
                return Err(
                    "content authority requires the exact installed writable ext4 mount".into(),
                );
            }
            found = true;
        }
        if !found {
            return Err("held content volume is absent from kernel mount evidence".into());
        }
        Ok(())
    }
    fn capture(path: &Path) -> Result<Self> {
        if !path.is_absolute() || fs::canonicalize(path)? != path {
            return Err("persistent content directory must be canonical and absolute".into());
        }
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("unsafe persistent content directory ancestor".into());
            }
        }
        let file = Self::open(path)?;
        let parent = Self::open(path.parent().ok_or("persistent content parent missing")?)?;
        let metadata = file.metadata()?;
        let parent_metadata = parent.metadata()?;
        if metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != 0
            || metadata.dev() != parent_metadata.dev()
        {
            return Err(
                "private content namespace must remain on its installed parent volume".into(),
            );
        }
        Self::ext4(&file)?;
        Self::ext4(&parent)?;
        let mount = Self::mount(&file)?;
        if Self::mount(&parent)? != mount {
            return Err("content authority may not cross a bind or other mount".into());
        }
        let pin = Self {
            file,
            parent,
            path: path.into(),
            identity: checkpoint_identity(&metadata),
            parent_identity: checkpoint_identity(&parent_metadata),
            mount,
        };
        pin.check()?;
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        let current = Self::open(&self.path)?;
        let current_parent = Self::open(
            self.path
                .parent()
                .ok_or("persistent content parent missing")?,
        )?;
        for (held, current, identity) in [
            (&self.file, &current, self.identity),
            (&self.parent, &current_parent, self.parent_identity),
        ] {
            for file in [held, current] {
                let metadata = file.metadata()?;
                if !metadata.is_dir()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                    || checkpoint_identity(&metadata) != identity
                    || Self::mount(file)? != self.mount
                {
                    return Err(
                        "persistent content directory inode, permissions, volume or mount changed"
                            .into(),
                    );
                }
                Self::installed_mount(file, self.mount)?;
            }
        }
        Ok(())
    }
}

struct CheckpointLock {
    file: File,
    parent: File,
    path: PathBuf,
    directory_identity: (u64, u64),
    runtime: Option<(File, PathBuf)>,
    private_parent: bool,
    persistent: Option<PersistentDirectory>,
}
impl CheckpointLock {
    fn fixed() -> Result<Self> {
        let runtime = Path::new(LOCK)
            .parent()
            .and_then(Path::parent)
            .ok_or("fixed content runtime lock hierarchy missing")?;
        let mut lock = Self::fixed_in(runtime)?;
        lock.persistent = Some(PersistentDirectory::capture(Path::new(DIRECTORY))?);
        lock.check()?;
        Ok(lock)
    }
    fn fixed_in(runtime_path: &Path) -> Result<Self> {
        let runtime = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(runtime_path)?;
        let runtime_metadata = runtime.metadata()?;
        let current_runtime = fs::symlink_metadata(runtime_path)?;
        if !runtime_metadata.is_dir()
            || runtime_metadata.uid() != 0
            || runtime_metadata.mode() & 0o7022 != 0
            || !current_runtime.is_dir()
            || (runtime_metadata.dev(), runtime_metadata.ino())
                != (current_runtime.dev(), current_runtime.ino())
        {
            return Err("unsafe independent content runtime root".into());
        }
        let namespace = std::ffi::CString::new(RUNTIME_NAMESPACE)?;
        let created = unsafe { libc::mkdirat(runtime.as_raw_fd(), namespace.as_ptr(), 0o700) } == 0;
        if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory_fd = unsafe {
            libc::openat(
                runtime.as_raw_fd(),
                namespace.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if directory_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory: File = unsafe { std::os::fd::FromRawFd::from_raw_fd(directory_fd) };
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(
                "independent content runtime namespace must be root-owned mode 0700".into(),
            );
        }
        let path = runtime_path.join(RUNTIME_LOCK_NAME);
        let name = std::ffi::CString::new("authority.lock")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file: File = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
        let mut lock = Self::from_file(file, &path)?;
        if lock.directory_identity != (metadata.dev(), metadata.ino()) {
            return Err("independent content runtime namespace changed during opening".into());
        }
        lock.runtime = Some((runtime, runtime_path.into()));
        lock.private_parent = true;
        lock.check()?;
        lock.file.sync_all()?;
        directory.sync_all()?;
        if created {
            lock.runtime
                .as_ref()
                .ok_or("content runtime root pin absent")?
                .0
                .sync_all()?;
        }
        lock.check()?;
        Ok(lock)
    }
    fn from_file(file: File, path: &Path) -> Result<Self> {
        let parent_path = path.parent().ok_or("content lock parent missing")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent_path)?;
        let m = parent.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe content lock parent".into());
        }
        let lock = Self {
            file,
            parent,
            path: path.into(),
            directory_identity: (m.dev(), m.ino()),
            runtime: None,
            private_parent: false,
            persistent: None,
        };
        lock.check()?;
        if unsafe { libc::flock(lock.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another independent content checkpoint writer is active".into());
        }
        lock.check()?;
        Ok(lock)
    }

    fn check(&self) -> Result<()> {
        if let Some(pin) = &self.persistent {
            pin.check()?;
        }
        if let Some((held, path)) = &self.runtime {
            let metadata = held.metadata()?;
            let current = fs::symlink_metadata(path)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o7022 != 0
                || !current.is_dir()
                || current.uid() != 0
                || current.mode() & 0o7022 != 0
                || (metadata.dev(), metadata.ino()) != (current.dev(), current.ino())
            {
                return Err("independent content runtime root identity changed".into());
            }
        }
        let directory = self.parent.metadata()?;
        let current_directory =
            fs::symlink_metadata(self.path.parent().ok_or("content lock parent missing")?)?;
        if !directory.is_dir()
            || directory.uid() != 0
            || directory.mode() & 0o022 != 0
            || !current_directory.is_dir()
            || current_directory.uid() != 0
            || current_directory.mode() & 0o022 != 0
            || (current_directory.dev(), current_directory.ino()) != self.directory_identity
            || (self.private_parent
                && (directory.mode() & 0o7777 != 0o700
                    || current_directory.mode() & 0o7777 != 0o700))
        {
            return Err("content checkpoint exclusion directory changed".into());
        }
        let held = self.file.metadata()?;
        let name = std::ffi::CString::new(
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid content lock member")?,
        )?;
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let current: File = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
        let m = current.metadata()?;
        if !held.is_file()
            || held.uid() != 0
            || held.mode() & 0o7777 != 0o600
            || held.nlink() != 1
            || held.len() != 0
            || !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() != 0
            || (held.dev(), held.ino()) != (m.dev(), m.ino())
        {
            return Err("content checkpoint exclusion inode replaced or unsafe".into());
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}
fn nonzero(value: &str) -> Result<[u8; 32]> {
    let bytes = tpm::decode(value)?;
    if bytes == [0; 32] {
        return Err("content checkpoint requires a nonzero exact digest".into());
    }
    Ok(bytes)
}
struct MemberParent {
    file: File,
    path: PathBuf,
    root: Option<PersistentDirectory>,
    identity: (u64, u64, u32, u32, u32),
    mount: u64,
}
impl MemberParent {
    fn capture(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or("content enrollment parent missing")?;
        let root = if path.starts_with(DIRECTORY) {
            Some(PersistentDirectory::capture(Path::new(DIRECTORY))?)
        } else {
            #[cfg(not(test))]
            {
                return Err(
                    "content enrollment may only access its fixed authority namespace".into(),
                );
            }
            #[cfg(test)]
            {
                path.ancestors()
                    .find(|ancestor| tpm::validate_fixture_directory(ancestor).is_ok())
                    .ok_or("explicit disposable TPM fixture namespace required")?;
                None
            }
        };
        if !parent.is_absolute() || fs::canonicalize(parent)? != parent {
            return Err("content member parent is not canonical".into());
        }
        tpm::private_directory(parent)?;
        let file = PersistentDirectory::open(parent)?;
        let metadata = file.metadata()?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err("content member parent must be private mode0700".into());
        }
        let mount = PersistentDirectory::mount(&file)?;
        if let Some(pin) = &root {
            if metadata.dev() != pin.identity.0 || mount != pin.mount {
                return Err("content enrollment member crossed installed volume or mount".into());
            }
        }
        let pin = Self {
            file,
            path: parent.into(),
            root,
            identity: checkpoint_identity(&metadata),
            mount,
        };
        pin.check()?;
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        if let Some(pin) = &self.root {
            pin.check()?;
        }
        let current = PersistentDirectory::open(&self.path)?;
        for file in [&self.file, &current] {
            let metadata = file.metadata()?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o700
                || checkpoint_identity(&metadata) != self.identity
                || PersistentDirectory::mount(file)? != self.mount
            {
                return Err("content member parent inode, permissions or mount changed".into());
            }
        }
        Ok(())
    }
    fn open(&self, path: &Path, flags: i32, mode: u32) -> Result<File> {
        self.check()?;
        let name = std::ffi::CString::new(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or("content member name missing")?,
        )?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
    }
    fn member(&self, file: &File, bound: u64) -> Result<fs::Metadata> {
        self.check()?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o400
            || metadata.len() > bound
            || metadata.dev() != self.identity.0
            || PersistentDirectory::mount(file)? != self.mount
        {
            return Err("unsafe, oversized or substituted content enrollment member".into());
        }
        Ok(metadata)
    }
}
fn file_identity(
    metadata: &fs::Metadata,
) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
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
    )
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL {
        return Err("content enrollment write exceeds closed bound".into());
    }
    let parent = MemberParent::capture(path)?;
    let mut file = parent.open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o400)?;
    parent.member(&file, 0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.file.sync_all()?;
    let before = parent.member(&file, bytes.len() as u64)?;
    let current = parent.open(path, libc::O_RDONLY, 0)?;
    if file_identity(&before) != file_identity(&parent.member(&current, bytes.len() as u64)?)
        || immutable(path, bytes.len() as u64)? != bytes
    {
        return Err("content enrollment write identity or bytes changed; retain evidence".into());
    }
    parent.check()?;
    Ok(())
}
fn immutable(path: &Path, bound: u64) -> Result<Vec<u8>> {
    if bound > MAX_CREDENTIAL {
        return Err("content enrollment read exceeds closed bound".into());
    }
    let parent = MemberParent::capture(path)?;
    let mut file = parent.open(path, libc::O_RDONLY, 0)?;
    let before = parent.member(&file, bound)?;
    let mut bytes = Vec::new();
    (&mut file).take(bound + 1).read_to_end(&mut bytes)?;
    let after = parent.member(&file, bound)?;
    let current = parent.open(path, libc::O_RDONLY, 0)?;
    if bytes.len() as u64 != before.len()
        || file_identity(&before) != file_identity(&after)
        || file_identity(&before) != file_identity(&parent.member(&current, bound)?)
    {
        return Err("content enrollment member changed during bounded held-file capture".into());
    }
    parent.check()?;
    Ok(bytes)
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("content enrollment destination already exists; preserve it".into()),
        Err(e) => Err(e.into()),
    }
}
fn encode_hex(bytes: &[u8]) -> String {
    bundle::hex(bytes)
}
fn decode_blob(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 8192
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("content sealed TPM blob is not bounded canonical hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema_version: u32,
    profile: String,
    installation: String,
    index: u32,
    parent: u32,
    nv_name: String,
    parent_name: String,
    genesis_event: String,
    enrollment_review: String,
    pcr_public_key_sha256: String,
    pcr7_sha256: String,
    policy11_sha256: String,
    sealed_credential_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParentRecord {
    schema_version: u32,
    installation: String,
    genesis_event: String,
    enrollment_review: String,
    parent_name: String,
    parent: u32,
}
impl ParentRecord {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.parent != PARENT
            || tpm::decode::<34>(&self.parent_name)?[..2] != [0, 0xb]
        {
            return Err("content retained expected parent profile differs".into());
        }
        nonzero(&self.installation)?;
        nonzero(&self.genesis_event)?;
        nonzero(&self.enrollment_review)?;
        Ok(())
    }
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.profile != CHECKPOINT_PROFILE
            || self.index != INDEX
            || self.parent != PARENT
            || tpm::decode::<34>(&self.nv_name)? != checkpoint_name()
            || tpm::decode::<34>(&self.parent_name)?[..2] != [0, 0xb]
        {
            return Err(
                "content checkpoint configuration differs from independent fixed profile".into(),
            );
        }
        for value in [
            &self.installation,
            &self.genesis_event,
            &self.enrollment_review,
            &self.pcr_public_key_sha256,
            &self.sealed_credential_sha256,
        ] {
            nonzero(value)?;
        }
        tpm::decode::<32>(&self.pcr7_sha256)?;
        tpm::decode::<32>(&self.policy11_sha256)?;
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    format: String,
    installation: String,
    parent_name: String,
    public_key_sha256: String,
    public_blob: String,
    private_blob: String,
}
impl Sealed {
    fn unseal(
        &self,
        config: &Configuration,
        device: &mut CheckpointDevice,
        public: &[u8],
        signature: &[u8],
    ) -> Result<Secret> {
        if self.format != MAGIC
            || self.installation != config.installation
            || self.parent_name != config.parent_name
            || self.public_key_sha256 != config.pcr_public_key_sha256
        {
            return Err("content sealed envelope parent/installation/signer mismatch".into());
        }
        let policy = current_policy(device, public, signature)?;
        device.unseal(
            &tpm::decode(&self.parent_name)?,
            public,
            &decode_blob(&self.public_blob)?,
            &decode_blob(&self.private_blob)?,
            &policy.digest,
            &policy.signature,
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureFile {
    sha256: Vec<SignatureEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureEntry {
    pcrs: Vec<u8>,
    pkfp: String,
    pol: String,
    sig: String,
}
struct Policy {
    digest: [u8; 32],
    signature: [u8; 256],
}
fn current_policy(device: &mut CheckpointDevice, public: &[u8], signature: &[u8]) -> Result<Policy> {
    if signature.is_empty() || signature.len() > 16 * 1024 {
        return Err("content signed PCR policy outside bound".into());
    }
    let entries: SignatureFile = serde_json::from_slice(signature)?;
    if entries.sha256.is_empty() || entries.sha256.len() > 32 {
        return Err("content signed PCR policy count outside bound".into());
    }
    let fingerprint = tpm::credential_fingerprint(public)?;
    let current = device.current_policy11()?;
    let mut selected = None;
    for entry in entries.sha256 {
        let pk = tpm::decode::<32>(&entry.pkfp)?;
        let policy = tpm::decode::<32>(&entry.pol)?;
        let sig: [u8; 256] = crate::sealed_credential::decode_blob(entry.sig.as_bytes())?
            .try_into()
            .map_err(|_| "content signed policy requires RSA-2048 signature")?;
        if entry.pcrs == [11] && pk == fingerprint && policy == current {
            if selected.is_some() {
                return Err("ambiguous matching content PCR policy".into());
            }
            selected = Some(Policy {
                digest: policy,
                signature: sig,
            });
        }
    }
    let selected = selected.ok_or("no current content PCR11 policy signed by image verifier")?;
    device.verify_boot(public, &selected.digest, &selected.signature)?;
    Ok(selected)
}
fn canonical<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical content enrollment record".into());
    }
    Ok(value)
}
fn load(
    directory: &Path,
    device: &mut CheckpointDevice,
    public: &[u8],
    signature: &[u8],
) -> Result<(Configuration, Secret, Vec<u8>, Vec<u8>)> {
    let config_bytes = immutable(&directory.join("anchor.json"), MAX_CONFIG)?;
    let blob = immutable(&directory.join("nv-auth.cred"), MAX_CREDENTIAL)?;
    let config: Configuration = canonical(&config_bytes)?;
    config.validate()?;
    validate_genesis_binding(directory.parent().ok_or("checkpoint genesis parent absent")?,&config.installation,nonzero(&config.genesis_event)?)?;
    if digest(public) != config.pcr_public_key_sha256
        || digest(&blob) != config.sealed_credential_sha256
    {
        return Err("content sealed delivery hash differs from exact configuration".into());
    }
    let sealed: Sealed = canonical(&blob)?;
    let secret = sealed.unseal(&config, device, public, signature)?;
    if immutable(&directory.join("anchor.json"), MAX_CONFIG)? != config_bytes
        || immutable(&directory.join("nv-auth.cred"), MAX_CREDENTIAL)? != blob
    {
        return Err("content sealed inputs changed while authenticating TPM".into());
    }
    Ok((config, secret, config_bytes, blob))
}

pub(crate) struct IndependentAnchor {
    device: CheckpointDevice,
    lock: CheckpointLock,
    installation: String,
    genesis: [u8; 32],
    poisoned: bool,
}
impl IndependentAnchor {
    pub(crate) fn installed() -> Result<Self> {
        crate::require_root()?;
        crate::platform::require_installed()?;
        let lock = CheckpointLock::fixed()?;
        let mut device = CheckpointDevice::local()?;
        let public = admin_credentials::public_input(Path::new(PUBLIC), 4096)?;
        let signature = admin_credentials::public_input(Path::new(SIGNATURE), 16 * 1024)?;
        let (config, secret, _, _) = load(
            &Path::new(DIRECTORY).join("sealed"),
            &mut device,
            &public,
            &signature,
        )?;
        if admin_credentials::public_input(Path::new(PUBLIC), 4096)? != public
            || admin_credentials::public_input(Path::new(SIGNATURE), 16 * 1024)? != signature
        {
            return Err(
                "content image signer or current boot signature changed during delivery".into(),
            );
        }
        Self::connect(device, &secret, lock, &config)
    }

    fn connect(
        mut device: CheckpointDevice,
        secret: &Secret,
        lock: CheckpointLock,
        config: &Configuration,
    ) -> Result<Self> {
        config.validate()?;
        device.connect(secret)?;
        Ok(Self {
            device,
            lock,
            installation: config.installation.clone(),
            genesis: nonzero(&config.genesis_event)?,
            poisoned: false,
        })
    }
    pub(crate) fn installation(&self) -> &str {
        &self.installation
    }
    pub(crate) fn genesis_event(&self) -> [u8; 32] {
        self.genesis
    }
    fn live(&self) -> Result<()> {
        if self.poisoned {
            return Err(
                "content TPM write uncertain; preserve prepared cut and reconcile explicitly"
                    .into(),
            );
        }
        self.lock.check()
    }
}
impl Checkpoint for IndependentAnchor {
    fn read(&mut self) -> Result<[u8; 32]> {
        self.live()?;
        let value = self.device.read()?;
        self.lock.check()?;
        Ok(value)
    }
    fn clock(&mut self) -> Result<tpm::Clock> {
        self.live()?;
        let clock = self.device.clock()?;
        self.lock.check()?;
        Ok(clock)
    }
    fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        self.live()?;
        if event == [0; 32] || self.device.read()? != expected {
            return Err(
                "content checkpoint expected head conflict or empty event; no dispatch".into(),
            );
        }
        self.lock.check()?;
        // Fence before the only mutating command. Even a successful command with
        // lost readback cannot be retried through this retained writer object.
        self.poisoned = true;
        self.device.extend(event)?;
        let wanted = tpm::extend_value(expected, event);
        if self.device.read()? != wanted {
            return Err(
                "content NV outcome ambiguous; exact backup reconciliation required".into(),
            );
        }
        self.lock.check()?;
        self.poisoned = false;
        Ok(wanted)
    }
}

pub(crate) struct Provisioner {
    device: CheckpointDevice,
    admission: tpm::Admission,
    public: Vec<u8>,
    signature: Vec<u8>,
    root: PathBuf,
    lock: CheckpointLock,
    public_path: PathBuf,
    signature_path: PathBuf,
}
impl Provisioner {
    pub(crate) fn local() -> Result<Self> {
        let lock = CheckpointLock::fixed()?;
        let device = CheckpointDevice::local()?;
        Self::from_device(
            device,
            Path::new(DIRECTORY),
            lock,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn from_device(
        mut device: CheckpointDevice,
        root: &Path,
        lock: CheckpointLock,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16 * 1024)?;
        tpm::private_directory(root)?;
        absent(&root.join(".parent-intent.json"))?;
        absent(&root.join(".parent-name.json"))?;
        absent(&root.join(".parent-dispatched.json"))?;
        absent(&root.join(".parent-reconciled.json"))?;
        absent(&root.join(".enrollment-prepared"))?;
        absent(&root.join("sealed"))?;
        let admission = device.vacant()?;
        current_policy(&mut device, &public, &signature)?;
        Ok(Self {
            device,
            admission,
            public,
            signature,
            root: root.into(),
            lock,
            public_path: public_path.into(),
            signature_path: signature_path.into(),
        })
    }

    fn delivery_current(&self) -> Result<()> {
        self.lock.check()?;
        if admin_credentials::public_input(&self.public_path, 4096)? != self.public
            || admin_credentials::public_input(&self.signature_path, 16 * 1024)? != self.signature
        {
            return Err("content enrollment image signer or current boot signature changed".into());
        }
        Ok(())
    }
    fn proposal_value(
        &mut self,
        installation: &str,
        genesis: [u8; 32],
    ) -> Result<serde_json::Value> {
        nonzero(installation)?;
        if genesis == [0; 32] {
            return Err(
                "content genesis must bind explicitly reviewed empty namespace bytes".into(),
            );
        }
        self.device.recheck(&self.admission)?;
        self.delivery_current()?;
        let policy = current_policy(&mut self.device, &self.public, &self.signature)?;
        Ok(
            serde_json::json!({"schema_version":1,"kind":ENROLLMENT_KIND,
            "installation":installation,"genesis_event":bundle::hex(&genesis),"index":INDEX,"parent":PARENT,
            "nv_name":bundle::hex(&checkpoint_name()),"pcr_public_key_sha256":digest(&self.public),
            "pcr7_sha256":self.admission.pcr7(),"pcr11_sha256":self.admission.pcr11(),
            "tpm_boot_epoch":self.admission.epoch(),
            "policy11_sha256":bundle::hex(&policy.digest),"public_boot_signature_sha256":digest(&self.signature)}),
        )
    }
    pub(crate) fn proposal(
        &mut self,
        installation: &str,
        genesis: [u8; 32],
    ) -> Result<serde_json::Value> {
        let proposal = self.proposal_value(installation, genesis)?;
        Ok(
            serde_json::json!({"proposal":proposal,"review_sha256":digest(&serde_json::to_vec(&proposal)?),
            "custody":CUSTODY_KIND,"requires_authenticated_admin":true,
            "physical_qualification":false,"timed_authority":false}),
        )
    }
    /// The composition root's callback must authenticate the current Admin and
    /// exact explicit empty namespace genesis under retained drainage before each mutation.
    /// It is an in-process composition boundary, never a JSON authentication bit.
    pub(crate) fn prepare(
        mut self,
        installation: &str,
        genesis: [u8; 32],
        reviewed: &str,
        owner: &PrivateBuffer,
        secret: &Secret,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<PreparedEnrollment> {
        validate_genesis_binding(&self.root,installation,genesis)?;
        let proposal = self.proposal_value(installation, genesis)?;
        let intent = serde_json::to_vec(&proposal)?;
        if digest(&intent) != reviewed {
            return Err("content enrollment exact review changed".into());
        }
        check()?;
        write_new(&self.root.join(".parent-intent.json"), &intent)?;
        self.device.recheck(&self.admission)?;
        self.delivery_current()?;
        check()?;
        if immutable(&self.root.join(".parent-intent.json"), MAX_CONFIG)? != intent {
            return Err("content enrollment parent intent changed; no allocation".into());
        }
        // Prepare only a transient primary and retain its cryptographic Name
        // BEFORE the persistent allocation dispatch. A lost reply can then be
        // reconciled against the exact Name, not mere occupied-handle metadata.
        let parent = self.device.prepare_parent(owner)?;
        let parent_record = serde_json::to_vec(&ParentRecord {
            schema_version: 1,
            installation: installation.into(),
            genesis_event: bundle::hex(&genesis),
            enrollment_review: reviewed.into(),
            parent_name: bundle::hex(&parent),
            parent: PARENT,
        })?;
        write_new(&self.root.join(".parent-name.json"), &parent_record)?;
        self.device.recheck(&self.admission)?;
        self.delivery_current()?;
        check()?;
        write_new(&self.root.join(".parent-dispatched.json"), &parent_record)?;
        self.device.recheck(&self.admission)?;
        check()?;
        if immutable(&self.root.join(".parent-name.json"), MAX_CONFIG)? != parent_record
            || immutable(&self.root.join(".parent-dispatched.json"), MAX_CONFIG)? != parent_record
        {
            return Err("content expected parent Name or dispatch fence changed".into());
        }
        self.device.persist_parent(owner, &parent)?;
        self.device.recheck(&self.admission)?;
        check()?;
        self.prepare_sealed(
            installation,
            genesis,
            reviewed,
            secret,
            parent,
            intent,
            check,
        )
    }
    fn prepare_sealed(
        mut self,
        installation: &str,
        genesis: [u8; 32],
        reviewed: &str,
        secret: &Secret,
        parent: [u8; 34],
        intent: Vec<u8>,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<PreparedEnrollment> {
        self.delivery_current()?;
        self.device.parent_matches(&parent)?;
        self.device.nv_absent()?;
        check()?;
        let (public_blob, private_blob) = self.device.seal(&parent, &self.public, secret)?;
        let sealed = Sealed {
            format: MAGIC.into(),
            installation: installation.into(),
            parent_name: bundle::hex(&parent),
            public_key_sha256: digest(&self.public),
            public_blob: encode_hex(&public_blob),
            private_blob: encode_hex(&private_blob),
        };
        let blob = serde_json::to_vec(&sealed)?;
        if blob.len() as u64 > MAX_CREDENTIAL {
            return Err("content sealed enrollment exceeds bound; preserve intent".into());
        }
        let policy = current_policy(&mut self.device, &self.public, &self.signature)?;
        let config = Configuration {
            schema_version: 1,
            profile: CHECKPOINT_PROFILE.into(),
            installation: installation.into(),
            index: INDEX,
            parent: PARENT,
            nv_name: bundle::hex(&checkpoint_name()),
            parent_name: bundle::hex(&parent),
            genesis_event: bundle::hex(&genesis),
            enrollment_review: reviewed.into(),
            pcr_public_key_sha256: digest(&self.public),
            pcr7_sha256: self.admission.pcr7().into(),
            policy11_sha256: bundle::hex(&policy.digest),
            sealed_credential_sha256: digest(&blob),
        };
        config.validate()?;
        let recovered = sealed.unseal(&config, &mut self.device, &self.public, &self.signature)?;
        if recovered.bytes() != secret.bytes() {
            return Err("content sealed preflight mismatch; preserve parent intent".into());
        }
        drop(recovered);
        let prepared = self.root.join(".enrollment-prepared");
        self.delivery_current()?;
        check()?;
        let root_pin = MemberParent::capture(&self.root.join(".parent-intent.json"))?;
        let name = std::ffi::CString::new(".enrollment-prepared")?;
        if unsafe { libc::mkdirat(root_pin.file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        root_pin.file.sync_all()?;
        root_pin.check()?;
        self.delivery_current()?;
        let config_bytes = serde_json::to_vec(&config)?;
        write_new(&prepared.join("anchor.json"), &config_bytes)?;
        write_new(&prepared.join("nv-auth.cred"), &blob)?;
        check()?;
        Ok(PreparedEnrollment {
            provisioner: self,
            config,
            config_bytes,
            blob,
            intent,
        })
    }
}

pub(crate) struct PreparedEnrollment {
    provisioner: Provisioner,
    config: Configuration,
    config_bytes: Vec<u8>,
    blob: Vec<u8>,
    intent: Vec<u8>,
}
impl PreparedEnrollment {
    fn recheck(&mut self) -> Result<()> {
        self.provisioner
            .device
            .recheck(&self.provisioner.admission)?;
        self.provisioner.delivery_current()?;
        let root = &self.provisioner.root;
        if immutable(&root.join(".parent-intent.json"), MAX_CONFIG)? != self.intent
            || immutable(&root.join(".enrollment-prepared/anchor.json"), MAX_CONFIG)?
                != self.config_bytes
            || immutable(
                &root.join(".enrollment-prepared/nv-auth.cred"),
                MAX_CREDENTIAL,
            )? != self.blob
        {
            return Err("content prepared enrollment changed; retain it".into());
        }
        absent(&root.join("sealed"))?;
        Ok(())
    }
    pub(crate) fn commit(
        mut self,
        owner: &PrivateBuffer,
        secret: &Secret,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<IndependentAnchor> {
        validate_genesis_binding(&self.provisioner.root,&self.config.installation,nonzero(&self.config.genesis_event)?)?;
        self.recheck()?;
        check()?;
        let sealed: Sealed = canonical(&self.blob)?;
        let recovered = sealed.unseal(
            &self.config,
            &mut self.provisioner.device,
            &self.provisioner.public,
            &self.provisioner.signature,
        )?;
        if recovered.bytes() != secret.bytes() {
            return Err("content NV secret does not match retained sealed proposal".into());
        }
        drop(recovered);
        write_new(
            &self
                .provisioner
                .root
                .join(".enrollment-prepared/nv-dispatched.json"),
            &serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"enrollment_review":self.config.enrollment_review,"genesis_event":self.config.genesis_event}))?,
        )?;
        self.recheck()?;
        check()?;
        let genesis = nonzero(&self.config.genesis_event)?;
        self.provisioner.device.provision(owner, secret, genesis)?;
        let mut anchor = IndependentAnchor::connect(
            self.provisioner.device,
            secret,
            self.provisioner.lock,
            &self.config,
        )?;
        if anchor.read()? != tpm::extend_value([0; 32], genesis) {
            return Err(
                "content enrollment NV readback uncertain; preserve prepared enrollment evidence"
                    .into(),
            );
        }
        check()?;
        publish_sealed(&self.provisioner.root, &self.config_bytes, &self.blob)?;
        Ok(anchor)
    }
}
fn publish_sealed(root: &Path, config: &[u8], blob: &[u8]) -> Result<()> {
    let prepared_pin = MemberParent::capture(&root.join(".enrollment-prepared/anchor.json"))?;
    let root_pin = MemberParent::capture(&root.join(".parent-intent.json"))?;
    if immutable(&root.join(".enrollment-prepared/anchor.json"), MAX_CONFIG)? != config
        || immutable(
            &root.join(".enrollment-prepared/nv-auth.cred"),
            MAX_CREDENTIAL,
        )? != blob
    {
        return Err(
            "content enrollment changed after NV write; preserve pending publication".into(),
        );
    }
    absent(&root.join("sealed"))?;
    prepared_pin.check()?;
    root_pin.check()?;
    let parent = &root_pin.file;
    let old = std::ffi::CString::new(".enrollment-prepared")?;
    let new = std::ffi::CString::new("sealed")?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            old.as_ptr(),
            parent.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    root_pin.check()?;
    let published = PersistentDirectory::open(&root.join("sealed"))?;
    if checkpoint_identity(&published.metadata()?) != prepared_pin.identity
        || PersistentDirectory::mount(&published)? != prepared_pin.mount
    {
        return Err(
            "content sealed publication directory identity changed; retain evidence".into(),
        );
    }
    if immutable(&root.join("sealed/anchor.json"), MAX_CONFIG)? != config
        || immutable(&root.join("sealed/nv-auth.cred"), MAX_CREDENTIAL)? != blob
    {
        return Err("content enrollment publication readback uncertain".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentIntent {
    schema_version: u32,
    kind: String,
    installation: String,
    genesis_event: String,
    index: u32,
    parent: u32,
    nv_name: String,
    pcr_public_key_sha256: String,
    pcr7_sha256: String,
    pcr11_sha256: String,
    tpm_boot_epoch: (u32, u32),
    policy11_sha256: String,
    public_boot_signature_sha256: String,
}
struct ParentPending {
    provisioner: Provisioner,
    record: ParentRecord,
    intent: Vec<u8>,
    parent_bytes: Vec<u8>,
    review: String,
}
impl ParentPending {
    fn open_at(
        root: &Path,
        mut device: CheckpointDevice,
        lock: CheckpointLock,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        tpm::private_directory(root)?;
        absent(&root.join("sealed"))?;
        absent(&root.join(".enrollment-prepared"))?;
        absent(&root.join(".parent-reconciled.json"))?;
        let intent = immutable(&root.join(".parent-intent.json"), MAX_CONFIG)?;
        let parent_bytes = immutable(&root.join(".parent-name.json"), MAX_CONFIG)?;
        if immutable(&root.join(".parent-dispatched.json"), MAX_CONFIG)? != parent_bytes {
            return Err("content parent dispatch fence differs from retained expected Name".into());
        }
        let record: ParentRecord = canonical(&parent_bytes)?;
        record.validate()?;
        let typed: EnrollmentIntent = serde_json::from_slice(&intent)?;
        let _: serde_json::Value = canonical(&intent)?;
        if digest(&intent) != record.enrollment_review
            || typed.schema_version != 1
            || typed.kind != ENROLLMENT_KIND
            || typed.installation != record.installation
            || typed.genesis_event != record.genesis_event
            || typed.index != INDEX
            || typed.parent != PARENT
            || tpm::decode::<34>(&typed.nv_name)? != checkpoint_name()
        {
            return Err(
                "content parent origin intent does not bind exact installation/genesis/profile"
                    .into(),
            );
        }
        tpm::decode::<32>(&typed.pcr11_sha256)?;
        tpm::decode::<32>(&typed.policy11_sha256)?;
        nonzero(&typed.public_boot_signature_sha256)?;
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16 * 1024)?;
        let admission = device.observation()?;
        let policy = current_policy(&mut device, &public, &signature)?;
        if digest(&public) != typed.pcr_public_key_sha256 || admission.pcr7() != typed.pcr7_sha256 {
            return Err("content pending parent signer or fixed secure-boot PCR7 changed".into());
        }
        device.parent_matches(&tpm::decode(&record.parent_name)?)?;
        device.nv_absent()?;
        let review = digest(&serde_json::to_vec(
            &serde_json::json!({"kind":PARENT_RECONCILE_PURPOSE,
            "installation":record.installation,"genesis_event":record.genesis_event,"expected_parent_name":record.parent_name,
            "original_review":record.enrollment_review,"parent_evidence_sha256":digest(&parent_bytes),
            "original_tpm_boot_epoch":typed.tpm_boot_epoch,"current_tpm_boot_epoch":admission.epoch(),
            "current_policy11_sha256":bundle::hex(&policy.digest),"current_boot_signature_sha256":digest(&signature)}),
        )?);
        let provisioner = Provisioner {
            device,
            admission,
            public,
            signature,
            root: root.into(),
            lock,
            public_path: public_path.into(),
            signature_path: signature_path.into(),
        };
        Ok(Self {
            provisioner,
            record,
            intent,
            parent_bytes,
            review,
        })
    }
    fn local() -> Result<Self> {
        Self::open_at(
            Path::new(DIRECTORY),
            CheckpointDevice::local()?,
            CheckpointLock::fixed()?,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn report(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":PARENT_RECONCILE_KIND,"review_sha256":self.review,
            "installation":self.record.installation,"genesis_event":self.record.genesis_event,
            "parent_name":self.record.parent_name,"parent_persistence_replay":false,"nv_dispatched":false,
            "authority_receipt":false})
    }
    fn resume(
        mut self,
        installation: &str,
        genesis: [u8; 32],
        reviewed: &str,
        secret: &Secret,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<PreparedEnrollment> {
        if self.review != reviewed
            || self.record.installation != installation
            || nonzero(&self.record.genesis_event)? != genesis
        {
            return Err(
                "content parent continuation exact reviewed empty namespace identity changed"
                    .into(),
            );
        }
        self.provisioner
            .device
            .recheck(&self.provisioner.admission)?;
        self.provisioner.delivery_current()?;
        self.provisioner
            .device
            .parent_matches(&tpm::decode(&self.record.parent_name)?)?;
        self.provisioner.device.nv_absent()?;
        check()?;
        let root = &self.provisioner.root;
        if immutable(&root.join(".parent-intent.json"), MAX_CONFIG)? != self.intent
            || immutable(&root.join(".parent-name.json"), MAX_CONFIG)? != self.parent_bytes
            || immutable(&root.join(".parent-dispatched.json"), MAX_CONFIG)? != self.parent_bytes
        {
            return Err(
                "content parent expected Name or origin changed during revalidation".into(),
            );
        }
        write_new(
            &root.join(".parent-reconciled.json"),
            &serde_json::to_vec(&self.report())?,
        )?;
        self.provisioner.prepare_sealed(
            installation,
            genesis,
            &self.record.enrollment_review,
            secret,
            tpm::decode(&self.record.parent_name)?,
            self.intent,
            check,
        )
    }
}
/// ReadPublic equality proves the exact pre-dispatch Name under the fixed
/// content template; this inspection is not permission to repeat EvictControl.
pub(crate) fn parent_pending_report() -> Result<serde_json::Value> {
    Ok(ParentPending::local()?.report())
}
pub(crate) fn continue_parent(
    installation: &str,
    genesis: [u8; 32],
    reviewed: &str,
    secret: &Secret,
    check: impl FnMut() -> Result<()>,
) -> Result<PreparedEnrollment> {
    ParentPending::local()?.resume(installation, genesis, reviewed, secret, check)
}

struct PendingPublication {
    root: PathBuf,
    anchor: IndependentAnchor,
    config: Configuration,
    config_bytes: Vec<u8>,
    blob: Vec<u8>,
    public: Vec<u8>,
    signature: Vec<u8>,
    review: String,
    public_path: PathBuf,
    signature_path: PathBuf,
}
impl PendingPublication {
    fn open_at(
        root: &Path,
        mut device: CheckpointDevice,
        lock: CheckpointLock,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16 * 1024)?;
        absent(&root.join("sealed"))?;
        let (config, secret, config_bytes, blob) = load(
            &root.join(".enrollment-prepared"),
            &mut device,
            &public,
            &signature,
        )?;
        let parent_intent = immutable(&root.join(".parent-intent.json"), MAX_CONFIG)?;
        if digest(&parent_intent) != config.enrollment_review {
            return Err("content pending parent intent differs from enrollment review".into());
        }
        let marker = immutable(
            &root.join(".enrollment-prepared/nv-dispatched.json"),
            MAX_CONFIG,
        )?;
        let expected = serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "enrollment_review":config.enrollment_review,"genesis_event":config.genesis_event}))?;
        if marker != expected {
            return Err("content pending one-shot NV dispatch fence differs".into());
        }
        let mut anchor = IndependentAnchor::connect(device, &secret, lock, &config)?;
        if anchor.read()? != tpm::extend_value([0; 32], anchor.genesis) {
            return Err(
                "content pending NV is not the exact enrolled genesis; no write retry or reset"
                    .into(),
            );
        }
        let review = digest(&serde_json::to_vec(
            &serde_json::json!({"kind":FINALIZE_PURPOSE,
            "installation":config.installation,"config_sha256":digest(&config_bytes),"sealed_sha256":digest(&blob),
            "parent_intent_sha256":digest(&parent_intent),"nv_dispatch_sha256":digest(&marker),
            "authenticated_genesis_head":bundle::hex(&tpm::extend_value([0;32],anchor.genesis))}),
        )?);
        Ok(Self {
            root: root.into(),
            anchor,
            config,
            config_bytes,
            blob,
            public,
            signature,
            review,
            public_path: public_path.into(),
            signature_path: signature_path.into(),
        })
    }
    fn local() -> Result<Self> {
        let lock = CheckpointLock::fixed()?;
        Self::open_at(
            Path::new(DIRECTORY),
            CheckpointDevice::local()?,
            lock,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn report(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":FINALIZE_KIND, "review_sha256":self.review,
            "installation":self.config.installation,"genesis_event":self.config.genesis_event,
            "checkpoint_index":INDEX,"credential_parent":PARENT,"nv_name":self.config.nv_name,
            "parent_name":self.config.parent_name,"nv_write_retry":false,"role_authority":false})
    }
    fn finalize(
        mut self,
        installation: &str,
        genesis: [u8; 32],
        reviewed: &str,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<IndependentAnchor> {
        if self.review != reviewed
            || self.config.installation != installation
            || self.anchor.genesis != genesis
        {
            return Err(
                "content pending publication exact empty namespace identity or review changed"
                    .into(),
            );
        }
        check()?;
        if self.anchor.read()? != tpm::extend_value([0; 32], genesis) {
            return Err("content pending head changed; preserve all prepared evidence".into());
        }
        if admin_credentials::public_input(&self.public_path, 4096)? != self.public
            || admin_credentials::public_input(&self.signature_path, 16 * 1024)? != self.signature
        {
            return Err("content pending boot delivery changed; preserve evidence".into());
        }
        check()?;
        publish_sealed(&self.root, &self.config_bytes, &self.blob)?;
        Ok(self.anchor)
    }
}
/// Read-only authenticated pending-genesis inspection; this report grants no
/// permission to repeat parent/NV allocation or to change paired authority.
pub(crate) fn pending_report() -> Result<serde_json::Value> {
    Ok(PendingPublication::local()?.report())
}
pub(crate) fn finalize_pending(
    installation: &str,
    genesis: [u8; 32],
    reviewed: &str,
    check: impl FnMut() -> Result<()>,
) -> Result<IndependentAnchor> {
    PendingPublication::local()?.finalize(installation, genesis, reviewed, check)
}


fn checkpoint_identity(metadata: &fs::Metadata) -> (u64,u64,u32,u32,u32) {
    (metadata.dev(),metadata.ino(),metadata.uid(),metadata.gid(),metadata.mode())
}
