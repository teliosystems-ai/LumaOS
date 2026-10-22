//! Fixed builder observation from the already authenticated immutable image.
//! A supplied tuple or historical observation is never accepted in its place.
use super::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const SOURCE_LOCK: &str = "/usr/share/luma-os/source-lock.json";
const EXECUTABLE: &str = "/usr/libexec/luma-os/luma-platform";
const INDEX_POLICY: &str = "/usr/share/luma-os/content-index-policy.json";
const MAX_SOURCE_LOCK: usize = 2 * 1024 * 1024;
const MAX_EXECUTABLE: u64 = 128 * 1024 * 1024;
const REQUIRED:&[&str]=&[
    "rust/Cargo.lock",
    "rust/luma-content/src/lib.rs",
    "rust/luma-content-store/src/corpus_index.rs",
    "rust/luma-content-store/src/corpus_index/build.rs",
    "rust/luma-content-store/src/corpus_index/math.rs",
    "rust/luma-content-store/src/corpus_index/job.rs",
    "rust/luma-content-store/src/corpus_index/job/statistics.rs",
    "rust/luma-content-store/src/corpus_index/job/covariance.rs",
    "rust/luma-content-store/src/corpus_index/job/covariance/projection.rs",
    "rust/luma-content-store/src/corpus_index/job/covariance/projection/vectors.rs",
    "rust/luma-content-store/src/corpus_index/job/covariance/projection/vectors/generation.rs",
    "rust/luma-content-store/src/corpus_index/job/covariance/projection/vectors/generation/audit.rs",
    "rust/luma-platform/src/content_index.rs",
    "rust/luma-platform/src/content_index/builder.rs",
    "rust/luma-platform/src/content_index/policy.rs",
    "rust/luma-platform/src/content_index/runtime.rs",
    "native/image/overlay/usr/share/luma-os/content-index-policy.json",
    "rust/luma-platform/src/content_index/client.rs",
    "rust/luma-platform/src/content_index/request.rs",
    "rust/luma-platform/src/content_index/scope.rs",
    "rust/luma-platform/src/content_index/state.rs",
    "rust/luma-platform/src/content_index/phase.rs",
    "rust/luma-platform/src/content_index/observed.rs",
    "rust/luma-platform/src/content_index/observed/metadata.rs",
    "rust/luma-platform/src/content_index/transport.rs",
    "rust/luma-platform/src/content_custody/indexed.rs",
    "rust/luma-platform/src/content_custody/indexed/boundary.rs",
    "rust/luma-platform/src/content_custody/indexed/compute.rs",
    "rust/luma-content-store/src/v2/objects/blob_plan.rs",
    "rust/luma-content-store/src/v2/objects/index_writer.rs",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceLock {
    schema_version: u32,
    files: Vec<SourceFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFile {
    path: String,
    bytes: u64,
    sha256: String,
}

fn source_digest(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_LOCK {
        return Err("immutable image source inventory exceeds fixed bound".into());
    }
    let lock: SourceLock = serde_json::from_slice(bytes)?;
    if lock.schema_version != 1 || lock.files.len() < REQUIRED.len() || lock.files.len() > 16384 {
        return Err("immutable image source inventory shape differs".into());
    }
    let mut previous: Option<&str> = None;
    for file in &lock.files {
        hash(&file.sha256)?;
        if file.path.is_empty()
            || file.path.len() > 512
            || file.bytes > 64 * 1024 * 1024
            || file
                .path
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || file
                .path
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b"/._-@".contains(&b)))
            || previous.is_some_and(|old| old >= file.path.as_str())
        {
            return Err("immutable source inventory has an unknown/duplicate/aliased entry".into());
        }
        previous = Some(&file.path);
    }
    for path in REQUIRED {
        let found = lock
            .files
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .map_err(|_| "immutable source inventory omits a fixed builder dependency")?;
        if lock.files[found].bytes == 0 {
            return Err("immutable builder dependency is empty".into());
        }
    }
    Ok(luma_content::sha256(bytes))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pin {
    device: u64,
    inode: u64,
    mode: u32,
    bytes: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
}
fn pin(file: &File, maximum: u64) -> Result<Pin> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
        || m.len() == 0
        || m.len() > maximum
    {
        return Err("fixed image builder input is not a bounded protected regular file".into());
    }
    Ok(Pin {
        device: m.dev(),
        inode: m.ino(),
        mode: m.mode(),
        bytes: m.len(),
        modified: m.mtime(),
        modified_ns: m.mtime_nsec(),
        changed: m.ctime(),
        changed_ns: m.ctime_nsec(),
    })
}
fn open(path: &str) -> Result<File> {
    let mut parent = Path::new(path).parent();
    while let Some(directory) = parent {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("fixed builder input has a writable or aliased parent".into());
        }
        parent = directory.parent();
    }
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?)
}

fn mount_id(file: &File) -> Result<u64> {
    let mut value: libc::statx = unsafe { std::mem::zeroed() };
    let empty = std::ffi::CString::new("")?;
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut value,
        )
    } != 0
        || value.stx_mask & libc::STATX_MNT_ID == 0
        || value.stx_mnt_id == 0
    {
        return Err("kernel did not prove the fixed builder mount identity".into());
    }
    Ok(value.stx_mnt_id)
}

/// A held observation, not a signed receipt or a grant. Every use rechecks the
/// genuine installed verified root and both exact named/held file identities.
pub(crate) struct FixedBuilder {
    source: File,
    source_pin: Pin,
    executable: File,
    executable_pin: Pin,
    policy: File,
    policy_pin: Pin,
    identity: BuilderIdentity,
    installed: crate::platform::InstalledDataClaim,
    root: File,
    root_mount: u64,
}
impl FixedBuilder {
    pub(crate) fn installed(mut check: impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        let installed = crate::platform::InstalledDataClaim::capture()?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open("/")?;
        let root_mount = mount_id(&root)?;
        let mut source = open(SOURCE_LOCK)?;
        let source_pin = pin(&source, MAX_SOURCE_LOCK as u64)?;
        let mut bytes = Vec::with_capacity(source_pin.bytes as usize);
        source
            .by_ref()
            .take(source_pin.bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != source_pin.bytes
            || pin(&source, MAX_SOURCE_LOCK as u64)? != source_pin
        {
            return Err("immutable source inventory changed while observing builder".into());
        }
        let source_sha256 = source_digest(&bytes)?;
        check()?;
        let mut policy = open(INDEX_POLICY)?;
        let policy_pin = pin(&policy, 4096)?;
        let mut policy_bytes = Vec::with_capacity(policy_pin.bytes as usize);
        policy
            .by_ref()
            .take(policy_pin.bytes + 1)
            .read_to_end(&mut policy_bytes)?;
        if policy_bytes.len() as u64 != policy_pin.bytes
            || pin(&policy, 4096)? != policy_pin
            || super::policy::Policy::parse(&policy_bytes)? != super::policy::Policy::compiled()
            || luma_content::sha256(&policy_bytes) != super::policy::sha256()?
        {
            return Err(
                "immutable index quota input differs from exact compiled policy bytes".into(),
            );
        }
        check()?;
        let mut executable = open(EXECUTABLE)?;
        let executable_pin = pin(&executable, MAX_EXECUTABLE)?;
        let self_image = File::open("/proc/self/exe")?;
        if pin(&self_image, MAX_EXECUTABLE)? != executable_pin {
            return Err("index builder must be the actual fixed installed image executable".into());
        }
        let mut sha = Sha256::new();
        let mut length = 0_u64;
        let mut block = [0_u8; 65536];
        loop {
            check()?;
            let count = executable.read(&mut block)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or("builder length overflow")?;
            if length > executable_pin.bytes {
                return Err("fixed builder grew during observation".into());
            }
            sha.update(&block[..count]);
        }
        if length != executable_pin.bytes {
            return Err("fixed builder ended before its pinned length".into());
        }
        let value = Self {
            source,
            source_pin,
            executable,
            executable_pin,
            policy,
            policy_pin,
            identity: BuilderIdentity {
                source_sha256,
                runtime_sha256: crate::bundle::hex(&sha.finalize()),
            },
            installed,
            root,
            root_mount,
        };
        value.check(&mut check)?;
        Ok(value)
    }
    pub(crate) fn identity(&self) -> &BuilderIdentity {
        &self.identity
    }
    pub(crate) fn check(&self, mut check: impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.installed.recheck()?;
        let named_source = open(SOURCE_LOCK)?;
        let named_executable = open(EXECUTABLE)?;
        let named_policy = open(INDEX_POLICY)?;
        let self_image = File::open("/proc/self/exe")?;
        if pin(&self.source, MAX_SOURCE_LOCK as u64)? != self.source_pin
            || pin(&named_source, MAX_SOURCE_LOCK as u64)? != self.source_pin
            || pin(&self.executable, MAX_EXECUTABLE)? != self.executable_pin
            || pin(&named_executable, MAX_EXECUTABLE)? != self.executable_pin
            || pin(&self_image, MAX_EXECUTABLE)? != self.executable_pin
            || pin(&self.policy, 4096)? != self.policy_pin
            || pin(&named_policy, 4096)? != self.policy_pin
            || [
                &self.source,
                &self.executable,
                &named_source,
                &named_executable,
                &self_image,
                &self.policy,
                &named_policy,
                &self.root,
            ]
            .iter()
            .any(|file| mount_id(file).ok() != Some(self.root_mount))
        {
            return Err("authenticated immutable builder inputs changed".into());
        }
        self.identity.validate()?;
        check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock() -> serde_json::Value {
        let mut files: Vec<_> = REQUIRED
            .iter()
            .map(|path| serde_json::json!({"path":path,"bytes":1,"sha256":"1".repeat(64)}))
            .collect();
        files.sort_by_key(|entry| entry["path"].as_str().unwrap().to_owned());
        serde_json::json!({"schema_version":1,"files":files})
    }
    #[test]
    fn immutable_inventory_closes_builder_source_tuple() {
        let original = lock();
        let bytes = serde_json::to_vec(&original).unwrap();
        assert_eq!(source_digest(&bytes).unwrap(), luma_content::sha256(&bytes));
        let mut actual_template = original.clone();
        let files = actual_template["files"].as_array_mut().unwrap();
        files.push(serde_json::json!({"path":"native/image/overlay/etc/systemd/system/luma-hardware-query@.service","bytes":1,"sha256":"2".repeat(64)}));
        files.sort_by_key(|entry| entry["path"].as_str().unwrap().to_owned());
        assert!(source_digest(&serde_json::to_vec(&actual_template).unwrap()).is_ok());
        let mut missing = original.clone();
        missing["files"].as_array_mut().unwrap().pop();
        assert!(source_digest(&serde_json::to_vec(&missing).unwrap()).is_err());
        for path in [
            "../rust/source",
            "/rust/source",
            "rust//source",
            "rust/./source",
            "rust\\source",
        ] {
            let mut changed = original.clone();
            changed["files"][0]["path"] = path.into();
            assert!(source_digest(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut duplicate = original;
        let first = duplicate["files"][0].clone();
        duplicate["files"].as_array_mut().unwrap().insert(1, first);
        assert!(source_digest(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }
}
