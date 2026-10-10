//! Independently enrolled TPM2 resource head and sealed authorization.
//! Only the composition root admits Admin ceremonies and prepares the exact
//! paired genesis backup. This module never reconstructs missing authority,
//! changes ownership, clears handles, retries uncertain writes or uses UTC.
use crate::{
    admin_credentials, bundle,
    sealed_credential::{PrivateBuffer, Secret},
    tpm::{self, Checkpoint, ResourceDevice},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/resource-checkpoint";
pub(crate) const LOCK: &str = "/run/luma-resource-checkpoint/authority.lock";
pub(crate) const INDEX: u32 = tpm::RESOURCE_INDEX;
pub(crate) const PARENT: u32 = tpm::RESOURCE_PARENT;
const MAX_CREDENTIAL: u64 = 20 * 1024;
const MAX_CONFIG: u64 = 4096;
const PUBLIC: &str = admin_credentials::PUBLIC_KEY;
const SIGNATURE: &str = admin_credentials::BOOT_SIGNATURE;
const MAGIC: &str = "luma-resource-sealed-v1";

struct ResourceLock {
    file: File,
    parent: File,
    path: PathBuf,
    directory_identity: (u64, u64),
    runtime: Option<(File, PathBuf)>,
    private_parent: bool,
}
impl ResourceLock {
    fn fixed() -> Result<Self> {
        let runtime = Path::new(LOCK)
            .parent()
            .and_then(Path::parent)
            .ok_or("fixed resource runtime lock hierarchy missing")?;
        Self::fixed_in(runtime)
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
            return Err("unsafe independent resource runtime root".into());
        }
        let namespace = std::ffi::CString::new("luma-resource-checkpoint")?;
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
                "independent resource runtime namespace must be root-owned mode 0700".into(),
            );
        }
        let path = runtime_path.join("luma-resource-checkpoint/authority.lock");
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
            return Err("independent resource runtime namespace changed during opening".into());
        }
        lock.runtime = Some((runtime, runtime_path.into()));
        lock.private_parent = true;
        lock.check()?;
        lock.file.sync_all()?;
        directory.sync_all()?;
        if created {
            lock.runtime
                .as_ref()
                .ok_or("resource runtime root pin absent")?
                .0
                .sync_all()?;
        }
        lock.check()?;
        Ok(lock)
    }
    fn from_file(file: File, path: &Path) -> Result<Self> {
        let parent_path = path.parent().ok_or("resource lock parent missing")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent_path)?;
        let m = parent.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe resource lock parent".into());
        }
        let lock = Self {
            file,
            parent,
            path: path.into(),
            directory_identity: (m.dev(), m.ino()),
            runtime: None,
            private_parent: false,
        };
        lock.check()?;
        if unsafe { libc::flock(lock.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another independent resource checkpoint writer is active".into());
        }
        lock.check()?;
        Ok(lock)
    }
    #[cfg(test)]
    fn fixture(file: File) -> Result<Self> {
        let path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        Self::from_file(file, &path)
    }
    fn check(&self) -> Result<()> {
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
                return Err("independent resource runtime root identity changed".into());
            }
        }
        let directory = self.parent.metadata()?;
        let current_directory =
            fs::symlink_metadata(self.path.parent().ok_or("resource lock parent missing")?)?;
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
            return Err("resource checkpoint exclusion directory changed".into());
        }
        let held = self.file.metadata()?;
        let name = std::ffi::CString::new(
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid resource lock member")?,
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
            return Err("resource checkpoint exclusion inode replaced or unsafe".into());
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
        return Err("resource checkpoint requires a nonzero exact digest".into());
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    tpm::private_directory(path.parent().ok_or("resource enrollment parent missing")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("resource enrollment parent missing")?)?.sync_all()?;
    Ok(())
}
fn immutable(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let bytes = tpm::private_read(path, bound)?;
    let m = fs::symlink_metadata(path)?;
    if m.mode() & 0o7777 != 0o400 {
        return Err("resource enrollment input lost immutable mode".into());
    }
    Ok(bytes)
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("resource enrollment destination already exists; preserve it".into()),
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
        return Err("resource sealed TPM blob is not bounded canonical hex".into());
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
            return Err("resource retained expected parent profile differs".into());
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
            || self.profile != "local-tpm2-resource"
            || self.index != INDEX
            || self.parent != PARENT
            || tpm::decode::<34>(&self.nv_name)? != tpm::resource_checkpoint_name()
            || tpm::decode::<34>(&self.parent_name)?[..2] != [0, 0xb]
        {
            return Err(
                "resource checkpoint configuration differs from independent fixed profile".into(),
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
        device: &mut ResourceDevice,
        public: &[u8],
        signature: &[u8],
    ) -> Result<Secret> {
        if self.format != MAGIC
            || self.installation != config.installation
            || self.parent_name != config.parent_name
            || self.public_key_sha256 != config.pcr_public_key_sha256
        {
            return Err("resource sealed envelope parent/installation/signer mismatch".into());
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
fn current_policy(device: &mut ResourceDevice, public: &[u8], signature: &[u8]) -> Result<Policy> {
    if signature.is_empty() || signature.len() > 16 * 1024 {
        return Err("resource signed PCR policy outside bound".into());
    }
    let entries: SignatureFile = serde_json::from_slice(signature)?;
    if entries.sha256.is_empty() || entries.sha256.len() > 32 {
        return Err("resource signed PCR policy count outside bound".into());
    }
    let fingerprint = tpm::credential_fingerprint(public)?;
    let current = device.current_policy11()?;
    let mut selected = None;
    for entry in entries.sha256 {
        let pk = tpm::decode::<32>(&entry.pkfp)?;
        let policy = tpm::decode::<32>(&entry.pol)?;
        let sig: [u8; 256] = crate::sealed_credential::decode_blob(entry.sig.as_bytes())?
            .try_into()
            .map_err(|_| "resource signed policy requires RSA-2048 signature")?;
        if entry.pcrs == [11] && pk == fingerprint && policy == current {
            if selected.is_some() {
                return Err("ambiguous matching resource PCR policy".into());
            }
            selected = Some(Policy {
                digest: policy,
                signature: sig,
            });
        }
    }
    let selected = selected.ok_or("no current resource PCR11 policy signed by image verifier")?;
    device.verify_boot(public, &selected.digest, &selected.signature)?;
    Ok(selected)
}
fn canonical<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical resource enrollment record".into());
    }
    Ok(value)
}
fn load(
    directory: &Path,
    device: &mut ResourceDevice,
    public: &[u8],
    signature: &[u8],
) -> Result<(Configuration, Secret, Vec<u8>, Vec<u8>)> {
    let config_bytes = immutable(&directory.join("anchor.json"), MAX_CONFIG)?;
    let blob = immutable(&directory.join("nv-auth.cred"), MAX_CREDENTIAL)?;
    let config: Configuration = canonical(&config_bytes)?;
    config.validate()?;
    if digest(public) != config.pcr_public_key_sha256
        || digest(&blob) != config.sealed_credential_sha256
    {
        return Err("resource sealed delivery hash differs from exact configuration".into());
    }
    let sealed: Sealed = canonical(&blob)?;
    let secret = sealed.unseal(&config, device, public, signature)?;
    if immutable(&directory.join("anchor.json"), MAX_CONFIG)? != config_bytes
        || immutable(&directory.join("nv-auth.cred"), MAX_CREDENTIAL)? != blob
    {
        return Err("resource sealed inputs changed while authenticating TPM".into());
    }
    Ok((config, secret, config_bytes, blob))
}

pub(crate) struct ResourceAnchor {
    device: ResourceDevice,
    lock: ResourceLock,
    installation: String,
    genesis: [u8; 32],
    poisoned: bool,
}
impl ResourceAnchor {
    pub(crate) fn installed() -> Result<Self> {
        crate::require_root()?;
        crate::platform::require_installed()?;
        let lock = ResourceLock::fixed()?;
        let mut device = ResourceDevice::local()?;
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
                "resource image signer or current boot signature changed during delivery".into(),
            );
        }
        Self::connect(device, &secret, lock, &config)
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        directory: &Path,
        root: &Path,
        lock: File,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        let mut device = ResourceDevice::fixture(directory)?;
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16 * 1024)?;
        let (config, secret, _, _) = load(&root.join("sealed"), &mut device, &public, &signature)?;
        Self::connect(device, &secret, ResourceLock::fixture(lock)?, &config)
    }
    fn connect(
        mut device: ResourceDevice,
        secret: &Secret,
        lock: ResourceLock,
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
                "resource TPM write uncertain; preserve prepared cut and reconcile explicitly"
                    .into(),
            );
        }
        self.lock.check()
    }
}
impl Checkpoint for ResourceAnchor {
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
                "resource checkpoint expected head conflict or empty event; no dispatch".into(),
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
                "resource NV outcome ambiguous; exact backup reconciliation required".into(),
            );
        }
        self.lock.check()?;
        self.poisoned = false;
        Ok(wanted)
    }
}

pub(crate) struct Provisioner {
    device: ResourceDevice,
    admission: tpm::Admission,
    public: Vec<u8>,
    signature: Vec<u8>,
    root: PathBuf,
    lock: ResourceLock,
    public_path: PathBuf,
    signature_path: PathBuf,
}
impl Provisioner {
    pub(crate) fn local() -> Result<Self> {
        let lock = ResourceLock::fixed()?;
        let device = ResourceDevice::local()?;
        Self::from_device(
            device,
            Path::new(DIRECTORY),
            lock,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn from_device(
        mut device: ResourceDevice,
        root: &Path,
        lock: ResourceLock,
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
    #[cfg(test)]
    pub(crate) fn fixture(
        directory: &Path,
        root: &Path,
        lock: File,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        Self::from_device(
            ResourceDevice::fixture(directory)?,
            root,
            ResourceLock::fixture(lock)?,
            public_path,
            signature_path,
        )
    }
    fn delivery_current(&self) -> Result<()> {
        self.lock.check()?;
        if admin_credentials::public_input(&self.public_path, 4096)? != self.public
            || admin_credentials::public_input(&self.signature_path, 16 * 1024)? != self.signature
        {
            return Err(
                "resource enrollment image signer or current boot signature changed".into(),
            );
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
            return Err("resource genesis must bind prepared paired authority bytes".into());
        }
        self.device.recheck(&self.admission)?;
        self.delivery_current()?;
        let policy = current_policy(&mut self.device, &self.public, &self.signature)?;
        Ok(
            serde_json::json!({"schema_version":1,"kind":"resource-checkpoint-enrollment",
            "installation":installation,"genesis_event":bundle::hex(&genesis),"index":INDEX,"parent":PARENT,
            "nv_name":bundle::hex(&tpm::resource_checkpoint_name()),"pcr_public_key_sha256":digest(&self.public),
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
            "custody":"existing-owner-independent-resource-auth","requires_authenticated_admin":true,
            "physical_qualification":false,"timed_authority":false}),
        )
    }
    /// The composition root's callback must authenticate the current Admin and
    /// exact paired genesis backup under retained drainage before each mutation.
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
        let proposal = self.proposal_value(installation, genesis)?;
        let intent = serde_json::to_vec(&proposal)?;
        if digest(&intent) != reviewed {
            return Err("resource enrollment exact review changed".into());
        }
        check()?;
        write_new(&self.root.join(".parent-intent.json"), &intent)?;
        self.device.recheck(&self.admission)?;
        self.delivery_current()?;
        check()?;
        if immutable(&self.root.join(".parent-intent.json"), MAX_CONFIG)? != intent {
            return Err("resource enrollment parent intent changed; no allocation".into());
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
            return Err("resource expected parent Name or dispatch fence changed".into());
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
            return Err("resource sealed enrollment exceeds bound; preserve intent".into());
        }
        let policy = current_policy(&mut self.device, &self.public, &self.signature)?;
        let config = Configuration {
            schema_version: 1,
            profile: "local-tpm2-resource".into(),
            installation: installation.into(),
            index: INDEX,
            parent: PARENT,
            nv_name: bundle::hex(&tpm::resource_checkpoint_name()),
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
            return Err("resource sealed preflight mismatch; preserve parent intent".into());
        }
        drop(recovered);
        let prepared = self.root.join(".enrollment-prepared");
        fs::DirBuilder::new().mode(0o700).create(&prepared)?;
        File::open(&self.root)?.sync_all()?;
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
            return Err("resource prepared enrollment changed; retain it".into());
        }
        absent(&root.join("sealed"))?;
        Ok(())
    }
    pub(crate) fn commit(
        mut self,
        owner: &PrivateBuffer,
        secret: &Secret,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<ResourceAnchor> {
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
            return Err("resource NV secret does not match retained sealed proposal".into());
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
        let mut anchor = ResourceAnchor::connect(
            self.provisioner.device,
            secret,
            self.provisioner.lock,
            &self.config,
        )?;
        if anchor.read()? != tpm::extend_value([0; 32], genesis) {
            return Err(
                "resource enrollment NV readback uncertain; preserve prepared backups".into(),
            );
        }
        check()?;
        publish_sealed(&self.provisioner.root, &self.config_bytes, &self.blob)?;
        Ok(anchor)
    }
}
fn publish_sealed(root: &Path, config: &[u8], blob: &[u8]) -> Result<()> {
    if immutable(&root.join(".enrollment-prepared/anchor.json"), MAX_CONFIG)? != config
        || immutable(
            &root.join(".enrollment-prepared/nv-auth.cred"),
            MAX_CREDENTIAL,
        )? != blob
    {
        return Err(
            "resource enrollment changed after NV write; preserve pending publication".into(),
        );
    }
    absent(&root.join("sealed"))?;
    let parent = File::open(root)?;
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
    if immutable(&root.join("sealed/anchor.json"), MAX_CONFIG)? != config
        || immutable(&root.join("sealed/nv-auth.cred"), MAX_CREDENTIAL)? != blob
    {
        return Err("resource enrollment publication readback uncertain".into());
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
        mut device: ResourceDevice,
        lock: ResourceLock,
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
            return Err(
                "resource parent dispatch fence differs from retained expected Name".into(),
            );
        }
        let record: ParentRecord = canonical(&parent_bytes)?;
        record.validate()?;
        let typed: EnrollmentIntent = serde_json::from_slice(&intent)?;
        let _: serde_json::Value = canonical(&intent)?;
        if digest(&intent) != record.enrollment_review
            || typed.schema_version != 1
            || typed.kind != "resource-checkpoint-enrollment"
            || typed.installation != record.installation
            || typed.genesis_event != record.genesis_event
            || typed.index != INDEX
            || typed.parent != PARENT
            || tpm::decode::<34>(&typed.nv_name)? != tpm::resource_checkpoint_name()
        {
            return Err(
                "resource parent origin intent does not bind exact installation/genesis/profile"
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
            return Err("resource pending parent signer or fixed secure-boot PCR7 changed".into());
        }
        device.parent_matches(&tpm::decode(&record.parent_name)?)?;
        device.nv_absent()?;
        let review = digest(&serde_json::to_vec(
            &serde_json::json!({"kind":"resource-parent-reconcile-v1",
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
            ResourceDevice::local()?,
            ResourceLock::fixed()?,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn report(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":"resource-parent-reconcile","review_sha256":self.review,
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
                "resource parent continuation exact reviewed paired identity changed".into(),
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
                "resource parent expected Name or origin changed during revalidation".into(),
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
/// resource template; this inspection is not permission to repeat EvictControl.
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
    anchor: ResourceAnchor,
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
        mut device: ResourceDevice,
        lock: ResourceLock,
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
            return Err("resource pending parent intent differs from enrollment review".into());
        }
        let marker = immutable(
            &root.join(".enrollment-prepared/nv-dispatched.json"),
            MAX_CONFIG,
        )?;
        let expected = serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "enrollment_review":config.enrollment_review,"genesis_event":config.genesis_event}))?;
        if marker != expected {
            return Err("resource pending one-shot NV dispatch fence differs".into());
        }
        let mut anchor = ResourceAnchor::connect(device, &secret, lock, &config)?;
        if anchor.read()? != tpm::extend_value([0; 32], anchor.genesis) {
            return Err(
                "resource pending NV is not the exact enrolled genesis; no write retry or reset"
                    .into(),
            );
        }
        let review = digest(&serde_json::to_vec(
            &serde_json::json!({"kind":"resource-pending-finalize-v1",
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
        let lock = ResourceLock::fixed()?;
        Self::open_at(
            Path::new(DIRECTORY),
            ResourceDevice::local()?,
            lock,
            Path::new(PUBLIC),
            Path::new(SIGNATURE),
        )
    }
    fn report(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":"resource-pending-finalize", "review_sha256":self.review,
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
    ) -> Result<ResourceAnchor> {
        if self.review != reviewed
            || self.config.installation != installation
            || self.anchor.genesis != genesis
        {
            return Err(
                "resource pending publication exact paired identity or review changed".into(),
            );
        }
        check()?;
        if self.anchor.read()? != tpm::extend_value([0; 32], genesis) {
            return Err("resource pending head changed; preserve all prepared evidence".into());
        }
        if admin_credentials::public_input(&self.public_path, 4096)? != self.public
            || admin_credentials::public_input(&self.signature_path, 16 * 1024)? != self.signature
        {
            return Err("resource pending boot delivery changed; preserve evidence".into());
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
) -> Result<ResourceAnchor> {
    PendingPublication::local()?.finalize(installation, genesis, reviewed, check)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Configuration {
        Configuration {
            schema_version: 1,
            profile: "local-tpm2-resource".into(),
            installation: "11".repeat(32),
            index: INDEX,
            parent: PARENT,
            nv_name: bundle::hex(&tpm::resource_checkpoint_name()),
            parent_name: format!("000b{}", "22".repeat(32)),
            genesis_event: "33".repeat(32),
            enrollment_review: "44".repeat(32),
            pcr_public_key_sha256: "55".repeat(32),
            pcr7_sha256: "00".repeat(32),
            policy11_sha256: "66".repeat(32),
            sealed_credential_sha256: "77".repeat(32),
        }
    }
    #[test]
    fn resource_profile_cannot_select_admin_authority_or_unbound_installation() {
        let initial = config();
        initial.validate().unwrap();
        assert_ne!(tpm::resource_checkpoint_name(), tpm::checkpoint_name());
        for field in 0..7 {
            let mut next = initial.clone();
            match field {
                0 => next.index = 0x01804c41,
                1 => next.parent = 0x81004c41,
                2 => next.nv_name = bundle::hex(&tpm::checkpoint_name()),
                3 => next.installation = "00".repeat(32),
                4 => next.genesis_event = "00".repeat(32),
                5 => next.profile = "local-tpm2".into(),
                _ => next.parent_name = "00".repeat(34),
            }
            assert!(next.validate().is_err());
        }
        let mut value = serde_json::to_value(initial).unwrap();
        value["caller_verified"] = true.into();
        assert!(serde_json::from_value::<Configuration>(value).is_err());
    }
    #[test]
    fn independent_lock_refuses_current_inode_replacement_and_public_writes() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "luma-resource-checkpoint-lock-{}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
        let path = root.join("anchor.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let lock = ResourceLock::from_file(file, &path).unwrap();
        lock.check().unwrap();
        let duplicate = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(ResourceLock::from_file(duplicate, &path).is_err());
        fs::remove_file(&path).unwrap();
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(lock.check().is_err());
        drop(lock);
        let replacement = ResourceLock::from_file(replacement, &path).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(replacement.check().is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        drop(replacement);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn fixed_lock_has_closed_independent_runtime_namespace() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        assert_eq!(LOCK, "/run/luma-resource-checkpoint/authority.lock");
        let root =
            std::env::temp_dir().join(format!("luma-resource-fixed-lock-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
        let namespace = root.join("luma-resource-checkpoint");
        let path = namespace.join("authority.lock");
        let lock = ResourceLock::fixed_in(&root).unwrap();
        assert_eq!(
            fs::symlink_metadata(&namespace).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert!(ResourceLock::fixed_in(&root).is_err());
        let broker = root.join("luma-broker");
        fs::DirBuilder::new().mode(0o755).create(&broker).unwrap();
        fs::remove_dir(&broker).unwrap();
        lock.check().unwrap();

        let moved = root.with_extension("retained");
        fs::rename(&root, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        assert!(lock.check().is_err());
        drop(lock);
        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ResourceLock::fixed_in(&root).is_err());
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"foreign lock contents").unwrap();
        assert!(ResourceLock::fixed_in(&root).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&namespace).unwrap();
        let target = root.join("foreign-namespace");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        symlink(&target, &namespace).unwrap();
        assert!(ResourceLock::fixed_in(&root).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_file(&namespace).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ResourceLock::fixed_in(&root).is_err());
        assert!(!namespace.exists());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(&target).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn bounded_canonical_sealed_payload_has_no_secret_or_shared_profile() {
        let value = Sealed {
            format: MAGIC.into(),
            installation: "11".repeat(32),
            parent_name: format!("000b{}", "22".repeat(32)),
            public_key_sha256: "33".repeat(32),
            public_blob: encode_hex(b"TPM public blob"),
            private_blob: encode_hex(b"TPM encrypted private blob"),
        };
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: Sealed = canonical(&encoded).unwrap();
        assert_eq!(
            decode_blob(&decoded.public_blob).unwrap(),
            b"TPM public blob"
        );
        for bad in [
            "".into(),
            "0".into(),
            "AA".into(),
            "zz".into(),
            "00".repeat(4097),
        ] {
            assert!(decode_blob(&bad).is_err());
        }
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend(encoded);
        assert!(canonical::<Sealed>(&noncanonical).is_err());
    }
    #[test]
    #[ignore = "requires fresh disposable swtpm, existing-owner binary and signed PCR11 fixture"]
    fn emulator_resource_enrollment_sealed_restart_and_exact_extend() {
        use std::io::Read;
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("resource-state");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("resource-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let genesis = [0x71; 32];
        let installation = "11".repeat(32);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        let prepared = provisioner
            .prepare(&installation, genesis, review, &owner, &secret, || Ok(()))
            .unwrap();
        let mut anchor = prepared.commit(&owner, &secret, || Ok(())).unwrap();
        assert_eq!(anchor.installation(), installation);
        assert_eq!(anchor.genesis_event(), genesis);
        let head = tpm::extend_value([0; 32], genesis);
        assert_eq!(anchor.read().unwrap(), head);
        assert!(tpm::exclusive_lock(&lock_path).is_err());
        let next = anchor.advance(head, [0x72; 32]).unwrap();
        assert_eq!(next, tpm::extend_value(head, [0x72; 32]));
        assert!(anchor.advance(head, [0x73; 32]).is_err());
        assert_eq!(anchor.read().unwrap(), next);
        drop(anchor);
        let mut reopened = ResourceAnchor::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        assert_eq!(reopened.read().unwrap(), next);
        assert!(Provisioner::fixture(
            &directory,
            &root,
            File::open("/dev/null").unwrap(),
            &public,
            &signature
        )
        .is_err());
        let saved = immutable(&root.join("sealed/anchor.json"), MAX_CONFIG).unwrap();
        let mut substituted: Configuration = canonical(&saved).unwrap();
        substituted.index = 0x01804c41;
        assert!(substituted.validate().is_err());
    }
    #[test]
    #[ignore = "requires fresh disposable swtpm, existing-owner binary and signed PCR11 fixture"]
    fn emulator_resource_lost_publication_is_explicit_finalize_without_nv_replay() {
        use std::io::Read;
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("resource-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("resource-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let genesis = [0x74; 32];
        let installation = "12".repeat(32);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let prepared = provisioner
            .prepare(
                &installation,
                genesis,
                proposal["review_sha256"].as_str().unwrap(),
                &owner,
                &secret,
                || Ok(()),
            )
            .unwrap();
        let mut boundaries = 0;
        assert!(prepared
            .commit(&owner, &secret, || {
                boundaries += 1;
                if boundaries == 3 {
                    Err("fixture loses final publication authority".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(boundaries, 3);
        assert!(root
            .join(".enrollment-prepared/nv-dispatched.json")
            .is_file());
        assert!(!root.join("sealed").exists());
        let pending = PendingPublication::open_at(
            &root,
            ResourceDevice::fixture(&directory).unwrap(),
            ResourceLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let report = pending.report();
        assert_eq!(report["nv_write_retry"], false);
        assert!(pending
            .finalize(&installation, genesis, &"00".repeat(32), || panic!(
                "wrong review cannot publish"
            ))
            .is_err());
        let pending = PendingPublication::open_at(
            &root,
            ResourceDevice::fixture(&directory).unwrap(),
            ResourceLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let mut anchor = pending
            .finalize(
                &installation,
                genesis,
                report["review_sha256"].as_str().unwrap(),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(anchor.read().unwrap(), tpm::extend_value([0; 32], genesis));
        assert!(root.join("sealed").is_dir());
        assert!(!root.join(".enrollment-prepared").exists());
    }
    #[test]
    #[ignore = "requires fresh disposable swtpm, existing-owner binary and signed PCR11 fixture"]
    fn emulator_resource_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay()
    {
        use std::io::Read;
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("resource-parent-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("resource-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let genesis = [0x75; 32];
        let installation = "13".repeat(32);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let mut boundaries = 0;
        assert!(provisioner
            .prepare(
                &installation,
                genesis,
                proposal["review_sha256"].as_str().unwrap(),
                &owner,
                &secret,
                || {
                    boundaries += 1;
                    if boundaries == 5 {
                        Err("fixture loses parent persistence reply before sealing".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert_eq!(boundaries, 5);
        assert!(!root.join(".enrollment-prepared").exists());
        let expected = immutable(&root.join(".parent-name.json"), MAX_CONFIG).unwrap();
        assert_eq!(
            immutable(&root.join(".parent-dispatched.json"), MAX_CONFIG).unwrap(),
            expected
        );
        let pending = ParentPending::open_at(
            &root,
            ResourceDevice::fixture(&directory).unwrap(),
            ResourceLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let report = pending.report();
        assert_eq!(report["parent_persistence_replay"], false);
        let prepared = pending
            .resume(
                &installation,
                genesis,
                report["review_sha256"].as_str().unwrap(),
                &secret,
                || Ok(()),
            )
            .unwrap();
        let mut anchor = prepared.commit(&owner, &secret, || Ok(())).unwrap();
        assert_eq!(anchor.read().unwrap(), tpm::extend_value([0; 32], genesis));
        assert_eq!(
            immutable(&root.join(".parent-name.json"), MAX_CONFIG).unwrap(),
            expected
        );
        assert!(root.join(".parent-reconciled.json").is_file());
    }
}
