use crate::{
    bundle::{self, Manifest, VerifiedBundle},
    disk::{command, Disk},
    Result,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MIB: u64 = 1024 * 1024;
const BOOT_COUNT_PATH: &str =
    "/sys/firmware/efi/efivars/LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

pub fn console_line(secret: bool) -> Result<String> {
    console_prompt(secret, None)
}

fn console_prompt(secret: bool, prompt: Option<&str>) -> Result<String> {
    terminal_prompt(secret, prompt, false)
}

struct Terminal {
    file: File,
    original: libc::termios,
    secret: bool,
}
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original);
        }
        if self.secret {
            let _ = self.file.write_all(b"\n");
        }
    }
}

fn terminal_prompt(secret: bool, prompt: Option<&str>, boot: bool) -> Result<String> {
    let paths: Vec<String> = if boot {
        // Prompt both an attached display/keyboard and an active serial console.
        // /dev/console alone would route native unlock only to the last console=
        // argument and could strand a physical machine without a serial cable.
        fs::read_to_string("/sys/class/tty/console/active")?
            .split_whitespace()
            .filter(|s| s.len() < 32 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(|s| format!("/dev/{}", if s == "tty0" { "tty1" } else { s }))
            .collect()
    } else {
        vec!["/dev/tty".into()]
    };
    let files: std::io::Result<Vec<_>> = paths
        .iter()
        .map(|path| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(path)
        })
        .collect();
    prompt_files(files?, secret, prompt)
}

fn prompt_files(files: Vec<File>, secret: bool, prompt: Option<&str>) -> Result<String> {
    let mut terminals = Vec::new();
    for file in files {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut original) } != 0 {
            return Err("interactive terminal required".into());
        }
        let terminal = Terminal {
            file,
            original,
            secret,
        };
        if secret {
            let mut hidden = original;
            hidden.c_lflag &= !libc::ECHO;
            if unsafe { libc::tcsetattr(terminal.file.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
                return Err("cannot suppress terminal echo".into());
            }
        }
        terminals.push(terminal);
    }
    if terminals.is_empty() {
        return Err("no active local console".into());
    }
    // Echo is disabled everywhere before advertising the secret prompt.
    if let Some(prompt) = prompt {
        for terminal in &mut terminals {
            writeln!(terminal.file, "{prompt}")?;
            terminal.file.flush()?;
        }
    }
    let mut polls: Vec<_> = terminals
        .iter()
        .map(|t| libc::pollfd {
            fd: t.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 180_000) } <= 0 {
        return Err("local input timed out or was interrupted".into());
    }
    let index = polls
        .iter()
        .position(|p| p.revents & libc::POLLIN != 0)
        .ok_or("console disconnected")?;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        terminals[index].file.read_exact(&mut byte)?;
        if matches!(byte[0], b'\n' | b'\r') {
            break;
        }
        if bytes.len() >= 1024 || byte[0] < 32 {
            return Err("invalid console input".into());
        }
        bytes.push(byte[0]);
    }
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    #[test]
    fn immediate_input_is_not_flushed_and_echo_is_hidden_before_prompt() {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let check = slave.try_clone().unwrap();
        let input = std::thread::spawn(move || {
            let mut master = master;
            let mut output = Vec::new();
            let mut b = [0u8; 1];
            while !output.ends_with(b"SECRET_PROMPT\r\n") {
                master.read_exact(&mut b).unwrap();
                output.push(b[0]);
            }
            let mut state: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::tcgetattr(master.as_raw_fd(), &mut state) },
                0
            );
            assert_eq!(state.c_lflag & libc::ECHO, 0);
            master.write_all(b"immediate-passphrase\n").unwrap();
            // Keep the master alive until the reader has completed.
            master
        });
        assert_eq!(
            prompt_files(vec![slave], true, Some("SECRET_PROMPT")).unwrap(),
            "immediate-passphrase"
        );
        let master = input.join().unwrap();
        let mut state: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(check.as_raw_fd(), &mut state) }, 0);
        assert_ne!(state.c_lflag & libc::ECHO, 0);
        drop(master);
    }
    #[test]
    fn no_console_is_denied() {
        assert!(prompt_files(vec![], true, Some("secret")).is_err());
    }
}

fn password(label: &str) -> Result<String> {
    let value = console_prompt(true, Some(&format!("{label} (at least 16 characters):")))?;
    if value.chars().count() < 16 {
        return Err("credential is too short".into());
    }
    if console_prompt(true, Some(&format!("Repeat {label}:")))? != value {
        return Err("credentials do not match".into());
    }
    Ok(value)
}

fn secret_fd(secret: &str) -> Result<File> {
    let name = std::ffi::CString::new("luma-credential")?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(secret.as_bytes())?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn with_input(program: &str, args: &[&str], input: &str) -> Result<String> {
    let fd = secret_fd(input)?;
    let result = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::from(fd))
        .output()?;
    if !result.status.success() {
        let detail = String::from_utf8_lossy(&result.stderr).replace(input, "[redacted]");
        return Err(format!(
            "{program} failed ({}): {}",
            result.status,
            detail.chars().take(512).collect::<String>()
        )
        .into());
    }
    Ok(String::from_utf8(result.stdout)?)
}

fn path(p: &Path) -> Result<&str> {
    p.to_str().ok_or_else(|| "non-UTF8 path".into())
}
fn cmdline() -> Result<String> {
    Ok(fs::read_to_string("/proc/cmdline")?)
}
pub(crate) fn live() -> Result<bool> {
    Ok(cmdline()?.split_whitespace().any(|a| a == "luma.mode=live"))
}

pub(crate) fn require_live() -> Result<()> {
    crate::require_root()?;
    if !live()? {
        return Err(
            "installation and offline recovery require the booted Luma recovery image".into(),
        );
    }
    Ok(())
}

/// Static laboratory signatures are never a fallback for a production root,
/// including an inert first boot with no enrolled release authority yet.
pub(crate) fn require_laboratory_image() -> Result<()> {
    let identity: RunningIdentity =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    validate_image_identity(&identity)?;
    require_laboratory_environment(&identity.environment)
}

fn require_laboratory_environment(environment: &str) -> Result<()> {
    if environment != "lab" {
        return Err("static laboratory signatures require an immutable laboratory image; production cannot downgrade before enrollment".into());
    }
    Ok(())
}

/// Shared service/CLI activation fence. A structurally signed initial image
/// has no protected authority until current TPM-backed Admin trust explicitly
/// acknowledges this exact installed immutable release.
pub(crate) fn require_production_activation() -> Result<()> {
    let identity: RunningIdentity =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    validate_image_identity(&identity)?;
    if identity.environment != "production" {
        return Ok(());
    }
    require_installed()?;
    let state = crate::admin_governance::release_state_optional()?
        .ok_or("production image is inert until Admin/TPM/UTC release activation")?;
    for retained in [state.acknowledged.as_ref(), state.retained.as_ref()] {
        if let Some(manifest) = retained {
            if check_governance_manifest(manifest).is_ok() {
                return Ok(());
            }
        }
    }
    if let Some(pending) = &state.pending {
        check_governance_manifest(&pending.candidate.manifest)?;
        let current = crate::admin_governance::release_authority()?;
        if current.0.as_ref() != Some(&state) {
            return Err("production release activation changed".into());
        }
        return crate::release_trust::check_effect_time(&state, current.1);
    }
    Err("production image is not an exact activated release or retained fallback".into())
}

enum CatalogImageSource {
    Installed,
    #[cfg(test)]
    Disposable {
        directory: PathBuf,
        descriptor: File,
        identity: (u64, u64),
    },
}

/// Private image context owned by one authenticated catalog attempt. A
/// disposable laboratory context is available only to isolated test builds;
/// there is no caller environment flag or missing-file production fallback.
pub(crate) struct CatalogImage {
    source: CatalogImageSource,
    bytes: Vec<u8>,
    identity: RunningIdentity,
}
impl CatalogImage {
    pub(crate) fn capture(directory: &Path) -> Result<Self> {
        #[cfg(test)]
        if directory.file_name() == Some(std::ffi::OsStr::new("admin"))
            && directory.parent().is_some_and(|parent| {
                parent.parent() == Some(Path::new("/tmp"))
                    && parent.file_name().is_some_and(|name| {
                        name.to_string_lossy().starts_with("luma-tpm-delivery-")
                    })
            })
            && Path::new("/.dockerenv").is_file()
            && !Path::new("/dev/tpm0").exists()
            && !Path::new("/dev/tpmrm0").exists()
        {
            let descriptor = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory)?;
            let metadata = descriptor.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err("unsafe disposable catalog image context".into());
            }
            let identity = RunningIdentity {
                schema_version: 1,
                release: "disposable-catalog-fixture".into(),
                sequence: 1,
                environment: "lab".into(),
                architecture: "amd64".into(),
                ubuntu: "24.04".into(),
                edition: "headless".into(),
            };
            let bytes = serde_json::to_vec(&identity)?;
            return Ok(Self {
                source: CatalogImageSource::Disposable {
                    directory: directory.into(),
                    descriptor,
                    identity: (metadata.dev(), metadata.ino()),
                },
                bytes,
                identity,
            });
        }
        if directory != Path::new("/var/lib/luma-os/admin") {
            return Err("installed catalog image requires the fixed Admin namespace".into());
        }
        let bytes = crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?;
        let identity: RunningIdentity = serde_json::from_slice(&bytes)?;
        validate_image_identity(&identity)?;
        Ok(Self {
            source: CatalogImageSource::Installed,
            bytes,
            identity,
        })
    }
    pub(crate) fn production(&self) -> bool {
        self.identity.environment == "production"
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        match &self.source {
            CatalogImageSource::Installed => {
                if crate::admin_credentials::public_input(
                    Path::new("/usr/share/luma-os/release-identity.json"),
                    4096,
                )? != self.bytes
                {
                    return Err("catalog immutable image identity changed".into());
                }
            }
            #[cfg(test)]
            CatalogImageSource::Disposable {
                directory,
                descriptor,
                identity,
            } => {
                let current = fs::symlink_metadata(directory)?;
                let held = descriptor.metadata()?;
                if !current.is_dir()
                    || (current.dev(), current.ino()) != *identity
                    || (held.dev(), held.ino()) != *identity
                {
                    return Err("disposable catalog context changed".into());
                }
            }
        }
        validate_image_identity(&self.identity)
    }
}

fn validate_image_identity(identity: &RunningIdentity) -> Result<()> {
    if identity.schema_version != 1
        || identity.sequence == 0
        || identity.sequence > i64::MAX as u64
        || !crate::admin_roles::identifier(&identity.release)
        || !matches!(identity.environment.as_str(), "lab" | "production")
        || identity.architecture != "amd64"
        || identity.ubuntu != "24.04"
        || !matches!(identity.edition.as_str(), "headless" | "desktop")
    {
        return Err("invalid immutable release identity".into());
    }
    Ok(())
}

pub(crate) fn write_atomic(destination: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    write_atomic_guarded(destination, bytes, mode, &mut || Ok(()))
}

fn write_atomic_guarded(
    destination: &Path,
    bytes: &[u8],
    mode: u32,
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let parent = destination.parent().ok_or("missing parent")?;
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let temporary = destination.with_extension(format!("new-{}", bundle::hex(&random)));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(temporary.clone());
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    for chunk in bytes.chunks(1024 * 1024) {
        guard()?;
        f.write_all(chunk)?;
        guard()?;
    }
    guard()?;
    // Publish the exact requested mode, independently of hardened service
    // umasks. Incomplete staging stays private until all bytes are written.
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    guard()?;
    f.sync_all()?;
    guard()?;
    fs::rename(&temporary, destination)?;
    guard()?;
    File::open(parent)?.sync_all()?;
    guard()?;
    Ok(())
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;

    #[test]
    fn exact_modes_survive_restrictive_umask_without_public_partial_bytes() {
        if std::env::var_os("LUMA_ATOMIC_UMASK_FIXTURE").is_none() {
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::atomic_write_tests::exact_modes_survive_restrictive_umask_without_public_partial_bytes",
                    "--test-threads=1",
                ])
                .env("LUMA_ATOMIC_UMASK_FIXTURE", "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        // This is an owned test process, never the parallel harness or host.
        unsafe {
            libc::umask(0o077);
        }
        let directory =
            std::env::temp_dir().join(format!("luma-atomic-mode-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let destination = directory.join("published");
        for mode in [0o600, 0o644, 0o444, 0o755] {
            let bytes = vec![b'x'; 2 * 1024 * 1024];
            let mut observations = 0;
            write_atomic_guarded(&destination, &bytes, mode, &mut || {
                for entry in fs::read_dir(&directory)? {
                    let entry = entry?;
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("published.new-")
                    {
                        let metadata = entry.metadata()?;
                        if metadata.len() < bytes.len() as u64 {
                            assert_eq!(metadata.mode() & 0o777, 0o600);
                            observations += 1;
                        }
                    }
                }
                Ok(())
            })
            .unwrap();
            assert!(observations > 0);
            assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, mode);
            assert_eq!(fs::read(&destination).unwrap(), bytes);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        }
        fs::remove_file(destination).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}

struct Mount {
    at: PathBuf,
    device: PathBuf,
}
impl Mount {
    fn new(device: &Path, at: PathBuf, options: &str) -> Result<Self> {
        let device = fs::canonicalize(device)?;
        fs::create_dir_all(&at)?;
        command(
            "/usr/bin/mount",
            &["-o", options, path(&device)?, path(&at)?],
        )?;
        Ok(Self { at, device })
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        let _ = command("/usr/bin/umount", &[self.at.to_str().unwrap_or("")]);
    }
}

struct Crypt {
    name: String,
}
impl Drop for Crypt {
    fn drop(&mut self) {
        let _ = command("/usr/sbin/cryptsetup", &["close", &self.name]);
    }
}

fn unlock(device: &Path, readonly: bool) -> Result<Crypt> {
    let secret = console_prompt(true, Some("Enter data or independent recovery passphrase:"))?;
    let name = format!("luma-recovery-{}", std::process::id());
    let mut args = vec![
        "open",
        "--type",
        "luks2",
        "--key-file",
        "-",
        path(device)?,
        &name,
    ];
    if readonly {
        args.insert(1, "--readonly");
    }
    with_input("/usr/sbin/cryptsetup", &args, &secret)?;
    Ok(Crypt { name })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KernelMount {
    id: u64,
    device: String,
    root: String,
    at: PathBuf,
    options: Vec<String>,
    filesystem: String,
    source: String,
    super_options: Vec<String>,
}

/// Data-only exact installer mount observation. It is not recovery, trust,
/// model activation, or an installed resource lease.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallerMountClaim {
    device: PathBuf,
    at: PathBuf,
    mount: KernelMount,
    directory_identity: (u64, u64),
    disk: crate::disk::Identity,
    partition: u8,
    mapper_uuid: Option<String>,
}
impl InstallerMountClaim {
    pub(crate) fn at(&self) -> &Path {
        &self.at
    }
    pub(crate) fn disk(&self) -> &crate::disk::Identity {
        &self.disk
    }
    pub(crate) fn enter_worker(&mut self) -> Result<()> {
        let current = kernel_mount(&self.at)?;
        let mut expected = self.mount.clone();
        expected.id = current.id;
        if self.partition == 6 && current.options.iter().any(|v| v == "ro") {
            for option in &mut expected.options {
                if option == "rw" {
                    *option = "ro".into();
                }
            }
        }
        if current != expected {
            return Err("installer worker namespace differs from target mount".into());
        }
        self.mount = current;
        self.recheck()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::disk::recheck_installer_identity(&self.disk)?;
        let current = fs::symlink_metadata(&self.at)?;
        let device = fs::metadata(&self.device)?;
        use std::os::unix::fs::FileTypeExt;
        if !current.is_dir()
            || current.uid() != 0
            || current.mode() & 0o022 != 0
            || (current.dev(), current.ino()) != self.directory_identity
            || kernel_mount(&self.at)? != self.mount
            || !device.file_type().is_block_device()
            || device_number(&device) != self.mount.device
            || self.mount.root != "/"
        {
            return Err("installer target mount identity changed".into());
        }
        check_installer_mount_claim(&self.mount, self.partition)?;
        let sys = Path::new("/sys/class/block")
            .join(self.device.file_name().ok_or("installer device name")?);
        let underlying = if self.partition == 6 {
            let uuid = fs::read_to_string(sys.join("dm/uuid"))?;
            if self.mapper_uuid.as_ref() != Some(&uuid) || !uuid.trim().starts_with("CRYPT-LUKS2-")
            {
                return Err("installer encrypted mapper identity changed".into());
            }
            let slaves = fs::read_dir(sys.join("slaves"))?.collect::<std::io::Result<Vec<_>>>()?;
            if slaves.len() != 1 {
                return Err("installer mapper backing device is ambiguous".into());
            }
            Path::new("/dev").join(slaves[0].file_name())
        } else {
            if self.mapper_uuid.is_some() {
                return Err("unexpected installer mapper claim".into());
            }
            self.device.clone()
        };
        if crate::disk::parent_disk(&underlying)? != Path::new(&self.disk.path)
            || fs::read_to_string(
                Path::new("/sys/class/block")
                    .join(underlying.file_name().ok_or("installer partition")?)
                    .join("partition"),
            )?
            .trim()
            .parse::<u8>()?
                != self.partition
        {
            return Err("installer mount belongs to another target partition".into());
        }
        Ok(())
    }
}
fn check_installer_mount_claim(mount: &KernelMount, partition: u8) -> Result<()> {
    let has = |value: &str| mount.options.iter().any(|v| v == value);
    if !has("nodev")
        || !has("nosuid")
        || mount.root != "/"
        || match partition {
            1 => mount.filesystem != "vfat" || !has("rw") || !has("noexec"),
            2 => mount.filesystem != "ext4" || !has("ro") || !has("noexec"),
            6 => mount.filesystem != "ext4" || !(has("rw") ^ has("ro")),
            _ => true,
        }
    {
        return Err("unsupported installer mount disposition".into());
    }
    Ok(())
}
/// Only the installer can mint this capability from its owned Mount object.
pub(crate) struct InstallerMount {
    claim: InstallerMountClaim,
    directory: File,
}
impl InstallerMount {
    fn capture(disk: &Disk, mount: &Mount, partition: u8) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&mount.at)?;
        let metadata = directory.metadata()?;
        let claim = InstallerMountClaim {
            device: mount.device.clone(),
            at: mount.at.clone(),
            mount: kernel_mount(&mount.at)?,
            directory_identity: (metadata.dev(), metadata.ino()),
            disk: disk.identity.clone(),
            partition,
            mapper_uuid: if partition == 6 {
                Some(fs::read_to_string(
                    Path::new("/sys/class/block")
                        .join(mount.device.file_name().ok_or("installer mapper name")?)
                        .join("dm/uuid"),
                )?)
            } else {
                None
            },
        };
        if partition == 6 && !claim.mount.options.iter().any(|v| v == "rw") {
            return Err("installer controller data mount is not writable".into());
        }
        claim.recheck()?;
        Ok(Self { claim, directory })
    }
    pub(crate) fn claim(&self) -> InstallerMountClaim {
        self.claim.clone()
    }
    pub(crate) fn device(&self) -> &Path {
        &self.claim.device
    }
    pub(crate) fn at(&self) -> &Path {
        &self.claim.at
    }
    pub(crate) fn recheck(&self, disk: &crate::disk::Identity) -> Result<()> {
        let m = self.directory.metadata()?;
        if &self.claim.disk != disk || (m.dev(), m.ino()) != self.claim.directory_identity {
            return Err("installer mount capability changed".into());
        }
        self.claim.recheck()
    }
}

#[cfg(test)]
mod installer_mount_tests {
    use super::*;
    #[test]
    fn installer_mounts_are_closed_to_exact_filesystem_partition_and_access_mode() {
        for (partition, line) in [
            (
                1,
                "30 20 8:1 / /esp rw,nodev,nosuid,noexec - vfat /dev/sda1 rw\n",
            ),
            (
                2,
                "31 20 8:2 / /root ro,nodev,nosuid,noexec - ext4 /dev/sda2 rw\n",
            ),
            (
                6,
                "32 20 253:0 / /data rw,nodev,nosuid - ext4 /dev/dm-0 rw\n",
            ),
        ] {
            let at = match partition {
                1 => "/esp",
                2 => "/root",
                _ => "/data",
            };
            let mount = parse_kernel_mount(line, Path::new(at)).unwrap();
            check_installer_mount_claim(&mount, partition).unwrap();
            for case in 0..4 {
                let mut other = mount.clone();
                match case {
                    0 => other.filesystem = "overlay".into(),
                    1 => other.root = "/subtree".into(),
                    2 => other.options.retain(|v| v != "nodev"),
                    _ => other.options.retain(|v| v != "nosuid"),
                };
                assert!(check_installer_mount_claim(&other, partition).is_err());
            }
            assert!(check_installer_mount_claim(&mount, 3).is_err());
        }
        let root = parse_kernel_mount(
            "31 20 8:2 / /root rw,nodev,nosuid,noexec - ext4 /dev/sda2 rw\n",
            Path::new("/root"),
        )
        .unwrap();
        assert!(check_installer_mount_claim(&root, 2).is_err());
    }
}

fn mount_word(word: &str) -> Result<String> {
    let mut out = Vec::new();
    let bytes = word.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..index + 4]
                    .iter()
                    .all(|v| (b'0'..=b'7').contains(v))
            {
                return Err("invalid kernel mount escape".into());
            }
            let value = u8::try_from(
                u16::from(bytes[index + 1] - b'0') * 64
                    + u16::from(bytes[index + 2] - b'0') * 8
                    + u16::from(bytes[index + 3] - b'0'),
            )?;
            if value == 0 {
                return Err("NUL kernel mount path".into());
            }
            out.push(value);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

fn kernel_mount(at: &Path) -> Result<KernelMount> {
    let bytes = fs::read("/proc/self/mountinfo")?;
    if bytes.len() > 1024 * 1024 {
        return Err("oversized kernel mount inventory".into());
    }
    let inventory = String::from_utf8(bytes)?;
    parse_kernel_mount(&inventory, at)
}

fn parse_kernel_mount(inventory: &str, at: &Path) -> Result<KernelMount> {
    let mut found = None;
    for line in inventory.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or("malformed kernel mount record")?;
        let a: Vec<_> = left.split_whitespace().collect();
        let b: Vec<_> = right.split_whitespace().collect();
        if a.len() < 6 || b.len() != 3 {
            return Err("malformed kernel mount fields".into());
        }
        let point = PathBuf::from(mount_word(a[4])?);
        if point != at {
            continue;
        }
        if found.is_some() {
            return Err("stacked recovery mountpoint is ambiguous".into());
        }
        found = Some(KernelMount {
            id: a[0].parse()?,
            device: a[2].into(),
            root: mount_word(a[3])?,
            at: point,
            options: a[5].split(',').map(str::to_owned).collect(),
            filesystem: b[0].into(),
            source: mount_word(b[1])?,
            super_options: b[2].split(',').map(str::to_owned).collect(),
        });
    }
    found.ok_or_else(|| "expected kernel mount is absent".into())
}

fn has_option(options: &[String], value: &str) -> bool {
    options.iter().any(|option| option == value)
}

fn device_number(metadata: &fs::Metadata) -> String {
    // The libc scalar helpers decode stat's dev_t without accessing a device.
    let (major, minor) = unsafe { (libc::major(metadata.rdev()), libc::minor(metadata.rdev())) };
    format!("{major}:{minor}")
}

/// Independently verifiable immutable live-image proof. The UTC keeper may
/// retain this token without ever opening target data, a TPM, or a raw device.
pub(crate) struct RecoveryImage {
    identity: Vec<u8>,
    command_line: String,
    mount: KernelMount,
    root: File,
    root_identity: (u64, u64),
}
impl RecoveryImage {
    pub(crate) fn current() -> Result<Self> {
        require_live()?;
        let identity = crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?;
        let parsed: RunningIdentity = serde_json::from_slice(&identity)?;
        let command_line = cmdline()?;
        let mount = kernel_mount(Path::new("/"))?;
        validate_recovery_image(&parsed, &command_line, &mount)?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let metadata = root.metadata()?;
        let result = Self {
            identity,
            command_line,
            mount,
            root,
            root_identity: (metadata.dev(), metadata.ino()),
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require_live()?;
        let metadata = self.root.metadata()?;
        let current = fs::metadata("/")?;
        if (metadata.dev(), metadata.ino()) != self.root_identity
            || (current.dev(), current.ino()) != self.root_identity
            || cmdline()? != self.command_line
            || kernel_mount(Path::new("/"))? != self.mount
            || crate::admin_credentials::public_input(
                Path::new("/usr/share/luma-os/release-identity.json"),
                4096,
            )? != self.identity
        {
            return Err("immutable recovery image changed".into());
        }
        validate_recovery_image(
            &serde_json::from_slice(&self.identity)?,
            &self.command_line,
            &self.mount,
        )
    }
}

fn validate_recovery_image(
    identity: &RunningIdentity,
    args: &str,
    mount: &KernelMount,
) -> Result<()> {
    check_recovery_image_claims(identity, args, mount)?;
    let dm = Path::new("/sys/dev/block").join(&mount.device).join("dm");
    if fs::read_to_string(dm.join("name"))?.trim() != "root"
        || !fs::read_to_string(dm.join("uuid"))?
            .trim()
            .starts_with("CRYPT-VERITY-")
    {
        return Err("live root is not the kernel verity mapping".into());
    }
    require_firmware_authentication()?;
    Ok(())
}

fn check_recovery_image_claims(
    identity: &RunningIdentity,
    args: &str,
    mount: &KernelMount,
) -> Result<()> {
    validate_image_identity(identity)?;
    let (major, minor) = mount
        .device
        .split_once(':')
        .ok_or("invalid kernel mount device number")?;
    let major = major.parse::<u32>()?;
    let minor = minor.parse::<u32>()?;
    if major == 0
        || !(mount.source == "/dev/mapper/root" || mount.source == format!("/dev/dm-{minor}"))
    {
        return Err("recovery root source is not the exact kernel mapper".into());
    }
    let values = |prefix: &str| {
        args.split_whitespace()
            .filter_map(|arg| arg.strip_prefix(prefix))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let hash = values("roothash=");
    if identity.schema_version != 1
        || identity.sequence == 0
        || identity.sequence > i64::MAX as u64
        || !crate::admin_roles::identifier(&identity.release)
        || !matches!(identity.environment.as_str(), "lab" | "production")
        || identity.architecture != "amd64"
        || identity.ubuntu != "24.04"
        || !matches!(identity.edition.as_str(), "headless" | "desktop")
        || values("luma.mode=") != ["live"]
        || values("luma.slot=") != ["live"]
        || values("root=") != ["/dev/mapper/root"]
        || hash.len() != 1
        || crate::tpm::decode::<32>(&hash[0]).is_err()
        || mount.root != "/"
        || mount.filesystem != "ext4"
        || !has_option(&mount.options, "ro")
        || !has_option(&mount.super_options, "ro")
    {
        return Err(
            "recovery requires the fixed read-only verity live UKI and immutable image identity"
                .into(),
        );
    }
    let expected=format!("root=/dev/mapper/root ro roothash={} systemd.verity_root_options=panic-on-corruption systemd.verity_root_data=/dev/disk/by-partlabel/luma-live-root systemd.verity_root_hash=/dev/disk/by-partlabel/luma-live-hash luma.mode=live luma.slot=live systemd.unit=multi-user.target console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor systemd.show_status=yes rd.shell=0 panic=10",hash[0]);
    let words: Vec<_> = args.split_whitespace().collect();
    let actual: std::collections::BTreeSet<_> = words.iter().copied().collect();
    if actual.len() != words.len() || actual != expected.split_whitespace().collect() {
        return Err(
            "recovery command line has an unknown, duplicate or alternate security/boot option"
                .into(),
        );
    }
    Ok(())
}

fn require_firmware_authentication() -> Result<()> {
    for (variable, expected) in [("SecureBoot", 1u8), ("SetupMode", 0u8)] {
        let value = fs::read(format!(
            "/sys/firmware/efi/efivars/{variable}-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        ))?;
        check_firmware_variable(&value, expected)?;
    }
    Ok(())
}

fn check_firmware_variable(value: &[u8], expected: u8) -> Result<()> {
    if value.len() != 5 || value[4] != expected || value[..4] != [6, 0, 0, 0] {
        return Err(
            "authenticated recovery requires protected firmware Secure Boot outside setup mode"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod recovery_claim_tests {
    use super::*;
    fn identity() -> RunningIdentity {
        RunningIdentity {
            schema_version: 1,
            release: "recovery-fixture".into(),
            sequence: 10,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
        }
    }
    fn mount() -> KernelMount {
        parse_kernel_mount(
            "30 20 253:0 / / ro,relatime - ext4 /dev/mapper/root ro\n",
            Path::new("/"),
        )
        .unwrap()
    }
    fn arguments() -> String {
        format!("root=/dev/mapper/root ro roothash={} systemd.verity_root_options=panic-on-corruption systemd.verity_root_data=/dev/disk/by-partlabel/luma-live-root systemd.verity_root_hash=/dev/disk/by-partlabel/luma-live-hash luma.mode=live luma.slot=live systemd.unit=multi-user.target console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor systemd.show_status=yes rd.shell=0 panic=10","1".repeat(64))
    }
    #[test]
    fn live_claims_require_closed_readonly_signed_uki_shape() {
        check_recovery_image_claims(&identity(), &arguments(), &mount()).unwrap();
        for extra in [
            " init=/bin/sh",
            " rw",
            " luma.mode=installed",
            " luma.slot=live",
            " systemd.unit=rescue.target",
            " apparmor=0",
            " rd.shell=1",
        ] {
            assert!(
                check_recovery_image_claims(&identity(), &(arguments() + extra), &mount()).is_err(),
                "{extra}"
            );
        }
        for case in 0..6 {
            let mut current = mount();
            match case {
                0 => current.options = vec!["rw".into()],
                1 => current.super_options = vec!["rw".into()],
                2 => current.root = "/subdir".into(),
                3 => current.filesystem = "overlay".into(),
                4 => current.source = "/dev/dm-1".into(),
                _ => current.device = "../other".into(),
            }
            assert!(
                check_recovery_image_claims(&identity(), &arguments(), &current).is_err(),
                "{case}"
            );
        }
        for environment in ["unknown", "", "production-override"] {
            let mut i = identity();
            i.environment = environment.into();
            assert!(check_recovery_image_claims(&i, &arguments(), &mount()).is_err());
        }
        let mut i = identity();
        i.environment = "production".into();
        check_recovery_image_claims(&i, &arguments(), &mount()).unwrap();
    }
    #[test]
    fn mount_parser_rejects_stacked_missing_malformed_and_hostile_escapes() {
        let line = "30 20 253:0 / / ro - ext4 /dev/mapper/root ro\n";
        assert!(parse_kernel_mount(&(line.to_owned() + line), Path::new("/")).is_err());
        assert!(parse_kernel_mount(line, Path::new("/missing")).is_err());
        for malformed in [
            "30 20 253:0 / / ro\n",
            "30 - ext4 device ro\n",
            "30 20 253:0 / / ro - ext4 device\n",
        ] {
            assert!(parse_kernel_mount(malformed, Path::new("/")).is_err());
        }
        assert_eq!(
            mount_word("/mounted\\040space\\134slash").unwrap(),
            "/mounted space\\slash"
        );
        for word in ["\\000", "\\777", "\\12", "\\xyz"] {
            assert!(mount_word(word).is_err());
        }
        let escaped=parse_kernel_mount("31 20 253:1 / /mounted\\040space ro,nodev,nosuid,noexec - ext4 /dev/mapper/luma-recovery-123 ro\n",Path::new("/mounted space")).unwrap();
        assert_eq!(escaped.at, Path::new("/mounted space"));
        assert_eq!(escaped.source, "/dev/mapper/luma-recovery-123");
    }
    #[test]
    fn firmware_state_requires_exact_protected_bool_variable() {
        check_firmware_variable(&[6, 0, 0, 0, 1], 1).unwrap();
        check_firmware_variable(&[6, 0, 0, 0, 0], 0).unwrap();
        for malformed in [
            &[6, 0, 0, 0, 0][..],
            &[7, 0, 0, 0, 1][..],
            &[6, 0, 0, 0, 2][..],
            &[6, 0, 0, 1][..],
            &[6, 0, 0, 0, 1, 0][..],
        ] {
            assert!(check_firmware_variable(malformed, 1).is_err());
        }
    }
    #[test]
    fn target_claims_keep_data_readonly_and_esp_separate() {
        let data = parse_kernel_mount(
            "31 20 253:1 / /data ro,nodev,nosuid,noexec - ext4 /dev/mapper/luma-recovery-1 ro\n",
            Path::new("/data"),
        )
        .unwrap();
        check_recovery_mount_claims(
            &data,
            "253:1",
            6,
            true,
            "CRYPT-LUKS2-fixture-luma-recovery-1",
        )
        .unwrap();
        for case in 0..6 {
            let mut bad=parse_kernel_mount("31 20 253:1 / /data ro,nodev,nosuid,noexec - ext4 /dev/mapper/luma-recovery-1 ro\n",Path::new("/data")).unwrap();
            match case {
                0 => bad.device = "253:2".into(),
                1 => bad.options.retain(|v| v != "noexec"),
                2 => bad.options.retain(|v| v != "nodev"),
                3 => bad.options.retain(|v| v != "nosuid"),
                4 => bad.root = "/subdir".into(),
                _ => bad.filesystem = "vfat".into(),
            }
            assert!(
                check_recovery_mount_claims(&bad, "253:1", 6, true, "CRYPT-LUKS2-fixture").is_err()
            );
        }
        assert!(
            check_recovery_mount_claims(&data, "253:1", 6, false, "CRYPT-LUKS2-fixture").is_err()
        );
        assert!(check_recovery_mount_claims(&data, "253:1", 6, true, "linear-other").is_err());
        assert!(
            check_recovery_mount_claims(&data, "253:1", 2, true, "CRYPT-LUKS2-fixture").is_err()
        );
        let esp = parse_kernel_mount(
            "32 20 8:1 / /esp rw,nodev,nosuid,noexec - vfat /dev/sda1 rw\n",
            Path::new("/esp"),
        )
        .unwrap();
        check_recovery_mount_claims(&esp, "8:1", 1, false, "").unwrap();
        assert!(check_recovery_mount_claims(&esp, "8:1", 6, false, "").is_err());
        assert!(check_recovery_mount_claims(&esp, "8:1", 1, true, "").is_err());
    }
}

/// Retained exact mount proof, minted only by this module after its own mount.
pub(crate) struct RecoveryMount {
    device: PathBuf,
    at: PathBuf,
    mount: KernelMount,
    directory: File,
    identity: (u64, u64),
    disk: crate::disk::Identity,
    partition: u8,
    mapper_uuid: Option<String>,
}
impl RecoveryMount {
    fn capture(disk: &Disk, mount: &Mount, partition: u8) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&mount.at)?;
        let metadata = directory.metadata()?;
        let mapper_uuid = if partition == 6 {
            Some(fs::read_to_string(
                Path::new("/sys/class/block")
                    .join(mount.device.file_name().ok_or("mapper name")?)
                    .join("dm/uuid"),
            )?)
        } else {
            None
        };
        let result = Self {
            device: mount.device.clone(),
            at: mount.at.clone(),
            mount: kernel_mount(&mount.at)?,
            directory,
            identity: (metadata.dev(), metadata.ino()),
            disk: disk.identity.clone(),
            partition,
            mapper_uuid,
        };
        result.recheck(&disk.identity)?;
        Ok(result)
    }
    pub(crate) fn device(&self) -> &Path {
        &self.device
    }
    pub(crate) fn at(&self) -> &Path {
        &self.at
    }
    pub(crate) fn recheck(&self, disk: &crate::disk::Identity) -> Result<()> {
        if &self.disk != disk || kernel_mount(&self.at)? != self.mount {
            return Err("target recovery mount changed".into());
        }
        let metadata = self.directory.metadata()?;
        let current = fs::symlink_metadata(&self.at)?;
        if (metadata.dev(), metadata.ino()) != self.identity
            || (current.dev(), current.ino()) != self.identity
            || !current.is_dir()
        {
            return Err("target mounted directory identity changed".into());
        }
        let metadata = fs::metadata(&self.device)?;
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_block_device()
            || device_number(&metadata) != self.mount.device
            || self.mount.root != "/"
        {
            return Err("target mount source does not bind retained block device".into());
        }
        let name = self
            .device
            .file_name()
            .ok_or("missing recovery device name")?;
        let sys = Path::new("/sys/class/block").join(name);
        let underlying = if self.partition == 6 {
            let uuid = fs::read_to_string(sys.join("dm/uuid"))?;
            if self.mapper_uuid.as_ref() != Some(&uuid) {
                return Err("target mapper UUID changed".into());
            }
            check_recovery_mount_claims(
                &self.mount,
                &device_number(&metadata),
                6,
                fs::read_to_string(sys.join("ro"))?.trim() == "1",
                uuid.trim(),
            )?;
            let slaves = fs::read_dir(sys.join("slaves"))?.collect::<std::io::Result<Vec<_>>>()?;
            if slaves.len() != 1 {
                return Err("ambiguous recovery mapper backing device".into());
            }
            Path::new("/dev").join(slaves[0].file_name())
        } else if self.partition == 1 && self.mount.filesystem == "vfat" {
            check_recovery_mount_claims(&self.mount, &device_number(&metadata), 1, false, "")?;
            self.device.clone()
        } else {
            return Err("unsupported recovery mount partition".into());
        };
        if crate::disk::parent_disk(&underlying)? != Path::new(&disk.path) {
            return Err("recovery mapping belongs to another disk".into());
        }
        let actual = fs::read_to_string(
            Path::new("/sys/class/block")
                .join(underlying.file_name().ok_or("partition name")?)
                .join("partition"),
        )?;
        if actual.trim().parse::<u8>()? != self.partition {
            return Err("recovery mapping is not the exact target partition".into());
        }
        Ok(())
    }
}

fn check_recovery_mount_claims(
    mount: &KernelMount,
    device: &str,
    partition: u8,
    readonly: bool,
    uuid: &str,
) -> Result<()> {
    if mount.device != device
        || mount.root != "/"
        || !["nodev", "nosuid", "noexec"]
            .iter()
            .all(|option| has_option(&mount.options, option))
    {
        return Err("target mount source or security flags differ from retained descriptor".into());
    }
    if partition == 6 {
        if mount.filesystem != "ext4"
            || !readonly
            || !has_option(&mount.options, "ro")
            || !has_option(&mount.super_options, "ro")
            || !uuid.starts_with("CRYPT-LUKS2-")
        {
            return Err("target data requires the exact read-only LUKS2 mapping".into());
        }
    } else if partition == 1 {
        if mount.filesystem != "vfat"
            || readonly
            || !has_option(&mount.options, "rw")
            || !has_option(&mount.super_options, "rw")
            || !uuid.is_empty()
        {
            return Err("recovery ESP requires the exact writable FAT mount".into());
        }
    } else {
        return Err("recovery cannot adopt arbitrary target partitions".into());
    }
    Ok(())
}

/// Nontransferable live recovery target. Only the exact initially unmounted
/// selected disk and this process's read-only decrypted mount can mint it.
pub(crate) struct RecoveryTarget {
    image: RecoveryImage,
    disk: Disk,
    proof: RecoveryMount,
    data: Mount,
    _crypt: Crypt,
    esp: std::cell::RefCell<Option<(RecoveryMount, Mount)>>,
    admin: PathBuf,
    registry: PathBuf,
    root_table: String,
}
impl RecoveryTarget {
    fn open(disk: Disk) -> Result<Self> {
        let image = RecoveryImage::current()?;
        let table = command("/usr/sbin/dmsetup", &["table", "root"])?;
        let hash = image
            .command_line
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix("roothash="))
            .ok_or("missing live hash")?;
        let fields: Vec<_> = table.split_whitespace().collect();
        if table.lines().count() != 1
            || fields.len() < 13
            || fields[0] != "0"
            || fields[2] != "verity"
            || fields[3] != "1"
            || fields[6] != "4096"
            || fields[7] != "4096"
            || fields[10] != "sha256"
            || fields[11] != hash
            || fields[8].parse::<u64>()? == 0
            || fields[1].parse::<u64>()?
                != fields[8]
                    .parse::<u64>()?
                    .checked_mul(8)
                    .ok_or("verity geometry overflow")?
        {
            return Err("actual live verity mapping differs from immutable UKI intent".into());
        }
        for (field, label) in [(4, "luma-live-root"), (5, "luma-live-hash")] {
            if device_number(&fs::metadata(format!("/dev/disk/by-partlabel/{label}"))?)
                != fields[field]
            {
                return Err("live verity devices do not match recovery media".into());
            }
        }
        disk.recheck()?;
        let crypt = unlock(&disk.partition(6)?, true)?;
        let staging = bundle::private_dir("target-recovery")?;
        let data = Mount::new(
            Path::new(&format!("/dev/mapper/{}", crypt.name)),
            staging.join("data"),
            "ro,noload,nodev,nosuid,noexec",
        )?;
        let proof = RecoveryMount::capture(&disk, &data, 6)?;
        disk.admit_recovery_mount(&proof)?;
        let admin = data.at.join("lib/luma-os/admin");
        let registry = data.at.join("lib/luma-os/principals/registry.json");
        let result = Self {
            image,
            disk,
            proof,
            data,
            _crypt: crypt,
            esp: std::cell::RefCell::new(None),
            admin,
            registry,
            root_table: table,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn image(&self) -> &RecoveryImage {
        &self.image
    }
    pub(crate) fn admin_directory(&self) -> &Path {
        &self.admin
    }
    pub(crate) fn registry_path(&self) -> &Path {
        &self.registry
    }
    pub(crate) fn data_root(&self) -> &Path {
        &self.data.at
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.image.recheck()?;
        if command("/usr/sbin/dmsetup", &["table", "root"])? != self.root_table {
            return Err("actual recovery media verity mapping changed".into());
        }
        self.proof.recheck(&self.disk.identity)?;
        if let Some((proof, _)) = &*self.esp.borrow() {
            proof.recheck(&self.disk.identity)?;
        }
        self.disk.recheck()
    }
    fn mount_esp(&self) -> Result<()> {
        self.recheck()?;
        if self.esp.borrow().is_some() {
            return Err("recovery ESP already mounted".into());
        }
        let staging = bundle::private_dir("target-esp")?;
        let mount = Mount::new(
            &self.disk.partition(1)?,
            staging.join("esp"),
            "nodev,nosuid,noexec,umask=0077",
        )?;
        let proof = RecoveryMount::capture(&self.disk, &mount, 1)?;
        self.disk.admit_recovery_mount(&proof)?;
        *self.esp.borrow_mut() = Some((proof, mount));
        self.recheck()
    }
}

fn install_slots(disk: &Disk, bundle: &VerifiedBundle, slots: &[char]) -> Result<()> {
    install_slots_guarded(disk, bundle, slots, &mut || Ok(()))
}

fn install_slots_guarded(
    disk: &Disk,
    bundle: &VerifiedBundle,
    slots: &[char],
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    for slot in slots {
        println!("Writing and verifying system slot {slot}...");
        let (data, hash) = match slot {
            'a' => (2, 3),
            'b' => (4, 5),
            _ => return Err("invalid slot".into()),
        };
        disk.write_artifact_guarded(
            &bundle.path("root.ext4")?,
            data,
            bundle.manifest.root_bytes,
            guard,
        )?;
        disk.write_artifact_guarded(
            &bundle.path("root.verity")?,
            hash,
            bundle.manifest.hash_bytes,
            guard,
        )?;
        command(
            "/usr/sbin/veritysetup",
            &[
                "verify",
                path(&disk.partition(data)?)?,
                path(&disk.partition(hash)?)?,
                &bundle.manifest.root_hash,
            ],
        )?;
        guard()?;
    }
    Ok(())
}

fn publish_efi_guarded(
    esp: &Path,
    bundle: &VerifiedBundle,
    slots: &[char],
    trial: char,
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    publish_efi_guarded_mode(esp, bundle, slots, trial, true, guard)
}

fn publish_efi_guarded_mode(
    esp: &Path,
    bundle: &VerifiedBundle,
    slots: &[char],
    trial: char,
    counted: bool,
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    guard()?;
    let linux = esp.join("EFI/Linux");
    fs::create_dir_all(&linux)?;
    let loader = esp.join("EFI/BOOT");
    fs::create_dir_all(&loader)?;
    if !loader.join("BOOTX64.EFI").exists() {
        let bytes = fs::read(bundle.path("bootloader.efi")?)?;
        guard()?;
        write_atomic_guarded(&loader.join("BOOTX64.EFI"), &bytes, 0o600, guard)?;
        guard()?;
    }
    for slot in slots {
        guard()?;
        let source = bundle.path(&format!("slot-{slot}.efi"))?;
        let suffix = if counted && *slot == trial { "+3" } else { "" };
        let name = format!("luma-{slot}-{:020}{suffix}.efi", bundle.manifest.sequence);
        let bytes = fs::read(source)?;
        guard()?;
        write_atomic_guarded(&linux.join(&name), &bytes, 0o600, guard)?;
        guard()?;
        // A reused slot no longer contains the old release's root. Remove only
        // our obsolete entries for that exact slot, after publishing its UKI.
        for entry in fs::read_dir(&linux)? {
            let entry = entry?;
            let old = entry.file_name();
            let old = old.to_string_lossy();
            if old != name && old.starts_with(&format!("luma-{slot}-")) && old.ends_with(".efi") {
                if !entry.file_type()?.is_file() {
                    return Err("unexpected boot entry type".into());
                }
                guard()?;
                fs::remove_file(entry.path())?;
                guard()?;
            }
        }
    }
    fs::create_dir_all(esp.join("loader"))?;
    // Firmware receives no automatic key enrollment or boot-order mutation.
    let config = loader_config(trial, bundle.manifest.sequence, counted);
    guard()?;
    write_atomic_guarded(
        &esp.join("loader/loader.conf"),
        config.as_bytes(),
        0o600,
        guard,
    )?;
    guard()?;
    File::open(esp)?.sync_all()?;
    guard()?;
    Ok(())
}

fn loader_config(slot: char, sequence: u64, trial: bool) -> String {
    // systemd-boot 255's explicit default can override assessment ordering.
    // Match only a non-exhausted trial. At zero, no default matches and the
    // loader selects a non-exhausted fallback. After acknowledgement use the
    // exact counter-free filename, never a glob which also matches +0-N.
    let suffix = if trial { "+[1-3]*" } else { "" };
    format!("default luma-{slot}-{sequence:020}{suffix}.efi\ntimeout 5\neditor no\nauto-entries no\nauto-firmware yes\n")
}

#[cfg(test)]
mod boot_selection_tests {
    use super::*;
    extern "C" {
        fn fnmatch(
            pattern: *const libc::c_char,
            name: *const libc::c_char,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
    #[test]
    fn default_patterns_never_force_exhausted_entries() {
        for trial in [true, false] {
            let config = loader_config('a', 1, trial);
            let pattern = std::ffi::CString::new(
                config
                    .lines()
                    .next()
                    .unwrap()
                    .strip_prefix("default ")
                    .unwrap(),
            )
            .unwrap();
            for (suffix, expected) in [
                ("+3", trial),
                ("+2-1", trial),
                ("+1-2", trial),
                ("+0-3", false),
                ("", !trial),
            ] {
                let name = std::ffi::CString::new(format!("luma-a-{:020}{suffix}.efi", 1)).unwrap();
                assert_eq!(
                    unsafe { fnmatch(pattern.as_ptr(), name.as_ptr(), 0) } == 0,
                    expected
                );
            }
        }
    }
}

fn user_name(label: &str) -> Result<String> {
    println!("{label} login name:");
    let name = console_line(false)?;
    if name.is_empty()
        || name.len() > 24
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || !name.as_bytes()[0].is_ascii_lowercase()
        || ["root", "nobody", "luma"].contains(&name.as_str())
    {
        return Err("invalid login name".into());
    }
    if fs::read_to_string("/etc/passwd")?
        .lines()
        .any(|line| line.starts_with(&format!("{name}:")))
    {
        return Err("login name is reserved by an existing system identity".into());
    }
    Ok(name)
}

fn create_identity(
    var: &Path,
    user: &str,
    admin: &str,
    user_password: &str,
    admin_password: &str,
) -> Result<()> {
    let identity = var.join("lib/luma-os/identity");
    fs::create_dir_all(&identity)?;
    for entry in fs::read_to_string(identity.join("passwd"))?.lines() {
        let fields: Vec<_> = entry.split(':').collect();
        if fields.len() != 7
            || fields[0] == user
            || fields[0] == admin
            || matches!(fields[2], "1000" | "1001")
        {
            return Err("base image contains a conflicting account identity".into());
        }
    }
    for (name, uid, password) in [(user, 1000, user_password), (admin, 1001, admin_password)] {
        let hashed = with_input("/usr/bin/openssl", &["passwd", "-6", "-stdin"], password)?;
        for (file, entry) in [
            (
                "passwd",
                format!("{name}:x:{uid}:{uid}:Luma local user:/home/{name}:/bin/bash\n"),
            ),
            (
                "shadow",
                format!("{name}:{}:20000:0:99999:7:::\n", hashed.trim()),
            ),
            ("group", format!("{name}:x:{uid}:\n")),
            ("gshadow", format!("{name}:!::\n")),
        ] {
            let mut f = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(identity.join(file))?;
            f.write_all(entry.as_bytes())?;
            f.sync_all()?;
        }
        let home = var.join("home").join(name);
        fs::create_dir_all(&home)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        command("/usr/bin/chown", &[&format!("{uid}:{uid}"), path(&home)?])?;
    }
    fs::create_dir_all(var.join("lib/luma-os/sudoers"))?;
    write_atomic(
        &var.join("lib/luma-os/sudoers/admin"),
        format!("{admin} ALL=(ALL:ALL) ALL\n").as_bytes(),
        0o440,
    )?;
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    write_atomic(
        &identity.join("machine-id"),
        format!("{}\n", bundle::hex(&random)).as_bytes(),
        0o444,
    )?;
    Ok(())
}

fn copy_network_profiles(source: &Path, destination: &Path) -> Result<()> {
    if !source.exists() {
        return Ok(());
    }
    let root = fs::symlink_metadata(source)?;
    if !root.is_dir() || root.uid() != 0 || root.mode() & 0o077 != 0 {
        return Err("live network profile directory is not private".into());
    }
    fs::create_dir_all(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    if entries.len() > 32 {
        return Err("too many network profiles".into());
    }
    for entry in entries {
        if !entry
            .file_name()
            .to_string_lossy()
            .ends_with(".nmconnection")
        {
            continue;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.len() > 65536
        {
            return Err("network profile is not a private bounded regular file".into());
        }
        let mut bytes = Vec::new();
        (&mut file).take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("network profile changed during capture".into());
        }
        write_atomic(&destination.join(entry.file_name()), &bytes, 0o600)?;
    }
    Ok(())
}

pub(crate) fn ensure_model_identities(var: &Path) -> Result<()> {
    // Upgrade older manual-only data volumes without replacing user identities.
    // Every step is idempotent; conflicting names, IDs or group members fail closed.
    let identity = var.join("lib/luma-os/identity");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(identity.join("migration.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("identity migration is already running".into());
    }
    for (uid, name) in [(989, "luma-model"), (988, "luma-fetch")] {
        for (file, entry, number) in [
            ("group", format!("{name}:x:{uid}:"), Some(uid)),
            ("gshadow", format!("{name}:!::"), None),
            (
                "passwd",
                format!("{name}:x:{uid}:{uid}::/nonexistent:/usr/sbin/nologin"),
                Some(uid),
            ),
            ("shadow", format!("{name}:!:20000:0:99999:7:::"), None),
        ] {
            let at = identity.join(file);
            let mut input = String::new();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&at)?
                .take(1024 * 1024 + 1)
                .read_to_string(&mut input)?;
            if input.len() > 1024 * 1024 {
                return Err("identity store exceeds bound".into());
            }
            let matches: Vec<_> = input
                .lines()
                .filter(|line| {
                    let fields: Vec<_> = line.split(':').collect();
                    fields.first() == Some(&name)
                        || number.map_or(false, |n| {
                            fields.get(2).and_then(|s| s.parse::<u32>().ok()) == Some(n)
                        })
                })
                .collect();
            if !matches.is_empty() {
                let okay = matches.len() == 1
                    && if file == "shadow" {
                        let fields: Vec<_> = matches[0].split(':').collect();
                        fields.len() == 9
                            && fields[0] == name
                            && matches!(fields[1], "!" | "!!" | "*")
                    } else {
                        matches[0] == entry
                    };
                if !okay {
                    return Err("model service identity conflicts with existing data; manual reconciliation required".into());
                }
            } else {
                if !input.ends_with('\n') {
                    return Err("identity store is not line terminated".into());
                }
                input.push_str(&entry);
                input.push('\n');
                write_atomic(
                    &at,
                    input.as_bytes(),
                    if matches!(file, "shadow" | "gshadow") {
                        0o600
                    } else {
                        0o644
                    },
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod identity_migration_tests {
    use super::*;
    #[test]
    fn network_profiles_copy_private_bytes_and_refuse_public_or_symlink_files() {
        // The native test container runs as root, matching installer ownership.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = std::env::temp_dir().join(format!("luma-network-{}", std::process::id()));
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let profile = source.join("private.nmconnection");
        write_atomic(&profile, b"[connection]\nid=fixture\n", 0o600).unwrap();
        copy_network_profiles(&source, &destination).unwrap();
        assert_eq!(
            fs::read(destination.join("private.nmconnection")).unwrap(),
            b"[connection]\nid=fixture\n"
        );
        assert_eq!(
            fs::metadata(destination.join("private.nmconnection"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(copy_network_profiles(&source, &destination).is_err());
        fs::remove_file(&profile).unwrap();
        std::os::unix::fs::symlink("missing", &profile).unwrap();
        assert!(copy_network_profiles(&source, &destination).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("luma-identity-{label}-{}", std::process::id()));
        let identity = root.join("lib/luma-os/identity");
        fs::create_dir_all(&identity).unwrap();
        for (file, text) in [
            ("passwd", "root:x:0:0:root:/root:/bin/bash\n"),
            ("shadow", "root:!:20000:0:99999:7:::\n"),
            ("group", "root:x:0:\n"),
            ("gshadow", "root:!::\n"),
        ] {
            fs::write(identity.join(file), text).unwrap();
        }
        root
    }
    #[test]
    fn service_identity_migration_is_idempotent_and_preserves_accounts() {
        let root = fixture("idempotent");
        ensure_model_identities(&root).unwrap();
        let before = fs::read(root.join("lib/luma-os/identity/passwd")).unwrap();
        ensure_model_identities(&root).unwrap();
        assert_eq!(
            before,
            fs::read(root.join("lib/luma-os/identity/passwd")).unwrap()
        );
        assert!(String::from_utf8(before)
            .unwrap()
            .starts_with("root:x:0:0:"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn service_identity_migration_refuses_existing_uid_and_group_members() {
        for (label, line) in [
            ("conflict", "another:x:989:"),
            ("member", "luma-model:x:989:unexpected"),
        ] {
            let root = fixture(label);
            fs::write(
                root.join("lib/luma-os/identity/group"),
                format!("root:x:0:\n{line}\n"),
            )
            .unwrap();
            assert!(ensure_model_identities(&root).is_err());
            assert_eq!(
                fs::read_to_string(root.join("lib/luma-os/identity/passwd")).unwrap(),
                "root:x:0:0:root:/root:/bin/bash\n"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}

pub fn install(selection: &str, source: &Path, model_id: Option<&str>) -> Result<()> {
    install_mode(selection, source, model_id, false)
}
pub(crate) fn install_staged(selection: &str, source: &Path, model_id: &str) -> Result<()> {
    install_mode(selection, source, Some(model_id), true)
}
fn install_mode(
    selection: &str,
    source: &Path,
    model_id: Option<&str>,
    stage_only: bool,
) -> Result<()> {
    require_live()?;
    // Local TPM2 is the selected installation profile. This is read-only,
    // before target admission or credentials, and never selects a fallback.
    let admin_admission = crate::tpm::installation_admission()?;
    let disk = Disk::open(selection, false)?;
    let original_memory = fs::read_to_string("/proc/meminfo")?;
    let original_total = crate::model::memory(&original_memory, "MemTotal")?;
    let original_available = crate::model::memory(&original_memory, "MemAvailable")?;
    // Observe available RAM before the live installer's verified bundle
    // snapshot temporarily occupies memory-backed staging. Recheck again
    // after releasing that snapshot and before acquiring any model bytes.
    let preview = bundle::initial_preview(source)?;
    let preview_manifest: Manifest = serde_json::from_slice(&preview)?;
    let inert = preview_manifest.environment == "production" || stage_only;
    let model = if inert {
        println!("Image will be installed in manual mode. Selected model bytes may be staged inertly; normal serving remains disabled pending genuine activation and qualification.");
        None
    } else {
        crate::model::choose(model_id, disk.identity.bytes)?
    };
    let verified = bundle::verify_initial(source)?;
    if verified.manifest_bytes != preview {
        return Err("installation manifest changed after model/resource planning".into());
    }
    let roots_mib = verified
        .manifest
        .root_bytes
        .checked_add(MIB - 1)
        .ok_or("size overflow")?
        / MIB;
    let hashes_mib = verified
        .manifest
        .hash_bytes
        .checked_add(MIB - 1)
        .ok_or("size overflow")?
        / MIB;
    let minimum = (2 * roots_mib + 2 * hashes_mib + 1024 + 16384 + 16)
        .checked_mul(MIB)
        .ok_or("size overflow")?;
    if disk.identity.bytes < minimum {
        return Err(format!("disk requires at least {minimum} bytes").into());
    }
    let staged_model = if inert {
        let metadata_directory = bundle::private_dir("model-preview")?;
        let metadata_root = Mount::new(
            &verified.path("root.ext4")?,
            metadata_directory.join("root"),
            "loop,ro,nodev,nosuid,noexec",
        )?;
        let free = disk
            .identity
            .bytes
            .checked_sub(
                (2 * roots_mib + 2 * hashes_mib + 1024 + 32)
                    .checked_mul(MIB)
                    .ok_or("installer data geometry overflow")?,
            )
            .ok_or("installer data geometry underflow")?;
        let planned = crate::model::installer_staging::select(
            &metadata_root.at,
            &verified.manifest,
            model_id,
            original_total,
            original_available,
            free,
        )?;
        drop(metadata_root);
        planned
    } else {
        None
    };
    println!("Release {}: EFI 1 GiB; two {} MiB roots and {} MiB hash partitions; remaining space encrypted.",verified.manifest.release,roots_mib,hashes_mib);
    println!("Admin profile: local-tpm2. This install creates separate Unix accounts; explicit checkpoint enrollment, product Admin bootstrap and principal adoption remain required after boot.");
    disk.confirm("ERASE")?;
    let user = user_name("First user")?;
    let admin = user_name("Separate administrator")?;
    if user == admin {
        return Err("user and administrator must be separate identities".into());
    }
    let user_password = password("User password")?;
    let admin_password = password("Administrator password")?;
    let data_secret = password("Data unlock passphrase")?;
    let recovery = password("Independent recovery passphrase (retain off this disk)")?;
    if recovery == data_secret {
        return Err("recovery credential must be independent".into());
    }
    let admin_recovery = crate::admin_recovery::Credential::generate_confirmed()?;
    admin_admission.recheck()?;
    disk.recheck()?;
    let size_a = format!("2:0:+{roots_mib}M");
    let size_ha = format!("3:0:+{hashes_mib}M");
    let size_b = format!("4:0:+{roots_mib}M");
    let size_hb = format!("5:0:+{hashes_mib}M");
    command(
        "/usr/sbin/sgdisk",
        &[
            "--zap-all",
            "--clear",
            "--new",
            "1:0:+1024M",
            "--typecode",
            "1:ef00",
            "--change-name",
            "1:LUMA-ESP",
            "--new",
            &size_a,
            "--change-name",
            "2:luma-root-a",
            "--new",
            &size_ha,
            "--change-name",
            "3:luma-hash-a",
            "--new",
            &size_b,
            "--change-name",
            "4:luma-root-b",
            "--new",
            &size_hb,
            "--change-name",
            "5:luma-hash-b",
            "--new",
            "6:0:0",
            "--change-name",
            "6:luma-data",
            &disk.identity.path,
        ],
    )?;
    disk.reread_partitions()?;
    install_slots(&disk, &verified, &['a', 'b'])?;
    command(
        "/usr/sbin/mkfs.vfat",
        &["-F", "32", "-n", "LUMAESP", path(&disk.partition(1)?)?],
    )?;
    let data_device = disk.partition(6)?;
    println!("Creating encrypted data and independent recovery key slot...");
    with_input(
        "/usr/sbin/cryptsetup",
        &[
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--pbkdf",
            "argon2id",
            "--key-file",
            "-",
            path(&data_device)?,
        ],
        &data_secret,
    )?;
    let key = secret_fd(&data_secret)?;
    let recovery_key = secret_fd(&recovery)?;
    command(
        "/usr/sbin/cryptsetup",
        &[
            "luksAddKey",
            "--key-file",
            &format!("/proc/self/fd/{}", key.as_raw_fd()),
            path(&data_device)?,
            &format!("/proc/self/fd/{}", recovery_key.as_raw_fd()),
        ],
    )?;
    with_input(
        "/usr/sbin/cryptsetup",
        &[
            "open",
            "--test-passphrase",
            "--key-file",
            "-",
            path(&data_device)?,
        ],
        &recovery,
    )?;
    let name = format!("luma-install-{}", std::process::id());
    with_input(
        "/usr/sbin/cryptsetup",
        &["open", "--key-file", "-", path(&data_device)?, &name],
        &data_secret,
    )?;
    let _crypt = Crypt { name: name.clone() };
    let mapper = PathBuf::from(format!("/dev/mapper/{name}"));
    command(
        "/usr/sbin/mkfs.ext4",
        &["-F", "-L", "luma-data", path(&mapper)?],
    )?;
    let staging = bundle::private_dir("install")?;
    let data = Mount::new(&mapper, staging.join("data"), "nodev,nosuid")?;
    let data_proof = InstallerMount::capture(&disk, &data, 6)?;
    disk.admit_installer_mount(&data_proof)?;
    println!("Initializing encrypted identity and application state...");
    let root = Mount::new(
        &disk.partition(2)?,
        staging.join("root"),
        "ro,nodev,nosuid,noexec",
    )?;
    let root_proof = InstallerMount::capture(&disk, &root, 2)?;
    disk.admit_installer_mount(&root_proof)?;
    if let Some(plan) = &staged_model {
        crate::model::installer_staging::check_target(&root.at, &verified.manifest, plan)?;
    }
    command(
        "/usr/bin/cp",
        &[
            "-a",
            &format!("{}/usr/share/luma-os/var-template/.", path(&root.at)?),
            path(&data.at)?,
        ],
    )?;
    create_identity(&data.at, &user, &admin, &user_password, &admin_password)?;
    crate::principal::initialize_with_recovery(
        &data.at.join("lib/luma-os/principals"),
        &[(&user, 1000), (&admin, 1001)],
        &admin_recovery,
    )?;
    drop(admin_recovery);
    crate::broker_effects::initialize(&data.at.join("lib/luma-broker"))?;
    crate::resources::initialize(&data.at.join("lib/luma-broker/resources"))?;
    crate::artifacts::initialize(
        &data.at.join("lib/luma-os/artifacts"),
        &crate::principal::installation_at(&data.at.join("lib/luma-os/principals/registry.json"))?,
    )?;
    crate::artifact_catalog::initialize(
        &data.at.join("lib/luma-os/artifact-catalog"),
        &crate::principal::installation_at(&data.at.join("lib/luma-os/principals/registry.json"))?,
    )?;
    crate::workflow_runs::initialize(
        &data.at.join("lib/luma-os/workflow-runs"),
        &crate::principal::installation_at(&data.at.join("lib/luma-os/principals/registry.json"))?,
    )?;
    crate::workflow_runs::history::initialize_at(
        &data.at.join("lib/luma-os/workflow-history"),
        &crate::principal::installation_at(&data.at.join("lib/luma-os/principals/registry.json"))?,
    )?;
    // The encrypted filesystem is freshly formatted and populated only from
    // the verified image template. Provision fixed empty owner-domain roots;
    // never create these as a fallback while loading an established authority.
    let state = crate::scoped_read::open_directory(&data.at.join("lib/luma-os"))?;
    for name in [
        "artifact-catalog-domains",
        "workflow-invoice-domains",
        "workflow-dags",
    ] {
        crate::artifacts::mkdir_at(&state, name)?.sync_all()?;
    }
    for (name, mode) in [("policy-decisions", 0o700), ("workflow-inputs", 0o711)] {
        let directory =
            crate::artifacts::open_at(&state, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != mode
            || metadata.dev() != state.metadata()?.dev()
        {
            return Err("invalid product namespace in the verified installation template".into());
        }
        directory.sync_all()?;
    }
    state.sync_all()?;
    write_atomic(
        &data.at.join("lib/luma-os/admin-install-intent.json"),
        &serde_json::to_vec(&admin_admission.intent(&admin))?,
        0o600,
    )?;
    copy_network_profiles(
        Path::new("/var/lib/NetworkManager/system-connections"),
        &data.at.join("lib/NetworkManager/system-connections"),
    )?;
    write_atomic(
        &data.at.join("lib/luma-os/installed.json"),
        &serde_json::to_vec(&verified.manifest)?,
        0o600,
    )?;
    if let Some(trust) = &verified.inert_trust {
        let staged = crate::release_trust::StagedRelease {
            schema_version: 1,
            trust: serde_json::from_slice(trust)?,
            manifest_json: String::from_utf8(verified.manifest_bytes.clone())?,
            signature_hex: bundle::hex(&verified.signature),
        };
        write_atomic(
            &data.at.join("lib/luma-os/staged-release.json"),
            &serde_json::to_vec(&staged)?,
            0o600,
        )?;
    }
    let esp = Mount::new(
        &disk.partition(1)?,
        staging.join("esp"),
        "nodev,nosuid,noexec,umask=0077",
    )?;
    let esp_proof = InstallerMount::capture(&disk, &esp, 1)?;
    disk.admit_installer_mount(&esp_proof)?;
    publish_efi_guarded_mode(
        &esp.at,
        &verified,
        &['a', 'b'],
        'a',
        verified.manifest.environment != "production",
        &mut || Ok(()),
    )?;
    let trust_instruction = certificate_enrollment_instruction(&verified.manifest.environment)?;
    command("/usr/bin/sync", &[])?;
    let target_release = verified.manifest.clone();
    drop(verified);
    if let Some(plan) = &staged_model {
        if let Err(error) = crate::model::installer_staging::run(
            &root_proof,
            &data_proof,
            &disk,
            &target_release,
            plan,
        ) {
            eprintln!("OS remains installed in manual mode. Inert model staging is incomplete; preserve installer-model-staging receipts and uncertain partials. No normal model has been enabled.");
            return Err(error);
        }
    }
    drop(root_proof);
    drop(root);
    if let Some(profile) = model {
        if let Err(error) = crate::model::provision(&data.at, &profile) {
            eprintln!("OS installation is bootable in manual mode, but the selected model was NOT installed. After boot and network setup, retry: sudo luma-platform model-install {}", profile.id);
            return Err(error);
        }
    }
    println!("ADMIN ENROLLMENT REQUIRED: local TPM2 hardware admission passed. Use explicit existing-owner Admin checkpoint enrollment, bootstrap and principal adoption after boot; the separate Unix administrator is not automatically product Admin.");
    println!("RESOURCE CHECKPOINT REQUIRED before installed broker admission: after Admin/UTC setup, use reviewed resource-checkpoint prepare/enroll ceremonies with the broker/model/acquisition masked and drained. This installer does not mutate existing TPM ownership or provision a resource NV handle unattended.");
    println!("Offline Admin recovery verifier installed but NOT recovery authority until explicit TPM checkpoint enrollment, product bootstrap and principal adoption commit. Retain the confirmed Admin recovery credential separately from the disk recovery passphrase.");
    println!("INSTALLATION COMPLETE: remove recovery media and boot the selected disk. {trust_instruction} Keep the independent recovery passphrase offline.");
    Ok(())
}

fn certificate_enrollment_instruction(environment: &str) -> Result<&'static str> {
    match environment {
        "lab" => Ok("Secure Boot requires the laboratory certificate to be enrolled by the operator; it does not establish production qualification."),
        "production" => Ok("Secure Boot requires the independently approved production certificate to be trusted by firmware. Preserve existing platform keys; this installer performs no certificate enrollment or firmware mutation. The staged release remains inert until explicit Admin/TPM/protected-UTC activation."),
        _ => Err("unsupported certificate environment".into()),
    }
}

fn validate_laboratory_repair(current: &Manifest, candidate: &Manifest) -> Result<()> {
    bundle::validate_manifest(current)?;
    bundle::validate_manifest(candidate)?;
    if current.environment != "lab"
        || candidate.environment != "lab"
        || candidate.sequence < current.sequence
        || current.edition != candidate.edition
        || current.root_bytes != candidate.root_bytes
        || current.hash_bytes != candidate.hash_bytes
    {
        return Err("laboratory repair cannot lower target release sequence or change target environment/geometry/edition".into());
    }
    Ok(())
}

pub(crate) fn require_installed() -> Result<()> {
    running_slot()?;
    if live()? {
        return Err("operation requires an installed Luma system".into());
    }
    Ok(())
}

fn running_slot() -> Result<char> {
    let args = cmdline()?;
    match args
        .split_whitespace()
        .find_map(|v| v.strip_prefix("luma.slot="))
    {
        Some("a") => Ok('a'),
        Some("b") => Ok('b'),
        _ => Err("running slot is not an installed A/B system".into()),
    }
}

fn running_disk() -> Result<Disk> {
    let slot = running_slot()?;
    let partition = active_root_partition(slot)?;
    let target = crate::disk::parent_disk(&partition)?;
    for entry in fs::read_dir("/dev/disk/by-id")? {
        let entry = entry?;
        if fs::canonicalize(entry.path()).ok().as_ref() == Some(&target) {
            return Disk::open(path(&entry.path())?, true);
        }
    }
    Err("running disk has no stable by-id identity".into())
}

fn active_root_partition(slot: char) -> Result<PathBuf> {
    let partition = fs::canonicalize(format!("/dev/disk/by-partlabel/luma-root-{slot}"))?;
    let inventory: serde_json::Value = serde_json::from_str(&command(
        "/usr/bin/lsblk",
        &["--json", "--list", "--output", "PATH,PARTLABEL"],
    )?)?;
    let devices = inventory["blockdevices"]
        .as_array()
        .ok_or("missing partition inventory")?;
    let label = format!("luma-root-{slot}");
    if devices
        .iter()
        .filter(|d| d["partlabel"].as_str() == Some(label.as_str()))
        .count()
        != 1
    {
        return Err("ambiguous root labels; disconnect other Luma system disks".into());
    }
    let mapper = fs::canonicalize("/dev/mapper/root")?;
    let slaves = Path::new("/sys/class/block")
        .join(mapper.file_name().ok_or("root mapper name missing")?)
        .join("slaves");
    let name = partition.file_name().ok_or("root partition name missing")?;
    if !slaves.join(name).exists() {
        return Err("selected root partition is not the active verity mapping".into());
    }
    Ok(partition)
}

fn verify_esp(disk: &Disk) -> Result<()> {
    let source = command(
        "/usr/bin/findmnt",
        &["--mountpoint", "/efi", "--noheadings", "--output", "SOURCE"],
    )?;
    if fs::canonicalize(source.trim())? != fs::canonicalize(disk.partition(1)?)? {
        return Err("mounted EFI partition does not belong to the active system disk".into());
    }
    Ok(())
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RunningIdentity {
    schema_version: u32,
    release: String,
    sequence: u64,
    environment: String,
    architecture: String,
    ubuntu: String,
    edition: String,
}

#[cfg(test)]
mod measured_release_tests {
    use super::*;
    #[test]
    fn laboratory_repair_never_crosses_a_production_boundary_or_lowers_geometry() {
        let (_, current, _, _) = fixture();
        validate_laboratory_repair(&current, &current).unwrap();
        let mut newer = current.clone();
        newer.sequence += 1;
        validate_laboratory_repair(&current, &newer).unwrap();
        for fault in 0..5 {
            let mut candidate = current.clone();
            match fault {
                0 => candidate.environment = "production".into(),
                1 => candidate.sequence -= 1,
                2 => candidate.edition = "desktop".into(),
                3 => {
                    candidate.root_bytes += 4096;
                    candidate
                        .artifacts
                        .iter_mut()
                        .find(|a| a.name == "root.ext4")
                        .unwrap()
                        .bytes += 4096;
                }
                _ => {
                    candidate.hash_bytes += 4096;
                    candidate
                        .artifacts
                        .iter_mut()
                        .find(|a| a.name == "root.verity")
                        .unwrap()
                        .bytes += 4096;
                }
            }
            assert!(validate_laboratory_repair(&current, &candidate).is_err());
        }
        let mut production = current.clone();
        production.environment = "production".into();
        assert!(validate_laboratory_repair(&production, &current).is_err());
        assert!(validate_laboratory_repair(&production, &production).is_err());
    }
    #[test]
    fn installation_certificate_guidance_preserves_environment_and_custody() {
        let lab = certificate_enrollment_instruction("lab").unwrap();
        let production = certificate_enrollment_instruction("production").unwrap();
        assert!(lab.contains("laboratory certificate"));
        assert!(lab.contains("does not establish production qualification"));
        assert!(production.contains("independently approved production certificate"));
        assert!(production.contains("no certificate enrollment or firmware mutation"));
        assert!(production.contains("remains inert"));
        assert!(!production.contains("laboratory"));
        assert!(certificate_enrollment_instruction("unknown").is_err());
    }
    #[test]
    fn static_laboratory_signature_fallback_requires_exact_immutable_lab_environment() {
        require_laboratory_environment("lab").unwrap();
        for environment in ["production", "", "unknown", "LAB", "lab-override"] {
            assert!(require_laboratory_environment(environment).is_err());
        }
    }
    fn fixture() -> (RunningIdentity, Manifest, String, String) {
        let root_bytes = 512 * 1024 * 1024;
        let hash_bytes = 8 * 1024 * 1024;
        let manifest = Manifest {
            schema_version: 1,
            release: "test-release".into(),
            sequence: 10,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
            root_hash: "1".repeat(64),
            root_bytes,
            hash_bytes,
            artifacts: [
                "root.ext4",
                "root.verity",
                "slot-a.efi",
                "slot-b.efi",
                "bootloader.efi",
                "secureboot.cer",
            ]
            .iter()
            .map(|name| bundle::Artifact {
                name: (*name).into(),
                bytes: match *name {
                    "root.ext4" => root_bytes,
                    "root.verity" => hash_bytes,
                    _ => 4096,
                },
                sha256: "2".repeat(64),
            })
            .collect(),
        };
        let identity = RunningIdentity {
            schema_version: 1,
            release: manifest.release.clone(),
            sequence: 10,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
        };
        let args = format!(
            "root=/dev/mapper/root ro luma.slot=a luma.mode=installed roothash={}",
            manifest.root_hash
        );
        let table = format!(
            "0 {} verity 1 8:2 8:3 4096 4096 {} 1 sha256 {} -\n",
            root_bytes / 512,
            root_bytes / 4096,
            manifest.root_hash
        );
        (identity, manifest, args, table)
    }
    #[test]
    fn exact_running_metadata_signed_uki_and_actual_verity_geometry_match() {
        let (identity, manifest, args, table) = fixture();
        check_identity(&identity, &manifest, &args, &table).unwrap();
    }
    #[test]
    fn reused_release_id_does_not_acknowledge_different_sequence_edition_or_root() {
        let (mut identity, manifest, args, table) = fixture();
        identity.sequence += 1;
        assert!(check_identity(&identity, &manifest, &args, &table).is_err());
        identity.sequence -= 1;
        identity.edition = "desktop".into();
        assert!(check_identity(&identity, &manifest, &args, &table).is_err());
        let (identity, manifest, args, table) = fixture();
        assert!(check_identity(
            &identity,
            &manifest,
            &args,
            &table.replace(&manifest.root_hash, &"3".repeat(64))
        )
        .is_err());
    }
    #[test]
    fn ambiguous_kernel_hash_mode_or_slot_and_verity_dimensions_refuse() {
        let (identity, manifest, args, table) = fixture();
        for extra in [
            format!(" roothash={}", manifest.root_hash),
            " luma.slot=b".into(),
            " luma.mode=live".into(),
        ] {
            assert!(
                check_identity(&identity, &manifest, &(args.clone() + &extra), &table).is_err()
            );
        }
        for changed in [
            table.replace("4096 4096", "8192 4096"),
            table.replace("sha256", "sha512"),
            table.replace("verity 1", "verity 0"),
            format!("{table}{table}"),
        ] {
            assert!(check_identity(&identity, &manifest, &args, &changed).is_err());
        }
    }
    #[test]
    fn missing_metadata_or_unknown_fields_cannot_be_migrated_implicitly() {
        let (identity, _, _, _) = fixture();
        let bytes = serde_json::to_string(&identity).unwrap();
        assert!(serde_json::from_str::<RunningIdentity>(&bytes.replacen(
            "{",
            "{\"bootstrap_override\":true,",
            1
        ))
        .is_err());
        assert!(serde_json::from_str::<RunningIdentity>("{}").is_err());
    }
}

fn check_governance_identity(
    identity: &RunningIdentity,
    manifest: &Manifest,
    args: &str,
) -> Result<()> {
    bundle::validate_manifest(manifest)?;
    if identity.schema_version != 1
        || identity.release != manifest.release
        || identity.sequence != manifest.sequence
        || identity.environment != manifest.environment
        || identity.architecture != manifest.architecture
        || identity.ubuntu != manifest.ubuntu
        || identity.edition != manifest.edition
    {
        return Err("running immutable image identity differs from the signed release".into());
    }
    let roots: Vec<_> = args
        .split_whitespace()
        .filter_map(|v| v.strip_prefix("roothash="))
        .collect();
    let slots: Vec<_> = args
        .split_whitespace()
        .filter_map(|v| v.strip_prefix("luma.slot="))
        .collect();
    let modes: Vec<_> = args
        .split_whitespace()
        .filter_map(|v| v.strip_prefix("luma.mode="))
        .collect();
    if roots != [manifest.root_hash.as_str()]
        || modes != ["installed"]
        || slots.len() != 1
        || !matches!(slots[0], "a" | "b")
    {
        return Err("signed UKI release hash/mode/slot differs from release intent".into());
    }
    Ok(())
}

fn check_identity(
    identity: &RunningIdentity,
    manifest: &Manifest,
    args: &str,
    table: &str,
) -> Result<()> {
    check_governance_identity(identity, manifest, args)?;
    let values: Vec<_> = table.split_whitespace().collect();
    if table.lines().count() != 1
        || values.len() < 13
        || values[0] != "0"
        || values[2] != "verity"
        || values[3] != "1"
        || values[6] != "4096"
        || values[7] != "4096"
        || values[10] != "sha256"
        || values[8].parse::<u64>()? != manifest.root_bytes / 4096
        || values[1].parse::<u64>()? != manifest.root_bytes / 512
        || values[11] != manifest.root_hash
    {
        return Err("actual dm-verity geometry/hash differs from signed UKI and release".into());
    }
    Ok(())
}

/// Confined Admin governance may inspect immutable image metadata and the
/// kernel-owned signed UKI command line; it cannot perform raw device ioctls.
/// This is intent governance, never a machine health acknowledgement.
pub(crate) fn check_governance_manifest(manifest: &Manifest) -> Result<()> {
    require_installed()?;
    let identity: RunningIdentity =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    check_governance_identity(&identity, manifest, &cmdline()?)?;
    if manifest.environment == "production" {
        require_firmware_authentication()?;
        let mount = kernel_mount(Path::new("/"))?;
        let dm = Path::new("/sys/dev/block").join(&mount.device).join("dm");
        if mount.root != "/"
            || mount.filesystem != "ext4"
            || !has_option(&mount.options, "ro")
            || !has_option(&mount.super_options, "ro")
            || fs::read_to_string(dm.join("name"))?.trim() != "root"
            || !fs::read_to_string(dm.join("uuid"))?
                .trim()
                .starts_with("CRYPT-VERITY-")
        {
            return Err(
                "production governance requires authenticated read-only kernel verity root".into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn check_running_manifest(manifest: &Manifest) -> Result<()> {
    require_installed()?;
    let identity: RunningIdentity =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    let args = cmdline()?;
    let table = command("/usr/sbin/dmsetup", &["table", "root"])?;
    check_identity(&identity, manifest, &args, &table)?;
    let slot = running_slot()?;
    active_root_partition(slot)?;
    let fields: Vec<_> = table.split_whitespace().collect();
    for (field, label) in [
        (4, format!("luma-root-{slot}")),
        (5, format!("luma-hash-{slot}")),
    ] {
        let metadata = fs::metadata(format!("/dev/disk/by-partlabel/{label}"))?;
        use std::os::unix::fs::FileTypeExt;
        // These libc helpers only decode the scalar dev_t returned by stat;
        // they neither dereference a pointer nor access the device.
        let (major, minor) =
            unsafe { (libc::major(metadata.rdev()), libc::minor(metadata.rdev())) };
        if !metadata.file_type().is_block_device() || fields[field] != format!("{major}:{minor}") {
            return Err("verity devices do not bind the actual selected signed slot".into());
        }
    }
    Ok(())
}

fn update_operation() -> Result<File> {
    use std::os::unix::fs::DirBuilderExt;
    let directory = Path::new("/run/luma-platform-update");
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    crate::tpm::exclusive_lock(&directory.join("operation.lock"))
}

pub fn update(source: &Path) -> Result<()> {
    crate::require_root()?;
    let _operation = update_operation()?;
    let verified = bundle::verify(source)?;
    let current: Manifest = serde_json::from_slice(&crate::admin_credentials::public_input(
        Path::new("/var/lib/luma-os/installed.json"),
        65536,
    )?)?;
    bundle::validate_manifest(&current)?;
    check_running_manifest(&current)?;
    if verified.manifest.environment != current.environment
        || verified.manifest.edition != current.edition
        || verified.manifest.root_bytes != current.root_bytes
        || verified.manifest.hash_bytes != current.hash_bytes
    {
        return Err(
            "update cannot change environment, edition or physical root/hash geometry".into(),
        );
    }
    let governed = crate::admin_governance::release_authority_optional()?;
    if let Some((state, interval)) = &governed {
        let authority = state
            .as_ref()
            .ok_or("Admin must publish release trust and admit this exact update")?;
        crate::release_trust::check_bundle_admission(&verified, authority)?;
        crate::release_trust::check_effect_time(authority, *interval)?;
        if authority.acknowledged.as_ref() != Some(&current) {
            return Err("installed manifest differs from TPM-anchored acknowledged release".into());
        }
    } else if current.environment == "production" {
        return Err("production update requires anchored Admin release authority".into());
    }
    if verified.manifest.sequence <= current.sequence {
        return Err("update sequence must increase".into());
    }
    let pending = Path::new("/var/lib/luma-os/pending.json");
    if pending.exists() {
        let previous: Manifest =
            serde_json::from_slice(&crate::admin_credentials::public_input(pending, 65536)?)?;
        if previous != verified.manifest {
            return Err(
                "a different update requires explicit recovery; pending intent cannot be replaced"
                    .into(),
            );
        }
    }
    let slot = if running_slot()? == 'a' { 'b' } else { 'a' };
    let disk = running_disk()?;
    verify_esp(&disk)?;
    println!(
        "Update {} to {} on inactive slot {slot}.",
        current.release, verified.manifest.release
    );
    disk.confirm("UPDATE")?;
    if let Some(expected) = &governed {
        let current = crate::admin_governance::release_authority()?;
        if current.0 != expected.0 {
            return Err(
                "release trust/admission changed while awaiting local disk confirmation".into(),
            );
        }
        crate::release_trust::check_effect_time(
            current.0.as_ref().ok_or("missing release admission")?,
            current.1,
        )?;
    }
    write_atomic(pending, &serde_json::to_vec(&verified.manifest)?, 0o600)?;
    let mut guard = || {
        if let Some(expected) = &governed {
            let current = crate::admin_governance::release_authority()?;
            if current.0 != expected.0 {
                return Err("release authority changed during inactive-slot staging; preserve pending evidence".into());
            }
            crate::release_trust::check_effect_time(
                current.0.as_ref().ok_or("missing release admission")?,
                current.1,
            )?;
        }
        Ok(())
    };
    install_slots_guarded(&disk, &verified, &[slot], &mut guard)?;
    publish_efi_guarded(Path::new("/efi"), &verified, &[slot], slot, &mut guard)?;
    println!("Inactive slot staged for at most three trial boots. Reboot when ready.");
    Ok(())
}

pub fn recover(args: &[String]) -> Result<()> {
    require_live()?;
    if args.len() < 2 {
        return Err("recovery needs an action and exact disk identity".into());
    }
    let action = &args[0];
    let disk = Disk::open(&args[1], false)?;
    if matches!(action.as_str(), "utc-seed" | "utc-reacquire") {
        let target = RecoveryTarget::open(disk)?;
        let credential = crate::admin_recovery::Credential::read()?;
        let authority = crate::admin_governance::TargetAuthority::new(&target, &credential)?;
        let report = if action == "utc-seed" {
            if args.len() != 3 && !(args.len() == 6 && args[3] == "--commit") {
                return Err(
                    "recover utc-seed DISK SEED-FILE [--commit KEEPER-INSTANCE REVIEW-SHA256]"
                        .into(),
                );
            }
            let seed: crate::utc_provider::Seed = serde_json::from_slice(
                &crate::admin_credentials::public_input(Path::new(&args[2]), 16384)?,
            )?;
            if args.len() == 3 {
                crate::utc_provider::recovery_seed_proposal(&authority, &seed)?
            } else {
                crate::utc_provider::recovery_deliver_seed(&authority, &seed, &args[4], &args[5])?;
                serde_json::json!({"schema_version":1,"seed_delivered":true,"timed_authority":false,"target_custody_verified":true})
            }
        } else {
            if args.len() != 2 && !(args.len() == 5 && args[2] == "--commit") {
                return Err(
                    "recover utc-reacquire DISK [--commit KEEPER-INSTANCE REVIEW-SHA256]".into(),
                );
            }
            if args.len() == 2 {
                crate::utc_provider::recovery_reacquire_proposal(&authority)?
            } else {
                crate::utc_provider::recovery_reacquire(&authority, &args[3], &args[4])?;
                serde_json::json!({"schema_version":1,"reacquired":true,"new_independent_seed_required":true,"timed_authority":false})
            }
        };
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    if action == "repair-data" && args.len() == 2 {
        println!("This repairs ext4 metadata and replays its journal. It never formats the encrypted volume. Preserve a backup before repairing damaged media.");
        disk.confirm("REPAIR-DATA")?;
        let crypt = unlock(&disk.partition(6)?, false)?;
        let output = Command::new("/usr/sbin/e2fsck")
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin")
            .args(["-p", &format!("/dev/mapper/{}", crypt.name)])
            .stdin(Stdio::null())
            .output()?;
        if !matches!(output.status.code(), Some(0) | Some(1)) {
            return Err("automatic data repair could not complete; retain the original and obtain filesystem recovery assistance".into());
        }
        println!("Encrypted data filesystem checked/repaired without formatting.");
        return Ok(());
    }
    if matches!(action.as_str(), "repair-a" | "repair-b") && args.len() == 3 {
        let target = RecoveryTarget::open(disk)?;
        if fs::symlink_metadata(target.admin_directory().join("anchor.json")).is_ok() {
            return repair_governed(&target, action, Path::new(&args[2]));
        }
        let retained = match fs::read_dir(target.admin_directory()) {
            Ok(mut entries) => entries.next().transpose()?.is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        } || target
            .admin_directory()
            .with_file_name("admin.parent-intent")
            .exists()
            || target
                .admin_directory()
                .with_file_name("admin.enrollment-pending")
                .exists();
        let (parent, nv, _) = crate::tpm::enrollment_handles(None)?;
        if retained || parent || nv {
            return Err("target enrollment is damaged or another fixed Luma authority exists; no static lab downgrade".into());
        }
        let verified = bundle::verify(Path::new(&args[2]))?;
        let current: Manifest = serde_json::from_slice(&crate::admin_credentials::public_input(
            &target.data_root().join("lib/luma-os/installed.json"),
            65536,
        )?)?;
        validate_laboratory_repair(&current, &verified.manifest)?;
        target.disk.confirm("REPAIR")?;
        let slot = if action == "repair-a" { 'a' } else { 'b' };
        let mut guard = || target.recheck();
        install_slots_guarded(&target.disk, &verified, &[slot], &mut guard)?;
        target.mount_esp()?;
        let esp = target.esp.borrow();
        publish_efi_guarded(
            &esp.as_ref().ok_or("missing target ESP")?.1.at,
            &verified,
            &[slot],
            slot,
            &mut guard,
        )?;
        println!("Selected system slot repaired; encrypted data was not formatted.");
        return Ok(());
    }
    if !matches!(action.as_str(), "unlock" | "export" | "disable-model") {
        return Err("unknown recovery action".into());
    }
    if (action == "export" && args.len() != 3) || (action != "export" && args.len() != 2) {
        return Err("wrong recovery argument count".into());
    }
    disk.confirm("RECOVER")?;
    let crypt = unlock(&disk.partition(6)?, action != "disable-model")?;
    let staging = bundle::private_dir("recovery")?;
    let data = Mount::new(
        Path::new(&format!("/dev/mapper/{}", crypt.name)),
        staging.join("data"),
        if action == "disable-model" {
            "nodev,nosuid,noexec"
        } else {
            "ro,nodev,nosuid,noexec"
        },
    )?;
    if action == "export" {
        let destination = Path::new(&args[2]);
        crate::recovery_export::export(&data.at, destination)?;
        println!("Encrypted data exported to the operator-selected destination. Protect the unencrypted archive.");
    } else if action == "disable-model" {
        write_atomic(
            &data.at.join("lib/luma-os/model-disabled"),
            b"disabled by offline recovery\n",
            0o600,
        )?;
        println!("Model disabled. Manual operation remains available.");
    } else {
        println!(
            "Recovery credential successfully unlocked and mounted the data volume read-only."
        );
    }
    Ok(())
}

fn repair_governed(target: &RecoveryTarget, action: &str, source: &Path) -> Result<()> {
    let credential = crate::admin_recovery::Credential::read()?;
    let authority = crate::admin_governance::TargetAuthority::new(target, &credential)?;
    let state = authority.release_state()?.clone();
    let mut client = crate::utc_provider::RecoveryClient::new(&authority)?;
    let first = client.current()?;
    let verified = bundle::verify_recovery(source, &state, first.interval())?;
    let signed = crate::release_trust::verify_current_release(
        &state.trust,
        &verified.manifest_bytes,
        &verified.signature,
        client.current()?.interval(),
    )?;
    let slot = if action == "repair-a" { 'a' } else { 'b' };
    let review = serde_json::json!({"schema_version":1,"kind":"target-bound-retained-image-repair","disk":target.disk.identity,
        "data_mount_device":target.proof.mount.device,"data_mount_id":target.proof.mount.id,
        "history_sha256":bundle::hex(&sha2::Sha256::digest(format!("{:?}",authority.history_binding()).as_bytes())),
        "release":verified.manifest,"manifest_sha256":signed.digest()?,"signer":signed.signer,
        "trust_sha256":state.trust.digest()?,"floor":state.floor,"slot":slot,"maximum_session_seconds":1800,
        "data_writable":false,"checkpoint_mutation":false,"automatic_renewal":false});
    let review_bytes = serde_json::to_vec(&review)?;
    use sha2::Digest;
    let digest = bundle::hex(&sha2::Sha256::digest(&review_bytes));
    println!("{}", serde_json::to_string_pretty(&review)?);
    println!("Review this exact disk/image transaction. Type exactly: REPAIR {digest}");
    if console_line(false)? != format!("REPAIR {digest}") {
        return Err("exact target repair review denied".into());
    }
    target.disk.confirm("REPAIR")?;
    let mut previous = client.current()?;
    let mut guard = || {
        let current = client.project_after_checks(&previous)?;
        crate::release_trust::repair_identity(&state, &verified.manifest)?;
        signed.check_time(&state.trust, current.interval())?;
        previous = current;
        Ok(())
    };
    guard()?;
    install_slots_guarded(&target.disk, &verified, &[slot], &mut guard)?;
    guard()?;
    target.mount_esp()?;
    guard()?;
    let esp = target.esp.borrow();
    publish_efi_guarded(
        &esp.as_ref().ok_or("missing governed repair ESP")?.1.at,
        &verified,
        &[slot],
        slot,
        &mut guard,
    )?;
    guard()?;
    println!("Exact TPM-anchored image repaired with continuous target/Admin/UTC checks. Encrypted data and monotonic release floor were not changed. Boot qualification remains required.");
    Ok(())
}

pub fn boot_health() -> Result<()> {
    crate::require_root()?;
    let _operation = update_operation()?;
    if live()? {
        return Err("recovery media cannot acknowledge installed boot health".into());
    }
    let authority = crate::admin_governance::release_state_optional()?;
    let immutable: RunningIdentity =
        serde_json::from_slice(&crate::admin_credentials::public_input(
            Path::new("/usr/share/luma-os/release-identity.json"),
            4096,
        )?)?;
    if immutable.environment == "production"
        && authority
            .as_ref()
            .map_or(true, |state| state.acknowledged.is_none())
    {
        let staged: crate::release_trust::StagedRelease =
            serde_json::from_slice(&crate::admin_credentials::public_input(
                Path::new("/var/lib/luma-os/staged-release.json"),
                131072,
            )?)?;
        check_running_manifest(&staged.release()?.manifest)?;
        println!("LUMA_BOOT_INERT_PRODUCTION: explicit Admin/TPM/protected-UTC/trust activation remains required; no boot-health acknowledgement or protected service authority issued.");
        return Ok(());
    }
    check_essential_health()?;
    let pending = Path::new("/var/lib/luma-os/pending.json");
    let mut failed = None;
    let acknowledged = if let Some(state) = &authority {
        let mut identities = Vec::new();
        for identity in [
            state.acknowledged.as_ref(),
            state.retained.as_ref(),
            state.pending.as_ref().map(|p| &p.prior),
            state.pending.as_ref().map(|p| &p.candidate.manifest),
        ]
        .into_iter()
        .flatten()
        {
            if !identities.contains(identity) {
                identities.push(identity.clone());
            }
        }
        let mut matches = identities
            .into_iter()
            .filter(|identity| check_running_manifest(identity).is_ok());
        let selected = matches
            .next()
            .ok_or("healthy running root is not any exact TPM-anchored release identity")?;
        if matches.next().is_some() {
            return Err("running release identity is ambiguous".into());
        }
        if let Some(p) = &state.pending {
            if selected != p.candidate.manifest {
                failed = Some(p.candidate.manifest.clone());
            }
        }
        selected
    } else {
        let mut selected: Manifest =
            serde_json::from_slice(&crate::admin_credentials::public_input(
                Path::new("/var/lib/luma-os/installed.json"),
                65536,
            )?)?;
        if pending.exists() {
            let candidate: Manifest =
                serde_json::from_slice(&crate::admin_credentials::public_input(pending, 65536)?)?;
            if check_running_manifest(&candidate).is_ok() {
                selected = candidate;
            } else {
                check_running_manifest(&selected)?;
                failed = Some(candidate);
            }
        } else {
            check_running_manifest(&selected)?;
        }
        selected
    };
    if let Some(authority) = authority {
        // The prepared exact intent authorizes machine health confirmation but
        // never a machine append impersonating the original Admin. Catalog
        // pending state remains until fresh human reconciliation; its floor
        // already prevents another lower-sequence installation/update.
        if let Some(admission) = &authority.pending {
            if acknowledged == admission.candidate.manifest {
                let current = crate::admin_governance::release_authority()?;
                if current.0.as_ref() != Some(&authority) {
                    return Err(
                        "release admission changed during candidate health validation".into(),
                    );
                }
                crate::release_trust::check_effect_time(&authority, current.1)?;
            } else if acknowledged != admission.prior
                && authority.retained.as_ref() != Some(&acknowledged)
            {
                return Err(
                    "healthy image is not exact admitted candidate or retained prior".into(),
                );
            }
        } else if authority.acknowledged.as_ref() != Some(&acknowledged)
            && authority.retained.as_ref() != Some(&acknowledged)
        {
            return Err("healthy image differs from TPM-anchored acknowledged release".into());
        }
    } else if acknowledged.environment == "production" {
        return Err("production health requires anchored release authority".into());
    }
    if Path::new(BOOT_COUNT_PATH).exists() {
        command("/usr/lib/systemd/systemd-bless-boot", &["good"])?;
    }
    write_atomic(
        Path::new("/var/lib/luma-os/installed.json"),
        &serde_json::to_vec(&acknowledged)?,
        0o600,
    )?;
    if let Some(manifest) = failed {
        write_atomic(
            Path::new("/var/lib/luma-os/failed-update.json"),
            &serde_json::to_vec(&manifest)?,
            0o600,
        )?;
    }
    write_atomic(
        Path::new("/efi/loader/loader.conf"),
        loader_config(running_slot()?, acknowledged.sequence, false).as_bytes(),
        0o600,
    )?;
    if pending.exists() {
        fs::remove_file(pending)?;
        File::open("/var/lib/luma-os")?.sync_all()?;
    }
    println!("LUMA_BOOT_HEALTH_OK");
    Ok(())
}

pub(crate) fn check_essential_health() -> Result<()> {
    crate::require_root()?;
    require_installed()?;
    running_slot()?;
    verify_esp(&running_disk()?)?;
    crate::service::security_check()?;
    command(
        "/usr/bin/systemctl",
        &["is-active", "--quiet", "luma-broker.service"],
    )?;
    if !command("/usr/bin/findmnt", &["-n", "-o", "OPTIONS", "/"])?
        .split(',')
        .any(|p| p.trim() == "ro")
    {
        return Err("root is not read-only".into());
    }
    if !command("/usr/sbin/veritysetup", &["status", "root"])?
        .lines()
        .any(|line| {
            line.split_once(':').map_or(false, |(key, value)| {
                key.trim() == "type" && value.trim().eq_ignore_ascii_case("VERITY")
            })
        })
    {
        return Err("root verity mapping is absent".into());
    }
    command("/usr/sbin/cryptsetup", &["status", "luma-data"])?;
    let probe = Path::new("/var/lib/luma-os/health-probe");
    write_atomic(probe, b"durable\n", 0o600)?;
    if fs::read(probe)? != b"durable\n" {
        return Err("data read-back failed".into());
    }
    Ok(())
}

pub fn boot_failed() -> Result<()> {
    crate::require_root()?;
    if live()? {
        return Err("live media never reboots for a failed installed health check".into());
    }
    // systemd-boot exposes this only for the currently booted counted entry.
    // Never loop rebooting an uncounted fallback or a manually selected image.
    let variable = Path::new(BOOT_COUNT_PATH);
    if !variable.exists() {
        eprintln!("Boot health failed; manual recovery required.");
        return Ok(());
    }
    let bytes = fs::read(variable)?;
    if bytes.len() < 6 || bytes.len() > 2048 || bytes.len() % 2 != 0 {
        return Err("invalid boot count EFI value".into());
    }
    let value = String::from_utf16(
        &bytes[4..]
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect::<Vec<_>>(),
    )?;
    if !value.contains("luma-") || !value.contains('+') {
        return Err("not a Luma counted trial".into());
    }
    command("/usr/bin/systemctl", &["--no-block", "reboot"])?;
    Ok(())
}

pub fn init_data(mode: &str) -> Result<()> {
    crate::require_root()?;
    let sysroot = Path::new("/sysroot");
    if mode == "live" {
        command(
            "/usr/bin/mount",
            &[
                "-t",
                "tmpfs",
                "-o",
                "mode=0755,nodev,nosuid",
                "tmpfs",
                "/sysroot/var",
            ],
        )?;
        command(
            "/usr/bin/cp",
            &[
                "-a",
                "/sysroot/usr/share/luma-os/var-template/.",
                "/sysroot/var",
            ],
        )?;
    } else if mode == "installed" {
        let slot = running_slot()?;
        let root = active_root_partition(slot)?;
        let parent = crate::disk::parent_disk(&root)?;
        let parent = path(&parent)?;
        let separator = if parent.ends_with(|c: char| c.is_ascii_digit()) {
            "p"
        } else {
            ""
        };
        let device = format!("{parent}{separator}6");
        let mut unlocked = false;
        for attempt in 1..=3 {
            let secret = terminal_prompt(
                true,
                Some("LUMA_DATA_UNLOCK: enter data or independent recovery passphrase:"),
                true,
            )?;
            match with_input(
                "/usr/sbin/cryptsetup",
                &[
                    "open",
                    "--type",
                    "luks2",
                    "--key-file",
                    "-",
                    &device,
                    "luma-data",
                ],
                &secret,
            ) {
                Ok(_) => {
                    unlocked = true;
                    break;
                }
                Err(error) => eprintln!("Data unlock attempt {attempt}/3: {error}"),
            }
        }
        if !unlocked {
            return Err("data unlock failed; use independent recovery media".into());
        }
        command(
            "/usr/bin/mount",
            &[
                "-o",
                "nodev,nosuid",
                "/dev/mapper/luma-data",
                "/sysroot/var",
            ],
        )?;
    } else {
        return Err("invalid init-data mode".into());
    }
    if !sysroot.join("var/lib/luma-os/identity/passwd").is_file() {
        return Err("data identity store is missing".into());
    }
    Ok(())
}
