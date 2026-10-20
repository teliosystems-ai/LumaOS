//! Persistent negative cancellation barrier for exact hosted request bytes.
//! This is not an issuer, grant, clock, checkpoint or replacement for Windows
//! journal/TPM authority. It only prevents an already drained request from
//! executing later through a delayed systemd start. Markers are never deleted.
use crate::Result;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const ROOT: &str = "/var/lib/luma-hosted-revocations";
static REQUEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) fn bind(resource: &str, request: &str) -> Result<()> {
    digest(resource)?;
    digest(request)?;
    REQUEST
        .set(request.to_owned())
        .map_err(|_| "hosted process cannot replace its original request binding")?;
    check_current()
}
pub(crate) fn check_current() -> Result<()> {
    check(
        REQUEST
            .get()
            .ok_or("hosted worker has no original request binding")?,
    )
}
pub(crate) fn require_bytes(bytes: &[u8]) -> Result<()> {
    if REQUEST.get().ok_or("hosted request binding missing")? != &luma_content::sha256(bytes) {
        return Err("hosted input differs from its pre-dispatch original request digest".into());
    }
    check_current()
}
pub(crate) fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || crate::tpm::decode::<32>(value)? == [0; 32]
    {
        return Err("exact nonzero lowercase hosted request/resource digest required".into());
    }
    Ok(())
}
fn root(create: bool) -> Result<File> {
    if create {
        crate::require_root()?;
        match std::fs::create_dir(ROOT) {
            Ok(()) => {
                std::fs::set_permissions(ROOT, std::fs::Permissions::from_mode(0o755))?;
                File::open("/var/lib")?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    for path in Path::new(ROOT).ancestors() {
        let info = std::fs::symlink_metadata(path)?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o7022 != 0 {
            return Err("hosted cancellation namespace is not root protected".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)?;
    check_root(&file)?;
    Ok(file)
}
fn check_root(file: &File) -> Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(ROOT)?;
    let identity = |info: &std::fs::Metadata| (info.dev(), info.ino(), info.uid(), info.mode());
    if identity(&held) != identity(&named)
        || !held.is_dir()
        || held.uid() != 0
        || held.mode() & 0o7022 != 0
    {
        return Err("hosted cancellation namespace identity changed".into());
    }
    Ok(())
}
fn absent(file: &File, request: &str) -> Result<()> {
    digest(request)?;
    let name = std::ffi::CString::new(request)?;
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            file.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Err(
            "hosted request was cancelled/drained; it cannot execute or be replayed".into(),
        );
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err("hosted request cancellation state is unobservable".into());
    }
    Ok(())
}
pub(crate) fn prepare(resource: &str, request: &str) -> Result<()> {
    digest(resource)?;
    digest(request)?;
    let file = root(true)?;
    if inventory(Path::new(ROOT))? >= 1024 {
        return Err("hosted cancellation capacity exhausted before dispatch".into());
    }
    absent(&file, request)?;
    check_root(&file)
}
pub(crate) fn check(request: &str) -> Result<()> {
    let file = root(false)?;
    absent(&file, request)?;
    check_root(&file)
}
fn inventory(path: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        count += 1;
        if count > 1024 || digest(&entry.file_name().to_string_lossy()).is_err() {
            return Err("hosted cancellation inventory is unknown or exhausted".into());
        }
        let info = entry.metadata()?;
        if !info.is_file()
            || info.uid() != 0
            || info.mode() & 0o7022 != 0
            || info.nlink() != 1
            || info.len() != 0
        {
            return Err("hosted cancellation inventory contains an invalid marker".into());
        }
    }
    Ok(count)
}
pub(crate) fn revoke(request: &str) -> Result<()> {
    digest(request)?;
    let file = root(true)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another hosted cancellation transition is active".into());
    }
    // The single exact namespace is bounded; no unknown files are adopted or
    // silently retired to manufacture capacity. Exhaustion refuses recovery.
    let count = inventory(Path::new(ROOT))?;
    if count >= 1024 && absent(&file, request).is_ok() {
        return Err(
            "hosted cancellation capacity exhausted; preserve every existing marker".into(),
        );
    }
    let name = std::ffi::CString::new(request)?;
    let fd = unsafe {
        libc::openat(
            file.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    let marker = if fd >= 0 {
        let marker = unsafe { File::from_raw_fd(fd) };
        marker.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        marker
    } else {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) || count > 1024 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe { File::from_raw_fd(fd) }
    };
    let info = marker.metadata()?;
    if !info.is_file()
        || info.uid() != 0
        || info.mode() & 0o7022 != 0
        || info.nlink() != 1
        || info.len() != 0
    {
        return Err("hosted cancellation marker identity differs; preserve evidence".into());
    }
    marker.sync_all()?;
    file.sync_all()?;
    check_root(&file)?;
    if absent(&file, request).is_ok() {
        return Err("hosted cancellation marker did not persist".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_keys_are_exact_data_not_paths_or_authority() {
        assert!(digest(&"ab".repeat(32)).is_ok());
        for invalid in [
            "".into(),
            "00".repeat(32),
            "AB".repeat(32),
            "../other".into(),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(digest(&invalid).is_err());
        }
    }
    #[test]
    fn actual_negative_marker_blocks_only_its_exact_request_without_reset() {
        let base = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = base.join(format!("hosted-negative-fence-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let file = File::open(&directory).unwrap();
        let request = "ab".repeat(32);
        let next = "bc".repeat(32);
        absent(&file, &request).unwrap();
        let marker = directory.join(&request);
        let held = File::create(&marker).unwrap();
        held.set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        held.sync_all().unwrap();
        if unsafe { libc::getuid() } == 0 {
            assert_eq!(inventory(&directory).unwrap(), 1);
        } else {
            assert!(inventory(&directory).is_err());
        }
        assert!(absent(&file, &request).is_err());
        absent(&file, &next).unwrap();
        assert!(absent(&file, "../other").is_err());
        let unknown = directory.join("unrecognized");
        File::create(&unknown).unwrap();
        assert!(inventory(&directory).is_err());
        std::fs::remove_file(unknown).unwrap();
        std::fs::remove_file(marker).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
