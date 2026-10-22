//! Fixed launcher snapshot and actual acquisition-worker command checks. These
//! are descriptive input checks, not an alternate PAM, grant or lease broker.
use super::*;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
#[path = "client/admission.rs"]
mod admission;
pub(crate) use admission::check_client_arguments;

fn namespace(path: &Path) -> bool {
    path.to_str()
        .and_then(|s| s.strip_prefix("/run/luma-granted-client/requests/"))
        .and_then(|s| s.strip_suffix("/index.json"))
        .is_some_and(|id| identifier(id).is_ok())
}
fn identity(m: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o400
        || m.len() == 0
        || m.len() > MAX_REQUEST as u64
    {
        return Err("native index snapshot must be bounded root-owned0400 single-link data".into());
    }
    Ok(())
}
fn snapshot_bytes(path: &Path) -> Result<Vec<u8>> {
    if !namespace(path) {
        return Err("index requires its exact protected original-launcher snapshot".into());
    }
    let mut ancestors = Vec::new();
    for at in path
        .parent()
        .ok_or("index snapshot parent absent")?
        .ancestors()
    {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o022 != 0
            || (at.starts_with("/run/luma-granted-client") && m.mode() & 0o7777 != 0o700)
        {
            return Err("index launcher namespace is writable or aliased".into());
        }
        ancestors.push((at.to_owned(), m.dev(), m.ino(), m.mode()));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    private(&file)?;
    let before = file.metadata()?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    private(&file)?;
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if identity(&before) != identity(&after)
        || identity(&before) != identity(&named)
        || bytes.len() as u64 != before.len()
        || !named.is_file()
        || named.uid() != 0
        || named.gid() != 0
        || named.nlink() != 1
    {
        return Err("index original snapshot changed during same-file read".into());
    }
    for (at, dev, ino, mode) in ancestors {
        let m = std::fs::symlink_metadata(at)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || (m.dev(), m.ino(), m.mode()) != (dev, ino, mode)
        {
            return Err("index original snapshot ancestor changed".into());
        }
    }
    Ok(bytes)
}
pub(crate) fn original_input(path: &Path, login: &str) -> Result<request::Input> {
    let input = request::Input::parse(&snapshot_bytes(path)?)?;
    if input.login != login {
        return Err("index original command substitutes human login".into());
    }
    Ok(input)
}
pub(crate) fn read_snapshot(path: &Path, profile: &str, login: &str) -> Result<request::Input> {
    let input = scope::verify_input(profile, &snapshot_bytes(path)?)?;
    if input.login != login {
        return Err("index original command substitutes the human login".into());
    }
    Ok(input)
}
pub(crate) fn check_worker(profile: &str, device: &str, pid: u32) -> Result<()> {
    request::parse_profile(profile)?;
    if pid == 0 || device != crate::resource_manager::storage_device(Path::new("/var"))? {
        return Err("index worker requires exact installed storage generation".into());
    }
    let mut raw = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/cmdline"))?
        .take(4097)
        .read_to_end(&mut raw)?;
    let expected =
        format!("/usr/libexec/luma-os/luma-platform\0index-resource-worker\0{profile}\0");
    if raw.len() > 4096 || raw != expected.as_bytes() {
        return Err("index admission requires the exact fixed resource worker command".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_namespace_is_exact_no_alias_or_arbitrary_file() {
        assert!(namespace(Path::new(&format!(
            "/run/luma-granted-client/requests/{}/index.json",
            "a".repeat(32)
        ))));
        for path in [
            "/tmp/index.json",
            "/run/luma-granted-client/requests/../index.json",
            "/run/luma-granted-client/requests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/content.json",
            "/run/luma-granted-client/requests/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x/../index.json",
            "/run/luma-granted-client/requests/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/index.json",
        ] {
            assert!(!namespace(Path::new(path)));
        }
    }
}
