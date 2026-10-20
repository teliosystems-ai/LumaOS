//! Proposed source privacy before privileged parsing. Terminal ownership only
//! restricts readable proposal files; it never authenticates a product account.
use super::*;
use std::os::unix::fs::FileTypeExt;

const TIOCGDEV: libc::c_ulong = 0x80045432;
type Key = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn key(m: &fs::Metadata) -> Key {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn device(file: &fs::File) -> Result<u64> {
    let mut encoded = 0u32;
    if unsafe { libc::isatty(file.as_raw_fd()) } != 1
        || unsafe { libc::ioctl(file.as_raw_fd(), TIOCGDEV, &mut encoded) } < 0
    {
        return Err("proposal source requires an actual kernel terminal device".into());
    }
    // Linux v6.8 new_decode_dev, matching tty_io.c TIOCGDEV's new_encode_dev.
    Ok(libc::makedev(
        (encoded & 0xfff00) >> 8,
        (encoded & 0xff) | ((encoded >> 12) & 0xfff00),
    ))
}
struct Tty {
    terminal: fs::File,
    node: fs::File,
    path: std::path::PathBuf,
    identity: Key,
    device: u64,
    session: libc::pid_t,
}
fn node_for(device: u64) -> Result<(fs::File, std::path::PathBuf)> {
    let pts = Path::new("/dev/pts");
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(pts)?;
    let metadata = directory.metadata()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } < 0
        || filesystem.f_type != 0x1cd1
    {
        return Err("proposal terminal requires actual protected devpts inventory".into());
    }
    let mut found = None;
    for (count, entry) in fs::read_dir(pts)?.enumerate() {
        if count >= 4096 {
            return Err("proposal terminal inventory exceeds fixed bound".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        if text
            .parse::<u32>()
            .map_or(true, |n| n.to_string() != text || n > 1_048_575)
        {
            continue;
        }
        let m = fs::symlink_metadata(entry.path())?;
        if m.file_type().is_char_device() && m.rdev() == device {
            if found.is_some() {
                return Err("proposal terminal node identity is ambiguous".into());
            }
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(entry.path())?;
            if key(&file.metadata()?) != key(&m) {
                return Err("proposal terminal changed during observation".into());
            }
            found = Some((file, entry.path()));
        }
    }
    if let Some(found) = found {
        return Ok(found);
    }
    let major = unsafe { libc::major(device) };
    let minor = unsafe { libc::minor(device) };
    let path = if major == 4 && (1..64).contains(&minor) {
        std::path::PathBuf::from(format!("/dev/tty{minor}"))
    } else if major == 4 && (64..256).contains(&minor) {
        std::path::PathBuf::from(format!("/dev/ttyS{}", minor - 64))
    } else {
        return Err("proposal terminal is not a supported native PTY/console".into());
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    Ok((file, path))
}
impl Tty {
    fn capture() -> Result<Self> {
        let terminal = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/tty")?;
        let device = device(&terminal)?;
        let (node, path) = node_for(device)?;
        let identity = key(&node.metadata()?);
        let mut session = 0;
        if unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCGSID, &mut session) } < 0
            || session <= 0
            || session != unsafe { libc::getsid(0) }
        {
            return Err("proposal source is not on its original controlling terminal".into());
        }
        let result = Self {
            terminal,
            node,
            path,
            identity,
            device,
            session,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let current = self.node.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        let mut session = 0;
        if !current.file_type().is_char_device()
            || current.rdev() != self.device
            || current.mode() & 7 != 0
            || key(&current) != self.identity
            || key(&named) != self.identity
            || device(&self.terminal)? != self.device
            || unsafe { libc::ioctl(self.terminal.as_raw_fd(), libc::TIOCGSID, &mut session) } < 0
            || session != self.session
            || session != unsafe { libc::getsid(0) }
        {
            return Err("original proposal terminal ownership/generation changed".into());
        }
        Ok(())
    }
    fn owner(&self) -> Result<u32> {
        self.check()?;
        let uid = self.node.metadata()?.uid();
        if uid != 0 && !(1000..65534).contains(&uid) {
            return Err("proposal terminal is not an ordinary human/root console".into());
        }
        Ok(uid)
    }
}
fn file_owner(file: &fs::Metadata, owner: u32, maximum: usize) -> Result<()> {
    if !file.is_file()
        || file.uid() != owner
        || file.nlink() != 1
        || file.mode() & 0o7777 != 0o600
        || file.len() == 0
        || file.len() > maximum as u64
    {
        return Err("source must be caller-owned0600 bounded single-link proposal data".into());
    }
    Ok(())
}
struct Proposal {
    file: fs::File,
    path: std::path::PathBuf,
    pin: Key,
    parents: Vec<(std::path::PathBuf, fs::File, (u64, u64, u32, u32, u32))>,
    owner: u32,
    maximum: usize,
}
fn dirkey(m: &fs::Metadata) -> (u64, u64, u32, u32, u32) {
    (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
}
impl Proposal {
    fn capture(path: &Path, owner: u32, namespace: &Path, maximum: usize) -> Result<Self> {
        let nonce = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".request"))
            .ok_or("proposal requires exact uuid32.request leaf")?;
        crate::tpm::decode::<16>(nonce)?;
        if nonce != nonce.to_ascii_lowercase()
            || path.parent() != Some(namespace)
            || fs::canonicalize(path)? != path
        {
            return Err("proposal path is outside the exact original caller namespace".into());
        }
        let mut parents = Vec::new();
        for at in path.ancestors().skip(1) {
            let held = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(at)?;
            let m = held.metadata()?;
            let private = at == namespace
                || owner != 0 && at == namespace.parent().ok_or("caller runtime absent")?
                || owner == 0 && at.starts_with("/run/luma-granted-client");
            let expected = if private { owner } else { 0 };
            if !m.is_dir()
                || m.uid() != expected
                || m.mode() & 0o022 != 0
                || private && m.mode() & 0o7777 != 0o700
                || dirkey(&m) != dirkey(&fs::symlink_metadata(at)?)
            {
                return Err(
                    "proposal parent namespace is not protected for original caller".into(),
                );
            }
            parents.push((at.to_path_buf(), held, dirkey(&m)));
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        file_owner(&metadata, owner, maximum)?;
        let result = Self {
            file,
            path: path.to_path_buf(),
            pin: key(&metadata),
            parents,
            owner,
            maximum,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let held = self.file.metadata()?;
        file_owner(&held, self.owner, self.maximum)?;
        if key(&held) != self.pin
            || key(&fs::symlink_metadata(&self.path)?) != self.pin
            || self.parents.iter().any(|(path, held, pin)| {
                held.metadata().map_or(true, |m| dirkey(&m) != *pin)
                    || fs::symlink_metadata(path).map_or(true, |m| dirkey(&m) != *pin)
            })
        {
            return Err("original caller proposal changed before private capture completed".into());
        }
        Ok(())
    }
    fn read(mut self, mut check: impl FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        self.check()?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(self.maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        self.check()?;
        check()?;
        if bytes.len() as u64 != self.pin.6 {
            return Err("caller proposal length changed".into());
        }
        Ok(bytes)
    }
}
pub(super) fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let tty = Tty::capture()?;
    let owner = tty.owner()?;
    let namespace = if owner == 0 {
        std::path::PathBuf::from("/run/luma-granted-client/manual-inputs")
    } else {
        std::path::PathBuf::from(format!("/run/user/{owner}/luma-terminal-proposals"))
    };
    Proposal::capture(path, owner, &namespace, maximum)?.read(|| tty.check())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let path = root.join(format!(
                "proposal-source-{}",
                crate::resources::random_id().unwrap()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> std::path::PathBuf {
            self.0.join(format!("{}.request", "1".repeat(32)))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn write(path: &Path) {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(b"literal owned source").unwrap();
    }
    #[test]
    fn held_private_source_refuses_aliases_hardlinks_foreign_owner_and_replaced_namespace() {
        let f = Fixture::new();
        let path = f.file();
        write(&path);
        let uid = unsafe { libc::geteuid() };
        let claim = Proposal::capture(&path, uid, &f.0, 1024).unwrap();
        assert_eq!(claim.read(|| Ok(())).unwrap(), b"literal owned source");
        let metadata = fs::metadata(&path).unwrap();
        assert!(file_owner(&metadata, uid + 1, 1024).is_err());
        let alias = f.0.join(format!("{}.request", "2".repeat(32)));
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(Proposal::capture(&alias, uid, &f.0, 1024).is_err());
        fs::remove_file(alias).unwrap();
        let link = f.0.join("second");
        fs::hard_link(&path, &link).unwrap();
        assert!(Proposal::capture(&path, uid, &f.0, 1024).is_err());
        fs::remove_file(link).unwrap();
        let claim = Proposal::capture(&path, uid, &f.0, 1024).unwrap();
        fs::rename(&path, f.0.join("old")).unwrap();
        write(&path);
        assert!(claim.read(|| Ok(())).is_err());
    }
    #[test]
    fn source_retains_fd_and_refuses_inplace_mutation_mode_drift_and_cancellation() {
        let f = Fixture::new();
        let path = f.file();
        write(&path);
        let uid = unsafe { libc::geteuid() };
        let claim = Proposal::capture(&path, uid, &f.0, 1024).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(b"altered")
            .unwrap();
        assert!(claim.read(|| Ok(())).is_err());
        let claim = Proposal::capture(&path, uid, &f.0, 1024).unwrap();
        assert!(claim.read(|| Err("original terminal lost".into())).is_err());
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Proposal::capture(&path, uid, &f.0, 1024).is_err());
    }
    #[test]
    fn actual_disposable_devpts_fd_matches_kernel_primary_device_and_real_node_owner() {
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
        let _master = unsafe { fs::File::from_raw_fd(master) };
        let slave = unsafe { fs::File::from_raw_fd(slave) };
        let dev = device(&slave).unwrap();
        assert_eq!(dev, slave.metadata().unwrap().rdev());
        let (node, path) = node_for(dev).unwrap();
        assert!(path.starts_with("/dev/pts"));
        assert_eq!(
            node.metadata().unwrap().uid(),
            slave.metadata().unwrap().uid()
        );
        assert_eq!(node.metadata().unwrap().rdev(), dev);
        let regular = fs::File::open("/dev/null").unwrap();
        assert!(device(&regular).is_err());
    }
}
