//! Short-lived local account authentication, not product Admin enrollment.
use crate::{
    principal::{self, AccountBinding},
    sealed_credential::PrivateBuffer,
    Result,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PROFILE: &[u8] = include_bytes!("../../../native/image/overlay/etc/pam.d/luma-admin");
const HELPER: &str = "/usr/libexec/luma-os/luma-auth-helper";
const LIMIT: usize = 1024;
pub(crate) const PASSWORD_FRAME: usize = LIMIT + 1;
mod session;

fn login(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 32
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    {
        return Err("invalid local account name".into());
    }
    Ok(())
}

struct Terminal(File, libc::termios);
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.0.as_raw_fd(), libc::TCSANOW, &self.1);
        }
    }
}

fn password_from(file: File) -> Result<PrivateBuffer> {
    hidden_from(file, "Account password (authentication only):")
}

pub(crate) fn hidden_from(file: File, prompt: &str) -> Result<PrivateBuffer> {
    let mut buffer = PrivateBuffer::new(LIMIT + 1)?;
    let mut saved = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut saved) } != 0 {
        return Err("controlling terminal required".into());
    }
    let mut hidden = saved;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
        return Err("cannot suppress password echo".into());
    }
    let mut terminal = Terminal(file, saved);
    writeln!(terminal.0, "{prompt}")?;
    terminal.0.flush()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut offset = 0;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("password input expired")?;
        let mut poll = libc::pollfd {
            fd: terminal.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        } <= 0
        {
            return Err("password input unavailable or expired".into());
        }
        terminal
            .0
            .read_exact(&mut buffer.bytes_mut()[offset..offset + 1])?;
        let byte = buffer.bytes()[offset];
        if matches!(byte, 3 | 4) {
            return Err("password input cancelled".into());
        }
        if matches!(byte, 8 | 127) {
            buffer.bytes_mut()[offset] = 0;
            if offset > 0 {
                offset -= 1;
                while offset > 0 && buffer.bytes()[offset] & 0xc0 == 0x80 {
                    buffer.bytes_mut()[offset] = 0;
                    offset -= 1;
                }
                buffer.bytes_mut()[offset] = 0;
            }
            continue;
        }
        if matches!(byte, b'\n' | b'\r') {
            buffer.bytes_mut()[offset] = 0;
            if offset == 0 {
                return Err("empty password refused".into());
            }
            return Ok(buffer);
        }
        if byte < 32 || offset == LIMIT {
            return Err("password outside bound".into());
        }
        offset += 1;
    }
}

struct Helper(Child);
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// This is intentionally not Clone, Serialize or caller-constructible. It is
// an ephemeral authentication observation, not a capability or persistent role.
pub(crate) struct AuthenticatedAccount {
    binding: AccountBinding,
    lifetime: session::Lifetime,
    exchange_started: session::Boundary,
}

// Root-owned ordering metadata has no JSON form and supplies no PAM authority.
pub(crate) struct ExchangeBoundary {
    boundary: session::Boundary,
}

/// Protected-process lifetime only: no PAM, principal, role or authority.
/// Recovery uses the same boot/process/root pins and suspend-aware 30s bound.
pub(crate) struct ProtectedOperation(session::Lifetime);

impl ProtectedOperation {
    pub(crate) fn start() -> Result<Self> {
        Ok(Self(session::Lifetime::start()?))
    }
    pub(crate) fn within<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.0.observe(operation)
    }
    pub(crate) fn close(&self) {
        self.0.close();
    }
}

impl Drop for ProtectedOperation {
    fn drop(&mut self) {
        self.close();
    }
}

impl ExchangeBoundary {
    pub(crate) fn capture() -> Result<Self> {
        crate::require_root()?;
        Ok(Self {
            boundary: session::Boundary::capture()?,
        })
    }
}

impl AuthenticatedAccount {
    pub(crate) fn observe_fresh<T>(
        &self,
        boundary: &ExchangeBoundary,
        project: impl FnOnce(&serde_json::Value) -> Result<T>,
    ) -> Result<T> {
        self.observe(|local| {
            boundary.boundary.require_later(&self.exchange_started)?;
            project(local)
        })
    }

    /// Bind a complete protected projection to the original account pins and
    /// PAM lifetime. Error, timeout or unwinding fences that PAM observation.
    pub(crate) fn observe<T>(
        &self,
        project: impl FnOnce(&serde_json::Value) -> Result<T>,
    ) -> Result<T> {
        self.lifetime.observe(|| {
            let local = self.binding.identity()?;
            let result = project(&local)?;
            if self.binding.identity()? != local {
                return Err("local PAM identity changed during protected projection".into());
            }
            Ok(result)
        })
    }

    pub(crate) fn identity(&self) -> Result<serde_json::Value> {
        self.lifetime.observe(|| self.binding.identity())
    }

    fn current_uid(&self) -> Result<u32> {
        self.lifetime.observe(|| self.binding.current_uid())
    }

    pub(crate) fn logout(&self) {
        self.lifetime.close();
    }
}

impl Drop for AuthenticatedAccount {
    fn drop(&mut self) {
        self.logout();
    }
}

fn authenticate(
    helper: &Path,
    username: &str,
    password: &PrivateBuffer,
) -> Result<AuthenticatedAccount> {
    authenticate_at(
        helper,
        username,
        password,
        Path::new(principal::REGISTRY),
        Path::new(principal::IDENTITY),
    )
}

fn authenticate_at(
    helper: &Path,
    username: &str,
    password: &PrivateBuffer,
    registry: &Path,
    identity: &Path,
) -> Result<AuthenticatedAccount> {
    crate::require_root()?;
    login(username)?;
    if password.bytes().len() != LIMIT + 1 {
        return Err("invalid password frame".into());
    }
    let authentication_budget = session::Lifetime::start()?;
    let exchange_started = authentication_budget.boundary();
    let binding = AccountBinding::capture(registry, identity, username)?;
    let profile = Path::new("/etc/pam.d/luma-admin");
    let metadata = std::fs::symlink_metadata(profile)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() != PROFILE.len() as u64
        || std::fs::read(profile)? != PROFILE
    {
        return Err("unexpected local authentication profile".into());
    }
    let metadata = std::fs::symlink_metadata(helper)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o6022 != 0
        || metadata.nlink() != 1
    {
        return Err("unsafe authentication helper".into());
    }
    let output = PrivateBuffer::new(4)?;
    let mut result_file = output.descriptor()?;
    let mut command = Command::new(helper);
    command
        .arg(username)
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C")
        .stdin(Stdio::from(password.descriptor()?))
        .stdout(Stdio::from(output.descriptor()?))
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 4,
                rlim_max: 4,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    authentication_budget.check()?;
    let mut child = Helper(command.spawn()?);
    loop {
        authentication_budget.check()?;
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("local account authentication denied".into());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if result_file.stream_position()? != 4 {
        return Err("invalid authentication response".into());
    }
    let uid = u32::from_be_bytes(output.bytes().try_into()?);
    if !(1000..65534).contains(&uid) {
        return Err("service/system account refused".into());
    }
    if binding.current_uid()? != uid {
        return Err("PAM identity differs from the bound local principal".into());
    }
    authentication_budget.check()?;
    let lifetime = session::Lifetime::start()?;
    authentication_budget.check()?;
    Ok(AuthenticatedAccount {
        binding,
        lifetime,
        exchange_started,
    })
}

pub(crate) fn local(username: &str) -> Result<AuthenticatedAccount> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    login(username)?;
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let password = password_from(terminal)?;
    authenticate(Path::new(HELPER), username, &password)
}

pub(crate) fn console_password(username: &str) -> Result<PrivateBuffer> {
    crate::protect_memory()?;
    crate::platform::require_installed()?;
    login(username)?;
    password_from(
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/tty")?,
    )
}

/// The trusted IPC composition supplies the kernel peer, never request JSON.
pub(crate) fn peer_account(
    username: &str,
    password: &PrivateBuffer,
    peer: u32,
) -> Result<AuthenticatedAccount> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    authenticate_peer(peer, || authenticate(Path::new(HELPER), username, password))
}

fn authenticate_peer(
    peer: u32,
    authenticate: impl FnOnce() -> Result<AuthenticatedAccount>,
) -> Result<AuthenticatedAccount> {
    if peer != 1001 {
        return Err("Admin service requires the selected human peer".into());
    }
    let authenticated = authenticate()?;
    if authenticated.current_uid()? != peer {
        return Err("PAM principal differs from the kernel peer".into());
    }
    Ok(authenticated)
}

/// Existing owner bytes are entered as hex, never argv, environment or a file.
pub(crate) fn existing_owner() -> Result<PrivateBuffer> {
    crate::require_root()?;
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let encoded = hidden_from(
        terminal,
        "Existing TPM owner authorization as hex (hidden; no ownership change):",
    )?;
    decode_owner(&encoded)
}

fn decode_owner(encoded: &PrivateBuffer) -> Result<PrivateBuffer> {
    let size = encoded
        .bytes()
        .iter()
        .position(|b| *b == 0)
        .ok_or("unterminated owner authorization")?;
    if size == 0 || size > 128 || size % 2 != 0 {
        return Err("existing owner authorization must be 2..128 hex characters".into());
    }
    let mut owner = PrivateBuffer::new(size / 2)?;
    for (i, pair) in encoded.bytes()[..size].chunks_exact(2).enumerate() {
        let nibble = |b: u8| -> Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err("invalid owner authorization hex".into()),
            }
        };
        owner.bytes_mut()[i] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(owner)
}

pub fn check(username: &str) -> Result<()> {
    let account = local(username)?;
    let uid = account.current_uid()?;
    account.logout();
    println!(
        "{}",
        serde_json::json!({"authenticated_uid":uid,
        "product_admin_active":false,"role_grant":false,"gate_closing":false})
    );
    Ok(())
}

#[cfg(test)]
impl ProtectedOperation {
    pub(crate) fn expired_fixture() -> Result<Self> {
        Ok(Self(session::Lifetime::expired_fixture()?))
    }
}

#[cfg(test)]
pub(crate) fn fixture_peer_account(
    directory: &Path,
    username: &str,
    password: &PrivateBuffer,
    peer: u32,
) -> Result<AuthenticatedAccount> {
    authenticate_peer(peer, || {
        fixture_local_account(directory, username, password)
    })
}

#[cfg(test)]
pub(crate) fn fixture_local_account(
    directory: &Path,
    username: &str,
    password: &PrivateBuffer,
) -> Result<AuthenticatedAccount> {
    crate::require_root()?;
    if !Path::new("/.dockerenv").is_file()
        || !directory.starts_with("/tmp")
        || !directory
            .file_name()
            .ok_or("missing fixture directory")?
            .to_string_lossy()
            .starts_with("luma-tpm-delivery-")
        || Path::new("/dev/tpm0").exists()
        || Path::new("/dev/tpmrm0").exists()
    {
        return Err("fresh disposable PAM fixture required".into());
    }
    authenticate_at(
        &Path::new(env!("OUT_DIR")).join("luma-auth-helper"),
        username,
        password,
        &directory.join("registry.json"),
        Path::new("/etc"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    fn console_fixture(input: &'static [u8], cancelled: bool) {
        let (mut master, mut slave) = (-1, -1);
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
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let check = slave.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            let mut byte = [0];
            loop {
                master.read_exact(&mut byte).unwrap();
                if byte[0] == b'\n' {
                    break;
                }
            }
            let mut state = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::tcgetattr(master.as_raw_fd(), &mut state) },
                0
            );
            assert_eq!(state.c_lflag & (libc::ECHO | libc::ECHONL | libc::ISIG), 0);
            master.write_all(input).unwrap();
            master
        });
        let result = password_from(slave);
        if cancelled {
            assert!(result.is_err());
        } else {
            assert!(&result.unwrap().bytes()[..7] == b"secret\0");
        }
        let master = writer.join().unwrap();
        let mut state = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(check.as_raw_fd(), &mut state) }, 0);
        assert_ne!(state.c_lflag & libc::ECHO, 0);
        assert_ne!(state.c_lflag & libc::ICANON, 0);
        assert_ne!(state.c_lflag & libc::ISIG, 0);
        drop(master);
    }
    #[test]
    fn protected_console_input_and_editing() {
        console_fixture(b"secrex\x7ft\n", false);
    }
    #[test]
    fn console_cancellation_restores_terminal() {
        console_fixture(b"partial\x03", true);
    }
    #[test]
    fn names_and_expiry_are_closed() {
        for value in ["", "root:0", "--help", "../admin", "ADMIN", "a\0b"] {
            assert!(login(value).is_err());
        }
        login("luma-admin").unwrap();
        session::Lifetime::start().unwrap().check().unwrap();
        assert!(session::Lifetime::expired_fixture()
            .unwrap()
            .check()
            .is_err());
    }
    #[test]
    fn complete_observation_is_bounded_before_and_after_projection() {
        let lifetime = session::Lifetime::start().unwrap();
        assert!(lifetime
            .observe(|| {
                lifetime.close();
                Ok(serde_json::json!({"uid":1001}))
            })
            .is_err());
        assert!(lifetime
            .observe(|| -> Result<()> { panic!("closed session reached identity projection") })
            .is_err());
        let expired = session::Lifetime::expired_fixture().unwrap();
        assert!(expired
            .observe(|| -> Result<()> { panic!("expired session reached identity projection") })
            .is_err());
        assert!(authenticate_peer(0, || panic!("root peer reached PAM")).is_err());
        assert!(authenticate_peer(1000, || panic!("ordinary peer reached PAM")).is_err());
    }
    #[test]
    fn protected_projection_rechecks_pins_and_fences_failure_and_unwinding() {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!("luma-pam-projection-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let identity = root.join("identity");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&identity)
            .unwrap();
        let passwd = b"human:x:1001:1001:Human:/home/human:/bin/bash\n";
        for (name, bytes) in [
            ("passwd", passwd.as_slice()),
            (
                "shadow",
                b"human:$6$public$fixture:20000:0:99999:7:::\n".as_slice(),
            ),
        ] {
            crate::platform::write_atomic(&identity.join(name), bytes, 0o600).unwrap();
        }
        principal::initialize(&root.join("principals"), &[("human", 1001)]).unwrap();
        // Synthetic account/lifetime composition tests pin and unwind behavior,
        // not PAM success. Genuine PAM is exercised by the guarded integration.
        let account = || AuthenticatedAccount {
            binding: AccountBinding::capture(
                &root.join("principals/registry.json"),
                &identity,
                "human",
            )
            .unwrap(),
            lifetime: session::Lifetime::start().unwrap(),
            exchange_started: session::Boundary::capture().unwrap(),
        };
        let changed = account();
        assert!(changed
            .observe(|_| {
                crate::platform::write_atomic(&identity.join("passwd"), passwd, 0o600)?;
                Ok(())
            })
            .is_err());
        assert!(changed.identity().is_err());
        let failed = account();
        assert!(failed
            .observe::<()>(|_| Err("fixture protected projection failure".into()))
            .is_err());
        assert!(failed.identity().is_err());
        let unwound = account();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || unwound.observe::<()>(|_| panic!("fixture unwind"))
        ))
        .is_err());
        assert!(unwound.identity().is_err());
        let expired = account();
        assert!(expired
            .observe(|_| {
                expired.logout();
                Ok(())
            })
            .is_err());
        assert!(expired.identity().is_err());
        let healthy = account();
        assert_eq!(
            healthy.observe(|local| Ok(local["uid"].clone())).unwrap(),
            1001
        );
        let older = account();
        let boundary = ExchangeBoundary::capture().unwrap();
        assert!(older.observe_fresh(&boundary, |_| Ok(())).is_err());
        assert!(older.identity().is_err());
        let fresh = account();
        assert_eq!(
            fresh
                .observe_fresh(&boundary, |local| Ok(local["uid"].clone()))
                .unwrap(),
            1001
        );
        let interrupted = account();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            interrupted
                .observe_fresh::<()>(&boundary, |_| panic!("fixture fresh projection unwind"))
        }))
        .is_err());
        assert!(interrupted.identity().is_err());
        for directory in [identity, root.join("principals")] {
            for entry in std::fs::read_dir(&directory).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
            std::fs::remove_dir(directory).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn existing_owner_hex_is_bounded_and_decoded_in_locked_memory() {
        for (input, expected) in [
            ("00aBFF", Some(vec![0, 171, 255])),
            ("", None),
            ("a", None),
            ("gg", None),
            ("aa bb", None),
        ] {
            let mut encoded = PrivateBuffer::new(LIMIT + 1).unwrap();
            encoded.bytes_mut()[..input.len()].copy_from_slice(input.as_bytes());
            match expected {
                Some(bytes) => assert_eq!(decode_owner(&encoded).unwrap().bytes(), bytes),
                None => assert!(decode_owner(&encoded).is_err()),
            }
        }
        let mut encoded = PrivateBuffer::new(LIMIT + 1).unwrap();
        encoded.bytes_mut()[..128].fill(b'f');
        assert_eq!(decode_owner(&encoded).unwrap().bytes(), [255; 64]);
        encoded.bytes_mut()[128..130].fill(b'f');
        assert!(decode_owner(&encoded).is_err());
    }
    #[test]
    #[ignore = "requires isolated real PAM account fixture"]
    fn local_pam_account() {
        assert!(Path::new("/.dockerenv").is_file());
        let directory = std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap();
        assert!(directory.starts_with("/tmp/luma-tpm-"));
        let mut password = PrivateBuffer::new(LIMIT + 1).unwrap();
        let value = crate::tpm::private_read(
            &Path::new(&directory).join("account-password"),
            LIMIT as u64,
        )
        .unwrap();
        password.bytes_mut()[..value.len()].copy_from_slice(&value);
        let helper = Path::new(env!("OUT_DIR")).join("luma-auth-helper");
        let state = Path::new(&directory).join("principals");
        if !state.exists() {
            principal::initialize(&state, &[("luma-auth-test", 32001)]).unwrap();
        }
        let registry = state.join("registry.json");
        let observe = |password: &PrivateBuffer| {
            authenticate_at(
                &helper,
                "luma-auth-test",
                password,
                &registry,
                Path::new("/etc"),
            )
        };
        let mode = std::env::var("LUMA_PAM_TEST_MODE").unwrap();
        let result = observe(&password);
        if mode == "allow" {
            assert_eq!(result.unwrap().current_uid().unwrap(), 32001);
            let empty = PrivateBuffer::new(LIMIT + 1).unwrap();
            assert!(observe(&empty).is_err());
            assert!(authenticate_at(
                &helper,
                "luma-absent",
                &password,
                &registry,
                Path::new("/etc")
            )
            .is_err());
            password.bytes_mut()[0] ^= 1;
            assert!(observe(&password).is_err());
            assert!(
                authenticate_at(&helper, "root", &password, &registry, Path::new("/etc")).is_err()
            );
            password.bytes_mut()[0] ^= 1;
            let bound = observe(&password).unwrap();
            let identity = bound.identity().unwrap();
            assert_eq!(identity["uid"], 32001);
            assert_eq!(identity["login"], "luma-auth-test");
            assert_eq!(identity["generation"], 1);
            assert!(identity.get("account_digest").is_none());
            // The ignored fixture is isolated and owns this exact test account.
            // Locking its credential after PAM must revoke the observation.
            assert!(Command::new("/usr/sbin/usermod")
                .args(["--lock", "luma-auth-test"])
                .status()
                .unwrap()
                .success());
            assert!(bound.current_uid().is_err());
            assert!(bound.identity().is_err());
            assert!(Command::new("/usr/sbin/usermod")
                .args(["--unlock", "luma-auth-test"])
                .status()
                .unwrap()
                .success());
            assert!(bound.current_uid().is_err()); // Unlock cannot revive an invalidated observation.
            let logged_out = observe(&password).unwrap();
            assert_eq!(logged_out.current_uid().unwrap(), 32001);
            logged_out.logout();
            logged_out.logout();
            assert!(logged_out.current_uid().is_err());
            assert!(logged_out.identity().is_err());
            assert_eq!(observe(&password).unwrap().current_uid().unwrap(), 32001);
            let mut expired = observe(&password).unwrap();
            expired.lifetime = session::Lifetime::expired_fixture().unwrap();
            assert!(expired.current_uid().is_err());
            assert!(expired.identity().is_err());
            let replaced = observe(&password).unwrap();
            let retained_registry = std::fs::read(&registry).unwrap();
            crate::platform::write_atomic(&registry, &retained_registry, 0o600).unwrap();
            assert!(replaced.current_uid().is_err());
            assert!(replaced.identity().is_err());
            assert_eq!(observe(&password).unwrap().current_uid().unwrap(), 32001);
            crate::platform::write_atomic(&registry, &retained_registry, 0o600).unwrap();
            assert!(replaced.current_uid().is_err());
        } else {
            assert!(result.is_err());
        }
    }
}
