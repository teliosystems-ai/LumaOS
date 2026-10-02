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
    writeln!(terminal.0, "Account password (authentication only):")?;
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
struct AuthenticatedAccount {
    binding: AccountBinding,
    completed: Instant,
}
fn fresh(completed: Instant) -> Result<()> {
    if completed.elapsed() > Duration::from_secs(30) {
        return Err("account authentication expired".into());
    }
    Ok(())
}
impl AuthenticatedAccount {
    fn current_uid(&self) -> Result<u32> {
        fresh(self.completed)?;
        self.binding.current_uid()
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
    let mut child = Helper(command.spawn()?);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("local account authentication denied".into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("local account authentication timed out".into());
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
    Ok(AuthenticatedAccount {
        binding,
        completed: Instant::now(),
    })
}

pub fn check(username: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    login(username)?;
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let password = password_from(terminal)?;
    let account = authenticate(Path::new(HELPER), username, &password)?;
    println!(
        "{}",
        serde_json::json!({"authenticated_uid":account.current_uid()?,
        "product_admin_active":false,"role_grant":false,"gate_closing":false})
    );
    Ok(())
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
        fresh(Instant::now()).unwrap();
        assert!(fresh(Instant::now() - Duration::from_secs(31)).is_err());
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
            // The ignored fixture is isolated and owns this exact test account.
            // Locking its credential after PAM must revoke the observation.
            assert!(Command::new("/usr/sbin/usermod")
                .args(["--lock", "luma-auth-test"])
                .status()
                .unwrap()
                .success());
            assert!(bound.current_uid().is_err());
            assert!(Command::new("/usr/sbin/usermod")
                .args(["--unlock", "luma-auth-test"])
                .status()
                .unwrap()
                .success());
            assert!(bound.current_uid().is_err()); // Unlock cannot revive an invalidated observation.
            let mut expired = observe(&password).unwrap();
            expired.completed = Instant::now() - Duration::from_secs(31);
            assert!(expired.current_uid().is_err());
        } else {
            assert!(result.is_err());
        }
    }
}
