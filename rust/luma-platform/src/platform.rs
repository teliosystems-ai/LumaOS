use crate::{
    bundle::{self, Manifest, VerifiedBundle},
    disk::{command, Disk},
    Result,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
fn live() -> Result<bool> {
    Ok(cmdline()?.split_whitespace().any(|a| a == "luma.mode=live"))
}

fn require_live() -> Result<()> {
    crate::require_root()?;
    if !live()? {
        return Err(
            "installation and offline recovery require the booted Luma recovery image".into(),
        );
    }
    Ok(())
}

pub(crate) fn write_atomic(destination: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = destination.parent().ok_or("missing parent")?;
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let temporary = destination.with_extension(format!("new-{}", bundle::hex(&random)));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(temporary.clone());
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

struct Mount {
    at: PathBuf,
}
impl Mount {
    fn new(device: &Path, at: PathBuf, options: &str) -> Result<Self> {
        fs::create_dir_all(&at)?;
        command(
            "/usr/bin/mount",
            &["-o", options, path(device)?, path(&at)?],
        )?;
        Ok(Self { at })
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

fn install_slots(disk: &Disk, bundle: &VerifiedBundle, slots: &[char]) -> Result<()> {
    for slot in slots {
        println!("Writing and verifying system slot {slot}...");
        let (data, hash) = match slot {
            'a' => (2, 3),
            'b' => (4, 5),
            _ => return Err("invalid slot".into()),
        };
        disk.write_artifact(&bundle.path("root.ext4")?, data, bundle.manifest.root_bytes)?;
        disk.write_artifact(
            &bundle.path("root.verity")?,
            hash,
            bundle.manifest.hash_bytes,
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
    }
    Ok(())
}

fn publish_efi(esp: &Path, bundle: &VerifiedBundle, slots: &[char], trial: char) -> Result<()> {
    let linux = esp.join("EFI/Linux");
    fs::create_dir_all(&linux)?;
    let loader = esp.join("EFI/BOOT");
    fs::create_dir_all(&loader)?;
    if !loader.join("BOOTX64.EFI").exists() {
        write_atomic(
            &loader.join("BOOTX64.EFI"),
            &fs::read(bundle.path("bootloader.efi")?)?,
            0o600,
        )?;
    }
    for slot in slots {
        let source = bundle.path(&format!("slot-{slot}.efi"))?;
        let suffix = if *slot == trial { "+3" } else { "" };
        let name = format!("luma-{slot}-{:020}{suffix}.efi", bundle.manifest.sequence);
        write_atomic(&linux.join(&name), &fs::read(source)?, 0o600)?;
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
                fs::remove_file(entry.path())?;
            }
        }
    }
    fs::create_dir_all(esp.join("loader"))?;
    // Firmware receives no automatic key enrollment or boot-order mutation.
    let config = loader_config(trial, bundle.manifest.sequence, true);
    write_atomic(&esp.join("loader/loader.conf"), config.as_bytes(), 0o600)?;
    File::open(esp)?.sync_all()?;
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
    use std::os::unix::fs::MetadataExt;
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
    require_live()?;
    // Local TPM2 is the selected installation profile. This is read-only,
    // before target admission or credentials, and never selects a fallback.
    let admin_admission = crate::tpm::installation_admission()?;
    let disk = Disk::open(selection, false)?;
    // Observe available RAM before the live installer's verified bundle
    // snapshot temporarily occupies memory-backed staging. Recheck again
    // after releasing that snapshot and before acquiring any model bytes.
    let model = crate::model::choose(model_id, disk.identity.bytes)?;
    let verified = bundle::verify(source)?;
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
    println!("Release {}: EFI 1 GiB; two {} MiB roots and {} MiB hash partitions; remaining space encrypted.",verified.manifest.release,roots_mib,hashes_mib);
    println!("Admin profile: local-tpm2. Laboratory limitation: sealed product Admin enrollment remains required and unavailable; this install creates only separate Unix accounts, not active product Admin authority.");
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
    println!("Initializing encrypted identity and application state...");
    let root = Mount::new(
        &disk.partition(2)?,
        staging.join("root"),
        "ro,nodev,nosuid,noexec",
    )?;
    command(
        "/usr/bin/cp",
        &[
            "-a",
            &format!("{}/usr/share/luma-os/var-template/.", path(&root.at)?),
            path(&data.at)?,
        ],
    )?;
    create_identity(&data.at, &user, &admin, &user_password, &admin_password)?;
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
    let esp = Mount::new(
        &disk.partition(1)?,
        staging.join("esp"),
        "nodev,nosuid,noexec,umask=0077",
    )?;
    publish_efi(&esp.at, &verified, &['a', 'b'], 'a')?;
    command("/usr/bin/sync", &[])?;
    drop(root);
    drop(verified);
    if let Some(profile) = model {
        if let Err(error) = crate::model::provision(&data.at, &profile) {
            eprintln!("OS installation is bootable in manual mode, but the selected model was NOT installed. After boot and network setup, retry: sudo luma-platform model-install {}", profile.id);
            return Err(error);
        }
    }
    println!("ADMIN ENROLLMENT REQUIRED: local TPM2 hardware admission passed, but sealed product Admin enrollment is not implemented in this laboratory installer. The separate Unix administrator is not product Admin.");
    println!("INSTALLATION COMPLETE: remove recovery media and boot the selected disk. Secure Boot requires the laboratory certificate to be enrolled by the operator. Keep the independent recovery passphrase offline.");
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

pub fn update(source: &Path) -> Result<()> {
    crate::require_root()?;
    let verified = bundle::verify(source)?;
    let current: Manifest = serde_json::from_slice(&fs::read("/var/lib/luma-os/installed.json")?)?;
    if verified.manifest.sequence <= current.sequence {
        return Err("update sequence must increase".into());
    }
    let pending = Path::new("/var/lib/luma-os/pending.json");
    if pending.exists() {
        return Err("an update already requires boot or explicit recovery reconciliation".into());
    }
    let slot = if running_slot()? == 'a' { 'b' } else { 'a' };
    let disk = running_disk()?;
    verify_esp(&disk)?;
    println!(
        "Update {} to {} on inactive slot {slot}.",
        current.release, verified.manifest.release
    );
    disk.confirm("UPDATE")?;
    write_atomic(pending, &serde_json::to_vec(&verified.manifest)?, 0o600)?;
    install_slots(&disk, &verified, &[slot])?;
    publish_efi(Path::new("/efi"), &verified, &[slot], slot)?;
    println!("Inactive slot staged for at most three trial boots. Reboot when ready.");
    Ok(())
}

pub fn recover(args: &[String]) -> Result<()> {
    require_live()?;
    let action = &args[0];
    let disk = Disk::open(&args[1], false)?;
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
        let verified = bundle::verify(Path::new(&args[2]))?;
        disk.confirm("REPAIR")?;
        let slot = if action == "repair-a" { 'a' } else { 'b' };
        install_slots(&disk, &verified, &[slot])?;
        let staging = bundle::private_dir("repair")?;
        let esp = Mount::new(
            &disk.partition(1)?,
            staging.join("esp"),
            "nodev,nosuid,noexec,umask=0077",
        )?;
        publish_efi(&esp.at, &verified, &[slot], slot)?;
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
        if !destination.is_absolute()
            || fs::symlink_metadata(destination)?.file_type().is_symlink()
            || !destination.is_dir()
            || fs::read_dir(destination)?.next().is_some()
        {
            return Err("export destination must be an existing empty absolute directory".into());
        }
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination.join("luma-user-data.tar"))?;
        let status = Command::new("/usr/bin/tar")
            .env_clear()
            .args([
                "--one-file-system",
                "--numeric-owner",
                "-cf",
                "-",
                "-C",
                path(&data.at)?,
                "home",
                "lib/luma-os",
            ])
            .stdout(Stdio::from(output.try_clone()?))
            .status()?;
        if !status.success() {
            return Err("data export failed".into());
        }
        output.sync_all()?;
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

pub fn boot_health() -> Result<()> {
    crate::require_root()?;
    if live()? {
        return Err("recovery media cannot acknowledge installed boot health".into());
    }
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
    let pending = Path::new("/var/lib/luma-os/pending.json");
    let mut acknowledged: Manifest =
        serde_json::from_slice(&fs::read("/var/lib/luma-os/installed.json")?)?;
    let mut failed = None;
    if pending.exists() {
        let manifest: Manifest = serde_json::from_slice(&fs::read(pending)?)?;
        let installed_release = fs::read_to_string("/usr/share/luma-os/release-id")?;
        if installed_release.trim() == manifest.release {
            acknowledged = manifest;
        } else {
            if installed_release.trim() != acknowledged.release {
                return Err("running release is neither current nor pending".into());
            }
            // A failed trial fell back to the previously acknowledged root.
            // Retain evidence, clear the pending transaction and select that root.
            failed = Some(manifest);
        }
    }
    // Do not replace the last acknowledged manifest before blessing succeeds.
    // A crash after blessing leaves pending available for idempotent promotion.
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
