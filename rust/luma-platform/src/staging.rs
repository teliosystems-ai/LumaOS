//! Bounded, restart-reconcilable private bundle snapshots. Not a generic janitor.
//! The exclusive lock remains held until the verified bytes are no longer used.
use crate::{bundle, Result};
use serde::Serialize;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const BASE: &str = "/var/lib/luma-os/staging";
const NAMESPACE: &str = "verified-v1";
const MAX_ORPHANS: usize = 32;
const RESERVE: u64 = 64 * 1024 * 1024;
// Live staging must leave RAM for the OS and cryptsetup's memory-hard KDF.
// This admission observation is not an atomic memory lease or OOM guarantee.
const MEMORY_RESERVE: u64 = 2 * 1024 * 1024 * 1024;
const MEMBERS: [&str; 8] = [
    "release.json",
    "release.sig",
    "root.ext4",
    "root.verity",
    "slot-a.efi",
    "slot-b.efi",
    "bootloader.efi",
    "secureboot.cer",
];

#[derive(Default, Serialize)]
pub struct Report {
    pub removed_snapshots: usize,
    pub removed_files: usize,
    pub removed_logical_bytes: u64,
}

fn private_directory(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().ok_or("missing staging parent")?)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("unsafe private staging directory".into());
    }
    Ok(())
}

struct Locked {
    directory: PathBuf,
    _lock: File,
}

// st_dev alone does not distinguish same-filesystem bind mounts. fdinfo is
// supplied by the running Linux kernel; absence is a refusal, not a fallback.
pub(crate) fn mount_id(path: &Path) -> Result<u64> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let mut info = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut info)?;
    if info.len() > 4096 {
        return Err("oversized kernel mount identity".into());
    }
    Ok(info
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .ok_or("kernel mount identity unavailable")?
        .trim()
        .parse()?)
}

impl Locked {
    fn acquire(base: &Path) -> Result<Self> {
        private_directory(base)?;
        let directory = base.join(NAMESPACE);
        private_directory(&directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("lock"))?;
        let m = lock.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
        {
            return Err("unsafe snapshot lock".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("a verified bundle operation is active; cleanup refused".into());
        }
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    fn reconcile(&self) -> Result<Report> {
        let mut snapshots = Vec::new();
        let mut report = Report::default();
        // Validate the complete bounded inventory before deleting anything.
        // Never recurse into mountpoints, unknown directories or symlink targets.
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.file_name() == "lock" {
                continue;
            }
            if snapshots.len() == MAX_ORPHANS {
                return Err("snapshot inventory limit exceeded".into());
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid snapshot name")?;
            if !snapshot_name(name) {
                return Err("unknown snapshot staging entry; retained".into());
            }
            let path = entry.path();
            let files = inspect_snapshot(&self.directory, &path)?;
            for file in &files {
                report.removed_logical_bytes = report
                    .removed_logical_bytes
                    .checked_add(fs::symlink_metadata(file)?.len())
                    .ok_or("snapshot size overflow")?;
            }
            report.removed_files += files.len();
            snapshots.push((path, files));
        }
        for (path, files) in snapshots {
            remove_snapshot(&path, &files)?;
            report.removed_snapshots += 1;
        }
        File::open(&self.directory)?.sync_all()?;
        Ok(report)
    }
}

fn snapshot_name(name: &str) -> bool {
    name.strip_prefix("bundle-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn inspect_snapshot(parent: &Path, path: &Path) -> Result<Vec<PathBuf>> {
    if path.parent() != Some(parent)
        || !snapshot_name(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid snapshot path")?,
        )
    {
        return Err("snapshot escapes owned namespace".into());
    }
    let m = fs::symlink_metadata(path)?;
    let parent_mount = mount_id(parent)?;
    if !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.dev() != fs::symlink_metadata(parent)?.dev()
        || mount_id(path)? != parent_mount
    {
        return Err("unsafe snapshot directory; retained".into());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        if files.len() == MEMBERS.len() || !MEMBERS.contains(&name.to_str().unwrap_or("")) {
            return Err("unknown snapshot member; retained".into());
        }
        let member = entry.path();
        let f = fs::symlink_metadata(&member)?;
        if !f.is_file()
            || f.uid() != m.uid()
            || f.dev() != m.dev()
            || f.nlink() != 1
            || f.mode() & 0o077 != 0
            || mount_id(&member)? != parent_mount
        {
            return Err("unsafe snapshot member; retained".into());
        }
        files.push(member);
    }
    Ok(files)
}

fn remove_snapshot(path: &Path, files: &[PathBuf]) -> Result<()> {
    // All names are exact direct children validated under the held namespace lock.
    for file in files {
        fs::remove_file(file)?;
    }
    File::open(path)?.sync_all()?;
    fs::remove_dir(path)?;
    Ok(())
}

pub struct Snapshot {
    directory: PathBuf,
    owner: Locked,
}

impl Snapshot {
    pub fn create() -> Result<Self> {
        Self::create_at(Path::new(BASE))
    }

    fn create_at(base: &Path) -> Result<Self> {
        let owner = Locked::acquire(base)?;
        owner.reconcile()?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let directory = owner
            .directory
            .join(format!("bundle-{}", bundle::hex(&random)));
        DirBuilder::new().mode(0o700).create(&directory)?;
        File::open(&owner.directory)?.sync_all()?;
        Ok(Self { directory, owner })
    }

    pub fn path(&self) -> &Path {
        &self.directory
    }

    pub fn admit(&self, bytes: u64) -> Result<()> {
        let dir = File::open(&self.directory)?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(dir.as_raw_fd(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let available = stat
            .f_bavail
            .checked_mul(stat.f_frsize)
            .ok_or("free space overflow")?;
        check_capacity(bytes, available)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if filesystem.f_type == libc::TMPFS_MAGIC {
            check_memory(bytes, &fs::read_to_string("/proc/meminfo")?)?;
        }
        if stat.f_favail < (MEMBERS.len() + 1) as u64 {
            return Err("insufficient snapshot inode headroom".into());
        }
        Ok(())
    }
}

fn check_capacity(bytes: u64, available: u64) -> Result<()> {
    if bytes
        .checked_add(RESERVE)
        .ok_or("snapshot capacity overflow")?
        > available
    {
        return Err(format!("insufficient snapshot storage; no payload copied: payload {bytes} bytes, reserve {RESERVE} bytes, available {available} bytes; live media requires sufficient RAM-backed staging (desktop installation evaluation uses 6 GiB RAM)").into());
    }
    Ok(())
}

fn check_memory(bytes: u64, info: &str) -> Result<()> {
    let available = crate::model::memory(info, "MemAvailable")?;
    let required = bytes
        .checked_add(MEMORY_RESERVE)
        .ok_or("snapshot memory overflow")?;
    if available < required {
        return Err(format!("insufficient snapshot memory; no payload copied: payload {bytes} bytes, RAM reserve {MEMORY_RESERVE} bytes, available {available} bytes").into());
    }
    Ok(())
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        // Failure retains the snapshot for reconciliation; never broad recursive removal.
        let result = inspect_snapshot(&self.owner.directory, &self.directory)
            .and_then(|files| remove_snapshot(&self.directory, &files))
            .and_then(|()| {
                File::open(&self.owner.directory)?.sync_all()?;
                Ok(())
            });
        if let Err(error) = result {
            eprintln!("private snapshot retained: {error}");
        }
    }
}

pub fn clean() -> Result<Report> {
    crate::require_root()?;
    Locked::acquire(Path::new(BASE))?.reconcile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn temporary() -> PathBuf {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        let at = std::env::temp_dir().join(format!("luma-staging-test-{}", bundle::hex(&bytes)));
        DirBuilder::new().mode(0o700).create(&at).unwrap();
        at
    }

    fn member(at: &Path) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(at.join("root.ext4"))
            .unwrap();
        file.write_all(b"test payload").unwrap();
        file.sync_all().unwrap();
    }

    fn finish(at: &Path) {
        fs::remove_file(at.join(NAMESPACE).join("lock")).unwrap();
        fs::remove_dir(at.join(NAMESPACE)).unwrap();
        fs::remove_dir(at).unwrap();
    }

    #[test]
    fn active_snapshot_is_locked_and_normal_drop_reclaims() {
        let at = temporary();
        let snapshot = Snapshot::create_at(&at).unwrap();
        member(snapshot.path());
        assert!(Locked::acquire(&at).is_err());
        assert!(snapshot.path().join("root.ext4").exists());
        drop(snapshot);
        assert_eq!(
            Locked::acquire(&at)
                .unwrap()
                .reconcile()
                .unwrap()
                .removed_snapshots,
            0
        );
        finish(&at);
    }

    #[test]
    fn refuses_links_unknown_entries_and_nested_directories_without_partial_cleanup() {
        for attack in ["symlink", "hardlink", "directory", "unknown", "permissions"] {
            let at = temporary();
            let owner = Locked::acquire(&at).unwrap();
            let path = owner.directory.join(format!("bundle-{}", "a".repeat(32)));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            member(&path);
            let external = at.join("sentinel");
            fs::write(&external, b"must survive").unwrap();
            let target = path.join(if attack == "unknown" {
                "unknown"
            } else {
                "release.sig"
            });
            match attack {
                "symlink" => symlink(&external, &target).unwrap(),
                "hardlink" => fs::hard_link(&external, &target).unwrap(),
                "directory" => fs::create_dir(&target).unwrap(),
                "permissions" => {
                    fs::set_permissions(path.join("root.ext4"), fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                _ => fs::write(&target, b"unknown").unwrap(),
            }
            assert!(owner.reconcile().is_err(), "{attack}");
            assert_eq!(fs::read(&external).unwrap(), b"must survive");
            assert!(path.join("root.ext4").exists());
            match attack {
                "directory" => fs::remove_dir(&target).unwrap(),
                "permissions" => {
                    fs::set_permissions(path.join("root.ext4"), fs::Permissions::from_mode(0o600))
                        .unwrap()
                }
                _ => fs::remove_file(&target).unwrap(),
            }
            assert_eq!(owner.reconcile().unwrap().removed_snapshots, 1);
            fs::remove_file(external).unwrap();
            drop(owner);
            finish(&at);
        }
    }

    #[test]
    fn bounded_inventory_refuses_before_any_deletion() {
        let at = temporary();
        let owner = Locked::acquire(&at).unwrap();
        for i in 0..=MAX_ORPHANS {
            DirBuilder::new()
                .mode(0o700)
                .create(owner.directory.join(format!("bundle-{i:032x}")))
                .unwrap();
        }
        assert!(owner.reconcile().is_err());
        assert_eq!(
            fs::read_dir(&owner.directory).unwrap().count(),
            MAX_ORPHANS + 2
        );
        fs::remove_dir(owner.directory.join(format!("bundle-{:032x}", MAX_ORPHANS))).unwrap();
        assert_eq!(owner.reconcile().unwrap().removed_snapshots, MAX_ORPHANS);
        drop(owner);
        finish(&at);
    }

    #[test]
    fn capacity_boundaries_and_overflow_fail_closed() {
        assert!(check_capacity(1, RESERVE).is_err());
        check_capacity(1, RESERVE + 1).unwrap();
        assert!(check_capacity(u64::MAX, u64::MAX).is_err());
        let detail = check_capacity(1, RESERVE).unwrap_err().to_string();
        assert!(
            detail.contains("payload 1 bytes")
                && detail.contains(&format!("available {RESERVE} bytes"))
        );
    }

    #[test]
    fn tmpfs_admission_preserves_memory_reserve_and_rejects_bad_observations() {
        let payload = 3 * 1024 * 1024 * 1024;
        let required_kib = (payload + MEMORY_RESERVE) / 1024;
        check_memory(payload, &format!("MemAvailable: {required_kib} kB\n")).unwrap();
        assert!(
            check_memory(payload, &format!("MemAvailable: {} kB\n", required_kib - 1)).is_err()
        );
        for info in [
            "",
            "MemAvailable: 0 kB",
            "MemAvailable: 999999999 MB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert!(check_memory(payload, info).is_err());
        }
        assert!(check_memory(u64::MAX, "MemAvailable: 9999999 kB").is_err());
    }

    #[test]
    fn thousand_snapshot_cycles_leave_no_payloads() {
        // The parallel test harness also spawns processes. Between fork and
        // exec those children can briefly retain another thread's flock fd,
        // even with CLOEXEC. Test immediate release in an isolated process;
        // do not weaken the product's correct active-owner refusal or retry it
        // until it happens to pass.
        if std::env::var_os("LUMA_STAGING_CYCLE_CHILD").is_none() {
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "staging::tests::thousand_snapshot_cycles_leave_no_payloads",
                    "--test-threads=1",
                ])
                .env("LUMA_STAGING_CYCLE_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated cycles failed: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        let at = temporary();
        for _ in 0..1000 {
            let snapshot = Snapshot::create_at(&at).unwrap();
            member(snapshot.path());
            snapshot.admit(1).unwrap();
        }
        let owner = Locked::acquire(&at).unwrap();
        assert_eq!(fs::read_dir(&owner.directory).unwrap().count(), 1);
        assert_eq!(owner.reconcile().unwrap().removed_snapshots, 0);
        drop(owner);
        finish(&at);
    }

    #[test]
    fn child_holds_snapshot() {
        let Some(at) = std::env::var_os("LUMA_STAGING_TEST_CHILD") else {
            return;
        };
        let at = PathBuf::from(at);
        let snapshot = Snapshot::create_at(&at).unwrap();
        member(snapshot.path());
        fs::write(at.join("ready"), b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
        panic!("parent must kill this test child");
    }

    #[test]
    fn real_process_kill_releases_lock_and_reclaims_only_orphan() {
        let at = temporary();
        // Repeated SIGKILL, not a destructor simulation or power-loss claim.
        for _ in 0..8 {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "staging::tests::child_holds_snapshot"])
                .env("LUMA_STAGING_TEST_CHILD", &at)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !at.join("ready").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let ready = at.join("ready").exists();
            let busy = if ready {
                Locked::acquire(&at).is_err()
            } else {
                false
            };
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(ready && busy);
            fs::remove_file(at.join("ready")).unwrap();
            let report = Locked::acquire(&at).unwrap().reconcile().unwrap();
            assert_eq!(report.removed_snapshots, 1);
            assert_eq!(report.removed_files, 1);
            assert_eq!(report.removed_logical_bytes, 12);
        }
        finish(&at);
    }
}
