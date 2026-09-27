use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn command(program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    if result.stdout.len() > 4 * 1024 * 1024 {
        return Err("tool output exceeded limit".into());
    }
    Ok(String::from_utf8(result.stdout)?)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    pub path: String,
    pub serial: String,
    pub wwn: String,
    pub bytes: u64,
    pub major_minor: String,
}

fn lsblk(path: Option<&Path>) -> Result<serde_json::Value> {
    // lsblk emits a flat JSON list unless NAME is selected or --tree is explicit.
    // Admission needs descendants beneath exactly one selected whole disk.
    let mut args = vec![
        "--json",
        "--tree",
        "--bytes",
        "--output",
        "PATH,TYPE,SIZE,RO,SERIAL,WWN,MOUNTPOINTS,MAJ:MIN",
    ];
    if let Some(p) = path {
        args.push(p.to_str().ok_or("non-UTF8 device path")?);
    }
    Ok(serde_json::from_str(&command("/usr/bin/lsblk", &args)?)?)
}

pub fn inventory() -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&lsblk(None)?)?);
    Ok(())
}

pub fn parent_disk(partition: &Path) -> Result<PathBuf> {
    let name = partition.file_name().ok_or("partition name missing")?;
    let sys = fs::canonicalize(Path::new("/sys/class/block").join(name))?;
    if !sys.join("partition").is_file() {
        return Err("expected a kernel partition device".into());
    }
    let parent = sys
        .parent()
        .and_then(Path::file_name)
        .ok_or("partition parent missing")?;
    let disk = Path::new("/dev").join(parent);
    if !fs::metadata(&disk)?.file_type().is_block_device() {
        return Err("partition parent is not a block device".into());
    }
    Ok(disk)
}

fn mounted(node: &serde_json::Value) -> bool {
    node["mountpoints"]
        .as_array()
        .map_or(false, |v| v.iter().any(|p| !p.is_null()))
        || node["children"]
            .as_array()
            .map_or(false, |v| v.iter().any(mounted))
}

pub fn identity(path: &Path, allow_mounted: bool) -> Result<Identity> {
    let value = lsblk(Some(path))?;
    let nodes = value["blockdevices"]
        .as_array()
        .ok_or("missing block inventory")?;
    if nodes.len() != 1 {
        return Err("ambiguous disk inventory".into());
    }
    let d = &nodes[0];
    if d["type"] != "disk" || d["ro"] != false || (!allow_mounted && mounted(d)) {
        return Err("target is not an unmounted writable whole disk".into());
    }
    let i = Identity {
        path: path.to_str().ok_or("invalid disk path")?.into(),
        serial: d["serial"].as_str().unwrap_or("").trim().into(),
        wwn: d["wwn"].as_str().unwrap_or("").trim().into(),
        bytes: d["size"].as_u64().ok_or("invalid disk size")?,
        major_minor: d["maj:min"]
            .as_str()
            .ok_or("invalid disk device identity")?
            .into(),
    };
    if i.serial.is_empty() && i.wwn.is_empty() {
        return Err("target has no hardware-reported serial or WWN".into());
    }
    Ok(i)
}

pub struct Disk {
    pub identity: Identity,
    handle: File,
    _operation_lock: File,
    allow_mounted: bool,
}

impl Disk {
    pub fn open(selection: &str, allow_mounted: bool) -> Result<Self> {
        crate::require_root()?;
        if !selection.starts_with("/dev/disk/by-id/") || selection.contains("..") {
            return Err("select an exact /dev/disk/by-id/ whole-disk identity".into());
        }
        let path = fs::canonicalize(selection)?;
        if !path.starts_with("/dev") || !fs::metadata(&path)?.file_type().is_block_device() {
            return Err("selected target is not a block device".into());
        }
        let original = identity(&path, allow_mounted)?;
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        // Do not flock the device across udev settlement: udev probes take that
        // same lock. Serialize our operations with a separate root-owned lock,
        // retain the device descriptor, and kernel-exclude each partition write.
        let lock_dir = Path::new("/run/luma-disk-locks");
        match fs::DirBuilder::new().mode(0o700).create(lock_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let meta = fs::symlink_metadata(lock_dir)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err("unsafe disk lock directory".into());
        }
        let operation_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_dir.join(original.major_minor.replace(':', "-")))?;
        if unsafe { libc::flock(operation_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("disk is locked by another operation".into());
        }
        // Check kernel holders before installation; each partition write
        // separately acquires an exclusive kernel open.
        // A whole-disk O_EXCL claim cannot coexist with dm-crypt partition claims.
        if !allow_mounted {
            let probe = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW)
                .open(&path)?;
            drop(probe);
        }
        let disk = Self {
            identity: original,
            handle,
            _operation_lock: operation_lock,
            allow_mounted,
        };
        disk.recheck()?;
        Ok(disk)
    }

    pub fn recheck(&self) -> Result<()> {
        let path = Path::new(&self.identity.path);
        if self.handle.metadata()?.rdev() != fs::metadata(path)?.rdev()
            || identity(path, self.allow_mounted)? != self.identity
        {
            return Err("disk identity, size, or mount disposition changed".into());
        }
        Ok(())
    }

    pub fn partition(&self, index: u8) -> Result<PathBuf> {
        if !(1..=6).contains(&index) {
            return Err("invalid partition index".into());
        }
        let suffix = if self.identity.path.ends_with(|c: char| c.is_ascii_digit()) {
            "p"
        } else {
            ""
        };
        let path = PathBuf::from(format!("{}{suffix}{index}", self.identity.path));
        let name = path.file_name().ok_or("partition name missing")?;
        let sys = fs::canonicalize(Path::new("/sys/class/block").join(name))?;
        let disk_name = Path::new(&self.identity.path)
            .file_name()
            .ok_or("disk name missing")?;
        if sys.parent().and_then(Path::file_name) != Some(disk_name)
            || !fs::metadata(&path)?.file_type().is_block_device()
        {
            return Err("partition is not a child of the held disk".into());
        }
        Ok(path)
    }

    pub fn reread_partitions(&self) -> Result<()> {
        // sgdisk's initial reread can start udev probes which briefly hold a
        // partition open. Settle those probes before retrying BLKRRPART. Use
        // the retained whole-disk descriptor, not a newly resolved path.
        // Linux UAPI linux/fs.h: BLKRRPART = _IO(0x12, 95).
        const BLKRRPART: libc::c_ulong = 0x125f;
        for attempt in 0..5 {
            command("/usr/bin/udevadm", &["settle", "--timeout=30"])?;
            self.recheck()?;
            if unsafe { libc::ioctl(self.handle.as_raw_fd(), BLKRRPART) } == 0 {
                command("/usr/bin/udevadm", &["settle", "--timeout=30"])?;
                return self.recheck();
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBUSY) || attempt == 4 {
                return Err(error.into());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err("partition reread did not complete".into())
    }

    pub fn confirm(&self, verb: &str) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(&self.identity)?);
        let token = if self.identity.wwn.is_empty() {
            &self.identity.serial
        } else {
            &self.identity.wwn
        };
        println!("{verb}. All affected data may be lost.\nType exactly: {verb} {token}");
        let response = crate::platform::console_line(false)?;
        if response != format!("{verb} {token}") {
            return Err("exact disk confirmation denied".into());
        }
        self.recheck()
    }

    pub fn write_artifact(&self, source: &Path, partition: u8, bytes: u64) -> Result<()> {
        self.recheck()?;
        let path = self.partition(partition)?;
        let size: u64 = command(
            "/usr/sbin/blockdev",
            &["--getsize64", path.to_str().ok_or("invalid path")?],
        )?
        .trim()
        .parse()?;
        if bytes > size {
            return Err("artifact exceeds partition capacity".into());
        }
        let mut input = File::open(source)?;
        if input.metadata()?.len() != bytes {
            return Err("artifact snapshot size changed".into());
        }
        let mut target = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW)
            .open(&path)?;
        let copied = std::io::copy(&mut input, &mut target)?;
        if copied != bytes {
            return Err("short artifact write".into());
        }
        target.flush()?;
        target.sync_all()?;
        // Full read-back against the verified private source before publishing boot selection.
        use sha2::{Digest, Sha256};
        let mut source = File::open(source)?;
        let mut target = File::open(path)?.take(bytes);
        let mut a = Sha256::new();
        let mut b = Sha256::new();
        std::io::copy(&mut source, &mut a)?;
        std::io::copy(&mut target, &mut b)?;
        if a.finalize() != b.finalize() {
            return Err("artifact read-back mismatch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descendants_and_swap_block_admission() {
        assert!(mounted(
            &serde_json::json!({"mountpoints": [null], "children": [{"mountpoints": ["[SWAP]"]}]})
        ));
        assert!(mounted(&serde_json::json!({"mountpoints": ["/"]})));
        assert!(!mounted(
            &serde_json::json!({"mountpoints": [null], "children": []})
        ));
    }
    #[test]
    fn rejects_broad_or_alias_selection_before_open() {
        for bad in ["/dev/sda", "/dev/disk/by-id/../../sda", "/", "*"] {
            assert!(Disk::open(bad, false).is_err());
        }
    }
}
