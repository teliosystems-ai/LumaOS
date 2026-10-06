//! Resolve the native ext4/LUKS storage throttle to systemd's whole-disk IO
//! controller identity using bounded, read-only kernel sysfs observations.
use crate::Result;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

struct Observation {
    crypt_slave: Option<String>,
    partition_parent: Option<String>,
    queue: bool,
}

fn identity(text: &str) -> Result<String> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let (major, minor) = text.split_once(':').ok_or("invalid block identity")?;
    for part in [major, minor] {
        if part.parse::<u32>().map_or(true, |v| v.to_string() != part) {
            return Err("noncanonical block identity".into());
        }
    }
    if major == "0" {
        return Err("storage is not block-backed".into());
    }
    Ok(text.into())
}

fn read(path: &Path) -> Result<String> {
    let mut text = String::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("unsafe kernel block attribute".into());
    }
    file.take(513).read_to_string(&mut text)?;
    if text.len() > 512 {
        return Err("oversized kernel block attribute".into());
    }
    Ok(text)
}

fn node(path: &Path) -> Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    if !resolved.starts_with("/sys/devices") {
        return Err("block path outside kernel device tree".into());
    }
    let file = File::open(&resolved)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let m = file.metadata()?;
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
        || stat.f_type != 0x62656572
        || !m.is_dir()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
    {
        return Err("trusted kernel sysfs unavailable".into());
    }
    Ok(resolved)
}

fn optional(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn observe(id: &str) -> Result<Observation> {
    let path = node(&Path::new("/sys/dev/block").join(identity(id)?))?;
    if identity(&read(&path.join("dev"))?)? != id {
        return Err("kernel block identity changed".into());
    }
    let crypt_slave = if optional(&path.join("dm"))? {
        if !read(&path.join("dm/uuid"))?.starts_with("CRYPT-") {
            return Err("unsupported non-crypt device-mapper storage topology".into());
        }
        let mut entries = fs::read_dir(path.join("slaves"))?;
        let slave = entries.next().ok_or("crypt storage slave missing")??;
        if entries.next().is_some() {
            return Err("ambiguous crypt storage topology".into());
        }
        Some(identity(&read(&node(&slave.path())?.join("dev"))?)?)
    } else {
        None
    };
    let partition_parent = if optional(&path.join("partition"))? {
        Some(identity(&read(
            &node(path.parent().ok_or("missing block parent")?)?.join("dev"),
        )?)?)
    } else {
        None
    };
    Ok(Observation {
        crypt_slave,
        partition_parent,
        queue: optional(&path.join("queue"))?,
    })
}

fn resolve(
    initial: &str,
    mut observation: impl FnMut(&str) -> Result<Observation>,
) -> Result<String> {
    let mut current = identity(initial)?;
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        if !seen.insert(current.clone()) {
            return Err("cyclic block storage topology".into());
        }
        let next = observation(&current)?;
        if let Some(slave) = next.crypt_slave {
            current = identity(&slave)?;
            continue;
        }
        if let Some(parent) = next.partition_parent {
            current = identity(&parent)?;
            continue;
        }
        if !next.queue {
            return Err("whole-disk IO queue unavailable".into());
        }
        return Ok(current);
    }
    Err("block topology exceeds supported bound".into())
}

pub(crate) fn device_for_path(path: &Path) -> Result<String> {
    let device = fs::metadata(path)?.dev();
    let initial = unsafe { format!("{}:{}", libc::major(device), libc::minor(device)) };
    resolve(&initial, observe)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_partition_resolves_to_the_physical_whole_disk_not_mapper_or_partition() {
        assert_eq!(
            resolve("253:0", |id| Ok(match id {
                "253:0" => Observation {
                    crypt_slave: Some("259:3".into()),
                    partition_parent: None,
                    queue: true
                },
                "259:3" => Observation {
                    crypt_slave: None,
                    partition_parent: Some("259:0".into()),
                    queue: false
                },
                "259:0" => Observation {
                    crypt_slave: None,
                    partition_parent: None,
                    queue: true
                },
                _ => return Err("unexpected block identity".into()),
            }))
            .unwrap(),
            "259:0"
        );
    }
    #[test]
    fn unknown_missing_cyclic_oversized_and_noncanonical_topologies_refuse() {
        assert!(resolve("253:0", |_| Err("missing kernel device".into())).is_err());
        assert!(resolve("253:0", |id| Ok(Observation {
            crypt_slave: Some(id.into()),
            partition_parent: None,
            queue: true
        }))
        .is_err());
        assert!(resolve("253:0", |_| Ok(Observation {
            crypt_slave: None,
            partition_parent: None,
            queue: false
        }))
        .is_err());
        assert!(resolve("8:0", |id| {
            let minor = id.split_once(':').unwrap().1.parse::<u32>().unwrap() + 1;
            Ok(Observation {
                crypt_slave: Some(format!("8:{minor}")),
                partition_parent: None,
                queue: true,
            })
        })
        .is_err());
        for text in ["0:1", "08:0", "8:00", "8:-1", "8:0:1", "4294967296:0"] {
            assert!(identity(text).is_err());
        }
    }
}
