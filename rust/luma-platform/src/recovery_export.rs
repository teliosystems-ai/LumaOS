//! Descriptor-bound, no-overwrite recovery archive publication. An interrupted
//! export stays visibly partial; existing operator data is never cleaned up.
use crate::Result;
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

const PARTIAL: &[u8] = b"luma-user-data.tar.partial\0";
const FINAL: &[u8] = b"luma-user-data.tar\0";

fn open_directory(destination: &Path) -> Result<File> {
    if !destination.is_absolute() || destination == Path::new("/") {
        return Err("export requires a non-root absolute directory".into());
    }
    let mut directory = File::open("/")?;
    for component in destination.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes())?,
            _ => return Err("export path must not contain parent traversal".into()),
        };
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(
            "export directory must be owned by the operator and not writable by others".into(),
        );
    }
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("export destination is busy or does not support locking".into());
    }
    Ok(directory)
}

pub fn export(data: &Path, destination: &Path) -> Result<()> {
    archive(destination, |output| {
        let status = Command::new("/usr/bin/tar")
            .env_clear()
            .args(["--one-file-system", "--numeric-owner", "-cf", "-", "-C"])
            .arg(data)
            .args(["home", "lib/luma-os"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .status()?;
        if !status.success() {
            return Err("data export producer failed".into());
        }
        Ok(())
    })
}

fn archive(destination: &Path, write: impl FnOnce(&File) -> Result<()>) -> Result<()> {
    let directory = open_directory(destination)?;
    // Enumerate the pinned descriptor, not a path which could have been renamed.
    let inventory = format!("/proc/self/fd/{}", directory.as_raw_fd());
    if fs::read_dir(&inventory)?.next().is_some() {
        return Err("export requires an empty directory; retain prior partials separately".into());
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            PARTIAL.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let output = unsafe { File::from_raw_fd(fd) };
    let metadata = output.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err("export filesystem cannot protect the plaintext partial archive".into());
    }
    directory.sync_all()?;
    // Failure intentionally retains the exact partial, with no automatic retry
    // or deletion. No final filename exists until the producer and fsync succeed.
    write(&output).map_err(|error| {
        format!("export incomplete; retain luma-user-data.tar.partial: {error}")
    })?;
    output.sync_all()?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            PARTIAL.as_ptr().cast(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let current = unsafe { File::from_raw_fd(fd) }.metadata()?;
    let written = output.metadata()?;
    if current.dev() != written.dev()
        || current.ino() != written.ino()
        || written.nlink() != 1
        || written.mode() & 0o077 != 0
    {
        return Err("partial export identity or permissions changed; publication refused".into());
    }
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            PARTIAL.as_ptr().cast(),
            directory.as_raw_fd(),
            FINAL.as_ptr().cast(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err("export publication refused; existing output and partial retained".into());
    }
    // A failure here is an uncertain durability outcome, never a success report.
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("luma-export-{label}-{}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only a unique fixture directory created by this test.
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn publishes_only_completed_private_bytes_and_refuses_reuse() {
        let f = Fixture::new("success");
        archive(&f.0, |mut output| {
            output.write_all(b"completed archive")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            fs::read(f.0.join("luma-user-data.tar")).unwrap(),
            b"completed archive"
        );
        assert_eq!(
            fs::metadata(f.0.join("luma-user-data.tar")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(!f.0.join("luma-user-data.tar.partial").exists());
        assert!(archive(&f.0, |_| panic!("must not enter writer")).is_err());
    }

    #[test]
    fn failed_producer_retains_partial_without_final_or_automatic_retry() {
        let f = Fixture::new("failure");
        assert!(archive(&f.0, |mut output| {
            output.write_all(b"incomplete")?;
            Err("injected producer failure".into())
        })
        .is_err());
        assert!(!f.0.join("luma-user-data.tar").exists());
        assert_eq!(
            fs::read(f.0.join("luma-user-data.tar.partial")).unwrap(),
            b"incomplete"
        );
        assert!(archive(&f.0, |_| panic!("partial must fence retry")).is_err());
    }

    #[test]
    fn competing_export_and_concurrent_final_are_not_overwritten() {
        let f = Fixture::new("concurrent");
        assert!(archive(&f.0, |mut output| {
            assert!(archive(&f.0, |_| panic!("competing writer")).is_err());
            output.write_all(b"new archive")?;
            fs::write(f.0.join("luma-user-data.tar"), b"operator data")?;
            Ok(())
        })
        .is_err());
        assert_eq!(
            fs::read(f.0.join("luma-user-data.tar")).unwrap(),
            b"operator data"
        );
        assert_eq!(
            fs::read(f.0.join("luma-user-data.tar.partial")).unwrap(),
            b"new archive"
        );
    }

    #[test]
    fn refuses_linked_paths_and_other_writable_destinations() {
        let f = Fixture::new("path");
        let destination = f.0.join("destination");
        fs::create_dir(&destination).unwrap();
        symlink(&destination, f.0.join("link")).unwrap();
        for path in [
            f.0.join("link"),
            f.0.join("link/subdir"),
            f.0.join("destination/.."),
            std::path::PathBuf::from("relative"),
            std::path::PathBuf::from("/"),
        ] {
            assert!(archive(&path, |_| panic!("unsafe destination")).is_err());
        }
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(archive(&destination, |_| panic!("writable destination")).is_err());
    }

    #[test]
    fn directory_rename_cannot_redirect_output() {
        let f = Fixture::new("rename");
        let original = f.0.join("original");
        let moved = f.0.join("moved");
        fs::create_dir(&original).unwrap();
        archive(&original, |mut output| {
            fs::rename(&original, &moved)?;
            fs::create_dir(&original)?;
            output.write_all(b"pinned directory")?;
            Ok(())
        })
        .unwrap();
        assert!(fs::read_dir(&original).unwrap().next().is_none());
        assert_eq!(
            fs::read(moved.join("luma-user-data.tar")).unwrap(),
            b"pinned directory"
        );
    }

    #[test]
    fn changed_partial_identity_or_new_hardlink_prevents_publication() {
        for attack in ["replace", "hardlink"] {
            let f = Fixture::new(attack);
            assert!(archive(&f.0, |mut output| {
                output.write_all(b"original")?;
                let partial = f.0.join("luma-user-data.tar.partial");
                if attack == "replace" {
                    fs::rename(&partial, f.0.join("retained"))?;
                    fs::write(&partial, b"replacement")?;
                } else {
                    fs::hard_link(&partial, f.0.join("extra-link"))?;
                }
                Ok(())
            })
            .is_err());
            assert!(!f.0.join("luma-user-data.tar").exists());
        }
    }

    #[test]
    fn actual_tar_round_trip_and_failed_producer_have_distinct_publication() {
        let f = Fixture::new("tar");
        let data = f.0.join("data");
        fs::create_dir_all(data.join("home/user")).unwrap();
        fs::create_dir_all(data.join("lib/luma-os")).unwrap();
        fs::write(data.join("home/user/sentinel"), b"acknowledged data").unwrap();
        fs::write(data.join("lib/luma-os/state"), b"public fixture state").unwrap();
        let destination = f.0.join("success");
        fs::create_dir(&destination).unwrap();
        export(&data, &destination).unwrap();
        let output = Command::new("/usr/bin/tar")
            .arg("-xOf")
            .arg(destination.join("luma-user-data.tar"))
            .arg("home/user/sentinel")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"acknowledged data");
        let failed = f.0.join("failure");
        fs::create_dir(&failed).unwrap();
        assert!(export(&f.0.join("absent-source"), &failed).is_err());
        assert!(!failed.join("luma-user-data.tar").exists());
        assert!(failed.join("luma-user-data.tar.partial").is_file());
    }

    #[test]
    #[ignore = "requires a disposable container and private mount namespace with CAP_SYS_ADMIN"]
    fn actual_full_filesystem_retains_partial_and_never_publishes_final() {
        assert_eq!(std::env::var("LUMA_EXPORT_MOUNT_TEST").as_deref(), Ok("1"));
        assert!(Path::new("/.dockerenv").is_file());
        let f = Fixture::new("enospc");
        let mounted = f.0.join("destination");
        fs::create_dir(&mounted).unwrap();
        assert!(Command::new("/usr/bin/mount")
            .args([
                "-t",
                "tmpfs",
                "-o",
                "size=1048576,mode=0700,nodev,nosuid,noexec",
                "tmpfs"
            ])
            .arg(&mounted)
            .status()
            .unwrap()
            .success());
        struct Mount(std::path::PathBuf);
        impl Drop for Mount {
            fn drop(&mut self) {
                assert!(Command::new("/usr/bin/umount")
                    .arg(&self.0)
                    .status()
                    .unwrap()
                    .success());
            }
        }
        let _mount = Mount(mounted.clone());
        let mut observed_enospc = false;
        assert!(archive(&mounted, |mut output| {
            match output.write_all(&vec![0x5a; 2 * 1024 * 1024]) {
                Ok(()) => Err("expected bounded filesystem exhaustion".into()),
                Err(error) => {
                    observed_enospc = error.raw_os_error() == Some(libc::ENOSPC);
                    Err(error.into())
                }
            }
        })
        .is_err());
        assert!(observed_enospc);
        assert!(!mounted.join("luma-user-data.tar").exists());
        assert!(
            fs::metadata(mounted.join("luma-user-data.tar.partial"))
                .unwrap()
                .len()
                > 0
        );
        assert!(archive(&mounted, |_| panic!("partial must fence retry")).is_err());
    }
}
