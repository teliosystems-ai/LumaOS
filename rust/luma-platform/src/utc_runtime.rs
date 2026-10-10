//! Immutable UTC producer admission and the fixed measurement endpoint.
//! A release manifest describes code, not a capability. Admission additionally
//! requires retained read-only file descriptors and live kernel confinement.
//! This module neither supplies a clock seed nor grants time-bound effects.
#![cfg_attr(not(test), allow(dead_code))]
use crate::{bundle, utc_policy::ApprovedPolicy, utc_receiver, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) const PRODUCER_ID: u32 = 987;
const MANIFEST: &str = "/usr/share/luma-os/utc/runtime.json";
const DIRECTORY: &str = "/run/luma-utc";
const SOCKET_NAME: &str = "measurements.sock";
const EXECUTABLE: &str = "/usr/libexec/luma-os/chronyd";
const CONFIGURATION: &str = "/usr/share/luma-os/utc/chrony.conf";
const REQUIRED: [(&str, &str); 6] = [
    ("executable", EXECUTABLE),
    ("configuration", CONFIGURATION),
    ("certificates", "/usr/share/luma-os/utc/ca-certificates.crt"),
    ("policy", "/usr/share/luma-os/utc/approved-policy.json"),
    (
        "service",
        "/usr/lib/systemd/system/luma-utc-producer.service",
    ),
    ("confinement", "/etc/apparmor.d/luma-utc-producer"),
];
const MAX_MANIFEST: u64 = 32 * 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 64;
const SYS_TIME: u64 = 1 << 25;
const CONFIGURATION_BYTES: &[u8] = include_bytes!("../../../native/image/utc/chrony.conf");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    policy_sha256: String,
    files: Vec<Artifact>,
}
fn canonical_path(path: &str) -> Result<()> {
    let value = Path::new(path);
    if !value.is_absolute()
        || path.len() > 256
        || path.bytes().any(|b| b <= 32 || b >= 127)
        || value
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || value.components().collect::<PathBuf>().to_str() != Some(path)
    {
        return Err("noncanonical UTC runtime path".into());
    }
    Ok(())
}
impl Manifest {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.policy_sha256 != bundle::hex(&ApprovedPolicy::fixed()?.digest())
            || !(REQUIRED.len() + 1..=MAX_FILES).contains(&self.files.len())
        {
            return Err("UTC runtime policy or inventory differs".into());
        }
        let mut roles = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut previous = None;
        let mut total = 0u64;
        for artifact in &self.files {
            canonical_path(&artifact.path)?;
            if artifact.path == MANIFEST
                || !paths.insert(&artifact.path)
                || previous.is_some_and(|old: &String| old >= &artifact.path)
                || artifact.bytes == 0
                || artifact.bytes > MAX_FILE
                || crate::tpm::decode::<32>(&artifact.sha256)? == [0; 32]
            {
                return Err("UTC runtime artifact is invalid or duplicated".into());
            }
            previous = Some(&artifact.path);
            total = total
                .checked_add(artifact.bytes)
                .ok_or("UTC runtime size overflow")?;
            if total > MAX_TOTAL {
                return Err("UTC runtime exceeds total size bound".into());
            }
            if artifact.role == "library" {
                let name = Path::new(&artifact.path)
                    .file_name()
                    .and_then(|v| v.to_str());
                if !artifact.path.starts_with("/usr/lib/x86_64-linux-gnu/")
                    || !name.is_some_and(|v| v.contains(".so") && !v.starts_with('.'))
                {
                    return Err("UTC runtime library path differs".into());
                }
            } else if !REQUIRED
                .iter()
                .any(|(role, path)| *role == artifact.role && *path == artifact.path)
                || !roles.insert(artifact.role.as_str())
            {
                return Err("UTC runtime contains an unapproved artifact role".into());
            }
        }
        if roles.len() != REQUIRED.len() {
            return Err("UTC runtime required artifact is absent".into());
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            links: m.nlink(),
            bytes: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}
struct Parent {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    mode: u32,
    gid: u32,
}
impl Parent {
    fn capture(path: PathBuf, file: File, mode: Option<(u32, u32)>) -> Result<Self> {
        let m = file.metadata()?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o7022 != 0
            || mode
                .is_some_and(|(permission, gid)| m.mode() & 0o7777 != permission || m.gid() != gid)
        {
            return Err("UTC runtime parent is not protected".into());
        }
        Ok(Self {
            path,
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            gid: m.gid(),
            file,
        })
    }
    fn recheck(&self) -> Result<()> {
        for m in [self.file.metadata()?, fs::symlink_metadata(&self.path)?] {
            if !m.is_dir()
                || m.uid() != 0
                || (m.dev(), m.ino(), m.mode(), m.gid())
                    != (self.device, self.inode, self.mode, self.gid)
            {
                return Err("UTC runtime parent changed".into());
            }
        }
        Ok(())
    }
}
fn open_at(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn readonly(file: &File) -> Result<()> {
    let mut info: libc::statvfs = unsafe { zeroed() };
    if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut info) } != 0
        || info.f_flag & libc::ST_RDONLY == 0
    {
        return Err("UTC runtime requires an immutable release filesystem".into());
    }
    Ok(())
}
pub(crate) struct Pin {
    path: PathBuf,
    file: File,
    identity: Identity,
    parents: Vec<Parent>,
}
impl Pin {
    pub(crate) fn immutable(path: &str, limit: u64, exact: Option<&[u8]>) -> Result<Self> {
        let pin = Self::open(Path::new(path), limit)?;
        pin.immutable_recheck()?;
        if exact.is_some_and(|expected| pin.bytes(limit).map_or(true, |bytes| bytes != expected)) {
            return Err("UTC immutable artifact differs from compiled release".into());
        }
        pin.immutable_recheck()?;
        Ok(pin)
    }
    pub(crate) fn immutable_recheck(&self) -> Result<()> {
        self.recheck()?;
        readonly(&self.file)
    }
    fn open(path: &Path, limit: u64) -> Result<Self> {
        canonical_path(path.to_str().ok_or("invalid UTC runtime path")?)?;
        let mut names = path.components().skip(1).collect::<Vec<_>>();
        let name = names.pop().ok_or("UTC runtime artifact cannot be root")?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let mut parents = vec![Parent::capture(PathBuf::from("/"), root, None)?];
        let mut current = PathBuf::from("/");
        for component in names {
            current.push(component.as_os_str());
            let file = open_at(&parents.last().unwrap().file, component.as_os_str(), true)?;
            parents.push(Parent::capture(current.clone(), file, None)?);
        }
        let file = open_at(&parents.last().unwrap().file, name.as_os_str(), false)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.nlink() != 1
            || m.mode() & 0o7022 != 0
            || m.len() == 0
            || m.len() > limit
        {
            return Err("UTC runtime artifact is not a bounded protected regular file".into());
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            identity: Identity::of(&m),
            parents,
        })
    }
    fn recheck(&self) -> Result<()> {
        for parent in &self.parents {
            parent.recheck()?;
        }
        if Identity::of(&self.file.metadata()?) != self.identity
            || Identity::of(&fs::symlink_metadata(&self.path)?) != self.identity
        {
            return Err("UTC runtime artifact changed".into());
        }
        Ok(())
    }
    fn bytes(&self, limit: u64) -> Result<Vec<u8>> {
        self.recheck()?;
        if self.identity.bytes > limit {
            return Err("UTC runtime document exceeds read bound".into());
        }
        let mut bytes = vec![0; usize::try_from(self.identity.bytes)?];
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(&mut bytes, 0)?;
        self.recheck()?;
        Ok(bytes)
    }
    fn digest(&self) -> Result<String> {
        use std::os::unix::fs::FileExt;
        self.recheck()?;
        let mut offset = 0;
        let mut block = [0; 65_536];
        let mut digest = Sha256::new();
        while offset < self.identity.bytes {
            let length = usize::try_from((self.identity.bytes - offset).min(block.len() as u64))?;
            self.file.read_exact_at(&mut block[..length], offset)?;
            digest.update(&block[..length]);
            offset += length as u64;
        }
        self.recheck()?;
        Ok(bundle::hex(&digest.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn manifest() -> Manifest {
        let mut files: Vec<_> = REQUIRED
            .iter()
            .map(|(role, path)| Artifact {
                role: (*role).into(),
                path: (*path).into(),
                bytes: 16,
                sha256: "ab".repeat(32),
            })
            .collect();
        files.push(Artifact {
            role: "library".into(),
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
            bytes: 16,
            sha256: "cd".repeat(32),
        });
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Manifest {
            schema_version: 1,
            policy_sha256: bundle::hex(&ApprovedPolicy::fixed().unwrap().digest()),
            files,
        }
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let path = root.join(format!("utc-runtime-{name}-{}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            path
        }
        fn deployment(&self) -> Deployment {
            let path = self.file("runtime.json", b"{}\n");
            Deployment {
                manifest: Pin::open(&path, MAX_MANIFEST).unwrap(),
                files: BTreeMap::new(),
                digest: "ab".repeat(32),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn exact_manifest_inventory_accepts_only_fixed_roles_and_canonical_paths() {
        manifest().validate().unwrap();
        for path in [
            "/a/../b", "/a/./b", "/a//b", "/a/", "relative", "/a b", "/a\n", "/a\0",
        ] {
            assert!(canonical_path(path).is_err(), "{path:?}");
        }
        canonical_path(EXECUTABLE).unwrap();
        for variant in 0..17 {
            let mut m = manifest();
            match variant {
                0 => m.schema_version = 2,
                1 => m.policy_sha256 = "00".repeat(32),
                2 => {
                    m.files.pop();
                }
                3 => m.files[0].role = "seed".into(),
                4 => m.files[0].path = MANIFEST.into(),
                5 => m.files[0].bytes = 0,
                6 => m.files[0].bytes = MAX_FILE + 1,
                7 => m.files[0].sha256 = "00".repeat(32),
                8 => m.files[0].sha256 = "AB".repeat(32),
                9 => m.files[0].sha256 = "ab".repeat(31),
                10 => m.files.swap(0, 1),
                11 => m.files[1].path = m.files[0].path.clone(),
                12 => {
                    m.files
                        .iter_mut()
                        .find(|v| v.role == "library")
                        .unwrap()
                        .path = "/var/evil.so".into()
                }
                13 => {
                    m.files
                        .iter_mut()
                        .find(|v| v.role == "library")
                        .unwrap()
                        .path = "/usr/lib/x86_64-linux-gnu/.evil.so".into()
                }
                14 => {
                    m.files
                        .iter_mut()
                        .find(|v| v.role == "library")
                        .unwrap()
                        .path = "/usr/lib/x86_64-linux-gnu/evil".into()
                }
                15 => {
                    for f in &mut m.files {
                        f.bytes = MAX_FILE;
                    }
                }
                16 => m.files.extend((0..MAX_FILES).map(|n| Artifact {
                    role: "library".into(),
                    path: format!("/usr/lib/x86_64-linux-gnu/lib{n}.so"),
                    bytes: 1,
                    sha256: "ab".repeat(32),
                })),
                _ => unreachable!(),
            }
            assert!(m.validate().is_err(), "variant {variant}");
        }
    }
    #[test]
    fn manifest_wire_is_closed_and_non_authorizing() {
        let m = manifest();
        let bytes = serde_json::to_vec(&m).unwrap();
        serde_json::from_slice::<Manifest>(&bytes)
            .unwrap()
            .validate()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for path in ["/trusted", "/pid", "/files/0/trusted"] {
            let mut changed = value.clone();
            if path.starts_with("/files") {
                changed["files"][0]["trusted"] = true.into();
            } else {
                changed[path.trim_start_matches('/')] = true.into();
            }
            assert!(serde_json::from_value::<Manifest>(changed).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(serde_json::from_str::<Manifest>(&duplicate).is_err());
    }
    #[test]
    fn retained_file_pin_detects_replacement_and_restored_in_place_bytes() {
        for variant in 0..4 {
            let fixture = Fixture::new(&format!("pin-{variant}"));
            let path = fixture.file("source", b"original bytes");
            let pin = Pin::open(&path, 128).unwrap();
            assert_eq!(pin.bytes(128).unwrap(), b"original bytes");
            assert!(pin.bytes(4).is_err());
            assert_eq!(
                pin.digest().unwrap(),
                bundle::hex(&Sha256::digest(b"original bytes"))
            );
            match variant {
                0 => {
                    let other = fixture.file("next", b"original bytes");
                    fs::rename(other, &path).unwrap();
                }
                1 => {
                    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.write_all(b"changed! bytes").unwrap();
                    file.seek(SeekFrom::Start(0)).unwrap();
                    file.write_all(b"original bytes").unwrap();
                    file.sync_all().unwrap();
                    let m = file.metadata().unwrap();
                    let times = [
                        libc::timespec {
                            tv_sec: 0,
                            tv_nsec: libc::UTIME_OMIT,
                        },
                        libc::timespec {
                            tv_sec: m.mtime() + 1,
                            tv_nsec: 0,
                        },
                    ];
                    assert_eq!(
                        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
                        0
                    );
                }
                2 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                3 => fs::hard_link(&path, fixture.0.join("linked")).unwrap(),
                _ => unreachable!(),
            }
            assert!(pin.recheck().is_err());
            assert!(pin.digest().is_err());
            assert!(pin.bytes(128).is_err());
        }
    }
    #[test]
    fn links_writable_parents_special_modes_and_size_bounds_refuse() {
        let fixture = Fixture::new("unsafe-files");
        let path = fixture.file("source", b"bytes");
        symlink(&path, fixture.0.join("link")).unwrap();
        assert!(Pin::open(&fixture.0.join("link"), 128).is_err());
        assert!(Pin::open(&path, 4).is_err());
        let empty = fixture.file("empty", b"");
        assert!(Pin::open(&empty, 128).is_err());
        for mode in [0o622, 0o662, 0o4600, 0o2600, 0o1600] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(Pin::open(&path, 128).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let pin = Pin::open(&path, 128).unwrap();
        assert!(readonly(&pin.file).is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(Pin::open(&path, 128).is_err());
        assert!(pin.recheck().is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn status() -> String {
        format!("Uid:\t987 987 987 987\nGid:\t987 987 987 987\nCapInh:\t0000000000000000\nCapPrm:\t0000000002000000\nCapEff:\t0000000002000000\nCapBnd:\t0000000002000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
    }
    #[test]
    fn confinement_controls_are_admitted_not_merely_fingerprinted() {
        controls(&status()).unwrap();
        for (from, to) in [
            ("987 987 987 987", "987 987 0 987"),
            ("Seccomp:\t2", "Seccomp:\t0"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("0000000002000000", "0000000002000001"),
            ("0000000002000000", "000000000200000A"),
            ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
        ] {
            assert!(controls(&status().replace(from, to)).is_err());
        }
        assert!(controls(&(status() + "Seccomp:\t2\n")).is_err());
        assert!(controls(&status().replace("Seccomp:\t2\n", "")).is_err());
    }
    #[test]
    fn environment_rejects_loader_tls_nss_and_noncanonical_controls() {
        environment(b"LANG=C\0LC_ALL=C\0TZ=UTC\0PATH=/usr/sbin:/usr/bin:/sbin:/bin\0SYSTEMD_EXEC_PID=42\0INVOCATION_ID=abababababababababababababababab\0JOURNAL_STREAM=8:9\0", 42).unwrap();
        environment(b"", 42).unwrap();
        for value in [
            b"LD_PRELOAD=/tmp/a.so\0".as_slice(),
            b"GNUTLS_SYSTEM_PRIORITY_FILE=/tmp/a\0",
            b"NSS_WRAPPER_PASSWD=/tmp/a\0",
            b"LANG=C.UTF-8\0",
            b"TZ=local\0",
            b"SYSTEMD_EXEC_PID=43\0",
            b"LANG=C\0LANG=C\0",
            b"LANG=C",
            b"INVOCATION_ID=ab\0",
            b"JOURNAL_STREAM=8:a\0",
            b"invalid\0",
        ] {
            assert!(environment(value, 42).is_err(), "{value:?}");
        }
        assert!(environment(&[b'X'; 257], 42).is_err());
        assert_eq!(command_line().split(|b| *b == 0).count(), 10);
    }
    fn mapping_identity() -> Identity {
        Identity {
            device: libc::makedev(8, 1),
            inode: 7,
            mode: 0o100555,
            uid: 0,
            gid: 0,
            links: 1,
            bytes: 8192,
            modified: (0, 0),
            changed: (0, 0),
        }
    }
    fn maps() -> String {
        format!("1000-2000 r-xp 00000000 08:01 7 {EXECUTABLE}\n2000-3000 rw-p 00001000 08:01 7 {EXECUTABLE}\n3000-4000 rw-p 00000000 00:00 0 [heap]\n4000-5000 r-xp 00000000 00:00 0 [vdso]\n5000-6000 r--p 00000000 00:00 0 [vvar]\n")
    }
    #[test]
    fn executable_mapping_inventory_refuses_injection_substitution_and_ambiguity() {
        let identity = mapping_identity();
        let inventory = BTreeMap::from([(EXECUTABLE, &identity)]);
        mapping_inventory(&maps(), &inventory, 0x4000).unwrap();
        for permissions in ["--xp", "r-xp"] {
            let legacy = maps()
                + &format!(
                    "ffffffffff600000-ffffffffff601000 {permissions} 00000000 00:00 0 [vsyscall]\n"
                );
            mapping_inventory(&legacy, &inventory, 0x4000).unwrap();
            assert!(mapping_inventory(
                &legacy.replace("ffffffffff600000", "ffffffffff500000"),
                &inventory,
                0x4000
            )
            .is_err());
            assert!(
                mapping_inventory(&legacy.replace(permissions, "rwxp"), &inventory, 0x4000)
                    .is_err()
            );
        }
        for (from, to) in [
            ("r-xp", "rwxp"),
            ("08:01 7", "08:02 7"),
            ("08:01 7", "08:01 8"),
            ("00001000", "00002000"),
            ("[vdso]", "[vsyscall]"),
            ("[heap]", "/tmp/a"),
            ("3000-4000", "1000-4000"),
            ("1000-2000", "2000-1000"),
            ("r-xp", "r-xs"),
            (EXECUTABLE, "/var/evil"),
            ("[vdso]", ""),
            ("[vvar]", "[vvar] trailing"),
        ] {
            assert!(
                mapping_inventory(&maps().replace(from, to), &inventory, 0x4000).is_err(),
                "{from} -> {to}"
            );
        }
        assert!(mapping_inventory(&maps(), &inventory, 0x9000).is_err());
        assert!(mapping_inventory("", &inventory, 0x4000).is_err());
        assert!(mapping_inventory(
            &(maps() + "6000-7000 r-xp 00000000 00:00 0\n"),
            &inventory,
            0x4000
        )
        .is_err());
        assert!(mapping_inventory(
            &(maps() + &"7000-8000 ---p 00000000 00:00 0\n".repeat(513)),
            &inventory,
            0x4000
        )
        .is_err());
    }
    fn auxv(entries: &[(u64, u64)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(key, value)| [key.to_ne_bytes(), value.to_ne_bytes()].concat())
            .collect()
    }
    #[test]
    fn vdso_requires_unique_kernel_auxiliary_identity_and_terminator() {
        let valid = auxv(&[(libc::AT_SYSINFO_EHDR, 0x4000), (0, 0)]);
        assert_eq!(vdso_address(&valid).unwrap(), 0x4000);
        for bytes in [
            vec![],
            valid[..31].to_vec(),
            auxv(&[(0, 0)]),
            auxv(&[(libc::AT_SYSINFO_EHDR, 0)]),
            auxv(&[(libc::AT_SYSINFO_EHDR, 0x4000)]),
            auxv(&[
                (libc::AT_SYSINFO_EHDR, 0x4000),
                (libc::AT_SYSINFO_EHDR, 0x4000),
                (0, 0),
            ]),
            auxv(&[(libc::AT_SYSINFO_EHDR, 0x4000), (0, 1)]),
            auxv(&[(libc::AT_SYSINFO_EHDR, 0x4000), (0, 0), (1, 1)]),
        ] {
            assert!(vdso_address(&bytes).is_err());
        }
    }
    #[test]
    fn installed_admission_never_accepts_mutable_fixture_or_caller_runtime_digest() {
        assert!(Deployment::installed().is_err());
        let fixture = Fixture::new("deployment-refusal");
        let deployment = fixture.deployment();
        assert_eq!(deployment.digest(), "ab".repeat(32));
        assert!(deployment.recheck().is_err());
        assert!(deployment.producer(std::process::id() as i32).is_err());
        assert!(Endpoint::bind(deployment).is_err());
        assert!(proc_bytes(&fixture.0.join("runtime.json"), 128).is_err());
        assert!(tasks(&fixture.0).is_err());
    }
    #[test]
    fn runtime_endpoint_preserves_socket_and_rejects_forged_acquisition() {
        let fixture = Fixture::new("acquisition-refusal");
        let path = fixture.0.join(SOCKET_NAME);
        let socket = UnixDatagram::bind(&path).unwrap();
        utc_receiver::configure(&socket).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender.send_to(b"not a measurement", &path).unwrap();
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&fixture.0)
            .unwrap();
        let identity = Identity::of(&fs::symlink_metadata(&path).unwrap());
        let deployment = fixture.deployment();
        let endpoint = Endpoint {
            socket,
            admission: Admission {
                deployment,
                endpoint: SocketPin {
                    parent: Parent::capture(fixture.0.clone(), parent, None).unwrap(),
                    path: path.clone(),
                    identity,
                },
            },
            barrier_ms: 1,
            boundary: Boundary {
                clock: utc_receiver::Receiver::clock(0).unwrap(),
                watch: crate::utc_step_watch::StepWatch::arm().unwrap(),
            },
        };
        assert_eq!(endpoint.admission.digest(), "ab".repeat(32));
        assert!(endpoint.acquire().is_err());
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        assert!(UnixDatagram::bind(&path).is_err());
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&fixture.0)
            .unwrap();
        let pin = SocketPin {
            parent: Parent::capture(fixture.0.clone(), parent, None).unwrap(),
            path: path.clone(),
            identity: Identity::of(&fs::symlink_metadata(&path).unwrap()),
        };
        pin.recheck().unwrap();
        fs::rename(&path, fixture.0.join("retained.sock")).unwrap();
        let replacement = UnixDatagram::bind(&path).unwrap();
        assert!(pin.recheck().is_err());
        drop(replacement);
    }
    #[test]
    fn descriptor_relative_socket_binding_sets_protection_and_kernel_credentials() {
        let fixture = Fixture::new("bound-socket");
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o710)).unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&fixture.0)
            .unwrap();
        assert_eq!(
            unsafe { libc::fchown(directory.as_raw_fd(), 0, PRODUCER_ID) },
            0
        );
        let parent =
            Parent::capture(fixture.0.clone(), directory, Some((0o710, PRODUCER_ID))).unwrap();
        let (socket, pin) = bind_socket(parent).unwrap();
        pin.recheck().unwrap();
        let metadata = fs::symlink_metadata(&pin.path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (0, PRODUCER_ID, 0o660)
        );
        assert_ne!(
            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let now = utc_receiver::Receiver::clock(0).unwrap();
        let round = crate::utc_protocol::ProducerRound {
            epoch: crate::utc_protocol::ProducerEpoch {
                boot_id: [1; 16],
                process_generation: 1,
                source_clock_generation: 1,
                policy_digest: ApprovedPolicy::fixed().unwrap().digest(),
            },
            sequence: 1,
            captured_boottime_ms: now.boottime_ms,
            captured_monotonic_ms: now.monotonic_ms,
            captured_realtime_ms: now.realtime_ms,
            sources: [1, 2, 3]
                .map(|operator| crate::utc_protocol::SourceData::Unavailable { operator }),
        };
        let sender = UnixDatagram::unbound().unwrap();
        sender
            .send_to(
                &crate::utc_protocol::fixture_encode(&round, unsafe { libc::getpid() }, unsafe {
                    libc::getuid()
                }),
                &pin.path,
            )
            .unwrap();
        let (received, credentials) = utc_receiver::receive(&socket).unwrap().unwrap();
        assert_eq!(received.epoch, round.epoch);
        assert_eq!(received.sequence, round.sequence);
        assert_eq!(received.captured_boottime_ms, round.captured_boottime_ms);
        assert_eq!(received.captured_monotonic_ms, round.captured_monotonic_ms);
        assert_eq!(received.captured_realtime_ms, round.captured_realtime_ms);
        assert_eq!(received.sources, round.sources);
        assert_eq!(
            (credentials.pid, credentials.uid, credentials.gid),
            (
                unsafe { libc::getpid() },
                unsafe { libc::getuid() },
                unsafe { libc::getgid() }
            )
        );
        let other = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&fixture.0)
            .unwrap();
        assert!(bind_socket(
            Parent::capture(fixture.0.clone(), other, Some((0o710, PRODUCER_ID))).unwrap()
        )
        .is_err());
        pin.recheck().unwrap();
        drop(socket);
        assert_eq!(
            fs::symlink_metadata(&pin.path).unwrap().ino(),
            metadata.ino()
        );
    }
}

/// This cannot be deserialized or reconstructed from a caller's digest.
pub(crate) struct Deployment {
    manifest: Pin,
    files: BTreeMap<String, (String, Pin)>,
    digest: String,
}
impl Deployment {
    pub(crate) fn installed() -> Result<Self> {
        crate::platform::require_installed()?;
        let manifest = Pin::open(Path::new(MANIFEST), MAX_MANIFEST)?;
        readonly(&manifest.file)?;
        let bytes = manifest.bytes(MAX_MANIFEST)?;
        let document: Manifest = serde_json::from_slice(&bytes)?;
        document.validate()?;
        // Canonical serialization also rejects duplicated JSON field spellings.
        if serde_json::to_vec(&document)? != bytes {
            return Err("UTC runtime manifest must have canonical compact encoding".into());
        }
        let mut files = BTreeMap::new();
        for artifact in document.files {
            let pin = Pin::open(Path::new(&artifact.path), MAX_FILE)?;
            readonly(&pin.file)?;
            if pin.identity.bytes != artifact.bytes || pin.digest()? != artifact.sha256 {
                return Err("UTC runtime release artifact digest differs".into());
            }
            if artifact.role == "executable" && pin.identity.mode & 0o111 == 0 {
                return Err("UTC producer artifact is not executable".into());
            }
            if artifact.role == "policy"
                && pin.bytes(MAX_MANIFEST)? != crate::utc_policy::POLICY_BYTES
            {
                return Err("UTC installed source policy differs from compiled approval".into());
            }
            if artifact.role == "configuration" && pin.bytes(MAX_MANIFEST)? != CONFIGURATION_BYTES {
                return Err(
                    "UTC installed source configuration differs from compiled approval".into(),
                );
            }
            files.insert(artifact.path, (artifact.role, pin));
        }
        let mut digest = Sha256::new();
        digest.update(b"luma-native-utc-runtime-v1\0");
        digest.update(&bytes);
        let deployment = Self {
            manifest,
            files,
            digest: bundle::hex(&digest.finalize()),
        };
        deployment.recheck()?;
        Ok(deployment)
    }
    fn recheck(&self) -> Result<()> {
        self.manifest.recheck()?;
        readonly(&self.manifest.file)?;
        for (_, pin) in self.files.values() {
            pin.recheck()?;
            readonly(&pin.file)?;
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    fn producer(&self, pid: i32) -> Result<()> {
        self.recheck()?;
        if pid <= 0 {
            return Err("UTC producer PID is invalid".into());
        }
        let prefix = Path::new("/proc").join(pid.to_string());
        let root = fs::metadata(prefix.join("root"))?;
        let own_root = fs::metadata("/")?;
        if (root.dev(), root.ino()) != (own_root.dev(), own_root.ino()) {
            return Err("UTC producer filesystem root differs".into());
        }
        for (path, (_, pin)) in &self.files {
            let visible = fs::metadata(prefix.join("root").join(path.trim_start_matches('/')))?;
            if Identity::of(&visible) != pin.identity {
                return Err("UTC producer namespace substituted a release artifact".into());
            }
        }
        let executable = fs::metadata(prefix.join("exe"))?;
        let approved = &self
            .files
            .get(EXECUTABLE)
            .ok_or("UTC executable admission absent")?
            .1
            .identity;
        if Identity::of(&executable) != *approved {
            return Err("UTC peer executable is not the approved release object".into());
        }
        controls(&proc_text(&prefix.join("status"), 65_536)?)?;
        environment(&proc_bytes(&prefix.join("environ"), 16_384)?, pid)?;
        if proc_text(&prefix.join("attr/current"), 256)? != "luma-utc-producer (enforce)\n"
            || proc_text(&prefix.join("cgroup"), 4096)?
                != "0::/system.slice/luma-utc-producer.service\n"
            || proc_bytes(&prefix.join("cmdline"), 4096)? != command_line()
        {
            return Err("UTC producer executable arguments or enforced confinement differs".into());
        }
        let inventory: BTreeMap<_, _> = self
            .files
            .iter()
            .filter(|(_, (role, _))| role == "executable" || role == "library")
            .map(|(path, (_, pin))| (path.as_str(), &pin.identity))
            .collect();
        let vdso = vdso_address(&proc_bytes(&prefix.join("auxv"), 4096)?)?;
        mapping_inventory(
            &proc_text(&prefix.join("maps"), 256 * 1024)?,
            &inventory,
            vdso,
        )?;
        // All producer tasks must retain the same credentials/confinement.
        // A new or removed thread during observation denies this acquisition.
        let task_path = prefix.join("task");
        let tasks = tasks(&task_path)?;
        for tid in &tasks {
            controls(&proc_text(&task_path.join(tid).join("status"), 65_536)?)?;
            if proc_text(&task_path.join(tid).join("attr/current"), 256)?
                != "luma-utc-producer (enforce)\n"
            {
                return Err("UTC producer task confinement differs".into());
            }
        }
        if self::tasks(&task_path)? != tasks {
            return Err("UTC producer task inventory changed".into());
        }
        self.recheck()
    }
}
fn proc_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut info: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } != 0 || info.f_type != 0x9fa0 {
        return Err("UTC producer observation requires kernel procfs".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("UTC producer kernel observation exceeds bound".into());
    }
    Ok(bytes)
}
fn proc_text(path: &Path, limit: u64) -> Result<String> {
    Ok(String::from_utf8(proc_bytes(path, limit)?)?)
}
fn tasks(path: &Path) -> Result<BTreeSet<String>> {
    let mut tasks = BTreeSet::new();
    for entry in fs::read_dir(path)?.take(17) {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| "invalid UTC task identity")?;
        let tid: u32 = name.parse()?;
        if tid == 0 || name != tid.to_string() || !tasks.insert(name) || tasks.len() > 16 {
            return Err("UTC producer task inventory exceeds bound".into());
        }
    }
    if tasks.is_empty() {
        return Err("UTC producer has no live tasks".into());
    }
    Ok(tasks)
}
fn command_line() -> Vec<u8> {
    [
        EXECUTABLE,
        "-n",
        "-U",
        "-f",
        CONFIGURATION,
        "-u",
        "luma-utc-producer",
        "-F",
        "1",
    ]
    .iter()
    .flat_map(|s| s.as_bytes().iter().copied().chain(std::iter::once(0)))
    .collect()
}
fn field<'a>(status: &'a str, name: &str) -> Result<&'a str> {
    let mut fields = status.lines().filter_map(|s| s.strip_prefix(name));
    let field = fields
        .next()
        .ok_or("UTC producer kernel control absent")?
        .trim();
    if fields.next().is_some() {
        return Err("UTC producer kernel control duplicated".into());
    }
    Ok(field)
}
fn controls(status: &str) -> Result<()> {
    for name in ["Uid:", "Gid:"] {
        let ids = field(status, name)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids != vec![PRODUCER_ID; 4] {
            return Err("UTC producer credentials differ".into());
        }
    }
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = field(status, name)?;
        let mask = u64::from_str_radix(value, 16)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || mask & !SYS_TIME != 0
        {
            return Err("UTC producer has unapproved capabilities".into());
        }
    }
    if field(status, "NoNewPrivs:")? != "1" || field(status, "Seccomp:")? != "2" {
        return Err("UTC producer kernel confinement is not enforced".into());
    }
    Ok(())
}
fn environment(bytes: &[u8], pid: i32) -> Result<()> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err("UTC producer environment is unterminated".into());
    }
    let mut names = BTreeSet::new();
    for value in bytes.split(|v| *v == 0).filter(|v| !v.is_empty()) {
        let entry = std::str::from_utf8(value)?;
        let (name, value) = entry
            .split_once('=')
            .ok_or("UTC producer environment is malformed")?;
        if !names.insert(name) || value.len() > 256 {
            return Err("UTC producer environment duplicates a control".into());
        }
        let valid = match name {
            "LANG" | "LC_ALL" => value == "C",
            "TZ" => value == "UTC",
            "PATH" => value == "/usr/sbin:/usr/bin:/sbin:/bin",
            "SYSTEMD_EXEC_PID" => value == pid.to_string(),
            "INVOCATION_ID" => {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            "JOURNAL_STREAM" => value.split_once(':').is_some_and(|(device, inode)| {
                device.parse::<u64>().is_ok()
                    && inode.parse::<u64>().is_ok()
                    && !device.is_empty()
                    && !inode.is_empty()
            }),
            _ => false,
        };
        if !valid {
            return Err("UTC producer environment contains an unapproved runtime control".into());
        }
    }
    Ok(())
}
fn vdso_address(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.len() % 16 != 0 {
        return Err("UTC producer auxiliary vector malformed".into());
    }
    let mut address = None;
    let mut ended = false;
    for pair in bytes.chunks_exact(16) {
        let key = u64::from_ne_bytes(pair[..8].try_into()?);
        let value = u64::from_ne_bytes(pair[8..].try_into()?);
        if ended {
            return Err("UTC producer auxiliary vector has trailing entries".into());
        }
        if key == 0 {
            if value != 0 {
                return Err("UTC producer auxiliary terminator malformed".into());
            }
            ended = true;
        }
        if key == libc::AT_SYSINFO_EHDR {
            if value == 0 || address.replace(value).is_some() {
                return Err("UTC producer vDSO identity ambiguous".into());
            }
        }
    }
    if !ended {
        return Err("UTC producer auxiliary vector is unterminated".into());
    }
    address.ok_or_else(|| "UTC producer vDSO identity absent".into())
}
fn mapping_inventory(text: &str, inventory: &BTreeMap<&str, &Identity>, vdso: u64) -> Result<()> {
    let mut executable = false;
    let mut saw_vdso = false;
    let mut saw_vsyscall = false;
    let mut end = 0;
    let mut count = 0;
    for line in text.lines() {
        count += 1;
        if count > 512 {
            return Err("UTC producer mapping inventory exceeds bound".into());
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if !(5..=6).contains(&fields.len()) {
            return Err("UTC producer mapping is ambiguous".into());
        }
        let (start, finish) = fields[0]
            .split_once('-')
            .ok_or("UTC mapping range malformed")?;
        let start = u64::from_str_radix(start, 16)?;
        let finish = u64::from_str_radix(finish, 16)?;
        let permissions = fields[1].as_bytes();
        if start >= finish
            || start < end
            || permissions.len() != 4
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's')
            || permissions[1..3] == *b"wx"
        {
            return Err("UTC producer mapping range or protection differs".into());
        }
        end = finish;
        let offset = u64::from_str_radix(fields[2], 16)?;
        let (major, minor) = fields[3]
            .split_once(':')
            .ok_or("UTC mapping device malformed")?;
        let major = u32::from_str_radix(major, 16)?;
        let minor = u32::from_str_radix(minor, 16)?;
        let inode: u64 = fields[4].parse()?;
        let path = fields.get(5).copied().unwrap_or("");
        if inode != 0 {
            let pin = inventory
                .get(path)
                .ok_or("UTC producer mapped an unapproved release object")?;
            if pin.inode != inode
                || unsafe { libc::major(pin.device) } != major
                || unsafe { libc::minor(pin.device) } != minor
                || offset >= pin.bytes
                || permissions[3] != b'p'
            {
                return Err("UTC producer mapping differs from retained release descriptor".into());
            }
            if path == EXECUTABLE && permissions[2] == b'x' {
                executable = true;
            }
        } else if permissions[2] == b'x' {
            if path == "[vsyscall]"
                && start == 0xffffffffff600000
                && finish == 0xffffffffff601000
                && offset == 0
                && major == 0
                && minor == 0
                && !saw_vsyscall
                && (permissions == b"--xp" || permissions == b"r-xp")
            {
                saw_vsyscall = true;
                continue;
            }
            if path != "[vdso]"
                || start != vdso
                || offset != 0
                || major != 0
                || minor != 0
                || permissions != b"r-xp"
                || saw_vdso
            {
                return Err("UTC producer has anonymous or unapproved executable memory".into());
            }
            saw_vdso = true;
        } else if !matches!(path, "" | "[heap]" | "[stack]" | "[vvar]" | "[vvar_vclock]") {
            return Err("UTC producer anonymous mapping identity differs".into());
        }
    }
    if !executable || !saw_vdso {
        return Err("UTC producer executable inventory incomplete".into());
    }
    Ok(())
}

struct SocketPin {
    parent: Parent,
    path: PathBuf,
    identity: Identity,
}
impl SocketPin {
    fn recheck(&self) -> Result<()> {
        self.parent.recheck()?;
        if Identity::of(&fs::symlink_metadata(&self.path)?) != self.identity {
            return Err("UTC measurement endpoint replaced or modified".into());
        }
        Ok(())
    }
}
pub(crate) struct Admission {
    deployment: Deployment,
    endpoint: SocketPin,
}
impl Admission {
    pub(crate) fn recheck(&self, pid: i32) -> Result<()> {
        self.endpoint.recheck()?;
        self.deployment.producer(pid)?;
        self.endpoint.recheck()
    }
    pub(crate) fn digest(&self) -> &str {
        self.deployment.digest()
    }
}
/// An existing endpoint is never unlinked/replaced here, including on failure.
/// The service supervisor must retire its old runtime directory explicitly.
pub(crate) struct Endpoint {
    socket: UnixDatagram,
    admission: Admission,
    barrier_ms: u64,
    boundary: Boundary,
}
pub(crate) struct Boundary {
    pub(crate) clock: crate::utc_keeper::Clock,
    pub(crate) watch: crate::utc_step_watch::StepWatch,
}
fn bind_socket(parent: Parent) -> Result<(UnixDatagram, SocketPin)> {
    parent.recheck()?;
    let path = parent.path.join(SOCKET_NAME);
    let descriptor_path =
        PathBuf::from(format!("/proc/self/fd/{}", parent.file.as_raw_fd())).join(SOCKET_NAME);
    let socket = UnixDatagram::bind(descriptor_path)?;
    utc_receiver::configure(&socket)?;
    let name = CString::new(SOCKET_NAME)?;
    if unsafe {
        libc::fchownat(
            parent.file.as_raw_fd(),
            name.as_ptr(),
            0,
            PRODUCER_ID,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || unsafe { libc::fchmodat(parent.file.as_raw_fd(), name.as_ptr(), 0o660, 0) } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    parent.recheck()?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != PRODUCER_ID
        || metadata.mode() & 0o7777 != 0o660
        || metadata.nlink() != 1
    {
        return Err("UTC measurement socket protection differs".into());
    }
    Ok((
        socket,
        SocketPin {
            parent,
            path,
            identity: Identity::of(&metadata),
        },
    ))
}
impl Endpoint {
    pub(crate) fn bind(deployment: Deployment) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("UTC endpoint requires its protected root supervisor".into());
        }
        deployment.recheck()?;
        let mut watch = crate::utc_step_watch::StepWatch::arm()?;
        let clock = utc_receiver::Receiver::clock(0)?;
        let pin = Pin::open_directory(Path::new(DIRECTORY))?;
        let parent = Parent::capture(PathBuf::from(DIRECTORY), pin, Some((0o710, PRODUCER_ID)))?;
        let (socket, endpoint) = bind_socket(parent)?;
        let endpoint = Self {
            socket,
            admission: Admission {
                deployment,
                endpoint,
            },
            barrier_ms: clock
                .boottime_ms
                .checked_add(1)
                .ok_or("UTC acquisition barrier overflow")?,
            boundary: Boundary {
                clock,
                watch: {
                    watch.check()?;
                    watch
                },
            },
        };
        endpoint.admission.endpoint.recheck()?;
        Ok(endpoint)
    }
    pub(crate) fn acquire(mut self) -> Result<utc_receiver::Receiver> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            self.boundary.watch.check()?;
            self.admission.endpoint.recheck()?;
            if let Some((round, peer)) = utc_receiver::receive(&self.socket)? {
                if peer.uid != PRODUCER_ID || peer.gid != PRODUCER_ID {
                    return Err("UTC acquisition sender is not the producer identity".into());
                }
                self.admission.recheck(peer.pid)?;
                if Instant::now() >= deadline {
                    return Err("UTC acquisition runtime admission exceeded deadline".into());
                }
                return utc_receiver::Receiver::admitted(
                    self.socket,
                    peer,
                    round,
                    self.barrier_ms,
                    self.admission,
                    self.boundary,
                );
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or("UTC producer acquisition timed out")?;
            let mut poll = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = remaining.as_millis().saturating_add(1).min(100) as i32;
            let count = unsafe { libc::poll(&mut poll, 1, timeout) };
            if count < 0 || poll.revents & !libc::POLLIN != 0 {
                return Err("UTC producer acquisition interrupted or unavailable".into());
            }
        }
    }
}
impl Pin {
    fn open_directory(path: &Path) -> Result<File> {
        // Retain and check both fixed parents; /run may not be writable by the
        // producer. Open the final directory without following a stale symlink.
        let run = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run")?;
        let parent = Parent::capture(PathBuf::from("/run"), run, None)?;
        let file = open_at(
            &parent.file,
            path.file_name().ok_or("UTC directory name absent")?,
            true,
        )?;
        parent.recheck()?;
        Ok(file)
    }
}
