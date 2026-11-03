//! Real mounts over the C namespace in a private mount namespace, not installed
//! custody qualification.
use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CHILDREN: [&str; 5] = ["pages", "records", "attempts", "controls", "tails"];
const MOUNT_CHANGED: &str =
    "persistent content directory inode, permissions, volume or mount changed";
const CROSSED: &str = "paged C namespace crossed installed mount";

fn path(value: &Path) -> CString {
    CString::new(value.as_os_str().as_bytes()).unwrap()
}
fn mount(source: &CString, target: &CString, flags: libc::c_ulong) {
    let status = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
}

/// Detached on drop, because the store's pins may still hold the mount.
struct Bind(CString);
impl Bind {
    fn over(target: &Path) -> Self {
        let target = path(target);
        mount(&target, &target, libc::MS_BIND);
        Self(target)
    }
}
impl Drop for Bind {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) },
            0
        );
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        assert_eq!(std::env::var("LUMA_CUSTODY_MOUNT_TEST").as_deref(), Ok("1"));
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let base = PathBuf::from(
            std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("explicit disposable ext4 data root required"),
        );
        let path = base.join(format!("luma-tpm-paged-mounts-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        crate::tpm::validate_fixture_directory(&path).unwrap();
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
        Self(path)
    }
    fn binding() -> luma_content_store::v2::custody_map::CustodyBinding {
        luma_content_store::v2::custody_map::CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "22".repeat(32),
        }
    }
    fn open(&self) -> Result<PageStore> {
        PageStore::open(&self.0, Self::binding(), &mut || Ok(()))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(fs::canonicalize(&self.0).unwrap(), self.0);
        assert!(self
            .0
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("luma-tpm-paged-mounts-"));
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// Repeats one check until it sees the root on two mounts. Returns instead of
/// panicking, so the caller can always stop the mover first.
fn checks_until_crossed(store: &PageStore) -> std::result::Result<u64, String> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut checks = 0;
    while Instant::now() < deadline {
        checks += 1;
        match store.check() {
            Err(refusal) if refusal.to_string() == CROSSED => return Ok(checks),
            Err(refusal) if refusal.to_string() == MOUNT_CHANGED => {}
            Err(refusal) => return Err(format!("unexpected refusal: {refusal}")),
            Ok(()) => return Err("a split mount was admitted".into()),
        }
    }
    Err(format!("no crossing observed in {checks} checks"))
}

#[test]
#[ignore = "requires a disposable container and private mount namespace with CAP_SYS_ADMIN"]
fn actual_binds_and_a_mount_moved_during_one_check_are_refused() {
    let fixture = Fixture::new();
    PageStore::create(&fixture.0, Fixture::binding(), &mut || Ok(())).unwrap();
    let root = fixture.0.join(NAME);
    let pages = root.join("pages");

    // A bind already in place is refused when the child is captured.
    {
        let _bind = Bind::over(&pages);
        let refusal = fixture.open().err().unwrap();
        assert_eq!(
            refusal.to_string(),
            "content authority may not cross a bind or other mount"
        );
    }

    // A bind added later is refused by the held pin of what it covers.
    let mut store = fixture.open().unwrap();
    store.check().unwrap();
    for covered in [&pages, &root] {
        let _bind = Bind::over(covered);
        assert_eq!(store.check().unwrap_err().to_string(), MOUNT_CHANGED);
    }
    store.check().unwrap();

    // Neither position of the mount below reaches the crossing refusal. With
    // it over the root, the root's pin refuses; with it aside, the children's
    // pins refuse. Only a move between those two reads in one check gets there,
    // so the mover keeps moving it. A moved mount keeps its id, which a new
    // bind would not.
    let _bind = Bind::over(&root);
    for (child, name) in store.children.iter_mut().zip(CHILDREN) {
        *child = PersistentDirectory::capture(&root.join(name)).unwrap();
    }
    assert_eq!(store.check().unwrap_err().to_string(), MOUNT_CHANGED);
    let aside = fixture.0.join("aside");
    fs::DirBuilder::new().mode(0o700).create(&aside).unwrap();
    let (over, aside) = (path(&root), path(&aside));
    mount(&over, &aside, libc::MS_MOVE);
    assert_eq!(store.check().unwrap_err().to_string(), MOUNT_CHANGED);
    mount(&aside, &over, libc::MS_MOVE);

    let stop = AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                mount(&over, &aside, libc::MS_MOVE);
                mount(&aside, &over, libc::MS_MOVE);
            }
        });
        let outcome = checks_until_crossed(&store);
        stop.store(true, Ordering::SeqCst);
        outcome
    });
    println!(
        "crossed installed mount refused on check {}",
        outcome.unwrap()
    );
}
