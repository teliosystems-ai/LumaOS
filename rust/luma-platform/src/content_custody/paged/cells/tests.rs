//! Real disposable-filesystem tests, not installed custody qualification.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(!Path::new("/dev/tpm0").exists() && !Path::new("/dev/tpmrm0").exists());
        let base = PathBuf::from(
            std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("explicit disposable ext4 data root required"),
        );
        let path = base.join(format!(
            "luma-tpm-fixed-cells-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
        Self(path)
    }
    fn pages(&self) -> PageStore {
        PageStore::create(
            &self.0,
            luma_content_store::v2::custody_map::CustodyBinding {
                installation: "11".repeat(32),
                sealed_genesis_sha256: "22".repeat(32),
            },
            &mut || Ok(()),
        )
        .unwrap()
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
            .starts_with("luma-tpm-fixed-cells-"));
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn prepare(pages: &PageStore) {
    pages
        .admit_writes(1024 * 1024, 3, 0, &mut || Ok(()))
        .unwrap();
}
#[test]
fn actual_three_control_inodes_are_reused_without_new_names_blocks_or_renames() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let controls = Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).unwrap();
    let selection = controls.selection().clone();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    assert_eq!(before.interrupted_files, 0);
    let original = controls.read(0, &mut || Ok(())).unwrap();
    let first = controls.read(1, &mut || Ok(())).unwrap();
    let second = [2_u8; BYTES];
    let changed = controls.rewrite(&first, &second, &mut || Ok(())).unwrap();
    assert_eq!(changed.bytes(), second);
    assert_eq!(changed.sha256(), hash(&second));
    let third = [3_u8; BYTES];
    controls.rewrite(&changed, &third, &mut || Ok(())).unwrap();
    assert_eq!(
        controls.read(0, &mut || Ok(())).unwrap().bytes(),
        original.bytes()
    );
    assert_eq!(controls.selection(), &selection);
    assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
    assert!(pages.require_hash_controls_empty().is_err());
    drop(controls);
    let reopened = Files::open(&pages, selection, &mut || Ok(())).unwrap();
    assert_eq!(reopened.read(1, &mut || Ok(())).unwrap().bytes(), third);
    assert_eq!(
        names(&pages.root.join("controls"), 3).unwrap(),
        vec!["pending", "selector-0", "selector-1"]
    );
}
#[test]
fn stale_compare_fails_before_any_rewrite_and_cannot_reset_expected_identity() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let controls = Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).unwrap();
    let old = controls.read(2, &mut || Ok(())).unwrap();
    let next = [2_u8; BYTES];
    controls.rewrite(&old, &next, &mut || Ok(())).unwrap();
    assert!(controls.rewrite(&old, &initial, &mut || Ok(())).is_err());
    assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), next);
    let current = controls.read(2, &mut || Ok(())).unwrap();
    assert!(controls
        .rewrite(&current, &initial[..BYTES - 1], &mut || Ok(()))
        .is_err());
    assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), next);
}
#[test]
fn original_revocation_during_write_poisoned_handle_preserves_partial_exact_inode() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let controls = Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).unwrap();
    let selection = controls.selection().clone();
    let old = controls.read(2, &mut || Ok(())).unwrap();
    let file = controls.files[2].try_clone().unwrap();
    let mut check = || {
        let mut byte = [0_u8; 1];
        if unsafe { libc::pread(file.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) } != 1 {
            return Err("fixture inspection failed".into());
        }
        if byte[0] == 2 {
            return Err("software original revoked after first block".into());
        }
        Ok(())
    };
    let next = [2_u8; BYTES];
    assert!(controls.rewrite(&old, &next, &mut check).is_err());
    assert!(controls.read(0, &mut || Ok(())).is_err());
    drop(controls);
    let fresh = Files::open(&pages, selection, &mut || Ok(())).unwrap();
    let partial = fresh.read(2, &mut || Ok(())).unwrap();
    assert_eq!(&partial.bytes()[..4096], &next[..4096]);
    assert_eq!(&partial.bytes()[4096..], &initial[4096..]);
    assert_eq!(fresh.read(0, &mut || Ok(())).unwrap().bytes(), initial);
}
#[test]
fn partial_initial_creation_is_charged_and_never_adopted_or_retried() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let mut fail = || {
        if pages.root.join("controls/selector-0").exists() {
            Err("software original revoked immediately after create".into())
        } else {
            Ok(())
        }
    };
    assert!(Files::create(&pages, [&initial, &initial, &initial], &mut fail).is_err());
    let inventory = pages.inventory(&mut || Ok(())).unwrap();
    assert_eq!(inventory.interrupted_files, 1);
    assert!(Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).is_err());
    assert!(pages
        .admit_writes(1024 * 1024, 3, 0, &mut || Ok(()))
        .is_err());
}
#[test]
fn aliases_substituted_selected_inodes_and_unknown_control_names_are_rejected() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let controls = Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).unwrap();
    let mut selection = controls.selection().clone();
    selection.cells[1].inode = selection.cells[0].inode;
    assert!(selection.validate().is_err());
    let selection = controls.selection().clone();
    let path = pages.root.join("controls/selector-0");
    fs::rename(&path, pages.root.join("controls/old-selector")).unwrap();
    let mut replacement = MemberParent::capture(&path)
        .unwrap()
        .open(&path, libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600)
        .unwrap();
    replacement.write_all(&initial).unwrap();
    replacement.sync_all().unwrap();
    assert!(controls.read(0, &mut || Ok(())).is_err());
    assert!(Files::open(&pages, selection, &mut || Ok(())).is_err());
    assert!(pages.inventory(&mut || Ok(())).is_err());
}
#[test]
fn selected_control_identity_cannot_cross_c_binding_or_directory_generation() {
    let fixture = Fixture::new();
    let pages = fixture.pages();
    prepare(&pages);
    let initial = [1_u8; BYTES];
    let controls = Files::create(&pages, [&initial, &initial, &initial], &mut || Ok(())).unwrap();
    let mut altered = controls.selection().clone();
    altered.binding.installation = "33".repeat(32);
    assert!(Files::open(&pages, altered, &mut || Ok(())).is_err());
    let path = pages.root.join("controls");
    let old = pages.root.join("controls-old");
    fs::rename(&path, &old).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    assert!(controls.read(0, &mut || Ok(())).is_err());
    assert!(pages.check().is_err());
}
