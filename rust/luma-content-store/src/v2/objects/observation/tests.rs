//! Real disposable ext4 read/namespace observations under an explicit software
//! Boundary fixture, not a current native C/creator/PAM qualification.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("raw observation tests require disposable private ext4");
        let path = Path::new(&base).join(format!(
            "raw-observer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn raw(&self, hash: &str) -> std::path::PathBuf {
        self.0
            .join(ObjectStore::name(&binding()).unwrap())
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    }
}
struct Gate {
    live: bool,
    write: bool,
    checks: u64,
}
impl Boundary for Gate {
    fn admit(&mut self, b: &OwnerBinding, r: ResourceBudget) -> Result<()> {
        if !self.live
            || b != &binding()
            || r.memory_bytes > 192 * 1024 * 1024
            || (r.write_bytes > 0 && !self.write)
        {
            return Err("fixture original resource/read admission absent".into());
        }
        Ok(())
    }
    fn check(&mut self, a: Access<'_>) -> Result<()> {
        self.checks += 1;
        if !self.live {
            return Err("fixture original read revoked".into());
        }
        match a {
            Access::Inspect { binding: b } if b == &binding() => Ok(()),
            Access::Mutate { binding: b, .. } if self.write && b == &binding() => Ok(()),
            _ => Err("fixture wrong original access".into()),
        }
    }
}
fn gate() -> Gate {
    Gate {
        live: true,
        write: true,
        checks: 0,
    }
}
fn read() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "c".repeat(64),
        decision: DecisionKind::Published,
        source_bytes: 4096,
    }
}
fn store(f: &Fixture, b: &mut Gate) -> ObjectStore {
    ObjectStore::create_at(
        &f.0,
        &binding(),
        IoBudget {
            read_bytes: 128 * 1024,
            write_bytes: 128 * 1024,
            new_files: 64,
        },
        &mutation(),
        b,
    )
    .unwrap()
}
fn page(s: &ObjectStore, bytes: &[u8], b: &mut Gate) -> String {
    s.prepare_page(
        bytes,
        IoBudget {
            read_bytes: 128 * 1024,
            write_bytes: 128 * 1024,
            new_files: 64,
        },
        &mutation(),
        b,
    )
    .unwrap()
}
#[test]
fn actual_same_held_namespace_and_complete_page_bytes_metadata_recheck() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = page(&s, b"actual immutable raw page", &mut b);
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    let (bytes, held) = s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .unwrap();
    assert_eq!(bytes, b"actual immutable raw page");
    let actual = fs::metadata(fixture.raw(&hash)).unwrap();
    match held.data() {
        RawObjectObservationData::Present {
            file,
            complete,
            actual_sha256,
            ..
        } => {
            assert!(*complete);
            assert_eq!(actual_sha256, &hash);
            assert_eq!(file.inode, actual.ino());
            assert_eq!(file.device, actual.dev());
            assert_eq!(file.bytes, actual.len());
            assert_eq!(file.allocated_bytes, actual.blocks() * 512);
            assert!(file.mount_id > 0);
        }
        _ => panic!("existing page must be present"),
    }
    assert_eq!(
        s.check_raw_object_observation(&namespace, &held, read(), &mut b)
            .unwrap(),
        bytes
    );
    s.check_namespace_observation(&namespace, read(), &mut b)
        .unwrap();
    assert!(b.checks > 20);
}
#[test]
fn actual_absence_at_each_computed_prefix_and_later_creation_are_not_authority() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = "d".repeat(64);
    let raw = fixture.raw(&hash);
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    for level in 0..3 {
        let (bytes, held) = s
            .observe_raw_object(&namespace, &hash, read(), &mut b)
            .unwrap();
        assert!(bytes.is_empty());
        match held.data() {
            RawObjectObservationData::Absent {
                missing_component, ..
            } => assert_eq!(*missing_component, level),
            _ => panic!("computed path must be absent"),
        }
        assert!(s
            .check_raw_object_observation(&namespace, &held, read(), &mut b)
            .unwrap()
            .is_empty());
        if level == 0 {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(raw.parent().unwrap().parent().unwrap())
                .unwrap();
        } else if level == 1 {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(raw.parent().unwrap())
                .unwrap();
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&raw)
                .unwrap()
                .sync_all()
                .unwrap();
        }
        assert!(s
            .check_raw_object_observation(&namespace, &held, read(), &mut b)
            .is_err());
    }
    let (bytes, held) = s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .unwrap();
    assert!(bytes.is_empty());
    assert!(matches!(
        held.data(),
        RawObjectObservationData::Present {
            complete: false,
            ..
        }
    ));
}
#[test]
fn incomplete_content_retained_hashes_and_zero_length_are_measured_not_promoted() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = page(&s, b"original", &mut b);
    fs::set_permissions(fixture.raw(&hash), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(fixture.raw(&hash), b"partial bytes").unwrap();
    fs::set_permissions(fixture.raw(&hash), fs::Permissions::from_mode(0o400)).unwrap();
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    let (bytes, held) = s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .unwrap();
    assert_eq!(bytes, b"partial bytes");
    match held.data() {
        RawObjectObservationData::Present {
            complete,
            actual_sha256,
            ..
        } => {
            assert!(!complete);
            assert_eq!(actual_sha256, &luma_content::sha256(&bytes));
        }
        _ => panic!("expected incomplete data"),
    }
    assert_eq!(
        s.check_raw_object_observation(&namespace, &held, read(), &mut b)
            .unwrap(),
        bytes
    );
}
#[test]
fn held_ofd_session_alias_replacement_content_changes_and_revocation_refuse() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = page(&s, b"same held source bytes", &mut b);
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    let (_, held) = s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .unwrap();
    let other = s.observe_namespace(read(), &mut b).unwrap();
    assert_eq!(namespace.data(), other.data());
    assert!(s
        .check_raw_object_observation(&other, &held, read(), &mut b)
        .is_err());
    let orphan = {
        let temporary = s.observe_namespace(read(), &mut b).unwrap();
        s.observe_raw_object(&temporary, &hash, read(), &mut b)
            .unwrap()
            .1
    };
    let reopened = s.observe_namespace(read(), &mut b).unwrap();
    assert!(orphan.namespace.root.metadata().unwrap().is_dir());
    assert!(s
        .check_raw_object_observation(&reopened, &orphan, read(), &mut b)
        .is_err());
    b.live = false;
    assert!(s
        .check_raw_object_observation(&namespace, &held, read(), &mut b)
        .is_err());
    b.live = true;
    let raw = fixture.raw(&hash);
    let old = raw.with_extension("retained");
    fs::rename(&raw, &old).unwrap();
    fs::write(&raw, b"same held source bytes").unwrap();
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(s
        .check_raw_object_observation(&namespace, &held, read(), &mut b)
        .is_err());
    fs::remove_file(&raw).unwrap();
    fs::rename(&old, &raw).unwrap();
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&raw, b"altered source bytes!!").unwrap();
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(s
        .check_raw_object_observation(&namespace, &held, read(), &mut b)
        .is_err());
}
#[test]
fn exact_read_budget_reserves_actual_source_and_final_eof_before_delivery() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = page(&s, &vec![7; 4096], &mut b);
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    let exact = 2 * (namespace.data().identity.bytes + 1) + 4096 + 1;
    let small = IoBudget {
        read_bytes: exact - 1,
        ..read()
    };
    assert!(s
        .observe_raw_object(&namespace, &hash, small, &mut b)
        .is_err());
    let budget = IoBudget {
        read_bytes: exact,
        ..read()
    };
    assert_eq!(
        s.observe_raw_object(&namespace, &hash, budget, &mut b)
            .unwrap()
            .0
            .len(),
        4096
    );
    assert!(s
        .observe_namespace(
            IoBudget {
                read_bytes: 128 * 1024 + 1,
                ..read()
            },
            &mut b
        )
        .is_err());
    assert!(s
        .observe_raw_object(
            &namespace,
            &hash,
            IoBudget {
                write_bytes: 1,
                new_files: 1,
                ..read()
            },
            &mut b
        )
        .is_err());
    assert!(s
        .observe_raw_object(&namespace, &hash.to_uppercase(), read(), &mut b)
        .is_err());
}
#[test]
fn symlink_unsafe_mode_unknown_namespace_and_oversized_raw_data_refuse() {
    let fixture = Fixture::new();
    let mut b = gate();
    let s = store(&fixture, &mut b);
    let hash = page(&s, b"private", &mut b);
    let namespace = s.observe_namespace(read(), &mut b).unwrap();
    let raw = fixture.raw(&hash);
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .is_err());
    fs::write(&raw, vec![1; MAX_PAGE_BYTES + 1]).unwrap();
    fs::set_permissions(&raw, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .is_err());
    fs::remove_file(&raw).unwrap();
    std::os::unix::fs::symlink("identity.json", &raw).unwrap();
    assert!(s
        .observe_raw_object(&namespace, &hash, read(), &mut b)
        .is_err());
    fs::remove_file(&raw).unwrap();
    fs::write(
        fixture
            .0
            .join(ObjectStore::name(&binding()).unwrap())
            .join("unexpected"),
        b"inert",
    )
    .unwrap();
    assert!(s
        .check_namespace_observation(&namespace, read(), &mut b)
        .is_err());
}
