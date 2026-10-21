//! Actual disposable ext4/OFD/kernel-lock tests, not native creator/C grants.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let base =
            std::env::var("LUMA_STORAGE_TEST_ROOT").expect("writer tests require disposable ext4");
        let path = Path::new(&base).join(format!(
            "writer-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct SoftwareIo {
    live: bool,
}
impl Boundary for SoftwareIo {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if !self.live || binding != &owner() || budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("explicit software fixture original admission revoked/mismatched".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if !self.live {
            return Err("explicit fixture original revoked".into());
        }
        match access {
            Access::Inspect { binding } | Access::Mutate { binding, .. } if binding == &owner() => {
                Ok(())
            }
            _ => Err("explicit fixture owner/scope differs".into()),
        }
    }
}
fn owner() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    }
}
fn read() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn setup() -> (Fixture, ObjectStore, SoftwareIo) {
    let fixture = Fixture::new();
    let mut io = SoftwareIo { live: true };
    let store = ObjectStore::create_at(
        &fixture.0,
        &owner(),
        IoBudget {
            read_bytes: 128 * 1024,
            write_bytes: 128 * 1024,
            new_files: 64,
        },
        &Mutation {
            review_sha256: "c".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 1,
        },
        &mut io,
    )
    .unwrap();
    (fixture, store, io)
}

#[test]
fn actual_duplicate_retains_existing_sender_flock_without_minting_one() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let writer = store.acquire_writer().unwrap();
    let held = store
        .observe_existing_writer(
            &namespace,
            writer.try_clone().unwrap(),
            std::process::id(),
            read(),
            &mut io,
        )
        .unwrap();
    assert_eq!(held.data().root.inode, writer.metadata().unwrap().ino());
    assert_eq!(held.data().sender_pid, std::process::id());
    assert!(store.acquire_writer().is_err());
    store
        .check_existing_writer(&namespace, &held, read(), &mut io)
        .unwrap();
    drop(writer);
    // The retained duplicate still owns that same advisory lock/OFD.
    assert!(store.acquire_writer().is_err());
    store
        .check_existing_writer(&namespace, &held, read(), &mut io)
        .unwrap();
    drop(held);
    assert!(store.acquire_writer().is_ok());
}

#[test]
fn fresh_unlocked_open_of_same_inode_is_not_the_locked_description() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let _writer = store.acquire_writer().unwrap();
    let separate =
        crate::storage::open(&store.root, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
    assert!(store
        .observe_existing_writer(&namespace, separate, std::process::id(), read(), &mut io)
        .is_err());
}

#[test]
fn unlock_and_move_lock_to_other_ofd_refuses_even_same_pid_and_inode() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let writer = store.acquire_writer().unwrap();
    let held = store
        .observe_existing_writer(
            &namespace,
            writer.try_clone().unwrap(),
            std::process::id(),
            read(),
            &mut io,
        )
        .unwrap();
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) }, 0);
    let _other = store.acquire_writer().unwrap();
    assert!(store
        .check_existing_writer(&namespace, &held, read(), &mut io)
        .is_err());
}

#[test]
fn wrong_root_pid_flags_or_namespace_session_refuses() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let (other_fixture, other, mut other_io) = setup();
    let wrong_root = other.acquire_writer().unwrap();
    assert!(store
        .observe_existing_writer(&namespace, wrong_root, std::process::id(), read(), &mut io)
        .is_err());
    let writer = store.acquire_writer().unwrap();
    assert!(store
        .observe_existing_writer(
            &namespace,
            writer.try_clone().unwrap(),
            std::process::id() + 1,
            read(),
            &mut io
        )
        .is_err());
    let duplicate = writer.try_clone().unwrap();
    assert_eq!(
        unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    assert!(store
        .observe_existing_writer(&namespace, duplicate, std::process::id(), read(), &mut io)
        .is_err());
    let held = store
        .observe_existing_writer(
            &namespace,
            writer.try_clone().unwrap(),
            std::process::id(),
            read(),
            &mut io,
        )
        .unwrap();
    let other_session = store.observe_namespace(read(), &mut io).unwrap();
    assert!(store
        .check_existing_writer(&other_session, &held, read(), &mut io)
        .is_err());
    // Other stores remain ordinary data; observing one cannot adopt the other.
    assert!(other.observe_namespace(read(), &mut other_io).is_ok());
    drop(other_fixture);
}

#[test]
fn original_revocation_and_read_exhaustion_refuse_actual_recheck() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let writer = store.acquire_writer().unwrap();
    let held = store
        .observe_existing_writer(
            &namespace,
            writer.try_clone().unwrap(),
            std::process::id(),
            read(),
            &mut io,
        )
        .unwrap();
    assert!(store
        .check_existing_writer(
            &namespace,
            &held,
            IoBudget {
                read_bytes: 1,
                write_bytes: 0,
                new_files: 0
            },
            &mut io
        )
        .is_err());
    io.live = false;
    assert!(store
        .check_existing_writer(&namespace, &held, read(), &mut io)
        .is_err());
}

#[test]
fn kernel_transcript_parser_is_closed_on_ambiguous_missing_or_other_locks() {
    let (_fixture, store, mut io) = setup();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let writer = store.acquire_writer().unwrap();
    let root = writer_file(&writer, &namespace).unwrap();
    let binding = owner();
    let mut guard = Guard::new(&mut io, &binding, read(), None).unwrap();
    let actual = proc_info(&writer, &mut guard).unwrap();
    existing_lock(&actual, std::process::id(), &root).unwrap();
    for attack in 0..6 {
        let mut forged = actual.clone();
        match attack {
            0 => {
                forged = actual
                    .lines()
                    .filter(|line| !line.starts_with("lock:"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            1 => forged.push_str(
                actual
                    .lines()
                    .find(|line| line.starts_with("lock:"))
                    .unwrap(),
            ),
            2 => forged = forged.replace("FLOCK", "POSIX"),
            3 => forged = forged.replace("WRITE", "READ"),
            4 => forged.push_str("mnt_id:\t1\n"),
            _ => forged = forged.replace(" EOF", " 1"),
        }
        assert!(
            existing_lock(&forged, std::process::id(), &root).is_err(),
            "attack {attack}"
        );
    }
}
