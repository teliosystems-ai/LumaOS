//! Actual SCM_RIGHTS/socket/OFD fixtures. The real disposable peer is pinned,
//! but its nonproduct label is never called installed C/worker qualification.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Io {
    binding: OwnerBinding,
    live: bool,
}
impl Boundary for Io {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if !self.live || owner != &self.binding || budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("explicit software original admission absent".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if !self.live {
            return Err("explicit software original revoked".into());
        }
        match access {
            Access::Inspect { binding } | Access::Mutate { binding, .. }
                if binding == &self.binding =>
            {
                Ok(())
            }
            _ => Err("explicit software original owner/scope differs".into()),
        }
    }
}
fn read() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn owner_path(fixture: &Fixture) -> std::path::PathBuf {
    let entries = std::fs::read_dir(&fixture.0)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    entries[0].path()
}
fn setup() -> (
    Fixture,
    ObjectStore,
    HeldNamespaceObservation,
    Io,
    WriterOffer,
    File,
) {
    let root =
        std::env::var("LUMA_STORAGE_TEST_ROOT").expect("writer transport requires private ext4");
    let path = std::path::Path::new(&root).join(format!(
        "writer-transfer-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let fixture = Fixture(path);
    let owner = OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    };
    let mut io = Io {
        binding: owner.clone(),
        live: true,
    };
    let store = ObjectStore::create_at(
        &fixture.0,
        &owner,
        IoBudget {
            read_bytes: 128 * 1024,
            write_bytes: 128 * 1024,
            new_files: 64,
        },
        &luma_content_store::v2::Mutation {
            review_sha256: "c".repeat(64),
            decision: luma_content_store::DecisionKind::Published,
            source_bytes: 1,
        },
        &mut io,
    )
    .unwrap();
    let physical = store.inventory(read(), &mut io, |_| Ok(())).unwrap();
    let head = OwnerHeadV2::empty_data(&owner, physical).unwrap();
    let namespace = store.observe_namespace(read(), &mut io).unwrap();
    let offer = WriterOffer {
        schema_version: 1,
        purpose: PURPOSE.into(),
        nonce: "d".repeat(32),
        context: Context {
            schema_version: 1,
            binding: owner.clone(),
            source_request_sha256: "e".repeat(64),
            source_profile: "explicit-software-writer-fixture-v1".into(),
            selected_before_sha256: head.sha256().unwrap(),
            selected_before: head,
            lease: crate::resources::Token {
                lease_id: "1".repeat(32),
                generation: 2,
                manager_epoch: "2".repeat(32),
            },
        },
        review_sha256: "f".repeat(64),
        worker_pid: std::process::id(),
        worker_start: start(std::process::id() as i32).unwrap(),
    };
    let writer = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(owner_path(&fixture))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    (fixture, store, namespace, io, offer, writer)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn raw_marker(socket: &UnixStream, descriptors: &[File], marker: u8) {
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: (&marker as *const u8).cast_mut().cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE((descriptors.len() * size_of::<i32>()) as u32) } as usize;
        assert!(message.msg_controllen <= size_of_val(&control));
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * size_of::<i32>()) as u32) as usize;
            for (index, descriptor) in descriptors.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header)
                        .add(index * size_of::<i32>())
                        .cast::<i32>(),
                    descriptor.as_raw_fd(),
                );
            }
        }
    }
    assert_eq!(
        unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
        1
    );
}

#[test]
fn actual_single_fd_keeps_same_ofd_observation_and_detects_connection_loss() {
    let (_fixture, store, namespace, mut io, offer, writer) = setup();
    let (client, server) = UnixStream::pair().unwrap();
    let peer = Peer::software_fixture(&server).unwrap();
    let clone = writer.try_clone().unwrap();
    let sent = offer.clone();
    let (done, hold) = mpsc::channel();
    let thread = thread::spawn(move || {
        let peer = Peer::software_fixture(&client).unwrap();
        send_to(&client, &peer, &sent, &clone, deadline(), &mut || Ok(())).unwrap();
        hold.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let received = receive_from(&server, peer, &offer, deadline(), &mut || Ok(())).unwrap();
    assert_ne!(received.writer.as_raw_fd(), writer.as_raw_fd());
    let observed = received
        .observe(&store, &namespace, read(), &mut io)
        .unwrap();
    observed.check(&store, &namespace, read(), &mut io).unwrap();
    assert_eq!(observed.data().root.inode, writer.metadata().unwrap().ino());
    done.send(()).unwrap();
    thread.join().unwrap();
    assert!(observed.check(&store, &namespace, read(), &mut io).is_err());
}

#[test]
fn missing_extra_truncated_or_trailing_descriptor_frames_are_closed() {
    for attack in 0..5 {
        let (_fixture, _store, _namespace, _io, offer, writer) = setup();
        let (client, server) = UnixStream::pair().unwrap();
        let peer = Peer::software_fixture(&server).unwrap();
        let offer_bytes = serde_json::to_vec(&offer).unwrap();
        let amount = match attack {
            0 => 0,
            1 => 2,
            2 => 64,
            _ => 1,
        };
        let descriptors = (0..amount)
            .map(|_| writer.try_clone().unwrap())
            .collect::<Vec<_>>();
        let (done, hold) = mpsc::channel();
        let thread = thread::spawn(move || {
            super::super::super::wire::send(&client, &offer_bytes, deadline(), &mut || Ok(()))
                .unwrap();
            raw_marker(&client, &descriptors, if attack == 3 { b'X' } else { b'W' });
            if attack == 4 {
                raw_marker(&client, &descriptors, b'W');
            }
            client.shutdown(Shutdown::Write).unwrap();
            let _ = hold.recv_timeout(Duration::from_secs(10));
        });
        assert!(
            receive_from(&server, peer, &offer, deadline(), &mut || Ok(())).is_err(),
            "attack {attack}"
        );
        done.send(()).unwrap();
        thread.join().unwrap();
        drop(writer);
        // Any leaked received duplicate would still hold the original flock.
        let reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(owner_path(&_fixture))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(reopened.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "received descriptor leak attack {attack}"
        );
    }
}

#[test]
fn different_nonce_context_source_worker_or_lease_cannot_use_expected_offer() {
    for attack in 0..5 {
        let (_fixture, _store, _namespace, _io, expected, writer) = setup();
        let mut offer = expected.clone();
        match attack {
            0 => offer.nonce = "9".repeat(32),
            1 => offer.context.source_request_sha256 = "9".repeat(64),
            2 => offer.review_sha256 = "9".repeat(64),
            3 => offer.context.lease.generation += 1,
            _ => offer.worker_start += 1,
        }
        let (client, server) = UnixStream::pair().unwrap();
        let peer = Peer::software_fixture(&server).unwrap();
        super::super::super::wire::send(
            &client,
            &serde_json::to_vec(&offer).unwrap(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
        assert!(receive_from(&server, peer, &expected, deadline(), &mut || Ok(())).is_err());
        drop(writer);
    }
}

#[test]
fn stalled_missing_marker_obeys_actual_original_revocation_and_poisoning() {
    let (_fixture, _store, _namespace, _io, offer, _writer) = setup();
    let (client, server) = UnixStream::pair().unwrap();
    let peer = Peer::software_fixture(&server).unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let flag = revoked.clone();
    super::super::super::wire::send(
        &client,
        &serde_json::to_vec(&offer).unwrap(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let visible = ready.clone();
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WAITING_FOR_RIGHTS.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    WAITING_FOR_RIGHTS.with(|slot| *slot.borrow_mut() = Some(ready));
    let revoke = thread::spawn(move || {
        let end = deadline();
        while !visible.load(Ordering::Acquire) && Instant::now() < end {
            thread::yield_now();
        }
        assert!(visible.load(Ordering::Acquire));
        flag.store(true, Ordering::Release);
    });
    let mut check = || {
        if revoked.load(Ordering::Acquire) {
            return Err("fixture original revoked during socket stall".into());
        }
        Ok(())
    };
    let begin = Instant::now();
    assert!(receive_from(&server, peer, &offer, deadline(), &mut check).is_err());
    revoke.join().unwrap();
    assert!(begin.elapsed() < Duration::from_secs(1));
    let mut byte = [0];
    use std::io::Read;
    assert_eq!((&client).read(&mut byte).unwrap(), 0);
}

#[test]
fn offer_shape_unknown_fields_and_wrong_actual_generation_refuse() {
    let (_fixture, store, namespace, mut io, offer, writer) = setup();
    offer.validate().unwrap();
    let mut extra = serde_json::to_value(&offer).unwrap();
    extra["authorized"] = true.into();
    assert!(serde_json::from_value::<WriterOffer>(extra).is_err());
    let (client, server) = UnixStream::pair().unwrap();
    let peer = Peer::software_fixture(&server).unwrap();
    let mut wrong = offer;
    wrong.worker_start += 1;
    assert!(receive_from(&server, peer, &wrong, deadline(), &mut || Ok(())).is_err());
    drop(client);
    // The actual nonproduct peer never satisfies either installed fixed label.
    let (client, server) = UnixStream::pair().unwrap();
    assert!(send(&client, &wrong, &writer, &mut || Ok(())).is_err());
    assert!(receive(
        &server,
        &wrong,
        &store,
        &namespace,
        read(),
        &mut || Ok(()),
        &mut io
    )
    .is_err());
}
