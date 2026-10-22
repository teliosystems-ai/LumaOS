//! Real socket/ext4 fixtures. Their actual unconfined kernel peer pins and
//! explicitly controlled software callbacks are NOT installed C/PAM authority.
use super::*;
use luma_content_store::v2::readonly::ObservedPageReader;
use luma_content_store::v2::{IoBudget, Mutation, ObjectStore};
use luma_content_store::{Access, Boundary, DecisionKind, ResourceBudget};
use std::fs;
use std::io::Write;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
mod recheck;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("observer requires disposable private ext4 fixtures");
        let path = Path::new(&root).join(format!(
            "query-observer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn raw(&self, sha: &str) -> PathBuf {
        let name = fs::read_dir(&self.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name();
        self.0
            .join(name)
            .join("objects")
            .join(&sha[..2])
            .join(&sha[2..4])
            .join(sha)
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
        owner_generation: 3,
    }
}
struct SoftwareIo;
impl Boundary for SoftwareIo {
    fn admit(&mut self, binding: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        if binding != &self::binding() {
            return Err("fixture owner differs".into());
        }
        binding.validate()?;
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        match access {
            Access::Inspect { binding } | Access::Mutate { binding, .. }
                if binding == &self::binding() =>
            {
                Ok(())
            }
            _ => Err("fixture unrelated access refused".into()),
        }
    }
}
fn setup(count: usize) -> (Fixture, Context, Vec<(String, Vec<u8>)>) {
    let fixture = Fixture::new();
    let budget = IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 64 * 1024 * 1024,
        new_files: 4096,
    };
    let mutation = Mutation {
        review_sha256: "c".repeat(64),
        decision: DecisionKind::Published,
        source_bytes: 4096,
    };
    let store =
        ObjectStore::create_at(&fixture.0, &binding(), budget, &mutation, &mut SoftwareIo).unwrap();
    let mut objects = Vec::new();
    for i in 0..count {
        let bytes = format!("exact-observed-object-{i}").into_bytes();
        let sha = store
            .prepare_page(&bytes, budget, &mutation, &mut SoftwareIo)
            .unwrap();
        objects.push((sha, bytes));
    }
    let physical = store
        .inventory(
            IoBudget {
                read_bytes: budget.read_bytes,
                write_bytes: 0,
                new_files: 0,
            },
            &mut SoftwareIo,
            |_| Ok(()),
        )
        .unwrap();
    let head = OwnerHeadV2::empty_data(&binding(), physical).unwrap();
    let context = Context {
        schema_version: 1,
        binding: binding(),
        source_request_sha256: "d".repeat(64),
        source_profile: "luma-observer-software-fixture-v1".into(),
        selected_before_sha256: head.sha256().unwrap(),
        selected_before: head,
        lease: crate::resources::Token {
            lease_id: "e".repeat(32),
            generation: 9,
            manager_epoch: "f".repeat(32),
        },
    };
    (fixture, context, objects)
}
fn serving(path: PathBuf) -> (UnixStream, thread::JoinHandle<bool>) {
    let (client, server) = UnixStream::pair().unwrap();
    let thread = thread::spawn(move || {
        let peer = endpoint::Peer::software_fixture(&server).unwrap();
        server::handle(&server, peer, &path).is_ok()
    });
    (client, thread)
}
fn begin<'a>(
    socket: UnixStream,
    context: Context,
    live: &'a mut dyn FnMut() -> Result<()>,
) -> Client<'a> {
    let peer = endpoint::Peer::software_fixture(&socket).unwrap();
    Client::begin_pinned(socket, peer, context, live).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(RPC_MS)
}
fn request(
    context: &Context,
    session: Option<String>,
    sequence: u32,
    operation: Operation,
) -> Request {
    Request {
        schema_version: 1,
        nonce: crate::resources::random_id().unwrap(),
        deadline_ms: now().unwrap() + RPC_MS,
        session_id: session,
        sequence,
        context_sha256: context.sha256().unwrap(),
        operation,
    }
}
fn exchange(socket: &UnixStream, request: &Request) -> Response {
    wire::send(
        socket,
        &serde_json::to_vec(request).unwrap(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    canonical(&wire::receive(socket, deadline(), &mut || Ok(())).unwrap()).unwrap()
}

#[test]
fn real_same_fd_raw_metadata_recheck_and_explicit_end() {
    let (fixture, context, objects) = setup(1);
    let (socket, server) = serving(fixture.0.clone());
    let mut original = || Ok(());
    let mut client = begin(socket, context.clone(), &mut original);
    assert_eq!(client.namespace_data().binding, context.binding);
    let (bytes, data) = client.observe(&objects[0].0, &mut || Ok(())).unwrap();
    assert_eq!(bytes, objects[0].1);
    match data {
        RawObjectObservationData::Present { complete, file, .. } => {
            assert!(complete);
            assert_eq!(file.bytes, bytes.len() as u64);
            assert!(file.inode > 0);
            assert!(file.mount_id > 0);
        }
        _ => panic!("actual existing object missing"),
    }
    assert_eq!(
        client.observe(&objects[0].0, &mut || Ok(())).unwrap().0,
        bytes
    );
    assert_eq!(client.retained_count(), 1);
    client.finish(&mut || Ok(())).unwrap();
    assert!(server.join().unwrap());
}

#[test]
fn ephemeral_merkle_reads_do_not_consume_64_retained_slots() {
    let (fixture, context, objects) = setup(70);
    let (socket, server) = serving(fixture.0.clone());
    let mut original = || Ok(());
    let mut client = begin(socket, context, &mut original);
    for (sha, bytes) in &objects {
        assert_eq!(
            client
                .read_observed_page(&binding(), sha, 16384, &mut || Ok(()))
                .unwrap(),
            *bytes
        );
    }
    assert_eq!(client.retained_count(), 0);
    for (sha, _) in objects.iter().take(64) {
        client.observe(sha, &mut || Ok(())).unwrap();
    }
    assert_eq!(client.retained_count(), 64);
    assert!(client.observe(&objects[64].0, &mut || Ok(())).is_err());
    // Rechecks still work; no automatic eviction/replacement occurred.
    client.observe(&objects[0].0, &mut || Ok(())).unwrap();
    client.finish(&mut || Ok(())).unwrap();
    assert!(server.join().unwrap());
}

#[test]
fn actual_server_65th_retained_observation_refuses_before_private_read() {
    let (fixture, context, objects) = setup(64);
    let (socket, server) = serving(fixture.0.clone());
    let first = exchange(
        &socket,
        &request(
            &context,
            None,
            0,
            Operation::Begin {
                context: context.clone(),
            },
        ),
    );
    for (i, (sha, _)) in objects.iter().enumerate() {
        let response = exchange(
            &socket,
            &request(
                &context,
                Some(first.session_id.clone()),
                i as u32 + 1,
                Operation::Observe {
                    object_sha256: sha.clone(),
                },
            ),
        );
        assert!(matches!(response.data, Data::Observed { slot, .. } if usize::from(slot) == i));
    }
    let invalid_private_object = "1".repeat(64);
    // If this reaches private I/O the malformed prefix would refuse too, so
    // the server branch's before-I/O capacity check is also source-reviewed.
    let last = request(
        &context,
        Some(first.session_id),
        65,
        Operation::Observe {
            object_sha256: invalid_private_object,
        },
    );
    wire::send(
        &socket,
        &serde_json::to_vec(&last).unwrap(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    assert!(wire::receive(&socket, deadline(), &mut || Ok(())).is_err());
    assert!(!server.join().unwrap());
}

#[test]
fn real_incomplete_absent_and_same_inode_tampering_never_become_pages() {
    let (fixture, context, objects) = setup(1);
    let path = fixture.raw(&objects[0].0);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"incomplete").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let (socket, server) = serving(fixture.0.clone());
    let mut original = || Ok(());
    let mut client = begin(socket, context, &mut original);
    let (bytes, data) = client.observe(&objects[0].0, &mut || Ok(())).unwrap();
    assert_eq!(bytes, b"incomplete");
    assert!(matches!(
        data,
        RawObjectObservationData::Present {
            complete: false,
            ..
        }
    ));
    let (_, absent) = client.observe(&"2".repeat(64), &mut || Ok(())).unwrap();
    assert!(matches!(absent, RawObjectObservationData::Absent { .. }));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"other-data").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(client.observe(&objects[0].0, &mut || Ok(())).is_err());
    drop(client);
    assert!(!server.join().unwrap());
    let (socket, server) = serving(fixture.0.clone());
    let (_, context, _) = setup(0);
    // Same binding but unrelated head remains DATA; this fixture does not
    // authenticate it as C. The actual raw incomplete bytes still refuse.
    let mut client = begin(socket, context, &mut original);
    assert!(client
        .read_observed_page(&binding(), &objects[0].0, 16384, &mut || Ok(()))
        .is_err());
    drop(client);
    assert!(!server.join().unwrap());
}

#[test]
fn strict_context_nonce_sequence_deadline_and_closed_canonical_data() {
    let (fixture, context, _) = setup(0);
    for attack in 0..7 {
        let (socket, server) = serving(fixture.0.clone());
        let first = exchange(
            &socket,
            &request(
                &context,
                None,
                0,
                Operation::Begin {
                    context: context.clone(),
                },
            ),
        );
        let mut next = request(&context, Some(first.session_id), 1, Operation::End);
        match attack {
            0 => next.context_sha256 = "1".repeat(64),
            1 => next.sequence = 2,
            2 => next.session_id = Some("2".repeat(32)),
            3 => next.deadline_ms = now().unwrap(),
            4 => {
                next.operation = Operation::Begin {
                    context: context.clone(),
                }
            }
            5 => next.deadline_ms = now().unwrap() + RPC_MS + 1000,
            _ => next.nonce = first.nonce,
        }
        wire::send(
            &socket,
            &serde_json::to_vec(&next).unwrap(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
        assert!(wire::receive(&socket, deadline(), &mut || Ok(())).is_err());
        assert!(!server.join().unwrap());
    }
    let mut value = serde_json::to_value(&context).unwrap();
    value["grant_returned"] = serde_json::json!(true);
    assert!(canonical::<Context>(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut stale = context.clone();
    stale.selected_before_sha256 = "1".repeat(64);
    assert!(stale.validate().is_err());
    let mut stale = context.clone();
    stale.lease.generation = 0;
    assert!(stale.validate().is_err());
    let mut stale = context;
    stale.source_profile = "../../path".into();
    assert!(stale.validate().is_err());
}

#[test]
fn maximum_blob_fits_finite_rpc_capacity_and_exhausted_sequence_refuses() {
    assert!(4096 + 64 + 1 + 2 < MAX_RPCS);
    let (fixture, context, _) = setup(0);
    let mut edge = request(&context, Some("1".repeat(32)), MAX_RPCS - 1, Operation::End);
    edge.validate().unwrap();
    edge.sequence = MAX_RPCS;
    assert!(edge.validate().is_err());
    let (socket, server) = serving(fixture.0.clone());
    let first = exchange(
        &socket,
        &request(
            &context,
            None,
            0,
            Operation::Begin {
                context: context.clone(),
            },
        ),
    );
    edge.session_id = Some(first.session_id);
    wire::send(
        &socket,
        &serde_json::to_vec(&edge).unwrap(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    assert!(wire::receive(&socket, deadline(), &mut || Ok(())).is_err());
    assert!(!server.join().unwrap());
}

#[test]
fn actual_stalled_response_observes_original_revocation_and_owned_socket_close() {
    let (fixture, context, _) = setup(0);
    let (socket, server_socket) = UnixStream::pair().unwrap();
    let actual_namespace = {
        let store = ObjectStore::open_at(
            &fixture.0,
            &binding(),
            IoBudget {
                read_bytes: READ_BYTES,
                write_bytes: 0,
                new_files: 0,
            },
            &mut SoftwareIo,
        )
        .unwrap();
        store
            .observe_namespace(
                IoBudget {
                    read_bytes: READ_BYTES,
                    write_bytes: 0,
                    new_files: 0,
                },
                &mut SoftwareIo,
            )
            .unwrap()
            .data()
            .clone()
    };
    let revoked = Arc::new(AtomicBool::new(false));
    let signal = revoked.clone();
    let (seen, wait) = mpsc::channel();
    let server = thread::spawn(move || {
        let first_bytes = wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
        let first: Request = canonical(&first_bytes).unwrap();
        let response = Response {
            schema_version: 1,
            nonce: first.nonce,
            request_sha256: luma_content::sha256(&first_bytes),
            context_sha256: first.context_sha256,
            session_id: "1".repeat(32),
            sequence: 0,
            data: Data::Begun {
                namespace: actual_namespace,
            },
        };
        wire::send(
            &server_socket,
            &serde_json::to_vec(&response).unwrap(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
        // This marker proves an actual full RPC was received before refusal;
        // no arbitrary callback-count assumption or fake child state.
        wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
        signal.store(true, Ordering::SeqCst);
        seen.send(()).unwrap();
        assert!(wire::receive(&server_socket, deadline(), &mut || Ok(())).is_err());
    });
    let mut original = || {
        if revoked.load(Ordering::SeqCst) {
            Err("fixture original Standard window revoked".into())
        } else {
            Ok(())
        }
    };
    let mut client = begin(socket, context, &mut original);
    let started = Instant::now();
    assert!(client.observe(&"3".repeat(64), &mut || Ok(())).is_err());
    wait.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(client);
    server.join().unwrap();
}

#[test]
fn real_kernel_fixture_label_is_not_accepted_as_fixed_product_peer() {
    let (a, b) = UnixStream::pair().unwrap();
    let actual = endpoint::Peer::software_fixture(&a).unwrap();
    actual.check(&a).unwrap();
    assert!(endpoint::Peer::capture(&a, C_PEER).is_err());
    assert!(endpoint::Peer::capture(&b, OBSERVER).is_err());
}

#[test]
fn actual_fragmented_binary_frames_are_bounded_and_truncated_data_refuses() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let payload: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
    let expected = payload.clone();
    let sender = thread::spawn(move || {
        b.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        b.write_all(&(payload.len() as u32).to_be_bytes()).unwrap();
        for chunk in payload.chunks(37) {
            b.write_all(chunk).unwrap();
        }
    });
    assert_eq!(
        wire::receive(&a, deadline(), &mut || Ok(())).unwrap(),
        expected
    );
    sender.join().unwrap();
    for size in [0u32, (FRAME + 1) as u32] {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&size.to_be_bytes()).unwrap();
        assert!(wire::receive(&a, deadline(), &mut || Ok(())).is_err());
    }
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(&8u32.to_be_bytes()).unwrap();
    b.write_all(b"123").unwrap();
    b.shutdown(Shutdown::Write).unwrap();
    assert!(wire::receive(&a, deadline(), &mut || Ok(())).is_err());
}

#[test]
fn substituted_responses_poison_owned_channel_without_returning_bytes() {
    let (fixture, context, objects) = setup(1);
    let budget = IoBudget {
        read_bytes: READ_BYTES,
        write_bytes: 0,
        new_files: 0,
    };
    let store = ObjectStore::open_at(&fixture.0, &binding(), budget, &mut SoftwareIo).unwrap();
    let held = store.observe_namespace(budget, &mut SoftwareIo).unwrap();
    let (_, raw) = store
        .observe_raw_object(&held, &objects[0].0, budget, &mut SoftwareIo)
        .unwrap();
    for attack in 0..8 {
        let (socket, server_socket) = UnixStream::pair().unwrap();
        let namespace = held.data().clone();
        let raw = raw.data().clone();
        let bytes = objects[0].1.clone();
        let fake = thread::spawn(move || {
            let first_bytes = wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
            let first: Request = canonical(&first_bytes).unwrap();
            let response = Response {
                schema_version: 1,
                nonce: first.nonce,
                request_sha256: luma_content::sha256(&first_bytes),
                context_sha256: first.context_sha256.clone(),
                session_id: "1".repeat(32),
                sequence: 0,
                data: Data::Begun { namespace },
            };
            wire::send(
                &server_socket,
                &serde_json::to_vec(&response).unwrap(),
                deadline(),
                &mut || Ok(()),
            )
            .unwrap();
            let next_bytes = wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
            let next: Request = canonical(&next_bytes).unwrap();
            let mut response = Response {
                schema_version: 1,
                nonce: next.nonce,
                request_sha256: luma_content::sha256(&next_bytes),
                context_sha256: first.context_sha256,
                session_id: "1".repeat(32),
                sequence: 1,
                data: Data::Observed {
                    slot: 0,
                    object: raw,
                    bytes_hex: bytes_hex(&bytes),
                },
            };
            match attack {
                0 => response.nonce = "2".repeat(32),
                1 => response.request_sha256 = "2".repeat(64),
                2 => response.context_sha256 = "2".repeat(64),
                3 => response.session_id = "2".repeat(32),
                4 => response.sequence = 2,
                5 => {
                    if let Data::Observed { slot, .. } = &mut response.data {
                        *slot = 1;
                    }
                }
                6 => {
                    if let Data::Observed { bytes_hex, .. } = &mut response.data {
                        *bytes_hex = "00".into();
                    }
                }
                _ => {
                    if let Data::Observed {
                        object: RawObjectObservationData::Present { file, .. },
                        ..
                    } = &mut response.data
                    {
                        file.mode = libc::S_IFREG | 0o600;
                    }
                }
            }
            wire::send(
                &server_socket,
                &serde_json::to_vec(&response).unwrap(),
                deadline(),
                &mut || Ok(()),
            )
            .unwrap();
            assert!(wire::receive(&server_socket, deadline(), &mut || Ok(())).is_err());
        });
        let mut original = || Ok(());
        let mut client = begin(socket, context.clone(), &mut original);
        assert!(client.observe(&objects[0].0, &mut || Ok(())).is_err());
        assert!(client.observe(&objects[0].0, &mut || Ok(())).is_err());
        drop(client);
        fake.join().unwrap();
    }
}
