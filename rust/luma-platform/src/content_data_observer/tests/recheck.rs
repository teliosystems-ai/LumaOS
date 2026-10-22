//! Adversarial response from a disposable socket peer, not product authority.
use super::*;

#[test]
fn changed_recheck_inode_transcript_closes_channel_even_with_same_valid_bytes() {
    let (fixture, context, objects) = setup(1);
    let budget = IoBudget {
        read_bytes: READ_BYTES,
        write_bytes: 0,
        new_files: 0,
    };
    let store = ObjectStore::open_at(&fixture.0, &binding(), budget, &mut SoftwareIo).unwrap();
    let namespace = store.observe_namespace(budget, &mut SoftwareIo).unwrap();
    let (_, raw) = store
        .observe_raw_object(&namespace, &objects[0].0, budget, &mut SoftwareIo)
        .unwrap();
    let namespace = namespace.data().clone();
    let raw = raw.data().clone();
    let bytes = objects[0].1.clone();
    let (socket, server_socket) = UnixStream::pair().unwrap();
    let fake = thread::spawn(move || {
        let first_bytes = wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
        let first: Request = canonical(&first_bytes).unwrap();
        let response = Response {
            schema_version: 1,
            nonce: first.nonce,
            request_sha256: luma_content::sha256(&first_bytes),
            context_sha256: first.context_sha256,
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
        for sequence in 1..=2 {
            let request_bytes = wire::receive(&server_socket, deadline(), &mut || Ok(())).unwrap();
            let request: Request = canonical(&request_bytes).unwrap();
            let data = if sequence == 1 {
                Data::Observed {
                    slot: 0,
                    object: raw.clone(),
                    bytes_hex: bytes_hex(&bytes),
                }
            } else {
                let mut changed = raw.clone();
                if let RawObjectObservationData::Present { file, .. } = &mut changed {
                    file.inode += 1;
                }
                Data::Rechecked {
                    slot: 0,
                    object: changed,
                    bytes_hex: bytes_hex(&bytes),
                }
            };
            let response = Response {
                schema_version: 1,
                nonce: request.nonce,
                request_sha256: luma_content::sha256(&request_bytes),
                context_sha256: request.context_sha256,
                session_id: "1".repeat(32),
                sequence,
                data,
            };
            wire::send(
                &server_socket,
                &serde_json::to_vec(&response).unwrap(),
                deadline(),
                &mut || Ok(()),
            )
            .unwrap();
        }
        assert!(wire::receive(&server_socket, deadline(), &mut || Ok(())).is_err());
    });
    let mut original = || Ok(());
    let mut client = begin(socket, context, &mut original);
    assert_eq!(
        client.observe(&objects[0].0, &mut || Ok(())).unwrap().0,
        objects[0].1
    );
    assert!(client.observe(&objects[0].0, &mut || Ok(())).is_err());
    drop(client);
    fake.join().unwrap();
}

#[test]
fn absent_objects_identity_is_exact_but_directory_mutable_metadata_is_not_authority() {
    let (fixture, _, _) = setup(0);
    let budget = IoBudget {
        read_bytes: READ_BYTES,
        write_bytes: 0,
        new_files: 0,
    };
    let store = ObjectStore::open_at(&fixture.0, &binding(), budget, &mut SoftwareIo).unwrap();
    let namespace = store.observe_namespace(budget, &mut SoftwareIo).unwrap();
    let selector = "1".repeat(64);
    let (_, raw) = store
        .observe_raw_object(&namespace, &selector, budget, &mut SoftwareIo)
        .unwrap();
    let mut record = raw.data().clone();
    match &mut record {
        RawObjectObservationData::Absent {
            missing_component,
            nearest_ancestor,
            ..
        } => {
            assert_eq!(*missing_component, 0);
            nearest_ancestor.modified_seconds += 1;
            nearest_ancestor.bytes += 4096;
        }
        _ => panic!("fixture has no prefix"),
    }
    data::raw(&record, &selector, &[], namespace.data()).unwrap();
    if let RawObjectObservationData::Absent {
        nearest_ancestor, ..
    } = &mut record
    {
        nearest_ancestor.inode += 1;
    }
    assert!(data::raw(&record, &selector, &[], namespace.data()).is_err());
}
