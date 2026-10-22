//! Actual disposable Unix-socket transports under software callback fixtures.
//! No PAM, live native grant/C selection, installed endpoint or signing custody
//! is qualified by these tests. No host service or volume is changed.
use super::super::tests::fixture;
use super::*;
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
fn scope<'a>(input: &'a scope::Input, header: &receipt::Header) -> SnapshotScope<'a> {
    let pair = scope::uses(
        &input.profile().unwrap(),
        "8:1",
        &input.intent.head.binding.installation,
    )
    .unwrap();
    SnapshotScope::new(
        input,
        header,
        "8:1",
        &[
            ("read-fixture".into(), pair[0].clone()),
            ("export-fixture".into(), pair[1].clone()),
        ],
        SessionPurpose::Export,
        &mut || Ok(()),
    )
    .unwrap()
}
fn socket_buffer(socket: &UnixStream, size: i32) {
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        },
        0
    );
}
#[test]
fn actual_acknowledged_binary_package_delivery_requires_terminal_ack_and_exact_digest() {
    let (header, source, _) = fixture();
    let input = header.source().unwrap();
    let scope = scope(&input, &header);
    let (producer, relay_source) = UnixStream::pair().unwrap();
    let (relay_output, mut consumer) = UnixStream::pair().unwrap();
    consumer
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket_buffer(&relay_output, 2048);
    std::thread::scope(|threads| {
        let sender = threads.spawn(|| {
            let mut source = source;
            deliver(
                &header,
                &mut source,
                &scope,
                scope.diagnostic_bound().unwrap(),
                CheckedPayload::diagnostic_socket(producer).unwrap(),
                &mut || Ok(()),
            )
            .unwrap()
        });
        let relay_scope = &scope;
        let relay = threads.spawn(move || {
            relay(
                relay_scope,
                &relay_source,
                &relay_output,
                Instant::now() + Duration::from_secs(10),
                &mut || Ok(()),
            )
            .unwrap()
        });
        let receiver = threads.spawn(move || {
            let mut bytes = Vec::new();
            let mut block = [0; 137];
            loop {
                let n = consumer.read(&mut block).unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&block[..n]);
            }
            bytes
        });
        let sent = sender.join().unwrap();
        let relayed = relay.join().unwrap();
        let bytes = receiver.join().unwrap();
        assert_eq!(sent.bytes, bytes.len() as u64);
        assert_eq!(sent.sha256, crate::artifacts::digest(&bytes));
        assert_eq!(relayed, (sent.bytes, sent.sha256));
        let mut sink = super::super::tests::Sink::default();
        let decoded =
            super::super::decode(&mut std::io::Cursor::new(bytes), &mut sink, &mut || Ok(()))
                .unwrap();
        assert_eq!(decoded.summary.bytes, scope.expected_bytes);
    });
}
#[test]
fn actual_stalled_ack_continues_original_checks_and_revocation_closes_owned_producer() {
    let (header, mut source, _) = fixture();
    let input = header.source().unwrap();
    let scope = scope(&input, &header);
    let (producer, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let live = Arc::new(AtomicBool::new(true));
    std::thread::scope(|threads| {
        let sender_live = Arc::clone(&live);
        let header_ref = &header;
        let source_ref = &mut source;
        let scope_ref = &scope;
        let sender = threads.spawn(move || {
            deliver(
                header_ref,
                source_ref,
                scope_ref,
                scope_ref.diagnostic_bound().unwrap(),
                CheckedPayload::diagnostic_socket(producer).unwrap(),
                &mut || {
                    if sender_live.load(Ordering::SeqCst) {
                        Ok(())
                    } else {
                        Err("fixture original Export revoked during actual ACK wait".into())
                    }
                },
            )
            .is_err()
        });
        let mut size = [0; 4];
        peer.read_exact(&mut size).unwrap();
        let mut first = vec![0; u32::from_be_bytes(size) as usize];
        peer.read_exact(&mut first).unwrap();
        assert!(!first.is_empty());
        // The actual peer has received a full frame and deliberately withholds
        // its ACK. Revocation is therefore not a guessed callback count.
        let start = Instant::now();
        live.store(false, Ordering::SeqCst);
        assert!(sender.join().unwrap());
        assert!(start.elapsed() < Duration::from_secs(3));
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    });
}
#[test]
fn forged_first_and_final_ack_never_return_delivery_completion_even_after_full_bytes() {
    for forge_final in [false, true] {
        let (header, mut source, _) = fixture();
        let input = header.source().unwrap();
        let scope = scope(&input, &header);
        let (producer, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        std::thread::scope(|threads| {
            let sender = threads.spawn(|| {
                deliver(
                    &header,
                    &mut source,
                    &scope,
                    scope.diagnostic_bound().unwrap(),
                    CheckedPayload::diagnostic_socket(producer).unwrap(),
                    &mut || Ok(()),
                )
                .is_err()
            });
            let mut total = 0u64;
            let mut hash = Sha256::new();
            loop {
                let mut size = [0; 4];
                peer.read_exact(&mut size).unwrap();
                let size = u32::from_be_bytes(size) as usize;
                assert!(size <= 4096);
                let mut bytes = vec![0; size];
                peer.read_exact(&mut bytes).unwrap();
                total += size as u64;
                hash.update(&bytes);
                let mut ack = total.to_be_bytes().to_vec();
                ack.extend(hash.clone().finalize());
                if !forge_final || size == 0 {
                    ack[39] ^= 1;
                    peer.write_all(&ack).unwrap();
                    break;
                }
                peer.write_all(&ack).unwrap();
            }
            assert!(sender.join().unwrap());
            if forge_final {
                assert_eq!(total, scope.expected_bytes);
            } else {
                assert!(total < scope.expected_bytes);
            }
        });
    }
}
#[test]
fn actual_output_wouldblock_revocation_is_observed_inside_stall_and_not_native_authority() {
    let (header, source, _) = fixture();
    let input = header.source().unwrap();
    let scope = scope(&input, &header);
    let (producer, relay_source) = UnixStream::pair().unwrap();
    let (relay_output, _consumer) = UnixStream::pair().unwrap();
    socket_buffer(&relay_output, 2048);
    let filler = [0u8; 4096];
    let mut filled = 0;
    loop {
        let count = unsafe {
            libc::send(
                relay_output.as_raw_fd(),
                filler.as_ptr().cast(),
                filler.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
        assert!(count > 0);
        filled += count;
        assert!(filled <= 1024 * 1024);
    }
    assert!(filled > 0);
    std::thread::scope(|threads| {
        let sender = threads.spawn(|| {
            let mut source = source;
            deliver(
                &header,
                &mut source,
                &scope,
                scope.diagnostic_bound().unwrap(),
                CheckedPayload::diagnostic_socket(producer).unwrap(),
                &mut || Ok(()),
            )
            .is_err()
        });
        let mut observed = false;
        let start = Instant::now();
        assert!(relay(
            &scope,
            &relay_source,
            &relay_output,
            Instant::now() + Duration::from_secs(5),
            &mut || {
                if OBSERVED_OUTPUT_STALL.with(|s| s.get()) {
                    observed = true;
                    Err("fixture original window revoked during observed output WouldBlock".into())
                } else {
                    Ok(())
                }
            }
        )
        .is_err());
        assert!(observed);
        assert!(!OBSERVED_OUTPUT_STALL.with(|s| s.get()));
        drop(relay_source);
        assert!(sender.join().unwrap());
        assert!(start.elapsed() < Duration::from_secs(3));
    });
}
#[test]
fn partial_binary_nonblocking_socket_send_preserves_bytes_and_inherited_flags() {
    let (producer, _producer_peer) = UnixStream::pair().unwrap();
    let (output, mut consumer) = UnixStream::pair().unwrap();
    consumer
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket_buffer(&output, 2048);
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    let bytes: Vec<u8> = [0, 255, 10, 13, 128, 27]
        .into_iter()
        .cycle()
        .take(90_001)
        .collect();
    std::thread::scope(|threads| {
        let reader = threads.spawn(|| {
            let mut found = vec![0; bytes.len()];
            consumer.read_exact(&mut found).unwrap();
            found
        });
        send(
            &output,
            &producer,
            &bytes,
            Instant::now() + Duration::from_secs(10),
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(reader.join().unwrap(), bytes);
    });
    assert_eq!(
        unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) },
        flags
    );
}
#[test]
fn scope_data_rejects_substituted_pair_device_purpose_and_revocation_before_transport() {
    let (header, _, _) = fixture();
    let input = header.source().unwrap();
    let uses = scope::uses(
        &input.profile().unwrap(),
        "8:1",
        &input.intent.head.binding.installation,
    )
    .unwrap();
    let pair = [
        ("read-fixture".into(), uses[0].clone()),
        ("export-fixture".into(), uses[1].clone()),
    ];
    for purpose in [
        SessionPurpose::Standard,
        SessionPurpose::ModelImport,
        SessionPurpose::ModelActivation,
        SessionPurpose::ModelQa,
    ] {
        assert!(
            SnapshotScope::new(&input, &header, "8:1", &pair, purpose, &mut || Ok(())).is_err()
        );
    }
    assert!(SnapshotScope::new(
        &input,
        &header,
        "8:2",
        &pair,
        SessionPurpose::Export,
        &mut || Ok(())
    )
    .is_err());
    assert!(SnapshotScope::new(
        &input,
        &header,
        "8:1",
        &pair[..1],
        SessionPurpose::Export,
        &mut || Ok(())
    )
    .is_err());
    let mut duplicate = pair.clone();
    duplicate[1].0 = duplicate[0].0.clone();
    assert!(SnapshotScope::new(
        &input,
        &header,
        "8:1",
        &duplicate,
        SessionPurpose::Export,
        &mut || Ok(())
    )
    .is_err());
    assert!(SnapshotScope::new(
        &input,
        &header,
        "8:1",
        &pair,
        SessionPurpose::Export,
        &mut || Err("fixture original operation revoked".into())
    )
    .is_err());
}
#[test]
fn premature_flush_eof_and_postterminal_data_cannot_be_transport_completion() {
    let (header, _, _) = fixture();
    let input = header.source().unwrap();
    let scope = scope(&input, &header);
    for flush in [false, true] {
        let (mut producer, relay_source) = UnixStream::pair().unwrap();
        let (relay_output, _consumer) = UnixStream::pair().unwrap();
        producer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        std::thread::scope(|threads| {
            let scope_ref = &scope;
            let worker = threads.spawn(move || {
                relay(
                    scope_ref,
                    &relay_source,
                    &relay_output,
                    Instant::now() + Duration::from_secs(3),
                    &mut || Ok(()),
                )
                .is_err()
            });
            producer.write_all(&100u32.to_be_bytes()).unwrap();
            producer.write_all(&[7; 100]).unwrap();
            let mut ack = [0; 40];
            producer.read_exact(&mut ack).unwrap();
            assert_eq!(&ack[..8], &100u64.to_be_bytes());
            if flush {
                producer.write_all(&0u32.to_be_bytes()).unwrap();
            } else {
                producer.shutdown(std::net::Shutdown::Write).unwrap();
            }
            assert!(worker.join().unwrap());
        });
    }
    let (mut producer, relay_source) = UnixStream::pair().unwrap();
    let (relay_output, _consumer) = UnixStream::pair().unwrap();
    producer
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    std::thread::scope(|threads| {
        let scope_ref = &scope;
        let worker = threads.spawn(move || {
            relay(
                scope_ref,
                &relay_source,
                &relay_output,
                Instant::now() + Duration::from_secs(3),
                &mut || Ok(()),
            )
            .is_err()
        });
        let mut remaining = scope.expected_bytes;
        let mut ack = [0; 40];
        while remaining > 0 {
            let count = remaining.min(4096) as usize;
            producer.write_all(&(count as u32).to_be_bytes()).unwrap();
            producer.write_all(&vec![7; count]).unwrap();
            producer.read_exact(&mut ack).unwrap();
            remaining -= count as u64;
        }
        producer.write_all(&0u32.to_be_bytes()).unwrap();
        producer.read_exact(&mut ack).unwrap();
        producer.write_all(&[0, 0, 0, 1, 7]).unwrap();
        assert!(worker.join().unwrap());
    });
    let (producer, relay_source) = UnixStream::pair().unwrap();
    let (relay_output, _consumer) = UnixStream::pair().unwrap();
    assert!(relay(
        &scope,
        &relay_source,
        &relay_output,
        Instant::now() + Duration::from_secs(1801),
        &mut || Ok(())
    )
    .is_err());
    drop(producer);
}
