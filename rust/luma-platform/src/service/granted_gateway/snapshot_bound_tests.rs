//! Structural finite-bound tests only, not a principal/grant/C qualification.
use super::*;
fn pair() -> [Use; 2] {
    use crate::finite_grants as g;
    let read = Use {
        action: Action::Read,
        selector: Selector {
            kind: Kind::File,
            id: g::SNAPSHOT_READ_ID.into(),
            generation: 1,
            digest: "a".repeat(64),
        },
        input_bytes: 128 * 1024 * 1024,
        output_bytes: g::SNAPSHOT_MAX_REVIEW_BYTES,
        units: 1,
    };
    let export = Use {
        action: Action::Export,
        selector: Selector {
            kind: Kind::Artifact,
            id: g::SNAPSHOT_EXPORT_ID.into(),
            ..read.selector.clone()
        },
        output_bytes: g::SNAPSHOT_MAX_EXPORT_BYTES,
        ..read.clone()
    };
    [read, export]
}
#[test]
fn snapshot_diagnostic_bridge_cannot_expand_legacy_or_accept_cross_kind_or_pair() {
    let [read, export] = pair();
    assert_eq!(PAYLOAD_MAX, 256 * 1024 * 1024);
    assert_eq!(
        snapshot_delivery_bound(&read, &export).unwrap().maximum,
        crate::finite_grants::SNAPSHOT_MAX_EXPORT_BYTES
    );
    for which in 0..6 {
        let mut changed = export.clone();
        match which {
            0 => changed.selector.id.push('x'),
            1 => changed.selector.kind = Kind::File,
            2 => changed.action = Action::Write,
            3 => changed.selector.generation += 1,
            4 => changed.selector.digest = "b".repeat(64),
            _ => changed.input_bytes -= 1,
        }
        assert!(snapshot_delivery_bound(&read, &changed).is_err());
    }
    let mut changed = export.clone();
    changed.output_bytes += 1;
    assert!(snapshot_delivery_bound(&read, &changed).is_err());
    let (producer, consumer) = UnixStream::pair().unwrap();
    let writer = CheckedPayload::diagnostic_socket(producer).unwrap();
    assert_eq!(writer.checked_measurement(), (0, Sha256::digest([]).into()));
    drop(consumer);
}
