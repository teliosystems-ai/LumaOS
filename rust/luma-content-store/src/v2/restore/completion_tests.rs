//! Closed pure DATA terminal invariants only. These fixtures do not claim an
//! origin signature, actual filesystem, original Admin or C selection.
use super::super::super::backup::{
    PartDirectoryRef, SnapshotIntent, SnapshotReview, SNAPSHOT_PROFILE,
};
use super::*;
fn fixture() -> (WholeSnapshotManifest, RestorePrefix) {
    let origin = OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    };
    let head = OwnerHeadV2::empty_data(&origin, PhysicalInventory::default()).unwrap();
    let intent = SnapshotIntent {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        snapshot_id: "c".repeat(64),
        head_sha256: head.sha256().unwrap(),
        head,
        recipient_generation: 1,
        recipients_sha256: "d".repeat(64),
        origin_spki_sha256: "e".repeat(64),
    };
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        inventory: PhysicalInventory {
            regular_files: 1,
            directories: 2,
            ..PhysicalInventory::default()
        },
        object_count: 0,
        object_bytes: 0,
        stream_sha256: "f".repeat(64),
        review_sha256: String::new(),
    };
    review.review_sha256 = luma_content::sha256(&serde_json::to_vec(&review).unwrap());
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent,
        review,
        parts: PartDirectoryRef {
            sha256: "1".repeat(64),
            first: 0,
            count: 1,
            height: 0,
            objects: 0,
            plaintext_bytes: 100,
            ciphertext_bytes: 120,
        },
        part_count: 1,
        plaintext_bytes: 100,
        ciphertext_bytes: 120,
        last_plaintext_sha256: "2".repeat(64),
    };
    let target = OwnerBinding {
        installation: "3".repeat(64),
        owner: "4".repeat(64),
        owner_generation: 1,
    };
    let prefix = RestorePrefix {
        schema_version: 1,
        profile: RESTORE_PROFILE.into(),
        job_sha256: "5".repeat(64),
        manifest_sha256: manifest.sha256().unwrap(),
        target: OwnerHeadV2::empty_data(&target, PhysicalInventory::default()).unwrap(),
        request_namespace: "restore".into(),
        stage: RestoreStage::Replaying,
        origin_namespace_sha256: "6".repeat(64),
        job_namespace_sha256: "7".repeat(64),
        import: ImportProgress {
            next_part: 1,
            objects: 0,
            raw_bytes: 0,
            incomplete_objects: 0,
            stream_sha256: manifest.review.stream_sha256.clone(),
            previous_plaintext_sha256: Some(manifest.last_plaintext_sha256.clone()),
            last_object_sha256: None,
        },
        next_source_ordinal: 1,
        published_versions: 0,
        lifecycle_outcomes: 0,
        inert_outcomes: 0,
        verified_final_artifacts: 0,
        mappings: MapRoot::empty(&target, MapKind::RestoreMappings).unwrap(),
        source_lifecycle: MapRoot::empty(&target, MapKind::RestoreSourceLifecycle).unwrap(),
        reservations: RestoreReservations {
            reservation_sha256: "8".repeat(64),
            publication_tail: 2,
            terminal_tail: 1,
            reserved_bytes: 32768,
            reserved_inodes: 3,
        },
    };
    prefix.validate(&manifest).unwrap();
    (manifest, prefix)
}
fn terminal() -> RestoreReservations {
    RestoreReservations {
        reservation_sha256: "9".repeat(64),
        publication_tail: 0,
        terminal_tail: 0,
        reserved_bytes: 0,
        reserved_inodes: 0,
    }
}
#[test]
fn terminal_data_changes_only_stage_and_exact_consumed_work_reservation() {
    let (manifest, prefix) = fixture();
    let next = proposed(&manifest, &prefix, terminal()).unwrap();
    assert_eq!(next.stage, RestoreStage::Complete);
    let mut expected = prefix;
    expected.stage = RestoreStage::Complete;
    expected.reservations = terminal();
    assert_eq!(next, expected);
    next.validate(&manifest).unwrap();
}
#[test]
fn terminal_data_refuses_incomplete_progress_active_tails_or_new_work() {
    let (manifest, prefix) = fixture();
    let mut wrong = prefix.clone();
    wrong.import.next_part = 0;
    assert!(proposed(&manifest, &wrong, terminal()).is_err());
    wrong = prefix.clone();
    wrong.next_source_ordinal = 2;
    assert!(proposed(&manifest, &wrong, terminal()).is_err());
    wrong = prefix.clone();
    wrong.verified_final_artifacts = 1;
    assert!(proposed(&manifest, &wrong, terminal()).is_err());
    let mut work = terminal();
    work.reserved_bytes = 1;
    assert!(proposed(&manifest, &prefix, work).is_err());
    assert!(proposed(&manifest, &prefix, prefix.reservations.clone()).is_err());
    wrong = prefix;
    wrong.stage = RestoreStage::Complete;
    wrong.reservations = terminal();
    assert!(proposed(&manifest, &wrong, terminal()).is_err());
}
