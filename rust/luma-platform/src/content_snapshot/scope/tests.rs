use super::*;
use luma_content::OwnerBinding;
use luma_content_store::v2::{backup::SNAPSHOT_PROFILE, head::OwnerHeadV2, PhysicalInventory};

pub(crate) fn input() -> Input {
    // Structural request fixtures, not valid X509 recipients or trusted custody.
    let recipients = backup_crypto::RecipientPins {
        owner: backup_crypto::RecipientPin {
            certificate_sha256: artifacts::digest(&[1]),
            spki_sha256: "a".repeat(64),
        },
        offline_admin: backup_crypto::RecipientPin {
            certificate_sha256: artifacts::digest(&[2]),
            spki_sha256: "b".repeat(64),
        },
    };
    let head = OwnerHeadV2::empty_data(
        &OwnerBinding {
            installation: "c".repeat(64),
            owner: "d".repeat(64),
            owner_generation: 7,
        },
        PhysicalInventory::default(),
    )
    .unwrap();
    Input {
        schema_version: 1,
        login: "owner".into(),
        intent: SnapshotIntent {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            snapshot_id: "e".repeat(64),
            head_sha256: head.sha256().unwrap(),
            head,
            recipient_generation: 9,
            recipients_sha256: artifacts::digest(&serde_json::to_vec(&recipients).unwrap()),
            origin_spki_sha256: "f".repeat(64),
        },
        mode: SnapshotMode::Review,
        budget: SnapshotBudget {
            read_bytes: grants::SNAPSHOT_MAX_READ_BYTES,
            output_bytes: 0,
            maximum_objects: 4_194_303,
            maximum_parts: 131072,
        },
        review: None,
        recipients,
        owner_certificate_der_hex: "01".into(),
        offline_admin_certificate_der_hex: "02".into(),
    }
}
#[test]
fn canonical_source_commits_every_request_field_and_rejects_transport_substitution() {
    let original = input();
    let bytes = original.canonical_bytes().unwrap();
    assert_eq!(
        Input::from_canonical(&bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes
    );
    let profile = original.profile().unwrap();
    assert_eq!(
        parse_profile(&profile).unwrap().source_sha256,
        artifacts::digest(&bytes)
    );
    let mut modified = original.clone();
    modified.login = "other".into();
    assert_ne!(profile, modified.profile().unwrap());
    modified = original.clone();
    modified.budget.maximum_parts -= 1;
    assert_ne!(profile, modified.profile().unwrap());
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert!(Input::from_canonical(&padded).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["trusted"] = serde_json::json!(true);
    assert!(Input::from_canonical(&serde_json::to_vec(&unknown).unwrap()).is_err());
    modified = original.clone();
    modified.recipients.owner.spki_sha256 = "1".repeat(64);
    assert!(modified.validate().is_err());
    modified = original;
    modified.mode = SnapshotMode::Export;
    assert!(modified.validate().is_err());
}
#[test]
fn exact_pair_requires_export_purpose_both_grants_and_identical_request_target() {
    let request = input();
    let profile = request.profile().unwrap();
    let installation = &request.intent.head.binding.installation;
    let [read, export] = uses(&profile, "8:1", installation).unwrap();
    let pair = vec![
        ("read-grant".into(), read),
        ("export-grant".into(), export.clone()),
    ];
    assert_eq!(
        export_pair(
            &profile,
            "8:1",
            installation,
            &pair,
            &export,
            SessionPurpose::Export
        )
        .unwrap(),
        1
    );
    let mut reversed = pair.clone();
    reversed.reverse();
    assert_eq!(
        export_pair(
            &profile,
            "8:1",
            installation,
            &reversed,
            &export,
            SessionPurpose::Export
        )
        .unwrap(),
        0
    );
    for purpose in [
        SessionPurpose::Standard,
        SessionPurpose::ModelImport,
        SessionPurpose::ModelActivation,
        SessionPurpose::ModelQa,
    ] {
        assert!(export_pair(&profile, "8:1", installation, &pair, &export, purpose).is_err());
    }
    assert!(export_pair(
        &profile,
        "8:2",
        installation,
        &pair,
        &export,
        SessionPurpose::Export
    )
    .is_err());
    assert!(export_pair(
        &profile,
        "8:1",
        &"1".repeat(64),
        &pair,
        &export,
        SessionPurpose::Export
    )
    .is_err());
    for index in 0..2 {
        let mut bad = pair.clone();
        bad[index].1.input_bytes -= 1;
        assert!(export_pair(
            &profile,
            "8:1",
            installation,
            &bad,
            &export,
            SessionPurpose::Export
        )
        .is_err());
    }
    let mut bad = pair.clone();
    bad[0].0 = bad[1].0.clone();
    assert!(export_pair(
        &profile,
        "8:1",
        installation,
        &bad,
        &export,
        SessionPurpose::Export
    )
    .is_err());
    assert!(export_pair(
        &profile,
        "8:1",
        installation,
        &pair[..1],
        &export,
        SessionPurpose::Export
    )
    .is_err());
}
#[test]
fn profile_bounds_do_not_widen_sessions_generic_grants_or_storage_targets() {
    let request = input();
    let profile = request.profile().unwrap();
    for bad in [
        profile.replace("-7-", "-07-"),
        profile.replace("-7-", "-0-"),
        format!("{profile}-extra"),
        profile.replacen("snapshot-v1-review", "snapshot-v1-restore", 1),
        profile.replace("-32768-", "-32769-"),
        profile.replace(
            parse_profile(&profile).unwrap().source_sha256,
            &"0".repeat(64),
        ),
    ] {
        assert!(parse_profile(&bad).is_err());
    }
    for device in ["0:1", "08:1", "8:01", "8:1:2", "-8:1", "8:", "path"] {
        assert!(uses(&profile, device, &request.intent.head.binding.installation).is_err());
    }
    assert!(uses(&profile, "8:1", &"0".repeat(64)).is_err());
    let export = format!(
        "snapshot-v1-export-7-{}-{}-{}",
        grants::SNAPSHOT_MAX_READ_BYTES,
        luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES,
        "a".repeat(64)
    );
    assert!(parse_profile(&export).is_ok());
    assert!(parse_profile(&export.replace(
        &luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES.to_string(),
        &(luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES + 1).to_string()
    ))
    .is_err());
}
