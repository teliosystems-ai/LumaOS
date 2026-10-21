use super::*;
use crate::finite_grants;
use luma_content_store::v2::{
    backup::{PartDirectoryRef, SnapshotReview, SNAPSHOT_PROFILE},
    PhysicalInventory,
};

fn body(public: &[u8]) -> (scope::Input, Body) {
    // Consistent inert manifest DATA only: no filesystem inventory, recipient
    // custody, C selection or production signer is claimed by this fixture.
    let mut input = scope::tests::input();
    input.mode = SnapshotMode::Export;
    input.budget.output_bytes = luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES;
    input.intent.origin_spki_sha256 = artifacts::digest(public);
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: input.intent.sha256().unwrap(),
        inventory: PhysicalInventory {
            regular_files: 1,
            directories: 2,
            ..PhysicalInventory::default()
        },
        object_count: 0,
        object_bytes: 0,
        stream_sha256: "1".repeat(64),
        review_sha256: String::new(),
    };
    review.review_sha256 = artifacts::digest(&serde_json::to_vec(&review).unwrap());
    review.validate(&input.intent).unwrap();
    input.review = Some(review.clone());
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent: input.intent.clone(),
        review,
        parts: PartDirectoryRef {
            sha256: "2".repeat(64),
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
        last_plaintext_sha256: "3".repeat(64),
    };
    let audit = finite_grants::Audit {
        subject: input.intent.head.binding.owner.clone(),
        subject_generation: input.intent.head.binding.owner_generation,
        grant_id: "export-grant".into(),
        grant_version: 1,
        checkpoint_head: "4".repeat(64),
        operation_id: Some("a".repeat(32)),
        usage: scope::uses(
            &input.profile().unwrap(),
            "8:1",
            &input.intent.head.binding.installation,
        )
        .unwrap()[1]
            .clone(),
    };
    let body = Body::new_data(
        &input,
        manifest,
        8192,
        "8:1",
        &crate::bundle::hex(public),
        &"5".repeat(64),
        audit,
    )
    .unwrap();
    (input, body)
}
#[test]
fn whole_receipt_binds_complete_manifest_source_output_and_original_attribution() {
    let mut public = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    public.extend([1; 32]);
    let (input, original) = body(&public);
    original.check_source(&input).unwrap();
    assert_eq!(&original.manifest, original.manifest());
    assert_eq!(&original.original_authority, original.audit());
    assert!(original.message().unwrap().len() < receipt_signer::MAX_MESSAGE - 4096);
    let mut changed_input = input.clone();
    changed_input.login = "other".into();
    assert!(original.check_source(&changed_input).is_err());
    let mut changed = original.clone();
    changed.manifest.parts.sha256 = "9".repeat(64);
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.measured_package_bytes = changed.manifest.ciphertext_bytes;
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.measured_package_bytes = input.budget.output_bytes + 1;
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.original_authority.subject_generation += 1;
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.original_authority.operation_id = None;
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.storage_device = "8:2".into();
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.schema_version = 1;
    assert!(changed.validate().is_err());
    changed = original;
    changed.purpose = "luma-content-measured-backup-export-v1".into();
    assert!(changed.validate().is_err());
}
#[test]
fn actual_origin_crypto_rejects_cross_key_modified_bytes_and_live_revocation() {
    let (seed, public) = receipt_signer::generate(|| Ok(())).unwrap();
    let (input, body) = body(&public);
    let signature = receipt_signer::sign(&seed, &body.message().unwrap(), || Ok(())).unwrap();
    let receipt = Receipt {
        body,
        signature_hex: crate::bundle::hex(&signature),
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let parsed = Receipt::from_canonical(&bytes).unwrap();
    let pin = artifacts::digest(&public);
    parsed.verify_origin(&pin, &mut || Ok(())).unwrap();
    parsed.body.check_source(&input).unwrap();
    let (_, other) = receipt_signer::generate(|| Ok(())).unwrap();
    assert!(parsed
        .verify_origin(&artifacts::digest(&other), &mut || Ok(()))
        .is_err());
    let mut changed = parsed.clone();
    changed.body.measured_package_bytes += 1;
    changed.body.validate().unwrap();
    assert!(changed.verify_origin(&pin, &mut || Ok(())).is_err());
    changed = parsed.clone();
    changed.signature_hex.replace_range(
        ..2,
        if &parsed.signature_hex[..2] == "00" {
            "01"
        } else {
            "00"
        },
    );
    assert!(changed.verify_origin(&pin, &mut || Ok(())).is_err());
    let mut checks = 0;
    assert!(parsed
        .verify_origin(&pin, &mut || {
            checks += 1;
            Err("fixture revoked original operation".into())
        })
        .is_err());
    assert_eq!(checks, 1);
    let mut padded = bytes;
    padded.push(b' ');
    assert!(Receipt::from_canonical(&padded).is_err());
    let mut value = serde_json::to_value(parsed).unwrap();
    value["authority"] = serde_json::json!(true);
    assert!(Receipt::from_canonical(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn package_header_retains_exact_recovery_certificates_without_duplicate_manifest() {
    let (seed, public) = receipt_signer::generate(|| Ok(())).unwrap();
    let (input, body) = body(&public);
    let signature = receipt_signer::sign(&seed, &body.message().unwrap(), || Ok(())).unwrap();
    let receipt = Receipt {
        body,
        signature_hex: crate::bundle::hex(&signature),
    };
    let header = Header::new_data(&input, receipt).unwrap();
    let bytes = header.canonical_bytes().unwrap();
    let parsed = Header::from_canonical(&bytes).unwrap();
    assert_eq!(
        parsed.source().unwrap().canonical_bytes().unwrap(),
        input.canonical_bytes().unwrap()
    );
    parsed
        .receipt
        .verify_origin(&artifacts::digest(&public), &mut || Ok(()))
        .unwrap();
    let mut bad = parsed.clone();
    bad.owner_certificate_der_hex = "02".into();
    assert!(bad.canonical_bytes().is_err());
    bad = parsed.clone();
    bad.budget.maximum_parts -= 1;
    assert!(bad.source().is_err());
    bad = parsed.clone();
    bad.login = "other".into();
    assert!(bad.source().is_err());
    let mut padded = bytes;
    padded.push(b' ');
    assert!(Header::from_canonical(&padded).is_err());
    assert!(Header::from_canonical(&vec![b' '; 65537]).is_err());
    let mut unknown = serde_json::to_value(parsed).unwrap();
    unknown["authority"] = serde_json::json!(true);
    assert!(Header::from_canonical(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn fresh_source_profile_cannot_sign_a_manifest_beyond_reviewed_part_or_object_work() {
    let mut public = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    public.extend([1; 32]);
    let (mut input, mut original) = body(&public);
    let mut review = original.manifest.review.clone();
    review.object_count = 33;
    review.object_bytes = 33;
    review.inventory.regular_files = 34;
    review.inventory.logical_bytes = 33;
    review.review_sha256.clear();
    review.review_sha256 = artifacts::digest(&serde_json::to_vec(&review).unwrap());
    input.review = Some(review.clone());
    original.manifest.review = review;
    original.manifest.part_count = 2;
    original.manifest.parts.count = 2;
    original.manifest.parts.objects = 33;
    original.manifest.parts.plaintext_bytes = 200;
    original.manifest.parts.ciphertext_bytes = 220;
    original.manifest.plaintext_bytes = 200;
    original.manifest.ciphertext_bytes = 220;
    original.manifest.validate().unwrap();
    input.budget.maximum_parts = 1;
    input.validate().unwrap();
    // Bind a NEW, internally consistent attribution/profile for the lowered
    // budget: rejection must not rely on detecting only an old request hash.
    let mut audit = original.original_authority.clone();
    audit.usage = scope::uses(
        &input.profile().unwrap(),
        "8:1",
        &input.intent.head.binding.installation,
    )
    .unwrap()[1]
        .clone();
    assert!(Body::new_data(
        &input,
        original.manifest.clone(),
        8192,
        "8:1",
        &crate::bundle::hex(&public),
        &"5".repeat(64),
        audit
    )
    .is_err());
    input.budget.maximum_parts = 2;
    input.budget.maximum_objects = 32;
    assert!(input.validate().is_err());
    input.budget.maximum_objects = 33;
    input.budget.read_bytes = 128 * 1024 * 1024;
    assert!(input.validate().is_err());
}
