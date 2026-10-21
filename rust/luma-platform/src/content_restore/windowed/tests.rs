//! Actual isolated CMS/locked-buffer tests with disposable RSA software keys.
//! Synthetic original-window observations are NOT PAM, grants, C custody or an
//! installed encrypted-volume qualification. No host credentials or keys used.
use super::*;
use crate::authentication::SessionPurpose;
use crypto::{CryptoBoundary, CryptoBudget, CryptoOperation, CryptoRequest, RecipientPins};
use luma_content::OwnerBinding;
use luma_content_store::v2::restore::{ImportProgress, RestoreReservations, RESTORE_PROFILE};
use luma_content_store::v2::{backup::*, head::OwnerHeadV2, MapKind, MapRoot, PhysicalInventory};
use serde::Serialize;
use std::collections::BTreeMap;
#[derive(Default)]
struct Pages(BTreeMap<String, Vec<u8>>);
impl SnapshotPages for Pages {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.0.insert(sha.into(), bytes.into());
        check()
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        let bytes = self.0.get(sha).cloned().ok_or("fixture page absent")?;
        check()?;
        Ok(bytes)
    }
}
#[derive(Serialize)]
struct Directory<'a> {
    schema_version: u32,
    profile: &'a str,
    intent_sha256: String,
    body: Leaf<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Leaf<'a> {
    Leaf { parts: Vec<&'a PartCommitment> },
}
struct Fixture {
    owner: crypto::tests::KeyFixture,
    admin: crypto::tests::KeyFixture,
    recipients: crypto::Recipients,
}
impl Fixture {
    fn new() -> Self {
        let owner = crypto::tests::KeyFixture::new(3072);
        let admin = crypto::tests::KeyFixture::new(3072);
        let pins = RecipientPins {
            owner: owner.pin.clone(),
            offline_admin: admin.pin.clone(),
        };
        let recipients =
            crypto::Recipients::new(&owner.certificate, &admin.certificate, pins).unwrap();
        Self {
            owner,
            admin,
            recipients,
        }
    }
    fn frame(&self) -> (SnapshotIntent, Vec<u8>) {
        let binding = OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 1,
        };
        let head = OwnerHeadV2::empty_data(&binding, PhysicalInventory::default()).unwrap();
        let intent = SnapshotIntent {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            snapshot_id: "c".repeat(64),
            head_sha256: head.sha256().unwrap(),
            head,
            recipient_generation: 1,
            recipients_sha256: luma_content::sha256(
                &serde_json::to_vec(self.recipients.pins()).unwrap(),
            ),
            origin_spki_sha256: "d".repeat(64),
        };
        let header = SnapshotPartHeader {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            intent_sha256: intent.sha256().unwrap(),
            number: 0,
            previous_plaintext_sha256: None,
            objects: vec![],
        };
        let metadata = serde_json::to_vec(&header).unwrap();
        let mut bytes = b"LUMAV2SNAPSHOT1\n".to_vec();
        bytes.extend((metadata.len() as u32).to_be_bytes());
        bytes.extend(metadata);
        (intent, bytes)
    }
    fn package(
        &self,
        intent: SnapshotIntent,
        bytes: &[u8],
    ) -> (WholeSnapshotManifest, RestorePrefix, Pages, Vec<u8>) {
        let mut guard =
            crypto::tests::Guard::new(&self.recipients, CryptoOperation::Encrypt, bytes);
        let encrypted = crypto::encrypt_data(
            bytes,
            &luma_content::sha256(bytes),
            &self.recipients,
            &mut guard,
        )
        .unwrap();
        let part = PartCommitment {
            number: 0,
            plaintext_sha256: luma_content::sha256(bytes),
            plaintext_bytes: bytes.len() as u64,
            ciphertext_sha256: encrypted.commitment().cms_sha256.clone(),
            ciphertext_bytes: encrypted.bytes().len() as u64,
            objects: 0,
            previous_plaintext_sha256: None,
        };
        let page = serde_json::to_vec(&Directory {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE,
            intent_sha256: intent.sha256().unwrap(),
            body: Leaf::Leaf { parts: vec![&part] },
        })
        .unwrap();
        let sha = luma_content::sha256(&page);
        let mut pages = Pages::default();
        pages.0.insert(sha.clone(), page);
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
            stream_sha256: "e".repeat(64),
            review_sha256: String::new(),
        };
        review.review_sha256 = luma_content::sha256(&serde_json::to_vec(&review).unwrap());
        let manifest = WholeSnapshotManifest {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            intent,
            review,
            parts: PartDirectoryRef {
                sha256: sha,
                first: 0,
                count: 1,
                height: 0,
                objects: 0,
                plaintext_bytes: part.plaintext_bytes,
                ciphertext_bytes: part.ciphertext_bytes,
            },
            part_count: 1,
            plaintext_bytes: part.plaintext_bytes,
            ciphertext_bytes: part.ciphertext_bytes,
            last_plaintext_sha256: part.plaintext_sha256,
        };
        let target = OwnerBinding {
            installation: "1".repeat(64),
            owner: "2".repeat(64),
            owner_generation: 1,
        };
        let prefix = RestorePrefix {
            schema_version: 1,
            profile: RESTORE_PROFILE.into(),
            job_sha256: "3".repeat(64),
            manifest_sha256: manifest.sha256().unwrap(),
            target: OwnerHeadV2::empty_data(&target, PhysicalInventory::default()).unwrap(),
            request_namespace: "restore".into(),
            stage: RestoreStage::Importing,
            origin_namespace_sha256: "4".repeat(64),
            job_namespace_sha256: "5".repeat(64),
            import: ImportProgress {
                next_part: 0,
                objects: 0,
                raw_bytes: 0,
                incomplete_objects: 0,
                stream_sha256: "e".repeat(64),
                previous_plaintext_sha256: None,
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
                reservation_sha256: "6".repeat(64),
                publication_tail: 2,
                terminal_tail: 1,
                reserved_bytes: 32768,
                reserved_inodes: 3,
            },
        };
        prefix.validate(&manifest).unwrap();
        (manifest, prefix, pages, encrypted.bytes().into())
    }
}
struct Original {
    crypto: crypto::tests::Guard,
    manifest: String,
    prefix: String,
    purpose: SessionPurpose,
    expired: bool,
    checks: usize,
    expire_at: usize,
}
impl Original {
    fn new(f: &Fixture, m: &WholeSnapshotManifest, p: &RestorePrefix, cipher: &[u8]) -> Self {
        Self {
            crypto: crypto::tests::Guard::new(
                &f.recipients,
                CryptoOperation::DecryptOfflineAdmin,
                cipher,
            ),
            manifest: m.sha256().unwrap(),
            prefix: p.sha256(m).unwrap(),
            purpose: SessionPurpose::Standard,
            expired: false,
            checks: 0,
            expire_at: usize::MAX,
        }
    }
}
impl CryptoBoundary for Original {
    fn admit(&mut self, request: &CryptoRequest, budget: CryptoBudget) -> Result<()> {
        self.crypto.admit(request, budget)
    }
    fn check(&mut self, request: &CryptoRequest) -> Result<()> {
        self.crypto.check(request)
    }
}
impl OriginalStandardWindow for Original {
    fn current_import_window(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
    ) -> Result<()> {
        self.checks += 1;
        if self.expired
            || (self.crypto.admitted && self.checks >= self.expire_at)
            || self.purpose != SessionPurpose::Standard
            || m.sha256()? != self.manifest
            || p.sha256(m)? != self.prefix
        {
            return Err("synthetic original Standard window refused; not authentication".into());
        }
        Ok(())
    }
}
#[test]
fn actual_two_recipient_cms_locked_plaintext_only_delivers_in_original_standard_window() {
    let fixture = Fixture::new();
    let (intent, frame) = fixture.frame();
    let (manifest, prefix, mut pages, cipher) = fixture.package(intent, &frame);
    let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
    let plaintext = decrypt_import_part(
        &manifest,
        &prefix,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.admin.key,
        &mut original,
    )
    .unwrap();
    let hash = plaintext
        .with_plaintext(&manifest, &prefix, &mut original, |bytes, _| {
            assert_eq!(bytes, frame);
            Ok(luma_content::sha256(bytes))
        })
        .unwrap();
    assert_eq!(hash, luma_content::sha256(&frame));
    assert!(original.crypto.admitted);
    original.expired = true;
    let mut delivered = false;
    assert!(plaintext
        .with_plaintext(&manifest, &prefix, &mut original, |_, _| {
            delivered = true;
            Ok(())
        })
        .is_err());
    assert!(!delivered);
    let mut wrong_key = Original::new(&fixture, &manifest, &prefix, &cipher);
    assert!(decrypt_import_part(
        &manifest,
        &prefix,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.owner.key,
        &mut wrong_key
    )
    .is_err());
}
#[test]
fn nonstandard_purpose_and_midprotocol_revocation_never_deliver_plaintext() {
    let fixture = Fixture::new();
    let (intent, frame) = fixture.frame();
    let (manifest, prefix, mut pages, cipher) = fixture.package(intent, &frame);
    for purpose in [
        SessionPurpose::Export,
        SessionPurpose::ModelImport,
        SessionPurpose::ModelActivation,
        SessionPurpose::ModelQa,
    ] {
        let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
        original.purpose = purpose;
        assert!(decrypt_import_part(
            &manifest,
            &prefix,
            &mut pages,
            &cipher,
            &fixture.recipients,
            &fixture.admin.key,
            &mut original
        )
        .is_err());
        assert!(!original.crypto.admitted);
    }
    let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
    original.expire_at = 20;
    assert!(decrypt_import_part(
        &manifest,
        &prefix,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.admin.key,
        &mut original
    )
    .is_err());
    assert!(original.crypto.admitted);
    assert!(original.checks >= 20);
}
#[test]
fn real_cms_does_not_accept_changed_ciphertext_intent_or_nonframe_plaintext() {
    let fixture = Fixture::new();
    let (intent, frame) = fixture.frame();
    let (manifest, prefix, mut pages, mut cipher) = fixture.package(intent.clone(), &frame);
    let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
    let end = cipher.len() - 1;
    cipher[end] ^= 1;
    assert!(decrypt_import_part(
        &manifest,
        &prefix,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.admin.key,
        &mut original
    )
    .is_err());
    cipher[end] ^= 1;
    let mut changed = prefix.clone();
    changed.job_sha256 = "f".repeat(64);
    let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
    assert!(decrypt_import_part(
        &manifest,
        &changed,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.admin.key,
        &mut original
    )
    .is_err());
    assert!(!original.crypto.admitted);
    let wrong = b"THIS IS REAL ENCRYPTED DATA BUT NOT A SNAPSHOT FRAME";
    let (manifest, prefix, mut pages, cipher) = fixture.package(intent, wrong);
    // The typed whole metadata can be structurally valid but signature/custody
    // is deliberately absent in this fixture; framing still must be checked.
    let mut original = Original::new(&fixture, &manifest, &prefix, &cipher);
    assert!(decrypt_import_part(
        &manifest,
        &prefix,
        &mut pages,
        &cipher,
        &fixture.recipients,
        &fixture.admin.key,
        &mut original
    )
    .is_err());
}
