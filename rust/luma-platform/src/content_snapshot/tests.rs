//! Actual private ext4 staging and isolated CMS tests. The explicit software
//! gate is not PAM, a product grant, encrypted-volume proof or selected C.
use super::*;
use crate::backup_crypto::tests::{Guard, KeyFixture};
use crate::backup_crypto::{CryptoBoundary, CryptoBudget, CryptoRequest};
use luma_content_store::v2::backup::{SnapshotPartHeader, SNAPSHOT_PROFILE};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("CMS stage tests require disposable private ext4");
        let path = Path::new(&base).join(format!(
            "native-cms-stage-{}-{}",
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
struct Gate {
    intent: SnapshotIntent,
    review: SnapshotReview,
    directory: File,
    crypto: Guard,
    live: bool,
    admitted: bool,
}
impl CryptoBoundary for Gate {
    fn admit(&mut self, request: &CryptoRequest, budget: CryptoBudget) -> Result<()> {
        if !self.live || !self.admitted {
            return Err("fixture original output admission unavailable".into());
        }
        self.crypto.admit(request, budget)
    }
    fn check(&mut self, request: &CryptoRequest) -> Result<()> {
        if !self.live {
            return Err("fixture original Export revoked".into());
        }
        self.crypto.check(request)
    }
}
impl StageBoundary for Gate {
    fn current_snapshot_stage(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        directory: &File,
    ) -> Result<()> {
        if !self.live
            || intent != &self.intent
            || review != &self.review
            || pin(&directory.metadata()?) != pin(&self.directory.metadata()?)
        {
            return Err("fixture original stage/head/review changed".into());
        }
        Ok(())
    }
    fn admit_snapshot_output(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        directory_bytes: u64,
        files: u32,
    ) -> Result<()> {
        if !self.live
            || intent != &self.intent
            || review != &self.review
            || directory_bytes > 2 * 1024 * 1024
            || files > 8
        {
            return Err("fixture exact output reservation refused".into());
        }
        self.admitted = true;
        Ok(())
    }
}
fn data(recipients: &backup_crypto::Recipients) -> (SnapshotIntent, SnapshotReview, Vec<u8>) {
    let mut input = scope::tests::input();
    input.intent.recipients_sha256 =
        luma_content::sha256(&serde_json::to_vec(recipients.pins()).unwrap());
    let intent = input.intent;
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        inventory: luma_content_store::v2::PhysicalInventory {
            regular_files: 1,
            directories: 2,
            ..Default::default()
        },
        object_count: 0,
        object_bytes: 0,
        stream_sha256: "a".repeat(64),
        review_sha256: String::new(),
    };
    review.review_sha256 = luma_content::sha256(&serde_json::to_vec(&review).unwrap());
    review.validate(&intent).unwrap();
    let header = SnapshotPartHeader {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        number: 0,
        previous_plaintext_sha256: None,
        objects: Vec::new(),
    };
    let encoded = serde_json::to_vec(&header).unwrap();
    let mut bytes = b"LUMAV2SNAPSHOT1\n".to_vec();
    bytes.extend((encoded.len() as u32).to_be_bytes());
    bytes.extend(encoded);
    SnapshotPart::parse(&bytes, &intent, &mut || Ok(())).unwrap();
    (intent, review, bytes)
}
#[test]
fn actual_stage_encrypts_retains_reads_back_and_decrypts_exact_cms_part_without_whole_backup_claim()
{
    let fixture = Fixture::new();
    let owner = KeyFixture::new(3072);
    let admin = KeyFixture::new(3072);
    let recipients = backup_crypto::Recipients::new(
        &owner.certificate,
        &admin.certificate,
        backup_crypto::RecipientPins {
            owner: owner.pin.clone(),
            offline_admin: admin.pin.clone(),
        },
    )
    .unwrap();
    let (intent, review, bytes) = data(&recipients);
    let directory = File::open(&fixture.0).unwrap();
    let mut gate = Gate {
        intent: intent.clone(),
        review: review.clone(),
        directory: directory.try_clone().unwrap(),
        crypto: Guard::new(&recipients, backup_crypto::CryptoOperation::Encrypt, &bytes),
        live: true,
        admitted: false,
    };
    let mut stage = CmsStage::new(
        directory,
        &intent,
        &review,
        &recipients,
        &mut gate,
        2 * 1024 * 1024,
        8,
    )
    .unwrap();
    let commitment = stage.retain_part(&intent, &bytes, &mut || Ok(())).unwrap();
    assert_eq!(commitment.plaintext_sha256, luma_content::sha256(&bytes));
    assert_eq!(commitment.objects, 0);
    let path = fixture
        .0
        .join(format!("part-000000-{}.cms", commitment.ciphertext_sha256));
    let meta = fs::symlink_metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o400);
    assert_eq!(meta.nlink(), 1);
    let ciphertext = fs::read(path).unwrap();
    assert_eq!(
        luma_content::sha256(&ciphertext),
        commitment.ciphertext_sha256
    );
    let mut read = Guard::new(
        &recipients,
        backup_crypto::CryptoOperation::DecryptOfflineAdmin,
        &ciphertext,
    );
    let plaintext = backup_crypto::decrypt_backup_data(
        &ciphertext,
        &commitment.ciphertext_sha256,
        &recipients,
        backup_crypto::CryptoOperation::DecryptOfflineAdmin,
        &admin.key,
        &mut read,
    )
    .unwrap();
    assert_eq!(plaintext.data_checked(&mut read).unwrap(), bytes);
    assert!(stage.retain_part(&intent, &bytes, &mut || Ok(())).is_err());
    let page = b"bounded directory data, not selected authority";
    let sha = luma_content::sha256(page);
    stage.put_page(&sha, page, &mut || Ok(())).unwrap();
    assert_eq!(stage.read_page(&sha, &mut || Ok(())).unwrap(), page);
    assert!(stage.put_page(&sha, page, &mut || Ok(())).is_err());
    fs::hard_link(
        fixture.0.join(format!("page-{sha}")),
        fixture.0.join("alias"),
    )
    .unwrap();
    assert!(stage.read_page(&sha, &mut || Ok(())).is_err());
}
#[test]
fn stage_refuses_original_revocation_and_output_exhaustion_before_creating_a_member() {
    let fixture = Fixture::new();
    // This case does not enter crypto; byte-pinned public DATA is sufficient.
    let recipients = scope::tests::input().recipient_data().unwrap();
    let (intent, review, bytes) = data(&recipients);
    let directory = File::open(&fixture.0).unwrap();
    let mut gate = Gate {
        intent: intent.clone(),
        review: review.clone(),
        directory: directory.try_clone().unwrap(),
        crypto: Guard::new(&recipients, backup_crypto::CryptoOperation::Encrypt, &bytes),
        live: false,
        admitted: false,
    };
    assert!(CmsStage::new(
        directory.try_clone().unwrap(),
        &intent,
        &review,
        &recipients,
        &mut gate,
        64,
        1
    )
    .is_err());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    gate.live = true;
    let mut stage =
        CmsStage::new(directory, &intent, &review, &recipients, &mut gate, 64, 1).unwrap();
    let large = [1_u8; 65];
    let sha = luma_content::sha256(&large);
    assert!(stage.put_page(&sha, &large, &mut || Ok(())).is_err());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    let page = b"bounded";
    let sha = luma_content::sha256(page);
    assert!(stage
        .put_page(&sha, page, &mut || Err(
            "fixture original Export expired".into()
        ))
        .is_err());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}
