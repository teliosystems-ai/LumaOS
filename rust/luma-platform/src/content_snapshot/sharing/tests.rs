//! Composition-only software fixtures. No PAM, finite grant, installed C,
//! encrypted volume, live resource lease or CMS authorization is qualified here.
use super::*;
use backup_crypto::{CryptoBoundary, CryptoBudget, CryptoOperation, CryptoRequest};

struct FixtureBoundary {
    live: bool,
    calls: Vec<&'static str>,
}
impl FixtureBoundary {
    fn call(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        if !self.live {
            return Err("fixture original Export revoked".into());
        }
        Ok(())
    }
}
impl Boundary for FixtureBoundary {
    fn admit(&mut self, _: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        self.call("source-admit")
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        self.call("source-check")
    }
}
impl OwnerBoundary for FixtureBoundary {
    fn current_owner_head(&mut self, _: &OwnerHeadV2) -> Result<()> {
        self.call("head")
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.call("physical")?;
        Ok(head.physical.observed.clone())
    }
    fn verify_prepared_allocations(&mut self, _: &AppendCommitment) -> Result<()> {
        self.call("allocations")
    }
}
impl SnapshotBoundary for FixtureBoundary {
    fn admit_snapshot(
        &mut self,
        _: &SnapshotIntent,
        _: SnapshotMode,
        _: SnapshotBudget,
    ) -> Result<()> {
        self.call("snapshot-admit")
    }
    fn check_snapshot(
        &mut self,
        _: &SnapshotIntent,
        _: SnapshotMode,
        _: Option<&str>,
    ) -> Result<()> {
        self.call("snapshot-check")
    }
    fn verify_snapshot_head(&mut self, _: &OwnerHeadV2) -> Result<()> {
        self.call("semantic-closure")
    }
}
impl CryptoBoundary for FixtureBoundary {
    fn admit(&mut self, _: &CryptoRequest, _: CryptoBudget) -> Result<()> {
        self.call("crypto-admit")
    }
    fn check(&mut self, _: &CryptoRequest) -> Result<()> {
        self.call("crypto-check")
    }
}
impl StageBoundary for FixtureBoundary {
    fn current_snapshot_stage(
        &mut self,
        _: &SnapshotIntent,
        _: &SnapshotReview,
        _: &File,
    ) -> Result<()> {
        self.call("stage-current")
    }
    fn admit_snapshot_output(
        &mut self,
        _: &SnapshotIntent,
        _: &SnapshotReview,
        _: u64,
        _: u32,
    ) -> Result<()> {
        self.call("stage-admit")
    }
}
fn gate() -> FixtureBoundary {
    FixtureBoundary {
        live: true,
        calls: Vec::new(),
    }
}
fn input() -> scope::Input {
    let mut input = scope::tests::input();
    input.mode = SnapshotMode::Export;
    input.budget.output_bytes = luma_content_store::v2::backup::MAX_SNAPSHOT_EXPORT_BYTES;
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: input.intent.profile.clone(),
        intent_sha256: input.intent.sha256().unwrap(),
        inventory: PhysicalInventory {
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
    input.review = Some(review);
    input.validate().unwrap();
    input
}
fn request(input: &scope::Input) -> CryptoRequest {
    CryptoRequest {
        schema_version: 1,
        operation: CryptoOperation::Encrypt,
        input_sha256: "a".repeat(64),
        input_bytes: 1,
        recipients: input.recipients.clone(),
    }
}
fn crypto_budget() -> CryptoBudget {
    CryptoBudget {
        child_memory_bytes: 512 * 1024 * 1024,
        parent_memory_bytes: 192 * 1024 * 1024,
        aggregate_memory_bytes: 704 * 1024 * 1024,
        aggregate_locked_bytes: 640 * 1024 * 1024,
        maximum_output_bytes: backup_crypto::MAX_ENCRYPTED_BACKUP_BYTES as u64,
        tasks: 2,
        maximum_seconds: 1800,
    }
}
#[test]
fn both_facades_delegate_to_one_original_context_and_observe_shared_revocation() {
    let input = input();
    let mut original = gate();
    let shared = SharedExport::new(&input, &mut original).unwrap();
    let (mut source, mut stage) = shared.split();
    source
        .admit_snapshot(&input.intent, input.mode, input.budget)
        .unwrap();
    source
        .admit(
            &input.intent.head.binding,
            ResourceBudget {
                memory_bytes: 192 * 1024 * 1024,
                tasks: 1,
                read_bytes: 4096,
                write_bytes: 0,
                additional_storage_bytes: 0,
            },
        )
        .unwrap();
    source
        .current_physical_accounting(&input.intent.head)
        .unwrap();
    source.verify_snapshot_head(&input.intent.head).unwrap();
    let directory = File::open("/dev/null").unwrap();
    let review = input.review.as_ref().unwrap();
    stage
        .current_snapshot_stage(&input.intent, review, &directory)
        .unwrap();
    stage
        .admit_snapshot_output(&input.intent, review, input.budget.output_bytes, 8)
        .unwrap();
    let request = request(&input);
    CryptoBoundary::admit(&mut stage, &request, crypto_budget()).unwrap();
    CryptoBoundary::check(&mut stage, &request).unwrap();
    shared
        .with(|b| {
            assert_eq!(
                b.calls,
                [
                    "head",
                    "snapshot-check",
                    "snapshot-admit",
                    "source-admit",
                    "physical",
                    "semantic-closure",
                    "stage-current",
                    "stage-admit",
                    "crypto-admit",
                    "crypto-check"
                ]
            );
            b.live = false;
            Ok(())
        })
        .unwrap();
    assert!(source
        .check(Access::Inspect {
            binding: &input.intent.head.binding
        })
        .is_err());
    assert!(CryptoBoundary::check(&mut stage, &request).is_err());
    assert!(source.current_owner_head(&input.intent.head).is_err());
    assert!(stage
        .current_snapshot_stage(&input.intent, review, &directory)
        .is_err());
}
#[test]
fn reentrant_borrow_refuses_without_panicking_or_delegating() {
    let input = input();
    let mut original = gate();
    let shared = SharedExport::new(&input, &mut original).unwrap();
    let (mut source, mut stage) = shared.split();
    let held = shared.boundary.try_borrow_mut().unwrap();
    assert!(source.current_owner_head(&input.intent.head).is_err());
    assert!(CryptoBoundary::check(&mut stage, &request(&input)).is_err());
    assert_eq!(held.calls, ["head", "snapshot-check"]);
    drop(held);
    source.current_owner_head(&input.intent.head).unwrap();
    CryptoBoundary::check(&mut stage, &request(&input)).unwrap();
}
#[test]
fn substituted_selectors_and_expanded_output_refuse_before_original_callback() {
    let input = input();
    let mut original = gate();
    let shared = SharedExport::new(&input, &mut original).unwrap();
    let (mut source, mut stage) = shared.split();
    let mut other = input.intent.clone();
    other.snapshot_id = "b".repeat(64);
    assert!(source
        .admit_snapshot(&other, input.mode, input.budget)
        .is_err());
    assert!(source
        .check_snapshot(&input.intent, SnapshotMode::Review, None)
        .is_err());
    assert!(source
        .check_snapshot(&input.intent, SnapshotMode::Export, Some(&"b".repeat(64)))
        .is_err());
    let mut budget = input.budget;
    budget.maximum_objects -= 1;
    assert!(source
        .admit_snapshot(&input.intent, input.mode, budget)
        .is_err());
    let mut head = input.intent.head.clone();
    head.binding.owner_generation += 1;
    assert!(source.current_owner_head(&head).is_err());
    assert!(source
        .check(Access::Inspect {
            binding: &head.binding
        })
        .is_err());
    let review = input.review.as_ref().unwrap();
    let mut other_review = review.clone();
    other_review.stream_sha256 = "b".repeat(64);
    assert!(stage
        .admit_snapshot_output(&input.intent, &other_review, 1024, 8)
        .is_err());
    assert!(stage
        .admit_snapshot_output(&input.intent, review, input.budget.output_bytes + 1, 8)
        .is_err());
    let mut req = request(&input);
    req.operation = CryptoOperation::DecryptOfflineAdmin;
    assert!(CryptoBoundary::check(&mut stage, &req).is_err());
    req.operation = CryptoOperation::Encrypt;
    req.recipients.owner.spki_sha256 = "b".repeat(64);
    assert!(CryptoBoundary::admit(&mut stage, &req, crypto_budget()).is_err());
    assert_eq!(shared.boundary.borrow().calls, ["head", "snapshot-check"]);
}
#[test]
fn creation_never_turns_request_data_into_original_authority() {
    let input = input();
    let mut original = gate();
    original.live = false;
    assert!(SharedExport::new(&input, &mut original).is_err());
    let mut original = gate();
    let unreviewed = scope::tests::input();
    assert!(SharedExport::new(&unreviewed, &mut original).is_err());
    assert!(original.calls.is_empty());
    let mut tampered = input.clone();
    tampered.review.as_mut().unwrap().stream_sha256 = "b".repeat(64);
    assert!(SharedExport::new(&tampered, &mut original).is_err());
    assert!(original.calls.is_empty());
}
