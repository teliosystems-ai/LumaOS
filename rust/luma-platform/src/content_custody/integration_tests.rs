//! Real immutable store records and durable private journal files; only the
//! Checkpoint is an explicit in-memory failure fixture, never host TPM custody.
use super::*;
use crate::finite_grants::Use;
use luma_content::{EditOrigin, Format, Provenance};
use luma_content_store::{Access, Boundary, Plan, Repository, ResourceBudget};
use std::cell::Cell;
use std::os::unix::fs::DirBuilderExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct FixtureExport {
    binding: OwnerBinding,
    manifest: String,
}
impl luma_content_store::BackupBoundary for FixtureExport {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: luma_content_store::BackupBudget,
    ) -> luma_content_store::Result<()> {
        if binding != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.archive_bytes > luma_content_store::MAX_CONTENT_BACKUP_BYTES as u64
            || budget.tasks != 1
        {
            return Err("explicit fixture export budget/binding differs".into());
        }
        Ok(())
    }
    fn check(
        &mut self,
        binding: &OwnerBinding,
        manifest: Option<&str>,
    ) -> luma_content_store::Result<()> {
        if binding != &self.binding || manifest != Some(self.manifest.as_str()) {
            return Err("fixture lacks the exact independent export review".into());
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Memory {
    head: Rc<Cell<[u8; 32]>>,
    advances: Rc<Cell<usize>>,
    lose_reply: Rc<Cell<bool>>,
}
impl Memory {
    fn new(head: [u8; 32]) -> Self {
        Self {
            head: Rc::new(Cell::new(head)),
            advances: Rc::new(Cell::new(0)),
            lose_reply: Rc::new(Cell::new(false)),
        }
    }
}
impl Checkpoint for Memory {
    fn read(&mut self) -> Result<[u8; 32]> {
        Ok(self.head.get())
    }
    fn clock(&mut self) -> Result<tpm::Clock> {
        Ok(tpm::Clock {
            milliseconds: 1,
            reset_count: 1,
            restart_count: 1,
        })
    }
    fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        if self.head.get() != expected {
            return Err("fixture checkpoint conflict".into());
        }
        self.advances.set(self.advances.get() + 1);
        let next = tpm::extend_value(expected, event);
        self.head.set(next);
        if self.lose_reply.replace(false) {
            return Err("fixture write applied but reply lost".into());
        }
        Ok(next)
    }
}
struct Fixture {
    authority: PathBuf,
    data: PathBuf,
    binding: OwnerBinding,
    memory: Memory,
}
impl Fixture {
    fn new() -> Self {
        assert!(
            std::path::Path::new("/.dockerenv").is_file(),
            "owned disposable Linux container required"
        );
        assert!(
            !std::path::Path::new("/dev/tpm0").exists()
                && !std::path::Path::new("/dev/tpmrm0").exists()
        );
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let authority = PathBuf::from(format!(
            "/tmp/luma-tpm-custody-{}-{serial}",
            std::process::id()
        ));
        let data = PathBuf::from(
            std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("disposable ext4 content fixture required"),
        )
        .join(format!("custody-content-{}-{serial}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&authority)
            .unwrap();
        fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
        let binding = OwnerBinding {
            installation: "11".repeat(32),
            owner: "22".repeat(32),
            owner_generation: 7,
        };
        let journal = Journal::empty(&binding.installation, [3; 32]).unwrap();
        let memory = Memory::new(journal.validate().unwrap().checkpoint);
        Files {
            root: authority.clone(),
        }
        .create(JOURNAL, &journal.bytes().unwrap(), &mut || Ok(()))
        .unwrap();
        Self {
            authority,
            data,
            binding,
            memory,
        }
    }
    fn files(&self) -> Files {
        Files {
            root: self.authority.clone(),
        }
    }
    fn store(&self) -> Store<Memory> {
        Store::open(self.memory.clone(), self.files(), &mut || Ok(())).unwrap()
    }
    fn plan(&self) -> Plan {
        let source = b"original governed fixture source";
        Plan::capture(
            self.binding.clone(),
            "document",
            Format::Utf8Text,
            source,
            Provenance {
                request_id: "custody.fixture.one".into(),
                workflow_sha256: "44".repeat(32),
                source_sha256: hash(source),
                origin: EditOrigin::Managed,
            },
        )
        .unwrap()
    }
    fn audit(&self, usage: Use) -> Audit {
        Audit {
            subject: self.binding.owner.clone(),
            subject_generation: self.binding.owner_generation,
            grant_id: "fixture-finite-grant".into(),
            grant_version: 1,
            checkpoint_head: "55".repeat(32),
            operation_id: Some("66".repeat(16)),
            usage,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(self.authority.parent(), Some(std::path::Path::new("/tmp")));
        assert!(self
            .authority
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("luma-tpm-custody-"));
        fs::remove_dir_all(&self.authority).unwrap();
        fs::remove_dir_all(&self.data).unwrap();
    }
}
struct Guard {
    binding: OwnerBinding,
    review: Option<String>,
    recover: Option<String>,
}
impl Guard {
    fn read(binding: &OwnerBinding) -> Self {
        Self {
            binding: binding.clone(),
            review: None,
            recover: None,
        }
    }
    fn write(plan: &Plan) -> Self {
        Self {
            binding: plan.binding().clone(),
            review: Some(plan.review_sha256().into()),
            recover: None,
        }
    }
    fn recover(review: &luma_content_store::PreparationReview) -> Self {
        Self {
            binding: review.binding.clone(),
            review: None,
            recover: Some(review.review_sha256.clone()),
        }
    }
}
impl Boundary for Guard {
    fn admit(
        &mut self,
        owner: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if owner != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("fixture finite resource refusal".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.binding && self.review.as_deref() == Some(review_sha256) => {
                Ok(())
            }
            Access::Recover {
                binding,
                review_sha256,
                ..
            } if binding == &self.binding && self.recover.as_deref() == Some(review_sha256) => {
                Ok(())
            }
            _ => Err("fixture lacks exact purpose/owner/review authority".into()),
        }
    }
}
fn prepared(fixture: &Fixture, plan: &Plan) -> (Repository, Vec<u8>, Vec<u8>, String, Audit) {
    let mut repository =
        Repository::create_at(&fixture.data, plan, &mut Guard::write(plan)).unwrap();
    let token = repository
        .prepare(
            plan,
            b"original governed fixture source",
            &mut Guard::write(plan),
        )
        .unwrap();
    let commitment = token.commitment().canonical_bytes().unwrap();
    let record = token.record_bytes().to_vec();
    drop(token);
    let profile = format!(
        "content-v1-write-{}-{}-{}",
        fixture.binding.owner_generation,
        "77".repeat(32),
        plan.review_sha256()
    );
    let usage = crate::content_governed::custody_usage(
        &profile,
        "8:1",
        &fixture.binding,
        plan.review_sha256(),
    )
    .unwrap();
    let audit = fixture.audit(usage);
    (repository, commitment, record, profile, audit)
}

#[test]
fn fresh_restore_real_history_resumes_after_c_before_rename_and_retires_without_erasing_bytes() {
    let mut origin = Fixture::new();
    origin.binding = OwnerBinding {
        installation: "ab".repeat(32),
        owner: "cd".repeat(32),
        owner_generation: 1,
    };
    let source_plan = origin.plan();
    let mut source_repository =
        Repository::create_at(&origin.data, &source_plan, &mut Guard::write(&source_plan)).unwrap();
    source_repository
        .apply(
            &source_plan,
            b"original governed fixture source",
            &mut Guard::write(&source_plan),
        )
        .unwrap();
    let backup_review = source_repository
        .review_backup_data(&mut Guard::read(&origin.binding))
        .unwrap();
    let archive = source_repository
        .backup_data(
            &backup_review,
            &mut Guard::read(&origin.binding),
            &mut FixtureExport {
                binding: origin.binding.clone(),
                manifest: backup_review.manifest_sha256.clone(),
            },
        )
        .unwrap();
    // Actual source reconstruction, derivation/rebind planning and immutable
    // ext4 records are exercised here. CMS itself has separate real-key tests;
    // only the journal checkpoint is the explicit failure fixture above.
    let target = Fixture::new();
    let planner = luma_content_store::plan_restore_data_checked(
        archive.bytes(),
        &target.binding,
        "restored.fixture",
        &crate::content_restore::graph_sha256(),
        &mut || Ok(()),
    )
    .unwrap();
    let receipt = backup::test_receipt_for_review(&backup_review);
    let mut input = crate::content_restore::Input {
        schema_version: 1,
        login: "admin".into(),
        admin: OwnerBinding {
            installation: target.binding.installation.clone(),
            owner: "b1".repeat(32),
            owner_generation: 9,
        },
        target_login: "target".into(),
        target: target.binding.clone(),
        independently_selected_origin_spki_sha256: receipt.body.origin_spki_sha256.clone(),
        request_namespace: "restored.fixture".into(),
        key_role: crate::content_restore::KeyRole::OfflineAdmin,
        capsule_path:
            "/run/luma-granted-client/requests/0123456789abcdef0123456789abcdef/content-restore.cms"
                .into(),
        capsule_bytes: 4096,
        capsule_sha256: hash(b"explicit synthetic ciphertext framing; real CMS tested separately"),
        review: Some(planner.review().clone()),
    };
    let profile =
        crate::content_restore::profile(&input, &serde_json::to_vec(&input).unwrap()).unwrap();
    let mut audit = target.audit(
        crate::content_restore::custody_usage(&profile, "8:1", &target.binding.installation)
            .unwrap(),
    );
    audit.subject = input.admin.owner.clone();
    audit.subject_generation = input.admin.owner_generation;
    let mut store = target.store();
    assert!(!store
        .restore_status(&input, &profile, "8:1", &audit, &mut || Ok(()))
        .unwrap());
    store
        .start_restore(&input, &receipt, &profile, "8:1", &audit, &mut || Ok(()))
        .unwrap();
    assert_eq!(target.memory.advances.get(), 1);
    let (plan, source) = planner.steps().next().unwrap();
    let mut repository =
        Repository::create_at(&target.data, plan, &mut Guard::write(plan)).unwrap();
    let token = repository
        .prepare(plan, source, &mut Guard::write(plan))
        .unwrap();
    let commitment = token.commitment().canonical_bytes().unwrap();
    let record = token.record_bytes().to_vec();
    let wanted = store
        .publish_restore(
            &input,
            &commitment,
            &record,
            &profile,
            "8:1",
            &audit,
            &mut || Ok(()),
        )
        .unwrap();
    drop(token);
    drop(store);
    assert_eq!(target.memory.advances.get(), 2);
    // A new genuinely authorized controller may resume; historical operation
    // IDs and prior Admin scopes are not manufactured into current authority.
    input.admin.owner = "b2".repeat(32);
    input.admin.owner_generation = 10;
    input.capsule_path =
        "/run/luma-granted-client/requests/1123456789abcdef0123456789abcdef/content-restore.cms"
            .into();
    let profile =
        crate::content_restore::profile(&input, &serde_json::to_vec(&input).unwrap()).unwrap();
    audit.subject = input.admin.owner.clone();
    audit.subject_generation = input.admin.owner_generation;
    audit.operation_id = Some("77".repeat(16));
    audit.usage =
        crate::content_restore::custody_usage(&profile, "8:1", &target.binding.installation)
            .unwrap();
    let mut store = target.store();
    store
        .start_restore(&input, &receipt, &profile, "8:1", &audit, &mut || Ok(()))
        .unwrap();
    let cut = store
        .restore_cut(
            &input,
            &profile,
            "8:1",
            &audit,
            plan.request_id(),
            plan.review_sha256(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(cut.current, wanted);
    assert_eq!(
        cut.prior_base,
        Some(VerifiedState::empty(&target.binding).unwrap())
    );
    let token = repository
        .prepare(plan, source, &mut Guard::write(plan))
        .unwrap();
    assert_eq!(
        store
            .publish_restore(
                &input,
                &token.commitment().canonical_bytes().unwrap(),
                token.record_bytes(),
                &profile,
                "8:1",
                &audit,
                &mut || Ok(())
            )
            .unwrap(),
        wanted
    );
    token.publish(&mut Guard::write(plan)).unwrap();
    drop(repository);
    let mut repository = Repository::open_at(
        &target.data,
        &target.binding,
        &mut Guard::read(&target.binding),
    )
    .unwrap();
    repository
        .require_state(&wanted, &mut Guard::read(&target.binding))
        .unwrap();
    assert_eq!(
        repository
            .current(plan.artifact_id(), &mut Guard::read(&target.binding))
            .unwrap()
            .reference()
            .unwrap(),
        *plan.resulting()
    );
    assert_eq!(target.memory.advances.get(), 2);
    let mut wrong = input.clone();
    wrong.capsule_sha256 = "ef".repeat(32);
    let wrong_profile =
        crate::content_restore::profile(&wrong, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    let mut wrong_audit = audit.clone();
    wrong_audit.usage =
        crate::content_restore::custody_usage(&wrong_profile, "8:1", &target.binding.installation)
            .unwrap();
    assert!(store
        .start_restore(
            &wrong,
            &receipt,
            &wrong_profile,
            "8:1",
            &wrong_audit,
            &mut || Ok(())
        )
        .is_err());
    // Preserve a deliberately damaged unrelated pending member. Retirement
    // never traverses/adopts these bytes or rolls back the published record.
    let pending_plan = Plan::capture(
        target.binding.clone(),
        "pending.forensic",
        Format::Utf8Text,
        b"forensic",
        Provenance {
            request_id: "forensic.pending".into(),
            workflow_sha256: "88".repeat(32),
            source_sha256: hash(b"forensic"),
            origin: EditOrigin::Managed,
        },
    )
    .unwrap();
    drop(
        repository
            .prepare(&pending_plan, b"forensic", &mut Guard::write(&pending_plan))
            .unwrap(),
    );
    drop(repository);
    let owner = target
        .data
        .join(luma_content_store::domain_name(&target.binding).unwrap());
    let committed_record = fs::read_dir(owner.join("outcomes"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("record.json");
    let committed_bytes = fs::read(&committed_record).unwrap();
    let pending = owner
        .join("pending")
        .join(hash(pending_plan.request_id().as_bytes()))
        .join("source.bin");
    fs::write(&pending, b"deliberately damaged retained source").unwrap();
    let before = fs::read(&pending).unwrap();
    let request = retire::Request {
        input: input.clone(),
        expected_review_sha256: None,
    };
    let mut inspect_audit = audit.clone();
    inspect_audit.usage = request.usage(retire::INSPECT).unwrap();
    let inspected = store
        .execute_retirement(&request, retire::INSPECT, &inspect_audit, &mut || Ok(()))
        .unwrap();
    let request = retire::Request {
        input: input.clone(),
        expected_review_sha256: Some(inspected["review_sha256"].as_str().unwrap().into()),
    };
    let mut retire_audit = audit.clone();
    retire_audit.usage = request.usage(retire::RETIRE).unwrap();
    assert!(store
        .execute_retirement(&request, retire::RETIRE, &retire_audit, &mut || Err(
            "fixture revocation".into()
        ))
        .is_err());
    let retired = store
        .execute_retirement(&request, retire::RETIRE, &retire_audit, &mut || Ok(()))
        .unwrap();
    assert_eq!(retired["owner_marked_unavailable"], true);
    assert_eq!(fs::read(&pending).unwrap(), before);
    assert_eq!(target.memory.advances.get(), 3);
    assert!(store.selected(&target.binding, &mut || Ok(())).is_err());
    store
        .execute_retirement(&request, retire::RETIRE, &retire_audit, &mut || Ok(()))
        .unwrap();
    assert_eq!(target.memory.advances.get(), 3);
    let mut fresh = target.binding.clone();
    fresh.owner_generation += 1;
    assert_eq!(
        store.selected(&fresh, &mut || Ok(())).unwrap(),
        VerifiedState::empty(&fresh).unwrap()
    );
    drop(store);
    let mut reopened = target.store();
    assert!(reopened.selected(&target.binding, &mut || Ok(())).is_err());
    assert_eq!(fs::read(&pending).unwrap(), before);
    assert_eq!(fs::read(&committed_record).unwrap(), committed_bytes);
}

#[test]
fn protected_publication_acknowledges_exact_pending_and_published_retries_without_reextend() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let (mut repository, commitment, record, profile, audit) = prepared(&fixture, &plan);
    let mut store = fixture.store();
    let mut check = || Ok(());
    let wanted = store
        .publish(&commitment, &record, &profile, "8:1", &audit, &mut check)
        .unwrap();
    assert_eq!(fixture.memory.advances.get(), 1);
    let cut = store
        .preparation_cut(
            &fixture.binding,
            &profile,
            "8:1",
            plan.request_id(),
            plan.review_sha256(),
            &audit,
            &mut check,
        )
        .unwrap();
    assert_eq!(cut.current, wanted);
    assert_eq!(
        cut.prior_base,
        Some(VerifiedState::empty(&fixture.binding).unwrap())
    );
    assert_eq!(
        store
            .publish(&commitment, &record, &profile, "8:1", &audit, &mut check)
            .unwrap(),
        wanted
    );
    assert_eq!(fixture.memory.advances.get(), 1);
    let token = repository
        .prepare(
            &plan,
            b"original governed fixture source",
            &mut Guard::write(&plan),
        )
        .unwrap();
    token.publish(&mut Guard::write(&plan)).unwrap();
    let status = store.status_data(&mut check).unwrap();
    assert_eq!(status["events"], 1);
    assert_eq!(status["owner_domains"], 1);
    assert_eq!(
        status["checkpoint_head"],
        bundle::hex(&fixture.memory.head.get())
    );
    assert_ne!(
        status["checkpoint_head"],
        bundle::hex(
            &Journal::empty(&fixture.binding.installation, [3; 32])
                .unwrap()
                .validate()
                .unwrap()
                .checkpoint
        )
    );
    assert_eq!(status["pending"], false);
    assert_eq!(status["content_bytes_changed"], false);
    assert_eq!(status["authority_returned"], false);
    assert!(store
        .status_data(&mut || Err("explicit fixture Admin revocation".into()))
        .is_err());
    assert_eq!(fixture.memory.advances.get(), 1);
    assert_eq!(
        repository
            .verified_state(&mut Guard::read(&fixture.binding))
            .unwrap(),
        wanted
    );
    let token = repository
        .prepare(
            &plan,
            b"original governed fixture source",
            &mut Guard::write(&plan),
        )
        .unwrap();
    let replay = token.commitment().canonical_bytes().unwrap();
    let replay_record = token.record_bytes().to_vec();
    assert_eq!(
        store
            .publish(&replay, &replay_record, &profile, "8:1", &audit, &mut check)
            .unwrap(),
        wanted
    );
    assert_eq!(fixture.memory.advances.get(), 1);
    let mut substituted = record;
    substituted.push(b' ');
    assert!(store
        .publish(&replay, &substituted, &profile, "8:1", &audit, &mut check)
        .is_err());
    assert_eq!(fixture.memory.advances.get(), 1);
}

#[test]
fn uncertain_applied_nv_write_retains_evidence_and_admin_finalize_never_reextends() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let (_repository, commitment, record, profile, audit) = prepared(&fixture, &plan);
    let mut store = fixture.store();
    fixture.memory.lose_reply.set(true);
    assert!(store
        .publish(
            &commitment,
            &record,
            &profile,
            "8:1",
            &audit,
            &mut || Ok(())
        )
        .is_err());
    assert_eq!(fixture.memory.advances.get(), 1);
    assert!(store
        .publish(
            &commitment,
            &record,
            &profile,
            "8:1",
            &audit,
            &mut || Ok(())
        )
        .is_err());
    assert!(Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err());
    let mut anchor = fixture.memory.clone();
    let (review, _) = admin::pending_review(&mut anchor, &fixture.files(), &mut || Ok(())).unwrap();
    admin::reconcile(&mut anchor, &fixture.files(), &review, &mut || Ok(())).unwrap();
    assert_eq!(fixture.memory.advances.get(), 1);
    let mut reopened = fixture.store();
    assert_eq!(
        reopened
            .selected(&fixture.binding, &mut || Ok(()))
            .unwrap()
            .outcome_count,
        1
    );
    assert!(!fixture.authority.join(PREPARED).exists());
}

#[test]
fn revoked_before_nv_dispatch_requires_exact_reviewed_retirement_without_deleting_content() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let (_repository, commitment, record, profile, audit) = prepared(&fixture, &plan);
    let mut store = fixture.store();
    let mut revoked = false;
    let mut check = || -> Result<()> {
        if fs::read(fixture.authority.join(PREPARED))
            .is_ok_and(|bytes| canonical::<Prepared>(&bytes, MAX_FILE).is_ok())
        {
            revoked = true;
            return Err("fixture original grant revoked after complete pending stage".into());
        }
        Ok(())
    };
    assert!(store
        .publish(&commitment, &record, &profile, "8:1", &audit, &mut check)
        .is_err());
    drop(check);
    assert!(revoked);
    assert_eq!(fixture.memory.advances.get(), 0);
    assert!(Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err());
    let bytes = fixture.files().read(PREPARED, &mut || Ok(())).unwrap();
    canonical::<Prepared>(&bytes, MAX_FILE).unwrap();
    let mut anchor = fixture.memory.clone();
    let (review, _) = admin::pending_review(&mut anchor, &fixture.files(), &mut || Ok(())).unwrap();
    admin::reconcile(&mut anchor, &fixture.files(), &review, &mut || Ok(())).unwrap();
    assert_eq!(fixture.store().state.checkpoint, fixture.memory.head.get());
    assert_eq!(fixture.memory.advances.get(), 0);
    let pending = fixture
        .data
        .join(luma_content_store::domain_name(&fixture.binding).unwrap())
        .join("pending")
        .join(hash(plan.request_id().as_bytes()));
    assert_eq!(
        fs::read(pending.join("source.bin")).unwrap(),
        b"original governed fixture source"
    );
}

#[test]
fn independent_quarantine_head_matches_actual_retirement_and_refuses_unreviewed_replay() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let (mut repository, _, _, _, _) = prepared(&fixture, &plan);
    let review = repository
        .review_preparation(
            &hash(plan.request_id().as_bytes()),
            &mut Guard::read(&fixture.binding),
        )
        .unwrap();
    let profile = format!(
        "content-v1-recover-{}-{}-{}",
        fixture.binding.owner_generation,
        "77".repeat(32),
        review.review_sha256
    );
    let audit = fixture.audit(
        crate::content_governed::custody_usage(
            &profile,
            "8:1",
            &fixture.binding,
            &review.review_sha256,
        )
        .unwrap(),
    );
    let mut store = fixture.store();
    let wanted = store
        .quarantine(&review, &profile, "8:1", &audit, &mut || Ok(()))
        .unwrap();
    assert_eq!(
        store
            .recovery_cut(&review, &profile, "8:1", &audit, &mut || Ok(()))
            .unwrap()
            .prior_base,
        Some(review.base_state().unwrap())
    );
    repository
        .recover_preparation(&review, &mut Guard::recover(&review))
        .unwrap();
    assert_eq!(
        repository
            .verified_state(&mut Guard::read(&fixture.binding))
            .unwrap(),
        wanted
    );
    assert_eq!(
        store
            .quarantine(&review, &profile, "8:1", &audit, &mut || Ok(()))
            .unwrap(),
        wanted
    );
    assert_eq!(fixture.memory.advances.get(), 1);
    let mut wrong = audit;
    wrong.subject_generation += 1;
    assert!(store
        .quarantine(&review, &profile, "8:1", &wrong, &mut || Ok(()))
        .is_err());
    assert_eq!(fixture.memory.advances.get(), 1);
}
