//! Actual filesystem and software-checkpoint joins. Original authentication,
//! resources and NV below are explicit fixtures, not installed qualification.
use super::super::super::super::bootstrap::direct_progress as progress;
use super::super::super::backend::Backend;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn observed_ctime_change(path: &Path, mutate: &mut impl FnMut()) {
    let initial = fs::metadata(path).unwrap();
    let before = (initial.ctime(), initial.ctime_nsec());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        mutate();
        let current = fs::metadata(path).unwrap();
        if (current.ctime(), current.ctime_nsec()) != before {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "disposable fixture did not observe a changed filesystem ctime within one second"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub(super) fn open(fixture: &Fixture) -> Backend<Memory> {
    Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap()
}
pub(super) fn proposal(
    fixture: &Fixture,
    backend: &mut Backend<Memory>,
    number: u64,
) -> serde_json::Value {
    let OperationData::BootstrapProgress {
        window_intent_sha256,
        ..
    } = &backend.descriptor().operation
    else {
        panic!("bootstrap fixture required")
    };
    let review_scope = serde_json::json!({"stable_review_sha256":backend.descriptor().phase.review_sha256,"window_intent_sha256":window_intent_sha256});
    let (audit, source) = fixture.source(false, &review_scope, number);
    let mut check = || Ok(());
    progress::review(
        backend,
        &mut software_admin_operation(&audit, source, &mut check),
    )
    .unwrap()
}
fn source(
    fixture: &Fixture,
    proposal: &serde_json::Value,
    number: u64,
) -> (Audit, TypedAdminOperationSource) {
    let (audit, mut source) = fixture.source(false, proposal, number);
    source
        .paged_control
        .as_mut()
        .unwrap()
        .expected_selected_descriptor_sha256 = Some(
        proposal["expected_selected_descriptor_sha256"]
            .as_str()
            .unwrap()
            .into(),
    );
    (audit, source)
}
pub(super) fn step(
    fixture: &Fixture,
    backend: Backend<Memory>,
    proposal: &serde_json::Value,
    number: u64,
) -> Result<Backend<Memory>> {
    let (audit, source) = source(fixture, proposal, number);
    let mut check = || Ok(());
    progress::window(
        backend,
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut software_admin_operation(&audit, source, &mut check),
    )
}

#[test]
fn actual_zero_row_finalization_uses_exact_slots_one_advance_and_cold_ready_selection() {
    let fixture = Fixture::new();
    fixture.dispatch().unwrap();
    let mut backend = open(&fixture);
    let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
    let proposal = proposal(&fixture, &mut backend, 2);
    assert_eq!(proposal["from_row"], 0);
    assert_eq!(proposal["to_row"], 0);
    assert_eq!(proposal["maximum_projection_rows_per_window"], 1);
    assert_eq!(
        fixture.pages().inventory(&mut || Ok(())).unwrap(),
        before,
        "read review has no physical publication effect"
    );
    let current = step(&fixture, backend, &proposal, 3).unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    assert_eq!(current.descriptor().sequence, 2);
    assert_eq!(current.descriptor().phase.state, bootstrap::State::Ready);
    assert_eq!(
        current
            .descriptor()
            .storage
            .as_ref()
            .unwrap()
            .jobs
            .as_ref()
            .unwrap()
            .entries(),
        2
    );
    assert_eq!(
        current
            .descriptor()
            .storage
            .as_ref()
            .unwrap()
            .locations
            .entries,
        1
    );
    assert!(current
        .descriptor()
        .storage
        .as_ref()
        .unwrap()
        .parent_allocation
        .is_some());
    let selected = current.descriptor().clone();
    drop(current);
    let mut cold = open(&fixture);
    assert_eq!(cold.descriptor(), &selected);
    let (audit, source) = source(&fixture, &proposal, 4);
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    assert!(
        progress::review(&mut cold, &mut authority).is_err(),
        "Ready cannot renew bootstrap"
    );
    let mut original = COperation::Admin(&mut authority);
    assert!(cold
        .lookup(&selected.roots.owners, b"unselected-owner", &mut original)
        .unwrap()
        .is_none());
    assert_eq!(fixture.memory.0.borrow().calls, 2);
}

#[test]
fn actual_progress_lost_new_reply_requires_distinct_recovery_and_never_redispatches() {
    let fixture = Fixture::new();
    fixture.dispatch().unwrap();
    let mut backend = open(&fixture);
    let proposal = proposal(&fixture, &mut backend, 2);
    fixture.memory.0.borrow_mut().fault = Fault::Lost;
    assert!(step(&fixture, backend, &proposal, 3).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    assert!(Backend::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(())
    )
    .is_err());
    let pages = fixture.pages();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    let review = progress::recovery_review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    let (audit, source) = fixture.source(true, &review, 4);
    let mut check = || Ok(());
    let current = progress::reconcile(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        review["review_sha256"].as_str().unwrap(),
        &mut software_admin_operation(&audit, source, &mut check),
    )
    .unwrap();
    assert_eq!(current.descriptor().phase.state, bootstrap::State::Ready);
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    assert_eq!(
        fixture.pages().inventory(&mut || Ok(())).unwrap(),
        before,
        "only the existing pending inode changes"
    );
    assert!(progress::recovery_review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &fixture.pages(),
        &fixture.binding,
        &mut || Ok(())
    )
    .is_err());
}

#[test]
fn actual_old_and_third_nv_progress_remain_fenced_without_retry_or_allocation_adoption() {
    for fault in [Fault::Old, Fault::Third] {
        let fixture = Fixture::new();
        fixture.dispatch().unwrap();
        let mut backend = open(&fixture);
        let proposal = proposal(&fixture, &mut backend, 2);
        let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
        fixture.memory.0.borrow_mut().fault = fault;
        assert!(step(&fixture, backend, &proposal, 3).is_err());
        let after = fixture.pages().inventory(&mut || Ok(())).unwrap();
        assert!(after.files > before.files && after.allocated_bytes > before.allocated_bytes);
        assert!(Backend::open(
            fixture.memory.clone(),
            fixture.files(),
            fixture.binding.clone(),
            &mut || Ok(())
        )
        .is_err());
        assert!(progress::recovery_review(
            &mut fixture.memory.clone(),
            &fixture.files(),
            &fixture.pages(),
            &fixture.binding,
            &mut || Ok(())
        )
        .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, 2);
        assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), after);
    }
}

#[test]
fn actual_progress_rejects_frame_as_canonical_selection_and_revocation_before_allocation() {
    let fixture = Fixture::new();
    fixture.dispatch().unwrap();
    let mut backend = open(&fixture);
    let proposal = proposal(&fixture, &mut backend, 2);
    let before = fixture.pages().inventory(&mut || Ok(())).unwrap();
    let (audit, mut candidate_source) = source(&fixture, &proposal, 3);
    candidate_source
        .paged_control
        .as_mut()
        .unwrap()
        .expected_selected_descriptor_sha256 =
        Some(hash(&backend.descriptor().slot_frame().unwrap()));
    let mut check = || Ok(());
    assert!(progress::window(
        backend,
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut software_admin_operation(&audit, candidate_source, &mut check)
    )
    .is_err());
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), before);
    let backend = open(&fixture);
    let (audit, candidate_source) = source(&fixture, &proposal, 4);
    let mut revoked = || Err("explicit software original revoked".into());
    assert!(progress::window(
        backend,
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut software_admin_operation(&audit, candidate_source, &mut revoked)
    )
    .is_err());
    assert_eq!(fixture.pages().inventory(&mut || Ok(())).unwrap(), before);
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}

#[test]
fn held_complete_data_observation_rejects_same_bytes_recreation_and_original_loss() {
    let fixture = Fixture::new();
    let bytes = fixture.files().read(JOURNAL, &mut || Ok(())).unwrap();
    let path = fixture.root.join(JOURNAL);
    let pin =
        super::super::super::pinned::Pinned::capture(path.clone(), &bytes, 0o400, &mut || Ok(()))
            .unwrap();
    pin.verify(&mut || Ok(())).unwrap();
    assert!(pin
        .check(&mut || Err("software original lost".into()))
        .is_err());
    let held = fixture.root.join("retained-original-journal");
    fs::rename(&path, &held).unwrap();
    let mut replacement = MemberParent::capture(&path)
        .unwrap()
        .open(&path, libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o400)
        .unwrap();
    replacement.write_all(&bytes).unwrap();
    replacement.sync_all().unwrap();
    drop(replacement);
    assert!(pin.check(&mut || Ok(())).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&held, &path).unwrap();
    observed_ctime_change(&path, &mut || {
        fs::rename(&path, &held).unwrap();
        fs::rename(&held, &path).unwrap();
    });
    assert!(
        pin.check(&mut || Ok(())).is_err(),
        "rename back cannot erase changed inode ctime"
    );
}

#[test]
fn current_descriptor_pin_detects_inode_mutation_even_after_bytes_and_mode_are_restored() {
    let fixture = Fixture::new();
    let current = fixture.dispatch().unwrap();
    let mut backend = open(&fixture);
    let slot = &current.descriptor.storage.as_ref().unwrap().descriptor_slot;
    let path = current
        .pages
        .root
        .join("tails")
        .join(&slot.job)
        .join(format!("{:08x}", slot.number));
    observed_ctime_change(&path, &mut || {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    });
    assert!(backend.live(&mut || Ok(())).is_err());
    assert!(
        backend.live(&mut || Ok(())).is_err(),
        "once uncertain, a reader cannot reset its captured pins"
    );
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}

pub(super) struct ContentGuard {
    pub(super) owner: OwnerBinding,
    pub(super) review: String,
}
impl luma_content_store::Boundary for ContentGuard {
    fn admit(
        &mut self,
        owner: &OwnerBinding,
        budget: luma_content_store::ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if owner != &self.owner
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("explicit software owner resource-boundary refusal".into());
        }
        Ok(())
    }
    fn check(&mut self, access: luma_content_store::Access<'_>) -> luma_content_store::Result<()> {
        match access {
            luma_content_store::Access::Inspect { binding } if binding == &self.owner => Ok(()),
            luma_content_store::Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.owner && review_sha256 == self.review => Ok(()),
            _ => Err("explicit software owner-boundary refusal".into()),
        }
    }
}
#[test]
fn actual_nonempty_legacy_owner_row_is_copied_and_cold_selected_without_loss_or_empty_fallback() {
    use luma_content::{EditOrigin, Format, Provenance};
    use luma_content_store::{Plan, Repository};
    let fixture = Fixture::new();
    let owner = OwnerBinding {
        installation: fixture.binding.installation.clone(),
        owner: "22".repeat(32),
        owner_generation: 1,
    };
    let body = b"real retained owner bytes before direct C bootstrap";
    let plan = Plan::capture(
        owner.clone(),
        "document",
        Format::Utf8Text,
        body,
        Provenance {
            request_id: "direct-existing-owner".into(),
            workflow_sha256: "44".repeat(32),
            source_sha256: hash(body),
            origin: EditOrigin::Managed,
        },
    )
    .unwrap();
    let mut guard = ContentGuard {
        owner: owner.clone(),
        review: plan.review_sha256().into(),
    };
    let mut repository = Repository::create_at(&fixture.data, &plan, &mut guard).unwrap();
    let held = repository.prepare(&plan, body, &mut guard).unwrap();
    let commitment = held.commitment().canonical_bytes().unwrap();
    let record = held.record_bytes().to_vec();
    drop(held);
    let profile = format!(
        "content-v1-write-1-{}-{}",
        "77".repeat(32),
        plan.review_sha256()
    );
    let usage =
        crate::content_governed::custody_usage(&profile, "8:1", &owner, plan.review_sha256())
            .unwrap();
    let audit = Audit {
        subject: owner.owner.clone(),
        subject_generation: 1,
        grant_id: "explicit-software-existing-owner".into(),
        grant_version: 1,
        checkpoint_head: "33".repeat(32),
        operation_id: Some(format!("{:032x}", 40)),
        usage,
    };
    let mut legacy = fixture.store();
    let wanted = legacy
        .publish(
            &commitment,
            &record,
            &profile,
            "8:1",
            &audit,
            &mut || Ok(()),
        )
        .unwrap();
    drop(legacy);
    fixture.dispatch().unwrap();
    let mut backend = open(&fixture);
    let before = backend.descriptor().clone();
    assert_eq!(before.phase.expected_counts[0], 1);
    assert!(before.roots.owners.entry_count == 0);
    let proposal = proposal(&fixture, &mut backend, 2);
    assert_eq!(proposal["from_row"], 0);
    assert_eq!(proposal["to_row"], 1);
    let mut current = step(&fixture, backend, &proposal, 3).unwrap();
    assert_eq!(current.descriptor().phase.state, bootstrap::State::Ready);
    assert_eq!(current.descriptor().roots.owners.entry_count, 1);
    let (audit, source) = source(&fixture, &proposal, 4);
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    let root = current.descriptor().roots.owners.clone();
    let bytes = current
        .lookup(
            &root,
            owner_key(&owner).unwrap().as_bytes(),
            &mut COperation::Admin(&mut authority),
        )
        .unwrap()
        .unwrap();
    let leaf: OwnerLeaf = canonical(&bytes, map::MAX_VALUE_BYTES).unwrap();
    let OwnerLeaf::V1 { state, records, .. } = leaf else {
        panic!("ordinary v1 owner must remain tagged v1")
    };
    assert_eq!(state, wanted);
    assert_eq!(records.legacy_owner_record_count, 1);
    assert_eq!(records.suffix_count, 0);
    assert_eq!(
        fixture.memory.0.borrow().calls,
        3,
        "one legacy publication plus two independently selected direct C windows"
    );
    drop(current);
    drop(repository);
    let cold = open(&fixture);
    assert_eq!(cold.descriptor().phase.state, bootstrap::State::Ready);
}
