use super::super::migration::{
    self, MigrationBoundary, MigrationPrefix, MigrationReview, MigrationWindowCommitment,
};
use super::super::owner_segment::Locator;
use super::*;
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("recovery fixtures require private disposable ext4");
        let path = Path::new(&root).join(format!(
            "owner-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn object(&self, hash: &str) -> PathBuf {
        self.0
            .join(ObjectStore::name(&binding()).unwrap())
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    }
}
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 64 * 1024 * 1024,
        new_files: 32768,
    }
}
fn provenance(id: &str, bytes: &[u8]) -> crate::Provenance {
    crate::Provenance {
        request_id: id.into(),
        workflow_sha256: "c".repeat(64),
        source_sha256: luma_content::sha256(bytes),
        origin: luma_content::EditOrigin::External,
    }
}
struct Io;
// Only this private disposable software fixture supplies synthetic authority.
// It provides no installed principal, TPM selection or resource qualification.
impl Boundary for Io {
    fn admit(&mut self, binding: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        Ok(binding.validate()?)
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
struct State {
    legacy: crate::VerifiedState,
    prefix: Option<MigrationPrefix>,
    head: Option<OwnerHeadV2>,
    physical: PhysicalInventory,
    mutation: Option<String>,
    recovery: Option<String>,
    recovery_checks: usize,
    mutation_checks: usize,
    revoked: bool,
}
struct Authority<'a> {
    store: &'a ObjectStore,
    state: Rc<RefCell<State>>,
}
impl Boundary for Authority<'_> {
    fn admit(&mut self, b: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if b != &self.state.borrow().legacy.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("fixture finite resource admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        let mut s = self.state.borrow_mut();
        if s.revoked {
            return Err("fixture original authority revoked".into());
        }
        match access {
            Access::Inspect { binding: b } => {
                if b != &s.legacy.binding {
                    return Err("fixture owner substitution".into());
                }
            }
            Access::Mutate { review_sha256, .. } => {
                s.mutation_checks += 1;
                if s.mutation.as_deref() != Some(review_sha256) {
                    return Err("fixture mutation review refused".into());
                }
            }
            Access::Recover { review_sha256, .. } => {
                s.recovery_checks += 1;
                if s.recovery.as_deref() != Some(review_sha256) {
                    return Err("fixture independent Recover review refused".into());
                }
            }
        }
        Ok(())
    }
}
impl Authority<'_> {
    fn actual_after(&self, before: &PhysicalInventory, after: &PhysicalInventory) -> Result<()> {
        if &self.state.borrow().physical != before
            || self
                .store
                .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))?
                != *after
        {
            return Err("fixture actual physical audit differs".into());
        }
        Ok(())
    }
}
impl MigrationBoundary for Authority<'_> {
    fn current_legacy_state(&mut self, expected: &crate::VerifiedState) -> Result<()> {
        let s = self.state.borrow();
        if s.revoked || s.head.is_some() || &s.legacy != expected {
            return Err("fixture legacy selection differs".into());
        }
        Ok(())
    }
    fn current_migration_prefix(
        &mut self,
        review: &MigrationReview,
        prefix: Option<&MigrationPrefix>,
    ) -> Result<PhysicalInventory> {
        self.current_legacy_state(&review.legacy)?;
        let s = self.state.borrow();
        if s.prefix.as_ref() != prefix {
            return Err("fixture C progress CAS refused".into());
        }
        Ok(s.physical.clone())
    }
    fn verify_migration_allocations(&mut self, c: &MigrationWindowCommitment) -> Result<()> {
        self.actual_after(&c.physical_before, &c.next.physical_after)
    }
}
impl OwnerBoundary for Authority<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        let s = self.state.borrow();
        if s.revoked || s.head.as_ref() != Some(head) {
            return Err("fixture actual owner selection differs".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.state.borrow().physical.clone())
    }
    fn verify_prepared_allocations(&mut self, c: &AppendCommitment) -> Result<()> {
        self.actual_after(&c.physical_before, &c.physical_after)
    }
}
impl OwnerRecoveryBoundary for Authority<'_> {
    fn verify_recovery_allocations(&mut self, c: &RecoveryCommitment) -> Result<()> {
        self.actual_after(&c.physical_before, &c.physical_after)
    }
}
fn setup() -> (Fixture, ObjectStore, Rc<RefCell<State>>) {
    let fixture = Fixture::new();
    let capture = crate::Plan::capture(
        binding(),
        "document",
        luma_content::Format::Utf8Text,
        b"original",
        provenance("first", b"original"),
    )
    .unwrap();
    let mut source = crate::Repository::create_at(&fixture.0, &capture, &mut Io).unwrap();
    source.apply(&capture, b"original", &mut Io).unwrap();
    for id in ["retired-old", "pending-old"] {
        let plan = source
            .plan_external_edit(
                "document",
                capture.resulting().clone(),
                id.as_bytes(),
                provenance(id, id.as_bytes()),
                &mut Io,
            )
            .unwrap();
        drop(source.prepare(&plan, id.as_bytes(), &mut Io).unwrap());
        if id == "retired-old" {
            let review = source
                .review_preparation(&luma_content::sha256(id.as_bytes()), &mut Io)
                .unwrap();
            source.recover_preparation(&review, &mut Io).unwrap();
        }
    }
    let store = ObjectStore::create_at(
        &fixture.0,
        &binding(),
        budget(),
        &Mutation {
            review_sha256: "d".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut Io,
    )
    .unwrap();
    let physical = store
        .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    let legacy = source.verified_state(&mut Io).unwrap();
    let state = Rc::new(RefCell::new(State {
        legacy: legacy.clone(),
        prefix: None,
        head: None,
        physical,
        mutation: None,
        recovery: None,
        recovery_checks: 0,
        mutation_checks: 0,
        revoked: false,
    }));
    {
        let mut authority = Authority {
            store: &store,
            state: state.clone(),
        };
        let review = migration::review_migration(&source, &legacy, &mut authority).unwrap();
        state.borrow_mut().mutation = Some(review.sha256().unwrap());
        let prepared = migration::prepare_migration_window(
            &source,
            &store,
            &review,
            None,
            16,
            32,
            budget(),
            &mut authority,
        )
        .unwrap();
        let next = migration::verify_migration_window_data(
            &source,
            &store,
            &review,
            prepared.commitment(),
            super::super::owner::read_budget(),
            &mut authority,
        )
        .unwrap();
        assert!(next.complete);
        {
            let mut s = state.borrow_mut();
            s.head = Some(next.head.clone());
            s.physical = next.physical_after;
        }
        prepared.acknowledge_owner(&review, &mut authority).unwrap();
    }
    state.borrow_mut().mutation = None;
    (fixture, store, state)
}
fn review(store: &ObjectStore, state: &Rc<RefCell<State>>) -> RecoveryReview {
    let head = state.borrow().head.clone().unwrap();
    review_owner_recovery(
        store,
        &head,
        &luma_content::sha256(b"pending-old"),
        &mut Authority {
            store,
            state: state.clone(),
        },
    )
    .unwrap()
}
fn recover(
    store: &ObjectStore,
    state: &Rc<RefCell<State>>,
    review: &RecoveryReview,
) -> OwnerHeadV2 {
    let base = state.borrow().head.clone().unwrap();
    state.borrow_mut().recovery = Some(review.review_sha256.clone());
    let mut authority = Authority {
        store,
        state: state.clone(),
    };
    let prepared = prepare_owner_recovery(store, &base, review, budget(), &mut authority).unwrap();
    verify_owner_recovery_data(
        store,
        prepared.commitment(),
        super::super::owner::read_budget(),
        &mut authority,
    )
    .unwrap();
    {
        let mut s = state.borrow_mut();
        s.head = Some(prepared.commitment().next.clone());
        s.physical = prepared.commitment().physical_after.clone();
    }
    prepared.acknowledge_selected(&mut authority).unwrap()
}
fn capture_plan(store: &ObjectStore, state: &Rc<RefCell<State>>, id: &str) -> OwnerPlan {
    let head = state.borrow().head.clone().unwrap();
    let mut authority = Authority {
        store,
        state: state.clone(),
    };
    OwnerRepository::at_selected(store, &head, &mut authority)
        .unwrap()
        .plan_capture(
            "new-document",
            luma_content::Format::Utf8Text,
            b"new",
            provenance(id, b"new"),
            &mut authority,
        )
        .unwrap()
}

#[test]
fn actual_recovery_preserves_all_bytes_history_and_lifecycle_then_allows_only_fresh_ids() {
    let (_fixture, store, state) = setup();
    let base = state.borrow().head.clone().unwrap();
    let plan = capture_plan(&store, &state, "new-request");
    state.borrow_mut().mutation = Some(plan.review_sha256().into());
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    assert!(OwnerRepository::at_selected(&store, &base, &mut authority)
        .unwrap()
        .prepare_append(&plan, budget(), &mut authority)
        .is_err());
    let review = review(&store, &state);
    let original_metadata = review.target.entries.clone();
    let mutation_checks = state.borrow().mutation_checks;
    let next = recover(&store, &state, &review);
    assert_eq!(next.history, base.history);
    assert_eq!(next.roots.artifacts, base.roots.artifacts);
    assert_eq!(next.roots.lifecycle, base.roots.lifecycle);
    assert_eq!(next.roots.corpus, base.roots.corpus);
    assert_eq!(
        next.roots.retained.entry_count,
        base.roots.retained.entry_count + 1
    );
    assert_eq!(next.roots.pending.entry_count, 1);
    assert_eq!(state.borrow().mutation_checks, mutation_checks);
    assert!(state.borrow().recovery_checks > 0);
    let mut io = Io;
    let mut guard = Guard::new(
        &mut io,
        &next.binding,
        super::super::owner::read_budget(),
        None,
    )
    .unwrap();
    for original in original_metadata {
        let retained: PendingEntry = store
            .value(
                &next.roots.retained,
                &next
                    .roots
                    .retained
                    .key(&original.entry.key().unwrap())
                    .unwrap(),
                &mut guard,
            )
            .unwrap()
            .unwrap();
        assert_eq!(retained, original);
        store.get_blob(&retained.bytes, &mut guard).unwrap();
    }
    for id in ["pending-old", "retired-old"] {
        let plan = capture_plan(&store, &state, id);
        state.borrow_mut().mutation = Some(plan.review_sha256().into());
        assert!(OwnerRepository::at_selected(&store, &next, &mut authority)
            .unwrap()
            .prepare_append(&plan, budget(), &mut authority)
            .is_err());
    }
    let plan = capture_plan(&store, &state, "genuinely-new");
    state.borrow_mut().mutation = Some(plan.review_sha256().into());
    let repository = OwnerRepository::at_selected(&store, &next, &mut authority).unwrap();
    let prepared = repository
        .prepare_append(&plan, budget(), &mut authority)
        .unwrap();
    verify_append_data(
        &store,
        prepared.commitment(),
        super::super::owner::read_budget(),
        &mut authority,
    )
    .unwrap();
}
#[test]
fn separate_recover_authority_is_required_even_when_exact_mutation_review_was_approved() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone().unwrap();
    let review = review(&store, &state);
    state.borrow_mut().mutation = Some(review.review_sha256.clone());
    let before = store
        .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    assert!(prepare_owner_recovery(&store, &head, &review, budget(), &mut authority).is_err());
    assert_eq!(
        before,
        store
            .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))
            .unwrap()
    );
    assert!(state.borrow().recovery_checks > 0);
    state.borrow_mut().recovery = Some(review.review_sha256.clone());
    state.borrow_mut().revoked = true;
    assert!(prepare_owner_recovery(&store, &head, &review, budget(), &mut authority).is_err());
    assert_eq!(state.borrow().head.as_ref(), Some(&head));
}
#[test]
fn stale_reviews_physical_tampering_and_unrelated_history_changes_are_not_recovery() {
    let (_fixture, store, state) = setup();
    let base = state.borrow().head.clone().unwrap();
    let review = review(&store, &state);
    state.borrow_mut().recovery = Some(review.review_sha256.clone());
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    let prepared =
        prepare_owner_recovery(&store, &base, &review, budget(), &mut authority).unwrap();
    let mut changed = prepared.commitment().clone();
    changed.physical_after.allocated_bytes += 4096;
    assert!(verify_owner_recovery_data(
        &store,
        &changed,
        super::super::owner::read_budget(),
        &mut authority
    )
    .is_err());
    let mut changed = prepared.commitment().clone();
    changed.next.history.outcomes += 1;
    assert!(changed.validate().is_err());
    let c = prepared.commitment().clone();
    verify_owner_recovery_data(
        &store,
        &c,
        super::super::owner::read_budget(),
        &mut authority,
    )
    .unwrap();
    {
        let mut s = state.borrow_mut();
        s.head = Some(c.next.clone());
        s.physical = c.physical_after.clone();
    }
    prepared.acknowledge_selected(&mut authority).unwrap();
    assert!(prepare_owner_recovery(&store, &c.next, &review, budget(), &mut authority).is_err());
    assert!(verify_owner_recovery_data(
        &store,
        &c,
        super::super::owner::read_budget(),
        &mut authority
    )
    .is_err());
    assert!(review_owner_recovery(
        &store,
        &c.next,
        &review.target.transaction_sha256,
        &mut authority
    )
    .is_err());
}
#[test]
fn damaged_retained_preparation_metadata_refuses_recovery_and_new_mutations() {
    let (fixture, store, state) = setup();
    let head = state.borrow().head.clone().unwrap();
    let review = review(&store, &state);
    let entry = &review.target.entries[0];
    let mut io = Io;
    let mut guard = Guard::new(
        &mut io,
        &head.binding,
        super::super::owner::read_budget(),
        None,
    )
    .unwrap();
    let raw = store
        .get_map(
            &head.roots.pending,
            &head.roots.pending.key(&entry.entry.key().unwrap()).unwrap(),
            &mut guard,
        )
        .unwrap()
        .unwrap();
    let metadata: ValueRef = canonical(&raw, MAX_VALUE_BYTES).unwrap();
    let path = fixture.object(&metadata.sha256);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"damaged").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    assert!(review_owner_recovery(
        &store,
        &head,
        &review.target.transaction_sha256,
        &mut authority
    )
    .is_err());
    let plan = capture_plan(&store, &state, "new");
    state.borrow_mut().mutation = Some(plan.review_sha256().into());
    assert!(OwnerRepository::at_selected(&store, &head, &mut authority)
        .unwrap()
        .prepare_append(&plan, budget(), &mut authority)
        .is_err());
    assert_eq!(state.borrow().head.as_ref(), Some(&head));
}

fn untrusted_pending_candidate(
    store: &ObjectStore,
    head: &OwnerHeadV2,
    plan: &OwnerPlan,
    before: &PhysicalInventory,
) -> AppendCommitment {
    // Adversarial DATA construction through private test-driver I/O. Deliberately
    // bypasses the public preparation fence to exercise the independent verifier.
    let mutation = Mutation {
        review_sha256: plan.review_sha256().into(),
        decision: plan.decision(),
        source_bytes: plan.source.len() as u64,
    };
    let mut io = Io;
    let mut guard = Guard::new(&mut io, &head.binding, budget(), Some(&mutation)).unwrap();
    let payload = store.put_blob(&plan.payload, &mut guard).unwrap();
    let source = store.put_blob(&plan.source, &mut guard).unwrap();
    let mut next = head.clone();
    store
        .apply_record(
            &mut next,
            &plan.record,
            &plan.source,
            &plan.payload,
            &payload,
            &source,
            false,
            &mut guard,
        )
        .unwrap();
    let (requests, segments, last, count) = store
        .extend_owner_segment(
            head,
            SegmentInput {
                ordinal: plan.record.sequence,
                record: &plan.canonical_record().unwrap(),
                source: &plan.source,
                payload: &plan.payload,
            },
            &mut guard,
        )
        .unwrap();
    next.roots.requests = requests;
    next.roots.segments = segments;
    next.history = super::super::head::HistoryCursor {
        outcomes: plan.record.sequence,
        segments: count,
        last_segment: Some(last),
    };
    next.physical =
        PhysicalAccounting::from_observation(add_physical(before, &guard.allocations).unwrap())
            .unwrap();
    let head_object_sha256 = store
        .write_object(&next.canonical_bytes().unwrap(), &mut guard)
        .unwrap();
    let locator: Locator = canonical(
        &store
            .get_map(
                &next.roots.requests,
                &next
                    .roots
                    .requests
                    .key(plan.request_id().as_bytes())
                    .unwrap(),
                &mut guard,
            )
            .unwrap()
            .unwrap(),
        MAX_VALUE_BYTES,
    )
    .unwrap();
    AppendCommitment {
        schema_version: 2,
        domain: "luma-owner-append-commitment-v2".into(),
        base: head.clone(),
        next,
        review_sha256: plan.review_sha256().into(),
        member: locator.member,
        head_object_sha256,
        physical_before: before.clone(),
        physical_after: add_physical(before, &guard.allocations).unwrap(),
    }
}
#[test]
fn independently_replayed_otherwise_valid_append_cannot_bypass_pending_fence() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone().unwrap();
    let plan = capture_plan(&store, &state, "attempted-bypass");
    let before = state.borrow().physical.clone();
    let candidate = untrusted_pending_candidate(&store, &head, &plan, &before);
    candidate.validate().unwrap();
    state.borrow_mut().mutation = Some(plan.review_sha256().into());
    assert!(verify_append_data(
        &store,
        &candidate,
        super::super::owner::read_budget(),
        &mut Authority {
            store: &store,
            state: state.clone()
        }
    )
    .is_err());
    assert_eq!(state.borrow().head.as_ref(), Some(&head));
}

#[test]
fn different_owner_namespace_is_refused_before_read_prepare_or_replay_io() {
    let (fixture, store, state) = setup();
    let head = state.borrow().head.clone().unwrap();
    let review = review(&store, &state);
    let mut other_binding = binding();
    other_binding.owner = "e".repeat(64);
    let other = ObjectStore::create_at(
        &fixture.0,
        &other_binding,
        budget(),
        &Mutation {
            review_sha256: "f".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut Io,
    )
    .unwrap();
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    let error = review_owner_recovery(
        &other,
        &head,
        &review.target.transaction_sha256,
        &mut authority,
    )
    .unwrap_err();
    assert!(error.to_string().contains("different owner namespace"));
    state.borrow_mut().recovery = Some(review.review_sha256.clone());
    let error = match prepare_owner_recovery(&other, &head, &review, budget(), &mut authority) {
        Ok(_) => panic!("wrong owner preparation accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("different owner namespace"));
    // Produce a genuine otherwise-valid candidate in the correct private
    // namespace; source substitution must still refuse before replay I/O.
    let prepared =
        prepare_owner_recovery(&store, &head, &review, budget(), &mut authority).unwrap();
    let error = verify_owner_recovery_data(
        &other,
        prepared.commitment(),
        super::super::owner::read_budget(),
        &mut authority,
    )
    .unwrap_err();
    assert!(error.to_string().contains("different owner namespace"));
    assert_eq!(state.borrow().head.as_ref(), Some(&head));
}
