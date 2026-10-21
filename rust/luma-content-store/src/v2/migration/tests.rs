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
            .expect("migration fixtures require private disposable ext4");
        let path = Path::new(&root).join(format!(
            "migration-{}-{}",
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
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
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
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 128 * 1024 * 1024,
        new_files: 32768,
    }
}
struct Io;
// Explicit software fixture. It is not a native principal or C authority.
impl Boundary for Io {
    fn admit(&mut self, b: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        Ok(b.validate()?)
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
struct State {
    legacy: VerifiedState,
    prefix: Option<MigrationPrefix>,
    physical: PhysicalInventory,
    selected: Option<OwnerHeadV2>,
    revoked: bool,
    review: Option<String>,
    checks: usize,
    revoke_at: usize,
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
            return Err("fixture admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.checks += 1;
        if state.revoked || state.checks >= state.revoke_at {
            return Err("fixture original session revoked".into());
        }
        if let Access::Mutate { review_sha256, .. } = access {
            if state.review.as_deref() != Some(review_sha256) {
                return Err("fixture exact review refused".into());
            }
        }
        Ok(())
    }
}
impl MigrationBoundary for Authority<'_> {
    fn current_legacy_state(&mut self, expected: &VerifiedState) -> Result<()> {
        let state = self.state.borrow();
        if state.revoked || state.selected.is_some() || expected != &state.legacy {
            return Err("fixture selected legacy changed".into());
        }
        Ok(())
    }
    fn current_migration_prefix(
        &mut self,
        review: &MigrationReview,
        prefix: Option<&MigrationPrefix>,
    ) -> Result<PhysicalInventory> {
        self.current_legacy_state(&review.legacy)?;
        let state = self.state.borrow();
        if prefix != state.prefix.as_ref() {
            return Err("fixture prefix CAS refused".into());
        }
        Ok(state.physical.clone())
    }
    fn verify_migration_allocations(&mut self, c: &MigrationWindowCommitment) -> Result<()> {
        // The production adapter must instead join original worker creation
        // observations and actual protected C counters/reservations.
        if self
            .store
            .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))?
            != c.next.physical_after
            || self.state.borrow().physical != c.physical_before
        {
            return Err("fixture physical allocation audit differs".into());
        }
        Ok(())
    }
}
impl OwnerBoundary for Authority<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        let state = self.state.borrow();
        if state.revoked || state.selected.as_ref() != Some(head) {
            return Err("fixture owner not actually selected".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.state.borrow().physical.clone())
    }
    fn verify_prepared_allocations(&mut self, _: &AppendCommitment) -> Result<()> {
        Err("fixture migration never authorizes an append".into())
    }
}
fn setup() -> (Fixture, Repository, ObjectStore, Rc<RefCell<State>>) {
    let fixture = Fixture::new();
    let first = crate::Plan::capture(
        binding(),
        "document",
        luma_content::Format::Utf8Text,
        b"one\r\n",
        provenance("first", b"one\r\n"),
    )
    .unwrap();
    let mut repo = Repository::create_at(&fixture.0, &first, &mut Io).unwrap();
    repo.apply(&first, b"one\r\n", &mut Io).unwrap();
    let edit = repo
        .plan_external_edit(
            "document",
            first.resulting().clone(),
            b"two",
            provenance("second", b"two"),
            &mut Io,
        )
        .unwrap();
    repo.apply(&edit, b"two", &mut Io).unwrap();
    let conflict = repo
        .plan_external_edit(
            "document",
            first.resulting().clone(),
            b"candidate",
            provenance("conflict", b"candidate"),
            &mut Io,
        )
        .unwrap();
    repo.apply(&conflict, b"candidate", &mut Io).unwrap();
    let store = ObjectStore::create_at(
        &fixture.0,
        &binding(),
        budget(),
        &Mutation {
            review_sha256: "c".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut Io,
    )
    .unwrap();
    let physical = store
        .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    let state = Rc::new(RefCell::new(State {
        legacy: repo.verified_state(&mut Io).unwrap(),
        prefix: None,
        physical,
        selected: None,
        revoked: false,
        review: None,
        checks: 0,
        revoke_at: usize::MAX,
    }));
    (fixture, repo, store, state)
}
fn run_window<'a>(
    repo: &'a Repository,
    store: &'a ObjectStore,
    review: &MigrationReview,
    state: &Rc<RefCell<State>>,
    outcomes: usize,
    retained: usize,
) -> PreparedMigrationWindow<'a> {
    state.borrow_mut().review = Some(review.sha256().unwrap());
    let prefix = state.borrow().prefix.clone();
    let mut authority = Authority {
        store,
        state: state.clone(),
    };
    let prepared = prepare_migration_window(
        repo,
        store,
        review,
        prefix.as_ref(),
        outcomes,
        retained,
        budget(),
        &mut authority,
    )
    .unwrap();
    assert_eq!(
        verify_migration_window_data(
            repo,
            store,
            review,
            prepared.commitment(),
            super::super::owner::read_budget(),
            &mut authority
        )
        .unwrap(),
        prepared.commitment().next
    );
    prepared
}
fn select_prefix(
    prepared: PreparedMigrationWindow<'_>,
    review: &MigrationReview,
    state: &Rc<RefCell<State>>,
    store: &ObjectStore,
) {
    let next = prepared.commitment().next.clone();
    {
        let mut s = state.borrow_mut();
        s.prefix = Some(next.clone());
        s.physical = next.physical_after.clone();
    }
    prepared
        .acknowledge_prefix(
            review,
            &mut Authority {
                store,
                state: state.clone(),
            },
        )
        .unwrap();
}
#[test]
fn bounded_migration_preserves_original_records_refs_sources_and_retained_conflict() {
    let (_fixture, repo, store, state) = setup();
    let original = repo.snapshot(None, &mut Io).unwrap();
    let legacy = state.borrow().legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    let mut windows = 0;
    loop {
        let prepared = run_window(&repo, &store, &review, &state, 1, 3);
        windows += 1;
        if prepared.commitment().next.complete {
            let next = prepared.commitment().next.clone();
            {
                let mut s = state.borrow_mut();
                s.selected = Some(next.head.clone());
                s.physical = next.physical_after.clone();
            }
            let head = prepared
                .acknowledge_owner(
                    &review,
                    &mut Authority {
                        store: &store,
                        state: state.clone(),
                    },
                )
                .unwrap();
            assert_eq!(head.history.outcomes, 3);
            assert_eq!(
                head.roots.retained.entry_count,
                review.inventory.len() as u64
            );
            let mut authority = Authority {
                store: &store,
                state: state.clone(),
            };
            let owner = OwnerRepository::at_selected(&store, &head, &mut authority).unwrap();
            assert_eq!(
                owner.current("document", &mut authority).unwrap().content(),
                b"two"
            );
            for (i, (record, plan, source)) in original.records.iter().enumerate() {
                let copied = owner.outcome_at(i as u64 + 1, &mut authority).unwrap();
                assert_eq!(copied.record, serde_json::to_vec(record).unwrap());
                assert_eq!(copied.source, *source);
                assert_eq!(copied.payload, plan.payload);
            }
            break;
        }
        select_prefix(prepared, &review, &state, &store);
        assert_eq!(repo.verified_state(&mut Io).unwrap(), legacy);
        assert!(windows < 32);
    }
    assert!(windows > 1);
    assert_eq!(repo.verified_state(&mut Io).unwrap(), legacy);
}
#[test]
fn selected_progress_cas_and_original_revocation_refuse_replay_or_prefix_adoption() {
    let (_fixture, repo, store, state) = setup();
    let legacy = state.borrow().legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    let prepared = run_window(&repo, &store, &review, &state, 1, 0);
    let copied = prepared.commitment().clone();
    select_prefix(prepared, &review, &state, &store);
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    assert!(verify_migration_window_data(
        &repo,
        &store,
        &review,
        &copied,
        super::super::owner::read_budget(),
        &mut authority
    )
    .is_err());
    assert!(
        prepare_migration_window(&repo, &store, &review, None, 1, 0, budget(), &mut authority)
            .is_err()
    );
    let prefix = state.borrow().prefix.clone();
    state.borrow_mut().revoked = true;
    assert!(prepare_migration_window(
        &repo,
        &store,
        &review,
        prefix.as_ref(),
        1,
        0,
        budget(),
        &mut authority
    )
    .is_err());
}
#[test]
fn physical_counter_tampering_and_unrelated_map_substitution_fail_independent_replay() {
    let (_fixture, repo, store, state) = setup();
    let legacy = state.borrow().legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    let prepared = run_window(&repo, &store, &review, &state, 1, 0);
    let mut altered = prepared.commitment().clone();
    altered.next.physical_after.allocated_bytes += 4096;
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    assert!(verify_migration_window_data(
        &repo,
        &store,
        &review,
        &altered,
        super::super::owner::read_budget(),
        &mut authority
    )
    .is_err());
    let mut altered = prepared.commitment().clone();
    altered.steps[0].head.roots.corpus = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    assert!(verify_migration_window_data(
        &repo,
        &store,
        &review,
        &altered,
        super::super::owner::read_budget(),
        &mut authority
    )
    .is_err());
    assert!(state.borrow().prefix.is_none());
}
#[test]
fn changed_pending_bytes_fence_source_review_and_never_become_an_outcome() {
    let (fixture, mut repo, store, state) = setup();
    let pending = repo
        .plan_external_edit(
            "document",
            repo.current("document", &mut Io)
                .unwrap()
                .reference()
                .unwrap(),
            b"pending",
            provenance("pending", b"pending"),
            &mut Io,
        )
        .unwrap();
    drop(repo.prepare(&pending, b"pending", &mut Io).unwrap());
    let legacy = repo.verified_state(&mut Io).unwrap();
    state.borrow_mut().legacy = legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    assert!(review
        .inventory
        .iter()
        .any(|e| e.area == SourceArea::Pending && e.member.as_deref() == Some("source.bin")));
    let path = fixture
        .0
        .join(crate::domain_name(&binding()).unwrap())
        .join("pending")
        .join(luma_content::sha256(b"pending"))
        .join("source.bin");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"mutated").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    state.borrow_mut().review = Some(review.sha256().unwrap());
    assert!(prepare_migration_window(
        &repo,
        &store,
        &review,
        None,
        1,
        0,
        budget(),
        &mut Authority {
            store: &store,
            state: state.clone()
        }
    )
    .is_err());
    assert_eq!(state.borrow().legacy.outcome_count, 3);
    assert!(state.borrow().prefix.is_none());
}
#[test]
fn incomplete_preparation_is_retained_and_cannot_restart_as_fresh_namespace() {
    let (_fixture, repo, store, state) = setup();
    let legacy = state.borrow().legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    state.borrow_mut().review = Some(review.sha256().unwrap());
    // The first leaf needs two directory inodes and one file inode. Permit
    // exactly those three creations, then refuse further work by finite budget
    // (not by an implementation-dependent count of authority callbacks).
    let short = IoBudget {
        new_files: 3,
        ..budget()
    };
    assert!(prepare_migration_window(
        &repo,
        &store,
        &review,
        None,
        1,
        0,
        short,
        &mut Authority {
            store: &store,
            state: state.clone()
        }
    )
    .is_err());
    let actual = store
        .inventory(super::super::owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    assert!(actual.regular_files > 1);
    assert!(prepare_migration_window(
        &repo,
        &store,
        &review,
        None,
        1,
        0,
        budget(),
        &mut Authority {
            store: &store,
            state: state.clone()
        }
    )
    .is_err());
    assert!(state.borrow().prefix.is_none());
}
#[test]
fn canonical_review_and_prefix_reject_closed_shape_aliases_and_inventory_reordering() {
    let (_fixture, repo, store, state) = setup();
    let legacy = state.borrow().legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        MigrationReview::from_canonical(&review.canonical_bytes().unwrap()).unwrap(),
        review
    );
    let mut changed = review.clone();
    changed.inventory.reverse();
    changed.inventory_sha256 =
        luma_content::sha256(&serde_json::to_vec(&changed.inventory).unwrap());
    assert!(changed.validate().is_err());
    let mut changed = review.clone();
    changed
        .inventory
        .iter_mut()
        .find(|entry| entry.transaction.is_some())
        .unwrap()
        .identity
        .mount_id += 1;
    changed.inventory_sha256 =
        luma_content::sha256(&serde_json::to_vec(&changed.inventory).unwrap());
    assert!(changed.validate().is_err());
    let prepared = run_window(&repo, &store, &review, &state, 1, 0);
    let prefix = &prepared.commitment().next;
    assert_eq!(
        MigrationPrefix::from_canonical(&prefix.canonical_bytes(&review).unwrap(), &review)
            .unwrap(),
        *prefix
    );
    let mut changed = prefix.clone();
    changed.next_outcome += 1;
    assert!(changed.validate(&review).is_err());
    let mut changed = prefix.clone();
    changed.complete = true;
    assert!(changed.validate(&review).is_err());
    let mut bytes = review.canonical_bytes().unwrap();
    bytes.push(b' ');
    assert!(MigrationReview::from_canonical(&bytes).is_err());
}

#[test]
fn migration_retains_real_trash_revision_pending_and_quarantined_original_bytes() {
    let (_fixture, mut repo, store, state) = setup();
    for (id, bytes) in [("quarantined", b"quarantined".as_slice())] {
        let expected = repo
            .current("document", &mut Io)
            .unwrap()
            .reference()
            .unwrap();
        let plan = repo
            .plan_external_edit("document", expected, bytes, provenance(id, bytes), &mut Io)
            .unwrap();
        drop(repo.prepare(&plan, bytes, &mut Io).unwrap());
        if id == "quarantined" {
            let review = repo
                .review_preparation(&luma_content::sha256(id.as_bytes()), &mut Io)
                .unwrap();
            repo.recover_preparation(&review, &mut Io).unwrap();
        }
    }
    // Keep a distinct live artifact for the final pending preparation. The
    // original store correctly forbids a different effect while any pending
    // transaction exists, and forbids ordinary edits of the trashed document.
    let other = crate::Plan::capture(
        binding(),
        "pending-document",
        luma_content::Format::Utf8Text,
        b"active",
        provenance("pending-first", b"active"),
    )
    .unwrap();
    repo.apply(&other, b"active", &mut Io).unwrap();
    let request = crate::LifecycleRequest {
        schema_version: 1,
        binding: binding(),
        request_id: "trash".into(),
        workflow_sha256: "d".repeat(64),
        expected: repo.lifecycle_status("document", &mut Io).unwrap(),
        operation: crate::LifecycleOperation::Trash,
        retention: crate::RetentionPolicy::UntilExplicitRestoreNoPurge,
    };
    let plan = repo.plan_lifecycle(&request, &mut Io).unwrap();
    repo.apply(&plan, &request.canonical_bytes().unwrap(), &mut Io)
        .unwrap();
    let pending = repo
        .plan_external_edit(
            "pending-document",
            other.resulting().clone(),
            b"pending",
            provenance("pending", b"pending"),
            &mut Io,
        )
        .unwrap();
    drop(repo.prepare(&pending, b"pending", &mut Io).unwrap());
    let original = repo.lifecycle_status("document", &mut Io).unwrap();
    let legacy = repo.verified_state(&mut Io).unwrap();
    state.borrow_mut().legacy = legacy.clone();
    let review = review_migration(
        &repo,
        &legacy,
        &mut Authority {
            store: &store,
            state: state.clone(),
        },
    )
    .unwrap();
    assert!(review
        .inventory
        .iter()
        .any(|entry| entry.area == SourceArea::Quarantine
            && entry.member.as_deref() == Some("source.bin")));
    assert!(review
        .inventory
        .iter()
        .any(|entry| entry.area == SourceArea::Pending
            && entry.member.as_deref() == Some("source.bin")));
    let head = loop {
        let prepared = run_window(&repo, &store, &review, &state, 2, 8);
        if prepared.commitment().next.complete {
            let next = prepared.commitment().next.clone();
            {
                let mut s = state.borrow_mut();
                s.selected = Some(next.head.clone());
                s.physical = next.physical_after.clone();
            }
            break prepared
                .acknowledge_owner(
                    &review,
                    &mut Authority {
                        store: &store,
                        state: state.clone(),
                    },
                )
                .unwrap();
        }
        select_prefix(prepared, &review, &state, &store);
    };
    let mut authority = Authority {
        store: &store,
        state: state.clone(),
    };
    let owner = OwnerRepository::at_selected(&store, &head, &mut authority).unwrap();
    assert!(owner.current("document", &mut authority).is_err());
    let status = owner.lifecycle_status("document", &mut authority).unwrap();
    assert_eq!(status.wire(), original);
    assert_eq!(
        owner
            .trash_version(&original.version, &mut authority)
            .unwrap()
            .content(),
        b"two"
    );
    assert_eq!(head.roots.corpus.entry_count, 1);
    assert_eq!(
        owner
            .current("pending-document", &mut authority)
            .unwrap()
            .content(),
        b"active"
    );
    assert_eq!(
        head.roots.pending.entry_count,
        review
            .inventory
            .iter()
            .filter(|entry| entry.area == SourceArea::Pending)
            .count() as u64
    );
    let mut io = Io;
    let mut guard = Guard::new(
        &mut io,
        &head.binding,
        super::super::owner::read_budget(),
        None,
    )
    .unwrap();
    for entry in &review.inventory {
        let retained: RetainedSource = store
            .value(
                &head.roots.retained,
                &head.roots.retained.key(&entry.key().unwrap()).unwrap(),
                &mut guard,
            )
            .unwrap()
            .unwrap();
        assert_eq!(retained.entry, *entry);
        assert_eq!(
            store.get_blob(&retained.bytes, &mut guard).unwrap(),
            read_entry(&repo, entry, &mut guard).unwrap()
        );
    }
    assert_eq!(repo.verified_state(&mut Io).unwrap(), legacy);
}
