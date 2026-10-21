use super::head::OwnerHeadV2;
use super::lifecycle::LifecycleRequestV2;
use super::*;
use crate::{LifecycleOperation, RetentionPolicy};
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("owner fixtures require private disposable ext4");
        let path = Path::new(&root).join(format!(
            "owner-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
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
struct Io;
// Explicit disposable software fixture, not an installed principal/custody root.
impl Boundary for Io {
    fn admit(&mut self, binding: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        binding.validate()?;
        Ok(())
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
struct State {
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    revoked: bool,
}
struct Live<'a> {
    store: &'a ObjectStore,
    state: Rc<RefCell<State>>,
    review: Option<String>,
}
impl Boundary for Live<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if binding != &self.state.borrow().head.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || self.state.borrow().revoked
        {
            return Err("fixture live resource/owner admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if self.state.borrow().revoked {
            return Err("fixture revoked original authority".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.state.borrow().head.binding => Ok(()),
            Access::Mutate { review_sha256, .. }
                if self.review.as_deref() == Some(review_sha256) =>
            {
                Ok(())
            }
            _ => Err("fixture finite effect scope refused".into()),
        }
    }
}
impl OwnerBoundary for Live<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if self.state.borrow().revoked || &self.state.borrow().head != head {
            return Err("fixture actual selected C head changed".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.state.borrow().physical.clone())
    }
    fn verify_prepared_allocations(&mut self, commitment: &AppendCommitment) -> Result<()> {
        self.current_owner_head(&commitment.base)?;
        let actual = self
            .store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))?;
        if actual != commitment.physical_after {
            return Err("fixture actual ext4 allocations differ from candidate".into());
        }
        Ok(())
    }
}
fn setup() -> (Fixture, ObjectStore, Rc<RefCell<State>>) {
    let fixture = Fixture::new();
    let store = ObjectStore::create_at(
        &fixture.path,
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
        .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    let head = OwnerHeadV2::empty_data(&binding(), physical.clone()).unwrap();
    let state = Rc::new(RefCell::new(State {
        head,
        physical,
        revoked: false,
    }));
    (fixture, store, state)
}
fn provenance(request: &str, source: &[u8]) -> crate::Provenance {
    crate::Provenance {
        request_id: request.into(),
        workflow_sha256: "d".repeat(64),
        source_sha256: luma_content::sha256(source),
        origin: luma_content::EditOrigin::External,
    }
}
fn publish(store: &ObjectStore, state: &Rc<RefCell<State>>, plan: &OwnerPlan) -> OwnerHeadV2 {
    let mut live = Live {
        store,
        state: state.clone(),
        review: Some(plan.review_sha256().into()),
    };
    let head = state.borrow().head.clone();
    let repository = OwnerRepository::at_selected(store, &head, &mut live).unwrap();
    let prepared = repository
        .prepare_append(plan, budget(), &mut live)
        .unwrap();
    let commitment = prepared.commitment().clone();
    verify_append_data(store, &commitment, owner::read_budget(), &mut live).unwrap();
    {
        let mut state = state.borrow_mut();
        state.head = commitment.next.clone();
        state.physical = commitment.physical_after.clone();
    }
    prepared.acknowledge_selected(&mut live).unwrap()
}
#[test]
fn selected_owner_real_capture_external_edit_stale_conflict_and_exact_history() {
    let (_fixture, store, state) = setup();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let head = state.borrow().head.clone();
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let plan = repository
        .plan_capture(
            "document",
            luma_content::Format::Utf8Text,
            b"one\r\n",
            provenance("first", b"one\r\n"),
            &mut live,
        )
        .unwrap();
    let first = plan.resulting().clone();
    let head = publish(&store, &state, &plan);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    assert_eq!(
        repository.current("document", &mut live).unwrap().content(),
        b"one\n"
    );
    let plan = repository
        .plan_external_edit(
            "document",
            first.clone(),
            b"two",
            provenance("second", b"two"),
            &mut live,
        )
        .unwrap();
    let second = plan.resulting().clone();
    let head = publish(&store, &state, &plan);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let conflict = repository
        .plan_external_edit(
            "document",
            first.clone(),
            b"candidate",
            provenance("stale", b"candidate"),
            &mut live,
        )
        .unwrap();
    assert_eq!(conflict.decision(), DecisionKind::ConflictRetained);
    let head = publish(&store, &state, &conflict);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    assert_eq!(
        repository
            .current("document", &mut live)
            .unwrap()
            .reference()
            .unwrap(),
        second
    );
    assert_eq!(
        repository.historical(&first, &mut live).unwrap().content(),
        b"one\n"
    );
    let retained = repository.outcome_at(3, &mut live).unwrap();
    let candidate: luma_content::CapturedContent =
        serde_json::from_slice(&retained.payload).unwrap();
    assert_eq!(candidate.content, "candidate");
    assert_eq!(retained.source, b"candidate");
    assert_eq!(head.history.segments, 1);
}
#[test]
fn selected_owner_trash_restore_aba_and_corpus_visibility_use_real_replay() {
    let (_fixture, store, state) = setup();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let head = state.borrow().head.clone();
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let plan = repository
        .plan_capture(
            "document",
            luma_content::Format::Utf8Text,
            b"private",
            provenance("first", b"private"),
            &mut live,
        )
        .unwrap();
    let reference = plan.resulting().clone();
    let head = publish(&store, &state, &plan);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let initial = repository.lifecycle_status("document", &mut live).unwrap();
    let request = LifecycleRequestV2 {
        schema_version: 2,
        binding: binding(),
        request_id: "trash".into(),
        workflow_sha256: "e".repeat(64),
        expected: initial.clone(),
        operation: LifecycleOperation::Trash,
        retention: RetentionPolicy::UntilExplicitRestoreNoPurge,
    };
    let plan = repository.plan_lifecycle(&request, &mut live).unwrap();
    let head = publish(&store, &state, &plan);
    assert_eq!(head.roots.corpus.entry_count, 0);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    assert!(repository.current("document", &mut live).is_err());
    assert!(repository.historical(&reference, &mut live).is_err());
    assert_eq!(
        repository
            .trash_version(&reference, &mut live)
            .unwrap()
            .content(),
        b"private"
    );
    let trashed = repository.lifecycle_status("document", &mut live).unwrap();
    let restore = LifecycleRequestV2 {
        request_id: "restore".into(),
        expected: trashed,
        operation: LifecycleOperation::Restore,
        ..request.clone()
    };
    let plan = repository.plan_lifecycle(&restore, &mut live).unwrap();
    let head = publish(&store, &state, &plan);
    assert_eq!(head.roots.corpus.entry_count, 1);
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    assert_eq!(
        repository
            .current("document", &mut live)
            .unwrap()
            .reference()
            .unwrap(),
        reference
    );
    let stale = LifecycleRequestV2 {
        request_id: "stale-aba".into(),
        ..request
    };
    let plan = repository.plan_lifecycle(&stale, &mut live).unwrap();
    assert_eq!(plan.decision(), DecisionKind::ConflictRetained);
    let head = publish(&store, &state, &plan);
    assert_eq!(head.roots.corpus.entry_count, 1);
}
#[test]
fn selected_owner_rejects_copied_head_stale_plan_duplicate_request_and_revocation() {
    let (_fixture, store, state) = setup();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let head = state.borrow().head.clone();
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let first = repository
        .plan_capture(
            "a",
            luma_content::Format::Utf8Text,
            b"a",
            provenance("first", b"a"),
            &mut live,
        )
        .unwrap();
    let stale = repository
        .plan_capture(
            "b",
            luma_content::Format::Utf8Text,
            b"b",
            provenance("second", b"b"),
            &mut live,
        )
        .unwrap();
    let next = publish(&store, &state, &first);
    assert!(OwnerRepository::at_selected(&store, &head, &mut live).is_err());
    let repository = OwnerRepository::at_selected(&store, &next, &mut live).unwrap();
    live.review = Some(stale.review_sha256().into());
    assert!(repository
        .prepare_append(&stale, budget(), &mut live)
        .is_err());
    let duplicate = repository
        .plan_external_edit(
            "a",
            first.resulting().clone(),
            b"x",
            provenance("first", b"x"),
            &mut live,
        )
        .unwrap();
    live.review = Some(duplicate.review_sha256().into());
    assert!(repository
        .prepare_append(&duplicate, budget(), &mut live)
        .is_err());
    state.borrow_mut().revoked = true;
    assert!(repository.current("a", &mut live).is_err());
}
#[test]
fn prepared_append_requires_actual_allocation_join_and_all_generated_pages() {
    let (fixture, store, state) = setup();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let head = state.borrow().head.clone();
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let plan = repository
        .plan_capture(
            "a",
            luma_content::Format::Utf8Text,
            b"a",
            provenance("first", b"a"),
            &mut live,
        )
        .unwrap();
    live.review = Some(plan.review_sha256().into());
    let prepared = repository
        .prepare_append(&plan, budget(), &mut live)
        .unwrap();
    let mut altered = prepared.commitment().clone();
    altered.physical_after.allocated_bytes += 4096;
    assert!(verify_append_data(&store, &altered, owner::read_budget(), &mut live).is_err());
    let hash = prepared
        .commitment()
        .next
        .roots
        .corpus
        .page
        .as_ref()
        .unwrap()
        .sha256
        .clone();
    let path = fixture
        .path
        .join(ObjectStore::name(&binding()).unwrap())
        .join("objects")
        .join(&hash[..2])
        .join(&hash[2..4])
        .join(&hash);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"tampered").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(verify_append_data(
        &store,
        prepared.commitment(),
        owner::read_budget(),
        &mut live
    )
    .is_err());
    assert_eq!(state.borrow().head, head);
}
#[test]
fn owner_head_closed_nine_roles_counts_and_migration_binding_are_not_aliases() {
    let (_fixture, _store, state) = setup();
    let head = state.borrow().head.clone();
    assert_eq!(
        OwnerHeadV2::from_canonical(&head.canonical_bytes().unwrap()).unwrap(),
        head
    );
    let mut bad = head.clone();
    bad.roots.corpus.kind = MapKind::Artifacts;
    assert!(bad.validate().is_err());
    bad = head.clone();
    bad.history.outcomes = 1;
    assert!(bad.validate().is_err());
    bad = head.clone();
    bad.physical.observation_sha256 = "f".repeat(64);
    assert!(bad.validate().is_err());
    let mut bytes = head.canonical_bytes().unwrap();
    bytes.push(b' ');
    assert!(OwnerHeadV2::from_canonical(&bytes).is_err());
}
