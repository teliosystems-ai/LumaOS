use super::*;
mod collections;
use luma_content::EditOrigin;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT").expect(
            "content-store fixtures require private disposable ext4 LUMA_STORAGE_TEST_ROOT",
        );
        let path = Path::new(&base).join(format!(
            "content-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn root(&self, binding: &OwnerBinding) -> PathBuf {
        self.path.join(domain_name(binding).unwrap())
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
fn provenance(request: &str, bytes: &[u8], origin: EditOrigin) -> Provenance {
    Provenance {
        request_id: request.into(),
        workflow_sha256: "c".repeat(64),
        source_sha256: luma_content::sha256(bytes),
        origin,
    }
}
fn capture(request: &str, artifact: &str, bytes: &[u8]) -> Plan {
    Plan::capture(
        binding(),
        artifact,
        Format::Utf8Text,
        bytes,
        provenance(request, bytes, EditOrigin::Managed),
    )
    .unwrap()
}

// Only this disposable fixture implements permissive authority. Production
// callers must supply actual owner/grant/resource adapters; none is provided.
struct Guard {
    binding: OwnerBinding,
    review: Option<String>,
    checks: usize,
    admissions: usize,
    refuse_at: usize,
    refuse_resources: bool,
}
impl Guard {
    fn read() -> Self {
        Self {
            binding: binding(),
            review: None,
            checks: 0,
            admissions: 0,
            refuse_at: usize::MAX,
            refuse_resources: false,
        }
    }
    fn write(plan: &Plan) -> Self {
        Self {
            binding: plan.binding().clone(),
            review: Some(plan.review.clone()),
            ..Self::read()
        }
    }
}
impl Boundary for Guard {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.admissions += 1;
        if self.refuse_resources
            || binding != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.additional_storage_bytes > MAX_SOURCE + MAX_PAYLOAD + 2 * MAX_RECORD
        {
            return Err("fixture resource lease admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if self.checks >= self.refuse_at {
            return Err("fixture owner/account/grant/lease revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.binding && self.review.as_deref() == Some(review_sha256) => {
                Ok(())
            }
            _ => Err("fixture exact authority scope refused".into()),
        }
    }
}

#[test]
fn original_source_canonical_content_and_immutable_versions_survive_reopen() {
    let f = Fixture::new();
    let source = b"Original\r\n";
    let plan = capture("one", "document", source);
    let mut guard = Guard::write(&plan);
    let mut store = Repository::create_at(&f.path, &plan, &mut guard).unwrap();
    let first = store.apply(&plan, source, &mut guard).unwrap();
    assert_eq!(first.sequence, 1);
    assert!(!first.replayed);
    assert_eq!(
        store
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"Original\n"
    );
    let retained = store.retained("one", &mut Guard::read()).unwrap();
    assert_eq!(retained.source, source);
    assert_eq!(retained.outcome.source_sha256, luma_content::sha256(source));
    let next_source = b"Changed\r\n";
    let next = store
        .plan_external_edit(
            "document",
            first.resulting.clone(),
            next_source,
            provenance("two", next_source, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let second = store
        .apply(&next, next_source, &mut Guard::write(&next))
        .unwrap();
    assert_eq!(second.resulting.version, 2);
    assert_eq!(store.retained("one", &mut Guard::read()).unwrap(), retained);
    drop(store);
    let reopened = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
    assert_eq!(reopened.inventory(&mut Guard::read()).unwrap().len(), 2);
    assert_eq!(
        reopened
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"Changed\n"
    );
}

#[test]
fn stale_editor_save_retains_conflict_and_no_change_retains_exact_external_source() {
    let f = Fixture::new();
    let initial = capture("one", "document", b"a\r\n");
    let mut store = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    let first = store
        .apply(&initial, b"a\r\n", &mut Guard::write(&initial))
        .unwrap();
    let next = store
        .plan_external_edit(
            "document",
            first.resulting.clone(),
            b"b\n",
            provenance("two", b"b\n", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let second = store
        .apply(&next, b"b\n", &mut Guard::write(&next))
        .unwrap();
    let conflict = store
        .plan_external_edit(
            "document",
            first.resulting,
            b"c\r\n",
            provenance("three", b"c\r\n", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    assert_eq!(conflict.decision(), DecisionKind::ConflictRetained);
    store
        .apply(&conflict, b"c\r\n", &mut Guard::write(&conflict))
        .unwrap();
    let retained = store.retained("three", &mut Guard::read()).unwrap();
    let candidate: luma_content::CapturedContent =
        serde_json::from_slice(&retained.payload).unwrap();
    assert_eq!(candidate.content, "c\n");
    assert_eq!(retained.source, b"c\r\n");
    assert_eq!(
        store
            .current("document", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        second.resulting
    );
    let unchanged = store
        .plan_external_edit(
            "document",
            second.resulting,
            b"b\r\n",
            provenance("four", b"b\r\n", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    assert_eq!(unchanged.decision(), DecisionKind::NoChangeRetained);
    store
        .apply(&unchanged, b"b\r\n", &mut Guard::write(&unchanged))
        .unwrap();
    assert_eq!(
        store.retained("four", &mut Guard::read()).unwrap().source,
        b"b\r\n"
    );
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 4);
}

#[test]
fn every_durable_phase_resumes_or_replays_one_atomic_outcome() {
    for fail_at in 1..=6 {
        let f = Fixture::new();
        let plan = capture("one", "document", b"exact source");
        let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
        let mut observed = 0;
        assert!(store
            .apply_with_hook(&plan, b"exact source", &mut Guard::write(&plan), |_| {
                observed += 1;
                if observed == fail_at {
                    Err("fixture power loss/lost acknowledgement".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(store);
        let mut store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
        assert_eq!(
            store.inventory(&mut Guard::read()).unwrap().len(),
            usize::from(fail_at >= 5)
        );
        let result = store
            .apply(&plan, b"exact source", &mut Guard::write(&plan))
            .unwrap();
        assert_eq!(result.replayed, fail_at >= 5);
        assert_eq!(result.sequence, 1);
        assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 1);
        assert_eq!(
            storage::names(&store.pending, MAX_PENDING).unwrap().len(),
            0
        );
    }
}

#[test]
fn resource_and_inspection_scopes_cannot_create_or_mutate_a_repository() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"a");
    assert!(Repository::create_at(&f.path, &plan, &mut Guard::read()).is_err());
    assert!(!f.root(&binding()).exists());
    let mut denied = Guard::write(&plan);
    denied.refuse_resources = true;
    assert!(Repository::create_at(&f.path, &plan, &mut denied).is_err());
    assert_eq!(denied.checks, 0);
    assert!(!f.root(&binding()).exists());
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    assert!(store.apply(&plan, b"a", &mut Guard::read()).is_err());
    assert!(store.inventory(&mut Guard::read()).unwrap().is_empty());
}

#[test]
fn wrong_source_owner_generation_or_request_replay_cannot_replace_content() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"a");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    assert!(store.apply(&plan, b"b", &mut Guard::write(&plan)).is_err());
    store.apply(&plan, b"a", &mut Guard::write(&plan)).unwrap();
    let conflicting = capture("one", "other", b"b");
    assert!(store
        .apply(&conflicting, b"b", &mut Guard::write(&conflicting))
        .is_err());
    let foreign = OwnerBinding {
        owner_generation: 8,
        ..binding()
    };
    let foreign_plan = Plan::capture(
        foreign.clone(),
        "document",
        Format::Utf8Text,
        b"c",
        provenance("foreign", b"c", EditOrigin::Managed),
    )
    .unwrap();
    assert!(store
        .apply(&foreign_plan, b"c", &mut Guard::write(&foreign_plan))
        .is_err());
    assert_ne!(
        domain_name(&binding()).unwrap(),
        domain_name(&foreign).unwrap()
    );
    assert!(Repository::open_at(
        &f.path,
        &foreign,
        &mut Guard {
            binding: foreign.clone(),
            ..Guard::read()
        }
    )
    .is_err());
    assert_eq!(
        store
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"a"
    );
}

#[test]
fn a_reviewed_plan_cannot_overwrite_a_later_current_version() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"a");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    let first = store.apply(&plan, b"a", &mut Guard::write(&plan)).unwrap();
    let stale = store
        .plan_external_edit(
            "document",
            first.resulting.clone(),
            b"b",
            provenance("stale", b"b", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let latest = store
        .plan_external_edit(
            "document",
            first.resulting,
            b"c",
            provenance("latest", b"c", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    store
        .apply(&latest, b"c", &mut Guard::write(&latest))
        .unwrap();
    assert!(store
        .apply(&stale, b"b", &mut Guard::write(&stale))
        .is_err());
    assert_eq!(
        store
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"c"
    );
    assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 2);
}

#[test]
fn changed_or_partial_preparations_are_preserved_without_publication() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"exact original");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    assert!(store
        .apply_with_hook(
            &plan,
            b"exact original",
            &mut Guard::write(&plan),
            |phase| {
                if matches!(phase, Phase::Prepared) {
                    Err("fixture prepared interruption".into())
                } else {
                    Ok(())
                }
            }
        )
        .is_err());
    let path = f
        .root(&binding())
        .join("pending")
        .join(luma_content::sha256(b"one"))
        .join("source.bin");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"partial").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store
        .apply(&plan, b"exact original", &mut Guard::write(&plan))
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), b"partial");
    assert!(store.inventory(&mut Guard::read()).unwrap().is_empty());
}

#[test]
fn preparation_mutation_after_sync_is_detected_before_atomic_rename() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"original");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    let path = f
        .root(&binding())
        .join("pending")
        .join(luma_content::sha256(b"one"))
        .join("source.bin");
    assert!(store
        .apply_with_hook(&plan, b"original", &mut Guard::write(&plan), |phase| {
            if matches!(phase, Phase::Prepared) {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                fs::write(&path, b"modified")?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
            }
            Ok(())
        })
        .is_err());
    assert!(store.inventory(&mut Guard::read()).unwrap().is_empty());
    assert_eq!(fs::read(path).unwrap(), b"modified");
}

#[test]
fn revocation_during_each_private_read_boundary_discards_results() {
    let f = Fixture::new();
    let bytes = vec![b'x'; 100_000];
    let plan = capture("one", "document", &bytes);
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    store
        .apply(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    let mut baseline = Guard::read();
    store.current("document", &mut baseline).unwrap();
    assert!(baseline.checks > 20);
    for at in 1..=baseline.checks {
        let mut revoked = Guard::read();
        revoked.refuse_at = at;
        assert!(
            store.current("document", &mut revoked).is_err(),
            "revocation at {at}"
        );
        assert_eq!(revoked.checks, at);
    }
}

#[test]
fn namespaces_are_pinned_and_committed_source_tampering_is_refused() {
    let f = Fixture::new();
    let plan = capture("one", "document", b"a");
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    store.apply(&plan, b"a", &mut Guard::write(&plan)).unwrap();
    let original = f.root(&binding()).join("outcomes");
    let moved = f.root(&binding()).join("moved-outcomes");
    fs::rename(&original, &moved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
    assert!(store.current("document", &mut Guard::read()).is_err());
    fs::remove_dir(&original).unwrap();
    fs::rename(&moved, &original).unwrap();
    let source = original
        .join(luma_content::sha256(b"one"))
        .join("source.bin");
    fs::hard_link(&source, f.path.join("linked-source")).unwrap();
    assert!(store.current("document", &mut Guard::read()).is_err());
}

#[test]
fn every_mutation_checkpoint_refuses_revocation_without_claiming_completion() {
    let source = vec![b'x'; 70_000];
    let plan = capture("one", "document", &source);
    let checkpoints = {
        let f = Fixture::new();
        let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
        let mut baseline = Guard::write(&plan);
        store.apply(&plan, &source, &mut baseline).unwrap();
        baseline.checks
    };
    assert!(checkpoints > 20);
    for at in 1..=checkpoints {
        let f = Fixture::new();
        let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
        let mut revoked = Guard::write(&plan);
        revoked.refuse_at = at;
        assert!(
            store.apply(&plan, &source, &mut revoked).is_err(),
            "revocation at {at}"
        );
        assert_eq!(revoked.checks, at, "no further operation after refusal");
        // A post-rename refusal can leave a committed but unacknowledged
        // outcome. An earlier refusal can leave a partial preparation. Neither
        // is erased or interpreted as a successful response to the old caller.
        let before = store.inventory(&mut Guard::read()).unwrap();
        assert!(before.len() <= 1);
        let retried = store.apply(&plan, &source, &mut Guard::write(&plan));
        let after = store.inventory(&mut Guard::read()).unwrap();
        if let Ok(acknowledged) = retried {
            assert_eq!(after.len(), 1);
            assert_eq!(acknowledged.resulting.version, 1);
            assert_eq!(
                store.retained("one", &mut Guard::read()).unwrap().source,
                source
            );
        } else {
            assert_eq!(after, before, "incompatible partial bytes remain preserved");
            assert!(!storage::names(&store.pending, MAX_PENDING)
                .unwrap()
                .is_empty());
        }
    }
}

#[test]
fn namespace_capacity_is_serialized_and_exactly_bounded() {
    let f = Fixture::new();
    for i in 0..MAX_DOMAINS - 1 {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(
                f.path
                    .join(luma_content::sha256(format!("occupied-{i}").as_bytes())),
            )
            .unwrap();
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for owner in ["d", "e"] {
        let path = f.path.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let plan = Plan::capture(
                OwnerBinding {
                    owner: owner.repeat(64),
                    ..binding()
                },
                "document",
                Format::Utf8Text,
                b"a",
                provenance("one", b"a", EditOrigin::Managed),
            )
            .unwrap();
            barrier.wait();
            Repository::create_at(&path, &plan, &mut Guard::write(&plan)).is_ok()
        }));
    }
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|passed| *passed)
            .count(),
        1
    );
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), MAX_DOMAINS);
    let extra = capture("extra", "document", b"a");
    assert!(Repository::create_at(&f.path, &extra, &mut Guard::write(&extra)).is_err());
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), MAX_DOMAINS);
}

#[test]
fn complete_preparation_charges_only_missing_bytes_at_the_storage_boundary() {
    assert_eq!(
        additional_charge(MAX_REPOSITORY_BYTES, 2 * 1024 * 1024, 2 * 1024 * 1024).unwrap(),
        0
    );
    assert_eq!(
        additional_charge(MAX_REPOSITORY_BYTES - 1024, 4096, 3072).unwrap(),
        1024
    );
    assert!(additional_charge(MAX_REPOSITORY_BYTES - 1024, 4096, 3071).is_err());
    assert!(additional_charge(0, 10, 11).is_err());
    assert!(additional_charge(u64::MAX, 1, 0).is_err());
}

#[test]
fn independent_domains_can_be_created_while_another_repository_remains_open() {
    let f = Fixture::new();
    let first = capture("one", "document", b"a");
    let a = Repository::create_at(&f.path, &first, &mut Guard::write(&first)).unwrap();
    let second = Plan::capture(
        OwnerBinding {
            owner: "d".repeat(64),
            ..binding()
        },
        "document",
        Format::Utf8Text,
        b"b",
        provenance("two", b"b", EditOrigin::Managed),
    )
    .unwrap();
    let b = Repository::create_at(&f.path, &second, &mut Guard::write(&second)).unwrap();
    assert!(Repository::open_at(&f.path, first.binding(), &mut Guard::read()).is_err());
    assert!(a.inventory(&mut Guard::read()).unwrap().is_empty());
    assert!(b
        .inventory(&mut Guard {
            binding: second.binding().clone(),
            ..Guard::read()
        })
        .unwrap()
        .is_empty());
}

#[test]
fn unsupported_storage_and_symlink_namespaces_are_not_followed() {
    assert!(storage::base(Path::new("/proc")).is_err());
    let f = Fixture::new();
    let plan = capture("one", "document", b"a");
    std::os::unix::fs::symlink("/proc", f.root(&binding())).unwrap();
    assert!(Repository::open_at(&f.path, &binding(), &mut Guard::read()).is_err());
    assert!(Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).is_err());
}

#[test]
fn shared_history_reconstruction_fences_failed_or_repeated_observations() {
    let first = capture("first", "document", b"first");
    let second = capture("second", "other", b"second");
    let record = |plan: &Plan, sequence| Record {
        schema_version: plan.data.schema_version,
        sequence,
        review_sha256: plan.review.clone(),
        plan: plan.data.clone(),
    };
    let mut history = HistoryReconstruction::new();
    assert_eq!(
        history
            .observe(
                &binding(),
                &record(&first, 1),
                &first.payload,
                b"first",
                &mut || Ok(())
            )
            .unwrap(),
        first
    );
    assert!(history
        .observe(
            &binding(),
            &record(&first, 1),
            &first.payload,
            b"first",
            &mut || Ok(())
        )
        .is_err());
    assert!(history
        .observe(
            &binding(),
            &record(&second, 2),
            &second.payload,
            b"second",
            &mut || Ok(())
        )
        .is_err());
    assert_eq!(history.count, 1);
    assert_eq!(history.current.len(), 1);
    let mut fresh = HistoryReconstruction::new();
    for (plan, source, sequence) in [
        (&first, b"first".as_slice(), 1),
        (&second, b"second".as_slice(), 2),
    ] {
        fresh
            .observe(
                &binding(),
                &record(plan, sequence),
                &plan.payload,
                source,
                &mut || Ok(()),
            )
            .unwrap();
    }
    assert_eq!(fresh.count, 2);
    assert_eq!(fresh.current.len(), 2);
}

#[test]
fn shared_history_reconstruction_never_skips_bad_binding_bytes_or_authority_refusal() {
    let plan = capture("first", "document", b"first");
    for change in 0..7 {
        let mut record = Record {
            schema_version: plan.data.schema_version,
            sequence: 1,
            review_sha256: plan.review.clone(),
            plan: plan.data.clone(),
        };
        let mut payload = plan.payload.clone();
        let mut source = b"first".to_vec();
        match change {
            0 => record.schema_version = 4,
            1 => record.plan.binding.owner_generation += 1,
            2 => record.sequence = 2,
            3 => record.review_sha256 = "f".repeat(64),
            4 => payload[0] ^= 1,
            5 => source[0] ^= 1,
            6 => (),
            _ => unreachable!(),
        }
        let mut history = HistoryReconstruction::new();
        let mut check = || -> Result<()> {
            if change == 6 {
                Err("fixture authority refusal".into())
            } else {
                Ok(())
            }
        };
        assert!(history
            .observe(&binding(), &record, &payload, &source, &mut check)
            .is_err());
        assert!(history
            .observe(
                &binding(),
                &Record {
                    schema_version: plan.data.schema_version,
                    sequence: 1,
                    review_sha256: plan.review.clone(),
                    plan: plan.data.clone(),
                },
                &plan.payload,
                b"first",
                &mut || Ok(())
            )
            .is_err());
        assert_eq!(history.count, 0);
        assert!(history.current.is_empty());
    }
}

mod backup;
mod managed;
mod publication;
mod queries;
mod recovery;
mod rendered;
mod restore;
