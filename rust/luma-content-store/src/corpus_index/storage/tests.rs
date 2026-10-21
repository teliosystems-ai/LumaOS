//! Real private ObjectStore reads with explicit synthetic authorization; not
//! installed observer/PAM/C identity, allocation or latency qualification.
use super::*;
use crate::corpus_index::storage::{IndexReadStore, ObservedIndexStore};
use crate::v2::readonly::ObservedPageReader;
use std::cell::Cell;

struct Reader<'a> {
    store: &'a ObjectStore,
    calls: &'a Cell<usize>,
    corrupt: &'a Cell<bool>,
}
struct Checked<'a> {
    binding: &'a OwnerBinding,
    check: &'a mut dyn FnMut() -> Result<()>,
}
impl Boundary for Checked<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if *binding != *self.binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("fixture observed read refuses another owner or writes".into());
        }
        (self.check)()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if !matches!(access,Access::Inspect{binding} if binding==self.binding) {
            return Err("fixture observer is read-only".into());
        }
        (self.check)()
    }
}
impl ObservedPageReader for Reader<'_> {
    fn read_observed_page(
        &mut self,
        binding: &OwnerBinding,
        sha: &str,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        self.calls.set(self.calls.get() + 1);
        let mut bytes = self.store.read_page(
            sha,
            IoBudget {
                read_bytes: 32 * 1024,
                write_bytes: 0,
                new_files: 0,
            },
            &mut Checked { binding, check },
        )?;
        if bytes.len() > maximum {
            return Err("fixture maximum exceeded".into());
        }
        if self.corrupt.get() {
            bytes[0] ^= 1;
        }
        check()?;
        Ok(bytes)
    }
}
fn scan(
    store: &dyn IndexReadStore,
    request: &IngestRequest,
    cursor: &crate::v2::cursor::MapCursor,
    maximum: usize,
    guard: &mut Guard,
) -> Result<crate::v2::cursor::MapWindow> {
    let progress = IngestProgress::beginning(request)?;
    store.scan_map_window(
        &request.corpus,
        cursor,
        maximum,
        read_budget(),
        &mut Live {
            request,
            progress: &progress,
            boundary: guard,
        },
    )
}

#[test]
fn readonly_observer_replays_actual_ingestion_and_prepared_pages() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&["alpha beta", "gamma alpha"]);
    let base = IngestProgress::beginning(&request).unwrap();
    let local = plan_ingestion_window(
        &store,
        &request,
        &base,
        2,
        limits(),
        &mut sources,
        &mut guard,
    )
    .unwrap();
    let calls = Cell::new(0);
    let corrupt = Cell::new(false);
    let remote = ObservedIndexStore::new(
        &owner(),
        Reader {
            store: &store,
            calls: &calls,
            corrupt: &corrupt,
        },
    )
    .unwrap();
    let observed = plan_ingestion_window(
        &remote,
        &request,
        &base,
        2,
        limits(),
        &mut sources,
        &mut guard,
    )
    .unwrap();
    assert_eq!(local.commitment(), observed.commitment());
    let mutation = Mutation {
        review_sha256: local.commitment().review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: local.commitment().next.totals.source_bytes,
    };
    guard.review = mutation.review_sha256.clone();
    let prepared = prepare_ingestion(&store, &local, &mutation, &mut guard).unwrap();
    verify_ingestion_data(&remote, prepared.commitment(), &mut sources, &mut guard).unwrap();
    assert!(calls.get() > 0);
    corrupt.set(true);
    assert!(
        verify_ingestion_data(&remote, prepared.commitment(), &mut sources, &mut guard).is_err()
    );
}

#[test]
fn readonly_observer_checks_true_budgets_before_io_and_rehashes_cached_reuse() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&["alpha beta"]);
    let plan = plan_ingestion_window(
        &store,
        &request,
        &IngestProgress::beginning(&request).unwrap(),
        1,
        limits(),
        &mut sources,
        &mut guard,
    )
    .unwrap();
    let mutation = Mutation {
        review_sha256: plan.commitment().review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: plan.commitment().next.totals.source_bytes,
    };
    guard.review = mutation.review_sha256.clone();
    let prepared = prepare_ingestion(&store, &plan, &mutation, &mut guard).unwrap();
    let sha = &prepared.commitment().next.last_run.as_ref().unwrap().sha256;
    let calls = Cell::new(0);
    let corrupt = Cell::new(false);
    let remote = ObservedIndexStore::new(
        &owner(),
        Reader {
            store: &store,
            calls: &calls,
            corrupt: &corrupt,
        },
    )
    .unwrap();
    assert!(remote
        .read_page(
            sha,
            IoBudget {
                read_bytes: 1,
                write_bytes: 0,
                new_files: 0
            },
            &mut guard
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    assert!(remote
        .read_page(
            sha,
            IoBudget {
                read_bytes: 32768,
                write_bytes: 1,
                new_files: 1
            },
            &mut guard
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    let (_, pin) = remote
        .read_page_observed(sha, read_budget(), &mut guard)
        .unwrap();
    let before = calls.get();
    assert!(
        remote
            .check_page_observation(&pin, read_budget(), &mut guard)
            .unwrap()
            > 0
    );
    assert_eq!(calls.get(), before + 1);
    assert!(
        IndexReadStore::check_page_observation(&store, &pin, read_budget(), &mut guard).is_err()
    );
    corrupt.set(true);
    assert!(remote
        .check_page_observation(&pin, read_budget(), &mut guard)
        .is_err());
    corrupt.set(false);
    guard.revoked = true;
    let before = calls.get();
    assert!(remote
        .check_page_observation(&pin, read_budget(), &mut guard)
        .is_err());
    assert_eq!(calls.get(), before);
}

#[test]
fn observer_map_cursor_and_blob_share_actual_parsers_and_owner_fences() {
    let (_fixture, store, request, _sources, mut guard) =
        setup(&["alpha", "beta", "gamma", "delta", "epsilon"]);
    let calls = Cell::new(0);
    let corrupt = Cell::new(false);
    let remote = ObservedIndexStore::new(
        &owner(),
        Reader {
            store: &store,
            calls: &calls,
            corrupt: &corrupt,
        },
    )
    .unwrap();
    let cursor = crate::v2::cursor::MapCursor::beginning(&request.corpus).unwrap();
    let local = scan(&store, &request, &cursor, 3, &mut guard).unwrap();
    let observed = scan(&remote, &request, &cursor, 3, &mut guard).unwrap();
    assert_eq!(observed.entries, local.entries);
    assert_eq!(observed.next, local.next);
    let observed = scan(&remote, &request, &observed.next, 3, &mut guard).unwrap();
    assert!(observed.complete);
    assert_eq!(observed.entries.len(), 2);
    let key = &observed.entries[0].0;
    assert_eq!(
        remote
            .lookup_map(&request.corpus, key, read_budget(), &mut guard)
            .unwrap()
            .verify(&request.corpus)
            .unwrap(),
        store
            .lookup_map(&request.corpus, key, read_budget(), &mut guard)
            .unwrap()
            .verify(&request.corpus)
            .unwrap()
    );
    let data = vec![b'z'; 65536];
    guard.review = seed_mutation().review_sha256;
    let blob = store
        .prepare_blob(&data, budget(), &seed_mutation(), &mut guard)
        .unwrap();
    assert_eq!(
        remote.read_blob(&blob, read_budget(), &mut guard).unwrap(),
        data
    );
    let mut other = blob.clone();
    other.binding.owner_generation += 1;
    let before = calls.get();
    assert!(remote.read_blob(&other, read_budget(), &mut guard).is_err());
    assert_eq!(calls.get(), before);
    corrupt.set(true);
    assert!(scan(&remote, &request, &cursor, 3, &mut guard).is_err());
    assert!(remote.read_blob(&blob, read_budget(), &mut guard).is_err());
}

#[test]
fn actual_blob_writer_consumes_the_same_complete_object_plan() {
    let (_fixture, store, _request, _sources, mut guard) = setup(&[]);
    guard.review = seed_mutation().review_sha256;
    let bytes: Vec<u8> = (0..2 * 16384 + 123).map(|i| (i % 251) as u8).collect();
    let plan = crate::v2::BlobObjectPlan::data(&owner(), &bytes, || {
        guard.check(Access::Inspect { binding: &owner() })
    })
    .unwrap();
    let actual = store
        .prepare_blob(&bytes, budget(), &seed_mutation(), &mut guard)
        .unwrap();
    assert_eq!(&actual, plan.reference());
    for object in plan.objects() {
        assert_eq!(
            store
                .read_page(object.sha256(), read_budget(), &mut guard)
                .unwrap(),
            object.bytes()
        );
    }
    assert_eq!(
        store.read_blob(&actual, read_budget(), &mut guard).unwrap(),
        bytes
    );
}
