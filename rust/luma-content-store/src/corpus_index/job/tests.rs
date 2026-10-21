//! Actual private-store/algorithm fixtures with explicitly synthetic authority.
//! These are not installed PAM, current C, allocation-observer or NF08 evidence.
use super::*;
use crate::v2::{MapEdit, MapKind};
use luma_content::OwnerBinding;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[path = "../storage/tests.rs"]
mod observed_storage_tests;
pub(super) struct Fixture {
    pub(super) path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base =
            std::env::var("LUMA_STORAGE_TEST_ROOT").expect("private disposable ext4 required");
        let path = Path::new(&base).join(format!(
            "ingest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn object(&self, hash: &str) -> PathBuf {
        fs::read_dir(&self.path)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn owner() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    }
}
fn builder() -> BuilderIdentity {
    BuilderIdentity {
        source_sha256: "1".repeat(64),
        runtime_sha256: "2".repeat(64),
    }
}
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 64 * 1024 * 1024,
        new_files: 8192,
    }
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn limits() -> CorpusIndexLimits {
    CorpusIndexLimits {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 16 * 1024 * 1024,
        source_bytes: 4 * 1024 * 1024,
        postings: 65536,
        floating_operations: 100_000_000,
    }
}
fn seed_mutation() -> Mutation {
    Mutation {
        review_sha256: "c".repeat(64),
        decision: crate::DecisionKind::Published,
        source_bytes: 1024,
    }
}

pub(super) struct Guard {
    root: MapRoot,
    request: Option<IngestRequest>,
    selected: Option<IngestProgress>,
    review: String,
    write: bool,
    write_admissions: usize,
    stop_after_write_admissions: Option<usize>,
    mutate_checks: usize,
    allocation_checks: usize,
    revoked: bool,
    changed_builder: bool,
}
impl Guard {
    fn seed(root: &MapRoot) -> Self {
        Self {
            root: root.clone(),
            request: None,
            selected: None,
            review: "c".repeat(64),
            write: true,
            write_admissions: 0,
            stop_after_write_admissions: None,
            mutate_checks: 0,
            allocation_checks: 0,
            revoked: false,
            changed_builder: false,
        }
    }
    fn job(request: &IngestRequest, selected: &IngestProgress) -> Self {
        let mut value = Self::seed(&request.corpus);
        value.request = Some(request.clone());
        value.selected = Some(selected.clone());
        value
    }
}
impl Boundary for Guard {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if self.revoked
            || binding != &self.root.binding
            || budget.memory_bytes > 192 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("fixture admission denied".into());
        }
        if budget.write_bytes != 0 {
            if !self.write
                || self
                    .stop_after_write_admissions
                    .is_some_and(|n| self.write_admissions >= n)
            {
                return Err("fixture finite allocation admission exhausted".into());
            }
            self.write_admissions += 1;
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if self.revoked {
            return Err("fixture original authority revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.root.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                decision,
                ..
            } if self.write
                && binding == &self.root.binding
                && review_sha256 == self.review
                && decision == crate::DecisionKind::Published =>
            {
                self.mutate_checks += 1;
                Ok(())
            }
            _ => Err("fixture independent effect denied".into()),
        }
    }
}
impl CorpusIndexBoundary for Guard {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if self.revoked || root != &self.root {
            return Err("fixture selected corpus changed".into());
        }
        Ok(())
    }
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()> {
        self.current_corpus(root)?;
        if self.changed_builder || identity != &builder() {
            return Err("fixture builder changed".into());
        }
        Ok(())
    }
    fn current_index_generation(&mut self, _: &MapRoot, _: &str) -> Result<()> {
        Err("ingestion is not a selected completed index".into())
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        record.validate()
    }
}
impl CorpusIndexJobBoundary for Guard {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()> {
        if self.revoked
            || self.request.as_ref() != Some(request)
            || self.selected.as_ref() != Some(progress)
        {
            return Err("fixture independently selected progress differs".into());
        }
        Ok(())
    }
    fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()> {
        self.current_job(&value.request, &value.base)?;
        self.allocation_checks += 1;
        Ok(())
    }
}
pub(super) struct Sources {
    bytes: BTreeMap<String, Vec<u8>>,
    changed: bool,
    calls: usize,
}
impl CorpusContent for Sources {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        b: &mut B,
    ) -> Result<Vec<u8>> {
        b.check(Access::Inspect { binding: &owner() })?;
        self.calls += 1;
        let mut bytes = self
            .bytes
            .get(&record.reference.content_sha256)
            .ok_or("exact fixture source absent")?
            .clone();
        if self.changed {
            bytes.push(b'!');
        }
        Ok(bytes)
    }
}
fn setup(texts: &[&str]) -> (Fixture, ObjectStore, IngestRequest, Sources, Guard) {
    let fixture = Fixture::new();
    let empty = MapRoot::empty(&owner(), MapKind::Corpus).unwrap();
    let mut seed = Guard::seed(&empty);
    let store = ObjectStore::create_at(
        &fixture.path,
        &owner(),
        budget(),
        &seed_mutation(),
        &mut seed,
    )
    .unwrap();
    let mut source = Sources {
        bytes: BTreeMap::new(),
        changed: false,
        calls: 0,
    };
    let mut edits = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        let hash = luma_content::sha256(text.as_bytes());
        source.bytes.insert(hash.clone(), text.as_bytes().to_vec());
        let record = CorpusRecord {
            schema_version: 1,
            reference: VersionReference {
                artifact_id: format!("document-{i}"),
                version: 1,
                content_sha256: hash,
                receipt_sha256: "d".repeat(64),
            },
            format: Format::Utf8Text,
            content_bytes: text.len() as u64,
            lifecycle_revision: 1,
            lifecycle_state_sha256: "e".repeat(64),
        };
        edits.push(MapEdit {
            key: empty.corpus_key(&record.reference.artifact_id).unwrap(),
            expected_value_sha256: None,
            value: Some(record.canonical_bytes().unwrap()),
        });
    }
    edits.sort_by(|a, z| a.key.cmp(&z.key));
    let mut root = empty;
    for window in edits.chunks(256) {
        root = store
            .prepare_map(&root, window, budget(), &seed_mutation(), &mut seed)
            .unwrap();
    }
    let request = IngestRequest {
        schema_version: 1,
        job_sha256: "f".repeat(64),
        corpus: root,
        builder: builder(),
        limits: CorpusIndexLimits {
            read_bytes: 8 * 1024 * 1024 * 1024,
            write_bytes: 1024 * 1024 * 1024,
            source_bytes: MAX_INDEX_SOURCE_BYTES,
            postings: MAX_INDEX_POSTINGS,
            floating_operations: 2_000_000_000,
        },
    };
    let guard = Guard::job(&request, &IngestProgress::beginning(&request).unwrap());
    (fixture, store, request, source, guard)
}
fn plan(
    store: &ObjectStore,
    request: &IngestRequest,
    source: &mut Sources,
    guard: &mut Guard,
) -> IngestPlan {
    plan_ingestion_window(
        store,
        request,
        &guard.selected.clone().unwrap(),
        MAX_INGEST_DOCUMENTS,
        limits(),
        source,
        guard,
    )
    .unwrap()
}
fn effect(value: &IngestPlan) -> Mutation {
    Mutation {
        review_sha256: value.commitment.review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: value.commitment.next.totals.source_bytes
            - value.commitment.base.totals.source_bytes,
    }
}
pub(super) fn completed_fixture(
    texts: &[&str],
) -> (Fixture, ObjectStore, IngestRequest, IngestProgress, Guard) {
    let (fixture, store, request, mut sources, mut guard) = setup(texts);
    while !guard.selected.as_ref().unwrap().complete(&request).unwrap() {
        let plan = plan(&store, &request, &mut sources, &mut guard);
        let mutation = effect(&plan);
        guard.review = mutation.review_sha256.clone();
        let prepared = prepare_ingestion(&store, &plan, &mutation, &mut guard).unwrap();
        guard.write = false;
        verify_ingestion_data(&store, prepared.commitment(), &mut sources, &mut guard).unwrap();
        guard.selected = Some(prepared.commitment.next.clone());
        guard.write = true;
    }
    (
        fixture,
        store,
        request,
        guard.selected.clone().unwrap(),
        guard,
    )
}
impl Guard {
    pub(super) fn set_review(&mut self, review: String) {
        self.review = review;
    }
    pub(super) fn set_write(&mut self, value: bool) {
        self.write = value;
    }
    pub(super) fn set_revoked(&mut self, value: bool) {
        self.revoked = value;
    }
    pub(super) fn mutation_count(&self) -> usize {
        self.mutate_checks
    }
}

#[test]
fn actual_ingestion_resumes_exact_rank_windows_and_requires_independent_selection() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&[
        "alpha beta",
        "beta gamma",
        "alpha delta",
        "one two",
        "two three",
        "three four",
        "five six",
        "six seven",
        "eight nine",
    ]);
    for expected in [4, 8, 9] {
        let plan = plan(&store, &request, &mut sources, &mut guard);
        let mutation = effect(&plan);
        guard.review = mutation.review_sha256.clone();
        let prepared = prepare_ingestion(&store, &plan, &mutation, &mut guard).unwrap();
        assert!(prepared.acknowledge_selected(&mut guard).is_err());
        let mutations = guard.mutate_checks;
        guard.write = false;
        verify_ingestion_data(&store, prepared.commitment(), &mut sources, &mut guard).unwrap();
        assert_eq!(guard.mutate_checks, mutations);
        guard.selected = Some(prepared.commitment.next.clone());
        prepared.acknowledge_selected(&mut guard).unwrap();
        assert_eq!(
            guard.selected.as_ref().unwrap().cursor.after_count(),
            expected
        );
        guard.write = true;
    }
    let final_progress = guard.selected.clone().unwrap();
    assert!(final_progress.complete(&request).unwrap());
    assert_eq!(final_progress.windows, 3);
    assert_eq!(sources.calls, 18);
    assert!(plan_ingestion_window(
        &store,
        &request,
        &final_progress,
        4,
        limits(),
        &mut sources,
        &mut guard
    )
    .is_err());
}

#[test]
fn forged_progress_or_generation_and_cumulative_window_reset_are_refused() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&["alpha beta", "gamma"]);
    let base = guard.selected.clone().unwrap();
    let mut foreign = base.clone();
    foreign.request_sha256 = "9".repeat(64);
    assert!(plan_ingestion_window(
        &store,
        &request,
        &foreign,
        4,
        limits(),
        &mut sources,
        &mut guard
    )
    .is_err());
    guard.changed_builder = true;
    assert!(plan_ingestion_window(
        &store,
        &request,
        &base,
        4,
        limits(),
        &mut sources,
        &mut guard
    )
    .is_err());
    guard.changed_builder = false;
    let mut tiny = request.clone();
    tiny.limits.read_bytes = 1024;
    let progress = IngestProgress::beginning(&tiny).unwrap();
    guard.request = Some(tiny.clone());
    guard.selected = Some(progress.clone());
    assert!(plan_ingestion_window(
        &store,
        &tiny,
        &progress,
        4,
        limits(),
        &mut sources,
        &mut guard
    )
    .is_err());
    assert_eq!(sources.calls, 0);
}

#[test]
fn independent_replay_refuses_rehashed_false_run_and_changed_exact_source() {
    let (_fixture, store, request, mut sources, mut guard) =
        setup(&["alpha alpha beta", "gamma delta"]);
    let plan = plan(&store, &request, &mut sources, &mut guard);
    let mutation = effect(&plan);
    guard.review = mutation.review_sha256.clone();
    prepare_ingestion(&store, &plan, &mutation, &mut guard).unwrap();
    let mut forged = plan.commitment.clone();
    forged.next.last_run.as_mut().unwrap().sha256 = "8".repeat(64);
    forged.review_sha256 = forged.review().unwrap();
    guard.write = false;
    assert!(verify_ingestion_data(&store, &forged, &mut sources, &mut guard).is_err());
    sources.changed = true;
    assert!(verify_ingestion_data(&store, &plan.commitment, &mut sources, &mut guard).is_err());
}

#[test]
fn exhausted_real_write_admission_retains_partial_pages_without_progress_or_retry_success() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&["alpha beta gamma"]);
    let plan = plan(&store, &request, &mut sources, &mut guard);
    let mutation = effect(&plan);
    guard.review = mutation.review_sha256.clone();
    let before = store
        .inventory(read_budget(), &mut guard, |_| Ok(()))
        .unwrap();
    guard.stop_after_write_admissions = Some(1);
    assert!(prepare_ingestion(&store, &plan, &mutation, &mut guard).is_err());
    assert_eq!(guard.selected.as_ref(), Some(&plan.commitment.base));
    guard.write = false;
    let after = store
        .inventory(read_budget(), &mut guard, |_| Ok(()))
        .unwrap();
    assert!(after.regular_files > before.regular_files);
    assert!(verify_ingestion_data(&store, &plan.commitment, &mut sources, &mut guard).is_err());
    assert_eq!(guard.allocation_checks, 0);
}

#[test]
fn copied_plan_cannot_survive_revocation_or_substituted_reviewed_effect() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&["alpha beta"]);
    let plan = plan(&store, &request, &mut sources, &mut guard);
    let mut mutation = effect(&plan);
    guard.review = mutation.review_sha256.clone();
    mutation.source_bytes += 1;
    assert!(prepare_ingestion(&store, &plan, &mutation, &mut guard).is_err());
    mutation = effect(&plan);
    guard.revoked = true;
    assert!(prepare_ingestion(&store, &plan, &mutation, &mut guard).is_err());
    assert_eq!(guard.write_admissions, 0);
}

#[test]
fn empty_corpus_is_ingestion_complete_without_fabricated_completed_index() {
    let (_fixture, store, request, mut sources, mut guard) = setup(&[]);
    let base = guard.selected.clone().unwrap();
    assert!(base.complete(&request).unwrap());
    assert!(plan_ingestion_window(
        &store,
        &request,
        &base,
        1,
        limits(),
        &mut sources,
        &mut guard
    )
    .is_err());
    assert!(guard
        .current_index_generation(&request.corpus, &"1".repeat(64))
        .is_err());
    assert_eq!(sources.calls, 0);
}

#[test]
fn observed_cache_refuses_actual_tamper_replacement_missing_and_revocation() {
    let (fixture, store, request, ingested, mut guard) = completed_fixture(&["alpha beta gamma"]);
    let run = ingested.last_run.clone().unwrap();
    let mut cache = BTreeMap::new();
    let first = read_ingest_run_cached(
        &store,
        &request,
        &ingested,
        &run,
        0,
        1,
        read_budget(),
        &mut guard,
        &mut cache,
    );
    // The accessor's explicit4MiB maximum is a real per-call ceiling.
    assert!(first.is_err());
    assert!(cache.is_empty());
    let io = IoBudget {
        read_bytes: 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    };
    read_ingest_run_cached(
        &store, &request, &ingested, &run, 0, 1, io, &mut guard, &mut cache,
    )
    .unwrap();
    guard.set_revoked(true);
    assert!(read_ingest_run_cached(
        &store, &request, &ingested, &run, 0, 1, io, &mut guard, &mut cache
    )
    .is_err());
    assert!(cache.is_empty());
    guard.set_revoked(false);
    read_ingest_run_cached(
        &store, &request, &ingested, &run, 0, 1, io, &mut guard, &mut cache,
    )
    .unwrap();
    let path = fixture.object(&run.sha256);
    let bytes = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    fs::write(&path, &changed).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(read_ingest_run_cached(
        &store, &request, &ingested, &run, 0, 1, io, &mut guard, &mut cache
    )
    .is_err());
    assert!(cache.is_empty());
    fs::remove_file(&path).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let (_, pin) = store
        .read_page_observed(&run.sha256, io, &mut guard)
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store.check_page_observation(&pin, io, &mut guard).is_err());
    let (_, pin) = store
        .read_page_observed(&run.sha256, io, &mut guard)
        .unwrap();
    fs::remove_file(&path).unwrap();
    assert!(store.check_page_observation(&pin, io, &mut guard).is_err());
}

#[test]
fn observed_pin_refuses_another_owner_namespace_before_cache_use() {
    let (_f, store, request, ingested, mut guard) = completed_fixture(&["alpha"]);
    let hash = &ingested.last_run.unwrap().sha256;
    let (_, pin) = store
        .read_page_observed(hash, read_budget(), &mut guard)
        .unwrap();
    let fixture = Fixture::new();
    let mut other = owner();
    other.owner = "8".repeat(64);
    let empty = MapRoot::empty(&other, MapKind::Corpus).unwrap();
    let mut other_guard = Guard::seed(&empty);
    let other_store = ObjectStore::create_at(
        &fixture.path,
        &other,
        budget(),
        &seed_mutation(),
        &mut other_guard,
    )
    .unwrap();
    assert!(other_store
        .check_page_observation(&pin, read_budget(), &mut other_guard)
        .is_err());
    assert_eq!(request.corpus.binding, owner());
}

#[test]
fn public_delta_verifier_reopens_old_only_split_sibling_and_never_writes() {
    let (fixture, store, request, _ingested, mut guard) =
        completed_fixture(&["a", "b", "c", "d", "e", "f", "g", "h"]);
    let key = format!("{}1", "0".repeat(63));
    assert!(key < request.corpus.page.as_ref().unwrap().first_key);
    let edits = vec![MapEdit {
        key: key.clone(),
        expected_value_sha256: None,
        value: Some(vec![7]),
    }];
    let mutation = seed_mutation();
    guard.set_review(mutation.review_sha256.clone());
    let next = store
        .prepare_map(&request.corpus, &edits, budget(), &mutation, &mut guard)
        .unwrap();
    guard.set_write(false);
    let before = guard.mutation_count();
    assert_eq!(
        store
            .verify_map_delta(&request.corpus, &edits, read_budget(), &mut guard)
            .unwrap(),
        next
    );
    assert_eq!(before, guard.mutation_count());
    assert!(store
        .verify_map_delta(&request.corpus, &edits, budget(), &mut guard)
        .is_err());
    let root = next.page.as_ref().unwrap();
    assert_ne!(root.height, 0);
    let bytes = store
        .read_page(&root.sha256, read_budget(), &mut guard)
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sibling = page["body"]["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|child| {
            let first = child["first_key"].as_str().unwrap();
            let last = child["last_key"].as_str().unwrap();
            key.as_str() < first || key.as_str() > last
        })
        .unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    fs::remove_file(fixture.object(&sibling)).unwrap();
    assert!(store
        .verify_map_delta(&request.corpus, &edits, read_budget(), &mut guard)
        .is_err());
}

#[test]
fn opt_in_page_measurements_observe_real_allocations_under_original_reserve() {
    let (_fixture, store, _request, _ingested, mut guard) = completed_fixture(&["alpha"]);
    let mutation = seed_mutation();
    guard.set_review(mutation.review_sha256.clone());
    let finite = IoBudget {
        read_bytes: 64 * 1024,
        write_bytes: 128 * 1024,
        new_files: 3,
    };
    let bytes = vec![31_u8; 1024];
    let value = store
        .prepare_page_measured(&bytes, finite, &mutation, 128 * 1024, &mut guard)
        .unwrap();
    assert_eq!(value.sha256, luma_content::sha256(&bytes));
    assert_eq!(value.logical_written_bytes, bytes.len() as u64);
    assert!(value.read_bytes <= finite.read_bytes && value.new_inodes <= finite.new_files);
    assert_eq!(value.allocation.regular_files, 1);
    assert!(
        value.allocation.allocated_bytes >= 4096
            && value.allocation.allocated_bytes <= finite.write_bytes
    );
    let reused = store
        .prepare_page_measured(&bytes, finite, &mutation, 1, &mut guard)
        .unwrap();
    assert_eq!(reused.allocation, crate::v2::PhysicalInventory::default());
    let before = store
        .inventory(read_budget(), &mut guard, |_| Ok(()))
        .unwrap();
    assert!(store
        .prepare_page_measured(&vec![32_u8; 1024], finite, &mutation, 1, &mut guard)
        .is_err());
    let after = store
        .inventory(read_budget(), &mut guard, |_| Ok(()))
        .unwrap();
    assert!(after.regular_files > before.regular_files);
    assert!(store
        .prepare_page_measured(
            &bytes,
            finite,
            &mutation,
            finite.write_bytes + 1,
            &mut guard
        )
        .is_err());
}
