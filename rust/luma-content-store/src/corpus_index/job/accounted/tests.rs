//! Real private-object writes/replay with explicitly synthetic reservation and
//! selection callbacks. These do not qualify native C or its allocation witness.
use super::super::statistics::accounted as stats;
use super::super::statistics::{self, StatisticsBoundary, StatisticsProgress, StatisticsRequest};
use super::super::tests as fixture;
use super::*;

struct Guard {
    inner: fixture::Guard,
    request: IngestRequest,
    selected: IngestProgress,
    statistics: Option<(StatisticsRequest, StatisticsProgress)>,
    held: Option<PageReserve>,
    observed: Option<PageDebitCommitment>,
    releases: usize,
    release_error: bool,
    reserve_error: bool,
    observation_error: bool,
}
impl Boundary for Guard {
    fn admit(&mut self, owner: &luma_content::OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.inner.admit(owner, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.inner.check(access)
    }
}
impl CorpusIndexBoundary for Guard {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        self.inner.current_corpus(root)
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        self.inner.current_builder(root, builder)
    }
    fn current_index_generation(&mut self, root: &MapRoot, value: &str) -> Result<()> {
        self.inner.current_index_generation(root, value)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.inner.current_candidate(root, record)
    }
}
impl CorpusIndexJobBoundary for Guard {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()> {
        self.check(Access::Inspect {
            binding: &request.corpus.binding,
        })?;
        if request != &self.request || progress != &self.selected {
            return Err("synthetic fixture independently selected ingestion differs".into());
        }
        Ok(())
    }
    fn verify_ingest_allocations(&mut self, _: &IngestCommitment) -> Result<()> {
        Err("measured fixture must not borrow legacy allocation approval".into())
    }
}
impl StatisticsBoundary for Guard {
    fn current_statistics(
        &mut self,
        request: &StatisticsRequest,
        progress: &StatisticsProgress,
    ) -> Result<()> {
        self.current_job(&request.ingestion, &request.ingested)?;
        if self.statistics.as_ref() != Some(&(request.clone(), progress.clone())) {
            return Err("synthetic fixture independently selected statistics differs".into());
        }
        Ok(())
    }
    fn verify_statistics_allocations(
        &mut self,
        _: &statistics::StatisticsCommitment,
    ) -> Result<()> {
        Err("measured fixture must not borrow legacy statistics allocation approval".into())
    }
}
impl PageAccountingBoundary for Guard {
    fn reserve_pages(&mut self, reserve: &PageReserve) -> Result<()> {
        reserve.canonical_bytes()?;
        mutation_check(self, reserve)?;
        if self.held.is_some() || self.reserve_error {
            return Err("synthetic durable reservation refuses duplicate/unknown attempt".into());
        }
        self.held = Some(reserve.clone());
        Ok(())
    }
    fn observe_pages(
        &mut self,
        value: &PageDebitCommitment,
        captured: &CapturedPageMeasurements,
    ) -> Result<()> {
        value.canonical_bytes()?;
        mutation_check(self, &value.reserve)?;
        if self.held.as_ref() != Some(&value.reserve)
            || self.observed.is_some()
            || captured.reserve_sha256() != luma_content::sha256(&value.reserve.canonical_bytes()?)
            || captured.pages() != value.pages.as_slice()
            || self.observation_error
        {
            return Err("synthetic actual-writer measurement observation refused".into());
        }
        self.observed = Some(value.clone());
        Ok(())
    }
    fn verify_pages(&mut self, value: &PageDebitCommitment) -> Result<()> {
        self.check(Access::Inspect {
            binding: &value.reserve.binding,
        })?;
        if self.held.as_ref() != Some(&value.reserve) || self.observed.as_ref() != Some(value) {
            return Err(
                "candidate JSON is not a previously captured actual-writer observation".into(),
            );
        }
        Ok(())
    }
    fn release_pages_after_selection(&mut self, value: &PageDebitCommitment) -> Result<()> {
        self.verify_pages(value)?;
        self.releases += 1;
        if self.release_error {
            return Err("synthetic uncertain release dispatch".into());
        }
        self.held = None;
        self.observed = None;
        Ok(())
    }
}
struct Content {
    values: BTreeMap<String, Vec<u8>>,
}
impl CorpusContent for Content {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        b: &mut B,
    ) -> Result<Vec<u8>> {
        b.check(Access::Inspect {
            binding: &record_owner(),
        })?;
        self.values
            .get(&record.reference.content_sha256)
            .cloned()
            .ok_or_else(|| "fixture content absent".into())
    }
}
fn record_owner() -> luma_content::OwnerBinding {
    luma_content::OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    }
}
fn setup(texts: &[&str], start_again: bool) -> (fixture::Fixture, ObjectStore, Guard, Content) {
    let (fixture, store, mut request, old, inner) = fixture::completed_fixture(texts);
    let selected = if start_again {
        request.job_sha256 = "9".repeat(64);
        IngestProgress::beginning(&request).unwrap()
    } else {
        old
    };
    let content = Content {
        values: texts
            .iter()
            .map(|text| {
                (
                    luma_content::sha256(text.as_bytes()),
                    text.as_bytes().to_vec(),
                )
            })
            .collect(),
    };
    (
        fixture,
        store,
        Guard {
            inner,
            request,
            selected,
            statistics: None,
            held: None,
            observed: None,
            releases: 0,
            release_error: false,
            reserve_error: false,
            observation_error: false,
        },
        content,
    )
}
fn ingest_plan(store: &ObjectStore, b: &mut Guard, content: &mut Content) -> AccountedIngestPlan {
    let plan = plan_ingestion_window(
        store,
        &b.request.clone(),
        &b.selected.clone(),
        MAX_INGEST_DOCUMENTS,
        CorpusIndexLimits {
            read_bytes: 64 * 1024 * 1024,
            write_bytes: 16 * 1024 * 1024,
            source_bytes: 4 * 1024 * 1024,
            postings: 65536,
            floating_operations: 100_000_000,
        },
        content,
        b,
    )
    .unwrap();
    account_ingestion_plan(plan).unwrap()
}
fn effect(reserve: &PageReserve, b: &mut Guard) -> Mutation {
    b.inner.set_write(true);
    b.inner.set_review(reserve.review_sha256.clone());
    Mutation {
        review_sha256: reserve.review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: reserve.source_bytes,
    }
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}

#[test]
fn actual_ingestion_debits_keep_original_reserve_until_exact_selection_and_single_ack() {
    let (_fixture, store, mut b, mut content) = setup(&["alpha beta alpha", "beta gamma"], true);
    let plan = ingest_plan(&store, &mut b, &mut content);
    let original = plan.semantic().clone();
    let mutation = effect(plan.reserve(), &mut b);
    let prepared = prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).unwrap();
    let value = prepared.commitment();
    assert_eq!(value.semantic, original);
    assert_eq!(
        value.accounting.reserve.maximum_storage_bytes,
        original.next.totals.write_bytes
    );
    assert!(value.accounting.actual_storage_bytes > 0);
    assert!(value.accounting.actual_storage_bytes < value.accounting.reserve.maximum_storage_bytes);
    assert_eq!(
        value.next.totals.read_bytes,
        original.next.totals.read_bytes
    );
    assert_eq!(
        value.next.totals.write_bytes,
        value.accounting.actual_storage_bytes
    );
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    assert_eq!(b.releases, 0);
    let before = b.inner.mutation_count();
    b.inner.set_write(false);
    verify_accounted_ingestion_data(&store, value, &mut content, &mut b).unwrap();
    assert_eq!(before, b.inner.mutation_count());
    assert!(b.held.is_some());
    b.selected = value.next.clone();
    prepared.acknowledge_selected(&mut b).unwrap();
    assert!(b.held.is_none());
    assert_eq!(b.releases, 1);
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    assert_eq!(b.releases, 1);
}

#[test]
fn reservation_refusal_precedes_any_private_write_and_error_retains_full_hold() {
    let (_fixture, store, mut b, mut content) = setup(&["alpha beta"], true);
    let plan = ingest_plan(&store, &mut b, &mut content);
    let mutation = effect(plan.reserve(), &mut b);
    let before = store.inventory(read_budget(), &mut b, |_| Ok(())).unwrap();
    b.reserve_error = true;
    assert!(prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).is_err());
    assert_eq!(
        before,
        store.inventory(read_budget(), &mut b, |_| Ok(())).unwrap()
    );
    assert!(b.held.is_none());
    b.reserve_error = false;
    b.observation_error = true;
    assert!(prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).is_err());
    assert!(b.held.is_some());
    let retained = store.inventory(read_budget(), &mut b, |_| Ok(())).unwrap();
    assert!(retained.regular_files > before.regular_files);
    assert!(prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).is_err());
    assert_eq!(
        retained,
        store.inventory(read_budget(), &mut b, |_| Ok(())).unwrap()
    );
    assert_eq!(b.releases, 0);
}

#[test]
fn rehashed_zero_debit_and_missing_pages_cannot_initialize_independent_observation() {
    let (fixture, store, mut b, mut content) = setup(&["one two three"], true);
    let plan = ingest_plan(&store, &mut b, &mut content);
    let mutation = effect(plan.reserve(), &mut b);
    let prepared = prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).unwrap();
    let mut forged = prepared.commitment().clone();
    for page in &mut forged.accounting.pages {
        page.logical_written_bytes = 0;
        page.logical_allocated_bytes = 0;
        page.regular_files = 0;
        page.directories = 0;
        page.allocated_bytes = 0;
    }
    forged.accounting.actual_storage_bytes = 0;
    forged.next.totals.write_bytes = forged.semantic.base.totals.write_bytes;
    forged.canonical_bytes().unwrap();
    b.inner.set_write(false);
    assert!(verify_accounted_ingestion_data(&store, &forged, &mut content, &mut b).is_err());
    let hash = &prepared.commitment().accounting.pages[0].sha256;
    let namespace = std::fs::read_dir(&fixture.path)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(
        namespace
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash),
    )
    .unwrap();
    assert!(
        verify_accounted_ingestion_data(&store, prepared.commitment(), &mut content, &mut b)
            .is_err()
    );
    assert!(b.held.is_some());
}

#[test]
fn revoked_drop_and_uncertain_release_never_automatically_free_or_retry() {
    let (_fixture, store, mut b, mut content) = setup(&["alpha"], true);
    let plan = ingest_plan(&store, &mut b, &mut content);
    let mutation = effect(plan.reserve(), &mut b);
    let prepared = prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).unwrap();
    b.selected = prepared.commitment().next.clone();
    b.inner.set_revoked(true);
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    assert_eq!(b.releases, 0);
    assert!(b.held.is_some());
    b.inner.set_revoked(false);
    b.release_error = true;
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    assert_eq!(b.releases, 1);
    b.release_error = false;
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    assert_eq!(b.releases, 1);
    drop(prepared);
    assert!(b.held.is_some());
}

#[test]
fn accounted_statistics_replays_all_phases_with_exact_functional_progress_and_lower_actual_debit() {
    let (_fixture, store, mut b, _content) = setup(
        &["alpha beta", "beta gamma", "alpha", "beta", "gamma"],
        false,
    );
    let request = StatisticsRequest {
        schema_version: 1,
        ingestion: b.request.clone(),
        ingested: b.selected.clone(),
    };
    b.statistics = Some((
        request.clone(),
        StatisticsProgress::beginning(&request).unwrap(),
    ));
    let initial = b.statistics.as_ref().unwrap().1.totals;
    let mut conservative_sum = 0_u64;
    for _ in 0..32 {
        let base = b.statistics.as_ref().unwrap().1.clone();
        if base.complete {
            break;
        }
        let plan = statistics::plan_statistics_window(
            &store,
            &request,
            &base,
            64 * 1024 * 1024,
            16 * 1024 * 1024,
            &mut b,
        )
        .unwrap();
        let old = plan.commitment().clone();
        let plan = stats::account_statistics_plan(plan).unwrap();
        conservative_sum += plan.reserve().maximum_storage_bytes;
        let mutation = effect(plan.reserve(), &mut b);
        let prepared =
            stats::prepare_accounted_statistics(&store, &plan, &mutation, &mut b).unwrap();
        assert_eq!(prepared.commitment().semantic, old);
        let before = b.inner.mutation_count();
        b.inner.set_write(false);
        stats::verify_accounted_statistics_data(&store, prepared.commitment(), &mut b).unwrap();
        assert_eq!(before, b.inner.mutation_count());
        assert!(prepared.acknowledge_selected(&mut b).is_err());
        b.statistics = Some((request.clone(), prepared.commitment().next.clone()));
        prepared.acknowledge_selected(&mut b).unwrap();
    }
    let selected = b.statistics.as_ref().unwrap().1.clone();
    assert!(selected.complete);
    let result = statistics::read_statistics_result(&request, &selected, &mut b).unwrap();
    assert_eq!(result.features.len(), 3);
    assert!(
        result
            .features
            .iter()
            .find(|entry| entry.term == "alpha")
            .unwrap()
            .documents
            == 2
    );
    assert!(conservative_sum > 0);
    assert!(selected.totals.write_bytes - initial.write_bytes < conservative_sum);
    assert_eq!(selected.totals.postings, initial.postings);
    assert!(b.held.is_none());
}

#[test]
fn actual_accounting_validation_rejects_substituted_totals_and_finite_debit_overflow() {
    let (_fixture, store, mut b, mut content) = setup(&["alpha beta"], true);
    let plan = ingest_plan(&store, &mut b, &mut content);
    let mutation = effect(plan.reserve(), &mut b);
    let prepared = prepare_accounted_ingestion(&store, &plan, &mutation, &mut b).unwrap();
    let mut bad = prepared.commitment().clone();
    bad.accounting.pages[0].allocated_bytes = PAGE_WRITE;
    assert!(bad.canonical_bytes().is_err());
    bad = prepared.commitment().clone();
    bad.accounting.reserve.maximum_storage_bytes += 1;
    assert!(bad.canonical_bytes().is_err());
    bad = prepared.commitment().clone();
    bad.next.totals.read_bytes += 1;
    assert!(bad.canonical_bytes().is_err());
}
