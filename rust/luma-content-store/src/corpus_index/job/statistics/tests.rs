//! Actual immutable-store and algorithm fixtures. Synthetic boundary callbacks
//! do not qualify installed C, PAM, physical allocation custody or NF08 timing.
use super::super::tests as fixture;
use super::*;

struct Guard {
    inner: fixture::Guard,
    request: StatisticsRequest,
    selected: StatisticsProgress,
    allocation_checks: usize,
    deny_allocations: bool,
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
    fn current_index_generation(&mut self, root: &MapRoot, hash: &str) -> Result<()> {
        self.inner.current_index_generation(root, hash)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.inner.current_candidate(root, record)
    }
}
impl CorpusIndexJobBoundary for Guard {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()> {
        self.inner.current_job(request, progress)
    }
    fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()> {
        self.inner.verify_ingest_allocations(value)
    }
}
impl StatisticsBoundary for Guard {
    fn current_statistics(
        &mut self,
        request: &StatisticsRequest,
        progress: &StatisticsProgress,
    ) -> Result<()> {
        if request != &self.request || progress != &self.selected {
            return Err("fixture selected statistics progress differs".into());
        }
        Ok(())
    }
    fn verify_statistics_allocations(&mut self, value: &StatisticsCommitment) -> Result<()> {
        self.current_statistics(&value.request, &value.base)?;
        if self.deny_allocations {
            return Err("fixture actual allocation witness refused".into());
        }
        self.allocation_checks += 1;
        Ok(())
    }
}
fn setup(texts: &[&str]) -> (fixture::Fixture, ObjectStore, Guard) {
    let (fixture, store, ingestion, ingested, inner) = fixture::completed_fixture(texts);
    let request = StatisticsRequest {
        schema_version: 1,
        ingestion,
        ingested,
    };
    let selected = StatisticsProgress::beginning(&request).unwrap();
    (
        fixture,
        store,
        Guard {
            inner,
            request,
            selected,
            allocation_checks: 0,
            deny_allocations: false,
        },
    )
}
fn plan(store: &ObjectStore, b: &mut Guard) -> StatisticsPlan {
    plan_statistics_window(
        store,
        &b.request.clone(),
        &b.selected.clone(),
        MAX_WINDOW_READ,
        MAX_WINDOW_WRITE,
        b,
    )
    .unwrap()
}
fn effect(plan: &StatisticsPlan) -> Mutation {
    Mutation {
        review_sha256: plan.commitment.review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    }
}
fn advance(store: &ObjectStore, b: &mut Guard) -> StatisticsCommitment {
    let plan = plan(store, b);
    let effect = effect(&plan);
    b.inner.set_review(effect.review_sha256.clone());
    let prepared = prepare_statistics(store, &plan, &effect, b).unwrap();
    assert!(prepared.acknowledge_selected(b).is_err());
    let mutations = b.inner.mutation_count();
    b.inner.set_write(false);
    verify_statistics_data(store, prepared.commitment(), b).unwrap();
    assert_eq!(b.inner.mutation_count(), mutations);
    b.selected = prepared.commitment.next.clone();
    prepared.acknowledge_selected(b).unwrap();
    b.inner.set_write(true);
    prepared.commitment.clone()
}
fn complete(store: &ObjectStore, b: &mut Guard) -> StatisticsCommitment {
    let mut last = None;
    for _ in 0..512 {
        if b.selected.complete {
            return last.unwrap();
        }
        last = Some(advance(store, b));
    }
    panic!("fixture did not complete bounded statistics phases");
}

#[test]
fn actual_sixteen_way_merge_resumes_multiple_output_windows_and_computes_df() {
    let text = (0..80)
        .map(|i| format!("term{i:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let texts: Vec<&str> = (0..65).map(|_| text.as_str()).collect();
    let (_fixture, store, mut b) = setup(&texts);
    let original = b.selected.totals;
    let mut saw_sixteen = false;
    let mut saw_partial = false;
    for _ in 0..128 {
        if b.selected.complete {
            break;
        }
        advance(&store, &mut b);
        if let Some(merge) = &b.selected.merging {
            saw_sixteen |= merge.inputs.len() == 16;
            saw_partial |= merge.output_records >= OUTPUT_RECORDS as u64;
        }
    }
    assert!(b.selected.complete);
    assert!(saw_sixteen);
    assert!(saw_partial);
    let result = read_statistics_result(&b.request.clone(), &b.selected.clone(), &mut b).unwrap();
    assert_eq!(result.vocabulary, 80);
    assert_eq!(result.features.len(), 80);
    assert!(result.features.iter().all(|value| value.documents == 65));
    assert_eq!(result.totals.postings, 5200);
    assert_eq!(result.totals.source_bytes, original.source_bytes);
    assert!(result.totals.read_bytes > original.read_bytes);
    assert!(result.totals.write_bytes > original.write_bytes);
    assert_eq!(b.selected.collected_runs, 17);
    assert!(plan_statistics_window(
        &store,
        &b.request.clone(),
        &b.selected.clone(),
        MAX_WINDOW_READ,
        MAX_WINDOW_WRITE,
        &mut b
    )
    .is_err());
}

#[test]
fn leaf_probe_seeks_match_exact_rank_bounds_with_fewer_measured_reads() {
    use selected::SelectedPostingReader;
    let text = (0..80)
        .map(|i| format!("term{i:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let texts: Vec<&str> = (0..65).map(|_| text.as_str()).collect();
    let (_fixture, store, mut b) = setup(&texts);
    complete(&store, &mut b);
    let (request, selected) = (b.request.clone(), b.selected.clone());
    let mut reader =
        SelectedPostingReader::open(&store, &request, &selected, 512 * 1024 * 1024, &mut b)
            .unwrap();
    let mut all = Vec::new();
    while (all.len() as u64) < reader.count() {
        all.extend(reader.range(all.len() as u64, 4096).unwrap());
    }
    // 5200 rows span many 96-row leaves under a multi-level merged tree.
    assert_eq!(all.len(), 5200);
    let mut terms: Vec<String> = (0..80).map(|i| format!("term{i:04}")).collect();
    terms.push("notpresent".into());
    let (mut leaf_probe, mut rank_probe) = (0, 0);
    for term in &terms {
        for document in [0, 1, 32, 64, 65, u32::MAX] {
            let target = (bucket(term), term.clone(), document);
            let expected = all.iter().filter(|row| posting_key(row) < target).count() as u64;
            let before = reader.read_bytes();
            assert_eq!(reader.lower_bound(term, document).unwrap(), expected);
            let after = reader.read_bytes();
            leaf_probe += after - before;
            // The former seek: a full root descent for every single-rank
            // probe, followed by the same adjacent-boundary proof.
            let (mut low, mut high) = (0, reader.count());
            while low < high {
                let middle = low + (high - low) / 2;
                let row = reader.range(middle, 1).unwrap().pop().unwrap();
                if posting_key(&row) < target {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            assert_eq!(low, expected);
            if low != 0 {
                reader.range(low - 1, 1).unwrap();
            }
            if low < reader.count() {
                reader.range(low, 1).unwrap();
            }
            rank_probe += reader.read_bytes() - after;
        }
    }
    eprintln!("seek measured reads: leaf probe {leaf_probe}, rank probe {rank_probe}");
    assert!(leaf_probe < rank_probe);
}

#[test]
fn df_counts_documents_not_term_frequency_and_top512_ties_match_existing_profile() {
    let text = (0..700)
        .map(|i| format!("term{i:04} term{i:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let (_fixture, store, mut b) = setup(&[text.as_str(), "term0000 term0000"]);
    complete(&store, &mut b);
    let result = read_statistics_result(&b.request.clone(), &b.selected.clone(), &mut b).unwrap();
    assert_eq!(result.vocabulary, 700);
    assert_eq!(result.features.len(), 512);
    assert_eq!(
        result.features[0],
        DocumentFrequency {
            term: "term0000".into(),
            documents: 2
        }
    );
    assert_eq!(result.features.last().unwrap().term, "term0511");
    assert!(result.features[1..]
        .iter()
        .all(|value| value.documents == 1));
}

#[test]
fn independently_rehashed_false_frequency_result_cannot_be_selected() {
    let (_fixture, store, mut b) = setup(&["alpha beta", "alpha beta", "alpha beta"]);
    let last = complete(&store, &mut b);
    b.selected = last.base.clone();
    let mut forged = last.clone();
    forged.next.frequencies.as_mut().unwrap().top[0].documents -= 1;
    forged.review_sha256 = forged.review().unwrap();
    forged.canonical_bytes().unwrap();
    b.inner.set_write(false);
    assert!(verify_statistics_data(&store, &forged, &mut b).is_err());
    assert_eq!(b.selected, last.base);
}

#[test]
fn source_selection_revocation_and_allocation_failure_withhold_progress() {
    let (_fixture, store, mut b) = setup(&["alpha beta", "gamma delta"]);
    let initial = b.selected.clone();
    let planned = plan(&store, &mut b);
    let effect = effect(&planned);
    b.inner.set_review(effect.review_sha256.clone());
    b.inner.set_revoked(true);
    assert!(prepare_statistics(&store, &planned, &effect, &mut b).is_err());
    b.inner.set_revoked(false);
    b.deny_allocations = true;
    assert!(prepare_statistics(&store, &planned, &effect, &mut b).is_err());
    assert_eq!(b.selected, initial);
    b.deny_allocations = false;
    let mut changed = b.request.clone();
    changed.ingestion.job_sha256 = "9".repeat(64);
    assert!(plan_statistics_window(
        &store,
        &changed,
        &initial,
        MAX_WINDOW_READ,
        MAX_WINDOW_WRITE,
        &mut b
    )
    .is_err());
}

#[test]
fn cumulative_limits_cannot_restart_after_a_new_statistics_window() {
    let (_fixture, store, mut b) = setup(&["alpha beta"]);
    b.selected.totals.read_bytes = b.request.ingestion.limits.read_bytes - 1024;
    let before = b.selected.clone();
    assert!(plan_statistics_window(
        &store,
        &b.request.clone(),
        &before,
        MAX_WINDOW_READ,
        MAX_WINDOW_WRITE,
        &mut b
    )
    .is_err());
    assert_eq!(b.selected, before);
}

#[test]
fn empty_or_wordless_corpora_finish_statistics_without_claiming_an_index() {
    let (_fixture, store, mut empty) = setup(&[]);
    assert!(empty.selected.complete);
    let result =
        read_statistics_result(&empty.request.clone(), &empty.selected.clone(), &mut empty)
            .unwrap();
    assert_eq!(result.vocabulary, 0);
    assert!(result.features.is_empty());
    assert!(result.sorted_stream.is_none());
    let (_fixture, store2, mut b) = setup(&["", "--- ___"]);
    complete(&store2, &mut b);
    let result = read_statistics_result(&b.request.clone(), &b.selected.clone(), &mut b).unwrap();
    assert_eq!(result.vocabulary, 0);
    assert!(result.features.is_empty());
    assert!(result.sorted_stream.is_some());
    assert!(b
        .current_index_generation(&b.request.ingestion.corpus.clone(), &"1".repeat(64))
        .is_err());
    drop(store);
}
