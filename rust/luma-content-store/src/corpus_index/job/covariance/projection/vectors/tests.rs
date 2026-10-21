//! Actual full-pipeline and private-store vector fixtures with synthetic
//! selection/allocation callbacks, not native publication or NF08 evidence.
use super::super::tests as fixture;
use super::*;

pub(super) struct Guard {
    pub(super) inner: fixture::Guard,
    pub(super) request: VectorRequest,
    pub(super) selected: VectorProgress,
    deny_allocations: bool,
    deny_candidate: bool,
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
    fn current_index_generation(&mut self, root: &MapRoot, digest: &str) -> Result<()> {
        self.inner.current_index_generation(root, digest)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        if self.deny_candidate {
            return Err("fixture selected source lifecycle/ref changed".into());
        }
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
        self.inner.current_statistics(request, progress)
    }
    fn verify_statistics_allocations(
        &mut self,
        value: &crate::corpus_index::job::statistics::StatisticsCommitment,
    ) -> Result<()> {
        self.inner.verify_statistics_allocations(value)
    }
}
impl CovarianceBoundary for Guard {
    fn current_covariance(
        &mut self,
        request: &CovarianceRequest,
        progress: &CovarianceProgress,
    ) -> Result<()> {
        self.inner.current_covariance(request, progress)
    }
    fn verify_covariance_allocations(&mut self, value: &CovarianceCommitment) -> Result<()> {
        self.inner.verify_covariance_allocations(value)
    }
}
impl ProjectionBoundary for Guard {
    fn current_projection(
        &mut self,
        request: &ProjectionRequest,
        progress: &ProjectionProgress,
    ) -> Result<()> {
        self.inner.current_projection(request, progress)
    }
    fn verify_projection_allocations(&mut self, value: &ProjectionCommitment) -> Result<()> {
        self.inner.verify_projection_allocations(value)
    }
}
impl VectorBoundary for Guard {
    fn current_vectors(
        &mut self,
        request: &VectorRequest,
        progress: &VectorProgress,
    ) -> Result<()> {
        if request != &self.request || progress != &self.selected {
            return Err("fixture independently selected vector phase differs".into());
        }
        self.inner.check(Access::Inspect {
            binding: &request.corpus().binding,
        })
    }
    fn verify_vector_allocations(&mut self, value: &VectorCommitment) -> Result<()> {
        self.current_vectors(&value.request, &value.base)?;
        if self.deny_allocations {
            return Err("fixture actual vector allocation witness refused".into());
        }
        Ok(())
    }
}
struct Sources {
    bytes: BTreeMap<String, Vec<u8>>,
    changed: bool,
}
impl CorpusContent for Sources {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        b: &mut B,
    ) -> Result<Vec<u8>> {
        b.check(Access::Inspect {
            binding: &luma_content::OwnerBinding {
                installation: "a".repeat(64),
                owner: "b".repeat(64),
                owner_generation: 7,
            },
        })?;
        let mut value = self
            .bytes
            .get(&record.reference.content_sha256)
            .cloned()
            .ok_or("fixture source absent")?;
        if self.changed {
            value.push(b'!');
        }
        Ok(value)
    }
}
fn setup(
    texts: &[&str],
) -> (
    crate::corpus_index::job::tests::Fixture,
    ObjectStore,
    Guard,
    Sources,
) {
    let (fixture, store, projection, selected_projection, inner) =
        fixture::completed_fixture(texts, 8);
    let request = VectorRequest {
        schema_version: 1,
        projection,
        selected_projection,
    };
    let selected = VectorProgress::beginning(&request).unwrap();
    let sources = Sources {
        bytes: texts
            .iter()
            .map(|text| {
                (
                    luma_content::sha256(text.as_bytes()),
                    text.as_bytes().to_vec(),
                )
            })
            .collect(),
        changed: false,
    };
    (
        fixture,
        store,
        Guard {
            inner,
            request,
            selected,
            deny_allocations: false,
            deny_candidate: false,
        },
        sources,
    )
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: MAX_VECTOR_READ,
        write_bytes: 0,
        new_files: 0,
    }
}
fn plan(store: &ObjectStore, sources: &mut Sources, b: &mut Guard, maximum: usize) -> VectorPlan {
    plan_vector_window(
        store,
        &b.request.clone(),
        &b.selected.clone(),
        maximum,
        MAX_VECTOR_READ,
        MAX_VECTOR_WRITE,
        sources,
        b,
    )
    .unwrap()
}
fn effect(value: &VectorCommitment, b: &mut Guard) -> Mutation {
    b.inner.inner.set_write(true);
    b.inner.inner.set_review(value.review_sha256.clone());
    Mutation {
        review_sha256: value.review_sha256.clone(),
        decision: crate::DecisionKind::Published,
        source_bytes: value.source_bytes,
    }
}
fn next(
    store: &ObjectStore,
    sources: &mut Sources,
    b: &mut Guard,
    maximum: usize,
) -> VectorCommitment {
    let plan = plan(store, sources, b, maximum);
    let mutation = effect(plan.commitment(), b);
    let exact_objects = plan.planned_objects(|| Ok(())).unwrap();
    let prepared = prepare_vectors(store, &plan, &mutation, b).unwrap();
    for object in exact_objects {
        let bytes = store
            .read_page(
                &object.sha256,
                IoBudget {
                    read_bytes: 32768,
                    write_bytes: 0,
                    new_files: 0,
                },
                b,
            )
            .unwrap();
        assert_eq!(bytes.len(), object.bytes as usize);
        assert_eq!(luma_content::sha256(&bytes), object.sha256);
    }
    assert!(prepared.acknowledge_selected(b).is_err());
    let before = b.inner.inner.mutation_count();
    b.inner.inner.set_write(false);
    verify_vectors_data(store, prepared.commitment(), sources, b).unwrap();
    assert_eq!(before, b.inner.inner.mutation_count());
    b.selected = prepared.commitment().next.clone();
    prepared.acknowledge_selected(b).unwrap();
    b.inner.inner.set_write(true);
    prepared.commitment().clone()
}
fn complete(store: &ObjectStore, sources: &mut Sources, b: &mut Guard, maximum: usize) {
    for _ in 0..128 {
        if b.selected.complete {
            return;
        }
        next(store, sources, b, maximum);
    }
    panic!("actual fixture vector windows did not complete");
}
pub(super) fn completed_fixture(
    texts: &[&str],
) -> (crate::corpus_index::job::tests::Fixture, ObjectStore, Guard) {
    let (fixture, store, mut guard, mut sources) = setup(texts);
    complete(&store, &mut sources, &mut guard, MAX_VECTOR_DOCUMENTS);
    (fixture, store, guard)
}

#[test]
fn actual_multiwindow_vectors_match_original_weights_project_and_normalize_bits() {
    let (_fixture, store, mut b, mut sources) = setup(&[
        "alpha alpha beta",
        "beta gamma",
        "alpha delta",
        "gamma delta",
        "alpha beta gamma delta",
    ]);
    let initial = b.selected.totals;
    complete(&store, &mut sources, &mut b, 2);
    let request = b.request.clone();
    let selected = b.selected.clone();
    let projection = read_projection_basis(
        &store,
        &request.projection,
        &request.selected_projection,
        read_budget(),
        &mut b,
    )
    .unwrap();
    let features = request.projection.covariance.features().unwrap();
    let idfs: Vec<_> = features
        .iter()
        .map(|(_, df)| crate::corpus_index::build::idf(request.corpus().entry_count, *df))
        .collect();
    for ordinal in 0..request.corpus().entry_count {
        let row = read_vector(
            &store,
            &request,
            &selected,
            ordinal as u32,
            read_budget(),
            &mut b,
        )
        .unwrap();
        let bytes = sources
            .bytes
            .get(&row.record.reference.content_sha256)
            .unwrap();
        let mut live = Current {
            request: &request,
            base: &selected,
            b: &mut b,
        };
        let mut meter = Meter::new(
            request.corpus(),
            &request.projection.covariance.statistics.ingestion.builder,
            CorpusIndexLimits {
                read_bytes: MAX_VECTOR_READ,
                write_bytes: 0,
                source_bytes: MAX_INDEX_SOURCE_BYTES,
                postings: 0,
                floating_operations: 100_000_000,
            },
            None,
            &mut live,
        )
        .unwrap();
        let tf = words(bytes, request.corpus(), &mut meter, &mut live).unwrap();
        let weights = crate::corpus_index::build::weights(&tf, &features, &idfs).unwrap();
        let expected = crate::corpus_index::build::project(
            &weights,
            &projection,
            usize::from(selected.dimensions.unwrap()),
        )
        .unwrap();
        assert_eq!(
            row.components,
            expected
                .iter()
                .map(|v| (*v as f32).to_bits())
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(b.selected.totals.postings, initial.postings);
    assert_eq!(b.selected.totals.source_bytes, initial.source_bytes);
    assert!(b.selected.totals.read_bytes > initial.read_bytes);
    assert!(b.current_index_generation(request.corpus(), "f").is_err());
}

#[test]
fn actual_277_document_frontier_crosses_32_way_boundary_and_authenticates_ordinal_lookup() {
    let texts = vec!["alpha"; 277];
    let (_fixture, store, mut b, mut sources) = setup(&texts);
    next(&store, &mut sources, &mut b, 128);
    assert_eq!(b.selected.coordinates.tail.len(), 128);
    assert!(b.selected.coordinates.root.is_none());
    next(&store, &mut sources, &mut b, 128);
    assert!(b.selected.coordinates.tail.is_empty());
    assert_eq!(b.selected.coordinates.frontier[0][0].count, 256);
    next(&store, &mut sources, &mut b, 128);
    assert_eq!(b.selected.cursor.after_count(), 277);
    assert!(b.selected.root.as_ref().unwrap().height >= 2);
    assert!(b.selected.frontier.is_empty());
    let request = b.request.clone();
    let selected = b.selected.clone();
    let coordinate_root = selected.coordinates.root.clone().unwrap();
    let mut live = Current {
        request: &request,
        base: &selected,
        b: &mut b,
    };
    let coordinates::ReadBody::Branch(children) =
        coordinates::read_node(&store, &request, 1, &coordinate_root, &mut live).unwrap()
    else {
        panic!("277 rows require two compact blocks")
    };
    assert_eq!(
        children.iter().map(|node| node.count).collect::<Vec<_>>(),
        vec![256, 21]
    );
    for child in children {
        let coordinates::ReadBody::Leaf(rows) =
            coordinates::read_node(&store, &request, 1, &child, &mut live).unwrap()
        else {
            panic!("compact child must be a binary block")
        };
        assert_eq!(rows.len(), child.count as usize);
        assert!(rows.iter().all(|row| *row == vec![1_f32.to_bits()]));
    }
    let mut blocks = 0;
    let scan = coordinates::visit_coordinate_blocks_checked(
        &store,
        &request,
        &selected,
        read_budget(),
        &mut b,
        |_, rows, _| {
            blocks += 1;
            assert!(rows.iter().all(|row| *row == vec![1_f32.to_bits()]));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(scan.rows, 277);
    assert_eq!(blocks, 2);
    assert_eq!(scan.read_bytes, 3 * RUN_PAGE_READ);
    let mut expected = Vec::new();
    store
        .visit_map(request.corpus(), read_budget(), &mut b, |_, value| {
            expected.push(serde_json::from_slice::<CorpusRecord>(value)?);
            Ok(())
        })
        .unwrap();
    for ordinal in [0_u32, 127, 255, 256, 276] {
        let row = read_vector(&store, &request, &selected, ordinal, read_budget(), &mut b).unwrap();
        assert_eq!(row.ordinal, ordinal);
        assert_eq!(row.record, expected[ordinal as usize]);
        assert_eq!(row.components, vec![1_f32.to_bits()]);
    }
    assert!(read_vector(&store, &request, &selected, 277, read_budget(), &mut b).is_err());
    assert!(read_vector(
        &store,
        &request,
        &selected,
        0,
        IoBudget {
            read_bytes: RUN_PAGE_READ - 1,
            write_bytes: 0,
            new_files: 0
        },
        &mut b
    )
    .is_err());
}

#[test]
fn independently_rehashed_wrong_vector_is_refused_even_with_real_immutable_page() {
    let (_fixture, store, mut b, mut sources) = setup(&["alpha", "alpha alpha"]);
    let plan = plan(&store, &mut sources, &mut b, 2);
    let mutation = effect(plan.commitment(), &mut b);
    let prepared = prepare_vectors(&store, &plan, &mutation, &mut b).unwrap();
    let mut bad = prepared.commitment().clone();
    let root = bad.next.root.clone().unwrap();
    let bytes = plan
        .pages
        .iter()
        .find(|(hash, _)| hash == &root.sha256)
        .unwrap()
        .1
        .clone();
    let mut page: Page = serde_json::from_slice(&bytes).unwrap();
    let Body::Leaf { rows, .. } = &mut page.body else {
        panic!("small fixture must be one vector leaf")
    };
    rows[0].components[0] = (-1_f32).to_bits();
    let bytes = serde_json::to_vec(&page).unwrap();
    let hash = store
        .prepare_page(
            &bytes,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 1024 * 1024,
                new_files: 3,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    bad.next.root = Some(page.node(&bad.request, 1, hash).unwrap());
    bad.review_sha256 = bad.review().unwrap();
    bad.canonical_bytes().unwrap();
    b.inner.inner.set_write(false);
    assert!(verify_vectors_data(&store, &bad, &mut sources, &mut b).is_err());
    verify_vectors_data(&store, prepared.commitment(), &mut sources, &mut b).unwrap();
}

#[test]
fn exact_source_and_current_candidate_are_required_during_build_and_each_read() {
    let (_fixture, store, mut b, mut sources) = setup(&["alpha beta", "gamma beta"]);
    let request = b.request.clone();
    let base = b.selected.clone();
    sources.changed = true;
    assert!(plan_vector_window(
        &store,
        &request,
        &base,
        2,
        MAX_VECTOR_READ,
        MAX_VECTOR_WRITE,
        &mut sources,
        &mut b
    )
    .is_err());
    sources.changed = false;
    complete(&store, &mut sources, &mut b, 1);
    let selected = b.selected.clone();
    b.deny_candidate = true;
    assert!(read_vector(&store, &request, &selected, 0, read_budget(), &mut b).is_err());
    b.deny_candidate = false;
    b.inner.inner.set_revoked(true);
    assert!(read_vector(&store, &request, &selected, 0, read_budget(), &mut b).is_err());
}

#[test]
fn allocation_stale_progress_missing_page_and_cumulative_exhaustion_fail_closed() {
    let (fixture, store, mut b, mut sources) = setup(&["alpha beta", "beta gamma"]);
    let plan = plan(&store, &mut sources, &mut b, 1);
    let mutation = effect(plan.commitment(), &mut b);
    b.deny_allocations = true;
    assert!(prepare_vectors(&store, &plan, &mutation, &mut b).is_err());
    b.deny_allocations = false;
    let prepared = prepare_vectors(&store, &plan, &mutation, &mut b).unwrap();
    b.selected = prepared.commitment().next.clone();
    assert!(verify_vectors_data(&store, prepared.commitment(), &mut sources, &mut b).is_err());
    complete(&store, &mut sources, &mut b, 1);
    let request = b.request.clone();
    let selected = b.selected.clone();
    let hash = selected.root.as_ref().unwrap().sha256.clone();
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
            .join(&hash),
    )
    .unwrap();
    assert!(read_vector(&store, &request, &selected, 0, read_budget(), &mut b).is_err());
    let mut exhausted = VectorProgress::beginning(&request).unwrap();
    // Initialized unfinished progress can legitimately carry accumulated finite
    // counters; exhaustion remains subject to the independently selected cut.
    exhausted.dimensions = Some(selected.dimensions.unwrap());
    exhausted.totals.read_bytes = request.limits().read_bytes;
    b.selected = exhausted.clone();
    assert!(plan_vector_window(
        &store,
        &request,
        &exhausted,
        1,
        1,
        MAX_VECTOR_WRITE,
        &mut sources,
        &mut b
    )
    .is_err());
}

#[test]
fn empty_and_wordless_corpora_complete_explicit_zero_vectors_without_index_authority() {
    for texts in [&[][..], &["!!!", ""][..]] {
        let (_fixture, store, mut b, mut sources) = setup(texts);
        complete(&store, &mut sources, &mut b, 1);
        assert_eq!(b.selected.dimensions, Some(0));
        assert_eq!(b.selected.cursor.after_count(), texts.len() as u64);
        assert!(b.selected.complete);
        let request = b.request.clone();
        let selected = b.selected.clone();
        for ordinal in 0..texts.len() {
            assert!(read_vector(
                &store,
                &request,
                &selected,
                ordinal as u32,
                read_budget(),
                &mut b
            )
            .unwrap()
            .components
            .is_empty());
        }
        assert!(b.current_index_generation(request.corpus(), "f").is_err());
    }
}

#[test]
fn independent_replay_rejects_rehashed_compact_block_and_tampered_unsealed_tail() {
    let (_fixture, store, mut b, mut sources) = setup(&["alpha", "alpha alpha"]);
    let plan = plan(&store, &mut sources, &mut b, 2);
    let mutation = effect(plan.commitment(), &mut b);
    let prepared = prepare_vectors(&store, &plan, &mutation, &mut b).unwrap();
    let mut bad = prepared.commitment().clone();
    let original = bad.next.coordinates.root.clone().unwrap();
    let mut bytes = plan
        .pages
        .iter()
        .find(|(hash, _)| hash == &original.sha256)
        .unwrap()
        .1
        .clone();
    let start = bytes.len() - original.count as usize * 4;
    bytes[start..start + 4].copy_from_slice(&(-1_f32).to_bits().to_le_bytes());
    let hash = store
        .prepare_page(
            &bytes,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 1024 * 1024,
                new_files: 3,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    bad.next.coordinates.root.as_mut().unwrap().sha256 = hash;
    bad.review_sha256 = bad.review().unwrap();
    bad.canonical_bytes().unwrap();
    b.inner.inner.set_write(false);
    assert!(verify_vectors_data(&store, &bad, &mut sources, &mut b).is_err());
    let base = b.selected.clone();
    let plan = plan_vector_window(
        &store,
        &b.request.clone(),
        &base,
        1,
        MAX_VECTOR_READ,
        MAX_VECTOR_WRITE,
        &mut sources,
        &mut b,
    )
    .unwrap();
    let mut bad = plan.value.clone();
    bad.next.coordinates.tail[0][0] = (-1_f32).to_bits();
    bad.review_sha256 = bad.review().unwrap();
    bad.canonical_bytes().unwrap();
    assert!(verify_vectors_data(&store, &bad, &mut sources, &mut b).is_err());
}

#[test]
fn compact_binary_layout_and_partial_state_refuse_wrong_context_or_trailing_bytes() {
    let (_fixture, store, mut b, mut sources) = setup(&["alpha", "alpha alpha"]);
    let plan = plan(&store, &mut sources, &mut b, 2);
    let mutation = effect(plan.commitment(), &mut b);
    let prepared = prepare_vectors(&store, &plan, &mutation, &mut b).unwrap();
    let root = prepared.commitment().next.coordinates.root.clone().unwrap();
    let bytes = plan
        .pages
        .iter()
        .find(|(hash, _)| hash == &root.sha256)
        .unwrap()
        .1
        .clone();
    for data in [bytes[..bytes.len() - 1].to_vec(), {
        let mut data = bytes.clone();
        data.push(0);
        data
    }] {
        let hash = store
            .prepare_page(
                &data,
                IoBudget {
                    read_bytes: RUN_PAGE_READ,
                    write_bytes: 1024 * 1024,
                    new_files: 3,
                },
                &mutation,
                &mut b,
            )
            .unwrap();
        let mut node = root.clone();
        node.sha256 = hash;
        assert!(coordinates::read_node(&store, &b.request.clone(), 1, &node, &mut b).is_err());
    }
    let mut bad = prepared.commitment().next.clone();
    bad.coordinates.tail.push(vec![1_f32.to_bits()]);
    assert!(bad.canonical_bytes(&b.request).is_err());
}

#[test]
fn selected_sorted_stream_rank_seeks_prove_exact_term_bounds_without_bucket_scans() {
    use crate::corpus_index::job::statistics::selected::SelectedPostingReader;
    for texts in [
        vec!["alpha alpha beta", "beta gamma", "delta"],
        vec!["alpha beta"; 9],
    ] {
        let (_fixture, store, mut b, _sources) = setup(&texts);
        let statistics = b.request.projection.covariance.statistics.clone();
        let selected = b.request.projection.covariance.selected_statistics.clone();
        let mut reader =
            SelectedPostingReader::open(&store, &statistics, &selected, 16 * 1024 * 1024, &mut b)
                .unwrap();
        let mut all = Vec::new();
        let mut after = 0;
        while after < reader.count() {
            let rows = reader.range(after, 2).unwrap();
            after += rows.len() as u64;
            all.extend(rows);
        }
        assert_eq!(all.len() as u64, statistics.ingested.totals.postings);
        for term in ["alpha", "beta", "delta", "gamma", "notpresent"] {
            let first = reader.lower_bound(term, 0).unwrap();
            let end = reader.lower_bound(term, u32::MAX).unwrap();
            let expected: Vec<_> = all
                .iter()
                .filter(|entry| entry.term == term)
                .cloned()
                .collect();
            assert_eq!(end - first, expected.len() as u64);
            if first != end {
                assert_eq!(reader.range(first, expected.len()).unwrap(), expected);
            }
        }
        assert!(reader.read_bytes() < 16 * 1024 * 1024);
    }
}

#[test]
fn selected_posting_reads_refuse_tiny_budget_revocation_and_missing_actual_leaf() {
    use crate::corpus_index::job::statistics::{selected::SelectedPostingReader, StatisticsStream};
    let (fixture, store, mut b, _sources) = setup(&["alpha beta", "gamma beta"]);
    let statistics = b.request.projection.covariance.statistics.clone();
    let selected = b.request.projection.covariance.selected_statistics.clone();
    assert!(
        SelectedPostingReader::open(&store, &statistics, &selected, RUN_PAGE_READ - 1, &mut b)
            .is_err()
    );
    b.inner.inner.set_revoked(true);
    assert!(
        SelectedPostingReader::open(&store, &statistics, &selected, 1024 * 1024, &mut b).is_err()
    );
    b.inner.inner.set_revoked(false);
    let Some(StatisticsStream::Ingest { run }) = &selected.frequencies.as_ref().unwrap().stream
    else {
        panic!("two documents use a single actual ingestion stream")
    };
    let bytes = store.read_page(&run.sha256, read_budget(), &mut b).unwrap();
    let descriptor: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let hash = descriptor["body"]["postings"]["sha256"].as_str().unwrap();
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
    let mut reader =
        SelectedPostingReader::open(&store, &statistics, &selected, 1024 * 1024, &mut b).unwrap();
    assert!(reader.range(0, 1).is_err());
}
