//! Disposable real-store/math fixtures; these callbacks are explicitly not
//! installed PAM, protected C publication or authenticated allocation witnesses.
use super::super::statistics::{
    plan_statistics_window, prepare_statistics, verify_statistics_data, StatisticsCommitment,
};
use super::super::tests as fixture;
use super::*;

struct Guard {
    inner: fixture::Guard,
    statistics: StatisticsRequest,
    selected_statistics: StatisticsProgress,
    covariance: Option<CovarianceRequest>,
    selected_covariance: Option<CovarianceProgress>,
    deny_witness: bool,
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
        if request != &self.statistics || progress != &self.selected_statistics {
            return Err("fixture selected statistics differs".into());
        }
        Ok(())
    }
    fn verify_statistics_allocations(&mut self, value: &StatisticsCommitment) -> Result<()> {
        self.current_statistics(&value.request, &value.base)
    }
}
impl CovarianceBoundary for Guard {
    fn current_covariance(
        &mut self,
        request: &CovarianceRequest,
        progress: &CovarianceProgress,
    ) -> Result<()> {
        if self.covariance.as_ref() != Some(request)
            || self.selected_covariance.as_ref() != Some(progress)
        {
            return Err("fixture selected covariance differs".into());
        }
        Ok(())
    }
    fn verify_covariance_allocations(&mut self, value: &CovarianceCommitment) -> Result<()> {
        self.current_covariance(&value.request, &value.base)?;
        if self.deny_witness {
            return Err("fixture actual allocation witness refused".into());
        }
        Ok(())
    }
}
struct Sources {
    owner: luma_content::OwnerBinding,
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
        b.check(Access::Inspect {
            binding: &self.owner,
        })?;
        self.calls += 1;
        let mut bytes = self
            .bytes
            .get(&record.reference.content_sha256)
            .ok_or("exact literal fixture source missing")?
            .clone();
        if self.changed {
            bytes.push(b'!');
        }
        Ok(bytes)
    }
}
fn setup(
    texts: &[&str],
) -> (
    fixture::Fixture,
    ObjectStore,
    CovarianceRequest,
    Sources,
    Guard,
) {
    let (fixture, store, ingestion, ingested, inner) = fixture::completed_fixture(texts);
    let statistics = StatisticsRequest {
        schema_version: 1,
        ingestion,
        ingested,
    };
    let mut b = Guard {
        inner,
        selected_statistics: StatisticsProgress::beginning(&statistics).unwrap(),
        statistics,
        covariance: None,
        selected_covariance: None,
        deny_witness: false,
    };
    for _ in 0..512 {
        if b.selected_statistics.complete {
            break;
        }
        let plan = plan_statistics_window(
            &store,
            &b.statistics.clone(),
            &b.selected_statistics.clone(),
            64 * 1024 * 1024,
            16 * 1024 * 1024,
            &mut b,
        )
        .unwrap();
        let mutation = Mutation {
            review_sha256: plan.commitment().review_sha256.clone(),
            decision: crate::DecisionKind::Published,
            source_bytes: 0,
        };
        b.inner.set_review(mutation.review_sha256.clone());
        let prepared = prepare_statistics(&store, &plan, &mutation, &mut b).unwrap();
        b.inner.set_write(false);
        verify_statistics_data(&store, prepared.commitment(), &mut b).unwrap();
        b.selected_statistics = prepared.commitment().next.clone();
        b.inner.set_write(true);
    }
    assert!(b.selected_statistics.complete);
    let request = CovarianceRequest {
        schema_version: 1,
        statistics: b.statistics.clone(),
        selected_statistics: b.selected_statistics.clone(),
    };
    b.selected_covariance = Some(CovarianceProgress::beginning(&request).unwrap());
    b.covariance = Some(request.clone());
    let sources = Sources {
        owner: request.corpus().binding.clone(),
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
        calls: 0,
    };
    (fixture, store, request, sources, b)
}
fn next(
    store: &ObjectStore,
    request: &CovarianceRequest,
    sources: &mut Sources,
    b: &mut Guard,
    maximum: usize,
    read: u64,
) -> CovarianceCommitment {
    let base = b.selected_covariance.clone().unwrap();
    let plan = plan_covariance_window(store, request, &base, maximum, read, MAX_WRITE, sources, b)
        .unwrap();
    let mutation = Mutation {
        review_sha256: plan.review().sha256().unwrap(),
        decision: crate::DecisionKind::Published,
        source_bytes: plan.review().source_bytes,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    let exact_objects = plan.planned_objects(|| Ok(())).unwrap();
    let prepared = prepare_covariance(store, &plan, &mutation, b).unwrap();
    for object in exact_objects {
        let bytes = store.read_page(&object.sha256, read_budget(), b).unwrap();
        assert_eq!(bytes.len(), object.bytes as usize);
        assert_eq!(luma_content::sha256(&bytes), object.sha256);
    }
    assert!(prepared.acknowledge_selected(b).is_err());
    let count = b.inner.mutation_count();
    b.inner.set_write(false);
    verify_covariance_data(store, prepared.commitment(), sources, b).unwrap();
    assert_eq!(b.inner.mutation_count(), count);
    b.selected_covariance = Some(prepared.commitment().next.clone());
    prepared.acknowledge_selected(b).unwrap();
    b.inner.set_write(true);
    prepared.commitment().clone()
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 8 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}

#[test]
fn actual_resumable_matrix_matches_existing_normalized_weight_outer_products_bit_exactly() {
    let (_fixture, store, request, mut source, mut b) = setup(&[
        "alpha alpha beta",
        "beta gamma",
        "alpha delta",
        "delta gamma",
        "alpha beta gamma delta",
    ]);
    while !b.selected_covariance.as_ref().unwrap().complete {
        next(&store, &request, &mut source, &mut b, 2, MAX_READ);
    }
    let selected = b.selected_covariance.clone().unwrap();
    let matrix =
        read_covariance_matrix(&store, &request, &selected, read_budget(), &mut b).unwrap();
    let features = request.features().unwrap();
    let n = features.len();
    let mut expected = vec![vec![0.0; n]; n];
    let idfs: Vec<_> = features
        .iter()
        .map(|(_, df)| super::super::super::build::idf(request.corpus().entry_count, *df))
        .collect();
    store
        .visit_map(request.corpus(), read_budget(), &mut b, |_, bytes| {
            let record: CorpusRecord = decode(bytes, crate::v2::MAX_VALUE_BYTES)?;
            let text =
                std::str::from_utf8(source.bytes.get(&record.reference.content_sha256).unwrap())?;
            let mut tf: BTreeMap<String, (u32, u32)> = BTreeMap::new();
            for word in text.split_ascii_whitespace() {
                tf.entry(word.into()).or_insert((0, 0)).0 += 1;
            }
            let vector = super::super::super::build::weights(&tf, &features, &idfs)?;
            let nonzero: Vec<_> = vector
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, v)| *v != 0.0)
                .collect();
            for (i, x) in &nonzero {
                for (j, y) in &nonzero {
                    expected[*i][*j] += x * y;
                }
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        matrix
            .iter()
            .flatten()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .flatten()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>()
    );
    assert_eq!(selected.cursor.after_count(), 5);
    assert_eq!(source.calls, 10);
    assert!(plan_covariance_window(
        &store,
        &request,
        &selected,
        2,
        MAX_READ,
        MAX_WRITE,
        &mut source,
        &mut b
    )
    .is_err());
}

#[test]
fn exact_partial_source_prefix_stops_before_finite_read_exhaustion_then_resumes() {
    let text = "alpha beta ".repeat(45_000);
    let (_fixture, store, request, mut sources, mut b) =
        setup(&[text.as_str(), text.as_str(), text.as_str(), text.as_str()]);
    let first = next(&store, &request, &mut sources, &mut b, 128, 8 * 1024 * 1024);
    assert!(first.next.cursor.after_count() > 0 && first.next.cursor.after_count() < 4);
    while !b.selected_covariance.as_ref().unwrap().complete {
        next(&store, &request, &mut sources, &mut b, 128, MAX_READ);
    }
    assert_eq!(
        b.selected_covariance.as_ref().unwrap().cursor.after_count(),
        4
    );
}

#[test]
fn rehashed_physically_written_false_matrix_fails_independent_source_reconstruction() {
    let (_fixture, store, request, mut sources, mut b) = setup(&["alpha beta", "alpha beta"]);
    let value = next(&store, &request, &mut sources, &mut b, 128, MAX_READ);
    b.selected_covariance = Some(value.base.clone());
    let mut matrix =
        vec![vec![0.0; request.features().unwrap().len()]; request.features().unwrap().len()];
    matrix[0][0] = 7.0;
    let bytes = encode_matrix(&request, &value.next.cursor, &matrix).unwrap();
    let mutation = Mutation {
        review_sha256: "d".repeat(64),
        decision: crate::DecisionKind::Published,
        source_bytes: bytes.len() as u64,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    let reference = store
        .prepare_blob(
            &bytes,
            IoBudget {
                read_bytes: 8 * 1024 * 1024,
                write_bytes: 8 * 1024 * 1024,
                new_files: 4096,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    let mut forged = value.clone();
    forged.next.matrix = Some(reference.clone());
    forged.review.matrix_sha256 = reference.sha256;
    forged.canonical_bytes().unwrap();
    b.inner.set_write(false);
    assert!(verify_covariance_data(&store, &forged, &mut sources, &mut b).is_err());
}

#[test]
fn revoked_or_changed_sources_and_allocation_witness_withhold_current_matrix() {
    let (_fixture, store, request, mut sources, mut b) = setup(&["alpha beta", "beta gamma"]);
    let base = b.selected_covariance.clone().unwrap();
    sources.changed = true;
    assert!(plan_covariance_window(
        &store,
        &request,
        &base,
        128,
        MAX_READ,
        MAX_WRITE,
        &mut sources,
        &mut b
    )
    .is_err());
    sources.changed = false;
    let plan = plan_covariance_window(
        &store,
        &request,
        &base,
        128,
        MAX_READ,
        MAX_WRITE,
        &mut sources,
        &mut b,
    )
    .unwrap();
    let mutation = Mutation {
        review_sha256: plan.review().sha256().unwrap(),
        decision: crate::DecisionKind::Published,
        source_bytes: plan.review().source_bytes,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    b.inner.set_revoked(true);
    assert!(prepare_covariance(&store, &plan, &mutation, &mut b).is_err());
    b.inner.set_revoked(false);
    b.deny_witness = true;
    assert!(prepare_covariance(&store, &plan, &mutation, &mut b).is_err());
    assert_eq!(b.selected_covariance.as_ref(), Some(&base));
}

#[test]
fn binary_matrix_refuses_nonfinite_asymmetric_context_and_length_substitutions() {
    let (_fixture, _store, request, _source, b) = setup(&["alpha beta"]);
    let cursor = &b.selected_covariance.as_ref().unwrap().cursor;
    let matrix = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
    let bytes = encode_matrix(&request, cursor, &matrix).unwrap();
    assert_eq!(decode_matrix(&request, cursor, &bytes).unwrap(), matrix);
    let mut changed = bytes.clone();
    changed[HEADER.len()] = b'9';
    assert!(decode_matrix(&request, cursor, &changed).is_err());
    let mut changed = bytes.clone();
    changed.pop();
    assert!(decode_matrix(&request, cursor, &changed).is_err());
    let mut changed = bytes.clone();
    let offset = HEADER.len() + 64 + 2 + 8;
    changed[offset..offset + 8].copy_from_slice(&f64::NAN.to_bits().to_le_bytes());
    assert!(decode_matrix(&request, cursor, &changed).is_err());
    assert!(encode_matrix(&request, cursor, &[vec![1.0, 1.0], vec![0.0, 1.0]]).is_err());
    assert!(encode_matrix(&request, cursor, &[vec![-1.0, 0.0], vec![0.0, 1.0]]).is_err());
}

#[test]
fn wordless_covariance_is_an_explicit_zero_feature_case_not_a_fabricated_source_scan() {
    let (_fixture, store, request, _sources, mut b) = setup(&["--- ___", ""]);
    let progress = b.selected_covariance.clone().unwrap();
    assert!(progress.complete);
    assert_eq!(progress.cursor.after_count(), 0);
    assert!(progress.matrix.is_none());
    assert!(
        read_covariance_matrix(&store, &request, &progress, read_budget(), &mut b)
            .unwrap()
            .is_empty()
    );
    assert!(b
        .current_index_generation(request.corpus(), &"1".repeat(64))
        .is_err());
}
