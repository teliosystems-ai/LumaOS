//! Actual immutable storage and reference-math fixtures with synthetic current
//! selection/allocation callbacks, not installed C/PAM or native qualification.
use super::*;
use crate::corpus_index::job::statistics::{
    plan_statistics_window, prepare_statistics, verify_statistics_data, StatisticsCommitment,
};
use crate::corpus_index::job::tests as fixture;

pub(super) struct Guard {
    pub(super) inner: fixture::Guard,
    statistics: StatisticsRequest,
    selected_statistics: StatisticsProgress,
    covariance: CovarianceRequest,
    selected_covariance: CovarianceProgress,
    projection: Option<ProjectionRequest>,
    selected_projection: Option<ProjectionProgress>,
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
    fn current_index_generation(&mut self, root: &MapRoot, digest: &str) -> Result<()> {
        self.inner.current_index_generation(root, digest)
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
        self.inner.check(Access::Inspect {
            binding: &request.ingestion.corpus.binding,
        })
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
        if request != &self.covariance || progress != &self.selected_covariance {
            return Err("fixture selected covariance differs".into());
        }
        self.inner.check(Access::Inspect {
            binding: &request.corpus().binding,
        })
    }
    fn verify_covariance_allocations(&mut self, value: &CovarianceCommitment) -> Result<()> {
        self.current_covariance(&value.request, &value.base)
    }
}
impl ProjectionBoundary for Guard {
    fn current_projection(
        &mut self,
        request: &ProjectionRequest,
        progress: &ProjectionProgress,
    ) -> Result<()> {
        if self.projection.as_ref() != Some(request)
            || self.selected_projection.as_ref() != Some(progress)
        {
            return Err("fixture selected projection differs".into());
        }
        self.inner.check(Access::Inspect {
            binding: &request.corpus().binding,
        })
    }
    fn verify_projection_allocations(&mut self, value: &ProjectionCommitment) -> Result<()> {
        self.current_projection(&value.request, &value.base)?;
        if self.deny_witness {
            return Err("fixture actual retained allocation witness refuses".into());
        }
        Ok(())
    }
}
struct Sources {
    owner: luma_content::OwnerBinding,
    bytes: BTreeMap<String, Vec<u8>>,
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
        self.bytes
            .get(&record.reference.content_sha256)
            .cloned()
            .ok_or_else(|| "fixture exact source absent".into())
    }
}
fn setup(
    texts: &[&str],
    dimensions: u16,
) -> (
    fixture::Fixture,
    ObjectStore,
    ProjectionRequest,
    Vec<Vec<f64>>,
    Guard,
) {
    let (fixture, store, ingestion, ingested, inner) = fixture::completed_fixture(texts);
    let statistics = StatisticsRequest {
        schema_version: 1,
        ingestion,
        ingested,
    };
    let initial_statistics = StatisticsProgress::beginning(&statistics).unwrap();
    // Finish actual statistics using a separate selected-phase wrapper first.
    struct Stats<'a> {
        inner: &'a mut fixture::Guard,
        request: &'a StatisticsRequest,
        selected: &'a StatisticsProgress,
    }
    impl Boundary for Stats<'_> {
        fn admit(
            &mut self,
            owner: &luma_content::OwnerBinding,
            budget: ResourceBudget,
        ) -> Result<()> {
            self.inner.admit(owner, budget)
        }
        fn check(&mut self, access: Access<'_>) -> Result<()> {
            self.inner.check(access)
        }
    }
    impl CorpusIndexBoundary for Stats<'_> {
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
            self.inner.current_candidate(root, record)
        }
    }
    impl CorpusIndexJobBoundary for Stats<'_> {
        fn current_job(
            &mut self,
            request: &IngestRequest,
            progress: &IngestProgress,
        ) -> Result<()> {
            self.inner.current_job(request, progress)
        }
        fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()> {
            self.inner.verify_ingest_allocations(value)
        }
    }
    impl StatisticsBoundary for Stats<'_> {
        fn current_statistics(
            &mut self,
            request: &StatisticsRequest,
            progress: &StatisticsProgress,
        ) -> Result<()> {
            if request != self.request || progress != self.selected {
                return Err("fixture actual statistics phase differs".into());
            }
            self.inner.check(Access::Inspect {
                binding: &request.ingestion.corpus.binding,
            })
        }
        fn verify_statistics_allocations(&mut self, value: &StatisticsCommitment) -> Result<()> {
            self.current_statistics(&value.request, &value.base)
        }
    }
    let mut inner = inner;
    let mut selected_statistics = initial_statistics;
    for _ in 0..128 {
        if selected_statistics.complete {
            break;
        }
        let mut b = Stats {
            inner: &mut inner,
            request: &statistics,
            selected: &selected_statistics,
        };
        let plan = plan_statistics_window(
            &store,
            &statistics,
            &selected_statistics,
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
        selected_statistics = prepared.commitment().next.clone();
        inner.set_write(true);
    }
    assert!(selected_statistics.complete);
    let covariance = CovarianceRequest {
        schema_version: 1,
        statistics: statistics.clone(),
        selected_statistics: selected_statistics.clone(),
    };
    let selected_covariance = CovarianceProgress::beginning(&covariance).unwrap();
    let mut b = Guard {
        inner,
        statistics,
        selected_statistics,
        covariance: covariance.clone(),
        selected_covariance,
        projection: None,
        selected_projection: None,
        deny_witness: false,
    };
    let mut sources = Sources {
        owner: covariance.corpus().binding.clone(),
        bytes: texts
            .iter()
            .map(|text| {
                (
                    luma_content::sha256(text.as_bytes()),
                    text.as_bytes().to_vec(),
                )
            })
            .collect(),
    };
    for _ in 0..32 {
        if b.selected_covariance.complete {
            break;
        }
        let base = b.selected_covariance.clone();
        let plan = plan_covariance_window(
            &store,
            &covariance,
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
        let prepared = prepare_covariance(&store, &plan, &mutation, &mut b).unwrap();
        b.inner.set_write(false);
        verify_covariance_data(&store, prepared.commitment(), &mut sources, &mut b).unwrap();
        b.selected_covariance = prepared.commitment().next.clone();
        b.inner.set_write(true);
    }
    assert!(b.selected_covariance.complete);
    let selected = b.selected_covariance.clone();
    let matrix =
        read_covariance_matrix(&store, &covariance, &selected, read_budget(), &mut b).unwrap();
    let request = ProjectionRequest {
        schema_version: 1,
        covariance,
        selected_covariance: selected,
        requested_dimensions: dimensions,
    };
    b.selected_projection = Some(ProjectionProgress::beginning(&request).unwrap());
    b.projection = Some(request.clone());
    (fixture, store, request, matrix, b)
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: MAX_PROJECTION_READ,
        write_bytes: 0,
        new_files: 0,
    }
}
pub(super) fn completed_fixture(
    texts: &[&str],
    dimensions: u16,
) -> (
    fixture::Fixture,
    ObjectStore,
    ProjectionRequest,
    ProjectionProgress,
    Guard,
) {
    let (fixture, store, request, _matrix, mut b) = setup(texts, dimensions);
    for _ in 0..256 {
        if b.selected_projection.as_ref().unwrap().cursor.complete {
            return (
                fixture,
                store,
                request,
                b.selected_projection.clone().unwrap(),
                b,
            );
        }
        next(&store, &request, &mut b, MAX_PAIR_VISITS);
    }
    panic!("actual fixture projection exceeded its bounded convergence profile");
}
fn next(
    store: &ObjectStore,
    request: &ProjectionRequest,
    b: &mut Guard,
    pairs: usize,
) -> ProjectionCommitment {
    let base = b.selected_projection.clone().unwrap();
    let plan = plan_projection_window(
        store,
        request,
        &base,
        pairs,
        MAX_PROJECTION_READ,
        MAX_PROJECTION_WRITE,
        b,
    )
    .unwrap();
    let mutation = Mutation {
        review_sha256: plan.review().sha256().unwrap(),
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    let exact_objects = plan.planned_objects(|| Ok(())).unwrap();
    let prepared = prepare_projection(store, &plan, &mutation, b).unwrap();
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
    let before = b.inner.mutation_count();
    b.inner.set_write(false);
    verify_projection_data(store, prepared.commitment(), b).unwrap();
    assert_eq!(before, b.inner.mutation_count());
    b.selected_projection = Some(prepared.commitment().next.clone());
    prepared.acknowledge_selected(b).unwrap();
    b.inner.set_write(true);
    prepared.commitment().clone()
}

#[test]
fn actual_multiwindow_projection_matches_existing_math_bit_exactly_and_preserves_work() {
    let (_fixture, store, request, matrix, mut b) = setup(
        &[
            "alpha alpha beta",
            "beta gamma",
            "alpha delta",
            "delta gamma",
            "alpha beta gamma delta",
        ],
        3,
    );
    let mut original_work = 0_u64;
    let expected = crate::corpus_index::math::projection(matrix, 3, &mut |n| {
        original_work += n;
        Ok(())
    })
    .unwrap();
    let initial = b.selected_projection.as_ref().unwrap().totals;
    let mut windows = 0;
    while !b.selected_projection.as_ref().unwrap().cursor.complete {
        assert!(windows < 256);
        assert!(read_projection_basis(
            &store,
            &request,
            &b.selected_projection.clone().unwrap(),
            read_budget(),
            &mut b
        )
        .is_err());
        next(&store, &request, &mut b, 1);
        windows += 1;
    }
    assert!(windows > 1);
    let selected = b.selected_projection.clone().unwrap();
    let actual = read_projection_basis(&store, &request, &selected, read_budget(), &mut b).unwrap();
    assert_eq!(
        actual
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
    assert_eq!(selected.totals.work - initial.work, original_work * 2);
    assert_eq!(selected.totals.source_bytes, initial.source_bytes);
    assert_eq!(selected.totals.postings, initial.postings);
    assert!(plan_projection_window(
        &store,
        &request,
        &selected,
        1,
        MAX_PROJECTION_READ,
        MAX_PROJECTION_WRITE,
        &mut b
    )
    .is_err());
}

#[test]
fn independent_replay_rejects_actual_rehashed_false_matrix_or_basis() {
    let (_fixture, store, request, _matrix, mut b) = setup(&["alpha beta", "beta gamma"], 2);
    let base = b.selected_projection.clone().unwrap();
    let plan = plan_projection_window(
        &store,
        &request,
        &base,
        1,
        MAX_PROJECTION_READ,
        MAX_PROJECTION_WRITE,
        &mut b,
    )
    .unwrap();
    let mutation = Mutation {
        review_sha256: plan.review().sha256().unwrap(),
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    let prepared = prepare_projection(&store, &plan, &mutation, &mut b).unwrap();
    let mut bad = prepared.commitment().clone();
    let mut state = decode(&request, &bad.next.cursor, &plan.bytes).unwrap();
    state.vectors[0][0] += 0.125;
    let bytes = encode(&request, &state).unwrap();
    let reference = store
        .prepare_blob(
            &bytes,
            IoBudget {
                read_bytes: 1024 * 1024,
                write_bytes: 1024 * 1024,
                new_files: 64,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    bad.review.state_sha256 = reference.sha256.clone();
    bad.review.state_bytes = reference.bytes;
    bad.next.state = Some(reference);
    bad.canonical_bytes().unwrap();
    b.inner.set_write(false);
    assert!(verify_projection_data(&store, &bad, &mut b).is_err());
    verify_projection_data(&store, prepared.commitment(), &mut b).unwrap();
}

#[test]
fn stale_phase_revocation_allocation_and_cumulative_exhaustion_refuse_without_success() {
    let (_fixture, store, request, _matrix, mut b) = setup(&["alpha beta", "beta gamma"], 2);
    let base = b.selected_projection.clone().unwrap();
    let plan = plan_projection_window(
        &store,
        &request,
        &base,
        1,
        MAX_PROJECTION_READ,
        MAX_PROJECTION_WRITE,
        &mut b,
    )
    .unwrap();
    let mutation = Mutation {
        review_sha256: plan.review().sha256().unwrap(),
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    };
    b.inner.set_review(mutation.review_sha256.clone());
    b.inner.set_revoked(true);
    assert!(prepare_projection(&store, &plan, &mutation, &mut b).is_err());
    b.inner.set_revoked(false);
    b.deny_witness = true;
    assert!(prepare_projection(&store, &plan, &mutation, &mut b).is_err());
    b.deny_witness = false;
    let good = prepare_projection(&store, &plan, &mutation, &mut b).unwrap();
    b.selected_projection = Some(good.commitment().next.clone());
    assert!(verify_projection_data(&store, good.commitment(), &mut b).is_err());
    let mut exhausted = b.selected_projection.clone().unwrap();
    exhausted.totals.read_bytes = request.covariance.statistics.ingestion.limits.read_bytes;
    b.selected_projection = Some(exhausted.clone());
    assert!(plan_projection_window(
        &store,
        &request,
        &exhausted,
        1,
        1,
        MAX_PROJECTION_WRITE,
        &mut b
    )
    .is_err());
}

#[test]
fn binary_cursor_context_and_nonfinite_shape_are_closed() {
    let (_fixture, store, request, _matrix, mut b) = setup(&["alpha beta", "beta gamma"], 2);
    let base = b.selected_projection.clone().unwrap();
    let plan = plan_projection_window(
        &store,
        &request,
        &base,
        1,
        MAX_PROJECTION_READ,
        MAX_PROJECTION_WRITE,
        &mut b,
    )
    .unwrap();
    for bytes in [
        plan.bytes[..plan.bytes.len() - 1].to_vec(),
        {
            let mut data = plan.bytes.clone();
            data.push(0);
            data
        },
        {
            let mut data = plan.bytes.clone();
            let at = PROJECTION_HEADER.len();
            data[at] = if data[at] == b'0' { b'1' } else { b'0' };
            data
        },
    ] {
        assert!(decode(&request, &plan.review.cursor, &bytes).is_err());
    }
    let mut state = decode(&request, &plan.review.cursor, &plan.bytes).unwrap();
    state.matrix[0][0] = f64::NAN;
    assert!(encode(&request, &state).is_err());
    let mut wrong = plan.review.cursor.clone();
    wrong.p = u16::MAX;
    assert!(decode(&request, &wrong, &plan.bytes).is_err());
}

#[test]
fn exact_pair_order_sign_ties_and_sixty_four_sweep_refusal_match_reference() {
    let (_fixture, _store, request, _, _) = setup(&["alpha", "beta", "gamma"], 2);
    let n = request.n().unwrap();
    let mut state = State {
        cursor: JacobiCursor::beginning(),
        scale: 5.0,
        matrix: vec![
            vec![2.0, 0.0, 0.0],
            vec![0.0, 2.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ],
        vectors: vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ],
        basis: Vec::new(),
    };
    assert_eq!(n, 3);
    advance(&request, &mut state, 3, 1_000_000, &mut || Ok(())).unwrap();
    assert!(state.cursor.complete);
    assert_eq!(
        state.basis,
        vec![vec![1.0, 0.0], vec![0.0, 1.0], vec![0.0, 0.0]]
    );
    let mut last = State {
        cursor: JacobiCursor {
            sweep: 63,
            p: 1,
            q: 2,
            sweep_open: true,
            changed: true,
            complete: false,
        },
        scale: 3.0,
        matrix: vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ],
        vectors: vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ],
        basis: Vec::new(),
    };
    assert!(advance(&request, &mut last, 1, 1_000_000, &mut || Ok(())).is_err());
    assert!(!last.cursor.complete);
}

#[test]
fn wordless_and_rank_one_bases_are_actual_completed_phases_not_index_authority() {
    for texts in [&["!!!", ""][..], &["alpha", "alpha alpha"][..]] {
        let (_fixture, store, request, matrix, mut b) = setup(texts, 8);
        let expected = crate::corpus_index::math::projection(matrix, 8, &mut |_| Ok(())).unwrap();
        for _ in 0..8 {
            if b.selected_projection.as_ref().unwrap().cursor.complete {
                break;
            }
            next(&store, &request, &mut b, MAX_PAIR_VISITS);
        }
        let selected = b.selected_projection.clone().unwrap();
        assert!(selected.cursor.complete);
        assert_eq!(
            read_projection_basis(&store, &request, &selected, read_budget(), &mut b).unwrap(),
            expected
        );
        assert!(b.current_index_generation(request.corpus(), "f").is_err());
    }
}
