//! Real immutable full-pipeline/query fixtures. Current-C, grant, reservation
//! and fixed-runtime callbacks here are synthetic, not installed qualification.
use super::super::tests as fixture;
use super::*;
use crate::corpus_index::{CorpusQueryKind, CorpusQueryResults};
use audit::{AuditCommitment, AuditPhase, AuditProgress, GenerationAuditBoundary};

struct Guard {
    inner: fixture::Guard,
    job: GenerationJob,
    audit: AuditProgress,
    generation: Option<GenerationManifest>,
    held: Option<GenerationReview>,
    deny_provenance: bool,
    deny_allocations: bool,
    deny_reserve: bool,
    deny_candidates: bool,
    release_error: bool,
    releases: usize,
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
    fn current_index_generation(&mut self, root: &MapRoot, selected: &str) -> Result<()> {
        self.inner.current_corpus(root)?;
        if self
            .generation
            .as_ref()
            .map(GenerationManifest::sha256)
            .transpose()?
            .as_deref()
            != Some(selected)
        {
            return Err("fixture exact current generation differs".into());
        }
        Ok(())
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        if self.deny_candidates {
            return Err("fixture fresh source/lifecycle permission refused".into());
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
        self.inner.current_vectors(request, progress)
    }
    fn verify_vector_allocations(&mut self, value: &VectorCommitment) -> Result<()> {
        self.inner.verify_vector_allocations(value)
    }
}
impl GenerationAuditBoundary for Guard {
    fn current_generation_audit(
        &mut self,
        job: &GenerationJob,
        progress: &AuditProgress,
    ) -> Result<()> {
        if job != &self.job || progress != &self.audit {
            return Err("fixture audit cursor is not independently selected".into());
        }
        self.inner.check(Access::Inspect {
            binding: &job.corpus().binding,
        })
    }
    fn verify_audit_reservations(&mut self, value: &AuditCommitment) -> Result<()> {
        self.current_generation_audit(&value.job, &value.base)
    }
}
impl GenerationPublicationBoundary for Guard {
    fn verify_original_phase_provenance(
        &mut self,
        job: &GenerationJob,
        selected_audit: &AuditProgress,
    ) -> Result<()> {
        self.current_generation_audit(job, selected_audit)?;
        if self.deny_provenance {
            return Err("fixture independent original phase provenance unavailable".into());
        }
        Ok(())
    }
    fn reserve_generation(&mut self, review: &GenerationReview) -> Result<()> {
        if self.deny_reserve
            || self.held.is_some()
            || review.job_sha256 != self.job.sha256()?
            || review.audit_sha256 != luma_content::sha256(&self.audit.canonical_bytes(&self.job)?)
        {
            return Err("fixture durable generation hold refuses unknown/duplicate attempt".into());
        }
        self.held = Some(review.clone());
        Ok(())
    }
    fn verify_generation_allocations(&mut self, value: &GenerationCommitment) -> Result<()> {
        self.current_generation_audit(&value.job, &value.audit)?;
        if self.held.as_ref() != Some(&value.review) || self.deny_allocations {
            return Err("fixture actual generation allocation observation unavailable".into());
        }
        Ok(())
    }
    fn release_generation_after_selection(&mut self, value: &GenerationCommitment) -> Result<()> {
        self.current_generation(&value.manifest)?;
        if self.held.as_ref() != Some(&value.review) {
            return Err("fixture selected generation differs from held reservation".into());
        }
        self.releases += 1;
        if self.release_error {
            return Err("fixture uncertain release dispatch".into());
        }
        self.held = None;
        Ok(())
    }
}
impl CurrentGenerationBoundary for Guard {
    fn current_generation(&mut self, manifest: &GenerationManifest) -> Result<()> {
        self.inner.check(Access::Inspect {
            binding: &manifest.corpus.binding,
        })?;
        if self.generation.as_ref() != Some(manifest) {
            return Err("fixture actual selected generation absent/different".into());
        }
        Ok(())
    }
}
fn setup(texts: &[&str]) -> (crate::corpus_index::job::tests::Fixture, ObjectStore, Guard) {
    let (fixture, store, inner) = fixture::completed_fixture(texts);
    let job = GenerationJob {
        schema_version: 1,
        request: inner.request.clone(),
        progress: inner.selected.clone(),
    };
    let selected_audit = AuditProgress::beginning(&job).unwrap();
    (
        fixture,
        store,
        Guard {
            inner,
            job,
            audit: selected_audit,
            generation: None,
            held: None,
            deny_provenance: false,
            deny_allocations: false,
            deny_reserve: false,
            deny_candidates: false,
            release_error: false,
            releases: 0,
        },
    )
}
fn mutation(review_sha256: String, b: &mut Guard) -> Mutation {
    b.inner.inner.inner.set_write(true);
    b.inner.inner.inner.set_review(review_sha256.clone());
    Mutation {
        review_sha256,
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    }
}
fn audit_step(store: &ObjectStore, b: &mut Guard, maximum: usize) -> AuditCommitment {
    let value = audit::plan_audit_window(
        store,
        &b.job.clone(),
        &b.audit.clone(),
        maximum,
        64 * 1024 * 1024,
        b,
    )
    .unwrap();
    let mutation = mutation(value.review_sha256.clone(), b);
    let prepared = audit::prepare_audit(&value, &mutation, b).unwrap();
    assert!(prepared.acknowledge_selected(b).is_err());
    b.inner.inner.inner.set_write(false);
    audit::verify_audit_data(store, &value, b).unwrap();
    b.audit = value.next.clone();
    prepared.acknowledge_selected(b).unwrap();
    b.inner.inner.inner.set_write(true);
    value
}
fn complete_audit(store: &ObjectStore, b: &mut Guard) {
    for _ in 0..256 {
        if b.audit.phase == AuditPhase::Complete {
            return;
        }
        let maximum = if b.audit.phase == AuditPhase::Coverage {
            2
        } else {
            3
        };
        audit_step(store, b, maximum);
    }
    panic!("fixture full closure audit did not finish");
}
fn publish(store: &ObjectStore, b: &mut Guard) -> GenerationCommitment {
    complete_audit(store, b);
    let plan = plan_generation(store, &b.job.clone(), &b.audit.clone(), b).unwrap();
    let mutation = mutation(plan.review().sha256().unwrap(), b);
    let exact_objects = plan.planned_objects(|| Ok(())).unwrap();
    let prepared = prepare_generation(store, &plan, &mutation, b).unwrap();
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
    b.inner.inner.inner.set_write(false);
    verify_generation_data(store, prepared.commitment(), b).unwrap();
    b.generation = Some(prepared.commitment().manifest.clone());
    prepared.acknowledge_selected(b).unwrap();
    b.inner.inner.inner.set_write(true);
    prepared.commitment().clone()
}
fn limits() -> CorpusIndexLimits {
    CorpusIndexLimits {
        read_bytes: 128 * 1024 * 1024,
        write_bytes: 0,
        source_bytes: MAX_INDEX_SOURCE_BYTES,
        postings: MAX_INDEX_POSTINGS,
        floating_operations: 100_000_000,
    }
}
fn open(
    store: &ObjectStore,
    value: &GenerationCommitment,
    b: &mut Guard,
) -> query::VerifiedGeneration {
    query::VerifiedGeneration::open(
        store,
        &value.manifest.canonical_bytes().unwrap(),
        &value.manifest.sha256().unwrap(),
        limits(),
        b,
    )
    .unwrap()
}
fn compare_results(
    a: &CorpusQueryResults,
    expected: &[(u32, i64)],
    records: &[VectorRecord],
    limit: usize,
) {
    assert_eq!(a.total_matches, expected.len() as u64);
    assert_eq!(a.truncated, expected.len() > limit);
    assert_eq!(a.matches.len(), expected.len().min(limit));
    for (hit, (ordinal, score)) in a.matches.iter().zip(expected) {
        assert_eq!(hit.reference, records[*ordinal as usize].record.reference);
        assert_eq!(hit.score, *score);
    }
}

#[test]
fn actual_resumed_full_closure_generation_and_both_queries_match_exact_reference_ranking() {
    let texts = [
        "alpha alpha beta",
        "beta gamma",
        "alpha delta",
        "delta gamma",
        "alpha beta gamma delta",
    ];
    let (_fixture, store, mut b) = setup(&texts);
    let value = publish(&store, &mut b);
    assert!(value.manifest.canonical_bytes().unwrap().len() <= 16 * 1024);
    assert!(
        value.job.canonical_bytes().unwrap().len()
            > value.manifest.canonical_bytes().unwrap().len()
    );
    let generation = open(&store, &value, &mut b);
    let records = super::super::read::read_record_window_data(
        &store,
        &b.job.request.clone(),
        &b.job.progress.clone(),
        0,
        128,
        IoBudget {
            read_bytes: 8 * 1024 * 1024,
            write_bytes: 0,
            new_files: 0,
        },
        &mut b,
    )
    .unwrap()
    .rows;
    let mut lexical = Vec::new();
    for row in &records {
        let id = row
            .record
            .reference
            .artifact_id
            .strip_prefix("document-")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let tokens: Vec<_> = texts[id].split(' ').collect();
        if tokens.contains(&"alpha") && tokens.contains(&"beta") {
            lexical.push((
                row.ordinal,
                tokens
                    .iter()
                    .filter(|t| **t == "alpha" || **t == "beta")
                    .count() as i64,
            ));
        }
    }
    lexical.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let result = generation
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "Alpha beta",
            1,
            limits(),
            &mut b,
        )
        .unwrap();
    compare_results(&result, &lexical, &records, 1);
    let mut expected = Vec::new();
    let model = build_model(&store, &b.job.clone(), &b.audit.clone(), &mut b).unwrap();
    let features: Vec<_> = model
        .features
        .iter()
        .map(|f| (f.term.clone(), f.documents))
        .collect();
    let idfs: Vec<_> = model
        .features
        .iter()
        .map(|f| f64::from_bits(f.idf_bits))
        .collect();
    let basis: Vec<Vec<_>> = model
        .features
        .iter()
        .map(|f| {
            f.projection_bits
                .iter()
                .map(|v| f64::from_bits(*v))
                .collect()
        })
        .collect();
    let mut tf = BTreeMap::new();
    tf.insert("alpha".into(), (1, 0));
    let weights = crate::corpus_index::build::weights(&tf, &features, &idfs).unwrap();
    let latent = crate::corpus_index::build::project(
        &weights,
        &basis,
        usize::from(value.manifest.dimensions),
    )
    .unwrap();
    for row in &records {
        let cosine: f64 = row
            .components
            .iter()
            .zip(&latent)
            .map(|(v, q)| f64::from(f32::from_bits(*v)) * q)
            .sum();
        let score = (cosine.clamp(-1.0, 1.0) * 1_000_000.0).round() as i64;
        if score > 0 {
            expected.push((row.ordinal, score));
        }
    }
    expected.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let result = generation
        .query(
            &store,
            CorpusQueryKind::FeatureLsa,
            "alpha",
            2,
            limits(),
            &mut b,
        )
        .unwrap();
    compare_results(&result, &expected, &records, 2);
}

#[test]
fn audit_independent_replay_rejects_borrowed_cursor_and_rehashed_false_df() {
    let (_fixture, store, mut b) = setup(&["alpha alpha beta", "beta gamma", "alpha"]);
    let first = audit_step(&store, &mut b, 1);
    assert!(audit::verify_audit_data(&store, &first, &mut b).is_err());
    while b.audit.phase == AuditPhase::Coverage {
        audit_step(&store, &mut b, 1);
    }
    let mut value = audit::plan_audit_window(
        &store,
        &b.job.clone(),
        &b.audit.clone(),
        1,
        64 * 1024 * 1024,
        &mut b,
    )
    .unwrap();
    value.next.frequencies.current.as_mut().unwrap().documents += 1;
    value.review_sha256 = value.review().unwrap();
    value.canonical_bytes().unwrap();
    assert!(audit::verify_audit_data(&store, &value, &mut b).is_err());
    let mut forged = b.audit.clone();
    forged.phase = AuditPhase::Complete;
    assert!(forged.canonical_bytes(&b.job).is_err());
}

#[test]
fn complete_audit_compares_actual_compact_rows_with_independent_record_proofs() {
    let (_fixture, store, mut b) = setup(&["alpha", "alpha alpha"]);
    let node = b.job.progress.coordinates.root.clone().unwrap();
    let bytes = store
        .read_page(
            &node.sha256,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut b,
        )
        .unwrap();
    let mut bad = bytes;
    let at = bad.len() - node.count as usize * 4;
    bad[at..at + 4].copy_from_slice(&(-1_f32).to_bits().to_le_bytes());
    let mutation = mutation("c".repeat(64), &mut b);
    let sha = store
        .prepare_page(
            &bad,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 1024 * 1024,
                new_files: 3,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    b.inner.selected.coordinates.root.as_mut().unwrap().sha256 = sha;
    b.job.progress = b.inner.selected.clone();
    b.audit = AuditProgress::beginning(&b.job).unwrap();
    assert!(audit::plan_audit_window(
        &store,
        &b.job.clone(),
        &b.audit.clone(),
        2,
        64 * 1024 * 1024,
        &mut b
    )
    .is_err());
}

#[test]
fn final_model_rehash_current_selection_revocation_and_candidate_refusal_withhold_entire_output() {
    let (_fixture, store, mut b) = setup(&["alpha beta", "beta gamma", "alpha"]);
    let value = publish(&store, &mut b);
    let generation = open(&store, &value, &mut b);
    b.deny_candidates = true;
    assert!(generation
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            2,
            limits(),
            &mut b
        )
        .is_err());
    b.deny_candidates = false;
    b.generation = None;
    assert!(generation
        .query(
            &store,
            CorpusQueryKind::FeatureLsa,
            "alpha",
            2,
            limits(),
            &mut b
        )
        .is_err());
    b.generation = Some(value.manifest.clone());
    b.inner.inner.inner.set_revoked(true);
    assert!(generation
        .query(
            &store,
            CorpusQueryKind::FeatureLsa,
            "alpha",
            2,
            limits(),
            &mut b
        )
        .is_err());
    b.inner.inner.inner.set_revoked(false);
    let mut bad_model = build_model(&store, &b.job.clone(), &b.audit.clone(), &mut b).unwrap();
    for feature in &mut bad_model.features {
        feature.projection_bits[0] = (-f64::from_bits(feature.projection_bits[0])).to_bits();
    }
    let bytes = bad_model.canonical_bytes(&b.job).unwrap();
    let mutation = mutation(value.review.sha256().unwrap(), &mut b);
    let model = store
        .prepare_blob(
            &bytes,
            IoBudget {
                read_bytes: 4 * 1024 * 1024,
                write_bytes: 4 * 1024 * 1024,
                new_files: 128,
            },
            &mutation,
            &mut b,
        )
        .unwrap();
    let mut bad = value.clone();
    bad.manifest.model = model;
    bad.review.model_sha256 = luma_content::sha256(&bytes);
    bad.review.model_bytes = bytes.len() as u64;
    bad.canonical_bytes().unwrap();
    assert!(verify_generation_data(&store, &bad, &mut b).is_err());
}

#[test]
fn durable_generation_hold_precedes_writes_and_uncertain_ack_cannot_retry() {
    let (_fixture, store, mut b) = setup(&["alpha beta", "gamma"]);
    complete_audit(&store, &mut b);
    let plan = plan_generation(&store, &b.job.clone(), &b.audit.clone(), &mut b).unwrap();
    let mutation = mutation(plan.review().sha256().unwrap(), &mut b);
    let io = IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    };
    let before = store.inventory(io, &mut b, |_| Ok(())).unwrap();
    b.deny_reserve = true;
    assert!(prepare_generation(&store, &plan, &mutation, &mut b).is_err());
    assert_eq!(before, store.inventory(io, &mut b, |_| Ok(())).unwrap());
    b.deny_reserve = false;
    let prepared = prepare_generation(&store, &plan, &mutation, &mut b).unwrap();
    assert!(b.held.is_some());
    assert!(prepared.acknowledge_selected(&mut b).is_err());
    b.generation = Some(prepared.commitment().manifest.clone());
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
fn empty_wordless_and_missing_actual_model_are_closed_without_index_authority_from_job_data() {
    for texts in [&[][..], &["!!!", ""][..]] {
        let (fixture, store, mut b) = setup(texts);
        let value = publish(&store, &mut b);
        let generation = open(&store, &value, &mut b);
        for kind in [CorpusQueryKind::LexicalAnd, CorpusQueryKind::FeatureLsa] {
            let result = generation
                .query(&store, kind, "alpha", 2, limits(), &mut b)
                .unwrap();
            assert!(result.matches.is_empty());
            assert_eq!(result.total_matches, 0);
        }
        let hash = value.manifest.model.index_sha256.as_ref().unwrap();
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
        assert!(generation
            .query(
                &store,
                CorpusQueryKind::FeatureLsa,
                "alpha",
                2,
                limits(),
                &mut b
            )
            .is_err());
    }
}
