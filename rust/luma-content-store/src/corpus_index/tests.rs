//! Disposable-data boundary fixtures, not PAM, grants, custody or native NF08
//! acceptance. Index pages and source-map proofs use the actual private store.
use super::*;
use crate::v2::MapEdit;
use luma_content::OwnerBinding;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("corpus tests require private disposable ext4");
        let path = Path::new(&base).join(format!(
            "corpus-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn object(&self, hash: &str) -> PathBuf {
        let root = fs::read_dir(&self.path)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        root.join("objects")
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
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "c".repeat(64),
        decision: crate::DecisionKind::Published,
        source_bytes: 1024,
    }
}
fn builder() -> BuilderIdentity {
    // Explicit synthetic source/runtime pins for data-boundary tests only.
    BuilderIdentity {
        source_sha256: "1".repeat(64),
        runtime_sha256: "2".repeat(64),
    }
}
fn io() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 64 * 1024 * 1024,
        new_files: 32768,
    }
}
fn limits(write: bool) -> CorpusIndexLimits {
    CorpusIndexLimits {
        read_bytes: 8 * 1024 * 1024 * 1024,
        write_bytes: if write { 512 * 1024 * 1024 } else { 0 },
        source_bytes: MAX_INDEX_SOURCE_BYTES,
        postings: MAX_INDEX_POSTINGS,
        floating_operations: 1_000_000_000,
    }
}
struct Guard {
    builder: BuilderIdentity,
    root: MapRoot,
    selected: Option<String>,
    write: bool,
    checks: u64,
    fail_at: Option<u64>,
    candidate_checks: u64,
    deny_after_candidates: Option<u64>,
}
impl Guard {
    fn new(root: &MapRoot, write: bool) -> Self {
        Self {
            builder: builder(),
            root: root.clone(),
            selected: None,
            write,
            checks: 0,
            fail_at: None,
            candidate_checks: 0,
            deny_after_candidates: None,
        }
    }
}
impl Boundary for Guard {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if binding != &self.root.binding
            || budget.memory_bytes > 192 * 1024 * 1024
            || budget.tasks != 1
            || (!self.write && budget.write_bytes != 0)
        {
            return Err("fixture finite admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if self.fail_at.is_some_and(|n| self.checks >= n) {
            return Err("fixture authority revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.root.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if self.write && binding == &self.root.binding && review_sha256 == "c".repeat(64) => {
                Ok(())
            }
            _ => Err("fixture independent effect refused".into()),
        }
    }
}
impl CorpusIndexBoundary for Guard {
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()> {
        self.current_corpus(root)?;
        if identity != &self.builder {
            return Err("fixture independently observed builder tuple differs".into());
        }
        Ok(())
    }
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.root {
            return Err("fixture independently selected corpus changed".into());
        }
        Ok(())
    }
    fn current_index_generation(&mut self, root: &MapRoot, hash: &str) -> Result<()> {
        self.current_corpus(root)?;
        if self.selected.as_deref() != Some(hash) {
            return Err("fixture selected fixed-builder generation mismatch".into());
        }
        Ok(())
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        record.validate()?;
        self.candidate_checks += 1;
        if self
            .deny_after_candidates
            .is_some_and(|n| self.candidate_checks > n)
        {
            return Err("fixture candidate current access revoked".into());
        }
        Ok(())
    }
}
struct Sources {
    bytes: BTreeMap<String, Vec<u8>>,
    tamper: bool,
}
impl CorpusContent for Sources {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        b: &mut B,
    ) -> Result<Vec<u8>> {
        b.check(Access::Inspect {
            binding: &binding(),
        })?;
        let mut bytes = self
            .bytes
            .get(&record.reference.content_sha256)
            .ok_or("fixture exact content absent")?
            .clone();
        if self.tamper {
            bytes.push(b'!');
        }
        Ok(bytes)
    }
}
fn setup(texts: &[&str]) -> (Fixture, ObjectStore, MapRoot, Sources) {
    let fixture = Fixture::new();
    let empty = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    let store = ObjectStore::create_at(
        &fixture.path,
        &binding(),
        io(),
        &mutation(),
        &mut Guard::new(&empty, true),
    )
    .unwrap();
    let mut bytes = BTreeMap::new();
    let mut edits = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        let digest = luma_content::sha256(text.as_bytes());
        bytes.insert(digest.clone(), text.as_bytes().to_vec());
        let record = CorpusRecord {
            schema_version: 1,
            reference: VersionReference {
                artifact_id: format!("document-{i}"),
                version: 1,
                content_sha256: digest,
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
    edits.sort_by(|a, b| a.key.cmp(&b.key));
    let root = if edits.is_empty() {
        empty.clone()
    } else {
        store
            .prepare_map(
                &empty,
                &edits,
                io(),
                &mutation(),
                &mut Guard::new(&empty, true),
            )
            .unwrap()
    };
    (
        fixture,
        store,
        root,
        Sources {
            bytes,
            tamper: false,
        },
    )
}
fn build(store: &ObjectStore, root: &MapRoot, sources: &mut Sources) -> BuiltCorpusIndex {
    build_corpus_index(
        store,
        root,
        &builder(),
        sources,
        &mutation(),
        limits(true),
        &mut Guard::new(root, true),
    )
    .unwrap()
}
fn open(store: &ObjectStore, built: &BuiltCorpusIndex) -> (VerifiedCorpusIndex, Guard) {
    let mut guard = Guard::new(&built.manifest.corpus, false);
    guard.selected = Some(built.manifest_sha256.clone());
    let index = VerifiedCorpusIndex::open(
        store,
        &built.manifest.corpus,
        &built.manifest_sha256,
        &built.manifest.canonical_bytes().unwrap(),
        limits(false),
        &mut guard,
    )
    .unwrap();
    (index, guard)
}

#[test]
fn complete_actual_map_lexical_and_ranking_and_whole_ascii_boundaries() {
    let (_fixture, store, root, mut sources) = setup(&[
        "alpha beta alpha",
        "alpha beta",
        "alphabet beta alpha_beta caféalpha",
        "beta",
    ]);
    let built = build(&store, &root, &mut sources);
    assert_eq!(
        built.manifest.source_bytes,
        sources.bytes.values().map(|x| x.len() as u64).sum::<u64>()
    );
    let (index, mut guard) = open(&store, &built);
    let result = index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "BETA alpha",
            1,
            limits(false),
            &mut guard,
        )
        .unwrap();
    assert_eq!(result.canonical_query, "alpha beta");
    assert_eq!(result.total_matches, 2);
    assert!(result.truncated);
    assert_eq!(result.matches[0].reference.artifact_id, "document-0");
    assert_eq!(result.matches[0].score, 3);
    assert_eq!(
        index
            .query(
                &store,
                CorpusQueryKind::LexicalAnd,
                "alpha",
                64,
                limits(false),
                &mut guard
            )
            .unwrap()
            .total_matches,
        2
    );
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "café",
            1,
            limits(false),
            &mut guard
        )
        .is_err());
}

#[test]
fn deterministic_full_source_build_and_actual_semantic_coordinates() {
    let (_fixture, store, root, mut sources) = setup(&[
        "apple fruit orchard",
        "apple fruit pear",
        "engine wheel motor",
        "engine wheel axle",
    ]);
    let first = build(&store, &root, &mut sources);
    let second = build(&store, &root, &mut sources);
    assert_eq!(first.manifest_sha256, second.manifest_sha256);
    assert!(first.manifest.dimensions > 0);
    let (index, mut guard) = open(&store, &first);
    assert_eq!(index.manifest_sha256(), first.manifest_sha256);
    let hits = index
        .query(
            &store,
            CorpusQueryKind::FeatureLsa,
            "apple",
            4,
            limits(false),
            &mut guard,
        )
        .unwrap();
    assert!(hits
        .matches
        .iter()
        .any(|h| h.reference.artifact_id == "document-0"));
    assert!(hits
        .matches
        .iter()
        .filter(|h| h.reference.artifact_id.starts_with("document-"))
        .all(|h| h.score > 0));
    assert!(index
        .query(
            &store,
            CorpusQueryKind::FeatureLsa,
            "unknownword",
            4,
            limits(false),
            &mut guard
        )
        .unwrap()
        .matches
        .is_empty());
}

#[test]
fn empty_and_zero_supported_words_keep_exact_full_corpus_coverage() {
    for texts in [&[][..], &["", "café αλφα under_score"][..]] {
        let (_fixture, store, root, mut sources) = setup(texts);
        let built = build(&store, &root, &mut sources);
        assert_eq!(built.manifest.features, 0);
        assert_eq!(built.manifest.dimensions, 0);
        let (index, mut guard) = open(&store, &built);
        for kind in [CorpusQueryKind::LexicalAnd, CorpusQueryKind::FeatureLsa] {
            assert!(index
                .query(&store, kind, "alpha", 1, limits(false), &mut guard)
                .unwrap()
                .matches
                .is_empty());
        }
    }
}

#[test]
fn stale_root_generation_foreign_owner_and_candidate_revocation_withhold_results() {
    let (_fixture, store, root, mut sources) = setup(&["alpha beta"]);
    let built = build(&store, &root, &mut sources);
    let (index, mut guard) = open(&store, &built);
    guard.selected = Some("f".repeat(64));
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            1,
            limits(false),
            &mut guard
        )
        .is_err());
    guard.selected = Some(built.manifest_sha256.clone());
    guard.root.binding.owner_generation += 1;
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            1,
            limits(false),
            &mut guard
        )
        .is_err());
    guard.root = root.clone();
    guard.candidate_checks = 0;
    guard.deny_after_candidates = Some(1);
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            1,
            limits(false),
            &mut guard
        )
        .is_err());
    let mut wrong = root.clone();
    wrong.binding.owner = "f".repeat(64);
    assert!(VerifiedCorpusIndex::open(
        &store,
        &wrong,
        &built.manifest_sha256,
        &built.manifest.canonical_bytes().unwrap(),
        limits(false),
        &mut guard
    )
    .is_err());
}

#[test]
fn continuous_check_and_exact_source_digest_fail_before_successful_generation() {
    let (_fixture, store, root, mut sources) = setup(&["alpha beta"]);
    sources.tamper = true;
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        limits(true),
        &mut Guard::new(&root, true)
    )
    .is_err());
    sources.tamper = false;
    let mut revoked = Guard::new(&root, true);
    revoked.fail_at = Some(40);
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        limits(true),
        &mut revoked
    )
    .is_err());
    let mut finite = limits(true);
    finite.source_bytes = 1;
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        finite,
        &mut Guard::new(&root, true)
    )
    .is_err());
    finite = limits(true);
    finite.postings = 1;
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        finite,
        &mut Guard::new(&root, true)
    )
    .is_err());
    finite = limits(true);
    finite.floating_operations = 1;
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        finite,
        &mut Guard::new(&root, true)
    )
    .is_err());
}

#[test]
fn canonical_manifest_closed_fields_digest_coverage_and_read_only_admission() {
    let (_fixture, store, root, mut sources) = setup(&["alpha beta"]);
    let built = build(&store, &root, &mut sources);
    let bytes = built.manifest.canonical_bytes().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(b' ');
    assert!(CorpusIndexManifest::parse(&trailing).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["complete"] = serde_json::Value::Bool(true);
    assert!(CorpusIndexManifest::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut wrong = built.manifest.clone();
    wrong.source_bytes += 1;
    let mut guard = Guard::new(&root, false);
    guard.selected = Some(wrong.sha256().unwrap());
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &wrong.sha256().unwrap(),
        &wrong.canonical_bytes().unwrap(),
        limits(false),
        &mut guard
    )
    .is_err());
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &built.manifest_sha256,
        &bytes,
        limits(true),
        &mut guard
    )
    .is_err());
    let (index, mut guard) = open(&store, &built);
    let mut finite = limits(false);
    finite.read_bytes = 1;
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            1,
            finite,
            &mut guard
        )
        .is_err());
    assert!(build_corpus_index(
        &store,
        &root,
        &builder(),
        &mut sources,
        &mutation(),
        limits(false),
        &mut Guard::new(&root, true)
    )
    .is_err());
}

#[test]
fn actual_private_page_corruption_missing_page_and_unselected_manifest_refuse() {
    let (fixture, store, root, mut sources) = setup(&["alpha beta"]);
    let built = build(&store, &root, &mut sources);
    let bytes = built.manifest.canonical_bytes().unwrap();
    let mut guard = Guard::new(&root, false);
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &built.manifest_sha256,
        &bytes,
        limits(false),
        &mut guard
    )
    .is_err());
    guard.selected = Some(built.manifest_sha256.clone());
    let path = fixture.object(&built.manifest.model.as_ref().unwrap().sha256);
    let original = fs::read(&path).unwrap();
    let mut bad = original.clone();
    bad[0] ^= 1;
    fs::write(&path, &bad).unwrap();
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &built.manifest_sha256,
        &bytes,
        limits(false),
        &mut guard
    )
    .is_err());
    fs::write(&path, &original).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &built.manifest_sha256,
        &bytes,
        limits(false),
        &mut guard
    )
    .is_err());
}

#[test]
fn record_key_length_and_token_bounds_reject_not_silently_omit() {
    let (_fixture, store, root, mut sources) = setup(&["alpha"]);
    let built = build(&store, &root, &mut sources);
    let mut guard = Guard::new(&root, false);
    let mut m = Meter::new(&root, &builder(), limits(false), None, &mut guard).unwrap();
    let record = pages::record(
        &store,
        &root,
        built.manifest.documents.as_ref().unwrap(),
        0,
        &mut m,
        &mut guard,
    )
    .unwrap();
    assert!(
        CorpusRecord::parse(&record.canonical_bytes().unwrap(), &root, &"f".repeat(64)).is_err()
    );
    let mut bad = record.clone();
    bad.content_bytes = MAX_DOCUMENT_BYTES as u64 + 1;
    assert!(bad.validate().is_err());
    bad = record;
    bad.lifecycle_revision = 0;
    assert!(bad.validate().is_err());
    let oversized = (0..=MAX_DOCUMENT_TERMS)
        .map(|i| format!("word{i} "))
        .collect::<String>();
    assert!(words(oversized.as_bytes(), &root, &mut m, &mut guard).is_err());
    assert!(words(&[255], &root, &mut m, &mut guard).is_err());
}

#[test]
fn reverse_posting_chain_rejects_duplicate_document_and_sequence_alias() {
    let (_fixture, store, root, mut sources) = setup(&["alpha"]);
    let built = build(&store, &root, &mut sources);
    let mut guard = Guard::new(&root, true);
    let mut m = Meter::new(&root, &builder(), limits(true), None, &mut guard).unwrap();
    let id = bucket("alpha");
    let entry = Posting {
        term: "alpha".into(),
        document: 0,
        frequency: 1,
        offset: 0,
    };
    let page = pages::put(
        &store,
        &root,
        pages::Body::Postings {
            bucket: id as u16,
            sequence: 0,
            previous: None,
            entries: vec![entry.clone(), entry],
        },
        &mutation(),
        &mut m,
        &mut guard,
    )
    .unwrap();
    let mut heads = vec![pages::BucketHead::empty(); BUCKETS];
    heads[id] = pages::BucketHead {
        head: Some(page),
        records: 2,
        pages: 1,
    };
    assert!(build::statistics(&store, &root, &heads, &mut m, &mut guard).is_err());
    let mut head = pages::directory(
        &store,
        &root,
        &built.manifest.buckets,
        id,
        &mut m,
        &mut guard,
    )
    .unwrap();
    head.pages = 2;
    assert!(
        pages::postings(&store, &root, id, &head, &mut m, &mut guard, |_, _, _| Ok(
            ()
        ))
        .is_err()
    );
}

#[test]
fn fixed_feature_dimension_and_hundred_thousand_object_descriptor_caps() {
    assert_eq!(MAX_FEATURES, 512);
    assert_eq!(MAX_DIMENSIONS, 8);
    let root = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    let mut guard = Guard::new(&root, false);
    let mut m = Meter::new(&root, &builder(), limits(false), None, &mut guard).unwrap();
    assert!(pages::Span {
        tree: pages::Tree::Documents,
        first: 0,
        count: 100_001,
        height: 0,
        sha256: "d".repeat(64)
    }
    .validate(&root)
    .is_err());
    let counts = (0..100_000_u32)
        .map(|i| (i, i64::from(i % 99)))
        .collect::<Vec<_>>();
    assert_eq!(counts.len(), 100_000);
    assert!(counts.capacity() * std::mem::size_of::<(u32, i64)>() <= 2 * 1024 * 1024);
    assert!(m.work(1_000_000_001, &root, &mut guard).is_err());
}

#[test]
fn independently_observed_builder_tuple_is_required_for_build_open_and_each_query() {
    let (_fixture, store, root, mut sources) = setup(&["alpha beta"]);
    let mut substituted = builder();
    substituted.source_sha256 = "3".repeat(64);
    let mut guard = Guard::new(&root, true);
    assert!(build_corpus_index(
        &store,
        &root,
        &substituted,
        &mut sources,
        &mutation(),
        limits(true),
        &mut guard
    )
    .is_err());
    assert_eq!(guard.checks, 1); // Refused before any private source/map operation.
    let built = build(&store, &root, &mut sources);
    let mut changed = built.manifest.clone();
    changed.builder.runtime_sha256 = "4".repeat(64);
    let mut guard = Guard::new(&root, false);
    guard.selected = Some(changed.sha256().unwrap());
    assert!(VerifiedCorpusIndex::open(
        &store,
        &root,
        &changed.sha256().unwrap(),
        &changed.canonical_bytes().unwrap(),
        limits(false),
        &mut guard
    )
    .is_err());
    let (index, mut guard) = open(&store, &built);
    guard.builder.runtime_sha256 = "5".repeat(64);
    assert!(index
        .query(
            &store,
            CorpusQueryKind::LexicalAnd,
            "alpha",
            1,
            limits(false),
            &mut guard
        )
        .is_err());
    changed.builder.runtime_sha256 = "0".repeat(64);
    assert!(changed.canonical_bytes().is_err());
}
