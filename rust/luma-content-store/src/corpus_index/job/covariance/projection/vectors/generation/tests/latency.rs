//! Ignored NF08 development measurement. A deterministic synthetic corpus of
//! `LUMA_NF08_SCALE_DOCUMENTS` (default 100,000) owner-local UTF8 text objects
//! is built through every actual index phase into one published generation.
//! Sampled first-result latency is then measured over the observed native
//! IndexRead order (`observed::request`: selected manifest blob, open, query,
//! per-hit current proof) with a fresh original read reservation per request.
//! A query returns its whole bounded top-K at once, so first-result latency is
//! request latency. Current C, ACL, observer and TPM callbacks are synthetic
//! here; their wall time is reported apart as `boundary` and the rest as
//! `path`. The store is warm in the page cache; this is development evidence,
//! not acceptance, installed latency or native TPM cost. Run:
//! `LUMA_NF08_SCALE_DOCUMENTS=100000 cargo test --release -p luma-content-store
//! --lib nf08_first_result_latency -- --ignored --nocapture --test-threads=1`
use super::observed::{request, select_manifest, Outcome, Request, ORIGINAL_READ};
use super::*;
use crate::corpus_index::job::tests::SCALE_DOCUMENTS;
use std::time::{Duration, Instant};

const VOCABULARY: usize = 30_000;
const LIMIT: usize = 10;
const WARMUP: usize = 3;
const SEED: u64 = 0x4e46_3038_7365_6172;
const CONSONANTS: &[u8] = b"bcdfghjklmnprstv";
const VOWELS: &[u8] = b"aeiou";

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |v| v.parse().expect("numeric NF08 setting"))
}

struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high - low + 1)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1_u64 << 53) as f64
    }
}

/// A distinct lowercase ASCII word per rank: base-80 consonant-vowel syllables.
fn word(rank: usize) -> String {
    let mut n = rank + 80;
    let mut syllables = Vec::new();
    while n > 0 {
        syllables.push(n % 80);
        n /= 80;
    }
    syllables
        .iter()
        .rev()
        .flat_map(|s| [CONSONANTS[s / 5] as char, VOWELS[s % 5] as char])
        .collect()
}

/// The deterministic corpus and each document's sorted (rank, frequency) terms.
struct Corpus {
    texts: Vec<String>,
    terms: Vec<Vec<(u32, u32)>>,
    long: usize,
}
fn corpus(documents: usize, rng: &mut SplitMix64) -> Corpus {
    let mut total = 0.0;
    let cdf: Vec<f64> = (0..VOCABULARY)
        .map(|rank| {
            total += 1.0 / (rank + 1) as f64;
            total
        })
        .collect();
    let words: Vec<String> = (0..VOCABULARY).map(word).collect();
    let mut value = Corpus {
        texts: Vec::with_capacity(documents),
        terms: Vec::with_capacity(documents),
        long: 0,
    };
    for _ in 0..documents {
        let long = rng.below(100) == 0;
        let length = if long {
            rng.between(1024, 4096)
        } else {
            rng.between(32, 160)
        };
        value.long += usize::from(long);
        let mut ranks = Vec::with_capacity(length);
        let mut text = String::with_capacity(length * 6);
        for i in 0..length {
            let x = rng.unit() * total;
            let rank = cdf.partition_point(|c| *c <= x).min(VOCABULARY - 1);
            if i > 0 {
                text.push(' ');
            }
            text.push_str(&words[rank]);
            ranks.push(rank as u32);
        }
        ranks.sort_unstable();
        let mut terms: Vec<(u32, u32)> = Vec::new();
        for rank in ranks {
            match terms.last_mut() {
                Some((last, count)) if *last == rank => *count += 1,
                _ => terms.push((rank, 1)),
            }
        }
        value.texts.push(text);
        value.terms.push(terms);
    }
    value
}

/// Every document containing all ranks, with its summed term frequency.
fn expected(corpus: &Corpus, ranks: &[u32]) -> Vec<(usize, i64)> {
    corpus
        .terms
        .iter()
        .enumerate()
        .filter_map(|(document, terms)| {
            let mut score = 0_i64;
            for rank in ranks {
                let at = terms.binary_search_by_key(rank, |(r, _)| *r).ok()?;
                score += i64::from(terms[at].1);
            }
            Some((document, score))
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Class {
    name: &'static str,
    kind: CorpusQueryKind,
    terms: usize,
    low: usize,
    high: usize,
}
const CLASSES: [Class; 7] = [
    Class {
        name: "lexical-common",
        kind: CorpusQueryKind::LexicalAnd,
        terms: 1,
        low: 0,
        high: 8,
    },
    Class {
        name: "lexical-mid",
        kind: CorpusQueryKind::LexicalAnd,
        terms: 1,
        low: 200,
        high: 400,
    },
    Class {
        name: "lexical-rare",
        kind: CorpusQueryKind::LexicalAnd,
        terms: 1,
        low: 15_000,
        high: 30_000,
    },
    Class {
        name: "lexical-and2",
        kind: CorpusQueryKind::LexicalAnd,
        terms: 2,
        low: 8,
        high: 200,
    },
    Class {
        name: "lexical-and3",
        kind: CorpusQueryKind::LexicalAnd,
        terms: 3,
        low: 0,
        high: 100,
    },
    Class {
        name: "semantic-1",
        kind: CorpusQueryKind::FeatureLsa,
        terms: 1,
        low: 0,
        high: 400,
    },
    Class {
        name: "semantic-2",
        kind: CorpusQueryKind::FeatureLsa,
        terms: 2,
        low: 0,
        high: 400,
    },
];
fn ranks(class: &Class, rng: &mut SplitMix64) -> Vec<u32> {
    let mut ranks: Vec<u32> = Vec::with_capacity(class.terms);
    while ranks.len() < class.terms {
        let rank = (class.low + rng.below(class.high - class.low)) as u32;
        if !ranks.contains(&rank) {
            ranks.push(rank);
        }
    }
    ranks
}
fn text(ranks: &[u32]) -> String {
    let mut words: Vec<String> = ranks.iter().map(|r| word(*r as usize)).collect();
    words.sort();
    words.join(" ")
}

fn check(class: &Class, corpus: &Corpus, ranks: &[u32], results: &CorpusQueryResults) {
    assert!(results.matches.len() <= LIMIT);
    assert_eq!(results.truncated, results.total_matches > LIMIT as u64);
    for pair in results.matches.windows(2) {
        assert!(pair[0].score >= pair[1].score);
    }
    let document = |hit: &crate::corpus_index::CorpusHit| -> usize {
        hit.reference
            .artifact_id
            .strip_prefix("document-")
            .unwrap()
            .parse()
            .unwrap()
    };
    match class.kind {
        CorpusQueryKind::LexicalAnd => {
            let expected = expected(corpus, ranks);
            assert_eq!(results.total_matches, expected.len() as u64);
            let mut scores: Vec<i64> = expected.iter().map(|(_, s)| *s).collect();
            scores.sort_unstable_by(|a, z| z.cmp(a));
            scores.truncate(LIMIT);
            let returned: Vec<i64> = results.matches.iter().map(|h| h.score).collect();
            assert_eq!(returned, scores);
            for hit in &results.matches {
                let i = document(hit);
                assert!(expected.contains(&(i, hit.score)));
            }
        }
        CorpusQueryKind::FeatureLsa => {
            for hit in &results.matches {
                assert!(hit.score > 0 && hit.score <= 1_000_000);
                assert!(document(hit) < corpus.texts.len());
            }
        }
    }
}

/// Nearest-rank percentile in milliseconds.
fn percentile(times: &[Duration], p: f64) -> f64 {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1].as_secs_f64() * 1000.0
}

#[derive(Default)]
struct Samples {
    times: Vec<Duration>,
    /// Time inside the synthetic fixture boundary callbacks.
    boundary: Vec<Duration>,
    /// Request time outside them: the content-store query path itself.
    path: Vec<Duration>,
    pages: Vec<u64>,
    debited: Vec<u64>,
    calls: Vec<u64>,
    native_checks: Vec<u64>,
    hits: Vec<u64>,
    total_matches: Vec<u64>,
}
impl Samples {
    fn record(&mut self, time: Duration, outcome: &Outcome, results: &CorpusQueryResults) {
        let boundary = Duration::from_nanos(outcome.boundary_nanos);
        self.times.push(time);
        self.boundary.push(boundary);
        self.path.push(time.saturating_sub(boundary));
        self.pages.push(outcome.pages);
        self.debited.push(outcome.debited);
        self.calls.push(outcome.calls.total());
        self.native_checks
            .push(outcome.calls.native_checks(outcome.pages));
        self.hits.push(results.matches.len() as u64);
        self.total_matches.push(results.total_matches);
    }
    fn extend(&mut self, other: &Self) {
        self.times.extend(&other.times);
        self.boundary.extend(&other.boundary);
        self.path.extend(&other.path);
        self.pages.extend(&other.pages);
        self.debited.extend(&other.debited);
        self.calls.extend(&other.calls);
        self.native_checks.extend(&other.native_checks);
        self.hits.extend(&other.hits);
        self.total_matches.extend(&other.total_matches);
    }
    fn report(&self, name: &str) -> f64 {
        let mean = |v: &[u64]| v.iter().sum::<u64>() as f64 / v.len() as f64;
        let max = |v: &[u64]| v.iter().copied().max().unwrap_or(0);
        let p95 = percentile(&self.times, 0.95);
        eprintln!(
            "nf08-latency class {name} samples {} p50_ms {:.3} p95_ms {:.3} max_ms {:.3} \
             boundary p50_ms {:.3} p95_ms {:.3} path p50_ms {:.3} p95_ms {:.3} \
             pages mean {:.1} max {} debit_max {} calls mean {:.1} max {} \
             native_checks>= mean {:.1} max {} hits mean {:.1} total_matches mean {:.1} max {}",
            self.times.len(),
            percentile(&self.times, 0.5),
            p95,
            percentile(&self.times, 1.0),
            percentile(&self.boundary, 0.5),
            percentile(&self.boundary, 0.95),
            percentile(&self.path, 0.5),
            percentile(&self.path, 0.95),
            mean(&self.pages),
            max(&self.pages),
            max(&self.debited),
            mean(&self.calls),
            max(&self.calls),
            mean(&self.native_checks),
            max(&self.native_checks),
            mean(&self.hits),
            mean(&self.total_matches),
            max(&self.total_matches),
        );
        p95
    }
}

fn store_bytes(path: &std::path::Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                bytes += metadata.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

#[test]
#[ignore = "NF08 development measurement: builds a 100,000-object generation"]
fn nf08_first_result_latency_over_observed_native_query_path() {
    let documents = setting("LUMA_NF08_SCALE_DOCUMENTS", 100_000);
    let samples = setting("LUMA_NF08_SAMPLES", 30);
    assert!(
        documents >= SCALE_DOCUMENTS && documents as u64 <= crate::corpus_index::MAX_CORPUS_OBJECTS
    );
    assert!(samples > 0);
    let mut rng = SplitMix64(SEED);
    let started = Instant::now();
    let corpus = corpus(documents, &mut rng);
    let sizes: Vec<usize> = corpus.texts.iter().map(String::len).collect();
    let source: usize = sizes.iter().sum();
    let postings: usize = corpus.terms.iter().map(Vec::len).sum();
    eprintln!(
        "nf08-latency corpus documents {documents} long {} vocabulary-ranks {VOCABULARY} \
         object_bytes min {} mean {:.1} max {} source_bytes {source} distinct_postings {postings} \
         seed {SEED:#x} generate_seconds {:.3}",
        corpus.long,
        sizes.iter().min().unwrap(),
        source as f64 / documents as f64,
        sizes.iter().max().unwrap(),
        started.elapsed().as_secs_f64()
    );
    let texts: Vec<&str> = corpus.texts.iter().map(String::as_str).collect();
    let started = Instant::now();
    let (fixture, store, mut b) = setup(&texts);
    let value = publish(&store, &mut b);
    let selected = select_manifest(&store, &value, &mut b);
    let (bytes, files) = store_bytes(&fixture.path);
    let manifest = &value.manifest;
    eprintln!(
        "nf08-latency generation build_seconds {:.3} entries {} features {} dimensions {} \
         vocabulary {} postings {} source_bytes {} job_read {} job_write {} \
         manifest_bytes {} store_bytes {bytes} store_files {files}",
        started.elapsed().as_secs_f64(),
        manifest.corpus.entry_count,
        manifest.features,
        manifest.dimensions,
        manifest.vocabulary,
        manifest.totals.postings,
        manifest.totals.source_bytes,
        manifest.totals.read_bytes,
        manifest.totals.write_bytes,
        selected.bytes,
    );
    assert_eq!(manifest.corpus.entry_count, documents as u64);
    let sha = manifest.sha256().unwrap();
    // The unit cost of the selected manifest's canonical hash, which the
    // fixture's current_index_generation (and the native Gate's
    // current_generation) recompute on every call.
    let hashes = 10_000_u32;
    let started = Instant::now();
    for _ in 0..hashes {
        assert_eq!(std::hint::black_box(manifest).sha256().unwrap(), sha);
    }
    eprintln!(
        "nf08-latency manifest_sha256 calls {hashes} mean_us {:.3}",
        started.elapsed().as_secs_f64() * 1e6 / f64::from(hashes)
    );
    let owner = manifest.corpus.binding.clone();
    let limits = limits();
    let native = Request {
        store: &store,
        selected: &selected,
        reader_owner: &owner,
        reservation: ORIGINAL_READ,
        limits,
        deny_artifact: None,
    };
    eprintln!(
        "nf08-latency query limit {LIMIT} warmup {WARMUP} samples-per-class {samples} \
         reservation {ORIGINAL_READ} read_bytes {} floating_operations {}",
        limits.read_bytes, limits.floating_operations
    );
    let mut all = Samples::default();
    for class in &CLASSES {
        let mut measured = Samples::default();
        for sample in 0..WARMUP + samples {
            let ranks = ranks(class, &mut rng);
            let query = text(&ranks);
            let started = Instant::now();
            let outcome = request(&native, &mut b, &sha, class.kind, &query, LIMIT);
            let elapsed = started.elapsed();
            let results = match &outcome.result {
                Ok(results) => results,
                Err(error) => panic!("{} {query:?} refused: {error}", class.name),
            };
            check(class, &corpus, &ranks, results);
            if sample >= WARMUP {
                measured.record(elapsed, &outcome, results);
            }
        }
        measured.report(class.name);
        all.extend(&measured);
    }
    let p95 = all.report("overall");
    eprintln!("nf08-latency target p95_ms<=500 met {}", p95 <= 500.0);
}
