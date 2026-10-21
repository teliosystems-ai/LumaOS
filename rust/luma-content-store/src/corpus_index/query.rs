use super::*;
use pages::{Body, BucketHead, Feature};
use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, VecDeque};

/// Higher scores, then lower document ordinals, are better. The reverse heap
/// keeps the worst retained result at its root; no corpus-sized ranking vector
/// or full sort is needed. This is derivative DATA, never an access decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ranked {
    ordinal: u32,
    score: i64,
}
impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| other.ordinal.cmp(&self.ordinal))
    }
}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
struct TopMatches {
    limit: usize,
    maximum: u32,
    total: u64,
    heap: BinaryHeap<Reverse<Ranked>>,
}
impl TopMatches {
    fn new(limit: usize, maximum: u64) -> Result<Self> {
        if !(1..=crate::MAX_SEARCH_RESULTS).contains(&limit) || maximum > MAX_CORPUS_OBJECTS {
            return Err("query rank capacity exceeds the finite corpus profile".into());
        }
        Ok(Self {
            limit,
            maximum: u32::try_from(maximum)?,
            total: 0,
            heap: BinaryHeap::with_capacity(limit),
        })
    }
    fn offer(&mut self, ordinal: u32, score: i64) -> Result<()> {
        if ordinal >= self.maximum || score <= 0 || self.total >= u64::from(self.maximum) {
            return Err("query rank row exceeds its exact positive ordinal coverage".into());
        }
        self.total += 1;
        let row = Ranked { ordinal, score };
        if self.heap.len() < self.limit {
            self.heap.push(Reverse(row));
        } else if let Some(mut worst) = self.heap.peek_mut() {
            if row > worst.0 {
                *worst = Reverse(row);
            }
        }
        Ok(())
    }
    fn finish(mut self) -> (u64, Vec<Ranked>) {
        let mut retained = Vec::with_capacity(self.heap.len());
        while let Some(Reverse(row)) = self.heap.pop() {
            retained.push(row);
        }
        retained.reverse();
        (self.total, retained)
    }
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusQueryKind {
    LexicalAnd,
    FeatureLsa,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusHit {
    pub reference: VersionReference,
    pub format: Format,
    pub score: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusQueryResults {
    pub schema_version: u32,
    pub profile: String,
    pub kind: CorpusQueryKind,
    pub canonical_query: String,
    pub corpus_sha256: String,
    pub index_sha256: String,
    pub matches: Vec<CorpusHit>,
    pub total_matches: u64,
    pub truncated: bool,
}

impl VerifiedCorpusIndex {
    /// Full structural/coverage verification of an independently selected fixed-
    /// builder generation. Hashes alone do NOT authenticate the builder, its
    /// algorithm output, a publisher or a grant. `current_index_generation` must
    /// independently establish that provenance on every callback. This function
    /// does not recompute source TF-IDF or certify retrieval quality/latency.
    pub fn open<B: CorpusIndexBoundary>(
        store: &ObjectStore,
        current_corpus: &MapRoot,
        selected_manifest_sha256: &str,
        manifest_bytes: &[u8],
        limits: CorpusIndexLimits,
        b: &mut B,
    ) -> Result<Self> {
        hash(selected_manifest_sha256)?;
        let manifest = CorpusIndexManifest::parse(manifest_bytes)?;
        if &manifest.corpus != current_corpus || manifest.sha256()? != selected_manifest_sha256 {
            return Err("selected index does not bind exact current corpus/manifest".into());
        }
        let mut m = readonly(
            current_corpus,
            &manifest.builder,
            limits,
            selected_manifest_sha256,
            b,
        )?;
        let mut ordinal = 0_u32;
        let mut source = 0_u64;
        // Consume each authenticated document leaf once within this operation.
        // This is only a bounded queue of already decoded DATA, not a selected
        // generation, reusable authority or a filesystem-immutability cache.
        let mut document_rows = VecDeque::new();
        m.read(512 * 1024 * 1024)?;
        let count = store.visit_map_checked(
            current_corpus,
            IoBudget {
                read_bytes: 512 * 1024 * 1024,
                write_bytes: 0,
                new_files: 0,
            },
            b,
            |key, value, b| {
                m.check(current_corpus, b)?;
                let actual = CorpusRecord::parse(value, current_corpus, key)?;
                let span = manifest
                    .documents
                    .as_ref()
                    .ok_or("index omitted nonempty corpus documents")?;
                if document_rows.is_empty() {
                    let Body::Documents { first, records } =
                        pages::at(store, current_corpus, span, ordinal, &mut m, b)?
                    else {
                        return Err("document coverage reached another page type".into());
                    };
                    if first != ordinal || records.is_empty() {
                        return Err("document leaf repeats or skips the exact corpus prefix".into());
                    }
                    document_rows.extend(records);
                }
                let indexed = document_rows
                    .pop_front()
                    .ok_or("document coverage lost a row")?;
                if indexed != actual {
                    return Err(
                        "index document differs from exact authenticated corpus entry".into(),
                    );
                }
                source = source
                    .checked_add(actual.content_bytes)
                    .ok_or("index source coverage overflow")?;
                b.current_candidate(current_corpus, &actual)?;
                ordinal += 1;
                Ok(())
            },
        )?;
        if count != current_corpus.entry_count
            || u64::from(ordinal) != count
            || source != manifest.source_bytes
            || !document_rows.is_empty()
        {
            return Err("index full corpus/source coverage differs".into());
        }
        let heads = directory(store, &manifest, &mut m, b)?;
        let (vocabulary, selected, postings) =
            build::statistics(store, current_corpus, &heads, &mut m, b)?;
        if vocabulary != manifest.vocabulary_terms
            || postings != manifest.posting_records
            || selected.len() != usize::from(manifest.features)
        {
            return Err(
                "verified lexical vocabulary/coverage differs from index descriptor".into(),
            );
        }
        let features = model(store, &manifest, &mut m, b)?;
        for (feature, (term, df)) in features.iter().zip(&selected) {
            if &feature.term != term
                || feature.documents != *df
                || feature.idf_bits != build::idf(current_corpus.entry_count, *df).to_bits()
                || feature.projection_bits.len() != usize::from(manifest.dimensions)
            {
                return Err(
                    "feature model does not bind deterministic full-corpus DF selection".into(),
                );
            }
        }
        let dimensions = usize::from(manifest.dimensions);
        for i in 0..dimensions {
            for j in 0..dimensions {
                m.work(features.len() as u64, current_corpus, b)?;
                let dot = features
                    .iter()
                    .map(|f| {
                        f64::from_bits(f.projection_bits[i]) * f64::from_bits(f.projection_bits[j])
                    })
                    .sum::<f64>();
                if (dot - if i == j { 1.0 } else { 0.0 }).abs() > 1e-7 {
                    return Err("selected feature basis is not orthonormal".into());
                }
            }
        }
        let mut rows_seen = 0_u32;
        if let Some(span) = &manifest.vectors {
            pages::walk(store, current_corpus, span, &mut m, b, &mut |body, m, b| {
                let Body::Vectors { first, rows } = body else {
                    return Err("vector coverage reached another page type".into());
                };
                if *first != rows_seen || rows.iter().any(|row| row.len() != dimensions) {
                    return Err("vector dimensions or contiguous coverage differ".into());
                }
                rows_seen = rows_seen
                    .checked_add(rows.len() as u32)
                    .ok_or("vector coverage overflow")?;
                m.check(current_corpus, b)
            })?;
        }
        if u64::from(rows_seen) != count {
            return Err("selected index lost vector rows".into());
        }
        m.check(current_corpus, b)?;
        Ok(Self {
            manifest,
            manifest_sha256: selected_manifest_sha256.to_owned(),
        })
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Complete chain scans, not an asserted 500ms native index. The selected
    /// corpus is owner-generation scoped; a refused current-candidate check
    /// withholds the ENTIRE result rather than exposing filtered private counts.
    pub fn query<B: CorpusIndexBoundary>(
        &self,
        store: &ObjectStore,
        kind: CorpusQueryKind,
        query: &str,
        limit: usize,
        limits: CorpusIndexLimits,
        b: &mut B,
    ) -> Result<CorpusQueryResults> {
        let canonical = crate::canonical_search_query(query, limit)?;
        let root = &self.manifest.corpus;
        let mut m = readonly(
            root,
            &self.manifest.builder,
            limits,
            &self.manifest_sha256,
            b,
        )?;
        let mut ranked = TopMatches::new(limit, root.entry_count)?;
        match kind {
            CorpusQueryKind::LexicalAnd => {
                lexical(store, &self.manifest, &canonical, &mut ranked, &mut m, b)?
            }
            CorpusQueryKind::FeatureLsa => {
                semantic(store, &self.manifest, &canonical, &mut ranked, &mut m, b)?
            }
        };
        // At most64 retained rows; each heap pop traverses at most six levels.
        // Reserve comparison work before draining, not after protected results.
        m.work((ranked.heap.len() as u64) * 16, root, b)?;
        let (total_matches, ranked) = ranked.finish();
        let mut matches = Vec::new();
        for Ranked { ordinal, score } in ranked {
            m.check(root, b)?;
            let record = pages::record(
                store,
                root,
                self.manifest
                    .documents
                    .as_ref()
                    .ok_or("query document tree absent")?,
                ordinal,
                &mut m,
                b,
            )?;
            b.current_candidate(root, &record)?;
            m.check(root, b)?;
            matches.push(CorpusHit {
                reference: record.reference,
                format: record.format,
                score,
            });
        }
        // Recheck EVERY delivered candidate after all private reads, then the
        // generation/subject again. No cached authorization or partial output.
        for hit in &matches {
            let key = root.corpus_key(&hit.reference.artifact_id)?;
            m.read(PAGE_READ * 9)?;
            let proof = store.lookup_map(
                root,
                &key,
                IoBudget {
                    read_bytes: PAGE_READ * 9,
                    write_bytes: 0,
                    new_files: 0,
                },
                b,
            )?;
            let bytes = proof
                .verify(root)?
                .ok_or("query candidate no longer in current corpus")?;
            let record = CorpusRecord::parse(&bytes, root, &key)?;
            if record.reference != hit.reference {
                return Err("query candidate immutable reference changed".into());
            }
            b.current_candidate(root, &record)?;
            m.check(root, b)?;
        }
        let result = CorpusQueryResults {
            schema_version: 1,
            profile: CORPUS_INDEX_PROFILE.into(),
            kind,
            canonical_query: canonical,
            corpus_sha256: self.manifest.corpus_sha256.clone(),
            index_sha256: self.manifest_sha256.clone(),
            matches,
            total_matches,
            truncated: total_matches > limit as u64,
        };
        if serde_json::to_vec(&result)?.len() > crate::MAX_SEARCH_RESPONSE_BYTES {
            return Err("query response exceeds fixed output bound".into());
        }
        m.check(root, b)?;
        Ok(result)
    }
}

fn readonly<B: CorpusIndexBoundary>(
    root: &MapRoot,
    builder: &BuilderIdentity,
    limits: CorpusIndexLimits,
    generation: &str,
    b: &mut B,
) -> Result<Meter> {
    if limits.write_bytes != 0 {
        return Err("index read may not request write admission".into());
    }
    Meter::new(root, builder, limits, Some(generation.to_owned()), b)
}
fn directory<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    manifest: &CorpusIndexManifest,
    m: &mut Meter,
    b: &mut B,
) -> Result<Vec<BucketHead>> {
    let root = &manifest.corpus;
    let mut heads = Vec::with_capacity(BUCKETS);
    pages::walk(store, root, &manifest.buckets, m, b, &mut |body, m, b| {
        let Body::Buckets { first, rows } = body else {
            return Err("directory closure reached another page type".into());
        };
        if *first as usize != heads.len() {
            return Err("directory does not cover exact ordered bucket prefix".into());
        }
        heads.extend_from_slice(rows);
        m.check(root, b)
    })?;
    if heads.len() != BUCKETS {
        return Err("directory omits corpus posting buckets".into());
    }
    Ok(heads)
}
fn model<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    manifest: &CorpusIndexManifest,
    m: &mut Meter,
    b: &mut B,
) -> Result<Vec<Feature>> {
    let root = &manifest.corpus;
    let mut result = Vec::new();
    if let Some(span) = &manifest.model {
        pages::walk(store, root, span, m, b, &mut |body, m, b| {
            let Body::Model { first, features } = body else {
                return Err("model closure reached another page type".into());
            };
            if *first as usize != result.len() {
                return Err("model feature rows lost ordered coverage".into());
            }
            result.extend_from_slice(features);
            m.check(root, b)
        })?;
    }
    if result.len() != usize::from(manifest.features) {
        return Err("model feature count differs".into());
    }
    Ok(result)
}
fn lexical<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    manifest: &CorpusIndexManifest,
    query: &str,
    ranked: &mut TopMatches,
    m: &mut Meter,
    b: &mut B,
) -> Result<()> {
    let root = &manifest.corpus;
    let terms: Vec<_> = query.split(' ').collect();
    // Fixed scalar state per object, never a term's unbounded list of IDs.
    let mut counts = vec![(0_u8, 0_u64); root.entry_count as usize];
    let mut buckets: BTreeMap<usize, Vec<(usize, &str)>> = BTreeMap::new();
    for (i, term) in terms.iter().enumerate() {
        buckets.entry(bucket(term)).or_default().push((i, term));
    }
    for (id, selected) in buckets {
        let head = pages::directory(store, root, &manifest.buckets, id, m, b)?;
        pages::postings(store, root, id, &head, m, b, |entry, m, b| {
            m.work(1, root, b)?;
            if let Some((index, _)) = selected.iter().find(|(_, term)| *term == entry.term) {
                let row = counts
                    .get_mut(entry.document as usize)
                    .ok_or("posting ordinal outside corpus")?;
                let bit = 1_u8 << *index;
                if row.0 & bit != 0 {
                    return Err("duplicate current query posting".into());
                }
                row.0 |= bit;
                row.1 = row
                    .1
                    .checked_add(u64::from(entry.frequency))
                    .ok_or("lexical score overflow")?;
            }
            Ok(())
        })?;
    }
    let all = ((1_u16 << terms.len()) - 1) as u8;
    for (i, (mask, score)) in counts.into_iter().enumerate() {
        m.work(1, root, b)?;
        if mask == all {
            // A push or root replacement traverses at most six heap levels.
            m.work(16, root, b)?;
            ranked.offer(i as u32, i64::try_from(score)?)?;
        }
    }
    Ok(())
}
fn semantic<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    manifest: &CorpusIndexManifest,
    query: &str,
    ranked: &mut TopMatches,
    m: &mut Meter,
    b: &mut B,
) -> Result<()> {
    let root = &manifest.corpus;
    let features = model(store, manifest, m, b)?;
    if features.is_empty() {
        return Ok(());
    }
    let frequencies: Vec<_> = features
        .iter()
        .map(|f| (f.term.clone(), f.documents))
        .collect();
    let idfs: Vec<_> = features
        .iter()
        .map(|f| f64::from_bits(f.idf_bits))
        .collect();
    let projection: Vec<Vec<f64>> = features
        .iter()
        .map(|f| {
            f.projection_bits
                .iter()
                .map(|x| f64::from_bits(*x))
                .collect()
        })
        .collect();
    let tf = words(query.as_bytes(), root, m, b)?;
    let weights = build::weights(&tf, &frequencies, &idfs)?;
    let latent = build::project(&weights, &projection, usize::from(manifest.dimensions))?;
    if latent.iter().all(|x| *x == 0.0) {
        return Ok(());
    }
    if let Some(span) = &manifest.vectors {
        pages::walk(store, root, span, m, b, &mut |body, m, b| {
            let Body::Vectors { first, rows } = body else {
                return Err("semantic traversal reached another page type".into());
            };
            for (index, row) in rows.iter().enumerate() {
                if row.len() != latent.len() {
                    return Err("semantic coordinate dimensions changed".into());
                }
                m.work(row.len() as u64, root, b)?;
                let cosine = row
                    .iter()
                    .zip(&latent)
                    .map(|(bits, q)| f64::from(f32::from_bits(*bits)) * q)
                    .sum::<f64>();
                if !cosine.is_finite() {
                    return Err("semantic cosine is not finite".into());
                }
                let score = (cosine.clamp(-1.0, 1.0) * 1_000_000.0).round() as i64;
                if score > 0 {
                    m.work(16, root, b)?;
                    ranked.offer(*first + index as u32, score)?;
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}
