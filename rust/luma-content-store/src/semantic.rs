//! Rebuildable owner-local latent semantic indexing, not an access authority.
//! TF-IDF and a truncated singular-value projection are computed from only the
//! exact admitted published selection. No persisted index, external model,
//! network, spelling expansion or unselected corpus supplies a result.
use crate::{queries, storage, Boundary, DecisionKind, Repository, ResourceBudget, Result};
use luma_content::{ArtifactVersion, Format, VersionReference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_SEMANTIC_VOCABULARY: usize = 4096;
pub const MAX_SEMANTIC_FEATURES: usize = 512;
pub const MAX_SEMANTIC_DIMENSIONS: usize = 8;
const MAX_ROTATIONS: usize = 16384;
const CHECK_BYTES: usize = 32768;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticHit {
    pub reference: VersionReference,
    pub format: Format,
    /// Rounded positive cosine similarity, not confidence or authorization.
    pub cosine_millionths: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticResults {
    pub algorithm: String,
    pub canonical_query: String,
    pub selection_sha256: String,
    pub index_descriptor_sha256: String,
    pub selected_versions: usize,
    pub vocabulary_terms: usize,
    pub indexed_features: usize,
    pub requested_dimensions: usize,
    pub effective_dimensions: usize,
    pub matches: Vec<SemanticHit>,
    pub total_matches: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticCollectionResults {
    pub collection: VersionReference,
    pub search: SemanticResults,
}

pub fn validate_semantic_query(query: &str, limit: usize, dimensions: usize) -> Result<String> {
    if !(1..=MAX_SEMANTIC_DIMENSIONS).contains(&dimensions) {
        return Err("latent semantic dimensions exceed their fixed bound".into());
    }
    queries::canonical_search_query(query, limit)
}

struct Document {
    reference: VersionReference,
    format: Format,
    counts: BTreeMap<usize, u32>,
}

fn tokens(
    bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
    mut word: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut start = None;
    let mut ascii = true;
    for offset in 0..=bytes.len() {
        if offset % CHECK_BYTES == 0 {
            check()?;
        }
        let value = bytes.get(offset).copied();
        if value.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || !b.is_ascii()) {
            start.get_or_insert(offset);
            ascii &= value.is_some_and(|b| b.is_ascii_alphanumeric());
        } else if let Some(begin) = start.take() {
            if ascii && offset - begin <= queries::MAX_SEARCH_TERM_BYTES {
                word(&std::str::from_utf8(&bytes[begin..offset])?.to_ascii_lowercase())?;
            }
            ascii = true;
        }
    }
    check()
}

fn normalize(values: &mut [f64]) -> Result<bool> {
    let norm = values.iter().map(|v| v * v).sum::<f64>().sqrt();
    if !norm.is_finite() {
        return Err("nonfinite latent semantic norm".into());
    }
    if norm <= 1e-12 {
        return Ok(false);
    }
    for value in values {
        *value /= norm;
    }
    Ok(true)
}

/// Deterministic symmetric Jacobi decomposition of the at-most64-square Gram
/// matrix. Every bounded rotation group rechecks current caller authority.
fn eigen(
    mut matrix: Vec<Vec<f64>>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Vec<f64>, Vec<Vec<f64>>)> {
    let n = matrix.len();
    let mut vectors = vec![vec![0.0; n]; n];
    for (i, row) in vectors.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    let scale = matrix
        .iter()
        .enumerate()
        .map(|(i, row)| row[i].abs())
        .sum::<f64>()
        .max(1.0);
    let mut converged = n < 2;
    for iteration in 0..MAX_ROTATIONS {
        if iteration % 16 == 0 {
            check()?;
        }
        let (mut p, mut q, mut largest) = (0, 0, 0.0);
        for (i, row) in matrix.iter().enumerate() {
            for (j, value) in row.iter().enumerate().skip(i + 1) {
                if value.abs() > largest {
                    p = i;
                    q = j;
                    largest = value.abs();
                }
            }
        }
        if largest <= 1e-12 * scale {
            converged = true;
            break;
        }
        let angle = 0.5 * (2.0 * matrix[p][q]).atan2(matrix[q][q] - matrix[p][p]);
        let (s, c) = angle.sin_cos();
        let (a, b, d) = (matrix[p][p], matrix[p][q], matrix[q][q]);
        matrix[p][p] = c * c * a - 2.0 * s * c * b + s * s * d;
        matrix[q][q] = s * s * a + 2.0 * s * c * b + c * c * d;
        matrix[p][q] = 0.0;
        matrix[q][p] = 0.0;
        for i in 0..n {
            if i != p && i != q {
                let (x, y) = (matrix[i][p], matrix[i][q]);
                matrix[i][p] = c * x - s * y;
                matrix[p][i] = matrix[i][p];
                matrix[i][q] = s * x + c * y;
                matrix[q][i] = matrix[i][q];
            }
            let (x, y) = (vectors[i][p], vectors[i][q]);
            vectors[i][p] = c * x - s * y;
            vectors[i][q] = s * x + c * y;
        }
    }
    check()?;
    if !converged
        || matrix
            .iter()
            .flatten()
            .chain(vectors.iter().flatten())
            .any(|v| !v.is_finite())
    {
        return Err("bounded latent semantic decomposition did not converge".into());
    }
    let values = (0..n).map(|i| matrix[i][i].max(0.0)).collect();
    Ok((values, vectors))
}

fn rank(
    documents: &[Document],
    vocabulary: &BTreeMap<String, usize>,
    query: &str,
    dimensions: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(usize, usize, Vec<(usize, u32)>)> {
    let n = documents.len();
    let mut frequencies = vec![0usize; vocabulary.len()];
    for document in documents {
        check()?;
        for term in document.counts.keys() {
            frequencies[*term] += 1;
        }
    }
    let mut features: Vec<_> = vocabulary
        .iter()
        .filter(|(_, id)| frequencies[**id] > 0)
        .collect();
    // Most widely observed terms first, with lexical ties, makes truncation
    // deterministic and independent of query. Query-only terms never create
    // learned dimensions or an apparent index result.
    features.sort_by(|(a, ai), (b, bi)| frequencies[**bi].cmp(&frequencies[**ai]).then(a.cmp(b)));
    features.truncate(MAX_SEMANTIC_FEATURES);
    features.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut matrix = vec![vec![0.0; features.len()]; n];
    let query_terms: Vec<_> = query.split(' ').collect();
    let mut query_vector = vec![0.0; features.len()];
    for (j, (word, id)) in features.iter().enumerate() {
        let inverse = ((n + 1) as f64 / (frequencies[**id] + 1) as f64).ln() + 1.0;
        for (i, document) in documents.iter().enumerate() {
            let count = document.counts.get(*id).copied().unwrap_or(0);
            if count > 0 {
                matrix[i][j] = (1.0 + f64::from(count).ln()) * inverse;
            }
        }
        if query_terms.binary_search(&word.as_str()).is_ok() {
            query_vector[j] = inverse;
        }
    }
    for row in &mut matrix {
        normalize(row)?;
    }
    let query_known = normalize(&mut query_vector)?;
    let mut gram = vec![vec![0.0; n]; n];
    let mut products = vec![0.0; n];
    for i in 0..n {
        check()?;
        products[i] = matrix[i]
            .iter()
            .zip(&query_vector)
            .map(|(x, y)| x * y)
            .sum();
        for j in i..n {
            let dot = matrix[i].iter().zip(&matrix[j]).map(|(x, y)| x * y).sum();
            gram[i][j] = dot;
            gram[j][i] = dot;
        }
    }
    let (values, vectors) = eigen(gram, check)?;
    let mut order: Vec<_> = (0..n).filter(|i| values[*i] > 1e-10).collect();
    order.sort_by(|a, b| values[*b].total_cmp(&values[*a]).then(a.cmp(b)));
    order.truncate(dimensions);
    if !query_known {
        check()?;
        return Ok((features.len(), order.len(), Vec::new()));
    }
    let mut projected: Vec<_> = order
        .iter()
        .map(|j| (0..n).map(|i| vectors[i][*j] * products[i]).sum::<f64>() / values[*j].sqrt())
        .collect();
    if !normalize(&mut projected)? {
        return Ok((features.len(), order.len(), Vec::new()));
    }
    let mut hits = Vec::new();
    for (i, row) in vectors.iter().enumerate() {
        check()?;
        let mut latent: Vec<_> = order.iter().map(|j| row[*j] * values[*j].sqrt()).collect();
        if !normalize(&mut latent)? {
            continue;
        }
        let cosine = latent
            .iter()
            .zip(&projected)
            .map(|(x, y)| x * y)
            .sum::<f64>();
        if !cosine.is_finite() {
            return Err("nonfinite latent semantic score".into());
        }
        let score = (cosine.clamp(0.0, 1.0) * 1_000_000.0).round() as u32;
        if score > 0 {
            hits.push((i, score));
        }
    }
    hits.sort_by(|(a, sa), (b, sb)| {
        sb.cmp(sa).then(
            documents[*a]
                .reference
                .artifact_id
                .cmp(&documents[*b].reference.artifact_id),
        )
    });
    check()?;
    Ok((features.len(), order.len(), hits))
}

impl Repository {
    /// The live boundary covers the COMPLETE exact selection before any
    /// private snapshot, not just returned hits. Semantic similarity is never
    /// an ACL, a grant, evidence of truth or a reason to enlarge that selection.
    pub fn semantic_search_selected(
        &self,
        references: &[VersionReference],
        query: &str,
        limit: usize,
        dimensions: usize,
        boundary: &mut impl Boundary,
    ) -> Result<SemanticResults> {
        let selection = queries::canonical_search_selection(references)?;
        let query = validate_semantic_query(query, limit, dimensions)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        self.semantic_snapshot(
            references, selection, query, limit, dimensions, snapshot, boundary,
        )
    }

    pub fn semantic_search_collection(
        &self,
        expected: &VersionReference,
        query: &str,
        limit: usize,
        dimensions: usize,
        boundary: &mut impl Boundary,
    ) -> Result<SemanticCollectionResults> {
        crate::collections::reference(expected)?;
        let query = validate_semantic_query(query, limit, dimensions)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        snapshot.require_live(&expected.artifact_id)?;
        let source = snapshot
            .records
            .iter()
            .find(|(record, plan, _)| {
                record.plan.decision == DecisionKind::Published
                    && plan.source_kind() == crate::SourceKind::CollectionIntent
                    && plan.resulting() == expected
            })
            .map(|(_, _, source)| crate::CollectionSource::from_canonical(source))
            .transpose()?
            .ok_or("exact typed semantic collection unavailable")?;
        storage::repository_check(self, None, boundary)?;
        let selection = if source.members.is_empty() {
            b"[]".to_vec()
        } else {
            queries::canonical_search_selection(&source.members)?
        };
        let search = self.semantic_snapshot(
            &source.members,
            selection,
            query,
            limit,
            dimensions,
            snapshot,
            boundary,
        )?;
        let result = SemanticCollectionResults {
            collection: expected.clone(),
            search,
        };
        if serde_json::to_vec(&result)?.len() > queries::MAX_SEARCH_RESPONSE_BYTES {
            return Err("semantic collection response exceeds fixed bound".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    fn semantic_snapshot(
        &self,
        references: &[VersionReference],
        selection: Vec<u8>,
        query: String,
        limit: usize,
        dimensions: usize,
        snapshot: crate::Snapshot,
        boundary: &mut impl Boundary,
    ) -> Result<SemanticResults> {
        for reference in references {
            snapshot.require_live(&reference.artifact_id)?;
        }
        let mut selected = BTreeMap::new();
        for (record, plan, _) in &snapshot.records {
            storage::repository_check(self, None, boundary)?;
            if record.plan.decision == DecisionKind::Published
                && references.iter().any(|r| r == plan.resulting())
                && selected
                    .insert(plan.artifact_id(), plan.payload.as_slice())
                    .is_some()
            {
                return Err("ambiguous exact semantic search reference".into());
            }
        }
        if selected.len() != references.len() {
            return Err("exact semantic selected published version unavailable".into());
        }
        let mut vocabulary = BTreeMap::new();
        let mut documents = Vec::new();
        for payload in selected.into_values() {
            storage::repository_check(self, None, boundary)?;
            let version: ArtifactVersion = luma_content::reopen(payload, &self.binding)?;
            let mut counts = BTreeMap::<usize, u32>::new();
            tokens(
                version.content(),
                &mut || storage::repository_check(self, None, boundary),
                |word| {
                    let next = vocabulary.len();
                    let id = if let Some(id) = vocabulary.get(word) {
                        *id
                    } else {
                        if next == MAX_SEMANTIC_VOCABULARY {
                            return Err("semantic corpus vocabulary exceeds its fixed bound".into());
                        }
                        vocabulary.insert(word.to_owned(), next);
                        next
                    };
                    let count = counts.entry(id).or_default();
                    *count = count
                        .checked_add(1)
                        .ok_or("semantic term frequency overflow")?;
                    Ok(())
                },
            )?;
            documents.push(Document {
                reference: version.reference()?,
                format: version.receipt().format,
                counts,
            });
        }
        // A reproducible cache key commits the owner-generation, algorithm,
        // dimensions and exact immutable refs, not platform-sensitive floats.
        let descriptor = serde_json::json!({"schema_version":1,"algorithm":"tfidf-lsa-jacobi-v1",
            "binding":self.binding,"references":references,"dimensions":dimensions,
            "maximum_vocabulary":MAX_SEMANTIC_VOCABULARY,"maximum_features":MAX_SEMANTIC_FEATURES});
        let index_descriptor_sha256 = luma_content::sha256(&serde_json::to_vec(&descriptor)?);
        let (features, effective, hits) =
            rank(&documents, &vocabulary, &query, dimensions, &mut || {
                storage::repository_check(self, None, boundary)
            })?;
        let total_matches = hits.len();
        let mut result = SemanticResults {
            algorithm: "tfidf-lsa-jacobi-v1".into(),
            canonical_query: query,
            selection_sha256: luma_content::sha256(&selection),
            index_descriptor_sha256,
            selected_versions: references.len(),
            vocabulary_terms: vocabulary.len(),
            indexed_features: features,
            requested_dimensions: dimensions,
            effective_dimensions: effective,
            matches: Vec::new(),
            total_matches,
            truncated: false,
        };
        for (i, score) in hits.into_iter().take(limit) {
            storage::repository_check(self, None, boundary)?;
            result.matches.push(SemanticHit {
                reference: documents[i].reference.clone(),
                format: documents[i].format,
                cosine_millionths: score,
            });
            if serde_json::to_vec(&result)?.len() > queries::MAX_SEARCH_RESPONSE_BYTES - 32 {
                result.matches.pop();
                break;
            }
        }
        result.truncated = result.matches.len() < total_matches;
        if serde_json::to_vec(&result)?.len() > queries::MAX_SEARCH_RESPONSE_BYTES {
            return Err("semantic search response exceeds its fixed bound".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_token_boundaries_do_not_split_unicode_identifiers_or_long_words() {
        let input = format!("cat café cat_dog {} CATS", "z".repeat(65));
        let mut words = Vec::new();
        tokens(input.as_bytes(), &mut || Ok(()), |s| {
            words.push(s.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(words, vec!["cat", "cats"]);
    }
    #[test]
    fn semantic_decomposition_reconstructs_symmetric_gram_and_checks_revocation() {
        let input = vec![
            vec![1.0, 0.6, 0.1],
            vec![0.6, 1.0, 0.3],
            vec![0.1, 0.3, 1.0],
        ];
        let (values, vectors) = eigen(input.clone(), &mut || Ok(())).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let reconstructed = (0..3)
                    .map(|k| vectors[i][k] * values[k] * vectors[j][k])
                    .sum::<f64>();
                assert!((reconstructed - input[i][j]).abs() < 1e-9);
            }
        }
        assert!(eigen(input, &mut || Err("revoked".into())).is_err());
        assert!(validate_semantic_query("cat", 1, 0).is_err());
        assert!(validate_semantic_query("cat", 1, 9).is_err());
    }
    #[test]
    fn semantic_maximum_dense_and_degenerate_matrices_are_bounded_and_reconstruct() {
        for n in [1, 8, 64] {
            let rows: Vec<Vec<f64>> = (0..n)
                .map(|i| {
                    (0..32)
                        .map(|j| f64::from(((i * 17 + j * 23 + i * j * 7) % 41) as u32) / 41.0)
                        .collect()
                })
                .collect();
            let gram: Vec<Vec<f64>> = rows
                .iter()
                .map(|a| {
                    rows.iter()
                        .map(|b| a.iter().zip(b).map(|(x, y)| x * y).sum())
                        .collect()
                })
                .collect();
            let (values, vectors) = eigen(gram.clone(), &mut || Ok(())).unwrap();
            for i in 0..n {
                for j in 0..n {
                    let restored = (0..n)
                        .map(|k| vectors[i][k] * values[k] * vectors[j][k])
                        .sum::<f64>();
                    assert!((restored - gram[i][j]).abs() < 1e-8);
                }
            }
        }
        let (values, _) = eigen(vec![vec![1.0; 8]; 8], &mut || Ok(())).unwrap();
        assert_eq!(values.iter().filter(|v| **v > 1e-8).count(), 1);
        let mut checks = 0;
        let input = vec![
            vec![1.0, 0.6, 0.1],
            vec![0.6, 1.0, 0.3],
            vec![0.1, 0.3, 1.0],
        ];
        assert!(eigen(input, &mut || {
            checks += 1;
            if checks >= 2 {
                Err("revoked mid-decomposition".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert!(checks >= 2);
    }
}
