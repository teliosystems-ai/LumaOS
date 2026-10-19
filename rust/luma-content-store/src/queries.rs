//! Owner-local reads rebuilt from the complete verified outcome history.
//!
//! Search is an AND of whole ASCII alphanumeric words in canonical content
//! bytes, not a semantic, stemming, JSON-property, or CSV-cell query language.
//! Non-ASCII bytes and underscores remain word constituents: an ASCII query
//! cannot match a partial Unicode word or a substring of an identifier.
use crate::{storage, Boundary, DecisionKind, Repository, ResourceBudget, Result};
use luma_content::{ArtifactVersion, Format, VersionReference};
use serde::{Deserialize, Serialize};

pub const MAX_SEARCH_QUERY_BYTES: usize = 256;
pub const MAX_SEARCH_TERMS: usize = 8;
pub const MAX_SEARCH_TERM_BYTES: usize = 64;
pub const MAX_SEARCH_RESULTS: usize = 64;
pub const MAX_SEARCH_RESPONSE_BYTES: usize = 65_536;
pub const MAX_SEARCH_SELECTION: usize = 64;
const CHECK_INTERVAL: usize = 32 * 1024;

/// An exact occurrence in canonical content bytes. This is not provenance or
/// authority evidence. Offsets do not refer to the original imported source.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TermMatch {
    pub term: String,
    pub byte_offset: u64,
    pub byte_length: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SearchHit {
    pub reference: VersionReference,
    pub format: Format,
    pub terms: Vec<TermMatch>,
}

/// Only latest published versions participate. Results are ordered by exact
/// artifact ID, not score, outcome filename, request ID, or supplied provenance.
/// The returned prefix respects both the requested count and response byte cap.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SearchResults {
    pub canonical_query: String,
    pub matches: Vec<SearchHit>,
    pub total_matches: usize,
    pub truncated: bool,
}

/// An exact immutable collection selection. Membership narrows a search; it
/// never grants access or upgrades a historical member to its current version.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSearchResults {
    pub collection: VersionReference,
    pub search: SearchResults,
}

/// A caller-selected exact historical set, not an ACL or a capability. The
/// digest binds the complete canonical selection; counters include only that
/// selection, never other current versions or retained conflict candidates.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelectedSearchResults {
    pub selection_sha256: String,
    pub selected_versions: usize,
    pub search: SearchResults,
}

/// Pure validation/canonicalization for binding a finite Read request before
/// any private I/O. References must be sorted by artifact ID, with exactly one
/// version per artifact. This does not prove publication or grant visibility.
pub fn canonical_search_selection(references: &[VersionReference]) -> Result<Vec<u8>> {
    if references.is_empty() || references.len() > MAX_SEARCH_SELECTION {
        return Err("exact search selection exceeds its bounded reference count".into());
    }
    let mut previous: Option<&str> = None;
    for reference in references {
        crate::collections::reference(reference)?;
        if previous.is_some_and(|id| id >= reference.artifact_id.as_str()) {
            return Err("exact search references must be unique and sorted by artifact ID".into());
        }
        previous = Some(&reference.artifact_id);
    }
    Ok(serde_json::to_vec(&serde_json::to_value(references)?)?)
}

/// Pure public prevalidation: no filesystem access, authority, or private data.
/// ASCII case/whitespace/order aliases normalize to one sorted unique query.
/// Raw term count is bounded before deduplication to bound parsing work too.
pub fn canonical_search_query(query: &str, limit: usize) -> Result<String> {
    if query.len() > MAX_SEARCH_QUERY_BYTES
        || !query.is_ascii()
        || !(1..=MAX_SEARCH_RESULTS).contains(&limit)
    {
        return Err("content search query or result bound exceeded".into());
    }
    let mut terms = Vec::new();
    for term in query.split_ascii_whitespace() {
        if terms.len() == MAX_SEARCH_TERMS
            || term.len() > MAX_SEARCH_TERM_BYTES
            || !term.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err("content search requires bounded ASCII alphanumeric terms".into());
        }
        terms.push(term.to_ascii_lowercase());
    }
    if terms.is_empty() {
        return Err("content search requires at least one term".into());
    }
    terms.sort();
    terms.dedup();
    Ok(terms.join(" "))
}

impl Repository {
    /// Read one exact published historical version. A stale but genuine
    /// reference is readable, never silently substituted with the current one.
    /// All reference fields must match, and conflict candidates are not versions.
    pub fn historical(
        &self,
        expected: &VersionReference,
        boundary: &mut impl Boundary,
    ) -> Result<ArtifactVersion> {
        if !artifact_identifier(&expected.artifact_id)
            || expected.version == 0
            || [&expected.content_sha256, &expected.receipt_sha256]
                .iter()
                .any(|digest| !crate::hash(digest) || digest.bytes().all(|byte| byte == b'0'))
        {
            return Err("invalid bounded historical content reference".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        let mut found = None;
        for (record, plan, _) in snapshot.records {
            storage::repository_check(self, None, boundary)?;
            if record.plan.decision == DecisionKind::Published && record.plan.resulting == *expected
            {
                if found.is_some() {
                    return Err("ambiguous content historical reference".into());
                }
                found = Some(luma_content::reopen(&plan.payload, &self.binding)?);
                storage::repository_check(self, None, boundary)?;
            }
        }
        let result = found.ok_or("exact published content version unavailable")?;
        if result.reference()? != *expected {
            return Err("historical content reference reconstruction mismatch".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    pub fn current_reference(
        &self,
        artifact: &str,
        boundary: &mut impl Boundary,
    ) -> Result<VersionReference> {
        let reference = self.current(artifact, boundary)?.reference()?;
        storage::repository_check(self, None, boundary)?;
        Ok(reference)
    }

    /// Rebuild and verify every committed outcome, then scan only the current
    /// owner-generation's latest published versions. No index is persisted or
    /// trusted, no other namespace is opened, and no repair or write occurs.
    /// Exact term offsets are metadata for a subsequent separately admitted read.
    pub fn search(
        &self,
        query: &str,
        limit: usize,
        boundary: &mut impl Boundary,
    ) -> Result<SearchResults> {
        let canonical_query = canonical_search_query(query, limit)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        self.search_versions(
            canonical_query,
            limit,
            snapshot.current.into_values().map(Ok),
            boundary,
        )
    }

    /// Search only an explicit exact set admitted by the caller's live Read
    /// boundary. Resolve all references from one verified snapshot before
    /// scanning anything; absent, forged and conflict references refuse the
    /// complete request. Newer versions are never substituted. No index or
    /// policy is persisted and no other owner namespace is opened.
    pub fn search_selected(
        &self,
        references: &[VersionReference],
        query: &str,
        limit: usize,
        boundary: &mut impl Boundary,
    ) -> Result<SelectedSearchResults> {
        let selection = canonical_search_selection(references)?;
        let canonical_query = canonical_search_query(query, limit)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        let mut selected = std::collections::BTreeMap::new();
        for (record, plan, _) in &snapshot.records {
            storage::repository_check(self, None, boundary)?;
            if record.plan.decision == DecisionKind::Published
                && references
                    .iter()
                    .any(|reference| reference == plan.resulting())
                && selected
                    .insert(plan.artifact_id(), plan.payload.as_slice())
                    .is_some()
            {
                return Err("ambiguous exact selected search version".into());
            }
        }
        if selected.len() != references.len() {
            return Err("exact selected published search version unavailable".into());
        }
        let search = self.search_versions(
            canonical_query,
            limit,
            selected
                .into_values()
                .map(|payload| -> Result<ArtifactVersion> {
                    Ok(luma_content::reopen(payload, &self.binding)?)
                }),
            boundary,
        )?;
        let result = SelectedSearchResults {
            selection_sha256: luma_content::sha256(&selection),
            selected_versions: references.len(),
            search,
        };
        if serde_json::to_vec(&result)?.len() > MAX_SEARCH_RESPONSE_BYTES {
            return Err("exact selected search response byte bound exceeded".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    /// Search only exact published versions in one genuine typed collection.
    /// A single verified snapshot supplies both membership and member bytes;
    /// forged JSON collections, conflict candidates and latest-version aliases
    /// cannot enlarge that selection. The ordinary live owner Read boundary
    /// remains mandatory throughout reconstruction, scanning and delivery.
    pub fn search_collection(
        &self,
        expected: &VersionReference,
        query: &str,
        limit: usize,
        boundary: &mut impl Boundary,
    ) -> Result<CollectionSearchResults> {
        crate::collections::reference(expected)?;
        let canonical_query = canonical_search_query(query, limit)?;
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
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
            .ok_or("exact published typed collection unavailable")?;
        storage::repository_check(self, None, boundary)?;
        let mut selected = std::collections::BTreeMap::new();
        for (record, plan, _) in &snapshot.records {
            storage::repository_check(self, None, boundary)?;
            if record.plan.decision == DecisionKind::Published
                && source
                    .members
                    .iter()
                    .any(|member| member == plan.resulting())
                && selected
                    .insert(plan.artifact_id(), plan.payload.as_slice())
                    .is_some()
            {
                return Err("ambiguous exact collection search member".into());
            }
        }
        if selected.len() != source.members.len() {
            return Err("published collection search member unavailable".into());
        }
        let search = self.search_versions(
            canonical_query,
            limit,
            selected
                .into_values()
                .map(|payload| -> Result<ArtifactVersion> {
                    Ok(luma_content::reopen(payload, &self.binding)?)
                }),
            boundary,
        )?;
        let result = CollectionSearchResults {
            collection: expected.clone(),
            search,
        };
        if serde_json::to_vec(&result)?.len() > MAX_SEARCH_RESPONSE_BYTES {
            return Err("collection search response byte bound exceeded".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }

    fn search_versions(
        &self,
        canonical_query: String,
        limit: usize,
        versions: impl IntoIterator<Item = Result<ArtifactVersion>>,
        boundary: &mut impl Boundary,
    ) -> Result<SearchResults> {
        let terms: Vec<_> = canonical_query.split(' ').collect();
        let mut matches = Vec::new();
        let mut total_matches = 0;
        let mut hit_bytes = 0;
        let mut delivery_full = false;
        let mut versions = versions.into_iter();
        loop {
            storage::repository_check(self, None, boundary)?;
            let Some(version) = versions.next() else {
                break;
            };
            let version = version?;
            let positions = scan(version.content(), &terms, &mut || {
                storage::repository_check(self, None, boundary)
            })?;
            if let Some(positions) = positions {
                total_matches += 1;
                if matches.len() < limit && !delivery_full {
                    let hit = SearchHit {
                        reference: version.reference()?,
                        format: version.receipt().format,
                        terms: terms
                            .iter()
                            .zip(positions)
                            .map(|(term, position)| TermMatch {
                                term: (*term).into(),
                                byte_offset: position as u64,
                                byte_length: term.len() as u64,
                            })
                            .collect(),
                    };
                    storage::repository_check(self, None, boundary)?;
                    let bytes = serde_json::to_vec(&hit)?.len() + 1;
                    // Reserve 1024 bytes for the <=256-byte canonical query and
                    // finite result counters/field names outside the hit array.
                    // Once full, keep a deterministic prefix, not later small hits.
                    if hit_bytes + bytes <= MAX_SEARCH_RESPONSE_BYTES - 1024 {
                        hit_bytes += bytes;
                        matches.push(hit);
                    } else {
                        delivery_full = true;
                    }
                }
            }
            storage::repository_check(self, None, boundary)?;
        }
        let result = SearchResults {
            canonical_query,
            truncated: total_matches > matches.len(),
            matches,
            total_matches,
        };
        if serde_json::to_vec(&result)?.len() > MAX_SEARCH_RESPONSE_BYTES {
            return Err("content search response byte bound exceeded".into());
        }
        storage::repository_check(self, None, boundary)?;
        Ok(result)
    }
}

fn artifact_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte >= 128 || byte == b'_'
}

fn scan(
    content: &[u8],
    terms: &[&str],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Option<Vec<usize>>> {
    check()?;
    let mut positions = vec![None; terms.len()];
    let mut token_start = None;
    // Inclusive sentinel finishes the last token without allocating a copy.
    for index in 0..=content.len() {
        if index % CHECK_INTERVAL == 0 {
            check()?;
        }
        if index < content.len() && word_byte(content[index]) {
            token_start.get_or_insert(index);
        } else if let Some(start) = token_start.take() {
            let token = &content[start..index];
            for (term, position) in terms.iter().zip(&mut positions) {
                if position.is_none() && token.eq_ignore_ascii_case(term.as_bytes()) {
                    *position = Some(start);
                }
            }
            if positions.iter().all(Option::is_some) {
                check()?;
                return Ok(Some(positions.into_iter().flatten().collect()));
            }
        }
    }
    check()?;
    Ok(None)
}

#[cfg(test)]
mod scanner_tests {
    use super::*;

    #[test]
    fn long_words_cannot_bypass_periodic_revocation_or_allocate_an_index() {
        let content = vec![b'a'; luma_content::MAX_CONTENT_BYTES];
        let mut checks = 0;
        assert!(scan(&content, &["fox"], &mut || {
            checks += 1;
            if checks == 3 {
                Err("revoked during one oversized lexical token".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(checks, 3);
        let mut checks = 0;
        assert_eq!(
            scan(&content, &["fox"], &mut || {
                checks += 1;
                Ok(())
            })
            .unwrap(),
            None
        );
        assert_eq!(checks, content.len() / CHECK_INTERVAL + 3);
    }

    #[test]
    fn unicode_and_identifier_words_do_not_produce_ascii_substring_matches() {
        for content in ["café", "éfox", "foxé", "_fox", "fox_", "fox42", "42fox"] {
            assert_eq!(
                scan(content.as_bytes(), &["fox"], &mut || Ok(())).unwrap(),
                None
            );
        }
        assert_eq!(
            scan("é fox".as_bytes(), &["fox"], &mut || Ok(())).unwrap(),
            Some(vec![3])
        );
        assert_eq!(
            scan(b"FOX", &["fox"], &mut || Ok(())).unwrap(),
            Some(vec![0])
        );
    }
}
