//! Disposable lexical index. Verified catalog receipts remain authoritative.
use super::*;
use std::collections::BTreeMap;

const MAX_TERM_BYTES: usize = 128;
const MAX_POSTINGS: usize = 131_072;
const MAX_QUERY_BYTES: usize = 512;
const MAX_QUERY_TERMS: usize = 8;
const MAX_RESULTS: usize = 100;

fn terms(text: &str, mut accept: impl FnMut(String) -> Result<()>) -> Result<()> {
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        // Oversized terms are rejected, not truncated to another identity.
        if word.len() > MAX_TERM_BYTES {
            return Err("search term exceeds byte bound".into());
        }
        let normalized = word.to_lowercase();
        if normalized.len() > MAX_TERM_BYTES {
            return Err("normalized search term exceeds byte bound".into());
        }
        accept(normalized)?;
    }
    Ok(())
}

fn query(text: &str, limit: &str) -> Result<(BTreeSet<String>, usize)> {
    if text.is_empty() || text.len() > MAX_QUERY_BYTES || text.chars().any(char::is_control) {
        return Err("search query exceeds the closed text contract".into());
    }
    let limit_number: usize = limit.parse()?;
    if !(1..=MAX_RESULTS).contains(&limit_number) || limit_number.to_string() != limit {
        return Err("search limit must be a canonical integer from 1 to 100".into());
    }
    let mut result = BTreeSet::new();
    terms(text, |term| {
        result.insert(term);
        if result.len() > MAX_QUERY_TERMS {
            return Err("search query has too many distinct terms".into());
        }
        Ok(())
    })?;
    if result.is_empty() {
        return Err("search query requires an alphanumeric term".into());
    }
    Ok((result, limit_number))
}

struct Index {
    documents: BTreeMap<String, Receipt>,
    postings: BTreeMap<String, BTreeSet<String>>,
    posting_count: usize,
}

impl Index {
    fn new() -> Self {
        Self {
            documents: BTreeMap::new(),
            postings: BTreeMap::new(),
            posting_count: 0,
        }
    }

    fn add_term(&mut self, id: &str, term: String) -> Result<()> {
        let posting = self.postings.entry(term).or_default();
        if !posting.contains(id) {
            if self.posting_count == MAX_POSTINGS {
                return Err("search index exceeds the fixed posting budget".into());
            }
            posting.insert(id.into());
            self.posting_count += 1;
        }
        Ok(())
    }

    fn value(&mut self, id: &str, value: &serde_json::Value) -> Result<()> {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    terms(key, |term| self.add_term(id, term))?;
                    self.value(id, value)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    self.value(id, value)?;
                }
            }
            serde_json::Value::String(text) => terms(text, |term| self.add_term(id, term))?,
            serde_json::Value::Number(number) => {
                terms(&number.to_string(), |term| self.add_term(id, term))?;
            }
            serde_json::Value::Bool(value) => self.add_term(id, value.to_string())?,
            serde_json::Value::Null => (),
        }
        Ok(())
    }

    fn add(&mut self, receipt: &Receipt, bytes: &[u8]) -> Result<()> {
        if self.documents.len() >= MAX_RECORDS
            || self.documents.contains_key(&receipt.artifact_id)
            || bytes.len() as u64 != receipt.content_bytes
            || io::digest(bytes) != receipt.content_sha256
        {
            return Err("search document is duplicated, altered or exceeds capacity".into());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        terms(&receipt.filename, |term| {
            self.add_term(&receipt.artifact_id, term)
        })?;
        self.value(&receipt.artifact_id, &value)?;
        self.documents
            .insert(receipt.artifact_id.clone(), receipt.clone());
        Ok(())
    }

    fn results(&self, wanted: &BTreeSet<String>, limit: usize) -> Vec<&Receipt> {
        // Ordered intersection: no frequency or cross-domain statistics leak.
        self.documents
            .iter()
            .filter(|(id, _)| {
                wanted
                    .iter()
                    .all(|term| self.postings.get(term).is_some_and(|ids| ids.contains(*id)))
            })
            .take(limit)
            .map(|(_, receipt)| receipt)
            .collect()
    }
}

fn search(catalog: &Catalog, text: &str, limit: &str) -> Result<serde_json::Value> {
    let (wanted, limit) = query(text, limit)?;
    let (records, _, _) = catalog.inventory()?;
    let snapshot = io::digest(&serde_json::to_vec(&records)?);
    let mut latest = BTreeMap::<String, &Receipt>::new();
    for (_, receipt) in &records {
        let prior = latest.get(&receipt.artifact_id);
        if prior.map_or(true, |prior| prior.version < receipt.version) {
            latest.insert(receipt.artifact_id.clone(), receipt);
        }
    }
    let mut index = Index::new();
    for receipt in latest.values() {
        let bytes = io::read_member(&catalog.objects, &receipt.content_sha256, MAX_CONTENT)?;
        index.add(receipt, &bytes)?;
    }
    if io::digest(&serde_json::to_vec(&catalog.inventory()?.0)?) != snapshot {
        return Err("catalog changed while rebuilding search; retry without cached results".into());
    }
    let hits: Vec<_> = index
        .results(&wanted, limit)
        .into_iter()
        .map(|r| {
            serde_json::json!({"artifact_id":r.artifact_id,"version":r.version,
            "content_sha256":r.content_sha256,"filename":r.filename,"media_type":r.media_type})
        })
        .collect();
    Ok(
        serde_json::json!({"schema_version":1,"mode":"lexical-all-terms-v1",
        "environment":"lab","owner":catalog.owner,"installation":catalog.installation,
        "catalog_snapshot_sha256":snapshot,"terms":wanted,"current_documents":index.documents.len(),
        "hits":hits,"index_persisted":false,"semantic_search":false,"gate_closing":false}),
    )
}

pub(crate) fn command(text: &str, limit: &str) -> Result<()> {
    // This first slice cannot read private product domains or accept grants as
    // a substitute for its explicit non-product laboratory boundary.
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_laboratory_image()?;
    crate::admin_governance::reject_laboratory_effects_after_bootstrap()?;
    query(text, limit)?;
    let installation = io::installation()?;
    let catalog = Catalog::open(Path::new(DIRECTORY), &installation)?;
    let result = search(&catalog, text, limit)?;
    crate::admin_governance::reject_laboratory_effects_after_bootstrap()?;
    if io::installation()? != installation {
        return Err("search installation changed".into());
    }
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_bounded_canonical_and_language_aware() {
        assert_eq!(
            query("INVOICE invoice Café", "10").unwrap().0,
            ["café".into(), "invoice".into()].into()
        );
        for (q, n) in [
            ("", "1"),
            ("---", "1"),
            ("x\ny", "1"),
            ("x", "0"),
            ("x", "01"),
            ("x", "101"),
            ("a b c d e f g h i", "1"),
        ] {
            assert!(query(q, n).is_err());
        }
        assert!(query(&"x".repeat(129), "1").is_err());
        assert!(query(&"x ".repeat(257), "1").is_err());
    }

    #[test]
    fn rebuild_reads_only_current_verified_versions_and_is_deterministic() {
        let fixture = super::super::tests::Fixture::new("search-current");
        let catalog = Catalog::open(&fixture.path, &"a".repeat(64)).unwrap();
        for (request, artifact, version, text) in [
            ("one", "alpha", 0, "obsolete"),
            ("two", "alpha", 1, "current"),
            ("three", "beta", 0, "current"),
        ] {
            let (mut receipt, _) = super::super::tests::proposal(request, artifact, version);
            let bytes = serde_json::to_vec(&serde_json::json!({"title":text,"amount":42})).unwrap();
            receipt.content_sha256 = io::digest(&bytes);
            receipt.content_bytes = bytes.len() as u64;
            catalog.publish(&receipt, &bytes, |_| Ok(())).unwrap();
        }
        assert_eq!(
            search(&catalog, "obsolete", "10").unwrap()["hits"],
            serde_json::json!([])
        );
        let first = search(&catalog, "CURRENT 42", "10").unwrap();
        assert_eq!(first, search(&catalog, "CURRENT 42", "10").unwrap());
        assert_eq!(first["hits"][0]["artifact_id"], "alpha");
        assert_eq!(first["hits"][0]["version"], 2);
        assert_eq!(first["hits"].as_array().unwrap().len(), 2);
        assert_eq!(
            search(&catalog, "current", "1").unwrap()["hits"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            search(&catalog, "current absent", "10").unwrap()["hits"],
            serde_json::json!([])
        );
    }

    #[test]
    fn altered_objects_and_index_exhaustion_are_refused_without_results() {
        let (receipt, bytes) = super::super::tests::proposal("one", "alpha", 0);
        let mut index = Index::new();
        assert!(index.add(&receipt, b"altered").is_err());
        index.add(&receipt, &bytes).unwrap();
        assert!(index.add(&receipt, &bytes).is_err());
        index.posting_count = MAX_POSTINGS;
        assert!(index.add_term("beta", "new".into()).is_err());
    }
}
