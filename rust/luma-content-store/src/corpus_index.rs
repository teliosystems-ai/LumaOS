//! Owner-corpus derivative indexes. These data APIs neither select C state nor
//! authenticate a user, issue a grant, publish an index generation or deliver
//! file contents. Every entry point requires an explicit live boundary.
use crate::v2::{IoBudget, MapKind, MapRoot, Mutation, ObjectStore};
use crate::{Access, Boundary, ResourceBudget, Result};
use luma_content::{Format, VersionReference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod build;
pub mod job;
mod math;
mod pages;
mod query;
pub mod storage;
pub use pages::{Span as CorpusIndexPageRef, Tree as CorpusIndexTreeKind};
use storage::IndexReadStore;
#[cfg(test)]
mod tests;

pub const CORPUS_INDEX_PROFILE: &str = "luma-owner-corpus-ascii-tfidf-feature-lsa-v1";
pub const MAX_CORPUS_OBJECTS: u64 = 100_000;
pub const MAX_FEATURES: usize = 512;
pub const MAX_DIMENSIONS: usize = 8;
pub const MAX_INDEX_PAGE_BYTES: usize = 16 * 1024;
pub const MAX_INDEX_SOURCE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_INDEX_POSTINGS: u64 = 32_000_000;
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_DOCUMENT_TERMS: usize = 16_384;
const BUCKETS: usize = 4096;
const MAX_BUCKET_TERMS: usize = 65_536;
const PAGE_READ: u64 = 128 * 1024;
const PAGE_WRITE: u64 = 128 * 1024;

/// The authoritative corpus map's closed DATA value. A visible/current corpus
/// is selected by independent C custody, not by construction of this value.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusRecord {
    pub schema_version: u32,
    pub reference: VersionReference,
    pub format: Format,
    pub content_bytes: u64,
    pub lifecycle_revision: u64,
    pub lifecycle_state_sha256: String,
}
impl CorpusRecord {
    pub fn validate(&self) -> Result<()> {
        crate::collections::reference(&self.reference)?;
        hash(&self.lifecycle_state_sha256)?;
        if self.schema_version != 1
            || self.content_bytes > MAX_DOCUMENT_BYTES as u64
            || self.lifecycle_revision == 0
            || (self.content_bytes == 0 && self.format != Format::Utf8Text)
        {
            return Err("invalid closed current-corpus record".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > crate::v2::MAX_VALUE_BYTES {
            return Err("corpus record exceeds authenticated map value bound".into());
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8], root: &MapRoot, key: &str) -> Result<Self> {
        let value: Self = decode(bytes, crate::v2::MAX_VALUE_BYTES)?;
        value.validate()?;
        if root.corpus_key(&value.reference.artifact_id)? != key {
            return Err("corpus key does not bind the exact artifact identifier".into());
        }
        Ok(value)
    }
}

/// No default implementation: runtime integration must refresh the independently
/// selected corpus, live subject/grants/resources and derivative generation.
pub trait CorpusIndexBoundary: Boundary {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()>;
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()>;
    fn current_index_generation(&mut self, root: &MapRoot, manifest_sha256: &str) -> Result<()>;
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()>;
}

/// A build/runtime tuple, NOT proof of its observation, signature or admission.
/// The live boundary independently binds both pins to its fixed builder.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuilderIdentity {
    pub source_sha256: String,
    pub runtime_sha256: String,
}
impl BuilderIdentity {
    pub fn validate(&self) -> Result<()> {
        hash(&self.source_sha256)?;
        hash(&self.runtime_sha256)
    }
}

/// Exact immutable source lookup, not a path/label/URL or a model assertion.
/// Implementations must retain their own real private-read/output boundary.
pub trait CorpusContent {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        boundary: &mut B,
    ) -> Result<Vec<u8>>;
}

/// Finite requested limits; not evidence of admission or a longer session.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusIndexLimits {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub source_bytes: u64,
    pub postings: u64,
    pub floating_operations: u64,
}
impl CorpusIndexLimits {
    pub fn validate(&self) -> Result<()> {
        if self.read_bytes == 0
            || self.read_bytes > 128 * 1024 * 1024 * 1024
            || self.write_bytes > 64 * 1024 * 1024 * 1024
            || self.source_bytes > MAX_INDEX_SOURCE_BYTES
            || self.postings > MAX_INDEX_POSTINGS
            || self.floating_operations == 0
            || self.floating_operations > 64_000_000_000
        {
            return Err("invalid finite owner-corpus index limits".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusIndexManifest {
    pub schema_version: u32,
    pub profile: String,
    pub builder: BuilderIdentity,
    pub corpus: MapRoot,
    pub corpus_sha256: String,
    pub source_bytes: u64,
    pub posting_records: u64,
    pub vocabulary_terms: u64,
    pub features: u16,
    pub dimensions: u8,
    pub documents: Option<pages::Span>,
    pub buckets: pages::Span,
    pub model: Option<pages::Span>,
    pub vectors: Option<pages::Span>,
}
impl CorpusIndexManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_INDEX_PAGE_BYTES {
            return Err("index manifest exceeds one bounded page".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_INDEX_PAGE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        corpus(&self.corpus)?;
        self.builder.validate()?;
        if self.schema_version != 1
            || self.profile != CORPUS_INDEX_PROFILE
            || self.corpus_sha256 != self.corpus.sha256()?
            || self.source_bytes > MAX_INDEX_SOURCE_BYTES
            || self.posting_records > MAX_INDEX_POSTINGS
            || self.vocabulary_terms > self.posting_records
            || self.features as usize > MAX_FEATURES
            || self.features as u64 > self.vocabulary_terms
            || self.dimensions as usize > MAX_DIMENSIONS
            || self.dimensions as u16 > self.features
            || (self.features == 0) != (self.dimensions == 0)
        {
            return Err("index descriptor profile/coverage/bounds mismatch".into());
        }
        pages::validate_root(
            &self.documents,
            pages::Tree::Documents,
            self.corpus.entry_count as u32,
            &self.corpus,
        )?;
        pages::validate_root(
            &self.vectors,
            pages::Tree::Vectors,
            self.corpus.entry_count as u32,
            &self.corpus,
        )?;
        pages::validate_root(
            &self.model,
            pages::Tree::Model,
            u32::from(self.features),
            &self.corpus,
        )?;
        self.buckets.validate(&self.corpus)?;
        if self.buckets.tree != pages::Tree::Buckets
            || self.buckets.first != 0
            || self.buckets.count != BUCKETS as u32
        {
            return Err("index bucket directory coverage mismatch".into());
        }
        Ok(())
    }
}

/// Unselected derivative DATA only. A runtime must separately observe and select
/// this generation before `VerifiedCorpusIndex::open` permits any query.
pub struct BuiltCorpusIndex {
    pub manifest: CorpusIndexManifest,
    pub manifest_sha256: String,
}

pub struct VerifiedCorpusIndex {
    manifest: CorpusIndexManifest,
    manifest_sha256: String,
}

pub use query::{CorpusHit, CorpusQueryKind, CorpusQueryResults};

pub fn build_corpus_index<B: CorpusIndexBoundary, C: CorpusContent>(
    store: &ObjectStore,
    root: &MapRoot,
    builder: &BuilderIdentity,
    content: &mut C,
    mutation: &Mutation,
    limits: CorpusIndexLimits,
    boundary: &mut B,
) -> Result<BuiltCorpusIndex> {
    build::build(store, root, builder, content, mutation, limits, boundary)
}

fn corpus(root: &MapRoot) -> Result<()> {
    root.validate()?;
    if root.kind != MapKind::Corpus || root.entry_count > MAX_CORPUS_OBJECTS {
        return Err("index requires the exact bounded owner Corpus map".into());
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value.bytes().all(|b| b == b'0')
    {
        return Err("nonzero canonical index digest required".into());
    }
    Ok(())
}
fn decode<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("index canonical data exceeds bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("index data must use exact closed canonical encoding".into());
    }
    Ok(value)
}

struct Meter {
    builder: BuilderIdentity,
    limits: CorpusIndexLimits,
    read: u64,
    written: u64,
    source: u64,
    postings: u64,
    work: u64,
    since_check: u64,
    generation: Option<String>,
}
impl Meter {
    fn new<B: CorpusIndexBoundary>(
        root: &MapRoot,
        builder: &BuilderIdentity,
        limits: CorpusIndexLimits,
        generation: Option<String>,
        b: &mut B,
    ) -> Result<Self> {
        corpus(root)?;
        builder.validate()?;
        limits.validate()?;
        b.admit(
            &root.binding,
            ResourceBudget {
                memory_bytes: 192 * 1024 * 1024,
                tasks: 1,
                read_bytes: limits.read_bytes,
                write_bytes: limits.write_bytes,
                additional_storage_bytes: limits.write_bytes,
            },
        )?;
        let mut value = Self {
            builder: builder.clone(),
            limits,
            read: 0,
            written: 0,
            source: 0,
            postings: 0,
            work: 0,
            since_check: 0,
            generation,
        };
        value.check(root, b)?;
        Ok(value)
    }
    fn check<B: CorpusIndexBoundary>(&mut self, root: &MapRoot, b: &mut B) -> Result<()> {
        b.check(Access::Inspect {
            binding: &root.binding,
        })?;
        b.current_corpus(root)?;
        b.current_builder(root, &self.builder)?;
        if let Some(hash) = &self.generation {
            b.current_index_generation(root, hash)?;
        }
        self.since_check = 0;
        Ok(())
    }
    fn read(&mut self, bytes: u64) -> Result<()> {
        self.read = self.read.checked_add(bytes).ok_or("index read overflow")?;
        if self.read > self.limits.read_bytes {
            return Err("finite index read budget exhausted".into());
        }
        Ok(())
    }
    fn write(&mut self, bytes: u64) -> Result<()> {
        self.written = self
            .written
            .checked_add(bytes)
            .ok_or("index write overflow")?;
        if self.written > self.limits.write_bytes {
            return Err("finite index write budget exhausted".into());
        }
        Ok(())
    }
    fn work<B: CorpusIndexBoundary>(
        &mut self,
        amount: u64,
        root: &MapRoot,
        b: &mut B,
    ) -> Result<()> {
        self.work = self.work.checked_add(amount).ok_or("index work overflow")?;
        self.since_check = self
            .since_check
            .checked_add(amount)
            .ok_or("index check interval overflow")?;
        if self.work > self.limits.floating_operations {
            return Err("finite index work budget exhausted".into());
        }
        if self.since_check >= 32768 {
            self.check(root, b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Posting {
    term: String,
    document: u32,
    frequency: u32,
    offset: u32,
}
fn bucket(term: &str) -> usize {
    let hash = luma_content::sha256(term.as_bytes());
    hash.as_bytes()[..3].iter().fold(0, |n, b| {
        n * 16
            + usize::from(if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            })
    })
}

fn words<B: CorpusIndexBoundary>(
    bytes: &[u8],
    root: &MapRoot,
    meter: &mut Meter,
    b: &mut B,
) -> Result<BTreeMap<String, (u32, u32)>> {
    if bytes.len() > MAX_DOCUMENT_BYTES || std::str::from_utf8(bytes).is_err() {
        return Err("index source must be bounded canonical UTF8".into());
    }
    let mut result = BTreeMap::new();
    let mut start = None;
    let mut ascii = true;
    for offset in 0..=bytes.len() {
        if offset % 32768 == 0 {
            meter.work(32768, root, b)?;
            meter.check(root, b)?;
        }
        let value = bytes.get(offset).copied();
        if value.is_some_and(|v| v.is_ascii_alphanumeric() || v == b'_' || !v.is_ascii()) {
            start.get_or_insert(offset);
            ascii &= value.is_some_and(|v| v.is_ascii_alphanumeric());
        } else if let Some(begin) = start.take() {
            if ascii && offset - begin <= crate::MAX_SEARCH_TERM_BYTES {
                let term = std::str::from_utf8(&bytes[begin..offset])?.to_ascii_lowercase();
                let count = result.entry(term).or_insert((0_u32, begin as u32));
                count.0 = count
                    .0
                    .checked_add(1)
                    .ok_or("index term frequency overflow")?;
                if result.len() > MAX_DOCUMENT_TERMS {
                    return Err("document distinct-word profile exhausted; index not ready".into());
                }
            }
            ascii = true;
        }
    }
    meter.check(root, b)?;
    Ok(result)
}
fn read_content<B: CorpusIndexBoundary, C: CorpusContent>(
    root: &MapRoot,
    record: &CorpusRecord,
    content: &mut C,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Vec<u8>> {
    meter.check(root, b)?;
    b.current_candidate(root, record)?;
    meter.read(record.content_bytes)?;
    let bytes = content.read_content(record, b)?;
    if bytes.len() as u64 != record.content_bytes
        || luma_content::sha256(&bytes) != record.reference.content_sha256
    {
        return Err("exact immutable index source length/content digest changed".into());
    }
    meter.check(root, b)?;
    b.current_candidate(root, record)?;
    Ok(bytes)
}
