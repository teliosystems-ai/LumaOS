//! Resumable16-way sorted-run reduction and linear document-frequency DATA.
//! A completed statistics state is not a projection, vector index, selected
//! generation or query authority. Every window requires its original boundary.
use super::*;

const STATS_DOMAIN: &str = "luma-corpus-statistics-v1";
const LEVELS: usize = 5;
const FAN_IN: usize = 16;
const OUTPUT_RECORDS: usize = 4096;
const PROGRESS_BYTES: usize = 64 * 1024;
const MAX_WINDOW_READ: u64 = 64 * 1024 * 1024;
const MAX_WINDOW_WRITE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatisticsRequest {
    pub schema_version: u32,
    pub ingestion: IngestRequest,
    pub ingested: IngestProgress,
}
impl StatisticsRequest {
    pub fn validate(&self) -> Result<()> {
        self.ingestion.validate()?;
        self.ingested.validate(&self.ingestion)?;
        if self.schema_version != 1 || !self.ingested.complete(&self.ingestion)? {
            return Err("statistics requires the exact completed ingestion selection".into());
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StatisticsStream {
    Ingest {
        run: RunRef,
    },
    Merged {
        sha256: String,
        first: u32,
        documents: u32,
        postings: u64,
        runs: u32,
    },
}
impl StatisticsStream {
    fn first(&self) -> u32 {
        match self {
            Self::Ingest { run } => run.first,
            Self::Merged { first, .. } => *first,
        }
    }
    fn documents(&self) -> u32 {
        match self {
            Self::Ingest { run } => run.documents,
            Self::Merged { documents, .. } => *documents,
        }
    }
    fn postings(&self) -> u64 {
        match self {
            Self::Ingest { run } => run.postings,
            Self::Merged { postings, .. } => *postings,
        }
    }
    fn runs(&self) -> u32 {
        match self {
            Self::Ingest { .. } => 1,
            Self::Merged { runs, .. } => *runs,
        }
    }
    fn validate(&self, request: &StatisticsRequest) -> Result<()> {
        match self {
            Self::Ingest { run } => run.validate(&request.ingestion)?,
            Self::Merged {
                sha256,
                documents,
                postings,
                runs,
                ..
            } => {
                hash(sha256)?;
                if *documents == 0
                    || *runs < 2
                    || *runs > *documents
                    || *postings > request.ingested.totals.postings
                {
                    return Err("merged statistics stream count exceeds source coverage".into());
                }
            }
        }
        if u64::from(self.first()) + u64::from(self.documents())
            > request.ingestion.corpus.entry_count
        {
            return Err("statistics stream document range exceeds selected corpus".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatisticsNode {
    pub first: u64,
    pub count: u64,
    pub height: u8,
    pub sha256: String,
}
impl StatisticsNode {
    fn validate(&self, request: &StatisticsRequest) -> Result<()> {
        hash(&self.sha256)?;
        if self.count == 0
            || self.height > 12
            || self
                .first
                .checked_add(self.count)
                .map_or(true, |end| end > request.ingested.totals.postings)
        {
            return Err("statistics posting subtree exceeds selected coverage".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MergeDestination {
    Level(u8),
    Fold,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MergeProgress {
    pub inputs: Vec<StatisticsStream>,
    pub positions: Vec<u64>,
    pub frontier: Vec<Vec<StatisticsNode>>,
    pub output_records: u64,
    pub destination: MergeDestination,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentFrequency {
    pub term: String,
    pub documents: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrequencyProgress {
    pub stream: Option<StatisticsStream>,
    pub offset: u64,
    pub current: Option<DocumentFrequency>,
    pub last_document: Option<u32>,
    pub vocabulary: u64,
    pub bucket: u16,
    pub bucket_terms: u64,
    pub bucket_key_bytes: u64,
    pub top: Vec<DocumentFrequency>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatisticsProgress {
    pub schema_version: u32,
    pub request_sha256: String,
    pub next_source_run: Option<RunRef>,
    pub collected_documents: u64,
    pub collected_runs: u64,
    pub collected_postings: u64,
    pub levels: Vec<Vec<StatisticsStream>>,
    pub fold: Option<StatisticsStream>,
    pub merging: Option<MergeProgress>,
    pub frequencies: Option<FrequencyProgress>,
    pub complete: bool,
    /// Cumulative across ingestion AND statistics; never reset per window.
    pub totals: IngestTotals,
}
impl StatisticsProgress {
    pub fn beginning(request: &StatisticsRequest) -> Result<Self> {
        request.validate()?;
        let empty = request.ingestion.corpus.entry_count == 0;
        Ok(Self {
            schema_version: 1,
            request_sha256: request.sha256()?,
            next_source_run: request.ingested.last_run.clone(),
            collected_documents: 0,
            collected_runs: 0,
            collected_postings: 0,
            levels: vec![Vec::new(); LEVELS],
            fold: None,
            merging: None,
            frequencies: empty.then_some(FrequencyProgress {
                stream: None,
                offset: 0,
                current: None,
                last_document: None,
                vocabulary: 0,
                bucket: 0,
                bucket_terms: 0,
                bucket_key_bytes: 0,
                top: Vec::new(),
            }),
            complete: empty,
            totals: request.ingested.totals,
        })
    }
    pub fn validate(&self, request: &StatisticsRequest) -> Result<()> {
        request.validate()?;
        self.totals.validate(&request.ingestion.limits)?;
        if self.schema_version != 1
            || self.request_sha256 != request.sha256()?
            || self.levels.len() != LEVELS
            || self.collected_documents > request.ingestion.corpus.entry_count
            || self.collected_runs > request.ingested.windows
            || self.collected_runs > self.collected_documents
            || self.collected_postings > request.ingested.totals.postings
            || self.totals.source_bytes != request.ingested.totals.source_bytes
            || self.totals.postings != request.ingested.totals.postings
            || self.totals.read_bytes < request.ingested.totals.read_bytes
            || self.totals.write_bytes < request.ingested.totals.write_bytes
            || self.totals.work < request.ingested.totals.work
        {
            return Err("statistics progress substitutes source or cumulative accounting".into());
        }
        if let Some(run) = &self.next_source_run {
            run.validate(&request.ingestion)?;
        }
        for level in &self.levels {
            if level.len() >= FAN_IN {
                return Err("unreduced statistics level exceeds16-way fan-in".into());
            }
            for stream in level {
                stream.validate(request)?;
            }
        }
        if let Some(fold) = &self.fold {
            fold.validate(request)?;
        }
        if let Some(merge) = &self.merging {
            if self.frequencies.is_some()
                || self.complete
                || merge.inputs.len() < 2
                || merge.inputs.len() > FAN_IN
                || merge.positions.len() != merge.inputs.len()
                || merge.frontier.len() != 9
                || matches!(merge.destination, MergeDestination::Level(level) if usize::from(level)>=LEVELS)
            {
                return Err("invalid finite statistics merge state".into());
            }
            let mut consumed = 0_u64;
            for (i, stream) in merge.inputs.iter().enumerate() {
                stream.validate(request)?;
                if merge.positions[i] > stream.postings() {
                    return Err("statistics input cursor exceeds stream".into());
                }
                consumed = consumed
                    .checked_add(merge.positions[i])
                    .ok_or("merge count overflow")?;
                if i > 0
                    && u64::from(stream.first()) + u64::from(stream.documents())
                        != u64::from(merge.inputs[i - 1].first())
                {
                    return Err("statistics merge inputs overlap or skip source documents".into());
                }
            }
            if consumed != merge.output_records {
                return Err("statistics output count differs from input cursors".into());
            }
            let mut nodes: Vec<_> = merge.frontier.iter().flatten().collect();
            nodes.sort_by_key(|node| node.first);
            let mut next = 0;
            for (height, row) in merge.frontier.iter().enumerate() {
                if row.len() >= 32 || row.iter().any(|n| usize::from(n.height) != height) {
                    return Err("statistics append frontier exceeds bounded shape".into());
                }
            }
            for node in nodes {
                node.validate(request)?;
                if node.first != next {
                    return Err("statistics frontier lost exact rank coverage".into());
                }
                next = next
                    .checked_add(node.count)
                    .ok_or("frontier count overflow")?;
            }
            if next != consumed {
                return Err("statistics frontier total differs".into());
            }
        }
        if let Some(frequency) = &self.frequencies {
            if self.next_source_run.is_some()
                || self.merging.is_some()
                || self.fold.is_some()
                || self.levels.iter().any(|x| !x.is_empty())
                || self.collected_documents != request.ingestion.corpus.entry_count
                || self.collected_postings != request.ingested.totals.postings
                || self.collected_runs != request.ingested.windows
                || frequency.top.len() > MAX_FEATURES
                || usize::from(frequency.bucket) >= BUCKETS
                || frequency.bucket_terms > MAX_BUCKET_TERMS as u64
                || frequency.bucket_key_bytes > 8 * 1024 * 1024
                || frequency.vocabulary > request.ingested.totals.postings
            {
                return Err("invalid statistics frequency coverage".into());
            }
            match &frequency.stream {
                Some(stream) => {
                    stream.validate(request)?;
                    if stream.first() != 0
                        || u64::from(stream.documents()) != request.ingestion.corpus.entry_count
                        || stream.postings() != request.ingested.totals.postings
                        || u64::from(stream.runs()) != request.ingested.windows
                        || frequency.offset > stream.postings()
                    {
                        return Err("DF source stream differs from complete corpus".into());
                    }
                }
                None if request.ingestion.corpus.entry_count == 0 => {}
                None => return Err("nonempty corpus has no statistics source stream".into()),
            }
            let mut previous = None;
            for entry in &frequency.top {
                validate_frequency(entry, request)?;
                if previous.is_some_and(|old: &str| old >= entry.term.as_str()) {
                    return Err("DF top terms must be unique and lexically ordered".into());
                }
                previous = Some(entry.term.as_str());
            }
            if let Some(current) = &frequency.current {
                validate_frequency(current, request)?;
            }
            if frequency.current.is_some() != frequency.last_document.is_some()
                || frequency
                    .last_document
                    .is_some_and(|doc| u64::from(doc) >= request.ingestion.corpus.entry_count)
                || (self.complete
                    && (frequency.current.is_some()
                        || frequency.offset != request.ingested.totals.postings))
            {
                return Err("DF partial-term/completion cursor inconsistent".into());
            }
        } else if self.complete {
            return Err("statistics complete without a frequency result".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, request: &StatisticsRequest) -> Result<Vec<u8>> {
        self.validate(request)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > PROGRESS_BYTES {
            return Err("statistics progress exceeds64KiB".into());
        }
        Ok(bytes)
    }
}

pub trait StatisticsBoundary: CorpusIndexJobBoundary {
    fn current_statistics(
        &mut self,
        request: &StatisticsRequest,
        progress: &StatisticsProgress,
    ) -> Result<()>;
    fn verify_statistics_allocations(&mut self, value: &StatisticsCommitment) -> Result<()>;
}

struct Current<'a, B: StatisticsBoundary> {
    request: &'a StatisticsRequest,
    base: &'a StatisticsProgress,
    b: &'a mut B,
}
impl<B: StatisticsBoundary> Current<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.b.check(Access::Inspect {
            binding: &self.request.ingestion.corpus.binding,
        })?;
        self.b.current_statistics(self.request, self.base)?;
        self.b
            .current_job(&self.request.ingestion, &self.request.ingested)?;
        self.b.current_corpus(&self.request.ingestion.corpus)?;
        self.b.current_builder(
            &self.request.ingestion.corpus,
            &self.request.ingestion.builder,
        )
    }
}
impl<B: StatisticsBoundary> Boundary for Current<'_, B> {
    fn admit(&mut self, owner: &luma_content::OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if owner != &self.request.ingestion.corpus.binding {
            return Err("statistics store owner differs".into());
        }
        self.current()?;
        self.b.admit(owner, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.b.check(access)?;
        self.current()
    }
}
impl<B: StatisticsBoundary> CorpusIndexBoundary for Current<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.request.ingestion.corpus {
            return Err("statistics corpus substituted".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()> {
        if root != &self.request.ingestion.corpus || identity != &self.request.ingestion.builder {
            return Err("statistics builder substituted".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, hash: &str) -> Result<()> {
        self.current()?;
        self.b.current_index_generation(root, hash)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: StatisticsBoundary> CorpusIndexJobBoundary for Current<'_, B> {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()> {
        if request != &self.request.ingestion || progress != &self.request.ingested {
            return Err("statistics ingestion selection changed".into());
        }
        self.current()
    }
    fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()> {
        self.current()?;
        self.b.verify_ingest_allocations(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Postings {
        first: u64,
        entries: Vec<IngestPosting>,
    },
    Branch {
        children: Vec<StatisticsNode>,
    },
    Stream {
        inputs: Vec<StatisticsStream>,
        first: u32,
        documents: u32,
        postings: u64,
        runs: u32,
        root: Option<StatisticsNode>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    domain: String,
    request_sha256: String,
    body: Body,
}

fn validate_frequency(value: &DocumentFrequency, request: &StatisticsRequest) -> Result<()> {
    if value.term.is_empty()
        || value.term.len() > crate::MAX_SEARCH_TERM_BYTES
        || !value
            .term
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || value.documents == 0
        || u64::from(value.documents) > request.ingestion.corpus.entry_count
    {
        return Err("invalid closed term document frequency".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatisticsCommitment {
    pub request: StatisticsRequest,
    pub base: StatisticsProgress,
    pub next: StatisticsProgress,
    pub window_read_bytes: u64,
    pub window_write_bytes: u64,
    pub review_sha256: String,
}
impl StatisticsCommitment {
    fn review(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            STATS_DOMAIN,
            &self.request,
            &self.base,
            &self.next,
            self.window_read_bytes,
            self.window_write_bytes,
        ))?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.base.validate(&self.request)?;
        self.next.validate(&self.request)?;
        if self.window_read_bytes == 0
            || self.window_read_bytes > MAX_WINDOW_READ
            || self.window_write_bytes > MAX_WINDOW_WRITE
            || self.review_sha256 != self.review()?
        {
            return Err("statistics commitment review/budget mismatch".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 2 * PROGRESS_BYTES + 16 * 1024 {
            return Err("statistics commitment exceeds bounded envelope".into());
        }
        Ok(bytes)
    }
}
pub struct StatisticsPlan {
    commitment: StatisticsCommitment,
    pages: Vec<(String, Vec<u8>)>,
}
impl StatisticsPlan {
    pub fn commitment(&self) -> &StatisticsCommitment {
        &self.commitment
    }
}
pub struct PreparedStatistics {
    commitment: StatisticsCommitment,
}
impl PreparedStatistics {
    pub fn commitment(&self) -> &StatisticsCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected<B: StatisticsBoundary>(&self, b: &mut B) -> Result<()> {
        b.check(Access::Inspect {
            binding: &self.commitment.request.ingestion.corpus.binding,
        })?;
        b.current_job(
            &self.commitment.request.ingestion,
            &self.commitment.request.ingested,
        )?;
        b.current_builder(
            &self.commitment.request.ingestion.corpus,
            &self.commitment.request.ingestion.builder,
        )?;
        b.current_statistics(&self.commitment.request, &self.commitment.next)
    }
}

struct CachedPage {
    value: Page,
    observation: crate::v2::PageObservation,
}
#[derive(Default)]
struct InputCache {
    ingestion: BTreeMap<String, CachedRunPage>,
    merged: BTreeMap<String, CachedPage>,
}
struct Window<'a, 'b, B: StatisticsBoundary> {
    store: &'a ObjectStore,
    live: &'b mut Current<'a, B>,
    read_limit: u64,
    write_limit: u64,
    read: u64,
    work: u64,
    pages: Vec<(String, Vec<u8>)>,
    bytes: usize,
}
impl<B: StatisticsBoundary> Window<'_, '_, B> {
    fn work(&mut self, amount: u64) -> Result<()> {
        self.work = self
            .work
            .checked_add(amount)
            .ok_or("statistics work overflow")?;
        let remaining =
            self.live.request.ingestion.limits.floating_operations - self.live.base.totals.work;
        if self.work.checked_mul(2).map_or(true, |n| n > remaining) {
            return Err("finite cumulative statistics work exhausted".into());
        }
        Ok(())
    }
    fn remaining(&self) -> Result<u64> {
        self.read_limit
            .checked_sub(self.read)
            .ok_or_else(|| "statistics read allowance exhausted".into())
    }
    fn page(&mut self, hash: &str, cache: &mut BTreeMap<String, CachedPage>) -> Result<Page> {
        self.live.current()?;
        if let Some(value) = cache.get(hash) {
            if self.remaining()? < RUN_PAGE_READ {
                return Err("finite cached statistics verification allowance exhausted".into());
            }
            self.store
                .check_page_observation(
                    &value.observation,
                    IoBudget {
                        read_bytes: RUN_PAGE_READ,
                        write_bytes: 0,
                        new_files: 0,
                    },
                    self.live,
                )
                .and_then(|used| {
                    self.read = self
                        .read
                        .checked_add(used)
                        .ok_or("cached statistics read overflow")?;
                    Ok(())
                })?;
            self.live.current()?;
            return Ok(value.value.clone());
        }
        if self.remaining()? < RUN_PAGE_READ || cache.len() >= 256 {
            return Err("finite merged-page allowance exhausted".into());
        }
        let (bytes, observation) = self.store.read_page_observed(
            hash,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            self.live,
        )?;
        self.read = self
            .read
            .checked_add(bytes.len() as u64 + 1)
            .ok_or("statistics read overflow")?;
        let page: Page = decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
        if page.schema_version != 1
            || page.domain != STATS_DOMAIN
            || page.request_sha256 != self.live.request.sha256()?
        {
            return Err("merged page substitutes selected statistics request".into());
        }
        cache.insert(
            hash.into(),
            CachedPage {
                value: page.clone(),
                observation,
            },
        );
        self.live.current()?;
        Ok(page)
    }
    fn make(&mut self, body: Body) -> Result<String> {
        let bytes = serde_json::to_vec(&Page {
            schema_version: 1,
            domain: STATS_DOMAIN.into(),
            request_sha256: self.live.request.sha256()?,
            body,
        })?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or("statistics page bytes overflow")?;
        if bytes.len() > MAX_INDEX_PAGE_BYTES
            || self.bytes > MAX_WINDOW_WRITE as usize
            || self.pages.len() >= 2048
        {
            return Err("statistics immutable window memory/page bound exhausted".into());
        }
        // Per-file reserve covers payload, two new prefix directories and their
        // actual block growth; actual physical observations remain mandatory.
        if (self.pages.len() as u64 + 1) * PAGE_WRITE > self.write_limit {
            return Err("finite statistics immutable write reserve exhausted".into());
        }
        let hash = luma_content::sha256(&bytes);
        self.pages.push((hash.clone(), bytes));
        Ok(hash)
    }
    fn branch(&mut self, children: Vec<StatisticsNode>) -> Result<StatisticsNode> {
        if children.is_empty() || children.len() > 32 {
            return Err("statistics branch fanout invalid".into());
        }
        let first = children[0].first;
        let mut next = first;
        let mut height = 0;
        for child in &children {
            child.validate(self.live.request)?;
            if child.first != next {
                return Err("statistics branch lost exact coverage".into());
            }
            next = next
                .checked_add(child.count)
                .ok_or("statistics branch overflow")?;
            height = height.max(child.height);
        }
        let sha256 = self.make(Body::Branch { children })?;
        Ok(StatisticsNode {
            first,
            count: next - first,
            height: height + 1,
            sha256,
        })
    }
    fn range(
        &mut self,
        node: &StatisticsNode,
        range: std::ops::Range<u64>,
        cache: &mut BTreeMap<String, CachedPage>,
        output: &mut Vec<IngestPosting>,
    ) -> Result<()> {
        node.validate(self.live.request)?;
        match self.page(&node.sha256, cache)?.body {
            Body::Postings { first, entries } if node.height == 0 => {
                if first != node.first
                    || entries.len() as u64 != node.count
                    || entries.is_empty()
                    || entries.len() > pages::POSTING_ROWS
                {
                    return Err("merged posting leaf lost rank coverage".into());
                }
                let mut previous = None;
                for (i, entry) in entries.into_iter().enumerate() {
                    validate_posting(&entry, self.live.request)?;
                    let key = posting_key(&entry);
                    if previous.as_ref().is_some_and(|old| old >= &key) {
                        return Err("merged posting leaf is duplicated or unordered".into());
                    }
                    previous = Some(key);
                    if range.contains(&(first + i as u64)) {
                        output.push(entry);
                    }
                }
            }
            Body::Branch { children } if node.height != 0 => {
                if children.is_empty() || children.len() > 32 {
                    return Err("merged branch fanout invalid".into());
                }
                let mut next = node.first;
                let mut maximum = 0;
                for child in &children {
                    child.validate(self.live.request)?;
                    if child.first != next || child.height >= node.height {
                        return Err("merged subtree range/height substituted".into());
                    }
                    next = next
                        .checked_add(child.count)
                        .ok_or("merged range overflow")?;
                    maximum = maximum.max(child.height);
                }
                if next != node.first + node.count || maximum + 1 != node.height {
                    return Err("merged subtree total/height differs".into());
                }
                for child in children {
                    if child.first < range.end && child.first + child.count > range.start {
                        self.range(&child, range.clone(), cache, output)?;
                    }
                }
            }
            _ => return Err("merged posting tree crosses page types".into()),
        }
        Ok(())
    }
    fn input(
        &mut self,
        stream: &StatisticsStream,
        after: u64,
        maximum: usize,
        cache: &mut InputCache,
    ) -> Result<Vec<IngestPosting>> {
        stream.validate(self.live.request)?;
        if maximum == 0 || maximum > 128 || after > stream.postings() {
            return Err("statistics input rank/window invalid".into());
        }
        if after == stream.postings() {
            return Ok(Vec::new());
        }
        match stream {
            StatisticsStream::Ingest { run } => {
                let budget = self.remaining()?.min(4 * 1024 * 1024);
                let read = read_ingest_run_cached(
                    self.store,
                    &self.live.request.ingestion,
                    &self.live.request.ingested,
                    run,
                    after,
                    maximum,
                    IoBudget {
                        read_bytes: budget,
                        write_bytes: 0,
                        new_files: 0,
                    },
                    self.live,
                    &mut cache.ingestion,
                )?;
                self.read = self
                    .read
                    .checked_add(read.read_bytes)
                    .ok_or("statistics source read overflow")?;
                Ok(read.entries)
            }
            StatisticsStream::Merged {
                sha256,
                first,
                documents,
                postings,
                runs,
            } => {
                let Body::Stream {
                    inputs,
                    first: actual_first,
                    documents: actual_documents,
                    postings: actual_postings,
                    runs: actual_runs,
                    root,
                } = self.page(sha256, &mut cache.merged)?.body
                else {
                    return Err("merged stream descriptor has another page type".into());
                };
                if (actual_first, actual_documents, actual_postings, actual_runs)
                    != (*first, *documents, *postings, *runs)
                {
                    return Err("merged descriptor differs from selected stream".into());
                }
                let shape = stream_shape(&inputs, self.live.request)?;
                if shape != (*first, *documents, *postings, *runs) {
                    return Err("merged stream parent coverage differs".into());
                }
                let count = (*postings - after).min(maximum as u64);
                let mut entries = Vec::new();
                match root {
                    Some(node) if node.first == 0 && node.count == *postings => self.range(
                        &node,
                        after.saturating_sub(1)..after + count,
                        &mut cache.merged,
                        &mut entries,
                    )?,
                    _ => return Err("merged stream root coverage differs".into()),
                }
                if entries.len() as u64 != count + u64::from(after != 0) {
                    return Err("merged cursor lost exact rank coverage".into());
                }
                if entries
                    .windows(2)
                    .any(|p| posting_key(&p[0]) >= posting_key(&p[1]))
                {
                    return Err("merged cursor crossed unordered pages".into());
                }
                if after != 0 {
                    entries.remove(0);
                }
                Ok(entries)
            }
        }
    }
    fn append(&mut self, merge: &mut MergeProgress, entries: Vec<IngestPosting>) -> Result<()> {
        let mut pending = Vec::new();
        let mut first = merge.output_records;
        for entry in entries {
            pending.push(entry);
            let body = Body::Postings {
                first,
                entries: pending.clone(),
            };
            let size = serde_json::to_vec(&Page {
                schema_version: 1,
                domain: STATS_DOMAIN.into(),
                request_sha256: self.live.request.sha256()?,
                body,
            })?
            .len();
            if pending.len() > pages::POSTING_ROWS || size > MAX_INDEX_PAGE_BYTES {
                let last = pending.pop().ok_or("statistics leaf pack underflow")?;
                let count = pending.len() as u64;
                let hash = self.make(Body::Postings {
                    first,
                    entries: std::mem::take(&mut pending),
                })?;
                self.carry(
                    merge,
                    StatisticsNode {
                        first,
                        count,
                        height: 0,
                        sha256: hash,
                    },
                )?;
                first += count;
                pending.push(last);
            }
        }
        if !pending.is_empty() {
            let count = pending.len() as u64;
            let hash = self.make(Body::Postings {
                first,
                entries: pending,
            })?;
            self.carry(
                merge,
                StatisticsNode {
                    first,
                    count,
                    height: 0,
                    sha256: hash,
                },
            )?;
            first += count;
        }
        merge.output_records = first;
        Ok(())
    }
    fn carry(&mut self, merge: &mut MergeProgress, mut node: StatisticsNode) -> Result<()> {
        loop {
            let height = usize::from(node.height);
            if height >= merge.frontier.len() {
                return Err("statistics append frontier height exhausted".into());
            }
            merge.frontier[height].push(node);
            if merge.frontier[height].len() < 32 {
                return Ok(());
            }
            node = self.branch(std::mem::take(&mut merge.frontier[height]))?;
        }
    }
    fn finish_merge(&mut self, merge: &MergeProgress) -> Result<StatisticsStream> {
        let (first, documents, postings, runs) = stream_shape(&merge.inputs, self.live.request)?;
        if merge.output_records != postings
            || merge
                .inputs
                .iter()
                .zip(&merge.positions)
                .any(|(input, position)| input.postings() != *position)
        {
            return Err("statistics merge is not fully drained".into());
        }
        let mut nodes: Vec<_> = merge.frontier.iter().flatten().cloned().collect();
        nodes.sort_by_key(|n| n.first);
        while nodes.len() > 1 {
            let mut next = Vec::new();
            for children in nodes.chunks(32) {
                next.push(self.branch(children.to_vec())?);
            }
            nodes = next;
        }
        let root = nodes.pop();
        if root.as_ref().map_or(0, |n| n.count) != postings {
            return Err("statistics merged root total differs".into());
        }
        let sha256 = self.make(Body::Stream {
            inputs: merge.inputs.clone(),
            first,
            documents,
            postings,
            runs,
            root,
        })?;
        Ok(StatisticsStream::Merged {
            sha256,
            first,
            documents,
            postings,
            runs,
        })
    }
}
fn posting_key(value: &IngestPosting) -> (usize, String, u32) {
    (bucket(&value.term), value.term.clone(), value.document)
}
fn validate_posting(value: &IngestPosting, request: &StatisticsRequest) -> Result<()> {
    validate_frequency(
        &DocumentFrequency {
            term: value.term.clone(),
            documents: 1,
        },
        request,
    )?;
    if u64::from(value.document) >= request.ingestion.corpus.entry_count
        || value.frequency == 0
        || value.frequency > MAX_DOCUMENT_BYTES as u32
        || value.offset >= MAX_DOCUMENT_BYTES as u32
    {
        return Err("statistics posting source bounds differ".into());
    }
    Ok(())
}
fn stream_shape(
    inputs: &[StatisticsStream],
    request: &StatisticsRequest,
) -> Result<(u32, u32, u64, u32)> {
    if inputs.len() < 2 || inputs.len() > FAN_IN {
        return Err("statistics stream requires2–16 exact inputs".into());
    }
    let mut documents = 0_u32;
    let mut postings = 0_u64;
    let mut runs = 0_u32;
    for (i, input) in inputs.iter().enumerate() {
        input.validate(request)?;
        if i > 0
            && u64::from(input.first()) + u64::from(input.documents())
                != u64::from(inputs[i - 1].first())
        {
            return Err("statistics inputs skipped/overlapped document ranges".into());
        }
        documents = documents
            .checked_add(input.documents())
            .ok_or("statistics document overflow")?;
        postings = postings
            .checked_add(input.postings())
            .ok_or("statistics posting overflow")?;
        runs = runs
            .checked_add(input.runs())
            .ok_or("statistics run overflow")?;
    }
    if postings > request.ingested.totals.postings || u64::from(runs) > request.ingested.windows {
        return Err("statistics stream exceeds ingestion totals".into());
    }
    Ok((
        inputs.last().ok_or("missing input")?.first(),
        documents,
        postings,
        runs,
    ))
}
fn merge_start(inputs: Vec<StatisticsStream>, destination: MergeDestination) -> MergeProgress {
    let positions = vec![0; inputs.len()];
    MergeProgress {
        inputs,
        positions,
        frontier: vec![Vec::new(); 9],
        output_records: 0,
        destination,
    }
}
fn install_level(
    next: &mut StatisticsProgress,
    stream: StatisticsStream,
    level: usize,
) -> Result<()> {
    if level >= LEVELS {
        return Err("statistics compaction level exhausted".into());
    }
    next.levels[level].push(stream);
    if next.levels[level].len() == FAN_IN {
        if level + 1 >= LEVELS {
            return Err("statistics compaction exceeds selected100k runs".into());
        }
        let inputs = std::mem::take(&mut next.levels[level]);
        next.merging = Some(merge_start(
            inputs,
            MergeDestination::Level((level + 1) as u8),
        ));
    }
    Ok(())
}
fn begin_frequency(stream: StatisticsStream) -> FrequencyProgress {
    FrequencyProgress {
        stream: Some(stream),
        offset: 0,
        current: None,
        last_document: None,
        vocabulary: 0,
        bucket: 0,
        bucket_terms: 0,
        bucket_key_bytes: 0,
        top: Vec::new(),
    }
}
fn finish_term(
    frequency: &mut FrequencyProgress,
    top: &mut std::collections::BTreeSet<(u32, std::cmp::Reverse<String>)>,
) -> Result<()> {
    if let Some(entry) = frequency.current.take() {
        let bucket = bucket(&entry.term) as u16;
        if bucket < frequency.bucket {
            return Err("DF stream moved backwards across buckets".into());
        }
        if bucket != frequency.bucket {
            frequency.bucket = bucket;
            frequency.bucket_terms = 0;
            frequency.bucket_key_bytes = 0;
        }
        frequency.bucket_terms += 1;
        frequency.bucket_key_bytes += entry.term.len() as u64;
        if frequency.bucket_terms > MAX_BUCKET_TERMS as u64
            || frequency.bucket_key_bytes > 8 * 1024 * 1024
        {
            return Err("statistics hash-bucket vocabulary profile exhausted".into());
        }
        frequency.vocabulary = frequency
            .vocabulary
            .checked_add(1)
            .ok_or("DF vocabulary overflow")?;
        top.insert((entry.documents, std::cmp::Reverse(entry.term)));
        if top.len() > MAX_FEATURES {
            top.pop_first();
        }
    }
    frequency.last_document = None;
    Ok(())
}

pub fn plan_statistics_window<B: StatisticsBoundary>(
    store: &ObjectStore,
    request: &StatisticsRequest,
    base: &StatisticsProgress,
    read_bytes: u64,
    write_bytes: u64,
    b: &mut B,
) -> Result<StatisticsPlan> {
    base.validate(request)?;
    if base.complete
        || read_bytes == 0
        || read_bytes > MAX_WINDOW_READ
        || write_bytes > MAX_WINDOW_WRITE
        || read_bytes > request.ingestion.limits.read_bytes - base.totals.read_bytes
        || write_bytes > request.ingestion.limits.write_bytes - base.totals.write_bytes
    {
        return Err("statistics window exceeds remaining finite job".into());
    }
    let mut live = Current { request, base, b };
    live.admit(
        &request.ingestion.corpus.binding,
        ResourceBudget {
            memory_bytes: 192 * 1024 * 1024,
            tasks: 1,
            read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    let mut window = Window {
        store,
        live: &mut live,
        read_limit: read_bytes / 2,
        write_limit: write_bytes,
        read: 0,
        work: 0,
        pages: Vec::new(),
        bytes: 0,
    };
    let mut next = base.clone();
    if let Some(mut merge) = next.merging.take() {
        let mut caches: Vec<InputCache> = (0..merge.inputs.len())
            .map(|_| InputCache::default())
            .collect();
        let mut buffers: Vec<std::collections::VecDeque<IngestPosting>> = (0..merge.inputs.len())
            .map(|_| std::collections::VecDeque::new())
            .collect();
        let mut output = Vec::new();
        while output.len() < OUTPUT_RECORDS {
            if output.len() % 128 == 0 {
                window.live.current()?;
            }
            let mut selected: Option<usize> = None;
            for i in 0..merge.inputs.len() {
                if buffers[i].is_empty() && merge.positions[i] < merge.inputs[i].postings() {
                    buffers[i] = window
                        .input(&merge.inputs[i], merge.positions[i], 128, &mut caches[i])?
                        .into();
                    if buffers[i].is_empty() {
                        return Err("unfinished merge input returned no records".into());
                    }
                }
                if let Some(head) = buffers[i].front() {
                    window.work(head.term.len() as u64 + 1)?;
                    let replace = match selected {
                        None => true,
                        Some(old) => {
                            posting_key(head)
                                < posting_key(
                                    buffers[old]
                                        .front()
                                        .ok_or("selected merge head disappeared")?,
                                )
                        }
                    };
                    if replace {
                        selected = Some(i);
                    }
                }
            }
            let Some(i) = selected else {
                break;
            };
            let entry = buffers[i]
                .pop_front()
                .ok_or("selected merge head disappeared")?;
            if output
                .last()
                .is_some_and(|previous| posting_key(previous) >= posting_key(&entry))
            {
                return Err("statistics merge produced duplicate/unordered records".into());
            }
            merge.positions[i] += 1;
            output.push(entry);
        }
        window.append(&mut merge, output)?;
        if merge
            .inputs
            .iter()
            .zip(&merge.positions)
            .all(|(input, position)| input.postings() == *position)
        {
            let stream = window.finish_merge(&merge)?;
            match merge.destination {
                MergeDestination::Level(level) => {
                    install_level(&mut next, stream, usize::from(level))?
                }
                MergeDestination::Fold => next.fold = Some(stream),
            }
        } else {
            next.merging = Some(merge);
        }
    } else if let Some(mut frequency) = next.frequencies.take() {
        let mut top: std::collections::BTreeSet<_> = frequency
            .top
            .iter()
            .map(|value| (value.documents, std::cmp::Reverse(value.term.clone())))
            .collect();
        let stream = frequency
            .stream
            .as_ref()
            .ok_or("nonempty unfinished statistics has no stream")?
            .clone();
        let mut cache = InputCache::default();
        let mut consumed = 0;
        while frequency.offset < stream.postings() && consumed < OUTPUT_RECORDS {
            let entries = window.input(&stream, frequency.offset, 128, &mut cache)?;
            if entries.is_empty() {
                return Err("unfinished DF stream returned no records".into());
            }
            for entry in entries {
                window.work(entry.term.len() as u64 + 1)?;
                if frequency
                    .current
                    .as_ref()
                    .is_some_and(|value| value.term != entry.term)
                {
                    window.work(16)?;
                    finish_term(&mut frequency, &mut top)?;
                }
                match &mut frequency.current {
                    Some(current) => {
                        if frequency
                            .last_document
                            .is_some_and(|old| old >= entry.document)
                        {
                            return Err("DF stream repeats a document for one term".into());
                        }
                        current.documents = current
                            .documents
                            .checked_add(1)
                            .ok_or("DF count overflow")?;
                    }
                    None => {
                        frequency.current = Some(DocumentFrequency {
                            term: entry.term,
                            documents: 1,
                        })
                    }
                }
                frequency.last_document = Some(entry.document);
                frequency.offset += 1;
                consumed += 1;
            }
        }
        if frequency.offset == stream.postings() {
            window.work(16)?;
            finish_term(&mut frequency, &mut top)?;
            next.complete = true;
        }
        frequency.top = top
            .into_iter()
            .map(|(documents, term)| DocumentFrequency {
                term: term.0,
                documents,
            })
            .collect();
        frequency.top.sort_by(|a, z| a.term.cmp(&z.term));
        next.frequencies = Some(frequency);
    } else if let Some(run) = next.next_source_run.clone() {
        let mut cache = BTreeMap::new();
        let remaining = window.remaining()?.min(4 * 1024 * 1024);
        let value = read_ingest_run_cached(
            store,
            &request.ingestion,
            &request.ingested,
            &run,
            0,
            1,
            IoBudget {
                read_bytes: remaining,
                write_bytes: 0,
                new_files: 0,
            },
            window.live,
            &mut cache,
        )?;
        window.read = window
            .read
            .checked_add(value.read_bytes)
            .ok_or("statistics source read overflow")?;
        if u64::from(run.first) + u64::from(run.documents)
            != request.ingestion.corpus.entry_count - next.collected_documents
        {
            return Err("statistics collection skipped source run ordinals".into());
        }
        next.collected_documents += u64::from(run.documents);
        next.collected_runs += 1;
        next.collected_postings = next
            .collected_postings
            .checked_add(run.postings)
            .ok_or("collected posting overflow")?;
        next.next_source_run = value.previous;
        install_level(&mut next, StatisticsStream::Ingest { run }, 0)?;
    } else {
        if next.collected_documents != request.ingestion.corpus.entry_count
            || next.collected_runs != request.ingested.windows
            || next.collected_postings != request.ingested.totals.postings
        {
            return Err("statistics source collection is incomplete".into());
        }
        let mut inputs = Vec::new();
        if let Some(stream) = next.fold.take() {
            inputs.push(stream);
        }
        for level in (0..LEVELS).rev() {
            while !next.levels[level].is_empty() && inputs.len() < FAN_IN {
                inputs.push(next.levels[level].remove(0));
            }
        }
        match inputs.len() {
            0 => return Err("nonempty statistics has no retained source stream".into()),
            1 if next.levels.iter().all(|level| level.is_empty()) => {
                next.frequencies = Some(begin_frequency(inputs.remove(0)))
            }
            _ => next.merging = Some(merge_start(inputs, MergeDestination::Fold)),
        }
    }
    let write = (window.pages.len() as u64)
        .checked_mul(PAGE_WRITE)
        .ok_or("statistics write reserve overflow")?;
    // Reserve complete first pass + physical writer readback + independent
    // replay/page-presence verification. No successful-window counter reset.
    let page_read = window.pages.len() as u64 * RUN_PAGE_READ;
    let read = window
        .read
        .checked_add(page_read)
        .and_then(|n| n.checked_mul(2))
        .ok_or("statistics read reserve overflow")?;
    if read > read_bytes || write > write_bytes {
        return Err("statistics window does not reserve independent verification".into());
    }
    next.totals = base.totals.plus(&IngestTotals {
        read_bytes: read,
        write_bytes: write,
        source_bytes: 0,
        postings: 0,
        work: window
            .work
            .checked_mul(2)
            .ok_or("statistics work overflow")?,
    })?;
    next.canonical_bytes(request)?;
    window.live.current()?;
    let mut commitment = StatisticsCommitment {
        request: request.clone(),
        base: base.clone(),
        next,
        window_read_bytes: read_bytes,
        window_write_bytes: write_bytes,
        review_sha256: String::new(),
    };
    commitment.review_sha256 = commitment.review()?;
    commitment.canonical_bytes()?;
    Ok(StatisticsPlan {
        commitment,
        pages: window.pages,
    })
}
pub fn prepare_statistics<B: StatisticsBoundary>(
    store: &ObjectStore,
    plan: &StatisticsPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedStatistics> {
    let value = &plan.commitment;
    value.canonical_bytes()?;
    if mutation.review_sha256 != value.review_sha256
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != 0
    {
        return Err("statistics effect differs from reviewed window".into());
    }
    let mut live = Current {
        request: &value.request,
        base: &value.base,
        b,
    };
    for (hash, bytes) in &plan.pages {
        live.current()?;
        let actual = store.prepare_page(
            bytes,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: MAX_INDEX_PAGE_BYTES as u64,
                new_files: 3,
            },
            mutation,
            &mut live,
        )?;
        if actual != *hash {
            return Err("statistics writer substituted deterministic output".into());
        }
    }
    live.current()?;
    b.verify_statistics_allocations(value)?;
    b.check(Access::Mutate {
        binding: &value.request.ingestion.corpus.binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: 0,
        storage_bytes: value.next.totals.write_bytes - value.base.totals.write_bytes,
    })?;
    b.current_statistics(&value.request, &value.base)?;
    Ok(PreparedStatistics {
        commitment: value.clone(),
    })
}
pub fn verify_statistics_data<B: StatisticsBoundary>(
    store: &ObjectStore,
    value: &StatisticsCommitment,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let plan = plan_statistics_window(
        store,
        &value.request,
        &value.base,
        value.window_read_bytes,
        value.window_write_bytes,
        b,
    )?;
    if plan.commitment != *value {
        return Err("statistics candidate differs from independent exact replay".into());
    }
    let mut live = Current {
        request: &value.request,
        base: &value.base,
        b,
    };
    for (hash, expected) in &plan.pages {
        live.current()?;
        let actual = store.read_page(
            hash,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        if actual != *expected {
            return Err("statistics prepared page differs from replay".into());
        }
    }
    live.current()?;
    b.verify_statistics_allocations(value)?;
    b.check(Access::Inspect {
        binding: &value.request.ingestion.corpus.binding,
    })?;
    b.current_statistics(&value.request, &value.base)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatisticsResult {
    pub schema_version: u32,
    pub profile: String,
    pub request_sha256: String,
    pub corpus: MapRoot,
    pub builder: BuilderIdentity,
    pub sorted_stream: Option<StatisticsStream>,
    pub vocabulary: u64,
    pub features: Vec<DocumentFrequency>,
    pub totals: IngestTotals,
}
/// Fresh selected-stage DATA only: no covariance, projection, vectors, current
/// query generation, model output or publication/effect authority is returned.
pub fn read_statistics_result<B: StatisticsBoundary>(
    request: &StatisticsRequest,
    progress: &StatisticsProgress,
    b: &mut B,
) -> Result<StatisticsResult> {
    progress.validate(request)?;
    if !progress.complete {
        return Err("document-frequency stage is not complete".into());
    }
    let mut current = Current {
        request,
        base: progress,
        b,
    };
    current.current()?;
    let frequency = progress
        .frequencies
        .as_ref()
        .ok_or("statistics result has no DF state")?;
    let value = StatisticsResult {
        schema_version: 1,
        profile: STATS_DOMAIN.into(),
        request_sha256: request.sha256()?,
        corpus: request.ingestion.corpus.clone(),
        builder: request.ingestion.builder.clone(),
        sorted_stream: frequency.stream.clone(),
        vocabulary: frequency.vocabulary,
        features: frequency.top.clone(),
        totals: progress.totals,
    };
    current.current()?;
    Ok(value)
}

#[cfg(test)]
#[path = "statistics/tests.rs"]
mod tests;
