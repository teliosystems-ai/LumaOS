//! Bounded, resumable ingestion DATA. This is not a selected index generation:
//! DF, covariance, projection and vectors are deliberately not represented by a
//! successful ingestion state. Progress selection and allocation accounting
//! require the independently implemented live boundary below.
use super::*;
use crate::v2::cursor::{MapCursor, MapCursorBoundary};
pub mod accounted;
pub mod covariance;
pub mod statistics;

const DOMAIN: &str = "luma-corpus-ingestion-v1";
pub const MAX_INGEST_DOCUMENTS: usize = 4;
const CURSOR_READ: u64 = 1024 * 1024;
const RUN_PAGE_READ: u64 = 32 * 1024;
const MAX_RUN_PAGES: usize = 2048;
const MAX_RUN_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngestRequest {
    pub schema_version: u32,
    pub job_sha256: String,
    pub corpus: MapRoot,
    pub builder: BuilderIdentity,
    pub limits: CorpusIndexLimits,
}
impl IngestRequest {
    pub fn validate(&self) -> Result<()> {
        corpus(&self.corpus)?;
        self.builder.validate()?;
        self.limits.validate()?;
        hash(&self.job_sha256)?;
        if self.schema_version != 1 || self.limits.write_bytes == 0 {
            return Err("ingestion request requires a closed finite write profile".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngestTotals {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub source_bytes: u64,
    pub postings: u64,
    pub work: u64,
}
impl IngestTotals {
    fn validate(&self, limits: &CorpusIndexLimits) -> Result<()> {
        if self.read_bytes > limits.read_bytes
            || self.write_bytes > limits.write_bytes
            || self.source_bytes > limits.source_bytes
            || self.postings > limits.postings
            || self.work > limits.floating_operations
        {
            return Err("cumulative ingestion accounting exceeds the reviewed job".into());
        }
        Ok(())
    }
    fn plus(&self, delta: &Self) -> Result<Self> {
        Ok(Self {
            read_bytes: self
                .read_bytes
                .checked_add(delta.read_bytes)
                .ok_or("read overflow")?,
            write_bytes: self
                .write_bytes
                .checked_add(delta.write_bytes)
                .ok_or("write overflow")?,
            source_bytes: self
                .source_bytes
                .checked_add(delta.source_bytes)
                .ok_or("source overflow")?,
            postings: self
                .postings
                .checked_add(delta.postings)
                .ok_or("posting overflow")?,
            work: self.work.checked_add(delta.work).ok_or("work overflow")?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunRef {
    pub sha256: String,
    pub first: u32,
    pub documents: u32,
    pub postings: u64,
}
impl RunRef {
    fn validate(&self, request: &IngestRequest) -> Result<()> {
        hash(&self.sha256)?;
        if self.documents == 0
            || self.documents as usize > MAX_INGEST_DOCUMENTS
            || u64::from(self.first) + u64::from(self.documents) > request.corpus.entry_count
            || self.postings > MAX_INGEST_DOCUMENTS as u64 * MAX_DOCUMENT_TERMS as u64
        {
            return Err("ingestion run has invalid exact ordinal coverage".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngestProgress {
    pub schema_version: u32,
    pub request_sha256: String,
    pub cursor: MapCursor,
    pub windows: u64,
    pub last_run: Option<RunRef>,
    pub totals: IngestTotals,
}
impl IngestProgress {
    /// Pure initial DATA, never permission to reset an existing C-selected job.
    pub fn beginning(request: &IngestRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            schema_version: 1,
            request_sha256: request.sha256()?,
            cursor: MapCursor::beginning(&request.corpus)?,
            windows: 0,
            last_run: None,
            totals: IngestTotals::default(),
        })
    }
    pub fn validate(&self, request: &IngestRequest) -> Result<()> {
        request.validate()?;
        self.cursor.canonical_bytes(&request.corpus)?;
        self.totals.validate(&request.limits)?;
        let count = self.cursor.after_count();
        if self.schema_version != 1
            || self.request_sha256 != request.sha256()?
            || self.windows > count
            || count > self.windows.saturating_mul(MAX_INGEST_DOCUMENTS as u64)
            || (count == 0) != self.last_run.is_none()
            || (count == 0) != (self.windows == 0)
        {
            return Err("ingestion progress substitutes request or coverage".into());
        }
        if let Some(run) = &self.last_run {
            run.validate(request)?;
            if u64::from(run.first) + u64::from(run.documents) != count
                || run.postings > self.totals.postings
            {
                return Err("ingestion tail differs from cumulative progress".into());
            }
        }
        if count == 0 && self.totals != IngestTotals::default() {
            return Err("initial ingestion progress has nonzero accounting".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self, request: &IngestRequest) -> Result<Vec<u8>> {
        self.validate(request)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_INDEX_PAGE_BYTES {
            return Err("ingestion progress exceeds one page".into());
        }
        Ok(bytes)
    }
    pub fn complete(&self, request: &IngestRequest) -> Result<bool> {
        self.validate(request)?;
        Ok(self.cursor.after_count() == request.corpus.entry_count)
    }
}

/// Neither method has a default. Runtime integration must bind progress to
/// current independent C, and verify actual retained allocation observations,
/// including failed-window reservations; a supplied JSON counter is not enough.
pub trait CorpusIndexJobBoundary: CorpusIndexBoundary {
    fn current_job(&mut self, request: &IngestRequest, progress: &IngestProgress) -> Result<()>;
    fn verify_ingest_allocations(&mut self, value: &IngestCommitment) -> Result<()>;
}

struct Live<'a, B: CorpusIndexJobBoundary> {
    request: &'a IngestRequest,
    progress: &'a IngestProgress,
    boundary: &'a mut B,
}
impl<B: CorpusIndexJobBoundary> Live<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.boundary.check(Access::Inspect {
            binding: &self.request.corpus.binding,
        })?;
        self.boundary.current_job(self.request, self.progress)?;
        self.boundary.current_corpus(&self.request.corpus)?;
        self.boundary
            .current_builder(&self.request.corpus, &self.request.builder)
    }
}
impl<B: CorpusIndexJobBoundary> Boundary for Live<'_, B> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        if binding != &self.request.corpus.binding {
            return Err("ingestion object owner differs".into());
        }
        self.current()?;
        self.boundary.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.boundary.check(access)?;
        self.current()
    }
}
impl<B: CorpusIndexJobBoundary> CorpusIndexBoundary for Live<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.request.corpus {
            return Err("ingestion corpus substituted".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, identity: &BuilderIdentity) -> Result<()> {
        if root != &self.request.corpus || identity != &self.request.builder {
            return Err("ingestion builder substituted".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, manifest: &str) -> Result<()> {
        self.current()?;
        self.boundary.current_index_generation(root, manifest)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.boundary.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: CorpusIndexJobBoundary> MapCursorBoundary for Live<'_, B> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.current_corpus(root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Part {
    first: u32,
    count: u32,
    height: u8,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RunBody {
    Documents {
        first: u32,
        records: Vec<CorpusRecord>,
    },
    Postings {
        entries: Vec<Posting>,
    },
    Branch {
        children: Vec<Part>,
    },
    Run {
        previous: Option<RunRef>,
        first: u32,
        documents: u32,
        posting_records: u64,
        document_page: String,
        postings: Option<Part>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunPage {
    schema_version: u32,
    domain: String,
    request_sha256: String,
    body: RunBody,
}

/// Typed posting DATA returned only after exact immutable page validation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngestPosting {
    pub term: String,
    pub document: u32,
    pub frequency: u32,
    pub offset: u32,
}
impl IngestPosting {
    fn from_posting(value: Posting) -> Self {
        Self {
            term: value.term,
            document: value.document,
            frequency: value.frequency,
            offset: value.offset,
        }
    }
}
pub struct IngestRunWindow {
    pub previous: Option<RunRef>,
    pub entries: Vec<IngestPosting>,
    pub next_offset: u64,
    pub complete: bool,
    /// Conservative read credit actually reserved before each held object read.
    pub read_bytes: u64,
}

struct RunReader<'a, 'b, B: CorpusIndexJobBoundary> {
    store: &'a dyn IndexReadStore,
    live: &'b mut Live<'a, B>,
    maximum: u64,
    read: u64,
    cache: BTreeMap<String, CachedRunPage>,
    first_document: u32,
    records: Vec<CorpusRecord>,
}
struct CachedRunPage {
    page: RunPage,
    observation: storage::IndexObservation,
}
impl<B: CorpusIndexJobBoundary> RunReader<'_, '_, B> {
    fn get(&mut self, hash: &str) -> Result<RunPage> {
        self.live.current()?;
        if let Some(value) = self.cache.get(hash) {
            if self
                .read
                .checked_add(RUN_PAGE_READ)
                .map_or(true, |n| n > self.maximum)
            {
                return Err("finite cached-run content verification allowance exhausted".into());
            }
            let used = self.store.check_page_observation(
                &value.observation,
                IoBudget {
                    read_bytes: RUN_PAGE_READ,
                    write_bytes: 0,
                    new_files: 0,
                },
                self.live,
            )?;
            self.read = self
                .read
                .checked_add(used)
                .ok_or("cached run read overflow")?;
            self.live.current()?;
            return Ok(value.page.clone());
        }
        let upper = self
            .read
            .checked_add(RUN_PAGE_READ)
            .ok_or("run read overflow")?;
        if upper > self.maximum || self.cache.len() >= 256 {
            return Err("finite ingestion-run read allowance exhausted".into());
        }
        self.live.current()?;
        let (bytes, observation) = self.store.read_page_observed(
            hash,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            self.live,
        )?;
        let value: RunPage = decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
        self.read = self
            .read
            .checked_add(bytes.len() as u64 + 1)
            .ok_or("run read overflow")?;
        if value.schema_version != 1
            || value.domain != DOMAIN
            || value.request_sha256 != self.live.request.sha256()?
        {
            return Err("ingestion run page substitutes builder/request domain".into());
        }
        self.cache.insert(
            hash.into(),
            CachedRunPage {
                page: value.clone(),
                observation,
            },
        );
        Ok(value)
    }
    fn range(
        &mut self,
        part: &Part,
        range: std::ops::Range<u64>,
        output: &mut Vec<Posting>,
    ) -> Result<()> {
        hash(&part.sha256)?;
        if part.count == 0
            || part.height > 8
            || u64::from(part.first) + u64::from(part.count)
                > MAX_INGEST_DOCUMENTS as u64 * MAX_DOCUMENT_TERMS as u64
        {
            return Err("invalid ingestion posting subtree range".into());
        }
        match self.get(&part.sha256)?.body {
            RunBody::Postings { entries } if part.height == 0 => {
                if entries.len() != part.count as usize || entries.len() > pages::POSTING_ROWS {
                    return Err("ingestion leaf count differs from authenticated span".into());
                }
                let mut previous: Option<(usize, String, u32)> = None;
                for (offset, entry) in entries.into_iter().enumerate() {
                    if entry.term.is_empty()
                        || entry.term.len() > crate::MAX_SEARCH_TERM_BYTES
                        || !entry
                            .term
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                        || entry.document < self.first_document
                        || entry.document - self.first_document >= self.records.len() as u32
                    {
                        return Err("ingestion posting term/document is outside its run".into());
                    }
                    let record = &self.records[(entry.document - self.first_document) as usize];
                    if entry.frequency == 0
                        || u64::from(entry.frequency) > record.content_bytes
                        || u64::from(entry.offset) >= record.content_bytes
                    {
                        return Err(
                            "ingestion posting frequency/offset exceeds exact source".into()
                        );
                    }
                    let key = (bucket(&entry.term), entry.term.clone(), entry.document);
                    if previous.as_ref().is_some_and(|old| old >= &key) {
                        return Err("ingestion posting leaf is repeated or unordered".into());
                    }
                    previous = Some(key);
                    let rank = u64::from(part.first) + offset as u64;
                    if range.contains(&rank) {
                        output.push(entry);
                    }
                }
            }
            RunBody::Branch { children } if part.height != 0 => {
                if children.is_empty() || children.len() > 32 {
                    return Err("ingestion branch fanout invalid".into());
                }
                let mut next = part.first;
                for child in &children {
                    if child.first != next || child.height + 1 != part.height || child.count == 0 {
                        return Err("ingestion subtree lost exact contiguous rank coverage".into());
                    }
                    next = next.checked_add(child.count).ok_or("run rank overflow")?;
                }
                if u64::from(next) != u64::from(part.first) + u64::from(part.count) {
                    return Err("ingestion branch total differs".into());
                }
                for child in children {
                    if u64::from(child.first) < range.end
                        && u64::from(child.first) + u64::from(child.count) > range.start
                    {
                        self.range(&child, range.clone(), output)?;
                    }
                }
            }
            _ => return Err("ingestion posting tree crosses page type/height".into()),
        }
        Ok(())
    }
}

/// A bounded DATA accessor. The caller must separately bind run/rank to its
/// current selected phase progress; an arbitrary historical run argument is not
/// proof of membership in the current ingestion chain.
pub fn read_ingest_run_window<B: CorpusIndexJobBoundary>(
    store: &dyn IndexReadStore,
    request: &IngestRequest,
    ingested: &IngestProgress,
    run: &RunRef,
    after: u64,
    maximum: usize,
    budget: IoBudget,
    b: &mut B,
) -> Result<IngestRunWindow> {
    read_ingest_run_cached(
        store,
        request,
        ingested,
        run,
        after,
        maximum,
        budget,
        b,
        &mut BTreeMap::new(),
    )
}

// A cache is local to ONE separately admitted statistics window. Its immutable
// hash-bound bytes never constitute a saved cursor or selected-job permission.
fn read_ingest_run_cached<B: CorpusIndexJobBoundary>(
    store: &dyn IndexReadStore,
    request: &IngestRequest,
    ingested: &IngestProgress,
    run: &RunRef,
    after: u64,
    maximum: usize,
    budget: IoBudget,
    b: &mut B,
    cache: &mut BTreeMap<String, CachedRunPage>,
) -> Result<IngestRunWindow> {
    // Any refusal poisons this ephemeral cache, including a failure before the
    // first file read or before admission has refreshed original authority.
    let captured_cache = std::mem::take(cache);
    request.validate()?;
    ingested.validate(request)?;
    run.validate(request)?;
    budget.validate()?;
    if !ingested.complete(request)?
        || maximum == 0
        || maximum > 128
        || budget.write_bytes != 0
        || budget.new_files != 0
        || budget.read_bytes > 4 * 1024 * 1024
        || after > run.postings
        || (after == run.postings && run.postings != 0)
    {
        return Err(
            "ingestion-run accessor requires a completed build and bounded read rank".into(),
        );
    }
    let mut live = Live {
        request,
        progress: ingested,
        boundary: b,
    };
    live.admit(
        &request.corpus.binding,
        ResourceBudget {
            memory_bytes: 192 * 1024 * 1024,
            tasks: 1,
            read_bytes: budget.read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    let mut reader = RunReader {
        store,
        live: &mut live,
        maximum: budget.read_bytes,
        read: 0,
        cache: captured_cache,
        first_document: run.first,
        records: Vec::new(),
    };
    let RunBody::Run {
        previous,
        first,
        documents,
        posting_records,
        document_page,
        postings,
    } = reader.get(&run.sha256)?.body
    else {
        return Err("ingestion run reference is not a run descriptor".into());
    };
    if first != run.first || documents != run.documents || posting_records != run.postings {
        return Err("ingestion run descriptor differs from exact committed reference".into());
    }
    match &previous {
        Some(value) => {
            value.validate(request)?;
            if u64::from(value.first) + u64::from(value.documents) != u64::from(first) {
                return Err("ingestion run chain skipped document ordinals".into());
            }
        }
        None if first == 0 => {}
        None => return Err("ingestion run chain terminates before corpus genesis".into()),
    }
    let RunBody::Documents {
        first: document_first,
        records,
    } = reader.get(&document_page)?.body
    else {
        return Err("ingestion run document reference has another page type".into());
    };
    if document_first != first || records.len() != documents as usize {
        return Err("ingestion document page lost coverage".into());
    }
    for record in &records {
        record.validate()?;
        reader.live.current_candidate(&request.corpus, record)?;
    }
    reader.records = records;
    let count = (run.postings - after).min(maximum as u64);
    let mut entries = Vec::new();
    match postings {
        Some(part)
            if run.postings != 0 && part.first == 0 && u64::from(part.count) == run.postings =>
        {
            reader.range(&part, after.saturating_sub(1)..after + count, &mut entries)?;
            let expected = count + u64::from(after != 0);
            if entries.len() as u64 != expected {
                return Err("ingestion posting window lost rank coverage".into());
            }
            for pair in entries.windows(2) {
                if (bucket(&pair[0].term), &pair[0].term, pair[0].document)
                    >= (bucket(&pair[1].term), &pair[1].term, pair[1].document)
                {
                    return Err("ingestion cursor crossed unordered posting pages".into());
                }
            }
            if after != 0 {
                entries.remove(0);
            }
        }
        None if run.postings == 0 => {}
        _ => return Err("ingestion posting root does not match run total".into()),
    }
    reader.live.current()?;
    let result = IngestRunWindow {
        previous,
        entries: entries
            .into_iter()
            .map(IngestPosting::from_posting)
            .collect(),
        next_offset: after + count,
        complete: after + count == run.postings,
        read_bytes: reader.read,
    };
    *cache = reader.cache;
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngestCommitment {
    pub request: IngestRequest,
    pub base: IngestProgress,
    pub next: IngestProgress,
    pub maximum_documents: u8,
    pub window_limits: CorpusIndexLimits,
    pub review_sha256: String,
}
impl IngestCommitment {
    fn review(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            DOMAIN,
            &self.request,
            &self.base,
            &self.next,
            self.maximum_documents,
            self.window_limits,
        ))?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.request.validate()?;
        self.base.validate(&self.request)?;
        self.next.validate(&self.request)?;
        self.window_limits.validate()?;
        if self.maximum_documents == 0
            || self.maximum_documents as usize > MAX_INGEST_DOCUMENTS
            || self.review_sha256 != self.review()?
        {
            return Err("ingestion commitment review/bound mismatch".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 {
            return Err("ingestion commitment exceeds16KiB".into());
        }
        Ok(bytes)
    }
}

/// Non-deserializable reviewed construction. Private pages are bounded to32MiB;
/// no source text or entire corpus is retained across a window.
pub struct IngestPlan {
    commitment: IngestCommitment,
    records: Vec<CorpusRecord>,
    pages: Vec<(String, Vec<u8>)>,
}
impl IngestPlan {
    pub fn commitment(&self) -> &IngestCommitment {
        &self.commitment
    }
}
pub struct PreparedIngest {
    commitment: IngestCommitment,
}
impl PreparedIngest {
    pub fn commitment(&self) -> &IngestCommitment {
        &self.commitment
    }
    /// Call only after independent publication. A receipt cannot implement the
    /// required current-job boundary or extend the original finite session.
    pub fn acknowledge_selected<B: CorpusIndexJobBoundary>(&self, b: &mut B) -> Result<()> {
        b.current_corpus(&self.commitment.request.corpus)?;
        b.current_builder(
            &self.commitment.request.corpus,
            &self.commitment.request.builder,
        )?;
        b.check(Access::Inspect {
            binding: &self.commitment.request.corpus.binding,
        })?;
        b.current_job(&self.commitment.request, &self.commitment.next)
    }
}

struct Cache {
    request: String,
    pages: Vec<(String, Vec<u8>)>,
    bytes: usize,
}
impl Cache {
    fn put(&mut self, body: RunBody) -> Result<String> {
        let bytes = serde_json::to_vec(&RunPage {
            schema_version: 1,
            domain: DOMAIN.into(),
            request_sha256: self.request.clone(),
            body,
        })?;
        if bytes.len() > MAX_INDEX_PAGE_BYTES {
            return Err("ingestion leaf exceeds16KiB".into());
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or("run byte overflow")?;
        if self.pages.len() >= MAX_RUN_PAGES || self.bytes > MAX_RUN_BYTES {
            return Err("ingestion window immutable-page memory profile exhausted".into());
        }
        let hash = luma_content::sha256(&bytes);
        self.pages.push((hash.clone(), bytes));
        Ok(hash)
    }
}

fn finite_remaining(
    request: &IngestRequest,
    base: &IngestProgress,
    window: CorpusIndexLimits,
) -> Result<()> {
    window.validate()?;
    base.validate(request)?;
    if window.write_bytes == 0
        || window.read_bytes > request.limits.read_bytes - base.totals.read_bytes
        || window.write_bytes > request.limits.write_bytes - base.totals.write_bytes
        || window.source_bytes > request.limits.source_bytes - base.totals.source_bytes
        || window.postings > request.limits.postings - base.totals.postings
        || window.floating_operations > request.limits.floating_operations - base.totals.work
    {
        return Err("window reservation exceeds remaining cumulative job accounting".into());
    }
    Ok(())
}

pub fn plan_ingestion_window<B: CorpusIndexJobBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    request: &IngestRequest,
    base: &IngestProgress,
    maximum: usize,
    window: CorpusIndexLimits,
    content: &mut C,
    b: &mut B,
) -> Result<IngestPlan> {
    finite_remaining(request, base, window)?;
    if maximum == 0 || maximum > MAX_INGEST_DOCUMENTS || base.complete(request)? {
        return Err("ingestion requires an unfinished finite document window".into());
    }
    let root = &request.corpus;
    let mut live = Live {
        request,
        progress: base,
        boundary: b,
    };
    let mut read_limits = window;
    read_limits.write_bytes = 0;
    let mut meter = Meter::new(root, &request.builder, read_limits, None, &mut live)?;
    meter.read(CURSOR_READ)?;
    let scan = store.scan_map_window(
        root,
        &base.cursor,
        maximum,
        IoBudget {
            read_bytes: CURSOR_READ,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let mut records = Vec::new();
    let mut postings = Vec::new();
    for (key, bytes) in scan.entries {
        meter.check(root, &mut live)?;
        let record = CorpusRecord::parse(&bytes, root, &key)?;
        meter.source = meter
            .source
            .checked_add(record.content_bytes)
            .ok_or("source overflow")?;
        if meter.source > window.source_bytes {
            return Err("window source bound exhausted".into());
        }
        let bytes = read_content(root, &record, content, &mut meter, &mut live)?;
        let document = u32::try_from(base.cursor.after_count() + records.len() as u64)?;
        for (term, (frequency, offset)) in words(&bytes, root, &mut meter, &mut live)? {
            meter.postings = meter.postings.checked_add(1).ok_or("posting overflow")?;
            if meter.postings > window.postings {
                return Err("window posting bound exhausted".into());
            }
            postings.push((
                bucket(&term),
                Posting {
                    term,
                    document,
                    frequency,
                    offset,
                },
            ));
        }
        records.push(record);
    }
    if records.is_empty() {
        return Err("unfinished corpus returned no ingestion records".into());
    }
    // Cache bucket hashes before sorting; hashing the term in each comparison
    // would amplify CPU work without contributing any new authenticated data.
    meter.work(postings.len() as u64 * 32, root, &mut live)?;
    postings.sort_by(|a, z| (a.0, &a.1.term, a.1.document).cmp(&(z.0, &z.1.term, z.1.document)));
    let mut cache = Cache {
        request: request.sha256()?,
        pages: Vec::new(),
        bytes: 0,
    };
    let document_page = cache.put(RunBody::Documents {
        first: base.cursor.after_count() as u32,
        records: records.clone(),
    })?;
    let mut parts = Vec::new();
    let mut pending = Vec::new();
    let mut first = 0_u32;
    for (ordinal, (_, entry)) in postings.into_iter().enumerate() {
        if ordinal % pages::POSTING_ROWS == 0 {
            meter.check(root, &mut live)?;
        }
        pending.push(entry);
        let body = RunPage {
            schema_version: 1,
            domain: DOMAIN.into(),
            request_sha256: cache.request.clone(),
            body: RunBody::Postings {
                entries: pending.clone(),
            },
        };
        if pending.len() > pages::POSTING_ROWS
            || serde_json::to_vec(&body)?.len() > MAX_INDEX_PAGE_BYTES
        {
            let last = pending.pop().ok_or("posting pack underflow")?;
            let count = pending.len() as u32;
            let hash = cache.put(RunBody::Postings {
                entries: std::mem::take(&mut pending),
            })?;
            parts.push(Part {
                first,
                count,
                height: 0,
                sha256: hash,
            });
            first += count;
            pending.push(last);
        }
    }
    if !pending.is_empty() {
        let count = pending.len() as u32;
        let sha256 = cache.put(RunBody::Postings { entries: pending })?;
        parts.push(Part {
            first,
            count,
            height: 0,
            sha256,
        });
    }
    while parts.len() > 1 {
        let mut next = Vec::new();
        for children in parts.chunks(32) {
            meter.check(root, &mut live)?;
            let first = children.first().ok_or("missing run child")?;
            let count = children.iter().try_fold(0_u32, |n, p| {
                n.checked_add(p.count).ok_or("run count overflow")
            })?;
            let hash = cache.put(RunBody::Branch {
                children: children.to_vec(),
            })?;
            next.push(Part {
                first: first.first,
                count,
                height: first.height + 1,
                sha256: hash,
            });
        }
        parts = next;
    }
    let run_hash = cache.put(RunBody::Run {
        previous: base.last_run.clone(),
        first: base.cursor.after_count() as u32,
        documents: records.len() as u32,
        posting_records: meter.postings,
        document_page,
        postings: parts.pop(),
    })?;
    // Reserve every actual writer/readback page before any private write. The
    // cursor allowance is1MiB, not512MiB per4documents, so100k remains expressible.
    let write = (cache.pages.len() as u64)
        .checked_mul(PAGE_WRITE)
        .ok_or("page reserve overflow")?;
    if write > window.write_bytes {
        return Err("window immutable allocation allowance exhausted".into());
    }
    meter.read(cache.pages.len() as u64 * RUN_PAGE_READ)?;
    // The independent publisher repeats semantic construction and then reads
    // every prepared page. Account for BOTH construction passes, not just the
    // worker's first pass. Failed/review-only attempts must additionally remain
    // charged by the boundary's real admission/reservation implementation.
    let read_bytes = meter
        .read
        .checked_mul(2)
        .ok_or("verification read reserve overflow")?;
    let work = meter
        .work
        .checked_mul(2)
        .ok_or("verification work reserve overflow")?;
    if read_bytes > window.read_bytes || work > window.floating_operations {
        return Err("window does not reserve independent semantic verification".into());
    }
    let delta = IngestTotals {
        read_bytes,
        write_bytes: write,
        source_bytes: meter.source,
        postings: meter.postings,
        work,
    };
    let next = IngestProgress {
        schema_version: 1,
        request_sha256: request.sha256()?,
        cursor: scan.next,
        windows: base.windows + 1,
        last_run: Some(RunRef {
            sha256: run_hash,
            first: base.cursor.after_count() as u32,
            documents: records.len() as u32,
            postings: meter.postings,
        }),
        totals: base.totals.plus(&delta)?,
    };
    let mut commitment = IngestCommitment {
        request: request.clone(),
        base: base.clone(),
        next,
        maximum_documents: maximum as u8,
        window_limits: window,
        review_sha256: String::new(),
    };
    commitment.review_sha256 = commitment.review()?;
    commitment.canonical_bytes()?;
    meter.check(root, &mut live)?;
    Ok(IngestPlan {
        commitment,
        records,
        pages: cache.pages,
    })
}

pub fn prepare_ingestion<B: CorpusIndexJobBoundary>(
    store: &ObjectStore,
    plan: &IngestPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedIngest> {
    let value = &plan.commitment;
    value.canonical_bytes()?;
    if mutation.review_sha256 != value.review_sha256
        || mutation.decision != crate::DecisionKind::Published
        || mutation.source_bytes != value.next.totals.source_bytes - value.base.totals.source_bytes
    {
        return Err("ingestion effect differs from the independently reviewed exact window".into());
    }
    let mut live = Live {
        request: &value.request,
        progress: &value.base,
        boundary: b,
    };
    for record in &plan.records {
        live.current_candidate(&value.request.corpus, record)?;
    }
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
            return Err("ingestion object writer substituted exact output".into());
        }
        live.current()?;
    }
    for record in &plan.records {
        live.current_candidate(&value.request.corpus, record)?;
    }
    live.current()?;
    b.verify_ingest_allocations(value)?;
    b.check(Access::Mutate {
        binding: &value.request.corpus.binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: mutation.source_bytes,
        storage_bytes: value.next.totals.write_bytes - value.base.totals.write_bytes,
    })?;
    b.current_job(&value.request, &value.base)?;
    Ok(PreparedIngest {
        commitment: value.clone(),
    })
}

/// Independent read-only semantic reconstruction, not a hash-only publication
/// setter. Every expected page must actually exist with exactly rebuilt bytes.
pub fn verify_ingestion_data<B: CorpusIndexJobBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    value: &IngestCommitment,
    content: &mut C,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let plan = plan_ingestion_window(
        store,
        &value.request,
        &value.base,
        value.maximum_documents as usize,
        value.window_limits,
        content,
        b,
    )?;
    if plan.commitment != *value {
        return Err("ingestion candidate differs from exact replay".into());
    }
    let mut live = Live {
        request: &value.request,
        progress: &value.base,
        boundary: b,
    };
    for (hash, bytes) in &plan.pages {
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
        if actual != *bytes {
            return Err("prepared ingestion page differs from semantic replay".into());
        }
    }
    live.current()?;
    b.verify_ingest_allocations(value)?;
    b.check(Access::Inspect {
        binding: &value.request.corpus.binding,
    })?;
    b.current_job(&value.request, &value.base)
}

#[cfg(test)]
#[path = "job/tests.rs"]
mod tests;
