//! Read-only ranked posting DATA. A caller must independently authenticate the
//! selected generation and sorted-stream provenance; these bytes grant nothing.
use super::*;

#[derive(Clone)]
enum Node {
    Merged(StatisticsNode),
    Ingest(Part),
}
impl Node {
    fn first(&self) -> u64 {
        match self {
            Self::Merged(n) => n.first,
            Self::Ingest(n) => u64::from(n.first),
        }
    }
    fn count(&self) -> u64 {
        match self {
            Self::Merged(n) => n.count,
            Self::Ingest(n) => u64::from(n.count),
        }
    }
    fn height(&self) -> u8 {
        match self {
            Self::Merged(n) => n.height,
            Self::Ingest(n) => n.height,
        }
    }
    fn hash(&self) -> &str {
        match self {
            Self::Merged(n) => &n.sha256,
            Self::Ingest(n) => &n.sha256,
        }
    }
}
pub struct SelectedPostingReader<'a, B: CorpusIndexBoundary> {
    store: &'a dyn IndexReadStore,
    request: &'a StatisticsRequest,
    boundary: &'a mut B,
    root: Option<Node>,
    postings: u64,
    read_limit: u64,
    read: u64,
}
impl<'a, B: CorpusIndexBoundary> SelectedPostingReader<'a, B> {
    pub fn open(
        store: &'a dyn IndexReadStore,
        request: &'a StatisticsRequest,
        selected: &StatisticsProgress,
        read_limit: u64,
        boundary: &'a mut B,
    ) -> Result<Self> {
        selected.validate(request)?;
        if !selected.complete || read_limit == 0 || read_limit > 512 * 1024 * 1024 {
            return Err("posting reader requires complete finite read-only DATA".into());
        }
        let stream = selected
            .frequencies
            .as_ref()
            .ok_or("complete statistics lacks frequencies")?
            .stream
            .clone();
        let mut value = Self {
            store,
            request,
            boundary,
            root: None,
            postings: request.ingested.totals.postings,
            read_limit,
            read: 0,
        };
        value.current()?;
        match stream {
            None if value.postings == 0 => (),
            Some(StatisticsStream::Ingest { run }) => {
                run.validate(&request.ingestion)?;
                let bytes = value.bytes(&run.sha256)?;
                let page: RunPage = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
                let RunBody::Run {
                    first,
                    documents,
                    posting_records,
                    postings,
                    ..
                } = page.body
                else {
                    return Err("selected ingestion stream crosses page kinds".into());
                };
                if page.schema_version != 1
                    || page.domain != super::super::DOMAIN
                    || page.request_sha256 != request.ingestion.sha256()?
                    || (first, documents, posting_records)
                        != (run.first, run.documents, run.postings)
                    || first != 0
                    || u64::from(documents) != request.ingestion.corpus.entry_count
                    || run.postings != value.postings
                {
                    return Err("selected ingestion stream differs from whole corpus".into());
                }
                value.root = postings.map(Node::Ingest);
            }
            Some(StatisticsStream::Merged {
                sha256,
                first,
                documents,
                postings,
                runs,
            }) => {
                StatisticsStream::Merged {
                    sha256: sha256.clone(),
                    first,
                    documents,
                    postings,
                    runs,
                }
                .validate(request)?;
                let bytes = value.bytes(&sha256)?;
                let page: Page = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
                let Body::Stream {
                    inputs,
                    first: actual_first,
                    documents: actual_documents,
                    postings: actual_postings,
                    runs: actual_runs,
                    root,
                } = page.body
                else {
                    return Err("selected stream descriptor crosses page kinds".into());
                };
                if page.schema_version != 1
                    || page.domain != STATS_DOMAIN
                    || page.request_sha256 != request.sha256()?
                    || (actual_first, actual_documents, actual_postings, actual_runs)
                        != (first, documents, postings, runs)
                    || stream_shape(&inputs, request)? != (first, documents, postings, runs)
                    || first != 0
                    || u64::from(documents) != request.ingestion.corpus.entry_count
                    || postings != value.postings
                {
                    return Err("selected merged stream omits full exact source coverage".into());
                }
                value.root = root.map(Node::Merged);
            }
            _ => return Err("selected statistics stream omits actual postings".into()),
        }
        match &value.root {
            None if value.postings == 0 => (),
            Some(node) if node.first() == 0 && node.count() == value.postings => (),
            _ => {
                return Err("selected posting root differs from exact global rank coverage".into())
            }
        }
        value.current()?;
        Ok(value)
    }
    fn current(&mut self) -> Result<()> {
        self.boundary.check(Access::Inspect {
            binding: &self.request.ingestion.corpus.binding,
        })?;
        self.boundary
            .current_corpus(&self.request.ingestion.corpus)?;
        self.boundary.current_builder(
            &self.request.ingestion.corpus,
            &self.request.ingestion.builder,
        )
    }
    fn bytes(&mut self, sha256: &str) -> Result<Vec<u8>> {
        self.current()?;
        if self
            .read
            .checked_add(RUN_PAGE_READ)
            .map_or(true, |n| n > self.read_limit)
        {
            return Err("posting rank read allowance exhausted before I/O".into());
        }
        let bytes = self.store.read_page(
            sha256,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            self.boundary,
        )?;
        self.read = self
            .read
            .checked_add(bytes.len() as u64 + 1)
            .ok_or("posting rank measured read overflow")?;
        self.current()?;
        Ok(bytes)
    }
    pub fn read_bytes(&self) -> u64 {
        self.read
    }
    pub fn count(&self) -> u64 {
        self.postings
    }
    pub fn with_boundary_checked<R>(&mut self, f: impl FnOnce(&mut B) -> Result<R>) -> Result<R> {
        self.current()?;
        let result = f(self.boundary)?;
        self.current()?;
        Ok(result)
    }
    fn range_node(
        &mut self,
        node: &Node,
        range: std::ops::Range<u64>,
        output: &mut Vec<IngestPosting>,
    ) -> Result<()> {
        if node.count() == 0
            || node.height() > 12
            || node
                .first()
                .checked_add(node.count())
                .map_or(true, |n| n > self.postings)
        {
            return Err("posting rank subtree has invalid finite coverage".into());
        }
        let bytes = self.bytes(node.hash())?;
        let (entries, children) = match node {
            Node::Merged(n) => {
                let page: Page = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
                if page.schema_version != 1
                    || page.domain != STATS_DOMAIN
                    || page.request_sha256 != self.request.sha256()?
                {
                    return Err("posting rank page substitutes statistics context".into());
                }
                match page.body {
                    Body::Postings { first, entries } if n.height == 0 && first == n.first => {
                        (Some(entries), None)
                    }
                    Body::Branch { children } if n.height != 0 => (
                        None,
                        Some(children.into_iter().map(Node::Merged).collect::<Vec<_>>()),
                    ),
                    _ => return Err("posting rank tree crosses node types".into()),
                }
            }
            Node::Ingest(n) => {
                let page: RunPage = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
                if page.schema_version != 1
                    || page.domain != super::super::DOMAIN
                    || page.request_sha256 != self.request.ingestion.sha256()?
                {
                    return Err("posting rank page substitutes ingestion context".into());
                }
                match page.body {
                    RunBody::Postings { entries } if n.height == 0 => (
                        Some(
                            entries
                                .into_iter()
                                .map(IngestPosting::from_posting)
                                .collect(),
                        ),
                        None,
                    ),
                    RunBody::Branch { children } if n.height != 0 => (
                        None,
                        Some(children.into_iter().map(Node::Ingest).collect::<Vec<_>>()),
                    ),
                    _ => return Err("posting rank tree crosses ingestion types".into()),
                }
            }
        };
        if let Some(entries) = entries {
            if entries.is_empty()
                || entries.len() > pages::POSTING_ROWS
                || entries.len() as u64 != node.count()
            {
                return Err("posting rank leaf count differs".into());
            }
            let mut last = None;
            for (i, entry) in entries.into_iter().enumerate() {
                validate_posting(&entry, self.request)?;
                let key = posting_key(&entry);
                if last.as_ref().is_some_and(|old| old >= &key) {
                    return Err("posting rank leaf is duplicated or unordered".into());
                }
                last = Some(key);
                if range.contains(&(node.first() + i as u64)) {
                    output.push(entry);
                }
            }
        } else if let Some(children) = children {
            if children.is_empty() || children.len() > 32 {
                return Err("posting rank branch fanout invalid".into());
            }
            let mut end = node.first();
            let mut height = 0;
            for child in &children {
                if child.first() != end || child.height() >= node.height() || child.count() == 0 {
                    return Err("posting rank branch skips exact coverage".into());
                }
                end = end
                    .checked_add(child.count())
                    .ok_or("posting rank overflow")?;
                height = height.max(child.height());
            }
            if end != node.first() + node.count() || height + 1 != node.height() {
                return Err("posting rank branch total/height differs".into());
            }
            for child in children {
                if child.first() < range.end && child.first() + child.count() > range.start {
                    self.range_node(&child, range.clone(), output)?;
                }
            }
        }
        Ok(())
    }
    pub fn range(&mut self, after: u64, maximum: usize) -> Result<Vec<IngestPosting>> {
        if after > self.postings || maximum == 0 || maximum > 4096 {
            return Err("posting rank window invalid".into());
        }
        let count = (self.postings - after).min(maximum as u64);
        if count == 0 {
            self.current()?;
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let root = self.root.clone().ok_or("posting rank root absent")?;
        self.range_node(&root, after.saturating_sub(1)..after + count, &mut output)?;
        if output.len() as u64 != count + u64::from(after != 0)
            || output
                .windows(2)
                .any(|pair| posting_key(&pair[0]) >= posting_key(&pair[1]))
        {
            return Err("posting rank cursor crosses duplicate/missing/unordered rows".into());
        }
        if after != 0 {
            output.remove(0);
        }
        self.current()?;
        Ok(output)
    }
    /// Binary rank seek uses the fully verified selected generation's global
    /// ordering, then verifies the exact adjacent boundary. No bucket scan.
    pub fn lower_bound(&mut self, term: &str, document: u32) -> Result<u64> {
        if term.is_empty()
            || term.len() > crate::MAX_SEARCH_TERM_BYTES
            || !term
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err("posting seek term invalid".into());
        }
        let target = (bucket(term), term.to_owned(), document);
        let mut low = 0;
        let mut high = self.postings;
        while low < high {
            let middle = low + (high - low) / 2;
            let row = self
                .range(middle, 1)?
                .pop()
                .ok_or("posting seek rank absent")?;
            if posting_key(&row) < target {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low != 0
            && posting_key(
                &self
                    .range(low - 1, 1)?
                    .pop()
                    .ok_or("posting seek predecessor absent")?,
            ) >= target
        {
            return Err("posting seek predecessor does not prove lower bound".into());
        }
        if low < self.postings
            && posting_key(
                &self
                    .range(low, 1)?
                    .pop()
                    .ok_or("posting seek successor absent")?,
            ) < target
        {
            return Err("posting seek successor does not prove lower bound".into());
        }
        self.current()?;
        Ok(low)
    }
}
