//! Bounded exact-source vector materialization over a selected completed basis.
//! Completion is DATA, not an index-generation publication or query grant.
use super::*;
use crate::v2::cursor::MapCursorBoundary;
pub mod coordinates;
pub mod generation;
pub mod read;

const VECTOR_DOMAIN: &str = "luma-corpus-vector-materialization-v1";
const LEAF_RECORDS: usize = 8;
const FANOUT: usize = 32;
const VECTOR_MAP_READ: u64 = 1024 * 1024;
const MAX_VECTOR_DOCUMENTS: usize = 128;
const MAX_VECTOR_PAGES: usize = 256;
const MAX_VECTOR_READ: u64 = 64 * 1024 * 1024;
const MAX_VECTOR_WRITE: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VectorRequest {
    pub schema_version: u32,
    pub projection: ProjectionRequest,
    pub selected_projection: ProjectionProgress,
}
impl VectorRequest {
    pub fn validate(&self) -> Result<()> {
        self.selected_projection.canonical_bytes(&self.projection)?;
        if self.schema_version != 1 || !self.selected_projection.cursor.complete {
            return Err("vectors require actual complete selected projection".into());
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
    fn corpus(&self) -> &MapRoot {
        self.projection.corpus()
    }
    fn limits(&self) -> CorpusIndexLimits {
        self.projection.covariance.statistics.ingestion.limits
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VectorNode {
    pub sha256: String,
    pub first: u32,
    pub count: u32,
    pub height: u8,
}
impl VectorNode {
    fn validate(&self, request: &VectorRequest) -> Result<()> {
        hash(&self.sha256)?;
        if self.count == 0
            || self.height > 8
            || self
                .first
                .checked_add(self.count)
                .map_or(true, |n| u64::from(n) > request.corpus().entry_count)
        {
            return Err("vector node has invalid finite ordinal coverage".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VectorProgress {
    pub schema_version: u32,
    pub request_sha256: String,
    pub cursor: MapCursor,
    pub dimensions: Option<u8>,
    pub frontier: Vec<Vec<VectorNode>>,
    pub root: Option<VectorNode>,
    pub complete: bool,
    pub coordinates: coordinates::CoordinateState,
    pub totals: IngestTotals,
}
impl VectorProgress {
    pub fn beginning(request: &VectorRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            schema_version: 1,
            request_sha256: request.sha256()?,
            cursor: MapCursor::beginning(request.corpus())?,
            dimensions: None,
            frontier: Vec::new(),
            root: None,
            complete: false,
            coordinates: coordinates::CoordinateState::default(),
            totals: request.selected_projection.totals,
        })
    }
    pub fn canonical_bytes(&self, request: &VectorRequest) -> Result<Vec<u8>> {
        request.validate()?;
        self.cursor.canonical_bytes(request.corpus())?;
        self.totals.validate(&request.limits())?;
        let prior = request.selected_projection.totals;
        self.coordinates.validate(
            request,
            self.cursor.after_count(),
            self.dimensions,
            self.complete,
        )?;
        let features = request.projection.n()?;
        if self.schema_version != 1
            || self.request_sha256 != request.sha256()?
            || self.dimensions.is_some_and(|n| {
                usize::from(n) > MAX_DIMENSIONS
                    || usize::from(n) > features
                    || u16::from(n) > request.projection.requested_dimensions
            })
            || self.totals.read_bytes < prior.read_bytes
            || self.totals.write_bytes < prior.write_bytes
            || self.totals.work < prior.work
            || self.totals.source_bytes != prior.source_bytes
            || self.totals.postings != prior.postings
            || self.frontier.len() > 9
            || (self.dimensions.is_some()
                && self.cursor.after_count() == request.corpus().entry_count
                && !self.complete)
        {
            return Err(
                "vector progress substitutes source, dimensions or cumulative counters".into(),
            );
        }
        if self.dimensions.is_none()
            && (self.cursor.after_count() != 0
                || !self.frontier.is_empty()
                || self.root.is_some()
                || self.complete
                || self.totals != prior)
        {
            return Err(
                "uninitialized vector progress carries effects or fabricated coverage".into(),
            );
        }
        if self.complete {
            if self.dimensions.is_none()
                || !self.frontier.is_empty()
                || self.cursor.after_count() != request.corpus().entry_count
            {
                return Err("completed vectors lack actual complete source coverage".into());
            }
            match &self.root {
                None if request.corpus().entry_count == 0 => (),
                Some(root)
                    if root.first == 0 && u64::from(root.count) == request.corpus().entry_count =>
                {
                    root.validate(request)?
                }
                _ => return Err("completed vector tree coverage differs from corpus".into()),
            }
        } else {
            if self.root.is_some() {
                return Err("partial vector frontier must not expose a final tree".into());
            }
            let mut spans = Vec::new();
            for (level, nodes) in self.frontier.iter().enumerate() {
                if nodes.len() >= FANOUT {
                    return Err("vector frontier exceeds bounded fanout".into());
                }
                for node in nodes {
                    node.validate(request)?;
                    if usize::from(node.height) != level {
                        return Err("vector frontier aliases its height".into());
                    }
                    spans.push(node);
                }
            }
            spans.sort_by_key(|node| node.first);
            let mut count = 0_u64;
            for node in spans {
                if u64::from(node.first) != count {
                    return Err("vector frontier has duplicate or missing ordinals".into());
                }
                count += u64::from(node.count);
            }
            if count != self.cursor.after_count() {
                return Err("vector frontier differs from authenticated source cursor".into());
            }
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 64 * 1024 {
            return Err("vector progress exceeds bounded frontier envelope".into());
        }
        Ok(bytes)
    }
}
pub trait VectorBoundary: ProjectionBoundary {
    fn current_vectors(&mut self, request: &VectorRequest, progress: &VectorProgress)
        -> Result<()>;
    fn verify_vector_allocations(&mut self, value: &VectorCommitment) -> Result<()>;
}
struct Current<'a, B: VectorBoundary> {
    request: &'a VectorRequest,
    base: &'a VectorProgress,
    b: &'a mut B,
}
impl<B: VectorBoundary> Current<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.b.current_vectors(self.request, self.base)?;
        super::Live {
            request: &self.request.projection,
            progress: &self.request.selected_projection,
            b: self.b,
        }
        .current()
    }
}
impl<B: VectorBoundary> Boundary for Current<'_, B> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        if binding != &self.request.corpus().binding {
            return Err("vector storage owner differs".into());
        }
        self.current()?;
        self.b.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.b.check(access)?;
        self.current()
    }
}
impl<B: VectorBoundary> CorpusIndexBoundary for Current<'_, B> {
    fn current_corpus(&mut self, root: &MapRoot) -> Result<()> {
        if root != self.request.corpus() {
            return Err("vector corpus substitution".into());
        }
        self.current()
    }
    fn current_builder(&mut self, root: &MapRoot, builder: &BuilderIdentity) -> Result<()> {
        if root != self.request.corpus()
            || builder
                != &self
                    .request
                    .projection
                    .covariance
                    .statistics
                    .ingestion
                    .builder
        {
            return Err("vector builder substitution".into());
        }
        self.current()
    }
    fn current_index_generation(&mut self, root: &MapRoot, digest: &str) -> Result<()> {
        self.current()?;
        self.b.current_index_generation(root, digest)
    }
    fn current_candidate(&mut self, root: &MapRoot, record: &CorpusRecord) -> Result<()> {
        self.current_corpus(root)?;
        self.b.current_candidate(root, record)?;
        self.current()
    }
}
impl<B: VectorBoundary> MapCursorBoundary for Current<'_, B> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.current_corpus(root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VectorRecord {
    pub ordinal: u32,
    pub record: CorpusRecord,
    pub components: Vec<u32>,
}
impl VectorRecord {
    fn validate(&self, dimensions: u8) -> Result<()> {
        self.record.validate()?;
        let mut norm = 0.0_f64;
        if self.components.len() != usize::from(dimensions) {
            return Err("vector row dimensions differ from selected basis".into());
        }
        for bits in &self.components {
            let value = f32::from_bits(*bits);
            if !value.is_finite() || value.abs() > 1.000001 {
                return Err("nonfinite vector component".into());
            }
            norm += f64::from(value) * f64::from(value);
        }
        if norm != 0.0 && (norm - 1.0).abs() > 0.00001 {
            return Err("vector is neither normalized nor zero".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Leaf { first: u32, rows: Vec<VectorRecord> },
    Branch { children: Vec<VectorNode> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    domain: String,
    request_sha256: String,
    dimensions: u8,
    body: Body,
}
impl Page {
    fn node(&self, request: &VectorRequest, dimensions: u8, sha256: String) -> Result<VectorNode> {
        if self.schema_version != 1
            || self.domain != VECTOR_DOMAIN
            || self.request_sha256 != request.sha256()?
            || self.dimensions != dimensions
        {
            return Err("vector page context differs".into());
        }
        let node = match &self.body {
            Body::Leaf { first, rows } => {
                if rows.is_empty() || rows.len() > LEAF_RECORDS {
                    return Err("vector leaf row bound exceeded".into());
                }
                for (i, row) in rows.iter().enumerate() {
                    row.validate(dimensions)?;
                    if row.ordinal
                        != first
                            .checked_add(i as u32)
                            .ok_or("vector ordinal overflow")?
                    {
                        return Err("vector leaf aliases ordinal order".into());
                    }
                }
                VectorNode {
                    sha256,
                    first: *first,
                    count: rows.len() as u32,
                    height: 0,
                }
            }
            Body::Branch { children } => {
                if children.len() < 2 || children.len() > FANOUT {
                    return Err("vector branch fanout invalid".into());
                }
                let first = children[0].first;
                let mut end = first;
                let mut height = 0;
                for child in children {
                    child.validate(request)?;
                    if child.first != end {
                        return Err("vector branch has duplicate or missing source range".into());
                    }
                    end = end
                        .checked_add(child.count)
                        .ok_or("vector branch ordinal overflow")?;
                    height = height.max(child.height);
                }
                VectorNode {
                    sha256,
                    first,
                    count: end - first,
                    height: height + 1,
                }
            }
        };
        node.validate(request)?;
        Ok(node)
    }
}
struct Pending {
    request: String,
    dimensions: u8,
    pages: Vec<(String, Vec<u8>)>,
}
impl Pending {
    fn put(&mut self, request: &VectorRequest, body: Body) -> Result<VectorNode> {
        let page = Page {
            schema_version: 1,
            domain: VECTOR_DOMAIN.into(),
            request_sha256: self.request.clone(),
            dimensions: self.dimensions,
            body,
        };
        let bytes = serde_json::to_vec(&page)?;
        if bytes.len() > MAX_INDEX_PAGE_BYTES || self.pages.len() >= MAX_VECTOR_PAGES {
            return Err("vector immutable-page profile exhausted".into());
        }
        let sha256 = luma_content::sha256(&bytes);
        let node = page.node(request, self.dimensions, sha256.clone())?;
        self.pages.push((sha256, bytes));
        Ok(node)
    }
    fn append(
        &mut self,
        request: &VectorRequest,
        frontier: &mut Vec<Vec<VectorNode>>,
        mut node: VectorNode,
    ) -> Result<()> {
        loop {
            let level = usize::from(node.height);
            if level >= 9 {
                return Err("vector frontier height exceeds fixed profile".into());
            }
            while frontier.len() <= level {
                frontier.push(Vec::new());
            }
            frontier[level].push(node);
            if frontier[level].len() < FANOUT {
                return Ok(());
            }
            node = self.put(
                request,
                Body::Branch {
                    children: std::mem::take(&mut frontier[level]),
                },
            )?;
        }
    }
    fn finish(
        &mut self,
        request: &VectorRequest,
        frontier: &mut Vec<Vec<VectorNode>>,
    ) -> Result<Option<VectorNode>> {
        let mut nodes: Vec<_> = std::mem::take(frontier).into_iter().flatten().collect();
        nodes.sort_by_key(|node| node.first);
        while nodes.len() > 1 {
            let mut next = Vec::new();
            for children in nodes.chunks(FANOUT) {
                next.push(if children.len() == 1 {
                    children[0].clone()
                } else {
                    self.put(
                        request,
                        Body::Branch {
                            children: children.to_vec(),
                        },
                    )?
                });
            }
            nodes = next;
        }
        Ok(nodes.pop())
    }
}
fn read_node<B: VectorBoundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    dimensions: u8,
    node: &VectorNode,
    live: &mut Current<'_, B>,
) -> Result<Page> {
    let bytes = store.read_page(
        &node.sha256,
        IoBudget {
            read_bytes: RUN_PAGE_READ,
            write_bytes: 0,
            new_files: 0,
        },
        live,
    )?;
    let page: Page = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
    if page.node(request, dimensions, node.sha256.clone())? != *node {
        return Err("actual vector page differs from authenticated node".into());
    }
    Ok(page)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VectorCommitment {
    pub request: VectorRequest,
    pub base: VectorProgress,
    pub next: VectorProgress,
    pub maximum_documents: u8,
    pub window_read_bytes: u64,
    pub window_write_bytes: u64,
    pub source_bytes: u64,
    pub review_sha256: String,
}
impl VectorCommitment {
    fn review(&self) -> Result<String> {
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            VECTOR_DOMAIN,
            &self.request,
            &self.base,
            &self.next,
            self.maximum_documents,
            self.window_read_bytes,
            self.window_write_bytes,
            self.source_bytes,
        ))?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.base.canonical_bytes(&self.request)?;
        self.next.canonical_bytes(&self.request)?;
        if self.base.complete
            || self.maximum_documents == 0
            || usize::from(self.maximum_documents) > MAX_VECTOR_DOCUMENTS
            || self.window_read_bytes == 0
            || self.window_read_bytes > MAX_VECTOR_READ
            || self.window_write_bytes == 0
            || self.window_write_bytes > MAX_VECTOR_WRITE
            || self.source_bytes > crate::v2::MAX_SEGMENT_BYTES
            || self.review_sha256 != self.review()?
            || self.next.cursor.after_count() < self.base.cursor.after_count()
            || (self.next.cursor.after_count() == self.base.cursor.after_count()
                && !self.next.complete)
            || self.next.cursor.after_count() - self.base.cursor.after_count()
                > u64::from(self.maximum_documents)
            || self
                .next
                .totals
                .read_bytes
                .checked_sub(self.base.totals.read_bytes)
                .map_or(true, |v| v > self.window_read_bytes)
            || self
                .next
                .totals
                .write_bytes
                .checked_sub(self.base.totals.write_bytes)
                .map_or(true, |v| v > self.window_write_bytes)
            || self.next.totals.work < self.base.totals.work
        {
            return Err("vector commitment differs from exact reviewed finite transition".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 512 * 1024 {
            return Err("vector commitment exceeds finite envelope".into());
        }
        Ok(bytes)
    }
}
pub struct VectorPlan {
    value: VectorCommitment,
    records: Vec<CorpusRecord>,
    pages: Vec<(String, Vec<u8>)>,
}
impl VectorPlan {
    pub fn commitment(&self) -> &VectorCommitment {
        &self.value
    }
    pub fn planned_objects(
        &self,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<crate::v2::ObjectWriteSpec>> {
        self.value.canonical_bytes()?;
        let mut result = Vec::new();
        let mut seen = std::collections::BTreeMap::<&str, &[u8]>::new();
        for (sha, bytes) in &self.pages {
            check()?;
            if luma_content::sha256(bytes) != *sha {
                return Err("vector write-set differs from its actual planned page".into());
            }
            if let Some(prior) = seen.get(sha.as_str()) {
                if *prior != bytes.as_slice() {
                    return Err("vector write-set hash collision".into());
                }
            } else {
                seen.insert(sha, bytes);
                let spec = crate::v2::ObjectWriteSpec {
                    sha256: sha.clone(),
                    bytes: u32::try_from(bytes.len())?,
                };
                spec.validate()?;
                result.push(spec);
            }
        }
        check()?;
        Ok(result)
    }
}
pub fn plan_vector_window<B: VectorBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    base: &VectorProgress,
    maximum_documents: usize,
    window_read_bytes: u64,
    window_write_bytes: u64,
    content: &mut C,
    b: &mut B,
) -> Result<VectorPlan> {
    base.canonical_bytes(request)?;
    if base.complete
        || maximum_documents == 0
        || maximum_documents > MAX_VECTOR_DOCUMENTS
        || window_read_bytes == 0
        || window_read_bytes > MAX_VECTOR_READ
        || window_write_bytes == 0
        || window_write_bytes > MAX_VECTOR_WRITE
        || window_read_bytes > request.limits().read_bytes - base.totals.read_bytes
        || window_write_bytes > request.limits().write_bytes - base.totals.write_bytes
    {
        return Err("vectors require an unfinished finite cumulative window".into());
    }
    let mut live = Current { request, base, b };
    let mut meter = Meter::new(
        request.corpus(),
        &request.projection.covariance.statistics.ingestion.builder,
        CorpusIndexLimits {
            read_bytes: window_read_bytes,
            write_bytes: 0,
            source_bytes: MAX_INDEX_SOURCE_BYTES,
            postings: 0,
            floating_operations: request.limits().floating_operations - base.totals.work,
        },
        None,
        &mut live,
    )?;
    let reference = request
        .selected_projection
        .state
        .as_ref()
        .ok_or("selected projection lacks physical basis state")?;
    let basis_credit = blob_read_credit(reference.bytes)?;
    meter.read(basis_credit)?;
    let bytes = store.read_blob(
        reference,
        IoBudget {
            read_bytes: basis_credit,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let state = super::decode(
        &request.projection,
        &request.selected_projection.cursor,
        &bytes,
    )?;
    let basis = state.basis;
    let dimensions = u8::try_from(basis.first().map_or(0, Vec::len))?;
    if base.dimensions.is_some_and(|n| n != dimensions) {
        return Err("vector window changed selected actual basis dimensions".into());
    }
    for node in base.frontier.iter().flatten() {
        meter.read(RUN_PAGE_READ)?;
        read_node(store, request, dimensions, node, &mut live)?;
    }
    for node in base.coordinates.frontier.iter().flatten() {
        meter.read(RUN_PAGE_READ)?;
        coordinates::read_node(store, request, dimensions, node, &mut live)?;
    }
    meter.read(VECTOR_MAP_READ)?;
    let scan = store.scan_map_window(
        request.corpus(),
        &base.cursor,
        maximum_documents,
        IoBudget {
            read_bytes: VECTOR_MAP_READ,
            write_bytes: 0,
            new_files: 0,
        },
        &mut live,
    )?;
    let features = request.projection.covariance.features()?;
    let idfs: Vec<_> = features
        .iter()
        .map(|(_, df)| crate::corpus_index::build::idf(request.corpus().entry_count, *df))
        .collect();
    let mut records = Vec::new();
    let mut rows = Vec::new();
    for (key, value) in &scan.entries {
        let record = CorpusRecord::parse(value, request.corpus(), key)?;
        let page_ceiling = ((records.len() + 1 + LEAF_RECORDS - 1) / LEAF_RECORDS + 32) as u64;
        let read_after = meter
            .read
            .checked_add(record.content_bytes)
            .and_then(|v| v.checked_add(VECTOR_MAP_READ))
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(page_ceiling * RUN_PAGE_READ * 2));
        if read_after.map_or(true, |v| v > window_read_bytes) {
            break;
        }
        meter.source = meter
            .source
            .checked_add(record.content_bytes)
            .ok_or("vector source overflow")?;
        let bytes = read_content(request.corpus(), &record, content, &mut meter, &mut live)?;
        let tf = words(&bytes, request.corpus(), &mut meter, &mut live)?;
        let weights = crate::corpus_index::build::weights(&tf, &features, &idfs)?;
        meter.work(
            weights.len() as u64 * u64::from(dimensions),
            request.corpus(),
            &mut live,
        )?;
        let latent =
            crate::corpus_index::build::project(&weights, &basis, usize::from(dimensions))?;
        let row = VectorRecord {
            ordinal: u32::try_from(base.cursor.after_count() + records.len() as u64)?,
            record: record.clone(),
            components: latent.iter().map(|x| (*x as f32).to_bits()).collect(),
        };
        row.validate(dimensions)?;
        rows.push(row);
        records.push(record);
    }
    if records.is_empty() && base.cursor.after_count() != request.corpus().entry_count {
        return Err("vector window cannot reserve one actual complete source".into());
    }
    let cursor = if records.len() == scan.entries.len() {
        scan.next
    } else {
        meter.read(VECTOR_MAP_READ)?;
        let prefix = store.scan_map_window(
            request.corpus(),
            &base.cursor,
            records.len(),
            IoBudget {
                read_bytes: VECTOR_MAP_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        if prefix.entries != scan.entries[..records.len()] {
            return Err("actual vector source prefix changed".into());
        }
        prefix.next
    };
    let mut pending = Pending {
        request: request.sha256()?,
        dimensions,
        pages: Vec::new(),
    };
    let mut frontier = base.frontier.clone();
    for chunk in rows.chunks(LEAF_RECORDS) {
        let leaf = pending.put(
            request,
            Body::Leaf {
                first: chunk[0].ordinal,
                rows: chunk.to_vec(),
            },
        )?;
        pending.append(request, &mut frontier, leaf)?;
    }
    let complete = cursor.after_count() == request.corpus().entry_count;
    let root = if complete {
        pending.finish(request, &mut frontier)?
    } else {
        None
    };
    let coordinates = coordinates::extend(
        request,
        base,
        &rows,
        dimensions,
        complete,
        &mut pending.pages,
    )?;
    let write = pending.pages.len() as u64 * PAGE_WRITE;
    let read = meter
        .read
        .checked_mul(2)
        .and_then(|n| n.checked_add(pending.pages.len() as u64 * RUN_PAGE_READ * 2))
        .ok_or("vector replay read overflow")?;
    let work = meter
        .work
        .checked_mul(2)
        .ok_or("vector replay work overflow")?;
    if read > window_read_bytes || write > window_write_bytes {
        return Err("vector window cannot reserve independent exact replay/readback".into());
    }
    let next = VectorProgress {
        schema_version: 1,
        request_sha256: request.sha256()?,
        cursor,
        dimensions: Some(dimensions),
        frontier,
        root,
        complete,
        coordinates,
        totals: base.totals.plus(&IngestTotals {
            read_bytes: read,
            write_bytes: write,
            source_bytes: 0,
            postings: 0,
            work,
        })?,
    };
    let mut value = VectorCommitment {
        request: request.clone(),
        base: base.clone(),
        next,
        maximum_documents: maximum_documents as u8,
        window_read_bytes,
        window_write_bytes,
        source_bytes: meter.source,
        review_sha256: String::new(),
    };
    value.review_sha256 = value.review()?;
    value.canonical_bytes()?;
    meter.check(request.corpus(), &mut live)?;
    Ok(VectorPlan {
        value,
        records,
        pages: pending.pages,
    })
}
pub struct PreparedVectors {
    value: VectorCommitment,
}
impl PreparedVectors {
    pub fn commitment(&self) -> &VectorCommitment {
        &self.value
    }
    pub fn acknowledge_selected<B: VectorBoundary>(&self, b: &mut B) -> Result<()> {
        Current {
            request: &self.value.request,
            base: &self.value.next,
            b,
        }
        .current()
    }
}
pub fn prepare_vectors<B: VectorBoundary>(
    store: &ObjectStore,
    plan: &VectorPlan,
    mutation: &Mutation,
    b: &mut B,
) -> Result<PreparedVectors> {
    let value = &plan.value;
    value.canonical_bytes()?;
    if mutation.review_sha256 != value.review_sha256
        || mutation.source_bytes != value.source_bytes
        || mutation.decision != crate::DecisionKind::Published
    {
        return Err("vector mutation differs from exact reviewed source/window".into());
    }
    let mut live = Current {
        request: &value.request,
        base: &value.base,
        b,
    };
    for record in &plan.records {
        live.current_candidate(value.request.corpus(), record)?;
    }
    for (hash, bytes) in &plan.pages {
        if store.prepare_page(
            bytes,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: MAX_INDEX_PAGE_BYTES as u64,
                new_files: 3,
            },
            mutation,
            &mut live,
        )? != *hash
        {
            return Err("vector writer substituted actual deterministic page".into());
        }
    }
    for record in &plan.records {
        live.current_candidate(value.request.corpus(), record)?;
    }
    live.current()?;
    b.verify_vector_allocations(value)?;
    b.check(Access::Mutate {
        binding: &value.request.corpus().binding,
        review_sha256: &mutation.review_sha256,
        decision: mutation.decision,
        source_bytes: mutation.source_bytes,
        storage_bytes: value.next.totals.write_bytes - value.base.totals.write_bytes,
    })?;
    Current {
        request: &value.request,
        base: &value.base,
        b,
    }
    .current()?;
    Ok(PreparedVectors {
        value: value.clone(),
    })
}
pub fn verify_vectors_data<B: VectorBoundary, C: CorpusContent>(
    store: &dyn IndexReadStore,
    value: &VectorCommitment,
    content: &mut C,
    b: &mut B,
) -> Result<()> {
    value.canonical_bytes()?;
    let plan = plan_vector_window(
        store,
        &value.request,
        &value.base,
        usize::from(value.maximum_documents),
        value.window_read_bytes,
        value.window_write_bytes,
        content,
        b,
    )?;
    if plan.value != *value {
        return Err("vector candidate differs from independent exact source/basis replay".into());
    }
    let mut live = Current {
        request: &value.request,
        base: &value.base,
        b,
    };
    for (hash, expected) in &plan.pages {
        let bytes = store.read_page(
            hash,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            &mut live,
        )?;
        if bytes != *expected {
            return Err("prepared vector page differs from exact source reconstruction".into());
        }
    }
    live.current()?;
    b.verify_vector_allocations(value)?;
    Current {
        request: &value.request,
        base: &value.base,
        b,
    }
    .current()
}
/// Bounded authenticated ordinal read with fresh source/current-candidate checks.
/// The returned components remain derivative DATA, never citation/effect authority.
pub fn read_vector<B: VectorBoundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    selected: &VectorProgress,
    ordinal: u32,
    budget: IoBudget,
    b: &mut B,
) -> Result<VectorRecord> {
    selected.canonical_bytes(request)?;
    budget.validate()?;
    if !selected.complete
        || u64::from(ordinal) >= request.corpus().entry_count
        || budget.write_bytes != 0
        || budget.new_files != 0
    {
        return Err(
            "vector read requires complete selected coverage and exact in-range ordinal".into(),
        );
    }
    let mut live = Current {
        request,
        base: selected,
        b,
    };
    live.current()?;
    let dimensions = selected
        .dimensions
        .ok_or("selected vector tree has no actual dimensions")?;
    let mut node = selected
        .root
        .clone()
        .ok_or("selected vector tree has no physical root")?;
    let mut charged = 0_u64;
    for _ in 0..9 {
        charged = charged
            .checked_add(RUN_PAGE_READ)
            .ok_or("vector lookup read overflow")?;
        if charged > budget.read_bytes {
            return Err("vector lookup exhausts finite read budget before I/O".into());
        }
        match read_node(store, request, dimensions, &node, &mut live)?.body {
            Body::Leaf { first, rows } => {
                let row = rows
                    .get(usize::try_from(
                        ordinal
                            .checked_sub(first)
                            .ok_or("vector ordinal underflow")?,
                    )?)
                    .ok_or("vector leaf omits requested ordinal")?
                    .clone();
                live.current_candidate(request.corpus(), &row.record)?;
                live.current()?;
                return Ok(row);
            }
            Body::Branch { children } => {
                node = children
                    .into_iter()
                    .find(|child| ordinal >= child.first && ordinal < child.first + child.count)
                    .ok_or("vector branch omits requested ordinal")?;
            }
        }
    }
    Err("vector lookup exceeds fixed authenticated tree depth".into())
}

#[cfg(test)]
mod tests;
