use super::*;

pub(super) const DOCUMENT_ROWS: usize = 16;
pub(super) const VECTOR_ROWS: usize = 128;
pub(super) const MODEL_ROWS: usize = 32;
pub(super) const BUCKET_ROWS: usize = 64;
pub(super) const POSTING_ROWS: usize = 96;
const FANOUT: usize = 32;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Tree {
    Documents,
    Buckets,
    Model,
    Vectors,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub tree: Tree,
    pub first: u32,
    pub count: u32,
    pub height: u8,
    pub sha256: String,
}
impl Span {
    pub(super) fn validate(&self, _root: &MapRoot) -> Result<()> {
        hash(&self.sha256)?;
        if self.count == 0
            || self.height > 8
            || self.first.checked_add(self.count).is_none()
            || self.first + self.count
                > match self.tree {
                    Tree::Documents | Tree::Vectors => MAX_CORPUS_OBJECTS as u32,
                    Tree::Buckets => BUCKETS as u32,
                    Tree::Model => MAX_FEATURES as u32,
                }
        {
            return Err("index page span/height/count exceeds profile".into());
        }
        Ok(())
    }
}
pub(super) fn validate_root(
    value: &Option<Span>,
    tree: Tree,
    count: u32,
    root: &MapRoot,
) -> Result<()> {
    match value {
        None if count == 0 => Ok(()),
        Some(span) if span.tree == tree && span.first == 0 && span.count == count => {
            span.validate(root)
        }
        _ => Err("complete index tree coverage differs from manifest".into()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct BucketHead {
    pub head: Option<String>,
    pub records: u64,
    pub pages: u32,
}
impl BucketHead {
    pub fn empty() -> Self {
        Self {
            head: None,
            records: 0,
            pages: 0,
        }
    }
    fn validate(&self) -> Result<()> {
        if self.records > MAX_INDEX_POSTINGS
            || (self.head.is_none()) != (self.records == 0)
            || (self.pages == 0) != (self.records == 0)
            || (self.pages > 0
                && (self.records <= u64::from(self.pages - 1) * POSTING_ROWS as u64
                    || self.records > u64::from(self.pages) * POSTING_ROWS as u64))
        {
            return Err("index posting bucket coverage invalid".into());
        }
        if let Some(value) = &self.head {
            hash(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Feature {
    pub term: String,
    pub documents: u32,
    pub idf_bits: u64,
    pub projection_bits: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Body {
    Documents {
        first: u32,
        records: Vec<CorpusRecord>,
    },
    Buckets {
        first: u32,
        rows: Vec<BucketHead>,
    },
    Model {
        first: u32,
        features: Vec<Feature>,
    },
    Vectors {
        first: u32,
        rows: Vec<Vec<u32>>,
    },
    Branch {
        tree: Tree,
        first: u32,
        count: u32,
        height: u8,
        children: Vec<Span>,
    },
    Postings {
        bucket: u16,
        sequence: u32,
        previous: Option<String>,
        entries: Vec<Posting>,
    },
}
impl Body {
    fn span(&self, sha256: String) -> Result<Span> {
        let (tree, first, count, height) = match self {
            Self::Documents { first, records } => {
                (Tree::Documents, *first, records.len() as u32, 0)
            }
            Self::Buckets { first, rows } => (Tree::Buckets, *first, rows.len() as u32, 0),
            Self::Model { first, features } => (Tree::Model, *first, features.len() as u32, 0),
            Self::Vectors { first, rows } => (Tree::Vectors, *first, rows.len() as u32, 0),
            Self::Branch {
                tree,
                first,
                count,
                height,
                ..
            } => (*tree, *first, *count, *height),
            Self::Postings { .. } => {
                return Err("posting chain is not an ordinal index tree".into())
            }
        };
        Ok(Span {
            tree,
            first,
            count,
            height,
            sha256,
        })
    }
    fn validate(&self, root: &MapRoot) -> Result<()> {
        match self {
            Self::Documents { records, .. } => {
                if records.is_empty() || records.len() > DOCUMENT_ROWS {
                    return Err("index document leaf bound exceeded".into());
                }
                for record in records {
                    record.validate()?;
                }
            }
            Self::Buckets { rows, .. } => {
                if rows.is_empty() || rows.len() > BUCKET_ROWS {
                    return Err("index directory leaf bound exceeded".into());
                }
                for row in rows {
                    row.validate()?;
                }
            }
            Self::Model { features, .. } => {
                if features.is_empty() || features.len() > MODEL_ROWS {
                    return Err("index model leaf bound exceeded".into());
                }
                for feature in features {
                    term(&feature.term)?;
                    let idf = f64::from_bits(feature.idf_bits);
                    if feature.documents == 0
                        || u64::from(feature.documents) > root.entry_count
                        || !idf.is_finite()
                        || idf < 1.0
                        || feature.projection_bits.len() > MAX_DIMENSIONS
                        || feature.projection_bits.iter().any(|bits| {
                            let x = f64::from_bits(*bits);
                            !x.is_finite() || x.abs() > 1.000001
                        })
                    {
                        return Err("index feature row is not finite/bounded".into());
                    }
                }
            }
            Self::Vectors { rows, .. } => {
                if rows.is_empty() || rows.len() > VECTOR_ROWS {
                    return Err("index vector leaf bound exceeded".into());
                }
                for row in rows {
                    if row.len() > MAX_DIMENSIONS {
                        return Err("index latent dimensions exceeded".into());
                    }
                    let mut norm = 0.0_f64;
                    for bits in row {
                        let value = f32::from_bits(*bits);
                        if !value.is_finite() || value.abs() > 1.000001 {
                            return Err("nonfinite index latent coordinate".into());
                        }
                        norm += f64::from(value) * f64::from(value);
                    }
                    if norm != 0.0 && (norm - 1.0).abs() > 0.00001 {
                        return Err("index latent row is neither normalized nor zero".into());
                    }
                }
            }
            Self::Branch {
                tree,
                first,
                count,
                height,
                children,
            } => {
                if children.is_empty() || children.len() > FANOUT || *height == 0 || *height > 8 {
                    return Err("index branch fanout/depth invalid".into());
                }
                let mut next = *first;
                for child in children {
                    child.validate(root)?;
                    if child.tree != *tree || child.height + 1 != *height || child.first != next {
                        return Err("index child order/height/coverage mismatch".into());
                    }
                    next = next
                        .checked_add(child.count)
                        .ok_or("index ordinal overflow")?;
                }
                if next.checked_sub(*first) != Some(*count) {
                    return Err("index branch total differs".into());
                }
            }
            Self::Postings {
                bucket: bucket_id,
                sequence,
                previous,
                entries,
            } => {
                if usize::from(*bucket_id) >= BUCKETS
                    || *sequence > MAX_INDEX_POSTINGS as u32 / POSTING_ROWS as u32
                    || (*sequence == 0) != (previous.is_none())
                    || entries.is_empty()
                    || entries.len() > POSTING_ROWS
                {
                    return Err("index posting page chain/bounds invalid".into());
                }
                if let Some(value) = previous {
                    hash(value)?;
                }
                for entry in entries {
                    term(&entry.term)?;
                    if super::bucket(&entry.term) != usize::from(*bucket_id)
                        || u64::from(entry.document) >= root.entry_count
                        || entry.frequency == 0
                        || entry.frequency > MAX_DOCUMENT_BYTES as u32
                        || entry.offset >= MAX_DOCUMENT_BYTES as u32
                    {
                        return Err("posting term/document/bucket does not match profile".into());
                    }
                }
                return Ok(());
            }
        }
        self.span("1".repeat(64))?.validate(root)
    }
}
fn term(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > crate::MAX_SEARCH_TERM_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err("index term must be a complete canonical ASCII alphanumeric word".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    profile: String,
    corpus_sha256: String,
    body: Body,
}

pub(super) fn put<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    body: Body,
    mutation: &Mutation,
    meter: &mut Meter,
    b: &mut B,
) -> Result<String> {
    body.validate(root)?;
    meter.check(root, b)?;
    let bytes = serde_json::to_vec(&Page {
        schema_version: 1,
        profile: CORPUS_INDEX_PROFILE.into(),
        corpus_sha256: root.sha256()?,
        body,
    })?;
    if bytes.len() > MAX_INDEX_PAGE_BYTES {
        return Err("canonical index page exceeds16KiB; generation not ready".into());
    }
    meter.write(PAGE_WRITE)?;
    meter.read(PAGE_READ)?;
    let expected = luma_content::sha256(&bytes);
    let actual = store.prepare_page(
        &bytes,
        IoBudget {
            read_bytes: PAGE_READ,
            write_bytes: MAX_INDEX_PAGE_BYTES as u64,
            new_files: 3,
        },
        mutation,
        b,
    )?;
    if actual != expected {
        return Err("private object writer substituted index page".into());
    }
    meter.check(root, b)?;
    Ok(actual)
}
pub(super) fn put_leaf<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    body: Body,
    mutation: &Mutation,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Span> {
    let template = body.clone();
    let hash = put(store, root, body, mutation, meter, b)?;
    template.span(hash)
}
pub(super) fn get<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    sha: &str,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Body> {
    hash(sha)?;
    meter.check(root, b)?;
    meter.read(PAGE_READ)?;
    let bytes = store.read_page(
        sha,
        IoBudget {
            read_bytes: PAGE_READ,
            write_bytes: 0,
            new_files: 0,
        },
        b,
    )?;
    if luma_content::sha256(&bytes) != sha {
        return Err("index page hash changed".into());
    }
    let page: Page = decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
    if page.schema_version != 1
        || page.profile != CORPUS_INDEX_PROFILE
        || page.corpus_sha256 != root.sha256()?
    {
        return Err("index page owner/corpus/profile changed".into());
    }
    page.body.validate(root)?;
    meter.check(root, b)?;
    Ok(page.body)
}
pub(super) fn selected<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    span: &Span,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Body> {
    span.validate(root)?;
    let body = get(store, root, &span.sha256, meter, b)?;
    if body.span(span.sha256.clone())? != *span {
        return Err("index selected page span differs".into());
    }
    Ok(body)
}

pub(super) fn tree<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    mut leaves: Vec<Span>,
    mutation: &Mutation,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Option<Span>> {
    while leaves.len() > 1 {
        let mut next = Vec::new();
        for children in leaves.chunks(FANOUT) {
            let first = children.first().ok_or("index branch missing")?;
            let count = children.iter().try_fold(0_u32, |n, child| {
                n.checked_add(child.count)
                    .ok_or("index branch count overflow")
            })?;
            next.push(put_leaf(
                store,
                root,
                Body::Branch {
                    tree: first.tree,
                    first: first.first,
                    count,
                    height: first.height + 1,
                    children: children.to_vec(),
                },
                mutation,
                meter,
                b,
            )?);
        }
        leaves = next;
    }
    Ok(leaves.pop())
}

pub(super) fn walk<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    span: &Span,
    meter: &mut Meter,
    b: &mut B,
    visitor: &mut impl FnMut(&Body, &mut Meter, &mut B) -> Result<()>,
) -> Result<()> {
    match selected(store, root, span, meter, b)? {
        Body::Branch { children, .. } => {
            for child in children {
                walk(store, root, &child, meter, b, visitor)?;
            }
        }
        body => {
            meter.check(root, b)?;
            visitor(&body, meter, b)?;
            meter.check(root, b)?;
        }
    }
    Ok(())
}

pub(super) fn at<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    span: &Span,
    ordinal: u32,
    meter: &mut Meter,
    b: &mut B,
) -> Result<Body> {
    if ordinal < span.first || ordinal >= span.first + span.count {
        return Err("index lookup outside exact ordinal coverage".into());
    }
    match selected(store, root, span, meter, b)? {
        Body::Branch { children, .. } => {
            let child = children
                .into_iter()
                .find(|child| child.first <= ordinal && ordinal < child.first + child.count)
                .ok_or("index child missing selected ordinal")?;
            at(store, root, &child, ordinal, meter, b)
        }
        body => Ok(body),
    }
}
pub(super) fn record<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    span: &Span,
    ordinal: u32,
    meter: &mut Meter,
    b: &mut B,
) -> Result<CorpusRecord> {
    match at(store, root, span, ordinal, meter, b)? {
        Body::Documents { first, records } => records
            .get((ordinal - first) as usize)
            .cloned()
            .ok_or_else(|| "index document row absent".into()),
        _ => Err("index document selector reached another page kind".into()),
    }
}
pub(super) fn directory<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    span: &Span,
    id: usize,
    meter: &mut Meter,
    b: &mut B,
) -> Result<BucketHead> {
    match at(store, root, span, id as u32, meter, b)? {
        Body::Buckets { first, rows } => rows
            .get(id - first as usize)
            .cloned()
            .ok_or_else(|| "index bucket row absent".into()),
        _ => Err("index directory selector reached another page kind".into()),
    }
}

pub(super) fn postings<B: CorpusIndexBoundary>(
    store: &ObjectStore,
    root: &MapRoot,
    id: usize,
    head: &BucketHead,
    meter: &mut Meter,
    b: &mut B,
    mut visitor: impl FnMut(&Posting, &mut Meter, &mut B) -> Result<()>,
) -> Result<()> {
    head.validate()?;
    let mut next = head.head.clone();
    let mut expected = head.pages;
    let mut total = 0_u64;
    while let Some(hash) = next {
        expected = expected
            .checked_sub(1)
            .ok_or("index posting chain has extra page")?;
        match get(store, root, &hash, meter, b)? {
            Body::Postings {
                bucket,
                sequence,
                previous,
                entries,
            } if usize::from(bucket) == id && sequence == expected => {
                if expected + 1 < head.pages && entries.len() != POSTING_ROWS {
                    return Err("nonterminal posting page has incomplete count".into());
                }
                for entry in entries.iter().rev() {
                    meter.check(root, b)?;
                    visitor(entry, meter, b)?;
                    total = total.checked_add(1).ok_or("posting count overflow")?;
                }
                next = previous;
            }
            _ => return Err("index posting chain type/bucket/sequence mismatch".into()),
        }
    }
    if expected != 0 || total != head.records {
        return Err("index posting chain lost declared coverage".into());
    }
    meter.check(root, b)
}
