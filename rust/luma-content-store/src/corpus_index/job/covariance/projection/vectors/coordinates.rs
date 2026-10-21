//! Compact coordinates are independently reconstructed in the same vector
//! transition as exact record proofs. They do not authenticate those records.
use super::*;

const HEADER: &[u8] = b"LUMA-COORDINATES-V1\n";
const DOMAIN: &str = "luma-corpus-coordinate-branches-v1";
pub const BLOCK_ROWS: usize = 256;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinateState {
    pub frontier: Vec<Vec<VectorNode>>,
    pub tail: Vec<Vec<u32>>,
    pub root: Option<VectorNode>,
}
fn validate_row(row: &[u32], dimensions: u8) -> Result<()> {
    if row.len() != usize::from(dimensions) {
        return Err("compact coordinate dimensions differ".into());
    }
    let mut norm = 0.0;
    for bits in row {
        let value = f32::from_bits(*bits);
        if !value.is_finite() || value.abs() > 1.000001 {
            return Err("invalid compact coordinate".into());
        }
        norm += f64::from(value) * f64::from(value);
    }
    if norm != 0.0 && (norm - 1.0).abs() > 0.00001 {
        return Err("compact coordinate is neither normalized nor zero".into());
    }
    Ok(())
}
impl CoordinateState {
    pub(super) fn validate(
        &self,
        request: &VectorRequest,
        count: u64,
        dimensions: Option<u8>,
        complete: bool,
    ) -> Result<()> {
        if self.frontier.len() > 9
            || self.tail.len() >= BLOCK_ROWS
            || self.tail.len() as u64 > count
        {
            return Err("compact coordinate frontier/tail exceeds finite source coverage".into());
        }
        for row in &self.tail {
            validate_row(
                row,
                dimensions.ok_or("coordinate tail precedes actual basis dimensions")?,
            )?;
        }
        if complete {
            if !self.tail.is_empty() || !self.frontier.is_empty() {
                return Err("completed coordinates retain unfinished blocks".into());
            }
            match &self.root {
                None if count == 0 => (),
                Some(node) if node.first == 0 && u64::from(node.count) == count => {
                    node.validate(request)?
                }
                _ => return Err("compact coordinate root omits complete corpus coverage".into()),
            }
        } else {
            if self.root.is_some() {
                return Err("partial coordinate tree must not expose a root".into());
            }
            let mut nodes = Vec::new();
            for (height, level) in self.frontier.iter().enumerate() {
                if level.len() >= FANOUT {
                    return Err("compact coordinate frontier fanout exceeded".into());
                }
                for node in level {
                    node.validate(request)?;
                    if usize::from(node.height) != height {
                        return Err("compact coordinate frontier aliases height".into());
                    }
                    nodes.push(node);
                }
            }
            nodes.sort_by_key(|node| node.first);
            let mut end = 0_u64;
            for node in nodes {
                if u64::from(node.first) != end {
                    return Err(
                        "compact coordinates have duplicate or missing ordinal ranges".into(),
                    );
                }
                end += u64::from(node.count);
            }
            if end.checked_add(self.tail.len() as u64) != Some(count) {
                return Err(
                    "compact coordinate tail/frontier differs from actual source cursor".into(),
                );
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Branch {
    schema_version: u32,
    domain: String,
    request_sha256: String,
    dimensions: u8,
    children: Vec<VectorNode>,
}
pub(super) enum ReadBody {
    Leaf(Vec<Vec<u32>>),
    Branch(Vec<VectorNode>),
}
fn branch_node(
    request: &VectorRequest,
    children: &[VectorNode],
    sha256: String,
) -> Result<VectorNode> {
    if children.len() < 2 || children.len() > FANOUT {
        return Err("compact branch fanout invalid".into());
    }
    let first = children[0].first;
    let mut end = first;
    let mut height = 0;
    for child in children {
        child.validate(request)?;
        if child.first != end {
            return Err("compact branch loses exact ordinal coverage".into());
        }
        end = end
            .checked_add(child.count)
            .ok_or("coordinate ordinal overflow")?;
        height = height.max(child.height);
    }
    let node = VectorNode {
        sha256,
        first,
        count: end - first,
        height: height + 1,
    };
    node.validate(request)?;
    Ok(node)
}
fn push_page(pages: &mut Vec<(String, Vec<u8>)>, bytes: Vec<u8>) -> Result<String> {
    if bytes.len() > MAX_INDEX_PAGE_BYTES || pages.len() >= MAX_VECTOR_PAGES {
        return Err("compact page exhausts existing vector page profile".into());
    }
    let hash = luma_content::sha256(&bytes);
    pages.push((hash.clone(), bytes));
    Ok(hash)
}
fn branch(
    request: &VectorRequest,
    dimensions: u8,
    children: Vec<VectorNode>,
    pages: &mut Vec<(String, Vec<u8>)>,
) -> Result<VectorNode> {
    let bytes = serde_json::to_vec(&Branch {
        schema_version: 1,
        domain: DOMAIN.into(),
        request_sha256: request.sha256()?,
        dimensions,
        children: children.clone(),
    })?;
    branch_node(request, &children, push_page(pages, bytes)?)
}
fn leaf(
    request: &VectorRequest,
    dimensions: u8,
    first: u32,
    rows: &[Vec<u32>],
    pages: &mut Vec<(String, Vec<u8>)>,
) -> Result<VectorNode> {
    if rows.is_empty() || rows.len() > BLOCK_ROWS {
        return Err("compact block row bound exceeded".into());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HEADER);
    bytes.extend_from_slice(request.sha256()?.as_bytes());
    bytes.push(dimensions);
    bytes.extend_from_slice(&first.to_le_bytes());
    bytes.extend_from_slice(&(rows.len() as u16).to_le_bytes());
    for row in rows {
        validate_row(row, dimensions)?;
        for value in row {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    let node = VectorNode {
        sha256: push_page(pages, bytes)?,
        first,
        count: rows.len() as u32,
        height: 0,
    };
    node.validate(request)?;
    Ok(node)
}
fn append(
    request: &VectorRequest,
    dimensions: u8,
    frontier: &mut Vec<Vec<VectorNode>>,
    mut node: VectorNode,
    pages: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    loop {
        let level = usize::from(node.height);
        if level >= 9 {
            return Err("compact frontier height exceeded".into());
        }
        while frontier.len() <= level {
            frontier.push(Vec::new());
        }
        frontier[level].push(node);
        if frontier[level].len() < FANOUT {
            return Ok(());
        }
        node = branch(
            request,
            dimensions,
            std::mem::take(&mut frontier[level]),
            pages,
        )?;
    }
}
pub(super) fn extend(
    request: &VectorRequest,
    base: &VectorProgress,
    rows: &[VectorRecord],
    dimensions: u8,
    complete: bool,
    pages: &mut Vec<(String, Vec<u8>)>,
) -> Result<CoordinateState> {
    let mut result = base.coordinates.clone();
    let mut end = base.cursor.after_count();
    for row in rows {
        if u64::from(row.ordinal) != end {
            return Err("compact materialization substitutes actual row order".into());
        }
        result.tail.push(row.components.clone());
        end += 1;
        if result.tail.len() == BLOCK_ROWS {
            let node = leaf(
                request,
                dimensions,
                u32::try_from(end - BLOCK_ROWS as u64)?,
                &std::mem::take(&mut result.tail),
                pages,
            )?;
            append(request, dimensions, &mut result.frontier, node, pages)?;
        }
    }
    if complete {
        if !result.tail.is_empty() {
            let first = u32::try_from(end - result.tail.len() as u64)?;
            let node = leaf(
                request,
                dimensions,
                first,
                &std::mem::take(&mut result.tail),
                pages,
            )?;
            append(request, dimensions, &mut result.frontier, node, pages)?;
        }
        let mut nodes: Vec<_> = std::mem::take(&mut result.frontier)
            .into_iter()
            .flatten()
            .collect();
        nodes.sort_by_key(|node| node.first);
        while nodes.len() > 1 {
            let mut next = Vec::new();
            for children in nodes.chunks(FANOUT) {
                next.push(if children.len() == 1 {
                    children[0].clone()
                } else {
                    branch(request, dimensions, children.to_vec(), pages)?
                });
            }
            nodes = next;
        }
        result.root = nodes.pop();
    }
    result.validate(request, end, Some(dimensions), complete)?;
    Ok(result)
}
pub(super) fn read_node<B: Boundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    dimensions: u8,
    node: &VectorNode,
    boundary: &mut B,
) -> Result<ReadBody> {
    node.validate(request)?;
    let bytes = store.read_page(
        &node.sha256,
        IoBudget {
            read_bytes: RUN_PAGE_READ,
            write_bytes: 0,
            new_files: 0,
        },
        boundary,
    )?;
    if node.height == 0 {
        let prefix = HEADER.len() + 64 + 1 + 4 + 2;
        if bytes.len() < prefix
            || !bytes.starts_with(HEADER)
            || &bytes[HEADER.len()..HEADER.len() + 64] != request.sha256()?.as_bytes()
            || bytes[HEADER.len() + 64] != dimensions
            || node.count as usize > BLOCK_ROWS
            || u32::from_le_bytes(bytes[HEADER.len() + 65..HEADER.len() + 69].try_into()?)
                != node.first
            || u32::from(u16::from_le_bytes(
                bytes[HEADER.len() + 69..prefix].try_into()?,
            )) != node.count
            || bytes.len() != prefix + node.count as usize * usize::from(dimensions) * 4
        {
            return Err("compact coordinate block identity/length/coverage mismatch".into());
        }
        let mut rows = vec![vec![0; usize::from(dimensions)]; node.count as usize];
        let mut at = prefix;
        for row in &mut rows {
            for bits in row.iter_mut() {
                *bits = u32::from_le_bytes(bytes[at..at + 4].try_into()?);
                at += 4;
            }
            validate_row(row, dimensions)?;
        }
        Ok(ReadBody::Leaf(rows))
    } else {
        let page: Branch = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
        if page.schema_version != 1
            || page.domain != DOMAIN
            || page.request_sha256 != request.sha256()?
            || page.dimensions != dimensions
            || branch_node(request, &page.children, node.sha256.clone())? != *node
        {
            return Err("compact coordinate branch context/coverage mismatch".into());
        }
        Ok(ReadBody::Branch(page.children))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinateVisit {
    pub rows: u64,
    pub read_bytes: u64,
}
/// Streaming DATA traversal, not generation authentication. A publication or
/// query caller must wrap its genuine current selection in the supplied live
/// Boundary. No coordinates or authorization observations persist here.
pub fn visit_coordinate_blocks_checked<B: Boundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    selected: &VectorProgress,
    budget: IoBudget,
    boundary: &mut B,
    mut visitor: impl FnMut(u32, &[Vec<u32>], &mut B) -> Result<()>,
) -> Result<CoordinateVisit> {
    selected.canonical_bytes(request)?;
    budget.validate()?;
    if !selected.complete || budget.write_bytes != 0 || budget.new_files != 0 {
        return Err("coordinate traversal requires complete finite read-only DATA".into());
    }
    let dimensions = selected
        .dimensions
        .ok_or("complete coordinates have no actual basis dimensions")?;
    let mut result = CoordinateVisit {
        rows: 0,
        read_bytes: 0,
    };
    fn walk<B: Boundary>(
        store: &dyn IndexReadStore,
        request: &VectorRequest,
        dimensions: u8,
        node: &VectorNode,
        limit: u64,
        result: &mut CoordinateVisit,
        boundary: &mut B,
        visitor: &mut impl FnMut(u32, &[Vec<u32>], &mut B) -> Result<()>,
    ) -> Result<()> {
        boundary.check(Access::Inspect {
            binding: &request.corpus().binding,
        })?;
        result.read_bytes = result
            .read_bytes
            .checked_add(RUN_PAGE_READ)
            .ok_or("compact traversal read overflow")?;
        if result.read_bytes > limit {
            return Err("compact traversal exhausts read credit before I/O".into());
        }
        match read_node(store, request, dimensions, node, boundary)? {
            ReadBody::Leaf(rows) => {
                if u64::from(node.first) != result.rows {
                    return Err("compact traversal skips/duplicates ordinal coverage".into());
                }
                visitor(node.first, &rows, boundary)?;
                result.rows = result
                    .rows
                    .checked_add(rows.len() as u64)
                    .ok_or("compact traversal row overflow")?;
            }
            ReadBody::Branch(children) => {
                for child in children {
                    walk(
                        store, request, dimensions, &child, limit, result, boundary, visitor,
                    )?;
                }
            }
        }
        boundary.check(Access::Inspect {
            binding: &request.corpus().binding,
        })
    }
    if let Some(root) = &selected.coordinates.root {
        walk(
            store,
            request,
            dimensions,
            root,
            budget.read_bytes,
            &mut result,
            boundary,
            &mut visitor,
        )?;
    }
    if result.rows != request.corpus().entry_count {
        return Err("compact traversal omits actual complete corpus coverage".into());
    }
    boundary.check(Access::Inspect {
        binding: &request.corpus().binding,
    })?;
    Ok(result)
}
