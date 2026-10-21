//! Bounded proof DATA readers for independent closure verification and a fresh
//! selected-generation query boundary. They do not select a build job or grant.
use super::*;

pub struct RecordWindow {
    pub first: u32,
    pub rows: Vec<VectorRecord>,
    pub read_bytes: u64,
}
pub struct CoordinateWindow {
    pub first: u32,
    pub rows: Vec<Vec<u32>>,
    pub read_bytes: u64,
}

fn current<B: CorpusIndexBoundary>(request: &VectorRequest, b: &mut B) -> Result<()> {
    b.check(Access::Inspect {
        binding: &request.corpus().binding,
    })?;
    b.current_corpus(request.corpus())?;
    b.current_builder(
        request.corpus(),
        &request.projection.covariance.statistics.ingestion.builder,
    )
}
fn charge(used: &mut u64, limit: u64) -> Result<()> {
    *used = used
        .checked_add(RUN_PAGE_READ)
        .ok_or("vector DATA read overflow")?;
    if *used > limit {
        return Err("vector DATA reader exhausts credit before private I/O".into());
    }
    Ok(())
}
pub fn read_record_window_data<B: CorpusIndexBoundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    selected: &VectorProgress,
    after: u32,
    maximum: usize,
    budget: IoBudget,
    b: &mut B,
) -> Result<RecordWindow> {
    selected.canonical_bytes(request)?;
    budget.validate()?;
    if !selected.complete
        || maximum == 0
        || maximum > 256
        || u64::from(after) > request.corpus().entry_count
        || budget.write_bytes != 0
        || budget.new_files != 0
    {
        return Err("record DATA reader requires complete finite rank coverage".into());
    }
    let count = (request.corpus().entry_count - u64::from(after)).min(maximum as u64);
    let end = u64::from(after) + count;
    let mut result = RecordWindow {
        first: after,
        rows: Vec::new(),
        read_bytes: 0,
    };
    fn walk<B: CorpusIndexBoundary>(
        store: &dyn IndexReadStore,
        request: &VectorRequest,
        dimensions: u8,
        node: &VectorNode,
        range: &std::ops::Range<u64>,
        result: &mut RecordWindow,
        limit: u64,
        b: &mut B,
    ) -> Result<()> {
        if u64::from(node.first) >= range.end
            || u64::from(node.first) + u64::from(node.count) <= range.start
        {
            return Ok(());
        }
        current(request, b)?;
        charge(&mut result.read_bytes, limit)?;
        let bytes = store.read_page(
            &node.sha256,
            IoBudget {
                read_bytes: RUN_PAGE_READ,
                write_bytes: 0,
                new_files: 0,
            },
            b,
        )?;
        let page: Page = crate::corpus_index::decode(&bytes, MAX_INDEX_PAGE_BYTES)?;
        if page.node(request, dimensions, node.sha256.clone())? != *node {
            return Err("record DATA subtree identity/coverage differs".into());
        }
        match page.body {
            Body::Leaf { rows, .. } => {
                for row in rows {
                    if range.contains(&u64::from(row.ordinal)) {
                        if u64::from(row.ordinal)
                            != u64::from(result.first) + result.rows.len() as u64
                        {
                            return Err("record DATA window skips or duplicates a rank".into());
                        }
                        b.current_candidate(request.corpus(), &row.record)?;
                        result.rows.push(row);
                    }
                }
            }
            Body::Branch { children } => {
                for child in children {
                    walk(store, request, dimensions, &child, range, result, limit, b)?;
                }
            }
        }
        current(request, b)
    }
    current(request, b)?;
    if count != 0 {
        walk(
            store,
            request,
            selected
                .dimensions
                .ok_or("complete vectors omit dimensions")?,
            selected
                .root
                .as_ref()
                .ok_or("complete record root absent")?,
            &(u64::from(after)..end),
            &mut result,
            budget.read_bytes,
            b,
        )?;
    }
    if result.rows.len() as u64 != count {
        return Err("record DATA reader omits requested ranks".into());
    }
    for row in &result.rows {
        b.current_candidate(request.corpus(), &row.record)?;
    }
    current(request, b)?;
    Ok(result)
}
pub fn read_coordinate_window_data<B: CorpusIndexBoundary>(
    store: &dyn IndexReadStore,
    request: &VectorRequest,
    selected: &VectorProgress,
    after: u32,
    maximum: usize,
    budget: IoBudget,
    b: &mut B,
) -> Result<CoordinateWindow> {
    selected.canonical_bytes(request)?;
    budget.validate()?;
    if !selected.complete
        || maximum == 0
        || maximum > coordinates::BLOCK_ROWS
        || u64::from(after) > request.corpus().entry_count
        || budget.write_bytes != 0
        || budget.new_files != 0
    {
        return Err("coordinate DATA reader requires complete finite rank coverage".into());
    }
    let count = (request.corpus().entry_count - u64::from(after)).min(maximum as u64);
    let end = u64::from(after) + count;
    let mut result = CoordinateWindow {
        first: after,
        rows: Vec::new(),
        read_bytes: 0,
    };
    fn walk<B: CorpusIndexBoundary>(
        store: &dyn IndexReadStore,
        request: &VectorRequest,
        dimensions: u8,
        node: &VectorNode,
        range: &std::ops::Range<u64>,
        result: &mut CoordinateWindow,
        limit: u64,
        b: &mut B,
    ) -> Result<()> {
        if u64::from(node.first) >= range.end
            || u64::from(node.first) + u64::from(node.count) <= range.start
        {
            return Ok(());
        }
        current(request, b)?;
        charge(&mut result.read_bytes, limit)?;
        match coordinates::read_node(store, request, dimensions, node, b)? {
            coordinates::ReadBody::Leaf(rows) => {
                for (i, row) in rows.into_iter().enumerate() {
                    let ordinal = u64::from(node.first) + i as u64;
                    if range.contains(&ordinal) {
                        if ordinal != u64::from(result.first) + result.rows.len() as u64 {
                            return Err("coordinate DATA window skips/duplicates a rank".into());
                        }
                        result.rows.push(row);
                    }
                }
            }
            coordinates::ReadBody::Branch(children) => {
                for child in children {
                    walk(store, request, dimensions, &child, range, result, limit, b)?;
                }
            }
        }
        current(request, b)
    }
    current(request, b)?;
    if count != 0 {
        walk(
            store,
            request,
            selected
                .dimensions
                .ok_or("complete vectors omit dimensions")?,
            selected
                .coordinates
                .root
                .as_ref()
                .ok_or("complete coordinate root absent")?,
            &(u64::from(after)..end),
            &mut result,
            budget.read_bytes,
            b,
        )?;
    }
    if result.rows.len() as u64 != count {
        return Err("coordinate DATA reader omits requested ranks".into());
    }
    current(request, b)?;
    Ok(result)
}
