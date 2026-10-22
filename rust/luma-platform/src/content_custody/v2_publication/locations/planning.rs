//! Exact new-node counts from genuine selected tree topology and real new
//! logical keys. No future address, inode, object digest, write or authority is
//! synthesized. The publisher must still verify the actual exact node count.
use super::*;

// These are ancestor-authenticated addresses in an already selected current
// tree, not a directory inventory or a hash-to-path adoption mechanism. Older
// immutable subtrees cannot contain the newly introduced job's nodes: every
// new child requires a newly sealed ancestor in the deterministic COW update.
pub(in crate::content_checkpoint::custody) fn selected_location_nodes(
    root: &Root,
    job: &str,
    io: &mut impl Io,
) -> Result<Vec<SealedReference>> {
    root.validate()?;
    selected_nodes(root, job, DOMAIN, io)
}
pub(in crate::content_checkpoint::custody) fn selected_job_nodes(
    root: &JobRoot,
    job: &str,
    io: &mut impl Io,
) -> Result<Vec<SealedReference>> {
    root.validate()?;
    selected_nodes(&root.0, job, JOB_DOMAIN, io)
}
fn selected_nodes(
    root: &Root,
    job: &str,
    domain: &str,
    io: &mut impl Io,
) -> Result<Vec<SealedReference>> {
    digest(job)?;
    io.check()?;
    let mut session = Session {
        binding: &root.binding,
        domain,
        io,
        reads: 0,
        writes: 0,
    };
    let mut pending = root.page.clone().into_iter().collect::<Vec<_>>();
    let mut selected = BTreeMap::new();
    while let Some(reference) = pending.pop() {
        session.io.check()?;
        if reference.location.slot.job != job {
            continue;
        }
        if selected.len() >= 256
            || selected
                .insert(reference.location.slot.number, reference.location.clone())
                .is_some()
        {
            return Err("current selected index aliases/exceeds one exact job namespace".into());
        }
        let node = session.read(&reference)?;
        if let Body::Branch { children } = node.body {
            pending.extend(children);
        }
    }
    session.io.check()?;
    Ok(selected.into_values().collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::content_checkpoint::custody) struct Layout {
    pub new_nodes: usize,
    pub entries: u64,
    pub height: u8,
}
#[derive(Clone)]
struct Shape {
    first: String,
    last: String,
    entries: u64,
    height: u8,
}
impl Shape {
    fn of(reference: &NodeRef) -> Self {
        Self {
            first: reference.first_key.clone(),
            last: reference.last_key.clone(),
            entries: reference.entries,
            height: reference.height,
        }
    }
    fn branch(children: &[Self], height: u8) -> Result<Self> {
        if children.is_empty() || children.len() > FANOUT || height == 0 || height > MAX_HEIGHT {
            return Err("planned direct index branch exceeds closed topology".into());
        }
        let mut count = 0_u64;
        let mut previous = None;
        for child in children {
            if child.height.checked_add(1) != Some(height)
                || previous.is_some_and(|last: &String| last >= &child.first)
            {
                return Err("planned direct index child ranges overlap or change height".into());
            }
            count = count
                .checked_add(child.entries)
                .ok_or("planned direct index count overflow")?;
            previous = Some(&child.last);
        }
        if count > MAX_ENTRIES {
            return Err("planned direct index exceeds entry policy".into());
        }
        Ok(Self {
            first: children[0].first.clone(),
            last: children[children.len() - 1].last.clone(),
            entries: count,
            height,
        })
    }
}
struct Planner<'a, 'b, T: Io> {
    session: Session<'a, T>,
    written: &'b mut usize,
}
impl<T: Io> Planner<'_, '_, T> {
    fn charge(&mut self) -> Result<()> {
        self.session.io.check()?;
        if *self.written >= MAX_NODES {
            return Err("planned new-node budget exhausted before allocation".into());
        }
        *self.written += 1;
        Ok(())
    }
    fn batch(&mut self, base: Option<&NodeRef>, keys: &[String]) -> Result<Vec<Shape>> {
        self.session.io.check()?;
        if keys.is_empty() {
            return Ok(base.map(Shape::of).into_iter().collect());
        }
        let node = base
            .map(|reference| self.session.read(reference))
            .transpose()?;
        match node.map(|node| (node.height, node.body)) {
            None | Some((0, Body::Leaf { .. })) => {
                let mut all = match base {
                    None => Vec::new(),
                    Some(reference) => match self.session.read(reference)?.body {
                        Body::Leaf { entries } => {
                            entries.into_iter().map(|entry| entry.sha256).collect()
                        }
                        _ => {
                            return Err(
                                "selected leaf changed during exact topology planning".into()
                            )
                        }
                    },
                };
                for key in keys {
                    match all.binary_search(key) {
                        Ok(_) => {
                            return Err(
                                "planned new logical key already exists; no overwrite/adoption"
                                    .into(),
                            )
                        }
                        Err(index) => all.insert(index, key.clone()),
                    }
                }
                let mut result = Vec::new();
                for chunk in all.chunks(FANOUT) {
                    self.charge()?;
                    result.push(Shape {
                        first: chunk[0].clone(),
                        last: chunk[chunk.len() - 1].clone(),
                        entries: chunk.len() as u64,
                        height: 0,
                    });
                }
                Ok(result)
            }
            Some((height, Body::Branch { children })) => {
                let mut next = Vec::new();
                let mut used = 0;
                for (index, child) in children.iter().enumerate() {
                    let first = used;
                    while used < keys.len()
                        && (index + 1 == children.len() || keys[used] <= child.last_key)
                    {
                        used += 1;
                    }
                    if used == first {
                        next.push(Shape::of(child));
                    } else {
                        next.extend(self.batch(Some(child), &keys[first..used])?);
                    }
                }
                if used != keys.len() {
                    return Err(
                        "topology planner did not consume the exact ordered key range".into(),
                    );
                }
                let mut result = Vec::new();
                for children in next.chunks(FANOUT) {
                    let shape = Shape::branch(children, height)?;
                    self.charge()?;
                    result.push(shape);
                }
                Ok(result)
            }
            _ => Err("selected topology node body contradicts height".into()),
        }
    }
}
fn plan(root: &Root, keys: &[String], domain: &str, io: &mut impl Io) -> Result<Layout> {
    root.validate_domain(domain)?;
    if keys.is_empty() || keys.len() > MAX_INSERTIONS {
        return Err("invalid exact topology planning batch".into());
    }
    let expected = root
        .entries
        .checked_add(keys.len() as u64)
        .ok_or("planned entry count overflow")?;
    if expected > MAX_ENTRIES {
        return Err("planned entry count exceeds policy before I/O".into());
    }
    let mut previous = None;
    for key in keys {
        digest(key)?;
        if previous.is_some_and(|old: &String| old >= key) {
            return Err("planned logical keys must be unique and sorted".into());
        }
        previous = Some(key);
    }
    let mut count = 0;
    let mut planner = Planner {
        session: Session {
            binding: &root.binding,
            domain,
            io,
            reads: 0,
            writes: 0,
        },
        written: &mut count,
    };
    let mut forest = planner.batch(root.page.as_ref(), keys)?;
    while forest.len() > 1 {
        let height = forest[0]
            .height
            .checked_add(1)
            .ok_or("planned direct height overflow")?;
        let mut parents = Vec::new();
        for children in forest.chunks(FANOUT) {
            let shape = Shape::branch(children, height)?;
            planner.charge()?;
            parents.push(shape);
        }
        forest = parents;
    }
    let root_shape = forest.pop().ok_or("planned index unexpectedly empty")?;
    if root_shape.entries != expected {
        return Err("planned topology loses or duplicates logical entries".into());
    }
    planner.session.io.check()?;
    Ok(Layout {
        new_nodes: count,
        entries: expected,
        height: root_shape.height,
    })
}
pub(in crate::content_checkpoint::custody) fn new_locations(
    root: &Root,
    keys: &[String],
    io: &mut impl Io,
) -> Result<Layout> {
    plan(root, keys, DOMAIN, io)
}
pub(in crate::content_checkpoint::custody) fn new_jobs(
    root: &JobRoot,
    keys: &[String],
    io: &mut impl Io,
) -> Result<Layout> {
    plan(&root.0, keys, JOB_DOMAIN, io)
}
