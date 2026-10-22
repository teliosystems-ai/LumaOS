//! Direct-addressed immutable storage-location tree. Every node child contains
//! its exact sealed slot address and digest. Runtime lookup never scans a
//! namespace or consults an unselected hash resolver. This DATA component does
//! not select C, authenticate an operation or replace independent semantic and
//! physical allocation verification in the native publisher.
use super::super::paged::slots::{Kind as SlotKind, SealedReference};
use super::*;

const FANOUT: usize = 16;
const MAX_HEIGHT: u8 = 8;
const MAX_ENTRIES: u64 = 1_048_576;
const MAX_INSERTIONS: usize = 256;
const MAX_NODES: usize = 5120;
const DOMAIN: &str = "luma-c-direct-slot-locations-v3";
const JOB_DOMAIN: &str = "luma-c-direct-job-manifests-v4";
#[cfg(test)]
#[path = "locations/planning.rs"]
pub(super) mod planning;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeRef {
    pub location: SealedReference,
    pub first_key: String,
    pub last_key: String,
    pub entries: u64,
    pub height: u8,
}
impl NodeRef {
    fn validate(&self) -> Result<()> {
        digest(&self.first_key)?;
        digest(&self.last_key)?;
        self.location.validate_data()?;
        digest(&self.location.sha256)?;
        if self.location.slot.kind != SlotKind::Page
            || self.location.bytes == 0
            || self.location.bytes > PAGE_BYTES as u64
            || self.first_key > self.last_key
            || self.entries == 0
            || self.entries > MAX_ENTRIES
            || self.height > MAX_HEIGHT
        {
            return Err("invalid closed direct-addressed location node reference".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Root {
    pub schema_version: u32,
    pub domain: String,
    pub binding: map::CustodyBinding,
    pub page: Option<NodeRef>,
    pub entries: u64,
}
impl Root {
    pub fn empty_data(binding: &map::CustodyBinding) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            page: None,
            entries: 0,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_domain(DOMAIN)
    }
    fn validate_domain(&self, domain: &str) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 3
            || ![DOMAIN, JOB_DOMAIN].contains(&domain)
            || self.domain != domain
            || self.entries > MAX_ENTRIES
            || self.page.is_none() != (self.entries == 0)
        {
            return Err("invalid C storage-location root".into());
        }
        if let Some(page) = &self.page {
            page.validate()?;
            if page.entries != self.entries {
                return Err("location root count differs from its exact direct node".into());
            }
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 4096 {
            return Err("storage-location root exceeds bounded descriptor field".into());
        }
        Ok(bytes)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(hash(&self.bytes()?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Insertion {
    pub sha256: String,
    pub location: SealedReference,
}
impl Insertion {
    fn validate_domain(&self, domain: &str) -> Result<()> {
        digest(&self.sha256)?;
        self.location.validate_data()?;
        if ![DOMAIN, JOB_DOMAIN].contains(&domain)
            || (domain == DOMAIN && self.sha256 != self.location.sha256)
            || (domain == JOB_DOMAIN && self.location.slot.kind != SlotKind::Record)
            || self.location.bytes == 0
            || self.location.bytes > self.location.slot.capacity
        {
            return Err(
                "location insertion does not bind complete sealed object hash/capacity".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Leaf { entries: Vec<Insertion> },
    Branch { children: Vec<NodeRef> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    schema_version: u32,
    domain: String,
    binding: map::CustodyBinding,
    height: u8,
    body: Body,
}
impl Node {
    fn summary(&self) -> Result<(String, String, u64)> {
        self.binding.validate()?;
        if self.schema_version != 3
            || ![DOMAIN, JOB_DOMAIN].contains(&self.domain.as_str())
            || self.height > MAX_HEIGHT
        {
            return Err("invalid direct-slot node domain/version/height".into());
        }
        match &self.body {
            Body::Leaf { entries } => {
                if self.height != 0 || entries.is_empty() || entries.len() > FANOUT {
                    return Err("invalid bounded location leaf".into());
                }
                let mut previous = None;
                for entry in entries {
                    entry.validate_domain(&self.domain)?;
                    if previous.is_some_and(|key: &String| key >= &entry.sha256) {
                        return Err("location leaf repeats or reorders a whole object hash".into());
                    }
                    previous = Some(&entry.sha256);
                }
                Ok((
                    entries[0].sha256.clone(),
                    entries[entries.len() - 1].sha256.clone(),
                    entries.len() as u64,
                ))
            }
            Body::Branch { children } => {
                if self.height == 0 || children.is_empty() || children.len() > FANOUT {
                    return Err("invalid bounded location branch".into());
                }
                let mut last = None;
                let mut count = 0_u64;
                for child in children {
                    child.validate()?;
                    if child.height.checked_add(1) != Some(self.height)
                        || last.is_some_and(|key: &String| key >= &child.first_key)
                    {
                        return Err("location children overlap or change height".into());
                    }
                    count = count
                        .checked_add(child.entries)
                        .ok_or("location subtree count overflow")?;
                    last = Some(&child.last_key);
                }
                if count > MAX_ENTRIES {
                    return Err("location subtree exceeds finite bound".into());
                }
                Ok((
                    children[0].first_key.clone(),
                    children[children.len() - 1].last_key.clone(),
                    count,
                ))
            }
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.summary()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > PAGE_BYTES {
            return Err("direct-slot node exceeds one physically preallocated page".into());
        }
        Ok(bytes)
    }
    fn reference(&self, location: SealedReference) -> Result<NodeRef> {
        let bytes = self.bytes()?;
        if location.sha256 != hash(&bytes) || location.bytes != bytes.len() as u64 {
            return Err("new location node seal does not cover exact canonical bytes".into());
        }
        let (first_key, last_key, entries) = self.summary()?;
        let reference = NodeRef {
            location,
            first_key,
            last_key,
            entries,
            height: self.height,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Native implementations must bind these calls to the original selected C
/// cut and actual held slot allocations. An implementation supplies I/O only;
/// neither trait membership nor serialized roots grants publication authority.
pub(super) trait Io {
    fn check(&mut self) -> Result<()>;
    fn read(&mut self, location: &SealedReference) -> Result<Vec<u8>>;
    fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference>;
}
struct Session<'a, T: Io> {
    binding: &'a map::CustodyBinding,
    domain: &'a str,
    io: &'a mut T,
    reads: usize,
    writes: usize,
}
impl<T: Io> Session<'_, T> {
    fn read(&mut self, reference: &NodeRef) -> Result<Node> {
        reference.validate()?;
        self.io.check()?;
        if self.reads >= MAX_NODES {
            return Err("direct-slot verification read budget exhausted before I/O".into());
        }
        self.reads += 1;
        let bytes = self.io.read(&reference.location)?;
        if bytes.len() as u64 != reference.location.bytes
            || bytes.len() > PAGE_BYTES
            || hash(&bytes) != reference.location.sha256
        {
            return Err("direct-addressed node data/hash differs".into());
        }
        let node: Node = canonical(&bytes, PAGE_BYTES)?;
        if node.binding != *self.binding
            || node.domain != self.domain
            || node.reference(reference.location.clone())? != *reference
        {
            return Err("direct node substitutes C binding, key range or exact child count".into());
        }
        self.io.check()?;
        Ok(node)
    }
    fn write(&mut self, node: Node) -> Result<NodeRef> {
        self.io.check()?;
        if node.binding != *self.binding || node.domain != self.domain {
            return Err(
                "direct tree write changes its exact domain/C binding before allocation".into(),
            );
        }
        let bytes = node.bytes()?;
        if self.writes >= MAX_NODES {
            return Err("direct-slot new node budget exhausted before allocation".into());
        }
        self.writes += 1;
        let location = self.io.seal_node(&bytes)?;
        let reference = node.reference(location)?;
        if self.read(&reference)? != node {
            return Err("direct node complete readback differs".into());
        }
        Ok(reference)
    }
    fn insert_batch(&mut self, base: Option<&NodeRef>, batch: &[Change]) -> Result<Vec<NodeRef>> {
        self.io.check()?;
        if batch.is_empty() {
            return Ok(base.cloned().into_iter().collect());
        }
        let node = base.map(|value| self.read(value)).transpose()?;
        match node.map(|value| (value.height, value.body)) {
            None | Some((0, Body::Leaf { .. })) => {
                let mut entries = match base {
                    Some(reference) => match self.read(reference)?.body {
                        Body::Leaf { entries } => entries,
                        _ => return Err("location leaf changed within the original batch".into()),
                    },
                    None => Vec::new(),
                };
                for change in batch {
                    let entry = &change.next;
                    match entries.binary_search_by(|old| old.sha256.cmp(&entry.sha256)) {
                        Ok(index) => {
                            if self.domain != JOB_DOMAIN
                                || change.previous.as_ref() != Some(&entries[index].location)
                            {
                                return Err("selected direct key cannot be redirected without its exact job-manifest CAS".into());
                            }
                            entries[index] = entry.clone();
                        }
                        Err(index) => {
                            if change.previous.is_some() {
                                return Err(
                                    "job-manifest CAS expects a nonexistent previous value".into(),
                                );
                            }
                            entries.insert(index, entry.clone());
                        }
                    }
                }
                let mut pages = Vec::new();
                for chunk in entries.chunks(FANOUT) {
                    pages.push(self.write(Node {
                        schema_version: 3,
                        domain: self.domain.into(),
                        binding: self.binding.clone(),
                        height: 0,
                        body: Body::Leaf {
                            entries: chunk.to_vec(),
                        },
                    })?);
                }
                Ok(pages)
            }
            Some((height, Body::Branch { children })) => {
                let mut next = Vec::with_capacity(children.len() + batch.len());
                let mut consumed = 0;
                for (index, child) in children.iter().enumerate() {
                    let first = consumed;
                    while consumed < batch.len()
                        && (index + 1 == children.len()
                            || batch[consumed].next.sha256 <= child.last_key)
                    {
                        consumed += 1;
                    }
                    if consumed == first {
                        next.push(child.clone());
                    } else {
                        next.extend(self.insert_batch(Some(child), &batch[first..consumed])?);
                    }
                }
                if consumed != batch.len() {
                    return Err("location batch did not consume its exact ordered key range".into());
                }
                let mut pages = Vec::new();
                for chunk in next.chunks(FANOUT) {
                    pages.push(self.write(Node {
                        schema_version: 3,
                        domain: self.domain.into(),
                        binding: self.binding.clone(),
                        height,
                        body: Body::Branch {
                            children: chunk.to_vec(),
                        },
                    })?);
                }
                Ok(pages)
            }
            _ => Err("direct-slot node body contradicts its height".into()),
        }
    }
}

pub(super) fn lookup(root: &Root, key: &str, io: &mut impl Io) -> Result<Option<SealedReference>> {
    root.validate()?;
    lookup_domain(root, key, DOMAIN, io)
}
fn lookup_domain(
    root: &Root,
    key: &str,
    domain: &str,
    io: &mut impl Io,
) -> Result<Option<SealedReference>> {
    root.validate_domain(domain)?;
    digest(key)?;
    let mut session = Session {
        binding: &root.binding,
        domain,
        io,
        reads: 0,
        writes: 0,
    };
    session.io.check()?;
    let mut next = root.page.clone();
    while let Some(reference) = next {
        if key < reference.first_key.as_str() || key > reference.last_key.as_str() {
            session.io.check()?;
            return Ok(None);
        }
        match session.read(&reference)?.body {
            Body::Leaf { entries } => {
                let result = entries
                    .binary_search_by(|entry| entry.sha256.as_str().cmp(key))
                    .ok()
                    .map(|index| entries[index].location.clone());
                session.io.check()?;
                return Ok(result);
            }
            Body::Branch { children } => {
                next = children
                    .into_iter()
                    .find(|child| key >= child.first_key.as_str() && key <= child.last_key.as_str())
            }
        }
    }
    session.io.check()?;
    Ok(None)
}

/// Exact append-only storage-location DATA. Replacing an existing hash address
/// fails; unchanged subtrees remain byte-for-byte referenced. A native publisher
/// must additionally prove the independent semantic delta and exact physical
/// consumption before selecting the returned root under its existing C event.
pub(super) fn insert(root: &Root, entries: &[Insertion], io: &mut impl Io) -> Result<Root> {
    root.validate()?;
    let changes: Vec<_> = entries
        .iter()
        .map(|next| Change {
            previous: None,
            next: next.clone(),
        })
        .collect();
    update_domain(root, &changes, DOMAIN, io)
}
#[derive(Clone)]
struct Change {
    previous: Option<SealedReference>,
    next: Insertion,
}
fn update_domain(root: &Root, changes: &[Change], domain: &str, io: &mut impl Io) -> Result<Root> {
    root.validate_domain(domain)?;
    if changes.is_empty() || changes.len() > MAX_INSERTIONS {
        return Err("invalid bounded location insertion batch".into());
    }
    let mut previous = None;
    for change in changes {
        let entry = &change.next;
        entry.validate_domain(domain)?;
        if let Some(before) = &change.previous {
            before.validate_data()?;
            if domain != JOB_DOMAIN || before == &entry.location {
                return Err("direct manifest edit has invalid/no-op previous reference".into());
            }
        }
        if previous.is_some_and(|key: &String| key >= &entry.sha256) {
            return Err("location batch must contain unique sorted hashes".into());
        }
        previous = Some(&entry.sha256);
    }
    if root
        .entries
        .checked_add(
            changes
                .iter()
                .filter(|change| change.previous.is_none())
                .count() as u64,
        )
        .map_or(true, |count| count > MAX_ENTRIES)
    {
        return Err("location batch exceeds its immutable index count before I/O".into());
    }
    let mut session = Session {
        binding: &root.binding,
        domain,
        io,
        reads: 0,
        writes: 0,
    };
    for change in changes {
        let entry = &change.next;
        session.io.check()?;
        let data = session.io.read(&entry.location)?;
        if data.len() as u64 != entry.location.bytes || hash(&data) != entry.location.sha256 {
            return Err(
                "location insertion does not contain complete physically observed object data"
                    .into(),
            );
        }
        session.io.check()?;
    }
    // One ordered recursive batch: no intermediate prefix tree is sealed and
    // retained merely because another entry belongs to this same operation.
    let mut next = session.insert_batch(root.page.as_ref(), changes)?;
    while next.len() > 1 {
        let height = next[0]
            .height
            .checked_add(1)
            .ok_or("location tree height overflow")?;
        if height > MAX_HEIGHT {
            return Err("location tree reaches finite maximum height".into());
        }
        let mut parent = Vec::new();
        for children in next.chunks(FANOUT) {
            parent.push(session.write(Node {
                schema_version: 3,
                domain: domain.into(),
                binding: root.binding.clone(),
                height,
                body: Body::Branch {
                    children: children.to_vec(),
                },
            })?);
        }
        next = parent;
    }
    let page = next.pop();
    let next = Root {
        page,
        entries: 0,
        ..root.clone()
    };
    let next = Root {
        entries: next.page.as_ref().map_or(0, |page| page.entries),
        ..next
    };
    next.validate_domain(domain)?;
    session.io.check()?;
    Ok(next)
}

/// Independently replays the identical insertion algorithm without invoking a
/// backing writer. Proposed node locations are a finite witness, not a resolver
/// or an authorization: each is reread in full, hashed and compared with the
/// exact newly reconstructed node bytes, and every witness must be consumed.
pub(super) fn verify_insertions(
    base: &Root,
    expected: &Root,
    entries: &[Insertion],
    witnesses: &[SealedReference],
    io: &mut impl Io,
) -> Result<()> {
    base.validate()?;
    expected.validate()?;
    let changes: Vec<_> = entries
        .iter()
        .map(|next| Change {
            previous: None,
            next: next.clone(),
        })
        .collect();
    verify_changes(base, expected, &changes, witnesses, DOMAIN, io)
}
fn verify_changes(
    base: &Root,
    expected: &Root,
    changes: &[Change],
    witnesses: &[SealedReference],
    domain: &str,
    io: &mut impl Io,
) -> Result<()> {
    base.validate_domain(domain)?;
    expected.validate_domain(domain)?;
    if base.binding != expected.binding || witnesses.is_empty() || witnesses.len() > MAX_NODES {
        return Err("invalid finite direct-location replay witness".into());
    }
    let mut physical = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for reference in witnesses {
        reference.validate_data()?;
        digest(&reference.sha256)?;
        if reference.slot.kind != SlotKind::Page
            || reference.bytes == 0
            || reference.bytes > PAGE_BYTES as u64
            || !physical.insert((
                reference.slot.device,
                reference.slot.inode,
                reference.slot.mount,
            ))
            || !addresses.insert((reference.slot.job.clone(), reference.slot.number))
        {
            return Err(
                "location replay witness repeats a physical slot or substitutes an index node"
                    .into(),
            );
        }
    }
    struct Readonly<'a, T: Io> {
        io: &'a mut T,
        supplied: &'a [SealedReference],
        consumed: usize,
    }
    impl<T: Io> Io for Readonly<'_, T> {
        fn check(&mut self) -> Result<()> {
            self.io.check()
        }
        fn read(&mut self, location: &SealedReference) -> Result<Vec<u8>> {
            self.io.read(location)
        }
        fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference> {
            self.io.check()?;
            let reference = self
                .supplied
                .get(self.consumed)
                .ok_or("next exact location-delta seal call has no ordered physical witness")?
                .clone();
            let actual = self.io.read(&reference)?;
            if actual != bytes
                || reference.bytes != bytes.len() as u64
                || reference.sha256 != hash(bytes)
            {
                return Err(
                    "proposed index slot differs from independently reconstructed node bytes"
                        .into(),
                );
            }
            self.consumed += 1;
            self.io.check()?;
            Ok(reference)
        }
    }
    let mut replay = Readonly {
        io,
        supplied: witnesses,
        consumed: 0,
    };
    if update_domain(base, changes, domain, &mut replay)? != *expected
        || replay.consumed != replay.supplied.len()
    {
        return Err("proposed location root is not the exact complete append-only delta".into());
    }
    replay.io.check()
}

/// A disjoint direct-addressed JOB index, never an object-hash resolver. The
/// value is an immutable complete job manifest. Its own index nodes are bound
/// directly by ancestors, not recursively entered into their own index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub(super) struct JobRoot(Root);
impl JobRoot {
    pub fn empty_data(binding: &map::CustodyBinding) -> Result<Self> {
        let mut root = Root::empty_data(binding)?;
        root.domain = JOB_DOMAIN.into();
        let value = Self(root);
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.0.validate_domain(JOB_DOMAIN)
    }
    pub fn binding(&self) -> &map::CustodyBinding {
        &self.0.binding
    }
    pub fn entries(&self) -> u64 {
        self.0.entries
    }
    pub fn root_node(&self) -> Result<Option<&NodeRef>> {
        self.validate()?;
        Ok(self.0.page.as_ref())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub fn lookup(&self, job: &str, io: &mut impl Io) -> Result<Option<SealedReference>> {
        self.validate()?;
        lookup_domain(&self.0, job, JOB_DOMAIN, io)
    }
    pub fn update(&self, edits: &[JobEdit], io: &mut impl Io) -> Result<Self> {
        self.validate()?;
        let changes = job_changes(edits)?;
        Ok(Self(update_domain(&self.0, &changes, JOB_DOMAIN, io)?))
    }
    pub fn verify_update(
        &self,
        next: &Self,
        edits: &[JobEdit],
        witnesses: &[SealedReference],
        io: &mut impl Io,
    ) -> Result<()> {
        self.validate()?;
        next.validate()?;
        verify_changes(
            &self.0,
            &next.0,
            &job_changes(edits)?,
            witnesses,
            JOB_DOMAIN,
            io,
        )
    }
}
#[derive(Clone, Debug)]
pub(super) struct JobEdit {
    pub job: String,
    pub previous: Option<SealedReference>,
    pub next: SealedReference,
}
fn job_changes(edits: &[JobEdit]) -> Result<Vec<Change>> {
    if edits.is_empty() || edits.len() > MAX_INSERTIONS {
        return Err("invalid bounded job manifest batch".into());
    }
    edits
        .iter()
        .map(|edit| {
            digest(&edit.job)?;
            edit.next.validate_data()?;
            if edit.next.slot.kind != SlotKind::Record {
                return Err("job index requires a complete immutable manifest record".into());
            }
            Ok(Change {
                previous: edit.previous.clone(),
                next: Insertion {
                    sha256: edit.job.clone(),
                    location: edit.next.clone(),
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::super::paged::slots::{Pool, Reference};
    use super::*;
    #[derive(Default)]
    struct Memory {
        objects: BTreeMap<u32, (SealedReference, Vec<u8>)>,
        next: u32,
        reads: usize,
        writes: usize,
        witnesses: Vec<SealedReference>,
        refuse: bool,
    }
    impl Memory {
        fn object(&mut self, bytes: &[u8]) -> SealedReference {
            let count = self.next;
            self.next += 1;
            let ordinal = count / 128;
            let number = ordinal * 138 + count % 128;
            let reference = SealedReference {
                slot: Reference {
                    schema_version: 3,
                    job: "77".repeat(32),
                    number,
                    pool: Pool::Publication(ordinal),
                    kind: SlotKind::Page,
                    capacity: PAGE_BYTES as u64,
                    device: 1,
                    inode: u64::from(count) + 1,
                    mount: 2,
                    allocated_bytes: PAGE_BYTES as u64,
                    instance_id: hash(&count.to_be_bytes()),
                    created_ctime_seconds: 1,
                    created_ctime_nanoseconds: 0,
                },
                bytes: bytes.len() as u64,
                sha256: hash(bytes),
                sealed_ctime_seconds: 2,
                sealed_ctime_nanoseconds: 0,
            };
            self.objects
                .insert(number, (reference.clone(), bytes.to_vec()));
            reference
        }
    }
    impl Io for Memory {
        fn check(&mut self) -> Result<()> {
            if self.refuse {
                return Err("fixture original-selection loss".into());
            }
            Ok(())
        }
        fn read(&mut self, location: &SealedReference) -> Result<Vec<u8>> {
            self.check()?;
            self.reads += 1;
            let (reference, bytes) = self
                .objects
                .get(&location.slot.number)
                .ok_or("fixture missing actual slot")?;
            if reference != location {
                return Err("fixture slot identity changed".into());
            }
            Ok(bytes.clone())
        }
        fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference> {
            self.check()?;
            self.writes += 1;
            let location = self.object(bytes);
            self.witnesses.push(location.clone());
            Ok(location)
        }
    }
    fn binding() -> map::CustodyBinding {
        map::CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "22".repeat(32),
        }
    }
    fn entries(io: &mut Memory, count: usize) -> Vec<Insertion> {
        let mut entries = (0..count)
            .map(|index| {
                let location = io.object(format!("complete-object-{index}").as_bytes());
                Insertion {
                    sha256: location.sha256.clone(),
                    location,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        entries
    }
    #[test]
    fn exact_topology_plan_matches_every_actual_seal_across_leaf_branch_and_root_splits() {
        for initial in [0, 1, 15, 16, 17, 40, 256] {
            let mut io = Memory::default();
            let empty = Root::empty_data(&binding()).unwrap();
            let base = if initial == 0 {
                empty
            } else {
                let batch = entries(&mut io, initial);
                insert(&empty, &batch, &mut io).unwrap()
            };
            let mut batch = (0..64)
                .map(|index| {
                    let location =
                        io.object(format!("new-topology-object-{initial}-{index}").as_bytes());
                    Insertion {
                        sha256: location.sha256.clone(),
                        location,
                    }
                })
                .collect::<Vec<_>>();
            batch.sort_by(|a, b| a.sha256.cmp(&b.sha256));
            let keys = batch
                .iter()
                .map(|entry| entry.sha256.clone())
                .collect::<Vec<_>>();
            let before = io.writes;
            let planned = planning::new_locations(&base, &keys, &mut io).unwrap();
            assert_eq!(io.writes, before, "planning has no seal callback");
            let next = insert(&base, &batch, &mut io).unwrap();
            assert_eq!(io.writes - before, planned.new_nodes);
            assert_eq!(next.entries, planned.entries);
            assert_eq!(next.page.as_ref().unwrap().height, planned.height);
        }
    }
    #[test]
    fn exact_topology_plan_refuses_bad_or_stale_inputs_before_writes() {
        let mut io = Memory::default();
        let empty = Root::empty_data(&binding()).unwrap();
        let keys = vec!["44".repeat(32); MAX_INSERTIONS + 1];
        assert!(planning::new_locations(&empty, &keys, &mut io).is_err());
        assert_eq!((io.reads, io.writes), (0, 0));
        assert!(planning::new_locations(&empty, &keys[..2], &mut io).is_err());
        assert_eq!((io.reads, io.writes), (0, 0));
        let batch = entries(&mut io, 40);
        let base = insert(&empty, &batch, &mut io).unwrap();
        let writes = io.writes;
        assert!(planning::new_locations(&base, &[batch[0].sha256.clone()], &mut io).is_err());
        assert_eq!(io.writes, writes);
        io.refuse = true;
        assert!(planning::new_locations(&base, &["ff".repeat(32)], &mut io).is_err());
        assert_eq!(io.writes, writes);
    }
    #[test]
    fn exact_job_topology_plan_uses_disjoint_real_logical_keys_and_matches_actual_count() {
        let mut io = Memory::default();
        let root = JobRoot::empty_data(&binding()).unwrap();
        let keys = (1..=20).map(|n| format!("{n:064x}")).collect::<Vec<_>>();
        let planned = planning::new_jobs(&root, &keys, &mut io).unwrap();
        assert_eq!((io.reads, io.writes), (0, 0));
        let edits = keys
            .into_iter()
            .map(|job| {
                let mut next = io.object(format!("whole-job-manifest-{job}").as_bytes());
                next.slot.schema_version = 4;
                next.slot.kind = SlotKind::Record;
                next.slot.capacity = 1024 * 1024;
                next.slot.allocated_bytes = 1024 * 1024;
                io.objects.insert(
                    next.slot.number,
                    (
                        next.clone(),
                        format!("whole-job-manifest-{job}").into_bytes(),
                    ),
                );
                JobEdit {
                    job,
                    previous: None,
                    next,
                }
            })
            .collect::<Vec<_>>();
        let next = root.update(&edits, &mut io).unwrap();
        assert_eq!(io.writes, planned.new_nodes);
        assert_eq!(next.entries(), planned.entries);
        let node = next.root_node().unwrap().unwrap();
        let selected =
            planning::selected_job_nodes(&next, &node.location.slot.job.clone(), &mut io).unwrap();
        assert_eq!(selected.len(), planned.new_nodes);
        assert_eq!(
            io.writes, planned.new_nodes,
            "selected metadata closure is strictly read-only"
        );
    }
    #[test]
    fn fixed_fanout_page_bound_covers_maximum_decimal_physical_reference_fields() {
        let mut entries = Vec::new();
        for index in 1..=FANOUT {
            let key = format!("{index:064x}");
            let reference = SealedReference {
                slot: Reference {
                    schema_version: 4,
                    job: "ff".repeat(32),
                    number: 255,
                    pool: Pool::Publication(255),
                    kind: SlotKind::Record,
                    capacity: 1024 * 1024,
                    device: u64::MAX,
                    inode: u64::MAX,
                    mount: u64::MAX,
                    allocated_bytes: 1024 * 1024 + 64 * 1024,
                    instance_id: "ff".repeat(32),
                    created_ctime_seconds: i64::MIN,
                    created_ctime_nanoseconds: 999_999_999,
                },
                bytes: 1024 * 1024,
                sha256: key.clone(),
                sealed_ctime_seconds: i64::MIN,
                sealed_ctime_nanoseconds: 999_999_999,
            };
            reference.validate_data().unwrap();
            assert!(
                serde_json::to_vec(&reference.slot).unwrap().len() <= 640,
                "exact reviewed manifest bound must include maximum decimal physical fields"
            );
            assert!(
                serde_json::to_vec(&reference).unwrap().len() <= 896,
                "semantic manifest bound must include the whole maximum-field seal"
            );
            entries.push(Insertion {
                sha256: key,
                location: reference,
            });
        }
        let leaf = Node {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: binding(),
            height: 0,
            body: Body::Leaf {
                entries: entries.clone(),
            },
        };
        assert!(leaf.bytes().unwrap().len() <= PAGE_BYTES);
        let children = entries
            .into_iter()
            .map(|entry| {
                let mut location = entry.location;
                location.slot.kind = SlotKind::Page;
                location.slot.capacity = PAGE_BYTES as u64;
                location.slot.allocated_bytes = PAGE_BYTES as u64 + 64 * 1024;
                location.bytes = PAGE_BYTES as u64;
                NodeRef {
                    location,
                    first_key: entry.sha256.clone(),
                    last_key: entry.sha256,
                    entries: MAX_ENTRIES / FANOUT as u64,
                    height: MAX_HEIGHT - 1,
                }
            })
            .collect();
        let branch = Node {
            schema_version: 3,
            domain: JOB_DOMAIN.into(),
            binding: binding(),
            height: MAX_HEIGHT,
            body: Body::Branch { children },
        };
        assert!(branch.bytes().unwrap().len() <= PAGE_BYTES);
    }
    #[test]
    fn direct_tree_splits_and_exact_readonly_replay_preserves_complete_addresses() {
        let base = Root::empty_data(&binding()).unwrap();
        let mut io = Memory::default();
        let entries = entries(&mut io, 40);
        let next = insert(&base, &entries, &mut io).unwrap();
        assert_eq!(next.entries, 40);
        assert!(next.page.as_ref().unwrap().height > 0);
        let selected = planning::selected_location_nodes(
            &next,
            &next.page.as_ref().unwrap().location.slot.job.clone(),
            &mut io,
        )
        .unwrap();
        assert_eq!(selected.len(), io.witnesses.len());
        for entry in &entries {
            assert_eq!(
                lookup(&next, &entry.sha256, &mut io).unwrap(),
                Some(entry.location.clone())
            );
        }
        assert_eq!(lookup(&next, &"ff".repeat(32), &mut io).unwrap(), None);
        let witnesses = io.witnesses.clone();
        let writes = io.writes;
        verify_insertions(&base, &next, &entries, &witnesses, &mut io).unwrap();
        assert_eq!(writes, io.writes);
        assert!(verify_insertions(
            &base,
            &next,
            &entries,
            &witnesses[..witnesses.len() - 1],
            &mut io
        )
        .is_err());
        assert_eq!(writes, io.writes);
        let mut extra = witnesses.clone();
        extra.push(io.object(b"unreferenced-witness"));
        assert!(verify_insertions(&base, &next, &entries, &extra, &mut io).is_err());
        let mut wrong = next.clone();
        wrong.binding.installation = "33".repeat(32);
        assert!(lookup(&wrong, &entries[0].sha256, &mut io).is_err());
    }
    #[test]
    fn immutable_hash_cannot_be_reinserted_redirected_or_duplicated_in_a_batch() {
        let base = Root::empty_data(&binding()).unwrap();
        let mut io = Memory::default();
        let entries = entries(&mut io, 1);
        let next = insert(&base, &entries, &mut io).unwrap();
        let writes = io.writes;
        assert!(insert(&next, &entries, &mut io).is_err());
        assert_eq!(writes, io.writes);
        let bytes = io.read(&entries[0].location).unwrap();
        let replacement = io.object(&bytes);
        assert!(insert(
            &next,
            &[Insertion {
                sha256: replacement.sha256.clone(),
                location: replacement
            }],
            &mut io
        )
        .is_err());
        assert!(insert(&base, &[entries[0].clone(), entries[0].clone()], &mut io).is_err());
        io.refuse = true;
        assert!(lookup(&next, &entries[0].sha256, &mut io).is_err());
    }
    #[test]
    fn ordered_batch_seals_only_final_nodes_and_replay_rejects_reused_or_reordered_slots() {
        let base = Root::empty_data(&binding()).unwrap();
        let mut io = Memory::default();
        let entries = entries(&mut io, 40);
        let next = insert(&base, &entries, &mut io).unwrap();
        let witnesses = io.witnesses.clone();
        assert_eq!(witnesses.len(), 4, "forty entries produce three final leaves and one parent, not forty retained prefix trees");
        assert_eq!(
            witnesses
                .iter()
                .map(|value| &value.sha256)
                .collect::<BTreeSet<_>>()
                .len(),
            witnesses.len()
        );
        let (first, second) = (0, 1);
        assert_ne!(witnesses[first].slot.inode, witnesses[second].slot.inode);
        assert_ne!(witnesses[first].slot.number, witnesses[second].slot.number);
        let writes = io.writes;
        verify_insertions(&base, &next, &entries, &witnesses, &mut io).unwrap();
        assert_eq!(io.writes, writes);

        let mut duplicate_physical = witnesses.clone();
        duplicate_physical[second] = duplicate_physical[first].clone();
        let before = io.reads;
        assert!(verify_insertions(&base, &next, &entries, &duplicate_physical, &mut io).is_err());
        assert_eq!(
            io.reads, before,
            "reused physical slots refuse before backing I/O"
        );

        let mut reordered = witnesses.clone();
        reordered.swap(0, 1);
        assert!(verify_insertions(&base, &next, &entries, &reordered, &mut io).is_err());
        assert_eq!(io.writes, writes);

        let reference = &witnesses[first];
        let original = io.objects.get(&reference.slot.number).unwrap().clone();
        io.objects
            .get_mut(&reference.slot.number)
            .unwrap()
            .0
            .slot
            .inode += 1;
        assert!(verify_insertions(&base, &next, &entries, &witnesses, &mut io).is_err());
        io.objects.insert(reference.slot.number, original);
        verify_insertions(&base, &next, &entries, &witnesses, &mut io).unwrap();
        assert_eq!(io.writes, writes);
    }
    #[test]
    fn malformed_direct_nodes_fail_even_with_recomputed_outer_hashes() {
        let base = Root::empty_data(&binding()).unwrap();
        let mut io = Memory::default();
        let entries = entries(&mut io, 1);
        let next = insert(&base, &entries, &mut io).unwrap();
        let location = &next.page.as_ref().unwrap().location;
        let bytes = io.read(location).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for raw in [
            format!("{text}\n"),
            text.replacen(
                "\"schema_version\":3",
                "\"schema_version\":3,\"schema_version\":3",
                1,
            ),
            text.replacen(
                "\"schema_version\":3",
                "\"schema_version\":3,\"authority\":true",
                1,
            ),
        ] {
            let location = io.object(raw.as_bytes());
            let mut wrong = next.clone();
            wrong.page.as_mut().unwrap().location = location;
            assert!(lookup(&wrong, &entries[0].sha256, &mut io).is_err());
        }
        let mut wrong = next.clone();
        wrong.page.as_mut().unwrap().entries = 2;
        wrong.entries = 2;
        assert!(lookup(&wrong, &entries[0].sha256, &mut io).is_err());
    }
    #[test]
    fn read_and_write_budgets_refuse_before_backing_io() {
        let base = Root::empty_data(&binding()).unwrap();
        let mut io = Memory::default();
        let entries = entries(&mut io, 1);
        let next = insert(&base, &entries, &mut io).unwrap();
        let reads = io.reads;
        let writes = io.writes;
        let mut session = Session {
            binding: &base.binding,
            domain: DOMAIN,
            io: &mut io,
            reads: MAX_NODES,
            writes: 0,
        };
        assert!(session.read(next.page.as_ref().unwrap()).is_err());
        assert_eq!(session.io.reads, reads);
        let node = Node {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: base.binding.clone(),
            height: 0,
            body: Body::Leaf { entries },
        };
        session.reads = 0;
        session.writes = MAX_NODES;
        assert!(session.write(node).is_err());
        assert_eq!(session.io.writes, writes);
    }
    #[test]
    fn empty_location_root_is_nonzero_binding_scoped_data_not_a_selected_authority() {
        let base = Root::empty_data(&binding()).unwrap();
        assert_eq!(base.entries, 0);
        assert!(base.page.is_none());
        assert_ne!(base.sha256().unwrap(), "00".repeat(32));
        let mut other = base.clone();
        other.binding.sealed_genesis_sha256 = "33".repeat(32);
        assert_ne!(base.sha256().unwrap(), other.sha256().unwrap());
        other.domain = "luma-editable-content-store-v2".into();
        assert!(other.validate().is_err());
    }
    fn manifest(io: &mut Memory, bytes: &[u8]) -> SealedReference {
        let mut reference = io.object(bytes);
        reference.slot.schema_version = 4;
        reference.slot.kind = SlotKind::Record;
        reference.slot.capacity = 4096;
        reference.slot.allocated_bytes = 4096;
        reference.validate_data().unwrap();
        io.objects.get_mut(&reference.slot.number).unwrap().0 = reference.clone();
        reference
    }
    #[test]
    fn disjoint_job_index_counts_jobs_not_slots_and_requires_exact_previous_manifest() {
        let mut io = Memory::default();
        let base = JobRoot::empty_data(&binding()).unwrap();
        let first = manifest(&mut io, b"complete immutable job manifest one");
        let job = "11".repeat(32);
        let edit = JobEdit {
            job: job.clone(),
            previous: None,
            next: first.clone(),
        };
        let next = base.update(std::slice::from_ref(&edit), &mut io).unwrap();
        assert_eq!(next.entries(), 1);
        assert_eq!(next.binding(), &binding());
        assert_eq!(next.lookup(&job, &mut io).unwrap(), Some(first.clone()));
        let witnesses = io.witnesses.clone();
        let writes = io.writes;
        base.verify_update(&next, std::slice::from_ref(&edit), &witnesses, &mut io)
            .unwrap();
        assert_eq!(writes, io.writes);
        let second = manifest(&mut io, b"complete immutable successor job manifest");
        let update = JobEdit {
            job: job.clone(),
            previous: Some(first.clone()),
            next: second.clone(),
        };
        let before = io.witnesses.len();
        let changed = next.update(std::slice::from_ref(&update), &mut io).unwrap();
        let witnesses = io.witnesses[before..].to_vec();
        next.verify_update(&changed, std::slice::from_ref(&update), &witnesses, &mut io)
            .unwrap();
        assert_eq!(changed.entries(), 1);
        assert_eq!(changed.lookup(&job, &mut io).unwrap(), Some(second.clone()));
        assert_ne!(changed.sha256().unwrap(), next.sha256().unwrap());
        assert!(next
            .update(
                &[JobEdit {
                    previous: None,
                    ..update.clone()
                }],
                &mut io
            )
            .is_err());
        assert!(changed
            .update(std::slice::from_ref(&update), &mut io)
            .is_err());
        assert!(base.update(&[update], &mut io).is_err());
        assert!(
            lookup(&changed.0, &job, &mut io).is_err(),
            "a job index can never be used as a content-hash resolver"
        );
        let mut wrong = changed.clone();
        wrong.0.domain = DOMAIN.into();
        assert!(wrong.lookup(&job, &mut io).is_err());
        let mut wrong_binding = changed.clone();
        wrong_binding.0.binding.installation = "33".repeat(32);
        assert!(wrong_binding.lookup(&job, &mut io).is_err());
    }
}
