//! Direct-addressed physical slot ledger DATA. Every available address is
//! selected by an authenticated ancestor; an existing address can only move
//! from Available to Spent, never be redirected or made available again.
//! Spent metadata addresses deliberately contain no self-file hash. Their
//! actual complete bytes are committed by direct parent references, avoiding
//! a descriptor/index self-hash cycle without treating a filename as authority.
use super::super::super::paged::slots::{Kind as SlotKind, Reference, SealedReference};
use super::super::*;

const DOMAIN: &str = "luma-c-selected-slot-ledger-v3";
const LEAF: usize = 16;
const FANOUT: usize = 16;
const HEIGHT: u8 = 8;
const MAX_ENTRIES: u64 = 1_048_576;
const MAX_EDITS: usize = 256;
const MAX_NODES: usize = 5120;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Purpose {
    SemanticPage,
    SemanticRecord,
    LocationIndex,
    ReservationIndex,
    Descriptor,
    Retired,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum State {
    Available,
    Spent {
        operation_sha256: String,
        purpose: Purpose,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub slot: Reference,
    pub state: State,
}
impl Entry {
    fn validate(&self) -> Result<()> {
        self.slot.validate_data()?;
        if let State::Spent {
            operation_sha256,
            purpose,
        } = &self.state
        {
            digest(operation_sha256)?;
            let allowed = match purpose {
                Purpose::SemanticRecord => self.slot.kind == SlotKind::Record,
                Purpose::Retired => true,
                _ => self.slot.kind == SlotKind::Page,
            };
            if !allowed {
                return Err(
                    "slot disposition does not match its selected fixed capacity class".into(),
                );
            }
        }
        Ok(())
    }
    pub fn key(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("{}{:08x}", self.slot.job, self.slot.number))
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
    fn available(&self) -> u64 {
        u64::from(matches!(self.state, State::Available))
    }
    fn bytes(&self) -> u64 {
        if self.available() == 1 {
            self.slot.capacity
        } else {
            0
        }
    }
}
fn key(value: &str) -> Result<()> {
    if value.len() != 72
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid exact job-and-slot reservation key".into());
    }
    digest(&value[..64])
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeRef {
    pub location: SealedReference,
    pub first_key: String,
    pub last_key: String,
    pub entries: u64,
    pub available: u64,
    pub available_bytes: u64,
    pub height: u8,
}
impl NodeRef {
    fn validate(&self) -> Result<()> {
        self.location.validate_data()?;
        key(&self.first_key)?;
        key(&self.last_key)?;
        if self.location.slot.kind != SlotKind::Page
            || self.location.bytes > PAGE_BYTES as u64
            || self.first_key > self.last_key
            || self.entries == 0
            || self.entries > MAX_ENTRIES
            || self.available > self.entries
            || self.height > HEIGHT
            || self.available_bytes > 24 * 1024 * 1024 * 1024
        {
            return Err("invalid selected slot-ledger direct child".into());
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
    pub available: u64,
    pub available_bytes: u64,
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
            available: 0,
            available_bytes: 0,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 3
            || self.domain != DOMAIN
            || self.entries > MAX_ENTRIES
            || self.available > self.entries
            || self.available_bytes > 24 * 1024 * 1024 * 1024
            || self.page.is_none() != (self.entries == 0)
        {
            return Err("invalid selected physical slot ledger root".into());
        }
        match &self.page {
            Some(page) => {
                page.validate()?;
                if (page.entries, page.available, page.available_bytes)
                    != (self.entries, self.available, self.available_bytes)
                {
                    return Err("slot ledger root totals differ from its exact child".into());
                }
            }
            None => {
                if self.available != 0 || self.available_bytes != 0 {
                    return Err("empty ledger has nonempty capacity".into());
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Leaf { entries: Vec<Entry> },
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
    fn summary(&self) -> Result<(String, String, u64, u64, u64)> {
        self.binding.validate()?;
        if self.schema_version != 3 || self.domain != DOMAIN || self.height > HEIGHT {
            return Err("invalid physical ledger node domain/binding/height".into());
        }
        let mut first = None;
        let mut last = None;
        let mut count = 0_u64;
        let mut available = 0_u64;
        let mut bytes = 0_u64;
        let mut add = |begin: String, end: String, n: u64, a: u64, b: u64| -> Result<()> {
            if last.as_ref().is_some_and(|old: &String| old >= &begin) {
                return Err("slot ledger duplicate/overlapping ordered key".into());
            }
            if first.is_none() {
                first = Some(begin);
            }
            last = Some(end);
            count = count.checked_add(n).ok_or("slot ledger count overflow")?;
            available = available
                .checked_add(a)
                .ok_or("slot ledger available count overflow")?;
            bytes = bytes
                .checked_add(b)
                .ok_or("slot ledger capacity overflow")?;
            Ok(())
        };
        match &self.body {
            Body::Leaf { entries } => {
                if self.height != 0 || entries.is_empty() || entries.len() > LEAF {
                    return Err("invalid bounded slot-ledger leaf".into());
                }
                for entry in entries {
                    let key = entry.key()?;
                    add(key.clone(), key, 1, entry.available(), entry.bytes())?;
                }
            }
            Body::Branch { children } => {
                if self.height == 0 || children.is_empty() || children.len() > FANOUT {
                    return Err("invalid bounded slot-ledger branch".into());
                }
                for child in children {
                    child.validate()?;
                    if child.height.checked_add(1) != Some(self.height) {
                        return Err("slot ledger child height differs".into());
                    }
                    add(
                        child.first_key.clone(),
                        child.last_key.clone(),
                        child.entries,
                        child.available,
                        child.available_bytes,
                    )?;
                }
            }
        }
        if count > MAX_ENTRIES || bytes > 24 * 1024 * 1024 * 1024 {
            return Err("slot ledger finite capacity exceeded".into());
        }
        Ok((
            first.ok_or("slot ledger empty first key")?,
            last.ok_or("slot ledger empty last key")?,
            count,
            available,
            bytes,
        ))
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.summary()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > PAGE_BYTES {
            return Err("physical ledger node exceeds fixed page slot".into());
        }
        Ok(bytes)
    }
    fn reference(&self, location: SealedReference) -> Result<NodeRef> {
        let (first_key, last_key, entries, available, available_bytes) = self.summary()?;
        let bytes = self.bytes()?;
        if location.sha256 != hash(&bytes) || location.bytes != bytes.len() as u64 {
            return Err("physical ledger seal does not bind actual whole page".into());
        }
        let value = NodeRef {
            location,
            first_key,
            last_key,
            entries,
            available,
            available_bytes,
            height: self.height,
        };
        value.validate()?;
        Ok(value)
    }
}

/// I/O only. Neither this trait nor a supplied root proves current C or a
/// grant. The native adapter must retain current original operation and the
/// actual selected reservation proof before any physical seal call.
pub(super) trait Io {
    fn check(&mut self) -> Result<()>;
    fn read(&mut self, reference: &SealedReference) -> Result<Vec<u8>>;
    fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference>;
}
struct Session<'a, T: Io> {
    binding: &'a map::CustodyBinding,
    io: &'a mut T,
    reads: usize,
    writes: usize,
}
impl<T: Io> Session<'_, T> {
    fn read(&mut self, reference: &NodeRef) -> Result<Node> {
        reference.validate()?;
        self.io.check()?;
        if self.reads >= MAX_NODES {
            return Err("physical ledger bounded read budget exhausted before I/O".into());
        }
        self.reads += 1;
        let bytes = self.io.read(&reference.location)?;
        if bytes.len() > PAGE_BYTES
            || bytes.len() as u64 != reference.location.bytes
            || hash(&bytes) != reference.location.sha256
        {
            return Err("physical ledger immutable page hash/length differs".into());
        }
        let node: Node = canonical(&bytes, PAGE_BYTES)?;
        if node.binding != *self.binding
            || node.reference(reference.location.clone())? != *reference
        {
            return Err("physical ledger child substitutes C binding/range/capacity".into());
        }
        self.io.check()?;
        Ok(node)
    }
    fn write(&mut self, node: Node) -> Result<NodeRef> {
        self.io.check()?;
        let bytes = node.bytes()?;
        if self.writes >= MAX_NODES {
            return Err("physical ledger bounded seal budget exhausted before I/O".into());
        }
        self.writes += 1;
        let reference = node.reference(self.io.seal_node(&bytes)?)?;
        if self.read(&reference)? != node {
            return Err("physical ledger complete seal/readback differs".into());
        }
        Ok(reference)
    }
    fn change(&mut self, base: Option<&NodeRef>, edit: &Edit) -> Result<Vec<NodeRef>> {
        let node = base.map(|reference| self.read(reference)).transpose()?;
        match node.map(|node| (node.height, node.body)) {
            None => {
                if edit.expected_sha256.is_some() || !matches!(edit.next.state, State::Available) {
                    return Err(
                        "new physical slot is not an exact absent available allocation".into(),
                    );
                }
                Ok(vec![self.write(Node {
                    schema_version: 3,
                    domain: DOMAIN.into(),
                    binding: self.binding.clone(),
                    height: 0,
                    body: Body::Leaf {
                        entries: vec![edit.next.clone()],
                    },
                })?])
            }
            Some((0, Body::Leaf { mut entries })) => {
                match entries
                    .binary_search_by(|old| old.key().expect("validated entry key").cmp(&edit.key))
                {
                    Ok(index) => {
                        let old = &entries[index];
                        if edit.expected_sha256.as_ref() != Some(&old.sha256()?)
                            || old.slot != edit.next.slot
                            || !matches!(old.state, State::Available)
                            || !matches!(edit.next.state, State::Spent { .. })
                        {
                            return Err("physical slot transition redirects/reuses a selected allocation or changes its CAS".into());
                        }
                        entries[index] = edit.next.clone();
                    }
                    Err(index) => {
                        if edit.expected_sha256.is_some()
                            || !matches!(edit.next.state, State::Available)
                        {
                            return Err(
                                "physical slot insert does not prove absent available allocation"
                                    .into(),
                            );
                        }
                        entries.insert(index, edit.next.clone());
                    }
                }
                let mut result = Vec::new();
                for chunk in entries.chunks(LEAF) {
                    result.push(self.write(Node {
                        schema_version: 3,
                        domain: DOMAIN.into(),
                        binding: self.binding.clone(),
                        height: 0,
                        body: Body::Leaf {
                            entries: chunk.to_vec(),
                        },
                    })?);
                }
                Ok(result)
            }
            Some((height, Body::Branch { mut children })) => {
                let index = children
                    .iter()
                    .position(|child| edit.key <= child.last_key)
                    .unwrap_or(children.len() - 1);
                let replacements = self.change(Some(&children[index]), edit)?;
                children.splice(index..index + 1, replacements);
                let mut result = Vec::new();
                for chunk in children.chunks(FANOUT) {
                    result.push(self.write(Node {
                        schema_version: 3,
                        domain: DOMAIN.into(),
                        binding: self.binding.clone(),
                        height,
                        body: Body::Branch {
                            children: chunk.to_vec(),
                        },
                    })?);
                }
                Ok(result)
            }
            _ => Err("physical ledger body/height mismatch".into()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Edit {
    pub key: String,
    pub expected_sha256: Option<String>,
    pub next: Entry,
}
impl Edit {
    pub fn validate(&self) -> Result<()> {
        key(&self.key)?;
        self.next.validate()?;
        if self.next.key()? != self.key {
            return Err("physical ledger edit changes exact job/slot key".into());
        }
        if let Some(old) = &self.expected_sha256 {
            digest(old)?;
        }
        Ok(())
    }
}
pub(super) fn lookup(root: &Root, literal: &str, io: &mut impl Io) -> Result<Option<Entry>> {
    root.validate()?;
    key(literal)?;
    io.check()?;
    let mut session = Session {
        binding: &root.binding,
        io,
        reads: 0,
        writes: 0,
    };
    let mut reference = root.page.clone();
    while let Some(current) = reference {
        if literal < current.first_key.as_str() || literal > current.last_key.as_str() {
            session.io.check()?;
            return Ok(None);
        }
        match session.read(&current)?.body {
            Body::Leaf { entries } => {
                let result = entries
                    .into_iter()
                    .find(|entry| entry.key().is_ok_and(|key| key == literal));
                session.io.check()?;
                return Ok(result);
            }
            Body::Branch { children } => {
                reference = children.into_iter().find(|child| {
                    literal >= child.first_key.as_str() && literal <= child.last_key.as_str()
                });
            }
        }
    }
    session.io.check()?;
    Ok(None)
}
pub(super) fn prepare(root: &Root, edits: &[Edit], io: &mut impl Io) -> Result<Root> {
    root.validate()?;
    io.check()?;
    if edits.is_empty() || edits.len() > MAX_EDITS {
        return Err("physical ledger edit window exceeds fixed bounds".into());
    }
    let mut previous = None;
    let mut physical = BTreeSet::new();
    let mut instances = BTreeSet::new();
    for edit in edits {
        edit.validate()?;
        if previous.is_some_and(|old: &String| old >= &edit.key) {
            return Err("physical ledger edit batch repeats/reorders an address".into());
        }
        if !physical.insert((
            edit.next.slot.device,
            edit.next.slot.inode,
            edit.next.slot.mount,
        )) || !instances.insert(edit.next.slot.instance_id.clone())
        {
            return Err(
                "physical slot edit window aliases an actual inode or instance marker".into(),
            );
        }
        previous = Some(&edit.key);
    }
    let mut session = Session {
        binding: &root.binding,
        io,
        reads: 0,
        writes: 0,
    };
    let mut page = root.page.clone();
    for edit in edits {
        let mut changed = session.change(page.as_ref(), edit)?;
        page = if changed.len() == 1 {
            changed.pop()
        } else {
            let height = changed[0]
                .height
                .checked_add(1)
                .ok_or("physical ledger height overflow")?;
            if height > HEIGHT {
                return Err("physical ledger maximum direct height exhausted".into());
            }
            Some(session.write(Node {
                schema_version: 3,
                domain: DOMAIN.into(),
                binding: root.binding.clone(),
                height,
                body: Body::Branch { children: changed },
            })?)
        };
    }
    let root = Root {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: root.binding.clone(),
        entries: page.as_ref().map_or(0, |page| page.entries),
        available: page.as_ref().map_or(0, |page| page.available),
        available_bytes: page.as_ref().map_or(0, |page| page.available_bytes),
        page,
    };
    root.validate()?;
    session.io.check()?;
    Ok(root)
}

/// Exact ordered seal-call replay. Repeated payload digests are legal only at
/// distinct actual physical addresses, never deduplicated into a hash oracle.
pub(super) fn verify(
    root: &Root,
    next: &Root,
    edits: &[Edit],
    witnesses: &[SealedReference],
    io: &mut impl Io,
) -> Result<()> {
    root.validate()?;
    next.validate()?;
    if root.binding != next.binding || witnesses.is_empty() || witnesses.len() > MAX_NODES {
        return Err("invalid bounded physical ledger replay witness".into());
    }
    let mut physical = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for reference in witnesses {
        reference.validate_data()?;
        if reference.slot.kind != SlotKind::Page
            || reference.bytes > PAGE_BYTES as u64
            || !physical.insert((
                reference.slot.device,
                reference.slot.inode,
                reference.slot.mount,
            ))
            || !addresses.insert((reference.slot.job.clone(), reference.slot.number))
        {
            return Err(
                "physical ledger witness reuses an inode/address or changes page class".into(),
            );
        }
    }
    struct Readonly<'a, T: Io> {
        io: &'a mut T,
        witnesses: &'a [SealedReference],
        used: usize,
    }
    impl<T: Io> Io for Readonly<'_, T> {
        fn check(&mut self) -> Result<()> {
            self.io.check()
        }
        fn read(&mut self, reference: &SealedReference) -> Result<Vec<u8>> {
            self.io.read(reference)
        }
        fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference> {
            self.io.check()?;
            let reference = self
                .witnesses
                .get(self.used)
                .ok_or("physical ledger next seal-call witness absent")?
                .clone();
            let actual = self.io.read(&reference)?;
            if actual != bytes
                || reference.bytes != bytes.len() as u64
                || reference.sha256 != hash(bytes)
            {
                return Err(
                    "physical ledger ordered witness differs from exact reconstructed page".into(),
                );
            }
            self.used += 1;
            self.io.check()?;
            Ok(reference)
        }
    }
    let mut readonly = Readonly {
        io,
        witnesses,
        used: 0,
    };
    if prepare(root, edits, &mut readonly)? != *next || readonly.used != witnesses.len() {
        return Err("physical ledger proposed delta/witness coverage differs".into());
    }
    readonly.io.check()
}
#[cfg(test)]
#[path = "reservations/tests.rs"]
mod tests;
