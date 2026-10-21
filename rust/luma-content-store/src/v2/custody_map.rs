//! Independent-C authenticated maps. These bytes never encode an OwnerBinding
//! and never turn a caller's root/digest into current checkpoint authority.
use crate::Result;
use luma_content::sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DOMAIN: &str = "luma-content-custody-map-v2";
pub const MAX_PAGE_BYTES: usize = 16 * 1024;
pub const MAX_VALUE_BYTES: usize = 2048;
pub const MAX_ENTRIES: u64 = 1_048_576;
pub const MAX_HEIGHT: u8 = 8;
pub const MAX_EDITS: usize = 256;
const LEAF: usize = 8;
const FANOUT: usize = 32;
const MAX_GENERATED_PAGES: usize = 5120;
const MAX_GENERATED_BYTES: usize = 96 * 1024 * 1024;

fn hash(value: &str) -> Result<()> {
    super::digest(value)
}
fn canonical<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8], limit: usize) -> Result<T> {
    super::canonical(bytes, limit)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyBinding {
    pub installation: String,
    pub sealed_genesis_sha256: String,
}
impl CustodyBinding {
    pub fn validate(&self) -> Result<()> {
        hash(&self.installation)?;
        hash(&self.sealed_genesis_sha256)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    OwnerStates,
    Recipients,
    Signers,
    Unavailable,
    RestoreReservations,
    ArchiveInventory,
    IndexGenerations,
}
pub type PageRef = super::PageRef;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub schema_version: u32,
    pub domain: String,
    pub binding: CustodyBinding,
    pub kind: Kind,
    pub page: Option<PageRef>,
    pub entry_count: u64,
}
impl Root {
    pub fn empty_data(binding: &CustodyBinding, kind: Kind) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            kind,
            page: None,
            entry_count: 0,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1 || self.domain != DOMAIN || self.entry_count > MAX_ENTRIES {
            return Err("invalid C map binding/domain/count".into());
        }
        match &self.page {
            None if self.entry_count == 0 => Ok(()),
            Some(page) if self.entry_count > 0 => {
                page.validate()?;
                if page.entry_count != self.entry_count {
                    return Err("C map root count differs".into());
                }
                Ok(())
            }
            _ => Err("C map empty/page mismatch".into()),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 4096)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(sha256(&self.canonical_bytes()?))
    }
    pub fn key(&self, literal: &[u8]) -> Result<String> {
        self.validate()?;
        if literal.is_empty() || literal.len() > 4096 {
            return Err("C map key preimage outside bound".into());
        }
        Ok(sha256(&serde_json::to_vec(&(
            "luma-custody-map-key-v2",
            &self.binding,
            self.kind,
            literal,
        ))?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: String,
    value: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Leaf { entries: Vec<Entry> },
    Branch { children: Vec<PageRef> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    domain: String,
    binding: CustodyBinding,
    map_kind: Kind,
    body: Body,
}
impl Page {
    fn new(root: &Root, body: Body) -> Self {
        Self {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: root.binding.clone(),
            map_kind: root.kind,
            body,
        }
    }
    fn encode(&self) -> Result<(Vec<u8>, PageRef)> {
        self.binding.validate()?;
        if self.schema_version != 1 || self.domain != DOMAIN {
            return Err("invalid C map page domain".into());
        }
        let (first, last, count, height) = match &self.body {
            Body::Leaf { entries } => {
                if entries.is_empty() || entries.len() > LEAF {
                    return Err("C map leaf fanout exceeded".into());
                }
                let mut previous: Option<&str> = None;
                for entry in entries {
                    hash(&entry.key)?;
                    if entry.value.is_empty()
                        || entry.value.len() > MAX_VALUE_BYTES
                        || previous.is_some_and(|p| p >= entry.key.as_str())
                    {
                        return Err("C map leaf value/order invalid".into());
                    }
                    previous = Some(&entry.key);
                }
                (
                    entries[0].key.clone(),
                    entries.last().ok_or("C leaf empty")?.key.clone(),
                    entries.len() as u64,
                    0,
                )
            }
            Body::Branch { children } => {
                if children.is_empty() || children.len() > FANOUT {
                    return Err("C map branch fanout exceeded".into());
                }
                let height = children[0]
                    .height
                    .checked_add(1)
                    .ok_or("C map height overflow")?;
                let mut count = 0_u64;
                let mut previous: Option<&str> = None;
                for child in children {
                    child.validate()?;
                    if child.height.checked_add(1) != Some(height)
                        || previous.is_some_and(|p| p >= child.first_key.as_str())
                    {
                        return Err("C branch overlapping ranges/mixed heights".into());
                    }
                    count = count
                        .checked_add(child.entry_count)
                        .ok_or("C branch count overflow")?;
                    previous = Some(&child.last_key);
                }
                (
                    children[0].first_key.clone(),
                    children.last().ok_or("C branch empty")?.last_key.clone(),
                    count,
                    height,
                )
            }
        };
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("C map page bytes exceeded".into());
        }
        let reference = PageRef {
            sha256: sha256(&bytes),
            first_key: first,
            last_key: last,
            entry_count: count,
            height,
        };
        reference.validate()?;
        Ok((bytes, reference))
    }
    fn decode(bytes: &[u8], root: &Root, expected: &PageRef) -> Result<Self> {
        expected.validate()?;
        let value: Self = canonical(bytes, MAX_PAGE_BYTES)?;
        if value.binding != root.binding
            || value.map_kind != root.kind
            || value.encode()?.1 != *expected
        {
            return Err("C page hash/binding/kind/range/count differs".into());
        }
        Ok(value)
    }
}

/// Current original C selection and operation identity supplied to the native
/// callback. Possession/serialization is not a C token or grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub binding: CustodyBinding,
    pub selected_descriptor_sha256: String,
    pub selected_nv_head: String,
    pub review_sha256: Option<String>,
}
impl Context {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        hash(&self.selected_descriptor_sha256)?;
        hash(&self.selected_nv_head)?;
        if let Some(review) = &self.review_sha256 {
            hash(review)?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub new_files: u32,
}
impl Budget {
    pub fn validate(&self) -> Result<()> {
        if self.read_bytes == 0
            || self.read_bytes > 512 * 1024 * 1024
            || self.write_bytes > 256 * 1024 * 1024
            || self.new_files > 32768
            || (self.write_bytes == 0) != (self.new_files == 0)
        {
            return Err("C map I/O budget invalid".into());
        }
        Ok(())
    }
}

/// There is deliberately no default/permissive implementation or owner
/// Boundary adapter. Native implementations must check existing sealed C/NV,
/// held selection, current original principal/grant/UTC/lease on every call.
pub trait CustodyIo {
    fn admit(&mut self, context: &Context, budget: Budget) -> Result<()>;
    fn check_current(&mut self, context: &Context) -> Result<()>;
    fn read_page(&mut self, context: &Context, sha256: &str, maximum: usize) -> Result<Vec<u8>>;
    fn write_page(&mut self, context: &Context, bytes: &[u8]) -> Result<()>;
}
struct Session<'a, I: CustodyIo> {
    io: &'a mut I,
    context: &'a Context,
    budget: Budget,
    read: u64,
    written: u64,
    files: u32,
    persist: bool,
    pages: BTreeMap<String, Vec<u8>>,
    generated_bytes: usize,
}
impl<'a, I: CustodyIo> Session<'a, I> {
    fn new(io: &'a mut I, context: &'a Context, budget: Budget, persist: bool) -> Result<Self> {
        context.validate()?;
        budget.validate()?;
        if persist && context.review_sha256.is_none() || !persist && budget.write_bytes != 0 {
            return Err("C map write requires exact review; read cannot reserve effects".into());
        }
        io.admit(context, budget)?;
        io.check_current(context)?;
        Ok(Self {
            io,
            context,
            budget,
            read: 0,
            written: 0,
            files: 0,
            persist,
            pages: BTreeMap::new(),
            generated_bytes: 0,
        })
    }
    fn check(&mut self) -> Result<()> {
        self.io.check_current(self.context)
    }
    fn read(&mut self, reference: &PageRef) -> Result<Vec<u8>> {
        self.check()?;
        if let Some(bytes) = self.pages.get(&reference.sha256) {
            return Ok(bytes.clone());
        }
        self.read = self
            .read
            .checked_add(MAX_PAGE_BYTES as u64 + 1)
            .ok_or("C map read overflow")?;
        if self.read > self.budget.read_bytes {
            return Err("C map read admission exhausted BEFORE I/O".into());
        }
        let bytes = self
            .io
            .read_page(self.context, &reference.sha256, MAX_PAGE_BYTES)?;
        self.check()?;
        if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES || sha256(&bytes) != reference.sha256 {
            return Err("C map page read integrity differs".into());
        }
        Ok(bytes)
    }
    fn put(&mut self, root: &Root, body: Body) -> Result<PageRef> {
        let (bytes, reference) = Page::new(root, body).encode()?;
        self.check()?;
        if self.persist {
            self.written = self
                .written
                .checked_add(bytes.len() as u64)
                .ok_or("C map write overflow")?;
            self.files = self.files.checked_add(1).ok_or("C map inode overflow")?;
            if self.written > self.budget.write_bytes || self.files > self.budget.new_files {
                return Err("C map write admission exhausted BEFORE I/O".into());
            }
            self.io.write_page(self.context, &bytes)?;
            self.check()?;
        } else if !self.pages.contains_key(&reference.sha256) {
            let next = self
                .generated_bytes
                .checked_add(bytes.len())
                .ok_or("C generated page memory overflow")?;
            if next > MAX_GENERATED_BYTES || self.pages.len() >= MAX_GENERATED_PAGES {
                return Err("C generated page memory bound exceeded".into());
            }
            self.generated_bytes = next;
            self.pages.insert(reference.sha256.clone(), bytes);
        }
        Ok(reference)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub key: String,
    pub expected_value_sha256: Option<String>,
    pub value: Option<Vec<u8>>,
}
impl Edit {
    fn validate(&self) -> Result<()> {
        hash(&self.key)?;
        if let Some(value) = &self.expected_value_sha256 {
            hash(value)?;
        }
        if self
            .value
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > MAX_VALUE_BYTES)
            || self.value.is_none() && self.expected_value_sha256.is_none()
        {
            return Err("C map exact edit invalid".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub root: Root,
    pub key: String,
    pub pages: Vec<Vec<u8>>,
}
impl Proof {
    pub fn verify_data(&self, expected: &Root) -> Result<Option<Vec<u8>>> {
        expected.validate()?;
        hash(&self.key)?;
        if self.root != *expected || self.pages.len() > usize::from(MAX_HEIGHT) + 1 {
            return Err("C proof root/path differs".into());
        }
        let mut next = expected.page.clone();
        let mut index = 0;
        while let Some(reference) = next {
            let page = Page::decode(
                self.pages.get(index).ok_or("C proof page missing")?,
                expected,
                &reference,
            )?;
            index += 1;
            match page.body {
                Body::Leaf { entries } => {
                    if index != self.pages.len() {
                        return Err("C proof has trailing pages".into());
                    }
                    return Ok(entries
                        .into_iter()
                        .find(|e| e.key == self.key)
                        .map(|e| e.value));
                }
                Body::Branch { children } => {
                    next = children
                        .into_iter()
                        .find(|r| r.first_key <= self.key && self.key <= r.last_key)
                }
            }
        }
        if index != self.pages.len() {
            return Err("C absence proof has trailing pages".into());
        }
        Ok(None)
    }
}
fn check_root(root: &Root, context: &Context) -> Result<()> {
    root.validate()?;
    context.validate()?;
    if root.binding != context.binding {
        return Err("C map belongs to another independent authority".into());
    }
    Ok(())
}
fn get<I: CustodyIo>(
    root: &Root,
    key: &str,
    session: &mut Session<'_, I>,
) -> Result<Option<Vec<u8>>> {
    let mut next = root.page.clone();
    let mut depth = 0;
    while let Some(reference) = next {
        depth += 1;
        if depth > usize::from(MAX_HEIGHT) + 1 {
            return Err("C map path exceeded".into());
        }
        let page = Page::decode(&session.read(&reference)?, root, &reference)?;
        match page.body {
            Body::Leaf { entries } => {
                return Ok(entries.into_iter().find(|e| e.key == key).map(|e| e.value))
            }
            Body::Branch { children } => {
                next = children
                    .into_iter()
                    .find(|p| p.first_key.as_str() <= key && key <= p.last_key.as_str())
            }
        }
    }
    Ok(None)
}
pub fn lookup(
    root: &Root,
    key: &str,
    context: &Context,
    budget: Budget,
    io: &mut impl CustodyIo,
) -> Result<Proof> {
    check_root(root, context)?;
    hash(key)?;
    let mut session = Session::new(io, context, budget, false)?;
    let mut pages = Vec::new();
    let mut next = root.page.clone();
    while let Some(reference) = next {
        let bytes = session.read(&reference)?;
        let page = Page::decode(&bytes, root, &reference)?;
        next = match page.body {
            Body::Leaf { .. } => None,
            Body::Branch { children } => children
                .into_iter()
                .find(|p| p.first_key.as_str() <= key && key <= p.last_key.as_str()),
        };
        pages.push(bytes);
        if pages.len() > usize::from(MAX_HEIGHT) + 1 {
            return Err("C map lookup path exceeded".into());
        }
    }
    let proof = Proof {
        root: root.clone(),
        key: key.into(),
        pages,
    };
    proof.verify_data(root)?;
    session.check()?;
    Ok(proof)
}
fn update_page<I: CustodyIo>(
    root: &Root,
    reference: &PageRef,
    edit: &Edit,
    session: &mut Session<'_, I>,
) -> Result<Vec<PageRef>> {
    let page = Page::decode(&session.read(reference)?, root, reference)?;
    match page.body {
        Body::Leaf { mut entries } => {
            match entries.binary_search_by(|v| v.key.cmp(&edit.key)) {
                Ok(index) => match &edit.value {
                    Some(value) => entries[index].value = value.clone(),
                    None => {
                        entries.remove(index);
                    }
                },
                Err(index) => entries.insert(
                    index,
                    Entry {
                        key: edit.key.clone(),
                        value: edit.value.clone().ok_or("C delete lost exact base")?,
                    },
                ),
            }
            let mut output = Vec::new();
            let mut packed = Vec::new();
            for entry in entries {
                packed.push(entry);
                if packed.len() > LEAF
                    || serde_json::to_vec(&Page::new(
                        root,
                        Body::Leaf {
                            entries: packed.clone(),
                        },
                    ))?
                    .len()
                        > MAX_PAGE_BYTES
                {
                    let tail = packed.pop().ok_or("C packing empty")?;
                    if packed.is_empty() {
                        return Err("C value cannot fit bounded page".into());
                    }
                    output.push(session.put(
                        root,
                        Body::Leaf {
                            entries: std::mem::take(&mut packed),
                        },
                    )?);
                    packed.push(tail);
                }
            }
            if !packed.is_empty() {
                output.push(session.put(root, Body::Leaf { entries: packed })?);
            }
            Ok(output)
        }
        Body::Branch { mut children } => {
            let index = children
                .iter()
                .position(|p| p.last_key >= edit.key)
                .unwrap_or(children.len() - 1);
            let replacement = update_page(root, &children[index], edit, session)?;
            children.splice(index..index + 1, replacement);
            let mut output = Vec::new();
            for chunk in children.chunks(FANOUT) {
                output.push(session.put(
                    root,
                    Body::Branch {
                        children: chunk.to_vec(),
                    },
                )?);
            }
            Ok(output)
        }
    }
}
fn edit<I: CustodyIo>(
    base: &Root,
    edits: &[Edit],
    context: &Context,
    budget: Budget,
    io: &mut I,
    persist: bool,
) -> Result<Root> {
    check_root(base, context)?;
    if edits.is_empty() || edits.len() > MAX_EDITS {
        return Err("C map delta count invalid".into());
    }
    let mut session = Session::new(io, context, budget, persist)?;
    let mut previous: Option<&str> = None;
    for edit in edits {
        edit.validate()?;
        if previous.is_some_and(|p| p >= edit.key.as_str()) {
            return Err("C edits require sorted unique keys".into());
        }
        previous = Some(&edit.key);
        if get(base, &edit.key, &mut session)?
            .as_ref()
            .map(|v| sha256(v))
            != edit.expected_value_sha256
        {
            return Err("C map exact value CAS conflict".into());
        }
    }
    let mut root = base.clone();
    for edit in edits {
        session.check()?;
        let nodes = match &root.page {
            Some(reference) => update_page(&root, reference, edit, &mut session)?,
            None => vec![session.put(
                &root,
                Body::Leaf {
                    entries: vec![Entry {
                        key: edit.key.clone(),
                        value: edit.value.clone().ok_or("C empty map delete")?,
                    }],
                },
            )?],
        };
        root.page = match nodes.len() {
            0 => None,
            1 => Some(nodes[0].clone()),
            _ => Some(session.put(&root, Body::Branch { children: nodes })?),
        };
        root.entry_count = root.page.as_ref().map_or(0, |p| p.entry_count);
        root.validate()?;
    }
    session.check()?;
    Ok(root)
}
/// Writes immutable unselected pages under an exact current C callback.
pub fn prepare_update(
    base: &Root,
    edits: &[Edit],
    context: &Context,
    budget: Budget,
    io: &mut impl CustodyIo,
) -> Result<Root> {
    edit(base, edits, context, budget, io, true)
}
/// Replays the SAME deterministic CAS algorithm without filesystem writes;
/// unchanged child hashes are retained, so deletion of old unrelated keys fails.
pub fn verify_update(
    base: &Root,
    expected: &Root,
    edits: &[Edit],
    context: &Context,
    budget: Budget,
    io: &mut impl CustodyIo,
) -> Result<()> {
    check_root(expected, context)?;
    let actual = edit(base, edits, context, budget, io, false)?;
    if actual != *expected {
        return Err("C candidate map does not equal exact closed delta".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Memory {
        pages: BTreeMap<String, Vec<u8>>,
        checks: usize,
        fail_at: Option<usize>,
        reads: usize,
        writes: usize,
    }
    impl CustodyIo for Memory {
        fn admit(&mut self, _: &Context, _: Budget) -> Result<()> {
            Ok(())
        }
        fn check_current(&mut self, _: &Context) -> Result<()> {
            self.checks += 1;
            if self.fail_at == Some(self.checks) {
                Err("fixture C revoked".into())
            } else {
                Ok(())
            }
        }
        fn read_page(&mut self, _: &Context, hash: &str, _: usize) -> Result<Vec<u8>> {
            self.reads += 1;
            self.pages
                .get(hash)
                .cloned()
                .ok_or_else(|| "fixture missing page".into())
        }
        fn write_page(&mut self, _: &Context, bytes: &[u8]) -> Result<()> {
            self.writes += 1;
            self.pages.insert(sha256(bytes), bytes.to_vec());
            Ok(())
        }
    }
    fn fixture() -> (Root, Context, Memory) {
        let binding = CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "22".repeat(32),
        };
        (
            Root::empty_data(&binding, Kind::OwnerStates).unwrap(),
            Context {
                binding,
                selected_descriptor_sha256: "33".repeat(32),
                selected_nv_head: "44".repeat(32),
                review_sha256: Some("55".repeat(32)),
            },
            Memory::default(),
        )
    }
    fn budget(write: bool) -> Budget {
        Budget {
            read_bytes: 32 * 1024 * 1024,
            write_bytes: if write { 8 * 1024 * 1024 } else { 0 },
            new_files: if write { 4096 } else { 0 },
        }
    }
    fn edits(root: &Root, n: usize) -> Vec<Edit> {
        let mut values = (0..n)
            .map(|i| Edit {
                key: root.key(format!("owner-{i}").as_bytes()).unwrap(),
                expected_value_sha256: None,
                value: Some(format!("literal-{i}").into_bytes()),
            })
            .collect::<Vec<_>>();
        values.sort_by(|a, b| a.key.cmp(&b.key));
        values
    }
    #[test]
    fn c_binding_and_kind_cannot_be_replaced_by_owner_or_other_custody() {
        let (root, context, _) = fixture();
        let mut other = root.clone();
        other.kind = Kind::Recipients;
        assert_ne!(other.sha256().unwrap(), root.sha256().unwrap());
        assert_ne!(other.key(b"same").unwrap(), root.key(b"same").unwrap());
        other.binding.sealed_genesis_sha256 = "66".repeat(32);
        assert!(check_root(&other, &context).is_err());
        let mut value = serde_json::to_value(&root).unwrap();
        value["binding"] = serde_json::json!({"installation":"11".repeat(32),"owner":"22".repeat(32),"owner_generation":1});
        assert!(serde_json::from_value::<Root>(value).is_err());
    }
    #[test]
    fn actual_page_cas_lookup_absence_and_readonly_delta_preserve_every_old_key() {
        let (root, context, mut io) = fixture();
        let first = edits(&root, 48);
        let next = prepare_update(&root, &first, &context, budget(true), &mut io).unwrap();
        let writes = io.writes;
        verify_update(&root, &next, &first, &context, budget(false), &mut io).unwrap();
        assert_eq!(io.writes, writes);
        for e in &first {
            assert_eq!(
                lookup(&next, &e.key, &context, budget(false), &mut io)
                    .unwrap()
                    .verify_data(&next)
                    .unwrap(),
                e.value
            );
        }
        let missing = next.key(b"not present").unwrap();
        assert_eq!(
            lookup(&next, &missing, &context, budget(false), &mut io)
                .unwrap()
                .verify_data(&next)
                .unwrap(),
            None
        );
        let mut delta = vec![Edit {
            key: first[0].key.clone(),
            expected_value_sha256: Some(sha256(first[0].value.as_ref().unwrap())),
            value: Some(b"changed".to_vec()),
        }];
        let result = prepare_update(&next, &delta, &context, budget(true), &mut io).unwrap();
        delta.push(Edit {
            key: first[1].key.clone(),
            expected_value_sha256: Some(sha256(first[1].value.as_ref().unwrap())),
            value: None,
        });
        assert!(verify_update(&next, &result, &delta, &context, budget(false), &mut io).is_err());
    }
    #[test]
    fn revoked_c_and_exhausted_read_budget_refuse_before_read_or_write() {
        let (root, context, mut io) = fixture();
        let next =
            prepare_update(&root, &edits(&root, 1), &context, budget(true), &mut io).unwrap();
        let reads = io.reads;
        let tiny = Budget {
            read_bytes: 1,
            write_bytes: 0,
            new_files: 0,
        };
        assert!(lookup(
            &next,
            &next.key(b"owner-0").unwrap(),
            &context,
            tiny,
            &mut io
        )
        .is_err());
        assert_eq!(io.reads, reads);
        io.fail_at = Some(io.checks + 2);
        let writes = io.writes;
        assert!(prepare_update(&next, &edits(&next, 2), &context, budget(true), &mut io).is_err());
        assert_eq!(io.writes, writes);
    }
    #[test]
    fn wrong_hash_kind_missing_or_trailing_proof_pages_fail_closed() {
        let (root, context, mut io) = fixture();
        let next =
            prepare_update(&root, &edits(&root, 20), &context, budget(true), &mut io).unwrap();
        let key = next.key(b"owner-0").unwrap();
        let proof = lookup(&next, &key, &context, budget(false), &mut io).unwrap();
        let mut bad = proof.clone();
        bad.pages.push(b"{}".to_vec());
        assert!(bad.verify_data(&next).is_err());
        let mut bad = proof.clone();
        bad.pages.pop();
        assert!(bad.verify_data(&next).is_err());
        let mut bad = proof;
        bad.pages[0][0] = b' ';
        assert!(bad.verify_data(&next).is_err());
        let mut other = next;
        other.kind = Kind::Signers;
        assert!(lookup(&other, &key, &context, budget(false), &mut io).is_err());
    }
    #[test]
    fn empty_is_data_only_and_no_review_cannot_persist() {
        let (root, mut context, mut io) = fixture();
        let bytes = root.canonical_bytes().unwrap();
        assert_eq!(Root::parse(&bytes).unwrap(), root);
        context.review_sha256 = None;
        assert!(prepare_update(&root, &edits(&root, 1), &context, budget(true), &mut io).is_err());
        assert_eq!(io.writes, 0);
        let mut bad = bytes;
        bad.push(b'\n');
        assert!(Root::parse(&bad).is_err());
    }
    #[test]
    fn decimal_expanded_maximum_values_split_by_bytes_and_keep_unmodified_children() {
        let (root, context, mut io) = fixture();
        let mut entries = edits(&root, 24);
        for entry in &mut entries {
            entry.value = Some(vec![255; MAX_VALUE_BYTES]);
        }
        let next = prepare_update(&root, &entries, &context, budget(true), &mut io).unwrap();
        assert!(next.page.as_ref().unwrap().height > 0);
        assert!(io.pages.values().all(|bytes| bytes.len() <= MAX_PAGE_BYTES));
        verify_update(&root, &next, &entries, &context, budget(false), &mut io).unwrap();
        let untouched = lookup(&next, &entries[23].key, &context, budget(false), &mut io).unwrap();
        let mut delta = vec![
            Edit {
                key: entries[0].key.clone(),
                expected_value_sha256: Some(sha256(entries[0].value.as_ref().unwrap())),
                value: Some(vec![254; MAX_VALUE_BYTES]),
            },
            Edit {
                key: entries[1].key.clone(),
                expected_value_sha256: Some(sha256(entries[1].value.as_ref().unwrap())),
                value: None,
            },
        ];
        delta.sort_by(|a, b| a.key.cmp(&b.key));
        let changed = prepare_update(&next, &delta, &context, budget(true), &mut io).unwrap();
        verify_update(&next, &changed, &delta, &context, budget(false), &mut io).unwrap();
        let still = lookup(&changed, &entries[23].key, &context, budget(false), &mut io).unwrap();
        assert_eq!(untouched.pages.last(), still.pages.last());
        assert_eq!(still.verify_data(&changed).unwrap(), entries[23].value);
        assert_eq!(changed.entry_count, 23);
    }
    #[test]
    fn write_budget_is_debited_before_effect_and_context_substitution_fails_before_io() {
        let (root, context, mut io) = fixture();
        let mut values = edits(&root, 1);
        values[0].value = Some(vec![255; MAX_VALUE_BYTES]);
        let tiny = Budget {
            read_bytes: 32768,
            write_bytes: 1,
            new_files: 1,
        };
        assert!(prepare_update(&root, &values, &context, tiny, &mut io).is_err());
        assert_eq!(io.writes, 0);
        let mut other = context.clone();
        other.binding.installation = "aa".repeat(32);
        let checks = io.checks;
        assert!(prepare_update(&root, &values, &other, budget(true), &mut io).is_err());
        assert_eq!(io.checks, checks);
        struct Selected {
            inner: Memory,
            selected: Context,
        }
        impl CustodyIo for Selected {
            fn admit(&mut self, c: &Context, _: Budget) -> Result<()> {
                self.check_current(c)
            }
            fn check_current(&mut self, c: &Context) -> Result<()> {
                if c != &self.selected {
                    return Err("fixture current C selection changed".into());
                }
                self.inner.check_current(c)
            }
            fn read_page(&mut self, c: &Context, h: &str, n: usize) -> Result<Vec<u8>> {
                self.check_current(c)?;
                self.inner.read_page(c, h, n)
            }
            fn write_page(&mut self, c: &Context, b: &[u8]) -> Result<()> {
                self.check_current(c)?;
                self.inner.write_page(c, b)
            }
        }
        let mut selected = Selected {
            inner: io,
            selected: context.clone(),
        };
        let mut changed = context.clone();
        changed.selected_nv_head = "bb".repeat(32);
        assert!(prepare_update(&root, &values, &changed, budget(true), &mut selected).is_err());
        assert_eq!(selected.inner.writes, 0);
    }
}
