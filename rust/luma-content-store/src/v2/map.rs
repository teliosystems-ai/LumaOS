use super::page::{Body, Entry, Page, FANOUT, LEAF};
use super::*;
use std::collections::BTreeMap;

// At most two new pages per visited level and delta. Read-only reconstruction
// retains only this finite set; it never scans/materializes the old map.
const MAX_GENERATED_PAGES: usize = MAX_MAP_EDITS * (MAX_MAP_HEIGHT as usize + 2) * 2;
const MAX_GENERATED_BYTES: usize = 96 * 1024 * 1024;
struct PageSession {
    persist: bool,
    pages: BTreeMap<String, Vec<u8>>,
    bytes: usize,
}
impl PageSession {
    fn new(persist: bool) -> Self {
        Self {
            persist,
            pages: BTreeMap::new(),
            bytes: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapRoot {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub kind: MapKind,
    pub page: Option<PageRef>,
    pub entry_count: u64,
}
impl MapRoot {
    /// Pure empty data; never permission to initialize/adopt an owner namespace.
    pub fn empty(binding: &OwnerBinding, kind: MapKind) -> Result<Self> {
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
        if self.schema_version != 1 || self.domain != DOMAIN || self.entry_count > MAX_MAP_ENTRIES {
            return Err("invalid v2 map domain/count".into());
        }
        match &self.page {
            None if self.entry_count == 0 => Ok(()),
            Some(page) if self.entry_count > 0 => {
                page.validate()?;
                if page.entry_count != self.entry_count {
                    return Err("v2 map root count mismatch".into());
                }
                Ok(())
            }
            _ => Err("v2 empty map/page mismatch".into()),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 4096)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    /// Hashes bounded literal key bytes with owner and map-kind separation.
    pub fn key(&self, bytes: &[u8]) -> Result<String> {
        self.validate()?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("v2 key preimage bound exceeded".into());
        }
        Ok(luma_content::sha256(&serde_json::to_vec(&(
            "luma-v2-map-key-v1",
            &self.binding,
            self.kind,
            bytes,
        ))?))
    }
    pub fn corpus_key(&self, artifact_id: &str) -> Result<String> {
        if self.kind != MapKind::Corpus {
            return Err("corpus key requires the exact corpus map kind".into());
        }
        identifier(artifact_id)?;
        self.key(artifact_id.as_bytes())
    }
}

/// Exact value CAS. None expected means absent; None value means remove an
/// existing entry. Values are data; their schema is validated by the owner map.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapEdit {
    pub key: String,
    pub expected_value_sha256: Option<String>,
    pub value: Option<Vec<u8>>,
}
impl MapEdit {
    fn validate(&self) -> Result<()> {
        digest(&self.key)?;
        if let Some(expected) = &self.expected_value_sha256 {
            digest(expected)?;
        }
        if self
            .value
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > MAX_VALUE_BYTES)
            || (self.value.is_none() && self.expected_value_sha256.is_none())
        {
            return Err("invalid bounded exact v2 map edit".into());
        }
        Ok(())
    }
}

/// A bounded membership/absence proof is descriptive bytes, not a current Read
/// authorization. The caller supplies the independently selected exact root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LookupProof {
    pub root: MapRoot,
    pub key: String,
    pub pages: Vec<Vec<u8>>,
}
impl LookupProof {
    pub fn verify(&self, expected: &MapRoot) -> Result<Option<Vec<u8>>> {
        expected.validate()?;
        digest(&self.key)?;
        if self.root != *expected || self.pages.len() > usize::from(MAX_MAP_HEIGHT) + 1 {
            return Err("v2 proof root/depth mismatch".into());
        }
        let mut next = expected.page.clone();
        let mut index = 0;
        while let Some(reference) = next {
            let bytes = self.pages.get(index).ok_or("v2 proof path missing")?;
            index += 1;
            let page = Page::decode(bytes, &expected.binding, expected.kind, &reference)?;
            match page.body {
                Body::Leaf { entries } => {
                    if index != self.pages.len() {
                        return Err("v2 proof has trailing pages".into());
                    }
                    return Ok(entries
                        .into_iter()
                        .find(|v| v.key == self.key)
                        .map(|v| v.value));
                }
                Body::Branch { children } => {
                    next = children
                        .into_iter()
                        .find(|p| p.first_key <= self.key && self.key <= p.last_key);
                }
            }
        }
        if index != self.pages.len() {
            return Err("v2 absence proof has trailing pages".into());
        }
        Ok(None)
    }
}

impl ObjectStore {
    pub fn lookup_map(
        &self,
        root: &MapRoot,
        key: &str,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<LookupProof> {
        self.check_root(root)?;
        digest(key)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let mut pages = Vec::new();
        let mut next = root.page.clone();
        while let Some(reference) = next {
            let bytes = self.read_object(&reference.sha256, MAX_PAGE_BYTES, &mut guard)?;
            let page = Page::decode(&bytes, &self.binding, root.kind, &reference)?;
            next = match &page.body {
                Body::Leaf { .. } => None,
                Body::Branch { children } => children
                    .iter()
                    .find(|p| p.first_key.as_str() <= key && key <= p.last_key.as_str())
                    .cloned(),
            };
            let leaf = matches!(page.body, Body::Leaf { .. });
            pages.push(bytes);
            if pages.len() > usize::from(MAX_MAP_HEIGHT) + 1 {
                return Err("v2 lookup depth exceeded".into());
            }
            if leaf {
                break;
            }
        }
        let proof = LookupProof {
            root: root.clone(),
            key: key.into(),
            pages,
        };
        proof.verify(root)?;
        guard.check()?;
        Ok(proof)
    }
    /// Full ordered coverage with O(depth*page-size) retained tree memory. Every
    /// entry is checked against the selected page root before the callback.
    pub fn visit_map(
        &self,
        root: &MapRoot,
        budget: IoBudget,
        boundary: &mut impl Boundary,
        mut visitor: impl FnMut(&str, &[u8]) -> Result<()>,
    ) -> Result<u64> {
        self.visit_map_checked(root, budget, boundary, |key, value, _| visitor(key, value))
    }
    pub fn visit_map_checked<B: Boundary>(
        &self,
        root: &MapRoot,
        budget: IoBudget,
        boundary: &mut B,
        mut visitor: impl FnMut(&str, &[u8], &mut B) -> Result<()>,
    ) -> Result<u64> {
        self.check_root(root)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let mut count = 0_u64;
        let mut previous = None;
        if let Some(page) = &root.page {
            self.visit_page(
                root.kind,
                page,
                &mut guard,
                &mut previous,
                &mut count,
                &mut visitor,
            )?;
        }
        if count != root.entry_count {
            return Err("v2 complete map coverage count differs".into());
        }
        guard.check()?;
        Ok(count)
    }
    fn visit_page<B: Boundary>(
        &self,
        kind: MapKind,
        reference: &PageRef,
        guard: &mut Guard<'_, B>,
        previous: &mut Option<String>,
        count: &mut u64,
        visitor: &mut impl FnMut(&str, &[u8], &mut B) -> Result<()>,
    ) -> Result<()> {
        let bytes = self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?;
        let page = Page::decode(&bytes, &self.binding, kind, reference)?;
        match page.body {
            Body::Leaf { entries } => {
                for entry in entries {
                    if previous.as_ref().is_some_and(|p| p >= &entry.key) {
                        return Err("v2 full map repeats/reorders keys".into());
                    }
                    guard.check()?;
                    visitor(&entry.key, &entry.value, &mut *guard.boundary)?;
                    guard.check()?;
                    *count = count.checked_add(1).ok_or("v2 visit count overflow")?;
                    *previous = Some(entry.key);
                }
            }
            Body::Branch { children } => {
                for child in children {
                    self.visit_page(kind, &child, guard, previous, count, visitor)?;
                }
            }
        }
        Ok(())
    }
    /// Writes only immutable unselected objects. A successful return is NOT a
    /// compare-and-publish of C, permission to release charges or an effect receipt.
    pub fn prepare_map(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut impl Boundary,
    ) -> Result<MapRoot> {
        self.check_root(base)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, Some(mutation))?;
        let root = self.edit_map(base, edits, &mut guard)?;
        guard.check()?;
        Ok(root)
    }
    /// Read-only deterministic replay of the SAME bounded map algorithm. The
    /// complete result commits untouched child references as well as each CAS;
    /// it is not a selectable root, publication or independent authorization.
    pub fn preview_map(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<MapRoot> {
        self.check_root(base)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let root = self.edit_map_mode(base, edits, &mut guard, false, false)?;
        guard.check()?;
        Ok(root)
    }
    /// Read-only exact delta reconstruction with physical presence checks for
    /// every generated page, including split siblings containing only old keys.
    /// This DATA verifier neither selects a root nor grants publication rights.
    pub fn verify_map_delta(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<MapRoot> {
        self.check_root(base)?;
        if budget.write_bytes != 0 || budget.new_files != 0 {
            return Err("map delta verification requires a read-only budget".into());
        }
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let root = self.verify_map_inner(base, edits, &mut guard)?;
        guard.check()?;
        Ok(root)
    }
    pub(super) fn check_root(&self, root: &MapRoot) -> Result<()> {
        root.validate()?;
        if root.binding != self.binding {
            return Err("v2 map belongs to another owner generation".into());
        }
        Ok(())
    }
    pub(super) fn get_map<B: Boundary>(
        &self,
        root: &MapRoot,
        key: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<Option<Vec<u8>>> {
        self.check_root(root)?;
        digest(key)?;
        let mut next = root.page.clone();
        let mut depth = 0;
        while let Some(reference) = next {
            depth += 1;
            if depth > usize::from(MAX_MAP_HEIGHT) + 1 {
                return Err("v2 map path depth exceeded".into());
            }
            let bytes = self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?;
            let page = Page::decode(&bytes, &self.binding, root.kind, &reference)?;
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
    pub(super) fn edit_map<B: Boundary>(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        guard: &mut Guard<'_, B>,
    ) -> Result<MapRoot> {
        self.edit_map_mode(base, edits, guard, true, false)
    }
    pub(super) fn preview_map_inner<B: Boundary>(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        guard: &mut Guard<'_, B>,
    ) -> Result<MapRoot> {
        self.edit_map_mode(base, edits, guard, false, false)
    }
    pub(super) fn verify_map_inner<B: Boundary>(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        guard: &mut Guard<'_, B>,
    ) -> Result<MapRoot> {
        self.edit_map_mode(base, edits, guard, false, true)
    }
    fn edit_map_mode<B: Boundary>(
        &self,
        base: &MapRoot,
        edits: &[MapEdit],
        guard: &mut Guard<'_, B>,
        persist: bool,
        require_present: bool,
    ) -> Result<MapRoot> {
        self.check_root(base)?;
        if edits.is_empty() || edits.len() > MAX_MAP_EDITS {
            return Err("v2 map delta count invalid".into());
        }
        let mut previous = None;
        for edit in edits {
            edit.validate()?;
            if previous.is_some_and(|p: &str| p >= edit.key.as_str()) {
                return Err("v2 map delta must be sorted unique keys".into());
            }
            previous = Some(edit.key.as_str());
            let observed = self.get_map(base, &edit.key, guard)?;
            if observed.as_ref().map(|v| luma_content::sha256(v)) != edit.expected_value_sha256 {
                return Err("v2 map exact value CAS conflict".into());
            }
        }
        let mut root = base.clone();
        let mut session = PageSession::new(persist);
        for edit in edits {
            guard.check()?;
            let nodes = match &root.page {
                Some(reference) => {
                    self.update_page(root.kind, reference, edit, guard, &mut session)?
                }
                None => {
                    let value = edit.value.as_ref().ok_or("v2 empty map deletion")?;
                    vec![self.put_page(
                        Page::new(
                            &self.binding,
                            root.kind,
                            Body::Leaf {
                                entries: vec![Entry {
                                    key: edit.key.clone(),
                                    value: value.clone(),
                                }],
                            },
                        ),
                        guard,
                        &mut session,
                    )?]
                }
            };
            root.page = match nodes.len() {
                0 => None,
                1 => Some(nodes[0].clone()),
                _ => Some(self.put_page(
                    Page::new(&self.binding, root.kind, Body::Branch { children: nodes }),
                    guard,
                    &mut session,
                )?),
            };
            root.entry_count = root.page.as_ref().map_or(0, |p| p.entry_count);
            root.validate()?;
        }
        if require_present {
            for (hash, bytes) in &session.pages {
                if self.read_object(hash, MAX_PAGE_BYTES, guard)? != *bytes {
                    return Err("v2 derived map page missing or changed before selection".into());
                }
            }
        }
        guard.check()?;
        Ok(root)
    }
    fn put_page<B: Boundary>(
        &self,
        page: Page,
        guard: &mut Guard<'_, B>,
        session: &mut PageSession,
    ) -> Result<PageRef> {
        let (bytes, reference) = page.encode()?;
        guard.check()?;
        if session.persist {
            self.write_object(&bytes, guard)?;
        } else if !session.pages.contains_key(&reference.sha256) {
            if session.pages.len() >= MAX_GENERATED_PAGES
                || session
                    .bytes
                    .checked_add(bytes.len())
                    .map_or(true, |n| n > MAX_GENERATED_BYTES)
            {
                return Err("v2 read-only delta generated-page memory bound exceeded".into());
            }
            session.bytes += bytes.len();
            session.pages.insert(reference.sha256.clone(), bytes);
        }
        Ok(reference)
    }
    fn update_page<B: Boundary>(
        &self,
        kind: MapKind,
        reference: &PageRef,
        edit: &MapEdit,
        guard: &mut Guard<'_, B>,
        session: &mut PageSession,
    ) -> Result<Vec<PageRef>> {
        let bytes = match session.pages.get(&reference.sha256) {
            Some(bytes) => {
                guard.check()?;
                bytes.clone()
            }
            None => self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?,
        };
        let page = Page::decode(&bytes, &self.binding, kind, reference)?;
        match page.body {
            Body::Leaf { mut entries } => {
                match entries.binary_search_by(|v| v.key.cmp(&edit.key)) {
                    Ok(index) => match &edit.value {
                        Some(value) => entries[index].value = value.clone(),
                        None => {
                            entries.remove(index);
                        }
                    },
                    Err(index) => {
                        let value = edit.value.as_ref().ok_or("v2 deletion lost exact base")?;
                        entries.insert(
                            index,
                            Entry {
                                key: edit.key.clone(),
                                value: value.clone(),
                            },
                        );
                    }
                }
                if entries.is_empty() {
                    return Ok(vec![]);
                }
                let mut result = Vec::new();
                let mut packed = Vec::new();
                for entry in entries {
                    packed.push(entry);
                    if packed.len() > LEAF
                        || serde_json::to_vec(&Page::new(
                            &self.binding,
                            kind,
                            Body::Leaf {
                                entries: packed.clone(),
                            },
                        ))?
                        .len()
                            > MAX_PAGE_BYTES
                    {
                        let tail = packed.pop().ok_or("v2 page packing empty")?;
                        if packed.is_empty() {
                            return Err("v2 single value cannot fit bounded page".into());
                        }
                        result.push(self.put_page(
                            Page::new(
                                &self.binding,
                                kind,
                                Body::Leaf {
                                    entries: std::mem::take(&mut packed),
                                },
                            ),
                            guard,
                            session,
                        )?);
                        packed.push(tail);
                    }
                }
                if !packed.is_empty() {
                    result.push(self.put_page(
                        Page::new(&self.binding, kind, Body::Leaf { entries: packed }),
                        guard,
                        session,
                    )?);
                }
                Ok(result)
            }
            Body::Branch { mut children } => {
                let index = children
                    .iter()
                    .position(|p| p.last_key >= edit.key)
                    .unwrap_or(children.len() - 1);
                let replacement = self.update_page(kind, &children[index], edit, guard, session)?;
                children.splice(index..index + 1, replacement);
                let mut result = Vec::new();
                for chunk in children.chunks(FANOUT) {
                    result.push(self.put_page(
                        Page::new(
                            &self.binding,
                            kind,
                            Body::Branch {
                                children: chunk.to_vec(),
                            },
                        ),
                        guard,
                        session,
                    )?);
                }
                Ok(result)
            }
        }
    }
}
