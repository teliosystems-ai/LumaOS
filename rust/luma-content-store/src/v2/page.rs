use super::*;

pub(super) const LEAF: usize = 8;
pub(super) const FANOUT: usize = 32;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MapKind {
    Artifacts,
    History,
    Requests,
    Collections,
    Lifecycle,
    Segments,
    Pending,
    Retained,
    Corpus,
    SegmentMembers,
    RestoreMappings,
    RestoreSourceLifecycle,
    IndexTermBuckets,
    IndexTerms,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageRef {
    pub sha256: String,
    pub first_key: String,
    pub last_key: String,
    pub entry_count: u64,
    pub height: u8,
}
impl PageRef {
    pub fn validate(&self) -> Result<()> {
        digest(&self.sha256)?;
        digest(&self.first_key)?;
        digest(&self.last_key)?;
        if self.first_key > self.last_key
            || self.entry_count == 0
            || self.entry_count > MAX_MAP_ENTRIES
            || self.height > MAX_MAP_HEIGHT
            || (self.height == 0 && self.entry_count > LEAF as u64)
        {
            return Err("invalid v2 page range/count/height".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub key: String,
    pub value: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Body {
    Leaf { entries: Vec<Entry> },
    Branch { children: Vec<PageRef> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub map_kind: MapKind,
    pub body: Body,
}
impl Page {
    pub fn new(binding: &OwnerBinding, kind: MapKind, body: Body) -> Self {
        Self {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            map_kind: kind,
            body,
        }
    }
    pub fn encode(&self) -> Result<(Vec<u8>, PageRef)> {
        self.binding.validate()?;
        if self.schema_version != 1 || self.domain != DOMAIN {
            return Err("invalid v2 page domain".into());
        }
        let (first, last, count, height) = match &self.body {
            Body::Leaf { entries } => {
                if entries.is_empty() || entries.len() > LEAF {
                    return Err("v2 leaf fanout exceeded".into());
                }
                let mut previous = None;
                for entry in entries {
                    digest(&entry.key)?;
                    if entry.value.is_empty()
                        || entry.value.len() > MAX_VALUE_BYTES
                        || previous.is_some_and(|p: &str| p >= entry.key.as_str())
                    {
                        return Err("invalid v2 leaf value/key order".into());
                    }
                    previous = Some(entry.key.as_str());
                }
                (
                    entries[0].key.clone(),
                    entries.last().unwrap().key.clone(),
                    entries.len() as u64,
                    0,
                )
            }
            Body::Branch { children } => {
                if children.is_empty() || children.len() > FANOUT {
                    return Err("v2 branch fanout exceeded".into());
                }
                let mut previous = None;
                let mut count = 0_u64;
                let height = children[0]
                    .height
                    .checked_add(1)
                    .ok_or("v2 height overflow")?;
                for child in children {
                    child.validate()?;
                    if child.height + 1 != height
                        || previous.is_some_and(|p: &str| p >= child.first_key.as_str())
                    {
                        return Err("v2 branch overlaps or mixes heights".into());
                    }
                    count = count
                        .checked_add(child.entry_count)
                        .ok_or("v2 count overflow")?;
                    previous = Some(child.last_key.as_str());
                }
                (
                    children[0].first_key.clone(),
                    children.last().unwrap().last_key.clone(),
                    count,
                    height,
                )
            }
        };
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PAGE_BYTES {
            return Err("v2 page byte bound exceeded".into());
        }
        let reference = PageRef {
            sha256: luma_content::sha256(&bytes),
            first_key: first,
            last_key: last,
            entry_count: count,
            height,
        };
        reference.validate()?;
        Ok((bytes, reference))
    }
    pub fn decode(
        bytes: &[u8],
        binding: &OwnerBinding,
        kind: MapKind,
        expected: &PageRef,
    ) -> Result<Self> {
        expected.validate()?;
        let page: Self = canonical(bytes, MAX_PAGE_BYTES)?;
        if page.binding != *binding || page.map_kind != kind || page.encode()?.1 != *expected {
            return Err("v2 page owner/range/count/hash commitment mismatch".into());
        }
        Ok(page)
    }
}
