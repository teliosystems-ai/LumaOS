//! Bounded authenticated map traversal. Saved positions are DATA: the exact
//! root, rank and last key are checked again under the original live boundary.
use super::page::{Body, Page};
use super::*;

pub const MAX_WINDOW_ENTRIES: usize = 256;

/// Native callers must independently select this exact current map. A generic
/// owner check alone cannot authenticate an arbitrary caller-supplied root.
pub trait MapCursorBoundary: Boundary {
    fn current_map(&mut self, root: &MapRoot) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapCursor {
    schema_version: u32,
    root_sha256: String,
    after_count: u64,
    after_key: Option<String>,
}

impl MapCursor {
    pub fn beginning(root: &MapRoot) -> Result<Self> {
        root.validate()?;
        Ok(Self {
            schema_version: 1,
            root_sha256: root.sha256()?,
            after_count: 0,
            after_key: None,
        })
    }

    fn validate(&self, root: &MapRoot) -> Result<()> {
        root.validate()?;
        digest(&self.root_sha256)?;
        if let Some(key) = &self.after_key {
            digest(key)?;
        }
        if self.schema_version != 1
            || self.root_sha256 != root.sha256()?
            || self.after_count > root.entry_count
            || (self.after_count == 0) != self.after_key.is_none()
        {
            return Err("map cursor does not bind the exact root and finite position".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self, root: &MapRoot) -> Result<Vec<u8>> {
        self.validate(root)?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_canonical(bytes: &[u8], root: &MapRoot) -> Result<Self> {
        let value: Self = canonical(bytes, 1024)?;
        value.validate(root)?;
        Ok(value)
    }

    pub fn after_count(&self) -> u64 {
        self.after_count
    }
}

/// Returned values remain inert data, not proof that a checkpoint, index,
/// snapshot or workflow has been published. The caller must retain its own
/// independently selected progress and fresh authority across separate windows.
pub struct MapWindow {
    pub entries: Vec<(String, Vec<u8>)>,
    pub next: MapCursor,
    pub complete: bool,
}

struct Current<'a, B: MapCursorBoundary> {
    root: &'a MapRoot,
    boundary: &'a mut B,
}

impl<B: MapCursorBoundary> Boundary for Current<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.boundary.current_map(self.root)?;
        self.boundary.admit(binding, budget)?;
        self.boundary.current_map(self.root)
    }

    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.boundary.current_map(self.root)?;
        self.boundary.check(access)?;
        self.boundary.current_map(self.root)
    }
}

impl ObjectStore {
    /// Read at most 256 values without rescanning earlier leaves. Before any
    /// continuation, an authenticated search path proves that the last key has
    /// exactly the saved rank. A changed root, missing member, substituted rank,
    /// denied boundary or exhausted budget withholds the entire window.
    pub fn scan_map_window<B: MapCursorBoundary>(
        &self,
        root: &MapRoot,
        cursor: &MapCursor,
        maximum: usize,
        budget: IoBudget,
        boundary: &mut B,
    ) -> Result<MapWindow> {
        self.check_root(root)?;
        cursor.validate(root)?;
        if maximum == 0 || maximum > MAX_WINDOW_ENTRIES || budget.write_bytes != 0 {
            return Err("map cursor requires a finite read-only window".into());
        }
        if root.entry_count != 0 && cursor.after_count == root.entry_count {
            return Err("completed map cursor cannot be resumed".into());
        }
        let mut current = Current { root, boundary };
        let mut guard = Guard::new(&mut current, &root.binding, budget, None)?;
        if let Some(key) = &cursor.after_key {
            let reference = root.page.as_ref().ok_or("cursor key has no root page")?;
            let rank = self.cursor_rank(root, reference, key, &mut guard)?;
            if rank.checked_add(1) != Some(cursor.after_count) {
                return Err("map cursor last key does not have its declared exact rank".into());
            }
        }
        let count = (root.entry_count - cursor.after_count).min(maximum as u64);
        let mut entries = Vec::with_capacity(count as usize);
        if let Some(reference) = &root.page {
            self.cursor_range(
                root,
                reference,
                0,
                cursor.after_count..cursor.after_count + count,
                &mut entries,
                &mut guard,
            )?;
        }
        if entries.len() as u64 != count
            || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || cursor
                .after_key
                .as_ref()
                .is_some_and(|key| entries.first().is_some_and(|entry| entry.0 <= *key))
        {
            return Err("authenticated map window lost, repeated or reordered coverage".into());
        }
        let after_count = cursor
            .after_count
            .checked_add(count)
            .ok_or("cursor count overflow")?;
        let next = MapCursor {
            schema_version: 1,
            root_sha256: cursor.root_sha256.clone(),
            after_count,
            after_key: entries
                .last()
                .map(|entry| entry.0.clone())
                .or_else(|| cursor.after_key.clone()),
        };
        next.validate(root)?;
        guard.check()?;
        Ok(MapWindow {
            entries,
            next,
            complete: after_count == root.entry_count,
        })
    }

    fn cursor_rank<B: Boundary>(
        &self,
        root: &MapRoot,
        reference: &PageRef,
        key: &str,
        guard: &mut Guard<'_, B>,
    ) -> Result<u64> {
        let bytes = self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?;
        let page = Page::decode(&bytes, &root.binding, root.kind, reference)?;
        match page.body {
            Body::Leaf { entries } => entries
                .iter()
                .position(|entry| entry.key == key)
                .map(|rank| rank as u64)
                .ok_or_else(|| "cursor last key is absent from selected map".into()),
            Body::Branch { children } => {
                let mut before = 0_u64;
                for child in children {
                    guard.check()?;
                    if child.first_key.as_str() <= key && key <= child.last_key.as_str() {
                        return before
                            .checked_add(self.cursor_rank(root, &child, key, guard)?)
                            .ok_or_else(|| "cursor rank overflow".into());
                    }
                    before = before
                        .checked_add(child.entry_count)
                        .ok_or("cursor subtree count overflow")?;
                }
                Err("cursor last key lies in no selected subtree".into())
            }
        }
    }

    fn cursor_range<B: Boundary>(
        &self,
        root: &MapRoot,
        reference: &PageRef,
        offset: u64,
        range: std::ops::Range<u64>,
        entries: &mut Vec<(String, Vec<u8>)>,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        guard.check()?;
        let subtree_end = offset
            .checked_add(reference.entry_count)
            .ok_or("cursor subtree range overflow")?;
        if offset >= range.end || subtree_end <= range.start {
            return Ok(());
        }
        let bytes = self.read_object(&reference.sha256, MAX_PAGE_BYTES, guard)?;
        let page = Page::decode(&bytes, &root.binding, root.kind, reference)?;
        match page.body {
            Body::Leaf { entries: rows } => {
                for (position, row) in rows.into_iter().enumerate() {
                    guard.check()?;
                    let ordinal = offset
                        .checked_add(position as u64)
                        .ok_or("cursor leaf position overflow")?;
                    if range.contains(&ordinal) {
                        if entries.len() >= MAX_WINDOW_ENTRIES {
                            return Err("cursor output exceeds finite entry bound".into());
                        }
                        entries.push((row.key, row.value));
                    }
                }
            }
            Body::Branch { children } => {
                let mut next_offset = offset;
                for child in children {
                    self.cursor_range(root, &child, next_offset, range.clone(), entries, guard)?;
                    next_offset = next_offset
                        .checked_add(child.entry_count)
                        .ok_or("cursor child position overflow")?;
                }
            }
        }
        guard.check()
    }
}

#[cfg(test)]
mod tests;
