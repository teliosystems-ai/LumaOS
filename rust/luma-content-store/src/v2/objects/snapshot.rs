//! Held, windowed raw content DATA traversal. No selector, import or authority.
use super::*;

type Pin = (u64, u64, u64, i64, i64, i64, i64, u32);
struct Prefix {
    first: String,
    second: String,
    first_pin: Pin,
    second_pin: Pin,
}
struct Active {
    first: File,
    second: File,
    names: Vec<String>,
    next: usize,
}

/// A bounded observation window, not a grant or a whole-backup receipt.
pub struct RawObjectWindow {
    pub visited: u32,
    pub completed: bool,
}
pub struct RawObjectScan<'a> {
    store: &'a ObjectStore,
    root_pin: Pin,
    objects_pin: Pin,
    first_prefixes: Vec<(String, Pin)>,
    prefixes: Vec<Prefix>,
    next_prefix: usize,
    active: Option<Active>,
    inventory: PhysicalInventory,
    completed: bool,
    poisoned: bool,
}
impl ObjectStore {
    /// Retain source namespace/prefix identities, never all object contents or
    /// names. New windows retain the same live authority and finite lease; this
    /// context cannot renew them and never creates a backup completion token.
    pub fn begin_raw_snapshot<B: Boundary>(
        &self,
        budget: IoBudget,
        boundary: &mut B,
    ) -> Result<RawObjectScan<'_>> {
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        self.check()?;
        let root_pin = pin(&self.root.metadata()?);
        let objects_pin = pin(&self.objects.metadata()?);
        let mut inventory = PhysicalInventory::default();
        for file in [&self.root, &self.objects] {
            charge_dir(file, &mut inventory)?;
        }
        let identity = self.identity.metadata()?;
        inventory.regular_files = 1;
        inventory.logical_bytes = identity.len();
        inventory.allocated_bytes = inventory
            .allocated_bytes
            .checked_add(identity.blocks() * 512)
            .ok_or("snapshot identity allocation overflow")?;
        let mut prefixes = Vec::new();
        let mut first_prefixes = Vec::new();
        for first in canonical_names(&self.objects, 256, &mut guard)? {
            prefix(&first)?;
            self.check()?;
            let a = crate::storage::directory(&self.objects, &first)?;
            if mount(&a)? != self.mount_id {
                return Err("snapshot prefix mount changed".into());
            }
            let first_pin = pin(&a.metadata()?);
            charge_dir(&a, &mut inventory)?;
            first_prefixes.push((first.clone(), first_pin));
            for second in canonical_names(&a, 256, &mut guard)? {
                prefix(&second)?;
                guard.check()?;
                let b = crate::storage::directory(&a, &second)?;
                if mount(&b)? != self.mount_id {
                    return Err("snapshot leaf mount changed".into());
                }
                let second_pin = pin(&b.metadata()?);
                charge_dir(&b, &mut inventory)?;
                if prefixes.len() >= 65536 {
                    return Err("snapshot prefix descriptor bound exhausted".into());
                }
                guard.read(256)?;
                prefixes.push(Prefix {
                    first: first.clone(),
                    second,
                    first_pin,
                    second_pin,
                });
            }
            if first_pin != pin(&a.metadata()?) {
                return Err("snapshot prefix changed during enumeration".into());
            }
        }
        if root_pin != pin(&self.root.metadata()?)
            || objects_pin != pin(&self.objects.metadata()?)
        {
            return Err("snapshot namespace changed during enumeration".into());
        }
        self.check()?;
        guard.check()?;
        Ok(RawObjectScan {
            store: self,
            root_pin,
            objects_pin,
            first_prefixes,
            prefixes,
            next_prefix: 0,
            active: None,
            inventory,
            completed: false,
            poisoned: false,
        })
    }
}
impl RawObjectScan<'_> {
    fn current(&self) -> Result<()> {
        self.store.check()?;
        if self.root_pin != pin(&self.store.root.metadata()?)
            || self.objects_pin != pin(&self.store.objects.metadata()?)
        {
            return Err("held raw snapshot namespace changed".into());
        }
        Ok(())
    }
    /// At most 256 bounded objects are read before returning control. Even an
    /// empty leaf is charged and live-checked. A final whole-prefix pin audit is
    /// mandatory before completed=true; caller flags cannot skip that audit.
    pub fn next_window<B: Boundary>(
        &mut self,
        budget: IoBudget,
        maximum_objects: u32,
        boundary: &mut B,
        mut visitor: impl FnMut(&str, Allocation, &[u8], &mut B) -> Result<()>,
    ) -> Result<RawObjectWindow> {
        if maximum_objects == 0 || maximum_objects > 256 || self.completed || self.poisoned {
            return Err("invalid, failed or already completed snapshot window".into());
        }
        self.poisoned = true;
        let mut guard = Guard::new(boundary, &self.store.binding, budget, None)?;
        self.current()?;
        let mut visited = 0;
        while self.next_prefix < self.prefixes.len() {
            guard.check()?;
            self.current()?;
            let prefix = &self.prefixes[self.next_prefix];
            if self.active.is_none() {
                let first = crate::storage::directory(&self.store.objects, &prefix.first)?;
                let second = crate::storage::directory(&first, &prefix.second)?;
                if pin(&first.metadata()?) != prefix.first_pin
                    || pin(&second.metadata()?) != prefix.second_pin
                    || mount(&first)? != self.store.mount_id
                    || mount(&second)? != self.store.mount_id
                {
                    return Err("snapshot private prefix identity changed".into());
                }
                let names = canonical_names(&second, 65536, &mut guard)?;
                self.active = Some(Active {
                    first,
                    second,
                    names,
                    next: 0,
                });
            }
            let active = self.active.as_mut().ok_or("snapshot active leaf absent")?;
            if pin(&active.first.metadata()?) != prefix.first_pin
                || pin(&active.second.metadata()?) != prefix.second_pin
            {
                return Err("snapshot active leaf changed".into());
            }
            while active.next < active.names.len() && visited < maximum_objects {
                guard.check()?;
                self.store.check()?;
                let name = &active.names[active.next];
                digest(name)?;
                if name[..2] != prefix.first || name[2..4] != prefix.second {
                    return Err("snapshot object hash is misplaced".into());
                }
                let observed = read_member_observed(
                    &active.second,
                    name,
                    MAX_PAGE_BYTES,
                    self.store.mount_id,
                    &mut guard,
                    || {
                        self.store.check()?;
                        if !same(
                            &active.first,
                            &crate::storage::directory(&self.store.objects, &prefix.first)?,
                        )? || !same(
                            &active.second,
                            &crate::storage::directory(&active.first, &prefix.second)?,
                        )? || pin(&active.first.metadata()?) != prefix.first_pin
                            || pin(&active.second.metadata()?) != prefix.second_pin
                        {
                            return Err("snapshot object namespace moved".into());
                        }
                        Ok(())
                    },
                )?;
                let bytes = &observed.bytes;
                let metadata = &observed.before;
                let complete = !bytes.is_empty() && luma_content::sha256(&bytes) == *name;
                let allocation = Allocation {
                    relative_path: format!("objects/{}/{}/{name}", prefix.first, prefix.second),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    bytes: metadata.len(),
                    allocated_bytes: metadata.blocks() * 512,
                    complete,
                };
                self.inventory.regular_files = self
                    .inventory
                    .regular_files
                    .checked_add(1)
                    .ok_or("snapshot inode overflow")?;
                if self.inventory.regular_files > MAX_OBJECTS {
                    return Err("snapshot physical object ceiling exhausted".into());
                }
                self.inventory.logical_bytes = self
                    .inventory
                    .logical_bytes
                    .checked_add(metadata.len())
                    .ok_or("snapshot logical byte overflow")?;
                self.inventory.allocated_bytes = self
                    .inventory
                    .allocated_bytes
                    .checked_add(allocation.allocated_bytes)
                    .ok_or("snapshot allocation overflow")?;
                if !complete {
                    self.inventory.incomplete_objects += 1;
                }
                visitor(name, allocation, bytes, guard.boundary)?;
                guard.check()?;
                observed.recheck(&active.second, name, self.store.mount_id)?;
                guard.check()?;
                active.next += 1;
                visited += 1;
            }
            if pin(&active.first.metadata()?) != prefix.first_pin
                || pin(&active.second.metadata()?) != prefix.second_pin
            {
                return Err("snapshot leaf changed while reading window".into());
            }
            if active.next == active.names.len() {
                self.active = None;
                self.next_prefix += 1;
            }
            if visited == maximum_objects {
                break;
            }
        }
        if self.next_prefix == self.prefixes.len() {
            for (name, expected) in &self.first_prefixes {
                guard.check()?;
                guard.read(256)?;
                self.current()?;
                let directory = crate::storage::directory(&self.store.objects, name)?;
                if pin(&directory.metadata()?) != *expected
                    || mount(&directory)? != self.store.mount_id
                {
                    return Err("snapshot first-prefix completion audit changed".into());
                }
            }
            for prefix in &self.prefixes {
                guard.check()?;
                guard.read(256)?;
                self.current()?;
                let first = crate::storage::directory(&self.store.objects, &prefix.first)?;
                let second = crate::storage::directory(&first, &prefix.second)?;
                if pin(&first.metadata()?) != prefix.first_pin
                    || pin(&second.metadata()?) != prefix.second_pin
                    || mount(&first)? != self.store.mount_id
                    || mount(&second)? != self.store.mount_id
                {
                    return Err("snapshot whole-prefix completion audit changed".into());
                }
            }
            self.current()?;
            guard.check()?;
            self.completed = true;
        }
        self.poisoned = false;
        Ok(RawObjectWindow {
            visited,
            completed: self.completed,
        })
    }
    pub fn completed_inventory(&self) -> Result<&PhysicalInventory> {
        if !self.completed {
            return Err("partial raw snapshot has no whole inventory".into());
        }
        Ok(&self.inventory)
    }
}
fn canonical_names<B: Boundary>(
    directory: &File,
    maximum: usize,
    guard: &mut Guard<'_, B>,
) -> Result<Vec<String>> {
    held_names(directory, maximum, guard)
}
