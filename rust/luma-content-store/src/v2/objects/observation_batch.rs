//! Finite prewrite/postwrite observations for EXACT planned objects and touched
//! ancestors. Not a whole-owner inventory, creator attestation, reservation
//! release, selected head or publication permission. The fixed writer, original
//! source/lease, C finite hold and independent whole-phase replay remain needed.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_WRITER_BATCH_OBJECTS: usize = 32;
const MAX_DIRECTORY_NAMES: usize = 256;
const MAX_UNPLANNED_MEMBERS: usize = 128;
const MAX_READ_BYTES: u64 = 32 * 1024 * 1024;
const RAW_READ: u64 = 64 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlannedWriterObject {
    pub sha256: String,
    pub bytes: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WriterBatchPlan {
    pub schema_version: u32,
    pub request_sha256: String,
    pub batch: u32,
    pub objects: Vec<PlannedWriterObject>,
}
impl WriterBatchPlan {
    pub fn validate(&self) -> Result<()> {
        digest(&self.request_sha256)?;
        if self.schema_version != 1
            || self.objects.is_empty()
            || self.objects.len() > MAX_WRITER_BATCH_OBJECTS
        {
            return Err("writer batch must contain one to 32 exact objects".into());
        }
        let mut previous: Option<&str> = None;
        for object in &self.objects {
            digest(&object.sha256)?;
            if object.bytes == 0
                || object.bytes > MAX_PAGE_BYTES as u32
                || previous.is_some_and(|old| old >= object.sha256.as_str())
            {
                return Err(
                    "writer batch objects must be sorted unique exact bounded SHA/length pairs"
                        .into(),
                );
            }
            previous = Some(&object.sha256);
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
}
#[derive(Serialize)]
struct DirectoryChange {
    computed_path: String,
    before: Option<ObservedFileData>,
    after: ObservedFileData,
}
#[derive(Serialize)]
struct ObjectChange {
    planned: PlannedWriterObject,
    before: RawObjectObservationData,
    after: RawObjectObservationData,
}
/// Opaque measured SCOPED DATA. Deliberately no Deserialize, public fields,
/// PhysicalInventory conversion or whole-owner/release success constructor.
#[derive(Serialize)]
pub struct ScopedObjectDelta {
    schema_version: u32,
    coverage: &'static str,
    plan_sha256: String,
    writer: WriterObservationData,
    objects: Vec<ObjectChange>,
    ancestors: Vec<DirectoryChange>,
    new_files: u64,
    new_directories: u64,
    logical_bytes: u64,
    allocated_growth_bytes: u64,
    checked_unplanned_existing_members: u32,
    admitted_read_ceiling: u64,
}
impl ScopedObjectDelta {
    pub fn new_file_count(&self) -> u64 {
        self.new_files
    }
    pub fn new_directory_count(&self) -> u64 {
        self.new_directories
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn allocated_growth_bytes(&self) -> u64 {
        self.allocated_growth_bytes
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 256 * 1024 {
            return Err("scoped writer delta exceeds fixed metadata bound".into());
        }
        Ok(bytes)
    }
}
struct DirectorySnapshot {
    object: usize,
    depth: u8,
    data: Option<ObservedFileData>,
    names: Vec<String>,
    unrelated: Vec<(String, RawObjectObservationData)>,
}
struct BatchState<'w> {
    writer: &'w HeldWriterObservation,
    namespace: Arc<NamespaceHeld>,
    plan: WriterBatchPlan,
    before: Vec<HeldRawObjectObservation>,
    directories: BTreeMap<String, DirectorySnapshot>,
    remaining: u64,
    initial_read: u64,
}
pub struct HeldWriterBatch<'w> {
    state: BatchState<'w>,
}
pub struct CompletedWriterBatch<'w> {
    state: BatchState<'w>,
    after: Vec<HeldRawObjectObservation>,
    delta: ScopedObjectDelta,
}
impl CompletedWriterBatch<'_> {
    pub fn scoped_delta(&self) -> &ScopedObjectDelta {
        &self.delta
    }
}
struct Meter<'a, B: Boundary> {
    remaining: &'a mut u64,
    boundary: &'a mut B,
    binding: &'a OwnerBinding,
}
impl<B: Boundary> Meter<'_, B> {
    fn inspect(&mut self) -> Result<()> {
        self.boundary.check(Access::Inspect {
            binding: self.binding,
        })
    }
    fn reserve(&mut self, bytes: u64) -> Result<()> {
        *self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or("writer batch cumulative read reservation exhausted before IO")?;
        Ok(())
    }
    fn raw(
        &mut self,
        store: &ObjectStore,
        ns: &HeldNamespaceObservation,
        sha: &str,
    ) -> Result<HeldRawObjectObservation> {
        self.reserve(RAW_READ)?;
        let (_, held) = store.observe_raw_object(ns, sha, read(RAW_READ), self.boundary)?;
        Ok(held)
    }
    fn recheck(
        &mut self,
        store: &ObjectStore,
        ns: &HeldNamespaceObservation,
        held: &HeldRawObjectObservation,
    ) -> Result<()> {
        self.reserve(RAW_READ)?;
        store.check_raw_object_observation(ns, held, read(RAW_READ), self.boundary)?;
        Ok(())
    }
    fn writer(
        &mut self,
        store: &ObjectStore,
        ns: &HeldNamespaceObservation,
        writer: &HeldWriterObservation,
    ) -> Result<()> {
        self.reserve(RAW_READ)?;
        store.check_existing_writer(ns, writer, read(RAW_READ), self.boundary)
    }
    fn names(&mut self, file: &File, maximum: usize) -> Result<Vec<String>> {
        let bound = (maximum as u64 + 3) * 192;
        let reserved = bound * 2;
        self.reserve(reserved)?;
        let mut guard = Guard::new(self.boundary, self.binding, read(reserved), None)?;
        // Reserve the maximum BEFORE readdir, including dot entries/EOF.
        // The shared iterator's actual-name accounting is additional, bounded.
        guard.read(bound)?;
        let before = ObservedFileData::capture(file)?;
        let names = held_names(file, maximum, &mut guard)?;
        if ObservedFileData::capture(file)? != before {
            return Err("writer directory changed during bounded names read".into());
        }
        guard.check()?;
        Ok(names)
    }
}
fn read(bytes: u64) -> IoBudget {
    IoBudget {
        read_bytes: bytes,
        write_bytes: 0,
        new_files: 0,
    }
}
fn file<'a>(
    ns: &'a HeldNamespaceObservation,
    raw: &'a [HeldRawObjectObservation],
    slot: &DirectorySnapshot,
) -> Option<&'a File> {
    match slot.depth {
        0 => Some(&ns.held.objects),
        1 => raw[slot.object].prefixes.first.as_ref(),
        2 => raw[slot.object].prefixes.second.as_ref(),
        _ => None,
    }
}
fn complete<'a>(
    data: &'a RawObjectObservationData,
    sha: &str,
    expected: Option<u32>,
) -> Result<&'a ObservedFileData> {
    match data {
        RawObjectObservationData::Present {
            object_sha256,
            actual_sha256,
            complete: true,
            file,
            ..
        } if object_sha256 == sha
            && actual_sha256 == sha
            && expected.map_or(true, |n| file.bytes == u64::from(n)) =>
        {
            Ok(file)
        }
        _ => Err("writer planned/existing member is incomplete, mismatched or absent".into()),
    }
}
fn planned_names(
    path: &str,
    old: &[String],
    plan: &WriterBatchPlan,
    before: &BTreeMap<String, DirectorySnapshot>,
    raw: &[HeldRawObjectObservation],
) -> Result<Vec<String>> {
    let mut expected = old.iter().cloned().collect::<BTreeSet<_>>();
    for (number, object) in plan.objects.iter().enumerate() {
        if !matches!(raw[number].data(), RawObjectObservationData::Absent { .. }) {
            continue;
        }
        let first = format!("objects/{}", &object.sha256[..2]);
        let second = format!("{first}/{}", &object.sha256[2..4]);
        if path == "objects" && before.get(&first).is_some_and(|d| d.data.is_none()) {
            expected.insert(object.sha256[..2].to_owned());
        } else if path == first && before.get(&second).is_some_and(|d| d.data.is_none()) {
            expected.insert(object.sha256[2..4].to_owned());
        } else if path == second {
            expected.insert(object.sha256.clone());
        }
    }
    if expected.len() > MAX_DIRECTORY_NAMES {
        return Err("writer batch directory capacity would exceed fixed profile".into());
    }
    Ok(expected.into_iter().collect())
}
fn same_directory_node(before: &ObservedFileData, after: &ObservedFileData) -> bool {
    (
        before.device,
        before.inode,
        before.mount_id,
        before.uid,
        before.gid,
        before.mode,
    ) == (
        after.device,
        after.inode,
        after.mount_id,
        after.uid,
        after.gid,
        after.mode,
    )
}
fn directory_growth(
    before: Option<&ObservedFileData>,
    after: &ObservedFileData,
) -> Result<(u64, u64)> {
    if let Some(before) = before {
        if !same_directory_node(before, after)
            || after.allocated_bytes < before.allocated_bytes
            || after.bytes < before.bytes
        {
            return Err("writer ancestor replaced or shrank".into());
        }
        Ok((0, after.allocated_bytes - before.allocated_bytes))
    } else {
        Ok((1, after.allocated_bytes))
    }
}
impl ObjectStore {
    /// Before EACH batch's actual writes. All actual observations are retained
    /// and the supplied total read ceiling is consumed across finish/rechecks;
    /// it cannot be replenished by passing a new budget to those operations.
    pub fn begin_writer_batch<'w>(
        &self,
        ns: &HeldNamespaceObservation,
        writer: &'w HeldWriterObservation,
        plan: WriterBatchPlan,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<HeldWriterBatch<'w>> {
        budget.validate()?;
        plan.validate()?;
        if budget.write_bytes != 0 || budget.new_files != 0 || budget.read_bytes > MAX_READ_BYTES {
            return Err("writer batch observation requires finite read-only 32 MiB ceiling".into());
        }
        boundary.admit(
            &self.binding,
            ResourceBudget {
                memory_bytes: 192 * 1024 * 1024,
                tasks: 1,
                read_bytes: budget.read_bytes,
                write_bytes: 0,
                additional_storage_bytes: 0,
            },
        )?;
        let mut state = BatchState {
            writer,
            namespace: ns.held.clone(),
            plan,
            before: Vec::new(),
            directories: BTreeMap::new(),
            remaining: budget.read_bytes,
            initial_read: budget.read_bytes,
        };
        let mut meter = Meter {
            remaining: &mut state.remaining,
            boundary,
            binding: &self.binding,
        };
        meter.writer(self, ns, writer)?;
        for object in &state.plan.objects {
            let held = meter.raw(self, ns, &object.sha256)?;
            if matches!(held.data(), RawObjectObservationData::Present { .. }) {
                complete(held.data(), &object.sha256, Some(object.bytes))?;
            }
            state.before.push(held);
        }
        let mut positions = BTreeMap::new();
        positions.insert("objects".to_owned(), (0, 0));
        for (number, object) in state.plan.objects.iter().enumerate() {
            positions
                .entry(format!("objects/{}", &object.sha256[..2]))
                .or_insert((number, 1));
            positions
                .entry(format!(
                    "objects/{}/{}",
                    &object.sha256[..2],
                    &object.sha256[2..4]
                ))
                .or_insert((number, 2));
        }
        let planned = state
            .plan
            .objects
            .iter()
            .map(|o| o.sha256.as_str())
            .collect::<BTreeSet<_>>();
        let mut unplanned = 0;
        for (path, (object, depth)) in positions {
            let mut snapshot = DirectorySnapshot {
                object,
                depth,
                data: None,
                names: Vec::new(),
                unrelated: Vec::new(),
            };
            if let Some(dir) = file(ns, &state.before, &snapshot) {
                let data = ObservedFileData::capture(dir)?;
                let names = meter.names(dir, MAX_DIRECTORY_NAMES)?;
                for name in &names {
                    if depth < 2 {
                        prefix(name)?;
                        meter.inspect()?;
                        let child = crate::storage::directory(dir, name)?;
                        if mount(&child)? != self.mount_id {
                            return Err("writer directory entry crosses held volume".into());
                        }
                        meter.inspect()?;
                    } else {
                        digest(name)?;
                        let expected = format!("objects/{}/{}", &name[..2], &name[2..4]);
                        if expected != path {
                            return Err("writer touched leaf contains misplaced member".into());
                        }
                        if !planned.contains(name.as_str()) {
                            if unplanned == MAX_UNPLANNED_MEMBERS {
                                return Err("writer batch unplanned retained-member coverage exceeds finite profile".into());
                            }
                            unplanned += 1;
                            let observed = meter.raw(self, ns, name)?;
                            complete(observed.data(), name, None)?;
                            snapshot
                                .unrelated
                                .push((name.clone(), observed.data().clone()));
                        }
                    }
                }
                if ObservedFileData::capture(dir)? != data {
                    return Err("writer batch before-directory changed during observation".into());
                }
                snapshot.data = Some(data);
                snapshot.names = names;
            }
            state.directories.insert(path, snapshot);
        }
        for (path, snapshot) in &state.directories {
            planned_names(
                path,
                &snapshot.names,
                &state.plan,
                &state.directories,
                &state.before,
            )?;
        }
        for observed in &state.before {
            meter.recheck(self, ns, observed)?;
        }
        meter.writer(self, ns, writer)?;
        // Refuse BEFORE writes if even an unchanged finish and one fresh
        // post-observation validation cannot fit the original total ceiling.
        let raw_calls = 2 * state.plan.objects.len() as u64
            + state
                .before
                .iter()
                .filter(|raw| matches!(raw.data(), RawObjectObservationData::Present { .. }))
                .count() as u64
            + 2 * unplanned as u64
            + 4;
        let names_reservation =
            state.directories.len() as u64 * 2 * ((MAX_DIRECTORY_NAMES as u64 + 3) * 192 * 2);
        let future = raw_calls
            .checked_mul(RAW_READ)
            .and_then(|n| n.checked_add(names_reservation))
            .ok_or("writer future observation reservation overflow")?;
        if *meter.remaining < future {
            return Err("writer original read ceiling cannot cover complete finish and fresh recheck; no writes admitted".into());
        }
        Ok(HeldWriterBatch { state })
    }
    /// Observe measured results, not permission to publish or release a C hold.
    /// Missing, interrupted, unplanned or changed touched members refuse.
    pub fn finish_writer_batch<'w>(
        &self,
        ns: &HeldNamespaceObservation,
        batch: HeldWriterBatch<'w>,
        boundary: &mut impl Boundary,
    ) -> Result<CompletedWriterBatch<'w>> {
        let mut state = batch.state;
        if !Arc::ptr_eq(&state.namespace, &ns.held) {
            return Err("writer batch namespace/OFD session substituted".into());
        }
        let mut meter = Meter {
            remaining: &mut state.remaining,
            boundary,
            binding: &self.binding,
        };
        meter.writer(self, ns, state.writer)?;
        let mut after = Vec::new();
        let mut objects = Vec::new();
        let (mut new_files, mut new_directories, mut logical_bytes, mut allocated_growth_bytes) =
            (0_u64, 0_u64, 0_u64, 0_u64);
        for (number, object) in state.plan.objects.iter().enumerate() {
            meter.inspect()?;
            before_current(self, ns, &state.before[number])?;
            meter.inspect()?;
            let observed = meter.raw(self, ns, &object.sha256)?;
            let actual = complete(observed.data(), &object.sha256, Some(object.bytes))?;
            match state.before[number].data() {
                RawObjectObservationData::Absent { .. } => {
                    new_files += 1;
                    logical_bytes += actual.bytes;
                    allocated_growth_bytes = allocated_growth_bytes
                        .checked_add(actual.allocated_bytes)
                        .ok_or("writer file allocation overflow")?;
                }
                old @ RawObjectObservationData::Present { .. } => {
                    meter.recheck(self, ns, &state.before[number])?;
                    if observed.data() != old {
                        return Err("reused writer member was replaced/modified".into());
                    }
                }
            }
            objects.push(ObjectChange {
                planned: object.clone(),
                before: state.before[number].data().clone(),
                after: observed.data().clone(),
            });
            after.push(observed);
        }
        let mut ancestors = Vec::new();
        let mut unrelated_count = 0;
        for (path, snapshot) in &state.directories {
            let dir = file(ns, &after, snapshot)
                .ok_or("writer planned prefix directory remains absent")?;
            let current = ObservedFileData::capture(dir)?;
            let (count, growth) = directory_growth(snapshot.data.as_ref(), &current)?;
            new_directories += count;
            allocated_growth_bytes = allocated_growth_bytes
                .checked_add(growth)
                .ok_or("writer directory allocation/growth overflow")?;
            let expected = planned_names(
                path,
                &snapshot.names,
                &state.plan,
                &state.directories,
                &state.before,
            )?;
            if meter.names(dir, MAX_DIRECTORY_NAMES)? != expected {
                return Err("writer touched directory has unplanned added/deleted names".into());
            }
            for (sha, original) in &snapshot.unrelated {
                let observed = meter.raw(self, ns, sha)?;
                complete(observed.data(), sha, None)?;
                if observed.data() != original {
                    return Err("writer changed unrelated retained member".into());
                }
                unrelated_count += 1;
            }
            if ObservedFileData::capture(dir)? != current {
                return Err("writer after-directory changed during observation".into());
            }
            ancestors.push(DirectoryChange {
                computed_path: path.clone(),
                before: snapshot.data.clone(),
                after: current,
            });
        }
        meter.writer(self, ns, state.writer)?;
        let delta = ScopedObjectDelta {
            schema_version: 1,
            coverage: "exact-planned-objects-and-touched-ancestors-not-whole-owner-v1",
            plan_sha256: state.plan.sha256()?,
            writer: state.writer.data().clone(),
            objects,
            ancestors,
            new_files,
            new_directories,
            logical_bytes,
            allocated_growth_bytes,
            checked_unplanned_existing_members: unrelated_count,
            admitted_read_ceiling: state.initial_read,
        };
        delta.canonical_bytes()?;
        Ok(CompletedWriterBatch {
            state,
            after,
            delta,
        })
    }
    pub fn recheck_writer_batch(
        &self,
        ns: &HeldNamespaceObservation,
        completed: &mut CompletedWriterBatch<'_>,
        boundary: &mut impl Boundary,
    ) -> Result<()> {
        let state = &mut completed.state;
        if !Arc::ptr_eq(&state.namespace, &ns.held) {
            return Err("completed writer batch namespace session changed".into());
        }
        let mut meter = Meter {
            remaining: &mut state.remaining,
            boundary,
            binding: &self.binding,
        };
        meter.writer(self, ns, state.writer)?;
        for (old, actual) in state.before.iter().zip(&completed.after) {
            meter.inspect()?;
            before_current(self, ns, old)?;
            meter.inspect()?;
            meter.recheck(self, ns, actual)?;
        }
        for (path, snapshot) in &state.directories {
            let dir =
                file(ns, &completed.after, snapshot).ok_or("completed writer directory absent")?;
            let data = completed
                .delta
                .ancestors
                .iter()
                .find(|d| &d.computed_path == path)
                .ok_or("completed writer directory coverage missing")?;
            if ObservedFileData::capture(dir)? != data.after
                || meter.names(dir, MAX_DIRECTORY_NAMES)?
                    != planned_names(
                        path,
                        &snapshot.names,
                        &state.plan,
                        &state.directories,
                        &state.before,
                    )?
            {
                return Err("completed scoped writer directory data stale".into());
            }
            for (sha, old) in &snapshot.unrelated {
                let actual = meter.raw(self, ns, sha)?;
                complete(actual.data(), sha, None)?;
                if actual.data() != old {
                    return Err("completed writer changed unrelated member".into());
                }
            }
            if ObservedFileData::capture(dir)? != data.after {
                return Err("completed writer directory changed during read".into());
            }
        }
        meter.writer(self, ns, state.writer)
    }
}

#[cfg(test)]
#[path = "observation_batch/tests.rs"]
mod tests;
fn before_current(
    store: &ObjectStore,
    ns: &HeldNamespaceObservation,
    held: &HeldRawObjectObservation,
) -> Result<()> {
    if !Arc::ptr_eq(&held.namespace, &ns.held) {
        return Err("writer preobservation namespace changed".into());
    }
    match held.data() {
        RawObjectObservationData::Absent {
            object_sha256,
            nearest_ancestor,
            ..
        } => {
            held.prefixes.check(store, object_sha256)?;
            nearest_ancestor.same_directory(held.prefixes.parent(ns))
        }
        RawObjectObservationData::Present { object_sha256, .. } => {
            held.prefixes.check(store, object_sha256)
        }
    }
}
