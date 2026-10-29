//! Exact closed storage planning and the sole worker dispatch. All immutable
//! inode creation, bounded writes and complete readback happen before advance.
//! A failed/unknown dispatch retains every charged allocation and fixed pending
//! frame; there is no reserve-bin release, automatic retry or hash fallback.
use super::super::super::super::super::paged::cells;
use super::super::super::super::parent_allocation::{Delta, Observation, MAX_GROWTH};
use super::super::super::jobs::{self, Disposition, Manifest, Member, Role};
use super::super::super::reader;
use super::*;
use crate::content_checkpoint::PersistentDirectory;
use std::os::unix::fs::MetadataExt;

pub(super) struct Data {
    pub(super) sha256: String,
    pub(super) bytes: Vec<u8>,
    pub(super) kind: slots::Kind,
}
pub(super) struct Plan {
    pub(super) job: String,
    pub(super) source: String,
    pub(super) request: String,
    pub(super) window: String,
    pub(super) specifications: Vec<slots::ExactSlot>,
    pub(super) data: Vec<Data>,
    pub(super) locations: usize,
    pub(super) jobs: usize,
}

struct ReadNodes<'a, 'b, 'c, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    original: &'b mut OriginalCOperation<'c>,
}
impl<A: Checkpoint> locations::Io for ReadNodes<'_, '_, '_, A> {
    fn check(&mut self) -> Result<()> {
        self.backend.live(&mut || self.original.check())
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        let expected = self.backend.nv;
        let anchor = &mut self.backend.anchor;
        let pages = &self.backend.pages;
        let original = &mut self.original;
        let mut check = || -> Result<()> {
            original.check()?;
            pages.check()?;
            if anchor.read()? != expected {
                return Err("actual C changed within worker structural read".into());
            }
            original.check()
        };
        let bytes = slots::Directory::at_reference(pages, &reference.slot, &mut check)?
            .read(reference, &mut check)?;
        check()?;
        drop(check);
        self.check()?;
        Ok(bytes)
    }
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("worker topology review has no physical writer".into())
    }
}
fn source<A: Checkpoint>(
    backend: &mut Backend<A>,
    token: &VerifiedTransition,
    original: &mut OriginalCOperation<'_>,
) -> Result<()> {
    original.check()?;
    backend.live(&mut || original.check())?;
    if token.base != Selector::for_descriptor(&backend.descriptor)?
        || token.base_frame_sha256 != backend.descriptor_frame_sha256
        || token.source_sha256 != hash(&COperation::Worker(original).source_bytes()?)
        || token.request_sha256 != original.source_binding().request_sha256
    {
        return Err(
            "direct worker transition changed its actual original source or selected base".into(),
        );
    }
    original.check()
}
fn admission(specifications: &[slots::ExactSlot]) -> Result<u64> {
    specifications.iter().try_fold(
        3 * 64 * 1024 + slots::PLAN_BYTES as u64 + MAX_GROWTH,
        |total, spec| {
            total
                .checked_add(spec.capacity)
                .and_then(|n| n.checked_add(64 * 1024 + 4096))
                .ok_or_else(|| "worker direct allocation admission overflow".into())
        },
    )
}
fn plan<A: Checkpoint>(
    backend: &mut Backend<A>,
    token: &VerifiedTransition,
    original: &mut OriginalCOperation<'_>,
) -> Result<Plan> {
    source(backend, token, original)?;
    let binding = backend.descriptor.binding.clone();
    let storage = backend.descriptor.storage.clone();
    let planned = layout(
        &binding,
        storage.as_ref(),
        token,
        &mut ReadNodes { backend, original },
    )?;
    source(backend, token, original)?;
    Ok(planned)
}
/// The deterministic exact layout of one verified transition over its base
/// storage. A cold reader recomputes it from the actual selected base alone.
pub(super) fn layout(
    binding: &map::CustodyBinding,
    storage: Option<&StorageSelection>,
    token: &VerifiedTransition,
    io: &mut impl locations::Io,
) -> Result<Plan> {
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-worker-allocation-v4",
        binding,
        &token.base_frame_sha256,
        &token.operation,
        &token.source_sha256,
        &token.request_sha256,
        &token.review_sha256,
    ))?);
    let mut data = Vec::with_capacity(token.records.len() + token.pages.len());
    for (kind, values) in [
        (slots::Kind::Record, &token.records),
        (slots::Kind::Page, &token.pages),
    ] {
        for (sha, bytes) in values {
            let bound = if kind == slots::Kind::Page {
                PAGE_BYTES
            } else {
                super::super::super::super::super::paged::FILE_BYTES
            };
            if bytes.is_empty() || bytes.len() > bound || hash(bytes) != *sha {
                return Err("verified worker semantic bytes exceed their closed data kind".into());
            }
            data.push(Data {
                sha256: sha.clone(),
                bytes: bytes.clone(),
                kind,
            });
        }
    }
    if data.is_empty() || data.len() > 256 {
        return Err(
            "worker direct transition has no semantic bytes or exceeds the exact slot admission"
                .into(),
        );
    }
    let mut keys = data
        .iter()
        .map(|value| value.sha256.clone())
        .collect::<Vec<_>>();
    keys.push(token.base_frame_sha256.clone());
    keys.sort();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("worker semantic/location inputs repeat a complete object digest".into());
    }
    let storage = storage.ok_or("worker base has no selected direct storage")?;
    let location_nodes =
        locations::planning::new_locations(&storage.locations, &keys, io)?.new_nodes;
    let old_jobs = storage
        .jobs
        .as_ref()
        .ok_or("worker base has no selected allocation index")?;
    let job_nodes =
        locations::planning::new_jobs(old_jobs, std::slice::from_ref(&job), io)?.new_nodes;
    let count = data
        .len()
        .checked_add(location_nodes)
        .and_then(|n| n.checked_add(job_nodes))
        .and_then(|n| n.checked_add(2))
        .ok_or("worker exact slot count overflow")?;
    if count > 256 {
        return Err("worker window plus its metadata exceeds 256 exact slots; a separately reviewed smaller window is required".into());
    }
    let manifest_bound = 4096_u64
        .checked_add(
            u64::try_from(data.len())?
                .checked_mul(1664)
                .ok_or("worker manifest semantic bound overflow")?,
        )
        .and_then(|n| {
            n.checked_add(
                u64::try_from(location_nodes + job_nodes + 2)
                    .ok()?
                    .checked_mul(768)?,
            )
        })
        .and_then(|n| n.checked_add(u64::try_from(count).ok()?.checked_mul(128)?))
        .ok_or("worker manifest bound overflow")?;
    if manifest_bound > 256 * 1024 {
        return Err("worker exact manifest exceeds its closed record bound".into());
    }
    let mut specifications = data
        .iter()
        .map(|value| {
            slots::ExactSlot::for_bytes(
                slots::Pool::Publication(0),
                value.kind,
                value.bytes.len() as u64,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for _ in 0..location_nodes {
        specifications.push(slots::ExactSlot::for_bytes(
            slots::Pool::Publication(0),
            slots::Kind::Page,
            PAGE_BYTES as u64,
        )?);
    }
    specifications.push(slots::ExactSlot::for_bytes(
        slots::Pool::Publication(0),
        slots::Kind::Record,
        manifest_bound,
    )?);
    for _ in 0..job_nodes {
        specifications.push(slots::ExactSlot::for_bytes(
            slots::Pool::Publication(0),
            slots::Kind::Page,
            PAGE_BYTES as u64,
        )?);
    }
    specifications.push(slots::ExactSlot::for_bytes(
        slots::Pool::Publication(0),
        slots::Kind::Page,
        PAGE_BYTES as u64,
    )?);
    slots::Plan::exact(binding, &job, specifications.clone())?;
    let window = hash(&serde_json::to_vec(&(
        "luma-c-direct-worker-storage-v4",
        &token.base,
        &job,
        &token.operation,
        &token.roots,
        data.iter()
            .map(|value| (&value.sha256, value.bytes.len(), value.kind))
            .collect::<Vec<_>>(),
        &specifications,
        location_nodes,
        job_nodes,
        admission(&specifications)?,
    ))?);
    Ok(Plan {
        job,
        source: token.source_sha256.clone(),
        request: token.request_sha256.clone(),
        window,
        specifications,
        data,
        locations: location_nodes,
        jobs: job_nodes,
    })
}

struct Parent {
    name: &'static str,
    pin: PersistentDirectory,
    before: Observation,
}
struct Parents(Vec<Parent>);
fn observe_parent(
    pin: &PersistentDirectory,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Observation> {
    check()?;
    pin.check()?;
    let named = PersistentDirectory::open(&pin.path)?;
    let before = pin.file.metadata()?;
    let current = named.metadata()?;
    let mount = PersistentDirectory::mount(&pin.file)?;
    if file_identity(&before) != file_identity(&current)
        || before.blocks() != current.blocks()
        || PersistentDirectory::mount(&named)? != mount
    {
        return Err("worker parent lost its exact named/held observation".into());
    }
    let value = Observation {
        device: before.dev(),
        inode: before.ino(),
        mount,
        allocated_bytes: before
            .blocks()
            .checked_mul(512)
            .ok_or("worker parent allocation overflow")?,
        ctime_seconds: before.ctime(),
        ctime_nanoseconds: before.ctime_nsec(),
    };
    pin.check()?;
    check()?;
    Ok(value)
}
impl Parents {
    fn capture(pages: &PageStore, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        pages.check()?;
        let mut held = Vec::with_capacity(6);
        for name in ["", "pages", "records", "attempts", "controls", "tails"] {
            let pin = PersistentDirectory::capture(&pages.root.join(name))?;
            let before = observe_parent(&pin, check)?;
            held.push(Parent { name, pin, before });
        }
        pages.check()?;
        check()?;
        Ok(Self(held))
    }
    fn finish(&self, check: &mut impl FnMut() -> Result<()>) -> Result<Delta> {
        let mut delta = None;
        for parent in &self.0 {
            let after = observe_parent(&parent.pin, check)?;
            if parent.name == "attempts" {
                let value = Delta {
                    schema_version: 4,
                    domain: "luma-c-direct-attempts-parent-allocation-v4".into(),
                    before: parent.before.clone(),
                    after,
                };
                value.validate()?;
                delta = Some(value);
            } else if (
                parent.before.device,
                parent.before.inode,
                parent.before.mount,
                parent.before.allocated_bytes,
            ) != (
                after.device,
                after.inode,
                after.mount,
                after.allocated_bytes,
            ) {
                return Err(
                    "worker write changed an unreviewed existing directory allocation".into(),
                );
            }
        }
        check()?;
        delta.ok_or_else(|| "worker direct parent observation missing".into())
    }
}
struct Writer<'a, 'b, 'c, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    directory: &'a slots::Directory<'b>,
    slots: &'a [slots::Reference],
    used: usize,
    sealed: Vec<slots::SealedReference>,
    check: &'c mut F,
}
impl<F: FnMut() -> Result<()>> locations::Io for Writer<'_, '_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = slots::Directory::at_reference(self.pages, &reference.slot, self.check)?
            .read(reference, self.check)?;
        self.check()?;
        Ok(bytes)
    }
    fn seal_node(&mut self, bytes: &[u8]) -> Result<slots::SealedReference> {
        self.check()?;
        let reference = self
            .slots
            .get(self.used)
            .ok_or("worker actual index topology exceeded its exact planned slots")?;
        let value =
            self.directory
                .fill(reference, slots::Pool::Publication(0), bytes, self.check)?;
        self.used += 1;
        self.sealed.push(value.clone());
        Ok(value)
    }
}
struct Descriptors<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    check: &'b mut F,
}
impl<F: FnMut() -> Result<()>> control::Reader for Descriptors<'_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read_descriptor(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = slots::Directory::at_reference(self.pages, &reference.slot, self.check)?
            .read(reference, self.check)?;
        self.check()?;
        Ok(bytes)
    }
    fn read_descriptor_original(
        &mut self,
        reference: &slots::SealedReference,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>> {
        let mut current = || -> Result<()> {
            original.check()?;
            (self.check)()?;
            self.pages.check()?;
            original.check()
        };
        let bytes = slots::Directory::at_reference(self.pages, &reference.slot, &mut current)?
            .read(reference, &mut current)?;
        current()?;
        Ok(bytes)
    }
}
struct Actual<'a, 'b, 'c, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    directory: &'a slots::Directory<'b>,
    old: &'a locations::Root,
    new: &'a BTreeMap<String, slots::SealedReference>,
    context: map::Context,
    check: &'c mut F,
}
impl<F: FnMut() -> Result<()>> locations::Io for Actual<'_, '_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        locations::Io::check(self)?;
        let bytes = slots::Directory::at_reference(self.pages, &reference.slot, self.check)?
            .read(reference, self.check)?;
        locations::Io::check(self)?;
        Ok(bytes)
    }
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("post-seal semantic verification cannot create physical index objects".into())
    }
}
impl<F: FnMut() -> Result<()>> map::CustodyIo for Actual<'_, '_, '_, F> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if budget.write_bytes != 0 || budget.new_files != 0 || budget.read_bytes > READ_BUDGET {
            return Err("post-seal semantic verifier has no write admission".into());
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        if context != &self.context {
            return Err("post-seal verifier changed the exact current C/original review".into());
        }
        locations::Io::check(self)
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("post-seal semantic verifier changed one-page bound".into());
        }
        let bytes = if let Some(reference) = self.new.get(sha) {
            if reference.slot.kind != slots::Kind::Page {
                return Err("semantic page proof substituted a sealed record".into());
            }
            self.directory.read(reference, self.check)?
        } else {
            let old = self.old.clone();
            let reference = locations::lookup(&old, sha, self)?
                .ok_or("post-seal verifier lost an actual old selected page")?;
            if reference.slot.kind != slots::Kind::Page {
                return Err("old selected semantic page has another kind".into());
            }
            locations::Io::read(self, &reference)?
        };
        if bytes.is_empty() || bytes.len() > maximum || hash(&bytes) != sha {
            return Err("post-seal semantic page complete bytes changed".into());
        }
        self.check_current(context)?;
        Ok(bytes)
    }
    fn write_page(&mut self, _: &map::Context, _: &[u8]) -> Result<()> {
        Err("post-seal semantic verification refuses write effects".into())
    }
}

pub(super) fn publish<A: Checkpoint>(
    mut backend: Backend<A>,
    token: VerifiedTransition,
    original: &mut OriginalCOperation<'_>,
) -> Result<Completed> {
    let planned = plan(&mut backend, &token, original)?;
    source(&mut backend, &token, original)?;
    let cut = reader::observe(
        &mut backend.anchor,
        &backend.pages,
        &backend.descriptor.binding,
        &mut || original.check(),
    )?;
    if cut.descriptor().bytes()? != backend.descriptor.bytes()? {
        return Err("worker direct selected cut changed after exact semantic planning".into());
    }
    let cell = cut.cell().clone();
    let index = u8::try_from(cut.index())?;
    cut.completed_read()?;
    let Backend {
        mut anchor,
        files: _,
        pages,
        descriptor: previous,
        ..
    } = backend;
    let control::Cell::Selected {
        descriptor: old_location,
        ..
    } = &cell
    else {
        return Err("worker direct base has no descriptor address".into());
    };
    let old = tpm::decode::<32>(&previous.selected_nv_head)?;
    let mut live = || -> Result<()> {
        original.check()?;
        pages.check()?;
        if anchor.read()? != old {
            return Err("actual C changed during worker exact-slot preparation".into());
        }
        original.check()
    };
    let before = pages.inventory(&mut live)?;
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("worker direct base storage absent")?;
    if before != previous_storage.post_allocation {
        return Err("worker direct physical baseline changed before reservation".into());
    }
    let parents = Parents::capture(&pages, &mut live)?;
    pages.admit_writes(
        admission(&planned.specifications)?,
        u64::try_from(planned.specifications.len())? + 1,
        1,
        &mut live,
    )?;
    let layout = slots::Plan::exact(
        &previous.binding,
        &planned.job,
        planned.specifications.clone(),
    )?;
    let directory = slots::Directory::create(&pages, layout.clone(), &mut live)?;
    let mut references = Vec::with_capacity(planned.specifications.len());
    while references.len() < planned.specifications.len() {
        let first = u32::try_from(references.len())?;
        let count = u32::try_from((planned.specifications.len() - references.len()).min(16))?;
        references.extend(directory.allocate_window(first, count, &mut live)?);
    }
    let namespace = directory.observe_namespace(&mut live)?;
    let semantic = planned.data.len();
    let manifest_index = semantic + planned.locations;
    let job_start = manifest_index + 1;
    let descriptor_index = references.len() - 1;
    let mut semantic_locations = BTreeMap::new();
    for (value, reference) in planned.data.iter().zip(&references[..semantic]) {
        let sealed = directory.fill(
            reference,
            slots::Pool::Publication(0),
            &value.bytes,
            &mut live,
        )?;
        if sealed.sha256 != value.sha256 || directory.read(&sealed, &mut live)? != value.bytes {
            return Err(
                "worker sealed semantic bytes differ from genuine independent reconstruction"
                    .into(),
            );
        }
        if semantic_locations
            .insert(value.sha256.clone(), sealed)
            .is_some()
        {
            return Err("worker semantic bytes alias a digest".into());
        }
    }
    let mut insertions = semantic_locations
        .iter()
        .map(|(sha, location)| locations::Insertion {
            sha256: sha.clone(),
            location: location.clone(),
        })
        .collect::<Vec<_>>();
    insertions.push(locations::Insertion {
        sha256: old_location.sha256.clone(),
        location: old_location.clone(),
    });
    insertions.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    let mut writer = Writer {
        pages: &pages,
        directory: &directory,
        slots: &references[semantic..manifest_index],
        used: 0,
        sealed: Vec::new(),
        check: &mut live,
    };
    let locations = locations::insert(&previous_storage.locations, &insertions, &mut writer)?;
    if writer.used != planned.locations {
        return Err("worker location index did not consume every exact planned slot".into());
    }
    let location_witnesses = writer.sealed.clone();
    locations::verify_insertions(
        &previous_storage.locations,
        &locations,
        &insertions,
        &location_witnesses,
        &mut writer,
    )?;
    drop(writer);
    let allocated = references.iter().try_fold(
        namespace
            .allocated_bytes
            .checked_add(namespace.identity_allocated_bytes)
            .ok_or("worker namespace overflow")?,
        |sum, reference| {
            sum.checked_add(reference.allocated_bytes)
                .ok_or("worker namespace total overflow")
        },
    )?;
    let manifest = Manifest {
        schema_version: 4,
        domain: "luma-c-reviewed-job-allocation-v4".into(),
        binding: previous.binding.clone(),
        job: planned.job.clone(),
        base_descriptor_sha256: token.base.descriptor_sha256.clone(),
        original_request_sha256: planned.request.clone(),
        review_sha256: planned.window.clone(),
        source_sha256: planned.source.clone(),
        previous: None,
        own_slot: manifest_index as u32,
        layout,
        namespace,
        members: references
            .iter()
            .enumerate()
            .map(|(number, slot)| Member {
                slot: slot.clone(),
                role: if number < semantic {
                    if planned.data[number].kind == slots::Kind::Record {
                        Role::SemanticRecord
                    } else {
                        Role::SemanticPage
                    }
                } else if number < manifest_index {
                    Role::LocationIndex
                } else if number == manifest_index {
                    Role::Manifest
                } else if number < descriptor_index {
                    Role::JobIndex
                } else {
                    Role::Descriptor
                },
                disposition: if number < semantic {
                    Disposition::Sealed {
                        value: semantic_locations[&planned.data[number].sha256].clone(),
                    }
                } else {
                    Disposition::BoundMetadata
                },
            })
            .collect(),
        allocated_bytes: allocated,
    };
    let manifest_location = directory.fill(
        &references[manifest_index],
        slots::Pool::Publication(0),
        &manifest.canonical_bytes()?,
        &mut live,
    )?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("worker selected job index absent")?;
    let job_edit = locations::JobEdit {
        job: planned.job.clone(),
        previous: None,
        next: manifest_location.clone(),
    };
    let mut writer = Writer {
        pages: &pages,
        directory: &directory,
        slots: &references[job_start..descriptor_index],
        used: 0,
        sealed: Vec::new(),
        check: &mut live,
    };
    let jobs = old_jobs.update(std::slice::from_ref(&job_edit), &mut writer)?;
    if writer.used != planned.jobs {
        return Err("worker job index did not consume every exact planned slot".into());
    }
    let job_witnesses = writer.sealed.clone();
    old_jobs.verify_update(
        &jobs,
        std::slice::from_ref(&job_edit),
        &job_witnesses,
        &mut writer,
    )?;
    drop(writer);
    let parent_allocation = parents.finish(&mut live)?;
    if let Some(prior) = &previous_storage.parent_allocation {
        if prior.after != parent_allocation.before {
            return Err("worker parent delta resets selected allocation lineage".into());
        }
    }
    let mut physical = pages.inventory(&mut live)?;
    if physical.interrupted_files != 1
        || physical.files
            != before
                .files
                .checked_add(references.len() as u64 + 1)
                .ok_or("worker file total overflow")?
        || physical.directories
            != before
                .directories
                .checked_add(1)
                .ok_or("worker directory total overflow")?
    {
        return Err("worker direct preparation introduced unknown/unconsumed allocations".into());
    }
    physical.interrupted_files = 0;
    physical.logical_bytes = physical
        .logical_bytes
        .checked_add(PAGE_BYTES as u64)
        .ok_or("worker descriptor size overflow")?;
    live()?;
    drop(live);
    original.check()?;
    if planned.source != hash(&COperation::Worker(original).source_bytes()?)
        || planned.request != original.source_binding().request_sha256
    {
        return Err("worker original source changed before final descriptor creation".into());
    }
    let next = Descriptor {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: previous.binding.clone(),
        sequence: previous
            .sequence
            .checked_add(1)
            .ok_or("worker descriptor sequence overflow")?,
        global_ordinal: previous
            .global_ordinal
            .checked_add(1)
            .ok_or("worker global ordinal overflow")?,
        previous_descriptor_sha256: Some(token.base_frame_sha256.clone()),
        previous_nv_head: previous.selected_nv_head.clone(),
        event_sha256: String::new(),
        selected_nv_head: String::new(),
        legacy: previous.legacy.clone(),
        roots: token.roots.clone(),
        phase: previous.phase.clone(),
        operation: token.operation.clone(),
        storage: Some(StorageSelection {
            schema_version: 2,
            controls: previous_storage.controls.clone(),
            locations,
            jobs: Some(jobs),
            descriptor_slot: references[descriptor_index].clone(),
            post_allocation: physical.clone(),
            parent_allocation: Some(parent_allocation),
        }),
    }
    .seal()?;
    let mut live = || -> Result<()> {
        original.check()?;
        pages.check()?;
        if anchor.read()? != old {
            return Err("actual C changed before worker direct dispatch".into());
        }
        original.check()
    };
    let descriptor_location = directory.fill(
        &references[descriptor_index],
        slots::Pool::Publication(0),
        &next.slot_frame()?,
        &mut live,
    )?;
    let mut metadata = BTreeMap::from([
        (manifest_index as u32, manifest_location),
        (descriptor_index as u32, descriptor_location.clone()),
    ]);
    for reference in location_witnesses.iter().chain(&job_witnesses) {
        if metadata
            .insert(reference.slot.number, reference.clone())
            .is_some()
        {
            return Err("worker metadata aliases an existing exact slot".into());
        }
    }
    let observed = jobs::observe(
        &pages,
        &metadata[&(manifest_index as u32)],
        &metadata,
        &mut live,
    )?;
    let delta = next
        .storage
        .as_ref()
        .and_then(|value| value.parent_allocation.as_ref())
        .ok_or("worker parent delta absent")?;
    let added = observed.physical();
    let growth = delta
        .after
        .allocated_bytes
        .checked_sub(delta.before.allocated_bytes)
        .ok_or("worker parent allocation decreased")?;
    let accounted = paged::PhysicalInventory {
        files: before
            .files
            .checked_add(added.files)
            .ok_or("worker files overflow")?,
        directories: before
            .directories
            .checked_add(added.directories)
            .ok_or("worker directories overflow")?,
        logical_bytes: before
            .logical_bytes
            .checked_add(added.logical_bytes)
            .ok_or("worker logical bytes overflow")?,
        allocated_bytes: before
            .allocated_bytes
            .checked_add(added.allocated_bytes)
            .and_then(|n| n.checked_add(growth))
            .ok_or("worker allocated bytes overflow")?,
        interrupted_files: before
            .interrupted_files
            .checked_add(added.interrupted_files)
            .ok_or("worker partial count overflow")?,
    };
    if observed.manifest() != &manifest
        || accounted != physical
        || pages.inventory(&mut live)? != physical
    {
        return Err(
            "worker actual complete allocation closure differs before its sole dispatch".into(),
        );
    }
    // The factory's pages/records were independently reconstructed. Read every
    // actual sealed member again, then replay the exact owner-map delta from
    // actual old and new pages before allowing the sole C effect.
    for value in &planned.data {
        if directory.read(&semantic_locations[&value.sha256], &mut live)? != value.bytes {
            return Err("worker actual sealed semantic readback changed before dispatch".into());
        }
    }
    let context = map::Context {
        binding: previous.binding.clone(),
        selected_descriptor_sha256: token.base.descriptor_sha256.clone(),
        selected_nv_head: token.base.nv_head.clone(),
        review_sha256: Some(token.review_sha256.clone()),
    };
    for (role, edits) in &token.edits {
        map::verify_update(
            previous.roots.role(*role),
            next.roots.role(*role),
            edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut Actual {
                pages: &pages,
                directory: &directory,
                old: &previous_storage.locations,
                new: &semantic_locations,
                context: context.clone(),
                check: &mut live,
            },
        )?;
    }
    for expected in &token.read_cas {
        let root = previous.roots.role(expected.role);
        let key = root.key(&expected.literal)?;
        let proof = map::lookup(
            root,
            &key,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut Actual {
                pages: &pages,
                directory: &directory,
                old: &previous_storage.locations,
                new: &semantic_locations,
                context: context.clone(),
                check: &mut live,
            },
        )?;
        if proof.verify_data(root)?.as_deref() != Some(expected.value.as_slice()) {
            return Err("worker post-seal unchanged-role read-CAS changed".into());
        }
    }
    live()?;
    drop(live);
    let controls = cells::Files::open(&pages, previous_storage.controls.clone(), &mut || {
        original.check()
    })?;
    let pending = control::PendingCell {
        schema_version: 3,
        domain: "luma-c-direct-slot-pending-v3".into(),
        binding: previous.binding.clone(),
        base: control::Base::Slot { index, cell },
        inactive_index: 1 - index,
        next: control::Cell::for_descriptor(&next, descriptor_location)?,
        event_sha256: next.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&next.operation)?),
    };
    let mut old_pin = || -> Result<()> {
        pages.check()?;
        if anchor.read()? != old {
            return Err("actual C changed during worker fixed-control staging".into());
        }
        Ok(())
    };
    let mut operation = COperation::Worker(original);
    let staged = control::stage(
        &controls,
        pending,
        Some(&previous),
        &next,
        old,
        &mut Descriptors {
            pages: &pages,
            check: &mut old_pin,
        },
        &mut operation,
    )?;
    staged.check(&controls, &mut operation)?;
    old_pin()?;
    operation.check()?;
    drop(old_pin);
    if anchor.read()? != old {
        return Err("actual C changed immediately before worker's sole dispatch".into());
    }
    let actual = anchor.advance(old, tpm::decode(&next.event_sha256)?)?;
    let expected = tpm::decode::<32>(&next.selected_nv_head)?;
    if actual != expected || anchor.read()? != expected {
        return Err("worker direct checkpoint outcome remains uncertain".into());
    }
    staged.check(&controls, &mut operation)?;
    let snapshot = controls.read(2, &mut || operation.check())?;
    if snapshot.bytes()
        != (control::PendingFrame::Prepared {
            pending: staged.pending.clone(),
        })
        .frame()?
    {
        return Err("worker pending changed after actual C dispatch".into());
    }
    controls.rewrite(
        &snapshot,
        &control::PendingFrame::Completed {
            pending: staged.pending,
        }
        .frame()?,
        &mut || {
            operation.check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during fixed worker completion".into());
            }
            operation.check()
        },
    )?;
    operation.check()?;
    Ok(token.outcome)
}
