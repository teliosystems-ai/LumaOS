//! Actual single-row direct C bootstrap, a private child of bootstrap so its
//! genuine verified rows are used without JSON casts or synthetic authority.
//! This profile retains the old hash format's sixteen-row limit unchanged.
use super::super::super::paged::{cells, slots};
use super::super::direct::backend::{Backend, ProgressBase};
use super::super::direct::jobs::{self, Disposition, Manifest, Member, Role};
use super::*;
#[path = "progress/cold.rs"]
mod cold;
#[path = "progress/parents.rs"]
mod parents;
#[path = "progress/recovery.rs"]
mod recovery;
pub(in crate::content_checkpoint::custody) use cold::verify_selected;
pub(in crate::content_checkpoint::custody::v2_publication) use cold::{
    verify_closure, Closure, Data,
};
pub(in crate::content_checkpoint::custody) use recovery::{reconcile, recovery_review};

const CACHE_PAGES: usize = 64;
const CACHE_BYTES: usize = 1024 * 1024;
const MANIFEST_HEADER_BOUND: u64 = 4096;
const LAYOUT_MEMBER_BOUND: u64 = 128;
const SEMANTIC_MEMBER_BOUND: u64 = 1664;
const METADATA_MEMBER_BOUND: u64 = 768;

struct Cache<'a, 'b, 'c, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    authority: &'b mut OriginalCAdminOperation<'c>,
    context: map::Context,
    pages: BTreeMap<String, Vec<u8>>,
    bytes: usize,
    readonly: bool,
}
impl<A: Checkpoint> map::CustodyIo for Cache<'_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if self.readonly && (budget.write_bytes != 0 || budget.new_files != 0)
            || budget.write_bytes > CACHE_BYTES as u64
            || budget.new_files > CACHE_PAGES as u32
        {
            return Err("single-row direct planning exceeds bounded memory-only admission".into());
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        if context != &self.context {
            return Err(
                "single-row planner changed current C selection or logical review DATA".into(),
            );
        }
        self.backend.live(&mut || self.authority.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum == 0 || maximum > PAGE_BYTES {
            return Err("single-row map page exceeds its actual format bound".into());
        }
        let bytes = match self.pages.get(sha) {
            Some(bytes) => bytes.clone(),
            None => self.backend.read_immutable(
                sha,
                slots::Kind::Page,
                &mut COperation::Admin(self.authority),
            )?,
        };
        if bytes.len() > maximum || hash(&bytes) != sha {
            return Err("single-row map read changes complete page bytes".into());
        }
        self.check_current(context)?;
        Ok(bytes)
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        if self.readonly || bytes.is_empty() || bytes.len() > PAGE_BYTES {
            return Err("single-row independent replay cannot write or exceed one page".into());
        }
        let sha = hash(bytes);
        if let Some(old) = self.pages.get(&sha) {
            if old != bytes {
                return Err("single-row cache digest collision".into());
            }
            return self.check_current(context);
        }
        if self.pages.len() >= CACHE_PAGES
            || self
                .bytes
                .checked_add(bytes.len())
                .map_or(true, |n| n > CACHE_BYTES)
        {
            return Err("single-row bounded cache exhausted before copying bytes".into());
        }
        self.bytes += bytes.len();
        self.pages.insert(sha, bytes.to_vec());
        self.check_current(context)
    }
}
struct ReadNodes<'a, 'b, 'c, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    authority: &'b mut OriginalCAdminOperation<'c>,
}
impl<A: Checkpoint> locations::Io for ReadNodes<'_, '_, '_, A> {
    fn check(&mut self) -> Result<()> {
        self.backend.live(&mut || self.authority.check())
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.backend.read_structural(reference, self.authority)
    }
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("exact direct topology review has no physical writer".into())
    }
}
struct Planned {
    base: Selector,
    base_frame_sha256: String,
    logical_sha256: String,
    job: String,
    from: u64,
    to: u64,
    roots: Roots,
    phase: Phase,
    pages: BTreeMap<String, Vec<u8>>,
    location_nodes: usize,
    job_nodes: usize,
    specs: Vec<slots::ExactSlot>,
    window_sha256: String,
}
fn manifest_bound(semantic: usize, metadata: usize, slots: usize) -> Result<u64> {
    let bound = MANIFEST_HEADER_BOUND
        .checked_add(
            u64::try_from(semantic)?
                .checked_mul(SEMANTIC_MEMBER_BOUND)
                .ok_or("semantic manifest bound overflow")?,
        )
        .and_then(|n| {
            n.checked_add(
                u64::try_from(metadata)
                    .ok()?
                    .checked_mul(METADATA_MEMBER_BOUND)?,
            )
        })
        .and_then(|n| {
            n.checked_add(
                u64::try_from(slots)
                    .ok()?
                    .checked_mul(LAYOUT_MEMBER_BOUND)?,
            )
        })
        .ok_or("whole manifest bound overflow")?;
    if bound > 256 * 1024 {
        return Err("single-row exact manifest exceeds its immutable format bound".into());
    }
    Ok(bound)
}
fn plan<A: Checkpoint>(
    backend: &mut Backend<A>,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<Planned> {
    backend.live(&mut || authority.check())?;
    let descriptor = backend.descriptor().clone();
    if descriptor.phase.state != State::Pending {
        return Err("C projection is already complete; no bootstrap renewal".into());
    }
    // The installed reader already joins the real C-selected retained journal;
    // a structural source below is read-only and cannot supply an owner store.
    let source = backend.legacy_data(&mut || authority.check())?;
    let blueprint = Blueprint::verified_legacy(&descriptor.binding, &descriptor.legacy, &source)?;
    blueprint.require_phase(&descriptor.phase)?;
    let base = Selector::for_descriptor(&descriptor)?;
    let base_frame = hash(&descriptor.slot_frame()?);
    let from = usize::try_from(descriptor.phase.copied_entries)?;
    let to = from
        .checked_add(1)
        .ok_or("single-row projection cursor overflow")?
        .min(blueprint.rows.len());
    let logical = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-logical-v4",
        &descriptor.binding,
        &base,
        &base_frame,
        &descriptor.phase,
        from,
        to,
        hash(&serde_json::to_vec(&blueprint.rows[from..to])?),
    ))?);
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-job-v4",
        &descriptor.binding,
        &base_frame,
        &logical,
    ))?);
    let mut context = backend.context()?;
    context.review_sha256 = Some(logical.clone());
    let mut cache = Cache {
        backend,
        authority,
        context: context.clone(),
        pages: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let mut roots = descriptor.roots.clone();
    for role in [
        map::Kind::OwnerStates,
        map::Kind::Recipients,
        map::Kind::Signers,
        map::Kind::Unavailable,
        map::Kind::RestoreReservations,
        map::Kind::ArchiveInventory,
        map::Kind::IndexGenerations,
    ] {
        let edits = blueprint.rows[from..to]
            .iter()
            .filter(|row| row.role == role)
            .map(|row| map::Edit {
                key: row.key.clone(),
                expected_value_sha256: None,
                value: Some(row.value.clone()),
            })
            .collect::<Vec<_>>();
        if edits.is_empty() {
            continue;
        }
        let before = roots.role(role).clone();
        let next = map::prepare_update(
            &before,
            &edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: CACHE_BYTES as u64,
                new_files: CACHE_PAGES as u32,
            },
            &mut cache,
        )?;
        cache.readonly = true;
        map::verify_update(
            &before,
            &next,
            &edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut cache,
        )?;
        cache.readonly = false;
        roots.set_role(role, next)?;
    }
    let pages = std::mem::take(&mut cache.pages);
    drop(cache);
    let phase = Phase {
        copied_entries: to as u64,
        state: if to == blueprint.rows.len() {
            State::Ready
        } else {
            State::Pending
        },
        ..descriptor.phase.clone()
    };
    descriptor.phase.require_successor(&phase)?;
    phase.validate(&descriptor.legacy, &roots)?;
    let storage = descriptor
        .storage
        .as_ref()
        .ok_or("direct base has no selected storage")?;
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("direct base has no selected job root")?;
    let mut keys = pages.keys().cloned().collect::<Vec<_>>();
    keys.push(base_frame.clone());
    keys.sort();
    let location_nodes = locations::planning::new_locations(
        &storage.locations,
        &keys,
        &mut ReadNodes { backend, authority },
    )?
    .new_nodes;
    let job_nodes =
        locations::planning::new_jobs(jobs, &[job.clone()], &mut ReadNodes { backend, authority })?
            .new_nodes;
    backend.live(&mut || authority.check())?;
    complete_plan(
        &descriptor,
        &blueprint,
        roots,
        pages,
        location_nodes,
        job_nodes,
    )
}
fn complete_plan(
    descriptor: &Descriptor,
    blueprint: &Blueprint,
    roots: Roots,
    pages: BTreeMap<String, Vec<u8>>,
    location_nodes: usize,
    job_nodes: usize,
) -> Result<Planned> {
    blueprint.require_phase(&descriptor.phase)?;
    if descriptor.phase.state != State::Pending {
        return Err("completed bootstrap has no next direct plan".into());
    }
    let base = Selector::for_descriptor(descriptor)?;
    let base_frame = hash(&descriptor.slot_frame()?);
    let from = usize::try_from(descriptor.phase.copied_entries)?;
    let to = from
        .checked_add(1)
        .ok_or("projection cursor overflow")?
        .min(blueprint.rows.len());
    let logical = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-logical-v4",
        &descriptor.binding,
        &base,
        &base_frame,
        &descriptor.phase,
        from,
        to,
        hash(&serde_json::to_vec(&blueprint.rows[from..to])?),
    ))?);
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-job-v4",
        &descriptor.binding,
        &base_frame,
        &logical,
    ))?);
    let phase = Phase {
        copied_entries: to as u64,
        state: if to == blueprint.rows.len() {
            State::Ready
        } else {
            State::Pending
        },
        ..descriptor.phase.clone()
    };
    descriptor.phase.require_successor(&phase)?;
    phase.validate(&descriptor.legacy, &roots)?;
    let total = pages
        .len()
        .checked_add(location_nodes)
        .and_then(|n| n.checked_add(job_nodes))
        .and_then(|n| n.checked_add(2))
        .ok_or("single-row total exact slots overflow")?;
    if total > 256 {
        return Err("single-row storage layout exceeds exact slot namespace".into());
    }
    let manifest_bytes = manifest_bound(pages.len(), location_nodes + job_nodes + 2, total)?;
    let mut specifications = pages
        .values()
        .map(|bytes| {
            slots::ExactSlot::for_bytes(
                slots::Pool::Publication(0),
                slots::Kind::Page,
                bytes.len() as u64,
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
        manifest_bytes,
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
    slots::Plan::exact(&descriptor.binding, &job, specifications.clone())?;
    let window=hash(&serde_json::to_vec(&(
        "luma-c-exact-single-row-window-v4",&base,&base_frame,&logical,&job,&phase,&roots,
        pages.iter().map(|(sha,bytes)|(sha,bytes.len())).collect::<Vec<_>>(),location_nodes,job_nodes,&specifications,
        admission_bytes(&specifications)?,
        "one-row-per-fresh-original-standard-session;retain-all-history;one-C-advance;no-post-NV-allocation",
    ))?);
    Ok(Planned {
        base,
        base_frame_sha256: base_frame,
        logical_sha256: logical,
        job,
        from: from as u64,
        to: to as u64,
        roots,
        phase,
        pages,
        location_nodes,
        job_nodes,
        specs: specifications,
        window_sha256: window,
    })
}
pub(in crate::content_checkpoint::custody) fn review<A: Checkpoint>(
    backend: &mut Backend<A>,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<serde_json::Value> {
    let planned = plan(backend, authority)?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-direct-single-row-v4",
        "stable_review_sha256":backend.descriptor().phase.review_sha256,
        "window_intent_sha256":planned.window_sha256,"expected_selected_descriptor_sha256":planned.base.descriptor_sha256,
        "from_row":planned.from,"to_row":planned.to,"next_phase":planned.phase,"exact_slots":planned.specs,
        "logical_window_sha256":planned.logical_sha256,
        "fresh_standard_session_per_window":true,"maximum_projection_rows_per_window":1,
        "ordinary_owner_access_available":false,"filesystem_changed":false,"TPM_extended":false,
        "authority_returned":false,"production_qualified":false}),
    )
}

fn admission_bytes(specifications: &[slots::ExactSlot]) -> Result<u64> {
    specifications.iter().try_fold(
        3 * 64 * 1024 + slots::PLAN_BYTES as u64 + parents::growth_budget(),
        |total, spec| {
            total
                .checked_add(spec.capacity)
                .and_then(|n| n.checked_add(64 * 1024 + 4096))
                .ok_or_else(|| "single-row physical admission overflow".into())
        },
    )
}
struct NodeWriter<'a, 'b, 'c, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    directory: &'a slots::Directory<'b>,
    references: &'a [slots::Reference],
    used: usize,
    sealed: Vec<slots::SealedReference>,
    check: &'c mut F,
}
impl<F: FnMut() -> Result<()>> locations::Io for NodeWriter<'_, '_, '_, F> {
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
            .references
            .get(self.used)
            .ok_or("actual direct topology exceeds its exact reviewed node count")?;
        let sealed =
            self.directory
                .fill(reference, slots::Pool::Publication(0), bytes, self.check)?;
        self.used += 1;
        self.sealed.push(sealed.clone());
        Ok(sealed)
    }
}
struct DescriptorRead<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    check: &'b mut F,
}
impl<F: FnMut() -> Result<()>> control::Reader for DescriptorRead<'_, '_, F> {
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
        let mut live = || -> Result<()> {
            original.check()?;
            (self.check)()?;
            self.pages.check()?;
            original.check()
        };
        let bytes = slots::Directory::at_reference(self.pages, &reference.slot, &mut live)?
            .read(reference, &mut live)?;
        live()?;
        Ok(bytes)
    }
}
pub(in crate::content_checkpoint::custody) fn window<A: Checkpoint>(
    mut backend: Backend<A>,
    expected_window: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<Backend<A>> {
    let planned = plan(&mut backend, authority)?;
    if planned.window_sha256 != expected_window {
        return Err("direct single-row window changed after its exact original review".into());
    }
    let base = backend.into_progress(expected_window, authority)?;
    base.check_source(authority)?;
    let ProgressBase {
        mut anchor,
        files,
        pages,
        descriptor: previous,
        cell,
        index,
        source_sha256,
        request_sha256,
        ..
    } = base;
    let control::Cell::Selected {
        descriptor: previous_location,
        ..
    } = &cell
    else {
        return Err("direct progress lost its actual selected descriptor location".into());
    };
    if previous_location.sha256 != planned.base_frame_sha256
        || hash(&previous.bytes()?) != planned.base.descriptor_sha256
        || previous.selected_nv_head != planned.base.nv_head
    {
        return Err(
            "direct progress carrier substitutes the independently planned current C base".into(),
        );
    }
    let old = tpm::decode::<32>(&previous.selected_nv_head)?;
    let mut live = || -> Result<()> {
        authority.check()?;
        pages.check()?;
        if anchor.read()? != old {
            return Err("actual C changed during direct single-row preparation".into());
        }
        authority.check()
    };
    let before = pages.inventory(&mut live)?;
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("direct previous storage absent")?;
    if before != previous_storage.post_allocation {
        return Err("direct base physical accounting changed before allocation".into());
    }
    let parents = parents::Parents::capture(&pages, &mut live)?;
    let layout = slots::Plan::exact(&previous.binding, &planned.job, planned.specs.clone())?;
    pages.admit_writes(
        admission_bytes(&planned.specs)?,
        u64::try_from(planned.specs.len())? + 1,
        1,
        &mut live,
    )?;
    let directory = slots::Directory::create(&pages, layout.clone(), &mut live)?;
    let mut references = Vec::with_capacity(planned.specs.len());
    while references.len() < planned.specs.len() {
        let first = u32::try_from(references.len())?;
        let count = u32::try_from((planned.specs.len() - references.len()).min(16))?;
        references.extend(directory.allocate_window(first, count, &mut live)?);
    }
    let namespace = directory.observe_namespace(&mut live)?;
    let semantic = planned.pages.len();
    let location_start = semantic;
    let manifest_index = semantic + planned.location_nodes;
    let job_start = manifest_index + 1;
    let descriptor_index = references.len() - 1;
    let mut semantic_refs = Vec::new();
    for ((sha, bytes), reference) in planned.pages.iter().zip(&references[..semantic]) {
        let location = directory.fill(reference, slots::Pool::Publication(0), bytes, &mut live)?;
        if location.sha256 != *sha || directory.read(&location, &mut live)? != *bytes {
            return Err(
                "actual semantic page differs from independently verified single-row bytes".into(),
            );
        }
        semantic_refs.push(location);
    }
    let mut insertions = semantic_refs
        .iter()
        .map(|location| locations::Insertion {
            sha256: location.sha256.clone(),
            location: location.clone(),
        })
        .collect::<Vec<_>>();
    insertions.push(locations::Insertion {
        sha256: previous_location.sha256.clone(),
        location: previous_location.clone(),
    });
    insertions.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    let mut location_writer = NodeWriter {
        pages: &pages,
        directory: &directory,
        references: &references[location_start..manifest_index],
        used: 0,
        sealed: Vec::new(),
        check: &mut live,
    };
    let locations = locations::insert(
        &previous_storage.locations,
        &insertions,
        &mut location_writer,
    )?;
    if location_writer.used != planned.location_nodes {
        return Err("actual location tree did not consume every exact reviewed slot".into());
    }
    let location_witnesses = location_writer.sealed.clone();
    locations::verify_insertions(
        &previous_storage.locations,
        &locations,
        &insertions,
        &location_witnesses,
        &mut location_writer,
    )?;
    drop(location_writer);
    let allocated = references.iter().try_fold(
        namespace
            .allocated_bytes
            .checked_add(namespace.identity_allocated_bytes)
            .ok_or("direct progress namespace overflow")?,
        |sum, reference| {
            sum.checked_add(reference.allocated_bytes)
                .ok_or("direct progress allocation overflow")
        },
    )?;
    let manifest = Manifest {
        schema_version: 4,
        domain: "luma-c-reviewed-job-allocation-v4".into(),
        binding: previous.binding.clone(),
        job: planned.job.clone(),
        base_descriptor_sha256: planned.base.descriptor_sha256.clone(),
        original_request_sha256: request_sha256.clone(),
        review_sha256: expected_window.into(),
        source_sha256: source_sha256.clone(),
        previous: None,
        own_slot: u32::try_from(manifest_index)?,
        layout,
        namespace,
        members: references
            .iter()
            .enumerate()
            .map(|(number, reference)| Member {
                slot: reference.clone(),
                role: if number < semantic {
                    Role::SemanticPage
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
                        value: semantic_refs[number].clone(),
                    }
                } else {
                    Disposition::BoundMetadata
                },
            })
            .collect(),
        allocated_bytes: allocated,
    };
    let manifest_bytes = manifest.canonical_bytes()?;
    if manifest_bytes.len() as u64 > references[manifest_index].capacity {
        return Err("actual manifest exceeded the maximum-field reviewed bound".into());
    }
    let manifest_location = directory.fill(
        &references[manifest_index],
        slots::Pool::Publication(0),
        &manifest_bytes,
        &mut live,
    )?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("direct previous job index absent")?;
    let job_edit = locations::JobEdit {
        job: planned.job.clone(),
        previous: None,
        next: manifest_location.clone(),
    };
    let mut job_writer = NodeWriter {
        pages: &pages,
        directory: &directory,
        references: &references[job_start..descriptor_index],
        used: 0,
        sealed: Vec::new(),
        check: &mut live,
    };
    let jobs = old_jobs.update(std::slice::from_ref(&job_edit), &mut job_writer)?;
    if job_writer.used != planned.job_nodes {
        return Err("actual job tree did not consume every exact reviewed slot".into());
    }
    let job_witnesses = job_writer.sealed.clone();
    old_jobs.verify_update(
        &jobs,
        std::slice::from_ref(&job_edit),
        &job_witnesses,
        &mut job_writer,
    )?;
    drop(job_writer);
    let parent_allocation = parents.finish(&mut live)?;
    if let Some(old_delta) = &previous_storage.parent_allocation {
        if old_delta.after != parent_allocation.before {
            return Err(
                "direct progress parent does not continue the prior selected after observation"
                    .into(),
            );
        }
    }
    let mut physical = pages.inventory(&mut live)?;
    if physical.interrupted_files != 1
        || physical.files
            != before
                .files
                .checked_add(u64::try_from(references.len())? + 1)
                .ok_or("progress file count overflow")?
        || physical.directories
            != before
                .directories
                .checked_add(1)
                .ok_or("progress directory count overflow")?
    {
        return Err("single-row preparation introduced unknown or unconsumed allocations".into());
    }
    physical.interrupted_files = 0;
    physical.logical_bytes = physical
        .logical_bytes
        .checked_add(PAGE_BYTES as u64)
        .ok_or("progress logical size overflow")?;
    live()?;
    drop(live);
    require_admin(
        authority,
        &previous.binding,
        &previous.phase,
        expected_window,
        Some(&planned.base.descriptor_sha256),
        None,
    )?;
    let next = Descriptor {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: previous.binding.clone(),
        sequence: previous
            .sequence
            .checked_add(1)
            .ok_or("progress sequence overflow")?,
        global_ordinal: previous
            .global_ordinal
            .checked_add(1)
            .ok_or("progress ordinal overflow")?,
        previous_descriptor_sha256: Some(planned.base_frame_sha256.clone()),
        previous_nv_head: previous.selected_nv_head.clone(),
        event_sha256: String::new(),
        selected_nv_head: String::new(),
        legacy: previous.legacy.clone(),
        roots: planned.roots,
        phase: planned.phase,
        operation: OperationData::BootstrapProgress {
            previous_retirement: None,
            review_sha256: previous.phase.review_sha256.clone(),
            window_intent_sha256: expected_window.into(),
            request_sha256,
            source_sha256,
            original_authority: authority.audit().clone(),
        },
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
        authority.check()?;
        if anchor.read()? != old {
            return Err("actual C changed before direct progress dispatch".into());
        }
        authority.check()
    };
    let next_location = directory.fill(
        &references[descriptor_index],
        slots::Pool::Publication(0),
        &next.slot_frame()?,
        &mut live,
    )?;
    let mut metadata = BTreeMap::from([
        (u32::try_from(manifest_index)?, manifest_location.clone()),
        (u32::try_from(descriptor_index)?, next_location.clone()),
    ]);
    for (number, location) in location_witnesses.iter().enumerate() {
        metadata.insert(u32::try_from(location_start + number)?, location.clone());
    }
    for (number, location) in job_witnesses.iter().enumerate() {
        metadata.insert(u32::try_from(job_start + number)?, location.clone());
    }
    let observed = jobs::observe(&pages, &manifest_location, &metadata, &mut live)?;
    if observed.manifest() != &manifest || pages.inventory(&mut live)? != physical {
        return Err(
            "actual complete direct progress allocation closure differs before dispatch".into(),
        );
    }
    let delta = next
        .storage
        .as_ref()
        .and_then(|value| value.parent_allocation.as_ref())
        .ok_or("direct progress lost the independently measured parent delta")?;
    parents::verify_after(&pages, delta, &mut live)?;
    let growth = delta
        .after
        .allocated_bytes
        .checked_sub(delta.before.allocated_bytes)
        .ok_or("direct parent blocks decreased")?;
    let added = observed.physical();
    let accounted = paged::PhysicalInventory {
        files: before
            .files
            .checked_add(added.files)
            .ok_or("progress accounted files overflow")?,
        directories: before
            .directories
            .checked_add(added.directories)
            .ok_or("progress accounted directories overflow")?,
        logical_bytes: before
            .logical_bytes
            .checked_add(added.logical_bytes)
            .ok_or("progress accounted logical bytes overflow")?,
        allocated_bytes: before
            .allocated_bytes
            .checked_add(added.allocated_bytes)
            .and_then(|n| n.checked_add(growth))
            .ok_or("progress accounted allocations overflow")?,
        interrupted_files: before
            .interrupted_files
            .checked_add(added.interrupted_files)
            .ok_or("progress accounted incomplete count overflow")?,
    };
    if accounted != physical {
        return Err("direct progress global delta contains an unexplained physical allocation before dispatch".into());
    }
    live()?;
    drop(live);
    let controls = cells::Files::open(&pages, previous_storage.controls.clone(), &mut || {
        authority.check()
    })?;
    let pending = control::PendingCell {
        schema_version: 3,
        domain: "luma-c-direct-slot-pending-v3".into(),
        binding: previous.binding.clone(),
        base: control::Base::Slot { index, cell },
        inactive_index: 1 - index,
        next: control::Cell::for_descriptor(&next, next_location)?,
        event_sha256: next.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&next.operation)?),
    };
    let mut old_pin = || -> Result<()> {
        pages.check()?;
        if anchor.read()? != old {
            return Err("actual C changed during exact control staging".into());
        }
        Ok(())
    };
    let mut original = COperation::Admin(authority);
    let staged = control::stage(
        &controls,
        pending,
        Some(&previous),
        &next,
        old,
        &mut DescriptorRead {
            pages: &pages,
            check: &mut old_pin,
        },
        &mut original,
    )?;
    staged.check(&controls, &mut original)?;
    old_pin()?;
    original.check()?;
    drop(old_pin);
    if anchor.read()? != old {
        return Err("actual C changed immediately before sole direct progress dispatch".into());
    }
    let actual = anchor.advance(old, tpm::decode(&next.event_sha256)?)?;
    let expected = tpm::decode::<32>(&next.selected_nv_head)?;
    if actual != expected || anchor.read()? != expected {
        return Err("direct progress checkpoint outcome remains uncertain".into());
    }
    staged.check(&controls, &mut original)?;
    let snapshot = controls.read(2, &mut || original.check())?;
    if snapshot.bytes()
        != (control::PendingFrame::Prepared {
            pending: staged.pending.clone(),
        })
        .frame()?
    {
        return Err("direct progress pending changed after actual C dispatch".into());
    }
    controls.rewrite(
        &snapshot,
        &control::PendingFrame::Completed {
            pending: staged.pending,
        }
        .frame()?,
        &mut || {
            original.check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during fixed progress completion".into());
            }
            original.check()
        },
    )?;
    original.check()?;
    drop(original);
    drop(directory);
    drop(controls);
    Backend::open(anchor, files, previous.binding, &mut || authority.check())
}
