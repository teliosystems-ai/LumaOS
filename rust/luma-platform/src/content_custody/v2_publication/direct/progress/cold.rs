//! A cold current-C join reconstructs just the selected transition, not every
//! historical window. All source addresses descend from the complete descriptor
//! selected by the actual existing anchor. An unselected pending attempt must
//! still be independently reconciled; this module never redispatches it.
use super::*;

struct Data<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    locations: &'a locations::Root,
    check: &'b mut F,
    context: map::Context,
    cache: BTreeMap<String, Vec<u8>>,
    bytes: usize,
    readonly: bool,
}
impl<F: FnMut() -> Result<()>> locations::Io for Data<'_, '_, F> {
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
        Err("cold selected C proof cannot seal a physical index node".into())
    }
}
impl<F: FnMut() -> Result<()>> map::CustodyIo for Data<'_, '_, F> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if self.readonly && (budget.write_bytes != 0 || budget.new_files != 0)
            || budget.write_bytes > CACHE_BYTES as u64
            || budget.new_files > CACHE_PAGES as u32
        {
            return Err("cold transition exceeds its memory-only reconstruction budget".into());
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        if context != &self.context {
            return Err("cold transition substitutes the actual current C context".into());
        }
        locations::Io::check(self)
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum == 0 || maximum > PAGE_BYTES {
            return Err("cold C page read exceeds one bounded page".into());
        }
        let bytes = if let Some(bytes) = self.cache.get(sha) {
            bytes.clone()
        } else {
            let root = self.locations.clone();
            let location = locations::lookup(&root, sha, self)?
                .ok_or("actual current C has no selected semantic page address")?;
            if location.slot.kind != slots::Kind::Page {
                return Err("semantic page resolves to a different selected kind".into());
            }
            locations::Io::read(self, &location)?
        };
        if bytes.len() > maximum || hash(&bytes) != sha {
            return Err("cold C page complete bytes/hash differ".into());
        }
        self.check_current(context)?;
        Ok(bytes)
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        if self.readonly || bytes.is_empty() || bytes.len() > PAGE_BYTES {
            return Err("cold C replay cannot exceed its memory-only page profile".into());
        }
        let sha = hash(bytes);
        if let Some(old) = self.cache.get(&sha) {
            if old != bytes {
                return Err("cold C memory reconstruction digest collision".into());
            }
            return self.check_current(context);
        }
        if self.cache.len() >= CACHE_PAGES
            || self
                .bytes
                .checked_add(bytes.len())
                .map_or(true, |n| n > CACHE_BYTES)
        {
            return Err("cold C memory reconstruction exhausted before allocation".into());
        }
        self.bytes += bytes.len();
        self.cache.insert(sha, bytes.to_vec());
        self.check_current(context)
    }
}

pub(in crate::content_checkpoint::custody) fn verify_selected(
    files: &Files,
    pages: &PageStore,
    current: &Descriptor,
    location: &slots::SealedReference,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    current.validate()?;
    let storage = current
        .storage
        .as_ref()
        .ok_or("cold direct progress has no selected storage")?;
    if current.sequence <= 1
        || storage.schema_version != 2
        || storage.descriptor_slot != location.slot
        || location.sha256 != hash(&current.slot_frame()?)
        || location.bytes != PAGE_BYTES as u64
    {
        return Err("cold direct progress is not its exact selected descriptor location".into());
    }
    let OperationData::BootstrapProgress {
        previous_retirement: None,
        window_intent_sha256,
        request_sha256,
        source_sha256,
        ..
    } = &current.operation
    else {
        return Err("cold direct progress does not accept a different semantic event class".into());
    };
    let journal_bytes = files.read(JOURNAL, check)?;
    let journal: Journal = canonical(&journal_bytes, MAX_JOURNAL)?;
    let blueprint = Blueprint::verified_legacy(&current.binding, &current.legacy, &journal)?;
    blueprint.require_phase(&current.phase)?;
    let context = map::Context {
        binding: current.binding.clone(),
        selected_descriptor_sha256: hash(&current.bytes()?),
        selected_nv_head: current.selected_nv_head.clone(),
        review_sha256: None,
    };
    let mut data = Data {
        pages,
        locations: &storage.locations,
        check,
        context: context.clone(),
        cache: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let previous_sha = current
        .previous_descriptor_sha256
        .as_ref()
        .ok_or("cold progress has no previous full-frame commitment")?;
    let previous_location = locations::lookup(&storage.locations, previous_sha, &mut data)?
        .ok_or("cold progress lost the exact selected previous descriptor address")?;
    let previous =
        Descriptor::from_slot_frame(&locations::Io::read(&mut data, &previous_location)?)?;
    if previous_location.sha256 != *previous_sha
        || previous.binding != current.binding
        || previous.legacy != current.legacy
        || previous.sequence.checked_add(1) != Some(current.sequence)
        || previous.global_ordinal.checked_add(1) != Some(current.global_ordinal)
        || previous.selected_nv_head != current.previous_nv_head
        || !matches!(previous.operation, OperationData::BootstrapProgress { .. })
    {
        return Err("cold progress does not continue the exact authenticated old typed cut".into());
    }
    blueprint.require_phase(&previous.phase)?;
    previous.phase.require_successor(&current.phase)?;
    let from = usize::try_from(previous.phase.copied_entries)?;
    let to = from
        .checked_add(1)
        .ok_or("cold projection cursor overflow")?
        .min(blueprint.rows.len());
    let base = Selector::for_descriptor(&previous)?;
    let logical = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-logical-v4",
        &previous.binding,
        &base,
        previous_sha,
        &previous.phase,
        from,
        to,
        hash(&serde_json::to_vec(&blueprint.rows[from..to])?),
    ))?);
    // Memory-only replay still prepares map pages, so it binds the same exact
    // reviewed window identity as the original planner, never an absent review.
    let context = map::Context {
        review_sha256: Some(logical.clone()),
        ..context
    };
    data.context = context.clone();
    let mut roots = previous.roots.clone();
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
            &mut data,
        )?;
        data.readonly = true;
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
            &mut data,
        )?;
        data.readonly = false;
        roots.set_role(role, next)?;
    }
    if roots != current.roots {
        return Err("cold progress role roots differ from independent genuine row replay".into());
    }
    let new_pages = std::mem::take(&mut data.cache);
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("cold previous direct storage absent")?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("cold previous job index absent")?;
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("cold current job index absent")?;
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-single-row-job-v4",
        &previous.binding,
        previous_sha,
        &logical,
    ))?);
    let mut keys = new_pages.keys().cloned().collect::<Vec<_>>();
    keys.push(previous_sha.clone());
    keys.sort();
    let location_nodes =
        locations::planning::new_locations(&previous_storage.locations, &keys, &mut data)?
            .new_nodes;
    let job_nodes =
        locations::planning::new_jobs(old_jobs, std::slice::from_ref(&job), &mut data)?.new_nodes;
    let planned = complete_plan(
        &previous,
        &blueprint,
        roots,
        new_pages,
        location_nodes,
        job_nodes,
    )?;
    if planned.window_sha256 != *window_intent_sha256
        || planned.phase != current.phase
        || planned.job != job
        || storage.controls != previous_storage.controls
        || storage.descriptor_slot.job != job
    {
        return Err(
            "cold C progress differs from its deterministic reviewed exact layout/phase".into(),
        );
    }
    let manifest_location = jobs
        .lookup(&job, &mut data)?
        .ok_or("cold C progress has no selected allocation manifest")?;
    let manifest = Manifest::from_canonical(&locations::Io::read(&mut data, &manifest_location)?)?;
    let semantic = planned.pages.len();
    let manifest_index = semantic + planned.location_nodes;
    let descriptor_index = planned.specs.len() - 1;
    if manifest.layout != slots::Plan::exact(&current.binding, &job, planned.specs.clone())?
        || manifest.base_descriptor_sha256 != planned.base.descriptor_sha256
        || manifest.original_request_sha256 != *request_sha256
        || manifest.source_sha256 != *source_sha256
        || manifest.review_sha256 != *window_intent_sha256
        || manifest.previous.is_some()
        || manifest.own_slot as usize != manifest_index
        || manifest.members[descriptor_index].slot != storage.descriptor_slot
    {
        return Err(
            "cold C manifest changes selected source, review, membership or exact sizes".into(),
        );
    }
    let location_witnesses =
        locations::planning::selected_location_nodes(&storage.locations, &job, &mut data)?;
    let job_witnesses = locations::planning::selected_job_nodes(jobs, &job, &mut data)?;
    if location_witnesses.len() != planned.location_nodes
        || job_witnesses.len() != planned.job_nodes
    {
        return Err(
            "cold C selected index metadata omits/adds an exact reviewed physical member".into(),
        );
    }
    let mut metadata = BTreeMap::from([
        (manifest_index as u32, manifest_location.clone()),
        (descriptor_index as u32, location.clone()),
    ]);
    for reference in location_witnesses.iter().chain(&job_witnesses) {
        if metadata
            .insert(reference.slot.number, reference.clone())
            .is_some()
        {
            return Err("cold C metadata aliases a selected slot".into());
        }
    }
    let mut insertions = vec![locations::Insertion {
        sha256: previous_sha.clone(),
        location: previous_location,
    }];
    for (number, (sha, bytes)) in planned.pages.iter().enumerate() {
        let member = &manifest.members[number];
        let Disposition::Sealed { value } = &member.disposition else {
            return Err("cold C semantic page is not actually sealed".into());
        };
        if member.role != Role::SemanticPage
            || value.sha256 != *sha
            || locations::Io::read(&mut data, value)? != *bytes
        {
            return Err(
                "cold C semantic bytes do not equal complete deterministic reconstruction".into(),
            );
        }
        insertions.push(locations::Insertion {
            sha256: sha.clone(),
            location: value.clone(),
        });
    }
    insertions.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    locations::verify_insertions(
        &previous_storage.locations,
        &storage.locations,
        &insertions,
        &location_witnesses,
        &mut data,
    )?;
    old_jobs.verify_update(
        jobs,
        &[locations::JobEdit {
            job: job.clone(),
            previous: None,
            next: manifest_location.clone(),
        }],
        &job_witnesses,
        &mut data,
    )?;
    for (number, member) in manifest.members.iter().enumerate() {
        let expected_role = if number < semantic {
            Role::SemanticPage
        } else if number < manifest_index {
            Role::LocationIndex
        } else if number == manifest_index {
            Role::Manifest
        } else if number < descriptor_index {
            Role::JobIndex
        } else {
            Role::Descriptor
        };
        if member.role != expected_role
            || (number >= semantic && member.disposition != Disposition::BoundMetadata)
        {
            return Err("cold C current allocation member changes semantic/metadata role".into());
        }
    }
    let observed = jobs::observe(pages, &manifest_location, &metadata, data.check)?;
    let old = &previous_storage.post_allocation;
    let added = observed.physical();
    let expected = paged::PhysicalInventory {
        files: old
            .files
            .checked_add(added.files)
            .ok_or("cold C file total overflow")?,
        directories: old
            .directories
            .checked_add(added.directories)
            .ok_or("cold C directory total overflow")?,
        logical_bytes: old
            .logical_bytes
            .checked_add(added.logical_bytes)
            .ok_or("cold C logical total overflow")?,
        allocated_bytes: old
            .allocated_bytes
            .checked_add(added.allocated_bytes)
            .ok_or("cold C allocation total overflow")?,
        interrupted_files: old
            .interrupted_files
            .checked_add(added.interrupted_files)
            .ok_or("cold C incomplete total overflow")?,
    };
    let parent_delta = storage
        .parent_allocation
        .as_ref()
        .ok_or("current C progress omits the exact existing-parent allocation delta")?;
    parents::verify_after(pages, parent_delta, data.check)?;
    if let Some(previous_delta) = &previous_storage.parent_allocation {
        if previous_delta.after != parent_delta.before {
            return Err(
                "current C parent delta changes the prior selected parent observation".into(),
            );
        }
    }
    let mut charged = expected;
    let growth = parent_delta
        .after
        .allocated_bytes
        .checked_sub(parent_delta.before.allocated_bytes)
        .ok_or("cold selected parent lost blocks")?;
    charged.allocated_bytes = charged
        .allocated_bytes
        .checked_add(growth)
        .ok_or("cold parent allocation total overflow")?;
    if observed.manifest() != &manifest
        || charged != storage.post_allocation
        || pages.inventory(data.check)? != charged
    {
        return Err(
            "cold C actual complete physical closure differs from its selected exact delta".into(),
        );
    }
    (data.check)()
}
