//! One freshly reviewed restart of the first direct bootstrap. Failed slots
//! are retained under the new event's job index and an immutable full-record
//! reference. No opener, protocol endpoint or unchecked descriptor setter is
//! provided by this internal consumer.
use super::super::super::paged::{cells, slots};
use super::super::*;
use super::jobs::{self, Disposition, Manifest, Member, Role};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAttempt {
    schema_version: u32,
    domain: String,
    retirement: control::InitialRetirement,
    descriptor: slots::SealedReference,
    manifest: slots::SealedReference,
    job_node: slots::SealedReference,
}
impl RetainedAttempt {
    fn bytes(&self) -> Result<Vec<u8>> {
        self.retirement.validate_data()?;
        for reference in [&self.descriptor, &self.manifest, &self.job_node] {
            reference.validate_data()?;
        }
        let control::Cell::Selected { descriptor, .. } = &self.retirement.pending.next else {
            return Err("retained failed descriptor is absent".into());
        };
        if self.schema_version != 4
            || self.domain != "luma-c-retained-first-direct-attempt-v4"
            || descriptor != &self.descriptor
            || self.manifest.slot.kind != slots::Kind::Record
            || self.job_node.slot.kind != slots::Kind::Page
        {
            return Err(
                "retained first attempt changes exact original allocation references".into(),
            );
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 16 * 1024 {
            return Err("retained first attempt exceeds its reviewed slot".into());
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 16 * 1024)?;
        if value.bytes()? != bytes {
            return Err("retained first attempt is not exact canonical DATA".into());
        }
        Ok(value)
    }
}
fn specs() -> Result<Vec<slots::ExactSlot>> {
    [
        (slots::Kind::Record, 16 * 1024),
        (slots::Kind::Page, PAGE_BYTES as u64),
        (slots::Kind::Record, 16 * 1024),
        (slots::Kind::Page, PAGE_BYTES as u64),
        (slots::Kind::Page, PAGE_BYTES as u64),
    ]
    .into_iter()
    .map(|(kind, bytes)| slots::ExactSlot::for_bytes(slots::Pool::Publication(0), kind, bytes))
    .collect()
}
struct Io<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    check: &'b mut F,
}
impl<F: FnMut() -> Result<()>> locations::Io for Io<'_, '_, F> {
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
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("restart readback cannot allocate".into())
    }
}
fn read(
    pages: &PageStore,
    reference: &slots::SealedReference,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    locations::Io::read(&mut Io { pages, check }, reference)
}
fn intent(
    record: &RetainedAttempt,
    phase: &bootstrap::Phase,
    binding: &map::CustodyBinding,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        "luma-c-fresh-first-direct-resume-v4",
        binding,
        &phase.review_sha256,
        hash(&record.bytes()?),
        specs()?,
        "retain-failed-slots;new-request-and-operation;one-dispatch;no-post-NV-allocation",
    ))?))
}
/// Original checkpoint and the retained journal independently reconstruct the
/// original failed event. Its former serialized post-allocation counters are
/// DATA, not permission to exclude later allocations from the current count.
fn original(
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    record: &RetainedAttempt,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Descriptor, jobs::ObservedManifest)> {
    record.bytes()?;
    let descriptor = Descriptor::from_slot_frame(&read(pages, &record.descriptor, check)?)?;
    record
        .retirement
        .pending
        .verify_descriptors(None, &descriptor)?;
    let OperationData::BootstrapProgress {
        previous_retirement: None,
        request_sha256,
        source_sha256,
        window_intent_sha256,
        original_authority,
        ..
    } = &descriptor.operation
    else {
        return Err("fresh first restart cannot adopt a prior restart or ordinary event".into());
    };
    if descriptor.binding != *binding
        || descriptor.roots != Roots::empty(binding)?
        || record.retirement.original_recovery.operation_id == original_authority.operation_id
        || record.retirement.recovery_request_sha256 == *request_sha256
    {
        return Err(
            "retained first restart changes binding, roots or separate recovery provenance".into(),
        );
    }
    validate_genesis_at(
        &files.root,
        &binding.installation,
        tpm::decode(&binding.sealed_genesis_sha256)?,
    )?;
    let journal: Journal = canonical(&files.read(JOURNAL, check)?, MAX_JOURNAL)?;
    let blueprint = bootstrap::Blueprint::verified_legacy(binding, &descriptor.legacy, &journal)?;
    let phase = blueprint.initial_phase()?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: descriptor.legacy.clone(),
    }
    .selector()?;
    if descriptor.phase != phase
        || *window_intent_sha256 != super::initial::window_intent(&blueprint, &phase, &base)?
        || capacity::remaining(&journal.validate()?)?.outstanding_restore_batches != 0
    {
        return Err(
            "retained failed event does not reconstruct its genuine complete legacy projection"
                .into(),
        );
    }
    let storage = descriptor
        .storage
        .as_ref()
        .ok_or("retained original storage absent")?;
    let old_jobs = storage
        .jobs
        .as_ref()
        .ok_or("retained original job membership absent")?;
    let node = old_jobs
        .root_node()?
        .ok_or("retained original job tree empty")?;
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-bootstrap-allocation-v4",
        binding,
        request_sha256,
        window_intent_sha256,
    ))?);
    if old_jobs.entries() != 1
        || node.entries != 1
        || node.height != 0
        || node.location != record.job_node
        || storage.schema_version != 2
        || storage.locations.entries != 0
        || storage.post_allocation.files != 8
        || storage.post_allocation.directories != 7
        || storage.post_allocation.interrupted_files != 0
        || old_jobs
            .lookup(
                &job,
                &mut Io {
                    pages,
                    check: &mut *check,
                },
            )?
            .as_ref()
            != Some(&record.manifest)
    {
        return Err("retained failed job index has substituted membership or metadata".into());
    }
    let observed = jobs::observe(
        pages,
        &record.manifest,
        &BTreeMap::from([
            (0, record.manifest.clone()),
            (1, record.job_node.clone()),
            (2, record.descriptor.clone()),
        ]),
        check,
    )?;
    let manifest = observed.manifest();
    if manifest.layout != slots::Plan::exact(binding, &job, super::initial::specifications()?)?
        || manifest.own_slot != 0
        || manifest.previous.is_some()
        || manifest.job != job
        || manifest.base_descriptor_sha256
            != hash(&serde_json::to_vec(&BaseSnapshot::Legacy {
                binding: binding.clone(),
                cut: descriptor.legacy.clone(),
            })?)
        || manifest.original_request_sha256 != *request_sha256
        || manifest.review_sha256 != *window_intent_sha256
        || manifest.source_sha256 != *source_sha256
        || !manifest.closed()?
        || manifest.members.iter().enumerate().any(|(index, member)| {
            member.role != [Role::Manifest, Role::JobIndex, Role::Descriptor][index]
                || member.disposition != Disposition::BoundMetadata
        })
    {
        return Err("retained original allocation is not the exact immutable first job".into());
    }
    if record.retirement.cells[1 - record.retirement.pending.inactive_index as usize]
        != control::Cell::empty_data(binding)?
        || record.retirement.review_sha256
            != hash(&serde_json::to_vec(&(
                "luma-c-direct-old-nv-retirement-v4",
                binding,
                &record.retirement.pending,
                &record.retirement.cells,
                descriptor.bytes()?,
                observed.location(),
                observed.physical(),
                &storage.controls,
                &descriptor.previous_nv_head,
            ))?)
    {
        return Err("retained first attempt changes the complete independently reconstructed old-NV recovery review".into());
    }
    check()?;
    Ok((descriptor, observed))
}
fn load<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(RetainedAttempt, Descriptor, String)> {
    let proposal = super::retired::review(anchor, files, pages, binding, check)?;
    if proposal["already_retired"] != true {
        return Err("fresh restart requires an explicitly completed original retirement".into());
    }
    let old = anchor.read()?;
    let mut live = || -> Result<()> {
        check()?;
        if anchor.read()? != old {
            return Err("old C changed during restart review".into());
        }
        check()
    };
    let controls = cells::Files::observe(pages, &mut live)?;
    let control::PendingFrame::RetiredInitial { retirement } =
        control::PendingFrame::from_frame(controls.read(2, &mut live)?.bytes())?
    else {
        return Err("retired first controls changed before restart review".into());
    };
    let control::Cell::Selected {
        descriptor: location,
        ..
    } = &retirement.pending.next
    else {
        return Err("retired descriptor lost".into());
    };
    let descriptor = Descriptor::from_slot_frame(&read(pages, location, &mut live)?)?;
    let jobs = descriptor
        .storage
        .as_ref()
        .and_then(|s| s.jobs.as_ref())
        .ok_or("retired membership absent")?;
    let OperationData::BootstrapProgress {
        request_sha256,
        window_intent_sha256,
        ..
    } = &descriptor.operation
    else {
        return Err("retired bootstrap source absent".into());
    };
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-bootstrap-allocation-v4",
        binding,
        request_sha256,
        window_intent_sha256,
    ))?);
    let manifest = jobs
        .lookup(
            &job,
            &mut Io {
                pages,
                check: &mut live,
            },
        )?
        .ok_or("retired manifest absent")?;
    let node = jobs
        .root_node()?
        .ok_or("retired job root empty")?
        .location
        .clone();
    let record = RetainedAttempt {
        schema_version: 4,
        domain: "luma-c-retained-first-direct-attempt-v4".into(),
        descriptor: location.clone(),
        manifest,
        job_node: node,
        retirement,
    };
    let (verified, _) = original(files, pages, binding, &record, &mut live)?;
    if verified.bytes()? != descriptor.bytes()?
        || tpm::decode::<32>(&verified.previous_nv_head)? != old
        || descriptor
            .storage
            .as_ref()
            .ok_or("retired storage absent")?
            .controls
            != *controls.selection()
        || pages.inventory(&mut live)?
            != descriptor
                .storage
                .as_ref()
                .ok_or("retired physical cut absent")?
                .post_allocation
    {
        return Err("fresh restart changes original failed descriptor or actual old C".into());
    }
    live()?;
    Ok((
        record,
        descriptor,
        proposal["attempt_sha256"]
            .as_str()
            .ok_or("retirement attempt missing")?
            .into(),
    ))
}
pub(super) fn review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (record, descriptor, attempt) = load(anchor, files, pages, binding, check)?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-fresh-first-direct-resume-v4",
        "stable_review_sha256":descriptor.phase.review_sha256,
        "window_intent_sha256":intent(&record,&descriptor.phase,binding)?,
        "attempt_sha256":attempt,"expected_selected_descriptor_sha256":null,
        "failed_allocations_retained":true,"filesystem_changed":false,"TPM_extended":false,
        "authority_returned":false,"production_qualified":false}),
    )
}

/// A single actual node writer. The reviewed finite first-restart profile has
/// at most two jobs and one retained-record location; a split is a refusal,
/// never creation of an unreviewed extra inode.
struct Index<'a, 'b, 'c, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    directory: &'a slots::Directory<'b>,
    reference: &'a slots::Reference,
    check: &'c mut F,
    witnesses: Vec<slots::SealedReference>,
}
impl<F: FnMut() -> Result<()>> locations::Io for Index<'_, '_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        read(self.pages, reference, self.check)
    }
    fn seal_node(&mut self, bytes: &[u8]) -> Result<slots::SealedReference> {
        self.check()?;
        if !self.witnesses.is_empty() {
            return Err("fresh first restart exceeds its single exact index node".into());
        }
        let location = self.directory.fill(
            self.reference,
            slots::Pool::Publication(0),
            bytes,
            self.check,
        )?;
        self.witnesses.push(location.clone());
        Ok(location)
    }
}

fn require_fresh(
    authority: &mut OriginalCAdminOperation<'_>,
    binding: &map::CustodyBinding,
    record: &RetainedAttempt,
    failed: &Descriptor,
    window: &str,
    attempt: &str,
) -> Result<()> {
    bootstrap::require_admin(
        authority,
        binding,
        &failed.phase,
        window,
        None,
        Some(attempt),
    )?;
    let OperationData::BootstrapProgress {
        request_sha256,
        original_authority,
        ..
    } = &failed.operation
    else {
        return Err("fresh restart lost original failed bootstrap attribution".into());
    };
    let source = authority.source_binding();
    let current = authority.audit();
    if source.request_sha256 == *request_sha256
        || source.request_sha256 == record.retirement.recovery_request_sha256
        || current.operation_id == original_authority.operation_id
        || current.operation_id == record.retirement.original_recovery.operation_id
    {
        return Err("restart reuses the failed bootstrap or retirement request/operation".into());
    }
    authority.check()
}

pub(super) fn begin<A: Checkpoint>(
    mut anchor: A,
    files: Files,
    pages: PageStore,
    binding: map::CustodyBinding,
    expected_window: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<super::initial::Current<A>> {
    let (record, failed, attempt) = load(&mut anchor, &files, &pages, &binding, &mut || {
        authority.check()
    })?;
    let window = intent(&record, &failed.phase, &binding)?;
    if window != expected_window {
        return Err("restart needs the exact current retained-attempt/allocation review".into());
    }
    require_fresh(authority, &binding, &record, &failed, &window, &attempt)?;
    let old = tpm::decode::<32>(&failed.previous_nv_head)?;
    let request = authority.source_binding().request_sha256.clone();
    let source = hash(&COperation::Admin(authority).source_bytes()?);
    let operation = OperationData::BootstrapProgress {
        previous_retirement: Some(hash(&record.bytes()?)),
        review_sha256: failed.phase.review_sha256.clone(),
        window_intent_sha256: window.clone(),
        request_sha256: request.clone(),
        source_sha256: source.clone(),
        original_authority: authority.audit().clone(),
    };
    let before = pages.inventory(&mut || authority.check())?;
    let mut live = || -> Result<()> {
        authority.check()?;
        pages.check()?;
        if anchor.read()? != old {
            return Err("old C changed during fresh restart preparation".into());
        }
        authority.check()
    };
    pages.admit_writes(1024 * 1024, 10, 2, &mut live)?;
    let controls = cells::Files::open(
        &pages,
        failed
            .storage
            .as_ref()
            .ok_or("failed controls absent")?
            .controls
            .clone(),
        &mut live,
    )?;
    let baseline = [
        controls.read(0, &mut live)?,
        controls.read(1, &mut live)?,
        controls.read(2, &mut live)?,
    ];
    if control::PendingFrame::from_frame(baseline[2].bytes())?.frame()?
        != (control::PendingFrame::RetiredInitial {
            retirement: record.retirement.clone(),
        })
        .frame()?
        || control::Cell::from_frame(baseline[0].bytes())? != record.retirement.cells[0]
        || control::Cell::from_frame(baseline[1].bytes())? != record.retirement.cells[1]
    {
        return Err("fixed retired controls changed before fresh restart preparation".into());
    }
    let job = hash(&serde_json::to_vec(&(
        "luma-c-fresh-first-restart-job-v4",
        &binding,
        &request,
        &window,
        &attempt,
    ))?);
    let plan = slots::Plan::exact(&binding, &job, specs()?)?;
    let directory = slots::Directory::create(&pages, plan.clone(), &mut live)?;
    let refs = directory.allocate_window(0, 5, &mut live)?;
    let namespace = directory.observe_namespace(&mut live)?;
    let retained = directory.fill(
        &refs[0],
        slots::Pool::Publication(0),
        &record.bytes()?,
        &mut live,
    )?;
    let location_entry = locations::Insertion {
        sha256: retained.sha256.clone(),
        location: retained.clone(),
    };
    let empty_locations = locations::Root::empty_data(&binding)?;
    let mut location_io = Index {
        pages: &pages,
        directory: &directory,
        reference: &refs[1],
        check: &mut live,
        witnesses: Vec::new(),
    };
    let locations = locations::insert(
        &empty_locations,
        std::slice::from_ref(&location_entry),
        &mut location_io,
    )?;
    let location_nodes = location_io.witnesses.clone();
    locations::verify_insertions(
        &empty_locations,
        &locations,
        std::slice::from_ref(&location_entry),
        &location_nodes,
        &mut location_io,
    )?;
    drop(location_io);
    let allocated = refs.iter().try_fold(
        namespace
            .allocated_bytes
            .checked_add(namespace.identity_allocated_bytes)
            .ok_or("restart namespace accounting overflow")?,
        |total, reference| {
            total
                .checked_add(reference.allocated_bytes)
                .ok_or("restart slot accounting overflow")
        },
    )?;
    let manifest = Manifest {
        schema_version: 4,
        domain: "luma-c-reviewed-job-allocation-v4".into(),
        binding: binding.clone(),
        job: job.clone(),
        base_descriptor_sha256: hash(&serde_json::to_vec(&BaseSnapshot::Legacy {
            binding: binding.clone(),
            cut: failed.legacy.clone(),
        })?),
        original_request_sha256: request,
        review_sha256: window.clone(),
        source_sha256: source,
        previous: None,
        own_slot: 2,
        layout: plan,
        namespace,
        members: refs
            .iter()
            .enumerate()
            .map(|(index, slot)| Member {
                slot: slot.clone(),
                role: [
                    Role::SemanticRecord,
                    Role::LocationIndex,
                    Role::Manifest,
                    Role::JobIndex,
                    Role::Descriptor,
                ][index],
                disposition: if index == 0 {
                    Disposition::Sealed {
                        value: retained.clone(),
                    }
                } else {
                    Disposition::BoundMetadata
                },
            })
            .collect(),
        allocated_bytes: allocated,
    };
    let manifest_location = directory.fill(
        &refs[2],
        slots::Pool::Publication(0),
        &manifest.canonical_bytes()?,
        &mut live,
    )?;
    let old_jobs = failed
        .storage
        .as_ref()
        .and_then(|s| s.jobs.as_ref())
        .ok_or("failed selected job root absent")?;
    let job_edit = locations::JobEdit {
        job,
        previous: None,
        next: manifest_location.clone(),
    };
    let mut job_io = Index {
        pages: &pages,
        directory: &directory,
        reference: &refs[3],
        check: &mut live,
        witnesses: Vec::new(),
    };
    let jobs = old_jobs.update(std::slice::from_ref(&job_edit), &mut job_io)?;
    let job_nodes = job_io.witnesses.clone();
    old_jobs.verify_update(
        &jobs,
        std::slice::from_ref(&job_edit),
        &job_nodes,
        &mut job_io,
    )?;
    drop(job_io);
    let mut physical = pages.inventory(&mut live)?;
    if physical.interrupted_files != 1
        || physical.files
            != before
                .files
                .checked_add(6)
                .ok_or("restart file count overflow")?
        || physical.directories
            != before
                .directories
                .checked_add(1)
                .ok_or("restart directory count overflow")?
    {
        return Err("restart contains unknown partial or extra namespace allocations".into());
    }
    physical.interrupted_files = 0;
    physical.logical_bytes = physical
        .logical_bytes
        .checked_add(PAGE_BYTES as u64)
        .ok_or("restart descriptor count overflow")?;
    let descriptor = Descriptor {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: binding.clone(),
        sequence: 1,
        global_ordinal: failed
            .legacy
            .events
            .checked_add(2)
            .ok_or("restart global ordinal overflow")?,
        previous_descriptor_sha256: None,
        previous_nv_head: failed.legacy.nv_head.clone(),
        event_sha256: String::new(),
        selected_nv_head: String::new(),
        legacy: failed.legacy.clone(),
        roots: Roots::empty(&binding)?,
        phase: failed.phase.clone(),
        operation,
        storage: Some(StorageSelection {
            schema_version: 2,
            controls: controls.selection().clone(),
            locations,
            jobs: Some(jobs),
            descriptor_slot: refs[4].clone(),
            post_allocation: physical.clone(),
            parent_allocation: None,
        }),
    }
    .seal()?;
    let descriptor_location = directory.fill(
        &refs[4],
        slots::Pool::Publication(0),
        &descriptor.slot_frame()?,
        &mut live,
    )?;
    let observed = jobs::observe(
        &pages,
        &manifest_location,
        &BTreeMap::from([
            (
                1,
                location_nodes
                    .first()
                    .ok_or("restart location witness absent")?
                    .clone(),
            ),
            (2, manifest_location.clone()),
            (
                3,
                job_nodes
                    .first()
                    .ok_or("restart job witness absent")?
                    .clone(),
            ),
            (4, descriptor_location.clone()),
        ]),
        &mut live,
    )?;
    let (_, old_manifest) = original(&files, &pages, &binding, &record, &mut live)?;
    if observed.manifest() != &manifest
        || old_manifest.location() != &record.manifest
        || pages.inventory(&mut live)? != physical
    {
        return Err("restart actual complete allocation/source readback differs from reviewed retained closure".into());
    }
    for (index, snapshot) in baseline.iter().enumerate() {
        if controls.read(index, &mut live)?.bytes() != snapshot.bytes() {
            return Err("retired controls drifted during restart allocations".into());
        }
    }
    live()?;
    drop(live);
    require_fresh(authority, &binding, &record, &failed, &window, &attempt)?;
    let inactive = 1 - record.retirement.pending.inactive_index;
    let pending = control::PendingCell {
        schema_version: 3,
        domain: "luma-c-direct-slot-pending-v3".into(),
        binding: binding.clone(),
        base: control::Base::Legacy {
            binding: binding.clone(),
            cut: failed.legacy.clone(),
        },
        inactive_index: inactive,
        next: control::Cell::for_descriptor(&descriptor, descriptor_location)?,
        event_sha256: descriptor.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&descriptor.operation)?),
    };
    pending.verify_descriptors(None, &descriptor)?;
    let mut old_live = || -> Result<()> {
        authority.check()?;
        if anchor.read()? != old {
            return Err("C changed before restart's sole dispatch".into());
        }
        authority.check()
    };
    for (index, snapshot) in baseline.iter().enumerate() {
        if controls.read(index, &mut old_live)?.bytes() != snapshot.bytes() {
            return Err("retired control changed before prepared restart".into());
        }
    }
    let pending_frame = control::PendingFrame::Prepared {
        pending: pending.clone(),
    }
    .frame()?;
    let after_pending = controls.rewrite(&baseline[2], &pending_frame, &mut old_live)?;
    let after_next = controls.rewrite(
        &baseline[inactive as usize],
        &pending.next.frame()?,
        &mut old_live,
    )?;
    if controls.read(2, &mut old_live)?.bytes() != after_pending.bytes()
        || controls.read(inactive as usize, &mut old_live)?.bytes() != after_next.bytes()
        || controls.read(1 - inactive as usize, &mut old_live)?.bytes()
            != baseline[1 - inactive as usize].bytes()
    {
        return Err(
            "fresh restart changed preserved failed selector or staged control readback".into(),
        );
    }
    old_live()?;
    drop(old_live);
    require_fresh(authority, &binding, &record, &failed, &window, &attempt)?;
    if anchor.read()? != old {
        return Err("actual C changed immediately before restart dispatch".into());
    }
    let actual = anchor.advance(old, tpm::decode(&descriptor.event_sha256)?)?;
    let expected = tpm::decode(&descriptor.selected_nv_head)?;
    if actual != expected || anchor.read()? != expected {
        return Err("fresh restart checkpoint outcome remains uncertain".into());
    }
    let mut new_live = || -> Result<()> {
        authority.check()?;
        if anchor.read()? != expected {
            return Err("C changed during restarted fixed-inode completion".into());
        }
        authority.check()
    };
    if controls.read(2, &mut new_live)?.bytes() != pending_frame
        || controls.read(inactive as usize, &mut new_live)?.bytes() != after_next.bytes()
        || controls.read(1 - inactive as usize, &mut new_live)?.bytes()
            != baseline[1 - inactive as usize].bytes()
    {
        return Err("restart control outcome drifted after actual C dispatch".into());
    }
    let snapshot = controls.read(2, &mut new_live)?;
    controls.rewrite(
        &snapshot,
        &control::PendingFrame::Completed { pending }.frame()?,
        &mut new_live,
    )?;
    new_live()?;
    drop(new_live);
    drop(directory);
    drop(controls);
    let verified = verify_current(&mut anchor, &files, &pages, &binding, &mut || {
        authority.check()
    })?
    .0;
    if verified.descriptor().bytes()? != descriptor.bytes()? {
        return Err("completed resumed cut differs from exact original event".into());
    }
    verified.completed_read()?;
    authority.check()?;
    Ok(super::initial::Current {
        anchor,
        files,
        pages,
        descriptor,
    })
}

pub(super) fn verify_current<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(super::reader::ObservedCut, String, String)> {
    let cut = super::reader::observe(anchor, pages, binding, check)?;
    let descriptor = cut.descriptor();
    let current = tpm::decode::<32>(&descriptor.selected_nv_head)?;
    let mut live = || -> Result<()> {
        check()?;
        if anchor.read()? != current {
            return Err("actual C changed during complete resumed-cut verification".into());
        }
        check()
    };
    let OperationData::BootstrapProgress {
        previous_retirement: Some(retirement_hash),
        request_sha256,
        source_sha256,
        window_intent_sha256,
        original_authority,
        ..
    } = &descriptor.operation
    else {
        return Err("current cut is not the distinct first-restart profile".into());
    };
    let storage = descriptor
        .storage
        .as_ref()
        .ok_or("resumed direct storage absent")?;
    if descriptor.sequence != 1
        || descriptor.roots != Roots::empty(binding)?
        || descriptor.phase.state != bootstrap::State::Pending
        || descriptor.phase.copied_entries != 0
        || storage.schema_version != 2
        || storage.locations.entries != 1
    {
        return Err("resumed current cut changed original zero-row maintenance semantics".into());
    }
    let retained = locations::lookup(
        &storage.locations,
        retirement_hash,
        &mut Io {
            pages,
            check: &mut live,
        },
    )?
    .ok_or("current C does not bind its complete immutable retained-attempt record")?;
    let record = RetainedAttempt::parse(&read(pages, &retained, &mut live)?)?;
    if retained.sha256 != *retirement_hash {
        return Err("retained attempt data hash is substituted".into());
    }
    let (failed, old_manifest) = original(files, pages, binding, &record, &mut live)?;
    let attempt = hash(&serde_json::to_vec(&(
        "luma-c-direct-initial-attempt-v4",
        control::PendingFrame::Prepared {
            pending: record.retirement.pending.clone(),
        },
    ))?);
    if descriptor.legacy != failed.legacy
        || descriptor.phase != failed.phase
        || descriptor.previous_nv_head != failed.previous_nv_head
        || storage.controls
            != failed
                .storage
                .as_ref()
                .ok_or("retained fixed controls absent")?
                .controls
        || *window_intent_sha256 != intent(&record, &failed.phase, binding)?
        || original_authority.operation_id == record.retirement.original_recovery.operation_id
        || *request_sha256 == record.retirement.recovery_request_sha256
    {
        return Err(
            "resumed event changes legacy source/review or reuses recovery authority".into(),
        );
    }
    let OperationData::BootstrapProgress {
        request_sha256: failed_request,
        original_authority: failed_audit,
        ..
    } = &failed.operation
    else {
        return Err("retained failed bootstrap operation lost".into());
    };
    if original_authority.operation_id == failed_audit.operation_id
        || request_sha256 == failed_request
    {
        return Err("resumed event reuses the failed original bootstrap authority".into());
    }
    let selected_jobs = storage
        .jobs
        .as_ref()
        .ok_or("resumed selected job root absent")?;
    let old_jobs = failed
        .storage
        .as_ref()
        .and_then(|s| s.jobs.as_ref())
        .ok_or("failed job membership absent")?;
    let node = selected_jobs.root_node()?.ok_or("resumed job tree empty")?;
    let location_node = storage
        .locations
        .page
        .as_ref()
        .ok_or("retained attempt index absent")?;
    if selected_jobs.entries() != 2
        || node.entries != 2
        || node.height != 0
        || location_node.entries != 1
        || location_node.height != 0
    {
        return Err(
            "resumed job/location trees exceed their exact finite reviewed membership".into(),
        );
    }
    let job = hash(&serde_json::to_vec(&(
        "luma-c-fresh-first-restart-job-v4",
        binding,
        request_sha256,
        window_intent_sha256,
        &attempt,
    ))?);
    let manifest_location = selected_jobs
        .lookup(
            &job,
            &mut Io {
                pages,
                check: &mut live,
            },
        )?
        .ok_or("resumed job manifest absent")?;
    let control::Cell::Selected {
        descriptor: descriptor_location,
        ..
    } = cut.cell()
    else {
        return Err("selected resumed descriptor absent".into());
    };
    let observed = jobs::observe(
        pages,
        &manifest_location,
        &BTreeMap::from([
            (1, location_node.location.clone()),
            (2, manifest_location.clone()),
            (3, node.location.clone()),
            (4, descriptor_location.clone()),
        ]),
        &mut live,
    )?;
    let manifest = observed.manifest();
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: failed.legacy.clone(),
    };
    if manifest.layout != slots::Plan::exact(binding, &job, specs()?)?
        || manifest.own_slot != 2
        || manifest.previous.is_some()
        || manifest.original_request_sha256 != *request_sha256
        || manifest.review_sha256 != *window_intent_sha256
        || manifest.source_sha256 != *source_sha256
        || manifest.base_descriptor_sha256 != hash(&serde_json::to_vec(&base)?)
        || !manifest.closed()?
        || manifest.members.iter().enumerate().any(|(index, member)| {
            member.role
                != [
                    Role::SemanticRecord,
                    Role::LocationIndex,
                    Role::Manifest,
                    Role::JobIndex,
                    Role::Descriptor,
                ][index]
                || if index == 0 {
                    member.disposition
                        != Disposition::Sealed {
                            value: retained.clone(),
                        }
                } else {
                    member.disposition != Disposition::BoundMetadata
                }
        })
    {
        return Err(
            "resumed selected manifest changes reviewed original source or exact retained slots"
                .into(),
        );
    }
    old_jobs.verify_update(
        selected_jobs,
        &[locations::JobEdit {
            job,
            previous: None,
            next: manifest_location.clone(),
        }],
        &[node.location.clone()],
        &mut Io {
            pages,
            check: &mut live,
        },
    )?;
    locations::verify_insertions(
        &locations::Root::empty_data(binding)?,
        &storage.locations,
        &[locations::Insertion {
            sha256: retained.sha256.clone(),
            location: retained,
        }],
        &[location_node.location.clone()],
        &mut Io {
            pages,
            check: &mut live,
        },
    )?;
    if old_manifest.location() != &record.manifest
        || storage.post_allocation.files != 14
        || storage.post_allocation.directories != 8
        || storage.post_allocation.interrupted_files != 0
        || pages.inventory(&mut live)? != storage.post_allocation
    {
        return Err(
            "resumed current C differs from complete retained and new allocation accounting".into(),
        );
    }
    live()?;
    drop(live);
    let current_attempt = hash(&serde_json::to_vec(&(
        "luma-c-direct-resumed-attempt-v4",
        cut.pending(),
    ))?);
    let review = hash(&serde_json::to_vec(&(
        "luma-c-direct-resumed-recovery-v4",
        cut.review_sha256()?,
        &current_attempt,
        manifest_location,
        observed.physical(),
        old_manifest.physical(),
    ))?);
    Ok((cut, current_attempt, review))
}

pub(super) fn recovery_review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (cut, attempt, review) = verify_current(anchor, files, pages, binding, check)?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: cut.descriptor().legacy.clone(),
    }
    .selector()?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-first-direct-resume-recovery-v4",
        "stable_review_sha256":cut.descriptor().phase.review_sha256,"review_sha256":review,
        "attempt_sha256":attempt,"expected_selected_descriptor_sha256":base.descriptor_sha256,
        "actual_nv_is_new":true,"filesystem_changed":false,"TPM_extended":false,
        "authority_returned":false,"production_qualified":false}),
    )
}

/// The lost-reply path verifies the actual already-new cut and rewrites only
/// its original pending inode. Old/third C is not a license to dispatch again.
pub(super) fn reconcile<A: Checkpoint>(
    mut anchor: A,
    files: Files,
    pages: PageStore,
    binding: map::CustodyBinding,
    expected_review: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<super::initial::Current<A>> {
    let (cut, attempt, review) =
        verify_current(&mut anchor, &files, &pages, &binding, &mut || {
            authority.check()
        })?;
    let descriptor = cut.descriptor().clone();
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: descriptor.legacy.clone(),
    }
    .selector()?;
    let source = authority.source_binding();
    let control = source
        .paged_control
        .as_ref()
        .ok_or("resumed recovery lacks exact original control")?;
    control.validate()?;
    let opaque = tpm::decode::<16>(&source.job)?;
    let audit = authority.audit();
    audit.validate()?;
    let OperationData::BootstrapProgress {
        request_sha256,
        original_authority,
        ..
    } = &descriptor.operation
    else {
        return Err("resumed original operation absent".into());
    };
    if review != expected_review
        || source.command != "content-custody-paged-reconcile"
        || source.installation != binding.installation
        || opaque == [0; 16]
        || source.job != bundle::hex(&opaque)
        || control.stable_review_sha256 != descriptor.phase.review_sha256
        || control.expected_window_sha256 != review
        || control.expected_selected_descriptor_sha256.as_deref()
            != Some(base.descriptor_sha256.as_str())
        || control.attempt_sha256.as_deref() != Some(attempt.as_str())
        || source.request_sha256 == *request_sha256
        || audit.operation_id == original_authority.operation_id
        || audit.usage.action != crate::finite_grants::Action::RecoverResource
        || audit.usage.selector.id != "content-custody-paged-reconcile-v3"
        || audit.usage.selector.digest != review
    {
        return Err("resumed recovery lacks distinct fresh exact original Admin authority".into());
    }
    let control::PendingFrame::Prepared { pending } = cut.pending() else {
        return Err("resumed pending is not uncertain; no acknowledgement retry or renewal".into());
    };
    let expected = tpm::decode::<32>(&descriptor.selected_nv_head)?;
    let mut live = || -> Result<()> {
        authority.check()?;
        if anchor.read()? != expected {
            return Err("actual C changed during resumed recovery".into());
        }
        authority.check()
    };
    let controls = cells::Files::open(
        &pages,
        descriptor
            .storage
            .as_ref()
            .ok_or("resumed controls lost")?
            .controls
            .clone(),
        &mut live,
    )?;
    let snapshot = controls.read(2, &mut live)?;
    if snapshot.bytes() != cut.pending().frame()? {
        return Err("resumed pending drifted after fresh review".into());
    }
    controls.rewrite(
        &snapshot,
        &control::PendingFrame::Completed {
            pending: pending.clone(),
        }
        .frame()?,
        &mut live,
    )?;
    live()?;
    drop(live);
    drop(controls);
    let verified = verify_current(&mut anchor, &files, &pages, &binding, &mut || {
        authority.check()
    })?
    .0;
    if verified.descriptor().bytes()? != descriptor.bytes()? {
        return Err("resumed recovery changed current C descriptor".into());
    }
    verified.completed_read()?;
    authority.check()?;
    Ok(super::initial::Current {
        anchor,
        files,
        pages,
        descriptor,
    })
}
