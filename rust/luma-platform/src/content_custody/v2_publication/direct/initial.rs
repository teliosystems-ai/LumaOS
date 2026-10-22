//! Original-Admin first direct maintenance publication. All namespace/data
//! allocation and complete readback precede the one existing C advance. This
//! internal path is not an installed command or permission constructor.
use super::super::super::paged::{cells, slots};
use super::super::*;
#[cfg(test)]
#[path = "initial/tests.rs"]
mod tests;
use super::jobs::{self, Disposition, Manifest, Member, Role};

pub(super) struct Current<A: Checkpoint> {
    pub anchor: A,
    pub files: Files,
    pub pages: PageStore,
    pub descriptor: Descriptor,
}
pub(super) fn specifications() -> Result<Vec<slots::ExactSlot>> {
    Ok(vec![
        slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Record, 16 * 1024)?,
        slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Page, 4096)?,
        slots::ExactSlot::for_bytes(
            slots::Pool::Publication(0),
            slots::Kind::Page,
            PAGE_BYTES as u64,
        )?,
    ])
}
pub(super) fn window_intent(
    blueprint: &bootstrap::Blueprint,
    phase: &bootstrap::Phase,
    base: &Selector,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        "luma-c-exact-direct-bootstrap-v4",
        hash(&blueprint.next_window_intent(phase, base)?),
        specifications()?,
        "three-permanent-64k-controls;all-slots-before-one-C-advance;no-post-NV-allocation",
    ))?))
}
pub(super) fn review<A: Checkpoint>(
    store: &mut Store<A>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (binding, legacy, blueprint) = bootstrap::legacy_snapshot(store, check)?;
    if capacity::remaining(&store.state)?.outstanding_restore_batches != 0 {
        return Err(
            "direct bootstrap cannot abandon an outstanding legacy restore obligation".into(),
        );
    }
    let phase = blueprint.initial_phase()?;
    let base = BaseSnapshot::Legacy {
        binding,
        cut: legacy,
    }
    .selector()?;
    let intent = window_intent(&blueprint, &phase, &base)?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-exact-direct-bootstrap-v4",
        "stable_review_sha256":phase.review_sha256,"window_intent_sha256":intent,
        "selected_base":base,"phase":phase,"ordinary_owner_access_available":false,
        "authority_returned":false,"production_qualified":false}),
    )
}
struct Raw<'a, A: Checkpoint> {
    pages: &'a PageStore,
    anchor: &'a mut A,
    old: [u8; 32],
}
impl<A: Checkpoint> control::Reader for Raw<'_, A> {
    fn check(&mut self) -> Result<()> {
        self.pages.check()?;
        if self.anchor.read()? != self.old {
            return Err("original C changed during direct stage readback".into());
        }
        Ok(())
    }
    fn read_descriptor(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        let pages = self.pages;
        let anchor = &mut self.anchor;
        let old = self.old;
        let mut live = || -> Result<()> {
            pages.check()?;
            if anchor.read()? != old {
                return Err("original C changed within direct descriptor read".into());
            }
            Ok(())
        };
        let directory = slots::Directory::at_reference(pages, &reference.slot, &mut live)?;
        let bytes = directory.read(reference, &mut live)?;
        live()?;
        Ok(bytes)
    }
    fn read_descriptor_original(
        &mut self,
        reference: &slots::SealedReference,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>> {
        let pages = self.pages;
        let anchor = &mut self.anchor;
        let old = self.old;
        let mut live = || -> Result<()> {
            original.check()?;
            pages.check()?;
            if anchor.read()? != old {
                return Err(
                    "actual C changed within original-authorized descriptor readback".into(),
                );
            }
            original.check()
        };
        let directory = slots::Directory::at_reference(pages, &reference.slot, &mut live)?;
        let bytes = directory.read(reference, &mut live)?;
        live()?;
        Ok(bytes)
    }
}
pub(super) fn begin<A: Checkpoint>(
    mut legacy_store: Store<A>,
    expected_intent: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<Current<A>> {
    let proposal = review(&mut legacy_store, &mut || authority.check())?;
    if proposal["window_intent_sha256"].as_str() != Some(expected_intent) {
        return Err("direct bootstrap requires its exact current original resource review".into());
    }
    let (binding, legacy, blueprint) =
        bootstrap::legacy_snapshot(&mut legacy_store, &mut || authority.check())?;
    let phase = blueprint.initial_phase()?;
    bootstrap::require_admin(authority, &binding, &phase, expected_intent, None, None)?;
    let operation = OperationData::BootstrapProgress {
        previous_retirement: None,
        review_sha256: phase.review_sha256.clone(),
        window_intent_sha256: expected_intent.into(),
        request_sha256: authority.source_binding().request_sha256.clone(),
        source_sha256: hash(&COperation::Admin(authority).source_bytes()?),
        original_authority: authority.audit().clone(),
    };
    let request = authority.source_binding().request_sha256.clone();
    let source_sha = hash(&COperation::Admin(authority).source_bytes()?);
    let old = tpm::decode(&legacy.nv_head)?;
    let legacy_bytes = legacy_store.bytes.clone();
    let genesis = legacy_store
        .genesis_proof
        .clone()
        .ok_or("direct bootstrap lacks independently held original genesis")?;
    legacy_store.live(&mut || authority.check())?;
    legacy_store.poisoned = true;
    let Store {
        mut anchor, files, ..
    } = legacy_store;
    let pages = PageStore::create(&files.root, binding.clone(), &mut || authority.check())?;
    let legacy_pin = super::pinned::Pinned::capture(
        files.root.join(JOURNAL),
        &legacy_bytes,
        0o400,
        &mut || authority.check(),
    )?;
    let genesis_pin = super::pinned::Pinned::capture(
        files.root.join("genesis.json"),
        &genesis,
        0o400,
        &mut || authority.check(),
    )?;
    let mut old_live = || -> Result<()> {
        authority.check()?;
        legacy_pin.check(&mut || authority.check())?;
        genesis_pin.check(&mut || authority.check())?;
        if anchor.read()? != old {
            return Err(
                "direct preparation lost its independently held original legacy C cut".into(),
            );
        }
        authority.check()
    };
    old_live()?;
    pages.admit_writes(2 * 1024 * 1024, 16, 2, &mut old_live)?;
    let empty = control::Cell::empty_data(&binding)?.frame()?;
    let pending_empty = control::PendingFrame::empty_data(&binding)?.frame()?;
    let controls = cells::Files::create(&pages, [&empty, &empty, &pending_empty], &mut old_live)?;
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-bootstrap-allocation-v4",
        &binding,
        &request,
        expected_intent,
    ))?);
    let plan = slots::Plan::exact(&binding, &job, specifications()?)?;
    let directory = slots::Directory::create(&pages, plan.clone(), &mut old_live)?;
    let references = directory.allocate_window(0, 3, &mut old_live)?;
    let namespace = directory.observe_namespace(&mut old_live)?;
    let allocated = references.iter().try_fold(
        namespace
            .allocated_bytes
            .checked_add(namespace.identity_allocated_bytes)
            .ok_or("initial namespace accounting overflow")?,
        |sum, reference| {
            sum.checked_add(reference.allocated_bytes)
                .ok_or("initial allocation accounting overflow")
        },
    )?;
    let manifest = Manifest {
        schema_version: 4,
        domain: "luma-c-reviewed-job-allocation-v4".into(),
        binding: binding.clone(),
        job: job.clone(),
        base_descriptor_sha256: hash(&serde_json::to_vec(&BaseSnapshot::Legacy {
            binding: binding.clone(),
            cut: legacy.clone(),
        })?),
        original_request_sha256: request,
        review_sha256: expected_intent.into(),
        source_sha256: source_sha,
        previous: None,
        own_slot: 0,
        layout: plan,
        namespace,
        members: references
            .iter()
            .enumerate()
            .map(|(index, slot)| Member {
                slot: slot.clone(),
                role: [Role::Manifest, Role::JobIndex, Role::Descriptor][index],
                disposition: Disposition::BoundMetadata,
            })
            .collect(),
        allocated_bytes: allocated,
    };
    let manifest_location = directory.fill(
        &references[0],
        slots::Pool::Publication(0),
        &manifest.canonical_bytes()?,
        &mut old_live,
    )?;
    struct Index<'a, 'b, 'c, F: FnMut() -> Result<()>> {
        directory: &'a slots::Directory<'b>,
        reference: &'a slots::Reference,
        check: &'c mut F,
        witnesses: Vec<slots::SealedReference>,
    }
    impl<F: FnMut() -> Result<()>> locations::Io for Index<'_, '_, '_, F> {
        fn check(&mut self) -> Result<()> {
            (self.check)()
        }
        fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
            self.directory.read(reference, self.check)
        }
        fn seal_node(&mut self, bytes: &[u8]) -> Result<slots::SealedReference> {
            if !self.witnesses.is_empty() {
                return Err(
                    "initial singleton job index exceeds its exact reviewed one-node allocation"
                        .into(),
                );
            }
            let value = self.directory.fill(
                self.reference,
                slots::Pool::Publication(0),
                bytes,
                self.check,
            )?;
            self.witnesses.push(value.clone());
            Ok(value)
        }
    }
    let base_jobs = locations::JobRoot::empty_data(&binding)?;
    let edit = locations::JobEdit {
        job,
        previous: None,
        next: manifest_location.clone(),
    };
    let mut index = Index {
        directory: &directory,
        reference: &references[1],
        check: &mut old_live,
        witnesses: Vec::new(),
    };
    let jobs = base_jobs.update(std::slice::from_ref(&edit), &mut index)?;
    let index_seals = index.witnesses.clone();
    base_jobs.verify_update(&jobs, std::slice::from_ref(&edit), &index_seals, &mut index)?;
    drop(index);
    let mut physical = pages.inventory(&mut old_live)?;
    if physical.interrupted_files != 1 {
        return Err("first direct stage has unknown incomplete allocations".into());
    }
    physical.interrupted_files = 0;
    physical.logical_bytes = physical
        .logical_bytes
        .checked_add(PAGE_BYTES as u64)
        .ok_or("initial descriptor physical counter overflow")?;
    let descriptor = Descriptor {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: binding.clone(),
        sequence: 1,
        global_ordinal: legacy
            .events
            .checked_add(2)
            .ok_or("direct initial ordinal overflow")?,
        previous_descriptor_sha256: None,
        previous_nv_head: legacy.nv_head.clone(),
        event_sha256: String::new(),
        selected_nv_head: String::new(),
        legacy: legacy.clone(),
        roots: Roots::empty(&binding)?,
        phase,
        operation,
        storage: Some(StorageSelection {
            schema_version: 2,
            controls: controls.selection().clone(),
            locations: locations::Root::empty_data(&binding)?,
            jobs: Some(jobs),
            descriptor_slot: references[2].clone(),
            post_allocation: physical.clone(),
            parent_allocation: None,
        }),
    }
    .seal()?;
    let descriptor_location = directory.fill(
        &references[2],
        slots::Pool::Publication(0),
        &descriptor.slot_frame()?,
        &mut old_live,
    )?;
    let metadata = BTreeMap::from([
        (0, manifest_location.clone()),
        (1, index_seals[0].clone()),
        (2, descriptor_location.clone()),
    ]);
    let observed = jobs::observe(&pages, &manifest_location, &metadata, &mut old_live)?;
    if observed.manifest() != &manifest || pages.inventory(&mut old_live)? != physical {
        return Err(
            "actual direct initial whole-resource readback differs from reviewed immutable stage"
                .into(),
        );
    }
    old_live()?;
    drop(old_live);
    bootstrap::require_admin(
        authority,
        &binding,
        &descriptor.phase,
        expected_intent,
        None,
        None,
    )?;
    let pending = control::PendingCell {
        schema_version: 3,
        domain: "luma-c-direct-slot-pending-v3".into(),
        binding: binding.clone(),
        base: control::Base::Legacy {
            binding: binding.clone(),
            cut: legacy,
        },
        inactive_index: 0,
        next: control::Cell::for_descriptor(&descriptor, descriptor_location)?,
        event_sha256: descriptor.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&descriptor.operation)?),
    };
    let mut original = COperation::Admin(authority);
    let staged = control::stage(
        &controls,
        pending,
        None,
        &descriptor,
        old,
        &mut Raw {
            pages: &pages,
            anchor: &mut anchor,
            old,
        },
        &mut original,
    )?;
    staged.check(&controls, &mut original)?;
    original.check()?;
    if anchor.read()? != old {
        return Err("actual initial C changed immediately before the only dispatch".into());
    }
    // There is exactly one dispatch. Even a lost reply is not retried here.
    let actual = anchor.advance(old, tpm::decode(&descriptor.event_sha256)?)?;
    let expected = tpm::decode(&descriptor.selected_nv_head)?;
    if actual != expected || anchor.read()? != expected {
        return Err("direct initial dispatch/readback remains uncertain".into());
    }
    staged.check(&controls, &mut original)?;
    let snapshot = controls.read(2, &mut || original.check())?;
    if snapshot.bytes()
        != (control::PendingFrame::Prepared {
            pending: staged.pending.clone(),
        })
        .frame()?
    {
        return Err("initial pending marker changed after actual C dispatch".into());
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
                return Err("actual C changed during fixed-inode completion".into());
            }
            original.check()
        },
    )?;
    original.check()?;
    drop(original);
    drop(directory);
    drop(controls);
    let current = verified_initial(&mut anchor, &files, &pages, &binding, &mut || {
        authority.check()
    })?
    .0;
    if current.descriptor().bytes()? != descriptor.bytes()? {
        return Err("completed direct current descriptor changed".into());
    }
    current.completed_read()?;
    Ok(Current {
        anchor,
        files,
        pages,
        descriptor,
    })
}

struct Readonly<'a, 'b, F: FnMut() -> Result<()>> {
    pages: &'a PageStore,
    check: &'b mut F,
}
impl<F: FnMut() -> Result<()>> locations::Io for Readonly<'_, '_, F> {
    fn check(&mut self) -> Result<()> {
        (self.check)()?;
        self.pages.check()?;
        (self.check)()
    }
    fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        slots::Directory::at_reference(self.pages, &reference.slot, self.check)?
            .read(reference, self.check)
    }
    fn seal_node(&mut self, _: &[u8]) -> Result<slots::SealedReference> {
        Err("direct initial recovery observation cannot allocate".into())
    }
}
pub(super) fn verify_initial_objects(
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    descriptor: &Descriptor,
    descriptor_location: &slots::SealedReference,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<jobs::ObservedManifest> {
    check()?;
    validate_genesis_at(
        &files.root,
        &binding.installation,
        tpm::decode(&binding.sealed_genesis_sha256)?,
    )?;
    descriptor.validate()?;
    if descriptor.binding != *binding {
        return Err("initial objects cross the independently sealed C binding".into());
    }
    control::Cell::for_descriptor(descriptor, descriptor_location.clone())?;
    let storage = descriptor
        .storage
        .as_ref()
        .ok_or("direct initial cut lacks complete storage")?;
    let (request, window, source) = match &descriptor.operation {
        OperationData::BootstrapProgress {
            request_sha256,
            window_intent_sha256,
            source_sha256,
            previous_retirement: None,
            ..
        } => (request_sha256, window_intent_sha256, source_sha256),
        _ => return Err("direct initial recovery is not an original first bootstrap event".into()),
    };
    if descriptor.sequence != 1
        || descriptor.phase.state != bootstrap::State::Pending
        || descriptor.phase.copied_entries != 0
        || descriptor.roots != Roots::empty(binding)?
        || storage.schema_version != 2
        || storage.locations.entries != 0
    {
        return Err(
            "direct initial recovery cannot reinterpret a later/foreign maintenance cut".into(),
        );
    }
    let journal_bytes = files.read(JOURNAL, check)?;
    let journal: Journal = canonical(&journal_bytes, MAX_JOURNAL)?;
    journal.require_identity(
        &binding.installation,
        tpm::decode(&binding.sealed_genesis_sha256)?,
    )?;
    let state = journal.validate()?;
    if hash(&journal_bytes) != descriptor.legacy.journal_sha256
        || journal_bytes.len() as u64 != descriptor.legacy.journal_bytes
        || journal.events.len() as u64 != descriptor.legacy.events
        || bundle::hex(&state.checkpoint) != descriptor.legacy.nv_head
    {
        return Err(
            "direct initial selected C does not commit this exact retained legacy DATA".into(),
        );
    }
    let blueprint = bootstrap::Blueprint::verified_legacy(binding, &descriptor.legacy, &journal)?;
    let phase = blueprint.initial_phase()?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: descriptor.legacy.clone(),
    }
    .selector()?;
    if capacity::remaining(&state)?.outstanding_restore_batches != 0
        || descriptor.phase != phase
        || *window != window_intent(&blueprint, &phase, &base)?
    {
        return Err("initial descriptor does not reconstruct the complete original legacy projection and reviewed zero-row event".into());
    }
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("direct initial C has no selected job manifest index")?;
    if jobs.entries() != 1 || jobs.binding() != binding {
        return Err("direct first cut has unexpected selected job membership".into());
    }
    let job = hash(&serde_json::to_vec(&(
        "luma-c-direct-bootstrap-allocation-v4",
        binding,
        request,
        window,
    ))?);
    let node = jobs.root_node()?.ok_or("first job index is empty")?;
    if node.entries != 1 || node.height != 0 {
        return Err("first job index is not its exact singleton canonical tree".into());
    }
    let location = jobs
        .lookup(
            &job,
            &mut Readonly {
                pages,
                check: &mut *check,
            },
        )?
        .ok_or("original first allocation manifest is absent")?;
    let proof = jobs::observe(
        pages,
        &location,
        &BTreeMap::from([
            (0, location.clone()),
            (1, node.location.clone()),
            (2, descriptor_location.clone()),
        ]),
        check,
    )?;
    let manifest = proof.manifest();
    let layout = slots::Plan::exact(binding, &job, specifications()?)?;
    let expected_base = hash(&serde_json::to_vec(&BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: descriptor.legacy.clone(),
    })?);
    if manifest.layout != layout
        || manifest.job != job
        || manifest.original_request_sha256 != *request
        || manifest.base_descriptor_sha256 != expected_base
        || manifest.review_sha256 != *window
        || manifest.source_sha256 != *source
        || manifest.previous.is_some()
        || manifest.own_slot != 0
        || !manifest.closed()?
        || manifest.members.iter().enumerate().any(|(index, member)| {
            member.role != [Role::Manifest, Role::JobIndex, Role::Descriptor][index]
                || member.disposition != Disposition::BoundMetadata
        })
        || pages.inventory(check)? != storage.post_allocation
    {
        return Err("direct initial recovery changes exact selected allocation/source/full physical closure".into());
    }
    check()?;
    Ok(proof)
}
fn verified_initial<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(super::reader::ObservedCut, String, String)> {
    let cut = super::reader::observe(anchor, pages, binding, check)?;
    let expected = tpm::decode(&cut.descriptor().selected_nv_head)?;
    let mut live = || -> Result<()> {
        check()?;
        if anchor.read()? != expected {
            return Err("actual C changed during direct initial recovery DATA observation".into());
        }
        check()
    };
    let control::Cell::Selected {
        descriptor: reference,
        ..
    } = cut.cell()
    else {
        return Err("actual selected initial cell is empty".into());
    };
    let proof = verify_initial_objects(
        files,
        pages,
        binding,
        cut.descriptor(),
        reference,
        &mut live,
    )?;
    live()?;
    drop(live);
    let attempt = hash(&serde_json::to_vec(&(
        "luma-c-direct-initial-attempt-v4",
        cut.pending(),
    ))?);
    let review = hash(&serde_json::to_vec(&(
        "luma-c-direct-initial-recovery-v4",
        cut.review_sha256()?,
        &attempt,
        proof.location(),
        proof.physical(),
    ))?);
    Ok((cut, attempt, review))
}
pub(super) fn recovery_review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (cut, attempt, review) = verified_initial(anchor, files, pages, binding, check)?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: cut.descriptor().legacy.clone(),
    }
    .selector()?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-direct-initial-recovery-v4",
        "stable_review_sha256":cut.descriptor().phase.review_sha256,"review_sha256":review,
        "attempt_sha256":attempt,"expected_selected_descriptor_sha256":base.descriptor_sha256,
        "actual_nv_head":cut.descriptor().selected_nv_head,"actual_nv_is_new":true,
        "filesystem_changed":false,"TPM_extended":false,"authority_returned":false,"production_qualified":false}),
    )
}
/// Fresh original Admin recovery may acknowledge only the exact already-new C
/// cut. Old/third NV cannot pass the selected-cell proof and remain fenced;
/// this function never calls advance or retries the original dispatch.
pub(super) fn reconcile<A: Checkpoint>(
    mut anchor: A,
    files: Files,
    pages: PageStore,
    binding: map::CustodyBinding,
    expected_review: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<Current<A>> {
    authority.check()?;
    let (cut, attempt, review) =
        verified_initial(&mut anchor, &files, &pages, &binding, &mut || {
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
        .ok_or("direct recovery lacks authenticated original control")?;
    control.validate()?;
    let opaque = tpm::decode::<16>(&source.job)?;
    let audit = authority.audit();
    audit.validate()?;
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
        || audit.operation_id.is_none()
        || audit.usage.action != crate::finite_grants::Action::RecoverResource
        || audit.usage.selector.id != "content-custody-paged-reconcile-v3"
        || audit.usage.selector.digest != review
    {
        return Err("direct initial completion lacks separate fresh exact original Admin recovery authority".into());
    }
    authority.check()?;
    let pending = match cut.pending() {
        control::PendingFrame::Prepared { pending } => pending.clone(),
        control::PendingFrame::Completed { .. } => return Err(
            "initial cut is already completed; a recovery review is not a redispatch or renewal"
                .into(),
        ),
        _ => return Err("initial pending evidence is absent".into()),
    };
    let expected = tpm::decode(&descriptor.selected_nv_head)?;
    let controls = cells::Files::open(
        &pages,
        descriptor
            .storage
            .as_ref()
            .ok_or("direct storage lost")?
            .controls
            .clone(),
        &mut || authority.check(),
    )?;
    let snapshot = controls.read(2, &mut || authority.check())?;
    if snapshot.bytes()
        != (control::PendingFrame::Prepared {
            pending: pending.clone(),
        })
        .frame()?
    {
        return Err("direct pending changed after fresh recovery review".into());
    }
    controls.rewrite(
        &snapshot,
        &control::PendingFrame::Completed { pending }.frame()?,
        &mut || {
            authority.check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during reviewed fixed-inode completion".into());
            }
            authority.check()
        },
    )?;
    drop(controls);
    let finished = verified_initial(&mut anchor, &files, &pages, &binding, &mut || {
        authority.check()
    })?
    .0;
    if finished.descriptor().bytes()? != descriptor.bytes()? {
        return Err("direct recovery completion changed the authenticated event".into());
    }
    finished.completed_read()?;
    authority.check()?;
    Ok(Current {
        anchor,
        files,
        pages,
        descriptor,
    })
}
