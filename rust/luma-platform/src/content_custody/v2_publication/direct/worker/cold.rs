//! Cold lineage verifier for one selected direct V1 publication. It replays the
//! exact V1 owner semantics over the authenticated previous cut alone, then
//! reconstructs the deterministic physical closure. It never dispatches, and
//! an unselected pending attempt still requires independent reconciliation.
use super::super::super::super::bootstrap::direct_progress::{
    verify_closure, Closure, Data as Replay,
};
use super::super::super::jobs::Role;
use super::v1::{attributed, replay, Cut, Semantic};
use super::*;

/// The exact previous cut of a selected V1 transition. Every read resolves
/// through that cut's own authenticated location tree and roots.
pub(super) struct Cold<'x, 'a, 'b, F: FnMut() -> Result<()>> {
    pub(super) data: &'x mut Replay<'a, 'b, F>,
    pub(super) files: &'x Files,
    pub(super) previous: &'x Descriptor,
}
impl<F: FnMut() -> Result<()>> Cut for Cold<'_, '_, '_, F> {
    fn descriptor(&self) -> &Descriptor {
        self.previous
    }
    fn check(&mut self) -> Result<()> {
        locations::Io::check(&mut *self.data)
    }
    fn live(&mut self) -> Result<()> {
        locations::Io::check(&mut *self.data)
    }
    fn lookup(&mut self, root: &map::Root, literal: &[u8]) -> Result<Option<Vec<u8>>> {
        self.previous.phase.require_ready()?;
        let roots = self.previous.roots.all();
        if !roots.iter().any(|selected| *selected == root) {
            return Err("cold V1 map reader refuses an unselected role/root".into());
        }
        let context = self.data.context().clone();
        let key = root.key(literal)?;
        let proof = map::lookup(
            root,
            &key,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut *self.data,
        )?;
        if proof.key != key {
            return Err("cold V1 map proof substitutes requested logical key".into());
        }
        proof.verify_data(root)
    }
    fn read_record(&mut self, sha: &str) -> Result<Vec<u8>> {
        self.data.record(sha)
    }
    fn journal(&mut self) -> Result<Journal> {
        let files = self.files;
        let data = &mut *self.data;
        locations::Io::check(&mut *data)?;
        let bytes = files.read(JOURNAL, &mut || locations::Io::check(&mut *data))?;
        let journal = retained_journal(self.previous, &bytes)?;
        locations::Io::check(&mut *data)?;
        Ok(journal)
    }
}

/// Verifies that the actual selected descriptor is the exact deterministic V1
/// publication over its authenticated previous cut. Only that last transition
/// is reconstructed; the previous cut is bound by its frame hash and NV head.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_selected(
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
        .ok_or("cold V1 publication has no selected storage")?;
    if current.sequence <= 1
        || storage.schema_version != 2
        || storage.descriptor_slot != location.slot
        || location.sha256 != hash(&current.slot_frame()?)
        || location.bytes != PAGE_BYTES as u64
    {
        return Err("cold V1 publication is not its exact selected descriptor location".into());
    }
    let OperationData::V1Publication {
        binding,
        request_sha256,
        source_sha256,
        event,
        original_authority,
    } = &current.operation
    else {
        return Err("cold V1 verifier does not accept a different semantic event class".into());
    };
    current.phase.require_ready()?;
    original_authority.validate()?;
    let mut data = Replay::new(
        pages,
        storage.locations.clone(),
        check,
        map::Context {
            binding: current.binding.clone(),
            selected_descriptor_sha256: hash(&current.bytes()?),
            selected_nv_head: current.selected_nv_head.clone(),
            review_sha256: None,
        },
        MEMORY_BYTES,
        MEMORY_PAGES,
    );
    let previous_sha = current
        .previous_descriptor_sha256
        .as_ref()
        .ok_or("cold V1 publication has no previous full-frame commitment")?;
    let previous_location = locations::lookup(&storage.locations, previous_sha, &mut data)?
        .ok_or("cold V1 publication lost the exact selected previous descriptor address")?;
    let previous =
        Descriptor::from_slot_frame(&locations::Io::read(&mut data, &previous_location)?)?;
    // Only event classes with a cold lineage verifier are inherited; an index
    // phase preparation has none yet and is refused. The V1 replay below still
    // refuses a migrating or migrated owner.
    if previous_location.sha256 != *previous_sha
        || previous.binding != current.binding
        || previous.legacy != current.legacy
        || previous.phase != current.phase
        || previous.sequence.checked_add(1) != Some(current.sequence)
        || previous.global_ordinal.checked_add(1) != Some(current.global_ordinal)
        || previous.selected_nv_head != current.previous_nv_head
        || !matches!(
            previous.operation,
            OperationData::BootstrapProgress { .. }
                | OperationData::V1Publication { .. }
                | OperationData::OwnerMigration { .. }
                | OperationData::IndexJobReservation { .. }
        )
    {
        return Err(
            "cold V1 publication does not continue the exact authenticated old typed cut".into(),
        );
    }
    previous.phase.require_ready()?;
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("cold V1 previous direct storage absent")?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("cold V1 previous job index absent")?;
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("cold V1 current job index absent")?;
    event.validate()?;
    let record = data.record(&event.sha256)?;
    if record.len() as u64 != event.bytes {
        return Err("cold V1 event record changes its complete byte length".into());
    }
    let node: RecordNode = canonical(
        &record,
        super::super::super::super::super::paged::FILE_BYTES,
    )?;
    let held = node.publication.validate()?;
    if node.schema_version != 3
        || node.binding != *binding
        || held.binding != *binding
        || node.publication.original_authority != *original_authority
        || !attributed(
            &held,
            &node.publication.profile,
            &node.publication.storage_device,
            original_authority,
        )?
    {
        return Err(
            "cold V1 publication event differs from its selected owner/finite effect".into(),
        );
    }
    // The owner semantics read the previous cut exactly as its warm publisher
    // did: its own location tree, roots and selected context.
    let previous_context = map::Context {
        binding: previous.binding.clone(),
        selected_descriptor_sha256: hash(&previous.bytes()?),
        selected_nv_head: previous.selected_nv_head.clone(),
        review_sha256: None,
    };
    data.set_locations(previous_storage.locations.clone());
    data.set_context(previous_context.clone());
    let Semantic::Append {
        owner_root,
        edits,
        reference,
        bytes,
    } = replay(
        &mut Cold {
            data: &mut data,
            files,
            previous: &previous,
        },
        &held,
        node.publication.commitment.as_bytes(),
        node.publication.record.as_bytes(),
        &node.publication.profile,
        &node.publication.storage_device,
        original_authority,
    )?
    else {
        return Err("cold V1 publication replays as an already selected outcome".into());
    };
    if reference != *event || bytes != record {
        return Err("cold V1 event record differs from independent owner semantic replay".into());
    }
    let context = map::Context {
        review_sha256: Some(held.review_sha256.clone()),
        ..previous_context
    };
    data.set_context(context.clone());
    let root = map::prepare_update(
        &owner_root,
        &edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: MEMORY_BYTES as u64,
            new_files: MEMORY_PAGES as u32,
        },
        &mut data,
    )?;
    data.set_readonly(true);
    map::verify_update(
        &owner_root,
        &root,
        &edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: 0,
            new_files: 0,
        },
        &mut data,
    )?;
    let generated = data.take_cache();
    let mut roots = previous.roots.clone();
    roots.owners = root;
    if roots != current.roots {
        return Err("cold V1 role roots differ from independent owner semantic replay".into());
    }
    let token = VerifiedTransition {
        base: Selector::for_descriptor(&previous)?,
        base_frame_sha256: previous_sha.clone(),
        source_sha256: source_sha256.clone(),
        request_sha256: request_sha256.clone(),
        review_sha256: held.review_sha256.clone(),
        roots,
        edits: BTreeMap::from([(map::Kind::OwnerStates, edits)]),
        pages: generated,
        records: BTreeMap::from([(reference.sha256.clone(), bytes)]),
        operation: current.operation.clone(),
        read_cas: Vec::new(),
        outcome: Completed::V1(held.outcome()),
    };
    let plan =
        super::storage::layout(&previous.binding, Some(previous_storage), &token, &mut data)?;
    if storage.controls != previous_storage.controls || storage.descriptor_slot.job != plan.job {
        return Err(
            "cold V1 publication differs from its deterministic reviewed exact layout".into(),
        );
    }
    data.set_locations(storage.locations.clone());
    let semantic = plan
        .data
        .iter()
        .map(|value| {
            let role = if value.kind == slots::Kind::Record {
                Role::SemanticRecord
            } else {
                Role::SemanticPage
            };
            (value.sha256.as_str(), value.bytes.as_slice(), role)
        })
        .collect();
    verify_closure(
        &mut data,
        Closure {
            binding: &current.binding,
            storage,
            previous: previous_storage,
            old_jobs,
            jobs,
            location,
            previous_sha256: previous_sha,
            previous_location,
            job: &plan.job,
            specs: &plan.specifications,
            base_descriptor_sha256: &token.base.descriptor_sha256,
            request_sha256: &plan.request,
            source_sha256: &plan.source,
            review_sha256: &plan.window,
            semantic,
            location_nodes: plan.locations,
            job_nodes: plan.jobs,
        },
    )
}
