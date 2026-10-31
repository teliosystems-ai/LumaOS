//! Cold lineage verifier for one selected direct index phase preparation. It
//! replays the preparation's retained DATA over the authenticated previous cut
//! alone, rebuilds the exact index role edit and then the deterministic
//! physical closure. The retained attribution, plan review and inventory are
//! historical DATA, never a current grant or permission to publish, and
//! nothing here dispatches.
use super::super::super::super::super::paged::FILE_BYTES;
use super::super::super::super::bootstrap::direct_progress::{
    verify_closure, Closure, Data as Replay,
};
use super::super::super::jobs::Role;
use super::*;
use crate::content_checkpoint::custody::v2_publication::index::effects::{
    replay_selected_data, SelectedEventData, SelectedPreparationReader,
};
use std::cell::RefCell;

/// The selected before/after cut. A before root resolves through the previous
/// location tree and context, an after root and every record through the
/// current ones; any other root is refused.
struct Reader<'x, 'a, 'b, 'c, F: FnMut() -> Result<()>> {
    data: &'x RefCell<&'c mut Replay<'a, 'b, F>>,
    previous: &'x Descriptor,
    current: &'x Descriptor,
    previous_locations: &'x locations::Root,
    current_locations: &'x locations::Root,
    previous_context: &'x map::Context,
    current_context: &'x map::Context,
}
impl<F: FnMut() -> Result<()>> SelectedPreparationReader for Reader<'_, '_, '_, '_, F> {
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        check()?;
        let (tree, context) = if self.previous.roots.all().contains(&root) {
            (self.previous_locations, self.previous_context)
        } else if self.current.roots.all().contains(&root) {
            (self.current_locations, self.current_context)
        } else {
            return Err("cold index preparation reader refuses an unselected role/root".into());
        };
        let key = root.key(literal)?;
        let value = {
            let mut data = self.data.borrow_mut();
            data.set_locations(tree.clone());
            data.set_context(context.clone());
            let proof = map::lookup(
                root,
                &key,
                context,
                map::Budget {
                    read_bytes: READ_BUDGET,
                    write_bytes: 0,
                    new_files: 0,
                },
                &mut **data,
            )?;
            if proof.key != key {
                return Err(
                    "cold index preparation map proof substitutes requested logical key".into(),
                );
            }
            proof.verify_data(root)?
        };
        check()?;
        Ok(value)
    }
    fn record(
        &mut self,
        reference: &RecordRef,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        reference.validate()?;
        if maximum == 0 || maximum > FILE_BYTES || reference.bytes > maximum as u64 {
            return Err("cold index preparation record exceeds its closed class before I/O".into());
        }
        let bytes = {
            let mut data = self.data.borrow_mut();
            data.set_locations(self.current_locations.clone());
            data.record(&reference.sha256)?
        };
        if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
            return Err("cold index preparation record complete bytes changed".into());
        }
        check()?;
        Ok(bytes)
    }
}

/// Verifies that the actual selected descriptor is the exact deterministic
/// index phase preparation over its authenticated previous cut. Only that last
/// transition is reconstructed; the previous cut is bound by its frame hash and
/// NV head.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_selected(
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
        .ok_or("cold index preparation has no selected storage")?;
    if current.sequence <= 1
        || storage.schema_version != 2
        || storage.descriptor_slot != location.slot
        || location.sha256 != hash(&current.slot_frame()?)
        || location.bytes != PAGE_BYTES as u64
    {
        return Err("cold index preparation is not its exact selected descriptor location".into());
    }
    let OperationData::IndexPreparation {
        binding,
        request_sha256,
        input_sha256,
        source_sha256,
        preparation,
        original_authority,
    } = &current.operation
    else {
        return Err(
            "cold index preparation verifier refuses a different semantic event class".into(),
        );
    };
    current.phase.require_ready()?;
    original_authority.validate()?;
    let current_context = map::Context {
        binding: current.binding.clone(),
        selected_descriptor_sha256: hash(&current.bytes()?),
        selected_nv_head: current.selected_nv_head.clone(),
        review_sha256: None,
    };
    let mut data = Replay::new(
        pages,
        storage.locations.clone(),
        check,
        current_context.clone(),
        MEMORY_BYTES,
        MEMORY_PAGES,
    );
    let previous_sha = current
        .previous_descriptor_sha256
        .as_ref()
        .ok_or("cold index preparation has no previous full-frame commitment")?;
    let previous_location = locations::lookup(&storage.locations, previous_sha, &mut data)?
        .ok_or("cold index preparation lost the exact selected previous descriptor address")?;
    let previous =
        Descriptor::from_slot_frame(&locations::Io::read(&mut data, &previous_location)?)?;
    // Only event classes with a cold lineage verifier are inherited. A
    // previous preparation for the same owner is refused by the replay below,
    // which requires the old index leaf to carry no preparation.
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
                | OperationData::IndexJobSelection { .. }
                | OperationData::IndexPreparation { .. }
        )
    {
        return Err(
            "cold index preparation does not continue the exact authenticated old cut".into(),
        );
    }
    previous.phase.require_ready()?;
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("cold index preparation previous direct storage absent")?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("cold index preparation previous job index absent")?;
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("cold index preparation current job index absent")?;
    let previous_context = map::Context {
        binding: previous.binding.clone(),
        selected_descriptor_sha256: hash(&previous.bytes()?),
        selected_nv_head: previous.selected_nv_head.clone(),
        review_sha256: None,
    };
    // The preparation, its plan inventory, owner point and the after CAS are
    // replayed from the selected records and both cuts' own roots alone.
    let historical = {
        let cell = RefCell::new(&mut data);
        let mut reader = Reader {
            data: &cell,
            previous: &previous,
            current,
            previous_locations: &previous_storage.locations,
            current_locations: &storage.locations,
            previous_context: &previous_context,
            current_context: &current_context,
        };
        let mut live = || locations::Io::check(&mut **cell.borrow_mut());
        let replayed = replay_selected_data(
            &mut reader,
            &previous,
            current,
            SelectedEventData {
                binding,
                request_sha256: request_sha256.as_str(),
                input_sha256: input_sha256.as_str(),
                source_sha256: source_sha256.as_str(),
                preparation,
                original_authority,
            },
            READ_BUDGET,
            &mut live,
        )?;
        replayed
    };
    let context = map::Context {
        review_sha256: Some(input_sha256.clone()),
        ..previous_context
    };
    data.set_locations(previous_storage.locations.clone());
    data.set_context(context.clone());
    let index_root = &previous.roots.index_generations;
    let edits = vec![map::Edit {
        key: index_root.key(&historical.owner_literal)?,
        expected_value_sha256: historical
            .expected_index_value
            .as_ref()
            .map(|value| hash(value)),
        value: Some(historical.replacement_index_value),
    }];
    let root = map::prepare_update(
        index_root,
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
        index_root,
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
    roots.index_generations = root;
    if roots != current.roots {
        return Err(
            "cold index preparation role roots differ from independent preparation replay".into(),
        );
    }
    let mut records = BTreeMap::new();
    for (reference, value) in historical.records {
        if records.insert(reference.sha256, value).is_some() {
            return Err("cold index preparation repeats a complete record digest".into());
        }
    }
    let token = VerifiedTransition {
        base: Selector::for_descriptor(&previous)?,
        base_frame_sha256: previous_sha.clone(),
        source_sha256: source_sha256.clone(),
        request_sha256: request_sha256.clone(),
        review_sha256: input_sha256.clone(),
        roots,
        edits: BTreeMap::from([(map::Kind::IndexGenerations, edits)]),
        pages: generated,
        records,
        operation: current.operation.clone(),
        read_cas: vec![ReadCas {
            role: map::Kind::OwnerStates,
            literal: historical.owner_literal,
            value: historical.expected_owner_value,
        }],
        outcome: Completed::IndexPreparation(preparation.clone()),
    };
    let plan =
        super::storage::layout(&previous.binding, Some(previous_storage), &token, &mut data)?;
    if storage.controls != previous_storage.controls || storage.descriptor_slot.job != plan.job {
        return Err("cold index preparation differs from its deterministic reviewed layout".into());
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
