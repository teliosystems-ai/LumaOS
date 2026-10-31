//! Historical DATA replay only. A current C checkpoint authenticates retained
//! before/after descriptors and immutable records; this module never recreates
//! an old OriginalCOperation, revives a grant, grants writer Go or releases a
//! liability. The actual cold consumer separately verifies map/slot/physical
//! closure and the descriptor's typed operation under its fresh caller checks.
use super::job::{JobReservation, JobSelection};
use super::*;

pub(in crate::content_checkpoint::custody::v2_publication) trait SelectedPreparationReader {
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<Vec<u8>>>;
    fn record(
        &mut self,
        reference: &RecordRef,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>>;
}

/// Extracted from the actually checkpoint-selected typed operation, not a
/// worker-supplied callback, signed-looking JSON or a historical grant check.
pub(in crate::content_checkpoint::custody::v2_publication) struct SelectedEventData<'a> {
    pub(in crate::content_checkpoint::custody::v2_publication) binding: &'a OwnerBinding,
    pub(in crate::content_checkpoint::custody::v2_publication) request_sha256: &'a str,
    pub(in crate::content_checkpoint::custody::v2_publication) input_sha256: &'a str,
    pub(in crate::content_checkpoint::custody::v2_publication) source_sha256: &'a str,
    pub(in crate::content_checkpoint::custody::v2_publication) preparation: &'a RecordRef,
    pub(in crate::content_checkpoint::custody::v2_publication) original_authority: &'a Audit,
}

/// Deliberately NOT VerifiedIndexPreparation and not accepted by a writer-Go
/// factory. These exact old/new CAS bytes drive the cold map-delta verifier.
pub(in crate::content_checkpoint::custody::v2_publication) struct HistoricalPreparationData {
    pub(in crate::content_checkpoint::custody::v2_publication) owner_literal: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_index_value:
        Option<Vec<u8>>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) records: Vec<(RecordRef, Vec<u8>)>,
}

fn record(
    reader: &mut impl SelectedPreparationReader,
    reference: &RecordRef,
    limit: usize,
    credit: &mut u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    check()?;
    reference.validate()?;
    if reference.bytes > limit as u64 {
        return Err("selected preparation record exceeds closed class before private IO".into());
    }
    *credit = credit
        .checked_sub(reference.bytes + 1)
        .ok_or("selected preparation read credit exhausted before IO")?;
    let bytes = reader.record(reference, limit, check)?;
    check()?;
    if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
        return Err("selected preparation immutable record hash/length differs".into());
    }
    Ok(bytes)
}

fn historical_source_sha256(p: &Attribution, binding: &OwnerBinding) -> Result<String> {
    // Reconstruct descriptive source bytes only; no ephemeral original context
    // is created and no historic session is treated as current authorization.
    let data = crate::content_checkpoint::custody::protocol::TypedOperationSource {
        schema_version: 1,
        request_sha256: p.rpc_sha256.clone(),
        purpose: SourcePurpose::IndexPrepare,
        profile: p.profile.clone(),
        storage_device: p.storage_device.clone(),
        binding: binding.clone(),
        worker_pid: p.worker_pid,
        worker_start: p.worker_start,
        worker_label: p.worker_label.clone(),
        lease: p.lease.clone(),
    };
    Ok(hash(&serde_json::to_vec(&(
        "luma-c-original-worker-source-v1",
        data,
    ))?))
}

/// The exact retained before/after cut of one index event: only the index
/// role map, and for a job selection the owner role map, may differ and the
/// after descriptor directly succeeds before.
fn selected_cut(
    before: &Descriptor,
    after: &Descriptor,
    event: &SelectedEventData<'_>,
    owner_changes: bool,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    before.validate()?;
    after.validate()?;
    event.binding.validate()?;
    digest(event.request_sha256)?;
    digest(event.input_sha256)?;
    digest(event.source_sha256)?;
    event.original_authority.validate()?;
    before.phase.require_ready()?;
    after.phase.require_ready()?;
    if before.storage.is_none()
        || after.storage.is_none()
        || before.binding != after.binding
        || after.previous_descriptor_sha256.as_deref() != Some(hash(&before.slot_frame()?).as_str())
        || after.previous_nv_head != before.selected_nv_head
        || after.sequence
            != before
                .sequence
                .checked_add(1)
                .ok_or("selected preparation sequence overflow")?
        || !owner_changes && before.roots.owners != after.roots.owners
        || before.roots.recipients != after.roots.recipients
        || before.roots.signers != after.roots.signers
        || before.roots.unavailable != after.roots.unavailable
        || before.roots.restore_reservations != after.roots.restore_reservations
        || before.roots.archive_inventory != after.roots.archive_inventory
    {
        return Err("selected preparation changes unrelated C roots/before cut or actual physical owner selection".into());
    }
    Ok(())
}

/// The retained before owner and index value, read from the before roots.
struct SelectedOwner {
    literal: Vec<u8>,
    owner_value: Vec<u8>,
    head_ref: RecordRef,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    index_value: Option<Vec<u8>>,
}

fn selected_owner(
    reader: &mut impl SelectedPreparationReader,
    before: &Descriptor,
    binding: &OwnerBinding,
    read_credit: &mut u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<SelectedOwner> {
    let literal = owner_key(binding)?.into_bytes();
    check()?;
    if reader
        .value(&before.roots.unavailable, &literal, check)?
        .is_some()
    {
        return Err("selected preparation owner was unavailable".into());
    }
    check()?;
    let owner_value = reader
        .value(&before.roots.owners, &literal, check)?
        .ok_or("selected preparation original owner absent")?;
    check()?;
    let owner: OwnerLeaf = canonical(&owner_value, map::MAX_VALUE_BYTES)?;
    owner.validate(&binding.installation, &before.legacy)?;
    let (head_ref, physical) = match owner {
        OwnerLeaf::V2 {
            binding: selected,
            head,
            physical,
        } if selected == *binding => (head, physical),
        _ => return Err("selected preparation lacks its original exact paged owner".into()),
    };
    let head =
        OwnerHeadV2::from_canonical(&record(reader, &head_ref, PAGE_BYTES, read_credit, check)?)?;
    check()?;
    let index_value = reader.value(&before.roots.index_generations, &literal, check)?;
    check()?;
    Ok(SelectedOwner {
        literal,
        owner_value,
        head_ref,
        head,
        physical,
        index_value,
    })
}

/// The exact replacement leaf DATA and its indirect map reference value.
fn replacement_leaf(leaf: &Leaf, binding: &OwnerBinding) -> Result<(Vec<u8>, RecordRef, Vec<u8>)> {
    leaf.validate(binding)?;
    let leaf_bytes = serde_json::to_vec(leaf)?;
    let leaf_ref = RecordRef {
        sha256: hash(&leaf_bytes),
        bytes: leaf_bytes.len() as u64,
    };
    let replacement = serde_json::to_vec(&Reference {
        schema_version: 2,
        binding: binding.clone(),
        record: leaf_ref.clone(),
    })?;
    Reference::parse(&replacement, binding)?;
    Ok((replacement, leaf_ref, leaf_bytes))
}

/// The after owner/index CAS and the actually retained replacement leaf. Its
/// read must already be reserved from the caller's finite credit.
#[allow(clippy::too_many_arguments)]
fn after_cas(
    reader: &mut impl SelectedPreparationReader,
    after: &Descriptor,
    owner: &SelectedOwner,
    owner_value: &[u8],
    replacement: &[u8],
    leaf_ref: &RecordRef,
    leaf_bytes: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let after_owner = reader.value(&after.roots.owners, &owner.literal, check)?;
    check()?;
    let after_index = reader.value(&after.roots.index_generations, &owner.literal, check)?;
    check()?;
    if after_owner.as_deref() != Some(owner_value) || after_index.as_deref() != Some(replacement) {
        return Err(
            "selected preparation role CAS differs from exact canonical retained data".into(),
        );
    }
    check()?;
    let stored = reader.record(leaf_ref, LEAF_BYTES, check)?;
    check()?;
    if stored != leaf_bytes {
        return Err("selected preparation replacement index leaf differs".into());
    }
    check()
}

/// before/after MUST be independently authenticated by the actual cold C
/// consumer. The caller's finite original check remains fresh at every IO;
/// this format replay itself returns DATA and supplies no C-current assertion.
pub(in crate::content_checkpoint::custody::v2_publication) fn replay_selected_data(
    reader: &mut impl SelectedPreparationReader,
    before: &Descriptor,
    after: &Descriptor,
    event: SelectedEventData<'_>,
    mut read_credit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<HistoricalPreparationData> {
    selected_cut(before, after, &event, false, check)?;
    let bytes = record(
        reader,
        event.preparation,
        PREPARATION_BYTES as usize,
        &mut read_credit,
        check,
    )?;
    let preparation = Preparation::parse(&bytes)?;
    if preparation.input.binding != *event.binding
        || preparation.original.rpc_sha256 != event.request_sha256
        || preparation.input.sha256()? != event.input_sha256
        || preparation.original.effect != *event.original_authority
        || historical_source_sha256(&preparation.original, &preparation.input.binding)?
            != event.source_sha256
        || preparation.base.descriptor_sha256 != hash(&before.bytes()?)
        || preparation.base.nv_head != before.selected_nv_head
    {
        return Err("selected preparation body substitutes exact checkpointed source/attribution/before tuple".into());
    }
    let owner = selected_owner(reader, before, event.binding, &mut read_credit, check)?;
    let old_ref = Reference::parse(
        owner
            .index_value
            .as_ref()
            .ok_or("phase preparation original index absent")?,
        event.binding,
    )?;
    let old_leaf = Leaf::parse(
        &record(reader, &old_ref.record, LEAF_BYTES, &mut read_credit, check)?,
        event.binding,
    )?;
    if old_leaf.has_preparation()
        || owner.head.binding != *event.binding
        || old_leaf.current_job.as_ref().map(|r| r.sha256.as_str())
            != Some(preparation.review.base_sha256.as_str())
    {
        return Err(
            "selected preparation overwrites existing liability or changes selected job/owner"
                .into(),
        );
    }
    let base = Base {
        binding: event.binding.clone(),
        descriptor_sha256: hash(&before.bytes()?),
        nv_head: before.selected_nv_head.clone(),
        owner_sha256: owner.head.sha256()?,
        physical: owner.physical.clone(),
        segments: owner.head.history.segments,
        index_sha256: Some(old_leaf.sha256()?),
    };
    let mut next_leaf = old_leaf.clone();
    next_leaf.preparation = Some(event.preparation.clone());
    let (replacement, leaf_ref, leaf_bytes) = replacement_leaf(&next_leaf, event.binding)?;
    // Reserve this later actual read BEFORE giving the remaining finite
    // immutable-record credit to the complete inventory traversal.
    read_credit = read_credit
        .checked_sub(leaf_ref.bytes + 1)
        .ok_or("selected replacement-leaf credit exhausted before inventory IO")?;
    let mut records = Vec::new();
    let objects = inventory::walk(
        &preparation.inventory,
        event.binding,
        read_credit,
        check,
        |reference, current| {
            current()?;
            let data = reader.record(reference, PAGE_BYTES, current)?;
            current()?;
            records.push((reference.clone(), data.clone()));
            Ok(data)
        },
    )?;
    preparation.replay_data(
        &base,
        &preparation.input,
        &preparation.review,
        &objects,
        &preparation.original,
        check,
    )?;
    records.push((event.preparation.clone(), bytes));
    // This actual read was reserved before the inventory traversal above.
    after_cas(
        reader,
        after,
        &owner,
        &owner.owner_value,
        &replacement,
        &leaf_ref,
        &leaf_bytes,
        check,
    )?;
    records.push((leaf_ref, leaf_bytes));
    check()?;
    Ok(HistoricalPreparationData {
        owner_literal: owner.literal,
        expected_owner_value: owner.owner_value,
        expected_index_value: owner.index_value,
        replacement_index_value: replacement,
        records,
    })
}

/// The same historical DATA replay for a checkpoint-selected Start
/// reservation. Its builder is the reservation's own retained DATA: the replay
/// proves exact first-job/plan closure, never that it is the current image.
pub(in crate::content_checkpoint::custody::v2_publication) fn replay_reserved_start_data(
    reader: &mut impl SelectedPreparationReader,
    before: &Descriptor,
    after: &Descriptor,
    event: SelectedEventData<'_>,
    mut read_credit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<HistoricalPreparationData> {
    selected_cut(before, after, &event, false, check)?;
    let bytes = record(
        reader,
        event.preparation,
        PREPARATION_BYTES as usize,
        &mut read_credit,
        check,
    )?;
    let reservation = JobReservation::parse(&bytes)?;
    if reservation.input().binding != *event.binding
        || reservation.original().rpc_sha256 != event.request_sha256
        || reservation.input().sha256()? != event.input_sha256
        || reservation.original().effect != *event.original_authority
        || historical_source_sha256(reservation.original(), &reservation.input().binding)?
            != event.source_sha256
        || reservation.base().descriptor_sha256 != hash(&before.bytes()?)
        || reservation.base().nv_head != before.selected_nv_head
    {
        return Err("selected Start reservation body substitutes exact checkpointed source/attribution/before tuple".into());
    }
    let owner = selected_owner(reader, before, event.binding, &mut read_credit, check)?;
    if owner.index_value.is_some() || owner.head.binding != *event.binding {
        return Err(
            "selected Start reservation replaces an existing C index leaf or changes owner".into(),
        );
    }
    let base = Base {
        binding: event.binding.clone(),
        descriptor_sha256: hash(&before.bytes()?),
        nv_head: before.selected_nv_head.clone(),
        owner_sha256: owner.head.sha256()?,
        physical: owner.physical.clone(),
        segments: owner.head.history.segments,
        index_sha256: None,
    };
    let next_leaf = Leaf {
        schema_version: 2,
        binding: event.binding.clone(),
        current_generation: None,
        current_job: None,
        preparation: Some(event.preparation.clone()),
    };
    let (replacement, leaf_ref, leaf_bytes) = replacement_leaf(&next_leaf, event.binding)?;
    // The final actual leaf read must fit the remaining finite credit.
    if read_credit < leaf_ref.bytes + 1 {
        return Err("selected replacement-leaf credit exhausted before Start replay".into());
    }
    reservation.replay_data(
        &base,
        &owner.head,
        reservation.input(),
        reservation.builder(),
        reservation.original(),
        check,
    )?;
    after_cas(
        reader,
        after,
        &owner,
        &owner.owner_value,
        &replacement,
        &leaf_ref,
        &leaf_bytes,
        check,
    )?;
    let records = vec![(event.preparation.clone(), bytes), (leaf_ref, leaf_bytes)];
    check()?;
    Ok(HistoricalPreparationData {
        owner_literal: owner.literal,
        expected_owner_value: owner.owner_value,
        expected_index_value: None,
        replacement_index_value: replacement,
        records,
    })
}

/// The owner and index role CAS of one selected first job. Like
/// HistoricalPreparationData it is DATA for the cold map-delta verifier only.
pub(in crate::content_checkpoint::custody::v2_publication) struct HistoricalSelectionData {
    pub(in crate::content_checkpoint::custody::v2_publication) owner_literal: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) records: Vec<(RecordRef, Vec<u8>)>,
}

/// The same historical DATA replay for a checkpoint-selected first job. The
/// consumed reservation is read from the before cut, its transition and job
/// bytes are re-derived from the retained owner head and its own builder DATA,
/// and the measured physical delta is checked against its reserved liability.
/// The store blob is NOT re-read here: the measured inventory is selection
/// DATA, and every later store opening compares the store with the owner leaf
/// this event selects.
pub(in crate::content_checkpoint::custody::v2_publication) fn replay_selected_job_data(
    reader: &mut impl SelectedPreparationReader,
    before: &Descriptor,
    after: &Descriptor,
    event: SelectedEventData<'_>,
    mut read_credit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<HistoricalSelectionData> {
    selected_cut(before, after, &event, true, check)?;
    let bytes = record(
        reader,
        event.preparation,
        PREPARATION_BYTES as usize,
        &mut read_credit,
        check,
    )?;
    let selection = JobSelection::parse(&bytes)?;
    if selection.base().binding != *event.binding
        || selection.original().rpc_sha256 != event.request_sha256
        || selection.original().effect != *event.original_authority
        || historical_source_sha256(selection.original(), event.binding)? != event.source_sha256
        || selection.base().descriptor_sha256 != hash(&before.bytes()?)
        || selection.base().nv_head != before.selected_nv_head
    {
        return Err("selected job selection body substitutes exact checkpointed source/attribution/before tuple".into());
    }
    let owner = selected_owner(reader, before, event.binding, &mut read_credit, check)?;
    let expected_index_value = owner
        .index_value
        .clone()
        .ok_or("selected job selection original reservation leaf absent")?;
    let old_ref = Reference::parse(&expected_index_value, event.binding)?;
    let old_leaf = Leaf::parse(
        &record(reader, &old_ref.record, LEAF_BYTES, &mut read_credit, check)?,
        event.binding,
    )?;
    match (
        &old_leaf.current_generation,
        &old_leaf.current_job,
        &old_leaf.preparation,
    ) {
        (None, None, Some(reserved)) if reserved == selection.reservation() => {}
        _ => {
            return Err(
                "selected job selection does not consume the exact C-selected reservation".into(),
            )
        }
    }
    let reservation = JobReservation::parse(&record(
        reader,
        selection.reservation(),
        PREPARATION_BYTES as usize,
        &mut read_credit,
        check,
    )?)?;
    selection.validate_against(&reservation, selection.reservation())?;
    let base = Base {
        binding: event.binding.clone(),
        descriptor_sha256: hash(&before.bytes()?),
        nv_head: before.selected_nv_head.clone(),
        owner_sha256: owner.head.sha256()?,
        physical: owner.physical.clone(),
        segments: owner.head.history.segments,
        index_sha256: Some(old_leaf.sha256()?),
    };
    if selection.base() != &base
        || owner.head.binding != *event.binding
        || reservation.input().binding != *event.binding
        || reservation.input().sha256()? != event.input_sha256
    {
        return Err(
            "selected job selection differs from its retained owner/reservation/input".into(),
        );
    }
    reservation.replay_data(
        reservation.base(),
        &owner.head,
        reservation.input(),
        reservation.builder(),
        reservation.original(),
        check,
    )?;
    reservation.job_bytes(&owner.head, check)?;
    let next_leaf = Leaf {
        schema_version: 2,
        binding: event.binding.clone(),
        current_generation: None,
        current_job: Some(selection.job().clone()),
        preparation: None,
    };
    let (replacement, leaf_ref, leaf_bytes) = replacement_leaf(&next_leaf, event.binding)?;
    let next_owner = OwnerLeaf::V2 {
        binding: event.binding.clone(),
        head: owner.head_ref.clone(),
        physical: selection.physical_after().clone(),
    };
    next_owner.validate(&event.binding.installation, &before.legacy)?;
    let owner_value = serde_json::to_vec(&next_owner)?;
    if owner_value.len() > map::MAX_VALUE_BYTES {
        return Err("selected job selection owner leaf exceeds its bounded map value".into());
    }
    // The final actual leaf read must fit the remaining finite credit.
    if read_credit < leaf_ref.bytes + 1 {
        return Err(
            "selected replacement-leaf credit exhausted before job selection replay".into(),
        );
    }
    after_cas(
        reader,
        after,
        &owner,
        &owner_value,
        &replacement,
        &leaf_ref,
        &leaf_bytes,
        check,
    )?;
    let records = vec![(event.preparation.clone(), bytes), (leaf_ref, leaf_bytes)];
    check()?;
    Ok(HistoricalSelectionData {
        owner_literal: owner.literal,
        expected_owner_value: owner.owner_value,
        replacement_owner_value: owner_value,
        expected_index_value,
        replacement_index_value: replacement,
        records,
    })
}
