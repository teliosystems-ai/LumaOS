//! Original-Admin retirement of a fully read-back first direct publication
//! whose existing C anchor is provably still old. No NV operation, allocation,
//! deletion, empty-state adoption or automatic dispatch retry occurs here.
use super::super::super::paged::{cells, slots};
use super::super::*;

pub(super) struct Observation {
    pub descriptor: Descriptor,
    pub pending: control::PendingCell,
    pub cells: [control::Cell; 2],
    pub retirement: Option<control::InitialRetirement>,
    pub attempt_sha256: String,
    pub review_sha256: String,
    frames: [Vec<u8>; 3],
}

/// Reconstructs the failed zero-row event from the genuine retained legacy
/// journal and every original slot. Unselected progress is never a shortcut
/// around semantic reconstruction or the current original checkpoint.
fn observe<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Observation> {
    binding.validate()?;
    check()?;
    if pages.binding() != binding {
        return Err("initial retirement crosses the independently sealed C binding".into());
    }
    let actual = anchor.read()?;
    let mut live = || -> Result<()> {
        check()?;
        pages.check()?;
        if anchor.read()? != actual {
            return Err("actual C changed during failed-initial reconstruction".into());
        }
        check()
    };
    let controls = cells::Files::observe(pages, &mut live)?;
    let frames = [
        controls.read(0, &mut live)?.bytes().to_vec(),
        controls.read(1, &mut live)?.bytes().to_vec(),
        controls.read(2, &mut live)?.bytes().to_vec(),
    ];
    let selected = [
        control::Cell::from_frame(&frames[0])?,
        control::Cell::from_frame(&frames[1])?,
    ];
    let (pending, retirement) = match control::PendingFrame::from_frame(&frames[2])? {
        control::PendingFrame::Prepared { pending } => (pending, None),
        control::PendingFrame::RetiredInitial { retirement } => {
            (retirement.pending.clone(), Some(retirement))
        }
        _ => {
            return Err(
                "initial retirement requires exact interrupted original dispatch evidence".into(),
            )
        }
    };
    let control::Base::Legacy {
        binding: old_binding,
        cut,
    } = &pending.base
    else {
        return Err("initial retirement cannot reinterpret an established paged C cut".into());
    };
    if old_binding != binding
        || pending.binding != *binding
        || tpm::decode::<32>(&cut.nv_head)? != actual
        || selected[pending.inactive_index as usize] != pending.next
        || selected[1 - pending.inactive_index as usize] != control::Cell::empty_data(binding)?
    {
        return Err(
            "failed initial controls do not preserve the exact old C and sole staged next cell"
                .into(),
        );
    }
    let control::Cell::Selected {
        descriptor: location,
        ..
    } = &pending.next
    else {
        return Err("failed initial descriptor location is absent".into());
    };
    let directory = slots::Directory::at_reference(pages, &location.slot, &mut live)?;
    let descriptor = Descriptor::from_slot_frame(&directory.read(location, &mut live)?)?;
    pending.verify_descriptors(None, &descriptor)?;
    if descriptor
        .storage
        .as_ref()
        .ok_or("failed first descriptor lacks storage")?
        .controls
        != *controls.selection()
    {
        return Err(
            "failed initial descriptor changes the actual permanently allocated controls".into(),
        );
    }
    let proof = super::initial::verify_initial_objects(
        files,
        pages,
        binding,
        &descriptor,
        location,
        &mut live,
    )?;
    let attempt = hash(&serde_json::to_vec(&(
        "luma-c-direct-initial-attempt-v4",
        control::PendingFrame::Prepared {
            pending: pending.clone(),
        },
    ))?);
    let review = hash(&serde_json::to_vec(&(
        "luma-c-direct-old-nv-retirement-v4",
        binding,
        &pending,
        &selected,
        descriptor.bytes()?,
        proof.location(),
        proof.physical(),
        controls.selection(),
        bundle::hex(&actual),
    ))?);
    if let Some(retirement) = &retirement {
        retirement.validate_data()?;
        if retirement.cells != selected || retirement.review_sha256 != review {
            return Err(
                "retired initial marker substitutes the independently reconstructed failed attempt"
                    .into(),
            );
        }
        let OperationData::BootstrapProgress {
            request_sha256,
            original_authority,
            ..
        } = &descriptor.operation
        else {
            return Err("failed initial operation is not bootstrap".into());
        };
        if retirement.recovery_request_sha256 == *request_sha256
            || retirement.original_recovery.operation_id == original_authority.operation_id
        {
            return Err(
                "initial retirement reused the failed original request or operation".into(),
            );
        }
    }
    for (index, frame) in frames.iter().enumerate() {
        if controls.read(index, &mut live)?.bytes() != frame {
            return Err("failed initial control bytes changed during complete observation".into());
        }
    }
    live()?;
    Ok(Observation {
        descriptor,
        pending,
        cells: selected,
        retirement,
        attempt_sha256: attempt,
        review_sha256: review,
        frames,
    })
}

pub(super) fn review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let observed = observe(anchor, files, pages, binding, check)?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-direct-old-nv-retirement-v4",
        "stable_review_sha256":observed.descriptor.phase.review_sha256,
        "review_sha256":observed.review_sha256,"attempt_sha256":observed.attempt_sha256,
        "actual_nv_is_old":true,"already_retired":observed.retirement.is_some(),
        "expected_selected_descriptor_sha256":null,"filesystem_changed":false,
        "TPM_extended":false,"authority_returned":false,"production_qualified":false}),
    )
}

/// Changes only the permanent pending inode after complete old-NV and actual
/// allocation reconstruction. Fresh original Admin recovery cannot be reused
/// as a bootstrap permission; the failed request/operation must be distinct.
pub(super) fn retire<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    expected_review: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<control::InitialRetirement> {
    let observed = observe(anchor, files, pages, binding, &mut || authority.check())?;
    if observed.retirement.is_some() {
        return Err(
            "failed first dispatch is already retired; no retry or renewed authority".into(),
        );
    }
    let source = authority.source_binding();
    let control = source
        .paged_control
        .as_ref()
        .ok_or("retirement lacks original exact control")?;
    control.validate()?;
    let job = tpm::decode::<16>(&source.job)?;
    let audit = authority.audit();
    audit.validate()?;
    let OperationData::BootstrapProgress {
        request_sha256,
        original_authority,
        ..
    } = &observed.descriptor.operation
    else {
        return Err("initial retirement original operation is absent".into());
    };
    if expected_review != observed.review_sha256
        || source.command != "content-custody-paged-reconcile"
        || source.installation != binding.installation
        || job == [0; 16]
        || source.job != bundle::hex(&job)
        || control.stable_review_sha256 != observed.descriptor.phase.review_sha256
        || control.expected_window_sha256 != observed.review_sha256
        || control.expected_selected_descriptor_sha256.is_some()
        || control.attempt_sha256.as_deref() != Some(observed.attempt_sha256.as_str())
        || source.request_sha256 == *request_sha256
        || audit.operation_id.is_none()
        || audit.operation_id == original_authority.operation_id
    {
        return Err("initial retirement lacks separate fresh exact original Admin recovery".into());
    }
    let source_hash = hash(&COperation::Admin(authority).source_bytes()?);
    let retirement = control::InitialRetirement {
        schema_version: 4,
        domain: "luma-c-direct-initial-retirement-v4".into(),
        pending: observed.pending.clone(),
        cells: observed.cells.clone(),
        review_sha256: observed.review_sha256.clone(),
        recovery_request_sha256: authority.source_binding().request_sha256.clone(),
        recovery_source_sha256: source_hash,
        original_recovery: authority.audit().clone(),
    };
    retirement.validate_data()?;
    let old = tpm::decode::<32>(&observed.descriptor.previous_nv_head)?;
    let mut live = || -> Result<()> {
        authority.check()?;
        if anchor.read()? != old {
            return Err("C changed during fresh reviewed initial retirement".into());
        }
        authority.check()
    };
    let controls = cells::Files::open(
        pages,
        observed
            .descriptor
            .storage
            .as_ref()
            .ok_or("retirement lost fixed controls")?
            .controls
            .clone(),
        &mut live,
    )?;
    for (index, frame) in observed.frames.iter().enumerate() {
        if controls.read(index, &mut live)?.bytes() != frame {
            return Err("initial evidence changed after retirement review".into());
        }
    }
    let pending = controls.read(2, &mut live)?;
    controls.rewrite(
        &pending,
        &control::PendingFrame::RetiredInitial {
            retirement: retirement.clone(),
        }
        .frame()?,
        &mut live,
    )?;
    live()?;
    drop(live);
    drop(controls);
    let verified = observe(anchor, files, pages, binding, &mut || authority.check())?;
    if verified
        .retirement
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?
        != Some(serde_json::to_vec(&retirement)?)
    {
        return Err("retired initial pending inode failed complete original readback".into());
    }
    authority.check()?;
    Ok(retirement)
}
