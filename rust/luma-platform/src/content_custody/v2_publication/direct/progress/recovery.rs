//! Fresh recovery may complete only a proved already-new progress dispatch.
//! Rejected/third-NV attempts retain all allocations and uncertainty. There is
//! no retry, guessed adoption, authority renewal or second C advance here.
use super::super::super::direct::reader::{self, ObservedCut};
use super::*;

fn observed<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(ObservedCut, String, String, String)> {
    let cut = reader::observe(anchor, pages, binding, check)?;
    let descriptor = cut.descriptor();
    let control::PendingFrame::Prepared { pending } = cut.pending() else {
        return Err("direct progress recovery requires one exact uncompleted dispatch".into());
    };
    let control::Cell::Selected {
        descriptor: location,
        ..
    } = cut.cell()
    else {
        return Err("direct progress recovery has no actual selected descriptor".into());
    };
    if pending.next != *cut.cell() || descriptor.sequence <= 1 {
        return Err("direct progress recovery cannot adopt old NV or an initial attempt".into());
    }
    let expected = tpm::decode::<32>(&descriptor.selected_nv_head)?;
    let mut live = || -> Result<()> {
        check()?;
        if anchor.read()? != expected {
            return Err("actual C changed during progress recovery observation".into());
        }
        check()
    };
    verify_selected(files, pages, descriptor, location, &mut live)?;
    let control::Base::Slot {
        cell:
            control::Cell::Selected {
                descriptor: base_location,
                ..
            },
        ..
    } = &pending.base
    else {
        return Err("direct progress recovery does not continue an exact old slot".into());
    };
    let base_bytes = slots::Directory::at_reference(pages, &base_location.slot, &mut live)?
        .read(base_location, &mut live)?;
    let base = Descriptor::from_slot_frame(&base_bytes)?;
    let selected = hash(&base.bytes()?);
    let attempt = hash(&serde_json::to_vec(&(
        "luma-c-direct-progress-attempt-v4",
        pending,
    ))?);
    let review = hash(&serde_json::to_vec(&(
        "luma-c-direct-progress-recovery-v4",
        cut.review_sha256()?,
        &attempt,
        &selected,
        descriptor
            .storage
            .as_ref()
            .ok_or("recovery storage absent")?,
    ))?);
    live()?;
    drop(live);
    Ok((cut, attempt, review, selected))
}
pub(in crate::content_checkpoint::custody) fn recovery_review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    pages: &PageStore,
    binding: &map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (cut, attempt, review, selected) = observed(anchor, files, pages, binding, check)?;
    Ok(
        serde_json::json!({"schema_version":4,"profile":"luma-c-direct-progress-recovery-v4",
        "stable_review_sha256":cut.descriptor().phase.review_sha256,"review_sha256":review,
        "attempt_sha256":attempt,"expected_selected_descriptor_sha256":selected,
        "actual_nv_head":cut.descriptor().selected_nv_head,"actual_nv_is_new":true,
        "filesystem_changed":false,"TPM_extended":false,"authority_returned":false,"production_qualified":false}),
    )
}
pub(in crate::content_checkpoint::custody) fn reconcile<A: Checkpoint>(
    mut anchor: A,
    files: Files,
    pages: PageStore,
    binding: map::CustodyBinding,
    expected_review: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<Backend<A>> {
    authority.check()?;
    let (cut, attempt, review, selected) =
        observed(&mut anchor, &files, &pages, &binding, &mut || {
            authority.check()
        })?;
    let descriptor = cut.descriptor();
    let source = authority.source_binding();
    let control_source = source
        .paged_control
        .as_ref()
        .ok_or("progress recovery lacks authenticated original controls")?;
    control_source.validate()?;
    let audit = authority.audit();
    audit.validate()?;
    let opaque = tpm::decode::<16>(&source.job)?;
    let OperationData::BootstrapProgress {
        request_sha256,
        original_authority,
        ..
    } = &descriptor.operation
    else {
        return Err("progress recovery operation class changed".into());
    };
    if expected_review != review
        || source.command != "content-custody-paged-reconcile"
        || source.installation != binding.installation
        || opaque == [0; 16]
        || bundle::hex(&opaque) != source.job
        || control_source.stable_review_sha256 != descriptor.phase.review_sha256
        || control_source.expected_window_sha256 != review
        || control_source
            .expected_selected_descriptor_sha256
            .as_deref()
            != Some(selected.as_str())
        || control_source.attempt_sha256.as_deref() != Some(attempt.as_str())
        || audit.operation_id.is_none()
        || audit.operation_id == original_authority.operation_id
        || source.request_sha256 == *request_sha256
        || audit.usage.action != crate::finite_grants::Action::RecoverResource
        || audit.usage.selector.id != "content-custody-paged-reconcile-v3"
        || audit.usage.selector.digest != review
    {
        return Err(
            "progress completion requires separate fresh exact original Admin recovery".into(),
        );
    }
    let control::PendingFrame::Prepared { pending } = cut.pending() else {
        return Err("progress dispatch is no longer pending".into());
    };
    let controls = cells::Files::open(
        &pages,
        descriptor
            .storage
            .as_ref()
            .ok_or("selected direct storage absent")?
            .controls
            .clone(),
        &mut || authority.check(),
    )?;
    let expected = tpm::decode::<32>(&descriptor.selected_nv_head)?;
    let mut live = || -> Result<()> {
        authority.check()?;
        if anchor.read()? != expected {
            return Err("actual C changed during fixed progress recovery".into());
        }
        authority.check()
    };
    let snapshot = controls.read(2, &mut live)?;
    if snapshot.bytes() != cut.pending().frame()? {
        return Err("pending progress bytes changed after exact recovery review".into());
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
    Backend::open(anchor, files, binding, &mut || authority.check())
}
