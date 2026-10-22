//! Read-only installed Admin observations. Output hashes describe exact actual
//! pending bytes and current NV; they never select, repair or redispatch C.
use super::*;

impl PagedStore<super::super::super::ContentAnchor> {
    pub(crate) fn maintenance_review(
        &mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.live(check)?;
        if self.descriptor.phase.state == bootstrap::State::Pending {
            return self.bootstrap_review(check);
        }
        self.descriptor.phase.require_ready()?;
        let value = serde_json::json!({
            "schema_version":3, "installation":self.descriptor.binding.installation,
            "stable_review_sha256":self.descriptor.phase.review_sha256,
            "selected_descriptor_sha256":self.selected.descriptor_sha256,
            "checkpoint_head":self.selected.nv_head,
            "phase":self.descriptor.phase,
            "global_format_ready":true,"owner_permission_returned":false,
            "filesystem_changed":false,"TPM_extended":false,
            "authority_returned":false,"production_qualified":false,
        });
        self.live(check)?;
        Ok(value)
    }
    pub(crate) fn pending_recovery_review(
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        check()?;
        let anchor = super::super::super::ContentAnchor::installed()?;
        let binding = map::CustodyBinding {
            installation: anchor.installation().into(),
            sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
        };
        recovery_review_at(anchor, Files::installed(), binding, check)
    }
}

pub(super) fn recovery_review_at<A: Checkpoint>(
    mut anchor: A,
    files: Files,
    binding: map::CustodyBinding,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    binding.validate()?;
    check()?;
    validate_genesis_at(
        &files.root,
        &binding.installation,
        tpm::decode(&binding.sealed_genesis_sha256)?,
    )?;
    let pages = PageStore::open(&files.root, binding.clone(), check)?;
    // Direct controls are a separate closed reader. Never reinterpret them as
    // this retained hash-format pending record or fall back to a legacy Store.
    pages.require_hash_controls_empty()?;
    let bytes = pages.read("pending.json", CONTROL_BYTES, check)?;
    let pending: Pending = canonical(&bytes, CONTROL_BYTES)?;
    pending.bytes()?;
    let prefix = format!("attempts/{}", pending.attempt);
    if pages.read(&format!("{prefix}/prepared.json"), CONTROL_BYTES, check)? != bytes {
        return Err("pending Admin review differs from the original immutable prepared cut".into());
    }
    let dispatch = serde_json::to_vec(&(
        "luma-paged-c-single-dispatch-intent-v3",
        hash(&pending.bytes()?),
    ))?;
    if pages.read(&format!("{prefix}/dispatch.json"), 4096, check)? != dispatch {
        return Err("pending Admin review lacks its exact original dispatch intent".into());
    }
    let base: BaseSnapshot = canonical(
        &pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, check)?,
        CONTROL_BYTES,
    )?;
    let next: Descriptor = canonical(
        &pages.read(&format!("{prefix}/next.json"), PAGE_BYTES, check)?,
        PAGE_BYTES,
    )?;
    pending.validate_base(&base, &next)?;
    if base.binding() != &binding
        || next.storage.is_some()
        || pages.read_page(&pending.next.descriptor_sha256, check)? != next.bytes()?
    {
        return Err(
            "pending Admin review substitutes sealed C binding or complete next descriptor".into(),
        );
    }
    let actual = anchor.read()?;
    let selected_bytes = pages.read("selected.json", 4096, check)?;
    let selected: Selector = canonical(&selected_bytes, 4096)?;
    selected.validate()?;
    if (actual != tpm::decode(&pending.base.nv_head)?
        && actual != tpm::decode(&pending.next.nv_head)?)
        || (selected != pending.base && selected != pending.next)
    {
        return Err(
            "actual C matches neither exact original pending cut; preserve evidence".into(),
        );
    }
    let review = hash(&serde_json::to_vec(&(
        "luma-paged-c-reconciliation-v3",
        &binding,
        &pending,
        &base,
        &next,
        bundle::hex(&actual),
        &selected,
    ))?);
    check()?;
    if anchor.read()? != actual
        || pages.read("pending.json", CONTROL_BYTES, check)? != bytes
        || pages.read("selected.json", 4096, check)? != selected_bytes
        || pages.read(&format!("{prefix}/prepared.json"), CONTROL_BYTES, check)? != bytes
        || pages.read(&format!("{prefix}/dispatch.json"), 4096, check)? != dispatch
        || pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, check)?
            != serde_json::to_vec(&base)?
        || pages.read_page(&pending.next.descriptor_sha256, check)? != next.bytes()?
    {
        return Err("actual pending C changed before Admin observation completion".into());
    }
    let value = serde_json::json!({
        "schema_version":3,"installation":binding.installation,
        "stable_review_sha256":next.phase.review_sha256,
        "review_sha256":review,"attempt_sha256":pending.attempt,
        "expected_selected_descriptor_sha256":pending.base.descriptor_sha256,
        "actual_nv_head":bundle::hex(&actual),
        "nv_is_old":bundle::hex(&actual)==pending.base.nv_head,
        "nv_is_new":bundle::hex(&actual)==pending.next.nv_head,
        "selected_filesystem_descriptor_sha256":selected.descriptor_sha256,
        "next_descriptor_sha256":pending.next.descriptor_sha256,
        "initial_bootstrap":matches!(base,BaseSnapshot::Legacy{..}),
        "filesystem_changed":false,"TPM_extended":false,"event_redispatched":false,
        "authority_returned":false,"production_qualified":false,
    });
    if serde_json::to_vec(&value)?.len() > 8192 {
        return Err("pending review exceeds finite output".into());
    }
    check()?;
    Ok(value)
}
