//! Explicit retirement of an uncertain FIRST dispatch whose actual C NV is
//! still the independently reconstructed legacy head. Retirement never opens
//! the old writer, deletes evidence or resends the old TPM event. Resumption is
//! a separate original Admin operation with a new request and operation ID.
use super::*;

pub(super) struct RetiredCut {
    pending: Pending,
    next: Descriptor,
}
pub(super) struct Initial {
    pub anchor: super::super::super::super::ContentAnchor,
    pub files: Files,
    pub pages: PageStore,
    pub binding: map::CustodyBinding,
    pub legacy: LegacyCut,
    pub bytes: Vec<u8>,
    pub genesis_proof: Vec<u8>,
    pub retired: Option<RetiredCut>,
}
impl Initial {
    pub fn previous_retirement(&self) -> Option<String> {
        self.retired.as_ref().map(|cut| cut.pending.attempt.clone())
    }
    pub fn intent(&self, blueprint: &Blueprint, phase: &Phase, base: &Selector) -> Result<String> {
        start_intent(blueprint, phase, base, self.retired.as_ref())
    }
    pub fn check(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.pages.check()?;
        if self.anchor.installation() != self.binding.installation
            || bundle::hex(&self.anchor.genesis_event()) != self.binding.sealed_genesis_sha256
            || self.anchor.read()? != tpm::decode(&self.legacy.nv_head)?
            || self.files.read(JOURNAL, check)? != self.bytes
            || self.files.read("genesis.json", check)? != self.genesis_proof
            || !self.pages.absent("pending.json")?
        {
            return Err(
                "initial-maintenance token no longer matches actual original sealed C cut".into(),
            );
        }
        let base = BaseSnapshot::Legacy {
            binding: self.binding.clone(),
            cut: self.legacy.clone(),
        }
        .selector()?;
        if self.pages.absent("selected.json")? {
            if self.retired.is_some() {
                return Err(
                    "retired first-dispatch namespace lost its exact legacy selector".into(),
                );
            }
        } else if self.pages.read("selected.json", 4096, check)? != base.bytes()? {
            return Err("first-dispatch namespace selector changed; no legacy adoption".into());
        }
        if let Some(retired) = &self.retired {
            let prefix = format!("attempts/{}", retired.pending.attempt);
            if self
                .pages
                .read(&format!("{prefix}/retired.json"), CONTROL_BYTES, check)?
                != retired.pending.bytes()?
                || self
                    .pages
                    .read(&format!("{prefix}/prepared.json"), CONTROL_BYTES, check)?
                    != retired.pending.bytes()?
                || self
                    .pages
                    .read(&format!("{prefix}/next.json"), PAGE_BYTES, check)?
                    != retired.next.bytes()?
                || self
                    .pages
                    .read(&format!("{prefix}/base.json"), CONTROL_BYTES, check)?
                    != (BaseSnapshot::Legacy {
                        binding: self.binding.clone(),
                        cut: self.legacy.clone(),
                    })
                    .bytes()?
                || self
                    .pages
                    .read(&format!("{prefix}/selector.json"), 4096, check)?
                    != retired.pending.next.bytes()?
                || self
                    .pages
                    .read(&format!("{prefix}/dispatch.json"), 4096, check)?
                    != serde_json::to_vec(&(
                        "luma-paged-c-single-dispatch-intent-v3",
                        hash(&retired.pending.bytes()?),
                    ))?
                || self
                    .pages
                    .read_page(&retired.pending.next.descriptor_sha256, check)?
                    != retired.next.bytes()?
                || !self.pages.absent(&format!("{prefix}/completed.json"))?
            {
                return Err("explicit original first-dispatch retirement evidence changed".into());
            }
        }
        check()?;
        if self.anchor.read()? != tpm::decode(&self.legacy.nv_head)? {
            return Err("C NV changed after first-dispatch retirement observation".into());
        }
        check()
    }
    pub fn require_new_operation(&self, authority: &mut OriginalCAdminOperation<'_>) -> Result<()> {
        authority.check()?;
        if let Some(retired) = &self.retired {
            match &retired.next.operation {
                OperationData::BootstrapProgress {
                    request_sha256,
                    original_authority,
                    ..
                } => {
                    fresh_identity(
                        request_sha256,
                        original_authority.operation_id.as_deref(),
                        &authority.source_binding().request_sha256,
                        authority.audit().operation_id.as_deref(),
                    )?;
                }
                _ => {
                    return Err(
                        "initial retirement does not describe an actual bootstrap event".into(),
                    )
                }
            }
        }
        authority.check()
    }
}

fn fresh_identity(
    old_request: &str,
    old_operation: Option<&str>,
    request: &str,
    operation: Option<&str>,
) -> Result<()> {
    if old_operation.is_none()
        || operation.is_none()
        || old_request == request
        || old_operation == operation
    {
        return Err("a retired first dispatch requires both a new request and a new original finite operation identity".into());
    }
    Ok(())
}

fn start_intent(
    blueprint: &Blueprint,
    phase: &Phase,
    base: &Selector,
    retired: Option<&RetiredCut>,
) -> Result<String> {
    let ordinary = blueprint.next_window_intent(phase, base)?;
    match retired {
        None => Ok(hash(&ordinary)),
        Some(cut) => {
            cut.pending.validate_base(
                &BaseSnapshot::Legacy {
                    binding: blueprint.binding.clone(),
                    cut: blueprint.legacy.clone(),
                },
                &cut.next,
            )?;
            Ok(hash(&serde_json::to_vec(&(
                "luma-c-bootstrap-fresh-start-after-explicit-retirement-v3",
                hash(&ordinary),
                &cut.pending.attempt,
                hash(&cut.pending.bytes()?),
                &cut.next.event_sha256,
            ))?))
        }
    }
}

fn previous_cut(
    pages: &PageStore,
    attempt: &str,
    binding: &map::CustodyBinding,
    legacy: &LegacyCut,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<RetiredCut> {
    digest(attempt)?;
    let prefix = format!("attempts/{attempt}");
    let retired = pages.read(&format!("{prefix}/retired.json"), CONTROL_BYTES, check)?;
    let pending: Pending = canonical(&retired, CONTROL_BYTES)?;
    let next: Descriptor = canonical(
        &pages.read(&format!("{prefix}/next.json"), PAGE_BYTES, check)?,
        PAGE_BYTES,
    )?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: legacy.clone(),
    };
    pending.validate_base(&base, &next)?;
    if pending.attempt != attempt
        || pages.read(&format!("{prefix}/prepared.json"), CONTROL_BYTES, check)? != retired
        || pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, check)? != base.bytes()?
        || pages.read(&format!("{prefix}/selector.json"), 4096, check)? != pending.next.bytes()?
        || pages.read(&format!("{prefix}/dispatch.json"), 4096, check)?
            != serde_json::to_vec(&(
                "luma-paged-c-single-dispatch-intent-v3",
                hash(&pending.bytes()?),
            ))?
        || pages.read_page(&pending.next.descriptor_sha256, check)? != next.bytes()?
        || !pages.absent(&format!("{prefix}/completed.json"))?
    {
        return Err(
            "resumed start does not retain exact independently retired prior first dispatch".into(),
        );
    }
    Ok(RetiredCut { pending, next })
}

/// This held selection/recovery result is DATA, not permission. It cannot be
/// cloned or deserialized and every use requires fresh original callbacks.
pub(crate) struct RetiredInitialBootstrap {
    state: Initial,
}
impl RetiredInitialBootstrap {
    pub(crate) fn review(
        &mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.state.check(check)?;
        let journal: Journal = canonical(&self.state.bytes, MAX_JOURNAL)?;
        let blueprint =
            Blueprint::verified_legacy(&self.state.binding, &self.state.legacy, &journal)?;
        let base = BaseSnapshot::Legacy {
            binding: self.state.binding.clone(),
            cut: self.state.legacy.clone(),
        }
        .selector()?;
        let phase = blueprint.initial_phase()?;
        let mut value = review_value(&blueprint, &phase, &base)?;
        let object = value
            .as_object_mut()
            .ok_or("bootstrap review lost closed object")?;
        object.insert(
            "window_intent_sha256".into(),
            serde_json::Value::String(self.state.intent(&blueprint, &phase, &base)?),
        );
        object.insert(
            "previous_retirement".into(),
            serde_json::to_value(self.state.previous_retirement())?,
        );
        object.insert(
            "fresh_original_operation_required".into(),
            serde_json::Value::Bool(true),
        );
        self.state.check(check)?;
        Ok(value)
    }
    pub(crate) fn resume(
        self,
        expected_intent: &str,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<PagedStore<super::super::super::super::ContentAnchor>> {
        dispatch_initial(self.state, expected_intent, authority)
    }
}

fn load_initial(
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Initial, Pending, Descriptor, String)> {
    check()?;
    let mut anchor = super::super::super::super::ContentAnchor::installed()?;
    let binding = map::CustodyBinding {
        installation: anchor.installation().into(),
        sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
    };
    let files = Files::installed();
    validate_genesis_at(&files.root, &binding.installation, anchor.genesis_event())?;
    let genesis_proof = files.read("genesis.json", check)?;
    genesis::validate(
        &genesis_proof,
        &binding.installation,
        anchor.genesis_event(),
    )?;
    let pages = PageStore::open(&files.root, binding.clone(), check)?;
    let pending_bytes = pages.read("pending.json", CONTROL_BYTES, check)?;
    let pending: Pending = canonical(&pending_bytes, CONTROL_BYTES)?;
    let prefix = format!("attempts/{}", pending.attempt);
    let base: BaseSnapshot = canonical(
        &pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, check)?,
        CONTROL_BYTES,
    )?;
    let next: Descriptor = canonical(
        &pages.read(&format!("{prefix}/next.json"), PAGE_BYTES, check)?,
        PAGE_BYTES,
    )?;
    pending.validate_base(&base, &next)?;
    let legacy = match &base {
        BaseSnapshot::Legacy { binding: old, cut } if old == &binding => cut.clone(),
        _ => {
            return Err(
                "first-dispatch recovery cannot reinterpret a paged or different sealed base"
                    .into(),
            )
        }
    };
    let bytes = files.read(JOURNAL, check)?;
    let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
    let blueprint = Blueprint::verified_legacy(&binding, &legacy, &journal)?;
    let state = journal.validate()?;
    if capacity::remaining(&state)?.outstanding_restore_batches != 0 {
        return Err(
            "initial retirement source has unsupported existing restore obligations".into(),
        );
    }
    blueprint.require_phase(&next.phase)?;
    let base_selector = base.selector()?;
    let previous = match &next.operation {
        OperationData::BootstrapProgress {
            previous_retirement: Some(attempt),
            ..
        } => {
            if *attempt == pending.attempt {
                return Err("initial bootstrap retirement reference is cyclic".into());
            }
            Some(previous_cut(&pages, attempt, &binding, &legacy, check)?)
        }
        _ => None,
    };
    let intent = start_intent(&blueprint, &next.phase, &base_selector, previous.as_ref())?;
    match &next.operation {
        OperationData::BootstrapProgress {
            window_intent_sha256,
            ..
        } if *window_intent_sha256 == intent => {}
        _ => {
            return Err(
                "first prepared bootstrap event differs from exact zero-row source intent".into(),
            )
        }
    }
    let actual = anchor.read()?;
    let selected: Selector = canonical(&pages.read("selected.json", 4096, check)?, 4096)?;
    if actual != tpm::decode(&legacy.nv_head)?
        || selected != base_selector
        || pages.read(&format!("{prefix}/prepared.json"), CONTROL_BYTES, check)? != pending_bytes
        || pages.read(&format!("{prefix}/selector.json"), 4096, check)? != pending.next.bytes()?
        || pages.read(&format!("{prefix}/dispatch.json"), 4096, check)?
            != serde_json::to_vec(&(
                "luma-paged-c-single-dispatch-intent-v3",
                hash(&pending.bytes()?),
            ))?
        || pages.read_page(&pending.next.descriptor_sha256, check)? != next.bytes()?
        || !pages.absent(&format!("{prefix}/retired.json"))?
        || !pages.absent(&format!("{prefix}/completed.json"))?
    {
        return Err("initial retirement requires exact unchanged old NV, all original stages and no prior disposition".into());
    }
    let review = hash(&serde_json::to_vec(&(
        "luma-paged-c-initial-dispatch-retirement-v3",
        &binding,
        &pending,
        &base,
        &next,
        bundle::hex(&actual),
        &selected,
    ))?);
    check()?;
    if anchor.read()? != actual
        || files.read(JOURNAL, check)? != bytes
        || files.read("genesis.json", check)? != genesis_proof
        || pages.read("pending.json", CONTROL_BYTES, check)? != pending_bytes
        || pages.read("selected.json", 4096, check)? != selected.bytes()?
    {
        return Err("initial retirement observation changed before returning its review".into());
    }
    Ok((
        Initial {
            anchor,
            files,
            pages,
            binding,
            legacy,
            bytes,
            genesis_proof,
            retired: None,
        },
        pending,
        next,
        review,
    ))
}

pub(crate) fn initial_recovery_review(
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (state, pending, _, review) = load_initial(check)?;
    let value = serde_json::json!({"schema_version":3,"installation":state.binding.installation,"review_sha256":review,
        "attempt":pending.attempt,"actual_nv_head":state.legacy.nv_head,"retirement_only":true,
        "legacy_writer_available":false,"old_event_will_be_redispatched":false,
        "separate_fresh_bootstrap_required":true,"authority_returned":false,"production_qualified":false});
    if serde_json::to_vec(&value)?.len() > 8192 {
        return Err("initial recovery review exceeds finite output bound".into());
    }
    Ok(value)
}

fn open_retired(
    attempt: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<RetiredInitialBootstrap> {
    digest(attempt)?;
    check()?;
    let anchor = super::super::super::super::ContentAnchor::installed()?;
    let binding = map::CustodyBinding {
        installation: anchor.installation().into(),
        sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
    };
    let files = Files::installed();
    validate_genesis_at(&files.root, &binding.installation, anchor.genesis_event())?;
    let pages = PageStore::open(&files.root, binding.clone(), check)?;
    let base: BaseSnapshot = canonical(
        &pages.read(
            &format!("attempts/{attempt}/base.json"),
            CONTROL_BYTES,
            check,
        )?,
        CONTROL_BYTES,
    )?;
    let legacy =
        match base {
            BaseSnapshot::Legacy { binding: old, cut } if old == binding => cut,
            _ => return Err(
                "retired initial namespace does not retain exact independent sealed legacy base"
                    .into(),
            ),
        };
    let retired = previous_cut(&pages, attempt, &binding, &legacy, check)?;
    let bytes = files.read(JOURNAL, check)?;
    let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
    let blueprint = Blueprint::verified_legacy(&binding, &legacy, &journal)?;
    blueprint.require_phase(&retired.next.phase)?;
    if capacity::remaining(&journal.validate()?)?.outstanding_restore_batches != 0 {
        return Err("retired initial source has unsupported existing restore obligations".into());
    }
    let genesis_proof = files.read("genesis.json", check)?;
    genesis::validate(
        &genesis_proof,
        &binding.installation,
        anchor.genesis_event(),
    )?;
    let mut state = Initial {
        anchor,
        files,
        pages,
        binding,
        legacy,
        bytes,
        genesis_proof,
        retired: Some(retired),
    };
    state.check(check)?;
    Ok(RetiredInitialBootstrap { state })
}

/// Opens retained retirement DATA afresh, so a separate original thirty-second
/// Admin window does not require a live object or cached authorization from the
/// earlier recovery request. Original sealed genesis, journal fold and actual
/// unchanged NV are all proved again; namespace presence alone is insufficient.
pub(crate) fn retired_bootstrap_review(
    attempt: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    open_retired(attempt, check)?.review(check)
}

pub(crate) fn resume_retired_bootstrap(
    attempt: &str,
    expected_intent: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<PagedStore<super::super::super::super::ContentAnchor>> {
    authority.check()?;
    open_retired(attempt, &mut || authority.check())?.resume(expected_intent, authority)
}

pub(crate) fn retire_initial_bootstrap(
    expected_review: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<RetiredInitialBootstrap> {
    use crate::finite_grants::{Action, Kind};
    digest(expected_review)?;
    authority.check()?;
    let (mut state, pending, next, review) = load_initial(&mut || authority.check())?;
    let source = authority.source_binding();
    let audit = authority.audit();
    if review != expected_review
        || source.command != "content-custody-paged-reconcile"
        || source.installation != state.binding.installation
        || source.job != pending.attempt
        || source.usage != audit.usage
        || audit.operation_id.is_none()
        || audit.usage.action != Action::RecoverResource
        || audit.usage.selector.kind != Kind::Resource
        || audit.usage.selector.id != "content-custody-paged-reconcile-v3"
        || audit.usage.selector.generation != 1
        || audit.usage.selector.digest != review
        || audit.usage.input_bytes != 0
        || audit.usage.output_bytes != 8192
        || audit.usage.units != 1
    {
        return Err("initial retirement lacks its separately reviewed fresh exact original Admin recovery scope".into());
    }
    authority.check()?;
    let prefix = format!("attempts/{}", pending.attempt);
    state.pages.rename(
        "pending.json",
        &format!("{prefix}/retired.json"),
        false,
        &mut || authority.check(),
    )?;
    state.retired = Some(RetiredCut { pending, next });
    state.check(&mut || authority.check())?;
    Ok(RetiredInitialBootstrap { state })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resumed_start_binds_exact_retirement_and_does_not_reuse_the_old_request_intent() {
        use crate::finite_grants::{Action, Kind, Selector as GrantSelector, Use};
        let binding = map::CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "22".repeat(32),
        };
        let journal = Journal::empty(
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256).unwrap(),
        )
        .unwrap();
        let legacy = LegacyCut {
            journal_sha256: hash(&journal.bytes().unwrap()),
            journal_bytes: journal.bytes().unwrap().len() as u64,
            events: 0,
            nv_head: bundle::hex(&journal.validate().unwrap().checkpoint),
        };
        let blueprint = Blueprint::verified_legacy(&binding, &legacy, &journal).unwrap();
        let phase = blueprint.initial_phase().unwrap();
        let base = BaseSnapshot::Legacy {
            binding: binding.clone(),
            cut: legacy.clone(),
        };
        let selected = base.selector().unwrap();
        let first = start_intent(&blueprint, &phase, &selected, None).unwrap();
        let audit = Audit {
            subject: "33".repeat(32),
            subject_generation: 1,
            grant_id: "retirement-format-fixture".into(),
            grant_version: 1,
            checkpoint_head: "44".repeat(32),
            operation_id: Some("55".repeat(16)),
            usage: Use {
                action: Action::ProvisionResource,
                selector: GrantSelector {
                    kind: Kind::Resource,
                    id: "content-custody-paged-bootstrap-v3".into(),
                    generation: 1,
                    digest: first.clone(),
                },
                input_bytes: 0,
                output_bytes: 8192,
                units: 1,
            },
        };
        let next = Descriptor {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            sequence: 1,
            global_ordinal: 2,
            previous_descriptor_sha256: None,
            previous_nv_head: legacy.nv_head.clone(),
            event_sha256: String::new(),
            selected_nv_head: String::new(),
            legacy,
            roots: Roots::empty(&binding).unwrap(),
            phase: phase.clone(),
            operation: OperationData::BootstrapProgress {
                previous_retirement: None,
                review_sha256: phase.review_sha256.clone(),
                window_intent_sha256: first.clone(),
                request_sha256: "66".repeat(32),
                source_sha256: "77".repeat(32),
                original_authority: audit,
            },
        }
        .seal()
        .unwrap();
        let pending = Pending {
            schema_version: 3,
            attempt: "88".repeat(32),
            base: selected.clone(),
            next: Selector::for_descriptor(&next).unwrap(),
            event_sha256: next.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&next.operation).unwrap()),
        };
        let mut cut = RetiredCut { pending, next };
        let resumed = start_intent(&blueprint, &phase, &selected, Some(&cut)).unwrap();
        assert_ne!(first, resumed);
        cut.pending.attempt = "99".repeat(32);
        assert_ne!(
            resumed,
            start_intent(&blueprint, &phase, &selected, Some(&cut)).unwrap()
        );
        cut.pending.base.nv_head = "aa".repeat(32);
        assert!(start_intent(&blueprint, &phase, &selected, Some(&cut)).is_err());
    }
    #[test]
    fn retirement_is_not_permission_to_reuse_an_operation_or_body() {
        let request = "11".repeat(32);
        let next = "22".repeat(32);
        let operation = "33".repeat(16);
        let fresh = "44".repeat(16);
        fresh_identity(&request, Some(&operation), &next, Some(&fresh)).unwrap();
        assert!(fresh_identity(&request, Some(&operation), &request, Some(&fresh)).is_err());
        assert!(fresh_identity(&request, Some(&operation), &next, Some(&operation)).is_err());
        assert!(fresh_identity(&request, Some(&operation), &next, None).is_err());
        assert!(fresh_identity(&request, None, &next, Some(&fresh)).is_err());
    }
}
