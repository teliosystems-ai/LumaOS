//! An exact original-Admin fresh-owner batch, anchored before its first member.
//! Resumption requires NEW live authority; the old audit is historical data.
use super::*;
use crate::content_restore::Input;
use luma_content_store::RestoreReview;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    schema_version: u32,
    purpose: String,
    pub(super) input: Input,
    receipt: backup::Receipt,
    profile: String,
    storage_device: String,
    original_authority: Audit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capacity: Option<super::capacity::Reservation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    pub entry: super::Publication,
    batch_review_sha256: String,
}
impl Start {
    pub(super) fn review(&self) -> Result<&RestoreReview> {
        self.input
            .review
            .as_ref()
            .ok_or_else(|| "restore start has no exact approved review".into())
    }
    pub(super) fn validate(&self, installation: &str) -> Result<()> {
        self.input.validate()?;
        self.original_authority.validate()?;
        let review = self.review()?;
        self.receipt
            .check_data(&self.receipt.body.input, &self.receipt.body.encryption)?;
        let capacity_valid = match (self.schema_version, &self.capacity) {
            (1, None) => true,
            (2, Some(value)) => value == &super::capacity::Reservation::fixed(),
            _ => false,
        };
        if !capacity_valid
            || self.purpose != "luma-content-fresh-owner-restore-start-v1"
            || self.input.target.installation != installation
            || review.target != self.input.target
            || review.origin != self.receipt.body.input.binding
            || review.archive_sha256 != self.receipt.body.encryption.archive_sha256
            || review.archive_bytes != self.receipt.body.encryption.archive_bytes
            || review.origin_head_sha256 != self.receipt.body.source_state.head_sha256
            || review.manifest_sha256 != self.receipt.body.input.review.manifest_sha256
            || review
                .published_outcomes
                .checked_add(review.inert_committed_outcomes)
                != Some(self.receipt.body.source_state.outcome_count)
            || review.inert_pending_directories
                != self.receipt.body.input.review.areas[1].directories
            || review.inert_quarantined_directories
                != self.receipt.body.input.review.areas[2].directories
            || self.input.independently_selected_origin_spki_sha256
                != self.receipt.body.origin_spki_sha256
            || self.original_authority.subject != self.input.admin.owner
            || self.original_authority.subject_generation != self.input.admin.owner_generation
            || self.original_authority.operation_id.is_none()
            || crate::content_restore::profile(&self.input, &serde_json::to_vec(&self.input)?)?
                != self.profile
            || self.original_authority.usage
                != crate::content_restore::custody_usage(
                    &self.profile,
                    &self.storage_device,
                    installation,
                )?
        {
            return Err("restore start substitutes exact authenticated archive, current target or reviewed finite batch".into());
        }
        Ok(())
    }
    fn same_batch(&self, input: &Input, receipt: &backup::Receipt) -> Result<bool> {
        Ok(self.matches_input(input)?
            && serde_json::to_vec(&self.receipt)? == serde_json::to_vec(receipt)?)
    }
    pub(super) fn matches_input(&self, input: &Input) -> Result<bool> {
        input.validate()?;
        Ok(self.input.review == input.review
            && self.input.target == input.target
            && self.input.independently_selected_origin_spki_sha256
                == input.independently_selected_origin_spki_sha256
            && self.input.capsule_sha256 == input.capsule_sha256
            && self.input.capsule_bytes == input.capsule_bytes)
    }
}
pub(super) fn authority(
    profile: &str,
    device: &str,
    binding: &OwnerBinding,
    audit: &Audit,
) -> Result<()> {
    audit.validate()?;
    let (mode, admin_generation, target_generation, _, _, _) =
        crate::content_restore::parse_profile(profile)?;
    if mode != 'w'
        || target_generation != binding.owner_generation
        || admin_generation != audit.subject_generation
        || audit.operation_id.is_none()
        || audit.usage
            != crate::content_restore::custody_usage(profile, device, &binding.installation)?
    {
        return Err(
            "restore publication lacks its exact current original-Admin finite Write batch".into(),
        );
    }
    Ok(())
}
pub(super) fn start_event(value: &Start, installation: &str, state: &mut Validated) -> Result<()> {
    value.validate(installation)?;
    let key = owner_key(&value.input.target)?;
    if super::retire::principal_unavailable(&value.input.target, state)? {
        return Err("retired owner-generation cannot restart; independently provision a fresh owner binding".into());
    }
    let empty = VerifiedState::empty(&value.input.target)?;
    if state.restores.contains_key(&key)
        || state.owners.get(&key).is_some_and(|cut| cut != &empty)
        || state
            .records
            .get(&key)
            .is_some_and(|records| !records.is_empty())
    {
        return Err(
            "fresh-owner restore start refuses existing or previously adopted content".into(),
        );
    }
    state.restores.insert(key, value.clone());
    Ok(())
}
pub(super) fn publication_event(value: &Publication, state: &Validated) -> Result<()> {
    let held = value.entry.validate()?;
    if super::retire::principal_unavailable(&held.binding, state)? {
        return Err("retired content principal cannot receive a restored publication".into());
    }
    let key = owner_key(&held.binding)?;
    let batch = state
        .restores
        .get(&key)
        .ok_or("restore publication has no protected start")?;
    let review = batch.review()?;
    let index = usize::try_from(held.base_outcome_count)?;
    let step = review
        .steps
        .get(index)
        .ok_or("restore publication exceeds exact batch")?;
    if value.batch_review_sha256 != review.review_sha256
        || !matches!(
            held.decision,
            DecisionKind::Published | DecisionKind::Trashed | DecisionKind::Restored
        )
        || (held.decision != DecisionKind::Published && review.schema_version != 2)
        || held.already_published
        || held.request_id != step.request_id
        || held.review_sha256 != step.review_sha256
        || held.binding != review.target
        || held.outcome_count != held.base_outcome_count + 1
    {
        return Err(
            "restore publication substitutes reviewed chronological source/plan or target".into(),
        );
    }
    authority(
        &value.entry.profile,
        &value.entry.storage_device,
        &held.binding,
        &value.entry.original_authority,
    )
}
pub(super) fn ordinary_publication(
    binding: &OwnerBinding,
    profile: &str,
    state: &Validated,
) -> Result<()> {
    if super::retire::principal_unavailable(binding, state)? {
        return Err("retired content principal is unavailable for ordinary changes".into());
    }
    if profile.starts_with(crate::content_restore::PREFIX) {
        return Err("restore cannot use an ordinary publication event".into());
    }
    if let Some(batch) = state.restores.get(&owner_key(binding)?) {
        let count = state
            .owners
            .get(&owner_key(binding)?)
            .map_or(0, |s| s.outcome_count);
        if count < batch.review()?.published_outcomes {
            return Err("incomplete protected restore batch refuses unrelated publication".into());
        }
    }
    Ok(())
}
impl<A: Checkpoint> Store<A> {
    pub(super) fn restore_status(
        &mut self,
        input: &Input,
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        authority(profile, device, &input.target, audit)?;
        input.validate()?;
        if super::retire::principal_unavailable(&input.target, &self.state)? {
            return Err("retired restore owner is unavailable, never repaired or adopted".into());
        }
        self.live(check)?;
        if self.state.restores.contains_key(&owner_key(&input.target)?) {
            self.restore_batch(input, profile, device, audit, check)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn restore_batch<'a>(
        &'a mut self,
        input: &Input,
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<&'a Start> {
        input.validate()?;
        if super::retire::principal_unavailable(&input.target, &self.state)? {
            return Err("retired restore batch cannot resume".into());
        }
        authority(profile, device, &input.target, audit)?;
        if crate::content_restore::profile(input, &serde_json::to_vec(input)?)? != profile {
            return Err("restore transport differs from live original request".into());
        }
        self.live(check)?;
        let start = self
            .state
            .restores
            .get(&owner_key(&input.target)?)
            .ok_or("protected restore start missing")?;
        if start.input.review != input.review
            || start.input.target != input.target
            || start.input.capsule_sha256 != input.capsule_sha256
            || start.input.capsule_bytes != input.capsule_bytes
            || start.input.independently_selected_origin_spki_sha256
                != input.independently_selected_origin_spki_sha256
        {
            return Err(
                "restore resumption differs from independently anchored exact batch".into(),
            );
        }
        Ok(start)
    }
    pub(super) fn start_restore(
        &mut self,
        input: &Input,
        receipt: &backup::Receipt,
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        self.live(check)?;
        let entry = Start {
            schema_version: 2,
            purpose: "luma-content-fresh-owner-restore-start-v1".into(),
            input: input.clone(),
            receipt: receipt.clone(),
            profile: profile.into(),
            storage_device: device.into(),
            original_authority: audit.clone(),
            capacity: Some(super::capacity::Reservation::fixed()),
        };
        entry.validate(&self.journal.installation)?;
        receipt.verify_origin(&input.independently_selected_origin_spki_sha256, check)?;
        if let Some(prior) = self.state.restores.get(&owner_key(&input.target)?) {
            if !prior.same_batch(input, receipt)? {
                return Err("restore refuses a different prior protected batch".into());
            }
            self.restore_batch(input, profile, device, audit, check)?;
        } else {
            if self.selected(&input.target, check)? != VerifiedState::empty(&input.target)? {
                return Err("restore target is not genuinely fresh".into());
            }
            self.commit(Event::RestoreStart(entry), check)?;
        }
        self.selected(&input.target, check)
    }
    pub(super) fn restore_cut(
        &mut self,
        input: &Input,
        profile: &str,
        device: &str,
        audit: &Audit,
        request: &str,
        review: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PreparationCut> {
        let start = self.restore_batch(input, profile, device, audit, check)?;
        let steps = &start.review()?.steps;
        let index = steps
            .iter()
            .position(|s| s.request_id == request && s.review_sha256 == review)
            .ok_or("restore step is outside protected reviewed batch")?;
        let current = self.selected(&input.target, check)?;
        if current.outcome_count < index as u64 {
            return Err("restore cannot skip earlier reviewed publications".into());
        }
        let mut prior_base = None;
        if current.outcome_count == index as u64 + 1 {
            let entry = self
                .journal
                .events
                .iter()
                .find_map(|event| match event {
                    Event::RestorePublication(value)
                        if value.entry.validate().is_ok_and(|held| {
                            held.binding == input.target && held.request_id == request
                        }) =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .ok_or("restore checkpoint lacks exact prior publication")?;
            let held = entry.entry.validate()?;
            if held.review_sha256 != review || held.outcome() != current {
                return Err("restore pending checkpoint differs".into());
            }
            prior_base = Some(held.base());
        }
        self.live(check)?;
        Ok(PreparationCut {
            current,
            prior_base,
        })
    }
    pub(super) fn publish_restore(
        &mut self,
        input: &Input,
        commitment: &[u8],
        record: &[u8],
        profile: &str,
        device: &str,
        audit: &Audit,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedState> {
        let batch_sha = self
            .restore_batch(input, profile, device, audit, check)?
            .review()?
            .review_sha256
            .clone();
        let held = HeldPublication::parse(commitment)?;
        if held.binding != input.target {
            return Err("restore publication belongs to a different current target".into());
        }
        let cut = self.restore_cut(
            input,
            profile,
            device,
            audit,
            &held.request_id,
            &held.review_sha256,
            check,
        )?;
        if held.already_published || cut.current != held.base() {
            if cut.current != held.outcome() {
                return Err("restore retry differs from current protected head".into());
            }
            let prior = self
                .journal
                .events
                .iter()
                .find_map(|event| match event {
                    Event::RestorePublication(value)
                        if value.entry.validate().is_ok_and(|v| {
                            v.binding == input.target && v.request_id == held.request_id
                        }) =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .ok_or("restore retry has no exact protected publication")?;
            let original = prior.entry.validate()?;
            if prior.batch_review_sha256 != batch_sha
                || prior.entry.record.as_bytes() != record
                || original.review_sha256 != held.review_sha256
                || original.resulting != held.resulting
                || original
                    .members
                    .iter()
                    .zip(&held.members)
                    .any(|(a, b)| a.name != b.name || a.sha256 != b.sha256 || a.bytes != b.bytes)
            {
                return Err("restore retry substitutes exact original held bytes".into());
            }
            self.live(check)?;
            return Ok(cut.current);
        }
        let value = Publication {
            batch_review_sha256: batch_sha,
            entry: super::Publication {
                schema_version: 1,
                purpose: "luma-content-custody-publication-v1".into(),
                commitment: std::str::from_utf8(commitment)?.into(),
                record: std::str::from_utf8(record)?.into(),
                profile: profile.into(),
                storage_device: device.into(),
                original_authority: audit.clone(),
            },
        };
        publication_event(&value, &self.state)?;
        self.commit(Event::RestorePublication(value), check)?;
        Ok(held.outcome())
    }
}
