//! Appendable immutable segment descriptors. An active segment is extended by
//! new immutable member/map roots; no old descriptor or source is overwritten.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerSegmentV2 {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub segment_number: u64,
    pub first_ordinal: u64,
    pub last_ordinal: u64,
    pub previous_segment_sha256: Option<String>,
    pub logical_bytes: u64,
    pub members: MapRoot,
    pub requests_before: MapRoot,
    pub requests_after: MapRoot,
}
impl OwnerSegmentV2 {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.members.validate()?;
        self.requests_before.validate()?;
        self.requests_after.validate()?;
        let count = self
            .last_ordinal
            .checked_sub(self.first_ordinal)
            .and_then(|v| v.checked_add(1))
            .ok_or("v2 owner segment ordinal range invalid")?;
        if self.schema_version != 2
            || self.domain != DOMAIN
            || self.segment_number >= MAX_SEGMENTS
            || self.first_ordinal == 0
            || count == 0
            || count > MAX_SEGMENT_OUTCOMES as u64
            || self.logical_bytes > MAX_SEGMENT_BYTES
            || self.members.binding != self.binding
            || self.members.kind != MapKind::SegmentMembers
            || self.members.entry_count != count
            || self.requests_before.binding != self.binding
            || self.requests_after.binding != self.binding
            || self.requests_before.kind != MapKind::Requests
            || self.requests_after.kind != MapKind::Requests
            || self.requests_before.entry_count + 1 != self.first_ordinal
            || self.requests_after.entry_count != self.last_ordinal
        {
            return Err("v2 owner segment role/count/owner mismatch".into());
        }
        match &self.previous_segment_sha256 {
            None if self.segment_number == 0 && self.first_ordinal == 1 => {}
            Some(hash) if self.segment_number > 0 => digest(hash)?,
            _ => return Err("v2 owner segment predecessor mismatch".into()),
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 8192 {
            return Err("v2 owner segment descriptor exceeds bound".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 8192)?;
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Member {
    pub ordinal: u64,
    pub request_id: String,
    pub record: BlobReference,
    pub source: BlobReference,
    pub payload: BlobReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Locator {
    pub ordinal: u64,
    pub segment_number: u64,
    pub member: BlobReference,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOutcome {
    pub ordinal: u64,
    pub record: Vec<u8>,
    pub source: Vec<u8>,
    pub payload: Vec<u8>,
}

impl ObjectStore {
    pub(super) fn verify_owner_extension<B: Boundary>(
        &self,
        base: &head::OwnerHeadV2,
        candidate: &head::OwnerHeadV2,
        member_ref: &BlobReference,
        member: &Member,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        if member.ordinal
            != base
                .history
                .outcomes
                .checked_add(1)
                .ok_or("v2 ordinal overflow")?
            || candidate.history.outcomes != member.ordinal
        {
            return Err("v2 owner extension skips an ordinal".into());
        }
        let logical = member
            .record
            .bytes
            .checked_add(member.source.bytes)
            .and_then(|n| n.checked_add(member.payload.bytes))
            .ok_or("v2 owner segment logical byte overflow")?;
        let prior = base
            .history
            .last_segment
            .as_ref()
            .map(|r| self.owner_segment(r, guard))
            .transpose()?;
        let extend = prior.as_ref().is_some_and(|p| {
            p.members.entry_count < MAX_SEGMENT_OUTCOMES as u64
                && p.logical_bytes
                    .checked_add(logical)
                    .is_some_and(|n| n <= MAX_SEGMENT_BYTES)
        });
        let (mut expected, old_ref) = if extend {
            (
                prior.ok_or("v2 active segment missing")?,
                base.history.last_segment.clone(),
            )
        } else {
            (
                OwnerSegmentV2 {
                    schema_version: 2,
                    domain: DOMAIN.into(),
                    binding: self.binding.clone(),
                    segment_number: base.history.segments,
                    first_ordinal: member.ordinal,
                    last_ordinal: member.ordinal,
                    previous_segment_sha256: base
                        .history
                        .last_segment
                        .as_ref()
                        .map(|r| r.sha256.clone()),
                    logical_bytes: 0,
                    members: MapRoot::empty(&self.binding, MapKind::SegmentMembers)?,
                    requests_before: base.roots.requests.clone(),
                    requests_after: base.roots.requests.clone(),
                },
                None,
            )
        };
        expected.members = self.verify_map_inner(
            &expected.members,
            &[MapEdit {
                key: expected.members.key(&member.ordinal.to_be_bytes())?,
                expected_value_sha256: None,
                value: Some(member_ref.canonical_bytes()?),
            }],
            guard,
        )?;
        let locator = Locator {
            ordinal: member.ordinal,
            segment_number: expected.segment_number,
            member: member_ref.clone(),
        };
        expected.requests_after = self.verify_map_inner(
            &base.roots.requests,
            &[MapEdit {
                key: base.roots.requests.key(member.request_id.as_bytes())?,
                expected_value_sha256: None,
                value: Some(serde_json::to_vec(&locator)?),
            }],
            guard,
        )?;
        expected.last_ordinal = member.ordinal;
        expected.logical_bytes = expected
            .logical_bytes
            .checked_add(logical)
            .ok_or("v2 segment extent overflow")?;
        let new_ref = candidate
            .history
            .last_segment
            .as_ref()
            .ok_or("v2 candidate has no last segment")?;
        if self.get_blob(new_ref, guard)? != expected.canonical_bytes()?
            || candidate.history.segments != expected.segment_number + 1
            || candidate.roots.requests != expected.requests_after
        {
            return Err("v2 candidate segment/history does not reconstruct exact append".into());
        }
        let segments = self.verify_map_inner(
            &base.roots.segments,
            &[MapEdit {
                key: base
                    .roots
                    .segments
                    .key(&expected.segment_number.to_be_bytes())?,
                expected_value_sha256: old_ref
                    .as_ref()
                    .map(BlobReference::canonical_bytes)
                    .transpose()?
                    .map(|b| luma_content::sha256(&b)),
                value: Some(new_ref.canonical_bytes()?),
            }],
            guard,
        )?;
        if segments != candidate.roots.segments {
            return Err("v2 append changes unrelated segment inventory".into());
        }
        guard.check()
    }
    pub(super) fn owner_segment<B: Boundary>(
        &self,
        reference: &BlobReference,
        guard: &mut Guard<'_, B>,
    ) -> Result<OwnerSegmentV2> {
        let value = OwnerSegmentV2::from_canonical(&self.get_blob(reference, guard)?)?;
        if value.binding != self.binding {
            return Err("v2 owner segment belongs to a different owner".into());
        }
        Ok(value)
    }
    pub(super) fn extend_owner_segment<B: Boundary>(
        &self,
        head: &head::OwnerHeadV2,
        input: SegmentInput<'_>,
        guard: &mut Guard<'_, B>,
    ) -> Result<(MapRoot, MapRoot, BlobReference, u64)> {
        let request = segment::validate_record(&self.binding, &input, &mut || guard.check())?;
        if input.ordinal
            != head
                .history
                .outcomes
                .checked_add(1)
                .ok_or("v2 owner ordinal overflow")?
        {
            return Err("v2 owner append ordinal does not extend selected head".into());
        }
        let request_key = head.roots.requests.key(request.as_bytes())?;
        if self
            .get_map(&head.roots.requests, &request_key, guard)?
            .is_some()
        {
            return Err("v2 owner request identifier already retained".into());
        }
        let logical = (input.record.len() as u64)
            .checked_add(input.source.len() as u64)
            .and_then(|v| v.checked_add(input.payload.len() as u64))
            .ok_or("v2 owner outcome byte overflow")?;
        if logical > MAX_SEGMENT_BYTES {
            return Err("v2 owner outcome exceeds whole segment bound".into());
        }
        let prior = head
            .history
            .last_segment
            .as_ref()
            .map(|reference| self.owner_segment(reference, guard))
            .transpose()?;
        if let Some(prior) = &prior {
            if prior.last_ordinal != head.history.outcomes
                || prior.segment_number + 1 != head.history.segments
                || prior.requests_after != head.roots.requests
            {
                return Err("v2 owner last segment differs from aggregate head".into());
            }
        }
        let extend = prior.as_ref().is_some_and(|p| {
            p.members.entry_count < MAX_SEGMENT_OUTCOMES as u64
                && p.logical_bytes
                    .checked_add(logical)
                    .is_some_and(|n| n <= MAX_SEGMENT_BYTES)
        });
        let (mut next, previous_member) = if extend {
            (
                prior.ok_or("v2 active segment absent")?,
                head.history.last_segment.clone(),
            )
        } else {
            let number = head.history.segments;
            if number >= MAX_SEGMENTS {
                return Err("v2 owner segment capacity exhausted".into());
            }
            (
                OwnerSegmentV2 {
                    schema_version: 2,
                    domain: DOMAIN.into(),
                    binding: self.binding.clone(),
                    segment_number: number,
                    first_ordinal: input.ordinal,
                    last_ordinal: input.ordinal,
                    previous_segment_sha256: head
                        .history
                        .last_segment
                        .as_ref()
                        .map(|r| r.sha256.clone()),
                    logical_bytes: 0,
                    members: MapRoot::empty(&self.binding, MapKind::SegmentMembers)?,
                    requests_before: head.roots.requests.clone(),
                    requests_after: head.roots.requests.clone(),
                },
                None,
            )
        };
        let member = Member {
            ordinal: input.ordinal,
            request_id: request.clone(),
            record: self.put_blob(input.record, guard)?,
            source: self.put_blob(input.source, guard)?,
            payload: self.put_blob(input.payload, guard)?,
        };
        let member_ref = self.put_blob(&serde_json::to_vec(&member)?, guard)?;
        next.members = self.edit_map(
            &next.members,
            &[MapEdit {
                key: next.members.key(&input.ordinal.to_be_bytes())?,
                expected_value_sha256: None,
                value: Some(member_ref.canonical_bytes()?),
            }],
            guard,
        )?;
        let locator = Locator {
            ordinal: input.ordinal,
            segment_number: next.segment_number,
            member: member_ref,
        };
        let requests = self.edit_map(
            &head.roots.requests,
            &[MapEdit {
                key: request_key,
                expected_value_sha256: None,
                value: Some(serde_json::to_vec(&locator)?),
            }],
            guard,
        )?;
        next.requests_after = requests.clone();
        next.last_ordinal = input.ordinal;
        next.logical_bytes = next
            .logical_bytes
            .checked_add(logical)
            .ok_or("v2 owner segment byte overflow")?;
        let reference = self.put_blob(&next.canonical_bytes()?, guard)?;
        let key = head
            .roots
            .segments
            .key(&next.segment_number.to_be_bytes())?;
        let expected = previous_member
            .as_ref()
            .map(BlobReference::canonical_bytes)
            .transpose()?
            .map(|bytes| luma_content::sha256(&bytes));
        let segments = self.edit_map(
            &head.roots.segments,
            &[MapEdit {
                key,
                expected_value_sha256: expected,
                value: Some(reference.canonical_bytes()?),
            }],
            guard,
        )?;
        Ok((requests, segments, reference, next.segment_number + 1))
    }
    pub(super) fn outcome_from_locator<B: Boundary>(
        &self,
        locator: &Locator,
        guard: &mut Guard<'_, B>,
    ) -> Result<StoredOutcome> {
        if locator.ordinal == 0
            || locator.ordinal > MAX_MAP_ENTRIES
            || locator.segment_number >= MAX_SEGMENTS
        {
            return Err("v2 outcome locator bound invalid".into());
        }
        let member: Member = canonical(&self.get_blob(&locator.member, guard)?, 8192)?;
        if member.ordinal != locator.ordinal {
            return Err("v2 outcome member ordinal differs from locator".into());
        }
        identifier(&member.request_id)?;
        let result = StoredOutcome {
            ordinal: member.ordinal,
            record: self.get_blob(&member.record, guard)?,
            source: self.get_blob(&member.source, guard)?,
            payload: self.get_blob(&member.payload, guard)?,
        };
        let request = segment::validate_record(
            &self.binding,
            &SegmentInput {
                ordinal: result.ordinal,
                record: &result.record,
                source: &result.source,
                payload: &result.payload,
            },
            &mut || guard.check(),
        )?;
        if request != member.request_id {
            return Err("v2 outcome member request differs from record".into());
        }
        Ok(result)
    }
    pub(super) fn owner_outcome<B: Boundary>(
        &self,
        head: &head::OwnerHeadV2,
        ordinal: u64,
        guard: &mut Guard<'_, B>,
    ) -> Result<StoredOutcome> {
        if ordinal == 0 || ordinal > head.history.outcomes {
            return Err("v2 outcome ordinal outside selected history".into());
        }
        let (mut low, mut high) = (0_u64, head.history.segments);
        while low < high {
            let middle = low + (high - low) / 2;
            let key = head.roots.segments.key(&middle.to_be_bytes())?;
            let bytes = self
                .get_map(&head.roots.segments, &key, guard)?
                .ok_or("v2 selected segment inventory has a missing ordinal")?;
            let reference: BlobReference = canonical(&bytes, MAX_VALUE_BYTES)?;
            let segment = self.owner_segment(&reference, guard)?;
            if segment.segment_number != middle {
                return Err("v2 segment inventory retargets its number".into());
            }
            if ordinal < segment.first_ordinal {
                high = middle;
            } else if ordinal > segment.last_ordinal {
                low = middle + 1;
            } else {
                let key = segment.members.key(&ordinal.to_be_bytes())?;
                let bytes = self
                    .get_map(&segment.members, &key, guard)?
                    .ok_or("v2 segment omitted selected immutable member")?;
                let member: BlobReference = canonical(&bytes, MAX_VALUE_BYTES)?;
                return self.outcome_from_locator(
                    &Locator {
                        ordinal,
                        segment_number: middle,
                        member,
                    },
                    guard,
                );
            }
        }
        Err("v2 owner history lost requested ordinal".into())
    }
}
