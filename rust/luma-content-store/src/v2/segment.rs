use super::*;
use std::collections::BTreeSet;

/// Borrowed original immutable bytes. Canonical record syntax/integrity is
/// verified here; semantic engine replay against selected artifact/lifecycle
/// maps remains the independently admitted publisher's responsibility.
pub struct SegmentInput<'a> {
    pub ordinal: u64,
    pub record: &'a [u8],
    pub source: &'a [u8],
    pub payload: &'a [u8],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    ordinal: u64,
    request_id: String,
    record: BlobReference,
    source: BlobReference,
    payload: BlobReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    segment_number: u64,
    members: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SegmentDescriptor {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub segment_number: u64,
    pub first_ordinal: u64,
    pub last_ordinal: u64,
    pub previous_segment_sha256: Option<String>,
    pub outcome_count: u32,
    pub logical_bytes: u64,
    pub manifest: BlobReference,
    pub requests_before: MapRoot,
    pub requests_after: MapRoot,
}
impl SegmentDescriptor {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.manifest.validate()?;
        self.requests_before.validate()?;
        self.requests_after.validate()?;
        if self.schema_version != 1
            || self.domain != DOMAIN
            || self.segment_number >= MAX_SEGMENTS
            || self.first_ordinal == 0
            || self
                .last_ordinal
                .checked_sub(self.first_ordinal)
                .and_then(|v| v.checked_add(1))
                != Some(u64::from(self.outcome_count))
            || self.outcome_count == 0
            || self.outcome_count as usize > MAX_SEGMENT_OUTCOMES
            || self.logical_bytes > MAX_SEGMENT_BYTES
            || self.manifest.bytes == 0
            || self.manifest.bytes > 1024 * 1024
            || self.manifest.binding != self.binding
            || self.requests_before.binding != self.binding
            || self.requests_after.binding != self.binding
            || self.requests_before.kind != MapKind::Requests
            || self.requests_after.kind != MapKind::Requests
            || self
                .requests_before
                .entry_count
                .checked_add(u64::from(self.outcome_count))
                != Some(self.requests_after.entry_count)
            || self.requests_before.entry_count.checked_add(1) != Some(self.first_ordinal)
            || self.requests_after.entry_count != self.last_ordinal
        {
            return Err("v2 segment domain/owner/global ordinal/request coverage invalid".into());
        }
        match &self.previous_segment_sha256 {
            None if self.segment_number == 0 && self.first_ordinal == 1 => Ok(()),
            Some(hash) if self.segment_number > 0 => digest(hash),
            _ => Err("v2 segment initial/continuation mismatch".into()),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 8192 {
            return Err("v2 segment descriptor byte bound exceeded".into());
        }
        Ok(bytes)
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 8192)?;
        value.validate()?;
        Ok(value)
    }
    pub fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    pub fn follows(&self, previous: Option<&Self>) -> Result<()> {
        self.validate()?;
        match previous {
            None if self.segment_number == 0 => Ok(()),
            Some(previous) => {
                previous.validate()?;
                if self.binding != previous.binding
                    || self.segment_number != previous.segment_number + 1
                    || self.previous_segment_sha256.as_ref() != Some(&previous.sha256()?)
                    || self.first_ordinal
                        != previous
                            .last_ordinal
                            .checked_add(1)
                            .ok_or("v2 global ordinal overflow")?
                    || self.requests_before != previous.requests_after
                {
                    return Err("v2 segment does not extend exact predecessor".into());
                }
                Ok(())
            }
            _ => Err("v2 continuation requires exact preceding segment descriptor".into()),
        }
    }
}
/// Synchronized immutable DATA only. Neither serialization nor possession
/// publishes this segment, changes custody selection or releases reservations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSegment {
    pub descriptor: SegmentDescriptor,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestValue {
    schema_version: u32,
    ordinal: u64,
    segment_number: u64,
    record_sha256: String,
}

fn validate_record(
    binding: &OwnerBinding,
    input: &SegmentInput<'_>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<String> {
    check()?;
    if input.record.is_empty()
        || input.record.len() as u64 > crate::MAX_RECORD
        || input.source.len() as u64 > super::MAX_SEGMENT_BYTES
        || input.payload.len() as u64 > crate::MAX_PAYLOAD
    {
        return Err("v2 outcome member byte limit exceeded".into());
    }
    let record: crate::Record = canonical(input.record, crate::MAX_RECORD as usize)?;
    let data = &record.plan;
    let source_limit = match (record.schema_version, data.source_kind) {
        (1, None) => luma_content::MAX_CONTENT_BYTES as u64,
        (2, Some(crate::SourceKind::ManagedTableIntent))
        | (3, Some(crate::SourceKind::ManagedRenderIntent)) => crate::MAX_SOURCE,
        (4, Some(crate::SourceKind::CollectionIntent)) => crate::MAX_COLLECTION_SOURCE_BYTES as u64,
        (5, Some(crate::SourceKind::LifecycleIntent)) => crate::MAX_RECORD,
        _ => return Err("v2 canonical outcome schema/source kind invalid".into()),
    };
    identifier(&data.artifact_id)?;
    identifier(&data.provenance.request_id)?;
    digest(&data.provenance.workflow_sha256)?;
    crate::lifecycle::validate_data(data)?;
    for reference in std::iter::once(&data.resulting)
        .chain(data.observed.iter())
        .chain(data.expected.iter())
    {
        crate::collections::reference(reference)?;
        if reference.artifact_id != data.artifact_id {
            return Err("v2 outcome reference retargets another artifact".into());
        }
    }
    check()?;
    let source_sha = luma_content::sha256(input.source);
    check()?;
    let payload_sha = luma_content::sha256(input.payload);
    check()?;
    if record.sequence != input.ordinal
        || input.ordinal == 0
        || data.schema_version != record.schema_version
        || data.binding != *binding
        || data.source_bytes != input.source.len() as u64
        || data.payload_bytes != input.payload.len() as u64
        || data.source_bytes > source_limit
        || data.payload_bytes == 0
        || data.source_sha256 != source_sha
        || data.source_sha256 != data.provenance.source_sha256
        || data.payload_sha256 != payload_sha
        || record.review_sha256 != luma_content::sha256(&serde_json::to_vec(data)?)
        || (record.schema_version == 3) != data.derivation.is_some()
    {
        return Err(
            "v2 canonical outcome global ordinal/owner/exact member commitment differs".into(),
        );
    }
    check()?;
    let version = luma_content::reopen(input.payload, binding)?;
    check()?;
    if version.reference()? != data.resulting
        || version.receipt().artifact_id != data.artifact_id
        || version.receipt().format != data.format
    {
        return Err("v2 outcome payload reference differs from record".into());
    }
    Ok(data.provenance.request_id.clone())
}
impl ObjectStore {
    pub fn seal_segment(
        &self,
        previous: Option<&SegmentDescriptor>,
        requests: &MapRoot,
        inputs: &[SegmentInput<'_>],
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut impl Boundary,
    ) -> Result<SealedSegment> {
        self.check_root(requests)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, Some(mutation))?;
        if requests.kind != MapKind::Requests
            || inputs.is_empty()
            || inputs.len() > MAX_SEGMENT_OUTCOMES
        {
            return Err("v2 segment request-map/outcome bound invalid".into());
        }
        let (number, first, previous_hash) = match previous {
            Some(prior) => {
                prior.validate()?;
                if prior.binding != self.binding || prior.requests_after != *requests {
                    return Err("v2 segment supplied a different request history".into());
                }
                (
                    prior
                        .segment_number
                        .checked_add(1)
                        .ok_or("v2 segment number overflow")?,
                    prior
                        .last_ordinal
                        .checked_add(1)
                        .ok_or("v2 ordinal overflow")?,
                    Some(prior.sha256()?),
                )
            }
            None => {
                if requests.entry_count != 0 || requests.page.is_some() {
                    return Err("v2 first segment requires exact empty request map".into());
                }
                (0, 1, None)
            }
        };
        if number >= MAX_SEGMENTS {
            return Err("v2 immutable segment count ceiling reached".into());
        }
        let mut total = 0_u64;
        let mut seen = BTreeSet::new();
        let mut metadata = Vec::new();
        for (index, input) in inputs.iter().enumerate() {
            if input.ordinal
                != first
                    .checked_add(index as u64)
                    .ok_or("v2 ordinal overflow")?
            {
                return Err("v2 segment global ordinals are not contiguous".into());
            }
            let request = validate_record(&self.binding, input, &mut || guard.check())?;
            if !seen.insert(request.clone()) {
                return Err("v2 segment repeats request identifier".into());
            }
            total = total
                .checked_add(input.record.len() as u64)
                .and_then(|v| v.checked_add(input.source.len() as u64))
                .and_then(|v| v.checked_add(input.payload.len() as u64))
                .ok_or("v2 segment logical byte overflow")?;
            if total > MAX_SEGMENT_BYTES {
                return Err("v2 immutable segment byte ceiling reached".into());
            }
            metadata.push(request);
        }
        // All duplicate checks happen before new private objects are written.
        for request in &metadata {
            if self
                .get_map(requests, &requests.key(request.as_bytes())?, &mut guard)?
                .is_some()
            {
                return Err("v2 request identifier already exists in earlier segment".into());
            }
        }
        let mut members = Vec::new();
        let mut edits = Vec::new();
        for (input, request_id) in inputs.iter().zip(metadata) {
            guard.check()?;
            members.push(Member {
                ordinal: input.ordinal,
                request_id: request_id.clone(),
                record: self.put_blob(input.record, &mut guard)?,
                source: self.put_blob(input.source, &mut guard)?,
                payload: self.put_blob(input.payload, &mut guard)?,
            });
            edits.push(MapEdit {
                key: requests.key(request_id.as_bytes())?,
                expected_value_sha256: None,
                value: Some(serde_json::to_vec(&RequestValue {
                    schema_version: 1,
                    ordinal: input.ordinal,
                    segment_number: number,
                    record_sha256: luma_content::sha256(input.record),
                })?),
            });
        }
        edits.sort_by(|a, b| a.key.cmp(&b.key));
        let next = self.edit_map(requests, &edits, &mut guard)?;
        let manifest = serde_json::to_vec(&Manifest {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: self.binding.clone(),
            segment_number: number,
            members,
        })?;
        if manifest.len() > 1024 * 1024 {
            return Err("v2 bounded segment manifest exceeded".into());
        }
        let descriptor = SegmentDescriptor {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: self.binding.clone(),
            segment_number: number,
            first_ordinal: first,
            last_ordinal: first + inputs.len() as u64 - 1,
            previous_segment_sha256: previous_hash,
            outcome_count: inputs.len() as u32,
            logical_bytes: total,
            manifest: self.put_blob(&manifest, &mut guard)?,
            requests_before: requests.clone(),
            requests_after: next,
        };
        descriptor.follows(previous)?;
        guard.check()?;
        Ok(SealedSegment { descriptor })
    }
    /// Verifies exact immutable members and globally unique request-map entries.
    /// This is structural/data verification, not semantic engine replay or C.
    pub fn visit_segment(
        &self,
        descriptor: &SegmentDescriptor,
        previous: Option<&SegmentDescriptor>,
        budget: IoBudget,
        boundary: &mut impl Boundary,
        mut visitor: impl FnMut(SegmentInput<'_>) -> Result<()>,
    ) -> Result<u64> {
        descriptor.follows(previous)?;
        if descriptor.binding != self.binding {
            return Err("v2 segment belongs to another owner".into());
        }
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let bytes = self.get_blob(&descriptor.manifest, &mut guard)?;
        let manifest: Manifest = canonical(&bytes, 1024 * 1024)?;
        if manifest.schema_version != 1
            || manifest.domain != DOMAIN
            || manifest.binding != self.binding
            || manifest.segment_number != descriptor.segment_number
            || manifest.members.len() != descriptor.outcome_count as usize
        {
            return Err("v2 segment manifest identity/count differs".into());
        }
        // Reconstruct the COMPLETE exact root delta, preserving every untouched
        // old subtree. Count plus membership of new IDs alone is insufficient.
        let mut edits = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, member) in manifest.members.iter().enumerate() {
            if member.ordinal != descriptor.first_ordinal + index as u64
                || !seen.insert(member.request_id.clone())
            {
                return Err("v2 segment repeats/reorders request metadata".into());
            }
            identifier(&member.request_id)?;
            member.record.validate()?;
            member.source.validate()?;
            member.payload.validate()?;
            edits.push(MapEdit {
                key: descriptor
                    .requests_before
                    .key(member.request_id.as_bytes())?,
                expected_value_sha256: None,
                value: Some(serde_json::to_vec(&RequestValue {
                    schema_version: 1,
                    ordinal: member.ordinal,
                    segment_number: descriptor.segment_number,
                    record_sha256: member.record.sha256.clone(),
                })?),
            });
        }
        edits.sort_by(|a, b| a.key.cmp(&b.key));
        if self.preview_map_inner(&descriptor.requests_before, &edits, &mut guard)?
            != descriptor.requests_after
        {
            return Err("v2 segment changes unrelated global request history".into());
        }
        let mut total = 0_u64;
        let mut requests = BTreeSet::new();
        for (index, member) in manifest.members.into_iter().enumerate() {
            if member.ordinal != descriptor.first_ordinal + index as u64
                || !requests.insert(member.request_id.clone())
            {
                return Err("v2 segment manifest repeats/reorders outcomes".into());
            }
            let record = self.get_blob(&member.record, &mut guard)?;
            let source = self.get_blob(&member.source, &mut guard)?;
            let payload = self.get_blob(&member.payload, &mut guard)?;
            let input = SegmentInput {
                ordinal: member.ordinal,
                record: &record,
                source: &source,
                payload: &payload,
            };
            if validate_record(&self.binding, &input, &mut || guard.check())? != member.request_id {
                return Err("v2 segment request label differs from canonical record".into());
            }
            let key = descriptor
                .requests_after
                .key(member.request_id.as_bytes())?;
            if self
                .get_map(&descriptor.requests_before, &key, &mut guard)?
                .is_some()
            {
                return Err("v2 segment reuses earlier global request".into());
            }
            let expected = serde_json::to_vec(&RequestValue {
                schema_version: 1,
                ordinal: member.ordinal,
                segment_number: descriptor.segment_number,
                record_sha256: luma_content::sha256(&record),
            })?;
            if self
                .get_map(&descriptor.requests_after, &key, &mut guard)?
                .as_ref()
                != Some(&expected)
            {
                return Err("v2 segment outcome missing from exact request map".into());
            }
            total = total
                .checked_add(record.len() as u64)
                .and_then(|v| v.checked_add(source.len() as u64))
                .and_then(|v| v.checked_add(payload.len() as u64))
                .ok_or("v2 verified segment byte overflow")?;
            if total > MAX_SEGMENT_BYTES {
                return Err("v2 verified segment byte ceiling exceeded".into());
            }
            guard.check()?;
            visitor(input)?;
            guard.check()?;
        }
        if total != descriptor.logical_bytes {
            return Err("v2 segment logical byte commitment differs".into());
        }
        guard.check()?;
        Ok(u64::from(descriptor.outcome_count))
    }
}
