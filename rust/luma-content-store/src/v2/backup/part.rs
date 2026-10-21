use super::*;
const MAGIC: &[u8; 16] = b"LUMAV2SNAPSHOT1\n";

/// Original file identity is descriptive evidence only. Import never recreates
/// these inode/device/permission values or treats an incomplete object as live.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotObject {
    pub object_sha256: String,
    pub actual_sha256: String,
    pub bytes: u64,
    pub allocated_bytes: u64,
    pub complete: bool,
    pub source_device: u64,
    pub source_inode: u64,
}
impl SnapshotObject {
    pub fn validate(&self) -> Result<()> {
        digest(&self.object_sha256)?;
        digest(&self.actual_sha256)?;
        if self.bytes > MAX_PAGE_BYTES as u64
            || self.source_device == 0
            || self.source_inode == 0
            || self.allocated_bytes % 512 != 0
            || self.complete != (self.bytes > 0 && self.object_sha256 == self.actual_sha256)
        {
            return Err("invalid bounded raw snapshot object evidence".into());
        }
        Ok(())
    }
    pub(super) fn measured(name: &str, allocation: Allocation, bytes: &[u8]) -> Result<Self> {
        if allocation.bytes != bytes.len() as u64 {
            return Err("raw snapshot allocation/bytes changed".into());
        }
        let value = Self {
            object_sha256: name.into(),
            actual_sha256: luma_content::sha256(bytes),
            bytes: allocation.bytes,
            allocated_bytes: allocation.allocated_bytes,
            complete: allocation.complete,
            source_device: allocation.device,
            source_inode: allocation.inode,
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPartHeader {
    pub schema_version: u32,
    pub profile: String,
    pub intent_sha256: String,
    pub number: u32,
    pub previous_plaintext_sha256: Option<String>,
    pub objects: Vec<SnapshotObject>,
}
impl SnapshotPartHeader {
    fn validate(&self, intent: &SnapshotIntent) -> Result<()> {
        if self.schema_version != 1
            || self.profile != SNAPSHOT_PROFILE
            || self.intent_sha256 != intent.sha256()?
            || self.number >= MAX_SNAPSHOT_PARTS
            || self.objects.len() > MAX_PART_OBJECTS
            || (self.objects.is_empty() && self.number != 0)
            || (self.number == 0) != (self.previous_plaintext_sha256.is_none())
        {
            return Err("snapshot part intent/order/object bounds differ".into());
        }
        if let Some(previous) = &self.previous_plaintext_sha256 {
            digest(previous)?;
        }
        let mut last = None;
        for object in &self.objects {
            object.validate()?;
            if last.is_some_and(|old: &str| old >= object.object_sha256.as_str()) {
                return Err("snapshot objects repeat or lose canonical order".into());
            }
            last = Some(object.object_sha256.as_str());
        }
        Ok(())
    }
}
/// Borrowed plaintext framing only. Production decryption keeps its containing
/// bytes in the existing locked, nondumpable crypto buffer, not a pageable copy.
pub struct SnapshotPart<'a> {
    header: SnapshotPartHeader,
    data: &'a [u8],
    sha256: String,
}
impl SnapshotPart<'_> {
    pub fn header(&self) -> &SnapshotPartHeader {
        &self.header
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn visit_objects(
        &self,
        check: &mut impl FnMut() -> Result<()>,
        mut visitor: impl FnMut(&SnapshotObject, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut offset = 0_usize;
        for object in &self.header.objects {
            check()?;
            let end = offset
                .checked_add(object.bytes as usize)
                .ok_or("snapshot object offset overflow")?;
            let bytes = self
                .data
                .get(offset..end)
                .ok_or("truncated snapshot object bytes")?;
            if luma_content::sha256(bytes) != object.actual_sha256 {
                return Err("snapshot object bytes do not match measured commitment".into());
            }
            check()?;
            visitor(object, bytes)?;
            check()?;
            offset = end;
        }
        if offset != self.data.len() {
            return Err("snapshot part has uncommitted trailing data".into());
        }
        check()
    }
}
impl<'a> SnapshotPart<'a> {
    pub fn parse(
        bytes: &'a [u8],
        intent: &SnapshotIntent,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        intent.validate()?;
        if bytes.len() < 20 || bytes.len() > MAX_SNAPSHOT_PART_BYTES || &bytes[..16] != MAGIC {
            return Err("invalid bounded snapshot part frame".into());
        }
        let length = u32::from_be_bytes(bytes[16..20].try_into()?) as usize;
        if length == 0 || length > MAX_PAGE_BYTES || length > bytes.len() - 20 {
            return Err("snapshot part metadata length invalid".into());
        }
        let header: SnapshotPartHeader = canonical(&bytes[20..20 + length], MAX_PAGE_BYTES)?;
        header.validate(intent)?;
        let part = Self {
            header,
            data: &bytes[20 + length..],
            sha256: luma_content::sha256(bytes),
        };
        part.visit_objects(check, |_, _| Ok(()))?;
        check()?;
        Ok(part)
    }
}
pub(super) fn encode(
    intent: &SnapshotIntent,
    number: u32,
    previous: Option<String>,
    objects: Vec<SnapshotObject>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let header = SnapshotPartHeader {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256()?,
        number,
        previous_plaintext_sha256: previous,
        objects,
    };
    header.validate(intent)?;
    let metadata = bounded(&header, MAX_PAGE_BYTES)?;
    let total = 20_usize
        .checked_add(metadata.len())
        .and_then(|n| n.checked_add(data.len()))
        .ok_or("snapshot part frame overflow")?;
    if total > MAX_SNAPSHOT_PART_BYTES {
        return Err("snapshot part exceeds finite plaintext bound".into());
    }
    let mut result = Vec::with_capacity(total);
    result.extend(MAGIC);
    result.extend((metadata.len() as u32).to_be_bytes());
    result.extend(metadata);
    result.extend(data);
    SnapshotPart::parse(&result, intent, &mut || Ok(()))?;
    Ok(result)
}
