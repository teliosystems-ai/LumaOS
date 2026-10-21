//! The single blob encoder for actual immutable writes and their complete
//! deterministic pre-write DATA inventory. No file is opened by this encoder.
use super::*;
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteSpec {
    pub sha256: String,
    pub bytes: u32,
}
impl ObjectWriteSpec {
    pub fn validate(&self) -> Result<()> {
        digest(&self.sha256)?;
        if self.bytes == 0 || self.bytes as usize > MAX_PAGE_BYTES {
            return Err("planned immutable object exceeds one finite page".into());
        }
        Ok(())
    }
}
pub struct PlannedBlobObject<'a> {
    sha256: String,
    bytes: Cow<'a, [u8]>,
}
impl PlannedBlobObject<'_> {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn specification(&self) -> ObjectWriteSpec {
        ObjectWriteSpec {
            sha256: self.sha256.clone(),
            bytes: self.bytes.len() as u32,
        }
    }
}
/// Chunk slices borrow the original bounded source; only canonical group/index
/// metadata is allocated. Repeated SHA occurrences are retained in write order
/// to preserve the actual old encoder's reuse/readback semantics.
pub struct BlobObjectPlan<'a> {
    reference: BlobReference,
    objects: Vec<PlannedBlobObject<'a>>,
}
impl<'a> BlobObjectPlan<'a> {
    pub fn data(
        binding: &OwnerBinding,
        bytes: &'a [u8],
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        check()?;
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return Err("blob plan exceeds unchanged finite64MiB source bound".into());
        }
        let mut objects = Vec::new();
        let mut groups = Vec::new();
        let mut chunks = Vec::new();
        let mut count = 0_u32;
        for part in bytes.chunks(MAX_PAGE_BYTES) {
            check()?;
            let sha256 = luma_content::sha256(part);
            check()?;
            chunks.push(Chunk {
                sha256: sha256.clone(),
                bytes: part.len() as u32,
            });
            objects.push(PlannedBlobObject {
                sha256,
                bytes: Cow::Borrowed(part),
            });
            count = count
                .checked_add(1)
                .ok_or("blob plan chunk count overflow")?;
            if chunks.len() == GROUP {
                groups.push(group(
                    binding,
                    std::mem::take(&mut chunks),
                    &mut objects,
                    &mut check,
                )?);
            }
        }
        if !chunks.is_empty() {
            groups.push(group(binding, chunks, &mut objects, &mut check)?);
        }
        let index_sha256 = if groups.is_empty() {
            None
        } else {
            check()?;
            let encoded = serde_json::to_vec(&BlobIndex {
                schema_version: 1,
                domain: DOMAIN.into(),
                binding: binding.clone(),
                groups,
            })?;
            Some(owned(encoded, &mut objects, &mut check)?)
        };
        check()?;
        let sha256 = luma_content::sha256(bytes);
        check()?;
        let reference = BlobReference {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            sha256,
            bytes: bytes.len() as u64,
            chunk_count: count,
            index_sha256,
        };
        reference.validate()?;
        if objects.len() > 4161 {
            return Err("blob encoder exceeds its exact4096chunk+64group+1index bound".into());
        }
        Ok(Self { reference, objects })
    }
    pub fn reference(&self) -> &BlobReference {
        &self.reference
    }
    pub fn objects(&self) -> impl Iterator<Item = &PlannedBlobObject<'a>> {
        self.objects.iter()
    }
    /// Complete first-occurrence inventory, with exact byte equality for every
    /// repeated SHA. It is not evidence of preabsence, creation or allocation.
    pub fn write_set(&self, mut check: impl FnMut() -> Result<()>) -> Result<Vec<ObjectWriteSpec>> {
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        let mut result = Vec::new();
        for (ordinal, object) in self.objects.iter().enumerate() {
            check()?;
            if let Some(previous) = seen.get(object.sha256.as_str()) {
                if self.objects[*previous].bytes() != object.bytes() {
                    return Err("blob plan SHA collision has different actual bytes".into());
                }
            } else {
                seen.insert(&object.sha256, ordinal);
                let spec = object.specification();
                spec.validate()?;
                result.push(spec);
            }
        }
        check()?;
        Ok(result)
    }
}
fn owned<'a>(
    bytes: Vec<u8>,
    objects: &mut Vec<PlannedBlobObject<'a>>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<String> {
    check()?;
    if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
        return Err("canonical blob metadata exceeds unchanged page bound".into());
    }
    let sha256 = luma_content::sha256(&bytes);
    objects.push(PlannedBlobObject {
        sha256: sha256.clone(),
        bytes: Cow::Owned(bytes),
    });
    check()?;
    Ok(sha256)
}
fn group<'a>(
    binding: &OwnerBinding,
    chunks: Vec<Chunk>,
    objects: &mut Vec<PlannedBlobObject<'a>>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<GroupRef> {
    check()?;
    if chunks.is_empty() || chunks.len() > GROUP {
        return Err("blob plan group exceeds exact64chunk boundary".into());
    }
    let bytes = chunks.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(u64::from(chunk.bytes))
            .ok_or("blob plan byte sum overflow")
    })?;
    let count = chunks.len() as u32;
    let encoded = serde_json::to_vec(&ChunkGroup {
        schema_version: 1,
        domain: DOMAIN.into(),
        binding: binding.clone(),
        chunks,
    })?;
    Ok(GroupRef {
        sha256: owned(encoded, objects, check)?,
        bytes,
        chunks: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> OwnerBinding {
        OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 1,
        }
    }
    #[test]
    fn empty_blob_has_no_invented_object() {
        let plan = BlobObjectPlan::data(&owner(), &[], || Ok(())).unwrap();
        assert_eq!(plan.reference().sha256, luma_content::sha256(&[]));
        assert!(plan.reference().index_sha256.is_none());
        assert_eq!(plan.objects().count(), 0);
        assert!(plan.write_set(|| Ok(())).unwrap().is_empty());
    }
    #[test]
    fn actual65chunk_boundary_and_exact_duplicate_inventory() {
        let bytes = vec![b'x'; 65 * MAX_PAGE_BYTES];
        let plan = BlobObjectPlan::data(&owner(), &bytes, || Ok(())).unwrap();
        assert_eq!(plan.reference().chunk_count, 65);
        assert_eq!(plan.objects().count(), 68);
        let inventory = plan.write_set(|| Ok(())).unwrap();
        assert_eq!(inventory.len(), 4);
        let map: BTreeMap<_, _> = plan
            .objects()
            .map(|entry| (entry.sha256().to_owned(), entry.bytes().to_vec()))
            .collect();
        let actual = collect_blob_range(plan.reference(), 0, bytes.len() as u64, |sha| {
            Ok(map.get(sha).ok_or("missing exact planned member")?.clone())
        })
        .unwrap();
        assert_eq!(actual, bytes);
    }
    #[test]
    fn finite_bound_and_live_cancellation_are_checked_before_data_result() {
        let oversized = vec![0; (MAX_SEGMENT_BYTES + 1) as usize];
        assert!(BlobObjectPlan::data(&owner(), &oversized, || Ok(())).is_err());
        let bytes = vec![1; 3 * MAX_PAGE_BYTES];
        let mut calls = 0;
        assert!(BlobObjectPlan::data(&owner(), &bytes, || {
            calls += 1;
            if calls >= 4 {
                Err("fixture original authorization expired".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(calls, 4);
    }
    #[test]
    fn duplicate_sha_never_hides_different_actual_bytes() {
        let data = b"one";
        let mut plan = BlobObjectPlan::data(&owner(), data, || Ok(())).unwrap();
        let sha = plan.objects[0].sha256.clone();
        plan.objects.push(PlannedBlobObject {
            sha256: sha,
            bytes: Cow::Owned(b"two".to_vec()),
        });
        assert!(plan.write_set(|| Ok(())).is_err());
    }
}
