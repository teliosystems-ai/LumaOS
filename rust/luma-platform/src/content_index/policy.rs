//! Versioned compiled owner-v2 quota DATA. These ceilings do not reserve disk,
//! supply a grant, prove free space/inodes or replace current C selection.
use super::*;
use luma_content_store::v2::PhysicalInventory;
pub(crate) fn sha256() -> Result<String> {
    // The same complete source asset is embedded in the immutable executable.
    // Actual installed consumption additionally pins the held image file.
    Policy::parse(include_bytes!(
        "../../../../native/image/overlay/usr/share/luma-os/content-index-policy.json"
    ))?
    .sha256()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    schema_version: u32,
    profile: String,
    maximum_allocated_bytes: u64,
    maximum_regular_files: u64,
    maximum_directories: u64,
    maximum_segments: u64,
}
impl Policy {
    pub(crate) fn compiled() -> Self {
        Self {
            schema_version: 1,
            profile: "luma-owner-v2-quota-v1".into(),
            maximum_allocated_bytes: 64 * 1024 * 1024 * 1024,
            maximum_regular_files: 1_048_576,
            maximum_directories: 65_536,
            maximum_segments: 4096,
        }
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self != &Self::compiled() {
            return Err("owner-v2 quota differs from the exact compiled support profile".into());
        }
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        // The single final LF is part of the exact compiled asset pin.
        let compact = bytes
            .strip_suffix(b"\n")
            .ok_or("compiled quota asset omits exact final LF")?;
        let value: Self = decode(compact, 4096)?;
        if value.canonical_bytes()? != bytes {
            return Err("quota asset differs from exact compiled canonical bytes".into());
        }
        Ok(value)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(luma_content::sha256(&self.canonical_bytes()?))
    }
    pub(crate) fn preview_liability(
        review: &phase::WindowReview,
        objects: &[luma_content_store::v2::ObjectWriteSpec],
    ) -> Result<Liability> {
        review.validate()?;
        if objects.len() > 32768
            || luma_content::sha256(&serde_json::to_vec(objects)?) != review.planned_objects_sha256
        {
            return Err("quota preview does not bind exact independently reconstructed derivative inventory".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for object in objects {
            object.validate()?;
            if !seen.insert(&object.sha256) {
                return Err("quota preview repeats derivative object".into());
            }
        }
        let count = objects.len() as u64;
        let derivative = count
            .checked_mul(131072)
            .ok_or("index preview derivative hold overflow")?
            .max(review.maximum_write_bytes);
        let allocated_bytes = derivative
            .checked_add(review.metadata_maximum.write_bytes)
            .ok_or("index preview metadata hold overflow")?;
        if allocated_bytes > 128 * 1024 * 1024 {
            return Err(
                "reviewed derivative plus metadata hold exceeds unchanged finite Write ceiling"
                    .into(),
            );
        }
        Ok(Liability {
            allocated_bytes,
            regular_files: count + u64::from(review.metadata_maximum.object_writes),
            directories: count
                .checked_mul(2)
                .and_then(|n| n.checked_add(2 * u64::from(review.metadata_maximum.object_writes)))
                .ok_or("index preview inode hold overflow")?,
            segments: 0,
        })
    }
    pub(crate) fn metadata_liability(
        objects: &[luma_content_store::v2::ObjectWriteSpec],
    ) -> Result<Liability> {
        let maximum = phase::MetadataMaximum::compiled();
        maximum.validate()?;
        if objects.is_empty() || objects.len() > maximum.object_writes as usize {
            return Err("index transition metadata exceeds fixed reviewed maximum".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for object in objects {
            object.validate()?;
            if !seen.insert(&object.sha256) {
                return Err("transition metadata repeats object".into());
            }
        }
        Ok(Liability {
            allocated_bytes: maximum.write_bytes,
            regular_files: u64::from(maximum.object_writes),
            directories: 2 * u64::from(maximum.object_writes),
            segments: 0,
        })
    }
    pub(crate) fn admit_data(
        &self,
        actual: &PhysicalInventory,
        segments: u64,
        retained: impl IntoIterator<Item = Liability>,
        requested: &Liability,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<CapacitySummary> {
        check()?;
        self.canonical_bytes()?;
        if actual.incomplete_objects > actual.regular_files {
            return Err("owner physical counters are inconsistent".into());
        }
        let actual = Liability {
            allocated_bytes: actual.allocated_bytes,
            regular_files: actual.regular_files,
            directories: actual.directories,
            segments,
        };
        self.limit(&actual)?;
        let mut total = actual.clone();
        let mut retained_total = Liability::default();
        let mut count = 0u64;
        let mut retained = retained.into_iter();
        loop {
            // Current original checks occur BEFORE advancing an iterator that
            // may itself read bounded independently selected private records.
            check()?;
            let Some(value) = retained.next() else {
                break;
            };
            count = count
                .checked_add(1)
                .filter(|v| *v <= self.maximum_regular_files)
                .ok_or("owner retained-liability record count exceeds finite support profile")?;
            self.limit(&value)?;
            retained_total.add(&value)?;
            total.add(&value)?;
            self.limit(&total)?;
        }
        check()?;
        self.limit(requested)?;
        total.add(requested)?;
        self.limit(&total)?;
        check()?;
        Ok(CapacitySummary {
            schema_version: 1,
            policy_sha256: self.sha256()?,
            actual,
            retained_records: count,
            retained: retained_total,
            requested: requested.clone(),
            total,
        })
    }
    fn limit(&self, value: &Liability) -> Result<()> {
        if value.allocated_bytes > self.maximum_allocated_bytes
            || value.regular_files > self.maximum_regular_files
            || value.directories > self.maximum_directories
            || value.segments > self.maximum_segments
        {
            return Err(
                "actual plus retained plus requested owner-v2 liability exceeds the compiled quota"
                    .into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Liability {
    pub(crate) allocated_bytes: u64,
    pub(crate) regular_files: u64,
    pub(crate) directories: u64,
    pub(crate) segments: u64,
}
impl Liability {
    fn add(&mut self, value: &Self) -> Result<()> {
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(value.allocated_bytes)
            .ok_or("owner byte liability overflow")?;
        self.regular_files = self
            .regular_files
            .checked_add(value.regular_files)
            .ok_or("owner file liability overflow")?;
        self.directories = self
            .directories
            .checked_add(value.directories)
            .ok_or("owner directory liability overflow")?;
        self.segments = self
            .segments
            .checked_add(value.segments)
            .ok_or("owner segment liability overflow")?;
        Ok(())
    }
}
/// A checked arithmetic description ONLY. Native admission must ALSO prove
/// actual hardware headroom, C metadata/tails, original grants and selection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacitySummary {
    schema_version: u32,
    policy_sha256: String,
    actual: Liability,
    retained_records: u64,
    retained: Liability,
    requested: Liability,
    total: Liability,
}
impl CapacitySummary {
    pub(crate) fn validate_data(&self) -> Result<()> {
        let policy = Policy::compiled();
        if self.schema_version != 1
            || self.policy_sha256 != policy.sha256()?
            || self.retained_records > policy.maximum_regular_files
        {
            return Err("owner capacity summary substitutes compiled policy".into());
        }
        for value in [&self.actual, &self.retained, &self.requested, &self.total] {
            policy.limit(value)?;
        }
        let mut expected = self.actual.clone();
        expected.add(&self.retained)?;
        expected.add(&self.requested)?;
        if expected != self.total {
            return Err("owner capacity summary omits retained/requested liability".into());
        }
        Ok(())
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        self.validate_data()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_profile_is_closed_versioned_and_not_legacy_or_snapshot_permission() {
        let p = Policy::compiled();
        let bytes = p.canonical_bytes().unwrap();
        assert_eq!(Policy::parse(&bytes).unwrap(), p);
        assert_ne!(
            p.maximum_allocated_bytes,
            luma_content_store::MAX_REPOSITORY_BYTES
        );
        assert_eq!(p.maximum_segments * 256, 1_048_576);
        assert_eq!(
            Policy::parse(include_bytes!(
                "../../../../native/image/overlay/usr/share/luma-os/content-index-policy.json"
            ))
            .unwrap(),
            p
        );
        for field in 0..5 {
            let mut changed = p.clone();
            match field {
                0 => changed.schema_version += 1,
                1 => changed.maximum_allocated_bytes += 1,
                2 => changed.maximum_regular_files += 1,
                3 => changed.maximum_directories += 1,
                4 => changed.maximum_segments += 1,
                _ => unreachable!(),
            }
            assert!(changed.canonical_bytes().is_err());
        }
    }
    #[test]
    fn actual_plus_all_retained_and_new_hold_are_counted_before_return() {
        let p = Policy::compiled();
        let actual = PhysicalInventory {
            allocated_bytes: p.maximum_allocated_bytes - 10,
            ..Default::default()
        };
        let retain = Liability {
            allocated_bytes: 6,
            ..Default::default()
        };
        let request = Liability {
            allocated_bytes: 4,
            ..Default::default()
        };
        let summary = p
            .admit_data(&actual, 0, [retain.clone()], &request, &mut || Ok(()))
            .unwrap();
        summary.validate_data().unwrap();
        let mut changed = request;
        changed.allocated_bytes += 1;
        assert!(p
            .admit_data(&actual, 0, [retain], &changed, &mut || Ok(()))
            .is_err());
        let actual = PhysicalInventory {
            regular_files: p.maximum_regular_files,
            ..Default::default()
        };
        assert!(p
            .admit_data(
                &actual,
                0,
                [],
                &Liability {
                    regular_files: 1,
                    ..Default::default()
                },
                &mut || Ok(())
            )
            .is_err());
        assert!(p
            .admit_data(
                &PhysicalInventory::default(),
                p.maximum_segments + 1,
                [],
                &Liability::default(),
                &mut || Ok(())
            )
            .is_err());
    }
    #[test]
    fn arithmetic_overflow_or_revocation_refuses_before_private_iterator_step() {
        let mut liability = Liability {
            allocated_bytes: u64::MAX,
            ..Default::default()
        };
        assert!(liability
            .add(&Liability {
                allocated_bytes: 1,
                ..Default::default()
            })
            .is_err());
        let iterator = std::iter::from_fn(|| -> Option<Liability> {
            panic!("revoked before private record advance")
        });
        assert!(Policy::compiled()
            .admit_data(
                &PhysicalInventory::default(),
                0,
                iterator,
                &Liability::default(),
                &mut || Err("fixture revoked".into())
            )
            .is_err());
    }
}
