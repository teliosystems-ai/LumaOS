//! Bounded observations of the one existing parent allowed to grow when a
//! direct job directory is created. DATA is covered by the existing C event;
//! these filesystem timestamps and identities are not independent authority.
use super::*;
pub(super) const MAX_GROWTH: u64 = 64 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub device: u64,
    pub inode: u64,
    pub mount: u64,
    pub allocated_bytes: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}
impl Observation {
    fn validate(&self) -> Result<()> {
        if self.inode == 0
            || self.mount == 0
            || self.allocated_bytes % 512 != 0
            || self.allocated_bytes > 24 * 1024 * 1024 * 1024
            || !(0..1_000_000_000).contains(&self.ctime_nanoseconds)
        {
            return Err("invalid bounded direct parent physical DATA".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Delta {
    pub schema_version: u32,
    pub domain: String,
    pub before: Observation,
    pub after: Observation,
}
impl Delta {
    pub fn validate(&self) -> Result<()> {
        self.before.validate()?;
        self.after.validate()?;
        if self.schema_version != 4
            || self.domain != "luma-c-direct-attempts-parent-allocation-v4"
            || (self.before.device, self.before.inode, self.before.mount)
                != (self.after.device, self.after.inode, self.after.mount)
            || self
                .after
                .allocated_bytes
                .checked_sub(self.before.allocated_bytes)
                .map_or(true, |n| n > MAX_GROWTH)
        {
            return Err("direct parent delta resets identity, loses blocks or exceeds reserved metadata growth".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn delta() -> Delta {
        let before = Observation {
            device: u64::MAX,
            inode: u64::MAX,
            mount: u64::MAX,
            allocated_bytes: 4096,
            ctime_seconds: i64::MIN,
            ctime_nanoseconds: 999_999_999,
        };
        Delta {
            schema_version: 4,
            domain: "luma-c-direct-attempts-parent-allocation-v4".into(),
            after: Observation {
                allocated_bytes: 4096 + MAX_GROWTH,
                ctime_seconds: i64::MAX,
                ..before.clone()
            },
            before,
        }
    }
    #[test]
    fn exact_parent_delta_is_bounded_identity_data_not_a_free_allocation_exemption() {
        let valid = delta();
        valid.validate().unwrap();
        for index in 0..9 {
            let mut candidate = valid.clone();
            match index {
                0 => candidate.after.allocated_bytes += 512,
                1 => candidate.after.allocated_bytes = candidate.before.allocated_bytes - 512,
                2 => candidate.after.inode -= 1,
                3 => candidate.after.mount -= 1,
                4 => candidate.after.device -= 1,
                5 => candidate.after.ctime_nanoseconds = 1_000_000_000,
                6 => candidate.before.ctime_nanoseconds = -1,
                7 => candidate.after.allocated_bytes -= 1,
                _ => candidate.domain = "different-parent".into(),
            }
            assert!(
                candidate.validate().is_err(),
                "changed parent field {index}"
            );
        }
        let mut unchanged = valid;
        unchanged.after = unchanged.before.clone();
        unchanged.validate().unwrap();
    }
    #[test]
    fn parent_delta_decoder_refuses_unknown_fields_and_duplicate_members() {
        let bytes = serde_json::to_string(&delta()).unwrap();
        let unknown = bytes.replacen(
            "\"schema_version\":4",
            "\"schema_version\":4,\"authority\":true",
            1,
        );
        assert!(serde_json::from_str::<Delta>(&unknown).is_err());
        let duplicate = bytes.replacen(
            "\"schema_version\":4",
            "\"schema_version\":4,\"schema_version\":4",
            1,
        );
        assert!(serde_json::from_str::<Delta>(&duplicate).is_err());
    }
}
