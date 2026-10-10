//! Semantic UTC floors in the existing Admin checkpoint domain, NOT live time.
//! A canonical payload or verified historical floor never grants authority.
//! No new NV index, writer endpoint, clock seed, reset or automatic recovery.
#![cfg_attr(not(test), allow(dead_code))]
pub(crate) use crate::utc_stream::Observation;
use crate::{admin_governance::Identity, bundle, tpm, utc_policy::ApprovedPolicy, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) const ACTIVITY: &str = "admin.utc-history-advance";

/// Inert proposed floor/context, not proof that the producer is approved.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Statement {
    pub floor_ms: i64,
    pub policy_sha256: String,
    pub boot_id: String,
    pub process_generation: u64,
    pub source_clock_generation: u64,
    pub keeper_generation: u64,
    pub runtime_sha256: String,
}
impl Statement {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.floor_ms <= 0
            || self.floor_ms > 4_102_444_800_000
            || tpm::decode::<32>(&self.policy_sha256)? != ApprovedPolicy::fixed()?.digest()
            || tpm::decode::<16>(&self.boot_id)? == [0; 16]
            || tpm::decode::<32>(&self.runtime_sha256)? == [0; 32]
            || self.process_generation == 0
            || self.source_clock_generation == 0
            || self.keeper_generation == 0
        {
            return Err("invalid UTC history statement".into());
        }
        Ok(())
    }
    pub(crate) fn supported_by(&self, live: &Observation) -> Result<()> {
        self.validate()?;
        live.context().validate()?;
        let (lower, upper) = live.interval().endpoints();
        let mut expected = live.context().clone();
        expected.floor_ms = self.floor_ms;
        if &expected != self
            || live.context().floor_ms != lower
            || upper - lower > 500
            || upper > 4_102_444_800_000
            || self.floor_ms > lower
        {
            return Err("UTC history lacks matching current observation".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub schema_version: u32,
    pub kind: String,
    pub deployment: String,
    pub enrollment_sha256: String,
    pub principal: Identity,
    pub request_id: String,
    pub sequence: usize,
    pub previous_head: String,
    pub history_version_before: u64,
    pub previous_floor_ms: i64,
    pub statement: Statement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct History {
    pub floor_ms: i64,
    pub version: u64,
}
impl History {
    pub(crate) fn initial() -> Self {
        Self {
            floor_ms: 0,
            version: 0,
        }
    }
    // Common deployment/principal/head/payload bindings are checked by the
    // owning governance replayer, which obtained a fresh Store::snapshot().
    pub(crate) fn apply(&mut self, record: &Record) -> Result<()> {
        record.statement.validate()?;
        if record.schema_version != 1
            || record.kind != "native-admin-utc-history"
            || record.previous_floor_ms != self.floor_ms
            || record.history_version_before != self.version
            || record.statement.floor_ms <= self.floor_ms
        {
            return Err("invalid UTC history transition; preserve state".into());
        }
        let version = self
            .version
            .checked_add(1)
            .ok_or("UTC history version exhausted")?;
        self.floor_ms = record.statement.floor_ms;
        self.version = version;
        Ok(())
    }
}

pub(crate) fn read(path: &Path, request: &str) -> Result<(Record, Vec<u8>)> {
    let bytes = tpm::private_read(path, 16384)?;
    let record: Record = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&record)? != bytes || record.request_id != request {
        return Err("noncanonical or substituted UTC history payload; preserve state".into());
    }
    // This hash is checked against the shared Admin event, not a second anchor.
    tpm::decode::<32>(&record.previous_head)?;
    tpm::decode::<32>(&record.deployment)?;
    tpm::decode::<32>(&record.enrollment_sha256)?;
    record.statement.validate()?;
    Ok((record, bytes))
}

pub(crate) fn policy_digest() -> Result<String> {
    Ok(bundle::hex(&ApprovedPolicy::fixed()?.digest()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utc_bounds::Interval;
    fn statement() -> Statement {
        Statement {
            floor_ms: 1000,
            policy_sha256: policy_digest().unwrap(),
            boot_id: "12".repeat(16),
            process_generation: 1,
            source_clock_generation: 2,
            keeper_generation: 3,
            runtime_sha256: "34".repeat(32),
        }
    }
    fn record() -> Record {
        Record { schema_version: 1, kind: "native-admin-utc-history".into(), deployment: "56".repeat(32),
            enrollment_sha256: "78".repeat(32), principal: serde_json::from_value(serde_json::json!({
                "installation":"ab".repeat(32),"principal":"cd".repeat(32),"generation":1,"login":"human","uid":1001})).unwrap(),
            request_id: "floor-1".into(), sequence: 2, previous_head: "90".repeat(32),
            history_version_before: 0, previous_floor_ms: 0, statement: statement() }
    }
    #[test]
    fn floor_and_version_advance_only_monotonically() {
        let mut history = History::initial();
        let r = record();
        history.apply(&r).unwrap();
        assert_eq!(
            history,
            History {
                floor_ms: 1000,
                version: 1
            }
        );
        let before = history.clone();
        assert!(history.apply(&r).is_err());
        assert_eq!(history, before);
        let mut next = r.clone();
        next.previous_floor_ms = 1000;
        next.history_version_before = 1;
        for value in [999, 1000] {
            next.statement.floor_ms = value;
            assert!(history.apply(&next).is_err());
            assert_eq!(history, before);
        }
        next.statement.floor_ms = 1001;
        history.apply(&next).unwrap();
        assert_eq!(history.version, 2);
    }
    #[test]
    fn invalid_kind_transition_and_exhausted_version_leave_state_unchanged() {
        for variant in 0..4 {
            let mut r = record();
            match variant {
                0 => r.schema_version = 2,
                1 => r.kind = "utc-authority".into(),
                2 => r.previous_floor_ms = 1,
                _ => r.history_version_before = 1,
            }
            let mut history = History::initial();
            assert!(history.apply(&r).is_err());
            assert_eq!(history, History::initial());
        }
        let mut history = History {
            floor_ms: 0,
            version: u64::MAX,
        };
        let mut r = record();
        r.history_version_before = u64::MAX;
        assert!(history.apply(&r).is_err());
        assert_eq!(history.floor_ms, 0);
        assert_eq!(history.version, u64::MAX);
    }
    #[test]
    fn statement_context_bounds_and_policy_are_closed() {
        for variant in 0..11 {
            let mut s = statement();
            match variant {
                0 => s.floor_ms = 0,
                1 => s.floor_ms = -1,
                2 => s.floor_ms = 4_102_444_800_001,
                3 => s.policy_sha256 = "00".repeat(32),
                4 => s.boot_id = "00".repeat(16),
                5 => s.runtime_sha256 = "00".repeat(32),
                6 => s.process_generation = 0,
                7 => s.source_clock_generation = 0,
                8 => s.keeper_generation = 0,
                9 => s.runtime_sha256 = "ab".repeat(31),
                _ => s.boot_id = "AB".repeat(16),
            }
            assert!(s.validate().is_err(), "variant {variant}");
        }
    }
    #[test]
    fn fresh_observation_must_support_floor_and_exact_context() {
        let s = statement();
        assert!(s
            .supported_by(&Observation::fixture(
                s.clone(),
                Interval::new(1000, 1100).unwrap()
            ))
            .is_ok());
        let mut advanced = s.clone();
        advanced.floor_ms = 1100;
        assert!(s
            .supported_by(&Observation::fixture(
                advanced,
                Interval::new(1100, 1200).unwrap()
            ))
            .is_ok());
        for variant in 0..7 {
            let mut context = s.clone();
            let mut utc = Interval::new(1000, 1100).unwrap();
            match variant {
                0 => context.boot_id = "34".repeat(16),
                1 => context.runtime_sha256 = "56".repeat(32),
                2 => context.keeper_generation += 1,
                3 => context.source_clock_generation += 1,
                4 => {
                    context.floor_ms = 999;
                    utc = Interval::new(999, 1099).unwrap();
                }
                5 => utc = Interval::new(1000, 1501).unwrap(),
                _ => context.floor_ms = 1001,
            }
            assert!(s.supported_by(&Observation::fixture(context, utc)).is_err());
        }
    }
    #[test]
    fn nested_record_fields_are_not_extensible_or_authority_claims() {
        let value = serde_json::to_value(record()).unwrap();
        for path in ["", "/statement", "/principal"] {
            let mut changed = value.clone();
            changed
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("trusted".into(), true.into());
            assert!(serde_json::from_value::<Record>(changed).is_err());
        }
        for path in [
            "/statement/floor_ms",
            "/statement/runtime_sha256",
            "/previous_head",
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = serde_json::Value::Null;
            assert!(serde_json::from_value::<Record>(changed).is_err());
        }
    }
}
