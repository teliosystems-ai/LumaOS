//! Inert interval arithmetic for the proposed UTC adapter; NOT a trusted clock.
//! Inputs do not prove NTS authentication, operator independence or freshness.
//! No CLI/IPC, serialized time token, wall-clock read, or authorization wiring.
#![cfg_attr(not(test), allow(dead_code))] // Protected live adapter is not implemented.
use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Interval {
    lower_ms: i64,
    upper_ms: i64,
}

impl Interval {
    pub(crate) fn endpoints(self) -> (i64, i64) {
        (self.lower_ms, self.upper_ms)
    }
    pub(crate) fn new(lower_ms: i64, upper_ms: i64) -> Result<Self> {
        if lower_ms < 0 || upper_ms < lower_ms {
            return Err("invalid UTC interval".into());
        }
        Ok(Self { lower_ms, upper_ms })
    }

    /// Every possible time must be inside [not_before, expires); equality at
    /// expiry refuses. This predicate itself supplies no role or effect grant.
    pub(crate) fn within(self, not_before_ms: i64, expires_ms: i64) -> Result<bool> {
        if not_before_ms < 0 || expires_ms <= not_before_ms {
            return Err("invalid finite UTC validity window".into());
        }
        Ok(self.lower_ms >= not_before_ms && self.upper_ms < expires_ms)
    }

    fn intersection(self, other: Self) -> Option<Self> {
        let lower_ms = self.lower_ms.max(other.lower_ms);
        let upper_ms = self.upper_ms.min(other.upper_ms);
        (lower_ms <= upper_ms).then_some(Self { lower_ms, upper_ms })
    }

    fn hull(self, other: Self) -> Self {
        Self {
            lower_ms: self.lower_ms.min(other.lower_ms),
            upper_ms: self.upper_ms.max(other.upper_ms),
        }
    }
}

/// Values must eventually come from a protected adapter, not the request.
/// Generation changes include restart, suspend and clock discontinuities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    pub(crate) boot_id: [u8; 16],
    pub(crate) provider_generation: u64,
    pub(crate) clock_generation: u64,
    pub(crate) policy_digest: [u8; 32],
}

impl Epoch {
    fn validate(self) -> Result<()> {
        if self.boot_id == [0; 16]
            || self.provider_generation == 0
            || self.clock_generation == 0
            || self.policy_digest == [0; 32]
        {
            return Err("uninitialized UTC epoch".into());
        }
        Ok(())
    }
}

/// Policy arguments are arithmetic inputs, not approved production settings.
#[derive(Clone, Copy)]
pub(crate) struct Policy {
    pub(crate) max_age_ms: u64,
    pub(crate) max_width_ms: u64,
    pub(crate) drift_ppm: u32, // Total rate error relative to true elapsed time.
}

impl Policy {
    fn validate(self) -> Result<()> {
        // Hard arithmetic limits; a live adapter must additionally enforce the
        // exact reviewed policy bound into Epoch.policy_digest.
        if self.max_age_ms == 0
            || self.max_age_ms > 3_600_000
            || self.max_width_ms == 0
            || self.max_width_ms > 1_000
            || self.drift_ppm == 0
            || self.drift_ppm > 1_000
        {
            return Err("invalid bounded UTC policy".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Measurement {
    pub(crate) operator: u8, // Fixed policy-local identities 1..=3, not IP addresses.
    pub(crate) utc: Interval,
    pub(crate) observed_boottime_ms: u64,
    pub(crate) epoch: Epoch,
}

fn project(sample: Measurement, now_ms: u64, epoch: Epoch, policy: Policy) -> Result<Interval> {
    if sample.epoch != epoch || !(1..=3).contains(&sample.operator) {
        return Err("UTC source or epoch mismatch".into());
    }
    let age = now_ms
        .checked_sub(sample.observed_boottime_ms)
        .filter(|age| *age <= policy.max_age_ms)
        .ok_or("UTC sample is future-dated or stale")?;
    // The elapsed clock may be slow: real elapsed can be age/(1-error).
    // Divide by (1-error), not 1, and round UP on both ends. The freshness
    // deadline uses the maximum possible real age, not just measured age.
    let drift = (u128::from(age) * u128::from(policy.drift_ppm))
        .div_ceil(1_000_000 - u128::from(policy.drift_ppm));
    if u128::from(age) + drift > u128::from(policy.max_age_ms) {
        return Err("UTC sample may exceed its real-age limit".into());
    }
    let age = i64::try_from(age)?;
    let drift = i64::try_from(drift)?;
    let lower = sample
        .utc
        .lower_ms
        .checked_add(age)
        .and_then(|v| v.checked_sub(drift))
        .ok_or("UTC projection overflow")?;
    let upper = sample
        .utc
        .upper_ms
        .checked_add(age)
        .and_then(|v| v.checked_add(drift))
        .ok_or("UTC projection overflow")?;
    Interval::new(lower, upper)
}

/// Conservative two-of-three arithmetic under the conditional assumption that
/// at most ONE configured operator is faulty and each honest input covers UTC.
/// With three inputs, retain the HULL of ALL pair intersections, not the tightest
/// pair. With two inputs, require overlap but keep their UNION hull: either input
/// could be faulty. Neither case authenticates inputs or mints time authority.
pub(crate) fn consensus(
    samples: &[Measurement],
    now_boottime_ms: u64,
    epoch: Epoch,
    policy: Policy,
) -> Result<Interval> {
    epoch.validate()?;
    policy.validate()?;
    if !(2..=3).contains(&samples.len()) {
        return Err("UTC requires two or three independent operators".into());
    }
    let mut projected = Vec::with_capacity(3);
    let mut operators = 0u8;
    for sample in samples {
        let interval = project(*sample, now_boottime_ms, epoch, policy)?;
        let bit = 1 << sample.operator;
        if operators & bit != 0 {
            return Err("duplicate UTC operator".into());
        }
        operators |= bit;
        projected.push(interval);
    }
    let bounds = if projected.len() == 2 {
        projected[0]
            .intersection(projected[1])
            .ok_or("UTC operators disagree")?;
        projected[0].hull(projected[1])
    } else {
        let mut possible: Option<Interval> = None;
        for i in 0..3 {
            for j in i + 1..3 {
                if let Some(overlap) = projected[i].intersection(projected[j]) {
                    possible = Some(possible.map_or(overlap, |v| v.hull(overlap)));
                }
            }
        }
        possible.ok_or("UTC operators disagree")?
    };
    if u64::try_from(bounds.upper_ms - bounds.lower_ms)? > policy.max_width_ms {
        return Err("UTC uncertainty exceeds policy".into());
    }
    Ok(bounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> Epoch {
        Epoch {
            boot_id: [1; 16],
            provider_generation: 1,
            clock_generation: 1,
            policy_digest: [2; 32],
        }
    }
    fn policy() -> Policy {
        Policy {
            max_age_ms: 180_000,
            max_width_ms: 500,
            drift_ppm: 100,
        }
    }
    fn sample(operator: u8, lower: i64, upper: i64) -> Measurement {
        Measurement {
            operator,
            utc: Interval::new(lower, upper).unwrap(),
            observed_boottime_ms: 1_000,
            epoch: epoch(),
        }
    }
    fn bounds(samples: &[Measurement]) -> Result<Interval> {
        consensus(samples, 1_000, epoch(), policy())
    }

    #[test]
    fn validity_requires_entire_interval_and_strict_expiry() {
        let time = Interval::new(1_000, 1_100).unwrap();
        assert!(time.within(1_000, 1_101).unwrap());
        assert!(!time.within(1_001, 2_000).unwrap());
        assert!(!time.within(1_000, 1_100).unwrap());
        assert!(!time.within(0, 1_050).unwrap());
        assert!(time.within(1_000, 1_000).is_err());
        assert!(time.within(-1, 2_000).is_err());
    }
    #[test]
    fn invalid_intervals_refuse() {
        assert!(Interval::new(-1, 1).is_err());
        assert!(Interval::new(2, 1).is_err());
    }
    #[test]
    fn two_sources_keep_hull_not_false_precision() {
        assert_eq!(
            bounds(&[sample(1, 1_000, 1_100), sample(2, 1_050, 1_200)]).unwrap(),
            Interval::new(1_000, 1_200).unwrap()
        );
    }
    #[test]
    fn third_outlier_does_not_move_honest_pair() {
        assert_eq!(
            bounds(&[
                sample(1, 1_000, 1_100),
                sample(2, 1_050, 1_200),
                sample(3, 9_000, 9_100)
            ])
            .unwrap(),
            Interval::new(1_050, 1_100).unwrap()
        );
    }
    #[test]
    fn all_possible_majorities_are_retained() {
        // Taking only the narrowest pair [1190,1200] loses plausible honest
        // majority [1000,1100]. An authenticated liar must not narrow truth away.
        assert_eq!(
            bounds(&[
                sample(1, 1_000, 1_200),
                sample(2, 1_000, 1_100),
                sample(3, 1_190, 1_200)
            ])
            .unwrap(),
            Interval::new(1_000, 1_200).unwrap()
        );
    }
    #[test]
    fn source_order_does_not_choose_a_majority() {
        let samples = [
            sample(1, 1_000, 1_200),
            sample(2, 1_000, 1_100),
            sample(3, 1_190, 1_200),
        ];
        let expected = bounds(&samples).unwrap();
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            assert_eq!(bounds(&order.map(|i| samples[i])).unwrap(), expected);
        }
    }
    #[test]
    fn disagreeing_and_missing_sources_refuse() {
        assert!(bounds(&[]).is_err());
        assert!(bounds(&[sample(1, 1_000, 1_100)]).is_err());
        assert!(bounds(&[sample(1, 1_000, 1_100), sample(2, 2_000, 2_100)]).is_err());
        assert!(bounds(&[
            sample(1, 1_000, 1_100),
            sample(2, 2_000, 2_100),
            sample(3, 3_000, 3_100)
        ])
        .is_err());
        assert!(bounds(&[sample(1, 1_000, 1_100); 4]).is_err());
    }
    #[test]
    fn duplicate_or_unknown_operators_refuse() {
        for id in [0, 1, 4, 255] {
            assert!(bounds(&[sample(1, 1_000, 1_100), sample(id, 1_000, 1_100)]).is_err());
        }
    }
    #[test]
    fn drift_is_rounded_up_and_expands_both_ends() {
        let samples = [sample(1, 1_000, 1_100), sample(2, 1_000, 1_100)];
        assert_eq!(
            consensus(&samples, 1_001, epoch(), policy()).unwrap(),
            Interval::new(1_000, 1_102).unwrap()
        );
        assert_eq!(
            consensus(&samples, 101_000, epoch(), policy()).unwrap(),
            Interval::new(100_989, 101_111).unwrap()
        );
    }
    #[test]
    fn future_or_stale_samples_refuse() {
        let samples = [sample(1, 1_000, 1_100), sample(2, 1_000, 1_100)];
        assert!(consensus(&samples, 999, epoch(), policy()).is_err());
        assert!(consensus(&samples, 181_001, epoch(), policy()).is_err());
        // Raw age at the deadline is unsafe when elapsed time runs slow.
        assert!(consensus(&samples, 181_000, epoch(), policy()).is_err());
        assert!(consensus(&samples, 180_982, epoch(), policy()).is_ok());
        assert!(consensus(&samples, 180_983, epoch(), policy()).is_err());
    }
    #[test]
    fn every_epoch_component_invalidates_old_observations() {
        let samples = [sample(1, 1_000, 1_100), sample(2, 1_000, 1_100)];
        let mut variants = [epoch(); 4];
        variants[0].boot_id[0] = 3;
        variants[1].provider_generation += 1;
        variants[2].clock_generation += 1;
        variants[3].policy_digest[0] = 3;
        for changed in variants {
            assert!(consensus(&samples, 1_000, changed, policy()).is_err());
        }
        let mut uninitialized = epoch();
        uninitialized.provider_generation = 0;
        assert!(consensus(&[], 0, uninitialized, policy()).is_err());
    }
    #[test]
    fn excessive_uncertainty_and_projection_overflow_refuse() {
        assert!(bounds(&[sample(1, 1_000, 1_501), sample(2, 1_000, 1_501)]).is_err());
        assert!(bounds(&[sample(1, 1_000, 1_500), sample(2, 1_000, 1_500)]).is_ok());
        let samples = [sample(1, i64::MAX, i64::MAX), sample(2, i64::MAX, i64::MAX)];
        assert!(consensus(&samples, 1_001, epoch(), policy()).is_err());
        let samples = [sample(1, 1_000, 1_500), sample(2, 1_000, 1_500)];
        assert!(consensus(&samples, 1_001, epoch(), policy()).is_err());
    }
    #[test]
    fn malformed_policy_refuses() {
        let samples = [sample(1, 1_000, 1_100), sample(2, 1_000, 1_100)];
        let variants = [
            Policy {
                max_age_ms: 0,
                ..policy()
            },
            Policy {
                max_age_ms: 3_600_001,
                ..policy()
            },
            Policy {
                max_width_ms: 0,
                ..policy()
            },
            Policy {
                max_width_ms: 1_001,
                ..policy()
            },
            Policy {
                drift_ppm: 0,
                ..policy()
            },
            Policy {
                drift_ppm: 1_001,
                ..policy()
            },
        ];
        for malformed in variants {
            assert!(consensus(&samples, 1_000, epoch(), malformed).is_err());
        }
    }
    #[test]
    fn one_fault_cannot_exclude_truth_when_two_honest_bounds_cover_it() {
        // Exhaustive small interval combinations, each operator chosen faulty.
        // A denial is allowed; an accepted estimate must retain the true instant.
        for truth in 1..=5 {
            for bad_lower in 0..=6 {
                for bad_upper in bad_lower..=6 {
                    for faulty in 0..3 {
                        let mut samples = [
                            sample(1, truth - 1, truth + 1),
                            sample(2, truth, truth + 2),
                            sample(3, truth - 1, truth),
                        ];
                        samples[faulty].utc = Interval::new(bad_lower, bad_upper).unwrap();
                        if let Ok(time) = bounds(&samples) {
                            assert!(time.lower_ms <= truth && time.upper_ms >= truth);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn two_available_sources_retain_truth_with_one_fault() {
        for truth in 1..=5 {
            for bad_lower in 0..=6 {
                for bad_upper in bad_lower..=6 {
                    for faulty in 0..2 {
                        let mut samples =
                            [sample(1, truth - 1, truth + 1), sample(2, truth, truth + 2)];
                        samples[faulty].utc = Interval::new(bad_lower, bad_upper).unwrap();
                        if let Ok(time) = bounds(&samples) {
                            assert!(time.lower_ms <= truth && time.upper_ms >= truth);
                        }
                    }
                }
            }
        }
    }
}
