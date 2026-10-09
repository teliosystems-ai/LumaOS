//! Non-authorizing UTC lifecycle reducer for a future protected publisher.
//! All round/clock/history inputs are data, NOT authentication or TPM proofs.
//! No live backend, wall-clock reader, IPC, serialization or grant integration.
#![cfg_attr(not(test), allow(dead_code))] // Publisher/clock/history adapters remain pending.
use crate::{
    utc_bounds::{self, Epoch, Interval, Measurement},
    utc_policy::ApprovedPolicy,
    Result,
};

const ROUND_BUDGET_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Uninitialized,
    Acquiring,
    Bounded, // Arithmetic candidate only, never "trusted UTC available".
    Fenced,
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Clock {
    pub(crate) boottime_ms: u64,
    pub(crate) monotonic_ms: u64,
    pub(crate) realtime_ms: i64,
    pub(crate) suspend_generation: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Source {
    Unavailable {
        operator: u8,
    },
    Measured {
        sequence: u64,
        sample: Measurement,
        normal_leap: bool,
    },
}
impl Source {
    fn operator(self) -> u8 {
        match self {
            Self::Unavailable { operator } => operator,
            Self::Measured { sample, .. } => sample.operator,
        }
    }
}

pub(crate) struct Round {
    pub(crate) epoch: Epoch,
    pub(crate) sequence: u64,
    pub(crate) captured_boottime_ms: u64,
    // A complete bounded source inventory, not a caller-selected majority.
    pub(crate) sources: [Source; 3],
}

pub(crate) struct Keeper {
    policy: ApprovedPolicy,
    epoch: Epoch,
    state: State,
    // The future composition root must verify this floor against TPM history.
    floor_ms: i64,
    last_clock: Option<Clock>,
    barrier_ms: u64,
    last_round: u64,
    last_samples: [Option<(u64, Measurement)>; 3],
    current_sources: Option<[Source; 3]>,
    estimate: Option<Interval>,
}

impl Keeper {
    pub(crate) fn new(boot_id: [u8; 16], provider_generation: u64, floor_ms: i64) -> Result<Self> {
        if boot_id == [0; 16] || provider_generation == 0 || floor_ms < 0 {
            return Err("uninitialized UTC lifecycle context".into());
        }
        let policy = ApprovedPolicy::fixed()?;
        let epoch = Epoch {
            boot_id,
            provider_generation,
            clock_generation: 1,
            policy_digest: policy.digest(),
        };
        Ok(Self {
            policy,
            epoch,
            state: State::Uninitialized,
            floor_ms,
            last_clock: None,
            barrier_ms: 0,
            last_round: 0,
            last_samples: [None; 3],
            current_sources: None,
            estimate: None,
        })
    }
    pub(crate) fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub(crate) fn state(&self) -> State {
        self.state
    }

    // Read-only consistency boundary when acquisition has no first sample yet.
    pub(crate) fn check_boundary(&mut self, now: Clock) -> Result<()> {
        let result = self.check_clock(now);
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Explicit arithmetic reacquisition. The future service must separately
    /// enforce the reviewed recovery procedure; this method supplies no consent.
    pub(crate) fn reacquire(&mut self, clock: Clock) -> Result<()> {
        let result = (|| {
            if !matches!(self.state, State::Uninitialized | State::Fenced) {
                return Err("UTC reacquisition requires an initial or fenced state".into());
            }
            validate_clock(clock)?;
            if self.last_clock.is_some_and(|old| {
                clock.boottime_ms < old.boottime_ms || clock.monotonic_ms < old.monotonic_ms
            }) {
                return Err("UTC monotonic regression cannot be rebased".into());
            }
            if self.state == State::Fenced {
                self.epoch.clock_generation = self
                    .epoch
                    .clock_generation
                    .checked_add(1)
                    .ok_or("UTC generation overflow")?;
            }
            self.barrier_ms = clock.boottime_ms;
            self.last_clock = Some(clock);
            self.estimate = None;
            self.current_sources = None;
            self.state = State::Acquiring;
            Ok(())
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Immediate outage/provider failure; no retained estimate is returned.
    pub(crate) fn fence(&mut self) {
        self.estimate = None;
        self.current_sources = None;
        if self.state != State::ReconciliationRequired {
            self.state = State::Fenced;
        }
    }

    pub(crate) fn refresh(&mut self, round: &Round, now: Clock) -> Result<Interval> {
        let result = self
            .refresh_inner(round, now, false)
            .and_then(|candidate| candidate.ok_or_else(|| "UTC round has no quorum".into()));
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Before the first quorum, validated heartbeats may remain Acquiring.
    /// This never supplies a one-source estimate and cannot revive a fence.
    pub(crate) fn acquire_round(&mut self, round: &Round, now: Clock) -> Result<Option<Interval>> {
        let result = if self.state == State::Acquiring {
            self.refresh_inner(round, now, true)
        } else {
            Err("UTC initial acquisition is no longer active".into())
        };
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Re-evaluate current observations at a new boundary, never return the
    /// saved interval. Still arithmetic data, not trusted-clock authority.
    pub(crate) fn candidate_at(&mut self, now: Clock) -> Result<Interval> {
        let result = (|| {
            if self.state != State::Bounded {
                return Err("UTC lifecycle has no current candidate".into());
            }
            self.check_clock(now)?;
            let sources = self.current_sources.ok_or("missing UTC source inventory")?;
            let samples: Vec<_> = sources
                .iter()
                .filter_map(|source| match source {
                    Source::Measured { sample, .. } => Some(*sample),
                    Source::Unavailable { .. } => None,
                })
                .collect();
            let candidate =
                utc_bounds::consensus(&samples, now.boottime_ms, self.epoch, self.policy.bounds())?;
            let (lower, upper) = candidate.endpoints();
            if upper < self.floor_ms {
                self.state = State::ReconciliationRequired;
                return Err("UTC candidate is behind protected history".into());
            }
            let candidate = Interval::new(lower.max(self.floor_ms), upper)?;
            self.last_clock = Some(now);
            self.estimate = Some(candidate);
            Ok(candidate)
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }

    fn refresh_inner(
        &mut self,
        round: &Round,
        now: Clock,
        acquiring: bool,
    ) -> Result<Option<Interval>> {
        if !matches!(self.state, State::Acquiring | State::Bounded) {
            return Err("UTC lifecycle is not acquiring or bounded".into());
        }
        self.check_clock(now)?;
        if round.epoch != self.epoch || round.sequence <= self.last_round {
            return Err("UTC round epoch mismatch or replay".into());
        }
        let acquisition_age = now
            .boottime_ms
            .checked_sub(round.captured_boottime_ms)
            .filter(|v| *v <= ROUND_BUDGET_MS)
            .ok_or("UTC round is future-dated or acquisition timed out")?;
        let acquisition_error = (u128::from(acquisition_age) * 100).div_ceil(999_900);
        if round.captured_boottime_ms < self.last_clock.unwrap().boottime_ms
            || u128::from(acquisition_age) + acquisition_error > u128::from(ROUND_BUDGET_MS)
        {
            return Err(
                "UTC round predates its boundary or may exceed acquisition deadline".into(),
            );
        }
        let mut samples = Vec::with_capacity(3);
        let mut next_samples = self.last_samples;
        for (index, source) in round.sources.iter().enumerate() {
            if usize::from(source.operator()) != index + 1 {
                return Err("UTC round has duplicate, missing or reordered operators".into());
            }
            if let Source::Measured {
                sequence,
                sample,
                normal_leap,
            } = source
            {
                if !normal_leap
                    || *sequence == 0
                    || sample.observed_boottime_ms < self.barrier_ms
                    || sample.observed_boottime_ms > round.captured_boottime_ms
                {
                    return Err(
                        "UTC measurement has invalid leap, sequence or acquisition epoch".into(),
                    );
                }
                if let Some((previous_sequence, previous_sample)) = self.last_samples[index] {
                    if *sequence < previous_sequence
                        || (*sequence == previous_sequence && *sample != previous_sample)
                        || (*sequence > previous_sequence
                            && sample.observed_boottime_ms <= previous_sample.observed_boottime_ms)
                    {
                        return Err(
                            "UTC measurement replay, re-aging or timestamp regression".into()
                        );
                    }
                }
                next_samples[index] = Some((*sequence, *sample));
                samples.push(*sample);
            }
        }
        if acquiring && self.state == State::Acquiring && samples.len() < 2 {
            for sample in &samples {
                utc_bounds::project(*sample, now.boottime_ms, self.epoch, self.policy.bounds())?;
            }
            self.last_samples = next_samples;
            self.current_sources = Some(round.sources);
            self.last_round = round.sequence;
            self.last_clock = Some(now);
            self.estimate = None;
            return Ok(None);
        }
        let interval =
            utc_bounds::consensus(&samples, now.boottime_ms, self.epoch, self.policy.bounds())?;
        let (lower, upper) = interval.endpoints();
        if upper < self.floor_ms {
            self.state = State::ReconciliationRequired;
            return Err("UTC candidate is behind protected history; preserve the fence".into());
        }
        let bounded = Interval::new(lower.max(self.floor_ms), upper)?;
        self.last_samples = next_samples;
        self.current_sources = Some(round.sources);
        self.last_round = round.sequence;
        self.last_clock = Some(now);
        self.estimate = Some(bounded);
        self.state = State::Bounded;
        Ok(Some(bounded))
    }

    // A clock consistency check supplements, but does not replace, protected
    // step/suspend notifications and a qualified total clock-rate envelope.
    fn check_clock(&self, now: Clock) -> Result<()> {
        validate_clock(now)?;
        let old = self.last_clock.ok_or("UTC acquisition has not started")?;
        let boot_delta = now
            .boottime_ms
            .checked_sub(old.boottime_ms)
            .ok_or("UTC boot clock regressed")?;
        let mono_delta = now
            .monotonic_ms
            .checked_sub(old.monotonic_ms)
            .ok_or("UTC monotonic clock regressed")?;
        if now.suspend_generation != old.suspend_generation || boot_delta.abs_diff(mono_delta) > 2 {
            return Err("UTC suspend or inconsistent elapsed clocks".into());
        }
        let real_delta = i128::from(now.realtime_ms) - i128::from(old.realtime_ms);
        let allowed = (u128::from(boot_delta) * 100).div_ceil(999_900) + 2;
        if (real_delta - i128::from(boot_delta)).unsigned_abs() > allowed {
            return Err("UTC wall clock step or rate inconsistency".into());
        }
        Ok(())
    }
}

fn validate_clock(clock: Clock) -> Result<()> {
    if clock.realtime_ms < 0 || clock.boottime_ms < clock.monotonic_ms {
        return Err("invalid UTC clock observation".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(now: u64) -> Clock {
        Clock {
            boottime_ms: now,
            monotonic_ms: now,
            realtime_ms: 1_000_000 + i64::try_from(now).unwrap(),
            suspend_generation: 0,
        }
    }
    fn keeper(floor: i64) -> Keeper {
        let mut keeper = Keeper::new([1; 16], 1, floor).unwrap();
        keeper.reacquire(clock(1_000)).unwrap();
        keeper
    }
    fn round(keeper: &Keeper, sequence: u64, now: u64) -> Round {
        let epoch = keeper.epoch();
        Round {
            epoch,
            sequence,
            captured_boottime_ms: now,
            sources: [1, 2, 3].map(|operator| Source::Measured {
                sequence,
                normal_leap: true,
                sample: Measurement {
                    operator,
                    utc: Interval::new(1_000_000 + now as i64, 1_000_100 + now as i64).unwrap(),
                    observed_boottime_ms: now,
                    epoch,
                },
            }),
        }
    }
    fn measured(source: &mut Source) -> (&mut u64, &mut Measurement, &mut bool) {
        match source {
            Source::Measured {
                sequence,
                sample,
                normal_leap,
            } => (sequence, sample, normal_leap),
            _ => panic!("expected measurement"),
        }
    }

    #[test]
    fn starts_uninitialized_and_never_admits_without_explicit_acquisition() {
        let mut k = Keeper::new([1; 16], 1, 0).unwrap();
        assert_eq!(k.state(), State::Uninitialized);
        assert!(k.refresh(&round(&k, 1, 1_000), clock(1_000)).is_err());
        assert_eq!(k.state(), State::Fenced);
        assert!(k.estimate.is_none());
        assert!(Keeper::new([0; 16], 1, 0).is_err());
        assert!(Keeper::new([1; 16], 0, 0).is_err());
        assert!(Keeper::new([1; 16], 1, -1).is_err());
    }
    #[test]
    fn complete_round_produces_only_a_bounded_arithmetic_candidate() {
        let mut k = keeper(0);
        let r = round(&k, 1, 1_000);
        assert_eq!(
            k.refresh(&r, clock(1_000)).unwrap().endpoints(),
            (1_001_000, 1_001_100)
        );
        assert_eq!(k.state(), State::Bounded);
        assert!(k.refresh(&round(&k, 2, 1_001), clock(1_001)).is_ok());
    }
    #[test]
    fn lost_quorum_fences_immediately_before_sample_age_deadline() {
        let mut k = keeper(0);
        k.refresh(&round(&k, 1, 1_000), clock(1_000)).unwrap();
        let mut r = round(&k, 2, 1_001);
        r.sources[1] = Source::Unavailable { operator: 2 };
        r.sources[2] = Source::Unavailable { operator: 3 };
        assert!(k.refresh(&r, clock(1_001)).is_err());
        assert_eq!(k.state(), State::Fenced);
        assert!(k.estimate.is_none());
        assert!(k.refresh(&round(&k, 3, 1_002), clock(1_002)).is_err());
    }
    #[test]
    fn one_explicitly_unavailable_operator_does_not_destroy_two_source_quorum() {
        let mut k = keeper(0);
        let mut r = round(&k, 1, 1_000);
        r.sources[2] = Source::Unavailable { operator: 3 };
        assert!(k.refresh(&r, clock(1_000)).is_ok());
    }
    #[test]
    fn explicit_provider_failure_discards_estimate_and_never_auto_recovers() {
        let mut k = keeper(0);
        k.refresh(&round(&k, 1, 1_000), clock(1_000)).unwrap();
        k.fence();
        assert!(k.estimate.is_none());
        assert!(k.refresh(&round(&k, 2, 1_001), clock(1_001)).is_err());
        k.reacquire(clock(1_002)).unwrap();
        assert_eq!(k.state(), State::Acquiring);
        assert!(k.refresh(&round(&k, 2, 1_002), clock(1_002)).is_ok());
    }
    #[test]
    fn old_epoch_or_pre_reacquisition_samples_cannot_restore_time() {
        let mut k = keeper(0);
        let old = round(&k, 1, 1_000);
        k.refresh(&old, clock(1_000)).unwrap();
        k.fence();
        k.reacquire(clock(2_000)).unwrap();
        assert_ne!(k.epoch(), old.epoch);
        assert!(k.refresh(&old, clock(2_000)).is_err());
        k.reacquire(clock(2_001)).unwrap();
        let mut stale = round(&k, 2, 2_001);
        measured(&mut stale.sources[0]).1.observed_boottime_ms = 2_000;
        assert!(k.refresh(&stale, clock(2_001)).is_err());
    }
    #[test]
    fn round_or_source_replay_and_reaging_refuse() {
        for modification in 0..4 {
            let mut k = keeper(0);
            k.refresh(&round(&k, 5, 1_000), clock(1_000)).unwrap();
            let mut r = round(&k, 6, 1_001);
            match modification {
                0 => r.sequence = 5,
                1 => *measured(&mut r.sources[0]).0 = 4,
                2 => *measured(&mut r.sources[0]).0 = 5,
                3 => measured(&mut r.sources[0]).1.observed_boottime_ms = 1_000,
                _ => unreachable!(),
            }
            assert!(k.refresh(&r, clock(1_001)).is_err());
            assert!(k.estimate.is_none());
        }
    }
    #[test]
    fn unchanged_measurement_may_project_but_cannot_be_retimestamped() {
        let mut k = keeper(0);
        let initial = round(&k, 1, 1_000);
        k.refresh(&initial, clock(1_000)).unwrap();
        let mut r = round(&k, 2, 1_001);
        r.sources = initial.sources;
        assert_eq!(
            k.refresh(&r, clock(1_001)).unwrap().endpoints(),
            (1_001_000, 1_001_102)
        );
    }
    #[test]
    fn acquisition_timeout_future_and_old_rounds_refuse() {
        for capture in [999, 2_002] {
            let mut k = keeper(0);
            let mut r = round(&k, 1, 1_000);
            r.captured_boottime_ms = capture;
            assert!(k.refresh(&r, clock(1_001)).is_err());
        }
        let mut k = keeper(0);
        assert!(k.refresh(&round(&k, 1, 1_000), clock(2_001)).is_err());
    }
    #[test]
    fn duplicate_unknown_reordered_and_future_sources_refuse() {
        for bad in [0, 1, 4, 255] {
            let mut k = keeper(0);
            let mut r = round(&k, 1, 1_000);
            measured(&mut r.sources[1]).1.operator = bad;
            assert!(k.refresh(&r, clock(1_000)).is_err());
        }
        let mut k = keeper(0);
        let mut r = round(&k, 1, 1_000);
        r.sources.swap(0, 1);
        assert!(k.refresh(&r, clock(1_000)).is_err());
        let mut k = keeper(0);
        let mut r = round(&k, 1, 1_000);
        measured(&mut r.sources[0]).1.observed_boottime_ms = 1_001;
        assert!(k.refresh(&r, clock(1_000)).is_err());
    }
    #[test]
    fn leap_uncertainty_and_source_epoch_changes_fence() {
        for variant in 0..5 {
            let mut k = keeper(0);
            let mut r = round(&k, 1, 1_000);
            let (_, sample, leap) = measured(&mut r.sources[0]);
            match variant {
                0 => *leap = false,
                1 => sample.epoch.boot_id[0] = 2,
                2 => sample.epoch.clock_generation += 1,
                3 => sample.epoch.provider_generation += 1,
                4 => sample.epoch.policy_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(k.refresh(&r, clock(1_000)).is_err());
            assert_eq!(k.state(), State::Fenced);
        }
    }
    #[test]
    fn restart_policy_boot_and_generation_mismatch_fence_round() {
        for variant in 0..4 {
            let mut k = keeper(0);
            let mut r = round(&k, 1, 1_000);
            match variant {
                0 => r.epoch.boot_id[0] = 2,
                1 => r.epoch.provider_generation += 1,
                2 => r.epoch.clock_generation += 1,
                3 => r.epoch.policy_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(k.refresh(&r, clock(1_000)).is_err());
        }
    }
    #[test]
    fn suspend_notifier_and_elapsed_clock_disagreement_fence() {
        for variant in 0..2 {
            let mut k = keeper(0);
            let mut now = clock(1_010);
            if variant == 0 {
                now.suspend_generation = 1;
            } else {
                now.monotonic_ms = 1_001;
            }
            assert!(k.refresh(&round(&k, 1, 1_010), now).is_err());
            assert_eq!(k.state(), State::Fenced);
        }
    }
    #[test]
    fn forward_backward_steps_and_monotonic_regression_refuse() {
        for delta in [-10, 10] {
            let mut k = keeper(0);
            let mut now = clock(1_001);
            now.realtime_ms += delta;
            assert!(k.refresh(&round(&k, 1, 1_001), now).is_err());
        }
        let mut k = keeper(0);
        assert!(k.refresh(&round(&k, 1, 999), clock(999)).is_err());
        assert!(k.reacquire(clock(999)).is_err());
    }
    #[test]
    fn history_rollback_stays_in_reconciliation_and_has_no_reset_path() {
        let mut k = keeper(2_000_000);
        assert!(k.refresh(&round(&k, 1, 1_000), clock(1_000)).is_err());
        assert_eq!(k.state(), State::ReconciliationRequired);
        k.fence();
        assert_eq!(k.state(), State::ReconciliationRequired);
        assert!(k.reacquire(clock(1_001)).is_err());
        assert!(k.estimate.is_none());
    }
    #[test]
    fn protected_floor_can_clip_but_does_not_create_current_time() {
        let mut k = keeper(1_001_050);
        assert_eq!(
            k.refresh(&round(&k, 1, 1_000), clock(1_000))
                .unwrap()
                .endpoints(),
            (1_001_050, 1_001_100)
        );
        k.fence();
        assert!(k.estimate.is_none());
    }
    #[test]
    fn generation_overflow_refuses_without_wrapping_or_cached_estimate() {
        let mut k = keeper(0);
        k.epoch.clock_generation = u64::MAX;
        k.fence();
        assert!(k.reacquire(clock(1_001)).is_err());
        assert_eq!(k.epoch.clock_generation, u64::MAX);
        assert!(k.estimate.is_none());
    }
    #[test]
    fn zero_sequences_and_invalid_clock_observations_refuse() {
        for sequence in [0, 1] {
            let mut k = keeper(0);
            let mut r = round(&k, sequence, 1_000);
            if sequence == 1 {
                *measured(&mut r.sources[0]).0 = 0;
            }
            assert!(k.refresh(&r, clock(1_000)).is_err());
        }
        for now in [
            Clock {
                realtime_ms: -1,
                ..clock(1_000)
            },
            Clock {
                monotonic_ms: 1_001,
                ..clock(1_000)
            },
        ] {
            let mut k = keeper(0);
            assert!(k.refresh(&round(&k, 1, 1_000), now).is_err());
        }
    }
}
