//! Receiver/keeper composition for the source fixture, NOT a time authority.
//! Shared history is freshly bound in source; runtime approval is still pending.
//! No listener, CLI, serialized capability, Admin assignment or effect wiring.
#![cfg_attr(not(test), allow(dead_code))]
use crate::{
    admin_governance::{HistoryBinding, HistoryReader},
    tpm::Checkpoint,
    utc_bounds::{Interval, Measurement},
    utc_keeper::{Clock, Keeper, Round, Source, State},
    utc_policy::ApprovedPolicy,
    utc_protocol::{ProducerEpoch, ProducerRound, SourceData},
    utc_receiver::{Receiver, DRAIN_LIMIT},
    utc_step_watch::StepWatch,
    Result,
};

// The receiver preserves EVERY queued round. Quorum loss or disagreement in an
// intermediate round must not be hidden by a later, numerically valid round.
struct BatchKeeper {
    producer: ProducerEpoch,
    keeper: Keeper,
    last_capture_ms: Option<u64>,
}

impl BatchKeeper {
    fn new(producer: ProducerEpoch, history_floor_ms: i64, initial: Clock) -> Result<Self> {
        if producer.policy_digest != ApprovedPolicy::fixed()?.digest()
            || producer.source_clock_generation == 0
        {
            return Err("invalid UTC producer mapping".into());
        }
        // The producer's source-clock generation is pinned independently. It
        // must NOT be substituted for Keeper's reviewed acquisition generation.
        // Only the bound composition supplies floors outside test fixtures.
        let mut keeper = Keeper::new(
            producer.boot_id,
            producer.process_generation,
            history_floor_ms,
        )?;
        keeper.reacquire(initial)?;
        Ok(Self {
            producer,
            keeper,
            last_capture_ms: None,
        })
    }

    fn refresh(&mut self, rounds: &[ProducerRound], now: Clock) -> Result<Option<Interval>> {
        let result = self.refresh_inner(rounds, now);
        if result.is_err() {
            self.keeper.fence();
        }
        result
    }

    fn refresh_inner(&mut self, rounds: &[ProducerRound], now: Clock) -> Result<Option<Interval>> {
        if !matches!(self.keeper.state(), State::Acquiring | State::Bounded) {
            return Err("UTC stream requires reviewed reconstruction".into());
        }
        if rounds.len() > DRAIN_LIMIT {
            return Err("UTC stream batch exceeded bound".into());
        }
        for producer in rounds {
            if producer.epoch != self.producer {
                return Err("UTC producer changed during acquisition".into());
            }
            let epoch = self.keeper.epoch();
            let round = Round {
                epoch,
                sequence: producer.sequence,
                captured_boottime_ms: producer.captured_boottime_ms,
                sources: producer.sources.map(|source| match source {
                    SourceData::Unavailable { operator } => Source::Unavailable { operator },
                    SourceData::Measured {
                        operator,
                        sequence,
                        observed_boottime_ms,
                        utc,
                    } => Source::Measured {
                        sequence,
                        // The pinned hook invalidates measurements on leap
                        // ambiguity; the closed frame has no permissive flag.
                        normal_leap: true,
                        sample: Measurement {
                            operator,
                            utc,
                            observed_boottime_ms,
                            epoch,
                        },
                    },
                }),
            };
            // These already receiver-checked coordinates advance the reducer
            // in queue order. They are NOT an independently trusted live clock.
            let captured = Clock {
                boottime_ms: producer.captured_boottime_ms,
                monotonic_ms: producer.captured_monotonic_ms,
                realtime_ms: producer.captured_realtime_ms,
                suspend_generation: now.suspend_generation,
            };
            self.keeper.refresh(&round, captured)?;
            self.last_capture_ms = Some(producer.captured_boottime_ms);
        }
        self.candidate_at(now)
    }

    fn candidate_at(&mut self, now: Clock) -> Result<Option<Interval>> {
        let Some(capture) = self.last_capture_ms else {
            // Still check the initial clock boundary even without a first round.
            // No estimate, wall-clock fallback or reacquisition is manufactured.
            if self.keeper.state() != State::Acquiring {
                return Err("UTC stream has no active acquisition".into());
            }
            self.keeper.check_boundary(now)?;
            return Ok(None);
        };
        let age = now
            .boottime_ms
            .checked_sub(capture)
            .filter(|age| *age <= 999)
            .ok_or("UTC producer heartbeat is missing or future-dated")?;
        if u128::from(age) + (u128::from(age) * 100).div_ceil(999_900) > 1_000 {
            return Err("UTC heartbeat may exceed its real-age deadline".into());
        }
        self.keeper.candidate_at(now).map(Some)
    }
}

pub(crate) struct Stream {
    receiver: Receiver,
    batch: BatchKeeper,
    suspend_generation: u64,
    step_watch: StepWatch,
}

impl Stream {
    // Private numeric assembly. Production-source consumers must use BoundStream
    // and the semantic HistoryReader, never a caller-provided floor.
    fn assemble(
        receiver: Receiver,
        history_floor_ms: i64,
        suspend_generation: u64,
    ) -> Result<Self> {
        // Arm before the initial clock read. A notification/error is a fence,
        // never a request to reset history or silently reacquire the epoch.
        let step_watch = StepWatch::arm()?;
        let batch = BatchKeeper::new(
            receiver.epoch(),
            history_floor_ms,
            Receiver::clock(suspend_generation)?,
        )?;
        Ok(Self {
            receiver,
            batch,
            suspend_generation,
            step_watch,
        })
    }

    pub(crate) fn state(&self) -> State {
        self.batch.keeper.state()
    }

    /// Notify restart, suspend/step, history/policy change or supervisor failure.
    /// There is no automatic recovery path or caller-issued reacquisition token.
    pub(crate) fn invalidate(&mut self) {
        self.batch.keeper.fence();
    }

    pub(crate) fn poll(&mut self) -> Result<Option<Interval>> {
        let result = (|| {
            if !matches!(self.state(), State::Acquiring | State::Bounded) {
                return Err("UTC stream is fenced".into());
            }
            self.step_watch.check()?;
            let rounds = self.receiver.poll()?;
            self.batch
                .refresh(&rounds, Receiver::clock(self.suspend_generation)?)?;
            // A queued change during reduction is a denial, not silent caching.
            self.receiver.recheck_quiet()?;
            let candidate = self
                .batch
                .candidate_at(Receiver::clock(self.suspend_generation)?)?;
            self.step_watch.check()?;
            Ok(candidate)
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }

    // History replay may block. Re-read peer/queue/clock/watch AFTER it rather
    // than returning the candidate sampled before that work.
    fn candidate_after_history(&mut self) -> Result<Option<Interval>> {
        self.receiver.recheck_quiet()?;
        let candidate = self
            .batch
            .candidate_at(Receiver::clock(self.suspend_generation)?)?;
        self.step_watch.check()?;
        Ok(candidate)
    }

    #[cfg(test)]
    pub(crate) fn attach(
        receiver: Receiver,
        history_floor_ms: i64,
        suspend_generation: u64,
    ) -> Result<Self> {
        Self::assemble(receiver, history_floor_ms, suspend_generation)
    }

    #[cfg(test)]
    pub(crate) fn expire_watch_fixture(&mut self) {
        self.step_watch = StepWatch::expired_fixture().unwrap();
    }
}

/// A non-authorizing source composition. Historical floor verification never
/// approves the publisher, certifies its clocks or enables an effect grant.
pub(crate) struct BoundStream {
    stream: Stream,
    history: HistoryBinding,
}

impl BoundStream {
    pub(crate) fn attach<A: Checkpoint>(
        receiver: Receiver,
        reader: &mut HistoryReader<'_, A>,
        suspend_generation: u64,
    ) -> Result<Self> {
        let history = reader.read()?;
        let mut stream = Stream::assemble(receiver, history.floor_ms(), suspend_generation)?;
        history.recheck(reader)?;
        stream.candidate_after_history()?;
        Ok(Self { stream, history })
    }

    pub(crate) fn state(&self) -> State {
        self.stream.state()
    }

    pub(crate) fn invalidate(&mut self) {
        self.stream.invalidate();
    }

    pub(crate) fn poll<A: Checkpoint>(
        &mut self,
        reader: &mut HistoryReader<'_, A>,
    ) -> Result<Option<Interval>> {
        let result = (|| {
            if !matches!(self.state(), State::Acquiring | State::Bounded) {
                return Err("UTC bound stream is fenced".into());
            }
            self.history.recheck(reader)?;
            self.stream.poll()?;
            self.history.recheck(reader)?;
            self.stream.candidate_after_history()
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn epoch() -> ProducerEpoch {
        ProducerEpoch {
            boot_id: [1; 16],
            process_generation: 7,
            source_clock_generation: 17,
            policy_digest: ApprovedPolicy::fixed().unwrap().digest(),
        }
    }
    fn clock(now: u64) -> Clock {
        Clock {
            boottime_ms: now,
            monotonic_ms: now,
            realtime_ms: 1_000_000 + now as i64,
            suspend_generation: 5,
        }
    }
    fn batch(floor: i64) -> BatchKeeper {
        BatchKeeper::new(epoch(), floor, clock(1_000)).unwrap()
    }
    fn round(sequence: u64, now: u64) -> ProducerRound {
        ProducerRound {
            epoch: epoch(),
            sequence,
            captured_boottime_ms: now,
            captured_monotonic_ms: now,
            captured_realtime_ms: clock(now).realtime_ms,
            sources: [1, 2, 3].map(|operator| SourceData::Measured {
                operator,
                sequence,
                observed_boottime_ms: now,
                utc: Interval::new(1_000_000 + now as i64, 1_000_100 + now as i64).unwrap(),
            }),
        }
    }
    #[test]
    fn producer_and_keeper_generations_are_explicitly_distinct() {
        let mut b = batch(0);
        assert_eq!(b.producer.source_clock_generation, 17);
        assert_eq!(b.keeper.epoch().clock_generation, 1);
        assert_eq!(
            b.refresh(&[round(1, 1_001)], clock(1_002))
                .unwrap()
                .unwrap()
                .endpoints(),
            (1_001_001, 1_001_103)
        );
    }
    #[test]
    fn every_queued_round_is_reduced_without_hiding_quorum_loss() {
        for lost_position in 0..3 {
            let mut b = batch(0);
            let mut rounds = [round(1, 1_001), round(2, 1_002), round(3, 1_003)];
            rounds[lost_position].sources[1] = SourceData::Unavailable { operator: 2 };
            rounds[lost_position].sources[2] = SourceData::Unavailable { operator: 3 };
            assert!(b.refresh(&rounds, clock(1_004)).is_err());
            assert_eq!(b.keeper.state(), State::Fenced);
            assert!(b.refresh(&[round(4, 1_005)], clock(1_005)).is_err());
        }
    }
    #[test]
    fn intermediate_disagreement_and_changed_epoch_are_not_overwritten() {
        for variant in 0..5 {
            let mut b = batch(0);
            let mut bad = round(2, 1_002);
            match variant {
                0 => bad.epoch.boot_id[0] = 2,
                1 => bad.epoch.process_generation += 1,
                2 => bad.epoch.source_clock_generation += 1,
                3 => bad.epoch.policy_digest[0] ^= 1,
                4 => {
                    bad.sources[1] = SourceData::Unavailable { operator: 2 };
                    if let SourceData::Measured { utc, .. } = &mut bad.sources[0] {
                        *utc = Interval::new(2_000_000, 2_000_100).unwrap();
                    }
                }
                _ => unreachable!(),
            }
            assert!(b
                .refresh(&[round(1, 1_001), bad, round(3, 1_003)], clock(1_004))
                .is_err());
            assert_eq!(b.keeper.state(), State::Fenced);
        }
    }
    #[test]
    fn quiet_poll_reprojects_samples_instead_of_returning_saved_interval() {
        let mut b = batch(0);
        let first = b
            .refresh(&[round(1, 1_001)], clock(1_001))
            .unwrap()
            .unwrap();
        let later = b.refresh(&[], clock(1_002)).unwrap().unwrap();
        assert_eq!(first.endpoints(), (1_001_001, 1_001_101));
        assert_eq!(later.endpoints(), (1_001_001, 1_001_103));
        assert_ne!(first, later);
    }
    #[test]
    fn absent_initial_round_does_not_create_time_but_clock_failure_fences() {
        let mut b = batch(0);
        assert!(b.refresh(&[], clock(1_001)).unwrap().is_none());
        assert_eq!(b.keeper.state(), State::Acquiring);
        let mut stepped = clock(1_002);
        stepped.realtime_ms += 20;
        assert!(b.refresh(&[], stepped).is_err());
        assert_eq!(b.keeper.state(), State::Fenced);
    }
    #[test]
    fn quiet_poll_requires_current_heartbeat_and_does_not_auto_recover() {
        let mut b = batch(0);
        b.refresh(&[round(1, 1_001)], clock(1_001)).unwrap();
        assert!(b.refresh(&[], clock(2_000)).is_ok());
        assert!(b.refresh(&[], clock(2_001)).is_err());
        assert_eq!(b.keeper.state(), State::Fenced);
        assert!(b.refresh(&[round(2, 2_002)], clock(2_002)).is_err());
    }
    #[test]
    fn stale_missing_operator_is_not_restored_during_quiet_projection() {
        let mut b = batch(0);
        b.refresh(&[round(1, 1_001)], clock(1_001)).unwrap();
        let mut two = round(2, 1_002);
        two.sources[2] = SourceData::Unavailable { operator: 3 };
        if let SourceData::Measured { utc, .. } = &mut two.sources[0] {
            *utc = Interval::new(1_001_002, 1_001_102).unwrap();
        }
        if let SourceData::Measured { utc, .. } = &mut two.sources[1] {
            *utc = Interval::new(1_001_090, 1_001_190).unwrap();
        }
        b.refresh(&[two], clock(1_002)).unwrap();
        assert_eq!(
            b.refresh(&[], clock(1_003)).unwrap().unwrap().endpoints(),
            (1_001_002, 1_001_192)
        );
    }
    #[test]
    fn producer_clock_step_and_final_clock_step_both_fence() {
        for producer_step in [false, true] {
            let mut b = batch(0);
            let mut r = round(1, 1_001);
            let mut now = clock(1_002);
            if producer_step {
                r.captured_realtime_ms += 20;
            } else {
                now.realtime_ms += 20;
            }
            assert!(b.refresh(&[r], now).is_err());
            assert_eq!(b.keeper.state(), State::Fenced);
        }
    }
    #[test]
    fn suspended_or_regressed_clock_refuses_quiet_projection() {
        for variant in 0..3 {
            let mut b = batch(0);
            b.refresh(&[round(1, 1_001)], clock(1_001)).unwrap();
            let mut now = clock(1_002);
            match variant {
                0 => now.suspend_generation += 1,
                1 => now.monotonic_ms = 990,
                2 => now.boottime_ms = 1_000,
                _ => unreachable!(),
            }
            assert!(b.refresh(&[], now).is_err());
        }
    }
    #[test]
    fn history_conflict_preserves_reconciliation_and_never_uses_wall_time() {
        let mut b = batch(2_000_000);
        assert!(b.refresh(&[round(1, 1_001)], clock(1_002)).is_err());
        assert_eq!(b.keeper.state(), State::ReconciliationRequired);
        assert!(b.refresh(&[round(2, 1_003)], clock(1_003)).is_err());
        assert_eq!(b.keeper.state(), State::ReconciliationRequired);
    }
    #[test]
    fn oversized_batch_replay_and_invalid_mapping_refuse() {
        let mut b = batch(0);
        let rounds: Vec<_> = (1..=9).map(|n| round(n, 1_000 + n)).collect();
        assert!(b.refresh(&rounds, clock(1_010)).is_err());
        let mut b = batch(0);
        assert!(b
            .refresh(&[round(1, 1_001), round(1, 1_002)], clock(1_003))
            .is_err());
        let mut bad = epoch();
        bad.source_clock_generation = 0;
        assert!(BatchKeeper::new(bad, 0, clock(1_000)).is_err());
        bad = epoch();
        bad.policy_digest[0] ^= 1;
        assert!(BatchKeeper::new(bad, 0, clock(1_000)).is_err());
        assert!(BatchKeeper::new(epoch(), -1, clock(1_000)).is_err());
    }
}
