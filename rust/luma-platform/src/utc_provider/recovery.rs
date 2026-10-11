//! Target-bound recovery delivery. The keeper never receives this authority,
//! target paths, TPM credentials or the original Admin recovery secret.
use super::*;
use crate::admin_governance::TargetAuthority;

pub(crate) struct RecoveryClient<'authority, 'target, 'credential> {
    authority: &'authority TargetAuthority<'target, 'credential>,
    client: Client,
}
impl<'authority, 'target, 'credential> RecoveryClient<'authority, 'target, 'credential> {
    pub(crate) fn new(
        authority: &'authority TargetAuthority<'target, 'credential>,
    ) -> Result<Self> {
        authority.target().image().recheck()?;
        let client = authority.observe_history(authority.history_binding(), Client::recovery)?;
        Ok(Self { authority, client })
    }
    pub(crate) fn current(&mut self) -> Result<Observation> {
        let result = (|| {
            let binding = self.authority.history_binding();
            let observation = self
                .authority
                .observe_history(binding, || self.client.current(binding))?;
            // The observer's final semantic TPM/catalog reads are potentially
            // blocking. Reproject the ORIGINAL query only after those reads,
            // and check the original fixed repair deadline at this same point.
            self.client
                .project_after_checks(binding, &observation, |clock| {
                    self.authority.check_projection(clock)
                })
        })();
        if result.is_err() {
            self.client.fenced = true;
            self.client.sample = None;
        }
        result
    }
    pub(crate) fn project_after_checks(&mut self, previous: &Observation) -> Result<Observation> {
        let result = (|| {
            let binding = self.authority.history_binding();
            let observation = self
                .authority
                .observe_history(binding, || self.client.recheck(binding, previous))?;
            self.client
                .project_after_checks(binding, &observation, |clock| {
                    self.authority.check_projection(clock)
                })
        })();
        if result.is_err() {
            self.client.fenced = true;
            self.client.sample = None;
        }
        result
    }
}

pub(crate) fn recovery_seed_proposal(
    authority: &TargetAuthority<'_, '_>,
    seed: &Seed,
) -> Result<serde_json::Value> {
    authority.observe_history(authority.history_binding(), || {
        seed_proposal_release(&Release::recovery()?, authority.history_binding(), seed)
    })
}
pub(crate) fn recovery_deliver_seed(
    authority: &TargetAuthority<'_, '_>,
    seed: &Seed,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    authority.observe_history(authority.history_binding(), || {
        seed_transport_release(
            &Release::recovery()?,
            authority.history_binding(),
            seed,
            instance,
            reviewed,
        )
    })
}
pub(crate) fn recovery_reacquire_proposal(
    authority: &TargetAuthority<'_, '_>,
) -> Result<serde_json::Value> {
    authority.observe_history(authority.history_binding(), || {
        let release = Release::recovery()?;
        let reply = control_inspect_release(&release)?;
        Ok(
            serde_json::json!({"schema_version":1,"kind":"explicit-fixed-utc-supervisor-restart",
            "instance":reply.instance,"state":reply.result,
            "reviewed_sha256":restart_review(authority.history_binding(),&reply)?,
            "new_independent_seed_required":true,"timed_authority":false}),
        )
    })
}
pub(crate) fn recovery_reacquire(
    authority: &TargetAuthority<'_, '_>,
    instance: &str,
    reviewed: &str,
) -> Result<()> {
    authority.observe_history(authority.history_binding(), || {
        restart_fixed_release(
            &Release::recovery()?,
            authority.history_binding(),
            instance,
            reviewed,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utc_keeper::{Clock, Keeper, Round, Source, State};
    fn clock(now: u64) -> Clock {
        Clock {
            boottime_ms: now,
            monotonic_ms: now,
            realtime_ms: 1_000_000 + now as i64,
            suspend_generation: 0,
        }
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
                sample: crate::utc_bounds::Measurement {
                    operator,
                    utc: Interval::new(1_000_000 + now as i64, 1_000_100 + now as i64).unwrap(),
                    observed_boottime_ms: now,
                    epoch,
                },
            }),
        }
    }
    #[test]
    fn recovery_uses_current_quorum_not_seed_one_operator_or_cached_estimate() {
        let seed = Seed {
            schema_version: 1,
            earliest_ms: 1_000_000,
            latest_ms: 1_000_200,
            independent_source: "reviewed-independent-clock".into(),
            review_reference: "operator-review-1".into(),
        };
        seed.validate(1_000_000).unwrap();
        let mut keeper = Keeper::new([1; 16], 1, 1_000_000).unwrap();
        assert!(keeper.candidate_at(clock(1000)).is_err());
        keeper.reacquire(clock(1000)).unwrap();
        let mut one = round(&keeper, 1, 1000);
        one.sources[1] = Source::Unavailable { operator: 2 };
        one.sources[2] = Source::Unavailable { operator: 3 };
        assert!(keeper.acquire_round(&one, clock(1000)).unwrap().is_none());
        assert_eq!(keeper.state(), State::Acquiring);
        let mut two = round(&keeper, 2, 1001);
        two.sources[2] = Source::Unavailable { operator: 3 };
        let interval = keeper.acquire_round(&two, clock(1001)).unwrap().unwrap();
        assert!(interval.endpoints().0 >= 1_000_000);
        assert_eq!(keeper.state(), State::Bounded);
        let mut loss = round(&keeper, 3, 1002);
        loss.sources[1] = Source::Unavailable { operator: 2 };
        loss.sources[2] = Source::Unavailable { operator: 3 };
        assert!(keeper.refresh(&loss, clock(1002)).is_err());
        assert_eq!(keeper.state(), State::Fenced);
        assert!(keeper.candidate_at(clock(1003)).is_err());
        assert!(keeper
            .refresh(&round(&keeper, 4, 1003), clock(1003))
            .is_err());
    }
    #[test]
    fn recovery_refuses_protected_floor_leap_and_source_generation_replay() {
        for variant in 0..3 {
            let mut keeper =
                Keeper::new([1; 16], 1, if variant == 0 { 2_000_000 } else { 0 }).unwrap();
            keeper.reacquire(clock(1000)).unwrap();
            let mut observation = round(&keeper, 1, 1000);
            if variant == 1 {
                if let Source::Measured { normal_leap, .. } = &mut observation.sources[0] {
                    *normal_leap = false;
                }
            } else if variant == 2 {
                observation.epoch.provider_generation += 1;
            }
            assert!(keeper.acquire_round(&observation, clock(1000)).is_err());
            assert_eq!(
                keeper.state(),
                if variant == 0 {
                    State::ReconciliationRequired
                } else {
                    State::Fenced
                }
            );
        }
    }
}
