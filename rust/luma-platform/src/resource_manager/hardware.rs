//! Resource admission's side of the separate hardware configuration exclusion.
//! Current TPM obligations and kernel locks fence new work, never grant effects.
use super::*;
use crate::hardware_policy::{
    exclusion::{Held, Locks},
    handoff::{AllocationWindow, Purpose, Reply, Request},
    Adapter, Intent, Phase, State as HardwareState, Worker,
};
use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;

pub(super) struct Gate {
    locks: Option<Locks>,
    blocked: BTreeSet<Worker>,
    active: BTreeMap<Worker, Active>,
}
struct Active {
    intent: Intent,
    exclusion: Held,
    owner: peer::HardwarePeer,
    pin: File,
    stream: UnixStream,
    _idle: Option<File>,
    authority_sha256: String,
    allocation_deadline: Option<u64>,
}
impl Active {
    fn controller_alive(&self) -> Result<bool> {
        Ok(pidfd_alive(&self.pin)? && self.owner.command == peer::HardwareCommand::Console)
    }
    fn deadline_reason(&self, now: u64) -> Option<&'static str> {
        if now >= self.intent.deadline_ms {
            Some("hardware-policy-expired")
        } else if self
            .allocation_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            Some("hardware-original-allocation-window-expired")
        } else {
            None
        }
    }
}

fn outstanding(state: &HardwareState) -> Result<BTreeSet<Worker>> {
    let mut blocked = BTreeSet::new();
    for (transaction, transition) in &state.transactions {
        transition.intent.validate()?;
        if transaction != &transition.intent.transaction
            || transition.revision <= transition.intent.expected_revision
        {
            return Err("resource admission found an invalid hardware obligation".into());
        }
        if matches!(
            transition.phase,
            Phase::Prepared | Phase::Applied | Phase::Fenced
        ) {
            if let Some(worker) = transition.intent.target.worker {
                blocked.insert(worker);
            }
        }
    }
    Ok(blocked)
}
fn worker(kind: Kind) -> Worker {
    match kind {
        Kind::Model => Worker::Model,
        Kind::Acquisition => Worker::Acquisition,
    }
}

impl Gate {
    pub(super) fn open() -> Result<Self> {
        if crate::platform::require_live().is_ok() {
            // Hardware mutation is installed-only. The unenrolled live
            // installer has no hardware-policy session or handoff endpoint.
            return Ok(Self {
                locks: None,
                blocked: BTreeSet::new(),
                active: BTreeMap::new(),
            });
        }
        crate::platform::require_installed()?;
        let locks = Locks::provision()?;
        let state = crate::admin_governance::current_hardware_state()?;
        Ok(Self {
            locks: Some(locks),
            blocked: outstanding(&state)?,
            active: BTreeMap::new(),
        })
    }

    /// Resource Store -> configuration OFD -> Admin/NV is the fixed lock order.
    /// The hardware controller never makes a broker RPC under an Admin lock.
    pub(super) fn admit(&mut self, kind: Kind) -> Result<Option<Held>> {
        let Some(locks) = &self.locks else {
            return Ok(None);
        };
        let held = locks
            .shared(worker(kind))?
            .ok_or("worker hardware configuration is held by its original live controller")?;
        let state = crate::admin_governance::current_hardware_state()?;
        self.blocked = outstanding(&state)?;
        if self.blocked.contains(&worker(kind)) {
            return Err("worker hardware obligation is outstanding; exact Admin reconciliation required before new admission".into());
        }
        held.check()?;
        Ok(Some(held))
    }

    /// Same-worker physical policy obligations retain their exact admitted
    /// allocation even after process drainage. Hold SH across finish_draining:
    /// a controller cannot acquire EX and dispatch between the current TPM
    /// observation and the resource checkpoint commit. No Admin lock survives
    /// the observation, so the checkpoint can perform its own authority read.
    pub(super) fn can_finish_draining(
        &self,
        kind: Kind,
        token: &Token,
    ) -> Result<(bool, Option<Held>)> {
        let Some(locks) = &self.locks else {
            return Ok((true, None));
        };
        let Some(held) = locks.shared(worker(kind))? else {
            return Ok((false, None));
        };
        let state = crate::admin_governance::current_hardware_state()?;
        outstanding(&state)?;
        if retains_token(&state, token) {
            return Ok((false, None));
        }
        held.check()?;
        Ok((true, Some(held)))
    }

    pub(super) fn observe_allocations(&self, ledger: &resources::Ledger) -> Result<()> {
        let now = now()?;
        for active in self.active.values() {
            if let Some(token) = active
                .intent
                .target
                .resource
                .as_ref()
                .and_then(|value| value.lease.as_ref())
            {
                let still_active = ledger.leases.iter().any(|lease| {
                    &lease.token == token && lease.state == State::Active && lease.deadline_ms > now
                });
                if !still_active {
                    // Fences new APPLY but retains EX and charges. Exact
                    // precommitted undo cannot require renewing execution.
                    active.stream.shutdown(std::net::Shutdown::Both)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn observe_authority(&mut self) -> Result<Vec<(Token, &'static str)>> {
        if self.active.is_empty() {
            return Ok(Vec::new());
        }
        let guard = crate::admin_governance::hardware_guard_snapshot();
        if guard.is_err() {
            let mut revoke = Vec::new();
            for active in self.active.values() {
                active.stream.shutdown(std::net::Shutdown::Both)?;
                if let Some(token) = active
                    .intent
                    .target
                    .resource
                    .as_ref()
                    .and_then(|binding| binding.lease.clone())
                {
                    revoke.push((token, "hardware-authority-unavailable"));
                }
            }
            return Ok(revoke);
        }
        let guard = guard?;
        let state = &guard.state;
        self.blocked = outstanding(&state)?;
        let mut completed = Vec::new();
        let mut revoke = Vec::new();
        for (worker, active) in &self.active {
            let transition = state
                .transactions
                .get(&active.intent.transaction)
                .ok_or("retained hardware handoff lost its authenticated obligation")?;
            if transition.intent != active.intent {
                return Err("retained hardware intent changed under its original EX".into());
            }
            active.exclusion.check()?;
            let reason = (|| -> Result<Option<&'static str>> {
                let terminal = matches!(transition.phase, Phase::Restored | Phase::Reconciled);
                if !terminal && !active.controller_alive()? {
                    return Ok(Some("hardware-controller-lost"));
                }
                if !terminal {
                    let credentials = crate::service::credentials(&active.stream)?;
                    if peer::hardware_generation(credentials, &active.pin)? != active.owner {
                        return Ok(Some("hardware-controller-generation-lost"));
                    }
                }
                if !matches!(transition.phase, Phase::Restored | Phase::Reconciled)
                    && (guard.authority_sha256 != active.authority_sha256
                        || guard
                            .finite_deadlines
                            .get(&active.intent.apply_grant)
                            .map_or(true, |deadline| guard.utc_upper_ms >= *deadline)
                        || guard
                            .finite_deadlines
                            .get(&active.intent.restore_grant)
                            .map_or(true, |deadline| guard.utc_upper_ms >= *deadline))
                {
                    return Ok(Some("hardware-finite-authority-changed"));
                }
                let now = now()?;
                if !terminal {
                    if let Some(reason) = active.deadline_reason(now) {
                        return Ok(Some(reason));
                    }
                }
                if transition.phase != Phase::Reconciled
                    && matches!(
                        active.intent.target.adapter,
                        Adapter::CpuQuota | Adapter::CpuWeight | Adapter::StorageRate
                    )
                {
                    let control = crate::hardware_policy::cgroup::Control::open(*worker)?;
                    let binding = active
                        .intent
                        .target
                        .resource
                        .clone()
                        .ok_or("hardware guard resource tuple absent")?;
                    if control.target(active.intent.target.adapter, binding)?
                        != active.intent.target
                    {
                        return Ok(Some("hardware-parent-generation-lost"));
                    }
                    let observed = control.observe(active.intent.target.adapter)?;
                    if !accepts_parent_readback(transition, &observed, now) {
                        return Ok(Some("hardware-parent-enforcement-lost"));
                    }
                }
                Ok(None)
            })()
            .unwrap_or(Some("hardware-parent-observation-unknown"));
            if let Some(reason) = reason {
                active.stream.shutdown(std::net::Shutdown::Both)?;
                if let Some(token) = active
                    .intent
                    .target
                    .resource
                    .as_ref()
                    .and_then(|binding| binding.lease.clone())
                {
                    revoke.push((token, reason));
                }
                continue;
            }
            if matches!(transition.phase, Phase::Restored | Phase::Reconciled) {
                completed.push(*worker);
            }
        }
        // Current TPM terminal state, not process exit or a lost JSON ACK,
        // ends the Manager's reference. Any surviving receiver's same OFD
        // still excludes SH drainage/admission until it really closes.
        for worker in completed {
            self.active.remove(&worker);
        }
        Ok(revoke)
    }
}

fn accepts_parent_readback(
    transition: &crate::hardware_policy::Transition,
    observed: &crate::hardware_policy::Setting,
    now: u64,
) -> bool {
    use crate::hardware_policy::WriteKind;
    match transition.phase {
        Phase::Prepared if transition.dispatches.is_empty() => {
            observed == &transition.intent.before
        }
        Phase::Prepared | Phase::Applied => {
            let Some(dispatch) = transition.dispatches.last() else {
                return false;
            };
            if transition.phase == Phase::Applied && dispatch.kind == WriteKind::Apply {
                observed == &transition.intent.after
            } else {
                now >= dispatch.started_ms
                    && now - dispatch.started_ms <= 1000
                    && (observed == &transition.intent.before
                        || observed == &transition.intent.after)
            }
        }
        Phase::Restored => observed == &transition.intent.before,
        Phase::Reconciled => transition
            .observation
            .as_ref()
            .is_some_and(|value| observed == &value.setting),
        Phase::Fenced => false,
    }
}

fn retains_token(state: &HardwareState, token: &Token) -> bool {
    state.transactions.values().any(|transition| {
        matches!(
            transition.phase,
            Phase::Prepared | Phase::Applied | Phase::Fenced
        ) && transition
            .intent
            .target
            .resource
            .as_ref()
            .and_then(|resource| resource.lease.as_ref())
            == Some(token)
    })
}

fn selected_kind(worker: Worker) -> Kind {
    match worker {
        Worker::Model => Kind::Model,
        Worker::Acquisition => Kind::Acquisition,
    }
}

impl Manager {
    /// The broker owns allocation state throughout this handshake. The request
    /// carries no grant or session; it can only reserve configuration exclusion
    /// for an already current TPM-committed original-PAM obligation.
    pub(crate) fn hardware_handoff(
        &mut self,
        request: &Request,
        stream: &UnixStream,
    ) -> Result<Reply> {
        crate::platform::require_installed()?;
        crate::platform::require_production_activation()?;
        request.validate(now()?)?;
        let credentials = crate::service::credentials(stream)?;
        let pin = crate::service::peer_pidfd(stream)?;
        let actor = peer::hardware_generation(credentials, &pin)?;
        let guard = crate::admin_governance::hardware_guard_snapshot()?;
        let state = &guard.state;
        self.hardware.blocked = outstanding(&state)?;
        let transition = state
            .transactions
            .get(&request.transaction)
            .ok_or("hardware handoff has no current authenticated obligation")?;
        let intent = &transition.intent;
        let worker = intent
            .target
            .worker
            .ok_or("global device cannot borrow worker exclusion")?;
        let kind = selected_kind(worker);
        let group = match kind {
            Kind::Model => &self.group,
            Kind::Acquisition => &self.acquisition,
        };
        let current = Group::for_kind(kind)?;
        let ledger = self.store.read()?;
        let allocation = intent
            .target
            .resource
            .as_ref()
            .and_then(|value| value.lease.as_ref())
            .map(|token| {
                ledger
                    .leases
                    .iter()
                    .find(|lease| &lease.token == token)
                    .map(|lease| AllocationWindow {
                        lease: token.clone(),
                        deadline_ms: lease.deadline_ms,
                    })
                    .ok_or("hardware handoff allocation history is unavailable")
            })
            .transpose()?;
        let reply = Reply::for_intent(request, intent, allocation)?;
        if current.identity()? != group.identity()?
            || group.identity()?.1 != intent.target.generation
            || intent.target.boot != actor.boot
            || intent.target.boot != crate::hardware_policy::current_boot()?
            || intent.target.identity_sha256
                != crate::hardware_policy::handoff::worker_identity(worker)?
            || intent
                .target
                .resource
                .as_ref()
                .ok_or("worker hardware handoff has no resource binding")?
                .manager_epoch
                != ledger.manager_epoch
        {
            return Err(
                "hardware handoff lost its actual cgroup/boot/resource-manager generation".into(),
            );
        }
        match request.action.as_str() {
            "hardware-handoff-open" => {
                let purpose = request.purpose.ok_or("hardware handoff purpose absent")?;
                if now()? < intent.created_ms
                    || now()? > intent.deadline_ms + crate::hardware_policy::CLEANUP_GRACE_MS
                {
                    return Err("hardware handoff activation/cleanup lifetime elapsed".into());
                }
                if purpose == Purpose::CommittedCleanup {
                    if actor.command != peer::HardwareCommand::Cleanup(intent.transaction.clone())
                        || !matches!(transition.phase, Phase::Prepared | Phase::Applied)
                    {
                        return Err("hardware cleanup handoff is not its exact fixed cleanup command/obligation".into());
                    }
                    let active=self.hardware.active.get_mut(&worker).ok_or("Manager restart or absent original handoff; preserve obligation for fresh Admin reconciliation")?;
                    if active.intent != *intent
                        || actor.unit != active.owner.unit
                        || pidfd_alive(&active.pin)?
                    {
                        return Err("hardware cleanup may replace only its deceased original controller in the same fixed unit".into());
                    }
                    active.exclusion.check()?;
                    if crate::admin_governance::current_hardware_state()?
                        .transactions
                        .get(&intent.transaction)
                        != Some(transition)
                    {
                        return Err(
                            "hardware cleanup obligation changed before descriptor delivery".into(),
                        );
                    }
                    active.exclusion.send(stream, &request.binding()?)?;
                    active.owner = actor.clone();
                    active.pin = pin;
                    active.stream = stream.try_clone()?;
                } else {
                    if actor.command != peer::HardwareCommand::Console
                        || transition.phase != Phase::Prepared
                        || now()? > intent.deadline_ms
                        || self.hardware.active.contains_key(&worker)
                    {
                        return Err("hardware apply handoff cannot replay, renew or replace an original live obligation".into());
                    }
                    let binding = intent
                        .target
                        .resource
                        .as_ref()
                        .ok_or("worker resource binding missing")?;
                    let outstanding = ledger
                        .leases
                        .iter()
                        .filter(|lease| {
                            lease.owner.uid
                                == match kind {
                                    Kind::Model => 989,
                                    Kind::Acquisition => 0,
                                }
                                && lease.state != State::Released
                        })
                        .collect::<Vec<_>>();
                    let exact = match (&binding.lease, outstanding.as_slice()) {
                        (None, []) => true,
                        (Some(expected), [lease]) => {
                            expected == &lease.token
                                && lease.state == State::Active
                                && lease.deadline_ms > now()?
                        }
                        _ => false,
                    };
                    if !exact {
                        return Err("hardware handoff changes its exact admitted allocation or drained generation".into());
                    }
                    let drained = matches!(
                        intent.target.adapter,
                        Adapter::MemoryProfile | Adapter::WorkerNetwork
                    );
                    if drained
                        && (binding.lease.is_some()
                            || group.populated()?
                            || self.requests.occupied()
                            || self.gateway.is_some()
                            || self.acquisition_authority.is_some())
                    {
                        return Err("memory/network hardware policy requires complete worker/guardian/request drainage".into());
                    }
                    let exclusion=self.hardware.locks.as_ref().ok_or("hardware handoff is unavailable in live installer")?
                        .exclusive(worker)?.ok_or("hardware configuration is already excluded by admission or an earlier controller")?;
                    let idle = if drained && worker == Worker::Model {
                        Some(model::resource_idle()?)
                    } else {
                        None
                    };
                    if crate::admin_governance::current_hardware_state()?
                        .transactions
                        .get(&intent.transaction)
                        != Some(transition)
                    {
                        return Err("hardware original prepared obligation changed before exclusion delivery".into());
                    }
                    if peer::hardware_generation(credentials, &pin)? != actor
                        || now()? > intent.deadline_ms
                    {
                        return Err(
                            "hardware original controller or bounded preparation changed".into(),
                        );
                    }
                    // Retain before sending. A failed/uncertain descriptor or
                    // reply delivery never unlocks and silently redispatches.
                    self.hardware.active.insert(
                        worker,
                        Active {
                            intent: intent.clone(),
                            exclusion,
                            owner: actor.clone(),
                            pin,
                            stream: stream.try_clone()?,
                            _idle: idle,
                            authority_sha256: guard.authority_sha256.clone(),
                            allocation_deadline: reply
                                .allocation
                                .as_ref()
                                .map(|value| value.deadline_ms),
                        },
                    );
                    self.hardware
                        .active
                        .get(&worker)
                        .ok_or("hardware retained exclusion missing")?
                        .exclusion
                        .send(stream, &request.binding()?)?;
                }
            }
            "hardware-handoff-finish" => {
                if actor.command != peer::HardwareCommand::Console
                    || !matches!(transition.phase, Phase::Restored | Phase::Reconciled)
                {
                    return Err("hardware handoff cannot finish from cleanup, uncertainty or an unobserved outcome".into());
                }
                if let Some(active) = self.hardware.active.get(&worker) {
                    if active.intent != *intent
                        || (active.owner != actor && pidfd_alive(&active.pin)?)
                    {
                        return Err("hardware finish substitutes its original live controller or unresolved intent".into());
                    }
                    active.exclusion.check()?;
                }
                if peer::hardware_generation(credentials, &pin)? != actor {
                    return Err("hardware completion controller changed".into());
                }
                // A receiver's same OFD still excludes new admission until it
                // actually closes. Dropping this reference is not a drainage
                // or resource-release receipt and never changes the ledger.
                self.hardware.active.remove(&worker);
                self.hardware.blocked = outstanding(&state)?;
            }
            _ => return Err("unsupported closed hardware handoff action".into()),
        }
        request.validate(now()?)?;
        if peer::hardware_generation(credentials, &crate::service::peer_pidfd(stream)?)? != actor {
            return Err("hardware controller changed before handoff acknowledgement".into());
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware_policy::{Event, FenceReason, Reconciliation};
    fn prepared() -> HardwareState {
        let mut state = HardwareState::default();
        state
            .apply(&Event::Prepare {
                intent: crate::hardware_policy::tests::intent(),
            })
            .unwrap();
        state
    }
    #[test]
    fn active_parent_guard_accepts_only_exact_phase_or_a_single_bounded_dispatch_window() {
        use crate::hardware_policy::{Dispatch, WriteKind};
        let state = prepared();
        let mut current = state.transactions["cpu-policy-one"].clone();
        assert!(accepts_parent_readback(
            &current,
            &current.intent.before,
            1200
        ));
        assert!(!accepts_parent_readback(
            &current,
            &current.intent.after,
            1200
        ));
        current.dispatches.push(Dispatch {
            kind: WriteKind::Apply,
            witness: None,
            started_ms: 1300,
        });
        for observed in [&current.intent.before, &current.intent.after] {
            assert!(accepts_parent_readback(&current, observed, 1300));
            assert!(accepts_parent_readback(&current, observed, 2300));
            assert!(!accepts_parent_readback(&current, observed, 2301));
            assert!(!accepts_parent_readback(&current, observed, 1299));
        }
        current.phase = Phase::Applied;
        assert!(accepts_parent_readback(
            &current,
            &current.intent.after,
            5000
        ));
        assert!(!accepts_parent_readback(
            &current,
            &current.intent.before,
            5000
        ));
        current.dispatches.push(Dispatch {
            kind: WriteKind::Restore,
            witness: None,
            started_ms: 6000,
        });
        assert!(accepts_parent_readback(
            &current,
            &current.intent.before,
            6500
        ));
        assert!(!accepts_parent_readback(
            &current,
            &current.intent.before,
            7001
        ));
        current.phase = Phase::Restored;
        assert!(accepts_parent_readback(
            &current,
            &current.intent.before,
            8000
        ));
        assert!(!accepts_parent_readback(
            &current,
            &current.intent.after,
            8000
        ));
        current.phase = Phase::Fenced;
        assert!(!accepts_parent_readback(
            &current,
            &current.intent.before,
            8000
        ));
    }
    #[test]
    fn current_prepared_applied_and_fenced_obligations_block_only_the_exact_worker() {
        let mut state = prepared();
        assert_eq!(
            outstanding(&state).unwrap(),
            BTreeSet::from([Worker::Model])
        );
        state
            .apply(&Event::Fenced {
                transaction: "cpu-policy-one".into(),
                expected_revision: 1,
                reason: FenceReason::AuthorizationLost,
            })
            .unwrap();
        assert_eq!(
            outstanding(&state).unwrap(),
            BTreeSet::from([Worker::Model])
        );
        state
            .apply(&Event::Reconciled {
                transaction: "cpu-policy-one".into(),
                expected_revision: 2,
                disposition: Reconciliation::DeviceUnavailable,
                observation: None,
            })
            .unwrap();
        assert!(outstanding(&state).unwrap().is_empty());
    }
    #[test]
    fn malformed_retained_state_is_not_interpreted_as_unblocked_capacity() {
        for variant in 0..3 {
            let mut state = prepared();
            let current = state.transactions.get_mut("cpu-policy-one").unwrap();
            match variant {
                0 => current.revision = 0,
                1 => current.intent.target.resource = None,
                _ => current.intent.transaction = "substituted".into(),
            }
            assert!(outstanding(&state).is_err());
        }
    }

    #[test]
    fn exact_allocation_charges_remain_bound_until_observed_restore_or_explicit_reconciliation() {
        let mut intent = crate::hardware_policy::tests::intent();
        let token = Token {
            lease_id: "ab".repeat(16),
            generation: 4,
            manager_epoch: "56".repeat(16),
        };
        intent.target.resource.as_mut().unwrap().lease = Some(token.clone());
        let mut state = HardwareState::default();
        state.apply(&Event::Prepare { intent }).unwrap();
        assert!(retains_token(&state, &token));
        let mut other = token.clone();
        other.generation += 1;
        assert!(!retains_token(&state, &other));
        state
            .apply(&Event::Fenced {
                transaction: "cpu-policy-one".into(),
                expected_revision: 1,
                reason: FenceReason::ResourceLost,
            })
            .unwrap();
        assert!(retains_token(&state, &token));
        state
            .apply(&Event::Reconciled {
                transaction: "cpu-policy-one".into(),
                expected_revision: 2,
                disposition: Reconciliation::DeviceUnavailable,
                observation: None,
            })
            .unwrap();
        assert!(!retains_token(&state, &token));
    }

    #[test]
    fn actual_revocation_eof_keeps_the_same_kernel_exclusion_until_every_owned_fd_closes() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "luma-hardware-revoke-{}",
            resources::random_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _directory = Directory(path.clone());
        let locks = Locks::for_test(&path).unwrap();
        let exclusion = locks.exclusive(Worker::Model).unwrap().unwrap();
        let (left, mut right) = UnixStream::pair().unwrap();
        exclusion.send(&left, &[9; 32]).unwrap();
        let receiver = locks.receive(&right, Worker::Model, &[9; 32]).unwrap();
        let mut intent = crate::hardware_policy::tests::intent();
        intent.target.resource.as_mut().unwrap().lease = Some(Token {
            lease_id: "ab".repeat(16),
            generation: 4,
            manager_epoch: "56".repeat(16),
        });
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(raw >= 0);
        let pin = unsafe { File::from_raw_fd(raw as i32) };
        let mut active = Active {
            intent,
            exclusion,
            owner: peer::HardwarePeer {
                pid: std::process::id(),
                start: 1,
                boot: "12".repeat(16),
                unit: "transport-fixture".into(),
                command: peer::HardwareCommand::Console,
            },
            pin,
            stream: left,
            _idle: None,
            authority_sha256: "12".repeat(32),
            allocation_deadline: Some(5000),
        };
        assert_eq!(active.deadline_reason(4999), None);
        assert_eq!(
            active.deadline_reason(5000),
            Some("hardware-original-allocation-window-expired")
        );
        assert_eq!(
            active.deadline_reason(active.intent.deadline_ms),
            Some("hardware-policy-expired")
        );
        // A future heartbeat is not stored in this original handoff: the
        // actual production predicate retains its first absolute deadline.
        assert_eq!(
            active.deadline_reason(9000),
            Some("hardware-original-allocation-window-expired")
        );
        assert!(active.controller_alive().unwrap());
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.0.id(), 0) };
        assert!(fd >= 0);
        active.pin = unsafe { File::from_raw_fd(fd as i32) };
        active.owner.pid = child.0.id();
        assert!(active.controller_alive().unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!active.controller_alive().unwrap());
        let gate = Gate {
            locks: None,
            blocked: BTreeSet::new(),
            active: BTreeMap::from([(Worker::Model, active)]),
        };
        gate.observe_allocations(&resources::Ledger::fresh_for_test())
            .unwrap();
        right
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(right.read(&mut byte).unwrap(), 0);
        assert!(locks.shared(Worker::Model).unwrap().is_none());
        receiver.check().unwrap();
        drop(gate);
        assert!(locks.shared(Worker::Model).unwrap().is_none());
        drop(receiver);
        assert!(locks.shared(Worker::Model).unwrap().is_some());
    }
}
