//! Native installed-root inference slot accounting within an existing worker
//! peak. No new listener, additional physical RAM charge or caller release of
//! the serving lease. Other inference consumers still need gateway integration.
use super::*;
mod journal;
pub(crate) use journal::initialize;
pub(crate) use journal::request_migration;

const MAX_RECEIPTS: usize = 256;
const MAX_OUTPUT: u64 = 128;
const MAX_REQUEST_MS: u64 = 1_800_000;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    #[serde(with = "resources::decimal")]
    pub deadline: u64,
    pub action: String,
    pub payload: Message,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Message {
    Inspect {},
    Begin {
        nonce: String,
        worker: Token,
        profile: String,
        #[serde(with = "resources::decimal")]
        max_output_tokens: u64,
        #[serde(with = "resources::decimal")]
        request_deadline: u64,
    },
    Admit {
        nonce: String,
        worker: Token,
        #[serde(with = "resources::decimal")]
        prompt_tokens: u64,
        token_digest: String,
    },
    Finish {
        nonce: String,
        worker: Token,
        #[serde(with = "resources::decimal")]
        prompt_tokens: u64,
        #[serde(with = "resources::decimal")]
        output_tokens: u64,
        result_digest: String,
    },
    Cancel {
        nonce: String,
        worker: Token,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Caller {
    pid: u32,
    #[serde(with = "resources::decimal")]
    start: u64,
    boot: String,
}
impl Caller {
    fn observe(peer: libc::ucred, pin: &File) -> Result<Self> {
        if peer.uid != 0 || peer.pid <= 0 || !pidfd_alive(pin)? {
            return Err("inference maintenance requires a live installed-root peer".into());
        }
        let path = format!("/proc/{}/stat", peer.pid);
        let start = start_ticks(&safe_text(Path::new(&path), 4096)?)?;
        let boot = boot_identity()?;
        if !pidfd_alive(pin)? || start_ticks(&safe_text(Path::new(&path), 4096)?)? != start {
            return Err("inference caller generation changed".into());
        }
        Ok(Self {
            pid: peer.pid as u32,
            start,
            boot,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Preparing,
    Admitted,
    Completed,
    Draining,
    Released,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    caller: Caller,
    #[serde(skip)]
    pin: Option<File>,
    nonce: String,
    worker: Token,
    profile: String,
    #[serde(with = "resources::decimal")]
    limit: u64,
    #[serde(with = "resources::decimal")]
    context: u64,
    #[serde(with = "resources::decimal")]
    until: u64,
    phase: Phase,
    #[serde(with = "journal::optional_decimal")]
    prompt: Option<u64>,
    token_digest: Option<String>,
    #[serde(with = "journal::optional_decimal")]
    output: Option<u64>,
    result_digest: Option<String>,
}
impl Record {
    fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"kind":"permit", "nonce":self.nonce, "worker":self.worker,
            "phase":self.phase, "profile":self.profile,
            "max_output_tokens":self.limit.to_string(), "context_tokens":self.context.to_string(),
            "request_deadline":self.until.to_string(),
            "prompt_tokens":self.prompt.map(|v|v.to_string()), "token_digest":self.token_digest,
            "output_tokens":self.output.map(|v|v.to_string()), "result_digest":self.result_digest,
            "slot_released":matches!(self.phase,Phase::Completed|Phase::Released),
            "worker_resources_released":false})
    }
}

pub(super) struct Gate {
    records: Vec<Record>,
    retention: journal::Retention,
}
impl Gate {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self {
            records: Vec::new(),
            retention: journal::Retention::default(),
        }
    }
    pub(super) fn occupied(&self) -> bool {
        self.retention.poisoned
            || self.records.iter().any(|r| {
                matches!(
                    r.phase,
                    Phase::Preparing | Phase::Admitted | Phase::Draining
                )
            })
    }
    fn begin(
        &mut self,
        caller: Caller,
        pin: File,
        message: &Message,
        context: u64,
        time: u64,
    ) -> Result<serde_json::Value> {
        let Message::Begin {
            nonce,
            worker,
            profile,
            max_output_tokens,
            request_deadline,
        } = message
        else {
            return Err("invalid inference begin shape".into());
        };
        self.retention.check()?;
        if !nonce_valid(nonce)
            || *max_output_tokens == 0
            || *max_output_tokens > MAX_OUTPUT
            || *max_output_tokens >= context
            || *request_deadline <= time
            || *request_deadline - time > MAX_REQUEST_MS
        {
            return Err("inference request budget or identity denied".into());
        }
        if let Some(prior) = self.records.iter().find(|record| &record.nonce == nonce) {
            if prior.caller != caller
                || &prior.worker != worker
                || &prior.profile != profile
                || prior.limit != *max_output_tokens
                || prior.until != *request_deadline
                || prior.context != context
                || !matches!(prior.phase, Phase::Preparing | Phase::Admitted)
            {
                return Err("inference replay differs or belongs to a completed generation".into());
            }
            return Ok(prior.receipt());
        }
        if self.occupied()
            || self.records.len() >= MAX_RECEIPTS
            || self.retention.retired.contains(nonce)
        {
            return Err("inference slot or retained request inventory exhausted".into());
        }
        let record = Record {
            caller,
            pin: Some(pin),
            nonce: nonce.clone(),
            worker: worker.clone(),
            profile: profile.clone(),
            limit: *max_output_tokens,
            context,
            until: *request_deadline,
            phase: Phase::Preparing,
            prompt: None,
            token_digest: None,
            output: None,
            result_digest: None,
        };
        let receipt = record.receipt();
        self.records.push(record);
        Ok(receipt)
    }
    fn record(&mut self, caller: &Caller, nonce: &str, worker: &Token) -> Result<&mut Record> {
        self.retention.check()?;
        if !nonce_valid(nonce) {
            return Err("invalid inference request identity".into());
        }
        self.records
            .iter_mut()
            .find(|record| {
                &record.caller == caller && record.nonce == nonce && &record.worker == worker
            })
            .ok_or_else(|| "unknown, stale or foreign inference generation".into())
    }
    fn admit(
        &mut self,
        caller: &Caller,
        message: &Message,
        time: u64,
    ) -> Result<serde_json::Value> {
        let Message::Admit {
            nonce,
            worker,
            prompt_tokens,
            token_digest,
        } = message
        else {
            return Err("invalid inference admission shape".into());
        };
        let record = self.record(caller, nonce, worker)?;
        if time >= record.until
            || *prompt_tokens == 0
            || !digest_valid(token_digest)
            || prompt_tokens
                .checked_add(record.limit)
                .map_or(true, |sum| sum > record.context)
        {
            return Err(
                "rendered prompt and maximum output do not fit the reserved context".into(),
            );
        }
        if record.phase == Phase::Admitted {
            if record.prompt == Some(*prompt_tokens)
                && record.token_digest.as_ref() == Some(token_digest)
            {
                return Ok(record.receipt());
            }
            return Err("inference admission replay differs".into());
        }
        if record.phase != Phase::Preparing {
            return Err("inference generation is fenced or completed".into());
        }
        record.prompt = Some(*prompt_tokens);
        record.token_digest = Some(token_digest.clone());
        record.phase = Phase::Admitted;
        Ok(record.receipt())
    }
    fn finish(
        &mut self,
        caller: &Caller,
        message: &Message,
        time: u64,
    ) -> Result<serde_json::Value> {
        let Message::Finish {
            nonce,
            worker,
            prompt_tokens,
            output_tokens,
            result_digest,
        } = message
        else {
            return Err("invalid inference finish shape".into());
        };
        let record = self.record(caller, nonce, worker)?;
        if time >= record.until
            || record.prompt != Some(*prompt_tokens)
            || *output_tokens == 0
            || *output_tokens > record.limit
            || !digest_valid(result_digest)
        {
            return Err("inference completion does not match the accepted budget".into());
        }
        if record.phase == Phase::Completed {
            if record.output == Some(*output_tokens)
                && record.result_digest.as_ref() == Some(result_digest)
            {
                return Ok(record.receipt());
            }
            return Err("inference completion replay differs".into());
        }
        if record.phase != Phase::Admitted {
            return Err("inference generation is not admitted".into());
        }
        record.output = Some(*output_tokens);
        record.result_digest = Some(result_digest.clone());
        record.phase = Phase::Completed;
        record.pin = None;
        Ok(record.receipt())
    }
    fn cancel(
        &mut self,
        caller: &Caller,
        nonce: &str,
        worker: &Token,
    ) -> Result<serde_json::Value> {
        let record = self.record(caller, nonce, worker)?;
        if matches!(record.phase, Phase::Preparing | Phase::Admitted) {
            record.phase = Phase::Draining;
        }
        Ok(record.receipt())
    }
    pub(super) fn maintain(&mut self, ledger: &resources::Ledger, time: u64) -> Result<Vec<Token>> {
        self.maintain_with(ledger, time, pidfd_alive)
    }
    fn maintain_with(
        &mut self,
        ledger: &resources::Ledger,
        time: u64,
        alive: impl Fn(&File) -> Result<bool>,
    ) -> Result<Vec<Token>> {
        self.retention.check()?;
        let mut cancellations = Vec::new();
        for record in &mut self.records {
            if matches!(record.phase, Phase::Completed | Phase::Released) {
                continue;
            }
            let lease = ledger
                .leases
                .iter()
                .find(|l| l.token == record.worker)
                .ok_or("outstanding inference allocation receipt unavailable")?;
            if lease.state == State::Released {
                record.phase = Phase::Released;
                record.pin = None;
                continue;
            }
            if time >= record.until
                || lease.state != State::Active
                || lease.deadline_ms <= time
                || match &record.pin {
                    Some(pin) => !alive(pin)?,
                    None => true,
                }
            {
                record.phase = Phase::Draining;
            }
            if record.phase == Phase::Draining && lease.state == State::Active {
                cancellations.push(record.worker.clone());
            }
        }
        Ok(cancellations)
    }
}

fn nonce_valid(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate(request: &Request, uid: u32, time: u64) -> Result<()> {
    if uid != 0
        || request.caller != uid
        || request.schema_version != 1
        || request.action != "resource-inference"
        || request.request_id.is_empty()
        || request.request_id.len() > 64
        || !request
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || request.deadline <= time
        || request.deadline - time > 5000
    {
        return Err("inference resource envelope or peer denied".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> (Gate, resources::Ledger, Token, Caller) {
        let mut ledger = resources::Ledger::fresh_for_test();
        ledger
            .restart(
                "a".repeat(32),
                BTreeMap::from([(
                    "host".into(),
                    resources::Domain::new(10000, 100, 9000, 8000).unwrap(),
                )]),
            )
            .unwrap();
        let worker = ledger
            .admit(
                Owner {
                    uid: 989,
                    pid: 1,
                    start_ticks: 1,
                    boot: "boot-one".into(),
                    cgroup_device: 1,
                    cgroup_inode: 1,
                },
                "worker".into(),
                "a".repeat(64),
                vec![resources::Reservation {
                    domain: "host".into(),
                    loading: 5000,
                    serving: 4000,
                }],
                1,
                10000,
            )
            .unwrap();
        (
            Gate::new(),
            ledger,
            worker,
            Caller {
                pid: 2,
                start: 3,
                boot: "boot-one".into(),
            },
        )
    }
    pub(super) fn begin(worker: &Token, nonce: u64) -> Message {
        Message::Begin {
            nonce: format!("{nonce:032x}"),
            worker: worker.clone(),
            profile: "fixture".into(),
            max_output_tokens: 128,
            request_deadline: 9000,
        }
    }
    pub(super) fn reserve(
        gate: &mut Gate,
        caller: &Caller,
        message: &Message,
    ) -> Result<serde_json::Value> {
        gate.begin(caller.clone(), File::open("/dev/null")?, message, 2048, 2)
    }
    pub(super) fn admit(worker: &Token, nonce: u64, prompt: u64) -> Message {
        Message::Admit {
            nonce: format!("{nonce:032x}"),
            worker: worker.clone(),
            prompt_tokens: prompt,
            token_digest: "b".repeat(64),
        }
    }
    pub(super) fn finish(worker: &Token, nonce: u64, prompt: u64, output: u64) -> Message {
        Message::Finish {
            nonce: format!("{nonce:032x}"),
            worker: worker.clone(),
            prompt_tokens: prompt,
            output_tokens: output,
            result_digest: "c".repeat(64),
        }
    }
    #[test]
    fn preparing_slot_is_atomic_and_exact_replay_does_not_allocate_twice() {
        let (mut gate, ledger, worker, caller) = fixture();
        let first = reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        assert_eq!(
            reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap(),
            first
        );
        assert!(reserve(&mut gate, &caller, &begin(&worker, 2)).is_err());
        let mut foreign = caller.clone();
        foreign.start += 1;
        assert!(reserve(&mut gate, &foreign, &begin(&worker, 1)).is_err());
        let mut different = begin(&worker, 1);
        if let Message::Begin {
            max_output_tokens, ..
        } = &mut different
        {
            *max_output_tokens = 127;
        }
        assert!(reserve(&mut gate, &caller, &different).is_err());
        assert_eq!(gate.records.len(), 1);
        assert_eq!(ledger.charged("host").unwrap(), 5000);
    }
    #[test]
    fn invalid_budgets_and_nonce_leave_inventory_unchanged() {
        let (mut gate, _, worker, caller) = fixture();
        for (limit, until, nonce) in [
            (0, 9000, "a".repeat(32)),
            (129, 9000, "a".repeat(32)),
            (128, 2, "a".repeat(32)),
            (128, MAX_REQUEST_MS + 3, "a".repeat(32)),
            (128, 9000, "A".repeat(32)),
            (128, 9000, "a".repeat(31)),
        ] {
            let request = Message::Begin {
                nonce,
                worker: worker.clone(),
                profile: "fixture".into(),
                max_output_tokens: limit,
                request_deadline: until,
            };
            assert!(reserve(&mut gate, &caller, &request).is_err());
            assert!(gate.records.is_empty());
        }
    }
    #[test]
    fn exact_context_edge_is_accepted_but_overflow_and_token_drift_are_denied() {
        let (mut gate, _, worker, caller) = fixture();
        reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        for count in [0, 1921, u64::MAX] {
            assert!(gate.admit(&caller, &admit(&worker, 1, count), 3).is_err());
        }
        let receipt = gate.admit(&caller, &admit(&worker, 1, 1920), 3).unwrap();
        assert_eq!(
            gate.admit(&caller, &admit(&worker, 1, 1920), 4).unwrap(),
            receipt
        );
        assert!(gate.admit(&caller, &admit(&worker, 1, 1919), 4).is_err());
        let mut drift = admit(&worker, 1, 1920);
        if let Message::Admit { token_digest, .. } = &mut drift {
            *token_digest = "d".repeat(64);
        }
        assert!(gate.admit(&caller, &drift, 4).is_err());
        assert!(gate.admit(&caller, &admit(&worker, 1, 1920), 9000).is_err());
    }
    #[test]
    fn successful_completion_releases_only_logical_slot_and_preserves_receipt() {
        let (mut gate, ledger, worker, caller) = fixture();
        reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        assert!(gate.finish(&caller, &finish(&worker, 1, 10, 1), 3).is_err());
        gate.admit(&caller, &admit(&worker, 1, 10), 3).unwrap();
        for (prompt, output) in [(11, 1), (10, 0), (10, 129)] {
            assert!(gate
                .finish(&caller, &finish(&worker, 1, prompt, output), 4)
                .is_err());
        }
        let done = gate
            .finish(&caller, &finish(&worker, 1, 10, 128), 4)
            .unwrap();
        assert_eq!(done["slot_released"], true);
        assert_eq!(done["worker_resources_released"], false);
        assert_eq!(
            gate.finish(&caller, &finish(&worker, 1, 10, 128), 5)
                .unwrap(),
            done
        );
        assert!(gate
            .finish(&caller, &finish(&worker, 1, 10, 127), 5)
            .is_err());
        assert!(reserve(&mut gate, &caller, &begin(&worker, 1)).is_err());
        assert_eq!(
            gate.cancel(&caller, &format!("{:032x}", 1), &worker)
                .unwrap(),
            done
        );
        reserve(&mut gate, &caller, &begin(&worker, 2)).unwrap();
        assert_eq!(ledger.charged("host").unwrap(), 5000);
    }
    #[test]
    fn cancellation_holds_slot_and_bytes_until_trusted_physical_observation() {
        let (mut gate, mut ledger, worker, caller) = fixture();
        reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        let receipt = gate
            .cancel(&caller, &format!("{:032x}", 1), &worker)
            .unwrap();
        assert_eq!(receipt["phase"], "draining");
        assert_eq!(receipt["slot_released"], false);
        assert_eq!(
            gate.maintain_with(&ledger, 3, |_| Ok(true)).unwrap(),
            vec![worker.clone()]
        );
        ledger.revoke(&worker, "request-cancelled").unwrap();
        assert!(gate
            .maintain_with(&ledger, 4, |_| Ok(true))
            .unwrap()
            .is_empty());
        assert!(gate.occupied());
        assert_eq!(ledger.charged("host").unwrap(), 5000);
        assert!(gate.finish(&caller, &finish(&worker, 1, 10, 1), 4).is_err());
        ledger
            .finish_draining(&worker, &BTreeMap::from([("host".into(), 25)]))
            .unwrap();
        gate.maintain_with(&ledger, 5, |_| Ok(true)).unwrap();
        assert!(!gate.occupied());
        assert_eq!(gate.records[0].phase, Phase::Released);
        assert_eq!(ledger.charged("host").unwrap(), 25);
    }
    #[test]
    fn owner_death_deadlines_and_physical_restart_fence_without_early_reuse() {
        for cause in 0..4 {
            let (mut gate, mut ledger, worker, caller) = fixture();
            reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
            let time = if cause == 0 { 9000 } else { 3 };
            if cause == 2 {
                ledger.leases[0].deadline_ms = 3;
            }
            if cause == 3 {
                ledger
                    .restart("d".repeat(32), ledger.domains.clone())
                    .unwrap();
            }
            let cancelled = gate
                .maintain_with(&ledger, time, |_| Ok(cause != 1))
                .unwrap();
            assert_eq!(gate.records[0].phase, Phase::Draining);
            assert_eq!(cancelled.len(), usize::from(cause != 3));
            assert!(gate.occupied());
            assert_eq!(ledger.charged("host").unwrap(), 5000);
        }
    }
    #[test]
    fn lost_physical_receipt_or_failed_liveness_observation_cannot_free_capacity() {
        let (mut gate, mut ledger, worker, caller) = fixture();
        reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        assert!(gate
            .maintain_with(&ledger, 3, |_| Err("uncertain caller".into()))
            .is_err());
        ledger.leases.clear();
        assert!(gate.maintain_with(&ledger, 3, |_| Ok(true)).is_err());
        assert!(gate.occupied());
    }
    #[test]
    fn finite_receipt_history_refuses_instead_of_reusing_old_nonces() {
        let (mut gate, _, worker, caller) = fixture();
        for nonce in 1..=MAX_RECEIPTS as u64 {
            reserve(&mut gate, &caller, &begin(&worker, nonce)).unwrap();
            gate.admit(&caller, &admit(&worker, nonce, 10), 3).unwrap();
            gate.finish(&caller, &finish(&worker, nonce, 10, 1), 4)
                .unwrap();
        }
        assert!(!gate.occupied());
        assert!(reserve(&mut gate, &caller, &begin(&worker, MAX_RECEIPTS as u64 + 1)).is_err());
        assert_eq!(gate.records.len(), MAX_RECEIPTS);
    }
    #[test]
    fn stale_worker_and_foreign_owner_cannot_admit_complete_or_cancel() {
        let (mut gate, _, worker, caller) = fixture();
        reserve(&mut gate, &caller, &begin(&worker, 1)).unwrap();
        let mut stale = worker.clone();
        stale.generation += 1;
        let mut foreign = caller.clone();
        foreign.boot = "boot-two".into();
        assert!(gate.admit(&caller, &admit(&stale, 1, 10), 3).is_err());
        assert!(gate.admit(&foreign, &admit(&worker, 1, 10), 3).is_err());
        assert!(gate
            .cancel(&caller, &format!("{:032x}", 1), &stale)
            .is_err());
        assert!(gate
            .cancel(&foreign, &format!("{:032x}", 1), &worker)
            .is_err());
        assert_eq!(gate.records[0].phase, Phase::Preparing);
    }
    #[test]
    fn inference_envelope_is_closed_lossless_root_only_and_time_bounded() {
        let value = serde_json::json!({"schema_version":1,"request_id":"fixture","caller":0,
            "deadline":"100","action":"resource-inference","payload":{"operation":"inspect"}});
        let request: Request = serde_json::from_value(value.clone()).unwrap();
        validate(&request, 0, 1).unwrap();
        for (uid, time) in [(989, 1), (990, 1), (0, 100), (0, u64::MAX)] {
            assert!(validate(&request, uid, time).is_err());
        }
        for (field, invalid) in [
            ("deadline", serde_json::json!(100)),
            ("deadline", serde_json::json!("0100")),
            ("extra", serde_json::json!(true)),
            (
                "payload",
                serde_json::json!({"operation":"inspect","extra":1}),
            ),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(serde_json::from_value::<Request>(changed).is_err());
        }
        let mut long = request;
        long.deadline = 5002;
        assert!(validate(&long, 0, 1).is_err());
    }
    #[test]
    fn real_pidfd_pins_the_root_caller_generation() {
        use std::os::fd::FromRawFd;
        let pid = std::process::id() as i32;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        let pin = unsafe { File::from_raw_fd(fd as i32) };
        let peer = libc::ucred {
            pid,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        let observed = Caller::observe(peer, &pin).unwrap();
        assert_eq!(observed.pid, pid as u32);
        assert!(observed.start > 0);
        assert!(Caller::observe(libc::ucred { uid: 989, ..peer }, &pin).is_err());
    }

    #[test]
    fn actual_request_owner_exit_fences_worker_without_returning_physical_bytes() {
        let (mut gate, ledger, worker, _) = fixture();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("request fixture could not acquire owned PID handle");
        }
        let pin = unsafe { File::from_raw_fd(raw as i32) };
        let caller = Caller::observe(
            libc::ucred {
                pid,
                uid: 0,
                gid: 0,
            },
            &pin,
        )
        .unwrap();
        gate.begin(caller, pin, &begin(&worker, 1), 2048, 2)
            .unwrap();
        assert!(gate.maintain(&ledger, 3).unwrap().is_empty());
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(gate.maintain(&ledger, 4).unwrap(), vec![worker]);
        assert!(gate.occupied());
        assert_eq!(ledger.charged("host").unwrap(), 5000);
    }
}

impl Manager {
    fn inference_worker(
        &self,
        expected: Option<&Token>,
        time: u64,
    ) -> Result<(Token, model::Profile)> {
        let ledger = self.store.read()?;
        let mut workers = ledger
            .leases
            .iter()
            .filter(|lease| lease.owner.uid == 989 && lease.state == State::Active);
        let lease = workers.next().ok_or("no active serving generation")?;
        if workers.next().is_some() || expected.map_or(false, |token| token != &lease.token) {
            return Err("serving generation differs or is ambiguous".into());
        }
        ledger.assert_active(&lease.token, &lease.owner, time)?;
        let profile = model::resource_binding_profile(&lease.binding)?;
        model::resource_profile(&profile.id)?;
        Ok((lease.token.clone(), profile))
    }
    pub(crate) fn handle_inference(
        &mut self,
        request: &Request,
        peer: libc::ucred,
        pin: File,
    ) -> Result<serde_json::Value> {
        validate(request, peer.uid, now()?)?;
        crate::platform::require_installed()?;
        self.maintain()?;
        let caller = Caller::observe(peer, &pin)?;
        let time = now()?;
        validate(request, peer.uid, time)?;
        let status = match &request.payload {
            Message::Inspect {} => {
                let (worker, profile) = self.inference_worker(None, time)?;
                serde_json::json!({"kind":"worker","worker":worker,"profile":profile.id,
                    "context_tokens":profile.context_limit().to_string(),"max_output_tokens":MAX_OUTPUT.to_string(),"slots":"1"})
            }
            Message::Begin {
                worker, profile, ..
            } => {
                let (_, current) = self.inference_worker(Some(worker), time)?;
                if &current.id != profile {
                    return Err("inference selected profile differs".into());
                }
                self.requests
                    .begin(caller, pin, &request.payload, current.context_limit(), time)?
            }
            Message::Admit { worker, .. } => {
                self.inference_worker(Some(worker), time)?;
                self.requests.admit(&caller, &request.payload, time)?
            }
            Message::Finish { worker, .. } => {
                self.inference_worker(Some(worker), time)?;
                self.requests.finish(&caller, &request.payload, time)?
            }
            Message::Cancel { nonce, worker } => {
                self.requests.cancel(&caller, nonce, worker)?;
                self.maintain()?;
                self.requests.record(&caller, nonce, worker)?.receipt()
            }
        };
        self.requests.persist(&self.store, true)?;
        if now()? >= request.deadline {
            return Err("inference acknowledgement expired".into());
        }
        Ok(
            serde_json::json!({"schema_version":1,"request_id":request.request_id,"caller":0,"result":"ok","status":status}),
        )
    }
}
