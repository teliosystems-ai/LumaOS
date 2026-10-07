//! Bounded reference inference mediation on the existing broker socket.
//! Text is transient; durable receipts and physical leases remain authoritative.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Output {
    pub text: String,
    #[serde(with = "resources::decimal")]
    pub prompt_tokens: u64,
    #[serde(with = "resources::decimal")]
    pub output_tokens: u64,
}

pub(crate) fn input_digest(messages: &[ChatMessage]) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"luma-native-gateway-messages-v1\0");
    digest.update(serde_json::to_vec(messages)?);
    Ok(crate::bundle::hex(&digest.finalize()))
}
pub(crate) fn output_digest(output: &Output) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"luma-native-gateway-result-v1\0");
    digest.update(serde_json::to_vec(output)?);
    Ok(crate::bundle::hex(&digest.finalize()))
}

#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Message {
    Inspect {},
    Submit {
        nonce: String,
        worker: Token,
        profile: String,
        messages: Vec<ChatMessage>,
        #[serde(with = "resources::decimal")]
        max_output_tokens: u64,
        #[serde(with = "resources::decimal")]
        request_deadline: u64,
    },
    Fetch {
        nonce: String,
        worker: Token,
    },
    Ack {
        nonce: String,
        worker: Token,
        result_digest: String,
    },
    Cancel {
        nonce: String,
        worker: Token,
    },
    Ready {
        worker: Token,
    },
    Claim {
        worker: Token,
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
        output: Output,
    },
}

pub(crate) struct Job {
    caller: Caller,
    pin: File,
    nonce: String,
    worker: Token,
    messages: Vec<ChatMessage>,
    result: Option<Output>,
}

fn validate(request: &Request, uid: u32, time: u64) -> Result<()> {
    let method = match &request.payload {
        Message::Inspect {}
        | Message::Submit { .. }
        | Message::Fetch { .. }
        | Message::Ack { .. } => uid == 990,
        Message::Ready { .. }
        | Message::Claim { .. }
        | Message::Admit { .. }
        | Message::Finish { .. } => uid == 989,
        Message::Cancel { .. } => matches!(uid, 989 | 990),
    };
    if !method
        || request.schema_version != 1
        || request.caller != uid
        || request.action != "resource-gateway"
        || request.request_id.is_empty()
        || request.request_id.len() > 64
        || !request
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || request.deadline <= time
        || request.deadline - time > 5000
    {
        return Err("reference gateway envelope or peer denied".into());
    }
    Ok(())
}

pub(crate) fn messages_valid(messages: &[ChatMessage]) -> Result<()> {
    if messages.is_empty() || messages.len() > 16 || messages.last().unwrap().role != "user" {
        return Err("gateway messages must end with a user message".into());
    }
    let mut bytes = 0usize;
    for message in messages {
        if !matches!(message.role.as_str(), "system" | "user" | "assistant")
            || message.content.is_empty()
        {
            return Err("unsupported gateway message".into());
        }
        bytes = bytes
            .checked_add(message.content.len())
            .ok_or("message byte overflow")?;
    }
    if bytes > 8192 {
        return Err("gateway input exceeds bound".into());
    }
    Ok(())
}

fn wire_bound(status: &serde_json::Value) -> Result<()> {
    let reply = serde_json::json!({"schema_version":1,"request_id":"x".repeat(64),
        "caller":990,"result":"ok","status":status});
    if serde_json::to_vec(&reply)?.len() > 16384 {
        return Err("gateway reply exceeds existing frame bound".into());
    }
    Ok(())
}

impl Gate {
    fn gateway_ack(
        &mut self,
        caller: &Caller,
        nonce: &str,
        worker: &Token,
        digest: &str,
        time: u64,
    ) -> Result<serde_json::Value> {
        let record = self.record(caller, nonce, worker)?;
        if caller.uid != 990
            || record.phase != Phase::Completed
            || record.until <= time
            || record.input_digest.is_none()
            || !digest_valid(digest)
            || record.result_digest.as_deref() != Some(digest)
        {
            return Err("gateway acknowledgement differs".into());
        }
        Ok(record.receipt())
    }
}

fn serving_generation(
    ledger: &resources::Ledger,
    token: &Token,
    observed: &Owner,
    pinned: bool,
    ready: Option<&Token>,
    time: u64,
) -> Result<()> {
    if !pinned || ready != Some(token) {
        return Err("gateway serving owner/readiness unavailable".into());
    }
    ledger.assert_active(token, observed, time).map(|_| ())
}

impl Manager {
    fn gateway_serving(
        &self,
        expected: Option<&Token>,
        time: u64,
    ) -> Result<(Token, model::Profile)> {
        let (token, profile) = self.inference_worker(expected, time)?;
        let ledger = self.store.read()?;
        let lease = ledger
            .leases
            .iter()
            .find(|lease| lease.token == token)
            .ok_or("gateway physical receipt unavailable")?;
        let observed = owner(lease.owner.pid, lease.owner.uid, &self.group)?;
        let pinned = self
            .owners
            .get(&token.lease_id)
            .map(pidfd_alive)
            .transpose()?
            .unwrap_or(false);
        serving_generation(
            &ledger,
            &token,
            &observed,
            pinned,
            self.gateway_ready.as_ref(),
            now()?,
        )?;
        Ok((token, profile))
    }
    fn gateway_worker(&self, peer: libc::ucred, token: &Token, time: u64) -> Result<()> {
        if peer.uid != 989 || peer.pid <= 0 {
            return Err("gateway worker peer denied".into());
        }
        let observed = owner(peer.pid.try_into()?, peer.uid, &self.group)?;
        self.store.read()?.assert_active(token, &observed, time)?;
        self.inference_worker(Some(token), time)?;
        Ok(())
    }
    pub(in crate::resource_manager) fn maintain_gateway(&mut self, time: u64) -> Result<()> {
        let ledger = self.store.read()?;
        if self.gateway_ready.as_ref().map_or(false, |token| {
            !ledger
                .leases
                .iter()
                .any(|l| &l.token == token && l.state == State::Active && l.deadline_ms > time)
        }) {
            self.gateway_ready = None;
        }
        if let Some(job) = &self.gateway {
            let valid = job.caller.live(&job.pin)?
                && self.requests.records.iter().any(|r| {
                    r.nonce == job.nonce
                        && r.worker == job.worker
                        && r.caller == job.caller
                        && r.until > time
                        && matches!(
                            r.phase,
                            Phase::Preparing | Phase::Admitted | Phase::Completed
                        )
                })
                && ledger.leases.iter().any(|l| {
                    l.token == job.worker && l.state == State::Active && l.deadline_ms > time
                });
            if !valid {
                self.gateway = None;
            }
        }
        Ok(())
    }
    fn gateway_job(&self, nonce: &str, token: &Token) -> Result<&Job> {
        self.gateway
            .as_ref()
            .filter(|j| j.nonce == nonce && &j.worker == token)
            .ok_or_else(|| "gateway job unavailable, stale or retired".into())
    }
    fn job_status(&mut self) -> Result<serde_json::Value> {
        let job = self.gateway.as_ref().ok_or("gateway job unavailable")?;
        let receipt = self
            .requests
            .record(&job.caller, &job.nonce, &job.worker)?
            .receipt();
        Ok(serde_json::json!({"kind":"job","messages":job.messages,"receipt":receipt}))
    }
    pub(crate) fn handle_gateway(
        &mut self,
        request: &Request,
        peer: libc::ucred,
        pin: File,
    ) -> Result<serde_json::Value> {
        validate(request, peer.uid, now()?)?;
        crate::platform::require_installed()?;
        let identity = super::super::peer::live_generation(peer, &pin)?;
        self.maintain()?;
        let time = now()?;
        validate(request, peer.uid, time)?;
        if super::super::peer::live_generation(peer, &pin)? != identity {
            return Err("gateway peer changed".into());
        }
        let status = match &request.payload {
            Message::Inspect {} => {
                let (worker, profile) = self.gateway_serving(None, time)?;
                if self.gateway_ready.as_ref() != Some(&worker) {
                    return Err("gateway runtime not ready".into());
                }
                serde_json::json!({"kind":"worker","worker":worker,"profile":profile.id,
                    "context_tokens":profile.context_limit().to_string(),"max_output_tokens":MAX_OUTPUT.to_string(),"slots":"1"})
            }
            Message::Ready { worker } => {
                self.gateway_worker(peer, worker, time)?;
                self.gateway_ready = Some(worker.clone());
                serde_json::json!({"kind":"ready","worker":worker})
            }
            Message::Submit {
                nonce,
                worker,
                profile,
                messages,
                max_output_tokens,
                request_deadline,
            } => {
                messages_valid(messages)?;
                let (_, selected) = self.gateway_serving(Some(worker), time)?;
                if self.gateway_ready.as_ref() != Some(worker) || profile != &selected.id {
                    return Err("gateway selection/readiness differs".into());
                }
                let caller = Caller::observe_supported(peer, &pin)?;
                if let Some(job) = &self.gateway {
                    if job.caller != caller
                        || job.nonce != *nonce
                        || job.worker != *worker
                        || job.messages != *messages
                    {
                        return Err("gateway queue full or replay differs".into());
                    }
                }
                let begin = super::Message::Begin {
                    nonce: nonce.clone(),
                    worker: worker.clone(),
                    profile: profile.clone(),
                    input_digest: input_digest(messages)?,
                    max_output_tokens: *max_output_tokens,
                    request_deadline: *request_deadline,
                };
                // Bound the eventual claim before durable reservation. This prevents
                // a valid submission from becoming an unrepresentable worker job.
                let planned = serde_json::json!({"kind":"job","messages":messages,"receipt":{
                    "kind":"permit","nonce":nonce,"worker":worker,"phase":"preparing","profile":profile,
                    "input_digest":input_digest(messages)?,"max_output_tokens":max_output_tokens.to_string(),
                    "context_tokens":selected.context_limit().to_string(),"request_deadline":request_deadline.to_string(),
                    "prompt_tokens":null,"token_digest":null,"output_tokens":null,"result_digest":null,
                    "slot_released":false,"worker_resources_released":false}});
                wire_bound(&planned)?;
                let receipt = self.requests.begin(
                    caller.clone(),
                    pin.try_clone()?,
                    &begin,
                    selected.context_limit(),
                    time,
                )?;
                if self.gateway.is_none() {
                    self.gateway = Some(Job {
                        caller,
                        pin: pin.try_clone()?,
                        nonce: nonce.clone(),
                        worker: worker.clone(),
                        messages: messages.clone(),
                        result: None,
                    });
                }
                serde_json::json!({"kind":"permit","receipt":receipt})
            }
            Message::Claim { worker } => {
                self.gateway_worker(peer, worker, time)?;
                if self.gateway_ready.as_ref() != Some(worker) {
                    return Err("gateway worker not registered".into());
                }
                if let Some(job) = &self.gateway {
                    if &job.worker != worker {
                        return Err("gateway job generation differs".into());
                    }
                    let record = self.requests.record(&job.caller, &job.nonce, worker)?;
                    match record.phase {
                        Phase::Preparing => self.job_status()?,
                        Phase::Completed => serde_json::json!({"kind":"idle"}),
                        _ => return Err("gateway job already admitted or fenced".into()),
                    }
                } else {
                    serde_json::json!({"kind":"idle"})
                }
            }
            Message::Admit {
                nonce,
                worker,
                prompt_tokens,
                token_digest,
            } => {
                self.gateway_worker(peer, worker, time)?;
                let caller = self.gateway_job(nonce, worker)?.caller.clone();
                let receipt = self.requests.admit(
                    &caller,
                    &super::Message::Admit {
                        nonce: nonce.clone(),
                        worker: worker.clone(),
                        prompt_tokens: *prompt_tokens,
                        token_digest: token_digest.clone(),
                    },
                    time,
                )?;
                serde_json::json!({"kind":"permit","receipt":receipt})
            }
            Message::Finish {
                nonce,
                worker,
                output,
            } => {
                self.gateway_worker(peer, worker, time)?;
                if output.text.trim().is_empty() || output.text.len() > 8192 {
                    return Err("gateway result exceeds bound".into());
                }
                let caller = self.gateway_job(nonce, worker)?.caller.clone();
                let digest = output_digest(output)?;
                let mut planned = self.requests.record(&caller, nonce, worker)?.receipt();
                planned["phase"] = "completed".into();
                planned["output_tokens"] = output.output_tokens.to_string().into();
                planned["result_digest"] = digest.clone().into();
                planned["slot_released"] = true.into();
                wire_bound(
                    &serde_json::json!({"kind":"result","receipt":planned,"output":output}),
                )?;
                if self
                    .gateway_job(nonce, worker)?
                    .result
                    .as_ref()
                    .map_or(false, |prior| prior != output)
                {
                    return Err("gateway result replay differs".into());
                }
                let receipt = self.requests.finish(
                    &caller,
                    &super::Message::Finish {
                        nonce: nonce.clone(),
                        worker: worker.clone(),
                        prompt_tokens: output.prompt_tokens,
                        output_tokens: output.output_tokens,
                        result_digest: digest,
                    },
                    time,
                )?;
                self.gateway.as_mut().unwrap().result = Some(output.clone());
                self.gateway.as_mut().unwrap().messages.clear();
                serde_json::json!({"kind":"permit","receipt":receipt})
            }
            Message::Fetch { nonce, worker } => {
                self.gateway_serving(Some(worker), time)?;
                let caller = Caller::observe_supported(peer, &pin)?;
                let job = self.gateway_job(nonce, worker)?;
                if job.caller != caller {
                    return Err("gateway caller generation differs".into());
                }
                let output = job.result.clone();
                let receipt = self.requests.record(&caller, nonce, worker)?.receipt();
                if let Some(output) = output {
                    serde_json::json!({"kind":"result","receipt":receipt,"output":output})
                } else {
                    serde_json::json!({"kind":"permit","receipt":receipt})
                }
            }
            Message::Ack {
                nonce,
                worker,
                result_digest,
            } => {
                self.gateway_serving(Some(worker), time)?;
                let caller = Caller::observe_supported(peer, &pin)?;
                let receipt =
                    self.requests
                        .gateway_ack(&caller, nonce, worker, result_digest, time)?;
                if self.gateway.as_ref().map_or(false, |job| {
                    job.nonce == *nonce && job.worker == *worker && job.caller == caller
                }) {
                    self.gateway = None;
                }
                serde_json::json!({"kind":"permit","receipt":receipt})
            }
            Message::Cancel { nonce, worker } => {
                let caller = if peer.uid == 989 {
                    self.gateway_worker(peer, worker, time)?;
                    self.requests
                        .records
                        .iter()
                        .find(|record| {
                            record.nonce == *nonce
                                && record.worker == *worker
                                && record.caller.uid == 990
                        })
                        .ok_or("gateway cancellation unavailable")?
                        .caller
                        .clone()
                } else {
                    Caller::observe_supported(peer, &pin)?
                };
                let receipt = self.requests.cancel(&caller, nonce, worker)?;
                self.requests.persist(&self.store, true)?;
                self.maintain()?;
                if self.gateway.as_ref().map_or(false, |job| {
                    job.nonce == *nonce && job.worker == *worker && job.caller == caller
                }) {
                    self.gateway = None;
                }
                serde_json::json!({"kind":"permit","receipt":receipt})
            }
        };
        wire_bound(&status)?;
        self.requests.persist(
            &self.store,
            matches!(
                &request.payload,
                Message::Submit { .. }
                    | Message::Admit { .. }
                    | Message::Finish { .. }
                    | Message::Cancel { .. }
            ),
        )?;
        let (serving, expected) = match &request.payload {
            Message::Inspect {} => (true, None),
            Message::Submit { worker, .. }
            | Message::Ready { worker }
            | Message::Claim { worker }
            | Message::Admit { worker, .. }
            | Message::Finish { worker, .. }
            | Message::Fetch { worker, .. }
            | Message::Ack { worker, .. } => (true, Some(worker)),
            Message::Cancel { .. } => (false, None),
        };
        if serving {
            self.gateway_serving(expected, now()?)?;
        }
        if super::super::peer::live_generation(peer, &pin)? != identity
            || now()? >= request.deadline
        {
            return Err("gateway acknowledgement expired".into());
        }
        Ok(
            serde_json::json!({"schema_version":1,"request_id":request.request_id,"caller":peer.uid,"result":"ok","status":status}),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Permit {
    pub kind: String,
    pub nonce: String,
    pub worker: Token,
    pub phase: String,
    pub profile: String,
    pub input_digest: String,
    #[serde(with = "resources::decimal")]
    pub max_output_tokens: u64,
    #[serde(with = "resources::decimal")]
    pub context_tokens: u64,
    #[serde(with = "resources::decimal")]
    pub request_deadline: u64,
    #[serde(with = "journal::optional_decimal")]
    pub prompt_tokens: Option<u64>,
    pub token_digest: Option<String>,
    #[serde(with = "journal::optional_decimal")]
    pub output_tokens: Option<u64>,
    pub result_digest: Option<String>,
    pub slot_released: bool,
    pub worker_resources_released: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Status {
    Idle {},
    Ready {
        worker: Token,
    },
    Job {
        messages: Vec<ChatMessage>,
        receipt: Permit,
    },
    Permit {
        receipt: Permit,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    pub result: String,
    pub status: Status,
}

pub(crate) fn worker_request(payload: Message) -> Result<Request> {
    Ok(Request {
        schema_version: 1,
        request_id: resources::random_id()?,
        caller: 989,
        deadline: now()?
            .checked_add(4000)
            .ok_or("gateway RPC deadline overflow")?,
        action: "resource-gateway".into(),
        payload,
    })
}
pub(crate) fn validate_response(raw: &[u8], request: &Request) -> Result<Status> {
    let response: Response = serde_json::from_slice(raw)?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.caller != request.caller
        || response.result != "ok"
        || now()? >= request.deadline
        || serde_json::to_value(&response)? != serde_json::from_slice::<serde_json::Value>(raw)?
    {
        return Err("gateway reply identity or closed shape differs".into());
    }
    Ok(response.status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_requires_the_current_live_active_physical_generation_even_for_retained_receipts()
    {
        let (_, mut ledger, worker, _) = super::super::tests::fixture();
        let observed = ledger.leases[0].owner.clone();
        serving_generation(&ledger, &worker, &observed, true, Some(&worker), 2).unwrap();
        assert!(serving_generation(&ledger, &worker, &observed, false, Some(&worker), 2).is_err());
        assert!(serving_generation(&ledger, &worker, &observed, true, None, 2).is_err());
        assert!(
            serving_generation(&ledger, &worker, &observed, true, Some(&worker), 10000).is_err()
        );
        let mut changed = worker.clone();
        changed.generation += 1;
        assert!(serving_generation(&ledger, &worker, &observed, true, Some(&changed), 2).is_err());
        assert!(serving_generation(&ledger, &changed, &observed, true, Some(&changed), 2).is_err());
        let mut changed = observed.clone();
        changed.start_ticks += 1;
        assert!(serving_generation(&ledger, &worker, &changed, true, Some(&worker), 2).is_err());
        ledger.revoke(&worker, "fixture").unwrap();
        assert!(serving_generation(&ledger, &worker, &observed, true, Some(&worker), 2).is_err());
        ledger
            .finish_draining(&worker, &BTreeMap::from([("host".into(), 25)]))
            .unwrap();
        assert!(serving_generation(&ledger, &worker, &observed, true, Some(&worker), 2).is_err());
        assert_eq!(ledger.charged("host").unwrap(), 25);
    }
    #[test]
    fn roles_bytes_message_count_and_exact_input_identity_are_bounded() {
        let original = vec![ChatMessage {
            role: "user".into(),
            content: "hello".into(),
        }];
        messages_valid(&original).unwrap();
        for invalid in [
            vec![],
            vec![ChatMessage {
                role: "assistant".into(),
                content: "a".into(),
            }],
            vec![ChatMessage {
                role: "tool".into(),
                content: "a".into(),
            }],
            vec![ChatMessage {
                role: "user".into(),
                content: String::new(),
            }],
            vec![ChatMessage {
                role: "user".into(),
                content: "a".repeat(8193),
            }],
            vec![original[0].clone(); 17],
        ] {
            assert!(messages_valid(&invalid).is_err());
        }
        let mut changed = original.clone();
        changed[0].content.push(' ');
        assert_ne!(
            input_digest(&original).unwrap(),
            input_digest(&changed).unwrap()
        );
        let output = Output {
            text: "hello".into(),
            prompt_tokens: 1,
            output_tokens: 1,
        };
        assert_eq!(
            input_digest(&original).unwrap(),
            "97c789eaa3d9479f0fc8ecfad11bebf8f5d2693dd5073469a198ee3f1b2ff4ce"
        );
        assert_eq!(
            output_digest(&output).unwrap(),
            "186e3180d6090f3943fcae8df5fc45a043a207ce3a14e8be0ef884204d4b3a87"
        );
        assert_ne!(
            input_digest(&original).unwrap(),
            output_digest(&output).unwrap()
        );
    }
    #[test]
    fn peer_method_envelopes_do_not_delegate_worker_or_root_authority() {
        for (payload, uid) in [
            (Message::Inspect {}, 990),
            (
                Message::Ready {
                    worker: Token {
                        lease_id: "a".repeat(32),
                        generation: 1,
                        manager_epoch: "b".repeat(32),
                    },
                },
                989,
            ),
        ] {
            let mut request = worker_request(payload).unwrap();
            request.caller = uid;
            validate(&request, uid, now().unwrap()).unwrap();
            for other in [0, 988, 1000] {
                assert!(validate(&request, other, now().unwrap()).is_err());
            }
            request.schema_version = 2;
            assert!(validate(&request, uid, now().unwrap()).is_err());
            request.schema_version = 1;
            request.deadline = now().unwrap();
            assert!(validate(&request, uid, now().unwrap()).is_err());
        }
        assert!(wire_bound(&serde_json::json!({"text":"\u{0001}".repeat(8192)})).is_err());
    }
    #[test]
    fn delegated_reference_receipts_preserve_owner_fences_and_physical_charge() {
        let (mut gate, ledger, worker, mut caller) = super::super::tests::fixture();
        caller.uid = 990;
        let mut peer = super::super::tests::fixture().3;
        peer.uid = 0;
        let begin = super::super::tests::begin(&worker, 1);
        super::super::tests::reserve(&mut gate, &caller, &begin).unwrap();
        assert!(gate
            .admit(&peer, &super::super::tests::admit(&worker, 1, 10), 3)
            .is_err());
        gate.admit(&caller, &super::super::tests::admit(&worker, 1, 10), 3)
            .unwrap();
        gate.finish(&caller, &super::super::tests::finish(&worker, 1, 10, 1), 4)
            .unwrap();
        assert_eq!(ledger.charged("host").unwrap(), 5000);
        let snapshot = serde_json::to_value(&gate.records[0].caller).unwrap();
        assert_eq!(snapshot["uid"], 990);
        peer.uid = 0;
        assert!(serde_json::to_value(peer).unwrap().get("uid").is_none());
    }

    #[test]
    fn exact_terminal_ack_and_cancel_replay_preserve_charge_and_foreign_caller_fences() {
        let (mut gate, ledger, worker, mut caller) = super::super::tests::fixture();
        caller.uid = 990;
        let nonce = format!("{:032x}", 1);
        super::super::tests::reserve(&mut gate, &caller, &super::super::tests::begin(&worker, 1))
            .unwrap();
        assert!(gate
            .gateway_ack(&caller, &nonce, &worker, &"c".repeat(64), 3)
            .is_err());
        gate.admit(&caller, &super::super::tests::admit(&worker, 1, 10), 3)
            .unwrap();
        gate.finish(&caller, &super::super::tests::finish(&worker, 1, 10, 1), 4)
            .unwrap();
        let first = gate
            .gateway_ack(&caller, &nonce, &worker, &"c".repeat(64), 5)
            .unwrap();
        assert_eq!(
            gate.gateway_ack(&caller, &nonce, &worker, &"c".repeat(64), 6)
                .unwrap(),
            first
        );
        assert_eq!(gate.cancel(&caller, &nonce, &worker).unwrap(), first);
        assert_eq!(gate.cancel(&caller, &nonce, &worker).unwrap(), first);
        let mut foreign = caller.clone();
        foreign.start += 1;
        assert!(gate
            .gateway_ack(&foreign, &nonce, &worker, &"c".repeat(64), 6)
            .is_err());
        assert!(gate.cancel(&foreign, &nonce, &worker).is_err());
        assert!(gate
            .gateway_ack(&caller, &nonce, &worker, &"d".repeat(64), 6)
            .is_err());
        assert!(gate
            .gateway_ack(&caller, &nonce, &worker, &"c".repeat(64), 9000)
            .is_err());
        assert_eq!(ledger.charged("host").unwrap(), 5000);
    }

    #[test]
    fn closed_reply_identity_rejects_substitution_duplicate_keys_and_omitted_fields() {
        let request = worker_request(Message::Claim {
            worker: Token {
                lease_id: "a".repeat(32),
                generation: 1,
                manager_epoch: "b".repeat(32),
            },
        })
        .unwrap();
        let good = serde_json::json!({"schema_version":1,"request_id":request.request_id,"caller":989,"result":"ok","status":{"kind":"idle"}});
        assert!(matches!(
            validate_response(&serde_json::to_vec(&good).unwrap(), &request).unwrap(),
            Status::Idle {}
        ));
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("caller", serde_json::json!(990)),
            ("request_id", serde_json::json!("other")),
            ("result", serde_json::json!("denied")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut changed = good.clone();
            changed[field] = value;
            assert!(validate_response(&serde_json::to_vec(&changed).unwrap(), &request).is_err());
        }
        let duplicate = String::from_utf8(serde_json::to_vec(&good).unwrap())
            .unwrap()
            .replace("\"caller\":989", "\"caller\":989,\"caller\":989");
        assert!(validate_response(duplicate.as_bytes(), &request).is_err());
        let mut expired = request;
        expired.deadline = now().unwrap();
        assert!(validate_response(&serde_json::to_vec(&good).unwrap(), &expired).is_err());
        let (mut gate, _, worker, caller) = super::super::tests::fixture();
        let receipt = super::super::tests::reserve(
            &mut gate,
            &caller,
            &super::super::tests::begin(&worker, 1),
        )
        .unwrap();
        let mut reply = good;
        reply["status"] = serde_json::json!({"kind":"permit","receipt":receipt});
        let request = worker_request(Message::Claim { worker }).unwrap();
        reply["request_id"] = request.request_id.clone().into();
        assert!(validate_response(&serde_json::to_vec(&reply).unwrap(), &request).is_ok());
        for field in [
            "prompt_tokens",
            "output_tokens",
            "token_digest",
            "result_digest",
        ] {
            let mut missing = reply.clone();
            missing["status"]["receipt"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(validate_response(&serde_json::to_vec(&missing).unwrap(), &request).is_err());
        }
    }
}
