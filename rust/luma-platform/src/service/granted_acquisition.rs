//! Exact finite acquisition joined to its original PAM client's live socket.
//! Neither a request nor a proof frame is reusable authority.
use super::*;
use crate::{finite_grants::Use, resources::Token};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    #[serde(with = "crate::resources::decimal")]
    pub deadline: u64,
    pub action: String,
    pub job: String,
    pub profile: String,
    pub storage_device: String,
    pub usage: Use,
    pub input_sha256: String,
}
impl Request {
    pub(crate) fn validate(&self, peer: libc::ucred) -> Result<()> {
        let now = crate::resource_manager::now()?;
        if self.schema_version != 1
            || self.action != "resource-granted-acquisition"
            || self.caller != 0
            || peer.uid != 0
            || self.deadline <= now
            || self.deadline
                > now
                    .checked_add(10_000)
                    .ok_or("acquisition deadline overflow")?
            || !self.request_id.starts_with("console-")
            || self.request_id.len() != 40
        {
            return Err("invalid finite acquisition envelope".into());
        }
        crate::tpm::decode::<16>(&self.job)?;
        crate::tpm::decode::<32>(&self.input_sha256)?;
        let expected = usage(&self.profile)?;
        if self.usage != expected
            || self.input_sha256 != expected.selector.digest
            || self.storage_device != crate::resource_manager::storage_device(Path::new("/var"))?
        {
            return Err(
                "finite acquisition scope differs from exact installed pack/storage".into(),
            );
        }
        Ok(())
    }
}

pub(crate) struct Authority {
    admission: granted_gateway::Admission,
    profile: String,
    device: String,
    token: Option<Token>,
    next_check: u64,
    expected_output: Option<String>,
}
impl Authority {
    pub(crate) fn capture(socket: &UnixStream, request: &Request) -> Result<Self> {
        request.validate(credentials(socket)?)?;
        let admission = granted_gateway::Admission::capture_acquisition(
            socket,
            &request.job,
            &request.profile,
            request.usage.clone(),
            request.input_sha256.clone(),
        )?;
        let expected_output = if request.profile.starts_with("generated-v1-") {
            None
        } else if request.profile.starts_with("qa-v1-") {
            None
        } else if request.profile.starts_with("content-v1-") {
            None
        } else {
            Some(crate::model::pack_completion(
                &crate::model::public_profile(&request.profile)?,
                "prepare",
            )?)
        };
        Ok(Self {
            admission,
            profile: request.profile.clone(),
            device: request.storage_device.clone(),
            token: None,
            next_check: 0,
            expected_output,
        })
    }
    pub(crate) fn matches(&self, profile: &str, device: &str) -> bool {
        self.profile == profile && self.device == device
    }
    pub(crate) fn check(&mut self) -> Result<()> {
        self.admission.acquisition_liveness()?;
        let now = crate::resource_manager::now()?;
        // Content storage calls renew at every bounded I/O/commit checkpoint.
        // It requires a fresh original PAM/grant/UTC proof there, not the
        // model-controller's permitted 500ms cached sampling window.
        if !self.profile.starts_with("content-v1-") && now < self.next_check {
            return Ok(());
        }
        self.admission.check()?;
        self.next_check = crate::resource_manager::now()?
            .checked_add(500)
            .ok_or("acquisition check deadline overflow")?;
        Ok(())
    }
    pub(crate) fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }
    pub(crate) fn completed(&self) -> bool {
        self.admission.acquisition_completed()
    }
    pub(crate) fn finish_ack(&mut self) -> Result<()> {
        self.admission.acquisition_finish_ack()
    }
    pub(crate) fn completed_result(&self, ledger: &crate::resources::Ledger) -> bool {
        completed_lease(ledger, self.token())
            && self.expected_output.as_ref().map_or(true, |expected| {
                self.token()
                    .and_then(|token| ledger.leases.iter().find(|lease| lease.token == *token))
                    .and_then(|lease| lease.output_sha256.as_ref())
                    == Some(expected)
            })
    }
    pub(crate) fn attach(&mut self, token: &Token) -> Result<()> {
        if self.token.as_ref().is_some_and(|old| old != token) {
            return Err("acquisition admission already bound to another generation".into());
        }
        self.token = Some(token.clone());
        Ok(())
    }
}

pub(crate) fn usage(profile: &str) -> Result<Use> {
    if profile.starts_with("generated-v1-") {
        crate::generated_runtime::acquisition_usage(profile)
    } else if profile.starts_with("qa-v1-") {
        crate::model::qa::usage(profile)
    } else if profile.starts_with("content-v1-") {
        crate::content_governed::acquisition_usage(profile)
    } else {
        crate::model::pack_import_usage(profile)
    }
}
pub(crate) fn completed_lease(ledger: &crate::resources::Ledger, token: Option<&Token>) -> bool {
    token
        .filter(|token| token.manager_epoch == ledger.manager_epoch)
        .and_then(|token| ledger.leases.iter().find(|lease| lease.token == *token))
        .is_some_and(|lease| {
            lease.state == crate::resources::State::Released
                && !lease.output_fenced
                && lease.output_sha256.is_some()
                && lease.output_domain_epochs.as_ref().is_some_and(|epochs| {
                    !epochs.is_empty() && epochs.values().all(|epoch| epoch.0 > 0)
                })
        })
}
fn terminal_ack<T>(frame: &serde_json::Value, job: &str, result: &mut Option<T>) -> Result<T> {
    if frame != &serde_json::json!({"schema_version":1,"kind":"acquisition-completed","job":job}) {
        return Err("finite acquisition terminal acknowledgment differs".into());
    }
    result.take().ok_or_else(||"acquisition terminal acknowledgment arrived before controller completion or was replayed".into())
}

pub(crate) fn run(
    profile: &crate::model::Profile,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<()> {
    let profile = profile.clone();
    run_controller(&profile.id.clone(), usage, boundary, move |cancel| {
        crate::acquisition::run_checked(Path::new("/var"), &profile, "prepare", || {
            if cancel.load(Ordering::Acquire) {
                Err("original finite acquisition client fenced".into())
            } else {
                Ok(())
            }
        })
    })
}

pub(crate) fn run_generated<T: Send>(
    profile: &str,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> Result<T> + Send,
) -> Result<T> {
    if !profile.starts_with("generated-v1-") {
        return Err("generated acquisition profile is not closed".into());
    }
    run_controller(profile, usage, boundary, move |cancel| {
        controller(&mut || {
            if cancel.load(Ordering::Acquire) {
                Err("original generated principal fenced".into())
            } else {
                Ok(())
            }
        })
    })
}

pub(crate) fn run_qa<T: Send>(
    profile: &str,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> Result<T> + Send,
) -> Result<T> {
    crate::model::qa::parse_profile(profile)?;
    if boundary.session_purpose() != crate::authentication::SessionPurpose::ModelQa
        || usage != &crate::model::qa::usage(profile)?
    {
        return Err("QA controller cannot borrow normal serving/import authority".into());
    }
    run_controller(profile, usage, boundary, move |cancel| {
        controller(&mut || {
            if cancel.load(Ordering::Acquire) {
                Err("original QA Admin/UTC/grant connection fenced".into())
            } else {
                Ok(())
            }
        })
    })
}

pub(crate) fn run_content<T: Send>(
    profile: &str,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> Result<T> + Send,
) -> Result<T> {
    crate::content_governed::source_digest(profile)?;
    if boundary.session_purpose() != crate::authentication::SessionPurpose::Standard
        || usage != &crate::content_governed::acquisition_usage(profile)?
    {
        return Err("content controller cannot borrow another purpose or finite scope".into());
    }
    run_controller(profile, usage, boundary, move |cancel| {
        controller(&mut || {
            if cancel.load(Ordering::Acquire) {
                Err("original content principal fenced".into())
            } else {
                Ok(())
            }
        })
    })
}

fn run_controller<T: Send>(
    profile: &str,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(Arc<AtomicBool>) -> Result<T> + Send,
) -> Result<T> {
    boundary.check()?;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut socket = connect_local(SOCKET, deadline)?;
    if peer(&socket)? != 0 {
        return Err("finite acquisition broker peer is not root".into());
    }
    let job = crate::resources::random_id()?;
    let request = Request {
        schema_version: 1,
        request_id: fresh_request_id()?,
        caller: 0,
        deadline: crate::resource_manager::now()?
            .checked_add(4000)
            .ok_or("acquisition deadline overflow")?,
        action: "resource-granted-acquisition".into(),
        job: job.clone(),
        profile: profile.into(),
        storage_device: crate::resource_manager::storage_device(Path::new("/var"))?,
        usage: usage.clone(),
        input_sha256: usage.selector.digest.clone(),
    };
    write_frame_until(&mut socket, &serde_json::to_vec(&request)?, deadline)?;
    loop {
        let raw = read_frame_until(&mut socket, deadline)?;
        let frame: serde_json::Value = serde_json::from_slice(&raw)?;
        if frame.get("kind").and_then(|v| v.as_str()) == Some("grant-challenge") {
            let proof = granted_gateway::acquisition_proof(
                &raw,
                &job,
                usage,
                &request.input_sha256,
                boundary,
                false,
            )?;
            write_frame_until(&mut socket, &proof, deadline)?;
        } else {
            let expected = serde_json::json!({"schema_version":1,"result":"ok","request_id":request.request_id,"job":job});
            if frame != expected {
                return Err("finite acquisition registration refused or substituted".into());
            }
            break;
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| -> Result<T> {
        let cancel = cancelled.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let controller = scope.spawn(move || {
            let result = controller(cancel.clone())
                .and_then(|value| {
                    crate::acquisition::await_drainage_checked(&mut || {
                        if cancel.load(Ordering::Acquire) {
                            Err("finite acquisition completion cancelled".into())
                        } else {
                            Ok(())
                        }
                    })?;
                    Ok(value)
                })
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        let outcome = (|| -> Result<T> {
            let mut completed = None;
            let mut next_guard = Instant::now();
            loop {
                if Instant::now() >= next_guard {
                    boundary.check()?;
                    next_guard = Instant::now() + Duration::from_millis(500);
                }
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let count = unsafe { libc::poll(&mut poll, 1, 100) };
                if count < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                    && poll.revents & libc::POLLIN == 0
                {
                    return Err("finite acquisition broker connection lost".into());
                }
                if poll.revents & libc::POLLIN != 0 {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let raw = read_frame_until(&mut socket, deadline)?;
                    let frame: serde_json::Value = serde_json::from_slice(&raw)?;
                    if frame.get("kind").and_then(|value| value.as_str())
                        == Some("acquisition-completed")
                    {
                        boundary.check()?;
                        return terminal_ack(&frame, &job, &mut completed);
                    }
                    let proof = granted_gateway::acquisition_proof(
                        &raw,
                        &job,
                        usage,
                        &request.input_sha256,
                        boundary,
                        completed.is_some(),
                    )?;
                    write_frame_until(&mut socket, &proof, deadline)?;
                }
                if completed.is_some() {
                    continue;
                }
                match receiver.try_recv() {
                    Ok(Ok(value)) => {
                        boundary.check()?;
                        completed = Some(value);
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(std::sync::mpsc::TryRecvError::Empty) => (),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("acquisition controller outcome unavailable".into())
                    }
                }
            }
        })();
        cancelled.store(true, Ordering::Release);
        // The broker revokes the exact attached lease and observes drainage;
        // shutdown is not a serialized cancellation or capacity receipt.
        let _ = socket.shutdown(std::net::Shutdown::Both);
        if controller.join().is_err() {
            return Err("acquisition controller panicked; preserve pending bytes".into());
        }
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{Domain, Ledger, Owner, Reservation, State};
    use std::collections::BTreeMap;
    fn ledger() -> (Ledger, Token) {
        let mut ledger = Ledger::fresh_for_test();
        ledger
            .restart(
                "epoch-one".into(),
                BTreeMap::from([("host".into(), Domain::new(1000, 100, 950, 800).unwrap())]),
            )
            .unwrap();
        let owner = Owner {
            uid: 0,
            pid: 41,
            start_ticks: 1,
            boot: "a".repeat(32),
            cgroup_device: 2,
            cgroup_inode: 3,
        };
        let token = ledger
            .admit(
                owner.clone(),
                "operation-one".into(),
                "a".repeat(64),
                vec![Reservation {
                    domain: "host".into(),
                    loading: 40,
                    serving: 40,
                }],
                1,
                100,
            )
            .unwrap();
        ledger
            .complete_output(&token, &owner, 2, &"b".repeat(64))
            .unwrap();
        (ledger, token)
    }
    #[test]
    fn graceful_completion_requires_exact_unfenced_observed_release() {
        let (mut ledger, token) = ledger();
        assert!(!completed_lease(&ledger, Some(&token)));
        ledger.revoke(&token, "owner-lost").unwrap();
        assert_eq!(ledger.leases[0].state, State::Draining);
        assert!(!completed_lease(&ledger, Some(&token)));
        assert_eq!(ledger.charged("host").unwrap(), 40);
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 7)]))
            .unwrap();
        let before = ledger.clone();
        assert!(completed_lease(&ledger, Some(&token)));
        assert_eq!(ledger, before);
        assert!(!ledger.leases[0].output_fenced);
        for altered in [
            Token {
                generation: token.generation + 1,
                ..token.clone()
            },
            Token {
                manager_epoch: "wrong-epoch".into(),
                ..token.clone()
            },
            Token {
                lease_id: "wrong-lease".into(),
                ..token.clone()
            },
        ] {
            assert!(!completed_lease(&ledger, Some(&altered)));
        }
        assert!(!completed_lease(&ledger, None));
        ledger
            .revoke(&token, "original-acquisition-principal-fenced")
            .unwrap();
        assert!(!completed_lease(&ledger, Some(&token)));
        assert_eq!(ledger.charged("host").unwrap(), 7);
    }
    #[test]
    fn expiration_and_premature_completion_never_return_capacity_or_unfence_output() {
        let (mut ledger, token) = ledger();
        ledger.expire(100);
        assert_eq!(ledger.leases[0].state, State::Draining);
        assert!(!completed_lease(&ledger, Some(&token)));
        assert!(ledger.leases[0].output_fenced);
        assert_eq!(ledger.charged("host").unwrap(), 40);
        ledger
            .revoke(&token, "premature-acquisition-completion")
            .unwrap();
        assert_eq!(ledger.charged("host").unwrap(), 40);
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
            .unwrap();
        assert!(!completed_lease(&ledger, Some(&token)));
        let (mut ledger, token) = self::ledger();
        ledger.leases[0].output_sha256 = None;
        ledger.leases[0].output_domain_epochs = None;
        ledger.revoke(&token, "owner-lost").unwrap();
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
            .unwrap();
        assert!(!completed_lease(&ledger, Some(&token)));
    }
    #[test]
    fn terminal_ack_requires_completed_controller_exact_job_and_single_delivery() {
        let job = "a".repeat(32);
        let ack = serde_json::json!({"schema_version":1,"kind":"acquisition-completed","job":job});
        let mut pending: Option<u32> = None;
        assert!(terminal_ack(&ack, &job, &mut pending).is_err());
        pending = Some(7);
        assert!(terminal_ack(&ack, &"b".repeat(32), &mut pending).is_err());
        assert_eq!(pending, Some(7));
        let mut extra = ack.clone();
        extra["authority"] = serde_json::json!(true);
        assert!(terminal_ack(&extra, &job, &mut pending).is_err());
        assert_eq!(terminal_ack(&ack, &job, &mut pending).unwrap(), 7);
        assert!(terminal_ack(&ack, &job, &mut pending).is_err());
    }
}
