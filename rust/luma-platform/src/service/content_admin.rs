//! Original PAM Admin proof for the separately budgeted content-custody unit.
//! No serialized audit or Unix UID can register an Admin role on its own.
use super::*;
use crate::finite_grants::{Audit, Use};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub action: String,
    pub request_id: String,
    pub deadline: u64,
    pub job: String,
    pub command: String,
    pub usage: Use,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        let now = resource_manager::now()?;
        if self.schema_version != 1
            || self.action != "resource-content-admin-open"
            || self.deadline <= now
            || self.deadline
                > now
                    .checked_add(4000)
                    .ok_or("custody Admin deadline overflow")?
            || !self.request_id.starts_with("console-")
            || self.request_id.len() != 40
            || crate::tpm::decode::<16>(&self.job).is_err()
        {
            return Err("invalid closed content custody Admin opening".into());
        }
        crate::content_checkpoint::custody::admin_scope(&self.command, &self.usage)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Guard {
    pub schema_version: u32,
    pub action: String,
    pub request_id: String,
    pub deadline: u64,
    pub job: String,
    pub client_pid: u32,
    pub client_start: u64,
    pub command: String,
    pub usage: Use,
}
impl Guard {
    pub(crate) fn validate(&self) -> Result<()> {
        let now = resource_manager::now()?;
        if self.schema_version != 1
            || self.action != "resource-content-admin-guard"
            || self.deadline <= now
            || self.deadline
                > now
                    .checked_add(3000)
                    .ok_or("custody Admin deadline overflow")?
            || crate::tpm::decode::<16>(&self.request_id).is_err()
            || crate::tpm::decode::<16>(&self.job).is_err()
            || self.client_pid == 0
            || self.client_start == 0
        {
            return Err("invalid closed content custody Admin guard".into());
        }
        crate::content_checkpoint::custody::admin_scope(&self.command, &self.usage)?;
        Ok(())
    }
}
pub(crate) fn proof(request: &Guard) -> Result<Audit> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        schema_version: u32,
        result: String,
        request_id: String,
        audit: Audit,
    }
    request.validate()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut socket = connect_local(SOCKET, deadline)?;
    if credentials(&socket)?.uid != 0 {
        return Err("content Admin proof broker is not root".into());
    }
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    write_frame_until(&mut socket, &serde_json::to_vec(request)?, deadline)?;
    let reply: Reply = serde_json::from_slice(&read_frame_until(&mut socket, deadline)?)?;
    if reply.schema_version != 1 || reply.result != "ok" || reply.request_id != request.request_id {
        return Err("content Admin original proof refused or substituted".into());
    }
    reply.audit.validate()?;
    request.validate()?;
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    Ok(reply.audit)
}
pub(crate) struct Authority {
    admission: granted_gateway::Admission,
    job: String,
    command: String,
    usage: Use,
    client_pid: u32,
    client_start: u64,
}
impl Authority {
    pub(crate) fn capture(socket: &UnixStream, request: &Request) -> Result<Self> {
        request.validate()?;
        let peer = credentials(socket)?;
        if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 {
            return Err("content custody Admin requires original bounded grant client".into());
        }
        let pin = peer_pidfd(socket)?;
        crate::credential_observer::kernel_check(&pin, 0, 0)?;
        let client_start = crate::resource_manager::content_client_generation(peer, &pin)?;
        let admission = granted_gateway::Admission::capture_custody_admin(
            socket,
            &request.job,
            &request.command,
            request.usage.clone(),
        )?;
        Ok(Self {
            admission,
            job: request.job.clone(),
            command: request.command.clone(),
            usage: request.usage.clone(),
            client_pid: peer.pid as u32,
            client_start,
        })
    }
    pub(crate) fn check(&mut self) -> Result<()> {
        self.admission.acquisition_liveness()?;
        self.admission.check()
    }
    pub(crate) fn guard(&mut self, request: &Guard) -> Result<Audit> {
        request.validate()?;
        if request.job != self.job
            || request.command != self.command
            || request.usage != self.usage
            || request.client_pid != self.client_pid
            || request.client_start != self.client_start
        {
            return Err(
                "content custody Admin guard belongs to a different original operation".into(),
            );
        }
        self.check()?;
        Ok(self.admission.attribution()?.clone())
    }
}

pub(crate) fn run<T: Send>(
    command: &str,
    usage: &Use,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(String, Arc<AtomicBool>) -> Result<T> + Send,
) -> Result<T> {
    crate::content_checkpoint::custody::admin_scope(command, usage)?;
    boundary.require_admin()?;
    if boundary.audit()?.usage != *usage {
        return Err("content custody Admin scope is not exact original owned grant".into());
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut socket = connect_local(SOCKET, deadline)?;
    if credentials(&socket)?.uid != 0 {
        return Err("content custody Admin broker is not root".into());
    }
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    let job = crate::resources::random_id()?;
    let request = Request {
        schema_version: 1,
        action: "resource-content-admin-open".into(),
        request_id: fresh_request_id()?,
        deadline: resource_manager::now()?
            .checked_add(4000)
            .ok_or("content Admin deadline overflow")?,
        job: job.clone(),
        command: command.into(),
        usage: usage.clone(),
    };
    write_frame_until(&mut socket, &serde_json::to_vec(&request)?, deadline)?;
    loop {
        let raw = read_frame_until(&mut socket, deadline)?;
        let value: serde_json::Value = serde_json::from_slice(&raw)?;
        if value["kind"].as_str() == Some("grant-challenge") {
            let proof = granted_gateway::acquisition_proof(
                &raw,
                &job,
                usage,
                &usage.selector.digest,
                boundary,
                false,
                None,
            )?;
            write_frame_until(&mut socket, &proof, deadline)?;
        } else if value
            == serde_json::json!({"schema_version":1,"result":"ok","request_id":request.request_id,"job":job})
        {
            break;
        } else {
            return Err("content custody Admin original registration refused".into());
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let outcome = std::thread::scope(|scope| -> Result<T> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let child_cancel = cancel.clone();
        let child_job = job.clone();
        let child = scope.spawn(move || {
            let result = controller(child_job, child_cancel).map_err(|e| e.to_string());
            let _ = sender.send(result);
        });
        let result = (|| -> Result<T> {
            let total_deadline = Instant::now() + Duration::from_secs(120);
            loop {
                remaining(total_deadline)?;
                boundary.require_admin()?;
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 100) } < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err("content custody Admin original broker connection lost".into());
                }
                if poll.revents & libc::POLLIN != 0 {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let raw = read_frame_until(&mut socket, deadline)?;
                    let proof = granted_gateway::acquisition_proof(
                        &raw,
                        &job,
                        usage,
                        &usage.selector.digest,
                        boundary,
                        false,
                        None,
                    )?;
                    write_frame_until(&mut socket, &proof, deadline)?;
                }
                match receiver.try_recv() {
                    Ok(Ok(value)) => {
                        boundary.require_admin()?;
                        return Ok(value);
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("content custody Admin controller outcome missing".into())
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
        })();
        cancel.store(true, Ordering::Release);
        let _ = socket.shutdown(std::net::Shutdown::Both);
        if child.join().is_err() {
            return Err(
                "content custody Admin controller panicked; preserve prepared evidence".into(),
            );
        }
        result
    });
    cancel.store(true, Ordering::Release);
    outcome
}
