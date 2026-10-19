//! Independent live original-controller proof during private content delivery.
//! A completed worker's resource receipt is evidence, never current C access.
use super::*;
use crate::{
    finite_grants::{Audit, Use},
    resources::Token,
};
use luma_content::OwnerBinding;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    pub profile: String,
    pub storage_device: String,
    pub binding: OwnerBinding,
    pub lease: Token,
    pub output_sha256: String,
}
impl Descriptor {
    fn data_usage_at(&self, device: &str) -> Result<Use> {
        self.binding.validate()?;
        if !self.profile.starts_with("content-v1-")
            || !crate::workflow_resource::token_valid(&self.lease)
            || !crate::artifacts::hash(&self.output_sha256)
        {
            return Err("invalid closed content output descriptor".into());
        }
        let review = self
            .profile
            .rsplit('-')
            .next()
            .ok_or("content output profile lacks review")?;
        let usage =
            crate::content_governed::custody_usage(&self.profile, device, &self.binding, review)?;
        if usage.selector.generation != self.binding.owner_generation {
            return Err("content output descriptor differs from original owner generation".into());
        }
        Ok(usage)
    }
    pub(crate) fn usage(&self) -> Result<Use> {
        self.data_usage_at(&self.storage_device)
    }
    fn installed_usage(&self) -> Result<Use> {
        let expected = crate::content_governed::acquisition_usage(&self.profile)?;
        if self.storage_device != resource_manager::storage_device(Path::new("/var"))? {
            return Err("content output selected another installed storage device".into());
        }
        let actual = self.usage()?;
        if expected != actual {
            return Err("content output belongs to another installed authority".into());
        }
        Ok(actual)
    }
    fn receipt_at(&self, usage: &Use, value: serde_json::Value) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Receipt {
            binding: String,
            output_sha256: String,
            output_domain_epochs: std::collections::BTreeMap<String, crate::resources::OutputEpoch>,
            lease: Token,
            state: crate::resources::State,
            physical_release_granted: bool,
        }
        let receipt: Receipt = serde_json::from_value(value)?;
        if receipt.binding != usage.selector.digest
            || receipt.lease != self.lease
            || receipt.output_sha256 != self.output_sha256
            || receipt.physical_release_granted
            || receipt
                .output_domain_epochs
                .keys()
                .map(String::as_str)
                .ne(resource_manager::invoice_output_domains())
            || receipt
                .output_domain_epochs
                .values()
                .any(|epoch| epoch.0 == 0)
        {
            return Err(
                "content output lacks its exact current physical-generation receipt".into(),
            );
        }
        match receipt.state {
            crate::resources::State::Active
            | crate::resources::State::Draining
            | crate::resources::State::Released => Ok(()),
        }
    }
    pub(crate) fn ledger(&self, ledger: &crate::resources::Ledger) -> Result<()> {
        self.receipt_at(
            &self.usage()?,
            crate::workflow_resource::committed_receipt(ledger, &self.lease)?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub action: String,
    pub request_id: String,
    pub deadline: u64,
    pub job: String,
    pub descriptor: Descriptor,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.action != "resource-content-output-open"
            || !self.request_id.starts_with("console-")
            || self.request_id.len() != 40
            || crate::tpm::decode::<16>(&self.job).is_err()
        {
            return Err("invalid closed content output opening".into());
        }
        deadline(self.deadline, 4000)?;
        self.descriptor.usage()?;
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
    pub descriptor: Descriptor,
    pub client_pid: u32,
    pub client_start: u64,
}
fn deadline(value: u64, bound: u64) -> Result<()> {
    let now = resource_manager::now()?;
    if value <= now
        || value
            > now
                .checked_add(bound)
                .ok_or("content output deadline overflow")?
    {
        return Err("content output proof deadline expired or substituted".into());
    }
    Ok(())
}
impl Guard {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.action != "resource-content-output-guard"
            || crate::tpm::decode::<16>(&self.request_id).is_err()
            || crate::tpm::decode::<16>(&self.job).is_err()
            || self.client_pid == 0
            || self.client_start == 0
        {
            return Err("invalid closed content output guard".into());
        }
        deadline(self.deadline, 3000)?;
        self.descriptor.usage()?;
        Ok(())
    }
}

// Kernel procfs plus the existing exact-argv/immutable-snapshot verifier binds
// the requested owner to the actual original command, not a supplied SID/JSON.
fn original_binding(pid: u32, descriptor: &Descriptor, audit: &Audit) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/cmdline"))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0
        || stat.f_type != 0x9fa0
        || file.metadata()?.uid() != 0
    {
        return Err("content output original command is not kernel-owned procfs".into());
    }
    let mut raw = Vec::new();
    file.take(4097).read_to_end(&mut raw)?;
    if raw.len() > 4096 {
        return Err("content output original command exceeds bound".into());
    }
    let text = std::str::from_utf8(&raw)?;
    let args: Vec<_> = text.split('\0').collect();
    crate::content_governed::check_client_arguments(&args, &descriptor.profile, Some(audit))?;
    let path = match args.len() {
        6 => args[4],
        8 => args[6],
        _ => return Err("content output command shape differs".into()),
    };
    if crate::content_governed::verify_client_request(
        Path::new(path),
        &descriptor.profile,
        args[2],
    )? != descriptor.binding
        || audit.subject != descriptor.binding.owner
        || audit.subject_generation != descriptor.binding.owner_generation
    {
        return Err("content output owner differs from actual original immutable input".into());
    }
    Ok(())
}

pub(crate) struct Authority {
    admission: granted_gateway::Admission,
    job: String,
    descriptor: Descriptor,
    client_pid: u32,
    client_start: u64,
}
impl Authority {
    pub(crate) fn capture(socket: &UnixStream, request: &Request) -> Result<Self> {
        request.validate()?;
        let peer = credentials(socket)?;
        let pin = peer_pidfd(socket)?;
        let client_start = resource_manager::content_client_generation(peer, &pin)?;
        let usage = request.descriptor.installed_usage()?;
        // A NEW proof phase for this live original controller; it has no worker
        // admission/token, does not reactivate a released lease and selects no
        // Admin role. Effect profiles retain the full original Read/effect pair.
        let admission = granted_gateway::Admission::capture_acquisition(
            socket,
            &request.job,
            &request.descriptor.profile,
            usage.clone(),
            usage.selector.digest,
        )?;
        original_binding(
            peer.pid as u32,
            &request.descriptor,
            admission.attribution()?,
        )?;
        admission.acquisition_liveness()?;
        Ok(Self {
            admission,
            job: request.job.clone(),
            descriptor: request.descriptor.clone(),
            client_pid: peer.pid as u32,
            client_start,
        })
    }
    pub(crate) fn check(&mut self) -> Result<()> {
        self.descriptor.installed_usage()?;
        self.admission.acquisition_liveness()?;
        self.admission.check()?;
        original_binding(
            self.client_pid,
            &self.descriptor,
            self.admission.attribution()?,
        )
    }
    pub(crate) fn guard(&mut self, request: &Guard) -> Result<Audit> {
        request.validate()?;
        if request.job != self.job
            || request.descriptor != self.descriptor
            || request.client_pid != self.client_pid
            || request.client_start != self.client_start
        {
            return Err("content output guard substituted original controller or receipt".into());
        }
        self.check()?;
        Ok(self.admission.attribution()?.clone())
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
    let end = Instant::now() + Duration::from_secs(3);
    let mut socket = connect_local(SOCKET, end)?;
    if credentials(&socket)?.uid != 0 {
        return Err("content output proof broker is not root".into());
    }
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    write_frame_until(&mut socket, &serde_json::to_vec(request)?, end)?;
    let reply: Reply = serde_json::from_slice(&read_frame_until(&mut socket, end)?)?;
    if reply.schema_version != 1
        || reply.result != "ok"
        || reply.request_id != request.request_id
        || reply.audit.usage != request.descriptor.usage()?
        || reply.audit.subject != request.descriptor.binding.owner
        || reply.audit.subject_generation != request.descriptor.binding.owner_generation
    {
        return Err("content output original proof refused or substituted".into());
    }
    reply.audit.validate()?;
    request.validate()?;
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    Ok(reply.audit)
}

pub(crate) struct Proof {
    job: String,
    descriptor: Descriptor,
    cancel: Arc<AtomicBool>,
}
impl Proof {
    pub(crate) fn check(&self) -> Result<()> {
        self.local()?;
        crate::content_checkpoint::custody::check_output(
            &self.job,
            &self.descriptor,
            &self.cancel,
        )?;
        self.local()
    }
    fn local(&self) -> Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            return Err("original content output controller fenced".into());
        }
        Ok(())
    }
}

pub(crate) fn run<T: Send>(
    id: &str,
    binding: &OwnerBinding,
    lease: &Token,
    output_sha256: &str,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    controller: impl FnOnce(Proof) -> Result<T> + Send,
) -> Result<T> {
    let descriptor = Descriptor {
        profile: id.into(),
        storage_device: resource_manager::storage_device(Path::new("/var"))?,
        binding: binding.clone(),
        lease: lease.clone(),
        output_sha256: output_sha256.into(),
    };
    let usage = descriptor.usage()?;
    boundary.check()?;
    let end = Instant::now() + Duration::from_secs(4);
    let mut socket = connect_local(SOCKET, end)?;
    if credentials(&socket)?.uid != 0 {
        return Err("content output broker is not root".into());
    }
    crate::content_checkpoint::custody::verify_broker(&socket)?;
    let job = crate::resources::random_id()?;
    let request = Request {
        schema_version: 1,
        action: "resource-content-output-open".into(),
        request_id: fresh_request_id()?,
        deadline: resource_manager::now()?
            .checked_add(4000)
            .ok_or("content output opening overflow")?,
        job: job.clone(),
        descriptor: descriptor.clone(),
    };
    request.validate()?;
    write_frame_until(&mut socket, &serde_json::to_vec(&request)?, end)?;
    loop {
        let raw = read_frame_until(&mut socket, end)?;
        let value: serde_json::Value = serde_json::from_slice(&raw)?;
        if value["kind"].as_str() == Some("grant-challenge") {
            let reply = granted_gateway::acquisition_proof(
                &raw,
                &job,
                &usage,
                &usage.selector.digest,
                boundary,
                false,
                None,
            )?;
            write_frame_until(&mut socket, &reply, end)?;
        } else if value
            == serde_json::json!({"schema_version":1,"result":"ok","request_id":request.request_id,"job":job})
        {
            break;
        } else {
            return Err("content output original registration refused".into());
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let result = std::thread::scope(|scope| -> Result<T> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let child_cancel = cancel.clone();
        let child = scope.spawn(move || {
            let value = controller(Proof {
                job: job.clone(),
                descriptor,
                cancel: child_cancel,
            })
            .map_err(|e| e.to_string());
            let _ = sender.send(value);
        });
        let result = (|| -> Result<T> {
            let total = Instant::now() + Duration::from_secs(30);
            loop {
                remaining(total)?;
                boundary.check()?;
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 100) } < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err("content output original broker connection lost".into());
                }
                if poll.revents & libc::POLLIN != 0 {
                    let end = Instant::now() + Duration::from_secs(3);
                    let raw = read_frame_until(&mut socket, end)?;
                    let reply = granted_gateway::acquisition_proof(
                        &raw,
                        &request.job,
                        &usage,
                        &usage.selector.digest,
                        boundary,
                        false,
                        None,
                    )?;
                    write_frame_until(&mut socket, &reply, end)?;
                }
                match receiver.try_recv() {
                    Ok(Ok(value)) => {
                        boundary.check()?;
                        return Ok(value);
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("content output controller outcome missing".into())
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
        })();
        cancel.store(true, Ordering::Release);
        let _ = socket.shutdown(std::net::Shutdown::Both);
        if child.join().is_err() {
            return Err("content output controller panicked; partial delivery possible".into());
        }
        result
    });
    cancel.store(true, Ordering::Release);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor() -> Descriptor {
        Descriptor {
            profile: format!(
                "content-v1-envelope-7-{}-{}",
                "a".repeat(64),
                "a".repeat(64)
            ),
            storage_device: "8:1".into(),
            binding: OwnerBinding {
                installation: "11".repeat(32),
                owner: "22".repeat(32),
                owner_generation: 7,
            },
            lease: Token {
                lease_id: "33".repeat(16),
                generation: 1,
                manager_epoch: "44".repeat(16),
            },
            output_sha256: "55".repeat(32),
        }
    }
    fn receipt(value: &Descriptor, usage: &Use) -> serde_json::Value {
        serde_json::json!({"binding":usage.selector.digest,"lease":value.lease,"output_sha256":value.output_sha256,
            "output_domain_epochs":{"acquisition-executions":"1","host-memory":"1","worker-processes":"1"},
            "state":"released","physical_release_granted":false})
    }
    #[test]
    fn current_output_descriptor_is_bound_to_closed_profile_owner_and_resource_receipt() {
        let value = descriptor();
        let usage = value.data_usage_at("8:1").unwrap();
        assert_eq!(usage.action, crate::finite_grants::Action::Read);
        assert_eq!(usage.selector.id, "native-content-envelope-v1");
        value.receipt_at(&usage, receipt(&value, &usage)).unwrap();
        for (field, changed) in [
            ("binding", serde_json::json!("f".repeat(64))),
            ("output_sha256", serde_json::json!("f".repeat(64))),
            ("physical_release_granted", serde_json::json!(true)),
            (
                "output_domain_epochs",
                serde_json::json!({"host-memory":"1"}),
            ),
            ("state", serde_json::json!("unknown")),
        ] {
            let mut wrong = receipt(&value, &usage);
            wrong[field] = changed;
            assert!(value.receipt_at(&usage, wrong).is_err());
        }
        let mut wrong = receipt(&value, &usage);
        wrong["lease"]["generation"] = serde_json::json!("2");
        assert!(value.receipt_at(&usage, wrong).is_err());
        let mut wrong = value.clone();
        wrong.binding.owner_generation += 1;
        assert!(wrong.data_usage_at("8:1").is_err());
        let mut wrong = value.clone();
        wrong.profile = format!("qa-v1-{}", "a".repeat(64));
        assert!(wrong.data_usage_at("8:1").is_err());
        let mut wrong = value.clone();
        wrong.lease.generation = 0;
        assert!(wrong.data_usage_at("8:1").is_err());
        let mut wrong = value;
        wrong.output_sha256 = "not-a-digest".into();
        assert!(wrong.data_usage_at("8:1").is_err());
    }
    #[test]
    fn output_registration_and_guard_are_closed_distinct_non_admin_protocols() {
        let value = descriptor();
        let request = Request {
            schema_version: 1,
            action: "resource-content-output-open".into(),
            request_id: "console-".to_string() + &"1".repeat(32),
            deadline: 1,
            job: "2".repeat(32),
            descriptor: value.clone(),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.descriptor, value);
        assert!(parsed.validate().is_err());
        let mut extra = serde_json::to_value(&request).unwrap();
        extra["Admin"] = true.into();
        assert!(serde_json::from_value::<Request>(extra).is_err());
        assert!(serde_json::from_slice::<Guard>(&bytes).is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            '{',
            "{\"job\":\"00000000000000000000000000000000\",",
            1,
        );
        assert!(serde_json::from_str::<Request>(&duplicate).is_err());
    }
}
