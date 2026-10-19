//! C availability for the actual original controller after worker completion.
//! Responses describe current state; no JSON receipt is a reusable capability.
use super::*;
use crate::service::content_output::Descriptor;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub(super) const PURPOSE: &str = "luma-content-private-output-current-v1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    purpose: String,
    request_id: String,
    job: String,
    descriptor: Descriptor,
}
impl Request {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.purpose != PURPOSE
            || tpm::decode::<16>(&self.request_id).is_err()
            || tpm::decode::<16>(&self.job).is_err()
        {
            return Err("invalid closed private output current-C request".into());
        }
        self.descriptor.usage()?;
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    result: String,
    request_sha256: String,
    state: VerifiedState,
}

pub(crate) fn exchange(job: &str, descriptor: &Descriptor, cancel: &Arc<AtomicBool>) -> Result<()> {
    let check = || -> Result<()> {
        if cancel.load(Ordering::Acquire) {
            Err("original private output controller cancelled".into())
        } else {
            Ok(())
        }
    };
    check()?;
    let request = Request {
        schema_version: 1,
        purpose: PURPOSE.into(),
        request_id: random()?,
        job: job.into(),
        descriptor: descriptor.clone(),
    };
    request.validate()?;
    let bytes = serde_json::to_vec(&request)?;
    let end = Instant::now() + Duration::from_secs(3);
    let mut stream = crate::service::connect_local(SOCKET, end)?;
    if crate::service::credentials(&stream)?.uid != 0 {
        return Err("private output C service is not root".into());
    }
    peer_label(&stream, "luma-content-custody (enforce)")?;
    check()?;
    write(&mut stream, &bytes, end)?;
    let response: Response = canonical(&read(&mut stream, end)?, 4096)?;
    check()?;
    peer_label(&stream, "luma-content-custody (enforce)")?;
    response.state.validate()?;
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
        || response.state.binding != descriptor.binding
    {
        return Err(
            "private output current-C response differs from exact original operation".into(),
        );
    }
    Ok(())
}

pub(super) fn handle(
    stream: &mut UnixStream,
    confinement: confinement::KernelUnix,
    bytes: &[u8],
) -> Result<()> {
    let request: Request = canonical(bytes, 8192)?;
    request.validate()?;
    let end = Instant::now() + Duration::from_secs(3);
    let peer = crate::service::credentials(stream)?;
    if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 {
        return Err("private output requires actual original granted client".into());
    }
    peer_label(stream, "luma-granted-client (enforce)")?;
    let pin = crate::service::peer_pidfd(stream)?;
    let generation = start(peer.pid as u32)?;
    let original = || -> Result<Audit> {
        confinement.check()?;
        remaining(end)?;
        pidfd_alive(&pin)?;
        let now = crate::service::credentials(stream)?;
        if (now.pid, now.uid, now.gid) != (peer.pid, peer.uid, peer.gid)
            || start(peer.pid as u32)? != generation
        {
            return Err("private output original client generation changed".into());
        }
        // The fresh broker guard below observes every original task's current
        // kernel credentials through its retained Admission pidfd. C remains
        // capability-free and never gains cross-process ptrace privileges.
        peer_label(stream, "luma-granted-client (enforce)")?;
        let guard = crate::service::content_output::Guard {
            schema_version: 1,
            action: "resource-content-output-guard".into(),
            request_id: random()?,
            deadline: crate::resource_manager::now()?
                .checked_add(3000)
                .ok_or("private output deadline overflow")?,
            job: request.job.clone(),
            descriptor: request.descriptor.clone(),
            client_pid: peer.pid as u32,
            client_start: generation,
        };
        let audit = crate::service::content_output::proof(&guard)?;
        remaining(end)?;
        pidfd_alive(&pin)?;
        Ok(audit)
    };
    let initial = original()?;
    let mut live = || -> Result<()> {
        if original()? != initial {
            return Err("private output original finite attribution changed".into());
        }
        Ok(())
    };
    let mut store = Store::installed(&mut live)?;
    // Same actual protected semantic selector used by worker reads. Retirement,
    // rollback, uncertainty, missing history or substitution all refuse here.
    let state = store.selected(&request.descriptor.binding, &mut live)?;
    live()?;
    let response = Response {
        schema_version: 1,
        result: "ok".into(),
        request_sha256: hash(bytes),
        state,
    };
    let encoded = serde_json::to_vec(&response)?;
    if encoded.len() > 4096 {
        return Err("private output current-C response exceeds bound".into());
    }
    live()?;
    write(stream, &encoded, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            purpose: PURPOSE.into(),
            request_id: "11".repeat(16),
            job: "22".repeat(16),
            descriptor: Descriptor {
                profile: format!("content-v1-query-1-{}-{}", "a".repeat(64), "a".repeat(64)),
                storage_device: "8:1".into(),
                binding: OwnerBinding {
                    installation: "33".repeat(32),
                    owner: "44".repeat(32),
                    owner_generation: 1,
                },
                lease: Token {
                    lease_id: "55".repeat(16),
                    generation: 1,
                    manager_epoch: "66".repeat(16),
                },
                output_sha256: "77".repeat(32),
            },
        }
    }
    #[test]
    fn current_output_request_cannot_cross_admin_or_change_its_closed_canonical_purpose() {
        let request = request();
        request.validate().unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        canonical::<Request>(&bytes, 8192).unwrap();
        assert!(canonical::<AdminRequest>(&bytes, MAX_FRAME).is_err());
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["purpose"] = "content-admin".into();
        let parsed: Request = serde_json::from_value(unknown).unwrap();
        assert!(parsed.validate().is_err());
        let mut extra = serde_json::to_value(&request).unwrap();
        extra["command"] = "content-restore-retire".into();
        assert!(serde_json::from_value::<Request>(extra).is_err());
        let mut trailing = bytes;
        trailing.push(b' ');
        assert!(canonical::<Request>(&trailing, 8192).is_err());
    }
}
