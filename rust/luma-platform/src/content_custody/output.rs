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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<VerifiedState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paged_head_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    index_selection_sha256: Option<String>,
}
fn validate_selection(response: &Response, descriptor: &Descriptor) -> Result<()> {
    if descriptor.index_source()?.is_some() {
        if response.state.is_some()
            || response.paged_head_sha256.is_some()
            || response.index_selection_sha256.as_ref()
                != descriptor.index.as_ref().map(|p| &p.selection_sha256)
        {
            return Err(
                "private index output changed actual C selection or mixed response formats".into(),
            );
        }
        return digest(
            response
                .index_selection_sha256
                .as_ref()
                .ok_or("index output selection missing")?,
        );
    }
    if response.index_selection_sha256.is_some() {
        return Err("legacy/Page output cannot borrow index provenance".into());
    }
    match (
        descriptor.page_source()?,
        &response.state,
        &response.paged_head_sha256,
    ) {
        (None, Some(state), None) if state.binding == descriptor.binding => state.validate(),
        (Some(_), None, Some(head)) if Some(head) == descriptor.paged_head_sha256.as_ref() => {
            digest(head)
        }
        _ => Err("private output response changed exact legacy/paged selection".into()),
    }
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
    if response.schema_version != 1
        || response.result != "ok"
        || response.request_sha256 != hash(&bytes)
    {
        return Err(
            "private output current-C response differs from exact original operation".into(),
        );
    }
    validate_selection(&response, descriptor)?;
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
    let peer_socket = stream.try_clone()?;
    let original = || -> Result<Audit> {
        confinement.check()?;
        remaining(end)?;
        pidfd_alive(&pin)?;
        let now = crate::service::credentials(&peer_socket)?;
        if (now.pid, now.uid, now.gid) != (peer.pid, peer.uid, peer.gid)
            || start(peer.pid as u32)? != generation
        {
            return Err("private output original client generation changed".into());
        }
        // The fresh broker guard below observes every original task's current
        // kernel credentials through its retained Admission pidfd. C remains
        // capability-free and never gains cross-process ptrace privileges.
        peer_label(&peer_socket, "luma-granted-client (enforce)")?;
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
    if request.descriptor.index_source()?.is_some() {
        let expected = &request
            .descriptor
            .index
            .as_ref()
            .ok_or("index output source missing")?
            .selection_sha256;
        let mut store = super::super::v2_publication::PagedStore::installed(&mut live)?;
        let mut current = || {
            super::super::indexed_output::require(&request.descriptor, &initial, &mut live)?;
            let selected = store.selected_index(&request.descriptor.binding, &mut live)?;
            if super::super::indexed::selection_sha256(&selected)? != *expected {
                return Err(
                    "private index output exact current owner/index selection changed".into(),
                );
            }
            super::super::indexed_output::require(&request.descriptor, &initial, &mut live)
        };
        current()?;
        let response = Response {
            schema_version: 1,
            result: "ok".into(),
            request_sha256: hash(bytes),
            state: None,
            paged_head_sha256: None,
            index_selection_sha256: Some(expected.clone()),
        };
        return write_live(stream, &serde_json::to_vec(&response)?, end, &mut current);
    }
    if let Some(page) = request.descriptor.page_source()? {
        page.check_original(&initial)?;
        let expected = request
            .descriptor
            .paged_head_sha256
            .as_ref()
            .ok_or("paged output head missing")?;
        let mut store = super::super::v2_publication::PagedStore::installed(&mut live)?;
        let mut current = || {
            super::super::observed::require_output_observation(
                &request.descriptor,
                &initial,
                &mut live,
            )?;
            match store.selected_owner(&request.descriptor.binding, &mut live)? {
                super::super::v2_publication::SelectedOwner::Paged { head, .. }
                    if head.sha256()? == *expected =>
                {
                    ()
                }
                _ => return Err("private Page output exact current owner head changed".into()),
            }
            super::super::observed::require_output_observation(
                &request.descriptor,
                &initial,
                &mut live,
            )
        };
        current()?;
        let response = Response {
            schema_version: 1,
            result: "ok".into(),
            request_sha256: hash(bytes),
            state: None,
            paged_head_sha256: Some(expected.clone()),
            index_selection_sha256: None,
        };
        let encoded = serde_json::to_vec(&response)?;
        if encoded.len() > 4096 {
            return Err("paged output response exceeds existing bound".into());
        }
        return write_live(stream, &encoded, end, &mut current);
    }
    let mut store = Store::installed(&mut live)?;
    // Same actual protected semantic selector used by worker reads. Retirement,
    // rollback, uncertainty, missing history or substitution all refuse here.
    let state = store.selected(&request.descriptor.binding, &mut live)?;
    live()?;
    let response = Response {
        schema_version: 1,
        result: "ok".into(),
        request_sha256: hash(bytes),
        state: Some(state),
        paged_head_sha256: None,
        index_selection_sha256: None,
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
                paged_head_sha256: None,
                paged_source: None,
                index: None,
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
    #[test]
    fn paged_reply_cannot_strip_substitute_or_cross_legacy_selection() {
        let descriptor = crate::service::content_output::paged_tests::fixture();
        let mut response = Response {
            schema_version: 1,
            result: "ok".into(),
            request_sha256: "99".repeat(32),
            state: None,
            paged_head_sha256: descriptor.paged_head_sha256.clone(),
            index_selection_sha256: None,
        };
        validate_selection(&response, &descriptor).unwrap();
        response.paged_head_sha256 = Some("aa".repeat(32));
        assert!(validate_selection(&response, &descriptor).is_err());
        response.paged_head_sha256 = None;
        assert!(validate_selection(&response, &descriptor).is_err());
        response.state = Some(VerifiedState::empty(&descriptor.binding).unwrap());
        assert!(validate_selection(&response, &descriptor).is_err());
        let mut stripped = descriptor.clone();
        stripped.paged_source = None;
        assert!(validate_selection(&response, &stripped).is_err());
        stripped.paged_head_sha256 = None;
        validate_selection(&response, &stripped).unwrap();
        response.state = None;
        response.paged_head_sha256 = descriptor.paged_head_sha256.clone();
        assert!(validate_selection(&response, &stripped).is_err());
    }
    #[test]
    fn index_reply_cannot_strip_mix_or_substitute_current_selection() {
        let descriptor = super::super::super::indexed_output::tests::descriptor();
        let expected = descriptor.index.as_ref().unwrap().selection_sha256.clone();
        let mut response = Response {
            schema_version: 1,
            result: "ok".into(),
            request_sha256: "99".repeat(32),
            state: None,
            paged_head_sha256: None,
            index_selection_sha256: Some(expected.clone()),
        };
        validate_selection(&response, &descriptor).unwrap();
        response.index_selection_sha256 = Some("aa".repeat(32));
        assert!(validate_selection(&response, &descriptor).is_err());
        response.index_selection_sha256 = None;
        assert!(validate_selection(&response, &descriptor).is_err());
        response.index_selection_sha256 = Some(expected);
        response.paged_head_sha256 = Some("aa".repeat(32));
        assert!(validate_selection(&response, &descriptor).is_err());
        response.paged_head_sha256 = None;
        response.state = Some(VerifiedState::empty(&descriptor.binding).unwrap());
        assert!(validate_selection(&response, &descriptor).is_err());
        let legacy = request().descriptor;
        assert!(validate_selection(&response, &legacy).is_err());
    }
}
