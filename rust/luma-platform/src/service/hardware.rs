//! An owned live resource-configuration handoff. A reply or copied descriptor
//! alone never authorizes a device write; original PAM and current TPM intent
//! are checked independently by the hardware controller.
use super::*;
use crate::hardware_policy::{
    exclusion::{Held, Locks},
    handoff::{Purpose, Reply, Request},
    hash, Intent,
};

pub(crate) struct Handoff {
    intent: Intent,
    socket: UnixStream,
    peer: libc::ucred,
    pin: fs::File,
    exclusion: Held,
    allocation_deadline: Option<u64>,
}

fn request(intent: &Intent, action: &str, purpose: Option<Purpose>) -> Result<Request> {
    intent.validate()?;
    let request = Request {
        schema_version: 1,
        action: action.into(),
        request_id: crate::resources::random_id()?,
        transaction: intent.transaction.clone(),
        intent_sha256: hash(intent)?,
        deadline: resource_manager::now()?
            .checked_add(3000)
            .ok_or("hardware handoff deadline overflow")?,
        purpose,
    };
    request.validate(resource_manager::now()?)?;
    Ok(request)
}

fn broker(socket: &UnixStream, peer: libc::ucred, pin: &fs::File) -> Result<()> {
    let current = credentials(socket)?;
    if peer.pid <= 0
        || peer.uid != 0
        || peer.gid != 0
        || current.pid != peer.pid
        || current.uid != peer.uid
        || current.gid != peer.gid
    {
        return Err("hardware handoff broker credentials changed".into());
    }
    crate::credential_observer::kernel_check(pin, 0, 0)?;
    crate::content_checkpoint::custody::verify_broker(socket)
}

impl Handoff {
    /// The original Manager retains the same kernel EX description before
    /// sending it. Failure after this request may retain exclusion; callers
    /// must report uncertainty rather than retrying an effect or minting a new
    /// transaction with the same device.
    pub(crate) fn open(intent: &Intent, purpose: Purpose) -> Result<Self> {
        let worker = intent
            .target
            .worker
            .ok_or("a global device must not borrow a worker handoff")?;
        let request = request(intent, "hardware-handoff-open", Some(purpose))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut socket = connect_local(SOCKET, deadline)?;
        let peer = credentials(&socket)?;
        let pin = peer_pidfd(&socket)?;
        broker(&socket, peer, &pin)?;
        write_frame_until(&mut socket, &serde_json::to_vec(&request)?, deadline)?;
        // The descriptor header is deliberately separate from the following
        // JSON frame. No deserialized JSON can fabricate an OFD ownership.
        let exclusion = Locks::installed()?.receive(&socket, worker, &request.binding()?)?;
        let bytes = read_frame_until(&mut socket, deadline)?;
        let reply: Reply = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&serde_json::to_value(&reply)?)? != bytes {
            return Err("noncanonical hardware handoff reply".into());
        }
        reply.validate(&request, intent)?;
        request.validate(resource_manager::now()?)?;
        let handoff = Self {
            intent: intent.clone(),
            socket,
            peer,
            pin,
            exclusion,
            allocation_deadline: reply.allocation.map(|window| window.deadline_ms),
        };
        if purpose == Purpose::Apply {
            handoff.check(intent)?;
        } else {
            handoff.check_restore(intent)?;
        }
        Ok(handoff)
    }

    /// Local checks only: never make a broker/Admin RPC from a device callback
    /// while holding the Admin journal lock. Kernel EX survives Manager death;
    /// a restarted Manager separately reconstructs current TPM obligations
    /// before any new resource admission. This is not an atomic device CAS.
    pub(crate) fn check(&self, intent: &Intent) -> Result<()> {
        self.check_restore(intent)?;
        if self
            .allocation_deadline
            .is_some_and(|deadline| resource_manager::now().map_or(true, |now| now >= deadline))
        {
            return Err("hardware APPLY cannot outlive its original allocation window".into());
        }
        broker(&self.socket, self.peer, &self.pin)?;
        self.exclusion.check()?;
        let mut byte = 0u8;
        let count = unsafe {
            libc::recv(
                self.socket.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if count >= 0 {
            return Err("hardware handoff broker disconnected or sent an unexpected frame".into());
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN) {
            return Err("hardware handoff channel liveness is unknown".into());
        }
        Ok(())
    }

    /// Only precommitted undo, independently checked against current TPM and
    /// actual device generation by the caller. The same owned EX excludes new
    /// admission even after Manager death; no process can recreate it from an
    /// old JSON receipt. It grants neither an active allocation nor new policy.
    pub(crate) fn check_restore(&self, intent: &Intent) -> Result<()> {
        if &self.intent != intent || intent.target.boot != crate::hardware_policy::current_boot()? {
            return Err("hardware handoff substitutes its committed intent or boot".into());
        }
        self.exclusion.check()
    }

    /// Only after an independently TPM-committed Restored/Reconciled event.
    /// The Manager checks that state itself. Closing this object alone does
    /// not assert drainage or release a resource allocation.
    pub(crate) fn finish(self) -> Result<()> {
        self.check_restore(&self.intent)?;
        let request = request(&self.intent, "hardware-handoff-finish", None)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut socket = connect_local(SOCKET, deadline)?;
        let peer = credentials(&socket)?;
        let pin = peer_pidfd(&socket)?;
        broker(&socket, peer, &pin)?;
        if peer.pid != self.peer.pid {
            return Err("a restarted resource Manager cannot finish the old handoff".into());
        }
        write_frame_until(&mut socket, &serde_json::to_vec(&request)?, deadline)?;
        let bytes = read_frame_until(&mut socket, deadline)?;
        let reply: Reply = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&serde_json::to_value(&reply)?)? != bytes {
            return Err("noncanonical hardware handoff completion".into());
        }
        reply.validate(&request, &self.intent)?;
        broker(&socket, peer, &pin)?;
        request.validate(resource_manager::now()?)?;
        self.exclusion.check()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoff_envelopes_bind_full_activation_not_just_the_reusable_plan_digest() {
        let intent = crate::hardware_policy::tests::intent();
        let first = request(&intent, "hardware-handoff-open", Some(Purpose::Apply)).unwrap();
        let second = request(
            &intent,
            "hardware-handoff-open",
            Some(Purpose::CommittedCleanup),
        )
        .unwrap();
        assert_ne!(first.request_id, second.request_id);
        assert_ne!(first.binding().unwrap(), second.binding().unwrap());
        assert_eq!(first.intent_sha256, hash(&intent).unwrap());
        assert_ne!(first.intent_sha256, intent.digest().unwrap());
        assert!(request(&intent, "resource-acquire", Some(Purpose::Apply)).is_err());
        assert!(request(&intent, "hardware-handoff-finish", Some(Purpose::Apply)).is_err());
        request(&intent, "hardware-handoff-finish", None).unwrap();
    }
}
