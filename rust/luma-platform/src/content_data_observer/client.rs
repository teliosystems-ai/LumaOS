use super::*;
use luma_content_store::v2::readonly::ObservedPageReader;
use std::collections::BTreeMap;
use std::net::Shutdown;

/// Owns its socket while borrowing the genuine original C operation's live
/// check for the entire lifetime. Serialized Context is never that operation.
pub(crate) struct Client<'a> {
    socket: UnixStream,
    peer: endpoint::Peer,
    original: &'a mut dyn FnMut() -> Result<()>,
    context: Context,
    sha: String,
    session: String,
    sequence: u32,
    namespace: NamespaceObservationData,
    #[cfg_attr(not(test), allow(dead_code))]
    slots: BTreeMap<String, (u8, RawObjectObservationData)>,
    closed: bool,
}
impl<'a> Client<'a> {
    pub(crate) fn begin(
        context: Context,
        original: &'a mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        original()?;
        context.validate()?;
        let before = server::check_paths()?;
        let socket =
            crate::service::connect_local(SOCKET, Instant::now() + Duration::from_millis(RPC_MS))?;
        let peer = endpoint::Peer::capture(&socket, OBSERVER)?;
        if server::check_paths()? != before {
            return Err("observer fixed socket inode changed during connection".into());
        }
        Self::begin_pinned(socket, peer, context, original)
    }
    pub(super) fn begin_pinned(
        socket: UnixStream,
        peer: endpoint::Peer,
        context: Context,
        original: &'a mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        original()?;
        context.validate()?;
        let sha = context.sha256()?;
        let request = Request {
            schema_version: 1,
            nonce: crate::resources::random_id()?,
            deadline_ms: now()?
                .checked_add(RPC_MS)
                .ok_or("observer client deadline overflow")?,
            session_id: None,
            sequence: 0,
            context_sha256: sha.clone(),
            operation: Operation::Begin {
                context: context.clone(),
            },
        };
        let bytes = serde_json::to_vec(&request)?;
        let deadline = Instant::now() + Duration::from_millis(RPC_MS);
        let mut check = || {
            original()?;
            peer.check(&socket)
        };
        wire::send(&socket, &bytes, deadline, &mut check)?;
        let response: Response = canonical(&wire::receive(&socket, deadline, &mut check)?)?;
        check()?;
        if response.schema_version != 1
            || response.nonce != request.nonce
            || response.sequence != 0
            || response.request_sha256 != luma_content::sha256(&bytes)
            || response.context_sha256 != sha
            || !nonce(&response.session_id)
        {
            return Err("observer Begin response substituted original request/context".into());
        }
        let namespace = match response.data {
            Data::Begun { namespace }
                if namespace.schema_version == 1 && namespace.binding == context.binding =>
            {
                namespace
            }
            _ => return Err("observer Begin namespace data differs".into()),
        };
        data::namespace(&namespace, &context.binding)?;
        original()?;
        peer.check(&socket)?;
        Ok(Self {
            socket,
            peer,
            original,
            context,
            sha,
            session: response.session_id,
            sequence: 1,
            namespace,
            slots: BTreeMap::new(),
            closed: false,
        })
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn namespace_data(&self) -> &NamespaceObservationData {
        &self.namespace
    }
    #[cfg(test)]
    pub(super) fn retained_count(&self) -> usize {
        self.slots.len()
    }
    fn poison<T>(&mut self, error: Box<dyn std::error::Error>) -> Result<T> {
        self.closed = true;
        let _ = self.socket.shutdown(Shutdown::Both);
        Err(error)
    }
    fn delivery_check(&mut self, extra: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let observed = (|| {
            (self.original)()?;
            extra()?;
            self.peer.check(&self.socket)
        })();
        match observed {
            Ok(()) => Ok(()),
            Err(error) => self.poison(error),
        }
    }
    fn rpc(&mut self, operation: Operation, extra: &mut dyn FnMut() -> Result<()>) -> Result<Data> {
        if self.closed || self.sequence >= MAX_RPCS {
            return Err("observer original query session is closed/exhausted".into());
        }
        let request = Request {
            schema_version: 1,
            nonce: crate::resources::random_id()?,
            deadline_ms: now()?
                .checked_add(RPC_MS)
                .ok_or("observer client deadline overflow")?,
            session_id: Some(self.session.clone()),
            sequence: self.sequence,
            context_sha256: self.sha.clone(),
            operation,
        };
        let bytes = serde_json::to_vec(&request)?;
        let deadline = Instant::now() + Duration::from_millis(RPC_MS);
        let mut check = || {
            (self.original)()?;
            extra()?;
            self.peer.check(&self.socket)
        };
        let exchanged = (|| -> Result<Response> {
            check()?;
            wire::send(&self.socket, &bytes, deadline, &mut check)?;
            let response = canonical(&wire::receive(&self.socket, deadline, &mut check)?)?;
            check()?;
            Ok(response)
        })();
        let response = match exchanged {
            Ok(value) => value,
            Err(error) => {
                self.closed = true;
                let _ = self.socket.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        if response.schema_version != 1
            || response.nonce != request.nonce
            || response.sequence != request.sequence
            || response.request_sha256 != luma_content::sha256(&bytes)
            || response.context_sha256 != self.sha
            || response.session_id != self.session
        {
            self.closed = true;
            let _ = self.socket.shutdown(Shutdown::Both);
            return Err("observer response changed original nonce/source/sequence/session".into());
        }
        self.sequence += 1;
        Ok(response.data)
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn observe(
        &mut self,
        object: &str,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Vec<u8>, RawObjectObservationData)> {
        if !hash(object) {
            return Err("observer requires exact raw SHA selector".into());
        }
        let previous = self.slots.get(object).cloned();
        let old = previous.as_ref().map(|(slot, _)| *slot);
        if old.is_none() && self.slots.len() >= MAX_OBSERVATIONS {
            return Err("observer retained observation capacity exhausted before RPC".into());
        }
        let operation = match old {
            Some(slot) => Operation::Recheck { slot },
            None => Operation::Observe {
                object_sha256: object.into(),
            },
        };
        let data = self.rpc(operation, check)?;
        let (slot, observation, value) = match (old, data) {
            (
                None,
                Data::Observed {
                    slot,
                    object,
                    bytes_hex,
                },
            ) if usize::from(slot) == self.slots.len() => (slot, object, bytes_hex),
            (
                Some(expected),
                Data::Rechecked {
                    slot,
                    object,
                    bytes_hex,
                },
            ) if expected == slot => (slot, object, bytes_hex),
            _ => return self.poison("observer raw response kind/slot differs".into()),
        };
        let bytes = match decode_hex(&value) {
            Ok(bytes) => bytes,
            Err(error) => return self.poison(error),
        };
        if let Err(error) = data::raw(&observation, object, &bytes, &self.namespace) {
            return self.poison(error);
        }
        if previous
            .as_ref()
            .is_some_and(|(_, initial)| initial != &observation)
        {
            return self.poison("observer recheck changed original retained transcript".into());
        }
        if old.is_none() {
            self.slots
                .insert(object.into(), (slot, observation.clone()));
        }
        self.delivery_check(check)?;
        Ok((bytes, observation))
    }
    pub(crate) fn finish(mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if !matches!(self.rpc(Operation::End, check)?, Data::Closed) {
            return Err("observer omitted explicit End acknowledgement".into());
        }
        self.delivery_check(check)?;
        self.closed = true;
        self.socket.shutdown(Shutdown::Both)?;
        Ok(())
    }
}
impl ObservedPageReader for Client<'_> {
    fn read_observed_page(
        &mut self,
        binding: &OwnerBinding,
        sha256: &str,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.delivery_check(check)?;
        if binding != &self.context.binding
            || maximum == 0
            || maximum > luma_content_store::v2::MAX_PAGE_BYTES
        {
            return Err("observed Merkle reader changed exact owner/read bound".into());
        }
        if !hash(sha256) {
            return Err("observer Merkle selector is not exact SHA256".into());
        }
        let data = self.rpc(
            Operation::ReadPage {
                object_sha256: sha256.into(),
            },
            check,
        )?;
        let (observation, value) = match data {
            Data::Page { object, bytes_hex } => (object, bytes_hex),
            _ => return self.poison("observer page response kind differs".into()),
        };
        let bytes = match decode_hex(&value) {
            Ok(bytes) => bytes,
            Err(error) => return self.poison(error),
        };
        if let Err(error) = data::raw(&observation, sha256, &bytes, &self.namespace) {
            return self.poison(error);
        }
        if !matches!(
            observation,
            RawObjectObservationData::Present { complete: true, .. }
        ) || bytes.is_empty()
            || bytes.len() > maximum
            || luma_content::sha256(&bytes) != sha256
        {
            return self.poison("incomplete/absent raw data is not a Merkle page".into());
        }
        self.delivery_check(check)?;
        Ok(bytes)
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
