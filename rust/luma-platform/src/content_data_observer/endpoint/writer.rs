//! Closed one-OFD DATA transfer, not a generic descriptor service or creator
//! attestation. No installed socket/dispatcher is exposed by this component.
//! The independently selected original C context/physical reservation must
//! precede its use; no decoded offer grants a write or extends authentication.
use super::*;
use luma_content_store::v2::{
    HeldNamespaceObservation, HeldWriterObservation, IoBudget, ObjectStore, WriterObservationData,
};
use luma_content_store::{Access, Boundary, ResourceBudget};
use std::mem::{size_of, size_of_val};
use std::net::Shutdown;
use std::os::fd::FromRawFd;

const ACQUISITION: &str = "luma-acquisition (enforce)";
const OFFER_MAX: usize = 32768;
const PURPOSE: &str = "luma-content-writer-ofd-offer-v1";
#[cfg(test)]
thread_local! {
    static WAITING_FOR_RIGHTS: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> = const { std::cell::RefCell::new(None) };
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_data_observer) struct WriterOffer {
    pub(in crate::content_data_observer) schema_version: u32,
    pub(in crate::content_data_observer) purpose: String,
    pub(in crate::content_data_observer) nonce: String,
    pub(in crate::content_data_observer) context: Context,
    pub(in crate::content_data_observer) review_sha256: String,
    pub(in crate::content_data_observer) worker_pid: u32,
    pub(in crate::content_data_observer) worker_start: u64,
}
impl WriterOffer {
    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.schema_version != 1
            || self.purpose != PURPOSE
            || !nonce(&self.nonce)
            || !hash(&self.review_sha256)
            || self.worker_pid == 0
            || self.worker_start == 0
            || serde_json::to_vec(self)?.len() > OFFER_MAX
        {
            return Err("writer offer is outside the exact bounded source/context profile".into());
        }
        Ok(())
    }
}
fn connected(socket: &UnixStream, peer: &Peer) -> Result<()> {
    peer.check(socket)?;
    let mut p = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    if unsafe { libc::poll(&mut p, 1, 0) } < 0
        || p.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
    {
        return Err("original writer observation connection lost".into());
    }
    Ok(())
}
fn wait(
    socket: &UnixStream,
    event: i16,
    end: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if Instant::now() >= end {
        return Err("writer OFD transfer deadline expired".into());
    }
    let mut p = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: event,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut p, 1, 100) };
    let error = if result < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    check()?;
    if let Some(error) = error {
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    if Instant::now() >= end || p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err("writer OFD transfer unavailable or expired".into());
    }
    Ok(())
}
fn packet(
    socket: &UnixStream,
    end: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<(usize, u8, Vec<File>)> {
    loop {
        check()?;
        if Instant::now() >= end {
            return Err("writer OFD receive expired".into());
        }
        let mut byte = 0;
        // Aligned bounded control storage. Every installed rights/PIDFD is
        // RAII-owned before any subsequent fallible original/peer check.
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        let count = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            check()?;
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    WAITING_FOR_RIGHTS.with(|slot| {
                        if let Some(flag) = slot.borrow().as_ref() {
                            flag.store(true, std::sync::atomic::Ordering::Release);
                        }
                    });
                    wait(socket, libc::POLLIN, end, check)?;
                    continue;
                }
                _ => return Err(error.into()),
            }
        }
        let mut descriptors = Vec::new();
        let mut invalid = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let value = unsafe { &*header };
            let base = unsafe { libc::CMSG_LEN(0) } as usize;
            let offset = (header as usize)
                .checked_sub(message.msg_control as usize)
                .ok_or("writer ancillary pointer underflow")?;
            if offset > message.msg_controllen
                || value.cmsg_len < base
                || value.cmsg_len > message.msg_controllen - offset
            {
                return Err("writer ancillary kernel range malformed".into());
            }
            let length = value.cmsg_len - base;
            if value.cmsg_level == libc::SOL_SOCKET
                && (value.cmsg_type == libc::SCM_RIGHTS || value.cmsg_type == 4)
            {
                if value.cmsg_type != libc::SCM_RIGHTS || length % size_of::<i32>() != 0 {
                    invalid = true;
                }
                for index in 0..length / size_of::<i32>() {
                    let fd = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header)
                                .add(index * size_of::<i32>())
                                .cast::<i32>(),
                        )
                    };
                    if fd < 0 {
                        invalid = true;
                    } else {
                        descriptors.push(unsafe { File::from_raw_fd(fd) });
                    }
                }
            } else {
                invalid = true;
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        check()?;
        if invalid || Instant::now() >= end {
            return Err("writer OFD ancillary truncated/extra/unknown or expired".into());
        }
        return Ok((count as usize, byte, descriptors));
    }
}
fn send_marker(
    socket: &UnixStream,
    writer: &File,
    end: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let byte = b'W';
    let mut control = [0usize; 4];
    let mut iov = libc::iovec {
        iov_base: (&byte as *const u8).cast_mut().cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), writer.as_raw_fd());
    }
    loop {
        check()?;
        if Instant::now() >= end {
            return Err("writer OFD send expired".into());
        }
        let count = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        let error = if count < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        check()?;
        if count == 1 {
            return Ok(());
        }
        if let Some(error) = error {
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    wait(socket, libc::POLLOUT, end, check)?;
                    continue;
                }
                _ => return Err(error.into()),
            }
        }
        return Err("writer OFD marker short/closed".into());
    }
}
fn send_to(
    socket: &UnixStream,
    peer: &Peer,
    offer: &WriterOffer,
    writer: &File,
    end: Instant,
    original: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let result = send_to_inner(socket, peer, offer, writer, end, original);
    if result.is_err() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    result
}
fn send_to_inner(
    socket: &UnixStream,
    peer: &Peer,
    offer: &WriterOffer,
    writer: &File,
    end: Instant,
    original: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    offer.validate()?;
    if offer.worker_pid != std::process::id()
        || start(offer.worker_pid as i32)? != offer.worker_start
    {
        return Err("writer offer does not name actual sender process generation".into());
    }
    let mut check = || {
        original()?;
        connected(socket, peer)?;
        original()
    };
    check()?;
    super::super::wire::send(socket, &serde_json::to_vec(offer)?, end, &mut check)?;
    send_marker(socket, writer, end, &mut check)?;
    socket.shutdown(Shutdown::Write)?;
    check()
}
pub(in crate::content_data_observer) fn send(
    socket: &UnixStream,
    offer: &WriterOffer,
    writer: &File,
    original: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let result = (|| {
        let peer = Peer::capture(socket, OBSERVER)?;
        send_to(
            socket,
            &peer,
            offer,
            writer,
            Instant::now() + Duration::from_millis(RPC_MS),
            original,
        )
    })();
    if result.is_err() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    result
}
struct Received {
    offer: WriterOffer,
    writer: File,
    peer: Peer,
    socket: UnixStream,
}
fn receive_from(
    socket: &UnixStream,
    peer: Peer,
    expected: &WriterOffer,
    end: Instant,
    original: &mut dyn FnMut() -> Result<()>,
) -> Result<Received> {
    let result = receive_from_inner(socket, peer, expected, end, original);
    if result.is_err() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    result
}
fn receive_from_inner(
    socket: &UnixStream,
    peer: Peer,
    expected: &WriterOffer,
    end: Instant,
    original: &mut dyn FnMut() -> Result<()>,
) -> Result<Received> {
    expected.validate()?;
    if peer.pid as u32 != expected.worker_pid || peer.start != expected.worker_start {
        return Err("writer expected context names another actual worker generation".into());
    }
    let mut check = || {
        original()?;
        connected(socket, &peer)?;
        original()
    };
    let bytes = super::super::wire::receive(socket, end, &mut check)?;
    if bytes.len() > OFFER_MAX {
        return Err("writer offer frame exceeds closed bound".into());
    }
    let offer: WriterOffer = canonical(&bytes)?;
    offer.validate()?;
    if offer != *expected {
        return Err("writer transfer substitutes C-issued exact context/nonce/source".into());
    }
    let (count, marker, mut descriptors) = packet(socket, end, &mut check)?;
    if count != 1 || marker != b'W' || descriptors.len() != 1 {
        return Err("writer transfer requires exactly one descriptor and marker".into());
    }
    let writer = descriptors.pop().ok_or("writer OFD missing")?;
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err("writer transfer did not receive kernel CLOEXEC".into());
    }
    let (count, _, extra) = packet(socket, end, &mut check)?;
    if count != 0 || !extra.is_empty() {
        return Err("writer transfer has hidden trailing data/descriptors".into());
    }
    check()?;
    Ok(Received {
        offer,
        writer,
        peer,
        socket: socket.try_clone()?,
    })
}
pub(in crate::content_data_observer) struct ObservedWriter {
    offer: WriterOffer,
    held: HeldWriterObservation,
    peer: Peer,
    socket: UnixStream,
}
struct Live<'a, B: Boundary> {
    original: &'a mut B,
    peer: &'a Peer,
    socket: &'a UnixStream,
}
impl<B: Boundary> Boundary for Live<'_, B> {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        connected(self.socket, self.peer)?;
        self.original.admit(owner, budget)?;
        connected(self.socket, self.peer)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        connected(self.socket, self.peer)?;
        self.original.check(access)?;
        connected(self.socket, self.peer)
    }
}
impl Received {
    fn observe(
        self,
        store: &ObjectStore,
        namespace: &HeldNamespaceObservation,
        budget: IoBudget,
        original: &mut impl Boundary,
    ) -> Result<ObservedWriter> {
        if namespace.data().binding != self.offer.context.binding {
            return Err("writer offer owner differs from fixed namespace".into());
        }
        let mut live = Live {
            original,
            peer: &self.peer,
            socket: &self.socket,
        };
        let held = store.observe_existing_writer(
            namespace,
            self.writer,
            self.offer.worker_pid,
            budget,
            &mut live,
        )?;
        Ok(ObservedWriter {
            offer: self.offer,
            held,
            peer: self.peer,
            socket: self.socket,
        })
    }
}
impl ObservedWriter {
    pub(in crate::content_data_observer) fn data(&self) -> &WriterObservationData {
        self.held.data()
    }
    pub(in crate::content_data_observer) fn check(
        &self,
        store: &ObjectStore,
        namespace: &HeldNamespaceObservation,
        budget: IoBudget,
        original: &mut impl Boundary,
    ) -> Result<()> {
        let mut live = Live {
            original,
            peer: &self.peer,
            socket: &self.socket,
        };
        if self.offer.context.binding != namespace.data().binding {
            return Err("writer current owner changed".into());
        }
        store.check_existing_writer(namespace, &self.held, budget, &mut live)
    }
}
pub(in crate::content_data_observer) fn receive(
    socket: &UnixStream,
    expected: &WriterOffer,
    store: &ObjectStore,
    namespace: &HeldNamespaceObservation,
    budget: IoBudget,
    original_check: &mut dyn FnMut() -> Result<()>,
    original_io: &mut impl Boundary,
) -> Result<ObservedWriter> {
    let result = (|| {
        let peer = Peer::capture(socket, ACQUISITION)?;
        let received = receive_from(
            socket,
            peer,
            expected,
            Instant::now() + Duration::from_millis(RPC_MS),
            original_check,
        )?;
        original_check()?;
        let observed = received.observe(store, namespace, budget, original_io)?;
        original_check()?;
        Ok(observed)
    })();
    if result.is_err() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    result
}

#[cfg(test)]
#[path = "writer/tests.rs"]
mod tests;
