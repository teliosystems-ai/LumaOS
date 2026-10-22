//! Acknowledged, continuously checked socket delivery of encrypted package DATA.
//! The scope is a structural finite bound, not original authentication or C
//! attestation. No dispatcher, selected relay or installed signing route is
//! created here. The concrete original caller must retain actual authority.
use super::{io::FramedOutput, receipt, scope, PackageSource, Summary};
use crate::authentication::SessionPurpose;
use crate::finite_grants::Use;
use crate::service::granted_gateway::{CheckedDeliveryBound, CheckedPayload};
use crate::Result;
use sha2::{Digest, Sha256};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;
#[cfg(test)]
mod tests;
#[cfg(test)]
thread_local! { static OBSERVED_OUTPUT_STALL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
struct OutputStall(bool);
#[cfg(test)]
impl OutputStall {
    fn new() -> Self {
        Self(OBSERVED_OUTPUT_STALL.with(|s| s.replace(true)))
    }
}
#[cfg(test)]
impl Drop for OutputStall {
    fn drop(&mut self) {
        OBSERVED_OUTPUT_STALL.with(|s| s.set(self.0));
    }
}

/// Closed request DATA checked against the single existing scope parser and
/// the caller's current original pair. Its live callback must actually verify
/// original Export principal/purpose, both grants, UTC, C and resource generation.
pub(super) struct SnapshotScope<'a> {
    input: &'a scope::Input,
    expected_bytes: u64,
    pair: [Use; 2],
}
impl<'a> SnapshotScope<'a> {
    pub(super) fn new(
        input: &'a scope::Input,
        header: &receipt::Header,
        device: &str,
        current_pair: &[(String, Use)],
        purpose: SessionPurpose,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        input.canonical_bytes()?;
        header.canonical_bytes()?;
        header.receipt.body.check_source(input)?;
        let pair = scope::uses(
            &input.profile()?,
            device,
            &input.intent.head.binding.installation,
        )?;
        scope::export_pair(
            &input.profile()?,
            device,
            &input.intent.head.binding.installation,
            current_pair,
            &pair[1],
            purpose,
        )?;
        let expected_bytes = header.receipt.body.measured_package_bytes();
        if expected_bytes == 0 || expected_bytes > pair[1].output_bytes {
            return Err("snapshot delivery exceeds exact original package reservation".into());
        }
        check()?;
        Ok(Self {
            input,
            expected_bytes,
            pair,
        })
    }
    fn matches(&self, header: &receipt::Header) -> Result<()> {
        header.receipt.body.check_source(self.input)?;
        if header.receipt.body.measured_package_bytes() != self.expected_bytes {
            return Err("snapshot delivery changed exact whole-package measurement".into());
        }
        Ok(())
    }
    /// Diagnostic registration bridge only. The real production constructor
    /// remains unregistered until the actual original-worker/C route exists.
    #[cfg(test)]
    fn diagnostic_bound(&self) -> Result<CheckedDeliveryBound> {
        crate::service::granted_gateway::snapshot_delivery_bound(&self.pair[0], &self.pair[1])
    }
}
struct Delivery<'a> {
    output: Option<CheckedPayload>,
    bound: CheckedDeliveryBound,
    scope: &'a SnapshotScope<'a>,
    bytes: u64,
    digest: [u8; 32],
    finished: bool,
}
impl Delivery<'_> {
    fn failed<T>(&mut self, error: Box<dyn std::error::Error>) -> Result<T> {
        // Closing the actual owned producer socket makes a stalled relay see
        // loss of its original producer. No failed frame/ACK is retried/adopted.
        self.output.take();
        Err(error)
    }
}
impl FramedOutput for Delivery<'_> {
    fn exact(&mut self, bytes: &[u8], check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if self.finished
            || self.output.is_none()
            || self
                .bytes
                .checked_add(bytes.len() as u64)
                .map_or(true, |n| n > self.scope.expected_bytes)
        {
            return self
                .failed("snapshot acknowledged output is closed or exceeds exact size".into());
        }
        for chunk in bytes.chunks(4096) {
            let result = self
                .output
                .as_mut()
                .ok_or("snapshot producer already closed")?
                .write_checked_bound(chunk, &self.bound, check);
            if let Err(error) = result {
                return self.failed(error);
            }
            let (count, digest) = self
                .output
                .as_ref()
                .ok_or("snapshot producer already closed")?
                .checked_measurement();
            self.bytes = count;
            self.digest = digest;
        }
        if let Err(error) = check() {
            return self.failed(error);
        }
        Ok(())
    }
    fn bytes(&self) -> u64 {
        self.bytes
    }
    fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn flush(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if self.finished || self.bytes != self.scope.expected_bytes || self.output.is_none() {
            return self.failed("snapshot final ACK requires exact complete package bytes".into());
        }
        let result = self
            .output
            .as_mut()
            .ok_or("snapshot producer already closed")?
            .finish_checked(check);
        if let Err(error) = result {
            return self.failed(error);
        }
        self.finished = true;
        if let Err(error) = check() {
            return self.failed(error);
        }
        Ok(())
    }
}
/// The supplied opaque transport bound is constructed by the closed source
/// selector bridge, never a caller-provided arbitrary byte ceiling. All writes
/// and ACK/stall waits invoke the SAME original live callback.
pub(super) fn deliver<'a>(
    header: &receipt::Header,
    source: &mut impl PackageSource,
    scope: &'a SnapshotScope<'a>,
    bound: CheckedDeliveryBound,
    output: CheckedPayload,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Summary> {
    check()?;
    scope.matches(header)?;
    let (bytes, digest) = output.checked_measurement();
    if bytes != 0 {
        return Err("snapshot delivery cannot adopt a partly consumed relay".into());
    }
    super::encode_output(
        header,
        source,
        Delivery {
            output: Some(output),
            bound,
            scope,
            bytes,
            digest,
            finished: false,
        },
        check,
    )
}

fn poll(
    socket: &UnixStream,
    output: Option<&UnixStream>,
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if Instant::now() >= deadline {
        return Err("snapshot relay bounded deadline expired".into());
    }
    let mut events = [
        libc::pollfd {
            fd: socket.as_raw_fd(),
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: output.map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLOUT,
            revents: 0,
        },
    ];
    let result = unsafe { libc::poll(events.as_mut_ptr(), 2, 100) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().into());
    }
    check()?;
    if events
        .iter()
        .any(|e| e.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
    {
        return Err("snapshot relay original producer or consumer lost".into());
    }
    Ok(())
}
fn receive(
    socket: &UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    eof: bool,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let mut at = 0;
    while at < bytes.len() {
        check()?;
        if Instant::now() >= deadline {
            return Err("snapshot relay read deadline expired".into());
        }
        let count = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                bytes[at..].as_mut_ptr().cast(),
                bytes.len() - at,
                libc::MSG_DONTWAIT,
            )
        };
        let error = if count < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        check()?;
        if count > 0 {
            at += count as usize;
        } else if count == 0 {
            if eof && at == 0 {
                return Ok(false);
            }
            return Err("snapshot producer ended before full frame/terminal ACK".into());
        } else {
            let error = error.ok_or("snapshot receive omitted OS error")?;
            match error.kind() {
                std::io::ErrorKind::Interrupted => (),
                std::io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut p, 1, 100) };
                    if result < 0
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        return Err(std::io::Error::last_os_error().into());
                    }
                }
                _ => return Err(error.into()),
            }
        }
    }
    Ok(true)
}
fn send(
    socket: &UnixStream,
    producer: &UnixStream,
    bytes: &[u8],
    deadline: Instant,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        check()?;
        if Instant::now() >= deadline {
            return Err("snapshot relay write deadline expired".into());
        }
        // Probe producer loss even when the destination remains continuously
        // writable. This is not a grant observation; the live callback is too.
        let mut probe = libc::pollfd {
            fd: producer.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        if unsafe { libc::poll(&mut probe, 1, 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if probe.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("snapshot original producer lost before destination delivery".into());
        }
        let count = unsafe {
            libc::send(
                socket.as_raw_fd(),
                bytes[at..].as_ptr().cast(),
                bytes.len() - at,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        let error = if count < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        check()?;
        if count > 0 {
            at += count as usize;
        } else if count == 0 {
            return Err("snapshot destination made no progress".into());
        } else {
            let error = error.ok_or("snapshot send omitted OS error")?;
            match error.kind() {
                std::io::ErrorKind::Interrupted => (),
                std::io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    let _observed = OutputStall::new();
                    poll(producer, Some(socket), deadline, check)?;
                }
                _ => return Err(error.into()),
            }
        }
    }
    check()
}
/// Both descriptors are held sockets, not arbitrary Write implementations or
/// paths. MSG_DONTWAIT avoids changing inherited open-file-description flags.
/// This performs transport only; it never parses/signs/decrypts/restores data.
pub(super) fn relay(
    scope: &SnapshotScope<'_>,
    producer: &UnixStream,
    output: &UnixStream,
    deadline: Instant,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(u64, String)> {
    check()?;
    let now = Instant::now();
    if deadline <= now || deadline.duration_since(now) > std::time::Duration::from_secs(1800) {
        return Err("snapshot relay deadline exceeds original bounded Export profile".into());
    }
    let mut bytes = 0u64;
    let mut digest = Sha256::new();
    let mut finished = false;
    loop {
        let mut word = [0; 4];
        if !receive(producer, &mut word, deadline, finished, check)? {
            check()?;
            return Ok((bytes, crate::bundle::hex(&digest.finalize())));
        }
        let length = u32::from_be_bytes(word) as usize;
        if finished || length > 4096 {
            return Err("snapshot transport frame after terminal or above fixed bound".into());
        }
        let next = bytes
            .checked_add(length as u64)
            .filter(|n| *n <= scope.expected_bytes)
            .ok_or("snapshot relay exceeds exact signed package size")?;
        let mut chunk = [0; 4096];
        receive(producer, &mut chunk[..length], deadline, false, check)?;
        if length == 0 {
            if bytes != scope.expected_bytes || bytes == 0 {
                return Err("snapshot final frame omitted exact package bytes".into());
            }
            finished = true;
        } else {
            send(output, producer, &chunk[..length], deadline, check)?;
            digest.update(&chunk[..length]);
            bytes = next;
        }
        let mut ack = bytes.to_be_bytes().to_vec();
        ack.extend(digest.clone().finalize());
        send(producer, producer, &ack, deadline, check)?;
    }
}
