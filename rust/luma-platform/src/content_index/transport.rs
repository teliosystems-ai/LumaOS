//! Closed candidate DATA streaming. The live original operation and its finite
//! reservation are mandatory caller boundaries, not claims in these bytes.
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"LUMACAND";
const HEADER: usize = 1024;
const CHUNK: usize = 64 * 1024;
const IO: usize = 4096;

pub(crate) trait CandidateBoundary {
    fn current_candidate_source(&mut self, source_sha256: &str, review_sha256: &str) -> Result<()>;
    fn reserve_candidate_transfer(&mut self, wire_bytes: u64, memory_bytes: u64) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: u32,
    source_sha256: String,
    review_sha256: String,
    candidate_sha256: String,
    candidate_bytes: u64,
}
impl Header {
    fn validate(&self, source: &str, review: &str) -> Result<()> {
        for value in [source, review, self.candidate_sha256.as_str()] {
            hash(value)?;
        }
        if self.schema_version != 2
            || self.source_sha256 != source
            || self.review_sha256 != review
            || self.candidate_bytes == 0
            || self.candidate_bytes > MAX_COMMITMENT as u64
        {
            return Err("index candidate stream changes exact source/review/finite length".into());
        }
        Ok(())
    }
    fn body_wire_bytes(&self) -> Result<u64> {
        self.candidate_bytes
            .checked_add(4 * ((self.candidate_bytes + CHUNK as u64 - 1) / CHUNK as u64))
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| "candidate framing overflow".into())
    }
}

/// Hashed bytes only. Callers must parse the typed phase and independently
/// replay it against actual current C/observer state before selecting anything.
pub(crate) struct CandidateData {
    bytes: Vec<u8>,
}
impl CandidateData {
    pub(crate) fn parse(&self) -> Result<phase::Commitment> {
        phase::Commitment::parse(&self.bytes)
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct Transfer<'a, B: CandidateBoundary> {
    socket: &'a UnixStream,
    boundary: &'a mut B,
    source: &'a str,
    review: &'a str,
    deadline: Instant,
}
impl<B: CandidateBoundary> Transfer<'_, B> {
    fn current(&mut self) -> Result<Duration> {
        self.boundary
            .current_candidate_source(self.source, self.review)?;
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|n| !n.is_zero())
            .ok_or_else(|| "original index candidate transfer deadline expired".into())
    }
    fn io(&mut self, bytes: &mut [u8], send: bool) -> Result<()> {
        let mut position = 0;
        while position < bytes.len() {
            self.current()?;
            let count = (bytes.len() - position).min(IO);
            let result = unsafe {
                if send {
                    libc::send(
                        self.socket.as_raw_fd(),
                        bytes[position..].as_ptr().cast(),
                        count,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                } else {
                    libc::recv(
                        self.socket.as_raw_fd(),
                        bytes[position..].as_mut_ptr().cast(),
                        count,
                        libc::MSG_DONTWAIT,
                    )
                }
            };
            let error = if result < 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            self.current()?;
            if result > 0 {
                position += usize::try_from(result)?;
                continue;
            }
            if result == 0 {
                return Err("index candidate peer closed before complete bounded DATA".into());
            }
            let error = error.ok_or("candidate transport OS error missing")?;
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    let remaining = self.current()?;
                    let timeout = remaining.as_millis().clamp(1, 100) as i32;
                    let mut event = libc::pollfd {
                        fd: self.socket.as_raw_fd(),
                        events: if send { libc::POLLOUT } else { libc::POLLIN },
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut event, 1, timeout) };
                    let error = if result < 0 {
                        Some(std::io::Error::last_os_error())
                    } else {
                        None
                    };
                    self.current()?;
                    if let Some(error) = error {
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error.into());
                        }
                    }
                    if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                        return Err("candidate transport descriptor failed".into());
                    }
                }
                _ => return Err(error.into()),
            }
        }
        self.current()?;
        Ok(())
    }
}

pub(crate) fn receive(
    socket: &UnixStream,
    source: &str,
    review: &str,
    deadline: Instant,
    boundary: &mut impl CandidateBoundary,
) -> Result<CandidateData> {
    hash(source)?;
    hash(review)?;
    boundary.current_candidate_source(source, review)?;
    // Charge the complete fixed header allowance BEFORE even the first byte.
    boundary.reserve_candidate_transfer((MAGIC.len() + 4 + HEADER) as u64, HEADER as u64)?;
    let mut transfer = Transfer {
        socket,
        boundary,
        source,
        review,
        deadline,
    };
    let mut magic = [0; 8];
    transfer.io(&mut magic, false)?;
    if &magic != MAGIC {
        return Err("not the closed index candidate DATA stream".into());
    }
    let mut word = [0; 4];
    transfer.io(&mut word, false)?;
    let length = u32::from_be_bytes(word) as usize;
    if length == 0 || length > HEADER {
        return Err("candidate header outside fixed frame bound".into());
    }
    let mut bytes = vec![0; length];
    transfer.io(&mut bytes, false)?;
    let header: Header = decode(&bytes, HEADER)?;
    header.validate(source, review)?;
    transfer
        .boundary
        .reserve_candidate_transfer(header.body_wire_bytes()?, header.candidate_bytes)?;
    transfer.current()?;
    let mut bytes = vec![0; usize::try_from(header.candidate_bytes)?];
    let mut position = 0;
    while position < bytes.len() {
        transfer.io(&mut word, false)?;
        let length = u32::from_be_bytes(word) as usize;
        let expected = (bytes.len() - position).min(CHUNK);
        if length != expected {
            return Err("noncanonical or unbounded candidate DATA chunk".into());
        }
        transfer.io(&mut bytes[position..position + length], false)?;
        position += length;
    }
    transfer.io(&mut word, false)?;
    if u32::from_be_bytes(word) != 0 || luma_content::sha256(&bytes) != header.candidate_sha256 {
        return Err("index candidate full bytes/digest/end marker differ".into());
    }
    transfer.current()?;
    Ok(CandidateData { bytes })
}

pub(crate) fn send(
    socket: &UnixStream,
    source: &str,
    review: &str,
    candidate: &[u8],
    deadline: Instant,
    boundary: &mut impl CandidateBoundary,
) -> Result<()> {
    let header = Header {
        schema_version: 2,
        source_sha256: source.into(),
        review_sha256: review.into(),
        candidate_sha256: luma_content::sha256(candidate),
        candidate_bytes: candidate.len() as u64,
    };
    header.validate(source, review)?;
    boundary.current_candidate_source(source, review)?;
    let header_bytes = serde_json::to_vec(&header)?;
    if header_bytes.len() > HEADER {
        return Err("candidate header exceeds fixed bound".into());
    }
    boundary.reserve_candidate_transfer(
        (MAGIC.len() + 4 + HEADER) as u64 + header.body_wire_bytes()?,
        IO as u64,
    )?;
    let mut transfer = Transfer {
        socket,
        boundary,
        source,
        review,
        deadline,
    };
    let mut magic = *MAGIC;
    transfer.io(&mut magic, true)?;
    transfer.io(&mut (header_bytes.len() as u32).to_be_bytes(), true)?;
    for chunk in header_bytes.chunks(IO) {
        transfer.io(&mut chunk.to_vec(), true)?;
    }
    for chunk in candidate.chunks(CHUNK) {
        transfer.io(&mut (chunk.len() as u32).to_be_bytes(), true)?;
        for part in chunk.chunks(IO) {
            transfer.io(&mut part.to_vec(), true)?;
        }
    }
    transfer.io(&mut 0u32.to_be_bytes(), true)?;
    transfer.current()?;
    Ok(())
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;
