//! Real socket transport, with explicit software source/budget callbacks only.
//! These tests provide no principal, lease, C selection or phase authority.
use super::*;
use std::io::Write;

struct Boundary {
    checks: usize,
    fail_at: Option<usize>,
    holds: Vec<(u64, u64)>,
    available: u64,
}
impl Boundary {
    fn new() -> Self {
        Self {
            checks: 0,
            fail_at: None,
            holds: Vec::new(),
            available: 8 * 1024 * 1024,
        }
    }
}
impl CandidateBoundary for Boundary {
    fn current_candidate_source(&mut self, source: &str, review: &str) -> Result<()> {
        self.checks += 1;
        if source != "11".repeat(32)
            || review != "22".repeat(32)
            || self.fail_at.is_some_and(|n| self.checks >= n)
        {
            return Err("explicit software original-source revocation/substitution".into());
        }
        Ok(())
    }
    fn reserve_candidate_transfer(&mut self, wire: u64, memory: u64) -> Result<()> {
        self.available = self
            .available
            .checked_sub(wire)
            .ok_or("explicit finite transfer exhausted")?;
        self.holds.push((wire, memory));
        Ok(())
    }
}
fn source() -> String {
    "11".repeat(32)
}
fn review() -> String {
    "22".repeat(32)
}
fn header(payload: &[u8]) -> Header {
    Header {
        schema_version: 2,
        source_sha256: source(),
        review_sha256: review(),
        candidate_sha256: luma_content::sha256(payload),
        candidate_bytes: payload.len() as u64,
    }
}
fn header_wire(header: &Header) -> Vec<u8> {
    let bytes = serde_json::to_vec(header).unwrap();
    let mut result = MAGIC.to_vec();
    result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(&bytes);
    result
}
fn wire(payload: &[u8]) -> Vec<u8> {
    let mut result = header_wire(&header(payload));
    for chunk in payload.chunks(CHUNK) {
        result.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        result.extend_from_slice(chunk);
    }
    result.extend_from_slice(&0u32.to_be_bytes());
    result
}
fn refuse(bytes: &[u8]) -> Boundary {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(bytes).unwrap();
    drop(peer);
    let mut boundary = Boundary::new();
    assert!(receive(
        &socket,
        &source(),
        &review(),
        Instant::now() + Duration::from_secs(1),
        &mut boundary
    )
    .is_err());
    boundary
}

#[test]
fn full_maximum_candidate_uses_bounded_chunks_and_reserves_before_body_without_authority() {
    let payload = vec![0x35; MAX_COMMITMENT];
    let expected = payload.clone();
    let (receiver, sender) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || {
        let mut boundary = Boundary::new();
        send(
            &sender,
            &source(),
            &review(),
            &payload,
            Instant::now() + Duration::from_secs(10),
            &mut boundary,
        )
        .unwrap();
        boundary
    });
    let mut boundary = Boundary::new();
    let received = receive(
        &receiver,
        &source(),
        &review(),
        Instant::now() + Duration::from_secs(10),
        &mut boundary,
    )
    .unwrap();
    assert_eq!(received.bytes(), expected);
    assert!(
        received.parse().is_err(),
        "hashed bytes alone are not even a typed phase candidate"
    );
    assert_eq!(boundary.holds.len(), 2);
    assert_eq!(
        boundary.holds[0],
        ((MAGIC.len() + 4 + HEADER) as u64, HEADER as u64)
    );
    assert_eq!(
        boundary.holds[1],
        (
            header(&expected).body_wire_bytes().unwrap(),
            expected.len() as u64
        )
    );
    assert!(boundary.checks > 2 * MAX_COMMITMENT / IO);
    assert!(writer.join().unwrap().checks > 2 * MAX_COMMITMENT / IO);
}
#[test]
fn source_review_lengths_schema_and_noncanonical_headers_refuse_before_body_hold() {
    for variant in 0..5 {
        let mut header = header(b"{}");
        match variant {
            0 => header.source_sha256 = "33".repeat(32),
            1 => header.review_sha256 = "44".repeat(32),
            2 => header.candidate_bytes = 0,
            3 => header.candidate_bytes = MAX_COMMITMENT as u64 + 1,
            _ => header.schema_version = 1,
        }
        let boundary = refuse(&header_wire(&header));
        assert_eq!(boundary.holds.len(), 1);
    }
    let header = header(b"{}");
    let mut bytes = MAGIC.to_vec();
    let pretty = serde_json::to_vec_pretty(&header).unwrap();
    bytes.extend_from_slice(&(pretty.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&pretty);
    assert_eq!(refuse(&bytes).holds.len(), 1);
    for length in [0, HEADER as u32 + 1] {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        assert_eq!(refuse(&bytes).holds.len(), 1);
    }
}
#[test]
fn exact_chunks_full_digest_end_and_truncation_have_no_success_fallback_or_release() {
    let valid = wire(b"{}");
    for end in 0..valid.len() {
        refuse(&valid[..end]);
    }
    let mut changed = valid.clone();
    changed[0] ^= 1;
    refuse(&changed);
    let at = header_wire(&header(b"{}")).len();
    let mut changed = valid.clone();
    changed[at..at + 4].copy_from_slice(&1u32.to_be_bytes());
    refuse(&changed);
    let mut changed = valid.clone();
    changed[at + 4] ^= 1;
    assert_eq!(refuse(&changed).holds.len(), 2);
    let mut changed = valid.clone();
    *changed.last_mut().unwrap() = 1;
    assert_eq!(refuse(&changed).holds.len(), 2);
}
#[test]
fn original_revocation_during_idle_and_header_budget_exhaustion_do_not_read_a_body() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut boundary = Boundary::new();
    boundary.fail_at = Some(5);
    let started = Instant::now();
    assert!(receive(
        &socket,
        &source(),
        &review(),
        started + Duration::from_secs(5),
        &mut boundary
    )
    .is_err());
    assert_eq!(boundary.checks, 5);
    assert!(started.elapsed() < Duration::from_secs(1));
    let mut boundary = Boundary::new();
    boundary.available = 0;
    assert!(receive(
        &socket,
        &source(),
        &review(),
        Instant::now() + Duration::from_secs(1),
        &mut boundary
    )
    .is_err());
    assert!(boundary.holds.is_empty());
    let mut boundary = Boundary::new();
    assert!(receive(&socket, &source(), &review(), Instant::now(), &mut boundary).is_err());
    assert_eq!(boundary.holds.len(), 1);
}
#[test]
fn receiver_budget_failure_keeps_the_header_hold_and_returns_no_candidate() {
    let bytes = wire(b"{}");
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(&bytes).unwrap();
    let mut boundary = Boundary::new();
    boundary.available = (MAGIC.len() + 4 + HEADER) as u64;
    assert!(receive(
        &socket,
        &source(),
        &review(),
        Instant::now() + Duration::from_secs(1),
        &mut boundary
    )
    .is_err());
    assert_eq!(boundary.holds.len(), 1);
}
