//! Bounded ADR-0002 JSON measurement decoder, NOT an authenticated clock.
//! Kernel peer identity, runtime confinement, live capture and TPM history must
//! be verified by the future protected composition root before using these data.
#![cfg_attr(not(test), allow(dead_code))]
use crate::{utc_bounds::Interval, utc_policy::ApprovedPolicy, Result};

pub(crate) const MAX_ENVELOPE_SIZE: usize = 2048;
#[cfg(test)]
const FRAME_SIZE: usize = 232;

#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    request_id: String,
    caller: Caller,
    deadline: u64,
    deadline_clock: String,
    method: String,
    measurements: Measurements,
}
#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
struct Caller {
    pid: i32,
    uid: u32,
}
#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
struct Measurements {
    policy_sha256: String,
    boot_id: String,
    process_generation: u64,
    source_clock_generation: u64,
    sequence: u64,
    captured_boottime_ms: u64,
    captured_monotonic_ms: u64,
    captured_realtime_ms: i64,
    sources: [WireSource; 3],
}
#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
struct WireSource {
    operator: u8,
    available: bool,
    sequence: u64,
    observed_boottime_ms: u64,
    lower_ms: i64,
    upper_ms: i64,
}

fn hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical UTC hexadecimal identity".into());
    }
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[index * 2..index * 2 + 2], 16)?;
    }
    Ok(out)
}

// The caller arguments MUST come from SCM_CREDENTIALS, not the asserted JSON.
// This method profile is experimental: it does not provision or approve a socket.
pub(crate) fn decode_envelope(
    frame: &[u8],
    kernel_pid: i32,
    kernel_uid: u32,
) -> Result<ProducerRound> {
    if frame.len() < 5
        || frame.len() > MAX_ENVELOPE_SIZE
        || u32::from_be_bytes(frame[..4].try_into()?) as usize != frame.len() - 4
    {
        return Err("UTC envelope length mismatch".into());
    }
    let envelope: Envelope = serde_json::from_slice(&frame[4..])?;
    let m = envelope.measurements;
    let boot_id = hex::<16>(&m.boot_id)?;
    let policy_digest = hex::<32>(&m.policy_sha256)?;
    let request_id = format!(
        "utc-{}-{}-{}-{}",
        m.boot_id, m.process_generation, m.source_clock_generation, m.sequence
    );
    if envelope.schema_version != 1
        || envelope.method != "utc_measurements"
        || envelope.request_id != request_id
        || envelope.caller.pid <= 0
        || envelope.caller.pid != kernel_pid
        || envelope.caller.uid != kernel_uid
        || envelope.deadline_clock != "boottime"
        || Some(envelope.deadline) != m.captured_boottime_ms.checked_add(999)
        || policy_digest != ApprovedPolicy::fixed()?.digest()
        || boot_id == [0; 16]
        || m.process_generation == 0
        || m.source_clock_generation == 0
        || m.sequence == 0
        || m.captured_boottime_ms < m.captured_monotonic_ms
        || m.captured_realtime_ms < 0
    {
        return Err("invalid UTC envelope context or caller".into());
    }
    let mut sources = [
        SourceData::Unavailable { operator: 1 },
        SourceData::Unavailable { operator: 2 },
        SourceData::Unavailable { operator: 3 },
    ];
    for (index, entry) in m.sources.into_iter().enumerate() {
        let operator = index as u8 + 1;
        if entry.operator != operator {
            return Err("UTC source inventory mismatch".into());
        }
        if !entry.available {
            if entry.sequence != 0
                || entry.observed_boottime_ms != 0
                || entry.lower_ms != 0
                || entry.upper_ms != 0
            {
                return Err("inactive UTC source payload refused".into());
            }
        } else {
            if entry.sequence == 0
                || entry.observed_boottime_ms > m.captured_boottime_ms
                || m.captured_boottime_ms - entry.observed_boottime_ms > 179_982
                || entry.upper_ms > 4_102_444_800_000
            {
                return Err("UTC sample identity, age or range mismatch".into());
            }
            sources[index] = SourceData::Measured {
                operator,
                sequence: entry.sequence,
                observed_boottime_ms: entry.observed_boottime_ms,
                utc: Interval::new(entry.lower_ms, entry.upper_ms)?,
            };
        }
    }
    Ok(ProducerRound {
        epoch: ProducerEpoch {
            boot_id,
            process_generation: m.process_generation,
            source_clock_generation: m.source_clock_generation,
            policy_digest,
        },
        sequence: m.sequence,
        captured_boottime_ms: m.captured_boottime_ms,
        captured_monotonic_ms: m.captured_monotonic_ms,
        captured_realtime_ms: m.captured_realtime_ms,
        sources,
    })
}

#[cfg(test)]
fn fixture_envelope(r: &ProducerRound, pid: i32, uid: u32) -> Envelope {
    let encode_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let boot_id = encode_hex(&r.epoch.boot_id);
    Envelope {
        schema_version: 1,
        request_id: format!(
            "utc-{}-{}-{}-{}",
            boot_id, r.epoch.process_generation, r.epoch.source_clock_generation, r.sequence
        ),
        caller: Caller { pid, uid },
        deadline: r.captured_boottime_ms.checked_add(999).unwrap(),
        deadline_clock: "boottime".into(),
        method: "utc_measurements".into(),
        measurements: Measurements {
            policy_sha256: encode_hex(&r.epoch.policy_digest),
            boot_id,
            process_generation: r.epoch.process_generation,
            source_clock_generation: r.epoch.source_clock_generation,
            sequence: r.sequence,
            captured_boottime_ms: r.captured_boottime_ms,
            captured_monotonic_ms: r.captured_monotonic_ms,
            captured_realtime_ms: r.captured_realtime_ms,
            sources: r.sources.map(|s| match s {
                SourceData::Unavailable { operator } => WireSource {
                    operator,
                    available: false,
                    sequence: 0,
                    observed_boottime_ms: 0,
                    lower_ms: 0,
                    upper_ms: 0,
                },
                SourceData::Measured {
                    operator,
                    sequence,
                    observed_boottime_ms,
                    utc,
                } => {
                    let (lower_ms, upper_ms) = utc.endpoints();
                    WireSource {
                        operator,
                        available: true,
                        sequence,
                        observed_boottime_ms,
                        lower_ms,
                        upper_ms,
                    }
                }
            }),
        },
    }
}
#[cfg(test)]
pub(crate) fn fixture_encode(r: &ProducerRound, pid: i32, uid: u32) -> Vec<u8> {
    let payload = serde_json::to_vec(&fixture_envelope(r, pid, uid)).unwrap();
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend(payload);
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProducerEpoch {
    pub(crate) boot_id: [u8; 16],
    pub(crate) process_generation: u64,
    // Upstream source-clock invalidation, NOT Keeper's reacquisition generation.
    pub(crate) source_clock_generation: u64,
    pub(crate) policy_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceData {
    Unavailable {
        operator: u8,
    },
    Measured {
        operator: u8,
        sequence: u64,
        observed_boottime_ms: u64,
        utc: Interval,
    },
}

#[derive(Debug)]
pub(crate) struct ProducerRound {
    pub(crate) epoch: ProducerEpoch,
    pub(crate) sequence: u64,
    pub(crate) captured_boottime_ms: u64,
    pub(crate) captured_monotonic_ms: u64,
    // Host coordinate for jump detection only. It is NEVER the UTC estimate.
    pub(crate) captured_realtime_ms: i64,
    pub(crate) sources: [SourceData; 3],
}

#[cfg(test)]
fn u64_at(frame: &[u8], start: usize) -> u64 {
    u64::from_le_bytes(frame[start..start + 8].try_into().unwrap())
}

// Legacy binary codec exists ONLY for fixture construction and historical interop.
#[cfg(test)]
pub(crate) fn decode(frame: &[u8]) -> Result<ProducerRound> {
    if frame.len() != FRAME_SIZE || &frame[..8] != b"LUMAUTC1" {
        return Err("UTC frame size or version mismatch".into());
    }
    let policy_digest: [u8; 32] = frame[8..40].try_into()?;
    let boot_id: [u8; 16] = frame[40..56].try_into()?;
    let process_generation = u64_at(frame, 56);
    let source_clock_generation = u64_at(frame, 64);
    let sequence = u64_at(frame, 72);
    let captured_boottime_ms = u64_at(frame, 80);
    let captured_monotonic_ms = u64_at(frame, 88);
    let captured_realtime_ms = i64::from_le_bytes(frame[96..104].try_into()?);
    if policy_digest != ApprovedPolicy::fixed()?.digest()
        || boot_id == [0; 16]
        || process_generation == 0
        || source_clock_generation == 0
        || sequence == 0
        || captured_boottime_ms < captured_monotonic_ms
        || captured_realtime_ms < 0
        || frame[104..112] != [0; 8]
    {
        return Err("invalid UTC publisher context".into());
    }
    let mut sources = [
        SourceData::Unavailable { operator: 1 },
        SourceData::Unavailable { operator: 2 },
        SourceData::Unavailable { operator: 3 },
    ];
    for (index, source) in sources.iter_mut().enumerate() {
        let start = 112 + 40 * index;
        let entry = &frame[start..start + 40];
        let operator = index as u8 + 1;
        if entry[0] != operator || entry[2..8] != [0; 6] {
            return Err("UTC source identity or reserved data mismatch".into());
        }
        match entry[1] {
            0 if entry[8..] == [0; 32] => {}
            1 => {
                let sequence = u64_at(entry, 8);
                let observed_boottime_ms = u64_at(entry, 16);
                let lower = i64::from_le_bytes(entry[24..32].try_into()?);
                let upper = i64::from_le_bytes(entry[32..40].try_into()?);
                if sequence == 0
                    || observed_boottime_ms > captured_boottime_ms
                    || captured_boottime_ms - observed_boottime_ms > 179_982
                    || upper > 4_102_444_800_000
                {
                    return Err("UTC sample identity, age or range mismatch".into());
                }
                *source = SourceData::Measured {
                    operator,
                    sequence,
                    observed_boottime_ms,
                    utc: Interval::new(lower, upper)?,
                };
            }
            _ => return Err("UTC source state mismatch".into()),
        }
    }
    Ok(ProducerRound {
        epoch: ProducerEpoch {
            boot_id,
            process_generation,
            source_clock_generation,
            policy_digest,
        },
        sequence,
        captured_boottime_ms,
        captured_monotonic_ms,
        captured_realtime_ms,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(frame: &mut [u8], at: usize, value: u64) {
        frame[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn frame() -> [u8; FRAME_SIZE] {
        let mut f = [0; FRAME_SIZE];
        f[..8].copy_from_slice(b"LUMAUTC1");
        f[8..40].copy_from_slice(&ApprovedPolicy::fixed().unwrap().digest());
        f[40] = 2;
        put(&mut f, 56, 3);
        put(&mut f, 64, 1);
        put(&mut f, 72, 1);
        put(&mut f, 80, 1002);
        put(&mut f, 88, 900);
        put(&mut f, 96, 1_699_999_000_000);
        f[112] = 1;
        f[152] = 2;
        f[192] = 3;
        f[113] = 1;
        put(&mut f, 120, 1);
        put(&mut f, 128, 1001);
        put(&mut f, 136, 1_700_000_000_033);
        put(&mut f, 144, 1_700_000_000_068);
        f
    }
    #[test]
    fn closed_inventory_and_host_clock_are_data() {
        let r = decode(&frame()).unwrap();
        assert_eq!(r.epoch.process_generation, 3);
        assert_eq!(r.epoch.source_clock_generation, 1);
        assert_eq!(r.sequence, 1);
        assert_eq!(r.captured_boottime_ms, 1002);
        assert_eq!(r.captured_monotonic_ms, 900);
        assert_eq!(r.captured_realtime_ms, 1_699_999_000_000);
        assert!(matches!(
            r.sources[0],
            SourceData::Measured { operator: 1, .. }
        ));
        assert_eq!(r.sources[1], SourceData::Unavailable { operator: 2 });
    }
    fn json_frame(value: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(value).unwrap();
        let mut f = (body.len() as u32).to_be_bytes().to_vec();
        f.extend(body);
        f
    }
    fn json_value() -> serde_json::Value {
        serde_json::to_value(fixture_envelope(&decode(&frame()).unwrap(), 246, 1001)).unwrap()
    }
    #[test]
    fn json_round_trip_and_caller_is_kernel_bound() {
        let f = json_frame(&json_value());
        let r = decode_envelope(&f, 246, 1001).unwrap();
        assert_eq!(r.sources, decode(&frame()).unwrap().sources);
        assert_eq!(r.epoch, decode(&frame()).unwrap().epoch);
        assert_eq!(r.sequence, 1);
        for (pid, uid) in [(0, 1001), (247, 1001), (246, 1002)] {
            assert!(decode_envelope(&f, pid, uid).is_err());
        }
        assert!(decode_envelope(&frame(), 246, 1001).is_err()); // No binary fallback.
    }
    #[test]
    fn json_lengths_utf8_and_complete_payload_are_bounded() {
        let f = json_frame(&json_value());
        for length in 0..f.len() {
            assert!(decode_envelope(&f[..length], 246, 1001).is_err());
        }
        for declared in [0, 1, (f.len() - 3) as u32, u32::MAX] {
            let mut changed = f.clone();
            changed[..4].copy_from_slice(&declared.to_be_bytes());
            assert!(decode_envelope(&changed, 246, 1001).is_err());
        }
        let mut oversized = vec![b' '; MAX_ENVELOPE_SIZE + 1];
        oversized[..4].copy_from_slice(&((MAX_ENVELOPE_SIZE - 3) as u32).to_be_bytes());
        assert!(decode_envelope(&oversized, 246, 1001).is_err());
        for suffix in [b"{}".as_slice(), &[0xff], &[0]] {
            let mut changed = f.clone();
            changed.extend(suffix);
            let length = (changed.len() - 4) as u32;
            changed[..4].copy_from_slice(&length.to_be_bytes());
            assert!(decode_envelope(&changed, 246, 1001).is_err());
        }
        let mut invalid_utf8 = f.clone();
        let at = invalid_utf8.windows(3).position(|w| w == b"utc").unwrap();
        invalid_utf8[at] = 0xff; // Inside a required string, with unchanged length.
        assert!(decode_envelope(&invalid_utf8, 246, 1001).is_err());
    }
    #[test]
    fn json_unknown_missing_duplicate_and_wrong_types_refused() {
        for path in ["", "/caller", "/measurements", "/measurements/sources/0"] {
            let mut v = json_value();
            v.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("authority".into(), true.into());
            assert!(decode_envelope(&json_frame(&v), 246, 1001).is_err());
        }
        let value = json_value();
        for path in ["", "/caller", "/measurements", "/measurements/sources/0"] {
            for key in value.pointer(path).unwrap().as_object().unwrap().keys() {
                let mut v = value.clone();
                v.pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                assert!(
                    decode_envelope(&json_frame(&v), 246, 1001).is_err(),
                    "missing {path}/{key}"
                );
                for replacement in [
                    serde_json::Value::Null,
                    serde_json::json!({}),
                    serde_json::json!([]),
                ] {
                    let mut v = value.clone();
                    v.pointer_mut(path).unwrap()[key] = replacement;
                    assert!(
                        decode_envelope(&json_frame(&v), 246, 1001).is_err(),
                        "type {path}/{key}"
                    );
                }
            }
        }
        let original = String::from_utf8(serde_json::to_vec(&value).unwrap()).unwrap();
        for needle in [
            "\"schema_version\":1",
            "\"pid\":246",
            "\"process_generation\":3",
            "\"operator\":1",
        ] {
            let body = original.replacen(needle, &format!("{needle},{needle}"), 1);
            let mut f = (body.len() as u32).to_be_bytes().to_vec();
            f.extend(body.bytes());
            assert!(
                decode_envelope(&f, 246, 1001).is_err(),
                "duplicate {needle}"
            );
        }
        for (path, value) in [
            ("/caller/pid", serde_json::json!(246.0)),
            ("/caller/uid", serde_json::json!("1001")),
            ("/measurements/sources/0/available", serde_json::json!(1)),
            ("/measurements/sequence", serde_json::json!(-1)),
            ("/deadline", serde_json::json!(1.0)),
        ] {
            let mut v = json_value();
            *v.pointer_mut(path).unwrap() = value;
            assert!(decode_envelope(&json_frame(&v), 246, 1001).is_err());
        }
    }
    #[test]
    fn json_profile_epochs_deadline_and_inventory_are_closed() {
        for (path, value) in [
            ("/schema_version", serde_json::json!(2)),
            ("/request_id", serde_json::json!("other")),
            ("/method", serde_json::json!("utc_authority")),
            ("/deadline_clock", serde_json::json!("realtime")),
            ("/deadline", serde_json::json!(2002)),
            ("/caller/pid", serde_json::json!(0)),
            ("/caller/pid", serde_json::json!(2147483648u64)),
            ("/caller/uid", serde_json::json!(4294967296u64)),
            (
                "/measurements/boot_id",
                serde_json::json!("00000000000000000000000000000000"),
            ),
            ("/measurements/boot_id", serde_json::json!("02")),
            (
                "/measurements/policy_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/measurements/process_generation", serde_json::json!(0)),
            (
                "/measurements/source_clock_generation",
                serde_json::json!(0),
            ),
            ("/measurements/sequence", serde_json::json!(0)),
            (
                "/measurements/captured_monotonic_ms",
                serde_json::json!(1003),
            ),
            ("/measurements/captured_realtime_ms", serde_json::json!(-1)),
            (
                "/measurements/captured_boottime_ms",
                serde_json::json!(u64::MAX),
            ),
            ("/measurements/sources/1/operator", serde_json::json!(1)),
            ("/measurements/sources/1/sequence", serde_json::json!(1)),
            ("/measurements/sources/0/sequence", serde_json::json!(0)),
            (
                "/measurements/sources/0/observed_boottime_ms",
                serde_json::json!(1003),
            ),
            ("/measurements/sources/0/lower_ms", serde_json::json!(-1)),
            (
                "/measurements/sources/0/lower_ms",
                serde_json::json!(1_700_000_000_069i64),
            ),
            (
                "/measurements/sources/0/upper_ms",
                serde_json::json!(4_102_444_800_001i64),
            ),
        ] {
            let mut v = json_value();
            *v.pointer_mut(path).unwrap() = value;
            assert!(
                decode_envelope(&json_frame(&v), 246, 1001).is_err(),
                "{path}"
            );
        }
        for inventory in [serde_json::json!([]), serde_json::json!([{}, {}, {}, {}])] {
            let mut v = json_value();
            v["measurements"]["sources"] = inventory;
            assert!(decode_envelope(&json_frame(&v), 246, 1001).is_err());
        }
        let mut v = json_value();
        v["measurements"]["policy_sha256"] = serde_json::json!(ApprovedPolicy::fixed()
            .unwrap()
            .digest()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>());
        assert!(decode_envelope(&json_frame(&v), 246, 1001).is_err());
    }
    #[test]
    fn json_sample_age_boundary_and_maximum_counters() {
        for age in [179_982, 179_983] {
            let mut r = decode(&frame()).unwrap();
            r.captured_boottime_ms = 1001 + age;
            assert_eq!(
                decode_envelope(&fixture_encode(&r, 246, 1001), 246, 1001).is_ok(),
                age == 179_982
            );
        }
        let mut r = decode(&frame()).unwrap();
        r.epoch.process_generation = u64::MAX;
        r.epoch.source_clock_generation = u64::MAX;
        r.sequence = u64::MAX;
        r.captured_boottime_ms = u64::MAX - 999;
        r.captured_monotonic_ms = r.captured_boottime_ms;
        r.captured_realtime_ms = i64::MAX;
        r.sources = [1, 2, 3].map(|operator| SourceData::Measured {
            operator,
            sequence: u64::MAX,
            observed_boottime_ms: r.captured_boottime_ms,
            utc: Interval::new(4_102_444_800_000, 4_102_444_800_000).unwrap(),
        });
        let f = fixture_encode(&r, i32::MAX, u32::MAX);
        assert!(f.len() <= MAX_ENVELOPE_SIZE);
        assert!(decode_envelope(&f, i32::MAX, u32::MAX).is_ok());
    }
    #[test]
    #[ignore = "requires the isolated C JSON publisher fixture path"]
    fn c_publisher_cross_language_envelope() {
        let bytes = std::fs::read(std::env::var("LUMA_UTC_C_ENVELOPE").unwrap()).unwrap();
        let r = decode_envelope(&bytes, 246, 1001).unwrap();
        assert_eq!(r.epoch, decode(&frame()).unwrap().epoch);
        assert_eq!(r.sequence, 1);
        assert_eq!(r.captured_boottime_ms, 1002);
        assert_eq!(r.captured_monotonic_ms, 900);
        assert_eq!(r.captured_realtime_ms, 1_699_999_000_000);
        if let SourceData::Measured {
            sequence,
            observed_boottime_ms,
            utc,
            ..
        } = r.sources[0]
        {
            assert_eq!(sequence, 1);
            assert_eq!(observed_boottime_ms, 1001);
            assert!(utc.endpoints().0 <= 1_700_000_000_036);
            assert!(utc.endpoints().1 >= 1_700_000_000_064);
        } else {
            panic!("C JSON source missing");
        }
        assert_eq!(r.sources[1], SourceData::Unavailable { operator: 2 });
        assert_eq!(r.sources[2], SourceData::Unavailable { operator: 3 });
    }
    #[test]
    fn every_truncated_frame_and_trailing_byte_rejected() {
        let f = frame();
        for length in 0..FRAME_SIZE {
            assert!(decode(&f[..length]).is_err());
        }
        let mut extra = f.to_vec();
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    #[test]
    fn fixed_version_policy_and_zero_reserved_fields() {
        for at in (0..40)
            .chain(104..112)
            .chain(114..120)
            .chain(154..160)
            .chain(194..200)
        {
            let mut f = frame();
            f[at] ^= 1;
            assert!(decode(&f).is_err(), "byte {at}");
        }
    }
    #[test]
    fn uninitialized_and_regressed_context_rejected() {
        for at in [56, 64, 72, 120] {
            let mut f = frame();
            put(&mut f, at, 0);
            assert!(decode(&f).is_err());
        }
        let mut f = frame();
        f[40..56].fill(0);
        assert!(decode(&f).is_err());
        let mut f = frame();
        put(&mut f, 88, 1003);
        assert!(decode(&f).is_err());
        put(&mut f, 88, 900);
        put(&mut f, 96, u64::MAX);
        assert!(decode(&f).is_err());
    }
    #[test]
    fn aliases_duplicate_ids_unknown_states_and_inactive_payload_rejected() {
        for (at, value) in [(112, 2), (152, 1), (192, 4), (113, 2), (153, 1), (160, 1)] {
            let mut f = frame();
            f[at] = value;
            assert!(decode(&f).is_err());
        }
    }
    #[test]
    fn stale_future_inverted_negative_and_overrange_samples_rejected() {
        for (at, value) in [
            (128, 1003),
            (136, u64::MAX),
            (136, 1_700_000_000_069),
            (144, 4_102_444_800_001),
        ] {
            let mut f = frame();
            put(&mut f, at, value);
            assert!(decode(&f).is_err());
        }
        let mut f = frame();
        put(&mut f, 80, 1001 + 179_982);
        assert!(decode(&f).is_ok());
        put(&mut f, 80, 1001 + 179_983);
        assert!(decode(&f).is_err());
    }
    #[test]
    #[ignore = "requires the isolated C publisher fixture path"]
    fn c_publisher_cross_language_frame() {
        let bytes = std::fs::read(std::env::var("LUMA_UTC_C_FRAME").unwrap()).unwrap();
        let r = decode(&bytes).unwrap();
        assert_eq!(r.epoch.boot_id[0], 2);
        assert_eq!(r.epoch.process_generation, 3);
        assert_eq!(r.sequence, 1);
        if let SourceData::Measured {
            sequence,
            observed_boottime_ms,
            utc,
            ..
        } = r.sources[0]
        {
            assert_eq!(sequence, 1);
            assert_eq!(observed_boottime_ms, 1001);
            assert!(utc.endpoints().0 <= 1_700_000_000_036);
            assert!(utc.endpoints().1 >= 1_700_000_000_064);
        } else {
            panic!("C producer did not preserve the measured sample");
        }
        assert_eq!(r.sources[1], SourceData::Unavailable { operator: 2 });
        assert_eq!(r.sources[2], SourceData::Unavailable { operator: 3 });
    }
}
