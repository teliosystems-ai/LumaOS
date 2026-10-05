//! Bounded decoder for the chrony hook fixture, NOT an authenticated clock.
//! Kernel peer identity, runtime confinement, live capture and TPM history must
//! be verified by the future protected composition root before using these data.
#![cfg_attr(not(test), allow(dead_code))]
use crate::{utc_bounds::Interval, utc_policy::ApprovedPolicy, Result};

const FRAME_SIZE: usize = 232;

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

fn u64_at(frame: &[u8], start: usize) -> u64 {
    u64::from_le_bytes(frame[start..start + 8].try_into().unwrap())
}

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
