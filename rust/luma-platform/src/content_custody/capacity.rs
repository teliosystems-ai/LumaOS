//! Restore capacity is an admission promise, never an effect grant. Its source
//! is the NV-protected Start plus the exact protected publication/retirement
//! prefix. No reservation file, lease expiry, reset or separate TPM event exists.
use super::*;

// Each ceiling includes one JSON array delimiter. A held canonical commitment
// is at most 16KiB (fixed five namespaces/three members, bounded identifiers and
// integer widths); a canonical Record is at most 8KiB. Embedding canonical JSON
// as a JSON string expands at most twofold: its control characters are already
// escaped. Audit, profile, storage-device and event metadata fit another 4KiB.
// Thus 64KiB exceeds 2*(16KiB+8KiB)+4KiB+1. Retirement contains only the bounded
// Review, fixed hashes/owner/state and Audit, not the archive or Start body.
pub(super) const PUBLICATION_BYTES: usize = 64 * 1024;
pub(super) const TERMINAL_BYTES: usize = 8 * 1024;
const HELD_BYTES: usize = 16 * 1024;

pub(crate) fn policy() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"policy":Reservation::fixed(),
        "maximum_journal_bytes":MAX_JOURNAL,"maximum_journal_events":MAX_EVENTS,
        "all_remaining_publications_and_one_terminal_disposition_reserved_at_start":true,
        "terminal_capacity_remains_reserved_after_batch_completion":true,
        "exact_current_protected_capacity_admission_required":true,
        "nominal_256_steps_not_guaranteed_to_fit_current_journal":true,
        "capacity_report_is_not_an_effect_grant":true,"history_continuation_implemented":false})
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Reservation {
    schema_version: u32,
    purpose: String,
    publication_event_maximum_bytes: usize,
    terminal_event_maximum_bytes: usize,
}
impl Reservation {
    pub(super) fn fixed() -> Self {
        Self {
            schema_version: 1,
            purpose: "luma-content-restore-protected-capacity-v1".into(),
            publication_event_maximum_bytes: PUBLICATION_BYTES,
            terminal_event_maximum_bytes: TERMINAL_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub(super) struct Tail {
    pub outstanding_restore_batches: usize,
    pub reserved_event_slots: usize,
    pub reserved_journal_bytes: usize,
}
impl Tail {
    fn add(&mut self, publications: usize) -> Result<()> {
        let events = publications
            .checked_add(1)
            .ok_or("restore event capacity overflow")?;
        let bytes = publications
            .checked_mul(PUBLICATION_BYTES)
            .and_then(|value| value.checked_add(TERMINAL_BYTES))
            .ok_or("restore byte capacity overflow")?;
        self.outstanding_restore_batches = self
            .outstanding_restore_batches
            .checked_add(1)
            .ok_or("restore batch capacity overflow")?;
        self.reserved_event_slots = self
            .reserved_event_slots
            .checked_add(events)
            .ok_or("restore event capacity overflow")?;
        self.reserved_journal_bytes = self
            .reserved_journal_bytes
            .checked_add(bytes)
            .ok_or("restore byte capacity overflow")?;
        Ok(())
    }
    pub(super) fn require_fit(&self, bytes: usize, events: usize) -> Result<()> {
        if bytes > MAX_JOURNAL
            || events > MAX_EVENTS
            || bytes
                .checked_add(self.reserved_journal_bytes)
                .map_or(true, |n| n > MAX_JOURNAL)
            || events
                .checked_add(self.reserved_event_slots)
                .map_or(true, |n| n > MAX_EVENTS)
        {
            return Err("protected content capacity is reserved for admitted restore publications and terminal disposition; no reset, truncation or capacity increase".into());
        }
        Ok(())
    }
}

pub(super) fn remaining(state: &Validated) -> Result<Tail> {
    let mut tail = Tail::default();
    for (key, start) in &state.restores {
        if state.retired.contains(key) {
            continue;
        }
        let count = state.owners.get(key).map_or(0, |cut| cut.outcome_count);
        // After completion ordinary changes may increase count further. They
        // never consume the remaining terminal-disposition promise.
        let left = start.review()?.published_outcomes.saturating_sub(count);
        tail.add(usize::try_from(left)?)?;
    }
    Ok(tail)
}

pub(super) fn admit(journal: &Journal, state: &Validated) -> Result<()> {
    let entry = journal
        .events
        .last()
        .ok_or("capacity admission has no transition")?;
    let ceiling = match entry {
        Event::RestorePublication(value) => {
            if value.entry.commitment.len() > HELD_BYTES {
                return Err("restore held commitment exceeds its reserved typed envelope".into());
            }
            Some(PUBLICATION_BYTES)
        }
        Event::RestoreRetired(_) => Some(TERMINAL_BYTES),
        _ => None,
    };
    if let Some(limit) = ceiling {
        if serde_json::to_vec(entry)?
            .len()
            .checked_add(1)
            .map_or(true, |n| n > limit)
        {
            return Err("restore event exceeds its protected reserved byte ceiling".into());
        }
    }
    // Historical v1 journals remain readable without rewriting their bytes.
    // Their next mutation must preserve the same derived remaining tail. A
    // terminal event may release an old insufficient tail, and reviewed pending
    // reconciliation still completes the already-dispatched original cut.
    let bytes = journal.bytes()?.len();
    if matches!(entry, Event::RestoreRetired(_)) {
        // An old v1 history may already lack capacity for its tails. The
        // validated terminal event releases at least its own byte/slot ceiling
        // and creates no promise. Do not strand that independently reviewed
        // cleanup merely because a different historical batch is deficient.
        if journal.events.len() > MAX_EVENTS {
            return Err("terminal disposition exceeds fixed event capacity".into());
        }
        return Ok(());
    }
    remaining(state)?.require_fit(bytes, journal.events.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximal_typed_envelopes_and_nested_json_escaping_fit_the_enforced_ceilings() {
        // Width representatives, not a grant, archive, filesystem token or
        // fabricated executable. Every variable field uses its maximum encoded
        // width; strings intentionally include maximal legal JSON escaping.
        let binding = OwnerBinding {
            installation: "11".repeat(32),
            owner: "22".repeat(32),
            owner_generation: u64::MAX,
        };
        let directory = PreparationDirectoryIdentity {
            device: u64::MAX,
            inode: u64::MAX,
            owner: 0,
            group: u32::MAX,
            mode: (u32::MAX & !0o177777) | 0o040700,
        };
        let identity = PreparationFileIdentity {
            device: u64::MAX,
            inode: u64::MAX,
            owner: 0,
            group: u32::MAX,
            mode: (u32::MAX & !0o177777) | 0o100400,
            links: 1,
            modified_seconds: i64::MIN,
            modified_nanoseconds: 999_999_999,
            changed_seconds: i64::MIN,
            changed_nanoseconds: 999_999_999,
        };
        let held = HeldPublication {
            schema_version: 1,
            purpose: "luma-content-held-publication-v1".into(),
            binding: binding.clone(),
            request_id: "z".repeat(128),
            review_sha256: "33".repeat(32),
            decision: DecisionKind::Published,
            resulting: VersionReference {
                artifact_id: "\u{0001}".repeat(128),
                version: u64::MAX,
                content_sha256: "44".repeat(32),
                receipt_sha256: "55".repeat(32),
            },
            base_outcome_count: 255,
            outcome_count: 256,
            base_head_sha256: "66".repeat(32),
            outcome_head_sha256: "77".repeat(32),
            quarantine_sha256: "88".repeat(32),
            already_published: false,
            namespaces: ["base", "owner", "pending", "outcomes", "quarantine"]
                .into_iter()
                .map(|name| Namespace {
                    name: name.into(),
                    identity: directory.clone(),
                    mount_id: u64::MAX,
                })
                .collect(),
            directory,
            directory_mount_id: u64::MAX,
            members: ["payload.json", "record.json", "source.bin"]
                .into_iter()
                .map(|name| Member {
                    name: name.into(),
                    bytes: if name == "record.json" {
                        8192
                    } else {
                        24 * 1024 * 1024
                    },
                    sha256: "99".repeat(32),
                    identity: identity.clone(),
                    mount_id: u64::MAX,
                })
                .collect(),
        };
        held.validate().unwrap();
        let commitment = serde_json::to_string(&held).unwrap();
        assert!(commitment.len() < HELD_BYTES);
        let profile = format!(
            "{}w-{}-{}-{}-256-{}",
            crate::content_restore::PREFIX,
            u64::MAX,
            u64::MAX,
            crate::content_backup::MAX_EXPORT_BYTES,
            "aa".repeat(32)
        );
        let device = format!("{}:{}", u32::MAX, u32::MAX);
        let audit = Audit {
            subject: "bb".repeat(32),
            subject_generation: u64::MAX,
            grant_id: "G".repeat(64),
            grant_version: 1,
            checkpoint_head: "cc".repeat(32),
            operation_id: Some("dd".repeat(16)),
            usage: crate::content_restore::custody_usage(&profile, &device, &binding.installation)
                .unwrap(),
        };
        audit.validate().unwrap();
        let record = serde_json::to_string(&"\\".repeat(4095)).unwrap();
        assert_eq!(record.len(), 8192);
        let entry = Publication {
            schema_version: 1,
            purpose: "luma-content-custody-publication-v1".into(),
            commitment,
            record,
            profile,
            storage_device: device,
            original_authority: audit.clone(),
        };
        let value = Event::RestorePublication(
            serde_json::from_value(serde_json::json!({
                "batch_review_sha256": "ee".repeat(32), "entry": entry
            }))
            .unwrap(),
        );
        assert!(serde_json::to_vec(&value).unwrap().len() + 1 < PUBLICATION_BYTES);
        let terminal: retire::Retirement = serde_json::from_value(serde_json::json!({
            "review":{"schema_version":1,"purpose":"luma-content-restore-terminal-disposition-v1",
                "installation":binding.installation,"binding":binding,"batch_review_sha256":"11".repeat(32),
                "capsule_sha256":"22".repeat(32),"origin_spki_sha256":"33".repeat(32),
                "start_sha256":"44".repeat(32),"checkpoint_head":"55".repeat(32),
                "state":VerifiedState {binding:binding.clone(),outcome_count:u64::MAX,head_sha256:"66".repeat(32),quarantine_sha256:"77".repeat(32)},
                "disposition":"mark-owner-generation-unavailable-preserve-all-published-pending-quarantine-bytes"},
            "original_authority":audit})).unwrap();
        assert!(
            serde_json::to_vec(&Event::RestoreRetired(terminal))
                .unwrap()
                .len()
                + 1
                < TERMINAL_BYTES
        );
    }

    #[test]
    fn fixed_reservation_counts_full_batch_and_terminal_with_checked_boundaries() {
        let mut tail = Tail::default();
        tail.add(2).unwrap();
        assert_eq!(tail.reserved_event_slots, 3);
        assert_eq!(
            tail.reserved_journal_bytes,
            2 * PUBLICATION_BYTES + TERMINAL_BYTES
        );
        let bytes = MAX_JOURNAL - tail.reserved_journal_bytes;
        let events = MAX_EVENTS - tail.reserved_event_slots;
        tail.require_fit(bytes, events).unwrap();
        assert!(tail.require_fit(bytes + 1, events).is_err());
        assert!(tail.require_fit(bytes, events + 1).is_err());
        tail.add(0).unwrap();
        assert_eq!(tail.outstanding_restore_batches, 2);
        assert_eq!(tail.reserved_event_slots, 4);
        assert_eq!(
            tail.reserved_journal_bytes,
            2 * PUBLICATION_BYTES + 2 * TERMINAL_BYTES
        );
        assert!(tail.require_fit(bytes, events).is_err());
        assert!(tail.add(usize::MAX).is_err());
        assert!(tail.require_fit(usize::MAX, 0).is_err());
    }
}
