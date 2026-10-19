//! Read-only capacity DATA, not a continuation, enrollment or authorization.
//! Only the existing live protected Store supplies a current assessment.
use super::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RefusalCondition {
    InvalidOrSubstitutedJournal,
    UnmatchedProtectedCheckpoint,
    OriginalAdminReadUnavailable,
    PendingProtectedTransition,
    NextJournalExceedsByteLimit,
    NextJournalExceedsEventLimit,
    HistoryContinuationNotImplemented,
}

#[derive(Debug, Serialize)]
struct Capacity {
    journal_bytes: usize,
    maximum_journal_bytes: usize,
    remaining_journal_bytes: usize,
    event_count: usize,
    maximum_events: usize,
    remaining_event_slots: usize,
    at_byte_limit: bool,
    at_event_limit: bool,
    next_transition_must_pass_exact_commit_checks: bool,
    remaining_capacity_is_not_reserved_or_authorized: bool,
    restore_capacity: capacity::Tail,
    unreserved_journal_bytes: usize,
    unreserved_event_slots: usize,
    legacy_restore_capacity_deficient: bool,
}
impl Capacity {
    fn capture(bytes: usize, events: usize) -> Result<Self> {
        if bytes == 0 || bytes > MAX_JOURNAL || events > MAX_EVENTS {
            return Err("current custody journal exceeds its closed lifecycle capacity".into());
        }
        Ok(Self {
            journal_bytes: bytes,
            maximum_journal_bytes: MAX_JOURNAL,
            remaining_journal_bytes: MAX_JOURNAL - bytes,
            event_count: events,
            maximum_events: MAX_EVENTS,
            remaining_event_slots: MAX_EVENTS - events,
            at_byte_limit: bytes == MAX_JOURNAL,
            at_event_limit: events == MAX_EVENTS,
            next_transition_must_pass_exact_commit_checks: true,
            remaining_capacity_is_not_reserved_or_authorized: true,
            restore_capacity: capacity::Tail::default(),
            unreserved_journal_bytes: MAX_JOURNAL - bytes,
            unreserved_event_slots: MAX_EVENTS - events,
            legacy_restore_capacity_deficient: false,
        })
    }
}

// Deliberately not Deserialize: a supplied report is never a protected cut.
#[derive(Debug, Serialize)]
pub(super) struct Assessment {
    schema_version: u32,
    purpose: &'static str,
    installation: String,
    original_genesis_event: String,
    protected_checkpoint_head: String,
    journal_sha256: String,
    owner_domains: usize,
    capacity: Capacity,
    refusal_conditions: Vec<RefusalCondition>,
    history_continuation_implemented: bool,
    event_or_byte_limits_changed: bool,
    history_truncated: bool,
    epoch_created: bool,
    keys_changed: bool,
    checkpoint_extended: bool,
    content_bytes_changed: bool,
    authority_returned: bool,
    production_qualified: bool,
}
impl Assessment {
    /// Store::status_data brackets this computation with its original live
    /// callback, exact held journal comparison and actual checkpoint read.
    pub(super) fn capture(journal: &Journal, bytes: &[u8], state: &Validated) -> Result<Self> {
        let mut capacity = Capacity::capture(bytes.len(), journal.events.len())?;
        digest(&journal.installation)?;
        digest(&journal.genesis_event)?;
        digest(&bundle::hex(&state.checkpoint))?;
        if journal.bytes()? != bytes {
            return Err("lifecycle assessment bytes differ from current canonical journal".into());
        }
        // Journal::validate establishes semantics when Store is opened. Its
        // checkpoint recurrence is precisely this fold for every event kind.
        // Recheck that pairing here without allocating a second global set of
        // owners, record histories, restore batches or recipient enrollments.
        if journal.schema_version != 1 || journal.purpose != "luma-content-custody-history-v1" {
            return Err("lifecycle assessment journal purpose/schema differs".into());
        }
        let mut expected = tpm::extend_value([0; 32], tpm::decode(&journal.genesis_event)?);
        for event in &journal.events {
            expected = tpm::extend_value(expected, event.digest()?);
        }
        if expected != state.checkpoint {
            return Err(
                "lifecycle assessment current state and exact journal checkpoint differ".into(),
            );
        }
        let tail = capacity::remaining(state)?;
        capacity.remaining_capacity_is_not_reserved_or_authorized =
            tail.outstanding_restore_batches == 0;
        capacity.unreserved_journal_bytes = capacity
            .remaining_journal_bytes
            .saturating_sub(tail.reserved_journal_bytes);
        capacity.unreserved_event_slots = capacity
            .remaining_event_slots
            .saturating_sub(tail.reserved_event_slots);
        capacity.legacy_restore_capacity_deficient =
            tail.require_fit(bytes.len(), journal.events.len()).is_err();
        capacity.restore_capacity = tail;
        Ok(Self {
            schema_version: 1,
            purpose: "luma-content-custody-read-only-lifecycle-assessment-v1",
            installation: journal.installation.clone(),
            original_genesis_event: journal.genesis_event.clone(),
            protected_checkpoint_head: bundle::hex(&state.checkpoint),
            journal_sha256: hash(bytes),
            owner_domains: state.owners.len(),
            capacity,
            refusal_conditions: vec![
                RefusalCondition::InvalidOrSubstitutedJournal,
                RefusalCondition::UnmatchedProtectedCheckpoint,
                RefusalCondition::OriginalAdminReadUnavailable,
                RefusalCondition::PendingProtectedTransition,
                RefusalCondition::NextJournalExceedsByteLimit,
                RefusalCondition::NextJournalExceedsEventLimit,
                RefusalCondition::HistoryContinuationNotImplemented,
            ],
            history_continuation_implemented: false,
            event_or_byte_limits_changed: false,
            history_truncated: false,
            epoch_created: false,
            keys_changed: false,
            checkpoint_extended: false,
            content_bytes_changed: false,
            authority_returned: false,
            production_qualified: false,
        })
    }
    pub(super) fn sha256(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&serde_json::to_value(self)?)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_capacity_limits_are_reported_without_reservation_reset_or_saturation() {
        let value = Capacity::capture(123, 17).unwrap();
        assert_eq!(value.remaining_journal_bytes, MAX_JOURNAL - 123);
        assert_eq!(value.remaining_event_slots, MAX_EVENTS - 17);
        assert!(!value.at_byte_limit && !value.at_event_limit);
        let full = Capacity::capture(MAX_JOURNAL, MAX_EVENTS).unwrap();
        assert_eq!(full.remaining_journal_bytes, 0);
        assert_eq!(full.remaining_event_slots, 0);
        assert!(full.at_byte_limit && full.at_event_limit);
        assert!(Capacity::capture(0, 0).is_err());
        assert!(Capacity::capture(MAX_JOURNAL + 1, 0).is_err());
        assert!(Capacity::capture(1, MAX_EVENTS + 1).is_err());
    }
    #[test]
    fn assessment_is_exact_current_data_not_a_capacity_or_rollover_authority() {
        let journal = Journal::empty(&"12".repeat(32), [7; 32]).unwrap();
        let bytes = journal.bytes().unwrap();
        let state = journal.validate().unwrap();
        let assessment = Assessment::capture(&journal, &bytes, &state).unwrap();
        let encoded = serde_json::to_vec(&assessment).unwrap();
        assert!(encoded.len() < 4096);
        assert_eq!(assessment.journal_sha256, hash(&bytes));
        assert_eq!(
            assessment.protected_checkpoint_head,
            bundle::hex(&state.checkpoint)
        );
        assert_eq!(assessment.original_genesis_event, "07".repeat(32));
        assert!(!assessment.history_continuation_implemented);
        assert!(!assessment.authority_returned);
        assert_eq!(
            assessment.sha256().unwrap(),
            hash(&serde_json::to_vec(&serde_json::to_value(&assessment).unwrap()).unwrap())
        );
        let mut changed = bytes.clone();
        changed.push(b' ');
        assert!(Assessment::capture(&journal, &changed, &state).is_err());
        let mut mismatched = journal.validate().unwrap();
        mismatched.checkpoint = [8; 32];
        assert!(Assessment::capture(&journal, &bytes, &mismatched).is_err());
    }
}
