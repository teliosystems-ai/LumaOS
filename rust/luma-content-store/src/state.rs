//! Expected content-state selectors are data, not authenticated checkpoints.
//! Only a native caller with an actual independent custody cut can turn this
//! comparison into rollback protection; this crate never invents such a cut.
use crate::*;

/// Exact reconstructed committed history and retained retirement evidence.
/// Deserialization validates syntax only; it authenticates no issuer or time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedState {
    pub binding: OwnerBinding,
    pub outcome_count: u64,
    pub head_sha256: String,
    pub quarantine_sha256: String,
}
impl VerifiedState {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.outcome_count > MAX_OUTCOMES as u64
            || [&self.head_sha256, &self.quarantine_sha256]
                .iter()
                .any(|digest| !crate::hash(digest) || digest.bytes().all(|byte| byte == b'0'))
        {
            return Err("invalid bounded canonical content state selector".into());
        }
        if self.outcome_count == 0
            && self.head_sha256 != publication::history_head(&self.binding, std::iter::empty())?
        {
            return Err("empty content outcome count does not bind the exact empty history".into());
        }
        Ok(())
    }
    /// Pure expected empty data, never permission to initialize or adopt disk.
    pub fn empty(binding: &OwnerBinding) -> Result<Self> {
        binding.validate()?;
        let value = Self {
            binding: binding.clone(),
            outcome_count: 0,
            head_sha256: publication::history_head(binding, std::iter::empty())?,
            quarantine_sha256: recovery::inventory_digest(binding, &[])?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn from_snapshot(binding: &OwnerBinding, snapshot: &Snapshot) -> Result<Self> {
        let value = Self {
            binding: binding.clone(),
            outcome_count: snapshot.records.len() as u64,
            head_sha256: publication::history_head(
                binding,
                snapshot.records.iter().map(|(record, _, _)| record),
            )?,
            quarantine_sha256: snapshot.quarantine_sha256.clone(),
        };
        value.validate()?;
        Ok(value)
    }
}

impl Repository {
    /// Reconstruct exact current data under fresh live Read admission. The
    /// result is not itself proof that any TPM or custody service selected it.
    pub fn verified_state(&self, boundary: &mut impl Boundary) -> Result<VerifiedState> {
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        let snapshot = self.snapshot(None, boundary)?;
        VerifiedState::from_snapshot(&self.binding, &snapshot)
    }

    /// Select independently supplied expected data for this open repository.
    /// There is no API to clear the selection or silently fall back on mismatch.
    /// Native production callers must obtain this data from genuine current
    /// custody, not trust a user-selected JSON value or a self-consistent backup.
    /// Every query compares INSIDE its own reconstructed Snapshot; backup capture
    /// compares its own reconstructed captured bytes before returning any result.
    pub fn require_state(
        &mut self,
        expected: &VerifiedState,
        boundary: &mut impl Boundary,
    ) -> Result<()> {
        expected.validate()?;
        if expected.binding != self.binding {
            return Err("content state selector belongs to another owner generation".into());
        }
        boundary.admit(&self.binding, ResourceBudget::inspection())?;
        self.expected_state = Some(expected.clone());
        self.snapshot(None, boundary)?;
        Ok(())
    }

    pub(super) fn check_selected_state(&self, actual: &VerifiedState) -> Result<()> {
        check_expected(self.expected_state.as_ref(), actual)
    }
}

pub(super) fn check_expected(
    expected: Option<&VerifiedState>,
    actual: &VerifiedState,
) -> Result<()> {
    actual.validate()?;
    if expected.is_some_and(|selected| selected != actual) {
        return Err(
            "actual content snapshot differs from independently selected history or retirement cut"
                .into(),
        );
    }
    Ok(())
}
