//! Explicit terminal window after the independently selected chronological
//! prefix has complete source/current coverage. It is never an automatic last
//! part/outcome side effect and does not erase data or release retained charges.
use super::replay::ReplayBoundary;
use super::*;
#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;

pub trait CompletionBoundary: ReplayBoundary {
    /// Observe actual held terminal/publication files, current encrypted job
    /// volume, physical deltas, original Standard grants and drain state. This
    /// is not implemented by trusting a prefix, counter or serialized receipt.
    fn verify_prepared_terminal(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        review: &RestoreWindowReview,
        commitment: &TerminalCommitment,
        job: &ObjectStore,
    ) -> Result<()>;
}
pub struct CompletionPlan {
    review: RestoreWindowReview,
    next: RestorePrefix,
}
impl CompletionPlan {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
    pub fn proposed_prefix(&self) -> &RestorePrefix {
        &self.next
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalCommitment {
    pub review_sha256: String,
    pub base_prefix_sha256: String,
    pub prefix_object_sha256: String,
    pub next: RestorePrefix,
    pub newly_allocated_job: PhysicalInventory,
}
pub struct PreparedCompletion<'a> {
    job: &'a ObjectStore,
    _writer: std::fs::File,
    review: RestoreWindowReview,
    commitment: TerminalCommitment,
}
impl PreparedCompletion<'_> {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
    pub fn commitment(&self) -> &TerminalCommitment {
        &self.commitment
    }
    pub fn acknowledge_selected(
        self,
        manifest: &WholeSnapshotManifest,
        b: &mut impl CompletionBoundary,
    ) -> Result<RestorePrefix> {
        live(manifest, &self.commitment.next, None, b)?;
        b.verify_job_namespace(manifest, &self.commitment.next, self.job)?;
        b.retain_original_ciphertext(manifest, manifest.part_count)?;
        let mut selected = TerminalIo {
            b,
            job: self.job,
            window: CheckedWindow::new(manifest, &self.commitment.next, None)?,
        };
        let bytes = self.job.read_page(
            &self.commitment.prefix_object_sha256,
            IoBudget {
                read_bytes: IMPORT_MAX_READ_BYTES,
                write_bytes: 0,
                new_files: 0,
            },
            &mut selected,
        )?;
        if bytes != self.commitment.next.canonical_bytes(manifest)? {
            return Err(
                "selected restore terminal prefix object differs from held publication".into(),
            );
        }
        Ok(self.commitment.next)
    }
}
fn proposed(
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    terminal: RestoreReservations,
) -> Result<RestorePrefix> {
    prefix.validate(manifest)?;
    terminal.validate(true)?;
    if prefix.stage != RestoreStage::Replaying
        || prefix.next_source_ordinal != manifest.intent.head.history.outcomes + 1
        || terminal.reserved_bytes != 0
        || terminal.reserved_inodes != 0
    {
        return Err(
            "terminal restore requires complete selected history and no further work reservation"
                .into(),
        );
    }
    let mut next = prefix.clone();
    next.stage = RestoreStage::Complete;
    next.reservations = terminal;
    // Includes all current/live counts and exact verified-final coverage, not
    // just the ordinal or an arbitrary caller supplied 'completed' marker.
    next.validate(manifest)?;
    Ok(next)
}
pub fn plan_completion<B: CompletionBoundary>(
    job: &ObjectStore,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    terminal: RestoreReservations,
    b: &mut B,
) -> Result<CompletionPlan> {
    live(manifest, prefix, None, b)?;
    b.verify_job_namespace(manifest, prefix, job)?;
    b.retain_original_ciphertext(manifest, manifest.part_count)?;
    let next = proposed(manifest, prefix, terminal)?;
    let mut review = RestoreWindowReview {
        schema_version: 1,
        profile: RESTORE_PROFILE.into(),
        kind: RestoreWindowKind::Complete,
        job_sha256: prefix.job_sha256.clone(),
        manifest_sha256: manifest.sha256()?,
        prefix_sha256: prefix.sha256(manifest)?,
        target_head_sha256: prefix.target.sha256()?,
        proposed_data_sha256: next.sha256(manifest)?,
        source_ordinal: None,
        part: None,
        source_record_sha256: None,
        target_plan_sha256: None,
        review_sha256: String::new(),
    };
    review.finish(manifest, prefix)?;
    live(manifest, prefix, Some(&review), b)?;
    Ok(CompletionPlan { review, next })
}
struct TerminalIo<'a, B: CompletionBoundary> {
    b: &'a mut B,
    job: &'a ObjectStore,
    window: CheckedWindow<'a>,
}
impl<B: CompletionBoundary> TerminalIo<'_, B> {
    fn current(&mut self) -> Result<()> {
        self.window.current(self.b)?;
        self.b
            .verify_job_namespace(self.window.manifest, self.window.prefix, self.job)
    }
}
impl<B: CompletionBoundary> Boundary for TerminalIo<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.current()?;
        if binding != &self.window.prefix.target.binding {
            return Err("restore terminal retargets auxiliary namespace binding".into());
        }
        self.b.admit(binding, budget)?;
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.current()?;
        self.b.check(access)?;
        self.current()
    }
}
pub fn prepare_completion<'a, B: CompletionBoundary>(
    job: &'a ObjectStore,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    plan: CompletionPlan,
    b: &mut B,
) -> Result<PreparedCompletion<'a>> {
    plan.review.validate(manifest, prefix)?;
    live(manifest, prefix, Some(&plan.review), b)?;
    if plan.next != proposed(manifest, prefix, plan.next.reservations.clone())?
        || plan.review.proposed_data_sha256 != plan.next.sha256(manifest)?
    {
        return Err("restore terminal plan changed after original review".into());
    }
    b.verify_job_namespace(manifest, prefix, job)?;
    b.retain_original_ciphertext(manifest, manifest.part_count)?;
    let writer = job.acquire_writer()?;
    let bytes = plan.next.canonical_bytes(manifest)?;
    let mutation = Mutation {
        review_sha256: plan.review.review_sha256.clone(),
        decision: DecisionKind::NoChangeRetained,
        source_bytes: bytes.len() as u64,
    };
    let mut selected = TerminalIo {
        b,
        job,
        window: CheckedWindow::new(manifest, prefix, Some(&plan.review))?,
    };
    let mut guard = Guard::new(
        &mut selected,
        &prefix.target.binding,
        IoBudget {
            read_bytes: IMPORT_MAX_READ_BYTES,
            write_bytes: IMPORT_MAX_WRITE_BYTES,
            new_files: IMPORT_MAX_NEW_FILES,
        },
        Some(&mutation),
    )?;
    let prefix_object_sha256 = job.write_object(&bytes, &mut guard)?;
    guard.check()?;
    let commitment = TerminalCommitment {
        review_sha256: plan.review.review_sha256.clone(),
        base_prefix_sha256: prefix.sha256(manifest)?,
        prefix_object_sha256,
        next: plan.next,
        newly_allocated_job: guard.allocations.clone(),
    };
    drop(guard);
    drop(selected);
    b.verify_prepared_terminal(manifest, prefix, &plan.review, &commitment, job)?;
    live(manifest, prefix, Some(&plan.review), b)?;
    Ok(PreparedCompletion {
        job,
        _writer: writer,
        review: plan.review,
        commitment,
    })
}
/// Independent terminal semantics/readback before C publication. Physical
/// observations and original authority remain mandatory boundary operations;
/// the successful result itself is DATA and cannot select/complete a job.
pub fn verify_prepared_completion_data<B: CompletionBoundary>(
    job: &ObjectStore,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    review: &RestoreWindowReview,
    commitment: &TerminalCommitment,
    b: &mut B,
) -> Result<RestorePrefix> {
    live(manifest, prefix, Some(review), b)?;
    review.validate(manifest, prefix)?;
    let plan = plan_completion(
        job,
        manifest,
        prefix,
        commitment.next.reservations.clone(),
        b,
    )?;
    if plan.review != *review
        || plan.next != commitment.next
        || commitment.review_sha256 != review.review_sha256
        || commitment.base_prefix_sha256 != prefix.sha256(manifest)?
        || commitment.prefix_object_sha256 != commitment.next.sha256(manifest)?
    {
        return Err(
            "prepared terminal changes unrelated target/history/progress/reservations".into(),
        );
    }
    b.verify_prepared_terminal(manifest, prefix, review, commitment, job)?;
    let mut selected = TerminalIo {
        b,
        job,
        window: CheckedWindow::new(manifest, prefix, Some(review))?,
    };
    let bytes = job.read_page(
        &commitment.prefix_object_sha256,
        IoBudget {
            read_bytes: IMPORT_MAX_READ_BYTES,
            write_bytes: 0,
            new_files: 0,
        },
        &mut selected,
    )?;
    if bytes != commitment.next.canonical_bytes(manifest)? {
        return Err("prepared terminal lacks exact synchronized prefix bytes".into());
    }
    live(manifest, prefix, Some(review), selected.b)?;
    Ok(commitment.next.clone())
}
