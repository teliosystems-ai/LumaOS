use super::super::backup;
use super::*;

/// Borrows the real locked/nondumpable decrypted part. It is neither clonable
/// nor deserializable, and contains no whole-corpus plaintext allocation.
pub struct ImportPartPlan<'a> {
    part: SnapshotPart<'a>,
    review: RestoreWindowReview,
    next: RestorePrefix,
}
impl ImportPartPlan<'_> {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedImportCommitment {
    pub review_sha256: String,
    pub base_prefix_sha256: String,
    pub proposed_prefix_sha256: String,
    pub newly_allocated: PhysicalInventory,
}
pub struct PreparedImportPart<'a> {
    store: &'a ObjectStore,
    _writer: std::fs::File,
    review: RestoreWindowReview,
    next: RestorePrefix,
    commitment: PreparedImportCommitment,
}
impl PreparedImportPart<'_> {
    pub fn review(&self) -> &RestoreWindowReview {
        &self.review
    }
    pub fn proposed_prefix(&self) -> &RestorePrefix {
        &self.next
    }
    pub fn commitment(&self) -> &PreparedImportCommitment {
        &self.commitment
    }
    /// The C adapter must independently validate actual created files, current
    /// job context and all publication/terminal tails before selecting this cut.
    pub fn acknowledge_selected(
        self,
        manifest: &WholeSnapshotManifest,
        b: &mut impl RestoreBoundary,
    ) -> Result<RestorePrefix> {
        if self.commitment.proposed_prefix_sha256 != self.next.sha256(manifest)? {
            return Err("prepared import prefix changed".into());
        }
        live(manifest, &self.next, None, b)?;
        b.verify_origin_namespace(manifest, &self.next, self.store)?;
        b.retain_original_ciphertext(manifest, self.next.import.next_part)?;
        Ok(self.next)
    }
}

/// Resolve the next part from the independently authenticated whole directory,
/// then bind its exact plaintext and progress to a new original Standard window.
/// Plaintext stays borrowed from the real locked decryption allocation.
pub fn plan_import_part<'a, B: RestoreBoundary>(
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    plaintext: &'a [u8],
    pages: &mut impl SnapshotPages,
    b: &mut B,
) -> Result<ImportPartPlan<'a>> {
    live(manifest, prefix, None, b)?;
    if prefix.stage != RestoreStage::Importing || prefix.import.next_part >= manifest.part_count {
        return Err("restore has no next import window".into());
    }
    let commitment = manifest.part_at(prefix.import.next_part, pages, &mut || {
        live(manifest, prefix, None, b)
    })?;
    let part = SnapshotPart::parse(plaintext, &manifest.intent, &mut || {
        live(manifest, prefix, None, b)
    })?;
    if part.header().number != commitment.number
        || part.sha256() != commitment.plaintext_sha256
        || plaintext.len() as u64 != commitment.plaintext_bytes
        || part.header().objects.len() as u32 != commitment.objects
        || part.header().previous_plaintext_sha256 != prefix.import.previous_plaintext_sha256
        || part.header().previous_plaintext_sha256 != commitment.previous_plaintext_sha256
    {
        return Err("decrypted part differs from authenticated directory or current prefix".into());
    }
    let mut next = prefix.clone();
    if next.import.next_part == 0 && next.import.stream_sha256 != backup::seed(&manifest.intent)? {
        return Err("initial restore stream does not bind exact whole snapshot intent".into());
    }
    part.visit_objects(&mut || live(manifest, prefix, None, b), |object, _| {
        if next
            .import
            .last_object_sha256
            .as_ref()
            .is_some_and(|last| last >= &object.object_sha256)
        {
            return Err("restore part repeats or reorders a raw origin object".into());
        }
        next.import.stream_sha256 = backup::extend(&next.import.stream_sha256, object)?;
        next.import.objects = next
            .import
            .objects
            .checked_add(1)
            .ok_or("restore object count overflow")?;
        next.import.raw_bytes = next
            .import
            .raw_bytes
            .checked_add(object.bytes)
            .ok_or("restore raw size overflow")?;
        next.import.incomplete_objects = next
            .import
            .incomplete_objects
            .checked_add(u64::from(!object.complete))
            .ok_or("restore incomplete count overflow")?;
        next.import.last_object_sha256 = Some(object.object_sha256.clone());
        Ok(())
    })?;
    next.import.next_part = next
        .import
        .next_part
        .checked_add(1)
        .ok_or("restore part count overflow")?;
    next.import.previous_plaintext_sha256 = Some(part.sha256().into());
    if next.import.next_part == manifest.part_count {
        next.stage = RestoreStage::Replaying;
    }
    next.validate(manifest)?;
    let mut review = RestoreWindowReview {
        schema_version: 1,
        profile: RESTORE_PROFILE.into(),
        kind: RestoreWindowKind::ImportPart,
        job_sha256: prefix.job_sha256.clone(),
        manifest_sha256: manifest.sha256()?,
        prefix_sha256: prefix.sha256(manifest)?,
        target_head_sha256: prefix.target.sha256()?,
        proposed_data_sha256: next.sha256(manifest)?,
        source_ordinal: None,
        part: Some(commitment),
        source_record_sha256: None,
        target_plan_sha256: None,
        review_sha256: String::new(),
    };
    review.finish(manifest, prefix)?;
    live(manifest, prefix, Some(&review), b)?;
    Ok(ImportPartPlan { part, review, next })
}

/// Prepare immutable, complete origin pages only. The real job namespace is
/// independently proved by the boundary; a manifest owner is not local C owner
/// authority. One Guard accounts the entire window, never one renewed budget
/// per object. Partial/failed writes stay inert and are never auto-adopted.
pub fn prepare_import_part<'s, B: RestoreBoundary>(
    store: &'s ObjectStore,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    plan: ImportPartPlan<'_>,
    budget: IoBudget,
    b: &mut B,
) -> Result<PreparedImportPart<'s>> {
    budget.validate()?;
    if budget.read_bytes > IMPORT_MAX_READ_BYTES
        || budget.write_bytes == 0
        || budget.write_bytes > IMPORT_MAX_WRITE_BYTES
        || budget.new_files == 0
        || budget.new_files > IMPORT_MAX_NEW_FILES
    {
        return Err("restore import exceeds its reviewed fixed per-part resource profile".into());
    }
    plan.review.validate(manifest, prefix)?;
    if plan.review.proposed_data_sha256 != plan.next.sha256(manifest)? {
        return Err("restore planned prefix changed".into());
    }
    live(manifest, prefix, Some(&plan.review), b)?;
    b.verify_origin_namespace(manifest, prefix, store)?;
    b.retain_original_ciphertext(manifest, plan.next.import.next_part)?;
    store.check_root(&manifest.intent.head.roots.artifacts)?;
    let writer = store.acquire_writer()?;
    live(manifest, prefix, Some(&plan.review), b)?;
    let mutation = Mutation {
        review_sha256: plan.review.review_sha256.clone(),
        decision: DecisionKind::Published,
        source_bytes: plan
            .review
            .part
            .as_ref()
            .ok_or("import commitment missing")?
            .plaintext_bytes,
    };
    let mut source = read::source_boundary(manifest, prefix, Some(&plan.review), b)?;
    let guard = std::cell::RefCell::new(Guard::new(
        &mut source,
        &manifest.intent.head.binding,
        budget,
        Some(&mutation),
    )?);
    plan.part
        .visit_objects(&mut || guard.borrow_mut().check(), |object, bytes| {
            if object.complete
                && store.write_object(bytes, &mut guard.borrow_mut())? != object.object_sha256
            {
                return Err("prepared complete origin object has unexpected hash".into());
            }
            Ok(())
        })?;
    guard.borrow_mut().check()?;
    let commitment = PreparedImportCommitment {
        review_sha256: plan.review.review_sha256.clone(),
        base_prefix_sha256: prefix.sha256(manifest)?,
        proposed_prefix_sha256: plan.next.sha256(manifest)?,
        newly_allocated: guard.borrow().allocations.clone(),
    };
    drop(guard);
    drop(source);
    live(manifest, prefix, Some(&plan.review), b)?;
    b.verify_origin_namespace(manifest, prefix, store)?;
    b.verify_prepared_import(manifest, prefix, &plan.review, &commitment, store)?;
    Ok(PreparedImportPart {
        store,
        _writer: writer,
        review: plan.review,
        next: plan.next,
        commitment,
    })
}
