//! Non-serializable semantic proof for the direct C publisher. Selection and
//! reads come only from its current original-operation backend. This proof is
//! NOT writer Go: actual C allocation/tails, owner creation observation and the
//! single durable C dispatch must all finish before a worker can write.
use super::job::{JobReservation, JobSelection};
use super::*;
use crate::content_index::builder::FixedBuilder;
use luma_content_store::corpus_index::BuilderIdentity;

pub(in crate::content_checkpoint::custody::v2_publication) trait PreparationView {
    fn current(&mut self, original: &mut OriginalCOperation<'_>) -> Result<(Selector, Descriptor)>;
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Option<Vec<u8>>>;
    fn read_record(
        &mut self,
        reference: &RecordRef,
        maximum: usize,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Vec<u8>>;
}

/// There is no public constructor, decoder, Clone or authorization conversion.
/// Only the two verifiers below construct this semantic token.
pub(in crate::content_checkpoint::custody::v2_publication) struct VerifiedIndexPreparation {
    parts: PreparationParts,
}
/// The closed record class a token's C event must anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::content_checkpoint::custody::v2_publication) enum PreparedKind {
    Phase,
    Start,
}
pub(in crate::content_checkpoint::custody::v2_publication) struct PreparationParts {
    pub(in crate::content_checkpoint::custody::v2_publication) kind: PreparedKind,
    pub(in crate::content_checkpoint::custody::v2_publication) base: Selector,
    pub(in crate::content_checkpoint::custody::v2_publication) owner_root: map::Root,
    pub(in crate::content_checkpoint::custody::v2_publication) index_root: map::Root,
    pub(in crate::content_checkpoint::custody::v2_publication) owner_literal: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_index_value:
        Option<Vec<u8>>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) records: Vec<(RecordRef, Vec<u8>)>,
    pub(in crate::content_checkpoint::custody::v2_publication) preparation: RecordRef,
    pub(in crate::content_checkpoint::custody::v2_publication) binding: OwnerBinding,
    pub(in crate::content_checkpoint::custody::v2_publication) input_sha256: String,
    pub(in crate::content_checkpoint::custody::v2_publication) source_sha256: String,
    pub(in crate::content_checkpoint::custody::v2_publication) original_authority: Audit,
}
impl VerifiedIndexPreparation {
    pub(in crate::content_checkpoint::custody::v2_publication) fn into_parts(
        self,
    ) -> PreparationParts {
        self.parts
    }
}

fn checked_record(
    view: &mut impl PreparationView,
    reference: &RecordRef,
    maximum: usize,
    original: &mut OriginalCOperation<'_>,
) -> Result<Vec<u8>> {
    original.check()?;
    reference.validate()?;
    if reference.bytes > maximum as u64 {
        return Err("index semantic C record exceeds its closed class before read".into());
    }
    let bytes = view.read_record(reference, maximum, original)?;
    original.check()?;
    if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
        return Err("index semantic C record changes selected full bytes".into());
    }
    Ok(bytes)
}

fn original_data(
    input: &request::Input,
    review_sha256: &str,
    original: &mut OriginalCOperation<'_>,
) -> Result<Attribution> {
    original.check()?;
    let source = original.source_binding();
    if source.schema_version != 1
        || source.purpose != SourcePurpose::IndexPrepare
        || source.binding != input.binding
        || source.profile != input.effect_profile(review_sha256)?
    {
        return Err(
            "index prewrite requires its genuine original IndexPrepare purpose/source".into(),
        );
    }
    let value = Attribution {
        rpc_sha256: source.request_sha256.clone(),
        profile: source.profile.clone(),
        storage_device: source.storage_device.clone(),
        worker_pid: source.worker_pid,
        worker_start: source.worker_start,
        worker_label: source.worker_label.clone(),
        lease: source.lease.clone(),
        paired_read: crate::content_index::scope::original_usage(
            &source.profile,
            &source.storage_device,
            &input.binding,
            &input.sha256()?,
            true,
        )?,
        effect: original.audit().clone(),
    };
    value.validate(input, review_sha256)?;
    // The calculated Read Use is merely attribution DATA. This fresh original
    // callback re-proves the real independent pair held by GrantBoundary.
    original.check()?;
    Ok(value)
}

/// The exact current selected C owner, observed under the original boundary.
struct Observed {
    base: Selector,
    descriptor: Descriptor,
    literal: Vec<u8>,
    owner_value: Vec<u8>,
    head_ref: RecordRef,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    index_value: Option<Vec<u8>>,
}
impl Observed {
    fn before(&self, index_sha256: Option<String>) -> Result<Base> {
        Ok(Base {
            binding: self.head.binding.clone(),
            descriptor_sha256: self.base.descriptor_sha256.clone(),
            nv_head: self.base.nv_head.clone(),
            owner_sha256: self.head.sha256()?,
            physical: self.physical.clone(),
            segments: self.head.history.segments,
            index_sha256,
        })
    }
}

fn observe(
    view: &mut impl PreparationView,
    input: &request::Input,
    original: &mut OriginalCOperation<'_>,
) -> Result<Observed> {
    original.check()?;
    let (base, descriptor) = view.current(original)?;
    original.check()?;
    descriptor.validate()?;
    descriptor.phase.require_ready()?;
    if descriptor.storage.is_none()
        || base != Selector::for_descriptor(&descriptor)?
        || descriptor.binding.installation != input.binding.installation
    {
        return Err(
            "index preparation cannot use a hash backend, stale C cut or another installation"
                .into(),
        );
    }
    let literal = owner_key(&input.binding)?.into_bytes();
    original.check()?;
    if view
        .value(&descriptor.roots.unavailable, &literal, original)?
        .is_some()
    {
        return Err("index preparation owner is C-selected unavailable".into());
    }
    original.check()?;
    let owner_value = view
        .value(&descriptor.roots.owners, &literal, original)?
        .ok_or("index preparation requires an existing C-selected paged owner")?;
    original.check()?;
    let owner: OwnerLeaf = canonical(&owner_value, map::MAX_VALUE_BYTES)?;
    owner.validate(&input.binding.installation, &descriptor.legacy)?;
    let (head_ref, physical) = match owner {
        OwnerLeaf::V2 {
            binding,
            head,
            physical,
        } if binding == input.binding => (head, physical),
        _ => return Err("index preparation cannot downgrade or invent a paged owner".into()),
    };
    let head =
        OwnerHeadV2::from_canonical(&checked_record(view, &head_ref, PAGE_BYTES, original)?)?;
    if head.binding != input.binding {
        return Err("index preparation selected owner head changes generation".into());
    }
    original.check()?;
    let index_value = view.value(&descriptor.roots.index_generations, &literal, original)?;
    original.check()?;
    Ok(Observed {
        base,
        descriptor,
        literal,
        owner_value,
        head_ref,
        head,
        physical,
        index_value,
    })
}

/// The exact next leaf record and its one bounded indirect C map reference.
fn replacement(leaf: &Leaf, binding: &OwnerBinding) -> Result<(Vec<u8>, (RecordRef, Vec<u8>))> {
    leaf.validate(binding)?;
    let leaf_bytes = serde_json::to_vec(leaf)?;
    let leaf_ref = RecordRef {
        sha256: hash(&leaf_bytes),
        bytes: leaf_bytes.len() as u64,
    };
    let value = serde_json::to_vec(&Reference {
        schema_version: 2,
        binding: binding.clone(),
        record: leaf_ref.clone(),
    })?;
    Reference::parse(&value, binding)?;
    Ok((value, (leaf_ref, leaf_bytes)))
}

fn unchanged(
    view: &mut impl PreparationView,
    observed: &Observed,
    original: &mut OriginalCOperation<'_>,
) -> Result<()> {
    original.check()?;
    let (again, actual) = view.current(original)?;
    original.check()?;
    if again != observed.base || actual != observed.descriptor {
        return Err("C selection changed before preparation semantic proof delivery".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn deliver(
    view: &mut impl PreparationView,
    observed: Observed,
    input: &request::Input,
    kind: PreparedKind,
    replacement_index_value: Vec<u8>,
    records: Vec<(RecordRef, Vec<u8>)>,
    preparation: RecordRef,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedIndexPreparation> {
    // This is only a semantic proof. The publisher counts ALL actual generated
    // location/map/event/descriptor/tail slots too and refuses before writing
    // when the complete plan cannot fit its existing 256-slot window.
    unchanged(view, &observed, original)?;
    Ok(VerifiedIndexPreparation {
        parts: PreparationParts {
            kind,
            base: observed.base,
            owner_root: observed.descriptor.roots.owners,
            index_root: observed.descriptor.roots.index_generations,
            owner_literal: observed.literal,
            expected_owner_value: observed.owner_value,
            expected_index_value: observed.index_value,
            replacement_index_value,
            records,
            preparation,
            binding: input.binding.clone(),
            input_sha256: input.sha256()?,
            source_sha256: hash(&serde_json::to_vec(&(
                "luma-c-original-worker-source-v1",
                original.source_binding(),
            ))?),
            original_authority: original.audit().clone(),
        },
    })
}

/// The plan is an opaque C-reconstructed Plan, never worker JSON. The actual
/// direct backend must additionally enforce its finite aggregate read budget
/// before every RPC and prove the same original selected location/NV cut.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_index_preparation(
    view: &mut impl PreparationView,
    input: &request::Input,
    plan: &phase::Plan,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedIndexPreparation> {
    original.check()?;
    input.validate()?;
    let review = plan.review()?;
    let attributed = original_data(input, &review.review_sha256, original)?;
    let objects = plan.planned_objects(|| original.check())?;
    let observed = observe(view, input, original)?;
    let leaf = if let Some(bytes) = &observed.index_value {
        let reference = Reference::parse(bytes, &input.binding)?;
        Leaf::parse(
            &checked_record(view, &reference.record, LEAF_BYTES, original)?,
            &input.binding,
        )?
    } else {
        return Err(
            "phase preparation requires an independently selected existing index job".into(),
        );
    };
    if leaf.has_preparation() {
        return Err(
            "unresolved index preparation must remain charged; no second writer may start".into(),
        );
    }
    let job_reference = leaf
        .current_job
        .as_ref()
        .ok_or("phase preparation has no selected current job")?;
    if job_reference.sha256 != review.base_sha256 {
        return Err("index plan does not start from the exact C-selected job".into());
    }
    let before = observed.before(Some(leaf.sha256()?))?;
    let (preparation, inventory) =
        Preparation::data(&before, input, &review, &objects, &attributed, &mut || {
            original.check()
        })?;
    preparation.replay_data(&before, input, &review, &objects, &attributed, &mut || {
        original.check()
    })?;
    let bytes = preparation.bytes()?;
    let reference = RecordRef {
        sha256: hash(&bytes),
        bytes: bytes.len() as u64,
    };
    let mut next_leaf = leaf;
    next_leaf.preparation = Some(reference.clone());
    let (value, leaf_record) = replacement(&next_leaf, &input.binding)?;
    let mut records = inventory.pages().to_vec();
    records.push((reference.clone(), bytes));
    records.push(leaf_record);
    deliver(
        view,
        observed,
        input,
        PreparedKind::Phase,
        value,
        records,
        reference,
        original,
    )
}

/// The fixed image builder as currently re-proved under the original boundary.
pub(in crate::content_checkpoint::custody::v2_publication) trait CurrentBuilder {
    fn identity(&self) -> &BuilderIdentity;
    fn check(&self, original: &mut OriginalCOperation<'_>) -> Result<()>;
}
impl CurrentBuilder for FixedBuilder {
    fn identity(&self) -> &BuilderIdentity {
        FixedBuilder::identity(self)
    }
    fn check(&self, original: &mut OriginalCOperation<'_>) -> Result<()> {
        FixedBuilder::check(self, || original.check())
    }
}

/// A first index job is reconstructed by C from the selected owner and the
/// current fixed builder; only an owner without any C-selected index leaf may
/// reserve one. The new leaf selects no job or generation, only the charge.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_index_start(
    view: &mut impl PreparationView,
    input: &request::Input,
    builder: &impl CurrentBuilder,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedIndexPreparation> {
    original.check()?;
    input.validate()?;
    if !matches!(input.operation, request::Operation::Start { .. }) {
        return Err("index job reservation requires an exact Start request".into());
    }
    builder.check(original)?;
    let identity = builder.identity().clone();
    let observed = observe(view, input, original)?;
    if observed.index_value.is_some() {
        return Err(
            "index Start reservation requires an owner without a C-selected index leaf".into(),
        );
    }
    let before = observed.before(None)?;
    let transition =
        JobReservation::transition_data(&before, &observed.head, input, &identity, &mut || {
            original.check()
        })?;
    let attributed = original_data(input, &transition.review_sha256, original)?;
    let reservation = JobReservation::data(
        &before,
        &observed.head,
        input,
        &identity,
        &attributed,
        &mut || original.check(),
    )?;
    reservation.replay_data(
        &before,
        &observed.head,
        input,
        &identity,
        &attributed,
        &mut || original.check(),
    )?;
    builder.check(original)?;
    if builder.identity() != &identity {
        return Err("fixed index builder changed during Start reservation".into());
    }
    let bytes = reservation.bytes()?;
    let reference = RecordRef {
        sha256: hash(&bytes),
        bytes: bytes.len() as u64,
    };
    let next_leaf = Leaf {
        schema_version: 2,
        binding: input.binding.clone(),
        current_generation: None,
        current_job: None,
        preparation: Some(reference.clone()),
    };
    let (value, leaf_record) = replacement(&next_leaf, &input.binding)?;
    deliver(
        view,
        observed,
        input,
        PreparedKind::Start,
        value,
        vec![(reference.clone(), bytes), leaf_record],
        reference,
        original,
    )
}

/// The C event parts of one job selection. The owner leaf and the index leaf
/// change together in one cut; neither is a writer Go.
pub(in crate::content_checkpoint::custody::v2_publication) struct SelectionParts {
    pub(in crate::content_checkpoint::custody::v2_publication) base: Selector,
    pub(in crate::content_checkpoint::custody::v2_publication) owner_root: map::Root,
    pub(in crate::content_checkpoint::custody::v2_publication) index_root: map::Root,
    pub(in crate::content_checkpoint::custody::v2_publication) owner_literal: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_owner_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) expected_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) replacement_index_value: Vec<u8>,
    pub(in crate::content_checkpoint::custody::v2_publication) records: Vec<(RecordRef, Vec<u8>)>,
    pub(in crate::content_checkpoint::custody::v2_publication) selection: RecordRef,
    pub(in crate::content_checkpoint::custody::v2_publication) binding: OwnerBinding,
    pub(in crate::content_checkpoint::custody::v2_publication) input_sha256: String,
    pub(in crate::content_checkpoint::custody::v2_publication) source_sha256: String,
    pub(in crate::content_checkpoint::custody::v2_publication) original_authority: Audit,
}
/// Move-only, like VerifiedIndexPreparation; only JobSelectionPlan::finish
/// constructs it.
pub(in crate::content_checkpoint::custody::v2_publication) struct VerifiedIndexSelection {
    parts: SelectionParts,
}
impl VerifiedIndexSelection {
    pub(in crate::content_checkpoint::custody::v2_publication) fn into_parts(
        self,
    ) -> SelectionParts {
        self.parts
    }
}

/// The C-verified store write of the reserved first job. It holds no writer
/// Go: the store writer still needs the actual original boundary, and nothing
/// is selected until the C event built by `finish` is published.
pub(in crate::content_checkpoint::custody::v2_publication) struct JobSelectionPlan {
    observed: Observed,
    before: Base,
    reservation: JobReservation,
    reservation_ref: RecordRef,
    job_bytes: Vec<u8>,
    attributed: Attribution,
}
impl JobSelectionPlan {
    pub(in crate::content_checkpoint::custody::v2_publication) fn head(&self) -> &OwnerHeadV2 {
        &self.observed.head
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn head_ref(&self) -> &RecordRef {
        &self.observed.head_ref
    }
    /// The physical accounting of the C-selected owner leaf.
    pub(in crate::content_checkpoint::custody::v2_publication) fn physical(
        &self,
    ) -> &PhysicalInventory {
        &self.observed.physical
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn job_bytes(&self) -> &[u8] {
        &self.job_bytes
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn next_job(
        &self,
    ) -> &BlobReference {
        &self.reservation.transition().next_job
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn objects(
        &self,
    ) -> &[ObjectWriteSpec] {
        &self.reservation.transition().objects
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn review_sha256(&self) -> &str {
        &self.reservation.transition().review_sha256
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn liability(
        &self,
    ) -> &policy::Liability {
        self.reservation.liability()
    }
    /// `physical_after` is the store inventory measured after the job blob was
    /// written; it must stay inside the reserved liability. The same original
    /// operation that was verified must still be current.
    pub(in crate::content_checkpoint::custody::v2_publication) fn finish(
        self,
        view: &mut impl PreparationView,
        physical_after: &PhysicalInventory,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<VerifiedIndexSelection> {
        original.check()?;
        let input = self.reservation.input();
        let transition = self.reservation.transition();
        if original_data(input, &transition.review_sha256, original)? != self.attributed {
            return Err("index job selection finishes under a different original operation".into());
        }
        let selection = JobSelection::data(
            &self.before,
            &self.reservation,
            &self.reservation_ref,
            physical_after,
            &self.attributed,
            &mut || original.check(),
        )?;
        let bytes = selection.bytes()?;
        let reference = RecordRef {
            sha256: hash(&bytes),
            bytes: bytes.len() as u64,
        };
        let binding = &self.before.binding;
        let next_leaf = Leaf {
            schema_version: 2,
            binding: binding.clone(),
            current_generation: None,
            current_job: Some(selection.job().clone()),
            preparation: None,
        };
        let (index_value, leaf_record) = replacement(&next_leaf, binding)?;
        let owner = OwnerLeaf::V2 {
            binding: binding.clone(),
            head: self.observed.head_ref.clone(),
            physical: physical_after.clone(),
        };
        owner.validate(&binding.installation, &self.observed.descriptor.legacy)?;
        let owner_value = serde_json::to_vec(&owner)?;
        if owner_value.len() > map::MAX_VALUE_BYTES {
            return Err("index job selection owner leaf exceeds its bounded map value".into());
        }
        let expected_index_value = self
            .observed
            .index_value
            .clone()
            .ok_or("index job selection lost its C-selected reservation leaf")?;
        unchanged(view, &self.observed, original)?;
        let input_sha256 = input.sha256()?;
        let binding = binding.clone();
        let observed = self.observed;
        Ok(VerifiedIndexSelection {
            parts: SelectionParts {
                base: observed.base,
                owner_root: observed.descriptor.roots.owners,
                index_root: observed.descriptor.roots.index_generations,
                owner_literal: observed.literal,
                expected_owner_value: observed.owner_value,
                replacement_owner_value: owner_value,
                expected_index_value,
                replacement_index_value: index_value,
                records: vec![(reference.clone(), bytes), leaf_record],
                selection: reference,
                binding,
                input_sha256,
                source_sha256: hash(&serde_json::to_vec(&(
                    "luma-c-original-worker-source-v1",
                    original.source_binding(),
                ))?),
                original_authority: original.audit().clone(),
            },
        })
    }
}

/// The reserved first job becomes the selected job only under a NEW original
/// operation for the same Start. C re-derives the transition review and the job
/// bytes from the selected owner and the current fixed builder and compares
/// them with the reservation record; the record itself is never trusted.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_index_selection(
    view: &mut impl PreparationView,
    input: &request::Input,
    builder: &impl CurrentBuilder,
    original: &mut OriginalCOperation<'_>,
) -> Result<JobSelectionPlan> {
    original.check()?;
    input.validate()?;
    if !matches!(input.operation, request::Operation::Start { .. }) {
        return Err("index job selection requires the exact reserved Start request".into());
    }
    builder.check(original)?;
    let identity = builder.identity().clone();
    let observed = observe(view, input, original)?;
    let value = observed
        .index_value
        .as_ref()
        .ok_or("index job selection requires a C-selected Start reservation")?;
    let reference = Reference::parse(value, &input.binding)?;
    let leaf = Leaf::parse(
        &checked_record(view, &reference.record, LEAF_BYTES, original)?,
        &input.binding,
    )?;
    let reservation_ref = match (
        &leaf.current_generation,
        &leaf.current_job,
        &leaf.preparation,
    ) {
        (None, None, Some(reserved)) => reserved.clone(),
        _ => {
            return Err(
                "index job selection requires a reserved first job and no selected job".into(),
            )
        }
    };
    let reservation = JobReservation::parse(&checked_record(
        view,
        &reservation_ref,
        PREPARATION_BYTES as usize,
        original,
    )?)?;
    let before = observed.before(Some(leaf.sha256()?))?;
    let reserved = reservation.base();
    // The cut advanced past the reservation; its owner, physical accounting
    // and segments did not.
    if reservation.input() != input
        || reservation.builder() != &identity
        || before.binding != reserved.binding
        || before.owner_sha256 != reserved.owner_sha256
        || before.physical != reserved.physical
        || before.segments != reserved.segments
    {
        return Err(
            "index job selection differs from the C-selected reservation owner/input/builder"
                .into(),
        );
    }
    let transition =
        JobReservation::transition_data(reserved, &observed.head, input, &identity, &mut || {
            original.check()
        })?;
    if &transition != reservation.transition() {
        return Err("independent first job review differs from the C-selected reservation".into());
    }
    let attributed = original_data(input, &transition.review_sha256, original)?;
    if attributed.effect.operation_id == reservation.original().effect.operation_id {
        return Err(
            "index job selection requires a new original operation, not the reservation one".into(),
        );
    }
    let job_bytes = reservation.job_bytes(&observed.head, &mut || original.check())?;
    builder.check(original)?;
    if builder.identity() != &identity {
        return Err("fixed index builder changed during job selection".into());
    }
    unchanged(view, &observed, original)?;
    Ok(JobSelectionPlan {
        observed,
        before,
        reservation,
        reservation_ref,
        job_bytes,
        attributed,
    })
}
