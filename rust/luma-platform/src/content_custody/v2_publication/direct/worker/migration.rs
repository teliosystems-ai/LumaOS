//! Bounded direct C owner migration windows over the content-store side-by-side
//! v2 copy. Every v2 object and every C page/record of a window is allocated,
//! synchronized and read back before its sole NV dispatch. A prefix is
//! C-selected progress DATA; only the complete window replaces the V1 owner
//! leaf with the exact V2 head record and accounting. The fresh-namespace and
//! allocation joins are actual store inventory walks, not a C-reserved
//! namespace or joined protected C counters, and the cold verifier does not
//! re-verify object-store bytes.
use super::super::super::super::super::paged::FILE_BYTES;
use super::super::super::super::bootstrap::direct_progress::{
    verify_closure, Closure, Data as Replay,
};
use super::super::super::jobs::Role;
use super::cold::Cold;
use super::v1::{record, Cut, Warm};
use super::*;
use luma_content_store::v2::migration::{
    prepare_migration_window, review_migration, verify_migration_window_data, MigrationBoundary,
    MigrationPrefix, MigrationReview, MigrationWindowCommitment, PreparedMigrationWindow,
};
use luma_content_store::v2::{
    AppendCommitment, IoBudget, ObjectStore, OwnerBoundary, PhysicalInventory,
};
use luma_content_store::{Access, Boundary, DecisionKind, Repository, ResourceBudget};

const DOMAIN: &str = "luma-c-direct-owner-migration-v1";
const MAXIMUM_OUTCOMES: u32 = 16;
const MAXIMUM_RETAINED: u32 = 32;
const STORAGE_BYTES: u64 = 128 * 1024 * 1024;

fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn write_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: STORAGE_BYTES,
        new_files: 32768,
    }
}

/// One C-selected migration window. It is the closed DATA a cold verifier
/// replays; possession or deserialization never authorizes another window.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    sequence: u32,
    previous: Option<RecordRef>,
    review: RecordRef,
    window: RecordRef,
    head: Option<RecordRef>,
    maximum_outcomes: u32,
    maximum_retained: u32,
    profile: String,
    storage_device: String,
    original_authority: Audit,
}
impl Node {
    fn validate(&self, binding: &OwnerBinding) -> Result<()> {
        self.binding.validate()?;
        bounds(self.maximum_outcomes, self.maximum_retained)?;
        for reference in [Some(&self.review), Some(&self.window)]
            .into_iter()
            .chain([self.previous.as_ref(), self.head.as_ref()])
            .flatten()
        {
            reference.validate()?;
        }
        self.original_authority.validate()?;
        if self.schema_version != 1
            || self.domain != DOMAIN
            || self.binding != *binding
            || self.sequence == 0
            || (self.sequence == 1) != self.previous.is_none()
            || self.original_authority.subject != binding.owner
            || self.original_authority.subject_generation != binding.owner_generation
            || self.original_authority.operation_id.is_none()
        {
            return Err("direct owner migration node changes its closed owner window".into());
        }
        Ok(())
    }
}
fn bounds(maximum_outcomes: u32, maximum_retained: u32) -> Result<()> {
    if maximum_outcomes > MAXIMUM_OUTCOMES
        || maximum_retained > MAXIMUM_RETAINED
        || (maximum_outcomes == 0 && maximum_retained == 0)
    {
        return Err("direct owner migration window exceeds its closed finite bound".into());
    }
    Ok(())
}
fn reference(bytes: &[u8]) -> Result<RecordRef> {
    let reference = RecordRef {
        sha256: hash(bytes),
        bytes: bytes.len() as u64,
    };
    reference.validate()?;
    Ok(reference)
}
/// The original worker request commits to the exact reviewed legacy owner, the
/// exact C-selected prefix it continues and its finite window bound.
fn request(
    binding: &OwnerBinding,
    review: &MigrationReview,
    previous: Option<&MigrationPrefix>,
    maximum_outcomes: u32,
    maximum_retained: u32,
) -> Result<String> {
    let previous = previous
        .map(|prefix| prefix.canonical_bytes(review).map(|bytes| hash(&bytes)))
        .transpose()?;
    Ok(hash(&serde_json::to_vec(&(
        "luma-c-direct-owner-migration-request-v1",
        binding,
        review.sha256()?,
        previous,
        maximum_outcomes,
        maximum_retained,
    ))?))
}
/// Whether an original audit is the exact finite owner effect for the review.
fn attributed(
    binding: &OwnerBinding,
    review_sha256: &str,
    profile: &str,
    storage_device: &str,
    audit: &Audit,
) -> Result<bool> {
    Ok(audit.subject == binding.owner
        && audit.subject_generation == binding.owner_generation
        && audit.operation_id.is_some()
        && audit.usage
            == crate::content_governed::custody_usage(
                profile,
                storage_device,
                binding,
                review_sha256,
            )?)
}

/// The exact owner leaf a cut selects. Restore-reserved or unavailable owners
/// cannot enter or acknowledge a migration.
fn selected_leaf(
    cut: &mut impl Cut,
    binding: &OwnerBinding,
) -> Result<(String, map::Root, Vec<u8>, OwnerLeaf)> {
    cut.descriptor().phase.require_ready()?;
    let key = owner_key(binding)?;
    let root = cut.descriptor().roots.owners.clone();
    let value = cut
        .lookup(&root, key.as_bytes())?
        .ok_or("direct owner migration has no selected owner leaf")?;
    let leaf: OwnerLeaf = canonical(&value, map::MAX_VALUE_BYTES)?;
    leaf.validate(&binding.installation, &cut.descriptor().legacy)?;
    let exact = match &leaf {
        OwnerLeaf::V1 { state, .. } => state.binding == *binding,
        OwnerLeaf::V2 {
            binding: selected, ..
        } => selected == binding,
    };
    if !exact {
        return Err("direct owner migration selected owner binding changed".into());
    }
    let points = [
        cut.descriptor().roots.restore_reservations.clone(),
        cut.descriptor().roots.unavailable.clone(),
    ];
    for point in points {
        if cut.lookup(&point, key.as_bytes())?.is_some() {
            return Err(
                "direct owner migration refuses a restore-reserved or unavailable owner".into(),
            );
        }
    }
    Ok((key, root, value, leaf))
}

/// The actual selected V1 owner point a window continues and, after window
/// one, its C-selected node, review and unfinished prefix.
struct Prior {
    key: String,
    root: map::Root,
    value: Vec<u8>,
    state: VerifiedState,
    records: LegacyRecordClosure,
    node: Option<(RecordRef, Node)>,
    review: Option<(Vec<u8>, MigrationReview)>,
    previous: Option<MigrationPrefix>,
}
fn prior(cut: &mut impl Cut, binding: &OwnerBinding) -> Result<Prior> {
    let (key, root, value, leaf) = selected_leaf(cut, binding)?;
    let OwnerLeaf::V1 {
        state,
        records,
        migration_prefix,
    } = leaf
    else {
        return Err("direct owner migration cannot migrate a selected V2 owner again".into());
    };
    let mut budget = READ_BUDGET;
    let (node, review, previous) = match migration_prefix {
        None => (None, None, None),
        Some(selected) => {
            let node: Node = canonical(&record(cut, &selected, &mut budget)?, FILE_BYTES)?;
            node.validate(binding)?;
            let bytes = record(cut, &node.review, &mut budget)?;
            let review = MigrationReview::from_canonical(&bytes)?;
            let window = MigrationWindowCommitment::from_canonical(
                &record(cut, &node.window, &mut budget)?,
                &review,
            )?;
            window.validate(&review)?;
            if node.head.is_some() || window.next.complete || review.legacy != state {
                return Err("selected owner migration prefix differs from its V1 owner".into());
            }
            (
                Some((selected, node)),
                Some((bytes, review)),
                Some(window.next),
            )
        }
    };
    cut.live()?;
    Ok(Prior {
        key,
        root,
        value,
        state,
        records,
        node,
        review,
        previous,
    })
}

/// The deterministic C records and owner-leaf edit of one window. The warm
/// publisher and the cold verifier derive both from the same closed DATA.
struct Transition {
    node: RecordRef,
    edits: Vec<map::Edit>,
    records: BTreeMap<String, Vec<u8>>,
}
fn transition(
    prior: &Prior,
    review: &MigrationReview,
    window: &MigrationWindowCommitment,
    node: &Node,
    legacy: &LegacyCut,
) -> Result<Transition> {
    node.validate(&prior.state.binding)?;
    window.validate(review)?;
    let review_bytes = review.canonical_bytes()?;
    let window_bytes = window.canonical_bytes(review)?;
    let next = &window.next;
    let head_bytes = next.head.canonical_bytes()?;
    let head = reference(&head_bytes)?;
    let sequence = match &prior.node {
        None => Some(1),
        Some((_, previous)) => previous.sequence.checked_add(1),
    };
    if Some(node.sequence) != sequence
        || node.previous.as_ref() != prior.node.as_ref().map(|(selected, _)| selected)
        || node.review != reference(&review_bytes)?
        || node.window != reference(&window_bytes)?
        || prior
            .review
            .as_ref()
            .is_some_and(|(bytes, _)| *bytes != review_bytes)
        || review.legacy != prior.state
        || window.previous != prior.previous
        || window.steps.len() > node.maximum_outcomes as usize
        || window.retained.len() > node.maximum_retained as usize
        || node.head.is_some() != next.complete
        || (next.complete
            && (next.head_object_sha256 != head.sha256
                || head_bytes.len() > PAGE_BYTES
                || node.head.as_ref() != Some(&head)))
    {
        return Err("direct owner migration window differs from its selected C progress".into());
    }
    let node_bytes = serde_json::to_vec(node)?;
    let node_reference = reference(&node_bytes)?;
    let leaf = if next.complete {
        OwnerLeaf::V2 {
            binding: prior.state.binding.clone(),
            head: head.clone(),
            physical: next.physical_after.clone(),
        }
    } else {
        OwnerLeaf::V1 {
            state: prior.state.clone(),
            records: prior.records.clone(),
            migration_prefix: Some(node_reference.clone()),
        }
    };
    leaf.validate(&prior.state.binding.installation, legacy)?;
    let value = serde_json::to_vec(&leaf)?;
    if value.len() > map::MAX_VALUE_BYTES {
        return Err("direct owner migration leaf exceeds its bounded map value".into());
    }
    // The review record is written once by the first window; later windows
    // resolve the same C record through their selected node.
    let mut records = BTreeMap::from([
        (node_reference.sha256.clone(), node_bytes),
        (node.window.sha256.clone(), window_bytes),
    ]);
    if prior.node.is_none() {
        records.insert(node.review.sha256.clone(), review_bytes);
    }
    if next.complete {
        records.insert(head.sha256, head_bytes);
    }
    Ok(Transition {
        node: node_reference,
        edits: vec![map::Edit {
            key: prior.root.key(prior.key.as_bytes())?,
            expected_value_sha256: Some(hash(&prior.value)),
            value: Some(value),
        }],
        records,
    })
}

/// The actual C point and original worker that every content-store bound
/// re-observes. Its leaf, prefix and physical value were resolved by fresh C
/// reads and a store walk at construction; each admit/check re-proves the same
/// selected NV cut and live original before and after.
struct Current<'a, 'b, 'c, 's, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    original: &'b mut OriginalCOperation<'c>,
    store: &'s ObjectStore,
    binding: OwnerBinding,
    leaf: OwnerLeaf,
    review: Option<(String, u64)>,
    previous: Option<MigrationPrefix>,
    physical: PhysicalInventory,
}
impl<A: Checkpoint> Current<'_, '_, '_, '_, A> {
    fn live(&mut self) -> Result<()> {
        self.original.check()?;
        self.backend.live(&mut || self.original.check())
    }
}
impl<A: Checkpoint> Boundary for Current<'_, '_, '_, '_, A> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        if *binding != self.binding
            || budget.tasks != 1
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 512 * 1024 * 1024
            || budget.write_bytes > STORAGE_BYTES
            || budget.additional_storage_bytes > 512 * 1024 * 1024
        {
            return Err("direct owner migration exceeds its bounded original admission".into());
        }
        self.live()
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        self.live()?;
        let exact = match access {
            Access::Inspect { binding } => *binding == self.binding,
            Access::Mutate {
                binding,
                review_sha256,
                decision,
                source_bytes,
                storage_bytes,
            } => {
                *binding == self.binding
                    && decision == DecisionKind::Published
                    && storage_bytes <= STORAGE_BYTES
                    && self
                        .review
                        .as_ref()
                        .is_some_and(|(sha, bytes)| sha == review_sha256 && source_bytes <= *bytes)
            }
            Access::Recover { .. } => false,
        };
        if !exact {
            return Err(
                "direct owner migration access differs from its reviewed original effect".into(),
            );
        }
        self.live()
    }
}
impl<A: Checkpoint> MigrationBoundary for Current<'_, '_, '_, '_, A> {
    fn current_legacy_state(&mut self, expected: &VerifiedState) -> luma_content_store::Result<()> {
        self.live()?;
        match &self.leaf {
            OwnerLeaf::V1 { state, .. } if state == expected => Ok(()),
            _ => Err("direct owner migration legacy owner is not the selected V1 state".into()),
        }
    }
    fn current_migration_prefix(
        &mut self,
        review: &MigrationReview,
        prefix: Option<&MigrationPrefix>,
    ) -> luma_content_store::Result<PhysicalInventory> {
        self.current_legacy_state(&review.legacy)?;
        let sha = review.sha256()?;
        if self.review.as_ref().map(|(selected, _)| selected) != Some(&sha)
            || prefix != self.previous.as_ref()
        {
            return Err(
                "direct owner migration prefix differs from the actual C-selected progress".into(),
            );
        }
        Ok(self.physical.clone())
    }
    fn verify_migration_allocations(
        &mut self,
        commitment: &MigrationWindowCommitment,
    ) -> luma_content_store::Result<()> {
        if commitment.physical_before != self.physical || commitment.previous != self.previous {
            return Err("direct owner migration window changes its C-selected base".into());
        }
        let store = self.store;
        if store.inventory(read_budget(), self, |_| Ok(()))? != commitment.next.physical_after {
            return Err(
                "direct owner migration allocations differ from the actual store walk".into(),
            );
        }
        Ok(())
    }
}
impl<A: Checkpoint> OwnerBoundary for Current<'_, '_, '_, '_, A> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> luma_content_store::Result<()> {
        self.live()?;
        let bytes = head.canonical_bytes()?;
        match &self.leaf {
            OwnerLeaf::V2 {
                binding,
                head: selected,
                ..
            } if *binding == self.binding
                && head.binding == self.binding
                && selected.sha256 == hash(&bytes)
                && selected.bytes == bytes.len() as u64 =>
            {
                Ok(())
            }
            _ => Err("direct owner migration head is not the actual C-selected V2 owner".into()),
        }
    }
    fn current_physical_accounting(
        &mut self,
        head: &OwnerHeadV2,
    ) -> luma_content_store::Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        match &self.leaf {
            OwnerLeaf::V2 { physical, .. } => Ok(physical.clone()),
            OwnerLeaf::V1 { .. } => Err("direct owner migration has no selected V2 owner".into()),
        }
    }
    fn verify_prepared_allocations(
        &mut self,
        _: &AppendCommitment,
    ) -> luma_content_store::Result<()> {
        Err("direct owner migration acknowledgement never prepares an owner append".into())
    }
}

/// One prepared, NV-selected window. Its only uses are the explicit fresh C
/// acknowledgements below; it carries no authority of its own.
pub(in crate::content_checkpoint::custody::v2_publication) struct Window<'s> {
    prepared: PreparedMigrationWindow<'s>,
    store: &'s ObjectStore,
    review: MigrationReview,
    binding: OwnerBinding,
    node: RecordRef,
}
impl Window<'_> {
    pub(in crate::content_checkpoint::custody::v2_publication) fn complete(&self) -> bool {
        self.prepared.commitment().next.complete
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn next(&self) -> &MigrationPrefix {
        &self.prepared.commitment().next
    }
}

impl<A: Checkpoint> Backend<A> {
    /// Prepares, independently verifies and NV-selects exactly one bounded
    /// window for the actual original worker. The store-side window is not
    /// acknowledged here; only a fresh C read of the selected cut does that.
    pub(in crate::content_checkpoint::custody::v2_publication) fn migrate_owner_direct<'s>(
        mut self,
        source: &'s Repository,
        store: &'s ObjectStore,
        maximum_outcomes: u32,
        maximum_retained: u32,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Window<'s>> {
        let (token, window) = prepare(
            &mut self,
            source,
            store,
            maximum_outcomes,
            maximum_retained,
            original,
        )?;
        match super::storage::publish(self, token, original)? {
            Completed::OwnerMigration(reference) if reference == window.node => Ok(window),
            _ => Err("closed owner migration consumer received a different completion".into()),
        }
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn acknowledge_migration_prefix_direct(
        mut self,
        window: Window<'_>,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<MigrationPrefix> {
        let mut current = acknowledged(&mut self, &window, original)?;
        let Window {
            prepared, review, ..
        } = window;
        let prefix = prepared.acknowledge_prefix(&review, &mut current)?;
        current.live()?;
        Ok(prefix)
    }
    pub(in crate::content_checkpoint::custody::v2_publication) fn acknowledge_migration_owner_direct(
        mut self,
        window: Window<'_>,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<OwnerHeadV2> {
        let mut current = acknowledged(&mut self, &window, original)?;
        let Window {
            prepared, review, ..
        } = window;
        let head = prepared.acknowledge_owner(&review, &mut current)?;
        current.live()?;
        Ok(head)
    }
}

/// Re-resolves the actual selected owner leaf through a fresh C lookup and
/// requires that it selects exactly this window before any acknowledgement.
fn acknowledged<'a, 'b, 'c, 's, A: Checkpoint>(
    backend: &'a mut Backend<A>,
    window: &Window<'s>,
    original: &'b mut OriginalCOperation<'c>,
) -> Result<Current<'a, 'b, 'c, 's, A>> {
    backend.descriptor.phase.require_ready()?;
    original.check()?;
    let review_sha256 = window.review.sha256()?;
    let source = original.source_binding();
    if source.purpose != SourcePurpose::OwnerMigration
        || source.binding != window.binding
        || !attributed(
            &window.binding,
            &review_sha256,
            &source.profile,
            &source.storage_device,
            original.audit(),
        )?
    {
        return Err(
            "direct owner migration acknowledgement differs from its original owner effect".into(),
        );
    }
    let commitment = window.prepared.commitment();
    let mut cut = Warm {
        backend: &mut *backend,
        original: &mut *original,
    };
    let (_, _, _, leaf) = selected_leaf(&mut cut, &window.binding)?;
    let mut budget = READ_BUDGET;
    let exact = match &leaf {
        OwnerLeaf::V1 {
            migration_prefix: Some(selected),
            ..
        } if !commitment.next.complete && *selected == window.node => {
            let node: Node = canonical(&record(&mut cut, selected, &mut budget)?, FILE_BYTES)?;
            record(&mut cut, &node.window, &mut budget)?
                == commitment.canonical_bytes(&window.review)?
        }
        OwnerLeaf::V2 { head, physical, .. } if commitment.next.complete => {
            *head == reference(&commitment.next.head.canonical_bytes()?)?
                && *physical == commitment.next.physical_after
        }
        _ => false,
    };
    cut.live()?;
    if !exact {
        return Err(
            "direct owner migration window is not the actual C-selected owner progress".into(),
        );
    }
    Ok(Current {
        backend,
        original,
        store: window.store,
        binding: window.binding.clone(),
        leaf,
        review: Some((review_sha256, window.review.source_bytes)),
        previous: Some(commitment.next.clone()),
        physical: commitment.next.physical_after.clone(),
    })
}

fn prepare<'s, A: Checkpoint>(
    backend: &mut Backend<A>,
    source: &'s Repository,
    store: &'s ObjectStore,
    maximum_outcomes: u32,
    maximum_retained: u32,
    original: &mut OriginalCOperation<'_>,
) -> Result<(VerifiedTransition, Window<'s>)> {
    bounds(maximum_outcomes, maximum_retained)?;
    backend.descriptor.phase.require_ready()?;
    original.check()?;
    let typed = original.source_binding().clone();
    let audit = original.audit().clone();
    audit.validate()?;
    if typed.purpose != SourcePurpose::OwnerMigration
        || audit.subject != typed.binding.owner
        || audit.subject_generation != typed.binding.owner_generation
        || audit.operation_id.is_none()
    {
        return Err(
            "direct owner migration differs from the actual original owner/source effect".into(),
        );
    }
    let binding = typed.binding.clone();
    let prior = prior(
        &mut Warm {
            backend: &mut *backend,
            original: &mut *original,
        },
        &binding,
    )?;
    let mut current = Current {
        backend: &mut *backend,
        original: &mut *original,
        store,
        binding: binding.clone(),
        leaf: OwnerLeaf::V1 {
            state: prior.state.clone(),
            records: prior.records.clone(),
            migration_prefix: prior.node.as_ref().map(|(selected, _)| selected.clone()),
        },
        review: None,
        previous: prior.previous.clone(),
        physical: PhysicalInventory::default(),
    };
    current.physical = store.inventory(read_budget(), &mut current, |_| Ok(()))?;
    if prior
        .previous
        .as_ref()
        .is_some_and(|previous| previous.physical_after != current.physical)
    {
        return Err("actual v2 store differs from its C-selected migration prefix".into());
    }
    let review = match &prior.review {
        Some((_, review)) => review.clone(),
        None => review_migration(source, &prior.state, &mut current)?,
    };
    let review_sha256 = review.sha256()?;
    if review.legacy != prior.state
        || !attributed(
            &binding,
            &review_sha256,
            &typed.profile,
            &typed.storage_device,
            &audit,
        )?
        || request(
            &binding,
            &review,
            prior.previous.as_ref(),
            maximum_outcomes,
            maximum_retained,
        )? != typed.request_sha256
    {
        return Err("direct owner migration differs from its original reviewed request".into());
    }
    current.review = Some((review_sha256.clone(), review.source_bytes));
    let prepared = prepare_migration_window(
        source,
        store,
        &review,
        prior.previous.as_ref(),
        maximum_outcomes as usize,
        maximum_retained as usize,
        write_budget(),
        &mut current,
    )?;
    let commitment = prepared.commitment().clone();
    let next = verify_migration_window_data(
        source,
        store,
        &review,
        &commitment,
        read_budget(),
        &mut current,
    )?;
    current.live()?;
    if next != commitment.next {
        return Err("prepared owner migration window differs from its independent replay".into());
    }
    let node = Node {
        schema_version: 1,
        domain: DOMAIN.into(),
        binding: binding.clone(),
        sequence: prior
            .node
            .as_ref()
            .map_or(Some(1), |(_, node)| node.sequence.checked_add(1))
            .ok_or("direct owner migration window sequence exhausted")?,
        previous: prior.node.as_ref().map(|(selected, _)| selected.clone()),
        review: reference(&review.canonical_bytes()?)?,
        window: reference(&commitment.canonical_bytes(&review)?)?,
        head: if next.complete {
            Some(reference(&next.head.canonical_bytes()?)?)
        } else {
            None
        },
        maximum_outcomes,
        maximum_retained,
        profile: typed.profile.clone(),
        storage_device: typed.storage_device.clone(),
        original_authority: audit.clone(),
    };
    let transition = transition(
        &prior,
        &review,
        &commitment,
        &node,
        &backend.descriptor.legacy,
    )?;
    let mut context = backend.context()?;
    let selected = context.clone();
    context.review_sha256 = Some(review_sha256.clone());
    let source_sha256 = hash(&COperation::Worker(original).source_bytes()?);
    let mut cache = Memory {
        backend,
        original,
        context: context.clone(),
        generated: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let root = map::prepare_update(
        &prior.root,
        &transition.edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: MEMORY_BYTES as u64,
            new_files: MEMORY_PAGES as u32,
        },
        &mut cache,
    )?;
    cache.readonly = true;
    map::verify_update(
        &prior.root,
        &root,
        &transition.edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: 0,
            new_files: 0,
        },
        &mut cache,
    )?;
    let generated = std::mem::take(&mut cache.generated);
    cache.backend.live(&mut || cache.original.check())?;
    if cache.backend.context()? != selected {
        return Err("direct owner migration C cut changed during semantic preparation".into());
    }
    let mut roots = cache.backend.descriptor.roots.clone();
    roots.owners = root;
    let token = VerifiedTransition {
        base: Selector::for_descriptor(&cache.backend.descriptor)?,
        base_frame_sha256: cache.backend.descriptor_frame_sha256.clone(),
        source_sha256: source_sha256.clone(),
        request_sha256: typed.request_sha256.clone(),
        review_sha256,
        roots,
        edits: BTreeMap::from([(map::Kind::OwnerStates, transition.edits)]),
        pages: generated,
        records: transition.records,
        operation: OperationData::OwnerMigration {
            binding: binding.clone(),
            request_sha256: typed.request_sha256,
            source_sha256,
            event: transition.node.clone(),
            original_authority: audit,
        },
        read_cas: Vec::new(),
        outcome: Completed::OwnerMigration(transition.node.clone()),
    };
    Ok((
        token,
        Window {
            prepared,
            store,
            review,
            binding,
            node: transition.node,
        },
    ))
}

/// Verifies that the actual selected descriptor is the exact deterministic
/// owner migration window over its authenticated previous cut. Only that last
/// transition is reconstructed; its object-store bytes are not re-read here.
pub(in crate::content_checkpoint::custody::v2_publication) fn verify_selected(
    files: &Files,
    pages: &PageStore,
    current: &Descriptor,
    location: &slots::SealedReference,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    current.validate()?;
    let storage = current
        .storage
        .as_ref()
        .ok_or("cold owner migration has no selected storage")?;
    if current.sequence <= 1
        || storage.schema_version != 2
        || storage.descriptor_slot != location.slot
        || location.sha256 != hash(&current.slot_frame()?)
        || location.bytes != PAGE_BYTES as u64
    {
        return Err("cold owner migration is not its exact selected descriptor location".into());
    }
    let OperationData::OwnerMigration {
        binding,
        request_sha256,
        source_sha256,
        event,
        original_authority,
    } = &current.operation
    else {
        return Err(
            "cold owner migration verifier refuses a different semantic event class".into(),
        );
    };
    current.phase.require_ready()?;
    original_authority.validate()?;
    let mut data = Replay::new(
        pages,
        storage.locations.clone(),
        check,
        map::Context {
            binding: current.binding.clone(),
            selected_descriptor_sha256: hash(&current.bytes()?),
            selected_nv_head: current.selected_nv_head.clone(),
            review_sha256: None,
        },
        MEMORY_BYTES,
        MEMORY_PAGES,
    );
    let previous_sha = current
        .previous_descriptor_sha256
        .as_ref()
        .ok_or("cold owner migration has no previous full-frame commitment")?;
    let previous_location = locations::lookup(&storage.locations, previous_sha, &mut data)?
        .ok_or("cold owner migration lost the exact selected previous descriptor address")?;
    let previous =
        Descriptor::from_slot_frame(&locations::Io::read(&mut data, &previous_location)?)?;
    // Only event classes with a cold lineage verifier are inherited; an index
    // phase preparation has none yet and is refused.
    if previous_location.sha256 != *previous_sha
        || previous.binding != current.binding
        || previous.legacy != current.legacy
        || previous.phase != current.phase
        || previous.sequence.checked_add(1) != Some(current.sequence)
        || previous.global_ordinal.checked_add(1) != Some(current.global_ordinal)
        || previous.selected_nv_head != current.previous_nv_head
        || !matches!(
            previous.operation,
            OperationData::BootstrapProgress { .. }
                | OperationData::V1Publication { .. }
                | OperationData::OwnerMigration { .. }
                | OperationData::IndexJobReservation { .. }
                | OperationData::IndexJobSelection { .. }
        )
    {
        return Err(
            "cold owner migration does not continue the exact authenticated old cut".into(),
        );
    }
    previous.phase.require_ready()?;
    let previous_storage = previous
        .storage
        .as_ref()
        .ok_or("cold owner migration previous direct storage absent")?;
    let old_jobs = previous_storage
        .jobs
        .as_ref()
        .ok_or("cold owner migration previous job index absent")?;
    let jobs = storage
        .jobs
        .as_ref()
        .ok_or("cold owner migration current job index absent")?;
    // Every record of this window resolves through the current location tree;
    // the previous cut alone supplies the owner point it continues.
    event.validate()?;
    let bytes = data.record(&event.sha256)?;
    if bytes.len() as u64 != event.bytes {
        return Err("cold owner migration node changes its complete byte length".into());
    }
    let node: Node = canonical(&bytes, FILE_BYTES)?;
    node.validate(binding)?;
    if node.original_authority != *original_authority {
        return Err("cold owner migration node differs from its selected finite effect".into());
    }
    let review = MigrationReview::from_canonical(&data.record(&node.review.sha256)?)?;
    let window =
        MigrationWindowCommitment::from_canonical(&data.record(&node.window.sha256)?, &review)?;
    let review_sha256 = review.sha256()?;
    if !attributed(
        binding,
        &review_sha256,
        &node.profile,
        &node.storage_device,
        original_authority,
    )? || request(
        binding,
        &review,
        window.previous.as_ref(),
        node.maximum_outcomes,
        node.maximum_retained,
    )? != *request_sha256
    {
        return Err("cold owner migration differs from its original reviewed request".into());
    }
    let previous_context = map::Context {
        binding: previous.binding.clone(),
        selected_descriptor_sha256: hash(&previous.bytes()?),
        selected_nv_head: previous.selected_nv_head.clone(),
        review_sha256: None,
    };
    data.set_locations(previous_storage.locations.clone());
    data.set_context(previous_context.clone());
    let prior = prior(
        &mut Cold {
            data: &mut data,
            files,
            previous: &previous,
        },
        binding,
    )?;
    let transition = transition(&prior, &review, &window, &node, &previous.legacy)?;
    if transition.node != *event {
        return Err("cold owner migration node differs from independent window replay".into());
    }
    let context = map::Context {
        review_sha256: Some(review_sha256.clone()),
        ..previous_context
    };
    data.set_context(context.clone());
    let root = map::prepare_update(
        &prior.root,
        &transition.edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: MEMORY_BYTES as u64,
            new_files: MEMORY_PAGES as u32,
        },
        &mut data,
    )?;
    data.set_readonly(true);
    map::verify_update(
        &prior.root,
        &root,
        &transition.edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: 0,
            new_files: 0,
        },
        &mut data,
    )?;
    let generated = data.take_cache();
    let mut roots = previous.roots.clone();
    roots.owners = root;
    if roots != current.roots {
        return Err("cold owner migration roots differ from independent window replay".into());
    }
    let token = VerifiedTransition {
        base: Selector::for_descriptor(&previous)?,
        base_frame_sha256: previous_sha.clone(),
        source_sha256: source_sha256.clone(),
        request_sha256: request_sha256.clone(),
        review_sha256,
        roots,
        edits: BTreeMap::from([(map::Kind::OwnerStates, transition.edits)]),
        pages: generated,
        records: transition.records,
        operation: current.operation.clone(),
        read_cas: Vec::new(),
        outcome: Completed::OwnerMigration(transition.node),
    };
    let plan =
        super::storage::layout(&previous.binding, Some(previous_storage), &token, &mut data)?;
    if storage.controls != previous_storage.controls || storage.descriptor_slot.job != plan.job {
        return Err("cold owner migration differs from its deterministic reviewed layout".into());
    }
    data.set_locations(storage.locations.clone());
    let semantic = plan
        .data
        .iter()
        .map(|value| {
            let role = if value.kind == slots::Kind::Record {
                Role::SemanticRecord
            } else {
                Role::SemanticPage
            };
            (value.sha256.as_str(), value.bytes.as_slice(), role)
        })
        .collect();
    verify_closure(
        &mut data,
        Closure {
            binding: &current.binding,
            storage,
            previous: previous_storage,
            old_jobs,
            jobs,
            location,
            previous_sha256: previous_sha,
            previous_location,
            job: &plan.job,
            specs: &plan.specifications,
            base_descriptor_sha256: &token.base.descriptor_sha256,
            request_sha256: &plan.request,
            source_sha256: &plan.source,
            review_sha256: &plan.window,
            semantic,
            location_nodes: plan.locations,
            job_nodes: plan.jobs,
        },
    )
}
