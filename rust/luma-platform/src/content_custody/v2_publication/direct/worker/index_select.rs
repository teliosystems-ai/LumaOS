//! The reserved first index job becomes the selected job. C re-derives the
//! reservation's transition and job bytes, the actual original worker writes
//! the job blob under the SAME retained owner writer, and only then is one C
//! event built that replaces the owner leaf (its measured accounting) and the
//! index leaf (the selected job) together. The store write is DATA until that
//! event is NV-selected.
//!
//! A crashed attempt can leave the store ahead of C: the blob is written and
//! nothing is selected. A retry then refuses, because the observed writer
//! begin requires the actual store walk to equal the C-selected accounting.
//! Reconciling such an attempt is later G3 work; until a selection is
//! published the reservation's liability stays charged.
use super::index_preparation::View;
use super::*;
use crate::content_checkpoint::custody::v2_publication::index::effects;
use crate::content_index::{policy, request};
use luma_content_store::v2::{
    AppendCommitment, AppendWriterBoundary, HeldNamespaceObservation, HeldWriterObservation,
    IoBudget, Mutation, ObjectStore, OwnerBoundary, PhysicalInventory,
};
use luma_content_store::{Access, Boundary, DecisionKind, ResourceBudget};
use std::fs::File;
use std::os::unix::fs::MetadataExt;

fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn observation_budget() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
/// The per-object reserve of the observed metadata writer, over the exact
/// reserved write set. It must fit the reservation's liability.
fn write_budget(objects: usize, liability: &policy::Liability) -> Result<IoBudget> {
    let count = u64::try_from(objects)?;
    let budget = IoBudget {
        read_bytes: count
            .checked_mul(32 * 1024)
            .ok_or("index job selection read reserve overflow")?
            .max(1),
        write_bytes: count
            .checked_mul(128 * 1024)
            .ok_or("index job selection write reserve overflow")?,
        new_files: u32::try_from(
            count
                .checked_mul(3)
                .ok_or("index job selection inode reserve overflow")?,
        )?,
    };
    if count == 0
        || budget.write_bytes > liability.allocated_bytes
        || u64::from(budget.new_files)
            > liability
                .regular_files
                .checked_add(liability.directories)
                .ok_or("index job selection liability overflow")?
    {
        return Err("index job selection write scope exceeds its reserved liability".into());
    }
    Ok(budget)
}

/// The actual C point and original worker that every content-store bound
/// re-observes. The owner head and its accounting were resolved by the fresh
/// C verifier; each admit/check re-proves the same selected NV cut and live
/// original before and after. The writer OFD is advisory DATA observed from
/// this process; it is never a creator, grant or publication.
struct Current<'a, 'b, 'c, 's, A: Checkpoint> {
    backend: &'a mut Backend<A>,
    original: &'b mut OriginalCOperation<'c>,
    store: &'s ObjectStore,
    binding: OwnerBinding,
    head: RecordRef,
    physical: PhysicalInventory,
    review: String,
    source_bytes: u64,
    write: IoBudget,
    namespace: Option<HeldNamespaceObservation>,
    held: Option<HeldWriterObservation>,
}
impl<A: Checkpoint> Current<'_, '_, '_, '_, A> {
    fn live(&mut self) -> Result<()> {
        self.original.check()?;
        self.backend.live(&mut || self.original.check())
    }
    fn exact(&mut self, head: &OwnerHeadV2, review: &str) -> luma_content_store::Result<()> {
        self.current_owner_head(head)?;
        if review != self.review {
            return Err("index job selection writer changes its reserved review".into());
        }
        Ok(())
    }
}
impl<A: Checkpoint> Boundary for Current<'_, '_, '_, '_, A> {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        self.live()?;
        let additional = self
            .write
            .write_bytes
            .checked_add(u64::from(self.write.new_files) * 8192)
            .ok_or("index job selection physical reserve overflow")?;
        if *binding != self.binding
            || budget.tasks != 1
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 512 * 1024 * 1024
            || budget.write_bytes > self.write.write_bytes
            || budget.additional_storage_bytes > additional
        {
            return Err("index job selection exceeds its bounded original admission".into());
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
                    && review_sha256 == self.review
                    && source_bytes <= self.source_bytes
                    && storage_bytes <= self.write.write_bytes
            }
            Access::Recover { .. } => false,
        };
        if !exact {
            return Err(
                "index job selection access differs from its reserved original effect".into(),
            );
        }
        self.live()
    }
}
impl<A: Checkpoint> OwnerBoundary for Current<'_, '_, '_, '_, A> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> luma_content_store::Result<()> {
        self.live()?;
        let bytes = head.canonical_bytes()?;
        if head.binding != self.binding
            || hash(&bytes) != self.head.sha256
            || bytes.len() as u64 != self.head.bytes
        {
            return Err("index job selection head is not the actual C-selected V2 owner".into());
        }
        Ok(())
    }
    fn current_physical_accounting(
        &mut self,
        head: &OwnerHeadV2,
    ) -> luma_content_store::Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.physical.clone())
    }
    fn verify_prepared_allocations(
        &mut self,
        _: &AppendCommitment,
    ) -> luma_content_store::Result<()> {
        Err("index job selection never prepares an owner append".into())
    }
}
impl<A: Checkpoint> AppendWriterBoundary for Current<'_, '_, '_, '_, A> {
    fn begin_writer(
        &mut self,
        head: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> luma_content_store::Result<()> {
        self.exact(head, review_sha256)?;
        if self.held.is_some() {
            return Err("index job selection repeats its observed writer".into());
        }
        let store = self.store;
        if store.inventory(read_budget(), self, |_| Ok(()))? != self.physical {
            return Err(
                "actual v2 store differs from the C-selected owner accounting at writer begin"
                    .into(),
            );
        }
        let namespace = self
            .namespace
            .take()
            .ok_or("index job selection writer has no observed namespace")?;
        let held = store.observe_existing_writer(
            &namespace,
            writer.try_clone()?,
            std::process::id(),
            observation_budget(),
            self,
        );
        self.namespace = Some(namespace);
        self.held = Some(held?);
        self.exact(head, review_sha256)
    }
    fn check_writer(
        &mut self,
        head: &OwnerHeadV2,
        review_sha256: &str,
        writer: &File,
    ) -> luma_content_store::Result<()> {
        self.exact(head, review_sha256)?;
        let inode = writer.metadata()?.ino();
        let (namespace, held) = match (self.namespace.take(), self.held.take()) {
            (Some(namespace), Some(held)) => (namespace, held),
            (namespace, held) => {
                self.namespace = namespace;
                self.held = held;
                return Err("index job selection writer was never observed".into());
            }
        };
        let same = inode == held.data().root.inode;
        let store = self.store;
        let result = if same {
            store.check_existing_writer(&namespace, &held, observation_budget(), self)
        } else {
            Err("index job selection observed writer changed".into())
        };
        self.namespace = Some(namespace);
        self.held = Some(held);
        result?;
        self.exact(head, review_sha256)
    }
}

impl<A: Checkpoint> Backend<A> {
    /// Writes the reserved first job blob and NV-selects it for the actual
    /// original worker. The reservation is never trusted: C re-derives it.
    pub(in crate::content_checkpoint::custody::v2_publication) fn select_index_start_direct(
        mut self,
        store: &ObjectStore,
        input: &request::Input,
        builder: &impl effects::CurrentBuilder,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<RecordRef> {
        let token = select(&mut self, store, input, builder, original)?;
        let expected = match &token.outcome {
            Completed::IndexJobSelection(reference) => reference.clone(),
            _ => return Err("index job selection built a different completion class".into()),
        };
        match super::storage::publish(self, token, original)? {
            Completed::IndexJobSelection(reference) if reference == expected => Ok(reference),
            _ => Err(
                "closed index job-selection consumer received a different semantic completion"
                    .into(),
            ),
        }
    }
}

fn select<A: Checkpoint>(
    backend: &mut Backend<A>,
    store: &ObjectStore,
    input: &request::Input,
    builder: &impl effects::CurrentBuilder,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedTransition> {
    backend.descriptor.phase.require_ready()?;
    original.check()?;
    if original.source_binding().purpose != SourcePurpose::IndexPrepare
        || original.source_binding().binding != input.binding
    {
        return Err("index job selection differs from the actual original index source".into());
    }
    let plan = effects::verify_index_selection(
        &mut View {
            backend: &mut *backend,
            remaining: READ_BUDGET,
        },
        input,
        builder,
        original,
    )?;
    let write = write_budget(plan.objects().len(), plan.liability())?;
    let mutation = Mutation {
        review_sha256: plan.review_sha256().to_owned(),
        decision: DecisionKind::Published,
        source_bytes: u64::try_from(plan.job_bytes().len())?,
    };
    // Every store bound below re-proves the same NV cut and live original.
    let physical_after = {
        let mut current = Current {
            backend: &mut *backend,
            original: &mut *original,
            store,
            binding: input.binding.clone(),
            head: plan.head_ref().clone(),
            physical: plan.physical().clone(),
            review: mutation.review_sha256.clone(),
            source_bytes: mutation.source_bytes,
            write,
            namespace: None,
            held: None,
        };
        if store.inventory(read_budget(), &mut current, |_| Ok(()))? != current.physical {
            return Err(
                "actual v2 store differs from the C-selected owner accounting before job selection"
                    .into(),
            );
        }
        current.namespace = Some(store.observe_namespace(observation_budget(), &mut current)?);
        let writer = store.prepare_index_observed(plan.head(), &mutation, write, &mut current)?;
        let job = writer.prepare_blob(plan.job_bytes(), write, &mutation, &mut current, |b| {
            b.live()?;
            Ok(())
        })?;
        if job != *plan.next_job() {
            return Err("actual job blob differs from the C-reserved job reference".into());
        }
        if store.read_blob(&job, read_budget(), &mut current)? != plan.job_bytes() {
            return Err("actual job blob read-back differs from the C-derived job bytes".into());
        }
        let after = store.inventory(read_budget(), &mut current, |_| Ok(()))?;
        writer.check(&mut current)?;
        drop(writer);
        current.live()?;
        after
    };
    let parts = plan
        .finish(
            &mut View {
                backend: &mut *backend,
                remaining: READ_BUDGET,
            },
            &physical_after,
            original,
        )?
        .into_parts();
    let selected = Selector::for_descriptor(&backend.descriptor)?;
    if parts.base != selected
        || parts.owner_root != backend.descriptor.roots.owners
        || parts.index_root != backend.descriptor.roots.index_generations
        || parts.original_authority != *original.audit()
        || parts.binding != original.source_binding().binding
        || parts.source_sha256 != hash(&COperation::Worker(original).source_bytes()?)
        || parts.input_sha256 != input.sha256()?
    {
        return Err("verified index job selection changed actual C/source/owner/finite effect before exact storage planning".into());
    }
    let expected_owner = backend.lookup(
        &parts.owner_root,
        &parts.owner_literal,
        &mut COperation::Worker(original),
    )?;
    let expected_index = backend.lookup(
        &parts.index_root,
        &parts.owner_literal,
        &mut COperation::Worker(original),
    )?;
    if expected_owner.as_deref() != Some(parts.expected_owner_value.as_slice())
        || expected_index.as_deref() != Some(parts.expected_index_value.as_slice())
    {
        return Err(
            "verified index job selection no longer matches actual selected owner/index CAS".into(),
        );
    }
    let mut records = BTreeMap::new();
    let mut bytes = 0_usize;
    for (reference, value) in parts.records {
        reference.validate()?;
        if reference.bytes != value.len() as u64
            || hash(&value) != reference.sha256
            || value.len() > super::super::super::super::super::paged::FILE_BYTES
            || records.len() >= 256
            || bytes
                .checked_add(value.len())
                .map_or(true, |n| n > 16 * 1024 * 1024)
        {
            return Err("verified index job selection records exceed the actual direct finite window before allocation".into());
        }
        bytes += value.len();
        if records.insert(reference.sha256, value).is_some() {
            return Err("verified index job selection repeats a complete record digest".into());
        }
    }
    if records
        .get(&parts.selection.sha256)
        .map(|value| value.len() as u64)
        != Some(parts.selection.bytes)
    {
        return Err("verified index job selection omits its actual canonical record bytes".into());
    }
    let owner_edits = vec![map::Edit {
        key: parts.owner_root.key(&parts.owner_literal)?,
        expected_value_sha256: Some(hash(&parts.expected_owner_value)),
        value: Some(parts.replacement_owner_value),
    }];
    let index_edits = vec![map::Edit {
        key: parts.index_root.key(&parts.owner_literal)?,
        expected_value_sha256: Some(hash(&parts.expected_index_value)),
        value: Some(parts.replacement_index_value),
    }];
    let mut context = backend.context()?;
    context.review_sha256 = Some(parts.input_sha256.clone());
    let request_sha256 = original.source_binding().request_sha256.clone();
    let operation = OperationData::IndexJobSelection {
        binding: parts.binding,
        request_sha256: request_sha256.clone(),
        input_sha256: parts.input_sha256.clone(),
        source_sha256: parts.source_sha256.clone(),
        selection: parts.selection.clone(),
        original_authority: parts.original_authority,
    };
    operation.validate()?;
    let mut cache = Memory {
        backend,
        original,
        context: context.clone(),
        generated: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let mut next = Vec::with_capacity(2);
    for (root, edits) in [
        (&parts.owner_root, &owner_edits),
        (&parts.index_root, &index_edits),
    ] {
        next.push(map::prepare_update(
            root,
            edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: MEMORY_BYTES as u64,
                new_files: MEMORY_PAGES as u32,
            },
            &mut cache,
        )?);
    }
    cache.readonly = true;
    for ((root, edits), next) in [
        (&parts.owner_root, &owner_edits),
        (&parts.index_root, &index_edits),
    ]
    .into_iter()
    .zip(&next)
    {
        map::verify_update(
            root,
            next,
            edits,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut cache,
        )?;
    }
    let generated = std::mem::take(&mut cache.generated);
    cache.backend.live(&mut || cache.original.check())?;
    if Selector::for_descriptor(&cache.backend.descriptor)? != selected {
        return Err(
            "actual C changed during independently replayed index job-selection role maps".into(),
        );
    }
    let mut roots = cache.backend.descriptor.roots.clone();
    let mut next = next.into_iter();
    roots.owners = next
        .next()
        .ok_or("index job selection lost its owner root")?;
    roots.index_generations = next
        .next()
        .ok_or("index job selection lost its index root")?;
    Ok(VerifiedTransition {
        base: selected,
        base_frame_sha256: cache.backend.descriptor_frame_sha256.clone(),
        source_sha256: parts.source_sha256,
        request_sha256,
        review_sha256: parts.input_sha256,
        roots,
        edits: BTreeMap::from([
            (map::Kind::OwnerStates, owner_edits),
            (map::Kind::IndexGenerations, index_edits),
        ]),
        pages: generated,
        records,
        operation,
        // Both roles are replaced; neither is an unchanged read-CAS.
        read_cas: Vec::new(),
        outcome: Completed::IndexJobSelection(parts.selection),
    })
}
