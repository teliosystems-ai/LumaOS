//! The only index constructor consumes the C verifier's move-only semantic
//! token. Its unchanged owner read-CAS and exact index replacement are replayed
//! here against actual current direct roots; no supplied next roots are used.
use super::*;
use crate::content_checkpoint::custody::v2_publication::index::effects::{self, PreparationView};
use crate::content_index::{phase, request};

pub(super) struct View<'a, A: Checkpoint> {
    pub(super) backend: &'a mut Backend<A>,
    pub(super) remaining: u64,
}
impl<A: Checkpoint> PreparationView for View<'_, A> {
    fn current(&mut self, original: &mut OriginalCOperation<'_>) -> Result<(Selector, Descriptor)> {
        original.check()?;
        self.backend.descriptor.phase.require_ready()?;
        self.backend.live(&mut || original.check())?;
        let data = (
            Selector::for_descriptor(&self.backend.descriptor)?,
            self.backend.descriptor.clone(),
        );
        original.check()?;
        Ok(data)
    }
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Option<Vec<u8>>> {
        original.check()?;
        let value = self
            .backend
            .lookup(root, literal, &mut COperation::Worker(original))?;
        original.check()?;
        Ok(value)
    }
    fn read_record(
        &mut self,
        reference: &RecordRef,
        maximum: usize,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Vec<u8>> {
        reference.validate()?;
        original.check()?;
        if maximum == 0
            || maximum > super::super::super::super::super::paged::FILE_BYTES
            || reference.bytes > maximum as u64
        {
            return Err("direct index C-record read exceeds its closed class before I/O".into());
        }
        self.remaining = self
            .remaining
            .checked_sub(reference.bytes)
            .ok_or("direct index C-record read budget exhausted before I/O")?;
        let bytes = self.backend.read_immutable(
            &reference.sha256,
            slots::Kind::Record,
            &mut COperation::Worker(original),
        )?;
        if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
            return Err("direct index C-record complete bytes changed".into());
        }
        original.check()?;
        Ok(bytes)
    }
}
pub(super) fn prepare<A: Checkpoint>(
    backend: &mut Backend<A>,
    input: &request::Input,
    plan: &phase::Plan,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedTransition> {
    original.check()?;
    let proof = effects::verify_index_preparation(
        &mut View {
            backend,
            remaining: READ_BUDGET,
        },
        input,
        plan,
        original,
    )?;
    finish(
        backend,
        input,
        proof,
        effects::PreparedKind::Phase,
        original,
    )
}
pub(super) fn start<A: Checkpoint>(
    backend: &mut Backend<A>,
    input: &request::Input,
    builder: &impl effects::CurrentBuilder,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedTransition> {
    original.check()?;
    let proof = effects::verify_index_start(
        &mut View {
            backend,
            remaining: READ_BUDGET,
        },
        input,
        builder,
        original,
    )?;
    finish(
        backend,
        input,
        proof,
        effects::PreparedKind::Start,
        original,
    )
}
fn finish<A: Checkpoint>(
    backend: &mut Backend<A>,
    input: &request::Input,
    proof: effects::VerifiedIndexPreparation,
    kind: effects::PreparedKind,
    original: &mut OriginalCOperation<'_>,
) -> Result<VerifiedTransition> {
    let parts = proof.into_parts();
    let selected = Selector::for_descriptor(&backend.descriptor)?;
    if parts.kind != kind
        || parts.base != selected
        || parts.owner_root != backend.descriptor.roots.owners
        || parts.index_root != backend.descriptor.roots.index_generations
        || parts.original_authority != *original.audit()
        || parts.binding != original.source_binding().binding
        || original.source_binding().purpose != SourcePurpose::IndexPrepare
        || parts.source_sha256 != hash(&COperation::Worker(original).source_bytes()?)
        || parts.input_sha256 != input.sha256()?
    {
        return Err("verified index token changed actual C/source/owner/finite effect before exact storage planning".into());
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
        || expected_index != parts.expected_index_value
    {
        return Err(
            "verified index preparation no longer matches actual selected owner/index read-CAS"
                .into(),
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
            return Err("verified index immutable records exceed the actual direct finite window before allocation".into());
        }
        bytes += value.len();
        if records.insert(reference.sha256, value).is_some() {
            return Err("verified index preparation repeats a complete record digest".into());
        }
    }
    if records
        .get(&parts.preparation.sha256)
        .map(|value| value.len() as u64)
        != Some(parts.preparation.bytes)
    {
        return Err("verified index preparation omits its actual canonical record bytes".into());
    }
    let edits = vec![map::Edit {
        key: parts.index_root.key(&parts.owner_literal)?,
        expected_value_sha256: parts.expected_index_value.as_ref().map(|value| hash(value)),
        value: Some(parts.replacement_index_value),
    }];
    let mut context = backend.context()?;
    context.review_sha256 = Some(parts.input_sha256.clone());
    let request_sha256 = original.source_binding().request_sha256.clone();
    let (operation, outcome) = match kind {
        effects::PreparedKind::Phase => (
            OperationData::IndexPreparation {
                binding: parts.binding,
                request_sha256: request_sha256.clone(),
                input_sha256: parts.input_sha256.clone(),
                source_sha256: parts.source_sha256.clone(),
                preparation: parts.preparation.clone(),
                original_authority: parts.original_authority,
            },
            Completed::IndexPreparation(parts.preparation),
        ),
        effects::PreparedKind::Start => (
            OperationData::IndexJobReservation {
                binding: parts.binding,
                request_sha256: request_sha256.clone(),
                input_sha256: parts.input_sha256.clone(),
                source_sha256: parts.source_sha256.clone(),
                reservation: parts.preparation.clone(),
                original_authority: parts.original_authority,
            },
            Completed::IndexJobReservation(parts.preparation),
        ),
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
    let next = map::prepare_update(
        &parts.index_root,
        &edits,
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
        &parts.index_root,
        &next,
        &edits,
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
    if Selector::for_descriptor(&cache.backend.descriptor)? != selected {
        return Err(
            "actual C changed during independently replayed index role-map preparation".into(),
        );
    }
    let mut roots = cache.backend.descriptor.roots.clone();
    roots.index_generations = next;
    Ok(VerifiedTransition {
        base: selected,
        base_frame_sha256: cache.backend.descriptor_frame_sha256.clone(),
        source_sha256: parts.source_sha256,
        request_sha256,
        review_sha256: parts.input_sha256,
        roots,
        edits: BTreeMap::from([(map::Kind::IndexGenerations, edits)]),
        pages: generated,
        records,
        operation,
        read_cas: vec![ReadCas {
            role: map::Kind::OwnerStates,
            literal: parts.owner_literal,
            value: parts.expected_owner_value,
        }],
        outcome,
    })
}
