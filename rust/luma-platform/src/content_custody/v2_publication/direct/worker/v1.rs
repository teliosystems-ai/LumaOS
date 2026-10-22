//! Exact V1 owner publication semantics over a real selected direct C cut.
//! The retained original journal is immutable DATA under that current cut,
//! never an old-NV authority fallback. V2/migrating/retired/restore-incomplete
//! owners cannot enter this constructor.
use super::*;

fn exact<A: Checkpoint>(
    backend: &mut Backend<A>,
    held: &HeldPublication,
    original: &mut OriginalCOperation<'_>,
) -> Result<()> {
    backend.descriptor.phase.require_ready()?;
    original.check()?;
    let source = original.source_binding();
    let audit = original.audit();
    audit.validate()?;
    if source.purpose != SourcePurpose::Publish
        || source.binding != held.binding
        || audit.subject != held.binding.owner
        || audit.subject_generation != held.binding.owner_generation
        || audit.operation_id.is_none()
        || audit.usage
            != crate::content_governed::custody_usage(
                &source.profile,
                &source.storage_device,
                &held.binding,
                &held.review_sha256,
            )?
    {
        return Err(
            "direct V1 publication differs from the actual original owner/source/finite effect"
                .into(),
        );
    }
    backend.live(&mut || original.check())
}
fn value<A: Checkpoint>(
    backend: &mut Backend<A>,
    root: &map::Root,
    literal: &[u8],
    original: &mut OriginalCOperation<'_>,
) -> Result<Option<Vec<u8>>> {
    backend.lookup(root, literal, &mut COperation::Worker(original))
}
fn record<A: Checkpoint>(
    backend: &mut Backend<A>,
    reference: &RecordRef,
    budget: &mut u64,
    original: &mut OriginalCOperation<'_>,
) -> Result<Vec<u8>> {
    reference.validate()?;
    *budget = budget
        .checked_sub(reference.bytes)
        .ok_or("direct V1 historical-record budget exhausted before I/O")?;
    let bytes = backend.read_immutable(
        &reference.sha256,
        slots::Kind::Record,
        &mut COperation::Worker(original),
    )?;
    if bytes.len() as u64 != reference.bytes {
        return Err("selected direct V1 record changes its complete byte length".into());
    }
    Ok(bytes)
}
fn event<A: Checkpoint>(
    backend: &mut Backend<A>,
    root: &map::Root,
    literal: &[u8],
    journal: &Journal,
    budget: &mut u64,
    original: &mut OriginalCOperation<'_>,
) -> Result<Option<Event>> {
    let Some(bytes) = value(backend, root, literal, original)? else {
        return Ok(None);
    };
    let location: semantic::EventLocation = canonical(&bytes, map::MAX_VALUE_BYTES)?;
    let selected = match location {
        semantic::EventLocation::Legacy {
            ordinal,
            event_sha256,
        } => {
            if ordinal == 0 || ordinal > backend.descriptor.legacy.events {
                return Err("direct V1 point references an unselected original event".into());
            }
            let event = journal
                .events
                .get(usize::try_from(ordinal - 1)?)
                .ok_or("direct V1 original point missing")?
                .clone();
            if bundle::hex(&event.digest()?) != event_sha256 {
                return Err("direct V1 original point event commitment changed".into());
            }
            event
        }
        semantic::EventLocation::Immutable { reference } => {
            #[derive(Serialize, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Stored {
                schema_version: u32,
                event: Event,
            }
            let stored: Stored = canonical(
                &record(backend, &reference, budget, original)?,
                super::super::super::super::super::paged::FILE_BYTES,
            )?;
            if stored.schema_version != 3 {
                return Err("direct V1 point event has a different closed schema".into());
            }
            stored.event.digest()?;
            stored.event
        }
    };
    Ok(Some(selected))
}

pub(super) fn prepare<A: Checkpoint>(
    backend: &mut Backend<A>,
    commitment: &[u8],
    raw_record: &[u8],
    original: &mut OriginalCOperation<'_>,
) -> Result<Outcome> {
    let held = HeldPublication::parse(commitment)?;
    exact(backend, &held, original)?;
    let selected = backend.context()?;
    let key = owner_key(&held.binding)?;
    let owner_root = backend.descriptor.roots.owners.clone();
    let old_value = value(backend, &owner_root, key.as_bytes(), original)?;
    let leaf = old_value
        .as_ref()
        .map(|bytes| canonical::<OwnerLeaf>(bytes, map::MAX_VALUE_BYTES))
        .transpose()?;
    let (current, closure) = match leaf {
        Some(OwnerLeaf::V1 {
            state,
            records,
            migration_prefix: None,
        }) => {
            OwnerLeaf::V1 {
                state: state.clone(),
                records: records.clone(),
                migration_prefix: None,
            }
            .validate(&held.binding.installation, &backend.descriptor.legacy)?;
            if state.binding != held.binding {
                return Err("direct V1 selected owner binding changed".into());
            }
            (state, records)
        }
        Some(OwnerLeaf::V1 {
            migration_prefix: Some(_),
            ..
        }) => return Err("direct V1 publication cannot bypass selected migration".into()),
        Some(OwnerLeaf::V2 { .. }) => {
            return Err("direct V1 publication cannot downgrade selected V2 owner".into())
        }
        None => (
            VerifiedState::empty(&held.binding)?,
            LegacyRecordClosure {
                legacy_journal_sha256: backend.descriptor.legacy.journal_sha256.clone(),
                legacy_owner_record_count: 0,
                latest_suffix: None,
                suffix_count: 0,
            },
        ),
    };
    let journal = backend.legacy_data(&mut || original.check())?;
    let baseline = journal.validate()?;
    let mut records = baseline.records.get(&key).cloned().unwrap_or_default();
    if records.len() as u64 != closure.legacy_owner_record_count {
        return Err("direct V1 selected retained baseline record count changed".into());
    }
    let mut history = Vec::new();
    for event in &journal.events {
        let publication = match event {
            Event::Publication(value) => Some(value),
            Event::RestorePublication(value) => Some(&value.entry),
            _ => None,
        };
        if let Some(publication) = publication {
            if publication.validate()?.binding == held.binding {
                history.push(publication.clone());
            }
        }
    }
    let mut budget = READ_BUDGET;
    let mut next = closure.latest_suffix.clone();
    let mut suffix = Vec::new();
    for expected in (1..=closure.suffix_count).rev() {
        original.check()?;
        let reference = next.ok_or("direct V1 selected suffix ends before its protected count")?;
        let node: RecordNode = canonical(
            &record(backend, &reference, &mut budget, original)?,
            super::super::super::super::super::paged::FILE_BYTES,
        )?;
        let publication = node.publication.validate()?;
        if node.schema_version != 3
            || node.binding != held.binding
            || node.legacy_journal_sha256 != closure.legacy_journal_sha256
            || node.sequence != expected
            || publication.binding != held.binding
            || publication.base_outcome_count
                != closure
                    .legacy_owner_record_count
                    .checked_add(expected - 1)
                    .ok_or("V1 suffix ordinal overflow")?
        {
            return Err(
                "direct V1 selected suffix changes owner, original baseline or exact order".into(),
            );
        }
        next = node.previous;
        suffix.push(node.publication);
    }
    if next.is_some() {
        return Err("direct V1 selected suffix has an unselected hidden predecessor".into());
    }
    for publication in suffix.into_iter().rev() {
        let validated = publication.validate()?;
        if luma_content_store::canonical_record_history_head(&held.binding, &records)?
            != validated.base_head_sha256
        {
            return Err(
                "direct V1 selected suffix does not extend its retained canonical predecessor"
                    .into(),
            );
        }
        records.push(publication.record.as_bytes().to_vec());
        if luma_content_store::canonical_record_history_head(&held.binding, &records)?
            != validated.outcome_head_sha256
        {
            return Err("direct V1 selected suffix canonical history extension changed".into());
        }
        history.push(publication);
    }
    if records.len() as u64 != current.outcome_count
        || luma_content_store::canonical_record_history_head(&held.binding, &records)?
            != current.head_sha256
        || history.len() > 256
        || history.len() != records.len()
    {
        return Err(
            "direct V1 current owner is not its complete bounded canonical record closure".into(),
        );
    }
    let mut projection = Validated {
        checkpoint: tpm::decode(&backend.descriptor.selected_nv_head)?,
        owners: BTreeMap::from([(key.clone(), current.clone())]),
        records: BTreeMap::from([(key.clone(), records.clone())]),
        signer: None,
        recipients: BTreeMap::new(),
        restores: BTreeMap::new(),
        retired: BTreeSet::new(),
    };
    let restores = backend.descriptor.roots.restore_reservations.clone();
    if let Some(selected) = event(
        backend,
        &restores,
        key.as_bytes(),
        &journal,
        &mut budget,
        original,
    )? {
        let Event::RestoreStart(value) = selected else {
            return Err("direct restore-reservation point has a different typed event".into());
        };
        value.validate(&held.binding.installation)?;
        if value.input.target != held.binding {
            return Err("direct restore reservation changes the actual owner".into());
        }
        projection.restores.insert(key.clone(), value);
    }
    let unavailable = backend.descriptor.roots.unavailable.clone();
    if let Some(selected) = event(
        backend,
        &unavailable,
        key.as_bytes(),
        &journal,
        &mut budget,
        original,
    )? {
        let Event::RestoreRetired(value) = selected else {
            return Err("direct unavailable point has a different typed event".into());
        };
        value.audit().validate()?;
        if value.binding() != &held.binding {
            return Err("direct unavailable point changes the actual owner".into());
        }
        projection.retired.insert(key.clone());
    }
    restore::ordinary_publication(
        &held.binding,
        &original.source_binding().profile,
        &projection,
    )?;
    if let Some(prior) = history.iter().find(|prior| {
        prior
            .validate()
            .is_ok_and(|entry| entry.request_id == held.request_id)
    }) {
        let previous = prior.validate()?;
        if current != held.outcome()
            || previous.review_sha256 != held.review_sha256
            || previous.decision != held.decision
            || previous.resulting != held.resulting
            || prior.record.as_bytes() != raw_record
            || prior.original_authority.usage != original.audit().usage
            || previous.members.len() != held.members.len()
            || previous
                .members
                .iter()
                .zip(&held.members)
                .any(|(a, b)| a.name != b.name || a.bytes != b.bytes || a.sha256 != b.sha256)
        {
            return Err(
                "direct V1 retry substitutes an already selected immutable original outcome".into(),
            );
        }
        backend.live(&mut || original.check())?;
        return Ok(Outcome::Selected(current));
    }
    if held.already_published || held.base() != current {
        return Err("direct V1 append does not extend the actual current owner".into());
    }
    let publication = Publication {
        schema_version: 1,
        purpose: "luma-content-custody-publication-v1".into(),
        commitment: std::str::from_utf8(commitment)?.into(),
        record: std::str::from_utf8(raw_record)?.into(),
        profile: original.source_binding().profile.clone(),
        storage_device: original.source_binding().storage_device.clone(),
        original_authority: original.audit().clone(),
    };
    publication.validate()?;
    records.push(raw_record.to_vec());
    if luma_content_store::canonical_record_history_head(&held.binding, &records)?
        != held.outcome_head_sha256
    {
        return Err("direct V1 independently reconstructed new canonical history differs".into());
    }
    let sequence = closure
        .suffix_count
        .checked_add(1)
        .ok_or("direct V1 suffix overflow")?;
    if sequence > SUFFIX_LIMIT || records.len() > 256 {
        return Err("direct V1 retained suffix/history bound is unchanged; explicit owner migration required".into());
    }
    let node = RecordNode {
        schema_version: 3,
        binding: held.binding.clone(),
        legacy_journal_sha256: closure.legacy_journal_sha256.clone(),
        sequence,
        previous: closure.latest_suffix.clone(),
        publication,
    };
    let bytes = serde_json::to_vec(&node)?;
    if bytes.is_empty() || bytes.len() > super::super::super::super::super::paged::FILE_BYTES {
        return Err("direct V1 immutable record exceeds a closed record slot".into());
    }
    let reference = RecordRef {
        sha256: hash(&bytes),
        bytes: bytes.len() as u64,
    };
    let next_leaf = OwnerLeaf::V1 {
        state: held.outcome(),
        migration_prefix: None,
        records: LegacyRecordClosure {
            latest_suffix: Some(reference.clone()),
            suffix_count: sequence,
            ..closure
        },
    };
    next_leaf.validate(&held.binding.installation, &backend.descriptor.legacy)?;
    let edits = [map::Edit {
        key: owner_root.key(key.as_bytes())?,
        expected_value_sha256: old_value.as_ref().map(|value| hash(value)),
        value: Some(serde_json::to_vec(&next_leaf)?),
    }];
    let mut context = backend.context()?;
    context.review_sha256 = Some(held.review_sha256.clone());
    let source_sha256 = hash(&COperation::Worker(original).source_bytes()?);
    let request_sha256 = original.source_binding().request_sha256.clone();
    let mut cache = Memory {
        backend,
        original,
        context: context.clone(),
        generated: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let root = map::prepare_update(
        &owner_root,
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
        &owner_root,
        &root,
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
    if cache.backend.context()? != selected {
        return Err("actual direct C changed after independent original semantic replay".into());
    }
    let mut roots = cache.backend.descriptor.roots.clone();
    roots.owners = root;
    Ok(Outcome::Prepared(VerifiedTransition {
        base: Selector::for_descriptor(&cache.backend.descriptor)?,
        base_frame_sha256: cache.backend.descriptor_frame_sha256.clone(),
        source_sha256: source_sha256.clone(),
        request_sha256: request_sha256.clone(),
        review_sha256: held.review_sha256.clone(),
        roots,
        edits: BTreeMap::from([(map::Kind::OwnerStates, edits.into_iter().collect())]),
        pages: generated,
        records: BTreeMap::from([(reference.sha256.clone(), bytes)]),
        operation: OperationData::V1Publication {
            binding: held.binding.clone(),
            request_sha256,
            source_sha256,
            event: reference,
            original_authority: cache.original.audit().clone(),
        },
        read_cas: Vec::new(),
        outcome: Completed::V1(held.outcome()),
    }))
}
