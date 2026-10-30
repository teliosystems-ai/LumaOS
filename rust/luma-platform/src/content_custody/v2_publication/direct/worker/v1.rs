//! Exact V1 owner publication semantics over a real selected direct C cut.
//! The retained original journal is immutable DATA under that current cut,
//! never an old-NV authority fallback. V2/migrating/retired/restore-incomplete
//! owners cannot enter this constructor.
use super::*;

/// The actual selected C cut that V1 semantics read. The warm cut is the held
/// original backend; a cold cut is the exact previous descriptor of a selected
/// V1 transition. Both replay the same closed DATA; neither grants authority.
pub(super) trait Cut {
    fn descriptor(&self) -> &Descriptor;
    fn check(&mut self) -> Result<()>;
    fn live(&mut self) -> Result<()>;
    fn lookup(&mut self, root: &map::Root, literal: &[u8]) -> Result<Option<Vec<u8>>>;
    fn read_record(&mut self, sha: &str) -> Result<Vec<u8>>;
    fn journal(&mut self) -> Result<Journal>;
}
pub(super) struct Warm<'a, 'b, 'c, A: Checkpoint> {
    pub(super) backend: &'a mut Backend<A>,
    pub(super) original: &'b mut OriginalCOperation<'c>,
}
impl<A: Checkpoint> Cut for Warm<'_, '_, '_, A> {
    fn descriptor(&self) -> &Descriptor {
        &self.backend.descriptor
    }
    fn check(&mut self) -> Result<()> {
        self.original.check()
    }
    fn live(&mut self) -> Result<()> {
        self.backend.live(&mut || self.original.check())
    }
    fn lookup(&mut self, root: &map::Root, literal: &[u8]) -> Result<Option<Vec<u8>>> {
        self.backend
            .lookup(root, literal, &mut COperation::Worker(&mut *self.original))
    }
    fn read_record(&mut self, sha: &str) -> Result<Vec<u8>> {
        self.backend.read_immutable(
            sha,
            slots::Kind::Record,
            &mut COperation::Worker(&mut *self.original),
        )
    }
    fn journal(&mut self) -> Result<Journal> {
        self.backend.legacy_data(&mut || self.original.check())
    }
}

/// Whether an original audit is the exact finite owner effect for `held`.
pub(super) fn attributed(
    held: &HeldPublication,
    profile: &str,
    storage_device: &str,
    audit: &Audit,
) -> Result<bool> {
    Ok(audit.subject == held.binding.owner
        && audit.subject_generation == held.binding.owner_generation
        && audit.operation_id.is_some()
        && audit.usage
            == crate::content_governed::custody_usage(
                profile,
                storage_device,
                &held.binding,
                &held.review_sha256,
            )?)
}
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
        || !attributed(held, &source.profile, &source.storage_device, audit)?
    {
        return Err(
            "direct V1 publication differs from the actual original owner/source/finite effect"
                .into(),
        );
    }
    backend.live(&mut || original.check())
}
pub(super) fn record(
    cut: &mut impl Cut,
    reference: &RecordRef,
    budget: &mut u64,
) -> Result<Vec<u8>> {
    reference.validate()?;
    *budget = budget
        .checked_sub(reference.bytes)
        .ok_or("direct V1 historical-record budget exhausted before I/O")?;
    let bytes = cut.read_record(&reference.sha256)?;
    if bytes.len() as u64 != reference.bytes {
        return Err("selected direct V1 record changes its complete byte length".into());
    }
    Ok(bytes)
}
fn event(
    cut: &mut impl Cut,
    root: &map::Root,
    literal: &[u8],
    journal: &Journal,
    budget: &mut u64,
) -> Result<Option<Event>> {
    let Some(bytes) = cut.lookup(root, literal)? else {
        return Ok(None);
    };
    let location: semantic::EventLocation = canonical(&bytes, map::MAX_VALUE_BYTES)?;
    let selected = match location {
        semantic::EventLocation::Legacy {
            ordinal,
            event_sha256,
        } => {
            if ordinal == 0 || ordinal > cut.descriptor().legacy.events {
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
                &record(cut, &reference, budget)?,
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

/// The closed V1 semantic result over one actual cut: either the exact retry
/// of an already selected outcome or the sole owner-map append it requires.
pub(super) enum Semantic {
    Selected(VerifiedState),
    Append {
        owner_root: map::Root,
        edits: Vec<map::Edit>,
        reference: RecordRef,
        bytes: Vec<u8>,
    },
}
/// Reconstructs V1 owner semantics from the actual selected cut alone. The
/// profile, device and audit are those of the original operation (warm) or
/// of the exact selected publication event (cold).
pub(super) fn replay(
    cut: &mut impl Cut,
    held: &HeldPublication,
    commitment: &[u8],
    raw_record: &[u8],
    profile: &str,
    storage_device: &str,
    audit: &Audit,
) -> Result<Semantic> {
    let key = owner_key(&held.binding)?;
    let owner_root = cut.descriptor().roots.owners.clone();
    let old_value = cut.lookup(&owner_root, key.as_bytes())?;
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
            .validate(&held.binding.installation, &cut.descriptor().legacy)?;
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
                legacy_journal_sha256: cut.descriptor().legacy.journal_sha256.clone(),
                legacy_owner_record_count: 0,
                latest_suffix: None,
                suffix_count: 0,
            },
        ),
    };
    let journal = cut.journal()?;
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
        cut.check()?;
        let reference = next.ok_or("direct V1 selected suffix ends before its protected count")?;
        let node: RecordNode = canonical(
            &record(cut, &reference, &mut budget)?,
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
        checkpoint: tpm::decode(&cut.descriptor().selected_nv_head)?,
        owners: BTreeMap::from([(key.clone(), current.clone())]),
        records: BTreeMap::from([(key.clone(), records.clone())]),
        signer: None,
        recipients: BTreeMap::new(),
        restores: BTreeMap::new(),
        retired: BTreeSet::new(),
    };
    let restores = cut.descriptor().roots.restore_reservations.clone();
    if let Some(selected) = event(cut, &restores, key.as_bytes(), &journal, &mut budget)? {
        let Event::RestoreStart(value) = selected else {
            return Err("direct restore-reservation point has a different typed event".into());
        };
        value.validate(&held.binding.installation)?;
        if value.input.target != held.binding {
            return Err("direct restore reservation changes the actual owner".into());
        }
        projection.restores.insert(key.clone(), value);
    }
    let unavailable = cut.descriptor().roots.unavailable.clone();
    if let Some(selected) = event(cut, &unavailable, key.as_bytes(), &journal, &mut budget)? {
        let Event::RestoreRetired(value) = selected else {
            return Err("direct unavailable point has a different typed event".into());
        };
        value.audit().validate()?;
        if value.binding() != &held.binding {
            return Err("direct unavailable point changes the actual owner".into());
        }
        projection.retired.insert(key.clone());
    }
    restore::ordinary_publication(&held.binding, profile, &projection)?;
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
            || prior.original_authority.usage != audit.usage
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
        cut.live()?;
        return Ok(Semantic::Selected(current));
    }
    if held.already_published || held.base() != current {
        return Err("direct V1 append does not extend the actual current owner".into());
    }
    let publication = Publication {
        schema_version: 1,
        purpose: "luma-content-custody-publication-v1".into(),
        commitment: std::str::from_utf8(commitment)?.into(),
        record: std::str::from_utf8(raw_record)?.into(),
        profile: profile.to_owned(),
        storage_device: storage_device.to_owned(),
        original_authority: audit.clone(),
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
    next_leaf.validate(&held.binding.installation, &cut.descriptor().legacy)?;
    let edits = vec![map::Edit {
        key: owner_root.key(key.as_bytes())?,
        expected_value_sha256: old_value.as_ref().map(|value| hash(value)),
        value: Some(serde_json::to_vec(&next_leaf)?),
    }];
    Ok(Semantic::Append {
        owner_root,
        edits,
        reference,
        bytes,
    })
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
    let profile = original.source_binding().profile.clone();
    let storage_device = original.source_binding().storage_device.clone();
    let audit = original.audit().clone();
    let (owner_root, edits, reference, bytes) = match replay(
        &mut Warm {
            backend: &mut *backend,
            original: &mut *original,
        },
        &held,
        commitment,
        raw_record,
        &profile,
        &storage_device,
        &audit,
    )? {
        Semantic::Selected(current) => return Ok(Outcome::Selected(current)),
        Semantic::Append {
            owner_root,
            edits,
            reference,
            bytes,
        } => (owner_root, edits, reference, bytes),
    };
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
        edits: BTreeMap::from([(map::Kind::OwnerStates, edits)]),
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
