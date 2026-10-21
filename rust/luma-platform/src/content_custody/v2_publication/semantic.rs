//! Exact selected-C point reconstruction and typed legacy-event semantics.
//! This layer does not allocate restore tails, dispatch NV or expose an event
//! endpoint. Its private result is not sufficient without the physical publisher.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "location", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum EventLocation {
    Legacy { ordinal: u64, event_sha256: String },
    Immutable { reference: RecordRef },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEvent {
    schema_version: u32,
    event: Event,
}

/// A selected C state projection, not a synthetic journal or owner authority.
/// The stored global C head remains the real head even though only the exact
/// operation's owner/recipient/restore point paths need to be reconstructed.
struct Projection {
    selected: Selector,
    state: Validated,
    owner: Option<OwnerLeaf>,
}

/// No public constructor/decoder: only exact current C projection, actual typed
/// validators, original ephemeral context and canonical record replay create it.
pub(super) struct VerifiedEventSemantics {
    pub(super) base: Selector,
    pub(super) event: Event,
    pub(super) binding: Option<OwnerBinding>,
    pub(super) state: Validated,
    pub(super) owner: Option<OwnerLeaf>,
    pub(super) source_sha256: String,
}

fn binding(event: &Event) -> Result<Option<OwnerBinding>> {
    Ok(match event {
        Event::Publication(value) => Some(value.validate()?.binding),
        Event::RestorePublication(value) => Some(value.entry.validate()?.binding),
        Event::RestoreStart(value) => Some(value.input.target.clone()),
        Event::Backup(value) => Some(value.input.binding.clone()),
        Event::Recipients(value) => Some(value.request.binding.clone()),
        Event::Quarantine(value) => Some(value.review.binding.clone()),
        Event::RestoreRetired(value) => Some(value.binding().clone()),
        Event::ReceiptSigner(_) => None,
    })
}
fn audit(event: &Event) -> &Audit {
    match event {
        Event::Publication(value) => &value.original_authority,
        Event::RestorePublication(value) => &value.entry.original_authority,
        Event::RestoreStart(value) => value.audit(),
        Event::Backup(value) => value.audit(),
        Event::Recipients(value) => value.audit(),
        Event::Quarantine(value) => &value.original_authority,
        Event::RestoreRetired(value) => value.audit(),
        Event::ReceiptSigner(value) => value.audit(),
    }
}
fn require_original(
    event: &Event,
    installation: &str,
    original: &mut COperation<'_, '_>,
) -> Result<()> {
    original.check()?;
    audit(event).validate()?;
    if audit(event) != original.audit() {
        return Err("typed paged C event differs from actual original finite operation".into());
    }
    let expected_binding = binding(event)?;
    match original {
        COperation::Worker(value) => {
            let source = value.source_binding();
            let purpose = match event {
                Event::Publication(_) => SourcePurpose::Publish,
                Event::RestorePublication(_) => SourcePurpose::RestorePublish,
                Event::RestoreStart(_) => SourcePurpose::RestoreStart,
                Event::Backup(_) => SourcePurpose::BackupReceipt,
                Event::Quarantine(_) => SourcePurpose::Quarantine,
                _ => return Err("Admin event cannot borrow an ordinary worker context".into()),
            };
            if source.purpose != purpose
                || expected_binding.as_ref() != Some(&source.binding)
                || source.binding.installation != installation
            {
                return Err(
                    "typed C event substitutes original worker purpose/owner/installation".into(),
                );
            }
            let (profile, device): (&str, &str) = match event {
                Event::Publication(value) => (&value.profile, &value.storage_device),
                Event::RestorePublication(value) => {
                    (&value.entry.profile, &value.entry.storage_device)
                }
                Event::RestoreStart(value) => (value.profile(), value.device()),
                Event::Quarantine(value) => (&value.profile, &value.storage_device),
                Event::Backup(value) => {
                    // The typed backup validator binds its device in the
                    // identical finite usage; independently recompute its
                    // complete input/profile here as well.
                    if crate::content_backup::profile(
                        &value.input,
                        &serde_json::to_vec(&value.input)?,
                    )? != source.profile
                    {
                        return Err("typed backup input differs from original worker source".into());
                    }
                    (&source.profile, &source.storage_device)
                }
                _ => return Err("unsupported worker source binding".into()),
            };
            if profile != source.profile || device != source.storage_device {
                return Err("typed C event substitutes exact source profile/device".into());
            }
        }
        COperation::Admin(value) => {
            let source = value.source_binding();
            let command = match event {
                Event::Recipients(_) => "content-backup-recipients-enroll",
                Event::ReceiptSigner(_) => "content-backup-signer-enroll",
                Event::RestoreRetired(_) => retire::RETIRE,
                _ => return Err("worker event cannot borrow a separate Admin context".into()),
            };
            super::super::admin_scope(command, &source.usage)?;
            if source.command != command
                || source.installation != installation
                || source.usage != audit(event).usage
            {
                return Err(
                    "typed C event substitutes actual Admin command/installation/scope".into(),
                );
            }
        }
    }
    original.check()
}

impl<A: Checkpoint> PagedStore<A> {
    fn load_event(
        &self,
        location: &EventLocation,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Event> {
        match location {
            EventLocation::Legacy {
                ordinal,
                event_sha256,
            } => {
                digest(event_sha256)?;
                if *ordinal == 0 || *ordinal > self.descriptor.legacy.events {
                    return Err("C leaf references an unselected legacy ordinal".into());
                }
                let (journal, _) = self.legacy(check)?;
                let event = journal
                    .events
                    .get(usize::try_from(*ordinal - 1)?)
                    .ok_or("C legacy ordinal missing")?
                    .clone();
                if bundle::hex(&event.digest()?) != *event_sha256 {
                    return Err("C leaf legacy event commitment differs".into());
                }
                Ok(event)
            }
            EventLocation::Immutable { reference } => {
                reference.validate()?;
                let bytes = self.pages.read_record(&reference.sha256, check)?;
                if bytes.len() as u64 != reference.bytes {
                    return Err("C event immutable reference length differs".into());
                }
                let value: StoredEvent = canonical(&bytes, super::super::paged::FILE_BYTES)?;
                if value.schema_version != 3 {
                    return Err("wrong C immutable typed-event schema".into());
                }
                value.event.digest()?;
                Ok(value.event)
            }
        }
    }
    fn point_event(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Option<Event>> {
        self.value(root, literal, check)?
            .map(|bytes| {
                let location: EventLocation = canonical(&bytes, map::MAX_VALUE_BYTES)?;
                self.load_event(&location, check)
            })
            .transpose()
    }
    fn projection(
        &mut self,
        binding: Option<&OwnerBinding>,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Projection> {
        self.live(check)?;
        let mut state = Validated {
            checkpoint: tpm::decode(&self.selected.nv_head)?,
            owners: BTreeMap::new(),
            records: BTreeMap::new(),
            signer: None,
            recipients: BTreeMap::new(),
            restores: BTreeMap::new(),
            retired: BTreeSet::new(),
        };
        let signers = self.descriptor.roots.signers.clone();
        if let Some(event) = self.point_event(&signers, b"origin-signer", check)? {
            match event {
                Event::ReceiptSigner(value) => {
                    value.validate(&self.descriptor.binding.installation)?;
                    state.signer = Some(value);
                }
                _ => return Err("signer C map references a different typed event".into()),
            }
        }
        let owner = if let Some(binding) = binding {
            let key = owner_key(binding)?;
            let leaf = self.raw_owner_leaf(binding, check)?;
            match &leaf {
                Some(OwnerLeaf::V1 {
                    state: cut,
                    records,
                    migration_prefix,
                }) => {
                    if migration_prefix.is_some() {
                        return Err(
                            "legacy C mutation cannot bypass a selected owner migration prefix"
                                .into(),
                        );
                    }
                    state.owners.insert(key.clone(), cut.clone());
                    state
                        .records
                        .insert(key.clone(), self.records(cut, records, check)?);
                }
                Some(OwnerLeaf::V2 { .. }) => {
                    return Err("legacy-event replay cannot reinterpret a V2 owner".into())
                }
                None => {}
            }
            let recipients = self.descriptor.roots.recipients.clone();
            if let Some(event) = self.point_event(&recipients, key.as_bytes(), check)? {
                match event {
                    Event::Recipients(value) => {
                        value.validate(&binding.installation)?;
                        if value.request.binding != *binding {
                            return Err("recipient C point changes owner".into());
                        }
                        state.recipients.insert(key.clone(), value);
                    }
                    _ => return Err("recipient C map references a different typed event".into()),
                }
            }
            let restores = self.descriptor.roots.restore_reservations.clone();
            if let Some(event) = self.point_event(&restores, key.as_bytes(), check)? {
                match event {
                    Event::RestoreStart(value) => {
                        value.validate(&binding.installation)?;
                        if value.input.target != *binding {
                            return Err("restore C point changes target".into());
                        }
                        state.restores.insert(key.clone(), value);
                    }
                    _ => return Err("restore C map references a different typed event".into()),
                }
            }
            let unavailable = self.descriptor.roots.unavailable.clone();
            if let Some(event) = self.point_event(&unavailable, key.as_bytes(), check)? {
                match event {
                    Event::RestoreRetired(value) => {
                        value.audit().validate()?;
                        if value.binding() != binding {
                            return Err("unavailable C point changes owner generation".into());
                        }
                        state.retired.insert(key);
                    }
                    _ => return Err("unavailable C map references a different typed event".into()),
                }
            }
            leaf
        } else {
            None
        };
        self.live(check)?;
        Ok(Projection {
            selected: self.selected.clone(),
            state,
            owner,
        })
    }

    pub(super) fn verify_typed_event(
        &mut self,
        event: Event,
        original: &mut COperation<'_, '_>,
    ) -> Result<VerifiedEventSemantics> {
        self.descriptor.phase.require_ready()?;
        require_original(&event, &self.descriptor.binding.installation, original)?;
        let binding = binding(&event)?;
        let mut projection = self.projection(binding.as_ref(), &mut || original.check())?;
        let state = &mut projection.state;
        let publication = match &event {
            Event::Recipients(value) => {
                value.validate(&self.descriptor.binding.installation)?;
                value
                    .request
                    .cryptographic_check(&mut || original.check())?;
                let key = owner_key(&value.request.binding)?;
                let previous = state.recipients.get(&key).map_or(0, |v| v.generation);
                if value.request.expected_generation != previous {
                    return Err(
                        "paged recipient event has discontinuous selected generation".into(),
                    );
                }
                state.recipients.insert(key, value.clone());
                None
            }
            Event::ReceiptSigner(value) => {
                value.validate(&self.descriptor.binding.installation)?;
                if state.signer.is_some() {
                    return Err("selected C signer cannot be silently replaced".into());
                }
                state.signer = Some(value.clone());
                None
            }
            Event::RestoreRetired(value) => {
                retire::validate_event(value, &self.descriptor.binding.installation, state)?;
                None
            }
            Event::RestoreStart(value) => {
                value.receipt().verify_origin(
                    &value.input.independently_selected_origin_spki_sha256,
                    &mut || original.check(),
                )?;
                restore::start_event(value, &self.descriptor.binding.installation, state)?;
                None
            }
            Event::Backup(value) => {
                backup::validate_event(value, &self.descriptor.binding.installation, state)?;
                let archive = self.descriptor.roots.archive_inventory.clone();
                if self
                    .value(&archive, value.job()?.as_bytes(), &mut || original.check())?
                    .is_some()
                {
                    return Err("paged C backup export job already selected".into());
                }
                None
            }
            Event::Quarantine(value) => {
                value.validate()?;
                let key = owner_key(&value.review.binding)?;
                restore::ordinary_publication(&value.review.binding, "quarantine", state)?;
                let current = state
                    .owners
                    .get(&key)
                    .cloned()
                    .unwrap_or(VerifiedState::empty(&value.review.binding)?);
                if current != value.review.base_state()? {
                    return Err("paged quarantine does not extend actual selected owner cut".into());
                }
                state.owners.insert(key, value.review.retired_state()?);
                None
            }
            Event::Publication(value) => {
                let held = value.validate()?;
                restore::ordinary_publication(&held.binding, &value.profile, state)?;
                Some(value)
            }
            Event::RestorePublication(value) => {
                restore::publication_event(value, state)?;
                Some(&value.entry)
            }
        };
        if let Some(publication) = publication {
            let held = publication.validate()?;
            let key = owner_key(&held.binding)?;
            let current = state
                .owners
                .get(&key)
                .cloned()
                .unwrap_or(VerifiedState::empty(&held.binding)?);
            if held.base() != current {
                return Err(
                    "typed paged publication does not extend actual selected V1 base".into(),
                );
            }
            let records = state.records.entry(key.clone()).or_default();
            records.push(publication.record.as_bytes().to_vec());
            if luma_content_store::canonical_record_history_head(&held.binding, records)?
                != held.outcome_head_sha256
            {
                return Err("typed paged publication canonical record history differs".into());
            }
            state.owners.insert(key, held.outcome());
        }
        self.live(&mut || original.check())?;
        if projection.selected != self.selected {
            return Err("typed semantic reconstruction lost original selected C cut".into());
        }
        Ok(VerifiedEventSemantics {
            base: projection.selected,
            event,
            binding,
            state: projection.state,
            owner: projection.owner,
            source_sha256: hash(&original.source_bytes()?),
        })
    }
}
