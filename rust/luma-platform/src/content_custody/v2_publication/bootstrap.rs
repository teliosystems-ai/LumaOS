//! Bounded, C-selected global format bootstrap. A copied prefix is progress
//! DATA only: it cannot service ordinary selection until final completion.
use super::*;
#[path = "bootstrap/initial.rs"]
mod initial;
use initial::Initial;
pub(crate) use initial::{
    initial_recovery_review, resume_retired_bootstrap, retire_initial_bootstrap,
    retired_bootstrap_review, RetiredInitialBootstrap,
};
const WINDOW_ENTRIES: usize = 16;
const MAX_ENTRIES: u64 = 2 * MAX_EVENTS as u64;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum State {
    Pending,
    Ready,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Phase {
    pub state: State,
    pub review_sha256: String,
    pub projection_sha256: String,
    pub expected_counts: [u64; 7],
    pub copied_entries: u64,
}
impl Phase {
    pub fn validate(&self, legacy: &LegacyCut, roots: &Roots) -> Result<()> {
        digest(&self.review_sha256)?;
        digest(&self.projection_sha256)?;
        let total = self.total()?;
        if total > MAX_ENTRIES
            || total
                > legacy
                    .events
                    .checked_mul(2)
                    .ok_or("C bootstrap projection bound overflow")?
            || self.copied_entries > total
            || (self.state == State::Ready && self.copied_entries != total)
        {
            return Err("paged C bootstrap cursor/count is invalid".into());
        }
        if self.state == State::Pending {
            let actual = roots.all();
            let mut copied = 0_u64;
            for (index, root) in actual.iter().enumerate() {
                if root.entry_count > self.expected_counts[index] {
                    return Err("partial C bootstrap copied an unexpected role count".into());
                }
                copied = copied
                    .checked_add(root.entry_count)
                    .ok_or("C bootstrap copied count overflow")?;
            }
            if copied != self.copied_entries {
                return Err(
                    "partial C bootstrap roots differ from selected progress cursor".into(),
                );
            }
        }
        Ok(())
    }
    pub fn total(&self) -> Result<u64> {
        self.expected_counts.iter().try_fold(0_u64, |total, n| {
            total
                .checked_add(*n)
                .ok_or_else(|| "C bootstrap total overflow".into())
        })
    }
    pub fn require_ready(&self) -> Result<()> {
        if self.state != State::Ready {
            return Err("global C bootstrap is pending; ordinary owner selection/mutation is unavailable, not empty".into());
        }
        Ok(())
    }
    pub fn require_successor(&self, next: &Self) -> Result<()> {
        if self.state != State::Pending
            || self.review_sha256 != next.review_sha256
            || self.projection_sha256 != next.projection_sha256
            || self.expected_counts != next.expected_counts
            || next.copied_entries < self.copied_entries
            || next
                .copied_entries
                .checked_sub(self.copied_entries)
                .map_or(true, |n| n > WINDOW_ENTRIES as u64)
            || (next.copied_entries == self.copied_entries && next.state == self.state)
        {
            return Err(
                "C bootstrap successor resets, skips or renews the selected progress".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
struct Row {
    role: map::Kind,
    key: String,
    value: Vec<u8>,
}
pub(super) struct Blueprint {
    binding: map::CustodyBinding,
    legacy: LegacyCut,
    rows: Vec<Row>,
    expected_counts: [u64; 7],
    projection_sha256: String,
}
fn role_index(kind: map::Kind) -> usize {
    match kind {
        map::Kind::OwnerStates => 0,
        map::Kind::Recipients => 1,
        map::Kind::Signers => 2,
        map::Kind::Unavailable => 3,
        map::Kind::RestoreReservations => 4,
        map::Kind::ArchiveInventory => 5,
        map::Kind::IndexGenerations => 6,
    }
}
impl Blueprint {
    pub fn verified_legacy(
        binding: &map::CustodyBinding,
        legacy: &LegacyCut,
        journal: &Journal,
    ) -> Result<Self> {
        binding.validate()?;
        legacy.validate()?;
        journal.require_identity(
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256)?,
        )?;
        let bytes = journal.bytes()?;
        let state = journal.validate()?;
        if hash(&bytes) != legacy.journal_sha256
            || bytes.len() as u64 != legacy.journal_bytes
            || journal.events.len() as u64 != legacy.events
            || bundle::hex(&state.checkpoint) != legacy.nv_head
        {
            return Err(
                "C bootstrap projection does not reconstruct exact sealed legacy selection".into(),
            );
        }
        let mut entries = BTreeMap::<(map::Kind, String), Vec<u8>>::new();
        let mut put = |role: map::Kind, literal: &[u8], value: Vec<u8>| -> Result<()> {
            if value.is_empty() || value.len() > map::MAX_VALUE_BYTES {
                return Err("legacy C projection leaf exceeds native bound".into());
            }
            let root = map::Root::empty_data(binding, role)?;
            entries.insert((role, root.key(literal)?), value);
            Ok(())
        };
        for (key, cut) in &state.owners {
            let count = state.records.get(key).map_or(0, Vec::len) as u64;
            if count != cut.outcome_count {
                return Err("legacy C owner projection lost canonical records".into());
            }
            let leaf = OwnerLeaf::V1 {
                state: cut.clone(),
                records: LegacyRecordClosure {
                    legacy_journal_sha256: legacy.journal_sha256.clone(),
                    legacy_owner_record_count: count,
                    latest_suffix: None,
                    suffix_count: 0,
                },
                migration_prefix: None,
            };
            leaf.validate(&binding.installation, legacy)?;
            put(
                map::Kind::OwnerStates,
                key.as_bytes(),
                serde_json::to_vec(&leaf)?,
            )?;
        }
        for (index, event) in journal.events.iter().enumerate() {
            let location = serde_json::to_vec(&semantic::EventLocation::Legacy {
                ordinal: index as u64 + 1,
                event_sha256: bundle::hex(&event.digest()?),
            })?;
            match event {
                Event::Recipients(value) => put(
                    map::Kind::Recipients,
                    owner_key(&value.request.binding)?.as_bytes(),
                    location,
                )?,
                Event::ReceiptSigner(_) => put(map::Kind::Signers, b"origin-signer", location)?,
                Event::RestoreStart(value) => put(
                    map::Kind::RestoreReservations,
                    owner_key(&value.input.target)?.as_bytes(),
                    location,
                )?,
                Event::RestoreRetired(value) => put(
                    map::Kind::Unavailable,
                    owner_key(value.binding())?.as_bytes(),
                    location,
                )?,
                Event::Backup(value) => put(
                    map::Kind::ArchiveInventory,
                    value.job()?.as_bytes(),
                    location,
                )?,
                Event::Publication(_) | Event::RestorePublication(_) | Event::Quarantine(_) => {}
            }
        }
        let rows = entries
            .into_iter()
            .map(|((role, key), value)| Row { role, key, value })
            .collect::<Vec<_>>();
        let mut expected_counts = [0_u64; 7];
        for row in &rows {
            let index = role_index(row.role);
            expected_counts[index] = expected_counts[index]
                .checked_add(1)
                .ok_or("C bootstrap role overflow")?;
        }
        if rows.len() as u64 > MAX_ENTRIES {
            return Err("C bootstrap source projection exceeds unchanged legacy bounds".into());
        }
        let projection_sha256 = hash(&serde_json::to_vec(&(
            "luma-c-bootstrap-complete-projection-v3",
            binding,
            legacy,
            &rows,
        ))?);
        Ok(Self {
            binding: binding.clone(),
            legacy: legacy.clone(),
            rows,
            expected_counts,
            projection_sha256,
        })
    }
    fn review_data(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "luma-c-bootstrap-reviewed-legacy-v3",
            &self.binding,
            &self.legacy,
            &self.projection_sha256,
            self.expected_counts,
            "ordinary-owner-access-blocked-until-complete",
        ))?)
    }
    pub fn initial_phase(&self) -> Result<Phase> {
        Ok(Phase {
            state: State::Pending,
            review_sha256: hash(&self.review_data()?),
            projection_sha256: self.projection_sha256.clone(),
            expected_counts: self.expected_counts,
            copied_entries: 0,
        })
    }
    fn require_phase(&self, phase: &Phase) -> Result<()> {
        if phase.review_sha256 != hash(&self.review_data()?)
            || phase.projection_sha256 != self.projection_sha256
            || phase.expected_counts != self.expected_counts
            || phase.copied_entries > self.rows.len() as u64
        {
            return Err(
                "selected C bootstrap progress differs from original complete legacy projection"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn next_window_intent(&self, phase: &Phase, base: &Selector) -> Result<Vec<u8>> {
        self.require_phase(phase)?;
        base.validate()?;
        if phase.state != State::Pending {
            return Err("completed global C bootstrap cannot restart".into());
        }
        if base.schema_version == 1 {
            let expected = BaseSnapshot::Legacy {
                binding: self.binding.clone(),
                cut: self.legacy.clone(),
            }
            .selector()?;
            if base != &expected || phase.copied_entries != 0 {
                return Err("bootstrap-start intent must use exact genuine legacy base and zero copied rows".into());
            }
            return Ok(serde_json::to_vec(&(
                "luma-c-bootstrap-zero-row-start-intent-v3",
                &self.binding,
                &self.legacy,
                &phase.review_sha256,
                &phase.projection_sha256,
                base,
                phase,
                &Roots::empty(&self.binding)?,
            ))?);
        }
        let from = usize::try_from(phase.copied_entries)?;
        let to = (from + WINDOW_ENTRIES).min(self.rows.len());
        Ok(serde_json::to_vec(&(
            "luma-c-bootstrap-window-intent-v3",
            &self.binding,
            &self.legacy,
            &phase.review_sha256,
            &phase.projection_sha256,
            base,
            from,
            to,
            hash(&serde_json::to_vec(&self.rows[from..to])?),
        ))?)
    }
}

fn require_admin(
    authority: &mut OriginalCAdminOperation<'_>,
    binding: &map::CustodyBinding,
    phase: &Phase,
    intent: &str,
) -> Result<()> {
    use crate::finite_grants::{Action, Kind};
    authority.check()?;
    digest(intent)?;
    let source = authority.source_binding();
    let audit = authority.audit();
    if source.command != "content-custody-paged-bootstrap"
        || source.installation != binding.installation
        || source.job != phase.review_sha256
        || source.usage != audit.usage
        || audit.operation_id.is_none()
        || audit.usage.action != Action::ProvisionResource
        || audit.usage.selector.kind != Kind::Resource
        || audit.usage.selector.id != "content-custody-paged-bootstrap-v3"
        || audit.usage.selector.generation != 1
        || audit.usage.selector.digest != intent
        || audit.usage.input_bytes != 0
        || audit.usage.output_bytes != 8192
        || audit.usage.units != 1
    {
        return Err("global C bootstrap lacks fresh exact original Admin window authority".into());
    }
    authority.check()
}

fn legacy_snapshot<A: Checkpoint>(
    store: &mut Store<A>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(map::CustodyBinding, LegacyCut, Blueprint)> {
    store.live(check)?;
    let binding = map::CustodyBinding {
        installation: store.journal.installation.clone(),
        sealed_genesis_sha256: store.journal.genesis_event.clone(),
    };
    let proof = store
        .genesis_proof
        .as_ref()
        .ok_or("legacy bootstrap requires independently sealed installed C genesis proof")?;
    genesis::validate(
        proof,
        &binding.installation,
        tpm::decode(&binding.sealed_genesis_sha256)?,
    )?;
    let legacy = LegacyCut {
        journal_sha256: hash(&store.bytes),
        journal_bytes: store.bytes.len() as u64,
        events: store.journal.events.len() as u64,
        nv_head: bundle::hex(&store.state.checkpoint),
    };
    let blueprint = Blueprint::verified_legacy(&binding, &legacy, &store.journal)?;
    store.live(check)?;
    Ok((binding, legacy, blueprint))
}

fn review_value(
    blueprint: &Blueprint,
    phase: &Phase,
    base: &Selector,
) -> Result<serde_json::Value> {
    let intent = blueprint.next_window_intent(phase, base)?;
    let value = serde_json::json!({"schema_version":3,"installation":blueprint.binding.installation,
        "sealed_genesis_sha256":blueprint.binding.sealed_genesis_sha256,"legacy_cut":blueprint.legacy,
        "phase":phase,"selected_base":base,"window_intent_sha256":hash(&intent),
        "maximum_entries_per_window":WINDOW_ENTRIES,"ordinary_owner_access_available":false,
        "maintenance_message":"Global content custody bootstrap blocks ordinary owner access until all seven role projections are selected complete.",
        "authority_returned":false,"production_qualified":false});
    if serde_json::to_vec(&value)?.len() > 8192 {
        return Err("bootstrap review exceeds finite Admin output".into());
    }
    Ok(value)
}

pub(crate) fn legacy_bootstrap_review(
    store: &mut Store<super::super::super::ContentAnchor>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    let (binding, legacy, blueprint) = legacy_snapshot(store, check)?;
    let base = BaseSnapshot::Legacy {
        binding,
        cut: legacy,
    }
    .selector()?;
    review_value(&blueprint, &blueprint.initial_phase()?, &base)
}

/// Moves the actual already-open legacy C authority into a maintenance-only
/// selected format. The first event copies no rows; every later bounded window
/// has its own original Admin proof and exact selected progress commitment.
pub(crate) fn begin_bootstrap(
    mut store: Store<super::super::super::ContentAnchor>,
    expected_intent: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<PagedStore<super::super::super::ContentAnchor>> {
    let (binding, legacy, blueprint) = legacy_snapshot(&mut store, &mut || authority.check())?;
    if capacity::remaining(&store.state)?.outstanding_restore_batches != 0 {
        return Err("global bootstrap cannot release an existing restore publication/terminal capacity obligation; the current paged admission profile accepts only cuts without outstanding restore batches".into());
    }
    let phase = blueprint.initial_phase()?;
    let selected = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: legacy.clone(),
    }
    .selector()?;
    let intent = hash(&blueprint.next_window_intent(&phase, &selected)?);
    if intent != expected_intent {
        return Err("legacy C bootstrap review changed before namespace creation".into());
    }
    require_admin(authority, &binding, &phase, &intent)?;
    store.live(&mut || authority.check())?;
    store.poisoned = true;
    let pages = PageStore::create(&store.files.root, binding.clone(), &mut || {
        authority.check()
    })?;
    let initial = Initial {
        anchor: store.anchor,
        files: store.files,
        pages,
        binding,
        legacy,
        bytes: store.bytes,
        genesis_proof: store
            .genesis_proof
            .ok_or("independently held legacy genesis proof lost")?,
        retired: None,
    };
    dispatch_initial(initial, expected_intent, authority)
}

fn dispatch_initial(
    mut store: Initial,
    expected_intent: &str,
    authority: &mut OriginalCAdminOperation<'_>,
) -> Result<PagedStore<super::super::super::ContentAnchor>> {
    store.check(&mut || authority.check())?;
    store.require_new_operation(authority)?;
    let binding = store.binding.clone();
    let legacy = store.legacy.clone();
    let journal: Journal = canonical(&store.bytes, MAX_JOURNAL)?;
    let blueprint = Blueprint::verified_legacy(&binding, &legacy, &journal)?;
    let phase = blueprint.initial_phase()?;
    let base = BaseSnapshot::Legacy {
        binding: binding.clone(),
        cut: legacy.clone(),
    };
    let selected = base.selector()?;
    let intent = store.intent(&blueprint, &phase, &selected)?;
    if intent != expected_intent {
        return Err("legacy C bootstrap review changed before dispatch".into());
    }
    require_admin(authority, &binding, &phase, &intent)?;
    let operation = OperationData::BootstrapProgress {
        previous_retirement: store.previous_retirement(),
        review_sha256: phase.review_sha256.clone(),
        window_intent_sha256: intent,
        request_sha256: authority.source_binding().request_sha256.clone(),
        source_sha256: hash(&COperation::Admin(authority).source_bytes()?),
        original_authority: authority.audit().clone(),
    };
    let descriptor = Descriptor {
        schema_version: 3,
        domain: DOMAIN.into(),
        binding: binding.clone(),
        sequence: 1,
        global_ordinal: legacy
            .events
            .checked_add(2)
            .ok_or("initial C ordinal overflow")?,
        previous_descriptor_sha256: None,
        previous_nv_head: legacy.nv_head.clone(),
        event_sha256: String::new(),
        selected_nv_head: String::new(),
        legacy: legacy.clone(),
        roots: Roots::empty(&binding)?,
        phase: phase.clone(),
        operation,
    }
    .seal()?;
    store.check(&mut || authority.check())?;
    let Initial {
        mut anchor,
        files,
        pages,
        bytes: legacy_bytes,
        genesis_proof,
        ..
    } = store;
    let next = Selector::for_descriptor(&descriptor)?;
    let source_bytes = COperation::Admin(authority).source_bytes()?;
    let attempt = hash(&serde_json::to_vec(&(
        "luma-paged-c-bootstrap-attempt-v3",
        &selected,
        &next,
        authority.audit(),
        source_bytes,
    ))?);
    let pending = Pending {
        schema_version: 3,
        attempt: attempt.clone(),
        base: selected.clone(),
        next: next.clone(),
        event_sha256: descriptor.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&descriptor.operation)?),
    };
    pending.validate_base(&base, &descriptor)?;
    pages.admit_writes(16 * 1024 * 1024, 16, 8, &mut || authority.check())?;
    pages.create_attempt(&attempt, &mut || authority.check())?;
    let prefix = format!("attempts/{attempt}");
    let dispatch = serde_json::to_vec(&(
        "luma-paged-c-single-dispatch-intent-v3",
        hash(&pending.bytes()?),
    ))?;
    for (name, bytes) in [
        ("base.json", base.bytes()?),
        ("next.json", descriptor.bytes()?),
        ("prepared.json", pending.bytes()?),
        ("selector.json", next.bytes()?),
        ("dispatch.json", dispatch.clone()),
    ] {
        pages.create_member(&format!("{prefix}/{name}"), &bytes, &mut || {
            authority.check()
        })?;
    }
    if pages.write_page(&descriptor.bytes()?, &mut || authority.check())? != next.descriptor_sha256
    {
        return Err("first staged C descriptor hash differs".into());
    }
    if pages.absent("selected.json")? {
        pages.create_member("selected.json", &selected.bytes()?, &mut || {
            authority.check()
        })?;
    } else if pages.read("selected.json", 4096, &mut || authority.check())? != selected.bytes()? {
        return Err("resumed initial namespace has a different exact legacy selector".into());
    }
    pages.create_member("pending.json", &pending.bytes()?, &mut || authority.check())?;
    require_admin(authority, &binding, &phase, expected_intent)?;
    if anchor.read()? != tpm::decode(&legacy.nv_head)?
        || files.read(JOURNAL, &mut || authority.check())? != legacy_bytes
        || files.read("genesis.json", &mut || authority.check())? != genesis_proof
        || pages.read("selected.json", 4096, &mut || authority.check())? != selected.bytes()?
        || pages.read("pending.json", CONTROL_BYTES, &mut || authority.check())?
            != pending.bytes()?
        || pages.read(&format!("{prefix}/base.json"), CONTROL_BYTES, &mut || {
            authority.check()
        })? != base.bytes()?
        || pages.read(&format!("{prefix}/next.json"), PAGE_BYTES, &mut || {
            authority.check()
        })? != descriptor.bytes()?
        || pages.read(
            &format!("{prefix}/prepared.json"),
            CONTROL_BYTES,
            &mut || authority.check(),
        )? != pending.bytes()?
        || pages.read(&format!("{prefix}/dispatch.json"), 4096, &mut || {
            authority.check()
        })? != dispatch
        || pages.read(&format!("{prefix}/selector.json"), 4096, &mut || {
            authority.check()
        })? != next.bytes()?
    {
        return Err(
            "original legacy C or preallocated first cut changed before sole dispatch".into(),
        );
    }
    require_admin(authority, &binding, &phase, expected_intent)?;
    if anchor.advance(tpm::decode(&legacy.nv_head)?, descriptor.event_digest()?)?
        != tpm::decode(&next.nv_head)?
    {
        return Err("initial C dispatch returned different selected NV".into());
    }
    authority.check()?;
    pages.rename(
        &format!("{prefix}/selector.json"),
        "selected.json",
        true,
        &mut || authority.check(),
    )?;
    if pages.read("selected.json", 4096, &mut || authority.check())? != next.bytes()?
        || anchor.read()? != tpm::decode(&next.nv_head)?
    {
        return Err("first C selected/NV readback differs".into());
    }
    pages.rename(
        "pending.json",
        &format!("{prefix}/completed.json"),
        false,
        &mut || authority.check(),
    )?;
    if pages.read(
        &format!("{prefix}/completed.json"),
        CONTROL_BYTES,
        &mut || authority.check(),
    )? != pending.bytes()?
    {
        return Err("first C terminal readback differs".into());
    }
    PagedStore::open(anchor, files, binding, &mut || authority.check())
}

impl<A: Checkpoint> PagedStore<A> {
    fn bootstrap_blueprint(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<Blueprint> {
        self.live(check)?;
        let (journal, _) = self.legacy(check)?;
        let blueprint = Blueprint::verified_legacy(
            &self.descriptor.binding,
            &self.descriptor.legacy,
            &journal,
        )?;
        blueprint.require_phase(&self.descriptor.phase)?;
        self.live(check)?;
        Ok(blueprint)
    }
    pub(crate) fn bootstrap_review(
        &mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        let blueprint = self.bootstrap_blueprint(check)?;
        review_value(&blueprint, &self.descriptor.phase, &self.selected)
    }
    pub(crate) fn bootstrap_window(
        &mut self,
        expected_intent: &str,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<serde_json::Value> {
        let blueprint = self.bootstrap_blueprint(&mut || authority.check())?;
        let phase = self.descriptor.phase.clone();
        let intent = hash(&blueprint.next_window_intent(&phase, &self.selected)?);
        if intent != expected_intent {
            return Err("selected C bootstrap window changed after review".into());
        }
        require_admin(authority, &self.descriptor.binding, &phase, &intent)?;
        let from = usize::try_from(phase.copied_entries)?;
        let to = (from + WINDOW_ENTRIES).min(blueprint.rows.len());
        let context = self.context(Some(intent.clone()));
        let mut roots = self.descriptor.roots.clone();
        for role in [
            map::Kind::OwnerStates,
            map::Kind::Recipients,
            map::Kind::Signers,
            map::Kind::Unavailable,
            map::Kind::RestoreReservations,
            map::Kind::ArchiveInventory,
            map::Kind::IndexGenerations,
        ] {
            let edits = blueprint.rows[from..to]
                .iter()
                .filter(|row| row.role == role)
                .map(|row| map::Edit {
                    key: row.key.clone(),
                    expected_value_sha256: None,
                    value: Some(row.value.clone()),
                })
                .collect::<Vec<_>>();
            if edits.is_empty() {
                continue;
            }
            let before = roots.role(role).clone();
            let next = map::prepare_update(
                &before,
                &edits,
                &context,
                map::Budget {
                    read_bytes: READ_BUDGET,
                    write_bytes: 16 * 1024 * 1024,
                    new_files: 1024,
                },
                &mut AdminWriteIo {
                    store: self,
                    authority,
                },
            )?;
            map::verify_update(
                &before,
                &next,
                &edits,
                &context,
                map::Budget {
                    read_bytes: READ_BUDGET,
                    write_bytes: 0,
                    new_files: 0,
                },
                &mut ReadIo {
                    store: self,
                    check: &mut || authority.check(),
                },
            )?;
            roots.set_role(role, next)?;
        }
        let next_phase = Phase {
            copied_entries: to as u64,
            state: if to == blueprint.rows.len() {
                State::Ready
            } else {
                State::Pending
            },
            ..phase.clone()
        };
        phase.require_successor(&next_phase)?;
        next_phase.validate(&self.descriptor.legacy, &roots)?;
        let next = Descriptor {
            schema_version: 3,
            domain: DOMAIN.into(),
            binding: self.descriptor.binding.clone(),
            sequence: self
                .descriptor
                .sequence
                .checked_add(1)
                .ok_or("bootstrap descriptor sequence overflow")?,
            global_ordinal: self
                .descriptor
                .global_ordinal
                .checked_add(1)
                .ok_or("bootstrap global ordinal overflow")?,
            previous_descriptor_sha256: Some(self.selected.descriptor_sha256.clone()),
            previous_nv_head: self.selected.nv_head.clone(),
            event_sha256: String::new(),
            selected_nv_head: String::new(),
            legacy: self.descriptor.legacy.clone(),
            roots,
            phase: next_phase,
            operation: OperationData::BootstrapProgress {
                previous_retirement: None,
                review_sha256: phase.review_sha256.clone(),
                window_intent_sha256: intent.clone(),
                request_sha256: authority.source_binding().request_sha256.clone(),
                source_sha256: hash(&COperation::Admin(authority).source_bytes()?),
                original_authority: authority.audit().clone(),
            },
        }
        .seal()?;
        require_admin(authority, &self.descriptor.binding, &phase, &intent)?;
        self.commit_verified(
            VerifiedSemanticDelta {
                base: self.selected.clone(),
                next,
            },
            &mut COperation::Admin(authority),
        )?;
        Ok(
            serde_json::json!({"schema_version":3,"selected_nv_head":self.selected.nv_head,"descriptor_sha256":self.selected.descriptor_sha256,
            "phase":self.descriptor.phase,"ordinary_owner_access_available":self.descriptor.phase.state==State::Ready,
            "authority_returned":false,"production_qualified":false}),
        )
    }
}

impl Roots {
    pub(super) fn all(&self) -> [&map::Root; 7] {
        [
            &self.owners,
            &self.recipients,
            &self.signers,
            &self.unavailable,
            &self.restore_reservations,
            &self.archive_inventory,
            &self.index_generations,
        ]
    }
    fn role(&self, role: map::Kind) -> &map::Root {
        self.all()[role_index(role)]
    }
    fn set_role(&mut self, role: map::Kind, root: map::Root) -> Result<()> {
        if root.kind != role {
            return Err("C bootstrap role setter differs".into());
        }
        *match role {
            map::Kind::OwnerStates => &mut self.owners,
            map::Kind::Recipients => &mut self.recipients,
            map::Kind::Signers => &mut self.signers,
            map::Kind::Unavailable => &mut self.unavailable,
            map::Kind::RestoreReservations => &mut self.restore_reservations,
            map::Kind::ArchiveInventory => &mut self.archive_inventory,
            map::Kind::IndexGenerations => &mut self.index_generations,
        } = root;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_legacy_blueprint_still_blocks_ordinary_access_and_has_nonzero_complete_commitment() {
        let binding = map::CustodyBinding {
            installation: "11".repeat(32),
            sealed_genesis_sha256: "22".repeat(32),
        };
        let journal = Journal::empty(
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256).unwrap(),
        )
        .unwrap();
        let legacy = LegacyCut {
            journal_sha256: hash(&journal.bytes().unwrap()),
            journal_bytes: journal.bytes().unwrap().len() as u64,
            events: 0,
            nv_head: bundle::hex(&journal.validate().unwrap().checkpoint),
        };
        let blueprint = Blueprint::verified_legacy(&binding, &legacy, &journal).unwrap();
        let phase = blueprint.initial_phase().unwrap();
        phase
            .validate(&legacy, &Roots::empty(&binding).unwrap())
            .unwrap();
        assert!(phase.require_ready().is_err());
        assert_eq!(phase.total().unwrap(), 0);
        let mut forged = phase.clone();
        forged.copied_entries = 1;
        assert!(forged
            .validate(&legacy, &Roots::empty(&binding).unwrap())
            .is_err());
        let mut forged = legacy.clone();
        forged.nv_head = "33".repeat(32);
        assert!(Blueprint::verified_legacy(&binding, &forged, &journal).is_err());
        let base = BaseSnapshot::Legacy {
            binding: binding.clone(),
            cut: legacy.clone(),
        }
        .selector()
        .unwrap();
        let intent = blueprint.next_window_intent(&phase, &base).unwrap();
        assert!(String::from_utf8(intent.clone())
            .unwrap()
            .contains("zero-row-start-intent-v3"));
        let selected = Selector {
            schema_version: 3,
            ..base.clone()
        };
        assert_ne!(
            intent,
            blueprint.next_window_intent(&phase, &selected).unwrap()
        );
        let mut substituted = base.clone();
        substituted.descriptor_sha256 = "44".repeat(32);
        assert!(blueprint.next_window_intent(&phase, &substituted).is_err());
    }
    #[test]
    fn bootstrap_prefix_cannot_skip_reset_or_replace_source_review() {
        let phase = Phase {
            state: State::Pending,
            review_sha256: "11".repeat(32),
            projection_sha256: "22".repeat(32),
            expected_counts: [100, 0, 0, 0, 0, 0, 0],
            copied_entries: 16,
        };
        let mut next = phase.clone();
        next.copied_entries = 32;
        phase.require_successor(&next).unwrap();
        next.copied_entries = 33;
        assert!(phase.require_successor(&next).is_err());
        next.copied_entries = 15;
        assert!(phase.require_successor(&next).is_err());
        next.copied_entries = 32;
        next.review_sha256 = "33".repeat(32);
        assert!(phase.require_successor(&next).is_err());
        assert!(phase.require_successor(&phase).is_err());
        let mut complete = phase.clone();
        complete.copied_entries = 100;
        let mut ready = complete.clone();
        ready.state = State::Ready;
        complete.require_successor(&ready).unwrap();
        assert!(ready.require_successor(&complete).is_err());
    }
}
