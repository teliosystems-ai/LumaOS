//! Original-PAM hardware-only transitions of the existing protected journal.
//! Serialized hardware records are obligations, never session capabilities.
use super::*;
use crate::hardware_policy::{Authorization, Event, Phase, State, Transition};
use std::collections::BTreeMap;

pub(crate) struct HardwareSession<'image> {
    image: &'image crate::hardware_policy::image::Image,
    session: PrincipalSession,
    client: Option<crate::utc_provider::Client>,
    operation: Option<crate::policy_decisions::Operation>,
    decision_ids: Vec<String>,
    uses: Vec<(String, crate::finite_grants::Use)>,
    attempted: BTreeSet<String>,
    fenced: bool,
}

/// Inert current projection. It cannot authenticate a later operation.
#[derive(Serialize)]
pub(crate) struct HardwareProjection {
    pub subject: String,
    pub subject_generation: u64,
    pub state: State,
    pub boot: String,
    pub lower_ms: i64,
    pub upper_ms: i64,
}

fn scope(uses: &[(String, crate::finite_grants::Use)]) -> Result<()> {
    use crate::finite_grants::{Action, Kind};
    if !matches!(
        uses,
        [(
            _,
            crate::finite_grants::Use {
                action: Action::InspectHardware | Action::RestoreHardware,
                ..
            }
        )] | [
            (
                _,
                crate::finite_grants::Use {
                    action: Action::ApplyHardware,
                    ..
                }
            ),
            (
                _,
                crate::finite_grants::Use {
                    action: Action::RestoreHardware,
                    ..
                }
            )
        ]
    ) {
        return Err("hardware session requires one Inspect/reconciliation scope or independent exact Apply/Restore scopes".into());
    }
    let mut ids = BTreeSet::new();
    for (id, usage) in uses {
        usage.validate()?;
        if !admin_roles::identifier(id)
            || !ids.insert(id)
            || usage.selector.kind != Kind::Hardware
            || usage.input_bytes != 65_536
            || usage.output_bytes != 65_536
            || usage.units != 1
        {
            return Err("hardware session exceeds its closed independent finite scope".into());
        }
    }
    Ok(())
}

fn exact_successor(before: &PrincipalBinding, after: &PrincipalBinding, head: &str) -> Result<()> {
    if before.checkpoint_head == head
        || after.checkpoint_head != head
        || before.password_epoch != after.password_epoch
        || before.credential_sha256 != after.credential_sha256
        || before.identity_path != after.identity_path
        || before.purpose != after.purpose
        || before.deployment != after.deployment
        || before.enrollment_sha256 != after.enrollment_sha256
        || before.reset_count != after.reset_count
        || before.restart_count != after.restart_count
        || before.identity != after.identity
    {
        return Err(
            "hardware self-transition changed more than its one committed journal head".into(),
        );
    }
    Ok(())
}

fn request_id(event: &Event, head: &str) -> Result<String> {
    let digest =
        crate::hardware_policy::hash(&("luma-native-hardware-event-request-v1", event, head))?;
    // Preserve all 256 hash bits while satisfying the catalog's leading-letter
    // identifier rule; the first nibble uses the bijective alphabet a..p.
    let nibble = digest.as_bytes()[0];
    let nibble = if nibble <= b'9' {
        nibble - b'0'
    } else {
        nibble - b'a' + 10
    };
    Ok(format!("{}{}", char::from(b'a' + nibble), &digest[1..]))
}

pub(super) fn check_event(
    event: &CatalogEvent,
    catalog: &Catalog,
    history_floor: i64,
) -> Result<()> {
    if let Command::HardwarePolicyEvent {
        event: hardware,
        authorization,
    } = &event.command
    {
        hardware.validate()?;
        authorization.validate()?;
        let boot = match hardware {
            Event::Prepare { intent } => &intent.target.boot,
            Event::Reconciled {
                observation: Some(value),
                ..
            } => &value.target.boot,
            Event::Reconciled {
                observation: None, ..
            } => &authorization.context.boot_id,
            _ => {
                &catalog
                    .hardware_policies
                    .transactions
                    .get(hardware.transaction())
                    .ok_or("hardware event lacks its authenticated preparation")?
                    .intent
                    .target
                    .boot
            }
        };
        if authorization.subject != event.principal.principal
            || authorization.subject_generation != event.principal.generation
            || authorization.lower_ms < history_floor
            || &authorization.context.boot_id != boot
        {
            return Err("hardware attribution differs from its actual Admin writer, boot or protected UTC prefix".into());
        }
    }
    Ok(())
}

impl<'image> HardwareSession<'image> {
    pub(crate) fn open(
        login: &str,
        uses: Vec<(String, crate::finite_grants::Use)>,
        image: &'image crate::hardware_policy::image::Image,
    ) -> Result<Self> {
        crate::require_root()?;
        platform::require_installed()?;
        platform::require_production_activation()?;
        image.check()?;
        scope(&uses)?;
        let directory = Path::new(DIRECTORY);
        let attempt = {
            let mut store = Store::open(
                tpm::LocalAnchor::installed()?,
                &directory.join("journal.json"),
            )?;
            PrincipalLogin::prepare(&mut PrincipalReader::new(&mut store, directory), login)?
        };
        let account = authentication::local(login)?;
        let session = {
            let mut store = Store::open(
                tpm::LocalAnchor::installed()?,
                &directory.join("journal.json"),
            )?;
            PrincipalSession::new(
                account,
                attempt,
                &mut PrincipalReader::new(&mut store, directory),
            )?
        };
        let mut value = Self {
            image,
            session,
            client: Some(crate::utc_provider::Client::installed()?),
            operation: Some(crate::policy_decisions::Operation::begin(
                crate::policy_decisions::Store::installed()?,
                &uses,
            )?),
            decision_ids: Vec::new(),
            uses,
            attempted: BTreeSet::new(),
            fenced: false,
        };
        value.project()?;
        Ok(value)
    }

    fn capture(&mut self) -> Result<GrantCapture> {
        if let Err(error) = self.image.check() {
            self.fenced = true;
            self.session.close();
            return Err(error);
        }
        if self.fenced {
            return Err("hardware original PAM session is fenced".into());
        }
        self.fenced = true;
        let mut boundary = GrantBoundary {
            session: &self.session,
            directory: Path::new(DIRECTORY),
            registry_path: Path::new(crate::principal::REGISTRY),
            client: self
                .client
                .take()
                .ok_or("hardware UTC client is unavailable")?,
            uses: self.uses.clone(),
            operation: self
                .operation
                .take()
                .ok_or("hardware evidence operation is unavailable")?,
            decision_ids: Vec::new(),
            observation: None,
            capture_reason: crate::policy_decisions::Reason::PrincipalUnavailable,
            fenced: false,
        };
        let result = (|| {
            boundary.check()?;
            boundary.require_admin()?;
            let capture = boundary.capture()?;
            current_admin(&capture.catalog, &capture.identity)?;
            if capture.credential_refusal.is_some() {
                return Err("hardware original account credential age is no longer current".into());
            }
            for (grant, usage) in &self.uses {
                capture
                    .catalog
                    .grants
                    .get(grant)
                    .ok_or("hardware grant is unavailable")?
                    .authorize(
                        &capture.catalog,
                        &capture.identity,
                        capture.observation.interval(),
                        usage,
                    )?;
            }
            Ok(capture)
        })();
        let result = result.and_then(|value| {
            self.image.check()?;
            Ok(value)
        });
        self.decision_ids = boundary.decision_ids.clone();
        self.client = Some(boundary.client);
        self.operation = Some(boundary.operation);
        if result.is_ok() {
            self.fenced = false;
        } else {
            self.session.close();
        }
        result
    }

    pub(crate) fn project(&mut self) -> Result<HardwareProjection> {
        let captured = self.capture()?;
        let (lower_ms, upper_ms) = captured.observation.interval().endpoints();
        Ok(HardwareProjection {
            subject: captured.identity["principal"]
                .as_str()
                .ok_or("missing hardware Admin subject")?
                .into(),
            subject_generation: captured.identity["generation"]
                .as_u64()
                .ok_or("missing hardware Admin generation")?,
            state: captured.catalog.hardware_policies,
            boot: captured.observation.context().boot_id.clone(),
            lower_ms,
            upper_ms,
        })
    }

    pub(crate) fn prepare(&mut self, plan: crate::hardware_policy::Plan) -> Result<Transition> {
        plan.validate()?;
        let intent = plan.start(crate::resource_manager::now()?)?;
        self.commit(Event::Prepare { intent }, None)
    }

    /// Brackets one bounded compare/write/readback while holding the current
    /// Admin/NV lock. The callback must not wait for resource-manager or broker
    /// RPC, acquire a resource lock, or run the policy lifetime loop.
    pub(crate) fn dispatch(
        &mut self,
        transaction: &str,
        revision: u64,
        kind: crate::hardware_policy::WriteKind,
        effect: impl FnOnce(&Transition) -> Result<crate::hardware_policy::Observation>,
    ) -> Result<crate::hardware_policy::Observation> {
        let captured = self.capture()?;
        self.fenced = true;
        let effect_id = crate::hardware_policy::hash(&(
            "luma-native-hardware-physical-effect-v1",
            transaction,
            revision,
            match kind {
                crate::hardware_policy::WriteKind::Apply => "apply",
                crate::hardware_policy::WriteKind::Restore => "restore",
            },
            &captured.head,
        ))?;
        if !self.attempted.insert(effect_id.clone()) {
            self.session.close();
            return Err("hardware dispatch has already been attempted; no hidden retry".into());
        }
        let operation = self
            .operation
            .as_ref()
            .ok_or("hardware policy evidence was lost")?;
        let pending = operation.effect_begin(
            &effect_id,
            crate::policy_decisions::EffectKind::HardwarePolicy,
            &self.decision_ids,
        )?;
        let operation_id = operation.id().to_string();
        let directory = Path::new(DIRECTORY);
        let client = self.client.as_mut().ok_or("hardware UTC client was lost")?;
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        let uses = &self.uses;
        let result=self.session.observe_store(&mut PrincipalReader::new(&mut store,directory),|identity,store| {
            let snapshot=store.snapshot()?;
            let context=Context::load(directory,&snapshot.deployment)?;
            let catalog=context.events(&snapshot,None)?.0;
            if snapshot.head!=captured.head || catalog!=captured.catalog || identity!=&captured.identity {
                return Err("hardware current authority changed before bounded dispatch".into());
            }
            current_admin(&catalog,identity)?;
            let transition=catalog.hardware_policies.transactions.get(transaction)
                .ok_or("hardware dispatch has no authenticated prepared obligation")?;
            let expected_uses=(Event::Prepare {intent:transition.intent.clone()}).uses(&State::default(),None)?;
            if transition.revision!=revision || uses!=&expected_uses {
                return Err("hardware dispatch substitutes its exact revision or finite grants".into());
            }
            if transition.dispatches.last().map(|value|value.kind)!=Some(kind) {
                return Err("physical dispatch requires its prior exact protected dispatch-start witness".into());
            }
            let now=crate::resource_manager::now()?;
            let last=match kind {
                crate::hardware_policy::WriteKind::Apply if transition.phase==Phase::Prepared=>transition.intent.deadline_ms,
                crate::hardware_policy::WriteKind::Restore if matches!(transition.phase,Phase::Prepared|Phase::Applied)=>
                    transition.intent.deadline_ms+crate::hardware_policy::CLEANUP_GRACE_MS,
                _=>return Err("hardware dispatch cannot replay or revive an observed/fenced effect".into()),
            };
            if now<transition.intent.created_ms || now>last || crate::hardware_policy::current_boot()?!=transition.intent.target.boot {
                return Err("hardware dispatch lost its original boot or bounded lifetime".into());
            }
            let history=HistoryReader::new(store,directory).read()?;
            let live=client.recheck(&history,&captured.observation)?;
            if live.context().boot_id!=transition.intent.target.boot
                || capture_credential_refusal(&catalog,identity,self.session.binding.password_epoch.as_ref(),&live)?.is_some() {
                return Err("hardware dispatch lost its original UTC/password epoch".into());
            }
            for (id,usage) in uses {
                catalog.grants.get(id).ok_or("hardware current finite grant missing")?
                    .authorize(&catalog,identity,live.interval(),usage)?;
            }
            let result=effect(transition)?;
            self.image.check()?;
            let after=crate::resource_manager::now()?;
            result.validate()?;
            let expected=match kind {
                crate::hardware_policy::WriteKind::Apply=>&transition.intent.after,
                crate::hardware_policy::WriteKind::Restore=>&transition.intent.before,
            };
            if result.target!=transition.intent.target || &result.setting!=expected
                || result.observed_ms<now || result.observed_ms>after {
                return Err("hardware adapter returned a substituted or stale physical observation".into());
            }
            if after<now || after-now>1000 || after>last {
                return Err("hardware write/readback exceeded the bounded operation; retain uncertain obligation".into());
            }
            let live=client.recheck(&history,&live)?;
            for (id,usage) in uses {
                catalog.grants.get(id).ok_or("hardware grant missing after write")?
                    .authorize(&catalog,identity,live.interval(),usage)?;
            }
            Ok(result)
        });
        let result = result.and_then(|observation| {
            pending.complete(&operation_id, &crate::hardware_policy::hash(&observation)?)?;
            Ok(observation)
        });
        if result.is_ok() {
            self.fenced = false;
        } else {
            self.session.close();
        }
        result
    }

    /// Commits exactly one hardware state event, not an arbitrary Admin command.
    /// An error after append leaves that committed obligation visible to cleanup.
    pub(crate) fn commit(
        &mut self,
        event: Event,
        recovery_grant: Option<&str>,
    ) -> Result<Transition> {
        let captured = self.capture()?;
        self.fenced = true;
        self.session.fenced.set(true);
        let result = self.commit_captured(captured, event, recovery_grant);
        if result.is_ok() {
            self.session.fenced.set(false);
            self.fenced = false;
        } else {
            self.session.close();
        }
        result
    }

    fn commit_captured(
        &mut self,
        captured: GrantCapture,
        event: Event,
        recovery_grant: Option<&str>,
    ) -> Result<Transition> {
        event.validate()?;
        if let Event::Reconciled { transaction, .. } = &event {
            let transition = captured
                .catalog
                .hardware_policies
                .transactions
                .get(transaction)
                .ok_or("hardware reconciliation lacks current protected intent")?;
            if let Some(witness) = transition.ambiguous_external_dispatch() {
                witness.require_exited(&transition.intent.target.boot)?;
            }
        }
        if self.uses != event.uses(&captured.catalog.hardware_policies, recovery_grant)? {
            return Err(
                "hardware event is not the original independently admitted finite operation".into(),
            );
        }
        let (lower_ms, upper_ms) = captured.observation.interval().endpoints();
        let authorization = Authorization {
            subject: captured.identity["principal"]
                .as_str()
                .ok_or("missing hardware actor")?
                .into(),
            subject_generation: captured.identity["generation"]
                .as_u64()
                .ok_or("missing hardware actor generation")?,
            context: captured.observation.context().clone(),
            lower_ms,
            upper_ms,
            uses: self.uses.clone(),
        };
        let command = Command::HardwarePolicyEvent {
            event: event.clone(),
            authorization,
        };
        command.validate()?;
        let directory = Path::new(DIRECTORY);
        let registry = Path::new(crate::principal::REGISTRY);
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        let snapshot = store.snapshot()?;
        snapshot.clock.elapsed_since(self.session.clock.get())?;
        if snapshot.head != captured.head || snapshot.head != self.session.binding.checkpoint_head {
            return Err("hardware journal changed before its owned transition".into());
        }
        let context = Context::load_at(directory, &snapshot.deployment, registry)?;
        if !context.state(&snapshot, None)?.1
            || context.events(&snapshot, None)?.0 != captured.catalog
        {
            return Err("hardware semantic catalog changed before its owned transition".into());
        }
        let writer = context.writer(&captured.catalog)?;
        if serde_json::to_value(&writer)? != captured.identity {
            return Err("hardware actual original Admin differs from its protected writer".into());
        }
        self.session.account.observe(|local| {
            let before = PrincipalReader::at(&mut store, directory, registry)
                .resolve_since(local, Some(self.session.clock.get()))?;
            if before != self.session.binding {
                return Err("hardware original account or catalog changed".into());
            }
            Ok(())
        })?;
        let history = HistoryReader::new(&mut store, directory).read()?;
        let client = self.client.as_mut().ok_or("hardware UTC client was lost")?;
        let mut predicted = captured.catalog.clone();
        if !predicted.apply(&command)? {
            return Err("hardware event is not a state transition".into());
        }
        let request = request_id(&event, &snapshot.head)?;
        if snapshot
            .entries
            .iter()
            .any(|entry| entry.request_id == request)
        {
            return Err("hardware event request identity was already consumed".into());
        }
        let payload = CatalogEvent {
            schema_version: 1,
            kind: "native-admin-catalog-event".into(),
            deployment: snapshot.deployment.clone(),
            enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
            principal: writer,
            request_id: request.clone(),
            sequence: snapshot.entries.len() + 1,
            state_version_before: captured.catalog.state_version,
            previous_head: snapshot.head.clone(),
            command,
        };
        check_event(&payload, &captured.catalog, history.floor_ms())?;
        let bytes = serde_json::to_vec(&payload)?;
        if bytes.len() as u64 > MAX_CATALOG_EVENT {
            return Err("hardware event exceeds its fixed payload bound".into());
        }
        let path = directory.join(event_name(&request));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        let entry = Entry {
            request_id: request.clone(),
            authenticated_uid: payload.principal.uid,
            clock: snapshot.clock,
            activity: payload.command.activity().into(),
            payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
        };
        store.append(entry.clone(), |proposed| {
            if proposed != &entry
                || read_event(directory, &request)?.1 != bytes
                || context.events(&snapshot, Some(&request))?.0 != captured.catalog
            {
                return Err("hardware precommitted event or semantic prefix changed".into());
            }
            self.session.account.observe(|local| {
                context.recheck(&mut || Ok(local.clone()))?;
                if captured.catalog.resolve_principal(local)? != captured.identity {
                    return Err("hardware original PAM actor changed before TPM commit".into());
                }
                let live = client.recheck(&history, &captured.observation)?;
                if capture_credential_refusal(
                    &captured.catalog,
                    &captured.identity,
                    self.session.binding.password_epoch.as_ref(),
                    &live,
                )?
                .is_some()
                {
                    return Err("hardware original password epoch expired before TPM commit".into());
                }
                current_admin(&captured.catalog, &captured.identity)?;
                for (id, usage) in &self.uses {
                    captured
                        .catalog
                        .grants
                        .get(id)
                        .ok_or("hardware grant disappeared")?
                        .authorize(
                            &captured.catalog,
                            &captured.identity,
                            live.interval(),
                            usage,
                        )?;
                }
                Ok(())
            })
        })?;
        let final_snapshot = store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if final_snapshot.entries.len() != snapshot.entries.len() + 1
            || final_snapshot.entries.last() != Some(&entry)
            || context.events(&final_snapshot, None)?.0 != predicted
        {
            return Err("hardware committed journal differs from its one predicted event".into());
        }
        let after = self.session.account.observe(|local| {
            let mut reader = PrincipalReader::at(&mut store, directory, registry);
            let after = reader.resolve_since(local, Some(self.session.clock.get()))?;
            exact_successor(&self.session.binding, &after, &final_snapshot.head)?;
            let history = HistoryReader::new(reader.store, directory).read()?;
            let live = client.current(&history)?;
            for (id, usage) in &self.uses {
                predicted
                    .grants
                    .get(id)
                    .ok_or("hardware grant disappeared after commit")?
                    .authorize(&predicted, &after.identity, live.interval(), usage)?;
            }
            Ok(after)
        })?;
        self.session.binding = after;
        self.session.clock.set(final_snapshot.clock);
        Ok(predicted
            .hardware_policies
            .transactions
            .get(event.transaction())
            .ok_or("committed hardware transition missing")?
            .clone())
    }
}

impl Drop for HardwareSession<'_> {
    fn drop(&mut self) {
        self.fenced = true;
        self.session.close();
    }
}

/// Holds the real installed TPM/NV writer lock for the entire fixed cleanup.
/// It never authenticates a human, changes the journal or permits a new policy.
pub(crate) fn with_hardware_cleanup(
    image: &crate::hardware_policy::image::Image,
    transaction: &str,
    cleanup: impl FnOnce(&Transition) -> Result<crate::hardware_policy::Observation>,
) -> Result<crate::hardware_policy::Observation> {
    crate::require_root()?;
    platform::require_installed()?;
    image.check()?;
    if !admin_roles::identifier(transaction) {
        return Err("invalid hardware cleanup transaction".into());
    }
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let first = store.snapshot()?;
    let context = Context::load(directory, &first.deployment)?;
    if !context.state(&first, None)?.1 {
        return Err("hardware cleanup requires authenticated Admin bootstrap".into());
    }
    let state = context.events(&first, None)?.0.hardware_policies;
    let transition = state
        .transactions
        .get(transaction)
        .ok_or("hardware cleanup has no committed obligation")?;
    if !matches!(transition.phase, Phase::Prepared | Phase::Applied) {
        return Err("hardware cleanup refuses fenced, superseded or completed obligations".into());
    }
    if transition
        .dispatches
        .iter()
        .any(|value| value.witness.is_some())
    {
        return Err("external daemon cleanup cannot start or replay a mutating message without a prior live-session restore dispatch commitment; preserve the obligation for fresh Admin reconciliation".into());
    }
    transition.intent.validate()?;
    let now = crate::resource_manager::now()?;
    if crate::hardware_policy::current_boot()? != transition.intent.target.boot
        || now < transition.intent.created_ms
        || now > transition.intent.deadline_ms + crate::hardware_policy::CLEANUP_GRACE_MS
    {
        return Err(
            "hardware cleanup lost its same-boot precommitted bounded restoration window".into(),
        );
    }
    let result = cleanup(transition)?;
    image.check()?;
    let after = crate::resource_manager::now()?;
    result.validate()?;
    if result.target != transition.intent.target
        || result.setting != transition.intent.before
        || result.observed_ms < now
        || result.observed_ms > after
    {
        return Err("hardware cleanup returned a substituted or stale baseline observation".into());
    }
    if after < now
        || after - now > 1000
        || after > transition.intent.deadline_ms + crate::hardware_policy::CLEANUP_GRACE_MS
    {
        return Err(
            "hardware cleanup exceeded its bounded operation; preserve uncertain outcome".into(),
        );
    }
    let last = store.snapshot()?;
    last.clock.elapsed_since(first.clock)?;
    if last.head != first.head
        || last.deployment != first.deployment
        || context.events(&last, None)?.0.hardware_policies != state
    {
        return Err("hardware cleanup authority changed; preserve uncertain outcome".into());
    }
    Ok(result)
}

/// Current TPM-authenticated data for the resource manager's admission fences.
/// Missing/damaged established custody is an error, never an empty-state reset.
pub(crate) fn current_hardware_state() -> Result<State> {
    Ok(catalog_state_optional()?.map_or_else(State::default, |catalog| catalog.hardware_policies))
}

/// Read-only current guard data. This cannot authenticate a caller, grant an
/// effect or replace original PAM. The Manager uses it only to revoke work.
pub(crate) struct HardwareGuard {
    pub state: State,
    pub authority_sha256: String,
    pub utc_upper_ms: i64,
    pub finite_deadlines: BTreeMap<String, i64>,
}
fn guard_catalog(mut catalog: Catalog, utc_upper_ms: i64) -> Result<HardwareGuard> {
    let mut finite_deadlines = BTreeMap::new();
    for (id, grant) in &catalog.grants {
        if !matches!(
            grant.action,
            crate::finite_grants::Action::ApplyHardware
                | crate::finite_grants::Action::RestoreHardware
        ) {
            continue;
        }
        let assignment = catalog
            .assignments
            .get(&grant.assignment)
            .ok_or("hardware guard grant assignment absent")?;
        finite_deadlines.insert(id.clone(), grant.expires_ms.min(assignment.expires_ms));
    }
    let state = std::mem::take(&mut catalog.hardware_policies);
    catalog.state_version = 0;
    let authority_sha256 = crate::hardware_policy::hash(&(
        "luma-native-hardware-non-effect-authority-guard-v1",
        catalog,
    ))?;
    Ok(HardwareGuard {
        state,
        authority_sha256,
        utc_upper_ms,
        finite_deadlines,
    })
}
pub(crate) fn hardware_guard_snapshot() -> Result<HardwareGuard> {
    crate::require_root()?;
    platform::require_installed()?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let first = store.snapshot()?;
    let context = Context::load(directory, &first.deployment)?;
    if !context.state(&first, None)?.1 {
        return Err("hardware active guard requires authenticated Admin bootstrap".into());
    }
    let catalog = context.events(&first, None)?.0;
    let history = HistoryReader::new(&mut store, directory).read()?;
    let mut client = crate::utc_provider::Client::installed()?;
    let observation = client.current(&history)?;
    history.recheck(&mut HistoryReader::new(&mut store, directory))?;
    let last = store.snapshot()?;
    last.clock.elapsed_since(first.clock)?;
    if last.head != first.head
        || last.deployment != first.deployment
        || context.events(&last, None)?.0 != catalog
    {
        return Err("hardware authority changed during current protected UTC guard".into());
    }
    guard_catalog(catalog, observation.interval().endpoints().1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        finite_grants::{Action, Kind, Selector, Use},
        hardware_policy::Adapter,
    };

    fn usage(action: Action) -> (String, Use) {
        (
            format!("grant-{}", action.activity()),
            Use {
                action,
                selector: Selector {
                    kind: Kind::Hardware,
                    id: Adapter::CpuQuota.id().into(),
                    generation: 1,
                    digest: "12".repeat(32),
                },
                input_bytes: 65_536,
                output_bytes: 65_536,
                units: 1,
            },
        )
    }
    #[test]
    fn active_guard_ignores_only_own_hardware_history_and_not_account_or_role_changes() {
        let initial = Catalog::initial();
        let first = guard_catalog(initial.clone(), 1000).unwrap();
        let mut changed = initial.clone();
        changed.state_version += 5;
        changed
            .hardware_policies
            .apply(&Event::Prepare {
                intent: crate::hardware_policy::tests::intent(),
            })
            .unwrap();
        let own = guard_catalog(changed.clone(), 2000).unwrap();
        assert_eq!(first.authority_sha256, own.authority_sha256);
        assert_eq!(own.utc_upper_ms, 2000);
        assert_eq!(own.state.transactions.len(), 1);
        changed.activities.insert("new-reviewed-activity".into());
        assert_ne!(
            first.authority_sha256,
            guard_catalog(changed, 2000).unwrap().authority_sha256
        );
        let mut changed = initial;
        changed.principal_states.insert(
            "12".repeat(32),
            admin_roles::PrincipalState {
                generation: 2,
                enabled: false,
            },
        );
        assert_ne!(
            first.authority_sha256,
            guard_catalog(changed, 2000).unwrap().authority_sha256
        );
    }
    #[test]
    fn only_closed_independent_standard_hardware_scopes_are_accepted() {
        for action in [Action::InspectHardware, Action::RestoreHardware] {
            scope(&[usage(action)]).unwrap();
        }
        scope(&[usage(Action::ApplyHardware), usage(Action::RestoreHardware)]).unwrap();
        for actions in [
            vec![],
            vec![Action::ApplyHardware],
            vec![Action::Infer],
            vec![Action::RestoreHardware, Action::ApplyHardware],
            vec![Action::InspectHardware, Action::ApplyHardware],
            vec![
                Action::ApplyHardware,
                Action::RestoreHardware,
                Action::InspectHardware,
            ],
        ] {
            assert!(scope(&actions.into_iter().map(usage).collect::<Vec<_>>()).is_err());
        }
        let pair = vec![usage(Action::ApplyHardware), usage(Action::RestoreHardware)];
        for variant in 0..6 {
            let mut changed = pair.clone();
            match variant {
                0 => changed[1].0 = changed[0].0.clone(),
                1 => changed[0].1.input_bytes -= 1,
                2 => changed[0].1.output_bytes += 1,
                3 => changed[0].1.units += 1,
                4 => changed[0].1.selector.kind = Kind::Worker,
                _ => changed[0].0 = "bad/id".into(),
            }
            assert!(scope(&changed).is_err());
        }
    }

    fn binding(head: &str) -> PrincipalBinding {
        PrincipalBinding {
            password_epoch: Some(("12".repeat(32), "34".repeat(16), 1, 2, 3)),
            credential_sha256: Some("56".repeat(32)),
            identity_path: "/var/lib/luma-os/identity".into(),
            purpose: PrincipalPurpose::General,
            deployment: "78".repeat(32),
            enrollment_sha256: "89".repeat(32),
            checkpoint_head: head.into(),
            reset_count: 1,
            restart_count: 2,
            identity: serde_json::json!({"principal":"cd".repeat(32),"generation":1}),
        }
    }
    #[test]
    fn one_exact_hardware_head_transition_does_not_renew_other_authority() {
        let before = binding(&"ab".repeat(32));
        let mut after = binding(&"bc".repeat(32));
        exact_successor(&before, &after, &"bc".repeat(32)).unwrap();
        for variant in 0..12 {
            after = binding(&"bc".repeat(32));
            match variant {
                0 => after.password_epoch = None,
                1 => after.credential_sha256 = None,
                2 => after.identity_path = "/tmp/identity".into(),
                3 => after.purpose = PrincipalPurpose::UtcSeed { candidate: None },
                4 => after.deployment = "ef".repeat(32),
                5 => after.enrollment_sha256 = "ef".repeat(32),
                6 => after.reset_count += 1,
                7 => after.restart_count += 1,
                8 => after.identity["generation"] = 2.into(),
                9 => after.identity["principal"] = "ef".repeat(32).into(),
                10 => after.checkpoint_head = "cd".repeat(32),
                _ => after.checkpoint_head = before.checkpoint_head.clone(),
            }
            assert!(
                exact_successor(&before, &after, &"bc".repeat(32)).is_err(),
                "variant {variant}"
            );
        }
        assert!(exact_successor(&before, &before, &before.checkpoint_head).is_err());
    }
}
