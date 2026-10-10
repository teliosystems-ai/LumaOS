//! Explicit product Admin bootstrap atop the inert TPM checkpoint adapter.
//! The receipt establishes one governance principal, never an effect grant.
//! No implicit root role, automatic enrollment, transfer or authority reset.
//! Explicit offline custody recovery is separate from ordinary PAM commands.
use crate::{
    admin_enrollment,
    admin_journal::{self, Entry, Snapshot, Store},
    admin_roles::{self, Catalog, Command},
    authentication, bundle, platform,
    tpm::{self, Checkpoint},
    utc_history::{self, History, Record as HistoryRecord, Statement},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const DIRECTORY: &str = "/var/lib/luma-os/admin";
const REQUEST: &str = "admin-bootstrap-v1";
const ACTIVITY: &str = "admin.bootstrap";
const MAX_CATALOG_EVENT: u64 = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    installation: String,
    principal: String,
    generation: u64,
    login: String,
    uid: u32,
}

impl Identity {
    fn parse(value: serde_json::Value) -> Result<Self> {
        let identity: Self = serde_json::from_value(value)?;
        tpm::decode::<32>(&identity.installation)?;
        tpm::decode::<32>(&identity.principal)?;
        if identity.uid != 1001
            || identity.generation == 0
            || identity.installation == identity.principal
            || identity.login.is_empty()
            || identity.login.len() > 32
            || !identity.login.as_bytes()[0].is_ascii_lowercase()
            || !identity
                .login
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err("Admin bootstrap requires the enrolled installer-selected human".into());
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    schema_version: u32,
    kind: String,
    role: String,
    deployment: String,
    enrollment_sha256: String,
    principal: Identity,
    previous_head: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CatalogEvent {
    schema_version: u32,
    kind: String,
    deployment: String,
    enrollment_sha256: String,
    principal: Identity,
    request_id: String,
    sequence: usize,
    state_version_before: u64,
    previous_head: String,
    command: Command,
}

fn event_name(request: &str) -> String {
    format!(
        "event-{}.json",
        bundle::hex(&Sha256::digest(request.as_bytes()))
    )
}

fn read_event(directory: &Path, request: &str) -> Result<(CatalogEvent, Vec<u8>)> {
    let bytes = tpm::private_read(&directory.join(event_name(request)), MAX_CATALOG_EVENT)?;
    let event: CatalogEvent = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&event)? != bytes || event.request_id != request {
        return Err("noncanonical or substituted Admin catalog payload; preserve state".into());
    }
    Ok((event, bytes))
}

struct Context<'a> {
    directory: &'a Path,
    enrollment: Vec<u8>,
    deployment: String,
    principal: Identity,
    registry_path: &'a Path,
}

impl<'a> Context<'a> {
    fn load(directory: &'a Path, deployment: &str) -> Result<Self> {
        Self::load_at(directory, deployment, Path::new(crate::principal::REGISTRY))
    }

    fn load_at(directory: &'a Path, deployment: &str, registry_path: &'a Path) -> Result<Self> {
        let enrollment = tpm::private_read(&directory.join("enrollment.json"), 16384)?;
        let principal = Identity::parse(admin_enrollment::checkpoint_identity(
            &enrollment,
            deployment,
        )?)?;
        Ok(Self {
            directory,
            enrollment,
            deployment: deployment.into(),
            principal,
            registry_path,
        })
    }

    fn recheck(&self, authenticate: &mut impl FnMut() -> Result<serde_json::Value>) -> Result<()> {
        // Finish potentially blocking enrollment reads before renewing the
        // short-lived PAM observation. JSON projection alone is not authority.
        if tpm::private_read(&self.directory.join("enrollment.json"), 16384)? != self.enrollment
            || Identity::parse(authenticate()?)? != self.principal
        {
            return Err(
                "Admin bootstrap principal or enrollment changed; authenticate again".into(),
            );
        }
        Ok(())
    }

    // PAM identifies the immutable installation account. Product writer
    // generations come only from the catalog at the exact journal prefix;
    // neither a caller's generation nor today's state can authorize old bytes.
    fn writer(&self, catalog: &Catalog) -> Result<Identity> {
        if catalog.principal_registry.is_none() {
            return Ok(self.principal.clone());
        }
        Identity::parse(catalog.resolve_principal(&serde_json::to_value(&self.principal)?)?)
    }

    fn custody_writer(&self, catalog: &Catalog) -> Result<Identity> {
        let registry = catalog.registry()?;
        let admin = registry
            .bootstrap_admin()
            .ok_or("missing original Admin custody identity")?;
        if registry.identity(admin) != serde_json::to_value(&self.principal)? {
            return Err("offline custody does not bind the enrolled original Admin".into());
        }
        let mut writer = self.principal.clone();
        writer.generation = catalog
            .principal_states
            .get(&admin.id)
            .map_or(admin.generation, |state| state.generation);
        Ok(writer)
    }

    fn payload(&self, previous_head: &str) -> Bootstrap {
        Bootstrap {
            schema_version: 1,
            kind: "local-tpm2-admin-bootstrap".into(),
            role: "Admin".into(),
            deployment: self.deployment.clone(),
            enrollment_sha256: bundle::hex(&Sha256::digest(&self.enrollment)),
            principal: self.principal.clone(),
            previous_head: previous_head.into(),
        }
    }

    fn existing(&self) -> Result<Option<(Bootstrap, Vec<u8>)>> {
        let path = self.directory.join("bootstrap.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => (),
        }
        let bytes = tpm::private_read(&path, 4096)?;
        let parsed: Bootstrap = serde_json::from_slice(&bytes)?;
        tpm::decode::<32>(&parsed.previous_head)?;
        if serde_json::to_vec(&parsed)? != bytes || parsed != self.payload(&parsed.previous_head) {
            return Err("invalid or changed Admin bootstrap payload; preserve state".into());
        }
        Ok(Some((parsed, bytes)))
    }

    fn prepare(&self, payload: &Bootstrap) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(payload)?;
        if let Some((_, existing)) = self.existing()? {
            if existing != bytes {
                return Err("different retained Admin bootstrap; preserve state".into());
            }
        } else {
            // A partial write remains a fence. Never overwrite retained bytes.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(self.directory.join("bootstrap.json"))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        File::open(self.directory.join("bootstrap.json"))?.sync_all()?;
        File::open(self.directory)?.sync_all()?;
        if self.existing()?.ok_or("missing Admin bootstrap")?.1 != bytes {
            return Err("Admin bootstrap changed during preparation".into());
        }
        Ok(bytes)
    }

    fn state(&self, snapshot: &Snapshot, candidate: Option<&str>) -> Result<(Bootstrap, bool)> {
        let state = self.bootstrap_state(snapshot)?;
        self.events(snapshot, candidate)?;
        Ok(state)
    }

    fn bootstrap_state(&self, snapshot: &Snapshot) -> Result<(Bootstrap, bool)> {
        if snapshot.deployment != self.deployment {
            return Err("Admin checkpoint deployment changed".into());
        }
        let retained = self.existing()?;
        match snapshot.entries.as_slice() {
            [] => {
                let payload = self.payload(&snapshot.head);
                if retained.is_some_and(|(old, _)| old != payload) {
                    return Err("retained Admin bootstrap does not bind the current head".into());
                }
                Ok((payload, false))
            }
            [entry, ..] => {
                let (payload, bytes) =
                    retained.ok_or("anchored Admin bootstrap payload missing")?;
                let genesis = bundle::hex(&tpm::extend_value(
                    [0; 32],
                    admin_journal::genesis(&self.deployment)?,
                ));
                if entry.request_id != REQUEST
                    || entry.activity != ACTIVITY
                    || entry.authenticated_uid != self.principal.uid
                    || entry.payload_sha256 != bundle::hex(&Sha256::digest(&bytes))
                    || payload.previous_head != genesis
                {
                    return Err("checkpoint is not the supported Admin bootstrap history".into());
                }
                Ok((payload, true))
            }
        }
    }

    fn events(
        &self,
        snapshot: &Snapshot,
        candidate: Option<&str>,
    ) -> Result<(Catalog, Vec<CatalogEvent>)> {
        let (catalog, events, _, _) = self.replay(snapshot, candidate)?;
        Ok((catalog, events))
    }
    fn history(
        &self,
        snapshot: &Snapshot,
        candidate: Option<&str>,
    ) -> Result<(History, Vec<HistoryRecord>)> {
        let (_, _, history, records) = self.replay(snapshot, candidate)?;
        Ok((history, records))
    }
    fn replay(
        &self,
        snapshot: &Snapshot,
        candidate: Option<&str>,
    ) -> Result<(Catalog, Vec<CatalogEvent>, History, Vec<HistoryRecord>)> {
        let mut catalog = Catalog::initial();
        let mut events = Vec::new();
        let mut history = History::initial();
        let mut records = Vec::new();
        let mut names = BTreeSet::new();
        for (position, entry) in snapshot.entries.iter().enumerate().skip(1) {
            if entry.activity == utc_history::ACTIVITY {
                let writer = self.writer(&catalog)?;
                let (record, bytes) = utc_history::read(
                    &self.directory.join(event_name(&entry.request_id)),
                    &entry.request_id,
                )?;
                if !admin_roles::identifier(&entry.request_id)
                    || entry.request_id == REQUEST
                    || record.deployment != self.deployment
                    || record.principal != writer
                    || record.enrollment_sha256 != bundle::hex(&Sha256::digest(&self.enrollment))
                    || record.sequence != position + 1
                    || snapshot.prefix_heads.get(position) != Some(&record.previous_head)
                    || entry.authenticated_uid != self.principal.uid
                    || entry.payload_sha256 != bundle::hex(&Sha256::digest(&bytes))
                {
                    return Err(
                        "UTC history does not bind the authenticated Admin checkpoint".into(),
                    );
                }
                history.apply(&record)?;
                names.insert(event_name(&entry.request_id));
                records.push(record);
                continue;
            }
            let (event, bytes) = read_event(self.directory, &entry.request_id)?;
            let writer = if admin_account_recovery(&event.command) {
                self.custody_writer(&catalog)?
            } else {
                self.writer(&catalog)?
            };
            if !admin_roles::identifier(&entry.request_id)
                || entry.request_id == REQUEST
                || event.schema_version != 1
                || event.kind != "native-admin-catalog-event"
                || event.deployment != self.deployment
                || event.principal != writer
                || event.enrollment_sha256 != bundle::hex(&Sha256::digest(&self.enrollment))
                || event.sequence != position + 1
                || event.state_version_before != catalog.state_version
                || snapshot.prefix_heads.get(position) != Some(&event.previous_head)
                || entry.authenticated_uid != self.principal.uid
                || entry.activity != event.command.activity()
                || entry.payload_sha256 != bundle::hex(&Sha256::digest(&bytes))
            {
                return Err("Admin catalog event does not bind the authenticated history".into());
            }
            if !catalog.apply(&event.command)? {
                return Err("anchored Admin catalog event is not a mutation".into());
            }
            if let Command::AdoptPrincipals { registry } = &event.command {
                if !registry.binds(
                    &self.principal.installation,
                    &self.principal.principal,
                    self.principal.generation,
                    &self.principal.login,
                    self.principal.uid,
                ) {
                    return Err(
                        "anchored principal registry does not bind the original Admin".into(),
                    );
                }
            }
            names.insert(event_name(&entry.request_id));
            events.push(event);
        }
        // A payload written before journal preparation is still retained
        // intent. Only its exact request may review/resume it at the same head.
        // Unrelated mutations and ordinary status never skip that fence.
        if let Some(request) = candidate {
            names.insert(event_name(request));
        }
        for (count, item) in fs::read_dir(self.directory)?.enumerate() {
            if count >= 4104 {
                return Err("oversized Admin payload inventory".into());
            }
            let item = item?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 Admin state file")?;
            if name.starts_with("event-") && !names.contains(name) {
                return Err(
                    "unreferenced Admin catalog preparation; preserve and review its request"
                        .into(),
                );
            }
        }
        if catalog.principal_registry.is_some() {
            let current = crate::principal::RegistryBinding::capture(self.registry_path)?;
            if !catalog.accepts_registry(current.current()?)? {
                return Err("installed principal registry differs from TPM-backed authority; preserve state".into());
            }
        }
        Ok((catalog, events, history, records))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PrincipalPurpose {
    General,
    AdminCatalog { candidate: Option<String> },
    UtcSeed { candidate: Option<String> },
}

#[derive(Debug, PartialEq, Eq)]
struct PrincipalBinding {
    password_epoch: Option<(String, String, u64, u64, u64)>,
    credential_sha256: Option<String>,
    identity_path: std::path::PathBuf,
    purpose: PrincipalPurpose,
    deployment: String,
    enrollment_sha256: String,
    checkpoint_head: String,
    reset_count: u32,
    restart_count: u32,
    identity: serde_json::Value,
}

// Retains original registry handles and the exact pre-PAM authority. It cannot
// be cloned, deserialized, exported or used as authentication on its own.
struct PrincipalLogin {
    registry: crate::principal::RegistryBinding,
    local: serde_json::Value,
    binding: PrincipalBinding,
    clock: tpm::Clock,
    exchange: authentication::ExchangeBoundary,
}

impl PrincipalLogin {
    fn prepare<A: Checkpoint>(reader: &mut PrincipalReader<'_, A>, login: &str) -> Result<Self> {
        let registry = crate::principal::RegistryBinding::capture(reader.registry_path)?;
        let current = registry.current()?;
        let record = current
            .account(login)
            .filter(|record| record.enabled)
            .ok_or("missing enabled installed principal for governed login")?;
        let local = current.identity(record);
        let binding = reader.resolve(&local)?;
        let clock = reader
            .last_clock
            .ok_or("missing governed login checkpoint clock")?;
        registry.current()?;
        let exchange = authentication::ExchangeBoundary::capture()?;
        Ok(Self {
            registry,
            local,
            binding,
            clock,
            exchange,
        })
    }
}

/// Owned by the protected TPM/PAM composition. No caller-selected path or
/// identity is accepted by the public reader; every read needs a live account.
pub(crate) struct PrincipalReader<'a, A: Checkpoint> {
    store: &'a mut Store<A>,
    directory: &'a Path,
    registry_path: &'a Path,
    identity_path: &'a Path,
    last_clock: Option<tpm::Clock>,
    fenced: bool,
    admin_candidate: Option<Option<&'a str>>,
    seed_only: bool,
}

impl<'a, A: Checkpoint> PrincipalReader<'a, A> {
    fn new(store: &'a mut Store<A>, directory: &'a Path) -> Self {
        Self::at(store, directory, Path::new(crate::principal::REGISTRY))
    }

    fn at(store: &'a mut Store<A>, directory: &'a Path, registry_path: &'a Path) -> Self {
        Self {
            store,
            directory,
            registry_path,
            identity_path: account_identity(registry_path),
            last_clock: None,
            fenced: false,
            admin_candidate: None,
            seed_only: false,
        }
    }

    fn admin_at(
        store: &'a mut Store<A>,
        directory: &'a Path,
        registry_path: &'a Path,
        candidate: Option<&'a str>,
    ) -> Self {
        let mut reader = Self::at(store, directory, registry_path);
        reader.admin_candidate = Some(candidate);
        reader
    }

    fn seed_at(
        store: &'a mut Store<A>,
        directory: &'a Path,
        registry_path: &'a Path,
        candidate: Option<&'a str>,
    ) -> Self {
        let mut reader = Self::admin_at(store, directory, registry_path, candidate);
        reader.seed_only = true;
        reader
    }

    fn replay(
        &mut self,
        local: &serde_json::Value,
        session_clock: Option<tpm::Clock>,
    ) -> Result<(PrincipalBinding, tpm::Clock)> {
        let registry = crate::principal::RegistryBinding::capture(self.registry_path)?;
        let snapshot = self.store.snapshot()?;
        for previous in [session_clock, self.last_clock].into_iter().flatten() {
            snapshot.clock.elapsed_since(previous)?;
        }
        let context = Context::load_at(self.directory, &snapshot.deployment, self.registry_path)?;
        if !context.bootstrap_state(&snapshot)?.1 {
            return Err("explicit product Admin bootstrap required".into());
        }
        let (catalog, _) = context.events(&snapshot, self.admin_candidate.flatten())?;
        let credential = if catalog.account_commitments.is_empty() {
            None
        } else {
            let principal = local["principal"]
                .as_str()
                .ok_or("missing local account principal")?;
            let expected = catalog
                .account_commitments
                .get(principal)
                .ok_or("missing checkpointed account credential")?;
            let name = local["login"]
                .as_str()
                .ok_or("missing local account login")?;
            let account = crate::principal::AccountBinding::capture(
                self.registry_path,
                self.identity_path,
                name,
            )?;
            if &account.credential_commitment()? != expected {
                return Err("local account differs from TPM-checkpointed credentials; governed lifecycle recovery required".into());
            }
            Some((expected.clone(), account))
        };
        let (identity, purpose) = if let Some(candidate) = self.admin_candidate {
            if Identity::parse(local.clone())? != context.principal {
                return Err("catalog session requires the original enrolled Admin account".into());
            }
            (
                serde_json::to_value(context.writer(&catalog)?)?,
                if self.seed_only {
                    PrincipalPurpose::UtcSeed {
                        candidate: candidate.map(str::to_owned),
                    }
                } else {
                    PrincipalPurpose::AdminCatalog {
                        candidate: candidate.map(str::to_owned),
                    }
                },
            )
        } else {
            (catalog.resolve_principal(local)?, PrincipalPurpose::General)
        };
        let password_epoch = if let Some(day) = catalog
            .password_day(local["principal"].as_str().ok_or("missing principal")?)
            .filter(|_| !self.seed_only)
        {
            let mut history = match self.admin_candidate.flatten() {
                Some(request) => HistoryReader::for_candidate(self.store, self.directory, request)?,
                None => HistoryReader::new(self.store, self.directory),
            };
            let binding = history.read()?;
            let mut client = crate::utc_provider::Client::installed()?;
            let live = client.current(&binding)?;
            binding.recheck(&mut history)?;
            let (lower, upper) = live.interval().endpoints();
            let start = i64::from(day) * 86_400_000;
            let end = i64::from(day)
                .checked_add(90)
                .ok_or("password age overflow")?
                * 86_400_000;
            if lower < start || upper >= end {
                return Err("password aging expired or current protected UTC unavailable; governed password renewal required".into());
            }
            let context = live.context();
            Some((
                context.runtime_sha256.clone(),
                context.boot_id.clone(),
                context.process_generation,
                context.source_clock_generation,
                context.keeper_generation,
            ))
        } else {
            None
        };
        let final_snapshot = self.store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if final_snapshot.head != snapshot.head
            || final_snapshot.deployment != snapshot.deployment
            || tpm::private_read(&self.directory.join("enrollment.json"), 16384)?
                != context.enrollment
        {
            return Err("principal authority changed during replay".into());
        }
        registry.current()?;
        if let Some((_, account)) = &credential {
            account.current_uid()?;
        }
        Ok((
            PrincipalBinding {
                password_epoch,
                credential_sha256: credential.map(|(commitment, _)| commitment),
                identity_path: self.identity_path.into(),
                purpose,
                deployment: snapshot.deployment,
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                checkpoint_head: snapshot.head,
                reset_count: final_snapshot.clock.reset_count,
                restart_count: final_snapshot.clock.restart_count,
                identity,
            },
            final_snapshot.clock,
        ))
    }

    // Inert identity lookup only. Native callers cannot invoke this path with
    // JSON in place of authentication; the public composition uses real PAM.
    fn resolve(&mut self, local: &serde_json::Value) -> Result<PrincipalBinding> {
        self.resolve_since(local, None)
    }

    fn resolve_since(
        &mut self,
        local: &serde_json::Value,
        session_clock: Option<tpm::Clock>,
    ) -> Result<PrincipalBinding> {
        if self.fenced {
            return Err("principal authority reader is fenced".into());
        }
        // An error or unwinding cannot reactivate the reader after a lost proof.
        self.fenced = true;
        let (before, first_clock) = self.replay(local, session_clock)?;
        if let Some(issued) = session_clock {
            first_clock.elapsed_since(issued)?;
        }
        if let Some(previous) = self.last_clock {
            first_clock.elapsed_since(previous)?;
        }
        let (after, last_clock) = self.replay(local, Some(first_clock))?;
        last_clock.elapsed_since(first_clock)?;
        if before != after {
            return Err("principal history changed during double replay".into());
        }
        self.last_clock = Some(last_clock);
        self.fenced = false;
        Ok(after)
    }

    fn read_account(
        &mut self,
        account: &authentication::AuthenticatedAccount,
        login: &PrincipalLogin,
    ) -> Result<PrincipalBinding> {
        let result = account.observe_fresh(&login.exchange, |local| {
            login.registry.current()?;
            if local != &login.local {
                return Err("PAM account differs from the governed login principal".into());
            }
            let current = self.resolve_since(local, Some(login.clock))?;
            self.last_clock
                .ok_or("missing post-PAM checkpoint clock")?
                .elapsed_since(login.clock)?;
            login.registry.current()?;
            if current != login.binding {
                return Err("governed authority changed during PAM; restart login".into());
            }
            Ok(current)
        });
        if result.is_err() {
            self.fenced = true;
            account.logout();
        }
        result
    }
}

/// A process-local, nonserializable composition of genuine bounded PAM and a
/// current TPM principal binding. It conveys no role, custody or effect grant.
pub(crate) struct PrincipalSession {
    account: authentication::AuthenticatedAccount,
    binding: PrincipalBinding,
    clock: std::cell::Cell<tpm::Clock>,
    fenced: std::cell::Cell<bool>,
}

// A failed or unwound projection closes every participating live observation.
// Completion occurs only after both semantic replays and PAM's final pin/expiry
// check; there is no result, retry, renewal or recovery capability in this guard.
struct PrincipalProjection<'r, 's, A: Checkpoint> {
    session: &'r PrincipalSession,
    reader: &'r mut PrincipalReader<'s, A>,
    completed: bool,
}

impl<A: Checkpoint> Drop for PrincipalProjection<'_, '_, A> {
    fn drop(&mut self) {
        if !self.completed {
            self.reader.fenced = true;
            self.session.close();
        }
    }
}

impl PrincipalSession {
    fn new<A: Checkpoint>(
        account: authentication::AuthenticatedAccount,
        login: PrincipalLogin,
        reader: &mut PrincipalReader<'_, A>,
    ) -> Result<Self> {
        let binding = reader.read_account(&account, &login)?;
        let clock = reader
            .last_clock
            .ok_or("missing governed session issuance clock")?;
        Ok(Self {
            account,
            binding,
            clock: std::cell::Cell::new(clock),
            fenced: std::cell::Cell::new(false),
        })
    }

    fn identity<A: Checkpoint>(
        &self,
        reader: &mut PrincipalReader<'_, A>,
    ) -> Result<serde_json::Value> {
        self.observe(reader, |identity| Ok(identity.clone()))
    }

    // Bracket a protected projection, not just a preliminary identity lookup.
    // This authenticates its principal throughout; separate role, folder,
    // resource and effect policies must still authorize any actual operation.
    fn observe<A: Checkpoint, T>(
        &self,
        reader: &mut PrincipalReader<'_, A>,
        project: impl FnOnce(&serde_json::Value) -> Result<T>,
    ) -> Result<T> {
        self.observe_store(reader, |identity, _store| project(identity))
    }

    // Read-only semantic projections may borrow the same protected store while
    // bracketed. A mutation must instead consume CatalogAttempt: this method's
    // final replay deliberately refuses a changed head, never rolls back effects.
    fn observe_store<A: Checkpoint, T>(
        &self,
        reader: &mut PrincipalReader<'_, A>,
        project: impl FnOnce(&serde_json::Value, &mut Store<A>) -> Result<T>,
    ) -> Result<T> {
        if self.fenced.get() {
            reader.fenced = true;
            self.close();
            return Err("governed principal session is fenced".into());
        }
        self.fenced.set(true);
        let mut projection = PrincipalProjection {
            session: self,
            reader,
            completed: false,
        };
        let result = self.account.observe(|local| {
            let before = projection
                .reader
                .resolve_since(local, Some(self.clock.get()))?;
            if before != self.binding {
                return Err(
                    "governed generation or shared authority changed; authenticate again".into(),
                );
            }
            let result = project(&before.identity, projection.reader.store)?;
            let after = projection
                .reader
                .resolve_since(local, Some(self.clock.get()))?;
            if after != before {
                return Err("governed authority changed during protected projection".into());
            }
            Ok(result)
        });
        let result = result?;
        self.clock.set(
            projection
                .reader
                .last_clock
                .ok_or("missing governed projection completion clock")?,
        );
        projection.completed = true;
        self.fenced.set(false);
        Ok(result)
    }

    fn close(&self) {
        self.fenced.set(true);
        self.account.logout();
    }
}

impl Drop for PrincipalSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Current read-only projection of the real adopted account and TPM catalog.
/// This is not authentication or admission; callers still require genuine PAM.
pub(crate) fn current_principal(
    login: &str,
) -> Result<(
    crate::principal::RegistryBinding,
    crate::principal::Principal,
    String,
)> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let registry =
        crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
    let installation = registry.current()?.installation().to_owned();
    let baseline = registry
        .current()?
        .account(login)
        .filter(|p| p.enabled)
        .ok_or("enabled installed principal unavailable")?
        .clone();
    let local = registry.current()?.identity(&baseline);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &Path::new(DIRECTORY).join("journal.json"),
    )?;
    let binding = PrincipalReader::new(&mut store, Path::new(DIRECTORY)).resolve(&local)?;
    let current = current_projection(&baseline, &binding.identity)?;
    let snapshot = store.snapshot()?;
    if snapshot.head != binding.checkpoint_head || snapshot.deployment != binding.deployment {
        return Err("current principal projection changed before delivery".into());
    }
    let context = Context::load_at(
        Path::new(DIRECTORY),
        &snapshot.deployment,
        Path::new(crate::principal::REGISTRY),
    )?;
    let (catalog, _) = context.events(&snapshot, None)?;
    projection_available(&catalog, &current.id)?;
    let final_snapshot = store.snapshot()?;
    final_snapshot.clock.elapsed_since(snapshot.clock)?;
    if final_snapshot.head != snapshot.head || final_snapshot.deployment != snapshot.deployment {
        return Err("current principal catalog changed before delivery".into());
    }
    registry.current()?;
    Ok((registry, current, installation))
}

fn current_projection(
    baseline: &crate::principal::Principal,
    identity: &serde_json::Value,
) -> Result<crate::principal::Principal> {
    let mut current = baseline.clone();
    if identity["principal"].as_str() != Some(baseline.id.as_str())
        || identity["login"].as_str() != Some(baseline.login.as_str())
        || identity["uid"].as_u64() != Some(u64::from(baseline.uid))
    {
        return Err("current catalog principal does not match installed account".into());
    }
    current.generation = identity["generation"]
        .as_u64()
        .filter(|n| *n >= baseline.generation)
        .ok_or("invalid current principal generation")?;
    current.enabled = true;
    Ok(current)
}

fn projection_available(catalog: &Catalog, principal: &str) -> Result<()> {
    if catalog.deleted_principals.contains(principal)
        || catalog.needs_password_aging.contains(principal)
        || catalog
            .principal_states
            .get(principal)
            .is_some_and(|state| !state.enabled)
    {
        return Err("current principal is deleted, disabled or awaiting activation".into());
    }
    Ok(())
}

/// An owned operation's live human, catalog and UTC boundary. The grant record
/// itself is never returned, and neither this object nor its PAM session has a
/// serialized form. The catalog writer lock is held only for each check, never
/// through the workflow: revocation can commit between every effect/poll.
pub(crate) struct GrantBoundary<'a> {
    session: &'a PrincipalSession,
    directory: &'a Path,
    registry_path: &'a Path,
    client: crate::utc_provider::Client,
    uses: Vec<(String, crate::finite_grants::Use)>,
    operation: crate::policy_decisions::Operation,
    decision_ids: Vec<String>,
    observation: Option<crate::utc_stream::Observation>,
    capture_reason: crate::policy_decisions::Reason,
    fenced: bool,
}

struct GrantCapture {
    catalog: Catalog,
    identity: serde_json::Value,
    head: String,
    observation: crate::utc_stream::Observation,
    credential_refusal: Option<crate::policy_decisions::Reason>,
}

impl GrantBoundary<'_> {
    pub(crate) fn audit(&self) -> Result<crate::finite_grants::Audit> {
        if self.fenced || self.uses.len() != 1 {
            return Err("inference attribution requires its current single owned scope".into());
        }
        let record = crate::finite_grants::Audit {
            subject: self.subject()?.into(),
            subject_generation: self.subject_generation()?,
            grant_id: self.uses[0].0.clone(),
            grant_version: 1,
            checkpoint_head: self.session.binding.checkpoint_head.clone(),
            operation_id: Some(self.operation.id().into()),
            usage: self.uses[0].1.clone(),
        };
        record.validate()?;
        Ok(record)
    }
    pub(crate) fn subject(&self) -> Result<&str> {
        self.session.binding.identity["principal"]
            .as_str()
            .ok_or_else(|| "missing governed grant subject".into())
    }

    pub(crate) fn subject_generation(&self) -> Result<u64> {
        self.session.binding.identity["generation"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or_else(|| "missing governed subject generation".into())
    }
    pub(crate) fn subject_uid(&self) -> Result<u32> {
        self.session.binding.identity["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| "missing actual governed human UID".into())
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.operation.id()
    }

    pub(crate) fn observation(&mut self) -> Result<crate::utc_stream::Observation> {
        self.check()?;
        self.observation
            .take()
            .ok_or_else(|| "missing actual protected policy observation".into())
    }

    pub(crate) fn effect_begin(
        &mut self,
        effect_id: &str,
        kind: crate::policy_decisions::EffectKind,
    ) -> Result<crate::policy_decisions::PendingEffect> {
        self.check()?;
        let pending = self
            .operation
            .effect_begin(effect_id, kind, &self.decision_ids)?;
        self.check()?;
        Ok(pending)
    }

    pub(crate) fn effect_complete(
        &mut self,
        pending: crate::policy_decisions::PendingEffect,
        receipt_sha256: &str,
    ) -> Result<()> {
        pending.complete(self.operation.id(), receipt_sha256)?;
        // A confirmed outcome is retained even when this final live check
        // refuses. No denial can erase or re-dispatch an already committed effect.
        self.check()
    }

    fn unavailable(&self, reason: crate::policy_decisions::Reason) -> Result<()> {
        self.operation.decisions(
            self.uses
                .iter()
                .map(|(grant, usage)| {
                    crate::policy_decisions::Decision::unavailable(grant, usage, reason)
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
        Ok(())
    }

    fn decisions(&self, capture: &GrantCapture) -> Result<Vec<crate::policy_decisions::Decision>> {
        self.uses
            .iter()
            .map(|(grant, usage)| {
                crate::policy_decisions::Decision::evaluate(
                    &capture.catalog,
                    &capture.identity,
                    &capture.head,
                    &capture.observation,
                    grant,
                    usage,
                    capture.credential_refusal,
                )
            })
            .collect()
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        if self.fenced {
            return Err("finite grant operation is permanently fenced".into());
        }
        self.fenced = true;
        self.observation = None;
        let captured = match self.capture() {
            Ok(value) => value,
            Err(error) => {
                self.unavailable(self.capture_reason)?;
                return Err(error);
            }
        };
        let decisions = self.decisions(&captured)?;
        let allowed = decisions
            .iter()
            .all(|v| v.outcome == crate::policy_decisions::DecisionOutcome::Allow);
        self.decision_ids = self.operation.decisions(decisions)?;
        if !allowed {
            return Err("current finite policy denied the owned effect scopes".into());
        }
        // Evidence persistence can block and must never cache effect authority.
        // Reopen the actual catalog/PAM/UTC projection AFTER that I/O, allowing
        // a revocation writer to commit while the inert audit lock is held.
        let final_capture = match self.capture() {
            Ok(value) => value,
            Err(error) => {
                self.unavailable(self.capture_reason)?;
                return Err(error);
            }
        };
        let decisions = self.decisions(&final_capture)?;
        if decisions
            .iter()
            .any(|v| v.outcome != crate::policy_decisions::DecisionOutcome::Allow)
        {
            self.operation.decisions(decisions)?;
            return Err("finite policy changed after its durable decision".into());
        }
        self.observation = Some(final_capture.observation);
        self.fenced = false;
        Ok(())
    }

    fn capture(&mut self) -> Result<GrantCapture> {
        self.capture_reason = crate::policy_decisions::Reason::CatalogUnavailable;
        let client = &mut self.client;
        let stage = &mut self.capture_reason;
        let directory = self.directory;
        let registry_path = self.registry_path;
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        *stage = crate::policy_decisions::Reason::PrincipalUnavailable;
        let (catalog, identity, history, observation) = self.session.observe_store(
            &mut PrincipalReader::at(&mut store, directory, registry_path),
            |identity, store| {
                *stage = crate::policy_decisions::Reason::CatalogUnavailable;
                let snapshot = store.snapshot()?;
                let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
                let catalog = context.events(&snapshot, None)?.0;
                let history = HistoryReader::new(store, directory).read()?;
                *stage = crate::policy_decisions::Reason::UtcUnavailable;
                let current = client.current(&history)?;
                *stage = crate::policy_decisions::Reason::AuthorityChanged;
                history.recheck(&mut HistoryReader::new(store, directory))?;
                let final_snapshot = store.snapshot()?;
                final_snapshot.clock.elapsed_since(snapshot.clock)?;
                if final_snapshot.head != snapshot.head
                    || final_snapshot.deployment != snapshot.deployment
                    || context.events(&final_snapshot, None)?.0 != catalog
                {
                    return Err("finite grant catalog changed at the effect boundary".into());
                }
                history.recheck(&mut HistoryReader::new(store, directory))?;
                Ok((catalog, identity.clone(), history, current))
            },
        )?;
        // Full catalog/PAM/history reads may block. Project from the SAME live
        // producer/keeper generation again after those reads, not from the
        // interval returned before semantic replay completed.
        *stage = crate::policy_decisions::Reason::UtcUnavailable;
        let final_observation = client.recheck(&history, &observation)?;
        *stage = crate::policy_decisions::Reason::CredentialsExpired;
        let principal = identity["principal"]
            .as_str()
            .ok_or("finite grant subject is missing")?;
        let credential_refusal = if let Some(day) = catalog.password_day(principal) {
            if password_window(
                day,
                self.session
                    .binding
                    .password_epoch
                    .as_ref()
                    .ok_or("finite grant actor lacks its original protected password epoch")?,
                &final_observation,
            )
            .is_err()
            {
                Some(crate::policy_decisions::Reason::CredentialsExpired)
            } else {
                None
            }
        } else if self.session.binding.password_epoch.is_some() {
            Some(crate::policy_decisions::Reason::CredentialsExpired)
        } else {
            None
        };
        Ok(GrantCapture {
            catalog,
            identity,
            head: self.session.binding.checkpoint_head.clone(),
            observation: final_observation,
            credential_refusal,
        })
    }
}

/// Protected local-terminal composition. Root is an execution prerequisite,
/// never the subject or grant authority; genuine PAM establishes the subject.
pub(crate) fn with_grant<T>(
    login: &str,
    grant_id: &str,
    usage: &crate::finite_grants::Use,
    effect: impl FnOnce(&mut GrantBoundary<'_>) -> Result<T>,
) -> Result<T> {
    with_grants(login, &[(grant_id.into(), usage.clone())], effect)
}

pub(crate) fn with_grants<T>(
    login: &str,
    uses: &[(String, crate::finite_grants::Use)],
    effect: impl FnOnce(&mut GrantBoundary<'_>) -> Result<T>,
) -> Result<T> {
    crate::require_root()?;
    platform::require_installed()?;
    if uses.is_empty() || uses.len() > 64 {
        return Err("finite operation needs one to 64 exact grant scopes".into());
    }
    let mut identities = BTreeSet::new();
    for (grant_id, usage) in uses {
        usage.validate()?;
        if !admin_roles::identifier(grant_id) || !identities.insert(grant_id) {
            return Err("invalid or duplicate exact grant identifier".into());
        }
    }
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let mut operation = crate::policy_decisions::Operation::begin(
        crate::policy_decisions::Store::installed()?,
        uses,
    )?;
    let prepared = (|| {
        let attempt = {
            let mut store = Store::open(
                tpm::LocalAnchor::installed()?,
                &directory.join("journal.json"),
            )?;
            PrincipalLogin::prepare(&mut PrincipalReader::new(&mut store, directory), login)?
        };
        let account = match authentication::local(login) {
            Ok(value) => value,
            Err(error) => {
                operation.decisions(
                    uses.iter()
                        .map(|(grant, usage)| {
                            crate::policy_decisions::Decision::unavailable(
                                grant,
                                usage,
                                crate::policy_decisions::Reason::AuthenticationUnavailable,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?,
                )?;
                return Err(error);
            }
        };
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        let session = PrincipalSession::new(
            account,
            attempt,
            &mut PrincipalReader::new(&mut store, directory),
        )?;
        drop(store);
        Ok(session)
    })();
    let session = match prepared {
        Ok(value) => value,
        Err(error) => {
            operation.decisions(
                uses.iter()
                    .map(|(grant, usage)| {
                        crate::policy_decisions::Decision::unavailable(
                            grant,
                            usage,
                            crate::policy_decisions::Reason::PrincipalUnavailable,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?,
            )?;
            operation.finish(crate::policy_decisions::OperationOutcome::Denied)?;
            return Err(error);
        }
    };
    let client = match crate::utc_provider::Client::installed() {
        Ok(value) => value,
        Err(error) => {
            operation.decisions(
                uses.iter()
                    .map(|(grant, usage)| {
                        crate::policy_decisions::Decision::unavailable(
                            grant,
                            usage,
                            crate::policy_decisions::Reason::UtcUnavailable,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?,
            )?;
            operation.finish(crate::policy_decisions::OperationOutcome::Denied)?;
            return Err(error);
        }
    };
    let mut boundary = GrantBoundary {
        session: &session,
        directory,
        registry_path,
        client,
        uses: uses.to_vec(),
        operation,
        decision_ids: Vec::new(),
        observation: None,
        capture_reason: crate::policy_decisions::Reason::PrincipalUnavailable,
        fenced: false,
    };
    if let Err(error) = boundary.check() {
        boundary
            .operation
            .finish(crate::policy_decisions::OperationOutcome::Denied)?;
        return Err(error);
    }
    let result = effect(&mut boundary);
    match result {
        Ok(value) => {
            if let Err(error) = boundary.check() {
                boundary
                    .operation
                    .finish(crate::policy_decisions::OperationOutcome::Uncertain)?;
                return Err(error);
            }
            boundary
                .operation
                .finish(crate::policy_decisions::OperationOutcome::Completed)?;
            Ok(value)
        }
        Err(error) => {
            boundary
                .operation
                .finish(crate::policy_decisions::OperationOutcome::Uncertain)?;
            Err(error)
        }
    }
}

/// Legacy qualification entrypoints are not alternate product effect routes.
/// Missing/uncertain history refuses; only the exact enrolled, empty pre-
/// bootstrap journal can enter the explicitly non-product laboratory path.
pub(crate) fn reject_laboratory_effects_after_bootstrap() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let snapshot = store.snapshot()?;
    let context = Context::load(directory, &snapshot.deployment)?;
    let (_, bootstrapped) = context.state(&snapshot, None)?;
    let final_snapshot = store.snapshot()?;
    final_snapshot.clock.elapsed_since(snapshot.clock)?;
    if final_snapshot.head != snapshot.head
        || final_snapshot.deployment != snapshot.deployment
        || tpm::private_read(&directory.join("enrollment.json"), 16384)? != context.enrollment
    {
        return Err("laboratory mode authority changed during inspection".into());
    }
    if bootstrapped || !snapshot.entries.is_empty() || context.existing()?.is_some() {
        return Err(
            "unscoped laboratory effects are unavailable after product Admin bootstrap".into(),
        );
    }
    Ok(())
}

pub fn principal_check(login: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let directory = Path::new(DIRECTORY);
    // Do not hold the journal/TPM writer locks while a human enters a password.
    // The retained binding is checked again, never refreshed to a newer head.
    let attempt = {
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        PrincipalLogin::prepare(&mut PrincipalReader::new(&mut store, directory), login)?
    };
    let account = authentication::local(login)?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let mut reader = PrincipalReader::new(&mut store, directory);
    let session = PrincipalSession::new(account, attempt, &mut reader)?;
    let identity = session.identity(&mut reader)?;
    let credentials_checkpointed = session.binding.credential_sha256.is_some();
    session.close();
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"action":"governed-principal-check",
        "principal":identity,"authentication_current":true,"session_returned":false,
        "account_credentials_checkpointed":credentials_checkpointed,
        "role_grant":false,"effect_grant":false,"gate_closing":false})
    );
    Ok(())
}

/// A replayed floor binding, not a saved estimate or an authority token. Only
/// the shared Admin semantic reader can construct it; it has no wire form.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoryBinding {
    deployment: String,
    enrollment_sha256: String,
    principal: Identity,
    checkpoint_head: String,
    history_floor_ms: i64,
    history_version: u64,
    reset_count: u32,
    restart_count: u32,
}

#[cfg_attr(not(test), allow(dead_code))]
impl HistoryBinding {
    pub(crate) fn floor_ms(&self) -> i64 {
        self.history_floor_ms
    }

    pub(crate) fn recheck<A: Checkpoint>(&self, reader: &mut HistoryReader<'_, A>) -> Result<()> {
        if reader.read()? != *self {
            return Err("UTC shared history binding changed; reconstruct explicitly".into());
        }
        Ok(())
    }
}

/// Borrow the Admin owner's existing store. This does not provision another
/// anchor, export TPM credentials to a keeper daemon, authenticate a human or
/// approve runtime provenance. The eventual protected composition owns it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct HistoryReader<'a, A: Checkpoint> {
    store: &'a mut Store<A>,
    directory: &'a Path,
    last_clock: Option<tpm::Clock>,
    fenced: bool,
    candidate: Option<&'a str>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<'a, A: Checkpoint> HistoryReader<'a, A> {
    pub(crate) fn new(store: &'a mut Store<A>, directory: &'a Path) -> Self {
        Self {
            store,
            directory,
            last_clock: None,
            fenced: false,
            candidate: None,
        }
    }

    pub(crate) fn for_candidate(
        store: &'a mut Store<A>,
        directory: &'a Path,
        request: &'a str,
    ) -> Result<Self> {
        if !admin_roles::identifier(request) || request == REQUEST {
            return Err("invalid UTC history candidate".into());
        }
        Ok(Self {
            candidate: Some(request),
            ..Self::new(store, directory)
        })
    }

    pub(crate) fn read(&mut self) -> Result<HistoryBinding> {
        if self.fenced {
            return Err("UTC history reader is fenced; reconstruct explicitly".into());
        }
        let result = (|| {
            let (before, first_clock) = self.replay()?;
            if let Some(previous) = self.last_clock {
                first_clock.elapsed_since(previous)?;
            }
            // Re-read ALL semantic payloads after the first potentially blocking
            // replay. A matching journal head alone cannot authenticate them.
            let (after, last_clock) = self.replay()?;
            last_clock.elapsed_since(first_clock)?;
            if before != after {
                return Err("UTC history changed during replay".into());
            }
            self.last_clock = Some(last_clock);
            Ok(after)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn replay(&mut self) -> Result<(HistoryBinding, tpm::Clock)> {
        let snapshot = self.store.snapshot()?;
        let context = Context::load(self.directory, &snapshot.deployment)?;
        if !context.bootstrap_state(&snapshot)?.1 {
            return Err("explicit product Admin bootstrap required for UTC history read".into());
        }
        let (history, _) = context.history(&snapshot, self.candidate)?;
        // The retained identity identifies the historical writer only. It is
        // deliberately NOT substituted for current PAM/effect authorization.
        if tpm::private_read(&self.directory.join("enrollment.json"), 16384)? != context.enrollment
        {
            return Err("UTC history enrollment changed during replay".into());
        }
        let final_snapshot = self.store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if final_snapshot.head != snapshot.head || final_snapshot.deployment != snapshot.deployment
        {
            return Err("UTC checkpoint changed during semantic replay".into());
        }
        Ok((
            HistoryBinding {
                deployment: context.deployment,
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                principal: context.principal,
                checkpoint_head: snapshot.head,
                history_floor_ms: history.floor_ms,
                history_version: history.version,
                reset_count: final_snapshot.clock.reset_count,
                restart_count: final_snapshot.clock.restart_count,
            },
            final_snapshot.clock,
        ))
    }
}

fn utc_input<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    use std::io::Read;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > 16_384 {
        return Err("UTC input must be a bounded regular JSON file".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(16_385).read_to_end(&mut bytes)?;
    use std::os::unix::fs::MetadataExt;
    let same = |a: &fs::Metadata, b: &fs::Metadata| {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    };
    if bytes.len() as u64 != before.len()
        || !same(&before, &file.metadata()?)
        || !same(&before, &fs::symlink_metadata(path)?)
    {
        return Err("UTC input changed during review".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) struct SeedCustody<'a> {
    credential: &'a crate::admin_recovery::Credential,
    verifier: crate::admin_recovery::Verifier,
    registry: crate::principal::RegistryBinding,
    store: std::cell::RefCell<Store<tpm::LocalAnchor>>,
    catalog: Catalog,
    enrollment: Vec<u8>,
    binding: HistoryBinding,
    clock: std::cell::Cell<tpm::Clock>,
    lifetime: authentication::ProtectedOperation,
}
impl<'a> SeedCustody<'a> {
    fn installed(credential: &'a crate::admin_recovery::Credential) -> Result<Self> {
        let directory = Path::new(DIRECTORY);
        let registry =
            crate::principal::RegistryBinding::capture(Path::new(crate::principal::REGISTRY))?;
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        let snapshot = store.snapshot()?;
        let context = Context::load(directory, &snapshot.deployment)?;
        if !context.state(&snapshot, None)?.1 {
            return Err("offline seed custody requires original Admin bootstrap".into());
        }
        let catalog = context.events(&snapshot, None)?.0;
        let writer = context.custody_writer(&catalog)?;
        if registry.current()? != catalog.registry()? {
            return Err("offline seed custody registry changed".into());
        }
        let verifier = catalog.recovery_verifier()?.clone();
        verifier.validate(&writer.installation, &writer.principal)?;
        verifier.verify(credential)?;
        let binding = HistoryReader::new(&mut store, directory).read()?;
        let final_snapshot = store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if snapshot.head != final_snapshot.head
            || context.events(&final_snapshot, None)?.0 != catalog
        {
            return Err("offline seed authority changed during verification".into());
        }
        let result = Self {
            credential,
            verifier,
            registry,
            store: std::cell::RefCell::new(store),
            catalog,
            enrollment: context.enrollment,
            binding,
            clock: std::cell::Cell::new(final_snapshot.clock),
            lifetime: authentication::ProtectedOperation::start()?,
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        self.registry.current()?;
        let mut store = self.store.borrow_mut();
        let snapshot = store.snapshot()?;
        snapshot.clock.elapsed_since(self.clock.get())?;
        self.clock.set(snapshot.clock);
        let context = Context::load(Path::new(DIRECTORY), &snapshot.deployment)?;
        let catalog = context.events(&snapshot, None)?.0;
        if snapshot.head != self.binding.checkpoint_head
            || context.enrollment != self.enrollment
            || catalog != self.catalog
            || catalog.recovery_verifier()? != &self.verifier
            || catalog.registry()? != self.registry.current()?
        {
            return Err("offline seed custody no longer binds exact current authority".into());
        }
        context.custody_writer(&catalog)?;
        self.verifier.verify(self.credential)?;
        self.binding
            .recheck(&mut HistoryReader::new(&mut *store, Path::new(DIRECTORY)))?;
        self.registry.current()?;
        self.verifier.verify(self.credential)
    }
    pub(crate) fn observe<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.lifetime.within(|| {
            self.recheck()?;
            let result = operation()?;
            self.recheck()?;
            Ok(result)
        })
    }
}

pub(crate) fn utc_seed_recovery_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let commit = if args.len() == 2 {
        None
    } else if args.len() == 5 && args[2] == "--commit" {
        Some((&args[3], &args[4]))
    } else {
        return Err("expected utc-seed-recovery SEED-FILE [--commit KEEPER-INSTANCE REVIEW-SHA256]; current offline credential is terminal-only".into());
    };
    let seed: crate::utc_provider::Seed = utc_input(&args[1])?;
    let credential = crate::admin_recovery::Credential::read()?;
    let custody = SeedCustody::installed(&credential)?;
    let result = if let Some((instance, reviewed)) = commit {
        let delivered = crate::utc_provider::deliver_seed_custody(
            &custody,
            &custody.binding,
            &seed,
            instance,
            reviewed,
        );
        custody.lifetime.close();
        delivered?;
        serde_json::json!({"schema_version":1,"instance":instance,"seed_delivered":true,
            "custody_verified":true,"timed_authority":false,"admin_password_changed":false,
            "effect_grant":false,"automatic_retry":false})
    } else {
        custody.observe(|| crate::utc_provider::seed_proposal(&custody.binding, &seed))?
    };
    println!("{result}");
    Ok(())
}

/// Only the current original Admin can deliver an independently reviewed seed.
/// The shared history is held and rechecked throughout; the seed is not time
/// authority and does not append to the checkpoint or activate a grant.
pub(crate) fn utc_seed_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let commit = if args.len() == 3 {
        None
    } else if args.len() == 6 && args[3] == "--commit" {
        Some((&args[4], &args[5]))
    } else {
        return Err(
            "expected utc-seed LOGIN SEED-FILE [--commit KEEPER-INSTANCE REVIEW-SHA256]".into(),
        );
    };
    let seed: crate::utc_provider::Seed = utc_input(&args[2])?;
    let prepared = prepare_seed_control(&args[1], None)?;
    let account = authentication::local(&args[1])?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(
        account,
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        None,
    )?;
    let result = session.observe_store(
        &mut PrincipalReader::seed_at(
            &mut store,
            directory,
            Path::new(crate::principal::REGISTRY),
            None,
        ),
        |identity, store| {
            let snapshot = store.snapshot()?;
            let context = Context::load(directory, &snapshot.deployment)?;
            let catalog = context.events(&snapshot, None)?.0;
            if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                return Err("seed delivery requires the current original Admin".into());
            }
            let binding = HistoryReader::new(store, directory).read()?;
            let result = if let Some((instance, reviewed)) = commit {
                crate::utc_provider::deliver_seed(
                    &session.account,
                    &binding,
                    &seed,
                    instance,
                    reviewed,
                )?;
                serde_json::json!({"schema_version":1,"instance":instance,
                "seed_delivered":true,"timed_authority":false,"automatic_retry":false})
            } else {
                crate::utc_provider::seed_proposal(&binding, &seed)?
            };
            binding.recheck(&mut HistoryReader::new(store, directory))?;
            Ok(result)
        },
    )?;
    println!("{result}");
    Ok(())
}

pub(crate) fn utc_query_command(login: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let directory = Path::new(DIRECTORY);
    let attempt = {
        let mut store = Store::open(
            tpm::LocalAnchor::installed()?,
            &directory.join("journal.json"),
        )?;
        PrincipalLogin::prepare(&mut PrincipalReader::new(&mut store, directory), login)?
    };
    let account = authentication::local(login)?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = PrincipalSession::new(
        account,
        attempt,
        &mut PrincipalReader::new(&mut store, directory),
    )?;
    let result = session.observe_store(
        &mut PrincipalReader::new(&mut store, directory),
        |_, store| {
            let binding = HistoryReader::new(store, directory).read()?;
            let mut client = crate::utc_provider::Client::installed()?;
            let observation = client.current(&binding)?;
            binding.recheck(&mut HistoryReader::new(store, directory))?;
            let observation = client.recheck(&binding, &observation)?;
            let (lower, upper) = observation.interval().endpoints();
            Ok(
                serde_json::json!({"statement":observation.context(),"earliest_ms":lower,
            "latest_ms":upper,"serialized_time_authority":false}),
            )
        },
    )?;
    println!("{result}");
    Ok(())
}

pub(crate) fn utc_reacquire_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let commit = if args.len() == 2 {
        None
    } else if args.len() == 5 && args[2] == "--commit" {
        Some((&args[3], &args[4]))
    } else {
        return Err("expected utc-reacquire LOGIN [--commit KEEPER-INSTANCE REVIEW-SHA256]".into());
    };
    let prepared = prepare_seed_control(&args[1], None)?;
    let account = authentication::local(&args[1])?;
    let directory = Path::new(DIRECTORY);
    let registry = Path::new(crate::principal::REGISTRY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(account, &mut store, directory, registry, None)?;
    let result = session.observe_store(&mut PrincipalReader::seed_at(&mut store, directory, registry, None), |identity, store| {
        let snapshot = store.snapshot()?;
        let context = Context::load(directory, &snapshot.deployment)?;
        let catalog = context.events(&snapshot, None)?.0;
        if serde_json::to_value(context.writer(&catalog)?)? != *identity {
            return Err("UTC reacquisition requires the current original Admin".into());
        }
        let binding = HistoryReader::new(store, directory).read()?;
        let result = if let Some((instance, reviewed)) = commit {
            crate::utc_provider::reacquire_admin(&session.account, &binding, instance, reviewed)?;
            serde_json::json!({"utc_reacquisition_dispatched":true,"fresh_independent_seed_required":true,
                "timed_authority":false,"automatic_retry":false})
        } else { crate::utc_provider::reacquire_proposal(&binding)? };
        binding.recheck(&mut HistoryReader::new(store, directory))?;
        Ok(result)
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn utc_reacquire_recovery_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let commit = if args.len() == 1 {
        None
    } else if args.len() == 4 && args[1] == "--commit" {
        Some((&args[2], &args[3]))
    } else {
        return Err("expected utc-reacquire-recovery [--commit KEEPER-INSTANCE REVIEW-SHA256]; custody credential is terminal-only".into());
    };
    let credential = crate::admin_recovery::Credential::read()?;
    let custody = SeedCustody::installed(&credential)?;
    let result = if let Some((instance, reviewed)) = commit {
        let dispatched =
            crate::utc_provider::reacquire_custody(&custody, &custody.binding, instance, reviewed);
        custody.lifetime.close();
        dispatched?;
        serde_json::json!({"utc_reacquisition_dispatched":true,"fresh_independent_seed_required":true,
            "custody_verified":true,"timed_authority":false,"automatic_retry":false})
    } else {
        custody.observe(|| crate::utc_provider::reacquire_proposal(&custody.binding))?
    };
    println!("{result}");
    Ok(())
}

pub(crate) fn utc_history_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let reviewed = if args.len() == 4 {
        None
    } else if args.len() == 6 && args[4] == "--commit" {
        Some(args[5].as_str())
    } else {
        return Err(
            "expected utc-history LOGIN REQUEST STATEMENT-FILE [--commit REVIEW-SHA256]".into(),
        );
    };
    let statement: Statement = utc_input(&args[3])?;
    let request = &args[2];
    let prepared = prepare_control(&args[1], Some(request))?;
    let account = authentication::local(&args[1])?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(
        account,
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        Some(request),
    )?;
    session.identity(&mut PrincipalReader::admin_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        Some(request),
    ))?;
    let binding = HistoryReader::for_candidate(&mut store, directory, request)?.read()?;
    let mut client = crate::utc_provider::Client::installed()?;
    let result = execute_history_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        || session.account.identity(),
        |proposed| proposed.supported_by(&client.current(&binding)?),
        request,
        &statement,
        reviewed,
    )?;
    // No old client or PAM session survives this command. Any successful append
    // changes the shared head; a later command must explicitly bind it anew.
    println!("{result}");
    Ok(())
}

/// Internal delivery from the admitted stream and a real current PAM account.
/// The Store is the existing exclusive journal writer, not a second UTC owner.
/// There is still no human-control listener or seed acceptance in this adapter.
#[allow(dead_code)]
pub(crate) fn execute_history_live<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    account: &authentication::AuthenticatedAccount,
    stream: &mut crate::utc_stream::BoundStream,
    request: &str,
    statement: &Statement,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    let result = (|| {
        crate::require_root()?;
        platform::require_installed()?;
        let binding = HistoryReader::new(store, directory).read()?;
        execute_history_at(
            store,
            directory,
            Path::new(crate::principal::REGISTRY),
            || account.identity(),
            |proposed| stream.history_delivery(&binding)?.support(proposed),
            request,
            statement,
            reviewed,
        )
    })();
    // A new checkpoint is a generation boundary. Errors may follow an uncertain
    // TPM dispatch; neither case permits reuse of the previous stream binding.
    if result
        .as_ref()
        .map_or(true, |receipt| receipt["tpm_write_performed"] == true)
    {
        stream.invalidate();
    }
    result
}

// Arbitrary authentication/source callbacks exist only in isolated fixtures.
#[cfg(test)]
fn execute_history<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    authenticate: impl FnMut() -> Result<serde_json::Value>,
    observe: impl FnMut(&Statement) -> Result<()>,
    request: &str,
    statement: &Statement,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    execute_history_at(
        store,
        directory,
        Path::new(crate::principal::REGISTRY),
        authenticate,
        observe,
        request,
        statement,
        reviewed,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn execute_history_at<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    mut authenticate: impl FnMut() -> Result<serde_json::Value>,
    mut observe: impl FnMut(&Statement) -> Result<()>,
    request: &str,
    statement: &Statement,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved UTC history request".into());
    }
    statement.validate()?;
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit product Admin bootstrap required for UTC history".into());
    }
    let (history, records) = context.history(&snapshot, Some(request))?;
    let (catalog, _) = context.events(&snapshot, Some(request))?;
    let writer = context.writer(&catalog)?;
    context.recheck(&mut authenticate)?;
    let old = records.iter().find(|record| record.request_id == request);
    let replayed = old.is_some();
    let (record, changed) = if let Some(old) = old {
        if &old.statement != statement {
            return Err("UTC request already binds a different floor/context".into());
        }
        (old.clone(), false)
    } else {
        if snapshot
            .entries
            .iter()
            .any(|entry| entry.request_id == request)
        {
            return Err("Admin request belongs to another semantic activity".into());
        }
        if statement.floor_ms < history.floor_ms {
            return Err("UTC history floor regression refused".into());
        }
        observe(statement)?;
        (
            HistoryRecord {
                schema_version: 1,
                kind: "native-admin-utc-history".into(),
                deployment: context.deployment.clone(),
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                principal: writer,
                request_id: request.into(),
                sequence: snapshot.entries.len() + 1,
                previous_head: snapshot.head.clone(),
                history_version_before: history.version,
                previous_floor_ms: history.floor_ms,
                statement: statement.clone(),
            },
            statement.floor_ms > history.floor_ms,
        )
    };
    let bytes = serde_json::to_vec(&record)?;
    let path = directory.join(event_name(request));
    let retained = match fs::symlink_metadata(&path) {
        Ok(_) => Some(utc_history::read(&path, request)?.1),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if retained.as_ref().is_some_and(|old| old != &bytes) {
        return Err("different retained UTC history proposal; preserve state".into());
    }
    if retained.is_some() && !replayed && !changed {
        return Err("retained UTC no-op requires reconciliation".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-native-admin-utc-history-review-v1\0");
    digest.update(serde_json::to_vec(
        &serde_json::json!({"record":record,"head":snapshot.head,
        "replayed":replayed,"changed":changed,"reset_count":snapshot.clock.reset_count,
        "restart_count":snapshot.clock.restart_count}),
    )?);
    let digest = bundle::hex(&digest.finalize());
    let mut written = false;
    if let Some(approved) = reviewed {
        tpm::decode::<32>(approved)?;
        if approved != digest {
            return Err("UTC history review changed; inspect again".into());
        }
        if changed {
            // Never prepare disk state on the strength of a caller's floor.
            observe(statement)?;
            context.recheck(&mut authenticate)?;
            observe(statement)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                Err(error) => return Err(error.into()),
            }
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?
                .sync_all()?;
            File::open(directory)?.sync_all()?;
            let entry = Entry {
                request_id: request.into(),
                authenticated_uid: context.principal.uid,
                clock: snapshot.clock,
                activity: utc_history::ACTIVITY.into(),
                payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
            };
            store.append(entry.clone(), |proposed| {
                if proposed != &entry {
                    return Err("UTC history entry changed before commit".into());
                }
                // Renew the live observation on every journal writer boundary.
                // It may block; re-read semantic inputs after it, then renew PAM.
                observe(statement)?;
                if utc_history::read(&path, request)?.1 != bytes
                    || !context.state(&snapshot, Some(request))?.1
                    || context.history(&snapshot, Some(request))?.0 != history
                    || context.events(&snapshot, Some(request))?.0 != catalog
                {
                    return Err("UTC history inputs changed before TPM dispatch".into());
                }
                context.recheck(&mut authenticate)?;
                // Semantic replay and PAM may block. Renew the actual source
                // after them, at the final writer authorization boundary.
                observe(statement)
            })?;
            written = true;
        }
    }
    let final_snapshot = store.snapshot()?;
    context.state(&final_snapshot, Some(request))?;
    let (current, _) = context.history(&final_snapshot, Some(request))?;
    if written && (current.floor_ms != statement.floor_ms || current.version != history.version + 1)
    {
        return Err("committed UTC history differs from proposal".into());
    }
    context.recheck(&mut authenticate)?;
    Ok(
        serde_json::json!({"schema_version":1,"action":"admin-utc-history-source-transaction",
        "proposal":record,"review_sha256":digest,"history_floor_ms":current.floor_ms,
        "history_version":current.version,"committed":reviewed.is_some() && (written || replayed),
        "replayed":replayed,"no_change":!changed && !replayed,"tpm_write_performed":written,
        "trusted_utc_available":false,"effect_grant":false,"delegation_available":false,"gate_closing":false}),
    )
}

fn review(snapshot: &Snapshot, payload: &Bootstrap, active: bool) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"luma-native-admin-bootstrap-review-v1\0");
    hash.update(serde_json::to_vec(&serde_json::json!({"payload":payload,
        "head":snapshot.head,"active":active,"reset_count":snapshot.clock.reset_count,
        "restart_count":snapshot.clock.restart_count}))?);
    Ok(bundle::hex(&hash.finalize()))
}

// The only product entry point below supplies a fresh, non-deserializable PAM
// observation. Arbitrary JSON, caller UID and the retained payload are not an
// authenticator. Keep this semantic adapter private, including its test seam.
fn execute<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    mut authenticate: impl FnMut() -> Result<serde_json::Value>,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    let snapshot = store.snapshot()?;
    let context = Context::load(directory, &snapshot.deployment)?;
    context.recheck(&mut authenticate)?;
    let (payload, active) = context.state(&snapshot, None)?;
    let digest = review(&snapshot, &payload, active)?;
    let mut replayed = false;
    if let Some(approved) = reviewed {
        tpm::decode::<32>(approved)?;
        if approved != digest {
            return Err("Admin bootstrap review does not match current state and TPM epoch".into());
        }
        if active {
            replayed = true;
        } else {
            context.recheck(&mut authenticate)?;
            let bytes = context.prepare(&payload)?;
            let entry = Entry {
                request_id: REQUEST.into(),
                authenticated_uid: context.principal.uid,
                clock: snapshot.clock,
                activity: ACTIVITY.into(),
                payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
            };
            store.append(entry.clone(), |proposed| {
                if proposed != &entry
                    || context.existing()?.ok_or("missing bootstrap payload")?.1 != bytes
                {
                    return Err("Admin bootstrap entry or payload changed before commit".into());
                }
                context.recheck(&mut authenticate)
            })?;
        }
    }
    let final_snapshot = store.snapshot()?;
    let (_, final_active) = context.state(&final_snapshot, None)?;
    let (catalog, _) = context.events(&final_snapshot, None)?;
    let principal = context.writer(&catalog)?;
    // A receipt is not a reusable authenticated session. Recheck freshness and
    // live principal/account state before reporting a successful observation.
    context.recheck(&mut authenticate)?;
    Ok(
        serde_json::json!({"schema_version":1,"action":"admin-bootstrap",
        "principal":principal,"review_sha256":digest,
        "product_admin_active":final_active,"replayed":replayed,
        "tpm_write_performed":reviewed.is_some() && !active,
        "checkpoint_head":final_snapshot.head,"delegation_available":false,
        "effect_grant":false,"production_custody_verified":false,"gate_closing":false}),
    )
}

pub fn bootstrap(login: &str, reviewed: Option<&str>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let authenticated = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let report = execute(&mut store, directory, || authenticated.identity(), reviewed)?;
    authenticated.logout();
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

enum CatalogAuthority<'a, 's> {
    Governed(&'a CatalogAttempt<'s>),
    Recovery(&'a RecoveryAttempt<'s>),
    #[cfg(test)]
    Primitive,
}

fn admin_account_recovery(command: &Command) -> bool {
    matches!(
        command,
        Command::PrepareAdminAccountRecovery { .. }
            | Command::PermitAdminAccountRecovery { .. }
            | Command::CompleteAdminAccountRecovery { .. }
    )
}

struct AccountTime {
    client: crate::utc_provider::Client,
    binding: HistoryBinding,
    day: u32,
}

type PasswordEpoch = (String, String, u64, u64, u64);

fn password_epoch(live: &crate::utc_stream::Observation) -> PasswordEpoch {
    let context = live.context();
    (
        context.runtime_sha256.clone(),
        context.boot_id.clone(),
        context.process_generation,
        context.source_clock_generation,
        context.keeper_generation,
    )
}

fn password_window(
    day: u32,
    expected: &PasswordEpoch,
    live: &crate::utc_stream::Observation,
) -> Result<()> {
    live.context().validate()?;
    let start = i64::from(day)
        .checked_mul(86_400_000)
        .ok_or("password age overflow")?;
    let end = i64::from(day)
        .checked_add(90)
        .and_then(|value| value.checked_mul(86_400_000))
        .ok_or("password age overflow")?;
    if day == 0 || &password_epoch(live) != expected || !live.interval().within(start, end)? {
        return Err(
            "acting principal password expired or its protected UTC generation changed".into(),
        );
    }
    Ok(())
}

struct ActorAging {
    client: crate::utc_provider::Client,
    history: HistoryBinding,
    day: u32,
    epoch: PasswordEpoch,
}
impl ActorAging {
    fn capture<A: Checkpoint>(
        session: &PrincipalSession,
        catalog: &Catalog,
        store: &mut Store<A>,
        directory: &Path,
        request: &str,
    ) -> Result<Option<Self>> {
        if session.fenced.get() {
            return Err("aged actor session is fenced".into());
        }
        let principal = session.binding.identity["principal"]
            .as_str()
            .ok_or("missing actor principal")?;
        let Some(day) = catalog.password_day(principal) else {
            if session.binding.password_epoch.is_some() {
                return Err("acting principal aging authority disappeared".into());
            }
            return Ok(None);
        };
        let epoch = session
            .binding
            .password_epoch
            .clone()
            .ok_or("acting principal lacks its original protected UTC epoch")?;
        let history = HistoryReader::for_candidate(store, directory, request)?.read()?;
        let mut actor = Self {
            client: crate::utc_provider::Client::installed()?,
            history,
            day,
            epoch,
        };
        actor.recheck()?;
        actor.history.recheck(&mut HistoryReader::for_candidate(
            store, directory, request,
        )?)?;
        if session.fenced.get() {
            return Err("aged actor session was fenced during reconstruction".into());
        }
        actor.recheck()?;
        Ok(Some(actor))
    }
    fn recheck(&mut self) -> Result<()> {
        password_window(self.day, &self.epoch, &self.client.current(&self.history)?)
    }
}
impl AccountTime {
    fn capture<A: Checkpoint>(
        store: &mut Store<A>,
        directory: &Path,
        day: u32,
        request: &str,
    ) -> Result<Self> {
        let mut reader = HistoryReader::for_candidate(store, directory, request)?;
        let binding = reader.read()?;
        let mut result = Self {
            client: crate::utc_provider::Client::installed()?,
            binding,
            day,
        };
        result.recheck()?;
        result.binding.recheck(&mut reader)?;
        Ok(result)
    }
    fn recheck(&mut self) -> Result<()> {
        let live = self.client.current(&self.binding)?;
        let (lower, upper) = live.interval().endpoints();
        if lower <= 0 || lower < i64::from(self.day) * 86_400_000 || upper < lower {
            return Err("current protected UTC precedes the exact recorded credential day".into());
        }
        Ok(())
    }
}

fn account_day(catalog: &Catalog, command: &Command) -> Option<u32> {
    let intent = match command {
        Command::PrepareAccountLock { intent }
        | Command::PrepareAdminAccountRecovery { intent, .. } => intent,
        Command::PermitAccountPublication { transaction }
        | Command::CompleteAccountLock { transaction }
        | Command::PermitAdminAccountRecovery { transaction }
        | Command::CompleteAdminAccountRecovery { transaction } => {
            &catalog.account_transitions.get(transaction)?.intent
        }
        _ => return None,
    };
    match &intent.kind {
        Some(
            crate::account_transition::Kind::Activation { day, .. }
            | crate::account_transition::Kind::AdminRecovery { day, .. }
            | crate::account_transition::Kind::Renewal { day, .. },
        ) => Some(*day),
        _ => None,
    }
}

/// The original Admin's catalog-scoped, pre-PAM login. It cannot be supplied
/// through JSON, reused as a general-principal login or used as an effect grant.
pub(crate) struct AdminLogin {
    login: PrincipalLogin,
    candidate: Option<String>,
    seed_only: bool,
}

impl AdminLogin {
    fn prepare_at<A: Checkpoint>(
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        name: &str,
        candidate: Option<&str>,
    ) -> Result<Self> {
        if candidate.is_some_and(|request| !admin_roles::identifier(request) || request == REQUEST)
        {
            return Err("invalid catalog login request".into());
        }
        let login = PrincipalLogin::prepare(
            &mut PrincipalReader::admin_at(store, directory, registry_path, candidate),
            name,
        )?;
        Ok(Self {
            login,
            candidate: candidate.map(str::to_owned),
            seed_only: false,
        })
    }

    fn issue<A: Checkpoint>(
        self,
        account: authentication::AuthenticatedAccount,
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        candidate: Option<&str>,
    ) -> Result<PrincipalSession> {
        if self.candidate.as_deref() != candidate {
            account.logout();
            return Err("catalog login cannot switch its requested operation".into());
        }
        PrincipalSession::new(
            account,
            self.login,
            &mut if self.seed_only {
                PrincipalReader::seed_at(store, directory, registry_path, candidate)
            } else {
                PrincipalReader::admin_at(store, directory, registry_path, candidate)
            },
        )
    }
}

fn prepare_control(name: &str, candidate: Option<&str>) -> Result<AdminLogin> {
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    AdminLogin::prepare_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        name,
        candidate,
    )
}

fn prepare_seed_control(name: &str, candidate: Option<&str>) -> Result<AdminLogin> {
    if candidate.is_some_and(|request| !admin_roles::identifier(request) || request == REQUEST) {
        return Err("invalid seed-only request".into());
    }
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let login = PrincipalLogin::prepare(
        &mut PrincipalReader::seed_at(
            &mut store,
            directory,
            Path::new(crate::principal::REGISTRY),
            candidate,
        ),
        name,
    )?;
    Ok(AdminLogin {
        login,
        candidate: candidate.map(str::to_owned),
        seed_only: true,
    })
}

pub(crate) fn prepare_service(
    name: &str,
    candidate: Option<&str>,
    peer: &crate::admin_service::Peer,
) -> Result<AdminLogin> {
    peer.observe(|| prepare_control(name, candidate))
}

struct GrantTime {
    client: crate::utc_provider::Client,
    history: HistoryBinding,
    not_before_ms: i64,
    expires_ms: i64,
}
impl GrantTime {
    fn capture<A: Checkpoint>(
        store: &mut Store<A>,
        directory: &Path,
        request: &str,
        command: &Command,
    ) -> Result<Option<Self>> {
        let (not_before_ms, expires_ms) = match command {
            Command::AssignRole { assignment } => (assignment.not_before_ms, assignment.expires_ms),
            Command::IssueGrant { grant } => (grant.not_before_ms, grant.expires_ms),
            _ => return Ok(None),
        };
        let history = HistoryReader::for_candidate(store, directory, request)?.read()?;
        let mut time = Self {
            client: crate::utc_provider::Client::installed()?,
            history,
            not_before_ms,
            expires_ms,
        };
        time.recheck()?;
        time.history.recheck(&mut HistoryReader::for_candidate(
            store, directory, request,
        )?)?;
        Ok(Some(time))
    }
    fn recheck(&mut self) -> Result<()> {
        if !self
            .client
            .current(&self.history)?
            .interval()
            .within(self.not_before_ms, self.expires_ms)?
        {
            return Err(
                "role/grant issuance is outside the entire current protected UTC interval".into(),
            );
        }
        Ok(())
    }
}

// A narrowly scoped continuation across a deliberate journal mutation. The
// session is fully replayed before construction; append independently checks
// that exact prior journal, semantic payload and live writer at every boundary.
// Do not use a normal session projection after commit: the old head is stale.
struct CatalogAttempt<'s> {
    session: &'s PrincipalSession,
    registry: crate::principal::RegistryBinding,
    directory: std::path::PathBuf,
    registry_path: std::path::PathBuf,
    request: String,
    command: Command,
    peer: Option<&'s crate::admin_service::Peer>,
    account_time: std::cell::RefCell<Option<AccountTime>>,
    grant_time: std::cell::RefCell<Option<GrantTime>>,
    actor_aging: std::cell::RefCell<Option<ActorAging>>,
}

impl<'s> CatalogAttempt<'s> {
    fn prepare<A: Checkpoint>(
        session: &'s PrincipalSession,
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        request: &str,
        command: &Command,
        peer: Option<&'s crate::admin_service::Peer>,
    ) -> Result<Self> {
        command.validate()?;
        if matches!(command, Command::RecoverAdmin { .. }) || admin_account_recovery(command) {
            return Err("catalog sessions cannot substitute for offline recovery custody".into());
        }
        match &session.binding.purpose {
            PrincipalPurpose::AdminCatalog {
                candidate: Some(candidate),
            } if candidate == request => (),
            _ => return Err("catalog continuation requires its exact Admin login scope".into()),
        }
        let mut project = || {
            session.observe_store(
                &mut PrincipalReader::admin_at(store, directory, registry_path, Some(request)),
                |identity, store| {
                    let snapshot = store.snapshot()?;
                    snapshot.clock.elapsed_since(session.clock.get())?;
                    session.clock.set(snapshot.clock);
                    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
                    let catalog = context.events(&snapshot, Some(request))?.0;
                    if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                        return Err(
                            "catalog projection differs from the original governed Admin".into(),
                        );
                    }
                    context.recheck(&mut || session.account.identity())?;
                    Ok(Self {
                        session,
                        registry: crate::principal::RegistryBinding::capture(registry_path)?,
                        directory: directory.into(),
                        registry_path: registry_path.into(),
                        request: request.into(),
                        command: command.clone(),
                        peer,
                        actor_aging: std::cell::RefCell::new(ActorAging::capture(
                            session, &catalog, store, directory, request,
                        )?),
                        grant_time: std::cell::RefCell::new(GrantTime::capture(
                            store, directory, request, command,
                        )?),
                        account_time: std::cell::RefCell::new(
                            match account_day(&catalog, command) {
                                Some(day) => {
                                    Some(AccountTime::capture(store, directory, day, request)?)
                                }
                                None => None,
                            },
                        ),
                    })
                },
            )
        };
        if let Some(peer) = peer {
            peer.observe(project)
        } else {
            project()
        }
    }

    fn authenticate(&self) -> Result<serde_json::Value> {
        if self.session.fenced.get() {
            return Err("catalog session has been closed".into());
        }
        if let Some(aging) = &mut *self.actor_aging.borrow_mut() {
            aging.recheck()?;
        }
        if let Some(time) = &mut *self.grant_time.borrow_mut() {
            time.recheck()?;
        }
        if let Some(time) = &mut *self.account_time.borrow_mut() {
            time.recheck()?;
        }
        let project = || {
            self.session.account.observe(|local| {
                self.registry.current()?;
                if let Some(aging) = &mut *self.actor_aging.borrow_mut() {
                    aging.recheck()?;
                }
                Ok(local.clone())
            })
        };
        if let Some(peer) = self.peer {
            peer.observe(project)
        } else {
            project()
        }
    }

    fn check_boundary(
        &self,
        snapshot: &Snapshot,
        directory: &Path,
        registry_path: &Path,
        request: &str,
        command: &Command,
    ) -> Result<()> {
        if directory != self.directory
            || registry_path != self.registry_path
            || request != self.request
            || command != &self.command
            || snapshot.head != self.session.binding.checkpoint_head
            || snapshot.deployment != self.session.binding.deployment
        {
            return Err(
                "catalog continuation cannot change request, command, history or installation"
                    .into(),
            );
        }
        snapshot.clock.elapsed_since(self.session.clock.get())?;
        self.session.clock.set(snapshot.clock);
        self.authenticate()?;
        Ok(())
    }

    fn execute<A: Checkpoint>(
        self,
        store: &mut Store<A>,
        reviewed: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut project = || {
            self.session.account.observe(|_| {
                execute_catalog_authorized_at(
                    store,
                    &self.directory,
                    &self.registry_path,
                    &self.session.binding.identity_path,
                    || self.authenticate(),
                    &self.request,
                    &self.command,
                    reviewed,
                    CatalogAuthority::Governed(&self),
                )
            })
        };
        let report = if let Some(peer) = self.peer {
            peer.observe(project)
        } else {
            project()
        }?;
        // The ordinary account projection must finish before replacing shadow:
        // that replacement intentionally invalidates every old account handle.
        // Keep the owned continuation and live Admin for the final dispatch;
        // never accept a returned/serialized receipt as publication authority.
        if let Command::PermitAccountPublication { transaction } = &self.command {
            if report["committed"] == true {
                let snapshot = store.snapshot()?;
                snapshot.clock.elapsed_since(self.session.clock.get())?;
                self.session.clock.set(snapshot.clock);
                let context =
                    Context::load_at(&self.directory, &snapshot.deployment, &self.registry_path)?;
                let (catalog, events) = context.events(&snapshot, None)?;
                if !events
                    .iter()
                    .any(|event| event.request_id == self.request && event.command == self.command)
                    || serde_json::to_value(context.writer(&catalog)?)?
                        != self.session.binding.identity
                {
                    return Err("account publication lacks its exact governed continuation".into());
                }
                *self.actor_aging.borrow_mut() = ActorAging::capture(
                    self.session,
                    &catalog,
                    store,
                    &self.directory,
                    &self.request,
                )?;
                let transition = catalog
                    .account_transitions
                    .get(transaction)
                    .ok_or("missing account transition")?;
                if let Some(day) = account_day(&catalog, &self.command) {
                    *self.account_time.borrow_mut() = Some(AccountTime::capture(
                        store,
                        &self.directory,
                        day,
                        &self.request,
                    )?);
                }
                if transition.phase == crate::account_transition::Phase::PublicationPermitted {
                    let boundary = account_boundary(
                        &catalog,
                        &self.registry_path,
                        &self.session.binding.identity_path,
                        &self.command,
                    )?;
                    match boundary {
                        Some(AccountBoundary::Plan(guard)) => guard.publish(|| {
                            self.authenticate()?;
                            let current = store.snapshot()?;
                            current.clock.elapsed_since(self.session.clock.get())?;
                            self.session.clock.set(current.clock);
                            if current.head != snapshot.head
                                || current.deployment != snapshot.deployment
                                || context.events(&current, None)?.0 != catalog
                            {
                                return Err("account authority changed before publication".into());
                            }
                            context.recheck(&mut || self.authenticate())
                        })?,
                        Some(AccountBoundary::Published(guard)) => guard.recheck()?,
                        None => return Err("missing protected publication boundary".into()),
                    }
                }
            }
        }
        Ok(report)
    }
}

impl Drop for CatalogAttempt<'_> {
    fn drop(&mut self) {
        self.session.close();
    }
}

fn run_control_at<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    account: authentication::AuthenticatedAccount,
    login: AdminLogin,
    peer: Option<&crate::admin_service::Peer>,
    request: &str,
    command: Option<&Command>,
    review: Option<&str>,
) -> Result<serde_json::Value> {
    let candidate = command.map(|_| request);
    let session = login.issue(account, store, directory, registry_path, candidate)?;
    if let Some(command) = command {
        let attempt = CatalogAttempt::prepare(
            &session,
            store,
            directory,
            registry_path,
            request,
            command,
            peer,
        )?;
        return attempt.execute(store, review);
    }
    if review.is_some() {
        return Err("status cannot approve a mutation".into());
    }
    let mut project = || {
        session.observe_store(&mut PrincipalReader::admin_at(store, directory, registry_path, None),
        |identity, store| {
            let snapshot = store.snapshot()?;
            snapshot.clock.elapsed_since(session.clock.get())?;
            session.clock.set(snapshot.clock);
            let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
            let catalog = context.events(&snapshot, None)?.0;
            if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                return Err("status differs from the exact governed Admin".into());
            }
            Ok(serde_json::json!({"schema_version":1,"action":"admin-governance-status",
                "principal":identity,"catalog":catalog,"checkpoint_head":snapshot.head,
                "account_credentials_checkpointed":!catalog.account_commitments.is_empty(),
                "product_admin_active":true,"delegation_available":false,"effect_grant":false,"gate_closing":false}))
        })
    };
    if let Some(peer) = peer {
        peer.observe(project)
    } else {
        project()
    }
}

fn execute_catalog_authorized_at<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    identity_path: &Path,
    mut authenticate: impl FnMut() -> Result<serde_json::Value>,
    request: &str,
    command: &Command,
    reviewed: Option<&str>,
    authority: CatalogAuthority<'_, '_>,
) -> Result<serde_json::Value> {
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved Admin request".into());
    }
    command.validate()?;
    if let Command::PrepareAccountLock { intent }
    | Command::PrepareAdminAccountRecovery { intent, .. } = command
    {
        if intent.transaction != request {
            return Err("account preparation must bind its exact request".into());
        }
    }
    if let Command::PrepareAccountDeletion { intent } = command {
        if intent.transaction != request {
            return Err("deletion preparation must bind its exact request".into());
        }
    }
    if let Command::PrepareAccountCreation { intent } = command {
        if intent.transaction != request {
            return Err("creation preparation must bind its exact request".into());
        }
    }
    let snapshot = store.snapshot()?;
    match (command, &authority) {
        (_, CatalogAuthority::Recovery(attempt))
            if command == &attempt.command && snapshot.head == attempt.head =>
        {
            snapshot.clock.elapsed_since(attempt.clock.get())?;
            attempt.clock.set(snapshot.clock);
            attempt.authenticate()?;
        }
        (Command::RecoverAdmin { .. }, _) | (_, CatalogAuthority::Recovery(_)) => {
            return Err("Admin recovery requires its exact live offline-credential proof, not PAM or caller authority".into());
        }
        (_, CatalogAuthority::Governed(attempt)) => {
            if admin_account_recovery(command) {
                return Err("Admin OS recovery requires offline custody, not PAM".into());
            }
            attempt.check_boundary(&snapshot, directory, registry_path, request, command)?;
        }
        #[cfg(test)]
        (_, CatalogAuthority::Primitive) => (),
    }
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit product Admin bootstrap required".into());
    }
    let (catalog, events) = context.events(&snapshot, Some(request))?;
    let writer = if admin_account_recovery(command) {
        context.custody_writer(&catalog)?
    } else {
        context.writer(&catalog)?
    };
    if let CatalogAuthority::Governed(attempt) = &authority {
        if serde_json::to_value(&writer)? != attempt.session.binding.identity
            || bundle::hex(&Sha256::digest(&context.enrollment))
                != attempt.session.binding.enrollment_sha256
        {
            return Err("catalog writer differs from the exact governed session".into());
        }
    }
    let registry_binding = if catalog.principal_registry.is_some()
        || matches!(command, Command::AdoptPrincipals { .. })
    {
        Some(crate::principal::RegistryBinding::capture(registry_path)?)
    } else {
        None
    };
    if let Command::AdoptPrincipals { registry } = command {
        if registry_binding
            .as_ref()
            .ok_or("missing principal registry observation")?
            .current()?
            != registry
            || !registry.binds(
                &context.principal.installation,
                &context.principal.principal,
                context.principal.generation,
                &context.principal.login,
                context.principal.uid,
            )
        {
            return Err(
                "principal adoption must bind the current installed registry and original Admin"
                    .into(),
            );
        }
    }
    let account_pins = if matches!(command, Command::CheckpointAccounts { .. }) {
        let (observed, pins) = account_checkpoint_at(registry_path, identity_path)?;
        if &observed != command {
            return Err("account checkpoint differs from protected local records".into());
        }
        pins
    } else {
        vec![]
    };
    let account_boundary = account_boundary(&catalog, registry_path, identity_path, command)?;
    let deletion_boundary = deletion_boundary(&catalog, registry_path, identity_path, command)?;
    let creation_boundary = creation_boundary(&catalog, registry_path, identity_path, command)?;
    let mut authenticate = || {
        if let Some(boundary) = &creation_boundary {
            boundary.recheck()?;
        }
        if let Some(boundary) = &deletion_boundary {
            boundary.recheck()?;
        }
        if let Some(boundary) = &account_boundary {
            boundary.recheck()?;
        }
        for account in &account_pins {
            account.current_uid()?;
        }
        if let Some(binding) = &registry_binding {
            binding.current()?;
        }
        let value = authenticate()?;
        if let Some(boundary) = &creation_boundary {
            boundary.recheck()?;
        }
        if let Some(boundary) = &deletion_boundary {
            boundary.recheck()?;
        }
        if let Some(boundary) = &account_boundary {
            boundary.recheck()?;
        }
        for account in &account_pins {
            account.current_uid()?;
        }
        if let Some(binding) = &registry_binding {
            binding.current()?;
        }
        Ok(value)
    };
    context.recheck(&mut authenticate)?;
    let old = events.iter().find(|event| event.request_id == request);
    let replayed = old.is_some();
    let mut predicted = catalog.clone();
    let (event, changed) = if let Some(old) = old {
        if &old.command != command {
            return Err("Admin request already binds a different command".into());
        }
        (old.clone(), false)
    } else {
        if snapshot
            .entries
            .iter()
            .any(|entry| entry.request_id == request)
        {
            return Err("Admin request belongs to another semantic activity".into());
        }
        let changed = predicted.apply(command)?;
        (
            CatalogEvent {
                schema_version: 1,
                kind: "native-admin-catalog-event".into(),
                deployment: context.deployment.clone(),
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                principal: writer,
                request_id: request.into(),
                sequence: snapshot.entries.len() + 1,
                state_version_before: catalog.state_version,
                previous_head: snapshot.head.clone(),
                command: command.clone(),
            },
            changed,
        )
    };
    let bytes = serde_json::to_vec(&event)?;
    if bytes.len() as u64 > MAX_CATALOG_EVENT {
        return Err("principal/catalog payload exceeds the fixed bound".into());
    }
    let path = directory.join(event_name(request));
    let retained = match fs::symlink_metadata(&path) {
        Ok(_) => Some(read_event(directory, request)?.1),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let prepared = retained.is_some();
    if retained.is_some_and(|retained| retained != bytes) {
        return Err("retained Admin catalog proposal differs; preserve state".into());
    }
    if prepared && !replayed && !changed {
        return Err("unsupported retained no-op Admin proposal; preserve state".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"luma-native-admin-catalog-review-v1\0");
    digest.update(serde_json::to_vec(
        &serde_json::json!({"event":event,"head":snapshot.head,
        "replayed":replayed,"changed":changed,"reset_count":snapshot.clock.reset_count,
        "restart_count":snapshot.clock.restart_count}),
    )?);
    let digest = bundle::hex(&digest.finalize());
    let mut written = false;
    if let Some(approved) = reviewed {
        tpm::decode::<32>(approved)?;
        if approved != digest {
            return Err("Admin catalog review changed; inspect again".into());
        }
        if changed {
            context.recheck(&mut authenticate)?;
            if matches!(command, Command::PrepareAccountDeletion { .. }) {
                deletion_boundary
                    .as_ref()
                    .ok_or("deletion preparation lacks protected sources")?
                    .stage()?;
            }
            if matches!(
                command,
                Command::PrepareAccountLock { .. } | Command::PrepareAdminAccountRecovery { .. }
            ) {
                if let Some(AccountBoundary::Plan(guard)) = &account_boundary {
                    guard.stage()?;
                } else {
                    return Err("account preparation lacks protected source handles".into());
                }
            }
            match fs::symlink_metadata(&path) {
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                Err(error) => return Err(error.into()),
            }
            if read_event(directory, request)?.1 != bytes {
                return Err("Admin catalog payload changed".into());
            }
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?
                .sync_all()?;
            File::open(directory)?.sync_all()?;
            let entry = Entry {
                request_id: request.into(),
                authenticated_uid: context.principal.uid,
                clock: snapshot.clock,
                activity: command.activity().into(),
                payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
            };
            store.append(entry.clone(), |proposed| {
                if proposed != &entry
                    || read_event(directory, request)?.1 != bytes
                    || !context.state(&snapshot, Some(request))?.1
                    || context.events(&snapshot, Some(request))?.0 != catalog
                {
                    return Err(
                        "Admin catalog authority or semantic inputs changed before commit".into(),
                    );
                }
                context.recheck(&mut authenticate)
            })?;
            written = true;
        }
    }
    let final_snapshot = store.snapshot()?;
    match &authority {
        CatalogAuthority::Recovery(attempt) => {
            final_snapshot.clock.elapsed_since(attempt.clock.get())?;
            attempt.clock.set(final_snapshot.clock);
        }
        CatalogAuthority::Governed(attempt) => {
            final_snapshot
                .clock
                .elapsed_since(attempt.session.clock.get())?;
            attempt.session.clock.set(final_snapshot.clock);
        }
        #[cfg(test)]
        CatalogAuthority::Primitive => (),
    }
    context.state(&final_snapshot, Some(request))?;
    let (current, _) = context.events(&final_snapshot, Some(request))?;
    if written && current != predicted {
        return Err("committed Admin catalog differs from the proposed state".into());
    }
    context.recheck(&mut authenticate)?;
    Ok(
        serde_json::json!({"schema_version":1,"action":"admin-catalog-command",
        "review_sha256":digest,"proposal":event,"catalog":current,
        "committed":reviewed.is_some() && (written || replayed),"replayed":replayed,
        "no_change":!changed && !replayed,"tpm_write_performed":written,
        "product_admin_active":current.principal_states.get(&context.principal.principal).map_or(true, |state| state.enabled),
        "account_password_aging_policy":account_day(&current, command).map(|day| serde_json::json!({
            "credential_day":day,"minimum_days":0,"maximum_days":90,"warning_days":7,
            "clock_source":"protected_utc","saved_policy_is_authority":false})),
        "delegation_available":false,"effect_grant":false,
        "trusted_utc_available":false,"production_custody_verified":false,"gate_closing":false}),
    )
}

enum AccountBoundary {
    Plan(crate::account_transition::Guard),
    Published(crate::account_transition::Published),
}

fn creation_homes(identity_path: &Path) -> std::path::PathBuf {
    #[cfg(test)]
    if identity_path != Path::new(crate::principal::IDENTITY) {
        return identity_path.join("creation-homes");
    }
    let _ = identity_path;
    crate::account_creation::HOME.into()
}

fn creation_boundary(
    catalog: &Catalog,
    registry_path: &Path,
    identity_path: &Path,
    command: &Command,
) -> Result<Option<crate::account_creation::Guard>> {
    let intent = match command {
        Command::PrepareAccountCreation { intent } => {
            if catalog.account_creations.contains_key(&intent.transaction) {
                return Ok(None);
            }
            intent
        }
        Command::PermitAccountCreation { transaction }
        | Command::CompleteAccountCreation { transaction } => {
            let creation = catalog
                .account_creations
                .get(transaction)
                .ok_or("no anchored creation")?;
            if creation.phase == crate::account_transition::Phase::Complete {
                return Ok(None);
            }
            &creation.intent
        }
        _ => return Ok(None),
    };
    let guard = crate::account_creation::Guard::retained(
        registry_path,
        identity_path,
        &creation_homes(identity_path),
        intent,
    )?;
    if matches!(command, Command::PrepareAccountCreation { .. })
        || matches!(command,Command::PermitAccountCreation {transaction} if catalog.account_creations[transaction].phase==crate::account_transition::Phase::Prepared)
    {
        guard.unpublished()?;
    }
    if matches!(command, Command::CompleteAccountCreation { .. }) {
        guard.complete()?;
    }
    Ok(Some(guard))
}

fn deletion_boundary(
    catalog: &Catalog,
    registry_path: &Path,
    identity_path: &Path,
    command: &Command,
) -> Result<Option<crate::account_deletion::Guard>> {
    let intent = match command {
        Command::PrepareAccountDeletion { intent } => {
            if catalog.account_deletions.contains_key(&intent.transaction) {
                return Ok(None);
            }
            intent
        }
        Command::PermitAccountDeletion { transaction }
        | Command::CompleteAccountDeletion { transaction } => {
            let transition = catalog
                .account_deletions
                .get(transaction)
                .ok_or("no anchored account deletion")?;
            if transition.phase == crate::account_transition::Phase::Complete {
                return Ok(None);
            }
            &transition.intent
        }
        _ => return Ok(None),
    };
    let guard = if matches!(command, Command::PrepareAccountDeletion { .. }) {
        let registry = crate::principal::RegistryBinding::capture(registry_path)?;
        let name = &registry
            .current()?
            .principal(&intent.principal)
            .ok_or("unknown deletion principal")?
            .login;
        let guard = crate::account_deletion::Guard::prepare(
            registry_path,
            identity_path,
            name,
            intent.expected_generation,
            &intent.transaction,
        )?;
        registry.current()?;
        if guard.intent != *intent {
            return Err("deletion differs from protected installed records".into());
        }
        guard
    } else {
        crate::account_deletion::Guard::retained(registry_path, identity_path, intent)?
    };
    if matches!(command, Command::CompleteAccountDeletion { .. }) {
        guard.complete()?;
    }
    Ok(Some(guard))
}

impl AccountBoundary {
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Plan(guard) => guard.recheck(),
            Self::Published(guard) => guard.recheck(),
        }
    }
}

fn account_boundary(
    catalog: &Catalog,
    registry_path: &Path,
    identity_path: &Path,
    command: &Command,
) -> Result<Option<AccountBoundary>> {
    use crate::account_transition::{Guard, Phase, Published};
    let intent = match command {
        Command::PrepareAccountLock { intent }
        | Command::PrepareAdminAccountRecovery { intent, .. } => {
            if catalog
                .account_transitions
                .contains_key(&intent.transaction)
            {
                return Ok(None);
            }
            intent
        }
        Command::PermitAccountPublication { transaction }
        | Command::CompleteAccountLock { transaction }
        | Command::PermitAdminAccountRecovery { transaction }
        | Command::CompleteAdminAccountRecovery { transaction } => {
            let transition = catalog
                .account_transitions
                .get(transaction)
                .ok_or("no anchored account transition")?;
            if transition.phase == Phase::Complete {
                return Ok(None);
            }
            &transition.intent
        }
        _ => return Ok(None),
    };
    if !matches!(
        command,
        Command::PrepareAccountLock { .. } | Command::PrepareAdminAccountRecovery { .. }
    ) {
        // Already-published recovery is an exact read, never a second rename.
        if let Ok(published) = Published::capture(registry_path, identity_path, intent) {
            return Ok(Some(AccountBoundary::Published(published)));
        }
        if matches!(
            command,
            Command::CompleteAccountLock { .. } | Command::CompleteAdminAccountRecovery { .. }
        ) {
            return Err("account completion requires the exact published records".into());
        }
    }
    let registry = crate::principal::RegistryBinding::capture(registry_path)?;
    let name = &registry
        .current()?
        .principal(&intent.principal)
        .ok_or("unknown account transition principal")?
        .login;
    let guard = if matches!(
        intent.kind,
        Some(crate::account_transition::Kind::Renewal { .. })
    ) {
        Guard::retained_renewal(registry_path, identity_path, intent)?
    } else if matches!(
        intent.kind,
        Some(crate::account_transition::Kind::AdminRecovery { .. })
    ) {
        Guard::retained_admin_recovery(registry_path, identity_path, intent)?
    } else if matches!(
        intent.kind,
        Some(crate::account_transition::Kind::Activation { .. })
    ) {
        Guard::retained_activation(registry_path, identity_path, intent)?
    } else if intent.kind == Some(crate::account_transition::Kind::Password) {
        Guard::retained_password(registry_path, identity_path, intent)?
    } else {
        Guard::prepare(
            registry_path,
            identity_path,
            name,
            intent.expected_generation,
            &intent.transaction,
            intent.locked,
        )?
    };
    if &guard.intent != intent {
        return Err("account transition differs from protected records".into());
    }
    if matches!(
        command,
        Command::PermitAccountPublication { .. } | Command::PermitAdminAccountRecovery { .. }
    ) {
        guard.retain_stage()?;
    }
    registry.current()?;
    Ok(Some(AccountBoundary::Plan(guard)))
}

// Kept private to this composition. A captured verifier or JSON identity cannot
// construct, serialize, renew or transfer this proof to any ordinary command.
struct RecoveryAttempt<'a> {
    credential: &'a crate::admin_recovery::Credential,
    verifier: crate::admin_recovery::Verifier,
    registry: crate::principal::RegistryBinding,
    baseline: serde_json::Value,
    head: String,
    clock: std::cell::Cell<tpm::Clock>,
    command: Command,
    lifetime: authentication::ProtectedOperation,
    account_time: std::cell::RefCell<Option<AccountTime>>,
}

impl<'a> RecoveryAttempt<'a> {
    fn prepare<A: Checkpoint>(
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        credential: &'a crate::admin_recovery::Credential,
        replacement: &crate::admin_recovery::Credential,
    ) -> Result<Self> {
        let registry = crate::principal::RegistryBinding::capture(registry_path)?;
        let snapshot = store.snapshot()?;
        let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
        if !context.state(&snapshot, None)?.1 {
            return Err("explicit product Admin bootstrap required for recovery".into());
        }
        let catalog = context.events(&snapshot, None)?.0;
        if catalog.registry()? != registry.current()? {
            return Err("recovery requires unchanged explicitly adopted installer registry".into());
        }
        let writer = context.writer(&catalog)?;
        let verifier = catalog.recovery_verifier()?.clone();
        verifier.validate(&writer.installation, &writer.principal)?;
        verifier.verify(credential)?;
        if verifier.verify(replacement).is_ok() {
            return Err(
                "replacement recovery credential must differ from the current credential".into(),
            );
        }
        let replacement = crate::admin_recovery::Verifier::create(
            replacement,
            &writer.installation,
            &writer.principal,
            verifier
                .generation
                .checked_add(1)
                .ok_or("recovery generation exhausted")?,
        )?;
        let command = Command::RecoverAdmin {
            expected_generation: writer.generation,
            expected_recovery_generation: verifier.generation,
            replacement,
        };
        let mut predicted = catalog.clone();
        predicted.apply(&command)?;
        let final_snapshot = store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if final_snapshot.head != snapshot.head
            || final_snapshot.deployment != snapshot.deployment
            || context.events(&final_snapshot, None)?.0 != catalog
        {
            return Err("Admin recovery authority changed during credential verification".into());
        }
        registry.current()?;
        Ok(Self {
            credential,
            verifier,
            registry,
            baseline: serde_json::to_value(context.principal)?,
            head: snapshot.head,
            clock: std::cell::Cell::new(final_snapshot.clock),
            command,
            lifetime: authentication::ProtectedOperation::start()?,
            account_time: std::cell::RefCell::new(None),
        })
    }

    fn account<A: Checkpoint>(
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        credential: &'a crate::admin_recovery::Credential,
        request: &str,
        command: Command,
    ) -> Result<Self> {
        if !admin_account_recovery(&command) {
            return Err("not an offline Admin OS recovery command".into());
        }
        let registry = crate::principal::RegistryBinding::capture(registry_path)?;
        let snapshot = store.snapshot()?;
        let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
        if !context.state(&snapshot, Some(request))?.1 {
            return Err("Admin bootstrap required for OS recovery".into());
        }
        let (catalog, events) = context.events(&snapshot, Some(request))?;
        if catalog.registry()? != registry.current()? {
            return Err("Admin recovery registry changed".into());
        }
        let writer = context.custody_writer(&catalog)?;
        let verifier = catalog.recovery_verifier()?.clone();
        verifier.validate(&writer.installation, &writer.principal)?;
        verifier.verify(credential)?;
        let mut predicted = catalog.clone();
        if let Some(old) = events.iter().find(|event| event.request_id == request) {
            if old.command != command {
                return Err("Admin recovery request belongs to another command".into());
            }
        } else {
            predicted.apply(&command)?;
        }
        let time = AccountTime::capture(
            store,
            directory,
            account_day(&catalog, &command).ok_or("Admin recovery missing protected aging")?,
            request,
        )?;
        let final_snapshot = store.snapshot()?;
        final_snapshot.clock.elapsed_since(snapshot.clock)?;
        if final_snapshot.head != snapshot.head
            || context.events(&final_snapshot, Some(request))?.0 != catalog
        {
            return Err("Admin recovery authority changed".into());
        }
        registry.current()?;
        Ok(Self {
            credential,
            verifier,
            registry,
            baseline: serde_json::to_value(context.principal)?,
            head: snapshot.head,
            clock: std::cell::Cell::new(final_snapshot.clock),
            command,
            lifetime: authentication::ProtectedOperation::start()?,
            account_time: std::cell::RefCell::new(Some(time)),
        })
    }

    fn authenticate(&self) -> Result<serde_json::Value> {
        self.lifetime.within(|| {
            if let Some(time) = &mut *self.account_time.borrow_mut() {
                time.recheck()?;
            }
            self.registry.current()?;
            self.verifier.verify(self.credential)?;
            self.registry.current()?;
            Ok(self.baseline.clone())
        })
    }

    fn execute<A: Checkpoint>(
        &self,
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        request: &str,
        reviewed: Option<&str>,
    ) -> Result<serde_json::Value> {
        let result = self.lifetime.within(|| {
            let report = execute_catalog_authorized_at(
                store,
                directory,
                registry_path,
                Path::new(crate::principal::IDENTITY),
                || self.authenticate(),
                request,
                &self.command,
                reviewed,
                CatalogAuthority::Recovery(self),
            )?;
            if let Command::PermitAdminAccountRecovery { transaction } = &self.command {
                if report["committed"] == true {
                    let snapshot = store.snapshot()?;
                    snapshot.clock.elapsed_since(self.clock.get())?;
                    self.clock.set(snapshot.clock);
                    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
                    let (catalog, events) = context.events(&snapshot, None)?;
                    if catalog.recovery_verifier()? != &self.verifier
                        || !events.iter().any(|event| {
                            event.request_id == request && event.command == self.command
                        })
                    {
                        return Err(
                            "Admin OS publication lacks its exact live custody continuation".into(),
                        );
                    }
                    if let Some(day) = account_day(&catalog, &self.command) {
                        *self.account_time.borrow_mut() =
                            Some(AccountTime::capture(store, directory, day, request)?);
                    }
                    let boundary = account_boundary(
                        &catalog,
                        registry_path,
                        Path::new(crate::principal::IDENTITY),
                        &self.command,
                    )?;
                    match boundary {
                        Some(AccountBoundary::Plan(guard)) => guard.publish(|| {
                            self.authenticate()?;
                            let current = store.snapshot()?;
                            current.clock.elapsed_since(self.clock.get())?;
                            self.clock.set(current.clock);
                            if current.head != snapshot.head
                                || context.events(&current, None)?.0 != catalog
                            {
                                return Err(
                                    "Admin OS recovery authority changed before rename".into()
                                );
                            }
                            context.recheck(&mut || self.authenticate())
                        })?,
                        Some(AccountBoundary::Published(guard)) => guard.recheck()?,
                        None => return Err("missing Admin OS publication guard".into()),
                    }
                    let _ = transaction;
                }
            }
            Ok(report)
        });
        // A dispatched write attempt consumes this in-process proof even if the
        // TPM outcome is uncertain. Only exact journal reconciliation can follow.
        if reviewed.is_some() {
            self.lifetime.close();
        }
        result
    }
}

pub fn recover_admin(request: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved Admin recovery request".into());
    }
    let credential = crate::admin_recovery::Credential::read()?;
    let replacement = crate::admin_recovery::Credential::generate_confirmed()?;
    let directory = Path::new(DIRECTORY);
    let registry = Path::new(crate::principal::REGISTRY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let attempt =
        RecoveryAttempt::prepare(&mut store, directory, registry, &credential, &replacement)?;
    let inspected = attempt.execute(&mut store, directory, registry, request, None)?;
    println!("{}", serde_json::to_string(&inspected)?);
    let digest = inspected["review_sha256"]
        .as_str()
        .ok_or("missing recovery review digest")?;
    crate::admin_recovery::review(digest)?;
    let committed = attempt.execute(&mut store, directory, registry, request, Some(digest))?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
        "schema_version":1,"action":"admin-custody-recovery","receipt":committed,
        "unix_password_changed":false,"effect_grant":false,"gate_closing":false}))?
    );
    Ok(())
}

pub fn admin_account_recovery_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let prepare = args.first().map(String::as_str) == Some("admin-account-recover");
    if (prepare && args.len() != 2) || (!prepare && args.len() != 3) {
        return Err("use admin-account-recover TRANSACTION, admin-account-recover-publish TRANSACTION REQUEST, or admin-account-recover-complete TRANSACTION REQUEST; credentials remain terminal-only".into());
    }
    let transaction = &args[1];
    let request = if prepare { transaction } else { &args[2] };
    if !admin_roles::identifier(transaction)
        || !admin_roles::identifier(request)
        || transaction == REQUEST
        || request == REQUEST
        || (!prepare && transaction == request)
    {
        return Err("invalid or reused Admin account recovery request".into());
    }
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    let retained = crate::account_transition::retained_intent(identity_path, transaction)?;
    let retained_path = identity_path
        .join(format!("account-transition-{transaction}"))
        .join("recovery.json");
    let retained_command = match fs::symlink_metadata(&retained_path) {
        Ok(_) => {
            let bytes = tpm::private_read(&retained_path, 16384)?;
            let command: Command = serde_json::from_slice(&bytes)?;
            command.validate()?;
            if serde_json::to_vec(&command)? != bytes
                || !matches!(command, Command::PrepareAdminAccountRecovery { .. })
            {
                return Err(
                    "noncanonical retained Admin recovery proposal; preserve evidence".into(),
                );
            }
            Some(command)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    println!("Enter the CURRENT offline Admin credential. Root access and the Unix password are not recovery authorization.");
    let credential = crate::admin_recovery::Credential::read()?;
    let password = if prepare && retained.is_none() {
        Some(crate::account_password::Password::local_confirmed()?)
    } else {
        None
    };
    let replacement = if prepare {
        if retained_command.is_some() {
            println!("Enter the NEW offline recovery credential recorded when this exact retained proposal was first prepared.");
            Some(crate::admin_recovery::Credential::read()?)
        } else {
            Some(crate::admin_recovery::Credential::generate_confirmed()?)
        }
    } else {
        None
    };
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit Admin bootstrap required".into());
    }
    let catalog = context.events(&snapshot, Some(request))?.0;
    let writer = context.custody_writer(&catalog)?;
    let verifier = catalog.recovery_verifier()?;
    verifier.verify(&credential)?;
    let command = if prepare {
        if let Some(command) = retained_command {
            if let Command::PrepareAdminAccountRecovery {
                intent,
                replacement: approved,
                ..
            } = &command
            {
                if retained.as_ref() != Some(intent) || intent.transaction != *transaction {
                    return Err("retained Admin recovery records disagree".into());
                }
                approved.verify(
                    replacement
                        .as_ref()
                        .ok_or("missing retained replacement credential")?,
                )?;
                if !catalog.account_transitions.contains_key(transaction) {
                    crate::account_transition::Guard::retained_admin_recovery(
                        registry_path,
                        identity_path,
                        intent,
                    )?;
                }
            }
            command
        } else {
            if catalog.account_transitions.contains_key(transaction) {
                return Err(
                    "anchored Admin recovery lost its retained custody proposal; preserve state"
                        .into(),
                );
            }
            let binding = HistoryReader::for_candidate(&mut store, directory, request)?.read()?;
            let mut client = crate::utc_provider::Client::installed()?;
            let live = client.current(&binding)?;
            binding.recheck(&mut HistoryReader::for_candidate(
                &mut store, directory, request,
            )?)?;
            let (low, high) = live.interval().endpoints();
            if low <= 0 || low / 86_400_000 != high / 86_400_000 {
                return Err("Admin recovery requires an unambiguous protected UTC day".into());
            }
            let day = u32::try_from(low / 86_400_000)?;
            let replacement = replacement
                .as_ref()
                .ok_or("missing new confirmed offline credential")?;
            if verifier.verify(replacement).is_ok() {
                return Err("replacement offline credential must differ".into());
            }
            let new_verifier = crate::admin_recovery::Verifier::create(
                replacement,
                &writer.installation,
                &writer.principal,
                verifier
                    .generation
                    .checked_add(1)
                    .ok_or("recovery generation exhausted")?,
            )?;
            let guard = if let Some(intent) = &retained {
                crate::account_transition::Guard::retained_admin_recovery(
                    registry_path,
                    identity_path,
                    intent,
                )?
            } else {
                let hash = password
                    .as_ref()
                    .ok_or("new Admin recovery needs a confirmed password")?
                    .hash()?;
                crate::account_transition::Guard::prepare_admin_recovery(
                    registry_path,
                    identity_path,
                    &writer.login,
                    writer.generation,
                    transaction,
                    &hash,
                    day,
                    live.context(),
                )?
            };
            let command = Command::PrepareAdminAccountRecovery {
                intent: guard.intent.clone(),
                expected_credential: catalog
                    .account_commitments
                    .get(&writer.principal)
                    .ok_or("Admin recovery requires prior checkpointed credentials")?
                    .clone(),
                expected_recovery_generation: verifier.generation,
                replacement: new_verifier,
            };
            let mut projected = catalog.clone();
            projected.apply(&command)?;
            guard.stage_password_proposal(|| {
                verifier.verify(&credential)?;
                let current = store.snapshot()?;
                if current.head != snapshot.head
                    || context.events(&current, Some(request))?.0 != catalog
                {
                    return Err("Admin recovery authority changed before proposal retention".into());
                }
                binding.recheck(&mut HistoryReader::for_candidate(
                    &mut store, directory, request,
                )?)?;
                let current = client.current(&binding)?;
                let (lower, upper) = current.interval().endpoints();
                if lower / 86_400_000 != i64::from(day) || upper / 86_400_000 != i64::from(day) {
                    return Err("Admin recovery protected day changed".into());
                }
                binding.recheck(&mut HistoryReader::for_candidate(
                    &mut store, directory, request,
                )?)
            })?;
            let bytes = serde_json::to_vec(&command)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&retained_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            File::open(retained_path.parent().ok_or("missing proposal directory")?)?.sync_all()?;
            if tpm::private_read(&retained_path, 16384)? != bytes {
                return Err("Admin recovery proposal changed; preserve state".into());
            }
            command
        }
    } else {
        match args[0].as_str() {
            "admin-account-recover-publish" => Command::PermitAdminAccountRecovery {
                transaction: transaction.clone(),
            },
            "admin-account-recover-complete" => Command::CompleteAdminAccountRecovery {
                transaction: transaction.clone(),
            },
            _ => return Err("unknown Admin account recovery action".into()),
        }
    };
    let attempt = RecoveryAttempt::account(
        &mut store,
        directory,
        registry_path,
        &credential,
        request,
        command,
    )?;
    let inspected = attempt.execute(&mut store, directory, registry_path, request, None)?;
    println!("{}", serde_json::to_string(&inspected)?);
    let review = inspected["review_sha256"]
        .as_str()
        .ok_or("missing Admin OS recovery review")?;
    crate::admin_recovery::review(review)?;
    let committed = attempt.execute(&mut store, directory, registry_path, request, Some(review))?;
    println!("{}", serde_json::to_string(&committed)?);
    Ok(())
}

const MAX_GRANT_COMMAND_INPUT: usize = 16_384;

fn finite_catalog_json(bytes: &[u8]) -> Result<Command> {
    if bytes.is_empty() || bytes.len() > MAX_GRANT_COMMAND_INPUT {
        return Err("finite catalog command input exceeds its closed bound".into());
    }
    let command: Command = serde_json::from_slice(bytes)?;
    if !matches!(
        command,
        Command::AssignRole { .. }
            | Command::RevokeAssignment { .. }
            | Command::IssueGrant { .. }
            | Command::RevokeGrant { .. }
    ) {
        return Err("catalog JSON accepts only finite role assignment and grant governance".into());
    }
    command.validate()?;
    Ok(command)
}

/// The file contributes inert command data only. Its bytes are captured before
/// genuine PAM, then the normal catalog review and TPM writer bind that exact
/// owned command, current Admin, checkpoint, role, subject and UTC validity.
fn finite_catalog_file(path: &Path) -> Result<Command> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let initial = file.metadata()?;
    if !initial.is_file() || initial.len() == 0 || initial.len() > MAX_GRANT_COMMAND_INPUT as u64 {
        return Err("finite catalog JSON must be a bounded regular file".into());
    }
    let key = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_GRANT_COMMAND_INPUT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || key(&initial) != key(&file.metadata()?)
        || key(&initial) != key(&named)
        || bytes.len() as u64 != initial.len()
    {
        return Err("finite catalog command input changed while captured".into());
    }
    finite_catalog_json(&bytes)
}

fn parse_command(args: &[String]) -> Result<(&str, &str, Command, Option<&str>)> {
    let committed = args.len() >= 2 && args[args.len() - 2] == "--commit";
    let end = args.len() - if committed { 2 } else { 0 };
    let review = if committed {
        Some(args[args.len() - 1].as_str())
    } else {
        None
    };
    if let Some(review) = review {
        tpm::decode::<32>(review)?;
    }
    let command = match args.first().map(String::as_str) {
        Some("admin-catalog") if end == 4 => finite_catalog_file(Path::new(&args[3]))?,
        Some("admin-activity-register") if end == 4 => Command::RegisterActivity { activity: args[3].clone() },
        Some("admin-principal-advance") if end == 6 => Command::AdvancePrincipal {
            principal: args[3].clone(), expected_generation: args[4].parse()?, enabled: principal_enabled(&args[5])?,
        },
        Some("admin-principal-rotate") if end == 4 => Command::RotateAdmin {
            expected_generation: args[3].parse()?,
        },
        Some("admin-role-define") if (6..=69).contains(&end) => {
            let mut activities = args[5..end].to_vec();
            activities.sort();
            Command::DefineRole { name: args[3].clone(), activities, expected_version: args[4].parse()? }
        }
        _ => return Err("use admin-catalog LOGIN REQUEST FILE for finite assignment/grant JSON, admin-activity-register LOGIN REQUEST ACTIVITY, admin-principal-advance LOGIN REQUEST PRINCIPAL-ID EXPECTED-GENERATION enabled|disabled, admin-principal-rotate LOGIN REQUEST EXPECTED-GENERATION, or admin-role-define LOGIN REQUEST ROLE EXPECTED-VERSION ACTIVITY...; optional --commit REVIEW-SHA256".into()),
    };
    command.validate()?;
    if !admin_roles::identifier(&args[2]) || args[2] == REQUEST {
        return Err("invalid or reserved Admin request".into());
    }
    Ok((&args[1], &args[2], command, review))
}

pub fn catalog_command(args: &[String]) -> Result<()> {
    let (login, request, command, reviewed) = parse_command(args)?;
    crate::require_root()?;
    platform::require_installed()?;
    let prepared = prepare_control(login, Some(request))?;
    let authenticated = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let report = run_control_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        authenticated,
        prepared,
        None,
        request,
        Some(&command),
        reviewed,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub(crate) fn principal_enabled(value: &str) -> Result<bool> {
    match value {
        "enabled" => Ok(true),
        "disabled" => Ok(false),
        _ => Err("use exactly enabled or disabled for principal state".into()),
    }
}

pub(crate) fn adoption_command(registry_path: &Path) -> Result<Command> {
    let binding = crate::principal::RegistryBinding::capture(registry_path)?;
    Ok(Command::AdoptPrincipals {
        registry: binding.current()?.clone(),
    })
}

fn account_checkpoint_at(
    registry_path: &Path,
    identity_path: &Path,
) -> Result<(Command, Vec<crate::principal::AccountBinding>)> {
    let registry = crate::principal::RegistryBinding::capture(registry_path)?;
    let mut commitments = std::collections::BTreeMap::new();
    let mut pins = Vec::new();
    for record in registry
        .current()?
        .principals()
        .iter()
        .filter(|record| record.enabled)
    {
        let account =
            crate::principal::AccountBinding::capture(registry_path, identity_path, &record.login)?;
        commitments.insert(record.id.clone(), account.credential_commitment()?);
        pins.push(account);
    }
    registry.current()?;
    for account in &pins {
        account.current_uid()?;
    }
    let command = Command::CheckpointAccounts { commitments };
    command.validate()?;
    Ok((command, pins))
}

pub(crate) fn account_checkpoint_command(registry_path: &Path) -> Result<Command> {
    Ok(account_checkpoint_at(registry_path, account_identity(registry_path))?.0)
}

fn account_identity(registry_path: &Path) -> &Path {
    #[cfg(test)]
    if Path::new("/.dockerenv").is_file()
        && !Path::new("/dev/tpm0").exists()
        && !Path::new("/dev/tpmrm0").exists()
        && registry_path.parent().is_some_and(|root| {
            root.starts_with("/tmp")
                && root
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("luma-tpm-delivery-"))
        })
    {
        return Path::new("/etc");
    }
    let _ = registry_path;
    Path::new(crate::principal::IDENTITY)
}

pub fn checkpoint_accounts(login: &str, request: &str, reviewed: Option<&str>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let prepared = prepare_control(login, Some(request))?;
    let account = authentication::local(login)?;
    let registry = Path::new(crate::principal::REGISTRY);
    let command = account_checkpoint_command(registry)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let report = run_control_at(
        &mut store,
        directory,
        registry,
        account,
        prepared,
        None,
        request,
        Some(&command),
        reviewed,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn password_proposal<A: Checkpoint>(
    session: &PrincipalSession,
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    identity_path: &Path,
    target: &str,
    request: &str,
    password: Option<&crate::account_password::Password>,
) -> Result<Command> {
    session.observe_store(
        &mut PrincipalReader::admin_at(store, directory, registry_path, Some(request)),
        |identity, store| {
            let snapshot = store.snapshot()?;
            let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
            let catalog = context.events(&snapshot, Some(request))?.0;
            if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                return Err("password proposal differs from the governed Admin".into());
            }
            let registry = crate::principal::RegistryBinding::capture(registry_path)?;
            let record = registry
                .current()?
                .account(target)
                .ok_or("unknown installation account")?;
            let intent = if let Some(transition) = catalog.account_transitions.get(request) {
                transition.intent.clone()
            } else if let Some(intent) =
                crate::account_transition::retained_intent(identity_path, request)?
            {
                // Retain the exact reviewed salt and bytes, never regenerate on commit.
                crate::account_transition::Guard::retained_password(
                    registry_path,
                    identity_path,
                    &intent,
                )?;
                intent
            } else {
                let hash = password
                    .ok_or("new password proposal requires local secret entry")?
                    .hash()?;
                let generation = catalog
                    .principal_states
                    .get(&record.id)
                    .map_or(record.generation, |state| state.generation);
                let guard = crate::account_transition::Guard::prepare_password(
                    registry_path,
                    identity_path,
                    target,
                    generation,
                    request,
                    &hash,
                )?;
                let command = Command::PrepareAccountLock {
                    intent: guard.intent.clone(),
                };
                // Validate the reducer before creating even a private proposal.
                let mut projected = catalog.clone();
                projected.apply(&command)?;
                guard.stage_password_proposal(|| {
                    context.recheck(&mut || session.account.identity())?;
                    let current = store.snapshot()?;
                    if current.head != snapshot.head || current.deployment != snapshot.deployment {
                        return Err("password proposal authority changed before retention".into());
                    }
                    registry.current()?;
                    Ok(())
                })?;
                guard.intent.clone()
            };
            if intent.kind != Some(crate::account_transition::Kind::Password)
                || intent.principal != record.id
            {
                return Err("password request belongs to another account transition".into());
            }
            registry.current()?;
            context.recheck(&mut || session.account.identity())?;
            Ok(Command::PrepareAccountLock { intent })
        },
    )
}

fn creation_proposal<A: Checkpoint>(
    session: &PrincipalSession,
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    identity_path: &Path,
    name: &str,
    request: &str,
    password: Option<&crate::account_password::Password>,
) -> Result<Command> {
    session.observe_store(
        &mut PrincipalReader::admin_at(store, directory, registry_path, Some(request)),
        |identity, store| {
            let snapshot = store.snapshot()?;
            let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
            let catalog = context.events(&snapshot, Some(request))?.0;
            if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                return Err("creation proposal differs from the governed Admin".into());
            }
            let homes = creation_homes(identity_path);
            let intent = if let Some(creation) = catalog.account_creations.get(request) {
                creation.intent.clone()
            } else if let Some(intent) =
                crate::account_creation::retained_intent(identity_path, request)?
            {
                crate::account_creation::Guard::retained(
                    registry_path,
                    identity_path,
                    &homes,
                    &intent,
                )?
                .unpublished()?;
                let mut projected = catalog.clone();
                projected.apply(&Command::PrepareAccountCreation {
                    intent: intent.clone(),
                })?;
                intent
            } else {
                let hash = password
                    .ok_or("new account creation requires local secret entry")?
                    .hash()?;
                let guard = crate::account_creation::Guard::new(
                    registry_path,
                    identity_path,
                    &homes,
                    name,
                    request,
                    &hash,
                )?;
                let mut projected = catalog.clone();
                projected.apply(&Command::PrepareAccountCreation {
                    intent: guard.intent.clone(),
                })?;
                guard.stage(|| {
                    context.recheck(&mut || session.account.identity())?;
                    let current = store.snapshot()?;
                    if current.head != snapshot.head || current.deployment != snapshot.deployment {
                        return Err("creation proposal authority changed before retention".into());
                    }
                    Ok(())
                })?;
                let intent = guard.intent.clone();
                drop(guard);
                crate::account_creation::Guard::retained(
                    registry_path,
                    identity_path,
                    &homes,
                    &intent,
                )?
                .unpublished()?;
                intent
            };
            if intent.principal.login != name {
                return Err("creation request belongs to another login".into());
            }
            context.recheck(&mut || session.account.identity())?;
            Ok(Command::PrepareAccountCreation { intent })
        },
    )
}

struct CreationAttempt<'s> {
    session: &'s PrincipalSession,
    actor_aging: RefCell<Option<ActorAging>>,
    directory: std::path::PathBuf,
    registry_path: std::path::PathBuf,
    guard: crate::account_creation::Guard,
    catalog: Catalog,
    snapshot: Snapshot,
}
impl<'s> CreationAttempt<'s> {
    fn prepare<A: Checkpoint>(
        session: &'s PrincipalSession,
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        transaction: &str,
    ) -> Result<Self> {
        match &session.binding.purpose {
            PrincipalPurpose::AdminCatalog {
                candidate: Some(candidate),
            } if candidate == transaction => (),
            _ => {
                return Err(
                    "creation publication requires its exact owned Admin login scope".into(),
                )
            }
        }
        session.observe_store(
            &mut PrincipalReader::admin_at(store, directory, registry_path, Some(transaction)),
            |identity, store| {
                let snapshot = store.snapshot()?;
                let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
                let (catalog, events) = context.events(&snapshot, None)?;
                let creation = catalog
                    .account_creations
                    .get(transaction)
                    .ok_or("no anchored creation")?;
                if creation.phase == crate::account_transition::Phase::Prepared
                    || !events.iter().any(|event| {
                        event.command
                            == Command::PermitAccountCreation {
                                transaction: transaction.into(),
                            }
                    })
                    || serde_json::to_value(context.writer(&catalog)?)? != *identity
                {
                    return Err(
                        "creation publication lacks its exact committed governed permission".into(),
                    );
                }
                let identity_path = &session.binding.identity_path;
                let guard = crate::account_creation::Guard::retained(
                    registry_path,
                    identity_path,
                    &creation_homes(identity_path),
                    &creation.intent,
                )?;
                if creation.phase == crate::account_transition::Phase::Complete {
                    guard.complete()?;
                }
                context.recheck(&mut || session.account.identity())?;
                let actor_aging =
                    ActorAging::capture(session, &catalog, store, directory, transaction)?;
                Ok(Self {
                    session,
                    actor_aging: RefCell::new(actor_aging),
                    directory: directory.into(),
                    registry_path: registry_path.into(),
                    guard,
                    catalog,
                    snapshot,
                })
            },
        )
    }
    fn execute<A: Checkpoint>(self, store: &mut Store<A>, file: &str) -> Result<serde_json::Value> {
        let context = Context::load_at(
            &self.directory,
            &self.snapshot.deployment,
            &self.registry_path,
        )?;
        let written = self.guard.publish(file, || {
            if self.session.fenced.get() {
                return Err("creation continuation is fenced".into());
            }
            if let Some(aging) = self.actor_aging.borrow_mut().as_mut() {
                aging.recheck()?;
            }
            self.session.account.identity()?;
            let current = store.snapshot()?;
            current.clock.elapsed_since(self.session.clock.get())?;
            self.session.clock.set(current.clock);
            if current.head != self.snapshot.head
                || current.deployment != self.snapshot.deployment
                || context.events(&current, None)?.0 != self.catalog
                || serde_json::to_value(context.writer(&self.catalog)?)?
                    != self.session.binding.identity
            {
                return Err("creation authority changed before dispatch".into());
            }
            context.recheck(&mut || self.session.account.identity())?;
            if let Some(aging) = self.actor_aging.borrow_mut().as_mut() {
                aging.recheck()?;
            }
            Ok(())
        })?;
        Ok(
            serde_json::json!({"schema_version":1,"action":"admin-account-create-file",
            "transaction":self.guard.intent.transaction,"file":file,"file_published":true,
            "rename_performed":written,"replayed":!written,"principal_enabled":false,"gate_closing":false}),
        )
    }
}
impl Drop for CreationAttempt<'_> {
    fn drop(&mut self) {
        self.session.close();
    }
}

pub fn account_creation_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let file_dispatch = args.first().map(String::as_str) == Some("admin-account-create-file");
    let reviewed = if args.len() == 4 {
        None
    } else if !file_dispatch && args.len() == 6 && args[4] == "--commit" {
        tpm::decode::<32>(&args[5])?;
        Some(args[5].as_str())
    } else {
        return Err("invalid account creation arguments".into());
    };
    let request = if file_dispatch { &args[2] } else { &args[3] };
    if !admin_roles::identifier(request)
        || request == REQUEST
        || (file_dispatch
            && args[3] != "home"
            && !crate::account_creation::FILES.contains(&args[3].as_str()))
    {
        return Err("invalid creation request or publication file".into());
    }
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    let password = if args[0] == "admin-account-create" {
        let retained = crate::account_creation::retained_intent(identity_path, request)?;
        if reviewed.is_some() && retained.is_none() {
            return Err("creation commit requires its retained inspected proposal".into());
        }
        if retained.is_none() {
            Some(crate::account_password::Password::local_confirmed()?)
        } else {
            None
        }
    } else {
        None
    };
    let prepared = prepare_control(&args[1], Some(request))?;
    let account = authentication::local(&args[1])?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(account, &mut store, directory, registry_path, Some(request))?;
    if file_dispatch {
        let report =
            CreationAttempt::prepare(&session, &mut store, directory, registry_path, request)?
                .execute(&mut store, &args[3])?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let command = match args[0].as_str() {
        "admin-account-create" => creation_proposal(
            &session,
            &mut store,
            directory,
            registry_path,
            identity_path,
            &args[2],
            request,
            password.as_ref(),
        )?,
        "admin-account-create-permit" => Command::PermitAccountCreation {
            transaction: args[2].clone(),
        },
        "admin-account-create-complete" => Command::CompleteAccountCreation {
            transaction: args[2].clone(),
        },
        _ => return Err("unknown creation command".into()),
    };
    let report = CatalogAttempt::prepare(
        &session,
        &mut store,
        directory,
        registry_path,
        request,
        &command,
        None,
    )?
    .execute(&mut store, reviewed)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub fn account_activation_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let reviewed = if args.len() == 4 {
        None
    } else if args.len() == 6 && args[4] == "--commit" {
        tpm::decode::<32>(&args[5])?;
        Some(args[5].as_str())
    } else {
        return Err(
            "expected admin-account-activate LOGIN TARGET TRANSACTION [--commit REVIEW-SHA256]"
                .into(),
        );
    };
    let request = &args[3];
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid activation transaction".into());
    }
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    let renewal = args[0] == "admin-account-renew";
    let retained = crate::account_transition::retained_intent(identity_path, request)?;
    let password = if renewal && retained.is_none() {
        if reviewed.is_some() {
            return Err("renewal commit requires its inspected proposal".into());
        }
        Some(crate::account_password::Password::local_confirmed()?)
    } else {
        None
    };
    let prepared = prepare_control(&args[1], Some(request))?;
    let account = authentication::local(&args[1])?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(account, &mut store, directory, registry_path, Some(request))?;
    let command = session.observe_store(
        &mut PrincipalReader::admin_at(&mut store, directory, registry_path, Some(request)),
        |identity, store| {
            let snapshot = store.snapshot()?;
            let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
            let catalog = context.events(&snapshot, Some(request))?.0;
            if serde_json::to_value(context.writer(&catalog)?)? != *identity {
                return Err("activation writer changed".into());
            }
            let registry = crate::principal::RegistryBinding::capture(registry_path)?;
            let record = registry
                .current()?
                .account(&args[2])
                .ok_or("unknown activation account")?;
            let intent = if let Some(transition) = catalog.account_transitions.get(request) {
                transition.intent.clone()
            } else if let Some(intent) =
                crate::account_transition::retained_intent(identity_path, request)?
            {
                if renewal {
                    crate::account_transition::Guard::retained_renewal(
                        registry_path,
                        identity_path,
                        &intent,
                    )?;
                } else {
                    crate::account_transition::Guard::retained_activation(
                        registry_path,
                        identity_path,
                        &intent,
                    )?;
                }
                intent
            } else {
                if reviewed.is_some() {
                    return Err("activation commit requires its inspected retained proposal".into());
                }
                let binding = HistoryReader::for_candidate(store, directory, request)?.read()?;
                let mut client = crate::utc_provider::Client::installed()?;
                let live = client.current(&binding)?;
                binding.recheck(&mut HistoryReader::for_candidate(
                    store, directory, request,
                )?)?;
                let (lower, upper) = live.interval().endpoints();
                if lower <= 0 || lower / 86_400_000 != upper / 86_400_000 {
                    return Err("activation needs an unambiguous protected UTC day".into());
                }
                let day = u32::try_from(lower / 86_400_000)?;
                let generation = catalog
                    .principal_states
                    .get(&record.id)
                    .map_or(record.generation, |state| state.generation);
                let guard = if renewal {
                    let hash = password
                        .as_ref()
                        .ok_or("renewal requires confirmed local password")?
                        .hash()?;
                    crate::account_transition::Guard::prepare_renewal(
                        registry_path,
                        identity_path,
                        &record.login,
                        generation,
                        request,
                        &hash,
                        day,
                        live.context(),
                    )?
                } else {
                    crate::account_transition::Guard::prepare_activation(
                        registry_path,
                        identity_path,
                        &record.login,
                        generation,
                        request,
                        day,
                        live.context(),
                    )?
                };
                let mut projected = catalog.clone();
                projected.apply(&Command::PrepareAccountLock {
                    intent: guard.intent.clone(),
                })?;
                guard.stage_password_proposal(|| {
                    context.recheck(&mut || session.account.identity())?;
                    let current = store.snapshot()?;
                    if current.head != snapshot.head
                        || context.events(&current, Some(request))?.0 != catalog
                    {
                        return Err("activation authority changed before proposal retention".into());
                    }
                    binding.recheck(&mut HistoryReader::for_candidate(
                        store, directory, request,
                    )?)?;
                    let fresh = client.current(&binding)?;
                    let (low, high) = fresh.interval().endpoints();
                    if low / 86_400_000 != i64::from(day) || high / 86_400_000 != i64::from(day) {
                        return Err("activation aging day changed before retention".into());
                    }
                    binding.recheck(&mut HistoryReader::for_candidate(
                        store, directory, request,
                    )?)
                })?;
                guard.intent.clone()
            };
            if intent.principal != record.id
                || (renewal
                    != matches!(
                        intent.kind,
                        Some(crate::account_transition::Kind::Renewal { .. })
                    ))
                || !matches!(
                    intent.kind,
                    Some(
                        crate::account_transition::Kind::Activation { .. }
                            | crate::account_transition::Kind::Renewal { .. }
                    )
                )
            {
                return Err("activation/renewal transaction belongs to another account".into());
            }
            registry.current()?;
            Ok(Command::PrepareAccountLock { intent })
        },
    )?;
    let report = CatalogAttempt::prepare(
        &session,
        &mut store,
        directory,
        registry_path,
        request,
        &command,
        None,
    )?
    .execute(&mut store, reviewed)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub fn account_password_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let reviewed = if args.len() == 4 {
        None
    } else if args.len() == 6 && args[4] == "--commit" {
        tpm::decode::<32>(&args[5])?;
        Some(args[5].as_str())
    } else {
        return Err(
            "expected admin-account-password LOGIN TARGET TRANSACTION [--commit REVIEW-SHA256]"
                .into(),
        );
    };
    let request = &args[3];
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved password request".into());
    }
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    // This read decides whether to prompt, not whether an operation is permitted.
    // All proposal bytes and permissions are checked again inside the owned session.
    let retained = crate::account_transition::retained_intent(identity_path, request)?;
    if reviewed.is_some() && retained.is_none() {
        return Err("password commit requires its retained inspected proposal".into());
    }
    let password = if retained.is_none() {
        Some(crate::account_password::Password::local_confirmed()?)
    } else {
        None
    };
    let prepared = prepare_control(&args[1], Some(request))?;
    let account = authentication::local(&args[1])?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let session = prepared.issue(account, &mut store, directory, registry_path, Some(request))?;
    let command = password_proposal(
        &session,
        &mut store,
        directory,
        registry_path,
        identity_path,
        &args[2],
        request,
        password.as_ref(),
    )?;
    let report = CatalogAttempt::prepare(
        &session,
        &mut store,
        directory,
        registry_path,
        request,
        &command,
        None,
    )?
    .execute(&mut store, reviewed)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub fn account_lock_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let base = match args.first().map(String::as_str) {
        Some("admin-account-lock") => 5,
        Some("admin-account-publish" | "admin-account-complete") => 4,
        _ => return Err("unknown account lifecycle command".into()),
    };
    let reviewed = if args.len() == base {
        None
    } else if args.len() == base + 2 && args[base] == "--commit" {
        tpm::decode::<32>(&args[base + 1])?;
        Some(args[base + 1].as_str())
    } else {
        return Err("invalid account lifecycle command arguments".into());
    };
    let login = &args[1];
    let request = &args[3];
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved account lifecycle request".into());
    }
    let prepared = prepare_control(login, Some(request))?;
    let account = authentication::local(login)?;
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    let catalog = context.events(&snapshot, Some(request))?.0;
    let command = match args[0].as_str() {
        "admin-account-lock" => {
            let locked = match args[4].as_str() {
                "lock" => true,
                "unlock" => false,
                _ => return Err("account transition must be lock or unlock".into()),
            };
            let registry = crate::principal::RegistryBinding::capture(registry_path)?;
            let record = registry
                .current()?
                .account(&args[2])
                .ok_or("unknown installation account")?;
            let intent = if let Some(transition) = catalog.account_transitions.get(request) {
                if transition.intent.kind.is_some()
                    || transition.intent.principal != record.id
                    || transition.intent.locked != locked
                {
                    return Err("account request already belongs to another transition".into());
                }
                transition.intent.clone()
            } else {
                let generation = catalog
                    .principal_states
                    .get(&record.id)
                    .map_or(record.generation, |state| state.generation);
                let guard = crate::account_transition::Guard::prepare(
                    registry_path,
                    identity_path,
                    &args[2],
                    generation,
                    request,
                    locked,
                )?;
                guard.intent.clone()
            };
            registry.current()?;
            Command::PrepareAccountLock { intent }
        }
        "admin-account-publish" => Command::PermitAccountPublication {
            transaction: args[2].clone(),
        },
        "admin-account-complete" => Command::CompleteAccountLock {
            transaction: args[2].clone(),
        },
        _ => unreachable!("validated account command"),
    };
    let report = run_control_at(
        &mut store,
        directory,
        registry_path,
        account,
        prepared,
        None,
        request,
        Some(&command),
        reviewed,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

// Own the live session through dispatch. JSON, filesystem custody and even a
// valid PAM session with a different purpose cannot construct this continuation.
struct DeletionAttempt<'s> {
    session: &'s PrincipalSession,
    actor_aging: RefCell<Option<ActorAging>>,
    directory: std::path::PathBuf,
    registry_path: std::path::PathBuf,
    guard: crate::account_deletion::Guard,
    catalog: Catalog,
    snapshot: Snapshot,
}

impl<'s> DeletionAttempt<'s> {
    fn prepare<A: Checkpoint>(
        session: &'s PrincipalSession,
        store: &mut Store<A>,
        directory: &Path,
        registry_path: &Path,
        transaction: &str,
    ) -> Result<Self> {
        match &session.binding.purpose {
            PrincipalPurpose::AdminCatalog {
                candidate: Some(candidate),
            } if candidate == transaction => (),
            _ => {
                return Err(
                    "deletion publication requires its exact owned Admin login scope".into(),
                )
            }
        }
        session.observe_store(
            &mut PrincipalReader::admin_at(store, directory, registry_path, Some(transaction)),
            |identity, store| {
                let snapshot = store.snapshot()?;
                let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
                let (catalog, events) = context.events(&snapshot, None)?;
                let transition = catalog
                    .account_deletions
                    .get(transaction)
                    .ok_or("no anchored account deletion")?;
                if transition.phase == crate::account_transition::Phase::Prepared
                    || !events.iter().any(|event| {
                        event.command
                            == Command::PermitAccountDeletion {
                                transaction: transaction.into(),
                            }
                    })
                    || serde_json::to_value(context.writer(&catalog)?)? != *identity
                {
                    return Err(
                        "deletion file publication lacks its exact committed governed permission"
                            .into(),
                    );
                }
                let guard = crate::account_deletion::Guard::retained(
                    registry_path,
                    &session.binding.identity_path,
                    &transition.intent,
                )?;
                if transition.phase == crate::account_transition::Phase::Complete {
                    guard.complete()?;
                }
                context.recheck(&mut || session.account.identity())?;
                let actor_aging =
                    ActorAging::capture(session, &catalog, store, directory, transaction)?;
                Ok(Self {
                    session,
                    actor_aging: RefCell::new(actor_aging),
                    directory: directory.into(),
                    registry_path: registry_path.into(),
                    guard,
                    catalog,
                    snapshot,
                })
            },
        )
    }

    fn execute<A: Checkpoint>(self, store: &mut Store<A>, file: &str) -> Result<serde_json::Value> {
        let context = Context::load_at(
            &self.directory,
            &self.snapshot.deployment,
            &self.registry_path,
        )?;
        let written = self.guard.publish(file, || {
            if self.session.fenced.get() {
                return Err("deletion continuation is fenced".into());
            }
            if let Some(aging) = self.actor_aging.borrow_mut().as_mut() {
                aging.recheck()?;
            }
            self.session.account.identity()?;
            let current = store.snapshot()?;
            current.clock.elapsed_since(self.session.clock.get())?;
            self.session.clock.set(current.clock);
            if current.head != self.snapshot.head
                || current.deployment != self.snapshot.deployment
                || context.events(&current, None)?.0 != self.catalog
                || serde_json::to_value(context.writer(&self.catalog)?)?
                    != self.session.binding.identity
            {
                return Err("deletion authority changed before file dispatch".into());
            }
            context.recheck(&mut || self.session.account.identity())?;
            if let Some(aging) = self.actor_aging.borrow_mut().as_mut() {
                aging.recheck()?;
            }
            Ok(())
        })?;
        Ok(
            serde_json::json!({"schema_version":1,"action":"admin-account-delete-file",
            "transaction":self.guard.intent.transaction,"file":file,"file_published":true,
            "rename_performed":written,"replayed":!written,"home_data_removed":false,
            "principal_enabled":false,"gate_closing":false}),
        )
    }
}

impl Drop for DeletionAttempt<'_> {
    fn drop(&mut self) {
        self.session.close();
    }
}

pub fn account_deletion_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let base = 4;
    let file_dispatch = args.first().map(String::as_str) == Some("admin-account-delete-file");
    let reviewed = if args.len() == base {
        None
    } else if !file_dispatch && args.len() == base + 2 && args[base] == "--commit" {
        tpm::decode::<32>(&args[base + 1])?;
        Some(args[base + 1].as_str())
    } else {
        return Err("invalid account deletion arguments".into());
    };
    let request = if file_dispatch { &args[2] } else { &args[3] };
    if !admin_roles::identifier(request)
        || request == REQUEST
        || (file_dispatch && !crate::account_deletion::FILES.contains(&args[3].as_str()))
    {
        return Err("invalid deletion request or publication file".into());
    }
    let prepared = prepare_control(&args[1], Some(request))?;
    let account = authentication::local(&args[1])?;
    let directory = Path::new(DIRECTORY);
    let registry_path = Path::new(crate::principal::REGISTRY);
    let identity_path = Path::new(crate::principal::IDENTITY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    if file_dispatch {
        let session =
            prepared.issue(account, &mut store, directory, registry_path, Some(request))?;
        let report =
            DeletionAttempt::prepare(&session, &mut store, directory, registry_path, request)?
                .execute(&mut store, &args[3])?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    let catalog = context.events(&snapshot, Some(request))?.0;
    let command = match args[0].as_str() {
        "admin-account-delete" => {
            let registry = crate::principal::RegistryBinding::capture(registry_path)?;
            let record = registry
                .current()?
                .account(&args[2])
                .ok_or("unknown installation account")?;
            let intent = if let Some(transition) = catalog.account_deletions.get(request) {
                if transition.intent.principal != record.id {
                    return Err("deletion request belongs to another account".into());
                }
                transition.intent.clone()
            } else {
                let generation = catalog
                    .principal_states
                    .get(&record.id)
                    .map_or(record.generation, |state| state.generation);
                crate::account_deletion::Guard::prepare(
                    registry_path,
                    identity_path,
                    &record.login,
                    generation,
                    request,
                )?
                .intent
                .clone()
            };
            registry.current()?;
            Command::PrepareAccountDeletion { intent }
        }
        "admin-account-delete-permit" => Command::PermitAccountDeletion {
            transaction: args[2].clone(),
        },
        "admin-account-delete-complete" => Command::CompleteAccountDeletion {
            transaction: args[2].clone(),
        },
        _ => return Err("unknown account deletion command".into()),
    };
    let report = run_control_at(
        &mut store,
        directory,
        registry_path,
        account,
        prepared,
        None,
        request,
        Some(&command),
        reviewed,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub fn adopt_principals(login: &str, request: &str, reviewed: Option<&str>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let prepared = prepare_control(login, Some(request))?;
    let account = authentication::local(login)?;
    let command = adoption_command(Path::new(crate::principal::REGISTRY))?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let result = run_control_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        account,
        prepared,
        None,
        request,
        Some(&command),
        reviewed,
    );
    println!("{}", serde_json::to_string(&result?)?);
    Ok(())
}

pub fn catalog_status(login: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let prepared = prepare_control(login, None)?;
    let authenticated = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let report = run_control_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        authenticated,
        prepared,
        None,
        "status",
        None,
        None,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub(crate) fn service_request(
    account: authentication::AuthenticatedAccount,
    login: AdminLogin,
    peer: &crate::admin_service::Peer,
    request: &str,
    command: Option<&Command>,
    review: Option<&str>,
) -> Result<serde_json::Value> {
    peer.check()?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    run_control_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        account,
        login,
        Some(peer),
        request,
        command,
        review,
    )
}

// Primitive journal tests exercise replay/refusal without creating a genuine
// session. These adapters are absent from the production executable.
#[cfg(test)]
fn execute_catalog<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    authenticate: impl FnMut() -> Result<serde_json::Value>,
    request: &str,
    command: &Command,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    execute_catalog_at(
        store,
        directory,
        Path::new(crate::principal::REGISTRY),
        authenticate,
        request,
        command,
        reviewed,
    )
}

#[cfg(test)]
fn execute_catalog_at<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    authenticate: impl FnMut() -> Result<serde_json::Value>,
    request: &str,
    command: &Command,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    execute_catalog_authorized_at(
        store,
        directory,
        registry_path,
        Path::new(crate::principal::IDENTITY),
        authenticate,
        request,
        command,
        reviewed,
        CatalogAuthority::Primitive,
    )
}

#[cfg(test)]
struct RotationAttempt<'a> {
    account: &'a authentication::AuthenticatedAccount,
}

#[cfg(test)]
impl Drop for RotationAttempt<'_> {
    fn drop(&mut self) {
        self.account.logout();
    }
}

#[cfg(test)]
pub(crate) fn fixture_prepare_service(
    root: &Path,
    name: &str,
    candidate: Option<&str>,
    peer: &crate::admin_service::Peer,
) -> Result<AdminLogin> {
    peer.observe(|| {
        AdminLogin::prepare_at(
            &mut fixture_store(root)?,
            &root.join("admin"),
            &root.join("registry.json"),
            name,
            candidate,
        )
    })
}

#[cfg(test)]
pub(crate) fn fixture_service_request(
    root: &Path,
    account: authentication::AuthenticatedAccount,
    login: AdminLogin,
    peer: &crate::admin_service::Peer,
    request: &str,
    command: Option<&Command>,
    review: Option<&str>,
) -> Result<serde_json::Value> {
    peer.check()?;
    let directory = root.join("admin");
    let mut store = fixture_store(root)?;
    run_control_at(
        &mut store,
        &directory,
        &root.join("registry.json"),
        account,
        login,
        Some(peer),
        request,
        command,
        review,
    )
}

#[cfg(test)]
fn fixture_store(root: &Path) -> Result<Store<tpm::LocalAnchor>> {
    crate::require_root()?;
    if !Path::new("/.dockerenv").is_file()
        || !root.starts_with("/tmp")
        || !root
            .file_name()
            .ok_or("missing fixture directory")?
            .to_string_lossy()
            .starts_with("luma-tpm-delivery-")
        || Path::new("/dev/tpm0").exists()
        || Path::new("/dev/tpmrm0").exists()
    {
        return Err("fresh disposable governance fixture required".into());
    }
    let directory = root.join("admin");
    let (_, secret) = crate::admin_credentials::load_at(
        &directory,
        &root.join("pcr-public.pem"),
        &root.join("pcr-signature.json"),
        |d, n, p, b, s| crate::owner_credential::fixture_unseal(root, d, n, p, b, s),
    )?;
    let anchor = tpm::LocalAnchor::pending_enrollment_fixture(
        root,
        &secret,
        tpm::exclusive_lock(&root.join("bootstrap.lock"))?,
    )?;
    Store::open(anchor, &directory.join("journal.json"))
}

#[cfg(test)]
pub(crate) fn fixture_rotation_interruption(account: &authentication::AuthenticatedAccount) {
    let _rotation = RotationAttempt { account };
    panic!("deliberate rotation-attempt unwind fixture");
}

#[cfg(test)]
pub(crate) fn fixture_custody_recovery(
    root: &Path,
    password: &crate::sealed_credential::PrivateBuffer,
) {
    use crate::admin_recovery::Credential;
    // fixture_store proves the disposable-container boundary and rejects host
    // devices before any TPM operation. These are PUBLIC fixture credentials.
    let first = Credential::fixture(0x42);
    let second = Credential::fixture(0x43);
    let third = Credential::fixture(0x44);
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let login = {
        let mut store = fixture_store(root).unwrap();
        PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut store, &directory, &registry),
            "human",
        )
        .unwrap()
    };
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    let mut store = fixture_store(root).unwrap();
    let session = PrincipalSession::new(
        account,
        login,
        &mut PrincipalReader::at(&mut store, &directory, &registry),
    )
    .unwrap();
    let before = session
        .identity(&mut PrincipalReader::at(&mut store, &directory, &registry))
        .unwrap();
    let baseline = fs::read(&registry).unwrap();
    assert!(RecoveryAttempt::prepare(
        &mut store,
        &directory,
        &registry,
        &Credential::fixture(0x45),
        &second
    )
    .is_err());
    assert!(RecoveryAttempt::prepare(&mut store, &directory, &registry, &first, &first).is_err());
    println!("OFFLINE_RECOVERY_TPM_CASE=wrong-and-reused-credential-refused");
    let attempt =
        RecoveryAttempt::prepare(&mut store, &directory, &registry, &first, &second).unwrap();
    assert!(execute_catalog_at(
        &mut store,
        &directory,
        &registry,
        || session.account.identity(),
        "fixture-recover-pam",
        &attempt.command,
        None
    )
    .is_err());
    println!("OFFLINE_RECOVERY_TPM_CASE=genuine-pam-not-recovery-proof");
    let inspected = attempt
        .execute(
            &mut store,
            &directory,
            &registry,
            "fixture-offline-recover",
            None,
        )
        .unwrap();
    let committed = attempt
        .execute(
            &mut store,
            &directory,
            &registry,
            "fixture-offline-recover",
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
    assert_eq!(committed["committed"], true);
    assert_eq!(committed["catalog"]["admin_recovery"]["generation"], 2);
    assert_eq!(
        committed["catalog"]["principal_states"][before["principal"].as_str().unwrap()]
            ["generation"],
        before["generation"].as_u64().unwrap() + 1
    );
    println!("OFFLINE_RECOVERY_TPM_CASE=checkpointed-two-generation-rotation");
    assert!(attempt.authenticate().is_err());
    assert!(session
        .identity(&mut PrincipalReader::at(&mut store, &directory, &registry))
        .is_err());
    assert!(session.account.identity().is_err());
    println!("OFFLINE_RECOVERY_TPM_CASE=old-live-session-and-proof-closed");
    assert!(RecoveryAttempt::prepare(&mut store, &directory, &registry, &first, &third).is_err());
    let next =
        RecoveryAttempt::prepare(&mut store, &directory, &registry, &second, &third).unwrap();
    let inspected = next
        .execute(
            &mut store,
            &directory,
            &registry,
            "fixture-offline-recover-next",
            None,
        )
        .unwrap();
    next.execute(
        &mut store,
        &directory,
        &registry,
        "fixture-offline-recover-next",
        Some(inspected["review_sha256"].as_str().unwrap()),
    )
    .unwrap();
    assert!(RecoveryAttempt::prepare(&mut store, &directory, &registry, &second, &first).is_err());
    assert!(RecoveryAttempt::prepare(&mut store, &directory, &registry, &third, &second).is_ok());
    assert_eq!(fs::read(&registry).unwrap(), baseline);
    println!("OFFLINE_RECOVERY_TPM_CASE=old-credentials-consumed-and-baseline-preserved");
}

#[cfg(test)]
pub(crate) fn fixture_session_issuance(
    root: &Path,
    password: &crate::sealed_credential::PrivateBuffer,
) {
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let prepare = |login| {
        let mut store = fixture_store(root).unwrap();
        PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut store, &directory, &registry),
            login,
        )
        .unwrap()
    };
    let read = |account: &authentication::AuthenticatedAccount, login: &PrincipalLogin| {
        let mut store = fixture_store(root).unwrap();
        PrincipalReader::at(&mut store, &directory, &registry).read_account(account, login)
    };
    let commit = |account: &authentication::AuthenticatedAccount, request, command: &Command| {
        let mut store = fixture_store(root).unwrap();
        let inspected = execute_catalog_at(
            &mut store,
            &directory,
            &registry,
            || account.identity(),
            request,
            command,
            None,
        )
        .unwrap();
        execute_catalog_at(
            &mut store,
            &directory,
            &registry,
            || account.identity(),
            request,
            command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    };

    let earlier = authentication::fixture_local_account(root, "human", password).unwrap();
    let login = prepare("human");
    assert!(read(&earlier, &login).is_err());
    assert!(earlier.identity().is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=earlier-pam-refused");

    let login = prepare("human");
    let other = authentication::fixture_local_account(root, "otherhuman", password).unwrap();
    assert!(read(&other, &login).is_err());
    assert!(other.identity().is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=wrong-principal-refused");

    let login = prepare("human");
    let baseline = tpm::private_read(&registry, 64 * 1024).unwrap();
    platform::write_atomic(&registry, &baseline, 0o600).unwrap();
    let replaced = authentication::fixture_local_account(root, "human", password).unwrap();
    assert!(read(&replaced, &login).is_err());
    assert!(replaced.identity().is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=identical-registry-replacement-refused");

    let login = prepare("human");
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    commit(
        &account,
        "login-head-change",
        &Command::RegisterActivity {
            activity: "session.issue.test".into(),
        },
    );
    assert!(read(&account, &login).is_err());
    assert!(account.identity().is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=catalog-head-change-refused");

    let login = prepare("otherhuman");
    let account = authentication::fixture_local_account(root, "otherhuman", password).unwrap();
    let admin = authentication::fixture_local_account(root, "human", password).unwrap();
    let principal = login.binding.identity["principal"]
        .as_str()
        .unwrap()
        .to_owned();
    let generation = login.binding.identity["generation"].as_u64().unwrap();
    let disabled = commit(
        &admin,
        "login-disable",
        &Command::AdvancePrincipal {
            principal: principal.clone(),
            expected_generation: generation,
            enabled: false,
        },
    );
    assert!(read(&account, &login).is_err());
    assert!(account.identity().is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=disable-during-login-refused");

    let generation = disabled["catalog"]["principal_states"][&principal]["generation"]
        .as_u64()
        .unwrap();
    let enabled = commit(
        &admin,
        "login-enable",
        &Command::AdvancePrincipal {
            principal: principal.clone(),
            expected_generation: generation,
            enabled: true,
        },
    );
    admin.logout();
    assert!(read(&account, &login).is_err());
    println!("GOVERNED_SESSION_ISSUANCE_CASE=reenabling-does-not-revive-login");

    let session = fixture_governed_session(root, "otherhuman", password).unwrap();
    assert_eq!(
        fixture_governed_identity(root, &session).unwrap()["generation"],
        enabled["catalog"]["principal_states"][&principal]["generation"]
    );
    session.close();
    assert!(fixture_governed_identity(root, &session).is_err());
    assert_eq!(tpm::private_read(&registry, 64 * 1024).unwrap(), baseline);
    println!("GOVERNED_SESSION_ISSUANCE_CASE=fresh-login-binds-new-generation-and-closes");
}

#[cfg(test)]
pub(crate) fn fixture_owned_catalog(
    root: &Path,
    password: &crate::sealed_credential::PrivateBuffer,
) {
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let baseline = tpm::private_read(&registry, 64 * 1024).unwrap();
    let prepare = |candidate: Option<&str>| {
        AdminLogin::prepare_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            "human",
            candidate,
        )
        .unwrap()
    };
    let run = |request: &str, command: Option<&Command>, review: Option<&str>| {
        let login = prepare(command.map(|_| request));
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        run_control_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            account,
            login,
            None,
            request,
            command,
            review,
        )
    };
    let status = run("owned-status", None, None).unwrap();
    assert_eq!(status["effect_grant"], false);
    assert_eq!(
        status["principal"]["generation"],
        status["catalog"]["principal_states"][status["principal"]["principal"].as_str().unwrap()]
            ["generation"]
    );
    println!("GOVERNED_CATALOG_CASE=status-current-generation");
    let command = Command::RegisterActivity {
        activity: "owned.catalog.test".into(),
    };
    let earlier = authentication::fixture_local_account(root, "human", password).unwrap();
    let login = prepare(Some("owned-earlier"));
    assert!(run_control_at(
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        earlier,
        login,
        None,
        "owned-earlier",
        Some(&command),
        None
    )
    .is_err());
    println!("GOVERNED_CATALOG_CASE=earlier-pam-refused");
    let login = prepare(Some("owned-other"));
    let account = authentication::fixture_local_account(root, "otherhuman", password).unwrap();
    assert!(run_control_at(
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        account,
        login,
        None,
        "owned-other",
        Some(&command),
        None
    )
    .is_err());
    println!("GOVERNED_CATALOG_CASE=wrong-principal-refused");
    let login = prepare(Some("owned-original"));
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    assert!(run_control_at(
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        account,
        login,
        None,
        "owned-switched",
        Some(&command),
        None
    )
    .is_err());
    println!("GOVERNED_CATALOG_CASE=request-scope-switch-refused");
    let login = prepare(Some("owned-replaced"));
    platform::write_atomic(&registry, &baseline, 0o600).unwrap();
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    assert!(run_control_at(
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        account,
        login,
        None,
        "owned-replaced",
        Some(&command),
        None
    )
    .is_err());
    println!("GOVERNED_CATALOG_CASE=registry-replacement-refused");
    let stale_login = prepare(Some("owned-stale"));
    let inspected = run("owned-register", Some(&command), None).unwrap();
    assert_eq!(inspected["tpm_write_performed"], false);
    assert_eq!(
        run("owned-status", None, None).unwrap()["checkpoint_head"],
        status["checkpoint_head"]
    );
    println!("GOVERNED_CATALOG_CASE=inspection-does-not-write");
    assert!(run("owned-register", Some(&command), Some(&"00".repeat(32))).is_err());
    assert_eq!(
        run("owned-status", None, None).unwrap()["checkpoint_head"],
        status["checkpoint_head"]
    );
    println!("GOVERNED_CATALOG_CASE=wrong-review-refused");
    let committed = run(
        "owned-register",
        Some(&command),
        Some(inspected["review_sha256"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(committed["tpm_write_performed"], true);
    assert_ne!(
        run("owned-status", None, None).unwrap()["checkpoint_head"],
        status["checkpoint_head"]
    );
    println!("GOVERNED_CATALOG_CASE=reviewed-commit");
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    assert!(run_control_at(
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        account,
        stale_login,
        None,
        "owned-stale",
        Some(&command),
        None
    )
    .is_err());
    println!("GOVERNED_CATALOG_CASE=changed-head-refused");
    let replay = run("owned-register", Some(&command), None).unwrap();
    assert_eq!(replay["replayed"], true);
    let replay = run(
        "owned-register",
        Some(&command),
        Some(replay["review_sha256"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(replay["tpm_write_performed"], false);
    println!("GOVERNED_CATALOG_CASE=replay-does-not-extend");
    let no_op = run("owned-no-op", Some(&command), None).unwrap();
    assert_eq!(
        run(
            "owned-no-op",
            Some(&command),
            Some(no_op["review_sha256"].as_str().unwrap())
        )
        .unwrap()["tpm_write_performed"],
        false
    );
    println!("GOVERNED_CATALOG_CASE=no-op-does-not-extend");
    let login = prepare(Some("owned-consumed"));
    let account = authentication::fixture_local_account(root, "human", password).unwrap();
    let mut store = fixture_store(root).unwrap();
    let session = login
        .issue(
            account,
            &mut store,
            &directory,
            &registry,
            Some("owned-consumed"),
        )
        .unwrap();
    let attempt = CatalogAttempt::prepare(
        &session,
        &mut store,
        &directory,
        &registry,
        "owned-consumed",
        &command,
        None,
    )
    .unwrap();
    assert!(attempt
        .check_boundary(
            &store.snapshot().unwrap(),
            &directory,
            &registry,
            "owned-switched",
            &command
        )
        .is_err());
    let different = Command::RegisterActivity {
        activity: "owned.other.test".into(),
    };
    assert!(attempt
        .check_boundary(
            &store.snapshot().unwrap(),
            &directory,
            &registry,
            "owned-consumed",
            &different
        )
        .is_err());
    attempt.execute(&mut store, None).unwrap();
    assert!(session.account.identity().is_err());
    assert!(session
        .identity(&mut PrincipalReader::admin_at(
            &mut store,
            &directory,
            &registry,
            Some("owned-consumed")
        ))
        .is_err());
    println!("GOVERNED_CATALOG_CASE=exact-continuation-consumed");
    drop(store);
    for fault in [
        "wrong-review",
        "unwind",
        "registry",
        "logout",
        "clock-floor",
        "epoch",
    ] {
        let request = format!("owned-fault-{fault}");
        let login = prepare(Some(&request));
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        let mut store = fixture_store(root).unwrap();
        let session = login
            .issue(account, &mut store, &directory, &registry, Some(&request))
            .unwrap();
        let attempt = CatalogAttempt::prepare(
            &session, &mut store, &directory, &registry, &request, &different, None,
        )
        .unwrap();
        let before = tpm::private_read(&directory.join("journal.json"), 1024 * 1024).unwrap();
        match fault {
            "registry" => platform::write_atomic(&registry, &baseline, 0o600).unwrap(),
            "logout" => session.account.logout(),
            "clock-floor" => {
                // Inject a later in-process floor, not a host or TPM clock change.
                let mut clock = session.clock.get();
                clock.milliseconds = clock.milliseconds.checked_add(1_000_000).unwrap();
                session.clock.set(clock);
            }
            "epoch" => {
                let mut clock = session.clock.get();
                clock.restart_count = clock.restart_count.checked_add(1).unwrap();
                session.clock.set(clock);
            }
            "wrong-review" | "unwind" => (),
            _ => unreachable!(),
        }
        if fault == "unwind" {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _attempt = attempt;
                    panic!("deliberate catalog continuation unwind fixture");
                }))
                .is_err()
            );
        } else {
            assert!(attempt.execute(&mut store, Some(&"00".repeat(32))).is_err());
        }
        assert!(session.account.identity().is_err());
        assert!(session.fenced.get());
        assert_eq!(
            tpm::private_read(&directory.join("journal.json"), 1024 * 1024).unwrap(),
            before
        );
        assert!(!directory.join("journal.pending.json").exists());
        println!("GOVERNED_CATALOG_CASE=continuation-fault-{fault}-closes-without-write");
    }
    let general = fixture_governed_session(root, "human", password).unwrap();
    assert!(CatalogAttempt::prepare(
        &general,
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        "owned-general",
        &command,
        None
    )
    .is_err());
    general.close();
    assert_eq!(tpm::private_read(&registry, 64 * 1024).unwrap(), baseline);
    println!("GOVERNED_CATALOG_CASE=general-session-cannot-be-catalog-authority");
}

#[cfg(test)]
pub(crate) fn fixture_account_checkpoint(
    root: &Path,
    password: &crate::sealed_credential::PrivateBuffer,
) {
    // fixture_store verifies the disposable existing-owner/software-TPM boundary
    // before any account observation or fixture mutation. No host TPM is accepted.
    drop(fixture_store(root).unwrap());
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let run = |request: &str, command: &Command, reviewed: Option<&str>| {
        let login = AdminLogin::prepare_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            "human",
            Some(request),
        )
        .unwrap();
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        run_control_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            account,
            login,
            None,
            request,
            Some(command),
            reviewed,
        )
    };
    let command = account_checkpoint_command(&registry).unwrap();
    let inspected = run("account-credentials", &command, None).unwrap();
    assert_eq!(inspected["tpm_write_performed"], false);
    let command_json = serde_json::to_string(&command).unwrap();
    assert!(!command_json.contains('$'));
    println!("ACCOUNT_CHECKPOINT_CASE=protected-inspection-no-credential-disclosure");
    let committed = run(
        "account-credentials",
        &command,
        Some(inspected["review_sha256"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(committed["tpm_write_performed"], true);
    assert_eq!(
        committed["catalog"]["account_commitments"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    println!("ACCOUNT_CHECKPOINT_CASE=reviewed-complete-checkpoint");
    let replay = run("account-credentials", &command, None).unwrap();
    assert_eq!(
        run(
            "account-credentials",
            &command,
            Some(replay["review_sha256"].as_str().unwrap())
        )
        .unwrap()["tpm_write_performed"],
        false
    );
    println!("ACCOUNT_CHECKPOINT_CASE=replay-without-second-extend");
    let no_op = run("account-same", &command, None).unwrap();
    assert_eq!(
        run(
            "account-same",
            &command,
            Some(no_op["review_sha256"].as_str().unwrap())
        )
        .unwrap()["tpm_write_performed"],
        false
    );
    println!("ACCOUNT_CHECKPOINT_CASE=identical-new-request-no-op");
    let prior = fixture_governed_session(root, "otherhuman", password).unwrap();
    assert!(prior.binding.credential_sha256.is_some());
    println!("ACCOUNT_CHECKPOINT_CASE=fresh-pam-session-binds-anchored-credential");
    // Hash/aging rows stay in locked storage, including this private fixture.
    let mut file = File::open("/etc/shadow").unwrap();
    let size = usize::try_from(file.metadata().unwrap().len()).unwrap();
    assert!(size <= 16 * 1024);
    let mut original = crate::sealed_credential::PrivateBuffer::new(size).unwrap();
    std::io::Read::read_exact(&mut file, original.bytes_mut()).unwrap();
    for name in ["otherhuman", "human"] {
        let mut changed = crate::sealed_credential::PrivateBuffer::new(size).unwrap();
        changed.bytes_mut().copy_from_slice(original.bytes());
        let mut offset = 0;
        let mut position = None;
        for row in std::str::from_utf8(original.bytes())
            .unwrap()
            .split_inclusive('\n')
        {
            if row.starts_with(&format!("{name}:")) {
                let fields: Vec<_> = row.trim_end().split(':').collect();
                assert_eq!(fields.len(), 9);
                let days_offset = fields[..4]
                    .iter()
                    .map(|field| field.len() + 1)
                    .sum::<usize>();
                assert!(!fields[4].is_empty());
                position = Some(offset + days_offset + fields[4].len() - 1);
            }
            offset += row.len();
        }
        let position = position.unwrap();
        changed.bytes_mut()[position] = if changed.bytes()[position] == b'9' {
            b'8'
        } else {
            b'9'
        };
        platform::write_atomic(Path::new("/etc/shadow"), changed.bytes(), 0o600).unwrap();
        let local = authentication::fixture_local_account(root, name, password).unwrap();
        assert!(local.identity().is_ok());
        local.logout();
        assert!(fixture_governed_session(root, name, password).is_err());
        println!("ACCOUNT_CHECKPOINT_CASE=fresh-pam-cannot-adopt-{name}-credential-drift");
        if name == "otherhuman" {
            assert!(fixture_governed_identity(root, &prior).is_err());
            let changed_command = account_checkpoint_command(&registry).unwrap();
            assert!(run("account-rebind", &changed_command, None).is_err());
            assert!(!directory.join(event_name("account-rebind")).exists());
            println!("ACCOUNT_CHECKPOINT_CASE=ordinary-admin-cannot-silently-rebind-credential");
        }
        platform::write_atomic(Path::new("/etc/shadow"), original.bytes(), 0o600).unwrap();
        let restored = fixture_governed_session(root, name, password).unwrap();
        assert!(restored.binding.credential_sha256.is_some());
        restored.close();
    }
    assert!(fixture_governed_identity(root, &prior).is_err());
    println!("ACCOUNT_CHECKPOINT_CASE=restoration-does-not-revive-old-session");
    let enrollment = account_checkpoint_command(&registry).unwrap();
    let rotate = Command::RotateAdmin {
        expected_generation: committed["proposal"]["principal"]["generation"]
            .as_u64()
            .unwrap(),
    };
    let inspected = run("account-epoch-rotation", &rotate, None).unwrap();
    assert_eq!(
        run(
            "account-epoch-rotation",
            &rotate,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .unwrap()["tpm_write_performed"],
        true
    );
    assert_eq!(account_checkpoint_command(&registry).unwrap(), enrollment);
    let fresh = fixture_governed_session(root, "human", password).unwrap();
    assert!(fresh.binding.credential_sha256.is_some());
    fresh.close();
    println!("ACCOUNT_CHECKPOINT_CASE=principal-rotation-preserves-credential-checkpoint");
    fixture_account_lock(root, password);
    fixture_account_password(root, password);
    fixture_account_deletion(root, password);
    fixture_account_creation(root, password);
}

#[cfg(test)]
fn fixture_account_creation(root: &Path, password: &crate::sealed_credential::PrivateBuffer) {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    drop(fixture_store(root).unwrap());
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let identity = Path::new("/etc");
    let homes = creation_homes(identity);
    fs::DirBuilder::new().mode(0o700).create(&homes).unwrap();
    let baseline = crate::principal::RegistryBinding::capture(&registry)
        .unwrap()
        .current()
        .unwrap()
        .clone();
    let old_admin = fixture_governed_session(root, "human", password).unwrap();
    let secret = crate::account_password::Password::fixture(password).unwrap();
    let propose = |typed: Option<&crate::account_password::Password>, review: Option<&str>| {
        let mut store = fixture_store(root)?;
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry,
            "human",
            Some("create-new"),
        )?;
        let account = authentication::fixture_local_account(root, "human", password)?;
        let session = login.issue(
            account,
            &mut store,
            &directory,
            &registry,
            Some("create-new"),
        )?;
        let command = creation_proposal(
            &session,
            &mut store,
            &directory,
            &registry,
            identity,
            "newhuman",
            "create-new",
            typed,
        )?;
        let report = CatalogAttempt::prepare(
            &session,
            &mut store,
            &directory,
            &registry,
            "create-new",
            &command,
            None,
        )?
        .execute(&mut store, review);
        report
    };
    let proposal = propose(Some(&secret), None).unwrap();
    let intent = crate::account_creation::retained_intent(identity, "create-new")
        .unwrap()
        .unwrap();
    assert_eq!(proposal["tpm_write_performed"], false);
    assert!(!serde_json::to_string(&proposal).unwrap().contains('$'));
    assert!(!homes.join("newhuman").exists());
    assert!(propose(None, Some(&"00".repeat(32))).is_err());
    println!("ACCOUNT_CREATION_CASE=owned-pam-retains-exact-private-proposal-without-disclosure-or-publication");
    let run = |request: &str, command: &Command, review: Option<&str>| {
        let mut store = fixture_store(root)?;
        let login =
            AdminLogin::prepare_at(&mut store, &directory, &registry, "human", Some(request))?;
        let account = authentication::fixture_local_account(root, "human", password)?;
        run_control_at(
            &mut store,
            &directory,
            &registry,
            account,
            login,
            None,
            request,
            Some(command),
            review,
        )
    };
    let commit = |request: &str, command: &Command| {
        let proposal = run(request, command, None).unwrap();
        run(
            request,
            command,
            Some(proposal["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    };
    let publish = |file: &str| {
        let mut store = fixture_store(root)?;
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry,
            "human",
            Some("create-new"),
        )?;
        let account = authentication::fixture_local_account(root, "human", password)?;
        let session = login.issue(
            account,
            &mut store,
            &directory,
            &registry,
            Some("create-new"),
        )?;
        let result =
            CreationAttempt::prepare(&session, &mut store, &directory, &registry, "create-new")?
                .execute(&mut store, file);
        assert!(session.fenced.get());
        assert!(session.account.identity().is_err());
        result
    };
    assert!(publish("home").is_err());
    let prepared = propose(None, Some(proposal["review_sha256"].as_str().unwrap())).unwrap();
    assert_eq!(
        prepared["catalog"]["principal_states"][&intent.principal.id]["enabled"],
        false
    );
    assert!(publish("home").is_err());
    let complete = Command::CompleteAccountCreation {
        transaction: "create-new".into(),
    };
    assert!(run("create-early-complete", &complete, None).is_err());
    commit(
        "create-permit",
        &Command::PermitAccountCreation {
            transaction: "create-new".into(),
        },
    );
    assert!(publish("registry").is_err());
    println!("ACCOUNT_CREATION_CASE=committed-preparation-and-permission-fence-before-home-and-identity-dispatch");
    let general = fixture_governed_session(root, "human", password).unwrap();
    assert!(CreationAttempt::prepare(
        &general,
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry,
        "create-new"
    )
    .is_err());
    general.close();
    println!("ACCOUNT_CREATION_CASE=general-pam-session-cannot-dispatch-creation");
    for fault in ["closed", "clock-floor", "epoch", "head"] {
        let mut store = fixture_store(root).unwrap();
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry,
            "human",
            Some("create-new"),
        )
        .unwrap();
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        let session = login
            .issue(
                account,
                &mut store,
                &directory,
                &registry,
                Some("create-new"),
            )
            .unwrap();
        let attempt =
            CreationAttempt::prepare(&session, &mut store, &directory, &registry, "create-new")
                .unwrap();
        match fault {
            "closed" => session.close(),
            "clock-floor" => {
                let mut clock = session.clock.get();
                clock.milliseconds += 1_000_000;
                session.clock.set(clock);
            }
            "epoch" => {
                let mut clock = session.clock.get();
                clock.restart_count += 1;
                session.clock.set(clock);
            }
            "head" => {
                drop(store);
                commit(
                    "create-head-change",
                    &Command::RegisterActivity {
                        activity: "account.create.fixture".into(),
                    },
                );
                store = fixture_store(root).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(attempt.execute(&mut store, "home").is_err());
        assert!(session.fenced.get());
        assert!(!homes.join("newhuman").exists());
        println!("ACCOUNT_CREATION_CASE={fault}-continuation-closes-without-dispatch");
    }
    for (index, file) in ["home"]
        .into_iter()
        .chain(crate::account_creation::FILES)
        .enumerate()
    {
        assert_eq!(publish(file).unwrap()["rename_performed"], true);
        let path = if file == "home" {
            homes.join("newhuman")
        } else if file == "registry" {
            registry.clone()
        } else {
            identity.join(file)
        };
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert_eq!(publish(file).unwrap()["rename_performed"], false);
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        assert!(authentication::fixture_local_account(root, "newhuman", password).is_err());
        assert!(fixture_governed_session(root, "newhuman", password).is_err());
        assert!(fixture_governed_session(root, "human", password).is_ok());
        if index < 5 {
            assert!(run("create-early-complete", &complete, None).is_err());
        }
        println!("ACCOUNT_CREATION_CASE={file}-fresh-owned-pam-publication-and-replay-without-second-rename");
    }
    assert!(fixture_governed_identity(root, &old_admin).is_err());
    let completed = commit("create-complete", &complete);
    assert_eq!(
        completed["catalog"]["principal_registry"],
        serde_json::to_value(&baseline).unwrap()
    );
    assert_eq!(
        completed["catalog"]["current_registry"],
        serde_json::to_value(&intent.registry_after).unwrap()
    );
    assert_eq!(
        completed["catalog"]["principal_states"][&intent.principal.id]["enabled"],
        false
    );
    assert!(run(
        "create-enable-bypass",
        &Command::AdvancePrincipal {
            principal: intent.principal.id.clone(),
            expected_generation: 1,
            enabled: true
        },
        None
    )
    .is_err());
    let unlock = crate::account_transition::Guard::prepare(
        &registry,
        identity,
        "newhuman",
        1,
        "create-unlock-bypass",
        false,
    )
    .unwrap()
    .intent
    .clone();
    assert!(run(
        "create-unlock-bypass",
        &Command::PrepareAccountLock { intent: unlock },
        None
    )
    .is_err());
    assert_eq!(commit("create-complete", &complete)["replayed"], true);
    assert_eq!(publish("registry").unwrap()["rename_performed"], false);
    println!("ACCOUNT_CREATION_CASE=completed-exact-registry-extension-remains-locked-and-refuses-aging-bypass");
}

#[cfg(test)]
fn fixture_account_deletion(root: &Path, password: &crate::sealed_credential::PrivateBuffer) {
    use std::os::unix::fs::MetadataExt;
    // This final fixture removes only the otherhuman account that its parent
    // created inside the disposable container, after verifying the software TPM.
    drop(fixture_store(root).unwrap());
    let directory = root.join("admin");
    let registry_path = root.join("registry.json");
    let registry = crate::principal::RegistryBinding::capture(&registry_path).unwrap();
    let record = registry.current().unwrap().account("otherhuman").unwrap();
    let baseline = tpm::private_read(&registry_path, 65536).unwrap();
    let mut store = fixture_store(root).unwrap();
    let snapshot = store.snapshot().unwrap();
    let context = Context::load_at(&directory, &snapshot.deployment, &registry_path).unwrap();
    let catalog = context.events(&snapshot, None).unwrap().0;
    drop(store);
    let generation = catalog
        .principal_states
        .get(&record.id)
        .map_or(record.generation, |state| state.generation);
    let prior = fixture_governed_session(root, "otherhuman", password).unwrap();
    let guard = crate::account_deletion::Guard::prepare(
        &registry_path,
        Path::new("/etc"),
        "otherhuman",
        generation,
        "delete-other",
    )
    .unwrap();
    let intent = guard.intent.clone();
    drop(guard);
    let run = |request: &str, command: &Command, review: Option<&str>| {
        let mut store = fixture_store(root).unwrap();
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry_path,
            "human",
            Some(request),
        )?;
        let account = authentication::fixture_local_account(root, "human", password)?;
        run_control_at(
            &mut store,
            &directory,
            &registry_path,
            account,
            login,
            None,
            request,
            Some(command),
            review,
        )
    };
    let commit = |request: &str, command: &Command| {
        let proposal = run(request, command, None).unwrap();
        run(
            request,
            command,
            Some(proposal["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    };
    let publish = |name: &str| {
        let mut store = fixture_store(root).unwrap();
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry_path,
            "human",
            Some("delete-other"),
        )?;
        let account = authentication::fixture_local_account(root, "human", password)?;
        let session = login.issue(
            account,
            &mut store,
            &directory,
            &registry_path,
            Some("delete-other"),
        )?;
        let attempt = DeletionAttempt::prepare(
            &session,
            &mut store,
            &directory,
            &registry_path,
            "delete-other",
        )?;
        attempt.execute(&mut store, name)
    };
    let prepare = Command::PrepareAccountDeletion {
        intent: intent.clone(),
    };
    let permit = Command::PermitAccountDeletion {
        transaction: intent.transaction.clone(),
    };
    let complete = Command::CompleteAccountDeletion {
        transaction: intent.transaction.clone(),
    };
    let proposal = run("delete-other", &prepare, None).unwrap();
    assert!(!Path::new("/etc/account-deletion-delete-other").exists());
    assert!(run("delete-other", &prepare, Some(&"00".repeat(32))).is_err());
    assert!(publish("shadow").is_err());
    println!("ACCOUNT_DELETION_CASE=inspection-wrong-review-and-unprepared-dispatch-no-write");
    let prepared = run(
        "delete-other",
        &prepare,
        Some(proposal["review_sha256"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        prepared["catalog"]["principal_states"][&intent.principal]["generation"],
        generation + 1
    );
    assert_eq!(
        prepared["catalog"]["principal_states"][&intent.principal]["enabled"],
        false
    );
    assert!(fixture_governed_identity(root, &prior).is_err());
    assert!(authentication::fixture_local_account(root, "otherhuman", password).is_ok());
    assert!(fixture_governed_session(root, "otherhuman", password).is_err());
    assert!(publish("shadow").is_err());
    assert!(run("early-delete-complete", &complete, None).is_err());
    println!(
        "ACCOUNT_DELETION_CASE=prepare-fences-old-and-new-sessions-before-identity-publication"
    );
    commit("delete-permit", &permit);
    assert!(publish("passwd").is_err());
    assert!(run("early-delete-complete", &complete, None).is_err());
    println!("ACCOUNT_DELETION_CASE=committed-permission-does-not-publish-or-complete-files");
    let general = fixture_governed_session(root, "human", password).unwrap();
    assert!(DeletionAttempt::prepare(
        &general,
        &mut fixture_store(root).unwrap(),
        &directory,
        &registry_path,
        "delete-other"
    )
    .is_err());
    general.close();
    println!("ACCOUNT_DELETION_CASE=general-pam-session-is-not-deletion-dispatch-authority");
    for fault in ["closed", "expired", "epoch", "changed-head"] {
        let mut store = fixture_store(root).unwrap();
        let login = AdminLogin::prepare_at(
            &mut store,
            &directory,
            &registry_path,
            "human",
            Some("delete-other"),
        )
        .unwrap();
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        let session = login
            .issue(
                account,
                &mut store,
                &directory,
                &registry_path,
                Some("delete-other"),
            )
            .unwrap();
        let attempt = DeletionAttempt::prepare(
            &session,
            &mut store,
            &directory,
            &registry_path,
            "delete-other",
        )
        .unwrap();
        match fault {
            "closed" => session.close(),
            "expired" => {
                let mut clock = session.clock.get();
                clock.milliseconds += 1_000_000;
                session.clock.set(clock);
            }
            "epoch" => {
                let mut clock = session.clock.get();
                clock.restart_count += 1;
                session.clock.set(clock);
            }
            "changed-head" => {
                drop(store);
                commit(
                    "delete-head-change",
                    &Command::RegisterActivity {
                        activity: "account.delete.fault".into(),
                    },
                );
                store = fixture_store(root).unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata("/etc/shadow").unwrap().ino();
        assert!(attempt.execute(&mut store, "shadow").is_err());
        assert!(session.fenced.get());
        assert!(session.account.identity().is_err());
        assert_eq!(fs::symlink_metadata("/etc/shadow").unwrap().ino(), before);
        assert!(!Path::new("/etc/account-deletion-delete-other/shadow.next").exists());
        println!("ACCOUNT_DELETION_CASE={fault}-continuation-closes-without-dispatch");
    }
    for (index, name) in crate::account_deletion::FILES.into_iter().enumerate() {
        let report = publish(name).unwrap();
        assert_eq!(report["rename_performed"], true);
        let inode = fs::symlink_metadata(Path::new("/etc").join(name))
            .unwrap()
            .ino();
        let replay = publish(name).unwrap();
        assert_eq!(replay["rename_performed"], false);
        assert_eq!(
            fs::symlink_metadata(Path::new("/etc").join(name))
                .unwrap()
                .ino(),
            inode
        );
        assert!(authentication::fixture_local_account(root, "otherhuman", password).is_err());
        assert!(fixture_governed_session(root, "otherhuman", password).is_err());
        if index < 3 {
            assert!(run("early-delete-complete", &complete, None).is_err());
        }
        assert!(fixture_governed_session(root, "human", password).is_ok());
        assert_eq!(tpm::private_read(&registry_path, 65536).unwrap(), baseline);
        println!(
            "ACCOUNT_DELETION_CASE={name}-fresh-owned-pam-publication-and-replay-no-second-rename"
        );
    }
    let completed = commit("delete-complete", &complete);
    assert_eq!(
        completed["catalog"]["principal_states"][&intent.principal]["enabled"],
        false
    );
    assert!(completed["catalog"]["deleted_principals"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(intent.principal)));
    let advance = Command::AdvancePrincipal {
        principal: intent.principal.clone(),
        expected_generation: generation + 1,
        enabled: true,
    };
    assert!(run("revive-deleted", &advance, None).is_err());
    assert_eq!(commit("delete-complete", &complete)["replayed"], true);
    assert_eq!(publish("passwd").unwrap()["rename_performed"], false);
    assert!(fixture_governed_identity(root, &prior).is_err());
    assert_eq!(tpm::private_read(&registry_path, 65536).unwrap(), baseline);
    println!("ACCOUNT_DELETION_CASE=completed-tombstone-reserves-identity-and-never-reenables");
}

#[cfg(test)]
fn fixture_account_password(root: &Path, admin_password: &crate::sealed_credential::PrivateBuffer) {
    use crate::{account_password::Password, sealed_credential::PrivateBuffer};
    use std::os::unix::fs::MetadataExt;
    drop(fixture_store(root).unwrap());
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let mut replacement = PrivateBuffer::new(1025).unwrap();
    let value = b"Strong replacement fixture account password 2026";
    replacement.bytes_mut()[..value.len()].copy_from_slice(value);
    let prior = fixture_governed_session(root, "otherhuman", admin_password).unwrap();
    let propose = |transaction: &str, password: Option<&Password>, review: Option<&str>| {
        let login = AdminLogin::prepare_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            "human",
            Some(transaction),
        )?;
        let account = authentication::fixture_local_account(root, "human", admin_password)?;
        let mut store = fixture_store(root)?;
        let session = login.issue(
            account,
            &mut store,
            &directory,
            &registry,
            Some(transaction),
        )?;
        let command = password_proposal(
            &session,
            &mut store,
            &directory,
            &registry,
            Path::new("/etc"),
            "otherhuman",
            transaction,
            password,
        )?;
        let attempt = CatalogAttempt::prepare(
            &session,
            &mut store,
            &directory,
            &registry,
            transaction,
            &command,
            None,
        )?;
        attempt.execute(&mut store, review)
    };
    let run = |request: &str, command: &Command, review: Option<&str>| {
        let login = AdminLogin::prepare_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            "human",
            Some(request),
        )?;
        let account = authentication::fixture_local_account(root, "human", admin_password)?;
        run_control_at(
            &mut fixture_store(root)?,
            &directory,
            &registry,
            account,
            login,
            None,
            request,
            Some(command),
            review,
        )
    };
    let commit = |request: &str, command: &Command| {
        let inspected = run(request, command, None).unwrap();
        run(
            request,
            command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    };
    for (transaction, new_password, old_password) in [
        ("account-password-replace", &replacement, admin_password),
        ("account-password-restore", admin_password, &replacement),
    ] {
        let secret = Password::fixture(new_password).unwrap();
        let inode = fs::symlink_metadata("/etc/shadow").unwrap().ino();
        let original = crate::principal::account_file(Path::new("/etc/shadow"), true)
            .unwrap()
            .0;
        let inspected = propose(transaction, Some(&secret), None).unwrap();
        assert_eq!(inspected["tpm_write_performed"], false);
        assert_eq!(fs::symlink_metadata("/etc/shadow").unwrap().ino(), inode);
        assert_eq!(
            crate::principal::account_file(Path::new("/etc/shadow"), true)
                .unwrap()
                .0
                .bytes(),
            original.bytes()
        );
        let intent = crate::account_transition::retained_intent(Path::new("/etc"), transaction)
            .unwrap()
            .unwrap();
        assert_eq!(intent.kind, Some(crate::account_transition::Kind::Password));
        assert!(!serde_json::to_string(&inspected).unwrap().contains("$y$"));
        let repeated = propose(transaction, None, None).unwrap();
        assert_eq!(inspected["review_sha256"], repeated["review_sha256"]);
        assert!(propose(transaction, None, Some(&"00".repeat(32))).is_err());
        assert_eq!(fs::symlink_metadata("/etc/shadow").unwrap().ino(), inode);
        println!(
            "ACCOUNT_PASSWORD_CASE={transaction}-private-stable-proposal-no-password-publication"
        );
        let prepared = propose(
            transaction,
            None,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            prepared["catalog"]["principal_states"][&intent.principal]["enabled"],
            false
        );
        assert!(fixture_governed_session(root, "otherhuman", old_password).is_err());
        assert!(fixture_governed_session(root, "otherhuman", new_password).is_err());
        println!("ACCOUNT_PASSWORD_CASE={transaction}-prepare-fences-both-passwords");
        let complete = Command::CompleteAccountLock {
            transaction: transaction.into(),
        };
        assert!(run(&format!("{transaction}-early"), &complete, None).is_err());
        let publish = Command::PermitAccountPublication {
            transaction: transaction.into(),
        };
        let publication = format!("{transaction}-publish");
        commit(&publication, &publish);
        let published_inode = fs::symlink_metadata("/etc/shadow").unwrap().ino();
        assert_ne!(published_inode, inode);
        assert!(fixture_governed_session(root, "otherhuman", new_password).is_err());
        let replay = commit(&publication, &publish);
        assert_eq!(replay["tpm_write_performed"], false);
        assert_eq!(
            fs::symlink_metadata("/etc/shadow").unwrap().ino(),
            published_inode
        );
        println!(
            "ACCOUNT_PASSWORD_CASE={transaction}-publication-fenced-and-replay-no-second-rename"
        );
        let completed = commit(&format!("{transaction}-complete"), &complete);
        assert_eq!(
            completed["catalog"]["principal_states"][&intent.principal]["enabled"],
            true
        );
        assert_eq!(
            completed["catalog"]["principal_states"][&intent.principal]["generation"],
            intent.expected_generation + 1
        );
        assert!(authentication::fixture_local_account(root, "otherhuman", old_password).is_err());
        let fresh = fixture_governed_session(root, "otherhuman", new_password).unwrap();
        fresh.close();
        assert!(fixture_governed_identity(root, &prior).is_err());
        println!("ACCOUNT_PASSWORD_CASE={transaction}-new-password-pam-and-governed-generation-old-password-refused");
    }
    assert!(fixture_governed_identity(root, &prior).is_err());
    println!("ACCOUNT_PASSWORD_CASE=restoring-password-does-not-revive-old-session");
}

#[cfg(test)]
fn fixture_account_lock(root: &Path, password: &crate::sealed_credential::PrivateBuffer) {
    use std::os::unix::fs::MetadataExt;
    drop(fixture_store(root).unwrap());
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    let run = |request: &str, command: &Command, review: Option<&str>| {
        let login = AdminLogin::prepare_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            "human",
            Some(request),
        )
        .unwrap();
        let account = authentication::fixture_local_account(root, "human", password).unwrap();
        run_control_at(
            &mut fixture_store(root).unwrap(),
            &directory,
            &registry,
            account,
            login,
            None,
            request,
            Some(command),
            review,
        )
    };
    let commit = |request: &str, command: &Command| {
        let inspected = run(request, command, None).unwrap();
        run(
            request,
            command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    };
    let original = crate::principal::account_file(Path::new("/etc/shadow"), true)
        .unwrap()
        .0;
    let prior = fixture_governed_session(root, "otherhuman", password).unwrap();
    for (transaction, locked) in [
        ("account-lock-transaction", true),
        ("account-unlock-transaction", false),
    ] {
        let mut store = fixture_store(root).unwrap();
        let snapshot = store.snapshot().unwrap();
        let catalog = Context::load_at(&directory, &snapshot.deployment, &registry)
            .unwrap()
            .events(&snapshot, None)
            .unwrap()
            .0;
        drop(store);
        let baseline = crate::principal::RegistryBinding::capture(&registry).unwrap();
        let principal = baseline.current().unwrap().account("otherhuman").unwrap();
        let generation = catalog
            .principal_states
            .get(&principal.id)
            .map_or(principal.generation, |state| state.generation);
        let guard = crate::account_transition::Guard::prepare(
            &registry,
            Path::new("/etc"),
            "otherhuman",
            generation,
            transaction,
            locked,
        )
        .unwrap();
        let prepare = Command::PrepareAccountLock {
            intent: guard.intent.clone(),
        };
        drop(guard);
        let inode = fs::symlink_metadata("/etc/shadow").unwrap().ino();
        let inspected = run(transaction, &prepare, None).unwrap();
        assert!(!Path::new("/etc")
            .join(format!("account-transition-{transaction}"))
            .exists());
        assert_eq!(fs::symlink_metadata("/etc/shadow").unwrap().ino(), inode);
        assert!(run(transaction, &prepare, Some(&"00".repeat(32))).is_err());
        println!("ACCOUNT_LOCK_CASE={transaction}-inspection-and-wrong-review-do-not-stage");
        let prepared = run(
            transaction,
            &prepare,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            prepared["catalog"]["principal_states"][&principal.id]["enabled"],
            false
        );
        assert_eq!(
            prepared["catalog"]["principal_states"][&principal.id]["generation"],
            generation + 1
        );
        assert_eq!(fs::symlink_metadata("/etc/shadow").unwrap().ino(), inode);
        assert!(fixture_governed_session(root, "otherhuman", password).is_err());
        println!("ACCOUNT_LOCK_CASE={transaction}-prepared-generation-fenced-before-publication");
        let complete = Command::CompleteAccountLock {
            transaction: transaction.into(),
        };
        assert!(run(&format!("{transaction}-early-complete"), &complete, None).is_err());
        println!("ACCOUNT_LOCK_CASE={transaction}-early-completion-refused");
        let publish = Command::PermitAccountPublication {
            transaction: transaction.into(),
        };
        let publish_request = format!("{transaction}-publish");
        commit(&publish_request, &publish);
        let published_inode = fs::symlink_metadata("/etc/shadow").unwrap().ino();
        assert_ne!(published_inode, inode);
        assert!(fixture_governed_session(root, "otherhuman", password).is_err());
        println!("ACCOUNT_LOCK_CASE={transaction}-real-shadow-publication-retains-fence");
        let replay = commit(&publish_request, &publish);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["tpm_write_performed"], false);
        assert_eq!(
            fs::symlink_metadata("/etc/shadow").unwrap().ino(),
            published_inode
        );
        println!("ACCOUNT_LOCK_CASE={transaction}-already-published-recovery-no-second-rename");
        let completed = commit(&format!("{transaction}-complete"), &complete);
        assert_eq!(
            completed["catalog"]["principal_states"][&principal.id]["enabled"],
            !locked
        );
        assert_eq!(
            completed["catalog"]["principal_states"][&principal.id]["generation"],
            generation + 1
        );
        assert_eq!(
            fixture_governed_session(root, "otherhuman", password).is_ok(),
            !locked
        );
        println!("ACCOUNT_LOCK_CASE={transaction}-completion-checks-new-records-and-lock-state");
    }
    assert_eq!(
        crate::principal::account_file(Path::new("/etc/shadow"), true)
            .unwrap()
            .0
            .bytes(),
        original.bytes()
    );
    assert!(fixture_governed_identity(root, &prior).is_err());
    println!("ACCOUNT_LOCK_CASE=restored-password-does-not-revive-old-session");
}

#[cfg(test)]
pub(crate) fn fixture_session_projections(
    root: &Path,
    password: &crate::sealed_credential::PrivateBuffer,
) {
    let directory = root.join("admin");
    let registry = root.join("registry.json");
    for mode in [
        "success",
        "callback-error",
        "callback-unwind",
        "enrollment-change",
        "payload-change",
        "registry-replacement",
        "already-closed",
        "head-change",
        "pam-close-in-projection",
        "injected-session-clock-regression",
        "injected-session-clock-reset",
        "injected-session-clock-restart",
    ] {
        let session = fixture_governed_session(root, "human", password).unwrap();
        let original_clock = session.clock.get();
        // Synthetic floors exercise a real PAM/TPM session's refusal path;
        // these are not physical TPM regression/reset/restart observations.
        let mut floor = original_clock;
        match mode {
            "injected-session-clock-regression" => {
                floor.milliseconds = floor.milliseconds.checked_add(3_600_000).unwrap();
            }
            "injected-session-clock-reset" => {
                floor.reset_count = floor.reset_count.checked_add(1).unwrap();
            }
            "injected-session-clock-restart" => {
                floor.restart_count = floor.restart_count.checked_add(1).unwrap();
            }
            _ => (),
        }
        session.clock.set(floor);
        if mode == "already-closed" {
            session.close();
        }
        if mode == "head-change" {
            let account = authentication::fixture_local_account(root, "human", password).unwrap();
            let command = Command::RegisterActivity {
                activity: "session.projection.test".into(),
            };
            let mut store = fixture_store(root).unwrap();
            let inspected = execute_catalog_at(
                &mut store,
                &directory,
                &registry,
                || account.identity(),
                "projection-head-change",
                &command,
                None,
            )
            .unwrap();
            execute_catalog_at(
                &mut store,
                &directory,
                &registry,
                || account.identity(),
                "projection-head-change",
                &command,
                Some(inspected["review_sha256"].as_str().unwrap()),
            )
            .unwrap();
            account.logout();
        }
        let changed = match mode {
            "enrollment-change" => Some(directory.join("enrollment.json")),
            "payload-change" => Some(directory.join(event_name("login-head-change"))),
            "registry-replacement" => Some(registry.clone()),
            _ => None,
        };
        let original = changed
            .as_ref()
            .map(|path| tpm::private_read(path, MAX_CATALOG_EVENT).unwrap());
        let mut store = fixture_store(root).unwrap();
        let mut reader = PrincipalReader::at(&mut store, &directory, &registry);
        let calls = std::cell::Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            session.observe(&mut reader, |identity| {
                calls.set(calls.get() + 1);
                assert_eq!(identity, &session.binding.identity);
                if mode == "callback-error" {
                    return Err("deliberate protected projection refusal".into());
                }
                if mode == "callback-unwind" {
                    panic!("deliberate governed projection unwind");
                }
                if let (Some(path), Some(bytes)) = (&changed, &original) {
                    let mut replacement = bytes.clone();
                    if mode != "registry-replacement" {
                        replacement.push(b' ');
                    }
                    platform::write_atomic(path, &replacement, 0o600).unwrap();
                }
                if mode == "pam-close-in-projection" {
                    session.account.logout();
                }
                // A bounded inert result, not an actual effect or authority token.
                Ok(identity["generation"].as_u64().unwrap())
            })
        }));
        if let (Some(path), Some(bytes)) = (&changed, &original) {
            platform::write_atomic(path, bytes, 0o600).unwrap();
        }
        if mode.starts_with("injected-session-clock-") {
            session.clock.set(original_clock);
        }
        if mode == "success" {
            assert_eq!(
                result.unwrap().unwrap(),
                session.binding.identity["generation"].as_u64().unwrap()
            );
            assert_eq!(calls.get(), 1);
            assert!(!reader.fenced);
            assert!(!session.fenced.get());
            assert_eq!(reader.last_clock, Some(session.clock.get()));
            session.clock.get().elapsed_since(original_clock).unwrap();
            assert!(session.account.identity().is_ok());
            session
                .observe(&mut reader, |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap();
            assert_eq!(calls.get(), 2);
            assert_eq!(reader.last_clock, Some(session.clock.get()));
            session.close();
        } else {
            if mode == "callback-unwind" {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(reader.fenced);
            assert!(session.fenced.get());
            assert!(session.account.identity().is_err());
            assert_eq!(
                calls.get(),
                usize::from(
                    !matches!(mode, "already-closed" | "head-change")
                        && !mode.starts_with("injected-session-clock-")
                )
            );
            // Restoration cannot reactivate the same reader, PAM or session.
            assert!(reader.resolve(&session.binding.identity).is_err());
        }
        assert!(session
            .observe(&mut reader, |_| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err());
        assert!(reader.fenced);
        assert_eq!(
            calls.get(),
            if mode == "success" {
                2
            } else {
                usize::from(
                    !matches!(mode, "already-closed" | "head-change")
                        && !mode.starts_with("injected-session-clock-"),
                )
            }
        );
        drop(reader);
        drop(store);
        assert!(fixture_governed_identity(root, &session).is_err());
        let fresh = fixture_governed_session(root, "human", password).unwrap();
        assert!(fixture_governed_identity(root, &fresh).is_ok());
        fresh.close();
        println!("GOVERNED_SESSION_PROJECTION_CASE={mode}");
    }
}

#[cfg(test)]
pub(crate) fn fixture_governed_session(
    root: &Path,
    login: &str,
    password: &crate::sealed_credential::PrivateBuffer,
) -> Result<PrincipalSession> {
    let attempt = {
        let mut store = fixture_store(root)?;
        PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut store, &root.join("admin"), &root.join("registry.json")),
            login,
        )?
    };
    let account = authentication::fixture_local_account(root, login, password)?;
    let mut store = fixture_store(root)?;
    PrincipalSession::new(
        account,
        attempt,
        &mut PrincipalReader::at(&mut store, &root.join("admin"), &root.join("registry.json")),
    )
}

#[cfg(test)]
pub(crate) fn fixture_governed_identity(
    root: &Path,
    session: &PrincipalSession,
) -> Result<serde_json::Value> {
    let mut store = fixture_store(root)?;
    session.identity(&mut PrincipalReader::at(
        &mut store,
        &root.join("admin"),
        &root.join("registry.json"),
    ))
}

#[cfg(test)]
pub(crate) fn fixture_bound_utc_history(
    receiver: crate::utc_receiver::Receiver,
    variant: &str,
    send: impl FnMut(&str),
) {
    tests::bound_utc_history_case(receiver, variant, send);
}

#[cfg(test)]
pub(crate) fn fixture_governed_projection_interruption(
    root: &Path,
    session: &PrincipalSession,
) -> Result<()> {
    let mut store = fixture_store(root)?;
    session.observe(
        &mut PrincipalReader::at(&mut store, &root.join("admin"), &root.join("registry.json")),
        |_| panic!("fixture protected projection interruption"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::Clock;
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
    use std::{cell::RefCell, path::PathBuf, rc::Rc};

    #[derive(Clone)]
    struct Fake(Rc<RefCell<([u8; 32], Clock, usize, bool)>>);
    impl Checkpoint for Fake {
        fn read(&mut self) -> Result<[u8; 32]> {
            Ok(self.0.borrow().0)
        }
        fn clock(&mut self) -> Result<Clock> {
            Ok(self.0.borrow().1)
        }
        fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
            let mut state = self.0.borrow_mut();
            if state.0 != expected {
                return Err("conflict".into());
            }
            state.0 = tpm::extend_value(expected, event);
            state.2 += 1;
            if state.3 {
                return Err("lost TPM reply".into());
            }
            Ok(state.0)
        }
    }
    struct Fixture {
        directory: PathBuf,
        anchor: Fake,
        identity: serde_json::Value,
    }
    impl Fixture {
        fn new(label: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "luma-admin-bootstrap-{label}-{}",
                std::process::id()
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let identity = serde_json::json!({"installation":"ab".repeat(32),
                "principal":"cd".repeat(32),"generation":1,"login":"human","uid":1001});
            let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,
                "kind":"inert-checkpoint-enrollment","principal":identity,
                "admission_observation":{},"observation_is_attestation":false,
                "ownership":"existing-owner","credential_parent_handle":0x81004c41u32,
                "product_admin_active":false,"role_grant":false}))
            .unwrap();
            let mut digest = Sha256::new();
            digest.update(b"luma-native-checkpoint-enrollment-v1\0");
            digest.update(&record);
            let deployment = bundle::hex(&digest.finalize());
            platform::write_atomic(&directory.join("enrollment.json"), &record, 0o600).unwrap();
            platform::write_atomic(
                &directory.join("journal.json"),
                &admin_journal::initial(&deployment).unwrap(),
                0o600,
            )
            .unwrap();
            let anchor = Fake(Rc::new(RefCell::new((
                tpm::extend_value([0; 32], admin_journal::genesis(&deployment).unwrap()),
                Clock {
                    milliseconds: 100,
                    reset_count: 1,
                    restart_count: 2,
                },
                0,
                false,
            ))));
            Self {
                directory,
                anchor,
                identity,
            }
        }
        fn store(&self) -> Store<Fake> {
            Store::open(self.anchor.clone(), &self.directory.join("journal.json")).unwrap()
        }
        fn inspect(&self) -> serde_json::Value {
            execute(
                &mut self.store(),
                &self.directory,
                || Ok(self.identity.clone()),
                None,
            )
            .unwrap()
        }
        fn activate(&self) -> serde_json::Value {
            let review = self.inspect();
            execute(
                &mut self.store(),
                &self.directory,
                || Ok(self.identity.clone()),
                Some(review["review_sha256"].as_str().unwrap()),
            )
            .unwrap()
        }
        fn writes(&self) -> usize {
            self.anchor.0.borrow().2
        }
        fn catalog_inspect(&self, request: &str, command: &Command) -> Result<serde_json::Value> {
            execute_catalog(
                &mut self.store(),
                &self.directory,
                || Ok(self.identity.clone()),
                request,
                command,
                None,
            )
        }
        fn catalog_commit(&self, request: &str, command: &Command) -> serde_json::Value {
            let inspected = self.catalog_inspect(request, command).unwrap();
            execute_catalog(
                &mut self.store(),
                &self.directory,
                || Ok(self.identity.clone()),
                request,
                command,
                Some(inspected["review_sha256"].as_str().unwrap()),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only this test's exact, freshly created directory.
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn floor_statement(floor_ms: i64) -> Statement {
        Statement {
            floor_ms,
            policy_sha256: utc_history::policy_digest().unwrap(),
            boot_id: "12".repeat(16),
            process_generation: 7,
            source_clock_generation: 1,
            keeper_generation: 5,
            runtime_sha256: "ef".repeat(32),
        }
    }

    #[test]
    fn acting_password_aging_refuses_expiry_at_final_boundary() {
        let day = 20_000u32;
        let start = i64::from(day) * 86_400_000;
        let expiry = (i64::from(day) + 90) * 86_400_000;
        let initial = crate::utc_stream::Observation::fixture(
            floor_statement(expiry - 500),
            crate::utc_bounds::Interval::new(expiry - 500, expiry - 1).unwrap(),
        );
        let original_epoch = password_epoch(&initial);
        password_window(day, &original_epoch, &initial).unwrap();
        for (lower, upper) in [
            (expiry - 499, expiry),
            (expiry, expiry),
            (expiry, expiry + 100),
            (start - 1, start + 100),
        ] {
            let final_observation = crate::utc_stream::Observation::fixture(
                floor_statement(lower),
                crate::utc_bounds::Interval::new(lower, upper).unwrap(),
            );
            assert!(password_window(day, &original_epoch, &final_observation).is_err());
        }
        assert!(password_window(0, &original_epoch, &initial).is_err());
    }

    #[test]
    fn acting_password_aging_never_revives_across_protected_utc_epochs() {
        let day = 20_000u32;
        let lower = i64::from(day) * 86_400_000 + 1;
        let interval = crate::utc_bounds::Interval::new(lower, lower + 100).unwrap();
        let context = floor_statement(lower);
        let initial = crate::utc_stream::Observation::fixture(context.clone(), interval);
        let original_epoch = password_epoch(&initial);
        password_window(day, &original_epoch, &initial).unwrap();
        for field in 0..5 {
            let mut changed = context.clone();
            match field {
                0 => changed.runtime_sha256 = "ac".repeat(32),
                1 => changed.boot_id = "ac".repeat(16),
                2 => changed.process_generation += 1,
                3 => changed.source_clock_generation += 1,
                4 => changed.keeper_generation += 1,
                _ => unreachable!(),
            }
            let final_observation = crate::utc_stream::Observation::fixture(changed, interval);
            assert!(password_window(day, &original_epoch, &final_observation).is_err());
        }
    }

    fn principal_registry(f: &Fixture) -> Command {
        let value = serde_json::json!({"schema_version":1,"installation":"ab".repeat(32),
        "principals":[
            {"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true},
            {"id":"ef".repeat(32),"generation":1,"login":"otherhuman","uid":1002,"enabled":true}
        ]});
        platform::write_atomic(
            &f.directory.join("registry.json"),
            &serde_json::to_vec(&value).unwrap(),
            0o600,
        )
        .unwrap();
        adoption_command(&f.directory.join("registry.json")).unwrap()
    }

    fn recovery_fixture(label: &str, credential: &crate::admin_recovery::Credential) -> Fixture {
        let f = Fixture::new(label);
        let Command::AdoptPrincipals { registry } = principal_registry(&f) else {
            panic!("adoption fixture");
        };
        let mut value = serde_json::to_value(registry).unwrap();
        value["admin_recovery"] = serde_json::to_value(
            crate::admin_recovery::Verifier::create(
                credential,
                &"ab".repeat(32),
                &"cd".repeat(32),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        platform::write_atomic(
            &f.directory.join("registry.json"),
            &serde_json::to_vec(&value).unwrap(),
            0o600,
        )
        .unwrap();
        f.activate();
        principal_commit(
            &f,
            "adopt",
            &adoption_command(&f.directory.join("registry.json")).unwrap(),
        );
        f
    }

    #[test]
    fn offline_recovery_checkpoint_rotates_and_cannot_be_called_with_pam_or_reused() {
        use crate::admin_recovery::Credential;
        let first = Credential::fixture(0x42);
        let second = Credential::fixture(0x43);
        let third = Credential::fixture(0x44);
        let f = recovery_fixture("offline-recovery", &first);
        let registry = f.directory.join("registry.json");
        let baseline = fs::read(&registry).unwrap();
        let mut store = f.store();
        let attempt =
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &first, &second).unwrap();
        let writes = f.writes();
        assert!(execute_catalog_at(
            &mut store,
            &f.directory,
            &registry,
            || Ok(f.identity.clone()),
            "recover",
            &attempt.command,
            None
        )
        .is_err());
        assert_eq!(f.writes(), writes);
        let report = attempt
            .execute(&mut store, &f.directory, &registry, "recover", None)
            .unwrap();
        let committed = attempt
            .execute(
                &mut store,
                &f.directory,
                &registry,
                "recover",
                Some(report["review_sha256"].as_str().unwrap()),
            )
            .unwrap();
        assert_eq!(committed["committed"], true);
        assert_eq!(f.writes(), writes + 1);
        assert_eq!(committed["proposal"]["principal"]["generation"], 1);
        assert_eq!(
            committed["catalog"]["principal_states"][&"cd".repeat(32)]["generation"],
            2
        );
        assert_eq!(committed["catalog"]["admin_recovery"]["generation"], 2);
        assert_eq!(committed["effect_grant"], false);
        assert!(attempt
            .execute(&mut store, &f.directory, &registry, "recover-again", None)
            .is_err());
        assert!(
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &first, &third).is_err()
        );
        assert!(
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &second, &second)
                .is_err()
        );
        let next =
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &second, &third).unwrap();
        let report = next
            .execute(&mut store, &f.directory, &registry, "recover-next", None)
            .unwrap();
        let committed = next
            .execute(
                &mut store,
                &f.directory,
                &registry,
                "recover-next",
                Some(report["review_sha256"].as_str().unwrap()),
            )
            .unwrap();
        assert_eq!(committed["proposal"]["principal"]["generation"], 2);
        assert_eq!(
            committed["catalog"]["principal_states"][&"cd".repeat(32)]["generation"],
            3
        );
        assert_eq!(committed["catalog"]["admin_recovery"]["generation"], 3);
        assert_eq!(fs::read(&registry).unwrap(), baseline);
        assert_eq!(f.writes(), writes + 2);
    }

    #[test]
    fn recovery_proof_fences_on_wrong_review_registry_replacement_head_and_clock_changes() {
        use crate::admin_recovery::Credential;
        for fault in [
            "review",
            "registry",
            "head",
            "reset",
            "restart",
            "regression",
            "expired",
            "observed-floor",
        ] {
            let first = Credential::fixture(0x42);
            let second = Credential::fixture(0x43);
            let f = recovery_fixture(&format!("recovery-{fault}"), &first);
            let registry = f.directory.join("registry.json");
            let mut store = f.store();
            let mut attempt =
                RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &first, &second)
                    .unwrap();
            let report = attempt
                .execute(&mut store, &f.directory, &registry, "recover", None)
                .unwrap();
            let mut digest = report["review_sha256"].as_str().unwrap().to_string();
            match fault {
                "review" => digest = "00".repeat(32),
                "registry" => {
                    let bytes = fs::read(&registry).unwrap();
                    platform::write_atomic(&registry, &bytes, 0o600).unwrap();
                }
                "head" => {
                    let command = Command::RegisterActivity {
                        activity: "recovery.interleave".into(),
                    };
                    let inspected = execute_catalog_at(
                        &mut store,
                        &f.directory,
                        &registry,
                        || Ok(f.identity.clone()),
                        "interleave",
                        &command,
                        None,
                    )
                    .unwrap();
                    execute_catalog_at(
                        &mut store,
                        &f.directory,
                        &registry,
                        || Ok(f.identity.clone()),
                        "interleave",
                        &command,
                        Some(inspected["review_sha256"].as_str().unwrap()),
                    )
                    .unwrap();
                }
                "reset" => f.anchor.0.borrow_mut().1.reset_count += 1,
                "restart" => f.anchor.0.borrow_mut().1.restart_count += 1,
                "regression" => f.anchor.0.borrow_mut().1.milliseconds -= 1,
                "expired" => {
                    attempt.lifetime =
                        authentication::ProtectedOperation::expired_fixture().unwrap()
                }
                "observed-floor" => {
                    let mut clock = attempt.clock.get();
                    clock.milliseconds += 10;
                    attempt.clock.set(clock);
                }
                _ => unreachable!(),
            }
            let writes = f.writes();
            assert!(
                attempt
                    .execute(
                        &mut store,
                        &f.directory,
                        &registry,
                        "recover",
                        Some(&digest)
                    )
                    .is_err(),
                "{fault}"
            );
            assert!(attempt.authenticate().is_err(), "{fault}");
            assert_eq!(f.writes(), writes, "{fault}");
            assert!(!f.directory.join(event_name("recover")).exists(), "{fault}");
        }
    }

    #[test]
    fn recovery_uncertain_commit_retains_pending_and_never_retries_or_resets() {
        use crate::admin_recovery::Credential;
        let first = Credential::fixture(0x42);
        let second = Credential::fixture(0x43);
        let f = recovery_fixture("recovery-uncertain", &first);
        let registry = f.directory.join("registry.json");
        let mut store = f.store();
        let attempt =
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &first, &second).unwrap();
        let inspected = attempt
            .execute(&mut store, &f.directory, &registry, "recover", None)
            .unwrap();
        let writes = f.writes();
        f.anchor.0.borrow_mut().3 = true;
        assert!(attempt
            .execute(
                &mut store,
                &f.directory,
                &registry,
                "recover",
                Some(inspected["review_sha256"].as_str().unwrap())
            )
            .is_err());
        assert_eq!(f.writes(), writes + 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("recover")).exists());
        assert!(store.snapshot().is_err());
        assert!(attempt.authenticate().is_err());
        assert!(
            RecoveryAttempt::prepare(&mut store, &f.directory, &registry, &first, &second).is_err()
        );
        assert_eq!(f.writes(), writes + 1);
    }
    fn principal_call(
        f: &Fixture,
        request: &str,
        command: &Command,
        review: Option<&str>,
    ) -> Result<serde_json::Value> {
        execute_catalog_at(
            &mut f.store(),
            &f.directory,
            &f.directory.join("registry.json"),
            || Ok(f.identity.clone()),
            request,
            command,
            review,
        )
    }
    fn other_identity() -> serde_json::Value {
        serde_json::json!({"installation":"ab".repeat(32),"principal":"ef".repeat(32),
            "generation":1,"login":"otherhuman","uid":1002})
    }
    fn advance(generation: u64, enabled: bool) -> Command {
        Command::AdvancePrincipal {
            principal: "ef".repeat(32),
            expected_generation: generation,
            enabled,
        }
    }

    #[test]
    fn governed_login_preparation_requires_bootstrap_adoption_and_enabled_known_account() {
        let f = Fixture::new("login-preparation-refusals");
        let adoption = principal_registry(&f);
        let path = f.directory.join("registry.json");
        let prepare = |name| {
            PrincipalLogin::prepare(
                &mut PrincipalReader::at(&mut f.store(), &f.directory, &path),
                name,
            )
        };
        assert!(prepare("human").is_err());
        f.activate();
        assert!(prepare("human").is_err());
        principal_commit(&f, "adopt", &adoption);
        for name in ["", "unknown", "root", "../human", "human\0"] {
            assert!(prepare(name).is_err());
        }
        let attempt = prepare("human").unwrap();
        assert_eq!(attempt.local, f.identity);
        assert_eq!(attempt.binding.identity["generation"], 1);
        principal_commit(&f, "disable", &advance(1, false));
        assert!(prepare("otherhuman").is_err());
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn governed_login_retains_original_generation_without_holding_the_writer_lock() {
        let f = Fixture::new("login-lock-and-generation");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let path = f.directory.join("registry.json");
        let original = {
            let mut store = f.store();
            PrincipalLogin::prepare(
                &mut PrincipalReader::at(&mut store, &f.directory, &path),
                "human",
            )
            .unwrap()
        };
        // The login retains descriptors, not either writer's lifetime lock.
        principal_commit(
            &f,
            "rotate",
            &Command::RotateAdmin {
                expected_generation: 1,
            },
        );
        let current = PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut f.store(), &f.directory, &path),
            "human",
        )
        .unwrap();
        assert_eq!(original.binding.identity["generation"], 1);
        assert_eq!(current.binding.identity["generation"], 2);
        assert_ne!(original.binding, current.binding);
        assert_eq!(original.local, current.local);
        original.registry.current().unwrap();
        current.clock.elapsed_since(original.clock).unwrap();
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn governed_login_preparation_keeps_original_registry_pin_until_issuance() {
        let f = Fixture::new("login-original-registry");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let path = f.directory.join("registry.json");
        let baseline = fs::read(&path).unwrap();
        let original = PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut f.store(), &f.directory, &path),
            "human",
        )
        .unwrap();
        platform::write_atomic(&path, &baseline, 0o600).unwrap();
        assert!(original.registry.current().is_err());
        let fresh = PrincipalLogin::prepare(
            &mut PrincipalReader::at(&mut f.store(), &f.directory, &path),
            "human",
        )
        .unwrap();
        fresh.registry.current().unwrap();
        assert!(original.registry.current().is_err());
        assert_eq!(fresh.binding, original.binding);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn admin_rotation_binds_prefix_writers_and_historical_replay_without_reenrollment() {
        let f = Fixture::new("admin-rotation-writers");
        let adoption = principal_registry(&f);
        f.activate();
        assert!(principal_call(
            &f,
            "rotate",
            &Command::RotateAdmin {
                expected_generation: 1
            },
            None
        )
        .is_err());
        principal_commit(&f, "adopt", &adoption);
        let baseline = fs::read(f.directory.join("registry.json")).unwrap();
        let enrollment = fs::read(f.directory.join("enrollment.json")).unwrap();
        let bootstrap = fs::read(f.directory.join("bootstrap.json")).unwrap();
        principal_commit(&f, "old-register", &register());
        let rotation = Command::RotateAdmin {
            expected_generation: 1,
        };
        let inspected = principal_call(&f, "rotate", &rotation, None).unwrap();
        assert_eq!(inspected["proposal"]["principal"]["generation"], 1);
        assert!(!f.directory.join(event_name("rotate")).exists());
        assert!(principal_call(&f, "rotate", &rotation, Some(&"00".repeat(32))).is_err());
        let report = principal_commit(&f, "rotate", &rotation);
        assert_eq!(report["proposal"]["principal"]["generation"], 1);
        assert_eq!(
            report["catalog"]["principal_states"][&"cd".repeat(32)]["generation"],
            2
        );
        let stale = Command::RotateAdmin {
            expected_generation: 1,
        };
        assert!(principal_call(&f, "stale-rotate", &stale, None).is_err());
        assert!(!f.directory.join(event_name("stale-rotate")).exists());
        let next = principal_commit(&f, "define", &definition(0, &["model.select"]));
        assert_eq!(next["proposal"]["principal"]["generation"], 2);
        let second = principal_commit(
            &f,
            "second-rotate",
            &Command::RotateAdmin {
                expected_generation: 2,
            },
        );
        assert_eq!(second["proposal"]["principal"]["generation"], 2);
        let before = f.writes();
        let replay = principal_commit(&f, "rotate", &rotation);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["proposal"]["principal"]["generation"], 1);
        assert_eq!(
            replay["catalog"]["principal_states"][&"cd".repeat(32)]["generation"],
            3
        );
        assert_eq!(f.writes(), before);
        let path = f.directory.join("registry.json");
        let current = PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&f.identity)
            .unwrap();
        assert_eq!(current.identity["generation"], 3);
        for (name, bytes) in [
            ("registry.json", baseline),
            ("enrollment.json", enrollment),
            ("bootstrap.json", bootstrap),
        ] {
            assert_eq!(fs::read(f.directory.join(name)).unwrap(), bytes);
        }
    }

    #[test]
    fn replay_refuses_stale_and_future_writers_even_with_matching_checkpoint_payload_hash() {
        for generation in [1, 3] {
            let f = Fixture::new(&format!("admin-prefix-writer-{generation}"));
            let adoption = principal_registry(&f);
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            principal_commit(
                &f,
                "rotate",
                &Command::RotateAdmin {
                    expected_generation: 1,
                },
            );
            let mut store = f.store();
            let snapshot = store.snapshot().unwrap();
            let registry_path = f.directory.join("registry.json");
            let context =
                Context::load_at(&f.directory, &snapshot.deployment, &registry_path).unwrap();
            let (catalog, _) = context.events(&snapshot, None).unwrap();
            let mut writer = context.writer(&catalog).unwrap();
            writer.generation = generation;
            let command = Command::RegisterActivity {
                activity: "after.rotate".into(),
            };
            let event = CatalogEvent {
                schema_version: 1,
                kind: "native-admin-catalog-event".into(),
                deployment: snapshot.deployment.clone(),
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                principal: writer,
                request_id: "forged-writer".into(),
                sequence: snapshot.entries.len() + 1,
                state_version_before: catalog.state_version,
                previous_head: snapshot.head.clone(),
                command,
            };
            let bytes = serde_json::to_vec(&event).unwrap();
            platform::write_atomic(
                &f.directory.join(event_name("forged-writer")),
                &bytes,
                0o600,
            )
            .unwrap();
            store
                .append(
                    Entry {
                        request_id: event.request_id,
                        authenticated_uid: 1001,
                        clock: snapshot.clock,
                        activity: event.command.activity().into(),
                        payload_sha256: bundle::hex(&Sha256::digest(bytes)),
                    },
                    |_| Ok(()),
                )
                .unwrap();
            let anchored = store.snapshot().unwrap();
            assert!(context.state(&anchored, None).is_err());
        }
    }

    #[test]
    fn mixed_utc_history_uses_writer_generation_at_each_catalog_prefix() {
        let f = Fixture::new("admin-rotation-mixed-time");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let call = |request, statement: &Statement, reviewed: Option<&str>| {
            execute_history_at(
                &mut f.store(),
                &f.directory,
                &f.directory.join("registry.json"),
                || Ok(f.identity.clone()),
                |proposed| proposed.supported_by(&observation(statement)),
                request,
                statement,
                reviewed,
            )
        };
        let old = floor_statement(1000);
        let reviewed = call("first-floor", &old, None).unwrap();
        let committed = call(
            "first-floor",
            &old,
            Some(reviewed["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(committed["proposal"]["principal"]["generation"], 1);
        principal_commit(
            &f,
            "rotate",
            &Command::RotateAdmin {
                expected_generation: 1,
            },
        );
        let new = floor_statement(2000);
        let reviewed = call("second-floor", &new, None).unwrap();
        let committed = call(
            "second-floor",
            &new,
            Some(reviewed["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(committed["proposal"]["principal"]["generation"], 2);
        principal_commit(
            &f,
            "second-rotate",
            &Command::RotateAdmin {
                expected_generation: 2,
            },
        );
        let before = f.writes();
        let replay = call("first-floor", &old, None).unwrap();
        let replay = call(
            "first-floor",
            &old,
            Some(replay["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["proposal"]["principal"]["generation"], 1);
        assert_eq!(replay["history_floor_ms"], 2000);
        assert_eq!(f.writes(), before);
        let current = principal_commit(&f, "register", &register());
        assert_eq!(current["proposal"]["principal"]["generation"], 3);
    }

    #[test]
    fn admin_rotation_lost_reply_is_recovered_once_without_rotating_twice() {
        let f = Fixture::new("admin-rotation-lost-reply");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let command = Command::RotateAdmin {
            expected_generation: 1,
        };
        let inspected = principal_call(&f, "rotate", &command, None).unwrap();
        f.anchor.0.borrow_mut().3 = true;
        assert!(principal_call(
            &f,
            "rotate",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        drop(recovery.publish(&digest).unwrap());
        let replay = principal_commit(&f, "rotate", &command);
        assert_eq!(replay["replayed"], true);
        assert_eq!(
            replay["catalog"]["principal_states"][&"cd".repeat(32)]["generation"],
            2
        );
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn admin_rotation_final_authentication_loss_retains_intent_and_old_generation() {
        let f = Fixture::new("admin-rotation-auth-loss");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let command = Command::RotateAdmin {
            expected_generation: 1,
        };
        let inspected = principal_call(&f, "rotate", &command, None).unwrap();
        let mut calls = 0;
        assert!(execute_catalog_at(
            &mut f.store(),
            &f.directory,
            &f.directory.join("registry.json"),
            || {
                calls += 1;
                if calls >= 5 {
                    return Err("fixture PAM proof lost before dispatch".into());
                }
                Ok(f.identity.clone())
            },
            "rotate",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(calls, 5);
        assert_eq!(f.writes(), 2);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("rotate")).exists());
        assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
    }

    #[test]
    fn governed_principal_changes_are_reviewed_restartable_and_preserve_baseline_and_historical_requests(
    ) {
        let f = Fixture::new("governed-generation-chain");
        let adoption = principal_registry(&f);
        f.activate();
        assert!(principal_call(&f, "disable", &advance(1, false), None).is_err());
        principal_commit(&f, "adopt", &adoption);
        let baseline = fs::read(f.directory.join("registry.json")).unwrap();
        let inspected = principal_call(&f, "disable", &advance(1, false), None).unwrap();
        assert_eq!(f.writes(), 2);
        assert!(!f.directory.join(event_name("disable")).exists());
        assert!(principal_call(&f, "disable", &advance(1, false), Some(&"00".repeat(32))).is_err());
        let disabled = principal_call(
            &f,
            "disable",
            &advance(1, false),
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            disabled["catalog"]["principal_states"][&"ef".repeat(32)]["generation"],
            2
        );
        assert!(principal_call(&f, "stale", &advance(1, true), None).is_err());
        assert!(principal_call(&f, "disable", &advance(2, true), None).is_err());
        principal_commit(&f, "enable", &advance(2, true));
        principal_commit(&f, "rotate", &advance(3, true));
        let replay = principal_commit(&f, "disable", &advance(1, false));
        assert_eq!(replay["replayed"], true);
        assert_eq!(
            replay["catalog"]["principal_states"][&"ef".repeat(32)]["generation"],
            4
        );
        assert_eq!(
            replay["catalog"]["principal_states"][&"ef".repeat(32)]["enabled"],
            true
        );
        assert_eq!(
            fs::read(f.directory.join("registry.json")).unwrap(),
            baseline
        );
        assert_eq!(f.writes(), 5);
    }

    #[test]
    fn governed_generation_final_writer_revocation_retains_intent_without_tpm_dispatch() {
        let f = Fixture::new("governed-final-writer");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let inspected = principal_call(&f, "disable", &advance(1, false), None).unwrap();
        let mut calls = 0;
        assert!(execute_catalog_at(
            &mut f.store(),
            &f.directory,
            &f.directory.join("registry.json"),
            || {
                calls += 1;
                if calls >= 5 {
                    return Err("fixture authentication revoked at final writer".into());
                }
                Ok(f.identity.clone())
            },
            "disable",
            &advance(1, false),
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(calls, 5);
        assert_eq!(f.writes(), 2);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("disable")).exists());
    }

    #[test]
    fn governed_generation_lost_reply_requires_reviewed_publication_not_reapplication() {
        let f = Fixture::new("governed-lost-reply");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let inspected = principal_call(&f, "disable", &advance(1, false), None).unwrap();
        f.anchor.0.borrow_mut().3 = true;
        assert!(principal_call(
            &f,
            "disable",
            &advance(1, false),
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        drop(recovery.publish(&digest).unwrap());
        let replay = principal_commit(&f, "disable", &advance(1, false));
        assert_eq!(replay["replayed"], true);
        assert_eq!(
            replay["catalog"]["principal_states"][&"ef".repeat(32)]["generation"],
            2
        );
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn account_lock_uncertain_tpm_reply_fences_target_without_filesystem_dispatch() {
        for password_change in [false, true] {
            for phase in ["prepare", "permit", "complete"] {
                let f = Fixture::new(&format!("account-lock-lost-{password_change}-{phase}"));
                let adoption = principal_registry(&f);
                let registry = f.directory.join("registry.json");
                let identity = f.directory.join("identity");
                fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
                platform::write_atomic(&identity.join("passwd"),b"human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n",0o600).unwrap();
                let original=b"human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n";
                platform::write_atomic(&identity.join("shadow"), original, 0o600).unwrap();
                f.activate();
                principal_commit(&f, "adopt", &adoption);
                let execute = |request: &str, command: &Command, review: Option<&str>| {
                    execute_catalog_authorized_at(
                        &mut f.store(),
                        &f.directory,
                        &registry,
                        &identity,
                        || Ok(f.identity.clone()),
                        request,
                        command,
                        review,
                        CatalogAuthority::Primitive,
                    )
                };
                let commit = |request: &str, command: &Command| {
                    let inspected = execute(request, command, None).unwrap();
                    execute(
                        request,
                        command,
                        Some(inspected["review_sha256"].as_str().unwrap()),
                    )
                    .unwrap()
                };
                let (checkpoint, _) = account_checkpoint_at(&registry, &identity).unwrap();
                commit("accounts", &checkpoint);
                let guard = if password_change {
                    let mut secret = crate::sealed_credential::PrivateBuffer::new(1025).unwrap();
                    let value = b"Strong account lost reply fixture secret 2026";
                    secret.bytes_mut()[..value.len()].copy_from_slice(value);
                    let hash = crate::account_password::Password::fixture(&secret)
                        .unwrap()
                        .hash()
                        .unwrap();
                    let guard = crate::account_transition::Guard::prepare_password(
                        &registry,
                        &identity,
                        "otherhuman",
                        1,
                        "lock",
                        &hash,
                    )
                    .unwrap();
                    // Test-only FakeTPM fixture authority, never a production path.
                    guard.stage_password_proposal(|| Ok(())).unwrap();
                    guard
                } else {
                    crate::account_transition::Guard::prepare(
                        &registry,
                        &identity,
                        "otherhuman",
                        1,
                        "lock",
                        true,
                    )
                    .unwrap()
                };
                let intent = guard.intent.clone();
                drop(guard);
                let prepare = Command::PrepareAccountLock {
                    intent: intent.clone(),
                };
                let permit = Command::PermitAccountPublication {
                    transaction: "lock".into(),
                };
                let complete = Command::CompleteAccountLock {
                    transaction: "lock".into(),
                };
                let mut target = ("lock", &prepare);
                if phase != "prepare" {
                    commit("lock", &prepare);
                    let mut store = f.store();
                    let mut reader = PrincipalReader::at(&mut store, &f.directory, &registry);
                    reader.identity_path = &identity;
                    assert!(reader.resolve(&other_identity()).is_err());
                    assert!(execute("early-complete", &complete, None).is_err());
                    target = ("permit", &permit);
                    if phase == "complete" {
                        commit("permit", &permit);
                        // A private FakeTPM fixture dispatch, not production authority.
                        let guard = if password_change {
                            crate::account_transition::Guard::retained_password(
                                &registry, &identity, &intent,
                            )
                            .unwrap()
                        } else {
                            crate::account_transition::Guard::prepare(
                                &registry,
                                &identity,
                                "otherhuman",
                                1,
                                "lock",
                                true,
                            )
                            .unwrap()
                        };
                        guard.publish(|| Ok(())).unwrap();
                        drop(guard);
                        target = ("complete", &complete);
                    }
                }
                let inspected = execute(target.0, target.1, None).unwrap();
                let before = fs::read(identity.join("shadow")).unwrap();
                let writes = f.writes();
                f.anchor.0.borrow_mut().3 = true;
                assert!(execute(
                    target.0,
                    target.1,
                    Some(inspected["review_sha256"].as_str().unwrap())
                )
                .is_err());
                assert_eq!(f.writes(), writes + 1);
                assert_eq!(fs::read(identity.join("shadow")).unwrap(), before);
                assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
                let recovery = admin_journal::Recovery::inspect(
                    f.anchor.clone(),
                    &f.directory.join("journal.json"),
                )
                .unwrap();
                let review = recovery.digest().unwrap();
                drop(recovery.publish(&review).unwrap());
                let replay = commit(target.0, target.1);
                assert_eq!(replay["replayed"], true);
                assert_eq!(replay["tpm_write_performed"], false);
                assert_eq!(f.writes(), writes + 1);
                assert_eq!(fs::read(identity.join("shadow")).unwrap(), before);
                assert_ne!(
                    replay["catalog"]["account_transitions"]["lock"]["phase"],
                    serde_json::Value::Null
                );
            }
        }
    }

    #[test]
    fn account_deletion_uncertain_tpm_reply_retains_each_phase_without_dispatch() {
        for phase in ["prepare", "permit", "complete"] {
            let f = Fixture::new(&format!("account-delete-lost-{phase}"));
            let adoption = principal_registry(&f);
            let registry = f.directory.join("registry.json");
            let identity = f.directory.join("identity");
            fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
            for (name, bytes) in [
                ("passwd", "human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n"),
                ("shadow", "human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n"),
                ("group", "human:x:1001:\notherhuman:x:1002:\n"),
                ("gshadow", "human:!::\notherhuman:!::\n"),
            ] { platform::write_atomic(&identity.join(name), bytes.as_bytes(), 0o600).unwrap(); }
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let execute = |request: &str, command: &Command, review: Option<&str>| {
                execute_catalog_authorized_at(
                    &mut f.store(),
                    &f.directory,
                    &registry,
                    &identity,
                    || Ok(f.identity.clone()),
                    request,
                    command,
                    review,
                    CatalogAuthority::Primitive,
                )
            };
            let commit = |request: &str, command: &Command| {
                let proposal = execute(request, command, None).unwrap();
                execute(
                    request,
                    command,
                    Some(proposal["review_sha256"].as_str().unwrap()),
                )
                .unwrap()
            };
            commit(
                "accounts",
                &account_checkpoint_at(&registry, &identity).unwrap().0,
            );
            let guard = crate::account_deletion::Guard::prepare(
                &registry,
                &identity,
                "otherhuman",
                1,
                "delete-one",
            )
            .unwrap();
            let intent = guard.intent.clone();
            drop(guard);
            let prepare = Command::PrepareAccountDeletion {
                intent: intent.clone(),
            };
            let permit = Command::PermitAccountDeletion {
                transaction: intent.transaction.clone(),
            };
            let complete = Command::CompleteAccountDeletion {
                transaction: intent.transaction.clone(),
            };
            let target = match phase {
                "prepare" => ("delete-one", &prepare),
                "permit" => {
                    commit("delete-one", &prepare);
                    ("permit", &permit)
                }
                "complete" => {
                    commit("delete-one", &prepare);
                    commit("permit", &permit);
                    // Private FakeTPM fixture dispatch, not production authority.
                    for file in crate::account_deletion::FILES {
                        let guard =
                            crate::account_deletion::Guard::retained(&registry, &identity, &intent)
                                .unwrap();
                        assert!(guard.publish(file, || Ok(())).unwrap());
                    }
                    ("complete", &complete)
                }
                _ => unreachable!(),
            };
            let hashes = || {
                crate::account_deletion::FILES
                    .into_iter()
                    .map(|name| {
                        let (bytes, _) = crate::principal::account_file(
                            &identity.join(name),
                            name.ends_with("shadow"),
                        )
                        .unwrap();
                        bundle::hex(&Sha256::digest(bytes.bytes()))
                    })
                    .collect::<Vec<_>>()
            };
            let before = hashes();
            let proposal = execute(target.0, target.1, None).unwrap();
            let writes = f.writes();
            f.anchor.0.borrow_mut().3 = true;
            assert!(execute(
                target.0,
                target.1,
                Some(proposal["review_sha256"].as_str().unwrap())
            )
            .is_err());
            assert_eq!(f.writes(), writes + 1);
            assert_eq!(hashes(), before);
            assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
            let recovery = admin_journal::Recovery::inspect(
                f.anchor.clone(),
                &f.directory.join("journal.json"),
            )
            .unwrap();
            let review = recovery.digest().unwrap();
            drop(recovery.publish(&review).unwrap());
            let replay = commit(target.0, target.1);
            assert_eq!(replay["replayed"], true);
            assert_eq!(replay["tpm_write_performed"], false);
            assert_eq!(f.writes(), writes + 1);
            assert_eq!(hashes(), before);
        }
    }

    #[test]
    fn account_creation_uncertain_tpm_reply_reconciles_exact_phases_without_dispatch() {
        for phase in ["prepare", "permit", "complete"] {
            let f = Fixture::new(&format!("account-create-lost-{phase}"));
            let adoption = principal_registry(&f);
            let registry = f.directory.join("registry.json");
            let identity = f.directory.join("identity");
            fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
            let homes = creation_homes(&identity);
            fs::DirBuilder::new().mode(0o700).create(&homes).unwrap();
            for (name,bytes) in [
                ("passwd","human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n"),
                ("shadow","human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n"),
                ("group","human:x:1001:\notherhuman:x:1002:\n"),
                ("gshadow","human:!::\notherhuman:!::\n"),
            ] {platform::write_atomic(&identity.join(name),bytes.as_bytes(),0o600).unwrap();}
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let execute = |request: &str, command: &Command, review: Option<&str>| {
                execute_catalog_authorized_at(
                    &mut f.store(),
                    &f.directory,
                    &registry,
                    &identity,
                    || Ok(f.identity.clone()),
                    request,
                    command,
                    review,
                    CatalogAuthority::Primitive,
                )
            };
            let commit = |request: &str, command: &Command| {
                let proposal = execute(request, command, None).unwrap();
                execute(
                    request,
                    command,
                    Some(proposal["review_sha256"].as_str().unwrap()),
                )
                .unwrap()
            };
            commit(
                "accounts",
                &account_checkpoint_at(&registry, &identity).unwrap().0,
            );
            let mut secret = crate::sealed_credential::PrivateBuffer::new(1025).unwrap();
            let value = b"Strong account creation lost reply fixture 2026";
            secret.bytes_mut()[..value.len()].copy_from_slice(value);
            let hash = crate::account_password::Password::fixture(&secret)
                .unwrap()
                .hash()
                .unwrap();
            let guard = crate::account_creation::Guard::new(
                &registry,
                &identity,
                &homes,
                "newhuman",
                "create-new",
                &hash,
            )
            .unwrap();
            // This private FakeTPM fixture exercises the reducer, not production admission.
            guard.stage(|| Ok(())).unwrap();
            let intent = guard.intent.clone();
            drop(guard);
            let prepare = Command::PrepareAccountCreation {
                intent: intent.clone(),
            };
            let permit = Command::PermitAccountCreation {
                transaction: "create-new".into(),
            };
            let complete = Command::CompleteAccountCreation {
                transaction: "create-new".into(),
            };
            let target = match phase {
                "prepare" => ("create-new", &prepare),
                "permit" => {
                    commit("create-new", &prepare);
                    ("permit", &permit)
                }
                "complete" => {
                    commit("create-new", &prepare);
                    commit("permit", &permit);
                    for file in ["home"].into_iter().chain(crate::account_creation::FILES) {
                        assert!(crate::account_creation::Guard::retained(
                            &registry, &identity, &homes, &intent
                        )
                        .unwrap()
                        .publish(file, || Ok(()))
                        .unwrap());
                    }
                    ("complete", &complete)
                }
                _ => unreachable!(),
            };
            let hashes = || {
                crate::account_creation::FILES
                    .into_iter()
                    .map(|name| {
                        if name == "registry" {
                            bundle::hex(&Sha256::digest(
                                crate::principal::registry_file(&registry).unwrap().0,
                            ))
                        } else {
                            bundle::hex(&Sha256::digest(
                                crate::principal::account_file(
                                    &identity.join(name),
                                    name.ends_with("shadow"),
                                )
                                .unwrap()
                                .0
                                .bytes(),
                            ))
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let before = hashes();
            let inspected = execute(target.0, target.1, None).unwrap();
            let writes = f.writes();
            f.anchor.0.borrow_mut().3 = true;
            assert!(execute(
                target.0,
                target.1,
                Some(inspected["review_sha256"].as_str().unwrap())
            )
            .is_err());
            assert_eq!(f.writes(), writes + 1);
            assert_eq!(hashes(), before);
            assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
            let recovery = admin_journal::Recovery::inspect(
                f.anchor.clone(),
                &f.directory.join("journal.json"),
            )
            .unwrap();
            let review = recovery.digest().unwrap();
            drop(recovery.publish(&review).unwrap());
            let replay = commit(target.0, target.1);
            assert_eq!(replay["replayed"], true);
            assert_eq!(replay["tpm_write_performed"], false);
            assert_eq!(f.writes(), writes + 1);
            assert_eq!(hashes(), before);
        }
    }

    #[test]
    fn account_lock_staged_replacement_before_tpm_commit_is_not_dispatched() {
        let f = Fixture::new("account-lock-staged-replaced");
        let adoption = principal_registry(&f);
        let registry = f.directory.join("registry.json");
        let identity = f.directory.join("identity");
        fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
        platform::write_atomic(&identity.join("passwd"),b"human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n",0o600).unwrap();
        let original=b"human:$6$fixture$one:20000:0:99999:7:::\notherhuman:$6$fixture$two:20000:0:99999:7:::\n";
        platform::write_atomic(&identity.join("shadow"), original, 0o600).unwrap();
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let execute = |request: &str, command: &Command, review: Option<&str>| {
            execute_catalog_authorized_at(
                &mut f.store(),
                &f.directory,
                &registry,
                &identity,
                || Ok(f.identity.clone()),
                request,
                command,
                review,
                CatalogAuthority::Primitive,
            )
        };
        let commit = |request: &str, command: &Command| {
            let inspected = execute(request, command, None).unwrap();
            execute(
                request,
                command,
                Some(inspected["review_sha256"].as_str().unwrap()),
            )
            .unwrap()
        };
        let (checkpoint, _) = account_checkpoint_at(&registry, &identity).unwrap();
        commit("accounts", &checkpoint);
        let guard = crate::account_transition::Guard::prepare(
            &registry,
            &identity,
            "otherhuman",
            1,
            "lock",
            true,
        )
        .unwrap();
        let prepare = Command::PrepareAccountLock {
            intent: guard.intent.clone(),
        };
        drop(guard);
        commit("lock", &prepare);
        let permit = Command::PermitAccountPublication {
            transaction: "lock".into(),
        };
        let inspected = execute("permit", &permit, None).unwrap();
        let mut changed = false;
        let writes = f.writes();
        assert!(execute_catalog_authorized_at(
            &mut f.store(),
            &f.directory,
            &registry,
            &identity,
            || {
                if f.directory.join("journal.pending.json").exists() && !changed {
                    let path = identity.join("account-transition-lock/shadow.new");
                    let retained = crate::principal::account_file(&path, true)?.0;
                    platform::write_atomic(&path, retained.bytes(), 0o600)?;
                    changed = true;
                }
                Ok(f.identity.clone())
            },
            "permit",
            &permit,
            Some(inspected["review_sha256"].as_str().unwrap()),
            CatalogAuthority::Primitive
        )
        .is_err());
        assert!(changed);
        assert_eq!(f.writes(), writes);
        assert_eq!(fs::read(identity.join("shadow")).unwrap(), original);
        assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
    }

    #[test]
    fn account_checkpoint_pending_revocation_and_lost_reply_never_redispatch() {
        for fault in ["revocation", "lost-reply"] {
            let f = Fixture::new(&format!("account-checkpoint-{fault}"));
            let adoption = principal_registry(&f);
            let registry = f.directory.join("registry.json");
            let identity = f.directory.join("identity");
            fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
            platform::write_atomic(&identity.join("passwd"), b"human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n", 0o644).unwrap();
            let shadow = b"human:$6$public$one:20000:0:99999:7:::\notherhuman:$6$public$two:20000:0:99999:7:::\n";
            platform::write_atomic(&identity.join("shadow"), shadow, 0o600).unwrap();
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let (command, _) = account_checkpoint_at(&registry, &identity).unwrap();
            let inspected = execute_catalog_authorized_at(
                &mut f.store(),
                &f.directory,
                &registry,
                &identity,
                || Ok(f.identity.clone()),
                "accounts",
                &command,
                None,
                CatalogAuthority::Primitive,
            )
            .unwrap();
            let pending = f.directory.join("journal.pending.json");
            if fault == "lost-reply" {
                f.anchor.0.borrow_mut().3 = true;
            }
            let mut revoked = false;
            assert!(execute_catalog_authorized_at(&mut f.store(), &f.directory, &registry, &identity,
                || {
                    if fault == "revocation" && pending.exists() && !revoked {
                        platform::write_atomic(&identity.join("shadow"), b"human:$6$public$one:20000:0:99999:7:::\notherhuman:!locked:20000:0:99999:7:::\n", 0o600)?;
                        revoked = true;
                    }
                    Ok(f.identity.clone())
                }, "accounts", &command, Some(inspected["review_sha256"].as_str().unwrap()),
                CatalogAuthority::Primitive).is_err());
            assert!(pending.is_file());
            assert!(f.directory.join(event_name("accounts")).is_file());
            assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
            if fault == "revocation" {
                assert!(revoked);
                assert_eq!(f.writes(), 2);
                platform::write_atomic(&identity.join("shadow"), shadow, 0o600).unwrap();
                assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
            } else {
                assert_eq!(f.writes(), 3);
                let recovery = admin_journal::Recovery::inspect(
                    f.anchor.clone(),
                    &f.directory.join("journal.json"),
                )
                .unwrap();
                let review = recovery.digest().unwrap();
                drop(recovery.publish(&review).unwrap());
                let replay = execute_catalog_authorized_at(
                    &mut f.store(),
                    &f.directory,
                    &registry,
                    &identity,
                    || Ok(f.identity.clone()),
                    "accounts",
                    &command,
                    None,
                    CatalogAuthority::Primitive,
                )
                .unwrap();
                assert_eq!(replay["replayed"], true);
                execute_catalog_authorized_at(
                    &mut f.store(),
                    &f.directory,
                    &registry,
                    &identity,
                    || Ok(f.identity.clone()),
                    "accounts",
                    &command,
                    Some(replay["review_sha256"].as_str().unwrap()),
                    CatalogAuthority::Primitive,
                )
                .unwrap();
                assert_eq!(f.writes(), 3);
            }
        }
    }

    #[test]
    fn account_checkpoint_guards_fresh_readers_and_refuses_unreviewed_rebinding() {
        let f = Fixture::new("account-checkpoint-reader");
        let adoption = principal_registry(&f);
        let registry = f.directory.join("registry.json");
        let identity = f.directory.join("identity");
        fs::DirBuilder::new().mode(0o700).create(&identity).unwrap();
        platform::write_atomic(&identity.join("passwd"), b"human:x:1001:1001:Human:/home/human:/bin/bash\notherhuman:x:1002:1002:Other:/home/otherhuman:/bin/bash\n", 0o644).unwrap();
        let shadow = b"human:$6$public$one:20000:0:99999:7:::\notherhuman:$6$public$two:20000:0:99999:7:::\n";
        platform::write_atomic(&identity.join("shadow"), shadow, 0o600).unwrap();
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let (command, _) = account_checkpoint_at(&registry, &identity).unwrap();
        let execute = |request: &str, command: &Command, review: Option<&str>| {
            execute_catalog_authorized_at(
                &mut f.store(),
                &f.directory,
                &registry,
                &identity,
                || Ok(f.identity.clone()),
                request,
                command,
                review,
                CatalogAuthority::Primitive,
            )
        };
        let inspected = execute("accounts", &command, None).unwrap();
        assert_eq!(f.writes(), 2);
        assert!(!f.directory.join(event_name("accounts")).exists());
        assert!(execute("accounts", &command, Some(&"00".repeat(32))).is_err());
        execute(
            "accounts",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(f.writes(), 3);
        let resolve = |local: &serde_json::Value| {
            let mut store = f.store();
            let mut reader = PrincipalReader::at(&mut store, &f.directory, &registry);
            reader.identity_path = &identity;
            reader.resolve(local)
        };
        assert!(resolve(&f.identity).unwrap().credential_sha256.is_some());
        assert!(resolve(&other_identity())
            .unwrap()
            .credential_sha256
            .is_some());
        let replay = execute("accounts", &command, None).unwrap();
        assert_eq!(replay["replayed"], true);
        execute(
            "accounts",
            &command,
            Some(replay["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(f.writes(), 3);
        platform::write_atomic(&identity.join("shadow"), b"human:$6$public$one:20000:0:99999:7:::\notherhuman:$6$public$changed:20000:0:99999:7:::\n", 0o600).unwrap();
        assert!(resolve(&other_identity()).is_err());
        assert!(resolve(&f.identity).is_ok());
        let (changed, _) = account_checkpoint_at(&registry, &identity).unwrap();
        assert!(execute("rebind", &changed, None).is_err());
        assert_eq!(f.writes(), 3);
        platform::write_atomic(&identity.join("shadow"), shadow, 0o600).unwrap();
        assert!(resolve(&other_identity()).is_ok());
        principal_commit(
            &f,
            "rotate",
            &Command::RotateAdmin {
                expected_generation: 1,
            },
        );
        assert_eq!(resolve(&f.identity).unwrap().identity["generation"], 2);
    }

    #[test]
    fn catalog_reader_preserves_explicit_adoption_and_nonconvertible_purpose() {
        let f = Fixture::new("catalog-reader-purpose");
        let adoption = principal_registry(&f);
        let path = f.directory.join("registry.json");
        assert!(
            PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, None)
                .resolve(&f.identity)
                .is_err()
        );
        f.activate();
        let status = PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, None)
            .resolve(&f.identity)
            .unwrap();
        assert_eq!(
            status.purpose,
            PrincipalPurpose::AdminCatalog { candidate: None }
        );
        assert!(PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&f.identity)
            .is_err());
        assert!(
            PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, None)
                .resolve(&other_identity())
                .is_err()
        );
        principal_commit(&f, "adopt", &adoption);
        let general = PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&f.identity)
            .unwrap();
        let candidate =
            PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, Some("inspect"))
                .resolve(&f.identity)
                .unwrap();
        let other =
            PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, Some("different"))
                .resolve(&f.identity)
                .unwrap();
        assert_eq!(general.identity, candidate.identity);
        assert_ne!(general, candidate);
        assert_ne!(candidate, other);
        principal_commit(
            &f,
            "rotate",
            &Command::RotateAdmin {
                expected_generation: 1,
            },
        );
        let current = PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, None)
            .resolve(&f.identity)
            .unwrap();
        assert_eq!(current.identity["generation"], 2);
        assert_ne!(current.identity, status.identity);
        let mut forged = f.identity.clone();
        forged["generation"] = serde_json::json!(2);
        assert!(
            PrincipalReader::admin_at(&mut f.store(), &f.directory, &path, None)
                .resolve(&forged)
                .is_err()
        );
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn principal_reader_requires_adoption_matches_baseline_and_never_authenticates_json() {
        let f = Fixture::new("principal-reader-basics");
        let adoption = principal_registry(&f);
        let path = f.directory.join("registry.json");
        let mut store = f.store();
        assert!(PrincipalReader::at(&mut store, &f.directory, &path)
            .resolve(&other_identity())
            .is_err());
        drop(store);
        f.activate();
        assert!(PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&other_identity())
            .is_err());
        principal_commit(&f, "adopt", &adoption);
        let original = PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&other_identity())
            .unwrap();
        assert_eq!(original.identity["generation"], 1);
        principal_commit(&f, "disable", &advance(1, false));
        assert!(PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&other_identity())
            .is_err());
        principal_commit(&f, "enable", &advance(2, true));
        let current = PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&other_identity())
            .unwrap();
        assert_eq!(current.identity["generation"], 3);
        assert_ne!(original, current);
        let mut forged = other_identity();
        forged["generation"] = serde_json::json!(3);
        assert!(PrincipalReader::at(&mut f.store(), &f.directory, &path)
            .resolve(&forged)
            .is_err());
        assert_eq!(f.writes(), 4);
    }

    #[test]
    fn fresh_principal_reader_requires_the_owned_session_clock_floor_and_epoch() {
        for fault in ["regression", "reset", "restart"] {
            let f = Fixture::new(&format!("principal-session-floor-{fault}"));
            let adoption = principal_registry(&f);
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let path = f.directory.join("registry.json");
            let clock = f.anchor.0.borrow().1;
            let mut floor = clock;
            match fault {
                "regression" => floor.milliseconds += 1,
                "reset" => floor.reset_count += 1,
                "restart" => floor.restart_count += 1,
                _ => unreachable!(),
            }
            let mut store = f.store();
            let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
            assert!(reader.last_clock.is_none());
            assert!(reader
                .resolve_since(&other_identity(), Some(floor))
                .is_err());
            assert!(reader.fenced);
            assert!(reader
                .resolve_since(&other_identity(), Some(clock))
                .is_err());
            assert_eq!(f.writes(), 2);
        }
    }

    #[test]
    fn transferring_a_verified_clock_floor_to_another_reader_preserves_monotonicity() {
        let f = Fixture::new("principal-session-clock-transfer");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let path = f.directory.join("registry.json");
        let clock = f.anchor.0.borrow().1;
        let advanced = {
            let mut store = f.store();
            let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
            f.anchor.0.borrow_mut().1.milliseconds += 10;
            reader
                .resolve_since(&other_identity(), Some(clock))
                .unwrap();
            reader.last_clock.unwrap()
        };
        assert_eq!(advanced.milliseconds, clock.milliseconds + 10);
        f.anchor.0.borrow_mut().1.milliseconds = advanced.milliseconds - 1;
        let mut store = f.store();
        let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
        assert!(reader
            .resolve_since(&other_identity(), Some(advanced))
            .is_err());
        f.anchor.0.borrow_mut().1 = advanced;
        assert!(reader
            .resolve_since(&other_identity(), Some(advanced))
            .is_err());
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn first_replay_snapshot_cannot_hide_clock_regression_with_later_restoration() {
        for existing_reader in [false, true] {
            let f = Fixture::new(&format!("principal-first-snapshot-floor-{existing_reader}"));
            let adoption = principal_registry(&f);
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let clock = f.anchor.0.borrow().1;
            let count = Rc::new(std::cell::Cell::new(0));
            let trigger = Rc::new(std::cell::Cell::new(usize::MAX));
            let anchor = ReadHook {
                anchor: f.anchor.clone(),
                count: count.clone(),
                trigger: trigger.clone(),
                hook: Box::new(|| f.anchor.0.borrow_mut().1 = clock),
            };
            let mut store = Store::open(anchor, &f.directory.join("journal.json")).unwrap();
            let path = f.directory.join("registry.json");
            let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
            if existing_reader {
                reader.resolve(&other_identity()).unwrap();
            }
            f.anchor.0.borrow_mut().1.milliseconds -= 1;
            // Restoring the clock at the next snapshot must not excuse the
            // first snapshot's violation of either retained observation.
            trigger.set(count.get() + 2);
            assert!(reader
                .resolve_since(&other_identity(), (!existing_reader).then_some(clock))
                .is_err());
            assert!(count.get() < trigger.get());
            f.anchor.0.borrow_mut().1 = clock;
            assert!(reader
                .resolve_since(&other_identity(), Some(clock))
                .is_err());
            assert_eq!(f.writes(), 2);
        }
    }

    #[test]
    fn principal_reader_clock_and_semantic_proof_loss_are_sticky_after_restoration() {
        for choice in 0..3 {
            let f = Fixture::new(&format!("principal-reader-fence-{choice}"));
            let adoption = principal_registry(&f);
            f.activate();
            principal_commit(&f, "adopt", &adoption);
            let path = f.directory.join("registry.json");
            let payload = f.directory.join(event_name("adopt"));
            let original = fs::read(&payload).unwrap();
            let clock = f.anchor.0.borrow().1;
            let mut store = f.store();
            let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
            reader.resolve(&other_identity()).unwrap();
            if choice == 0 {
                f.anchor.0.borrow_mut().1.milliseconds -= 1;
            } else if choice == 1 {
                f.anchor.0.borrow_mut().1.restart_count += 1;
            } else {
                platform::write_atomic(&payload, b"{}", 0o600).unwrap();
            }
            assert!(reader.resolve(&other_identity()).is_err());
            f.anchor.0.borrow_mut().1 = clock;
            platform::write_atomic(&payload, &original, 0o600).unwrap();
            assert!(reader.resolve(&other_identity()).is_err());
            assert_eq!(f.writes(), 2);
        }
    }

    #[test]
    fn principal_reader_rechecks_payload_after_matching_anchor_read_and_refuses_journal_rollback() {
        let f = Fixture::new("principal-reader-payload-boundary");
        let adoption = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &adoption);
        let old_journal = fs::read(f.directory.join("journal.json")).unwrap();
        principal_commit(&f, "rotate", &advance(1, true));
        let count = Rc::new(std::cell::Cell::new(0));
        let trigger = Rc::new(std::cell::Cell::new(usize::MAX));
        let payload = f.directory.join(event_name("rotate"));
        let anchor = ReadHook {
            anchor: f.anchor.clone(),
            count: count.clone(),
            trigger: trigger.clone(),
            hook: Box::new(|| platform::write_atomic(&payload, b"{}", 0o600).unwrap()),
        };
        let mut store = Store::open(anchor, &f.directory.join("journal.json")).unwrap();
        // The first replay has two checkpoint snapshots. Interrupt the second
        // replay at its first matching anchor read, without changing the TPM.
        trigger.set(count.get() + 3);
        let path = f.directory.join("registry.json");
        let mut reader = PrincipalReader::at(&mut store, &f.directory, &path);
        assert!(reader.resolve(&other_identity()).is_err());
        assert!(count.get() >= trigger.get());
        drop(reader);
        drop(store);
        platform::write_atomic(&f.directory.join("journal.json"), &old_journal, 0o600).unwrap();
        assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
        assert_eq!(f.writes(), 3);
    }
    fn principal_commit(f: &Fixture, request: &str, command: &Command) -> serde_json::Value {
        let inspected = principal_call(f, request, command, None).unwrap();
        principal_call(
            f,
            request,
            command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn principal_adoption_requires_bootstrap_review_and_survives_restart_without_resetting_roles() {
        let f = Fixture::new("principal-adoption");
        let command = principal_registry(&f);
        assert!(principal_call(&f, "adopt", &command, None).is_err());
        assert_eq!(f.writes(), 0);
        f.activate();
        f.catalog_commit("register-model", &register());
        f.catalog_commit("define-role", &definition(0, &["model.select"]));
        let inspected = principal_call(&f, "adopt", &command, None).unwrap();
        assert!(!f.directory.join(event_name("adopt")).exists());
        assert_eq!(f.writes(), 3);
        assert!(principal_call(&f, "adopt", &command, Some(&"00".repeat(32))).is_err());
        let committed = principal_commit(&f, "adopt", &command);
        assert_eq!(committed["catalog"]["state_version"], 4);
        assert_eq!(committed["catalog"]["roles"]["Operator"]["version"], 1);
        assert_eq!(
            committed["catalog"]["principal_registry"],
            inspected["proposal"]["command"]["registry"]
        );
        assert_eq!(f.writes(), 4);
        let replay = principal_commit(&f, "adopt", &command);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["tpm_write_performed"], false);
        let noop = principal_commit(&f, "adopt-again", &command);
        assert_eq!(noop["no_change"], true);
        assert!(!f.directory.join(event_name("adopt-again")).exists());
        assert_eq!(f.writes(), 4);
        assert_eq!(
            principal_commit(
                &f,
                "register-other",
                &Command::RegisterActivity {
                    activity: "model.other".into()
                }
            )["catalog"]["state_version"],
            5
        );
    }

    #[test]
    fn principal_adoption_cannot_accept_caller_snapshot_or_different_original_admin() {
        let f = Fixture::new("principal-wrong-source");
        let command = principal_registry(&f);
        f.activate();
        let value = serde_json::to_value(&command).unwrap();
        for choice in 0..6 {
            let mut changed = value.clone();
            match choice {
                0 => changed["registry"]["installation"] = serde_json::json!("aa".repeat(32)),
                1 => {
                    changed["registry"]["principals"][0]["id"] = serde_json::json!("aa".repeat(32))
                }
                2 => changed["registry"]["principals"][0]["generation"] = serde_json::json!(2),
                3 => changed["registry"]["principals"][0]["enabled"] = serde_json::json!(false),
                4 => changed["registry"]["principals"][0]["uid"] = serde_json::json!(1003),
                _ => changed["registry"]["principals"][0]["login"] = serde_json::json!("different"),
            }
            let altered: Command = serde_json::from_value(changed.clone()).unwrap();
            assert!(principal_call(&f, "adopt", &altered, None).is_err());
            platform::write_atomic(
                &f.directory.join("registry.json"),
                &serde_json::to_vec(&changed["registry"]).unwrap(),
                0o600,
            )
            .unwrap();
            assert!(principal_call(&f, "adopt", &altered, None).is_err());
            principal_registry(&f);
            assert_eq!(f.writes(), 1);
            assert!(!f.directory.join(event_name("adopt")).exists());
        }
    }

    #[test]
    fn principal_checkpoint_detects_other_account_changes_and_missing_registry_without_writes() {
        let f = Fixture::new("principal-other-account");
        let command = principal_registry(&f);
        f.activate();
        principal_commit(&f, "adopt", &command);
        let original = fs::read(f.directory.join("registry.json")).unwrap();
        let journal = fs::read(f.directory.join("journal.json")).unwrap();
        let snapshot = f.store().snapshot().unwrap();
        let registry_path = f.directory.join("registry.json");
        let context = Context::load_at(&f.directory, &snapshot.deployment, &registry_path).unwrap();
        assert!(context.history(&snapshot, None).is_ok());
        for choice in 0..3 {
            let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
            if choice == 0 {
                changed["principals"][1]["generation"] = serde_json::json!(2);
            } else if choice == 1 {
                changed["principals"][1]["enabled"] = serde_json::json!(false);
            } else {
                changed["principals"].as_array_mut().unwrap().pop();
            }
            platform::write_atomic(
                &f.directory.join("registry.json"),
                &serde_json::to_vec(&changed).unwrap(),
                0o600,
            )
            .unwrap();
            assert!(principal_call(&f, "next", &register(), None).is_err());
            assert!(context.history(&snapshot, None).is_err());
            assert!(principal_call(
                &f,
                "replace",
                &adoption_command(&f.directory.join("registry.json")).unwrap(),
                None
            )
            .is_err());
            platform::write_atomic(&f.directory.join("registry.json"), &original, 0o600).unwrap();
            assert!(principal_call(&f, "next", &register(), None).is_ok());
            assert!(context.history(&snapshot, None).is_ok());
        }
        fs::remove_file(f.directory.join("registry.json")).unwrap();
        assert!(principal_call(&f, "next", &register(), None).is_err());
        assert_eq!(fs::read(f.directory.join("journal.json")).unwrap(), journal);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn principal_registry_replacement_at_final_writer_fences_even_identical_bytes() {
        let f = Fixture::new("principal-final-writer");
        let command = principal_registry(&f);
        f.activate();
        let inspected = principal_call(&f, "adopt", &command, None).unwrap();
        let registry = f.directory.join("registry.json");
        let original = fs::read(&registry).unwrap();
        let mut calls = 0;
        assert!(execute_catalog_at(
            &mut f.store(),
            &f.directory,
            &registry,
            || {
                calls += 1;
                if calls == 5 {
                    platform::write_atomic(&registry, &original, 0o600)?;
                }
                Ok(f.identity.clone())
            },
            "adopt",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(calls, 5);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("adopt")).exists());
    }

    #[test]
    fn principal_adoption_lost_reply_is_recovered_by_reviewed_publication_not_second_tpm_write() {
        let f = Fixture::new("principal-lost-reply");
        let command = principal_registry(&f);
        f.activate();
        let inspected = principal_call(&f, "adopt", &command, None).unwrap();
        f.anchor.0.borrow_mut().3 = true;
        assert!(principal_call(
            &f,
            "adopt",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        drop(recovery.publish(&digest).unwrap());
        let replay = principal_commit(&f, "adopt", &command);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["catalog"]["state_version"], 2);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn principal_checkpoint_payload_loss_or_substitution_never_reconstructs_authority() {
        for choice in 0..3 {
            let f = Fixture::new(&format!("principal-payload-{choice}"));
            let command = principal_registry(&f);
            f.activate();
            let before = fs::read(f.directory.join("journal.json")).unwrap();
            principal_commit(&f, "adopt", &command);
            let path = f.directory.join(event_name("adopt"));
            if choice == 0 {
                fs::remove_file(path).unwrap();
            } else if choice == 2 {
                platform::write_atomic(&f.directory.join("journal.json"), &before, 0o600).unwrap();
                assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
                assert_eq!(f.writes(), 2);
                continue;
            } else {
                let mut event: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                event["command"]["registry"]["principals"][1]["generation"] = serde_json::json!(2);
                platform::write_atomic(&path, &serde_json::to_vec(&event).unwrap(), 0o600).unwrap();
            }
            assert!(principal_call(&f, "next", &register(), None).is_err());
            assert_eq!(f.writes(), 2);
        }
    }
    fn observation(statement: &Statement) -> crate::utc_history::Observation {
        crate::utc_history::Observation::fixture(
            statement.clone(),
            crate::utc_bounds::Interval::new(statement.floor_ms, statement.floor_ms + 100).unwrap(),
        )
    }
    fn history_call(
        f: &Fixture,
        request: &str,
        statement: &Statement,
        review: Option<&str>,
    ) -> Result<serde_json::Value> {
        execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            |proposed| proposed.supported_by(&observation(statement)),
            request,
            statement,
            review,
        )
    }
    fn history_commit(f: &Fixture, request: &str, statement: &Statement) -> serde_json::Value {
        let inspected = history_call(f, request, statement, None).unwrap();
        history_call(
            f,
            request,
            statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap()
    }

    struct ReadHook<'a> {
        anchor: Fake,
        count: Rc<std::cell::Cell<usize>>,
        trigger: Rc<std::cell::Cell<usize>>,
        hook: Box<dyn FnMut() + 'a>,
    }
    impl Checkpoint for ReadHook<'_> {
        fn read(&mut self) -> Result<[u8; 32]> {
            let next = self.count.get() + 1;
            self.count.set(next);
            if next == self.trigger.get() {
                (self.hook)();
            }
            self.anchor.read()
        }
        fn clock(&mut self) -> Result<Clock> {
            self.anchor.clock()
        }
        fn advance(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<[u8; 32]> {
            panic!("read-only history adapter must never write its anchor")
        }
    }

    #[test]
    fn utc_history_reader_requires_bootstrap_and_reads_monotonic_floor_without_writes() {
        let f = Fixture::new("utc-reader-basics");
        assert!(HistoryReader::new(&mut f.store(), &f.directory)
            .read()
            .is_err());
        f.activate();
        let initial = HistoryReader::new(&mut f.store(), &f.directory)
            .read()
            .unwrap();
        assert_eq!(initial.floor_ms(), 0);
        assert_eq!(initial.history_version, 0);
        history_commit(&f, "floor-1", &floor_statement(1000));
        let mut store = f.store();
        let mut reader = HistoryReader::new(&mut store, &f.directory);
        let binding = reader.read().unwrap();
        assert_eq!(binding.floor_ms(), 1000);
        assert_eq!(binding.history_version, 1);
        assert_ne!(binding, initial);
        f.anchor.0.borrow_mut().1.milliseconds += 1;
        binding.recheck(&mut reader).unwrap();
        assert_eq!(reader.read().unwrap(), binding);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn utc_history_reader_boot_epoch_and_powered_clock_failure_are_sticky() {
        for variant in 0..3 {
            let f = Fixture::new(&format!("utc-reader-clock-{variant}"));
            f.activate();
            let mut store = f.store();
            let mut reader = HistoryReader::new(&mut store, &f.directory);
            reader.read().unwrap();
            let previous = f.anchor.0.borrow().1;
            match variant {
                0 => f.anchor.0.borrow_mut().1.reset_count += 1,
                1 => f.anchor.0.borrow_mut().1.restart_count += 1,
                _ => f.anchor.0.borrow_mut().1.milliseconds -= 1,
            }
            assert!(reader.read().is_err());
            f.anchor.0.borrow_mut().1 = previous;
            assert!(reader.read().is_err());
            assert_eq!(f.writes(), 1);
        }
    }

    #[test]
    fn utc_history_binding_fences_any_shared_head_change_not_only_floor_changes() {
        for variant in 0..2 {
            let f = Fixture::new(&format!("utc-reader-head-{variant}"));
            f.activate();
            let binding = HistoryReader::new(&mut f.store(), &f.directory)
                .read()
                .unwrap();
            if variant == 0 {
                f.catalog_commit("register-model", &register());
            } else {
                history_commit(&f, "floor-1", &floor_statement(1000));
            }
            let mut store = f.store();
            let mut reader = HistoryReader::new(&mut store, &f.directory);
            assert!(binding.recheck(&mut reader).is_err());
            let new_binding = reader.read().unwrap();
            assert_ne!(binding.checkpoint_head, new_binding.checkpoint_head);
            if variant == 0 {
                assert_eq!(binding.floor_ms(), new_binding.floor_ms());
            }
            assert_eq!(f.writes(), 2);
        }
    }

    #[test]
    fn utc_history_reader_rechecks_semantics_after_a_matching_checkpoint_read() {
        for variant in 0..4 {
            let f = Fixture::new(&format!("utc-reader-mid-read-{variant}"));
            f.activate();
            history_commit(&f, "floor-1", &floor_statement(1000));
            let payload = f.directory.join(event_name("floor-1"));
            let bytes = fs::read(&payload).unwrap();
            let anchor = ReadHook {
                anchor: f.anchor.clone(),
                count: Rc::new(std::cell::Cell::new(0)),
                // Open reads once; trigger on the final checkpoint read of the
                // first semantic pass, after its payload reads have completed.
                trigger: Rc::new(std::cell::Cell::new(3)),
                hook: Box::new(|| match variant {
                    0 => platform::write_atomic(&payload, b"{}", 0o600).unwrap(),
                    1 => platform::write_atomic(&f.directory.join("enrollment.json"), b"{}", 0o600)
                        .unwrap(),
                    2 => platform::write_atomic(
                        &f.directory.join("journal.pending.json"),
                        b"{}",
                        0o600,
                    )
                    .unwrap(),
                    _ => platform::write_atomic(
                        &f.directory.join(event_name("orphan")),
                        b"{}",
                        0o600,
                    )
                    .unwrap(),
                }),
            };
            let mut store = Store::open(anchor, &f.directory.join("journal.json")).unwrap();
            let mut reader = HistoryReader::new(&mut store, &f.directory);
            assert!(reader.read().is_err());
            // Restoring a payload does not un-fence a failed reader.
            platform::write_atomic(&payload, &bytes, 0o600).unwrap();
            assert!(reader.read().is_err());
            assert_eq!(f.writes(), 2);
        }
    }

    pub(super) fn bound_utc_history_case(
        receiver: crate::utc_receiver::Receiver,
        variant: &str,
        send: impl FnMut(&str),
    ) {
        use crate::{utc_keeper::State, utc_stream::BoundStream};
        let f = Fixture::new(&format!("utc-bound-{variant}"));
        f.activate();
        history_commit(
            &f,
            "floor-1",
            &floor_statement(if variant == "history-ahead" {
                4_102_444_799_900
            } else {
                1000
            }),
        );
        let send = Rc::new(RefCell::new(send));
        let count = Rc::new(std::cell::Cell::new(0));
        let trigger = Rc::new(std::cell::Cell::new(0));
        let hook_send = send.clone();
        let anchor = ReadHook {
            anchor: f.anchor.clone(),
            count: count.clone(),
            trigger: trigger.clone(),
            hook: Box::new(|| match variant {
                "queued-during-history" => (hook_send.borrow_mut())("two"),
                "delayed-history" => std::thread::sleep(std::time::Duration::from_millis(1100)),
                "payload-during-history" => {
                    platform::write_atomic(&f.directory.join(event_name("floor-1")), b"{}", 0o600)
                        .unwrap()
                }
                _ => unreachable!(),
            }),
        };
        let mut store = Store::open(anchor, &f.directory.join("journal.json")).unwrap();
        let mut reader = HistoryReader::new(&mut store, &f.directory);
        let mut stream = BoundStream::attach(receiver, &mut reader, 3).unwrap();
        assert!(stream.poll(&mut reader).unwrap().is_none());
        assert_eq!(stream.state(), State::Acquiring); // Saved floor is not UTC.
        (send.borrow_mut())("single");
        if variant == "history-ahead" {
            assert!(stream.poll(&mut reader).is_err());
            assert_eq!(stream.state(), State::ReconciliationRequired);
        } else {
            let first = stream.poll(&mut reader).unwrap().unwrap();
            assert_eq!(stream.state(), State::Bounded);
            match variant {
                "quiet" => {
                    let later = stream.poll(&mut reader).unwrap().unwrap();
                    assert!(later.endpoints().1 >= first.endpoints().1);
                    assert_eq!(f.writes(), 2);
                    stream.invalidate();
                }
                "raw-history-delivery" => {
                    let current = reader.read().unwrap();
                    let mut delivery = stream.history_delivery(&current).unwrap();
                    assert!(delivery.support(&floor_statement(1000)).is_err());
                    assert_eq!(stream.state(), State::Fenced);
                }
                "delivery-binding-change" => {
                    f.catalog_commit("register-model", &register());
                    // The old Store correctly fences on another writer's head.
                    // Reopen the current checkpoint without refreshing the
                    // retained stream, and test that delivery still refuses.
                    let current = HistoryReader::new(&mut f.store(), &f.directory)
                        .read()
                        .unwrap();
                    assert!(stream.history_delivery(&current).is_err());
                    assert_eq!(stream.state(), State::Fenced);
                }
                "catalog-change" => {
                    f.catalog_commit("register-model", &register());
                }
                "floor-change" => {
                    history_commit(&f, "floor-2", &floor_statement(1100));
                }
                "pending" => {
                    platform::write_atomic(&f.directory.join("journal.pending.json"), b"{}", 0o600)
                        .unwrap()
                }
                "enrollment-change" => {
                    platform::write_atomic(&f.directory.join("enrollment.json"), b"{}", 0o600)
                        .unwrap()
                }
                "missing-payload" => {
                    fs::remove_file(f.directory.join(event_name("floor-1"))).unwrap()
                }
                "tpm-epoch" => f.anchor.0.borrow_mut().1.restart_count += 1,
                "anchor-unavailable" => f.anchor.0.borrow_mut().0 = [0; 32],
                "queued-during-history" | "delayed-history" | "payload-during-history" => {
                    // Four checkpoint reads bracket the pre-poll history replay.
                    // Fire in the post-poll replay, after sampling the candidate.
                    trigger.set(count.get() + 5);
                }
                _ => unreachable!(),
            }
            let error = stream.poll(&mut reader).unwrap_err().to_string();
            if variant == "delayed-history" {
                assert_eq!(error, "UTC producer heartbeat is missing or future-dated");
            } else if variant == "queued-during-history" {
                assert_eq!(error, "UTC stream changed during candidate evaluation");
            }
            assert_eq!(stream.state(), State::Fenced);
        }
        (send.borrow_mut())("single");
        assert!(stream.poll(&mut reader).is_err());
        assert_eq!(
            f.writes(),
            if matches!(
                variant,
                "catalog-change" | "floor-change" | "delivery-binding-change"
            ) {
                3
            } else {
                2
            }
        );
    }
    #[test]
    fn utc_history_requires_explicit_bootstrap_and_current_human() {
        let f = Fixture::new("utc-no-bootstrap");
        let statement = floor_statement(1000);
        assert!(history_call(&f, "floor-1", &statement, None).is_err());
        assert_eq!(f.writes(), 0);
        f.activate();
        for uid in [0, 1000, 1002] {
            let mut wrong = f.identity.clone();
            wrong["uid"] = uid.into();
            assert!(execute_history(
                &mut f.store(),
                &f.directory,
                || Ok(wrong.clone()),
                |_| panic!("unauthenticated actor cannot observe/write"),
                "floor-1",
                &statement,
                None
            )
            .is_err());
        }
        assert!(!f.directory.join(event_name("floor-1")).exists());
        assert_eq!(f.writes(), 1);
    }
    #[test]
    fn utc_history_and_catalog_share_one_restartable_checkpoint() {
        let f = Fixture::new("utc-shared");
        f.activate();
        let first = history_commit(&f, "floor-1", &floor_statement(1000));
        assert_eq!(first["history_version"], 1);
        assert_eq!(first["history_floor_ms"], 1000);
        for field in [
            "effect_grant",
            "trusted_utc_available",
            "delegation_available",
            "gate_closing",
        ] {
            assert_eq!(first[field], false);
        }
        let catalog = f.catalog_commit("register-model", &register());
        assert_eq!(catalog["catalog"]["state_version"], 2);
        let mut next = floor_statement(1100);
        next.boot_id = "34".repeat(16);
        next.keeper_generation = 1;
        let second = history_commit(&f, "floor-2", &next);
        assert_eq!(second["history_version"], 2);
        assert_eq!(second["history_floor_ms"], 1100);
        let catalog = f.catalog_commit("define-role", &definition(0, &["model.select"]));
        assert_eq!(catalog["catalog"]["roles"]["Operator"]["version"], 1);
        assert_eq!(f.store().snapshot().unwrap().entries.len(), 5);
        assert_eq!(f.inspect()["product_admin_active"], true);
        assert_eq!(f.writes(), 5);
    }
    #[test]
    fn utc_history_exact_acknowledgement_never_reobserves_or_rewrites_time() {
        let f = Fixture::new("utc-replay");
        f.activate();
        let statement = floor_statement(1000);
        history_commit(&f, "floor-1", &statement);
        history_commit(&f, "floor-2", &floor_statement(1100));
        let inspected = execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            |_| panic!("historical replay is not acquisition"),
            "floor-1",
            &statement,
            None,
        )
        .unwrap();
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            |_| panic!("historical replay is not acquisition"),
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(result["replayed"], true);
        assert_eq!(result["history_floor_ms"], 1100);
        assert_eq!(result["tpm_write_performed"], false);
        assert_eq!(f.writes(), 3);
        assert!(history_call(&f, "floor-1", &floor_statement(1001), None).is_err());
        assert!(f.catalog_inspect("floor-1", &register()).is_err());
    }
    #[test]
    fn utc_history_noops_regression_and_cross_activity_requests_never_append() {
        let f = Fixture::new("utc-noops");
        f.activate();
        history_commit(&f, "floor-1", &floor_statement(1000));
        let equal = history_commit(&f, "floor-equal", &floor_statement(1000));
        assert_eq!(equal["no_change"], true);
        assert_eq!(equal["committed"], false);
        assert_eq!(f.writes(), 2);
        assert!(!f.directory.join(event_name("floor-equal")).exists());
        assert!(history_call(&f, "floor-old", &floor_statement(999), None).is_err());
        f.catalog_commit("register-model", &register());
        assert!(history_call(&f, "register-model", &floor_statement(1100), None).is_err());
        assert_eq!(f.writes(), 3);
    }
    #[test]
    fn utc_history_stale_review_and_changed_tpm_epoch_cannot_prepare() {
        for variant in 0..3 {
            let f = Fixture::new(&format!("utc-stale-{variant}"));
            f.activate();
            let statement = floor_statement(1000);
            let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
            match variant {
                0 => {
                    f.catalog_commit("register-model", &register());
                }
                1 => f.anchor.0.borrow_mut().1.restart_count += 1,
                _ => f.anchor.0.borrow_mut().1.reset_count += 1,
            }
            let before = f.writes();
            assert!(history_call(
                &f,
                "floor-1",
                &statement,
                Some(inspected["review_sha256"].as_str().unwrap())
            )
            .is_err());
            assert_eq!(f.writes(), before);
            assert!(!f.directory.join(event_name("floor-1")).exists());
        }
    }
    #[test]
    fn utc_history_final_source_loss_fences_preparation_without_tpm_dispatch() {
        let f = Fixture::new("utc-source-loss");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        let mut observations = 0;
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            |proposed| {
                observations += 1;
                if observations == 9 {
                    return Err("source fenced at final boundary".into());
                }
                proposed.supported_by(&observation(&statement))
            },
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(observations, 9);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("floor-1")).exists());
        assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
    }
    #[test]
    fn utc_history_final_principal_revocation_fences_without_dispatch() {
        let f = Fixture::new("utc-revoke");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        let mut authentications = 0;
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || {
                authentications += 1;
                let mut identity = f.identity.clone();
                if authentications == 5 {
                    identity["generation"] = 2.into();
                }
                Ok(identity)
            },
            |proposed| proposed.supported_by(&observation(&statement)),
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(authentications, 5);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
    }
    #[test]
    fn utc_history_source_loss_during_final_pam_check_cannot_dispatch() {
        let f = Fixture::new("utc-pam-source-loss");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        let authentications = std::cell::Cell::new(0);
        let source_lost = std::cell::Cell::new(false);
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || {
                authentications.set(authentications.get() + 1);
                if authentications.get() == 5 {
                    source_lost.set(true);
                }
                Ok(f.identity.clone())
            },
            |proposed| {
                if source_lost.get() {
                    return Err("UTC source lost during PAM".into());
                }
                proposed.supported_by(&observation(&statement))
            },
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(authentications.get(), 5);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(f.directory.join(event_name("floor-1")).exists());
    }
    #[test]
    fn utc_history_every_source_refusal_preserves_evidence_without_dispatch() {
        for refusal in 1..=9 {
            let f = Fixture::new(&format!("utc-source-boundary-{refusal}"));
            f.activate();
            let statement = floor_statement(1000);
            let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
            let mut calls = 0;
            let result = execute_history(
                &mut f.store(),
                &f.directory,
                || Ok(f.identity.clone()),
                |proposed| {
                    calls += 1;
                    if calls == refusal {
                        return Err("current source refused".into());
                    }
                    proposed.supported_by(&observation(&statement))
                },
                "floor-1",
                &statement,
                Some(inspected["review_sha256"].as_str().unwrap()),
            );
            assert!(result.is_err(), "boundary {refusal}");
            assert_eq!(calls, refusal);
            assert_eq!(f.writes(), 1);
            assert_eq!(
                f.directory.join(event_name("floor-1")).exists(),
                refusal >= 4
            );
            assert_eq!(
                f.directory.join("journal.pending.json").exists(),
                refusal >= 6
            );
        }
    }
    #[test]
    fn utc_history_lost_reply_requires_reviewed_committed_publication_not_retry() {
        let f = Fixture::new("utc-lost-reply");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        f.anchor.0.borrow_mut().3 = true;
        assert!(history_call(
            &f,
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(f.writes(), 2);
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        f.anchor.0.borrow_mut().3 = false;
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let reviewed = recovery.digest().unwrap();
        let mut recovered = recovery.publish(&reviewed).unwrap();
        let result = execute_history(
            &mut recovered,
            &f.directory,
            || Ok(f.identity.clone()),
            |_| panic!("publication must not redispatch or reacquire"),
            "floor-1",
            &statement,
            None,
        )
        .unwrap();
        assert_eq!(result["history_floor_ms"], 1000);
        assert_eq!(result["replayed"], true);
        assert_eq!(f.writes(), 2);
    }
    #[test]
    fn utc_history_substitution_missing_and_noncanonical_payloads_fence_catalog_too() {
        for variant in 0..4 {
            let f = Fixture::new(&format!("utc-payload-{variant}"));
            f.activate();
            history_commit(&f, "floor-1", &floor_statement(1000));
            let path = f.directory.join(event_name("floor-1"));
            let original = fs::read(&path).unwrap();
            match variant {
                0 => {
                    fs::remove_file(&path).unwrap();
                }
                1 => {
                    let mut changed: HistoryRecord = serde_json::from_slice(&original).unwrap();
                    changed.statement.floor_ms = 999;
                    platform::write_atomic(&path, &serde_json::to_vec(&changed).unwrap(), 0o600)
                        .unwrap();
                }
                2 => {
                    let mut changed = original.clone();
                    changed.push(b'\n');
                    platform::write_atomic(&path, &changed, 0o600).unwrap();
                }
                _ => {
                    fs::remove_file(&path).unwrap();
                    symlink("missing", &path).unwrap();
                }
            }
            assert!(f.catalog_inspect("register-model", &register()).is_err());
            assert!(history_call(&f, "floor-2", &floor_statement(1100), None).is_err());
            assert_eq!(f.writes(), 2);
        }
    }
    #[test]
    fn utc_history_orphan_intent_requires_exact_request_and_preserves_bytes() {
        let f = Fixture::new("utc-orphan");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        // The durable file uses Record field order, not Value map order.
        let record: HistoryRecord = serde_json::from_value(inspected["proposal"].clone()).unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        platform::write_atomic(&f.directory.join(event_name("floor-1")), &bytes, 0o600).unwrap();
        assert!(f.catalog_inspect("register-model", &register()).is_err());
        assert!(history_call(&f, "floor-2", &floor_statement(1100), None).is_err());
        let repeated = history_call(&f, "floor-1", &statement, None).unwrap();
        assert_eq!(inspected["review_sha256"], repeated["review_sha256"]);
        history_call(
            &f,
            "floor-1",
            &statement,
            Some(repeated["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(f.writes(), 2);
        assert_eq!(
            fs::read(f.directory.join(event_name("floor-1"))).unwrap(),
            bytes
        );
    }
    #[test]
    fn utc_history_valid_checkpoint_does_not_excuse_forged_semantic_bindings() {
        for variant in 0..9 {
            let f = Fixture::new(&format!("utc-forged-{variant}"));
            f.activate();
            let statement = floor_statement(1000);
            let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
            let mut record: HistoryRecord =
                serde_json::from_value(inspected["proposal"].clone()).unwrap();
            match variant {
                0 => record.deployment = "ab".repeat(32),
                1 => record.enrollment_sha256 = "ab".repeat(32),
                2 => record.principal.generation += 1,
                3 => record.sequence += 1,
                4 => record.previous_head = "ab".repeat(32),
                5 => record.previous_floor_ms = 1,
                6 => record.history_version_before = 1,
                7 => record.kind = "utc-authority".into(),
                _ => record.schema_version = 2,
            }
            let bytes = serde_json::to_vec(&record).unwrap();
            platform::write_atomic(&f.directory.join(event_name("floor-1")), &bytes, 0o600)
                .unwrap();
            let mut store = f.store();
            let snapshot = store.snapshot().unwrap();
            // Fake anchor deliberately accepts a generic audit append. The
            // semantic reader must reject it despite a matching checkpoint.
            store
                .append(
                    Entry {
                        request_id: "floor-1".into(),
                        authenticated_uid: 1001,
                        clock: snapshot.clock,
                        activity: utc_history::ACTIVITY.into(),
                        payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
                    },
                    |_| Ok(()),
                )
                .unwrap();
            assert!(
                f.catalog_inspect("register-model", &register()).is_err(),
                "variant {variant}"
            );
            assert!(history_call(&f, "floor-1", &statement, None).is_err());
        }
    }
    #[test]
    fn utc_history_full_journal_rollback_is_not_a_fresh_bootstrap() {
        let f = Fixture::new("utc-disk-rollback");
        f.activate();
        let path = f.directory.join("journal.json");
        let old = fs::read(&path).unwrap();
        history_commit(&f, "floor-1", &floor_statement(1000));
        platform::write_atomic(&path, &old, 0o600).unwrap();
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        assert_eq!(f.writes(), 2);
        assert!(f.directory.join(event_name("floor-1")).exists());
    }
    #[test]
    fn utc_history_payload_change_during_final_observation_prevents_dispatch() {
        let f = Fixture::new("utc-final-payload");
        f.activate();
        let statement = floor_statement(1000);
        let inspected = history_call(&f, "floor-1", &statement, None).unwrap();
        let mut observations = 0;
        let path = f.directory.join(event_name("floor-1"));
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            |proposed| {
                observations += 1;
                if observations == 8 {
                    let mut record: HistoryRecord =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    record.statement.floor_ms += 1;
                    platform::write_atomic(&path, &serde_json::to_vec(&record).unwrap(), 0o600)?;
                }
                proposed.supported_by(&observation(&statement))
            },
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(observations, 8);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(path.exists());
    }

    #[test]
    fn inspection_never_creates_role_payload_or_checkpoint() {
        let f = Fixture::new("inspect");
        let result = f.inspect();
        assert_eq!(result["product_admin_active"], false);
        assert_eq!(result["effect_grant"], false);
        assert!(!f.directory.join("bootstrap.json").exists());
        assert_eq!(f.writes(), 0);
    }

    #[test]
    fn explicit_bootstrap_persists_and_reviewed_replay_never_extends() {
        let f = Fixture::new("replay");
        let result = f.activate();
        assert_eq!(result["product_admin_active"], true);
        assert_eq!(result["delegation_available"], false);
        assert_eq!(result["tpm_write_performed"], true);
        assert_eq!(f.writes(), 1);
        let inspect = f.inspect();
        let result = execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            Some(inspect["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(result["replayed"], true);
        assert_eq!(result["tpm_write_performed"], false);
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn root_other_uid_or_changed_principal_never_bootstraps() {
        let f = Fixture::new("identity");
        for key in ["uid", "generation", "principal", "installation", "login"] {
            let mut wrong = f.identity.clone();
            wrong[key] = match key {
                "uid" => serde_json::json!(0),
                "generation" => serde_json::json!(2),
                _ => serde_json::json!("ef".repeat(32)),
            };
            assert!(execute(&mut f.store(), &f.directory, || Ok(wrong.clone()), None).is_err());
        }
        let mut wrong = f.identity.clone();
        wrong["role"] = serde_json::json!("Admin");
        assert!(execute(&mut f.store(), &f.directory, || Ok(wrong.clone()), None).is_err());
        assert_eq!(f.writes(), 0);
    }

    #[test]
    fn stale_review_or_changed_tpm_epoch_cannot_dispatch() {
        let f = Fixture::new("review");
        let digest = f.inspect()["review_sha256"].as_str().unwrap().to_owned();
        f.anchor.0.borrow_mut().1.restart_count += 1;
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            Some(&digest)
        )
        .is_err());
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            Some(&"00".repeat(32))
        )
        .is_err());
        assert_eq!(f.writes(), 0);
    }

    #[test]
    fn retained_payload_alone_is_not_admin_and_exact_preparation_is_resumable() {
        let f = Fixture::new("prepare");
        let mut store = f.store();
        let snapshot = store.snapshot().unwrap();
        let context = Context::load(&f.directory, &snapshot.deployment).unwrap();
        context.prepare(&context.payload(&snapshot.head)).unwrap();
        assert_eq!(f.inspect()["product_admin_active"], false);
        assert_eq!(f.activate()["product_admin_active"], true);
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn changed_or_missing_committed_payload_fences_authorization() {
        let f = Fixture::new("payload");
        f.activate();
        let path = f.directory.join("bootstrap.json");
        let original = fs::read(&path).unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["role"] = serde_json::json!("Other");
        platform::write_atomic(&path, &serde_json::to_vec(&changed).unwrap(), 0o600).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        fs::remove_file(&path).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn partial_noncanonical_symlink_and_public_payloads_are_preserved_and_refused() {
        let f = Fixture::new("unsafe");
        let path = f.directory.join("bootstrap.json");
        platform::write_atomic(&path, b"{", 0o600).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"{");
        fs::remove_file(&path).unwrap();
        symlink("nonexistent", &path).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        fs::remove_file(&path).unwrap();
        let snapshot = f.store().snapshot().unwrap();
        let context = Context::load(&f.directory, &snapshot.deployment).unwrap();
        let bytes = context.prepare(&context.payload(&snapshot.head)).unwrap();
        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        platform::write_atomic(&path, &noncanonical, 0o600).unwrap();
        assert!(context.existing().is_err());
        platform::write_atomic(&path, &bytes, 0o600).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(context.existing().is_err());
        assert_eq!(f.writes(), 0);
    }

    #[test]
    fn lost_tpm_reply_requires_explicit_publication_not_redispatch() {
        let f = Fixture::new("lost");
        let review = f.inspect();
        f.anchor.0.borrow_mut().3 = true;
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            Some(review["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(f.writes(), 1);
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        drop(recovery.publish(&digest).unwrap());
        assert_eq!(f.inspect()["product_admin_active"], true);
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn revoked_auth_after_journal_preparation_retains_fence_without_tpm_write() {
        let f = Fixture::new("revoked");
        let review = f.inspect();
        let mut calls = 0;
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || {
                calls += 1;
                if calls >= 4 {
                    return Err("expired or revoked authentication".into());
                }
                Ok(f.identity.clone())
            },
            Some(review["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(f.writes(), 0);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(Store::open(f.anchor.clone(), &f.directory.join("journal.json")).is_err());
    }

    #[test]
    fn payload_substitution_at_last_auth_boundary_prevents_dispatch() {
        let f = Fixture::new("substitution");
        let review = f.inspect();
        let mut calls = 0;
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || {
                calls += 1;
                if calls == 4 {
                    platform::write_atomic(&f.directory.join("bootstrap.json"), b"{}", 0o600)?;
                }
                Ok(f.identity.clone())
            },
            Some(review["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(f.writes(), 0);
    }

    #[test]
    fn enrollment_substitution_and_foreign_audit_history_do_not_activate_admin() {
        let f = Fixture::new("foreign");
        let mut store = f.store();
        let clock = store.snapshot().unwrap().clock;
        store
            .append(
                Entry {
                    request_id: "other".into(),
                    authenticated_uid: 1001,
                    clock,
                    activity: "policy.audit".into(),
                    payload_sha256: "ab".repeat(32),
                },
                |_| Ok(()),
            )
            .unwrap();
        assert!(execute(&mut store, &f.directory, || Ok(f.identity.clone()), None).is_err());
        assert_eq!(f.writes(), 1);
        let other = Fixture::new("enrollment-substitution");
        platform::write_atomic(&f.directory.join("enrollment.json"), b"{}", 0o600).unwrap();
        assert!(execute(
            &mut store,
            &f.directory,
            || Ok(other.identity.clone()),
            None
        )
        .is_err());
    }

    #[test]
    fn rollback_to_genesis_is_not_a_new_bootstrap() {
        let f = Fixture::new("rollback");
        let path = f.directory.join("journal.json");
        let initial = fs::read(&path).unwrap();
        f.activate();
        platform::write_atomic(&path, &initial, 0o600).unwrap();
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        assert_eq!(f.writes(), 1);
    }

    fn register() -> Command {
        Command::RegisterActivity {
            activity: "model.select".into(),
        }
    }
    fn definition(version: u64, activities: &[&str]) -> Command {
        Command::DefineRole {
            name: "Operator".into(),
            activities: activities.iter().map(|v| (*v).into()).collect(),
            expected_version: version,
        }
    }

    #[test]
    fn catalog_requires_bootstrap_and_exact_fresh_admin_principal() {
        let f = Fixture::new("catalog-auth");
        assert!(f.catalog_inspect("register", &register()).is_err());
        assert_eq!(f.writes(), 0);
        f.activate();
        let mut other = f.identity.clone();
        other["principal"] = serde_json::json!("ef".repeat(32));
        assert!(execute_catalog(
            &mut f.store(),
            &f.directory,
            || Ok(other.clone()),
            "register",
            &register(),
            None
        )
        .is_err());
        assert!(!f.directory.join(event_name("register")).exists());
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn finite_catalog_survives_restart_updates_and_historical_request_replay() {
        let f = Fixture::new("catalog-replay");
        f.activate();
        let inspected = f.catalog_inspect("register", &register()).unwrap();
        assert_eq!(inspected["committed"], false);
        assert!(!f.directory.join(event_name("register")).exists());
        f.catalog_commit("register", &register());
        let original = f.catalog_commit("define", &definition(0, &["model.select"]));
        assert_eq!(original["catalog"]["roles"]["Operator"]["version"], 1);
        let updated = f.catalog_commit(
            "update",
            &definition(1, &["admin.role.define", "model.select"]),
        );
        assert_eq!(updated["catalog"]["roles"]["Operator"]["version"], 2);
        let replay = f.catalog_commit("define", &definition(0, &["model.select"]));
        assert_eq!(replay["proposal"], original["proposal"]);
        assert_eq!(replay["catalog"]["roles"]["Operator"]["version"], 2);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["tpm_write_performed"], false);
        assert_eq!(replay["effect_grant"], false);
        assert_eq!(f.inspect()["product_admin_active"], true);
        assert_eq!(f.writes(), 4);
    }

    #[test]
    fn catalog_conflicts_undeclared_activity_and_root_role_never_prepare() {
        let f = Fixture::new("catalog-deny");
        f.activate();
        f.catalog_commit("register", &register());
        f.catalog_commit("define", &definition(0, &["model.select"]));
        for (request, command) in [
            ("register", definition(0, &["model.select"])),
            ("stale", definition(0, &["model.select"])),
            ("unknown", definition(1, &["unknown"])),
            (
                "root",
                Command::DefineRole {
                    name: "Admin".into(),
                    activities: vec!["model.select".into()],
                    expected_version: 0,
                },
            ),
            (
                "wildcard",
                Command::RegisterActivity {
                    activity: "model.*".into(),
                },
            ),
        ] {
            assert!(f.catalog_inspect(request, &command).is_err());
            if request != "register" {
                assert!(!f.directory.join(event_name(request)).exists());
            }
        }
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn valid_checkpoint_digest_does_not_excuse_forged_semantic_bindings() {
        for field in ["previous-head", "principal", "sequence", "state-version"] {
            let f = Fixture::new(&format!("catalog-forged-{field}"));
            f.activate();
            let inspected = f.catalog_inspect("forged", &register()).unwrap();
            let mut event: CatalogEvent =
                serde_json::from_value(inspected["proposal"].clone()).unwrap();
            match field {
                "previous-head" => event.previous_head = "ef".repeat(32),
                "principal" => event.principal.generation += 1,
                "sequence" => event.sequence += 1,
                "state-version" => event.state_version_before += 1,
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&event).unwrap();
            platform::write_atomic(&f.directory.join(event_name("forged")), &bytes, 0o600).unwrap();
            let mut store = f.store();
            let clock = store.snapshot().unwrap().clock;
            // Inject into the inert test adapter, not through a product API.
            // Semantic proof must remain mandatory even when digest/head match.
            store
                .append(
                    Entry {
                        request_id: "forged".into(),
                        authenticated_uid: 1001,
                        clock,
                        activity: register().activity().into(),
                        payload_sha256: bundle::hex(&Sha256::digest(&bytes)),
                    },
                    |_| Ok(()),
                )
                .unwrap();
            assert!(f.catalog_inspect("next", &register()).is_err());
            assert!(execute(
                &mut f.store(),
                &f.directory,
                || Ok(f.identity.clone()),
                None
            )
            .is_err());
            assert_eq!(f.writes(), 2);
        }
    }

    #[test]
    fn catalog_noops_have_no_new_payload_receipt_or_version() {
        let f = Fixture::new("catalog-noop");
        f.activate();
        f.catalog_commit("register", &register());
        let noop = f.catalog_commit("register-again", &register());
        assert_eq!(noop["no_change"], true);
        assert_eq!(noop["committed"], false);
        assert!(!f.directory.join(event_name("register-again")).exists());
        f.catalog_commit("define", &definition(0, &["model.select"]));
        let noop = f.catalog_commit("same-role", &definition(1, &["model.select"]));
        assert_eq!(noop["catalog"]["state_version"], 3);
        assert_eq!(noop["catalog"]["roles"]["Operator"]["version"], 1);
        assert_eq!(f.writes(), 3);
        let inspected = f.catalog_inspect("unsupported-noop", &register()).unwrap();
        let event: CatalogEvent = serde_json::from_value(inspected["proposal"].clone()).unwrap();
        let path = f.directory.join(event_name("unsupported-noop"));
        platform::write_atomic(&path, &serde_json::to_vec(&event).unwrap(), 0o600).unwrap();
        assert!(f.catalog_inspect("unsupported-noop", &register()).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec(&event).unwrap()
        );
        assert_eq!(f.writes(), 3);
    }

    #[test]
    fn orphan_preparation_blocks_unrelated_work_but_exact_review_can_resume() {
        let f = Fixture::new("catalog-orphan");
        f.activate();
        let inspected = f.catalog_inspect("register", &register()).unwrap();
        let event: CatalogEvent = serde_json::from_value(inspected["proposal"].clone()).unwrap();
        let path = f.directory.join(event_name("register"));
        platform::write_atomic(&path, &serde_json::to_vec(&event).unwrap(), 0o600).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        assert!(f.catalog_inspect("other", &register()).is_err());
        assert_eq!(
            f.catalog_inspect("register", &register()).unwrap()["review_sha256"],
            inspected["review_sha256"]
        );
        assert_eq!(f.catalog_commit("register", &register())["committed"], true);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn changed_missing_or_partial_catalog_payload_never_reconstructs_authority() {
        let f = Fixture::new("catalog-payload");
        f.activate();
        f.catalog_commit("register", &register());
        let path = f.directory.join(event_name("register"));
        let original = fs::read(&path).unwrap();
        platform::write_atomic(&path, b"{", 0o600).unwrap();
        assert!(f
            .catalog_inspect("define", &definition(0, &["model.select"]))
            .is_err());
        fs::remove_file(&path).unwrap();
        assert!(execute(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            None
        )
        .is_err());
        let mut changed: CatalogEvent = serde_json::from_slice(&original).unwrap();
        changed.command = Command::RegisterActivity {
            activity: "sign.production".into(),
        };
        platform::write_atomic(&path, &serde_json::to_vec(&changed).unwrap(), 0o600).unwrap();
        assert!(f.catalog_inspect("next", &register()).is_err());
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn catalog_lost_tpm_reply_requires_reviewed_committed_publication() {
        let f = Fixture::new("catalog-lost");
        f.activate();
        let inspected = f.catalog_inspect("register", &register()).unwrap();
        f.anchor.0.borrow_mut().3 = true;
        assert!(execute_catalog(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            "register",
            &register(),
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        let path = f.directory.join("journal.json");
        assert!(Store::open(f.anchor.clone(), &path).is_err());
        let recovery = admin_journal::Recovery::inspect(f.anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        drop(recovery.publish(&digest).unwrap());
        let replay = f.catalog_commit("register", &register());
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["catalog"]["state_version"], 2);
        assert_eq!(f.writes(), 2);
    }

    #[test]
    fn final_catalog_writer_revocation_fences_without_dispatch() {
        let f = Fixture::new("catalog-revoked");
        f.activate();
        let inspected = f.catalog_inspect("register", &register()).unwrap();
        let mut calls = 0;
        assert!(execute_catalog(
            &mut f.store(),
            &f.directory,
            || {
                calls += 1;
                if calls >= 5 {
                    return Err("authentication expired at final writer boundary".into());
                }
                Ok(f.identity.clone())
            },
            "register",
            &register(),
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        assert_eq!(calls, 5);
        assert_eq!(f.writes(), 1);
        assert!(f.directory.join("journal.pending.json").exists());
        assert!(admin_journal::Recovery::inspect(
            f.anchor.clone(),
            &f.directory.join("journal.json")
        )
        .is_err());
    }

    #[test]
    fn catalog_review_epoch_and_request_syntax_are_closed() {
        let f = Fixture::new("catalog-review");
        f.activate();
        let inspected = f.catalog_inspect("register", &register()).unwrap();
        f.anchor.0.borrow_mut().1.reset_count += 1;
        assert!(execute_catalog(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            "register",
            &register(),
            Some(inspected["review_sha256"].as_str().unwrap())
        )
        .is_err());
        for args in [
            vec![],
            vec!["admin-role-define"],
            vec![
                "admin-activity-register",
                "human",
                "../target",
                "model.select",
            ],
            vec![
                "admin-role-define",
                "human",
                "request",
                "Operator",
                "-1",
                "model.select",
            ],
            vec![
                "admin-role-define",
                "human",
                "request",
                "Operator",
                "0",
                "model.select",
                "model.select",
            ],
            vec!["admin-activity-register", "human", REQUEST, "model.select"],
        ] {
            assert!(parse_command(&args.iter().map(|v| (*v).into()).collect::<Vec<_>>()).is_err());
        }
        assert_eq!(f.writes(), 1);
    }

    #[test]
    fn finite_catalog_json_only_delivers_closed_valid_governance_data() {
        let assignment = serde_json::json!({"action":"assign_role","assignment":{
            "id":"operator-one","subject":"12".repeat(32),"subject_generation":1,
            "role":"Operator","role_version":1,"version":1,"not_before_ms":1_000,
            "expires_ms":61_000,"revoked":false}});
        let grant = serde_json::json!({"action":"issue_grant","grant":{
            "id":"infer-one","assignment":"operator-one","assignment_version":1,
            "subject":"12".repeat(32),"subject_generation":1,"action":"inference.execute",
            "selector":{"kind":"model","id":"Qwen3-4B","generation":1,"digest":"34".repeat(32)},
            "constraints":{"max_input_bytes":8192,"max_output_bytes":8192,"max_units":128},
            "version":1,"not_before_ms":1_000,"expires_ms":61_000,"revoked":false}});
        for value in [
            assignment,
            grant,
            serde_json::json!({"action":"revoke_assignment","assignment":"operator-one","expected_version":1}),
            serde_json::json!({"action":"revoke_grant","grant":"infer-one","expected_version":1}),
        ] {
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(finite_catalog_json(&bytes).is_ok());
            let mut expanded = value;
            expanded["authenticated"] = true.into();
            assert!(finite_catalog_json(&serde_json::to_vec(&expanded).unwrap()).is_err());
        }
        for value in [
            serde_json::json!({"action":"register_activity","activity":"inference.execute"}),
            serde_json::json!({"action":"rotate_admin","expected_generation":1}),
            serde_json::json!({"action":"permit_account_publication","transaction":"password-one"}),
            serde_json::json!({"action":"revoke_grant","grant":"*","expected_version":1}),
            serde_json::json!({"action":"revoke_grant","grant":"infer-one","expected_version":0}),
            serde_json::json!({"action":"trusted_grant","subject":"root"}),
        ] {
            assert!(finite_catalog_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(finite_catalog_json(&[]).is_err());
        assert!(finite_catalog_json(&vec![b' '; MAX_GRANT_COMMAND_INPUT + 1]).is_err());
        assert!(finite_catalog_json(b"{}{}").is_err());
    }

    #[test]
    fn finite_catalog_cli_reads_bounded_regular_inert_file_and_exact_commit_shape() {
        let fixture = Fixture::new("finite-catalog-cli");
        let path = fixture.directory.join("command-input.json");
        fs::write(
            &path,
            br#"{"action":"revoke_grant","grant":"infer-one","expected_version":1}"#,
        )
        .unwrap();
        let mut args = vec![
            "admin-catalog".into(),
            "human".into(),
            "grant-revoke-one".into(),
            path.to_str().unwrap().into(),
        ];
        let (login, request, command, review) = parse_command(&args).unwrap();
        assert_eq!(login, "human");
        assert_eq!(request, "grant-revoke-one");
        assert!(matches!(command, Command::RevokeGrant { .. }));
        assert!(review.is_none());
        args.extend(["--commit".into(), "56".repeat(32)]);
        assert_eq!(parse_command(&args).unwrap().3, Some(args[5].as_str()));
        args[5] = "caller-approval".into();
        assert!(parse_command(&args).is_err());
        args.truncate(4);
        args.push("--commit".into());
        assert!(parse_command(&args).is_err());
        let link = fixture.directory.join("command-link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        args.truncate(4);
        args[3] = link.to_str().unwrap().into();
        assert!(parse_command(&args).is_err());
        args[3] = fixture.directory.to_str().unwrap().into();
        assert!(parse_command(&args).is_err());
        args[3] = path.to_str().unwrap().into();
        fs::write(&path, vec![b' '; MAX_GRANT_COMMAND_INPUT + 1]).unwrap();
        assert!(parse_command(&args).is_err());
        assert_eq!(fixture.writes(), 0);
    }

    #[test]
    #[ignore = "requires already enrolled isolated existing-owner software TPM"]
    fn emulator_bootstrap() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let directory = root.join("admin");
        let connect = || {
            let (_, secret) = crate::admin_credentials::load_at(
                &directory,
                &root.join("pcr-public.pem"),
                &root.join("pcr-signature.json"),
                |d, n, p, b, s| crate::owner_credential::fixture_unseal(&root, d, n, p, b, s),
            )?;
            let anchor = tpm::LocalAnchor::pending_enrollment_fixture(
                &root,
                &secret,
                tpm::exclusive_lock(&root.join("bootstrap.lock"))?,
            )?;
            Store::open(anchor, &directory.join("journal.json"))
        };
        let mut store = connect().unwrap();
        let snapshot = store.snapshot().unwrap();
        let context = Context::load(&directory, &snapshot.deployment).unwrap();
        let identity = serde_json::to_value(&context.principal).unwrap();
        // This integration supplies a fixture identity; real PAM is tested
        // separately. It cannot establish installed PAM-to-TPM acceptance.
        let inspected = execute(&mut store, &directory, || Ok(identity.clone()), None).unwrap();
        assert_eq!(inspected["product_admin_active"], false);
        let activated = execute(
            &mut store,
            &directory,
            || Ok(identity.clone()),
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(activated["product_admin_active"], true);
        assert_eq!(activated["tpm_write_performed"], true);
        let committed = store.snapshot().unwrap().head;
        drop(store);
        let mut restarted = connect().unwrap();
        let inspected = execute(&mut restarted, &directory, || Ok(identity.clone()), None).unwrap();
        let replay = execute(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(replay["product_admin_active"], true);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["effect_grant"], false);
        assert_eq!(restarted.snapshot().unwrap().head, committed);
        let inspected = execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "register-model",
            &register(),
            None,
        )
        .unwrap();
        execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "register-model",
            &register(),
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        let command = definition(0, &["model.select"]);
        let inspected = execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "define-operator",
            &command,
            None,
        )
        .unwrap();
        let defined = execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "define-operator",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(defined["catalog"]["roles"]["Operator"]["version"], 1);
        let committed = restarted.snapshot().unwrap().head;
        drop(restarted);
        let mut restarted = connect().unwrap();
        let inspected = execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "define-operator",
            &command,
            None,
        )
        .unwrap();
        let replay = execute_catalog(
            &mut restarted,
            &directory,
            || Ok(identity.clone()),
            "define-operator",
            &command,
            Some(inspected["review_sha256"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["delegation_available"], false);
        assert_eq!(restarted.snapshot().unwrap().head, committed);
    }
}

#[cfg(test)]
mod current_principal_projection_tests {
    use super::*;
    #[test]
    fn projected_current_generation_is_catalog_bound_and_disabled_deleted_activation_refuse() {
        let principal = "cd".repeat(32);
        let registry:crate::principal::Registry=serde_json::from_value(serde_json::json!({"schema_version":1,
            "installation":"ab".repeat(32),"principals":[{"id":principal,"generation":1,"login":"human","uid":1001,"enabled":true}]})).unwrap();
        let baseline = registry.account("human").unwrap().clone();
        let local = registry.identity(&baseline);
        let mut catalog = Catalog::initial();
        catalog
            .apply(&Command::AdoptPrincipals { registry })
            .unwrap();
        catalog.principal_states.insert(
            principal.clone(),
            admin_roles::PrincipalState {
                generation: 7,
                enabled: true,
            },
        );
        let identity = catalog.resolve_principal(&local).unwrap();
        assert_eq!(
            current_projection(&baseline, &identity).unwrap().generation,
            7
        );
        assert_eq!(baseline.generation, 1);
        projection_available(&catalog, &principal).unwrap();
        catalog
            .principal_states
            .get_mut(&principal)
            .unwrap()
            .enabled = false;
        assert!(catalog.resolve_principal(&local).is_err());
        assert!(projection_available(&catalog, &principal).is_err());
        catalog
            .principal_states
            .get_mut(&principal)
            .unwrap()
            .enabled = true;
        catalog.deleted_principals.insert(principal.clone());
        assert!(projection_available(&catalog, &principal).is_err());
        catalog.deleted_principals.clear();
        catalog.needs_password_aging.insert(principal.clone());
        assert!(projection_available(&catalog, &principal).is_err());
        let mut counterfeit = identity;
        counterfeit["uid"] = 1002.into();
        assert!(current_projection(&baseline, &counterfeit).is_err());
    }
}
