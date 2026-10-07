//! Explicit product Admin bootstrap atop the inert TPM checkpoint adapter.
//! The receipt establishes one governance principal, never an effect grant.
//! No implicit root role, automatic enrollment, transfer, reset or recovery.
use crate::{
    admin_enrollment,
    admin_journal::{self, Entry, Snapshot, Store},
    admin_roles::{self, Catalog, Command},
    authentication, bundle, platform,
    tpm::{self, Checkpoint},
    utc_history::{self, History, Observation, Record as HistoryRecord, Statement},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
                let (record, bytes) = utc_history::read(
                    &self.directory.join(event_name(&entry.request_id)),
                    &entry.request_id,
                )?;
                if !admin_roles::identifier(&entry.request_id)
                    || entry.request_id == REQUEST
                    || record.deployment != self.deployment
                    || record.principal != self.principal
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
            if !admin_roles::identifier(&entry.request_id)
                || entry.request_id == REQUEST
                || event.schema_version != 1
                || event.kind != "native-admin-catalog-event"
                || event.deployment != self.deployment
                || event.principal != self.principal
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
        if let Some(anchored) = &catalog.principal_registry {
            let current = crate::principal::RegistryBinding::capture(self.registry_path)?;
            if current.current()? != anchored {
                return Err("installed principal registry differs from TPM-backed authority; preserve state".into());
            }
        }
        Ok((catalog, events, history, records))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PrincipalBinding {
    deployment: String,
    enrollment_sha256: String,
    checkpoint_head: String,
    reset_count: u32,
    restart_count: u32,
    identity: serde_json::Value,
}

/// Owned by the protected TPM/PAM composition. No caller-selected path or
/// identity is accepted by the public reader; every read needs a live account.
pub(crate) struct PrincipalReader<'a, A: Checkpoint> {
    store: &'a mut Store<A>,
    directory: &'a Path,
    registry_path: &'a Path,
    last_clock: Option<tpm::Clock>,
    fenced: bool,
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
            last_clock: None,
            fenced: false,
        }
    }

    fn replay(&mut self, local: &serde_json::Value) -> Result<(PrincipalBinding, tpm::Clock)> {
        let registry = crate::principal::RegistryBinding::capture(self.registry_path)?;
        let snapshot = self.store.snapshot()?;
        let context = Context::load_at(self.directory, &snapshot.deployment, self.registry_path)?;
        if !context.bootstrap_state(&snapshot)?.1 {
            return Err("explicit product Admin bootstrap required".into());
        }
        let (catalog, _) = context.events(&snapshot, None)?;
        let identity = catalog.resolve_principal(local)?;
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
        Ok((
            PrincipalBinding {
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
        if self.fenced {
            return Err("principal authority reader is fenced".into());
        }
        // An error or unwinding cannot reactivate the reader after a lost proof.
        self.fenced = true;
        let (before, first_clock) = self.replay(local)?;
        if let Some(previous) = self.last_clock {
            first_clock.elapsed_since(previous)?;
        }
        let (after, last_clock) = self.replay(local)?;
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
    ) -> Result<PrincipalBinding> {
        let result = account.observe(|local| self.resolve(local));
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
    fenced: std::cell::Cell<bool>,
}

impl PrincipalSession {
    fn new<A: Checkpoint>(
        account: authentication::AuthenticatedAccount,
        reader: &mut PrincipalReader<'_, A>,
    ) -> Result<Self> {
        let binding = reader.read_account(&account)?;
        Ok(Self {
            account,
            binding,
            fenced: std::cell::Cell::new(false),
        })
    }

    fn identity<A: Checkpoint>(
        &self,
        reader: &mut PrincipalReader<'_, A>,
    ) -> Result<serde_json::Value> {
        if self.fenced.get() {
            return Err("governed principal session is fenced".into());
        }
        self.fenced.set(true);
        let current = self.account.observe(|local| {
            let current = reader.resolve(local)?;
            if current != self.binding {
                return Err(
                    "governed generation or shared authority changed; authenticate again".into(),
                );
            }
            Ok(current)
        });
        let current = match current {
            Ok(current) => current,
            Err(error) => {
                reader.fenced = true;
                self.close();
                return Err(error);
            }
        };
        self.fenced.set(false);
        Ok(current.identity)
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

pub fn principal_check(login: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let account = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let mut reader = PrincipalReader::new(&mut store, directory);
    let session = PrincipalSession::new(account, &mut reader)?;
    let identity = session.identity(&mut reader)?;
    session.close();
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"action":"governed-principal-check",
        "principal":identity,"authentication_current":true,"session_returned":false,
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
}

#[cfg_attr(not(test), allow(dead_code))]
impl<'a, A: Checkpoint> HistoryReader<'a, A> {
    pub(crate) fn new(store: &'a mut Store<A>, directory: &'a Path) -> Self {
        Self {
            store,
            directory,
            last_clock: None,
            fenced: false,
        }
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
        let (history, _) = context.history(&snapshot, None)?;
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

// Deliberately private and not wired to any CLI, IPC or installed service.
// The future approved composition root must supply actual authenticated UTC
// observations. A caller's Statement, runtime digest or successful fake callback
// is not source provenance or live authority. This implements the durable
// semantic transaction/replay boundary while that provider remains unavailable.
#[cfg_attr(not(test), allow(dead_code))]
fn execute_history<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    mut authenticate: impl FnMut() -> Result<serde_json::Value>,
    mut observe: impl FnMut() -> Result<Observation>,
    request: &str,
    statement: &Statement,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved UTC history request".into());
    }
    statement.validate()?;
    let snapshot = store.snapshot()?;
    let context = Context::load(directory, &snapshot.deployment)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit product Admin bootstrap required for UTC history".into());
    }
    let (history, records) = context.history(&snapshot, Some(request))?;
    let (catalog, _) = context.events(&snapshot, Some(request))?;
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
        statement.supported_by(&observe()?)?;
        (
            HistoryRecord {
                schema_version: 1,
                kind: "native-admin-utc-history".into(),
                deployment: context.deployment.clone(),
                enrollment_sha256: bundle::hex(&Sha256::digest(&context.enrollment)),
                principal: context.principal.clone(),
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
            statement.supported_by(&observe()?)?;
            context.recheck(&mut authenticate)?;
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
                statement.supported_by(&observe()?)?;
                if utc_history::read(&path, request)?.1 != bytes
                    || !context.state(&snapshot, Some(request))?.1
                    || context.history(&snapshot, Some(request))?.0 != history
                    || context.events(&snapshot, Some(request))?.0 != catalog
                {
                    return Err("UTC history inputs changed before TPM dispatch".into());
                }
                context.recheck(&mut authenticate)
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
    // A receipt is not a reusable authenticated session. Recheck freshness and
    // live principal/account state before reporting a successful observation.
    context.recheck(&mut authenticate)?;
    Ok(
        serde_json::json!({"schema_version":1,"action":"admin-bootstrap",
        "principal":context.principal,"review_sha256":digest,
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

fn execute_catalog_at<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    mut authenticate: impl FnMut() -> Result<serde_json::Value>,
    request: &str,
    command: &Command,
    reviewed: Option<&str>,
) -> Result<serde_json::Value> {
    if !admin_roles::identifier(request) || request == REQUEST {
        return Err("invalid or reserved Admin request".into());
    }
    command.validate()?;
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit product Admin bootstrap required".into());
    }
    let (catalog, events) = context.events(&snapshot, Some(request))?;
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
    let mut authenticate = || {
        if let Some(binding) = &registry_binding {
            binding.current()?;
        }
        let value = authenticate()?;
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
                principal: context.principal.clone(),
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
        "product_admin_active":true,"delegation_available":false,"effect_grant":false,
        "trusted_utc_available":false,"production_custody_verified":false,"gate_closing":false}),
    )
}

fn parse_command(args: &[String]) -> Result<(&str, &str, Command, Option<&str>)> {
    let committed = args.len() >= 2 && args[args.len() - 2] == "--commit";
    let end = args.len() - if committed { 2 } else { 0 };
    let review = if committed {
        Some(args[args.len() - 1].as_str())
    } else {
        None
    };
    let command = match args.first().map(String::as_str) {
        Some("admin-activity-register") if end == 4 => Command::RegisterActivity { activity: args[3].clone() },
        Some("admin-principal-advance") if end == 6 => Command::AdvancePrincipal {
            principal: args[3].clone(), expected_generation: args[4].parse()?, enabled: principal_enabled(&args[5])?,
        },
        Some("admin-role-define") if (6..=69).contains(&end) => {
            let mut activities = args[5..end].to_vec();
            activities.sort();
            Command::DefineRole { name: args[3].clone(), activities, expected_version: args[4].parse()? }
        }
        _ => return Err("use admin-activity-register LOGIN REQUEST ACTIVITY, admin-principal-advance LOGIN REQUEST PRINCIPAL-ID EXPECTED-GENERATION enabled|disabled, or admin-role-define LOGIN REQUEST ROLE EXPECTED-VERSION ACTIVITY...; optional --commit REVIEW-SHA256".into()),
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
    let authenticated = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let report = execute_catalog(
        &mut store,
        directory,
        || authenticated.identity(),
        request,
        &command,
        reviewed,
    )?;
    authenticated.logout();
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

pub fn adopt_principals(login: &str, request: &str, reviewed: Option<&str>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let account = authentication::local(login)?;
    let command = adoption_command(Path::new(crate::principal::REGISTRY))?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let result = execute_catalog(
        &mut store,
        directory,
        || account.identity(),
        request,
        &command,
        reviewed,
    );
    account.logout();
    println!("{}", serde_json::to_string(&result?)?);
    Ok(())
}

pub fn catalog_status(login: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let authenticated = authentication::local(login)?;
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let snapshot = store.snapshot()?;
    let context = Context::load(directory, &snapshot.deployment)?;
    if !context.state(&snapshot, None)?.1 {
        return Err("explicit product Admin bootstrap required".into());
    }
    let (catalog, _) = context.events(&snapshot, None)?;
    context.recheck(&mut || authenticated.identity())?;
    authenticated.logout();
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({"schema_version":1,
        "action":"admin-governance-status","principal":context.principal,"catalog":catalog,
        "checkpoint_head":snapshot.head,"product_admin_active":true,
        "delegation_available":false,"effect_grant":false,"gate_closing":false}))?
    );
    Ok(())
}

/// Service composition accepts only the in-process PAM observation, not a
/// serialized role/session token. The original Admin is rechecked per request.
pub(crate) fn service_request(
    account: &authentication::AuthenticatedAccount,
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
    service_request_at(
        &mut store,
        directory,
        Path::new(crate::principal::REGISTRY),
        account,
        peer,
        request,
        command,
        review,
    )
}

fn service_request_at<A: tpm::Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
    registry_path: &Path,
    account: &authentication::AuthenticatedAccount,
    peer: &crate::admin_service::Peer,
    request: &str,
    command: Option<&Command>,
    review: Option<&str>,
) -> Result<serde_json::Value> {
    peer.check()?;
    if let Some(command) = command {
        return execute_catalog_at(
            store,
            directory,
            registry_path,
            || peer.observe(|| account.identity()),
            request,
            command,
            review,
        );
    }
    if review.is_some() {
        return Err("status cannot approve a mutation".into());
    }
    let snapshot = store.snapshot()?;
    let context = Context::load_at(directory, &snapshot.deployment, registry_path)?;
    if !context.state(&snapshot, None)?.1 {
        return Err("explicit product Admin bootstrap required".into());
    }
    let (catalog, _) = context.events(&snapshot, None)?;
    context.recheck(&mut || peer.observe(|| account.identity()))?;
    Ok(
        serde_json::json!({"schema_version":1,"action":"admin-governance-status",
        "principal":context.principal,"catalog":catalog,"checkpoint_head":snapshot.head,
        "product_admin_active":true,"delegation_available":false,"effect_grant":false,"gate_closing":false}),
    )
}

#[cfg(test)]
pub(crate) fn fixture_service_request(
    root: &Path,
    account: &authentication::AuthenticatedAccount,
    peer: &crate::admin_service::Peer,
    request: &str,
    command: Option<&Command>,
    review: Option<&str>,
) -> Result<serde_json::Value> {
    peer.check()?;
    let directory = root.join("admin");
    let mut store = fixture_store(root)?;
    service_request_at(
        &mut store,
        &directory,
        &root.join("registry.json"),
        account,
        peer,
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
pub(crate) fn fixture_governed_session(
    root: &Path,
    account: authentication::AuthenticatedAccount,
) -> Result<PrincipalSession> {
    let mut store = fixture_store(root)?;
    PrincipalSession::new(
        account,
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
    let _store = fixture_store(root)?;
    session
        .account
        .observe(|_| panic!("fixture protected projection interruption"))
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
    fn observation(statement: &Statement) -> Observation {
        Observation {
            context: statement.clone(),
            utc: crate::utc_bounds::Interval::new(statement.floor_ms, statement.floor_ms + 100)
                .unwrap(),
        }
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
            || Ok(observation(statement)),
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
            if matches!(variant, "catalog-change" | "floor-change") {
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
                || panic!("unauthenticated actor cannot observe/write"),
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
            || panic!("historical replay is not acquisition"),
            "floor-1",
            &statement,
            None,
        )
        .unwrap();
        let result = execute_history(
            &mut f.store(),
            &f.directory,
            || Ok(f.identity.clone()),
            || panic!("historical replay is not acquisition"),
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
            || {
                observations += 1;
                if observations == 5 {
                    return Err("source fenced at final boundary".into());
                }
                Ok(observation(&statement))
            },
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(observations, 5);
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
            || Ok(observation(&statement)),
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
            || panic!("publication must not redispatch or reacquire"),
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
            || {
                observations += 1;
                if observations == 5 {
                    let mut record: HistoryRecord =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    record.statement.floor_ms += 1;
                    platform::write_atomic(&path, &serde_json::to_vec(&record).unwrap(), 0o600)?;
                }
                Ok(observation(&statement))
            },
            "floor-1",
            &statement,
            Some(inspected["review_sha256"].as_str().unwrap()),
        );
        assert!(result.is_err());
        assert_eq!(observations, 5);
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
