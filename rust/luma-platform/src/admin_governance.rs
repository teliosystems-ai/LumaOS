//! Explicit product Admin bootstrap atop the inert TPM checkpoint adapter.
//! The receipt establishes one governance principal, never an effect grant.
//! No implicit root role, automatic enrollment, transfer, reset or recovery.
use crate::{
    admin_enrollment,
    admin_journal::{self, Entry, Snapshot, Store},
    admin_roles::{self, Catalog, Command},
    authentication, bundle, platform,
    tpm::{self, Checkpoint},
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
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
    let bytes = tpm::private_read(&directory.join(event_name(request)), 16384)?;
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
}

impl<'a> Context<'a> {
    fn load(directory: &'a Path, deployment: &str) -> Result<Self> {
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
                self.events(snapshot, candidate)?;
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
                self.events(snapshot, candidate)?;
                Ok((payload, true))
            }
        }
    }

    fn events(
        &self,
        snapshot: &Snapshot,
        candidate: Option<&str>,
    ) -> Result<(Catalog, Vec<CatalogEvent>)> {
        let mut catalog = Catalog::initial();
        let mut events = Vec::new();
        let mut names = BTreeSet::new();
        for (position, entry) in snapshot.entries.iter().enumerate().skip(1) {
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
        Ok((catalog, events))
    }
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
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn execute_catalog<A: Checkpoint>(
    store: &mut Store<A>,
    directory: &Path,
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
    let context = Context::load(directory, &snapshot.deployment)?;
    if !context.state(&snapshot, Some(request))?.1 {
        return Err("explicit product Admin bootstrap required".into());
    }
    let (catalog, events) = context.events(&snapshot, Some(request))?;
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
        Some("admin-role-define") if (6..=69).contains(&end) => {
            let mut activities = args[5..end].to_vec();
            activities.sort();
            Command::DefineRole { name: args[3].clone(), activities, expected_version: args[4].parse()? }
        }
        _ => return Err("use admin-activity-register LOGIN REQUEST ACTIVITY or admin-role-define LOGIN REQUEST ROLE EXPECTED-VERSION ACTIVITY...; optional --commit REVIEW-SHA256".into()),
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
    println!("{}", serde_json::to_string(&report)?);
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
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({"schema_version":1,
        "action":"admin-governance-status","principal":context.principal,"catalog":catalog,
        "checkpoint_head":snapshot.head,"product_admin_active":true,
        "delegation_available":false,"effect_grant":false,"gate_closing":false}))?
    );
    Ok(())
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
