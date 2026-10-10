//! Durable explanatory evidence, never an authorization or recovery store.
//! Only live PAM/catalog/UTC boundaries admit effects; retained records cannot.
use crate::{
    admin_roles::Catalog,
    artifacts as io,
    finite_grants::{Constraints, Grant, Use},
    Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/policy-decisions";
const MAX_RECORDS: usize = 16_384;
const MAX_RECORD: u64 = 131_072;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVES: usize = 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    Allowed,
    AuthenticationUnavailable,
    PrincipalUnavailable,
    CatalogUnavailable,
    UtcUnavailable,
    CredentialsExpired,
    GrantMissing,
    GrantRevoked,
    SubjectMismatch,
    TargetMismatch,
    ConstraintExceeded,
    OutsideValidity,
    AssignmentUnavailable,
    AssignmentRevoked,
    RoleSuperseded,
    GrantDenied,
    AuthorityChanged,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionOutcome {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationOutcome {
    Completed,
    Denied,
    Uncertain,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectKind {
    Snapshot,
    Calculation,
    Checkpoint,
    ArtifactPublication,
    ArtifactExport,
    Retention,
    Deletion,
    WorkerAdmission,
    ResourceAdmission,
    Inference,
    Recovery,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Timestamp {
    pub context: crate::utc_history::Statement,
    pub lower_ms: i64,
    pub upper_ms: i64,
}
impl Timestamp {
    pub(crate) fn observed(live: &crate::utc_stream::Observation) -> Result<Self> {
        let (lower_ms, upper_ms) = live.interval().endpoints();
        let result = Self {
            context: live.context().clone(),
            lower_ms,
            upper_ms,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.lower_ms != self.context.floor_ms
            || self.upper_ms < self.lower_ms
            || self.upper_ms - self.lower_ms > 500
            || self.upper_ms > 4_102_444_800_000
        {
            return Err("invalid inert policy timestamp evidence".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Subject {
    pub principal: String,
    pub generation: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleEvidence {
    pub name: String,
    pub version: u64,
    pub activities: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantEvidence {
    pub definition: Grant,
    pub assignment: Option<crate::finite_grants::Assignment>,
    pub current_role: Option<RoleEvidence>,
    pub grant_id: String,
    pub grant_version: u64,
    pub revoked: bool,
    pub assignment_id: String,
    pub assignment_version: u64,
    pub role: String,
    pub role_version: u64,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub constraints: Constraints,
}
impl GrantEvidence {
    fn capture(catalog: &Catalog, grant: &Grant) -> Self {
        let assignment = catalog.assignments.get(&grant.assignment);
        Self {
            definition: grant.clone(),
            assignment: assignment.cloned(),
            current_role: assignment
                .and_then(|a| catalog.roles.get(&a.role))
                .map(|r| RoleEvidence {
                    name: r.name.clone(),
                    version: r.version,
                    activities: r.activities.clone(),
                }),
            grant_id: grant.id.clone(),
            grant_version: grant.version,
            revoked: grant.revoked,
            assignment_id: grant.assignment.clone(),
            assignment_version: grant.assignment_version,
            role: assignment.map_or_else(String::new, |a| a.role.clone()),
            role_version: assignment.map_or(0, |a| a.role_version),
            not_before_ms: grant.not_before_ms,
            expires_ms: grant.expires_ms,
            constraints: grant.constraints.clone(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    pub decision_id: String,
    pub policy_version: u32,
    pub policy_sha256: String,
    pub subject: Option<Subject>,
    pub checkpoint_head: Option<String>,
    pub catalog_sha256: Option<String>,
    pub grant_id: String,
    pub grant: Option<GrantEvidence>,
    pub capability: crate::finite_grants::Action,
    pub normalized_resource: crate::finite_grants::Selector,
    pub evaluated_constraints: Use,
    pub outcome: DecisionOutcome,
    pub reason_code: Reason,
    pub timestamp: Option<Timestamp>,
}

fn policy_digest() -> String {
    static POLICY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    POLICY
        .get_or_init(|| {
            let mut bytes = b"luma-native-finite-policy-decision-v1\0".to_vec();
            bytes.extend_from_slice(include_bytes!("finite_grants.rs"));
            bytes.extend_from_slice(include_bytes!("admin_governance.rs"));
            bytes.extend_from_slice(include_bytes!("policy_decisions.rs"));
            bytes.extend_from_slice(include_bytes!("../../../docs/adr/0004-policy-model.md"));
            io::digest(&bytes)
        })
        .clone()
}
fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn effect_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
impl Decision {
    pub(crate) fn unavailable(grant_id: &str, usage: &Use, reason: Reason) -> Result<Self> {
        let result = Self {
            decision_id: crate::resources::random_id()?,
            policy_version: 1,
            policy_sha256: policy_digest(),
            subject: None,
            checkpoint_head: None,
            catalog_sha256: None,
            grant_id: grant_id.into(),
            grant: None,
            capability: usage.action,
            normalized_resource: usage.selector.clone(),
            evaluated_constraints: usage.clone(),
            outcome: DecisionOutcome::Deny,
            reason_code: reason,
            timestamp: None,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn evaluate(
        catalog: &Catalog,
        identity: &serde_json::Value,
        head: &str,
        live: &crate::utc_stream::Observation,
        grant_id: &str,
        usage: &Use,
        forced: Option<Reason>,
    ) -> Result<Self> {
        let timestamp = Timestamp::observed(live)?;
        let subject = Subject {
            principal: identity["principal"]
                .as_str()
                .ok_or("missing actual policy subject")?
                .into(),
            generation: identity["generation"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("missing actual policy generation")?,
        };
        let grant = catalog.grants.get(grant_id);
        let reason = forced.unwrap_or_else(|| match grant {
            None => Reason::GrantMissing,
            Some(g) if g.revoked => Reason::GrantRevoked,
            Some(g)
                if g.subject != subject.principal || g.subject_generation != subject.generation =>
            {
                Reason::SubjectMismatch
            }
            Some(g) if g.action != usage.action || g.selector != usage.selector => {
                Reason::TargetMismatch
            }
            Some(g)
                if usage.input_bytes > g.constraints.max_input_bytes
                    || usage.output_bytes > g.constraints.max_output_bytes
                    || usage.units > g.constraints.max_units =>
            {
                Reason::ConstraintExceeded
            }
            Some(g) if live.interval().within(g.not_before_ms, g.expires_ms).ok() != Some(true) => {
                Reason::OutsideValidity
            }
            Some(g) => match catalog.assignments.get(&g.assignment) {
                None => Reason::AssignmentUnavailable,
                Some(a) if a.revoked => Reason::AssignmentRevoked,
                Some(a)
                    if catalog.roles.get(&a.role).map(|r| r.version) != Some(a.role_version) =>
                {
                    Reason::RoleSuperseded
                }
                _ if g
                    .authorize(catalog, identity, live.interval(), usage)
                    .is_err() =>
                {
                    Reason::GrantDenied
                }
                _ => Reason::Allowed,
            },
        });
        let result = Self {
            decision_id: crate::resources::random_id()?,
            policy_version: 1,
            policy_sha256: policy_digest(),
            subject: Some(subject),
            checkpoint_head: Some(head.into()),
            catalog_sha256: Some(io::digest(&serde_json::to_vec(catalog)?)),
            grant_id: grant_id.into(),
            grant: grant.map(|g| GrantEvidence::capture(catalog, g)),
            capability: usage.action,
            normalized_resource: usage.selector.clone(),
            evaluated_constraints: usage.clone(),
            outcome: if reason == Reason::Allowed {
                DecisionOutcome::Allow
            } else {
                DecisionOutcome::Deny
            },
            reason_code: reason,
            timestamp: Some(timestamp),
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        self.evaluated_constraints.validate()?;
        if !id(&self.decision_id)
            || self.policy_version != 1
            || !io::hash(&self.policy_sha256)
            || !crate::admin_roles::identifier(&self.grant_id)
            || self.capability != self.evaluated_constraints.action
            || self.normalized_resource != self.evaluated_constraints.selector
            || (self.outcome == DecisionOutcome::Allow) != (self.reason_code == Reason::Allowed)
        {
            return Err("invalid closed policy decision evidence".into());
        }
        if let Some(subject) = &self.subject {
            if crate::tpm::decode::<32>(&subject.principal)? == [0; 32] || subject.generation == 0 {
                return Err("invalid policy subject evidence".into());
            }
        }
        for value in [&self.checkpoint_head, &self.catalog_sha256]
            .into_iter()
            .flatten()
        {
            if !io::hash(value) {
                return Err("invalid policy authority digest evidence".into());
            }
        }
        if let Some(timestamp) = &self.timestamp {
            timestamp.validate()?;
        }
        if let Some(grant) = &self.grant {
            grant.definition.selector.validate()?;
            if grant.grant_id != self.grant_id
                || !crate::admin_roles::identifier(&grant.assignment_id)
                || grant.grant_version == 0
                || grant.assignment_version == 0
                || grant.not_before_ms <= 0
                || grant.expires_ms <= grant.not_before_ms
                || grant.constraints.max_input_bytes > 1_073_741_824
                || grant.constraints.max_output_bytes > 1_073_741_824
                || grant.constraints.max_units == 0
                || grant.constraints.max_units > 1_000_000
                || (!grant.role.is_empty() && !crate::admin_roles::identifier(&grant.role))
            {
                return Err("invalid policy grant evidence".into());
            }
            if grant.definition.id != grant.grant_id
                || grant.definition.version != grant.grant_version
                || grant.definition.constraints != grant.constraints
                || grant.definition.assignment != grant.assignment_id
                || grant.definition.assignment_version != grant.assignment_version
                || grant.definition.revoked != grant.revoked
                || grant.definition.not_before_ms != grant.not_before_ms
                || grant.definition.expires_ms != grant.expires_ms
            {
                return Err("policy grant definition disagrees with evaluated evidence".into());
            }
            match &grant.assignment {
                Some(assignment)
                    if assignment.id == grant.assignment_id
                        && assignment.role == grant.role
                        && assignment.role_version == grant.role_version => {}
                None if grant.role.is_empty()
                    && grant.role_version == 0
                    && grant.current_role.is_none() => {}
                _ => return Err("policy assignment evidence disagrees with current catalog".into()),
            }
            if let Some(role) = &grant.current_role {
                if role.name != grant.role
                    || role.version == 0
                    || role.activities.is_empty()
                    || role.activities.len() > 256
                    || role
                        .activities
                        .iter()
                        .any(|v| !crate::admin_roles::identifier(v))
                {
                    return Err("invalid evaluated current role evidence".into());
                }
            }
        }
        if self.outcome == DecisionOutcome::Allow
            && (self.subject.is_none()
                || self.timestamp.is_none()
                || self.checkpoint_head.is_none()
                || self.catalog_sha256.is_none()
                || self.grant.is_none())
        {
            return Err("allowed policy decision lacks actual evidence".into());
        }
        if self.outcome == DecisionOutcome::Allow {
            let grant = self
                .grant
                .as_ref()
                .ok_or("missing allowed grant evidence")?;
            let assignment = grant
                .assignment
                .as_ref()
                .ok_or("missing allowed assignment evidence")?;
            let role = grant
                .current_role
                .as_ref()
                .ok_or("missing allowed role evidence")?;
            let subject = self
                .subject
                .as_ref()
                .ok_or("missing allowed subject evidence")?;
            let time = self
                .timestamp
                .as_ref()
                .ok_or("missing allowed UTC evidence")?;
            if grant.revoked
                || assignment.revoked
                || assignment.version != grant.assignment_version
                || assignment.role_version != role.version
                || grant.definition.subject != subject.principal
                || grant.definition.subject_generation != subject.generation
                || assignment.subject != subject.principal
                || assignment.subject_generation != subject.generation
                || grant.definition.action != self.capability
                || grant.definition.selector != self.normalized_resource
                || !role
                    .activities
                    .iter()
                    .any(|v| v == self.capability.activity())
                || time.lower_ms < grant.not_before_ms
                || time.upper_ms >= grant.expires_ms
                || time.lower_ms < assignment.not_before_ms
                || time.upper_ms >= assignment.expires_ms
                || self.evaluated_constraints.input_bytes > grant.constraints.max_input_bytes
                || self.evaluated_constraints.output_bytes > grant.constraints.max_output_bytes
                || self.evaluated_constraints.units > grant.constraints.max_units
            {
                return Err("allowed policy evidence contradicts evaluated authorization".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Payload {
    OperationStarted {
        scopes: Vec<(String, Use)>,
    },
    Decision {
        decision: Decision,
    },
    EffectStarted {
        effect_id: String,
        effect_kind: EffectKind,
        decision_ids: Vec<String>,
    },
    EffectFinished {
        begin_id: String,
        begin_sha256: String,
        receipt_sha256: Option<String>,
        outcome: OperationOutcome,
    },
    OperationFinished {
        outcome: OperationOutcome,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    installation: String,
    record_id: String,
    operation_id: String,
    payload: Payload,
}
impl Record {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || !id(&self.record_id)
            || !id(&self.operation_id)
        {
            return Err("invalid policy record identity".into());
        }
        match &self.payload {
            Payload::OperationStarted { scopes } => {
                let mut grants = BTreeSet::new();
                if scopes.is_empty() || scopes.len() > 64 {
                    return Err("invalid policy operation scope count".into());
                }
                for (grant, usage) in scopes {
                    usage.validate()?;
                    if !crate::admin_roles::identifier(grant) || !grants.insert(grant) {
                        return Err("invalid policy operation scopes".into());
                    }
                }
            }
            Payload::Decision { decision } => decision.validate()?,
            Payload::EffectStarted {
                effect_id,
                decision_ids,
                ..
            } => {
                if !effect_name(effect_id)
                    || decision_ids.is_empty()
                    || decision_ids.len() > 64
                    || decision_ids.iter().any(|v| !id(v))
                    || decision_ids.iter().collect::<BTreeSet<_>>().len() != decision_ids.len()
                {
                    return Err("invalid pending policy effect".into());
                }
            }
            Payload::EffectFinished {
                begin_id,
                begin_sha256,
                receipt_sha256,
                outcome,
            } => {
                if !id(begin_id)
                    || !io::hash(begin_sha256)
                    || receipt_sha256
                        .as_ref()
                        .is_some_and(|v| !io::hash(v) || v == &"00".repeat(32))
                    || (*outcome == OperationOutcome::Completed) != receipt_sha256.is_some()
                    || *outcome == OperationOutcome::Denied
                {
                    return Err("invalid policy effect terminal evidence".into());
                }
            }
            Payload::OperationFinished { .. } => {}
        }
        Ok(())
    }
}

pub(crate) struct Store {
    root: File,
    pending: File,
    archives: File,
    retained: File,
    path: PathBuf,
    installation: String,
}
impl Store {
    pub(crate) fn installed() -> Result<Rc<Self>> {
        crate::require_root()?;
        crate::platform::require_installed()?;
        Ok(Rc::new(Self::open(
            Path::new(DIRECTORY),
            &io::installation()?,
        )?))
    }
    fn open(path: &Path, installation: &str) -> Result<Self> {
        if !io::hash(installation) {
            return Err("invalid policy evidence installation".into());
        }
        for ancestor in path.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
                return Err("policy evidence ancestor is mutable or substituted".into());
            }
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        io::private_directory(&root)?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } != 0 || stat.f_type != 0xef53 {
            return Err("policy evidence requires its installed ext4 durability domain".into());
        }
        let pending = match io::child_directory(&root, "pending") {
            Ok(value) => value,
            Err(error) => {
                if io::names(&root, MAX_RECORDS + 2)?
                    .iter()
                    .any(|v| v == "pending")
                {
                    return Err(error);
                }
                io::mkdir_at(&root, "pending")?
            }
        };
        let archives = match io::child_directory(&root, "archives") {
            Ok(value) => value,
            Err(error) => {
                if io::names(&root, MAX_RECORDS + 3)?
                    .iter()
                    .any(|v| v == "archives")
                {
                    return Err(error);
                }
                io::mkdir_at(&root, "archives")?
            }
        };
        let retained = match io::child_directory(&root, "retained") {
            Ok(value) => value,
            Err(error) => {
                if io::names(&root, MAX_RECORDS + 4)?
                    .iter()
                    .any(|v| v == "retained")
                {
                    return Err(error);
                }
                io::mkdir_at(&root, "retained")?
            }
        };
        let store = Self {
            root,
            pending,
            archives,
            retained,
            path: path.into(),
            installation: installation.into(),
        };
        let _lock = store.lock()?;
        store.inventory()?;
        Ok(store)
    }
    fn lock(&self) -> Result<File> {
        let named = fs::symlink_metadata(&self.path)?;
        let actual = self.root.metadata()?;
        if !named.is_dir() || (named.dev(), named.ino()) != (actual.dev(), actual.ino()) {
            return Err("policy evidence root changed".into());
        }
        io::private_directory(&self.root)?;
        for (name, retained) in [
            ("pending", &self.pending),
            ("archives", &self.archives),
            ("retained", &self.retained),
        ] {
            let current = io::child_directory(&self.root, name)?;
            let current = current.metadata()?;
            let before = retained.metadata()?;
            if (current.dev(), current.ino()) != (before.dev(), before.ino()) {
                return Err("policy evidence child directory substituted".into());
            }
        }
        let lock = io::open_at(&self.root, "lock", libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let m = lock.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || m.len() != 0
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0
        {
            return Err("policy evidence writer lock unavailable".into());
        }
        Ok(lock)
    }
    fn inventory(&self) -> Result<BTreeMap<String, Record>> {
        let mut records = BTreeMap::new();
        let mut total = 0u64;
        for name in io::names(&self.root, MAX_RECORDS + 4)? {
            if name == "lock" {
                continue;
            }
            if name == "pending" {
                io::private_directory(&self.pending)?;
                continue;
            }
            if name == "archives" {
                io::private_directory(&self.archives)?;
                continue;
            }
            if name == "retained" {
                io::private_directory(&self.retained)?;
                continue;
            }
            let record_id = name
                .strip_prefix("record-")
                .and_then(|v| v.strip_suffix(".json"))
                .filter(|v| id(v))
                .ok_or("unknown policy evidence member; preserve and inspect")?;
            let bytes = io::read_member(&self.root, &name, MAX_RECORD)?;
            let record: Record = serde_json::from_slice(&bytes)?;
            record.validate()?;
            if record.record_id != record_id
                || record.installation != self.installation
                || serde_json::to_vec(&record)? != bytes
            {
                return Err("noncanonical policy evidence member".into());
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("policy evidence size overflow")?;
            if total > MAX_BYTES {
                return Err("policy evidence capacity exceeded".into());
            }
            records.insert(record_id.into(), record);
        }
        let mut pending_bytes = 0u64;
        let mut pending_archive_bytes = 0u64;
        for name in io::names(&self.pending, 1024)? {
            if name.starts_with("archive-") {
                archive_name(&name)?;
                pending_archive_bytes = pending_archive_bytes
                    .checked_add(io::read_member(&self.pending, &name, MAX_ARCHIVE)?.len() as u64)
                    .ok_or("policy pending capacity overflow")?;
                if pending_archive_bytes > 32 * 1024 * 1024 {
                    return Err("policy pending evidence requires reviewed retention".into());
                }
                continue;
            }
            if name
                .strip_prefix("record-")
                .and_then(|v| v.strip_suffix(".json"))
                .filter(|v| id(v))
                .is_none()
            {
                return Err("unknown policy pending evidence member".into());
            }
            pending_bytes = pending_bytes
                .checked_add(io::read_member(&self.pending, &name, MAX_RECORD)?.len() as u64)
                .ok_or("policy pending capacity overflow")?;
            if pending_bytes > 16 * 1024 * 1024 {
                return Err("policy pending evidence requires exact reviewed retention".into());
            }
        }
        // A synced complete archive is evidence for a partially interrupted
        // unlink sweep, never effect authority. Validate remaining original
        // members against it so interruption does not orphan the audit graph.
        self.archive_inventory(&mut records)?;
        let mut retained_bytes = 0u64;
        for name in io::names(&self.retained, 2048)? {
            pending_name(&name)?;
            retained_bytes = retained_bytes
                .checked_add(io::read_member(&self.retained, &name, MAX_ARCHIVE)?.len() as u64)
                .ok_or("retained policy evidence capacity overflow")?;
            if retained_bytes > 64 * 1024 * 1024 {
                return Err("retained partial policy evidence quota exceeded".into());
            }
        }
        validate_links(&records)?;
        Ok(records)
    }
    fn append(&self, operation: &str, payload: Payload) -> Result<Record> {
        let _lock = self.lock()?;
        let mut records = self.inventory()?;
        let record = Record {
            schema_version: 1,
            installation: self.installation.clone(),
            record_id: crate::resources::random_id()?,
            operation_id: operation.into(),
            payload,
        };
        record.validate()?;
        records.insert(record.record_id.clone(), record.clone());
        validate_links(&records)?;
        self.write(&record, &records)?;
        Ok(record)
    }
    fn write(&self, record: &Record, records: &BTreeMap<String, Record>) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        // Ordinary work leaves capacity for exact evidence retention and for
        // terminal/denial records. Reserve access is inert logging, not a grant.
        let retention = records
            .values()
            .find_map(|r| {
                if r.operation_id == record.operation_id {
                    match &r.payload {
                        Payload::OperationStarted { scopes } => {
                            Some(scopes.iter().all(|(_, usage)| {
                                usage.action == crate::finite_grants::Action::Retain
                                    && usage.selector.kind == crate::finite_grants::Kind::Resource
                                    && matches!(
                                        usage.selector.id.as_str(),
                                        "policy-evidence" | "policy-pending"
                                    )
                            }))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .unwrap_or(false);
        let terminal = matches!(
            record.payload,
            Payload::EffectFinished { .. } | Payload::OperationFinished { .. }
        ) || matches!(&record.payload,Payload::Decision {decision} if decision.outcome==DecisionOutcome::Deny);
        let record_limit = if retention || terminal {
            MAX_RECORDS
        } else {
            MAX_RECORDS - 1024
        };
        let byte_limit = if retention || terminal {
            MAX_BYTES
        } else {
            MAX_BYTES - 4 * 1024 * 1024
        };
        if records.len() > record_limit
            || bytes.len() as u64 > MAX_RECORD
            || records.values().try_fold(0u64, |n, r| {
                Ok::<_, Box<dyn std::error::Error>>(
                    n.checked_add(serde_json::to_vec(r)?.len() as u64)
                        .ok_or("policy evidence size overflow")?,
                )
            })? > byte_limit
        {
            return Err(
                "policy evidence capacity exhausted; retain/export exact closed operations".into(),
            );
        }
        // Closed archives may have original residuals after an interrupted
        // unlink. They are omitted from the graph projection, never from the
        // physical quota. Capacity is checked before allocating another file.
        let mut physical_bytes = 0u64;
        let mut physical_records = 0usize;
        for name in io::names(&self.root, MAX_RECORDS + 4)? {
            if matches!(name.as_str(), "lock" | "pending" | "archives" | "retained") {
                continue;
            }
            let member = name
                .strip_prefix("record-")
                .and_then(|v| v.strip_suffix(".json"))
                .filter(|v| id(v))
                .ok_or("unknown physical policy member")?;
            if member == record.record_id {
                return Err("policy record already exists".into());
            }
            let file = io::open_at(&self.root, &name, libc::O_RDONLY, 0)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.nlink() != 1
                || meta.mode() & 0o7777 != 0o400
                || meta.len() > MAX_RECORD
            {
                return Err("invalid immutable physical policy member".into());
            }
            physical_records += 1;
            physical_bytes = physical_bytes
                .checked_add(meta.len())
                .ok_or("physical policy capacity overflow")?;
        }
        if physical_records
            .checked_add(1)
            .ok_or("physical policy record overflow")?
            > record_limit
            || physical_bytes
                .checked_add(bytes.len() as u64)
                .ok_or("physical policy byte overflow")?
                > byte_limit
        {
            return Err(
                "physical policy evidence capacity exhausted; retain exact closed operations"
                    .into(),
            );
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut space) } != 0
            || space
                .f_bavail
                .checked_mul(space.f_frsize)
                .ok_or("policy evidence free-space overflow")?
                < bytes.len() as u64 + 16 * 1024 * 1024
        {
            return Err("policy evidence storage reserve unavailable".into());
        }
        let name = format!("record-{}.json", record.record_id);
        let mut file = io::open_at(
            &self.pending,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o400,
        )?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        self.pending.sync_all()?;
        if io::read_member(&self.pending, &name, MAX_RECORD)? != bytes {
            return Err("policy pending record changed".into());
        }
        let name_c = std::ffi::CString::new(name.clone())?;
        if unsafe {
            libc::renameat2(
                self.pending.as_raw_fd(),
                name_c.as_ptr(),
                self.root.as_raw_fd(),
                name_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("policy evidence publication uncertain; preserve pending record".into());
        }
        self.root.sync_all()?;
        self.pending.sync_all()?;
        if io::read_member(&self.root, &name, MAX_RECORD)? != bytes {
            return Err("policy evidence durability changed".into());
        }
        Ok(())
    }

    fn archive_inventory(
        &self,
        active: &mut BTreeMap<String, Record>,
    ) -> Result<BTreeMap<String, String>> {
        let mut total = 0u64;
        let mut operations = BTreeMap::new();
        for name in io::names(&self.archives, MAX_ARCHIVES)? {
            let (operation, digest) = archive_name(&name)?;
            let bytes = io::read_member(&self.archives, &name, MAX_ARCHIVE)?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("policy archive size overflow")?;
            if total > MAX_ARCHIVE_BYTES || io::digest(&bytes) != digest {
                return Err("policy archive capacity or digest failure".into());
            }
            let archive: Archive = serde_json::from_slice(&bytes)?;
            archive.validate()?;
            if archive.installation != self.installation
                || archive.operation_id != operation
                || serde_json::to_vec(&archive)? != bytes
                || operations.insert(operation.into(), name.clone()).is_some()
            {
                return Err(
                    "policy archive substituted installation, operation or canonical content"
                        .into(),
                );
            }
            if active
                .values()
                .any(|record| record.operation_id == operation)
            {
                for record in &archive.records {
                    if active
                        .get(&record.record_id)
                        .is_some_and(|old| old != record)
                    {
                        return Err("active policy member differs from retained archive".into());
                    }
                }
                let original: BTreeMap<_, _> = archive
                    .records
                    .iter()
                    .map(|r| (r.record_id.as_str(), r))
                    .collect();
                for record in active.values().filter(|r| r.operation_id == operation) {
                    if original.get(record.record_id.as_str()).copied() != Some(record) {
                        return Err(
                            "active policy residual was not in the exact closed archive".into()
                        );
                    }
                }
                // A completed immutable archive owns the explanatory graph.
                // Keep physical residuals charged on disk, not expanded into
                // the current admission graph after an interrupted unlink.
                active.retain(|_, record| record.operation_id != operation);
            }
        }
        Ok(operations)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Archive {
    schema_version: u32,
    installation: String,
    operation_id: String,
    records: Vec<Record>,
}
impl Archive {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || !id(&self.operation_id)
            || self.records.is_empty()
            || self.records.len() > MAX_RECORDS
        {
            return Err("invalid policy archive identity or capacity".into());
        }
        let mut records = BTreeMap::new();
        for record in &self.records {
            record.validate()?;
            if record.installation != self.installation
                || record.operation_id != self.operation_id
                || records.insert(record.record_id.clone(), record).is_some()
            {
                return Err("policy archive member identity substitution".into());
            }
        }
        validate_record_links(&records)?;
        if self
            .records
            .iter()
            .filter(|r| matches!(r.payload, Payload::OperationFinished { .. }))
            .count()
            != 1
        {
            return Err("active policy operation cannot be retained".into());
        }
        if !self
            .records
            .windows(2)
            .all(|w| w[0].record_id < w[1].record_id)
        {
            return Err("noncanonical policy archive ordering".into());
        }
        Ok(())
    }
}
fn archive_name(name: &str) -> Result<(&str, &str)> {
    let base = name
        .strip_prefix("archive-")
        .and_then(|v| v.strip_suffix(".json"))
        .ok_or("invalid policy archive name")?;
    let (operation, digest) = base.split_once('-').ok_or("invalid policy archive name")?;
    if !id(operation) || !io::hash(digest) {
        return Err("invalid policy archive identity".into());
    }
    Ok((operation, digest))
}
fn pending_name(name: &str) -> Result<()> {
    if name.starts_with("archive-") {
        archive_name(name)?;
        return Ok(());
    }
    if name
        .strip_prefix("record-")
        .and_then(|v| v.strip_suffix(".json"))
        .filter(|v| id(v))
        .is_none()
    {
        return Err("invalid exact policy pending member".into());
    }
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingPlan {
    installation: String,
    name: String,
    device: u64,
    inode: u64,
    bytes: u64,
    sha256: String,
}
impl Store {
    fn pending_plan(&self, name: &str) -> Result<PendingPlan> {
        pending_name(name)?;
        let source = if io::names(&self.pending, 1024)?.iter().any(|v| v == name) {
            &self.pending
        } else {
            &self.retained
        };
        let file = io::open_at(source, name, libc::O_RDONLY, 0)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.nlink() != 1
            || before.mode() & 0o7777 != 0o400
        {
            return Err("unsafe policy pending evidence".into());
        }
        let bytes = io::read_member(source, name, MAX_ARCHIVE)?;
        let after = file.metadata()?;
        let current = io::open_at(source, name, libc::O_RDONLY, 0)?.metadata()?;
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
        if key(&before) != key(&after)
            || key(&before) != key(&current)
            || before.len() != bytes.len() as u64
        {
            return Err("policy pending evidence changed during review".into());
        }
        Ok(PendingPlan {
            installation: self.installation.clone(),
            name: name.into(),
            device: before.dev(),
            inode: before.ino(),
            bytes: bytes.len() as u64,
            sha256: io::digest(&bytes),
        })
    }
    fn pending_retain(&self, plan: &PendingPlan) -> Result<()> {
        let _lock = self.lock()?;
        self.inventory()?;
        if self.pending_plan(&plan.name)? != *plan {
            return Err("policy pending retention exact inode or bytes changed".into());
        }
        if io::names(&self.retained, 2048)?.contains(&plan.name) {
            if io::names(&self.pending, 1024)?.contains(&plan.name) {
                return Err("pending and retained policy member collision".into());
            }
            self.retained.sync_all()?;
            return Ok(());
        }
        let total = io::names(&self.retained, 2048)?
            .iter()
            .try_fold(plan.bytes, |sum, name| {
                Ok::<_, Box<dyn std::error::Error>>(
                    sum.checked_add(
                        io::read_member(&self.retained, name, MAX_ARCHIVE)?.len() as u64
                    )
                    .ok_or("retained partial policy evidence overflow")?,
                )
            })?;
        if total > 64 * 1024 * 1024 {
            return Err("retained policy pending quota exhausted; preserve original member".into());
        }
        let name = std::ffi::CString::new(plan.name.clone())?;
        if unsafe {
            libc::renameat2(
                self.pending.as_raw_fd(),
                name.as_ptr(),
                self.retained.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(
                "policy pending retention uncertain; inspect exact original and retained member"
                    .into(),
            );
        }
        self.retained.sync_all()?;
        self.pending.sync_all()?;
        if self.pending_plan(&plan.name)? != *plan {
            return Err("retained partial policy evidence differs".into());
        }
        Ok(())
    }
}
fn pending_usage(plan: &PendingPlan) -> Result<(String, Use)> {
    let review = io::digest(&serde_json::to_vec(&(
        "luma-native-policy-pending-retention-v1",
        plan,
    ))?);
    let usage = Use {
        action: crate::finite_grants::Action::Retain,
        selector: crate::finite_grants::Selector {
            kind: crate::finite_grants::Kind::Resource,
            id: "policy-pending".into(),
            generation: 1,
            digest: review.clone(),
        },
        input_bytes: plan.bytes,
        output_bytes: 0,
        units: 1,
    };
    usage.validate()?;
    Ok((review, usage))
}
pub(crate) fn pending_review(name: &str) -> Result<()> {
    let store = Store::installed()?;
    let _lock = store.lock()?;
    store.inventory()?;
    let plan = store.pending_plan(name)?;
    let (review, usage) = pending_usage(&plan)?;
    println!(
        "{}",
        serde_json::json!({"plan":plan,"review_sha256":review,"usage":usage,
        "authority_returned":false,"grant_issued":false,"bytes_preserved":true})
    );
    Ok(())
}
pub(crate) fn pending_retain(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected policy-evidence-pending-retain LOGIN GRANT MEMBER REVIEW-SHA256".into(),
        );
    }
    let store = Store::installed()?;
    let plan = {
        let _lock = store.lock()?;
        store.inventory()?;
        store.pending_plan(&args[3])?
    };
    let (review, usage) = pending_usage(&plan)?;
    if args[4] != review {
        return Err("policy pending retention review changed".into());
    }
    crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let pending = boundary.effect_begin(&review, EffectKind::Retention)?;
        boundary.check()?;
        store.pending_retain(&plan)?;
        boundary.effect_complete(
            pending,
            &io::digest(&serde_json::to_vec(&(
                "luma-policy-pending-retained-v1",
                &plan,
                &review,
            ))?),
        )
    })?;
    println!(
        "{}",
        serde_json::json!({"member":plan.name,"review_sha256":review,"state":"retained","bytes_preserved":true})
    );
    Ok(())
}
fn archive_review(archive: &Archive) -> Result<(String, Vec<u8>, Use)> {
    archive.validate()?;
    let bytes = serde_json::to_vec(archive)?;
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err("closed operation exceeds bounded policy archive size".into());
    }
    let digest = io::digest(&bytes);
    let review = io::digest(&serde_json::to_vec(&(
        "luma-native-policy-evidence-retention-v1",
        &archive.installation,
        &archive.operation_id,
        &digest,
        bytes.len(),
    ))?);
    let usage = Use {
        action: crate::finite_grants::Action::Retain,
        selector: crate::finite_grants::Selector {
            kind: crate::finite_grants::Kind::Resource,
            id: "policy-evidence".into(),
            generation: 1,
            digest: review.clone(),
        },
        input_bytes: bytes.len() as u64,
        output_bytes: 0,
        units: archive.records.len() as u64,
    };
    usage.validate()?;
    Ok((review, bytes, usage))
}
impl Store {
    fn retention_input(&self, operation: &str) -> Result<Archive> {
        if !id(operation) {
            return Err("invalid exact policy operation selector".into());
        }
        let _lock = self.lock()?;
        let mut records = self.inventory()?;
        let archives = self.archive_inventory(&mut records)?;
        if let Some(name) = archives.get(operation) {
            let bytes = io::read_member(&self.archives, name, MAX_ARCHIVE)?;
            let archive: Archive = serde_json::from_slice(&bytes)?;
            archive.validate()?;
            return Ok(archive);
        }
        let archive = Archive {
            schema_version: 1,
            installation: self.installation.clone(),
            operation_id: operation.into(),
            records: records
                .into_values()
                .filter(|r| r.operation_id == operation)
                .collect(),
        };
        archive.validate()?;
        Ok(archive)
    }
    fn archive(&self, archive: &Archive, bytes: &[u8]) -> Result<()> {
        let _lock = self.lock()?;
        if &self.retention_input_unlocked(&archive.operation_id)? != archive {
            return Err("policy retention exact member set changed".into());
        }
        let name = format!(
            "archive-{}-{}.json",
            archive.operation_id,
            io::digest(bytes)
        );
        if io::names(&self.archives, MAX_ARCHIVES)?.contains(&name) {
            if io::read_member(&self.archives, &name, MAX_ARCHIVE)? != bytes {
                return Err("retained policy archive changed".into());
            }
            return Ok(());
        }
        let mut active = self.inventory()?;
        let existing = self.archive_inventory(&mut active)?;
        let total = existing
            .values()
            .try_fold(bytes.len() as u64, |sum, name| {
                Ok::<_, Box<dyn std::error::Error>>(
                    sum.checked_add(
                        io::read_member(&self.archives, name, MAX_ARCHIVE)?.len() as u64
                    )
                    .ok_or("policy archive capacity overflow")?,
                )
            })?;
        if existing.len() >= MAX_ARCHIVES || total > MAX_ARCHIVE_BYTES {
            return Err("policy archive quota exhausted; preserve all original evidence".into());
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut space) } != 0
            || space
                .f_bavail
                .checked_mul(space.f_frsize)
                .ok_or("policy archive free-space overflow")?
                < bytes.len() as u64 + 16 * 1024 * 1024
        {
            return Err(
                "policy archive storage reserve unavailable; preserve original evidence".into(),
            );
        }
        match io::open_at(
            &self.pending,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o400,
        ) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            Err(error) => {
                if !io::names(&self.pending, 1024)?.contains(&name) {
                    return Err(error);
                }
                if io::read_member(&self.pending, &name, MAX_ARCHIVE)? != bytes {
                    return Err(
                        "partial policy archive needs exact reviewed pending retention".into(),
                    );
                }
                io::open_at(&self.pending, &name, libc::O_RDONLY, 0)?.sync_all()?;
            }
        }
        self.pending.sync_all()?;
        if io::read_member(&self.pending, &name, MAX_ARCHIVE)? != bytes {
            return Err("policy archive proposal changed".into());
        }
        let named = std::ffi::CString::new(name.clone())?;
        if unsafe {
            libc::renameat2(
                self.pending.as_raw_fd(),
                named.as_ptr(),
                self.archives.as_raw_fd(),
                named.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(
                "policy archive publication uncertain; preserve pending and original evidence"
                    .into(),
            );
        }
        self.archives.sync_all()?;
        self.pending.sync_all()?;
        if io::read_member(&self.archives, &name, MAX_ARCHIVE)? != bytes {
            return Err("policy archive durability uncertain".into());
        }
        Ok(())
    }
    fn retention_input_unlocked(&self, operation: &str) -> Result<Archive> {
        let mut records = self.inventory()?;
        let archives = self.archive_inventory(&mut records)?;
        if let Some(name) = archives.get(operation) {
            let archive: Archive =
                serde_json::from_slice(&io::read_member(&self.archives, name, MAX_ARCHIVE)?)?;
            archive.validate()?;
            return Ok(archive);
        }
        let archive = Archive {
            schema_version: 1,
            installation: self.installation.clone(),
            operation_id: operation.into(),
            records: records
                .into_values()
                .filter(|r| r.operation_id == operation)
                .collect(),
        };
        archive.validate()?;
        Ok(archive)
    }
    fn unlink_archived(&self, record: &Record, archive: &Archive) -> Result<()> {
        let _lock = self.lock()?;
        let retained = self.retention_input_unlocked(&archive.operation_id)?;
        if &retained != archive || !archive.records.contains(record) {
            return Err("policy retention archive or exact member changed".into());
        }
        let name = format!("record-{}.json", record.record_id);
        if !io::names(&self.root, MAX_RECORDS + 4)?.contains(&name) {
            return Ok(());
        }
        let bytes = io::read_member(&self.root, &name, MAX_RECORD)?;
        if bytes != serde_json::to_vec(record)? {
            return Err("policy retention original member changed".into());
        }
        let named = std::ffi::CString::new(name)?;
        if unsafe { libc::unlinkat(self.root.as_raw_fd(), named.as_ptr(), 0) } != 0 {
            return Err("policy evidence unlink uncertain; preserve archive".into());
        }
        self.root.sync_all()?;
        Ok(())
    }
}

pub(crate) fn review(operation: &str) -> Result<()> {
    let store = Store::installed()?;
    let archive = store.retention_input(operation)?;
    let (review, _, usage) = archive_review(&archive)?;
    println!(
        "{}",
        serde_json::json!({"operation_id":operation,"review_sha256":review,"usage":usage,
        "member_count":archive.records.len(),"records_preserved":true,"grant_issued":false,"authority_returned":false})
    );
    Ok(())
}
pub(crate) fn retain(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(
            "expected policy-evidence-retain LOGIN RETENTION-GRANT OPERATION-ID REVIEW-SHA256"
                .into(),
        );
    }
    let store = Store::installed()?;
    let archive = store.retention_input(&args[3])?;
    let (review, bytes, usage) = archive_review(&archive)?;
    if args[4] != review {
        return Err("policy evidence retention review changed".into());
    }
    crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let pending = boundary.effect_begin(&review, EffectKind::Retention)?;
        boundary.check()?;
        store.archive(&archive, &bytes)?;
        for record in &archive.records {
            boundary.check()?;
            store.unlink_archived(record, &archive)?;
        }
        let receipt = io::digest(&serde_json::to_vec(&(
            "luma-policy-evidence-retained-v1",
            &review,
            io::digest(&bytes),
            archive.records.len(),
        ))?);
        boundary.effect_complete(pending, &receipt)?;
        Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({"operation_id":args[3],"review_sha256":review,"records_preserved":true,"state":"archived"})
    );
    Ok(())
}

fn validate_links(records: &BTreeMap<String, Record>) -> Result<()> {
    let index = records
        .iter()
        .map(|(name, record)| (name.clone(), record))
        .collect();
    validate_record_links(&index)
}
fn validate_record_links(records: &BTreeMap<String, &Record>) -> Result<()> {
    let mut starts = BTreeMap::new();
    let mut terminals = BTreeSet::new();
    let mut effect_terminals = BTreeSet::new();
    for record in records.values() {
        if let Payload::OperationStarted { scopes } = &record.payload {
            if starts.insert(record.operation_id.clone(), scopes).is_some() {
                return Err("duplicate policy operation start".into());
            }
        }
    }
    for record in records.values() {
        let scopes = starts
            .get(&record.operation_id)
            .ok_or("policy evidence lacks its exact operation start")?;
        match &record.payload {
            Payload::Decision { decision } => {
                if !scopes.iter().any(|(grant, usage)| {
                    grant == &decision.grant_id && usage == &decision.evaluated_constraints
                }) || decision.decision_id != record.record_id
                {
                    return Err("policy decision substituted its operation scope".into());
                }
            }
            Payload::EffectStarted { decision_ids, .. } => {
                if decision_ids.len() != scopes.len() {
                    return Err("pending effect omits required grant decisions".into());
                }
                let mut seen = BTreeSet::new();
                for decision_id in decision_ids {
                    let decision = records
                        .get(decision_id)
                        .filter(|r| r.operation_id == record.operation_id)
                        .ok_or("effect policy decision reference missing")?;
                    match &decision.payload {
                        Payload::Decision { decision }
                            if decision.outcome == DecisionOutcome::Allow
                                && seen.insert(&decision.grant_id) => {}
                        _ => {
                            return Err("pending effect references denied or duplicate scope".into())
                        }
                    }
                }
            }
            Payload::EffectFinished {
                begin_id,
                begin_sha256,
                ..
            } => {
                let begin = records
                    .get(begin_id)
                    .filter(|r| {
                        r.operation_id == record.operation_id
                            && matches!(r.payload, Payload::EffectStarted { .. })
                    })
                    .ok_or("effect outcome lacks its original pending evidence")?;
                if !effect_terminals.insert(begin_id)
                    || io::digest(&serde_json::to_vec(begin)?) != *begin_sha256
                {
                    return Err(
                        "effect outcome changed or duplicated original pending evidence".into(),
                    );
                }
            }
            Payload::OperationFinished { .. } => {
                if !terminals.insert(&record.operation_id) {
                    return Err("duplicate policy operation outcome".into());
                }
            }
            _ => {}
        }
    }
    for record in records.values() {
        if matches!(
            record.payload,
            Payload::OperationFinished {
                outcome: OperationOutcome::Completed
            }
        ) && records.values().any(|r| {
            r.operation_id == record.operation_id
                && ((matches!(r.payload, Payload::EffectStarted { .. })
                    && !effect_terminals.contains(&r.record_id))
                    || matches!(
                        r.payload,
                        Payload::EffectFinished {
                            outcome: OperationOutcome::Uncertain,
                            ..
                        }
                    ))
        }) {
            return Err("completed policy operation retains uncertain effect".into());
        }
    }
    Ok(())
}

pub(crate) struct Operation {
    store: Rc<Store>,
    id: String,
    finished: bool,
}
impl Operation {
    pub(crate) fn begin(store: Rc<Store>, scopes: &[(String, Use)]) -> Result<Self> {
        let id = crate::resources::random_id()?;
        store.append(
            &id,
            Payload::OperationStarted {
                scopes: scopes.to_vec(),
            },
        )?;
        Ok(Self {
            store,
            id,
            finished: false,
        })
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn decisions(&self, decisions: Vec<Decision>) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let _lock = self.store.lock()?;
        let mut records = self.store.inventory()?;
        for decision in decisions {
            let record = Record {
                schema_version: 1,
                installation: self.store.installation.clone(),
                record_id: decision.decision_id.clone(),
                operation_id: self.id.clone(),
                payload: Payload::Decision { decision },
            };
            // Preserve the typed decision identifier as the durable record key.
            record.validate()?;
            records.insert(record.record_id.clone(), record.clone());
            validate_links(&records)?;
            self.store.write(&record, &records)?;
            ids.push(record.record_id);
        }
        Ok(ids)
    }
    pub(crate) fn effect_begin(
        &self,
        effect_id: &str,
        kind: EffectKind,
        decision_ids: &[String],
    ) -> Result<PendingEffect> {
        let begin = self.store.append(
            &self.id,
            Payload::EffectStarted {
                effect_id: effect_id.into(),
                effect_kind: kind,
                decision_ids: decision_ids.to_vec(),
            },
        )?;
        Ok(PendingEffect {
            store: self.store.clone(),
            begin,
            finished: false,
        })
    }
    pub(crate) fn finish(&mut self, outcome: OperationOutcome) -> Result<()> {
        if self.finished {
            return Err("policy operation already closed".into());
        }
        self.store
            .append(&self.id, Payload::OperationFinished { outcome })?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(OperationOutcome::Uncertain);
        }
    }
}

/// Non-serializable correlation owned by the actual in-process dispatcher.
pub(crate) struct PendingEffect {
    store: Rc<Store>,
    begin: Record,
    finished: bool,
}
impl PendingEffect {
    pub(crate) fn complete(mut self, operation: &str, receipt: &str) -> Result<()> {
        if operation != self.begin.operation_id || !io::hash(receipt) || receipt == "00".repeat(32)
        {
            return Err("effect completion substituted its operation or receipt".into());
        }
        self.finish(OperationOutcome::Completed, Some(receipt.into()))
    }
    fn finish(&mut self, outcome: OperationOutcome, receipt: Option<String>) -> Result<()> {
        if self.finished {
            return Err("policy effect already closed".into());
        }
        self.store.append(
            &self.begin.operation_id,
            Payload::EffectFinished {
                begin_id: self.begin.record_id.clone(),
                begin_sha256: io::digest(&serde_json::to_vec(&self.begin)?),
                receipt_sha256: receipt,
                outcome,
            },
        )?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for PendingEffect {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(OperationOutcome::Uncertain, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt};
    fn usage() -> Use {
        Use {
            action: crate::finite_grants::Action::Infer,
            selector: crate::finite_grants::Selector {
                kind: crate::finite_grants::Kind::Model,
                id: "Qwen3-4B".into(),
                generation: 4,
                digest: "12".repeat(32),
            },
            input_bytes: 128,
            output_bytes: 8192,
            units: 32,
        }
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let parent = std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("policy evidence tests require the isolated ext4 test volume");
            let path =
                Path::new(&parent).join(format!("luma-policy-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> Rc<Store> {
            Rc::new(Store::open(&self.0, &"ab".repeat(32)).unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn unavailable_decisions_never_fabricate_subject_or_time_and_wire_is_closed() {
        for reason in [
            Reason::AuthenticationUnavailable,
            Reason::PrincipalUnavailable,
            Reason::CatalogUnavailable,
            Reason::UtcUnavailable,
        ] {
            let decision = Decision::unavailable("infer-one", &usage(), reason).unwrap();
            assert_eq!(decision.outcome, DecisionOutcome::Deny);
            assert!(
                decision.subject.is_none()
                    && decision.timestamp.is_none()
                    && decision.grant.is_none()
            );
            let mut counterfeit = decision.clone();
            counterfeit.outcome = DecisionOutcome::Allow;
            counterfeit.reason_code = Reason::Allowed;
            assert!(counterfeit.validate().is_err());
            let mut value = serde_json::to_value(decision).unwrap();
            value["root_authority"] = true.into();
            assert!(serde_json::from_value::<Decision>(value).is_err());
        }
        assert!(Decision::unavailable("*", &usage(), Reason::GrantMissing).is_err());
    }
    #[test]
    fn durably_closed_denial_survives_restart_without_becoming_authority() {
        let fixture = Fixture::new("denial");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        let op = operation.id().to_owned();
        let decision =
            Decision::unavailable("infer-one", &usage(), Reason::AuthenticationUnavailable)
                .unwrap();
        let ids = operation.decisions(vec![decision]).unwrap();
        assert_eq!(ids.len(), 1);
        operation.finish(OperationOutcome::Denied).unwrap();
        drop(operation);
        drop(store);
        let reopened = fixture.store();
        let records = reopened.inventory().unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.values().all(|r| r.operation_id == op));
        assert!(records.values().any(|r| matches!(
            r.payload,
            Payload::OperationFinished {
                outcome: OperationOutcome::Denied
            }
        )));
    }
    fn allow_data() -> Decision {
        let mut decision =
            Decision::unavailable("infer-one", &usage(), Reason::GrantDenied).unwrap();
        decision.outcome = DecisionOutcome::Allow;
        decision.reason_code = Reason::Allowed;
        decision.subject = Some(Subject {
            principal: "ab".repeat(32),
            generation: 2,
        });
        decision.checkpoint_head = Some("cd".repeat(32));
        decision.catalog_sha256 = Some("ef".repeat(32));
        decision.timestamp = Some(Timestamp {
            context: crate::utc_history::Statement {
                floor_ms: 1000,
                policy_sha256: crate::utc_history::policy_digest().unwrap(),
                boot_id: "12".repeat(16),
                process_generation: 1,
                source_clock_generation: 1,
                keeper_generation: 1,
                runtime_sha256: "34".repeat(32),
            },
            lower_ms: 1000,
            upper_ms: 1200,
        });
        decision.grant = Some(GrantEvidence {
            definition: Grant {
                id: "infer-one".into(),
                assignment: "operator-one".into(),
                assignment_version: 1,
                subject: "ab".repeat(32),
                subject_generation: 2,
                action: usage().action,
                selector: usage().selector,
                constraints: Constraints {
                    max_input_bytes: 8192,
                    max_output_bytes: 8192,
                    max_units: 128,
                },
                version: 1,
                not_before_ms: 500,
                expires_ms: 2000,
                revoked: false,
            },
            assignment: Some(crate::finite_grants::Assignment {
                id: "operator-one".into(),
                subject: "ab".repeat(32),
                subject_generation: 2,
                role: "Operator".into(),
                role_version: 1,
                version: 1,
                not_before_ms: 500,
                expires_ms: 2000,
                revoked: false,
            }),
            current_role: Some(RoleEvidence {
                name: "Operator".into(),
                version: 1,
                activities: vec!["inference.execute".into()],
            }),
            grant_id: "infer-one".into(),
            grant_version: 1,
            revoked: false,
            assignment_id: "operator-one".into(),
            assignment_version: 1,
            role: "Operator".into(),
            role_version: 1,
            not_before_ms: 500,
            expires_ms: 2000,
            constraints: Constraints {
                max_input_bytes: 8192,
                max_output_bytes: 8192,
                max_units: 128,
            },
        });
        decision.validate().unwrap();
        decision
    }
    #[test]
    fn allowed_evidence_requires_exact_subject_role_scope_and_full_utc_window() {
        let baseline = allow_data();
        let mut invalid = baseline.clone();
        invalid
            .grant
            .as_mut()
            .unwrap()
            .assignment
            .as_mut()
            .unwrap()
            .revoked = true;
        assert!(invalid.validate().is_err());
        let mut invalid = baseline.clone();
        invalid
            .grant
            .as_mut()
            .unwrap()
            .current_role
            .as_mut()
            .unwrap()
            .version += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = baseline.clone();
        invalid.subject.as_mut().unwrap().generation += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = baseline.clone();
        invalid.timestamp.as_mut().unwrap().upper_ms = 2000;
        invalid.timestamp.as_mut().unwrap().lower_ms = 1800;
        invalid.timestamp.as_mut().unwrap().context.floor_ms = 1800;
        assert!(invalid.validate().is_err());
        let mut invalid = baseline;
        invalid
            .grant
            .as_mut()
            .unwrap()
            .definition
            .selector
            .generation += 1;
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn ordinary_and_terminal_record_caps_refuse_before_staging_any_bytes() {
        let fixture = Fixture::new("quota");
        let store = fixture.store();
        let mut records = BTreeMap::new();
        for index in 0..=MAX_RECORDS {
            let record = Record {
                schema_version: 1,
                installation: store.installation.clone(),
                record_id: format!("{index:032x}"),
                operation_id: "21".repeat(16),
                payload: Payload::OperationStarted {
                    scopes: vec![("infer-one".into(), usage())],
                },
            };
            records.insert(record.record_id.clone(), record);
            if records.len() == MAX_RECORDS - 1023 {
                let ordinary = records.values().next().unwrap();
                assert!(store.write(ordinary, &records).is_err());
                assert!(io::names(&store.pending, 1024).unwrap().is_empty());
            }
        }
        let terminal = Record {
            schema_version: 1,
            installation: store.installation.clone(),
            record_id: "22".repeat(16),
            operation_id: "21".repeat(16),
            payload: Payload::OperationFinished {
                outcome: OperationOutcome::Uncertain,
            },
        };
        assert!(store.write(&terminal, &records).is_err());
        assert!(io::names(&store.pending, 1024).unwrap().is_empty());
        assert!(store.inventory().unwrap().is_empty());
    }
    #[test]
    fn effect_receipt_is_exact_and_uncertain_or_unclosed_effect_blocks_completed_operation() {
        let fixture = Fixture::new("effects");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        let ids = operation.decisions(vec![allow_data()]).unwrap();
        let pending = operation
            .effect_begin("job-one", EffectKind::Inference, &ids)
            .unwrap();
        assert!(operation.finish(OperationOutcome::Completed).is_err());
        pending.complete(operation.id(), &"56".repeat(32)).unwrap();
        operation.finish(OperationOutcome::Completed).unwrap();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        let ids = operation.decisions(vec![allow_data()]).unwrap();
        let pending = operation
            .effect_begin("job-two", EffectKind::Inference, &ids)
            .unwrap();
        drop(pending);
        assert!(operation.finish(OperationOutcome::Completed).is_err());
        operation.finish(OperationOutcome::Uncertain).unwrap();
        let records = store.inventory().unwrap();
        assert!(records.values().any(|r|matches!(&r.payload,Payload::EffectFinished {receipt_sha256:Some(v),outcome:OperationOutcome::Completed,..} if v==&"56".repeat(32))));
        assert!(records.values().any(|r| matches!(
            r.payload,
            Payload::EffectFinished {
                receipt_sha256: None,
                outcome: OperationOutcome::Uncertain,
                ..
            }
        )));
    }
    #[test]
    fn pending_partial_and_inode_swap_never_replace_committed_evidence() {
        let fixture = Fixture::new("pending");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        io::write_member(
            &store.pending,
            &format!("record-{}.json", "78".repeat(16)),
            b"partial",
            0o400,
        )
        .unwrap();
        assert_eq!(store.inventory().unwrap().len(), 1);
        operation.finish(OperationOutcome::Denied).unwrap();
        let replacement = fixture.0.with_extension("replacement");
        fs::rename(&fixture.0, &replacement).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.0)
            .unwrap();
        assert!(store
            .append(
                operation.id(),
                Payload::OperationFinished {
                    outcome: OperationOutcome::Completed
                }
            )
            .is_err());
        fs::remove_dir(&fixture.0).unwrap();
        fs::rename(&replacement, &fixture.0).unwrap();
        let path = fixture.0.join(format!("record-{}.json", "90".repeat(16)));
        symlink("/dev/null", &path).unwrap();
        assert!(store.inventory().is_err());
    }
    #[test]
    fn unrelated_scope_or_denied_decision_never_describes_pending_effect() {
        let fixture = Fixture::new("scope");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        let denied = operation
            .decisions(vec![Decision::unavailable(
                "infer-one",
                &usage(),
                Reason::GrantMissing,
            )
            .unwrap()])
            .unwrap();
        assert!(operation
            .effect_begin("task", EffectKind::Inference, &denied)
            .is_err());
        let mut swapped = allow_data();
        swapped.evaluated_constraints.selector.generation += 1;
        swapped.normalized_resource = swapped.evaluated_constraints.selector.clone();
        assert!(operation.decisions(vec![swapped]).is_err());
        operation.finish(OperationOutcome::Denied).unwrap();
    }

    #[test]
    fn exact_archive_preserves_interrupted_unlink_graph_and_replay() {
        let fixture = Fixture::new("archive");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        let op = operation.id().to_owned();
        operation
            .decisions(vec![Decision::unavailable(
                "infer-one",
                &usage(),
                Reason::GrantMissing,
            )
            .unwrap()])
            .unwrap();
        operation.finish(OperationOutcome::Denied).unwrap();
        let archive = store.retention_input(&op).unwrap();
        let (review, bytes, scope) = archive_review(&archive).unwrap();
        assert_eq!(scope.selector.digest, review);
        assert_eq!(scope.units, 3);
        store.archive(&archive, &bytes).unwrap();
        store
            .unlink_archived(&archive.records[0], &archive)
            .unwrap();
        // The original archive independently preserves the complete historical
        // graph. Residual members are charged on disk but never re-expanded.
        assert!(store.inventory().unwrap().is_empty());
        drop(store);
        let store = fixture.store();
        assert_eq!(store.retention_input(&op).unwrap(), archive);
        for record in &archive.records {
            store.unlink_archived(record, &archive).unwrap();
        }
        assert!(store.inventory().unwrap().is_empty());
        store.archive(&archive, &bytes).unwrap();
        assert_eq!(store.retention_input(&op).unwrap(), archive);
        let mut substituted = archive.clone();
        substituted.records[0].installation = "ef".repeat(32);
        assert!(store
            .archive(&substituted, &serde_json::to_vec(&substituted).unwrap())
            .is_err());
    }
    #[test]
    fn many_interrupted_archives_never_expand_and_exact_maintenance_still_admits() {
        let fixture = Fixture::new("bounded-archives");
        let store = fixture.store();
        let mut archives = Vec::new();
        for _ in 0..8 {
            let mut operation =
                Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
            operation
                .decisions(vec![Decision::unavailable(
                    "infer-one",
                    &usage(),
                    Reason::GrantMissing,
                )
                .unwrap()])
                .unwrap();
            operation.finish(OperationOutcome::Denied).unwrap();
            let archive = store.retention_input(operation.id()).unwrap();
            let (_, bytes, _) = archive_review(&archive).unwrap();
            store.archive(&archive, &bytes).unwrap();
            store
                .unlink_archived(&archive.records[0], &archive)
                .unwrap();
            archives.push(archive);
        }
        assert!(store.inventory().unwrap().is_empty());
        assert_eq!(
            io::names(&store.root, MAX_RECORDS + 4)
                .unwrap()
                .iter()
                .filter(|name| name.starts_with("record-"))
                .count(),
            16
        );
        let mut maintenance = Operation::begin(
            store.clone(),
            &[(
                "retention-one".into(),
                archive_review(&archives[0]).unwrap().2,
            )],
        )
        .unwrap();
        maintenance
            .decisions(vec![Decision::unavailable(
                "retention-one",
                &archive_review(&archives[0]).unwrap().2,
                Reason::AuthenticationUnavailable,
            )
            .unwrap()])
            .unwrap();
        for archive in &archives {
            assert_eq!(
                store.retention_input(&archive.operation_id).unwrap(),
                *archive
            );
            for record in &archive.records {
                store.unlink_archived(record, archive).unwrap();
            }
        }
        maintenance.finish(OperationOutcome::Denied).unwrap();
        assert_eq!(store.inventory().unwrap().len(), 3);
        // A residual with the same operation but no exact archived identity
        // cannot disappear into the historical projection.
        let mut counterfeit = archives[0].records[0].clone();
        counterfeit.record_id = "13".repeat(16);
        io::write_member(
            &store.root,
            &format!("record-{}.json", counterfeit.record_id),
            &serde_json::to_vec(&counterfeit).unwrap(),
            0o400,
        )
        .unwrap();
        assert!(store.inventory().is_err());
    }
    #[test]
    fn active_operation_never_archives_and_pending_retention_binds_original_inode() {
        let fixture = Fixture::new("pending-retention");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        assert!(store.retention_input(operation.id()).is_err());
        let name = format!("record-{}.json", "12".repeat(16));
        io::write_member(&store.pending, &name, b"partial", 0o400).unwrap();
        let plan = store.pending_plan(&name).unwrap();
        let (review, scope) = pending_usage(&plan).unwrap();
        assert_eq!(scope.selector.digest, review);
        assert_eq!(scope.input_bytes, 7);
        let mut different = plan.clone();
        different.inode += 1;
        assert!(store.pending_retain(&different).is_err());
        store.pending_retain(&plan).unwrap();
        store.pending_retain(&plan).unwrap();
        assert_eq!(
            io::read_member(&store.retained, &name, 1024).unwrap(),
            b"partial"
        );
        assert!(io::read_member(&store.pending, &name, 1024).is_err());
        operation.finish(OperationOutcome::Denied).unwrap();
    }
    #[test]
    fn archive_digest_closed_shape_and_child_directory_swaps_fail_closed() {
        let fixture = Fixture::new("archive-tamper");
        let store = fixture.store();
        let mut operation =
            Operation::begin(store.clone(), &[("infer-one".into(), usage())]).unwrap();
        operation.finish(OperationOutcome::Denied).unwrap();
        let archive = store.retention_input(operation.id()).unwrap();
        let (_, bytes, _) = archive_review(&archive).unwrap();
        store.archive(&archive, &bytes).unwrap();
        let name = io::names(&store.archives, MAX_ARCHIVES).unwrap().remove(0);
        fs::write(fixture.0.join("archives").join(name), b"changed").unwrap();
        assert!(store.inventory().is_err());
        let pending = fixture.0.join("pending");
        let old = fixture.0.join("old-pending");
        fs::rename(&pending, &old).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&pending).unwrap();
        assert!(store.lock().is_err());
        assert!(archive_name("archive-../target.json").is_err());
        assert!(pending_name("../member").is_err());
        let mut wire = serde_json::to_value(&archive).unwrap();
        wire["approved"] = true.into();
        assert!(serde_json::from_value::<Archive>(wire).is_err());
    }
}
