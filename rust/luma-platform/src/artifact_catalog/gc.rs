//! Explicit, principal-local garbage collection of proven unreferenced bytes.
//! Marks and receipts are local audit data; only fresh governed boundaries admit
//! either marking or deletion. No file timestamp or missing pathname is time.
use super::*;
use crate::{
    finite_grants::{Action, Audit, Kind, Selector, Use},
    utc_stream::Observation,
};
use std::io::Read;

const MAX_EVIDENCE: u64 = 16 * 1024;
const MAX_MARKS: usize = 64;
const MIN_GRACE_SECONDS: u64 = 3600;
const MAX_GRACE_SECONDS: u64 = 30 * 86400;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Area {
    Object,
    Retained,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub(super) area: Area,
    pub(super) name: String,
}
impl Target {
    fn validate(&self) -> Result<()> {
        if match self.area {
            Area::Object => !io::hash(&self.name),
            Area::Retained => !io::identifier(&self.name),
        } {
            return Err(
                "artifact GC requires one exact domain-local object or retained preparation".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
    sha256: String,
}
fn metadata_identity(m: &fs::Metadata, sha256: &str) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mode: m.mode(),
        uid: m.uid(),
        modified: m.mtime(),
        modified_ns: m.mtime_nsec(),
        changed: m.ctime(),
        changed_ns: m.ctime_nsec(),
        sha256: sha256.into(),
    }
}
fn identity(directory: &File, name: &str) -> Result<Identity> {
    let mut file = io::open_at(directory, name, libc::O_RDONLY, 0)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o7777 != 0o400
        || before.len() > MAX_CONTENT
    {
        return Err("artifact GC target is not bounded immutable private content".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_CONTENT + 1).read_to_end(&mut bytes)?;
    let sha256 = io::digest(&bytes);
    let observe = |m: &fs::Metadata| metadata_identity(m, &sha256);
    let current = io::open_at(directory, name, libc::O_RDONLY, 0)?.metadata()?;
    if bytes.len() as u64 != before.len()
        || observe(&before) != observe(&file.metadata()?)
        || observe(&before) != observe(&current)
    {
        return Err("artifact GC target changed during inspection".into());
    }
    Ok(observe(&before))
}
fn grace(seconds: u64) -> Result<u64> {
    if !(MIN_GRACE_SECONDS..=MAX_GRACE_SECONDS).contains(&seconds) {
        return Err("artifact GC grace must be explicitly one hour to thirty days".into());
    }
    seconds
        .checked_mul(1000)
        .ok_or_else(|| "artifact GC grace overflows".into())
}
fn canonical<T: Serialize + for<'a> Deserialize<'a>>(
    dir: &File,
    name: &str,
) -> Result<(T, Vec<u8>)> {
    let file = io::open_at(dir, name, libc::O_RDONLY, 0)?;
    if file.metadata()?.mode() & 0o7777 != 0o400 {
        return Err("artifact GC evidence lost immutable permissions".into());
    }
    let bytes = io::read_member(dir, name, MAX_EVIDENCE)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("noncanonical artifact GC evidence; retain it".into());
    }
    Ok((value, bytes))
}
fn publish<T: Serialize>(dir: &File, prefix: &str, value: &T) -> Result<String> {
    let names = io::names(dir, MAX_MARKS * 3)?;
    if names
        .iter()
        .filter(|n| n.starts_with(&format!("{prefix}-")))
        .count()
        >= MAX_MARKS
    {
        return Err("artifact GC evidence capacity exhausted; no automatic eviction".into());
    }
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_EVIDENCE {
        return Err("artifact GC evidence bound exceeded".into());
    }
    let digest = io::digest(&bytes);
    io::write_member(dir, &format!("{prefix}-{digest}.json"), &bytes, 0o400)?;
    dir.sync_all()?;
    Ok(digest)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    installation: String,
    owner: String,
    owner_generation: u64,
    catalog_directory: (u64, u64),
    receipt_head: String,
    target: Target,
    identity: Identity,
}
impl Plan {
    fn validate(&self) -> Result<()> {
        self.target.validate()?;
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || self.owner == "local-root"
            || !io::identifier(&self.owner)
            || self.owner_generation == 0
            || !io::hash(&self.receipt_head)
            || !io::hash(&self.identity.sha256)
            || self.identity.length > MAX_CONTENT
            || self.identity.mode & 0o7777 != 0o400
            || self.identity.uid != unsafe { libc::geteuid() }
        {
            return Err("artifact GC plan has no exact principal-local identity".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MarkProposal {
    plan: Plan,
    grace_seconds: u64,
}
impl MarkProposal {
    fn review(&self) -> Result<String> {
        self.plan.validate()?;
        grace(self.grace_seconds)?;
        let mut bytes = b"luma-artifact-gc-unreferenced-mark-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(io::digest(&bytes))
    }
    fn usage(&self) -> Result<Use> {
        usage(
            Action::Retain,
            &self.plan,
            self.review()?,
            self.plan.identity.length,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Mark {
    schema_version: u32,
    proposal: MarkProposal,
    observed: crate::policy_decisions::Timestamp,
    audit: Audit,
}
impl Mark {
    fn validate(&self) -> Result<()> {
        self.proposal.review()?;
        self.audit.validate()?;
        self.observed.context.validate()?;
        if self.schema_version != 1
            || self.audit.subject != self.proposal.plan.owner
            || self.audit.subject_generation != self.proposal.plan.owner_generation
            || self.audit.usage != self.proposal.usage()?
            || self.observed.lower_ms != self.observed.context.floor_ms
            || self.observed.lower_ms < 0
            || self.observed.upper_ms < self.observed.lower_ms
            || self.observed.upper_ms - self.observed.lower_ms > 500
            || self.observed.upper_ms > 4_102_444_800_000
        {
            return Err("artifact GC mark evidence is inconsistent".into());
        }
        Ok(())
    }
    fn not_before(&self) -> Result<i64> {
        self.validate()?;
        self.observed
            .upper_ms
            .checked_add(grace(self.proposal.grace_seconds)? as i64)
            .ok_or_else(|| "artifact GC grace deadline overflows".into())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeleteProposal {
    schema_version: u32,
    mark_sha256: String,
    plan: Plan,
    not_before_ms: i64,
}
impl DeleteProposal {
    fn review(&self) -> Result<String> {
        self.plan.validate()?;
        if self.schema_version != 1 || !io::hash(&self.mark_sha256) || self.not_before_ms < 0 {
            return Err("invalid artifact GC deletion proposal".into());
        }
        let mut bytes = b"luma-artifact-gc-exact-deletion-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(io::digest(&bytes))
    }
    fn usage(&self) -> Result<Use> {
        usage(
            Action::Delete,
            &self.plan,
            self.review()?,
            self.plan.identity.length + MAX_EVIDENCE,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    proposal: DeleteProposal,
    audit: Audit,
}
impl Intent {
    fn validate(&self) -> Result<()> {
        self.proposal.review()?;
        self.audit.validate()?;
        if self.schema_version != 1
            || self.audit.subject != self.proposal.plan.owner
            || self.audit.subject_generation != self.proposal.plan.owner_generation
            || self.audit.usage != self.proposal.usage()?
        {
            return Err("artifact GC deletion intent has mismatched governed scope".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Outcome {
    schema_version: u32,
    intent_sha256: String,
    mark_sha256: String,
    target: Target,
    identity: Identity,
    deleted: bool,
}
fn usage(action: Action, plan: &Plan, digest: String, input_bytes: u64) -> Result<Use> {
    let result = Use {
        action,
        selector: Selector {
            kind: Kind::Artifact,
            id: "artifact-gc-target".into(),
            generation: plan.owner_generation,
            digest,
        },
        input_bytes,
        output_bytes: MAX_EVIDENCE,
        units: 1,
    };
    result.validate()?;
    Ok(result)
}
fn live_scope(
    catalog: &Catalog,
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    expected: &Use,
) -> Result<Audit> {
    boundary.check()?;
    let audit = boundary.audit()?;
    if boundary.subject()? != catalog.owner.as_str() || audit.usage != *expected {
        return Err("artifact GC live principal or exact finite scope differs".into());
    }
    Ok(audit)
}

impl Catalog {
    fn gc_directory(&self) -> Result<File> {
        let directory = io::child_directory(&self.root, "gc")?;
        if directory.metadata()?.dev() != self.root.metadata()?.dev() {
            return Err("artifact GC sidecar must share local catalog filesystem".into());
        }
        validate_sidecar(&directory)?;
        Ok(directory)
    }
    fn gc_plan(&self, target: &Target, generation: u64) -> Result<Plan> {
        target.validate()?;
        io::private_directory(&self.root)?;
        let (receipts, orphans, _) = self.inventory()?;
        let directory = match target.area {
            Area::Object => {
                if !orphans.contains(&target.name) {
                    return Err("referenced or absent artifact objects are not GC targets".into());
                }
                &self.objects
            }
            Area::Retained => {
                if !io::names(&self.retained, MAX_FILES)?.contains(&target.name)
                    || receipts.iter().any(|(_, r)| r.request_id == target.name)
                {
                    return Err(
                        "artifact preparation is not independently retained and unreferenced"
                            .into(),
                    );
                }
                &self.retained
            }
        };
        let identity = identity(directory, &target.name)?;
        let root = self.root.metadata()?;
        let plan = Plan {
            schema_version: 1,
            installation: self.installation.clone(),
            owner: self.owner.clone(),
            owner_generation: generation,
            catalog_directory: (root.dev(), root.ino()),
            receipt_head: io::digest(&serde_json::to_vec(&receipts)?),
            target: target.clone(),
            identity,
        };
        plan.validate()?;
        Ok(plan)
    }
    fn gc_dispatch_guard(&self, plan: &Plan, sidecar: &File, metadata: &Identity) -> Result<()> {
        io::private_directory(&self.root)?;
        let root = self.root.metadata()?;
        if (root.dev(), root.ino()) != plan.catalog_directory {
            return Err("artifact GC catalog root changed at dispatch".into());
        }
        let (member, held) = match plan.target.area {
            Area::Object => ("objects", &self.objects),
            Area::Retained => ("retained", &self.retained),
        };
        for (name, held) in [(member, held), ("gc", sidecar)] {
            io::private_directory(held)?;
            let current = io::child_directory(&self.root, name)?.metadata()?;
            let original = held.metadata()?;
            if current.dev() != root.dev()
                || (current.dev(), current.ino()) != (original.dev(), original.ino())
            {
                return Err("artifact GC private namespace changed at dispatch".into());
            }
        }
        let current = io::open_at(&self.root, "metadata.sqlite3", libc::O_RDONLY, 0)?.metadata()?;
        if metadata_identity(&current, "") != *metadata {
            return Err("artifact GC receipt head storage changed at dispatch".into());
        }
        let current = io::open_at(held, &plan.target.name, libc::O_RDONLY, 0)?.metadata()?;
        if !current.is_file()
            || current.nlink() != 1
            || metadata_identity(&current, &plan.identity.sha256) != plan.identity
        {
            return Err("artifact GC immutable target changed at dispatch".into());
        }
        Ok(())
    }
    pub(super) fn gc_proposal(
        &self,
        target: &Target,
        seconds: u64,
        generation: u64,
    ) -> Result<serde_json::Value> {
        self.gc_directory()?;
        let proposal = MarkProposal {
            plan: self.gc_plan(target, generation)?,
            grace_seconds: seconds,
        };
        Ok(
            serde_json::json!({"review_sha256":proposal.review()?,"usage":proposal.usage()?,"proposal":proposal,
            "referenced_version_deletion":false,"timed_authority":false}),
        )
    }
    pub(super) fn gc_mark(
        &self,
        target: &Target,
        seconds: u64,
        review: &str,
        boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    ) -> Result<serde_json::Value> {
        let proposal = MarkProposal {
            plan: self.gc_plan(target, boundary.subject_generation()?)?,
            grace_seconds: seconds,
        };
        if proposal.review()? != review {
            return Err("artifact GC mark review changed".into());
        }
        let audit = live_scope(self, boundary, &proposal.usage()?)?;
        let pending =
            boundary.effect_begin(review, crate::policy_decisions::EffectKind::Retention)?;
        let result = self.gc_mark_checked(&proposal, &audit, || boundary.observation())?;
        boundary.effect_complete(pending, &io::digest(&serde_json::to_vec(&result)?))?;
        Ok(result)
    }
    fn gc_mark_checked(
        &self,
        proposal: &MarkProposal,
        audit: &Audit,
        mut observe: impl FnMut() -> Result<Observation>,
    ) -> Result<serde_json::Value> {
        if self.gc_plan(&proposal.plan.target, proposal.plan.owner_generation)? != proposal.plan {
            return Err("artifact GC target changed before mark".into());
        }
        let directory = self.gc_directory()?;
        if io::names(&directory, MAX_MARKS * 3)?
            .iter()
            .filter(|n| n.starts_with("mark-"))
            .count()
            >= MAX_MARKS
        {
            return Err("artifact GC mark inventory exhausted; preserve prior evidence".into());
        }
        observe()?;
        if self.gc_plan(&proposal.plan.target, proposal.plan.owner_generation)? != proposal.plan {
            return Err("artifact GC target changed during mark authority observation".into());
        }
        let metadata = metadata_identity(
            &io::open_at(&self.root, "metadata.sqlite3", libc::O_RDONLY, 0)?.metadata()?,
            "",
        );
        let observed = crate::policy_decisions::Timestamp::observed(&observe()?)?;
        let mark = Mark {
            schema_version: 1,
            proposal: proposal.clone(),
            observed,
            audit: audit.clone(),
        };
        mark.validate()?;
        // Catalog writers are serialized by the lifetime root flock. After the
        // last blocking authority read, recheck the immutable target and pinned
        // receipt storage metadata without repeating the whole content scan.
        self.gc_dispatch_guard(&proposal.plan, &directory, &metadata)?;
        let mark_sha256 = publish(&directory, "mark", &mark)?;
        self.root.sync_all()?;
        Ok(
            serde_json::json!({"schema_version":1,"mark_sha256":mark_sha256,"mark":mark,
            "not_before_ms":mark.not_before()?,"deleted":false,"receipt_authority":false}),
        )
    }
    fn gc_read_mark(&self, directory: &File, sha256: &str) -> Result<Mark> {
        if !io::hash(sha256) {
            return Err("invalid artifact GC mark identity".into());
        }
        let (mark, bytes): (Mark, _) = canonical(directory, &format!("mark-{sha256}.json"))?;
        mark.validate()?;
        if io::digest(&bytes) != sha256
            || mark.proposal.plan.owner != self.owner
            || mark.proposal.plan.installation != self.installation
        {
            return Err(
                "artifact GC mark belongs to different bytes, installation or principal".into(),
            );
        }
        Ok(mark)
    }
    fn gc_deletion(&self, sha256: &str, generation: u64) -> Result<DeleteProposal> {
        let directory = self.gc_directory()?;
        let mark = self.gc_read_mark(&directory, sha256)?;
        let plan = self.gc_plan(&mark.proposal.plan.target, generation)?;
        if plan.identity != mark.proposal.plan.identity
            || plan.catalog_directory != mark.proposal.plan.catalog_directory
        {
            return Err("artifact GC target inode changed after its grace mark".into());
        }
        Ok(DeleteProposal {
            schema_version: 1,
            mark_sha256: sha256.into(),
            plan,
            not_before_ms: mark.not_before()?,
        })
    }
    pub(super) fn gc_delete_proposal(
        &self,
        sha256: &str,
        generation: u64,
    ) -> Result<serde_json::Value> {
        let proposal = self.gc_deletion(sha256, generation)?;
        Ok(
            serde_json::json!({"review_sha256":proposal.review()?,"usage":proposal.usage()?,"proposal":proposal,
            "referenced_version_deletion":false,"timed_authority":false}),
        )
    }
    pub(super) fn gc_delete(
        &self,
        sha256: &str,
        review: &str,
        boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    ) -> Result<serde_json::Value> {
        let proposal = self.gc_deletion(sha256, boundary.subject_generation()?)?;
        if proposal.review()? != review {
            return Err("artifact GC deletion review changed".into());
        }
        let audit = live_scope(self, boundary, &proposal.usage()?)?;
        if boundary.observation()?.interval().endpoints().0 < proposal.not_before_ms {
            return Err("artifact GC grace has not elapsed under protected UTC".into());
        }
        let pending =
            boundary.effect_begin(review, crate::policy_decisions::EffectKind::Deletion)?;
        let result =
            self.gc_delete_checked(&proposal, &audit, || boundary.observation(), || Ok(()))?;
        boundary.effect_complete(pending, &io::digest(&serde_json::to_vec(&result)?))?;
        Ok(result)
    }
    fn gc_delete_checked(
        &self,
        proposal: &DeleteProposal,
        audit: &Audit,
        mut observe: impl FnMut() -> Result<Observation>,
        after_unlink: impl FnOnce() -> Result<()>,
    ) -> Result<serde_json::Value> {
        if self.gc_deletion(&proposal.mark_sha256, proposal.plan.owner_generation)? != *proposal {
            return Err("artifact GC deletion target changed".into());
        }
        let directory = self.gc_directory()?;
        if observe()?.interval().endpoints().0 < proposal.not_before_ms {
            return Err("artifact GC grace has not elapsed under protected UTC".into());
        }
        let intent = Intent {
            schema_version: 1,
            proposal: proposal.clone(),
            audit: audit.clone(),
        };
        intent.validate()?;
        let intent_sha256 = publish(&directory, "intent", &intent)?;
        self.root.sync_all()?;
        // The exact unreferenced cut is repeated AFTER durable preparation and
        // before the last potentially-blocking protected authority check.
        if self.gc_deletion(&proposal.mark_sha256, proposal.plan.owner_generation)? != *proposal {
            return Err("artifact GC target changed before final dispatch".into());
        }
        let current = observe()?;
        if current.interval().endpoints().0 < proposal.not_before_ms {
            return Err("artifact GC grace has not fully elapsed under protected UTC".into());
        }
        if self.gc_deletion(&proposal.mark_sha256, proposal.plan.owner_generation)? != *proposal {
            return Err("artifact GC target changed during final authority observation".into());
        }
        let metadata = metadata_identity(
            &io::open_at(&self.root, "metadata.sqlite3", libc::O_RDONLY, 0)?.metadata()?,
            "",
        );
        if observe()?.interval().endpoints().0 < proposal.not_before_ms {
            return Err("artifact GC protected grace changed before dispatch".into());
        }
        // Full receipt/reference and content checks precede this fresh boundary;
        // no authoritative writer can change that cut while root remains locked.
        // The cheap check catches namespace/inode changes during authority I/O.
        self.gc_dispatch_guard(&proposal.plan, &directory, &metadata)?;
        let target_directory = match proposal.plan.target.area {
            Area::Object => &self.objects,
            Area::Retained => &self.retained,
        };
        let name = CString::new(proposal.plan.target.name.as_bytes())?;
        if unsafe { libc::unlinkat(target_directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        target_directory.sync_all()?;
        self.root.sync_all()?;
        after_unlink()?;
        if io::names(target_directory, MAX_FILES)?.contains(&proposal.plan.target.name)
            || io::digest(&serde_json::to_vec(&self.inventory()?.0)?) != proposal.plan.receipt_head
        {
            return Err("artifact GC deletion outcome uncertain; preserve mark and intent".into());
        }
        let outcome = Outcome {
            schema_version: 1,
            intent_sha256,
            mark_sha256: proposal.mark_sha256.clone(),
            target: proposal.plan.target.clone(),
            identity: proposal.plan.identity.clone(),
            deleted: true,
        };
        let outcome_sha256 = publish(&directory, "outcome", &outcome)?;
        self.root.sync_all()?;
        Ok(
            serde_json::json!({"schema_version":1,"outcome_sha256":outcome_sha256,"outcome":outcome,
            "referenced_version_deleted":false,"receipt_authority":false}),
        )
    }
    pub(super) fn gc_outcomes(&self) -> Result<serde_json::Value> {
        let directory = self.gc_directory()?;
        let names = io::names(&directory, MAX_MARKS * 3)?;
        let mut outcomes = Vec::new();
        for name in &names {
            let Some(id) = name
                .strip_prefix("intent-")
                .and_then(|n| n.strip_suffix(".json"))
            else {
                continue;
            };
            let (intent, _): (Intent, _) = canonical(&directory, name)?;
            if intent.proposal.plan.owner != self.owner
                || intent.proposal.plan.installation != self.installation
            {
                return Err("artifact GC evidence belongs to another principal".into());
            }
            let mut confirmed = false;
            for outcome_name in names.iter().filter(|n| n.starts_with("outcome-")) {
                let (outcome, _): (Outcome, _) = canonical(&directory, outcome_name)?;
                if outcome.intent_sha256 == id {
                    confirmed = true;
                }
            }
            outcomes.push(serde_json::json!({"intent_sha256":id,"target":intent.proposal.plan.target,
                "outcome":if confirmed {"confirmed-local-deletion"} else {"uncertain-inspect-no-automatic-retry"},"receipt_authority":false}));
        }
        Ok(
            serde_json::json!({"schema_version":1,"outcomes":outcomes,"records_are_authority":false}),
        )
    }
}

pub(super) fn validate_sidecar(directory: &File) -> Result<()> {
    let names = io::names(directory, MAX_MARKS * 3)?;
    let mut marks: std::collections::BTreeMap<String, Mark> = std::collections::BTreeMap::new();
    let mut intents: std::collections::BTreeMap<String, Intent> = std::collections::BTreeMap::new();
    let mut outcomes = Vec::new();
    for name in names {
        let (kind, id) = name
            .strip_suffix(".json")
            .and_then(|n| n.split_once('-'))
            .ok_or("unknown artifact GC evidence name")?;
        if !io::hash(id) {
            return Err("noncanonical artifact GC evidence identity".into());
        }
        match kind {
            "mark" => {
                let (record, bytes): (Mark, _) = canonical(directory, &name)?;
                record.validate()?;
                if io::digest(&bytes) != id {
                    return Err("artifact GC mark digest mismatch".into());
                }
                marks.insert(id.into(), record);
            }
            "intent" => {
                let (record, bytes): (Intent, _) = canonical(directory, &name)?;
                record.validate()?;
                if io::digest(&bytes) != id {
                    return Err("artifact GC intent digest mismatch".into());
                }
                intents.insert(id.into(), record);
            }
            "outcome" => {
                let (record, bytes): (Outcome, _) = canonical(directory, &name)?;
                if io::digest(&bytes) != id || record.schema_version != 1 || !record.deleted {
                    return Err("artifact GC outcome digest/schema mismatch".into());
                }
                outcomes.push(record);
            }
            _ => return Err("unknown artifact GC evidence role".into()),
        }
    }
    if marks.len() > MAX_MARKS || intents.len() > MAX_MARKS || outcomes.len() > MAX_MARKS {
        return Err("artifact GC audit capacity exhausted".into());
    }
    for intent in intents.values() {
        let mark = marks
            .get(&intent.proposal.mark_sha256)
            .ok_or("artifact GC intent has no exact grace mark")?;
        if mark.not_before()? != intent.proposal.not_before_ms
            || mark.proposal.plan.identity != intent.proposal.plan.identity
            || mark.proposal.plan.target != intent.proposal.plan.target
            || mark.proposal.plan.owner != intent.proposal.plan.owner
            || mark.proposal.plan.installation != intent.proposal.plan.installation
            || mark.proposal.plan.catalog_directory != intent.proposal.plan.catalog_directory
        {
            return Err("artifact GC intent changed original mark target/grace".into());
        }
    }
    let mut completed = BTreeSet::new();
    for outcome in outcomes {
        let intent = intents
            .get(&outcome.intent_sha256)
            .ok_or("artifact GC outcome has no exact deletion intent")?;
        if !completed.insert(outcome.intent_sha256.clone())
            || outcome.mark_sha256 != intent.proposal.mark_sha256
            || outcome.target != intent.proposal.plan.target
            || outcome.identity != intent.proposal.plan.identity
        {
            return Err("artifact GC outcome changed or duplicated its exact intent".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(lower: i64, upper: i64) -> Observation {
        Observation::fixture(
            crate::utc_history::Statement {
                floor_ms: lower,
                policy_sha256: crate::bundle::hex(
                    &crate::utc_policy::ApprovedPolicy::fixed().unwrap().digest(),
                ),
                boot_id: "ab".repeat(16),
                process_generation: 1,
                source_clock_generation: 1,
                keeper_generation: 1,
                runtime_sha256: "cd".repeat(32),
            },
            crate::utc_bounds::Interval::new(lower, upper).unwrap(),
        )
    }
    fn audit(owner: &str, usage: Use) -> Audit {
        Audit {
            subject: owner.into(),
            subject_generation: 1,
            grant_id: "gc-scope".into(),
            grant_version: 1,
            checkpoint_head: "ef".repeat(32),
            operation_id: None,
            usage,
        }
    }
    fn catalog(label: &str) -> (super::super::tests::Fixture, Catalog, std::path::PathBuf) {
        let fixture = super::super::tests::Fixture::new(label);
        let path = fixture.path.parent().unwrap().join("owned");
        initialize_domain(&path, &"a".repeat(64), &"c".repeat(64)).unwrap();
        let catalog = Catalog::open_domain(&path, &"a".repeat(64), &"c".repeat(64)).unwrap();
        (fixture, catalog, path)
    }
    fn orphan(catalog: &Catalog, area: Area, bytes: &[u8]) -> Target {
        let target = Target {
            name: match area {
                Area::Object => io::digest(bytes),
                Area::Retained => "retained-preparation".into(),
            },
            area,
        };
        let directory = match target.area {
            Area::Object => &catalog.objects,
            Area::Retained => &catalog.retained,
        };
        io::write_member(directory, &target.name, bytes, 0o400).unwrap();
        directory.sync_all().unwrap();
        target
    }
    fn mark(catalog: &Catalog, target: &Target) -> String {
        let proposal = MarkProposal {
            plan: catalog.gc_plan(target, 1).unwrap(),
            grace_seconds: 3600,
        };
        let audit = audit(&catalog.owner, proposal.usage().unwrap());
        catalog
            .gc_mark_checked(&proposal, &audit, || Ok(observation(100_000, 100_100)))
            .unwrap()["mark_sha256"]
            .as_str()
            .unwrap()
            .into()
    }

    #[test]
    fn actual_orphan_unlink_after_conservative_grace_has_durable_outcome() {
        let (_fixture, catalog, path) = catalog("gc-object");
        let target = orphan(&catalog, Area::Object, b"orphan bytes");
        let mark = mark(&catalog, &target);
        let proposal = catalog.gc_deletion(&mark, 1).unwrap();
        assert_eq!(proposal.not_before_ms, 3_700_100);
        let audit = audit(&catalog.owner, proposal.usage().unwrap());
        let result = catalog
            .gc_delete_checked(
                &proposal,
                &audit,
                || Ok(observation(3_700_100, 3_700_200)),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(result["outcome"]["deleted"], true);
        assert!(!path.join("objects").join(target.name).exists());
        assert!(catalog.inventory().unwrap().0.is_empty());
        assert_eq!(
            catalog.gc_outcomes().unwrap()["outcomes"][0]["outcome"],
            "confirmed-local-deletion"
        );
        drop(catalog);
        let reopened = Catalog::open_domain(&path, &"a".repeat(64), &"c".repeat(64)).unwrap();
        assert_eq!(
            reopened.gc_outcomes().unwrap()["outcomes"][0]["receipt_authority"],
            false
        );
    }

    #[test]
    fn retained_preparation_requires_whole_interval_after_explicit_grace() {
        let (_fixture, catalog, _) = catalog("gc-retained-grace");
        let target = orphan(&catalog, Area::Retained, b"partial preparation");
        for invalid in [0, 3599, MAX_GRACE_SECONDS + 1, u64::MAX] {
            assert!(catalog.gc_proposal(&target, invalid, 1).is_err());
        }
        let mark = mark(&catalog, &target);
        let proposal = catalog.gc_deletion(&mark, 1).unwrap();
        let audit = audit(&catalog.owner, proposal.usage().unwrap());
        assert!(catalog
            .gc_delete_checked(
                &proposal,
                &audit,
                || Ok(observation(3_700_099, 3_700_200)),
                || panic!("grace refusal must not unlink")
            )
            .is_err());
        assert_eq!(
            io::read_member(&catalog.retained, &target.name, MAX_CONTENT).unwrap(),
            b"partial preparation"
        );
        assert!(catalog.gc_outcomes().unwrap()["outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        catalog
            .gc_delete_checked(
                &proposal,
                &audit,
                || Ok(observation(3_700_100, 3_700_200)),
                || Ok(()),
            )
            .unwrap();
        assert!(io::names(&catalog.retained, MAX_FILES).unwrap().is_empty());
    }

    #[test]
    fn committing_a_marked_object_permanently_denies_referenced_version_deletion() {
        let (_fixture, catalog, _) = catalog("gc-reference-race");
        let source = "b".repeat(64);
        let bytes = serde_json::to_vec(&serde_json::json!({"source_sha256":source})).unwrap();
        let target = orphan(&catalog, Area::Object, &bytes);
        let mark = mark(&catalog, &target);
        let commit = InvoiceCommit {
            installation: &catalog.installation,
            request_id: "committed-request",
            artifact_id: "committed-artifact",
            expected_version: 0,
            workflow_sha256: &"d".repeat(64),
            source_sha256: &source,
        };
        let receipt: Receipt = serde_json::from_value(
            domains::owned_invoice_receipt(&commit, &catalog.owner, 1, &bytes).unwrap(),
        )
        .unwrap();
        catalog.publish(&receipt, &bytes, |_| Ok(())).unwrap();
        assert!(catalog.gc_deletion(&mark, 1).is_err());
        assert!(catalog.gc_proposal(&target, 3600, 1).is_err());
        assert_eq!(
            io::read_member(&catalog.objects, &target.name, MAX_CONTENT).unwrap(),
            bytes
        );
        assert_eq!(catalog.inventory().unwrap().0.len(), 1);
    }

    #[test]
    fn interruption_after_unlink_preserves_uncertain_intent_without_auto_replay() {
        let (_fixture, catalog, path) = catalog("gc-uncertain");
        let target = orphan(&catalog, Area::Object, b"unreferenced bytes");
        let mark = mark(&catalog, &target);
        let proposal = catalog.gc_deletion(&mark, 1).unwrap();
        let audit = audit(&catalog.owner, proposal.usage().unwrap());
        assert!(catalog
            .gc_delete_checked(
                &proposal,
                &audit,
                || Ok(observation(3_700_100, 3_700_200)),
                || Err("lost deletion acknowledgment".into())
            )
            .is_err());
        assert!(!path.join("objects").join(&target.name).exists());
        assert_eq!(
            catalog.gc_outcomes().unwrap()["outcomes"][0]["outcome"],
            "uncertain-inspect-no-automatic-retry"
        );
        assert!(catalog.gc_deletion(&mark, 1).is_err());
        assert_eq!(catalog.inventory().unwrap().0.len(), 0);
    }

    #[test]
    fn same_digest_replacement_inode_and_foreign_domain_marks_never_cross_grace() {
        let (_fixture, catalog, path) = catalog("gc-identity");
        let bytes = b"same digest, different custody inode";
        let target = orphan(&catalog, Area::Object, bytes);
        let mark = mark(&catalog, &target);
        fs::remove_file(path.join("objects").join(&target.name)).unwrap();
        io::write_member(&catalog.objects, &target.name, bytes, 0o400).unwrap();
        catalog.objects.sync_all().unwrap();
        assert!(catalog.gc_deletion(&mark, 1).is_err());
        let other = path.parent().unwrap().join("other-owner");
        initialize_domain(&other, &catalog.installation, &"e".repeat(64)).unwrap();
        let foreign = Catalog::open_domain(&other, &catalog.installation, &"e".repeat(64)).unwrap();
        let original = catalog.gc_directory().unwrap();
        let copied =
            io::read_member(&original, &format!("mark-{mark}.json"), MAX_EVIDENCE).unwrap();
        let destination = foreign.gc_directory().unwrap();
        io::write_member(&destination, &format!("mark-{mark}.json"), &copied, 0o400).unwrap();
        destination.sync_all().unwrap();
        assert!(foreign.gc_deletion(&mark, 1).is_err());
    }

    #[test]
    fn mark_refuses_inode_replacement_during_each_authority_observation() {
        for replace_at in [1, 2] {
            let (_fixture, catalog, path) = catalog(&format!("gc-mark-observe-{replace_at}"));
            let bytes = b"same bytes cannot replace the reviewed custody inode";
            let target = orphan(&catalog, Area::Object, bytes);
            let proposal = MarkProposal {
                plan: catalog.gc_plan(&target, 1).unwrap(),
                grace_seconds: 3600,
            };
            let audit = audit(&catalog.owner, proposal.usage().unwrap());
            let _original = io::open_at(&catalog.objects, &target.name, libc::O_RDONLY, 0).unwrap();
            let mut observations = 0;
            assert!(catalog
                .gc_mark_checked(&proposal, &audit, || {
                    observations += 1;
                    if observations == replace_at {
                        fs::remove_file(path.join("objects").join(&target.name)).unwrap();
                        io::write_member(&catalog.objects, &target.name, bytes, 0o400).unwrap();
                        catalog.objects.sync_all().unwrap();
                    }
                    Ok(observation(100_000, 100_100))
                })
                .is_err());
            assert_eq!(observations, replace_at);
            assert!(io::names(&catalog.gc_directory().unwrap(), MAX_MARKS * 3)
                .unwrap()
                .is_empty());
            assert_eq!(
                io::read_member(&catalog.objects, &target.name, MAX_CONTENT).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn delete_refuses_inode_replacement_during_each_final_authority_observation() {
        for replace_at in [2, 3] {
            let (_fixture, catalog, path) = catalog(&format!("gc-delete-observe-{replace_at}"));
            let bytes = b"replacement must survive a stale deletion proposal";
            let target = orphan(&catalog, Area::Object, bytes);
            let mark = mark(&catalog, &target);
            let proposal = catalog.gc_deletion(&mark, 1).unwrap();
            let audit = audit(&catalog.owner, proposal.usage().unwrap());
            let _original = io::open_at(&catalog.objects, &target.name, libc::O_RDONLY, 0).unwrap();
            let mut observations = 0;
            assert!(catalog
                .gc_delete_checked(
                    &proposal,
                    &audit,
                    || {
                        observations += 1;
                        if observations == replace_at {
                            fs::remove_file(path.join("objects").join(&target.name)).unwrap();
                            io::write_member(&catalog.objects, &target.name, bytes, 0o400).unwrap();
                            catalog.objects.sync_all().unwrap();
                        }
                        Ok(observation(3_700_100, 3_700_200))
                    },
                    || panic!("replacement must never be unlinked")
                )
                .is_err());
            assert_eq!(observations, replace_at);
            assert_eq!(
                io::read_member(&catalog.objects, &target.name, MAX_CONTENT).unwrap(),
                bytes
            );
            assert_eq!(
                catalog.gc_outcomes().unwrap()["outcomes"][0]["outcome"],
                "uncertain-inspect-no-automatic-retry"
            );
        }
    }
}
