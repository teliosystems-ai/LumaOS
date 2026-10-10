//! Explicit terminal-domain disposition. Archive evidence is never authority.
//! Domain epochs survive removal; immutable workflow rows are not rewritten.
use crate::{
    artifacts as io,
    finite_grants::{Action, Kind, Selector, Use},
    scoped_read, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{BufRead, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
};

const BASE: &str = "/var/lib/luma-os/workflow-history";
const MAX_DOMAINS: usize = 2048;
const MAX_STATE: u64 = 4 * 1024 * 1024;
const MAX_STAGES: usize = 8;
const MAX_STAGED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 1029;
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
// Full supported object quota (128MiB) plus the closed DB quota (32MiB)
// fits with headroom. Canonical base64, bounded framing and the manifest remain
// strictly below the fixed 256MiB authenticated export transport limit.
const MAX_RAW: u64 = 176 * 1024 * 1024;
const CHUNK: usize = 65536;
const PREFIX: &str = "LUMA-WORKFLOW-HISTORY ";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Domain {
    Dag,
    Invoice,
}
impl Domain {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "dag" => Ok(Self::Dag),
            "invoice" => Ok(Self::Invoice),
            _ => Err("history type must be dag or invoice".into()),
        }
    }
    fn directory(self) -> &'static str {
        match self {
            Self::Dag => "/var/lib/luma-os/workflow-dags",
            Self::Invoice => "/var/lib/luma-os/workflow-invoice-domains",
        }
    }
    fn name(self, principal: &str) -> String {
        match self {
            Self::Dag => principal.into(),
            Self::Invoice => io::digest(principal.as_bytes()),
        }
    }
    pub(super) fn path(self, principal: &str) -> PathBuf {
        Path::new(self.directory()).join(self.name(principal))
    }
}
fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(io::digest(&serde_json::to_vec(value)?))
}
fn owner(principal: &str, generation: u64) -> Result<()> {
    if !io::hash(principal) || principal == "0".repeat(64) || generation == 0 {
        return Err("history requires an exact principal and generation".into());
    }
    Ok(())
}
pub(crate) fn epoch_argument(value: &str) -> Result<Option<u64>> {
    let epoch = value.parse::<u64>()?;
    if epoch.to_string() != value || epoch == u64::MAX {
        return Err("history epoch must be canonical and have a successor".into());
    }
    Ok((epoch != 0).then_some(epoch))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Incarnation {
    ext4_version: u32,
    birth_seconds: i64,
    birth_nanos: u32,
}
impl Incarnation {
    fn validate(&self) -> Result<()> {
        if self.birth_nanos >= 1_000_000_000 {
            return Err("invalid filesystem incarnation timestamp".into());
        }
        Ok(())
    }
    fn capture(file: &File) -> Result<Self> {
        // Inode numbers can be recycled after the last old descriptor closes.
        // The ext4 inode incarnation and immutable creation timestamp survive
        // content/directory changes but differ across such namespace reuse.
        let mut version = 0u32;
        let command: libc::c_ulong = if std::mem::size_of::<libc::c_long>() == 8 {
            0x8008_7601
        } else {
            0x8004_7601
        };
        if unsafe { libc::ioctl(file.as_raw_fd(), command, &mut version) } != 0 {
            return Err("history requires readable ext4 inode incarnation; preserve state".into());
        }
        let mut stat: libc::statx = unsafe { std::mem::zeroed() };
        let empty = CString::new("")?;
        if unsafe {
            libc::statx(
                file.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BTIME,
                &mut stat,
            )
        } != 0
            || stat.stx_mask & libc::STATX_BTIME == 0
        {
            return Err("history requires immutable ext4 birthtime; preserve state".into());
        }
        let incarnation = Self {
            ext4_version: version,
            birth_seconds: stat.stx_btime.tv_sec,
            birth_nanos: stat.stx_btime.tv_nsec,
        };
        incarnation.validate()?;
        Ok(incarnation)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    area: String,
    name: String,
    device: u64,
    inode: u64,
    incarnation: Incarnation,
    bytes: u64,
    mode: u32,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    installation: String,
    domain: Domain,
    principal: String,
    generation: u64,
    epoch: u64,
    root: scoped_read::RootIdentity,
    parent: scoped_read::RootIdentity,
    objects: scoped_read::RootIdentity,
    pending: scoped_read::RootIdentity,
    root_incarnation: Incarnation,
    parent_incarnation: Incarnation,
    objects_incarnation: Incarnation,
    pending_incarnation: Incarnation,
    pending_disposition: String,
    semantic_sha256: String,
    runs: usize,
    members: Vec<Member>,
    previous_retirement: String,
}
impl Manifest {
    fn validate(&self) -> Result<()> {
        owner(&self.principal, self.generation)?;
        self.root_incarnation.validate()?;
        self.parent_incarnation.validate()?;
        self.objects_incarnation.validate()?;
        self.pending_incarnation.validate()?;
        if self.schema_version != 2
            || !io::hash(&self.installation)
            || !io::hash(&self.semantic_sha256)
            || self.epoch == u64::MAX
            || self.pending_disposition != "unpublished_opaque_archive_only"
            || (self.runs == 0 && !self.members.iter().any(|member| member.area == "pending"))
            || self.runs > 256
            || self.members.is_empty()
            || self.members.len() > MAX_FILES
            || self
                .members
                .iter()
                .filter(|member| member.area != "root")
                .count()
                > match self.domain {
                    Domain::Dag => 1024,
                    Domain::Invoice => 512,
                }
            || self.root.inode == 0
            || self.parent.inode == 0
            || self.parent.device != self.root.device
            || self.objects.inode == 0
            || self.pending.inode == 0
            || self.objects.device != self.root.device
            || self.pending.device != self.root.device
            || (!self.previous_retirement.is_empty() && !io::hash(&self.previous_retirement))
        {
            return Err("invalid closed history manifest".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0u64;
        let mut object_bytes = 0u64;
        for member in &self.members {
            member.incarnation.validate()?;
            if !seen.insert((&member.area, &member.name))
                || member.device != self.root.device
                || member.inode == 0
                || (member.bytes == 0 && member.area != "pending")
                || member.bytes > MAX_FILE
                || !io::hash(&member.sha256)
                || match member.area.as_str() {
                    "root" => {
                        !matches!(
                            member.name.as_str(),
                            "metadata.sqlite3"
                                | "metadata.sqlite3-wal"
                                | "metadata.sqlite3-shm"
                                | "owner.json"
                        ) || member.mode
                            != if member.name == "owner.json" {
                                0o400
                            } else {
                                0o600
                            }
                    }
                    "objects" | "pending" => {
                        !io::hash(&member.name)
                            || member.mode != 0o400
                            || member.bytes > 2 * 1024 * 1024
                    }
                    _ => true,
                }
            {
                return Err("invalid history file binding".into());
            }
            total = total
                .checked_add(member.bytes)
                .ok_or("history byte overflow")?;
            if member.area != "root" {
                object_bytes = object_bytes
                    .checked_add(member.bytes)
                    .ok_or("history object byte overflow")?;
            }
        }
        if total > MAX_RAW
            || (self.domain == Domain::Invoice
                && !self
                    .members
                    .iter()
                    .any(|member| member.area == "root" && member.name == "owner.json"))
            || object_bytes
                > match self.domain {
                    Domain::Dag => 128 * 1024 * 1024,
                    Domain::Invoice => 64 * 1024 * 1024,
                }
            || serde_json::to_vec(self)?.len() as u64 > MAX_STATE
            || !self
                .members
                .iter()
                .any(|member| member.area == "root" && member.name == "metadata.sqlite3")
        {
            return Err("history archive capacity exceeded".into());
        }
        Ok(())
    }
    fn usage(&self, action: Action) -> Result<Use> {
        let kind = match action {
            Action::Read => Kind::File,
            Action::Export | Action::Delete => Kind::Artifact,
            Action::Retain => Kind::Resource,
            _ => return Err("unsupported history action".into()),
        };
        let usage = Use {
            action,
            selector: Selector {
                kind,
                id: "workflow-history".into(),
                generation: self.generation,
                digest: hash(self)?,
            },
            input_bytes: 0,
            output_bytes: if action == Action::Export {
                MAX_ARCHIVE
            } else {
                MAX_STATE
            },
            units: 1,
        };
        usage.validate()?;
        Ok(usage)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Export {
    manifest_sha256: String,
    archive_sha256: String,
    operation_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Mark {
    manifest: Manifest,
    export: Export,
    grace_seconds: u64,
    marked_upper_ms: i64,
    operation_id: String,
}
impl Mark {
    fn deadline(&self) -> Result<i64> {
        if !(3600..=30 * 86400).contains(&self.grace_seconds) || self.marked_upper_ms <= 0 {
            return Err("history grace must be one hour to thirty days under protected UTC".into());
        }
        self.marked_upper_ms
            .checked_add(i64::try_from(self.grace_seconds)? * 1000)
            .ok_or_else(|| "history grace overflow".into())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    epoch: u64,
    manifest_sha256: String,
    export: Export,
    mark_sha256: String,
    operation_id: String,
    previous_receipt_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u32,
    installation: String,
    domain: Domain,
    principal: String,
    epoch: u64,
    export: Option<Export>,
    mark: Option<Mark>,
    deleting: bool,
    last: Option<Tombstone>,
}
impl State {
    fn initial(installation: &str, domain: Domain, principal: &str) -> Self {
        Self {
            schema_version: 1,
            installation: installation.into(),
            domain,
            principal: principal.into(),
            epoch: 0,
            export: None,
            mark: None,
            deleting: false,
            last: None,
        }
    }
    fn validate(&self) -> Result<()> {
        owner(&self.principal, 1)?;
        if self.schema_version != 1
            || !io::hash(&self.installation)
            || self.epoch == u64::MAX
            || self.deleting && self.mark.is_none()
        {
            return Err("invalid history epoch state".into());
        }
        if let Some(mark) = &self.mark {
            mark.manifest.validate()?;
            mark.deadline()?;
            if mark.manifest.installation != self.installation
                || mark.manifest.domain != self.domain
                || mark.manifest.principal != self.principal
                || mark.manifest.epoch != self.epoch
                || !operation_id(&mark.operation_id)
                || mark.manifest.previous_retirement
                    != self
                        .last
                        .as_ref()
                        .map(hash)
                        .transpose()?
                        .unwrap_or_default()
                || mark.export.manifest_sha256 != hash(&mark.manifest)?
                || self.export.as_ref() != Some(&mark.export)
            {
                return Err("history mark differs from current epoch/export".into());
            }
        }
        if let Some(export) = &self.export {
            if !io::hash(&export.manifest_sha256)
                || !io::hash(&export.archive_sha256)
                || !operation_id(&export.operation_id)
            {
                return Err("invalid history export evidence".into());
            }
        }
        if let Some(last) = &self.last {
            if last.epoch.checked_add(1) != Some(self.epoch)
                || !io::hash(&last.manifest_sha256)
                || !io::hash(&last.mark_sha256)
                || !operation_id(&last.operation_id)
                || !operation_id(&last.export.operation_id)
                || last.export.manifest_sha256 != last.manifest_sha256
                || !io::hash(&last.export.archive_sha256)
                || (!last.previous_receipt_sha256.is_empty()
                    && !io::hash(&last.previous_receipt_sha256))
            {
                return Err("history retirement tombstone differs from its successor epoch".into());
            }
        } else if self.epoch != 0 {
            return Err("noninitial history epoch lacks its durable retirement tombstone".into());
        }
        Ok(())
    }
}
fn operation_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn staging_target(name: &str) -> Option<&str> {
    let (target, nonce) = name.strip_prefix(".new-")?.split_once('-')?;
    (io::hash(target) && operation_id(nonce)).then_some(target)
}
fn ledger_inventory(base: &File) -> Result<Vec<String>> {
    let names = io::names(base, MAX_DOMAINS + MAX_STAGES + 1)?;
    let mut targets = std::collections::BTreeSet::new();
    let mut bytes = 0u64;
    let mut states = 0usize;
    for name in &names {
        if name == "identity.json" {
            continue;
        }
        if io::hash(name) {
            states += 1;
            continue;
        }
        let target = staging_target(name).ok_or("unknown history ledger member; preserve state")?;
        if !targets.insert(target) || targets.len() > MAX_STAGES {
            return Err("history staging capacity/conflict; preserve all evidence".into());
        }
        let file = io::open_at(base, name, libc::O_RDONLY, 0)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.mode() & 0o7777 != 0o600
            || meta.len() > MAX_STATE
        {
            return Err("invalid history staging physical member".into());
        }
        bytes = bytes
            .checked_add(meta.len())
            .ok_or("history staging overflow")?;
    }
    if states > MAX_DOMAINS || bytes > MAX_STAGED_BYTES {
        return Err("history ledger capacity exceeded".into());
    }
    Ok(names)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StagingReview {
    schema_version: u32,
    installation: String,
    domain: Domain,
    principal: String,
    generation: u64,
    base: scoped_read::RootIdentity,
    base_incarnation: Incarnation,
    current_state_sha256: String,
    member: Member,
}
struct Ledger {
    base: File,
    incarnation: Incarnation,
    published: Option<String>,
    path: PathBuf,
    state: State,
}
impl Ledger {
    fn open(domain: Domain, principal: &str) -> Result<Self> {
        Self::at(Path::new(BASE), &io::installation()?, domain, principal)
    }
    fn at(base: &Path, installation: &str, domain: Domain, principal: &str) -> Result<Self> {
        owner(principal, 1)?;
        crate::artifact_catalog::safe_path(base)?;
        let directory = scoped_read::open_directory(base)?;
        io::private_directory(&directory)?;
        crate::artifact_catalog::ext4(&directory)?;
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("history epoch ledger busy".into());
        }
        let identity = io::read_member(&directory, "identity.json", 4096)?;
        if identity
            != serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"installation":installation}),
            )?
        {
            return Err("history ledger installation differs".into());
        }
        let names = ledger_inventory(&directory)?;
        let name = hash(&(domain, principal))?;
        let path = base.join(&name);
        let mut published = None;
        let state = if names.contains(&name) {
            let bytes = io::read_member(&directory, &name, MAX_STATE)?;
            published = Some(io::digest(&bytes));
            let state: State = serde_json::from_slice(&bytes)?;
            if serde_json::to_vec(&state)? != bytes {
                return Err("noncanonical history epoch state".into());
            }
            state
        } else {
            if names.iter().filter(|name| io::hash(name)).count() >= MAX_DOMAINS {
                return Err("history security-domain capacity exhausted".into());
            }
            State::initial(installation, domain, principal)
        };
        state.validate()?;
        if state.installation != installation
            || state.domain != domain
            || state.principal != principal
        {
            return Err("history state identity changed".into());
        }
        let ledger = Self {
            incarnation: Incarnation::capture(&directory)?,
            published,
            base: directory,
            path,
            state,
        };
        ledger.recheck()?;
        Ok(ledger)
    }
    fn recheck(&self) -> Result<()> {
        let base = self.path.parent().ok_or("history base missing")?;
        crate::artifact_catalog::safe_path(base)?;
        let named = scoped_read::open_directory(base)?;
        io::private_directory(&named)?;
        if scoped_read::identity(&named)? != scoped_read::identity(&self.base)?
            || Incarnation::capture(&named)? != self.incarnation
            || Incarnation::capture(&self.base)? != self.incarnation
        {
            return Err("history ledger namespace detached or replaced".into());
        }
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid ledger member")?;
        let exists = ledger_inventory(&self.base)?
            .iter()
            .any(|entry| entry == name);
        match &self.published {
            Some(expected)
                if exists
                    && io::digest(&io::read_member(&self.base, name, MAX_STATE)?) == *expected =>
            {
                Ok(())
            }
            None if !exists => Ok(()),
            _ => Err("history ledger publication changed outside retained transaction".into()),
        }
    }
    fn staging(&self, generation: u64) -> Result<StagingReview> {
        self.recheck()?;
        let target = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid staging target")?;
        let name = ledger_inventory(&self.base)?
            .into_iter()
            .find(|name| staging_target(name) == Some(target))
            .ok_or("no unpublished staging for this exact history domain")?;
        let file = io::open_at(&self.base, &name, libc::O_RDONLY, 0)?;
        let metadata = file.metadata()?;
        let bytes = io::read_member(&self.base, &name, MAX_STATE)?;
        let named = io::open_at(&self.base, &name, libc::O_RDONLY, 0)?;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ) != (
            named.metadata()?.dev(),
            named.metadata()?.ino(),
            named.metadata()?.len(),
            named.metadata()?.mtime(),
            named.metadata()?.mtime_nsec(),
            named.metadata()?.ctime(),
            named.metadata()?.ctime_nsec(),
        ) || Incarnation::capture(&named)? != Incarnation::capture(&file)?
        {
            return Err("history staging changed during pinned capture".into());
        }
        let stage = StagingReview {
            schema_version: 1,
            installation: self.state.installation.clone(),
            domain: self.state.domain,
            principal: self.state.principal.clone(),
            generation,
            base: scoped_read::identity(&self.base)?,
            base_incarnation: self.incarnation.clone(),
            current_state_sha256: hash(&self.state)?,
            member: Member {
                area: "unpublished_ledger_staging".into(),
                name,
                device: metadata.dev(),
                inode: metadata.ino(),
                incarnation: Incarnation::capture(&file)?,
                bytes: metadata.len(),
                mode: metadata.mode() & 0o7777,
                sha256: io::digest(&bytes),
            },
        };
        if stage.member.bytes != bytes.len() as u64 {
            return Err("history staging changed during capture".into());
        }
        self.recheck()?;
        Ok(stage)
    }
    fn require_clean(&self) -> Result<()> {
        self.recheck()?;
        let target = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid history target")?;
        if ledger_inventory(&self.base)?
            .iter()
            .any(|name| staging_target(name) == Some(target))
        {
            return Err("history namespace fenced by unresolved publication staging; exact reviewed discard required".into());
        }
        Ok(())
    }
    fn discard_staging(
        &self,
        reviewed: &StagingReview,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.recheck()?;
        if self.staging(reviewed.generation)? != *reviewed {
            return Err("history staging physical generation/content changed".into());
        }
        let file = io::open_at(&self.base, &reviewed.member.name, libc::O_RDONLY, 0)?;
        check()?;
        self.recheck()?;
        if self.staging(reviewed.generation)? != *reviewed
            || Incarnation::capture(&file)? != reviewed.member.incarnation
        {
            return Err("history staging changed after authority I/O".into());
        }
        let name = CString::new(reviewed.member.name.as_str())?;
        if unsafe { libc::unlinkat(self.base.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err("history staging discard uncertain; explicitly reinspect".into());
        }
        self.base.sync_all()?;
        check()?;
        self.recheck()?;
        if ledger_inventory(&self.base)?.contains(&reviewed.member.name) {
            return Err("history staging recreated during discard acknowledgment".into());
        }
        Ok(())
    }
    fn save(&mut self, state: State, mut check: impl FnMut() -> Result<()>) -> Result<()> {
        state.validate()?;
        let bytes = serde_json::to_vec(&state)?;
        if bytes.len() as u64 > MAX_STATE {
            return Err("history state capacity exhausted".into());
        }
        check()?;
        self.recheck()?;
        let target_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid ledger target")?;
        let names = ledger_inventory(&self.base)?;
        if names
            .iter()
            .any(|name| staging_target(name) == Some(target_name))
        {
            return Err("unpublished history staging requires exact governed review/discard before another publication".into());
        }
        if names
            .iter()
            .filter(|name| staging_target(name).is_some())
            .count()
            >= MAX_STAGES
        {
            return Err(
                "history staging capacity exhausted; perform explicit scoped disposition".into(),
            );
        }
        let mut nonce = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let temporary = format!(".new-{target_name}-{}", crate::bundle::hex(&nonce));
        io::write_member(&self.base, &temporary, &bytes, 0o600)?;
        self.base.sync_all()?;
        let mut pinned = io::open_at(&self.base, &temporary, libc::O_RDONLY, 0)?;
        let staged = self.staging(1)?;
        if staged.member.name != temporary
            || staged.member.bytes != bytes.len() as u64
            || staged.member.sha256 != io::digest(&bytes)
            || Incarnation::capture(&pinned)? != staged.member.incarnation
        {
            return Err("history staging differs from exact intended publication; preserve unpublished bytes".into());
        }
        check()?;
        self.recheck()?;
        let mut retained_bytes = Vec::new();
        (&mut pinned)
            .take(MAX_STATE + 1)
            .read_to_end(&mut retained_bytes)?;
        if retained_bytes != bytes
            || Incarnation::capture(&pinned)? != staged.member.incarnation
            || self.staging(1)? != staged
        {
            return Err(
                "history staging changed during authority I/O; preserve unpublished evidence"
                    .into(),
            );
        }
        self.recheck()?;
        let source = CString::new(temporary)?;
        let target = CString::new(
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid ledger name")?,
        )?;
        if unsafe {
            libc::renameat(
                self.base.as_raw_fd(),
                source.as_ptr(),
                self.base.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err("history publication uncertain; preserve exact ledger staging".into());
        }
        self.base.sync_all()?;
        self.published = Some(io::digest(&bytes));
        self.state = state;
        self.recheck()?;
        check()?;
        self.recheck()?;
        Ok(())
    }
}
fn admitted_epoch(state: &State) -> Result<u64> {
    state.validate()?;
    if state.mark.is_some() || state.deleting {
        return Err(
            "workflow history is closed for reviewed retirement; old requests cannot execute"
                .into(),
        );
    }
    Ok(state.epoch)
}
pub(crate) fn active_epoch(domain: Domain, principal: &str) -> Result<u64> {
    let ledger = Ledger::open(domain, principal)?;
    ledger.require_clean()?;
    admitted_epoch(&ledger.state)
}
pub(crate) fn check_epoch(domain: Domain, principal: &str, epoch: u64) -> Result<()> {
    if active_epoch(domain, principal)? != epoch {
        return Err(
            "workflow namespace epoch retired; no old request or grant may be replayed".into(),
        );
    }
    Ok(())
}
pub(crate) fn initialize_installed() -> Result<()> {
    initialize_at(Path::new(BASE), &io::installation()?)
}
pub(crate) fn initialize_at(path: &Path, installation: &str) -> Result<()> {
    if !io::hash(installation) {
        return Err("invalid history ledger installation".into());
    }
    let parent = path.parent().ok_or("history ledger parent missing")?;
    crate::artifact_catalog::safe_path(parent)?;
    let directory = scoped_read::open_directory(parent)?;
    crate::artifact_catalog::ext4(&directory)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    io::write_member(
        &root,
        "identity.json",
        &serde_json::to_vec(&serde_json::json!({"schema_version":1,"installation":installation}))?,
        0o400,
    )?;
    root.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

pub(crate) struct Input {
    pub root: File,
    pub path: PathBuf,
    pub semantic_sha256: String,
    pub runs: usize,
}
struct Tree {
    root: File,
    objects: Option<File>,
    pending: Option<File>,
    parent: File,
    parent_path: PathBuf,
    name: String,
    manifest: Manifest,
}
struct Absence {
    parent: File,
    path: PathBuf,
    name: String,
    identity: scoped_read::RootIdentity,
    incarnation: Incarnation,
}
impl Absence {
    fn at(manifest: &Manifest, path: &Path) -> Result<Self> {
        manifest.validate()?;
        let parent = path.parent().ok_or("history parent missing")?;
        crate::artifact_catalog::safe_path(parent)?;
        let proof = Self {
            parent: scoped_read::open_directory(parent)?,
            path: parent.into(),
            name: path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| io::hash(name))
                .ok_or("invalid absent history domain name")?
                .into(),
            identity: manifest.parent,
            incarnation: manifest.parent_incarnation.clone(),
        };
        proof.recheck()?;
        Ok(proof)
    }
    fn recheck(&self) -> Result<()> {
        crate::artifact_catalog::safe_path(&self.path)?;
        let named = scoped_read::open_directory(&self.path)?;
        io::private_directory(&named)?;
        if scoped_read::identity(&named)? != self.identity
            || scoped_read::identity(&self.parent)? != self.identity
            || Incarnation::capture(&named)? != self.incarnation
            || Incarnation::capture(&self.parent)? != self.incarnation
        {
            return Err(
                "absent history parent detached or replaced; preserve destructive intent".into(),
            );
        }
        if io::names(&named, 2048)?.contains(&self.name) {
            return Err("absent history domain recreated; no retirement acknowledgment".into());
        }
        Ok(())
    }
}
impl Tree {
    fn recheck_parent(&self) -> Result<()> {
        crate::artifact_catalog::safe_path(&self.parent_path)?;
        let named = scoped_read::open_directory(&self.parent_path)?;
        io::private_directory(&named)?;
        if scoped_read::identity(&self.parent)? != self.manifest.parent
            || scoped_read::identity(&named)? != self.manifest.parent
            || Incarnation::capture(&self.parent)? != self.manifest.parent_incarnation
            || Incarnation::capture(&named)? != self.manifest.parent_incarnation
        {
            return Err("history parent namespace detached or replaced".into());
        }
        Ok(())
    }
    fn capture(
        input: Input,
        domain: Domain,
        principal: &str,
        generation: u64,
        epoch: u64,
        previous: &str,
    ) -> Result<Self> {
        let parent = scoped_read::open_directory(
            input.path.parent().ok_or("history domain parent missing")?,
        )?;
        let objects = io::child_directory(&input.root, "objects")?;
        let pending = io::child_directory(&input.root, "pending")?;
        let mut members = Vec::new();
        for (area, directory, limit) in [
            ("root", &input.root, 6),
            ("objects", &objects, 1024),
            ("pending", &pending, 1024),
        ] {
            for name in io::names(directory, limit)? {
                if area == "root" && matches!(name.as_str(), "objects" | "pending") {
                    continue;
                }
                let bytes = io::read_member(directory, &name, MAX_FILE)?;
                let file = io::open_at(directory, &name, libc::O_RDONLY, 0)?;
                let meta = file.metadata()?;
                members.push(Member {
                    area: area.into(),
                    name,
                    device: meta.dev(),
                    inode: meta.ino(),
                    incarnation: Incarnation::capture(&file)?,
                    bytes: bytes.len() as u64,
                    mode: meta.mode() & 0o7777,
                    sha256: io::digest(&bytes),
                });
            }
        }
        let manifest = Manifest {
            schema_version: 2,
            installation: io::installation()?,
            domain,
            principal: principal.into(),
            generation,
            epoch,
            root: scoped_read::identity(&input.root)?,
            parent: scoped_read::identity(&parent)?,
            objects: scoped_read::identity(&objects)?,
            pending: scoped_read::identity(&pending)?,
            root_incarnation: Incarnation::capture(&input.root)?,
            parent_incarnation: Incarnation::capture(&parent)?,
            objects_incarnation: Incarnation::capture(&objects)?,
            pending_incarnation: Incarnation::capture(&pending)?,
            pending_disposition: "unpublished_opaque_archive_only".into(),
            semantic_sha256: input.semantic_sha256,
            runs: input.runs,
            members,
            previous_retirement: previous.into(),
        };
        manifest.validate()?;
        let name = input
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid history domain name")?
            .into();
        let tree = Self {
            parent_path: input
                .path
                .parent()
                .ok_or("history domain parent missing")?
                .into(),
            root: input.root,
            objects: Some(objects),
            pending: Some(pending),
            parent,
            name,
            manifest,
        };
        tree.recheck(false)?;
        Ok(tree)
    }
    fn marked(mark: &Mark, partial: bool) -> Result<Option<Self>> {
        Self::marked_at(
            mark,
            &mark.manifest.domain.path(&mark.manifest.principal),
            partial,
        )
    }
    fn marked_at(mark: &Mark, path: &Path, partial: bool) -> Result<Option<Self>> {
        mark.manifest.validate()?;
        let parent_path = path.parent().ok_or("history parent missing")?;
        crate::artifact_catalog::safe_path(parent_path)?;
        let parent = scoped_read::open_directory(parent_path)?;
        io::private_directory(&parent)?;
        crate::artifact_catalog::ext4(&parent)?;
        if scoped_read::identity(&parent)? != mark.manifest.parent
            || Incarnation::capture(&parent)? != mark.manifest.parent_incarnation
        {
            return Err(
                "marked history parent namespace replaced; preserve original evidence".into(),
            );
        }
        let names = io::names(&parent, 2048)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| io::hash(name))
            .ok_or("invalid history directory name")?
            .to_owned();
        if !names.contains(&name) {
            return if partial {
                Ok(None)
            } else {
                Err(
                    "marked history disappeared without destructive intent; preserve evidence"
                        .into(),
                )
            };
        }
        let root = io::child_directory(&parent, &name)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("retired history domain is busy".into());
        }
        let names = io::names(&root, 6)?;
        let objects = if names.contains(&"objects".into()) {
            Some(io::child_directory(&root, "objects")?)
        } else if partial {
            None
        } else {
            return Err("marked object directory disappeared before destructive intent".into());
        };
        let pending = if names.contains(&"pending".into()) {
            Some(io::child_directory(&root, "pending")?)
        } else if partial {
            None
        } else {
            return Err("marked pending directory disappeared before destructive intent".into());
        };
        Ok(Some(Self {
            parent_path: parent_path.into(),
            root,
            objects,
            pending,
            parent,
            name,
            manifest: mark.manifest.clone(),
        }))
    }
    fn file(&self, member: &Member) -> Result<&File> {
        match member.area.as_str() {
            "root" => Ok(&self.root),
            "objects" => self
                .objects
                .as_ref()
                .ok_or_else(|| "history object directory is already removed".into()),
            "pending" => self
                .pending
                .as_ref()
                .ok_or_else(|| "history pending directory is already removed".into()),
            _ => Err("unknown history member area".into()),
        }
    }
    fn bytes(&self, member: &Member) -> Result<Vec<u8>> {
        let parent = self.file(member)?;
        let mut file = io::open_at(parent, &member.name, libc::O_RDONLY, 0)?;
        let before = file.metadata()?;
        let snapshot = |meta: &fs::Metadata| {
            (
                meta.dev(),
                meta.ino(),
                meta.len(),
                meta.mode(),
                meta.uid(),
                meta.gid(),
                meta.nlink(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
            )
        };
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.nlink() != 1
            || before.dev() != member.device
            || before.ino() != member.inode
            || before.len() != member.bytes
            || before.len() > MAX_FILE
            || before.mode() & 0o7777 != member.mode
            || Incarnation::capture(&file)? != member.incarnation
        {
            return Err("history member physical generation changed".into());
        }
        let mut bytes = Vec::new();
        (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        let named_file = io::open_at(parent, &member.name, libc::O_RDONLY, 0)?;
        let named = named_file.metadata()?;
        if snapshot(&before) != snapshot(&after)
            || snapshot(&after) != snapshot(&named)
            || Incarnation::capture(&file)? != member.incarnation
            || Incarnation::capture(&named_file)? != member.incarnation
            || bytes.len() as u64 != member.bytes
            || io::digest(&bytes) != member.sha256
        {
            return Err("history member content or named physical generation changed".into());
        }
        Ok(bytes)
    }
    fn recheck_namespace(&self, partial: bool) -> Result<()> {
        self.recheck_parent()?;
        if scoped_read::identity(&self.root)? != self.manifest.root
            || Incarnation::capture(&self.root)? != self.manifest.root_incarnation
            || scoped_read::identity(&io::child_directory(&self.parent, &self.name)?)?
                != self.manifest.root
            || Incarnation::capture(&io::child_directory(&self.parent, &self.name)?)?
                != self.manifest.root_incarnation
        {
            return Err("history directory generation changed".into());
        }
        let root_names = io::names(&self.root, 6)?;
        for (name, retained, expected, incarnation) in [
            (
                "objects",
                self.objects.as_ref(),
                self.manifest.objects,
                &self.manifest.objects_incarnation,
            ),
            (
                "pending",
                self.pending.as_ref(),
                self.manifest.pending,
                &self.manifest.pending_incarnation,
            ),
        ] {
            match retained {
                Some(directory) => {
                    if partial
                        && !root_names.contains(&name.to_owned())
                        && directory.metadata()?.nlink() == 0
                        && io::names(directory, MAX_FILES)?.is_empty()
                    {
                        continue;
                    }
                    if scoped_read::identity(directory)? != expected
                        || &Incarnation::capture(directory)? != incarnation
                        || scoped_read::identity(&io::child_directory(&self.root, name)?)?
                            != expected
                        || &Incarnation::capture(&io::child_directory(&self.root, name)?)?
                            != incarnation
                    {
                        return Err("history child directory generation changed".into());
                    }
                }
                None => {
                    if !partial || root_names.contains(&name.to_owned()) {
                        return Err(
                            "history child directory unexpectedly missing or recreated".into()
                        );
                    }
                }
            }
        }
        Ok(())
    }
    fn recheck(&self, partial: bool) -> Result<Vec<String>> {
        self.recheck_namespace(partial)?;
        let mut present = Vec::new();
        for (area, parent, limit) in [
            ("root", Some(&self.root), 6),
            ("objects", self.objects.as_ref(), 1024),
            ("pending", self.pending.as_ref(), 1024),
        ] {
            let Some(parent) = parent else {
                continue;
            };
            for name in io::names(parent, limit)? {
                if area == "root" && matches!(name.as_str(), "objects" | "pending") {
                    continue;
                }
                let member = self
                    .manifest
                    .members
                    .iter()
                    .find(|member| member.area == area && member.name == name)
                    .ok_or("unknown history member; preserve state")?;
                self.bytes(member)?;
                present.push(format!("{area}/{name}"));
            }
        }
        if !partial && present.len() != self.manifest.members.len() {
            return Err("history lost a file before destructive intent; preserve state".into());
        }
        present.push("domain-present".into());
        if self.objects.is_some() {
            present.push("objects-directory-present".into());
        }
        if self.pending.is_some() {
            present.push("pending-directory-present".into());
        }
        Ok(present)
    }
    fn remove_members(&self, mut check: impl FnMut() -> Result<()>) -> Result<()> {
        self.recheck(true)?;
        for member in &self.manifest.members {
            if (member.area == "objects" && self.objects.is_none())
                || (member.area == "pending" && self.pending.is_none())
            {
                continue;
            }
            let directory = self.file(member)?;
            let names = io::names(directory, MAX_FILES)?;
            if !names.contains(&member.name) {
                continue;
            }
            check()?;
            self.recheck(true)?;
            self.bytes(member)?;
            self.recheck(true)?;
            let name = CString::new(member.name.as_str())?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(
                    "history member deletion uncertain; explicitly reinspect exact remaining files"
                        .into(),
                );
            }
            directory.sync_all()?;
            check()?;
            self.recheck(true)?;
        }
        self.recheck(true)?;
        Ok(())
    }
    fn remove_directories(&self, mut check: impl FnMut() -> Result<()>) -> Result<()> {
        self.recheck(true)?;
        for (name, directory, identity, incarnation) in [
            (
                "objects",
                self.objects.as_ref(),
                self.manifest.objects,
                &self.manifest.objects_incarnation,
            ),
            (
                "pending",
                self.pending.as_ref(),
                self.manifest.pending,
                &self.manifest.pending_incarnation,
            ),
        ] {
            if directory.is_none() {
                continue;
            }
            check()?;
            self.recheck(true)?;
            if scoped_read::identity(&io::child_directory(&self.root, name)?)? != identity {
                return Err("history child generation changed before removal".into());
            }
            if &Incarnation::capture(&io::child_directory(&self.root, name)?)? != incarnation {
                return Err("history child inode incarnation changed before removal".into());
            }
            let name = CString::new(name)?;
            if unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(
                    "history directory deletion uncertain; preserve retirement intent".into(),
                );
            }
            self.root.sync_all()?;
            check()?;
            self.recheck(true)?;
        }
        check()?;
        self.recheck(true)?;
        if scoped_read::identity(&io::child_directory(&self.parent, &self.name)?)?
            != self.manifest.root
            || Incarnation::capture(&io::child_directory(&self.parent, &self.name)?)?
                != self.manifest.root_incarnation
        {
            return Err("history domain generation changed before final removal".into());
        }
        let name = CString::new(self.name.as_str())?;
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return Err("history domain removal uncertain; preserve retirement intent".into());
        }
        self.parent.sync_all()?;
        check()?;
        self.recheck_parent()?;
        if io::names(&self.parent, 2048)?.contains(&self.name) {
            return Err("history domain recreated during final removal acknowledgment".into());
        }
        Ok(())
    }
}

fn inspection(installation: &str, domain: Domain, principal: &str, generation: u64) -> Result<Use> {
    owner(principal, generation)?;
    let usage = Use {
        action: Action::Read,
        selector: Selector {
            kind: Kind::File,
            id: "workflow-history-inspect".into(),
            generation,
            digest: hash(&(
                "luma-history-inspection-v1",
                installation,
                domain,
                principal,
                generation,
            ))?,
        },
        input_bytes: 0,
        output_bytes: MAX_STATE,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
fn staging_usage(stage: &StagingReview) -> Result<Use> {
    let usage = Use {
        action: Action::Retain,
        selector: Selector {
            kind: Kind::Resource,
            id: "workflow-history-staging".into(),
            generation: stage.generation,
            digest: hash(stage)?,
        },
        input_bytes: 0,
        output_bytes: MAX_STATE,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
fn input(domain: Domain, principal: &str, generation: u64, epoch: u64) -> Result<Input> {
    match domain {
        Domain::Dag => super::dag::closed_history(principal, generation, epoch),
        Domain::Invoice => super::closed_history(principal, generation, epoch),
    }
}
fn current_tree(ledger: &Ledger, generation: u64) -> Result<Tree> {
    ledger.require_clean()?;
    if ledger.state.mark.is_some() {
        return Err(
            "marked history requires deletion inspection, not another export or adoption".into(),
        );
    }
    let previous = ledger
        .state
        .last
        .as_ref()
        .map(hash)
        .transpose()?
        .unwrap_or_default();
    let tree = Tree::capture(
        input(
            ledger.state.domain,
            &ledger.state.principal,
            generation,
            ledger.state.epoch,
        )?,
        ledger.state.domain,
        &ledger.state.principal,
        generation,
        ledger.state.epoch,
        &previous,
    )?;
    ledger.recheck()?;
    Ok(tree)
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Begin {
        manifest: Manifest,
    },
    Member {
        index: usize,
    },
    Chunk {
        index: usize,
        offset: u64,
        base64: String,
    },
    EndMember {
        index: usize,
    },
    Complete {
        archive_sha256: String,
    },
}
fn encode_chunk(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(TABLE[(a >> 2) as usize] as char);
        encoded.push(TABLE[((a & 3) << 4 | b >> 4) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((b & 15) << 2 | c >> 6) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}
fn decode_chunk(encoded: &str) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() > (CHUNK + 2) / 3 * 4 || encoded.len() % 4 != 0 {
        return Err("history chunk encoding exceeds bounds".into());
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 4 * 3);
    for (index, chunk) in encoded.as_bytes().chunks_exact(4).enumerate() {
        let padding = if chunk[2] == b'=' {
            2
        } else {
            usize::from(chunk[3] == b'=')
        };
        let mut values = [0u8; 4];
        for at in 0..4 {
            values[at] = match chunk[at] {
                b'A'..=b'Z' => chunk[at] - b'A',
                b'a'..=b'z' => chunk[at] - b'a' + 26,
                b'0'..=b'9' => chunk[at] - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if at >= 4 - padding && index == encoded.len() / 4 - 1 => 0,
                _ => return Err("invalid history base64 chunk".into()),
            };
        }
        bytes.push(values[0] << 2 | values[1] >> 4);
        if padding < 2 {
            bytes.push(values[1] << 4 | values[2] >> 2);
        }
        if padding == 0 {
            bytes.push(values[2] << 6 | values[3]);
        }
    }
    if bytes.len() > CHUNK || encode_chunk(&bytes) != encoded {
        return Err("noncanonical history base64 chunk".into());
    }
    Ok(bytes)
}
fn write_record(writer: &mut impl Write, digest: &mut Sha256, record: &Record) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    writer.write_all(PREFIX.as_bytes())?;
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    digest.update(PREFIX.as_bytes());
    digest.update(&bytes);
    digest.update(b"\n");
    Ok(())
}
fn export(
    tree: &Tree,
    writer: &mut impl Write,
    mut check: impl FnMut() -> Result<()>,
) -> Result<String> {
    tree.recheck(false)?;
    let mut digest = Sha256::new();
    check()?;
    tree.recheck_namespace(false)?;
    write_record(
        writer,
        &mut digest,
        &Record::Begin {
            manifest: tree.manifest.clone(),
        },
    )?;
    for (index, member) in tree.manifest.members.iter().enumerate() {
        check()?;
        tree.recheck_namespace(false)?;
        let bytes = tree.bytes(member)?;
        write_record(writer, &mut digest, &Record::Member { index })?;
        for (chunk_index, chunk) in bytes.chunks(CHUNK).enumerate() {
            check()?;
            tree.recheck_namespace(false)?;
            write_record(
                writer,
                &mut digest,
                &Record::Chunk {
                    index,
                    offset: (chunk_index * CHUNK) as u64,
                    base64: encode_chunk(chunk),
                },
            )?;
            writer.flush()?;
            check()?;
            tree.recheck_namespace(false)?;
        }
        write_record(writer, &mut digest, &Record::EndMember { index })?;
    }
    tree.recheck(false)?;
    check()?;
    tree.recheck_namespace(false)?;
    let archive = crate::bundle::hex(&digest.finalize());
    writer.write_all(PREFIX.as_bytes())?;
    writer.write_all(&serde_json::to_vec(&Record::Complete {
        archive_sha256: archive.clone(),
    })?)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    check()?;
    Ok(archive)
}
fn canonical_generation(value: &str) -> Result<u64> {
    let value_parsed = value.parse::<u64>()?;
    if value_parsed == 0 || value_parsed.to_string() != value {
        return Err("history generation must be canonical and nonzero".into());
    }
    Ok(value_parsed)
}
fn canonical_grace(value: &str) -> Result<u64> {
    let seconds = value.parse::<u64>()?;
    if seconds.to_string() != value || !(3600..=30 * 86400).contains(&seconds) {
        return Err("history grace must be canonical one hour to thirty days".into());
    }
    Ok(seconds)
}
fn mark_review(manifest: &Manifest, exported: &Export, seconds: u64) -> Result<String> {
    manifest.validate()?;
    if !(3600..=30 * 86400).contains(&seconds)
        || exported.manifest_sha256 != hash(manifest)?
        || !io::hash(&exported.archive_sha256)
        || !operation_id(&exported.operation_id)
    {
        return Err("history grace intent lacks exact completed export evidence".into());
    }
    hash(&("luma-history-mark-v1", manifest, exported, seconds))
}
fn mark_usage(manifest: &Manifest, exported: &Export, seconds: u64) -> Result<Use> {
    let mut usage = manifest.usage(Action::Retain)?;
    usage.selector.digest = mark_review(manifest, exported, seconds)?;
    usage.validate()?;
    Ok(usage)
}
fn check(
    boundary: &mut crate::admin_governance::GrantBoundary<'_>,
    principal: &str,
    generation: u64,
) -> Result<()> {
    boundary.authorize_history_owner(principal, generation)
}
fn delete_review(state: &State, present: &[String]) -> Result<String> {
    hash(&("luma-history-delete-v1", state, present))
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let (domain_index, principal_index, generation_index) = match args.first().map(String::as_str) {
        Some("workflow-history-inspection-review") => (2, 3, 4),
        Some(
            "workflow-history-proposal"
            | "workflow-history-mark-proposal"
            | "workflow-history-delete-proposal"
            | "workflow-history-staging-proposal",
        ) => (3, 4, 5),
        Some(
            "workflow-history-export"
            | "workflow-history-mark"
            | "workflow-history-delete"
            | "workflow-history-staging-discard",
        ) => (4, 5, 6),
        _ => return Err("unsupported typed workflow history command".into()),
    };
    if args.len() <= generation_index {
        return Err("history needs LOGIN, exact grants, TYPE PRINCIPAL GENERATION and reviewed action fields".into());
    }
    let domain = Domain::parse(&args[domain_index])?;
    let principal = &args[principal_index];
    let generation = canonical_generation(&args[generation_index])?;
    owner(principal, generation)?;
    let installation = io::installation()?;
    let read = inspection(&installation, domain, principal, generation)?;
    if args[0] == "workflow-history-inspection-review" {
        if args.len() != 5 {
            return Err(
                "expected workflow-history-inspection-review LOGIN TYPE PRINCIPAL GENERATION"
                    .into(),
            );
        }
        println!(
            "{}",
            serde_json::json!({"usage":read,"grant_issued":false,"private_history_read":false})
        );
        return Ok(());
    }
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &read, |reader| {
        check(reader, principal, generation)?;
        let mut ledger = Ledger::open(domain, principal)?;
        if !matches!(
            args[0].as_str(),
            "workflow-history-staging-proposal" | "workflow-history-staging-discard"
        ) {
            ledger.require_clean()?;
        }
        match args[0].as_str() {
            "workflow-history-staging-proposal" if args.len() == 6 => {
                let stage = ledger.staging(generation)?;
                check(reader, principal, generation)?;
                ledger.recheck()?;
                if ledger.staging(generation)? != stage {
                    return Err("history staging changed during governed review".into());
                }
                Ok(
                    serde_json::json!({"staging":stage,"review_sha256":hash(&stage)?,"retain":staging_usage(&stage)?,"published_state_changed":false,"adopted":false,"discarded":false}),
                )
            }
            "workflow-history-staging-discard" if args.len() == 8 => {
                let stage = ledger.staging(generation)?;
                if hash(&stage)? != args[7] {
                    return Err(
                        "history staging review changed; preserve exact unpublished bytes".into(),
                    );
                }
                let usage = staging_usage(&stage)?;
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    check(reader, principal, generation)?;
                    check(boundary, principal, generation)?;
                    let pending = boundary.effect_begin(
                        "history-staging-discard",
                        crate::policy_decisions::EffectKind::Retention,
                    )?;
                    ledger.discard_staging(&stage, || {
                        check(reader, principal, generation)?;
                        check(boundary, principal, generation)
                    })?;
                    boundary.effect_complete(
                        pending,
                        &hash(&("unpublished-staging-discard-v1", &stage))?,
                    )?;
                    Ok(
                        serde_json::json!({"discarded":true,"review_sha256":hash(&stage)?,"published_state_changed":false,"adopted":false}),
                    )
                })
            }
            "workflow-history-proposal" if args.len() == 6 => {
                if let Some(mark) = &ledger.state.mark {
                    check(reader, principal, generation)?;
                    return Ok(
                        serde_json::json!({"mark":mark,"current_epoch":ledger.state.epoch,
                        "namespace_fenced":true,"deletion_started":ledger.state.deleting,"receipt_is_authority":false}),
                    );
                }
                let parent = scoped_read::open_directory(Path::new(domain.directory()))?;
                if !io::names(&parent, 2048)?.contains(&domain.name(principal)) {
                    check(reader, principal, generation)?;
                    return Ok(
                        serde_json::json!({"domain_absent":true,"current_epoch":ledger.state.epoch,
                        "retirement":ledger.state.last,"old_requests_fenced":ledger.state.epoch>0,"receipt_is_authority":false}),
                    );
                }
                let tree = current_tree(&ledger, generation)?;
                check(reader, principal, generation)?;
                Ok(
                    serde_json::json!({"manifest":tree.manifest,"review_sha256":hash(&tree.manifest)?,"export":tree.manifest.usage(Action::Export)?,
                    "current_epoch":ledger.state.epoch,"content_deleted":false,"grant_issued":false}),
                )
            }
            "workflow-history-export" if args.len() == 8 => {
                let tree = current_tree(&ledger, generation)?;
                if args[7] != hash(&tree.manifest)? {
                    return Err("history export review changed".into());
                }
                let usage = tree.manifest.usage(Action::Export)?;
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    check(reader, principal, generation)?;
                    check(boundary, principal, generation)?;
                    let pending = boundary.effect_begin(
                        "workflow-history-export",
                        crate::policy_decisions::EffectKind::ArtifactExport,
                    )?;
                    let mut writer = crate::service::granted_gateway::export_writer()?;
                    let archive = export(&tree, &mut writer, || {
                        reader.stream_history_owner(&pending, principal, generation)?;
                        boundary.stream_history_owner(&pending, principal, generation)?;
                        ledger.recheck()
                    })?;
                    let exported = Export {
                        manifest_sha256: hash(&tree.manifest)?,
                        archive_sha256: archive,
                        operation_id: boundary.operation_id().into(),
                    };
                    let mut next = ledger.state.clone();
                    next.export = Some(exported.clone());
                    ledger.save(next, || {
                        check(reader, principal, generation)?;
                        tree.recheck(false)?;
                        check(boundary, principal, generation)
                    })?;
                    boundary.effect_complete(pending, &hash(&exported)?)?;
                    Ok(
                        serde_json::json!({"export":exported,"content_deleted":false,"receipt_is_authority":false}),
                    )
                })
            }
            "workflow-history-mark-proposal" if args.len() == 8 => {
                let tree = current_tree(&ledger, generation)?;
                let exported = ledger
                    .state
                    .export
                    .as_ref()
                    .ok_or("history retirement requires a completed explicit export")?;
                if exported.archive_sha256 != args[6] {
                    return Err("history export custody acknowledgement differs".into());
                }
                let seconds = canonical_grace(&args[7])?;
                let usage = mark_usage(&tree.manifest, exported, seconds)?;
                check(reader, principal, generation)?;
                Ok(
                    serde_json::json!({"manifest":tree.manifest,"export":exported,"grace_seconds":seconds,"review_sha256":usage.selector.digest,"retain":usage,"namespace_fenced":false,"content_deleted":false,"grant_issued":false}),
                )
            }
            "workflow-history-mark" if args.len() == 10 => {
                let tree = current_tree(&ledger, generation)?;
                let exported = ledger
                    .state
                    .export
                    .clone()
                    .ok_or("history retirement requires a completed explicit export")?;
                if exported.manifest_sha256 != hash(&tree.manifest)?
                    || exported.archive_sha256 != args[7]
                {
                    return Err("history export custody acknowledgement differs from the exact current archive".into());
                }
                let seconds = canonical_grace(&args[8])?;
                let usage = mark_usage(&tree.manifest, &exported, seconds)?;
                if args[9] != usage.selector.digest {
                    return Err("history grace/proof mark review changed".into());
                }
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    check(reader, principal, generation)?;
                    check(boundary, principal, generation)?;
                    tree.recheck(false)?;
                    let pending = boundary.effect_begin(
                        "workflow-history-mark",
                        crate::policy_decisions::EffectKind::Retention,
                    )?;
                    let (_, upper) = boundary.observation()?.interval().endpoints();
                    let mark = Mark {
                        manifest: tree.manifest.clone(),
                        export: exported,
                        grace_seconds: seconds,
                        marked_upper_ms: upper,
                        operation_id: boundary.operation_id().into(),
                    };
                    mark.deadline()?;
                    let mut next = ledger.state.clone();
                    next.mark = Some(mark.clone());
                    ledger.save(next, || {
                        tree.recheck(false)?;
                        check(boundary, principal, generation)
                    })?;
                    boundary.effect_complete(pending, &hash(&mark)?)?;
                    Ok(
                        serde_json::json!({"mark":mark,"namespace_fenced":true,"content_deleted":false}),
                    )
                })
            }
            "workflow-history-delete-proposal" if args.len() == 6 => {
                let mark = ledger
                    .state
                    .mark
                    .as_ref()
                    .ok_or("history has no reviewed grace mark")?;
                if mark.manifest.generation > generation {
                    return Err("marked history generation exceeds current retirement actor".into());
                }
                let tree = Tree::marked(mark, ledger.state.deleting)?;
                let present = tree
                    .as_ref()
                    .map(|tree| tree.recheck(ledger.state.deleting))
                    .transpose()?
                    .unwrap_or_default();
                check(reader, principal, generation)?;
                Ok(
                    serde_json::json!({"review_sha256":delete_review(&ledger.state,&present)?,"delete":mark.manifest.usage(Action::Delete)?,
                    "deadline_ms":mark.deadline()?,"remaining":present,"current_epoch":ledger.state.epoch,"content_deleted":false}),
                )
            }
            "workflow-history-delete" if args.len() == 8 => {
                let mark = ledger
                    .state
                    .mark
                    .clone()
                    .ok_or("history has no reviewed grace mark")?;
                if mark.manifest.generation > generation {
                    return Err("marked history generation exceeds current retirement actor".into());
                }
                let tree = Tree::marked(&mark, ledger.state.deleting)?;
                let present = tree
                    .as_ref()
                    .map(|tree| tree.recheck(ledger.state.deleting))
                    .transpose()?
                    .unwrap_or_default();
                if delete_review(&ledger.state, &present)? != args[7] {
                    return Err(
                        "history deletion review changed; explicitly inspect any partial outcome"
                            .into(),
                    );
                }
                let usage = mark.manifest.usage(Action::Delete)?;
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    let mut authorize =
                        |boundary: &mut crate::admin_governance::GrantBoundary<'_>| -> Result<()> {
                            check(reader, principal, generation)?;
                            check(boundary, principal, generation)?;
                            let (lower, _) = boundary.observation()?.interval().endpoints();
                            if lower < mark.deadline()? {
                                return Err(
                                "history deletion grace has not fully elapsed under protected UTC"
                                    .into(),
                            );
                            }
                            Ok(())
                        };
                    authorize(boundary)?;
                    if let Some(tree) = &tree {
                        tree.recheck(ledger.state.deleting)?;
                    }
                    let pending = boundary.effect_begin(
                        "workflow-history-delete",
                        crate::policy_decisions::EffectKind::Deletion,
                    )?;
                    if !ledger.state.deleting {
                        let mut next = ledger.state.clone();
                        next.deleting = true;
                        ledger.save(next, || authorize(boundary))?;
                    }
                    if let Some(tree) = &tree {
                        tree.remove_members(|| authorize(boundary))?;
                        tree.remove_directories(|| authorize(boundary))?;
                    } else {
                        authorize(boundary)?;
                        let absent = Absence::at(&mark.manifest, &domain.path(principal))?;
                        absent.parent.sync_all()?;
                        absent.recheck()?;
                    }
                    let absent = Absence::at(&mark.manifest, &domain.path(principal))?;
                    let tombstone = Tombstone {
                        epoch: ledger.state.epoch,
                        manifest_sha256: hash(&mark.manifest)?,
                        export: mark.export.clone(),
                        mark_sha256: hash(&mark)?,
                        operation_id: boundary.operation_id().into(),
                        previous_receipt_sha256: ledger
                            .state
                            .last
                            .as_ref()
                            .map(hash)
                            .transpose()?
                            .unwrap_or_default(),
                    };
                    let mut next = ledger.state.clone();
                    next.epoch = next.epoch.checked_add(1).ok_or("history epoch exhausted")?;
                    next.last = Some(tombstone.clone());
                    next.export = None;
                    next.mark = None;
                    next.deleting = false;
                    ledger.save(next, || {
                        authorize(boundary)?;
                        absent.recheck()
                    })?;
                    boundary.effect_complete(pending, &hash(&tombstone)?)?;
                    absent.recheck()?;
                    Ok(
                        serde_json::json!({"retirement":tombstone,"next_epoch":ledger.state.epoch,"artifact_catalog_preserved":true,"external_sources_preserved":true,"old_requests_fenced":true}),
                    )
                })
            }
            _ => Err("invalid typed history action argument shape".into()),
        }
    })?;
    if args[0] == "workflow-history-export" {
        eprintln!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{result}");
    }
    Ok(())
}

fn bounded_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("truncated history archive line".into())
            };
        }
        let count = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if bytes.len() + count > MAX_STATE as usize + 1024 {
            return Err("oversized history archive line".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return Ok(Some(bytes));
        }
    }
}
pub(crate) fn archive_verify(path: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ARCHIVE {
        return Err("history archive must be bounded regular local evidence".into());
    }
    let result = verify(&mut std::io::BufReader::new(file))?;
    println!(
        "{}",
        serde_json::json!({"archive_sha256":result,"integrity_verified":true,"restored":false,"authority":false})
    );
    Ok(())
}
fn verify(reader: &mut impl BufRead) -> Result<String> {
    let mut digest = Sha256::new();
    let mut manifest: Option<Manifest> = None;
    let mut index = 0usize;
    let mut current: Option<(u64, Sha256)> = None;
    let mut complete = None;
    let mut bytes = 0u64;
    while let Some(line) = bounded_line(reader)? {
        bytes += line.len() as u64 + 1;
        if bytes > MAX_ARCHIVE {
            return Err("history archive capacity exceeded".into());
        }
        // Fixed PTY authentication may add non-archive status lines. Only this
        // exact prefixed, canonical closed framing participates in the digest.
        let Some(encoded) = line.strip_prefix(PREFIX.as_bytes()) else {
            continue;
        };
        if complete.is_some() {
            return Err("history archive has records after its completion".into());
        }
        let record: Record = serde_json::from_slice(encoded)?;
        if serde_json::to_vec(&record)? != encoded {
            return Err("noncanonical history archive record".into());
        }
        match &record {
            Record::Begin { manifest: value } => {
                if manifest.is_some() {
                    return Err("duplicate archive manifest".into());
                }
                value.validate()?;
                manifest = Some(value.clone());
            }
            Record::Member { index: requested } => {
                if manifest.is_none()
                    || current.is_some()
                    || *requested != index
                    || index >= manifest.as_ref().unwrap().members.len()
                {
                    return Err("archive member order differs".into());
                }
                current = Some((0, Sha256::new()));
            }
            Record::Chunk {
                index: requested,
                offset,
                base64,
            } => {
                let (count, member_hash) =
                    current.as_mut().ok_or("archive chunk lacks its member")?;
                if *requested != index || *offset != *count {
                    return Err("archive chunk bounds differ".into());
                }
                let content = decode_chunk(base64)?;
                *count = count
                    .checked_add(content.len() as u64)
                    .ok_or("archive member size overflow")?;
                if *count
                    > manifest.as_ref().ok_or("archive manifest missing")?.members[index].bytes
                {
                    return Err("archive member grew".into());
                }
                member_hash.update(&content);
            }
            Record::EndMember { index: requested } => {
                let (count, member_hash) = current.take().ok_or("archive member end missing")?;
                let member = &manifest.as_ref().ok_or("archive manifest missing")?.members[index];
                if *requested != index
                    || count != member.bytes
                    || crate::bundle::hex(&member_hash.finalize()) != member.sha256
                {
                    return Err("archive member integrity differs".into());
                }
                index += 1;
            }
            Record::Complete { archive_sha256 } => {
                if current.is_some()
                    || manifest
                        .as_ref()
                        .map_or(true, |manifest| index != manifest.members.len())
                    || archive_sha256 != &crate::bundle::hex(&digest.clone().finalize())
                {
                    return Err("archive completion digest differs".into());
                }
                complete = Some(archive_sha256.clone());
                continue;
            }
        }
        digest.update(PREFIX.as_bytes());
        digest.update(encoded);
        digest.update(b"\n");
    }
    complete.ok_or_else(|| "history archive is incomplete and cannot justify retirement".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Fixture {
        parent: PathBuf,
        path: PathBuf,
        tree: Option<Tree>,
    }
    impl Fixture {
        fn new(label: &str) -> Self {
            let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("history tests require the isolated private ext4 test volume");
            let parent =
                Path::new(&base).join(format!("luma-history-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
            let path = parent.join("a".repeat(64));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let root = scoped_read::open_directory(&path).unwrap();
            let objects = io::mkdir_at(&root, "objects").unwrap();
            let pending = io::mkdir_at(&root, "pending").unwrap();
            // Physical disposition/archive fixture, deliberately not an actual
            // SQLite/PAM/TPM/UTC admission or a production terminal-run proof.
            io::write_member(
                &root,
                "metadata.sqlite3",
                b"synthetic persistence fixture",
                0o600,
            )
            .unwrap();
            let bytes = b"value\n";
            let name = io::digest(bytes);
            io::write_member(&objects, &name, bytes, 0o400).unwrap();
            let mut members = Vec::new();
            for (area, directory, name) in [
                ("root", &root, "metadata.sqlite3"),
                ("objects", &objects, name.as_str()),
            ] {
                let content = io::read_member(directory, name, MAX_FILE).unwrap();
                let meta = io::open_at(directory, name, libc::O_RDONLY, 0)
                    .unwrap()
                    .metadata()
                    .unwrap();
                members.push(Member {
                    area: area.into(),
                    name: name.into(),
                    device: meta.dev(),
                    inode: meta.ino(),
                    incarnation: Incarnation::capture(
                        &io::open_at(directory, name, libc::O_RDONLY, 0).unwrap(),
                    )
                    .unwrap(),
                    bytes: meta.len(),
                    mode: meta.mode() & 0o7777,
                    sha256: io::digest(&content),
                });
            }
            let manifest = Manifest {
                schema_version: 2,
                installation: "b".repeat(64),
                domain: Domain::Dag,
                principal: "a".repeat(64),
                generation: 2,
                epoch: 0,
                root: scoped_read::identity(&root).unwrap(),
                parent: scoped_read::identity(&scoped_read::open_directory(&parent).unwrap())
                    .unwrap(),
                objects: scoped_read::identity(&objects).unwrap(),
                pending: scoped_read::identity(&pending).unwrap(),
                root_incarnation: Incarnation::capture(&root).unwrap(),
                parent_incarnation: Incarnation::capture(
                    &scoped_read::open_directory(&parent).unwrap(),
                )
                .unwrap(),
                objects_incarnation: Incarnation::capture(&objects).unwrap(),
                pending_incarnation: Incarnation::capture(&pending).unwrap(),
                pending_disposition: "unpublished_opaque_archive_only".into(),
                semantic_sha256: "c".repeat(64),
                runs: 1,
                members,
                previous_retirement: String::new(),
            };
            manifest.validate().unwrap();
            let tree = Tree {
                parent_path: parent.clone(),
                root,
                objects: Some(objects),
                pending: Some(pending),
                parent: scoped_read::open_directory(&parent).unwrap(),
                name: "a".repeat(64),
                manifest,
            };
            Self {
                parent,
                path,
                tree: Some(tree),
            }
        }
        fn mark(&self) -> Mark {
            let manifest = self.tree.as_ref().unwrap().manifest.clone();
            Mark {
                export: Export {
                    manifest_sha256: hash(&manifest).unwrap(),
                    archive_sha256: "d".repeat(64),
                    operation_id: "e".repeat(32),
                },
                manifest,
                grace_seconds: 3600,
                marked_upper_ms: 10_000,
                operation_id: "f".repeat(32),
            }
        }
        fn unpublished(&mut self, name: &str, bytes: &[u8]) {
            let tree = self.tree.as_mut().unwrap();
            let pending = tree.pending.as_ref().unwrap();
            io::write_member(pending, name, bytes, 0o400).unwrap();
            let file = io::open_at(pending, name, libc::O_RDONLY, 0).unwrap();
            let meta = file.metadata().unwrap();
            tree.manifest.members.push(Member {
                area: "pending".into(),
                name: name.into(),
                device: meta.dev(),
                inode: meta.ino(),
                incarnation: Incarnation::capture(&file).unwrap(),
                bytes: meta.len(),
                mode: meta.mode() & 0o7777,
                sha256: io::digest(bytes),
            });
            tree.manifest.validate().unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.tree = None;
            fs::remove_dir_all(&self.parent).unwrap();
        }
    }

    #[test]
    fn unpublished_partial_and_empty_bytes_are_archived_exactly_not_adopted_from_their_names() {
        let mut fixture = Fixture::new("opaque-pending");
        fixture.unpublished(&"1".repeat(64), b"interrupted unpublished bytes");
        fixture.unpublished(&"2".repeat(64), b"");
        let tree = fixture.tree.as_ref().unwrap();
        let pending_members: Vec<_> = tree
            .manifest
            .members
            .iter()
            .filter(|member| member.area == "pending")
            .collect();
        assert_eq!(pending_members.len(), 2);
        assert!(pending_members
            .iter()
            .all(|member| member.name != member.sha256));
        assert_eq!(tree.bytes(pending_members[1]).unwrap(), b"");
        let mut archive = Vec::new();
        let receipt = export(tree, &mut archive, || Ok(())).unwrap();
        assert_eq!(
            verify(&mut std::io::Cursor::new(&archive)).unwrap(),
            receipt
        );
        assert_eq!(
            tree.bytes(pending_members[0]).unwrap(),
            b"interrupted unpublished bytes"
        );
        let mark = fixture.mark();
        assert_eq!(
            mark.manifest.pending_disposition,
            "unpublished_opaque_archive_only"
        );
        assert!(tree
            .remove_members(|| Err("retention custody withdrawn".into()))
            .is_err());
        assert_eq!(
            tree.bytes(pending_members[0]).unwrap(),
            b"interrupted unpublished bytes"
        );
        tree.remove_members(|| Ok(())).unwrap();
        assert!(tree.recheck(false).is_err());
        tree.recheck(true).unwrap();
        tree.remove_directories(|| Ok(())).unwrap();
        fixture.tree = None;
        assert!(!fixture.path.exists());
    }

    #[test]
    fn zero_run_pending_disposition_is_explicit_and_bound_to_exact_archive_and_grace() {
        let mut fixture = Fixture::new("zero-run");
        let mut empty = fixture.tree.as_ref().unwrap().manifest.clone();
        empty.runs = 0;
        assert!(empty.validate().is_err());
        fixture.unpublished(&"3".repeat(64), b"");
        let tree = fixture.tree.as_mut().unwrap();
        tree.manifest.runs = 0;
        tree.manifest.validate().unwrap();
        let mut archive = Vec::new();
        let receipt = export(tree, &mut archive, || Ok(())).unwrap();
        assert_eq!(
            verify(&mut std::io::Cursor::new(&archive)).unwrap(),
            receipt
        );
        let mark = fixture.mark();
        let review = mark_review(&mark.manifest, &mark.export, 3600).unwrap();
        let mut changed = mark.manifest.clone();
        changed.pending_disposition = "published".into();
        assert!(changed.validate().is_err());
        changed = mark.manifest.clone();
        changed.members.last_mut().unwrap().sha256 = "4".repeat(64);
        assert!(mark_review(&changed, &mark.export, 3600).is_err());
        assert_ne!(
            review,
            mark_review(&mark.manifest, &mark.export, 3601).unwrap()
        );
    }

    #[test]
    fn objects_and_opaque_pending_share_closed_count_and_raw_byte_quotas() {
        let mut fixture = Fixture::new("pending-quota");
        fixture.unpublished(&"5".repeat(64), b"");
        let manifest = &fixture.tree.as_ref().unwrap().manifest;
        let seed = manifest
            .members
            .iter()
            .find(|member| member.area == "pending")
            .unwrap()
            .clone();
        let mut count = manifest.clone();
        for index in 0..1023 {
            let mut member = seed.clone();
            member.name = format!("{index:064x}");
            count.members.push(member);
        }
        assert!(count.validate().is_err());
        let mut quota = manifest.clone();
        for index in 0..64 {
            let mut member = seed.clone();
            member.name = format!("{index:064x}");
            member.bytes = 2 * 1024 * 1024;
            quota.members.push(member);
        }
        assert!(quota.validate().is_err());
        quota.domain = Domain::Invoice;
        assert!(quota.validate().is_err());
        let mut raw = manifest.clone();
        for index in 0..63 {
            let mut member = seed.clone();
            member.name = format!("{index:064x}");
            member.bytes = 2 * 1024 * 1024;
            raw.members.push(member);
        }
        for name in ["metadata.sqlite3-wal", "metadata.sqlite3-shm"] {
            let mut member = raw.members[0].clone();
            member.name = name.into();
            member.bytes = MAX_FILE;
            raw.members.push(member);
        }
        assert!(raw.validate().is_err());
    }

    #[test]
    fn canonical_base64_chunks_and_full_quota_framing_fit_the_authenticated_transport() {
        for length in [1, 2, 3, 4, CHUNK - 1, CHUNK] {
            let bytes: Vec<u8> = (0..length).map(|at| (at % 251) as u8).collect();
            let encoded = encode_chunk(&bytes);
            assert_eq!(decode_chunk(&encoded).unwrap(), bytes);
        }
        for invalid in [
            "", "YQ=", "YQ===", "YQ==\n", "YR==", "YWJ=", "YQ==YQ==", "====", "-A==",
        ] {
            assert!(decode_chunk(invalid).is_err(), "{invalid}");
        }
        assert!(decode_chunk(&encode_chunk(&vec![0; CHUNK + 1])).is_err());
        let chunks = (MAX_RAW + CHUNK as u64 - 1) / (CHUNK as u64) + MAX_FILES as u64;
        // At most four encoding bytes per three source bytes, per-file padding,
        // one bounded manifest and conservatively 1KiB framing per record.
        let worst = (MAX_RAW + 2) / 3 * 4
            + MAX_FILES as u64 * 4
            + MAX_STATE
            + (chunks + 2 * MAX_FILES as u64 + 2) * 1024;
        assert!(worst < MAX_ARCHIVE);
        assert!(128 * 1024 * 1024 + 32 * 1024 * 1024 < MAX_RAW);
    }

    #[test]
    fn grace_review_and_finite_retention_bind_exact_export_operation_and_duration() {
        let fixture = Fixture::new("mark-intent");
        let mark = fixture.mark();
        let baseline = mark_usage(&mark.manifest, &mark.export, 3600).unwrap();
        assert_eq!(
            baseline.selector.digest,
            mark_review(&mark.manifest, &mark.export, 3600).unwrap()
        );
        assert_ne!(
            baseline.selector.digest,
            mark_usage(&mark.manifest, &mark.export, 3601)
                .unwrap()
                .selector
                .digest
        );
        let mut another = mark.export.clone();
        another.archive_sha256 = "1".repeat(64);
        assert_ne!(
            baseline.selector.digest,
            mark_usage(&mark.manifest, &another, 3600)
                .unwrap()
                .selector
                .digest
        );
        another = mark.export.clone();
        another.operation_id = "2".repeat(32);
        assert_ne!(
            baseline.selector.digest,
            mark_usage(&mark.manifest, &another, 3600)
                .unwrap()
                .selector
                .digest
        );
        another.manifest_sha256 = "3".repeat(64);
        assert!(mark_usage(&mark.manifest, &another, 3600).is_err());
        assert!(mark_usage(&mark.manifest, &mark.export, 3599).is_err());
    }

    #[test]
    fn streamed_archive_verifies_every_exact_file_and_refuses_corruption_truncation_and_extra_records(
    ) {
        let fixture = Fixture::new("archive");
        let tree = fixture.tree.as_ref().unwrap();
        let mut bytes = Vec::new();
        let checks = Cell::new(0);
        let expected = export(tree, &mut bytes, || {
            checks.set(checks.get() + 1);
            Ok(())
        })
        .unwrap();
        assert!(checks.get() > tree.manifest.members.len());
        assert_eq!(verify(&mut std::io::Cursor::new(&bytes)).unwrap(), expected);
        let mut pty = Vec::new();
        pty.extend_from_slice(b"PAM status outside payload\n");
        for byte in &bytes {
            if *byte == b'\n' {
                pty.push(b'\r');
            }
            pty.push(*byte);
        }
        assert_eq!(verify(&mut std::io::Cursor::new(&pty)).unwrap(), expected);
        let mut changed = bytes.clone();
        let offset = changed
            .windows(8)
            .position(|part| part == b"dmFsdWUK")
            .unwrap();
        changed[offset] = b'f';
        assert!(verify(&mut std::io::Cursor::new(changed)).is_err());
        let last = bytes[..bytes.len() - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap();
        assert!(verify(&mut std::io::Cursor::new(&bytes[..last + 1])).is_err());
        let mut extra = bytes.clone();
        extra.extend_from_slice(b"LUMA-WORKFLOW-HISTORY {\"record\":\"member\",\"index\":0}\n");
        assert!(verify(&mut std::io::Cursor::new(extra)).is_err());
        assert!(verify(&mut std::io::Cursor::new(
            b"LUMA-WORKFLOW-HISTORY {\"record\":\"member\",\"index\":0,\"authority\":true}\n"
        ))
        .is_err());
        assert!(verify(&mut std::io::Cursor::new(vec![
            b'x';
            MAX_STATE as usize + 1025
        ]))
        .is_err());
    }
    #[test]
    fn history_deletion_retains_exact_partial_files_and_handles_each_directory_boundary_without_adoption(
    ) {
        let mut fixture = Fixture::new("partial");
        let mark = fixture.mark();
        let tree = fixture.tree.as_ref().unwrap();
        assert!(tree
            .remove_members(|| Err("revoked before unlink".into()))
            .is_err());
        assert!(tree.recheck(false).is_ok());
        let calls = Cell::new(0);
        assert!(tree
            .remove_members(|| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("lost authorization after one unlink".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(tree.recheck(false).is_err());
        let progress = tree.recheck(true).unwrap();
        assert!(progress.len() < mark.manifest.members.len() + 3);
        tree.remove_members(|| Ok(())).unwrap();
        let calls = Cell::new(0);
        assert!(tree
            .remove_directories(|| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("lost acknowledgement after object directory removal".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        fixture.tree = None;
        let resumed = Tree::marked_at(&mark, &fixture.path, true)
            .unwrap()
            .unwrap();
        assert!(resumed.objects.is_none());
        assert!(resumed.pending.is_some());
        assert!(resumed.recheck(true).is_ok());
        assert!(Tree::marked_at(&mark, &fixture.path, false).is_err());
        resumed.remove_members(|| Ok(())).unwrap();
        resumed.remove_directories(|| Ok(())).unwrap();
        drop(resumed);
        assert!(Tree::marked_at(&mark, &fixture.path, true)
            .unwrap()
            .is_none());
        assert!(Tree::marked_at(&mark, &fixture.path, false).is_err());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.path)
            .unwrap();
        let new_root = scoped_read::open_directory(&fixture.path).unwrap();
        io::mkdir_at(&new_root, "objects").unwrap();
        io::mkdir_at(&new_root, "pending").unwrap();
        let substituted = Tree::marked_at(&mark, &fixture.path, true)
            .unwrap()
            .unwrap();
        assert!(substituted.recheck(true).is_err());
    }
    #[test]
    fn durable_tombstone_advances_epoch_only_after_exact_export_and_preserves_old_receipt_chain() {
        let fixture = Fixture::new("epochs");
        let mark = fixture.mark();
        let ledger_path = fixture.parent.join("ledger");
        initialize_at(&ledger_path, &mark.manifest.installation).unwrap();
        let tree = fixture.tree.as_ref().unwrap();
        let content: Vec<Vec<u8>> = tree
            .manifest
            .members
            .iter()
            .map(|member| tree.bytes(member).unwrap())
            .collect();
        let mut ledger = Ledger::at(
            &ledger_path,
            &mark.manifest.installation,
            Domain::Dag,
            &mark.manifest.principal,
        )
        .unwrap();
        assert_eq!(admitted_epoch(&ledger.state).unwrap(), 0);
        let mut marked = ledger.state.clone();
        marked.export = Some(mark.export.clone());
        marked.mark = Some(mark.clone());
        assert!(ledger
            .save(marked.clone(), || Err("revoked".into()))
            .is_err());
        assert!(ledger.state.mark.is_none());
        ledger.save(marked, || Ok(())).unwrap();
        let bytes = fs::read(&ledger.path).unwrap();
        assert_eq!(
            serde_json::from_slice::<State>(&bytes).unwrap(),
            ledger.state
        );
        assert!(admitted_epoch(&ledger.state).is_err());
        for (member, expected) in tree.manifest.members.iter().zip(&content) {
            assert_eq!(&tree.bytes(member).unwrap(), expected);
        }
        let mut broken = ledger.state.clone();
        broken.mark.as_mut().unwrap().export.archive_sha256 = "0".repeat(64);
        assert!(broken.validate().is_err());
        let retired = Tombstone {
            epoch: 0,
            manifest_sha256: hash(&mark.manifest).unwrap(),
            export: mark.export.clone(),
            mark_sha256: hash(&mark).unwrap(),
            operation_id: "1".repeat(32),
            previous_receipt_sha256: String::new(),
        };
        let mut next = ledger.state.clone();
        next.epoch = 1;
        next.last = Some(retired.clone());
        next.mark = None;
        next.export = None;
        next.deleting = false;
        ledger.save(next, || Ok(())).unwrap();
        drop(ledger);
        let restored = Ledger::at(
            &ledger_path,
            &mark.manifest.installation,
            Domain::Dag,
            &mark.manifest.principal,
        )
        .unwrap();
        assert_eq!(admitted_epoch(&restored.state).unwrap(), 1);
        assert_eq!(restored.state.last, Some(retired));
        let mut missing = restored.state.clone();
        missing.last = None;
        assert!(missing.validate().is_err());
        assert_eq!(epoch_argument("0").unwrap(), None);
        assert_eq!(epoch_argument("1").unwrap(), Some(1));
        assert!(epoch_argument("01").is_err());
        assert!(epoch_argument(&u64::MAX.to_string()).is_err());
        assert_eq!(mark.deadline().unwrap(), 3_610_000);
        let mut bad_grace = mark;
        bad_grace.grace_seconds = 3599;
        assert!(bad_grace.deadline().is_err());
    }
    #[test]
    fn archive_mark_and_exact_domain_removal_leave_external_sources_and_retained_artifact_bytes_unchanged(
    ) {
        // These are physical sibling-preservation fixtures, not serialized
        // catalog receipts or replacements for production completed-run proofs.
        let mut fixture = Fixture::new("sibling-preservation");
        let tree = fixture.tree.as_ref().unwrap();
        let source = fixture.parent.join("external-source.csv");
        let artifact = fixture.parent.join("retained-artifact.json");
        let parent = scoped_read::open_directory(&fixture.parent).unwrap();
        io::write_member(&parent, "external-source.csv", b"source custody\n", 0o400).unwrap();
        io::write_member(
            &parent,
            "retained-artifact.json",
            b"artifact custody\n",
            0o400,
        )
        .unwrap();
        let source_before = fs::metadata(&source).unwrap();
        let artifact_before = fs::metadata(&artifact).unwrap();
        let mut archive = Vec::new();
        export(tree, &mut archive, || Ok(())).unwrap();
        assert!(tree.recheck(false).is_ok());
        let mark = fixture.mark();
        let mut state = State::initial(
            &mark.manifest.installation,
            Domain::Dag,
            &mark.manifest.principal,
        );
        state.export = Some(mark.export.clone());
        state.mark = Some(mark);
        state.validate().unwrap();
        assert!(admitted_epoch(&state).is_err());
        tree.remove_members(|| Ok(())).unwrap();
        tree.remove_directories(|| Ok(())).unwrap();
        fixture.tree = None;
        assert!(!fixture.path.exists());
        assert_eq!(fs::read(&source).unwrap(), b"source custody\n");
        assert_eq!(fs::read(&artifact).unwrap(), b"artifact custody\n");
        assert_eq!(fs::metadata(&source).unwrap().ino(), source_before.ino());
        assert_eq!(
            fs::metadata(&artifact).unwrap().ino(),
            artifact_before.ino()
        );
    }
    #[test]
    fn identical_content_file_replacement_and_unknown_files_never_cross_a_retirement_generation() {
        let fixture = Fixture::new("replacement");
        let tree = fixture.tree.as_ref().unwrap();
        let member = &tree.manifest.members[0];
        let original = tree.bytes(member).unwrap();
        let directory = tree.file(member).unwrap();
        let name = CString::new(member.name.as_str()).unwrap();
        let retained = CString::new("prior.sqlite3").unwrap();
        assert_eq!(
            unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    directory.as_raw_fd(),
                    retained.as_ptr(),
                )
            },
            0
        );
        io::write_member(directory, &member.name, &original, member.mode).unwrap();
        assert!(tree.bytes(member).is_err());
        assert!(tree.recheck(true).is_err());
        assert!(tree.remove_members(|| Ok(())).is_err());
        assert_eq!(
            io::read_member(directory, &member.name, MAX_FILE).unwrap(),
            original
        );
    }
    #[test]
    fn authority_callback_cannot_delete_bytes_from_a_detached_domain_or_parent() {
        let fixture = Fixture::new("callback-domain-swap");
        let tree = fixture.tree.as_ref().unwrap();
        let before = tree.bytes(&tree.manifest.members[0]).unwrap();
        let prior = fixture.parent.join("prior-domain");
        assert!(tree
            .remove_members(|| {
                fs::rename(&fixture.path, &prior)?;
                fs::DirBuilder::new().mode(0o700).create(&fixture.path)?;
                Ok(())
            })
            .is_err());
        assert_eq!(tree.bytes(&tree.manifest.members[0]).unwrap(), before);
        fs::remove_dir(&fixture.path).unwrap();
        fs::rename(&prior, &fixture.path).unwrap();
        let detached = fixture.parent.with_extension("detached");
        assert!(tree
            .remove_members(|| {
                fs::rename(&fixture.parent, &detached)?;
                fs::DirBuilder::new().mode(0o700).create(&fixture.parent)?;
                Ok(())
            })
            .is_err());
        assert_eq!(tree.bytes(&tree.manifest.members[0]).unwrap(), before);
        assert!(tree.recheck(true).is_err());
        fs::remove_dir(&fixture.parent).unwrap();
        fs::rename(&detached, &fixture.parent).unwrap();
        tree.recheck(false).unwrap();
    }
    #[test]
    fn ledger_authority_callback_cannot_publish_into_a_replaced_base_namespace() {
        let fixture = Fixture::new("ledger-callback-swap");
        let base = fixture.parent.join("ledger");
        let prior = fixture.parent.join("ledger-prior");
        let installation = &fixture.tree.as_ref().unwrap().manifest.installation;
        initialize_at(&base, installation).unwrap();
        let mut ledger = Ledger::at(&base, installation, Domain::Dag, &"a".repeat(64)).unwrap();
        let state = ledger.state.clone();
        assert!(ledger
            .save(state, || {
                fs::rename(&base, &prior)?;
                initialize_at(&base, installation)?;
                Ok(())
            })
            .is_err());
        assert_eq!(
            io::names(&ledger.base, MAX_DOMAINS + 1).unwrap(),
            ["identity.json"]
        );
        assert_eq!(
            io::names(
                &scoped_read::open_directory(&base).unwrap(),
                MAX_DOMAINS + 1
            )
            .unwrap(),
            ["identity.json"]
        );
        assert!(ledger.recheck().is_err());
    }
    #[test]
    fn interrupted_ledger_publication_is_inert_bounded_staging_with_explicit_exact_disposition() {
        let fixture = Fixture::new("ledger-interrupted");
        let base = fixture.parent.join("ledger");
        let installation = &fixture.tree.as_ref().unwrap().manifest.installation;
        let principal = "a".repeat(64);
        initialize_at(&base, installation).unwrap();
        let mut ledger = Ledger::at(&base, installation, Domain::Dag, &principal).unwrap();
        let initial = ledger.state.clone();
        let calls = Cell::new(0);
        assert!(ledger
            .save(initial.clone(), || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("authorization withdrawn after staging".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(ledger.state, initial);
        drop(ledger);
        let mut ledger = Ledger::at(&base, installation, Domain::Dag, &principal).unwrap();
        assert_eq!(ledger.state, initial);
        let reviewed = ledger.staging(2).unwrap();
        assert!(ledger.require_clean().is_err());
        staging_usage(&reviewed).unwrap();
        assert!(ledger.save(initial.clone(), || Ok(())).is_err());
        let mut changed = reviewed.clone();
        changed.member.sha256 = "f".repeat(64);
        assert!(ledger.discard_staging(&changed, || Ok(())).is_err());
        assert!(ledger
            .discard_staging(&reviewed, || Err("revoked".into()))
            .is_err());
        assert_eq!(ledger.staging(2).unwrap(), reviewed);
        ledger.discard_staging(&reviewed, || Ok(())).unwrap();
        ledger.require_clean().unwrap();
        assert_eq!(ledger.state, initial);
        ledger.save(initial.clone(), || Ok(())).unwrap();
        assert!(ledger.staging(2).is_err());
        let target = hash(&(Domain::Dag, &principal)).unwrap();
        let name = format!(".new-{target}-{}", "1".repeat(32));
        io::write_member(&ledger.base, &name, b"", 0o600).unwrap();
        let empty = ledger.staging(2).unwrap();
        assert_eq!(empty.member.bytes, 0);
        assert_eq!(empty.member.sha256, io::digest(b""));
        ledger.discard_staging(&empty, || Ok(())).unwrap();
        assert_eq!(ledger.state, initial);
    }
    #[test]
    fn changed_or_replaced_staging_after_authority_never_becomes_published_state() {
        for replacement in [false, true] {
            let fixture = Fixture::new(if replacement {
                "staging-replaced"
            } else {
                "staging-mutated"
            });
            let base = fixture.parent.join("ledger");
            let installation = &fixture.tree.as_ref().unwrap().manifest.installation;
            initialize_at(&base, installation).unwrap();
            let mut ledger = Ledger::at(&base, installation, Domain::Dag, &"a".repeat(64)).unwrap();
            let original = ledger.state.clone();
            let original_bytes = serde_json::to_vec(&original).unwrap();
            let calls = Cell::new(0);
            assert!(ledger
                .save(original.clone(), || {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        let name = ledger_inventory(&scoped_read::open_directory(&base)?)?
                            .into_iter()
                            .find(|name| staging_target(name).is_some())
                            .ok_or("test stage missing")?;
                        if replacement {
                            fs::rename(
                                base.join(&name),
                                fixture.parent.join("retained-original-staging"),
                            )?;
                            io::write_member(
                                &scoped_read::open_directory(&base)?,
                                &name,
                                &original_bytes,
                                0o600,
                            )?;
                        } else {
                            fs::write(base.join(&name), b"modified unpublished state")?;
                        }
                    }
                    Ok(())
                })
                .is_err());
            assert_eq!(ledger.state, original);
            assert!(!ledger.path.exists());
            assert!(ledger.require_clean().is_err());
            let stage = ledger.staging(2).unwrap();
            let observed = io::read_member(&ledger.base, &stage.member.name, MAX_STATE).unwrap();
            assert_eq!(
                observed,
                if replacement {
                    original_bytes.clone()
                } else {
                    b"modified unpublished state".to_vec()
                }
            );
            ledger.discard_staging(&stage, || Ok(())).unwrap();
            assert!(!ledger.path.exists());
        }
    }
    #[test]
    fn absent_domain_requires_the_original_parent_and_keeps_that_binding_through_tombstone_io() {
        let mut fixture = Fixture::new("absent-parent-binding");
        let mark = fixture.mark();
        let tree = fixture.tree.as_ref().unwrap();
        tree.remove_members(|| Ok(())).unwrap();
        tree.remove_directories(|| Ok(())).unwrap();
        fixture.tree = None;
        let absent = Absence::at(&mark.manifest, &fixture.path).unwrap();
        assert!(Tree::marked_at(&mark, &fixture.path, true)
            .unwrap()
            .is_none());
        let detached = fixture.parent.with_extension("detached");
        fs::rename(&fixture.parent, &detached).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.parent)
            .unwrap();
        assert!(Tree::marked_at(&mark, &fixture.path, true).is_err());
        assert!(absent.recheck().is_err());
        fs::remove_dir(&fixture.parent).unwrap();
        fs::rename(&detached, &fixture.parent).unwrap();
        absent.recheck().unwrap();
        let ledger_path = fixture.parent.join("ledger");
        initialize_at(&ledger_path, &mark.manifest.installation).unwrap();
        let mut ledger = Ledger::at(
            &ledger_path,
            &mark.manifest.installation,
            Domain::Dag,
            &mark.manifest.principal,
        )
        .unwrap();
        let initial = ledger.state.clone();
        let calls = Cell::new(0);
        assert!(ledger
            .save(initial.clone(), || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    fs::rename(&fixture.parent, &detached)?;
                    fs::DirBuilder::new().mode(0o700).create(&fixture.parent)?;
                }
                absent.recheck()
            })
            .is_err());
        assert_eq!(ledger.state, initial);
        assert!(!ledger.path.exists());
        fs::remove_dir(&fixture.parent).unwrap();
        fs::rename(&detached, &fixture.parent).unwrap();
        assert!(ledger.require_clean().is_err());
        let stage = ledger.staging(2).unwrap();
        ledger.discard_staging(&stage, || absent.recheck()).unwrap();
    }
}
