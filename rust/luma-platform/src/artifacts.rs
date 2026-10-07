//! Native laboratory managed invoice artifacts. Publication moves a complete
//! content/receipt pair atomically; uncertain preparations require review.
use crate::{
    bundle, calculation, platform, principal, scoped_read, skills, workflow_resource, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/artifacts";
const MAX_CONTENT: u64 = 2 * 1024 * 1024;
const MAX_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 1024;
const FREE_FLOOR: u64 = 16 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Format {
    schema_version: u32,
    environment: String,
    installation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) schema_version: u32,
    pub(crate) installation: String,
    pub(crate) request_id: String,
    pub(crate) authenticated_uid: u32,
    pub(crate) workflow_sha256: String,
    pub(crate) source_sha256: String,
    pub(crate) content_sha256: String,
    pub(crate) content_bytes: u64,
    pub(crate) filename: String,
    pub(crate) media_type: String,
    pub(crate) version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource_lease: Option<crate::resources::Token>,
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}

impl Receipt {
    pub(crate) fn validate(&self, installation: &str, request: &str) -> Result<()> {
        if self.schema_version != 1
            || self.installation != installation
            || !hash(installation)
            || self.request_id != request
            || !identifier(request)
            || self.authenticated_uid != 0
            || !hash(&self.workflow_sha256)
            || !hash(&self.source_sha256)
            || !hash(&self.content_sha256)
            || self.content_bytes == 0
            || self.content_bytes > MAX_CONTENT
            || self.filename != "invoice-summary.json"
            || self.media_type != "application/json"
            || self.version != 1
            || self
                .resource_lease
                .as_ref()
                .is_some_and(|t| !workflow_resource::token_valid(t))
        {
            return Err("invalid native artifact receipt".into());
        }
        Ok(())
    }

    pub(crate) fn review(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }

    fn stored_bytes(&self) -> Result<u64> {
        Ok(self.content_bytes + serde_json::to_vec(self)?.len() as u64)
    }
}

pub(crate) fn private_directory(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("unsafe native artifact directory".into());
    }
    Ok(())
}

pub(crate) fn open_at(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn child_directory(dir: &File, name: &str) -> Result<File> {
    let file = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    private_directory(&file)?;
    Ok(file)
}

pub(crate) fn mkdir_at(dir: &File, name: &str) -> Result<File> {
    let name_c = CString::new(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all()?;
    child_directory(dir, name)
}

pub(crate) fn names(dir: &File, max: usize) -> Result<Vec<String>> {
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| "invalid native artifact member name")?;
        if found.len() >= max {
            return Err("native artifact inventory exceeds capacity".into());
        }
        found.insert(name);
    }
    Ok(found.into_iter().collect())
}

pub(crate) fn read_member(dir: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut file = open_at(dir, name, libc::O_RDONLY, 0)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() > limit
    {
        return Err("unsafe or oversized native artifact member".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("native artifact member changed during read".into());
    }
    Ok(bytes)
}

pub(crate) fn write_member(dir: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = open_at(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        mode,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn initialize(path: &Path, installation: &str) -> Result<()> {
    if !hash(installation) {
        return Err("invalid artifact installation identity".into());
    }
    let parent = scoped_read::open_directory(path.parent().ok_or("missing artifact parent")?)?;
    let m = parent.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        return Err("unsafe artifact initialization parent".into());
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = scoped_read::open_directory(path)?;
    private_directory(&root)?;
    mkdir_at(&root, "committed")?;
    mkdir_at(&root, "pending")?;
    mkdir_at(&root, "retained")?;
    write_member(
        &root,
        "format.json",
        &serde_json::to_vec(&Format {
            schema_version: 1,
            environment: "lab".into(),
            installation: installation.into(),
        })?,
        0o600,
    )?;
    root.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

struct Store {
    root: File,
    committed: File,
    pending: File,
    retained: File,
    installation: String,
}

/// Keeps the legacy store locked for the complete reviewed import.
pub(crate) struct LegacySource(Store);

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyArtifact {
    pub(crate) receipt: Receipt,
    pub(crate) content: Vec<u8>,
}

impl LegacySource {
    pub(crate) fn open(path: &Path, installation: &str) -> Result<Self> {
        Ok(Self(Store::open(path, installation)?))
    }

    pub(crate) fn device(&self) -> Result<u64> {
        Ok(self.0.root.metadata()?.dev())
    }

    pub(crate) fn snapshot(&self, request: &str) -> Result<LegacyArtifact> {
        let (_, pending, _) = self.0.inventory()?;
        if !pending.is_empty() {
            return Err("legacy preparation requires reconciliation before import".into());
        }
        let (receipt, content) = self.0.pair(&self.0.committed, request)?;
        Ok(LegacyArtifact { receipt, content })
    }
}

#[derive(Clone, Copy)]
enum Phase {
    PreparedDirectory,
    ContentSynced,
    ReceiptSynced,
    Published,
}

impl Store {
    fn open(path: &Path, installation: &str) -> Result<Self> {
        let root = scoped_read::open_directory(path)?;
        private_directory(&root)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("native artifact store is busy".into());
        }
        if names(&root, 4)? != ["committed", "format.json", "pending", "retained"] {
            return Err("unknown native artifact store layout; preserve state".into());
        }
        let bytes = read_member(&root, "format.json", 4096)?;
        let format: Format = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&format)? != bytes
            || format.schema_version != 1
            || format.environment != "lab"
            || format.installation != installation
            || !hash(installation)
        {
            return Err("native artifact store installation mismatch".into());
        }
        let committed = child_directory(&root, "committed")?;
        let pending = child_directory(&root, "pending")?;
        let retained = child_directory(&root, "retained")?;
        Ok(Self {
            root,
            committed,
            pending,
            retained,
            installation: installation.into(),
        })
    }

    fn pair(&self, parent: &File, request: &str) -> Result<(Receipt, Vec<u8>)> {
        if !identifier(request) {
            return Err("invalid native artifact request".into());
        }
        let dir = child_directory(parent, request)?;
        if names(&dir, 2)? != ["receipt.json", "report.json"] {
            return Err("incomplete native artifact pair; retain preparation".into());
        }
        let bytes = read_member(&dir, "receipt.json", 4096)?;
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        receipt.validate(&self.installation, request)?;
        if serde_json::to_vec(&receipt)? != bytes {
            return Err("noncanonical artifact receipt".into());
        }
        let content = read_member(&dir, "report.json", MAX_CONTENT)?;
        if content.len() as u64 != receipt.content_bytes
            || digest(&content) != receipt.content_sha256
        {
            return Err("native artifact content integrity failure".into());
        }
        Ok((receipt, content))
    }

    fn inventory(&self) -> Result<(Vec<Receipt>, Vec<String>, u64)> {
        let mut receipts = Vec::new();
        let mut total = 0u64;
        for request in names(&self.committed, MAX_RECORDS)? {
            let (receipt, _) = self.pair(&self.committed, &request)?;
            total = total
                .checked_add(receipt.stored_bytes()?)
                .ok_or("artifact byte total overflow")?;
            if total > MAX_TOTAL {
                return Err("native artifact byte capacity exhausted".into());
            }
            receipts.push(receipt);
        }
        let retained = names(&self.retained, MAX_RECORDS)?;
        if receipts.len() + retained.len() > MAX_RECORDS {
            return Err("native artifact record capacity exhausted".into());
        }
        for request in &retained {
            if receipts.iter().any(|r| &r.request_id == request) {
                return Err("artifact identity appears in multiple states".into());
            }
            let (_, bytes) = self.observation(&self.retained, &request)?;
            total = total
                .checked_add(bytes)
                .ok_or("retained artifact capacity overflow")?;
            if total > MAX_TOTAL {
                return Err("retained artifact capacity exhausted".into());
            }
        }
        let pending = names(&self.pending, 1)?;
        if pending.iter().any(|id| {
            !identifier(id) || receipts.iter().any(|r| &r.request_id == id) || retained.contains(id)
        }) {
            return Err("unknown artifact preparation".into());
        }
        Ok((receipts, pending, total))
    }

    fn observation(&self, parent: &File, request: &str) -> Result<(serde_json::Value, u64)> {
        if !identifier(request) {
            return Err("invalid artifact preparation identity".into());
        }
        let dir = child_directory(parent, request)?;
        let mut members = Vec::new();
        let mut total = 0;
        for name in names(&dir, 2)? {
            let limit = match name.as_str() {
                "report.json" => MAX_CONTENT,
                "receipt.json" => 4096,
                _ => return Err("unknown artifact preparation member; preserve state".into()),
            };
            let bytes = read_member(&dir, &name, limit)?;
            total += bytes.len() as u64;
            members
                .push(serde_json::json!({"name":name,"bytes":bytes.len(),"sha256":digest(&bytes)}));
        }
        Ok((
            serde_json::json!({"installation":self.installation,"request_id":request,"members":members}),
            total,
        ))
    }

    fn abort(
        &self,
        request: &str,
        review: &str,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if !identifier(request) || !hash(review) {
            return Err("invalid artifact abort review".into());
        }
        let (receipts, pending, total) = self.inventory()?;
        if receipts.iter().any(|r| r.request_id == request) {
            return Err("acknowledged artifact cannot be aborted".into());
        }
        let already_retained = names(&self.retained, MAX_RECORDS)?
            .iter()
            .any(|r| r == request);
        let parent = if already_retained {
            &self.retained
        } else {
            &self.pending
        };
        if !already_retained && pending != [request] {
            return Err("artifact abort does not match current preparation".into());
        }
        let (observation, bytes) = self.observation(parent, request)?;
        if !already_retained
            && (receipts.len() + names(&self.retained, MAX_RECORDS)?.len() >= MAX_RECORDS
                || total + bytes > MAX_TOTAL)
        {
            return Err("artifact retention exceeds capacity; preserve preparation".into());
        }
        if digest(&serde_json::to_vec(&observation)?) != review {
            return Err("artifact preparation changed since abort review".into());
        }
        authorize()?;
        if !already_retained {
            let name = CString::new(request)?;
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
                return Err("artifact abort outcome requires reinspection".into());
            }
        }
        let dir = child_directory(&self.retained, request)?;
        for name in names(&dir, 2)? {
            open_at(&dir, &name, libc::O_RDONLY, 0)?.sync_all()?;
        }
        dir.sync_all()?;
        self.retained.sync_all()?;
        self.pending.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    fn durable(&self, request: &str) -> Result<()> {
        let dir = child_directory(&self.committed, request)?;
        for name in ["report.json", "receipt.json"] {
            open_at(&dir, name, libc::O_RDONLY, 0)?.sync_all()?;
        }
        dir.sync_all()?;
        self.committed.sync_all()?;
        self.pending.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }

    fn rename_pair(&self, request: &str) -> Result<()> {
        let name = CString::new(request)?;
        if unsafe {
            libc::renameat2(
                self.pending.as_raw_fd(),
                name.as_ptr(),
                self.committed.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("native artifact publication refused; retain preparation".into());
        }
        Ok(())
    }

    fn publish(
        &self,
        receipt: &Receipt,
        content: &[u8],
        authorize: impl FnMut(&Receipt) -> Result<()>,
    ) -> Result<bool> {
        self.publish_with_hook(receipt, content, authorize, |_| Ok(()))
    }

    fn publish_with_hook(
        &self,
        receipt: &Receipt,
        content: &[u8],
        mut authorize: impl FnMut(&Receipt) -> Result<()>,
        mut hook: impl FnMut(Phase) -> Result<()>,
    ) -> Result<bool> {
        receipt.validate(&self.installation, &receipt.request_id)?;
        if content.len() as u64 != receipt.content_bytes
            || digest(content) != receipt.content_sha256
        {
            return Err("native artifact request content mismatch".into());
        }
        authorize(receipt)?;
        let (receipts, pending, total) = self.inventory()?;
        let retained = names(&self.retained, MAX_RECORDS)?;
        if retained.iter().any(|id| id == &receipt.request_id) {
            return Err("artifact request was retained after abort; use a new request".into());
        }
        if let Some(previous) = receipts.iter().find(|r| r.request_id == receipt.request_id) {
            if previous != receipt {
                return Err("native artifact idempotency conflict".into());
            }
            authorize(receipt)?;
            self.durable(&receipt.request_id)?;
            return Ok(true);
        }
        if !pending.is_empty() {
            return Err("artifact preparation requires reviewed reconciliation".into());
        }
        if receipts.len() + retained.len() >= MAX_RECORDS
            || total + receipt.stored_bytes()? > MAX_TOTAL
        {
            return Err("native artifact capacity exhausted".into());
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut space) } != 0
            || (space.f_bavail as u64)
                .checked_mul(space.f_frsize as u64)
                .ok_or("artifact space observation overflow")?
                < receipt.stored_bytes()? + FREE_FLOOR
        {
            return Err("insufficient native artifact storage reserve".into());
        }
        let dir = mkdir_at(&self.pending, &receipt.request_id)?;
        hook(Phase::PreparedDirectory)?;
        write_member(&dir, "report.json", content, 0o400)?;
        hook(Phase::ContentSynced)?;
        write_member(&dir, "receipt.json", &serde_json::to_vec(receipt)?, 0o400)?;
        dir.sync_all()?;
        self.pending.sync_all()?;
        hook(Phase::ReceiptSynced)?;
        self.pair(&self.pending, &receipt.request_id)?;
        authorize(receipt)?;
        self.rename_pair(&receipt.request_id)?;
        hook(Phase::Published)?;
        self.durable(&receipt.request_id)?;
        Ok(false)
    }

    fn reconcile(
        &self,
        request: &str,
        review: &str,
        mut authorize: impl FnMut(&Receipt) -> Result<()>,
    ) -> Result<Receipt> {
        if !identifier(request) || !hash(review) {
            return Err("invalid artifact reconciliation review".into());
        }
        let (receipts, pending, total) = self.inventory()?;
        if let Some(receipt) = receipts.iter().find(|r| r.request_id == request) {
            if !pending.is_empty() || receipt.review()? != review {
                return Err("artifact reconciliation state conflict".into());
            }
            authorize(&receipt)?;
            self.durable(request)?;
            return Ok(receipt.clone());
        }
        if pending != [request] {
            return Err("artifact preparation does not match review".into());
        }
        let (receipt, _) = self.pair(&self.pending, request)?;
        if receipt.review()? != review {
            return Err("artifact preparation changed since review".into());
        }
        if receipts.len() + names(&self.retained, MAX_RECORDS)?.len() >= MAX_RECORDS
            || total + receipt.stored_bytes()? > MAX_TOTAL
        {
            return Err("native artifact recovery exceeds capacity".into());
        }
        authorize(&receipt)?;
        self.rename_pair(request)?;
        self.durable(request)?;
        Ok(receipt)
    }

    fn status(&self) -> Result<serde_json::Value> {
        let (receipts, pending, total) = self.inventory()?;
        let proposal = if let Some(request) = pending.first() {
            let mut result = match self.pair(&self.pending, request) {
                Ok((receipt, _)) => {
                    serde_json::json!({"request_id":request,"state":"prepared","review_sha256":receipt.review()?,"receipt":receipt})
                }
                Err(_) => {
                    serde_json::json!({"request_id":request,"state":"incomplete","review_sha256":null})
                }
            };
            result["abort_review_sha256"] = match self.observation(&self.pending, request) {
                Ok((observation, _)) => {
                    serde_json::json!(digest(&serde_json::to_vec(&observation)?))
                }
                Err(_) => serde_json::Value::Null,
            };
            result
        } else {
            serde_json::Value::Null
        };
        let mut retained = Vec::new();
        for request in names(&self.retained, MAX_RECORDS)? {
            let (observation, _) = self.observation(&self.retained, &request)?;
            retained.push(serde_json::json!({"request_id":request,"review_sha256":digest(&serde_json::to_vec(&observation)?)}));
        }
        Ok(
            serde_json::json!({"schema_version":1,"environment":"lab","records":receipts,"storage_bytes":total,"pending":proposal,"retained":retained,"product_admin_active":false,"rollback_protected":false,"gate_closing":false}),
        )
    }
}

pub(crate) fn installation() -> Result<String> {
    crate::require_root()?;
    platform::require_installed()?;
    principal::installation_at(Path::new(principal::REGISTRY))
}

fn authorize(receipt: &Receipt) -> Result<()> {
    if installation()? != receipt.installation
        || skills::admission()?["workflow_sha256"] != receipt.workflow_sha256
    {
        return Err("artifact installation or signed workflow authorization changed".into());
    }
    Ok(())
}

pub fn initialize_installed() -> Result<()> {
    initialize(Path::new(DIRECTORY), &installation()?)
}

pub fn status() -> Result<()> {
    println!(
        "{}",
        Store::open(Path::new(DIRECTORY), &installation()?)?.status()?
    );
    Ok(())
}

pub fn publish_invoice(request: &str) -> Result<()> {
    let result = invoice_publication(
        request,
        workflow_resource::calculate,
        workflow_resource::Calculation::recheck,
    )?;
    println!("{result}");
    Ok(())
}

pub(crate) fn invoice_publication(
    request: &str,
    calculate: impl FnOnce(&[u8]) -> Result<workflow_resource::Calculation>,
    mut recheck: impl FnMut(&workflow_resource::Calculation, &[u8], &str) -> Result<()>,
) -> Result<serde_json::Value> {
    if !identifier(request) {
        return Err("invalid native artifact request".into());
    }
    let installation = installation()?;
    let admission = skills::admission()?;
    let source = calculation::source_stdin()?;
    let result = calculate(&source)?;
    let content = &result.report;
    let mut receipt = Receipt {
        schema_version: 1,
        installation,
        request_id: request.into(),
        authenticated_uid: 0,
        workflow_sha256: admission["workflow_sha256"]
            .as_str()
            .ok_or("missing signed workflow identity")?
            .into(),
        source_sha256: digest(&source),
        content_sha256: digest(content),
        content_bytes: content.len() as u64,
        filename: "invoice-summary.json".into(),
        media_type: "application/json".into(),
        version: 1,
        resource_lease: Some(result.lease.clone()),
    };
    let store = Store::open(Path::new(DIRECTORY), &receipt.installation)?;
    if let Some(previous) = store
        .inventory()?
        .0
        .iter()
        .find(|r| r.request_id == request)
    {
        // Preserve immutable historical provenance on exact recomputation retry.
        // Missing legacy provenance stays missing; never attach a new token to it.
        receipt.resource_lease = previous.resource_lease.clone();
    }
    let replay = store.publish(&receipt, content, |receipt| {
        authorize(receipt)?;
        recheck(&result, &source, &receipt.installation)
    })?;
    Ok(
        serde_json::json!({"receipt":receipt,"replayed":replay,"environment":"lab",
        "calculation_lease":result.lease,"gate_closing":false}),
    )
}

pub fn read(request: &str) -> Result<()> {
    let store = Store::open(Path::new(DIRECTORY), &installation()?)?;
    let (_, content) = store.pair(&store.committed, request)?;
    std::io::stdout().lock().write_all(&content)?;
    Ok(())
}

pub fn reconcile(request: &str, review: &str) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&reconcile_invoice(
            request,
            review,
            workflow_resource::recheck_report
        )?)?
    );
    Ok(())
}

pub(crate) fn reconcile_invoice(
    request: &str,
    review: &str,
    mut recheck: impl FnMut(&crate::resources::Token, &str, &[u8], &str) -> Result<()>,
) -> Result<Receipt> {
    let store = Store::open(Path::new(DIRECTORY), &installation()?)?;
    let committed = store.inventory()?.0.iter().any(|r| r.request_id == request);
    // A committed acknowledgement is read-only. An uncertain preparation still
    // needs its live broker result receipt; operator review cannot replace it.
    let prepared = if committed {
        None
    } else {
        Some(store.pair(&store.pending, request)?)
    };
    store.reconcile(request, review, |receipt| {
        authorize(receipt)?;
        if let Some((expected, report)) = &prepared {
            if expected != receipt {
                return Err("prepared resource receipt changed".into());
            }
            let token = receipt.resource_lease.as_ref().ok_or(
                "prepared legacy artifact lacks resource provenance; retain and resubmit source",
            )?;
            recheck(token, &receipt.source_sha256, report, &receipt.installation)?;
        }
        Ok(())
    })
}

pub fn abort(request: &str, review: &str) -> Result<()> {
    let expected = installation()?;
    let store = Store::open(Path::new(DIRECTORY), &expected)?;
    store.abort(request, review, || {
        if installation()? != expected {
            return Err("artifact installation changed during abort".into());
        }
        Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({"request_id":request,"state":"retained","review_sha256":review,"gate_closing":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct Fixture {
        base: PathBuf,
        path: PathBuf,
    }
    impl Fixture {
        fn new(label: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("luma-artifacts-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let path = base.join("store");
            initialize(&path, &"a".repeat(64)).unwrap();
            Self { base, path }
        }
        fn open(&self) -> Store {
            Store::open(&self.path, &"a".repeat(64)).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.base).unwrap();
        }
    }

    fn proposal(request: &str) -> (Receipt, Vec<u8>) {
        let source = include_bytes!("../../../examples/invoices.csv");
        let content = calculation::report_bytes(source).unwrap();
        (
            Receipt {
                schema_version: 1,
                installation: "a".repeat(64),
                request_id: request.into(),
                authenticated_uid: 0,
                workflow_sha256: "b".repeat(64),
                source_sha256: digest(source),
                content_sha256: digest(&content),
                content_bytes: content.len() as u64,
                filename: "invoice-summary.json".into(),
                media_type: "application/json".into(),
                version: 1,
                resource_lease: None,
            },
            content,
        )
    }

    #[test]
    fn resource_provenance_is_optional_for_old_bytes_and_validated_for_new_receipts() {
        let (mut receipt, _) = proposal("request-1");
        let old = serde_json::to_vec(&receipt).unwrap();
        assert!(!std::str::from_utf8(&old)
            .unwrap()
            .contains("resource_lease"));
        let decoded: Receipt = serde_json::from_slice(&old).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), old);
        receipt.resource_lease = Some(crate::resources::Token {
            lease_id: "c".repeat(32),
            manager_epoch: "d".repeat(32),
            generation: 1,
        });
        receipt.validate(&"a".repeat(64), "request-1").unwrap();
        let encoded = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            serde_json::from_slice::<Receipt>(&encoded).unwrap(),
            receipt
        );
        receipt.resource_lease.as_mut().unwrap().generation = 0;
        assert!(receipt.validate(&"a".repeat(64), "request-1").is_err());
    }

    #[test]
    fn fenced_publication_retains_complete_generation_bound_preparation() {
        let f = Fixture::new("resource-fence");
        let (mut receipt, data) = proposal("request-1");
        receipt.resource_lease = Some(crate::resources::Token {
            lease_id: "c".repeat(32),
            manager_epoch: "d".repeat(32),
            generation: 1,
        });
        let mut checks = 0;
        assert!(f
            .open()
            .publish(&receipt, &data, |_| {
                checks += 1;
                if checks == 2 {
                    Err("broker generation fenced".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        let store = f.open();
        assert!(store.inventory().unwrap().0.is_empty());
        assert_eq!(
            store.pair(&store.pending, "request-1").unwrap(),
            (receipt.clone(), data)
        );
        assert!(store
            .reconcile("request-1", &receipt.review().unwrap(), |_| {
                Err("broker generation still fenced".into())
            })
            .is_err());
        assert!(store.inventory().unwrap().0.is_empty());
        assert_eq!(store.pair(&store.pending, "request-1").unwrap().0, receipt);
    }

    #[test]
    fn durable_pair_replays_after_reopen_and_conflicting_source_is_denied() {
        let f = Fixture::new("replay");
        let (r, data) = proposal("request-1");
        assert!(!f.open().publish(&r, &data, |_| Ok(())).unwrap());
        assert!(f.open().publish(&r, &data, |_| Ok(())).unwrap());
        let mut other = r.clone();
        other.source_sha256 = "c".repeat(64);
        assert!(f.open().publish(&other, &data, |_| Ok(())).is_err());
        let store = f.open();
        assert_eq!(store.pair(&store.committed, "request-1").unwrap().1, data);
    }

    #[test]
    fn interrupted_preparations_are_retained_and_incomplete_pairs_cannot_publish() {
        for (label, phase) in [("mkdir", 0), ("content", 1), ("receipt", 2)] {
            let f = Fixture::new(label);
            let (r, data) = proposal("request-1");
            assert!(f
                .open()
                .publish_with_hook(
                    &r,
                    &data,
                    |_| Ok(()),
                    |p| {
                        if matches!(
                            (phase, p),
                            (0, Phase::PreparedDirectory)
                                | (1, Phase::ContentSynced)
                                | (2, Phase::ReceiptSynced)
                        ) {
                            Err("interrupted".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            let store = f.open();
            let status = store.status().unwrap();
            assert_eq!(status["records"], serde_json::json!([]));
            assert!(store.publish(&r, &data, |_| Ok(())).is_err());
            if phase < 2 {
                assert!(store
                    .reconcile(&r.request_id, &r.review().unwrap(), |_| Ok(()))
                    .is_err());
            } else {
                assert!(store
                    .reconcile(&r.request_id, &"d".repeat(64), |_| Ok(()))
                    .is_err());
                store
                    .reconcile(&r.request_id, &r.review().unwrap(), |_| Ok(()))
                    .unwrap();
                assert!(store.publish(&r, &data, |_| Ok(())).unwrap());
            }
        }
    }

    #[test]
    fn reviewed_abort_preserves_bytes_blocks_reuse_and_allows_a_new_request() {
        for (label, phase) in [("abort-empty", 0), ("abort-content", 1), ("abort-pair", 2)] {
            let f = Fixture::new(label);
            let (r, data) = proposal("request-1");
            assert!(f
                .open()
                .publish_with_hook(
                    &r,
                    &data,
                    |_| Ok(()),
                    |p| {
                        if matches!(
                            (phase, p),
                            (0, Phase::PreparedDirectory)
                                | (1, Phase::ContentSynced)
                                | (2, Phase::ReceiptSynced)
                        ) {
                            Err("interrupted".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            let review = f.open().status().unwrap()["pending"]["abort_review_sha256"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(f
                .open()
                .abort("request-1", &"f".repeat(64), || Ok(()))
                .is_err());
            assert!(f
                .open()
                .abort("request-1", &review, || Err("revoked".into()))
                .is_err());
            let before = {
                let store = f.open();
                store.observation(&store.pending, "request-1").unwrap()
            };
            f.open().abort("request-1", &review, || Ok(())).unwrap();
            f.open().abort("request-1", &review, || Ok(())).unwrap();
            let store = f.open();
            assert_eq!(
                store.observation(&store.retained, "request-1").unwrap(),
                before
            );
            assert!(store.status().unwrap()["pending"].is_null());
            assert!(store.publish(&r, &data, |_| Ok(())).is_err());
            assert!(store
                .reconcile("request-1", &r.review().unwrap(), |_| Ok(()))
                .is_err());
            let (new, bytes) = proposal("request-2");
            store.publish(&new, &bytes, |_| Ok(())).unwrap();
            assert!(store
                .abort("request-2", &new.review().unwrap(), || Ok(()))
                .is_err());
            assert_eq!(
                store.status().unwrap()["storage_bytes"],
                before.1 + new.stored_bytes().unwrap()
            );
        }
    }

    #[test]
    fn abort_refuses_changed_bytes_unknown_members_and_links() {
        let f = Fixture::new("abort-unsafe");
        let (r, data) = proposal("request-1");
        assert!(f
            .open()
            .publish_with_hook(
                &r,
                &data,
                |_| Ok(()),
                |p| {
                    if matches!(p, Phase::ContentSynced) {
                        Err("interrupted".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        let review = f.open().status().unwrap()["pending"]["abort_review_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let report = f.path.join("pending/request-1/report.json");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&report, b"changed").unwrap();
        assert!(f.open().abort("request-1", &review, || Ok(())).is_err());
        fs::remove_file(&report).unwrap();
        symlink("receipt.json", &report).unwrap();
        assert!(f.open().status().unwrap()["pending"]["abort_review_sha256"].is_null());
        assert!(f.open().abort("request-1", &review, || Ok(())).is_err());
        fs::remove_file(&report).unwrap();
        fs::write(f.path.join("pending/request-1/unknown"), b"retain").unwrap();
        assert!(f.open().status().unwrap()["pending"]["abort_review_sha256"].is_null());
        assert!(f.open().abort("request-1", &review, || Ok(())).is_err());
    }

    #[test]
    fn lost_publication_ack_is_verified_and_resynced_without_another_write() {
        let f = Fixture::new("published");
        let (r, data) = proposal("request-1");
        assert!(f
            .open()
            .publish_with_hook(
                &r,
                &data,
                |_| Ok(()),
                |p| if matches!(p, Phase::Published) {
                    Err("lost acknowledgement".into())
                } else {
                    Ok(())
                }
            )
            .is_err());
        assert!(f.open().publish(&r, &data, |_| Ok(())).unwrap());
        assert_eq!(
            f.open().status().unwrap()["records"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn authorization_is_checked_before_preparation_before_publish_and_on_replay() {
        let f = Fixture::new("auth");
        let (r, data) = proposal("request-1");
        assert!(f
            .open()
            .publish(&r, &data, |_| Err("denied".into()))
            .is_err());
        assert!(f.open().status().unwrap()["pending"].is_null());
        let calls = Cell::new(0);
        assert!(f
            .open()
            .publish(&r, &data, |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("revoked".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
        assert!(f
            .open()
            .reconcile(
                &r.request_id,
                &r.review().unwrap(),
                |_| Err("denied".into())
            )
            .is_err());
        f.open()
            .reconcile(&r.request_id, &r.review().unwrap(), |_| Ok(()))
            .unwrap();
        assert!(f
            .open()
            .publish(&r, &data, |_| Err("denied replay".into()))
            .is_err());
        calls.set(0);
        assert!(f
            .open()
            .publish(&r, &data, |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("revoked during replay verification".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn tampering_links_unknown_files_identity_mismatch_and_concurrent_writer_fail_closed() {
        let f = Fixture::new("safety");
        let (r, data) = proposal("request-1");
        assert!(Store::open(&f.path, &"b".repeat(64)).is_err());
        let held = f.open();
        assert!(Store::open(&f.path, &"a".repeat(64)).is_err());
        drop(held);
        f.open().publish(&r, &data, |_| Ok(())).unwrap();
        let report = f.path.join("committed/request-1/report.json");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&report, b"altered").unwrap();
        assert!(f.open().status().is_err());
        fs::remove_file(&report).unwrap();
        symlink("receipt.json", &report).unwrap();
        assert!(f.open().status().is_err());
        fs::write(f.path.join("unknown"), b"retain").unwrap();
        assert!(Store::open(&f.path, &"a".repeat(64)).is_err());
        assert!(initialize(&f.path, &"a".repeat(64)).is_err());
    }
}
