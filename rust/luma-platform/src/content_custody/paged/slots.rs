//! Physical tail slots. Allocated data extents and inodes are retained at fixed
//! paths; sealing never releases a reserve and creates a replacement file.
//! These observations are DATA, not a grant, a C selection or an atomic promise
//! about filesystem directory/journal metadata under external space pressure.
use super::*;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;

const PER_POOL: u32 = 138;
const PAGE_SLOTS: u32 = 128;
const RECORD_SLOTS: u32 = 2;
const MAX_OUTCOMES: u32 = 256;
const WINDOW_SLOTS: u32 = 16;
const INSTANCE_ATTRIBUTE: &[u8] = b"user.luma.c-slot-v3\0";
pub(in crate::content_checkpoint::custody) const PLAN_BYTES: usize = 32 * 1024;
const MAX_EXACT_SLOTS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct ExactSlot {
    pub pool: Pool,
    pub kind: Kind,
    pub capacity: u64,
}
impl ExactSlot {
    pub fn for_bytes(pool: Pool, kind: Kind, bytes: u64) -> Result<Self> {
        let capacity = bytes
            .checked_add(4095)
            .ok_or("exact slot rounding overflow")?
            / 4096
            * 4096;
        let value = Self {
            pool,
            kind,
            capacity,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.capacity == 0
            || self.capacity % 4096 != 0
            || self.capacity > self.kind.capacity()
            || matches!(self.pool, Pool::Publication(value) if value >= MAX_OUTCOMES)
        {
            return Err("exact slot exceeds its finite reviewed kind/pool/capacity".into());
        }
        Ok(())
    }
}

pub(super) fn create_instance(file: &File) -> Result<String> {
    let mut bytes = [0_u8; 32];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) }
        != bytes.len() as isize
        || bytes == [0; 32]
    {
        return Err("slot identity generation failed; no fallback or preallocation".into());
    }
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            INSTANCE_ATTRIBUTE.as_ptr().cast(),
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::XATTR_CREATE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    file.sync_all()?;
    let value = bundle::hex(&bytes);
    if instance(file)? != value {
        return Err("slot identity xattr readback differs".into());
    }
    Ok(value)
}
pub(super) fn instance(file: &File) -> Result<String> {
    let mut bytes = [0_u8; 32];
    if unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            INSTANCE_ATTRIBUTE.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    } != bytes.len() as isize
        || bytes == [0; 32]
    {
        return Err("slot identity xattr is absent, unsupported, malformed or inaccessible".into());
    }
    Ok(bundle::hex(&bytes))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::content_checkpoint::custody) enum Pool {
    Publication(u32),
    Terminal,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::content_checkpoint::custody) enum Kind {
    Page,
    Record,
    Control,
}
impl Kind {
    pub(super) fn capacity(self) -> u64 {
        match self {
            Self::Page => PAGE_BYTES as u64,
            Self::Record => FILE_BYTES as u64,
            Self::Control => CONTROL_BYTES as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct Plan {
    pub schema_version: u32,
    pub purpose: String,
    pub binding: luma_content_store::v2::custody_map::CustodyBinding,
    pub job: String,
    pub outcomes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<Vec<ExactSlot>>,
}
impl Plan {
    pub fn fixed(
        binding: &luma_content_store::v2::custody_map::CustodyBinding,
        job: &str,
        outcomes: u32,
    ) -> Result<Self> {
        let value = Self {
            schema_version: 3,
            purpose: "luma-c-preallocated-restore-tail-slots-v3".into(),
            binding: binding.clone(),
            job: job.into(),
            outcomes,
            exact: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn exact(
        binding: &luma_content_store::v2::custody_map::CustodyBinding,
        job: &str,
        slots: Vec<ExactSlot>,
    ) -> Result<Self> {
        let value = Self {
            schema_version: 4,
            purpose: "luma-c-reviewed-exact-slot-layout-v4".into(),
            binding: binding.clone(),
            job: job.into(),
            outcomes: 0,
            exact: Some(slots),
        };
        value.validate()?;
        if serde_json::to_vec(&value)?.len() > PLAN_BYTES {
            return Err("exact slot layout exceeds its canonical control bound".into());
        }
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        digest(&self.job)?;
        if self.schema_version == 4 {
            let slots = self.exact.as_ref().ok_or("exact slot layout missing")?;
            if self.purpose != "luma-c-reviewed-exact-slot-layout-v4"
                || self.outcomes != 0
                || slots.is_empty()
                || slots.len() > MAX_EXACT_SLOTS
            {
                return Err("invalid exact finite C allocation layout".into());
            }
            let mut total = 0_u64;
            for slot in slots {
                slot.validate()?;
                total = total
                    .checked_add(slot.capacity)
                    .ok_or("exact layout accounting overflow")?;
            }
            if total > 16 * 1024 * 1024 {
                return Err(
                    "exact allocation layout exceeds a bounded original-operation window".into(),
                );
            }
            return Ok(());
        }
        if self.schema_version != 3
            || self.purpose != "luma-c-preallocated-restore-tail-slots-v3"
            || self.outcomes == 0
            || self.outcomes > MAX_OUTCOMES
            || self.exact.is_some()
        {
            return Err("invalid finite C physical tail plan".into());
        }
        Ok(())
    }
    pub fn slots(&self) -> Result<u32> {
        self.validate()?;
        if let Some(slots) = &self.exact {
            return Ok(u32::try_from(slots.len())?);
        }
        self.outcomes
            .checked_add(1)
            .and_then(|n| n.checked_mul(PER_POOL))
            .ok_or_else(|| "tail slot arithmetic overflow".into())
    }
    pub fn spec(&self, number: u32) -> Result<(Pool, Kind)> {
        if number >= self.slots()? {
            return Err("physical tail slot is outside its exact reviewed plan".into());
        }
        if let Some(slots) = &self.exact {
            let slot = &slots[number as usize];
            return Ok((slot.pool, slot.kind));
        }
        let ordinal = number / PER_POOL;
        let index = number % PER_POOL;
        let pool = if ordinal == self.outcomes {
            Pool::Terminal
        } else {
            Pool::Publication(ordinal)
        };
        let kind = if index < PAGE_SLOTS {
            Kind::Page
        } else if index < PAGE_SLOTS + RECORD_SLOTS {
            Kind::Record
        } else {
            Kind::Control
        };
        Ok((pool, kind))
    }
    pub fn capacity(&self, number: u32) -> Result<u64> {
        let (_, kind) = self.spec(number)?;
        Ok(self
            .exact
            .as_ref()
            .map_or_else(|| kind.capacity(), |slots| slots[number as usize].capacity))
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > PLAN_BYTES {
            return Err("canonical C allocation layout exceeds its control bound".into());
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct Reference {
    pub schema_version: u32,
    pub job: String,
    pub number: u32,
    pub pool: Pool,
    pub kind: Kind,
    pub capacity: u64,
    pub device: u64,
    pub inode: u64,
    pub mount: u64,
    pub allocated_bytes: u64,
    pub instance_id: String,
    pub created_ctime_seconds: i64,
    pub created_ctime_nanoseconds: i64,
}
impl Reference {
    pub fn validate_data(&self) -> Result<()> {
        digest(&self.job)?;
        digest(&self.instance_id)?;
        let ordinal = self.number / PER_POOL;
        let offset = self.number % PER_POOL;
        let kind = if offset < PAGE_SLOTS {
            Kind::Page
        } else if offset < PAGE_SLOTS + RECORD_SLOTS {
            Kind::Record
        } else {
            Kind::Control
        };
        let pool_valid = match self.pool {
            Pool::Publication(value) => value < MAX_OUTCOMES && value == ordinal,
            Pool::Terminal => ordinal > 0 && ordinal <= MAX_OUTCOMES,
        };
        let layout_valid = match self.schema_version {
            3 => pool_valid && self.kind == kind && self.capacity == kind.capacity(),
            4 => {
                self.number < MAX_EXACT_SLOTS as u32
                    && ExactSlot {
                        pool: self.pool,
                        kind: self.kind,
                        capacity: self.capacity,
                    }
                    .validate()
                    .is_ok()
            }
            _ => false,
        };
        if !layout_valid
            || self.inode == 0
            || self.mount == 0
            || !(0..1_000_000_000).contains(&self.created_ctime_nanoseconds)
            || self.allocated_bytes < self.capacity
            || self.allocated_bytes % 512 != 0
            || self.allocated_bytes
                > self
                    .capacity
                    .checked_add(64 * 1024)
                    .ok_or("tail allocation bound overflow")?
        {
            return Err("malformed bounded physical tail location DATA".into());
        }
        Ok(())
    }
    pub fn validate(&self, plan: &Plan) -> Result<()> {
        self.validate_data()?;
        let (pool, kind) = plan.spec(self.number)?;
        if self.schema_version != plan.schema_version
            || self.job != plan.job
            || self.pool != pool
            || self.kind != kind
            || self.capacity != plan.capacity(self.number)?
            || self.inode == 0
            || self.mount == 0
            || self.allocated_bytes < self.capacity
            || self.allocated_bytes % 512 != 0
            || self.allocated_bytes
                > self
                    .capacity
                    .checked_add(64 * 1024)
                    .ok_or("tail allocation bound overflow")?
        {
            return Err(
                "physical tail reference substitutes job, pool, kind, inode or capacity".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct SealedReference {
    pub slot: Reference,
    pub bytes: u64,
    pub sha256: String,
    pub sealed_ctime_seconds: i64,
    pub sealed_ctime_nanoseconds: i64,
}
impl SealedReference {
    pub fn validate_data(&self) -> Result<()> {
        self.slot.validate_data()?;
        digest(&self.sha256)?;
        if self.bytes == 0
            || self.bytes > self.slot.capacity
            || !(0..1_000_000_000).contains(&self.sealed_ctime_nanoseconds)
        {
            return Err("malformed immutable slot seal DATA".into());
        }
        Ok(())
    }
    pub fn validate(&self, plan: &Plan) -> Result<()> {
        self.validate_data()?;
        self.slot.validate(plan)?;
        digest(&self.sha256)?;
        if self.bytes == 0 || self.bytes > self.slot.capacity {
            return Err("sealed tail data exceeds the original allocated slot".into());
        }
        Ok(())
    }
}

pub(in crate::content_checkpoint::custody) struct Directory<'a> {
    pages: &'a PageStore,
    plan: Plan,
    pin: PersistentDirectory,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::content_checkpoint::custody) struct NamespaceObservation {
    pub device: u64,
    pub inode: u64,
    pub mount: u64,
    pub allocated_bytes: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
    pub identity_inode: u64,
    pub identity_sha256: String,
    pub identity_bytes: u64,
    pub identity_allocated_bytes: u64,
}
impl<'a> Directory<'a> {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn observe_namespace(
        &self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<NamespaceObservation> {
        self.check(check)?;
        let path = self.pages.root.join("tails").join(&self.plan.job);
        let directory = File::open(&path)?;
        let before = directory.metadata()?;
        if before.dev() != self.pin.identity.0
            || before.ino() != self.pin.identity.1
            || PersistentDirectory::mount(&directory)? != self.pin.mount
        {
            return Err("job namespace does not select its held allocation directory".into());
        }
        let identity = path.join("identity.json");
        let parent = MemberParent::capture(&identity)?;
        let file = parent.open(&identity, libc::O_RDONLY, 0)?;
        let identity_before = parent.member(&file, PLAN_BYTES as u64)?;
        if identity_before.dev() != self.pin.identity.0
            || PersistentDirectory::mount(&file)? != self.pin.mount
        {
            return Err("job identity crossed its held directory device/mount".into());
        }
        let bytes = self.pages.read(
            &format!("tails/{}/identity.json", self.plan.job),
            PLAN_BYTES,
            check,
        )?;
        if bytes != self.plan.bytes()?
            || file_identity(&file.metadata()?) != file_identity(&identity_before)
            || file_identity(&parent.open(&identity, libc::O_RDONLY, 0)?.metadata()?)
                != file_identity(&identity_before)
            || file_identity(&directory.metadata()?) != file_identity(&before)
        {
            return Err(
                "job identity or namespace changed across actual ownership observation".into(),
            );
        }
        self.check(check)?;
        Ok(NamespaceObservation {
            device: before.dev(),
            inode: before.ino(),
            mount: self.pin.mount,
            allocated_bytes: before
                .blocks()
                .checked_mul(512)
                .ok_or("job namespace allocation overflow")?,
            ctime_seconds: before.ctime(),
            ctime_nanoseconds: before.ctime_nsec(),
            identity_inode: identity_before.ino(),
            identity_sha256: hash(&bytes),
            identity_bytes: bytes.len() as u64,
            identity_allocated_bytes: identity_before
                .blocks()
                .checked_mul(512)
                .ok_or("job identity allocation overflow")?,
        })
    }
    pub fn at_reference(
        pages: &'a PageStore,
        reference: &Reference,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        reference.validate_data()?;
        check()?;
        let bytes = pages.read(
            &format!("tails/{}/identity.json", reference.job),
            PLAN_BYTES,
            check,
        )?;
        let plan: Plan = canonical(&bytes, PLAN_BYTES)?;
        plan.validate()?;
        reference.validate(&plan)?;
        let value = Self::open(pages, plan, check)?;
        check()?;
        Ok(value)
    }
    pub fn create(
        pages: &'a PageStore,
        plan: Plan,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        plan.validate()?;
        pages.check()?;
        check()?;
        if &plan.binding != pages.binding() {
            return Err("tail plan belongs to another independent C authority".into());
        }
        let path = pages.root.join("tails").join(&plan.job);
        let parent = MemberParent::capture(&path)?;
        pages.reserve_create(4096, true)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        parent.file.sync_all()?;
        check()?;
        pages.allocation_completed()?;
        pages.reserve_create(plan.bytes()?.len() as u64, false)?;
        PageStore::create_file_at(&path.join("identity.json"), &plan.bytes()?, check)?;
        pages.allocation_completed()?;
        Self::open(pages, plan, check)
    }
    pub fn open(
        pages: &'a PageStore,
        plan: Plan,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        plan.validate()?;
        pages.check()?;
        check()?;
        if &plan.binding != pages.binding() {
            return Err("tail opener cannot adopt another C authority".into());
        }
        let path = pages.root.join("tails").join(&plan.job);
        let pin = PersistentDirectory::capture(&path)?;
        let value = Self { pages, plan, pin };
        value.check(check)?;
        if pages.read(
            &format!("tails/{}/identity.json", value.plan.job),
            PLAN_BYTES,
            check,
        )? != value.plan.bytes()?
        {
            return Err("tail namespace identity differs from exact selected plan".into());
        }
        value.check(check)?;
        Ok(value)
    }
    fn path(&self, number: u32) -> Result<PathBuf> {
        self.plan.spec(number)?;
        Ok(self
            .pages
            .root
            .join("tails")
            .join(&self.plan.job)
            .join(format!("{number:08x}")))
    }
    fn check(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        self.pages.check()?;
        self.pin.check()?;
        if self.pin.mount != self.pages.pin.mount
            || self.pin.identity.0 != self.pages.pin.identity.0
        {
            return Err("physical tail namespace crossed C mount or backing device".into());
        }
        check()
    }
    fn member(
        &self,
        file: &File,
        path: &Path,
        mode: u32,
        length: u64,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<fs::Metadata> {
        self.check(check)?;
        let parent = MemberParent::capture(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != mode
            || metadata.len() != length
            || metadata.dev() != self.pages.pin.identity.0
            || PersistentDirectory::mount(file)? != self.pages.pin.mount
        {
            return Err(
                "tail slot is not its exact root-owned private inode/length/mode/mount".into(),
            );
        }
        let current = parent.open(path, libc::O_RDONLY, 0)?;
        if file_identity(&current.metadata()?) != file_identity(&metadata)
            || PersistentDirectory::mount(&current)? != self.pages.pin.mount
        {
            return Err("physical tail slot name no longer selects the held inode".into());
        }
        parent.check()?;
        self.check(check)?;
        Ok(metadata)
    }
    fn verify(
        &self,
        file: &File,
        reference: &Reference,
        mode: u32,
        length: u64,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        reference.validate(&self.plan)?;
        let metadata = self.member(file, &self.path(reference.number)?, mode, length, check)?;
        if metadata.dev() != reference.device
            || metadata.ino() != reference.inode
            || instance(file)? != reference.instance_id
            || metadata.blocks().checked_mul(512) != Some(reference.allocated_bytes)
            || (mode == 0o600
                && length == 0
                && (metadata.ctime() != reference.created_ctime_seconds
                    || metadata.ctime_nsec() != reference.created_ctime_nanoseconds))
        {
            return Err(
                "held tail allocation no longer matches the C-selected inode/extents observation"
                    .into(),
            );
        }
        let named = MemberParent::capture(&self.path(reference.number)?)?.open(
            &self.path(reference.number)?,
            libc::O_RDONLY,
            0,
        )?;
        if instance(&named)? != reference.instance_id
            || file_identity(&named.metadata()?) != file_identity(&metadata)
        {
            return Err(
                "named slot xattr/inode does not match its currently held allocation".into(),
            );
        }
        Ok(())
    }
    pub fn allocate_window(
        &self,
        first: u32,
        count: u32,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<Reference>> {
        let end = first
            .checked_add(count)
            .ok_or("tail preparation window overflow")?;
        if count == 0 || count > WINDOW_SLOTS || end > self.plan.slots()? {
            return Err(
                "tail preparation window exceeds fixed sixteen-slot/original plan bounds".into(),
            );
        }
        let mut result = Vec::with_capacity(count as usize);
        for number in first..first + count {
            self.check(check)?;
            let (pool, kind) = self.plan.spec(number)?;
            let capacity = self.plan.capacity(number)?;
            self.pages.reserve_create(capacity, false)?;
            let path = self.path(number)?;
            let parent = MemberParent::capture(&path)?;
            let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatvfs(parent.file.as_raw_fd(), &mut status) } != 0
                || status.f_favail < 2
                || status
                    .f_bavail
                    .checked_mul(status.f_frsize)
                    .ok_or("tail free-space arithmetic overflow")?
                    < capacity + 16 * 1024 * 1024
            {
                return Err(
                    "tail data extents/inodes unavailable before exclusive allocation".into(),
                );
            }
            let file = parent.open(&path, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600)?;
            self.member(&file, &path, 0o600, 0, check)?;
            let instance_id = create_instance(&file)?;
            if instance(&parent.open(&path, libc::O_RDONLY, 0)?)? != instance_id {
                return Err(
                    "new slot name does not select its exact newly created identity marker".into(),
                );
            }
            physical::allocate(&file, usize::try_from(capacity)?, check)?;
            parent.file.sync_all()?;
            let metadata = self.member(&file, &path, 0o600, 0, check)?;
            let reference = Reference {
                schema_version: self.plan.schema_version,
                job: self.plan.job.clone(),
                number,
                pool,
                kind,
                capacity,
                device: metadata.dev(),
                inode: metadata.ino(),
                mount: self.pages.pin.mount,
                allocated_bytes: metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or("tail extent accounting overflow")?,
                instance_id,
                created_ctime_seconds: metadata.ctime(),
                created_ctime_nanoseconds: metadata.ctime_nsec(),
            };
            reference.validate(&self.plan)?;
            self.verify(&file, &reference, 0o600, 0, check)?;
            self.pages.allocation_completed()?;
            result.push(reference);
        }
        self.check(check)?;
        Ok(result)
    }
    /// The caller must select the exact slot membership under current C and
    /// independently revalidate the operation/pool before invoking this storage
    /// primitive. Serialized Reference bytes are never such an authorization.
    pub fn fill(
        &self,
        reference: &Reference,
        expected_pool: Pool,
        bytes: &[u8],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<SealedReference> {
        reference.validate(&self.plan)?;
        if reference.pool != expected_pool
            || bytes.is_empty()
            || bytes.len() as u64 > reference.capacity
        {
            return Err("tail write changes its selected purpose or preallocated capacity".into());
        }
        let path = self.path(reference.number)?;
        let parent = MemberParent::capture(&path)?;
        let mut file = parent.open(&path, libc::O_RDWR, 0)?;
        self.verify(&file, reference, 0o600, 0, check)?;
        let mut written = 0_u64;
        for block in bytes.chunks(4096) {
            self.verify(&file, reference, 0o600, written, check)?;
            file.write_all(block)?;
            written = written
                .checked_add(block.len() as u64)
                .ok_or("tail write length overflow")?;
            self.verify(&file, reference, 0o600, written, check)?;
        }
        file.sync_all()?;
        self.verify(&file, reference, 0o600, written, check)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        parent.file.sync_all()?;
        self.verify(&file, reference, 0o400, written, check)?;
        let sealed_metadata = file.metadata()?;
        // Drop the writable file description before accepting sealed DATA.
        drop(file);
        let sealed = SealedReference {
            slot: reference.clone(),
            bytes: written,
            sha256: hash(bytes),
            sealed_ctime_seconds: sealed_metadata.ctime(),
            sealed_ctime_nanoseconds: sealed_metadata.ctime_nsec(),
        };
        if self.read(&sealed, check)? != bytes {
            return Err("sealed physical tail readback differs".into());
        }
        Ok(sealed)
    }
    pub fn require_unfilled(
        &self,
        reference: &Reference,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        reference.validate(&self.plan)?;
        let path = self.path(reference.number)?;
        let file = MemberParent::capture(&path)?.open(&path, libc::O_RDONLY, 0)?;
        self.verify(&file, reference, 0o600, 0, check)
    }
    /// Kernel allocation/identity observation only. A caller must separately
    /// prove current ledger membership and a typed spent disposition before a
    /// partially written or retired inode can be accounted as such.
    pub fn observe_allocation(
        &self,
        reference: &Reference,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<(u64, u64, u32)> {
        reference.validate(&self.plan)?;
        let path = self.path(reference.number)?;
        let file = MemberParent::capture(&path)?.open(&path, libc::O_RDONLY, 0)?;
        let before = file.metadata()?;
        let mode = before.mode() & 0o7777;
        if (mode != 0o600 && mode != 0o400)
            || before.len() > reference.capacity
            || (mode == 0o400 && before.len() == 0)
        {
            return Err("physical slot observation has invalid state/mode/length".into());
        }
        self.verify(&file, reference, mode, before.len(), check)?;
        if file_identity(&file.metadata()?) != file_identity(&before) {
            return Err("physical slot observation changed across validation".into());
        }
        check()?;
        Ok((before.len(), reference.allocated_bytes, mode))
    }
    pub fn read(
        &self,
        sealed: &SealedReference,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        sealed.validate(&self.plan)?;
        let path = self.path(sealed.slot.number)?;
        let parent = MemberParent::capture(&path)?;
        let mut file = parent.open(&path, libc::O_RDONLY, 0)?;
        self.verify_sealed(&file, sealed, check)?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(usize::try_from(sealed.bytes)?);
        let mut block = [0_u8; 4096];
        while (bytes.len() as u64) < sealed.bytes {
            self.verify_sealed(&file, sealed, check)?;
            let count = file.read(
                &mut block[..usize::try_from(sealed.bytes - bytes.len() as u64)?.min(4096)],
            )?;
            if count == 0 {
                return Err("sealed tail slot ended before its full committed data".into());
            }
            bytes.extend_from_slice(&block[..count]);
        }
        let mut extra = [0_u8; 1];
        if file.read(&mut extra)? != 0 || hash(&bytes) != sealed.sha256 {
            return Err("sealed tail data hash or exact EOF differs".into());
        }
        self.verify_sealed(&file, sealed, check)?;
        Ok(bytes)
    }
    fn verify_sealed(
        &self,
        file: &File,
        sealed: &SealedReference,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.verify(file, &sealed.slot, 0o400, sealed.bytes, check)?;
        let metadata = file.metadata()?;
        if metadata.ctime() != sealed.sealed_ctime_seconds
            || metadata.ctime_nsec() != sealed.sealed_ctime_nanoseconds
        {
            return Err(
                "sealed tail inode change-time differs from selected immutable seal".into(),
            );
        }
        self.check(check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan::fixed(
            &luma_content_store::v2::custody_map::CustodyBinding {
                installation: "11".repeat(32),
                sealed_genesis_sha256: "22".repeat(32),
            },
            &"33".repeat(32),
            256,
        )
        .unwrap()
    }
    #[test]
    fn exact_layout_preserves_reviewed_order_and_allocates_only_rounded_current_outputs() {
        let old = plan();
        let slots = vec![
            ExactSlot::for_bytes(Pool::Publication(0), Kind::Record, 31).unwrap(),
            ExactSlot::for_bytes(Pool::Publication(0), Kind::Page, 4097).unwrap(),
            ExactSlot::for_bytes(Pool::Terminal, Kind::Control, 1).unwrap(),
        ];
        let exact = Plan::exact(&old.binding, &old.job, slots).unwrap();
        assert_eq!(exact.slots().unwrap(), 3);
        assert_eq!(exact.capacity(0).unwrap(), 4096);
        assert_eq!(exact.capacity(1).unwrap(), 8192);
        assert_eq!(exact.capacity(2).unwrap(), 4096);
        assert_eq!(exact.spec(2).unwrap(), (Pool::Terminal, Kind::Control));
        let decoded: Plan = canonical(&exact.bytes().unwrap(), PLAN_BYTES).unwrap();
        assert_eq!(decoded, exact);
        let mut changed = exact.clone();
        changed.exact.as_mut().unwrap().swap(0, 1);
        assert_ne!(changed.bytes().unwrap(), exact.bytes().unwrap());
        assert!(exact.spec(3).is_err());
        assert!(ExactSlot::for_bytes(Pool::Terminal, Kind::Page, 0).is_err());
        assert!(ExactSlot::for_bytes(Pool::Terminal, Kind::Page, u64::MAX).is_err());
        assert!(ExactSlot::for_bytes(Pool::Publication(256), Kind::Page, 1).is_err());
        assert!(ExactSlot::for_bytes(Pool::Terminal, Kind::Page, PAGE_BYTES as u64 + 1).is_err());
        assert!(Plan::exact(&old.binding, &old.job, vec![]).is_err());
        assert!(Plan::exact(
            &old.binding,
            &old.job,
            vec![ExactSlot::for_bytes(Pool::Terminal, Kind::Page, 1).unwrap(); MAX_EXACT_SLOTS + 1]
        )
        .is_err());
        let mut changed = old.clone();
        changed.exact = exact.exact;
        assert!(changed.validate().is_err());
        assert!(!String::from_utf8(old.bytes().unwrap())
            .unwrap()
            .contains("exact"));
    }
    #[test]
    fn fixed_tail_plan_separates_every_publication_from_independent_terminal_capacity() {
        let plan = plan();
        assert_eq!(plan.slots().unwrap(), 257 * PER_POOL);
        assert_eq!(plan.spec(0).unwrap(), (Pool::Publication(0), Kind::Page));
        assert_eq!(
            plan.spec(PAGE_SLOTS).unwrap(),
            (Pool::Publication(0), Kind::Record)
        );
        assert_eq!(
            plan.spec(PER_POOL - 1).unwrap(),
            (Pool::Publication(0), Kind::Control)
        );
        assert_eq!(
            plan.spec(256 * PER_POOL).unwrap(),
            (Pool::Terminal, Kind::Page)
        );
        assert!(plan.spec(plan.slots().unwrap()).is_err());
        let mut changed = plan.clone();
        changed.outcomes = 257;
        assert!(changed.validate().is_err());
        changed.outcomes = 0;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn slot_reference_cannot_change_pool_kind_capacity_or_claim_unallocated_extents() {
        let plan = plan();
        let reference = Reference {
            schema_version: 3,
            job: plan.job.clone(),
            number: 0,
            pool: Pool::Publication(0),
            kind: Kind::Page,
            capacity: PAGE_BYTES as u64,
            device: 1,
            inode: 2,
            mount: 3,
            allocated_bytes: PAGE_BYTES as u64,
            instance_id: "55".repeat(32),
            created_ctime_seconds: 1,
            created_ctime_nanoseconds: 0,
        };
        reference.validate(&plan).unwrap();
        for changed in [
            Reference {
                pool: Pool::Terminal,
                ..reference.clone()
            },
            Reference {
                kind: Kind::Control,
                ..reference.clone()
            },
            Reference {
                capacity: 1,
                ..reference.clone()
            },
            Reference {
                allocated_bytes: 0,
                ..reference.clone()
            },
            Reference {
                inode: 0,
                ..reference.clone()
            },
        ] {
            assert!(changed.validate(&plan).is_err());
        }
        assert!(SealedReference {
            slot: reference.clone(),
            bytes: 0,
            sha256: "44".repeat(32),
            sealed_ctime_seconds: 1,
            sealed_ctime_nanoseconds: 0
        }
        .validate(&plan)
        .is_err());
        assert!(SealedReference {
            slot: reference,
            bytes: PAGE_BYTES as u64 + 1,
            sha256: "44".repeat(32),
            sealed_ctime_seconds: 1,
            sealed_ctime_nanoseconds: 0
        }
        .validate(&plan)
        .is_err());
    }
}
