use super::*;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const GROUP: usize = 64;
const MAX_OBJECTS: u64 = 4_194_304;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlobReference {
    pub schema_version: u32,
    pub domain: String,
    pub binding: OwnerBinding,
    pub sha256: String,
    pub bytes: u64,
    pub chunk_count: u32,
    pub index_sha256: Option<String>,
}
impl BlobReference {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        digest(&self.sha256)?;
        if self.schema_version != 1
            || self.domain != DOMAIN
            || self.bytes > MAX_SEGMENT_BYTES
            || u64::from(self.chunk_count)
                != (self.bytes + MAX_PAGE_BYTES as u64 - 1) / MAX_PAGE_BYTES as u64
        {
            return Err("invalid v2 bounded blob descriptor".into());
        }
        match &self.index_sha256 {
            None if self.bytes == 0 && self.sha256 == luma_content::sha256(&[]) => Ok(()),
            Some(hash) if self.bytes > 0 => digest(hash),
            _ => Err("v2 blob index/empty commitment mismatch".into()),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Chunk {
    sha256: String,
    bytes: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChunkGroup {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    chunks: Vec<Chunk>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GroupRef {
    sha256: String,
    bytes: u64,
    chunks: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BlobIndex {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    groups: Vec<GroupRef>,
}

/// Measured physical file state, including interrupted/unselected objects. It is
/// not an accounting reservation or permission to discard any retained object.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Allocation {
    pub relative_path: String,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub allocated_bytes: u64,
    pub complete: bool,
}
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PhysicalInventory {
    pub regular_files: u64,
    pub directories: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub incomplete_objects: u64,
}

/// Held same-ext4 immutable-object namespace. Opening it does not select any
/// map, establish current custody, initialize an absent owner or authorize GC.
pub struct ObjectStore {
    pub(super) binding: OwnerBinding,
    base: File,
    root: File,
    objects: File,
    identity: File,
    identity_pin: (u64, u64, u64, i64, i64, i64, i64, u32),
    name: String,
    base_path: PathBuf,
    mount_id: u64,
}
fn pin(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
    )
}
fn same(a: &File, b: &File) -> Result<bool> {
    let am = a.metadata()?;
    let bm = b.metadata()?;
    Ok(am.dev() == bm.dev() && am.ino() == bm.ino() && mount(a)? == mount(b)?)
}
fn mount(file: &File) -> Result<u64> {
    let mut value: libc::statx = unsafe { std::mem::zeroed() };
    let empty = std::ffi::CString::new("")?;
    const MASK: u32 = 0x1000;
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            MASK,
            &mut value,
        )
    } != 0
        || value.stx_mask & MASK == 0
        || value.stx_mnt_id == 0
    {
        return Err("v2 requires actual held mount identity".into());
    }
    Ok(value.stx_mnt_id)
}
fn read_member<B: Boundary>(
    directory: &File,
    name: &str,
    limit: usize,
    mount_id: u64,
    guard: &mut Guard<'_, B>,
    mut namespace: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    guard.check()?;
    namespace()?;
    let mut file = crate::storage::open(directory, name, libc::O_RDONLY, 0)?;
    crate::storage::check_private(&file, false)?;
    let before = file.metadata()?;
    let expected = pin(&before);
    if before.mode() & 0o7777 != 0o400 || before.len() > limit as u64 || mount(&file)? != mount_id {
        return Err("v2 held read file mode/length/mount invalid".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut block = [0_u8; 4096];
    loop {
        namespace()?;
        guard.check()?;
        let named = crate::storage::open(directory, name, libc::O_RDONLY, 0)?;
        if pin(&file.metadata()?) != expected
            || pin(&named.metadata()?) != expected
            || mount(&named)? != mount_id
        {
            return Err("v2 held file changed before private read".into());
        }
        let remaining = (before.len() as usize).saturating_sub(bytes.len());
        let capacity = remaining.min(block.len()).max(1);
        // Reserve capacity BEFORE read on this exact held FD, including the
        // final one-byte EOF probe. Replacement cannot enlarge this allowance.
        guard.read(capacity as u64)?;
        let count = file.read(&mut block[..capacity])?;
        guard.check()?;
        namespace()?;
        if count == 0 {
            if remaining != 0 {
                return Err("v2 held file shortened".into());
            }
            break;
        }
        if remaining == 0 || count > remaining {
            return Err("v2 held file grew past exact length".into());
        }
        bytes.extend_from_slice(&block[..count]);
    }
    let named = crate::storage::open(directory, name, libc::O_RDONLY, 0)?;
    if bytes.len() as u64 != before.len()
        || pin(&file.metadata()?) != expected
        || pin(&named.metadata()?) != expected
        || mount(&named)? != mount_id
        || mount(&file)? != mount_id
    {
        return Err("v2 immutable held file changed during read".into());
    }
    guard.check()?;
    namespace()?;
    Ok(bytes)
}
struct Leaf {
    first: File,
    second: File,
    a: String,
    b: String,
}
impl Leaf {
    fn check(&self, store: &ObjectStore) -> Result<()> {
        store.check()?;
        for file in [&self.first, &self.second] {
            crate::storage::check_private(file, true)?;
            if mount(file)? != store.mount_id {
                return Err("v2 object prefix mount changed".into());
            }
        }
        if !same(
            &self.first,
            &crate::storage::directory(&store.objects, &self.a)?,
        )? || !same(
            &self.second,
            &crate::storage::directory(&self.first, &self.b)?,
        )? {
            return Err("v2 held object prefix namespace changed".into());
        }
        Ok(())
    }
}
impl ObjectStore {
    pub(super) fn name(binding: &OwnerBinding) -> Result<String> {
        binding.validate()?;
        Ok(format!(
            "v2-{}",
            luma_content::sha256(&serde_json::to_vec(&(DOMAIN, binding))?)
        ))
    }
    /// Explicitly create data only. An existing namespace (including damaged or
    /// interrupted initialization) refuses; callers cannot use absence as C.
    pub fn create_at(
        base: &Path,
        binding: &OwnerBinding,
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        let mut guard = Guard::new(boundary, binding, budget, Some(mutation))?;
        let base_path = base.to_path_buf();
        let base = crate::storage::base(base)?;
        let mount_id = mount(&base)?;
        let name = Self::name(binding)?;
        guard.write(0)?;
        let root = crate::storage::mkdir(&base, &name)?;
        guard.check()?;
        guard.write(0)?;
        let objects = crate::storage::mkdir(&root, "objects")?;
        let bytes = serde_json::to_vec(&Identity {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: binding.clone(),
        })?;
        guard.write(bytes.len() as u64)?;
        crate::storage::write(&root, "identity.json", &bytes, &mut || guard.check())?;
        let identity = crate::storage::open(&root, "identity.json", libc::O_RDONLY, 0)?;
        let identity_pin = pin(&identity.metadata()?);
        guard.check()?;
        let store = Self {
            binding: binding.clone(),
            base,
            root,
            objects,
            identity,
            identity_pin,
            name,
            base_path,
            mount_id,
        };
        store.check()?;
        Ok(store)
    }
    pub fn open_at(
        base: &Path,
        binding: &OwnerBinding,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        let mut guard = Guard::new(boundary, binding, budget, None)?;
        let base_path = base.to_path_buf();
        let base = crate::storage::base(base)?;
        let mount_id = mount(&base)?;
        let name = Self::name(binding)?;
        let root = crate::storage::directory(&base, &name)?;
        let objects = crate::storage::directory(&root, "objects")?;
        let identity = crate::storage::open(&root, "identity.json", libc::O_RDONLY, 0)?;
        let identity_pin = pin(&identity.metadata()?);
        guard.check()?;
        let store = Self {
            binding: binding.clone(),
            base,
            root,
            objects,
            identity,
            identity_pin,
            name,
            base_path,
            mount_id,
        };
        let bytes = read_member(
            &store.root,
            "identity.json",
            4096,
            mount_id,
            &mut guard,
            || store.check(),
        )?;
        let actual: Identity = canonical(&bytes, 4096)?;
        if actual
            != (Identity {
                schema_version: 1,
                domain: DOMAIN.into(),
                binding: binding.clone(),
            })
        {
            return Err("v2 immutable namespace identity differs".into());
        }
        store.check()?;
        Ok(store)
    }
    fn check(&self) -> Result<()> {
        for file in [&self.base, &self.root, &self.objects] {
            crate::storage::check_private(file, true)?;
            if mount(file)? != self.mount_id {
                return Err("v2 held namespace mount changed".into());
            }
        }
        if crate::storage::names(&self.root, 2)? != ["identity.json", "objects"] {
            return Err("v2 root contains an unknown or missing retained member".into());
        }
        let current_base = crate::storage::base(&self.base_path)?;
        if !same(&self.base, &current_base)?
            || mount(&current_base)? != self.mount_id
            || !same(
                &self.root,
                &crate::storage::directory(&self.base, &self.name)?,
            )?
            || !same(
                &self.objects,
                &crate::storage::directory(&self.root, "objects")?,
            )?
            || pin(&self.identity.metadata()?) != self.identity_pin
            || pin(
                &crate::storage::open(&self.root, "identity.json", libc::O_RDONLY, 0)?
                    .metadata()?,
            ) != self.identity_pin
        {
            return Err("v2 namespace/identity changed".into());
        }
        Ok(())
    }
    fn leaf<B: Boundary>(
        &self,
        hash: &str,
        create: bool,
        guard: &mut Guard<'_, B>,
    ) -> Result<Leaf> {
        digest(hash)?;
        self.check()?;
        guard.check()?;
        let mut current = self.objects.try_clone()?;
        let mut first = None;
        for component in [&hash[..2], &hash[2..4]] {
            let opened = crate::storage::directory(&current, component);
            current = match opened {
                Ok(file) => file,
                Err(error) => {
                    if !create
                        || error
                            .downcast_ref::<std::io::Error>()
                            .map_or(true, |e| e.kind() != std::io::ErrorKind::NotFound)
                    {
                        return Err(error);
                    }
                    guard.write(0)?;
                    match crate::storage::mkdir(&current, component) {
                        Ok(file) => file,
                        Err(error) => {
                            if error
                                .downcast_ref::<std::io::Error>()
                                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
                            {
                                crate::storage::directory(&current, component)?
                            } else {
                                return Err(error);
                            }
                        }
                    }
                }
            };
            if first.is_none() {
                first = Some(current.try_clone()?);
            }
        }
        let leaf = Leaf {
            first: first.ok_or("v2 missing prefix")?,
            second: current,
            a: hash[..2].into(),
            b: hash[2..4].into(),
        };
        leaf.check(self)?;
        guard.check()?;
        Ok(leaf)
    }
    pub(super) fn read_object<B: Boundary>(
        &self,
        hash: &str,
        limit: usize,
        guard: &mut Guard<'_, B>,
    ) -> Result<Vec<u8>> {
        if limit == 0 || limit > MAX_PAGE_BYTES {
            return Err("v2 object read bound invalid".into());
        }
        self.check()?;
        let leaf = self.leaf(hash, false, guard)?;
        let bytes = read_member(&leaf.second, hash, limit, self.mount_id, guard, || {
            leaf.check(self)
        })?;
        leaf.check(self)?;
        if bytes.is_empty() || luma_content::sha256(&bytes) != hash {
            return Err("v2 object hash/length mismatch".into());
        }
        guard.check()?;
        Ok(bytes)
    }
    pub(super) fn write_object<B: Boundary>(
        &self,
        bytes: &[u8],
        guard: &mut Guard<'_, B>,
    ) -> Result<String> {
        if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
            return Err("v2 object write bound invalid".into());
        }
        self.check()?;
        guard.check()?;
        let hash = luma_content::sha256(bytes);
        let leaf = self.leaf(&hash, true, guard)?;
        match crate::storage::open(&leaf.second, &hash, libc::O_RDONLY, 0) {
            Ok(_) => {
                if self.read_object(&hash, MAX_PAGE_BYTES, guard)? != bytes {
                    return Err("v2 existing object differs".into());
                }
                return Ok(hash);
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        guard.write(bytes.len() as u64)?;
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(leaf.second.as_raw_fd(), &mut space) } != 0
            || space.f_favail < 2
            || space
                .f_bavail
                .checked_mul(space.f_frsize)
                .ok_or("v2 available space overflow")?
                < bytes.len() as u64 + 16 * 1024 * 1024
        {
            return Err("v2 physical block/inode reserve unavailable".into());
        }
        leaf.check(self)?;
        let mut file = crate::storage::open(
            &leaf.second,
            &hash,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o400,
        )?;
        for part in bytes.chunks(4096) {
            guard.check()?;
            leaf.check(self)?;
            file.write_all(part)?;
            guard.check()?;
        }
        file.sync_all()?;
        leaf.second.sync_all()?;
        leaf.check(self)?;
        guard.check()?;
        if self.read_object(&hash, MAX_PAGE_BYTES, guard)? != bytes {
            return Err("v2 synchronized object readback differs".into());
        }
        Ok(hash)
    }
    /// Bounded in-memory blob construction; no object exceeds 16KiB. Empty data
    /// has its exact SHA and no invented empty on-disk object.
    pub fn prepare_blob(
        &self,
        bytes: &[u8],
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut impl Boundary,
    ) -> Result<BlobReference> {
        let mut guard = Guard::new(boundary, &self.binding, budget, Some(mutation))?;
        let value = self.put_blob(bytes, &mut guard)?;
        guard.check()?;
        Ok(value)
    }
    /// Opaque bounded derivative page DATA; no authority or selectable index.
    pub fn prepare_page(
        &self,
        bytes: &[u8],
        budget: IoBudget,
        mutation: &Mutation,
        boundary: &mut impl Boundary,
    ) -> Result<String> {
        let mut guard = Guard::new(boundary, &self.binding, budget, Some(mutation))?;
        let hash = self.write_object(bytes, &mut guard)?;
        guard.check()?;
        Ok(hash)
    }
    pub fn read_page(
        &self,
        sha256: &str,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<Vec<u8>> {
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let bytes = self.read_object(sha256, MAX_PAGE_BYTES, &mut guard)?;
        guard.check()?;
        Ok(bytes)
    }
    pub(super) fn put_blob<B: Boundary>(
        &self,
        bytes: &[u8],
        guard: &mut Guard<'_, B>,
    ) -> Result<BlobReference> {
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return Err("v2 blob exceeds finite segment bound".into());
        }
        let mut groups = Vec::new();
        let mut chunks = Vec::new();
        let mut count = 0_u32;
        for part in bytes.chunks(MAX_PAGE_BYTES) {
            chunks.push(Chunk {
                sha256: self.write_object(part, guard)?,
                bytes: part.len() as u32,
            });
            count += 1;
            if chunks.len() == GROUP {
                groups.push(self.put_group(std::mem::take(&mut chunks), guard)?);
            }
        }
        if !chunks.is_empty() {
            groups.push(self.put_group(chunks, guard)?);
        }
        let index = if groups.is_empty() {
            None
        } else {
            let bytes = serde_json::to_vec(&BlobIndex {
                schema_version: 1,
                domain: DOMAIN.into(),
                binding: self.binding.clone(),
                groups,
            })?;
            Some(self.write_object(&bytes, guard)?)
        };
        let value = BlobReference {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: self.binding.clone(),
            sha256: luma_content::sha256(bytes),
            bytes: bytes.len() as u64,
            chunk_count: count,
            index_sha256: index,
        };
        value.validate()?;
        Ok(value)
    }
    fn put_group<B: Boundary>(
        &self,
        chunks: Vec<Chunk>,
        guard: &mut Guard<'_, B>,
    ) -> Result<GroupRef> {
        let bytes = chunks.iter().map(|c| u64::from(c.bytes)).sum();
        let count = chunks.len() as u32;
        let encoded = serde_json::to_vec(&ChunkGroup {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: self.binding.clone(),
            chunks,
        })?;
        Ok(GroupRef {
            sha256: self.write_object(&encoded, guard)?,
            bytes,
            chunks: count,
        })
    }
    pub fn read_blob(
        &self,
        reference: &BlobReference,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<Vec<u8>> {
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let result = self.get_blob(reference, &mut guard)?;
        guard.check()?;
        Ok(result)
    }
    pub(super) fn get_blob<B: Boundary>(
        &self,
        reference: &BlobReference,
        guard: &mut Guard<'_, B>,
    ) -> Result<Vec<u8>> {
        let bytes = self.blob_range(reference, 0, reference.bytes, guard)?;
        if luma_content::sha256(&bytes) != reference.sha256 {
            return Err("v2 whole blob commitment differs".into());
        }
        Ok(bytes)
    }
    /// Verifies the selected Merkle chunk/index path for exact bounded offsets;
    /// whole-source Read must instead use read_blob's complete content SHA.
    pub fn read_blob_range(
        &self,
        reference: &BlobReference,
        offset: u64,
        length: u64,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<Vec<u8>> {
        if length > MAX_PAGE_BYTES as u64 {
            return Err("v2 snippet range exceeds one page".into());
        }
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        let bytes = self.blob_range(reference, offset, length, &mut guard)?;
        guard.check()?;
        Ok(bytes)
    }
    fn blob_range<B: Boundary>(
        &self,
        reference: &BlobReference,
        offset: u64,
        length: u64,
        guard: &mut Guard<'_, B>,
    ) -> Result<Vec<u8>> {
        reference.validate()?;
        self.check()?;
        if reference.binding != self.binding
            || offset
                .checked_add(length)
                .map_or(true, |end| end > reference.bytes)
        {
            return Err("v2 blob owner/range mismatch".into());
        }
        if reference.bytes == 0 {
            guard.check()?;
            return Ok(Vec::new());
        }
        let index_bytes = self.read_object(
            reference
                .index_sha256
                .as_ref()
                .ok_or("v2 blob index missing")?,
            MAX_PAGE_BYTES,
            guard,
        )?;
        let index: BlobIndex = canonical(&index_bytes, MAX_PAGE_BYTES)?;
        if index.schema_version != 1
            || index.domain != DOMAIN
            || index.binding != self.binding
            || index.groups.is_empty()
            || index.groups.len() > GROUP
        {
            return Err("v2 blob index identity/fanout invalid".into());
        }
        let mut total = 0_u64;
        let mut chunk_count = 0_u32;
        for (number, group) in index.groups.iter().enumerate() {
            digest(&group.sha256)?;
            if group.chunks == 0
                || group.chunks > GROUP as u32
                || (number + 1 < index.groups.len() && group.chunks != GROUP as u32)
                || group.bytes == 0
                || group.bytes > u64::from(group.chunks) * MAX_PAGE_BYTES as u64
                || group.bytes <= u64::from(group.chunks - 1) * MAX_PAGE_BYTES as u64
                || (number + 1 < index.groups.len()
                    && group.bytes != u64::from(group.chunks) * MAX_PAGE_BYTES as u64)
            {
                return Err("v2 blob group coverage invalid".into());
            }
            total = total
                .checked_add(group.bytes)
                .ok_or("v2 blob byte overflow")?;
            chunk_count = chunk_count
                .checked_add(group.chunks)
                .ok_or("v2 blob count overflow")?;
        }
        if total != reference.bytes || chunk_count != reference.chunk_count {
            return Err("v2 blob index coverage differs".into());
        }
        let mut result = Vec::with_capacity(length as usize);
        let end = offset + length;
        let mut group_offset = 0_u64;
        for group in index.groups {
            let group_end = group_offset + group.bytes;
            if length > 0 && offset < group_end && group_offset < end {
                let bytes = self.read_object(&group.sha256, MAX_PAGE_BYTES, guard)?;
                let actual: ChunkGroup = canonical(&bytes, MAX_PAGE_BYTES)?;
                if actual.schema_version != 1
                    || actual.domain != DOMAIN
                    || actual.binding != self.binding
                    || actual.chunks.len() != group.chunks as usize
                {
                    return Err("v2 chunk group identity/count differs".into());
                }
                let mut position = group_offset;
                for (number, chunk) in actual.chunks.iter().enumerate() {
                    digest(&chunk.sha256)?;
                    if chunk.bytes == 0
                        || chunk.bytes > MAX_PAGE_BYTES as u32
                        || (number + 1 < actual.chunks.len()
                            && chunk.bytes != MAX_PAGE_BYTES as u32)
                    {
                        return Err("v2 chunk size invalid".into());
                    }
                    let next = position + u64::from(chunk.bytes);
                    if offset < next && position < end {
                        let bytes = self.read_object(&chunk.sha256, MAX_PAGE_BYTES, guard)?;
                        if bytes.len() != chunk.bytes as usize {
                            return Err("v2 chunk committed length differs".into());
                        }
                        result.extend_from_slice(
                            &bytes[(offset.saturating_sub(position)) as usize
                                ..(end.min(next) - position) as usize],
                        );
                    }
                    position = next;
                }
                if position != group_end {
                    return Err("v2 chunk group byte coverage differs".into());
                }
            }
            group_offset = group_end;
        }
        if result.len() as u64 != length {
            return Err("v2 blob range coverage differs".into());
        }
        guard.check()?;
        Ok(result)
    }
    /// Explicit full physical audit, including valid-hash-named partial writes.
    /// Every member is retained; this method never adopts, selects or removes it.
    pub fn inventory(
        &self,
        budget: IoBudget,
        boundary: &mut impl Boundary,
        mut visitor: impl FnMut(Allocation) -> Result<()>,
    ) -> Result<PhysicalInventory> {
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        self.check()?;
        let mut result = PhysicalInventory::default();
        let objects_pin = pin(&self.objects.metadata()?);
        let root_pin = pin(&self.root.metadata()?);
        for file in [&self.root, &self.objects] {
            let m = file.metadata()?;
            result.directories += 1;
            result.allocated_bytes = result
                .allocated_bytes
                .checked_add(m.blocks() * 512)
                .ok_or("v2 allocation overflow")?;
        }
        let identity = self.identity.metadata()?;
        result.regular_files = 1;
        result.logical_bytes = identity.len();
        result.allocated_bytes += identity.blocks() * 512;
        for first in fs::read_dir(format!("/proc/self/fd/{}", self.objects.as_raw_fd()))? {
            guard.check()?;
            let first = first?
                .file_name()
                .into_string()
                .map_err(|_| "v2 nonUTF8 prefix")?;
            prefix(&first)?;
            let a = crate::storage::directory(&self.objects, &first)?;
            charge_dir(&a, &mut result)?;
            let a_pin = pin(&a.metadata()?);
            for second in fs::read_dir(format!("/proc/self/fd/{}", a.as_raw_fd()))? {
                guard.check()?;
                let second = second?
                    .file_name()
                    .into_string()
                    .map_err(|_| "v2 nonUTF8 prefix")?;
                prefix(&second)?;
                let b = crate::storage::directory(&a, &second)?;
                charge_dir(&b, &mut result)?;
                let b_pin = pin(&b.metadata()?);
                for entry in fs::read_dir(format!("/proc/self/fd/{}", b.as_raw_fd()))? {
                    guard.check()?;
                    self.check()?;
                    let name = entry?
                        .file_name()
                        .into_string()
                        .map_err(|_| "v2 nonUTF8 object")?;
                    digest(&name)?;
                    if name[..2] != first || name[2..4] != second {
                        return Err("v2 misplaced object name".into());
                    }
                    let bytes =
                        read_member(&b, &name, MAX_PAGE_BYTES, self.mount_id, &mut guard, || {
                            self.check()?;
                            if !same(&a, &crate::storage::directory(&self.objects, &first)?)?
                                || !same(&b, &crate::storage::directory(&a, &second)?)?
                                || mount(&a)? != self.mount_id
                                || mount(&b)? != self.mount_id
                            {
                                return Err("v2 audited prefix moved".into());
                            }
                            Ok(())
                        })?;
                    let file = crate::storage::open(&b, &name, libc::O_RDONLY, 0)?;
                    let m = file.metadata()?;
                    let complete = !bytes.is_empty() && luma_content::sha256(&bytes) == name;
                    result.regular_files += 1;
                    if result.regular_files > MAX_OBJECTS {
                        return Err("v2 physical namespace inode ceiling exceeded".into());
                    }
                    result.logical_bytes = result
                        .logical_bytes
                        .checked_add(m.len())
                        .ok_or("v2 logical byte overflow")?;
                    result.allocated_bytes = result
                        .allocated_bytes
                        .checked_add(m.blocks() * 512)
                        .ok_or("v2 allocated byte overflow")?;
                    if !complete {
                        result.incomplete_objects += 1;
                    }
                    visitor(Allocation {
                        relative_path: format!("objects/{first}/{second}/{name}"),
                        device: m.dev(),
                        inode: m.ino(),
                        bytes: m.len(),
                        allocated_bytes: m.blocks() * 512,
                        complete,
                    })?;
                    guard.check()?;
                }
                if b_pin != pin(&b.metadata()?)
                    || !same(&b, &crate::storage::directory(&a, &second)?)?
                    || mount(&b)? != self.mount_id
                {
                    return Err("v2 physical inventory changed during leaf audit".into());
                }
            }
            if a_pin != pin(&a.metadata()?)
                || !same(&a, &crate::storage::directory(&self.objects, &first)?)?
                || mount(&a)? != self.mount_id
            {
                return Err("v2 physical inventory changed during prefix audit".into());
            }
        }
        if objects_pin != pin(&self.objects.metadata()?)
            || root_pin != pin(&self.root.metadata()?)
        {
            return Err("v2 physical inventory changed during audit".into());
        }
        self.check()?;
        guard.check()?;
        Ok(result)
    }
}
fn prefix(value: &str) -> Result<()> {
    if value.len() != 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("v2 noncanonical object prefix".into());
    }
    Ok(())
}
fn charge_dir(file: &File, result: &mut PhysicalInventory) -> Result<()> {
    let m = file.metadata()?;
    result.directories += 1;
    if result.directories > 2 + 256 + 65536 {
        return Err("v2 directory ceiling exceeded".into());
    }
    result.allocated_bytes = result
        .allocated_bytes
        .checked_add(m.blocks() * 512)
        .ok_or("v2 directory allocation overflow")?;
    Ok(())
}
