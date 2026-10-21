//! Bounded read-only observations of raw immutable-object DATA. Neither an
//! observation nor absence is a selected head, a grant or a creator witness.
//! Held values cannot be deserialized, cloned or converted into write access.
use super::*;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedFileData {
    pub device: u64,
    pub inode: u64,
    pub mount_id: u64,
    pub bytes: u64,
    pub allocated_bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}
impl ObservedFileData {
    fn capture(file: &File) -> Result<Self> {
        let before = file.metadata()?;
        let value = Self::metadata(&before, mount(file)?)?;
        if Self::metadata(&file.metadata()?, value.mount_id)? != value {
            return Err("held observation metadata changed during capture".into());
        }
        Ok(value)
    }
    fn metadata(m: &fs::Metadata, mount_id: u64) -> Result<Self> {
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            mount_id,
            bytes: m.len(),
            allocated_bytes: m
                .blocks()
                .checked_mul(512)
                .ok_or("observation allocation overflow")?,
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
        })
    }
    fn same_directory(&self, file: &File) -> Result<()> {
        crate::storage::check_private(file, true)?;
        let actual = Self::capture(file)?;
        if (
            actual.device,
            actual.inode,
            actual.mount_id,
            actual.uid,
            actual.gid,
            actual.mode,
        ) != (
            self.device,
            self.inode,
            self.mount_id,
            self.uid,
            self.gid,
            self.mode,
        ) {
            return Err("observed directory held identity changed".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceObservationData {
    pub schema_version: u32,
    pub binding: OwnerBinding,
    pub root: ObservedFileData,
    pub objects: ObservedFileData,
    pub identity: ObservedFileData,
    pub identity_sha256: String,
}
/// Retains fresh read-only namespace OFDs and the actual identity FD. No writer
/// lock is acquired: this cannot prove another process's creation/exclusion.
struct NamespaceHeld {
    root: File,
    objects: File,
    identity: File,
    data: NamespaceObservationData,
}
pub struct HeldNamespaceObservation {
    held: Arc<NamespaceHeld>,
}
impl HeldNamespaceObservation {
    pub fn data(&self) -> &NamespaceObservationData {
        &self.held.data
    }
    fn metadata(&self, store: &ObjectStore) -> Result<()> {
        store.check()?;
        if self.held.data.binding != store.binding
            || !same(&self.held.root, &store.root)?
            || !same(&self.held.objects, &store.objects)?
        {
            return Err("observation belongs to a different held namespace".into());
        }
        self.held.data.root.same_directory(&self.held.root)?;
        self.held.data.objects.same_directory(&self.held.objects)?;
        if ObservedFileData::capture(&self.held.identity)? != self.held.data.identity {
            return Err("observed held identity file changed".into());
        }
        let named = crate::storage::open(&store.root, "identity.json", libc::O_RDONLY, 0)?;
        if ObservedFileData::capture(&named)? != self.held.data.identity {
            return Err("observed named identity file changed".into());
        }
        Ok(())
    }
    fn current<B: Boundary>(&self, store: &ObjectStore, guard: &mut Guard<'_, B>) -> Result<()> {
        self.metadata(store)?;
        let bytes = read_held(
            &self.held.identity,
            &self.held.data.identity,
            &store.root,
            "identity.json",
            4096,
            guard,
            || self.metadata(store),
        )?;
        if luma_content::sha256(&bytes) != self.held.data.identity_sha256 {
            return Err("observed namespace identity content changed".into());
        }
        guard.check()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RawObjectObservationData {
    Absent {
        object_sha256: String,
        namespace_sha256: String,
        missing_component: u8,
        nearest_ancestor: ObservedFileData,
    },
    Present {
        object_sha256: String,
        namespace_sha256: String,
        actual_sha256: String,
        complete: bool,
        file: ObservedFileData,
    },
}
struct Prefixes {
    first: Option<File>,
    second: Option<File>,
}
impl Prefixes {
    fn parent<'a>(&'a self, namespace: &'a HeldNamespaceObservation) -> &'a File {
        self.second
            .as_ref()
            .or(self.first.as_ref())
            .unwrap_or(&namespace.held.objects)
    }
    fn check(&self, store: &ObjectStore, hash: &str) -> Result<()> {
        if let Some(first) = &self.first {
            let named = crate::storage::directory(&store.objects, &hash[..2])?;
            if !same(first, &named)? {
                return Err("observed first prefix replaced".into());
            }
            crate::storage::check_private(first, true)?;
        }
        if let Some(second) = &self.second {
            let first = self
                .first
                .as_ref()
                .ok_or("observed second prefix lacks parent")?;
            let named = crate::storage::directory(first, &hash[2..4])?;
            if !same(second, &named)? {
                return Err("observed second prefix replaced".into());
            }
            crate::storage::check_private(second, true)?;
        }
        Ok(())
    }
}
/// Opaque retained file/ancestor descriptors, never a serialized permission.
pub struct HeldRawObjectObservation {
    data: RawObjectObservationData,
    prefixes: Prefixes,
    file: Option<File>,
    namespace: Arc<NamespaceHeld>,
}
impl HeldRawObjectObservation {
    pub fn data(&self) -> &RawObjectObservationData {
        &self.data
    }
}
fn missing(error: &Box<dyn std::error::Error>) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
fn readonly(budget: IoBudget) -> Result<()> {
    budget.validate()?;
    if budget.write_bytes != 0 || budget.new_files != 0 || budget.read_bytes > 128 * 1024 {
        return Err("raw observation requires bounded read-only128KiB admission".into());
    }
    Ok(())
}
fn namespace_sha(namespace: &HeldNamespaceObservation) -> Result<String> {
    Ok(luma_content::sha256(&serde_json::to_vec(namespace.data())?))
}
fn read_held<B: Boundary>(
    file: &File,
    expected: &ObservedFileData,
    parent: &File,
    name: &str,
    maximum: usize,
    guard: &mut Guard<'_, B>,
    mut namespace: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    if expected.bytes > maximum as u64 {
        return Err("raw observation file exceeds fixed bound".into());
    }
    let mut bytes = Vec::with_capacity(expected.bytes as usize);
    let mut block = [0; 4096];
    loop {
        guard.check()?;
        namespace()?;
        crate::storage::check_private(file, false)?;
        let named = crate::storage::open(parent, name, libc::O_RDONLY, 0)?;
        if ObservedFileData::capture(file)? != *expected
            || ObservedFileData::capture(&named)? != *expected
        {
            return Err("raw observation held/named file changed before read".into());
        }
        let remaining = (expected.bytes as usize).saturating_sub(bytes.len());
        let capacity = remaining.min(block.len()).max(1);
        guard.read(capacity as u64)?;
        let count = unsafe {
            libc::pread(
                file.as_raw_fd(),
                block.as_mut_ptr().cast(),
                capacity,
                bytes.len() as libc::off_t,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        guard.check()?;
        namespace()?;
        if count == 0 {
            if remaining != 0 {
                return Err("raw observation file shortened".into());
            }
            break;
        }
        let count = count as usize;
        if remaining == 0 || count > remaining {
            return Err("raw observation file grew".into());
        }
        bytes.extend_from_slice(&block[..count]);
    }
    let named = crate::storage::open(parent, name, libc::O_RDONLY, 0)?;
    if ObservedFileData::capture(file)? != *expected
        || ObservedFileData::capture(&named)? != *expected
    {
        return Err("raw observation held/named file changed after read".into());
    }
    guard.check()?;
    namespace()?;
    Ok(bytes)
}
fn absence(
    namespace: &HeldNamespaceObservation,
    store: &ObjectStore,
    prefixes: &Prefixes,
    hash: &str,
    component: u8,
) -> Result<()> {
    namespace.metadata(store)?;
    prefixes.check(store, hash)?;
    let parent = prefixes.parent(namespace);
    let name = match component {
        0 => &hash[..2],
        1 => &hash[2..4],
        2 => hash,
        _ => return Err("raw absence component is not closed".into()),
    };
    let result = crate::storage::open(parent, name, libc::O_RDONLY, 0);
    match result {
        Err(error) if missing(&error) => (),
        _ => return Err("observed computed path is no longer absent".into()),
    }
    namespace.metadata(store)?;
    prefixes.check(store, hash)
}
impl ObjectStore {
    pub fn observe_namespace(
        &self,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<HeldNamespaceObservation> {
        readonly(budget)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        self.check()?;
        let root = crate::storage::open(&self.root, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let objects =
            crate::storage::open(&self.objects, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let value = read_member_observed(
            &self.root,
            "identity.json",
            4096,
            self.mount_id,
            &mut guard,
            || self.check(),
        )?;
        let identity: Identity = canonical(&value.bytes, 4096)?;
        if identity.binding != self.binding
            || identity.schema_version != 1
            || identity.domain != DOMAIN
        {
            return Err("raw observation namespace identity differs".into());
        }
        let data = NamespaceObservationData {
            schema_version: 1,
            binding: self.binding.clone(),
            root: ObservedFileData::capture(&root)?,
            objects: ObservedFileData::capture(&objects)?,
            identity: ObservedFileData::metadata(&value.before, self.mount_id)?,
            identity_sha256: luma_content::sha256(&value.bytes),
        };
        value.recheck(&self.root, "identity.json", self.mount_id)?;
        let result = HeldNamespaceObservation {
            held: Arc::new(NamespaceHeld {
                root,
                objects,
                identity: value.file,
                data,
            }),
        };
        result.current(self, &mut guard)?;
        Ok(result)
    }
    pub fn check_namespace_observation(
        &self,
        namespace: &HeldNamespaceObservation,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<()> {
        readonly(budget)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        namespace.current(self, &mut guard)
    }
    pub fn observe_raw_object(
        &self,
        namespace: &HeldNamespaceObservation,
        hash: &str,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<(Vec<u8>, HeldRawObjectObservation)> {
        readonly(budget)?;
        digest(hash)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        namespace.current(self, &mut guard)?;
        let mut prefixes = Prefixes {
            first: None,
            second: None,
        };
        let mut missing_at = None;
        for (index, name) in [&hash[..2], &hash[2..4]].iter().enumerate() {
            guard.check()?;
            namespace.metadata(self)?;
            prefixes.check(self, hash)?;
            match crate::storage::directory(prefixes.parent(namespace), name) {
                Ok(file) => {
                    if index == 0 {
                        prefixes.first = Some(file);
                    } else {
                        prefixes.second = Some(file);
                    }
                }
                Err(error) if missing(&error) => {
                    missing_at = Some(index as u8);
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let namespace_sha256 = namespace_sha(namespace)?;
        let mut file = None;
        let mut bytes = Vec::new();
        let data = if let Some(component) = missing_at {
            absence(namespace, self, &prefixes, hash, component)?;
            RawObjectObservationData::Absent {
                object_sha256: hash.into(),
                namespace_sha256,
                missing_component: component,
                nearest_ancestor: ObservedFileData::capture(prefixes.parent(namespace))?,
            }
        } else {
            let observed = read_member_observed(
                prefixes.parent(namespace),
                hash,
                MAX_PAGE_BYTES,
                self.mount_id,
                &mut guard,
                || {
                    namespace.metadata(self)?;
                    prefixes.check(self, hash)
                },
            );
            match observed {
                Ok(value) => {
                    let actual_sha256 = luma_content::sha256(&value.bytes);
                    let complete = !value.bytes.is_empty() && actual_sha256 == hash;
                    let data = RawObjectObservationData::Present {
                        object_sha256: hash.into(),
                        namespace_sha256,
                        actual_sha256,
                        complete,
                        file: ObservedFileData::metadata(&value.before, self.mount_id)?,
                    };
                    value.recheck(prefixes.parent(namespace), hash, self.mount_id)?;
                    file = Some(value.file);
                    bytes = value.bytes;
                    data
                }
                Err(error) if missing(&error) => {
                    absence(namespace, self, &prefixes, hash, 2)?;
                    RawObjectObservationData::Absent {
                        object_sha256: hash.into(),
                        namespace_sha256,
                        missing_component: 2,
                        nearest_ancestor: ObservedFileData::capture(prefixes.parent(namespace))?,
                    }
                }
                Err(error) => return Err(error),
            }
        };
        namespace.current(self, &mut guard)?;
        guard.check()?;
        match &data {
            RawObjectObservationData::Absent {
                missing_component, ..
            } => absence(namespace, self, &prefixes, hash, *missing_component)?,
            RawObjectObservationData::Present { file: expected, .. } => {
                let held = file
                    .as_ref()
                    .ok_or("raw observation did not retain read FD")?;
                let named =
                    crate::storage::open(prefixes.parent(namespace), hash, libc::O_RDONLY, 0)?;
                if ObservedFileData::capture(held)? != *expected
                    || ObservedFileData::capture(&named)? != *expected
                {
                    return Err("raw observed member changed before return".into());
                }
            }
        }
        guard.check()?;
        Ok((
            bytes,
            HeldRawObjectObservation {
                data,
                prefixes,
                file,
                namespace: Arc::clone(&namespace.held),
            },
        ))
    }
    pub fn check_raw_object_observation(
        &self,
        namespace: &HeldNamespaceObservation,
        observation: &HeldRawObjectObservation,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<Vec<u8>> {
        readonly(budget)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        if !Arc::ptr_eq(&observation.namespace, &namespace.held) {
            return Err("raw observation belongs to another retained namespace OFD session".into());
        }
        namespace.current(self, &mut guard)?;
        let expected_namespace = namespace_sha(namespace)?;
        let bytes = match &observation.data {
            RawObjectObservationData::Absent {
                object_sha256,
                namespace_sha256,
                missing_component,
                nearest_ancestor,
            } => {
                if namespace_sha256 != &expected_namespace || observation.file.is_some() {
                    return Err("raw absence belongs to another observation session".into());
                }
                nearest_ancestor.same_directory(observation.prefixes.parent(namespace))?;
                absence(
                    namespace,
                    self,
                    &observation.prefixes,
                    object_sha256,
                    *missing_component,
                )?;
                Vec::new()
            }
            RawObjectObservationData::Present {
                object_sha256,
                namespace_sha256,
                actual_sha256,
                file,
                ..
            } => {
                if namespace_sha256 != &expected_namespace {
                    return Err("raw file belongs to another observation session".into());
                }
                observation.prefixes.check(self, object_sha256)?;
                let held = observation
                    .file
                    .as_ref()
                    .ok_or("raw file observation lacks held descriptor")?;
                let bytes = read_held(
                    held,
                    file,
                    observation.prefixes.parent(namespace),
                    object_sha256,
                    MAX_PAGE_BYTES,
                    &mut guard,
                    || {
                        namespace.metadata(self)?;
                        observation.prefixes.check(self, object_sha256)
                    },
                )?;
                if luma_content::sha256(&bytes) != *actual_sha256 {
                    return Err("raw observation actual content changed".into());
                }
                bytes
            }
        };
        namespace.current(self, &mut guard)?;
        guard.check()?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
