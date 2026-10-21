//! Existing advisory flock on one actually held/received root OFD. This DATA
//! does not prove who created files, exclusion against noncooperating writers,
//! a complete physical baseline, an original principal or permission to publish.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WriterObservationData {
    pub schema_version: u32,
    pub namespace_sha256: String,
    pub sender_pid: u32,
    pub root: ObservedFileData,
    pub identity_sha256: String,
}

/// The original received OFD is retained, not reopened from a supplied path.
/// No constructor from serialized metadata or cached success is provided.
pub struct HeldWriterObservation {
    writer: File,
    identity: File,
    identity_data: ObservedFileData,
    namespace: Arc<NamespaceHeld>,
    data: WriterObservationData,
}
impl HeldWriterObservation {
    pub fn data(&self) -> &WriterObservationData {
        &self.data
    }
}

fn same_node(a: &ObservedFileData, b: &ObservedFileData) -> bool {
    // A received file carries its source vfsmount. The observer's fixed root
    // may be a read-only bind alias: both actual mount IDs are retained, not
    // falsely equated. Device/inode identify the same kernel filesystem node.
    a.device == b.device
        && a.inode == b.inode
        && a.uid == b.uid
        && a.gid == b.gid
        && a.mode == b.mode
}
fn proc_info(file: &File, guard: &mut Guard<'_, impl Boundary>) -> Result<String> {
    guard.check()?;
    guard.read(4097)?;
    let input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(input.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != 0x9fa0
        || input.metadata()?.uid() != 0
    {
        return Err("writer fdinfo is not actual root-owned kernel procfs".into());
    }
    let mut bytes = Vec::new();
    input.take(4097).read_to_end(&mut bytes)?;
    guard.check()?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("writer fdinfo exceeds fixed kernel transcript bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn existing_lock(info: &str, sender: u32, root: &ObservedFileData) -> Result<()> {
    let mut locks = 0;
    let mut mount_id = None;
    let mut inode = None;
    for line in info.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.first().copied() {
            Some("mnt_id:") => {
                if fields.len() != 2 || mount_id.replace(fields[1].parse::<u64>()?).is_some() {
                    return Err("writer fdinfo mount entry ambiguous".into());
                }
            }
            Some("ino:") => {
                if fields.len() != 2 || inode.replace(fields[1].parse::<u64>()?).is_some() {
                    return Err("writer fdinfo inode entry ambiguous".into());
                }
            }
            Some("lock:") => {
                locks += 1;
                if fields.len() != 9
                    || fields[2..5] != ["FLOCK", "ADVISORY", "WRITE"]
                    || fields[5].parse::<u32>()? != sender
                    || fields[7..] != ["0", "EOF"]
                {
                    return Err(
                        "held root OFD lacks the exact sender's existing advisory write flock"
                            .into(),
                    );
                }
                let ordinal = fields[1]
                    .strip_suffix(':')
                    .ok_or("writer lock ordinal malformed")?;
                if ordinal.parse::<u64>()? == 0 {
                    return Err("writer lock ordinal zero".into());
                }
                let node: Vec<_> = fields[6].split(':').collect();
                // Pinned libc marks these pure dev_t decoders unsafe; neither
                // function dereferences a pointer or accesses caller memory.
                let major = unsafe { libc::major(root.device) } as u64;
                let minor = unsafe { libc::minor(root.device) } as u64;
                if node.len() != 3
                    || u64::from_str_radix(node[0], 16)? != major
                    || u64::from_str_radix(node[1], 16)? != minor
                    || node[2].parse::<u64>()? != root.inode
                {
                    return Err("writer lock refers to a different filesystem node".into());
                }
            }
            _ => (),
        }
    }
    if locks != 1 || mount_id != Some(root.mount_id) || inode != Some(root.inode) {
        return Err(
            "writer existing OFD lock/mount/inode kernel evidence missing or ambiguous".into(),
        );
    }
    Ok(())
}
fn writer_file(file: &File, namespace: &HeldNamespaceObservation) -> Result<ObservedFileData> {
    crate::storage::check_private(file, true)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if flags < 0
        || descriptor_flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & libc::O_PATH != 0
        || flags & libc::O_DIRECTORY == 0
        || descriptor_flags & libc::FD_CLOEXEC == 0
        || unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != 0xef53
    {
        return Err(
            "writer observation accepts only one CLOEXEC readonly actual ext4 directory OFD".into(),
        );
    }
    let root = ObservedFileData::capture(file)?;
    if !same_node(&root, &namespace.data().root) {
        return Err("received writer OFD is not the fixed selected owner namespace".into());
    }
    Ok(root)
}
impl ObjectStore {
    /// Observe an ALREADY held sender flock. No flock(LOCK_EX), creator
    /// inference or publication permission is performed by this observer.
    pub fn observe_existing_writer(
        &self,
        namespace: &HeldNamespaceObservation,
        writer: File,
        sender_pid: u32,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<HeldWriterObservation> {
        readonly(budget)?;
        if sender_pid == 0 {
            return Err("writer observation requires actual pinned sender PID".into());
        }
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        namespace.current(self, &mut guard)?;
        let root = writer_file(&writer, namespace)?;
        existing_lock(&proc_info(&writer, &mut guard)?, sender_pid, &root)?;
        let member = read_member_observed(
            &writer,
            "identity.json",
            4096,
            root.mount_id,
            &mut guard,
            || namespace.metadata(self),
        )?;
        let identity_data = ObservedFileData::metadata(&member.before, root.mount_id)?;
        if !same_node(&identity_data, &namespace.data().identity)
            || luma_content::sha256(&member.bytes) != namespace.data().identity_sha256
        {
            return Err(
                "received writer namespace identity differs from fixed observed owner".into(),
            );
        }
        member.recheck(&writer, "identity.json", root.mount_id)?;
        let result = HeldWriterObservation {
            writer,
            identity: member.file,
            identity_data,
            namespace: namespace.held.clone(),
            data: WriterObservationData {
                schema_version: 1,
                namespace_sha256: luma_content::sha256(&serde_json::to_vec(namespace.data())?),
                sender_pid,
                root,
                identity_sha256: namespace.data().identity_sha256.clone(),
            },
        };
        self.check_existing_writer_inner(namespace, &result, &mut guard)?;
        Ok(result)
    }
    fn check_existing_writer_inner<B: Boundary>(
        &self,
        namespace: &HeldNamespaceObservation,
        held: &HeldWriterObservation,
        guard: &mut Guard<'_, B>,
    ) -> Result<()> {
        if !Arc::ptr_eq(&namespace.held, &held.namespace) {
            return Err("writer observation belongs to a different namespace OFD session".into());
        }
        namespace.current(self, guard)?;
        let root = writer_file(&held.writer, namespace)?;
        if !same_node(&root, &held.data.root) || root.mount_id != held.data.root.mount_id {
            return Err("received writer OFD identity/mount changed".into());
        }
        existing_lock(
            &proc_info(&held.writer, guard)?,
            held.data.sender_pid,
            &root,
        )?;
        let bytes = read_held(
            &held.identity,
            &held.identity_data,
            &held.writer,
            "identity.json",
            4096,
            guard,
            || namespace.metadata(self),
        )?;
        if luma_content::sha256(&bytes) != held.data.identity_sha256 {
            return Err("received writer identity bytes changed".into());
        }
        namespace.current(self, guard)?;
        existing_lock(
            &proc_info(&held.writer, guard)?,
            held.data.sender_pid,
            &writer_file(&held.writer, namespace)?,
        )?;
        guard.check()
    }
    pub fn check_existing_writer(
        &self,
        namespace: &HeldNamespaceObservation,
        held: &HeldWriterObservation,
        budget: IoBudget,
        boundary: &mut impl Boundary,
    ) -> Result<()> {
        readonly(budget)?;
        let mut guard = Guard::new(boundary, &self.binding, budget, None)?;
        self.check_existing_writer_inner(namespace, held, &mut guard)
    }
}

#[cfg(test)]
#[path = "writer_observation/tests.rs"]
mod tests;
