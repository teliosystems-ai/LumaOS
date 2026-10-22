use super::*;
use luma_content_store::v2::{
    HeldNamespaceObservation, HeldRawObjectObservation, IoBudget, ObjectStore,
};
use luma_content_store::{Access, Boundary, ResourceBudget};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

struct ReadOnly<'a> {
    socket: &'a UnixStream,
    peer: &'a endpoint::Peer,
    context: &'a Context,
    deadline_ms: u64,
    expires_ms: u64,
}
impl ReadOnly<'_> {
    fn current(&self) -> Result<()> {
        self.peer.check(self.socket)?;
        let current = now()?;
        if current >= self.deadline_ms || current >= self.expires_ms {
            return Err("observer bounded read/session resource deadline expired".into());
        }
        Ok(())
    }
}
impl Boundary for ReadOnly<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.current()?;
        if binding != &self.context.binding
            || budget.memory_bytes > 192 * 1024 * 1024
            || budget.tasks != 1
            || budget.read_bytes > READ_BYTES
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("observer refuses nonfixed or mutating resource request".into());
        }
        self.current()
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.context.binding => self.current(),
            _ => Err("query observer never grants mutation/recovery access".into()),
        }
    }
}
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: READ_BYTES,
        write_bytes: 0,
        new_files: 0,
    }
}
struct Session {
    context: Context,
    sha: String,
    id: String,
    next: u32,
    expires_ms: u64,
    store: ObjectStore,
    namespace: HeldNamespaceObservation,
    observations: Vec<HeldRawObjectObservation>,
    nonces: BTreeSet<String>,
}
fn check_request(session: &Session, request: &Request) -> Result<()> {
    request.validate()?;
    if request.session_id.as_ref() != Some(&session.id)
        || request.context_sha256 != session.sha
        || request.sequence != session.next
        || session.nonces.contains(&request.nonce)
        || now()? >= session.expires_ms
        || matches!(request.operation, Operation::Begin { .. })
    {
        return Err("observer request changed session/context/order or replayed nonce".into());
    }
    Ok(())
}
/// Internal engine receives an actual kernel-pinned peer and fixed source root.
/// Only command() supplies the production root and C label. Tests call this
/// private engine with disposable ext4 and an explicitly unconfined fixture pin.
pub(super) fn handle(socket: &UnixStream, peer: endpoint::Peer, root: &Path) -> Result<()> {
    let initial_deadline = Instant::now() + Duration::from_millis(RPC_MS);
    let first_bytes = wire::receive(socket, initial_deadline, &mut || peer.check(socket))?;
    let first: Request = canonical(&first_bytes)?;
    first.validate()?;
    let context = match &first.operation {
        Operation::Begin { context } => context.clone(),
        _ => return Err("observer connection must begin with exact context".into()),
    };
    let expires_ms = now()?
        .checked_add(SESSION_MS)
        .ok_or("observer session ceiling overflow")?;
    let mut boundary = ReadOnly {
        socket,
        peer: &peer,
        context: &context,
        deadline_ms: first.deadline_ms,
        expires_ms,
    };
    boundary.current()?;
    let store = ObjectStore::open_at(root, &context.binding, budget(), &mut boundary)?;
    let namespace = store.observe_namespace(budget(), &mut boundary)?;
    let id = crate::resources::random_id()?;
    let response = Response {
        schema_version: 1,
        nonce: first.nonce.clone(),
        request_sha256: luma_content::sha256(&first_bytes),
        context_sha256: context.sha256()?,
        session_id: id.clone(),
        sequence: 0,
        data: Data::Begun {
            namespace: namespace.data().clone(),
        },
    };
    wire::send(
        socket,
        &serde_json::to_vec(&response)?,
        initial_deadline,
        &mut || boundary.current(),
    )?;
    let mut session = Session {
        sha: context.sha256()?,
        context,
        id,
        next: 1,
        expires_ms,
        store,
        namespace,
        observations: Vec::with_capacity(MAX_OBSERVATIONS),
        nonces: [first.nonce].into_iter().collect(),
    };
    loop {
        // The held-FD lifetime is only a service resource ceiling. Every client
        // RPC additionally invokes its retained ORIGINAL C callback, whose
        // Standard30s or genuine Export cutoff is never renewed by this loop.
        let remaining = session
            .expires_ms
            .checked_sub(now()?)
            .filter(|n| *n > 0)
            .ok_or("observer session resource ceiling expired")?;
        let deadline = Instant::now() + Duration::from_millis(remaining.min(RPC_MS));
        let bytes = wire::receive(socket, deadline, &mut || peer.check(socket))?;
        let request: Request = canonical(&bytes)?;
        check_request(&session, &request)?;
        let mut boundary = ReadOnly {
            socket,
            peer: &peer,
            context: &session.context,
            deadline_ms: request.deadline_ms,
            expires_ms: session.expires_ms,
        };
        boundary.current()?;
        let data = match &request.operation {
            Operation::ReadPage { object_sha256 } => {
                // Ephemeral read: retain the original namespace, not one file
                // descriptor for every Merkle traversal page.
                let (bytes, observation) = session.store.observe_raw_object(
                    &session.namespace,
                    object_sha256,
                    budget(),
                    &mut boundary,
                )?;
                if !matches!(
                    observation.data(),
                    RawObjectObservationData::Present { complete: true, .. }
                ) {
                    return Err("observer Merkle page absent/incomplete".into());
                }
                Data::Page {
                    object: observation.data().clone(),
                    bytes_hex: bytes_hex(&bytes),
                }
            }
            Operation::Observe { object_sha256 } => {
                if session.observations.len() >= MAX_OBSERVATIONS {
                    return Err("observer held raw query capacity exhausted".into());
                }
                let (bytes, observation) = session.store.observe_raw_object(
                    &session.namespace,
                    object_sha256,
                    budget(),
                    &mut boundary,
                )?;
                let slot = session.observations.len() as u8;
                let object = observation.data().clone();
                session.observations.push(observation);
                Data::Observed {
                    slot,
                    object,
                    bytes_hex: bytes_hex(&bytes),
                }
            }
            Operation::Recheck { slot } => {
                let observation = session
                    .observations
                    .get(usize::from(*slot))
                    .ok_or("observer original slot absent")?;
                let bytes = session.store.check_raw_object_observation(
                    &session.namespace,
                    observation,
                    budget(),
                    &mut boundary,
                )?;
                Data::Rechecked {
                    slot: *slot,
                    object: observation.data().clone(),
                    bytes_hex: bytes_hex(&bytes),
                }
            }
            Operation::End => {
                session.store.check_namespace_observation(
                    &session.namespace,
                    budget(),
                    &mut boundary,
                )?;
                Data::Closed
            }
            Operation::Begin { .. } => {
                return Err("observer cannot replace an active original namespace".into())
            }
        };
        boundary.current()?;
        let response = Response {
            schema_version: 1,
            nonce: request.nonce.clone(),
            request_sha256: luma_content::sha256(&bytes),
            context_sha256: session.sha.clone(),
            session_id: session.id.clone(),
            sequence: request.sequence,
            data,
        };
        wire::send(
            socket,
            &serde_json::to_vec(&response)?,
            deadline,
            &mut || boundary.current(),
        )?;
        session.nonces.insert(request.nonce);
        session.next += 1;
        if matches!(request.operation, Operation::End) {
            return Ok(());
        }
        if session.next >= MAX_RPCS {
            return Err("observer finite RPC sequence exhausted without End".into());
        }
    }
}
fn protected(path: &Path, socket: bool) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    if m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != if socket { 0o600 } else { 0o700 }
        || if socket {
            !m.file_type().is_socket() || m.nlink() != 1
        } else {
            !m.is_dir()
        }
    {
        return Err("content observer fixed runtime namespace unsafe".into());
    }
    Ok(m)
}
pub(super) fn check_paths() -> Result<(u64, u64)> {
    protected(Path::new(DIRECTORY), false)?;
    let m = protected(Path::new(SOCKET), true)?;
    Ok((m.dev(), m.ino()))
}
fn kernel_text(path: &Path, maximum: usize, filesystem: u64) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } != 0
        || info.f_type as u64 != filesystem
    {
        return Err("observer requires real kernel status/resource filesystem".into());
    }
    let mut text = String::new();
    file.take((maximum + 1) as u64).read_to_string(&mut text)?;
    if text.len() > maximum {
        return Err("observer kernel status outside fixed bound".into());
    }
    Ok(text)
}
fn self_confinement() -> Result<()> {
    let status = kernel_text(Path::new("/proc/self/status"), 16384, 0x9fa0)?;
    for (key, wanted) in [
        ("Uid", "0\t0\t0\t0"),
        ("Gid", "0\t0\t0\t0"),
        ("CapInh", "0000000000000000"),
        ("CapPrm", "0000000000000000"),
        ("CapEff", "0000000000000000"),
        ("CapBnd", "0000000000000000"),
        ("CapAmb", "0000000000000000"),
        ("NoNewPrivs", "1"),
        ("Seccomp", "2"),
    ] {
        let mut values = status
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{key}:")));
        if values.next().map(str::trim) != Some(wanted) || values.next().is_some() {
            return Err("query observer is not exact root CAP0/NNP/seccomp endpoint".into());
        }
    }
    if kernel_text(Path::new("/proc/self/attr/current"), 256, 0x9fa0)?.trim() != OBSERVER
        || kernel_text(Path::new("/proc/self/cgroup"), 256, 0x9fa0)?
            != "0::/system.slice/luma-content-data-observer.service\n"
    {
        return Err("query observer enforcing profile/cgroup unavailable".into());
    }
    let group = Path::new("/sys/fs/cgroup/system.slice/luma-content-data-observer.service");
    for (name, expected) in [
        ("memory.max", "268435456"),
        ("memory.swap.max", "0"),
        ("pids.max", "2"),
        ("cpu.max", "25000 100000"),
    ] {
        let text = kernel_text(&group.join(name), 128, 0x63677270)?;
        if text.trim() != expected {
            return Err("query observer fixed resources differ".into());
        }
    }
    let mut descriptors: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptors) } != 0
        || descriptors.rlim_cur != 256
        || descriptors.rlim_max != 256
    {
        return Err("query observer held-descriptor ceiling differs".into());
    }
    Ok(())
}
pub(super) fn command() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    self_confinement()?;
    protected(Path::new(DIRECTORY), false)?;
    // Bind must fail on any pre-existing object. Never adopt/unlink a stale or
    // substituted socket or initialize an absent product-content namespace.
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))?;
    let pin = check_paths()?;
    loop {
        self_confinement()?;
        if check_paths()? != pin {
            return Err("query observer listener inode replaced".into());
        }
        let (socket, _) = listener.accept()?;
        // A refused connection closes without an authority/success reply or
        // private-data log. This daemon has no broker/C callback whatsoever.
        if let Ok(peer) = endpoint::Peer::capture(&socket, C_PEER) {
            let _ = handle(&socket, peer, Path::new(CONTENT_ROOT));
        }
    }
}
