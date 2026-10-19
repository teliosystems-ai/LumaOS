//! Independent Windows UTC publisher: U key state, fixed broker observations,
//! and nonce-bound exact-purpose ECDSA proofs. Disk/signatures are not authority.
use crate::{
    bundle,
    sealed_credential::{PrivateBuffer, Secret},
    tpm::{self, Checkpoint},
    utc_windows_checkpoint::{PublisherRoot, PublisherSealed, UtcAnchor},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/utc-windows";
const SOCKET: &str = "/run/luma-utc-windows/control.sock";
const TRANSPORT: &str = "/etc/luma-os/utc-windows/transport.json";
const CHALLENGE: &[u8] = b"luma-windows-hosted-utc-challenge-v1";
const DELIVERY: &[u8] = b"luma-windows-hosted-utc-delivery-v1";
const MAX_STATE: u64 = 2 * 1024 * 1024;
const MAX_EVENTS: usize = 64;
const FRONT_UID: u32 = 985;

fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}
fn nonzero(text: &str) -> Result<[u8; 32]> {
    let bytes = tpm::decode(text)?;
    if bytes == [0; 32] {
        return Err("UTC publisher zero identity refused".into());
    }
    Ok(bytes)
}
fn canonical<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("UTC publisher noncanonical data refused".into());
    }
    Ok(value)
}
fn name(value: &str) -> Result<std::ffi::CString> {
    if value.is_empty() || value.len() > 128 || value.contains('/') || matches!(value, "." | "..") {
        return Err("UTC fixed state member refused".into());
    }
    Ok(std::ffi::CString::new(value)?)
}
fn member(root: &PublisherRoot, value: &str, write: bool) -> Result<File> {
    root.recheck()?;
    let name = name(value)?;
    let fd = unsafe {
        libc::openat(
            root.descriptor().as_raw_fd(),
            name.as_ptr(),
            libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if write {
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
                } else {
                    libc::O_RDONLY
                },
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != 0
        || info.nlink() != 1
        || info.mode() & 0o7777 != 0o600
        || info.len() > MAX_STATE
    {
        return Err("UTC fixed state member inode/protection refused".into());
    }
    root.recheck()?;
    Ok(file)
}
fn identity(m: &fs::Metadata) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(root: &PublisherRoot, value: &str) -> Result<Vec<u8>> {
    let file = member(root, value, false)?;
    let before = file.metadata()?;
    if before.len() == 0 {
        return Err("UTC empty retained member refused".into());
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_STATE + 1).read_to_end(&mut bytes)?;
    let current = member(root, value, false)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&current.metadata()?)
    {
        return Err("UTC retained member changed during read".into());
    }
    root.recheck()?;
    Ok(bytes)
}
fn write_new(root: &PublisherRoot, value: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE {
        return Err("UTC bounded state write refused".into());
    }
    let mut file = member(root, value, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    root.descriptor().sync_all()?;
    root.recheck()?;
    if read(root, value)? != bytes {
        return Err("UTC state durable readback differs".into());
    }
    Ok(())
}
fn absent(root: &PublisherRoot, value: &str) -> Result<()> {
    root.recheck()?;
    let name = name(value)?;
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            root.descriptor().as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Err("UTC retained state already exists; no overwrite/reset".into());
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(std::io::Error::last_os_error().into());
    }
    root.recheck()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema_version: u32,
    windows_installations: Vec<String>,
    authorized_sources: Vec<AuthorizedSource>,
    transport_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorizedSource {
    installation: String,
    purpose: String,
    sha256: String,
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.windows_installations.is_empty()
            || self.windows_installations.len() > 64
        {
            return Err("UTC explicit bounded Windows installation allowlist required".into());
        }
        nonzero(&self.transport_sha256)?;
        let mut previous: Option<&str> = None;
        for installation in &self.windows_installations {
            nonzero(installation)?;
            if previous.is_some_and(|old| old >= installation.as_str()) {
                return Err("UTC installation allowlist must be sorted unique".into());
            }
            previous = Some(installation);
        }
        if self.authorized_sources.is_empty() || self.authorized_sources.len() > 64 {
            return Err("UTC requires explicit bounded reviewed operation sources".into());
        }
        let mut previous = None;
        for source in &self.authorized_sources {
            nonzero(&source.installation)?;
            nonzero(&source.sha256)?;
            let key = (source.installation.as_str(), source.sha256.as_str());
            if !matches!(
                source.purpose.as_str(),
                "release"
                    | "trust-change"
                    | "runtime-update"
                    | "host-file-read"
                    | "host-file-enrollment"
            ) || self
                .windows_installations
                .binary_search(&source.installation)
                .is_err()
                || previous.is_some_and(|old| old >= key)
            {
                return Err(
                    "UTC sources must be sorted unique, installation-bound and purpose-closed"
                        .into(),
                );
            }
            previous = Some(key);
        }
        Ok(())
    }
    fn permits_source(&self, installation: &[u8; 32], source: &[u8; 32]) -> bool {
        let installation = bundle::hex(installation);
        let source = bundle::hex(source);
        self.authorized_sources
            .binary_search_by(|item| {
                (item.installation.as_str(), item.sha256.as_str())
                    .cmp(&(installation.as_str(), source.as_str()))
            })
            .is_ok()
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Change {
    Commission {
        configuration: Configuration,
        public_blob: String,
        sealed: PublisherSealed,
    },
    Revoke {
        public_sha256: String,
    },
    AuthorizeSources {
        public_sha256: String,
        configuration: Configuration,
    },
}
#[derive(Clone, Copy)]
struct ActiveKey<'a> {
    configuration: &'a Configuration,
    public_blob: &'a str,
    sealed: &'a PublisherSealed,
}
fn validate_policy_amendment(current: &Configuration, wanted: &Configuration) -> Result<()> {
    current.validate()?;
    wanted.validate()?;
    if current.windows_installations != wanted.windows_installations
        || current.transport_sha256 != wanted.transport_sha256
        || current.authorized_sources == wanted.authorized_sources
    {
        return Err("UTC source-policy amendment must change only exact reviewed sources, preserving installations/transport/key".into());
    }
    Ok(())
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u64,
    previous_head: String,
    change: Change,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    installation: String,
    genesis: String,
    genesis_descriptor: serde_json::Value,
    events: Vec<Event>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisIdentity {
    device: String,
    inode: String,
    uid: u32,
    gid: u32,
    mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisDescriptor {
    schema_version: u32,
    kind: String,
    installation: String,
    namespace: String,
    identity: GenesisIdentity,
    domains: Vec<String>,
}
pub(crate) fn validate_genesis_witness(
    value: &serde_json::Value,
    installation: &str,
    genesis: [u8; 32],
) -> Result<()> {
    nonzero(installation)?;
    let witness: GenesisDescriptor = serde_json::from_value(value.clone())?;
    let device = witness.identity.device.parse::<u64>()?;
    let inode = witness.identity.inode.parse::<u64>()?;
    if witness.identity.device != device.to_string()
        || witness.identity.inode != inode.to_string()
        || witness.schema_version != 1
        || witness.kind != "luma-windows-utc-explicit-empty-genesis-v1"
        || witness.namespace != DIRECTORY
        || witness.installation != installation
        || !witness.domains.is_empty()
        || crate::utc_windows_checkpoint::genesis_descriptor(
            installation,
            (
                device,
                inode,
                witness.identity.uid,
                witness.identity.gid,
                witness.identity.mode,
            ),
        )? != *value
        || <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(value)?)) != genesis
    {
        return Err("UTC original protected genesis witness/installation/namespace differs".into());
    }
    Ok(())
}
impl Journal {
    fn replay(&self) -> Result<([u8; 32], Option<ActiveKey<'_>>)> {
        if self.schema_version != 1 || self.events.len() > MAX_EVENTS {
            return Err("UTC key history schema/count differs".into());
        }
        nonzero(&self.installation)?;
        let genesis = nonzero(&self.genesis)?;
        validate_genesis_witness(&self.genesis_descriptor, &self.installation, genesis)?;
        let mut head = tpm::extend_value([0; 32], genesis);
        let mut active = None;
        let mut seen = std::collections::BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            if event.sequence != (index + 1) as u64 || nonzero(&event.previous_head)? != head {
                return Err("UTC key history order/head differs".into());
            }
            match &event.change {
                Change::Commission {
                    configuration,
                    public_blob,
                    sealed,
                } => {
                    configuration.validate()?;
                    let public = decode_public(public_blob)?;
                    if !seen.insert(hash(&public)) {
                        return Err("UTC key reuse in rotation refused".into());
                    }
                    active = Some(ActiveKey {
                        configuration,
                        public_blob,
                        sealed,
                    });
                }
                Change::Revoke { public_sha256 } => {
                    nonzero(public_sha256)?;
                    match active {
                        Some(ActiveKey { public_blob, .. })
                            if hash(&decode_public(public_blob)?) == *public_sha256 =>
                        {
                            active = None
                        }
                        _ => {
                            return Err(
                                "UTC revocation must match exact currently active key".into()
                            )
                        }
                    }
                }
                Change::AuthorizeSources {
                    public_sha256,
                    configuration,
                } => {
                    nonzero(public_sha256)?;
                    let selected =
                        active.ok_or("UTC source amendment requires currently active key")?;
                    if hash(&decode_public(selected.public_blob)?) != *public_sha256 {
                        return Err("UTC source amendment exact active public key differs".into());
                    }
                    validate_policy_amendment(selected.configuration, configuration)?;
                    active = Some(ActiveKey {
                        configuration,
                        ..selected
                    });
                }
            }
            head = tpm::extend_value(head, event_digest(event)?);
        }
        Ok((head, active))
    }
}
fn decode_public(value: &str) -> Result<Vec<u8>> {
    let bytes = tpm::decode::<72>(value)?.to_vec();
    crate::utc_windows_crypto::validate_public(&bytes)?;
    Ok(bytes)
}
fn event_digest(event: &Event) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"luma-windows-protected-utc-key-event-v1\0");
    digest.update(serde_json::to_vec(event)?);
    Ok(digest.finalize().into())
}
fn open(root: &PublisherRoot, anchor: &mut UtcAnchor) -> Result<Journal> {
    absent(root, ".pending.json")?;
    let bytes = read(root, "journal.json")?;
    let journal: Journal = canonical(&bytes)?;
    if journal.installation != anchor.installation()
        || nonzero(&journal.genesis)? != anchor.genesis_event()
        || journal.replay()?.0 != anchor.read()?
    {
        return Err("UTC key state rollback/substitution/TPM mismatch".into());
    }
    if read(root, "journal.json")? != bytes {
        return Err("UTC key state changed during admission".into());
    }
    Ok(journal)
}
pub(crate) fn initialize_empty(
    anchor: &mut UtcAnchor,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let root = PublisherRoot::installed()?;
    initialize_at(&root, anchor, check)
}
fn initialize_at(
    root: &PublisherRoot,
    anchor: &mut UtcAnchor,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if !root.is_empty()? {
        return Err("UTC genesis requires explicit empty key state; no adoption".into());
    }
    if anchor.read()? != tpm::extend_value([0; 32], anchor.genesis_event()) {
        return Err("UTC empty genesis TPM head differs".into());
    }
    let metadata = root.descriptor().metadata()?;
    let descriptor = crate::utc_windows_checkpoint::genesis_descriptor(
        anchor.installation(),
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        ),
    )?;
    if hash(&serde_json::to_vec(&descriptor)?) != bundle::hex(&anchor.genesis_event()) {
        return Err(
            "UTC original empty genesis witness is not the authenticated enrolled digest".into(),
        );
    }
    let journal = Journal {
        schema_version: 1,
        installation: anchor.installation().into(),
        genesis: bundle::hex(&anchor.genesis_event()),
        genesis_descriptor: descriptor,
        events: vec![],
    };
    check()?;
    write_new(&root, "journal.json", &serde_json::to_vec(&journal)?)?;
    open(&root, anchor)?;
    Ok(())
}
pub(crate) fn checkpoint_status(
    mut anchor: UtcAnchor,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    check()?;
    let root = PublisherRoot::installed()?;
    let state = open(&root, &mut anchor)?;
    check()?;
    let (head, active) = state.replay()?;
    Ok(
        serde_json::json!({"schema_version":1,"installation":anchor.installation(),"genesis_event":bundle::hex(&anchor.genesis_event()),
        "protected_head":bundle::hex(&head),"event_count":state.events.len(),"active_time_key":active.is_some(),
        "authority_returned":false,"native_qualified":false}),
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeRequest {
    schema_version: u32,
    action: String,
    request_id: String,
    deadline: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeReply {
    schema_version: u32,
    result: String,
    request_id: String,
    lower_ms: i64,
    upper_ms: i64,
    sampled_boottime_ms: u64,
    history_head: String,
    context: crate::utc_history::Statement,
}
fn fresh_id() -> Result<String> {
    Ok(crate::resources::random_id()?)
}
fn proc_text(pid: i32, name: &str, maximum: u64) -> Result<String> {
    let mut value = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(Path::new("/proc").join(pid.to_string()).join(name))?
        .take(maximum + 1)
        .read_to_string(&mut value)?;
    if value.is_empty() || value.len() as u64 > maximum {
        return Err("UTC peer kernel evidence exceeds bound".into());
    }
    Ok(value)
}
fn peer(stream: &UnixStream, uid: u32, label: &str, cgroup: &str, command: &[u8]) -> Result<File> {
    let credential = crate::service::credentials(stream)?;
    let gid = match label {
        "luma-utc-windows (enforce)" => FRONT_UID,
        "luma-broker (enforce)" => 990,
        _ => uid,
    };
    if credential.pid <= 0 || credential.uid != uid || credential.gid != gid {
        return Err("UTC fixed kernel peer credentials differ".into());
    }
    let pin = crate::service::peer_pidfd(stream)?;
    let mut actual = [0u8; 256];
    let mut size = actual.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            actual.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size as usize > actual.len()
    {
        return Err("UTC peer AppArmor label unavailable".into());
    }
    let actual = actual[..size as usize]
        .strip_suffix(&[0])
        .unwrap_or(&actual[..size as usize]);
    if actual != label.as_bytes() || proc_text(credential.pid, "cgroup", 4096)? != cgroup {
        return Err("UTC peer fixed confinement/cgroup differs".into());
    }
    let mut cmd = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(
            Path::new("/proc")
                .join(credential.pid.to_string())
                .join("cmdline"),
        )?
        .take(1025)
        .read_to_end(&mut cmd)?;
    if cmd != command || cmd.len() > 1024 || !crate::resource_manager::pidfd_alive(&pin)? {
        return Err("UTC peer command/process generation differs".into());
    }
    let status = proc_text(credential.pid, "status", 16384)?;
    peer_status(&status, uid, gid, label)?;
    if label == "luma-utc-windows-front (enforce)" {
        unit_budget(
            "luma-utc-windows-front.service",
            128 * 1024 * 1024,
            1,
            "50000 100000\n",
        )?;
    }
    if label == "luma-utc-windows (enforce)" {
        unit_budget(
            "luma-utc-windows.service",
            256 * 1024 * 1024,
            4,
            "100000 100000\n",
        )?;
    }
    Ok(pin)
}
fn peer_status(status: &str, uid: u32, gid: u32, label: &str) -> Result<()> {
    let mut fields = std::collections::BTreeMap::new();
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(
            name,
            "Uid"
                | "Gid"
                | "CapInh"
                | "CapPrm"
                | "CapEff"
                | "CapBnd"
                | "CapAmb"
                | "NoNewPrivs"
                | "Seccomp"
        ) && fields.insert(name, value.trim()).is_some()
        {
            return Err("UTC duplicate peer status field".into());
        }
    }
    for (name, expected) in [("Uid", uid), ("Gid", gid)] {
        let values = fields
            .get(name)
            .ok_or("UTC peer credentials missing")?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        if values.len() != 4
            || values
                .iter()
                .any(|value| value.parse::<u32>().ok() != Some(expected))
        {
            return Err("UTC peer real/effective/saved/fs identity differs".into());
        }
    }
    let permitted = if label == "luma-broker (enforce)" {
        "0000000000080000"
    } else {
        "0000000000000000"
    };
    for name in ["CapPrm", "CapEff", "CapBnd"] {
        if fields.get(name).copied() != Some(permitted) {
            return Err("UTC peer fixed capabilities differ".into());
        }
    }
    for name in ["CapInh", "CapAmb"] {
        if fields.get(name).copied() != Some("0000000000000000") {
            return Err("UTC peer inherited/ambient capabilities refused".into());
        }
    }
    if fields.get("NoNewPrivs").copied() != Some("1") || fields.get("Seccomp").copied() != Some("2")
    {
        return Err("UTC peer actual no-new-privileges/seccomp missing".into());
    }
    Ok(())
}
fn unit_budget(unit: &str, memory: u64, tasks: u64, cpu: &str) -> Result<()> {
    if !matches!(
        unit,
        "luma-utc-windows.service" | "luma-utc-windows-front.service"
    ) {
        return Err("unsupported fixed UTC unit".into());
    }
    let path = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&path)?;
    let before = directory.metadata()?;
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut volume) } != 0
        || volume.f_type != 0x63677270
        || before.uid() != 0
        || before.mode() & 0o022 != 0
    {
        return Err("UTC fixed budget needs protected actual cgroup2".into());
    }
    for (name, expected) in [
        ("memory.max", format!("{memory}\n")),
        ("memory.swap.max", "0\n".into()),
        ("pids.max", format!("{tasks}\n")),
        ("cpu.max", cpu.into()),
    ] {
        let name = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut value = String::new();
        unsafe { File::from_raw_fd(fd) }
            .take(129)
            .read_to_string(&mut value)?;
        if value != expected {
            return Err("UTC actual CPU/memory/swap/tasks tuple differs".into());
        }
    }
    let current = fs::symlink_metadata(path)?;
    if !current.is_dir()
        || (current.dev(), current.ino(), current.mode(), current.uid())
            != (before.dev(), before.ino(), before.mode(), before.uid())
    {
        return Err("UTC cgroup2 directory substituted during budget check".into());
    }
    Ok(())
}
pub(crate) fn broker_time(stream: &UnixStream, bytes: &[u8]) -> Result<serde_json::Value> {
    let request: TimeRequest = canonical(bytes)?;
    let now = crate::resource_manager::now()?;
    if request.schema_version != 1
        || request.action != "resource-windows-utc-observe"
        || request.request_id.len() != 32
        || tpm::decode::<16>(&request.request_id)?
            .iter()
            .all(|v| *v == 0)
        || request.deadline <= now
        || request.deadline > now + 4000
    {
        return Err("UTC fixed broker observation request differs".into());
    }
    let command = b"/usr/libexec/luma-os/luma-platform\0utc-windows-serve\0";
    let pin = peer(
        stream,
        0,
        "luma-utc-windows (enforce)",
        "0::/system.slice/luma-utc-windows.service\n",
        command,
    )?;
    let (observation, history_head) = crate::admin_governance::publisher_time_observation()?;
    if crate::resource_manager::now()? >= request.deadline
        || !crate::resource_manager::pidfd_alive(&pin)?
    {
        return Err("UTC publisher peer expired during protected observation".into());
    }
    let _ = peer(
        stream,
        0,
        "luma-utc-windows (enforce)",
        "0::/system.slice/luma-utc-windows.service\n",
        command,
    )?;
    let (lower_ms, upper_ms) = observation.interval().endpoints();
    Ok(serde_json::to_value(TimeReply {
        schema_version: 1,
        result: "ok".into(),
        request_id: request.request_id,
        lower_ms,
        upper_ms,
        sampled_boottime_ms: crate::resource_manager::now()?,
        history_head,
        context: observation.context().clone(),
    })?)
}

fn frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err("UTC local frame bounds differ".into());
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}
fn unframe(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err("UTC local frame length refused".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn current_time() -> Result<TimeReply> {
    let before = crate::resource_manager::now()?;
    let id = fresh_id()?;
    let deadline = Instant::now() + Duration::from_secs(4);
    let request = TimeRequest {
        schema_version: 1,
        action: "resource-windows-utc-observe".into(),
        request_id: id.clone(),
        deadline: before + 4000,
    };
    let mut stream = crate::service::connect_local("/run/luma-broker/control.sock", deadline)?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    let peer_pin = peer(
        &stream,
        0,
        "luma-broker (enforce)",
        "0::/system.slice/luma-broker.service\n",
        b"/usr/libexec/luma-os/luma-platform\0broker\0",
    )?;
    frame(&mut stream, &serde_json::to_vec(&request)?)?;
    let reply: TimeReply = serde_json::from_slice(&unframe(&mut stream, 4096)?)?;
    let now = crate::resource_manager::now()?;
    if reply.schema_version != 1
        || reply.result != "ok"
        || reply.request_id != id
        || reply.lower_ms <= 0
        || reply.upper_ms < reply.lower_ms
        || reply.upper_ms > 4_102_444_800_000
        || reply.upper_ms - reply.lower_ms > 500
        || reply.sampled_boottime_ms < before
        || reply.sampled_boottime_ms > now
        || now >= before + 4000
        || Instant::now() >= deadline
        || !crate::resource_manager::pidfd_alive(&peer_pin)?
    {
        return Err("UTC broker observation stale/substituted/too wide".into());
    }
    reply.context.validate()?;
    nonzero(&reply.history_head)?;
    if reply.context.floor_ms != reply.lower_ms {
        return Err("UTC broker source context differs from interval".into());
    }
    let _ = peer(
        &stream,
        0,
        "luma-broker (enforce)",
        "0::/system.slice/luma-broker.service\n",
        b"/usr/libexec/luma-os/luma-platform\0broker\0",
    )?;
    Ok(reply)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    schema_version: u32,
    installation: String,
    base_head: String,
    configuration: Configuration,
    public_blob: String,
    sealed: PublisherSealed,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: u32,
    sequence: u64,
    base_sha256: String,
    base_head: String,
    wanted_head: String,
    next_sha256: String,
    event_sha256: String,
    draft_sha256: Option<String>,
}
fn rename(root: &PublisherRoot, old: &str, new: &str, replace: bool) -> Result<()> {
    root.recheck()?;
    let old = name(old)?;
    let new = name(new)?;
    let flags = if replace { 0 } else { libc::RENAME_NOREPLACE };
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            root.descriptor().as_raw_fd(),
            old.as_ptr(),
            root.descriptor().as_raw_fd(),
            new.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    root.descriptor().sync_all()?;
    root.recheck()
}
fn prepare_change(
    root: &PublisherRoot,
    anchor: &mut UtcAnchor,
    change: Change,
    draft: Option<String>,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let bytes = read(root, "journal.json")?;
    let mut journal = open(root, anchor)?;
    if journal.events.len() >= MAX_EVENTS {
        return Err("UTC bounded key history full; no reset".into());
    }
    absent(root, ".next-journal.json")?;
    absent(root, ".pending.json")?;
    let base = journal.replay()?.0;
    let event = Event {
        sequence: journal.events.len() as u64 + 1,
        previous_head: bundle::hex(&base),
        change,
    };
    let event_sha256 = bundle::hex(&event_digest(&event)?);
    journal.events.push(event);
    let wanted = journal.replay()?.0;
    let next = serde_json::to_vec(&journal)?;
    let pending = Pending {
        schema_version: 1,
        sequence: journal.events.len() as u64,
        base_sha256: hash(&bytes),
        base_head: bundle::hex(&base),
        wanted_head: bundle::hex(&wanted),
        next_sha256: hash(&next),
        event_sha256,
        draft_sha256: draft,
    };
    check()?;
    write_new(root, ".next-journal.json", &next)?;
    check()?;
    write_new(root, ".pending.json", &serde_json::to_vec(&pending)?)?;
    if read(root, "journal.json")? != bytes || read(root, ".next-journal.json")? != next {
        return Err("UTC prepared key state substituted; preserve pending".into());
    }
    check()?;
    // The fsynced pending file is a ONE-SHOT dispatch fence. Any error after
    // this call must be explicitly reconciled against the exact U head; never
    // re-extend, infer success from a key file, delete, or reconstruct empty.
    anchor.advance(base, tpm::decode(&pending.event_sha256)?)?;
    finalize_change(root, anchor, &hash(&serde_json::to_vec(&pending)?), check)
}
fn pending_report(root: &PublisherRoot, anchor: &mut UtcAnchor) -> Result<serde_json::Value> {
    let bytes = read(root, ".pending.json")?;
    let pending: Pending = canonical(&bytes)?;
    if pending.schema_version != 1 || pending.sequence == 0 || pending.sequence > MAX_EVENTS as u64
    {
        return Err("UTC pending schema/count differs".into());
    }
    for value in [
        &pending.base_sha256,
        &pending.base_head,
        &pending.wanted_head,
        &pending.next_sha256,
        &pending.event_sha256,
    ] {
        nonzero(value)?;
    }
    if tpm::extend_value(
        nonzero(&pending.base_head)?,
        nonzero(&pending.event_sha256)?,
    ) != nonzero(&pending.wanted_head)?
    {
        return Err("UTC pending exact extension differs".into());
    }
    let current = anchor.read()?;
    if current != nonzero(&pending.wanted_head)? {
        return Err(
            "UTC pending write is not the exact selected wanted head; no automatic retry/abort"
                .into(),
        );
    }
    Ok(
        serde_json::json!({"schema_version":1,"review_sha256":hash(&bytes),"sequence":pending.sequence,
        "selected_head":bundle::hex(&current),"next_sha256":pending.next_sha256,"nv_write_retry":false,"authority_returned":false}),
    )
}
fn finalize_change(
    root: &PublisherRoot,
    anchor: &mut UtcAnchor,
    review: &str,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let bytes = read(root, ".pending.json")?;
    let pending: Pending = canonical(&bytes)?;
    if hash(&bytes) != review {
        return Err("UTC reconciliation exact pending review changed".into());
    }
    pending_report(root, anchor)?;
    let old = read(root, "journal.json")?;
    if hash(&old) == pending.base_sha256 {
        let next = read(root, ".next-journal.json")?;
        let parsed: Journal = canonical(&next)?;
        if hash(&next) != pending.next_sha256
            || parsed.events.len() as u64 != pending.sequence
            || parsed.installation != anchor.installation()
            || parsed.replay()?.0 != nonzero(&pending.wanted_head)?
            || parsed
                .events
                .last()
                .map(event_digest)
                .transpose()?
                .map(|v| bundle::hex(&v))
                != Some(pending.event_sha256.clone())
        {
            return Err(
                "UTC held prepared journal/event differs from protected wanted head".into(),
            );
        }
        check()?;
        if read(root, "journal.json")? != old || read(root, ".next-journal.json")? != next {
            return Err("UTC publication input changed".into());
        }
        rename(root, ".next-journal.json", "journal.json", true)?;
    } else if hash(&old) != pending.next_sha256 {
        return Err("UTC current journal is neither exact reviewed base nor wanted".into());
    }
    let published = read(root, "journal.json")?;
    let parsed: Journal = canonical(&published)?;
    if hash(&published) != pending.next_sha256
        || parsed.installation != anchor.installation()
        || nonzero(&parsed.genesis)? != anchor.genesis_event()
        || parsed.replay()?.0 != anchor.read()?
    {
        return Err("UTC key publication uncertain; retain pending".into());
    }
    if let Some(expected) = &pending.draft_sha256 {
        let archived = format!("key-draft-{:08}.json", pending.sequence);
        match read(root, ".key-draft.json") {
            Ok(draft) => {
                if hash(&draft) != *expected {
                    return Err("UTC key draft changed before retirement".into());
                }
                check()?;
                rename(root, ".key-draft.json", &archived, false)?;
            }
            Err(_) => {
                if hash(&read(root, &archived)?) != *expected {
                    return Err("UTC key draft retirement is unconfirmed".into());
                }
            }
        }
    }
    check()?;
    if read(root, ".pending.json")? != bytes || anchor.read()? != nonzero(&pending.wanted_head)? {
        return Err("UTC pending receipt/head changed".into());
    }
    rename(
        root,
        ".pending.json",
        &format!("committed-{:08}.json", pending.sequence),
        false,
    )?;
    open(root, anchor)?;
    check()
}
fn public_from_secret(secret: &Secret, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
    let mut scalar = PrivateBuffer::new(32)?;
    scalar.bytes_mut().copy_from_slice(secret.bytes());
    crate::utc_windows_crypto::public(&scalar, check)
}
fn transport_pin() -> Result<String> {
    let path = Path::new(TRANSPORT);
    if fs::canonicalize(path)? != path {
        return Err("UTC transport configuration alias refused".into());
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("UTC transport protected ancestor differs".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != FRONT_UID
        || before.mode() & 0o7777 != 0o640
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > 4096
    {
        return Err("UTC explicitly commissioned transport config protections differ".into());
    }
    let mut bytes = Vec::new();
    (&file).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&fs::symlink_metadata(path)?)
    {
        return Err("UTC transport config changed during pin".into());
    }
    Ok(hash(&bytes))
}
fn draft_report(root: &PublisherRoot, anchor: &mut UtcAnchor) -> Result<serde_json::Value> {
    let bytes = read(root, ".key-draft.json")?;
    let draft: Draft = canonical(&bytes)?;
    draft.configuration.validate()?;
    let state = open(root, anchor)?;
    if draft.schema_version != 1
        || draft.installation != anchor.installation()
        || nonzero(&draft.base_head)? != state.replay()?.0
        || draft.configuration.transport_sha256 != transport_pin()?
    {
        return Err("UTC key draft no longer matches actual base/transport".into());
    }
    let public = decode_public(&draft.public_blob)?;
    Ok(
        serde_json::json!({"schema_version":1,"review_sha256":hash(&bytes),"public_blob":draft.public_blob,
        "public_sha256":hash(&public),"windows_installations":draft.configuration.windows_installations,
        "authorized_sources":draft.configuration.authorized_sources,
        "transport_sha256":draft.configuration.transport_sha256,"custody_provisioned":false,"time_authority":false}),
    )
}
fn usage(
    id: &str,
    action: crate::finite_grants::Action,
    review: &str,
) -> Result<crate::finite_grants::Use> {
    nonzero(review)?;
    let value = crate::finite_grants::Use {
        action,
        selector: crate::finite_grants::Selector {
            kind: if action == crate::finite_grants::Action::Read {
                crate::finite_grants::Kind::File
            } else {
                crate::finite_grants::Kind::Resource
            },
            id: id.into(),
            generation: 1,
            digest: review.into(),
        },
        input_bytes: 4096,
        output_bytes: 8192,
        units: 1,
    };
    value.validate()?;
    Ok(value)
}
fn config_input(path: &str) -> Result<(Configuration, Vec<u8>)> {
    if path != "/run/luma-admin/utc-windows-key.json" {
        return Err("UTC key input requires exact reviewed Admin runtime file".into());
    }
    let bytes = tpm::private_read(Path::new(path), 4096)?;
    let value: Configuration = canonical(&bytes)?;
    value.validate()?;
    Ok((value, bytes))
}
fn mutation_proposal(
    operation: &str,
    root: &PublisherRoot,
    anchor: &mut UtcAnchor,
    input: Option<&(Configuration, Vec<u8>)>,
    installation: &str,
) -> Result<serde_json::Value> {
    match operation {
        "draft" => {
            let (_, bytes) = input.ok_or("UTC reviewed key input missing")?;
            let state = open(root, anchor)?;
            let proposal = serde_json::json!({"schema_version":1,"kind":"windows-utc-key-draft-v1",
                "input_sha256":hash(bytes),"base_head":bundle::hex(&state.replay()?.0),"installation":installation});
            Ok(
                serde_json::json!({"review_sha256":hash(&serde_json::to_vec(&proposal)?),"proposal":proposal}),
            )
        }
        "commission" => draft_report(root, anchor),
        "revoke" => {
            let state = open(root, anchor)?;
            let (head, active) = state.replay()?;
            let Some(ActiveKey { public_blob, .. }) = active else {
                return Err("UTC no active key to revoke".into());
            };
            let proposal = serde_json::json!({"schema_version":1,"kind":"windows-utc-key-revoke-v1",
                "base_head":bundle::hex(&head),"public_sha256":hash(&decode_public(public_blob)?)});
            Ok(
                serde_json::json!({"review_sha256":hash(&serde_json::to_vec(&proposal)?),"proposal":proposal}),
            )
        }
        "authorize" => {
            let (wanted, bytes) = input.ok_or("UTC reviewed source-policy input missing")?;
            let state = open(root, anchor)?;
            let (head, active) = state.replay()?;
            let selected = active.ok_or("UTC source amendment requires active key")?;
            validate_policy_amendment(selected.configuration, wanted)?;
            let proposal = serde_json::json!({"schema_version":1,"kind":"windows-utc-key-authorize-v1",
                "input_sha256":hash(bytes),"base_head":bundle::hex(&head),"installation":installation,
                "public_sha256":hash(&decode_public(selected.public_blob)?),"configuration":wanted,
                "key_replaced":false,"transport_replaced":false});
            Ok(
                serde_json::json!({"review_sha256":hash(&serde_json::to_vec(&proposal)?),"proposal":proposal}),
            )
        }
        "reconcile" => pending_report(root, anchor),
        _ => Err("unsupported closed UTC key operation".into()),
    }
}
fn mutation_scope(operation: &str, review: &str) -> Result<crate::finite_grants::Use> {
    let (id, action) = match operation {
        "draft" => (
            "windows-utc-key-draft-v1",
            crate::finite_grants::Action::ProvisionResource,
        ),
        "commission" => (
            "windows-utc-key-commission-v1",
            crate::finite_grants::Action::ProvisionResource,
        ),
        "revoke" => (
            "windows-utc-key-revoke-v1",
            crate::finite_grants::Action::ProvisionResource,
        ),
        "reconcile" => (
            "windows-utc-key-reconcile-v1",
            crate::finite_grants::Action::RecoverResource,
        ),
        "authorize" => (
            "windows-utc-key-authorize-v1",
            crate::finite_grants::Action::ProvisionResource,
        ),
        _ => return Err("unsupported UTC finite mutation scope".into()),
    };
    usage(id, action, review)
}
fn inspection_proposal(
    operation: &str,
    installation: &str,
    input: Option<&(Configuration, Vec<u8>)>,
) -> Result<serde_json::Value> {
    nonzero(installation)?;
    if !matches!(
        operation,
        "draft" | "commission" | "revoke" | "reconcile" | "authorize"
    ) {
        return Err("unsupported UTC inspection operation".into());
    }
    let input_sha256 = input.map(|(_, bytes)| hash(bytes));
    if matches!(operation, "draft" | "authorize") != input_sha256.is_some() {
        return Err("UTC inspection input shape differs".into());
    }
    let proposal = serde_json::json!({"schema_version":1,"kind":"windows-utc-key-inspection-v1","operation":operation,
        "installation":installation,"input_sha256":input_sha256,"original_admin_read_required":true});
    Ok(
        serde_json::json!({"review_sha256":hash(&serde_json::to_vec(&proposal)?),"proposal":proposal}),
    )
}
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let command = args.first().ok_or("UTC publisher command missing")?;
    let (operation, mode) = match command.as_str() {
        "utc-windows-key-draft-review" => ("draft", "review"),
        "utc-windows-key-draft-inspect" => ("draft", "inspect"),
        "utc-windows-key-draft" => ("draft", "mutate"),
        "utc-windows-key-commission-review" => ("commission", "review"),
        "utc-windows-key-commission-inspect" => ("commission", "inspect"),
        "utc-windows-key-commission" => ("commission", "mutate"),
        "utc-windows-key-revoke-review" => ("revoke", "review"),
        "utc-windows-key-revoke-inspect" => ("revoke", "inspect"),
        "utc-windows-key-revoke" => ("revoke", "mutate"),
        "utc-windows-key-reconcile-review" => ("reconcile", "review"),
        "utc-windows-key-reconcile-inspect" => ("reconcile", "inspect"),
        "utc-windows-key-reconcile" => ("reconcile", "mutate"),
        "utc-windows-key-authorize-review" => ("authorize", "review"),
        "utc-windows-key-authorize-inspect" => ("authorize", "inspect"),
        "utc-windows-key-authorize" => ("authorize", "mutate"),
        _ => return Err("unsupported exact UTC key ceremony".into()),
    };
    let needs_input = matches!(operation, "draft" | "authorize");
    let count = if mode == "review" {
        if needs_input {
            3
        } else {
            2
        }
    } else if needs_input {
        5
    } else {
        4
    };
    if args.len() != count {
        return Err("UTC key ceremony exact argc required".into());
    }
    let login = &args[1];
    let (_, _, installation) = crate::admin_governance::current_principal(login)?;
    // This is caller-supplied inert config, never an installed U key/history.
    let input = if needs_input {
        Some(config_input(&args[if mode == "review" { 2 } else { 3 }])?)
    } else {
        None
    };
    let inspection = inspection_proposal(operation, &installation, input.as_ref())?;
    let inspection_review = inspection["review_sha256"]
        .as_str()
        .ok_or("UTC pure inspection review missing")?;
    let read_scope = usage(
        "windows-utc-key-inspection-v1",
        crate::finite_grants::Action::Read,
        inspection_review,
    )?;
    if mode == "review" {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"inspection":inspection,"usage":read_scope,
            "private_state_read":false,"authority_returned":false})
            )?
        );
        return Ok(());
    }
    let reviewed = &args[if needs_input { 4 } else { 3 }];
    nonzero(reviewed)?;
    if mode == "inspect" && reviewed != inspection_review {
        return Err("UTC pure inspection intent changed".into());
    }
    let scope = if mode == "inspect" {
        read_scope
    } else {
        mutation_scope(operation, reviewed)?
    };
    let result = crate::admin_governance::with_grant(login, &args[2], &scope, |guard| {
        guard.require_admin()?;
        // Only the ORIGINAL genuine finite Read or Provision/Recover boundary
        // may open U and unseal its NV authorization. Root/JSON is not a role.
        let mut anchor = UtcAnchor::installed()?;
        let root = PublisherRoot::installed()?;
        guard.require_admin()?;
        if anchor.installation() != installation {
            return Err("UTC publisher belongs to another installed Admin domain".into());
        }
        let proposal =
            mutation_proposal(operation, &root, &mut anchor, input.as_ref(), &installation)?;
        guard.require_admin()?;
        let actual_review = proposal["review_sha256"]
            .as_str()
            .ok_or("UTC actual private mutation review missing")?;
        if mode == "inspect" {
            return Ok(
                serde_json::json!({"proposal":proposal,"usage":mutation_scope(operation,actual_review)?,
                "original_admin_read_verified":true,"authority_returned":false}),
            );
        }
        if actual_review != reviewed {
            return Err("UTC actual mutation review changed; inspect again under Read".into());
        }
        let effect =
            guard.effect_begin(reviewed, crate::policy_decisions::EffectKind::Checkpoint)?;
        let mut check = || {
            guard.require_admin()?;
            root.recheck()
        };
        match operation {
            "draft" => {
                absent(&root, ".key-draft.json")?;
                let (configuration, bytes) = input.as_ref().ok_or("UTC key input missing")?;
                if config_input(&args[3])?.1 != *bytes
                    || transport_pin()? != configuration.transport_sha256
                {
                    return Err(
                        "UTC key config/actual commissioned transport changed after review".into(),
                    );
                }
                let state = open(&root, &mut anchor)?;
                let (scalar, public) = crate::utc_windows_crypto::generate(&mut check)?;
                let secret = Secret::from_buffer(scalar);
                let sealed = anchor.seal_time_key(&secret)?;
                let recovered = anchor.unseal_time_key(&sealed)?;
                if recovered.bytes() != secret.bytes()
                    || public_from_secret(&recovered, &mut check)? != public
                {
                    return Err("UTC TPM-sealed scalar roundtrip differs".into());
                }
                let draft = Draft {
                    schema_version: 1,
                    installation: installation.clone(),
                    base_head: bundle::hex(&state.replay()?.0),
                    configuration: configuration.clone(),
                    public_blob: bundle::hex(&public),
                    sealed,
                };
                check()?;
                write_new(&root, ".key-draft.json", &serde_json::to_vec(&draft)?)?;
            }
            "commission" => {
                let bytes = read(&root, ".key-draft.json")?;
                let draft: Draft = canonical(&bytes)?;
                if hash(&bytes) != *reviewed {
                    return Err("UTC exact sealed draft changed".into());
                }
                let secret = anchor.unseal_time_key(&draft.sealed)?;
                if public_from_secret(&secret, &mut check)? != decode_public(&draft.public_blob)? {
                    return Err("UTC commissioned scalar/public pin mismatch".into());
                }
                check()?;
                prepare_change(
                    &root,
                    &mut anchor,
                    Change::Commission {
                        configuration: draft.configuration,
                        public_blob: draft.public_blob,
                        sealed: draft.sealed,
                    },
                    Some(hash(&bytes)),
                    &mut check,
                )?;
            }
            "revoke" => {
                let public_sha256 = proposal["proposal"]["public_sha256"]
                    .as_str()
                    .ok_or("UTC current revoke key absent")?
                    .to_owned();
                prepare_change(
                    &root,
                    &mut anchor,
                    Change::Revoke { public_sha256 },
                    None,
                    &mut check,
                )?;
            }
            "authorize" => {
                let (configuration, bytes) =
                    input.as_ref().ok_or("UTC source-policy input missing")?;
                if config_input(&args[3])?.1 != *bytes
                    || transport_pin()? != configuration.transport_sha256
                {
                    return Err("UTC reviewed source-policy input/transport changed".into());
                }
                let public_sha256 = proposal["proposal"]["public_sha256"]
                    .as_str()
                    .ok_or("UTC source-policy active public pin absent")?
                    .to_owned();
                prepare_change(
                    &root,
                    &mut anchor,
                    Change::AuthorizeSources {
                        public_sha256,
                        configuration: configuration.clone(),
                    },
                    None,
                    &mut check,
                )?;
            }
            "reconcile" => finalize_change(&root, &mut anchor, reviewed, &mut check)?,
            _ => return Err("unsupported already-validated UTC mutation".into()),
        }
        check()?;
        drop(check);
        let result = if operation == "draft" {
            draft_report(&root, &mut anchor)?
        } else {
            let state = open(&root, &mut anchor)?;
            serde_json::json!({"schema_version":1,"protected_u_head":bundle::hex(&state.replay()?.0),"key_state_committed":true,
                "service_started":false,"windows_commissioned":false,"physical_qualified":false,"production_qualified":false})
        };
        guard.effect_complete(effect, &hash(&serde_json::to_vec(&result)?))?;
        Ok(result)
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn challenge(bytes: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let length = 4 + CHALLENGE.len() + 96;
    if bytes.len() != length
        || bytes[..4] != (CHALLENGE.len() as u32).to_be_bytes()
        || &bytes[4..4 + CHALLENGE.len()] != CHALLENGE
    {
        return Err("UTC exact bounded Windows challenge purpose required".into());
    }
    let body = &bytes[4 + CHALLENGE.len()..];
    let mut fields = [[0u8; 32]; 3];
    for (field, input) in fields.iter_mut().zip(body.chunks_exact(32)) {
        field.copy_from_slice(input);
        if *field == [0; 32] {
            return Err("UTC challenge zero identity refused".into());
        }
    }
    Ok((fields[0], fields[1], fields[2]))
}
fn proof(bytes: &[u8], lower: i64, upper: i64) -> Result<Vec<u8>> {
    challenge(bytes)?;
    let mut value = (crate::utc_windows_crypto::DOMAIN.len() as u32)
        .to_be_bytes()
        .to_vec();
    value.extend(crate::utc_windows_crypto::DOMAIN);
    value.extend(&bytes[bytes.len() - 96..]);
    value.extend(u64::try_from(lower)?.to_be_bytes());
    value.extend(u64::try_from(upper)?.to_be_bytes());
    crate::utc_windows_crypto::message(&value)?;
    Ok(value)
}
fn response(proof: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
    crate::utc_windows_crypto::message(proof)?;
    let mut value = (DELIVERY.len() as u32).to_be_bytes().to_vec();
    value.extend(DELIVERY);
    value.extend((proof.len() as u32).to_be_bytes());
    value.extend(proof);
    value.extend(signature);
    Ok(value)
}
fn budgets() -> Result<()> {
    unit_budget(
        "luma-utc-windows.service",
        256 * 1024 * 1024,
        4,
        "100000 100000\n",
    )?;
    peer_status(
        &proc_text(i32::try_from(std::process::id())?, "status", 16384)?,
        0,
        FRONT_UID,
        "luma-utc-windows (enforce)",
    )?;
    let root = Path::new("/sys/fs/cgroup/system.slice/luma-utc-windows.service");
    let file = File::open(root)?;
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut volume) } != 0 || volume.f_type != 0x63677270 {
        return Err("UTC actual cgroup2 fixed unit budget required".into());
    }
    for (name, expected) in [
        ("memory.max", "268435456\n"),
        ("memory.swap.max", "0\n"),
        ("pids.max", "4\n"),
    ] {
        let value = fs::read_to_string(root.join(name))?;
        if value != expected {
            return Err("UTC actual fixed unit budget tuple differs".into());
        }
    }
    if fs::read_to_string("/proc/self/cgroup")? != "0::/system.slice/luma-utc-windows.service\n"
        || fs::read_to_string("/proc/self/attr/current")?.trim_end_matches('\n')
            != "luma-utc-windows (enforce)"
    {
        return Err("UTC daemon requires exact enforcing unit/profile".into());
    }
    Ok(())
}
fn issue(stream: &UnixStream, bytes: &[u8]) -> Result<Vec<u8>> {
    budgets()?;
    let (installation, _, source) = challenge(bytes)?;
    let front_command =
        b"/usr/bin/python3\0-I\0-S\0-B\0/usr/libexec/luma-os/utc-windows-front.py\0";
    let front = peer(
        stream,
        FRONT_UID,
        "luma-utc-windows-front (enforce)",
        "0::/system.slice/luma-utc-windows-front.service\n",
        front_command,
    )?;
    let mut anchor = UtcAnchor::installed()?;
    let root = PublisherRoot::installed()?;
    let state = open(&root, &mut anchor)?;
    let (
        _,
        Some(ActiveKey {
            configuration,
            public_blob,
            sealed,
        }),
    ) = state.replay()?
    else {
        return Err("UTC no currently commissioned independent TimeKey".into());
    };
    if configuration
        .windows_installations
        .binary_search(&bundle::hex(&installation))
        .is_err()
        || !configuration.permits_source(&installation, &source)
        || transport_pin()? != configuration.transport_sha256
    {
        return Err("UTC installation/exact reviewed release or trust-transition/transport not commissioned by current U state".into());
    }
    let state_bytes = read(&root, "journal.json")?;
    let head = anchor.read()?;
    let public = decode_public(public_blob)?;
    let secret = anchor.unseal_time_key(sealed)?;
    let mut check = || {
        if !crate::resource_manager::pidfd_alive(&front)?
            || anchor.read()? != head
            || read(&root, "journal.json")? != state_bytes
        {
            return Err("UTC original frontend/U key state changed".into());
        }
        absent(&root, ".pending.json")?;
        if transport_pin()? != configuration.transport_sha256 {
            return Err("UTC commissioned transport changed".into());
        }
        Ok(())
    };
    if public_from_secret(&secret, &mut check)? != public {
        return Err("UTC actual sealed TimeKey does not match commissioned public key".into());
    }
    check()?;
    let before = current_time()?;
    let encoded = proof(bytes, before.lower_ms, before.upper_ms)?;
    let mut scalar = PrivateBuffer::new(32)?;
    scalar.bytes_mut().copy_from_slice(secret.bytes());
    let signature = crate::utc_windows_crypto::sign(&scalar, &encoded, &mut check)?;
    crate::utc_windows_crypto::verify(&public, &encoded, &signature, &mut check)?;
    let after = current_time()?;
    let mut original_context = before.context;
    original_context.floor_ms = after.context.floor_ms;
    if original_context != after.context
        || before.history_head != after.history_head
        || after.lower_ms < before.lower_ms
    {
        return Err("UTC protected history/provider generation changed while signing".into());
    }
    check()?;
    let _ = peer(
        stream,
        FRONT_UID,
        "luma-utc-windows-front (enforce)",
        "0::/system.slice/luma-utc-windows-front.service\n",
        front_command,
    )?;
    response(&encoded, &signature)
}
pub(crate) fn serve() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    budgets()?;
    if unsafe { libc::getegid() } != FRONT_UID {
        return Err("UTC root service requires fixed frontend runtime group985".into());
    }
    let parent = Path::new(SOCKET)
        .parent()
        .ok_or("UTC runtime parent absent")?;
    let info = fs::symlink_metadata(parent)?;
    if !info.is_dir()
        || info.uid() != 0
        || info.gid() != FRONT_UID
        || info.mode() & 0o7777 != 0o750
        || fs::canonicalize(parent)? != parent
    {
        return Err("UTC fixed runtime directory protections differ".into());
    }
    // Never unlink a socket or infer that retained runtime state is stale.
    let listener = UnixListener::bind(SOCKET)?;
    let mode = std::os::unix::fs::PermissionsExt::from_mode(0o660);
    fs::set_permissions(SOCKET, mode)?;
    let socket = fs::symlink_metadata(SOCKET)?;
    if !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.gid() != FRONT_UID
        || socket.nlink() != 1
    {
        return Err("UTC runtime socket identity differs".into());
    }
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        stream.set_read_timeout(Some(Duration::from_secs(4)))?;
        stream.set_write_timeout(Some(Duration::from_secs(4)))?;
        let handled = (|| -> Result<()> {
            let command =
                b"/usr/bin/python3\0-I\0-S\0-B\0/usr/libexec/luma-os/utc-windows-front.py\0";
            let _ = peer(
                &stream,
                FRONT_UID,
                "luma-utc-windows-front (enforce)",
                "0::/system.slice/luma-utc-windows-front.service\n",
                command,
            )?;
            let bytes = unframe(&mut stream, 1024)?;
            let mut extra = [0u8; 1];
            if stream.read(&mut extra)? != 0 {
                return Err("UTC extra challenge bytes refused".into());
            }
            let value = issue(&stream, &bytes)?;
            frame(&mut stream, &value)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            Ok(())
        })();
        if handled.is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
    Err("UTC fixed listener stopped unexpectedly".into())
}

#[cfg(test)]
pub(crate) fn exercise_emulator_journal(
    root: &PublisherRoot,
    anchor: &mut UtcAnchor,
    checkpoint: &Path,
    public_path: &Path,
    signature_path: &Path,
) {
    initialize_at(root, anchor, &mut || Ok(())).unwrap();
    assert!(initialize_at(root, anchor, &mut || Ok(())).is_err());
    let original = read(root, "journal.json").unwrap();
    let (scalar, public) = crate::utc_windows_crypto::generate(|| Ok(())).unwrap();
    let secret = Secret::from_buffer(scalar);
    let sealed = anchor
        .fixture_sealed_time_key(checkpoint, public_path, signature_path, &secret)
        .unwrap();
    let configuration = Configuration {
        schema_version: 1,
        windows_installations: vec!["11".repeat(32)],
        authorized_sources: vec![AuthorizedSource {
            installation: "11".repeat(32),
            purpose: "release".into(),
            sha256: "44".repeat(32),
        }],
        transport_sha256: "22".repeat(32),
    };
    prepare_change(
        root,
        anchor,
        Change::Commission {
            configuration: configuration.clone(),
            public_blob: bundle::hex(&public),
            sealed: sealed.clone(),
        },
        None,
        &mut || Ok(()),
    )
    .unwrap();
    let selected = open(root, anchor).unwrap();
    assert_eq!(selected.events.len(), 1);
    let selected = selected.replay().unwrap().1.unwrap();
    assert_eq!(decode_public(selected.public_blob).unwrap(), public);
    assert!(selected.sealed == &sealed);
    let mut wanted = configuration.clone();
    wanted.authorized_sources.push(AuthorizedSource {
        installation: "11".repeat(32),
        purpose: "trust-change".into(),
        sha256: "55".repeat(32),
    });
    prepare_change(
        root,
        anchor,
        Change::AuthorizeSources {
            public_sha256: hash(&public),
            configuration: wanted.clone(),
        },
        None,
        &mut || Ok(()),
    )
    .unwrap();
    let selected = open(root, anchor).unwrap();
    assert_eq!(selected.events.len(), 2);
    let selected = selected.replay().unwrap().1.unwrap();
    assert_eq!(selected.configuration, &wanted);
    assert_eq!(decode_public(selected.public_blob).unwrap(), public);
    assert!(selected.sealed == &sealed);
    let base = anchor.read().unwrap();
    let mut boundaries = 0;
    assert!(prepare_change(
        root,
        anchor,
        Change::Revoke {
            public_sha256: hash(&public)
        },
        None,
        &mut || {
            boundaries += 1;
            // Exactly the first finalize callback, after the one-shot TPM extend.
            if boundaries == 5 {
                Err("fixture revocation after NV before publication".into())
            } else {
                Ok(())
            }
        }
    )
    .is_err());
    assert_eq!(boundaries, 5);
    let committed = anchor.read().unwrap();
    assert_ne!(committed, base);
    assert!(open(root, anchor).is_err());
    let pending = pending_report(root, anchor).unwrap();
    let review = pending["review_sha256"].as_str().unwrap();
    finalize_change(root, anchor, review, &mut || Ok(())).unwrap();
    assert_eq!(anchor.read().unwrap(), committed);
    let state = open(root, anchor).unwrap();
    assert_eq!(state.events.len(), 3);
    assert!(state.replay().unwrap().1.is_none());
    assert!(finalize_change(root, anchor, review, &mut || Ok(())).is_err());
    assert!(initialize_at(root, anchor, &mut || Ok(())).is_err());
    let latest = read(root, "journal.json").unwrap();
    write_new(root, "fixture-rollback.json", &original).unwrap();
    rename(root, "fixture-rollback.json", "journal.json", true).unwrap();
    assert!(open(root, anchor).is_err());
    assert_eq!(anchor.read().unwrap(), committed);
    write_new(root, "fixture-restored.json", &latest).unwrap();
    rename(root, "fixture-restored.json", "journal.json", true).unwrap();
    assert_eq!(open(root, anchor).unwrap().events.len(), 3);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_peer_status_requires_all_ids_capability_sets_and_kernel_sandbox_flags() {
        let status="Uid:\t985\t985\t985\t985\nGid:\t985\t985\t985\t985\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        peer_status(status, 985, 985, "luma-utc-windows-front (enforce)").unwrap();
        for (old, new) in [
            ("985\t985\t985\t985", "985\t985\t0\t985"),
            ("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000080000"),
            ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("Seccomp:\t2", "Seccomp:\t0"),
        ] {
            assert!(peer_status(
                &status.replacen(old, new, 1),
                985,
                985,
                "luma-utc-windows-front (enforce)"
            )
            .is_err());
        }
        assert!(peer_status(
            &format!("{status}Seccomp:\t2\n"),
            985,
            985,
            "luma-utc-windows-front (enforce)"
        )
        .is_err());
        assert!(peer_status(status, 985, 0, "luma-utc-windows-front (enforce)").is_err());
        let broker = status
            .replace("985\t985\t985\t985", "0\t0\t0\t0")
            .replacen("Gid:\t0\t0\t0\t0", "Gid:\t990\t990\t990\t990", 1)
            .replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000080000")
            .replace("CapEff:\t0000000000000000", "CapEff:\t0000000000080000")
            .replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000080000");
        peer_status(&broker, 0, 990, "luma-broker (enforce)").unwrap();
        assert!(peer_status(&broker, 0, 990, "luma-utc-windows (enforce)").is_err());
        assert!(unit_budget("caller-unit.service", 1, 1, "max 100000\n").is_err());
    }
    #[test]
    fn pure_inspection_never_opens_private_key_state_or_self_authorizes_a_mutation() {
        let installation = "11".repeat(32);
        for operation in ["commission", "revoke", "reconcile"] {
            let proposal = inspection_proposal(operation, &installation, None).unwrap();
            assert_eq!(proposal["proposal"]["original_admin_read_required"], true);
            assert!(proposal["proposal"]
                .get("current_protected_state")
                .is_none());
            let review = proposal["review_sha256"].as_str().unwrap();
            let scope = usage(
                "windows-utc-key-inspection-v1",
                crate::finite_grants::Action::Read,
                review,
            )
            .unwrap();
            assert_eq!(scope.selector.kind, crate::finite_grants::Kind::File);
            assert_ne!(
                scope.action,
                mutation_scope(operation, review).unwrap().action
            );
        }
        assert!(inspection_proposal("draft", &installation, None).is_err());
        assert!(inspection_proposal("clear", &installation, None).is_err());
    }
    fn challenge_fixture() -> Vec<u8> {
        let mut bytes = (CHALLENGE.len() as u32).to_be_bytes().to_vec();
        bytes.extend(CHALLENGE);
        bytes.extend([1u8; 32]);
        bytes.extend([2u8; 32]);
        bytes.extend([3u8; 32]);
        bytes
    }
    #[test]
    fn closed_windows_wire_fields_and_bound_proof_match_exact_binary_purpose() {
        let bytes = challenge_fixture();
        let fields = challenge(&bytes).unwrap();
        assert_eq!(fields.0, [1; 32]);
        assert_eq!(fields.1, [2; 32]);
        assert_eq!(fields.2, [3; 32]);
        let encoded = proof(&bytes, 1_800_000_000_000, 1_800_000_000_500).unwrap();
        crate::utc_windows_crypto::message(&encoded).unwrap();
        assert!(response(&encoded, &[4; 64]).unwrap().ends_with(&[4; 64]));
        for index in [0, 4] {
            let mut wrong = bytes.clone();
            wrong[index] ^= 1;
            assert!(challenge(&wrong).is_err());
        }
        let mut wrong = bytes.clone();
        wrong[4 + CHALLENGE.len()..4 + CHALLENGE.len() + 32].fill(0);
        assert!(challenge(&wrong).is_err());
        assert!(proof(&bytes, 0, 500).is_err());
        assert!(proof(&bytes, 100, 10101).is_err());
        assert!(proof(&bytes, 500, 499).is_err());
        assert!(proof(&bytes, 1, 4_102_444_800_001).is_err());
    }
    #[test]
    fn exact_configuration_and_original_finite_key_scope_refuse_authority_substitution() {
        let mut config = Configuration {
            schema_version: 1,
            windows_installations: vec!["11".repeat(32)],
            authorized_sources: vec![AuthorizedSource {
                installation: "11".repeat(32),
                purpose: "release".into(),
                sha256: "44".repeat(32),
            }],
            transport_sha256: "22".repeat(32),
        };
        config.validate().unwrap();
        assert!(validate_policy_amendment(&config, &config).is_err());
        let mut wanted = config.clone();
        wanted.authorized_sources.push(AuthorizedSource {
            installation: "11".repeat(32),
            purpose: "trust-change".into(),
            sha256: "55".repeat(32),
        });
        validate_policy_amendment(&config, &wanted).unwrap();
        let input = (wanted.clone(), serde_json::to_vec(&wanted).unwrap());
        let proposal = inspection_proposal("authorize", &"11".repeat(32), Some(&input)).unwrap();
        assert_eq!(proposal["proposal"]["original_admin_read_required"], true);
        assert!(inspection_proposal("authorize", &"11".repeat(32), None).is_err());
        let mut changed = wanted.clone();
        changed.transport_sha256 = "33".repeat(32);
        assert!(validate_policy_amendment(&config, &changed).is_err());
        let mut changed = wanted.clone();
        changed.windows_installations.push("66".repeat(32));
        assert!(validate_policy_amendment(&config, &changed).is_err());
        assert!(config.permits_source(&[0x11; 32], &[0x44; 32]));
        assert!(!config.permits_source(&[0x11; 32], &[0x45; 32]));
        assert!(!config.permits_source(&[0x12; 32], &[0x44; 32]));
        let mut changed = config.clone();
        changed.authorized_sources[0].purpose = "trust-change".into();
        changed.validate().unwrap();
        changed.authorized_sources[0].purpose = "runtime-update".into();
        changed.validate().unwrap();
        validate_policy_amendment(&config, &changed).unwrap();
        changed.authorized_sources[0].purpose = "host-file-read".into();
        changed.validate().unwrap();
        validate_policy_amendment(&config, &changed).unwrap();
        assert!(changed.permits_source(&[0x11; 32], &[0x44; 32]));
        assert!(!changed.permits_source(&[0x12; 32], &[0x44; 32]));
        assert!(!changed.permits_source(&[0x11; 32], &[0x45; 32]));
        changed.authorized_sources[0].purpose = "host-file-enrollment".into();
        changed.validate().unwrap();
        validate_policy_amendment(&config, &changed).unwrap();
        assert!(changed.permits_source(&[0x11; 32], &[0x44; 32]));
        changed.authorized_sources[0].purpose = "any-caller-digest".into();
        assert!(changed.validate().is_err());
        let mut changed = config.clone();
        changed
            .authorized_sources
            .push(changed.authorized_sources[0].clone());
        assert!(changed.validate().is_err());
        let mut changed = config.clone();
        changed.authorized_sources.clear();
        assert!(changed.validate().is_err());
        config.windows_installations.push("11".repeat(32));
        assert!(config.validate().is_err());
        config.windows_installations = vec!["00".repeat(32)];
        assert!(config.validate().is_err());
        let value = usage(
            "windows-utc-key-commission-v1",
            crate::finite_grants::Action::ProvisionResource,
            &"11".repeat(32),
        )
        .unwrap();
        assert_eq!(value.selector.kind, crate::finite_grants::Kind::Resource);
        assert!(usage(
            "windows-utc-key-commission-v1",
            crate::finite_grants::Action::ProvisionResource,
            &"00".repeat(32)
        )
        .is_err());
        assert!(config_input("/tmp/caller.json").is_err());
        assert!(name("../journal.json").is_err());
    }
    #[test]
    fn empty_journal_selected_head_and_domain_separation_cannot_be_file_authority() {
        let witness = crate::utc_windows_checkpoint::genesis_descriptor(
            &"11".repeat(32),
            (1, 2, 0, 0, 0o40700),
        )
        .unwrap();
        let genesis = hash(&serde_json::to_vec(&witness).unwrap());
        let journal = Journal {
            schema_version: 1,
            installation: "11".repeat(32),
            genesis: genesis.clone(),
            genesis_descriptor: witness,
            events: vec![],
        };
        assert_eq!(
            journal.replay().unwrap().0,
            tpm::extend_value([0; 32], tpm::decode(&genesis).unwrap())
        );
        assert!(journal.replay().unwrap().1.is_none());
        let mut bad = journal.clone();
        bad.installation = "00".repeat(32);
        assert!(bad.replay().is_err());
        let mut bad = journal.clone();
        bad.installation = "33".repeat(32);
        assert!(bad.replay().is_err());
        bad.genesis_descriptor["installation"] = "33".repeat(32).into();
        assert!(bad.replay().is_err());
        bad.genesis_descriptor["namespace"] = "/var/lib/luma-os/content-store".into();
        assert!(bad.replay().is_err());
        let event = Event {
            sequence: 1,
            previous_head: bundle::hex(&journal.replay().unwrap().0),
            change: Change::Revoke {
                public_sha256: "33".repeat(32),
            },
        };
        let mut bad = journal;
        bad.events.push(event);
        assert!(bad.replay().is_err());
    }
}
