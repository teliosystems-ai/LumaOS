//! Live, kernel-peer-bound admission delivery from the confined PAM client.
//! A proof frame has no authority outside its original pending challenge/peer.
use super::*;
use crate::finite_grants::{Action, Kind, Selector, Use};
use crate::resource_manager::requests::gateway::{
    ChatMessage, Message, Output, Request as GatewayRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

const PROFILE: &str = "luma-granted-client (enforce)";
const CLIENT_PROFILE: &str = "/etc/apparmor.d/luma-granted-client";
const IMAGE_EXE: &str = "/usr/libexec/luma-os/luma-platform";
const CHALLENGE_LIMIT: usize = 4096;
const CHALLENGE_BUDGET: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Challenge {
    schema_version: u32,
    kind: String,
    nonce: String,
    job: String,
    usage: Use,
    input_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema_version: u32,
    kind: String,
    nonce: String,
    job: String,
    audit: crate::finite_grants::Audit,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    schema_version: u32,
    kind: String,
    job: String,
    output: Output,
    receipt: crate::resource_manager::requests::gateway::Permit,
}

fn label(socket: &UnixStream) -> Result<()> {
    let mut value = [0u8; 128];
    let mut size = value.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            value.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size == 0
        || size as usize > value.len()
    {
        return Err("grant client kernel security label unavailable".into());
    }
    let mut bytes = &value[..size as usize];
    if bytes.last() == Some(&0) {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes != PROFILE.as_bytes() {
        return Err("grant proof requires the fixed enforcing client profile".into());
    }
    Ok(())
}

fn kernel_text(path: &Path, maximum: u64, magic: libc::c_long) -> Result<String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != magic
        || !file.metadata()?.is_file()
    {
        return Err("grant client controls require actual public kernel metadata".into());
    }
    let mut text = String::new();
    (&mut file).take(maximum + 1).read_to_string(&mut text)?;
    if text.len() as u64 > maximum {
        return Err("grant client kernel control observation exceeds bound".into());
    }
    Ok(text)
}

fn client_status(status: &str) -> Result<()> {
    let field = |name: &str| -> Result<&str> {
        let prefix = format!("{name}:");
        let mut values = status
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .map(str::trim);
        let value = values
            .next()
            .ok_or("grant client kernel control field missing")?;
        if values.next().is_some() {
            return Err("grant client kernel control field duplicated".into());
        }
        Ok(value)
    };
    if field("NoNewPrivs")? != "1" || field("Seccomp")? != "2" {
        return Err("grant client privilege/filter enforcement unavailable".into());
    }
    for name in ["CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"] {
        let value = field(name)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err("grant client kernel capability observation malformed".into());
        }
        let caps = u64::from_str_radix(value, 16)?;
        if (matches!(name, "CapInh" | "CapAmb") && caps != 0) || caps & !1 != 0 {
            return Err("grant client capabilities exceed the closed CHOWN-only plan".into());
        }
    }
    Ok(())
}

struct ImagePin {
    path: &'static str,
    file: fs::File,
    metadata: (u64, u64, u64, i64, i64, i64, i64),
}
impl ImagePin {
    fn capture(path: &'static str, expected: Option<&[u8]>) -> Result<Self> {
        for parent in Path::new(path).ancestors().skip(1) {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("grant source image parent is mutable or substituted".into());
            }
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_flag & libc::ST_RDONLY == 0
        {
            return Err("grant source must be installed immutable image bytes".into());
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7022 != 0
            || metadata.len() == 0
            || metadata.len() > 64 * 1024 * 1024
        {
            return Err("invalid immutable grant source file".into());
        }
        let mut raw = Vec::new();
        (&file).take(metadata.len() + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 != metadata.len() || expected.is_some_and(|v| v != raw) {
            return Err("grant source image file differs from the compiled closed policy".into());
        }
        let pin = Self {
            path,
            file,
            metadata: (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        };
        pin.check()?;
        Ok(pin)
    }
    fn check(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(self.path)?;
        let retained = self.file.metadata()?;
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
        let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7022 != 0
            || key(&metadata) != self.metadata
            || key(&retained) != self.metadata
            || unsafe { libc::fstatvfs(self.file.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_flag & libc::ST_RDONLY == 0
        {
            return Err("immutable grant source file changed".into());
        }
        Ok(())
    }
}

pub(crate) struct Admission {
    socket: UnixStream,
    pin: fs::File,
    peer: libc::ucred,
    job: String,
    usage: Use,
    input_sha256: String,
    image: ImagePin,
    policy: ImagePin,
    fenced: bool,
    audit: Option<crate::finite_grants::Audit>,
}
impl Admission {
    pub(crate) fn capture(
        socket: &UnixStream,
        job: &str,
        usage: Use,
        input_sha256: String,
    ) -> Result<Self> {
        usage.validate()?;
        crate::tpm::decode::<32>(&input_sha256)?;
        let peer = credentials(socket)?;
        if peer.uid != 0
            || peer.gid != 0
            || peer.pid <= 0
            || job.len() != 32
            || !job
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err("grant admission requires the original protected local client".into());
        }
        let mut admission = Self {
            socket: socket.try_clone()?,
            pin: peer_pidfd(socket)?,
            peer,
            job: job.into(),
            usage,
            input_sha256,
            image: ImagePin::capture(IMAGE_EXE, None)?,
            policy: ImagePin::capture(
                CLIENT_PROFILE,
                Some(include_bytes!(
                    "../../../../native/image/overlay/etc/apparmor.d/luma-granted-client"
                )),
            )?,
            fenced: false,
            audit: None,
        };
        admission.check()?;
        Ok(admission)
    }
    fn peer_check(&self) -> Result<()> {
        let peer = credentials(&self.socket)?;
        if (peer.pid, peer.uid, peer.gid) != (self.peer.pid, self.peer.uid, self.peer.gid) {
            return Err("grant admission original kernel peer changed".into());
        }
        label(&self.socket)?;
        crate::credential_observer::kernel_check(&self.pin, 0, 0)?;
        let process = Path::new("/proc").join(self.peer.pid.to_string());
        client_status(&kernel_text(&process.join("status"), 65_536, 0x9fa0)?)?;
        let group = kernel_text(&process.join("cgroup"), 4096, 0x9fa0)?;
        let unit = group
            .strip_prefix("0::/system.slice/luma-granted-client-")
            .and_then(|v| v.strip_suffix(".service\n"))
            .filter(|v| {
                v.len() == 32
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or("grant client is not the installed bounded launcher generation")?;
        let controls = Path::new("/sys/fs/cgroup/system.slice")
            .join(format!("luma-granted-client-{unit}.service"));
        for (name, expected) in [
            ("memory.max", "268435456"),
            ("memory.swap.max", "0"),
            ("pids.max", "16"),
            ("cpu.max", "50000 100000"),
        ] {
            if kernel_text(&controls.join(name), 128, 0x63677270)?.trim() != expected {
                return Err(
                    "grant client physical resource controls differ from the fixed plan".into(),
                );
            }
        }
        crate::credential_observer::kernel_check(&self.pin, 0, 0)?;
        self.image.check()?;
        self.policy.check()?;
        Ok(())
    }
    pub(crate) fn check(&mut self) -> Result<()> {
        if self.fenced {
            return Err("grant admission connection is fenced".into());
        }
        self.fenced = true;
        self.peer_check()?;
        let nonce = fresh_request_id()?;
        let challenge = Challenge {
            schema_version: 1,
            kind: "grant-challenge".into(),
            nonce: nonce.clone(),
            job: self.job.clone(),
            usage: self.usage.clone(),
            input_sha256: self.input_sha256.clone(),
        };
        let deadline = Instant::now() + CHALLENGE_BUDGET;
        write_frame_until(&mut self.socket, &serde_json::to_vec(&challenge)?, deadline)?;
        let raw = read_frame_until(&mut self.socket, deadline)?;
        if raw.len() > CHALLENGE_LIMIT {
            return Err("grant admission proof exceeds bound".into());
        }
        let proof: Proof = serde_json::from_slice(&raw)?;
        if proof.schema_version != 1
            || proof.kind != "grant-proof"
            || proof.nonce != nonce
            || proof.job != self.job
        {
            return Err(
                "grant admission proof does not bind the pending original challenge".into(),
            );
        }
        proof.audit.validate()?;
        if proof.audit.usage != self.usage
            || self.audit.as_ref().is_some_and(|old| old != &proof.audit)
        {
            return Err(
                "grant proof changed its original subject, grant, checkpoint or scope".into(),
            );
        }
        self.audit = Some(proof.audit);
        self.peer_check()?;
        remaining(deadline)?;
        self.fenced = false;
        Ok(())
    }
    pub(crate) fn deliver(&mut self, output: &Output, receipt: serde_json::Value) -> Result<()> {
        self.check()?;
        let value = serde_json::json!({"schema_version":1,"kind":"granted-result","job":self.job,"output":output,"receipt":receipt});
        write_frame_until(
            &mut self.socket,
            &serde_json::to_vec(&value)?,
            Instant::now() + CHALLENGE_BUDGET,
        )
    }
    pub(crate) fn attribution(&self) -> Result<&crate::finite_grants::Audit> {
        self.audit
            .as_ref()
            .filter(|_| !self.fenced)
            .ok_or_else(|| "missing current granted subject attribution".into())
    }
}

fn infer_usage(
    worker: &crate::resources::Token,
    profile: &str,
    messages: &[ChatMessage],
    max_tokens: u64,
) -> Result<Use> {
    let selected = crate::model::catalog_profile(profile)?;
    if !(1..=128).contains(&max_tokens) {
        return Err("granted inference output bound invalid".into());
    }
    crate::resource_manager::requests::gateway::messages_valid(messages)?;
    let target = crate::bundle::hex(&Sha256::digest(serde_json::to_vec(&(
        "luma-native-finite-model-target-v1",
        selected.resource_binding()?,
        worker,
    ))?));
    Ok(Use {
        action: Action::Infer,
        selector: Selector {
            kind: Kind::Model,
            id: profile.into(),
            generation: worker.generation,
            digest: target,
        },
        input_bytes: messages.iter().map(|v| v.content.len() as u64).sum(),
        output_bytes: 8192,
        units: max_tokens,
    })
}

pub(crate) fn for_request(socket: &UnixStream, request: &GatewayRequest) -> Result<Admission> {
    match &request.payload {
        Message::Submit {
            nonce,
            worker,
            profile,
            messages,
            max_output_tokens,
            ..
        } => {
            crate::model::resource_profile(profile)?;
            Admission::capture(
                socket,
                nonce,
                infer_usage(worker, profile, messages, *max_output_tokens)?,
                crate::resource_manager::requests::gateway::input_digest(messages)?,
            )
        }
        _ => Err("grant opening accepts only a closed inference submission".into()),
    }
}

/// Only this fixed code path can answer a broker challenge; it owns genuine
/// PAM and the nonserializable GrantBoundary for the entire serving operation.
pub(crate) fn infer(
    login: &str,
    grant: &str,
    messages: Vec<ChatMessage>,
    max_tokens: u64,
) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if fs::read_to_string("/proc/self/attr/current")?.trim() != PROFILE {
        return Err("granted inference requires the installed confined client launcher".into());
    }
    let identity = fresh_request_id()?;
    let job = crate::resources::random_id()?;
    let inspect = GatewayRequest {
        schema_version: 1,
        request_id: identity.clone(),
        caller: 0,
        deadline: crate::resource_manager::now()? + 3000,
        action: "resource-granted-gateway".into(),
        payload: Message::Inspect {},
    };
    let (worker, profile) = match gateway_exchange(&inspect)? {
        crate::resource_manager::requests::gateway::Status::Worker {
            worker, profile, ..
        } => (worker, profile),
        _ => return Err("granted inference serving worker unavailable".into()),
    };
    let usage = infer_usage(&worker, &profile, &messages, max_tokens)?;
    let digest = crate::resource_manager::requests::gateway::input_digest(&messages)?;
    let result = crate::admin_governance::with_grant(login, grant, &usage, |boundary| {
        let mut socket = connect_local(SOCKET, Instant::now() + Duration::from_secs(3))?;
        if peer(&socket)? != 0 {
            return Err("granted inference broker peer denied".into());
        }
        let request = GatewayRequest {
            schema_version: 1,
            request_id: identity.clone(),
            caller: 0,
            deadline: crate::resource_manager::now()? + 3000,
            action: "resource-granted-gateway".into(),
            payload: Message::Submit {
                nonce: job.clone(),
                worker: worker.clone(),
                profile: profile.clone(),
                messages: messages.clone(),
                max_output_tokens: max_tokens,
                request_deadline: crate::resource_manager::now()? + 25_000,
            },
        };
        boundary.check()?;
        write_frame_until(
            &mut socket,
            &serde_json::to_vec(&request)?,
            Instant::now() + CHALLENGE_BUDGET,
        )?;
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut accepted = false;
        loop {
            let raw = read_frame_until(&mut socket, deadline)?;
            let value: serde_json::Value = serde_json::from_slice(&raw)?;
            if value["kind"] == "grant-challenge" {
                let challenge: Challenge = serde_json::from_slice(&raw)?;
                if challenge.schema_version != 1
                    || challenge.job != job
                    || challenge.usage != usage
                    || challenge.input_sha256 != digest
                    || !challenge.nonce.starts_with("console-")
                    || challenge.nonce.len() != 40
                {
                    return Err(
                        "grant challenge substituted exact task, target or constraints".into(),
                    );
                }
                boundary.check()?;
                write_frame_until(
                    &mut socket,
                    &serde_json::to_vec(&Proof {
                        schema_version: 1,
                        kind: "grant-proof".into(),
                        nonce: challenge.nonce,
                        job: job.clone(),
                        audit: boundary.audit()?,
                    })?,
                    Instant::now() + CHALLENGE_BUDGET,
                )?;
            } else if value["kind"] == "granted-result" {
                let delivery: Delivery = serde_json::from_slice(&raw)?;
                if !accepted
                    || delivery.job != job
                    || delivery.schema_version != 1
                    || delivery.kind != "granted-result"
                {
                    return Err("granted result task differs".into());
                }
                let output = delivery.output;
                if output.text.is_empty()
                    || output.text.len() > 8192
                    || output.output_tokens > max_tokens
                    || output.prompt_tokens > 2048
                {
                    return Err("granted inference result exceeds admitted constraints".into());
                }
                boundary.check()?;
                if delivery.receipt.nonce != job
                    || delivery.receipt.worker != worker
                    || delivery.receipt.profile != profile
                    || delivery.receipt.input_digest != digest
                    || delivery.receipt.max_output_tokens != max_tokens
                    || delivery.receipt.phase != "completed"
                    || !delivery.receipt.slot_released
                    || delivery.receipt.worker_resources_released
                    || delivery.receipt.prompt_tokens != Some(output.prompt_tokens)
                    || delivery.receipt.output_tokens != Some(output.output_tokens)
                    || delivery.receipt.result_digest.as_ref()
                        != Some(&crate::resource_manager::requests::gateway::output_digest(
                            &output,
                        )?)
                    || delivery.receipt.product != Some(boundary.audit()?)
                {
                    return Err("granted completion receipt differs from the exact admitted subject/task/result".into());
                }
                return Ok(
                    serde_json::json!({"schema_version":1,"result":"ok","output":output,"receipt":delivery.receipt,"gate_closing":false}),
                );
            } else {
                let receipt = match crate::resource_manager::requests::gateway::validate_response(
                    &raw, &request,
                )? {
                    crate::resource_manager::requests::gateway::Status::Permit { receipt } => {
                        receipt
                    }
                    _ => {
                        return Err("granted inference initial acknowledgement shape differs".into())
                    }
                };
                if accepted
                    || receipt.nonce != job
                    || receipt.worker != worker
                    || receipt.profile != profile
                    || receipt.phase != "preparing"
                    || receipt.input_digest != digest
                    || receipt.product != Some(boundary.audit()?)
                {
                    return Err(
                        "granted inference initial acknowledgement denied or changed".into(),
                    );
                }
                accepted = true;
            }
        }
    })?;
    println!("{result}");
    Ok(())
}

pub(crate) fn infer_review(messages: Vec<ChatMessage>, max_tokens: u64) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let request = GatewayRequest {
        schema_version: 1,
        request_id: fresh_request_id()?,
        caller: 0,
        deadline: crate::resource_manager::now()? + 3000,
        action: "resource-granted-gateway".into(),
        payload: Message::Inspect {},
    };
    let (worker, profile) = match gateway_exchange(&request)? {
        crate::resource_manager::requests::gateway::Status::Worker {
            worker,
            profile,
            context_tokens,
            max_output_tokens,
            slots,
        } if context_tokens == 2048 && max_output_tokens == 128 && slots == 1 => (worker, profile),
        _ => return Err("granted inference review serving tuple differs".into()),
    };
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"usage":infer_usage(&worker,&profile,&messages,max_tokens)?,
        "worker":worker,"input_sha256":crate::resource_manager::requests::gateway::input_digest(&messages)?,
        "authority_returned":false,"gate_closing":false})
    );
    Ok(())
}

/// Product export bytes must not be rewritten by the child PTY. PAM still
/// controls input echo independently; no caller-selected terminal flags exist.
pub(crate) fn prepare_terminal() -> Result<()> {
    if unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1 {
        return Err("confined product output requires its actual launcher PTY".into());
    }
    let mut terminal: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDOUT_FILENO, &mut terminal) } != 0 {
        return Err("cannot observe confined product output terminal".into());
    }
    terminal.c_oflag &= !libc::ONLCR;
    if unsafe { libc::tcsetattr(libc::STDOUT_FILENO, libc::TCSANOW, &terminal) } != 0 {
        return Err("cannot preserve exact product export bytes".into());
    }
    Ok(())
}

struct InputStage {
    path: std::path::PathBuf,
    file: fs::File,
    directory: fs::File,
}
impl InputStage {
    fn capture(bytes: &[u8], leaf: &str) -> Result<Self> {
        if !matches!(leaf, "input.json" | "input.csv")
            || bytes.is_empty()
            || bytes.len() > 1_048_576
        {
            return Err("invalid bounded inert product input".into());
        }
        for ancestor in ["/", "/run"] {
            let metadata = fs::symlink_metadata(ancestor)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("product input staging requires trusted runtime parents".into());
            }
        }
        let runtime = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run")?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(runtime.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type != 0x01021994
        {
            return Err("inert product inputs require actual volatile /run tmpfs".into());
        }
        let root = Path::new("/run/luma-granted-client/requests");
        for parent in [Path::new("/run/luma-granted-client"), root] {
            match fs::DirBuilder::new().mode(0o700).create(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err("product input staging parent substituted or not private".into());
            }
        }
        let directory_path = root.join(crate::resources::random_id()?);
        fs::DirBuilder::new().mode(0o700).create(&directory_path)?;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&directory_path)?;
        let path = directory_path.join(leaf);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        directory.sync_all()?;
        let stage = Self {
            path,
            file,
            directory,
        };
        stage.check()?;
        Ok(stage)
    }
    fn check(&self) -> Result<()> {
        let file = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        let directory = self.directory.metadata()?;
        let parent =
            fs::symlink_metadata(self.path.parent().ok_or("invalid product input parent")?)?;
        let file_key = |m: &fs::Metadata| {
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
        if !file.is_file()
            || file.uid() != 0
            || file.gid() != 0
            || file.mode() & 0o7777 != 0o400
            || file.nlink() != 1
            || !named.is_file()
            || file_key(&file) != file_key(&named)
            || !parent.is_dir()
            || parent.uid() != 0
            || parent.gid() != 0
            || parent.mode() & 0o7777 != 0o700
            || (directory.dev(), directory.ino()) != (parent.dev(), parent.ino())
        {
            return Err("private inert product input was substituted".into());
        }
        Ok(())
    }
}

/// Closed launcher: no caller-selected systemd property, executable, shell,
/// environment, UID, confinement profile or resource ceiling is accepted.
pub(crate) fn launch(arguments: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if arguments.is_empty()
        || arguments.len() > 32
        || arguments
            .iter()
            .any(|v| v.len() > 16_384 || v.contains('\0'))
        || !matches!(
            arguments[0].as_str(),
            "granted-infer"
                | "granted-infer-review"
                | "workflow-governed-review"
                | "workflow-governed-prepare"
                | "workflow-governed-advance"
                | "workflow-governed-cancel"
                | "workflow-governed-reconcile"
                | "artifact-governed-export-review"
                | "artifact-governed-export"
                | "artifact-governed-retain"
        )
    {
        return Err("granted client launcher accepts only fixed protected product commands".into());
    }
    let mut owned = arguments.to_vec();
    let stage = match arguments[0].as_str() {
        "granted-infer" | "granted-infer-review" => {
            let (count, index) = if arguments[0] == "granted-infer" {
                (5, 3)
            } else {
                (3, 1)
            };
            if arguments.len() != count {
                return Err("granted inference argument shape differs".into());
            }
            let messages = crate::inference_input(&arguments[index])?;
            let bytes = serde_json::to_vec(&messages)?;
            if bytes.len() > 16_384 {
                return Err("canonical inference input exceeds bound".into());
            }
            let stage = InputStage::capture(&bytes, "input.json")?;
            owned[index] = stage
                .path
                .to_str()
                .ok_or("invalid private input path")?
                .into();
            Some(stage)
        }
        "workflow-governed-review" | "workflow-governed-prepare" => {
            let count = if arguments[0] == "workflow-governed-review" {
                4
            } else {
                7
            };
            if arguments.len() != count {
                return Err("governed workflow argument shape differs".into());
            }
            let mut bytes = Vec::new();
            std::io::stdin()
                .lock()
                .take(1_048_577)
                .read_to_end(&mut bytes)?;
            if bytes.is_empty()
                || bytes.len() > 1_048_576
                || bytes.contains(&0)
                || std::str::from_utf8(&bytes).is_err()
            {
                return Err("governed workflow requires bounded UTF-8 CSV input before PAM".into());
            }
            let stage = InputStage::capture(&bytes, "input.csv")?;
            owned.push(
                stage
                    .path
                    .to_str()
                    .ok_or("invalid private input path")?
                    .into(),
            );
            Some(stage)
        }
        _ => None,
    };
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    if unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        return Err("product authentication requires an actual controlling terminal".into());
    }
    let unit = format!("luma-granted-client-{}", crate::resources::random_id()?);
    let mut command = Command::new("/usr/bin/systemd-run");
    command.args(["--pty","--wait","--collect","--quiet","--service-type=exec","--unit",&unit,
        "--property=User=root","--property=Group=root","--property=AppArmorProfile=luma-granted-client",
        "--property=NoNewPrivileges=yes","--property=CapabilityBoundingSet=CAP_CHOWN",
        "--property=AmbientCapabilities=","--property=UMask=0077","--property=ProtectSystem=strict",
        "--property=ProtectHome=yes","--property=PrivateTmp=yes","--property=PrivateDevices=no",
        "--property=ProtectKernelTunables=yes","--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes","--property=RestrictAddressFamilies=AF_UNIX",
        "--property=RestrictNamespaces=yes","--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes","--property=SystemCallArchitectures=native",
        "--property=SystemCallFilter=@system-service @memlock","--property=SystemCallFilter=~@mount @raw-io @reboot @swap @obsolete @debug",
        "--property=LimitCORE=0","--property=LimitNOFILE=128","--property=LimitMEMLOCK=524288",
        "--property=MemoryMax=268435456","--property=MemorySwapMax=0","--property=TasksMax=16",
        "--property=CPUQuota=50%","--property=RuntimeMaxSec=60","--property=TimeoutStopSec=5",
        "--property=KillMode=control-group","--property=ReadWritePaths=/var/lib/luma-os/workflow-runs /var/lib/luma-os/artifacts /var/lib/luma-os/artifact-catalog /run/luma-admin",
        "--setenv=PATH=/usr/bin","--setenv=LANG=C","--setenv=LC_ALL=C","--setenv=TZ=UTC",IMAGE_EXE]);
    command
        .args(&owned)
        .stdin(std::process::Stdio::from(tty))
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    if let Some(stage) = &stage {
        stage.check()?;
    }
    if !command.status()?.success() {
        return Err("confined granted client refused; preserve any uncertain effect state".into());
    }
    if let Some(stage) = &stage {
        stage.check()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_client_requires_every_closed_privilege_and_capability_field() {
        let supported="NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000001\nCapPrm:\t0000000000000001\nCapBnd:\t0000000000000001\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        client_status(supported).unwrap();
        for field in [
            "NoNewPrivs",
            "Seccomp",
            "CapEff",
            "CapPrm",
            "CapBnd",
            "CapInh",
            "CapAmb",
        ] {
            let changed = supported
                .lines()
                .map(|line| {
                    if line.starts_with(&format!("{field}:")) {
                        format!("{field}: unavailable")
                    } else {
                        line.into()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(client_status(&changed).is_err());
            assert!(client_status(&format!("{supported}{field}: 1\n")).is_err());
        }
        assert!(client_status(&supported.replace("0000000000000001", "0000000000200001")).is_err());
        assert!(client_status(
            &supported.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001")
        )
        .is_err());
    }
    #[test]
    fn raw_challenge_and_proof_are_closed_data_not_a_grant_constructor() {
        let usage = Use {
            action: Action::Infer,
            selector: Selector {
                kind: Kind::Model,
                id: "Qwen3-4B".into(),
                generation: 1,
                digest: "12".repeat(32),
            },
            input_bytes: 5,
            output_bytes: 8192,
            units: 16,
        };
        let challenge = Challenge {
            schema_version: 1,
            kind: "grant-challenge".into(),
            nonce: format!("console-{}", "ab".repeat(16)),
            job: "cd".repeat(16),
            usage: usage.clone(),
            input_sha256: "ef".repeat(32),
        };
        let mut value = serde_json::to_value(&challenge).unwrap();
        value["authenticated"] = true.into();
        assert!(serde_json::from_value::<Challenge>(value).is_err());
        let audit = crate::finite_grants::Audit {
            subject: "12".repeat(32),
            subject_generation: 1,
            grant_id: "infer-one".into(),
            grant_version: 1,
            checkpoint_head: "34".repeat(32),
            usage,
        };
        audit.validate().unwrap();
        let proof = Proof {
            schema_version: 1,
            kind: "grant-proof".into(),
            nonce: challenge.nonce,
            job: challenge.job,
            audit,
        };
        let mut value = serde_json::to_value(&proof).unwrap();
        value["utc_override"] = 1000.into();
        assert!(serde_json::from_value::<Proof>(value).is_err());
    }
    #[test]
    fn plain_kernel_root_socket_never_substitutes_for_confined_source() {
        let (socket, _) = UnixStream::pair().unwrap();
        assert!(label(&socket).is_err());
        assert!(Admission::capture(
            &socket,
            &"12".repeat(16),
            Use {
                action: Action::Infer,
                selector: Selector {
                    kind: Kind::Model,
                    id: "Qwen3-4B".into(),
                    generation: 1,
                    digest: "34".repeat(32)
                },
                input_bytes: 5,
                output_bytes: 8192,
                units: 16
            },
            "56".repeat(32)
        )
        .is_err());
    }
}
