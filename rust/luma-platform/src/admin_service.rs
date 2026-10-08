//! One-shot, kernel-peer-bound local Admin catalog service. No remote transport,
//! root caller role, serialized authority, assignments, shell or resource grants.
use crate::{
    admin_governance,
    admin_roles::{self, Command as CatalogCommand},
    authentication,
    sealed_credential::PrivateBuffer,
    tpm, Result,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DIRECTORY: &str = "/run/luma-governance";
const SOCKET: &str = "/run/luma-governance/control.sock";
const HUMAN: u32 = 1001;
const REQUEST_LIMIT: usize = 16384;
const RESPONSE_LIMIT: usize = 1024 * 1024;
const FRAME_BUDGET: Duration = Duration::from_secs(2);
const EXECUTION_BUDGET: Duration = Duration::from_secs(60);
mod peer;
pub(crate) use peer::Peer;

fn confined(
    profile: &str,
    status: &str,
    cgroup: &str,
    memory: &str,
    swap: &str,
    tasks: &str,
) -> Result<()> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let capabilities = u64::from_str_radix(field("CapEff:").ok_or("missing capabilities")?, 16)?;
    if profile.trim() != "luma-admin (enforce)"
        || field("NoNewPrivs:") != Some("1")
        || field("Seccomp:") != Some("2")
        || capabilities & !1 != 0
        || cgroup.trim() != "0::/system.slice/luma-admin.service"
        || memory.trim() != "268435456"
        || swap.trim() != "0"
        || tasks.trim() != "16"
    {
        return Err("Admin service confinement is not the installed supported profile".into());
    }
    Ok(())
}
fn require_confined() -> Result<()> {
    const CGROUP: &str = "/sys/fs/cgroup/system.slice/luma-admin.service";
    confined(
        &fs::read_to_string("/proc/self/attr/current")?,
        &fs::read_to_string("/proc/self/status")?,
        &fs::read_to_string("/proc/self/cgroup")?,
        &fs::read_to_string(format!("{CGROUP}/memory.max"))?,
        &fs::read_to_string(format!("{CGROUP}/memory.swap.max"))?,
        &fs::read_to_string(format!("{CGROUP}/pids.max"))?,
    )
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Status,
    AdoptPrincipals {
        review_sha256: Option<String>,
    },
    Catalog {
        command: CatalogCommand,
        review_sha256: Option<String>,
    },
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    request_id: String,
    login: String,
    operation: Operation,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    request_id: String,
    authenticated_uid: u32,
    status: String,
    result: Option<serde_json::Value>,
    gate_closing: bool,
}

fn credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err("kernel Admin peer authentication failed".into());
    }
    Ok(credentials)
}
fn peer(stream: &UnixStream) -> Result<u32> {
    Ok(credentials(stream)?.uid)
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Admin frame deadline exceeded"))
}
fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err("truncated Admin frame".into()),
            Ok(size) => bytes = &mut bytes[size..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_frame(stream: &mut UnixStream, limit: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    read_until(stream, &mut header, deadline)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > limit {
        return Err("Admin frame exceeds bound".into());
    }
    let mut bytes = vec![0; size];
    read_until(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn write_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err("short Admin frame write".into()),
            Ok(size) => bytes = &bytes[size..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    limit: usize,
    deadline: Instant,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("Admin response exceeds bound".into());
    }
    write_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_until(stream, bytes, deadline)
}
fn validate(request: &Request) -> Result<()> {
    if request.schema_version != 1
        || !admin_roles::identifier(&request.request_id)
        || request.request_id == "admin-bootstrap-v1"
        || request.login.is_empty()
        || request.login.len() > 32
        || !request.login.as_bytes()[0].is_ascii_lowercase()
        || !request
            .login
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    {
        return Err("invalid Admin request".into());
    }
    if let Operation::Catalog {
        command,
        review_sha256,
    } = &request.operation
    {
        if matches!(
            command,
            CatalogCommand::AdoptPrincipals { .. }
                | CatalogCommand::RecoverAdmin { .. }
                | CatalogCommand::CheckpointAccounts { .. }
        ) {
            return Err(
                "principal adoption or recovery cannot accept caller-supplied authority; account checkpoints require protected sources".into(),
            );
        }
        command.validate()?;
        if let Some(review) = review_sha256 {
            tpm::decode::<32>(review)?;
        }
    }
    if let Operation::AdoptPrincipals {
        review_sha256: Some(review),
    } = &request.operation
    {
        tpm::decode::<32>(review)?;
    }
    Ok(())
}

fn handle(
    stream: &mut UnixStream,
    execute: impl FnMut(&Request, &PrivateBuffer, &Peer) -> Result<serde_json::Value>,
) -> Result<()> {
    // Refuse workers, ordinary user and root before accepting any credential.
    let bound = Peer::capture(stream)?;
    handle_bound(stream, execute, bound)
}

fn handle_bound(
    stream: &mut UnixStream,
    mut execute: impl FnMut(&Request, &PrivateBuffer, &Peer) -> Result<serde_json::Value>,
    bound: Peer,
) -> Result<()> {
    let uid = bound.uid();
    let deadline = Instant::now() + FRAME_BUDGET;
    let request: Request = serde_json::from_slice(&read_frame(stream, REQUEST_LIMIT, deadline)?)?;
    validate(&request)?;
    let mut password = PrivateBuffer::new(authentication::PASSWORD_FRAME)?;
    read_until(stream, password.bytes_mut(), deadline)?;
    let end = password
        .bytes()
        .iter()
        .position(|v| *v == 0)
        .ok_or("unterminated password frame")?;
    if end == 0 || password.bytes()[end..].iter().any(|v| *v != 0) {
        return Err("invalid private password frame".into());
    }
    let result = bound.observe(|| execute(&request, &password, &bound));
    drop(password);
    // Never serialize authentication errors or peer-supplied exception text.
    let response = match result {
        Ok(result) => Response {
            schema_version: 1,
            request_id: request.request_id,
            authenticated_uid: uid,
            status: "ok".into(),
            result: Some(result),
            gate_closing: false,
        },
        Err(_) => Response {
            schema_version: 1,
            request_id: request.request_id,
            authenticated_uid: uid,
            status: "denied".into(),
            result: None,
            gate_closing: false,
        },
    };
    bound.check()?;
    write_frame(
        stream,
        &serde_json::to_vec(&response)?,
        RESPONSE_LIMIT,
        Instant::now() + FRAME_BUDGET,
    )
}

pub fn connection() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    require_confined()?;
    // Only the daemon's connected AF_UNIX stdin can pass SO_PEERCRED. Pipes,
    // terminals, ordinary root launchers and JSON caller fields cannot do so.
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    handle(&mut stream, |request, password, peer| {
        let candidate = if matches!(request.operation, Operation::Status) {
            None
        } else {
            Some(request.request_id.as_str())
        };
        let login = admin_governance::prepare_service(&request.login, candidate, peer)?;
        let account =
            peer.observe(|| authentication::peer_account(&request.login, password, peer.uid()))?;
        let result = match &request.operation {
            Operation::Status => admin_governance::service_request(
                account,
                login,
                peer,
                &request.request_id,
                None,
                None,
            ),
            Operation::Catalog {
                command,
                review_sha256,
            } => admin_governance::service_request(
                account,
                login,
                peer,
                &request.request_id,
                Some(command),
                review_sha256.as_deref(),
            ),
            Operation::AdoptPrincipals { review_sha256 } => {
                let command =
                    admin_governance::adoption_command(Path::new(crate::principal::REGISTRY))?;
                admin_governance::service_request(
                    account,
                    login,
                    peer,
                    &request.request_id,
                    Some(&command),
                    review_sha256.as_deref(),
                )
            }
        };
        result
    })
}

struct Session(Option<Child>);
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            // The unreaped leader still owns this PID; never signal a group
            // using the PID of an already reaped/reusable child.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
        }
    }
}
fn wait_session(child: Child, budget: Duration) -> Result<()> {
    let mut session = Session(Some(child));
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = session
            .0
            .as_mut()
            .ok_or("missing session child")?
            .try_wait()?
        {
            session.0.take();
            if status.success() {
                return Ok(());
            }
            return Err("Admin session refused".into());
        }
        if Instant::now() >= deadline {
            return Err("Admin session deadline exceeded; preserve uncertain state".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn serve_connection(stream: UnixStream) -> Result<()> {
    if peer(&stream)? != HUMAN {
        return Err("Admin service peer denied".into());
    }
    let input = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
    let mut command = Command::new("/usr/libexec/luma-os/luma-platform");
    command
        .arg("admin-service-request")
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C")
        .env("TSS2_LOG", "all+NONE")
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    wait_session(command.spawn()?, EXECUTION_BUDGET)
}
fn directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o711 {
        return Err("unsafe Admin runtime directory".into());
    }
    Ok(())
}
fn socket(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != HUMAN
        || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1
    {
        return Err("unsafe Admin socket".into());
    }
    Ok(())
}
pub fn serve() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    require_confined()?;
    let _singleton = tpm::exclusive_lock(Path::new("/run/luma-admin/service.lock"))?;
    directory(Path::new(DIRECTORY))?;
    let path = Path::new(SOCKET);
    match fs::symlink_metadata(path) {
        Ok(_) => {
            socket(path)?;
            match UnixStream::connect(path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?
                }
                _ => return Err("existing Admin socket is not proved stale".into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    let name = std::ffi::CString::new(SOCKET)?;
    if unsafe { libc::chown(name.as_ptr(), 0, HUMAN) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    socket(path)?;
    for incoming in listener.incoming() {
        let stream = incoming?;
        // Each connection owns a bounded child process and one PAM observation.
        // Failure never restarts/replays the request or logs its raw inputs.
        let _ = serve_connection(stream);
    }
    Ok(())
}

fn response(bytes: &[u8], request: &Request) -> Result<serde_json::Value> {
    let response: Response = serde_json::from_slice(bytes).map_err(|_| "invalid Admin response")?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.authenticated_uid != HUMAN
        || response.status != "ok"
        || response.gate_closing
    {
        return Err("Admin request denied or response substituted".into());
    }
    let result = response.result.ok_or("missing Admin response")?;
    let action = match &request.operation {
        Operation::Status => "admin-governance-status",
        _ => "admin-catalog-command",
    };
    if result["schema_version"] != 1
        || result["action"] != action
        || result["product_admin_active"] != true
        || result["delegation_available"] != false
        || result["effect_grant"] != false
        || result["gate_closing"] != false
    {
        return Err("Admin result exceeds the supported interface".into());
    }
    if let Operation::Catalog { command, .. } = &request.operation {
        if result["proposal"]["request_id"] != request.request_id
            || result["proposal"]["command"] != serde_json::to_value(command)?
        {
            return Err("Admin result does not bind the exact requested catalog command".into());
        }
    }
    if let Operation::AdoptPrincipals { .. } = &request.operation {
        if result["proposal"]["request_id"] != request.request_id {
            return Err("principal adoption response does not bind the request".into());
        }
        let command: CatalogCommand = serde_json::from_value(result["proposal"]["command"].clone())
            .map_err(|_| "invalid principal adoption response")?;
        command.validate()?;
        let CatalogCommand::AdoptPrincipals { registry } = &command else {
            return Err("principal adoption response substitutes another command".into());
        };
        let principal = &result["proposal"]["principal"];
        if !registry.binds(
            principal["installation"]
                .as_str()
                .ok_or("missing adoption installation")?,
            principal["principal"]
                .as_str()
                .ok_or("missing adoption principal")?,
            principal["generation"]
                .as_u64()
                .ok_or("missing adoption generation")?,
            &request.login,
            HUMAN,
        ) || principal["login"] != request.login
            || principal["uid"] != HUMAN
            || (result["committed"] == true
                && result["catalog"]["principal_registry"] != serde_json::to_value(registry)?)
        {
            return Err(
                "principal adoption response does not bind the authenticated registry".into(),
            );
        }
    }
    Ok(result)
}
fn client_request(args: &[String]) -> Result<Request> {
    if args.len() == 2 && args[1] == "status" {
        return Ok(Request {
            schema_version: 1,
            request_id: "status".into(),
            login: args[0].clone(),
            operation: Operation::Status,
        });
    }
    if (args.len() == 3 || (args.len() == 5 && args[3] == "--commit"))
        && args[1] == "adopt-principals"
    {
        let request = Request {
            schema_version: 1,
            request_id: args[2].clone(),
            login: args[0].clone(),
            operation: Operation::AdoptPrincipals {
                review_sha256: if args.len() == 5 {
                    Some(args[4].clone())
                } else {
                    None
                },
            },
        };
        validate(&request)?;
        return Ok(request);
    }
    if args.len() < 4 {
        return Err("admin-client LOGIN status | LOGIN adopt-principals REQUEST | LOGIN register REQUEST ACTIVITY | LOGIN define REQUEST ROLE VERSION ACTIVITY...; optional --commit REVIEW".into());
    }
    let committed = args.len() >= 2 && args[args.len() - 2] == "--commit";
    let end = args.len() - if committed { 2 } else { 0 };
    let review_sha256 = if committed {
        Some(args[args.len() - 1].clone())
    } else {
        None
    };
    let command = match args[1].as_str() {
        "rotate-admin" if end == 4 => CatalogCommand::RotateAdmin {
            expected_generation: args[3].parse()?,
        },
        "principal-advance" if end == 6 => CatalogCommand::AdvancePrincipal {
            principal: args[3].clone(),
            expected_generation: args[4].parse()?,
            enabled: admin_governance::principal_enabled(&args[5])?,
        },
        "register" if end == 4 => CatalogCommand::RegisterActivity {
            activity: args[3].clone(),
        },
        "define" if (6..=69).contains(&end) => {
            let mut activities = args[5..end].to_vec();
            activities.sort();
            CatalogCommand::DefineRole {
                name: args[3].clone(),
                expected_version: args[4].parse()?,
                activities,
            }
        }
        _ => return Err("unsupported Admin client operation".into()),
    };
    let request = Request {
        schema_version: 1,
        request_id: args[2].clone(),
        login: args[0].clone(),
        operation: Operation::Catalog {
            command,
            review_sha256,
        },
    };
    validate(&request)?;
    Ok(request)
}
pub fn client(args: &[String]) -> Result<()> {
    if unsafe { libc::geteuid() } != HUMAN {
        return Err("use the selected human account without sudo".into());
    }
    let request = client_request(args)?;
    validate(&request)?;
    directory(Path::new(DIRECTORY))?;
    socket(Path::new(SOCKET))?;
    let password = authentication::console_password(&request.login)?;
    let mut stream = UnixStream::connect(SOCKET)?;
    if peer(&stream)? != 0 {
        return Err("Admin server is not the protected root service".into());
    }
    let deadline = Instant::now() + FRAME_BUDGET;
    write_frame(
        &mut stream,
        &serde_json::to_vec(&request)?,
        REQUEST_LIMIT,
        deadline,
    )?;
    // Credential bytes are a separate fixed binary frame, never JSON/argv/env.
    write_until(&mut stream, password.bytes(), deadline)?;
    drop(password);
    let result = response(
        &read_frame(
            &mut stream,
            RESPONSE_LIMIT,
            Instant::now() + EXECUTION_BUDGET + FRAME_BUDGET,
        )?,
        &request,
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Explicitly uninstalled disposable-kernel composition. The shipped handle
    // always requires the confined observer; no environment/JSON fallback exists.
    fn handle(
        stream: &mut UnixStream,
        execute: impl FnMut(&Request, &PrivateBuffer, &Peer) -> Result<serde_json::Value>,
    ) -> Result<()> {
        let bound = Peer::capture_fixture(stream)?;
        super::handle_bound(stream, execute, bound)
    }
    fn request() -> Request {
        Request {
            schema_version: 1,
            request_id: "request".into(),
            login: "human".into(),
            operation: Operation::Status,
        }
    }
    fn public_result() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"action":"admin-governance-status",
            "product_admin_active":true,"delegation_available":false,"effect_grant":false,"gate_closing":false})
    }
    #[test]
    fn kernel_peer_root_or_worker_never_reaches_credential_or_executor() {
        let (_client, mut server) = UnixStream::pair().unwrap();
        assert_eq!(peer(&server).unwrap(), unsafe { libc::geteuid() });
        assert_ne!(peer(&server).unwrap(), HUMAN);
        assert!(handle(&mut server, |_, _, _| panic!(
            "unauthorized peer reached executor"
        ))
        .is_err());
    }
    #[test]
    fn admin_rotation_client_has_no_target_disable_force_or_implicit_review() {
        let args = ["human", "rotate-admin", "rotate", "1"].map(String::from);
        let request = client_request(&args).unwrap();
        assert!(matches!(
            request.operation,
            Operation::Catalog {
                command: CatalogCommand::RotateAdmin {
                    expected_generation: 1
                },
                review_sha256: None,
            }
        ));
        for generation in ["0", "-1", "18446744073709551616", "*"] {
            let mut changed = args.clone();
            changed[3] = generation.into();
            assert!(client_request(&changed).is_err());
        }
        let mut commit = args.to_vec();
        commit.extend(["--commit".into(), "ab".repeat(32)]);
        assert!(client_request(&commit).is_ok());
        for extra in ["disabled", "--force", "admin"] {
            let mut changed = args.to_vec();
            changed.push(extra.into());
            assert!(client_request(&changed).is_err());
        }
        commit[5] = "bad".into();
        assert!(client_request(&commit).is_err());
    }

    #[test]
    fn principal_advance_client_requires_exact_identity_generation_state_and_review() {
        let id = "ef".repeat(32);
        let args = [
            "human",
            "principal-advance",
            "disable",
            &id,
            "1",
            "disabled",
        ]
        .map(String::from);
        let request = client_request(&args).unwrap();
        validate(&request).unwrap();
        assert!(matches!(
            request.operation,
            Operation::Catalog {
                command: CatalogCommand::AdvancePrincipal {
                    expected_generation: 1,
                    enabled: false,
                    ..
                },
                review_sha256: None
            }
        ));
        for (index, value) in [(3, "bad"), (4, "0"), (5, "true"), (5, "*"), (5, "enable")] {
            let mut malformed = args.clone();
            malformed[index] = value.into();
            assert!(client_request(&malformed).is_err());
        }
        let mut committed = args.to_vec();
        committed.extend(["--commit".into(), "ab".repeat(32)]);
        assert!(client_request(&committed).is_ok());
        committed[7] = "bad".into();
        assert!(client_request(&committed).is_err());
    }

    #[test]
    fn principal_adoption_request_carries_no_caller_registry_or_path() {
        let args = ["human", "adopt-principals", "adopt"].map(String::from);
        let request = client_request(&args).unwrap();
        validate(&request).unwrap();
        assert!(matches!(
            request.operation,
            Operation::AdoptPrincipals {
                review_sha256: None
            }
        ));
        let value = serde_json::to_value(&request).unwrap();
        for key in ["registry", "registry_path", "principal", "generation"] {
            let mut changed = value.clone();
            changed["operation"][key] = serde_json::json!("caller-value");
            assert!(serde_json::from_value::<Request>(changed).is_err());
        }
        let mut supplied = client_request(&args).unwrap();
        supplied.operation = Operation::Catalog {
            command: CatalogCommand::AdoptPrincipals {
                registry: serde_json::from_value(serde_json::json!({"schema_version":1,
                "installation":"ab".repeat(32),"principals":[{"id":"cd".repeat(32),
                "generation":1,"login":"human","uid":1001,"enabled":true}]}))
                .unwrap(),
            },
            review_sha256: None,
        };
        assert!(validate(&supplied).is_err());
        supplied.operation = Operation::Catalog {
            command: CatalogCommand::RecoverAdmin {
                expected_generation: 1,
                expected_recovery_generation: 1,
                replacement: crate::admin_recovery::Verifier::create(
                    &crate::admin_recovery::Credential::fixture(0x42),
                    &"ab".repeat(32),
                    &"cd".repeat(32),
                    2,
                )
                .unwrap(),
            },
            review_sha256: None,
        };
        assert!(validate(&supplied).is_err());
        supplied.operation = Operation::Catalog {
            command: CatalogCommand::CheckpointAccounts {
                commitments: std::collections::BTreeMap::from([("cd".repeat(32), "12".repeat(32))]),
            },
            review_sha256: None,
        };
        assert!(validate(&supplied).is_err());
        assert!(client_request(
            &["human", "adopt-principals", "adopt", "--commit", "bad"].map(String::from)
        )
        .is_err());
        assert!(client_request(
            &["human", "adopt-principals", "adopt", "/caller/path"].map(String::from)
        )
        .is_err());
    }

    #[test]
    fn principal_adoption_reply_binds_request_admin_and_committed_snapshot() {
        let request =
            client_request(&["human", "adopt-principals", "adopt"].map(String::from)).unwrap();
        let registry = serde_json::json!({"schema_version":1,"installation":"ab".repeat(32),
            "principals":[{"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true}]});
        let mut result = public_result();
        result["action"] = serde_json::json!("admin-catalog-command");
        result["committed"] = serde_json::json!(true);
        result["catalog"] = serde_json::json!({"principal_registry":registry});
        result["proposal"] = serde_json::json!({"request_id":"adopt",
            "principal":{"installation":"ab".repeat(32),"principal":"cd".repeat(32),
                "generation":1,"login":"human","uid":1001},
            "command":{"action":"adopt_principals","registry":registry}});
        let value = serde_json::to_value(Response {
            schema_version: 1,
            request_id: "adopt".into(),
            authenticated_uid: HUMAN,
            status: "ok".into(),
            result: Some(result),
            gate_closing: false,
        })
        .unwrap();
        response(&serde_json::to_vec(&value).unwrap(), &request).unwrap();
        for choice in 0..4 {
            let mut changed = value.clone();
            match choice {
                0 => changed["result"]["proposal"]["request_id"] = serde_json::json!("other"),
                1 => {
                    changed["result"]["proposal"]["principal"]["generation"] = serde_json::json!(2)
                }
                2 => changed["result"]["catalog"]["principal_registry"] = serde_json::Value::Null,
                _ => {
                    changed["result"]["proposal"]["command"] =
                        serde_json::json!({"action":"register_activity","activity":"model.select"})
                }
            }
            assert!(response(&serde_json::to_vec(&changed).unwrap(), &request).is_err());
        }
    }

    #[test]
    fn metadata_has_no_caller_role_password_or_assignment_field() {
        let mut value = serde_json::to_value(request()).unwrap();
        for key in ["caller", "role", "password", "token"] {
            value[key] = serde_json::json!("unsupported");
            assert!(serde_json::from_value::<Request>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(key);
        }
        value["operation"] = serde_json::json!({"action":"assign_role","role":"Admin"});
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
    #[test]
    fn service_refuses_unconfined_unsandboxed_or_unbounded_launches() {
        let status = "NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000001\n";
        let group = "0::/system.slice/luma-admin.service";
        confined(
            "luma-admin (enforce)\n",
            status,
            group,
            "268435456",
            "0",
            "16",
        )
        .unwrap();
        for (profile, status, group, memory, swap, tasks) in [
            ("unconfined", status, group, "268435456", "0", "16"),
            (
                "luma-admin (complain)",
                status,
                group,
                "268435456",
                "0",
                "16",
            ),
            (
                "luma-admin (enforce)",
                "NoNewPrivs: 0\nSeccomp: 2\nCapEff: 1",
                group,
                "268435456",
                "0",
                "16",
            ),
            (
                "luma-admin (enforce)",
                "NoNewPrivs: 1\nSeccomp: 0\nCapEff: 1",
                group,
                "268435456",
                "0",
                "16",
            ),
            (
                "luma-admin (enforce)",
                "NoNewPrivs: 1\nSeccomp: 2\nCapEff: 3",
                group,
                "268435456",
                "0",
                "16",
            ),
            (
                "luma-admin (enforce)",
                status,
                "0::/other",
                "268435456",
                "0",
                "16",
            ),
            ("luma-admin (enforce)", status, group, "max", "0", "16"),
            (
                "luma-admin (enforce)",
                status,
                group,
                "268435456",
                "max",
                "16",
            ),
            (
                "luma-admin (enforce)",
                status,
                group,
                "268435456",
                "0",
                "max",
            ),
        ] {
            assert!(confined(profile, status, group, memory, swap, tasks).is_err());
        }
    }
    #[test]
    fn frames_are_bounded_and_have_one_monotonic_header_body_budget() {
        for size in [0, REQUEST_LIMIT + 1] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(&(size as u32).to_be_bytes()).unwrap();
            assert!(read_frame(&mut server, REQUEST_LIMIT, Instant::now() + FRAME_BUDGET).is_err());
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            let _ = client.write_all(&1u32.to_be_bytes());
            std::thread::sleep(Duration::from_millis(70));
            let _ = client.write_all(b"x");
        });
        assert!(read_frame(
            &mut server,
            REQUEST_LIMIT,
            Instant::now() + Duration::from_millis(65)
        )
        .is_err());
        writer.join().unwrap();
        assert!(write_frame(
            &mut server,
            b"x",
            RESPONSE_LIMIT,
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
    }
    #[test]
    fn substituted_denied_or_granting_responses_are_not_success() {
        let r = request();
        let initial = serde_json::to_value(Response {
            schema_version: 1,
            request_id: r.request_id.clone(),
            authenticated_uid: HUMAN,
            status: "ok".into(),
            result: Some(public_result()),
            gate_closing: false,
        })
        .unwrap();
        response(&serde_json::to_vec(&initial).unwrap(), &r).unwrap();
        for key in ["request_id", "authenticated_uid", "status", "gate_closing"] {
            let mut changed = initial.clone();
            changed[key] = match key {
                "authenticated_uid" => serde_json::json!(0),
                "gate_closing" => serde_json::json!(true),
                _ => serde_json::json!("private-unvalidated-text"),
            };
            let error = response(&serde_json::to_vec(&changed).unwrap(), &r)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-unvalidated-text"));
        }
        for key in ["effect_grant", "delegation_available", "gate_closing"] {
            let mut changed = initial.clone();
            changed["result"][key] = serde_json::json!(true);
            assert!(response(&serde_json::to_vec(&changed).unwrap(), &r).is_err());
        }
    }
    #[test]
    fn client_syntax_has_no_shell_paths_or_implicit_approval() {
        for args in [
            vec![],
            vec!["human"],
            vec!["human", "shell", "request", "id"],
            vec!["human", "register", "../path", "model.select"],
            vec!["human", "define", "request", "Admin", "0", "model.select"],
        ] {
            assert!(client_request(&args.iter().map(|v| (*v).into()).collect::<Vec<_>>()).is_err());
        }
        let r = client_request(
            &["human", "register", "request", "model.select"]
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            r.operation,
            Operation::Catalog {
                review_sha256: None,
                ..
            }
        ));
    }
    #[test]
    fn session_deadline_kills_and_reaps_only_its_unreaped_process_group() {
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pid = child.id();
        assert!(wait_session(child, Duration::from_millis(50)).is_err());
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        let mut command = Command::new("/bin/true");
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        wait_session(command.spawn().unwrap(), Duration::from_secs(1)).unwrap();
    }

    #[test]
    #[ignore = "requires disposable root container and unprivileged kernel-peer child"]
    fn kernel_human_connection() {
        assert!(Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = std::env::temp_dir().join(format!("luma-admin-ipc-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o711)).unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        for mode in ["allow", "deny", "truncated"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "admin_service::tests::kernel_human_child",
                    "--nocapture",
                ])
                .env("LUMA_ADMIN_IPC_TEST_SOCKET", &path)
                .env("LUMA_ADMIN_IPC_TEST_MODE", mode)
                .uid(HUMAN)
                .gid(HUMAN)
                .spawn()
                .unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(peer(&stream).unwrap(), HUMAN);
            let result = handle(&mut stream, |r, password, peer| {
                assert_eq!(peer.uid(), HUMAN);
                assert_eq!(r.login, "human");
                assert_eq!(&password.bytes()[..8], b"fixture\0");
                if mode == "deny" {
                    return Err("private-credential-detail-must-not-leak".into());
                }
                Ok(public_result())
            });
            assert_eq!(result.is_ok(), mode != "truncated");
            drop(stream);
            assert!(child.wait().unwrap().success());
        }
        drop(listener);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
    #[test]
    #[ignore = "child of kernel_human_connection only"]
    fn kernel_human_child() {
        assert_eq!(unsafe { libc::geteuid() }, HUMAN);
        let path = std::env::var("LUMA_ADMIN_IPC_TEST_SOCKET").unwrap();
        assert!(path.starts_with("/tmp/luma-admin-ipc-"));
        let mode = std::env::var("LUMA_ADMIN_IPC_TEST_MODE").unwrap();
        let mut stream = UnixStream::connect(path).unwrap();
        let r = request();
        write_frame(
            &mut stream,
            &serde_json::to_vec(&r).unwrap(),
            REQUEST_LIMIT,
            Instant::now() + FRAME_BUDGET,
        )
        .unwrap();
        let mut password = PrivateBuffer::new(authentication::PASSWORD_FRAME).unwrap();
        password.bytes_mut()[..7].copy_from_slice(b"fixture");
        if mode == "truncated" {
            write_until(
                &mut stream,
                &password.bytes()[..8],
                Instant::now() + FRAME_BUDGET,
            )
            .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => (),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => (),
                _ => panic!("truncated request received data or was not closed"),
            }
        } else {
            write_until(&mut stream, password.bytes(), Instant::now() + FRAME_BUDGET).unwrap();
            let bytes =
                read_frame(&mut stream, RESPONSE_LIMIT, Instant::now() + FRAME_BUDGET).unwrap();
            if mode == "allow" {
                response(&bytes, &r).unwrap();
            } else {
                assert!(response(&bytes, &r).is_err());
                assert!(!String::from_utf8(bytes)
                    .unwrap()
                    .contains("private-credential"));
            }
        }
    }

    fn pam_request(mode: &str, review: Option<String>) -> Request {
        let operation = if mode.starts_with("admin-rotate")
            || mode == "admin-stale"
            || mode == "admin-bad-review"
        {
            Operation::Catalog {
                command: CatalogCommand::RotateAdmin {
                    expected_generation: if mode == "admin-bad-review" {
                        3
                    } else if mode.starts_with("admin-rotate-new") {
                        2
                    } else {
                        1
                    },
                },
                review_sha256: review,
            }
        } else if mode.starts_with("admin-next") {
            Operation::Catalog {
                command: CatalogCommand::RegisterActivity {
                    activity: "model.after-rotation".into(),
                },
                review_sha256: review,
            }
        } else if mode.starts_with("life-") {
            let (generation, enabled) = if mode.starts_with("life-enable") || mode == "life-stale" {
                (2, true)
            } else if mode.starts_with("life-rotate") {
                (3, true)
            } else {
                (1, false)
            };
            Operation::Catalog {
                command: CatalogCommand::AdvancePrincipal {
                    principal: if mode == "life-admin" {
                        std::env::var("LUMA_ADMIN_PAM_TEST_ADMIN_ID").unwrap()
                    } else {
                        "cc".repeat(32)
                    },
                    expected_generation: if mode == "life-stale" { 1 } else { generation },
                    enabled,
                },
                review_sha256: review,
            }
        } else if mode.starts_with("adopt-") {
            Operation::AdoptPrincipals {
                review_sha256: review,
            }
        } else if mode.starts_with("peer-exit") {
            Operation::Catalog {
                command: CatalogCommand::RegisterActivity {
                    activity: "model.dead-peer".into(),
                },
                review_sha256: review,
            }
        } else if mode.starts_with("register") || mode == "invalid-review" {
            Operation::Catalog {
                command: CatalogCommand::RegisterActivity {
                    activity: "model.reconfigure".into(),
                },
                review_sha256: review,
            }
        } else if mode.starts_with("define") {
            Operation::Catalog {
                command: CatalogCommand::DefineRole {
                    name: "Operator".into(),
                    expected_version: 1,
                    activities: vec!["model.reconfigure".into(), "model.select".into()],
                },
                review_sha256: review,
            }
        } else {
            Operation::Status
        };
        Request {
            schema_version: 1,
            request_id: if mode.starts_with("admin-rotate-new") {
                "service-admin-rotate-new"
            } else if mode.starts_with("admin-rotate") {
                "service-admin-rotate"
            } else if mode.starts_with("admin-next") {
                "service-admin-next"
            } else if mode.starts_with("life-disable") || mode.starts_with("life-old-disable") {
                "service-life-disable"
            } else if mode.starts_with("life-enable") {
                "service-life-enable"
            } else if mode.starts_with("life-rotate") {
                "service-life-rotate"
            } else if mode.starts_with("adopt-") {
                "service-principal-adoption"
            } else if mode.starts_with("register") {
                "service-register"
            } else if mode.starts_with("define") {
                "service-define"
            } else if mode.starts_with("peer-exit") {
                "service-peer-exit"
            } else {
                mode
            }
            .into(),
            login: if mode == "wrong-login" {
                "otherhuman"
            } else {
                "human"
            }
            .into(),
            operation,
        }
    }

    #[test]
    #[ignore = "requires real PAM accounts and enrolled disposable existing-owner TPM"]
    fn pam_catalog_connection() {
        crate::require_root().unwrap();
        assert!(Path::new("/.dockerenv").is_file());
        assert!(!Path::new("/dev/tpmrm0").exists() && !Path::new("/dev/tpm0").exists());
        let root = std::path::PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        assert!(root.starts_with("/tmp"));
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("luma-tpm-delivery-"));
        let registry = root.join("registry.json");
        let original = fs::read(&registry).unwrap();
        let directory =
            std::env::temp_dir().join(format!("luma-admin-pam-ipc-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o711)).unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, HUMAN) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        socket(&path).unwrap();
        let mut password = PrivateBuffer::new(authentication::PASSWORD_FRAME).unwrap();
        let mut secret = File::open(root.join("account-password")).unwrap();
        secret.read_exact(&mut password.bytes_mut()[..64]).unwrap();
        let mut excess = [0];
        assert_eq!(secret.read(&mut excess).unwrap(), 0);
        let mut review: Option<String> = None;
        let governed = std::cell::OnceCell::new();
        let original_admin = std::cell::OnceCell::new();
        let rotated_admin = std::cell::OnceCell::new();
        let admin_id: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for mode in [
            "status",
            "register-review",
            "register-commit",
            "register-replay-review",
            "register-replay-commit",
            "define-review",
            "define-commit",
            "define-replay-review",
            "define-replay-commit",
            "wrong-password",
            "wrong-login",
            "invalid-review",
            "disabled",
            "changed-generation",
            "disable-after-pam",
            "peer-exit-review",
            "peer-exit-commit",
            "peer-exit-restored-commit",
            "locked",
            "restored",
            "adopt-review",
            "adopt-commit",
            "adopt-replay-review",
            "adopt-replay-commit",
            "registry-other-generation",
            "registry-restored",
            "life-disable-review",
            "life-disable-commit",
            "life-disable-replay-review",
            "life-disable-replay-commit",
            "life-stale",
            "life-admin",
            "life-enable-review",
            "life-enable-commit",
            "life-rotate-review",
            "life-rotate-commit",
            "life-old-disable-review",
            "life-old-disable-commit",
            "admin-rotate-review",
            "admin-rotate-commit",
            "admin-status",
            "admin-stale",
            "admin-next-review",
            "admin-next-commit",
            "admin-rotate-replay-review",
            "admin-rotate-replay-commit",
            "admin-rotate-new-review",
            "admin-rotate-new-commit",
            "admin-bad-review",
        ] {
            if mode == "admin-rotate-review" {
                let session =
                    admin_governance::fixture_governed_session(&root, "human", &password).unwrap();
                assert_eq!(
                    admin_governance::fixture_governed_identity(&root, &session).unwrap()
                        ["generation"],
                    1
                );
                original_admin
                    .set(session)
                    .ok()
                    .expect("one original Admin session");
            }
            if mode == "admin-rotate-new-review" {
                let session =
                    admin_governance::fixture_governed_session(&root, "human", &password).unwrap();
                assert_eq!(
                    admin_governance::fixture_governed_identity(&root, &session).unwrap()
                        ["generation"],
                    2
                );
                rotated_admin
                    .set(session)
                    .ok()
                    .expect("one second-generation Admin session");
            }
            if mode == "life-disable-review" {
                let session =
                    admin_governance::fixture_governed_session(&root, "otherhuman", &password)
                        .unwrap();
                assert_eq!(
                    admin_governance::fixture_governed_identity(&root, &session).unwrap()
                        ["generation"],
                    1
                );
                governed
                    .set(session)
                    .ok()
                    .expect("one original governed session");
            }
            let denied = matches!(
                mode,
                "wrong-password"
                    | "wrong-login"
                    | "invalid-review"
                    | "disabled"
                    | "changed-generation"
                    | "disable-after-pam"
                    | "peer-exit-commit"
                    | "locked"
                    | "registry-other-generation"
                    | "life-stale"
                    | "life-admin"
                    | "admin-stale"
                    | "admin-bad-review"
            );
            if mode == "registry-other-generation" {
                let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
                changed["principals"][1]["generation"] = serde_json::json!(2);
                crate::platform::write_atomic(
                    &registry,
                    &serde_json::to_vec(&changed).unwrap(),
                    0o600,
                )
                .unwrap();
            }
            if mode == "disabled" || mode == "changed-generation" {
                let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
                changed["principals"][0][if mode == "disabled" {
                    "enabled"
                } else {
                    "generation"
                }] = if mode == "disabled" {
                    serde_json::json!(false)
                } else {
                    serde_json::json!(2)
                };
                crate::platform::write_atomic(
                    &registry,
                    &serde_json::to_vec(&changed).unwrap(),
                    0o600,
                )
                .unwrap();
            }
            if mode == "locked" {
                assert!(Command::new("/usr/sbin/usermod")
                    .args(["--lock", "human"])
                    .status()
                    .unwrap()
                    .success());
            }
            let before = fs::read(root.join("admin/journal.json")).unwrap();
            let approval = if mode == "invalid-review" || mode == "admin-bad-review" {
                Some("00".repeat(32))
            } else if mode.ends_with("commit") {
                Some(review.clone().expect("separately inspected review"))
            } else {
                None
            };
            let mut child_command = Command::new(std::env::current_exe().unwrap());
            child_command
                .args([
                    "--ignored",
                    "--exact",
                    "admin_service::tests::pam_catalog_child",
                ])
                .env("LUMA_ADMIN_PAM_TEST_SOCKET", &path)
                .env("LUMA_ADMIN_PAM_TEST_MODE", mode)
                .env(
                    "LUMA_ADMIN_PAM_TEST_ADMIN_ID",
                    admin_id["principals"][0]["id"].as_str().unwrap(),
                )
                .env(
                    "LUMA_ADMIN_PAM_TEST_REVIEW",
                    approval.as_deref().unwrap_or(""),
                )
                .stdin(Stdio::from(password.descriptor().unwrap()))
                .uid(HUMAN)
                .gid(HUMAN);
            let mut child = child_command.spawn().unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut observed = None;
            let outcome = handle(&mut stream, |request, credential, peer| {
                let candidate = if matches!(request.operation, Operation::Status) {
                    None
                } else {
                    Some(request.request_id.as_str())
                };
                let login = admin_governance::fixture_prepare_service(
                    &root,
                    &request.login,
                    candidate,
                    peer,
                )?;
                let account = authentication::fixture_peer_account(
                    &root,
                    &request.login,
                    credential,
                    peer.uid(),
                )?;
                if mode == "peer-exit-commit" {
                    child.kill()?;
                    child.wait()?;
                }
                if mode == "disable-after-pam" {
                    let mut changed: serde_json::Value = serde_json::from_slice(&original)?;
                    changed["principals"][0]["enabled"] = serde_json::json!(false);
                    crate::platform::write_atomic(
                        &registry,
                        &serde_json::to_vec(&changed)?,
                        0o600,
                    )?;
                }
                let result = match &request.operation {
                    Operation::AdoptPrincipals { review_sha256 } => {
                        let command = admin_governance::adoption_command(&registry)?;
                        admin_governance::fixture_service_request(
                            &root,
                            account,
                            login,
                            peer,
                            &request.request_id,
                            Some(&command),
                            review_sha256.as_deref(),
                        )
                    }
                    Operation::Status => admin_governance::fixture_service_request(
                        &root,
                        account,
                        login,
                        peer,
                        &request.request_id,
                        None,
                        None,
                    ),
                    Operation::Catalog {
                        command,
                        review_sha256,
                    } => admin_governance::fixture_service_request(
                        &root,
                        account,
                        login,
                        peer,
                        &request.request_id,
                        Some(command),
                        review_sha256.as_deref(),
                    ),
                };
                let result = result?;
                observed = Some(result.clone());
                Ok(result)
            });
            drop(stream);
            if mode == "peer-exit-commit" {
                assert!(outcome.is_err());
                assert!(!child.wait().unwrap().success());
            } else {
                outcome.unwrap();
                assert!(child.wait().unwrap().success(), "client case {mode}");
            }
            let after = fs::read(root.join("admin/journal.json")).unwrap();
            if denied {
                assert!(observed.is_none(), "denied case {mode}");
                assert_eq!(after, before, "denied case changed journal: {mode}");
            } else {
                let report = observed.unwrap();
                if mode.ends_with("review") {
                    review = Some(report["review_sha256"].as_str().unwrap().into());
                }
                if mode == "register-commit"
                    || mode == "define-commit"
                    || mode == "peer-exit-restored-commit"
                    || mode == "adopt-commit"
                    || mode == "life-disable-commit"
                    || mode == "life-enable-commit"
                    || mode == "life-rotate-commit"
                    || mode == "admin-rotate-commit"
                    || mode == "admin-rotate-new-commit"
                    || mode == "admin-next-commit"
                {
                    assert_eq!(report["tpm_write_performed"], true);
                    assert_ne!(after, before);
                } else {
                    assert_eq!(after, before, "inspection/replay changed journal: {mode}");
                }
                if mode.contains("replay") || mode.starts_with("life-old-disable") {
                    assert_eq!(report["replayed"], true);
                }
                if mode == "restored" {
                    assert_eq!(report["catalog"]["roles"]["Operator"]["version"], 2);
                    assert_eq!(
                        report["catalog"]["roles"]["Operator"]["activities"],
                        serde_json::json!(["model.reconfigure", "model.select"])
                    );
                }
                if mode == "adopt-commit" || mode == "registry-restored" {
                    assert_eq!(
                        report["catalog"]["principal_registry"],
                        serde_json::from_slice::<serde_json::Value>(&original).unwrap()
                    );
                    assert_eq!(report["catalog"]["roles"]["Operator"]["version"], 2);
                }
                if mode == "life-disable-commit" {
                    assert_eq!(
                        report["catalog"]["principal_states"][&"cc".repeat(32)]["generation"],
                        2
                    );
                    assert!(admin_governance::fixture_governed_identity(
                        &root,
                        governed.get().unwrap()
                    )
                    .is_err());
                    let disabled =
                        authentication::fixture_local_account(&root, "otherhuman", &password)
                            .unwrap();
                    assert!(disabled.identity().is_ok());
                    disabled.logout();
                    assert!(admin_governance::fixture_governed_session(
                        &root,
                        "otherhuman",
                        &password
                    )
                    .is_err());
                }
                if mode == "life-enable-commit" || mode == "life-rotate-commit" {
                    assert!(admin_governance::fixture_governed_identity(
                        &root,
                        governed.get().unwrap()
                    )
                    .is_err());
                    let session =
                        admin_governance::fixture_governed_session(&root, "otherhuman", &password)
                            .unwrap();
                    assert_eq!(
                        admin_governance::fixture_governed_identity(&root, &session).unwrap()
                            ["generation"],
                        if mode == "life-enable-commit" { 3 } else { 4 }
                    );
                    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        admin_governance::fixture_governed_projection_interruption(&root, &session)
                    }));
                    assert!(panic.is_err());
                    assert!(admin_governance::fixture_governed_identity(&root, &session).is_err());
                }
                if mode.starts_with("life-old-disable") {
                    assert_eq!(
                        report["catalog"]["principal_states"][&"cc".repeat(32)]["generation"],
                        4
                    );
                    assert_eq!(
                        report["catalog"]["principal_states"][&"cc".repeat(32)]["enabled"],
                        true
                    );
                }
                if mode.starts_with("admin-") {
                    let id = admin_id["principals"][0]["id"].as_str().unwrap();
                    let expected = if mode == "admin-rotate-review" {
                        1
                    } else if mode == "admin-rotate-new-commit" {
                        3
                    } else {
                        2
                    };
                    if expected > 1 {
                        assert_eq!(
                            report["catalog"]["principal_states"][id]["generation"],
                            expected
                        );
                        assert_eq!(report["catalog"]["principal_states"][id]["enabled"], true);
                        assert!(admin_governance::fixture_governed_identity(
                            &root,
                            original_admin.get().unwrap()
                        )
                        .is_err());
                    }
                    if mode == "admin-status" {
                        assert_eq!(report["principal"]["generation"], 2);
                    }
                    if mode.starts_with("admin-next") || mode.starts_with("admin-rotate-new") {
                        assert_eq!(report["proposal"]["principal"]["generation"], 2);
                    } else if mode.starts_with("admin-rotate") {
                        assert_eq!(report["proposal"]["principal"]["generation"], 1);
                    }
                    if mode == "admin-rotate-commit" || mode == "admin-rotate-new-commit" {
                        let session =
                            admin_governance::fixture_governed_session(&root, "human", &password)
                                .unwrap();
                        assert_eq!(
                            admin_governance::fixture_governed_identity(&root, &session).unwrap()
                                ["generation"],
                            expected
                        );
                    }
                    if mode == "admin-rotate-new-commit" {
                        assert!(admin_governance::fixture_governed_identity(
                            &root,
                            rotated_admin.get().unwrap()
                        )
                        .is_err());
                        let account =
                            authentication::fixture_local_account(&root, "human", &password)
                                .unwrap();
                        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            admin_governance::fixture_rotation_interruption(&account)
                        }));
                        assert!(panic.is_err());
                        assert!(account.identity().is_err());
                    }
                }
            }
            // Older fixture cases reset installation metadata; governed changes
            // must leave that baseline untouched and advance only TPM history.
            if mode.starts_with("life-") || mode.starts_with("admin-") {
                assert_eq!(fs::read(&registry).unwrap(), original);
            } else {
                crate::platform::write_atomic(&registry, &original, 0o600).unwrap();
            }
            if mode == "locked" {
                assert!(Command::new("/usr/sbin/usermod")
                    .args(["--unlock", "human"])
                    .status()
                    .unwrap()
                    .success());
            }
        }
        admin_governance::fixture_session_issuance(&root, &password);
        admin_governance::fixture_session_projections(&root, &password);
        admin_governance::fixture_custody_recovery(&root, &password);
        admin_governance::fixture_owned_catalog(&root, &password);
        admin_governance::fixture_account_checkpoint(&root, &password);
        drop(listener);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    #[ignore = "unprivileged child of disposable PAM/catalog fixture only"]
    fn pam_catalog_child() {
        crate::protect_memory().unwrap();
        assert_eq!(unsafe { libc::geteuid() }, HUMAN);
        let path = std::env::var("LUMA_ADMIN_PAM_TEST_SOCKET").unwrap();
        assert!(path.starts_with("/tmp/luma-admin-pam-ipc-"));
        let mode = std::env::var("LUMA_ADMIN_PAM_TEST_MODE").unwrap();
        let review = std::env::var("LUMA_ADMIN_PAM_TEST_REVIEW").unwrap();
        let request = pam_request(
            &mode,
            if review.is_empty() {
                None
            } else {
                Some(review)
            },
        );
        validate(&request).unwrap();
        let mut credential = PrivateBuffer::new(authentication::PASSWORD_FRAME).unwrap();
        std::io::stdin().read_exact(credential.bytes_mut()).unwrap();
        if mode == "wrong-password" {
            credential.bytes_mut()[0] ^= 1;
        }
        let mut stream = UnixStream::connect(path).unwrap();
        assert_eq!(peer(&stream).unwrap(), 0);
        let deadline = Instant::now() + FRAME_BUDGET;
        write_frame(
            &mut stream,
            &serde_json::to_vec(&request).unwrap(),
            REQUEST_LIMIT,
            deadline,
        )
        .unwrap();
        write_until(&mut stream, credential.bytes(), deadline).unwrap();
        let bytes = read_frame(
            &mut stream,
            RESPONSE_LIMIT,
            Instant::now() + EXECUTION_BUDGET,
        )
        .unwrap();
        assert!(!bytes
            .windows(64)
            .any(|window| window == &credential.bytes()[..64]));
        drop(credential);
        let denied = matches!(
            mode.as_str(),
            "wrong-password"
                | "wrong-login"
                | "invalid-review"
                | "disabled"
                | "changed-generation"
                | "disable-after-pam"
                | "locked"
                | "registry-other-generation"
                | "life-stale"
                | "life-admin"
                | "admin-stale"
                | "admin-bad-review"
        );
        if denied {
            assert!(response(&bytes, &request).is_err());
            let envelope: Response = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(envelope.status, "denied");
            assert!(envelope.result.is_none());
        } else {
            response(&bytes, &request).unwrap();
        }
    }
}
