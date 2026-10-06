use crate::{broker_effects, resource_manager, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET: &str = "/run/luma-broker/control.sock";
const MAX_FRAME: usize = 16384;
const FRAME_TIMEOUT: Duration = Duration::from_secs(2);

mod ingress;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    pub deadline: u64,
    pub action: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    request_id: String,
    authenticated_uid: u32,
    result: String,
    implementation: String,
    generated_native_code: String,
    certification_closing: bool,
}

fn validate_response(bytes: &[u8], request: &Request) -> Result<Response> {
    // A refused/malformed reply is never a successful CLI operation. Do not
    // surface unvalidated peer text or accidentally echo extra payload fields.
    let response: Response =
        serde_json::from_slice(bytes).map_err(|_| "broker response is denied or malformed")?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.authenticated_uid != request.caller
        || response.result != "ok"
        || response.implementation != "rust-native-lab"
        || response.generated_native_code != "denied"
        || response.certification_closing
    {
        return Err("broker response does not match the request or supported contract".into());
    }
    Ok(response)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn fresh_request_id() -> Result<String> {
    // PIDs are recycled. An effect receipt must never silently correlate a
    // fresh CLI invocation with an older completed request from another PID
    // generation. Failure to obtain randomness is a refusal, not a fallback.
    let mut random = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(format!("console-{}", crate::bundle::hex(&random)))
}

fn validate(r: &Request, uid: u32, clock: u64) -> Result<()> {
    if r.schema_version != 1
        || r.caller != uid
        || r.request_id.is_empty()
        || r.request_id.len() > 64
        || !r
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || r.deadline < clock
        || r.deadline > clock.saturating_add(30)
        || !matches!(r.action.as_str(), "status" | "stop-worker" | "start-worker")
    {
        return Err("request identity, action, version, or deadline denied".into());
    }
    if uid != 0 && (uid != 990 || r.action != "status") {
        return Err("peer lacks authority for this activity".into());
    }
    Ok(())
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "IPC frame deadline exceeded"))
}

fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated IPC frame",
                ))
            }
            Ok(size) => bytes = &mut bytes[size..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    remaining(deadline)?;
    Ok(())
}

fn read_frame_until(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_until(stream, &mut header, deadline)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("IPC frame size denied".into());
    }
    let mut bytes = vec![0; size];
    read_until(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    // One monotonic budget covers header AND body. SO_RCVTIMEO alone is only
    // a per-read limit and permits an indefinitely slow fragmented sender.
    read_frame_until(stream, Instant::now() + FRAME_TIMEOUT)
}

fn write_frame_until(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("response exceeds limit".into());
    }
    let mut frame = Vec::with_capacity(bytes.len() + 4);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut pending = frame.as_slice();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(pending) {
            Ok(0) => return Err("IPC write made no progress".into()),
            Ok(size) => pending = &pending[size..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    remaining(deadline)?;
    Ok(())
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    write_frame_until(stream, bytes, Instant::now() + FRAME_TIMEOUT)
}

fn credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return Err("kernel peer authentication failed".into());
    }
    Ok(credentials)
}

fn peer(stream: &UnixStream) -> Result<u32> {
    Ok(credentials(stream)?.uid)
}

struct WorkerCommand(Child);
impl Drop for WorkerCommand {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_worker_command(child: Child, deadline: Instant) -> Result<()> {
    let mut child = WorkerCommand(child);
    loop {
        remaining(deadline)?;
        if let Some(status) = child.0.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err("worker operation failed; outcome requires reconciliation".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn worker_command(action: &broker_effects::Action, deadline: Instant) -> Result<()> {
    remaining(deadline)?;
    let verb = match action {
        broker_effects::Action::StartWorker => "start",
        broker_effects::Action::StopWorker => "stop",
    };
    let child = Command::new("/usr/bin/systemctl")
        .args([
            "--no-ask-password",
            "--no-pager",
            verb,
            "luma-reference.service",
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Killing a waiting systemctl does NOT cancel its systemd job. Timeout is
    // an uncertain external outcome; the durable Applying fence is retained.
    wait_worker_command(child, deadline)
}

fn handle_request(
    stream: &mut UnixStream,
    request: Request,
    uid: u32,
) -> Result<serde_json::Value> {
    validate(&request, uid, now()?)?;
    if request.action != "status" {
        crate::platform::require_installed()?;
        let action = broker_effects::Action::parse(&request.action)?;
        let budget = request.deadline.saturating_sub(now()?).min(10);
        let deadline = Instant::now() + Duration::from_secs(budget);
        let mut store = broker_effects::Store::open(Path::new(broker_effects::DIRECTORY))?;
        store.execute(
            &request.request_id,
            uid,
            action.clone(),
            || {
                remaining(deadline)?;
                if action == broker_effects::Action::StartWorker {
                    security_check()?;
                }
                // The existing kernel peer/root policy is checked AFTER slow
                // confinement/storage checks, including on historical replay.
                validate(&request, peer(stream)?, now()?)
            },
            || worker_command(&action, deadline),
        )?;
    }
    Ok(
        serde_json::json!({"schema_version": 1, "request_id": request.request_id,
        "authenticated_uid": uid, "result": "ok", "implementation": "rust-native-lab",
        "generated_native_code": "denied", "certification_closing": false}),
    )
}

pub fn security_check() -> Result<()> {
    if !fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?
        .split_whitespace()
        .any(|s| s == "memory")
    {
        return Err("cgroup v2 memory controller unavailable".into());
    }
    let profiles = fs::read_to_string("/sys/kernel/security/apparmor/profiles")?;
    if !profiles
        .lines()
        .any(|line| line == "luma-reference (enforce)")
    {
        return Err("mandatory AppArmor profile is not enforcing".into());
    }
    Ok(())
}

pub fn serve() -> Result<()> {
    crate::require_root()?;
    security_check()?;
    // RuntimeDirectory is created and owned by systemd. Never unlink an unknown socket.
    let mut manager = if crate::platform::require_installed().is_ok()
        || crate::platform::require_live().is_ok()
    {
        match resource_manager::Manager::open() {
            Ok(manager) => Some(manager),
            Err(_) => {
                let _ = resource_manager::fence_unavailable();
                eprintln!("resource manager fenced; inference unavailable; retained state requires review");
                None
            }
        }
    } else {
        None
    };
    let listener = UnixListener::bind(SOCKET)?;
    // Connection permission conveys no method authority. Every request retains
    // kernel peer authentication; UID 989 gets only its bounded resource methods.
    restrict_socket(Path::new(SOCKET))?;
    listener.set_nonblocking(true)?;
    let mut maintenance = Instant::now();
    let mut ingress = ingress::Ingress::new();
    // Only the independent legacy effect journal can run on this one helper.
    // The resource manager, its ledger and controller remain on this thread.
    let mut effect: Option<std::thread::JoinHandle<()>> = None;
    loop {
        if maintenance.elapsed() >= Duration::from_millis(100) {
            let failed = manager
                .as_mut()
                .map_or(false, |manager| manager.maintain().is_err());
            if failed {
                // Never recreate an empty ledger or re-enable inference in this
                // session. Manual/status paths remain available independently.
                if let Some(prior) = manager.as_ref() {
                    let _ = prior.fence_on_fault();
                }
                manager = None;
                eprintln!("resource manager fenced; inference unavailable; retained state requires review");
            }
            maintenance = Instant::now();
        }
        if effect.as_ref().map_or(false, |thread| thread.is_finished()) {
            if let Some(thread) = effect.take() {
                let _ = thread.join();
            }
        }
        // Ready frames cannot be held behind another client's partial frame,
        // response backpressure or a systemd job. The queue and reader count
        // are finite and partitioned by authenticated service UID.
        for _ in 0..16 {
            let Some(mut incoming) = ingress.receive() else {
                break;
            };
            let handled = (|| -> Result<Option<Request>> {
                let peer = credentials(&incoming.stream)?;
                let envelope: serde_json::Value = serde_json::from_slice(&incoming.bytes)?;
                if envelope
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map_or(false, |a| a.starts_with("resource-"))
                {
                    return Ok(None);
                }
                let request: Request = serde_json::from_slice(&incoming.bytes)?;
                validate(&request, peer.uid, now()?)?;
                Ok(Some(request))
            })();
            match handled {
                Ok(Some(request)) if request.action != "status" => {
                    if effect.is_some() {
                        incoming.respond(Err("legacy effect coordinator busy".into()));
                    } else {
                        let uid = request.caller;
                        effect = Some(
                            std::thread::Builder::new()
                                .name("broker-effect".into())
                                .stack_size(512 * 1024)
                                .spawn(move || {
                                    let result = handle_request(&mut incoming.stream, request, uid);
                                    incoming.respond(result);
                                })?,
                        );
                    }
                }
                Ok(Some(request)) => {
                    let uid = request.caller;
                    let result = handle_request(&mut incoming.stream, request, uid);
                    incoming.respond(result);
                }
                Ok(None) => {
                    let result = (|| -> Result<serde_json::Value> {
                        let peer = credentials(&incoming.stream)?;
                        let envelope: serde_json::Value = serde_json::from_slice(&incoming.bytes)?;
                        if envelope.get("action").and_then(|v| v.as_str())
                            == Some("resource-inference")
                        {
                            let request: resource_manager::requests::Request =
                                serde_json::from_slice(&incoming.bytes)?;
                            return manager
                                .as_mut()
                                .ok_or("resource manager unavailable in this session")?
                                .handle_inference(&request, peer, peer_pidfd(&incoming.stream)?);
                        }
                        let request: resource_manager::Request =
                            serde_json::from_slice(&incoming.bytes)?;
                        let pinned = if peer.uid == 989 || peer.uid == 0 {
                            Some(peer_pidfd(&incoming.stream)?)
                        } else {
                            None
                        };
                        Ok(serde_json::to_value(
                            manager
                                .as_mut()
                                .ok_or("resource manager unavailable in this session")?
                                .handle(&request, peer, pinned)?,
                        )?)
                    })();
                    incoming.respond(result);
                }
                Err(error) => incoming.respond(Err(error)),
            }
        }
        let (stream, _) = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let _ = ingress.accept(stream);
    }
}

fn restrict_socket(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = fs::symlink_metadata(path)?;
    let parent = fs::symlink_metadata(path.parent().ok_or("broker socket has no parent")?)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || !parent.is_dir()
        || parent.uid() != 0
        || parent.mode() & 0o022 != 0
    {
        return Err("unsafe broker socket or parent".into());
    }
    // Linux POSIX ACL v2. Named service-user entries grant only socket access,
    // never membership of the control group's database or source-folder ACLs.
    // The owning group has no grant; the mask is not an independent permission.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permission, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 6, 989),
        (2, 6, 990),
        (4, 0, u32::MAX),
        (16, 6, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permission.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let name = std::ffi::CString::new("system.posix_acl_access")?;
    if unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    } != 0
    {
        return Err("broker socket service ACL unavailable; no permissive fallback".into());
    }
    let mut observed = vec![0u8; acl.len() + 1];
    let count = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            observed.as_mut_ptr().cast(),
            observed.len(),
        )
    };
    if count < 0 || count as usize != acl.len() || observed[..acl.len()] != acl {
        return Err("broker socket ACL readback mismatch".into());
    }
    Ok(())
}

fn peer_pidfd(stream: &UnixStream) -> Result<fs::File> {
    // Linux 6.5+ SO_PEERPIDFD pins the actual connection creator, not a PID
    // potentially recycled after SO_PEERCRED. Unsupported kernels refuse.
    let mut fd: libc::c_int = -1;
    let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            77,
            &mut fd as *mut _ as *mut libc::c_void,
            &mut size,
        )
    } != 0
    {
        return Err("resource peer PID handle unavailable".into());
    }
    if fd < 0 {
        return Err("invalid resource peer PID handle".into());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if size as usize != std::mem::size_of::<libc::c_int>()
        || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        return Err("unsafe resource peer PID handle".into());
    }
    Ok(file)
}

pub(crate) fn resource_exchange(
    request: &resource_manager::Request,
) -> Result<resource_manager::Response> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut socket = connect_local(SOCKET, deadline)?;
    resource_exchange_on(&mut socket, request, deadline)
}

fn resource_exchange_on(
    socket: &mut UnixStream,
    request: &resource_manager::Request,
    deadline: Instant,
) -> Result<resource_manager::Response> {
    if peer(socket)? != 0 {
        return Err("resource broker is not root".into());
    }
    write_frame_until(socket, &serde_json::to_vec(request)?, deadline)?;
    let response: resource_manager::Response =
        serde_json::from_slice(&read_frame_until(socket, deadline)?)
            .map_err(|_| "resource response denied or malformed")?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.caller != request.caller
        || response.result != "ok"
    {
        return Err("resource response does not match authenticated request".into());
    }
    if resource_manager::now()? >= request.deadline {
        return Err("resource response arrived after its deadline".into());
    }
    let shape = match request.action.as_str() {
        "resource-acquire" => response.lease.is_some() && response.status.is_none(),
        "resource-renew" => {
            response.lease == request.lease && response.lease.is_some() && response.status.is_none()
        }
        "resource-reconcile" => response.lease.is_none() && response.status.is_none(),
        "resource-status" | "resource-revoke" | "resource-archive" => {
            response.lease.is_none()
                && response
                    .status
                    .as_ref()
                    .map_or(false, |value| value.is_object())
        }
        _ => false,
    };
    if !shape {
        return Err("resource acknowledgement has an unexpected method shape".into());
    }
    Ok(response)
}

fn exchange(socket: &mut UnixStream, request: &Request, deadline: Instant) -> Result<Response> {
    // One monotonic budget covers both request output and response input.
    // This private helper assumes the caller has authenticated the socket.
    write_frame_until(socket, &serde_json::to_vec(&request)?, deadline)?;
    validate_response(&read_frame_until(socket, deadline)?, request)
}

fn connect_local(path: &str, deadline: Instant) -> io::Result<UnixStream> {
    remaining(deadline)?;
    // Linux pathname sockets only; never accept an abstract/truncated name.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.starts_with('/') || path.len() >= address.sun_path.len() || path.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *target = byte as libc::c_char;
    }
    // SO_RCVTIMEO does not bound connect(). A full Unix listen queue must
    // refuse immediately, not block before the request deadline is installed.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Transfer ownership immediately, including all error paths below.
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        // EAGAIN (busy queue), EINTR and all other uncertain outcomes are
        // refusals. No automatic retry or reuse of a failed connection.
        return Err(io::Error::last_os_error());
    }
    remaining(deadline)?;
    socket.set_nonblocking(false)?;
    Ok(socket)
}

pub fn client(action: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut socket = connect_local(SOCKET, deadline)?;
    if peer(&socket)? != 0 {
        return Err("broker peer is not root".into());
    }
    let request = Request {
        schema_version: 1,
        request_id: fresh_request_id()?,
        caller: unsafe { libc::geteuid() },
        deadline: now()? + 5,
        action: action.into(),
    };
    let response = exchange(&mut socket, &request, deadline)?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_peer_handle_is_kernel_bound_and_closes_on_exec() {
        let (a, _b) = UnixStream::pair().unwrap();
        let pin = peer_pidfd(&a).unwrap();
        assert!(resource_manager::pidfd_alive(&pin).unwrap());
        assert_ne!(
            unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        // Heartbeats connect from a thread. The credential/PID handle must
        // identify the process generation, not a short-lived thread's TID.
        let (thread_socket, _other) = std::thread::spawn(|| UnixStream::pair().unwrap())
            .join()
            .unwrap();
        assert_eq!(
            credentials(&thread_socket).unwrap().pid,
            std::process::id() as libc::pid_t
        );
        assert!(resource_manager::pidfd_alive(&peer_pidfd(&thread_socket).unwrap()).unwrap());
    }

    #[test]
    fn broker_socket_acl_admits_only_root_and_exact_service_users_without_group_privilege() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        let directory = std::env::temp_dir().join(format!(
            "luma-broker-acl-{}",
            crate::resources::random_id().unwrap()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        restrict_socket(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
        for uid in [0u32, 989, 990, 988, 1000] {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-c", "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:s.connect(sys.argv[1])\nexcept PermissionError:sys.exit(13)", path.to_str().unwrap()]);
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(uid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(if [0, 989, 990].contains(&uid) { 0 } else { 13 }),
                "UID {uid}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn resource_socket_exchange_binds_root_peer_correlation_generation_and_method_shape() {
        for outcome in 0..7 {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let token = crate::resources::Token {
                lease_id: "a".repeat(32),
                generation: 1,
                manager_epoch: "b".repeat(32),
            };
            let request = resource_manager::Request {
                schema_version: 1,
                request_id: "renew-one".into(),
                caller: 0,
                deadline: resource_manager::now().unwrap() + 2000,
                action: "resource-renew".into(),
                idempotency_key: None,
                profile: None,
                lease: Some(token.clone()),
                review: None,
                storage_device: None,
            };
            let worker = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                let received: resource_manager::Request =
                    serde_json::from_slice(&read_frame_until(&mut server, deadline).unwrap())
                        .unwrap();
                let mut response = serde_json::json!({"schema_version":1,"request_id":received.request_id,
                    "caller":received.caller,"result":"ok","lease":token,"status":null});
                match outcome {
                    1 => response["request_id"] = serde_json::json!("other"),
                    2 => response["caller"] = serde_json::json!(989),
                    3 => response["lease"]["generation"] = serde_json::json!("2"),
                    4 => response["status"] = serde_json::json!({"unexpected":true}),
                    5 => response["unknown"] = serde_json::json!(true),
                    6 => response["lease"]["generation"] = serde_json::json!(1),
                    _ => (),
                }
                write_frame_until(
                    &mut server,
                    &serde_json::to_vec(&response).unwrap(),
                    deadline,
                )
                .unwrap();
            });
            let result = resource_exchange_on(
                &mut client,
                &request,
                Instant::now() + Duration::from_secs(2),
            );
            assert_eq!(result.is_ok(), outcome == 0, "outcome {outcome}");
            worker.join().unwrap();
        }
    }

    #[test]
    fn cli_request_ids_are_fresh_bounded_and_valid() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let id = fresh_request_id().unwrap();
            assert_eq!(id.len(), 40);
            assert!(id.starts_with("console-"));
            assert!(id[8..].bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(seen.insert(id.clone()));
            let request = Request {
                schema_version: 1,
                request_id: id,
                caller: 0,
                deadline: 110,
                action: "status".into(),
            };
            validate(&request, 0, 100).unwrap();
        }
    }

    #[test]
    fn worker_wait_is_bounded_reaps_children_and_preserves_failure() {
        let success = Command::new("/bin/true").spawn().unwrap();
        wait_worker_command(success, Instant::now() + Duration::from_secs(2)).unwrap();
        let failure = Command::new("/bin/false").spawn().unwrap();
        assert!(wait_worker_command(failure, Instant::now() + Duration::from_secs(2)).is_err());
        let child = Command::new("/bin/sleep").arg("3").spawn().unwrap();
        let pid = child.id();
        let started = Instant::now();
        assert!(wait_worker_command(child, started + Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn client_connection_refuses_invalid_missing_and_expired_endpoints() {
        for path in [
            "",
            "relative",
            "\0abstract",
            "/embedded\0suffix",
            &format!("/{}", "x".repeat(108)),
        ] {
            assert_eq!(
                connect_local(path, Instant::now() + Duration::from_secs(1))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            connect_local(SOCKET, Instant::now() - Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let missing = format!("/tmp/luma-absent-broker-{}/socket", std::process::id());
        assert_eq!(
            connect_local(&missing, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn client_connection_is_cloexec_and_refuses_full_queue_without_waiting() {
        let directory =
            std::env::temp_dir().join(format!("luma-broker-connect-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let endpoint = path.to_str().unwrap();
        let mut held = Vec::new();
        let mut busy = false;
        for _ in 0..8 {
            let started = Instant::now();
            match connect_local(endpoint, started + Duration::from_secs(3)) {
                Ok(socket) => {
                    assert_eq!(peer(&socket).unwrap(), unsafe { libc::geteuid() });
                    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
                    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
                    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
                    assert!(flags >= 0 && flags & libc::O_NONBLOCK == 0);
                    held.push(socket);
                }
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    assert!(started.elapsed() < Duration::from_secs(2));
                    busy = true;
                    break;
                }
            }
        }
        assert!(busy && !held.is_empty());
        for _ in &held {
            drop(listener.accept().unwrap());
        }
        drop(held);
        // Capacity recovery is explicit, not an internal retry of a failed call.
        let recovered = connect_local(endpoint, Instant::now() + Duration::from_secs(1)).unwrap();
        drop(listener.accept().unwrap());
        drop(recovered);
        drop(listener);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    fn client_request() -> Request {
        Request {
            schema_version: 1,
            request_id: "console-fixture".into(),
            caller: 990,
            deadline: 110,
            action: "status".into(),
        }
    }

    fn success_response() -> serde_json::Value {
        serde_json::json!({"schema_version":1, "request_id":"console-fixture",
            "authenticated_uid":990, "result":"ok", "implementation":"rust-native-lab",
            "generated_native_code":"denied", "certification_closing":false})
    }

    #[test]
    fn client_accepts_only_correlated_closed_success_response() {
        let request = client_request();
        let response = success_response();
        let checked = validate_response(&serde_json::to_vec(&response).unwrap(), &request).unwrap();
        assert_eq!(serde_json::to_value(checked).unwrap(), response);
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("request_id", serde_json::json!("different-request")),
            ("authenticated_uid", serde_json::json!(0)),
            ("result", serde_json::json!("denied")),
            ("implementation", serde_json::json!("other")),
            ("generated_native_code", serde_json::json!("allowed")),
            ("certification_closing", serde_json::json!(true)),
            ("unexpected", serde_json::json!("private-peer-payload")),
        ] {
            let mut changed = response.clone();
            changed[field] = value;
            let error = validate_response(&serde_json::to_vec(&changed).unwrap(), &request)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-peer-payload"));
        }
    }

    #[test]
    fn client_denied_malformed_duplicate_and_trailing_responses_are_errors() {
        let request = client_request();
        for bytes in [
            br#"{"schema_version":1,"result":"denied"}"#.as_slice(),
            b"private-peer-payload",
            b"[]",
            b"null",
            b"\xff",
            br#"{"result":"ok","result":"denied"}"#,
        ] {
            let error = validate_response(bytes, &request).unwrap_err().to_string();
            assert!(!error.contains("private-peer-payload"));
        }
        let mut trailing = serde_json::to_vec(&success_response()).unwrap();
        trailing.extend_from_slice(b"\n{}");
        assert!(validate_response(&trailing, &request).is_err());
        let duplicate = serde_json::to_string(&success_response())
            .unwrap()
            .replacen('{', "{\"result\":\"ok\",", 1);
        assert!(validate_response(duplicate.as_bytes(), &request).is_err());
    }

    #[test]
    fn client_exchange_checks_real_framed_socket_response_before_success() {
        for response in [
            success_response(),
            serde_json::json!({"schema_version":1,"result":"denied"}),
        ] {
            let expected_ok = response["result"] == "ok";
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let sender = std::thread::spawn(move || {
                let request: Request =
                    serde_json::from_slice(&read_frame(&mut server).unwrap()).unwrap();
                assert_eq!(request.request_id, "console-fixture");
                assert_eq!(request.caller, 990);
                write_frame(&mut server, &serde_json::to_vec(&response).unwrap()).unwrap();
            });
            assert_eq!(
                exchange(
                    &mut client,
                    &client_request(),
                    Instant::now() + Duration::from_secs(2)
                )
                .is_ok(),
                expected_ok
            );
            sender.join().unwrap();
        }
    }

    #[test]
    fn client_expired_exchange_cannot_send_a_request() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert!(exchange(
            &mut client,
            &client_request(),
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
        server.set_nonblocking(true).unwrap();
        let mut byte = [0];
        assert_eq!(
            server.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn peer_identity_action_and_time_are_bound() {
        let mut r = Request {
            schema_version: 1,
            request_id: "test".into(),
            caller: 990,
            deadline: 110,
            action: "status".into(),
        };
        validate(&r, 990, 100).unwrap();
        assert!(validate(&r, 1000, 100).is_err());
        assert!(validate(&r, 990, 111).is_err());
        r.action = "start-worker".into();
        assert!(validate(&r, 990, 100).is_err());
        r.caller = 0;
        validate(&r, 0, 100).unwrap();
        r.action = "shell".into();
        assert!(validate(&r, 0, 100).is_err());
    }
    #[test]
    fn oversized_frames_are_rejected_before_body_read() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(read_frame(&mut b).is_err());
    }
    #[test]
    fn actual_socket_peer_comes_from_kernel() {
        let (a, _) = UnixStream::pair().unwrap();
        assert_eq!(peer(&a).unwrap(), unsafe { libc::geteuid() });
    }

    #[test]
    fn fragmented_frame_completes_within_one_budget() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for byte in [0, 0, 0, 3, b'a', b'b', b'c'] {
                a.write_all(&[byte]).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        assert_eq!(read_frame(&mut b).unwrap(), b"abc");
        sender.join().unwrap();
    }

    #[test]
    fn slow_sender_cannot_reset_deadline_between_header_and_body() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(125));
            let _ = a.write_all(&3u32.to_be_bytes());
            std::thread::sleep(Duration::from_millis(125));
            let _ = a.write_all(b"abc");
        });
        let error =
            read_frame_until(&mut b, Instant::now() + Duration::from_millis(200)).unwrap_err();
        let kind = error.downcast_ref::<io::Error>().unwrap().kind();
        assert!(matches!(
            kind,
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        drop(b);
        sender.join().unwrap();
    }

    #[test]
    fn expired_budget_refuses_already_buffered_data_and_output() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[0, 0, 0, 1, b'x']).unwrap();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(read_frame_until(&mut b, past).is_err());
        assert!(write_frame_until(&mut b, b"response", past).is_err());
    }

    #[test]
    fn zero_length_truncated_header_and_truncated_body_are_refused() {
        for bytes in [&[0u8, 0, 0, 0][..], &[0, 0], &[0, 0, 0, 2, b'x']] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            a.write_all(bytes).unwrap();
            drop(a);
            assert!(read_frame(&mut b).is_err());
        }
    }

    #[test]
    fn stalled_response_receiver_is_bounded() {
        let (mut a, _b) = UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    a.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        assert!(write_frame_until(
            &mut a,
            &vec![b'x'; MAX_FRAME],
            Instant::now() + Duration::from_millis(100)
        )
        .is_err());
    }

    #[test]
    fn response_round_trip_and_size_boundaries() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        assert!(write_frame(&mut a, b"").is_err());
        assert!(write_frame(&mut a, &vec![0; MAX_FRAME + 1]).is_err());
        write_frame(&mut a, b"response").unwrap();
        assert_eq!(read_frame(&mut b).unwrap(), b"response");
    }
}
