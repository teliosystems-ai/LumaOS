use crate::{disk::command, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET: &str = "/run/luma-broker/control.sock";
const MAX_FRAME: usize = 16384;
const FRAME_TIMEOUT: Duration = Duration::from_secs(2);

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

fn peer(stream: &UnixStream) -> Result<u32> {
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
    Ok(credentials.uid)
}

fn handle(stream: &mut UnixStream) -> Result<serde_json::Value> {
    let uid = peer(stream)?;
    let request: Request = serde_json::from_slice(&read_frame(stream)?)?;
    validate(&request, uid, now()?)?;
    // Recheck the same kernel peer and deadline immediately before a finite effect.
    validate(&request, peer(stream)?, now()?)?;
    match request.action.as_str() {
        "start-worker" => {
            security_check()?;
            command("/usr/bin/systemctl", &["start", "luma-reference.service"])?;
        }
        "stop-worker" => {
            command("/usr/bin/systemctl", &["stop", "luma-reference.service"])?;
        }
        _ => {}
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
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let response = match handle(&mut stream) {
            Ok(value) => value,
            Err(_) => serde_json::json!({"schema_version":1,"result":"denied"}),
        };
        let _ = write_frame(&mut stream, &serde_json::to_vec(&response)?);
    }
    Ok(())
}

fn exchange(socket: &mut UnixStream, request: &Request, deadline: Instant) -> Result<Response> {
    // One monotonic budget covers both request output and response input.
    // This private helper assumes the caller has authenticated the socket.
    write_frame_until(socket, &serde_json::to_vec(&request)?, deadline)?;
    validate_response(&read_frame_until(socket, deadline)?, request)
}

pub fn client(action: &str) -> Result<()> {
    let mut socket = UnixStream::connect(SOCKET)?;
    if peer(&socket)? != 0 {
        return Err("broker peer is not root".into());
    }
    let request = Request {
        schema_version: 1,
        request_id: format!("console-{}", std::process::id()),
        caller: unsafe { libc::geteuid() },
        deadline: now()? + 5,
        action: action.into(),
    };
    let response = exchange(
        &mut socket,
        &request,
        Instant::now() + Duration::from_secs(3),
    )?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
