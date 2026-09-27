use crate::{disk::command, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOCKET: &str = "/run/luma-broker/control.sock";
const MAX_FRAME: usize = 16384;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    pub deadline: u64,
    pub action: String,
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

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("IPC frame size denied".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err("response exceeds limit".into());
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
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
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let response = match handle(&mut stream) {
            Ok(value) => value,
            Err(_) => serde_json::json!({"schema_version":1,"result":"denied"}),
        };
        let _ = write_frame(&mut stream, &serde_json::to_vec(&response)?);
    }
    Ok(())
}

pub fn client(action: &str) -> Result<()> {
    let mut socket = UnixStream::connect(SOCKET)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
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
    write_frame(&mut socket, &serde_json::to_vec(&request)?)?;
    println!("{}", String::from_utf8(read_frame(&mut socket)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
