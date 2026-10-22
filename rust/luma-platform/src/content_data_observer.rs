//! CAP0 query-only content-byte observation. Kernel peer authentication admits
//! only the fixed C process, never a user/model-provided owner claim. Returned
//! bytes/metadata are DATA; current C/root/grant decisions remain in the caller.
use crate::Result;
use luma_content::OwnerBinding;
use luma_content_store::v2::{
    head::OwnerHeadV2, NamespaceObservationData, RawObjectObservationData,
};
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
mod client;
mod data;
mod endpoint;
#[path = "backup_confinement.rs"]
mod kernel_unix;
mod server;
mod wire;
pub(crate) use client::Client;
#[cfg(test)]
mod tests;
const DIRECTORY: &str = "/run/luma-content-data-observer";
const SOCKET: &str = "/run/luma-content-data-observer/read.sock";
const CONTENT_ROOT: &str = "/var/lib/luma-os/content-store";
const FRAME: usize = 65536;
const MAX_OBSERVATIONS: usize = 64;
// A maximum 64 MiB blob needs 4,096 chunks + 64 chunk groups + one
// index, in addition to Begin/End. This is resource capacity, not a lease.
const MAX_RPCS: u32 = 8192;
const RPC_MS: u64 = 3000;
const SESSION_MS: u64 = 1800 * 1000;
const OBSERVER: &str = "luma-content-data-observer (enforce)";
const C_PEER: &str = "luma-content-custody (enforce)";
const READ_BYTES: u64 = 128 * 1024;

fn now() -> Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
        || value.tv_nsec >= 1_000_000_000
    {
        return Err("content observer monotonic deadline unavailable".into());
    }
    (value.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| "content observer monotonic time overflow".into())
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > FRAME {
        return Err("observer frame outside fixed bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("observer requires closed canonical data".into());
    }
    Ok(value)
}
fn bytes_hex(bytes: &[u8]) -> String {
    crate::bundle::hex(bytes)
}
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() > 2 * luma_content_store::v2::MAX_PAGE_BYTES
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("observer raw bytes exceed canonical fixed16KiB response".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|b| Ok(u8::from_str_radix(std::str::from_utf8(b)?, 16)?))
        .collect()
}
/// Caller-supplied DATA bound to its genuine original C operation. The observer
/// does not authenticate the selected head, source, lease or their permissions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) schema_version: u32,
    pub(crate) binding: OwnerBinding,
    pub(crate) source_request_sha256: String,
    pub(crate) source_profile: String,
    pub(crate) selected_before: OwnerHeadV2,
    pub(crate) selected_before_sha256: String,
    pub(crate) lease: crate::resources::Token,
}
impl Context {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.selected_before.validate()?;
        if self.schema_version != 1
            || !hash(&self.source_request_sha256)
            || self.selected_before.binding != self.binding
            || self.selected_before.sha256()? != self.selected_before_sha256
            || !crate::workflow_resource::token_valid(&self.lease)
            || self.source_profile.is_empty()
            || self.source_profile.len() > 256
            || !self
                .source_profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(
                "observer context loses exact source/before-head/owner/lease binding".into(),
            );
        }
        Ok(())
    }
    fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(luma_content::sha256(&serde_json::to_vec(self)?))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Begin { context: Context },
    Observe { object_sha256: String },
    ReadPage { object_sha256: String },
    Recheck { slot: u8 },
    End,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    nonce: String,
    deadline_ms: u64,
    session_id: Option<String>,
    sequence: u32,
    context_sha256: String,
    operation: Operation,
}
impl Request {
    fn validate(&self) -> Result<()> {
        let current = now()?;
        if self.schema_version != 1
            || !nonce(&self.nonce)
            || !hash(&self.context_sha256)
            || self.sequence >= MAX_RPCS
            || self.deadline_ms <= current
            || self.deadline_ms
                > current
                    .checked_add(RPC_MS)
                    .ok_or("observer deadline overflow")?
            || self.session_id.as_ref().is_some_and(|s| !nonce(s))
        {
            return Err("invalid finite observer request identity/deadline".into());
        }
        match &self.operation {
            Operation::Begin { context } => {
                context.validate()?;
                if self.session_id.is_some()
                    || self.sequence != 0
                    || context.sha256()? != self.context_sha256
                {
                    return Err("observer Begin context differs".into());
                }
            }
            Operation::Observe { object_sha256 } | Operation::ReadPage { object_sha256 }
                if !hash(object_sha256) =>
            {
                return Err("observer raw selector must be exact nonzero lowercase SHA256".into())
            }
            Operation::Recheck { slot } if usize::from(*slot) >= MAX_OBSERVATIONS => {
                return Err("observer slot exceeds fixed bound".into())
            }
            _ => (),
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Data {
    Begun {
        namespace: NamespaceObservationData,
    },
    Observed {
        slot: u8,
        object: RawObjectObservationData,
        bytes_hex: String,
    },
    Rechecked {
        slot: u8,
        object: RawObjectObservationData,
        bytes_hex: String,
    },
    Page {
        object: RawObjectObservationData,
        bytes_hex: String,
    },
    Closed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u32,
    nonce: String,
    request_sha256: String,
    context_sha256: String,
    session_id: String,
    sequence: u32,
    data: Data,
}

pub(crate) fn command() -> Result<()> {
    server::command()
}
