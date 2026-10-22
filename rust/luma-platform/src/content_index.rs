//! Native corpus indexing. Requests and phase records are DATA; selection,
//! source reads, physical reservations and publication belong to the original
//! finite-grant client and the independently anchored C service.
use crate::Result;
use luma_content::OwnerBinding;
use luma_content_store::corpus_index::{BuilderIdentity, CorpusIndexLimits, CorpusQueryKind};
use serde::{Deserialize, Serialize};

pub(crate) mod builder;
pub(crate) mod client;
// Observed preparation, phase effects and the worker transport serve index-run,
// which stays unexposed until its genuine C publication is implemented.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod observed;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod phase;
pub(crate) mod policy;
pub(crate) mod request;
pub(crate) mod runtime;
pub(crate) mod scope;
pub(crate) mod state;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod transport;

pub(crate) const PREFIX: &str = "index-v2-";
pub(crate) const MAX_REQUEST: usize = 64 * 1024;
pub(crate) const MAX_JOB: usize = 1024 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const MAX_COMMITMENT: usize = 2 * 1024 * 1024 + 64 * 1024;
pub(crate) const MAX_OUTPUT: u64 = 64 * 1024;

fn hash(value: &str) -> Result<()> {
    if crate::artifacts::hash(value) {
        Ok(())
    } else {
        Err("index requires an exact lower-case SHA256".into())
    }
}
fn identifier(value: &str) -> Result<()> {
    if value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("index request/job identifier requires exactly16 random bytes".into())
    }
}
fn decode<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("native index record exceeds its closed finite bound".into());
    }
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err("native index record is not exact typed canonical JSON".into());
    }
    Ok(value)
}
