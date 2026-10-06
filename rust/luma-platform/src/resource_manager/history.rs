//! Root-only immutable receipt export over the existing bounded broker socket.
use super::*;

pub(super) const CHUNK_BYTES: u64 = 2048;
pub(super) const EXPORT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub caller: u32,
    #[serde(with = "resources::decimal")]
    pub deadline: u64,
    pub action: String,
    #[serde(with = "resources::decimal")]
    pub batch: u64,
    pub sha256: String,
    #[serde(with = "resources::decimal")]
    pub offset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Chunk {
    #[serde(with = "resources::decimal")]
    pub batch: u64,
    pub sha256: String,
    #[serde(with = "resources::decimal")]
    pub offset: u64,
    #[serde(with = "resources::decimal")]
    pub next_offset: u64,
    #[serde(with = "resources::decimal")]
    pub total_bytes: u64,
    pub data: String,
    pub worker_resources_released: bool,
}

fn validate(r: &Request, uid: u32, time: u64) -> Result<()> {
    if r.schema_version != 1
        || r.caller != 0
        || uid != 0
        || r.action != "resource-request-export"
        || r.request_id.is_empty()
        || r.request_id.len() > 64
        || !r
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || r.deadline <= time
        || r.deadline - time > 5000
        || r.batch == 0
        || r.batch > 64
        || !requests::digest_valid(&r.sha256)
        || r.offset >= EXPORT_BYTES
        || r.offset % CHUNK_BYTES != 0
    {
        return Err("request archive export envelope denied".into());
    }
    Ok(())
}

pub(crate) fn validate_chunk(r: &Request, c: &Chunk) -> Result<()> {
    if c.batch != r.batch
        || c.sha256 != r.sha256
        || c.offset != r.offset
        || c.total_bytes == 0
        || c.total_bytes > EXPORT_BYTES
        || c.offset >= c.total_bytes
        || c.next_offset
            != c.offset
                .checked_add(CHUNK_BYTES)
                .ok_or("export offset overflow")?
                .min(c.total_bytes)
        || c.data.len() as u64 != c.next_offset - c.offset
        || !c.data.is_ascii()
        || c.worker_resources_released
    {
        return Err("request archive export chunk mismatch".into());
    }
    Ok(())
}

impl Manager {
    pub(crate) fn handle_export(
        &mut self,
        r: &Request,
        peer: libc::ucred,
        pin: File,
    ) -> Result<Response> {
        validate(r, peer.uid, now()?)?;
        crate::platform::require_installed()?;
        if peer.pid <= 0 || !pidfd_alive(&pin)? {
            return Err("request export requires live installed root".into());
        }
        self.maintain()?;
        self.requests.persist(&self.store, true)?;
        let chunk = self.requests.export_chunk(&self.store, r)?;
        if !pidfd_alive(&pin)? || now()? >= r.deadline {
            return Err("request export peer or deadline expired".into());
        }
        Ok(Response {
            schema_version: 1,
            request_id: r.request_id.clone(),
            caller: peer.uid,
            result: "ok".into(),
            lease: None,
            status: Some(serde_json::to_value(chunk)?),
        })
    }
}

pub(crate) fn export(batch: &str, sha256: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let number = batch.parse::<u64>()?;
    if number.to_string() != batch {
        return Err("noncanonical archive batch".into());
    }
    let bytes = collect(number, sha256, crate::service::resource_export_exchange)?;
    // Do not emit any archive bytes before complete length and digest validation.
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn collect(
    batch: u64,
    sha256: &str,
    mut exchange: impl FnMut(&Request) -> Result<Chunk>,
) -> Result<Vec<u8>> {
    let until = now()?
        .checked_add(30_000)
        .ok_or("export deadline overflow")?;
    let mut bytes = Vec::new();
    let mut total = None;
    for _ in 0..EXPORT_BYTES / CHUNK_BYTES {
        let time = now()?;
        if time >= until {
            return Err("request export whole-operation deadline expired".into());
        }
        let r = Request {
            schema_version: 1,
            request_id: resources::random_id()?,
            caller: 0,
            deadline: time
                .checked_add(4000)
                .ok_or("export envelope overflow")?
                .min(until),
            action: "resource-request-export".into(),
            batch,
            sha256: sha256.into(),
            offset: bytes.len() as u64,
        };
        validate(&r, 0, time)?;
        let c = exchange(&r)?;
        validate_chunk(&r, &c)?;
        if now()? >= r.deadline || total.map_or(false, |n| n != c.total_bytes) {
            return Err("request export changed length or exceeded deadline".into());
        }
        total = Some(c.total_bytes);
        bytes.extend_from_slice(c.data.as_bytes());
        if c.next_offset == c.total_bytes {
            if crate::bundle::hex(&Sha256::digest(&bytes)) != sha256 {
                return Err("request export final digest mismatch".into());
            }
            return Ok(bytes);
        }
    }
    Err("request export page budget exhausted".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            request_id: "export-test".into(),
            caller: 0,
            deadline: 4000,
            action: "resource-request-export".into(),
            batch: 1,
            sha256: "a".repeat(64),
            offset: 0,
        }
    }
    #[test]
    fn export_envelopes_are_root_only_canonical_and_bounded() {
        let mut r = request();
        assert!(validate(&r, 0, 1).is_ok());
        for uid in [989, 990, 1000] {
            assert!(validate(&r, uid, 1).is_err());
        }
        for offset in [1, EXPORT_BYTES, u64::MAX] {
            r.offset = offset;
            assert!(validate(&r, 0, 1).is_err());
        }
        r.offset = 0;
        r.batch = 65;
        assert!(validate(&r, 0, 1).is_err());
        r.batch = 1;
        r.deadline = 5002;
        assert!(validate(&r, 0, 1).is_err());
        let mut value = serde_json::to_value(request()).unwrap();
        value["offset"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Request>(value).is_err());
        let mut value = serde_json::to_value(request()).unwrap();
        value["path"] = serde_json::json!("/etc/passwd");
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
    #[test]
    fn assembled_export_checks_every_chunk_and_full_digest_before_returning_bytes() {
        let data = "x".repeat(5000);
        let hash = crate::bundle::hex(&Sha256::digest(data.as_bytes()));
        for fault in 0..8 {
            let result = collect(1, &hash, |r| {
                let end = (r.offset + CHUNK_BYTES).min(data.len() as u64);
                let mut c = Chunk {
                    batch: 1,
                    sha256: hash.clone(),
                    offset: r.offset,
                    next_offset: end,
                    total_bytes: data.len() as u64,
                    data: data[r.offset as usize..end as usize].into(),
                    worker_resources_released: false,
                };
                match fault {
                    1 => c.batch = 2,
                    2 => c.offset += 1,
                    3 => c.data.push('y'),
                    4 => c.worker_resources_released = true,
                    5 => c.data = c.data.replace('x', "y"),
                    6 if r.offset > 0 => c.total_bytes += 1,
                    7 => return Err("lost export page acknowledgement".into()),
                    _ => (),
                }
                Ok(c)
            });
            assert_eq!(result.is_ok(), fault == 0, "fault {fault}");
            if let Ok(bytes) = result {
                assert_eq!(bytes, data.as_bytes());
            }
        }
    }
}
