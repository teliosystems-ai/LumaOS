//! Exact existing Page source/profile DATA; no alternate Input decoder, grant,
//! timer, current owner selector or general-purpose private query is introduced.
use super::*;

pub(crate) struct PageSource {
    binding: OwnerBinding,
    expected: VersionReference,
    offset: u64,
    bytes: u32,
    profile: String,
    device: String,
    source_sha256: String,
    usage: grants::Use,
}
#[cfg(test)]
#[path = "observed_read/tests.rs"]
mod tests;
impl PageSource {
    pub(crate) fn parse(
        bytes: &[u8],
        profile_id: &str,
        device: &str,
        owner: &OwnerBinding,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("observed Page source exceeds its exact bounded shape".into());
        }
        let input = super::parse(bytes)?;
        let selected = profile(profile_id)?;
        let source_sha256 = io::digest(bytes);
        if !matches!(input.operation, Operation::Page { .. })
            || selected.mode != Mode::Query
            || selected.source != source_sha256
            || selected.review != source_sha256
            || input.binding != *owner
            || selected.generation != owner.owner_generation
            || !input.matches_mode(selected.mode)
        {
            return Err("observed Page input differs from original exact query profile".into());
        }
        let usage = custody_usage(profile_id, device, owner, &source_sha256)?;
        if usage.action != grants::Action::Read
            || usage.selector.kind != grants::Kind::File
            || usage.selector.id != "native-content-query-v1"
        {
            return Err("observed Page cannot borrow effect/inspection/export permission".into());
        }
        let (expected, offset, bytes) = match input.operation {
            Operation::Page {
                expected,
                offset,
                bytes,
            } => (expected, offset, bytes),
            _ => return Err("observed Page parser refuses other operations".into()),
        };
        Ok(Self {
            binding: input.binding,
            expected,
            offset,
            bytes,
            profile: profile_id.into(),
            device: device.into(),
            source_sha256,
            usage,
        })
    }
    pub(crate) fn binding(&self) -> &OwnerBinding {
        &self.binding
    }
    pub(crate) fn expected(&self) -> &VersionReference {
        &self.expected
    }
    pub(crate) fn profile(&self) -> &str {
        &self.profile
    }
    pub(crate) fn device(&self) -> &str {
        &self.device
    }
    pub(crate) fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub(crate) fn read_ceiling(&self) -> u64 {
        self.usage.input_bytes
    }
    pub(crate) fn check_original(&self, audit: &grants::Audit) -> Result<()> {
        audit.validate()?;
        if audit.subject != self.binding.owner
            || audit.subject_generation != self.binding.owner_generation
            || audit.usage != self.usage
            || audit.operation_id.is_none()
        {
            return Err("observed Page differs from original finite subject/query audit".into());
        }
        Ok(())
    }
    pub(crate) fn result(&self, version: &ArtifactVersion) -> Result<serde_json::Value> {
        if version.reference()? != *self.expected() || version.receipt().binding != self.binding {
            return Err("observed Page output changed exact owner/reference".into());
        }
        version_result(version, Some((self.offset, self.bytes)))
    }
    pub(crate) fn validate_result(&self, value: &serde_json::Value) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Page {
            schema_version: u32,
            reference: VersionReference,
            format: Format,
            envelope_bytes: u64,
            envelope_sha256: String,
            content_delivered: bool,
            committed: bool,
            authority_returned: bool,
            provenance_authority: bool,
            workflow_executed: bool,
            production_qualified: bool,
            encoding: String,
            offset: u64,
            next_offset: u64,
            eof: bool,
            slice_hex: String,
        }
        if serde_json::to_vec(value)?.len() as u64 >= MAX_OUTPUT {
            return Err("observed Page result exceeds existing output profile".into());
        }
        let page: Page = serde_json::from_value(value.clone())?;
        let end = self
            .offset
            .checked_add(u64::from(self.bytes))
            .ok_or("observed Page offset overflow")?
            .min(page.envelope_bytes);
        if page.schema_version != 1
            || page.reference != self.expected
            || page.envelope_bytes > luma_content::MAX_ENVELOPE_BYTES as u64
            || page.envelope_bytes == 0
            || self.offset > page.envelope_bytes
            || !io::hash(&page.envelope_sha256)
            || page.envelope_sha256.bytes().all(|b| b == b'0')
            || page.encoding != "hex"
            || page.offset != self.offset
            || page.next_offset != end
            || page.eof != (end == page.envelope_bytes)
            || page.slice_hex.len() as u64 != 2 * (end - self.offset)
            || !page
                .slice_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || page.content_delivered != (end > self.offset)
            || page.committed
            || page.authority_returned
            || page.provenance_authority
            || page.workflow_executed
            || page.production_qualified
        {
            return Err("observed Page result differs from exact inert native slice shape".into());
        }
        let _ = page.format;
        Ok(())
    }
}
