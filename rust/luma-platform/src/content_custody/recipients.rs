//! Explicit Admin-governed encryption recipients. Certificate bytes and pins
//! are approved together; neither a DN nor an archive can enroll custody.
use super::*;
use crate::{
    backup_crypto::{RecipientPins, Recipients},
    finite_grants::{Action, Kind, Selector, Use},
};
use std::path::Path;
pub(crate) const MAX_REQUEST: usize = 49152;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub purpose: String,
    pub binding: OwnerBinding,
    pub expected_generation: u64,
    pub active: bool,
    pub recipients: RecipientPins,
    pub owner_certificate_der_hex: String,
    pub offline_admin_certificate_der_hex: String,
}
fn decode(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 16384
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("recipient certificate is not bounded canonical DER hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect()
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.purpose != "luma-content-encryption-recipients-v1"
            || self.expected_generation >= MAX_EVENTS as u64
        {
            return Err("invalid closed encryption recipient commissioning request".into());
        }
        Recipients::new(
            &decode(&self.owner_certificate_der_hex)?,
            &decode(&self.offline_admin_certificate_der_hex)?,
            self.recipients.clone(),
        )?;
        if serde_json::to_vec(self)?.len() > MAX_REQUEST {
            return Err("recipient request exceeds finite transport bound".into());
        }
        Ok(())
    }
    fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub(super) fn cryptographic_check(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.validate()?;
        crate::receipt_signer::validate_recipients(
            &decode(&self.owner_certificate_der_hex)?,
            &decode(&self.offline_admin_certificate_der_hex)?,
            &self.recipients,
            &mut *check,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    schema_version: u32,
    purpose: String,
    pub(super) generation: u64,
    pub(super) request: Request,
    original_authority: Audit,
}
impl Enrollment {
    pub(super) fn audit(&self) -> &Audit {
        &self.original_authority
    }
    pub(super) fn validate(&self, installation: &str) -> Result<()> {
        self.request.validate()?;
        self.audit().validate()?;
        if self.schema_version != 1
            || self.purpose != "luma-content-recipient-custody-enrollment-v1"
            || self.request.binding.installation != installation
            || self.generation
                != self
                    .request
                    .expected_generation
                    .checked_add(1)
                    .ok_or("recipient generation overflow")?
            || self.audit().operation_id.is_none()
            || self.audit().usage
                != usage(&self.request, self.audit().subject_generation)?
        {
            return Err(
                "recipient custody event differs from its approved original Admin request".into(),
            );
        }
        Ok(())
    }
}
pub(super) fn scope(command: &str, usage: &Use) -> Result<()> {
    usage.validate()?;
    if command != "content-backup-recipients-enroll"
        || usage.action != Action::ProvisionResource
        || usage.selector.kind != Kind::Resource
        || usage.selector.id != "content-backup-recipients-enroll-v1"
        || usage.selector.generation == 0
        || usage.input_bytes != MAX_REQUEST as u64
        || usage.output_bytes != 65536
        || usage.units != 1
    {
        return Err(
            "recipient custody requires its exact separate finite commissioning scope".into(),
        );
    }
    digest(&usage.selector.digest)
}
fn usage(request: &Request, admin_generation: u64) -> Result<Use> {
    let usage = Use {
        action: Action::ProvisionResource,
        selector: Selector {
            kind: Kind::Resource,
            id: "content-backup-recipients-enroll-v1".into(),
            generation: admin_generation,
            digest: request.sha256()?,
        },
        input_bytes: MAX_REQUEST as u64,
        output_bytes: 65536,
        units: 1,
    };
    scope("content-backup-recipients-enroll", &usage)?;
    Ok(usage)
}
pub(crate) fn read_request(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_REQUEST as u64
    {
        return Err("recipient request must be bounded regular single-link data".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || file_identity(&before) != file_identity(&file.metadata()?)
        || file_identity(&before) != file_identity(&fs::symlink_metadata(path)?)
    {
        return Err("recipient request changed during capture".into());
    }
    let request: Request = canonical(&bytes, MAX_REQUEST)?;
    request.validate()?;
    Ok(bytes)
}
pub(crate) fn verify_staged(path: &Path, usage: &Use) -> Result<()> {
    scope("content-backup-recipients-enroll", usage)?;
    let raw = path.to_str().ok_or("recipient staged path is not UTF8")?;
    let name = raw
        .strip_prefix("/run/luma-granted-client/requests/")
        .and_then(|v| v.strip_suffix("/content-backup-recipients.json"))
        .ok_or("recipient request is outside original immutable launcher namespace")?;
    tpm::decode::<16>(name)?;
    if fs::canonicalize(path)? != path {
        return Err("recipient staged request path is not canonical".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o400 {
        return Err("recipient staged request is not immutable root-owned data".into());
    }
    if hash(&read_request(path)?) != usage.selector.digest {
        return Err("original recipient payload differs from exact finite scope".into());
    }
    Ok(())
}
pub(super) fn execute(
    store: &mut Store<super::super::ContentAnchor>,
    request: &Request,
    audit: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    request.validate()?;
    audit.validate()?;
    store.live(check)?;
    if request.binding.installation != store.journal.installation
        || audit.usage != usage(request, audit.subject_generation)?
        || audit.operation_id.is_none()
    {
        return Err(
            "recipient commissioning differs from current original Admin and installation".into(),
        );
    }
    request.cryptographic_check(check)?;
    let key = owner_key(&request.binding)?;
    let previous = store.state.recipients.get(&key).cloned();
    if let Some(previous) = &previous {
        if previous.request.sha256()? == request.sha256()? {
            store.live(check)?;
            return Ok(
                serde_json::json!({"schema_version":1,"binding":request.binding,"generation":previous.generation,"active":request.active,
                "recipients":request.recipients,"owner_certificate_der_hex":request.owner_certificate_der_hex,"offline_admin_certificate_der_hex":request.offline_admin_certificate_der_hex,
                "checkpoint_head":bundle::hex(&store.state.checkpoint),"custody_enrolled":true,"production_qualified":false}),
            );
        }
    }
    let actual = previous.as_ref().map_or(0, |value| value.generation);
    if request.expected_generation != actual {
        return Err(
            "recipient custody generation changed; inspect and approve a fresh exact request"
                .into(),
        );
    }
    let generation = actual
        .checked_add(1)
        .ok_or("recipient generation overflow")?;
    let enrollment = Enrollment {
        schema_version: 1,
        purpose: "luma-content-recipient-custody-enrollment-v1".into(),
        generation,
        request: request.clone(),
        original_authority: audit.clone(),
    };
    enrollment.validate(&store.journal.installation)?;
    store.commit(Event::Recipients(enrollment), check)?;
    store.live(check)?;
    Ok(
        serde_json::json!({"schema_version":1,"binding":request.binding,"generation":generation,"active":request.active,
        "recipients":request.recipients,"owner_certificate_der_hex":request.owner_certificate_der_hex,"offline_admin_certificate_der_hex":request.offline_admin_certificate_der_hex,
        "checkpoint_head":bundle::hex(&store.state.checkpoint),"custody_enrolled":true,"production_qualified":false}),
    )
}
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let proposal = args.first().map(String::as_str) == Some("content-backup-recipients-proposal");
    if args.len() != if proposal { 3 } else { 4 }
        || (!proposal
            && args.first().map(String::as_str) != Some("content-backup-recipients-enroll"))
    {
        return Err("expected content-backup-recipients-proposal LOGIN REQUEST | content-backup-recipients-enroll LOGIN GRANT REQUEST".into());
    }
    let path = Path::new(&args[if proposal { 2 } else { 3 }]);
    let bytes = read_request(path)?;
    let request: Request = canonical(&bytes, MAX_REQUEST)?;
    let (_, admin, installation) = crate::admin_governance::current_principal(&args[1])?;
    if request.binding.installation != installation {
        return Err("recipient request differs from installed Admin deployment".into());
    }
    let scope = usage(&request, admin.generation)?;
    if proposal {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"schema_version":1,"usage":scope,"request_sha256":hash(&bytes),"recipient_custody_enrolled":false})
            )?
        );
        return Ok(());
    }
    let value = crate::admin_governance::with_grant(&args[1], &args[2], &scope, |boundary| {
        boundary.require_admin()?;
        let pending = boundary.effect_begin(
            &scope.selector.digest,
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let value = crate::service::content_admin::run(
            "content-backup-recipients-enroll",
            &scope,
            boundary,
            |job, cancel| {
                super::protocol::admin_recipients_exchange(
                    &scope,
                    &installation,
                    &job,
                    request.clone(),
                    cancel,
                )
            },
        )?;
        boundary.require_admin()?;
        boundary.effect_complete(pending, &hash(&serde_json::to_vec(&value)?))?;
        boundary.require_admin()?;
        Ok(value)
    })?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
