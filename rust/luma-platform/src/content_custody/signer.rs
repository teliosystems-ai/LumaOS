//! Separate TPM-sealed receipt seed. Public preparation is not enrollment;
//! only a fresh original Admin proof and its exact C event enroll the pin.
use super::*;
use crate::{
    finite_grants::{Action, Kind, Selector, Use},
    sealed_credential::{PrivateBuffer, Secret},
};
use std::path::Path;
const SEALED: &str = "sealed/receipt-signer.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    purpose: String,
    installation: String,
    generation: u64,
    parent_name: String,
    pcr_public_key_sha256: String,
    spki_der_hex: String,
    spki_sha256: String,
    public_blob: String,
    private_blob: String,
}
impl Envelope {
    fn validate(&self, installation: &str) -> Result<Vec<u8>> {
        if self.schema_version != 1
            || self.purpose != "luma-content-receipt-sealed-seed-v1"
            || self.installation != installation
            || self.generation != 1
            || tpm::decode::<34>(&self.parent_name)?[..2] != [0, 0x0b]
        {
            return Err(
                "receipt seed envelope has wrong installation/parent/purpose/generation".into(),
            );
        }
        digest(&self.pcr_public_key_sha256)?;
        digest(&self.spki_sha256)?;
        let spki = tpm::decode::<44>(&self.spki_der_hex)?.to_vec();
        crate::receipt_signer::validate_public(&spki)?;
        if hash(&spki) != self.spki_sha256 {
            return Err("receipt SPKI pin differs from exact public bytes".into());
        }
        super::super::decode_blob(&self.public_blob)?;
        super::super::decode_blob(&self.private_blob)?;
        Ok(spki)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    schema_version: u32,
    purpose: String,
    installation: String,
    generation: u64,
    spki_der_hex: String,
    spki_sha256: String,
    sealed_envelope_sha256: String,
    original_authority: Audit,
}
impl Enrollment {
    pub(super) fn audit(&self) -> &Audit {
        &self.original_authority
    }
    pub(super) fn public_pin(&self) -> (&str, &str) {
        (&self.spki_der_hex, &self.spki_sha256)
    }
    pub(super) fn validate(&self, installation: &str) -> Result<()> {
        if self.schema_version != 1
            || self.purpose != "luma-content-receipt-signer-enrollment-v1"
            || self.installation != installation
            || self.generation != 1
        {
            return Err("invalid receipt signer enrollment event".into());
        }
        digest(installation)?;
        digest(&self.spki_sha256)?;
        digest(&self.sealed_envelope_sha256)?;
        let spki = tpm::decode::<44>(&self.spki_der_hex)?;
        crate::receipt_signer::validate_public(&spki)?;
        if hash(&spki) != self.spki_sha256 {
            return Err("receipt signer enrolled pin differs".into());
        }
        self.audit().validate()?;
        admin_scope(
            "content-backup-signer-enroll",
            &self.audit().usage,
        )?;
        if self.audit().usage.selector.digest != self.sealed_envelope_sha256
            || self.audit().operation_id.is_none()
        {
            return Err(
                "receipt signer enrollment lacks exact original reviewed Admin operation".into(),
            );
        }
        Ok(())
    }
}
pub(crate) fn admin_scope(command: &str, usage: &Use) -> Result<()> {
    usage.validate()?;
    let id = match command {
        "content-backup-signer-prepare" => "content-backup-signer-prepare-v1",
        "content-backup-signer-enroll" => "content-backup-signer-enroll-v1",
        _ => return Err("unsupported closed content custody Admin operation".into()),
    };
    if usage.action != Action::ProvisionResource
        || usage.selector.kind != Kind::Resource
        || usage.selector.id != id
        || usage.selector.generation == 0
        || usage.input_bytes != 0
        || usage.output_bytes != 8192
        || usage.units != 1
    {
        return Err(
            "content custody Admin grant is not the exact finite commissioning scope".into(),
        );
    }
    digest(&usage.selector.digest)
}
fn usage(command: &str, owner: &OwnerBinding, sha: &str) -> Result<Use> {
    owner.validate()?;
    digest(sha)?;
    let id = match command {
        "content-backup-signer-prepare" => "content-backup-signer-prepare-v1",
        "content-backup-signer-enroll" => "content-backup-signer-enroll-v1",
        _ => return Err("unsupported signer ceremony".into()),
    };
    let result = Use {
        action: Action::ProvisionResource,
        selector: Selector {
            kind: Kind::Resource,
            id: id.into(),
            generation: owner.owner_generation,
            digest: sha.into(),
        },
        input_bytes: 0,
        output_bytes: 8192,
        units: 1,
    };
    admin_scope(command, &result)?;
    Ok(result)
}
fn prepare_usage(owner: &OwnerBinding) -> Result<Use> {
    usage(
        "content-backup-signer-prepare",
        owner,
        &hash(&serde_json::to_vec(&(
            "luma-content-receipt-signer-prepare-v1",
            owner,
        ))?),
    )
}
fn config(
    anchor: &mut super::super::ContentAnchor,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(super::super::Configuration, Vec<u8>, Vec<u8>)> {
    check()?;
    let bytes = super::super::immutable(&Path::new(DIRECTORY).join("sealed/anchor.json"), 4096)?;
    let config: super::super::Configuration = super::super::canonical(&bytes)?;
    config.validate()?;
    if config.installation != anchor.installation()
        || tpm::decode::<32>(&config.genesis_event)? != anchor.genesis_event()
    {
        return Err("receipt signer differs from current independent sealed C authority".into());
    }
    let public = crate::admin_credentials::public_input(Path::new(super::super::PUBLIC), 4096)?;
    let signature =
        crate::admin_credentials::public_input(Path::new(super::super::SIGNATURE), 16384)?;
    if hash(&public) != config.pcr_public_key_sha256 {
        return Err("receipt parent boot public key changed".into());
    }
    anchor
        .device
        .parent_matches(&tpm::decode(&config.parent_name)?)?;
    check()?;
    Ok((config, public, signature))
}
fn unseal(
    anchor: &mut super::super::ContentAnchor,
    envelope: &Envelope,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<PrivateBuffer> {
    let (config, public, signature) = config(anchor, check)?;
    let expected = envelope.validate(anchor.installation())?;
    if envelope.parent_name != config.parent_name
        || envelope.pcr_public_key_sha256 != config.pcr_public_key_sha256
    {
        return Err("receipt signer sealed parent or verifier pin changed".into());
    }
    check()?;
    let policy = super::super::current_policy(&mut anchor.device, &public, &signature)?;
    let secret = anchor.device.unseal(
        &tpm::decode(&envelope.parent_name)?,
        &public,
        &super::super::decode_blob(&envelope.public_blob)?,
        &super::super::decode_blob(&envelope.private_blob)?,
        &policy.digest,
        &policy.signature,
    )?;
    check()?;
    let mut seed = PrivateBuffer::new(32)?;
    seed.bytes_mut().copy_from_slice(secret.bytes());
    drop(secret);
    if crate::receipt_signer::public(&seed, &mut *check)? != expected {
        return Err(
            "unsealed receipt seed does not derive independently reviewed public pin".into(),
        );
    }
    check()?;
    Ok(seed)
}
fn possession(
    anchor: &mut super::super::ContentAnchor,
    envelope: &Envelope,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let seed = unseal(anchor, envelope, check)?;
    let value = serde_json::json!({"schema_version":1,"receipt_kind":"enrollment-possession-test",
        "installation":anchor.installation(),"spki_sha256":envelope.spki_sha256,"sealed_envelope_sha256":hash(&serde_json::to_vec(envelope)?),"permits_restore":false});
    let mut message = crate::receipt_signer::DOMAIN.to_vec();
    message.extend(serde_json::to_vec(&value)?);
    let signature = crate::receipt_signer::sign(&seed, &message, &mut *check)?;
    let public = envelope.validate(anchor.installation())?;
    crate::receipt_signer::verify(&public, &message, &signature, &mut *check)?;
    check()
}
pub(super) fn sign_receipt(
    store: &mut Store<super::super::ContentAnchor>,
    message: &[u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<[u8; 64]> {
    store.live(check)?;
    let enrollment = store
        .state
        .signer
        .clone()
        .ok_or("receipt signer has not been explicitly enrolled")?;
    let bytes = store.files.read(SEALED, check)?;
    let envelope: Envelope = canonical(&bytes, 16384)?;
    let public = envelope.validate(&store.journal.installation)?;
    if enrollment.sealed_envelope_sha256 != hash(&bytes)
        || enrollment.spki_der_hex != envelope.spki_der_hex
        || enrollment.spki_sha256 != hash(&public)
    {
        return Err("current receipt seed differs from protected enrollment".into());
    }
    let seed = unseal(&mut store.anchor, &envelope, check)?;
    let signature = crate::receipt_signer::sign(&seed, message, &mut *check)?;
    drop(seed);
    crate::receipt_signer::verify(&public, message, &signature, &mut *check)?;
    store.live(check)?;
    Ok(signature)
}
pub(super) fn execute(
    store: &mut Store<super::super::ContentAnchor>,
    command: &str,
    audit: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    admin_scope(command, &audit.usage)?;
    audit.validate()?;
    store.live(check)?;
    let owner = OwnerBinding {
        installation: store.journal.installation.clone(),
        owner: audit.subject.clone(),
        owner_generation: audit.subject_generation,
    };
    if audit.usage.selector.generation != owner.owner_generation || audit.operation_id.is_none() {
        return Err("receipt signer requires current exact original Admin generation".into());
    }
    if command == "content-backup-signer-prepare" {
        if audit.usage != prepare_usage(&owner)? {
            return Err("receipt preparation is not the exact current commissioning scope".into());
        }
        if store.state.signer.is_some() {
            return Err("receipt signer already enrolled; no implicit key replacement".into());
        }
        match fs::symlink_metadata(store.files.root.join(SEALED)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let (config, public, _) = config(&mut store.anchor, check)?;
                let (seed, spki) = crate::receipt_signer::generate(&mut *check)?;
                let secret = Secret::from_buffer(seed);
                check()?;
                let (public_blob, private_blob) = store.anchor.device.seal(
                    &tpm::decode(&config.parent_name)?,
                    &public,
                    &secret,
                )?;
                drop(secret);
                check()?;
                let envelope = Envelope {
                    schema_version: 1,
                    purpose: "luma-content-receipt-sealed-seed-v1".into(),
                    installation: owner.installation.clone(),
                    generation: 1,
                    parent_name: config.parent_name,
                    pcr_public_key_sha256: config.pcr_public_key_sha256,
                    spki_der_hex: bundle::hex(&spki),
                    spki_sha256: hash(&spki),
                    public_blob: bundle::hex(&public_blob),
                    private_blob: bundle::hex(&private_blob),
                };
                envelope.validate(&owner.installation)?;
                let bytes = serde_json::to_vec(&envelope)?;
                if bytes.len() > 16384 {
                    return Err("sealed receipt seed envelope exceeds closed bound".into());
                }
                store.files.create(SEALED, &bytes, check)?;
            }
            Err(error) => return Err(error.into()),
        }
        let bytes = store.files.read(SEALED, check)?;
        let envelope: Envelope = canonical(&bytes, 16384)?;
        possession(&mut store.anchor, &envelope, check)?;
        store.live(check)?;
        let review = hash(&bytes);
        Ok(
            serde_json::json!({"schema_version":1,"installation":owner.installation,"spki_der_hex":envelope.spki_der_hex,
            "spki_sha256":envelope.spki_sha256,"review_sha256":review,"enrollment_usage":usage("content-backup-signer-enroll",&owner,&review)?,
            "TPM_sealed_seed":true,"TPM_resident_signing_key":false,"enrolled":false,"permits_restore":false}),
        )
    } else {
        let bytes = store.files.read(SEALED, check)?;
        let envelope: Envelope = canonical(&bytes, 16384)?;
        let spki = envelope.validate(&owner.installation)?;
        if audit.usage != usage(command, &owner, &hash(&bytes))? {
            return Err("receipt signer enrollment differs from exact approved sealed envelope and public pin".into());
        }
        possession(&mut store.anchor, &envelope, check)?;
        if let Some(enrollment) = &store.state.signer {
            if enrollment.spki_der_hex != envelope.spki_der_hex
                || enrollment.spki_sha256 != hash(&spki)
                || enrollment.sealed_envelope_sha256 != hash(&bytes)
            {
                return Err("different receipt signer already anchored; preserve custody".into());
            }
            store.live(check)?;
        } else {
            let enrollment = Enrollment {
                schema_version: 1,
                purpose: "luma-content-receipt-signer-enrollment-v1".into(),
                installation: owner.installation.clone(),
                generation: 1,
                spki_der_hex: envelope.spki_der_hex.clone(),
                spki_sha256: envelope.spki_sha256.clone(),
                sealed_envelope_sha256: hash(&bytes),
                original_authority: audit.clone(),
            };
            enrollment.validate(&owner.installation)?;
            store.commit(Event::ReceiptSigner(enrollment), check)?;
        }
        store.live(check)?;
        Ok(
            serde_json::json!({"schema_version":1,"installation":owner.installation,"spki_der_hex":envelope.spki_der_hex,
            "spki_sha256":envelope.spki_sha256,"checkpoint_head":bundle::hex(&store.state.checkpoint),"enrolled":true,
            "TPM_sealed_seed":true,"TPM_resident_signing_key":false,"permits_restore":false,"production_qualified":false}),
        )
    }
}
pub(crate) fn signer_command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let command = args
        .first()
        .map(String::as_str)
        .ok_or("receipt signer ceremony missing")?;
    let proposal = command == "content-backup-signer-prepare-proposal";
    if (!proposal
        && command != "content-backup-signer-prepare"
        && command != "content-backup-signer-enroll")
        || args.len()
            != if proposal {
                2
            } else if command == "content-backup-signer-prepare" {
                3
            } else {
                4
            }
    {
        return Err("expected content-backup-signer-prepare-proposal LOGIN | content-backup-signer-prepare LOGIN GRANT | content-backup-signer-enroll LOGIN GRANT EXACT-PUBLIC-PIN-REVIEW".into());
    }
    let (_, principal, installation) = crate::admin_governance::current_principal(&args[1])?;
    let owner = OwnerBinding {
        installation,
        owner: principal.id,
        owner_generation: principal.generation,
    };
    let scope = if command == "content-backup-signer-enroll" {
        usage(command, &owner, &args[3])?
    } else {
        prepare_usage(&owner)?
    };
    if proposal {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"schema_version":1,"usage":scope,"private_authority_read":false})
            )?
        );
        return Ok(());
    }
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &scope, |boundary| {
        boundary.require_admin()?;
        let pending = boundary.effect_begin(
            &scope.selector.digest,
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let value =
            crate::service::content_admin::run(command, &scope, boundary, |job, cancel| {
                super::protocol::admin_exchange(command, &scope, &owner.installation, &job, cancel)
            })?;
        boundary.require_admin()?;
        boundary.effect_complete(pending, &hash(&serde_json::to_vec(&value)?))?;
        boundary.require_admin()?;
        Ok(value)
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_preparation_and_enrollment_are_distinct_exact_finite_scopes() {
        let owner = OwnerBinding {
            installation: "11".repeat(32),
            owner: "22".repeat(32),
            owner_generation: 7,
        };
        let first = prepare_usage(&owner).unwrap();
        let second = usage("content-backup-signer-enroll", &owner, &"33".repeat(32)).unwrap();
        assert_ne!(first, second);
        admin_scope("content-backup-signer-prepare", &first).unwrap();
        assert!(admin_scope("content-backup-signer-enroll", &first).is_err());
        let mut oversized = second.clone();
        oversized.output_bytes += 1;
        assert!(admin_scope("content-backup-signer-enroll", &oversized).is_err());
        let mut other = owner;
        other.owner_generation += 1;
        assert_ne!(first, prepare_usage(&other).unwrap());
    }
}
