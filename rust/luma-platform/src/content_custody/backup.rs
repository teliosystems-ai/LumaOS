//! Exact protected export commitments. The signature authenticates measured
//! ciphertext and governed recipient pins, never an archive-supplied identity
//! or permission to restore accounts, grants, sessions or TPM authority.
use super::*;
use crate::{backup_crypto::EncryptionCommitment, content_backup::Input};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Body {
    schema_version: u32,
    purpose: String,
    pub(crate) input: Input,
    profile: String,
    storage_device: String,
    pub(crate) source_state: VerifiedState,
    pub(crate) encryption: EncryptionCommitment,
    recipient_generation: u64,
    pub(crate) origin_spki_der_hex: String,
    pub(crate) origin_spki_sha256: String,
    checkpoint_before: String,
    original_authority: Audit,
}
impl Body {
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = crate::receipt_signer::DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(&serde_json::to_value(self)?)?);
        if bytes.len() > crate::receipt_signer::MAX_MESSAGE - 4096 {
            return Err("backup custody receipt exceeds fixed signature bound".into());
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        self.input.validate()?;
        self.source_state.validate()?;
        self.original_authority.validate()?;
        digest(&self.checkpoint_before)?;
        digest(&self.origin_spki_sha256)?;
        let public = tpm::decode::<44>(&self.origin_spki_der_hex)?;
        crate::receipt_signer::validate_public(&public)?;
        if self.schema_version != 1
            || self.purpose != "luma-content-measured-backup-export-v1"
            || self.input.custody_generation()? != Some(self.recipient_generation)
            || self.source_state.binding != self.input.binding
            || self.source_state.outcome_count != self.input.review.committed_outcomes
            || self.source_state.head_sha256 != self.input.review.committed_head_sha256
            || hash(&public) != self.origin_spki_sha256
            || crate::content_backup::profile(&self.input, &serde_json::to_vec(&self.input)?)?
                != self.profile
            || self.original_authority.subject != self.input.binding.owner
            || self.original_authority.subject_generation != self.input.binding.owner_generation
            || self.original_authority.operation_id.is_none()
            || self.original_authority.usage
                != crate::content_backup::custody_usage(
                    &self.profile,
                    &self.storage_device,
                    &self.input.binding.installation,
                )?
        {
            return Err("backup receipt differs from exact original governed export".into());
        }
        crate::content_backup::validate_encryption(&self.encryption, &self.input)
    }
    pub(super) fn job(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&(
            &self.profile,
            &self.original_authority.operation_id,
        ))?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) body: Body,
    pub(crate) signature_hex: String,
}
impl Receipt {
    pub(crate) fn export_binding(&self) -> Result<String> {
        Ok(crate::content_backup::custody_usage(
            &self.body.profile,
            &self.body.storage_device,
            &self.body.input.binding.installation,
        )?
        .selector
        .digest)
    }
    /// Checks exact data binding, not signature trust. The independently pinned
    /// origin signature must also be verified before decrypting or importing.
    pub(crate) fn check_data(
        &self,
        input: &Input,
        encryption: &EncryptionCommitment,
    ) -> Result<()> {
        self.body.message()?;
        tpm::decode::<64>(&self.signature_hex)?;
        if serde_json::to_vec(&self.body.input)? != serde_json::to_vec(input)?
            || &self.body.encryption != encryption
        {
            return Err("custody receipt substitutes reviewed input or measured ciphertext".into());
        }
        Ok(())
    }
    pub(crate) fn verify_origin(
        &self,
        expected_origin: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        digest(expected_origin)?;
        if self.body.origin_spki_sha256 != expected_origin {
            return Err("backup origin differs from independently selected public pin".into());
        }
        let public = tpm::decode::<44>(&self.body.origin_spki_der_hex)?;
        let signature = tpm::decode::<64>(&self.signature_hex)?;
        crate::receipt_signer::verify(&public, &self.body.message()?, &signature, &mut *check)?;
        check()
    }
}

pub(crate) fn verify_stdin(expected_origin: &str) -> Result<()> {
    digest(expected_origin)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)?;
    let receipt: Receipt = canonical(&bytes, 65536)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    receipt.verify_origin(expected_origin, &mut || {
        if std::time::Instant::now() >= deadline {
            return Err("public signature verification deadline exceeded".into());
        }
        Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"origin_signature_valid":true,
        "independently_selected_origin_spki_sha256":expected_origin,"binding":receipt.body.input.binding,
        "review_sha256":receipt.body.input.review.review_sha256,
        "cms_sha256":receipt.body.encryption.cms_sha256,"cms_bytes":receipt.body.encryption.cms_bytes,
        "archive_sha256":receipt.body.encryption.archive_sha256,
        "current_custody_qualified":false,"archive_validated":false,
        "archive_decrypted":false,"restore_permitted":false,"authority_returned":false})
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_signed_receipt() -> Receipt {
    tests::signed_fixture()
}
#[cfg(test)]
pub(super) fn test_receipt_for_review(review: &luma_content_store::BackupReview) -> Receipt {
    tests::signed_review_fixture(review)
}

pub(super) fn validate_event(body: &Body, installation: &str, state: &Validated) -> Result<()> {
    body.message()?;
    let key = owner_key(&body.input.binding)?;
    let current = state
        .owners
        .get(&key)
        .cloned()
        .unwrap_or(VerifiedState::empty(&body.input.binding)?);
    let enrollment = state
        .recipients
        .get(&key)
        .ok_or("backup has no protected recipient custody")?;
    let signer = state
        .signer
        .as_ref()
        .ok_or("backup has no enrolled origin signer")?;
    let (public, pin) = signer.public_pin();
    if body.input.binding.installation != installation
        || body.source_state != current
        || body.checkpoint_before != bundle::hex(&state.checkpoint)
        || !enrollment.request.active
        || enrollment.generation != body.recipient_generation
        || enrollment.request.recipients != body.input.recipients
        || enrollment.request.owner_certificate_der_hex != body.input.owner_certificate_der_hex
        || enrollment.request.offline_admin_certificate_der_hex
            != body.input.offline_admin_certificate_der_hex
        || public != body.origin_spki_der_hex
        || pin != body.origin_spki_sha256
    {
        return Err(
            "backup does not extend exact active owner, recipient and origin custody".into(),
        );
    }
    Ok(())
}

pub(super) fn prepare(
    store: &mut Store<super::super::ContentAnchor>,
    input: &Input,
    profile: &str,
    device: &str,
    original: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<VerifiedState> {
    store.live(check)?;
    input.validate()?;
    if input.custody_generation()?.is_none()
        || crate::content_backup::profile(input, &serde_json::to_vec(input)?)? != profile
        || original.subject != input.binding.owner
        || original.subject_generation != input.binding.owner_generation
        || original.operation_id.is_none()
        || original.usage
            != crate::content_backup::custody_usage(profile, device, &input.binding.installation)?
    {
        return Err("backup custody requires the genuine original finite Export operation".into());
    }
    let current = store.selected(&input.binding, check)?;
    let key = owner_key(&input.binding)?;
    let recipients = store
        .state
        .recipients
        .get(&key)
        .ok_or("backup encryption recipients not enrolled")?;
    if !recipients.request.active
        || Some(recipients.generation) != input.custody_generation()?
        || recipients.request.recipients != input.recipients
        || recipients.request.owner_certificate_der_hex != input.owner_certificate_der_hex
        || recipients.request.offline_admin_certificate_der_hex
            != input.offline_admin_certificate_der_hex
        || store.state.signer.is_none()
        || current.outcome_count != input.review.committed_outcomes
        || current.head_sha256 != input.review.committed_head_sha256
    {
        return Err(
            "backup review, active recipients or signer differs from current protected cut".into(),
        );
    }
    crate::content_backup::binding(profile, device)?;
    store.live(check)?;
    Ok(current)
}

pub(super) fn issue(
    store: &mut Store<super::super::ContentAnchor>,
    input: &Input,
    encryption: &EncryptionCommitment,
    profile: &str,
    device: &str,
    original: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Receipt> {
    let source_state = prepare(store, input, profile, device, original, check)?;
    crate::content_backup::validate_encryption(encryption, input)?;
    let existing = store.journal.events.iter().find_map(|event| match event {
        Event::Backup(body)
            if body.profile == profile
                && body.original_authority.operation_id == original.operation_id =>
        {
            Some(body.clone())
        }
        _ => None,
    });
    let body = if let Some(body) = existing {
        if serde_json::to_vec(&body.input)? != serde_json::to_vec(input)?
            || body.encryption != *encryption
            || body.original_authority != *original
            || body.source_state != source_state
        {
            return Err(
                "existing backup job cannot be reused for substituted bytes or authority".into(),
            );
        }
        body
    } else {
        let signer = store.state.signer.as_ref().ok_or("origin signer missing")?;
        let (public, pin) = signer.public_pin();
        let body = Body {
            schema_version: 1,
            purpose: "luma-content-measured-backup-export-v1".into(),
            input: input.clone(),
            profile: profile.into(),
            storage_device: device.into(),
            source_state,
            encryption: encryption.clone(),
            recipient_generation: input
                .custody_generation()?
                .ok_or("governed generation missing")?,
            origin_spki_der_hex: public.into(),
            origin_spki_sha256: pin.into(),
            checkpoint_before: bundle::hex(&store.state.checkpoint),
            original_authority: original.clone(),
        };
        validate_event(&body, &store.journal.installation, &store.state)?;
        store.commit(Event::Backup(body.clone()), check)?;
        body
    };
    let signature = super::signer::sign_receipt(store, &body.message()?, check)?;
    let receipt = Receipt {
        body,
        signature_hex: bundle::hex(&signature),
    };
    receipt.check_data(input, encryption)?;
    store.live(check)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn body() -> Body {
        let mut input = crate::content_backup::test_input();
        input.recipient_choice = "governed-content-custody-v1-7".into();
        let profile =
            crate::content_backup::profile(&input, &serde_json::to_vec(&input).unwrap()).unwrap();
        let mut state = VerifiedState::empty(&input.binding).unwrap();
        state.head_sha256 = input.review.committed_head_sha256.clone();
        let public = format!("302a300506032b6570032100{}", "01".repeat(32));
        Body {
            schema_version: 1,
            purpose: "luma-content-measured-backup-export-v1".into(),
            profile: profile.clone(),
            storage_device: "8:1".into(),
            source_state: state,
            encryption: EncryptionCommitment {
                schema_version: 1,
                profile: "cms-auth-enveloped-aes256gcm-rsa-oaep-sha256-two-recipients-v1".into(),
                archive_sha256: input.review.archive_sha256.clone(),
                archive_bytes: input.review.archive_bytes,
                cms_sha256: hash(b"ciphertext"),
                cms_bytes: 10,
                recipients: input.recipients.clone(),
                authenticates_sender: false,
                proves_both_recipients_recoverable: false,
                permits_restore: false,
            },
            recipient_generation: 7,
            origin_spki_sha256: hash(&tpm::decode::<44>(&public).unwrap()),
            origin_spki_der_hex: public,
            checkpoint_before: "12".repeat(32),
            original_authority: Audit {
                subject: input.binding.owner.clone(),
                subject_generation: input.binding.owner_generation,
                grant_id: "explicit-fixture-export".into(),
                grant_version: 1,
                checkpoint_head: "13".repeat(32),
                operation_id: Some("14".repeat(16)),
                usage: crate::content_backup::custody_usage(
                    &profile,
                    "8:1",
                    &input.binding.installation,
                )
                .unwrap(),
            },
            input,
        }
    }
    pub(super) fn signed_fixture() -> Receipt {
        sign_body(body())
    }
    pub(super) fn signed_review_fixture(review: &luma_content_store::BackupReview) -> Receipt {
        let mut body = body();
        body.input.binding = review.binding.clone();
        body.input.review = review.clone();
        body.profile =
            crate::content_backup::profile(&body.input, &serde_json::to_vec(&body.input).unwrap())
                .unwrap();
        body.source_state = VerifiedState::empty(&review.binding).unwrap();
        body.source_state.outcome_count = review.committed_outcomes;
        body.source_state.head_sha256 = review.committed_head_sha256.clone();
        body.encryption.archive_sha256 = review.archive_sha256.clone();
        body.encryption.archive_bytes = review.archive_bytes;
        body.original_authority.subject = review.binding.owner.clone();
        body.original_authority.subject_generation = review.binding.owner_generation;
        body.original_authority.usage = crate::content_backup::custody_usage(
            &body.profile,
            &body.storage_device,
            &review.binding.installation,
        )
        .unwrap();
        sign_body(body)
    }
    fn sign_body(mut body: Body) -> Receipt {
        let (seed, public) = crate::receipt_signer::generate(|| Ok(())).unwrap();
        body.origin_spki_der_hex = bundle::hex(&public);
        body.origin_spki_sha256 = hash(&public);
        let signature =
            crate::receipt_signer::sign(&seed, &body.message().unwrap(), || Ok(())).unwrap();
        drop(seed);
        Receipt {
            body,
            signature_hex: bundle::hex(&signature),
        }
    }
    #[test]
    fn portable_data_binding_never_uses_the_receiving_installation_as_origin() {
        let body = body();
        let message = body.message().unwrap();
        assert!(message.starts_with(crate::receipt_signer::DOMAIN));
        let data = &message[crate::receipt_signer::DOMAIN.len()..];
        let value: serde_json::Value = serde_json::from_slice(data).unwrap();
        assert_eq!(serde_json::to_vec(&value).unwrap(), data);
        for field in [
            "recipient_generation",
            "checkpoint_before",
            "origin_spki_sha256",
        ] {
            let mut changed = serde_json::to_value(&body).unwrap();
            changed[field] = if field == "recipient_generation" {
                serde_json::json!(8)
            } else {
                serde_json::json!("00".repeat(32))
            };
            assert!(
                serde_json::from_value::<Body>(changed)
                    .unwrap()
                    .message()
                    .is_err(),
                "{field}"
            );
        }
        let mut changed = body.clone();
        changed.original_authority.operation_id = None;
        assert!(changed.message().is_err());
        let mut changed = body.clone();
        changed.encryption.proves_both_recipients_recoverable = true;
        assert!(changed.message().is_err());
        let mut state = Journal::empty(&body.input.binding.installation, [3; 32])
            .unwrap()
            .validate()
            .unwrap();
        state.owners.insert(
            owner_key(&body.input.binding).unwrap(),
            body.source_state.clone(),
        );
        assert!(validate_event(&body, &body.input.binding.installation, &state).is_err());
        // Syntax/checksum agreement does not supply enrolled custody or a
        // signature: even a shape-correct descriptive receipt cannot enroll.
        let receipt = Receipt {
            body: body.clone(),
            signature_hex: "15".repeat(64),
        };
        receipt.check_data(&body.input, &body.encryption).unwrap();
        let mut input = body.input.clone();
        input.login = "bob".into();
        assert!(receipt.check_data(&input, &body.encryption).is_err());
    }
    #[test]
    fn actual_signature_requires_independent_origin_pin_and_exact_receipt_bytes() {
        let mut body = body();
        let mut checks = 0;
        let mut live = || -> Result<()> {
            checks += 1;
            Ok(())
        };
        let (seed, public) = crate::receipt_signer::generate(&mut live).unwrap();
        body.origin_spki_der_hex = bundle::hex(&public);
        body.origin_spki_sha256 = hash(&public);
        let signature =
            crate::receipt_signer::sign(&seed, &body.message().unwrap(), &mut live).unwrap();
        drop(seed);
        let receipt = Receipt {
            body,
            signature_hex: bundle::hex(&signature),
        };
        receipt
            .verify_origin(&receipt.body.origin_spki_sha256, &mut live)
            .unwrap();
        assert!(receipt.verify_origin(&"ff".repeat(32), &mut live).is_err());
        let mut changed = receipt.clone();
        changed.body.encryption.cms_sha256 = hash(b"substituted wrapped recipient key");
        assert!(changed
            .verify_origin(&receipt.body.origin_spki_sha256, &mut live)
            .is_err());
        let mut changed = receipt.clone();
        changed.signature_hex = "00".repeat(64);
        assert!(changed
            .verify_origin(&receipt.body.origin_spki_sha256, &mut live)
            .is_err());
        assert!(checks > 10);
        assert!(receipt
            .verify_origin(&receipt.body.origin_spki_sha256, &mut || Err(
                "explicit revocation".into()
            ))
            .is_err());
    }
}
