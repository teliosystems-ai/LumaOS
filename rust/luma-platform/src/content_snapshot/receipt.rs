//! Whole-manifest origin attestation DATA. A valid historical signature is not
//! a current C selection, export permission or permission to restore anything.
use super::scope;
use crate::{artifacts, backup_crypto, finite_grants::Audit, receipt_signer, tpm, Result};
use luma_content_store::v2::backup::{SnapshotBudget, SnapshotMode, WholeSnapshotManifest};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "luma-content-whole-segmented-snapshot-export-v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Body {
    schema_version: u32,
    purpose: String,
    source_request_sha256: String,
    profile: String,
    storage_device: String,
    manifest: WholeSnapshotManifest,
    manifest_sha256: String,
    measured_package_bytes: u64,
    origin_spki_der_hex: String,
    checkpoint_before: String,
    original_authority: Audit,
}
impl Body {
    /// Constructs an unsigned attribution record only. The installed C path
    /// must independently revalidate source/head, all CMS parts/directory and
    /// recipients, then publish the export event before asking its signer.
    pub(crate) fn new_data(
        input: &scope::Input,
        manifest: WholeSnapshotManifest,
        measured_package_bytes: u64,
        storage_device: &str,
        origin_spki_der_hex: &str,
        checkpoint_before: &str,
        original_authority: Audit,
    ) -> Result<Self> {
        input.validate()?;
        manifest.validate()?;
        if input.mode != SnapshotMode::Export
            || input.intent != manifest.intent
            || input.review.as_ref() != Some(&manifest.review)
        {
            return Err("whole receipt substitutes the reviewed snapshot".into());
        }
        let value = Self {
            schema_version: 2,
            purpose: PURPOSE.into(),
            source_request_sha256: artifacts::digest(&input.canonical_bytes()?),
            profile: input.profile()?,
            storage_device: storage_device.into(),
            manifest_sha256: manifest.sha256()?,
            manifest,
            measured_package_bytes,
            origin_spki_der_hex: origin_spki_der_hex.into(),
            checkpoint_before: checkpoint_before.into(),
            original_authority,
        };
        value.validate()?;
        value.check_source(input)?;
        Ok(value)
    }
    pub(crate) fn manifest(&self) -> &WholeSnapshotManifest {
        &self.manifest
    }
    pub(crate) fn audit(&self) -> &Audit {
        &self.original_authority
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        self.original_authority.validate()?;
        let profile = scope::parse_profile(&self.profile)?;
        let public = tpm::decode::<44>(&self.origin_spki_der_hex)?;
        receipt_signer::validate_public(&public)?;
        let binding = &self.manifest.intent.head.binding;
        if self.schema_version != 2
            || self.purpose != PURPOSE
            || !scope::nonzero_hash(&self.checkpoint_before)
            || !scope::nonzero_hash(&self.source_request_sha256)
            || profile.mode != SnapshotMode::Export
            || profile.source_sha256 != self.source_request_sha256
            || profile.generation != binding.owner_generation
            || self.manifest_sha256 != self.manifest.sha256()?
            || self.manifest.intent.origin_spki_sha256 != artifacts::digest(&public)
            || self.measured_package_bytes <= self.manifest.ciphertext_bytes
            || self.measured_package_bytes > profile.output_bytes
            || self.original_authority.subject != binding.owner
            || self.original_authority.subject_generation != binding.owner_generation
            || self.original_authority.operation_id.is_none()
            || self.original_authority.usage
                != scope::uses(&self.profile, &self.storage_device, &binding.installation)?[1]
        {
            return Err(
                "whole receipt loses exact source, measured output or original Export attribution"
                    .into(),
            );
        }
        Ok(())
    }
    pub(crate) fn message(&self) -> Result<Vec<u8>> {
        self.validate()?;
        // Reuse the existing fixed-purpose backup signer envelope, with a
        // distinct closed body schema/purpose. Legacy deny-unknown-fields
        // parsers cannot interpret this body as a v1 single-archive receipt.
        let mut message = receipt_signer::DOMAIN.to_vec();
        message.extend(serde_json::to_vec(&serde_json::to_value(self)?)?);
        if message.len() > receipt_signer::MAX_MESSAGE - 4096 {
            return Err("whole receipt exceeds fixed signing envelope".into());
        }
        Ok(message)
    }
    pub(crate) fn check_source(&self, input: &scope::Input) -> Result<()> {
        self.validate()?;
        if input.mode != SnapshotMode::Export
            || input.intent != self.manifest.intent
            || input.review.as_ref() != Some(&self.manifest.review)
            || self.manifest.part_count > input.budget.maximum_parts
            || self.manifest.review.object_count > input.budget.maximum_objects
            || input.profile()? != self.profile
            || artifacts::digest(&input.canonical_bytes()?) != self.source_request_sha256
        {
            return Err("whole receipt differs from its exact original input".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) body: Body,
    pub(crate) signature_hex: String,
}
impl Receipt {
    pub(crate) fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > receipt_signer::MAX_MESSAGE {
            return Err("whole receipt exceeds bounded transport".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.body.validate()?;
        tpm::decode::<64>(&value.signature_hex)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err("whole receipt transport is not canonical".into());
        }
        Ok(value)
    }
    /// Verifies only immutable historical origin under an independently chosen
    /// pin. The caller still needs fresh Standard Admin restore authority and
    /// an independently selected target before importing or replaying content.
    pub(crate) fn verify_origin(
        &self,
        expected_origin: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.body.validate()?;
        if !scope::nonzero_hash(expected_origin)
            || self.body.manifest.intent.origin_spki_sha256 != expected_origin
        {
            return Err("whole snapshot origin differs from independent selected pin".into());
        }
        let public = tpm::decode::<44>(&self.body.origin_spki_der_hex)?;
        let signature = tpm::decode::<64>(&self.signature_hex)?;
        receipt_signer::verify(&public, &self.body.message()?, &signature, &mut *check)?;
        check()
    }
}

/// Public, bounded package metadata. It retains the exact original recipient
/// DER and reconstructs the signed source request without duplicating the
/// complete head/review already in the whole manifest. Parsing is not trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    schema_version: u32,
    profile: String,
    login: String,
    budget: SnapshotBudget,
    recipients: backup_crypto::RecipientPins,
    owner_certificate_der_hex: String,
    offline_admin_certificate_der_hex: String,
    pub(crate) receipt: Receipt,
}
impl Header {
    pub(crate) fn new_data(input: &scope::Input, receipt: Receipt) -> Result<Self> {
        receipt.body.check_source(input)?;
        tpm::decode::<64>(&receipt.signature_hex)?;
        let value = Self {
            schema_version: 1,
            profile: "luma-whole-snapshot-package-header-v1".into(),
            login: input.login.clone(),
            budget: input.budget,
            recipients: input.recipients.clone(),
            owner_certificate_der_hex: input.owner_certificate_der_hex.clone(),
            offline_admin_certificate_der_hex: input.offline_admin_certificate_der_hex.clone(),
            receipt,
        };
        value.canonical_bytes()?;
        Ok(value)
    }
    pub(crate) fn source(&self) -> Result<scope::Input> {
        if self.schema_version != 1 || self.profile != "luma-whole-snapshot-package-header-v1" {
            return Err("unknown whole snapshot package header".into());
        }
        let input = scope::Input {
            schema_version: 1,
            login: self.login.clone(),
            intent: self.receipt.body.manifest.intent.clone(),
            mode: SnapshotMode::Export,
            budget: self.budget,
            review: Some(self.receipt.body.manifest.review.clone()),
            recipients: self.recipients.clone(),
            owner_certificate_der_hex: self.owner_certificate_der_hex.clone(),
            offline_admin_certificate_der_hex: self.offline_admin_certificate_der_hex.clone(),
        };
        self.receipt.body.check_source(&input)?;
        tpm::decode::<64>(&self.receipt.signature_hex)?;
        Ok(input)
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.source()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err("whole snapshot header exceeds fixed package reserve".into());
        }
        Ok(bytes)
    }
    pub(crate) fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err("whole snapshot header exceeds fixed parser bound".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if value.canonical_bytes()? != bytes {
            return Err("whole snapshot header is not canonical".into());
        }
        Ok(value)
    }
}

#[cfg(test)]
#[path = "receipt/tests.rs"]
mod tests;
