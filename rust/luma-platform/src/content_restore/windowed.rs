//! Standard-window CMS input for segmented fresh-owner restore. Successful
//! decryption is inert DATA; it does not authenticate an origin, select a job,
//! renew a session or grant permission to import/replay any artifact.
use crate::{backup_crypto as crypto, sealed_credential::PrivateBuffer, Result};
use luma_content_store::v2::backup::{
    PartCommitment, SnapshotPages, SnapshotPart, WholeSnapshotManifest,
};
use luma_content_store::v2::restore::{RestorePrefix, RestoreStage};
#[cfg(test)]
#[path = "windowed/tests.rs"]
mod tests;

/// Installed implementation must retain the independently authenticated whole
/// origin, actual current C job/prefix, original Admin Standard-purpose session,
/// exact independent finite Read/Write grants and actual current resource lease.
/// It must check the ORIGINAL projected thirty-second cutoff on every call; the
/// crypto helper's larger process ceiling is never a restore authorization.
pub(crate) trait OriginalStandardWindow: crypto::CryptoBoundary {
    fn current_import_window(
        &mut self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
    ) -> Result<()>;
}
fn live<B: OriginalStandardWindow>(
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    b: &mut B,
) -> Result<()> {
    manifest.validate()?;
    prefix.validate(manifest)?;
    if prefix.stage != RestoreStage::Importing || prefix.import.next_part >= manifest.part_count {
        return Err("CMS import requires the exact current next-part restore window".into());
    }
    b.current_import_window(manifest, prefix)
}
struct StandardCrypto<'a, B: OriginalStandardWindow> {
    b: &'a mut B,
    manifest: &'a WholeSnapshotManifest,
    prefix: &'a RestorePrefix,
    part: &'a PartCommitment,
}
impl<B: OriginalStandardWindow> StandardCrypto<'_, B> {
    fn request(&mut self, request: &crypto::CryptoRequest) -> Result<()> {
        live(self.manifest, self.prefix, self.b)?;
        if request.operation != crypto::CryptoOperation::DecryptOfflineAdmin
            || request.input_sha256 != self.part.ciphertext_sha256
            || request.input_bytes != self.part.ciphertext_bytes
            || luma_content::sha256(&serde_json::to_vec(&request.recipients)?)
                != self.manifest.intent.recipients_sha256
        {
            return Err(
                "CMS request differs from independently authenticated next-part Admin recovery"
                    .into(),
            );
        }
        Ok(())
    }
}
impl<B: OriginalStandardWindow> crypto::CryptoBoundary for StandardCrypto<'_, B> {
    fn admit(
        &mut self,
        request: &crypto::CryptoRequest,
        budget: crypto::CryptoBudget,
    ) -> Result<()> {
        self.request(request)?;
        self.b.admit(request, budget)?;
        self.request(request)
    }
    fn check(&mut self, request: &crypto::CryptoRequest) -> Result<()> {
        self.request(request)?;
        self.b.check(request)?;
        self.request(request)
    }
}
/// No Clone/Debug/Serialize and no raw-byte accessor. The actual crypto buffer
/// remains locked, nondumpable and is wiped by its existing Drop implementation.
pub(crate) struct ImportPlaintext {
    data: crypto::DecryptedBackup,
    manifest_sha256: String,
    prefix_sha256: String,
    part: PartCommitment,
}
impl ImportPlaintext {
    /// Borrow the locked bytes only during an original live import operation.
    /// The callback may plan and prepare immutable pages, but cannot return a
    /// plaintext borrow. It must still use the independent core RestoreBoundary.
    pub(crate) fn with_plaintext<B: OriginalStandardWindow, T>(
        &self,
        manifest: &WholeSnapshotManifest,
        prefix: &RestorePrefix,
        b: &mut B,
        visitor: impl FnOnce(&[u8], &mut B) -> Result<T>,
    ) -> Result<T> {
        live(manifest, prefix, b)?;
        if self.manifest_sha256 != manifest.sha256()?
            || self.prefix_sha256 != prefix.sha256(manifest)?
            || self.part.number != prefix.import.next_part
        {
            return Err("locked import plaintext retargets current job/prefix".into());
        }
        let bytes = self.data.data_checked(&mut StandardCrypto {
            b,
            manifest,
            prefix,
            part: &self.part,
        })?;
        verify_plaintext(bytes, manifest, &self.part, &mut || {
            live(manifest, prefix, b)
        })?;
        let output = visitor(bytes, b)?;
        live(manifest, prefix, b)?;
        Ok(output)
    }
}
fn verify_plaintext(
    bytes: &[u8],
    manifest: &WholeSnapshotManifest,
    part: &PartCommitment,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    if bytes.len() as u64 != part.plaintext_bytes
        || luma_content::sha256(bytes) != part.plaintext_sha256
    {
        return Err("locked CMS plaintext differs from signed whole-directory commitment".into());
    }
    let parsed = SnapshotPart::parse(bytes, &manifest.intent, check)?;
    if parsed.header().number != part.number
        || parsed.header().previous_plaintext_sha256 != part.previous_plaintext_sha256
        || parsed.header().objects.len() as u32 != part.objects
    {
        return Err("locked CMS frame differs from authenticated part order/coverage".into());
    }
    check()
}
pub(crate) fn decrypt_import_part<B: OriginalStandardWindow>(
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    pages: &mut impl SnapshotPages,
    ciphertext: &[u8],
    recipients: &crypto::Recipients,
    key: &PrivateBuffer,
    b: &mut B,
) -> Result<ImportPlaintext> {
    live(manifest, prefix, b)?;
    let part = manifest.part_at(prefix.import.next_part, pages, &mut || {
        live(manifest, prefix, b)
    })?;
    if ciphertext.len() as u64 != part.ciphertext_bytes
        || ciphertext.len() as u64 > part.plaintext_bytes + 65536
        || luma_content::sha256(&serde_json::to_vec(recipients.pins())?)
            != manifest.intent.recipients_sha256
    {
        return Err(
            "bounded retained CMS bytes/recipients differ from whole-origin receipt".into(),
        );
    }
    let mut standard = StandardCrypto {
        b,
        manifest,
        prefix,
        part: &part,
    };
    let data = crypto::decrypt_backup_data(
        ciphertext,
        &part.ciphertext_sha256,
        recipients,
        crypto::CryptoOperation::DecryptOfflineAdmin,
        key,
        &mut standard,
    )?;
    let bytes = data.data_checked(&mut standard)?;
    drop(standard);
    verify_plaintext(bytes, manifest, &part, &mut || live(manifest, prefix, b))?;
    live(manifest, prefix, b)?;
    Ok(ImportPlaintext {
        data,
        manifest_sha256: manifest.sha256()?,
        prefix_sha256: prefix.sha256(manifest)?,
        part,
    })
}
