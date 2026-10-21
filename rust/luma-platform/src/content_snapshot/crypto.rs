use crate::{backup_crypto as crypto, Result};
use luma_content_store::v2::backup::{SnapshotIntent, SnapshotPart};

/// Retains the real original Export check during all existing helper protocol
/// states. Its fixed process ceiling never extends the original session.
pub(super) fn encrypt_part(
    bytes: &[u8],
    intent: &SnapshotIntent,
    recipients: &crypto::Recipients,
    boundary: &mut impl crypto::CryptoBoundary,
    original_export_check: &mut dyn FnMut() -> Result<()>,
) -> Result<crypto::EncryptedBackup> {
    original_export_check()?;
    intent.validate()?;
    if luma_content::sha256(&serde_json::to_vec(recipients.pins())?) != intent.recipients_sha256 {
        return Err("snapshot recipients differ from independently governed intent".into());
    }
    let parsed = SnapshotPart::parse(bytes, intent, &mut || original_export_check())?;
    let digest = parsed.sha256().to_owned();
    struct Original<'a, B> {
        boundary: &'a mut B,
        check: &'a mut dyn FnMut() -> Result<()>,
    }
    impl<B: crypto::CryptoBoundary> crypto::CryptoBoundary for Original<'_, B> {
        fn admit(
            &mut self,
            request: &crypto::CryptoRequest,
            budget: crypto::CryptoBudget,
        ) -> Result<()> {
            (self.check)()?;
            self.boundary.admit(request, budget)?;
            (self.check)()
        }
        fn check(&mut self, request: &crypto::CryptoRequest) -> Result<()> {
            (self.check)()?;
            self.boundary.check(request)?;
            (self.check)()
        }
    }
    let encrypted = crypto::encrypt_data(
        bytes,
        &digest,
        recipients,
        &mut Original {
            boundary,
            check: original_export_check,
        },
    )?;
    original_export_check()?;
    if encrypted.bytes().len() as u64 > bytes.len() as u64 + 65536 {
        return Err("snapshot CMS part exceeds bounded overhead".into());
    }
    Ok(encrypted)
}
