//! Native CMS part staging. This module does not issue origin signatures or
//! publish a snapshot: only the independent existing C export operation may
//! authenticate the final measured whole manifest. Failed preparations remain
//! inert; no directory absence, ciphertext or JSON is adopted as authority.
use crate::{artifacts, backup_crypto, Result};
use luma_content_store::v2::backup::{
    PartCommitment, SnapshotIntent, SnapshotPages, SnapshotPart, SnapshotReview, SnapshotSink,
    MAX_SNAPSHOT_EXPORT_BYTES,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
mod crypto;
pub(crate) mod receipt;
pub(crate) mod scope;
mod sharing;
#[cfg(test)]
mod tests;

/// Installed implementation must independently prove the fixed private stage
/// namespace, held mount/volume and original Export-purpose finite pair and
/// resource lease. No generic path or serialized success flag can implement it.
pub(crate) trait StageBoundary: backup_crypto::CryptoBoundary {
    fn current_snapshot_stage(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        directory: &File,
    ) -> Result<()>;
    fn admit_snapshot_output(
        &mut self,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        maximum_bytes: u64,
        maximum_files: u32,
    ) -> Result<()>;
}
pub(crate) struct CmsStage<'a, B: StageBoundary> {
    directory: File,
    _writer: File,
    intent: SnapshotIntent,
    review: SnapshotReview,
    recipients: &'a backup_crypto::Recipients,
    boundary: &'a mut B,
    maximum_bytes: u64,
    maximum_files: u32,
    written: u64,
    files: u32,
    next_part: u32,
}
struct StageCrypto<'a, B: StageBoundary> {
    boundary: &'a mut B,
    intent: &'a SnapshotIntent,
    review: &'a SnapshotReview,
    directory: &'a File,
}
impl<B: StageBoundary> backup_crypto::CryptoBoundary for StageCrypto<'_, B> {
    fn admit(
        &mut self,
        request: &backup_crypto::CryptoRequest,
        budget: backup_crypto::CryptoBudget,
    ) -> Result<()> {
        self.boundary
            .current_snapshot_stage(self.intent, self.review, self.directory)?;
        self.boundary.admit(request, budget)?;
        self.boundary
            .current_snapshot_stage(self.intent, self.review, self.directory)
    }
    fn check(&mut self, request: &backup_crypto::CryptoRequest) -> Result<()> {
        self.boundary
            .current_snapshot_stage(self.intent, self.review, self.directory)?;
        self.boundary.check(request)?;
        self.boundary
            .current_snapshot_stage(self.intent, self.review, self.directory)
    }
}
impl<'a, B: StageBoundary> CmsStage<'a, B> {
    /// Receives an already provisioned, independently pinned private stage.
    /// It never creates/adopts a stage from caller-supplied paths.
    pub(crate) fn new(
        directory: File,
        intent: &SnapshotIntent,
        review: &SnapshotReview,
        recipients: &'a backup_crypto::Recipients,
        boundary: &'a mut B,
        maximum_bytes: u64,
        maximum_files: u32,
    ) -> Result<Self> {
        intent.validate()?;
        review.validate(intent)?;
        artifacts::private_directory(&directory)?;
        if maximum_bytes == 0
            || maximum_bytes > MAX_SNAPSHOT_EXPORT_BYTES
            || maximum_files == 0
            || maximum_files > 135304
        {
            return Err("native snapshot stage exceeds finite output reservation".into());
        }
        boundary.current_snapshot_stage(intent, review, &directory)?;
        boundary.admit_snapshot_output(intent, review, maximum_bytes, maximum_files)?;
        let writer = artifacts::open_at(&directory, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        if unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        boundary.current_snapshot_stage(intent, review, &directory)?;
        Ok(Self {
            directory,
            _writer: writer,
            intent: intent.clone(),
            review: review.clone(),
            recipients,
            boundary,
            maximum_bytes,
            maximum_files,
            written: 0,
            files: 0,
            next_part: 0,
        })
    }
    fn check(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        check()?;
        artifacts::private_directory(&self.directory)?;
        self.boundary
            .current_snapshot_stage(&self.intent, &self.review, &self.directory)?;
        check()
    }
    fn read_exact(
        &mut self,
        name: &str,
        expected: &str,
        maximum: u64,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.check(check)?;
        let mut file = artifacts::open_at(&self.directory, name, libc::O_RDONLY, 0)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.mode() & 0o7777 != 0o400
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > maximum
        {
            return Err("unsafe bounded snapshot stage member".into());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
        let mut buffer = [0u8; 4096];
        loop {
            self.check(check)?;
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if bytes
                .len()
                .checked_add(n)
                .map_or(true, |size| size as u64 > before.len())
            {
                return Err("snapshot stage member grew".into());
            }
            bytes.extend_from_slice(&buffer[..n]);
        }
        self.check(check)?;
        let after = file.metadata()?;
        let named = artifacts::open_at(&self.directory, name, libc::O_RDONLY, 0)?.metadata()?;
        if pin(&before) != pin(&after)
            || pin(&after) != pin(&named)
            || bytes.len() as u64 != before.len()
            || luma_content::sha256(&bytes) != expected
        {
            return Err("snapshot stage held member changed or fails full readback".into());
        }
        self.check(check)?;
        Ok(bytes)
    }
    fn retain(
        &mut self,
        name: &str,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check(check)?;
        if bytes.is_empty() || luma_content::sha256(bytes) != sha {
            return Err("snapshot stage write commitment differs".into());
        }
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or("snapshot stage byte overflow")?;
        if next > self.maximum_bytes || self.files >= self.maximum_files {
            return Err("snapshot stage finite output reservation exhausted".into());
        }
        // Reserve before opening or writing. A failed/incomplete file is inert,
        // consumes this attempt, and is never automatically adopted/retried.
        self.written = next;
        self.files += 1;
        let mut file = artifacts::open_at(
            &self.directory,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o400,
        )?;
        for chunk in bytes.chunks(4096) {
            self.check(check)?;
            file.write_all(chunk)?;
            self.check(check)?;
        }
        file.sync_all()?;
        self.directory.sync_all()?;
        self.check(check)?;
        let held = file.metadata()?;
        let named = artifacts::open_at(&self.directory, name, libc::O_RDONLY, 0)?.metadata()?;
        if pin(&held) != pin(&named) {
            return Err("snapshot stage output inode was replaced".into());
        }
        if self.read_exact(name, sha, bytes.len() as u64, check)? != bytes {
            return Err("snapshot stage synchronized full readback differs".into());
        }
        self.check(check)
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn pin(m: &std::fs::Metadata) -> (u64, u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.blocks(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
impl<B: StageBoundary> SnapshotPages for CmsStage<'_, B> {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if !hash(sha) || bytes.len() > 16384 {
            return Err("invalid bounded snapshot directory page".into());
        }
        self.retain(&format!("page-{sha}"), sha, bytes, check)
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        if !hash(sha) {
            return Err("invalid snapshot page selector".into());
        }
        self.read_exact(&format!("page-{sha}"), sha, 16384, check)
    }
}
impl<B: StageBoundary> SnapshotSink for CmsStage<'_, B> {
    fn retain_part(
        &mut self,
        intent: &SnapshotIntent,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PartCommitment> {
        self.check(check)?;
        if intent != &self.intent {
            return Err("native CMS stage retargets snapshot intent".into());
        }
        let part = SnapshotPart::parse(bytes, intent, &mut || check())?;
        if part.header().number != self.next_part {
            return Err("native CMS stage part order/retry differs".into());
        }
        let maximum = bytes.len() as u64 + 65536;
        if self
            .written
            .checked_add(maximum)
            .map_or(true, |n| n > self.maximum_bytes)
            || self.files >= self.maximum_files
        {
            return Err("native CMS output not reserved before helper".into());
        }
        let encrypted = crypto::encrypt_part(
            bytes,
            intent,
            self.recipients,
            &mut StageCrypto {
                boundary: self.boundary,
                intent: &self.intent,
                review: &self.review,
                directory: &self.directory,
            },
            check,
        )?;
        self.check(check)?;
        let measured = encrypted.commitment();
        if measured.archive_sha256 != part.sha256()
            || measured.archive_bytes != bytes.len() as u64
            || measured.cms_bytes != encrypted.bytes().len() as u64
            || luma_content::sha256(encrypted.bytes()) != measured.cms_sha256
            || measured.authenticates_sender
            || measured.permits_restore
        {
            return Err("native CMS helper measured commitment differs".into());
        }
        let commitment = PartCommitment {
            number: self.next_part,
            plaintext_sha256: part.sha256().into(),
            plaintext_bytes: bytes.len() as u64,
            ciphertext_sha256: measured.cms_sha256.clone(),
            ciphertext_bytes: measured.cms_bytes,
            objects: part.header().objects.len() as u32,
            previous_plaintext_sha256: part.header().previous_plaintext_sha256.clone(),
        };
        commitment.validate()?;
        self.retain(
            &format!(
                "part-{:06}-{}.cms",
                self.next_part, commitment.ciphertext_sha256
            ),
            &commitment.ciphertext_sha256,
            encrypted.bytes(),
            check,
        )?;
        self.next_part = self
            .next_part
            .checked_add(1)
            .ok_or("native CMS part count overflow")?;
        self.check(check)?;
        Ok(commitment)
    }
}
