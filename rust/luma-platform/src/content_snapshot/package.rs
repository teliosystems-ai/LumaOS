//! Path-free streaming framing of inert encrypted whole-snapshot DATA. Parsing
//! and a complete trailer are not signature trust, C selection or restore
//! authorization. Retained partial outputs remain inert after every error.
//! Checks bracket each bounded I/O call; arbitrary Read/Write may still block
//! inside that call. Installed delivery must supply its existing acknowledged
//! relay or bounded nonblocking/deadline transport with live checks on stalls.
use super::{receipt, scope, CmsStage, StageBoundary};
use crate::{artifacts, finite_grants::Audit, Result};
use luma_content_store::v2::backup::{
    PartCommitment, PartDirectoryRef, SnapshotDirectoryEntry, SnapshotPages, WholeSnapshotManifest,
    MAX_SNAPSHOT_DIRECTORY_PAGES, MAX_SNAPSHOT_EXPORT_BYTES, MAX_SNAPSHOT_HEADER_BYTES,
    MAX_SNAPSHOT_PART_BYTES, SNAPSHOT_PACKAGE_PAGE_FRAME_BYTES, SNAPSHOT_PACKAGE_PART_FRAME_BYTES,
    SNAPSHOT_PACKAGE_PREFIX_BYTES, SNAPSHOT_PACKAGE_TRAILER_BYTES,
};
use std::cell::RefCell;
use std::io::{Read, Write};
mod delivery;
mod io;
#[cfg(test)]
mod tests;
const MAGIC: &[u8; 16] = b"LUMAV2PACKAGE1\n\0";
const PAGE: u8 = 1;
const PART: u8 = 2;
const END: u8 = 255;

/// The source supplies actual retained ciphertext, not a receipt claiming it
/// exists. Its concrete implementation retains the caller's original boundary.
pub(super) trait PackageSource: SnapshotPages {
    fn current_package_source(
        &mut self,
        manifest: &WholeSnapshotManifest,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn read_ciphertext(
        &mut self,
        part: &PartCommitment,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>>;
}
impl<B: StageBoundary> PackageSource for CmsStage<'_, B> {
    fn current_package_source(
        &mut self,
        manifest: &WholeSnapshotManifest,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check(check)?;
        if self.intent != manifest.intent
            || self.review != manifest.review
            || self.next_part != manifest.part_count
        {
            return Err("held CMS source differs from complete measured package".into());
        }
        self.check(check)
    }
    fn read_ciphertext(
        &mut self,
        part: &PartCommitment,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        part.validate()?;
        if part.number >= self.next_part {
            return Err("CMS package part not retained".into());
        }
        self.read_exact(
            &format!("part-{:06}-{}.cms", part.number, part.ciphertext_sha256),
            &part.ciphertext_sha256,
            part.ciphertext_bytes,
            check,
        )
    }
}
/// No paths or extraction API. Implementations must govern any retention and
/// treat these bytes as inert until independent whole-origin verification and
/// fresh native import authorization. No default success implementation exists.
pub(super) trait PackageSink {
    fn directory_page(
        &mut self,
        reference: &PartDirectoryRef,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn ciphertext(
        &mut self,
        part: &PartCommitment,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Summary {
    pub(super) bytes: u64,
    pub(super) pages: u32,
    pub(super) parts: u32,
    pub(super) sha256: String,
}
pub(super) struct Decoded {
    pub(super) header: receipt::Header,
    pub(super) summary: Summary,
}
#[derive(Default)]
struct Layout {
    pages: u32,
    parts: u32,
    payload: u64,
}
impl Layout {
    fn entry(&mut self, entry: SnapshotDirectoryEntry<'_>) -> Result<()> {
        let length = match entry {
            SnapshotDirectoryEntry::Page { bytes, .. } => {
                self.pages = self
                    .pages
                    .checked_add(1)
                    .ok_or("package page count overflow")?;
                bytes.len() as u64 + SNAPSHOT_PACKAGE_PAGE_FRAME_BYTES
            }
            SnapshotDirectoryEntry::Part(part) => {
                self.parts = self
                    .parts
                    .checked_add(1)
                    .ok_or("package part count overflow")?;
                part.ciphertext_bytes + SNAPSHOT_PACKAGE_PART_FRAME_BYTES
            }
        };
        self.payload = self
            .payload
            .checked_add(length)
            .ok_or("package payload overflow")?;
        if self.pages > MAX_SNAPSHOT_DIRECTORY_PAGES || self.payload > MAX_SNAPSHOT_EXPORT_BYTES {
            return Err("package frame inventory exceeds finite profile".into());
        }
        Ok(())
    }
    fn total(&self, header: usize) -> Result<u64> {
        self.payload
            .checked_add(header as u64)
            .and_then(|n| {
                n.checked_add(SNAPSHOT_PACKAGE_PREFIX_BYTES + SNAPSHOT_PACKAGE_TRAILER_BYTES)
            })
            .filter(|n| *n <= MAX_SNAPSHOT_EXPORT_BYTES)
            .ok_or_else(|| "whole package framed size exceeds finite profile".into())
    }
}
/// Plans exact size only. The returned UNSIGNED attribution DATA may be signed
/// only after actual C independently measures the held ciphertext/directory and
/// publishes the corresponding event. No signature is synthesized or returned.
pub(super) fn plan_body_data(
    input: &scope::Input,
    manifest: &WholeSnapshotManifest,
    pages: &mut impl SnapshotPages,
    storage: &str,
    origin: &str,
    checkpoint: &str,
    audit: Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<receipt::Body> {
    check()?;
    input.validate()?;
    let mut layout = Layout::default();
    manifest.visit_directory(pages, check, &mut |entry, check| {
        check()?;
        layout.entry(entry)
    })?;
    let mut measured = manifest
        .ciphertext_bytes
        .checked_add(1)
        .ok_or("package size overflow")?;
    for _ in 0..20 {
        check()?;
        let body = receipt::Body::new_data(
            input,
            manifest.clone(),
            measured,
            storage,
            origin,
            checkpoint,
            audit.clone(),
        )?;
        let total = layout.total(receipt::Header::unsigned_encoded_length_data(input, &body)?)?;
        if total == measured {
            check()?;
            return Ok(body);
        }
        measured = total;
    }
    Err("whole package encoded-length fixed point did not converge".into())
}
struct HeldPages<'s, 'b, S> {
    source: &'s RefCell<&'b mut S>,
}
impl<S: SnapshotPages> SnapshotPages for HeldPages<'_, '_, S> {
    fn put_page(&mut self, _: &str, _: &[u8], _: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        Err("package measurement is read-only".into())
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        self.source
            .try_borrow_mut()
            .map_err(|_| "reentrant package source")?
            .read_page(sha, check)
    }
}
pub(super) fn encode(
    header: &receipt::Header,
    source: &mut impl PackageSource,
    output: &mut impl Write,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Summary> {
    let out = io::Output::new(output, header.receipt.body.measured_package_bytes());
    encode_output(header, source, out, check)
}
fn encode_output(
    header: &receipt::Header,
    source: &mut impl PackageSource,
    mut out: impl io::FramedOutput,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Summary> {
    check()?;
    let header_bytes = header.canonical_bytes()?;
    let manifest = header.receipt.body.manifest();
    let measured = header.receipt.body.measured_package_bytes();
    source.current_package_source(manifest, check)?;
    let source = RefCell::new(source);
    let mut pages = HeldPages { source: &source };
    out.exact(MAGIC, check)?;
    out.exact(&(header_bytes.len() as u32).to_be_bytes(), check)?;
    out.exact(&header_bytes, check)?;
    let mut layout = Layout::default();
    manifest.visit_directory(&mut pages, check, &mut |entry, check| {
        layout.entry(entry)?;
        match entry {
            SnapshotDirectoryEntry::Page { bytes, .. } => {
                out.exact(&[PAGE], check)?;
                out.exact(&(bytes.len() as u32).to_be_bytes(), check)?;
                out.exact(bytes, check)?;
            }
            SnapshotDirectoryEntry::Part(part) => {
                let bytes = source
                    .try_borrow_mut()
                    .map_err(|_| "reentrant package ciphertext")?
                    .read_ciphertext(part, check)?;
                if bytes.len() as u64 != part.ciphertext_bytes
                    || artifacts::digest(&bytes) != part.ciphertext_sha256
                {
                    return Err("actual package ciphertext differs from measured commitment".into());
                }
                out.exact(&[PART], check)?;
                out.exact(&part.number.to_be_bytes(), check)?;
                out.exact(&(bytes.len() as u32).to_be_bytes(), check)?;
                out.exact(&bytes, check)?;
            }
        }
        check()
    })?;
    if layout.total(header_bytes.len())? != measured {
        return Err("signed package byte measurement differs".into());
    }
    source
        .try_borrow_mut()
        .map_err(|_| "reentrant final package source")?
        .current_package_source(manifest, check)?;
    let trailer = trailer(layout.pages, layout.parts, out.bytes(), out.digest());
    out.exact(&trailer, check)?;
    if out.bytes() != measured {
        return Err("complete package length differs from signed measurement".into());
    }
    out.flush(check)?;
    check()?;
    Ok(Summary {
        bytes: out.bytes(),
        pages: layout.pages,
        parts: layout.parts,
        sha256: crate::bundle::hex(&out.digest()),
    })
}
fn trailer(pages: u32, parts: u32, bytes: u64, sha: [u8; 32]) -> Vec<u8> {
    let mut result = vec![END];
    result.extend(pages.to_be_bytes());
    result.extend(parts.to_be_bytes());
    result.extend(bytes.to_be_bytes());
    result.extend(sha);
    result
}
struct FramedPages<'a, R> {
    input: &'a RefCell<io::Input<R>>,
}
impl<R: Read> SnapshotPages for FramedPages<'_, R> {
    fn put_page(&mut self, _: &str, _: &[u8], _: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        Err("package parser cannot create directory pages".into())
    }
    fn read_page(&mut self, _: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        let mut input = self
            .input
            .try_borrow_mut()
            .map_err(|_| "reentrant package input")?;
        if input.exact(1, check)? != [PAGE] {
            return Err("package expected next canonical directory page".into());
        }
        let length = u32::from_be_bytes(
            input
                .exact(4, check)?
                .try_into()
                .map_err(|_| "package page length word invalid")?,
        ) as usize;
        if length == 0 || length > 16384 {
            return Err("package directory page length invalid".into());
        }
        input.exact(length, check)
    }
}
pub(super) fn decode(
    input: &mut impl Read,
    sink: &mut impl PackageSink,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Decoded> {
    let mut input = io::Input::new(input, MAX_SNAPSHOT_EXPORT_BYTES);
    if input.exact(16, check)? != MAGIC {
        return Err("unknown whole snapshot package magic".into());
    }
    let length = u32::from_be_bytes(
        input
            .exact(4, check)?
            .try_into()
            .map_err(|_| "package header length word invalid")?,
    ) as usize;
    if length == 0 || length > MAX_SNAPSHOT_HEADER_BYTES {
        return Err("package header length invalid".into());
    }
    let header = receipt::Header::from_canonical(&input.exact(length, check)?)?;
    let measured = header.receipt.body.measured_package_bytes();
    if measured < input.bytes {
        return Err("signed package length shorter than header".into());
    }
    input.maximum = measured;
    let input = RefCell::new(input);
    let mut pages = FramedPages { input: &input };
    let mut layout = Layout::default();
    header
        .receipt
        .body
        .manifest()
        .visit_directory(&mut pages, check, &mut |entry, check| {
            layout.entry(entry)?;
            match entry {
                SnapshotDirectoryEntry::Page { reference, bytes } => {
                    sink.directory_page(reference, bytes, check)?
                }
                SnapshotDirectoryEntry::Part(part) => {
                    let bytes = {
                        let mut input = input
                            .try_borrow_mut()
                            .map_err(|_| "reentrant package part")?;
                        if input.exact(1, check)? != [PART]
                            || u32::from_be_bytes(
                                input
                                    .exact(4, check)?
                                    .try_into()
                                    .map_err(|_| "package part number word invalid")?,
                            ) != part.number
                        {
                            return Err("package ciphertext reordered or wrong frame kind".into());
                        }
                        let size = u32::from_be_bytes(
                            input
                                .exact(4, check)?
                                .try_into()
                                .map_err(|_| "package ciphertext length word invalid")?,
                        ) as usize;
                        if size as u64 != part.ciphertext_bytes
                            || size > MAX_SNAPSHOT_PART_BYTES + 65536
                        {
                            return Err(
                                "package ciphertext frame exceeds committed bounded size".into()
                            );
                        }
                        input.exact(size, check)?
                    };
                    if artifacts::digest(&bytes) != part.ciphertext_sha256 {
                        return Err("package ciphertext full digest differs".into());
                    }
                    check()?;
                    sink.ciphertext(part, &bytes, check)?;
                }
            }
            check()
        })?;
    if layout.total(length)? != measured {
        return Err("package signed size loses exact frame coverage".into());
    }
    let mut input = input.into_inner();
    let expected = trailer(layout.pages, layout.parts, input.bytes, input.digest());
    if input.exact(SNAPSHOT_PACKAGE_TRAILER_BYTES as usize, check)? != expected {
        return Err("whole package trailer counts, length or full prefix digest differs".into());
    }
    if input.bytes != measured {
        return Err("whole package final measured size differs".into());
    }
    input.eof(check)?;
    check()?;
    let summary = Summary {
        bytes: input.bytes,
        pages: layout.pages,
        parts: layout.parts,
        sha256: crate::bundle::hex(&input.digest()),
    };
    Ok(Decoded { header, summary })
}
