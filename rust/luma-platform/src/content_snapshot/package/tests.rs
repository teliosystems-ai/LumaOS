//! Inert framing and actual software Ed25519 tests, NOT native C signing, CMS,
//! installed grants/PAM, encrypted storage or restore-authorization evidence.
use super::*;
use crate::receipt_signer;
use luma_content_store::v2::backup::{SnapshotMode, SnapshotReview, SNAPSHOT_PROFILE};
use luma_content_store::v2::PhysicalInventory;
use serde::Serialize;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Cursor;

#[derive(Clone, Default)]
pub(super) struct Source {
    pages: BTreeMap<String, Vec<u8>>,
    cipher: Vec<u8>,
    manifest: Option<WholeSnapshotManifest>,
}
impl SnapshotPages for Source {
    fn put_page(&mut self, _: &str, _: &[u8], _: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        Err("fixture package source is readonly".into())
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        self.pages
            .get(sha)
            .cloned()
            .ok_or_else(|| "fixture page absent".into())
    }
}
impl PackageSource for Source {
    fn current_package_source(
        &mut self,
        manifest: &WholeSnapshotManifest,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if self.manifest.as_ref() != Some(manifest) {
            return Err("fixture source substituted".into());
        }
        check()
    }
    fn read_ciphertext(
        &mut self,
        _: &PartCommitment,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        Ok(self.cipher.clone())
    }
}
#[derive(Default)]
pub(super) struct Sink {
    pages: u32,
    parts: u32,
    cipher: Vec<u8>,
}
impl PackageSink for Sink {
    fn directory_page(
        &mut self,
        reference: &PartDirectoryRef,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        assert_eq!(artifacts::digest(bytes), reference.sha256);
        self.pages += 1;
        check()
    }
    fn ciphertext(
        &mut self,
        part: &PartCommitment,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        assert_eq!(artifacts::digest(bytes), part.ciphertext_sha256);
        self.parts += 1;
        self.cipher = bytes.to_vec();
        check()
    }
}
#[derive(Serialize)]
struct Page<'a> {
    schema_version: u32,
    profile: &'a str,
    intent_sha256: String,
    body: Leaf<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Leaf<'a> {
    Leaf { parts: &'a [PartCommitment] },
}
pub(super) fn fixture() -> (receipt::Header, Source, String) {
    let (seed, public) = receipt_signer::generate(|| Ok(())).unwrap();
    let pin = artifacts::digest(&public);
    let mut input = scope::tests::input();
    input.mode = SnapshotMode::Export;
    input.budget.output_bytes = MAX_SNAPSHOT_EXPORT_BYTES;
    input.intent.origin_spki_sha256 = pin.clone();
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: input.intent.sha256().unwrap(),
        inventory: PhysicalInventory {
            regular_files: 1,
            directories: 2,
            ..Default::default()
        },
        object_count: 0,
        object_bytes: 0,
        stream_sha256: "a".repeat(64),
        review_sha256: String::new(),
    };
    review.review_sha256 = artifacts::digest(&serde_json::to_vec(&review).unwrap());
    input.review = Some(review.clone());
    let cipher: Vec<u8> = (0..8192).map(|n| (n % 251) as u8).collect();
    let part = PartCommitment {
        number: 0,
        plaintext_sha256: artifacts::digest(b"inert plaintext DATA"),
        plaintext_bytes: 100,
        ciphertext_sha256: artifacts::digest(&cipher),
        ciphertext_bytes: cipher.len() as u64,
        objects: 0,
        previous_plaintext_sha256: None,
    };
    let page = serde_json::to_vec(&Page {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE,
        intent_sha256: input.intent.sha256().unwrap(),
        body: Leaf::Leaf {
            parts: &[part.clone()],
        },
    })
    .unwrap();
    let page_sha = artifacts::digest(&page);
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent: input.intent.clone(),
        review,
        parts: PartDirectoryRef {
            sha256: page_sha.clone(),
            first: 0,
            count: 1,
            height: 0,
            objects: 0,
            plaintext_bytes: part.plaintext_bytes,
            ciphertext_bytes: part.ciphertext_bytes,
        },
        part_count: 1,
        plaintext_bytes: part.plaintext_bytes,
        ciphertext_bytes: part.ciphertext_bytes,
        last_plaintext_sha256: part.plaintext_sha256.clone(),
    };
    let mut source = Source {
        pages: [(page_sha, page)].into_iter().collect(),
        cipher,
        manifest: Some(manifest.clone()),
    };
    let audit = Audit {
        subject: input.intent.head.binding.owner.clone(),
        subject_generation: input.intent.head.binding.owner_generation,
        grant_id: "export-fixture".into(),
        grant_version: 1,
        checkpoint_head: "b".repeat(64),
        operation_id: Some("c".repeat(32)),
        usage: scope::uses(
            &input.profile().unwrap(),
            "8:1",
            &input.intent.head.binding.installation,
        )
        .unwrap()[1]
            .clone(),
    };
    let body = plan_body_data(
        &input,
        &manifest,
        &mut source,
        "8:1",
        &crate::bundle::hex(&public),
        &"d".repeat(64),
        audit,
        &mut || Ok(()),
    )
    .unwrap();
    let signature = receipt_signer::sign(&seed, &body.message().unwrap(), || Ok(())).unwrap();
    let header = receipt::Header::new_data(
        &input,
        receipt::Receipt {
            body,
            signature_hex: crate::bundle::hex(&signature),
        },
    )
    .unwrap();
    (header, source, pin)
}
fn encoded() -> (Vec<u8>, receipt::Header, Source) {
    let (header, mut source, _) = fixture();
    let mut bytes = Vec::new();
    let summary = encode(&header, &mut source, &mut bytes, &mut || Ok(())).unwrap();
    assert_eq!(summary.sha256, artifacts::digest(&bytes));
    assert_eq!(summary.bytes, bytes.len() as u64);
    (bytes, header, source)
}
fn offsets(bytes: &[u8]) -> (usize, usize, usize) {
    let h = 20 + u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let p = h + 5 + u32::from_be_bytes(bytes[h + 1..h + 5].try_into().unwrap()) as usize;
    (h, p, p + 9)
}
struct Short<T>(T);
impl<T: Read> Read for Short<T> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let length = 1.min(out.len());
        self.0.read(&mut out[..length])
    }
}
impl<T: Write> Write for Short<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(&bytes[..1.min(bytes.len())])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
#[test]
fn exact_fixedpoint_actual_software_signature_and_short_io_roundtrip_are_data_only() {
    let (header, mut source, pin) = fixture();
    let mut bytes = Vec::new();
    let summary = encode(&header, &mut source, &mut Short(&mut bytes), &mut || Ok(())).unwrap();
    assert_eq!(
        header.receipt.body.measured_package_bytes(),
        bytes.len() as u64
    );
    let mut sink = Sink::default();
    let decoded = decode(&mut Short(Cursor::new(&bytes)), &mut sink, &mut || Ok(())).unwrap();
    assert_eq!(decoded.summary, summary);
    assert_eq!((sink.pages, sink.parts), (1, 1));
    assert_eq!(sink.cipher, source.cipher);
    assert_eq!(
        decoded.header.canonical_bytes().unwrap(),
        header.canonical_bytes().unwrap()
    );
    decoded
        .header
        .receipt
        .verify_origin(&pin, &mut || Ok(()))
        .unwrap();
    assert!(decoded
        .header
        .receipt
        .verify_origin(&"f".repeat(64), &mut || Ok(()))
        .is_err());
}
#[test]
fn truncation_at_every_frame_boundary_and_any_trailing_data_never_returns_complete() {
    let (bytes, _, _) = encoded();
    let (page, part, cipher) = offsets(&bytes);
    for cut in [
        0,
        1,
        15,
        16,
        19,
        20,
        page - 1,
        page,
        page + 4,
        part - 1,
        part,
        part + 8,
        cipher,
        cipher + 4095,
        bytes.len() - 49,
        bytes.len() - 1,
    ] {
        assert!(
            decode(
                &mut Cursor::new(&bytes[..cut]),
                &mut Sink::default(),
                &mut || Ok(())
            )
            .is_err(),
            "cut {cut}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(
        &mut Cursor::new(trailing),
        &mut Sink::default(),
        &mut || Ok(())
    )
    .is_err());
}
#[test]
fn wrong_frame_kinds_sizes_order_and_every_committed_digest_fail_closed() {
    let (bytes, _, _) = encoded();
    let (page, part, cipher) = offsets(&bytes);
    for at in [
        0,
        page,
        page + 5,
        part,
        part + 4,
        cipher + 4096,
        bytes.len() - 49,
        bytes.len() - 48,
        bytes.len() - 40,
        bytes.len() - 1,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(
            decode(&mut Cursor::new(bad), &mut Sink::default(), &mut || Ok(())).is_err(),
            "byte {at}"
        );
    }
    for at in [16, page + 1, part + 5] {
        let mut bad = bytes.clone();
        bad[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&mut Cursor::new(bad), &mut Sink::default(), &mut || Ok(())).is_err());
    }
    let mut duplicate = bytes[..part].to_vec();
    duplicate.extend_from_slice(&bytes[page..part]);
    duplicate.extend_from_slice(&bytes[part..]);
    assert!(decode(
        &mut Cursor::new(duplicate),
        &mut Sink::default(),
        &mut || Ok(())
    )
    .is_err());
}
#[test]
fn source_substitution_changed_cipher_and_signed_measurement_mismatch_cannot_finish() {
    let (header, source, _) = fixture();
    let mut bad = source.clone();
    bad.manifest.as_mut().unwrap().intent.snapshot_id = "f".repeat(64);
    let mut output = Vec::new();
    assert!(encode(&header, &mut bad, &mut output, &mut || Ok(())).is_err());
    assert!(output.is_empty());
    let mut bad = source;
    bad.cipher[0] ^= 1;
    assert!(encode(&header, &mut bad, &mut Vec::new(), &mut || Ok(())).is_err());
    let (bytes, header, mut source) = encoded();
    let mut value = serde_json::to_value(&header).unwrap();
    value["receipt"]["body"]["measured_package_bytes"] = serde_json::json!(bytes.len() as u64 + 1);
    // Parsed body data/signature is not independently trusted by this codec.
    // Even a structurally valid changed measurement cannot frame successfully.
    let bad: receipt::Header = serde_json::from_value(value).unwrap();
    assert!(encode(&bad, &mut source, &mut Vec::new(), &mut || Ok(())).is_err());
}
#[test]
fn mid_chunk_revocation_stops_read_and_write_without_completion_or_automatic_retry() {
    let (bytes, header, mut source) = encoded();
    let mut output = Vec::new();
    let progress = Cell::new(0);
    assert!(encode(
        &header,
        &mut source,
        &mut Observed {
            stream: &mut output,
            progress: &progress
        },
        &mut || {
            if progress.get() >= 4096 {
                Err("fixture original Export revoked".into())
            } else {
                Ok(())
            }
        }
    )
    .is_err());
    assert!(output.len() >= 4096);
    assert!(output.len() < bytes.len());
    let mut input = Cursor::new(&bytes);
    let progress = Cell::new(0);
    assert!(decode(
        &mut Observed {
            stream: &mut input,
            progress: &progress
        },
        &mut Sink::default(),
        &mut || {
            if progress.get() >= 4096 {
                Err("fixture original import Read revoked".into())
            } else {
                Ok(())
            }
        }
    )
    .is_err());
    assert!(input.position() >= 4096);
    assert!(input.position() < bytes.len() as u64);
}
struct Observed<'a, T> {
    stream: T,
    progress: &'a Cell<usize>,
}
impl<T: Read> Read for Observed<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.stream.read(bytes)?;
        self.progress.set(self.progress.get() + count);
        Ok(count)
    }
}
impl<T: Write> Write for Observed<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self.stream.write(bytes)?;
        self.progress.set(self.progress.get() + count);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
struct NoProgress;
impl Write for NoProgress {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Ok(0)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Interrupted<T> {
    stream: T,
    once: bool,
}
impl<T: Read> Read for Interrupted<T> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.once {
            self.once = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.stream.read(out)
    }
}
impl<T: Write> Write for Interrupted<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.once {
            self.once = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
#[test]
fn io_no_progress_errors_and_interruption_are_never_mistaken_for_completion() {
    let (header, mut source, _) = fixture();
    assert!(encode(&header, &mut source, &mut NoProgress, &mut || Ok(())).is_err());
    let mut bytes = Vec::new();
    encode(
        &header,
        &mut source,
        &mut Interrupted {
            stream: &mut bytes,
            once: false,
        },
        &mut || Ok(()),
    )
    .unwrap();
    decode(
        &mut Interrupted {
            stream: Cursor::new(&bytes),
            once: false,
        },
        &mut Sink::default(),
        &mut || Ok(()),
    )
    .unwrap();
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::Other.into())
        }
    }
    assert!(decode(&mut Broken, &mut Sink::default(), &mut || Ok(())).is_err());
}
#[test]
fn noncanonical_and_oversized_header_or_unbounded_part_claims_refuse_before_allocation() {
    let (bytes, _, _) = encoded();
    let (page, _, _) = offsets(&bytes);
    let mut padded = bytes[..page].to_vec();
    padded.push(b' ');
    padded[16..20].copy_from_slice(&((page - 19) as u32).to_be_bytes());
    padded.extend_from_slice(&bytes[page..]);
    assert!(
        decode(&mut Cursor::new(padded), &mut Sink::default(), &mut || Ok(
            ()
        ))
        .is_err()
    );
    let mut oversized = MAGIC.to_vec();
    oversized.extend((MAX_SNAPSHOT_HEADER_BYTES as u32 + 1).to_be_bytes());
    let mut input = Cursor::new(oversized);
    assert!(decode(&mut input, &mut Sink::default(), &mut || Ok(())).is_err());
    assert_eq!(input.position(), 20);
}
