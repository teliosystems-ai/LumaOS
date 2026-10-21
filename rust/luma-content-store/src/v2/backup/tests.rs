//! Actual private-store/framing tests with explicit disposable authority and a
//! NON-CRYPTOGRAPHIC sink. These tests do not qualify CMS, PAM, C or native jobs.
use super::super::head::{HistoryCursor, OwnerRoots, PhysicalAccounting};
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("snapshot tests require disposable private ext4");
        let path = Path::new(&base).join(format!(
            "snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn object(&self, sha: &str) -> PathBuf {
        self.path
            .join(ObjectStore::name(&binding()).unwrap())
            .join("objects")
            .join(&sha[..2])
            .join(&sha[2..4])
            .join(sha)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 7,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "c".repeat(64),
        decision: DecisionKind::Published,
        source_bytes: 1024,
    }
}
fn io(write: bool) -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: if write { 64 * 1024 * 1024 } else { 0 },
        new_files: if write { 32768 } else { 0 },
    }
}
fn head() -> OwnerHeadV2 {
    OwnerHeadV2 {
        schema_version: 2,
        domain: DOMAIN.into(),
        binding: binding(),
        history: HistoryCursor {
            outcomes: 0,
            segments: 0,
            last_segment: None,
        },
        roots: OwnerRoots::empty(&binding()).unwrap(),
        migration: None,
        physical: PhysicalAccounting::from_observation(PhysicalInventory::default()).unwrap(),
    }
}
struct Guard {
    head: OwnerHeadV2,
    write: bool,
    checks: u64,
    deny_at: Option<u64>,
    mode: Option<SnapshotMode>,
    review: Option<String>,
    closure_checks: u64,
}
impl Guard {
    fn new(head: &OwnerHeadV2, write: bool) -> Self {
        Self {
            head: head.clone(),
            write,
            checks: 0,
            deny_at: None,
            mode: None,
            review: None,
            closure_checks: 0,
        }
    }
}
impl Boundary for Guard {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if binding != &self.head.binding
            || budget.memory_bytes > 192 * 1024 * 1024
            || budget.tasks != 1
            || (!self.write && budget.write_bytes != 0)
        {
            return Err("fixture exact resource admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if self.deny_at.is_some_and(|n| self.checks >= n) {
            return Err("fixture live authority revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.head.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if self.write && binding == &self.head.binding && review_sha256 == "c".repeat(64) => {
                Ok(())
            }
            _ => Err("fixture independent effect refused".into()),
        }
    }
}
impl OwnerBoundary for Guard {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if head != &self.head {
            return Err("fixture independently selected head changed".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.head.physical.observed.clone())
    }
    fn verify_prepared_allocations(&mut self, _: &super::super::AppendCommitment) -> Result<()> {
        Err("snapshot read fixture never authorizes owner publication".into())
    }
}
impl SnapshotBoundary for Guard {
    fn admit_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        budget: SnapshotBudget,
    ) -> Result<()> {
        budget.validate(mode)?;
        self.current_owner_head(&intent.head)?;
        self.mode = Some(mode);
        Ok(())
    }
    fn check_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        review: Option<&str>,
    ) -> Result<()> {
        self.current_owner_head(&intent.head)?;
        if self.mode != Some(mode)
            || (mode == SnapshotMode::Review && review.is_some())
            || (mode == SnapshotMode::Export && review != self.review.as_deref())
        {
            return Err("fixture original Export pair/review differs".into());
        }
        Ok(())
    }
    fn verify_snapshot_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.current_owner_head(head)?;
        head.validate()?;
        // This fixture's entire selected semantic corpus is genuinely empty.
        // Raw immutable objects are unselected forensic DATA, never artifacts.
        if head
            .roots
            .all()
            .iter()
            .any(|root| root.entry_count != 0 || root.page.is_some())
        {
            return Err("empty-head fixture refuses an unverified nonempty semantic graph".into());
        }
        self.closure_checks += 1;
        Ok(())
    }
}
fn budget(export: bool) -> SnapshotBudget {
    SnapshotBudget {
        read_bytes: 1024 * 1024 * 1024,
        output_bytes: if export { MAX_SNAPSHOT_EXPORT_BYTES } else { 0 },
        maximum_objects: MAX_SNAPSHOT_OBJECTS,
        maximum_parts: MAX_SNAPSHOT_PARTS,
    }
}
fn intent(head: &OwnerHeadV2) -> SnapshotIntent {
    SnapshotIntent {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        snapshot_id: "1".repeat(64),
        head: head.clone(),
        head_sha256: head.sha256().unwrap(),
        recipient_generation: 3,
        recipients_sha256: "2".repeat(64),
        origin_spki_sha256: "3".repeat(64),
    }
}
fn setup(count: usize) -> (Fixture, ObjectStore, OwnerHeadV2) {
    let fixture = Fixture::new();
    let mut selected = head();
    let store = ObjectStore::create_at(
        &fixture.path,
        &binding(),
        io(true),
        &mutation(),
        &mut Guard::new(&selected, true),
    )
    .unwrap();
    for n in 0..count {
        let mut bytes = vec![255; MAX_PAGE_BYTES];
        bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
        store
            .prepare_page(
                &bytes,
                io(true),
                &mutation(),
                &mut Guard::new(&selected, true),
            )
            .unwrap();
    }
    let observed = store
        .inventory(io(false), &mut Guard::new(&selected, false), |_| Ok(()))
        .unwrap();
    selected.physical = PhysicalAccounting::from_observation(observed).unwrap();
    (fixture, store, selected)
}
#[derive(Default)]
struct UntrustedFixtureSink {
    pages: BTreeMap<String, Vec<u8>>,
    plaintext: BTreeMap<u32, Vec<u8>>,
    ciphertext: BTreeMap<u32, Vec<u8>>,
    refuse_part: Option<u32>,
}
impl SnapshotPages for UntrustedFixtureSink {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if luma_content::sha256(bytes) != sha || bytes.len() > MAX_PAGE_BYTES {
            return Err("fixture page commitment differs".into());
        }
        if let Some(existing) = self.pages.get(sha) {
            if existing != bytes {
                return Err("fixture immutable page differs".into());
            }
        }
        self.pages.insert(sha.into(), bytes.to_vec());
        check()
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        let value = self.pages.get(sha).cloned().ok_or("fixture page missing")?;
        check()?;
        Ok(value)
    }
}
impl SnapshotSink for UntrustedFixtureSink {
    fn retain_part(
        &mut self,
        intent: &SnapshotIntent,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PartCommitment> {
        let part = SnapshotPart::parse(bytes, intent, &mut || check())?;
        let header = part.header();
        if self.refuse_part == Some(header.number) {
            return Err("fixture part writer refused".into());
        }
        // A reversible test envelope is deliberately NOT called encryption/CMS.
        let mut cipher = b"UNTRUSTED-DATA-FIXTURE\n".to_vec();
        cipher.extend(bytes.iter().rev());
        self.plaintext.insert(header.number, bytes.to_vec());
        self.ciphertext.insert(header.number, cipher.clone());
        check()?;
        Ok(PartCommitment {
            number: header.number,
            plaintext_sha256: part.sha256().into(),
            plaintext_bytes: bytes.len() as u64,
            ciphertext_sha256: luma_content::sha256(&cipher),
            ciphertext_bytes: cipher.len() as u64,
            objects: header.objects.len() as u32,
            previous_plaintext_sha256: header.previous_plaintext_sha256.clone(),
        })
    }
}
fn exported(
    store: &ObjectStore,
    head: &OwnerHeadV2,
) -> (WholeSnapshotManifest, UntrustedFixtureSink) {
    let intent = intent(head);
    let mut guard = Guard::new(head, false);
    let review = review_snapshot(store, &intent, budget(false), &mut guard).unwrap();
    guard.review = Some(review.review_sha256.clone());
    let mut sink = UntrustedFixtureSink::default();
    let manifest =
        export_snapshot(store, &intent, &review, budget(true), &mut guard, &mut sink).unwrap();
    assert_eq!(guard.closure_checks, 4);
    (manifest, sink)
}

#[test]
fn actual_private_scanner_windows_are_canonical_and_complete_only_after_final_audit() {
    let (_fixture, store, head) = setup(35);
    let mut guard = Guard::new(&head, false);
    let mut scan = store.begin_raw_snapshot(io(false), &mut guard).unwrap();
    assert!(scan.completed_inventory().is_err());
    let mut names = Vec::new();
    let mut iterations = 0;
    loop {
        let result = scan
            .next_window(io(false), 3, &mut guard, |name, allocation, bytes, _| {
                assert_eq!(allocation.bytes, bytes.len() as u64);
                assert_eq!(luma_content::sha256(bytes), name);
                names.push(name.to_owned());
                Ok(())
            })
            .unwrap();
        iterations += 1;
        assert!(result.visited <= 3);
        if result.completed {
            break;
        }
    }
    assert_eq!(names.len(), 35);
    assert_eq!(iterations, 12);
    assert!(names.windows(2).all(|p| p[0] < p[1]));
    assert_eq!(scan.completed_inventory().unwrap(), &head.physical.observed);
    assert!(scan
        .next_window(io(false), 1, &mut guard, |_, _, _, _| Ok(()))
        .is_err());
}
#[test]
fn review_export_binary_parts_verify_exact_whole_directory_without_json_byte_expansion() {
    let (_fixture, store, head) = setup(65);
    let (manifest, mut sink) = exported(&store, &head);
    assert_eq!(manifest.part_count, 3);
    assert_eq!(manifest.review.object_count, 65);
    assert_eq!(manifest.review.object_bytes, 65 * MAX_PAGE_BYTES as u64);
    manifest
        .verify_directory(&mut sink, &mut || Ok(()))
        .unwrap();
    for number in 0..manifest.part_count {
        let commitment = manifest.part_at(number, &mut sink, &mut || Ok(())).unwrap();
        let bytes = &sink.plaintext[&number];
        let part = SnapshotPart::parse(bytes, &manifest.intent, &mut || Ok(())).unwrap();
        assert_eq!(part.header().number, number);
        assert_eq!(part.sha256(), commitment.plaintext_sha256);
        assert!(bytes.len() <= MAX_CANONICAL_PART_BYTES);
    }
    assert!(sink.plaintext[&0].len() < MAX_SNAPSHOT_PART_BYTES);
    assert!(sink.plaintext[&0].len() > 32 * MAX_PAGE_BYTES);
}
#[test]
fn empty_owner_has_one_real_bounded_part_not_a_skipped_backup() {
    let (_fixture, store, head) = setup(0);
    let (manifest, mut sink) = exported(&store, &head);
    assert_eq!(manifest.part_count, 1);
    assert_eq!(manifest.review.object_count, 0);
    assert_eq!(sink.plaintext.len(), 1);
    manifest
        .verify_directory(&mut sink, &mut || Ok(()))
        .unwrap();
    assert!(manifest.part_at(1, &mut sink, &mut || Ok(())).is_err());
}
#[test]
fn mutation_after_review_and_wrong_original_review_never_return_whole_manifest() {
    let (_fixture, store, head) = setup(1);
    let intent = intent(&head);
    let mut guard = Guard::new(&head, false);
    let review = review_snapshot(&store, &intent, budget(false), &mut guard).unwrap();
    guard.review = Some("f".repeat(64));
    assert!(export_snapshot(
        &store,
        &intent,
        &review,
        budget(true),
        &mut guard,
        &mut UntrustedFixtureSink::default()
    )
    .is_err());
    guard.review = Some(review.review_sha256.clone());
    store
        .prepare_page(
            b"new unselected forensic DATA",
            io(true),
            &mutation(),
            &mut Guard::new(&head, true),
        )
        .unwrap();
    assert!(export_snapshot(
        &store,
        &intent,
        &review,
        budget(true),
        &mut guard,
        &mut UntrustedFixtureSink::default()
    )
    .is_err());
}
#[test]
fn changed_captured_inode_metadata_or_bytes_poison_the_actual_scan() {
    let (fixture, store, head) = setup(2);
    let mut guard = Guard::new(&head, false);
    let mut scan = store.begin_raw_snapshot(io(false), &mut guard).unwrap();
    assert!(scan
        .next_window(io(false), 1, &mut guard, |name, _, bytes, _| {
            let mut changed = bytes.to_vec();
            changed[10] ^= 1;
            fs::write(fixture.object(name), changed)?;
            Ok(())
        })
        .is_err());
    assert!(scan.completed_inventory().is_err());
    assert!(scan
        .next_window(io(false), 1, &mut guard, |_, _, _, _| Ok(()))
        .is_err());
}
#[test]
fn incomplete_raw_objects_are_retained_labeled_and_never_promoted() {
    let (fixture, store, head) = setup(1);
    let mut name = None;
    store
        .inventory(io(false), &mut Guard::new(&head, false), |allocation| {
            name = allocation
                .relative_path
                .rsplit('/')
                .next()
                .map(str::to_owned);
            Ok(())
        })
        .unwrap();
    fs::write(
        fixture.object(name.as_deref().unwrap()),
        b"damaged retained evidence",
    )
    .unwrap();
    let (manifest, sink) = exported(&store, &head);
    assert_eq!(manifest.review.inventory.incomplete_objects, 1);
    let part = SnapshotPart::parse(&sink.plaintext[&0], &manifest.intent, &mut || Ok(())).unwrap();
    assert!(!part.header().objects[0].complete);
    assert_ne!(
        part.header().objects[0].object_sha256,
        part.header().objects[0].actual_sha256
    );
}
#[test]
fn missing_corrupt_directory_and_truncated_or_trailing_part_refuse() {
    let (_fixture, store, head) = setup(33);
    let (manifest, mut sink) = exported(&store, &head);
    let root = sink.pages.get_mut(&manifest.parts.sha256).unwrap();
    root[0] ^= 1;
    assert!(manifest
        .verify_directory(&mut sink, &mut || Ok(()))
        .is_err());
    sink.pages.clear();
    assert!(manifest.part_at(0, &mut sink, &mut || Ok(())).is_err());
    let original = &sink.plaintext[&0];
    for bytes in [original[..original.len() - 1].to_vec(), {
        let mut b = original.clone();
        b.push(0);
        b
    }] {
        assert!(SnapshotPart::parse(&bytes, &manifest.intent, &mut || Ok(())).is_err());
    }
}
#[test]
fn finite_budget_revocation_and_writer_failure_cannot_synthesize_completion() {
    let (_fixture, store, head) = setup(2);
    let intent = intent(&head);
    let mut guard = Guard::new(&head, false);
    let mut small = budget(false);
    small.maximum_objects = 1;
    assert!(review_snapshot(&store, &intent, small, &mut guard).is_err());
    guard = Guard::new(&head, false);
    guard.deny_at = Some(10);
    assert!(review_snapshot(&store, &intent, budget(false), &mut guard).is_err());
    guard = Guard::new(&head, false);
    let review = review_snapshot(&store, &intent, budget(false), &mut guard).unwrap();
    guard.review = Some(review.review_sha256.clone());
    let mut sink = UntrustedFixtureSink {
        refuse_part: Some(0),
        ..Default::default()
    };
    assert!(export_snapshot(
        &store,
        &intent,
        &review,
        budget(true),
        &mut guard,
        &mut sink
    )
    .is_err());
    let mut tiny = budget(true);
    tiny.output_bytes = MAX_SNAPSHOT_PACKAGE_OVERHEAD + 1;
    let mut sink = UntrustedFixtureSink::default();
    assert!(export_snapshot(&store, &intent, &review, tiny, &mut guard, &mut sink).is_err());
    assert!(sink.plaintext.is_empty());
}
#[test]
fn maximum_typed_nine_root_intent_review_and_whole_manifest_fit_bounded_metadata() {
    let mut head = head();
    head.binding.owner_generation = u64::MAX;
    head.roots = OwnerRoots::empty(&head.binding).unwrap();
    for root in [
        &mut head.roots.artifacts,
        &mut head.roots.history,
        &mut head.roots.requests,
        &mut head.roots.collections,
        &mut head.roots.lifecycle,
        &mut head.roots.segments,
        &mut head.roots.pending,
        &mut head.roots.retained,
        &mut head.roots.corpus,
    ] {
        let count = if root.kind == MapKind::Segments {
            MAX_SEGMENTS
        } else {
            MAX_MAP_ENTRIES
        };
        root.entry_count = count;
        root.page = Some(PageRef {
            sha256: "f".repeat(64),
            first_key: "1".repeat(64),
            last_key: "f".repeat(64),
            entry_count: count,
            height: 8,
        });
    }
    head.history = HistoryCursor {
        outcomes: MAX_MAP_ENTRIES,
        segments: MAX_SEGMENTS,
        last_segment: Some(BlobReference {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: head.binding.clone(),
            sha256: "4".repeat(64),
            bytes: 8192,
            chunk_count: 1,
            index_sha256: Some("5".repeat(64)),
        }),
    };
    let legacy = crate::VerifiedState {
        binding: head.binding.clone(),
        outcome_count: 256,
        head_sha256: "6".repeat(64),
        quarantine_sha256: "7".repeat(64),
    };
    head.migration = Some(super::super::head::MigrationProvenance {
        legacy,
        legacy_identity_sha256: "8".repeat(64),
        retained_inventory_sha256: "9".repeat(64),
    });
    let inventory = PhysicalInventory {
        regular_files: MAX_SNAPSHOT_OBJECTS + 1,
        directories: 65794,
        logical_bytes: MAX_SNAPSHOT_RAW_BYTES + MAX_PAGE_BYTES as u64,
        allocated_bytes: u64::MAX,
        incomplete_objects: MAX_SNAPSHOT_OBJECTS,
    };
    head.physical = PhysicalAccounting::from_observation(inventory.clone()).unwrap();
    head.validate().unwrap();
    let intent = intent(&head);
    assert!(intent.canonical_bytes().unwrap().len() <= MAX_PAGE_BYTES);
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        inventory,
        object_count: MAX_SNAPSHOT_OBJECTS,
        object_bytes: MAX_SNAPSHOT_RAW_BYTES,
        stream_sha256: "a".repeat(64),
        review_sha256: String::new(),
    };
    review.finish(&intent).unwrap();
    let plaintext =
        MAX_SNAPSHOT_RAW_BYTES + u64::from(MAX_SNAPSHOT_PARTS) * (MAX_PAGE_BYTES as u64 + 20);
    let parts = PartDirectoryRef {
        sha256: "b".repeat(64),
        first: 0,
        count: MAX_SNAPSHOT_PARTS,
        height: 3,
        objects: MAX_SNAPSHOT_OBJECTS,
        plaintext_bytes: plaintext,
        ciphertext_bytes: MAX_SNAPSHOT_CIPHERTEXT_BYTES,
    };
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent,
        review,
        parts,
        part_count: MAX_SNAPSHOT_PARTS,
        plaintext_bytes: plaintext,
        ciphertext_bytes: MAX_SNAPSHOT_CIPHERTEXT_BYTES,
        last_plaintext_sha256: "c".repeat(64),
    };
    let bytes = manifest.canonical_bytes().unwrap();
    assert!(bytes.len() <= MAX_PAGE_BYTES);
    assert_eq!(
        WholeSnapshotManifest::from_canonical(&bytes).unwrap(),
        manifest
    );
    let mut impossible = manifest.clone();
    impossible.plaintext_bytes = impossible.review.object_bytes - 1;
    impossible.parts.plaintext_bytes = impossible.plaintext_bytes;
    impossible.ciphertext_bytes = impossible.plaintext_bytes + 1;
    impossible.parts.ciphertext_bytes = impossible.ciphertext_bytes;
    assert!(impossible.validate().is_err());
    let mut impossible = manifest.clone();
    impossible.review.object_count = 0;
    impossible.review.object_bytes = 1;
    impossible.review.inventory.regular_files = 1;
    impossible.review.inventory.logical_bytes = 1;
    impossible.review.inventory.incomplete_objects = 0;
    assert!(impossible.review.finish(&impossible.intent).is_err());
    impossible = manifest.clone();
    impossible.review.object_count = 33;
    impossible.review.object_bytes = 1;
    impossible.review.inventory.regular_files = 34;
    impossible.review.inventory.logical_bytes = 1;
    impossible.review.inventory.incomplete_objects = 33;
    impossible.review.finish(&impossible.intent).unwrap();
    impossible.part_count = 1;
    impossible.parts.count = 1;
    impossible.parts.objects = 33;
    impossible.plaintext_bytes = 200;
    impossible.parts.plaintext_bytes = 200;
    impossible.ciphertext_bytes = 220;
    impossible.parts.ciphertext_bytes = 220;
    assert!(impossible.validate().is_err());
    impossible.review.inventory.incomplete_objects = 0;
    assert!(impossible.review.finish(&impossible.intent).is_err());
}
