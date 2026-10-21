//! Actual bounded inert-store preparation with explicit SOFTWARE authority and
//! plaintext framing fixtures. No CMS, installed C, PAM or encrypted-volume
//! qualification is claimed by these disposable tests.
use super::super::backup::{
    PartDirectoryRef, SnapshotIntent, SnapshotObject, SnapshotPartHeader, SnapshotReview,
    SNAPSHOT_PROFILE,
};
use super::super::head::{HistoryCursor, OwnerRoots, PhysicalAccounting};
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn origin() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    }
}
fn target() -> OwnerBinding {
    OwnerBinding {
        installation: "c".repeat(64),
        owner: "d".repeat(64),
        owner_generation: 2,
    }
}
fn head(binding: OwnerBinding) -> OwnerHeadV2 {
    OwnerHeadV2 {
        schema_version: 2,
        domain: DOMAIN.into(),
        roots: OwnerRoots::empty(&binding).unwrap(),
        binding,
        history: HistoryCursor {
            outcomes: 0,
            segments: 0,
            last_segment: None,
        },
        migration: None,
        physical: PhysicalAccounting::from_observation(PhysicalInventory::default()).unwrap(),
    }
}
fn io(write: bool) -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: if write { 4 * 1024 * 1024 } else { 0 },
        new_files: if write { 256 } else { 0 },
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("restore fixtures require private disposable ext4");
        let path = Path::new(&root).join(format!(
            "restore-window-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct SetupIo;
impl Boundary for SetupIo {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        binding.validate()?;
        if budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("fixture memory scope".into());
        }
        Ok(())
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
#[derive(Default)]
struct Pages(BTreeMap<String, Vec<u8>>);
impl SnapshotPages for Pages {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if luma_content::sha256(bytes) != sha {
            return Err("fixture page hash".into());
        }
        self.0.insert(sha.into(), bytes.into());
        check()
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        let bytes = self
            .0
            .get(sha)
            .cloned()
            .ok_or("fixture missing directory")?;
        check()?;
        Ok(bytes)
    }
}
#[derive(Serialize)]
struct Directory<'a> {
    schema_version: u32,
    profile: &'a str,
    intent_sha256: String,
    body: Leaf<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Leaf<'a> {
    Leaf { parts: Vec<&'a PartCommitment> },
}
fn snapshot(incomplete: bool) -> (WholeSnapshotManifest, Pages, Vec<u8>, String) {
    let mut data = vec![(b"one complete immutable data page".to_vec(), false)];
    if incomplete {
        data.push((b"truncated inert original".to_vec(), true));
    }
    let mut objects: Vec<_> = data
        .iter()
        .enumerate()
        .map(|(i, (bytes, bad))| {
            let actual = luma_content::sha256(bytes);
            SnapshotObject {
                object_sha256: if *bad { "f".repeat(64) } else { actual.clone() },
                actual_sha256: actual,
                bytes: bytes.len() as u64,
                allocated_bytes: 4096,
                complete: !*bad,
                source_device: 1,
                source_inode: i as u64 + 1,
            }
        })
        .collect();
    objects.sort_by(|a, b| a.object_sha256.cmp(&b.object_sha256));
    let complete = objects
        .iter()
        .find(|o| o.complete)
        .unwrap()
        .object_sha256
        .clone();
    let intent = SnapshotIntent {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        snapshot_id: "1".repeat(64),
        head: head(origin()),
        head_sha256: head(origin()).sha256().unwrap(),
        recipient_generation: 1,
        recipients_sha256: "2".repeat(64),
        origin_spki_sha256: "3".repeat(64),
    };
    let header = SnapshotPartHeader {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        number: 0,
        previous_plaintext_sha256: None,
        objects: objects.clone(),
    };
    let metadata = serde_json::to_vec(&header).unwrap();
    let mut frame = b"LUMAV2SNAPSHOT1\n".to_vec();
    frame.extend((metadata.len() as u32).to_be_bytes());
    frame.extend(metadata);
    let mut stream = backup::seed(&intent).unwrap();
    let mut raw = 0;
    for object in &objects {
        stream = backup::extend(&stream, object).unwrap();
        let bytes = &data
            .iter()
            .find(|(b, _)| luma_content::sha256(b) == object.actual_sha256)
            .unwrap()
            .0;
        frame.extend(bytes);
        raw += bytes.len() as u64;
    }
    let part = PartCommitment {
        number: 0,
        plaintext_sha256: luma_content::sha256(&frame),
        plaintext_bytes: frame.len() as u64,
        ciphertext_sha256: "4".repeat(64),
        ciphertext_bytes: frame.len() as u64 + 64,
        objects: objects.len() as u32,
        previous_plaintext_sha256: None,
    };
    let directory = serde_json::to_vec(&Directory {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE,
        intent_sha256: intent.sha256().unwrap(),
        body: Leaf::Leaf { parts: vec![&part] },
    })
    .unwrap();
    let directory_sha = luma_content::sha256(&directory);
    let mut pages = Pages::default();
    pages.0.insert(directory_sha.clone(), directory);
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        inventory: PhysicalInventory {
            regular_files: objects.len() as u64 + 1,
            directories: 2,
            logical_bytes: raw + 128,
            allocated_bytes: 16384,
            incomplete_objects: u64::from(incomplete),
        },
        object_count: objects.len() as u64,
        object_bytes: raw,
        stream_sha256: stream,
        review_sha256: String::new(),
    };
    review.review_sha256 = luma_content::sha256(&serde_json::to_vec(&review).unwrap());
    let manifest = WholeSnapshotManifest {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent,
        review,
        parts: PartDirectoryRef {
            sha256: directory_sha,
            first: 0,
            count: 1,
            height: 0,
            objects: objects.len() as u64,
            plaintext_bytes: part.plaintext_bytes,
            ciphertext_bytes: part.ciphertext_bytes,
        },
        part_count: 1,
        plaintext_bytes: part.plaintext_bytes,
        ciphertext_bytes: part.ciphertext_bytes,
        last_plaintext_sha256: part.plaintext_sha256,
    };
    manifest.validate().unwrap();
    (manifest, pages, frame, complete)
}
fn prefix(manifest: &WholeSnapshotManifest) -> RestorePrefix {
    RestorePrefix {
        schema_version: 1,
        profile: RESTORE_PROFILE.into(),
        job_sha256: "5".repeat(64),
        manifest_sha256: manifest.sha256().unwrap(),
        target: head(target()),
        request_namespace: "restore".into(),
        stage: RestoreStage::Importing,
        origin_namespace_sha256: "6".repeat(64),
        job_namespace_sha256: "7".repeat(64),
        import: ImportProgress {
            next_part: 0,
            objects: 0,
            raw_bytes: 0,
            incomplete_objects: 0,
            stream_sha256: backup::seed(&manifest.intent).unwrap(),
            previous_plaintext_sha256: None,
            last_object_sha256: None,
        },
        next_source_ordinal: 1,
        published_versions: 0,
        lifecycle_outcomes: 0,
        inert_outcomes: 0,
        verified_final_artifacts: 0,
        mappings: MapRoot::empty(&target(), MapKind::RestoreMappings).unwrap(),
        source_lifecycle: MapRoot::empty(&target(), MapKind::RestoreSourceLifecycle).unwrap(),
        reservations: RestoreReservations {
            reservation_sha256: "8".repeat(64),
            publication_tail: 2,
            terminal_tail: 1,
            reserved_bytes: 32768,
            reserved_inodes: 3,
        },
    }
}
struct Live {
    prefix: RestorePrefix,
    manifest_sha: String,
    review: Option<String>,
    revoked: bool,
    retained: bool,
    verified_prepared: bool,
}
impl Live {
    fn new(manifest: &WholeSnapshotManifest) -> Self {
        Self {
            prefix: prefix(manifest),
            manifest_sha: manifest.sha256().unwrap(),
            review: None,
            revoked: false,
            retained: true,
            verified_prepared: false,
        }
    }
}
impl Boundary for Live {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if self.revoked || binding != &origin() || budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("fixture exact source resource scope".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if self.revoked {
            return Err("fixture revoked original window".into());
        }
        match access {
            Access::Inspect { binding } if binding == &origin() => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &origin() && self.review.as_deref() == Some(review_sha256) => Ok(()),
            _ => Err("fixture independent import Write refused".into()),
        }
    }
}
impl OwnerBoundary for Live {
    fn current_owner_head(&mut self, h: &OwnerHeadV2) -> Result<()> {
        if self.revoked || h != &self.prefix.target || h.binding == origin() {
            return Err("fixture refuses foreign owner as selected target".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, h: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(h)?;
        Ok(h.physical.observed.clone())
    }
    fn verify_prepared_allocations(&mut self, _: &AppendCommitment) -> Result<()> {
        Err("fixture has no target append authority".into())
    }
}
impl SnapshotReadBoundary for Live {
    fn authenticated_snapshot(&mut self, m: &WholeSnapshotManifest) -> Result<()> {
        if self.revoked || m.sha256()? != self.manifest_sha {
            return Err("fixture pinned whole-origin receipt differs".into());
        }
        Ok(())
    }
}
impl RestoreBoundary for Live {
    fn current_restore_prefix(
        &mut self,
        _: &WholeSnapshotManifest,
        p: &RestorePrefix,
    ) -> Result<()> {
        if self.revoked || p != &self.prefix {
            return Err("fixture selected C prefix changed".into());
        }
        Ok(())
    }
    fn standard_admin_window(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        r: Option<&RestoreWindowReview>,
    ) -> Result<()> {
        if self.revoked {
            return Err("fixture Standard window expired".into());
        }
        if let Some(r) = r {
            r.validate(m, p)?;
        }
        Ok(())
    }
    fn retain_original_ciphertext(&mut self, _: &WholeSnapshotManifest, _: u32) -> Result<()> {
        if !self.retained {
            return Err("fixture original CMS part lost".into());
        }
        Ok(())
    }
    fn verify_origin_namespace(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        s: &ObjectStore,
    ) -> Result<()> {
        self.current_restore_prefix(m, p)?;
        s.check_root(&m.intent.head.roots.artifacts)
    }
    fn verify_prepared_import(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        r: &RestoreWindowReview,
        c: &PreparedImportCommitment,
        s: &ObjectStore,
    ) -> Result<()> {
        r.validate(m, p)?;
        if c.review_sha256 != r.review_sha256
            || c.base_prefix_sha256 != p.sha256(m)?
            || c.proposed_prefix_sha256 != r.proposed_data_sha256
        {
            return Err("fixture prepared semantic join".into());
        }
        let actual = s.inventory(io(false), &mut SetupIo, |_| Ok(()))?;
        if c.newly_allocated.regular_files + 1 != actual.regular_files
            || c.newly_allocated.incomplete_objects != 0
        {
            return Err("fixture actual newly created files differ".into());
        }
        self.verified_prepared = true;
        Ok(())
    }
}
#[test]
fn exact_part_import_keeps_foreign_origin_inert_and_requires_c_selection() {
    let (manifest, mut pages, frame, complete) = snapshot(true);
    let mut live = Live::new(&manifest);
    let old = live.prefix.clone();
    let plan = plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).unwrap();
    live.review = Some(plan.review().review_sha256.clone());
    let fixture = Fixture::new();
    let store = ObjectStore::create_at(
        &fixture.0,
        &origin(),
        io(true),
        &Mutation {
            review_sha256: "9".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut SetupIo,
    )
    .unwrap();
    let prepared = prepare_import_part(&store, &manifest, &old, plan, io(true), &mut live).unwrap();
    assert!(live.verified_prepared);
    assert_eq!(prepared.commitment().newly_allocated.regular_files, 1);
    assert_eq!(prepared.proposed_prefix().stage, RestoreStage::Replaying);
    assert!(store.read_page(&complete, io(false), &mut SetupIo).is_ok());
    assert!(store
        .read_page(&"f".repeat(64), io(false), &mut SetupIo)
        .is_err());
    let next = prepared.proposed_prefix().clone();
    live.prefix = next.clone();
    assert_eq!(
        prepared.acknowledge_selected(&manifest, &mut live).unwrap(),
        next
    );
    assert!(plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).is_err());
}
#[test]
fn prepare_without_independent_effect_or_retained_ciphertext_refuses() {
    let (manifest, mut pages, frame, _) = snapshot(false);
    let mut live = Live::new(&manifest);
    let old = live.prefix.clone();
    let fixture = Fixture::new();
    let store = ObjectStore::create_at(
        &fixture.0,
        &origin(),
        io(true),
        &Mutation {
            review_sha256: "9".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut SetupIo,
    )
    .unwrap();
    let plan = plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).unwrap();
    assert!(prepare_import_part(&store, &manifest, &old, plan, io(true), &mut live).is_err());
    let plan = plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).unwrap();
    live.review = Some(plan.review().review_sha256.clone());
    live.retained = false;
    assert!(prepare_import_part(&store, &manifest, &old, plan, io(true), &mut live).is_err());
    assert_eq!(
        store
            .inventory(io(false), &mut SetupIo, |_| Ok(()))
            .unwrap()
            .regular_files,
        1
    );
}
#[test]
fn tamper_missing_directory_revocation_and_stale_prefix_refuse() {
    let (manifest, mut pages, mut frame, _) = snapshot(false);
    let mut live = Live::new(&manifest);
    let old = live.prefix.clone();
    let last = frame.len() - 1;
    frame[last] ^= 1;
    assert!(plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).is_err());
    frame[last] ^= 1;
    let saved = pages.0.remove(&manifest.parts.sha256).unwrap();
    assert!(plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).is_err());
    pages.0.insert(manifest.parts.sha256.clone(), saved);
    live.revoked = true;
    assert!(plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).is_err());
    live.revoked = false;
    let mut stale = old.clone();
    stale.origin_namespace_sha256 = "e".repeat(64);
    assert!(plan_import_part(&manifest, &stale, &frame, &mut pages, &mut live).is_err());
}
#[test]
fn closed_prefix_and_review_bind_entire_proposed_progress() {
    let (manifest, mut pages, frame, _) = snapshot(false);
    let mut live = Live::new(&manifest);
    let old = live.prefix.clone();
    let plan = plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).unwrap();
    let mut review = plan.review().clone();
    review.proposed_data_sha256 = "e".repeat(64);
    assert!(review.validate(&manifest, &old).is_err());
    let bytes = old.canonical_bytes(&manifest).unwrap();
    assert_eq!(
        RestorePrefix::from_canonical(&bytes, &manifest).unwrap(),
        old
    );
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["authority"] = serde_json::Value::Bool(true);
    assert!(
        RestorePrefix::from_canonical(&serde_json::to_vec(&unknown).unwrap(), &manifest).is_err()
    );
}
#[test]
fn caller_cannot_expand_fixed_import_profile_before_any_write() {
    let (manifest, mut pages, frame, _) = snapshot(false);
    let mut live = Live::new(&manifest);
    let old = live.prefix.clone();
    let fixture = Fixture::new();
    let store = ObjectStore::create_at(
        &fixture.0,
        &origin(),
        io(true),
        &Mutation {
            review_sha256: "9".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut SetupIo,
    )
    .unwrap();
    for budget in [
        IoBudget {
            read_bytes: IMPORT_MAX_READ_BYTES + 1,
            ..io(true)
        },
        IoBudget {
            write_bytes: IMPORT_MAX_WRITE_BYTES + 1,
            ..io(true)
        },
        IoBudget {
            new_files: IMPORT_MAX_NEW_FILES + 1,
            ..io(true)
        },
        io(false),
    ] {
        let plan = plan_import_part(&manifest, &old, &frame, &mut pages, &mut live).unwrap();
        live.review = Some(plan.review().review_sha256.clone());
        assert!(prepare_import_part(&store, &manifest, &old, plan, budget, &mut live).is_err());
        assert_eq!(
            store
                .inventory(io(false), &mut SetupIo, |_| Ok(()))
                .unwrap()
                .regular_files,
            1
        );
    }
}
