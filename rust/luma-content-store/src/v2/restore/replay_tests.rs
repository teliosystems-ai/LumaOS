//! Real immutable-store/engine work under explicit SOFTWARE authority. The
//! reversible part envelope is NOT CMS; fixture selection is NOT installed C,
//! PAM, a grant ceremony, encrypted-volume proof or native qualification.
use super::super::super::backup::*;
use super::super::super::head::{HistoryCursor, OwnerRoots, PhysicalAccounting};
use super::super::completion::{
    plan_completion, prepare_completion, verify_prepared_completion_data, CompletionBoundary,
    TerminalCommitment,
};
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("restore engine fixtures require disposable private ext4");
        let path = Path::new(&base).join(format!(
            "restore-engine-{}-{}",
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
fn binding(target: bool) -> OwnerBinding {
    OwnerBinding {
        installation: if target {
            "c".repeat(64)
        } else {
            "a".repeat(64)
        },
        owner: if target {
            "d".repeat(64)
        } else {
            "b".repeat(64)
        },
        owner_generation: 1,
    }
}
fn io(write: bool) -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: if write { 4 * 1024 * 1024 } else { 0 },
        new_files: if write { 256 } else { 0 },
    }
}
struct RawIo;
impl Boundary for RawIo {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        binding.validate()?;
        if budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("fixture memory".into());
        }
        Ok(())
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
fn store(path: &Path, target: bool) -> ObjectStore {
    ObjectStore::create_at(
        path,
        &binding(target),
        io(true),
        &Mutation {
            review_sha256: "1".repeat(64),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut RawIo,
    )
    .unwrap()
}
fn observed(store: &ObjectStore) -> PhysicalInventory {
    store.inventory(io(false), &mut RawIo, |_| Ok(())).unwrap()
}
fn empty(store: &ObjectStore, target: bool) -> OwnerHeadV2 {
    OwnerHeadV2 {
        schema_version: 2,
        domain: DOMAIN.into(),
        binding: binding(target),
        history: HistoryCursor {
            outcomes: 0,
            segments: 0,
            last_segment: None,
        },
        roots: OwnerRoots::empty(&binding(target)).unwrap(),
        migration: None,
        physical: PhysicalAccounting::from_observation(observed(store)).unwrap(),
    }
}
fn provenance(id: &str, source: &[u8]) -> Provenance {
    Provenance {
        request_id: id.into(),
        workflow_sha256: "2".repeat(64),
        source_sha256: luma_content::sha256(source),
        origin: EditOrigin::External,
    }
}
struct Producer<'a> {
    store: &'a ObjectStore,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    review: Option<String>,
    mode: Option<SnapshotMode>,
    snapshot_review: Option<String>,
}
impl<'a> Producer<'a> {
    fn new(store: &'a ObjectStore) -> Self {
        Self {
            store,
            head: empty(store, false),
            physical: observed(store),
            review: None,
            mode: None,
            snapshot_review: None,
        }
    }
    fn publish(&mut self, plan: &OwnerPlan) {
        let store = self.store;
        let head = self.head.clone();
        self.review = Some(plan.review_sha256().into());
        let repo = OwnerRepository::at_selected(store, &head, self).unwrap();
        let prepared = repo.prepare_append(plan, io(true), self).unwrap();
        let commitment = prepared.commitment().clone();
        verify_append_data(store, &commitment, io(false), self).unwrap();
        self.head = commitment.next;
        self.physical = commitment.physical_after;
        prepared.acknowledge_selected(self).unwrap();
        self.review = None;
    }
    fn history(&mut self) {
        let store = self.store;
        let repo = OwnerRepository::at_selected(store, &self.head.clone(), self).unwrap();
        let plan = repo
            .plan_capture(
                "note",
                luma_content::Format::Utf8Text,
                b"first",
                provenance("first", b"first"),
                self,
            )
            .unwrap();
        let first = plan.resulting().clone();
        self.publish(&plan);
        let repo = OwnerRepository::at_selected(store, &self.head.clone(), self).unwrap();
        let plan = repo
            .plan_external_edit(
                "note",
                first.clone(),
                b"second",
                provenance("second", b"second"),
                self,
            )
            .unwrap();
        let second = plan.resulting().clone();
        self.publish(&plan);
        let mut unavailable = first;
        unavailable.version = 999;
        unavailable.receipt_sha256 = "f".repeat(64);
        let repo = OwnerRepository::at_selected(store, &self.head.clone(), self).unwrap();
        let plan = repo
            .plan_external_edit(
                "note",
                unavailable,
                b"retained candidate",
                provenance("stale", b"retained candidate"),
                self,
            )
            .unwrap();
        assert_eq!(plan.decision(), DecisionKind::ConflictRetained);
        self.publish(&plan);
        for (operation, id) in [
            (crate::LifecycleOperation::Trash, "trash"),
            (crate::LifecycleOperation::Restore, "untrash"),
        ] {
            let repo = OwnerRepository::at_selected(store, &self.head.clone(), self).unwrap();
            let request = super::super::super::lifecycle::LifecycleRequestV2 {
                schema_version: 2,
                binding: binding(false),
                request_id: id.into(),
                workflow_sha256: "2".repeat(64),
                expected: repo.lifecycle_status("note", self).unwrap(),
                operation,
                retention: crate::RetentionPolicy::UntilExplicitRestoreNoPurge,
            };
            let plan = repo.plan_lifecycle(&request, self).unwrap();
            self.publish(&plan);
        }
        let collection = crate::CollectionSource {
            schema_version: 1,
            kind: "luma-explicit-collection-v1".into(),
            collection_id: "set".into(),
            name: "Exact set".into(),
            members: vec![second],
        };
        let source = collection.canonical_bytes().unwrap();
        let repo = OwnerRepository::at_selected(store, &self.head.clone(), self).unwrap();
        let plan = repo
            .plan_collection(&collection, None, provenance("collection", &source), self)
            .unwrap();
        self.publish(&plan);
    }
}
impl Boundary for Producer<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if binding != &self.head.binding {
            return Err("fixture origin admission".into());
        }
        RawIo.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.head.binding => Ok(()),
            Access::Mutate { review_sha256, .. }
                if self.review.as_deref() == Some(review_sha256) =>
            {
                Ok(())
            }
            _ => Err("fixture origin effect".into()),
        }
    }
}
impl OwnerBoundary for Producer<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if head != &self.head {
            return Err("fixture origin current head".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.physical.clone())
    }
    fn verify_prepared_allocations(&mut self, c: &AppendCommitment) -> Result<()> {
        self.current_owner_head(&c.base)?;
        if observed(self.store) != c.physical_after {
            return Err("fixture origin actual allocations".into());
        }
        Ok(())
    }
}
impl SnapshotBoundary for Producer<'_> {
    fn admit_snapshot(
        &mut self,
        intent: &SnapshotIntent,
        mode: SnapshotMode,
        budget: SnapshotBudget,
    ) -> Result<()> {
        self.current_owner_head(&intent.head)?;
        budget.validate(mode)?;
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
            || (mode == SnapshotMode::Export && review != self.snapshot_review.as_deref())
        {
            return Err("fixture original export review".into());
        }
        Ok(())
    }
    fn verify_snapshot_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        self.current_owner_head(head)?;
        let store = self.store;
        for root in head.roots.all() {
            store.visit_map(root, io(false), self, |_, _| Ok(()))?;
        }
        let repo = OwnerRepository::at_selected(store, head, self)?;
        repo.visit_outcomes(1, 256, self, |_| Ok(()))?;
        Ok(())
    }
}
#[derive(Default)]
struct PlainFixtureSink {
    pages: BTreeMap<String, Vec<u8>>,
    parts: BTreeMap<u32, Vec<u8>>,
    cipher: BTreeMap<u32, Vec<u8>>,
}
impl SnapshotPages for PlainFixtureSink {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        if luma_content::sha256(bytes) != sha {
            return Err("fixture directory".into());
        }
        self.pages.insert(sha.into(), bytes.into());
        check()
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        let bytes = self
            .pages
            .get(sha)
            .cloned()
            .ok_or("fixture directory absent")?;
        check()?;
        Ok(bytes)
    }
}
impl SnapshotSink for PlainFixtureSink {
    fn retain_part(
        &mut self,
        intent: &SnapshotIntent,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PartCommitment> {
        let part = SnapshotPart::parse(bytes, intent, &mut || check())?;
        let mut cipher = b"NON-CRYPTOGRAPHIC-TEST-ENVELOPE".to_vec();
        cipher.extend(bytes);
        let value = PartCommitment {
            number: part.header().number,
            plaintext_sha256: part.sha256().into(),
            plaintext_bytes: bytes.len() as u64,
            ciphertext_sha256: luma_content::sha256(&cipher),
            ciphertext_bytes: cipher.len() as u64,
            objects: part.header().objects.len() as u32,
            previous_plaintext_sha256: part.header().previous_plaintext_sha256.clone(),
        };
        self.parts.insert(value.number, bytes.into());
        self.cipher.insert(value.number, cipher);
        check()?;
        Ok(value)
    }
}
fn archive(producer: &mut Producer<'_>) -> (WholeSnapshotManifest, PlainFixtureSink) {
    let intent = SnapshotIntent {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        snapshot_id: "3".repeat(64),
        head: producer.head.clone(),
        head_sha256: producer.head.sha256().unwrap(),
        recipient_generation: 1,
        recipients_sha256: "4".repeat(64),
        origin_spki_sha256: "5".repeat(64),
    };
    let budget = SnapshotBudget {
        read_bytes: 1024 * 1024 * 1024,
        output_bytes: 0,
        maximum_objects: MAX_SNAPSHOT_OBJECTS,
        maximum_parts: MAX_SNAPSHOT_PARTS,
    };
    let source = producer.store;
    let review = review_snapshot(source, &intent, budget, producer).unwrap();
    producer.snapshot_review = Some(review.review_sha256.clone());
    let mut sink = PlainFixtureSink::default();
    let manifest = export_snapshot(
        source,
        &intent,
        &review,
        SnapshotBudget {
            output_bytes: MAX_SNAPSHOT_EXPORT_BYTES,
            ..budget
        },
        producer,
        &mut sink,
    )
    .unwrap();
    (manifest, sink)
}
struct Live<'a> {
    origin: &'a ObjectStore,
    job: &'a ObjectStore,
    target: &'a ObjectStore,
    prefix: RestorePrefix,
    manifest: String,
    manifest_value: WholeSnapshotManifest,
    prefix_sha: String,
    target_sha: String,
    origin_physical: PhysicalInventory,
    job_physical: PhysicalInventory,
    target_physical: PhysicalInventory,
    reviews: Vec<String>,
    revoked: bool,
    retained: u32,
}
impl<'a> Live<'a> {
    fn new(
        origin: &'a ObjectStore,
        job: &'a ObjectStore,
        target: &'a ObjectStore,
        manifest: &WholeSnapshotManifest,
    ) -> Self {
        let prefix = RestorePrefix {
            schema_version: 1,
            profile: RESTORE_PROFILE.into(),
            job_sha256: "6".repeat(64),
            manifest_sha256: manifest.sha256().unwrap(),
            target: empty(target, true),
            request_namespace: "restored".into(),
            stage: RestoreStage::Importing,
            origin_namespace_sha256: "7".repeat(64),
            job_namespace_sha256: "8".repeat(64),
            import: ImportProgress {
                next_part: 0,
                objects: 0,
                raw_bytes: 0,
                incomplete_objects: 0,
                stream_sha256: super::super::super::backup::seed(&manifest.intent).unwrap(),
                previous_plaintext_sha256: None,
                last_object_sha256: None,
            },
            next_source_ordinal: 1,
            published_versions: 0,
            lifecycle_outcomes: 0,
            inert_outcomes: 0,
            verified_final_artifacts: 0,
            mappings: MapRoot::empty(&binding(true), MapKind::RestoreMappings).unwrap(),
            source_lifecycle: MapRoot::empty(&binding(true), MapKind::RestoreSourceLifecycle)
                .unwrap(),
            reservations: RestoreReservations {
                reservation_sha256: "9".repeat(64),
                publication_tail: 2,
                terminal_tail: 1,
                reserved_bytes: 32768,
                reserved_inodes: 3,
            },
        };
        Self {
            origin,
            job,
            target,
            prefix_sha: prefix.sha256(manifest).unwrap(),
            target_sha: prefix.target.sha256().unwrap(),
            prefix,
            manifest: manifest.sha256().unwrap(),
            manifest_value: manifest.clone(),
            origin_physical: observed(origin),
            job_physical: observed(job),
            target_physical: observed(target),
            reviews: Vec::new(),
            revoked: false,
            retained: manifest.part_count,
        }
    }
    fn select_prefix(&mut self, next: RestorePrefix) {
        self.prefix_sha = next.sha256(&self.manifest_value).unwrap();
        self.target_sha = next.target.sha256().unwrap();
        self.prefix = next;
    }
    fn import_all(&mut self, manifest: &WholeSnapshotManifest, sink: &mut PlainFixtureSink) {
        for number in 0..manifest.part_count {
            self.reviews.clear();
            let old = self.prefix.clone();
            let bytes = sink.parts[&number].clone();
            let plan = plan_import_part(manifest, &old, &bytes, sink, self).unwrap();
            self.reviews.push(plan.review().review_sha256.clone());
            let prepared =
                prepare_import_part(self.origin, manifest, &old, plan, io(true), self).unwrap();
            self.select_prefix(prepared.proposed_prefix().clone());
            self.origin_physical = observed(self.origin);
            prepared.acknowledge_selected(manifest, self).unwrap();
        }
        self.reviews.clear();
    }
}
impl Boundary for Live<'_> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if self.revoked
            || (binding != &self.prefix.target.binding && binding != &self.origin.binding)
        {
            return Err("fixture exact live scope".into());
        }
        RawIo.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if self.revoked {
            return Err("fixture original window revoked".into());
        }
        match access {
            Access::Inspect { binding }
                if binding == &self.origin.binding || binding == &self.prefix.target.binding =>
            {
                Ok(())
            }
            Access::Mutate { review_sha256, .. }
                if self.reviews.iter().any(|r| r == review_sha256) =>
            {
                Ok(())
            }
            _ => Err("fixture new independent original effect missing".into()),
        }
    }
}
impl OwnerBoundary for Live<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if self.revoked || head != &self.prefix.target || head.binding == self.origin.binding {
            return Err("fixture will never select foreign origin as local owner".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.target_physical.clone())
    }
    fn verify_prepared_allocations(&mut self, c: &AppendCommitment) -> Result<()> {
        self.current_owner_head(&c.base)?;
        if observed(self.target) != c.physical_after {
            return Err("fixture real target allocation mismatch".into());
        }
        Ok(())
    }
}
impl SnapshotReadBoundary for Live<'_> {
    fn authenticated_snapshot(&mut self, m: &WholeSnapshotManifest) -> Result<()> {
        if self.revoked || m != &self.manifest_value {
            return Err("fixture independent whole-origin pin differs".into());
        }
        Ok(())
    }
}
impl RestoreBoundary for Live<'_> {
    fn current_restore_prefix(
        &mut self,
        _: &WholeSnapshotManifest,
        p: &RestorePrefix,
    ) -> Result<()> {
        if self.revoked || p != &self.prefix {
            return Err("fixture current C job prefix differs".into());
        }
        Ok(())
    }
    fn standard_admin_window(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        r: Option<&RestoreWindowReview>,
    ) -> Result<()> {
        self.current_restore_prefix(m, p)?;
        if let Some(r) = r {
            if m != &self.manifest_value
                || p != &self.prefix
                || r.manifest_sha256 != self.manifest
                || r.prefix_sha256 != self.prefix_sha
                || r.target_head_sha256 != self.target_sha
                || r.job_sha256 != p.job_sha256
                || (!self.reviews.is_empty() && !self.reviews.contains(&r.review_sha256))
            {
                return Err("fixture current original review differs".into());
            }
        }
        Ok(())
    }
    fn retain_original_ciphertext(&mut self, m: &WholeSnapshotManifest, n: u32) -> Result<()> {
        if n > self.retained || self.retained != m.part_count {
            return Err("fixture original encrypted evidence lost".into());
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
        if !std::ptr::eq(s, self.origin) {
            return Err("fixture wrong inert namespace".into());
        }
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
            || c.proposed_prefix_sha256 != r.proposed_data_sha256
            || super::super::super::owner::add_physical(&self.origin_physical, &c.newly_allocated)?
                != observed(s)
        {
            return Err("fixture actual import allocation/proposal mismatch".into());
        }
        Ok(())
    }
}
impl ReplayBoundary for Live<'_> {
    fn verify_job_namespace(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        s: &ObjectStore,
    ) -> Result<()> {
        self.current_restore_prefix(m, p)?;
        if !std::ptr::eq(s, self.job) {
            return Err("fixture wrong auxiliary namespace".into());
        }
        s.check_root(&p.mappings)
    }
    fn verify_prepared_replay(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        r: &RestoreWindowReview,
        c: &PreparedReplayCommitment,
        s: &ObjectStore,
    ) -> Result<()> {
        r.validate(m, p)?;
        if c.review_sha256 != r.review_sha256
            || c.proposal.sha256()? != r.proposed_data_sha256
            || super::super::super::owner::add_physical(&self.job_physical, &c.newly_allocated_job)?
                != observed(s)
        {
            return Err("fixture actual auxiliary allocation/proposal mismatch".into());
        }
        if let Some(append) = &c.target_append {
            self.verify_prepared_allocations(append)?;
        }
        Ok(())
    }
}
impl CompletionBoundary for Live<'_> {
    fn verify_prepared_terminal(
        &mut self,
        m: &WholeSnapshotManifest,
        p: &RestorePrefix,
        r: &RestoreWindowReview,
        c: &TerminalCommitment,
        s: &ObjectStore,
    ) -> Result<()> {
        self.verify_job_namespace(m, p, s)?;
        r.validate(m, p)?;
        if c.review_sha256 != r.review_sha256
            || c.base_prefix_sha256 != p.sha256(m)?
            || c.prefix_object_sha256 != c.next.sha256(m)?
            || super::super::super::owner::add_physical(&self.job_physical, &c.newly_allocated_job)?
                != observed(s)
        {
            return Err("fixture actual terminal prefix/physical delta differs".into());
        }
        // This observes disposable job files only. Actual C preallocated tails,
        // installed encryption, PAM and NV publication are not this fixture.
        Ok(())
    }
}
fn replay_budget() -> ReplayBudget {
    ReplayBudget {
        source_read_bytes: 64 * 1024 * 1024,
        job_read_bytes: 64 * 1024 * 1024,
        job_write_bytes: 4 * 1024 * 1024,
        job_new_files: 256,
        target_read_bytes: 512 * 1024 * 1024,
        target_write_bytes: 4 * 1024 * 1024,
        target_new_files: 256,
    }
}
#[test]
fn actual_multiwindow_engines_remap_history_visibility_and_collection_without_inert_promotion() {
    let source_dir = Fixture::new();
    let source = store(&source_dir.0, false);
    let mut producer = Producer::new(&source);
    producer.history();
    let (manifest, mut sink) = archive(&mut producer);
    let origin_dir = Fixture::new();
    let job_dir = Fixture::new();
    let target_dir = Fixture::new();
    let origin = store(&origin_dir.0, false);
    let job = store(&job_dir.0, true);
    let target = store(&target_dir.0, true);
    let mut live = Live::new(&origin, &job, &target, &manifest);
    live.import_all(&manifest, &mut sink);
    while live.prefix.next_source_ordinal <= manifest.intent.head.history.outcomes {
        live.reviews.clear();
        let old = live.prefix.clone();
        let repo = OwnerRepository::at_selected(&target, &old.target, &mut live).unwrap();
        let plan = plan_replay_outcome(
            &origin,
            &job,
            &repo,
            &manifest,
            &old,
            &"e".repeat(64),
            old.reservations.clone(),
            replay_budget(),
            &mut live,
        )
        .unwrap();
        live.reviews.push(plan.review.review_sha256.clone());
        if let Some(target) = &plan.target_plan {
            live.reviews.push(target.review_sha256().into());
        }
        let review = plan.review.clone();
        let prepared = prepare_replay(&job, &repo, &manifest, &old, plan, &mut live).unwrap();
        let commitment = prepared.commitment().clone();
        assert_eq!(
            verify_prepared_replay_data(
                &origin,
                &job,
                &repo,
                &manifest,
                &old,
                &review,
                &commitment,
                &"e".repeat(64),
                &mut live
            )
            .unwrap(),
            commitment.next
        );
        let mut tampered = commitment.clone();
        tampered.next.inert_outcomes += 1;
        assert!(verify_prepared_replay_data(
            &origin,
            &job,
            &repo,
            &manifest,
            &old,
            &review,
            &tampered,
            &"e".repeat(64),
            &mut live
        )
        .is_err());
        live.target_physical = commitment
            .target_append
            .as_ref()
            .map(|a| a.physical_after.clone())
            .unwrap_or_else(|| live.target_physical.clone());
        live.job_physical = observed(&job);
        live.select_prefix(commitment.next);
        prepared.acknowledge_selected(&manifest, &mut live).unwrap();
    }
    assert_eq!(
        (
            live.prefix.published_versions,
            live.prefix.lifecycle_outcomes,
            live.prefix.inert_outcomes
        ),
        (3, 2, 1)
    );
    assert_eq!(live.prefix.verified_final_artifacts, 2);
    assert_eq!(live.prefix.target.history.outcomes, 5);
    let repo =
        OwnerRepository::at_selected(&target, &live.prefix.target.clone(), &mut live).unwrap();
    assert_eq!(
        repo.current("note", &mut live).unwrap().content(),
        b"second"
    );
    assert_eq!(
        repo.lifecycle_status("note", &mut live).unwrap().status,
        LifecycleStatus::Live
    );
    let collection = repo.current("collection.set", &mut live).unwrap();
    let body: crate::CollectionSource = serde_json::from_slice(collection.content()).unwrap();
    assert_eq!(
        body.members[0],
        repo.current("note", &mut live)
            .unwrap()
            .reference()
            .unwrap()
    );
    live.reviews.clear();
    let old = live.prefix.clone();
    let target_before = observed(&target);
    let job_before = observed(&job);
    let terminal = RestoreReservations {
        reservation_sha256: "f".repeat(64),
        publication_tail: 0,
        terminal_tail: 0,
        reserved_bytes: 0,
        reserved_inodes: 0,
    };
    let plan = plan_completion(&job, &manifest, &old, terminal.clone(), &mut live).unwrap();
    assert!(prepare_completion(&job, &manifest, &old, plan, &mut live).is_err());
    assert_eq!(observed(&job), job_before);
    let plan = plan_completion(&job, &manifest, &old, terminal.clone(), &mut live).unwrap();
    let review = plan.review().clone();
    live.reviews.push(review.review_sha256.clone());
    let prepared = prepare_completion(&job, &manifest, &old, plan, &mut live).unwrap();
    let commitment = prepared.commitment().clone();
    assert_eq!(
        verify_prepared_completion_data(&job, &manifest, &old, &review, &commitment, &mut live)
            .unwrap(),
        commitment.next
    );
    let mut altered = commitment.clone();
    altered.prefix_object_sha256 = "a".repeat(64);
    assert!(
        verify_prepared_completion_data(&job, &manifest, &old, &review, &altered, &mut live)
            .is_err()
    );
    live.job_physical = observed(&job);
    live.select_prefix(commitment.next);
    prepared.acknowledge_selected(&manifest, &mut live).unwrap();
    assert_eq!(live.prefix.stage, RestoreStage::Complete);
    assert_eq!(observed(&target), target_before);
    assert!(live.job_physical.regular_files > 0);
    let completed = live.prefix.clone();
    assert!(plan_completion(&job, &manifest, &completed, terminal, &mut live).is_err());
}
#[test]
fn replay_budget_cannot_expand_or_renew_unreviewed_work() {
    let mut budget = replay_budget();
    budget.validate().unwrap();
    budget.source_read_bytes += 1;
    assert!(budget.validate().is_err());
    budget = replay_budget();
    budget.job_new_files = 2049;
    assert!(budget.validate().is_err());
    budget = replay_budget();
    budget.target_write_bytes = 65 * 1024 * 1024;
    assert!(budget.validate().is_err());
}
