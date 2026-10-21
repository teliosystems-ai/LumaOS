//! Actual disposable ext4 typed-map fixtures. Software selected roots and live
//! callbacks below are NOT native C selection, publication, PAM or ACL proof.
use super::*;
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "31".repeat(32),
        owner: "42".repeat(32),
        owner_generation: 2,
    }
}
fn io() -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 16 * 1024 * 1024,
        new_files: 4096,
    }
}
fn read(bytes: u64) -> IoBudget {
    IoBudget {
        read_bytes: bytes,
        write_bytes: 0,
        new_files: 0,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "53".repeat(32),
        decision: crate::DecisionKind::Published,
        source_bytes: 0,
    }
}
struct SoftwareIo;
impl Boundary for SoftwareIo {
    fn admit(&mut self, owner: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        owner.validate()?;
        Ok(())
    }
    fn check(&mut self, _: Access<'_>) -> Result<()> {
        Ok(())
    }
}
struct Fixture {
    path: PathBuf,
    store: ObjectStore,
    head: OwnerHeadV2,
    expected: VersionReference,
    bytes: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn put<T: Serialize>(store: &ObjectStore, root: &MapRoot, key: String, value: &T) -> MapRoot {
    let old = store
        .lookup_map(root, &key, read(1024 * 1024), &mut SoftwareIo)
        .unwrap()
        .verify(root)
        .unwrap();
    let semantic = serde_json::to_vec(value).unwrap();
    let value = if matches!(root.kind, MapKind::Artifacts | MapKind::Lifecycle) {
        let sha256 = store
            .prepare_page(&semantic, io(), &mutation(), &mut SoftwareIo)
            .unwrap();
        serde_json::to_vec(&crate::v2::owner::ValueRef { sha256 }).unwrap()
    } else {
        semantic
    };
    store
        .prepare_map(
            root,
            &[MapEdit {
                key,
                expected_value_sha256: old.as_ref().map(|b| luma_content::sha256(b)),
                value: Some(value),
            }],
            io(),
            &mutation(),
            &mut SoftwareIo,
        )
        .unwrap()
}
struct Append<'a> {
    store: &'a ObjectStore,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    review: Option<String>,
}
impl Boundary for Append<'_> {
    fn admit(&mut self, owner: &OwnerBinding, _: ResourceBudget) -> Result<()> {
        if owner != &self.head.binding {
            return Err("fixture append owner differs".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.head.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.head.binding && self.review.as_deref() == Some(review_sha256) => {
                Ok(())
            }
            _ => Err("fixture append lacks exact reviewed software effect".into()),
        }
    }
}
impl crate::v2::OwnerBoundary for Append<'_> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if head != &self.head {
            return Err("fixture exact selected owner changed".into());
        }
        Ok(())
    }
    fn current_physical_accounting(&mut self, head: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.physical.clone())
    }
    fn verify_prepared_allocations(
        &mut self,
        commitment: &crate::v2::AppendCommitment,
    ) -> Result<()> {
        self.current_owner_head(&commitment.base)?;
        let actual = self
            .store
            .inventory(read(64 * 1024 * 1024), &mut SoftwareIo, |_| Ok(()))?;
        if actual != commitment.physical_after {
            return Err("fixture real held allocations differ".into());
        }
        Ok(())
    }
}
fn fixture() -> Fixture {
    let base = std::env::var("LUMA_STORAGE_TEST_ROOT").expect("requires disposable private ext4");
    let path = Path::new(&base).join(format!(
        "typed-observed-selection-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let store =
        ObjectStore::create_at(&path, &binding(), io(), &mutation(), &mut SoftwareIo).unwrap();
    let physical = store
        .inventory(read(1024 * 1024), &mut SoftwareIo, |_| Ok(()))
        .unwrap();
    let head = OwnerHeadV2::empty_data(&binding(), physical.clone()).unwrap();
    let mut selected = Append {
        store: &store,
        head: head.clone(),
        physical,
        review: None,
    };
    let repository = crate::v2::OwnerRepository::at_selected(&store, &head, &mut selected).unwrap();
    let plan = repository
        .plan_capture(
            "document",
            luma_content::Format::Utf8Text,
            b"exact observed source",
            luma_content::Provenance {
                request_id: "fixture".into(),
                workflow_sha256: "64".repeat(32),
                source_sha256: luma_content::sha256(b"exact observed source"),
                origin: luma_content::EditOrigin::External,
            },
            &mut selected,
        )
        .unwrap();
    let expected = plan.resulting().clone();
    selected.review = Some(plan.review_sha256().into());
    let prepared = repository
        .prepare_append(&plan, io(), &mut selected)
        .unwrap();
    let commitment = prepared.commitment().clone();
    crate::v2::verify_append_data(&store, &commitment, read(64 * 1024 * 1024), &mut selected)
        .unwrap();
    selected.head = commitment.next.clone();
    selected.physical = commitment.physical_after;
    let head = prepared.acknowledge_selected(&mut selected).unwrap();
    selected.review = None;
    let repository = crate::v2::OwnerRepository::at_selected(&store, &head, &mut selected).unwrap();
    let version = repository.current("document", &mut selected).unwrap();
    assert_eq!(version.reference().unwrap(), expected);
    let bytes = version.canonical_envelope().unwrap();
    Fixture {
        path,
        store,
        head,
        expected,
        bytes,
    }
}
struct Current {
    head: OwnerHeadV2,
    live: Rc<Cell<bool>>,
    checks: u64,
}
impl Boundary for Current {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if owner != &self.head.binding
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
            || budget.tasks != 1
            || budget.memory_bytes > 192 * 1024 * 1024
        {
            return Err("fixture finite read budget refused".into());
        }
        self.check(Access::Inspect { binding: owner })
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        match access {
            Access::Inspect { binding } if self.live.get() && binding == &self.head.binding => {
                Ok(())
            }
            _ => Err("fixture original owner/read generation revoked".into()),
        }
    }
}
impl MapCursorBoundary for Current {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        if !self.live.get() || !self.head.roots.all().contains(&root) {
            return Err("fixture selected root changed".into());
        }
        Ok(())
    }
}
impl CurrentOwnerReadBoundary for Current {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        if !self.live.get() || head != &self.head {
            return Err("fixture current head changed".into());
        }
        Ok(())
    }
}
struct Local<'a> {
    store: &'a ObjectStore,
    live: Rc<Cell<bool>>,
    reads: usize,
    revoke: Option<usize>,
}
impl ObservedPageReader for Local<'_> {
    fn read_observed_page(
        &mut self,
        owner: &OwnerBinding,
        sha: &str,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        assert_eq!(owner, &binding());
        assert_eq!(maximum, MAX_PAGE_BYTES);
        check()?;
        self.reads += 1;
        let bytes = self
            .store
            .read_page(sha, read(128 * 1024), &mut SoftwareIo)?;
        if self.revoke == Some(self.reads) {
            self.live.set(false);
        }
        check()?;
        Ok(bytes)
    }
}
fn data(f: &Fixture) -> CurrentArtifactProofData {
    let proof = |root: &MapRoot| {
        f.store
            .lookup_map(
                root,
                &root.key(b"document").unwrap(),
                read(1024 * 1024),
                &mut SoftwareIo,
            )
            .unwrap()
    };
    let artifacts = proof(&f.head.roots.artifacts);
    let lifecycle = proof(&f.head.roots.lifecycle);
    let raw = |proof: &LookupProof, root: &MapRoot| {
        let reference: crate::v2::owner::ValueRef =
            canonical(&proof.verify(root).unwrap().unwrap(), MAX_VALUE_BYTES).unwrap();
        f.store
            .read_page(&reference.sha256, read(128 * 1024), &mut SoftwareIo)
            .unwrap()
    };
    let artifact_value = raw(&artifacts, &f.head.roots.artifacts);
    let lifecycle_value = raw(&lifecycle, &f.head.roots.lifecycle);
    CurrentArtifactProofData::from_proofs(
        &f.head,
        &f.expected,
        artifacts,
        artifact_value,
        lifecycle,
        lifecycle_value,
        proof(&f.head.roots.corpus),
    )
    .unwrap()
}

#[test]
fn actual_typed_membership_resolves_and_reopens_only_exact_native_envelope() {
    let f = fixture();
    let live = Rc::new(Cell::new(true));
    let mut current = Current {
        head: f.head.clone(),
        live: live.clone(),
        checks: 0,
    };
    let mut reader = Local {
        store: &f.store,
        live,
        reads: 0,
        revoke: None,
    };
    let selected = resolve_current(
        &f.head,
        &f.expected,
        read(5 * (MAX_PAGE_BYTES as u64 + 1)),
        &mut reader,
        &mut current,
    )
    .unwrap();
    assert_eq!(reader.reads, 5);
    assert!(current.checks > 0);
    assert_eq!(selected.reference(), &f.expected);
    let artifact = selected.reopen_data_for_head(&f.head, &f.bytes).unwrap();
    assert_eq!(artifact.content(), b"exact observed source");
    let mut corrupt = f.bytes.clone();
    corrupt[0] ^= 1;
    assert!(selected.reopen_data_for_head(&f.head, &corrupt).is_err());
}

#[test]
fn stale_owner_or_substituted_reference_or_map_proof_refuses() {
    let f = fixture();
    let selected = data(&f);
    let mut changed = f.head.clone();
    changed.physical.observation_sha256 = "86".repeat(32);
    assert!(selected.verify_data_for_head(&changed).is_err());
    let mut selected = data(&f);
    selected.expected.version += 1;
    assert!(selected.verify_data_for_head(&f.head).is_err());
    let mut selected = data(&f);
    selected.artifacts.pages[0][0] ^= 1;
    assert!(selected.verify_data_for_head(&f.head).is_err());
    let mut selected = data(&f);
    selected.artifact_value[0] ^= 1;
    assert!(selected.verify_data_for_head(&f.head).is_err());
    let mut selected = data(&f);
    selected.lifecycle_value[0] ^= 1;
    assert!(selected.verify_data_for_head(&f.head).is_err());
    let mut selected = data(&f);
    selected.corpus.key = "97".repeat(32);
    assert!(selected.verify_data_for_head(&f.head).is_err());
    let mut changed = f.head.clone();
    changed.binding.owner_generation += 1;
    assert!(data(&f).verify_data_for_head(&changed).is_err());
}

#[test]
fn trashed_or_missing_or_cross_lifecycle_corpus_never_authorizes_current_blob() {
    for attack in 0..4 {
        let mut f = fixture();
        if attack == 0 {
            let state = LifecycleState {
                version: f.expected.clone(),
                revision: 1,
                state_sha256: "75".repeat(32),
                status: crate::LifecycleStatus::Trashed,
            };
            f.head.roots.lifecycle = put(
                &f.store,
                &f.head.roots.lifecycle,
                f.head.roots.lifecycle.key(b"document").unwrap(),
                &state,
            );
        } else if attack == 1 {
            f.head.roots.corpus = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
        } else {
            let mut corpus = data(&f).verify_data_for_head(&f.head).unwrap().corpus;
            if attack == 2 {
                corpus.lifecycle_revision += 1;
            } else {
                corpus.reference.receipt_sha256 = "a8".repeat(32);
            }
            f.head.roots.corpus = put(
                &f.store,
                &f.head.roots.corpus,
                f.head.roots.corpus.key(b"document").unwrap(),
                &corpus,
            );
        }
        let live = Rc::new(Cell::new(true));
        let mut current = Current {
            head: f.head.clone(),
            live: live.clone(),
            checks: 0,
        };
        let mut reader = Local {
            store: &f.store,
            live,
            reads: 0,
            revoke: None,
        };
        assert!(resolve_current(
            &f.head,
            &f.expected,
            read(1024 * 1024),
            &mut reader,
            &mut current
        )
        .is_err());
    }
}

#[test]
fn whole_resolution_charges_three_paths_before_io_and_revocation_returns_no_proof() {
    let f = fixture();
    for attack in 0..3 {
        let live = Rc::new(Cell::new(true));
        let mut current = Current {
            head: f.head.clone(),
            live: live.clone(),
            checks: 0,
        };
        let mut reader = Local {
            store: &f.store,
            live,
            reads: 0,
            revoke: if attack == 2 { Some(2) } else { None },
        };
        let bytes = if attack == 0 {
            MAX_PAGE_BYTES as u64
        } else if attack == 1 {
            5 * (MAX_PAGE_BYTES as u64 + 1) - 1
        } else {
            1024 * 1024
        };
        assert!(
            resolve_current(&f.head, &f.expected, read(bytes), &mut reader, &mut current).is_err()
        );
        assert_eq!(
            reader.reads,
            if attack == 0 {
                0
            } else if attack == 1 {
                4
            } else {
                2
            }
        );
    }
}

#[test]
fn canonical_unknown_fields_and_cross_owner_payload_are_not_valid_selected_data() {
    let mut f = fixture();
    let mut payload = data(&f).verify_data_for_head(&f.head).unwrap().payload;
    payload.binding.owner = "b9".repeat(32);
    let value = ArtifactValue {
        reference: f.expected.clone(),
        payload,
        collection: false,
    };
    f.head.roots.artifacts = put(
        &f.store,
        &f.head.roots.artifacts,
        f.head.roots.artifacts.key(b"document").unwrap(),
        &value,
    );
    let live = Rc::new(Cell::new(true));
    let mut current = Current {
        head: f.head.clone(),
        live: live.clone(),
        checks: 0,
    };
    let mut reader = Local {
        store: &f.store,
        live,
        reads: 0,
        revoke: None,
    };
    assert!(resolve_current(
        &f.head,
        &f.expected,
        read(1024 * 1024),
        &mut reader,
        &mut current
    )
    .is_err());
}

#[test]
fn direct_leaf_shortcut_and_unknown_semantic_fields_refuse_real_owner_schema() {
    for indirect in [false, true] {
        let mut f = fixture();
        let selected = data(&f).verify_data_for_head(&f.head).unwrap();
        let artifact = ArtifactValue {
            reference: selected.reference,
            payload: selected.payload,
            collection: false,
        };
        let key = f.head.roots.artifacts.key(b"document").unwrap();
        if indirect {
            let mut invalid = serde_json::to_value(&artifact).unwrap();
            invalid["permission"] = serde_json::json!(true);
            f.head.roots.artifacts = put(&f.store, &f.head.roots.artifacts, key, &invalid);
        } else {
            let previous = f
                .store
                .lookup_map(
                    &f.head.roots.artifacts,
                    &key,
                    read(1024 * 1024),
                    &mut SoftwareIo,
                )
                .unwrap()
                .verify(&f.head.roots.artifacts)
                .unwrap()
                .unwrap();
            f.head.roots.artifacts = f
                .store
                .prepare_map(
                    &f.head.roots.artifacts,
                    &[MapEdit {
                        key,
                        expected_value_sha256: Some(luma_content::sha256(&previous)),
                        value: Some(serde_json::to_vec(&artifact).unwrap()),
                    }],
                    io(),
                    &mutation(),
                    &mut SoftwareIo,
                )
                .unwrap();
        }
        let live = Rc::new(Cell::new(true));
        let mut current = Current {
            head: f.head.clone(),
            live: live.clone(),
            checks: 0,
        };
        let mut reader = Local {
            store: &f.store,
            live,
            reads: 0,
            revoke: None,
        };
        assert!(resolve_current(
            &f.head,
            &f.expected,
            read(1024 * 1024),
            &mut reader,
            &mut current
        )
        .is_err());
    }
}
