use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT")
            .expect("v2 tests require private disposable ext4");
        let path = Path::new(&base).join(format!(
            "v2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn object(&self, hash: &str) -> PathBuf {
        self.path
            .join(ObjectStore::name(&binding()).unwrap())
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4])
            .join(hash)
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
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn write_budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 64 * 1024 * 1024,
        new_files: 32768,
    }
}
// Explicit disposable-fixture authority only, never supplied by the library.
struct Guard {
    binding: OwnerBinding,
    write: bool,
    revoked: Rc<Cell<bool>>,
    hook: Option<Box<dyn FnMut()>>,
    checks: usize,
    admissions: usize,
}
impl Guard {
    fn new(write: bool) -> Self {
        Self {
            binding: binding(),
            write,
            revoked: Rc::new(Cell::new(false)),
            hook: None,
            checks: 0,
            admissions: 0,
        }
    }
}
impl Boundary for Guard {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.admissions += 1;
        if self.revoked.get()
            || binding != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("fixture admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if let Some(hook) = self.hook.as_mut() {
            hook();
        }
        if self.revoked.get() {
            return Err("fixture current authority revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if self.write && binding == &self.binding && review_sha256 == "c".repeat(64) => {
                Ok(())
            }
            _ => Err("fixture finite scope refused".into()),
        }
    }
}
fn setup() -> (Fixture, ObjectStore) {
    let fixture = Fixture::new();
    let store = ObjectStore::create_at(
        &fixture.path,
        &binding(),
        write_budget(),
        &mutation(),
        &mut Guard::new(true),
    )
    .unwrap();
    (fixture, store)
}
fn edits(root: &MapRoot, count: usize, size: usize) -> Vec<MapEdit> {
    let mut result = (0..count)
        .map(|n| MapEdit {
            key: root.key(format!("object-{n}").as_bytes()).unwrap(),
            expected_value_sha256: None,
            value: Some(vec![255; size]),
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.key.cmp(&b.key));
    result
}

#[test]
fn empty_roots_and_keys_bind_domain_owner_generation_and_map_kind() {
    let root = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    root.validate().unwrap();
    assert_eq!(
        MapRoot::from_canonical(&root.canonical_bytes().unwrap()).unwrap(),
        root
    );
    let mut other = root.clone();
    other.binding.owner_generation += 1;
    assert_ne!(root.sha256().unwrap(), other.sha256().unwrap());
    assert_ne!(root.key(b"x").unwrap(), other.key(b"x").unwrap());
    other = root.clone();
    other.kind = MapKind::Requests;
    assert_ne!(root.key(b"x").unwrap(), other.key(b"x").unwrap());
    assert!(other.corpus_key("document").is_err());
    assert!(root.corpus_key(".bad").is_err());
    other = root.clone();
    other.domain = "luma-editable-content-store-v1".into();
    assert!(other.validate().is_err());
    other = root.clone();
    other.entry_count = 1;
    assert!(other.validate().is_err());
    let mut bytes = root.canonical_bytes().unwrap();
    bytes.push(b' ');
    assert!(MapRoot::from_canonical(&bytes).is_err());
}

#[test]
fn maximum_binary_values_split_by_encoded_bytes_and_prove_exact_full_coverage() {
    let (_fixture, store) = setup();
    let empty = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    let delta = edits(&empty, 41, MAX_VALUE_BYTES);
    let preview = store
        .preview_map(&empty, &delta, read_budget(), &mut Guard::new(false))
        .unwrap();
    let root = store
        .prepare_map(
            &empty,
            &delta,
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    assert_eq!(root, preview);
    assert!(root.page.as_ref().unwrap().height > 0);
    let mut observed = BTreeMap::new();
    assert_eq!(
        store
            .visit_map(
                &root,
                read_budget(),
                &mut Guard::new(false),
                |key, value| {
                    observed.insert(key.to_owned(), value.to_vec());
                    Ok(())
                }
            )
            .unwrap(),
        41
    );
    for edit in &delta {
        assert_eq!(observed.get(&edit.key), edit.value.as_ref());
        let proof = store
            .lookup_map(&root, &edit.key, read_budget(), &mut Guard::new(false))
            .unwrap();
        assert_eq!(proof.verify(&root).unwrap(), edit.value);
        assert!(proof.pages.iter().all(|p| p.len() <= MAX_PAGE_BYTES));
    }
    let absent = root.key(b"absent").unwrap();
    assert!(store
        .lookup_map(&root, &absent, read_budget(), &mut Guard::new(false))
        .unwrap()
        .verify(&root)
        .unwrap()
        .is_none());
}

#[test]
fn corpus_sized_records_split_and_checked_visit_can_read_private_pages() {
    let (_fixture, store) = setup();
    let empty = MapRoot::empty(&binding(), MapKind::Corpus).unwrap();
    let delta = edits(&empty, 33, 600);
    let root = store
        .prepare_map(
            &empty,
            &delta,
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let marker = store
        .prepare_page(
            b"independent derived DATA",
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let mut count = 0;
    store
        .visit_map_checked(
            &root,
            read_budget(),
            &mut Guard::new(false),
            |_, value, guard| {
                assert_eq!(value.len(), 600);
                assert_eq!(
                    store.read_page(&marker, read_budget(), guard)?,
                    b"independent derived DATA"
                );
                count += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(count, 33);
}

#[test]
fn map_delta_cas_duplicates_noops_removals_and_read_only_replay_are_exact() {
    let (fixture, store) = setup();
    let empty = MapRoot::empty(&binding(), MapKind::Artifacts).unwrap();
    let delta = edits(&empty, 12, 32);
    let root = store
        .prepare_map(
            &empty,
            &delta,
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    assert!(store
        .prepare_map(
            &root,
            &delta,
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    assert!(store
        .preview_map(
            &root,
            &[delta[0].clone(), delta[0].clone()],
            read_budget(),
            &mut Guard::new(false)
        )
        .is_err());
    let same = MapEdit {
        key: delta[0].key.clone(),
        expected_value_sha256: Some(luma_content::sha256(delta[0].value.as_ref().unwrap())),
        value: delta[0].value.clone(),
    };
    assert_eq!(
        store
            .preview_map(&root, &[same], read_budget(), &mut Guard::new(false))
            .unwrap(),
        root
    );
    let before = store
        .inventory(read_budget(), &mut Guard::new(false), |_| Ok(()))
        .unwrap();
    let removal = MapEdit {
        key: delta[0].key.clone(),
        expected_value_sha256: Some(luma_content::sha256(delta[0].value.as_ref().unwrap())),
        value: None,
    };
    let preview = store
        .preview_map(
            &root,
            &[removal.clone()],
            read_budget(),
            &mut Guard::new(false),
        )
        .unwrap();
    assert_eq!(
        store
            .inventory(read_budget(), &mut Guard::new(false), |_| Ok(()))
            .unwrap(),
        before
    );
    let after = store
        .prepare_map(
            &root,
            &[removal],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    assert_eq!(after, preview);
    assert_eq!(after.entry_count, 11);
    assert!(store
        .lookup_map(&after, &delta[0].key, read_budget(), &mut Guard::new(false))
        .unwrap()
        .verify(&after)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .lookup_map(&root, &delta[0].key, read_budget(), &mut Guard::new(false))
            .unwrap()
            .verify(&root)
            .unwrap(),
        delta[0].value
    );
    assert!(fixture.object(&root.page.as_ref().unwrap().sha256).exists());
}

#[test]
fn proof_rejects_tamper_wrong_root_missing_trailing_and_malformed_page_ranges() {
    let (_fixture, store) = setup();
    let empty = MapRoot::empty(&binding(), MapKind::History).unwrap();
    let delta = edits(&empty, 17, 64);
    let root = store
        .prepare_map(
            &empty,
            &delta,
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let proof = store
        .lookup_map(&root, &delta[0].key, read_budget(), &mut Guard::new(false))
        .unwrap();
    let mut bad = proof.clone();
    bad.pages[0][0] ^= 1;
    assert!(bad.verify(&root).is_err());
    bad = proof.clone();
    bad.pages.pop();
    assert!(bad.verify(&root).is_err());
    bad = proof.clone();
    bad.pages.push(proof.pages[0].clone());
    assert!(bad.verify(&root).is_err());
    let mut wrong = root.clone();
    wrong.binding.owner_generation += 1;
    assert!(proof.verify(&wrong).is_err());
    let mut reference = root.page.clone().unwrap();
    reference.entry_count += 1;
    wrong = root.clone();
    wrong.page = Some(reference);
    wrong.entry_count += 1;
    assert!(proof.verify(&wrong).is_err());
}

#[test]
fn blob_merkle_chunks_exact_offsets_empty_full_digest_and_owner_are_verified() {
    let (_fixture, store) = setup();
    let bytes = (0..MAX_PAGE_BYTES * 65 + 137)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let blob = store
        .prepare_blob(&bytes, write_budget(), &mutation(), &mut Guard::new(true))
        .unwrap();
    assert_eq!(blob.chunk_count, 66);
    assert_eq!(
        store
            .read_blob(&blob, read_budget(), &mut Guard::new(false))
            .unwrap(),
        bytes
    );
    let offset = MAX_PAGE_BYTES as u64 * 64 - 13;
    assert_eq!(
        store
            .read_blob_range(&blob, offset, 97, read_budget(), &mut Guard::new(false))
            .unwrap(),
        bytes[offset as usize..offset as usize + 97]
    );
    assert!(store
        .read_blob_range(&blob, blob.bytes, 1, read_budget(), &mut Guard::new(false))
        .is_err());
    let empty = store
        .prepare_blob(&[], write_budget(), &mutation(), &mut Guard::new(true))
        .unwrap();
    assert!(store
        .read_blob(&empty, read_budget(), &mut Guard::new(false))
        .unwrap()
        .is_empty());
    let mut wrong = blob.clone();
    wrong.sha256 = "d".repeat(64);
    assert!(store
        .read_blob(&wrong, read_budget(), &mut Guard::new(false))
        .is_err());
    wrong = blob.clone();
    wrong.binding.owner_generation += 1;
    assert!(store
        .read_blob(&wrong, read_budget(), &mut Guard::new(false))
        .is_err());
}

#[test]
fn private_io_requires_original_effect_and_finite_read_before_consumption() {
    let (_fixture, store) = setup();
    assert!(store
        .prepare_page(
            b"private",
            write_budget(),
            &mutation(),
            &mut Guard::new(false)
        )
        .is_err());
    let hash = store
        .prepare_page(
            &vec![7; 4096],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let budget = IoBudget {
        read_bytes: 1,
        write_bytes: 0,
        new_files: 0,
    };
    let mut guard = Guard::new(false);
    assert!(store
        .read_page(&hash, budget, &mut guard)
        .unwrap_err()
        .to_string()
        .contains("budget"));
    assert_eq!(guard.admissions, 1);
    guard.revoked.set(true);
    assert!(store.read_page(&hash, read_budget(), &mut guard).is_err());
    let mut invalid = write_budget();
    invalid.new_files = 0;
    assert!(store
        .prepare_page(b"x", invalid, &mutation(), &mut Guard::new(true))
        .is_err());
}

#[test]
fn interrupted_write_is_retained_and_measured_never_reused_as_complete() {
    let (fixture, store) = setup();
    let bytes = vec![9; MAX_PAGE_BYTES];
    let hash = luma_content::sha256(&bytes);
    let path = fixture.object(&hash);
    let mut guard = Guard::new(true);
    let revoked = guard.revoked.clone();
    guard.hook = Some(Box::new(move || {
        if path.exists() {
            revoked.set(true);
        }
    }));
    assert!(store
        .prepare_page(&bytes, write_budget(), &mutation(), &mut guard)
        .is_err());
    assert!(fixture.object(&hash).exists());
    let mut incomplete = 0;
    let inventory = store
        .inventory(read_budget(), &mut Guard::new(false), |allocation| {
            if !allocation.complete {
                incomplete += 1;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(incomplete, 1);
    assert_eq!(inventory.incomplete_objects, 1);
    assert!(inventory.allocated_bytes > 0);
    assert!(store
        .prepare_page(&bytes, write_budget(), &mutation(), &mut Guard::new(true))
        .is_err());
}

#[test]
fn mutated_hardlinked_and_renamed_namespaces_fail_closed_without_adoption() {
    let (fixture, store) = setup();
    let hash = store
        .prepare_page(
            b"immutable",
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let path = fixture.object(&hash);
    let alias = path.with_file_name("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(store
        .read_page(&hash, read_budget(), &mut Guard::new(false))
        .is_err());
    fs::remove_file(&alias).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"mutated").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store
        .read_page(&hash, read_budget(), &mut Guard::new(false))
        .is_err());
    let root = fixture.path.join(ObjectStore::name(&binding()).unwrap());
    let moved = fixture.path.join("retained-original");
    fs::rename(&root, &moved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    assert!(store
        .read_page(&hash, read_budget(), &mut Guard::new(false))
        .is_err());
    assert!(ObjectStore::create_at(
        &fixture.path,
        &binding(),
        write_budget(),
        &mutation(),
        &mut Guard::new(true)
    )
    .is_err());
}

#[test]
fn renamed_original_base_and_prefix_are_not_followed_as_current_names() {
    let fixture = Fixture::new();
    let base = fixture.path.join("base");
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let store = ObjectStore::create_at(
        &base,
        &binding(),
        write_budget(),
        &mutation(),
        &mut Guard::new(true),
    )
    .unwrap();
    let hash = store
        .prepare_page(b"held", write_budget(), &mutation(), &mut Guard::new(true))
        .unwrap();
    let root = base.join(ObjectStore::name(&binding()).unwrap());
    let prefix = root.join("objects").join(&hash[..2]);
    let old = root.join("objects").join("retained-prefix");
    fs::rename(&prefix, &old).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&prefix).unwrap();
    assert!(store
        .read_page(&hash, read_budget(), &mut Guard::new(false))
        .is_err());
    fs::rename(&base, fixture.path.join("old-base")).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    assert!(store
        .read_page(&hash, read_budget(), &mut Guard::new(false))
        .is_err());
}

#[test]
fn physical_inventory_refuses_unaccounted_root_members_and_root_mutation() {
    let (fixture, store) = setup();
    let root = fixture.path.join(ObjectStore::name(&binding()).unwrap());
    let unknown = root.join("retained-unknown");
    fs::write(&unknown, b"unaccounted private bytes").unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store
        .inventory(read_budget(), &mut Guard::new(false), |_| Ok(()))
        .is_err());
    assert!(ObjectStore::open_at(
        &fixture.path,
        &binding(),
        read_budget(),
        &mut Guard::new(false)
    )
    .is_err());
    fs::remove_file(&unknown).unwrap();
    store
        .prepare_page(
            b"known immutable object",
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let mut changed = false;
    assert!(store
        .inventory(read_budget(), &mut Guard::new(false), |_| {
            if !changed {
                fs::write(&unknown, b"new unaccounted file")?;
                fs::set_permissions(&unknown, fs::Permissions::from_mode(0o400))?;
                changed = true;
            }
            Ok(())
        })
        .is_err());
    assert!(changed);
    assert!(unknown.exists());
}

fn outcome(ordinal: u64, request: &str, artifact: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let source = format!("original {request}\r\n").into_bytes();
    let provenance = luma_content::Provenance {
        request_id: request.into(),
        workflow_sha256: "d".repeat(64),
        source_sha256: luma_content::sha256(&source),
        origin: luma_content::EditOrigin::External,
    };
    let plan = crate::Plan::capture(
        binding(),
        artifact,
        luma_content::Format::Utf8Text,
        &source,
        provenance,
    )
    .unwrap();
    let record = crate::Record {
        schema_version: 1,
        sequence: ordinal,
        review_sha256: plan.review.clone(),
        plan: plan.data.clone(),
    };
    (serde_json::to_vec(&record).unwrap(), source, plan.payload)
}
fn input<'a>(ordinal: u64, bytes: &'a (Vec<u8>, Vec<u8>, Vec<u8>)) -> SegmentInput<'a> {
    SegmentInput {
        ordinal,
        record: &bytes.0,
        source: &bytes.1,
        payload: &bytes.2,
    }
}

#[test]
fn segments_extend_global_ordinals_and_preserve_cross_segment_request_uniqueness() {
    let (_fixture, store) = setup();
    let requests = MapRoot::empty(&binding(), MapKind::Requests).unwrap();
    let one = outcome(1, "first", "one");
    let first = store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let two = outcome(2, "second", "two");
    let second = store
        .seal_segment(
            Some(&first.descriptor),
            &first.descriptor.requests_after,
            &[input(2, &two)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    assert_eq!(second.descriptor.first_ordinal, 2);
    let mut observed = 0;
    assert_eq!(
        store
            .visit_segment(
                &second.descriptor,
                Some(&first.descriptor),
                read_budget(),
                &mut Guard::new(false),
                |value| {
                    assert_eq!(value.ordinal, 2);
                    assert_eq!(value.source, two.1);
                    observed += 1;
                    Ok(())
                }
            )
            .unwrap(),
        1
    );
    assert_eq!(observed, 1);
    let repeated = outcome(2, "first", "three");
    assert!(store
        .seal_segment(
            Some(&first.descriptor),
            &first.descriptor.requests_after,
            &[input(2, &repeated)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    assert!(store
        .seal_segment(
            Some(&first.descriptor),
            &requests,
            &[input(2, &two)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    assert!(store
        .visit_segment(
            &second.descriptor,
            None,
            read_budget(),
            &mut Guard::new(false),
            |_| Ok(())
        )
        .is_err());
}

#[test]
fn segment_verifier_rejects_same_count_drop_old_request_insert_unrelated_attack() {
    let (_fixture, store) = setup();
    let requests = MapRoot::empty(&binding(), MapKind::Requests).unwrap();
    let one = outcome(1, "first", "one");
    let first = store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let two = outcome(2, "second", "two");
    let second = store
        .seal_segment(
            Some(&first.descriptor),
            &first.descriptor.requests_after,
            &[input(2, &two)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let root = &second.descriptor.requests_after;
    let oldkey = root.key(b"first").unwrap();
    let old = store
        .lookup_map(root, &oldkey, read_budget(), &mut Guard::new(false))
        .unwrap()
        .verify(root)
        .unwrap()
        .unwrap();
    let mut edits = vec![
        MapEdit {
            key: oldkey,
            expected_value_sha256: Some(luma_content::sha256(&old)),
            value: None,
        },
        MapEdit {
            key: root.key(b"unrelated").unwrap(),
            expected_value_sha256: None,
            value: Some(b"unexpected".to_vec()),
        },
    ];
    edits.sort_by(|a, b| a.key.cmp(&b.key));
    let malicious = store
        .prepare_map(
            root,
            &edits,
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    assert_eq!(malicious.entry_count, root.entry_count);
    let mut descriptor = second.descriptor;
    descriptor.requests_after = malicious;
    descriptor.validate().unwrap();
    let mut delivered = false;
    assert!(store
        .visit_segment(
            &descriptor,
            Some(&first.descriptor),
            read_budget(),
            &mut Guard::new(false),
            |_| {
                delivered = true;
                Ok(())
            }
        )
        .is_err());
    assert!(!delivered);
}

#[test]
fn segment_integrity_canonical_schema_bad_order_owner_and_revocation_refuse() {
    let (_fixture, store) = setup();
    let requests = MapRoot::empty(&binding(), MapKind::Requests).unwrap();
    let mut one = outcome(1, "first", "one");
    let mut guard = Guard::new(true);
    guard.revoked.set(true);
    assert!(store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut guard
        )
        .is_err());
    assert_eq!(guard.admissions, 1);
    let good = one.0.clone();
    one.0.push(b' ');
    assert!(store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    one.0 = good;
    one.1[0] ^= 1;
    assert!(store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    one.1[0] ^= 1;
    assert!(store
        .seal_segment(
            None,
            &requests,
            &[input(2, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true)
        )
        .is_err());
    let sealed = store
        .seal_segment(
            None,
            &requests,
            &[input(1, &one)],
            write_budget(),
            &mutation(),
            &mut Guard::new(true),
        )
        .unwrap();
    let mut descriptor = sealed.descriptor;
    descriptor.logical_bytes += 1;
    assert!(store
        .visit_segment(
            &descriptor,
            None,
            read_budget(),
            &mut Guard::new(false),
            |_| Ok(())
        )
        .is_err());
}

#[test]
fn segment_metadata_rejects_malformed_and_retargeted_expected_or_observed_refs() {
    let (_fixture, store) = setup();
    let requests = MapRoot::empty(&binding(), MapKind::Requests).unwrap();
    let original = outcome(1, "first", "one");
    for observed in [false, true] {
        for retargeted in [false, true] {
            let mut bytes = original.clone();
            let mut record: crate::Record = serde_json::from_slice(&bytes.0).unwrap();
            let mut reference = record.plan.resulting.clone();
            if retargeted {
                reference.artifact_id = "different-artifact".into();
            } else {
                reference.receipt_sha256 = "not-a-canonical-sha256".into();
            }
            if observed {
                record.plan.observed = Some(reference);
            } else {
                record.plan.expected = Some(reference);
            }
            // Retain a correct self-commitment, so this actually exercises the
            // reference grammar/target fence rather than a stale review hash.
            record.review_sha256 = luma_content::sha256(&serde_json::to_vec(&record.plan).unwrap());
            bytes.0 = serde_json::to_vec(&record).unwrap();
            assert!(store
                .seal_segment(
                    None,
                    &requests,
                    &[input(1, &bytes)],
                    write_budget(),
                    &mutation(),
                    &mut Guard::new(true)
                )
                .is_err());
        }
    }
}
