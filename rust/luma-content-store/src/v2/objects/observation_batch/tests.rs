//! Real disposable private ext4 observations under explicit software access.
//! No test turns scoped counters/advisory locks into C/creator authority.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::var("LUMA_STORAGE_TEST_ROOT").expect("writer batch requires disposable ext4");
        let path = Path::new(&root).join(format!(
            "writer-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn raw(&self, sha: &str) -> std::path::PathBuf {
        self.0
            .join(ObjectStore::name(&binding()).unwrap())
            .join("objects")
            .join(&sha[..2])
            .join(&sha[2..4])
            .join(sha)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Io {
    live: bool,
}
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    }
}
impl Boundary for Io {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if !self.live || owner != &binding() || budget.memory_bytes > 192 * 1024 * 1024 {
            return Err("fixture original resource access absent".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        if !self.live {
            return Err("fixture original revoked".into());
        }
        match access {
            Access::Inspect { binding: b } | Access::Mutate { binding: b, .. }
                if b == &binding() =>
            {
                Ok(())
            }
            _ => Err("fixture source/owner differs".into()),
        }
    }
}
fn setup() -> (Fixture, ObjectStore, Io) {
    let fixture = Fixture::new();
    let mut io = Io { live: true };
    let store = ObjectStore::create_at(
        &fixture.0,
        &binding(),
        IoBudget {
            read_bytes: MAX_READ_BYTES,
            write_bytes: 1024 * 1024,
            new_files: 256,
        },
        &mutation(),
        &mut io,
    )
    .unwrap();
    (fixture, store, io)
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "c".repeat(64),
        decision: DecisionKind::Published,
        source_bytes: 32,
    }
}
fn page(store: &ObjectStore, bytes: &[u8], io: &mut Io) -> String {
    store
        .prepare_page(
            bytes,
            IoBudget {
                read_bytes: MAX_READ_BYTES,
                write_bytes: 1024 * 1024,
                new_files: 256,
            },
            &mutation(),
            io,
        )
        .unwrap()
}
fn plan(bytes: &[&[u8]]) -> WriterBatchPlan {
    let mut objects = bytes
        .iter()
        .map(|b| PlannedWriterObject {
            sha256: luma_content::sha256(b),
            bytes: b.len() as u32,
        })
        .collect::<Vec<_>>();
    objects.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    WriterBatchPlan {
        schema_version: 1,
        request_sha256: "d".repeat(64),
        batch: 0,
        objects,
    }
}
fn held(
    store: &ObjectStore,
    io: &mut Io,
) -> (HeldNamespaceObservation, File, HeldWriterObservation) {
    let ns = store.observe_namespace(read(RAW_READ), io).unwrap();
    let writer = store.acquire_writer().unwrap();
    let observed = store
        .observe_existing_writer(
            &ns,
            writer.try_clone().unwrap(),
            std::process::id(),
            read(RAW_READ),
            io,
        )
        .unwrap();
    (ns, writer, observed)
}

#[test]
fn actual_new_objects_prefixes_and_blocks_match_disposable_whole_inventory_delta() {
    let (_fixture, store, mut io) = setup();
    let before = store
        .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
        .unwrap();
    let (ns, _writer, observed) = held(&store, &mut io);
    let inputs: [&[u8]; 2] = [b"new-page-one", b"new-page-two"];
    let batch = store
        .begin_writer_batch(&ns, &observed, plan(&inputs), read(MAX_READ_BYTES), &mut io)
        .unwrap();
    for bytes in inputs {
        page(&store, bytes, &mut io);
    }
    let mut completed = store.finish_writer_batch(&ns, batch, &mut io).unwrap();
    store
        .recheck_writer_batch(&ns, &mut completed, &mut io)
        .unwrap();
    let after = store
        .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
        .unwrap();
    let delta = completed.scoped_delta();
    assert_eq!(
        delta.new_file_count(),
        after.regular_files - before.regular_files
    );
    assert_eq!(
        delta.new_directory_count(),
        after.directories - before.directories
    );
    assert_eq!(
        delta.logical_bytes(),
        after.logical_bytes - before.logical_bytes
    );
    assert_eq!(
        delta.allocated_growth_bytes(),
        after.allocated_bytes - before.allocated_bytes
    );
    let data: serde_json::Value =
        serde_json::from_slice(&delta.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        data["coverage"],
        "exact-planned-objects-and-touched-ancestors-not-whole-owner-v1"
    );
    assert!(data.get("physical_after").is_none());
}

#[test]
fn reused_members_are_not_charged_as_new_and_changed_unrelated_leaf_is_refused() {
    let (fixture, store, mut io) = setup();
    let old = b"writer-batch-fixture-97";
    let fresh = b"writer-batch-fixture-269";
    let old_sha = page(&store, old, &mut io);
    assert_eq!(&old_sha[..4], &luma_content::sha256(fresh)[..4]);
    let (ns, _writer, observed) = held(&store, &mut io);
    let batch = store
        .begin_writer_batch(&ns, &observed, plan(&[old]), read(MAX_READ_BYTES), &mut io)
        .unwrap();
    page(&store, old, &mut io);
    let completed = store.finish_writer_batch(&ns, batch, &mut io).unwrap();
    assert_eq!(completed.scoped_delta().new_file_count(), 0);
    assert_eq!(completed.scoped_delta().allocated_growth_bytes(), 0);
    drop(completed);
    let batch = store
        .begin_writer_batch(
            &ns,
            &observed,
            plan(&[fresh]),
            read(MAX_READ_BYTES),
            &mut io,
        )
        .unwrap();
    page(&store, fresh, &mut io);
    fs::set_permissions(fixture.raw(&old_sha), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(fixture.raw(&old_sha), b"changed retained bytes").unwrap();
    fs::set_permissions(fixture.raw(&old_sha), fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store.finish_writer_batch(&ns, batch, &mut io).is_err());
}

#[test]
fn preexisting_interrupted_member_refuses_before_writes_without_overwrite() {
    let (fixture, store, mut io) = setup();
    let input = b"intended complete page";
    let sha = luma_content::sha256(input);
    let path = fixture.raw(&sha);
    let second = path.parent().unwrap();
    let first = second.parent().unwrap();
    fs::DirBuilder::new().mode(0o700).create(first).unwrap();
    fs::DirBuilder::new().mode(0o700).create(second).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&path)
        .unwrap()
        .sync_all()
        .unwrap();
    let before = store
        .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
        .unwrap();
    assert_eq!(before.incomplete_objects, 1);
    let (ns, _writer, observed) = held(&store, &mut io);
    assert!(store
        .begin_writer_batch(
            &ns,
            &observed,
            plan(&[input]),
            read(MAX_READ_BYTES),
            &mut io
        )
        .is_err());
    assert_eq!(
        store
            .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
            .unwrap(),
        before
    );
    assert_eq!(fs::metadata(path).unwrap().len(), 0);
}

#[test]
fn unplanned_new_member_is_retained_but_no_scoped_completion_is_returned() {
    let (_fixture, store, mut io) = setup();
    let (ns, _writer, observed) = held(&store, &mut io);
    let batch = store
        .begin_writer_batch(
            &ns,
            &observed,
            plan(&[b"expected"]),
            read(MAX_READ_BYTES),
            &mut io,
        )
        .unwrap();
    page(&store, b"expected", &mut io);
    page(&store, b"not-in-plan", &mut io);
    assert!(store.finish_writer_batch(&ns, batch, &mut io).is_err());
    assert_eq!(
        store
            .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
            .unwrap()
            .regular_files,
        3
    );
}

#[test]
fn revocation_budget_and_finite_plan_cannot_be_replenished_or_skipped() {
    let (_fixture, store, mut io) = setup();
    let (ns, _writer, observed) = held(&store, &mut io);
    let intended = plan(&[b"bounded"]);
    assert!(store
        .begin_writer_batch(&ns, &observed, intended.clone(), read(1), &mut io)
        .is_err());
    let mut duplicate = intended.clone();
    duplicate.objects.push(duplicate.objects[0].clone());
    assert!(duplicate.validate().is_err());
    let mut excessive = intended.clone();
    excessive.objects = (0..33)
        .map(|n| PlannedWriterObject {
            sha256: format!("{n:064x}"),
            bytes: 1,
        })
        .collect();
    assert!(excessive.validate().is_err());
    let batch = store
        .begin_writer_batch(&ns, &observed, intended, read(MAX_READ_BYTES), &mut io)
        .unwrap();
    page(&store, b"bounded", &mut io);
    io.live = false;
    assert!(store.finish_writer_batch(&ns, batch, &mut io).is_err());
    io.live = true;
    assert_eq!(
        store
            .inventory(read(MAX_READ_BYTES), &mut io, |_| Ok(()))
            .unwrap()
            .regular_files,
        2
    );
}

#[test]
fn later_directory_changes_stale_the_scoped_posthandles() {
    let (_fixture, store, mut io) = setup();
    let (ns, _writer, observed) = held(&store, &mut io);
    let batch = store
        .begin_writer_batch(
            &ns,
            &observed,
            plan(&[b"first-batch"]),
            read(MAX_READ_BYTES),
            &mut io,
        )
        .unwrap();
    page(&store, b"first-batch", &mut io);
    let mut complete = store.finish_writer_batch(&ns, batch, &mut io).unwrap();
    page(&store, b"later-unreconciled-batch", &mut io);
    assert!(store
        .recheck_writer_batch(&ns, &mut complete, &mut io)
        .is_err());
}

#[test]
fn directory_delta_math_counts_existing_block_growth_and_refuses_replacement_or_shrink() {
    let (_fixture, store, mut io) = setup();
    let ns = store.observe_namespace(read(RAW_READ), &mut io).unwrap();
    let before = ns.data().objects.clone();
    // Pure arithmetic regression using captured metadata, not a manufactured
    // current observation or native allocation certificate.
    let mut grown = before.clone();
    grown.allocated_bytes += 4096;
    grown.bytes += 4096;
    assert_eq!(directory_growth(Some(&before), &grown).unwrap(), (0, 4096));
    assert_eq!(
        directory_growth(None, &grown).unwrap(),
        (1, grown.allocated_bytes)
    );
    grown.inode += 1;
    assert!(directory_growth(Some(&before), &grown).is_err());
    let mut shrink = before.clone();
    shrink.bytes = before.bytes.saturating_sub(1);
    assert!(directory_growth(Some(&before), &shrink).is_err());
}
