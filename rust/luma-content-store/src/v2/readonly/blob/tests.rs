//! Explicit fixture boundaries and byte readers are not production authority.
use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;
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
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
fn writable() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024 * 1024,
        write_bytes: 32 * 1024 * 1024,
        new_files: 4096,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "53".repeat(32),
        decision: DecisionKind::Published,
        source_bytes: 0,
    }
}
struct Current {
    selected: Option<BlobReference>,
    live: Rc<Cell<bool>>,
    checks: usize,
    admissions: usize,
    write: bool,
}
impl Boundary for Current {
    fn admit(&mut self, owner: &OwnerBinding, b: ResourceBudget) -> Result<()> {
        if !self.live.get()
            || owner != &binding()
            || b.tasks != 1
            || b.memory_bytes > 192 * 1024 * 1024
            || (!self.write && (b.write_bytes != 0 || b.additional_storage_bytes != 0))
        {
            return Err("fixture finite admission refused".into());
        }
        self.admissions += 1;
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if !self.live.get() {
            return Err("fixture original Read revoked".into());
        }
        match access {
            Access::Inspect { binding: owner } if owner == &binding() => Ok(()),
            Access::Mutate {
                binding: owner,
                review_sha256,
                ..
            } if self.write && owner == &binding() && review_sha256 == "53".repeat(32) => Ok(()),
            _ => Err("fixture exact original operation refused".into()),
        }
    }
}
impl CurrentBlobBoundary for Current {
    fn current_blob(&mut self, reference: &BlobReference) -> Result<()> {
        if !self.live.get() || self.selected.as_ref() != Some(reference) {
            return Err("fixture exact source is not current".into());
        }
        Ok(())
    }
}
struct Reader {
    bytes: BTreeMap<String, Vec<u8>>,
    reads: usize,
    live: Rc<Cell<bool>>,
    revoke_at: Option<usize>,
    tamper_at: Option<usize>,
    missing_at: Option<usize>,
    oversize_at: Option<usize>,
}
impl ObservedPageReader for Reader {
    fn read_observed_page(
        &mut self,
        owner: &OwnerBinding,
        sha: &str,
        max: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        assert_eq!(owner, &binding());
        assert_eq!(max, MAX_PAGE_BYTES);
        check()?;
        self.reads += 1;
        if self.missing_at == Some(self.reads) {
            return Err("fixture missing member".into());
        }
        let mut bytes = self.bytes.get(sha).ok_or("fixture absent hash")?.clone();
        if self.tamper_at == Some(self.reads) {
            bytes[0] ^= 1;
        }
        if self.oversize_at == Some(self.reads) {
            bytes.resize(MAX_PAGE_BYTES + 1, 0);
        }
        if self.revoke_at == Some(self.reads) {
            self.live.set(false);
        }
        check()?;
        Ok(bytes)
    }
}
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture(bytes: &[u8]) -> (Fixture, ObjectStore, BlobReference, Reader, Current) {
    let base = std::env::var("LUMA_STORAGE_TEST_ROOT").expect("requires disposable ext4");
    let path = Path::new(&base).join(format!(
        "observed-blob-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let live = Rc::new(Cell::new(true));
    let mut current = Current {
        selected: None,
        live: Rc::clone(&live),
        checks: 0,
        admissions: 0,
        write: true,
    };
    let store =
        ObjectStore::create_at(&path, &binding(), writable(), &mutation(), &mut current).unwrap();
    let reference = store
        .prepare_blob(bytes, writable(), &mutation(), &mut current)
        .unwrap();
    let mut reader = Reader {
        bytes: BTreeMap::new(),
        reads: 0,
        live,
        revoke_at: None,
        tamper_at: None,
        missing_at: None,
        oversize_at: None,
    };
    store
        .visit_raw_objects_checked(budget(), &mut current, |sha, allocation, bytes, _| {
            assert!(allocation.complete);
            reader.bytes.insert(sha.into(), bytes.into());
            Ok(())
        })
        .unwrap();
    current.write = false;
    current.selected = Some(reference.clone());
    (Fixture(path), store, reference, reader, current)
}

#[test]
fn real_store_and_observed_whole_and_cross_group_ranges_use_identical_commitments() {
    let source = (0..MAX_PAGE_BYTES * 65 + 19)
        .map(|n| ((n * 73 + n / 8191) % 251) as u8)
        .collect::<Vec<_>>();
    let (_fixture, store, reference, mut reader, mut current) = fixture(&source);
    assert_eq!(
        store.read_blob(&reference, budget(), &mut current).unwrap(),
        source
    );
    assert_eq!(
        read_current(&reference, budget(), &mut reader, &mut current).unwrap(),
        source
    );
    assert_eq!(reader.reads, 69); // index + two groups +66 data chunks
    for offset in [MAX_PAGE_BYTES as u64 - 7, (MAX_PAGE_BYTES * 64) as u64 - 7] {
        let actual =
            read_range_current(&reference, offset, 29, budget(), &mut reader, &mut current)
                .unwrap();
        assert_eq!(actual, source[offset as usize..offset as usize + 29]);
        assert_eq!(
            actual,
            store
                .read_blob_range(&reference, offset, 29, budget(), &mut current)
                .unwrap()
        );
    }
}

#[test]
fn empty_sources_require_current_authority_without_observer_io() {
    let (_fixture, _store, reference, mut reader, mut current) = fixture(&[]);
    assert_eq!(
        read_current(&reference, budget(), &mut reader, &mut current).unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(reader.reads, 0);
    let admissions = current.admissions;
    current.live.set(false);
    assert!(read_current(&reference, budget(), &mut reader, &mut current).is_err());
    assert_eq!(current.admissions, admissions);
    assert_eq!(reader.reads, 0);
}

#[test]
fn foreign_unselected_ranges_and_write_budgets_refuse_before_transport() {
    let (_fixture, _store, reference, mut reader, mut current) = fixture(b"source");
    let mut foreign = reference.clone();
    foreign.binding.owner_generation += 1;
    assert!(read_current(&foreign, budget(), &mut reader, &mut current).is_err());
    assert!(
        read_range_current(&reference, u64::MAX, 1, budget(), &mut reader, &mut current).is_err()
    );
    assert!(read_range_current(
        &reference,
        0,
        MAX_PAGE_BYTES as u64 + 1,
        budget(),
        &mut reader,
        &mut current
    )
    .is_err());
    assert!(read_current(&reference, writable(), &mut reader, &mut current).is_err());
    assert_eq!(reader.reads, 0);
}

#[test]
fn each_full_response_and_eof_probe_is_reserved_before_its_read() {
    let (_fixture, _store, reference, mut reader, mut current) = fixture(b"source");
    let mut small = budget();
    small.read_bytes = MAX_PAGE_BYTES as u64;
    assert!(read_current(&reference, small, &mut reader, &mut current).is_err());
    assert_eq!(reader.reads, 0);
    small.read_bytes = 2 * (MAX_PAGE_BYTES as u64 + 1);
    assert!(read_current(&reference, small, &mut reader, &mut current).is_err());
    assert_eq!(reader.reads, 2);
}

#[test]
fn tampered_missing_oversized_and_midread_revoked_members_never_return_bytes() {
    for mode in 0..4 {
        for read in 1..=3 {
            let (_fixture, _store, reference, mut reader, mut current) = fixture(b"source");
            match mode {
                0 => reader.tamper_at = Some(read),
                1 => reader.missing_at = Some(read),
                2 => reader.oversize_at = Some(read),
                _ => reader.revoke_at = Some(read),
            }
            assert!(read_current(&reference, budget(), &mut reader, &mut current).is_err());
            assert_eq!(reader.reads, read);
        }
    }
}

#[test]
fn whole_hash_is_distinct_from_a_valid_merkle_range_commitment() {
    let (_fixture, _store, mut reference, mut reader, mut current) = fixture(b"source");
    reference.sha256 = "64".repeat(32);
    current.selected = Some(reference.clone());
    // A range proves its selected Merkle path only; whole-source verification
    // additionally detects a substituted content commitment.
    assert_eq!(
        read_range_current(&reference, 1, 3, budget(), &mut reader, &mut current).unwrap(),
        b"our"
    );
    assert!(read_current(&reference, budget(), &mut reader, &mut current).is_err());
}

#[test]
fn rehashed_index_with_false_owner_or_coverage_is_not_a_valid_observation() {
    for mode in 0..3 {
        let (_fixture, _store, mut reference, mut reader, mut current) = fixture(b"source");
        let old = reference.index_sha256.as_ref().unwrap();
        // preserve canonical field order by replacing exact bytes, rather than
        // converting through an unordered JSON object representation.
        let encoded = std::str::from_utf8(reader.bytes.get(old).unwrap()).unwrap();
        let changed = match mode {
            0 => encoded.replacen(
                &format!("\"owner\":\"{}\"", "42".repeat(32)),
                &format!("\"owner\":\"{}\"", "75".repeat(32)),
                1,
            ),
            1 => encoded.replacen("\"bytes\":6", "\"bytes\":5", 1),
            _ => encoded.replacen("\"chunks\":1", "\"chunks\":2", 1),
        }
        .into_bytes();
        assert_ne!(&changed, reader.bytes.get(old).unwrap());
        let sha = luma_content::sha256(&changed);
        reader.bytes.insert(sha.clone(), changed);
        reference.index_sha256 = Some(sha);
        current.selected = Some(reference.clone());
        assert!(read_current(&reference, budget(), &mut reader, &mut current).is_err());
        assert_eq!(reader.reads, 1);
    }
}
