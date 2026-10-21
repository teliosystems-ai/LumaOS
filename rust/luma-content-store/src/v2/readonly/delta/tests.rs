//! Canonical page fixtures and explicit in-memory boundaries, not native C.
use super::*;
use crate::v2::page::{Body, Entry, Page};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "81".repeat(32),
        owner: "92".repeat(32),
        owner_generation: 1,
    }
}
fn key(n: u32) -> String {
    format!("{n:064x}")
}
fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 32 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
struct Memory(BTreeMap<String, Vec<u8>>);
impl MapIo for Memory {
    fn check(&mut self) -> Result<()> {
        Ok(())
    }
    fn read(&mut self, sha: &str) -> Result<Vec<u8>> {
        self.0
            .get(sha)
            .cloned()
            .ok_or_else(|| "fixture missing canonical page".into())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.insert(luma_content::sha256(bytes), bytes.to_vec());
        Ok(())
    }
}
struct Reader {
    pages: BTreeMap<String, Vec<u8>>,
    reads: usize,
    live: Rc<Cell<bool>>,
    revoke: Option<usize>,
    tamper: Option<usize>,
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
        let mut bytes = self
            .pages
            .get(sha)
            .ok_or("fixture missing observed member")?
            .clone();
        if self.tamper == Some(self.reads) {
            bytes[0] ^= 1;
        }
        if self.revoke == Some(self.reads) {
            self.live.set(false);
        }
        check()?;
        Ok(bytes)
    }
}
struct Current {
    base: MapRoot,
    proposed: MapRoot,
    edits: Vec<MapEdit>,
    live: Rc<Cell<bool>>,
    checks: usize,
    admitted: usize,
}
impl Boundary for Current {
    fn admit(&mut self, owner: &OwnerBinding, b: ResourceBudget) -> Result<()> {
        if owner != &binding()
            || b.memory_bytes != 192 * 1024 * 1024
            || b.tasks != 1
            || b.write_bytes != 0
            || b.additional_storage_bytes != 0
            || !self.live.get()
        {
            return Err("fixture finite read-only delta admission refused".into());
        }
        self.admitted += 1;
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        match access {
            Access::Inspect { binding: owner } if owner == &binding() && self.live.get() => Ok(()),
            _ => Err("fixture original reviewed operation revoked".into()),
        }
    }
}
impl MapCursorBoundary for Current {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.base || !self.live.get() {
            return Err("fixture selected base changed".into());
        }
        Ok(())
    }
}
impl CurrentDeltaBoundary for Current {
    fn current_delta(&mut self, base: &MapRoot, edits: &[MapEdit], next: &MapRoot) -> Result<()> {
        if base != &self.base || next != &self.proposed || edits != self.edits || !self.live.get() {
            return Err("fixture original exact reviewed proposal differs".into());
        }
        Ok(())
    }
}
fn fixture() -> (MapRoot, Vec<MapEdit>, MapRoot, Reader, Current) {
    let (bytes, page) = Page::new(
        &binding(),
        MapKind::Artifacts,
        Body::Leaf {
            entries: (1..=8)
                .map(|n| Entry {
                    key: key(n * 2),
                    value: vec![n as u8],
                })
                .collect(),
        },
    )
    .encode()
    .unwrap();
    let base = MapRoot {
        schema_version: 1,
        domain: DOMAIN.into(),
        binding: binding(),
        kind: MapKind::Artifacts,
        page: Some(page.clone()),
        entry_count: 8,
    };
    let edits = vec![MapEdit {
        key: key(1),
        expected_value_sha256: None,
        value: Some(vec![19]),
    }];
    let mut memory = Memory(BTreeMap::from([(page.sha256, bytes)]));
    let proposed = derive_delta(&base, &edits, &mut memory, true, false).unwrap();
    let live = Rc::new(Cell::new(true));
    let reader = Reader {
        pages: memory.0,
        reads: 0,
        live: Rc::clone(&live),
        revoke: None,
        tamper: None,
    };
    let current = Current {
        base: base.clone(),
        proposed: proposed.clone(),
        edits: edits.clone(),
        live,
        checks: 0,
        admitted: 0,
    };
    (base, edits, proposed, reader, current)
}

#[test]
fn original_packer_exact_cas_split_and_readonly_replay_are_identical() {
    let (base, edits, proposed, mut reader, mut current) = fixture();
    assert_eq!(proposed.entry_count, 9);
    assert_eq!(
        verify_current(
            &base,
            &edits,
            &proposed,
            budget(),
            &mut reader,
            &mut current
        )
        .unwrap(),
        proposed
    );
    assert_eq!(current.admitted, 1);
    assert!(current.checks >= reader.reads * 2);
    let mut memory = Memory(reader.pages.clone());
    let changes = vec![
        MapEdit {
            key: key(2),
            expected_value_sha256: Some(luma_content::sha256(&[1])),
            value: Some(vec![91]),
        },
        MapEdit {
            key: key(6),
            expected_value_sha256: Some(luma_content::sha256(&[3])),
            value: None,
        },
    ];
    let next = derive_delta(&proposed, &changes, &mut memory, true, false).unwrap();
    current.base = proposed.clone();
    current.proposed = next.clone();
    current.edits = changes.clone();
    reader.pages = memory.0;
    assert_eq!(
        verify_current(
            &proposed,
            &changes,
            &next,
            budget(),
            &mut reader,
            &mut current
        )
        .unwrap(),
        next
    );
}

#[test]
fn missing_split_sibling_with_only_old_keys_is_still_required() {
    let (base, edits, proposed, mut reader, mut current) = fixture();
    let root = proposed.page.as_ref().unwrap();
    let page = Page::decode(
        reader.pages.get(&root.sha256).unwrap(),
        &binding(),
        MapKind::Artifacts,
        root,
    )
    .unwrap();
    let children = match page.body {
        Body::Branch { children } => children,
        _ => panic!("actual split expected"),
    };
    let sibling = children.last().unwrap();
    assert_eq!(sibling.first_key, key(16));
    assert_ne!(sibling.sha256, base.page.as_ref().unwrap().sha256);
    reader.pages.remove(&sibling.sha256).unwrap();
    assert!(verify_current(
        &base,
        &edits,
        &proposed,
        budget(),
        &mut reader,
        &mut current
    )
    .is_err());
}

#[test]
fn physically_missing_intermediate_page_cannot_hide_behind_a_valid_final_root() {
    let (base, mut edits, _proposed, reader, mut current) = fixture();
    edits.push(MapEdit {
        key: key(3),
        expected_value_sha256: None,
        value: Some(vec![21]),
    });
    let mut memory = Memory(reader.pages.clone());
    let first = derive_delta(&base, &edits[..1], &mut memory, true, false).unwrap();
    let proposed = derive_delta(&base, &edits, &mut memory, true, false).unwrap();
    assert_ne!(first, proposed);
    let intermediate = first.page.unwrap().sha256;
    memory.0.remove(&intermediate).unwrap();
    let mut reader = Reader {
        pages: memory.0,
        ..reader
    };
    current.edits = edits.clone();
    current.proposed = proposed.clone();
    assert!(verify_current(
        &base,
        &edits,
        &proposed,
        budget(),
        &mut reader,
        &mut current
    )
    .is_err());
}

#[test]
fn live_scope_revocation_and_corrupted_observation_withhold_replay() {
    for tamper in [false, true] {
        let (base, edits, proposed, mut reader, mut current) = fixture();
        if tamper {
            reader.tamper = Some(2);
        } else {
            reader.revoke = Some(2);
        }
        assert!(verify_current(
            &base,
            &edits,
            &proposed,
            budget(),
            &mut reader,
            &mut current
        )
        .is_err());
        assert_eq!(reader.reads, 2);
    }
}

#[test]
fn changed_original_review_and_finite_budgets_refuse_before_byte_consumption() {
    let (base, edits, proposed, mut reader, mut current) = fixture();
    let mut changed = edits.clone();
    changed[0].value = Some(vec![20]);
    assert!(verify_current(
        &base,
        &changed,
        &proposed,
        budget(),
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
    let mut small = budget();
    small.read_bytes = MAX_PAGE_BYTES as u64;
    assert!(verify_current(&base, &edits, &proposed, small, &mut reader, &mut current).is_err());
    assert_eq!(reader.reads, 0);
    let mut writable = budget();
    writable.write_bytes = 1;
    writable.new_files = 1;
    assert!(verify_current(
        &base,
        &edits,
        &proposed,
        writable,
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
}

#[test]
fn reviewed_false_next_and_conflicting_cas_are_independently_rejected() {
    let (base, edits, _proposed, mut reader, mut current) = fixture();
    current.proposed = base.clone();
    assert!(verify_current(&base, &edits, &base, budget(), &mut reader, &mut current).is_err());
    let mut edits = edits;
    edits[0].expected_value_sha256 = Some("a3".repeat(32));
    current.edits = edits.clone();
    assert!(verify_current(&base, &edits, &base, budget(), &mut reader, &mut current).is_err());
}
