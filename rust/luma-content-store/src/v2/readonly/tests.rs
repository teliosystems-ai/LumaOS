//! Canonical page fixtures, not a deployed observer or original C authority.
use super::*;
use crate::v2::page::Entry;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "11".repeat(32),
        owner: "22".repeat(32),
        owner_generation: 1,
    }
}
fn budget(pages: u64) -> IoBudget {
    IoBudget {
        read_bytes: pages * (MAX_PAGE_BYTES as u64 + 1),
        write_bytes: 0,
        new_files: 0,
    }
}
struct Current {
    selected: MapRoot,
    live: Rc<Cell<bool>>,
    checks: u64,
    admitted: u64,
}
impl Boundary for Current {
    fn admit(&mut self, owner: &OwnerBinding, b: ResourceBudget) -> Result<()> {
        if owner != &self.selected.binding
            || b.memory_bytes != 1024 * 1024
            || b.tasks != 1
            || b.write_bytes != 0
            || b.additional_storage_bytes != 0
        {
            return Err("fixture finite read-only admission refused".into());
        }
        self.admitted += 1;
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if !self.live.get() {
            return Err("fixture original operation revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.selected.binding => Ok(()),
            _ => Err("fixture observer cannot mutate or switch owner".into()),
        }
    }
}
impl MapCursorBoundary for Current {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        if root != &self.selected || !self.live.get() {
            return Err("fixture independently selected map changed".into());
        }
        Ok(())
    }
}
struct Reader {
    bytes: BTreeMap<String, Vec<u8>>,
    reads: usize,
    tamper: bool,
    missing: bool,
    revoke_after: Option<usize>,
    live: Rc<Cell<bool>>,
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
        let mut bytes = if self.missing {
            return Err("fixture missing actual observed page".into());
        } else {
            self.bytes.get(sha).ok_or("fixture page absent")?.clone()
        };
        if self.tamper {
            bytes[0] ^= 1;
        }
        if self.revoke_after == Some(self.reads) {
            self.live.set(false);
        }
        check()?;
        Ok(bytes)
    }
}
fn fixture() -> (MapRoot, Reader, Current) {
    let live = Rc::new(Cell::new(true));
    let mut reader = Reader {
        bytes: BTreeMap::new(),
        reads: 0,
        tamper: false,
        missing: false,
        revoke_after: None,
        live: Rc::clone(&live),
    };
    let mut children = Vec::new();
    for id in [1_u8, 3] {
        let (bytes, page) = Page::new(
            &binding(),
            MapKind::Artifacts,
            Body::Leaf {
                entries: vec![Entry {
                    key: format!("{id:064x}"),
                    value: vec![id],
                }],
            },
        )
        .encode()
        .unwrap();
        reader.bytes.insert(page.sha256.clone(), bytes);
        children.push(page);
    }
    let (bytes, page) = Page::new(&binding(), MapKind::Artifacts, Body::Branch { children })
        .encode()
        .unwrap();
    reader.bytes.insert(page.sha256.clone(), bytes);
    let root = MapRoot {
        schema_version: 1,
        domain: DOMAIN.into(),
        binding: binding(),
        kind: MapKind::Artifacts,
        page: Some(page),
        entry_count: 2,
    };
    let current = Current {
        selected: root.clone(),
        live,
        checks: 0,
        admitted: 0,
    };
    (root, reader, current)
}

#[test]
fn actual_canonical_branch_membership_and_gap_absence_share_the_local_verifier() {
    let (root, mut reader, mut current) = fixture();
    let proof = lookup_current(
        &root,
        &format!("{:064x}", 3),
        budget(2),
        &mut reader,
        &mut current,
    )
    .unwrap();
    assert_eq!(proof.verify(&root).unwrap(), Some(vec![3]));
    assert_eq!(reader.reads, 2);
    let gap = lookup_current(
        &root,
        &format!("{:064x}", 2),
        budget(1),
        &mut reader,
        &mut current,
    )
    .unwrap();
    assert_eq!(gap.verify(&root).unwrap(), None);
    assert_eq!(gap.pages.len(), 1);
    assert!(current.checks >= 10);
    assert_eq!(current.admitted, 2);
}

#[test]
fn reserved_read_capacity_and_exact_selected_owner_refuse_before_observer_io() {
    let (root, mut reader, mut current) = fixture();
    let mut too_small = budget(1);
    too_small.read_bytes -= 1;
    assert!(lookup_current(
        &root,
        &format!("{:064x}", 1),
        too_small,
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
    let mut changed = root.clone();
    changed.binding.owner = "33".repeat(32);
    assert!(lookup_current(
        &changed,
        &format!("{:064x}", 1),
        budget(2),
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
    let mut writes = budget(2);
    writes.write_bytes = 1;
    writes.new_files = 1;
    assert!(lookup_current(
        &root,
        &format!("{:064x}", 1),
        writes,
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
}

#[test]
fn tampered_missing_and_midread_revoked_observations_never_return_a_proof() {
    for which in 0..3 {
        let (root, mut reader, mut current) = fixture();
        match which {
            0 => reader.tamper = true,
            1 => reader.missing = true,
            _ => reader.revoke_after = Some(1),
        }
        assert!(lookup_current(
            &root,
            &format!("{:064x}", 1),
            budget(2),
            &mut reader,
            &mut current
        )
        .is_err());
    }
}

#[test]
fn empty_map_still_needs_live_selection_but_does_not_consult_an_observer() {
    let (_, mut reader, mut current) = fixture();
    let root = MapRoot::empty(&binding(), MapKind::Artifacts).unwrap();
    current.selected = root.clone();
    let proof = lookup_current(
        &root,
        &format!("{:064x}", 1),
        budget(1),
        &mut reader,
        &mut current,
    )
    .unwrap();
    assert_eq!(proof.verify(&root).unwrap(), None);
    assert_eq!(reader.reads, 0);
    current.live.set(false);
    assert!(lookup_current(
        &root,
        &format!("{:064x}", 1),
        budget(1),
        &mut reader,
        &mut current
    )
    .is_err());
    assert_eq!(reader.reads, 0);
}
