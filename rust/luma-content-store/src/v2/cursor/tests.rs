//! Actual immutable map files, with explicit disposable-data authority only.
use super::*;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var("LUMA_STORAGE_TEST_ROOT").expect("disposable ext4 required");
        let root = Path::new(&base).join(format!(
            "map-cursor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct FixtureBoundary {
    binding: OwnerBinding,
    selected: MapRoot,
    checks: usize,
    revoke_at: Option<usize>,
}
impl Boundary for FixtureBoundary {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if binding != &self.binding || budget.tasks != 1 || budget.memory_bytes > 192 * 1024 * 1024
        {
            return Err("fixture map admission differs".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        let binding = match access {
            Access::Inspect { binding } | Access::Mutate { binding, .. } => binding,
            Access::Recover { .. } => return Err("fixture has no recovery authority".into()),
        };
        if binding != &self.binding {
            return Err("fixture owner differs".into());
        }
        Ok(())
    }
}
impl MapCursorBoundary for FixtureBoundary {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.checks += 1;
        if root != &self.selected || self.revoke_at.is_some_and(|at| self.checks >= at) {
            return Err("fixture selected map or original authority changed".into());
        }
        Ok(())
    }
}
fn setup(
    fixture: &Fixture,
    count: usize,
) -> (ObjectStore, FixtureBoundary, Vec<(String, Vec<u8>)>) {
    let binding = OwnerBinding {
        installation: "11".repeat(32),
        owner: "22".repeat(32),
        owner_generation: 7,
    };
    let mut root = MapRoot::empty(&binding, MapKind::Corpus).unwrap();
    let mut boundary = FixtureBoundary {
        binding: binding.clone(),
        selected: root.clone(),
        checks: 0,
        revoke_at: None,
    };
    let mutation = Mutation {
        review_sha256: "33".repeat(32),
        decision: DecisionKind::Published,
        source_bytes: 1,
    };
    let store = ObjectStore::create_at(
        &fixture.0,
        &binding,
        write_budget(),
        &mutation,
        &mut boundary,
    )
    .unwrap();
    let mut entries = (0..count)
        .map(|n| {
            (
                root.key(format!("doc-{n}").as_bytes()).unwrap(),
                format!("value-{n}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for batch in entries.chunks(128) {
        root = store
            .prepare_map(
                &root,
                &batch
                    .iter()
                    .map(|(key, value)| MapEdit {
                        key: key.clone(),
                        expected_value_sha256: None,
                        value: Some(value.clone()),
                    })
                    .collect::<Vec<_>>(),
                write_budget(),
                &mutation,
                &mut boundary,
            )
            .unwrap();
    }
    boundary.selected = root;
    (store, boundary, entries)
}
fn write_budget() -> IoBudget {
    IoBudget {
        read_bytes: 64 * 1024 * 1024,
        write_bytes: 16 * 1024 * 1024,
        new_files: 8192,
    }
}
fn read_budget() -> IoBudget {
    IoBudget {
        read_bytes: 16 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}

#[test]
fn bounded_windows_cover_actual_map_once_in_order_and_reject_resume_after_completion() {
    let fixture = Fixture::new();
    let (store, mut boundary, expected) = setup(&fixture, 277);
    let root = boundary.selected.clone();
    let mut cursor = MapCursor::beginning(&root).unwrap();
    let mut rows = Vec::new();
    loop {
        let bytes = cursor.canonical_bytes(&root).unwrap();
        cursor = MapCursor::from_canonical(&bytes, &root).unwrap();
        let window = store
            .scan_map_window(&root, &cursor, 17, read_budget(), &mut boundary)
            .unwrap();
        assert!(window.entries.len() <= 17);
        rows.extend(window.entries);
        assert_eq!(window.next.after_count(), rows.len() as u64);
        cursor = window.next;
        if window.complete {
            break;
        }
    }
    assert_eq!(rows, expected);
    assert!(store
        .scan_map_window(&root, &cursor, 17, read_budget(), &mut boundary)
        .is_err());
}

#[test]
fn changed_root_forged_rank_absent_key_and_noncanonical_checkpoint_refuse() {
    let fixture = Fixture::new();
    let (store, mut boundary, _) = setup(&fixture, 27);
    let root = boundary.selected.clone();
    let first = store
        .scan_map_window(
            &root,
            &MapCursor::beginning(&root).unwrap(),
            9,
            read_budget(),
            &mut boundary,
        )
        .unwrap();
    let mut forged = first.next.clone();
    forged.after_count += 1;
    assert!(store
        .scan_map_window(&root, &forged, 9, read_budget(), &mut boundary)
        .is_err());
    forged = first.next.clone();
    forged.after_key = Some(root.key(b"absent key").unwrap());
    assert!(store
        .scan_map_window(&root, &forged, 9, read_budget(), &mut boundary)
        .is_err());
    let mut wrong = root.clone();
    wrong.kind = MapKind::Retained;
    assert!(store
        .scan_map_window(&wrong, &first.next, 9, read_budget(), &mut boundary)
        .is_err());
    boundary.selected = wrong;
    assert!(store
        .scan_map_window(&root, &first.next, 9, read_budget(), &mut boundary)
        .is_err());
    let mut bytes = first.next.canonical_bytes(&root).unwrap();
    bytes.push(b'\n');
    assert!(MapCursor::from_canonical(&bytes, &root).is_err());
}

#[test]
fn budget_exhaustion_and_mid_traversal_revocation_withhold_the_entire_window() {
    let fixture = Fixture::new();
    let (store, mut boundary, _) = setup(&fixture, 25);
    let root = boundary.selected.clone();
    let cursor = MapCursor::beginning(&root).unwrap();
    assert!(store
        .scan_map_window(
            &root,
            &cursor,
            256,
            IoBudget {
                read_bytes: 1,
                write_bytes: 0,
                new_files: 0
            },
            &mut boundary
        )
        .is_err());
    boundary.revoke_at = Some(boundary.checks + 10);
    assert!(store
        .scan_map_window(&root, &cursor, 256, read_budget(), &mut boundary)
        .is_err());
    assert!(boundary.checks >= boundary.revoke_at.unwrap());
    assert!(store
        .scan_map_window(&root, &cursor, 257, read_budget(), &mut boundary)
        .is_err());
}

#[test]
fn independently_selected_empty_map_has_exact_empty_completion_not_an_invented_page() {
    let fixture = Fixture::new();
    let (store, mut boundary, _) = setup(&fixture, 0);
    let root = boundary.selected.clone();
    let window = store
        .scan_map_window(
            &root,
            &MapCursor::beginning(&root).unwrap(),
            1,
            read_budget(),
            &mut boundary,
        )
        .unwrap();
    assert!(window.entries.is_empty());
    assert!(window.complete);
    assert_eq!(window.next.after_count(), 0);
}
