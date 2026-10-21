use super::*;

/// A separately authenticated foreign-origin snapshot is inert DATA, never a
/// local current-owner head. Native adapters independently retain the pinned
/// whole-origin signature and current local Admin/source-Read/job observations.
pub trait SnapshotReadBoundary: Boundary {
    fn authenticated_snapshot(&mut self, manifest: &WholeSnapshotManifest) -> Result<()>;
}
struct Source<'a, B: RestoreBoundary> {
    boundary: &'a mut B,
    window: CheckedWindow<'a>,
}
impl<B: RestoreBoundary> Boundary for Source<'_, B> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.window.current(self.boundary)?;
        if binding != &self.window.manifest.intent.head.binding {
            return Err("snapshot source read retargets old origin".into());
        }
        self.boundary.admit(binding, budget)?;
        self.window.current(self.boundary)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.window.current(self.boundary)?;
        self.boundary.check(access)?;
        self.window.current(self.boundary)
    }
}
pub fn read_snapshot_outcome<B: RestoreBoundary>(
    store: &ObjectStore,
    manifest: &WholeSnapshotManifest,
    prefix: &RestorePrefix,
    ordinal: u64,
    budget: IoBudget,
    b: &mut B,
) -> Result<StoredOutcome> {
    live(manifest, prefix, None, b)?;
    if prefix.stage != RestoreStage::Replaying || ordinal != prefix.next_source_ordinal {
        return Err("snapshot source read is not the exact current chronological window".into());
    }
    b.verify_origin_namespace(manifest, prefix, store)?;
    store.check_root(&manifest.intent.head.roots.artifacts)?;
    let mut source = Source {
        boundary: b,
        window: CheckedWindow::new(manifest, prefix, None)?,
    };
    let mut guard = Guard::new(&mut source, &manifest.intent.head.binding, budget, None)?;
    let result = store.owner_outcome(&manifest.intent.head, ordinal, &mut guard)?;
    guard.check()?;
    Ok(result)
}
pub(super) fn source_boundary<'a, B: RestoreBoundary>(
    manifest: &'a WholeSnapshotManifest,
    prefix: &'a RestorePrefix,
    review: Option<&'a RestoreWindowReview>,
    b: &'a mut B,
) -> Result<impl Boundary + 'a> {
    Ok(Source {
        boundary: b,
        window: CheckedWindow::new(manifest, prefix, review)?,
    })
}
