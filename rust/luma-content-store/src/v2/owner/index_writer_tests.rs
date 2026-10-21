//! Real private ext4/OFD writes with explicit software authorization fixtures.
//! No native C, original PAM or physical creator qualification is asserted.
use super::*;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
struct Original<'a> {
    live: Live<'a>,
    namespace: HeldNamespaceObservation,
    held: Option<HeldWriterObservation>,
    begins: usize,
    deny_admission: bool,
    deny_after_write: bool,
}
fn observation_budget() -> IoBudget {
    IoBudget {
        read_bytes: 128 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}
impl Boundary for Original<'_> {
    fn admit(&mut self, b: &OwnerBinding, r: ResourceBudget) -> Result<()> {
        if self.deny_admission {
            return Err("fixture original admission revoked".into());
        }
        self.live.admit(b, r)
    }
    fn check(&mut self, a: Access<'_>) -> Result<()> {
        self.live.check(a)
    }
}
impl OwnerBoundary for Original<'_> {
    fn current_owner_head(&mut self, h: &OwnerHeadV2) -> Result<()> {
        self.live.current_owner_head(h)
    }
    fn current_physical_accounting(&mut self, h: &OwnerHeadV2) -> Result<PhysicalInventory> {
        self.live.current_physical_accounting(h)
    }
    fn verify_prepared_allocations(&mut self, c: &AppendCommitment) -> Result<()> {
        self.live.verify_prepared_allocations(c)
    }
}
impl AppendWriterBoundary for Original<'_> {
    fn begin_writer(&mut self, h: &OwnerHeadV2, r: &str, f: &File) -> Result<()> {
        self.live.current_owner_head(h)?;
        if self.live.review.as_deref() != Some(r) || self.held.is_some() {
            return Err("fixture repeated or substituted writer".into());
        }
        let actual = self
            .live
            .store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))?;
        if actual != h.physical.observed {
            return Err("fixture bytes created before observed begin".into());
        }
        self.held = Some(self.live.store.observe_existing_writer(
            &self.namespace,
            f.try_clone()?,
            std::process::id(),
            observation_budget(),
            &mut Io,
        )?);
        self.begins += 1;
        Ok(())
    }
    fn check_writer(&mut self, h: &OwnerHeadV2, r: &str, f: &File) -> Result<()> {
        self.live.current_owner_head(h)?;
        if self.live.review.as_deref() != Some(r)
            || f.metadata()?.ino()
                != self
                    .held
                    .as_ref()
                    .ok_or("fixture missing original writer")?
                    .data()
                    .root
                    .inode
        {
            return Err("fixture observed writer changed".into());
        }
        self.live.store.check_existing_writer(
            &self.namespace,
            self.held.as_ref().unwrap(),
            observation_budget(),
            &mut Io,
        )?;
        if self.deny_after_write
            && self
                .live
                .store
                .inventory(owner::read_budget(), &mut Io, |_| Ok(()))?
                .regular_files
                > h.physical.observed.regular_files
        {
            return Err("fixture revoked after actual allocation".into());
        }
        Ok(())
    }
}
fn original<'a>(store: &'a ObjectStore, state: Rc<RefCell<State>>) -> Original<'a> {
    Original {
        live: Live {
            store,
            state,
            review: Some("d".repeat(64)),
        },
        namespace: store
            .observe_namespace(observation_budget(), &mut Io)
            .unwrap(),
        held: None,
        begins: 0,
        deny_admission: false,
        deny_after_write: false,
    }
}
fn mutation() -> Mutation {
    Mutation {
        review_sha256: "d".repeat(64),
        decision: DecisionKind::Published,
        source_bytes: 7,
    }
}

#[test]
fn original_admission_precedes_observed_begin_and_any_new_object() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let before = store
        .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    let mut authority = original(&store, state);
    authority.deny_admission = true;
    assert!(store
        .prepare_index_observed(&head, &mutation(), budget(), &mut authority)
        .is_err());
    assert_eq!(authority.begins, 0);
    assert_eq!(
        store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
            .unwrap(),
        before
    );
    assert!(store.acquire_writer().is_ok());
}
#[test]
fn exact_metadata_callback_runs_before_effect_and_same_writer_remains_held() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut authority = original(&store, state.clone());
    let writer = store
        .prepare_index_observed(&head, &mutation(), budget(), &mut authority)
        .unwrap();
    assert_eq!(authority.begins, 1);
    assert!(store.acquire_writer().is_err());
    let before = store
        .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    assert!(writer
        .prepare_blob(b"private", budget(), &mutation(), &mut authority, |_| Err(
            "fixture exact C metadata reservation absent".into()
        ))
        .is_err());
    assert_eq!(
        store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
            .unwrap(),
        before
    );
    let mut checks = 0;
    let reference = writer
        .prepare_blob(b"private", budget(), &mutation(), &mut authority, |_| {
            checks += 1;
            Ok(())
        })
        .unwrap();
    assert!(checks > 4);
    assert_eq!(
        store
            .read_blob(&reference, owner::read_budget(), &mut Io)
            .unwrap(),
        b"private"
    );
    assert_eq!(authority.begins, 1);
    assert!(store.acquire_writer().is_err());
    state.borrow_mut().revoked = true;
    assert!(writer.check(&mut authority).is_err());
    drop(writer);
    assert!(store.acquire_writer().is_err());
    drop(authority);
    assert!(store.acquire_writer().is_ok());
}
#[test]
fn original_loss_after_actual_allocation_withholds_result_and_retains_files() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut authority = original(&store, state);
    let writer = store
        .prepare_index_observed(&head, &mutation(), budget(), &mut authority)
        .unwrap();
    authority.deny_after_write = true;
    assert!(writer
        .prepare_blob(
            b"private",
            budget(),
            &mutation(),
            &mut authority,
            |_| Ok(())
        )
        .is_err());
    let after = store
        .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    assert!(after.regular_files > head.physical.observed.regular_files);
    assert!(store.acquire_writer().is_err());
}
