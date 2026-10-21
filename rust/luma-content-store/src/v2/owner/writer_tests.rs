//! Actual append/files/flock callbacks with software-selected fixture heads.
//! These tests do not supply native C preregistration or a creator attestation.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::os::fd::AsRawFd;
fn observation_budget() -> IoBudget {
    IoBudget { read_bytes: 128 * 1024, write_bytes: 0, new_files: 0 }
}
struct Observer<'a> {
    store: &'a ObjectStore,
    namespace: HeldNamespaceObservation,
    held: Option<HeldWriterObservation>,
    base: OwnerHeadV2,
    review: String,
    begins: usize,
    checks: usize,
    deny_begin: bool,
    deny_after_write: bool,
}
impl<'a> Observer<'a> {
    fn new(store: &'a ObjectStore, head: &OwnerHeadV2, plan: &OwnerPlan) -> Self {
        Self {
            store,
            namespace: store
                .observe_namespace(observation_budget(), &mut Io)
                .unwrap(),
            held: None,
            base: head.clone(),
            review: plan.review_sha256().into(),
            begins: 0,
            checks: 0,
            deny_begin: false,
            deny_after_write: false,
        }
    }
}
impl AppendWriterBoundary for Observer<'_> {
    fn begin_writer(
        &mut self,
        base: &OwnerHeadV2,
        review: &str,
        writer: &std::fs::File,
    ) -> Result<()> {
        self.begins += 1;
        if self.deny_begin || base != &self.base || review != self.review || self.held.is_some() {
            return Err("fixture exact original observed begin refused".into());
        }
        let actual = self
            .store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))?;
        if actual != base.physical.observed {
            return Err("preparation wrote before observed begin".into());
        }
        self.held = Some(self.store.observe_existing_writer(
            &self.namespace,
            writer.try_clone()?,
            std::process::id(),
            observation_budget(),
            &mut Io,
        )?);
        Ok(())
    }
    fn check_writer(
        &mut self,
        base: &OwnerHeadV2,
        review: &str,
        writer: &std::fs::File,
    ) -> Result<()> {
        self.checks += 1;
        if base != &self.base || review != self.review {
            return Err("fixture observed original source changed".into());
        }
        let held = self
            .held
            .as_ref()
            .ok_or("fixture observed check before begin")?;
        if writer.metadata()?.ino() != held.data().root.inode {
            return Err("fixture callback writer FD changed".into());
        }
        self.store
            .check_existing_writer(&self.namespace, held, observation_budget(), &mut Io)?;
        if self.deny_after_write {
            let actual = self
                .store
                .inventory(owner::read_budget(), &mut Io, |_| Ok(()))?;
            if actual.regular_files > base.physical.observed.regular_files {
                return Err("fixture original observer revoked after actual new allocation".into());
            }
        }
        Ok(())
    }
}
fn plan(store: &ObjectStore, head: &OwnerHeadV2, live: &mut Live<'_>) -> OwnerPlan {
    let repository = OwnerRepository::at_selected(store, head, live).unwrap();
    repository
        .plan_capture(
            "observed",
            luma_content::Format::Utf8Text,
            b"exact edit",
            provenance("observed-first", b"exact edit"),
            live,
        )
        .unwrap()
}

#[test]
fn observed_append_begins_before_writes_retains_same_ofd_and_reopens_real_content() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let plan = plan(&store, &head, &mut live);
    live.review = Some(plan.review_sha256().into());
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let mut observer = Observer::new(&store, &head, &plan);
    let mut prepared = repository
        .prepare_append_observed(&plan, budget(), &mut live, &mut observer)
        .unwrap();
    prepared.check_observation().unwrap();
    assert!(store.acquire_writer().is_err());
    let commitment = prepared.commitment().clone();
    verify_append_data(&store, &commitment, owner::read_budget(), &mut live).unwrap();
    state.borrow_mut().head = commitment.next.clone();
    state.borrow_mut().physical = commitment.physical_after.clone();
    let selected = prepared.acknowledge_selected(&mut live).unwrap();
    assert_eq!(observer.begins, 1);
    assert!(observer.checks > 10);
    // The independent observation keeps its duplicate after preparation drops.
    assert!(store.acquire_writer().is_err());
    drop(observer);
    assert!(store.acquire_writer().is_ok());
    let repository = OwnerRepository::at_selected(&store, &selected, &mut live).unwrap();
    assert_eq!(
        repository.current("observed", &mut live).unwrap().content(),
        b"exact edit"
    );
}

#[test]
fn failed_observed_begin_leaves_actual_namespace_unwritten() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let plan = plan(&store, &head, &mut live);
    live.review = Some(plan.review_sha256().into());
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let mut observer = Observer::new(&store, &head, &plan);
    observer.deny_begin = true;
    assert!(repository
        .prepare_append_observed(&plan, budget(), &mut live, &mut observer)
        .is_err());
    assert_eq!(
        store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
            .unwrap(),
        state.borrow().physical
    );
    assert!(store.acquire_writer().is_ok());
    assert_eq!(observer.begins, 1);
    assert_eq!(observer.checks, 0);
}

#[test]
fn observer_loss_after_actual_write_refuses_and_retains_unselected_bytes() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let plan = plan(&store, &head, &mut live);
    live.review = Some(plan.review_sha256().into());
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    let mut observer = Observer::new(&store, &head, &plan);
    observer.deny_after_write = true;
    assert!(repository
        .prepare_append_observed(&plan, budget(), &mut live, &mut observer)
        .is_err());
    let actual = store
        .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
        .unwrap();
    assert!(actual.regular_files > head.physical.observed.regular_files);
    assert_eq!(state.borrow().head, head);
    assert!(repository.current("observed", &mut live).is_err());
}

#[test]
fn actual_writer_unlock_invalidates_retained_prepared_observation() {
    let (_fixture, store, state) = setup();
    let head = state.borrow().head.clone();
    let mut live = Live {
        store: &store,
        state: state.clone(),
        review: None,
    };
    let plan = plan(&store, &head, &mut live);
    live.review = Some(plan.review_sha256().into());
    let repository = OwnerRepository::at_selected(&store, &head, &mut live).unwrap();
    struct Unlock {
        began: bool,
    }
    impl AppendWriterBoundary for Unlock {
        fn begin_writer(&mut self, _: &OwnerHeadV2, _: &str, writer: &std::fs::File) -> Result<()> {
            self.began = true;
            if unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        fn check_writer(&mut self, _: &OwnerHeadV2, _: &str, _: &std::fs::File) -> Result<()> {
            Err("fixture lost actual advisory lock after begin".into())
        }
    }
    let mut observer = Unlock { began: false };
    assert!(repository
        .prepare_append_observed(&plan, budget(), &mut live, &mut observer)
        .is_err());
    assert!(observer.began);
    assert_eq!(
        store
            .inventory(owner::read_budget(), &mut Io, |_| Ok(()))
            .unwrap(),
        head.physical.observed
    );
}
