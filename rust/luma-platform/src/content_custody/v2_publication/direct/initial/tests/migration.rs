//! Actual bounded owner migration windows of the closed direct worker over a
//! real bootstrapped C cut and a real side-by-side v2 object store. Original
//! worker attribution, resources and NV are explicit software fixtures, not
//! installed qualification.
use super::super::super::super::super::protocol::{
    software_worker_operation, TypedOperationSource,
};
use super::worker_cases::{attribution, cold, ready, worker, Owner};
use super::*;
use luma_content_store::v2::migration::{
    review_migration, MigrationBoundary, MigrationPrefix, MigrationReview,
    MigrationWindowCommitment,
};
use luma_content_store::v2::{
    AppendCommitment, IoBudget, Mutation, ObjectStore, OwnerBoundary, OwnerRepository,
    PhysicalInventory,
};
use luma_content_store::{Access, Boundary, DecisionKind, ResourceBudget};

const BODY: &[u8] = b"real retained owner bytes before the direct worker publisher";

fn budget() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 128 * 1024 * 1024,
        new_files: 32768,
    }
}
/// Inventory walks are read-only admissions.
fn read() -> IoBudget {
    IoBudget {
        read_bytes: 512 * 1024 * 1024,
        write_bytes: 0,
        new_files: 0,
    }
}

/// Independent software owner authority for the test's own review and final
/// v2 read. It never stands in for the C adapter under test.
pub(super) struct Authority {
    legacy: VerifiedState,
    head: Option<OwnerHeadV2>,
    physical: PhysicalInventory,
}
impl Boundary for Authority {
    fn admit(&mut self, _: &OwnerBinding, _: ResourceBudget) -> luma_content_store::Result<()> {
        Ok(())
    }
    fn check(&mut self, _: Access<'_>) -> luma_content_store::Result<()> {
        Ok(())
    }
}
impl MigrationBoundary for Authority {
    fn current_legacy_state(&mut self, expected: &VerifiedState) -> luma_content_store::Result<()> {
        if *expected != self.legacy {
            return Err("test authority legacy state changed".into());
        }
        Ok(())
    }
    fn current_migration_prefix(
        &mut self,
        _: &MigrationReview,
        _: Option<&MigrationPrefix>,
    ) -> luma_content_store::Result<PhysicalInventory> {
        Ok(self.physical.clone())
    }
    fn verify_migration_allocations(
        &mut self,
        _: &MigrationWindowCommitment,
    ) -> luma_content_store::Result<()> {
        Err("test authority never prepares a migration window".into())
    }
}
impl OwnerBoundary for Authority {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> luma_content_store::Result<()> {
        if self.head.as_ref().map(OwnerHeadV2::sha256).transpose()? != Some(head.sha256()?) {
            return Err("test authority owner head changed".into());
        }
        Ok(())
    }
    fn current_physical_accounting(
        &mut self,
        head: &OwnerHeadV2,
    ) -> luma_content_store::Result<PhysicalInventory> {
        self.current_owner_head(head)?;
        Ok(self.physical.clone())
    }
    fn verify_prepared_allocations(
        &mut self,
        _: &AppendCommitment,
    ) -> luma_content_store::Result<()> {
        Err("test authority never prepares an owner append".into())
    }
}

/// A fresh v2 store beside the actual retained legacy owner and the test's
/// own independent review of that owner.
fn side(fixture: &Fixture, owner: &Owner) -> (ObjectStore, Authority, MigrationReview) {
    let mut authority = Authority {
        legacy: owner.wanted.clone(),
        head: None,
        physical: PhysicalInventory::default(),
    };
    let store = ObjectStore::create_at(
        &fixture.data,
        &owner.binding,
        budget(),
        &Mutation {
            review_sha256: "cc".repeat(32),
            decision: DecisionKind::Published,
            source_bytes: 0,
        },
        &mut authority,
    )
    .unwrap();
    authority.physical = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    let review = review_migration(&owner.repository, &owner.wanted, &mut authority).unwrap();
    (store, authority, review)
}

/// The original worker effect for one window, computed independently of the
/// module under test from its documented request tuple.
fn migration(
    owner: &Owner,
    review: &MigrationReview,
    previous: Option<&MigrationPrefix>,
    retained: u32,
    number: u64,
) -> (Audit, TypedOperationSource) {
    let review_sha256 = review.sha256().unwrap();
    let previous = previous.map(|prefix| hash(&prefix.canonical_bytes(review).unwrap()));
    let request = serde_json::to_vec(&(
        "luma-c-direct-owner-migration-request-v1",
        &owner.binding,
        &review_sha256,
        previous,
        1u32,
        retained,
    ))
    .unwrap();
    let (profile, audit) = attribution(&owner.binding, &review_sha256, number);
    let mut source = worker(&owner.binding, profile, &request);
    source.purpose = SourcePurpose::OwnerMigration;
    (audit, source)
}

/// The actual retained owner after its complete bounded migration. Every
/// window was one NV dispatch, replayed by a cold reopen before the next.
pub(super) struct Migrated {
    pub(super) owner: Owner,
    pub(super) store: ObjectStore,
    pub(super) authority: Authority,
    pub(super) review: MigrationReview,
    pub(super) head: OwnerHeadV2,
    pub(super) windows: u64,
}
/// A narrow first window copies only the outcome, so the retained blob needs
/// a selected prefix and a second window. A wide first window also retains
/// one blob and may complete the owner at once.
pub(super) fn migrated(fixture: &Fixture, wide: bool) -> Migrated {
    let (owner, mut current) = ready(fixture);
    let (store, authority, review) = side(fixture, &owner);
    let mut previous = None;
    let mut windows = 0;
    let head = loop {
        windows += 1;
        assert!(windows <= 64, "bounded migration did not finish");
        let retained = u32::from(wide || previous.is_some());
        let calls = fixture.memory.0.borrow().calls;
        let (audit, source) =
            migration(&owner, &review, previous.as_ref(), retained, 100 + windows);
        let mut check = || Ok(());
        let window = current
            .migrate_owner_direct(
                &owner.repository,
                &store,
                1,
                retained,
                &mut software_worker_operation(&audit, source.clone(), &mut check),
            )
            .unwrap();
        assert_eq!(
            fixture.memory.0.borrow().calls,
            calls + 1,
            "one NV dispatch per window"
        );
        let reopened = cold(fixture).expect("cold reopen replays the selected window");
        let mut check = || Ok(());
        let mut original = software_worker_operation(&audit, source, &mut check);
        if window.complete() {
            break reopened
                .acknowledge_migration_owner_direct(window, &mut original)
                .unwrap();
        }
        previous = Some(
            reopened
                .acknowledge_migration_prefix_direct(window, &mut original)
                .unwrap(),
        );
        current = cold(fixture).unwrap();
    };
    Migrated {
        owner,
        store,
        authority,
        review,
        head,
        windows,
    }
}

#[test]
fn actual_owner_migration_windows_are_c_selected_and_cold_reopen_replays_each() {
    let fixture = Fixture::new();
    let Migrated {
        owner,
        store,
        mut authority,
        review,
        head,
        windows,
    } = migrated(&fixture, false);
    assert!(windows >= 2, "the selected prefix path was exercised");
    authority.head = Some(head.clone());
    authority.physical = store.inventory(read(), &mut authority, |_| Ok(())).unwrap();
    let selected = OwnerRepository::at_selected(&store, &head, &mut authority).unwrap();
    assert_eq!(
        selected
            .current("document", &mut authority)
            .unwrap()
            .content(),
        BODY
    );
    // The selected V2 owner cannot be migrated again or downgraded.
    let calls = fixture.memory.0.borrow().calls;
    let (audit, source) = migration(&owner, &review, None, 0, 900);
    let mut check = || Ok(());
    assert!(cold(&fixture)
        .unwrap()
        .migrate_owner_direct(
            &owner.repository,
            &store,
            1,
            0,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, calls);
}

#[test]
fn actual_substituted_or_revoked_migration_original_is_refused_before_nv() {
    let fixture = Fixture::new();
    let (owner, _) = ready(&fixture);
    let (store, _, review) = side(&fixture, &owner);
    let (audit, source) = migration(&owner, &review, None, 0, 200);
    let mut publish = source.clone();
    publish.purpose = SourcePurpose::Publish;
    let mut request = source.clone();
    request.request_sha256 = "ab".repeat(32);
    let mut anonymous = audit.clone();
    anonymous.operation_id = None;
    let mut stale = audit.clone();
    stale.subject_generation += 1;
    let cases = [
        (audit.clone(), publish, true),
        (audit.clone(), request, true),
        (anonymous, source.clone(), true),
        (stale, source.clone(), true),
        (audit.clone(), source.clone(), false),
    ];
    for (audit, source, live) in cases {
        let calls = fixture.memory.0.borrow().calls;
        let mut check = || {
            if live {
                Ok(())
            } else {
                Err("software original revoked".into())
            }
        };
        assert!(cold(&fixture)
            .unwrap()
            .migrate_owner_direct(
                &owner.repository,
                &store,
                1,
                0,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, calls, "refused before NV");
    }
    // A wider window than its original request is refused as well.
    let mut check = || Ok(());
    assert!(cold(&fixture)
        .unwrap()
        .migrate_owner_direct(
            &owner.repository,
            &store,
            2,
            0,
            &mut software_worker_operation(&audit, source, &mut check),
        )
        .is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 3);
}

#[test]
fn actual_owner_migration_nv_faults_are_fenced_without_adoption() {
    for fault in [Fault::Old, Fault::Lost, Fault::Third] {
        let fixture = Fixture::new();
        let (owner, current) = ready(&fixture);
        let (store, _, review) = side(&fixture, &owner);
        let (audit, source) = migration(&owner, &review, None, 0, 300);
        fixture.memory.0.borrow_mut().fault = fault;
        let mut check = || Ok(());
        assert!(current
            .migrate_owner_direct(
                &owner.repository,
                &store,
                1,
                0,
                &mut software_worker_operation(&audit, source, &mut check),
            )
            .is_err());
        assert!(cold(&fixture).is_err());
        assert_eq!(fixture.memory.0.borrow().calls, 4, "no redispatch");
    }
}
