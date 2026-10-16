use super::*;
use crate::recovery::RecoveryPhase;
use std::os::unix::fs::MetadataExt;

struct RecoveryGuard {
    binding: OwnerBinding,
    review: Option<String>,
    retained: u64,
    checks: usize,
    recover_checks: usize,
    refuse_at: usize,
    refuse_resources: bool,
}

impl RecoveryGuard {
    fn read() -> Self {
        Self {
            binding: binding(),
            review: None,
            retained: 0,
            checks: 0,
            recover_checks: 0,
            refuse_at: usize::MAX,
            refuse_resources: false,
        }
    }

    fn recover(review: &PreparationReview) -> Self {
        Self {
            review: Some(review.review_sha256.clone()),
            retained: review.retained_bytes().unwrap(),
            ..Self::read()
        }
    }
}

impl Boundary for RecoveryGuard {
    fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        if self.refuse_resources
            || owner != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.write_bytes > 4096
            || budget.additional_storage_bytes > 4096
        {
            return Err("recovery fixture resource admission refused".into());
        }
        Ok(())
    }

    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.checks += 1;
        if self.checks >= self.refuse_at {
            return Err("recovery fixture live authority revoked".into());
        }
        match access {
            Access::Inspect { binding } if binding == &self.binding => Ok(()),
            Access::Recover {
                binding,
                review_sha256,
                retained_bytes,
            } if binding == &self.binding
                && self.review.as_deref() == Some(review_sha256)
                && retained_bytes == self.retained =>
            {
                self.recover_checks += 1;
                Ok(())
            }
            _ => Err("recovery fixture exact purpose authority refused".into()),
        }
    }
}

fn prepared() -> (Fixture, Repository, Plan) {
    let fixture = Fixture::new();
    let plan = capture("unfinished", "document", b"exact source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    assert!(repository
        .apply_with_hook(&plan, b"exact source", &mut Guard::write(&plan), |phase| {
            if matches!(phase, Phase::MemberSynced) {
                return Err("fixture interruption after immutable member sync".into());
            }
            Ok(())
        },)
        .is_err());
    (fixture, repository, plan)
}

fn review(repository: &Repository) -> PreparationReview {
    repository
        .review_preparation(
            &luma_content::sha256(b"unfinished"),
            &mut RecoveryGuard::read(),
        )
        .unwrap()
}

#[test]
fn exact_review_is_read_only_and_covers_pending_bytes_and_identity() {
    let (fixture, repository, _) = prepared();
    let root = fixture.root(&binding());
    let names = fs::read_dir(&root).unwrap().count();
    let reviewed = review(&repository);
    reviewed.validate().unwrap();
    assert_eq!(reviewed, review(&repository));
    assert_eq!(reviewed.outcome_count, 0);
    assert_eq!(reviewed.pending.len(), 1);
    assert_eq!(reviewed.pending[0].members.len(), 1);
    assert_eq!(reviewed.pending[0].members[0].name, "record.json");
    assert!(reviewed.pending[0].members[0].bytes > 0);
    assert!(reviewed.quarantined.is_empty());
    assert!(serde_json::to_vec(&reviewed).unwrap().len() <= MAX_PREPARATION_REVIEW_BYTES);
    repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .unwrap();
    assert_eq!(fs::read_dir(&root).unwrap().count(), names);
    assert!(!root.join("quarantine").exists());
}

#[test]
fn approved_recovery_preserves_exact_bytes_and_identity_with_durable_replay() {
    let (fixture, mut repository, _) = prepared();
    let reviewed = review(&repository);
    let target = &reviewed.pending[0];
    let original = fixture.root(&binding()).join("pending").join(&target.name);
    let original_bytes = fs::read(original.join("record.json")).unwrap();
    let original_inode = fs::metadata(&original).unwrap().ino();
    let mut guard = RecoveryGuard::recover(&reviewed);
    let outcome = repository
        .recover_preparation(&reviewed, &mut guard)
        .unwrap();
    assert!(!outcome.replayed);
    assert!(outcome.evidence_preserved && outcome.committed_outcomes_unchanged);
    assert!(!outcome.rollback_authority);
    assert_eq!(outcome.retained_bytes, original_bytes.len() as u64);
    assert!(guard.recover_checks > 20);
    assert!(!original.exists());
    let quarantined = fixture
        .root(&binding())
        .join("quarantine")
        .join(&target.name);
    assert_eq!(fs::metadata(&quarantined).unwrap().ino(), original_inode);
    assert_eq!(
        fs::read(quarantined.join("record.json")).unwrap(),
        original_bytes
    );
    repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .unwrap();
    let replay = repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.review_sha256, outcome.review_sha256);
    assert_eq!(replay.retained_bytes, outcome.retained_bytes);
    drop(repository);
    let mut reopened = Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
    let replay = reopened
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .unwrap();
    assert!(replay.replayed);
    assert!(reopened.inventory(&mut Guard::read()).unwrap().is_empty());
}

#[test]
fn read_only_wrong_review_owner_and_resource_authority_cannot_retire() {
    let (fixture, mut repository, _) = prepared();
    let reviewed = review(&repository);
    assert!(repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::read())
        .is_err());
    let mut wrong = RecoveryGuard::recover(&reviewed);
    wrong.review = Some("e".repeat(64));
    assert!(repository
        .recover_preparation(&reviewed, &mut wrong)
        .is_err());
    let mut owner = RecoveryGuard::recover(&reviewed);
    owner.binding.owner_generation += 1;
    assert!(repository
        .recover_preparation(&reviewed, &mut owner)
        .is_err());
    let mut resources = RecoveryGuard::recover(&reviewed);
    resources.refuse_resources = true;
    assert!(repository
        .recover_preparation(&reviewed, &mut resources)
        .is_err());
    assert_eq!(review(&repository), reviewed);
    assert!(!fixture.root(&binding()).join("quarantine").exists());
}

#[test]
fn malformed_or_mutated_review_is_rejected_before_authority_or_io() {
    let (_fixture, mut repository, _) = prepared();
    let reviewed = review(&repository);
    let mut changed = reviewed.clone();
    changed.pending[0].members[0].bytes += 1;
    let mut guard = RecoveryGuard::recover(&reviewed);
    assert!(changed.validate().is_err());
    assert!(repository
        .recover_preparation(&changed, &mut guard)
        .is_err());
    assert_eq!(guard.checks, 0);
    for target in ["", "../pending", &"A".repeat(64), &"a".repeat(63)] {
        assert!(repository
            .review_preparation(target, &mut RecoveryGuard::read())
            .is_err());
    }
    let mut json = serde_json::to_value(&reviewed).unwrap();
    json["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreparationReview>(json).is_err());
}

#[test]
fn changed_bytes_same_length_or_same_bytes_new_inode_require_new_review() {
    for replace in [false, true] {
        let (fixture, mut repository, _) = prepared();
        let reviewed = review(&repository);
        let member = fixture
            .root(&binding())
            .join("pending")
            .join(&reviewed.target)
            .join("record.json");
        let original = fs::read(&member).unwrap();
        if replace {
            let replacement = fixture.root(&binding()).join("replacement");
            fs::write(&replacement, &original).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
            fs::rename(&replacement, &member).unwrap();
        } else {
            fs::set_permissions(&member, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&member, vec![b'x'; original.len()]).unwrap();
            fs::set_permissions(&member, fs::Permissions::from_mode(0o400)).unwrap();
        }
        assert!(repository
            .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
            .is_err());
        assert!(repository
            .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
            .is_err());
        assert!(member.exists());
        assert!(!fixture.root(&binding()).join("quarantine").exists());
        assert_ne!(review(&repository), reviewed);
    }
}

#[test]
fn unknown_members_and_symlinks_remain_untouched_and_unreviewable() {
    for symlink in [false, true] {
        let (fixture, repository, _) = prepared();
        let path = fixture
            .root(&binding())
            .join("pending")
            .join(luma_content::sha256(b"unfinished"));
        if symlink {
            std::os::unix::fs::symlink("/proc/self/status", path.join("source.bin")).unwrap();
        } else {
            fs::write(path.join("unknown"), b"forensic evidence").unwrap();
        }
        assert!(repository
            .review_preparation(
                &luma_content::sha256(b"unfinished"),
                &mut RecoveryGuard::read()
            )
            .is_err());
        assert!(path.exists());
        assert!(!fixture.root(&binding()).join("quarantine").exists());
    }
}

#[test]
fn every_durable_recovery_phase_can_be_retried_without_losing_evidence() {
    for stop in 0..3 {
        let (fixture, mut repository, _) = prepared();
        let reviewed = review(&repository);
        let mut seen = 0;
        assert!(repository
            .recover_preparation_with_hook(
                &reviewed,
                &mut RecoveryGuard::recover(&reviewed),
                |phase| {
                    let index = match phase {
                        RecoveryPhase::NamespaceReady => 0,
                        RecoveryPhase::Renamed => 1,
                        RecoveryPhase::Committed => 2,
                    };
                    if index == stop {
                        seen += 1;
                        return Err("fixture interrupted durable recovery phase".into());
                    }
                    Ok(())
                },
            )
            .is_err());
        assert_eq!(seen, 1);
        drop(repository);
        let mut reopened =
            Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
        reopened
            .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
            .unwrap();
        let result = reopened
            .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
            .unwrap();
        assert_eq!(result.replayed, stop != 0);
        assert_eq!(result.retained_bytes, reviewed.retained_bytes().unwrap());
    }
}

#[test]
fn revocation_at_each_review_boundary_discards_results_without_mutation() {
    let (fixture, repository, _) = prepared();
    let mut baseline = RecoveryGuard::read();
    repository
        .review_preparation(&luma_content::sha256(b"unfinished"), &mut baseline)
        .unwrap();
    for at in 1..=baseline.checks {
        let mut revoked = RecoveryGuard::read();
        revoked.refuse_at = at;
        assert!(repository
            .review_preparation(&luma_content::sha256(b"unfinished"), &mut revoked)
            .is_err());
        assert_eq!(revoked.checks, at);
        assert!(!fixture.root(&binding()).join("quarantine").exists());
    }
}

#[test]
fn revocation_at_each_recovery_boundary_is_preserved_and_retryable() {
    let checks = {
        let (_fixture, mut repository, _) = prepared();
        let reviewed = review(&repository);
        let mut baseline = RecoveryGuard::recover(&reviewed);
        repository
            .recover_preparation(&reviewed, &mut baseline)
            .unwrap();
        baseline.checks
    };
    for at in 1..=checks {
        let (fixture, mut repository, _) = prepared();
        let reviewed = review(&repository);
        let mut revoked = RecoveryGuard::recover(&reviewed);
        revoked.refuse_at = at;
        assert!(
            repository
                .recover_preparation(&reviewed, &mut revoked)
                .is_err(),
            "revocation {at}"
        );
        assert_eq!(revoked.checks, at, "stop immediately on authority refusal");
        drop(repository);
        let mut reopened =
            Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
        reopened
            .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
            .unwrap();
        let recovered = reopened
            .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
            .unwrap();
        assert_eq!(recovered.retained_bytes, reviewed.retained_bytes().unwrap());
    }
}

#[test]
fn retired_request_is_not_reused_and_fresh_requests_preserve_committed_history() {
    let (_fixture, mut repository, plan) = prepared();
    let reviewed = review(&repository);
    repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .unwrap();
    assert!(repository
        .apply(&plan, b"exact source", &mut Guard::write(&plan))
        .is_err());
    assert!(storage::names(&repository.pending, MAX_PENDING)
        .unwrap()
        .is_empty());
    let fresh = capture("fresh-request", "document", b"fresh content");
    let outcome = repository
        .apply(&fresh, b"fresh content", &mut Guard::write(&fresh))
        .unwrap();
    assert_eq!(outcome.sequence, 1);
    assert_eq!(
        repository
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"fresh content"
    );
    assert_eq!(repository.inventory(&mut Guard::read()).unwrap().len(), 1);
    // The old receipt cannot acknowledge a different subsequently advanced head.
    assert!(repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .is_err());
    assert!(repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .is_err());
}

#[test]
fn damaged_committed_history_cannot_be_retired_or_replaced_as_preparation() {
    let (fixture, mut repository, _) = prepared();
    let fresh = capture("committed", "published", b"untouched");
    // A separate pending request prevents publication, not covert repair.
    assert!(repository
        .apply(&fresh, b"untouched", &mut Guard::write(&fresh))
        .is_err());
    let reviewed = review(&repository);
    let unknown = fixture
        .root(&binding())
        .join("outcomes")
        .join(luma_content::sha256(b"damaged"));
    fs::DirBuilder::new().mode(0o700).create(&unknown).unwrap();
    assert!(repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .is_err());
    assert!(repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .is_err());
    assert!(unknown.exists());
    assert!(!fixture.root(&binding()).join("quarantine").exists());
}

#[test]
fn empty_and_binary_partial_preparations_are_retained_without_guessing_a_plan() {
    for binary in [false, true] {
        let fixture = Fixture::new();
        let plan = capture("unfinished", "document", b"unavailable source");
        let mut repository =
            Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
        let name = luma_content::sha256(b"unfinished");
        let dir = storage::mkdir(&repository.pending, &name).unwrap();
        let bytes = [0, 255, 1, b'{', b'\n'];
        if binary {
            storage::write(&dir, "record.json", &bytes, &mut || Ok(())).unwrap();
        }
        let reviewed = review(&repository);
        assert_eq!(
            reviewed.pending[0].members.len(),
            if binary { 1 } else { 0 }
        );
        assert_eq!(
            reviewed.retained_bytes().unwrap(),
            if binary { bytes.len() as u64 } else { 0 }
        );
        repository
            .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
            .unwrap();
        let retained = fixture.root(&binding()).join("quarantine").join(name);
        if binary {
            assert_eq!(fs::read(retained.join("record.json")).unwrap(), bytes);
        } else {
            assert_eq!(fs::read_dir(retained).unwrap().count(), 0);
        }
        assert!(repository.inventory(&mut Guard::read()).unwrap().is_empty());
    }
}

#[test]
fn quarantine_capacity_is_bounded_without_eviction_or_an_extra_preparation() {
    let fixture = Fixture::new();
    let initial = capture("initial", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &initial, &mut Guard::write(&initial)).unwrap();
    for index in 0..MAX_QUARANTINED_PREPARATIONS {
        let name = luma_content::sha256(format!("incomplete-{index}").as_bytes());
        storage::mkdir(&repository.pending, &name).unwrap();
        let reviewed = repository
            .review_preparation(&name, &mut RecoveryGuard::read())
            .unwrap();
        repository
            .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
            .unwrap();
    }
    let extra = luma_content::sha256(b"extra preparation");
    storage::mkdir(&repository.pending, &extra).unwrap();
    assert!(repository
        .review_preparation(&extra, &mut RecoveryGuard::read())
        .is_err());
    assert_eq!(
        storage::names(
            repository.quarantine.as_ref().unwrap(),
            MAX_QUARANTINED_PREPARATIONS
        )
        .unwrap()
        .len(),
        MAX_QUARANTINED_PREPARATIONS
    );
    assert!(storage::directory(&repository.pending, &extra).is_ok());
    assert!(repository.inventory(&mut Guard::read()).unwrap().is_empty());
}

#[test]
fn post_rename_evidence_mutation_refuses_acknowledgment_and_preserves_changed_bytes() {
    let (fixture, mut repository, _) = prepared();
    let reviewed = review(&repository);
    let path = fixture
        .root(&binding())
        .join("quarantine")
        .join(&reviewed.target)
        .join("record.json");
    assert!(repository
        .recover_preparation_with_hook(&reviewed, &mut RecoveryGuard::recover(&reviewed), |phase| {
            if matches!(phase, RecoveryPhase::Renamed) {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                fs::write(&path, b"changed evidence")?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
            }
            Ok(())
        },)
        .is_err());
    assert!(repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .is_err());
    assert!(repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), b"changed evidence");
}

#[test]
fn existing_quarantine_namespace_is_pinned_and_not_redirected() {
    let (fixture, mut repository, _) = prepared();
    let reviewed = review(&repository);
    repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .unwrap();
    let original = fixture.root(&binding()).join("quarantine");
    let retained = fixture.root(&binding()).join("quarantine-retained");
    fs::rename(&original, &retained).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
    assert!(repository
        .check_preparation_review(&reviewed, &mut RecoveryGuard::read())
        .is_err());
    assert!(repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .is_err());
    assert!(retained.join(&reviewed.target).join("record.json").exists());
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
}

#[test]
fn valid_committed_versions_and_exact_sources_are_unchanged_by_retirement() {
    let fixture = Fixture::new();
    let seed = capture("committed", "existing-document", b"existing\r\nsource");
    let mut repository =
        Repository::create_at(&fixture.path, &seed, &mut Guard::write(&seed)).unwrap();
    repository
        .apply(&seed, b"existing\r\nsource", &mut Guard::write(&seed))
        .unwrap();
    let before = repository.inventory(&mut Guard::read()).unwrap();
    let retained = repository
        .retained("committed", &mut Guard::read())
        .unwrap();
    let unfinished = capture("unfinished", "new-document", b"uncommitted source");
    assert!(repository
        .apply_with_hook(
            &unfinished,
            b"uncommitted source",
            &mut Guard::write(&unfinished),
            |phase| {
                if matches!(phase, Phase::MemberSynced) {
                    return Err("fixture interruption".into());
                }
                Ok(())
            },
        )
        .is_err());
    let reviewed = review(&repository);
    assert_eq!(reviewed.outcome_count, 1);
    repository
        .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
        .unwrap();
    assert_eq!(repository.inventory(&mut Guard::read()).unwrap(), before);
    assert_eq!(
        repository
            .retained("committed", &mut Guard::read())
            .unwrap(),
        retained
    );
    assert_eq!(
        repository
            .current("existing-document", &mut Guard::read())
            .unwrap()
            .content(),
        b"existing\nsource"
    );
    assert!(repository
        .current("new-document", &mut Guard::read())
        .is_err());
}

#[test]
fn every_other_pending_directory_is_a_review_fence_and_is_not_retired() {
    for added_after_review in [false, true] {
        let (_fixture, mut repository, _) = prepared();
        let other = luma_content::sha256(b"other-uncommitted-request");
        let first_review = review(&repository);
        let other_dir = storage::mkdir(&repository.pending, &other).unwrap();
        let other_inode = other_dir.metadata().unwrap().ino();
        if added_after_review {
            assert!(repository
                .recover_preparation(&first_review, &mut RecoveryGuard::recover(&first_review))
                .is_err());
            assert!(repository.quarantine.is_none());
        } else {
            let reviewed = review(&repository);
            assert_eq!(reviewed.pending.len(), 2);
            repository
                .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
                .unwrap();
            assert_eq!(
                storage::names(&repository.pending, MAX_PENDING).unwrap(),
                [other.clone()]
            );
            assert_eq!(
                storage::directory(&repository.pending, &other)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .ino(),
                other_inode
            );
            assert!(
                repository
                    .recover_preparation(&reviewed, &mut RecoveryGuard::recover(&reviewed))
                    .unwrap()
                    .replayed
            );
        }
    }
}
