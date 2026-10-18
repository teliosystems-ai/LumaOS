use super::*;

fn pending(fixture: &Fixture, request: &str) -> PathBuf {
    fixture
        .root(&binding())
        .join("pending")
        .join(luma_content::sha256(request.as_bytes()))
}
fn outcomes(fixture: &Fixture) -> PathBuf {
    fixture.root(&binding()).join("outcomes")
}

#[test]
fn canonical_record_history_matches_exact_prepared_and_published_states() {
    let fixture = Fixture::new();
    let first = capture("first", "document", b"one");
    let mut repository =
        Repository::create_at(&fixture.path, &first, &mut Guard::write(&first)).unwrap();
    let mut records = Vec::new();
    assert_eq!(
        canonical_record_history_head(&binding(), &records).unwrap(),
        VerifiedState::empty(&binding()).unwrap().head_sha256
    );
    for plan in [first, capture("second", "other", b"two")] {
        let source = if plan.request_id() == "first" {
            b"one"
        } else {
            b"two"
        };
        let prepared = repository
            .prepare(&plan, source, &mut Guard::write(&plan))
            .unwrap();
        let bytes = prepared.record_bytes().to_vec();
        assert_eq!(
            fs::read(pending(&fixture, plan.request_id()).join("record.json")).unwrap(),
            bytes
        );
        records.push(bytes);
        assert_eq!(
            canonical_record_history_head(&binding(), &records).unwrap(),
            prepared.commitment().outcome_head_sha256()
        );
        prepared.publish(&mut Guard::write(&plan)).unwrap();
        assert_eq!(
            canonical_record_history_head(&binding(), &records).unwrap(),
            repository
                .verified_state(&mut Guard::read())
                .unwrap()
                .head_sha256
        );
    }
    records.reverse();
    assert!(canonical_record_history_head(&binding(), &records).is_err());
}

#[test]
fn canonical_record_history_refuses_noncanonical_unbounded_or_substituted_metadata() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    let original = prepared.record_bytes().to_vec();
    let mut whitespace = original.clone();
    whitespace.push(b'\n');
    let mut duplicate = original.clone();
    duplicate.splice(1..1, b"\"schema_version\":1,".iter().copied());
    for bytes in [
        Vec::new(),
        vec![b' '; MAX_RECORD as usize + 1],
        whitespace,
        duplicate,
    ] {
        assert!(canonical_record_history_head(&binding(), &[bytes]).is_err());
    }
    assert!(
        canonical_record_history_head(&binding(), &vec![original.clone(); MAX_OUTCOMES + 1])
            .is_err()
    );
    let mut other = binding();
    other.owner_generation += 1;
    assert!(canonical_record_history_head(&other, &[original.clone()]).is_err());
    for mutation in 0..9 {
        let mut record: Record = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => record.sequence = 2,
            1 => record.schema_version = 2,
            2 => record.plan.provenance.request_id = "../bad".into(),
            3 => record.plan.source_bytes = MAX_SOURCE + 1,
            4 => record.plan.payload_bytes = MAX_PAYLOAD + 1,
            5 => record.plan.source_sha256 = "0".repeat(64),
            6 => record.plan.resulting.version = 0,
            7 => record.plan.provenance.workflow_sha256 = "0".repeat(64),
            _ => record.plan.resulting.artifact_id = "another".into(),
        }
        record.review_sha256 = luma_content::sha256(&serde_json::to_vec(&record.plan).unwrap());
        assert!(
            canonical_record_history_head(&binding(), &[serde_json::to_vec(&record).unwrap()])
                .is_err(),
            "mutation {mutation}"
        );
    }
    let mut wrong_review: Record = serde_json::from_slice(&original).unwrap();
    wrong_review.review_sha256 = "f".repeat(64);
    assert!(canonical_record_history_head(
        &binding(),
        &[serde_json::to_vec(&wrong_review).unwrap()]
    )
    .is_err());
    let mut repeated: Record = serde_json::from_slice(&original).unwrap();
    repeated.sequence = 2;
    assert!(canonical_record_history_head(
        &binding(),
        &[original, serde_json::to_vec(&repeated).unwrap()]
    )
    .is_err());
}

#[test]
fn held_preparation_is_synchronized_data_and_drop_never_publishes_or_erases() {
    let fixture = Fixture::new();
    let source = b"exact original\r\n";
    let plan = capture("held", "document", source);
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let prepared = repository
        .prepare(&plan, source, &mut Guard::write(&plan))
        .unwrap();
    let commitment = prepared.commitment();
    assert_eq!(commitment.binding(), &binding());
    assert_eq!(commitment.request_id(), "held");
    assert_eq!(commitment.review_sha256(), plan.review_sha256());
    assert!(!commitment.already_published());
    assert_ne!(
        commitment.base_head_sha256(),
        commitment.outcome_head_sha256()
    );
    assert_eq!(
        commitment.sha256().unwrap(),
        luma_content::sha256(&commitment.canonical_bytes().unwrap())
    );
    assert_eq!(
        commitment
            .members()
            .iter()
            .map(|member| member.name())
            .collect::<Vec<_>>(),
        ["payload.json", "record.json", "source.bin"]
    );
    for member in commitment.members() {
        let bytes = fs::read(pending(&fixture, "held").join(member.name())).unwrap();
        assert_eq!(member.bytes(), bytes.len() as u64);
        assert_eq!(member.sha256(), luma_content::sha256(&bytes));
        assert_eq!(member.identity().mode & 0o7777, 0o400);
        assert_eq!(member.identity().links, 1);
    }
    assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
    assert!(Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).is_err());
    drop(prepared);
    assert_eq!(
        fs::read(pending(&fixture, "held").join("source.bin")).unwrap(),
        source
    );
    assert!(repository.inventory(&mut Guard::read()).unwrap().is_empty());
    drop(repository);
    let mut repository =
        Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
    let outcome = repository
        .prepare(&plan, source, &mut Guard::write(&plan))
        .unwrap()
        .publish(&mut Guard::write(&plan))
        .unwrap();
    assert_eq!(outcome.sequence, 1);
    assert!(!outcome.replayed);
}

#[test]
fn explicit_publication_joins_exact_head_and_replay_never_adds_an_outcome() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    let wanted = prepared.commitment().outcome_head_sha256().to_string();
    let outcome = prepared.publish(&mut Guard::write(&plan)).unwrap();
    assert_eq!(outcome.sequence, 1);
    assert!(!outcome.replayed);
    let replay = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    assert!(replay.commitment().already_published());
    assert_eq!(replay.commitment().base_head_sha256(), wanted);
    assert_eq!(replay.commitment().outcome_head_sha256(), wanted);
    assert!(replay.publish(&mut Guard::write(&plan)).unwrap().replayed);
    assert_eq!(repository.inventory(&mut Guard::read()).unwrap().len(), 1);
}

#[test]
fn publication_requires_fresh_read_effect_and_resource_admission() {
    for refusal in 0..3 {
        let fixture = Fixture::new();
        let plan = capture("one", "document", b"source");
        let mut repository =
            Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
        let prepared = repository
            .prepare(&plan, b"source", &mut Guard::write(&plan))
            .unwrap();
        let mut denied = if refusal == 0 {
            Guard::read()
        } else {
            Guard::write(&plan)
        };
        if refusal == 1 {
            denied.binding.owner_generation += 1;
        }
        if refusal == 2 {
            denied.refuse_resources = true;
        }
        assert!(prepared.publish(&mut denied).is_err());
        assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
        assert_eq!(
            fs::read(pending(&fixture, "one").join("source.bin")).unwrap(),
            b"source"
        );
    }
}

#[test]
fn a_refused_recheck_permanently_fences_the_same_handle() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let mut prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    let mut denied = Guard::write(&plan);
    denied.refuse_at = 1;
    assert!(prepared.recheck(&mut denied).is_err());
    let mut restored = Guard::write(&plan);
    assert!(prepared.recheck(&mut restored).is_err());
    assert_eq!(restored.checks, 0);
    assert!(prepared.publish(&mut restored).is_err());
    assert_eq!(restored.checks, 0);
    assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
}

#[test]
fn identical_bytes_in_replaced_member_inodes_cannot_substitute_held_preparation() {
    for name in ["record.json", "payload.json", "source.bin"] {
        let fixture = Fixture::new();
        let plan = capture("one", "document", b"source");
        let mut repository =
            Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
        let mut prepared = repository
            .prepare(&plan, b"source", &mut Guard::write(&plan))
            .unwrap();
        let path = pending(&fixture, "one").join(name);
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, fixture.path.join("retained-old-member")).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(prepared.recheck(&mut Guard::write(&plan)).is_err());
        assert!(prepared.publish(&mut Guard::write(&plan)).is_err());
        assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn exact_bytes_restored_after_inplace_tampering_do_not_restore_a_held_identity() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let mut prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    let path = pending(&fixture, "one").join("source.bin");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"tamper").unwrap();
    fs::write(&path, b"source").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(prepared.recheck(&mut Guard::write(&plan)).is_err());
    assert!(prepared.publish(&mut Guard::write(&plan)).is_err());
    assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
}

#[test]
fn held_directory_replacement_is_rejected_even_when_all_three_bytes_match() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let mut prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    let path = pending(&fixture, "one");
    let saved = fixture.path.join("retained-directory");
    fs::rename(&path, &saved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    for name in ["record.json", "payload.json", "source.bin"] {
        fs::write(path.join(name), fs::read(saved.join(name)).unwrap()).unwrap();
        fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o400)).unwrap();
    }
    assert!(prepared.recheck(&mut Guard::write(&plan)).is_err());
    assert!(prepared.publish(&mut Guard::write(&plan)).is_err());
    assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
}

#[test]
fn changed_quarantined_tombstone_evidence_fences_prepared_publication() {
    let fixture = Fixture::new();
    let plan = capture("one", "document", b"source");
    let repository = Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    let quarantine = fixture.root(&binding()).join("quarantine");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&quarantine)
        .unwrap();
    let retained = quarantine.join(luma_content::sha256(b"retired-request"));
    fs::DirBuilder::new().mode(0o700).create(&retained).unwrap();
    let path = retained.join("source.bin");
    fs::write(&path, b"retained partial bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    drop(repository);
    let mut repository =
        Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
    let mut prepared = repository
        .prepare(&plan, b"source", &mut Guard::write(&plan))
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"different retained bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(prepared.recheck(&mut Guard::write(&plan)).is_err());
    assert!(prepared.publish(&mut Guard::write(&plan)).is_err());
    assert_eq!(fs::read_dir(outcomes(&fixture)).unwrap().count(), 0);
    assert_eq!(fs::read(path).unwrap(), b"different retained bytes");
}

#[test]
fn exact_state_selectors_are_data_and_every_query_uses_its_own_verified_snapshot() {
    let fixture = Fixture::new();
    let first = capture("one", "document", b"first");
    let mut repository =
        Repository::create_at(&fixture.path, &first, &mut Guard::write(&first)).unwrap();
    assert_eq!(
        repository.verified_state(&mut Guard::read()).unwrap(),
        VerifiedState::empty(&binding()).unwrap()
    );
    let outcome = repository
        .apply(&first, b"first", &mut Guard::write(&first))
        .unwrap();
    let old = repository.verified_state(&mut Guard::read()).unwrap();
    let second = repository
        .plan_external_edit(
            "document",
            outcome.resulting.clone(),
            b"second",
            provenance("two", b"second", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repository
        .apply(&second, b"second", &mut Guard::write(&second))
        .unwrap();
    let selected = repository.verified_state(&mut Guard::read()).unwrap();
    assert_ne!(selected.head_sha256, old.head_sha256);
    repository
        .require_state(&selected, &mut Guard::read())
        .unwrap();
    let newer = outcomes(&fixture).join(luma_content::sha256(b"two"));
    let retained = fixture.path.join("held-newer-history");
    fs::rename(&newer, &retained).unwrap();
    assert!(repository.current("document", &mut Guard::read()).is_err());
    assert!(repository
        .historical(&outcome.resulting, &mut Guard::read())
        .is_err());
    assert!(repository.search("first", 8, &mut Guard::read()).is_err());
    assert!(repository.inventory(&mut Guard::read()).is_err());
    assert!(repository.review_backup_data(&mut Guard::read()).is_err());
    assert!(repository.verified_state(&mut Guard::read()).is_err());
    fs::rename(&retained, &newer).unwrap();
    assert_eq!(
        repository
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"second"
    );
    assert!(repository.review_backup_data(&mut Guard::read()).is_ok());
    let mut wrong = selected.clone();
    wrong.binding.owner_generation += 1;
    assert!(repository
        .require_state(&wrong, &mut Guard::read())
        .is_err());
    let mut zero = selected.clone();
    zero.head_sha256 = "0".repeat(64);
    assert!(zero.validate().is_err());
    let mut value = serde_json::to_value(&selected).unwrap();
    value["authority"] = true.into();
    assert!(serde_json::from_value::<VerifiedState>(value).is_err());
}

#[test]
fn old_snapshot_is_rejected_even_when_disk_is_restored_before_final_verification() {
    struct Swap {
        inner: Guard,
        current: PathBuf,
        retained: PathBuf,
        restore_at: usize,
        swapped: bool,
        restored: bool,
    }
    impl Boundary for Swap {
        fn admit(&mut self, owner: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
            self.inner.admit(owner, budget)
        }
        fn check(&mut self, access: Access<'_>) -> Result<()> {
            self.inner.check(access)?;
            if self.inner.checks == 1 {
                fs::rename(&self.current, &self.retained)?;
                self.swapped = true;
            }
            if self.inner.checks == self.restore_at {
                fs::rename(&self.retained, &self.current)?;
                self.restored = true;
            }
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let first = capture("one", "document", b"first");
    let mut repository =
        Repository::create_at(&fixture.path, &first, &mut Guard::write(&first)).unwrap();
    let initial = repository
        .apply(&first, b"first", &mut Guard::write(&first))
        .unwrap();
    let mut old_query = Guard::read();
    repository.current("document", &mut old_query).unwrap();
    assert!(old_query.checks > 2);
    let second = repository
        .plan_external_edit(
            "document",
            initial.resulting,
            b"second",
            provenance("two", b"second", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repository
        .apply(&second, b"second", &mut Guard::write(&second))
        .unwrap();
    let state = repository.verified_state(&mut Guard::read()).unwrap();
    repository
        .require_state(&state, &mut Guard::read())
        .unwrap();
    let mut attack = Swap {
        inner: Guard::read(),
        current: outcomes(&fixture).join(luma_content::sha256(b"two")),
        retained: fixture.path.join("temporarily-rolled-back"),
        restore_at: old_query.checks - 1,
        swapped: false,
        restored: false,
    };
    let result = repository.current("document", &mut attack);
    assert!(attack.swapped);
    assert!(attack.restored);
    assert!(result.is_err());
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("independently selected"));
    assert_eq!(
        repository
            .current("document", &mut Guard::read())
            .unwrap()
            .content(),
        b"second"
    );
}

#[test]
fn collections_share_the_same_held_commit_algorithm_and_state_selected_queries() {
    let fixture = Fixture::new();
    let initial = capture("initial", "document", b"member");
    let mut repository =
        Repository::create_at(&fixture.path, &initial, &mut Guard::write(&initial)).unwrap();
    let member = repository
        .apply(&initial, b"member", &mut Guard::write(&initial))
        .unwrap()
        .resulting;
    let source = CollectionSource {
        schema_version: 1,
        kind: "luma-explicit-collection-v1".into(),
        collection_id: "work".into(),
        name: "Work".into(),
        members: vec![member.clone()],
    };
    let bytes = source.canonical_bytes().unwrap();
    let plan = repository
        .plan_collection(
            &source,
            None,
            provenance("collection", &bytes, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    let prepared = repository
        .prepare_collection(&plan, &bytes, &mut Guard::write(&plan))
        .unwrap();
    let wanted = prepared.commitment().outcome_state();
    let outcome = prepared.publish(&mut Guard::write(&plan)).unwrap();
    assert_eq!(outcome.source_kind, SourceKind::CollectionIntent);
    repository
        .require_state(&wanted, &mut Guard::read())
        .unwrap();
    assert_eq!(
        repository
            .collection_current("work", &mut Guard::read())
            .unwrap()
            .reference,
        outcome.resulting
    );
    assert_eq!(
        repository
            .collections_for_member(&member, 0, 32, &mut Guard::read())
            .unwrap()
            .collections
            .len(),
        1
    );
    let directory = outcomes(&fixture).join(luma_content::sha256(b"collection"));
    let saved = fixture.path.join("retained-collection");
    fs::rename(&directory, &saved).unwrap();
    assert!(repository
        .collection_current("work", &mut Guard::read())
        .is_err());
    assert!(repository
        .collections_for_member(&member, 0, 32, &mut Guard::read())
        .is_err());
    fs::rename(&saved, &directory).unwrap();
}
