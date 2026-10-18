use super::*;

fn target() -> OwnerBinding {
    OwnerBinding {
        installation: "d".repeat(64),
        owner: "e".repeat(64),
        owner_generation: 1,
    }
}

fn archive_with_all_source_schemas() -> (Fixture, ContentBackup) {
    let f = Fixture::new();
    let bytes = b"name,value\na,1\n";
    let initial = Plan::capture(
        binding(),
        "table",
        Format::Csv,
        bytes,
        provenance("initial", bytes, EditOrigin::Managed),
    )
    .unwrap();
    let mut repo = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    repo.apply(&initial, bytes, &mut Guard::write(&initial))
        .unwrap();
    let original = initial.resulting().clone();
    let request = luma_content::table::TableEditRequest {
        binding: binding(),
        expected: original.clone(),
        metadata: luma_content::table::EditMetadata {
            request_id: "edit".into(),
            workflow_sha256: "c".repeat(64),
        },
        operations: vec![luma_content::table::Operation::SetCell {
            row: 1,
            column: 1,
            value: "2".into(),
        }],
    };
    let edit = repo.plan_table_edit(&request, &mut Guard::read()).unwrap();
    repo.apply(
        &edit,
        &request.canonical_bytes().unwrap(),
        &mut Guard::write(&edit),
    )
    .unwrap();
    let render = luma_content::rendered::Request {
        binding: binding(),
        artifact_id: "editable".into(),
        expected: None,
        metadata: luma_content::table::EditMetadata {
            request_id: "render".into(),
            workflow_sha256: "c".repeat(64),
        },
        engine: luma_content::rendered::Engine::Document,
        source: r#"{"schema_version":1,"title":"Blank","blocks":[]}"#.into(),
    };
    let plan = repo.plan_render(&render, &mut Guard::read()).unwrap();
    repo.apply(
        &plan,
        &render.canonical_bytes().unwrap(),
        &mut Guard::write(&plan),
    )
    .unwrap();
    let collection = CollectionSource {
        schema_version: 1,
        kind: "luma-explicit-collection-v1".into(),
        collection_id: "history".into(),
        name: "Historical table".into(),
        members: vec![original],
    };
    let source = collection.canonical_bytes().unwrap();
    let plan = repo
        .plan_collection(
            &collection,
            None,
            provenance("collection", &source, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repo.apply_collection(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    let nochange = repo
        .plan_external_edit(
            "table",
            edit.resulting().clone(),
            b"name,value\na,2\n",
            provenance("noop", b"name,value\na,2\n", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    assert_eq!(nochange.decision(), DecisionKind::NoChangeRetained);
    repo.apply(
        &nochange,
        b"name,value\na,2\n",
        &mut Guard::write(&nochange),
    )
    .unwrap();
    let archive = super::backup::backup(&repo);
    (f, archive)
}

#[test]
fn fresh_restore_replays_every_schema_and_remaps_historical_collection_references() {
    let (_source, archive) = archive_with_all_source_schemas();
    let target = target();
    let plan = plan_restore_data_checked(
        archive.bytes(),
        &target,
        "restore",
        &"f".repeat(64),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(plan.review().published_outcomes, 4);
    assert_eq!(plan.review().inert_committed_outcomes, 1);
    assert_eq!(plan.steps().len(), 4);
    assert_eq!(plan.mappings().len(), 4);
    assert!(serde_json::to_vec(plan.review()).unwrap().len() <= MAX_RESTORE_REVIEW_BYTES);
    let collection = CollectionSource::from_canonical(plan.steps().last().unwrap().1).unwrap();
    assert_eq!(collection.members, vec![plan.mappings()[0].target.clone()]);
    assert_eq!(collection.members[0].version, 1);
    assert_ne!(
        collection.members[0].receipt_sha256,
        plan.mappings()[0].origin.receipt_sha256
    );
    let destination = Fixture::new();
    let first = plan.steps().next().unwrap().0;
    let mut repo =
        Repository::create_at(&destination.path, first, &mut Guard::write(first)).unwrap();
    for (step, source) in plan.steps() {
        assert_eq!(step.binding(), &target);
        let outcome = repo.apply(step, source, &mut Guard::write(step)).unwrap();
        assert_eq!(outcome.decision, DecisionKind::Published);
    }
    let mut read = Guard::read();
    read.binding = target.clone();
    let reopened = Repository::open_at(&destination.path, &target, &mut read);
    assert!(
        reopened.is_err(),
        "original repository still holds exclusive lock"
    );
    drop(repo);
    let repo = Repository::open_at(&destination.path, &target, &mut read).unwrap();
    assert_eq!(
        repo.current("table", &mut read).unwrap().content(),
        b"name,value\na,2\n"
    );
    assert_eq!(
        repo.current("collection.history", &mut read)
            .unwrap()
            .receipt()
            .schema_version,
        1
    );
}

#[test]
fn restore_refuses_old_binding_bad_identity_tampering_and_every_revoked_checkpoint() {
    let f = Fixture::new();
    let initial = capture("first", "document", b"text");
    let mut repo = Repository::create_at(&f.path, &initial, &mut Guard::write(&initial)).unwrap();
    repo.apply(&initial, b"text", &mut Guard::write(&initial))
        .unwrap();
    let archive = super::backup::backup(&repo);
    let mut checks = 0;
    let result = plan_restore_data_checked(
        archive.bytes(),
        &target(),
        "restore",
        &"f".repeat(64),
        &mut || {
            checks += 1;
            Ok(())
        },
    )
    .unwrap();
    let expected_review = result.review().clone();
    expected_review.validate().unwrap();
    let resign_data = |review: &mut RestoreReview| {
        review.review_sha256.clear();
        review.review_sha256 = luma_content::sha256(&serde_json::to_vec(review).unwrap());
    };
    for case in 0..10 {
        let mut bad = expected_review.clone();
        match case {
            0 => bad.schema_version = 2,
            1 => bad.profile = "archive-is-authority".into(),
            2 => bad.target.installation = bad.origin.installation.clone(),
            3 => bad.target.owner = bad.origin.owner.clone(),
            4 => bad.target.owner_generation = 0,
            5 => bad.steps[0].request_id = "other.1".into(),
            6 => bad.steps[0].request_id = "restore.01".into(),
            7 => bad.steps[0].review_sha256 = "0".repeat(64),
            8 => bad.planned_storage_bytes = 0,
            9 => bad.inert_committed_outcomes = MAX_OUTCOMES as u64,
            _ => unreachable!(),
        }
        resign_data(&mut bad);
        assert!(
            bad.validate().is_err(),
            "consistently rehashed malformed review {case}"
        );
    }
    let mut bounded = expected_review.clone();
    bounded.published_outcomes = MAX_OUTCOMES as u64;
    bounded.planned_storage_bytes = MAX_OUTCOMES as u64 * MAX_RECORD;
    bounded.request_namespace = "a".repeat(64);
    bounded.steps = (1..=MAX_OUTCOMES)
        .map(|sequence| RestoreStepReview {
            request_id: format!("{}.{}", bounded.request_namespace, sequence),
            review_sha256: "f".repeat(64),
        })
        .collect();
    resign_data(&mut bounded);
    bounded.validate().unwrap();
    assert!(serde_json::to_vec(&bounded).unwrap().len() < MAX_RESTORE_REVIEW_BYTES);
    for stop in 1..=checks {
        let mut at = 0;
        assert!(
            plan_restore_data_checked(
                archive.bytes(),
                &target(),
                "restore",
                &"f".repeat(64),
                &mut || {
                    at += 1;
                    if at >= stop {
                        Err("fixture original authorization revoked".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err(),
            "checkpoint {stop} must refuse"
        );
    }
    for bad in [
        binding(),
        OwnerBinding {
            installation: binding().installation,
            ..target()
        },
        OwnerBinding {
            owner: binding().owner,
            ..target()
        },
    ] {
        assert!(plan_restore_data_checked(
            archive.bytes(),
            &bad,
            "restore",
            &"f".repeat(64),
            &mut || Ok(())
        )
        .is_err());
    }
    for namespace in ["", "../escape", &"a".repeat(65), "first"] {
        let value = plan_restore_data_checked(
            archive.bytes(),
            &target(),
            namespace,
            &"f".repeat(64),
            &mut || Ok(()),
        );
        if namespace == "first" {
            assert!(value.is_ok());
        } else {
            assert!(value.is_err());
        }
    }
    assert!(plan_restore_data_checked(
        archive.bytes(),
        &target(),
        "restore",
        &"0".repeat(64),
        &mut || Ok(())
    )
    .is_err());
    let mut tampered = archive.bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(plan_restore_data_checked(
        &tampered,
        &target(),
        "restore",
        &"f".repeat(64),
        &mut || Ok(())
    )
    .is_err());
    let repeat = plan_restore_data_checked(
        archive.bytes(),
        &target(),
        "restore",
        &"f".repeat(64),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(repeat.review(), &expected_review);
    assert!(
        plan_restore_data_checked(
            archive.bytes(),
            &target(),
            "restore",
            &"e".repeat(64),
            &mut || Ok(())
        )
        .unwrap()
        .review()
            != &expected_review
    );
}
