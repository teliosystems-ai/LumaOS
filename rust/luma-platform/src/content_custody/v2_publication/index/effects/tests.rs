//! Fixtures are explicit DATA, not native PAM/C selection or creator evidence.
use super::*;
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "1".repeat(64),
        owner: "2".repeat(64),
        owner_generation: 7,
    }
}
fn input() -> request::Input {
    request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding(),
        request_id: "a".repeat(32),
        operation: request::Operation::Step {
            job_id: "b".repeat(32),
            expected_job_sha256: "3".repeat(64),
            window: request::Window {
                maximum: 1,
                read_bytes: 1024 * 1024,
                write_bytes: 1024 * 1024,
            },
        },
    }
}
fn base() -> Base {
    Base {
        binding: binding(),
        descriptor_sha256: "4".repeat(64),
        nv_head: "5".repeat(64),
        owner_sha256: "6".repeat(64),
        physical: PhysicalInventory {
            regular_files: 20,
            directories: 10,
            allocated_bytes: 81920,
            logical_bytes: 5000,
            incomplete_objects: 0,
        },
        segments: 1,
        index_sha256: Some("7".repeat(64)),
    }
}
fn objects() -> Vec<ObjectWriteSpec> {
    vec![ObjectWriteSpec {
        sha256: "8".repeat(64),
        bytes: 500,
    }]
}
fn review(input: &request::Input, objects: &[ObjectWriteSpec]) -> phase::WindowReview {
    let mut r = phase::WindowReview {
        schema_version: 2,
        input_sha256: input.sha256().unwrap(),
        base_sha256: "3".repeat(64),
        phase: "ingest".into(),
        review_sha256: String::new(),
        core_review_sha256: "9".repeat(64),
        planned_objects_sha256: hash(&serde_json::to_vec(objects).unwrap()),
        builder: luma_content_store::corpus_index::BuilderIdentity {
            source_sha256: "a".repeat(64),
            runtime_sha256: "b".repeat(64),
        },
        policy_sha256: policy::sha256().unwrap(),
        metadata_maximum: phase::MetadataMaximum::compiled(),
        source_bytes: 100,
        maximum_read_bytes: 1024 * 1024,
        maximum_write_bytes: 1024 * 1024,
    };
    // Exact fixture of the public closed WindowReview canonical tuple. It is
    // checked by the real validator; no fake Plan or native authority is made.
    r.review_sha256 = hash(
        &serde_json::to_vec(&(
            "luma-native-index-window-review-v2",
            r.schema_version,
            &r.input_sha256,
            &r.base_sha256,
            &r.phase,
            &r.core_review_sha256,
            &r.planned_objects_sha256,
            &r.builder,
            &r.policy_sha256,
            &r.metadata_maximum,
            r.source_bytes,
            r.maximum_read_bytes,
            r.maximum_write_bytes,
        ))
        .unwrap(),
    );
    r.validate().unwrap();
    r
}
fn attributed(input: &request::Input, review: &str) -> Attribution {
    let profile = input.effect_profile(review).unwrap();
    let storage = "8:1";
    Attribution {
        rpc_sha256: "c".repeat(64),
        profile: profile.clone(),
        storage_device: storage.into(),
        worker_pid: 123,
        worker_start: 456,
        worker_label: "luma-acquisition (enforce)".into(),
        lease: crate::resources::Token {
            lease_id: "d".repeat(32),
            generation: 1,
            manager_epoch: "e".repeat(32),
        },
        paired_read: crate::content_index::scope::original_usage(
            &profile,
            storage,
            &input.binding,
            &input.sha256().unwrap(),
            true,
        )
        .unwrap(),
        effect: Audit {
            subject: input.binding.owner.clone(),
            subject_generation: input.binding.owner_generation,
            grant_id: "effect-grant".into(),
            grant_version: 1,
            checkpoint_head: "f".repeat(64),
            operation_id: Some("a".repeat(32)),
            usage: crate::content_index::scope::original_usage(
                &profile,
                storage,
                &input.binding,
                &input.sha256().unwrap(),
                false,
            )
            .unwrap(),
        },
    }
}
fn prepared() -> (Preparation, InventoryPlan) {
    let input = input();
    let objects = objects();
    let review = review(&input, &objects);
    Preparation::data(
        &base(),
        &input,
        &review,
        &objects,
        &attributed(&input, &review.review_sha256),
        &mut || Ok(()),
    )
    .unwrap()
}
#[test]
fn canonical_reservation_preserves_actual_physical_and_exact_finite_liability() {
    let (p, inventory) = prepared();
    let bytes = p.bytes().unwrap();
    assert!(bytes.len() < PREPARATION_BYTES as usize);
    assert_eq!(Preparation::parse(&bytes).unwrap(), p);
    assert_eq!(p.base.physical, base().physical);
    assert!(p.liability.allocated_bytes > p.base.physical.allocated_bytes);
    assert_eq!(inventory.root(), &p.inventory);
    assert_eq!(inventory.root().object_count(), 1);
    assert_eq!(inventory.root().object_bytes(), 500);
    assert!(inventory.root().closure_bytes() > 0);
    assert_eq!(inventory.root().page_count(), 1);
    assert_eq!(inventory.root().sha256().unwrap().len(), 64);
    assert!(Preparation::parse(serde_json::to_string_pretty(&p).unwrap().as_bytes()).is_err());
    let mut value = serde_json::to_value(&p).unwrap();
    value["go"] = serde_json::Value::Bool(true);
    assert!(Preparation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn independent_replay_refuses_changed_before_source_review_inventory_and_current_callback() {
    let (p, _) = prepared();
    let mut before = base();
    before.physical.allocated_bytes += 4096;
    assert!(p
        .replay_data(
            &before,
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut before = base();
    before.descriptor_sha256 = "d".repeat(64);
    assert!(p
        .replay_data(
            &before,
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut input = p.input.clone();
    input.request_id = "e".repeat(32);
    assert!(p
        .replay_data(
            &base(),
            &input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut values = objects();
    values[0].bytes += 1;
    assert!(p
        .replay_data(
            &base(),
            &p.input,
            &p.review,
            &values,
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut r = p.review.clone();
    r.policy_sha256 = "f".repeat(64);
    assert!(p
        .replay_data(&base(), &p.input, &r, &objects(), &p.original, &mut || Ok(
            ()
        ))
        .is_err());
    assert!(p
        .replay_data(
            &base(),
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Err("fixture revoked".into())
        )
        .is_err());
}
#[test]
fn attribution_data_cannot_relabel_read_as_write_or_other_worker_lease_source() {
    let (p, _) = prepared();
    for field in 0..7 {
        let mut a = p.original.clone();
        match field {
            0 => a.effect.usage = a.paired_read.clone(),
            1 => a.profile = p.input.profile().unwrap(),
            2 => a.worker_label = "unconfined".into(),
            3 => a.worker_start = 0,
            4 => a.lease.generation = 0,
            5 => a.effect.subject_generation += 1,
            6 => a.paired_read.selector.digest = "9".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            a.validate(&p.input, &p.review.review_sha256).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn impossible_or_uncovered_budget_refuses_instead_of_claiming_reserved_capacity() {
    let (p, _) = prepared();
    let mut b = base();
    b.physical.allocated_bytes = 64 * 1024 * 1024 * 1024;
    assert!(Preparation::data(
        &b,
        &p.input,
        &p.review,
        &objects(),
        &p.original,
        &mut || Ok(())
    )
    .is_err());
    let mut r = p.review.clone();
    r.maximum_write_bytes = 128 * 1024 * 1024;
    // The original review hash is now wrong even before the unchanged effect
    // ceiling independently rejects derivative plus metadata liability.
    assert!(
        Preparation::data(&base(), &p.input, &r, &objects(), &p.original, &mut || Ok(
            ()
        ))
        .is_err()
    );
    let mut altered = p.clone();
    altered.capacity = policy::Policy::compiled()
        .admit_data(
            &base().physical,
            base().segments,
            [],
            &policy::Liability::default(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(altered.validate_data().is_err());
    let mut understated = p.clone();
    understated.liability.allocated_bytes -= 1;
    understated.capacity = policy::Policy::compiled()
        .admit_data(
            &base().physical,
            base().segments,
            [],
            &understated.liability,
            &mut || Ok(()),
        )
        .unwrap();
    assert!(understated.validate_data().is_err());
}
#[test]
fn retain_is_distinct_finite_action_preserving_every_byte_and_inode_liability() {
    let (p, _) = prepared();
    let input = request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding(),
        request_id: "f".repeat(32),
        operation: request::Operation::Retain {
            job_id: "b".repeat(32),
            expected_job_sha256: p.review.base_sha256.clone(),
            preparation_sha256: hash(&p.bytes().unwrap()),
            retained_inventory_sha256: "a".repeat(64),
            review_sha256: "b".repeat(64),
        },
    };
    let a = attributed(&input, &"b".repeat(64));
    let retained = RetainedPreparation::data(&p, &input, &a).unwrap();
    assert_eq!(retained.liability, p.liability);
    assert!(retained.bytes(&p).unwrap().len() < PREPARATION_BYTES as usize);
    let mut changed = retained.clone();
    changed.liability.allocated_bytes -= 1;
    assert!(changed.validate_against(&p).is_err());
    let mut changed = retained.clone();
    changed.liability.regular_files -= 1;
    assert!(changed.validate_against(&p).is_err());
    assert!(RetainedPreparation::data(&p, &p.input, &p.original).is_err());
    let mut wrong = input;
    wrong.binding.owner_generation += 1;
    assert!(RetainedPreparation::data(&p, &wrong, &a).is_err());
}
