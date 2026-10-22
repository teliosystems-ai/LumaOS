use super::*;

fn owner() -> OwnerBinding {
    OwnerBinding {
        installation: "11".repeat(32),
        owner: "22".repeat(32),
        owner_generation: 3,
    }
}
fn blob(bytes: u64) -> BlobReference {
    BlobReference {
        schema_version: 1,
        domain: luma_content_store::v2::DOMAIN.into(),
        binding: owner(),
        sha256: "33".repeat(32),
        bytes,
        chunk_count: ((bytes + 16383) / 16384) as u32,
        index_sha256: Some("44".repeat(32)),
    }
}
fn leaf() -> Leaf {
    Leaf {
        schema_version: 2,
        binding: owner(),
        current_generation: Some(blob(GENERATION_BYTES)),
        current_job: Some(blob(JOB_BYTES)),
        preparation: Some(RecordRef {
            sha256: "66".repeat(32),
            bytes: PREPARATION_BYTES,
        }),
    }
}
#[test]
fn selected_index_leaf_has_closed_distinct_record_limits_and_owner_generation() {
    let original = leaf();
    let bytes = serde_json::to_vec(&original).unwrap();
    assert_eq!(Leaf::parse(&bytes, &owner()).unwrap(), original);
    assert!(bytes.len() <= LEAF_BYTES);
    for kind in 0..2 {
        let mut changed = original.clone();
        let reference = match kind {
            0 => &mut changed.current_generation,
            _ => &mut changed.current_job,
        };
        let reference = reference.as_mut().unwrap();
        reference.bytes += 1;
        reference.chunk_count = ((reference.bytes + 16383) / 16384) as u32;
        assert!(changed.validate(&owner()).is_err());
        let mut changed = original.clone();
        let reference = match kind {
            0 => &mut changed.current_generation,
            _ => &mut changed.current_job,
        };
        reference.as_mut().unwrap().binding.owner_generation += 1;
        assert!(changed.validate(&owner()).is_err());
    }
    let mut oversized = original.clone();
    oversized.preparation.as_mut().unwrap().bytes += 1;
    assert!(oversized.validate(&owner()).is_err());
    let mut changed_owner = owner();
    changed_owner.owner_generation += 1;
    assert!(Leaf::parse(&bytes, &changed_owner).is_err());
    assert!(Leaf::parse(
        serde_json::to_string_pretty(&original).unwrap().as_bytes(),
        &owner()
    )
    .is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["authorized"] = serde_json::Value::Bool(true);
    assert!(Leaf::parse(&serde_json::to_vec(&value).unwrap(), &owner()).is_err());
}
#[test]
fn absent_generation_and_pending_start_are_data_not_a_synthetic_usable_index() {
    let empty = Leaf {
        schema_version: 2,
        binding: owner(),
        current_generation: None,
        current_job: None,
        preparation: None,
    };
    empty.validate(&owner()).unwrap();
    assert!(empty.current_generation.is_none());
    let mut pending_start = empty.clone();
    pending_start.preparation = Some(RecordRef {
        sha256: "66".repeat(32),
        bytes: PREPARATION_BYTES,
    });
    pending_start.validate(&owner()).unwrap();
    assert_ne!(empty.sha256().unwrap(), pending_start.sha256().unwrap());
    assert!(pending_start.current_job.is_none());
    assert!(pending_start.current_generation.is_none());
    let mut changed = pending_start.clone();
    changed.schema_version = 1;
    assert!(changed.validate(&owner()).is_err());
}
#[test]
fn c_map_reference_is_small_canonical_and_cannot_select_another_owner() {
    let bytes = serde_json::to_vec(&leaf()).unwrap();
    let reference = Reference {
        schema_version: 2,
        binding: owner(),
        record: RecordRef {
            sha256: hash(&bytes),
            bytes: bytes.len() as u64,
        },
    };
    let encoded = serde_json::to_vec(&reference).unwrap();
    assert!(encoded.len() <= map::MAX_VALUE_BYTES);
    assert_eq!(Reference::parse(&encoded, &owner()).unwrap(), reference);
    let mut changed = reference.clone();
    changed.record.bytes = LEAF_BYTES as u64 + 1;
    assert!(Reference::parse(&serde_json::to_vec(&changed).unwrap(), &owner()).is_err());
    let mut changed_owner = owner();
    changed_owner.owner = "55".repeat(32);
    assert!(Reference::parse(&encoded, &changed_owner).is_err());
}
