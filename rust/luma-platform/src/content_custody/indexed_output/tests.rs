//! Producer DATA fixtures do not manufacture current sessions or C authority.
use super::*;

pub(in crate::content_checkpoint::custody) fn descriptor() -> Descriptor {
    let input: Input = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "login": "owner", "request_id": "aa".repeat(16),
        "binding": {"installation": "11".repeat(32), "owner": "22".repeat(32), "owner_generation": 7},
        "operation": {"kind": "status"}
    })).unwrap();
    Descriptor {
        profile: input.profile().unwrap(),
        storage_device: "8:1".into(),
        binding: input.binding.clone(),
        lease: crate::resources::Token {
            lease_id: "33".repeat(16),
            generation: 1,
            manager_epoch: "44".repeat(16),
        },
        output_sha256: "55".repeat(32),
        paged_head_sha256: None,
        paged_source: None,
        index: Some(IndexProof {
            selection_sha256: "66".repeat(32),
            source: String::from_utf8(input.canonical_bytes().unwrap()).unwrap(),
        }),
    }
}
fn fixture() -> (Descriptor, Audit, Key) {
    let descriptor = descriptor();
    let audit = Audit {
        subject: descriptor.binding.owner.clone(),
        subject_generation: descriptor.binding.owner_generation,
        grant_id: "index-reader-fixture".into(),
        grant_version: 1,
        checkpoint_head: "77".repeat(32),
        operation_id: Some("88".repeat(16)),
        usage: descriptor.usage().unwrap(),
    };
    let key = Key::descriptor(&descriptor, &audit).unwrap();
    (descriptor, audit, key)
}

#[test]
fn observed_result_selection_and_complete_original_operation_cannot_be_relabelled() {
    let (descriptor, _, key) = fixture();
    let selection = &descriptor.index.as_ref().unwrap().selection_sha256;
    let mut registry = Registry::default();
    registry
        .remember(&key, selection, &descriptor.output_sha256, 10)
        .unwrap();
    registry
        .require(&key, selection, &descriptor.output_sha256, 11)
        .unwrap();
    assert!(registry
        .require(&key, &"99".repeat(32), &descriptor.output_sha256, 11)
        .is_err());
    assert!(registry
        .require(&key, selection, &"99".repeat(32), 11)
        .is_err());
    assert!(registry
        .remember(&key, &"99".repeat(32), &descriptor.output_sha256, 11)
        .is_err());
    for attack in 0..10 {
        let (_, _, mut changed) = fixture();
        match attack {
            0 => changed.audit.operation_id = Some("99".repeat(16)),
            1 => changed.audit.checkpoint_head = "99".repeat(32),
            2 => changed.audit.grant_id = "another-reader".into(),
            3 => changed.source_sha256 = "99".repeat(32),
            4 => changed.profile.push('x'),
            5 => changed.binding.owner_generation += 1,
            6 => changed.binding.owner = "99".repeat(32),
            7 => changed.lease.generation += 1,
            8 => changed.lease.manager_epoch = "99".repeat(16),
            _ => changed.lease.lease_id = "99".repeat(16),
        }
        assert!(
            registry
                .require(&changed, selection, &descriptor.output_sha256, 11)
                .is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn producer_expiry_is_exact_nonrenewing_and_restart_never_adopts_data() {
    let (descriptor, _, key) = fixture();
    let selection = &descriptor.index.as_ref().unwrap().selection_sha256;
    let mut registry = Registry::default();
    registry
        .remember(&key, selection, &descriptor.output_sha256, 5)
        .unwrap();
    registry
        .remember(&key, selection, &descriptor.output_sha256, TTL_MS)
        .unwrap();
    registry
        .require(&key, selection, &descriptor.output_sha256, TTL_MS + 4)
        .unwrap();
    assert!(registry
        .require(&key, selection, &descriptor.output_sha256, TTL_MS + 5)
        .is_err());
    assert_eq!(registry.bytes, 0);
    assert!(Registry::default()
        .require(&key, selection, &descriptor.output_sha256, 6)
        .is_err());
}

#[test]
fn producer_storage_is_finite_and_does_not_evict_live_operations() {
    let (descriptor, _, _) = fixture();
    let selection = &descriptor.index.as_ref().unwrap().selection_sha256;
    let mut registry = Registry::default();
    for n in 0..COUNT {
        let (_, _, mut key) = fixture();
        key.audit.operation_id = Some(format!("{n:032x}"));
        registry
            .remember(&key, selection, &descriptor.output_sha256, 0)
            .unwrap();
    }
    let (_, _, mut extra) = fixture();
    extra.audit.operation_id = Some("ff".repeat(16));
    assert!(registry
        .remember(&extra, selection, &descriptor.output_sha256, 1)
        .is_err());
    assert_eq!(registry.entries.len(), COUNT);
    let (_, _, mut first) = fixture();
    first.audit.operation_id = Some(format!("{:032x}", 0));
    registry
        .require(&first, selection, &descriptor.output_sha256, 1)
        .unwrap();
    let mut bounded = Registry {
        entries: BTreeMap::new(),
        bytes: BYTES,
    };
    // Pruning recomputes bytes from actual entries, never a persisted counter.
    bounded
        .remember(&extra, selection, &descriptor.output_sha256, 1)
        .unwrap();
    assert_eq!(
        bounded.bytes,
        bounded.entries.values().map(Entry::size).sum::<usize>()
    );
}

#[test]
fn missing_mixed_changed_and_noncanonical_index_source_is_not_output_authority() {
    let (descriptor, audit, _) = fixture();
    for attack in 0..8 {
        let mut changed = descriptor.clone();
        match attack {
            0 => changed.index = None,
            1 => changed.paged_head_sha256 = Some("aa".repeat(32)),
            2 => changed.paged_source = Some("{}".into()),
            3 => changed.index.as_mut().unwrap().source.push(' '),
            4 => changed.index.as_mut().unwrap().selection_sha256 = "00".repeat(32),
            5 => changed.binding.owner_generation += 1,
            6 => changed.index.as_mut().unwrap().source = "x".repeat(4097),
            _ => changed.lease.generation = 0,
        }
        assert!(
            Key::descriptor(&changed, &audit)
                .and_then(|k| k.bytes())
                .is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn producer_byte_bound_refuses_before_entry_count_and_preserves_existing_data() {
    let (descriptor, _, mut key) = fixture();
    let selection = &descriptor.index.as_ref().unwrap().selection_sha256;
    // Synthetic keys exercise only the private DATA storage cap. Actual
    // production keys can originate only from the validated descriptor.
    while key.bytes().unwrap().len() < 4000 {
        key.profile.push('x');
    }
    let mut registry = Registry::default();
    let mut admitted = 0;
    for n in 0..COUNT {
        key.audit.operation_id = Some(format!("{n:032x}"));
        if registry
            .remember(&key, selection, &descriptor.output_sha256, 0)
            .is_err()
        {
            break;
        }
        admitted += 1;
    }
    assert!(admitted > 0 && admitted < COUNT);
    assert!(registry.bytes <= BYTES);
    assert_eq!(registry.entries.len(), admitted);
    key.audit.operation_id = Some(format!("{:032x}", 0));
    registry
        .require(&key, selection, &descriptor.output_sha256, 1)
        .unwrap();
}
