//! Producer DATA/cache tests. Fixture audits are not original PAM/C authority.
use super::*;
use crate::service::content_output::Descriptor;

fn fixture() -> (Descriptor, Audit, Key) {
    let descriptor = crate::service::content_output::paged_tests::fixture();
    let audit = Audit {
        subject: descriptor.binding.owner.clone(),
        subject_generation: descriptor.binding.owner_generation,
        grant_id: "page-reader-fixture".into(),
        grant_version: 1,
        checkpoint_head: "99".repeat(32),
        operation_id: Some("aa".repeat(16)),
        usage: descriptor.usage().unwrap(),
    };
    let key = Key::descriptor(&descriptor, &audit).unwrap();
    (descriptor, audit, key)
}

#[test]
fn exact_observed_result_cannot_be_relabelled_to_new_head_or_bytes() {
    let (descriptor, _, key) = fixture();
    let head = descriptor.paged_head_sha256.as_ref().unwrap();
    let mut registry = Registry::default();
    registry
        .remember(&key, head, &descriptor.output_sha256, 100)
        .unwrap();
    registry
        .require(&key, head, &descriptor.output_sha256, 101)
        .unwrap();
    assert!(registry
        .require(&key, &"bb".repeat(32), &descriptor.output_sha256, 101)
        .is_err());
    assert!(registry.require(&key, head, &"cc".repeat(32), 101).is_err());
    assert!(registry
        .remember(&key, &"bb".repeat(32), &descriptor.output_sha256, 101)
        .is_err());
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn full_original_audit_source_profile_owner_and_lease_are_part_of_key() {
    let (descriptor, _, key) = fixture();
    let head = descriptor.paged_head_sha256.as_ref().unwrap();
    let mut registry = Registry::default();
    registry
        .remember(&key, head, &descriptor.output_sha256, 0)
        .unwrap();
    for attack in 0..10 {
        let (_, _, mut changed) = fixture();
        match attack {
            0 => changed.audit.operation_id = Some("bb".repeat(16)),
            1 => changed.audit.checkpoint_head = "bb".repeat(32),
            2 => changed.audit.grant_id = "other-reader-fixture".into(),
            3 => changed.source_sha256 = "bb".repeat(32),
            4 => changed.profile.push('x'),
            5 => changed.binding.owner_generation += 1,
            6 => changed.binding.owner = "bb".repeat(32),
            7 => changed.lease.generation += 1,
            8 => changed.lease.manager_epoch = "bb".repeat(16),
            _ => changed.lease.lease_id = "bb".repeat(16),
        }
        assert!(
            registry
                .require(&changed, head, &descriptor.output_sha256, 1)
                .is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn expiry_is_exact_nonrenewing_and_restart_has_no_adoption() {
    let (descriptor, _, key) = fixture();
    let head = descriptor.paged_head_sha256.as_ref().unwrap();
    let mut registry = Registry::default();
    registry
        .remember(&key, head, &descriptor.output_sha256, 5)
        .unwrap();
    registry
        .remember(&key, head, &descriptor.output_sha256, TTL_MS)
        .unwrap();
    registry
        .require(&key, head, &descriptor.output_sha256, TTL_MS + 4)
        .unwrap();
    assert!(registry
        .require(&key, head, &descriptor.output_sha256, TTL_MS + 5)
        .is_err());
    assert_eq!(registry.bytes, 0);
    assert!(Registry::default()
        .require(&key, head, &descriptor.output_sha256, 6)
        .is_err());
}

#[test]
fn finite_capacity_refuses_without_eviction_or_replacement() {
    let (descriptor, _, _) = fixture();
    let head = descriptor.paged_head_sha256.as_ref().unwrap();
    let mut registry = Registry::default();
    for i in 0..COUNT {
        let (_, _, mut key) = fixture();
        key.audit.operation_id = Some(format!("{i:032x}"));
        registry
            .remember(&key, head, &descriptor.output_sha256, 0)
            .unwrap();
    }
    let (_, _, mut extra) = fixture();
    extra.audit.operation_id = Some("ff".repeat(16));
    let before = registry.bytes;
    assert!(registry
        .remember(&extra, head, &descriptor.output_sha256, 1)
        .is_err());
    assert_eq!(registry.entries.len(), COUNT);
    assert_eq!(registry.bytes, before);
    assert!(registry.bytes <= BYTES);
    let (_, _, mut first) = fixture();
    first.audit.operation_id = Some(format!("{:032x}", 0));
    registry
        .require(&first, head, &descriptor.output_sha256, 1)
        .unwrap();
    registry
        .remember(&extra, head, &descriptor.output_sha256, TTL_MS)
        .unwrap();
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn malformed_key_and_zero_digest_cannot_enter_registry() {
    let (descriptor, _, key) = fixture();
    let head = descriptor.paged_head_sha256.as_ref().unwrap();
    let mut registry = Registry::default();
    assert!(registry
        .remember(&key, &"00".repeat(32), &descriptor.output_sha256, 0)
        .is_err());
    assert!(registry.remember(&key, head, &"00".repeat(32), 0).is_err());
    let (_, _, mut malformed) = fixture();
    malformed.lease.generation = 0;
    assert!(registry
        .remember(&malformed, head, &descriptor.output_sha256, 0)
        .is_err());
    assert!(registry.entries.is_empty());
    assert!(registry
        .remember(&key, head, &descriptor.output_sha256, u64::MAX)
        .is_err());
}

#[test]
fn descriptor_cannot_strip_source_or_original_subject() {
    let (mut descriptor, mut audit, _) = fixture();
    descriptor.paged_source = None;
    assert!(Key::descriptor(&descriptor, &audit).is_err());
    descriptor = crate::service::content_output::paged_tests::fixture();
    audit.subject = "bb".repeat(32);
    assert!(Key::descriptor(&descriptor, &audit).is_err());
    audit.subject = descriptor.binding.owner.clone();
    audit.operation_id = None;
    assert!(Key::descriptor(&descriptor, &audit).is_err());
}

#[test]
fn fresh_live_checks_are_required_even_with_exact_retained_data() {
    let (descriptor, mut audit, _) = fixture();
    audit.operation_id = Some("ab".repeat(16));
    let key = Key::descriptor(&descriptor, &audit).unwrap();
    let id = hash(&key.bytes().unwrap());
    let now = crate::resource_manager::now().unwrap();
    registry()
        .lock()
        .unwrap()
        .remember(
            &key,
            descriptor.paged_head_sha256.as_ref().unwrap(),
            &descriptor.output_sha256,
            now,
        )
        .unwrap();
    let mut calls = 0;
    let mut live = || {
        calls += 1;
        if calls == 2 {
            return Err("fixture original revoked after observation".into());
        }
        Ok(())
    };
    assert!(require(&descriptor, &audit, &mut live).is_err());
    assert_eq!(calls, 2);
    let mut revoked = || -> Result<()> { Err("fixture original already revoked".into()) };
    assert!(require(&descriptor, &audit, &mut revoked).is_err());
    let mut registry = registry().lock().unwrap();
    registry.entries.remove(&id);
    registry.bytes = registry.entries.values().map(Entry::size).sum();
}
