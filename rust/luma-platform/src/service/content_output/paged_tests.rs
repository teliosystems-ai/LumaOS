//! Pure descriptor/source data tests, not a current C/grant qualification.
use super::*;
pub(crate) fn fixture() -> Descriptor {
    let binding = OwnerBinding {
        installation: "11".repeat(32),
        owner: "22".repeat(32),
        owner_generation: 7,
    };
    let raw = serde_json::to_vec(&serde_json::json!({"schema_version":1,"login":"owner","binding":binding,
        "operation":{"kind":"page","expected":{"artifact_id":"fixture","version":1,"content_sha256":"33".repeat(32),"receipt_sha256":"44".repeat(32)},"offset":0,"bytes":16384}})).unwrap();
    let bytes = crate::content_governed::canonical_request(&raw).unwrap();
    let digest = crate::artifacts::digest(&bytes);
    Descriptor {
        profile: format!("content-v1-query-7-{digest}-{digest}"),
        storage_device: "8:1".into(),
        binding,
        lease: Token {
            lease_id: "55".repeat(16),
            generation: 1,
            manager_epoch: "66".repeat(16),
        },
        output_sha256: "77".repeat(32),
        paged_head_sha256: Some("88".repeat(32)),
        paged_source: Some(String::from_utf8(bytes).unwrap()),
        index: None,
    }
}
#[test]
fn paired_paged_source_reuses_exact_existing_read_usage_and_bounds() {
    let descriptor = fixture();
    let usage = descriptor.usage().unwrap();
    assert_eq!(usage.action, crate::finite_grants::Action::Read);
    assert_eq!(usage.selector.id, "native-content-query-v1");
    assert!(descriptor.page_source().unwrap().is_some());
    assert!(serde_json::to_vec(&descriptor).unwrap().len() < 8192);
}
#[test]
fn one_sided_zero_head_stale_source_and_nonpage_scope_refuse() {
    for attack in 0..8 {
        let mut descriptor = fixture();
        match attack {
            0 => descriptor.paged_head_sha256 = None,
            1 => descriptor.paged_source = None,
            2 => descriptor.paged_head_sha256 = Some("00".repeat(32)),
            3 => descriptor.paged_head_sha256 = Some("GG".repeat(32)),
            4 => descriptor.paged_source.as_mut().unwrap().push(' '),
            5 => descriptor.paged_source = Some(" ".repeat(4097)),
            6 => descriptor.profile = descriptor.profile.replace("query", "envelope"),
            _ => {
                let mut source: serde_json::Value =
                    serde_json::from_str(descriptor.paged_source.as_ref().unwrap()).unwrap();
                source["operation"] = serde_json::json!({"kind":"current","artifact_id":"fixture"});
                let bytes = crate::content_governed::canonical_request(
                    &serde_json::to_vec(&source).unwrap(),
                )
                .unwrap();
                let digest = crate::artifacts::digest(&bytes);
                descriptor.profile = format!("content-v1-query-7-{digest}-{digest}");
                descriptor.paged_source = Some(String::from_utf8(bytes).unwrap());
            }
        }
        assert!(descriptor.usage().is_err());
    }
}
#[test]
fn both_absent_preserve_exact_legacy_descriptor_bytes_not_a_paged_permission() {
    let mut descriptor = fixture();
    descriptor.paged_head_sha256 = None;
    descriptor.paged_source = None;
    #[derive(Serialize)]
    struct Legacy<'a> {
        profile: &'a str,
        storage_device: &'a str,
        binding: &'a OwnerBinding,
        lease: &'a Token,
        output_sha256: &'a str,
    }
    let old = Legacy {
        profile: &descriptor.profile,
        storage_device: &descriptor.storage_device,
        binding: &descriptor.binding,
        lease: &descriptor.lease,
        output_sha256: &descriptor.output_sha256,
    };
    assert_eq!(
        serde_json::to_vec(&descriptor).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );
    assert!(descriptor.page_source().unwrap().is_none());
    // Runtime None deliberately uses only Store::installed, whose actual
    // format guard refuses any paged namespace; this data test cannot grant it.
}
