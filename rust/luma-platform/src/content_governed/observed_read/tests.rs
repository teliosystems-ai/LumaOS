//! Pure source/shape tests with explicit fixture audits, not original PAM/C.
use super::*;
fn fixture() -> (Input, Vec<u8>, String, ArtifactVersion) {
    let binding = OwnerBinding {
        installation: "11".repeat(32),
        owner: "22".repeat(32),
        owner_generation: 7,
    };
    let version = luma_content::capture(
        binding.clone(),
        "page",
        Format::Utf8Text,
        b"native page bytes",
        Provenance {
            request_id: "read-fixture".into(),
            workflow_sha256: "33".repeat(32),
            source_sha256: io::digest(b"native page bytes"),
            origin: luma_content::EditOrigin::External,
        },
    )
    .unwrap();
    let input = Input {
        schema_version: 1,
        login: "owner".into(),
        binding,
        operation: Operation::Page {
            expected: version.reference().unwrap(),
            offset: 3,
            bytes: 16,
        },
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let profile = profile_id(Mode::Query, &input, &bytes, &io::digest(&bytes)).unwrap();
    (input, bytes, profile, version)
}
fn audit(source: &PageSource) -> grants::Audit {
    grants::Audit {
        subject: source.binding.owner.clone(),
        subject_generation: source.binding.owner_generation,
        grant_id: "explicit-reader-fixture".into(),
        grant_version: 1,
        checkpoint_head: "44".repeat(32),
        operation_id: Some("55".repeat(16)),
        usage: source.usage.clone(),
    }
}
#[test]
fn existing_canonical_page_scope_and_envelope_slice_are_preserved_exactly() {
    let (input, bytes, profile, version) = fixture();
    let page = PageSource::parse(&bytes, &profile, "8:1", &input.binding).unwrap();
    page.check_original(&audit(&page)).unwrap();
    assert_eq!(page.source_sha256(), io::digest(&bytes));
    assert_eq!(page.expected(), &version.reference().unwrap());
    let result = page.result(&version).unwrap();
    page.validate_result(&result).unwrap();
    assert_eq!(result, version_result(&version, Some((3, 16))).unwrap());
    assert_eq!(
        result["slice_hex"],
        encode_hex(&version.canonical_envelope().unwrap()[3..19])
    );
}
#[test]
fn changed_source_profile_owner_or_nonpage_operation_cannot_borrow_read_scope() {
    let (mut input, bytes, profile, _) = fixture();
    assert!(PageSource::parse(
        &bytes,
        &profile.replace("query", "read"),
        "8:1",
        &input.binding
    )
    .is_err());
    assert!(PageSource::parse(
        &bytes,
        &profile.replace("query", "envelope"),
        "8:1",
        &input.binding
    )
    .is_err());
    assert!(PageSource::parse(&bytes, &profile, "0:1", &input.binding).is_err());
    let mut owner = input.binding.clone();
    owner.owner_generation += 1;
    assert!(PageSource::parse(&bytes, &profile, "8:1", &owner).is_err());
    let mut newline = bytes.clone();
    newline.push(b'\n');
    assert!(PageSource::parse(&newline, &profile, "8:1", &input.binding).is_err());
    let expected = match &input.operation {
        Operation::Page { expected, .. } => expected.clone(),
        _ => panic!("fixture Page"),
    };
    input.operation = Operation::Envelope { expected };
    let bytes = serde_json::to_vec(&input).unwrap();
    let profile = profile_id(Mode::Envelope, &input, &bytes, &io::digest(&bytes)).unwrap();
    assert!(PageSource::parse(&bytes, &profile, "8:1", &input.binding).is_err());
}
#[test]
fn wrong_subject_usage_or_nonoriginal_audit_refuses() {
    let (input, bytes, profile, _) = fixture();
    let page = PageSource::parse(&bytes, &profile, "8:1", &input.binding).unwrap();
    for attack in 0..5 {
        let mut changed = audit(&page);
        match attack {
            0 => changed.subject = "66".repeat(32),
            1 => changed.subject_generation += 1,
            2 => changed.usage.input_bytes -= 1,
            3 => changed.operation_id = None,
            _ => changed.usage.selector.id = "native-content-inspect-v1".into(),
        }
        assert!(page.check_original(&changed).is_err());
    }
}
#[test]
fn page_result_is_closed_and_cannot_return_authority_or_another_reference() {
    let (input, bytes, profile, version) = fixture();
    let page = PageSource::parse(&bytes, &profile, "8:1", &input.binding).unwrap();
    for attack in 0..7 {
        let mut value = page.result(&version).unwrap();
        match attack {
            0 => value["authority_returned"] = true.into(),
            1 => value["offset"] = 2.into(),
            2 => value["reference"]["version"] = 2.into(),
            3 => value["encoding"] = "raw".into(),
            4 => value["slice_hex"] = "00".into(),
            5 => value["head_authorized"] = true.into(),
            _ => value["production_qualified"] = true.into(),
        }
        assert!(page.validate_result(&value).is_err());
    }
}
