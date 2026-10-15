use super::*;

fn owner() -> OwnerBinding {
    OwnerBinding {
        installation: "1".repeat(64),
        owner: "2".repeat(64),
        owner_generation: 7,
    }
}

fn provenance(bytes: &[u8], origin: EditOrigin) -> Provenance {
    Provenance {
        request_id: "request-1".into(),
        workflow_sha256: "3".repeat(64),
        source_sha256: sha256(bytes),
        origin,
    }
}

fn document(format: Format, bytes: &[u8]) -> ArtifactVersion {
    capture(
        owner(),
        "artifact-1",
        format,
        bytes,
        provenance(bytes, EditOrigin::Managed),
    )
    .unwrap()
}

fn edit(
    current: &ArtifactVersion,
    expected: &VersionReference,
    bytes: &[u8],
) -> Result<EditDecision> {
    compare_external_edit(
        current,
        expected,
        &owner(),
        bytes,
        provenance(bytes, EditOrigin::External),
    )
}

#[test]
fn sha256_known_answer() {
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn text_retains_unicode_and_normalizes_only_crlf() {
    let original = "Résumé\r\n\t東京 e\u{301}\n";
    let document = document(Format::Utf8Text, original.as_bytes());
    assert_eq!(document.content(), "Résumé\n\t東京 e\u{301}\n".as_bytes());
    assert_eq!(
        document.receipt().provenance.source_sha256,
        sha256(original.as_bytes())
    );
    assert_ne!(
        document.receipt().content_sha256,
        sha256(original.as_bytes())
    );
    assert_eq!(document.receipt().original_bytes, original.len() as u64);
}

#[test]
fn captures_are_deterministic_and_reopen_identically() {
    for (format, input) in [
        (Format::Utf8Text, "héllo\r\nworld"),
        (Format::Json, " {\"z\":2,\"a\":[true,null,\"é\"]} "),
        (Format::Csv, "a,b\r\n\"x,y\",\"he said \"\"yes\"\"\"\r\n"),
    ] {
        let first = document(format, input.as_bytes());
        let second = document(format, input.as_bytes());
        let encoded = first.canonical_envelope().unwrap();
        assert_eq!(encoded, second.canonical_envelope().unwrap());
        assert_eq!(reopen(&encoded, &owner()).unwrap(), first);
        assert_eq!(first.reference().unwrap(), second.reference().unwrap());
    }
}

#[test]
fn json_sorts_all_object_keys_and_removes_insignificant_whitespace() {
    let document = document(Format::Json, br#" { "z": {"c":1,"a":2}, "a":true } "#);
    assert_eq!(document.content(), br#"{"a":true,"z":{"a":2,"c":1}}"#);
}

#[test]
fn json_duplicate_keys_including_escaped_and_nested_keys_refused() {
    for source in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"x":[{"a":1,"a":2}]}"#,
    ] {
        assert_eq!(
            canonical::content(Format::Json, source.as_bytes()),
            Err(Error::InvalidJson)
        );
    }
}

#[test]
fn json_integer_literals_do_not_silently_round() {
    for value in ["18446744073709551616", "-9223372036854775809"] {
        assert_eq!(
            canonical::content(Format::Json, value.as_bytes()),
            Err(Error::InvalidJson)
        );
    }
    for value in ["18446744073709551615", "-9223372036854775808"] {
        assert_eq!(
            canonical::content(Format::Json, value.as_bytes()).unwrap(),
            value
        );
    }
}

#[test]
fn json_floats_use_explicit_serde_representation_not_exact_decimals() {
    assert_ne!(
        document(Format::Json, b"1").content(),
        document(Format::Json, b"1.0").content()
    );
    assert_eq!(document(Format::Json, b"1e0").content(), b"1.0");
    for source in ["-0.0", "0.1", "1.2345678901234567", "1e100", "1.0e-100"] {
        let value = document(Format::Json, source.as_bytes());
        assert_eq!(
            reopen(&value.canonical_envelope().unwrap(), &owner()).unwrap(),
            value
        );
    }
    assert_eq!(
        canonical::content(Format::Json, b"1e999"),
        Err(Error::InvalidJson)
    );
}

#[test]
fn json_structure_limits_refuse_depth_and_nodes() {
    let deep = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert_eq!(
        canonical::content(Format::Json, deep.as_bytes()),
        Err(Error::InvalidJson)
    );
    let wide = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
    assert_eq!(
        canonical::content(Format::Json, wide.as_bytes()),
        Err(Error::InvalidJson)
    );
    let accepted = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert!(canonical::content(Format::Json, accepted.as_bytes()).is_ok());
}

#[test]
fn json_invalid_trailing_or_nul_data_refused() {
    for source in [
        "{}{}",
        "[1,]",
        "NaN",
        "Infinity",
        r#""\u0000""#,
        r#"{"\u0000":1}"#,
        "01",
        "--1",
    ] {
        assert_eq!(
            canonical::content(Format::Json, source.as_bytes()),
            Err(Error::InvalidJson)
        );
    }
}

#[test]
fn finite_decimal_canonicalization_reopens_without_a_second_numeric_change() {
    for source in [
        "0.246094891800000034",
        "0.247412855200000052",
        "0.223771953400000058",
    ] {
        let version = document(Format::Json, source.as_bytes());
        assert_eq!(
            reopen(&version.canonical_envelope().unwrap(), &owner()).unwrap(),
            version
        );
    }
}

#[test]
fn csv_quoting_and_line_endings_are_canonical() {
    let document = document(Format::Csv, b"\"a\",b\r\n\"two\r\nlines\",\"a\"\"b\"\r\n");
    assert_eq!(document.content(), b"a,b\n\"two\nlines\",\"a\"\"b\"\n");
    assert_eq!(document.receipt().media_type, "text/csv; charset=utf-8");
}

#[test]
fn csv_retains_empty_cells_and_final_delimiters() {
    for (source, expected) in [("a,b\nx,", "a,b\nx,\n"), ("\"\"", "\n"), (",", ",\n")] {
        assert_eq!(
            document(Format::Csv, source.as_bytes()).content(),
            expected.as_bytes()
        );
    }
}

#[test]
fn csv_malformed_quote_or_ragged_records_refused() {
    for source in ["a,b\nc", "a\"b,c", "\"a\" x,b", "\"a", "a,b\n\n"] {
        assert_eq!(
            canonical::content(Format::Csv, source.as_bytes()),
            Err(Error::InvalidCsv)
        );
    }
}

#[test]
fn csv_structural_limits_are_enforced() {
    for source in [
        vec!["a"; MAX_CSV_COLUMNS + 1].join(","),
        "a\n".repeat(MAX_CSV_ROWS + 1),
        "a".repeat(MAX_CSV_FIELD_BYTES + 1),
    ] {
        assert_eq!(
            canonical::content(Format::Csv, source.as_bytes()),
            Err(Error::Bounds)
        );
    }
    assert!(canonical::content(Format::Csv, &vec![b'a'; MAX_CSV_FIELD_BYTES]).is_ok());
}

#[test]
fn empty_oversized_invalid_utf8_and_unsupported_controls_refused() {
    for format in [Format::Utf8Text, Format::Json, Format::Csv] {
        if format == Format::Utf8Text {
            assert_eq!(canonical::content(format, b"").unwrap(), "");
        } else {
            assert_eq!(canonical::content(format, b""), Err(Error::Bounds));
        }
        assert_eq!(
            canonical::content(format, &vec![b'a'; MAX_CONTENT_BYTES + 1]),
            Err(Error::Bounds)
        );
        assert_eq!(canonical::content(format, &[0xff]), Err(Error::InvalidUtf8));
        for bytes in [b"a\0b".as_slice(), b"a\x01b", "\u{feff}a".as_bytes()] {
            assert_eq!(canonical::content(format, bytes), Err(Error::InvalidText));
        }
    }
    assert_eq!(
        canonical::content(Format::Utf8Text, b"a\rb"),
        Err(Error::InvalidText)
    );
    assert_eq!(
        canonical::content(Format::Csv, b"a\rb"),
        Err(Error::InvalidText)
    );
}

#[test]
fn blank_text_and_delete_all_saves_preserve_identity_and_reopen() {
    let blank = document(Format::Utf8Text, b"");
    assert_eq!(blank.receipt().content_bytes, 0);
    assert_eq!(blank.receipt().original_bytes, 0);
    assert_eq!(
        reopen(&blank.canonical_envelope().unwrap(), &owner()).unwrap(),
        blank
    );
    let original = document(Format::Utf8Text, b"Original");
    let EditDecision::NewVersion(cleared) =
        edit(&original, &original.reference().unwrap(), b"").unwrap()
    else {
        panic!("delete-all must propose a blank version");
    };
    assert_eq!(cleared.content(), b"");
    assert_eq!(cleared.receipt().version, 2);
    assert_eq!(
        cleared.receipt().artifact_id,
        original.receipt().artifact_id
    );
    assert_eq!(
        reopen(&cleared.canonical_envelope().unwrap(), &owner()).unwrap(),
        cleared
    );
}

#[test]
fn canonical_expansion_cannot_exceed_content_bound() {
    let mut source = vec!["a".repeat(MAX_CSV_FIELD_BYTES - 1); 256].join("\n");
    source.push('a');
    assert_eq!(source.len(), MAX_CONTENT_BYTES);
    assert_eq!(
        canonical::content(Format::Csv, source.as_bytes()),
        Err(Error::Bounds)
    );
    assert!(canonical::content(Format::Utf8Text, &vec![b'a'; MAX_CONTENT_BYTES]).is_ok());
}

#[test]
fn invalid_owner_generation_and_hash_bindings_refused() {
    for binding in [
        OwnerBinding {
            owner_generation: 0,
            ..owner()
        },
        OwnerBinding {
            installation: "0".repeat(64),
            ..owner()
        },
        OwnerBinding {
            owner: "A".repeat(64),
            ..owner()
        },
        OwnerBinding {
            owner: "2".repeat(63),
            ..owner()
        },
    ] {
        assert_eq!(
            capture(
                binding,
                "artifact",
                Format::Utf8Text,
                b"a",
                provenance(b"a", EditOrigin::Managed)
            ),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn artifact_and_provenance_identifiers_are_bounded_not_paths() {
    for id in [
        "",
        "../file",
        "/tmp/file",
        "..",
        "a b",
        "a:b",
        &"a".repeat(129),
    ] {
        assert_eq!(
            capture(
                owner(),
                id,
                Format::Utf8Text,
                b"a",
                provenance(b"a", EditOrigin::Managed)
            ),
            Err(Error::InvalidIdentifier)
        );
    }
    let mut provenance = provenance(b"a", EditOrigin::Managed);
    provenance.request_id = "../bad".into();
    assert_eq!(
        capture(owner(), "artifact", Format::Utf8Text, b"a", provenance),
        Err(Error::InvalidProvenance)
    );
}

#[test]
fn capture_requires_exact_original_digest_and_nonzero_workflow() {
    let mut metadata = provenance(b"a", EditOrigin::Managed);
    metadata.source_sha256 = sha256(b"b");
    assert_eq!(
        capture(owner(), "artifact", Format::Utf8Text, b"a", metadata),
        Err(Error::InvalidProvenance)
    );
    let mut metadata = provenance(b"a", EditOrigin::Managed);
    metadata.workflow_sha256 = "0".repeat(64);
    assert_eq!(
        capture(owner(), "artifact", Format::Utf8Text, b"a", metadata),
        Err(Error::InvalidProvenance)
    );
}

#[test]
fn unchanged_canonical_content_does_not_create_version() {
    let current = document(Format::Json, br#"{"a":1}"#);
    let result = edit(&current, &current.reference().unwrap(), br#" { "a" : 1 } "#).unwrap();
    match result {
        EditDecision::NoChange {
            current: reference,
            observed_source_sha256,
        } => {
            assert_eq!(reference, current.reference().unwrap());
            assert_eq!(observed_source_sha256, sha256(br#" { "a" : 1 } "#));
        }
        _ => panic!("unchanged content must not create a version"),
    }
}

#[test]
fn external_save_proposes_next_immutable_version_with_exact_parent() {
    let original = document(Format::Utf8Text, b"original");
    let base = original.reference().unwrap();
    let EditDecision::NewVersion(proposal) = edit(&original, &base, b"edited").unwrap() else {
        panic!("changed content must propose a new version");
    };
    assert_eq!(proposal.receipt().version, 2);
    assert_eq!(proposal.receipt().previous.as_ref(), Some(&base));
    assert_eq!(proposal.receipt().binding, owner());
    assert_eq!(proposal.receipt().provenance.origin, EditOrigin::External);
    assert_eq!(original.content(), b"original");
    assert_eq!(proposal.content(), b"edited");
    assert_eq!(
        reopen(&proposal.canonical_envelope().unwrap(), &owner()).unwrap(),
        proposal
    );
}

#[test]
fn competing_save_preserves_candidate_as_conflict_without_overwrite() {
    let original = document(Format::Utf8Text, b"original");
    let base = original.reference().unwrap();
    let EditDecision::NewVersion(current) = edit(&original, &base, b"agent save").unwrap() else {
        panic!("new version expected")
    };
    let EditDecision::Conflict {
        expected,
        current: observed,
        candidate,
    } = edit(&current, &base, b"editor save").unwrap()
    else {
        panic!("conflict expected")
    };
    assert_eq!(expected, base);
    assert_eq!(observed, current.reference().unwrap());
    assert_eq!(candidate.content, "editor save");
    assert_eq!(candidate.binding, owner());
    assert_eq!(candidate.artifact_id, "artifact-1");
    assert_eq!(candidate.provenance.source_sha256, sha256(b"editor save"));
    assert!(candidate.canonical_bytes().is_ok());
    assert_eq!(current.content(), b"agent save");
    assert_eq!(original.content(), b"original");
}

#[test]
fn stale_same_content_is_still_a_conflict() {
    let original = document(Format::Utf8Text, b"a");
    let base = original.reference().unwrap();
    let EditDecision::NewVersion(current) = edit(&original, &base, b"b").unwrap() else {
        panic!("new version expected")
    };
    assert!(matches!(
        edit(&current, &base, b"b"),
        Ok(EditDecision::Conflict { .. })
    ));
}

#[test]
fn wrong_version_or_digest_is_explicit_conflict() {
    let current = document(Format::Utf8Text, b"a");
    for expected in [
        VersionReference {
            version: 2,
            ..current.reference().unwrap()
        },
        VersionReference {
            content_sha256: "9".repeat(64),
            ..current.reference().unwrap()
        },
        VersionReference {
            receipt_sha256: "8".repeat(64),
            ..current.reference().unwrap()
        },
    ] {
        assert!(matches!(
            edit(&current, &expected, b"b"),
            Ok(EditDecision::Conflict { .. })
        ));
    }
}

#[test]
fn wrong_artifact_is_not_implicitly_retargeted() {
    let current = document(Format::Utf8Text, b"a");
    let expected = VersionReference {
        artifact_id: "other".into(),
        ..current.reference().unwrap()
    };
    assert_eq!(
        edit(&current, &expected, b"b"),
        Err(Error::InvalidIdentifier)
    );
}

#[test]
fn cross_owner_generation_and_installation_reopen_and_edit_refused() {
    let current = document(Format::Utf8Text, b"a");
    for unauthorized in [
        OwnerBinding {
            owner: "4".repeat(64),
            ..owner()
        },
        OwnerBinding {
            owner_generation: 8,
            ..owner()
        },
        OwnerBinding {
            installation: "5".repeat(64),
            ..owner()
        },
    ] {
        assert_eq!(
            reopen(&current.canonical_envelope().unwrap(), &unauthorized),
            Err(Error::OwnerMismatch)
        );
        assert_eq!(
            compare_external_edit(
                &current,
                &current.reference().unwrap(),
                &unauthorized,
                b"b",
                provenance(b"b", EditOrigin::External)
            ),
            Err(Error::OwnerMismatch)
        );
    }
}

#[test]
fn managed_origin_cannot_be_mislabeled_as_external_save() {
    let current = document(Format::Utf8Text, b"a");
    assert_eq!(
        compare_external_edit(
            &current,
            &current.reference().unwrap(),
            &owner(),
            b"b",
            provenance(b"b", EditOrigin::Managed)
        ),
        Err(Error::InvalidProvenance)
    );
}

#[test]
fn exhausted_version_never_wraps() {
    let mut current = document(Format::Utf8Text, b"a");
    current.receipt.version = u64::MAX;
    current.receipt.previous = Some(VersionReference {
        artifact_id: "artifact-1".into(),
        version: u64::MAX - 1,
        content_sha256: "4".repeat(64),
        receipt_sha256: "5".repeat(64),
    });
    assert!(current.validate().is_ok());
    assert_eq!(
        edit(&current, &current.reference().unwrap(), b"b"),
        Err(Error::VersionOverflow)
    );
}

#[test]
fn reopen_refuses_content_receipt_and_transport_tampering() {
    let current = document(Format::Utf8Text, b"a");
    let canonical = current.canonical_envelope().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    value["content"] = "b".into();
    assert_eq!(
        reopen(&serde_json::to_vec(&value).unwrap(), &owner()),
        Err(Error::HashMismatch)
    );
    let mut envelope: Envelope = serde_json::from_slice(&canonical).unwrap();
    envelope.receipt.provenance.request_id = "different-request".into();
    assert_eq!(
        reopen(&serde_json::to_vec(&envelope).unwrap(), &owner()),
        Err(Error::HashMismatch)
    );
    let mut padded = canonical.clone();
    padded.push(b'\n');
    assert_eq!(reopen(&padded, &owner()), Err(Error::NonCanonical));
    let mut envelope: Envelope = serde_json::from_slice(&canonical).unwrap();
    envelope.receipt_sha256 = "0".repeat(64);
    assert_eq!(
        reopen(&serde_json::to_vec(&envelope).unwrap(), &owner()),
        Err(Error::HashMismatch)
    );
}

#[test]
fn reopen_refuses_unknown_duplicate_and_oversized_envelope_fields() {
    let current = document(Format::Utf8Text, b"a");
    let canonical = String::from_utf8(current.canonical_envelope().unwrap()).unwrap();
    let unknown = format!("{{\"extra\":1,{}", &canonical[1..]);
    assert_eq!(
        reopen(unknown.as_bytes(), &owner()),
        Err(Error::InvalidEnvelope)
    );
    let duplicate = format!("{{\"content\":\"a\",{}", &canonical[1..]);
    assert_eq!(
        reopen(duplicate.as_bytes(), &owner()),
        Err(Error::InvalidEnvelope)
    );
    assert_eq!(
        reopen(&vec![b' '; MAX_ENVELOPE_BYTES + 1], &owner()),
        Err(Error::Bounds)
    );
}

#[test]
fn reopen_checks_receipt_schema_media_size_and_parent_chain_shape() {
    for change in [0, 1, 2, 3] {
        let mut current = document(Format::Utf8Text, b"a");
        match change {
            0 => current.receipt.schema_version = 2,
            1 => current.receipt.media_type = "application/msword".into(),
            2 => current.receipt.content_bytes = 0,
            _ => current.receipt.version = 2,
        }
        assert_eq!(current.validate(), Err(Error::InvalidReceipt));
    }
}

#[test]
fn public_candidate_serialization_validates_untrusted_mutations() {
    let current = document(Format::Utf8Text, b"a");
    let expected = VersionReference {
        version: 2,
        ..current.reference().unwrap()
    };
    let EditDecision::Conflict { mut candidate, .. } = edit(&current, &expected, b"b").unwrap()
    else {
        panic!("conflict expected")
    };
    candidate.content.push('c');
    assert_eq!(candidate.canonical_bytes(), Err(Error::HashMismatch));
}
