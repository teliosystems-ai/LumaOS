use super::*;
use crate::{capture, reopen};

fn owner() -> OwnerBinding {
    OwnerBinding {
        installation: "1".repeat(64),
        owner: "2".repeat(64),
        owner_generation: 3,
    }
}

fn table(bytes: &[u8]) -> ArtifactVersion {
    capture(
        owner(),
        "table-1",
        Format::Csv,
        bytes,
        Provenance {
            request_id: "initial".into(),
            workflow_sha256: "3".repeat(64),
            source_sha256: sha256(bytes),
            origin: EditOrigin::Managed,
        },
    )
    .unwrap()
}

fn request(current: &ArtifactVersion, operations: Vec<Operation>) -> TableEditRequest {
    TableEditRequest {
        binding: owner(),
        expected: current.reference().unwrap(),
        metadata: EditMetadata {
            request_id: "edit-1".into(),
            workflow_sha256: "4".repeat(64),
        },
        operations,
    }
}

fn set(row: u32, column: u32, value: &str) -> Operation {
    Operation::SetCell {
        row,
        column,
        value: value.into(),
    }
}

fn changed(current: &ArtifactVersion, operations: Vec<Operation>) -> ArtifactVersion {
    match apply(current, &request(current, operations)).unwrap() {
        Decision::NewVersion { version, .. } => version,
        _ => panic!("new version expected"),
    }
}

#[test]
fn typed_cell_edits_preserve_stable_identity_and_all_provenance() {
    let current = table(b"name,total\nAlice,12\n");
    let request = request(&current, vec![set(1, 1, "13")]);
    let Decision::NewVersion {
        version,
        edit_sha256,
    } = apply(&current, &request).unwrap()
    else {
        panic!("new version expected")
    };
    assert_eq!(version.content(), b"name,total\nAlice,13\n");
    assert_eq!(current.content(), b"name,total\nAlice,12\n");
    let receipt = version.receipt();
    assert_eq!(receipt.artifact_id, "table-1");
    assert_eq!(receipt.version, 2);
    assert_eq!(
        receipt.previous.as_ref(),
        Some(&current.reference().unwrap())
    );
    assert_eq!(receipt.binding, owner());
    assert_eq!(receipt.provenance.request_id, "edit-1");
    assert_eq!(receipt.provenance.workflow_sha256, "4".repeat(64));
    assert_eq!(receipt.provenance.source_sha256, sha256(version.content()));
    assert_eq!(receipt.provenance.origin, EditOrigin::Managed);
    assert_eq!(receipt.original_bytes, version.content().len() as u64);
    assert_eq!(receipt.content_bytes, receipt.original_bytes);
    assert_eq!(edit_sha256, sha256(&request.canonical_bytes().unwrap()));
    assert_eq!(
        reopen(&version.canonical_envelope().unwrap(), &owner()).unwrap(),
        version
    );
}

#[test]
fn row_and_column_operations_are_zero_based_and_sequential() {
    let current = table(b"a,b\nc,d\n");
    let version = changed(
        &current,
        vec![
            Operation::InsertRow {
                index: 0,
                values: vec!["first".into(), "row".into()],
            },
            Operation::InsertColumn {
                index: 1,
                values: vec!["X".into(), "Y".into(), "Z".into()],
            },
            set(1, 0, "updated"),
            Operation::DeleteRow { index: 2 },
            Operation::DeleteColumn { index: 2 },
        ],
    );
    assert_eq!(version.content(), b"first,X\nupdated,Y\n");
    assert_eq!(
        version.receipt().version,
        2,
        "one batch creates one proposed version"
    );
}

#[test]
fn row_and_column_insertions_accept_exact_append_positions() {
    let current = table(b"a\n");
    let version = changed(
        &current,
        vec![
            Operation::InsertRow {
                index: 1,
                values: vec!["b".into()],
            },
            Operation::InsertColumn {
                index: 1,
                values: vec!["x".into(), "y".into()],
            },
        ],
    );
    assert_eq!(version.content(), b"a,x\nb,y\n");
}

#[test]
fn cells_are_inert_strings_without_formula_execution_type_coercion_or_header_detection() {
    let current = table(b"a,b,c,d\n");
    let version = changed(
        &current,
        vec![
            set(0, 0, "=1+1"),
            set(0, 1, "001"),
            set(0, 2, "@SUM(A1)"),
            set(0, 3, "-2e4"),
        ],
    );
    assert_eq!(version.content(), b"=1+1,001,@SUM(A1),-2e4\n");
}

#[test]
fn unicode_multiline_quotes_commas_and_empty_cells_roundtrip() {
    let current = table(b"a,b\nc,d\n");
    let version = changed(
        &current,
        vec![
            set(0, 0, "Résumé, 東京"),
            set(0, 1, "he said \"yes\"\nnext"),
            set(1, 0, ""),
            set(1, 1, "\t"),
        ],
    );
    assert_eq!(
        version.content(),
        "\"Résumé, 東京\",\"he said \"\"yes\"\"\nnext\"\n,\t\n".as_bytes()
    );
    assert_eq!(
        reopen(&version.canonical_envelope().unwrap(), &owner()).unwrap(),
        version
    );
}

#[test]
fn unchanged_cells_and_compensating_edits_are_noops_not_versions() {
    let current = table(b"a,b\n");
    for operations in [
        vec![set(0, 0, "a")],
        vec![set(0, 0, "temporary"), set(0, 0, "a")],
        vec![
            Operation::InsertRow {
                index: 0,
                values: vec!["x".into(), "y".into()],
            },
            Operation::DeleteRow { index: 0 },
        ],
        vec![
            Operation::InsertColumn {
                index: 0,
                values: vec!["x".into()],
            },
            Operation::DeleteColumn { index: 0 },
        ],
    ] {
        let request = request(&current, operations);
        assert_eq!(
            apply(&current, &request).unwrap(),
            Decision::NoChange {
                current: current.reference().unwrap(),
                edit_sha256: sha256(&request.canonical_bytes().unwrap())
            }
        );
    }
}

#[test]
fn invalid_later_operation_never_partially_mutates_current() {
    let current = table(b"a,b\nc,d\n");
    let original = current.canonical_envelope().unwrap();
    let request = request(
        &current,
        vec![set(0, 0, "changed"), Operation::DeleteRow { index: 99 }],
    );
    assert_eq!(apply(&current, &request), Err(Error::InvalidEdit));
    assert_eq!(current.canonical_envelope().unwrap(), original);
}

#[test]
fn positions_are_never_wrapped_or_silently_clamped() {
    let current = table(b"a,b\nc,d\n");
    for operation in [
        set(2, 0, "x"),
        set(0, 2, "x"),
        set(u32::MAX, 0, "x"),
        Operation::DeleteRow { index: 2 },
        Operation::DeleteColumn { index: u32::MAX },
        Operation::InsertRow {
            index: 3,
            values: vec!["x".into(), "y".into()],
        },
        Operation::InsertColumn {
            index: 3,
            values: vec!["x".into(), "y".into()],
        },
    ] {
        assert_eq!(
            apply(&current, &request(&current, vec![operation])),
            Err(Error::InvalidEdit)
        );
    }
}

#[test]
fn insert_shapes_must_match_exact_current_dimensions() {
    let current = table(b"a,b\nc,d\n");
    for operation in [
        Operation::InsertRow {
            index: 0,
            values: vec![],
        },
        Operation::InsertRow {
            index: 0,
            values: vec!["x".into()],
        },
        Operation::InsertRow {
            index: 0,
            values: vec!["x".into(); 3],
        },
        Operation::InsertColumn {
            index: 0,
            values: vec![],
        },
        Operation::InsertColumn {
            index: 0,
            values: vec!["x".into()],
        },
        Operation::InsertColumn {
            index: 0,
            values: vec!["x".into(); 3],
        },
    ] {
        assert_eq!(
            apply(&current, &request(&current, vec![operation])),
            Err(Error::InvalidEdit)
        );
    }
}

#[test]
fn deletion_cannot_create_zero_rows_or_zero_columns_even_temporarily() {
    let current = table(b"a\n");
    for operation in [
        Operation::DeleteRow { index: 0 },
        Operation::DeleteColumn { index: 0 },
    ] {
        assert_eq!(
            apply(&current, &request(&current, vec![operation])),
            Err(Error::InvalidEdit)
        );
    }
    let current = table(b"a,b\nc,d\n");
    assert_eq!(
        apply(
            &current,
            &request(
                &current,
                vec![
                    Operation::DeleteRow { index: 0 },
                    Operation::DeleteRow { index: 0 }
                ]
            )
        ),
        Err(Error::InvalidEdit)
    );
    assert_eq!(
        apply(
            &current,
            &request(
                &current,
                vec![
                    Operation::DeleteColumn { index: 0 },
                    Operation::DeleteColumn { index: 0 }
                ]
            )
        ),
        Err(Error::InvalidEdit)
    );
}

#[test]
fn stale_base_conflicts_before_valid_positions_are_interpreted() {
    let base = table(b"a,b\nc,d\n");
    let current = changed(&base, vec![Operation::DeleteRow { index: 1 }]);
    let stale = request(&base, vec![set(1, 0, "preserve editor intent")]);
    let Decision::Conflict {
        expected,
        current: reference,
        edit_sha256,
    } = apply(&current, &stale).unwrap()
    else {
        panic!("stale save must conflict")
    };
    assert_eq!(expected, base.reference().unwrap());
    assert_eq!(reference, current.reference().unwrap());
    assert_eq!(edit_sha256, sha256(&stale.canonical_bytes().unwrap()));
    assert_eq!(current.content(), b"a,b\n");
}

#[test]
fn structurally_invalid_stale_requests_still_refuse() {
    let current = table(b"a,b\n");
    let mut stale = request(&current, vec![set(0, 0, "\0")]);
    stale.expected.version = 2;
    assert_eq!(apply(&current, &stale), Err(Error::InvalidText));
    stale.operations = vec![set(u32::MAX, 0, "x")];
    assert_eq!(apply(&current, &stale), Err(Error::InvalidEdit));
}

#[test]
fn every_exact_reference_field_participates_in_conflict_comparison() {
    let current = table(b"a,b\n");
    for change in 0..3 {
        let mut stale = request(&current, vec![set(0, 0, "a")]);
        match change {
            0 => stale.expected.version += 1,
            1 => stale.expected.content_sha256 = "9".repeat(64),
            _ => stale.expected.receipt_sha256 = "8".repeat(64),
        }
        assert!(matches!(
            apply(&current, &stale),
            Ok(Decision::Conflict { .. })
        ));
    }
}

#[test]
fn cross_owner_generation_installation_or_artifact_never_retargets() {
    let current = table(b"a,b\n");
    for change in 0..4 {
        let mut request = request(&current, vec![set(0, 0, "x")]);
        match change {
            0 => request.binding.owner = "9".repeat(64),
            1 => request.binding.owner_generation += 1,
            2 => request.binding.installation = "8".repeat(64),
            _ => request.expected.artifact_id = "other".into(),
        }
        assert_eq!(
            apply(&current, &request),
            Err(if change == 3 {
                Error::InvalidIdentifier
            } else {
                Error::OwnerMismatch
            })
        );
    }
}

#[test]
fn request_schema_rejects_unknown_fields_operations_duplicates_and_fractional_positions() {
    let current = table(b"a,b\n");
    let value = serde_json::to_value(request(&current, vec![set(0, 0, "x")])).unwrap();
    for mutated in [
        {
            let mut v = value.clone();
            v["unexpected"] = true.into();
            v
        },
        {
            let mut v = value.clone();
            v["operations"][0]["unexpected"] = true.into();
            v
        },
        {
            let mut v = value.clone();
            v["operations"][0]["row"] = 0.5.into();
            v
        },
        {
            let mut v = value.clone();
            v["operations"][0]["op"] = "run-formula".into();
            v
        },
        {
            let mut v = value.clone();
            v["metadata"]["unexpected"] = true.into();
            v
        },
    ] {
        assert!(serde_json::from_value::<TableEditRequest>(mutated).is_err());
    }
    assert!(serde_json::from_str::<Operation>(
        r#"{"op":"set-cell","row":0,"row":1,"column":0,"value":"x"}"#
    )
    .is_err());
}

#[test]
fn empty_or_excess_operation_batches_refuse_without_mutation() {
    let current = table(b"a,b\n");
    for operations in [vec![], vec![set(0, 0, "a"); MAX_OPERATIONS + 1]] {
        assert_eq!(
            apply(&current, &request(&current, operations)),
            Err(Error::Bounds)
        );
    }
    assert!(matches!(
        apply(
            &current,
            &request(&current, vec![set(0, 0, "a"); MAX_OPERATIONS])
        ),
        Ok(Decision::NoChange { .. })
    ));
}

#[test]
fn new_cells_reject_oversize_nul_cr_and_controls_but_keep_lf_and_tab() {
    let current = table(b"a\n");
    for value in ["\0", "\r", "\r\n", "\x01", "\x1f"] {
        assert_eq!(
            apply(&current, &request(&current, vec![set(0, 0, value)])),
            Err(Error::InvalidText)
        );
    }
    assert_eq!(
        apply(
            &current,
            &request(
                &current,
                vec![set(0, 0, &"x".repeat(MAX_CSV_FIELD_BYTES + 1))]
            )
        ),
        Err(Error::Bounds)
    );
    let version = changed(&current, vec![set(0, 0, &"x".repeat(MAX_CSV_FIELD_BYTES))]);
    assert_eq!(version.content().len(), MAX_CSV_FIELD_BYTES + 1);
}

#[test]
fn row_and_column_caps_apply_to_intermediate_states() {
    let current = table("a\n".repeat(MAX_CSV_ROWS).as_bytes());
    assert_eq!(
        apply(
            &current,
            &request(
                &current,
                vec![
                    Operation::InsertRow {
                        index: 0,
                        values: vec!["x".into()]
                    },
                    Operation::DeleteRow { index: 0 }
                ]
            )
        ),
        Err(Error::Bounds)
    );
    let current = table(format!("{}\n", vec!["a"; MAX_CSV_COLUMNS].join(",")).as_bytes());
    assert_eq!(
        apply(
            &current,
            &request(
                &current,
                vec![
                    Operation::InsertColumn {
                        index: 0,
                        values: vec!["x".into()]
                    },
                    Operation::DeleteColumn { index: 0 }
                ]
            )
        ),
        Err(Error::Bounds)
    );
}

#[test]
fn canonical_byte_expansion_is_bounded_before_compensating_edits() {
    let current = table(vec!["x".repeat(4095); 256].join("\n").as_bytes());
    assert_eq!(current.content().len(), MAX_CONTENT_BYTES);
    let request = request(
        &current,
        vec![set(0, 0, &"x".repeat(4096)), set(0, 0, &"x".repeat(4095))],
    );
    assert_eq!(apply(&current, &request), Err(Error::Bounds));
}

#[test]
fn total_input_payload_and_cell_counts_are_bounded_independent_of_noop_result() {
    let current = table(b"a\n");
    let mut operations = vec![
        Operation::InsertColumn {
            index: 0,
            values: vec!["".into(); MAX_CSV_ROWS]
        };
        MAX_CSV_COLUMNS
    ];
    operations.push(set(0, 0, ""));
    assert_eq!(
        request(&current, operations).canonical_bytes(),
        Err(Error::Bounds)
    );
    let request = request(
        &current,
        vec![Operation::InsertColumn {
            index: 0,
            values: vec!["x".repeat(MAX_CSV_FIELD_BYTES); 257],
        }],
    );
    assert_eq!(request.canonical_bytes(), Err(Error::Bounds));
}

#[test]
fn malformed_provenance_owner_and_base_are_rejected() {
    let current = table(b"a\n");
    for change in 0..5 {
        let mut request = request(&current, vec![set(0, 0, "x")]);
        let expected = match change {
            0 => {
                request.metadata.request_id = "../bad".into();
                Error::InvalidProvenance
            }
            1 => {
                request.metadata.workflow_sha256 = "0".repeat(64);
                Error::InvalidProvenance
            }
            2 => {
                request.binding.owner_generation = 0;
                Error::InvalidBinding
            }
            3 => {
                request.expected.version = 0;
                Error::InvalidReceipt
            }
            _ => {
                request.expected.receipt_sha256 = "0".repeat(64);
                Error::InvalidReceipt
            }
        };
        assert_eq!(apply(&current, &request), Err(expected));
    }
}

#[test]
fn non_csv_artifacts_are_not_interpreted_as_tables() {
    for format in [Format::Utf8Text, Format::Json] {
        let source = if format == Format::Json {
            b"{}".as_slice()
        } else {
            b"a,b\n".as_slice()
        };
        let current = capture(
            owner(),
            "table-1",
            format,
            source,
            Provenance {
                request_id: "initial".into(),
                workflow_sha256: "3".repeat(64),
                source_sha256: sha256(source),
                origin: EditOrigin::Managed,
            },
        )
        .unwrap();
        assert_eq!(
            apply(&current, &request(&current, vec![set(0, 0, "x")])),
            Err(Error::InvalidEdit)
        );
    }
}

#[test]
fn exhausted_version_does_not_wrap_and_noop_remains_safe() {
    let mut current = table(b"a\n");
    current.receipt.version = u64::MAX;
    current.receipt.previous = Some(VersionReference {
        artifact_id: "table-1".into(),
        version: u64::MAX - 1,
        content_sha256: "5".repeat(64),
        receipt_sha256: "6".repeat(64),
    });
    assert_eq!(
        apply(&current, &request(&current, vec![set(0, 0, "b")])),
        Err(Error::VersionOverflow)
    );
    assert!(matches!(
        apply(&current, &request(&current, vec![set(0, 0, "a")])),
        Ok(Decision::NoChange { .. })
    ));
}

#[test]
fn canonical_request_hash_and_proposal_are_deterministic_and_order_sensitive() {
    let current = table(b"a,b\n");
    let request = request(&current, vec![set(0, 0, "x"), set(0, 1, "y")]);
    let encoded = request.canonical_bytes().unwrap();
    let decoded: TableEditRequest = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(
        apply(&current, &request).unwrap(),
        apply(&current, &decoded).unwrap()
    );
    let mut reversed = request.clone();
    reversed.operations.reverse();
    assert_ne!(
        sha256(&encoded),
        sha256(&reversed.canonical_bytes().unwrap())
    );
    assert_eq!(
        changed(&current, request.operations).content(),
        changed(&current, reversed.operations).content()
    );
}
