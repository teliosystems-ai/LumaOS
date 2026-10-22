use super::*;
use crate::{capture, Provenance};

fn source() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"rows":[[
        {"kind":"number","value":"2"},{"kind":"number","value":"3"},
        {"kind":"formula","expression":{"op":"binary","operator":"add",
            "left":{"op":"cell","row":0,"column":0},"right":{"op":"cell","row":0,"column":1}}}
    ]]})
}
fn artifact() -> ArtifactVersion {
    let body =
        encode(&serde_json::json!({"schema_version":1,"engine":"spreadsheet","source":source()}))
            .unwrap();
    capture(
        OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 7,
        },
        "sheet.one",
        Format::Json,
        &body,
        Provenance {
            request_id: "sheet.capture".into(),
            workflow_sha256: "c".repeat(64),
            source_sha256: crate::sha256(&body),
            origin: crate::EditOrigin::External,
        },
    )
    .unwrap()
}
#[test]
fn actual_export_reopen_preserves_formulas_source_origin_and_exact_numeric_oracle() {
    let origin = artifact();
    let exported = Workbook::from_artifact(&origin)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let reopened = Workbook::reopen_data(&exported).unwrap();
    assert_eq!(
        reopened.origin_reference_data().unwrap(),
        origin.reference().unwrap()
    );
    assert_eq!(
        reopened.origin_binding_data().unwrap(),
        origin.receipt().binding
    );
    assert!(!reopened.source_changed().unwrap());
    let actual = reopened.recalculate_data().unwrap();
    assert_eq!(actual.canonical_csv, "2,3,5\n");
    assert_eq!(
        actual.values[0][2],
        spreadsheet::Value::Number { value: "5".into() }
    );
    assert!(actual.canonical_source.contains("\"formula\""));
    assert_eq!(reopened.managed_source_data().unwrap(), origin.content());
    assert_eq!(reopened.canonical_bytes().unwrap(), exported);
}
#[test]
fn editable_source_recalculates_without_relabeling_original_as_a_new_commit() {
    let original = Workbook::from_artifact(&artifact()).unwrap();
    let reference = original.origin_reference_data().unwrap();
    let mut edited = source();
    edited["rows"][0][0]["value"] = "11".into();
    let changed = original.edit_data(&encode(&edited).unwrap()).unwrap();
    let reopened = Workbook::reopen_data(&changed.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        reopened.recalculate_data().unwrap().canonical_csv,
        "11,3,14\n"
    );
    assert!(reopened.source_changed().unwrap());
    assert_eq!(reopened.origin_reference_data().unwrap(), reference);
    assert_eq!(
        original.recalculate_data().unwrap().canonical_csv,
        "2,3,5\n"
    );
    assert_eq!(reference.version, 1);
}
#[test]
fn stale_or_fabricated_cached_results_source_and_origin_mutation_refuse() {
    let bytes = Workbook::from_artifact(&artifact())
        .unwrap()
        .canonical_bytes()
        .unwrap();
    for field in 0..9 {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match field {
            0 => value["values"][0][2]["value"] = "999".into(),
            1 => value["source_sha256"] = "d".repeat(64).into(),
            2 => value["canonical_csv"] = "wrong\n".into(),
            3 => value["csv_sha256"] = "d".repeat(64).into(),
            4 => value["evaluation_steps"] = 0.into(),
            5 => value["origin"]["receipt"]["binding"]["owner_generation"] = 8.into(),
            6 => value["origin_envelope_sha256"] = "d".repeat(64).into(),
            7 => value["source_changed"] = true.into(),
            _ => value["profile"] = "xlsx-compatible".into(),
        }
        assert!(
            Workbook::reopen_data(&encode(&value).unwrap()).is_err(),
            "field{field}"
        );
    }
}
#[test]
fn unit_alias_extra_fields_duplicate_keys_and_noncanonical_transport_refuse() {
    let bytes = Workbook::from_artifact(&artifact())
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["path"] = "/arbitrary/export.xlsx".into();
    assert!(Workbook::reopen_data(&encode(&value).unwrap()).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(Workbook::reopen_data(format!("{text} ").as_bytes()).is_err());
    assert!(Workbook::reopen_data(
        text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1
        )
        .as_bytes()
    )
    .is_err());
    let mut source = source();
    source["rows"][0][0] = serde_json::json!({"kind":"blank","value":"ignored"});
    assert!(Workbook::from_artifact(&artifact())
        .unwrap()
        .edit_data(&encode(&source).unwrap())
        .is_err());
}
#[test]
fn foreign_formats_cycles_arithmetic_errors_and_bounds_never_become_workbooks() {
    let artifact = artifact();
    let text = capture(
        artifact.receipt().binding.clone(),
        "not.sheet",
        Format::Utf8Text,
        artifact.content(),
        Provenance {
            request_id: "not.sheet".into(),
            workflow_sha256: "c".repeat(64),
            source_sha256: crate::sha256(artifact.content()),
            origin: crate::EditOrigin::External,
        },
    )
    .unwrap();
    assert!(Workbook::from_artifact(&text).is_err());
    let original = Workbook::from_artifact(&artifact).unwrap();
    let mut cyclic = source();
    cyclic["rows"][0][2]["expression"] = serde_json::json!({"op":"cell","row":0,"column":2});
    assert!(original.edit_data(&encode(&cyclic).unwrap()).is_err());
    let mut zero = source();
    zero["rows"][0][2]["expression"] = serde_json::json!({"op":"binary","operator":"divide",
        "left":{"op":"number","value":"1"},"right":{"op":"number","value":"0"}});
    assert!(original.edit_data(&encode(&zero).unwrap()).is_err());
    assert!(Workbook::reopen_data(&[]).is_err());
    assert!(Workbook::reopen_data(&vec![b' '; MAX_WORKBOOK_BYTES + 1]).is_err());
}
