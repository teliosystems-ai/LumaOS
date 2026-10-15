use super::*;
use serde_json::{json, Value as Json};

fn n(value: &str) -> Json {
    json!({"kind":"number","value":value})
}
fn literal(value: &str) -> Json {
    json!({"op":"number","value":value})
}
fn reference(row: usize, column: usize) -> Json {
    json!({"op":"cell","row":row,"column":column})
}
fn formula(expression: Json) -> Json {
    json!({"kind":"formula","expression":expression})
}
fn binary(operator: &str, left: Json, right: Json) -> Json {
    json!({"op":"binary","operator":operator,"left":left,"right":right})
}
fn aggregate(function: &str, sr: usize, sc: usize, er: usize, ec: usize) -> Json {
    json!({"op":"aggregate","function":function,"start_row":sr,"start_column":sc,
        "end_row":er,"end_column":ec})
}
fn run(rows: Vec<Vec<Json>>) -> Result<Calculation> {
    calculate(&serde_json::to_vec(&json!({"schema_version":1,"rows":rows})).unwrap())
}

#[test]
fn exact_decimal_arithmetic_uses_no_binary_float_or_implicit_rounding() {
    let c = run(vec![vec![
        n("0.1"),
        n("0.2"),
        formula(binary("add", reference(0, 0), reference(0, 1))),
        formula(binary("multiply", literal("0.1"), literal("0.2"))),
        formula(binary("divide", literal("1"), literal("8"))),
        formula(binary("subtract", literal("-2"), literal("-0.5"))),
    ]])
    .unwrap();
    assert_eq!(c.canonical_csv, "0.1,0.2,0.3,0.02,0.125,-1.5\n");
    assert_eq!(
        c.values[0][2],
        Value::Number {
            value: "0.3".into()
        }
    );
    for expression in [
        binary("divide", literal("1"), literal("3")),
        binary("multiply", literal("0.000001"), literal("0.1")),
    ] {
        assert_eq!(
            run(vec![vec![formula(expression)]]).unwrap_err(),
            Error::Precision
        );
    }
    assert_eq!(
        run(vec![vec![formula(binary(
            "divide",
            literal("1"),
            literal("0")
        ))]])
        .unwrap_err(),
        Error::Arithmetic
    );
}

#[test]
fn sources_and_csv_reopen_and_recalculate_byte_identically() {
    let c = run(vec![vec![
        n("1.500000"),
        formula(json!({"op":"negate","value":reference(0,0)})),
    ]])
    .unwrap();
    let reopened = calculate(c.canonical_source.as_bytes()).unwrap();
    assert_eq!(c.canonical_source, reopened.canonical_source);
    assert_eq!(c.canonical_csv, reopened.canonical_csv);
    assert_eq!(c.values, reopened.values);
    assert_eq!(c.source_sha256, sha256(c.canonical_source.as_bytes()));
    assert_eq!(c.csv_sha256, sha256(c.canonical_csv.as_bytes()));
    assert_eq!(c.evaluation_steps, reopened.evaluation_steps);
    let binding = crate::OwnerBinding {
        installation: "a".repeat(64),
        owner: "b".repeat(64),
        owner_generation: 1,
    };
    for (format, source) in [
        (Format::Json, c.canonical_source.as_bytes()),
        (Format::Csv, c.canonical_csv.as_bytes()),
    ] {
        let version = crate::capture(
            binding.clone(),
            "sheet-one",
            format,
            source,
            crate::Provenance {
                request_id: "reopen-one".into(),
                workflow_sha256: "c".repeat(64),
                source_sha256: sha256(source),
                origin: crate::EditOrigin::Managed,
            },
        )
        .unwrap();
        assert_eq!(
            crate::reopen(&version.canonical_envelope().unwrap(), &binding).unwrap(),
            version
        );
    }
}

#[test]
fn forward_references_and_shared_dependencies_are_deterministic() {
    let c = run(vec![
        vec![
            formula(binary("add", reference(0, 1), reference(1, 0))),
            n("2"),
        ],
        vec![
            formula(binary("multiply", reference(0, 1), literal("3"))),
            n("0"),
        ],
    ])
    .unwrap();
    assert_eq!(c.canonical_csv, "8,2\n6,0\n");
}

#[test]
fn sum_minimum_maximum_average_and_blank_semantics_are_explicit() {
    for (function, expected) in [
        ("sum", "6"),
        ("minimum", "-2"),
        ("maximum", "6"),
        ("average", "2"),
    ] {
        let c = run(vec![vec![
            n("-2"),
            n("2"),
            n("6"),
            json!({"kind":"blank"}),
            formula(aggregate(function, 0, 0, 0, 3)),
        ]])
        .unwrap();
        assert_eq!(
            c.values[0][4],
            Value::Number {
                value: expected.into()
            }
        );
    }
    assert_eq!(
        run(vec![vec![
            json!({"kind":"blank"}),
            formula(reference(0, 0))
        ]])
        .unwrap()
        .canonical_csv,
        ",0\n"
    );
    for function in ["minimum", "maximum", "average"] {
        assert_eq!(
            run(vec![vec![
                json!({"kind":"blank"}),
                formula(aggregate(function, 0, 0, 0, 0))
            ]])
            .unwrap_err(),
            Error::NonNumeric
        );
    }
    assert_eq!(
        run(vec![vec![
            json!({"kind":"blank"}),
            formula(aggregate("sum", 0, 0, 0, 0))
        ]])
        .unwrap()
        .canonical_csv,
        ",0\n"
    );
    assert_eq!(
        run(vec![vec![
            n("1"),
            n("1"),
            n("2"),
            formula(aggregate("average", 0, 0, 0, 2))
        ]])
        .unwrap_err(),
        Error::Precision
    );
}

#[test]
fn cycles_are_refused_without_partial_values_or_source_mutation() {
    assert_eq!(
        run(vec![vec![formula(reference(0, 0))]]).unwrap_err(),
        Error::Cycle
    );
    assert_eq!(
        run(vec![vec![
            formula(reference(0, 1)),
            formula(reference(0, 0))
        ]])
        .unwrap_err(),
        Error::Cycle
    );
    assert_eq!(
        run(vec![vec![formula(aggregate("sum", 0, 0, 0, 0))]]).unwrap_err(),
        Error::Cycle
    );
}

#[test]
fn unsupported_operations_duplicate_keys_and_unknown_fields_are_refused() {
    for source in [
        r#"{"schema_version":1,"schema_version":1,"rows":[[{"kind":"blank"}]]}"#,
        r#"{"schema_version":1,"rows":[[{"kind":"number","value":"1","value":"2"}]]}"#,
        r#"{"schema_version":1,"rows":[[{"kind":"formula","expression":{"op":"shell","command":"id"}}]]}"#,
        r#"{"schema_version":1,"network":true,"rows":[[{"kind":"blank"}]]}"#,
        r#"{"schema_version":1,"rows":[[{"kind":"blank","value":"x"}]]}"#,
    ] {
        assert_eq!(calculate(source.as_bytes()).unwrap_err(), Error::Source);
    }
    for expression in [
        json!({"op":"binary","operator":"power","left":literal("1"),"right":literal("2")}),
        json!({"op":"cell","row":0,"column":0,"file":"secret"}),
    ] {
        assert_eq!(
            run(vec![vec![formula(expression)]]).unwrap_err(),
            Error::Source
        );
    }
}

#[test]
fn literal_text_stays_inert_and_csv_escaping_is_canonical() {
    let c = run(vec![vec![
        json!({"kind":"text","value":"=SUM(A1)"}),
        json!({"kind":"text","value":"a,\"b\"\r\nline"}),
        json!({"kind":"blank"}),
    ]])
    .unwrap();
    assert_eq!(c.canonical_csv, "=SUM(A1),\"a,\"\"b\"\"\nline\",\n");
    for expression in [reference(0, 0), aggregate("sum", 0, 0, 0, 0)] {
        assert_eq!(
            run(vec![vec![
                json!({"kind":"text","value":"1"}),
                formula(expression)
            ]])
            .unwrap_err(),
            Error::NonNumeric
        );
    }
    for value in ["\0", "\u{feff}x", "lone\rcarriage"] {
        assert_eq!(
            run(vec![vec![json!({"kind":"text","value":value})]]).unwrap_err(),
            Error::Source
        );
    }
}

#[test]
fn numeric_grammar_precision_magnitude_and_overflow_are_bounded() {
    for value in [
        "",
        "+1",
        " 1",
        "01",
        ".1",
        "1.",
        "1e2",
        "NaN",
        "inf",
        "0.0000001",
        "--1",
        "-",
        "١",
    ] {
        assert!(run(vec![vec![n(value)]]).is_err(), "accepted {value:?}");
    }
    assert_eq!(
        run(vec![vec![n("-0.000000"), n("1000000000000000000000000")]])
            .unwrap()
            .canonical_csv,
        "0,1000000000000000000000000\n"
    );
    assert!(run(vec![vec![n("1000000000000000000000001")]]).is_err());
    let max = "1000000000000000000000000";
    for op in ["add", "multiply"] {
        assert!(run(vec![vec![formula(binary(op, literal(max), literal(max)))]]).is_err());
    }
    // Min/max do not add their operands and must not fail due to unused sum overflow.
    assert!(run(vec![vec![
        n(max),
        n(max),
        formula(aggregate("maximum", 0, 0, 0, 1))
    ]])
    .is_ok());
    let averaged = run(vec![vec![
        n(max),
        n(max),
        formula(aggregate("average", 0, 0, 0, 1)),
    ]])
    .unwrap();
    assert_eq!(averaged.values[0][2], Value::Number { value: max.into() });
    let cancelled = run(vec![vec![
        n(max),
        n(max),
        n(&format!("-{max}")),
        formula(aggregate("sum", 0, 0, 0, 2)),
    ]])
    .unwrap();
    assert_eq!(cancelled.values[0][3], Value::Number { value: max.into() });
    let negative = run(vec![vec![
        n(&format!("-{max}")),
        n(&format!("-{max}")),
        formula(aggregate("average", 0, 0, 0, 1)),
    ]])
    .unwrap();
    assert_eq!(
        negative.values[0][2],
        Value::Number {
            value: format!("-{max}")
        }
    );
    assert_eq!(
        run(vec![vec![
            n(max),
            n(max),
            formula(aggregate("sum", 0, 0, 0, 1))
        ]])
        .unwrap_err(),
        Error::Arithmetic
    );
}

#[test]
fn shapes_positions_and_invalid_ranges_are_checked_before_evaluation() {
    for rows in [
        vec![],
        vec![vec![]],
        vec![vec![n("1")], vec![]],
        vec![vec![n("1"); MAX_COLUMNS + 1]],
        vec![vec![n("1")]; MAX_ROWS + 1],
    ] {
        assert_eq!(run(rows).unwrap_err(), Error::Bounds);
    }
    for expression in [
        reference(1, 0),
        reference(0, 1),
        aggregate("sum", 0, 0, 0, 1),
    ] {
        assert_eq!(
            run(vec![vec![formula(expression)]]).unwrap_err(),
            Error::Reference
        );
    }
    assert_eq!(
        run(vec![
            vec![formula(aggregate("sum", 1, 0, 0, 0))],
            vec![n("2")]
        ])
        .unwrap_err(),
        Error::Reference
    );
}

#[test]
fn maximum_dimensions_empty_cells_and_field_bounds_are_supported() {
    let c = run(vec![vec![json!({"kind":"blank"}); MAX_COLUMNS]; MAX_ROWS]).unwrap();
    assert_eq!(c.values.len(), MAX_ROWS);
    assert_eq!(c.values[0].len(), MAX_COLUMNS);
    assert!(run(vec![vec![
        json!({"kind":"text","value":"x".repeat(MAX_CSV_FIELD_BYTES)})
    ]])
    .is_ok());
    assert_eq!(
        run(vec![vec![
            json!({"kind":"text","value":"x".repeat(MAX_CSV_FIELD_BYTES+1)})
        ]])
        .unwrap_err(),
        Error::Bounds
    );
    assert!(run(vec![vec![json!({"kind":"blank"})]]).is_ok());
}

#[test]
fn excessive_reference_depth_and_repeated_range_work_are_refused() {
    let rows: Vec<Vec<Json>> = (0..MAX_ROWS)
        .map(|row| {
            (0..2)
                .map(|column| {
                    let index = row * 2 + column;
                    if index + 1 == MAX_ROWS * 2 {
                        n("1")
                    } else {
                        formula(reference((index + 1) / 2, (index + 1) % 2))
                    }
                })
                .collect()
        })
        .collect();
    assert_eq!(run(rows).unwrap_err(), Error::Bounds);
    let mut rows = vec![vec![n("1"); MAX_COLUMNS]; MAX_ROWS];
    for row in &mut rows {
        row[MAX_COLUMNS - 1] = formula(aggregate("sum", 0, 0, MAX_ROWS - 1, MAX_COLUMNS - 2));
    }
    assert_eq!(run(rows).unwrap_err(), Error::Bounds);
}

#[test]
fn source_size_schema_and_expression_depth_have_closed_limits() {
    assert_eq!(calculate(&[]).unwrap_err(), Error::Bounds);
    assert_eq!(
        calculate(&vec![b' '; MAX_CONTENT_BYTES + 1]).unwrap_err(),
        Error::Bounds
    );
    assert!(calculate(b"{\"schema_version\":2,\"rows\":[[{\"kind\":\"blank\"}]]}").is_err());
    let mut expression = literal("1");
    for _ in 0..MAX_EXPRESSION_DEPTH + 1 {
        expression = json!({"op":"negate","value":expression});
    }
    assert_eq!(
        run(vec![vec![formula(expression)]]).unwrap_err(),
        Error::Bounds
    );
}
