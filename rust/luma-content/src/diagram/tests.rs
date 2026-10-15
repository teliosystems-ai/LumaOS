use super::*;
use serde_json::{json, Value};

fn source() -> Value {
    json!({"schema_version":1,"title":"Flow <safe>","width":400,"height":240,
        "nodes":[{"id":"a","x":10,"y":20,"width":81,"height":41,
            "shape":"rectangle","fill":"blue","label":"Start\nnext"},
            {"id":"b","x":210,"y":120,"width":81,"height":41,
            "shape":"ellipse","fill":"green","label":"End"}],
        "edges":[{"id":"edge-one","from":"a","from_port":"east","to":"b",
            "to_port":"west","arrow":"both","label":"<step>"}]})
}
fn run(value: &Value) -> Result<Rendered> {
    render(&serde_json::to_vec(value).unwrap())
}

#[test]
fn exact_source_and_svg_reopen_and_edit_without_external_layout() {
    let result = run(&source()).unwrap();
    let reopened = render(result.canonical_source.as_bytes()).unwrap();
    assert_eq!(
        serde_json::to_vec(&result).unwrap(),
        serde_json::to_vec(&reopened).unwrap()
    );
    assert_eq!(
        sha256(result.canonical_source.as_bytes()),
        result.source_sha256
    );
    assert_eq!(sha256(result.canonical_svg.as_bytes()), result.svg_sha256);
    assert!(result
        .canonical_svg
        .contains("cx=\"250.5\" cy=\"140.5\" rx=\"40.5\" ry=\"20.5\""));
    assert!(result
        .canonical_svg
        .contains("x1=\"91\" y1=\"40.5\" x2=\"210\" y2=\"140.5\""));
    let mut edited = source();
    edited["nodes"][0]["label"] = json!("Changed");
    assert_ne!(run(&edited).unwrap().svg_sha256, result.svg_sha256);
}

#[test]
fn all_text_is_escaped_and_internal_references_are_fixed() {
    let attack = "<script onload='x'>&\"é";
    let mut value = source();
    value["title"] = json!(attack);
    value["nodes"][0]["label"] = json!(attack);
    value["edges"][0]["label"] = json!(attack);
    let svg = run(&value).unwrap().canonical_svg;
    assert!(!svg.contains("<script"));
    assert_eq!(svg.matches("&lt;script").count(), 3);
    assert!(svg.contains("&apos;x&apos;"));
    assert!(svg.contains("role=\"img\" aria-labelledby=\"luma-title\""));
    assert!(svg.contains("marker-start=\"url(#luma-start)\""));
}

#[test]
fn forbidden_xml_characters_are_refused_in_every_label_and_json_escape_spelling() {
    for forbidden in ['\u{fffe}', '\u{ffff}'] {
        for location in 0..3 {
            let mut value = source();
            match location {
                0 => value["title"] = json!(forbidden.to_string()),
                1 => value["nodes"][0]["label"] = json!(forbidden.to_string()),
                _ => value["edges"][0]["label"] = json!(forbidden.to_string()),
            }
            assert!(matches!(run(&value), Err(Error::Text)));
            let spelling = serde_json::to_string(&value)
                .unwrap()
                .replace(forbidden, &format!("\\u{:04x}", forbidden as u32));
            assert!(matches!(render(spelling.as_bytes()), Err(Error::Text)));
        }
    }
}

#[test]
fn zero_nodes_is_a_blank_canvas_and_delete_all_is_reopenable() {
    let mut value = source();
    value["nodes"] = json!([]);
    value["edges"] = json!([]);
    let result = run(&value).unwrap();
    assert!(!result.canonical_svg.contains("data-node-id"));
    assert_eq!(
        render(result.canonical_source.as_bytes())
            .unwrap()
            .svg_sha256,
        result.svg_sha256
    );
}

#[test]
fn identifier_duplicates_and_edge_retargeting_are_refused() {
    for id in ["", "A", "a\" onload=\"x", "é", &"a".repeat(65)] {
        let mut value = source();
        value["nodes"][0]["id"] = json!(id);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    value["nodes"][1]["id"] = json!("a");
    assert!(matches!(run(&value), Err(Error::Identifier)));
    for target in ["missing", "a"] {
        let mut value = source();
        value["edges"][0]["to"] = json!(target);
        assert!(matches!(run(&value), Err(Error::Reference)));
    }
    let mut value = source();
    let edge = value["edges"][0].clone();
    value["edges"].as_array_mut().unwrap().push(edge);
    assert!(matches!(run(&value), Err(Error::Identifier)));
}

#[test]
fn canvas_node_geometry_overflow_overlap_and_minimum_sizes_are_refused() {
    for (field, number) in [
        ("x", u32::MAX),
        ("y", u32::MAX),
        ("width", 31),
        ("height", 23),
    ] {
        let mut value = source();
        value["nodes"][0][field] = json!(number);
        assert!(matches!(run(&value), Err(Error::Geometry)));
    }
    let mut value = source();
    value["nodes"][1]["x"] = json!(20);
    value["nodes"][1]["y"] = json!(30);
    assert!(matches!(run(&value), Err(Error::Geometry)));
    for size in [0, 8193] {
        let mut value = source();
        value["width"] = json!(size);
        assert!(run(&value).is_err());
    }
    // Shared boundaries are allowed, overlapping area is not.
    value["nodes"][1]["x"] = json!(91);
    value["nodes"][1]["y"] = json!(20);
    assert!(run(&value).is_ok());
}

#[test]
fn unknown_fields_duplicates_external_styles_and_shapes_are_refused() {
    assert!(render(br#"{"schema_version":1,"schema_version":1}"#).is_err());
    for (field, entry) in [
        ("href", json!("https://example.invalid")),
        ("schema_version", json!(2)),
    ] {
        let mut value = source();
        value[field] = entry;
        assert!(run(&value).is_err());
    }
    for (field, entry) in [
        ("fill", json!("url(https://example.invalid)")),
        ("shape", json!("script")),
        ("onclick", json!("x")),
    ] {
        let mut value = source();
        value["nodes"][0][field] = entry;
        assert!(run(&value).is_err());
    }
}

#[test]
fn label_limits_multiline_nodes_and_control_refusals_are_explicit() {
    for text in [
        "x".repeat(MAX_LABEL_BYTES + 1),
        "x\n".repeat(8),
        "x\ry".into(),
        "x\u{007f}y".into(),
    ] {
        let mut value = source();
        value["nodes"][0]["label"] = json!(text);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    value["edges"][0]["label"] = json!("two\nlines");
    assert!(matches!(run(&value), Err(Error::Text)));
    value["edges"][0]["label"] = json!("");
    value["nodes"][0]["shape"] = json!("rounded-rectangle");
    assert!(run(&value).unwrap().canonical_svg.contains("rx=\"8\""));
}

#[test]
fn ports_and_arrow_variants_are_closed_and_deterministic() {
    for port_name in ["north", "east", "south", "west"] {
        for arrow in ["none", "end", "both"] {
            let mut value = source();
            value["edges"][0]["from_port"] = json!(port_name);
            value["edges"][0]["arrow"] = json!(arrow);
            assert!(run(&value).is_ok());
        }
    }
    let mut value = source();
    value["edges"][0]["from_port"] = json!("auto");
    assert!(run(&value).is_err());
}

#[test]
fn node_edge_and_input_limits_refuse_before_unbounded_work() {
    let mut value = source();
    value["nodes"] = json!(vec![value["nodes"][0].clone(); MAX_NODES + 1]);
    assert!(matches!(run(&value), Err(Error::Bounds)));
    let mut value = source();
    value["edges"] = json!(vec![value["edges"][0].clone(); MAX_EDGES + 1]);
    assert!(matches!(run(&value), Err(Error::Bounds)));
    let mut bytes = serde_json::to_vec(&source()).unwrap();
    bytes.extend(vec![b' '; MAX_CONTENT_BYTES]);
    assert!(render(&bytes).is_err());
    assert_eq!(half(-1), "-0.5");
}
