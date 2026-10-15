use super::*;
use serde_json::{json, Value};

fn source() -> Value {
    json!({"schema_version":1,"title":"Editable & safe","blocks":[
        {"kind":"heading","level":1,"text":"A < B"},
        {"kind":"paragraph","runs":[{"kind":"text","text":"Plain "},
            {"kind":"strong","text":"bold"},{"kind":"emphasis","text":"italic"},
            {"kind":"code","text":"<code>"},{"kind":"line-break"}]},
        {"kind":"list","ordered":true,"items":[[{"kind":"text","text":"first"}]]},
        {"kind":"table","header":["H"],"rows":[["value"]]},
        {"kind":"code","text":"print(\"x\")"},{"kind":"rule"}]})
}
fn run(value: &Value) -> Result<Rendered> {
    render(&serde_json::to_vec(value).unwrap())
}

#[test]
fn source_reopen_and_output_digests_are_exact_and_deterministic() {
    let rendered = run(&source()).unwrap();
    let reopened = render(rendered.canonical_source.as_bytes()).unwrap();
    assert_eq!(
        serde_json::to_vec(&rendered).unwrap(),
        serde_json::to_vec(&reopened).unwrap()
    );
    assert_eq!(
        sha256(rendered.canonical_source.as_bytes()),
        rendered.source_sha256
    );
    assert_eq!(
        sha256(rendered.canonical_html.as_bytes()),
        rendered.html_sha256
    );
    for expected in [
        "<h1>A &lt; B</h1>",
        "<strong>bold</strong>",
        "<em>italic</em>",
        "<code>&lt;code&gt;</code>",
        "<br>",
        "<ol>",
        "<th scope=\"col\">H</th>",
        "<td>value</td>",
        "<hr>",
        "Content-Security-Policy",
    ] {
        assert!(
            rendered.canonical_html.contains(expected),
            "missing {expected}"
        );
    }
}

#[test]
fn source_edit_changes_source_and_render_hash_without_changing_previous_output() {
    let original = run(&source()).unwrap();
    let mut edited: Value = serde_json::from_str(&original.canonical_source).unwrap();
    edited["blocks"][0]["text"] = json!("Changed");
    let changed = run(&edited).unwrap();
    assert_ne!(changed.source_sha256, original.source_sha256);
    assert_ne!(changed.html_sha256, original.html_sha256);
    assert!(original.canonical_html.contains("A &lt; B"));
}

#[test]
fn all_text_positions_escape_markup_quotes_and_unicode_remains_editable() {
    let attack = "<script src='https://example.invalid'>&\"é";
    let value = json!({"schema_version":1,"title":attack,"blocks":[
        {"kind":"heading","level":6,"text":attack},
        {"kind":"paragraph","runs":[{"kind":"code","text":attack}]},
        {"kind":"table","header":[attack],"rows":[[attack]]},
        {"kind":"code","text":attack}]});
    let rendered = run(&value).unwrap();
    assert!(!rendered.canonical_html.contains("<script"));
    assert_eq!(rendered.canonical_html.matches("&lt;script").count(), 6);
    assert!(rendered
        .canonical_html
        .contains("&#39;https://example.invalid&#39;"));
    assert!(rendered.canonical_source.contains('é'));
}

#[test]
fn unknown_tagged_unit_fields_duplicate_keys_and_active_grammar_are_refused() {
    for block in [
        json!({"kind":"rule","ignored":true}),
        json!({"kind":"paragraph","runs":[{"kind":"line-break","ignored":true}]}),
        json!({"kind":"iframe","url":"https://example.invalid"}),
    ] {
        let mut value = source();
        value["blocks"] = json!([block]);
        assert!(run(&value).is_err());
    }
    assert!(render(br#"{"schema_version":1,"schema_version":1,"title":"x","blocks":[]}"#).is_err());
    let mut value = source();
    value["stylesheet"] = json!("body{}");
    assert!(run(&value).is_err());
}

#[test]
fn blank_document_and_empty_text_are_supported_without_inferred_content() {
    let mut value = source();
    value["blocks"] = json!([]);
    assert!(run(&value)
        .unwrap()
        .canonical_html
        .contains("<main>\n</main>"));
    value["blocks"] = json!([{"kind":"paragraph","runs":[{"kind":"text","text":""}]}]);
    assert!(run(&value).unwrap().canonical_html.contains("<p></p>"));
}

#[test]
fn unsupported_text_controls_and_line_endings_are_refused() {
    for text in ["x\r\ny", "x\ry", "x\u{0000}y", "x\u{007f}y", "\u{feff}"] {
        let mut value = source();
        value["blocks"] = json!([{"kind":"code","text":text}]);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    value["blocks"] = json!([{"kind":"code","text":"x\n\ty"}]);
    assert!(run(&value).is_ok());
}

#[test]
fn invalid_block_shapes_and_structural_limits_are_refused() {
    for block in [
        json!({"kind":"heading","level":0,"text":"x"}),
        json!({"kind":"heading","level":7,"text":"x"}),
        json!({"kind":"heading","level":1,"text":""}),
        json!({"kind":"paragraph","runs":[]}),
        json!({"kind":"list","ordered":false,"items":[]}),
        json!({"kind":"table","header":["x"],"rows":[[]]}),
    ] {
        let mut value = source();
        value["blocks"] = json!([block]);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    value["blocks"] = json!(vec![json!({"kind":"rule"}); MAX_BLOCKS + 1]);
    assert!(run(&value).is_err());
    value["blocks"] = json!([{"kind":"code","text":"x".repeat(MAX_TEXT_BYTES+1)}]);
    assert!(run(&value).is_err());
}

#[test]
fn total_runs_table_cells_and_escaped_output_are_bounded() {
    let mut value = source();
    let runs = vec![json!({"kind":"line-break"}); MAX_RUNS_PER_ITEM];
    value["blocks"] = json!(vec![json!({"kind":"paragraph","runs":runs}); 65]);
    assert!(run(&value).is_err());
    let header = vec!["h"; 32];
    let rows = vec![vec!["x"; 32]; 64];
    value["blocks"] = json!([{"kind":"table","header":header,"rows":rows}]);
    assert!(run(&value).is_err());
    // Escaping expands an under-1MiB input past the independent output budget.
    value["blocks"] = json!(vec![
        json!({"kind":"code","text":"&".repeat(MAX_TEXT_BYTES)});
        64
    ]);
    assert!(serde_json::to_vec(&value).unwrap().len() < MAX_CONTENT_BYTES);
    assert!(matches!(run(&value), Err(Error::Bounds)));
}
