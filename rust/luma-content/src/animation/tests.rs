use super::*;
use serde_json::{json, Value};

fn source() -> Value {
    json!({"schema_version":1,"width":320,"height":240,"frames_per_second":24,
        "frame_count":3,"background":"#ffffff","sprites":[
            {"id":"box","shape":{"kind":"rectangle","width":10,"height":20},
            "fill":"#123abc","keyframes":[{"frame":0,"x":0,"y":2},{"frame":2,"x":3,"y":-1}]}]})
}
fn run(value: &Value) -> Result<Rendered> {
    render(&serde_json::to_vec(value).unwrap())
}

#[test]
fn source_reopens_and_every_frame_and_bundle_has_an_exact_digest() {
    let result = run(&source()).unwrap();
    assert_eq!(render(result.canonical_source.as_bytes()).unwrap(), result);
    assert_eq!(
        sha256(result.canonical_source.as_bytes()),
        result.source_sha256
    );
    assert_eq!(
        sha256(&serde_json::to_vec(&result.frames).unwrap()),
        result.frames_sha256
    );
    for frame in &result.frames {
        assert_eq!(sha256(frame.canonical_svg.as_bytes()), frame.svg_sha256);
    }
    assert_eq!(result.work_units, 9);
}

#[test]
fn integer_interpolation_rounds_down_for_both_signs_and_honors_endpoints() {
    let result = run(&source()).unwrap();
    for (index, expected) in ["x=\"0\" y=\"2\"", "x=\"1\" y=\"0\"", "x=\"3\" y=\"-1\""]
        .iter()
        .enumerate()
    {
        assert!(result.frames[index].canonical_svg.contains(expected));
    }
    assert_eq!(coordinate(0, -3, 1, 2), -2);
}

#[test]
fn single_frame_and_empty_scene_are_real_rendered_outputs() {
    let mut value = source();
    value["frame_count"] = json!(1);
    value["sprites"][0]["keyframes"] = json!([{"frame":0,"x":7,"y":8}]);
    assert!(run(&value).unwrap().frames[0]
        .canonical_svg
        .contains("x=\"7\" y=\"8\""));
    value["sprites"] = json!([]);
    assert_eq!(run(&value).unwrap().frames.len(), 1);
}

#[test]
fn circle_and_layer_order_are_preserved() {
    let mut value = source();
    let mut circle = value["sprites"][0].clone();
    circle["id"] = json!("ball");
    circle["shape"] = json!({"kind":"circle","radius":12});
    value["sprites"].as_array_mut().unwrap().push(circle);
    let svg = &run(&value).unwrap().frames[0].canonical_svg;
    assert!(svg.find("id=\"box\"").unwrap() < svg.find("id=\"ball\"").unwrap());
    assert!(svg.contains("<circle id=\"ball\" cx=\"0\" cy=\"2\" r=\"12\""));
}

#[test]
fn schema_duplicates_unknown_fields_and_non_integer_numbers_are_refused() {
    for raw in [
        b"{\"schema_version\":1,\"schema_version\":1}".as_slice(),
        b"null",
        b"[]",
    ] {
        assert!(render(raw).is_err());
    }
    for (field, item) in [
        ("schema_version", json!(2)),
        ("width", json!(1.5)),
        ("external_script", json!("https://example.invalid")),
    ] {
        let mut value = source();
        value[field] = item;
        assert!(run(&value).is_err());
    }
    let mut value = source();
    value["sprites"][0]["shape"]["onload"] = json!("alert(1)");
    assert!(run(&value).is_err());
}

#[test]
fn colors_ids_and_dimensions_cannot_inject_markup_or_external_references() {
    for fill in [
        "url(https://example.invalid)",
        "#FFFFFF",
        "#000000\" onload=\"x",
        "red",
    ] {
        let mut value = source();
        value["sprites"][0]["fill"] = json!(fill);
        assert!(run(&value).is_err());
    }
    for id in ["", "has space", "<script>", "é", &"a".repeat(65)] {
        let mut value = source();
        value["sprites"][0]["id"] = json!(id);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    let duplicate = value["sprites"][0].clone();
    value["sprites"].as_array_mut().unwrap().push(duplicate);
    assert!(run(&value).is_err());
    for size in [0, 4097] {
        let mut value = source();
        value["width"] = json!(size);
        assert!(run(&value).is_err());
    }
}

#[test]
fn keyframes_must_cover_exact_timeline_in_strict_order_with_bounded_coordinates() {
    for keys in [
        json!([]),
        json!([{"frame":1,"x":0,"y":0},{"frame":2,"x":0,"y":0}]),
        json!([{"frame":0,"x":0,"y":0}]),
        json!([{"frame":0,"x":0,"y":0},{"frame":0,"x":1,"y":1},{"frame":2,"x":0,"y":0}]),
        json!([{"frame":0,"x":8193,"y":0},{"frame":2,"x":0,"y":0}]),
    ] {
        let mut value = source();
        value["sprites"][0]["keyframes"] = keys;
        assert!(run(&value).is_err());
    }
}

#[test]
fn frame_rate_frame_count_and_sprite_bounds_are_enforced() {
    for (field, item) in [
        ("frames_per_second", 0),
        ("frames_per_second", 61),
        ("frame_count", 0),
        ("frame_count", 121),
    ] {
        let mut value = source();
        value[field] = json!(item);
        assert!(run(&value).is_err());
    }
    let mut value = source();
    let sprite = value["sprites"][0].clone();
    value["sprites"] = json!((0..33)
        .map(|index| {
            let mut s = sprite.clone();
            s["id"] = json!(format!("s{index}"));
            s
        })
        .collect::<Vec<_>>());
    assert!(run(&value).is_err());
}

#[test]
fn maximum_scene_is_complete_within_budget_and_oversized_source_is_refused() {
    let mut value = source();
    value["frame_count"] = json!(120);
    let mut sprite = value["sprites"][0].clone();
    sprite["keyframes"][1]["frame"] = json!(119);
    value["sprites"] = json!((0..32)
        .map(|index| {
            let mut s = sprite.clone();
            s["id"] = json!(format!("{index}{}", "x".repeat(62)));
            s
        })
        .collect::<Vec<_>>());
    // Valid maximum scene fits the bound; output is complete and never auto-plays.
    let result = run(&value).unwrap();
    assert_eq!(result.frames.len(), 120);
    assert!(serde_json::to_vec(&result.frames).unwrap().len() <= MAX_RENDER_BYTES);
    let mut oversized = serde_json::to_vec(&source()).unwrap();
    oversized.extend(std::iter::repeat(b' ').take(MAX_CONTENT_BYTES));
    assert!(render(&oversized).is_err());
}

#[test]
fn work_metric_counts_every_keyframe_pair_scanned_including_last_frame() {
    let mut value = source();
    value["frame_count"] = json!(4);
    value["sprites"][0]["keyframes"] = json!([
        {"frame":0,"x":0,"y":0},{"frame":1,"x":1,"y":1},
        {"frame":2,"x":2,"y":2},{"frame":3,"x":3,"y":3}]);
    let result = run(&value).unwrap();
    assert_eq!(result.work_units, 4 + 4 + 1 + 2 + 3 + 3);
    assert!(result.work_units <= MAX_RENDER_WORK_UNITS);
}
