use super::*;
use luma_content::rendered::{Engine, Request};
use serde_json::json;

fn request(engine: Engine, source: serde_json::Value) -> Request {
    Request {
        binding: binding(),
        artifact_id: "editable".into(),
        expected: None,
        metadata: luma_content::table::EditMetadata {
            request_id: "first".into(),
            workflow_sha256: "c".repeat(64),
        },
        engine,
        source: serde_json::to_string(&source).unwrap(),
    }
}
fn spreadsheet() -> Request {
    request(
        Engine::Spreadsheet,
        json!({"schema_version":1,"rows":[[{"kind":"number","value":"2"}]]}),
    )
}
fn publish(f: &Fixture, request: &Request) -> (Repository, Plan) {
    let plan = Plan::managed_render(None, request).unwrap();
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    store
        .apply(
            &plan,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    (store, plan)
}

#[test]
fn all_engines_publish_editable_sources_and_reconstruct_exact_derived_results() {
    let requests = [
        spreadsheet(),
        request(
            Engine::Document,
            json!({"schema_version":1,"title":"Blank","blocks":[]}),
        ),
        request(
            Engine::Diagram,
            json!({"schema_version":1,"title":"Blank","width":100,"height":100,"nodes":[],"edges":[]}),
        ),
        request(
            Engine::Animation,
            json!({"schema_version":1,"width":100,"height":100,
            "frames_per_second":24,"frame_count":1,"background":"#ffffff","sprites":[]}),
        ),
    ];
    for request in requests {
        let f = Fixture::new();
        let (store, plan) = publish(&f, &request);
        assert_eq!(plan.source_kind(), SourceKind::ManagedRenderIntent);
        assert_eq!(plan.derivation().unwrap().engine, request.engine);
        let retained = store.retained("first", &mut Guard::read()).unwrap();
        assert_eq!(retained.source, request.canonical_bytes().unwrap());
        let version = store.current("editable", &mut Guard::read()).unwrap();
        assert_eq!(version.receipt().format, Format::Json);
        let editable: serde_json::Value = serde_json::from_slice(version.content()).unwrap();
        assert_eq!(
            editable["engine"],
            serde_json::to_value(request.engine).unwrap()
        );
        assert_eq!(
            editable["source"],
            serde_json::from_str::<serde_json::Value>(&request.source).unwrap()
        );
        drop(store);
        let store = Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
        assert_eq!(
            store
                .replay_plan(
                    "first",
                    &request.canonical_bytes().unwrap(),
                    &mut Guard::read()
                )
                .unwrap()
                .unwrap(),
            plan
        );
        assert_eq!(
            store.retained("first", &mut Guard::read()).unwrap(),
            retained
        );
    }
}

#[test]
fn formula_source_edits_publish_even_when_csv_does_not_change_and_old_replay_never_rolls_back() {
    let f = Fixture::new();
    let mut request = spreadsheet();
    let (mut store, first) = publish(&f, &request);
    request.expected = Some(first.resulting().clone());
    request.metadata.request_id = "formula".into();
    request.source = json!({"schema_version":1,"rows":[[{"kind":"formula",
        "expression":{"op":"binary","operator":"add","left":{"op":"number","value":"1"},
            "right":{"op":"number","value":"1"}}}]]})
    .to_string();
    let second = store.plan_render(&request, &mut Guard::read()).unwrap();
    assert_eq!(second.decision(), DecisionKind::Published);
    assert_eq!(second.resulting().version, 2);
    assert_eq!(
        first.derivation().unwrap().output_sha256,
        second.derivation().unwrap().output_sha256
    );
    assert_ne!(
        first.resulting().content_sha256,
        second.resulting().content_sha256
    );
    store
        .apply(
            &second,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&second),
        )
        .unwrap();
    let initial = spreadsheet();
    assert!(
        store
            .apply(
                &first,
                &initial.canonical_bytes().unwrap(),
                &mut Guard::write(&first)
            )
            .unwrap()
            .replayed
    );
    assert_eq!(
        store
            .current("editable", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        *second.resulting()
    );
}

#[test]
fn no_change_and_stale_conflict_retain_the_exact_editable_intent_without_overwrite() {
    let f = Fixture::new();
    let mut request = spreadsheet();
    let (mut store, first) = publish(&f, &request);
    request.expected = Some(first.resulting().clone());
    request.metadata.request_id = "noop".into();
    request.source.push('\n');
    let no_change = store.plan_render(&request, &mut Guard::read()).unwrap();
    assert_eq!(no_change.decision(), DecisionKind::NoChangeRetained);
    store
        .apply(
            &no_change,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&no_change),
        )
        .unwrap();
    assert_eq!(
        store.retained("noop", &mut Guard::read()).unwrap().source,
        request.canonical_bytes().unwrap()
    );
    request.metadata.request_id = "stale".into();
    request.expected.as_mut().unwrap().receipt_sha256 = "d".repeat(64);
    request.source =
        json!({"schema_version":1,"rows":[[{"kind":"number","value":"9"}]]}).to_string();
    let conflict = store.plan_render(&request, &mut Guard::read()).unwrap();
    assert_eq!(conflict.decision(), DecisionKind::ConflictRetained);
    assert_eq!(
        conflict.derivation().unwrap().output_sha256,
        luma_content::sha256(b"9\n")
    );
    store
        .apply(
            &conflict,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&conflict),
        )
        .unwrap();
    assert_eq!(
        store
            .current("editable", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        *first.resulting()
    );
    drop(store);
    Repository::open_at(&f.path, &binding(), &mut Guard::read()).unwrap();
}

#[test]
fn wrong_owner_missing_base_engine_substitution_and_invalid_formula_refuse_without_writes() {
    let f = Fixture::new();
    let request = spreadsheet();
    let (store, first) = publish(&f, &request);
    assert!(store.plan_render(&request, &mut Guard::read()).is_err());
    let mut bad = request.clone();
    bad.expected = Some(first.resulting().clone());
    bad.binding.owner_generation += 1;
    assert!(store.plan_render(&bad, &mut Guard::read()).is_err());
    bad = request.clone();
    bad.expected = Some(first.resulting().clone());
    bad.engine = Engine::Document;
    bad.source = json!({"schema_version":1,"title":"x","blocks":[]}).to_string();
    assert!(store.plan_render(&bad, &mut Guard::read()).is_err());
    bad = request.clone();
    bad.source = json!({"schema_version":1,"rows":[[{"kind":"formula",
        "expression":{"op":"cell","row":0,"column":0}}]]})
    .to_string();
    assert!(Plan::managed_render(None, &bad).is_err());
    bad = request;
    bad.expected = Some(first.resulting().clone());
    assert!(Plan::managed_render(None, &bad).is_err());
}

#[test]
fn changed_exact_input_and_tampered_derivation_cannot_be_replayed_or_reconstructed() {
    let f = Fixture::new();
    let request = spreadsheet();
    let (store, _) = publish(&f, &request);
    let mut changed = request.clone();
    changed.source.push(' ');
    assert!(store
        .replay_plan(
            "first",
            &changed.canonical_bytes().unwrap(),
            &mut Guard::read()
        )
        .is_err());
    drop(store);
    let record_path = f
        .root(&binding())
        .join("outcomes")
        .join(luma_content::sha256(b"first"))
        .join("record.json");
    let bytes = fs::read(&record_path).unwrap();
    let mut record: Record = serde_json::from_slice(&bytes).unwrap();
    record.plan.derivation.as_mut().unwrap().output_sha256 = "e".repeat(64);
    // Even a self-consistently recomputed record review cannot fabricate an engine result.
    record.review_sha256 = luma_content::sha256(&serde_json::to_vec(&record.plan).unwrap());
    fs::write(record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(Repository::open_at(&f.path, &binding(), &mut Guard::read()).is_err());
}

#[test]
fn invalid_request_metadata_and_noncanonical_sources_cannot_bypass_typed_engines() {
    let mut request = spreadsheet();
    request.metadata.workflow_sha256 = "0".repeat(64);
    assert!(Plan::managed_render(None, &request).is_err());
    request = spreadsheet();
    request.metadata.request_id = "../x".into();
    assert!(Plan::managed_render(None, &request).is_err());
    request = spreadsheet();
    request.source = "{\"schema_version\":1,\"schema_version\":1,\"rows\":[]}".into();
    assert!(Plan::managed_render(None, &request).is_err());
}

#[test]
fn revocation_and_interrupted_preparation_preserve_complete_atomic_render_intent() {
    let request = spreadsheet();
    let plan = Plan::managed_render(None, &request).unwrap();
    let source = request.canonical_bytes().unwrap();
    let f = Fixture::new();
    let mut guard = Guard::write(&plan);
    let mut store = Repository::create_at(&f.path, &plan, &mut guard).unwrap();
    let mut revoked = Guard::write(&plan);
    revoked.refuse_at = 1;
    assert!(store.apply(&plan, &source, &mut revoked).is_err());
    let result = store.apply_with_hook(&plan, &source, &mut Guard::write(&plan), |point| {
        if matches!(point, Phase::Prepared) {
            Err("disposable render interruption".into())
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    store
        .apply(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    assert_eq!(
        store.retained("first", &mut Guard::read()).unwrap().source,
        source
    );
}

#[test]
fn every_render_publication_checkpoint_refuses_or_retains_the_exact_atomic_outcome() {
    let request = spreadsheet();
    let source = request.canonical_bytes().unwrap();
    let plan = Plan::managed_render(None, &request).unwrap();
    let f = Fixture::new();
    let mut store = Repository::create_at(&f.path, &plan, &mut Guard::write(&plan)).unwrap();
    let mut counter = Guard::write(&plan);
    store.apply(&plan, &source, &mut counter).unwrap();
    drop(store);
    for refused in 1..=counter.checks {
        let fixture = Fixture::new();
        let mut store =
            Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
        let mut guard = Guard::write(&plan);
        guard.refuse_at = refused;
        assert!(store.apply(&plan, &source, &mut guard).is_err());
        assert_eq!(guard.checks, refused, "no operation after revocation");
        drop(store);
        let mut store = Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
        let before = store.inventory(&mut Guard::read()).unwrap();
        assert!(before.len() <= 1);
        let pending_bytes = |store: &Repository| {
            let mut result = Vec::new();
            for name in storage::names(&store.pending, MAX_PENDING).unwrap() {
                let directory = storage::directory(&store.pending, &name).unwrap();
                for member in storage::names(&directory, 3).unwrap() {
                    result.push((
                        name.clone(),
                        member.clone(),
                        storage::read(&directory, &member, MAX_SOURCE, &mut || Ok(())).unwrap(),
                    ));
                }
            }
            result
        };
        let pending_before = pending_bytes(&store);
        let retried = store.apply(&plan, &source, &mut Guard::write(&plan));
        if let Err(error) = &retried {
            assert_eq!(
                error.to_string(),
                "partial or changed content preparation requires separate recovery"
            );
        }
        if let Ok(outcome) = retried {
            assert_eq!(outcome.resulting, *plan.resulting());
            assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 1);
            assert_eq!(
                store.retained("first", &mut Guard::read()).unwrap().source,
                source
            );
        } else {
            // Revocation may leave an incomplete member, not a fully prepared
            // transaction. Preserve those exact bytes for separate recovery;
            // never erase them or silently fill/overwrite a partial file.
            assert_eq!(store.inventory(&mut Guard::read()).unwrap(), before);
            assert!(!pending_before.is_empty());
            assert_eq!(pending_bytes(&store), pending_before);
        }
    }
}

#[test]
fn concurrent_render_head_change_refuses_old_approval_and_rereview_retains_conflict() {
    let f = Fixture::new();
    let initial = spreadsheet();
    let (mut store, first) = publish(&f, &initial);
    let mut edit = initial.clone();
    edit.expected = Some(first.resulting().clone());
    edit.metadata.request_id = "edit".into();
    edit.source = json!({"schema_version":1,"rows":[[{"kind":"number","value":"9"}]]}).to_string();
    let old = store.plan_render(&edit, &mut Guard::read()).unwrap();
    let mut newer = edit.clone();
    newer.metadata.request_id = "newer".into();
    newer.source = json!({"schema_version":1,"rows":[[{"kind":"number","value":"3"}]]}).to_string();
    let newer_plan = store.plan_render(&newer, &mut Guard::read()).unwrap();
    store
        .apply(
            &newer_plan,
            &newer.canonical_bytes().unwrap(),
            &mut Guard::write(&newer_plan),
        )
        .unwrap();
    assert!(store
        .apply(
            &old,
            &edit.canonical_bytes().unwrap(),
            &mut Guard::write(&old)
        )
        .is_err());
    let conflict = store.plan_render(&edit, &mut Guard::read()).unwrap();
    assert_eq!(conflict.decision(), DecisionKind::ConflictRetained);
    assert_eq!(conflict.resulting(), newer_plan.resulting());
    assert_eq!(
        conflict.derivation().unwrap().output_sha256,
        luma_content::sha256(b"9\n")
    );
    store
        .apply(
            &conflict,
            &edit.canonical_bytes().unwrap(),
            &mut Guard::write(&conflict),
        )
        .unwrap();
    assert_eq!(
        store
            .current("editable", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        *newer_plan.resulting()
    );
    assert_eq!(
        store.retained("edit", &mut Guard::read()).unwrap().source,
        edit.canonical_bytes().unwrap()
    );
}

#[test]
fn a_second_render_artifact_is_created_without_replacing_an_existing_head() {
    let f = Fixture::new();
    let initial = spreadsheet();
    let (mut store, first) = publish(&f, &initial);
    let mut second = initial;
    second.artifact_id = "second".into();
    second.metadata.request_id = "second".into();
    let plan = store.plan_render(&second, &mut Guard::read()).unwrap();
    store
        .apply(
            &plan,
            &second.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    assert_eq!(
        store
            .current("editable", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        *first.resulting()
    );
    assert_eq!(
        store
            .current("second", &mut Guard::read())
            .unwrap()
            .reference()
            .unwrap(),
        *plan.resulting()
    );
    drop(store);
    assert_eq!(
        Repository::open_at(&f.path, &binding(), &mut Guard::read())
            .unwrap()
            .inventory(&mut Guard::read())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn resealed_schema_downgrade_derivation_omission_and_engine_version_substitution_are_refused() {
    let f = Fixture::new();
    let request = spreadsheet();
    let (store, _) = publish(&f, &request);
    drop(store);
    let record_path = f
        .root(&binding())
        .join("outcomes")
        .join(luma_content::sha256(b"first"))
        .join("record.json");
    let original: Record = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
    for kind in 0..4 {
        let mut record = original.clone();
        match kind {
            0 => {
                record.schema_version = 1;
                record.plan.schema_version = 1;
                record.plan.source_kind = None;
                record.plan.derivation = None;
            }
            1 => {
                record.schema_version = 2;
                record.plan.schema_version = 2;
                record.plan.source_kind = Some(SourceKind::ManagedTableIntent);
                record.plan.derivation = None;
            }
            2 => record.plan.derivation = None,
            _ => {
                record.plan.derivation.as_mut().unwrap().implementation =
                    "unreviewed-engine-v2".into()
            }
        }
        record.review_sha256 = luma_content::sha256(&serde_json::to_vec(&record.plan).unwrap());
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(Repository::open_at(&f.path, &binding(), &mut Guard::read()).is_err());
    }
}

#[test]
fn interruption_at_each_render_durable_phase_retries_one_exact_atomic_outcome() {
    let request = spreadsheet();
    let source = request.canonical_bytes().unwrap();
    let plan = Plan::managed_render(None, &request).unwrap();
    for failed_phase in 0..4 {
        let fixture = Fixture::new();
        let mut store =
            Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
        assert!(store
            .apply_with_hook(&plan, &source, &mut Guard::write(&plan), |phase| {
                let selected = match failed_phase {
                    0 => matches!(phase, Phase::MemberSynced),
                    1 => matches!(phase, Phase::Prepared),
                    2 => matches!(phase, Phase::Renamed),
                    _ => matches!(phase, Phase::Committed),
                };
                if selected {
                    Err("disposable interrupted render".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(store);
        let mut store = Repository::open_at(&fixture.path, &binding(), &mut Guard::read()).unwrap();
        let result = store
            .apply(&plan, &source, &mut Guard::write(&plan))
            .unwrap();
        assert_eq!(result.replayed, failed_phase >= 2);
        assert_eq!(store.inventory(&mut Guard::read()).unwrap().len(), 1);
        assert_eq!(
            store
                .replay_plan("first", &source, &mut Guard::read())
                .unwrap()
                .unwrap(),
            plan
        );
    }
}
