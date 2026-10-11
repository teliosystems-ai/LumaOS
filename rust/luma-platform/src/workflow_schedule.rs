//! Finite reviewed round-robin dispatch. This queue is inert input, not authority.
//! Every item re-enters the ordinary principal/grant/UTC/resource/effect boundary.
use super::{advance_reviewed, io, scope_id, snapshot};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ITEMS: usize = 16;
const MAX_GRANTS: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Item {
    request_id: String,
    review_sha256: String,
    #[serde(deserialize_with = "deserialize_grants")]
    grants: BTreeMap<String, String>,
}

pub(super) fn deserialize_grants<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct GrantsVisitor;
    impl<'de> serde::de::Visitor<'de> for GrantsVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 256 distinct exact workflow grant selectors")
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut grants = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if grants.contains_key(&key) {
                    return Err(serde::de::Error::custom(
                        "duplicate workflow grant selector",
                    ));
                }
                if grants.len() == MAX_GRANTS {
                    return Err(serde::de::Error::custom(
                        "workflow grant selector count exceeded",
                    ));
                }
                grants.insert(key, map.next_value::<String>()?);
            }
            Ok(grants)
        }
    }
    deserializer.deserialize_map(GrantsVisitor)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    schema_version: u32,
    installation: String,
    items: Vec<Item>,
}

impl Schedule {
    fn validate(&self, installation: &str) -> Result<()> {
        if self.schema_version != 1
            || !io::hash(installation)
            || self.installation != installation
            || self.items.is_empty()
            || self.items.len() > MAX_ITEMS
        {
            return Err("invalid reviewed workflow schedule identity or bound".into());
        }
        let mut requests = BTreeSet::new();
        for item in &self.items {
            if !io::identifier(&item.request_id)
                || !requests.insert(&item.request_id)
                || !io::hash(&item.review_sha256)
                || item.grants.is_empty()
                || item.grants.len() > MAX_GRANTS
                || !item.grants.contains_key("resume")
                || item.grants.iter().any(|(key, id)| {
                    key.is_empty()
                        || key.len() > 80
                        || !key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
                        || !scope_id(id)
                })
            {
                return Err(
                    "schedule requires distinct exact requests, reviews and finite grants".into(),
                );
            }
        }
        Ok(())
    }
}

fn dispatch(
    schedule: &Schedule,
    installation: &str,
    mut step: impl FnMut(&Item) -> Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    // Validate the entire batch before even the first authorized transition.
    schedule.validate(installation)?;
    let mut acknowledged = Vec::new();
    for (index, item) in schedule.items.iter().enumerate() {
        match step(item).and_then(|outcome| acknowledgement(item, &outcome)) {
            Ok(outcome) => acknowledged.push(outcome),
            Err(_) => {
                // A failure can occur after a durable intent or publication.
                // Do not retry, roll back, cancel, or claim no effect occurred.
                return Ok(serde_json::json!({
                    "schema_version": 1,
                    "installation": installation,
                    "state": "stopped-reconciliation-required",
                    "acknowledged_node_steps": acknowledged.len(),
                    "acknowledged": acknowledged,
                    "failed_request": item.request_id,
                    "failed_review_sha256": item.review_sha256,
                    "failed_outcome_uncertain": true,
                    "not_dispatched": schedule.items[index + 1..]
                        .iter().map(|item| &item.request_id).collect::<Vec<_>>(),
                    "automatic_retry": false,
                    "authority_restored": false,
                }));
            }
        }
    }
    Ok(serde_json::json!({
        "schema_version": 1,
        "installation": installation,
        "state": "dispatch-acknowledged",
        "acknowledged_node_steps": acknowledged.len(),
        "acknowledged": acknowledged,
        "not_dispatched": [],
        "workflow_completion_claimed": false,
        "automatic_retry": false,
        "authority_restored": false,
    }))
}

fn acknowledgement(item: &Item, outcome: &serde_json::Value) -> Result<serde_json::Value> {
    // Earlier item sessions may have expired before the final batch report.
    // Never retain/re-deliver their private plans, source bindings or receipts.
    // This projection only reports inert acknowledgements of this invocation;
    // inspecting private status requires a separately current granted command.
    let review = outcome["review_sha256"]
        .as_str()
        .ok_or("missing schedule acknowledgement review")?;
    let node = outcome["checkpoint"]["node"]
        .as_str()
        .ok_or("missing schedule acknowledgement node")?;
    let state = outcome["state"]
        .as_str()
        .ok_or("missing schedule acknowledgement state")?;
    let transitions = outcome["checkpoint_transitions"]
        .as_u64()
        .filter(|count| (1..=2).contains(count))
        .ok_or("invalid schedule acknowledgement transition count")?;
    let completed = outcome["completed_nodes"]
        .as_u64()
        .filter(|count| (1..=64).contains(count))
        .ok_or("invalid schedule acknowledgement completed-node count")?;
    if outcome["schema_version"] != 1
        || outcome["request_id"] != item.request_id
        || !io::hash(review)
        || !scope_id(node)
        || !matches!(state, "ready" | "completed")
    {
        return Err("schedule acknowledgement identity/state differs".into());
    }
    Ok(serde_json::json!({
        "request_id":item.request_id,
        "review_sha256":item.review_sha256,
        "next_review_sha256":review,
        "node_id":node,
        "state":state,
        "completed_nodes":completed,
        "checkpoint_transitions":transitions,
        "authority_restored":false,
    }))
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if args.len() != 3 {
        return Err("expected workflow-dag-schedule LOGIN SCHEDULE-SNAPSHOT".into());
    }
    let schedule: Schedule = snapshot(&args[2])?;
    let installation = io::installation()?;
    let result = dispatch(&schedule, &installation, |item| {
        if io::installation()? != installation {
            return Err("workflow schedule installation changed".into());
        }
        advance_reviewed(
            &[
                "workflow-dag-advance".into(),
                args[1].clone(),
                args[2].clone(),
                item.request_id.clone(),
                item.review_sha256.clone(),
            ],
            item.grants.clone(),
            true,
        )
    })?;
    println!("{result}");
    if result["state"] != "dispatch-acknowledged" {
        return Err(
            "workflow schedule stopped; inspect and reconcile the exact failed request".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(count: usize) -> Schedule {
        Schedule {
            schema_version: 1,
            installation: "a".repeat(64),
            items: (0..count)
                .map(|index| Item {
                    request_id: format!("run-{index}"),
                    review_sha256: "b".repeat(64),
                    grants: BTreeMap::from([("resume".into(), "exact-grant".into())]),
                })
                .collect(),
        }
    }

    fn private_outcome(item: &Item) -> serde_json::Value {
        serde_json::json!({
            "schema_version":1,"request_id":item.request_id,"state":"ready",
            "review_sha256":"c".repeat(64),"completed_nodes":1,"checkpoint_transitions":1,
            "plan":{"private_source":"/private/source.csv","account":"private-account"},
            "checkpoint":{"node":"read","output":{"receipt":"private-receipt"}},
            "receipt":"private-receipt",
        })
    }

    #[test]
    fn finite_round_robin_dispatches_one_reviewed_step_per_distinct_run() {
        let schedule = schedule(MAX_ITEMS);
        let mut observed = Vec::new();
        let result = dispatch(&schedule, &schedule.installation, |item| {
            observed.push(item.request_id.clone());
            Ok(private_outcome(item))
        })
        .unwrap();
        assert_eq!(
            observed,
            (0..MAX_ITEMS)
                .map(|i| format!("run-{i}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(result["state"], "dispatch-acknowledged");
        assert_eq!(result["acknowledged"].as_array().unwrap().len(), MAX_ITEMS);
        assert_eq!(result["workflow_completion_claimed"], false);
        let encoded = serde_json::to_string(&result).unwrap();
        for private in [
            "private-source",
            "/private/source.csv",
            "private-account",
            "private-receipt",
            "\"plan\"",
            "\"checkpoint\"",
            "\"receipt\"",
        ] {
            assert!(!encoded.contains(private));
        }
        assert_eq!(
            result["acknowledged"][0]["next_review_sha256"],
            "c".repeat(64)
        );
    }

    #[test]
    fn refusal_or_post_publication_failure_stops_without_retry_or_false_rollback() {
        for fail_at in 0..4 {
            let schedule = schedule(4);
            let mut called = 0;
            let result = dispatch(&schedule, &schedule.installation, |item| {
                let current = called;
                called += 1;
                if current == fail_at {
                    Err("revoked or uncertain durable effect".into())
                } else {
                    Ok(private_outcome(item))
                }
            })
            .unwrap();
            assert_eq!(called, fail_at + 1);
            assert_eq!(result["acknowledged"].as_array().unwrap().len(), fail_at);
            assert_eq!(
                result["not_dispatched"].as_array().unwrap().len(),
                3 - fail_at
            );
            assert_eq!(result["failed_request"], format!("run-{fail_at}"));
            assert_eq!(result["failed_outcome_uncertain"], true);
            assert_eq!(result["automatic_retry"], false);
            assert_eq!(result["authority_restored"], false);
        }
    }

    #[test]
    fn malformed_batch_is_rejected_before_dispatch_including_late_bad_item() {
        let mut bad = Vec::new();
        bad.push(schedule(0));
        bad.push(schedule(MAX_ITEMS + 1));
        let mut duplicate = schedule(2);
        duplicate.items[1].request_id = duplicate.items[0].request_id.clone();
        bad.push(duplicate);
        let mut missing = schedule(2);
        missing.items[1].grants.clear();
        bad.push(missing);
        let mut malformed = schedule(2);
        malformed.items[1].review_sha256 = "B".repeat(64);
        bad.push(malformed);
        let mut schema = schedule(1);
        schema.schema_version = 2;
        bad.push(schema);
        let mut install = schedule(1);
        install.installation = "c".repeat(64);
        bad.push(install);
        let mut grant = schedule(2);
        grant.items[1]
            .grants
            .insert("resume".into(), "unsafe/grant".into());
        bad.push(grant);
        for schedule in bad {
            let result = dispatch(&schedule, &"a".repeat(64), |_| {
                panic!("malformed schedule dispatched an effect")
            });
            assert!(result.is_err());
        }
        let mut encoded = serde_json::to_value(schedule(1)).unwrap();
        encoded["restore_authority"] = true.into();
        assert!(serde_json::from_value::<Schedule>(encoded).is_err());
    }

    #[test]
    fn duplicate_or_excessive_grant_selectors_are_refused_during_parsing() {
        let manifest = serde_json::to_string(&schedule(1)).unwrap();
        for grants in [
            r#"{"resume":"one","resume":"two"}"#,
            r#"{"resume":"exact-grant","read.left":"one","read.left":"two"}"#,
        ] {
            let duplicated = manifest.replace(r#"{"resume":"exact-grant"}"#, grants);
            assert_ne!(duplicated, manifest);
            assert!(serde_json::from_str::<Schedule>(&duplicated).is_err());
        }
        let mut oversized = schedule(1);
        for index in 0..MAX_GRANTS {
            oversized.items[0]
                .grants
                .insert(format!("read.node-{index}"), "exact-grant".into());
        }
        assert_eq!(oversized.items[0].grants.len(), MAX_GRANTS + 1);
        let encoded = serde_json::to_vec(&oversized).unwrap();
        assert!(serde_json::from_slice::<Schedule>(&encoded).is_err());
        oversized.items[0].grants.remove("read.node-0");
        assert!(
            serde_json::from_slice::<Schedule>(&serde_json::to_vec(&oversized).unwrap()).is_ok()
        );
    }

    #[test]
    fn malformed_acknowledgements_stop_without_echoing_private_outcomes() {
        let schedule = schedule(2);
        for (field, value) in [
            ("state", serde_json::json!("applying")),
            ("request_id", serde_json::json!("different-run")),
            ("review_sha256", serde_json::json!("bad-digest")),
            ("checkpoint_transitions", serde_json::json!(0)),
            ("checkpoint_transitions", serde_json::json!(3)),
            ("completed_nodes", serde_json::json!(65)),
            ("completed_nodes", serde_json::json!(-1)),
            ("checkpoint", serde_json::json!({"node":"unsafe/node"})),
        ] {
            let mut called = 0;
            let result = dispatch(&schedule, &schedule.installation, |item| {
                called += 1;
                let mut outcome = private_outcome(item);
                outcome[field] = value.clone();
                Ok(outcome)
            })
            .unwrap();
            assert_eq!(called, 1);
            assert_eq!(result["acknowledged_node_steps"], 0);
            assert_eq!(result["failed_outcome_uncertain"], true);
            assert_eq!(result["not_dispatched"], serde_json::json!(["run-1"]));
            assert!(!result.to_string().contains("private-receipt"));
            assert!(!result.to_string().contains("/private/source.csv"));
        }
    }
}
