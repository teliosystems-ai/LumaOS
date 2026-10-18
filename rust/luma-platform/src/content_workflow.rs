//! The closed native content-engine workflow compiled into the measured image.
//! Requests cannot select a workflow hash, executable, graph or output. Its
//! durable checkpoint is the exact schema-3 Record admitted to the independent
//! C history, not an additional mutable workflow file or a caller's receipt.
//! This module validates execution data; the caller must retain original live
//! Read/effect/resource authority and verify the real C commit before publish.
use crate::Result;
use luma_content::{rendered, OwnerBinding, VersionReference};
use luma_content_store::{Access, Boundary, Outcome, Plan, PreparedPublication, VerifiedState};
use serde::{Deserialize, Serialize};

// This is a distinct built-in image workflow, not the separately signed
// file-to-invoice skill DAG. Updating it requires a new authenticated image.
const GRAPH: &[u8] = br#"{"schema_version":1,"profile":"native-content-engine-v1","nodes":["finite-read-and-current-C-state","deterministic-managed-render","exact-review-and-finite-effect","held-preparation","independent-C-anchor","no-replace-publication","same-state-reopen"]}"#;
const PROFILE: &str = "native-content-engine-v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) schema_version: u32,
    pub(crate) request_id: String,
    pub(crate) artifact_id: String,
    pub(crate) expected: Option<VersionReference>,
    pub(crate) engine: rendered::Engine,
    pub(crate) source: String,
}

pub(crate) fn graph_sha256() -> String {
    luma_content::sha256(GRAPH)
}

impl Request {
    /// Closed proposal data only. The image chooses the workflow identity.
    pub(crate) fn intent(&self, binding: &OwnerBinding) -> Result<rendered::Request> {
        if self.schema_version != 1 {
            return Err("unsupported native content workflow schema".into());
        }
        let request = rendered::Request {
            binding: binding.clone(),
            artifact_id: self.artifact_id.clone(),
            expected: self.expected.clone(),
            metadata: luma_content::table::EditMetadata {
                request_id: self.request_id.clone(),
                workflow_sha256: graph_sha256(),
            },
            engine: self.engine,
            source: self.source.clone(),
        };
        request.canonical_bytes()?;
        Ok(request)
    }
}

/// A real deterministic result checked against the actual private-history Plan.
/// It is not serializable, clonable, a grant, or a custody acknowledgment.
pub(crate) struct Execution {
    binding: OwnerBinding,
    intent: Vec<u8>,
    review: String,
    derivation: rendered::Derivation,
    request_id: String,
    resulting: VersionReference,
    decision: luma_content_store::DecisionKind,
}

/// Completion data for the caller that already verified the actual C outcome.
/// No signature, current authorization or production-qualification flag exists.
#[derive(Debug, Serialize)]
pub(crate) struct Completion {
    schema_version: u32,
    profile: String,
    workflow_sha256: String,
    binding: OwnerBinding,
    request_id: String,
    review_sha256: String,
    original_intent_sha256: String,
    derivation: rendered::Derivation,
    record_sha256: String,
    protected_outcome: VerifiedState,
    outcome: Outcome,
}

pub(crate) struct HeldExecution {
    execution: Execution,
    record_sha256: String,
    wanted: VerifiedState,
    sequence: u64,
}

impl Execution {
    /// Called inside the existing admitted, bounded content acquisition worker.
    /// The native caller admits the resource profile before constructing Plan;
    /// these repeated Boundary checks do not replace that admission or C proof.
    pub(crate) fn verify(
        request: &Request,
        binding: &OwnerBinding,
        plan: &Plan,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        boundary.check(Access::Inspect { binding })?;
        let intent = request.intent(binding)?;
        let bytes = intent.canonical_bytes()?;
        let (_, derivation) = rendered::prepare(&intent)?;
        if plan.binding() != binding
            || plan.artifact_id() != request.artifact_id
            || plan.request_id() != request.request_id
            || plan.expected() != request.expected.as_ref()
            || plan.format() != luma_content::Format::Json
            || plan.source_kind() != luma_content_store::SourceKind::ManagedRenderIntent
            || plan.provenance().origin != luma_content::EditOrigin::Managed
            || plan.provenance().workflow_sha256 != graph_sha256()
            || plan.provenance().source_sha256 != luma_content::sha256(&bytes)
            || plan.source_bytes() != bytes.len() as u64
            || plan.derivation() != Some(&derivation)
        {
            return Err(
                "actual managed workflow plan differs from the image-selected execution".into(),
            );
        }
        boundary.check(Access::Inspect { binding })?;
        Ok(Self {
            binding: binding.clone(),
            intent: bytes,
            review: plan.review_sha256().into(),
            derivation,
            request_id: request.request_id.clone(),
            resulting: plan.resulting().clone(),
            decision: plan.decision(),
        })
    }

    /// Bind the exact held preparation BEFORE its real C anchor. The Record
    /// already contains every execution/source/result field checked here.
    pub(crate) fn bind(self, prepared: &PreparedPublication<'_>) -> Result<HeldExecution> {
        let held = prepared.commitment();
        let record_sha256 = luma_content::sha256(prepared.record_bytes());
        let source = held
            .members()
            .iter()
            .find(|member| member.name() == "source.bin")
            .ok_or("workflow preparation lacks original intent")?;
        let record = held
            .members()
            .iter()
            .find(|member| member.name() == "record.json")
            .ok_or("workflow preparation lacks exact checkpoint record")?;
        if held.binding() != &self.binding
            || held.request_id() != self.request_id
            || held.review_sha256() != self.review
            || source.bytes() != self.intent.len() as u64
            || source.sha256() != luma_content::sha256(&self.intent)
            || record.sha256() != record_sha256
            || record.bytes() != prepared.record_bytes().len() as u64
        {
            return Err(
                "held publication substitutes managed workflow execution or its checkpoint".into(),
            );
        }
        let value: serde_json::Value = serde_json::from_slice(prepared.record_bytes())?;
        if value["plan"]["derivation"] != serde_json::to_value(&self.derivation)?
            || value["plan"]["provenance"]["workflow_sha256"] != graph_sha256()
            || value["plan"]["resulting"] != serde_json::to_value(&self.resulting)?
        {
            return Err(
                "durable workflow record differs from actual deterministic execution".into(),
            );
        }
        let sequence = value["sequence"]
            .as_u64()
            .ok_or("workflow checkpoint ordinal missing")?;
        if sequence == 0 || sequence > held.outcome_state().outcome_count {
            return Err("invalid workflow checkpoint ordinal".into());
        }
        Ok(HeldExecution {
            wanted: held.outcome_state(),
            execution: self,
            record_sha256,
            sequence,
        })
    }
}

impl HeldExecution {
    /// Validate completion data AFTER the native caller checks genuine C proof,
    /// publishes through the same live Boundary and reopens at that exact cut.
    /// A caller-supplied state alone is not authenticated by this function.
    pub(crate) fn completion(
        self,
        outcome: &Outcome,
        current: &VerifiedState,
    ) -> Result<Completion> {
        current.validate()?;
        if current != &self.wanted
            || outcome.sequence != self.sequence
            || outcome.request_id != self.execution.request_id
            || outcome.review_sha256 != self.execution.review
            || outcome.source_sha256 != luma_content::sha256(&self.execution.intent)
            || outcome.source_kind != luma_content_store::SourceKind::ManagedRenderIntent
            || outcome.decision != self.execution.decision
            || outcome.resulting != self.execution.resulting
        {
            return Err(
                "managed workflow completion differs from its exact committed checkpoint".into(),
            );
        }
        Ok(Completion {
            schema_version: 1,
            profile: PROFILE.into(),
            workflow_sha256: graph_sha256(),
            binding: self.execution.binding,
            request_id: self.execution.request_id,
            review_sha256: self.execution.review,
            original_intent_sha256: luma_content::sha256(&self.execution.intent),
            derivation: self.execution.derivation,
            record_sha256: self.record_sha256,
            protected_outcome: current.clone(),
            outcome: outcome.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> OwnerBinding {
        OwnerBinding {
            installation: "1".repeat(64),
            owner: "2".repeat(64),
            owner_generation: 1,
        }
    }
    fn request() -> Request {
        Request {schema_version:1,request_id:"workflow-one".into(),artifact_id:"document".into(),
        expected:None,engine:rendered::Engine::Document,source:r#"{"schema_version":1,"title":"Example","blocks":[{"kind":"paragraph","runs":[{"kind":"text","text":"actual"}]}]}"#.into()}
    }
    struct Guard(bool);
    impl Boundary for Guard {
        fn admit(
            &mut self,
            _: &OwnerBinding,
            _: luma_content_store::ResourceBudget,
        ) -> luma_content_store::Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err("revoked".into())
            }
        }
        fn check(&mut self, _: Access<'_>) -> luma_content_store::Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err("revoked".into())
            }
        }
    }
    #[test]
    fn closed_request_selects_image_workflow_not_caller_claim() {
        let value = request();
        let intent = value.intent(&binding()).unwrap();
        assert_eq!(intent.metadata.workflow_sha256, graph_sha256());
        let mut json = serde_json::to_value(&value).unwrap();
        json["workflow_sha256"] = "a".repeat(64).into();
        assert!(serde_json::from_value::<Request>(json).is_err());
        let plan = Plan::managed_render(None, &intent).unwrap();
        assert!(Execution::verify(&value, &binding(), &plan, &mut Guard(true)).is_ok());
        assert!(Execution::verify(&value, &binding(), &plan, &mut Guard(false)).is_err());
        let mut wrong = intent.clone();
        wrong.metadata.workflow_sha256 = "a".repeat(64);
        let forged = Plan::managed_render(None, &wrong).unwrap();
        assert!(Execution::verify(&value, &binding(), &forged, &mut Guard(true)).is_err());
    }

    #[test]
    fn actual_held_workflow_publication_and_same_state_reopen_bind_exact_checkpoint() {
        use std::os::unix::fs::DirBuilderExt;
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let root = std::env::var_os("LUMA_STORAGE_TEST_ROOT")
            .expect("workflow fixture requires private disposable ext4");
        let directory = Directory(std::path::PathBuf::from(root).join(format!(
            "luma-content-workflow-{}-{}",
            std::process::id(),
            crate::resources::random_id().unwrap()
        )));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let request = super::tests::request();
        let intent = request.intent(&binding()).unwrap();
        let source = intent.canonical_bytes().unwrap();
        let plan = Plan::managed_render(None, &intent).unwrap();
        let mut repository =
            luma_content_store::Repository::create_at(&directory.0, &plan, &mut Guard(true))
                .unwrap();
        let execution = Execution::verify(&request, &binding(), &plan, &mut Guard(true)).unwrap();
        let prepared = repository
            .prepare(&plan, &source, &mut Guard(true))
            .unwrap();
        let held = execution.bind(&prepared).unwrap();
        let wanted = prepared.commitment().outcome_state();
        let outcome = prepared.publish(&mut Guard(true)).unwrap();
        drop(repository);
        let mut reopened =
            luma_content_store::Repository::open_at(&directory.0, &binding(), &mut Guard(true))
                .unwrap();
        reopened.require_state(&wanted, &mut Guard(true)).unwrap();
        let current = reopened.verified_state(&mut Guard(true)).unwrap();
        let receipt = held.completion(&outcome, &current).unwrap();
        assert_eq!(receipt.workflow_sha256, graph_sha256());
        assert_eq!(receipt.derivation.engine, request.engine);
        let retained = reopened
            .retained(&outcome.request_id, &mut Guard(true))
            .unwrap();
        assert_eq!(retained.source, source);
        let value = serde_json::to_value(receipt).unwrap();
        assert!(value.get("workflow_executed").is_none());
        assert!(value.get("authority_returned").is_none());
        assert!(value.get("production_qualified").is_none());
        let mut wrong_request = super::tests::request();
        wrong_request.source = r#"{"schema_version":1,"title":"Other","blocks":[]}"#.into();
        assert!(Execution::verify(&wrong_request, &binding(), &plan, &mut Guard(true)).is_err());
        let execution = Execution::verify(&request, &binding(), &plan, &mut Guard(true)).unwrap();
        let prepared = reopened.prepare(&plan, &source, &mut Guard(true)).unwrap();
        let held = execution.bind(&prepared).unwrap();
        let mut wrong = outcome.clone();
        wrong.source_sha256 = "f".repeat(64);
        assert!(held.completion(&wrong, &current).is_err());
    }
}
