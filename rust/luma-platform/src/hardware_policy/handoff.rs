//! Closed resource-configuration handshake data. These envelopes cannot supply
//! PAM, grants, driver commands or a replacement resource authority.
use super::{hash, Intent, Result, Worker};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose {
    Apply,
    CommittedCleanup,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub schema_version: u32,
    pub action: String,
    pub request_id: String,
    pub transaction: String,
    pub intent_sha256: String,
    #[serde(with = "crate::resources::decimal")]
    pub deadline: u64,
    pub purpose: Option<Purpose>,
}
impl Request {
    pub(crate) fn validate(&self, now: u64) -> Result<()> {
        if self.schema_version != 1
            || crate::tpm::decode::<16>(&self.request_id)? == [0; 16]
            || !crate::admin_roles::identifier(&self.transaction)
            || crate::tpm::decode::<32>(&self.intent_sha256)? == [0; 32]
            || self.deadline <= now
            || self.deadline - now > 3000
            || !matches!(
                (self.action.as_str(), self.purpose),
                ("hardware-handoff-open", Some(_)) | ("hardware-handoff-finish", None)
            )
        {
            return Err("invalid closed hardware handoff envelope".into());
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> Result<[u8; 32]> {
        crate::tpm::decode::<32>(&hash(&("luma-native-hardware-handoff-v1", self))?)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AllocationWindow {
    pub lease: crate::resources::Token,
    #[serde(with = "crate::resources::decimal")]
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    pub schema_version: u32,
    pub result: String,
    pub request_id: String,
    pub transaction: String,
    pub intent_sha256: String,
    pub manager_epoch: String,
    pub worker: Worker,
    #[serde(with = "crate::resources::decimal")]
    pub generation: u64,
    pub allocation: Option<AllocationWindow>,
}
impl Reply {
    pub(crate) fn for_intent(
        request: &Request,
        intent: &Intent,
        allocation: Option<AllocationWindow>,
    ) -> Result<Self> {
        intent.validate()?;
        if request.transaction != intent.transaction || request.intent_sha256 != hash(intent)? {
            return Err("hardware handoff request differs from the committed full intent".into());
        }
        let expected_lease = intent
            .target
            .resource
            .as_ref()
            .ok_or("global device cannot borrow a resource handoff")?
            .lease
            .as_ref();
        if allocation.as_ref().map(|value| &value.lease) != expected_lease
            || allocation.as_ref().is_some_and(|value| {
                value.deadline_ms == 0
                    || value.deadline_ms > request.deadline.saturating_add(10_000)
            })
        {
            return Err(
                "hardware handoff substitutes or renews the exact admitted allocation window"
                    .into(),
            );
        }
        Ok(Self {
            schema_version: 1,
            result: "ok".into(),
            request_id: request.request_id.clone(),
            transaction: intent.transaction.clone(),
            intent_sha256: request.intent_sha256.clone(),
            manager_epoch: intent
                .target
                .resource
                .as_ref()
                .ok_or("global device cannot borrow a resource handoff")?
                .manager_epoch
                .clone(),
            worker: intent
                .target
                .worker
                .ok_or("global device cannot borrow a worker handoff")?,
            generation: intent.target.generation,
            allocation,
        })
    }
    pub(crate) fn validate(&self, request: &Request, intent: &Intent) -> Result<()> {
        if self != &Self::for_intent(request, intent, self.allocation.clone())? {
            return Err(
                "hardware handoff reply substitutes its original transaction, worker or epoch"
                    .into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn worker_identity(worker: Worker) -> Result<String> {
    hash(&(
        "luma-native-fixed-hardware-worker-identity-v1",
        worker,
        match worker {
            Worker::Model => "/sys/fs/cgroup/lumamodel.slice",
            Worker::Acquisition => "/sys/fs/cgroup/lumaacquisition.slice",
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        let intent = super::super::tests::intent();
        Request {
            schema_version: 1,
            action: "hardware-handoff-open".into(),
            request_id: "12".repeat(16),
            transaction: intent.transaction.clone(),
            intent_sha256: hash(&intent).unwrap(),
            deadline: 4000,
            purpose: Some(Purpose::Apply),
        }
    }
    #[test]
    fn closed_handoff_metadata_is_exact_and_separate_from_a_grant_or_plan() {
        let request = request();
        request.validate(1000).unwrap();
        let intent = super::super::tests::intent();
        let reply = Reply::for_intent(&request, &intent, None).unwrap();
        reply.validate(&request, &intent).unwrap();
        for variant in 0..8 {
            let mut changed = request.clone();
            match variant {
                0 => changed.deadline = 1000,
                1 => changed.deadline = 4001,
                2 => changed.action = "resource-acquire".into(),
                3 => changed.purpose = None,
                4 => changed.request_id = "00".repeat(16),
                5 => changed.transaction = "../../other".into(),
                6 => changed.intent_sha256 = "00".repeat(32),
                _ => changed.schema_version = 2,
            }
            assert!(changed.validate(1000).is_err());
        }
        assert_ne!(request.binding().unwrap(), {
            let mut changed = request.clone();
            changed.request_id = "34".repeat(16);
            changed.binding().unwrap()
        });
        assert_ne!(request.intent_sha256, intent.digest().unwrap());
    }
    #[test]
    fn reply_does_not_substitute_current_manager_or_device_generations() {
        let request = request();
        let intent = super::super::tests::intent();
        let reply = Reply::for_intent(&request, &intent, None).unwrap();
        for variant in 0..6 {
            let mut changed = reply.clone();
            match variant {
                0 => changed.manager_epoch = "ab".repeat(16),
                1 => changed.worker = Worker::Acquisition,
                2 => changed.generation += 1,
                3 => changed.intent_sha256 = intent.digest().unwrap(),
                4 => changed.request_id = "34".repeat(16),
                _ => changed.result = "pending".into(),
            }
            assert!(changed.validate(&request, &intent).is_err());
        }
    }
}
