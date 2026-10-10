//! Finite authorization records reconstructed only by the shared TPM catalog.
//! These serialized definitions are data, never transferable capabilities.
use crate::{admin_roles::Catalog, Result};
use serde::{Deserialize, Serialize};

const MAX_VALIDITY_MS: i64 = 366 * 86_400_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Assignment {
    pub id: String,
    pub subject: String,
    pub subject_generation: u64,
    pub role: String,
    pub role_version: u64,
    pub version: u64,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Action {
    #[serde(rename = "file.read")]
    Read,
    #[serde(rename = "calculation.execute")]
    Calculate,
    #[serde(rename = "artifact.write")]
    Write,
    #[serde(rename = "workflow.execute")]
    Execute,
    #[serde(rename = "workflow.cancel")]
    Cancel,
    #[serde(rename = "workflow.resume")]
    Resume,
    #[serde(rename = "resource.retention")]
    Retain,
    #[serde(rename = "artifact.export")]
    Export,
    #[serde(rename = "artifact.delete")]
    Delete,
    #[serde(rename = "inference.execute")]
    Infer,
    #[serde(rename = "worker.start")]
    StartWorker,
    #[serde(rename = "worker.stop")]
    StopWorker,
    #[serde(rename = "resource.acquire")]
    AcquireResource,
    #[serde(rename = "resource.provision")]
    ProvisionResource,
    #[serde(rename = "resource.recover")]
    RecoverResource,
}
impl Action {
    pub(crate) fn activity(self) -> &'static str {
        match self {
            Self::Read => "file.read",
            Self::Calculate => "calculation.execute",
            Self::Write => "artifact.write",
            Self::Execute => "workflow.execute",
            Self::Cancel => "workflow.cancel",
            Self::Resume => "workflow.resume",
            Self::Retain => "resource.retention",
            Self::Export => "artifact.export",
            Self::Delete => "artifact.delete",
            Self::Infer => "inference.execute",
            Self::StartWorker => "worker.start",
            Self::StopWorker => "worker.stop",
            Self::AcquireResource => "resource.acquire",
            Self::ProvisionResource => "resource.provision",
            Self::RecoverResource => "resource.recover",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    File,
    Calculation,
    Artifact,
    Workflow,
    Model,
    Worker,
    Resource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selector {
    pub kind: Kind,
    pub id: String,
    pub generation: u64,
    pub digest: String,
}
impl Selector {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::admin_roles::identifier(&self.id) || self.generation == 0 {
            return Err("finite selector requires exact identity and nonzero generation".into());
        }
        if crate::tpm::decode::<32>(&self.digest)? == [0; 32] {
            return Err("finite selector requires a nonzero protected target digest".into());
        }
        Ok(())
    }
    fn permits(&self, action: Action) -> bool {
        matches!(
            (self.kind, action),
            (Kind::File, Action::Read)
                | (Kind::Calculation, Action::Calculate)
                | (
                    Kind::Artifact,
                    Action::Write | Action::Export | Action::Delete | Action::Retain
                )
                | (
                    Kind::Workflow,
                    Action::Execute | Action::Cancel | Action::Resume
                )
                | (Kind::Model, Action::Infer)
                | (Kind::Worker, Action::StartWorker | Action::StopWorker)
                | (Kind::Resource, Action::AcquireResource | Action::Retain | Action::ProvisionResource | Action::RecoverResource)
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Constraints {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_units: u64,
}
impl Constraints {
    fn validate(&self) -> Result<()> {
        if self.max_input_bytes > 1_073_741_824
            || self.max_output_bytes > 1_073_741_824
            || self.max_units == 0
            || self.max_units > 1_000_000
        {
            return Err("finite grant constraints exceed product bounds".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub id: String,
    pub assignment: String,
    pub assignment_version: u64,
    pub subject: String,
    pub subject_generation: u64,
    pub action: Action,
    pub selector: Selector,
    pub constraints: Constraints,
    pub version: u64,
    pub not_before_ms: i64,
    pub expires_ms: i64,
    pub revoked: bool,
}

fn validity(not_before_ms: i64, expires_ms: i64) -> Result<()> {
    if not_before_ms <= 0
        || expires_ms > 4_102_444_800_000
        || expires_ms
            .checked_sub(not_before_ms)
            .filter(|v| *v > 0 && *v <= MAX_VALIDITY_MS)
            .is_none()
    {
        return Err("grant and assignment validity must be finite and bounded".into());
    }
    Ok(())
}

fn subject(catalog: &Catalog, principal: &str, generation: u64) -> Result<()> {
    let record = catalog
        .registry()?
        .principal(principal)
        .ok_or("unknown grant subject")?;
    let current = catalog.principal_states.get(principal);
    if !record.enabled
        || current.is_some_and(|v| !v.enabled)
        || current.map_or(record.generation, |v| v.generation) != generation
        || catalog.deleted_principals.contains(principal)
        || catalog.needs_password_aging.contains(principal)
        || !catalog.account_commitments.contains_key(principal)
    {
        return Err(
            "grant subject is disabled, stale, uncheckpointed or awaiting activation".into(),
        );
    }
    Ok(())
}

impl Assignment {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::tpm::decode::<32>(&self.subject)?;
        validity(self.not_before_ms, self.expires_ms)?;
        if !crate::admin_roles::identifier(&self.id)
            || !crate::admin_roles::identifier(&self.role)
            || self.role == "Admin"
            || self.subject_generation == 0
            || self.role_version == 0
            || self.version != 1
            || self.revoked
        {
            return Err("invalid finite role assignment; Admin is not delegable".into());
        }
        Ok(())
    }
    pub(crate) fn current(
        &self,
        catalog: &Catalog,
        interval: crate::utc_bounds::Interval,
    ) -> Result<()> {
        subject(catalog, &self.subject, self.subject_generation)?;
        let role = catalog
            .roles
            .get(&self.role)
            .ok_or("assigned role no longer exists")?;
        if catalog.assignments.get(&self.id) != Some(self)
            || self.revoked
            || role.version != self.role_version
            || !interval.within(self.not_before_ms, self.expires_ms)?
        {
            return Err("role assignment revoked, superseded or outside full UTC interval".into());
        }
        Ok(())
    }
}

impl Grant {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::tpm::decode::<32>(&self.subject)?;
        validity(self.not_before_ms, self.expires_ms)?;
        self.selector.validate()?;
        self.constraints.validate()?;
        if !crate::admin_roles::identifier(&self.id)
            || !crate::admin_roles::identifier(&self.assignment)
            || self.assignment_version == 0
            || self.subject_generation == 0
            || self.version != 1
            || self.revoked
            || !self.selector.permits(self.action)
        {
            return Err("invalid exact finite capability grant".into());
        }
        Ok(())
    }
    pub(crate) fn issue(&self, catalog: &Catalog) -> Result<()> {
        self.validate()?;
        subject(catalog, &self.subject, self.subject_generation)?;
        let assignment = catalog
            .assignments
            .get(&self.assignment)
            .ok_or("grant requires checkpointed assignment")?;
        let role = catalog
            .roles
            .get(&assignment.role)
            .ok_or("grant requires registered role")?;
        if assignment.revoked
            || assignment.version != self.assignment_version
            || assignment.subject != self.subject
            || assignment.subject_generation != self.subject_generation
            || assignment.role_version != role.version
            || !role.activities.iter().any(|v| v == self.action.activity())
            || self.not_before_ms < assignment.not_before_ms
            || self.expires_ms > assignment.expires_ms
        {
            return Err("grant cannot expand role, subject, version or assignment validity".into());
        }
        Ok(())
    }
    pub(crate) fn authorize(
        &self,
        catalog: &Catalog,
        identity: &serde_json::Value,
        interval: crate::utc_bounds::Interval,
        usage: &Use,
    ) -> Result<()> {
        usage.validate()?;
        if catalog.grants.get(&self.id) != Some(self)
            || self.revoked
            || identity["principal"].as_str() != Some(&self.subject)
            || identity["generation"].as_u64() != Some(self.subject_generation)
            || self.action != usage.action
            || self.selector != usage.selector
            || usage.input_bytes > self.constraints.max_input_bytes
            || usage.output_bytes > self.constraints.max_output_bytes
            || usage.units > self.constraints.max_units
            || !interval.within(self.not_before_ms, self.expires_ms)?
        {
            return Err(
                "finite grant denied exact subject, target, operation, constraints or UTC validity"
                    .into(),
            );
        }
        let assignment = catalog
            .assignments
            .get(&self.assignment)
            .ok_or("grant assignment missing")?;
        assignment.current(catalog, interval)?;
        if assignment.version != self.assignment_version
            || assignment.subject != self.subject
            || assignment.subject_generation != self.subject_generation
            || !catalog
                .roles
                .get(&assignment.role)
                .ok_or("grant role missing")?
                .activities
                .iter()
                .any(|v| v == self.action.activity())
        {
            return Err("finite grant role or assignment changed".into());
        }
        Ok(())
    }
}

/// Effect-supplied exact current target/resource tuple, not authority itself.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Use {
    pub action: Action,
    pub selector: Selector,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub units: u64,
}

/// Historical attribution only. Parsing or retaining this record never admits
/// an operation; current PAM/catalog/UTC and the live boundary remain required.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Audit {
    pub subject: String,
    pub subject_generation: u64,
    pub grant_id: String,
    pub grant_version: u64,
    pub checkpoint_head: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub usage: Use,
}
impl Audit {
    pub(crate) fn validate(&self) -> Result<()> {
        self.usage.validate()?;
        if crate::tpm::decode::<32>(&self.subject)? == [0; 32]
            || crate::tpm::decode::<32>(&self.checkpoint_head)? == [0; 32]
            || self.subject_generation == 0
            || self.grant_version != 1
            || !crate::admin_roles::identifier(&self.grant_id)
            || self.operation_id.as_ref().is_some_and(|v| {
                v.len() != 32
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("invalid finite grant attribution record".into());
        }
        Ok(())
    }
}
impl Use {
    pub(crate) fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        if self.units == 0 || !self.selector.permits(self.action) {
            return Err("effect use does not match its finite selector".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_roles::Command;
    fn fixture() -> (Catalog, serde_json::Value, Grant, Use) {
        let registry = serde_json::from_value(serde_json::json!({"schema_version":1,
            "installation":"ab".repeat(32),"principals":[
            {"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true},
            {"id":"ef".repeat(32),"generation":1,"login":"other","uid":1002,"enabled":true}]}))
        .unwrap();
        let mut catalog = Catalog::initial();
        catalog
            .apply(&Command::AdoptPrincipals { registry })
            .unwrap();
        catalog
            .apply(&Command::CheckpointAccounts {
                commitments: std::collections::BTreeMap::from([
                    ("cd".repeat(32), "12".repeat(32)),
                    ("ef".repeat(32), "34".repeat(32)),
                ]),
            })
            .unwrap();
        catalog
            .apply(&Command::RegisterActivity {
                activity: "file.read".into(),
            })
            .unwrap();
        catalog
            .apply(&Command::DefineRole {
                name: "Reader".into(),
                activities: vec!["file.read".into()],
                expected_version: 0,
            })
            .unwrap();
        catalog
            .apply(&Command::AssignRole {
                assignment: Assignment {
                    id: "reader-one".into(),
                    subject: "ef".repeat(32),
                    subject_generation: 1,
                    role: "Reader".into(),
                    role_version: 1,
                    version: 1,
                    not_before_ms: 1000,
                    expires_ms: 10_000,
                    revoked: false,
                },
            })
            .unwrap();
        let grant = Grant {
            id: "read-one".into(),
            assignment: "reader-one".into(),
            assignment_version: 1,
            subject: "ef".repeat(32),
            subject_generation: 1,
            action: Action::Read,
            selector: Selector {
                kind: Kind::File,
                id: "invoice-1".into(),
                generation: 3,
                digest: "56".repeat(32),
            },
            constraints: Constraints {
                max_input_bytes: 1024,
                max_output_bytes: 0,
                max_units: 1,
            },
            version: 1,
            not_before_ms: 2000,
            expires_ms: 9000,
            revoked: false,
        };
        catalog
            .apply(&Command::IssueGrant {
                grant: grant.clone(),
            })
            .unwrap();
        let identity = serde_json::json!({"installation":"ab".repeat(32),"principal":"ef".repeat(32),
            "generation":1,"login":"other","uid":1002});
        let usage = Use {
            action: Action::Read,
            selector: grant.selector.clone(),
            input_bytes: 1024,
            output_bytes: 0,
            units: 1,
        };
        (catalog, identity, grant, usage)
    }
    #[test]
    fn complete_current_exact_grant_accepts_full_interval_only() {
        let (catalog, identity, grant, usage) = fixture();
        grant
            .authorize(
                &catalog,
                &identity,
                crate::utc_bounds::Interval::new(2000, 8999).unwrap(),
                &usage,
            )
            .unwrap();
        for (lower, upper) in [(1999, 2000), (8999, 9000), (9000, 9000)] {
            assert!(grant
                .authorize(
                    &catalog,
                    &identity,
                    crate::utc_bounds::Interval::new(lower, upper).unwrap(),
                    &usage
                )
                .is_err());
        }
    }
    #[test]
    fn every_selector_constraint_and_subject_is_exact() {
        let (catalog, identity, grant, usage) = fixture();
        for variant in 0..9 {
            let mut usage = usage.clone();
            let mut identity = identity.clone();
            match variant {
                0 => usage.selector.id = "different".into(),
                1 => usage.selector.generation += 1,
                2 => usage.selector.digest = "78".repeat(32),
                3 => usage.action = Action::Write,
                4 => usage.input_bytes += 1,
                5 => usage.output_bytes = 1,
                6 => usage.units = 2,
                7 => identity["principal"] = "cd".repeat(32).into(),
                8 => identity["generation"] = 2.into(),
                _ => unreachable!(),
            }
            assert!(
                grant
                    .authorize(
                        &catalog,
                        &identity,
                        crate::utc_bounds::Interval::new(3000, 3100).unwrap(),
                        &usage
                    )
                    .is_err(),
                "variant {variant}"
            );
        }
    }
    #[test]
    fn assignment_revoke_and_role_supersession_invalidate_retained_grant() {
        for revoke in [true, false] {
            let (mut catalog, identity, grant, usage) = fixture();
            if revoke {
                catalog
                    .apply(&Command::RevokeAssignment {
                        assignment: "reader-one".into(),
                        expected_version: 1,
                    })
                    .unwrap();
            } else {
                catalog
                    .apply(&Command::RegisterActivity {
                        activity: "artifact.write".into(),
                    })
                    .unwrap();
                catalog
                    .apply(&Command::DefineRole {
                        name: "Reader".into(),
                        activities: vec!["artifact.write".into(), "file.read".into()],
                        expected_version: 1,
                    })
                    .unwrap();
            }
            assert!(grant
                .authorize(
                    &catalog,
                    &identity,
                    crate::utc_bounds::Interval::new(3000, 3100).unwrap(),
                    &usage
                )
                .is_err());
        }
    }
    #[test]
    fn grant_revocation_is_versioned_and_tombstone_cannot_be_reissued() {
        let (mut catalog, identity, grant, usage) = fixture();
        catalog
            .apply(&Command::RevokeGrant {
                grant: grant.id.clone(),
                expected_version: 1,
            })
            .unwrap();
        assert_eq!(catalog.grants[&grant.id].version, 2);
        assert!(catalog.grants[&grant.id]
            .authorize(
                &catalog,
                &identity,
                crate::utc_bounds::Interval::new(3000, 3100).unwrap(),
                &usage
            )
            .is_err());
        assert!(catalog
            .apply(&Command::IssueGrant {
                grant: grant.clone()
            })
            .is_err());
        assert!(catalog
            .apply(&Command::RevokeGrant {
                grant: grant.id,
                expected_version: 2
            })
            .is_err());
    }
    #[test]
    fn principal_lock_rotation_deletion_and_unactivated_account_deny() {
        for variant in 0..4 {
            let (mut catalog, identity, grant, usage) = fixture();
            match variant {
                0 => {
                    catalog.principal_states.insert(
                        grant.subject.clone(),
                        crate::admin_roles::PrincipalState {
                            generation: 1,
                            enabled: false,
                        },
                    );
                }
                1 => {
                    catalog.principal_states.insert(
                        grant.subject.clone(),
                        crate::admin_roles::PrincipalState {
                            generation: 2,
                            enabled: true,
                        },
                    );
                }
                2 => {
                    catalog.deleted_principals.insert(grant.subject.clone());
                }
                3 => {
                    catalog.needs_password_aging.insert(grant.subject.clone());
                }
                _ => unreachable!(),
            }
            assert!(grant
                .authorize(
                    &catalog,
                    &identity,
                    crate::utc_bounds::Interval::new(3000, 3100).unwrap(),
                    &usage
                )
                .is_err());
        }
    }
    #[test]
    fn grant_cannot_expand_assignment_role_or_validity() {
        let (catalog, _, grant, _) = fixture();
        for variant in 0..6 {
            let mut grant = grant.clone();
            match variant {
                0 => grant.not_before_ms = 999,
                1 => grant.expires_ms = 10001,
                2 => grant.assignment_version = 2,
                3 => grant.subject = "cd".repeat(32),
                4 => grant.subject_generation = 2,
                5 => {
                    grant.action = Action::Write;
                    grant.selector.kind = Kind::Artifact;
                }
                _ => unreachable!(),
            }
            assert!(grant.issue(&catalog).is_err(), "variant {variant}");
        }
    }
    #[test]
    fn definitions_never_delegate_admin_or_accept_wildcards_and_unbounded_values() {
        let (catalog, _, grant, _) = fixture();
        let mut assignment = catalog.assignments["reader-one"].clone();
        assignment.role = "Admin".into();
        assert!(assignment.validate().is_err());
        for variant in 0..7 {
            let mut grant = grant.clone();
            match variant {
                0 => grant.selector.id = "*".into(),
                1 => grant.selector.digest = "00".repeat(32),
                2 => grant.selector.generation = 0,
                3 => grant.constraints.max_units = 0,
                4 => grant.constraints.max_output_bytes = u64::MAX,
                5 => grant.expires_ms = grant.not_before_ms + MAX_VALIDITY_MS + 1,
                6 => grant.revoked = true,
                _ => unreachable!(),
            }
            assert!(grant.validate().is_err());
        }
    }
    #[test]
    fn closed_wire_refuses_unknown_action_and_additional_authority_fields() {
        let (_, _, grant, _) = fixture();
        let mut value = serde_json::to_value(&grant).unwrap();
        value["root_authority"] = true.into();
        assert!(serde_json::from_value::<Grant>(value).is_err());
        let mut value = serde_json::to_value(&grant).unwrap();
        value["action"] = "process.execute".into();
        assert!(serde_json::from_value::<Grant>(value).is_err());
        let bytes = serde_json::to_vec(&grant).unwrap();
        assert_eq!(serde_json::from_slice::<Grant>(&bytes).unwrap(), grant);
    }
}
