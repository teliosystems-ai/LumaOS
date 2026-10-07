//! Finite, versioned governance catalog. Definitions are never assignments,
//! authentication observations, capabilities, signing custody or effect grants.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ACTIVITIES: usize = 128;
const MAX_ROLES: usize = 128;
pub(crate) const CONTROL: [&str; 4] = [
    "admin.activity.register",
    "admin.role.define",
    "admin.role.assign",
    "admin.role.revoke",
];

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Command {
    RegisterActivity {
        activity: String,
    },
    DefineRole {
        name: String,
        activities: Vec<String>,
        expected_version: u64,
    },
    AdoptPrincipals {
        registry: crate::principal::Registry,
    },
    AdvancePrincipal {
        principal: String,
        expected_generation: u64,
        enabled: bool,
    },
}

impl Command {
    pub(crate) fn activity(&self) -> &'static str {
        match self {
            Self::RegisterActivity { .. } => "admin.activity.register",
            Self::DefineRole { .. } => "admin.role.define",
            Self::AdoptPrincipals { .. } => "admin.principal.adopt",
            Self::AdvancePrincipal { .. } => "admin.principal.advance",
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let valid_activity = |v: &str| identifier(v) && v != "admin.bootstrap";
        match self {
            Self::AdoptPrincipals { registry } => registry.validate(),
            Self::AdvancePrincipal {
                principal,
                expected_generation,
                ..
            } => {
                crate::tpm::decode::<32>(principal)?;
                if *expected_generation == 0 {
                    return Err("principal generation must be nonzero".into());
                }
                Ok(())
            }
            Self::RegisterActivity { activity } if valid_activity(activity) => Ok(()),
            Self::DefineRole {
                name, activities, ..
            } if identifier(name)
                && name != "Admin"
                && !activities.is_empty()
                && activities.len() <= 64
                && activities.iter().all(|v| valid_activity(v))
                && activities.windows(2).all(|pair| pair[0] < pair[1]) =>
            {
                Ok(())
            }
            _ => {
                Err("invalid finite Admin catalog command; no wildcards or root delegation".into())
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Role {
    pub name: String,
    pub activities: Vec<String>,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Catalog {
    pub state_version: u64,
    pub activities: BTreeSet<String>,
    pub roles: BTreeMap<String, Role>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_registry: Option<crate::principal::Registry>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub principal_states: BTreeMap<String, PrincipalState>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct PrincipalState {
    pub generation: u64,
    pub enabled: bool,
}

impl Catalog {
    pub(crate) fn initial() -> Self {
        Self {
            state_version: 1,
            activities: CONTROL.iter().map(|v| (*v).into()).collect(),
            roles: BTreeMap::new(),
            principal_registry: None,
            principal_states: BTreeMap::new(),
        }
    }

    /// The owning adapter must independently authenticate Admin, bind the
    /// semantic bytes into the checkpoint and revalidate at the write boundary.
    pub(crate) fn apply(&mut self, command: &Command) -> Result<bool> {
        command.validate()?;
        let next_state = self
            .state_version
            .checked_add(1)
            .ok_or("Admin catalog version exhausted")?;
        match command {
            Command::AdvancePrincipal {
                principal,
                expected_generation,
                enabled,
            } => {
                let record = self
                    .principal_registry
                    .as_ref()
                    .ok_or("explicit principal adoption required")?
                    .principal(principal)
                    .ok_or("unknown adopted principal")?;
                if record.uid == 1001 || !record.enabled {
                    return Err("bootstrap Admin or initially disabled account requires separate governed custody recovery".into());
                }
                let generation = self
                    .principal_states
                    .get(principal)
                    .map_or(record.generation, |state| state.generation);
                if generation != *expected_generation {
                    return Err("governed principal generation conflict".into());
                }
                let next = generation
                    .checked_add(1)
                    .ok_or("principal generation exhausted")?;
                self.principal_states.insert(
                    principal.clone(),
                    PrincipalState {
                        generation: next,
                        enabled: *enabled,
                    },
                );
            }
            Command::AdoptPrincipals { registry } => {
                if let Some(anchored) = &self.principal_registry {
                    if anchored == registry {
                        return Ok(false);
                    }
                    return Err("principal authority already adopted; a new snapshot cannot replace governed generations".into());
                }
                self.principal_registry = Some(registry.clone());
            }
            Command::RegisterActivity { activity } => {
                if self.activities.contains(activity) {
                    return Ok(false);
                }
                if self.activities.len() >= MAX_ACTIVITIES {
                    return Err("Admin activity catalog capacity exhausted".into());
                }
                self.activities.insert(activity.clone());
            }
            Command::DefineRole {
                name,
                activities,
                expected_version,
            } => {
                if activities.iter().any(|v| !self.activities.contains(v)) {
                    return Err("role names an unregistered activity".into());
                }
                let current = self.roles.get(name);
                if current.map_or(0, |role| role.version) != *expected_version {
                    return Err("Admin role version conflict".into());
                }
                if current.is_some_and(|role| &role.activities == activities) {
                    return Ok(false);
                }
                if current.is_none() && self.roles.len() >= MAX_ROLES {
                    return Err("Admin role catalog capacity exhausted".into());
                }
                let version = expected_version
                    .checked_add(1)
                    .ok_or("Admin role version exhausted")?;
                self.roles.insert(
                    name.clone(),
                    Role {
                        name: name.clone(),
                        activities: activities.clone(),
                        version,
                    },
                );
            }
        }
        self.state_version = next_state;
        Ok(true)
    }

    /// Resolve an inert local identity against adopted history. This is not
    /// authentication; the owning session separately requires live genuine PAM.
    pub(crate) fn resolve_principal(&self, local: &serde_json::Value) -> Result<serde_json::Value> {
        let registry = self
            .principal_registry
            .as_ref()
            .ok_or("explicit principal adoption required")?;
        let name = local["login"]
            .as_str()
            .ok_or("missing local principal login")?;
        let record = registry.account(name).ok_or("unknown adopted account")?;
        if !record.enabled || registry.identity(record) != *local {
            return Err("local identity does not match adopted installation baseline".into());
        }
        let mut current = record.clone();
        if let Some(state) = self.principal_states.get(&record.id) {
            current.generation = state.generation;
            current.enabled = state.enabled;
        }
        if !current.enabled {
            return Err("governed principal is disabled".into());
        }
        Ok(registry.identity(&current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn register(v: &str) -> Command {
        Command::RegisterActivity { activity: v.into() }
    }
    fn role(version: u64, values: &[&str]) -> Command {
        Command::DefineRole {
            name: "Operator".into(),
            activities: values.iter().map(|v| (*v).into()).collect(),
            expected_version: version,
        }
    }
    #[test]
    fn versioned_role_snapshot_and_explicit_compare_exchange() {
        let mut catalog = Catalog::initial();
        assert!(catalog.apply(&register("model.select")).unwrap());
        assert!(catalog.apply(&role(0, &["model.select"])).unwrap());
        assert_eq!(catalog.roles["Operator"].version, 1);
        assert!(catalog.apply(&role(0, &["model.select"])).is_err());
        assert!(catalog
            .apply(&role(1, &["admin.role.define", "model.select"]))
            .unwrap());
        assert_eq!(catalog.roles["Operator"].version, 2);
        assert_eq!(catalog.state_version, 4);
    }
    #[test]
    fn principal_adoption_is_explicit_immutable_and_preserves_legacy_serialization() {
        let mut catalog = Catalog::initial();
        assert!(serde_json::to_value(&catalog)
            .unwrap()
            .get("principal_registry")
            .is_none());
        let registry = serde_json::json!({"schema_version":1,"installation":"ab".repeat(32),
            "principals":[{"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true}]});
        let command = Command::AdoptPrincipals {
            registry: serde_json::from_value(registry.clone()).unwrap(),
        };
        assert!(catalog.apply(&command).unwrap());
        assert_eq!(catalog.state_version, 2);
        assert!(!catalog.apply(&command).unwrap());
        let before = catalog.clone();
        for invalid in [false, true] {
            let mut changed = registry.clone();
            changed["principals"][0]["generation"] = serde_json::json!(if invalid { 0 } else { 2 });
            let command = Command::AdoptPrincipals {
                registry: serde_json::from_value(changed).unwrap(),
            };
            assert!(catalog.apply(&command).is_err());
            assert_eq!(catalog, before);
        }
    }

    #[test]
    fn governed_generations_disable_reenable_and_rotate_without_editing_baseline() {
        let mut catalog = Catalog::initial();
        let registry = serde_json::json!({"schema_version":1,"installation":"ab".repeat(32),
            "principals":[{"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true},
            {"id":"ef".repeat(32),"generation":1,"login":"other","uid":1002,"enabled":true}]});
        catalog
            .apply(&Command::AdoptPrincipals {
                registry: serde_json::from_value(registry.clone()).unwrap(),
            })
            .unwrap();
        let local = serde_json::json!({"installation":"ab".repeat(32),"principal":"ef".repeat(32),
            "generation":1,"login":"other","uid":1002});
        assert_eq!(catalog.resolve_principal(&local).unwrap(), local);
        for (expected, enabled) in [(1, false), (2, true), (3, true)] {
            assert!(catalog
                .apply(&Command::AdvancePrincipal {
                    principal: "ef".repeat(32),
                    expected_generation: expected,
                    enabled
                })
                .unwrap());
            assert_eq!(
                catalog.principal_states[&"ef".repeat(32)].generation,
                expected + 1
            );
            if enabled {
                assert_eq!(
                    catalog.resolve_principal(&local).unwrap()["generation"],
                    expected + 1
                );
            } else {
                assert!(catalog.resolve_principal(&local).is_err());
            }
            assert_eq!(
                serde_json::to_value(&catalog.principal_registry).unwrap(),
                registry
            );
        }
        let before = catalog.clone();
        assert!(catalog
            .apply(&Command::AdvancePrincipal {
                principal: "ef".repeat(32),
                expected_generation: 1,
                enabled: true
            })
            .is_err());
        assert_eq!(catalog, before);
        let mut forged = local;
        forged["generation"] = serde_json::json!(4);
        assert!(catalog.resolve_principal(&forged).is_err());
    }

    #[test]
    fn principal_advance_refuses_unadopted_unknown_admin_malformed_and_exhausted_state_atomically()
    {
        let mut catalog = Catalog::initial();
        let advance = |id: &str, generation| Command::AdvancePrincipal {
            principal: id.into(),
            expected_generation: generation,
            enabled: false,
        };
        assert!(catalog.apply(&advance(&"ef".repeat(32), 1)).is_err());
        let registry = serde_json::json!({"schema_version":1,"installation":"ab".repeat(32),
            "principals":[{"id":"cd".repeat(32),"generation":1,"login":"human","uid":1001,"enabled":true},
            {"id":"ef".repeat(32),"generation":u64::MAX,"login":"other","uid":1002,"enabled":true},
            {"id":"aa".repeat(32),"generation":1,"login":"locked","uid":1003,"enabled":false}]});
        catalog
            .apply(&Command::AdoptPrincipals {
                registry: serde_json::from_value(registry).unwrap(),
            })
            .unwrap();
        let before = catalog.clone();
        for command in [
            advance(&"cd".repeat(32), 1),
            advance(&"bb".repeat(32), 1),
            advance("bad", 1),
            advance(&"ef".repeat(32), 0),
            advance(&"ef".repeat(32), u64::MAX),
            advance(&"aa".repeat(32), 1),
        ] {
            assert!(catalog.apply(&command).is_err());
            assert_eq!(catalog, before);
        }
        assert!(serde_json::from_value::<Command>(
            serde_json::json!({"action":"advance_principal",
            "principal":"ef".repeat(32),"expected_generation":1,"enabled":true,"force":true})
        )
        .is_err());
    }

    #[test]
    fn noops_do_not_create_versions() {
        let mut catalog = Catalog::initial();
        assert!(!catalog.apply(&register("admin.role.define")).unwrap());
        catalog.apply(&role(0, &["admin.role.define"])).unwrap();
        assert!(!catalog.apply(&role(1, &["admin.role.define"])).unwrap());
        assert_eq!(catalog.state_version, 2);
    }
    #[test]
    fn malformed_unknown_wildcard_and_root_definitions_are_atomic_refusals() {
        let initial = Catalog::initial();
        for command in [
            register("*"),
            register("admin.bootstrap"),
            register("../model"),
            role(0, &[]),
            role(0, &["unknown"]),
            role(0, &["admin.role.define", "admin.role.define"]),
            role(0, &["admin.role.define", "admin.activity.register"]),
            Command::DefineRole {
                name: "Admin".into(),
                activities: vec!["admin.role.define".into()],
                expected_version: 0,
            },
        ] {
            let mut catalog = initial.clone();
            assert!(catalog.apply(&command).is_err());
            assert_eq!(catalog, initial);
        }
        assert!(serde_json::from_str::<Command>(
            r#"{"action":"register_activity","activity":"model.select","grant":true}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Command>(r#"{"action":"assign_role","name":"Admin"}"#).is_err()
        );
    }
    #[test]
    fn bounded_catalog_never_silently_evicts_state() {
        let mut catalog = Catalog::initial();
        for index in 0..MAX_ACTIVITIES - CONTROL.len() {
            catalog.apply(&register(&format!("test.{index}"))).unwrap();
        }
        let before = catalog.clone();
        assert!(catalog.apply(&register("overflow")).is_err());
        assert_eq!(catalog, before);
        for index in 0..MAX_ROLES {
            catalog
                .apply(&Command::DefineRole {
                    name: format!("Role{index}"),
                    activities: vec!["admin.role.define".into()],
                    expected_version: 0,
                })
                .unwrap();
        }
        let before = catalog.clone();
        assert!(catalog
            .apply(&Command::DefineRole {
                name: "Overflow".into(),
                activities: vec!["admin.role.define".into()],
                expected_version: 0
            })
            .is_err());
        assert_eq!(catalog, before);
    }
}
