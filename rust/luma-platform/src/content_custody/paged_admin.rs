//! Closed global paged-custody control DATA. The broker registry's opaque
//! 128-bit job is distinct from a reviewed 256-bit bootstrap/attempt identity.
//! These types alone never open C, authenticate an Admin or dispatch NV.
use super::*;
use crate::finite_grants::{Action, Kind, Selector, Use};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Request {
    Review {},
    RecoveryReview {},
    InitialRecoveryReview {},
    RetiredReview {
        attempt_sha256: String,
    },
    Begin {
        stable_review_sha256: String,
        expected_window_sha256: String,
    },
    Step {
        stable_review_sha256: String,
        expected_window_sha256: String,
        expected_selected_descriptor_sha256: String,
    },
    Resume {
        attempt_sha256: String,
        stable_review_sha256: String,
        expected_window_sha256: String,
    },
    RetireInitial {
        attempt_sha256: String,
        stable_review_sha256: String,
        expected_window_sha256: String,
    },
    Reconcile {
        attempt_sha256: String,
        stable_review_sha256: String,
        expected_window_sha256: String,
        expected_selected_descriptor_sha256: String,
    },
}

/// Descriptive, privately constructed original-control source. Only the fixed
/// protocol's authenticated original Admin context supplies live authority.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Source {
    pub(super) stable_review_sha256: String,
    pub(super) expected_window_sha256: String,
    pub(super) expected_selected_descriptor_sha256: Option<String>,
    pub(super) attempt_sha256: Option<String>,
}
impl Source {
    pub(super) fn validate(&self) -> Result<()> {
        digest(&self.stable_review_sha256)?;
        digest(&self.expected_window_sha256)?;
        if let Some(value) = &self.expected_selected_descriptor_sha256 {
            digest(value)?;
        }
        if let Some(value) = &self.attempt_sha256 {
            digest(value)?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn software_fixture(
        stable: &str,
        window: &str,
        selected: Option<&str>,
        attempt: Option<&str>,
    ) -> Self {
        let value = Self {
            stable_review_sha256: stable.into(),
            expected_window_sha256: window.into(),
            expected_selected_descriptor_sha256: selected.map(str::to_owned),
            attempt_sha256: attempt.map(str::to_owned),
        };
        value
            .validate()
            .expect("explicit software control DATA must be canonical");
        value
    }
}
fn scope(action: Action, selector: &str, sha: &str) -> Result<Use> {
    digest(sha)?;
    let usage = Use {
        action,
        selector: Selector {
            kind: if action == Action::Read {
                Kind::File
            } else {
                Kind::Resource
            },
            id: selector.into(),
            generation: 1,
            digest: sha.into(),
        },
        input_bytes: 0,
        output_bytes: 8192,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
impl Request {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = canonical(bytes, 2048)?;
        value.original_source()?;
        Ok(value)
    }
    pub(super) fn command(&self) -> &'static str {
        match self {
            Self::Review {}
            | Self::RecoveryReview {}
            | Self::InitialRecoveryReview {}
            | Self::RetiredReview { .. } => "content-custody-paged-review",
            Self::Begin { .. } | Self::Step { .. } | Self::Resume { .. } => {
                "content-custody-paged-bootstrap"
            }
            Self::RetireInitial { .. } | Self::Reconcile { .. } => {
                "content-custody-paged-reconcile"
            }
        }
    }
    pub(super) fn original_source(&self) -> Result<Option<Source>> {
        let (stable, window, selected, attempt) = match self {
            Self::Review {} | Self::RecoveryReview {} | Self::InitialRecoveryReview {} => {
                return Ok(None)
            }
            Self::RetiredReview { attempt_sha256 } => {
                digest(attempt_sha256)?;
                return Ok(None);
            }
            Self::Begin {
                stable_review_sha256,
                expected_window_sha256,
            } => (stable_review_sha256, expected_window_sha256, None, None),
            Self::Step {
                stable_review_sha256,
                expected_window_sha256,
                expected_selected_descriptor_sha256,
            } => (
                stable_review_sha256,
                expected_window_sha256,
                Some(expected_selected_descriptor_sha256.clone()),
                None,
            ),
            Self::Reconcile {
                stable_review_sha256,
                expected_window_sha256,
                expected_selected_descriptor_sha256,
                attempt_sha256,
            } => (
                stable_review_sha256,
                expected_window_sha256,
                Some(expected_selected_descriptor_sha256.clone()),
                Some(attempt_sha256.clone()),
            ),
            Self::Resume {
                stable_review_sha256,
                expected_window_sha256,
                attempt_sha256,
            }
            | Self::RetireInitial {
                stable_review_sha256,
                expected_window_sha256,
                attempt_sha256,
            } => (
                stable_review_sha256,
                expected_window_sha256,
                None,
                Some(attempt_sha256.clone()),
            ),
        };
        let source = Source {
            stable_review_sha256: stable.clone(),
            expected_window_sha256: window.clone(),
            expected_selected_descriptor_sha256: selected,
            attempt_sha256: attempt,
        };
        source.validate()?;
        Ok(Some(source))
    }
    pub(super) fn usage(&self, installation: &str) -> Result<Use> {
        digest(installation)?;
        let source = self.original_source()?;
        match source {
            None => scope(
                Action::Read,
                "content-custody-paged-read-v3",
                &hash(&serde_json::to_vec(&(
                    "luma-paged-c-original-admin-inspection-v3",
                    installation,
                    self,
                ))?),
            ),
            Some(source) => scope(
                if self.command() == "content-custody-paged-bootstrap" {
                    Action::ProvisionResource
                } else {
                    Action::RecoverResource
                },
                if self.command() == "content-custody-paged-bootstrap" {
                    "content-custody-paged-bootstrap-v3"
                } else {
                    "content-custody-paged-reconcile-v3"
                },
                &source.expected_window_sha256,
            ),
        }
    }
    pub(super) fn validate_original(
        &self,
        command: &str,
        usage: &Use,
        installation: &str,
    ) -> Result<()> {
        if command != self.command() || *usage != self.usage(installation)? {
            return Err(
                "paged Admin payload differs from its exact original finite control scope".into(),
            );
        }
        Ok(())
    }
    pub(super) fn execute(
        &self,
        installation: &str,
        authority: &mut protocol::OriginalCAdminOperation<'_>,
    ) -> Result<serde_json::Value> {
        authority.check()?;
        self.validate_original(
            &authority.source_binding().command,
            &authority.audit().usage,
            installation,
        )?;
        if authority.source_binding().installation != installation
            || authority.source_binding().paged_control != self.original_source()?
            || authority.audit().operation_id.is_none()
        {
            return Err(
                "paged control differs from the authenticated original Admin request".into(),
            );
        }
        // Prove the actual separately sealed local installation, not a request
        // string or a newly generated namespace. Drop its serialization lock
        // before the closed operation reopens and retains its own real anchor.
        let anchor = super::super::ContentAnchor::installed()?;
        if anchor.installation() != installation {
            return Err("paged Admin targets a foreign sealed installation".into());
        }
        drop(anchor);
        authority.check()?;
        use super::v2_publication::{self as paged, PagedStore};
        let value = match self {
            Self::Review {} => match format::probe(&Files::installed(), &mut || authority.check())?
            {
                format::Layout::Legacy => {
                    let mut store = Store::installed(&mut || authority.check())?;
                    paged::legacy_bootstrap_review(&mut store, &mut || authority.check())?
                }
                format::Layout::Paged => PagedStore::installed(&mut || authority.check())?
                    .maintenance_review(&mut || authority.check())?,
            },
            Self::RecoveryReview {} => {
                PagedStore::pending_recovery_review(&mut || authority.check())?
            }
            Self::InitialRecoveryReview {} => {
                paged::initial_recovery_review(&mut || authority.check())?
            }
            Self::RetiredReview { attempt_sha256 } => {
                paged::retired_bootstrap_review(attempt_sha256, &mut || authority.check())?
            }
            Self::Begin {
                expected_window_sha256,
                ..
            } => {
                let store = Store::installed(&mut || authority.check())?;
                let mut store = paged::begin_bootstrap(store, expected_window_sha256, authority)?;
                store.maintenance_review(&mut || authority.check())?
            }
            Self::Step {
                expected_window_sha256,
                ..
            } => {
                let mut store = PagedStore::installed(&mut || authority.check())?;
                store.bootstrap_window(expected_window_sha256, authority)?
            }
            Self::Resume {
                attempt_sha256,
                expected_window_sha256,
                ..
            } => {
                let mut store = paged::resume_retired_bootstrap(
                    attempt_sha256,
                    expected_window_sha256,
                    authority,
                )?;
                store.maintenance_review(&mut || authority.check())?
            }
            Self::RetireInitial {
                expected_window_sha256,
                ..
            } => {
                let mut retired =
                    paged::retire_initial_bootstrap(expected_window_sha256, authority)?;
                retired.review(&mut || authority.check())?
            }
            Self::Reconcile {
                expected_window_sha256,
                ..
            } => {
                let mut store = PagedStore::reconcile_pending(expected_window_sha256, authority)?;
                store.maintenance_review(&mut || authority.check())?
            }
        };
        authority.check()?;
        if serde_json::to_vec(&value)?.len() > 7168 {
            return Err(
                "paged Admin result exceeds its original finite response reservation".into(),
            );
        }
        Ok(value)
    }
}

/// Checks actual original executable arguments read by the broker from procfs.
/// The bounded canonical control bytes are present in that same original argv;
/// no mutable input pathname or worker-returned payload supplies this binding.
pub(crate) fn original_arguments(
    args: &[&str],
    command: &str,
    usage: &Use,
    audit: Option<&Audit>,
) -> Result<()> {
    original_arguments_at(
        args,
        command,
        usage,
        audit,
        &crate::artifacts::installation()?,
    )
}

fn original_arguments_at(
    args: &[&str],
    command: &str,
    usage: &Use,
    audit: Option<&Audit>,
    installation: &str,
) -> Result<()> {
    if args.len() != 6
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != command
        || !matches!(
            command,
            "content-custody-paged-review"
                | "content-custody-paged-bootstrap"
                | "content-custody-paged-reconcile"
        )
        || args[2].is_empty()
        || args[2].len() > 32
        || !crate::admin_roles::identifier(args[3])
        || args[5] != ""
        || audit.is_some_and(|value| value.grant_id != args[3] || value.usage != *usage)
    {
        return Err("paged Admin proof requires its exact original canonical command".into());
    }
    let request = Request::parse(args[4].as_bytes())?;
    request.validate_original(command, usage, installation)
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let name = args
        .first()
        .map(String::as_str)
        .ok_or("paged custody command missing")?;
    let proposal = name == "content-custody-paged-proposal";
    if args.len() != if proposal { 3 } else { 4 }
        || (!proposal
            && !matches!(
                name,
                "content-custody-paged-review"
                    | "content-custody-paged-bootstrap"
                    | "content-custody-paged-reconcile"
            ))
    {
        return Err("expected content-custody-paged-proposal LOGIN CANONICAL-CONTROL-JSON | content-custody-paged-{review|bootstrap|reconcile} LOGIN GRANT CANONICAL-CONTROL-JSON".into());
    }
    let request = Request::parse(args.last().ok_or("paged control JSON missing")?.as_bytes())?;
    let installation = crate::artifacts::installation()?;
    let usage = request.usage(&installation)?;
    if !proposal && name != request.command() {
        return Err("paged control operation differs from original command".into());
    }
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":3,"command":request.command(),"control":request,"usage":usage,
            "private_authority_read":false,"filesystem_changed":false,"authority_returned":false})
        );
        return Ok(());
    }
    let value = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        boundary.require_admin()?;
        let pending = if usage.action == Action::Read {
            None
        } else {
            Some(boundary.effect_begin(
                &usage.selector.digest,
                if usage.action == Action::RecoverResource {
                    crate::policy_decisions::EffectKind::Recovery
                } else {
                    crate::policy_decisions::EffectKind::Checkpoint
                },
            )?)
        };
        let value = crate::service::content_admin::run(
            request.command(),
            &usage,
            boundary,
            |job, cancel| {
                protocol::admin_paged_exchange(&usage, &installation, &job, request.clone(), cancel)
            },
        )?;
        boundary.require_admin()?;
        if let Some(pending) = pending {
            boundary.effect_complete(pending, &hash(&serde_json::to_vec(&value)?))?;
        }
        boundary.require_admin()?;
        Ok(value)
    })?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_control_arguments_bind_the_exact_command_and_canonical_payload() {
        let installation = "79".repeat(32);
        let request = Request::Step {
            stable_review_sha256: "24".repeat(32),
            expected_window_sha256: "35".repeat(32),
            expected_selected_descriptor_sha256: "46".repeat(32),
        };
        let bytes = serde_json::to_string(&request).unwrap();
        let usage = request.usage(&installation).unwrap();
        let grant = "grant-paged-control";
        let args = [
            "/usr/libexec/luma-os/luma-platform",
            request.command(),
            "Admin",
            grant,
            &bytes,
            "",
        ];
        original_arguments_at(&args, request.command(), &usage, None, &installation).unwrap();
        for (position, value) in [
            (0, "/tmp/luma-platform"),
            (1, "content-custody-paged-review"),
            (2, ""),
            (3, "invalid/grant"),
            (4, usage.selector.digest.as_str()),
            (5, "extra"),
        ] {
            let mut changed = args;
            changed[position] = value;
            assert!(original_arguments_at(
                &changed,
                request.command(),
                &usage,
                None,
                &installation
            )
            .is_err());
        }
        for end in 0..args.len() {
            assert!(original_arguments_at(
                &args[..end],
                request.command(),
                &usage,
                None,
                &installation
            )
            .is_err());
        }
        let pretty = serde_json::to_string_pretty(&request).unwrap();
        let mut changed = args;
        changed[4] = &pretty;
        assert!(
            original_arguments_at(&changed, request.command(), &usage, None, &installation)
                .is_err()
        );
        let mut changed_usage = usage.clone();
        changed_usage.selector.digest = "57".repeat(32);
        assert!(original_arguments_at(
            &args,
            request.command(),
            &changed_usage,
            None,
            &installation
        )
        .is_err());
    }
    #[test]
    fn read_control_arguments_bind_full_request_and_local_installation() {
        let installation = "79".repeat(32);
        let request = Request::Review {};
        let bytes = serde_json::to_string(&request).unwrap();
        let usage = request.usage(&installation).unwrap();
        let grant = "grant-paged-control";
        let args = [
            "/usr/libexec/luma-os/luma-platform",
            request.command(),
            "Admin",
            grant,
            &bytes,
            "",
        ];
        original_arguments_at(&args, request.command(), &usage, None, &installation).unwrap();
        assert!(
            original_arguments_at(&args, request.command(), &usage, None, &"8a".repeat(32))
                .is_err()
        );
        let other = serde_json::to_string(&Request::RecoveryReview {}).unwrap();
        let mut changed = args;
        changed[4] = &other;
        assert!(
            original_arguments_at(&changed, request.command(), &usage, None, &installation)
                .is_err()
        );
    }
    #[test]
    fn opaque_registry_job_and_stable_control_digest_have_distinct_closed_widths() {
        let job = "13".repeat(16);
        let stable = "24".repeat(32);
        assert!(tpm::decode::<16>(&job).is_ok());
        assert!(tpm::decode::<16>(&stable).is_err());
        let request = Request::Begin {
            stable_review_sha256: stable.clone(),
            expected_window_sha256: "35".repeat(32),
        };
        let source = request.original_source().unwrap().unwrap();
        assert_eq!(source.stable_review_sha256, stable);
        assert_ne!(source.stable_review_sha256, job);
        assert!(source.expected_selected_descriptor_sha256.is_none());
        assert!(source.attempt_sha256.is_none());
    }
    #[test]
    fn continuation_and_initial_recovery_carry_exact_distinct_source_contexts() {
        let step = Request::Step {
            stable_review_sha256: "24".repeat(32),
            expected_window_sha256: "35".repeat(32),
            expected_selected_descriptor_sha256: "46".repeat(32),
        };
        let source = step.original_source().unwrap().unwrap();
        assert_eq!(
            source.expected_selected_descriptor_sha256,
            Some("46".repeat(32))
        );
        assert!(source.attempt_sha256.is_none());
        let retirement = Request::RetireInitial {
            stable_review_sha256: "24".repeat(32),
            expected_window_sha256: "57".repeat(32),
            attempt_sha256: "68".repeat(32),
        };
        let source = retirement.original_source().unwrap().unwrap();
        assert_eq!(source.attempt_sha256, Some("68".repeat(32)));
        assert!(source.expected_selected_descriptor_sha256.is_none());
        assert_ne!(
            step.usage(&"79".repeat(32)).unwrap().action,
            retirement.usage(&"79".repeat(32)).unwrap().action
        );
    }
    #[test]
    fn inspection_and_effects_are_exact_finite_scopes_not_generic_admin_flags() {
        let installation = "79".repeat(32);
        for request in [
            Request::Review {},
            Request::RecoveryReview {},
            Request::RetiredReview {
                attempt_sha256: "68".repeat(32),
            },
            Request::Begin {
                stable_review_sha256: "24".repeat(32),
                expected_window_sha256: "35".repeat(32),
            },
        ] {
            let usage = request.usage(&installation).unwrap();
            request
                .validate_original(request.command(), &usage, &installation)
                .unwrap();
            for mutate in 0..5 {
                let mut changed = usage.clone();
                match mutate {
                    0 => changed.selector.generation += 1,
                    1 => changed.output_bytes -= 1,
                    2 => changed.input_bytes = 1,
                    3 => changed.units += 1,
                    _ => changed.selector.digest = "8a".repeat(32),
                }
                assert!(request
                    .validate_original(request.command(), &changed, &installation)
                    .is_err());
            }
            assert!(request
                .validate_original("content-unrecognized", &usage, &installation)
                .is_err());
        }
        assert_ne!(
            Request::Review {}.usage(&installation).unwrap(),
            Request::RecoveryReview {}.usage(&installation).unwrap()
        );
    }
    #[test]
    fn invalid_or_unknown_control_data_cannot_become_an_original_source() {
        assert!(Request::Begin {
            stable_review_sha256: "0".repeat(64),
            expected_window_sha256: "35".repeat(32)
        }
        .original_source()
        .is_err());
        assert!(Request::RetiredReview {
            attempt_sha256: "13".repeat(16)
        }
        .usage(&"79".repeat(32))
        .is_err());
        assert!(
            serde_json::from_str::<Request>(r#"{"operation":"review","selected":true}"#).is_err()
        );
        assert!(serde_json::from_str::<Request>(
            r#"{"operation":"step","stable_review_sha256":"a","expected_window_sha256":"b"}"#
        )
        .is_err());
    }
}
