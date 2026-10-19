//! Native Linux platform boundary. No model-provided command or shell execution.
mod account_creation;
mod account_deletion;
mod account_password;
mod account_transition;
mod acquisition;
mod admin_credentials;
mod admin_enrollment;
mod admin_governance;
mod admin_journal;
mod admin_recovery;
mod admin_roles;
mod admin_service;
mod artifact_catalog;
mod artifacts;
mod authentication;
mod backup_crypto;
mod broker_effects;
mod bundle;
mod calculation;
mod content_backup;
mod content_checkpoint;
mod content_contract;
mod content_governed;
mod content_restore;
mod content_workflow;
mod credential_observer;
mod disk;
mod finite_grants;
mod generated_runtime;
mod hosted_windows;
mod model;
mod model_qualification;
mod model_trust;
mod office_adapter;
mod office_export;
mod owner_credential;
mod platform;
mod policy_decisions;
mod principal;
#[cfg(test)]
mod publication_fixture;
mod receipt_signer;
mod recovery_export;
mod release_trust;
mod resource_checkpoint;
mod resource_manager;
mod resources;
mod scoped_read;
mod sealed_credential;
mod service;
mod skill_trust;
mod skills;
mod sqlite;
mod staging;
mod storage_io;
mod tpm;
mod utc_bounds;
mod utc_history;
mod utc_keeper;
mod utc_policy;
mod utc_protocol;
mod utc_receiver;
mod utc_runtime;
mod utc_step_watch;
mod utc_stream;
mod utc_windows;
mod utc_windows_checkpoint;
mod utc_windows_crypto;
pub(crate) use utc_stream::provider as utc_provider;
mod workflow;
mod workflow_inputs;
mod workflow_resource;
mod workflow_runs;

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("this operation requires a local administrator".into());
    }
    protect_memory()
}

fn protect_memory() -> Result<()> {
    // Privileged operations may hold passphrases; never permit core dumps.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err("cannot protect privileged process memory".into());
    }
    Ok(())
}

fn inference_input(path: &str) -> Result<Vec<resource_manager::requests::gateway::ChatMessage>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > 16_384 {
        return Err(
            "inference input must be bounded regular JSON, not an authorization record".into(),
        );
    }
    let key = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let mut bytes = Vec::new();
    (&mut file).take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || key(&before) != key(&file.metadata()?)
        || key(&before) != key(&std::fs::symlink_metadata(path)?)
    {
        return Err("inference input changed while being captured".into());
    }
    let messages: Vec<resource_manager::requests::gateway::ChatMessage> =
        serde_json::from_slice(&bytes)?;
    resource_manager::requests::gateway::messages_valid(&messages)?;
    Ok(messages)
}

fn main() {
    // Set once before library initialization or worker threads. TPM library
    // trace logging must never be enabled by an inherited shell environment;
    // our adapter reports numeric failure codes without authorization bytes.
    std::env::set_var("TSS2_LOG", "all+NONE");
    if let Err(error) = dispatch() {
        eprintln!("luma-platform: {error}");
        std::process::exit(1);
    }
}

fn dispatch() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    service::granted_gateway::capture_export_channel(&mut args)?;
    let confined_client = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_default()
        .trim()
        == "luma-granted-client (enforce)";
    if confined_client
        && !matches!(
            args.first().map(String::as_str),
            Some(
                "granted-infer"
                    | "granted-infer-review"
                    | "generated-review"
                    | "generated-execute"
                    | "model-pack-import-review"
                    | "model-pack-import"
                    | "model-pack-pending-review"
                    | "model-pack-pending-retain"
                    | "model-qualification-review"
                    | "model-qualification-install"
                    | "model-qualification-observe"
                    | "model-qualification-pending-review"
                    | "model-qualification-pending-retain"
                    | "model-activate-review"
                    | "model-activate"
                    | "model-qa-review"
                    | "model-qa-run"
                    | "workflow-governed-review"
                    | "workflow-governed-prepare"
                    | "workflow-governed-advance"
                    | "workflow-governed-cancel"
                    | "workflow-governed-reconcile"
                    | "artifact-governed-export-review"
                    | "artifact-governed-export"
                    | "artifact-governed-retain"
                    | "workflow-dag-review"
                    | "workflow-dag-prepare"
                    | "workflow-dag-status"
                    | "workflow-dag-advance"
                    | "workflow-dag-cancel"
                    | "workflow-dag-reconcile"
                    | "workflow-dag-schedule"
                    | "resource-retention"
                    | "workflow-inputs-review"
                    | "workflow-inputs-init"
                    | "policy-evidence-review"
                    | "policy-evidence-retain"
                    | "policy-evidence-pending-review"
                    | "policy-evidence-pending-retain"
                    | "policy-archive-review"
                    | "policy-archive-export-proposal"
                    | "policy-archive-export"
                    | "policy-archive-dispose-proposal"
                    | "policy-archive-dispose-mark"
                    | "policy-archive-delete-proposal"
                    | "policy-archive-delete"
                    | "policy-archive-outcomes"
                    | "policy-archive-cleanup-proposal"
                    | "policy-archive-cleanup"
                    | "workflow-history-inspection-review"
                    | "workflow-history-proposal"
                    | "workflow-history-export"
                    | "workflow-history-mark"
                    | "workflow-history-mark-proposal"
                    | "workflow-history-delete-proposal"
                    | "workflow-history-delete"
                    | "workflow-history-staging-proposal"
                    | "workflow-history-staging-discard"
                    | "workflow-recovery-review"
                    | "workflow-recovery-inspect"
                    | "workflow-recovery-cancel"
                    | "workflow-recovery-reconcile"
                    | "artifact-gc-inspection-review"
                    | "artifact-gc-proposal"
                    | "artifact-gc-mark"
                    | "artifact-gc-delete-proposal"
                    | "artifact-gc-delete"
                    | "artifact-gc-outcomes"
                    | "artifact-owned-export-review"
                    | "artifact-owned-export"
                    | "artifact-owned-retain-proposal"
                    | "artifact-owned-retain"
                    | "artifact-owned-search"
                    | "content-owned-inspection-review"
                    | "content-owned-review"
                    | "content-owned-apply"
                    | "content-backup-export-proposal"
                    | "content-backup-export"
                    | "content-restore-proposal"
                    | "content-restore-review"
                    | "content-restore-apply"
                    | "content-restore-retire-proposal"
                    | "content-restore-retire-inspect"
                    | "content-restore-retire"
                    | "content-office-export-proposal"
                    | "content-office-export"
                    | "content-backup-signer-prepare-proposal"
                    | "content-backup-signer-prepare"
                    | "content-backup-signer-enroll"
                    | "content-backup-recipients-proposal"
                    | "content-backup-recipients-enroll"
            )
        )
    {
        return Err(
            "confined granted client cannot enter a daemon, worker, seed or Admin control path"
                .into(),
        );
    }
    if confined_client {
        service::granted_gateway::prepare_terminal()?;
    }
    if matches!(
        args.first().map(String::as_str),
        Some(
            "workflow-invoice-prepare"
                | "workflow-invoice-advance"
                | "workflow-invoice-cancel"
                | "workflow-invoice-reconcile"
                | "artifact-publish-invoice"
                | "artifact-read"
                | "artifact-reconcile"
                | "artifact-abort"
                | "artifact-catalog-publish-invoice"
                | "artifact-catalog-read"
                | "artifact-catalog-retain"
                | "artifact-catalog-import-legacy"
                | "invoice-calculate"
                | "scoped-file-read"
        )
    ) {
        platform::require_production_activation()?;
        admin_governance::reject_laboratory_effects_after_bootstrap()?;
    }
    match args.first().map(String::as_str) {
        Some("utc-windows-serve") if args.len() == 1 => utc_windows::serve(),
        Some(
            "utc-windows-checkpoint-enroll-review"
            | "utc-windows-checkpoint-enroll"
            | "utc-windows-checkpoint-parent-review"
            | "utc-windows-checkpoint-parent-continue"
            | "utc-windows-checkpoint-pending-review"
            | "utc-windows-checkpoint-finalize"
            | "utc-windows-checkpoint-status-review"
            | "utc-windows-checkpoint-status",
        ) => utc_windows_checkpoint::command(&args),
        Some(
            "utc-windows-key-draft-review"
            | "utc-windows-key-authorize-review"
            | "utc-windows-key-authorize-inspect"
            | "utc-windows-key-authorize"
            | "utc-windows-key-draft-inspect"
            | "utc-windows-key-draft"
            | "utc-windows-key-commission-review"
            | "utc-windows-key-commission-inspect"
            | "utc-windows-key-commission"
            | "utc-windows-key-revoke-review"
            | "utc-windows-key-revoke-inspect"
            | "utc-windows-key-revoke"
            | "utc-windows-key-reconcile-review"
            | "utc-windows-key-reconcile-inspect"
            | "utc-windows-key-reconcile",
        ) => utc_windows::command(&args),
        Some("content-office-request") if args.len() == 1 => office_export::prepare_stdin(),
        Some(
            "content-office-export-proposal"
            | "content-office-export"
            | "content-office-resource-worker",
        ) => office_export::command(&args),
        Some("hosted-windows-compute") if args.len() == 1 => hosted_windows::worker(),
        Some("hosted-windows-compute-launch") if args.len() == 1 => hosted_windows::launch(),
        Some("hosted-windows-compute-drain") if args.len() == 1 => hosted_windows::drain(),
        Some(
            "resource-checkpoint-prepare-review"
            | "resource-checkpoint-prepare"
            | "resource-checkpoint-enroll-review"
            | "resource-checkpoint-enroll"
            | "resource-checkpoint-parent-review"
            | "resource-checkpoint-parent-continue"
            | "resource-checkpoint-pending-review"
            | "resource-checkpoint-finalize"
            | "resource-checkpoint-recovery-review"
            | "resource-checkpoint-recover"
            | "resource-checkpoint-gc-review"
            | "resource-checkpoint-gc",
        ) => resources::checkpoint::command(&args),
        Some(
            "policy-archive-review"
            | "policy-archive-export-proposal"
            | "policy-archive-export"
            | "policy-archive-dispose-proposal"
            | "policy-archive-dispose-mark"
            | "policy-archive-delete-proposal"
            | "policy-archive-delete"
            | "policy-archive-outcomes"
            | "policy-archive-cleanup-proposal"
            | "policy-archive-cleanup",
        ) => policy_decisions::archive_command(&args),
        Some(
            "workflow-history-inspection-review"
            | "workflow-history-proposal"
            | "workflow-history-export"
            | "workflow-history-mark"
            | "workflow-history-mark-proposal"
            | "workflow-history-delete-proposal"
            | "workflow-history-delete"
            | "workflow-history-staging-proposal"
            | "workflow-history-staging-discard",
        ) => workflow_runs::history::command(&args),
        Some("workflow-history-init") if args.len() == 1 => {
            require_root()?;
            platform::require_installed()?;
            workflow_runs::history::initialize_installed()
        }
        Some("workflow-history-archive-verify") if args.len() == 2 => {
            workflow_runs::history::archive_verify(&args[1])
        }
        Some(
            "workflow-recovery-review"
            | "workflow-recovery-inspect"
            | "workflow-recovery-cancel"
            | "workflow-recovery-reconcile",
        ) => workflow_runs::recovery::command(&args),
        Some("granted-run") => service::granted_gateway::launch(&args[1..]),
        Some("content-custody-service") if args.len() == 1 => content_checkpoint::custody::run(),
        Some(
            "content-custody-bootstrap-proposal"
            | "content-custody-bootstrap-review"
            | "content-custody-bootstrap",
        ) => content_checkpoint::custody::bootstrap_command(&args),
        Some("content-backup-recipients-proposal" | "content-backup-recipients-enroll") => {
            content_checkpoint::custody::recipients_command(&args)
        }
        Some(
            "content-backup-signer-prepare-proposal"
            | "content-backup-signer-prepare"
            | "content-backup-signer-enroll",
        ) => content_checkpoint::custody::signer_command(&args),
        Some(
            "content-custody-inspect-proposal"
            | "content-custody-inspect"
            | "content-custody-reconcile",
        ) => content_checkpoint::custody::command(&args),
        Some("content-backup-request") if args.len() == 1 => content_backup::prepare_stdin(),
        Some("content-restore-request") if args.len() == 1 => content_restore::prepare_stdin(),
        Some("content-restore-retire-request") if args.len() == 1 => {
            content_checkpoint::custody::prepare_retirement_stdin()
        }
        Some(
            "content-restore-retire-proposal"
            | "content-restore-retire-inspect"
            | "content-restore-retire",
        ) => content_checkpoint::custody::retire_command(&args),
        Some(
            "content-restore-proposal"
            | "content-restore-review"
            | "content-restore-apply"
            | "content-restore-resource-worker",
        ) => content_restore::command(&args),
        Some("content-backup-receipt-verify") if args.len() == 2 => {
            content_checkpoint::custody::verify_backup_receipt_stdin(&args[1])
        }
        Some("content-backup-capsule-verify") if args.len() == 2 => {
            content_backup::verify_capsule_stdin(&args[1])
        }
        Some(
            "content-backup-export-proposal"
            | "content-backup-export"
            | "content-backup-resource-worker",
        ) => content_backup::command(&args),
        Some(
            "content-checkpoint-enroll-review"
            | "content-checkpoint-enroll"
            | "content-checkpoint-parent-review"
            | "content-checkpoint-parent-continue"
            | "content-checkpoint-pending-review"
            | "content-checkpoint-finalize"
            | "content-checkpoint-status-review"
            | "content-checkpoint-status",
        ) => content_checkpoint::command(&args),
        Some(
            "content-owned-inspection-review"
            | "content-owned-review"
            | "content-owned-apply"
            | "content-resource-worker",
        ) => content_governed::command(&args),
        Some(
            "content-contract-capture"
            | "content-contract-reopen"
            | "content-contract-compare"
            | "content-contract-spreadsheet"
            | "content-contract-document"
            | "content-contract-diagram"
            | "content-contract-animation"
            | "content-contract-collection"
            | "content-contract-native-request"
            | "content-contract-table-edit",
        ) if args.len() == 1 => content_contract::stdin(&args[0]),
        Some("artifact-owned-search") if args.len() == 5 => {
            artifact_catalog::owned_search_command(&args)
        }
        Some("generated-resource-worker" | "generated-review" | "generated-execute") => {
            generated_runtime::command(&args)
        }
        Some(
            "artifact-owned-export-review"
            | "artifact-owned-export"
            | "artifact-owned-retain-proposal"
            | "artifact-owned-retain",
        ) => artifact_catalog::owned_effects_command(&args),
        Some(
            "artifact-gc-inspection-review"
            | "artifact-gc-proposal"
            | "artifact-gc-mark"
            | "artifact-gc-delete-proposal"
            | "artifact-gc-delete"
            | "artifact-gc-outcomes",
        ) => artifact_catalog::gc_command(&args),
        Some("workflow-source-review") if args.len() == 3 => {
            workflow_runs::dag::source_review(&args[1], &args[2])
        }
        Some("workflow-dag-store-init") if args.len() == 1 => {
            require_root()?;
            platform::require_installed()?;
            workflow_runs::dag::initialize_installed()
        }
        Some("workflow-dag-review") if args.len() == 2 => workflow_runs::dag::review(&args[1]),
        Some("workflow-dag-prepare") => workflow_runs::dag::prepare(&args),
        Some("workflow-dag-status") => workflow_runs::dag::status(&args),
        Some("workflow-dag-advance") => workflow_runs::dag::advance(&args),
        Some("workflow-dag-cancel") => workflow_runs::dag::cancel(&args),
        Some("workflow-dag-reconcile") => workflow_runs::dag::reconcile(&args),
        Some("workflow-dag-schedule") => workflow_runs::dag::schedule_command(&args),
        Some("workflow-inputs-review") if args.len() == 2 => workflow_inputs::review(&args[1]),
        Some("workflow-inputs-init") => workflow_inputs::initialize(&args),
        Some("policy-evidence-review") if args.len() == 2 => policy_decisions::review(&args[1]),
        Some("policy-evidence-retain") => policy_decisions::retain(&args),
        Some("policy-evidence-pending-review") if args.len() == 2 => {
            policy_decisions::pending_review(&args[1])
        }
        Some("policy-evidence-pending-retain") => policy_decisions::pending_retain(&args),
        Some("resource-retention") => {
            require_root()?;
            platform::require_installed()?;
            resource_manager::recovery::retention_command(&args[1..])
        }
        Some("granted-infer") if args.len() == 5 => {
            let max_tokens = args[4].parse::<u64>()?;
            if max_tokens.to_string() != args[4] {
                return Err("noncanonical inference token bound".into());
            }
            service::granted_gateway::infer(
                &args[1],
                &args[2],
                inference_input(&args[3])?,
                max_tokens,
            )
        }
        Some("granted-infer-review") if args.len() == 3 => {
            let max_tokens = args[2].parse::<u64>()?;
            if max_tokens.to_string() != args[2] {
                return Err("noncanonical inference token bound".into());
            }
            service::granted_gateway::infer_review(inference_input(&args[1])?, max_tokens)
        }
        Some("utc-keeper") if args.len() == 1 => utc_provider::serve(),
        Some("utc-recovery-keeper") if args.len() == 1 => utc_provider::serve_recovery(),
        Some("utc-seed") => admin_governance::utc_seed_command(&args),
        Some("utc-seed-recovery") => admin_governance::utc_seed_recovery_command(&args),
        Some("utc-reacquire") => admin_governance::utc_reacquire_command(&args),
        Some("utc-reacquire-recovery") => admin_governance::utc_reacquire_recovery_command(&args),
        Some("utc-query") if args.len() == 2 => admin_governance::utc_query_command(&args[1]),
        Some("utc-history") => admin_governance::utc_history_command(&args),
        Some("workflow-governed-review") if args.len() == 6 => {
            workflow_runs::governed_review(&args[1], &args[2], &args[3], &args[4], &args[5])
        }
        Some("workflow-governed-prepare") => workflow_runs::governed_prepare(&args),
        Some("workflow-governed-advance") => workflow_runs::governed_advance(&args),
        Some("workflow-governed-cancel") => workflow_runs::governed_cancel(&args),
        Some("workflow-governed-reconcile") => workflow_runs::governed_reconcile(&args),
        Some("artifact-governed-export-review") if args.len() == 3 => {
            artifact_catalog::governed_export_review(&args[1], &args[2])
        }
        Some("artifact-governed-export") => artifact_catalog::governed_export(&args),
        Some("artifact-governed-retain") => artifact_catalog::governed_retain(&args),
        Some("workflow-resource-worker") if args.len() == 2 => workflow_resource::worker(&args[1]),
        Some("model-acquisition-worker") if args.len() == 4 => {
            acquisition::worker(&args[1], &args[2], Path::new(&args[3]))
        }
        Some("resource-live-initialize") if args.len() == 1 => resource_manager::initialize_live(),
        Some("resource-migration-status") if args.len() == 1 => {
            resource_manager::migration_status()
        }
        Some("resource-runtime-lock-status") if args.len() == 1 => {
            resource_manager::recovery::status()
        }
        Some("resource-runtime-lock-recover") if args.len() == 2 => {
            resource_manager::recovery::recover(&args[1])
        }
        Some("resource-migrate") if args.len() == 2 => resource_manager::migrate_reviewed(&args[1]),
        Some("inventory") if args.len() == 1 => disk::inventory(),
        Some("tpm-probe") if args.len() == 1 => {
            println!("{}", serde_json::to_string(&tpm::probe()?)?);
            Ok(())
        }
        Some("admin-install-check") if args.len() == 1 => {
            println!(
                "{}",
                serde_json::to_string(&tpm::installation_admission()?.intent("unselected"))?
            );
            Ok(())
        }
        Some("admin-checkpoint-status") if args.len() == 1 => admin_journal::status(),
        Some("admin-custody-recover") if args.len() == 2 => {
            admin_governance::recover_admin(&args[1])
        }
        Some("admin-bootstrap") if args.len() == 2 => admin_governance::bootstrap(&args[1], None),
        Some("admin-bootstrap") if args.len() == 4 && args[2] == "--activate" => {
            admin_governance::bootstrap(&args[1], Some(&args[3]))
        }
        Some("admin-governance-status") if args.len() == 2 => {
            admin_governance::catalog_status(&args[1])
        }
        Some("admin-service") if args.len() == 1 => admin_service::serve(),
        Some("admin-release-trust-stage" | "admin-release-activate") => {
            admin_governance::staged_release_command(&args)
        }
        Some("admin-release-command") => admin_governance::release_catalog_command(&args),
        Some("admin-model-command" | "admin-model-custodian-command") => {
            admin_governance::model_catalog_command(&args)
        }
        Some("admin-skill-trust-publish" | "admin-skill-registry-admit") => {
            admin_governance::skill_catalog_command(&args)
        }
        Some("peer-observer") if args.len() == 1 => credential_observer::serve(),
        Some("admin-service-request") if args.len() == 1 => admin_service::connection(),
        Some("admin-client") => admin_service::client(&args[1..]),
        Some("admin-principals-adopt") if args.len() == 3 => {
            admin_governance::adopt_principals(&args[1], &args[2], None)
        }
        Some("admin-principals-adopt") if args.len() == 5 && args[3] == "--commit" => {
            admin_governance::adopt_principals(&args[1], &args[2], Some(&args[4]))
        }
        Some("admin-accounts-checkpoint") if args.len() == 3 => {
            admin_governance::checkpoint_accounts(&args[1], &args[2], None)
        }
        Some("admin-accounts-checkpoint") if args.len() == 5 && args[3] == "--commit" => {
            admin_governance::checkpoint_accounts(&args[1], &args[2], Some(&args[4]))
        }
        Some("admin-account-password") => admin_governance::account_password_command(&args),
        Some("admin-account-activate" | "admin-account-renew") => {
            admin_governance::account_activation_command(&args)
        }
        Some(
            "admin-account-recover"
            | "admin-account-recover-publish"
            | "admin-account-recover-complete",
        ) => admin_governance::admin_account_recovery_command(&args),
        Some(
            "admin-account-create"
            | "admin-account-create-permit"
            | "admin-account-create-file"
            | "admin-account-create-complete",
        ) => admin_governance::account_creation_command(&args),
        Some(
            "admin-account-delete"
            | "admin-account-delete-permit"
            | "admin-account-delete-file"
            | "admin-account-delete-complete",
        ) => admin_governance::account_deletion_command(&args),
        Some("admin-account-lock")
        | Some("admin-account-publish")
        | Some("admin-account-complete") => admin_governance::account_lock_command(&args),
        Some("admin-activity-register")
        | Some("admin-catalog")
        | Some("admin-role-define")
        | Some("admin-principal-advance")
        | Some("admin-principal-rotate") => admin_governance::catalog_command(&args),
        Some("principal-check") if args.len() == 2 => admin_governance::principal_check(&args[1]),
        Some("admin-checkpoint-enroll") if args.len() == 3 && args[2] == "--existing-owner" => {
            admin_enrollment::enroll(&args[1])
        }
        Some("admin-checkpoint-enrollment-inspect") if args.len() == 1 => {
            admin_enrollment::inspect()
        }
        Some("admin-checkpoint-enrollment-resume") if args.len() == 3 => {
            admin_enrollment::resume_bound_parent(&args[1], &args[2])
        }
        Some("admin-checkpoint-enrollment-reconcile") if args.len() == 1 => {
            admin_enrollment::reconcile_pending(None, None)
        }
        Some("admin-checkpoint-enrollment-reconcile")
            if args.len() == 4 && args[1] == "--publish-committed" =>
        {
            admin_enrollment::reconcile_pending(Some(&args[2]), Some(&args[3]))
        }
        Some("admin-checkpoint-reconcile") if args.len() == 1 => admin_journal::reconcile(None),
        Some("admin-checkpoint-reconcile")
            if args.len() == 3 && args[1] == "--publish-committed" =>
        {
            admin_journal::reconcile(Some(&args[2]))
        }
        Some("broker-effect-status") if args.len() == 1 => broker_effects::status(),
        Some("admin-auth-check") if args.len() == 2 => authentication::check(&args[1]),
        Some("staging-clean") if args.len() == 1 => {
            println!("{}", serde_json::to_string(&staging::clean()?)?);
            Ok(())
        }
        Some("verify") if args.len() == 2 => {
            let verified = bundle::verify(Path::new(&args[1]))?;
            println!("{}", serde_json::to_string_pretty(&verified.manifest)?);
            Ok(())
        }
        Some("workflow-validate") if args.len() == 2 => {
            workflow::validate_file(Path::new(&args[1]))
        }
        Some("workflow-store-init") if args.len() == 1 => workflow_runs::initialize_installed(),
        Some("workflow-store-status") if args.len() == 1 => workflow_runs::store_status(),
        Some("workflow-invoice-prepare") if args.len() == 4 => {
            workflow_runs::prepare(&args[1], &args[2], &args[3])
        }
        Some("workflow-invoice-status") if args.len() == 2 => workflow_runs::status(&args[1]),
        Some("workflow-invoice-advance") if args.len() == 3 => {
            workflow_runs::advance(&args[1], &args[2])
        }
        Some("workflow-invoice-cancel") if args.len() == 3 => {
            workflow_runs::cancel(&args[1], &args[2])
        }
        Some("workflow-invoice-reconcile") if args.len() == 2 => {
            workflow_runs::reconcile(&args[1], None)
        }
        Some("workflow-invoice-reconcile")
            if args.len() == 4 && args[2] == "--publish-committed" =>
        {
            workflow_runs::reconcile(&args[1], Some(&args[3]))
        }
        Some("skill-registry-status") if args.len() == 1 => skills::status(),
        Some("invoice-calculate") if args.len() == 1 => calculation::calculate_stdin(),
        Some("artifact-store-init") if args.len() == 1 => artifacts::initialize_installed(),
        Some("artifact-store-status") if args.len() == 1 => artifacts::status(),
        Some("artifact-publish-invoice") if args.len() == 2 => artifacts::publish_invoice(&args[1]),
        Some("artifact-read") if args.len() == 2 => artifacts::read(&args[1]),
        Some("artifact-reconcile") if args.len() == 3 => artifacts::reconcile(&args[1], &args[2]),
        Some("artifact-abort") if args.len() == 3 => artifacts::abort(&args[1], &args[2]),
        Some("artifact-catalog-init") if args.len() == 1 => {
            artifact_catalog::initialize_installed()
        }
        Some("artifact-catalog-status") if args.len() == 1 => artifact_catalog::status(),
        Some("artifact-catalog-search") if args.len() == 3 => {
            artifact_catalog::search_command(&args[1], &args[2])
        }
        Some("artifact-catalog-publish-invoice") if args.len() == 4 => {
            artifact_catalog::publish_invoice(&args[1], &args[2], &args[3])
        }
        Some("artifact-catalog-read") if args.len() == 3 => {
            artifact_catalog::read(&args[1], &args[2])
        }
        Some("artifact-catalog-retain") if args.len() == 3 => {
            artifact_catalog::retain(&args[1], &args[2])
        }
        Some("artifact-catalog-legacy-inspect") if args.len() == 2 => {
            artifact_catalog::legacy_inspect(&args[1])
        }
        Some("artifact-catalog-import-legacy") if args.len() == 3 => {
            artifact_catalog::import_legacy(&args[1], &args[2])
        }
        Some("install") if args.len() == 3 => {
            platform::install(&args[1], Path::new(&args[2]), None)
        }
        Some("install") if args.len() == 5 && args[3] == "--model" => {
            platform::install(&args[1], Path::new(&args[2]), Some(&args[4]))
        }
        Some("install") if args.len() == 5 && args[3] == "--stage-model" => {
            platform::install_staged(&args[1], std::path::Path::new(&args[2]), &args[4])
        }
        Some("installer-model-stage-worker") if args.len() == 3 => {
            model::installer_staging::worker(std::path::Path::new(&args[1]), &args[2])
        }
        Some("model-qa-review") if args.len() == 3 => model::qa::review(&args[1], &args[2]),
        Some("model-qa-run") if args.len() == 5 => {
            model::qa::run(&args[1], &args[2], &args[3], &args[4])
        }
        Some("model-qa-worker") if args.len() == 3 => model::qa::worker(&args[1], &args[2]),
        Some("models") if args.len() == 1 => model::list(),
        Some("model-pack-import-review") if args.len() == 2 => model::pack_import_review(&args[1]),
        Some("model-pack-import") if args.len() == 4 => {
            model::pack_import(&args[1], &args[2], &args[3])
        }
        Some("model-pack-pending-review") if args.len() == 2 => {
            model::pack_pending_review(&args[1])
        }
        Some("model-pack-pending-retain") if args.len() == 5 => {
            model::pack_pending_retain(&args[1], &args[2], &args[3], &args[4])
        }
        Some("model-activate-review") if args.len() == 2 => model::activate_review(&args[1]),
        Some("model-activate") if args.len() == 4 => model::activate(&args[1], &args[2], &args[3]),
        Some("model-qualification-review") if args.len() == 3 => {
            model_qualification::review(&args[1], Path::new(&args[2]))
        }
        Some("model-qualification-install") if args.len() == 5 => {
            model_qualification::install(&args[1], &args[2], &args[3], Path::new(&args[4]))
        }
        Some("model-qualification-observe") if args.len() == 4 => {
            model_qualification::observe(&args[1], &args[2], &args[3])
        }
        Some("model-qualification-pending-review") if args.len() == 2 => {
            model_qualification::pending_review(&args[1])
        }
        Some("model-qualification-pending-retain") if args.len() == 5 => {
            model_qualification::pending_retain(&args[1], &args[2], &args[3], &args[4])
        }
        Some("model-install") if args.len() == 2 => model::install(&args[1]),
        Some("model-install-check") if args.len() == 2 => model::install_check(&args[1]),
        Some("model-migrate-legacy") if args.len() == 1 => model::migrate_legacy(),
        Some("model-activation-reconcile") if args.len() == 1 => model::activation_reconcile(None),
        Some("model-activation-reconcile") if args.len() == 3 => {
            model::activation_reconcile(Some((&args[1], &args[2])))
        }
        Some("model-rollback-reconcile") if args.len() == 1 => model::rollback_reconcile(None),
        Some("model-rollback-reconcile") if args.len() == 3 => {
            model::rollback_reconcile(Some((&args[1], &args[2])))
        }
        Some("model-quarantine-reconcile") if args.len() == 1 => model::quarantine_reconcile(None),
        Some("model-quarantine-reconcile")
            if args.len() == 2 && args[1] == "--inspect-incomplete" =>
        {
            model::quarantine_reconcile(Some((&args[1], "")))
        }
        Some("model-quarantine-reconcile") if args.len() == 3 => {
            model::quarantine_reconcile(Some((&args[1], &args[2])))
        }
        Some("model-validation-reconcile") if args.len() == 1 => model::validation_reconcile(None),
        Some("model-validation-reconcile")
            if args.len() == 2 && args[1] == "--inspect-incomplete" =>
        {
            model::validation_reconcile(Some((&args[1], "")))
        }
        Some("model-validation-reconcile") if args.len() == 3 => {
            model::validation_reconcile(Some((&args[1], &args[2])))
        }
        Some("model-clean") if args.len() == 1 => {
            println!(
                "{}",
                serde_json::json!({"removed_downloads": model::clean()?})
            );
            Ok(())
        }
        Some("model-serve") if args.len() == 1 => model::serve(),
        Some("model-unit") if args.len() == 1 => model::unit(),
        Some("model-chat") => {
            use std::os::unix::process::CommandExt;
            require_root()?;
            platform::require_installed()?;
            // Replace the CLI instead of leaving an unsupervised helper child.
            // Cancellation/death therefore reaches the very PID generation
            // pinned by request admission, including before an acknowledgement.
            let error = std::process::Command::new("/usr/bin/python3")
                .args(["-I", "/usr/libexec/luma-os/model-chat.py"])
                // The fixed helper parses only bounded numeric options. No
                // interpreter flags, endpoint, path or shell is caller-selected.
                .args(&args[1..])
                .env_clear()
                .env("PATH", "/usr/bin")
                .exec();
            Err(error.into())
        }
        Some("update") if args.len() == 2 => platform::update(Path::new(&args[1])),
        Some("recover") if args.len() >= 3 => platform::recover(&args[1..]),
        Some("broker") if args.len() == 1 => service::serve(),
        Some("status") if args.len() == 1 => service::client("status"),
        Some("resource-status") if args.len() == 1 => {
            resource_manager::client("resource-status", None)
        }
        Some("resource-request-status") if args.len() == 1 => {
            resource_manager::client("resource-request-status", None)
        }
        Some("resource-request-archive") if args.len() == 2 => {
            resource_manager::client("resource-request-archive", Some(&args[1]))
        }
        Some("resource-request-export") if args.len() == 3 => {
            resource_manager::history::export(&args[1], &args[2])
        }
        Some("resource-request-recovery-status") if args.len() == 1 => {
            resource_manager::client("resource-request-recovery-status", None)
        }
        Some("resource-request-recover") if args.len() == 2 => {
            resource_manager::client("resource-request-recover", Some(&args[1]))
        }
        Some("resource-recovery-status") if args.len() == 1 => {
            resource_manager::client("resource-recovery-status", None)
        }
        Some("resource-recover") if args.len() == 2 => {
            resource_manager::client("resource-recover", Some(&args[1]))
        }
        Some("resource-request-migration-status") if args.len() == 1 => {
            resource_manager::request_migration(None)
        }
        Some("resource-request-migrate") if args.len() == 2 => {
            resource_manager::request_migration(Some(&args[1]))
        }
        Some("resource-reconcile") if args.len() == 2 => {
            resource_manager::client("resource-reconcile", Some(&args[1]))
        }
        Some("resource-migrate") if args.len() == 1 => resource_manager::migrate(),
        Some("resource-archive") if args.len() == 2 => {
            resource_manager::client("resource-archive", Some(&args[1]))
        }
        Some("resource-revoke") if args.len() == 4 => {
            resource_manager::revoke(&args[1], &args[2], &args[3])
        }
        Some("boot-health") if args.len() == 1 => platform::boot_health(),
        Some("boot-failed") if args.len() == 1 => platform::boot_failed(),
        Some("init-data") if args.len() == 2 => platform::init_data(&args[1]),
        Some("help" | "--help") | None => {
            println!("Bounded workflow scheduling: granted-run workflow-dag-schedule LOGIN SCHEDULE-JSON. Up to 16 distinct reviewed run checkpoints; one currently authorized node step per run, no automatic retry or authority restoration. A failed item preserves its uncertain outcome and leaves the suffix undispatched.");
            println!("Release governance: luma-admin-control admin-release-command LOGIN REQUEST FILE [--commit REVIEW-SHA256] accepts only publish_release_trust, initialize_release, prepare_release and resolve_release JSON through current original Admin, protected UTC and the existing TPM journal. Trust/root environments, irreversible revocations, exact signed candidate bytes, geometry and monotonic admission floors are checked. Public production roots and real signing custody must be provisioned separately. admin-catalog remains finite role/grant governance only.");
            println!("Independent resource custody: luma-admin-control resource-checkpoint-prepare-review LOGIN | resource-checkpoint-prepare LOGIN GRANT REVIEW; enroll-review/enroll, parent-review/parent-continue, pending-review/finalize, recovery-review/recover and gc-review/gc follow the typed review plus exact finite-grant ceremony. Requires original Admin, protected UTC, fixed masks and drainage; no ownership takeover, NV replay, capacity release or service restart. See RESOURCE_CHECKPOINT_CUSTODY.md.");
            println!("Terminal history: granted-run workflow-history-inspection-review/proposal/export/mark-proposal/mark/delete-proposal/delete. Export uses a separate binary payload channel; marks bind exact custody acknowledgement and protected grace. Deletion retires only terminal workflow copies, preserves owned artifacts and sources, and advances a durable domain epoch. Historical invoice review/prepare requires HISTORY-EPOCH before captured CSV input. Policy archives: policy-archive-review/export-proposal/export/dispose-proposal/dispose-mark/delete-proposal/delete/outcomes/cleanup-proposal/cleanup, each with separate exact scopes; archives never restore authorization.");
            println!("Physical receipt preparation recovery: resource-recovery-status | resource-recover REVIEW-SHA256. Installed-root broker maintenance with terminal requests and empty, released worker generations. Review binds the exact hot ledger and selected interrupted stage inode/bytes; preserves the stage under an immutable private incident name. Complete checksum-matching stages remain for exact archival retry. Never deletes evidence, retires an owner, grants an effect or releases capacity.");
            println!("Receipt export: resource-request-export BATCH SHA256 writes a referenced immutable archive only after bounded chunk assembly and complete digest verification. Interrupted-stage recovery: resource-request-recovery-status | resource-request-recover REVIEW-SHA256 requires drained physical generations and empty workers; retains incomplete stage bytes under a reviewed immutable incident name. Neither command deletes evidence, releases resources or grants product Admin.");
            println!("Request history: resource-request-status | resource-request-archive REVIEW-SHA256. Installed-root reviewed archival preserves receipts and retired nonces; it never releases worker resources or automatically deletes history. Older images: resource-request-migration-status | resource-request-migrate REVIEW-SHA256, with broker stopped, both worker slices drained and the runtime exclusion held. Creates only absent request history, rotates an initialized physical manager epoch and explicitly records that pre-upgrade request receipts were not retained. A virgin ledger stays uninitialized. Never resets uncertain state.");
            println!("resource-runtime-lock-status | resource-runtime-lock-recover REVIEW-SHA256: explicit installed-root offline recovery of an absent model exclusion inode. Requires loaded runtime masks for luma-model, luma-acquisition and luma-broker, empty worker slices, no surviving model-identity task in the installed PID namespace, no outstanding resource generations and exclusive operation/store locks. Preserves masks and all ledger/receipt bytes; does not start services, release resources or grant product Admin.");
            println!("Resources: resource-status | resource-reconcile REVIEW-SHA256 | resource-archive REVIEW-SHA256 | resource-revoke LEASE-ID GENERATION MANAGER-EPOCH | resource-migrate | resource-migration-status | resource-migrate REVIEW-SHA256. Existing broker authority; installed root maintenance only. No-argument migration initializes only missing state; reviewed offline migration preserves receipts, epochs and retained charges with both worker slices idle and the broker stopped. Uncertain state is never reset. Workers require exact generation-fenced leases before heavy work.");
            println!("Local TPM diagnostics: tpm-probe | admin-checkpoint-status (root only; read-only; neither enrolls nor grants Admin). External Admin deployment is deferred.");
            println!("Integrated governed controls (software qualification pending): sudo luma-admin-control utc-seed/utc-seed-recovery/utc-query/utc-history, admin-account-activate/renew and admin-account-recover/-publish/-complete. Use /run/luma-admin for inert reviewed seed/statement files. Original PAM or offline custody, not sudo, authorizes control.");
            println!("Confined granted operations: sudo luma-platform granted-run granted-infer-review MESSAGES-JSON MAX-TOKENS | granted-infer LOGIN GRANT MESSAGES-JSON MAX-TOKENS; workflow-governed-review/prepare/advance/cancel/reconcile; artifact-governed-export-review/export/retain. Exact finite scopes, current PAM/TPM/UTC and fresh resource generations are required. Unscoped laboratory effects refuse after product bootstrap; damaged-authority restoration still requires an independently protected checkpoint.");
            println!("Supported file-to-artifact DAGs: workflow-dag-store-init (explicit installed-root namespace initialization); workflow-source-review ROOT RELATIVE (human owner, no sudo); granted-run workflow-dag-review SPEC-JSON | workflow-dag-prepare LOGIN SPEC-JSON | workflow-dag-status LOGIN GRANTS-JSON REQUEST | workflow-dag-advance/cancel LOGIN GRANTS-JSON REQUEST REVIEW-SHA256 | workflow-dag-reconcile LOGIN GRANTS-JSON REQUEST [--publish-committed REVIEW-SHA256]. Bounded FileRead, DeterministicCalculate and ArtifactWrite topology only; calculation runs in a leased worker, outputs and checkpoints are owner-isolated, and uncertain publication needs exact outcome reconciliation.");
            println!("Governed input folders: granted-run workflow-inputs-review LOGIN | workflow-inputs-init LOGIN EXECUTE-GRANT REVIEW-SHA256. The exact workflow.execute grant provisions only the current human's protected input namespace and root read-only child ACLs; no arbitrary folder delegation or DAC bypass. New files must remain human-owned and bounded, and source review grants no access.");
            println!("Governed evidence retention: granted-run resource-retention --proposal NAME... | --outcomes | LOGIN GRANT REVIEW-SHA256 NAME... (offline masks and real worker drainage required); policy-evidence-review OPERATION | policy-evidence-retain LOGIN GRANT OPERATION REVIEW-SHA256; policy-evidence-pending-review MEMBER | policy-evidence-pending-retain LOGIN GRANT MEMBER REVIEW-SHA256. Referenced authority history is preserved; archived policy records cannot grant access or restore authority.");
            println!("admin-checkpoint-enroll LOGIN --existing-owner: explicit installed-root checkpoint enrollment with local PAM and hidden custodian owner authorization; retains interrupted attempts; does not grant product Admin.");
            println!("admin-checkpoint-enrollment-inspect: read-only retained-intent and fixed TPM-handle observation; does not repair, retry, delete or grant Admin.");
            println!("admin-checkpoint-enrollment-resume LOGIN REVIEW-SHA256: explicit fresh-auth continuation only from a reviewed, bound parent with no NV proposal or index; never retries parent allocation.");
            println!("admin-checkpoint-enrollment-reconcile [--publish-committed LOGIN REVIEW-SHA256]: inspect, publish or replay an exact TPM-committed inert enrollment, including lost publication acknowledgement. Publication/replay requires fresh principal-bound PAM; never repeats a TPM write or activates product Admin.");
            println!("admin-checkpoint-reconcile [--publish-committed REVIEW-SHA256]: inspect or explicitly publish a TPM-proven pending inert audit commit; never replays effects or resets TPM state. Requires existing enrollment and credential delivery.");
            println!("admin-auth-check LOGIN: installed-system, controlling-terminal account authentication diagnostic; does not enroll or grant product Admin.");
            println!("admin-bootstrap LOGIN [--activate REVIEW-SHA256]: freshly authenticate the enrolled human, inspect or explicitly commit the installation-bound Admin bootstrap receipt. No role delegation, signing, resource capability or effect execution is enabled by this command.");
            println!("First-boot production activation: luma-admin-control admin-release-trust-stage LOGIN REQUEST [--commit REVIEW] then admin-release-activate LOGIN REQUEST [--commit REVIEW]. Each reviews exact retained signed staging evidence, original Admin, TPM and current protected UTC. Offline staging alone enables no protected operation.");
            println!("Skill trust: luma-admin-control admin-skill-trust-publish LOGIN REQUEST EXPECTED-VERSION SIGNED-TRUST-FILE [--commit REVIEW] | admin-skill-registry-admit LOGIN REQUEST EXPECTED-FLOOR SIGNED-ADMISSION-FILE [--commit REVIEW]. Separate immutable skill roots/policy, exact schema-2 registry/graph, finite current UTC, monotonic TPM trust/floor and explicit Admin review; no signing private key or effect grant.");
            println!("Target recovery: luma-recovery-control utc-seed DISK /run/luma-recovery-input/seed.json [--commit KEEPER-INSTANCE REVIEW] | utc-reacquire DISK [--commit KEEPER-INSTANCE REVIEW] | repair-a|repair-b DISK /run/luma-recovery-bundle. Original offline Admin custody and exact live image/target TPM/history are mandatory. Repairs use a separate nonrenewable 30-minute deadline and continuously current UTC; ordinary Admin/export sessions are unchanged.");
            println!("admin-governance-status LOGIN: fresh principal-bound inspection of the TPM-verified finite activity/role definition catalog; no assignment or effect grant.");
            println!("admin-client LOGIN status | LOGIN register REQUEST ACTIVITY | LOGIN define REQUEST ROLE VERSION ACTIVITY... [--commit REVIEW]: one fresh PAM-authenticated request to the fixed local Admin service, from the selected human account without sudo. No assignments or effect grants.");
            println!("admin-client LOGIN adopt-principals REQUEST [--commit REVIEW] | admin-principals-adopt LOGIN REQUEST [--commit REVIEW]: explicitly checkpoint the exact current installed principal registry after product bootstrap. Does not create/change accounts or grant effects. Once adopted, mismatched registry state fences Admin semantics; root file edits cannot replace the checkpoint.");
            println!("admin-activity-register LOGIN REQUEST ACTIVITY [--commit REVIEW-SHA256]: inspect or explicitly commit one declared finite activity.");
            println!("admin-client LOGIN principal-advance REQUEST PRINCIPAL-ID EXPECTED-GENERATION enabled|disabled [--commit REVIEW] | admin-principal-advance LOGIN REQUEST PRINCIPAL-ID EXPECTED-GENERATION enabled|disabled [--commit REVIEW]: reviewed non-Admin generation advance in TPM history; disable/re-enable or rotate without editing installation account files. Bootstrap Admin and initially disabled accounts require separate custody recovery.");
            println!("admin-client LOGIN rotate-admin REQUEST EXPECTED-GENERATION [--commit REVIEW] | admin-principal-rotate LOGIN REQUEST EXPECTED-GENERATION [--commit REVIEW]: reviewed generation rotation of the original enabled Admin only. Does not disable, transfer custody, change credentials or rewrite historical writers; a fresh authenticated request is needed for subsequent operations.");
            println!("admin-custody-recover REQUEST: installed local-terminal offline credential ceremony. Requires an installer verifier already adopted into intact TPM history, confirms a new offline credential and reviews the exact transaction within a protected 30s proof. Rotates original Admin and recovery generations; no password change, root/owner fallback or effect grant.");
            println!("principal-check LOGIN: installed root maintenance diagnostic with fresh local PAM and current adopted TPM principal history; no session, role or effect grant is returned. This is distinct from the local-only admin-auth-check.");
            println!("admin-accounts-checkpoint LOGIN REQUEST [--commit REVIEW-SHA256]: reviewed one-time adoption of every installed enabled account's protected credential commitment into intact TPM history. Fixed local sources only; no password/hash input, account mutation, replacement checkpoint, time authority or effect grant. Changed credentials require separate governed lifecycle recovery.");
            println!("admin-account-lock LOGIN TARGET TRANSACTION lock|unlock [--commit REVIEW-SHA256]: prepare a reviewed existing non-Admin account lock transition, advancing and fencing its generation. Follow with separately reviewed admin-account-publish LOGIN TRANSACTION REQUEST and admin-account-complete LOGIN TRANSACTION REQUEST; both accept [--commit REVIEW-SHA256]. Interrupted phases require exact explicit continuation; no root bypass, password/hash input, reset or automatic retry.");
            println!("admin-account-password LOGIN TARGET TRANSACTION [--commit REVIEW-SHA256]: locally enter and confirm a new non-Admin password without echo; authenticate the governed Admin to retain a private yescrypt proposal. Commit the exact review digest, then use separately reviewed admin-account-publish and admin-account-complete. Existing lock and aging fields are preserved; no secret/hash arguments, Admin password reset, implicit unlock or automatic recovery.");
            println!("admin-account-delete LOGIN TARGET TRANSACTION [--commit REVIEW-SHA256]: prepare a reviewed non-Admin deletion and fence its generation. Review and commit admin-account-delete-permit LOGIN TRANSACTION REQUEST. Then authenticate afresh for each admin-account-delete-file LOGIN TRANSACTION FILE in order shadow, gshadow, group, passwd. Review and commit admin-account-delete-complete LOGIN TRANSACTION REQUEST. Exact partial publication can resume; IDs/UIDs and private evidence remain reserved, home data is not removed, no root bypass or automatic rollback.");
            println!("admin-account-create LOGIN NAME TRANSACTION [--commit REVIEW-SHA256]: enter and confirm a hidden password to retain an exact locked-account proposal. Review and commit admin-account-create-permit LOGIN TRANSACTION REQUEST. Authenticate afresh for each admin-account-create-file LOGIN TRANSACTION FILE in order home, gshadow, group, shadow, passwd, registry. Review and commit admin-account-create-complete LOGIN TRANSACTION REQUEST. Installation history is preserved; protected password aging is required before activation. No password/hash argument or automatic enablement.");
            println!("admin-role-define LOGIN REQUEST ROLE EXPECTED-VERSION ACTIVITY... [--commit REVIEW-SHA256]: finite registered activities only; version 0 creates, the exact current version updates. Defines no assignment or resource grant.");
            println!("Install requires local TPM2 admission before any disk write. admin-install-check is read-only and does not enroll Admin; explicit checkpoint enrollment remains separate from product Admin activation.");
            println!("Maintenance: staging-clean | model-clean (root only; preserves active operations and unknown files).");
            println!("broker-effect-status: root-only installed laboratory worker-effect receipts; uncertain effects are fenced, never automatically replayed. Not product Admin or TPM rollback protection.");
            println!("workflow-validate GRAPH.json: read-only closed native file-to-artifact DAG check; does not admit signed skills or execute effects.");
            println!("Durable laboratory invoice coordinator (installed root, ext4): workflow-store-init | workflow-store-status | workflow-invoice-prepare REQUEST-ID ARTIFACT-ID EXPECTED-VERSION (CSV stdin snapshot) | workflow-invoice-status REQUEST-ID | workflow-invoice-advance REQUEST-ID REVIEW-SHA256 | workflow-invoice-cancel REQUEST-ID REVIEW-SHA256. Each advance checkpoints the next native step; publication checkpoints Applying before calling the catalog, and exact recovery verifies its idempotent receipt. Cancellation is accepted only before Applying. Not product Admin, folder grants, generic DAG execution or full G2.");
            println!("workflow-invoice-reconcile REQUEST-ID [--publish-committed REVIEW-SHA256]: inspect and explicitly acknowledge an exact already committed catalog receipt, including after skill withdrawal. Keeps coordinator/catalog ownership through the proof recheck; never publishes an artifact or infers completion from absent evidence. Installed-root lab audit recovery, not a grant or product Admin.");
            println!("skill-registry-status: verify the fixed image-owned lab skill signature, exact descriptors and bound workflow; read-only admission, no execution or effect grant.");
            println!("invoice-calculate: installed-root broker-leased invoice CSV on stdin to deterministic monthly JSON totals, with a fresh result-generation check before stdout. Missing/fenced resource authority refuses; no unleased CLI fallback, file grant, workflow execution or artifact write.");
            println!("Managed laboratory invoice artifacts (installed root only): artifact-store-init (explicit older-install setup; refuses existing state) | artifact-store-status | artifact-publish-invoice REQUEST-ID (CSV stdin; signed workflow and broker-leased calculation) | artifact-read REQUEST-ID | artifact-reconcile REQUEST-ID REVIEW-SHA256 (publish a complete reviewed preparation only with valid broker result provenance; committed acknowledgements are read-only) | artifact-abort REQUEST-ID ABORT-REVIEW-SHA256 (retain reviewed partial bytes; never reuse the request). Missing/fenced preparation provenance requires retention and a new request with source input. Root-owned storage; product Admin, folder grants and TPM rollback protection remain pending.");
            println!("Native ADR-0003 catalog (installed root only, ext4): artifact-catalog-init | artifact-catalog-status | artifact-catalog-publish-invoice REQUEST-ID ARTIFACT-ID EXPECTED-VERSION (CSV stdin; broker-leased calculation; 0 creates version 1) | artifact-catalog-read ARTIFACT-ID VERSION | artifact-catalog-retain REQUEST-ID RETAIN-REVIEW-SHA256. WAL metadata and append-only generation receipts commit after synchronized content objects and a fresh result recheck. No automatic migration/deletion, product Admin grants or rollback protection.");
            println!("Laboratory catalog discovery: artifact-catalog-search QUERY LIMIT. Rebuilds a bounded lexical index over verified current versions; exact all-term matching, deterministic ordering, no model or durable index. Installed laboratory root only, unavailable after Admin bootstrap. Not governed or semantic search.");
            println!("Owned catalog discovery: granted-run artifact-gc-inspection-review LOGIN returns the exact independent Read scope; granted-run artifact-owned-search LOGIN READ-GRANT QUERY LIMIT uses current principal/grant checks during verified rebuild and bounded delivery. Current-generation, latest-version lexical references only; no semantic model or cross-owner lookup.");
            println!("Editable-content contracts: content-contract-capture | content-contract-reopen | content-contract-compare | content-contract-table-edit | content-contract-native-request take bounded schema-1 JSON on stdin. UTF8 text/JSON/CSV only; immutable version references, canonical reopen, explicit external-edit conflicts and exact inert native request preparation. Table edits are atomic zero-based cell/row/column data proposals, never formula execution. Pure data inspection, not authenticated ownership, a file grant, durable publication, automatic merge or certification.");
            println!(concat!(
                "Encrypted backup: content-backup-request canonicalizes an exact prior backup-review and two public recipient certificates/pins. ",
                "Explicit laboratory manual custody remains separate; governed-content-custody-v1-GENERATION requires current separately enrolled C recipient custody, protected same-Snapshot source selection and an actual measured-ciphertext origin receipt. ",
                "granted-run content-backup-export-proposal LOGIN REQUEST returns exact finite Read/Export scopes; content-backup-export LOGIN READ-GRANT EXPORT-GRANT REQUEST retains the original thirty-minute Export session and acknowledged binary relay. ",
                "Governed output is LUMACMSFRAME01 framing with public signed metadata and CMS, not raw CMS. ",
                "content-backup-receipt-verify EXPECTED-ORIGIN-SPKI-SHA256 accepts canonical detached custody receipt JSON on stdin and verifies only the independently selected origin signature; never infers current custody, archive validity or restore permission. ",
                "content-restore-request prepares public restore input. content-restore-retire-request canonicalizes an explicit retirement wrapper on stdin and returns only phase/scope data, never authenticated review or grants. granted-run content-restore-proposal LOGIN REQUEST returns exact finite scopes; content-restore-review LOGIN READ-GRANT EFFECT-GRANT REQUEST and content-restore-apply LOGIN READ-GRANT EFFECT-GRANT REQUEST require the original Admin session, finite Read plus Recover or batch Write grants, a private PKCS8 credential on locked memfd stdin and an independently pinned origin. ",
                "Ordered C-checkpoint publication supports reviewed prefix resumption. content-restore-retire-proposal LOGIN REQUEST, content-restore-retire-inspect LOGIN READ-GRANT REQUEST and content-restore-retire LOGIN RECOVER-GRANT REQUEST preserve forensic bytes and disable only the exact damaged owner generation. ",
                "Restore uses the standard thirty-second session; there is no plaintext fallback or automatic authority/account restoration."
            ));
            println!("Governed content beta requires an installed laboratory image or activated production image with independent C custody. granted-run content-owned-inspection-review LOGIN REQUEST returns an exact finite Read scope without private content access. granted-run content-owned-review LOGIN READ-GRANT REQUEST uses a fresh broker lease for a query or exact proposed Read/effect scopes and write:SHA256 or retain:SHA256 approval. granted-run content-owned-apply LOGIN READ-GRANT EFFECT-GRANT APPROVAL REQUEST rechecks both grants, protected UTC, actual owner generation and resource fencing before immutable publication or intent retention. Image-defined engine Workflow completion requires actual C custody, not a laboratory file commit. Requests must use canonical JSON from content-contract-native-request. No unleased/root-bypass path or installed-image qualification is implied.");
            println!("Governed content reads: Current, Historical, Envelope, Page, Search and CollectionSearch use content-owned-inspection-review then content-owned-review with their exact finite Read scope. Envelope returns one exact immutable envelope under its separate native-content-envelope-v1 selector and finite output allowance, with continuous current authorization on every delivery chunk and the same standard30-second session. Ordinary queries retain their64-KiB cap. Low-level pages remain independently admitted, at most16384 bytes encoded as hex. Latest-version and exact-collection owner-local lexical search is bounded, not semantic search or cross-owner policy. Query workers mount storage read-only and never initialize or repair it. Delivery requires a pipe, socket or terminal, not direct file export.");
            println!("Deterministic spreadsheet data: content-contract-spreadsheet takes a schema-1 typed source with 1..64 rows and 1..32 columns. Explicit decimal/ref/negate/binary/sum/minimum/maximum/average expressions use exact six-place decimal arithmetic; overflow, cycles, zero division and required rounding are refused. Returns canonical editable JSON source and CSV digests. CSV formula-looking text stays inert. This pure command establishes no ownership, storage publication or workflow authority.");
            println!("Deterministic content rendering: content-contract-document | content-contract-diagram | content-contract-animation take bounded closed schema-1 editable JSON on stdin and return exact source/output SHA256 digests. Document outputs escaped standalone HTML; diagrams output integer-geometry SVG; animations output bounded sampled SVG frames with integer interpolation, never automatic playback. No scripts, external resources, file writes, browser launch, publication or authenticated workflow receipt.");
            println!("Explicit collection data: content-contract-collection prepares canonical schema-1 luma-explicit-collection-v1 JSON with a stable collection ID, name and up to64 sorted exact member references. Native laboratory content requests support collection publication, current/historical collection pages, reverse membership, preparation review and separately scoped recover:SHA quarantine retirement. Membership and reviews are data, never grants or rollback authority; each private read/effect still needs current finite authorization.");
            println!("Explicit legacy copy import (installed root only): artifact-catalog-legacy-inspect LEGACY-REQUEST-ID | artifact-catalog-import-legacy LEGACY-REQUEST-ID REVIEW-SHA256. Review binds the complete source receipt; fixed source/catalog locks and current signed workflow checks span publication. Stable mapped IDs provide exact replay. Original data/receipts and retained preparations are preserved; no automatic migration or format downgrade.");
            println!("Model operations: models | model-install-check MODEL-ID | model-install MODEL-ID | model-chat [--timeout-seconds 1..1800] [--max-tokens 1..128] (prompt on stdin).\nInstaller accepts --model MODEL-ID or --model manual-only; otherwise prompts.\nPreflight does not change model configuration or reserve future serving capacity; cached verification uses a temporary acquisition lease. Activation rechecks after stopping the worker. Weights are acquired from pinned HTTPS publisher URLs after hardware admission.");
            println!("Governed model distribution: admin-model-command LOGIN REQUEST FILE [--commit REVIEW-SHA256] (trust publication/catalog admission only); admin-model-custodian-command LOGIN REQUEST FILE [--commit REVIEW-SHA256] (closed approve/sign intent, actual scoped PAM, server-derived UTC and event receipt). Sign only the canonical statement returned after its committed signing authorization; private signing custody remains external. model-pack-import-review MODEL-ID | model-pack-import LOGIN GRANT MODEL-ID (pack preparation only, never catalog/serving activation).");
            println!("Interrupted pack preparation: model-pack-pending-review MODEL-ID | model-pack-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256 (retain exact interrupted unverified bytes; no deletion or catalog activation).");
            println!("Externally certified exact-image/machine qualification: model-qualification-observe MODEL-ID LEVEL REPORT-SHA256 (unsigned measured descriptor only); model-qualification-review MODEL-ID INPUT | model-qualification-install LOGIN GRANT MODEL-ID INPUT (original Admin finite resource.provision, atomic public package, exact reviewed predecessor). Serving after admitted catalog: model-activate-review MODEL-ID | model-activate LOGIN GRANTS-JSON MODEL-ID (closed provision/start/stop grants).");
            println!("Isolated native QA: model-qa-review MODEL-ID execution|cancellation | model-qa-run LOGIN GRANT MODEL-ID execution|cancellation. Original Admin, separate model.qa grant/session, physically pinned data and actual resource lease required; factual inert reports only, no certification, ordinary inference, selection or activation. Installer --stage-model MODEL-ID prepares inert cached bytes for this path.");
            println!("Interrupted qualification metadata: model-qualification-pending-review MODEL-ID | model-qualification-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256 (original Admin finite retention, preserve unverified bytes).");
            println!("model-activation-reconcile [--abort-unchanged REVIEW-SHA256 | --publish-committed REVIEW-SHA256 | --complete-candidate REVIEW-SHA256 | --restore-prior REVIEW-SHA256 | --discard-orphan-backup REVIEW-SHA256]: inspect, clear a verified fence, roll forward, restore retained prior settings, or discard an unchanged orphan backup. Root-only; does not start the worker. Older pending markers without saved prior bytes cannot be restored.");
            println!("model-migrate-legacy: explicit installed-root migration of one validated older model environment and runtime lock; stops and restarts the managed model/reference services. No automatic boot migration.");
            println!("model-rollback-reconcile [--restore-prior REVIEW-SHA256]: inspect or explicitly restore one retained prior configuration after completed activation. Installed-root maintenance; requires an idle runtime lock, does not start services or prove readiness, consumes the rollback record, and preserves a fence on interruption. Not production Admin authorization.");
            println!("model-quarantine-reconcile [--clear-consistent REVIEW-SHA256]: inspect or explicitly clear an observed reconfiguration-failure quarantine for verified current settings or manual-only state. Installed root and idle runtime lock required; no worker start, readiness claim, recovery-disablement removal or product Admin grant.");
            println!("model-quarantine-reconcile --inspect-incomplete | --retain-incomplete REVIEW-SHA256: review and privately retain only an empty/truncated JSON quarantine before explicit clearance with verified current settings. Complete or otherwise malformed records remain fenced; no worker start or evidence deletion.");
            println!("model-validation-reconcile [--retain-abandoned REVIEW-SHA256]: inspect and retain an abandoned installed reconfiguration trial before reviewed clearance. Root, idle runtime and no live controller lock required; does not start services, remove quarantine/disablement or prove resource return.");
            println!("model-validation-reconcile --inspect-incomplete | --retain-incomplete REVIEW-SHA256: review and privately retain only empty/truncated trial JSON before explicit clearance, under exclusive recovery locking and verified current settings or manual-only state. No service start, reset of unknown state or evidence deletion.");
            println!("Luma native platform alpha\n\n  inventory\n  verify BUNDLE\n  install /dev/disk/by-id/EXACT-ID BUNDLE\n  update BUNDLE\n  recover unlock /dev/disk/by-id/EXACT-ID\n  recover export /dev/disk/by-id/EXACT-ID EMPTY-DESTINATION\n  recover repair-a|repair-b /dev/disk/by-id/EXACT-ID BUNDLE\n  recover repair-data /dev/disk/by-id/EXACT-ID\n  recover disable-model /dev/disk/by-id/EXACT-ID\n  status\n\nInstall requires local interactive disk confirmation and new credentials.\nLaboratory image: native acceptance and production custody are outstanding.");
            Ok(())
        }
        _ => Err("unknown operation or wrong argument count; run --help".into()),
    }
}
