//! Native Linux platform boundary. No model-provided command or shell execution.
mod admin_credentials;
mod admin_enrollment;
mod admin_governance;
mod admin_journal;
mod admin_roles;
mod admin_service;
mod artifact_catalog;
mod artifacts;
mod authentication;
mod broker_effects;
mod bundle;
mod calculation;
mod disk;
mod model;
mod owner_credential;
mod platform;
mod principal;
mod recovery_export;
mod scoped_read;
mod sealed_credential;
mod service;
mod skills;
mod sqlite;
mod staging;
mod tpm;
mod utc_bounds;
mod utc_keeper;
mod utc_policy;
mod utc_protocol;
mod utc_receiver;
mod utc_stream;
mod workflow;
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
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
        Some("admin-bootstrap") if args.len() == 2 => admin_governance::bootstrap(&args[1], None),
        Some("admin-bootstrap") if args.len() == 4 && args[2] == "--activate" => {
            admin_governance::bootstrap(&args[1], Some(&args[3]))
        }
        Some("admin-governance-status") if args.len() == 2 => {
            admin_governance::catalog_status(&args[1])
        }
        Some("admin-service") if args.len() == 1 => admin_service::serve(),
        Some("admin-service-request") if args.len() == 1 => admin_service::connection(),
        Some("admin-client") => admin_service::client(&args[1..]),
        Some("admin-activity-register") | Some("admin-role-define") => {
            admin_governance::catalog_command(&args)
        }
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
        Some("models") if args.len() == 1 => model::list(),
        Some("model-install") if args.len() == 2 => model::install(&args[1]),
        Some("model-install-check") if args.len() == 2 => model::install_check(&args[1]),
        Some("model-migrate-legacy") if args.len() == 1 => model::migrate_legacy(),
        Some("model-activation-reconcile") if args.len() == 1 => model::activation_reconcile(None),
        Some("model-activation-reconcile") if args.len() == 3 => {
            model::activation_reconcile(Some((&args[1], &args[2])))
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
            require_root()?;
            platform::require_installed()?;
            if !std::process::Command::new("/usr/bin/python3")
                .args(["-I", "/usr/libexec/luma-os/model-chat.py"])
                // The fixed helper parses only bounded numeric options. No
                // interpreter flags, endpoint, path or shell is caller-selected.
                .args(&args[1..])
                .env_clear()
                .env("PATH", "/usr/bin")
                .status()?
                .success()
            {
                return Err("local inference failed; manual operation remains available".into());
            }
            Ok(())
        }
        Some("update") if args.len() == 2 => platform::update(Path::new(&args[1])),
        Some("recover") if args.len() >= 3 => platform::recover(&args[1..]),
        Some("broker") if args.len() == 1 => service::serve(),
        Some("status") if args.len() == 1 => service::client("status"),
        Some("boot-health") if args.len() == 1 => platform::boot_health(),
        Some("boot-failed") if args.len() == 1 => platform::boot_failed(),
        Some("init-data") if args.len() == 2 => platform::init_data(&args[1]),
        Some("help" | "--help") | None => {
            println!("Local TPM diagnostics: tpm-probe | admin-checkpoint-status (root only; read-only; neither enrolls nor grants Admin). External Admin deployment is deferred.");
            println!("admin-checkpoint-enroll LOGIN --existing-owner: explicit installed-root checkpoint enrollment with local PAM and hidden custodian owner authorization; retains interrupted attempts; does not grant product Admin.");
            println!("admin-checkpoint-enrollment-inspect: read-only retained-intent and fixed TPM-handle observation; does not repair, retry, delete or grant Admin.");
            println!("admin-checkpoint-enrollment-resume LOGIN REVIEW-SHA256: explicit fresh-auth continuation only from a reviewed, bound parent with no NV proposal or index; never retries parent allocation.");
            println!("admin-checkpoint-enrollment-reconcile [--publish-committed LOGIN REVIEW-SHA256]: inspect, publish or replay an exact TPM-committed inert enrollment, including lost publication acknowledgement. Publication/replay requires fresh principal-bound PAM; never repeats a TPM write or activates product Admin.");
            println!("admin-checkpoint-reconcile [--publish-committed REVIEW-SHA256]: inspect or explicitly publish a TPM-proven pending inert audit commit; never replays effects or resets TPM state. Requires existing enrollment and credential delivery.");
            println!("admin-auth-check LOGIN: installed-system, controlling-terminal account authentication diagnostic; does not enroll or grant product Admin.");
            println!("admin-bootstrap LOGIN [--activate REVIEW-SHA256]: freshly authenticate the enrolled human, inspect or explicitly commit the installation-bound Admin bootstrap receipt. No role delegation, signing, resource capability or effect execution is enabled by this command.");
            println!("admin-governance-status LOGIN: fresh principal-bound inspection of the TPM-verified finite activity/role definition catalog; no assignment or effect grant.");
            println!("admin-client LOGIN status | LOGIN register REQUEST ACTIVITY | LOGIN define REQUEST ROLE VERSION ACTIVITY... [--commit REVIEW]: one fresh PAM-authenticated request to the fixed local Admin service, from the selected human account without sudo. No assignments or effect grants.");
            println!("admin-activity-register LOGIN REQUEST ACTIVITY [--commit REVIEW-SHA256]: inspect or explicitly commit one declared finite activity.");
            println!("admin-role-define LOGIN REQUEST ROLE EXPECTED-VERSION ACTIVITY... [--commit REVIEW-SHA256]: finite registered activities only; version 0 creates, the exact current version updates. Defines no assignment or resource grant.");
            println!("Install requires local TPM2 admission before any disk write. admin-install-check is read-only and does not enroll Admin; explicit checkpoint enrollment remains separate from product Admin activation.");
            println!("Maintenance: staging-clean | model-clean (root only; preserves active operations and unknown files).");
            println!("broker-effect-status: root-only installed laboratory worker-effect receipts; uncertain effects are fenced, never automatically replayed. Not product Admin or TPM rollback protection.");
            println!("workflow-validate GRAPH.json: read-only closed native file-to-artifact DAG check; does not admit signed skills or execute effects.");
            println!("Durable laboratory invoice coordinator (installed root, ext4): workflow-store-init | workflow-store-status | workflow-invoice-prepare REQUEST-ID ARTIFACT-ID EXPECTED-VERSION (CSV stdin snapshot) | workflow-invoice-status REQUEST-ID | workflow-invoice-advance REQUEST-ID REVIEW-SHA256 | workflow-invoice-cancel REQUEST-ID REVIEW-SHA256. Each advance checkpoints the next native step; publication checkpoints Applying before calling the catalog, and exact recovery verifies its idempotent receipt. Cancellation is accepted only before Applying. Not product Admin, folder grants, generic DAG execution or full G2.");
            println!("workflow-invoice-reconcile REQUEST-ID [--publish-committed REVIEW-SHA256]: inspect and explicitly acknowledge an exact already committed catalog receipt, including after skill withdrawal. Keeps coordinator/catalog ownership through the proof recheck; never publishes an artifact or infers completion from absent evidence. Installed-root lab audit recovery, not a grant or product Admin.");
            println!("skill-registry-status: verify the fixed image-owned lab skill signature, exact descriptors and bound workflow; read-only admission, no execution or effect grant.");
            println!("invoice-calculate: bounded pure invoice CSV on stdin to deterministic monthly JSON totals; no file grant, workflow execution or artifact write.");
            println!("Managed laboratory invoice artifacts (installed root only): artifact-store-init (explicit older-install setup; refuses existing state) | artifact-store-status | artifact-publish-invoice REQUEST-ID (CSV stdin; signed workflow admission) | artifact-read REQUEST-ID | artifact-reconcile REQUEST-ID REVIEW-SHA256 (publish a complete reviewed preparation) | artifact-abort REQUEST-ID ABORT-REVIEW-SHA256 (retain reviewed partial bytes; never reuse the request). Root-owned storage; product Admin, folder grants and TPM rollback protection remain pending.");
            println!("Native ADR-0003 catalog (installed root only, ext4): artifact-catalog-init | artifact-catalog-status | artifact-catalog-publish-invoice REQUEST-ID ARTIFACT-ID EXPECTED-VERSION (CSV stdin; 0 creates version 1) | artifact-catalog-read ARTIFACT-ID VERSION | artifact-catalog-retain REQUEST-ID RETAIN-REVIEW-SHA256. WAL metadata and append-only receipts commit after synchronized content objects. No automatic migration/deletion, product Admin grants or rollback protection.");
            println!("Explicit legacy copy import (installed root only): artifact-catalog-legacy-inspect LEGACY-REQUEST-ID | artifact-catalog-import-legacy LEGACY-REQUEST-ID REVIEW-SHA256. Review binds the complete source receipt; fixed source/catalog locks and current signed workflow checks span publication. Stable mapped IDs provide exact replay. Original data/receipts and retained preparations are preserved; no automatic migration or format downgrade.");
            println!("Model operations: models | model-install-check MODEL-ID | model-install MODEL-ID | model-chat [--timeout-seconds 1..1800] [--max-tokens 1..128] (prompt on stdin).\nInstaller accepts --model MODEL-ID or --model manual-only; otherwise prompts.\nA successful read-only preflight is not a reservation; activation rechecks after stopping the worker. Weights are acquired from pinned HTTPS publisher URLs after hardware admission.");
            println!("model-activation-reconcile [--abort-unchanged REVIEW-SHA256 | --publish-committed REVIEW-SHA256 | --complete-candidate REVIEW-SHA256]: inspect, clear an unchanged/committed fence, or explicitly roll a partial activation forward to verified candidate settings. Root-only; does not start the worker.");
            println!("model-migrate-legacy: explicit installed-root migration of one validated older model environment and runtime lock; stops and restarts the managed model/reference services. No automatic boot migration.");
            println!("Luma native platform alpha\n\n  inventory\n  verify BUNDLE\n  install /dev/disk/by-id/EXACT-ID BUNDLE\n  update BUNDLE\n  recover unlock /dev/disk/by-id/EXACT-ID\n  recover export /dev/disk/by-id/EXACT-ID EMPTY-DESTINATION\n  recover repair-a|repair-b /dev/disk/by-id/EXACT-ID BUNDLE\n  recover repair-data /dev/disk/by-id/EXACT-ID\n  recover disable-model /dev/disk/by-id/EXACT-ID\n  status\n\nInstall requires local interactive disk confirmation and new credentials.\nLaboratory image: native acceptance and production custody are outstanding.");
            Ok(())
        }
        _ => Err("unknown operation or wrong argument count; run --help".into()),
    }
}
