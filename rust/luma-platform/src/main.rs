//! Native Linux platform boundary. No model-provided command or shell execution.
mod admin_credentials;
mod admin_enrollment;
mod admin_journal;
mod authentication;
mod broker_effects;
mod bundle;
mod disk;
mod model;
mod owner_credential;
mod platform;
mod principal;
mod recovery_export;
mod sealed_credential;
mod service;
mod staging;
mod tpm;

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("this operation requires a local administrator".into());
    }
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
            println!("admin-checkpoint-enrollment-reconcile [--publish-committed LOGIN REVIEW-SHA256]: inspect or explicitly publish only an authenticated TPM-committed pending inert enrollment; never repeats a TPM write.");
            println!("admin-checkpoint-reconcile [--publish-committed REVIEW-SHA256]: inspect or explicitly publish a TPM-proven pending inert audit commit; never replays effects or resets TPM state. Requires existing enrollment and credential delivery.");
            println!("admin-auth-check LOGIN: installed-system, controlling-terminal account authentication diagnostic; does not enroll or grant product Admin.");
            println!("Install requires local TPM2 admission before any disk write. admin-install-check is read-only and does not enroll Admin; explicit checkpoint enrollment remains separate from product Admin activation.");
            println!("Maintenance: staging-clean | model-clean (root only; preserves active operations and unknown files).");
            println!("broker-effect-status: root-only installed laboratory worker-effect receipts; uncertain effects are fenced, never automatically replayed. Not product Admin or TPM rollback protection.");
            println!("Model operations: models | model-install-check MODEL-ID | model-install MODEL-ID | model-chat [--timeout-seconds 1..1800] [--max-tokens 1..128] (prompt on stdin).\nInstaller accepts --model MODEL-ID or --model manual-only; otherwise prompts.\nA successful read-only preflight is not a reservation; activation rechecks after stopping the worker. Weights are acquired from pinned HTTPS publisher URLs after hardware admission.");
            println!("model-activation-reconcile [--abort-unchanged REVIEW-SHA256 | --publish-committed REVIEW-SHA256]: inspect or explicitly clear a pending model-activation fence only for an unchanged prior state or a verified consistent candidate. Does not start the worker.");
            println!("model-migrate-legacy: explicit installed-root migration of one validated older model environment and runtime lock; stops and restarts the managed model/reference services. No automatic boot migration.");
            println!("Luma native platform alpha\n\n  inventory\n  verify BUNDLE\n  install /dev/disk/by-id/EXACT-ID BUNDLE\n  update BUNDLE\n  recover unlock /dev/disk/by-id/EXACT-ID\n  recover export /dev/disk/by-id/EXACT-ID EMPTY-DESTINATION\n  recover repair-a|repair-b /dev/disk/by-id/EXACT-ID BUNDLE\n  recover repair-data /dev/disk/by-id/EXACT-ID\n  recover disable-model /dev/disk/by-id/EXACT-ID\n  status\n\nInstall requires local interactive disk confirmation and new credentials.\nLaboratory image: native acceptance and production custody are outstanding.");
            Ok(())
        }
        _ => Err("unknown operation or wrong argument count; run --help".into()),
    }
}
