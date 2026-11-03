//! Disposable store/crash fixture, compiled ONLY into the Rust test executable.
//! This substitutes synthetic computation, never native resource authority.
//! Inside the verified container it also substitutes an empty fixed-handle
//! observation for the absent TPM, never an enrolled Admin or release anchor.
//! The past-gate route runs the unchanged command past the laboratory gate, which
//! an unenrolled tools container cannot open; the gate has its own native cases.
use crate::{
    artifact_catalog, artifacts, calculation, resources, workflow_resource, workflow_runs, Result,
};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static DISPOSABLE: AtomicBool = AtomicBool::new(false);

/// True only after `disposable` verified the CLI container and the TPM device
/// nodes are still absent; ordinary unit tests never set it.
pub(crate) fn absent_tpm_verified() -> bool {
    DISPOSABLE.load(Ordering::SeqCst)
        && !Path::new("/dev/tpm0").exists()
        && !Path::new("/dev/tpmrm0").exists()
}

fn arguments(value: Option<&str>) -> Result<Vec<String>> {
    let args: Vec<String> = serde_json::from_str(value.ok_or("no publication fixture requested")?)?;
    match args.first().map(String::as_str) {
        Some("invoice-calculate") if args.len() == 1 => Ok(args),
        Some("artifact-publish-invoice") if args.len() == 2 => Ok(args),
        Some("artifact-catalog-publish-invoice") if args.len() == 4 => Ok(args),
        Some("artifact-reconcile") if args.len() == 3 => Ok(args),
        Some("past-gate") if args.len() > 1 => Ok(args),
        _ => Err("unsupported publication fixture command".into()),
    }
}

/// The dispatch of `main` for a command the gate would have stopped. Nothing
/// here is synthetic: each arm is the production function with its arguments.
fn past_gate(args: &[String]) -> Result<()> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["invoice-calculate"] => calculation::calculate_stdin(),
        ["artifact-publish-invoice", request] => artifacts::publish_invoice(request),
        ["artifact-read", request] => artifacts::read(request),
        ["artifact-reconcile", request, review] => artifacts::reconcile(request, review),
        ["artifact-abort", request, review] => artifacts::abort(request, review),
        ["artifact-catalog-publish-invoice", request, artifact, expected] => {
            artifact_catalog::publish_invoice(request, artifact, expected)
        }
        ["artifact-catalog-read", artifact, version] => artifact_catalog::read(artifact, version),
        ["artifact-catalog-retain", request, review] => artifact_catalog::retain(request, review),
        ["artifact-catalog-import-legacy", request, review] => {
            artifact_catalog::import_legacy(request, review)
        }
        ["workflow-invoice-prepare", request, artifact, expected] => {
            workflow_runs::prepare(request, artifact, expected)
        }
        ["workflow-invoice-advance", request, review] => workflow_runs::advance(request, review),
        ["workflow-invoice-cancel", request, review] => workflow_runs::cancel(request, review),
        ["workflow-invoice-reconcile", request] => workflow_runs::reconcile(request, None),
        _ => Err("unsupported publication fixture command".into()),
    }
}

fn disposable() -> Result<()> {
    if !Path::new("/.dockerenv").is_file()
        || unsafe { libc::geteuid() } != 0
        || Path::new("/dev/tpm0").exists()
        || Path::new("/dev/tpmrm0").exists()
        || std::env::var("LD_PRELOAD").ok().as_deref() != Some("/tmp/luma-artifact-test.so")
        || std::fs::read_to_string("/proc/cmdline")?.trim()
            != "luma.mode=installed luma.slot=a luma.fixture=artifact-cli"
    {
        return Err("publication fixture requires the isolated disposable CLI container".into());
    }
    DISPOSABLE.store(true, Ordering::SeqCst);
    Ok(())
}

fn execute(args: &[String]) -> Result<Option<serde_json::Value>> {
    disposable()?;
    if args[0] == "past-gate" {
        println!("\nLUMA_PAST_GATE_OUTPUT");
        std::io::stdout().flush()?;
        past_gate(&args[1..])?;
        return Ok(None);
    }
    synthetic(args).map(Some)
}

fn synthetic(args: &[String]) -> Result<serde_json::Value> {
    let generation = std::env::var("LUMA_PUBLICATION_TEST_GENERATION").unwrap_or("1".into());
    let parsed = generation.parse::<u64>()?;
    if parsed == 0 || parsed.to_string() != generation {
        return Err("noncanonical synthetic generation".into());
    }
    let fault = std::env::var("LUMA_PUBLICATION_TEST_RESOURCE_FAULT").unwrap_or_default();
    if ![
        "",
        "calculate",
        "recheck-1",
        "recheck-2",
        "recheck-3",
        "recheck-4",
        "recheck-5",
    ]
    .contains(&fault.as_str())
    {
        return Err("unknown computation fixture fault".into());
    }
    if args[0] == "invoice-calculate" {
        if !fault.is_empty() {
            return Err("synthetic calculation fixture refused".into());
        }
        let source = calculation::source_stdin()?;
        let report = calculation::report_bytes(&source)?;
        return Ok(serde_json::json!({"synthetic_computation_fixture":true,
            "report":String::from_utf8(report)?,"source_sha256":artifacts::digest(&source)}));
    }
    if args[0] == "artifact-reconcile" {
        let receipt = artifacts::reconcile_invoice(
            &args[1],
            &args[2],
            |token, source, report, installation| {
                if !fault.is_empty()
                    || !workflow_resource::token_valid(token)
                    || artifacts::installation()? != installation
                    || serde_json::from_slice::<serde_json::Value>(report)?["source_sha256"]
                        != source
                {
                    return Err("synthetic reconciliation generation fenced".into());
                }
                Ok(())
            },
        )?;
        let mut value = serde_json::to_value(receipt)?;
        value["synthetic_computation_fixture"] = true.into();
        return Ok(value);
    }
    let calculate = |source: &[u8]| {
        if fault == "calculate" {
            return Err("synthetic computation admission refused".into());
        }
        Ok(workflow_resource::Calculation {
            report: calculation::report_bytes(source)?,
            lease: resources::Token {
                manager_epoch: "a".repeat(32),
                lease_id: artifacts::digest(source)[..32].into(),
                generation: parsed,
            },
        })
    };
    let mut checks = 0;
    let check = |result: &workflow_resource::Calculation, source: &[u8], installation: &str| {
        checks += 1;
        if fault == format!("recheck-{checks}") {
            return Err("synthetic computation generation fenced before publication".into());
        }
        if artifacts::installation()? != installation
            || calculation::report_bytes(source)? != result.report
            || !workflow_resource::token_valid(&result.lease)
        {
            return Err("synthetic computation fixture identity changed".into());
        }
        Ok(())
    };
    let mut value = match args[0].as_str() {
        "artifact-publish-invoice" => artifacts::invoice_publication(&args[1], calculate, check)?,
        "artifact-catalog-publish-invoice" => {
            artifact_catalog::invoice_publication(&args[1], &args[2], &args[3], calculate, check)?
        }
        _ => return Err("unsupported publication fixture command".into()),
    };
    value["synthetic_computation_fixture"] = true.into();
    Ok(value)
}

#[test]
fn disposable_publication() {
    // Normal unit execution tests the closed selector; no ignored test or
    // fixture dispatch is added to the installed executable.
    let value = std::env::var("LUMA_PUBLICATION_TEST_ARGS").ok();
    if value.is_none() {
        assert!(arguments(None).is_err());
        for invalid in [
            "null",
            "[]",
            "[\"artifact-read\",\"id\"]",
            "[\"artifact-publish-invoice\",\"id\",\"extra\"]",
        ] {
            assert!(arguments(Some(invalid)).is_err());
        }
        assert_eq!(
            arguments(Some("[\"artifact-publish-invoice\",\"id\"]"))
                .unwrap()
                .len(),
            2
        );
        assert!(arguments(Some("[\"past-gate\"]")).is_err());
        // Only the closing arm has this text, so no production function ran.
        for refused in ["artifact-store-init", "artifact-read"] {
            assert_eq!(
                past_gate(&[refused.to_string()]).unwrap_err().to_string(),
                "unsupported publication fixture command"
            );
        }
        return;
    }
    let result = arguments(value.as_deref()).and_then(|args| execute(&args));
    match result {
        Ok(result) => {
            if let Some(result) = result {
                println!("\n{result}");
            }
            std::io::stdout().flush().unwrap();
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("publication store fixture: {error}");
            std::process::exit(1);
        }
    }
}
