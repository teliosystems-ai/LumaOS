//! Disposable store/crash fixture, compiled ONLY into the Rust test executable.
//! This substitutes synthetic computation, never native resource authority.
use crate::{artifact_catalog, artifacts, calculation, resources, workflow_resource, Result};
use std::io::Write;
use std::path::Path;

fn arguments(value: Option<&str>) -> Result<Vec<String>> {
    let args: Vec<String> = serde_json::from_str(value.ok_or("no publication fixture requested")?)?;
    match args.first().map(String::as_str) {
        Some("invoice-calculate") if args.len() == 1 => Ok(args),
        Some("artifact-publish-invoice") if args.len() == 2 => Ok(args),
        Some("artifact-catalog-publish-invoice") if args.len() == 4 => Ok(args),
        Some("artifact-reconcile") if args.len() == 3 => Ok(args),
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
    Ok(())
}

fn execute(args: &[String]) -> Result<serde_json::Value> {
    disposable()?;
    let generation = std::env::var("LUMA_PUBLICATION_TEST_GENERATION").unwrap_or("1".into());
    let parsed = generation.parse::<u64>()?;
    if parsed == 0 || parsed.to_string() != generation {
        return Err("noncanonical synthetic generation".into());
    }
    let fault = std::env::var("LUMA_PUBLICATION_TEST_RESOURCE_FAULT").unwrap_or_default();
    if !["", "calculate", "recheck-1", "recheck-2", "recheck-3"].contains(&fault.as_str()) {
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
        return;
    }
    let result = arguments(value.as_deref()).and_then(|args| execute(&args));
    match result {
        Ok(result) => {
            println!("\n{result}");
            std::io::stdout().flush().unwrap();
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("publication store fixture: {error}");
            std::process::exit(1);
        }
    }
}
