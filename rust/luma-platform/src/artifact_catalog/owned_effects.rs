//! Principal-owned artifact export and preparation preservation. Public review
//! never reads a private catalog without an independent current Read grant.
use super::*;
use crate::{
    finite_grants::{Action, Kind, Selector, Use},
    policy_decisions::EffectKind,
};

fn receipt(catalog: &Catalog, artifact: &str, version: &str) -> Result<Receipt> {
    let number = version.parse::<u64>()?;
    if !io::identifier(artifact) || number == 0 || number.to_string() != version {
        return Err("artifact export needs an exact canonical version".into());
    }
    let receipt = catalog
        .inventory()?
        .0
        .into_iter()
        .find(|(_, receipt)| receipt.artifact_id == artifact && receipt.version == number)
        .ok_or("owned artifact version unavailable")?
        .1;
    receipt.validate_owner(&catalog.installation, &catalog.owner)?;
    Ok(receipt)
}

fn preparation(catalog: &Catalog, request: &str) -> Result<(String, Use)> {
    if !io::identifier(request) {
        return Err("invalid exact owned preparation".into());
    }
    catalog.inventory()?;
    let already = io::names(&catalog.retained, MAX_FILES)?
        .iter()
        .any(|name| name == request);
    let bytes = io::read_member(
        if already {
            &catalog.retained
        } else {
            &catalog.pending
        },
        request,
        MAX_CONTENT,
    )?;
    let review = catalog.review(request, &bytes)?;
    let usage = Use {
        action: Action::Retain,
        selector: Selector {
            kind: Kind::Artifact,
            id: request.into(),
            generation: 1,
            digest: review.clone(),
        },
        input_bytes: bytes.len() as u64,
        output_bytes: 0,
        units: 1,
    };
    usage.validate()?;
    Ok((review, usage))
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if !matches!(args.first().map(String::as_str),
        Some("artifact-owned-export-review") if args.len() == 5)
        && !matches!(args.first().map(String::as_str),
        Some("artifact-owned-export") if args.len() == 6)
        && !matches!(args.first().map(String::as_str),
        Some("artifact-owned-retain-proposal") if args.len() == 4)
        && !matches!(args.first().map(String::as_str),
        Some("artifact-owned-retain") if args.len() == 6)
    {
        return Err("expected artifact-owned-export-review LOGIN READ-GRANT ARTIFACT VERSION | artifact-owned-export LOGIN READ-GRANT EXPORT-GRANT ARTIFACT VERSION | artifact-owned-retain-proposal LOGIN READ-GRANT REQUEST | artifact-owned-retain LOGIN READ-GRANT RETAIN-GRANT REQUEST REVIEW".into());
    }
    let (binding, account, installation) = gc_cli::subject(&args[1])?;
    let read = gc_cli::inspection(&installation, &account)?;
    crate::admin_governance::with_grant(&args[1], &args[2], &read, |reader| {
        gc_cli::check_owner(&binding, &account, reader)?;
        let catalog = gc_cli::catalog(&installation, &account)?;
        match args[0].as_str() {
            "artifact-owned-export-review" => {
                let exact = receipt(&catalog, &args[3], &args[4])?;
                let usage = export_usage(&exact)?;
                gc_cli::check_owner(&binding, &account, reader)?;
                println!(
                    "{}",
                    serde_json::json!({"usage":usage,"receipt":exact,
                    "content_exported":false,"grant_issued":false})
                );
                Ok(())
            }
            "artifact-owned-export" => {
                let exact = receipt(&catalog, &args[4], &args[5])?;
                let usage = export_usage(&exact)?;
                gc_cli::check_owner(&binding, &account, reader)?;
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    gc_cli::check_owner(&binding, &account, reader)?;
                    gc_cli::check_owner(&binding, &account, boundary)?;
                    if receipt(&catalog, &args[4], &args[5])? != exact {
                        return Err("owned export receipt changed".into());
                    }
                    let pending =
                        boundary.effect_begin(&exact.request_id, EffectKind::ArtifactExport)?;
                    let bytes =
                        io::read_member(&catalog.objects, &exact.content_sha256, MAX_CONTENT)?;
                    if bytes.len() as u64 != exact.content_bytes
                        || io::digest(&bytes) != exact.content_sha256
                    {
                        return Err("owned export content integrity failed".into());
                    }
                    let mut output = std::io::stdout().lock();
                    for block in bytes.chunks(32 * 1024) {
                        gc_cli::check_owner(&binding, &account, reader)?;
                        gc_cli::check_owner(&binding, &account, boundary)?;
                        output.write_all(block)?;
                    }
                    output.flush()?;
                    if receipt(&catalog, &args[4], &args[5])? != exact {
                        return Err(
                            "owned export outcome uncertain; preserve delivered bytes".into()
                        );
                    }
                    gc_cli::check_owner(&binding, &account, reader)?;
                    gc_cli::check_owner(&binding, &account, boundary)?;
                    boundary.effect_complete(pending, &io::digest(&serde_json::to_vec(&exact)?))
                })
            }
            "artifact-owned-retain-proposal" => {
                let (review, usage) = preparation(&catalog, &args[3])?;
                gc_cli::check_owner(&binding, &account, reader)?;
                println!(
                    "{}",
                    serde_json::json!({"usage":usage,"review_sha256":review,
                    "bytes_deleted":false,"grant_issued":false})
                );
                Ok(())
            }
            "artifact-owned-retain" => {
                let (review, usage) = preparation(&catalog, &args[4])?;
                if review != args[5] {
                    return Err("owned preparation review changed".into());
                }
                gc_cli::check_owner(&binding, &account, reader)?;
                crate::admin_governance::with_grant(&args[1], &args[3], &usage, |boundary| {
                    gc_cli::check_owner(&binding, &account, reader)?;
                    gc_cli::check_owner(&binding, &account, boundary)?;
                    let pending = boundary.effect_begin(&args[4], EffectKind::Retention)?;
                    catalog.retain_checked(&args[4], &review, || {
                        gc_cli::check_owner(&binding, &account, reader)?;
                        gc_cli::check_owner(&binding, &account, boundary)
                    })?;
                    boundary.effect_complete(pending, &review)?;
                    println!(
                        "{}",
                        serde_json::json!({"request_id":args[4],"state":"retained",
                        "principal":account.id,"review_sha256":review,"bytes_deleted":false})
                    );
                    Ok(())
                })
            }
            _ => Err("closed owned artifact command unavailable".into()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_export_versions_and_preparation_reviews_bind_distinct_owners() {
        let fixture = super::super::tests::Fixture::new("owned-export");
        let base = fixture.path.join("domains");
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let installation = "a".repeat(64);
        let first = "d".repeat(64);
        let second = "e".repeat(64);
        let a = domains::open_at_base(&base, &installation, &first, true, || Ok(())).unwrap();
        let b = domains::open_at_base(&base, &installation, &second, true, || Ok(())).unwrap();
        let source = "b".repeat(64);
        let workflow = "c".repeat(64);
        let commit = InvoiceCommit {
            installation: &installation,
            request_id: "request",
            artifact_id: "report",
            expected_version: 0,
            workflow_sha256: &workflow,
            source_sha256: &source,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({"source_sha256":source})).unwrap();
        let proposed: Receipt = serde_json::from_value(
            domains::owned_invoice_receipt(&commit, &first, 9, &bytes).unwrap(),
        )
        .unwrap();
        a.publish(&proposed, &bytes, |_| Ok(())).unwrap();
        assert_eq!(receipt(&a, "report", "1").unwrap(), proposed);
        assert!(receipt(&b, "report", "1").is_err());
        for version in ["0", "01", "+1", "1 ", "2"] {
            assert!(receipt(&a, "report", version).is_err());
        }
        assert_eq!(
            export_usage(&proposed).unwrap().output_bytes,
            bytes.len() as u64
        );
        for catalog in [&a, &b] {
            let mut staged = io::open_at(
                &catalog.pending,
                "preparation",
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o400,
            )
            .unwrap();
            staged.write_all(b"preserve exact pending bytes").unwrap();
            staged.sync_all().unwrap();
            catalog.pending.sync_all().unwrap();
        }
        let (review, usage) = preparation(&a, "preparation").unwrap();
        assert_ne!(review, preparation(&b, "preparation").unwrap().0);
        assert_eq!(usage.selector.digest, review);
        assert!(b.retain_checked("preparation", &review, || Ok(())).is_err());
        a.retain_checked("preparation", &review, || Ok(())).unwrap();
        assert_eq!(preparation(&a, "preparation").unwrap().0, review);
    }
}
