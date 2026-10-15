//! Current-generation owner-only discovery. An index is disposable data, never
//! identity, authorization, a grant, a private cross-owner corpus or a cache.
use super::*;

fn deliver(
    result: &serde_json::Value,
    output: &mut impl Write,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(result)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_CONTENT {
        return Err("owned search exceeds its independent Read output allowance".into());
    }
    // Acquire the output handle before the final authority observation. Each
    // fixed-size delivery is independently fenced, including after flush.
    for block in bytes.chunks(32 * 1024) {
        check()?;
        output.write_all(block)?;
    }
    check()?;
    output.flush()?;
    check()
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    if args.len() != 5 || args[0] != "artifact-owned-search" {
        return Err("expected artifact-owned-search LOGIN READ-GRANT QUERY LIMIT".into());
    }
    // Reject malformed public input before any private catalog admission.
    search::query(&args[3], &args[4])?;
    crate::require_root()?;
    crate::platform::require_installed()?;
    let (binding, account, installation) = gc_cli::subject(&args[1])?;
    let usage = gc_cli::inspection(&installation, &account)?;
    crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let mut check = || gc_cli::check_owner(&binding, &account, boundary);
        check()?;
        let catalog = domains::open_at_base(
            Path::new("/var/lib/luma-os/artifact-catalog-domains"),
            &installation,
            &account.id,
            false,
            &mut check,
        )?;
        let result = search::search_checked(
            &catalog,
            &args[3],
            &args[4],
            Some(account.generation),
            &mut check,
        )?;
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        deliver(&result, &mut output, &mut check)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn catalog(fixture: &super::super::tests::Fixture, owner: &str) -> Catalog {
        let base = fixture.path.join("domains");
        if !base.exists() {
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        }
        domains::open_at_base(&base, &"a".repeat(64), owner, true, || Ok(())).unwrap()
    }

    fn publish(
        catalog: &Catalog,
        request: &str,
        artifact: &str,
        expected: u64,
        generation: u64,
        title: &str,
    ) {
        let installation = "a".repeat(64);
        let source = "b".repeat(64);
        let workflow = "c".repeat(64);
        let commit = InvoiceCommit {
            installation: &installation,
            request_id: request,
            artifact_id: artifact,
            expected_version: expected,
            workflow_sha256: &workflow,
            source_sha256: &source,
        };
        let bytes =
            serde_json::to_vec(&serde_json::json!({"title":title,"source_sha256":source})).unwrap();
        let receipt = serde_json::from_value(
            domains::owned_invoice_receipt(&commit, &catalog.owner, generation, &bytes).unwrap(),
        )
        .unwrap();
        catalog.publish(&receipt, &bytes, |_| Ok(())).unwrap();
    }

    fn find(catalog: &Catalog, text: &str, generation: u64) -> serde_json::Value {
        search::search_checked(catalog, text, "100", Some(generation), &mut || Ok(())).unwrap()
    }

    #[test]
    fn current_generation_search_is_domain_local_and_does_not_resurrect_old_versions() {
        let fixture = super::super::tests::Fixture::new("owned-search-domains");
        let a = catalog(&fixture, &"d".repeat(64));
        let b = catalog(&fixture, &"e".repeat(64));
        publish(&a, "old-a", "alpha", 0, 6, "obsolete secretalpha");
        publish(&a, "new-a", "alpha", 1, 7, "current secretalpha");
        publish(&a, "second-a", "beta", 0, 7, "current secretalpha");
        publish(&b, "other-b", "alpha", 0, 7, "current secretbeta");
        assert!(find(&a, "secretbeta", 7)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(find(&b, "secretalpha", 7)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(find(&a, "obsolete", 7)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(find(&a, "obsolete", 6)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        let result = find(&a, "CURRENT secretalpha", 7);
        assert_eq!(result["environment"], "installed");
        assert_eq!(result["owner_generation"], 7);
        assert_eq!(result["current_documents"], 2);
        assert_eq!(result["hits"][0]["artifact_id"], "alpha");
        assert_eq!(result["hits"][0]["version"], 2);
        assert_eq!(result["hits"][1]["artifact_id"], "beta");
        assert_eq!(result, find(&a, "CURRENT secretalpha", 7));
        assert!(find(&a, "current", 8)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(search::search_checked(&a, "current", "1", None, &mut || Ok(())).is_err());
        assert!(search::search_checked(&a, "current", "1", Some(0), &mut || Ok(())).is_err());
    }

    #[test]
    fn every_authority_checkpoint_can_refuse_rebuild_without_delivering_results() {
        let fixture = super::super::tests::Fixture::new("owned-search-revocation");
        let catalog = catalog(&fixture, &"d".repeat(64));
        // Large punctuation spans and scalar arrays still require checkpoints;
        // term-free input cannot bypass continuous authorization observations.
        publish(
            &catalog,
            "one",
            "alpha",
            0,
            3,
            &format!("current {}", " ".repeat(70_000)),
        );
        let observed = Cell::new(0);
        search::search_checked(&catalog, "current", "1", Some(3), &mut || {
            observed.set(observed.get() + 1);
            Ok(())
        })
        .unwrap();
        assert!(observed.get() > 20);
        for revoked_at in 1..=observed.get() {
            let count = Cell::new(0);
            let result = search::search_checked(&catalog, "current", "1", Some(3), &mut || {
                count.set(count.get() + 1);
                if count.get() >= revoked_at {
                    Err("account disabled, generation changed or Read grant revoked".into())
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "revocation checkpoint {revoked_at}");
            assert_eq!(count.get(), revoked_at);
        }
    }

    #[test]
    fn changed_catalog_during_rebuild_is_not_delivered_and_next_rebuild_uses_new_current_version() {
        let fixture = super::super::tests::Fixture::new("owned-search-change");
        let catalog = catalog(&fixture, &"d".repeat(64));
        publish(&catalog, "one", "alpha", 0, 1, "first");
        let calls = Cell::new(0);
        let mutate_at = Cell::new(usize::MAX);
        // Find the checkpoint at which the actual index begins normalization.
        // A read-only baseline counts the initial complete inventory boundary.
        catalog
            .inventory_checked(&mut || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap();
        mutate_at.set(calls.get() + 4);
        calls.set(0);
        let result = search::search_checked(&catalog, "first", "1", Some(1), &mut || {
            calls.set(calls.get() + 1);
            if calls.get() == mutate_at.get() {
                publish(&catalog, "two", "alpha", 1, 1, "second");
            }
            Ok(())
        });
        assert!(calls.get() >= mutate_at.get());
        assert!(result.is_err());
        assert!(find(&catalog, "first", 1)["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(find(&catalog, "second", 1)["hits"][0]["version"], 2);
    }

    #[test]
    fn malformed_queries_and_current_generation_are_rejected_before_private_reads() {
        let fixture = super::super::tests::Fixture::new("owned-search-input");
        let catalog = catalog(&fixture, &"d".repeat(64));
        for (text, limit) in [
            ("", "1"),
            ("---", "1"),
            ("x\ny", "1"),
            ("x", "01"),
            ("x", "101"),
            ("a b c d e f g h i", "1"),
        ] {
            assert!(
                search::search_checked(&catalog, text, limit, Some(1), &mut || {
                    panic!("invalid query read private state")
                })
                .is_err()
            );
        }
        for args in [
            vec![],
            vec!["artifact-owned-search".into()],
            vec!["other".into(); 5],
        ] {
            assert!(command(&args).is_err());
        }
    }

    #[test]
    fn bounded_private_reads_discard_revoked_or_concurrently_modified_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = super::super::tests::Fixture::new("owned-search-read-checks");
        let catalog = catalog(&fixture, &"d".repeat(64));
        let bytes = vec![b'x'; 100_000];
        io::write_member(&catalog.pending, "bounded", &bytes, 0o400).unwrap();
        let checks = Cell::new(0);
        assert_eq!(
            io::read_member_checked(&catalog.pending, "bounded", MAX_CONTENT, || {
                checks.set(checks.get() + 1);
                Ok(())
            })
            .unwrap(),
            bytes
        );
        assert!(checks.get() >= 12);
        for revoked_at in 1..=checks.get() {
            let calls = Cell::new(0);
            assert!(
                io::read_member_checked(&catalog.pending, "bounded", MAX_CONTENT, || {
                    calls.set(calls.get() + 1);
                    if calls.get() >= revoked_at {
                        Err("Read grant revoked".into())
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            assert_eq!(calls.get(), revoked_at);
        }
        let path = fixture
            .path
            .join("domains")
            .join(io::digest(catalog.owner.as_bytes()))
            .join("pending/bounded");
        let calls = Cell::new(0);
        assert!(
            io::read_member_checked(&catalog.pending, "bounded", MAX_CONTENT, || {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                    fs::write(&path, vec![b'y'; bytes.len()])?;
                }
                Ok(())
            })
            .is_err()
        );
        assert!(io::read_member_checked(&catalog.pending, "bounded", 99_999, || Ok(())).is_err());
    }

    #[test]
    fn delivery_rechecks_current_authority_before_first_byte_each_block_and_after_flush() {
        let result = serde_json::json!({"test": "x".repeat(70_000)});
        for revoked_at in 1..=5 {
            let mut bytes = Vec::new();
            let observed = Cell::new(0);
            assert!(deliver(&result, &mut bytes, || {
                observed.set(observed.get() + 1);
                if observed.get() >= revoked_at {
                    Err("current owner generation or independent Read grant changed".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
            if revoked_at == 1 {
                assert!(bytes.is_empty());
            }
            if revoked_at == 2 {
                assert_eq!(bytes.len(), 32 * 1024);
            }
        }
        let mut bytes = Vec::new();
        deliver(&result, &mut bytes, || Ok(())).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            result
        );
        let oversized = serde_json::json!("x".repeat(MAX_CONTENT as usize));
        let mut bytes = Vec::new();
        assert!(deliver(&oversized, &mut bytes, || Ok(())).is_err());
        assert!(bytes.is_empty());
    }
}
