//! Principal-isolated catalogs. A content hash is never looked up across owners.
use super::*;

const BASE: &str = "/var/lib/luma-os/artifact-catalog-domains";

fn owner(principal: &str, generation: u64) -> Result<()> {
    if !io::hash(principal) || principal == "0".repeat(64) || generation == 0 {
        return Err("invalid artifact security domain".into());
    }
    Ok(())
}

pub(super) fn initialize_base() -> Result<()> {
    let parent = Path::new(BASE)
        .parent()
        .ok_or("missing artifact domains parent")?;
    safe_path(parent)?;
    let directory = scoped_read::open_directory(parent)?;
    ext4(&directory)?;
    io::mkdir_at(&directory, "artifact-catalog-domains")?;
    let base = io::child_directory(&directory, "artifact-catalog-domains")?;
    base.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

pub(super) fn open_at_base(
    base: &Path,
    installation: &str,
    principal: &str,
    create: bool,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Catalog> {
    safe_path(base)?;
    let directory = scoped_read::open_directory(base)?;
    io::private_directory(&directory)?;
    ext4(&directory)?;
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("artifact domain admission is busy".into());
    }
    // Bound namespace admission before allocating another domain.
    let names = io::names(&directory, MAX_RECORDS)?;
    if names.iter().any(|n| !io::hash(n)) {
        return Err("invalid artifact domain member; preserve state".into());
    }
    let name = io::digest(principal.as_bytes());
    let path = base.join(&name);
    if !names.contains(&name) {
        if !create || names.len() >= MAX_RECORDS {
            return Err("artifact owner domain unavailable".into());
        }
        check()?;
        initialize_domain(&path, installation, principal)?;
        directory.sync_all()?;
        check()?;
    }
    let result = Catalog::open_domain(&path, installation, principal)?;
    check()?;
    Ok(result)
}

pub(crate) fn owned_invoice_receipt(
    commit: &InvoiceCommit<'_>,
    principal: &str,
    generation: u64,
    bytes: &[u8],
) -> Result<serde_json::Value> {
    owner(principal, generation)?;
    let mut receipt: Receipt = serde_json::from_value(invoice_receipt(commit, bytes)?)?;
    receipt.owner = principal.into();
    receipt.owner_generation = Some(generation);
    receipt.environment = "installed".into();
    receipt.validate_owner(commit.installation, principal)?;
    Ok(serde_json::to_value(receipt)?)
}

pub(crate) fn commit_owned_invoice(
    commit: &InvoiceCommit<'_>,
    principal: &str,
    generation: u64,
    bytes: &[u8],
    replay_only: bool,
    mut coordinator_check: impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    if io::installation()? != commit.installation {
        return Err("workflow artifact installation changed".into());
    }
    let expected = owned_invoice_receipt(commit, principal, generation, bytes)?;
    let receipt: Receipt = serde_json::from_value(expected.clone())?;
    coordinator_check()?;
    let catalog = open_at_base(
        Path::new(BASE),
        commit.installation,
        principal,
        !replay_only,
        &mut coordinator_check,
    )?;
    if replay_only && !catalog.inventory()?.0.iter().any(|(_, r)| r == &receipt) {
        return Err("completed workflow lacks its exact owner receipt; preserve state".into());
    }
    catalog.publish(&receipt, bytes, |proposal| {
        if io::installation()? != proposal.installation
            || skills::admission()?["workflow_sha256"] != proposal.workflow_sha256
        {
            return Err("owner artifact signed workflow or installation changed".into());
        }
        coordinator_check()
    })?;
    coordinator_check()?;
    Ok(expected)
}

pub(crate) fn committed_owned_invoice(
    commit: &InvoiceCommit<'_>,
    principal: &str,
    generation: u64,
    bytes: &[u8],
) -> Result<InvoiceOutcome> {
    if io::installation()? != commit.installation {
        return Err("owner artifact reconciliation installation changed".into());
    }
    let expected =
        serde_json::from_value(owned_invoice_receipt(commit, principal, generation, bytes)?)?;
    let proof = InvoiceOutcome {
        catalog: open_at_base(
            Path::new(BASE),
            commit.installation,
            principal,
            false,
            || Ok(()),
        )?,
        expected,
    };
    proof.recheck()?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn receipts_bind_owner_generation_without_changing_legacy_canonical_bytes() {
        let installation = "a".repeat(64);
        let source = "b".repeat(64);
        let workflow = "c".repeat(64);
        let commit = InvoiceCommit {
            installation: &installation,
            request_id: "request-a",
            artifact_id: "artifact-a",
            expected_version: 0,
            workflow_sha256: &workflow,
            source_sha256: &source,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({"source_sha256":source})).unwrap();
        let legacy = invoice_receipt(&commit, &bytes).unwrap();
        assert!(legacy.get("owner_generation").is_none());
        let principal = "d".repeat(64);
        let owned = owned_invoice_receipt(&commit, &principal, 7, &bytes).unwrap();
        assert_eq!(owned["owner"], principal);
        assert_eq!(owned["owner_generation"], 7);
        let parsed: Receipt = serde_json::from_value(owned).unwrap();
        assert!(parsed
            .validate_owner(&installation, &"e".repeat(64))
            .is_err());
        assert!(owned_invoice_receipt(&commit, "local-root", 1, &bytes).is_err());
        assert!(owned_invoice_receipt(&commit, &principal, 0, &bytes).is_err());
    }

    #[test]
    fn owner_catalogs_never_share_content_or_accept_foreign_identity() {
        let fixture = super::super::tests::Fixture::new("owner-domains");
        let base = fixture.path.join("domains");
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let installation = "a".repeat(64);
        let principal_a = "d".repeat(64);
        let principal_b = "e".repeat(64);
        let a = open_at_base(&base, &installation, &principal_a, true, || Ok(())).unwrap();
        let b = open_at_base(&base, &installation, &principal_b, true, || Ok(())).unwrap();
        assert_ne!(
            a.objects.metadata().unwrap().ino(),
            b.objects.metadata().unwrap().ino()
        );
        let source = "b".repeat(64);
        let workflow = "c".repeat(64);
        let commit = InvoiceCommit {
            installation: &installation,
            request_id: "shared-request",
            artifact_id: "shared-artifact",
            expected_version: 0,
            workflow_sha256: &workflow,
            source_sha256: &source,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({"source_sha256":source})).unwrap();
        let ra: Receipt = serde_json::from_value(
            owned_invoice_receipt(&commit, &principal_a, 7, &bytes).unwrap(),
        )
        .unwrap();
        let rb: Receipt = serde_json::from_value(
            owned_invoice_receipt(&commit, &principal_b, 3, &bytes).unwrap(),
        )
        .unwrap();
        a.publish(&ra, &bytes, |_| Ok(())).unwrap();
        b.publish(&rb, &bytes, |_| Ok(())).unwrap();
        assert_ne!(
            io::open_at(&a.objects, &ra.content_sha256, libc::O_RDONLY, 0)
                .unwrap()
                .metadata()
                .unwrap()
                .ino(),
            io::open_at(&b.objects, &rb.content_sha256, libc::O_RDONLY, 0)
                .unwrap()
                .metadata()
                .unwrap()
                .ino()
        );
        let mut wrong_generation = ra.clone();
        wrong_generation.owner_generation = Some(8);
        assert!(a.publish(&wrong_generation, &bytes, |_| Ok(())).is_err());
        assert!(b.publish(&ra, &bytes, |_| Ok(())).is_err());
        assert!(a.root.metadata().unwrap().permissions().mode() & 0o077 == 0);
        drop(a);
        assert!(Catalog::open_domain(
            &base.join(io::digest(principal_a.as_bytes())),
            &installation,
            &principal_b
        )
        .is_err());
    }
}
