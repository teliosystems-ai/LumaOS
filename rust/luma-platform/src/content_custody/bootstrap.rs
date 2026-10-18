//! Explicit original-Admin recovery of ONLY the missing initial journal. No
//! advanced head, nonempty content namespace or foreign sealed identity is
//! adopted; acknowledgement of an identical completed creation is idempotent.
use super::*;
use crate::finite_grants::{Action, Kind, Selector, Use};

fn scope(action: Action, id: &str, sha: &str) -> Result<Use> {
    digest(sha)?;
    let usage = Use {
        action,
        selector: Selector {
            kind: if action == Action::Read {
                Kind::File
            } else {
                Kind::Resource
            },
            id: id.into(),
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
fn inspection(installation: &str) -> Result<Use> {
    digest(installation)?;
    scope(
        Action::Read,
        "content-custody-bootstrap-read-v1",
        &hash(&serde_json::to_vec(&(
            "luma-content-empty-bootstrap-inspection-v1",
            installation,
        ))?),
    )
}
fn review(
    installation: &str,
    empty: &super::super::EmptyNamespace,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    check()?;
    empty.check()?;
    let genesis = empty.genesis(installation)?;
    let wanted = Journal::empty(installation, genesis)?.bytes()?;
    let files = Files::installed();
    files.absent(PREPARED)?;
    files.absent(PUBLISHED)?;
    match fs::symlink_metadata(files.root.join("genesis.json")) {
        Ok(_) => genesis::validate(&files.read("genesis.json", check)?, installation, genesis)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(files.root.join(JOURNAL)) {
        Ok(_) => {
            if files.read(JOURNAL, check)? != wanted {
                return Err("bootstrap preserves different existing history".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    check()?;
    let config = super::super::immutable(
        &std::path::Path::new(DIRECTORY).join("sealed/anchor.json"),
        4096,
    )?;
    let configuration: super::super::Configuration = super::super::canonical(&config)?;
    configuration.validate()?;
    if configuration.installation != installation
        || tpm::decode::<32>(&configuration.genesis_event)? != genesis
    {
        return Err(
            "bootstrap refuses replaced EMPTY namespaces or mismatched commissioning metadata"
                .into(),
        );
    }
    let result = serde_json::json!({"schema_version":1,"purpose":"luma-content-explicit-empty-bootstrap-v1",
        "installation":installation,"genesis_event":bundle::hex(&genesis),
        "expected_checkpoint_head":bundle::hex(&tpm::extend_value([0;32],genesis)),"NV_authenticated":false,
        "config_sha256":hash(&config),"empty_namespace":empty.descriptor(installation)?,"journal_sha256":hash(&wanted),
        "operation":"retain-exact-public-genesis-proof-then-authenticate-initial-NV-and-create-or-acknowledge-identical-history"});
    empty.check()?;
    check()?;
    Ok(result)
}

pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let name = args
        .first()
        .map(String::as_str)
        .ok_or("bootstrap command missing")?;
    let proposal = name == "content-custody-bootstrap-proposal";
    let inspect = name == "content-custody-bootstrap-review";
    if (!proposal && !inspect && name != "content-custody-bootstrap")
        || args.len()
            != if proposal {
                2
            } else if inspect {
                3
            } else {
                4
            }
    {
        return Err("expected content-custody-bootstrap-proposal LOGIN | content-custody-bootstrap-review LOGIN READ-GRANT | content-custody-bootstrap LOGIN RECOVERY-GRANT EXACT-REVIEW".into());
    }
    let installation = crate::artifacts::installation()?;
    let read = inspection(&installation)?;
    if proposal {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"usage":read,"private_authority_read":false,
            "authority_returned":false,"filesystem_changed":false})
        );
        return Ok(());
    }
    let usage = if inspect {
        read
    } else {
        scope(
            Action::RecoverResource,
            "content-custody-bootstrap-v1",
            &args[3],
        )?
    };
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |guard| {
        guard.require_admin()?;
        let empty = super::super::EmptyNamespace::capture(std::path::Path::new(
            "/var/lib/luma-os/content-store",
        ))?;
        guard.require_admin()?;
        let selected = review(&installation, &empty, &mut || guard.require_admin())?;
        let sha = hash(&serde_json::to_vec(&selected)?);
        if inspect {
            return Ok(
                serde_json::json!({"schema_version":1,"review":selected,"review_sha256":sha,
                "recovery_usage":scope(Action::RecoverResource,"content-custody-bootstrap-v1",&sha)?,
                "filesystem_changed":false,"authority_returned":false}),
            );
        }
        if sha != args[3] {
            return Err("bootstrap requires exact current EMPTY review".into());
        }
        let pending = guard.effect_begin(&sha, crate::policy_decisions::EffectKind::Checkpoint)?;
        let genesis = empty.genesis(&installation)?;
        retain_genesis_statement(
            &installation,
            genesis,
            &empty.descriptor(&installation)?,
            &mut || {
                guard.require_admin()?;
                empty.check()
            },
        )?;
        let mut anchor = super::super::ContentAnchor::installed()?;
        if anchor.installation() != installation
            || anchor.genesis_event() != genesis
            || anchor.read()? != tpm::extend_value([0; 32], genesis)
        {
            return Err("bootstrap refuses noninitial NV or substituted authority; retain reviewed public proof as evidence".into());
        }
        initialize_empty(&mut anchor, &mut || {
            guard.require_admin()?;
            empty.check()
        })?;
        if review(&installation, &empty, &mut || guard.require_admin())? != selected {
            return Err(
                "bootstrap postcondition differs; preserve the exact journal and retry explicitly"
                    .into(),
            );
        }
        let result = serde_json::json!({"schema_version":1,"review_sha256":sha,"initial_history_available":true,"NV_authenticated":true,
            "TPM_extended":false,"content_bytes_changed":false,"credentials_restored":false,
            "authority_returned":false,"production_qualified":false});
        guard.effect_complete(pending, &hash(&serde_json::to_vec(&result)?))?;
        guard.require_admin()?;
        Ok(result)
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_history_bootstrap_requires_distinct_exact_finite_read_and_recovery_scopes() {
        let first = inspection(&"11".repeat(32)).unwrap();
        assert_eq!(first.selector.kind, Kind::File);
        let recover = scope(
            Action::RecoverResource,
            "content-custody-bootstrap-v1",
            &"12".repeat(32),
        )
        .unwrap();
        assert_eq!(recover.selector.kind, Kind::Resource);
        assert_ne!(first, recover);
        assert_eq!(recover.units, 1);
        assert_eq!(recover.output_bytes, 8192);
        assert!(inspection(&"00".repeat(32)).is_err());
        assert_ne!(
            first.selector.digest,
            inspection(&"13".repeat(32)).unwrap().selector.digest
        );
    }
}
