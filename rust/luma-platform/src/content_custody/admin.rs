//! Genuine Admin review and exact pre/post-TPM reconciliation. This ceremony
//! repairs only the separately protected journal, never content source bytes.
use super::*;
use crate::finite_grants::{Action, Kind, Selector, Use};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingReview {
    schema_version: u32,
    purpose: String,
    installation: String,
    current_sha256: String,
    prepared_sha256: String,
    publish_sha256: Option<String>,
    checkpoint_head: String,
    disposition: String,
}
impl PendingReview {
    fn sha256(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
}
fn installed_pending_review(
    anchor: &mut super::super::ContentAnchor,
    files: &Files,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(PendingReview, Prepared)> {
    let (review, pending) = pending_review(anchor, files, check)?;
    pending
        .previous
        .require_identity(anchor.installation(), anchor.genesis_event())?;
    pending
        .next
        .require_identity(anchor.installation(), anchor.genesis_event())?;
    if review.installation != anchor.installation() {
        return Err(
            "pending journal metadata differs from independently sealed C installation/genesis"
                .into(),
        );
    }
    check()?;
    Ok((review, pending))
}
fn present(files: &Files, name: &str) -> Result<bool> {
    match fs::symlink_metadata(files.root.join(name)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn scope(action: Action, id: &str, generation: u64, sha: &str) -> Result<Use> {
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
            generation,
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
        "content-custody-inspect-v1",
        1,
        &hash(&serde_json::to_vec(&(
            "luma-content-custody-inspection-v1",
            installation,
        ))?),
    )
}
pub(super) fn pending_review<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(PendingReview, Prepared)> {
    check()?;
    let current = files.read(JOURNAL, check)?;
    let pending_bytes = files.read(PREPARED, check)?;
    let pending: Prepared = canonical(&pending_bytes, MAX_FILE)?;
    let (before, after) = pending.validate(&current)?;
    let staged = if present(files, PUBLISHED)? {
        Some(files.read(PUBLISHED, check)?)
    } else {
        None
    };
    let next_bytes = pending.next.bytes()?;
    if staged.as_ref().is_some_and(|v| *v != next_bytes) {
        return Err("content publish staging differs from exact prepared next journal".into());
    }
    check()?;
    let actual = anchor.read()?;
    check()?;
    let disposition = if actual == before && current == pending.previous.bytes()? {
        "retire-uncommitted-prepared"
    } else if actual == after {
        "finalize-committed-prepared"
    } else {
        return Err(
            "content checkpoint is not an exact reviewed pre/post cut; preserve all evidence"
                .into(),
        );
    };
    let review = PendingReview {
        schema_version: 1,
        purpose: "luma-content-custody-reconciliation-v1".into(),
        installation: pending.next.installation.clone(),
        current_sha256: hash(&current),
        prepared_sha256: hash(&pending_bytes),
        publish_sha256: staged.as_ref().map(|v| hash(v)),
        checkpoint_head: bundle::hex(&actual),
        disposition: disposition.into(),
    };
    if files.read(JOURNAL, check)? != current
        || files.read(PREPARED, check)? != pending_bytes
        || anchor.read()? != actual
    {
        return Err("content pending reconciliation cut changed during inspection".into());
    }
    check()?;
    Ok((review, pending))
}
pub(super) fn reconcile<A: Checkpoint>(
    anchor: &mut A,
    files: &Files,
    expected: &PendingReview,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (current, pending) = pending_review(anchor, files, check)?;
    if current != *expected {
        return Err("content pending reconciliation no longer matches exact Admin review".into());
    }
    if current.disposition == "finalize-committed-prepared" {
        let next = pending.next.bytes()?;
        if hash(&files.read(JOURNAL, check)?) != hash(&next) {
            if !present(files, PUBLISHED)? {
                files.create(PUBLISHED, &next, check)?;
            }
            if files.read(PUBLISHED, check)? != next {
                return Err("content recovery publish stage differs".into());
            }
            check()?;
            if anchor.read()? != tpm::decode::<32>(&current.checkpoint_head)? {
                return Err("content checkpoint changed before reviewed finalization".into());
            }
            files.rename(PUBLISHED, JOURNAL, check)?;
        } else if present(files, PUBLISHED)? {
            if files.read(PUBLISHED, check)? != next {
                return Err("content finalized staging differs".into());
            }
            files.retire(PUBLISHED, check)?;
        }
        if files.read(JOURNAL, check)? != next {
            return Err("content recovery journal readback differs".into());
        }
    } else if current.disposition == "retire-uncommitted-prepared" {
        if files.read(JOURNAL, check)? != pending.previous.bytes()? {
            return Err("uncommitted content cut changed".into());
        }
        if let Some(expected_stage) = &current.publish_sha256 {
            if hash(&files.read(PUBLISHED, check)?) != *expected_stage {
                return Err("uncommitted content staging changed".into());
            }
            files.retire(PUBLISHED, check)?;
        }
    } else {
        return Err("unknown content reconciliation disposition".into());
    }
    check()?;
    if hash(&files.read(PREPARED, check)?) != current.prepared_sha256
        || anchor.read()? != tpm::decode::<32>(&current.checkpoint_head)?
    {
        return Err("content pending evidence changed before reviewed retirement".into());
    }
    files.retire(PREPARED, check)?;
    check()?;
    let bytes = files.read(JOURNAL, check)?;
    let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
    if anchor.read()? != journal.validate()?.checkpoint {
        return Err("reconciled content history does not match current protected head".into());
    }
    check()
}
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let name = args
        .first()
        .map(String::as_str)
        .ok_or("content custody ceremony missing")?;
    let proposal = name == "content-custody-inspect-proposal";
    let inspect = name == "content-custody-inspect";
    let reconcile_requested = name == "content-custody-reconcile";
    if (!proposal && !inspect && !reconcile_requested)
        || args.len()
            != if proposal {
                2
            } else if inspect {
                3
            } else {
                4
            }
    {
        return Err("expected content-custody-inspect-proposal LOGIN | content-custody-inspect LOGIN READ-GRANT | content-custody-reconcile LOGIN RECOVERY-GRANT EXACT-REVIEW".into());
    }
    let (_, _, installation) = crate::admin_governance::current_principal(&args[1])?;
    let read = inspection(&installation)?;
    if proposal {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"schema_version":1,"usage":read,"private_authority_read":false})
            )?
        );
        return Ok(());
    }
    let usage = if inspect {
        read
    } else {
        scope(
            Action::RecoverResource,
            "content-custody-reconcile-v1",
            1,
            &args[3],
        )?
    };
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        boundary.require_admin()?;
        let mut check = || boundary.require_admin();
        let mut anchor = super::super::ContentAnchor::installed()?;
        let files = Files::installed();
        if anchor.installation() != installation {
            return Err("content custody Admin installation differs".into());
        }
        if inspect {
            if present(&files, PREPARED)? {
                let (review, _) = installed_pending_review(&mut anchor, &files, &mut check)?;
                let sha = review.sha256()?;
                Ok(
                    serde_json::json!({"schema_version":1,"pending":review,"review_sha256":sha,
                    "reconciliation_usage":scope(Action::RecoverResource,"content-custody-reconcile-v1",1,&sha)?,
                    "content_bytes_changed":false,"production_qualified":false}),
                )
            } else {
                files.absent(PUBLISHED)?;
                let mut store = Store::from_anchor(anchor, files, &mut check)?;
                store.live(&mut check)?;
                Ok(
                    serde_json::json!({"schema_version":1,"installation":installation,"pending":null,
                    "checkpoint_head":bundle::hex(&store.state.checkpoint),"events":store.journal.events.len(),
                    "content_bytes_changed":false,"production_qualified":false}),
                )
            }
        } else {
            let (review, _) = installed_pending_review(&mut anchor, &files, &mut check)?;
            if review.sha256()? != args[3] {
                return Err("content reconciliation requires exact current reviewed cut".into());
            }
            drop(check);
            let pending_effect =
                boundary.effect_begin(&args[3], crate::policy_decisions::EffectKind::Checkpoint)?;
            reconcile(&mut anchor, &files, &review, &mut || {
                boundary.require_admin()
            })?;
            let result = serde_json::json!({"schema_version":1,"review_sha256":args[3],"disposition":review.disposition,
                "checkpoint_head":bundle::hex(&anchor.read()?),"content_bytes_changed":false,"TPM_extended":false,
                "credentials_restored":false,"production_qualified":false});
            boundary.effect_complete(pending_effect, &hash(&serde_json::to_vec(&result)?))?;
            boundary.require_admin()?;
            Ok(result)
        }
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proposal_scopes_are_distinct_finite_and_installation_bound() {
        let a = inspection(&"12".repeat(32)).unwrap();
        let b = inspection(&"13".repeat(32)).unwrap();
        assert_ne!(a.selector.digest, b.selector.digest);
        assert_eq!(a.action, Action::Read);
        assert_eq!(a.selector.kind, Kind::File);
        let recovery = scope(
            Action::RecoverResource,
            "content-custody-reconcile-v1",
            1,
            &a.selector.digest,
        )
        .unwrap();
        assert_ne!(recovery, a);
        assert_eq!(recovery.selector.kind, Kind::Resource);
        assert_eq!(recovery.units, 1);
        assert_eq!(recovery.input_bytes, 0);
        assert_eq!(recovery.output_bytes, 8192);
        assert!(inspection(&"00".repeat(32)).is_err());
    }
}
