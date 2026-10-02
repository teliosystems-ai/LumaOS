//! Durable native Admin-checkpoint journal. Records are inert audit data, not
//! capabilities. Native policy/effect services must separately authorize them.
//! Never repair, replay, or advance an ambiguous disk/TPM boundary automatically.
use crate::{
    bundle, platform,
    tpm::{self, Checkpoint, Clock},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub request_id: String,
    pub authenticated_uid: u32,
    pub clock: Clock,
    pub activity: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    deployment: String,
    entries: Vec<Entry>,
}

fn text_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn entry_digest(domain: &str, position: usize, entry: &Entry) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"luma-native-admin-audit-v1\0");
    hash.update(tpm::decode::<32>(domain)?);
    hash.update((position as u64).to_be_bytes());
    hash.update(serde_json::to_vec(entry)?);
    Ok(hash.finalize().into())
}

pub(crate) fn genesis(deployment: &str) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"luma-native-admin-genesis-v1\0");
    hash.update(tpm::decode::<32>(deployment)?);
    Ok(hash.finalize().into())
}

pub(crate) fn initial(deployment: &str) -> Result<Vec<u8>> {
    genesis(deployment)?;
    Ok(serde_json::to_vec(&Journal {
        schema_version: 1,
        deployment: deployment.into(),
        entries: vec![],
    })?)
}

fn head(journal: &Journal) -> Result<[u8; 32]> {
    if journal.schema_version != 1 || journal.entries.len() > MAX_EVENTS {
        return Err("invalid/oversized Admin journal".into());
    }
    tpm::decode::<32>(&journal.deployment)?;
    // Provisioning extends exactly this domain-separated installation genesis
    // into a fresh index. A missing journal is never inferred to be empty.
    let mut value = tpm::extend_value([0; 32], genesis(&journal.deployment)?);
    let mut requests = std::collections::BTreeSet::new();
    for (i, entry) in journal.entries.iter().enumerate() {
        if !text_id(&entry.request_id)
            || !text_id(&entry.activity)
            || !requests.insert(&entry.request_id)
            || entry.authenticated_uid < 1000
            || entry.authenticated_uid >= 65534
        {
            return Err("invalid, duplicate or service-identity Admin event".into());
        }
        tpm::decode::<32>(&entry.payload_sha256)?;
        value = tpm::extend_value(value, entry_digest(&journal.deployment, i, entry)?);
    }
    Ok(value)
}

pub struct Store<A: Checkpoint> {
    anchor: A,
    path: PathBuf,
    journal: Journal,
}

impl<A: Checkpoint> Store<A> {
    pub fn open(mut anchor: A, path: &Path) -> Result<Self> {
        let journal: Journal = serde_json::from_slice(&tpm::private_read(path, MAX_BYTES)?)?;
        let expected = head(&journal)?;
        if anchor.read()? != expected {
            return Err("Admin disk/TPM mismatch; explicit reconciliation required".into());
        }
        if has_pending(path)? {
            return Err("Admin pending transaction requires reconciliation".into());
        }
        Ok(Self {
            anchor,
            path: path.into(),
            journal,
        })
    }

    pub fn status(&mut self) -> Result<serde_json::Value> {
        let current: Journal = serde_json::from_slice(&tpm::private_read(&self.path, MAX_BYTES)?)?;
        if head(&current)? != head(&self.journal)?
            || self.anchor.read()? != head(&current)?
            || has_pending(&self.path)?
        {
            return Err("Admin checkpoint changed; authorization denied".into());
        }
        Ok(
            serde_json::json!({"schema_version":1,"profile":tpm::PROFILE,
            "deployment":current.deployment,"events":current.entries.len(),
            "head":bundle::hex(&head(&current)?),"clock":self.anchor.clock()?,
            "record_kind":"inert-audit-checkpoint","gate_closing":false}),
        )
    }

    /// Integrating services supply independently authenticated and authorized
    /// records. This adapter never treats an event payload as an authorization.
    #[cfg_attr(not(test), allow(dead_code))] // Trusted service integration is pending.
    pub fn append(&mut self, entry: Entry) -> Result<()> {
        self.status()?;
        if self
            .journal
            .entries
            .iter()
            .any(|old| old.request_id == entry.request_id)
        {
            return Err(
                "duplicate Admin event requires semantic replay by its owning service".into(),
            );
        }
        self.anchor.clock()?.elapsed_since(entry.clock)?;
        let before = head(&self.journal)?;
        let digest = entry_digest(&self.journal.deployment, self.journal.entries.len(), &entry)?;
        let mut next = self.journal.clone();
        next.entries.push(entry);
        let after = head(&next)?;
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("Admin journal capacity exhausted".into());
        }
        // Commit the complete proposed bytes first. This persistent fence is
        // retained on an uncertain TPM write; neither startup nor retries
        // redispatch. Publication is audit-only, not an external effect.
        let at = pending(&self.path);
        if has_pending(&self.path)? {
            return Err("pending Admin checkpoint; reconciliation required".into());
        }
        platform::write_atomic(&at, &bytes, 0o600)?;
        if self.anchor.advance(before, digest)? != after {
            return Err("Admin checkpoint outcome ambiguous; reconciliation required".into());
        }
        fs::rename(&at, &self.path)?;
        File::open(self.path.parent().ok_or("missing journal parent")?)?.sync_all()?;
        self.journal = next;
        self.status()?;
        Ok(())
    }
}

fn pending(path: &Path) -> PathBuf {
    path.with_extension("pending.json")
}

fn has_pending(path: &Path) -> Result<bool> {
    // A dangling symlink, directory or unreadable marker is also a fence.
    // Path::exists/try_exists would follow links and miss dangling markers.
    match fs::symlink_metadata(pending(path)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn status() -> Result<()> {
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        Path::new("/var/lib/luma-os/admin/journal.json"),
    )?;
    println!("{}", serde_json::to_string(&store.status()?)?);
    Ok(())
}

/// A recovery observation is not authorization. The only supported repair is
/// publishing an exact one-entry successor that the authenticated TPM already
/// contains. Never extend the TPM, discard an uncommitted proposal, infer an
/// empty genesis, or replay a service effect here.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct Publication {
    schema_version: u32,
    deployment: String,
    previous_events: usize,
    request_id: String,
    previous_head: String,
    committed_head: String,
    journal_sha256: String,
    pending_sha256: String,
}

pub(crate) struct Recovery<A: Checkpoint> {
    anchor: A,
    path: PathBuf,
    publication: Publication,
    observed: Clock,
}

fn publication<A: Checkpoint>(anchor: &mut A, path: &Path) -> Result<Publication> {
    let current_bytes = tpm::private_read(path, MAX_BYTES)?;
    let pending_bytes = tpm::private_read(&pending(path), MAX_BYTES)?;
    let current: Journal = serde_json::from_slice(&current_bytes)?;
    let proposed: Journal = serde_json::from_slice(&pending_bytes)?;
    let before = head(&current)?;
    let after = head(&proposed)?;
    if proposed.deployment != current.deployment
        || proposed.entries.len() != current.entries.len() + 1
        || !proposed.entries.starts_with(&current.entries)
    {
        return Err(
            "pending Admin journal is not an exact one-entry successor; preserve state".into(),
        );
    }
    if anchor.read()? != after {
        return Err(
            "TPM does not prove the pending Admin commit; preserve state; no replay".into(),
        );
    }
    Ok(Publication {
        schema_version: 1,
        deployment: current.deployment,
        previous_events: current.entries.len(),
        request_id: proposed
            .entries
            .last()
            .ok_or("missing pending event")?
            .request_id
            .clone(),
        previous_head: bundle::hex(&before),
        committed_head: bundle::hex(&after),
        journal_sha256: bundle::hex(&Sha256::digest(&current_bytes)),
        pending_sha256: bundle::hex(&Sha256::digest(&pending_bytes)),
    })
}

impl<A: Checkpoint> Recovery<A> {
    pub(crate) fn inspect(mut anchor: A, path: &Path) -> Result<Self> {
        let observed = anchor.clock()?;
        let publication = publication(&mut anchor, path)?;
        anchor.clock()?.elapsed_since(observed)?;
        Ok(Self {
            anchor,
            path: path.into(),
            publication,
            observed,
        })
    }

    pub(crate) fn digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(b"luma-native-admin-publication-v1\0");
        digest.update(serde_json::to_vec(&self.publication)?);
        Ok(bundle::hex(&digest.finalize()))
    }

    fn report(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "schema_version":1, "action":"publish-already-committed-audit",
            "review_sha256":self.digest()?, "publication":self.publication,
            "product_admin_active":false, "effect_replayed":false, "gate_closing":false
        }))
    }

    pub(crate) fn publish(mut self, reviewed_digest: &str) -> Result<Store<A>> {
        tpm::decode::<32>(reviewed_digest)?;
        if self.digest()? != reviewed_digest {
            return Err("Admin recovery review does not match current state".into());
        }
        // LocalAnchor retains its sole-writer lock throughout inspection,
        // revalidation and publication. It does not exclude hostile OS root.
        if publication(&mut self.anchor, &self.path)? != self.publication {
            return Err("Admin recovery inputs changed after review; preserve state".into());
        }
        self.anchor.clock()?.elapsed_since(self.observed)?;
        // Re-sync the prepared file before rename, including a retry following
        // a lost write/dir-sync acknowledgement. No journal records are lost:
        // the successor contains the complete previous prefix.
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(pending(&self.path))?;
        file.sync_all()?;
        fs::rename(pending(&self.path), &self.path)?;
        File::open(self.path.parent().ok_or("missing journal parent")?)?.sync_all()?;
        let mut store = Store::open(self.anchor, &self.path)?;
        store.status()?;
        Ok(store)
    }
}

/// Explicit root maintenance of inert audit data, not product Admin recovery.
/// No caller-selected paths, transport, credential, TPM write or force/reset.
pub fn reconcile(reviewed_digest: Option<&str>) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let recovery = Recovery::inspect(
        tpm::LocalAnchor::installed()?,
        Path::new("/var/lib/luma-os/admin/journal.json"),
    )?;
    let mut report = recovery.report()?;
    if let Some(digest) = reviewed_digest {
        let mut store = recovery.publish(digest)?;
        report["published"] = serde_json::json!(true);
        report["checkpoint"] = store.status()?;
    } else {
        report["published"] = serde_json::json!(false);
    }
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    struct Fake(Rc<RefCell<[u8; 32]>>, bool);
    impl Checkpoint for Fake {
        fn read(&mut self) -> Result<[u8; 32]> {
            Ok(*self.0.borrow())
        }
        fn clock(&mut self) -> Result<Clock> {
            Ok(Clock {
                milliseconds: 10,
                reset_count: 0,
                restart_count: 0,
            })
        }
        fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
            if self.read()? != expected {
                return Err("conflict".into());
            }
            let next = tpm::extend_value(expected, event);
            *self.0.borrow_mut() = next;
            if self.1 {
                return Err("injected lost reply after TPM write".into());
            }
            Ok(next)
        }
    }
    fn fixture(label: &str) -> (PathBuf, Journal, Fake) {
        let dir =
            std::env::temp_dir().join(format!("luma-admin-journal-{label}-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("journal.json");
        let journal = Journal {
            schema_version: 1,
            deployment: "ab".repeat(32),
            entries: vec![],
        };
        platform::write_atomic(&path, &serde_json::to_vec(&journal).unwrap(), 0o600).unwrap();
        let anchor = Fake(Rc::new(RefCell::new(head(&journal).unwrap())), false);
        (path, journal, anchor)
    }
    fn entry() -> Entry {
        Entry {
            request_id: "request-1".into(),
            authenticated_uid: 1001,
            clock: Clock {
                milliseconds: 5,
                reset_count: 0,
                restart_count: 0,
            },
            activity: "policy.audit".into(),
            payload_sha256: "12".repeat(32),
        }
    }
    fn cleanup(path: &Path) {
        fs::remove_file(path).unwrap();
        if pending(path).exists() {
            fs::remove_file(pending(path)).unwrap();
        }
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn append_survives_restart_and_rejects_disk_rollback() {
        let (path, initial, anchor) = fixture("restart");
        let mut store = Store::open(anchor.clone(), &path).unwrap();
        store.append(entry()).unwrap();
        assert!(store.append(entry()).is_err());
        drop(store);
        Store::open(anchor.clone(), &path)
            .unwrap()
            .status()
            .unwrap();
        platform::write_atomic(&path, &serde_json::to_vec(&initial).unwrap(), 0o600).unwrap();
        assert!(Store::open(anchor, &path).is_err());
        cleanup(&path);
    }
    #[test]
    fn lost_tpm_reply_fences_restart_and_never_reapplies() {
        let (path, _, mut anchor) = fixture("ambiguous");
        anchor.1 = true;
        let mut store = Store::open(anchor.clone(), &path).unwrap();
        assert!(store.append(entry()).is_err());
        let after = anchor.read().unwrap();
        assert!(pending(&path).exists());
        assert!(store.append(entry()).is_err());
        assert_eq!(anchor.read().unwrap(), after);
        assert!(Store::open(anchor, &path).is_err());
        cleanup(&path);
    }
    #[test]
    fn role_claims_unknown_fields_or_modified_payload_never_confer_authority() {
        let (path, mut journal, anchor) = fixture("tamper");
        journal.entries.push(entry());
        platform::write_atomic(&path, &serde_json::to_vec(&journal).unwrap(), 0o600).unwrap();
        assert!(Store::open(anchor, &path).is_err());
        let mut invalid = entry();
        invalid.authenticated_uid = 0;
        journal.entries = vec![invalid];
        assert!(head(&journal).is_err());
        let raw = serde_json::to_string(&journal)
            .unwrap()
            .replacen('{', "{\"authority\":true,", 1);
        assert!(serde_json::from_str::<Journal>(&raw).is_err());
        cleanup(&path);
    }

    #[test]
    fn unsafe_state_and_dangling_pending_marker_are_denied() {
        use std::os::unix::fs::symlink;
        let (path, _, anchor) = fixture("unsafe");
        let dir = path.parent().unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open(anchor.clone(), &path).is_err());
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::open(anchor.clone(), &path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, dir.join("alias")).unwrap();
        assert!(Store::open(anchor.clone(), &path).is_err());
        fs::remove_file(dir.join("alias")).unwrap();
        symlink(dir.join("absent"), pending(&path)).unwrap();
        assert!(Store::open(anchor.clone(), &path).is_err());
        fs::remove_file(pending(&path)).unwrap();
        Store::open(anchor, &path).unwrap().status().unwrap();
        cleanup(&path);
    }

    // Recovery is deliberately incapable of extending even in the fixture.
    #[derive(Clone)]
    struct ReadOnly {
        value: Rc<RefCell<[u8; 32]>>,
        clock: Rc<RefCell<Clock>>,
    }
    impl Checkpoint for ReadOnly {
        fn read(&mut self) -> Result<[u8; 32]> {
            Ok(*self.value.borrow())
        }
        fn clock(&mut self) -> Result<Clock> {
            Ok(*self.clock.borrow())
        }
        fn advance(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<[u8; 32]> {
            panic!("recovery must never write to the TPM")
        }
    }

    fn prepared(label: &str) -> (PathBuf, Journal, ReadOnly) {
        let (path, mut next, mut anchor) = fixture(label);
        anchor.1 = true;
        let mut store = Store::open(anchor.clone(), &path).unwrap();
        assert!(store.append(entry()).is_err()); // NV applied; reply lost.
        next.entries.push(entry());
        let read_only = ReadOnly {
            value: anchor.0,
            clock: Rc::new(RefCell::new(Clock {
                milliseconds: 20,
                reset_count: 0,
                restart_count: 0,
            })),
        };
        (path, next, read_only)
    }

    #[test]
    fn reviewed_committed_publication_survives_restart_without_tpm_write() {
        let (path, _, anchor) = prepared("recover");
        let before = fs::read(&path).unwrap();
        let proposed = fs::read(pending(&path)).unwrap();
        let recovery = Recovery::inspect(anchor.clone(), &path).unwrap();
        let report = recovery.report().unwrap();
        assert_eq!(report["gate_closing"], false);
        assert_eq!(report["effect_replayed"], false);
        assert_eq!(fs::read(&path).unwrap(), before); // inspection is read-only
        let digest = recovery.digest().unwrap();
        drop(recovery); // CLI review and apply are separate invocations.
        let mut store = Recovery::inspect(anchor.clone(), &path)
            .unwrap()
            .publish(&digest)
            .unwrap();
        assert_eq!(store.status().unwrap()["events"], 1);
        assert_eq!(fs::read(&path).unwrap(), proposed);
        assert!(!has_pending(&path).unwrap());
        drop(store);
        assert_eq!(
            Store::open(anchor.clone(), &path)
                .unwrap()
                .status()
                .unwrap()["events"],
            1
        );
        assert!(Recovery::inspect(anchor, &path).is_err()); // no empty/forced repair
        cleanup(&path);
    }

    #[test]
    fn recovery_requires_exact_review_and_rechecks_disk_and_anchor() {
        let (path, _, anchor) = prepared("review");
        let original = fs::read(&path).unwrap();
        let proposal = fs::read(pending(&path)).unwrap();
        for bad in ["", "force", &"00".repeat(32)] {
            assert!(Recovery::inspect(anchor.clone(), &path)
                .unwrap()
                .publish(bad)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(fs::read(pending(&path)).unwrap(), proposal);
        }
        // Even a semantically identical replacement needs a new byte-bound review.
        for target in [&path, &pending(&path)] {
            let recovery = Recovery::inspect(anchor.clone(), &path).unwrap();
            let digest = recovery.digest().unwrap();
            let previous = fs::read(target).unwrap();
            let mut changed = previous.clone();
            changed.push(b'\n');
            platform::write_atomic(target, &changed, 0o600).unwrap();
            assert!(recovery.publish(&digest).is_err());
            platform::write_atomic(target, &previous, 0o600).unwrap();
        }
        let recovery = Recovery::inspect(anchor.clone(), &path).unwrap();
        let digest = recovery.digest().unwrap();
        *anchor.value.borrow_mut() = [0xff; 32];
        assert!(recovery.publish(&digest).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(pending(&path)).unwrap(), proposal);
        cleanup(&path);
    }

    #[test]
    fn uncommitted_foreign_or_non_successor_proposals_remain_fenced() {
        let (path, mut proposed, anchor) = prepared("invalid-recovery");
        let original: Journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let committed = *anchor.value.borrow();
        *anchor.value.borrow_mut() = head(&original).unwrap();
        assert!(Recovery::inspect(anchor.clone(), &path).is_err());
        *anchor.value.borrow_mut() = committed;
        for variant in 0..5 {
            proposed.entries = vec![entry()];
            proposed.deployment = original.deployment.clone();
            match variant {
                0 => proposed.deployment = "cd".repeat(32),
                1 => proposed.entries.clear(),
                2 => {
                    let mut extra = entry();
                    extra.request_id = "extra".into();
                    proposed.entries.push(extra);
                }
                3 => proposed.entries[0].authenticated_uid = 0,
                _ => proposed.entries[0].payload_sha256 = "00".repeat(32),
            }
            platform::write_atomic(
                &pending(&path),
                &serde_json::to_vec(&proposed).unwrap(),
                0o600,
            )
            .unwrap();
            // An anchor matching a foreign domain, empty journal or multi-entry
            // proposal still cannot establish the required successor relation.
            if variant < 3 {
                *anchor.value.borrow_mut() = head(&proposed).unwrap();
            } else {
                *anchor.value.borrow_mut() = committed;
            }
            assert!(Recovery::inspect(anchor.clone(), &path).is_err());
            assert!(has_pending(&path).unwrap());
        }
        cleanup(&path);
    }

    #[test]
    fn recovery_cannot_replace_a_committed_prefix() {
        let (path, mut initial, anchor) = fixture("prefix");
        let mut store = Store::open(anchor.clone(), &path).unwrap();
        store.append(entry()).unwrap();
        initial.entries.push(entry());
        let mut second = entry();
        second.request_id = "second".into();
        initial.entries.push(second);
        initial.entries[0].payload_sha256 = "33".repeat(32);
        platform::write_atomic(
            &pending(&path),
            &serde_json::to_vec(&initial).unwrap(),
            0o600,
        )
        .unwrap();
        *anchor.0.borrow_mut() = head(&initial).unwrap();
        assert!(Recovery::inspect(anchor, &path).is_err());
        cleanup(&path);
    }

    #[test]
    fn recovery_rejects_epoch_changes_and_clock_regression_during_review() {
        let (path, _, anchor) = prepared("clock-recovery");
        for variant in 0..3 {
            *anchor.clock.borrow_mut() = Clock {
                milliseconds: 20,
                reset_count: 0,
                restart_count: 0,
            };
            let recovery = Recovery::inspect(anchor.clone(), &path).unwrap();
            let digest = recovery.digest().unwrap();
            match variant {
                0 => anchor.clock.borrow_mut().milliseconds = 19,
                1 => anchor.clock.borrow_mut().reset_count += 1,
                _ => anchor.clock.borrow_mut().restart_count += 1,
            }
            assert!(recovery.publish(&digest).is_err());
            assert!(has_pending(&path).unwrap());
        }
        cleanup(&path);
    }

    #[test]
    fn recovery_rejects_unsafe_or_malformed_pending_without_removing_it() {
        use std::os::unix::fs::symlink;
        let (path, _, anchor) = prepared("unsafe-recovery");
        let at = pending(&path);
        let good = fs::read(&at).unwrap();
        for bad in [b"{}".as_slice(), b"null", b"[]"] {
            platform::write_atomic(&at, bad, 0o600).unwrap();
            assert!(Recovery::inspect(anchor.clone(), &path).is_err());
            assert_eq!(fs::read(&at).unwrap(), bad);
        }
        platform::write_atomic(&at, &good, 0o644).unwrap();
        assert!(Recovery::inspect(anchor.clone(), &path).is_err());
        fs::set_permissions(&at, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = path.with_extension("alias");
        fs::hard_link(&at, &alias).unwrap();
        assert!(Recovery::inspect(anchor.clone(), &path).is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_file(&at).unwrap();
        symlink(path.with_extension("absent"), &at).unwrap();
        assert!(Recovery::inspect(anchor, &path).is_err());
        fs::remove_file(at).unwrap();
        cleanup(&path);
    }
}
