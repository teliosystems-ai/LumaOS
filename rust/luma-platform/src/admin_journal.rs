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

fn head(journal: &Journal) -> Result<[u8; 32]> {
    if journal.schema_version != 1 || journal.entries.len() > MAX_EVENTS {
        return Err("invalid/oversized Admin journal".into());
    }
    tpm::decode::<32>(&journal.deployment)?;
    // Provisioning extends exactly this domain-separated installation genesis
    // into a fresh index. A missing journal is never inferred to be empty.
    let mut genesis = Sha256::new();
    genesis.update(b"luma-native-admin-genesis-v1\0");
    genesis.update(tpm::decode::<32>(&journal.deployment)?);
    let mut value = tpm::extend_value([0; 32], genesis.finalize().into());
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
}
