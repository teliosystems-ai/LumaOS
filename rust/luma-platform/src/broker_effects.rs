//! Durable replay fence for the two existing laboratory root-only worker effects.
//! Not product Admin, TPM rollback protection or automatic reconciliation.
use crate::{platform, tpm, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const DIRECTORY: &str = "/var/lib/luma-broker";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    StartWorker,
    StopWorker,
}

impl Action {
    pub fn parse(action: &str) -> Result<Self> {
        match action {
            "start-worker" => Ok(Self::StartWorker),
            "stop-worker" => Ok(Self::StopWorker),
            _ => Err("unsupported journaled worker effect".into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum State {
    Applying,
    Completed,
    NotApplied,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request_id: String,
    authenticated_uid: u32,
    action: Action,
    state: State,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    records: Vec<Record>,
}

fn request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn validate(journal: &Journal) -> Result<()> {
    if journal.schema_version != 1 || journal.records.len() > MAX_RECORDS {
        return Err("invalid or exhausted broker effect journal".into());
    }
    let mut identities = BTreeSet::new();
    for (index, record) in journal.records.iter().enumerate() {
        if !request_id(&record.request_id)
            || record.authenticated_uid != 0
            || !identities.insert(&record.request_id)
            || (record.state == State::Applying && index + 1 != journal.records.len())
        {
            return Err("invalid broker effect record".into());
        }
    }
    Ok(())
}

/// Called only while initializing a fresh encrypted installation. Missing
/// state at runtime is never interpreted as a new installation or empty log.
pub fn initialize(directory: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    tpm::private_directory(directory)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("effects.json"))?;
    file.write_all(&serde_json::to_vec(&Journal {
        schema_version: 1,
        records: vec![],
    })?)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    File::open(directory.parent().ok_or("missing effects parent")?)?.sync_all()?;
    Ok(())
}

pub struct Store {
    path: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        let lock = tpm::exclusive_lock(&directory.join("effects.lock"))?;
        let store = Self {
            path: directory.join("effects.json"),
            _lock: lock,
        };
        store.read()?;
        Ok(store)
    }

    fn read(&self) -> Result<Journal> {
        let bytes = tpm::private_read(&self.path, MAX_BYTES)?;
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&journal)? != bytes {
            return Err("noncanonical broker effect journal; preserve state".into());
        }
        validate(&journal)?;
        Ok(journal)
    }

    fn publish(&self, journal: &Journal) -> Result<()> {
        validate(journal)?;
        let bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("broker effect journal exceeds capacity".into());
        }
        platform::write_atomic(&self.path, &bytes, 0o600)
    }

    /// Authorization is checked even on historical completion replay, and
    /// again after durable preparation immediately before external dispatch.
    /// Any dispatch error/panic or lost completion commit leaves Applying:
    /// never infer from a running/stopped service that this request succeeded.
    pub fn execute(
        &mut self,
        identity: &str,
        uid: u32,
        action: Action,
        mut authorize: impl FnMut() -> Result<()>,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        if !request_id(identity) || uid != 0 {
            return Err("invalid laboratory effect identity".into());
        }
        let mut journal = self.read()?;
        authorize()?;
        if journal.records.iter().any(|r| r.state == State::Applying) {
            return Err("broker effect outcome uncertain; reviewed reconciliation required".into());
        }
        if let Some(record) = journal.records.iter().find(|r| r.request_id == identity) {
            if record.authenticated_uid != uid || record.action != action {
                return Err("broker effect replay conflict".into());
            }
            return match record.state {
                State::Completed => {
                    // A preceding publisher may have renamed Completed but
                    // lost its directory-sync acknowledgement. A successful
                    // replay must establish durability again before replying.
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(&self.path)?
                        .sync_all()?;
                    File::open(self.path.parent().ok_or("missing effects parent")?)?.sync_all()?;
                    Ok(true)
                }
                _ => Err("broker effect was not applied; use a new authorized request".into()),
            };
        }
        if journal.records.len() >= MAX_RECORDS {
            return Err("broker effect journal capacity exhausted; no automatic rotation".into());
        }
        let index = journal.records.len();
        journal.records.push(Record {
            request_id: identity.into(),
            authenticated_uid: uid,
            action,
            state: State::Applying,
        });
        self.publish(&journal)?;
        if authorize().is_err() {
            journal.records[index].state = State::NotApplied;
            self.publish(&journal)?;
            return Err("effect-time authorization denied before dispatch".into());
        }
        effect()?;
        journal.records[index].state = State::Completed;
        self.publish(&journal)?;
        Ok(false)
    }

    pub fn status(&self) -> Result<serde_json::Value> {
        let journal = self.read()?;
        Ok(serde_json::json!({"schema_version":1,
            "record_kind":"laboratory-root-worker-effects", "records":journal.records,
            "reconciliation_required":journal.records.iter().any(|r| r.state == State::Applying),
            "product_admin_active":false, "rollback_protected":false, "gate_closing":false}))
    }
}

pub fn status() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    println!("{}", Store::open(Path::new(DIRECTORY))?.status()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let directory =
                std::env::temp_dir().join(format!("luma-effects-{label}-{}", std::process::id()));
            initialize(&directory).unwrap();
            Self(directory)
        }
        fn open(&self) -> Store {
            Store::open(&self.0).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only files in this newly created fixture, no recursive deletion.
            for item in fs::read_dir(&self.0).unwrap() {
                fs::remove_file(item.unwrap().path()).unwrap();
            }
            fs::remove_dir(&self.0).unwrap();
        }
    }

    #[test]
    fn durable_completion_replays_without_redispatch_and_conflicts_are_denied() {
        let fixture = Fixture::new("replay");
        let count = Cell::new(0);
        let run = || {
            count.set(count.get() + 1);
            Ok(())
        };
        assert!(!fixture
            .open()
            .execute("request-1", 0, Action::StartWorker, || Ok(()), run)
            .unwrap());
        assert!(fixture
            .open()
            .execute("request-1", 0, Action::StartWorker, || Ok(()), run)
            .unwrap());
        assert!(fixture
            .open()
            .execute("request-1", 0, Action::StopWorker, || Ok(()), run)
            .is_err());
        assert_eq!(count.get(), 1);
        assert_eq!(
            fixture.open().status().unwrap()["records"][0]["state"],
            "completed"
        );
    }

    #[test]
    fn lost_effect_reply_fences_same_and_different_requests_after_restart() {
        let fixture = Fixture::new("lost-reply");
        let count = Cell::new(0);
        assert!(fixture
            .open()
            .execute(
                "uncertain",
                0,
                Action::StartWorker,
                || Ok(()),
                || {
                    count.set(count.get() + 1);
                    Err("injected lost external reply".into())
                }
            )
            .is_err());
        for id in ["uncertain", "another-request"] {
            assert!(fixture
                .open()
                .execute(
                    id,
                    0,
                    Action::StopWorker,
                    || Ok(()),
                    || {
                        count.set(count.get() + 1);
                        Ok(())
                    }
                )
                .is_err());
        }
        assert_eq!(count.get(), 1);
        assert_eq!(
            fixture.open().status().unwrap()["reconciliation_required"],
            true
        );
    }

    #[test]
    fn preparation_is_durable_before_dispatch_and_panics_leave_a_fence() {
        let fixture = Fixture::new("panic");
        let interrupted = std::panic::catch_unwind(|| {
            fixture
                .open()
                .execute(
                    "interrupted",
                    0,
                    Action::StartWorker,
                    || Ok(()),
                    || {
                        let journal: Journal = serde_json::from_slice(
                            &fs::read(fixture.0.join("effects.json")).unwrap(),
                        )
                        .unwrap();
                        assert_eq!(journal.records[0].state, State::Applying);
                        panic!("injected interruption during dispatch");
                    },
                )
                .unwrap();
        });
        assert!(interrupted.is_err());
        assert_eq!(
            fixture.open().status().unwrap()["reconciliation_required"],
            true
        );
    }

    #[test]
    fn failed_completion_publication_cannot_report_success_or_repeat_effect() {
        let fixture = Fixture::new("commit-failure");
        // Preserve the durable Applying record, then make the publication
        // target invalid. This is a real rename failure, not simulated fsync.
        assert!(fixture
            .open()
            .execute(
                "applied",
                0,
                Action::StopWorker,
                || Ok(()),
                || {
                    fs::rename(fixture.0.join("effects.json"), fixture.0.join("saved.json"))?;
                    fs::create_dir(fixture.0.join("effects.json"))?;
                    Ok(())
                }
            )
            .is_err());
        assert!(Store::open(&fixture.0).is_err());
        fs::remove_dir(fixture.0.join("effects.json")).unwrap();
        fs::rename(fixture.0.join("saved.json"), fixture.0.join("effects.json")).unwrap();
        assert!(fixture
            .open()
            .execute(
                "applied",
                0,
                Action::StopWorker,
                || Ok(()),
                || panic!("uncertain effect redispatched")
            )
            .is_err());
    }

    #[test]
    fn current_authority_required_for_replay_and_rechecked_before_effect() {
        let fixture = Fixture::new("authority");
        assert!(fixture
            .open()
            .execute(
                "initial-denial",
                0,
                Action::StopWorker,
                || Err("denied".into()),
                || panic!("initially denied effect")
            )
            .is_err());
        assert_eq!(
            fixture.open().status().unwrap()["records"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let checks = Cell::new(0);
        assert!(fixture
            .open()
            .execute(
                "revoked",
                0,
                Action::StopWorker,
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == 2 {
                        Err("revoked".into())
                    } else {
                        Ok(())
                    }
                },
                || panic!("revoked effect executed")
            )
            .is_err());
        assert_eq!(
            fixture.open().status().unwrap()["records"][0]["state"],
            "not-applied"
        );
        assert!(fixture
            .open()
            .execute(
                "revoked",
                0,
                Action::StopWorker,
                || Ok(()),
                || panic!("replayed refusal")
            )
            .is_err());
        fixture
            .open()
            .execute("allowed", 0, Action::StopWorker, || Ok(()), || Ok(()))
            .unwrap();
        assert!(fixture
            .open()
            .execute(
                "allowed",
                0,
                Action::StopWorker,
                || Err("denied".into()),
                || panic!("replayed effect")
            )
            .is_err());
    }

    #[test]
    fn fresh_initialization_and_missing_malformed_state_are_not_reset() {
        let fixture = Fixture::new("missing");
        assert!(initialize(&fixture.0).is_err());
        fs::remove_file(fixture.0.join("effects.json")).unwrap();
        assert!(Store::open(&fixture.0).is_err());
        assert!(!fixture.0.join("effects.json").exists());
        fs::write(fixture.0.join("effects.json"), b"{}").unwrap();
        fs::set_permissions(
            fixture.0.join("effects.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(Store::open(&fixture.0).is_err());
    }

    #[test]
    fn semantically_identical_noncanonical_effect_journal_is_refused() {
        let fixture = Fixture::new("noncanonical");
        let path = fixture.0.join("effects.json");
        let canonical = fs::read(&path).unwrap();
        let mut whitespace = canonical.clone();
        whitespace.push(b'\n');
        assert!(validate(&serde_json::from_slice::<Journal>(&whitespace).unwrap()).is_ok());
        platform::write_atomic(&path, &whitespace, 0o600).unwrap();
        assert!(Store::open(&fixture.0).is_err());

        platform::write_atomic(&path, &canonical, 0o600).unwrap();
        let store = fixture.open();
        let reordered = br#"{"records":[],"schema_version":1}"#;
        assert!(validate(&serde_json::from_slice::<Journal>(reordered).unwrap()).is_ok());
        platform::write_atomic(&path, reordered, 0o600).unwrap();
        assert!(store.status().is_err());
        platform::write_atomic(&path, &canonical, 0o600).unwrap();
        assert_eq!(store.status().unwrap()["reconciliation_required"], false);
    }

    #[test]
    fn exclusive_writer_and_unsafe_state_are_refused() {
        let fixture = Fixture::new("locking");
        let store = fixture.open();
        assert!(Store::open(&fixture.0).is_err());
        drop(store);
        let path = fixture.0.join("effects.json");
        fs::hard_link(&path, fixture.0.join("alias")).unwrap();
        assert!(Store::open(&fixture.0).is_err());
        fs::remove_file(fixture.0.join("alias")).unwrap();
        fs::rename(&path, fixture.0.join("original")).unwrap();
        symlink(fixture.0.join("original"), &path).unwrap();
        assert!(Store::open(&fixture.0).is_err());
    }

    #[test]
    fn closed_schema_duplicates_capacity_and_invalid_principals_fail_closed() {
        let fixture = Fixture::new("schema");
        for uid in [1, 990, 1000] {
            assert!(fixture
                .open()
                .execute(
                    "id",
                    uid,
                    Action::StartWorker,
                    || Ok(()),
                    || panic!("unauthorized effect")
                )
                .is_err());
        }
        assert!(Action::parse("shell").is_err());
        let record = Record {
            request_id: "id".into(),
            authenticated_uid: 0,
            action: Action::StartWorker,
            state: State::Completed,
        };
        assert!(validate(&Journal {
            schema_version: 1,
            records: vec![record.clone(), record.clone()]
        })
        .is_err());
        let mut full = Journal {
            schema_version: 1,
            records: vec![],
        };
        for i in 0..MAX_RECORDS {
            full.records.push(Record {
                request_id: format!("id-{i}"),
                ..record.clone()
            });
        }
        fixture.open().publish(&full).unwrap();
        assert!(fixture
            .open()
            .execute(
                "id-0",
                0,
                Action::StartWorker,
                || Ok(()),
                || panic!("completed effect redispatched")
            )
            .unwrap());
        assert!(fixture
            .open()
            .execute(
                "overflow",
                0,
                Action::StartWorker,
                || Ok(()),
                || panic!("over-capacity effect")
            )
            .is_err());
        let encoded =
            serde_json::to_string(&full)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        assert!(serde_json::from_str::<Journal>(&encoded).is_err());
    }
}
