//! Reviewed preservation of interrupted physical-lease archive preparations.
//! It never repairs a ledger, retires owners, returns capacity or deletes bytes.
use super::*;
use std::os::unix::fs::MetadataExt;

pub(super) const MAX_DIRECTORY_ENTRIES: usize = 512;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
    sha256: String,
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(path: &Path) -> Result<Identity> {
    tpm::private_directory(path.parent().ok_or("missing resource incident parent")?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() > MAX_BYTES
    {
        return Err("unsafe or oversized resource archive preparation".into());
    }
    let mut digest = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or("resource incident length overflow")?;
        if length > MAX_BYTES {
            return Err("resource archive preparation grew beyond its bound".into());
        }
        digest.update(&buffer[..count]);
    }
    let sha256 = bundle::hex(&digest.finalize());
    let observed = |m: &fs::Metadata| Identity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        modified: m.mtime(),
        modified_ns: m.mtime_nsec(),
        changed: m.ctime(),
        changed_ns: m.ctime_nsec(),
        sha256: sha256.clone(),
    };
    if length != before.len()
        || observed(&before) != observed(&file.metadata()?)
        || observed(&before) != observed(&fs::symlink_metadata(path)?)
    {
        return Err("resource archive preparation changed during inspection".into());
    }
    Ok(observed(&before))
}

pub(super) fn verify_retained(path: &Path, suffix: &str) -> Result<()> {
    let (digest, review) = suffix
        .strip_suffix(".json")
        .and_then(|v| v.split_once('-'))
        .ok_or("invalid retained resource incident name")?;
    if !hash(digest) || !hash(review) || identity(path)?.sha256 != digest {
        return Err("retained resource incident mismatch".into());
    }
    Ok(())
}

fn reference(name: &str) -> Result<Archive> {
    let (generation, digest) = name
        .strip_prefix(".archive-stage-archive-")
        .and_then(|v| v.strip_suffix(".json"))
        .and_then(|v| v.split_once('-'))
        .ok_or("unknown resource archive preparation name; preserve state")?;
    let archive = Archive {
        through_generation: generation.parse()?,
        sha256: digest.into(),
    };
    if archive.through_generation == 0
        || !hash(digest)
        || format!(".archive-stage-{}", archive.name()) != name
    {
        return Err("noncanonical resource archive preparation name".into());
    }
    Ok(archive)
}

fn preserve(directory: &Path, source: &str, expected: &Identity, review: &str) -> Result<String> {
    let path = directory.join(source);
    if identity(&path)? != *expected {
        return Err("resource archive preparation changed before preservation".into());
    }
    File::open(&path)?.sync_all()?;
    let destination = format!(".archive-retained-{}-{}.json", expected.sha256, review);
    let from = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(directory.join(&destination).as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let retained = identity(&directory.join(&destination))?;
    if retained.device != expected.device
        || retained.inode != expected.inode
        || retained.length != expected.length
        || retained.sha256 != expected.sha256
        || path.try_exists()?
    {
        return Err("resource archive preservation outcome uncertain".into());
    }
    File::open(directory)?.sync_all()?;
    Ok(destination)
}

impl Store {
    pub(crate) fn recovery_binding(&self) -> Result<String> {
        let ledger = self.read()?;
        let durable = identity(&self.directory.join("ledger.json"))?;
        Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(&(
            "resource-recovery-authority-v1",
            ledger.review()?,
            durable,
        ))?)))
    }

    fn recovery_candidate(&self) -> Result<Option<(String, Identity, String)>> {
        let ledger = self.read()?;
        if ledger.leases.iter().any(|l| l.state != State::Released) {
            return Err("resource archive recovery requires released physical generations".into());
        }
        self.verify_archives(&ledger)?;
        let mut candidates = BTreeMap::new();
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index >= MAX_DIRECTORY_ENTRIES {
                return Err("resource recovery directory inspection limit exceeded".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid resource recovery filename")?;
            if !name.starts_with(".archive-stage-") {
                continue;
            }
            let archive = reference(name)?;
            if archive.through_generation > ledger.generation {
                return Err("resource preparation names an unavailable future generation".into());
            }
            let observed = identity(&entry.path())?;
            if observed.sha256 == archive.sha256 {
                // A checksum-matching complete publication is not damaged-state
                // recovery. Retain it for exact archival retry or investigation.
                continue;
            }
            candidates.insert(name.to_string(), observed);
        }
        let Some((name, observed)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let durable = identity(&self.directory.join("ledger.json"))?;
        let review = bundle::hex(&Sha256::digest(serde_json::to_vec(&(
            "retain-interrupted-resource-archive-v1",
            ledger.review()?,
            durable,
            &name,
            &observed,
        ))?));
        Ok(Some((name, observed, review)))
    }

    pub(crate) fn stage_recovery_status(&self) -> Result<serde_json::Value> {
        Ok(match self.recovery_candidate()? {
            Some((stage, observed, review)) => serde_json::json!({
                "recoverable":true,"stage":stage,"review":review,
                "stage_sha256":observed.sha256,"stage_bytes":observed.length.to_string(),
                "worker_resources_released":false,"evidence_deleted":false}),
            None => serde_json::json!({"recoverable":false,"review":null,
                "worker_resources_released":false,"evidence_deleted":false}),
        })
    }

    pub(crate) fn recover_stage_checked(
        &mut self,
        review: &str,
        mut observe: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.recover_stage_with(review, |directory, source, expected, review| {
            observe()?;
            let retained = preserve(directory, source, expected, review)?;
            observe()?;
            Ok(retained)
        })
    }

    fn recover_stage_with(
        &mut self,
        review: &str,
        retain: impl FnOnce(&Path, &str, &Identity, &str) -> Result<String>,
    ) -> Result<serde_json::Value> {
        let (stage, observed, current) = self
            .recovery_candidate()?
            .ok_or("no interrupted resource archive preparation")?;
        if current != review {
            return Err("stale resource archive preservation review".into());
        }
        let result = retain(&self.directory, &stage, &observed, &current);
        if result.is_err() {
            self.poisoned = true;
        }
        let retained = result?;
        Ok(
            serde_json::json!({"retained":retained,"sha256":observed.sha256,
            "retained_bytes":observed.length.to_string(),"worker_resources_released":false,
            "evidence_deleted":false,"hot_history_preserved":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture {
        directory: PathBuf,
        store: Store,
        owner: Owner,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir()
                .join(format!("luma-resource-retention-{}", random_id().unwrap()));
            initialize(&directory).unwrap();
            let mut store = Store::open(&directory).unwrap();
            let owner = Owner {
                uid: 989,
                pid: 81,
                start_ticks: 1,
                boot: "boot".into(),
                cgroup_device: 1,
                cgroup_inode: 1,
            };
            store
                .transact(|ledger| {
                    ledger.restart(
                        "a".repeat(32),
                        BTreeMap::from([("host".into(), Domain::new(1000, 100, 950, 800)?)]),
                    )?;
                    let token = ledger.admit(
                        owner.clone(),
                        "retention".into(),
                        "b".repeat(64),
                        vec![Reservation {
                            domain: "host".into(),
                            loading: 40,
                            serving: 40,
                        }],
                        1,
                        1000,
                    )?;
                    ledger.complete_output(&token, &owner, 2, &"d".repeat(64))?;
                    ledger.revoke(&token, "owner-lost")?;
                    ledger.finish_draining(&token, &BTreeMap::from([("host".into(), 7)]))
                })
                .unwrap();
            Self {
                directory,
                store,
                owner,
            }
        }
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.directory.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            File::open(&self.directory).unwrap().sync_all().unwrap();
            path
        }
        fn stage(&self, bytes: &[u8]) -> PathBuf {
            let ledger = fs::read(self.directory.join("ledger.json")).unwrap();
            let archive = Archive {
                through_generation: self.store.read().unwrap().generation,
                sha256: bundle::hex(&Sha256::digest(&ledger)),
            };
            self.write(&format!(".archive-stage-{}", archive.name()), bytes)
        }
        fn review(&self) -> String {
            self.store.stage_recovery_status().unwrap()["review"]
                .as_str()
                .unwrap()
                .into()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for entry in fs::read_dir(&self.directory).unwrap() {
                fs::remove_file(entry.unwrap().path()).unwrap();
            }
            fs::remove_dir(&self.directory).unwrap();
        }
    }

    #[test]
    fn reviewed_stage_preservation_keeps_inode_bytes_ledger_requests_and_charges() {
        for bytes in [b"".as_slice(), b"{", b"{\"damaged\":true}"] {
            let mut fixture = Fixture::new();
            let stage = fixture.stage(bytes);
            let original = identity(&stage).unwrap();
            let ledger = fs::read(fixture.directory.join("ledger.json")).unwrap();
            let requests = fs::read(fixture.directory.join("requests.json")).unwrap();
            let before = fixture.store.read().unwrap();
            let result = fixture
                .store
                .recover_stage_checked(&fixture.review(), || Ok(()))
                .unwrap();
            let retained = fixture.directory.join(result["retained"].as_str().unwrap());
            assert_eq!(fs::read(&retained).unwrap(), bytes);
            assert_eq!(identity(&retained).unwrap().inode, original.inode);
            assert!(!stage.exists());
            assert_eq!(
                fs::read(fixture.directory.join("ledger.json")).unwrap(),
                ledger
            );
            assert_eq!(
                fs::read(fixture.directory.join("requests.json")).unwrap(),
                requests
            );
            assert_eq!(fixture.store.read().unwrap(), before);
            assert_eq!(fixture.store.read().unwrap().charged("host").unwrap(), 7);
            assert!(!fixture.store.owner_retired(&fixture.owner).unwrap());
            assert_eq!(result["worker_resources_released"], false);
            assert_eq!(result["evidence_deleted"], false);
            assert_eq!(
                fixture.store.stage_recovery_status().unwrap()["recoverable"],
                false
            );
            let reopened = Store::open(&fixture.directory);
            assert!(
                reopened.is_err(),
                "lifetime store exclusion must remain held"
            );
            let review = fixture.store.read().unwrap().review().unwrap();
            let archive = fixture.store.archive(&review, "b".repeat(32)).unwrap();
            assert!(fixture.store.owner_retired(&fixture.owner).unwrap());
            assert_eq!(fs::read(retained).unwrap(), bytes);
            assert_eq!(fixture.store.archived(&archive).unwrap(), before);
        }
    }

    #[test]
    fn review_binds_stage_bytes_inode_and_exact_durable_ledger_identity() {
        for mutation in 0..4 {
            let mut fixture = Fixture::new();
            let stage = fixture.stage(b"{");
            let review = fixture.review();
            match mutation {
                0 => {
                    fs::write(&stage, b"{\"different\"").unwrap();
                }
                1 => {
                    let replacement = fixture.write("replacement", b"{");
                    fs::rename(replacement, &stage).unwrap();
                }
                2 => {
                    fixture
                        .store
                        .transact(|ledger| {
                            let token = ledger.leases[0].token.clone();
                            ledger.revoke(&token, "operator-revoked")
                        })
                        .unwrap();
                }
                _ => {
                    let bytes = fs::read(fixture.directory.join("ledger.json")).unwrap();
                    let replacement = fixture.write("replacement", &bytes);
                    fs::rename(replacement, fixture.directory.join("ledger.json")).unwrap();
                }
            }
            let before = fs::read(fixture.directory.join("ledger.json")).unwrap();
            assert!(fixture
                .store
                .recover_stage_checked(&review, || Ok(()))
                .is_err());
            assert!(stage.exists());
            assert_eq!(
                fs::read(fixture.directory.join("ledger.json")).unwrap(),
                before
            );
            assert_ne!(fixture.review(), review);
        }
    }

    #[test]
    fn older_interrupted_stages_survive_broker_restart_and_a_later_hot_cut() {
        let mut fixture = Fixture::new();
        let stage = fixture.write(
            &format!(".archive-stage-archive-1-{}.json", "f".repeat(64)),
            b"{",
        );
        let review = fixture.review();
        let inventory = fixture.store.read().unwrap().domains;
        fixture
            .store
            .transact(|ledger| ledger.restart("b".repeat(32), inventory))
            .unwrap();
        assert!(fixture
            .store
            .recover_stage_checked(&review, || Ok(()))
            .is_err());
        let archived = fixture
            .store
            .archive(
                &fixture.store.read().unwrap().review().unwrap(),
                "c".repeat(32),
            )
            .unwrap();
        let before = fixture.store.read().unwrap();
        let outcome = fixture
            .store
            .recover_stage_checked(&fixture.review(), || Ok(()))
            .unwrap();
        assert!(!stage.exists());
        assert_eq!(fixture.store.read().unwrap(), before);
        assert_eq!(before.archives, vec![archived]);
        assert!(fixture.store.owner_retired(&fixture.owner).unwrap());
        assert_eq!(
            fs::read(
                fixture
                    .directory
                    .join(outcome["retained"].as_str().unwrap())
            )
            .unwrap(),
            b"{"
        );
    }

    #[test]
    fn complete_stages_unknown_names_future_generations_and_live_allocations_refuse_repair() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.store.stage_recovery_status().unwrap()["recoverable"],
            false
        );
        let bytes = fs::read(fixture.directory.join("ledger.json")).unwrap();
        let complete = fixture.stage(&bytes);
        assert_eq!(
            fixture.store.stage_recovery_status().unwrap()["recoverable"],
            false
        );
        assert!(fixture
            .store
            .recover_stage_checked(&"a".repeat(64), || Ok(()))
            .is_err());
        assert_eq!(fs::read(&complete).unwrap(), bytes);
        fs::remove_file(complete).unwrap();
        for name in [
            ".archive-stage-unknown".to_string(),
            format!(".archive-stage-archive-2-{}.json", "a".repeat(64)),
        ] {
            let path = fixture.write(&name, b"{");
            assert!(fixture.store.stage_recovery_status().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"{");
            fs::remove_file(path).unwrap();
        }
        let stage = fixture.stage(b"{");
        let review = fixture.review();
        fixture
            .store
            .transact(|ledger| {
                ledger.admit(
                    Owner {
                        pid: 82,
                        ..fixture.owner.clone()
                    },
                    "another".into(),
                    "b".repeat(64),
                    vec![Reservation {
                        domain: "host".into(),
                        loading: 40,
                        serving: 40,
                    }],
                    1,
                    1000,
                )?;
                Ok(())
            })
            .unwrap();
        assert!(fixture.store.stage_recovery_status().is_err());
        assert!(fixture
            .store
            .recover_stage_checked(&review, || Ok(()))
            .is_err());
        assert_eq!(fs::read(stage).unwrap(), b"{");
        assert_eq!(fixture.store.read().unwrap().charged("host").unwrap(), 47);
    }

    #[test]
    fn lost_preservation_acknowledgements_poison_and_restart_never_changes_accounting() {
        for fail_after_move in [false, true] {
            let mut fixture = Fixture::new();
            let stage = fixture.stage(b"{");
            let review = fixture.review();
            let before = fixture.store.read().unwrap();
            let mut observations = 0;
            assert!(fixture
                .store
                .recover_stage_checked(&review, || {
                    observations += 1;
                    if observations == if fail_after_move { 2 } else { 1 } {
                        Err("lost trusted observation/acknowledgement".into())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert!(fixture.store.read().is_err());
            assert_eq!(stage.exists(), !fail_after_move);
            let fresh = Store::open(&fixture.directory);
            assert!(fresh.is_err());
            // Close only this fixture's lifetime lock before loading durable state.
            let replacement = OpenOptions::new().read(true).open("/dev/null").unwrap();
            drop(std::mem::replace(&mut fixture.store._lock, replacement));
            let fresh = Store::open(&fixture.directory).unwrap();
            assert_eq!(fresh.read().unwrap(), before);
            assert_eq!(fresh.read().unwrap().charged("host").unwrap(), 7);
            assert!(!fresh.owner_retired(&fixture.owner).unwrap());
            assert_eq!(
                fresh.stage_recovery_status().unwrap()["recoverable"],
                !fail_after_move
            );
        }
    }

    #[test]
    fn linked_public_symlinked_oversized_stages_and_destination_collision_never_overwrite() {
        for fault in 0..5 {
            let mut fixture = Fixture::new();
            let stage = fixture.stage(b"{");
            let review = fixture.review();
            match fault {
                0 => fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)).unwrap(),
                1 => fs::hard_link(&stage, fixture.directory.join("alias")).unwrap(),
                2 => {
                    fs::rename(&stage, fixture.directory.join("original")).unwrap();
                    symlink(fixture.directory.join("original"), &stage).unwrap();
                }
                3 => OpenOptions::new()
                    .write(true)
                    .open(&stage)
                    .unwrap()
                    .set_len(MAX_BYTES + 1)
                    .unwrap(),
                _ => {
                    let hash = identity(&stage).unwrap().sha256;
                    fixture.write(&format!(".archive-retained-{hash}-{review}.json"), b"{");
                }
            }
            let ledger = fs::read(fixture.directory.join("ledger.json")).unwrap();
            assert!(fixture
                .store
                .recover_stage_checked(&review, || Ok(()))
                .is_err());
            assert_eq!(
                fs::read(fixture.directory.join("ledger.json")).unwrap(),
                ledger
            );
            assert!(stage.symlink_metadata().is_ok());
            if fault == 4 {
                assert!(fixture.store.read().is_err());
                assert_eq!(
                    fs::read(fixture.directory.join(format!(
                        ".archive-retained-{}-{review}.json",
                        bundle::hex(&Sha256::digest(b"{"))
                    )))
                    .unwrap(),
                    b"{"
                );
            }
        }
    }

    #[test]
    fn damaged_incidents_and_file_directory_limits_fence_without_evidence_eviction() {
        let mut fixture = Fixture::new();
        let stage = fixture.stage(b"{");
        let hash = identity(&stage).unwrap().sha256;
        for index in 0..MAX_ARCHIVE_FILES - 1 {
            fixture.write(&format!(".archive-retained-{hash}-{index:064x}.json"), b"{");
        }
        fixture
            .store
            .recover_stage_checked(&fixture.review(), || Ok(()))
            .unwrap();
        let before = fixture.store.read().unwrap();
        assert!(fixture
            .store
            .archive(&before.review().unwrap(), "b".repeat(32))
            .is_err());
        assert_eq!(fixture.store.read().unwrap(), before);
        let damaged = fixture
            .directory
            .join(format!(".archive-retained-{hash}-{}.json", "0".repeat(64)));
        fs::write(&damaged, b"different").unwrap();
        assert!(fixture.store.stage_recovery_status().is_err());
        assert_eq!(fs::read(&damaged).unwrap(), b"different");
        fs::write(damaged, b"{").unwrap();
        for index in 0..MAX_DIRECTORY_ENTRIES {
            fixture.write(&format!("unrelated-{index}"), b"x");
        }
        assert!(fixture.store.stage_recovery_status().is_err());
        assert_eq!(fixture.store.read().unwrap(), before);
    }

    #[test]
    fn preparation_names_are_canonical_and_preserve_full_width_generations() {
        assert!(reference(&format!(
            ".archive-stage-archive-{}-{}.json",
            u64::MAX,
            "a".repeat(64)
        ))
        .is_ok());
        for generation in ["0", "01", "+1", "18446744073709551616"] {
            assert!(reference(&format!(
                ".archive-stage-archive-{generation}-{}.json",
                "a".repeat(64)
            ))
            .is_err());
        }
    }
}
