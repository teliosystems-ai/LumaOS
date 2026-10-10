//! Reviewed preservation and explicit governed deletion of unreferenced archive
//! evidence. Referenced authority, owner tombstones and accounting remain intact.
use super::*;
use std::os::unix::fs::MetadataExt;

pub(super) const MAX_DIRECTORY_ENTRIES: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    fn deletion_plan(&self, names: &[String]) -> Result<DeletionPlan> {
        if names.is_empty() || names.len() > 16 {
            return Err("resource retention requires one to sixteen exact evidence names".into());
        }
        let ledger = self.read()?;
        if ledger.generation == 0
            || ledger
                .leases
                .iter()
                .any(|lease| lease.state != State::Released)
        {
            return Err(
                "resource retention requires an initialized, physically released ledger".into(),
            );
        }
        self.verify_archives(&ledger)?;
        crate::resource_manager::requests::retention_idle(self)?;
        let requests = identity(&self.directory.join("requests.json"))?;
        let mut files = BTreeMap::new();
        for name in names {
            if files.contains_key(name) {
                return Err("duplicate resource retention target".into());
            }
            if let Some(suffix) = name.strip_prefix(".archive-retained-") {
                verify_retained(&self.directory.join(name), suffix)?;
            } else if name.starts_with(".archive-stage-") {
                let archive = reference(name)?;
                if archive.through_generation > ledger.generation {
                    return Err("future resource archive preparation cannot be deleted".into());
                }
            } else if let Some(suffix) = name.strip_prefix("archive-") {
                let archive = reference(&format!(".archive-stage-archive-{suffix}"))?;
                if ledger.archives.contains(&archive) {
                    return Err(
                        "referenced resource receipts and owner tombstones cannot be deleted"
                            .into(),
                    );
                }
                self.archived(&archive)?;
            } else if name.starts_with(".requests-") || name.starts_with("requests-archive-") {
                crate::resource_manager::requests::retention_evidence(self, name)?;
            } else {
                return Err(
                    "resource retention accepts only exact unreferenced archive evidence".into(),
                );
            }
            files.insert(name.clone(), identity(&self.directory.join(name))?);
        }
        let ledger_identity = identity(&self.directory.join("ledger.json"))?;
        self.verify_exclusion()?;
        Ok(DeletionPlan {
            schema_version: 1,
            generation: ledger.generation,
            directory: self.directory_identity,
            ledger: ledger_identity,
            requests,
            files,
        })
    }

    pub(crate) fn retention_proposal(&self, names: &[String]) -> Result<serde_json::Value> {
        let plan = self.deletion_plan(names)?;
        Ok(
            serde_json::json!({"schema_version":1,"review_sha256":plan.review()?,
            "usage":plan.usage()?,"files":plan.files,"authority_chain_preserved":true,
            "worker_resources_released":false,"deletion_performed":false}),
        )
    }

    pub(crate) fn retention_usage(
        &self,
        names: &[String],
        reviewed: &str,
    ) -> Result<crate::finite_grants::Use> {
        let plan = self.deletion_plan(names)?;
        if plan.review()? != reviewed {
            return Err("resource retention review changed".into());
        }
        plan.usage()
    }

    pub(crate) fn retention_outcomes(&self) -> Result<serde_json::Value> {
        self.read()?;
        let mut outcomes = BTreeMap::new();
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index >= MAX_DIRECTORY_ENTRIES {
                return Err("resource retention audit inspection bound exceeded".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or("invalid resource retention evidence name")?;
            let Some(reviewed) = name
                .strip_prefix(".retention-")
                .and_then(|s| s.strip_suffix(".intent.json"))
            else {
                continue;
            };
            if !hash(reviewed) || outcomes.len() >= 64 {
                return Err("resource retention audit inventory invalid or exhausted".into());
            }
            let bytes = tpm::private_read(&entry.path(), MAX_BYTES)?;
            let plan: DeletionPlan = serde_json::from_slice(&bytes)?;
            if plan.schema_version != 1
                || plan.generation == 0
                || plan.files.is_empty()
                || plan.files.len() > 16
                || plan.review()? != reviewed
                || serde_json::to_vec(&plan)? != bytes
            {
                return Err("resource retention intent damaged; retain evidence".into());
            }
            plan.usage()?;
            let receipt_path = self
                .directory
                .join(format!(".retention-{reviewed}.receipt.json"));
            let confirmed = match fs::symlink_metadata(&receipt_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    let receipt = tpm::private_read(&receipt_path, MAX_BYTES)?;
                    let expected = serde_json::json!({"schema_version":1,"review_sha256":reviewed,
                        "deleted":plan.files,"authority_chain_preserved":true,
                        "generation_preserved":true,"worker_resources_released":false});
                    if serde_json::to_vec(&expected)? != receipt {
                        return Err("resource retention receipt damaged; retain evidence".into());
                    }
                    true
                }
            };
            outcomes.insert(reviewed.to_string(), serde_json::json!({"targets":plan.files,
                "outcome":if confirmed { "confirmed-local-deletion" } else { "uncertain-inspect-no-automatic-retry" },
                "receipt_authority":false,"worker_resources_released":false}));
        }
        self.verify_exclusion()?;
        Ok(
            serde_json::json!({"schema_version":1,"outcomes":outcomes,"records_are_authority":false}),
        )
    }

    /// The caller supplies a live typed product boundary and retained physical
    /// shutdown proof. A receipt or the review digest is never authorization.
    pub(crate) fn delete_retained_checked(
        &mut self,
        names: &[String],
        reviewed: &str,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        let plan = self.deletion_plan(names)?;
        if plan.review()? != reviewed {
            return Err("resource retention review changed".into());
        }
        check()?;
        if self.deletion_plan(names)? != plan {
            return Err("resource retention target drifted after authorization".into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.directory)?;
        use std::os::fd::AsRawFd;
        let pinned = directory.metadata()?;
        if (pinned.dev(), pinned.ino()) != plan.directory {
            return Err("resource retention directory changed".into());
        }
        let result = (|| -> Result<serde_json::Value> {
            let intent_name = format!(".retention-{reviewed}.intent.json");
            let receipt_name = format!(".retention-{reviewed}.receipt.json");
            if self.retention_outcomes()?["outcomes"]
                .as_object()
                .ok_or("invalid retention outcome inventory")?
                .len()
                >= 64
            {
                return Err(
                    "resource retention outcome inventory exhausted; no automatic audit eviction"
                        .into(),
                );
            }
            let count = fs::read_dir(&self.directory)?.try_fold(
                0usize,
                |count, entry| -> Result<usize> {
                    entry?;
                    Ok(count + 1)
                },
            )?;
            if count >= MAX_DIRECTORY_ENTRIES - 2 {
                return Err(
                    "resource retention audit inventory exhausted; preserve prior outcomes".into(),
                );
            }
            // These records are historical data only. Their presence never
            // authorizes a retry, an accounting reset or an inferred success.
            publish_evidence(&directory, &intent_name, &serde_json::to_vec(&plan)?)?;
            for (name, expected) in &plan.files {
                check()?;
                self.verify_exclusion()?;
                if identity(&self.directory.join("ledger.json"))? != plan.ledger
                    || identity(&self.directory.join("requests.json"))? != plan.requests
                    || identity(&self.directory.join(name))? != *expected
                {
                    return Err(
                        "resource retention authority or evidence changed before deletion".into(),
                    );
                }
                // Bind the unlink to the held authority directory, never a
                // caller-selected parent or a subsequently substituted path.
                let member = std::ffi::CString::new(name.as_bytes())?;
                if unsafe { libc::unlinkat(directory.as_raw_fd(), member.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                directory.sync_all()?;
                match fs::symlink_metadata(self.directory.join(name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err("resource evidence deletion outcome is uncertain".into()),
                }
                self.verify_exclusion()?;
                if identity(&self.directory.join("ledger.json"))? != plan.ledger
                    || identity(&self.directory.join("requests.json"))? != plan.requests
                {
                    return Err("resource ledger changed during evidence deletion".into());
                }
            }
            self.verify_archives(&self.read()?)?;
            crate::resource_manager::requests::retention_idle(self)?;
            let receipt = serde_json::json!({"schema_version":1,"review_sha256":reviewed,
                "deleted":plan.files,"authority_chain_preserved":true,
                "generation_preserved":true,"worker_resources_released":false});
            publish_evidence(&directory, &receipt_name, &serde_json::to_vec(&receipt)?)?;
            Ok(receipt)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

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

fn publish_evidence(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let member = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            member.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeletionPlan {
    schema_version: u32,
    #[serde(with = "decimal")]
    generation: u64,
    directory: (u64, u64),
    ledger: Identity,
    requests: Identity,
    files: BTreeMap<String, Identity>,
}
impl DeletionPlan {
    fn review(&self) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"luma-resource-unreferenced-evidence-deletion-v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(bundle::hex(&hash.finalize()))
    }
    fn usage(&self) -> Result<crate::finite_grants::Use> {
        let usage = crate::finite_grants::Use {
            action: crate::finite_grants::Action::Retain,
            selector: crate::finite_grants::Selector {
                kind: crate::finite_grants::Kind::Resource,
                id: "resource-retention".into(),
                generation: self.generation,
                digest: self.review()?,
            },
            input_bytes: self.files.values().try_fold(0u64, |sum, file| {
                sum.checked_add(file.length)
                    .ok_or("resource evidence size overflow")
            })?,
            output_bytes: 0,
            units: self.files.len() as u64,
        };
        usage.validate()?;
        Ok(usage)
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

    #[test]
    fn governed_evidence_deletion_preserves_all_authority_and_records_exact_outcome() {
        let mut fixture = Fixture::new();
        let bytes = b"incomplete archived preparation";
        let name = format!(
            ".archive-retained-{}-{}.json",
            bundle::hex(&Sha256::digest(bytes)),
            "a".repeat(64)
        );
        fixture.write(&name, bytes);
        let names = vec![name.clone()];
        let ledger = fs::read(fixture.directory.join("ledger.json")).unwrap();
        let requests = fs::read(fixture.directory.join("requests.json")).unwrap();
        let proposal = fixture.store.retention_proposal(&names).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        let usage = fixture.store.retention_usage(&names, review).unwrap();
        assert_eq!(usage.action, crate::finite_grants::Action::Retain);
        assert_eq!(usage.selector.kind, crate::finite_grants::Kind::Resource);
        assert_eq!(usage.selector.digest, review);
        assert_eq!(usage.input_bytes, bytes.len() as u64);
        let mut checks = 0;
        let result = fixture
            .store
            .delete_retained_checked(&names, review, || {
                checks += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(checks, 2);
        assert!(!fixture.directory.join(name).exists());
        assert_eq!(result["worker_resources_released"], false);
        assert_eq!(
            fs::read(fixture.directory.join("ledger.json")).unwrap(),
            ledger
        );
        assert_eq!(
            fs::read(fixture.directory.join("requests.json")).unwrap(),
            requests
        );
        assert_eq!(fixture.store.read().unwrap().charged("host").unwrap(), 7);
        let outcomes = fixture.store.retention_outcomes().unwrap();
        assert_eq!(
            outcomes["outcomes"][review]["outcome"],
            "confirmed-local-deletion"
        );
        assert_eq!(outcomes["outcomes"][review]["receipt_authority"], false);
        assert!(fixture
            .store
            .delete_retained_checked(&names, review, || panic!("receipt cannot authorize replay"))
            .is_err());
    }

    #[test]
    fn retention_never_deletes_referenced_receipts_or_accepts_ambiguous_names() {
        let mut fixture = Fixture::new();
        let archived = fixture
            .store
            .archive(
                &fixture.store.read().unwrap().review().unwrap(),
                "b".repeat(32),
            )
            .unwrap();
        let original = fs::read(fixture.directory.join(archived.name())).unwrap();
        for names in [
            vec![],
            vec![archived.name()],
            vec!["ledger.json".into()],
            vec!["../ledger.json".into()],
            vec![".archive-stage-archive-01-unknown.json".into()],
        ] {
            assert!(fixture.store.retention_proposal(&names).is_err());
        }
        let name = format!(
            ".archive-retained-{}-{}.json",
            bundle::hex(&Sha256::digest(b"evidence")),
            "c".repeat(64)
        );
        fixture.write(&name, b"evidence");
        assert!(fixture
            .store
            .retention_proposal(&vec![name.clone(), name])
            .is_err());
        assert_eq!(
            fs::read(fixture.directory.join(archived.name())).unwrap(),
            original
        );
        assert!(fixture.store.owner_retired(&fixture.owner).unwrap());
    }

    #[test]
    fn partial_retention_batch_is_durable_uncertain_and_never_frees_accounting() {
        let mut fixture = Fixture::new();
        let digest = bundle::hex(&Sha256::digest(b"evidence"));
        let names: Vec<_> = (0..2)
            .map(|n| format!(".archive-retained-{digest}-{n:064x}.json"))
            .collect();
        for name in &names {
            fixture.write(name, b"evidence");
        }
        let proposal = fixture.store.retention_proposal(&names).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        let ledger = fs::read(fixture.directory.join("ledger.json")).unwrap();
        let mut checks = 0;
        assert!(fixture
            .store
            .delete_retained_checked(&names, review, || {
                checks += 1;
                if checks == 3 {
                    Err("live grant or shutdown generation lost".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(!fixture.directory.join(&names[0]).exists());
        assert!(fixture.directory.join(&names[1]).exists());
        assert!(fixture.store.read().is_err());
        assert_eq!(
            fs::read(fixture.directory.join("ledger.json")).unwrap(),
            ledger
        );
        let replacement = OpenOptions::new().read(true).open("/dev/null").unwrap();
        drop(std::mem::replace(&mut fixture.store._lock, replacement));
        let fresh = Store::open(&fixture.directory).unwrap();
        assert_eq!(fresh.read().unwrap().charged("host").unwrap(), 7);
        assert_eq!(
            fresh.retention_outcomes().unwrap()["outcomes"][review]["outcome"],
            "uncertain-inspect-no-automatic-retry"
        );
    }

    #[test]
    fn changed_retention_bytes_stale_review_and_refused_authentication_have_no_effect() {
        let mut fixture = Fixture::new();
        let names = vec![format!(".archive-stage-archive-1-{}.json", "d".repeat(64))];
        fixture.write(&names[0], b"{");
        let proposal = fixture.store.retention_proposal(&names).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        assert!(fixture
            .store
            .delete_retained_checked(&names, review, || Err(
                "current governed boundary refused".into()
            ))
            .is_err());
        assert!(fixture.store.read().is_ok());
        assert!(!fixture
            .directory
            .join(format!(".retention-{review}.intent.json"))
            .exists());
        fs::write(fixture.directory.join(&names[0]), b"different").unwrap();
        assert!(fixture.store.retention_usage(&names, review).is_err());
        assert!(fixture
            .store
            .delete_retained_checked(&names, review, || panic!("stale review before auth"))
            .is_err());
        assert_eq!(
            fs::read(fixture.directory.join(&names[0])).unwrap(),
            b"different"
        );
    }

    #[test]
    fn request_incident_retention_preserves_exact_hot_journal_and_refuses_damage() {
        let mut fixture = Fixture::new();
        let name = format!(
            ".requests-retained-{}-{}.json",
            bundle::hex(&Sha256::digest(b"partial request evidence")),
            "e".repeat(64)
        );
        fixture.write(&name, b"partial request evidence");
        let names = vec![name.clone()];
        let requests = fs::read(fixture.directory.join("requests.json")).unwrap();
        let proposal = fixture.store.retention_proposal(&names).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        fixture
            .store
            .delete_retained_checked(&names, review, || Ok(()))
            .unwrap();
        assert_eq!(
            fs::read(fixture.directory.join("requests.json")).unwrap(),
            requests
        );
        fixture.write(&name, b"partial request evidence");
        fs::write(fixture.directory.join("requests.json"), b"{").unwrap();
        assert!(fixture.store.retention_proposal(&names).is_err());
        assert!(fixture.directory.join(name).exists());
    }
}
