//! A held flock is not authority after its pathname or directory is replaced.
//! Loss is sticky for this session; only a fresh locked load can resume work.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::Ordering;

pub(super) fn directory_identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err("resource authority directory is not private root state".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn private_lock(metadata: &fs::Metadata) -> Result<(u64, u64)> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("resource lifetime lock lost private inode custody".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

impl Store {
    pub(super) fn verify_exclusion(&self) -> Result<()> {
        if self.authority_lost.load(Ordering::Acquire) {
            return Err("resource authority exclusion lost; preserve state and restart".into());
        }
        let result = (|| -> Result<()> {
            if directory_identity(&self.directory)? != self.directory_identity
                || private_lock(&self._lock.metadata()?)?
                    != private_lock(&fs::symlink_metadata(self.directory.join("ledger.lock"))?)?
            {
                return Err("resource authority directory or lifetime lock was replaced".into());
            }
            Ok(())
        })();
        if result.is_err() {
            self.authority_lost.store(true, Ordering::Release);
        }
        result
    }

    pub(super) fn durable_bytes(&self) -> Result<Vec<u8>> {
        self.verify_exclusion()?;
        let result = (|| -> Result<Vec<u8>> {
            let bytes = tpm::private_read(&self.directory.join("ledger.json"), MAX_BYTES)?;
            if bundle::hex(&Sha256::digest(&bytes)) != self.published_sha256 {
                return Err("resource ledger changed outside this writer; preserve state".into());
            }
            self.verify_exclusion()?;
            Ok(bytes)
        })();
        if result.is_err() {
            self.authority_lost.store(true, Ordering::Release);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture {
        root: PathBuf,
        directory: PathBuf,
        store: Store,
        owner: Owner,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("luma-resource-exclusion-{}", random_id().unwrap()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let directory = root.join("authority");
            initialize(&directory).unwrap();
            let mut store = Store::open(&directory).unwrap();
            let owner = Owner {
                uid: 989,
                pid: 123,
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
                    ledger.admit(
                        owner.clone(),
                        "first".into(),
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
            Self {
                root,
                directory,
                store,
                owner,
            }
        }
        fn bytes(&self) -> Vec<u8> {
            fs::read(self.directory.join("ledger.json")).unwrap()
        }
        fn assert_fenced(&mut self) {
            assert!(self.store.read().is_err());
            assert!(self.store.request_directory().is_err());
            assert!(self.store.owner_retired(&self.owner).is_err());
            assert!(self.store.stage_recovery_status().is_err());
            assert!(self.store.recovery_binding().is_err());
            assert!(self
                .store
                .transact::<()>(|_| panic!("lost authority cannot execute a mutation"))
                .is_err());
            assert!(self
                .store
                .observe(|_| panic!("lost authority cannot update telemetry"))
                .is_err());
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn replacement_lock_cannot_leave_the_original_writer_active_or_clear_a_latched_loss() {
        let mut f = Fixture::new();
        let original = f.bytes();
        let lock = f.directory.join("ledger.lock");
        let retained = f.directory.join("retained-lock");
        fs::rename(&lock, &retained).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap();
        let fresh = Store::open(&f.directory).unwrap();
        assert_eq!(fresh.read().unwrap().charged("host").unwrap(), 40);
        f.assert_fenced();
        assert_eq!(f.bytes(), original);
        assert!(Store::open(&f.directory).is_err());
        drop(fresh);
        fs::remove_file(&lock).unwrap();
        fs::rename(&retained, &lock).unwrap();
        f.assert_fenced();
        assert_eq!(f.bytes(), original);
        assert!(Store::open(&f.directory).is_err());
    }

    #[test]
    fn authority_directory_replacement_and_alias_never_redirect_an_existing_writer() {
        for alias in [false, true] {
            let mut f = Fixture::new();
            let original = f.bytes();
            let retained = f.root.join("retained-authority");
            fs::rename(&f.directory, &retained).unwrap();
            if alias {
                symlink(&retained, &f.directory).unwrap();
            } else {
                initialize(&f.directory).unwrap();
            }
            f.assert_fenced();
            assert_eq!(fs::read(retained.join("ledger.json")).unwrap(), original);
            if alias {
                fs::remove_file(&f.directory).unwrap();
            } else {
                let fresh = Store::open(&f.directory).unwrap();
                assert_eq!(fresh.read().unwrap(), Ledger::empty());
                drop(fresh);
                fs::remove_dir_all(&f.directory).unwrap();
            }
            fs::rename(retained, &f.directory).unwrap();
            f.assert_fenced();
            assert_eq!(f.bytes(), original);
        }
    }

    #[test]
    fn missing_linked_aliased_or_nonprivate_locks_and_directory_modes_latch_refusal() {
        for fault in 0..6 {
            let mut f = Fixture::new();
            let original = f.bytes();
            let lock = f.directory.join("ledger.lock");
            let other = f.directory.join("retained-lock");
            match fault {
                0 => fs::rename(&lock, &other).unwrap(),
                1 => fs::hard_link(&lock, &other).unwrap(),
                2 => {
                    fs::rename(&lock, &other).unwrap();
                    symlink(&other, &lock).unwrap();
                }
                3 => fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap(),
                4 => fs::set_permissions(&f.directory, fs::Permissions::from_mode(0o755)).unwrap(),
                _ => fs::set_permissions(&lock, fs::Permissions::from_mode(0o4600)).unwrap(),
            }
            f.assert_fenced();
            assert_eq!(f.bytes(), original);
            match fault {
                0 => fs::rename(&other, &lock).unwrap(),
                1 => fs::remove_file(&other).unwrap(),
                2 => {
                    fs::remove_file(&lock).unwrap();
                    fs::rename(&other, &lock).unwrap();
                }
                3 | 5 => fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap(),
                _ => fs::set_permissions(&f.directory, fs::Permissions::from_mode(0o700)).unwrap(),
            }
            f.assert_fenced();
        }
    }

    #[test]
    fn changed_canonical_ledger_bytes_are_not_an_authorized_update_or_a_capacity_credit() {
        for malformed in [false, true] {
            let mut f = Fixture::new();
            let original = f.bytes();
            let path = f.directory.join("ledger.json");
            let changed = if malformed {
                b"{".to_vec()
            } else {
                let mut ledger = f.store.read().unwrap();
                let token = ledger.leases[0].token.clone();
                ledger.revoke(&token, "outside-writer").unwrap();
                ledger
                    .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
                    .unwrap();
                serde_json::to_vec(&ledger).unwrap()
            };
            platform::write_atomic(&path, &changed, 0o600).unwrap();
            f.assert_fenced();
            assert_eq!(fs::read(&path).unwrap(), changed);
            platform::write_atomic(&path, &original, 0o600).unwrap();
            f.assert_fenced();
            assert_eq!(f.bytes(), original);
        }
    }

    #[test]
    fn successful_publisher_return_without_exact_readback_never_acknowledges_a_transition() {
        for wrong in [false, true] {
            let mut f = Fixture::new();
            let original = f.bytes();
            let result = f.store.transaction(
                |ledger| {
                    let token = ledger.leases[0].token.clone();
                    ledger.revoke(&token, "operator-revoked")
                },
                true,
                |path, _| {
                    if wrong {
                        platform::write_atomic(path, b"{", 0o600)?;
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            f.assert_fenced();
            assert_eq!(f.bytes(), if wrong { b"{".to_vec() } else { original });
        }
    }

    #[test]
    fn lock_loss_during_publication_or_unchanged_telemetry_never_returns_success() {
        for changed in [false, true] {
            let mut f = Fixture::new();
            let original = f.bytes();
            let lock = f.directory.join("ledger.lock");
            let retained = f.directory.join("retained-lock");
            let result = if changed {
                f.store.transaction(
                    |ledger| {
                        let token = ledger.leases[0].token.clone();
                        ledger.revoke(&token, "operator-revoked")
                    },
                    true,
                    |path, bytes| {
                        platform::write_atomic(path, bytes, 0o600)?;
                        fs::rename(&lock, &retained)?;
                        Ok(())
                    },
                )
            } else {
                f.store.observe(|ledger| {
                    fs::rename(&lock, &retained)?;
                    ledger.observe("host", 1, 0)
                })
            };
            assert!(result.is_err());
            f.assert_fenced();
            if !changed {
                assert_eq!(f.bytes(), original);
            } else {
                let ledger: Ledger = serde_json::from_slice(&f.bytes()).unwrap();
                assert_eq!(ledger.charged("host").unwrap(), 40);
                assert_eq!(ledger.leases[0].state, State::Draining);
            }
        }
    }
}
