#[cfg(test)]
pub(crate) mod emulator {
    use super::*;
    use crate::tpm::UtcDevice;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    type UtcLock = CheckpointLock;
    fn fixture_genesis(root: &Path, installation: &str) -> [u8; 32] {
        let publisher = root.with_extension("publisher");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&publisher)
            .unwrap();
        let value = genesis_descriptor(
            installation,
            checkpoint_identity(&fs::metadata(&publisher).unwrap()),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        let genesis = Sha256::digest(&bytes).into();
        write_new(&root.join("genesis.json"), &bytes).unwrap();
        validate_genesis_binding(root, installation, genesis).unwrap();
        genesis
    }
    fn emulator_windows_utc_enrollment_sealed_restart_and_exact_extend() {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("windows_utc-state");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("windows_utc-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let installation = "11".repeat(32);
        let genesis = fixture_genesis(&root, &installation);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let review = proposal["review_sha256"].as_str().unwrap();
        let prepared = provisioner
            .prepare(&installation, genesis, review, &owner, &secret, || Ok(()))
            .unwrap();
        let mut anchor = prepared.commit(&owner, &secret, || Ok(())).unwrap();
        assert_eq!(anchor.installation(), installation);
        assert_eq!(anchor.genesis_event(), genesis);
        let head = tpm::extend_value([0; 32], genesis);
        assert_eq!(anchor.read().unwrap(), head);
        assert!(tpm::exclusive_lock(&lock_path).is_err());
        let publisher = PublisherRoot::fixture(&root.with_extension("publisher")).unwrap();
        crate::utc_windows::exercise_emulator_journal(
            &publisher,
            &mut anchor,
            &root,
            &public,
            &signature,
        );
        let head = anchor.read().unwrap();
        let next = anchor.advance(head, [0x72; 32]).unwrap();
        assert_eq!(next, tpm::extend_value(head, [0x72; 32]));
        assert!(anchor.advance(head, [0x73; 32]).is_err());
        assert_eq!(anchor.read().unwrap(), next);
        drop(anchor);
        let mut reopened = UtcAnchor::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        assert_eq!(reopened.read().unwrap(), next);
        assert!(Provisioner::fixture(
            &directory,
            &root,
            File::open("/dev/null").unwrap(),
            &public,
            &signature
        )
        .is_err());
        let saved = immutable(&root.join("sealed/anchor.json"), MAX_CONFIG).unwrap();
        let mut substituted: Configuration = canonical(&saved).unwrap();
        substituted.index = 0x01804c41;
        assert!(substituted.validate().is_err());
        drop(reopened);
        let credential_path = root.join("sealed/nv-auth.cred");
        let credential = immutable(&credential_path, MAX_CREDENTIAL).unwrap();
        let mut envelope: Sealed = canonical(&credential).unwrap();
        envelope.installation = "39".repeat(32);
        let changed_credential = serde_json::to_vec(&envelope).unwrap();
        let mut changed: Configuration = canonical(&saved).unwrap();
        changed.installation = envelope.installation.clone();
        changed.sealed_credential_sha256 = digest(&changed_credential);
        for (path, bytes) in [
            (
                root.join("sealed/anchor.json"),
                serde_json::to_vec(&changed).unwrap(),
            ),
            (credential_path.clone(), changed_credential),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        assert!(UtcAnchor::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature
        )
        .is_err());
        for (path, bytes) in [
            (root.join("sealed/anchor.json"), saved),
            (credential_path, credential),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        let mut restored = UtcAnchor::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        assert_eq!(restored.read().unwrap(), next);
    }
    fn emulator_windows_utc_lost_publication_is_explicit_finalize_without_nv_replay() {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("windows_utc-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("windows_utc-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let installation = "12".repeat(32);
        let genesis = fixture_genesis(&root, &installation);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let prepared = provisioner
            .prepare(
                &installation,
                genesis,
                proposal["review_sha256"].as_str().unwrap(),
                &owner,
                &secret,
                || Ok(()),
            )
            .unwrap();
        let mut boundaries = 0;
        assert!(prepared
            .commit(&owner, &secret, || {
                boundaries += 1;
                if boundaries == 3 {
                    Err("fixture loses final publication authority".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(boundaries, 3);
        assert!(root
            .join(".enrollment-prepared/nv-dispatched.json")
            .is_file());
        assert!(!root.join("sealed").exists());
        let pending = PendingPublication::open_at(
            &root,
            UtcDevice::fixture(&directory).unwrap(),
            UtcLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let report = pending.report();
        assert_eq!(report["nv_write_retry"], false);
        assert!(pending
            .finalize(&installation, genesis, &"00".repeat(32), || panic!(
                "wrong review cannot publish"
            ))
            .is_err());
        let pending = PendingPublication::open_at(
            &root,
            UtcDevice::fixture(&directory).unwrap(),
            UtcLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let mut anchor = pending
            .finalize(
                &installation,
                genesis,
                report["review_sha256"].as_str().unwrap(),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(anchor.read().unwrap(), tpm::extend_value([0; 32], genesis));
        assert!(root.join("sealed").is_dir());
        assert!(!root.join(".enrollment-prepared").exists());
    }
    fn emulator_windows_utc_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay(
    ) {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("windows_utc-parent-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("windows_utc-anchor.lock");
        let mut owner = PrivateBuffer::new(32).unwrap();
        File::open(directory.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let secret = Secret::generate().unwrap();
        let installation = "13".repeat(32);
        let genesis = fixture_genesis(&root, &installation);
        let mut provisioner = Provisioner::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let proposal = provisioner.proposal(&installation, genesis).unwrap();
        let mut boundaries = 0;
        assert!(provisioner
            .prepare(
                &installation,
                genesis,
                proposal["review_sha256"].as_str().unwrap(),
                &owner,
                &secret,
                || {
                    boundaries += 1;
                    if boundaries == 5 {
                        Err("fixture loses parent persistence reply before sealing".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert_eq!(boundaries, 5);
        assert!(!root.join(".enrollment-prepared").exists());
        let expected = immutable(&root.join(".parent-name.json"), MAX_CONFIG).unwrap();
        assert_eq!(
            immutable(&root.join(".parent-dispatched.json"), MAX_CONFIG).unwrap(),
            expected
        );
        let pending = ParentPending::open_at(
            &root,
            UtcDevice::fixture(&directory).unwrap(),
            UtcLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        let report = pending.report();
        assert_eq!(report["parent_persistence_replay"], false);
        let prepared = pending
            .resume(
                &installation,
                genesis,
                report["review_sha256"].as_str().unwrap(),
                &secret,
                || Ok(()),
            )
            .unwrap();
        let mut anchor = prepared.commit(&owner, &secret, || Ok(())).unwrap();
        assert_eq!(anchor.read().unwrap(), tpm::extend_value([0; 32], genesis));
        assert_eq!(
            immutable(&root.join(".parent-name.json"), MAX_CONFIG).unwrap(),
            expected
        );
        assert!(root.join(".parent-reconciled.json").is_file());
    }

    // Invoked by the already existing isolated three-authority test entry.
    // It is not an ignored test or a conditional passing unit test.
    pub(crate) fn exercise_emulator(
        mode: &str,
        admin_parent: [u8; 34],
        resource_parent: [u8; 34],
        content_parent: [u8; 34],
        admin_secret: &Secret,
        resource_secret: &Secret,
        content_secret: &Secret,
    ) {
        let folder = match mode {
            "normal" => {
                emulator_windows_utc_enrollment_sealed_restart_and_exact_extend();
                "windows_utc-state"
            }
            "lost-publication" => {
                emulator_windows_utc_lost_publication_is_explicit_finalize_without_nv_replay();
                "windows_utc-pending"
            }
            "lost-parent" => {
                emulator_windows_utc_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay();
                "windows_utc-parent-pending"
            }
            _ => panic!("unsupported disposable windows_utc TPM fixture scenario"),
        };
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let config: Configuration = canonical(
            &immutable(
                &directory.join(folder).join("sealed/anchor.json"),
                MAX_CONFIG,
            )
            .unwrap(),
        )
        .unwrap();
        let parent = tpm::decode::<34>(&config.parent_name).unwrap();
        assert_ne!(parent, admin_parent);
        assert_ne!(parent, resource_parent);
        assert_ne!(parent, content_parent);
        let mut wrong = UtcDevice::fixture(&directory).unwrap();
        assert!(wrong.connect(admin_secret).is_err());
        drop(wrong);
        let mut wrong = UtcDevice::fixture(&directory).unwrap();
        assert!(wrong.connect(resource_secret).is_err());

        drop(wrong);
        let mut wrong = UtcDevice::fixture(&directory).unwrap();
        assert!(wrong.connect(content_secret).is_err());
        drop(wrong);
        // Four independent persistent NV authorizations coexist while this
        // actual U credential is unsealed and its P256 key signs a real proof.
        let public =
            admin_credentials::public_input(&directory.join("pcr-public.pem"), 4096).unwrap();
        let signature =
            admin_credentials::public_input(&directory.join("pcr-signature.json"), 16384).unwrap();
        let mut device = UtcDevice::fixture(&directory).unwrap();
        let (config, _, _, _) = load(
            &directory.join(folder).join("sealed"),
            &mut device,
            &public,
            &signature,
        )
        .unwrap();
        let policy = current_policy(&mut device, &public, &signature).unwrap();
        let (scalar, key) = crate::utc_windows_crypto::generate(|| Ok(())).unwrap();
        let secret = Secret::from_buffer(scalar);
        let (a, b) = device.seal(&parent, &public, &secret).unwrap();
        let recovered = device
            .unseal(&parent, &public, &a, &b, &policy.digest, &policy.signature)
            .unwrap();
        assert_eq!(secret.bytes(), recovered.bytes());
        let mut locked = PrivateBuffer::new(32).unwrap();
        locked.bytes_mut().copy_from_slice(recovered.bytes());
        assert_eq!(
            crate::utc_windows_crypto::public(&locked, || Ok(())).unwrap(),
            key
        );
        let domain = crate::utc_windows_crypto::DOMAIN;
        let mut proof = (domain.len() as u32).to_be_bytes().to_vec();
        proof.extend(domain);
        proof.extend([1u8; 32]);
        proof.extend([2u8; 32]);
        proof.extend([3u8; 32]);
        proof.extend(1_800_000_000_000u64.to_be_bytes());
        proof.extend(1_800_000_000_500u64.to_be_bytes());
        let signed = crate::utc_windows_crypto::sign(&locked, &proof, || Ok(())).unwrap();
        crate::utc_windows_crypto::verify(&key, &proof, &signed, || Ok(())).unwrap();
        let mut bad = config.clone();
        bad.index = tpm::CONTENT_INDEX;
        assert!(bad.validate().is_err());
        assert_eq!(config.profile, CHECKPOINT_PROFILE);
    }
}
// Independently enrolled Windows UTC publisher checkpoint; no time authority from disk.
use crate::tpm::UtcDevice as CheckpointDevice;
#[cfg(test)]
use crate::tpm::UtcDevice;
pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/utc-windows-checkpoint";
pub(crate) const LOCK: &str = "/run/luma-utc-windows-checkpoint/authority.lock";
pub(crate) const INDEX: u32 = crate::tpm::UTC_INDEX;
pub(crate) const PARENT: u32 = crate::tpm::UTC_PARENT;
const MAGIC: &str = "luma-windows-utc-sealed-v1";
const RUNTIME_NAMESPACE: &str = "luma-utc-windows-checkpoint";
const RUNTIME_LOCK_NAME: &str = "luma-utc-windows-checkpoint/authority.lock";
const CHECKPOINT_PROFILE: &str = "local-tpm2-windows-utc";
const ENROLLMENT_KIND: &str = "utc-windows-checkpoint-enrollment";
const CUSTODY_KIND: &str = "existing-owner-independent-windows-utc-auth";
const PARENT_RECONCILE_PURPOSE: &str = "windows-utc-parent-reconcile-v1";
const PARENT_RECONCILE_KIND: &str = "windows-utc-parent-reconcile";
const FINALIZE_PURPOSE: &str = "windows-utc-pending-finalize-v1";
const FINALIZE_KIND: &str = "windows-utc-pending-finalize";
fn checkpoint_name() -> [u8; 34] {
    crate::tpm::utc_checkpoint_name()
}
include!("independent_checkpoint.rs");
fn validate_genesis_binding(root: &Path, installation: &str, genesis: [u8; 32]) -> Result<()> {
    let bytes = immutable(&root.join("genesis.json"), 4096)?;
    let witness: serde_json::Value = canonical(&bytes)?;
    crate::utc_windows::validate_genesis_witness(&witness, installation, genesis)
}
fn retain_genesis_statement(
    installation: &str,
    genesis: [u8; 32],
    statement: &serde_json::Value,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    crate::utc_windows::validate_genesis_witness(statement, installation, genesis)?;
    let bytes = serde_json::to_vec(statement)?;
    let path = Path::new(DIRECTORY).join("genesis.json");
    check()?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if immutable(&path, 4096)? != bytes {
                return Err("UTC original genesis witness differs; no overwrite".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_new(&path, &bytes)?,
        Err(error) => return Err(error.into()),
    }
    check()?;
    validate_genesis_binding(Path::new(DIRECTORY), installation, genesis)
}
pub(crate) type UtcAnchor = IndependentAnchor;
#[cfg(test)]
impl CheckpointLock {
    fn fixture(file: File) -> Result<Self> {
        let path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        Self::from_file(file, &path)
    }
}

#[cfg(test)]
impl IndependentAnchor {
    pub(crate) fn fixture(
        directory: &Path,
        root: &Path,
        lock: File,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        let mut device = UtcDevice::fixture(directory)?;
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16 * 1024)?;
        let (config, secret, _, _) = load(&root.join("sealed"), &mut device, &public, &signature)?;
        Self::connect(device, &secret, CheckpointLock::fixture(lock)?, &config)
    }
}

#[cfg(test)]
impl Provisioner {
    pub(crate) fn fixture(
        directory: &Path,
        root: &Path,
        lock: File,
        public_path: &Path,
        signature_path: &Path,
    ) -> Result<Self> {
        Self::from_device(
            UtcDevice::fixture(directory)?,
            root,
            CheckpointLock::fixture(lock)?,
            public_path,
            signature_path,
        )
    }
}
pub(crate) fn genesis_descriptor(
    installation: &str,
    identity: (u64, u64, u32, u32, u32),
) -> Result<serde_json::Value> {
    nonzero(installation)?;
    if identity.0 == 0 || identity.1 == 0 || identity.2 != 0 || identity.4 != 0o40700 {
        return Err("UTC genesis witness requires original private directory identity".into());
    }
    Ok(
        serde_json::json!({"schema_version":1,"kind":"luma-windows-utc-explicit-empty-genesis-v1",
        "installation":installation,"namespace":crate::utc_windows::DIRECTORY,"identity":{
        "device":identity.0.to_string(),"inode":identity.1.to_string(),"uid":identity.2,"gid":identity.3,"mode":identity.4},"domains":[]}),
    )
}
pub(crate) struct PublisherRoot(PersistentDirectory);
impl PublisherRoot {
    #[cfg(test)]
    fn fixture(path: &Path) -> Result<Self> {
        Ok(Self(PersistentDirectory::capture(path)?))
    }
    pub(crate) fn installed() -> Result<Self> {
        Ok(Self(PersistentDirectory::capture(Path::new(
            crate::utc_windows::DIRECTORY,
        ))?))
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.0.check()
    }
    pub(crate) fn descriptor(&self) -> &File {
        &self.0.file
    }
    pub(crate) fn is_empty(&self) -> Result<bool> {
        self.recheck()?;
        let empty = fs::read_dir(&self.0.path)?.next().transpose()?.is_none();
        self.recheck()?;
        Ok(empty)
    }
}
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublisherSealed {
    format: String,
    installation: String,
    parent_name: String,
    signer_sha256: String,
    public_blob: String,
    private_blob: String,
}
impl IndependentAnchor {
    fn key_context(&mut self) -> Result<(Configuration, Vec<u8>, Vec<u8>, Policy)> {
        self.live()?;
        let config: Configuration = canonical(&immutable(
            &Path::new(DIRECTORY).join("sealed/anchor.json"),
            MAX_CONFIG,
        )?)?;
        config.validate()?;
        if config.installation != self.installation
            || nonzero(&config.genesis_event)? != self.genesis
        {
            return Err("UTC sealed key parent configuration changed".into());
        }
        let public = admin_credentials::public_input(Path::new(PUBLIC), 4096)?;
        let signature = admin_credentials::public_input(Path::new(SIGNATURE), 16 * 1024)?;
        if digest(&public) != config.pcr_public_key_sha256 {
            return Err("UTC signer pin changed".into());
        }
        let policy = current_policy(&mut self.device, &public, &signature)?;
        self.lock.check()?;
        Ok((config, public, signature, policy))
    }
    pub(crate) fn seal_time_key(&mut self, secret: &Secret) -> Result<PublisherSealed> {
        let (config, public, _, _) = self.key_context()?;
        self.seal_time_key_in_context(secret, config, &public)
    }
    fn seal_time_key_in_context(
        &mut self,
        secret: &Secret,
        config: Configuration,
        public: &[u8],
    ) -> Result<PublisherSealed> {
        let (a, b) = self
            .device
            .seal(&tpm::decode(&config.parent_name)?, public, secret)?;
        self.live()?;
        Ok(PublisherSealed {
            format: "luma-windows-utc-p256-scalar-sealed-v1".into(),
            installation: self.installation.clone(),
            parent_name: config.parent_name,
            signer_sha256: digest(public),
            public_blob: encode_hex(&a),
            private_blob: encode_hex(&b),
        })
    }
    pub(crate) fn unseal_time_key(&mut self, value: &PublisherSealed) -> Result<Secret> {
        let (config, public, _, policy) = self.key_context()?;
        self.unseal_time_key_in_context(value, config, &public, policy)
    }
    fn unseal_time_key_in_context(
        &mut self,
        value: &PublisherSealed,
        config: Configuration,
        public: &[u8],
        policy: Policy,
    ) -> Result<Secret> {
        if value.format != "luma-windows-utc-p256-scalar-sealed-v1"
            || value.installation != self.installation
            || value.parent_name != config.parent_name
            || value.signer_sha256 != digest(public)
        {
            return Err("UTC sealed scalar purpose/installation/parent/signer differs".into());
        }
        let result = self.device.unseal(
            &tpm::decode(&value.parent_name)?,
            public,
            &decode_blob(&value.public_blob)?,
            &decode_blob(&value.private_blob)?,
            &policy.digest,
            &policy.signature,
        )?;
        self.live()?;
        Ok(result)
    }
    #[cfg(test)]
    pub(crate) fn fixture_sealed_time_key(
        &mut self,
        root: &Path,
        public_path: &Path,
        signature_path: &Path,
        secret: &Secret,
    ) -> Result<PublisherSealed> {
        let public = admin_credentials::public_input(public_path, 4096)?;
        let signature = admin_credentials::public_input(signature_path, 16384)?;
        let (config, _, _, _) = load(&root.join("sealed"), &mut self.device, &public, &signature)?;
        if config.installation != self.installation
            || nonzero(&config.genesis_event)? != self.genesis
        {
            return Err("fixture anchor context differs".into());
        }
        let policy = current_policy(&mut self.device, &public, &signature)?;
        let sealed = self.seal_time_key_in_context(secret, config.clone(), &public)?;
        let recovered = self.unseal_time_key_in_context(&sealed, config, &public, policy)?;
        if recovered.bytes() != secret.bytes() {
            return Err("fixture genuine TPM roundtrip differs".into());
        }
        Ok(sealed)
    }
}
// Namespace creation and all publication remain separate governed operations.
// This first commissioning ceremony only accepts an existing, explicitly empty
// store while holding the same base-directory exclusion used by Repository.
struct EmptyNamespace {
    file: File,
    path: PathBuf,
    identity: (u64, u64, u32, u32, u32),
    persistent: Option<PersistentDirectory>,
}
impl EmptyNamespace {
    fn capture(path: &Path) -> Result<Self> {
        let mut ancestor = Some(path);
        while let Some(directory) = ancestor {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("content commissioning path has an unsafe ancestor".into());
            }
            ancestor = directory.parent();
        }
        let persistent = PersistentDirectory::capture(path)?;
        let mut namespace = Self::locked(path)?;
        namespace.persistent = Some(persistent);
        namespace.check()?;
        Ok(namespace)
    }
    fn locked(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err("empty content namespace must be root-owned mode 0700".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                "content namespace has another reader or publisher; do not commission".into(),
            );
        }
        let result = Self {
            file,
            path: path.into(),
            identity: Self::identity(&metadata),
            persistent: None,
        };
        result.check()?;
        Ok(result)
    }
    fn identity(metadata: &fs::Metadata) -> (u64, u64, u32, u32, u32) {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        )
    }
    fn check(&self) -> Result<()> {
        if let Some(pin) = &self.persistent {
            pin.check()?;
        }
        let current = fs::symlink_metadata(&self.path)?;
        let held = self.file.metadata()?;
        if !current.is_dir()
            || !held.is_dir()
            || Self::identity(&current) != self.identity
            || Self::identity(&held) != self.identity
            || current.mode() & 0o7777 != 0o700
            || current.uid() != 0
        {
            return Err(
                "empty content namespace identity changed; preserve enrollment evidence".into(),
            );
        }
        if fs::read_dir(&self.path)?.next().transpose()?.is_some() {
            return Err("content commissioning only supports an explicitly EMPTY namespace; no adoption or reset".into());
        }
        let after = fs::symlink_metadata(&self.path)?;
        if Self::identity(&after) != self.identity {
            return Err("empty content namespace changed during complete inventory".into());
        }
        Ok(())
    }
    fn genesis(&self, installation: &str) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(&self.descriptor(installation)?)?;
        Ok(Sha256::digest(bytes).into())
    }
    fn descriptor(&self, installation: &str) -> Result<serde_json::Value> {
        nonzero(installation)?;
        self.check()?;
        Ok(serde_json::json!({"schema_version":1,
            "kind":"luma-windows-utc-explicit-empty-genesis-v1","installation":installation,
            "namespace":crate::utc_windows::DIRECTORY,"identity":{
                "device":self.identity.0.to_string(),"inode":self.identity.1.to_string(),
                "uid":self.identity.2,"gid":self.identity.3,"mode":self.identity.4},"domains":[]}))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ceremony {
    EnrollReview,
    Enroll,
    ParentReview,
    ParentContinue,
    PendingReview,
    Finalize,
    StatusReview,
    Status,
}
struct Request<'a> {
    ceremony: Ceremony,
    login: &'a str,
    grant: Option<&'a str>,
    review: Option<&'a str>,
}
fn parse(args: &[String]) -> Result<Request<'_>> {
    let (ceremony, mutation) = match args.first().map(String::as_str) {
        Some("utc-windows-checkpoint-enroll-review") => (Ceremony::EnrollReview, false),
        Some("utc-windows-checkpoint-enroll") => (Ceremony::Enroll, true),
        Some("utc-windows-checkpoint-parent-review") => (Ceremony::ParentReview, false),
        Some("utc-windows-checkpoint-parent-continue") => (Ceremony::ParentContinue, true),
        Some("utc-windows-checkpoint-pending-review") => (Ceremony::PendingReview, false),
        Some("utc-windows-checkpoint-finalize") => (Ceremony::Finalize, true),
        Some("utc-windows-checkpoint-status-review") => (Ceremony::StatusReview, false),
        Some("utc-windows-checkpoint-status") => (Ceremony::Status, true),
        _ => return Err("unsupported closed content checkpoint ceremony".into()),
    };
    if args.len() != (if mutation { 4 } else { 2 })
        || args[1].is_empty()
        || args[1].len() > 32
        || !args[1]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err("content checkpoint requires LOGIN or LOGIN GRANT EXACT-REVIEW".into());
    }
    if mutation {
        if args[2].is_empty() || args[2].len() > 128 {
            return Err("bounded finite grant identifier required".into());
        }
        nonzero(&args[3])?;
    }
    Ok(Request {
        ceremony,
        login: &args[1],
        grant: mutation.then(|| args[2].as_str()),
        review: mutation.then(|| args[3].as_str()),
    })
}
fn usage(ceremony: &Ceremony, review: &str) -> Result<crate::finite_grants::Use> {
    use crate::finite_grants::{Action, Kind, Selector, Use};
    nonzero(review)?;
    let (action, id) = match ceremony {
        Ceremony::EnrollReview | Ceremony::Enroll => (
            Action::ProvisionResource,
            "utc-windows-checkpoint-enroll-v1",
        ),
        Ceremony::ParentReview | Ceremony::ParentContinue => (
            Action::ProvisionResource,
            "utc-windows-checkpoint-parent-continue-v1",
        ),
        Ceremony::PendingReview | Ceremony::Finalize => (
            Action::RecoverResource,
            "utc-windows-checkpoint-finalize-v1",
        ),
        Ceremony::StatusReview | Ceremony::Status => {
            (Action::Read, "utc-windows-checkpoint-status-v1")
        }
    };
    let value = Use {
        action,
        selector: Selector {
            kind: if action == Action::Read {
                Kind::File
            } else {
                Kind::Resource
            },
            id: id.into(),
            generation: 1,
            digest: review.into(),
        },
        input_bytes: 0,
        output_bytes: 8192,
        units: 1,
    };
    value.validate()?;
    Ok(value)
}
fn status_proposal(installation: &str, _genesis: [u8; 32]) -> Result<serde_json::Value> {
    nonzero(installation)?;
    // Pure inspection intent: no U/C secret, private journal, saved status,
    // or unauthenticated callback can authorize the subsequent read.
    let proposal = serde_json::json!({"schema_version":1,"kind":"utc-windows-checkpoint-status-v1",
        "installation":installation,"profile":CHECKPOINT_PROFILE,"index":INDEX,"parent":PARENT,
        "nv_name":bundle::hex(&checkpoint_name()),"original_admin_read_required":true});
    Ok(
        serde_json::json!({"proposal":proposal,"review_sha256":digest(&serde_json::to_vec(&proposal)?)}),
    )
}
fn status_command(request: &Request<'_>, installation: &str) -> Result<()> {
    let proposal = status_proposal(installation, [0; 32])?;
    let review = proposal["review_sha256"]
        .as_str()
        .ok_or("checkpoint inspection review missing")?;
    let scope = usage(&request.ceremony, review)?;
    let report = if request.ceremony == Ceremony::StatusReview {
        serde_json::json!({"proposal":proposal,"usage":scope,"authority_returned":false,
            "private_state_read":false,"explicit_empty_namespace_only":false})
    } else {
        if request.review != Some(review) {
            return Err("checkpoint inspection exact review changed".into());
        }
        crate::admin_governance::with_grant(
            request.login,
            request.grant.ok_or("checkpoint Read grant required")?,
            &scope,
            |guard| {
                guard.require_admin()?;
                let anchor = UtcAnchor::installed()?;
                guard.require_admin()?;
                if anchor.installation() != installation {
                    return Err("authenticated checkpoint belongs to another installation".into());
                }
                let state =
                    crate::utc_windows::checkpoint_status(anchor, &mut || guard.require_admin())?;
                guard.require_admin()?;
                let bytes = serde_json::to_vec(&state)?;
                Ok(
                    serde_json::json!({"schema_version":1,"status":state,"status_sha256":digest(&bytes),
                "original_admin_read_verified":true,"authority_returned":false,
                "physical_qualified":false,"production_qualified":false}),
                )
            },
        )?
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Genuine local-terminal PAM and the existing original-Admin finite grant
/// authorize commissioning. Neither Unix root nor existing TPM ownership is
/// a product role. No per-content event is appended to the shared Admin journal.
pub(crate) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let request = parse(args)?;
    let (_, _, installation) = crate::admin_governance::current_principal(request.login)?;
    if matches!(request.ceremony, Ceremony::StatusReview | Ceremony::Status) {
        return status_command(&request, &installation);
    }
    let empty = EmptyNamespace::capture(Path::new(crate::utc_windows::DIRECTORY))?;
    let genesis = empty.genesis(&installation)?;
    tpm::private_directory(Path::new(DIRECTORY))?;
    let report = match request.ceremony {
        Ceremony::EnrollReview
        | Ceremony::ParentReview
        | Ceremony::PendingReview
        | Ceremony::StatusReview => {
            let proposal = match request.ceremony {
                Ceremony::EnrollReview => Provisioner::local()?.proposal(&installation, genesis)?,
                Ceremony::ParentReview => parent_pending_report()?,
                Ceremony::PendingReview => pending_report()?,
                Ceremony::StatusReview => status_proposal(&installation, genesis)?,
                _ => unreachable!(),
            };
            empty.check()?;
            let review = proposal["review_sha256"]
                .as_str()
                .ok_or("content ceremony review missing")?;
            serde_json::json!({"proposal":proposal,"usage":usage(&request.ceremony,review)?,
                "empty_namespace":empty.descriptor(&installation)?,
                "explicit_empty_namespace_only":true,"utc_publisher_enabled":false})
        }
        _ => {
            let review = request.review.ok_or("content exact review missing")?;
            let grant = request.grant.ok_or("content finite grant missing")?;
            let scope = usage(&request.ceremony, review)?;
            crate::admin_governance::with_grant(request.login, grant, &scope, |boundary| {
                boundary.require_admin()?;
                empty.check()?;
                let pending =
                    if request.ceremony == Ceremony::Status {
                        None
                    } else {
                        Some(boundary.effect_begin(
                            review,
                            crate::policy_decisions::EffectKind::Checkpoint,
                        )?)
                    };
                let mut check = || {
                    boundary.require_admin()?;
                    empty.check()?;
                    if empty.genesis(&installation)? != genesis {
                        return Err("reviewed empty genesis changed".into());
                    }
                    Ok(())
                };
                retain_genesis_statement(
                    &installation,
                    genesis,
                    &empty.descriptor(&installation)?,
                    &mut check,
                )?;
                let mut anchor = match request.ceremony {
                    Ceremony::Enroll => {
                        let owner = crate::authentication::existing_owner()?;
                        let secret = Secret::generate()?;
                        let prepared = Provisioner::local()?.prepare(
                            &installation,
                            genesis,
                            review,
                            &owner,
                            &secret,
                            &mut check,
                        )?;
                        prepared.commit(&owner, &secret, &mut check)?
                    }
                    Ceremony::ParentContinue => {
                        let owner = crate::authentication::existing_owner()?;
                        let secret = Secret::generate()?;
                        continue_parent(&installation, genesis, review, &secret, &mut check)?
                            .commit(&owner, &secret, &mut check)?
                    }
                    Ceremony::Finalize => {
                        finalize_pending(&installation, genesis, review, &mut check)?
                    }
                    Ceremony::Status => {
                        if status_proposal(&installation, genesis)?["review_sha256"].as_str()
                            != Some(review)
                        {
                            return Err("content status review changed".into());
                        }
                        check()?;
                        UtcAnchor::installed()?
                    }
                    _ => return Err("read-only ceremony cannot dispatch custody".into()),
                };
                check()?;
                if anchor.installation() != installation || anchor.genesis_event() != genesis {
                    return Err("content sealed authority installation/genesis differs".into());
                }
                let head = anchor.read()?;
                if head != tpm::extend_value([0; 32], genesis) {
                    return Err("content authority has advanced; empty-only enrollment subsystem cannot adopt it".into());
                }
                if request.ceremony != Ceremony::Status {
                    crate::utc_windows::initialize_empty(&mut anchor, &mut check)?;
                }
                let result = serde_json::json!({"schema_version":1,"installation":installation,
                    "checkpoint_index":INDEX,"credential_parent":PARENT,"checkpoint_head":bundle::hex(&head),
                    "existing_sealed_authority_authenticated":true,"explicit_empty_namespace_only":true,
                    "utc_publisher_enabled":false,"physical_qualification":false,"production_qualified":false});
                drop(check);
                if let Some(pending) = pending {
                    boundary.effect_complete(pending, &digest(&serde_json::to_vec(&result)?))?;
                } else {
                    boundary.require_admin()?;
                }
                Ok(result)
            })?
        }
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_u_namespace_and_status_scope_cannot_substitute_c_admin_or_resource() {
        // This pure inspection proposal must succeed without any installed U
        // files, TPM access, or unauthenticated private-journal callback.
        let inspection = status_proposal(&"11".repeat(32), [0; 32]).unwrap();
        assert_eq!(inspection["proposal"]["original_admin_read_required"], true);
        assert!(inspection["proposal"]
            .get("current_protected_state")
            .is_none());
        assert_eq!(INDEX, 0x01804c55);
        assert_eq!(PARENT, 0x81004c55);
        for other in [
            tpm::checkpoint_name(),
            tpm::content_checkpoint_name(),
            tpm::resource_checkpoint_name(),
        ] {
            assert_ne!(checkpoint_name(), other);
        }
        for (command, mutation) in [
            ("enroll-review", false),
            ("enroll", true),
            ("parent-review", false),
            ("parent-continue", true),
            ("pending-review", false),
            ("finalize", true),
            ("status-review", false),
            ("status", true),
        ] {
            let mut args = vec![format!("utc-windows-checkpoint-{command}"), "admin".into()];
            if mutation {
                args.extend(["grant".into(), "11".repeat(32)]);
            }
            let request = parse(&args).unwrap();
            let value = usage(&request.ceremony, &"11".repeat(32)).unwrap();
            value.validate().unwrap();
            if command.starts_with("status") {
                assert_eq!(value.action, crate::finite_grants::Action::Read);
                assert_eq!(value.selector.kind, crate::finite_grants::Kind::File);
            }
            args[0] = args[0].replace("utc-windows", "content");
            assert!(parse(&args).is_err());
        }
        let config = Configuration {
            schema_version: 1,
            profile: CHECKPOINT_PROFILE.into(),
            installation: "11".repeat(32),
            index: INDEX,
            parent: PARENT,
            nv_name: bundle::hex(&checkpoint_name()),
            parent_name: format!("000b{}", "22".repeat(32)),
            genesis_event: "33".repeat(32),
            enrollment_review: "44".repeat(32),
            pcr_public_key_sha256: "55".repeat(32),
            pcr7_sha256: "00".repeat(32),
            policy11_sha256: "66".repeat(32),
            sealed_credential_sha256: "77".repeat(32),
        };
        config.validate().unwrap();
        let mut wrong = config.clone();
        wrong.profile = "local-tpm2-content".into();
        assert!(wrong.validate().is_err());
        wrong = config.clone();
        wrong.index = tpm::CONTENT_INDEX;
        assert!(wrong.validate().is_err());
        wrong = config;
        wrong.parent = tpm::CONTENT_PARENT;
        assert!(wrong.validate().is_err());
    }
}
