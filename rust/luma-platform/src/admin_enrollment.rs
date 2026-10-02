//! Explicit checkpoint bootstrap, not product Admin-role activation.
//! Never retry an uncertain TPM write or remove a retained enrollment proposal.
use crate::{
    admin_credentials as credentials, admin_journal, authentication, bundle,
    principal::{self, AccountBinding},
    sealed_credential::{self, Secret},
    tpm::{self, Checkpoint},
    Result,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const PENDING: &str = "/var/lib/luma-os/admin.enrollment-pending";
const LOCK: &str = "/run/luma-admin/anchor.lock";

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => {
            Err("existing or interrupted enrollment; preserve state for explicit review".into())
        }
    }
}

fn destinations(pending: &Path, final_path: &Path) -> Result<()> {
    let parent = pending.parent().ok_or("missing enrollment parent")?;
    if Some(parent) != final_path.parent() || pending == final_path {
        return Err("invalid enrollment destinations".into());
    }
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("unsafe enrollment parent".into());
    }
    absent(pending)?;
    absent(final_path)
}

struct Proposal {
    files: [(&'static str, Vec<u8>); 4],
    deployment: String,
}
impl Proposal {
    fn new(record: Vec<u8>, deployment: &str, public: &[u8], blob: Vec<u8>) -> Result<Self> {
        if record.is_empty() || record.len() > 16384 || blob.is_empty() || blob.len() > 16384 {
            return Err("invalid enrollment proposal size".into());
        }
        if record_deployment(&record) != deployment {
            return Err("enrollment record binding mismatch".into());
        }
        Ok(Self {
            files: [
                (
                    "anchor.json",
                    credentials::prepared(deployment, public, &blob)?,
                ),
                ("nv-auth.cred", blob),
                ("journal.json", admin_journal::initial(deployment)?),
                ("enrollment.json", record),
            ],
            deployment: deployment.into(),
        })
    }

    fn prepare(&self, pending: &Path, final_path: &Path) -> Result<()> {
        destinations(pending, final_path)?;
        fs::DirBuilder::new().mode(0o700).create(pending)?;
        // Persist even the empty attempt fence before preparing its contents.
        File::open(pending.parent().ok_or("missing enrollment parent")?)?.sync_all()?;
        tpm::private_directory(pending)?;
        for (name, bytes) in &self.files {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(pending.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        File::open(pending)?.sync_all()?;
        File::open(pending.parent().ok_or("missing enrollment parent")?)?.sync_all()?;
        self.recheck(pending)
    }

    fn recheck(&self, directory: &Path) -> Result<()> {
        tpm::private_directory(directory)?;
        if fs::read_dir(directory)?.count() != self.files.len() {
            return Err("unexpected enrollment proposal contents".into());
        }
        for (name, bytes) in &self.files {
            if tpm::private_read(&directory.join(name), 16384)? != *bytes {
                return Err("enrollment proposal changed; preserve state for review".into());
            }
        }
        Ok(())
    }
}

fn record_deployment(record: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"luma-native-checkpoint-enrollment-v1\0");
    digest.update(record);
    bundle::hex(&digest.finalize())
}

fn publish(pending: &Path, final_path: &Path) -> Result<()> {
    let source = CString::new(pending.as_os_str().as_bytes())?;
    let target = CString::new(final_path.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(final_path.parent().ok_or("missing enrollment parent")?)?.sync_all()?;
    Ok(())
}

/// Closures are private dependency boundaries for fault-injection tests, not
/// configurable production backends. No caller-controlled transport/path CLI.
fn commit<A: Checkpoint>(
    proposal: &Proposal,
    pending: &Path,
    final_path: &Path,
    authorize: impl FnOnce() -> Result<()>,
    provision: impl FnOnce() -> Result<A>,
) -> Result<serde_json::Value> {
    proposal.prepare(pending, final_path)?;
    authorize()?;
    proposal.recheck(pending)?;
    absent(final_path)?;
    let mut anchor = provision()?; // Any failure retains the proposal, never re-dispatches.
    if anchor.read()? != tpm::extend_value([0; 32], admin_journal::genesis(&proposal.deployment)?) {
        return Err("enrollment checkpoint readback mismatch; review retained proposal".into());
    }
    proposal.recheck(pending)?;
    publish(pending, final_path)?;
    proposal.recheck(final_path)?;
    let checkpoint =
        admin_journal::Store::open(anchor, &final_path.join("journal.json"))?.status()?;
    Ok(
        serde_json::json!({"schema_version":1,"checkpoint_enrolled":true,
        "product_admin_active":false,"role_grant":false,"gate_closing":false,
        "checkpoint":checkpoint}),
    )
}

pub fn enroll(username: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let lock = tpm::exclusive_lock(Path::new(LOCK))?;
    let pending = Path::new(PENDING);
    let final_path = Path::new(credentials::DIRECTORY);
    destinations(pending, final_path)?;
    let binding = AccountBinding::capture(
        Path::new(principal::REGISTRY),
        Path::new(principal::IDENTITY),
        username,
    )?;
    if binding.current_uid()? != 1001 {
        return Err(
            "checkpoint bootstrap requires the installer's selected local account (UID 1001)"
                .into(),
        );
    }
    let identity = binding.identity()?;
    let provisioner = tpm::Provisioner::local()?;
    let public_path = Path::new(credentials::PUBLIC_KEY);
    let signature_path = Path::new(credentials::BOOT_SIGNATURE);
    let public = credentials::public_input(public_path, 4096)?;
    let signature = credentials::public_input(signature_path, 16384)?;
    let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,
        "kind":"inert-checkpoint-enrollment","principal":identity,
        "admission_observation":provisioner.observation(),"observation_is_attestation":false,
        "ownership":"existing-owner","product_admin_active":false,"role_grant":false}))?;
    let deployment = record_deployment(&record);
    let secret = Secret::generate()?;
    let blob = sealed_credential::seal(&deployment, &public, &secret).map_err(|error|
        format!("checkpoint enrollment preflight refused before NV allocation: {error}; the packaged systemd 255 credential backend does not support nonempty existing owner authorization; do not clear or change TPM ownership"))?;
    let recovered = sealed_credential::unseal(&deployment, &public, &blob, &signature)?;
    if recovered.bytes() != secret.bytes() {
        return Err("sealed enrollment preflight mismatch".into());
    }
    drop(recovered);
    let proposal = Proposal::new(record, &deployment, &public, blob)?;
    eprintln!("Checkpoint enrollment will allocate TPM NV index 0x01804c41.\nExisting TPM ownership will not change. An interrupted attempt is retained and cannot be retried automatically.\nThis enrolls an audit checkpoint only; it does not activate product Admin. Cancel now if not intended.");
    let owner = authentication::existing_owner()?;
    // PAM comes after potentially slow sealing and custodian entry. Its opaque
    // observation is checked again immediately before the one-shot TPM dispatch.
    let account = authentication::local(username)?;
    let result = commit(
        &proposal,
        pending,
        final_path,
        || {
            if binding.identity()? != identity || account.identity()? != identity {
                return Err("enrollment principal changed; authenticate again after review".into());
            }
            if credentials::public_input(public_path, 4096)? != public
                || credentials::public_input(signature_path, 16384)? != signature
            {
                return Err("enrollment boot inputs changed; preserve proposal for review".into());
            }
            Ok(())
        },
        || provisioner.provision(&owner, &secret, admin_journal::genesis(&deployment)?, lock),
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Read;
    use std::path::PathBuf;
    #[test]
    // Kept as the pending positive acceptance test, not changed to accept a
    // backend refusal. The packaged systemd 255 backend currently fails it.
    #[ignore = "requires owner-compatible credential backend and isolated enrollment fixture"]
    fn emulator_enrollment() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let public = credentials::public_input(&root.join("pcr-public.pem"), 4096).unwrap();
        let signature = credentials::public_input(&root.join("pcr-signature.json"), 16384).unwrap();
        let provisioner = tpm::Provisioner::fixture(&root).unwrap();
        let record = serde_json::to_vec(&serde_json::json!({"kind":"inert-test-enrollment",
            "admission":provisioner.observation()}))
        .unwrap();
        let deployment = record_deployment(&record);
        let secret = Secret::generate().unwrap();
        let blob = sealed_credential::fixture_seal(&root, &deployment, &public, &secret).unwrap();
        let recovered =
            sealed_credential::fixture_unseal(&root, &deployment, &public, &blob, &signature)
                .unwrap();
        assert_eq!(recovered.bytes(), secret.bytes());
        drop(recovered);
        let mut owner = sealed_credential::PrivateBuffer::new(32).unwrap();
        File::open(root.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let proposal = Proposal::new(record, &deployment, &public, blob).unwrap();
        let pending = root.join("enrollment-pending");
        let final_path = root.join("admin");
        let lock = tpm::exclusive_lock(&root.join("enrollment.lock")).unwrap();
        let status = commit(
            &proposal,
            &pending,
            &final_path,
            || Ok(()),
            || provisioner.provision(&owner, &secret, admin_journal::genesis(&deployment)?, lock),
        )
        .unwrap();
        assert_eq!(status["checkpoint_enrolled"], true);
        assert_eq!(status["role_grant"], false);
        assert!(tpm::Provisioner::fixture(&root).is_err()); // occupied; no overwrite
        let (config, delivered) = credentials::load_at(
            &final_path,
            &root.join("pcr-public.pem"),
            &root.join("pcr-signature.json"),
            |d, p, b, s| sealed_credential::fixture_unseal(&root, d, p, b, s),
        )
        .unwrap();
        assert_eq!(config.deployment, deployment);
        assert_eq!(delivered.bytes(), secret.bytes());
        assert!(!final_path.join("nv-auth").exists());
        assert!(!pending.exists());
    }
    #[test]
    #[ignore = "requires isolated systemd 255 existing-owner compatibility fixture"]
    fn emulator_existing_owner_seal_refusal() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        tpm::Provisioner::fixture(&root).unwrap();
        let public = credentials::public_input(&root.join("pcr-public.pem"), 4096).unwrap();
        let signature = credentials::public_input(&root.join("pcr-signature.json"), 16384).unwrap();
        let secret = Secret::generate().unwrap();
        let deployment = "ab".repeat(32);
        // The harness proved this same helper/signature succeeds before adding
        // owner auth. Refusal here is a compatibility regression, NOT enrollment
        // acceptance. Neither seal-before-ownership nor ignoring refusal works.
        assert!(sealed_credential::fixture_seal(&root, &deployment, &public, &secret).is_err());
        let old_blob = tpm::private_read(&root.join("nv-auth.cred"), 16384).unwrap();
        assert!(sealed_credential::fixture_unseal(
            &root,
            &deployment,
            &public,
            &old_blob,
            &signature
        )
        .is_err());
        tpm::Provisioner::fixture(&root).unwrap(); // no NV index was allocated
        assert!(!root.join("admin").exists());
        assert!(!root.join("enrollment-pending").exists());
    }
    struct Fixture {
        root: PathBuf,
        pending: PathBuf,
        final_path: PathBuf,
        proposal: Proposal,
    }
    impl Fixture {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("luma-enroll-{label}-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let record = b"inert fixture record".to_vec();
            let deployment = record_deployment(&record);
            let proposal = Proposal::new(
                record,
                &deployment,
                b"public fixture",
                b"ciphertext fixture".to_vec(),
            )
            .unwrap();
            Self {
                pending: root.join("pending"),
                final_path: root.join("admin"),
                root,
                proposal,
            }
        }
        fn anchor(&self) -> Fake {
            Fake(tpm::extend_value(
                [0; 32],
                admin_journal::genesis(&self.proposal.deployment).unwrap(),
            ))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    struct Fake([u8; 32]);
    impl Checkpoint for Fake {
        fn read(&mut self) -> Result<[u8; 32]> {
            Ok(self.0)
        }
        fn clock(&mut self) -> Result<tpm::Clock> {
            Ok(tpm::Clock {
                milliseconds: 1,
                reset_count: 0,
                restart_count: 0,
            })
        }
        fn advance(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<[u8; 32]> {
            panic!("enrollment must not append/retry")
        }
    }
    #[test]
    fn publish_only_after_durable_preparation_and_readback() {
        let f = Fixture::new("success");
        let result = commit(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || Ok(()),
            || {
                f.proposal.recheck(&f.pending)?;
                assert!(!f.final_path.exists());
                Ok(f.anchor())
            },
        )
        .unwrap();
        assert_eq!(result["checkpoint_enrolled"], true);
        assert_eq!(result["product_admin_active"], false);
        assert!(!f.pending.exists());
        f.proposal.recheck(&f.final_path).unwrap();
        assert!(destinations(&f.pending, &f.final_path).is_err());
    }
    #[test]
    fn authorization_failure_retains_fence_without_dispatch() {
        let f = Fixture::new("auth");
        assert!(commit::<Fake>(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || Err("expired or changed identity".into()),
            || panic!("no TPM dispatch")
        )
        .is_err());
        f.proposal.recheck(&f.pending).unwrap();
        assert!(!f.final_path.exists());
        assert!(commit::<Fake>(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || panic!("no retry"),
            || panic!("no retry")
        )
        .is_err());
    }
    #[test]
    fn uncertain_dispatch_and_wrong_readback_never_publish_or_retry() {
        for (label, lose_reply) in [("lost", true), ("wrong", false)] {
            let f = Fixture::new(label);
            let calls = Cell::new(0);
            assert!(commit(
                &f.proposal,
                &f.pending,
                &f.final_path,
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    if lose_reply {
                        Err("lost TPM reply".into())
                    } else {
                        Ok(Fake([0; 32]))
                    }
                }
            )
            .is_err());
            assert_eq!(calls.get(), 1);
            f.proposal.recheck(&f.pending).unwrap();
            assert!(!f.final_path.exists());
            assert!(destinations(&f.pending, &f.final_path).is_err());
        }
    }
    #[test]
    fn publication_never_overwrites_a_competing_destination() {
        let f = Fixture::new("collision");
        assert!(commit(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || Ok(()),
            || {
                fs::create_dir(&f.final_path)?;
                Ok(f.anchor())
            }
        )
        .is_err());
        assert_eq!(fs::read_dir(&f.final_path).unwrap().count(), 0);
        f.proposal.recheck(&f.pending).unwrap();
    }
    #[test]
    fn changed_prepared_bytes_refuse_before_dispatch() {
        let f = Fixture::new("changed");
        assert!(commit::<Fake>(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || {
                fs::write(f.pending.join("enrollment.json"), b"substituted")?;
                Ok(())
            },
            || panic!("changed proposal must not dispatch")
        )
        .is_err());
        assert!(f.pending.is_dir());
        assert!(!f.final_path.exists());
    }
    #[test]
    fn changed_proposal_after_tpm_write_is_retained_not_published() {
        let f = Fixture::new("changed-after");
        assert!(commit(
            &f.proposal,
            &f.pending,
            &f.final_path,
            || Ok(()),
            || {
                fs::write(f.pending.join("nv-auth.cred"), b"changed ciphertext")?;
                Ok(f.anchor())
            }
        )
        .is_err());
        assert!(f.pending.is_dir());
        assert!(!f.final_path.exists());
        assert!(destinations(&f.pending, &f.final_path).is_err());
    }
    #[test]
    fn partial_and_symlink_attempts_are_not_reused() {
        let f = Fixture::new("partial");
        fs::create_dir(&f.pending).unwrap();
        assert!(f.proposal.prepare(&f.pending, &f.final_path).is_err());
        fs::remove_dir(&f.pending).unwrap();
        std::os::unix::fs::symlink(f.root.join("absent"), &f.pending).unwrap();
        assert!(f.proposal.prepare(&f.pending, &f.final_path).is_err());
        fs::remove_file(&f.pending).unwrap();
        std::os::unix::fs::symlink(f.root.join("absent"), &f.final_path).unwrap();
        assert!(f.proposal.prepare(&f.pending, &f.final_path).is_err());
        assert!(!f.pending.exists());
    }
}
