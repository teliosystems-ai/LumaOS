//! Independently enrolled TPM2 content checkpoint and sealed authorization.
//! C's existing on-disk schema and Admin ceremony remain unchanged.
use crate::tpm::ContentDevice as CheckpointDevice;
#[cfg(test)]
use crate::tpm::ContentDevice;
#[cfg(test)]
use std::os::unix::fs::DirBuilderExt;
pub(crate) const DIRECTORY: &str = "/var/lib/luma-os/content-checkpoint";
pub(crate) const LOCK: &str = "/run/luma-content-checkpoint/authority.lock";
pub(crate) const INDEX: u32 = crate::tpm::CONTENT_INDEX;
pub(crate) const PARENT: u32 = crate::tpm::CONTENT_PARENT;
const MAGIC: &str = "luma-content-sealed-v1";
const RUNTIME_NAMESPACE: &str = "luma-content-checkpoint";
const RUNTIME_LOCK_NAME: &str = "luma-content-checkpoint/authority.lock";
const CHECKPOINT_PROFILE: &str = "local-tpm2-content";
const ENROLLMENT_KIND: &str = "content-checkpoint-enrollment";
const CUSTODY_KIND: &str = "existing-owner-independent-content-auth";
const PARENT_RECONCILE_PURPOSE: &str = "content-parent-reconcile-v1";
const PARENT_RECONCILE_KIND: &str = "content-parent-reconcile";
const FINALIZE_PURPOSE: &str = "content-pending-finalize-v1";
const FINALIZE_KIND: &str = "content-pending-finalize";
fn checkpoint_name() -> [u8; 34] {
    crate::tpm::content_checkpoint_name()
}
include!("independent_checkpoint.rs");
fn validate_genesis_binding(root: &Path, installation: &str, genesis: [u8; 32]) -> Result<()> {
    custody::validate_genesis_at(root, installation, genesis)
}
pub(crate) type ContentAnchor = IndependentAnchor;
#[cfg(test)]
type ContentLock = CheckpointLock;
#[path = "content_custody.rs"]
pub(crate) mod custody;
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
        let mut device = ContentDevice::fixture(directory)?;
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
            ContentDevice::fixture(directory)?,
            root,
            CheckpointLock::fixture(lock)?,
            public_path,
            signature_path,
        )
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
            "kind":"luma-content-explicit-empty-genesis-v1","installation":installation,
            "namespace":"/var/lib/luma-os/content-store","identity":{
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
        Some("content-checkpoint-enroll-review") => (Ceremony::EnrollReview, false),
        Some("content-checkpoint-enroll") => (Ceremony::Enroll, true),
        Some("content-checkpoint-parent-review") => (Ceremony::ParentReview, false),
        Some("content-checkpoint-parent-continue") => (Ceremony::ParentContinue, true),
        Some("content-checkpoint-pending-review") => (Ceremony::PendingReview, false),
        Some("content-checkpoint-finalize") => (Ceremony::Finalize, true),
        Some("content-checkpoint-status-review") => (Ceremony::StatusReview, false),
        Some("content-checkpoint-status") => (Ceremony::Status, true),
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
        Ceremony::EnrollReview | Ceremony::Enroll => {
            (Action::ProvisionResource, "content-checkpoint-enroll-v1")
        }
        Ceremony::ParentReview | Ceremony::ParentContinue => (
            Action::ProvisionResource,
            "content-checkpoint-parent-continue-v1",
        ),
        Ceremony::PendingReview | Ceremony::Finalize => {
            (Action::RecoverResource, "content-checkpoint-finalize-v1")
        }
        Ceremony::StatusReview | Ceremony::Status => (Action::Read, "content-checkpoint-status-v1"),
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
    let proposal = serde_json::json!({"schema_version":1,"kind":"content-checkpoint-status-v1",
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
                let anchor = ContentAnchor::installed()?;
                guard.require_admin()?;
                if anchor.installation() != installation {
                    return Err("authenticated checkpoint belongs to another installation".into());
                }
                let state = custody::status_with_anchor(anchor, &mut || guard.require_admin())?;
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
    let empty = EmptyNamespace::capture(Path::new(crate::content_governed::DIRECTORY))?;
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
                "explicit_empty_namespace_only":true,"production_publication_enabled":false})
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
                custody::retain_genesis_statement(
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
                        ContentAnchor::installed()?
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
                    custody::initialize_empty(&mut anchor, &mut check)?;
                }
                let result = serde_json::json!({"schema_version":1,"installation":installation,
                    "checkpoint_index":INDEX,"credential_parent":PARENT,"checkpoint_head":bundle::hex(&head),
                    "existing_sealed_authority_authenticated":true,"explicit_empty_namespace_only":true,
                    "content_publication_enabled":false,"physical_qualification":false,"production_qualified":false});
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
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn shared_enrollment_members_use_the_same_real_isolated_fixture_admission() {
        let storage = PathBuf::from(
            std::env::var_os("LUMA_STORAGE_TEST_ROOT").expect("private ext4 fixture root required"),
        );
        let fixture = storage.join(format!("luma-tpm-members-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        tpm::validate_fixture_directory(&fixture).unwrap();
        let parent = fixture.join("member-state");
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let path = parent.join("record.json");
        write_new(&path, b"fixture data, never authority").unwrap();
        assert_eq!(
            immutable(&path, 4096).unwrap(),
            b"fixture data, never authority"
        );
        let outside = storage.join(format!("unadmitted-members-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        assert!(write_new(&outside.join("refused.json"), b"do not create").is_err());
        assert!(!outside.join("refused.json").exists());
        let alias = fixture.join("linked-members");
        std::os::unix::fs::symlink(&outside, &alias).unwrap();
        assert!(write_new(&alias.join("refused.json"), b"do not create").is_err());
        assert!(!outside.join("refused.json").exists());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(immutable(&path, 4096).is_err());
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            immutable(&path, 4096).unwrap(),
            b"fixture data, never authority"
        );
        fs::remove_file(path).unwrap();
        fs::remove_dir(parent).unwrap();
        fs::remove_dir(fixture).unwrap();
        fs::remove_dir(outside).unwrap();
    }
    #[test]
    fn empty_namespace_is_exact_retained_and_exclusive_not_a_reset_or_adoption() {
        let path = std::env::temp_dir().join(format!("luma-content-empty-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let pin = EmptyNamespace::locked(&path).unwrap();
        pin.check().unwrap();
        let installation = "19".repeat(32);
        let genesis = pin.genesis(&installation).unwrap();
        assert_eq!(pin.genesis(&installation).unwrap(), genesis);
        assert!(pin.genesis(&"00".repeat(32)).is_err());
        assert!(EmptyNamespace::locked(&path).is_err());
        let entry = path.join("retained-content");
        fs::write(&entry, b"never delete or adopt this data").unwrap();
        assert!(pin.check().is_err());
        assert!(pin.genesis(&installation).is_err());
        assert_eq!(
            fs::read(&entry).unwrap(),
            b"never delete or adopt this data"
        );
        fs::remove_file(&entry).unwrap();
        pin.check().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(pin.check().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        pin.check().unwrap();
        let moved = path.with_extension("retained");
        fs::rename(&path, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        assert!(pin.check().is_err());
        drop(pin);
        fs::remove_dir(&path).unwrap();
        fs::remove_dir(&moved).unwrap();
    }
    #[test]
    fn closed_ceremonies_require_exact_argc_login_grant_and_canonical_review() {
        let inspection = status_proposal(&"11".repeat(32), [0; 32]).unwrap();
        assert_eq!(inspection["proposal"]["original_admin_read_required"], true);
        assert!(inspection["proposal"]
            .get("current_protected_state")
            .is_none());
        let commands = [
            "content-checkpoint-enroll-review",
            "content-checkpoint-enroll",
            "content-checkpoint-parent-review",
            "content-checkpoint-parent-continue",
            "content-checkpoint-pending-review",
            "content-checkpoint-finalize",
            "content-checkpoint-status-review",
            "content-checkpoint-status",
        ];
        for (position, command) in commands.iter().enumerate() {
            let mut args = vec![command.to_string(), "admin".into()];
            if position % 2 == 1 {
                args.push("finite-grant".into());
                args.push("11".repeat(32));
            }
            let request = parse(&args).unwrap();
            assert_eq!(request.login, "admin");
            let value = usage(&request.ceremony, &"11".repeat(32)).unwrap();
            assert_eq!(value.selector.digest, "11".repeat(32));
            assert_eq!(value.units, 1);
            assert_eq!(value.input_bytes, 0);
            if position >= 6 {
                assert_eq!(value.action, crate::finite_grants::Action::Read);
                assert_eq!(value.selector.kind, crate::finite_grants::Kind::File);
            }
            let mut extra = args.clone();
            extra.push("--assume-admin".into());
            assert!(parse(&extra).is_err());
            args[1] = "../admin".into();
            assert!(parse(&args).is_err());
        }
        for args in [
            vec![],
            vec!["content-checkpoint-enroll".into()],
            vec![
                "content-checkpoint-enroll".into(),
                "admin".into(),
                "grant".into(),
                "00".repeat(32),
            ],
            vec!["content-checkpoint-clear".into(), "admin".into()],
        ] {
            assert!(parse(&args).is_err());
        }
    }
    #[test]
    fn content_namespace_cannot_share_admin_resource_or_windows_names() {
        assert_eq!(INDEX, 0x01804c43);
        assert_eq!(PARENT, 0x81004c43);
        assert_ne!(tpm::content_checkpoint_name(), tpm::checkpoint_name());
        assert_ne!(
            tpm::content_checkpoint_name(),
            tpm::resource_checkpoint_name()
        );
        for other in [0x01804c41, 0x01804c52, 0x01804c57, 0x01804c58] {
            assert_ne!(INDEX, other);
        }
        let mut configuration = config();
        configuration.index = tpm::RESOURCE_INDEX;
        assert!(configuration.validate().is_err());
        configuration = config();
        configuration.parent = tpm::RESOURCE_PARENT;
        assert!(configuration.validate().is_err());
        configuration = config();
        configuration.nv_name = bundle::hex(&tpm::resource_checkpoint_name());
        assert!(configuration.validate().is_err());
    }
    #[test]
    fn persistent_storage_uses_real_kernel_mount_and_filesystem_not_path_labels() {
        let directory = File::open(std::env::temp_dir()).unwrap();
        let mut status: libc::statfs = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut status) },
            0
        );
        assert_eq!(
            PersistentDirectory::ext4(&directory).is_ok(),
            status.f_type == 0xef53
        );
        let mount = PersistentDirectory::mount(&directory).unwrap();
        assert_ne!(mount, 0);
        assert_eq!(PersistentDirectory::mount(&directory).unwrap(), mount);
    }
    fn fixture_genesis(root: &Path, installation: &str) -> [u8; 32] {
        let metadata = fs::metadata(root).unwrap();
        let value = serde_json::json!({"schema_version":1,
            "kind":"luma-content-explicit-empty-genesis-v1", "installation":installation,
            "namespace":"/var/lib/luma-os/content-store", "identity":{
                "device":metadata.dev().to_string(),"inode":metadata.ino().to_string(),
                "uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode()},"domains":[]});
        let bytes = serde_json::to_vec(&value).unwrap();
        let genesis = Sha256::digest(&bytes).into();
        write_new(&root.join("genesis.json"), &bytes).unwrap();
        validate_genesis_binding(root, installation, genesis).unwrap();
        genesis
    }
    fn emulator_content_enrollment_sealed_restart_and_exact_extend() {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("content-state");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("content-anchor.lock");
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
        let next = anchor.advance(head, [0x72; 32]).unwrap();
        assert_eq!(next, tpm::extend_value(head, [0x72; 32]));
        assert!(anchor.advance(head, [0x73; 32]).is_err());
        assert_eq!(anchor.read().unwrap(), next);
        drop(anchor);
        let mut reopened = ContentAnchor::fixture(
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
        // Coordinating two mutable metadata headers must not relabel the
        // installation authenticated by the original protected genesis.
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
        assert!(ContentAnchor::fixture(
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
        let mut restored = ContentAnchor::fixture(
            &directory,
            &root,
            tpm::exclusive_lock(&lock_path).unwrap(),
            &public,
            &signature,
        )
        .unwrap();
        assert_eq!(restored.read().unwrap(), next);
    }
    fn emulator_content_lost_publication_is_explicit_finalize_without_nv_replay() {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("content-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("content-anchor.lock");
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
            ContentDevice::fixture(&directory).unwrap(),
            ContentLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
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
            ContentDevice::fixture(&directory).unwrap(),
            ContentLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
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
    fn emulator_content_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay() {
        let directory = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let root = directory.join("content-parent-pending");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = directory.join("pcr-public.pem");
        let signature = directory.join("pcr-signature.json");
        let lock_path = directory.join("content-anchor.lock");
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
            ContentDevice::fixture(&directory).unwrap(),
            ContentLock::fixture(tpm::exclusive_lock(&lock_path).unwrap()).unwrap(),
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
        admin_secret: &Secret,
        resource_secret: &Secret,
    ) -> ([u8; 34], Secret) {
        let folder = match mode {
            "normal" => {
                emulator_content_enrollment_sealed_restart_and_exact_extend();
                "content-state"
            }
            "lost-publication" => {
                emulator_content_lost_publication_is_explicit_finalize_without_nv_replay();
                "content-pending"
            }
            "lost-parent" => {
                emulator_content_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay();
                "content-parent-pending"
            }
            _ => panic!("unsupported disposable content TPM fixture scenario"),
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
        let mut wrong = ContentDevice::fixture(&directory).unwrap();
        assert!(wrong.connect(admin_secret).is_err());
        drop(wrong);
        let mut wrong = ContentDevice::fixture(&directory).unwrap();
        assert!(wrong.connect(resource_secret).is_err());
        drop(wrong);
        let public =
            admin_credentials::public_input(&directory.join("pcr-public.pem"), 4096).unwrap();
        let signature =
            admin_credentials::public_input(&directory.join("pcr-signature.json"), 16384).unwrap();
        let mut device = ContentDevice::fixture(&directory).unwrap();
        let (_, secret, _, _) = load(
            &directory.join(folder).join("sealed"),
            &mut device,
            &public,
            &signature,
        )
        .unwrap();
        (parent, secret)
    }
    fn config() -> Configuration {
        Configuration {
            schema_version: 1,
            profile: "local-tpm2-content".into(),
            installation: "11".repeat(32),
            index: INDEX,
            parent: PARENT,
            nv_name: bundle::hex(&tpm::content_checkpoint_name()),
            parent_name: format!("000b{}", "22".repeat(32)),
            genesis_event: "33".repeat(32),
            enrollment_review: "44".repeat(32),
            pcr_public_key_sha256: "55".repeat(32),
            pcr7_sha256: "00".repeat(32),
            policy11_sha256: "66".repeat(32),
            sealed_credential_sha256: "77".repeat(32),
        }
    }
    #[test]
    fn content_profile_cannot_select_admin_authority_or_unbound_installation() {
        let initial = config();
        initial.validate().unwrap();
        assert_ne!(tpm::content_checkpoint_name(), tpm::checkpoint_name());
        for field in 0..7 {
            let mut next = initial.clone();
            match field {
                0 => next.index = 0x01804c41,
                1 => next.parent = 0x81004c41,
                2 => next.nv_name = bundle::hex(&tpm::checkpoint_name()),
                3 => next.installation = "00".repeat(32),
                4 => next.genesis_event = "00".repeat(32),
                5 => next.profile = "local-tpm2".into(),
                _ => next.parent_name = "00".repeat(34),
            }
            assert!(next.validate().is_err());
        }
        let mut value = serde_json::to_value(initial).unwrap();
        value["caller_verified"] = true.into();
        assert!(serde_json::from_value::<Configuration>(value).is_err());
    }
    #[test]
    fn independent_lock_refuses_current_inode_replacement_and_public_writes() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "luma-content-checkpoint-lock-{}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
        let path = root.join("anchor.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let lock = ContentLock::from_file(file, &path).unwrap();
        lock.check().unwrap();
        let duplicate = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(ContentLock::from_file(duplicate, &path).is_err());
        fs::remove_file(&path).unwrap();
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(lock.check().is_err());
        drop(lock);
        let replacement = ContentLock::from_file(replacement, &path).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(replacement.check().is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        drop(replacement);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn fixed_lock_has_closed_independent_runtime_namespace() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        assert_eq!(LOCK, "/run/luma-content-checkpoint/authority.lock");
        let root =
            std::env::temp_dir().join(format!("luma-content-fixed-lock-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
        let namespace = root.join("luma-content-checkpoint");
        let path = namespace.join("authority.lock");
        let lock = ContentLock::fixed_in(&root).unwrap();
        assert_eq!(
            fs::symlink_metadata(&namespace).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert!(ContentLock::fixed_in(&root).is_err());
        let broker = root.join("luma-broker");
        fs::DirBuilder::new().mode(0o755).create(&broker).unwrap();
        fs::remove_dir(&broker).unwrap();
        lock.check().unwrap();

        let moved = root.with_extension("retained");
        fs::rename(&root, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        assert!(lock.check().is_err());
        drop(lock);
        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ContentLock::fixed_in(&root).is_err());
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"foreign lock contents").unwrap();
        assert!(ContentLock::fixed_in(&root).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&namespace).unwrap();
        let target = root.join("foreign-namespace");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        symlink(&target, &namespace).unwrap();
        assert!(ContentLock::fixed_in(&root).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_file(&namespace).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ContentLock::fixed_in(&root).is_err());
        assert!(!namespace.exists());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(&target).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn bounded_canonical_sealed_payload_has_no_secret_or_shared_profile() {
        let value = Sealed {
            format: MAGIC.into(),
            installation: "11".repeat(32),
            parent_name: format!("000b{}", "22".repeat(32)),
            public_key_sha256: "33".repeat(32),
            public_blob: encode_hex(b"TPM public blob"),
            private_blob: encode_hex(b"TPM encrypted private blob"),
        };
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: Sealed = canonical(&encoded).unwrap();
        assert_eq!(
            decode_blob(&decoded.public_blob).unwrap(),
            b"TPM public blob"
        );
        for bad in [
            "".into(),
            "0".into(),
            "AA".into(),
            "zz".into(),
            "00".repeat(4097),
        ] {
            assert!(decode_blob(&bad).is_err());
        }
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend(encoded);
        assert!(canonical::<Sealed>(&noncanonical).is_err());
    }
}
