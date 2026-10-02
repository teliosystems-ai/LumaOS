//! Explicit checkpoint bootstrap, not product Admin-role activation.
//! Never retry an uncertain TPM write or remove a retained enrollment proposal.
use crate::{
    admin_credentials as credentials, admin_journal, authentication, bundle, owner_credential,
    principal::{self, AccountBinding},
    sealed_credential::Secret,
    tpm::{self, Checkpoint},
    Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const PENDING: &str = "/var/lib/luma-os/admin.enrollment-pending";
const PARENT_INTENT: &str = "/var/lib/luma-os/admin.parent-intent";
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

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Retained even after successful checkpoint enrollment. A persistent TPM
/// parent is allocated only after this exact intent has been durably written.
struct ParentIntent {
    record: Vec<u8>,
    intent: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentMetadata {
    schema_version: u32,
    kind: String,
    deployment: String,
    parent_handle: u32,
    pcr_public_key_sha256: String,
    boot_signature_sha256: String,
    product_admin_active: bool,
    role_grant: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRecord {
    schema_version: u32,
    kind: String,
    principal: serde_json::Value,
    admission_observation: serde_json::Value,
    observation_is_attestation: bool,
    ownership: String,
    credential_parent_handle: u32,
    product_admin_active: bool,
    role_grant: bool,
}

fn enrollment_identity(record: &[u8]) -> Result<serde_json::Value> {
    let canonical: serde_json::Value = serde_json::from_slice(record)?;
    let parsed: EnrollmentRecord = serde_json::from_slice(record)?;
    if serde_json::to_vec(&canonical)? != record
        || parsed.schema_version != 1
        || parsed.kind != "inert-checkpoint-enrollment"
        || parsed.observation_is_attestation
        || parsed.ownership != "existing-owner"
        || parsed.credential_parent_handle != 0x81004c41
        || parsed.product_admin_active
        || parsed.role_grant
        || !parsed.principal.is_object()
        || !parsed.admission_observation.is_object()
    {
        return Err("retained enrollment record is not the native inert profile".into());
    }
    Ok(parsed.principal)
}
impl ParentIntent {
    fn new(record: Vec<u8>, deployment: &str, public: &[u8], signature: &[u8]) -> Result<Self> {
        if record.is_empty() || record.len() > 16384 || record_deployment(&record) != deployment {
            return Err("invalid persistent parent intent binding".into());
        }
        let intent = serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"kind":"existing-owner-credential-parent-intent",
            "deployment":deployment,"parent_handle":0x81004c41u32,
            "pcr_public_key_sha256":bundle::hex(&Sha256::digest(public)),
            "boot_signature_sha256":bundle::hex(&Sha256::digest(signature)),
            "product_admin_active":false,"role_grant":false}))?;
        Ok(Self { record, intent })
    }

    fn prepare(&self, path: &Path, pending: &Path, final_path: &Path) -> Result<()> {
        destinations(pending, final_path)?;
        if path.parent() != pending.parent() || path == pending || path == final_path {
            return Err("invalid persistent parent intent destination".into());
        }
        absent(path)?;
        fs::DirBuilder::new().mode(0o700).create(path)?;
        File::open(path.parent().ok_or("missing intent parent")?)?.sync_all()?;
        tpm::private_directory(path)?;
        write_new(&path.join("enrollment.json"), &self.record)?;
        write_new(&path.join("parent-intent.json"), &self.intent)?;
        File::open(path)?.sync_all()?;
        File::open(path.parent().ok_or("missing intent parent")?)?.sync_all()?;
        self.recheck(path)
    }

    fn recheck(&self, path: &Path) -> Result<()> {
        tpm::private_directory(path)?;
        if fs::read_dir(path)?.count() != 2
            || tpm::private_read(&path.join("enrollment.json"), 16384)? != self.record
            || tpm::private_read(&path.join("parent-intent.json"), 4096)? != self.intent
        {
            return Err("persistent parent intent changed; preserve for review".into());
        }
        Ok(())
    }

    fn bind_name(&self, path: &Path, name: &[u8; 34]) -> Result<()> {
        self.recheck(path)?;
        if name[..2] != [0, 0x0b] {
            return Err("invalid persistent parent Name".into());
        }
        write_new(&path.join("parent.name"), name)?;
        File::open(path)?.sync_all()?;
        File::open(path.parent().ok_or("missing intent parent")?)?.sync_all()?;
        self.recheck_bound(path, name)
    }

    fn recheck_bound(&self, path: &Path, name: &[u8; 34]) -> Result<()> {
        tpm::private_directory(path)?;
        if fs::read_dir(path)?.count() != 3
            || tpm::private_read(&path.join("enrollment.json"), 16384)? != self.record
            || tpm::private_read(&path.join("parent-intent.json"), 4096)? != self.intent
            || tpm::private_read(&path.join("parent.name"), 34)? != name
        {
            return Err("persistent parent binding changed; preserve for review".into());
        }
        Ok(())
    }

    fn read_for_inspection(path: &Path) -> Result<(Self, Option<[u8; 34]>)> {
        tpm::private_directory(path)?;
        let record = tpm::private_read(&path.join("enrollment.json"), 16384)?;
        let intent = tpm::private_read(&path.join("parent-intent.json"), 4096)?;
        let metadata: IntentMetadata = serde_json::from_slice(&intent)?;
        if metadata.schema_version != 1
            || metadata.kind != "existing-owner-credential-parent-intent"
            || metadata.parent_handle != 0x81004c41
            || metadata.product_admin_active
            || metadata.role_grant
            || record_deployment(&record) != metadata.deployment
        {
            return Err("invalid retained parent intent".into());
        }
        tpm::decode::<32>(&metadata.pcr_public_key_sha256)?;
        tpm::decode::<32>(&metadata.boot_signature_sha256)?;
        let canonical = serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"kind":"existing-owner-credential-parent-intent",
            "deployment":metadata.deployment,"parent_handle":0x81004c41u32,
            "pcr_public_key_sha256":metadata.pcr_public_key_sha256,
            "boot_signature_sha256":metadata.boot_signature_sha256,
            "product_admin_active":false,"role_grant":false}))?;
        if canonical != intent {
            return Err("noncanonical retained parent intent".into());
        }
        let name_path = path.join("parent.name");
        let name = match fs::symlink_metadata(&name_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
            Ok(_) => {
                let bytes = tpm::private_read(&name_path, 34)?;
                let name: [u8; 34] = bytes.try_into().map_err(|_| "invalid parent Name")?;
                if name[..2] != [0, 0x0b] {
                    return Err("invalid parent Name algorithm".into());
                }
                Some(name)
            }
        };
        if fs::read_dir(path)?.count() != if name.is_some() { 3 } else { 2 } {
            return Err("unexpected retained parent intent files".into());
        }
        Ok((Self { record, intent }, name))
    }
}

fn private_presence(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
        Ok(_) => {
            tpm::private_directory(path)?;
            Ok(true)
        }
    }
}

fn inspect_at(
    parent_path: &Path,
    pending: &Path,
    final_path: &Path,
    handles: impl FnOnce(Option<&[u8; 34]>) -> Result<(bool, bool, bool)>,
) -> Result<serde_json::Value> {
    let parent = pending.parent().ok_or("missing enrollment parent")?;
    if parent_path.parent() != Some(parent)
        || final_path.parent() != Some(parent)
        || parent_path == pending
        || parent_path == final_path
        || pending == final_path
    {
        return Err("invalid enrollment inspection paths".into());
    }
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("unsafe enrollment inspection parent".into());
    }
    let parent_present = private_presence(parent_path)?;
    let pending_present = private_presence(pending)?;
    let final_present = private_presence(final_path)?;
    let retained = if parent_present {
        Some(ParentIntent::read_for_inspection(parent_path)?)
    } else {
        None
    };
    let parent_name = retained.as_ref().and_then(|(_, name)| name.as_ref());
    let (parent_occupied, nv_occupied, parent_matches) = handles(parent_name)?;
    let phase = if !parent_present
        && !pending_present
        && !final_present
        && !parent_occupied
        && !nv_occupied
    {
        "not_started"
    } else if parent_present
        && parent_name.is_none()
        && !pending_present
        && !final_present
        && !nv_occupied
    {
        "parent_write_uncertain"
    } else if parent_present
        && parent_name.is_some()
        && parent_matches
        && !pending_present
        && !final_present
        && !nv_occupied
    {
        "parent_bound_proposal_absent"
    } else if parent_present && parent_matches && pending_present && !final_present {
        "nv_write_or_publication_uncertain"
    } else if parent_present && parent_matches && !pending_present && final_present && nv_occupied {
        "published_unverified"
    } else {
        "conflict_preserve_state"
    };
    let mut digest = Sha256::new();
    digest.update(b"luma-enrollment-inspection-v1\0");
    if let Some((intent, name)) = &retained {
        digest.update((intent.record.len() as u32).to_be_bytes());
        digest.update(&intent.record);
        digest.update((intent.intent.len() as u32).to_be_bytes());
        digest.update(&intent.intent);
        if let Some(name) = name {
            digest.update(name);
        }
    }
    digest.update([
        parent_present as u8,
        pending_present as u8,
        final_present as u8,
        parent_occupied as u8,
        nv_occupied as u8,
        parent_matches as u8,
    ]);
    Ok(serde_json::json!({"schema_version":1,"phase":phase,
        "parent_intent_present":parent_present,"parent_name_recorded":parent_name.is_some(),
        "parent_handle_occupied":parent_occupied,"parent_name_and_profile_match":parent_matches,
        "pending_proposal_present":pending_present,"final_directory_present":final_present,
        "nv_index_occupied":nv_occupied,
        "observation_sha256":bundle::hex(&digest.finalize()),
        "observation_is_attestation":false,"mutation_performed":false,
        "bounded_continuation_possible":phase == "parent_bound_proposal_absent",
        "reviewed_recovery_available":false}))
}

/// Only the bound parent with no NV proposal/index can be continued without
/// repeating an uncertain TPM write. The digest fences stale observations; it
/// does not itself authenticate a person or authorize continuation.
fn reviewed_bound_parent_at(
    parent_path: &Path,
    pending: &Path,
    final_path: &Path,
    reviewed: &str,
    mut handles: impl FnMut(Option<&[u8; 34]>) -> Result<(bool, bool, bool)>,
) -> Result<(ParentIntent, [u8; 34])> {
    tpm::decode::<32>(reviewed)?;
    let report = inspect_at(parent_path, pending, final_path, |name| handles(name))?;
    if report["phase"] != "parent_bound_proposal_absent" || report["observation_sha256"] != reviewed
    {
        return Err(
            "review does not match a bound parent with no NV proposal; preserve state".into(),
        );
    }
    let (intent, name) = ParentIntent::read_for_inspection(parent_path)?;
    let name = name.ok_or("reviewed parent Name missing")?;
    intent.recheck_bound(parent_path, &name)?;
    let rechecked = inspect_at(parent_path, pending, final_path, |name| handles(name))?;
    if rechecked["observation_sha256"] != reviewed {
        return Err("enrollment state changed after review; preserve state".into());
    }
    Ok((intent, name))
}

/// Read-only inspection of an interrupted checkpoint enrollment. It does not
/// authenticate final journal contents or authorize repeat provisioning.
pub fn inspect() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let _lock = tpm::exclusive_lock(Path::new(LOCK))?;
    let report = inspect_at(
        Path::new(PARENT_INTENT),
        Path::new(PENDING),
        Path::new(credentials::DIRECTORY),
        tpm::enrollment_handles,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Explicit continuation after a previously durable parent Name, before any
/// NV proposal. This never retries the parent write or an uncertain NV write.
pub fn resume_bound_parent(username: &str, reviewed: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let lock = tpm::exclusive_lock(Path::new(LOCK))?;
    let parent_path = Path::new(PARENT_INTENT);
    let pending = Path::new(PENDING);
    let final_path = Path::new(credentials::DIRECTORY);
    let (intent, parent_name) = reviewed_bound_parent_at(
        parent_path,
        pending,
        final_path,
        reviewed,
        tpm::enrollment_handles,
    )?;
    let binding = AccountBinding::capture(
        Path::new(principal::REGISTRY),
        Path::new(principal::IDENTITY),
        username,
    )?;
    if binding.current_uid()? != 1001 {
        return Err("checkpoint continuation requires the selected UID 1001 account".into());
    }
    let identity = binding.identity()?;
    if enrollment_identity(&intent.record)? != identity {
        return Err("retained enrollment principal differs from current account".into());
    }
    let deployment = record_deployment(&intent.record);
    let public_path = Path::new(credentials::PUBLIC_KEY);
    let signature_path = Path::new(credentials::BOOT_SIGNATURE);
    let public = credentials::public_input(public_path, 4096)?;
    let signature = credentials::public_input(signature_path, 16384)?;
    if ParentIntent::new(intent.record.clone(), &deployment, &public, &signature)?.intent
        != intent.intent
    {
        return Err("retained intent boot inputs differ from installed image".into());
    }
    owner_credential::verify_boot(&public, &signature)?;
    let provisioner = tpm::Provisioner::local()?;
    eprintln!("Continue only the reviewed bound-parent checkpoint attempt. No parent write will be retried; a sealed NV proposal will be retained before its one-shot TPM write. This does not activate product Admin. Cancel now if not intended.");
    let owner = authentication::existing_owner()?;
    let account = authentication::local(username)?;
    if binding.identity()? != identity || account.identity()? != identity {
        return Err("continuation principal changed after authentication".into());
    }
    if credentials::public_input(public_path, 4096)? != public
        || credentials::public_input(signature_path, 16384)? != signature
    {
        return Err("continuation boot inputs changed after authentication".into());
    }
    let (rechecked, rechecked_name) = reviewed_bound_parent_at(
        parent_path,
        pending,
        final_path,
        reviewed,
        tpm::enrollment_handles,
    )?;
    if rechecked.record != intent.record
        || rechecked.intent != intent.intent
        || rechecked_name != parent_name
    {
        return Err("retained enrollment changed after review".into());
    }
    let secret = Secret::generate()?;
    let blob = owner_credential::seal(&deployment, &parent_name, &public, &secret)?;
    let recovered =
        owner_credential::unseal(&deployment, &parent_name, &public, &blob, &signature)?;
    if recovered.bytes() != secret.bytes() {
        return Err("continued sealed enrollment preflight mismatch".into());
    }
    drop(recovered);
    let proposal = Proposal::new(
        intent.record.clone(),
        &deployment,
        &parent_name,
        &public,
        blob,
    )?;
    let result = commit(
        &proposal,
        pending,
        final_path,
        || {
            intent.recheck_bound(parent_path, &parent_name)?;
            if tpm::enrollment_handles(Some(&parent_name))? != (true, false, true) {
                return Err("continuation TPM handles changed before NV dispatch".into());
            }
            if binding.identity()? != identity || account.identity()? != identity {
                return Err("continuation principal changed before NV dispatch".into());
            }
            if credentials::public_input(public_path, 4096)? != public
                || credentials::public_input(signature_path, 16384)? != signature
            {
                return Err("continuation boot inputs changed before NV dispatch".into());
            }
            Ok(())
        },
        || provisioner.provision(&owner, &secret, admin_journal::genesis(&deployment)?, lock),
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn allocate_parent(
    intent: &ParentIntent,
    path: &Path,
    pending: &Path,
    final_path: &Path,
    authorize: impl FnOnce() -> Result<()>,
    allocate: impl FnOnce() -> Result<[u8; 34]>,
) -> Result<[u8; 34]> {
    intent.prepare(path, pending, final_path)?;
    authorize()?;
    intent.recheck(path)?;
    let name = allocate()?; // Never retry an uncertain persistent TPM write.
    intent.bind_name(path, &name)?;
    Ok(name)
}

struct Proposal {
    files: [(&'static str, Vec<u8>); 5],
    deployment: String,
}
impl Proposal {
    fn new(
        record: Vec<u8>,
        deployment: &str,
        parent_name: &[u8; 34],
        public: &[u8],
        blob: Vec<u8>,
    ) -> Result<Self> {
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
                    credentials::prepared(deployment, parent_name, public, &blob)?,
                ),
                ("nv-auth.cred", blob),
                ("journal.json", admin_journal::initial(deployment)?),
                ("enrollment.json", record),
                ("parent.name", parent_name.to_vec()),
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
            write_new(&pending.join(name), bytes)?;
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
    let parent_path = Path::new(PARENT_INTENT);
    let final_path = Path::new(credentials::DIRECTORY);
    destinations(pending, final_path)?;
    absent(parent_path)?;
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
    let mut provisioner = tpm::Provisioner::local()?;
    let public_path = Path::new(credentials::PUBLIC_KEY);
    let signature_path = Path::new(credentials::BOOT_SIGNATURE);
    let public = credentials::public_input(public_path, 4096)?;
    let signature = credentials::public_input(signature_path, 16384)?;
    // Verify that this boot's signed PCR11 policy is authentic and matches
    // the current TPM before preparing any persistent TPM allocation.
    owner_credential::verify_boot(&public, &signature)?;
    let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,
        "kind":"inert-checkpoint-enrollment","principal":identity,
        "admission_observation":provisioner.observation(),"observation_is_attestation":false,
        "ownership":"existing-owner","credential_parent_handle":0x81004c41u32,
        "product_admin_active":false,"role_grant":false}))?;
    let deployment = record_deployment(&record);
    let intent = ParentIntent::new(record.clone(), &deployment, &public, &signature)?;
    eprintln!("Checkpoint enrollment will allocate TPM persistent parent 0x81004c41 and NV index 0x01804c41.\nExisting TPM ownership will not change. Interrupted intent is retained and cannot be retried automatically.\nThis enrolls an audit checkpoint only; it does not activate product Admin. Cancel now if not intended.");
    let owner = authentication::existing_owner()?;
    let account = authentication::local(username)?;
    let parent_name = allocate_parent(
        &intent,
        parent_path,
        pending,
        final_path,
        || {
            if binding.identity()? != identity || account.identity()? != identity {
                return Err("enrollment principal changed; review retained parent intent".into());
            }
            if credentials::public_input(public_path, 4096)? != public
                || credentials::public_input(signature_path, 16384)? != signature
            {
                return Err("enrollment boot inputs changed; review retained parent intent".into());
            }
            Ok(())
        },
        || provisioner.provision_parent(&owner),
    )?;
    let secret = Secret::generate()?;
    let blob = owner_credential::seal(&deployment, &parent_name, &public, &secret)?;
    let recovered =
        owner_credential::unseal(&deployment, &parent_name, &public, &blob, &signature)?;
    if recovered.bytes() != secret.bytes() {
        return Err("native sealed enrollment preflight mismatch; preserve parent intent".into());
    }
    drop(recovered);
    let proposal = Proposal::new(record, &deployment, &parent_name, &public, blob)?;
    let result = commit(
        &proposal,
        pending,
        final_path,
        || {
            intent.recheck_bound(parent_path, &parent_name)?;
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
    use crate::{platform, sealed_credential};
    use std::cell::Cell;
    use std::io::Read;
    use std::path::PathBuf;
    #[test]
    #[ignore = "requires fresh isolated existing-owner TPM with signed PCR policy"]
    fn emulator_resume_bound_parent_without_reallocation() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let public = credentials::public_input(&root.join("pcr-public.pem"), 4096).unwrap();
        let signature = credentials::public_input(&root.join("pcr-signature.json"), 16384).unwrap();
        owner_credential::fixture_verify_boot(&root, &public, &signature).unwrap();
        let mut owner = sealed_credential::PrivateBuffer::new(32).unwrap();
        File::open(root.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let mut provisioner = tpm::Provisioner::fixture(&root).unwrap();
        let principal = serde_json::json!({"installation":"aa","principal":"bb",
            "generation":1,"login":"human","uid":1001});
        let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "kind":"inert-checkpoint-enrollment","principal":principal,
            "admission_observation":provisioner.observation(),
            "observation_is_attestation":false,"ownership":"existing-owner",
            "credential_parent_handle":0x81004c41u32,
            "product_admin_active":false,"role_grant":false}))
        .unwrap();
        assert_eq!(enrollment_identity(&record).unwrap(), principal);
        let deployment = record_deployment(&record);
        let intent = ParentIntent::new(record, &deployment, &public, &signature).unwrap();
        let parent_path = root.join("resume-parent-intent");
        let pending = root.join("resume-pending");
        let final_path = root.join("resume-admin");
        let name = allocate_parent(
            &intent,
            &parent_path,
            &pending,
            &final_path,
            || Ok(()),
            || provisioner.provision_parent(&owner),
        )
        .unwrap();
        let report = inspect_at(&parent_path, &pending, &final_path, |name| {
            tpm::enrollment_handles_fixture(&root, name)
        })
        .unwrap();
        assert_eq!(report["phase"], "parent_bound_proposal_absent");
        let reviewed = report["observation_sha256"].as_str().unwrap();
        let (retained, retained_name) =
            reviewed_bound_parent_at(&parent_path, &pending, &final_path, reviewed, |name| {
                tpm::enrollment_handles_fixture(&root, name)
            })
            .unwrap();
        assert_eq!(retained_name, name);
        assert_eq!(retained.record, intent.record);
        let secret = Secret::generate().unwrap();
        let blob =
            owner_credential::fixture_seal(&root, &deployment, &name, &public, &secret).unwrap();
        assert_eq!(owner_credential::fixture_unseal(
            &root, &deployment, &name, &public, &blob, &signature,
        ).unwrap().bytes(), secret.bytes());
        let proposal = Proposal::new(retained.record, &deployment, &name, &public, blob).unwrap();
        let lock = tpm::exclusive_lock(&root.join("resume.lock")).unwrap();
        let status = commit(
            &proposal,
            &pending,
            &final_path,
            || intent.recheck_bound(&parent_path, &name),
            || provisioner.provision(&owner, &secret, admin_journal::genesis(&deployment)?, lock),
        )
        .unwrap();
        assert_eq!(status["checkpoint_enrolled"], true);
        assert!(
            reviewed_bound_parent_at(&parent_path, &pending, &final_path, reviewed, |name| {
                tpm::enrollment_handles_fixture(&root, name)
            },)
            .is_err()
        );
        let (_, delivered) = credentials::load_at(
            &final_path,
            &root.join("pcr-public.pem"),
            &root.join("pcr-signature.json"),
            |d, name, p, b, s| owner_credential::fixture_unseal(&root, d, name, p, b, s),
        )
        .unwrap();
        assert_eq!(delivered.bytes(), secret.bytes());
    }
    #[test]
    #[ignore = "requires fresh isolated existing-owner enrollment TPM fixture"]
    fn emulator_enrollment() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let public = credentials::public_input(&root.join("pcr-public.pem"), 4096).unwrap();
        let signature = credentials::public_input(&root.join("pcr-signature.json"), 16384).unwrap();
        let mut provisioner = tpm::Provisioner::fixture(&root).unwrap();
        let record = serde_json::to_vec(&serde_json::json!({"kind":"inert-test-enrollment",
            "admission":provisioner.observation()}))
        .unwrap();
        let deployment = record_deployment(&record);
        let mut owner = sealed_credential::PrivateBuffer::new(32).unwrap();
        File::open(root.join("owner.binary"))
            .unwrap()
            .read_exact(owner.bytes_mut())
            .unwrap();
        let intent = ParentIntent::new(record.clone(), &deployment, &public, &signature).unwrap();
        let parent_path = root.join("parent-intent");
        let pending = root.join("enrollment-pending");
        let final_path = root.join("admin");
        owner_credential::fixture_verify_boot(&root, &public, &signature).unwrap();
        let parent_name = allocate_parent(
            &intent,
            &parent_path,
            &pending,
            &final_path,
            || Ok(()),
            || provisioner.provision_parent(&owner),
        )
        .unwrap();
        let secret = Secret::generate().unwrap();
        let blob =
            owner_credential::fixture_seal(&root, &deployment, &parent_name, &public, &secret)
                .unwrap();
        let recovered = owner_credential::fixture_unseal(
            &root,
            &deployment,
            &parent_name,
            &public,
            &blob,
            &signature,
        )
        .unwrap();
        assert_eq!(recovered.bytes(), secret.bytes());
        drop(recovered);
        let proposal = Proposal::new(record, &deployment, &parent_name, &public, blob).unwrap();
        let lock = tpm::exclusive_lock(&root.join("enrollment.lock")).unwrap();
        let status = commit(
            &proposal,
            &pending,
            &final_path,
            || intent.recheck_bound(&parent_path, &parent_name),
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
            |d, name, p, b, s| owner_credential::fixture_unseal(&root, d, name, p, b, s),
        )
        .unwrap();
        assert_eq!(config.deployment, deployment);
        assert_eq!(delivered.bytes(), secret.bytes());
        platform::write_atomic(
            &root.join("enrolled-secret.sha256"),
            bundle::hex(&Sha256::digest(secret.bytes())).as_bytes(),
            0o600,
        )
        .unwrap();
        assert!(!final_path.join("nv-auth").exists());
        assert!(!pending.exists());
        intent.recheck_bound(&parent_path, &parent_name).unwrap();
    }
    #[test]
    #[ignore = "requires previously enrolled isolated existing-owner TPM fixture"]
    fn emulator_enrolled_delivery() {
        let root = PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        let mode = std::env::var("LUMA_TPM_TEST_DELIVERY").unwrap();
        let result = credentials::load_at(
            &root.join("admin"),
            &root.join("pcr-public.pem"),
            &root.join("pcr-signature.json"),
            |d, name, p, b, s| owner_credential::fixture_unseal(&root, d, name, p, b, s),
        );
        match mode.as_str() {
            "allow" => {
                let (_, secret) = result.unwrap();
                assert_eq!(
                    bundle::hex(&Sha256::digest(secret.bytes())).as_bytes(),
                    tpm::private_read(&root.join("enrolled-secret.sha256"), 64).unwrap()
                );
            }
            "deny" => assert!(result.is_err()),
            _ => panic!("unknown enrolled delivery fixture mode"),
        }
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
                &tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap(),
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
    fn parent_allocation_follows_durable_intent_and_never_retries() {
        let f = Fixture::new("parent-success");
        let record = f.proposal.files[3].1.clone();
        let intent = ParentIntent::new(
            record,
            &f.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        let path = f.root.join("parent-intent");
        let name = tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap();
        let returned = allocate_parent(
            &intent,
            &path,
            &f.pending,
            &f.final_path,
            || {
                intent.recheck(&path)?;
                Ok(())
            },
            || {
                intent.recheck(&path)?;
                assert!(!f.final_path.exists());
                Ok(name)
            },
        )
        .unwrap();
        assert_eq!(returned, name);
        intent.recheck_bound(&path, &name).unwrap();
        assert!(allocate_parent(
            &intent,
            &path,
            &f.pending,
            &f.final_path,
            || panic!("no repeated authorization"),
            || panic!("no repeated persistent write")
        )
        .is_err());
    }
    #[test]
    fn parent_lost_reply_and_changed_intent_remain_fenced() {
        let f = Fixture::new("parent-lost");
        let intent = ParentIntent::new(
            f.proposal.files[3].1.clone(),
            &f.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        let path = f.root.join("parent-intent");
        assert!(allocate_parent(
            &intent,
            &path,
            &f.pending,
            &f.final_path,
            || Ok(()),
            || Err("lost persistent TPM write reply".into()),
        )
        .is_err());
        intent.recheck(&path).unwrap();
        assert!(allocate_parent(
            &intent,
            &path,
            &f.pending,
            &f.final_path,
            || panic!("no retry"),
            || panic!("no retry")
        )
        .is_err());
        let changed = Fixture::new("parent-changed");
        let intent = ParentIntent::new(
            changed.proposal.files[3].1.clone(),
            &changed.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        let path = changed.root.join("parent-intent");
        assert!(allocate_parent(
            &intent,
            &path,
            &changed.pending,
            &changed.final_path,
            || {
                fs::write(path.join("parent-intent.json"), b"substituted")?;
                Ok(())
            },
            || panic!("changed intent cannot write TPM")
        )
        .is_err());
        assert!(path.is_dir());
    }
    #[test]
    fn inspection_classifies_retained_parent_and_uncertain_nv_without_mutation() {
        let f = Fixture::new("inspect");
        let path = f.root.join("parent-intent");
        let fresh = inspect_at(&path, &f.pending, &f.final_path, |_| {
            Ok((false, false, false))
        })
        .unwrap();
        assert_eq!(fresh["phase"], "not_started");
        let intent = ParentIntent::new(
            f.proposal.files[3].1.clone(),
            &f.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        intent.prepare(&path, &f.pending, &f.final_path).unwrap();
        let uncertain = inspect_at(&path, &f.pending, &f.final_path, |_| {
            Ok((true, false, false))
        })
        .unwrap();
        assert_eq!(uncertain["phase"], "parent_write_uncertain");
        assert_eq!(
            inspect_at(&path, &f.pending, &f.final_path, |_| Ok((
                true, true, false
            )))
            .unwrap()["phase"],
            "conflict_preserve_state"
        );
        let name = tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap();
        intent.bind_name(&path, &name).unwrap();
        let bound = inspect_at(&path, &f.pending, &f.final_path, |_| {
            Ok((true, false, true))
        })
        .unwrap();
        assert_eq!(bound["phase"], "parent_bound_proposal_absent");
        assert_eq!(bound["reviewed_recovery_available"], false);
        assert_ne!(bound["observation_sha256"], uncertain["observation_sha256"]);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&f.pending)
            .unwrap();
        let pending =
            inspect_at(&path, &f.pending, &f.final_path, |_| Ok((true, true, true))).unwrap();
        assert_eq!(pending["phase"], "nv_write_or_publication_uncertain");
        assert_eq!(pending["mutation_performed"], false);
        assert_eq!(
            inspect_at(&path, &f.pending, &f.final_path, |_| Ok((
                true, true, false
            )))
            .unwrap()["phase"],
            "conflict_preserve_state"
        );
    }
    #[test]
    fn inspection_refuses_changed_or_unsafe_intent_before_tpm_observation() {
        let f = Fixture::new("inspect-refuse");
        let path = f.root.join("parent-intent");
        let intent = ParentIntent::new(
            f.proposal.files[3].1.clone(),
            &f.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        intent.prepare(&path, &f.pending, &f.final_path).unwrap();
        fs::write(path.join("parent-intent.json"), b"{}").unwrap();
        assert!(inspect_at(&path, &f.pending, &f.final_path, |_| panic!(
            "invalid intent must not reach TPM"
        ))
        .is_err());
        fs::remove_file(path.join("parent-intent.json")).unwrap();
        std::os::unix::fs::symlink("/tmp/missing", path.join("parent-intent.json")).unwrap();
        assert!(inspect_at(&path, &f.pending, &f.final_path, |_| panic!(
            "unsafe intent must not reach TPM"
        ))
        .is_err());
    }
    #[test]
    fn reviewed_bound_parent_requires_exact_fresh_snapshot_without_nv_proposal() {
        let f = Fixture::new("review-bound");
        let path = f.root.join("parent-intent");
        let intent = ParentIntent::new(
            f.proposal.files[3].1.clone(),
            &f.proposal.deployment,
            b"public fixture",
            b"signed fixture",
        )
        .unwrap();
        intent.prepare(&path, &f.pending, &f.final_path).unwrap();
        let name = tpm::decode::<34>(&format!("000b{}", "22".repeat(32))).unwrap();
        intent.bind_name(&path, &name).unwrap();
        let observed = inspect_at(&path, &f.pending, &f.final_path, |_| {
            Ok((true, false, true))
        })
        .unwrap();
        assert_eq!(observed["bounded_continuation_possible"], true);
        let digest = observed["observation_sha256"].as_str().unwrap();
        let (recovered, recovered_name) =
            reviewed_bound_parent_at(&path, &f.pending, &f.final_path, digest, |_| {
                Ok((true, false, true))
            })
            .unwrap();
        assert_eq!(recovered.record, intent.record);
        assert_eq!(recovered_name, name);
        assert!(reviewed_bound_parent_at(
            &path,
            &f.pending,
            &f.final_path,
            &"00".repeat(32),
            |_| Ok((true, false, true)),
        )
        .is_err());
        assert!(
            reviewed_bound_parent_at(&path, &f.pending, &f.final_path, digest, |_| Ok((
                true, true, true
            )),)
            .is_err()
        );
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&f.pending)
            .unwrap();
        assert!(
            reviewed_bound_parent_at(&path, &f.pending, &f.final_path, digest, |_| Ok((
                true, false, true
            )),)
            .is_err()
        );
    }
    #[test]
    fn retained_record_for_continuation_is_closed_canonical_and_inert() {
        let principal = serde_json::json!({"installation":"aa","principal":"bb",
            "generation":1,"login":"human","uid":1001});
        let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,
            "kind":"inert-checkpoint-enrollment","principal":principal,
            "admission_observation":{"clock":{"milliseconds":1}},
            "observation_is_attestation":false,"ownership":"existing-owner",
            "credential_parent_handle":0x81004c41u32,
            "product_admin_active":false,"role_grant":false}))
        .unwrap();
        assert_eq!(enrollment_identity(&record).unwrap(), principal);
        let mut changed: serde_json::Value = serde_json::from_slice(&record).unwrap();
        changed["role_grant"] = serde_json::json!(true);
        assert!(enrollment_identity(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed["role_grant"] = serde_json::json!(false);
        changed["credential_parent_handle"] = serde_json::json!(0x81004c42u32);
        assert!(enrollment_identity(&serde_json::to_vec(&changed).unwrap()).is_err());
        let noncanonical = String::from_utf8(record.clone())
            .unwrap()
            .replace(",\"kind\"", ", \"kind\"");
        assert!(enrollment_identity(noncanonical.as_bytes()).is_err());
        let duplicate =
            String::from_utf8(record)
                .unwrap()
                .replacen('{', "{\"schema_version\":1,", 1);
        assert!(enrollment_identity(duplicate.as_bytes()).is_err());
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
