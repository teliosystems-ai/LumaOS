//! Finite, original-Admin delivery of externally signed machine qualification.
//! Transport/storage envelopes do not alter the frozen signed certificate wire.
use crate::{
    bundle,
    finite_grants::{Action, Kind, Selector, Use},
    model_trust::{self, CertificationRecord, QualificationEvidence},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};
const ROOT: &str = "/var/lib/luma-os/model-qualifications";
const INPUT: &str = "/run/luma-admin/model-qualifications";
const LIMIT: u64 = 96 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Package {
    pub record: CertificationRecord,
    pub signature_hex: String,
    pub evidence: QualificationEvidence,
}
impl Package {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = model_trust::parse(bytes, LIMIT as usize)?;
        value.record.validate()?;
        value.signature()?;
        QualificationEvidence::parse(&model_trust::canonical(&value.evidence)?, &value.record)?;
        Ok(value)
    }
    pub(crate) fn signature(&self) -> Result<[u8; 64]> {
        let raw = crate::tpm::decode::<64>(&self.signature_hex)?;
        if bundle::hex(&raw) != self.signature_hex {
            return Err(
                "qualification signature encoding is not canonical lowercase raw Ed25519".into(),
            );
        }
        Ok(raw)
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = model_trust::canonical(self)?;
        Self::parse(&bytes)?;
        Ok(bytes)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    package: Package,
    expected_previous_sha256: Option<String>,
}
impl Transfer {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > LIMIT {
            return Err("qualification input exceeds bound".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.package.bytes()?;
        if let Some(digest) = &value.expected_previous_sha256 {
            crate::tpm::decode::<32>(digest)?;
            if digest != &digest.to_ascii_lowercase() {
                return Err("qualification predecessor digest is not canonical".into());
            }
        }
        Ok(value)
    }
}
fn hash(bytes: &[u8]) -> String {
    bundle::hex(&Sha256::digest(bytes))
}
fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
        || (m.dev(), m.ino()) != (named.dev(), named.ino())
        || named.file_type().is_symlink()
    {
        return Err(
            "qualification data must be exact root-owned unlinked regular public files".into(),
        );
    }
    Ok(file)
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let mut file = regular(path)?;
    let before = file.metadata()?;
    if before.len() > LIMIT {
        return Err("qualification file exceeds bound".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || regular(path)?.metadata()?.ino() != before.ino()
    {
        return Err("qualification file changed while captured".into());
    }
    Ok(bytes)
}
fn maybe_read(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(Some(read(path)?)),
    }
}
fn directory(path: &Path, create: bool) -> Result<()> {
    if create {
        match fs::create_dir(path) {
            Ok(()) => {
                fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
                File::open(
                    path.parent()
                        .ok_or("qualification directory lacks parent")?,
                )?
                .sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("unsafe qualification directory".into());
    }
    Ok(())
}
fn hierarchy(create: bool) -> Result<()> {
    for path in ["/var", "/var/lib", "/var/lib/luma-os"] {
        directory(Path::new(path), false)?;
    }
    directory(Path::new(ROOT), create)
}
fn source(path: &Path) -> Result<Transfer> {
    let parent = path.parent().ok_or("qualification source has no parent")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("invalid qualification input name")?;
    if parent == Path::new(INPUT)
        && name
            .strip_suffix(".json")
            .is_some_and(crate::admin_roles::identifier)
    {
        for at in ["/run", "/run/luma-admin", INPUT] {
            directory(Path::new(at), false)?;
        }
    } else if name == "input.json"
        && parent.parent() == Some(Path::new("/run/luma-granted-client/requests"))
        && parent
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(crate::admin_roles::identifier)
    {
        // The confined IPC gateway copies inert public input into its exact
        // root-owned request namespace. It supplies no authorization; the
        // original-Admin finite grant and signature checks remain mandatory.
        for at in [
            Path::new("/run"),
            Path::new("/run/luma-granted-client"),
            Path::new("/run/luma-granted-client/requests"),
            parent,
        ] {
            directory(at, false)?;
        }
    } else {
        return Err("qualification input must be named Admin public data or the exact confined gateway input namespace".into());
    }
    Transfer::parse(&read(path)?)
}
/// Inert public data copied by the fixed confined gateway, never authority.
pub(crate) fn stage_input(path: &Path) -> Result<Vec<u8>> {
    model_trust::canonical(&source(path)?)
}
fn destination(profile: &crate::model::Profile, package: &Package) -> Result<PathBuf> {
    let binding = profile
        .governed
        .as_ref()
        .ok_or("qualification requires governed public model profile")?;
    if binding.manifest_sha256 != package.record.pack_manifest_sha256
        || binding.runtime_tuple_sha256 != package.record.runtime_tuple_sha256
    {
        return Err("qualification package belongs to another model tuple".into());
    }
    Ok(Path::new(ROOT)
        .join(&binding.manifest_sha256)
        .join(format!("{}.qualification.json", package.record.level)))
}
fn current(path: &Path) -> Result<Option<String>> {
    maybe_read(path)?
        .map(|bytes| {
            Package::parse(&bytes)?;
            Ok(hash(&bytes))
        })
        .transpose()
}
fn usage(profile: &crate::model::Profile, transfer: &Transfer) -> Result<Use> {
    let bytes = transfer.package.bytes()?;
    let digest = model_trust::digest(
        &serde_json::json!({"domain":"luma-native-model-qualification-provision-v1","installation":crate::artifacts::installation()?,"profile":profile.resource_binding()?,"package_sha256":hash(&bytes),"previous_sha256":transfer.expected_previous_sha256}),
    )?;
    let usage = Use {
        action: Action::ProvisionResource,
        selector: Selector {
            kind: Kind::Resource,
            id: format!(
                "ModelQualification-{}-{}",
                profile.id, transfer.package.record.level
            ),
            generation: 1,
            digest,
        },
        input_bytes: model_trust::canonical(transfer)?.len() as u64,
        output_bytes: bytes.len() as u64,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
fn compare(path: &Path, transfer: &Transfer) -> Result<bool> {
    let desired = hash(&transfer.package.bytes()?);
    let existing = current(path)?;
    if existing.as_deref() == Some(desired.as_str()) {
        if let Some(previous) = &transfer.expected_previous_sha256 {
            if *previous != desired {
                let store_root = path
                    .parent()
                    .and_then(Path::parent)
                    .ok_or("qualification replay target lacks store root")?;
                let retained = read(
                    &store_root
                        .join(".history")
                        .join(format!("{previous}.qualification.json")),
                )?;
                let prior = Package::parse(&retained)?;
                if hash(&retained) != *previous
                    || prior.record.pack_manifest_sha256
                        != transfer.package.record.pack_manifest_sha256
                    || prior.record.level != transfer.package.record.level
                {
                    return Err("qualification retry cannot invent a predecessor absent exact retained history".into());
                }
            }
        }
        return Ok(true);
    }
    if existing != transfer.expected_previous_sha256 {
        return Err(
            "qualification predecessor changed; review exact current package before rotation"
                .into(),
        );
    }
    Ok(false)
}
fn lock() -> Result<File> {
    let path = Path::new(ROOT).join(".transfer.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err("unsafe qualification transfer lock".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another qualification transaction owns the target".into());
    }
    Ok(file)
}
fn new_file(path: &Path, bytes: &[u8], check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    check()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut offset = 0;
    while offset < bytes.len() {
        check()?;
        let count = file.write(&bytes[offset..])?;
        if count == 0 {
            return Err("qualification writer made no progress; preserve partial staging".into());
        }
        offset += count;
    }
    file.sync_all()?;
    File::open(path.parent().ok_or("qualification file lacks parent")?)?.sync_all()?;
    Ok(())
}
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bundle::hex(&bytes))
}
fn retain_previous(
    store_root: &Path,
    path: &Path,
    expected: &Option<String>,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let bytes = read(path)?;
    if hash(&bytes) != *expected {
        return Err("qualification predecessor changed before retention".into());
    }
    let history = store_root.join(".history");
    check()?;
    directory(&history, true)?;
    let retained = history.join(format!("{expected}.qualification.json"));
    match maybe_read(&retained)? {
        Some(existing) if existing == bytes => Ok(()),
        Some(_) => Err("retained qualification digest conflicts with existing bytes".into()),
        None => {
            let package = Package::parse(&bytes)?;
            let staged = store_root.join(format!(
                ".pending-{}-{}-history-{expected}-{}",
                package.record.pack_manifest_sha256,
                package.record.level,
                nonce()?
            ));
            new_file(&staged, &bytes, check)?;
            let from = std::ffi::CString::new(staged.as_os_str().as_bytes())?;
            let to = std::ffi::CString::new(retained.as_os_str().as_bytes())?;
            check()?;
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
            File::open(&history)?.sync_all()?;
            File::open(store_root)?.sync_all()?;
            Ok(())
        }
    }
}
fn publish(
    store_root: &Path,
    path: &Path,
    transfer: &Transfer,
    mut check: impl FnMut() -> Result<()>,
) -> Result<bool> {
    check()?;
    if compare(path, transfer)? {
        return Ok(false);
    }
    let prefix = format!(".pending-{}-", transfer.package.record.pack_manifest_sha256);
    let mut pending_count = 0;
    for entry in fs::read_dir(store_root)? {
        if entry?
            .file_name()
            .to_str()
            .ok_or("non-UTF8 qualification namespace")?
            .starts_with(&prefix)
        {
            pending_count += 1;
            if pending_count >= 64 {
                return Err("qualification pending limit reached; review and retain interrupted bytes before new writes".into());
            }
        }
    }
    let root = path
        .parent()
        .ok_or("qualification target lacks manifest namespace")?;
    directory(root, true)?;
    retain_previous(
        store_root,
        path,
        &transfer.expected_previous_sha256,
        &mut check,
    )?;
    check()?;
    let pending = store_root.join(format!(
        ".pending-{}-{}-{}",
        transfer.package.record.pack_manifest_sha256,
        transfer.package.record.level,
        nonce()?
    ));
    new_file(&pending, &transfer.package.bytes()?, &mut check)?;
    if compare(path, transfer)? {
        return Err(
            "qualification target completed concurrently; preserve prepared package".into(),
        );
    }
    let from = std::ffi::CString::new(pending.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // The root-only transfer lock owns the namespace. RENAME_NOREPLACE
    // protects initial publication; rotation compares the exact retained old
    // package immediately before the atomic same-filesystem replacement.
    let flags = if transfer.expected_previous_sha256.is_none() {
        libc::RENAME_NOREPLACE
    } else {
        0
    };
    check()?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(root)?.sync_all()?;
    File::open(store_root)?.sync_all()?;
    check()?;
    if current(path)?.as_deref() != Some(hash(&transfer.package.bytes()?).as_str()) {
        return Err("qualification publication readback failed".into());
    }
    Ok(true)
}
pub(crate) fn review(id: &str, input: &Path) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let profile = crate::model::public_profile(id)?;
    let transfer = source(input)?;
    crate::admin_governance::qualification_preparation(
        &profile,
        &transfer.package.record,
        &transfer.package.evidence,
        &transfer.package.signature()?,
    )?;
    let path = destination(&profile, &transfer.package)?;
    match fs::symlink_metadata(ROOT) {
        Ok(_) => {
            hierarchy(false)?;
            compare(&path, &transfer)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if transfer.expected_previous_sha256.is_some() {
                return Err("qualification predecessor is absent".into());
            }
        }
        Err(e) => return Err(e.into()),
    }
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"usage":usage(&profile,&transfer)?,"package_sha256":hash(&transfer.package.bytes()?),"previous_sha256":transfer.expected_previous_sha256,"activates_model":false,"externally_signed_qualification":true})
    );
    Ok(())
}
pub(crate) fn install(login: &str, grant: &str, id: &str, input: &Path) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let profile = crate::model::public_profile(id)?;
    let transfer = source(input)?;
    let path = destination(&profile, &transfer.package)?;
    let usage = usage(&profile, &transfer)?;
    crate::admin_governance::qualification_preparation(
        &profile,
        &transfer.package.record,
        &transfer.package.evidence,
        &transfer.package.signature()?,
    )?;
    crate::admin_governance::with_grant(login, grant, &usage, |boundary| {
        boundary.require_admin()?;
        hierarchy(true)?;
        let _lock = lock()?;
        compare(&path, &transfer)?;
        let intent = model_trust::digest(&transfer)?;
        let effect = boundary.effect_begin(
            &intent,
            crate::policy_decisions::EffectKind::ResourceAdmission,
        )?;
        let changed = publish(Path::new(ROOT), &path, &transfer, || {
            boundary.require_admin()?;
            crate::admin_governance::qualification_preparation(
                &profile,
                &transfer.package.record,
                &transfer.package.evidence,
                &transfer.package.signature()?,
            )?;
            boundary.check()
        })?;
        boundary.require_admin()?;
        let receipt = model_trust::digest(
            &serde_json::json!({"domain":"luma-model-qualification-delivered-v1","intent_sha256":intent,"package_sha256":hash(&transfer.package.bytes()?)}),
        )?;
        boundary.effect_complete(effect, &receipt)?;
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"changed":changed,"package_sha256":hash(&transfer.package.bytes()?),"activates_model":false})
        );
        Ok(())
    })
}
pub(crate) fn observe(id: &str, level: &str, report_sha256: &str) -> Result<()> {
    let profile = crate::model::public_profile(id)?;
    let evidence =
        crate::admin_governance::qualification_observation(&profile, level, report_sha256)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"evidence":evidence,"evidence_sha256":model_trust::digest(&evidence)?,"certified":false,"authority_returned":false})
    );
    Ok(())
}
#[derive(Serialize, PartialEq, Eq)]
struct Pending {
    name: String,
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_nsec: i64,
    sha256: String,
}
fn pending(profile: &crate::model::Profile) -> Result<Vec<Pending>> {
    let binding = profile
        .governed
        .as_ref()
        .ok_or("qualification retention requires exact governed public model")?;
    hierarchy(false)?;
    let prefix = format!(".pending-{}-", binding.manifest_sha256);
    let mut out = Vec::new();
    for entry in fs::read_dir(ROOT)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 qualification namespace")?;
        if !name.starts_with(&prefix) {
            continue;
        }
        if name.len() > 256
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err("unknown pending qualification name".into());
        }
        let file = regular(&entry.path())?;
        let before = file.metadata()?;
        let bytes = read(&entry.path())?;
        let after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err("pending qualification identity changed".into());
        }
        out.push(Pending {
            name,
            device: before.dev(),
            inode: before.ino(),
            size: before.len(),
            ctime: before.ctime(),
            ctime_nsec: before.ctime_nsec(),
            sha256: hash(&bytes),
        });
        if out.len() > 64 {
            return Err("qualification pending review exceeds bounded disposition batch".into());
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    if out.is_empty() {
        return Err("no interrupted qualification bytes remain".into());
    }
    Ok(out)
}
fn pending_usage(profile: &crate::model::Profile, witness: &[Pending]) -> Result<Use> {
    let digest = model_trust::digest(
        &serde_json::json!({"domain":"luma-model-qualification-retain-unverified-v1","installation":crate::artifacts::installation()?,"profile":profile.resource_binding()?,"pending":witness}),
    )?;
    let bytes = witness.iter().try_fold(0u64, |n, p| {
        n.checked_add(p.size)
            .ok_or("pending qualification size overflow")
    })?;
    let usage = Use {
        action: Action::Retain,
        selector: Selector {
            kind: Kind::Resource,
            id: format!("ModelQualification-{}-pending", profile.id),
            generation: 1,
            digest,
        },
        input_bytes: bytes,
        output_bytes: 0,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
pub(crate) fn pending_review(id: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let profile = crate::model::public_profile(id)?;
    let witness = pending(&profile)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"usage":pending_usage(&profile,&witness)?,"disposition":"retain-unverified","byte_verified":false,"activates_model":false})
    );
    Ok(())
}
pub(crate) fn pending_retain(login: &str, grant: &str, id: &str, review: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    crate::platform::require_production_activation()?;
    let profile = crate::model::public_profile(id)?;
    let witness = pending(&profile)?;
    let usage = pending_usage(&profile, &witness)?;
    if usage.selector.digest != review {
        return Err("qualification pending review changed".into());
    }
    crate::admin_governance::with_grant(login, grant, &usage, |boundary| {
        boundary.require_admin()?;
        let _lock = lock()?;
        if pending(&profile)? != witness {
            return Err("qualification pending disposition changed under lock".into());
        }
        let effect =
            boundary.effect_begin(review, crate::policy_decisions::EffectKind::Retention)?;
        let retained = Path::new(ROOT).join(".retained-pending");
        boundary.require_admin()?;
        directory(&retained, true)?;
        let batch = retained.join(review);
        boundary.require_admin()?;
        directory(&batch, true)?;
        for member in &witness {
            let from = Path::new(ROOT).join(&member.name);
            let to = batch.join(&member.name);
            let file = regular(&from)?;
            let m = file.metadata()?;
            if (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
                != (
                    member.device,
                    member.inode,
                    member.size,
                    member.ctime,
                    member.ctime_nsec,
                )
                || hash(&read(&from)?) != member.sha256
            {
                return Err("pending qualification bytes changed before retention".into());
            }
            let from = std::ffi::CString::new(from.as_os_str().as_bytes())?;
            let to = std::ffi::CString::new(to.as_os_str().as_bytes())?;
            boundary.require_admin()?;
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
            File::open(&batch)?.sync_all()?;
            File::open(ROOT)?.sync_all()?;
        }
        boundary.require_admin()?;
        let receipt = model_trust::digest(
            &serde_json::json!({"domain":"qualification-pending-retained-v1","review":review,"members":witness}),
        )?;
        boundary.effect_complete(effect, &receipt)?;
        println!(
            "{}",
            serde_json::json!({"retained_unverified":true,"deletes_content":false,"activates_model":false})
        );
        Ok(())
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_rejects_unknown_duplicate_unbounded_and_noncanonical_signature() {
        assert!(Transfer::parse(b"{}").is_err());
        assert!(Transfer::parse(&vec![b' '; LIMIT as usize + 1]).is_err());
        assert!(Transfer::parse(
            br#"{"package":{},"expected_previous_sha256":null,"expected_previous_sha256":null}"#
        )
        .is_err());
        assert!(Package::parse(
            br#"{"record":{},"signature_hex":"00","evidence":{},"authority":true}"#
        )
        .is_err());
    }
    fn transfer(report: char, previous: Option<String>) -> Transfer {
        let evidence = QualificationEvidence {
            schema_version: 1,
            level: "execution".into(),
            installation_sha256: "9".repeat(64),
            release_manifest_sha256: "1".repeat(64),
            model_profile_sha256: "2".repeat(64),
            runtime_tuple_sha256: "3".repeat(64),
            hardware: model_trust::MachineTuple {
                cpu_vendor: "GenuineIntel".into(),
                cpu_family: 6,
                cpu_model: 154,
                cpu_stepping: 3,
                features: vec!["sse2".into()],
                logical_cpus: 2,
                total_memory_bytes: 16 * 1024 * 1024 * 1024,
            },
            test_report_sha256: report.to_string().repeat(64),
        };
        // Filesystem fault tests use inert syntactically valid transport bytes;
        // live install separately requires genuine signatures/current authority.
        let record = CertificationRecord {
            level: "execution".into(),
            pack_manifest_sha256: "4".repeat(64),
            runtime_tuple_sha256: evidence.runtime_tuple_sha256.clone(),
            evidence_sha256: model_trust::digest(&evidence).unwrap(),
            signer_key_id: "external-qa".into(),
        };
        Transfer {
            package: Package {
                record,
                signature_hex: "ab".repeat(64),
                evidence,
            },
            expected_previous_sha256: previous,
        }
    }
    #[test]
    fn atomic_publication_rotation_exact_retry_and_faults_preserve_previous_bytes() {
        let root = std::env::temp_dir().join(format!(
            "luma-qualification-io-{}-{}",
            std::process::id(),
            nonce().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let path = root
            .join("4".repeat(64))
            .join("execution.qualification.json");
        let initial = transfer('5', None);
        let bytes = initial.package.bytes().unwrap();
        assert!(publish(&root, &path, &initial, || Ok(())).unwrap());
        assert_eq!(read(&path).unwrap(), bytes);
        assert!(!publish(&root, &path, &initial, || Ok(())).unwrap());
        let replacement = transfer('6', Some(hash(&bytes)));
        let mut checks = 0;
        assert!(publish(&root, &path, &replacement, || {
            checks += 1;
            if checks == 5 {
                Err("simulated grant revocation".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(read(&path).unwrap(), bytes);
        assert!(publish(&root, &path, &replacement, || Ok(())).unwrap());
        assert_eq!(
            read(
                &root
                    .join(".history")
                    .join(format!("{}.qualification.json", hash(&bytes)))
            )
            .unwrap(),
            bytes
        );
        assert!(!publish(&root, &path, &replacement, || Ok(())).unwrap());
        let stale = transfer('7', Some(hash(&initial.package.bytes().unwrap())));
        assert!(publish(&root, &path, &stale, || Ok(())).is_err());
        let snapshot = read(&path).unwrap();
        let changed = transfer('8', Some(hash(&snapshot)));
        assert!(publish(&root, &path, &changed, || Err(
            "authorization unavailable".into()
        ))
        .is_err());
        assert_eq!(read(&path).unwrap(), snapshot);
        let invented = transfer('6', Some("a".repeat(64)));
        assert!(publish(&root, &path, &invented, || Ok(())).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read(&alias).is_err());
        let linked = root.join("linked");
        fs::hard_link(&path, &linked).unwrap();
        assert!(read(&linked).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
