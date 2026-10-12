//! Exact public model metadata and canonical immutable pack storage.
//! Public profiles are data, not authority. The root broker reconstructs trust.
use super::*;
use crate::{
    model_trust::{
        self, ModelCatalog, ModelProfile, PackManifest, PackVerification, RuntimeTuple,
        SelectableProfile, SignedTrust,
    },
    utc_bounds::Interval,
};
use std::collections::BTreeSet;

const PUBLIC: &str = "/usr/share/luma-os/model-packs";
const PUBLIC_CATALOG: &str = "/usr/share/luma-os/models/catalog.json";
const RESERVE: u64 = 2 * 1024 * 1024 * 1024;

fn read(at: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = regular(at)?;
    if file.metadata()?.len() > maximum {
        return Err("model public metadata exceeds bound".into());
    }
    let before = identity(&file.metadata()?);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || identity(&file.metadata()?) != before {
        return Err("model metadata changed while reading".into());
    }
    Ok(bytes)
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn regular(at: &Path) -> Result<File> {
    let mut parent = at.parent().ok_or("model path has no parent")?;
    loop {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("model pack ancestor is not a protected root directory".into());
        }
        match parent.parent() {
            Some(next) => parent = next,
            None => break,
        }
    }
    let file = open_regular(at)?;
    let m = file.metadata()?;
    if m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o022 != 0 {
        return Err("model pack member is unowned, linked, or writable by others".into());
    }
    Ok(file)
}
fn public_manifest(digest: &str) -> Result<PackManifest> {
    if !crate::artifacts::hash(digest) {
        return Err("invalid model manifest digest".into());
    }
    let m = PackManifest::parse(&read(
        &Path::new(PUBLIC).join(digest).join("manifest.json"),
        model_trust::MAX_TRUST as u64,
    )?)?;
    if m.digest()? != digest {
        return Err("public model manifest is not its named exact digest".into());
    }
    Ok(m)
}
pub(crate) fn native_profile(
    p: &ModelProfile,
    manifest: &PackManifest,
    catalog: &str,
) -> Result<Profile> {
    let mut native = legacy_catalog()?
        .models
        .into_iter()
        .find(|n| n.id == p.profile_id)
        .ok_or("signed model profile requires an unsupported native adapter")?;
    let tuple = RuntimeTuple {
        os_family: "Linux".into(),
        architecture: "amd64".into(),
        backend: "llama.cpp".into(),
        backend_version: "b11100".into(),
        device: "cpu".into(),
    };
    let tuple_digest = tuple.digest()?;
    let weights = manifest
        .blobs
        .iter()
        .filter(|b| b.role == "model")
        .collect::<Vec<_>>();
    let install = manifest
        .installation_profiles
        .iter()
        .find(|i| i.profile_id == p.profile_id)
        .ok_or("pack lacks exact installation profile")?;
    let bytes = manifest.blobs.iter().try_fold(0u64, |sum, b| {
        sum.checked_add(b.size_bytes)
            .ok_or("model pack size overflow")
    })?;
    let peak = bytes
        .checked_add(native.bytes)
        .and_then(|v| v.checked_add(RESERVE))
        .ok_or("native model storage peak overflow")?;
    let memory_ok = |r: &[model_trust::Reservation]| {
        r.len() == 1 && r[0].domain == "host" && r[0].bytes >= native.memory_max_bytes
    };
    if p.kind != "model"
        || p.execution_mode != "cpu"
        || p.runtime_tuple_sha256 != tuple_digest
        || manifest.blobs.len() > 128
        || manifest
            .blobs
            .iter()
            .filter(|b| b.role != "model")
            .try_fold(0u64, |s, b| s.checked_add(b.size_bytes))
            .map_or(true, |size| size > 64 * 1024 * 1024)
        || !manifest.runtime_tuples.contains(&tuple)
        || weights.len() != 1
        || weights[0].shard_index != Some(0)
        || weights[0].sha256 != native.sha256
        || weights[0].size_bytes != native.bytes
        || manifest.model.architecture != "qwen3"
        || manifest.model.total_parameters != native.parameters
        || manifest.model.active_parameters_min != native.active_parameters
        || manifest.model.active_parameters_max != native.active_parameters
        || manifest.model.quantization != "Q4_K_M"
        || manifest.model.source != native.url
        || manifest.model.required_features
            != ["chat-completion".to_string(), "text-generation".to_string()]
        || p.parameter_total != native.parameters
        || p.parameter_active_min != native.active_parameters
        || p.parameter_active_max != native.active_parameters
        || p.model_pack_manifest_sha256 != manifest.digest()?
        || p.context_tokens != u64::from(native.context_tokens)
        || p.minimum_host_ram_bytes < native.minimum_ram_bytes
        || p.minimum_accelerator_memory_bytes != 0
        || p.install_bytes != bytes
        || p.storage_peak_bytes < peak
        || !memory_ok(&p.load_reservations)
        || !memory_ok(&p.serve_reservations)
        || p.minimum_host_ram_bytes
            <= p.load_reservations[0]
                .bytes
                .max(p.serve_reservations[0].bytes)
        || install.runtime_tuple_sha256 != tuple_digest
        || install.execution_mode != "cpu"
        || install.minimum_accelerator_memory_bytes != 0
        || install.minimum_host_ram_bytes > p.minimum_host_ram_bytes
        || install.minimum_model_storage_bytes > p.storage_peak_bytes
        || install.maximum_context_tokens < u64::from(native.context_tokens)
        || manifest.context.maximum_tokens < u64::from(native.context_tokens)
        || manifest.license.identifier != native.license
        || manifest.license.evaluation != "approved"
        || p.remote_fallback
    {
        return Err(
            "signed model catalog/pack understates or changes the closed native CPU/GGUF tuple"
                .into(),
        );
    }
    native.minimum_ram_bytes = p.minimum_host_ram_bytes;
    native.minimum_available_bytes = p.load_reservations[0]
        .bytes
        .max(p.serve_reservations[0].bytes);
    native.memory_max_bytes = native.minimum_available_bytes;
    native.governed = Some(NativeBinding {
        catalog_sha256: catalog.into(),
        profile_sha256: p.digest()?,
        manifest_sha256: manifest.digest()?,
        runtime_tuple_sha256: tuple_digest,
    });
    native.governed.as_ref().unwrap().validate()?;
    layout::Inventory::for_profile(&native)?;
    Ok(native)
}
pub(crate) fn public_native_profiles() -> Result<Option<Vec<Profile>>> {
    match fs::symlink_metadata(PUBLIC_CATALOG) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let catalog = ModelCatalog::parse(&read(
                Path::new(PUBLIC_CATALOG),
                model_trust::MAX_CATALOG as u64,
            )?)?;
            let digest = catalog.digest()?;
            let mut result = Vec::new();
            for profile in &catalog.profiles {
                if let SelectableProfile::Model(p) = profile {
                    result.push(native_profile(
                        p,
                        &public_manifest(&p.model_pack_manifest_sha256)?,
                        &digest,
                    )?);
                }
            }
            Ok(Some(result))
        }
    }
}
pub(crate) fn public_catalog_binding() -> Result<String> {
    match fs::symlink_metadata(PUBLIC_CATALOG) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            legacy_catalog()?;
            Ok(bundle::hex(&Sha256::digest(CATALOG.as_bytes())))
        }
        Err(e) => Err(e.into()),
        Ok(_) => ModelCatalog::parse(&read(
            Path::new(PUBLIC_CATALOG),
            model_trust::MAX_CATALOG as u64,
        )?)?
        .digest(),
    }
}
fn inventory(root: &Path) -> Result<BTreeSet<String>> {
    fn visit(
        root: &Path,
        at: &Path,
        out: &mut BTreeSet<String>,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<()> {
        *nodes = nodes
            .checked_add(1)
            .ok_or("model pack inventory counter overflow")?;
        if depth > 8 || *nodes > 4098 {
            return Err("model pack directory inventory exceeds bound".into());
        }
        let m = fs::symlink_metadata(at)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 || m.file_type().is_symlink() {
            return Err("unsafe model pack inventory member".into());
        }
        if m.is_dir() {
            let before = out.len();
            for entry in fs::read_dir(at)? {
                visit(root, &entry?.path(), out, depth + 1, nodes)?;
            }
            if at != root && out.len() == before {
                return Err("undeclared empty directory in model pack".into());
            }
        } else if m.is_file() && m.nlink() == 1 {
            let name = at
                .strip_prefix(root)?
                .to_str()
                .ok_or("non-UTF8 model pack path")?
                .replace('\\', "/");
            if !out.insert(name) {
                return Err("duplicate model pack file".into());
            }
        } else {
            return Err("linked or special file in model pack".into());
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    visit(root, root, &mut out, 0, &mut 0)?;
    Ok(out)
}
fn expected(m: &PackManifest, auxiliary: bool) -> BTreeSet<String> {
    let mut set = BTreeSet::from(["manifest.json".into(), "manifest.sig".into()]);
    for b in &m.blobs {
        if !auxiliary || b.role != "model" {
            set.insert(b.path.clone());
        }
    }
    set
}
fn hash_member(
    at: &Path,
    size: u64,
    digest: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<File> {
    let mut file = regular(at)?;
    let before = file.metadata()?;
    if before.len() != size {
        return Err("model pack blob size mismatch".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut count = 0u64;
    loop {
        check()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or("model blob size overflow")?;
        if count > size {
            return Err("model blob grew".into());
        }
        hash.update(&buffer[..n]);
    }
    if identity(&before) != identity(&file.metadata()?)
        || count != size
        || bundle::hex(&hash.finalize()) != digest
    {
        return Err("model blob digest/identity changed".into());
    }
    Ok(file)
}
fn verify_pack(
    root: &Path,
    m: &PackManifest,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    if inventory(root)? != expected(m, false) {
        return Err("model pack inventory is incomplete or contains undeclared files".into());
    }
    if read(&root.join("manifest.json"), model_trust::MAX_TRUST as u64)?
        != model_trust::canonical(m)?
    {
        return Err("installed model manifest differs from immutable declared manifest".into());
    }
    for b in &m.blobs {
        hash_member(&root.join(&b.path), b.size_bytes, &b.sha256, check)?;
    }
    verify_sidecars(root, m, check)?;
    check()
}
fn verify_sidecars(
    root: &Path,
    manifest: &PackManifest,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let weight = manifest
        .blobs
        .iter()
        .find(|b| b.role == "model")
        .ok_or("pack model blob missing")?;
    let profile = legacy_catalog()?
        .models
        .into_iter()
        .find(|p| p.sha256 == weight.sha256 && p.bytes == weight.size_bytes)
        .ok_or("sidecars require exact compiled native GGUF")?;
    let mut file = regular(&root.join(&weight.path))?;
    let before = identity(&file.metadata()?);
    let (tokenizer, template) = layout::sidecars(&mut file, &profile, &mut *check)?;
    for (role, bytes) in [("tokenizer", tokenizer), ("template", template)] {
        let blob = manifest
            .blobs
            .iter()
            .find(|b| b.role == role)
            .ok_or("required model sidecar missing")?;
        if bytes.len() as u64 != blob.size_bytes
            || bundle::hex(&Sha256::digest(&bytes)) != blob.sha256
            || read(&root.join(&blob.path), 16 * 1024 * 1024)? != bytes
        {
            return Err("signed model sidecar differs from tokenizer/template actually used by pinned GGUF runtime".into());
        }
    }
    if identity(&file.metadata()?) != before {
        return Err("model changed during embedded sidecar comparison".into());
    }
    check()
}
pub(super) fn acquisition_space(p: &Profile, cached: bool) -> Result<Option<u64>> {
    let Some(binding) = &p.governed else {
        return Ok(None);
    };
    let catalog = ModelCatalog::parse(&read(
        Path::new(PUBLIC_CATALOG),
        model_trust::MAX_CATALOG as u64,
    )?)?;
    if catalog.digest()? != binding.catalog_sha256 {
        return Err("acquisition catalog changed".into());
    }
    let item = catalog
        .profiles
        .iter()
        .find_map(|v| match v {
            SelectableProfile::Model(m) if m.profile_id == p.id => Some(m),
            _ => None,
        })
        .ok_or("acquisition profile disappeared")?;
    if item.digest()? != binding.profile_sha256 {
        return Err("acquisition resource profile changed".into());
    }
    Ok(Some(
        item.storage_peak_bytes
            .checked_sub(if cached { p.bytes } else { 0 })
            .ok_or("signed storage peak underflow")?,
    ))
}
pub(super) fn import_bounds(p: &Profile) -> Result<(u64, u64)> {
    let binding = p
        .governed
        .as_ref()
        .ok_or("typed production pack import requires governed public tuple")?;
    let catalog = ModelCatalog::parse(&read(
        Path::new(PUBLIC_CATALOG),
        model_trust::MAX_CATALOG as u64,
    )?)?;
    if catalog.digest()? != binding.catalog_sha256 {
        return Err("public pack import catalog changed".into());
    }
    let item = catalog
        .profiles
        .iter()
        .find_map(|v| match v {
            SelectableProfile::Model(m) if m.profile_id == p.id => Some(m),
            _ => None,
        })
        .ok_or("pack import profile missing")?;
    if item.digest()? != binding.profile_sha256 {
        return Err("pack import exact profile changed".into());
    }
    Ok((item.install_bytes, item.storage_peak_bytes))
}
pub(crate) fn import_pack(
    var: &Path,
    p: &Profile,
    weight: &Path,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let Some(binding) = &p.governed else {
        return Ok(());
    };
    let manifest = public_manifest(&binding.manifest_sha256)?;
    let source = Path::new(PUBLIC).join(&binding.manifest_sha256);
    if inventory(&source)? != expected(&manifest, true) {
        return Err("public model pack auxiliary inventory is incomplete or undeclared".into());
    }
    let root = var.join(STATE).join("model-packs");
    safe_dir(&root)?;
    let destination = root.join(&binding.manifest_sha256);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return verify_pack(&destination, &manifest, check),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let pending = root.join(format!(".import-{}.pending", binding.manifest_sha256));
    fs::create_dir(&pending).map_err(|e| {
        format!("model import is interrupted or cannot begin; preserve staging: {e}")
    })?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o700))?;
    File::open(&root)?.sync_all()?;
    for name in ["manifest.json", "manifest.sig"] {
        copy(
            &source.join(name),
            &pending.join(name),
            if name == "manifest.sig" {
                64
            } else {
                model_trust::MAX_TRUST as u64
            },
            check,
        )?;
    }
    for b in &manifest.blobs {
        let from = if b.role == "model" {
            weight.to_path_buf()
        } else {
            source.join(&b.path)
        };
        let to = pending.join(&b.path);
        safe_dir(to.parent().ok_or("blob has no parent")?)?;
        copy(&from, &to, b.size_bytes, check)?;
        hash_member(&to, b.size_bytes, &b.sha256, check)?;
    }
    verify_pack(&pending, &manifest, check)?;
    let witness = physical_witness(&pending, weight)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&root)?;
    let root_pin = identity(&directory.metadata()?);
    check()?;
    if physical_witness(&pending, weight)? != witness
        || identity(&directory.metadata()?) != root_pin
        || identity(&fs::symlink_metadata(&root)?) != root_pin
    {
        return Err("model pack namespace changed during final import authorization; preserve pending bytes".into());
    }
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(
        pending
            .file_name()
            .ok_or("pending model name missing")?
            .as_bytes(),
    )?;
    let to = std::ffi::CString::new(binding.manifest_sha256.as_bytes())?;
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}
/// Metadata-only disposition review of interrupted, unverified bytes. This is
/// not a byte verification, a pack admission, or permission to resume copying.
pub(super) fn pending_review(p: &Profile) -> Result<(String, u64, PathBuf)> {
    let binding = p
        .governed
        .as_ref()
        .ok_or("pending governed pack disposition requires exact signed public profile")?;
    let manifest = public_manifest(&binding.manifest_sha256)?;
    let root = Path::new(VAR).join(STATE).join("model-packs");
    let pending = root.join(format!(".import-{}.pending", binding.manifest_sha256));
    let names = expected(&manifest, false);
    let bounds = manifest
        .blobs
        .iter()
        .map(|blob| (blob.path.clone(), blob.size_bytes))
        .chain([
            ("manifest.json".into(), model_trust::MAX_TRUST as u64),
            ("manifest.sig".into(), 64),
        ])
        .collect::<std::collections::BTreeMap<_, _>>();
    fn visit(
        at: &Path,
        root: &Path,
        expected: &BTreeSet<String>,
        bounds: &std::collections::BTreeMap<String, u64>,
        out: &mut Vec<(String, (u64, u64, u64, i64, i64, i64, i64), u32)>,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(at)?;
        let name = at
            .strip_prefix(root)?
            .to_str()
            .ok_or("pending pack path encoding invalid")?
            .to_owned();
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.file_type().is_symlink()
            || out.len() > 512
        {
            return Err("unsafe or oversized interrupted model inventory".into());
        }
        if metadata.is_dir() {
            if !name.is_empty()
                && !expected
                    .iter()
                    .any(|member| member.starts_with(&format!("{name}/")))
            {
                return Err("interrupted model pack contains undeclared directory".into());
            }
            out.push((name, identity(&metadata), metadata.mode()));
            for entry in fs::read_dir(at)? {
                visit(&entry?.path(), root, expected, bounds, out)?;
            }
        } else {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || !expected.contains(&name)
                || metadata.len()
                    > *bounds
                        .get(&name)
                        .ok_or("interrupted pack member lacks declared bound")?
            {
                return Err(
                    "interrupted model pack contains special, linked, undeclared or oversized data"
                        .into(),
                );
            }
            let held = regular(at)?;
            if identity(&metadata) != identity(&held.metadata()?) {
                return Err("pending model member changed during review".into());
            }
            out.push((name, identity(&metadata), metadata.mode()));
        }
        Ok(())
    }
    let mut witness = Vec::new();
    visit(&pending, &pending, &names, &bounds, &mut witness)?;
    witness.sort_by(|a, b| a.0.cmp(&b.0));
    let bytes = serde_json::to_vec(&(
        "luma-native-unverified-model-pending-retention-v1",
        &binding,
        p.resource_binding()?,
        crate::resource_manager::storage_device(Path::new(VAR))?,
        witness,
    ))?;
    if bytes.len() > 65536 {
        return Err("interrupted model metadata review exceeds bound".into());
    }
    Ok((
        bundle::hex(&Sha256::digest(&bytes)),
        bytes.len() as u64,
        pending,
    ))
}
pub(super) fn retain_pending(
    p: &Profile,
    review: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (current, _, pending) = pending_review(p)?;
    if current != review {
        return Err("interrupted pack changed after reviewed disposition".into());
    }
    let root = pending.parent().ok_or("pending model parent missing")?;
    let binding = p
        .governed
        .as_ref()
        .ok_or("governed pending model binding missing")?;
    let retained_name = format!(".retained-{}-{review}", binding.manifest_sha256);
    let mut count = 0usize;
    let mut total = 0u64;
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        if index >= 256 {
            return Err("model pack namespace capacity exceeded; preserve pending bytes".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or("model retention namespace encoding invalid")?;
        if let Some(rest) = name.strip_prefix(".retained-") {
            let (manifest, disposition) = rest
                .split_once('-')
                .ok_or("retained model pack name malformed")?;
            if !crate::artifacts::hash(manifest) || !crate::artifacts::hash(disposition) {
                return Err("retained model pack identity malformed".into());
            }
            count += 1;
            let members = inventory(&entry.path())?;
            if members.len() > 512 || members.iter().any(|name| name.len() > 512) {
                return Err("retained model metadata inventory exceeds disposition bound".into());
            }
            for member in members {
                total = total
                    .checked_add(regular(&entry.path().join(member))?.metadata()?.len())
                    .ok_or("model retention byte accounting overflow")?;
            }
        }
    }
    for member in inventory(&pending)? {
        total = total
            .checked_add(regular(&pending.join(member))?.metadata()?.len())
            .ok_or("pending retention byte overflow")?;
    }
    if count >= 16 || total > 64 * 1024 * 1024 * 1024 {
        return Err(
            "unverified model retention capacity exceeded; pending bytes remain preserved".into(),
        );
    }
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(
        pending
            .file_name()
            .ok_or("pending component missing")?
            .as_bytes(),
    )?;
    let to = std::ffi::CString::new(retained_name)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let root_identity = identity(&directory.metadata()?);
    check()?;
    if pending_review(p)?.0 != review
        || identity(&directory.metadata()?) != root_identity
        || identity(&fs::symlink_metadata(root)?) != root_identity
    {
        return Err("interrupted model namespace changed during finite authorization".into());
    }
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}
fn copy(
    from: &Path,
    to: &Path,
    maximum: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut input = regular(from)?;
    let before = input.metadata()?;
    if before.len() > maximum {
        return Err("model pack copy exceeds declared size".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(to)?;
    let mut buffer = [0u8; 1024 * 1024];
    let mut copied = 0u64;
    loop {
        check()?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        copied = copied
            .checked_add(n as u64)
            .ok_or("model pack copy overflow")?;
        if copied > maximum {
            return Err("model pack source grew".into());
        }
        output.write_all(&buffer[..n])?;
    }
    if copied != before.len() || identity(&before) != identity(&input.metadata()?) {
        return Err("model pack source changed during import".into());
    }
    output.sync_all()?;
    File::open(to.parent().ok_or("model file has no parent")?)?.sync_all()?;
    Ok(())
}
/// An in-process physical proof retains the exact hashed descriptors. It has
/// no serialized representation and supplies no signature, UTC or grant proof.
struct RetainedPack {
    members: Vec<(PathBuf, File, (u64, u64, u64, i64, i64, i64, i64))>,
    directories: Vec<(PathBuf, File, (u64, u64, u64, i64, i64, i64, i64))>,
}
impl RetainedPack {
    fn recheck(&self) -> Result<()> {
        for (path, file, pin) in &self.directories {
            if identity(&file.metadata()?) != *pin || identity(&fs::symlink_metadata(path)?) != *pin
            {
                return Err("retained model pack directory namespace changed".into());
            }
        }
        for (path, file, pin) in &self.members {
            let m = file.metadata()?;
            let current = regular(path)?.metadata()?;
            if identity(&m) != *pin || identity(&current) != *pin {
                return Err("retained model bytes changed; refuse automatic proof renewal".into());
            }
        }
        Ok(())
    }
}
static PROOFS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, RetainedPack>>,
> = std::sync::OnceLock::new();
static BACKGROUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn retained_pack(
    root: &Path,
    manifest: &PackManifest,
    allow_hash: bool,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let proofs = PROOFS
        .get_or_init(Default::default)
        .try_lock()
        .map_err(|_| "physical model proof cache busy or unavailable")?;
    let digest = manifest.digest()?;
    if inventory(root)? != expected(manifest, false) {
        return Err("retained model pack inventory changed".into());
    }
    if let Some(proof) = proofs.get(&digest) {
        if read(&root.join("manifest.json"), model_trust::MAX_TRUST as u64)?
            != model_trust::canonical(manifest)?
        {
            return Err("retained installed model manifest changed".into());
        }
        proof.recheck()?;
        return check();
    }
    if !allow_hash {
        return Err("model bytes are not yet independently prewarmed; retry after physical verification completes".into());
    }
    if proofs.len() >= 16
        || proofs
            .values()
            .map(|p| p.members.len() + p.directories.len())
            .sum::<usize>()
            + manifest.blobs.len()
            > 512
    {
        return Err("retained physical model proof descriptor budget is full".into());
    }
    if read(&root.join("manifest.json"), model_trust::MAX_TRUST as u64)?
        != model_trust::canonical(manifest)?
    {
        return Err("installed pack manifest changed".into());
    }
    drop(proofs);
    let mut members = Vec::new();
    for blob in &manifest.blobs {
        let path = root.join(&blob.path);
        let file = hash_member(&path, blob.size_bytes, &blob.sha256, check)?;
        let pin = identity(&file.metadata()?);
        members.push((path, file, pin));
    }
    let weights = manifest
        .blobs
        .iter()
        .find(|blob| blob.role == "model")
        .ok_or("native pack model missing")?;
    let profile = legacy_catalog()?
        .models
        .into_iter()
        .find(|profile| profile.sha256 == weights.sha256 && profile.bytes == weights.size_bytes)
        .ok_or("runtime cache lacks exact compiled model tuple")?;
    let cached = Path::new(VAR)
        .join(STATE)
        .join("models")
        .join(format!("{}.gguf", profile.id));
    let file = hash_member(&cached, weights.size_bytes, &weights.sha256, check)?;
    let pin = identity(&file.metadata()?);
    members.push((cached, file, pin));
    let mut paths = BTreeSet::from([root.to_path_buf()]);
    for b in &manifest.blobs {
        let mut parent = root
            .join(&b.path)
            .parent()
            .ok_or("blob parent missing")?
            .to_path_buf();
        while parent != root {
            paths.insert(parent.clone());
            parent = parent
                .parent()
                .ok_or("blob escapes pack namespace")?
                .to_path_buf();
        }
    }
    let mut directories = Vec::new();
    for path in paths {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let pin = identity(&file.metadata()?);
        directories.push((path, file, pin));
    }
    let proof = RetainedPack {
        members,
        directories,
    };
    verify_sidecars(root, manifest, check)?;
    proof.recheck()?;
    check()?;
    let mut proofs = PROOFS
        .get_or_init(Default::default)
        .try_lock()
        .map_err(|_| "physical model proof publication busy; no authority was published")?;
    if proofs.len() >= 16
        || proofs
            .values()
            .map(|p| p.members.len() + p.directories.len())
            .sum::<usize>()
            + proof.members.len()
            + proof.directories.len()
            > 512
    {
        return Err("physical proof descriptor budget changed before publication".into());
    }
    if proofs.contains_key(&digest) {
        return Err("physical proof changed concurrently; retry current exact proof".into());
    }
    proofs.insert(digest, proof);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn native_fixture() -> (ModelProfile, PackManifest) {
        use model_trust::{
            Blob, Context, InstallationProfile, License, ModelIdentity, Reservation,
        };
        let n = legacy_catalog().unwrap().models.remove(0);
        let tuple = RuntimeTuple {
            os_family: "Linux".into(),
            architecture: "amd64".into(),
            backend: "llama.cpp".into(),
            backend_version: "b11100".into(),
            device: "cpu".into(),
        };
        let tuple_sha = tuple.digest().unwrap();
        let auxiliary = |role: &str, digit: &str| Blob {
            role: role.into(),
            path: if role == "license" {
                format!("licenses/{}.txt", digit.repeat(64))
            } else {
                format!("blobs/sha256/{}", digit.repeat(64))
            },
            sha256: digit.repeat(64),
            size_bytes: 32,
            shard_index: None,
        };
        let manifest = PackManifest {
            schema_version: 2,
            canonicalization: "RFC8785-ASCII-v1".into(),
            signature_algorithm: "Ed25519".into(),
            pack_id: n.id.clone(),
            pack_version: "1.0.0".into(),
            model: ModelIdentity {
                architecture: "qwen3".into(),
                identity: "Qwen/Qwen3".into(),
                parameter_class: "4B".into(),
                total_parameters: n.parameters,
                active_parameters_min: n.active_parameters,
                active_parameters_max: n.active_parameters,
                quantization: "Q4_K_M".into(),
                required_features: vec!["chat-completion".into(), "text-generation".into()],
                source: n.url.clone(),
            },
            context: Context {
                maximum_tokens: u64::from(n.context_tokens),
                template_sha256: "b".repeat(64),
            },
            blobs: vec![
                Blob {
                    role: "model".into(),
                    path: format!("blobs/sha256/{}", n.sha256),
                    sha256: n.sha256.clone(),
                    size_bytes: n.bytes,
                    shard_index: Some(0),
                },
                auxiliary("tokenizer", "a"),
                auxiliary("template", "b"),
                auxiliary("license", "c"),
            ],
            runtime_tuples: vec![tuple],
            installation_profiles: vec![InstallationProfile {
                profile_id: n.id.clone(),
                runtime_tuple_sha256: tuple_sha.clone(),
                execution_mode: "cpu".into(),
                minimum_host_ram_bytes: n.minimum_ram_bytes,
                minimum_accelerator_memory_bytes: 0,
                minimum_model_storage_bytes: n.bytes + 96,
                maximum_context_tokens: u64::from(n.context_tokens),
            }],
            license: License {
                identifier: n.license.clone(),
                evaluation: "approved".into(),
                redistribution: "approved".into(),
                files: vec![format!("licenses/{}.txt", "c".repeat(64))],
            },
            network_default: "deny".into(),
            signer_key_id: "PackSigner".into(),
        };
        manifest.validate().unwrap();
        let p = ModelProfile {
            kind: "model".into(),
            profile_id: n.id,
            parameter_total: n.parameters,
            parameter_active_min: n.active_parameters,
            parameter_active_max: n.active_parameters,
            model_pack_manifest_sha256: manifest.digest().unwrap(),
            runtime_tuple_sha256: tuple_sha,
            install_bytes: n.bytes + 96,
            storage_peak_bytes: 2 * n.bytes + 96 + RESERVE,
            minimum_host_ram_bytes: n.minimum_ram_bytes,
            minimum_accelerator_memory_bytes: 0,
            load_reservations: vec![Reservation {
                domain: "host".into(),
                bytes: n.memory_max_bytes,
            }],
            serve_reservations: vec![Reservation {
                domain: "host".into(),
                bytes: n.memory_max_bytes,
            }],
            context_tokens: u64::from(n.context_tokens),
            execution_mode: "cpu".into(),
            availability: "available".into(),
            verification_state: "verified".into(),
            development_state: "development-tested".into(),
            certification_state: "not-certified".into(),
            remote_fallback: false,
        };
        (p, manifest)
    }
    #[test]
    fn native_adapter_accepts_only_exact_pinned_cpu_gguf_resources_and_frozen_host_domain() {
        let (profile, manifest) = native_fixture();
        let native = native_profile(&profile, &manifest, &"d".repeat(64)).unwrap();
        assert_eq!(
            native.governed.as_ref().unwrap().manifest_sha256,
            manifest.digest().unwrap()
        );
        for case in 0..7 {
            let mut altered = profile.clone();
            match case {
                0 => altered.load_reservations[0].domain = "host-memory".into(),
                1 => altered.load_reservations[0].bytes = 1,
                2 => altered.execution_mode = "cuda".into(),
                3 => altered.context_tokens += 1,
                4 => altered.storage_peak_bytes = altered.install_bytes,
                5 => altered.remote_fallback = true,
                _ => altered.runtime_tuple_sha256 = "e".repeat(64),
            };
            assert!(native_profile(&altered, &manifest, &"d".repeat(64)).is_err());
        }
        let mut foreign = manifest.clone();
        foreign.runtime_tuples[0].architecture = "x86_64".into();
        assert!(native_profile(&profile, &foreign, &"d".repeat(64)).is_err());
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            crate::require_root().unwrap();
            let root = Path::new("/run").join(format!(
                "luma-model-proof-test-{}",
                crate::resources::random_id().unwrap()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn proof(&self) -> RetainedPack {
            let path = self.0.join("weight");
            fs::write(&path, b"exact-model-bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            let file = regular(&path).unwrap();
            let pin = identity(&file.metadata().unwrap());
            let directory = File::open(&self.0).unwrap();
            let directory_pin = identity(&directory.metadata().unwrap());
            RetainedPack {
                members: vec![(path, file, pin)],
                directories: vec![(self.0.clone(), directory, directory_pin)],
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn canonical_pack_inventory_refuses_empty_directories_and_special_members() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("manifest.json"), b"{}").unwrap();
        assert_eq!(
            inventory(&fixture.0).unwrap(),
            BTreeSet::from(["manifest.json".into()])
        );
        fs::create_dir(fixture.0.join("undeclared-empty")).unwrap();
        assert!(inventory(&fixture.0).is_err());
        fs::remove_dir(fixture.0.join("undeclared-empty")).unwrap();
        std::os::unix::fs::symlink("/dev/null", fixture.0.join("special")).unwrap();
        assert!(inventory(&fixture.0).is_err());
    }
    #[test]
    fn prewarm_retries_exact_new_cache_namespace_without_renewing_authority() {
        let pack = Fixture::new();
        fs::write(pack.0.join("manifest.json"), b"{}").unwrap();
        let cache = Fixture::new();
        let file = cache.0.join("compiled.gguf");
        let absent = physical_witness(&pack.0, &file).unwrap();
        fs::write(&file, b"cache-bytes").unwrap();
        let appeared = physical_witness(&pack.0, &file).unwrap();
        assert_ne!(absent, appeared);
        assert_eq!(appeared, physical_witness(&pack.0, &file).unwrap());
        fs::write(&file, b"other-bytes").unwrap();
        assert_ne!(appeared, physical_witness(&pack.0, &file).unwrap());
    }
    #[test]
    fn retained_byte_proof_refuses_namespace_and_file_replacement() {
        let fixture = Fixture::new();
        let proof = fixture.proof();
        proof.recheck().unwrap();
        let path = fixture.0.join("weight");
        fs::rename(&path, fixture.0.join("retained-old")).unwrap();
        fs::write(&path, b"exact-model-bytes").unwrap();
        assert!(proof.recheck().is_err());
    }
    #[test]
    fn retained_byte_proof_refuses_content_change_even_when_mtime_restored() {
        let fixture = Fixture::new();
        let proof = fixture.proof();
        let (path, file, pin) = &proof.members[0];
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(path, b"alter-model-bytes").unwrap();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: pin.3,
                tv_nsec: pin.4,
            },
        ];
        assert_eq!(
            unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
            0
        );
        assert!(proof.recheck().is_err());
    }
    #[test]
    fn retained_byte_proof_refuses_new_hardlinks_and_substituted_directory() {
        let fixture = Fixture::new();
        let proof = fixture.proof();
        fs::hard_link(fixture.0.join("weight"), fixture.0.join("alias")).unwrap();
        assert!(proof.recheck().is_err());
        let fixture = Fixture::new();
        let proof = fixture.proof();
        let displaced = fixture.0.with_extension("displaced");
        fs::rename(&fixture.0, &displaced).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        assert!(proof.recheck().is_err());
        fs::remove_dir_all(displaced).unwrap();
    }
}
pub(crate) fn verify_catalog_packs(
    catalog: &ModelCatalog,
    trust: &SignedTrust,
    interval: Interval,
) -> Result<Vec<PackVerification>> {
    let mut result = Vec::new();
    let digest = catalog.digest()?;
    for profile in &catalog.profiles {
        if let SelectableProfile::Model(p) = profile {
            let manifest = public_manifest(&p.model_pack_manifest_sha256)?;
            let native = native_profile(p, &manifest, &digest)?;
            if p.availability != "available" {
                continue;
            }
            let root = Path::new(VAR)
                .join(STATE)
                .join("model-packs")
                .join(&p.model_pack_manifest_sha256);
            manifest.check_signature(trust, &read(&root.join("manifest.sig"), 64)?, interval)?;
            retained_pack(
                &root,
                &manifest,
                !BACKGROUND.load(std::sync::atomic::Ordering::Acquire),
                &mut || Ok(()),
            )?;
            let tuple = manifest
                .runtime_tuples
                .iter()
                .find(|t| {
                    t.digest().ok().as_deref()
                        == Some(
                            native
                                .governed
                                .as_ref()
                                .unwrap()
                                .runtime_tuple_sha256
                                .as_str(),
                        )
                })
                .ok_or("exact native tuple missing")?
                .clone();
            let mut verification = PackVerification {
                manifest_sha256: manifest.digest()?,
                runtime_tuple: tuple,
                state: 2,
                evidence_sha256: None,
                signing_keys: vec![(manifest.signer_key_id.clone(), "model-pack-manifest".into())],
                qualifications: vec![],
            };
            let production = trust.bundle.environment == "production";
            let certification = Path::new(if production {
                "/var/lib/luma-os/model-qualifications"
            } else {
                "/usr/share/luma-os/model-certifications"
            })
            .join(&p.model_pack_manifest_sha256);
            let required = match p.certification_state.as_str() {
                "execution-certified" => 3,
                "interactive-certified" => 4,
                _ => 2,
            };
            for (level, state) in [("execution", 3), ("interactive", 4)] {
                if required < state {
                    break;
                }
                if production {
                    let package = crate::model_qualification::Package::parse(&read(
                        &certification.join(format!("{level}.qualification.json")),
                        96 * 1024,
                    )?)?;
                    verification = package.record.apply(
                        &verification,
                        trust,
                        &package.signature()?,
                        interval,
                    )?;
                    verification.qualifications.push(package.evidence);
                    continue;
                }
                let record = model_trust::parse::<model_trust::CertificationRecord>(
                    &read(&certification.join(format!("{level}.json")), 4096)?,
                    4096,
                )?;
                verification = record.apply(
                    &verification,
                    trust,
                    &read(&certification.join(format!("{level}.sig")), 64)?,
                    interval,
                )?;
            }
            let mut allowed = BTreeSet::new();
            for level in ["execution", "interactive"] {
                if production {
                    allowed.insert(format!("{level}.qualification.json"));
                } else {
                    allowed.extend([format!("{level}.json"), format!("{level}.sig")]);
                }
            }
            if required >= 3 && !inventory(&certification)?.is_subset(&allowed) {
                return Err("model certification namespace contains undeclared records".into());
            }
            result.push(verification);
        }
    }
    Ok(result)
}

pub(crate) struct PackVerifier {
    stop: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for PackVerifier {
    fn drop(&mut self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        if let Ok(mut stop) = self.stop.0.lock() {
            *stop = true;
            self.stop.1.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
/// Broker-only background byte proof. It never opens TPM, Admin authority,
/// credentials, clocks or grants and cannot admit a model or start a process.
pub(crate) fn start_pack_verifier() -> Result<PackVerifier> {
    crate::require_root()?;
    if BACKGROUND.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Err("physical verifier already started in this process".into());
    }
    let stop = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wait = stop.clone();
    let cancel = cancelled.clone();
    let thread = std::thread::Builder::new()
        .name("model-byte-proof".into())
        .spawn(move || {
            let mut attempted = std::collections::BTreeMap::new();
            while !cancel.load(std::sync::atomic::Ordering::Acquire) {
                if let Ok(Some(profiles)) = public_native_profiles() {
                    for profile in profiles {
                        if cancel.load(std::sync::atomic::Ordering::Acquire) {
                            break;
                        }
                        let Some(binding) = &profile.governed else {
                            continue;
                        };
                        let Ok(manifest) = public_manifest(&binding.manifest_sha256) else {
                            continue;
                        };
                        let root = Path::new(VAR)
                            .join(STATE)
                            .join("model-packs")
                            .join(&binding.manifest_sha256);
                        let cached = Path::new(VAR)
                            .join(STATE)
                            .join("models")
                            .join(format!("{}.gguf", profile.id));
                        let Ok(witness) = physical_witness(&root, &cached) else {
                            continue;
                        };
                        if attempted.get(&binding.manifest_sha256) == Some(&witness) {
                            continue;
                        }
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(3600);
                        let outcome = retained_pack(&root, &manifest, true, &mut || {
                            if cancel.load(std::sync::atomic::Ordering::Acquire)
                                || std::time::Instant::now() >= deadline
                            {
                                Err("physical model verification cancelled or timed out".into())
                            } else {
                                Ok(())
                            }
                        });
                        // Damage is not busy-looped into an automatic repair or
                        // proof renewal. A newly published physical namespace has
                        // a different witness and receives one bounded attempt.
                        let transient = outcome.as_ref().err().map_or(false, |error| {
                            let message = error.to_string();
                            message.contains("busy")
                                || message.contains("concurrently")
                                || message.contains("before publication")
                        });
                        if !transient
                            && (outcome.is_ok()
                                || !cancel.load(std::sync::atomic::Ordering::Acquire))
                        {
                            attempted.insert(binding.manifest_sha256.clone(), witness);
                        }
                    }
                }
                let Ok(guard) = wait.0.lock() else {
                    break;
                };
                if *guard {
                    break;
                }
                let Ok((guard, _)) = wait
                    .1
                    .wait_timeout(guard, std::time::Duration::from_secs(1))
                else {
                    break;
                };
                if *guard {
                    break;
                }
            }
        });
    match thread {
        Ok(thread) => Ok(PackVerifier {
            stop,
            cancelled,
            thread: Some(thread),
        }),
        Err(error) => {
            BACKGROUND.store(false, std::sync::atomic::Ordering::Release);
            Err(error.into())
        }
    }
}
fn physical_witness(root: &Path, cached: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(&identity(&fs::symlink_metadata(root)?))?);
    for name in inventory(root)? {
        hash.update(serde_json::to_vec(&(
            name.clone(),
            identity(&regular(&root.join(name))?.metadata()?),
        ))?);
    }
    match fs::symlink_metadata(cached) {
        Ok(_) => hash.update(serde_json::to_vec(&Some(identity(
            &regular(cached)?.metadata()?,
        )))?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hash.update(b"runtime-cache-absent")
        }
        Err(error) => return Err(error.into()),
    }
    Ok(bundle::hex(&hash.finalize()))
}

/// Preparation verifies manifest authority and all factory sidecars, but never
/// claims absent external weights are loadable or admits a serving catalog.
pub(crate) fn verify_public_preparation(
    p: &Profile,
    trust: &SignedTrust,
    interval: Interval,
) -> Result<PackVerification> {
    let binding = p
        .governed
        .as_ref()
        .ok_or("preparation requires exact governed public profile")?;
    if public_profile(&p.id)?.resource_binding()? != p.resource_binding()? {
        return Err("model preparation profile changed".into());
    }
    let manifest = public_manifest(&binding.manifest_sha256)?;
    let root = Path::new(PUBLIC).join(&binding.manifest_sha256);
    if inventory(&root)? != expected(&manifest, true) {
        return Err("public model preparation inventory changed".into());
    }
    manifest.check_signature(trust, &read(&root.join("manifest.sig"), 64)?, interval)?;
    for b in &manifest.blobs {
        if b.role != "model" {
            hash_member(&root.join(&b.path), b.size_bytes, &b.sha256, &mut || Ok(()))?;
        }
    }
    let tuple = manifest
        .runtime_tuples
        .iter()
        .find(|t| t.digest().ok().as_deref() == Some(binding.runtime_tuple_sha256.as_str()))
        .ok_or("preparation runtime tuple missing")?
        .clone();
    Ok(PackVerification {
        manifest_sha256: binding.manifest_sha256.clone(),
        runtime_tuple: tuple,
        state: 1,
        evidence_sha256: None,
        signing_keys: vec![(manifest.signer_key_id.clone(), "model-pack-manifest".into())],
        qualifications: vec![],
    })
}
