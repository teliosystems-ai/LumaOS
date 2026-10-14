//! Inert installer-only acquisition from the verified TARGET image.
//! Receipts describe bytes, never current UTC, certification or serving authority.
use super::*;
use crate::model_trust::{
    self, ModelCatalog, PackManifest, RootPolicy, SelectableProfile, SignedTrust,
};

const MEMORY: u64 = 512 * 1024 * 1024;
const MAX_REQUEST: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    profile: Profile,
    metadata_sha256: String,
    release_manifest_sha256: String,
    storage_peak_bytes: u64,
}
impl Plan {
    pub(crate) fn id(&self) -> &str {
        &self.profile.id
    }
}
fn read(at: &Path, bound: usize) -> Result<Vec<u8>> {
    crate::admin_credentials::public_input(at, bound as u64)
}
fn der(text: &str) -> Result<Vec<u8>> {
    let mut bytes = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    bytes.extend(model_trust::decode64::<32>(text)?);
    Ok(bytes)
}
fn provenance(
    policy: &RootPolicy,
    trust: &SignedTrust,
    manifest: &PackManifest,
    signature: &[u8],
    environment: &str,
) -> Result<()> {
    policy.validate()?;
    trust.validate()?;
    let bundle = &trust.bundle;
    let root = policy
        .roots
        .iter()
        .find(|root| {
            root.key_id == bundle.root_key_id
                && root.environment == environment
                && root.trust_domain == bundle.trust_domain
        })
        .ok_or("target model root identity mismatch")?;
    if root.revoked_at.is_some()
        || bundle.environment != environment
        || !policy
            .accepted_trust_policy_versions
            .contains(&bundle.policy_version)
        || bundle.not_before < root.not_before
        || bundle.not_after > root.not_after
    {
        return Err("target model root policy cannot authenticate inert provenance".into());
    }
    let root_der = der(&root.public_key)?;
    let roots = policy
        .roots
        .iter()
        .map(|root| der(&root.public_key))
        .collect::<Result<Vec<_>>>()?;
    if policy
        .separated_key_sha256
        .contains(&bundle::hex(&Sha256::digest(&root_der)))
    {
        return Err("target model root reuses another signing domain".into());
    }
    for key in &bundle.keys {
        let public = der(&key.public_key)?;
        if roots.contains(&public)
            || policy
                .separated_key_sha256
                .contains(&bundle::hex(&Sha256::digest(&public)))
        {
            return Err("target model leaf reuses another signing domain/root".into());
        }
    }
    crate::release_trust::verify_der(
        &root_der,
        &model_trust::canonical(bundle)?,
        &model_trust::decode64::<64>(&trust.signature)?,
    )?;
    let key = bundle
        .keys
        .iter()
        .find(|key| key.key_id == manifest.signer_key_id)
        .ok_or("target pack signer missing")?;
    let key_der = der(&key.public_key)?;
    if key.environment != environment
        || key.role != "model-pack-signer"
        || key.revoked_at.is_some()
        || !key
            .purposes
            .iter()
            .any(|purpose| purpose == "model-pack-manifest")
        || key_der == root_der
        || policy
            .separated_key_sha256
            .contains(&bundle::hex(&Sha256::digest(&key_der)))
    {
        return Err("target pack signer purpose/environment/separation mismatch".into());
    }
    crate::release_trust::verify_der(&key_der, &model_trust::canonical(manifest)?, signature)
}
fn expected_identity(manifest: &bundle::Manifest) -> serde_json::Value {
    serde_json::json!({"schema_version":1,"release":manifest.release,"sequence":manifest.sequence,
        "environment":manifest.environment,"architecture":manifest.architecture,"ubuntu":manifest.ubuntu,"edition":manifest.edition})
}
pub(crate) fn capture(root: &Path, release: &bundle::Manifest, id: &str) -> Result<Plan> {
    bundle::validate_manifest(release)?;
    let base = root.join("usr/share/luma-os");
    let identity = read(&base.join("release-identity.json"), 4096)?;
    let expected = expected_identity(release);
    // Assembly JSON whitespace is not authority; typed decoding rejects
    // duplicate and unknown members before comparing the complete identity.
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        schema_version: u32,
        release: String,
        sequence: u64,
        environment: String,
        architecture: String,
        ubuntu: String,
        edition: String,
    }
    let actual: Identity = serde_json::from_slice(&identity)?;
    if serde_json::to_value(actual)? != expected {
        return Err("target immutable release identity differs from verified bundle".into());
    }
    let catalog_at = base.join("models/catalog.json");
    let has_catalog = match fs::symlink_metadata(&catalog_at) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let mut metadata = Sha256::new();
    metadata.update((identity.len() as u64).to_be_bytes());
    metadata.update(&identity);
    let (profile, peak) = if has_catalog {
        let raw_catalog = read(&catalog_at, model_trust::MAX_CATALOG)?;
        let catalog = ModelCatalog::parse(&raw_catalog)?;
        let item = catalog
            .profiles
            .iter()
            .find_map(|item| match item {
                SelectableProfile::Model(p) if p.profile_id == id => Some(p),
                _ => None,
            })
            .ok_or("target catalog has no requested model profile")?;
        if item.availability != "available" {
            return Err("target model profile is unavailable".into());
        }
        let raw_policy = read(&base.join("model-roots.json"), model_trust::MAX_TRUST)?;
        let policy: RootPolicy = model_trust::parse(&raw_policy, model_trust::MAX_TRUST)?;
        let raw_trust = read(
            &base.join("models/initial-trust.json"),
            model_trust::MAX_TRUST,
        )?;
        let trust = SignedTrust::parse(&raw_trust)?;
        let pack = base
            .join("model-packs")
            .join(&item.model_pack_manifest_sha256);
        let raw_manifest = read(&pack.join("manifest.json"), model_trust::MAX_TRUST)?;
        let manifest = PackManifest::parse(&raw_manifest)?;
        let signature = read(&pack.join("manifest.sig"), 64)?;
        provenance(&policy, &trust, &manifest, &signature, &release.environment)?;
        for bytes in [
            &raw_catalog,
            &raw_policy,
            &raw_trust,
            &raw_manifest,
            &signature,
        ] {
            metadata.update((bytes.len() as u64).to_be_bytes());
            metadata.update(bytes);
        }
        (
            pack_store::native_profile(item, &manifest, &catalog.digest()?)?,
            item.storage_peak_bytes,
        )
    } else {
        if release.environment != "lab" {
            return Err(
                "production installer requires complete signed target model metadata".into(),
            );
        }
        for path in [
            base.join("model-roots.json"),
            base.join("models/initial-trust.json"),
        ] {
            match fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
                Ok(_) => {
                    return Err(
                        "damaged/enrolled target model metadata cannot downgrade to legacy LAB"
                            .into(),
                    )
                }
            }
        }
        let factory = read(&base.join("model-catalog.json"), CATALOG.len() + 1)?;
        if factory != CATALOG.as_bytes() {
            return Err("legacy LAB target catalog differs from compiled pinned adapter".into());
        }
        metadata.update((factory.len() as u64).to_be_bytes());
        metadata.update(factory);
        let profile = legacy_catalog()?
            .models
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or("unsupported target laboratory model")?;
        let peak = profile
            .bytes
            .checked_add(2 * 1024 * 1024 * 1024)
            .ok_or("installer storage bound overflow")?;
        (profile, peak)
    };
    Ok(Plan {
        profile,
        metadata_sha256: bundle::hex(&metadata.finalize()),
        release_manifest_sha256: model_trust::digest(release)?,
        storage_peak_bytes: peak,
    })
}
fn same_plan(actual: &Plan, expected: &Plan) -> Result<()> {
    if model_trust::canonical(actual)? != model_trust::canonical(expected)? {
        return Err("installer target model/release/runtime metadata changed".into());
    }
    Ok(())
}
pub(crate) fn check_target(root: &Path, release: &bundle::Manifest, expected: &Plan) -> Result<()> {
    same_plan(&capture(root, release, expected.id())?, expected)
}
fn resources(plan: &Plan, total: u64, available: u64, free: u64, cpus: usize) -> Result<()> {
    if total < plan.profile.minimum_ram_bytes
        || available < 2 * MEMORY
        || free < plan.storage_peak_bytes
        || cpus < 2
    {
        return Err("target model staging lacks required hardware, isolated memory headroom or storage peak; select manual-only or a smaller model".into());
    }
    Ok(())
}
pub(crate) fn select(
    root: &Path,
    release: &bundle::Manifest,
    requested: Option<&str>,
    total: u64,
    available: u64,
    free: u64,
) -> Result<Option<Plan>> {
    let id = match requested {
        Some("manual-only") => return Ok(None),
        Some(id) => id.to_string(),
        None => {
            println!("Inert model data staging: manual-only, qwen3-1-7b-q4-k-m, or qwen3-4b-q4-k-m. No model serving is enabled. Enter profile:");
            platform::console_line(false)?
        }
    };
    if id == "manual-only" {
        return Ok(None);
    }
    let plan = capture(root, release, &id)?;
    resources(
        &plan,
        total,
        available,
        free,
        std::thread::available_parallelism()?.get(),
    )?;
    Ok(Some(plan))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    schema_version: u32,
    parent: u32,
    parent_start: String,
    parent_command_sha256: String,
    request_nonce: String,
    root: platform::InstallerMountClaim,
    data: platform::InstallerMountClaim,
    release: bundle::Manifest,
    plan: Plan,
    installation_sha256: String,
    disk: crate::disk::Identity,
}
fn start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    if stat.len() > 4096 {
        return Err("oversized installer process observation".into());
    }
    let tail = stat
        .rsplit_once(')')
        .ok_or("invalid installer process stat")?
        .1;
    if matches!(tail.split_whitespace().next(), Some("Z" | "X" | "x")) {
        return Err("installer controller is no longer alive".into());
    }
    Ok(tail
        .split_whitespace()
        .nth(19)
        .ok_or("missing installer process start")?
        .into())
}
fn parent_command(pid: u32) -> Result<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    if raw.len() > 8192 {
        return Err("oversized installer command".into());
    }
    let words = raw
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let closed = words.len() == 4
        || words.len() == 6 && (words[4] == b"--model" || words[4] == b"--stage-model");
    if !closed
        || ![
            &b"/usr/libexec/luma-os/luma-platform"[..],
            &b"/usr/bin/luma-platform"[..],
            &b"luma-platform"[..],
        ]
        .contains(&words[0])
        || words[1] != b"install"
        || fs::metadata(format!("/proc/{pid}"))?.uid() != 0
        || fs::metadata(format!("/proc/{pid}/exe"))?.dev()
            != fs::metadata("/usr/libexec/luma-os/luma-platform")?.dev()
        || fs::metadata(format!("/proc/{pid}/exe"))?.ino()
            != fs::metadata("/usr/libexec/luma-os/luma-platform")?.ino()
    {
        return Err("staging requires the original fixed root installer process".into());
    }
    Ok(bundle::hex(&Sha256::digest(raw)))
}
fn job_check(job: &Job) -> Result<()> {
    if job.schema_version != 1
        || job.parent == 0
        || job.request_nonce.len() != 32
        || !job
            .request_nonce
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        || start(job.parent)? != job.parent_start
        || parent_command(job.parent)? != job.parent_command_sha256
    {
        return Err("installer staging original controller no longer matches".into());
    }
    if job.root.disk() != &job.disk
        || job.data.disk() != &job.disk
        || !crate::artifacts::hash(&job.installation_sha256)
    {
        return Err("installer root/data/installation target binding mismatch".into());
    }
    let command = fs::read(format!("/proc/{}/cmdline", job.parent))?;
    let words = command
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let selection = Path::new(std::str::from_utf8(
        words.get(2).ok_or("missing installer disk selector")?,
    )?);
    if selection.parent() != Some(Path::new("/dev/disk/by-id"))
        || fs::canonicalize(selection)? != Path::new(&job.disk.path)
    {
        return Err("installer original target selector differs from held job disk".into());
    }
    let lock_path = Path::new("/run/luma-disk-locks").join(job.disk.major_minor.replace(':', "-"));
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let lm = lock.metadata()?;
    if lm.uid() != 0 || lm.nlink() != 1 || lm.mode() & 0o077 != 0 {
        return Err("unsafe installer disk lock witness".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
    {
        return Err("original installer disk lock is not held".into());
    }
    let expected_device = fs::metadata(&job.disk.path)?.rdev();
    let handles =
        fs::read_dir(format!("/proc/{}/fd", job.parent))?.collect::<std::io::Result<Vec<_>>>()?;
    if handles.len() > 1024 {
        return Err("installer controller descriptor inventory exceeds bound".into());
    }
    let mut disk_held = false;
    let mut lock_held = false;
    for handle in handles {
        let observed = match fs::metadata(handle.path()) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        use std::os::unix::fs::FileTypeExt;
        disk_held |= observed.file_type().is_block_device() && observed.rdev() == expected_device;
        lock_held |= observed.dev() == lm.dev() && observed.ino() == lm.ino();
    }
    if !disk_held || !lock_held {
        return Err(
            "original installer no longer holds exact disk and operation lock descriptors".into(),
        );
    }
    job.root.recheck()?;
    job.data.recheck()?;
    if crate::principal::installation_at(
        &job.data.at().join(STATE).join("principals/registry.json"),
    )? != job.installation_sha256
    {
        return Err("installer target installation identity changed".into());
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    installation_sha256: String,
    plan: Plan,
    state: String,
    certified: bool,
    activated: bool,
    current_utc_authority: bool,
}
fn publish_once(at: &Path, bytes: &[u8]) -> Result<File> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(at.parent().ok_or("installer receipt parent")?)?.sync_all()?;
    Ok(file)
}
fn manual_only(var: &Path) -> Result<()> {
    let state = var.join(STATE);
    activation_absent(&state)?;
    for name in ["model-selection.json", "model-auth/api-key", REFERENCE_ENV] {
        match fs::symlink_metadata(state.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                return Err(
                    "inert installer staging refuses an active/configured model target".into(),
                )
            }
        };
    }
    Ok(())
}
pub(crate) fn run(
    root: &platform::InstallerMount,
    data: &platform::InstallerMount,
    disk: &crate::disk::Disk,
    release: &bundle::Manifest,
    plan: &Plan,
) -> Result<()> {
    crate::require_root()?;
    platform::require_live()?;
    manual_only(data.at())?;
    let domain = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/luma-installer-model-stage.lock")?;
    let dm = domain.metadata()?;
    if dm.uid() != 0
        || dm.nlink() != 1
        || dm.mode() & 0o7777 != 0o600
        || unsafe { libc::flock(domain.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("another installer staging owner or unsafe fixed-domain lock".into());
    }
    let group =
        Path::new("/sys/fs/cgroup/lumainstallerstage.slice/luma-installer-model-stage.service");
    match fs::symlink_metadata(group) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => return Err(
            "existing installer staging cgroup must be independently drained before another job"
                .into(),
        ),
    };
    same_plan(&capture(root.at(), release, plan.id())?, plan)?;
    let info = fs::read_to_string("/proc/meminfo")?;
    resources(
        plan,
        memory(&info, "MemTotal")?,
        memory(&info, "MemAvailable")?,
        available_space(data.at())?,
        std::thread::available_parallelism()?.get(),
    )?;
    let pending = data.at().join(STATE).join("installer-model-staging");
    safe_dir(&pending)?;
    for name in ["models", "model-packs"] {
        safe_dir(&data.at().join(STATE).join(name))?;
    }
    let operation = operation_lock(data.at())?;
    drop(operation);
    let mut nonce = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let nonce = bundle::hex(&nonce);
    let job_at = root
        .at()
        .parent()
        .ok_or("installer staging root parent")?
        .join(format!("model-{nonce}.json"));
    let parent = std::process::id();
    let job = Job {
        schema_version: 1,
        parent,
        parent_start: start(parent)?,
        parent_command_sha256: parent_command(parent)?,
        request_nonce: nonce.clone(),
        root: root.claim(),
        data: data.claim(),
        release: release.clone(),
        plan: plan.clone(),
        installation_sha256: crate::principal::installation_at(
            &data.at().join(STATE).join("principals/registry.json"),
        )?,
        disk: disk.identity.clone(),
    };
    let mut request = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&job_at)?;
    let bytes = model_trust::canonical(&job)?;
    if bytes.len() > MAX_REQUEST {
        return Err("installer model request exceeds bound".into());
    }
    request.write_all(&bytes)?;
    request.sync_all()?;
    if unsafe { libc::flock(request.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("cannot hold installer job lock".into());
    }
    let receipt_at = pending.join(format!("{}-{nonce}.json", plan.id()));
    let receipt = |state: &str| Receipt {
        schema_version: 1,
        installation_sha256: job.installation_sha256.clone(),
        plan: plan.clone(),
        state: state.into(),
        certified: false,
        activated: false,
        current_utc_authority: false,
    };
    let pending_bytes = model_trust::canonical(&receipt("pending-uncertified"))?;
    let pending_descriptor = publish_once(&receipt_at, &pending_bytes)?;
    let args = crate::acquisition::installer_staging_arguments(
        root.at(),
        data.at(),
        &job_at,
        &bundle::hex(&Sha256::digest(&bytes)),
        plan.profile.bytes,
    )?;
    let mut process = Command::new("/usr/bin/systemd-run");
    process
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let result = supervise_owned_controller(&mut process, || {
        disk.recheck()?;
        root.recheck(&disk.identity)?;
        data.recheck(&disk.identity)?;
        job_check(&job)
    });
    // The owned unit must be physically empty before success or error escapes.
    let drained = crate::acquisition::installer_staging_drain();
    result?;
    drained?;
    disk.recheck()?;
    job_check(&job)?;
    same_plan(&capture(root.at(), release, plan.id())?, plan)?;
    let expected_result = model_trust::canonical(&receipt("verified-bytes-uncertified"))?;
    if read(&pending.join(format!("{nonce}.result")), MAX_REQUEST)? != expected_result {
        return Err("installer worker did not publish exact bound verified-byte result; preserve pending receipt".into());
    }
    let held = pending_descriptor.metadata()?;
    let named = fs::symlink_metadata(&receipt_at)?;
    if held.dev() != named.dev()
        || held.ino() != named.ino()
        || read(&receipt_at, MAX_REQUEST)? != pending_bytes
    {
        return Err("installer pending receipt changed; preserve uncertain state".into());
    }
    manual_only(data.at())?;
    platform::write_atomic(
        &receipt_at,
        &model_trust::canonical(&receipt("verified-bytes-uncertified"))?,
        0o600,
    )?;
    println!("{} bytes staged and verified. Manual mode remains selected; real Admin/TPM/UTC/model trust/catalog and machine QA qualification are still required before normal activation.", plan.id());
    Ok(())
}
pub(crate) fn worker(request_at: &Path, expected_sha256: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_live()?;
    if !crate::artifacts::hash(expected_sha256) {
        return Err("invalid installer request digest".into());
    }
    let parent = request_at.parent().ok_or("installer request parent")?;
    let name = parent
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("installer staging name")?;
    if parent.parent() != Some(Path::new("/var/lib/luma-os/staging"))
        || !name.strip_prefix("install-").is_some_and(|n| {
            n.len() == 32
                && n.bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        })
    {
        return Err("installer job outside exact private namespace".into());
    }
    let file = open_regular(request_at)?;
    let m = file.metadata()?;
    if m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o600 || m.len() > MAX_REQUEST as u64
    {
        return Err("unsafe installer request inode".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Err("installer request has no live controller lock".into());
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
        return Err("cannot observe installer controller lock".into());
    }
    let raw = read(request_at, MAX_REQUEST)?;
    if bundle::hex(&Sha256::digest(&raw)) != expected_sha256 {
        return Err("installer job digest changed".into());
    }
    let mut job: Job = model_trust::parse(&raw, MAX_REQUEST)?;
    if job.root.at() != parent.join("root")
        || job.data.at() != parent.join("data")
        || request_at != parent.join(format!("model-{}.json", job.request_nonce))
    {
        return Err("installer job target namespace mismatch".into());
    }
    job.root.enter_worker()?;
    job.data.enter_worker()?;
    if fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumainstallerstage.slice/luma-installer-model-stage.service\n"
        || fs::read_to_string("/proc/self/attr/current")?.trim()
            != "luma-installer-model-stage (enforce)"
    {
        return Err("installer staging worker confinement absent".into());
    }
    job_check(&job)?;
    manual_only(job.data.at())?;
    let plan = capture(job.root.at(), &job.release, job.plan.id())?;
    same_plan(&plan, &job.plan)?;
    let _operation = operation_lock(job.data.at())?;
    let models = job.data.at().join(STATE).join("models");
    safe_dir(&models)?;
    let weight = models.join(format!("{}.gguf", plan.id()));
    let started = crate::resource_manager::now()?;
    let mut last = 0;
    let mut check = || -> Result<()> {
        let current = crate::resource_manager::now()?;
        if current
            .checked_sub(started)
            .ok_or("installer monotonic clock regressed")?
            >= 3_700_000
        {
            return Err("installer staging deadline expired".into());
        }
        if current.checked_sub(last).unwrap_or(u64::MAX) >= 250 {
            job_check(&job)?;
            let memory_info = fs::read_to_string("/proc/meminfo")?;
            if memory(&memory_info, "MemAvailable")? < MEMORY {
                return Err("installer staging memory pressure".into());
            }
            let named = fs::symlink_metadata(request_at)?;
            if named.dev() != m.dev()
                || named.ino() != m.ino()
                || named.nlink() != 1
                || named.uid() != 0
                || named.mode() & 0o7777 != 0o600
                || read(request_at, MAX_REQUEST)? != raw
            {
                return Err("installer job changed during acquisition".into());
            }
            last = current;
        }
        Ok(())
    };
    check()?;
    match fs::symlink_metadata(&weight) {
        Ok(_) => {
            verified_runtime_file(&weight, &plan.profile, &mut check)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fetch(&weight, &plan.profile, &mut check)?
        }
        Err(e) => return Err(e.into()),
    }
    pack_store::import_pack_from(
        &job.root.at().join("usr/share/luma-os/model-packs"),
        job.data.at(),
        &plan.profile,
        &weight,
        &mut check,
    )?;
    let verified = verified_runtime_file(&weight, &plan.profile, &mut check)?;
    job_check(&job)?;
    same_plan(&capture(job.root.at(), &job.release, plan.id())?, &plan)?;
    manual_only(job.data.at())?;
    let held = verified.metadata()?;
    let named = fs::symlink_metadata(&weight)?;
    if held.dev() != named.dev()
        || held.ino() != named.ino()
        || held.len() != named.len()
        || held.ctime() != named.ctime()
        || held.ctime_nsec() != named.ctime_nsec()
        || named.nlink() != 1
        || named.mode() & 0o022 != 0
    {
        return Err("installer final weight namespace changed; preserve pending receipt".into());
    }
    let receipt = Receipt {
        schema_version: 1,
        installation_sha256: job.installation_sha256.clone(),
        plan: plan.clone(),
        state: "verified-bytes-uncertified".into(),
        certified: false,
        activated: false,
        current_utc_authority: false,
    };
    publish_once(
        &job.data
            .at()
            .join(STATE)
            .join("installer-model-staging")
            .join(format!("{}.result", job.request_nonce)),
        &model_trust::canonical(&receipt)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut random = [0u8; 16];
            File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let at = PathBuf::from(format!(
                "/tmp/luma-installer-staging-{}",
                bundle::hex(&random)
            ));
            fs::create_dir(&at).unwrap();
            fs::set_permissions(&at, fs::Permissions::from_mode(0o700)).unwrap();
            Self(at)
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            let at = self.0.join(name);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(&at, bytes).unwrap();
            fs::set_permissions(at, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn manifest() -> bundle::Manifest {
        let root_bytes = 1024 * 1024 * 1024;
        let hash_bytes = 16 * 1024 * 1024;
        bundle::Manifest {
            schema_version: 1,
            release: "installer-unit-fixture".into(),
            sequence: 1,
            environment: "lab".into(),
            architecture: "amd64".into(),
            ubuntu: "24.04".into(),
            edition: "headless".into(),
            root_hash: "1".repeat(64),
            root_bytes,
            hash_bytes,
            artifacts: [
                "root.ext4",
                "root.verity",
                "slot-a.efi",
                "slot-b.efi",
                "bootloader.efi",
                "secureboot.cer",
            ]
            .into_iter()
            .map(|name| bundle::Artifact {
                name: name.into(),
                bytes: match name {
                    "root.ext4" => root_bytes,
                    "root.verity" => hash_bytes,
                    _ => 4096,
                },
                sha256: "2".repeat(64),
            })
            .collect(),
        }
    }
    #[test]
    fn target_metadata_uses_exact_image_not_live_catalog_or_unknown_identity() {
        let fixture = Fixture::new();
        let release = manifest();
        fixture.write(
            "usr/share/luma-os/release-identity.json",
            &serde_json::to_vec_pretty(&expected_identity(&release)).unwrap(),
        );
        fixture.write("usr/share/luma-os/model-catalog.json", CATALOG.as_bytes());
        let id = legacy_catalog().unwrap().models[0].id.clone();
        let original = capture(&fixture.0, &release, &id).unwrap();
        check_target(&fixture.0, &release, &original).unwrap();
        let mut other = release.clone();
        other.release.push_str("-other");
        assert!(capture(&fixture.0, &other, &id).is_err());
        fixture.write(
            "usr/share/luma-os/model-catalog.json",
            b"{\"schema_version\":1}",
        );
        assert!(capture(&fixture.0, &release, &id).is_err());
        fixture.write("usr/share/luma-os/model-catalog.json", CATALOG.as_bytes());
        fixture.write("usr/share/luma-os/model-roots.json", b"{}");
        assert!(capture(&fixture.0, &release, &id).is_err());
        let mut production = release;
        production.environment = "production".into();
        fixture.write(
            "usr/share/luma-os/release-identity.json",
            &serde_json::to_vec(&expected_identity(&production)).unwrap(),
        );
        assert!(capture(&fixture.0, &production, &id).is_err());
    }
    #[test]
    fn corrupted_cached_bytes_or_lost_boundary_never_verify() {
        let fixture = Fixture::new();
        let bytes = b"bounded inert byte fixture";
        let mut profile = legacy_catalog().unwrap().models.remove(0);
        profile.bytes = bytes.len() as u64;
        profile.sha256 = bundle::hex(&Sha256::digest(bytes));
        fixture.write("weight", bytes);
        verified_file_checked(&fixture.0.join("weight"), &profile, || Ok(())).unwrap();
        assert!(
            verified_file_checked(&fixture.0.join("weight"), &profile, || Err(
                "fixture mount lost".into()
            ))
            .is_err()
        );
        fixture.write("weight", b"bounded inert byte fixturf");
        assert!(verified_file_checked(&fixture.0.join("weight"), &profile, || Ok(())).is_err());
    }
    #[test]
    fn interrupted_receipt_is_retained_and_cannot_be_overwritten_or_activated() {
        let fixture = Fixture::new();
        let at = fixture.0.join("pending.json");
        let bytes = b"pending-uncertified";
        let descriptor = publish_once(&at, bytes).unwrap();
        assert!(publish_once(&at, b"invented completion").is_err());
        assert_eq!(fs::read(&at).unwrap(), bytes);
        assert_eq!(descriptor.metadata().unwrap().mode() & 0o7777, 0o600);
        fixture.write("lib/luma-os/model-selection.json", b"{}");
        assert!(manual_only(&fixture.0).is_err());
    }
    #[test]
    fn inert_receipt_never_converts_to_activation_or_clock_authority() {
        let p = legacy_catalog().unwrap().models.remove(0);
        let plan = Plan {
            profile: p,
            metadata_sha256: "1".repeat(64),
            release_manifest_sha256: "2".repeat(64),
            storage_peak_bytes: 8 * 1024 * 1024 * 1024,
        };
        for state in ["pending-uncertified", "verified-bytes-uncertified"] {
            let r = Receipt {
                schema_version: 1,
                installation_sha256: "3".repeat(64),
                plan: plan.clone(),
                state: state.into(),
                certified: false,
                activated: false,
                current_utc_authority: false,
            };
            let json = serde_json::to_value(r).unwrap();
            assert_eq!(json["activated"], false);
            assert_eq!(json["certified"], false);
            assert_eq!(json["current_utc_authority"], false);
        }
    }
    #[test]
    fn every_exact_plan_binding_and_resource_floor_is_checked() {
        let p = legacy_catalog().unwrap().models.remove(0);
        let plan = Plan {
            profile: p,
            metadata_sha256: "1".repeat(64),
            release_manifest_sha256: "2".repeat(64),
            storage_peak_bytes: 8 * 1024 * 1024 * 1024,
        };
        same_plan(&plan, &plan).unwrap();
        for case in 0..5 {
            let mut other = plan.clone();
            match case {
                0 => other.metadata_sha256 = "4".repeat(64),
                1 => other.release_manifest_sha256 = "4".repeat(64),
                2 => other.profile.sha256 = "4".repeat(64),
                3 => other.profile.id.push('x'),
                _ => other.storage_peak_bytes += 1,
            };
            assert!(same_plan(&other, &plan).is_err());
        }
        resources(
            &plan,
            plan.profile.minimum_ram_bytes,
            2 * MEMORY,
            plan.storage_peak_bytes,
            2,
        )
        .unwrap();
        for case in 0..4 {
            let mut values = (
                plan.profile.minimum_ram_bytes,
                2 * MEMORY,
                plan.storage_peak_bytes,
                2,
            );
            match case {
                0 => values.0 -= 1,
                1 => values.1 -= 1,
                2 => values.2 -= 1,
                _ => values.3 -= 1,
            };
            assert!(resources(&plan, values.0, values.1, values.2, values.3).is_err());
        }
    }
    #[test]
    fn captured_jobs_reject_unknown_or_duplicate_fields() {
        assert!(model_trust::parse::<Job>(
            br#"{"schema_version":1,"schema_version":1}"#,
            MAX_REQUEST
        )
        .is_err());
        assert!(model_trust::parse::<Receipt>(
            br#"{"activated":true,"authority":true}"#,
            MAX_REQUEST
        )
        .is_err());
    }
}
