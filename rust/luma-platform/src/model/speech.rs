//! Separately typed ASR projection within the existing signed model trust.
//! Auxiliary profiles are not text/GGUF Profiles or persistent text selections.
use super::*;
use crate::model_trust::{self, ModelProfile, PackManifest, RuntimeTuple, SelectableProfile};

pub(crate) const ID: &str = "whisper-tiny-multilingual-f16-cpu-v1";
pub(crate) const ARCHITECTURE: &str = "whisper-tiny-multilingual";
pub(crate) const SOURCE_COMMIT: &str = "d1be6fde11ac6e0407606b4e42fe72d34add8037";
pub(crate) const WEIGHT_SHA256: &str =
    "be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21";
pub(crate) const WEIGHT_BYTES: u64 = 77_691_713;
pub(crate) const PARAMETERS: u64 = 37_760_640;
pub(crate) const MEMORY: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_VIRTUAL: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_AUDIO: usize = 960_000;
pub(crate) const MAX_TEXT: usize = 8192;
pub(crate) const MAX_TOKENS: u64 = 128;
const DECODER_CONTEXT: u64 = 448;
pub(crate) const IMAGE_WEIGHT: &str = "/usr/share/luma-os/speech/ggml-tiny.bin";
const LICENSE_SHA256: &str = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d";
const SOURCE: &str = "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-tiny.bin";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub id: String,
    pub binding: NativeBinding,
    pub memory_bytes: u64,
    pub storage_peak_bytes: u64,
}
impl Profile {
    pub(crate) fn resource_binding(&self) -> Result<String> {
        self.binding.validate()?;
        if self.id != ID || self.memory_bytes != MEMORY || self.storage_peak_bytes < WEIGHT_BYTES {
            return Err("ASR projection is not the closed auxiliary profile".into());
        }
        model_trust::digest(self)
    }
}
pub(crate) fn tuple() -> RuntimeTuple {
    RuntimeTuple {
        os_family: "Linux".into(),
        architecture: "amd64".into(),
        backend: "whisper.cpp".into(),
        backend_version: "v1.9.5-luma-asr-v1".into(),
        device: "cpu".into(),
    }
}
pub(crate) fn tokenizer() -> Result<Vec<u8>> {
    model_trust::canonical(
        &serde_json::json!({"kind":"embedded-whisper-multilingual-vocabulary-v1",
        "model_sha256":WEIGHT_SHA256,"offset":64376,"size_bytes":508089,
        "sha256":"358bdf83c2253dea0c8a1749f5288d96d2b6f5f4119faee9e5e26611a8c8f17b",
        "stored_tokens":50257,"runtime_vocabulary_size":51865,
        "generated_special_tokens_runtime_commit":SOURCE_COMMIT}),
    )
}
pub(crate) fn policy() -> Result<Vec<u8>> {
    model_trust::canonical(&serde_json::json!({"schema_version":1,"profile":ID,
        "runtime_source_commit":SOURCE_COMMIT,"input_encoding":"S16LE","channels":1,"sample_rate":16000,
        "maximum_seconds":30,"maximum_pcm_bytes":MAX_AUDIO,"translation":false,"language":"en",
        "maximum_decoder_tokens":MAX_TOKENS,"maximum_text_bytes":MAX_TEXT,"cpu_threads":2,
        "maximum_decode_seconds":18,"physical_memory_max_bytes":MEMORY,"maximum_virtual_address_bytes":MAX_VIRTUAL,
        "review_before_model_handoff":true,"automatic_model_handoff":false}))
}
pub(crate) fn matches(p: &ModelProfile, m: &PackManifest) -> bool {
    p.profile_id == ID || m.model.architecture == ARCHITECTURE
}
pub(crate) fn project(p: &ModelProfile, m: &PackManifest, catalog: &str) -> Result<Profile> {
    m.validate()?;
    let runtime = tuple();
    let tuple_sha = runtime.digest()?;
    let token = tokenizer()?;
    let decoding = policy()?;
    let sidecars = [
        ("tokenizer", token.as_slice()),
        ("template", decoding.as_slice()),
    ];
    let exact_sidecars = sidecars.iter().all(|(role, bytes)| {
        m.blobs.iter().filter(|b| b.role == *role).count() == 1
            && m.blobs.iter().find(|b| b.role == *role).is_some_and(|b| {
                b.size_bytes == bytes.len() as u64
                    && b.sha256 == bundle::hex(&Sha256::digest(bytes))
            })
    });
    let weights = m
        .blobs
        .iter()
        .filter(|b| b.role == "model")
        .collect::<Vec<_>>();
    let license = m.blobs.iter().find(|b| b.role == "license");
    let bytes = m.blobs.iter().try_fold(0u64, |sum, b| {
        sum.checked_add(b.size_bytes)
            .ok_or("ASR pack byte overflow")
    })?;
    let install = m.installation_profiles.iter().find(|i| i.profile_id == ID);
    let memory = |r: &[model_trust::Reservation]| {
        r.len() == 1 && r[0].domain == "host" && r[0].bytes == MEMORY
    };
    if !crate::artifacts::hash(catalog)
        || p.profile_id != ID
        || p.kind != "model"
        || p.execution_mode != "cpu"
        || p.runtime_tuple_sha256 != tuple_sha
        || m.runtime_tuples != [runtime]
        || m.installation_profiles.len() != 1
        || m.blobs.len() != 4
        || weights.len() != 1
        || weights[0].shard_index != Some(0)
        || weights[0].sha256 != WEIGHT_SHA256
        || weights[0].size_bytes != WEIGHT_BYTES
        || !exact_sidecars
        || license.map_or(true, |b| b.sha256 != LICENSE_SHA256 || b.size_bytes != 1063)
        || m.model.architecture != ARCHITECTURE
        || m.model.total_parameters != PARAMETERS
        || m.model.active_parameters_min != PARAMETERS
        || m.model.active_parameters_max != PARAMETERS
        || m.model.quantization != "mixed-F16-F32"
        || m.model.source != SOURCE
        || m.model.required_features
            != [
                "automatic-speech-recognition".to_string(),
                "offline".to_string(),
                "speech-transcription".to_string(),
            ]
        || m.context.maximum_tokens != DECODER_CONTEXT
        || m.license.identifier != "MIT"
        || m.license.evaluation != "approved"
        || m.license.redistribution != "approved"
        || p.parameter_total != PARAMETERS
        || p.parameter_active_min != PARAMETERS
        || p.parameter_active_max != PARAMETERS
        || p.model_pack_manifest_sha256 != m.digest()?
        || p.context_tokens != DECODER_CONTEXT
        || p.minimum_host_ram_bytes < 2 * 1024 * 1024 * 1024
        || p.minimum_accelerator_memory_bytes != 0
        || p.install_bytes != bytes
        || p.storage_peak_bytes
            < bytes
                .checked_add(256 * 1024 * 1024)
                .ok_or("ASR peak overflow")?
        || !memory(&p.load_reservations)
        || !memory(&p.serve_reservations)
        || p.remote_fallback
        || install.map_or(true, |i| {
            i.runtime_tuple_sha256 != tuple_sha
                || i.execution_mode != "cpu"
                || i.minimum_accelerator_memory_bytes != 0
                || i.minimum_host_ram_bytes > p.minimum_host_ram_bytes
                || i.minimum_model_storage_bytes > p.storage_peak_bytes
                || i.maximum_context_tokens != DECODER_CONTEXT
        })
    {
        return Err(
            "ASR catalog/pack differs from exact multilingual-tiny English-decoder auxiliary tuple"
                .into(),
        );
    }
    let result = Profile {
        id: ID.into(),
        memory_bytes: MEMORY,
        storage_peak_bytes: p.storage_peak_bytes,
        binding: NativeBinding {
            catalog_sha256: catalog.into(),
            profile_sha256: p.digest()?,
            manifest_sha256: m.digest()?,
            runtime_tuple_sha256: tuple_sha,
        },
    };
    result.resource_binding()?;
    Ok(result)
}
pub(crate) fn public_profile() -> Result<Profile> {
    let catalog = model_trust::ModelCatalog::parse(&pack_store::read(
        Path::new(pack_store::PUBLIC_CATALOG),
        model_trust::MAX_CATALOG as u64,
    )?)?;
    let p = catalog
        .profiles
        .iter()
        .find_map(|p| match p {
            SelectableProfile::Model(p) if p.profile_id == ID => Some(p),
            _ => None,
        })
        .ok_or("signed auxiliary speech profile absent from immutable catalog")?;
    project(
        p,
        &pack_store::public_manifest(&p.model_pack_manifest_sha256)?,
        &catalog.digest()?,
    )
}
pub(crate) fn preparation(
    profile: &Profile,
    trust: &model_trust::SignedTrust,
    interval: crate::utc_bounds::Interval,
) -> Result<model_trust::PackVerification> {
    if profile.resource_binding()? != public_profile()?.resource_binding()? {
        return Err("ASR preparation projection changed".into());
    }
    let manifest = pack_store::public_manifest(&profile.binding.manifest_sha256)?;
    let root = Path::new(VAR)
        .join(STATE)
        .join("model-packs")
        .join(&profile.binding.manifest_sha256);
    manifest.check_signature(
        trust,
        &pack_store::read(&root.join("manifest.sig"), 64)?,
        interval,
    )?;
    pack_store::retained_pack(&root, &manifest, true, &mut || Ok(()))?;
    Ok(model_trust::PackVerification {
        manifest_sha256: manifest.digest()?,
        runtime_tuple: tuple(),
        state: 2,
        evidence_sha256: None,
        signing_keys: vec![(manifest.signer_key_id, "model-pack-manifest".into())],
        qualifications: vec![],
    })
}
pub(crate) fn public_preparation(
    profile: &Profile,
    trust: &model_trust::SignedTrust,
    interval: crate::utc_bounds::Interval,
) -> Result<model_trust::PackVerification> {
    if profile.resource_binding()? != public_profile()?.resource_binding()? {
        return Err("auxiliary import projection changed".into());
    }
    pack_store::verify_public_binding_preparation(&profile.binding, trust, interval)
}
pub(crate) fn import_usage() -> Result<crate::finite_grants::Use> {
    let p = public_profile()?;
    let catalog = model_trust::ModelCatalog::parse(&pack_store::read(
        Path::new(pack_store::PUBLIC_CATALOG),
        model_trust::MAX_CATALOG as u64,
    )?)?;
    let item = catalog
        .profiles
        .iter()
        .find_map(|p| match p {
            SelectableProfile::Model(p) if p.profile_id == ID => Some(p),
            _ => None,
        })
        .ok_or("auxiliary import profile missing")?;
    let digest = model_trust::digest(&(
        "luma-auxiliary-asr-pack-import-v1",
        crate::artifacts::installation()?,
        p.resource_binding()?,
        crate::resource_manager::storage_device(Path::new(VAR))?,
        WEIGHT_SHA256,
        item.install_bytes,
        p.storage_peak_bytes,
    ))?;
    let usage = crate::finite_grants::Use {
        action: crate::finite_grants::Action::AcquireResource,
        selector: crate::finite_grants::Selector {
            kind: crate::finite_grants::Kind::Resource,
            id: format!("ModelPack-{ID}"),
            generation: 1,
            digest,
        },
        input_bytes: item.install_bytes,
        output_bytes: p.storage_peak_bytes,
        units: 1,
    };
    usage.validate()?;
    Ok(usage)
}
pub(crate) fn import_completion() -> Result<String> {
    model_trust::digest(&(
        "luma-auxiliary-asr-pack-prepared-v1",
        public_profile()?.resource_binding()?,
        WEIGHT_SHA256,
    ))
}
pub(crate) fn import_review() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    let p = public_profile()?;
    crate::admin_governance::speech_pack_preparation_authority(&p)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"profile":ID,"usage":import_usage()?,"binding":p.binding,
        "source":"immutable-image-auxiliary-weights","activates_model":false,"authority_returned":false})
    );
    Ok(())
}
pub(crate) fn import(login: &str, grant: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    crate::admin_governance::speech_pack_preparation_authority(&public_profile()?)?;
    let _lock = operation_lock(Path::new(VAR))?;
    let usage = import_usage()?;
    crate::admin_governance::with_model_import_grant(login, grant, ID, &usage, |boundary| {
        let effect = boundary.effect_begin(
            &usage.selector.digest,
            crate::policy_decisions::EffectKind::ResourceAdmission,
        )?;
        crate::service::granted_acquisition::run_speech_import(&usage, boundary)?;
        boundary.effect_complete(effect, &import_completion()?)
    })
}
pub(crate) fn import_controller(check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
    check()?;
    crate::acquisition::await_drainage_checked(&mut || check())?;
    let mut child = Command::new("/usr/bin/systemd-run");
    child
        .args(crate::acquisition::arguments(
            Path::new(VAR),
            ID,
            "speech-import",
        )?)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let until = crate::resource_manager::now()?
        .checked_add(40_000)
        .ok_or("ASR import controller deadline overflow")?;
    supervise_owned_controller(&mut child, || {
        check()?;
        if crate::resource_manager::now()? >= until {
            return Err("ASR image-byte import timed out; preserve pending data".into());
        }
        Ok(())
    })?;
    crate::acquisition::await_drainage_checked(&mut || check())?;
    check()
}
pub(crate) fn import_worker() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    if fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
    {
        return Err("ASR image import requires the fixed enforcing acquisition pool".into());
    }
    let lease = crate::resource_manager::WorkerLease::acquire_acquisition(ID, Path::new(VAR))?;
    lease.check()?;
    let p = public_profile()?;
    let weight = pack_store::hash_member(
        Path::new(IMAGE_WEIGHT),
        WEIGHT_BYTES,
        WEIGHT_SHA256,
        &mut || lease.check(),
    )?;
    let pin = pack_store::identity(&weight.metadata()?);
    if available_space(Path::new(VAR))? < p.storage_peak_bytes {
        return Err("ASR image import lacks signed storage peak".into());
    }
    pack_store::import_binding_from(
        Path::new(pack_store::PUBLIC),
        Path::new(VAR),
        &p.binding,
        Path::new(IMAGE_WEIGHT),
        &mut || lease.check(),
    )?;
    if pin != pack_store::identity(&weight.metadata()?)
        || pin != pack_store::identity(&pack_store::regular(Path::new(IMAGE_WEIGHT))?.metadata()?)
    {
        return Err("ASR immutable import source changed".into());
    }
    lease.check()?;
    lease.complete_output(&import_completion()?)?;
    lease.check_local()
}
pub(crate) fn check_import_worker(pid: u32) -> Result<()> {
    let expected =
        format!("/usr/libexec/luma-os/luma-platform\0speech-import-resource-worker\0{ID}\0");
    let file = File::open(format!("/proc/{pid}/cmdline"))?;
    let mut actual = Vec::new();
    file.take(4097).read_to_end(&mut actual)?;
    if actual != expected.as_bytes() {
        return Err("ASR import resource peer lacks fixed image-byte command".into());
    }
    Ok(())
}
pub(crate) fn pending_review() -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    let p = public_profile()?;
    crate::admin_governance::speech_pack_preparation_authority(&p)?;
    let _lock = operation_lock(Path::new(VAR))?;
    crate::acquisition::await_drainage()?;
    let (review, bytes, _) = pack_store::pending_review(&p)?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"profile":ID,"review":review,"usage":super::pending_usage(ID,&review,bytes)?,
        "byte_verified":false,"disposition":"retain-unverified","deletes_content":false})
    );
    Ok(())
}
pub(crate) fn pending_retain(login: &str, grant: &str, review: &str) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    let p = public_profile()?;
    crate::admin_governance::speech_pack_preparation_authority(&p)?;
    let _lock = operation_lock(Path::new(VAR))?;
    crate::acquisition::await_drainage()?;
    let (current, bytes, _) = pack_store::pending_review(&p)?;
    if current != review {
        return Err("ASR interrupted pack changed after review".into());
    }
    let usage = super::pending_usage(ID, review, bytes)?;
    crate::admin_governance::with_grant(login, grant, &usage, |guard| {
        let effect = guard.effect_begin(review, crate::policy_decisions::EffectKind::Retention)?;
        pack_store::retain_pending(&p, review, &mut || guard.check())?;
        guard.effect_complete(effect, review)
    })
}
pub(crate) fn open_weight(profile: &Profile) -> Result<File> {
    if profile.resource_binding()? != public_profile()?.resource_binding()? {
        return Err("ASR held model projection changed".into());
    }
    let path = Path::new(VAR)
        .join(STATE)
        .join("model-packs")
        .join(&profile.binding.manifest_sha256)
        .join(format!("blobs/sha256/{WEIGHT_SHA256}"));
    let mut file = pack_store::regular(&path)?;
    let before = pack_store::identity(&file.metadata()?);
    if file.metadata()?.len() != WEIGHT_BYTES {
        return Err("ASR held model has wrong size".into());
    }
    let mut hash = Sha256::new();
    let mut block = [0u8; 65536];
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        hash.update(&block[..n]);
    }
    if bundle::hex(&hash.finalize()) != WEIGHT_SHA256
        || before != pack_store::identity(&file.metadata()?)
        || before != pack_store::identity(&pack_store::regular(&path)?.metadata()?)
    {
        return Err("ASR held model changed or failed byte verification".into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}
pub(super) fn sidecars(
    root: &Path,
    m: &PackManifest,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let model = m
        .blobs
        .iter()
        .find(|b| b.role == "model")
        .ok_or("ASR model shard missing")?;
    if model.sha256 != WEIGHT_SHA256 || model.size_bytes != WEIGHT_BYTES {
        return Err("ASR embedded tokenizer comparison requires exact supported model".into());
    }
    let mut file = pack_store::regular(&root.join(&model.path))?;
    let before = pack_store::identity(&file.metadata()?);
    let mut header = [0u8; 48];
    file.read_exact(&mut header)?;
    let expected = [0x67676d6cu32, 51865, 1500, 384, 6, 4, 448, 384, 6, 4, 80, 1];
    if header
        .chunks_exact(4)
        .zip(expected)
        .any(|(b, n)| b != n.to_le_bytes())
    {
        return Err("ASR header differs from exact GGML/F16 adapter".into());
    }
    file.seek(SeekFrom::Start(64376))?;
    let mut embedded = vec![0u8; 508089];
    file.read_exact(&mut embedded)?;
    if bundle::hex(&Sha256::digest(&embedded))
        != "358bdf83c2253dea0c8a1749f5288d96d2b6f5f4119faee9e5e26611a8c8f17b"
    {
        return Err("ASR actual embedded tokenizer digest differs".into());
    }
    for (role, bytes) in [("tokenizer", tokenizer()?), ("template", policy()?)] {
        check()?;
        let blob = m
            .blobs
            .iter()
            .find(|b| b.role == role)
            .ok_or("ASR sidecar missing")?;
        if bytes.len() as u64 != blob.size_bytes
            || bundle::hex(&Sha256::digest(&bytes)) != blob.sha256
            || pack_store::read(&root.join(&blob.path), 16384)? != bytes
        {
            return Err(
                "ASR signed tokenizer/decoding descriptor differs from actual pinned runtime"
                    .into(),
            );
        }
    }
    if before != pack_store::identity(&file.metadata()?) {
        return Err("ASR model changed during sidecar comparison".into());
    }
    check()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ModelProfile, PackManifest) {
        let token = tokenizer().unwrap();
        let decode = policy().unwrap();
        let token_sha = crate::artifacts::digest(&token);
        let decode_sha = crate::artifacts::digest(&decode);
        let blobs = serde_json::json!([
            {"role":"model","path":format!("blobs/sha256/{WEIGHT_SHA256}"),"sha256":WEIGHT_SHA256,"size_bytes":WEIGHT_BYTES,"shard_index":0},
            {"role":"tokenizer","path":format!("blobs/sha256/{token_sha}"),"sha256":token_sha,"size_bytes":token.len()},
            {"role":"template","path":format!("blobs/sha256/{decode_sha}"),"sha256":decode_sha,"size_bytes":decode.len()},
            {"role":"license","path":"licenses/WHISPER-MIT.txt","sha256":LICENSE_SHA256,"size_bytes":1063}]);
        let size = WEIGHT_BYTES + token.len() as u64 + decode.len() as u64 + 1063;
        let peak = size + 256 * 1024 * 1024;
        let tuple_sha = tuple().digest().unwrap();
        let manifest:PackManifest=serde_json::from_value(serde_json::json!({
            "schema_version":2,"canonicalization":"RFC8785-ASCII-v1","signature_algorithm":"Ed25519",
            "pack_id":ID,"pack_version":"1.0.0","model":{"architecture":ARCHITECTURE,
                "identity":"OpenAI Whisper tiny multilingual GGML","parameter_class":"37760640-stored-scalars",
                "total_parameters":PARAMETERS,"active_parameters_min":PARAMETERS,"active_parameters_max":PARAMETERS,
                "quantization":"mixed-F16-F32","required_features":["automatic-speech-recognition","offline","speech-transcription"],"source":SOURCE},
            "context":{"maximum_tokens":448,"template_sha256":decode_sha},"blobs":blobs,"runtime_tuples":[tuple()],
            "installation_profiles":[{"profile_id":ID,"runtime_tuple_sha256":tuple_sha,"execution_mode":"cpu",
                "minimum_host_ram_bytes":2147483648u64,"minimum_accelerator_memory_bytes":0,
                "minimum_model_storage_bytes":peak,"maximum_context_tokens":448}],
            "license":{"identifier":"MIT","evaluation":"approved","redistribution":"approved","files":["licenses/WHISPER-MIT.txt"]},
            "network_default":"deny","signer_key_id":"Pack"})).unwrap();
        let profile:ModelProfile=serde_json::from_value(serde_json::json!({
            "availability":"unavailable","certification_state":"not-certified","context_tokens":448,
            "development_state":"untested","execution_mode":"cpu","install_bytes":size,"kind":"model",
            "load_reservations":[{"domain":"host","bytes":MEMORY}],"minimum_accelerator_memory_bytes":0,
            "minimum_host_ram_bytes":2147483648u64,"model_pack_manifest_sha256":manifest.digest().unwrap(),
            "parameter_active_max":PARAMETERS,"parameter_active_min":PARAMETERS,"parameter_total":PARAMETERS,
            "profile_id":ID,"remote_fallback":false,"runtime_tuple_sha256":tuple_sha,
            "serve_reservations":[{"domain":"host","bytes":MEMORY}],"storage_peak_bytes":peak,"verification_state":"unverified"})).unwrap();
        (profile, manifest)
    }
    #[test]
    fn auxiliary_projection_matches_cross_language_metadata_not_text_or_availability_authority() {
        let (p, m) = fixture();
        assert_eq!(
            crate::artifacts::digest(&tokenizer().unwrap()),
            "97e7c85612b036bc28006b39828a06ea3f0db21559d3af6d3fa52392d582e513"
        );
        assert_eq!(
            crate::artifacts::digest(&policy().unwrap()),
            "be1791272979dea906c30869e96c3779253f9c294060e24987a8a4350f1c85c4"
        );
        let exact = project(&p, &m, &"1".repeat(64)).unwrap();
        assert_eq!(exact.id, ID);
        assert_eq!(exact.memory_bytes, MEMORY);
        assert_eq!(p.context_tokens, 448);
        assert!(super::super::pack_store::native_profile(&p, &m, &"1".repeat(64)).is_err());
        assert_ne!(
            exact.resource_binding().unwrap(),
            project(&p, &m, &"2".repeat(64))
                .unwrap()
                .resource_binding()
                .unwrap()
        );
    }
    #[test]
    fn auxiliary_projection_refuses_changed_model_runtime_context_reservations_and_sidecars() {
        let (p, m) = fixture();
        let mut changed = p.clone();
        changed.context_tokens = 128;
        assert!(project(&changed, &m, &"1".repeat(64)).is_err());
        let mut changed = p.clone();
        changed.load_reservations[0].bytes = 1;
        assert!(project(&changed, &m, &"1".repeat(64)).is_err());
        let mut changed = p.clone();
        changed.runtime_tuple_sha256 = "2".repeat(64);
        assert!(project(&changed, &m, &"1".repeat(64)).is_err());
        let mut changed = p.clone();
        changed.profile_id = "qwen3-4b-cpu".into();
        assert!(matches(&changed, &m));
        assert!(project(&changed, &m, &"1".repeat(64)).is_err());
        for mutation in [0, 1, 2, 3, 4, 5] {
            let mut changed = m.clone();
            match mutation {
                0 => changed.model.architecture = "qwen3".into(),
                1 => changed.runtime_tuples[0].backend = "llama.cpp".into(),
                2 => changed.blobs[0].sha256 = "2".repeat(64),
                3 => changed.blobs[1].sha256 = "3".repeat(64),
                4 => changed.context.maximum_tokens = 128,
                _ => changed.blobs[3].sha256 = "4".repeat(64),
            };
            let mut profile = p.clone();
            profile.model_pack_manifest_sha256 = changed.digest().unwrap();
            assert!(project(&profile, &changed, &"1".repeat(64)).is_err());
        }
    }
    #[test]
    fn auxiliary_resource_projection_cannot_alias_text_or_understate_memory() {
        let (p, m) = fixture();
        let exact = project(&p, &m, &"1".repeat(64)).unwrap();
        let mut changed = exact.clone();
        changed.id = "qwen3-4b".into();
        assert!(changed.resource_binding().is_err());
        let mut changed = exact.clone();
        changed.memory_bytes = MEMORY - 1;
        assert!(changed.resource_binding().is_err());
        let mut changed = exact.clone();
        changed.storage_peak_bytes = WEIGHT_BYTES - 1;
        assert!(changed.resource_binding().is_err());
        let mut changed = exact;
        changed.binding.catalog_sha256 = "".into();
        assert!(changed.resource_binding().is_err());
    }
}
