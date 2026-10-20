//! Auxiliary ASR uses existing anchored model custody, not the text selection.
use super::*;
use crate::model::speech::Profile;
use crate::model_trust::{self, CertificationRecord, QualificationEvidence, SelectableProfile};

pub(crate) fn current_speech_authority(profile: &Profile) -> Result<()> {
    authority(profile, false, None)
}
pub(crate) fn speech_pack_preparation_authority(profile: &Profile) -> Result<()> {
    authority(profile, true, None)
}
pub(crate) fn speech_qualification_preparation(
    profile: &Profile,
    record: &CertificationRecord,
    evidence: &QualificationEvidence,
    signature: &[u8],
) -> Result<()> {
    authority(profile, false, Some((record, evidence, signature)))
}
fn authority(
    profile: &Profile,
    preparation: bool,
    qualification: Option<(&CertificationRecord, &QualificationEvidence, &[u8])>,
) -> Result<()> {
    crate::require_root()?;
    platform::require_installed()?;
    let image = platform::CatalogImage::capture(Path::new(DIRECTORY))?;
    let expected = catalog_state_optional()?.ok_or("ASR requires the current Admin checkpoint")?;
    let state = expected
        .model_trust
        .as_ref()
        .ok_or("auxiliary model trust is not anchored")?;
    if image.production() != (state.trust.bundle.environment == "production")
        || profile.resource_binding()?
            != crate::model::speech::public_profile()?.resource_binding()?
    {
        return Err("ASR immutable model projection/environment changed".into());
    }
    if qualification.is_some() && !image.production() {
        return Err("external ASR qualification delivery is production-only; lab certification remains explicitly signed development input".into());
    }
    if image.production() {
        platform::check_governance_manifest(
            expected
                .release
                .as_ref()
                .and_then(|r| r.acknowledged.as_ref())
                .ok_or("production ASR requires acknowledged running release")?,
        )?;
    }
    let directory = Path::new(DIRECTORY);
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    let first = store.snapshot()?;
    let context = Context::load(directory, &first.deployment)?;
    if context.events(&first, None)?.0 != expected {
        return Err("ASR authority changed before admission".into());
    }
    let history = HistoryReader::new(&mut store, directory).read()?;
    let mut client = crate::utc_provider::Client::installed()?;
    let before = client.current(&history)?.interval();
    state.trust.check_root(before)?;
    model_trust::check_model_separation(&expected, &state.trust)?;
    drop(store);
    let public = model_trust::ModelCatalog::parse(&crate::admin_credentials::public_input(
        Path::new("/usr/share/luma-os/models/catalog.json"),
        model_trust::MAX_CATALOG as u64,
    )?)?;
    let selected = public
        .profiles
        .iter()
        .find_map(|p| match p {
            SelectableProfile::Model(p) if p.profile_id == profile.id => Some(p),
            _ => None,
        })
        .ok_or("ASR profile absent from immutable catalog")?;
    if public.digest()? != profile.binding.catalog_sha256
        || selected.digest()? != profile.binding.profile_sha256
    {
        return Err("ASR signed profile digest changed".into());
    }
    let (command, packs) = if let Some((record, evidence, signature)) = qualification {
        record.validate()?;
        if record.pack_manifest_sha256 != profile.binding.manifest_sha256
            || record.runtime_tuple_sha256 != profile.binding.runtime_tuple_sha256
        {
            return Err("ASR qualification differs from exact auxiliary pack/runtime".into());
        }
        QualificationEvidence::parse(&model_trust::canonical(evidence)?, record)?;
        evidence.check(
            expected
                .release
                .as_ref()
                .and_then(|r| r.acknowledged.as_ref())
                .ok_or("ASR qualification requires acknowledged release")?,
            selected,
            &model_trust::MachineTuple::current()?,
            expected.registry()?.installation(),
        )?;
        let purpose = if record.level == "execution" {
            "model-pack-execution-certification"
        } else {
            "model-pack-interactive-certification"
        };
        state.trust.verify(
            &record.signer_key_id,
            purpose,
            &model_trust::canonical(record)?,
            signature,
            before,
        )?;
        let mut pack = crate::model::speech::preparation(profile, &state.trust, before)?;
        pack.signing_keys
            .push((record.signer_key_id.clone(), purpose.into()));
        (
            Command::PublishModelTrust {
                expected_sequence: state.trust.bundle.bundle_sequence,
                bundle: state.trust.clone(),
            },
            vec![pack],
        )
    } else if preparation {
        let pack = crate::model::speech::public_preparation(profile, &state.trust, before)?;
        (
            Command::PublishModelTrust {
                expected_sequence: state.trust.bundle.bundle_sequence,
                bundle: state.trust.clone(),
            },
            vec![pack],
        )
    } else {
        let admission = state
            .current
            .as_ref()
            .ok_or("ASR catalog is not admitted")?;
        let catalog = model_trust::ModelCatalog::parse(admission.catalog_json.as_bytes())?;
        let packs = crate::model::verify_catalog_packs(&catalog, &state.trust, before)?;
        model_trust::current_catalog(&expected, before, &packs)?;
        if catalog != public
            || selected.availability != "available"
            || selected.verification_state != "verified"
            || selected.development_state != "development-tested"
            || selected.certification_state != "interactive-certified"
        {
            return Err("ASR requires exact admitted, verified and independently interactive-qualified auxiliary catalog".into());
        }
        (
            Command::AdmitModelCatalog {
                expected_floor: state.floor,
                admission: admission.clone(),
            },
            packs,
        )
    };
    let proof = model_trust::TimeProof::capture(&expected, &command, &packs)?;
    let accounts =
        ModelAccounts::capture(&expected, &command, Path::new(crate::principal::REGISTRY))?;
    let mut store = Store::open(
        tpm::LocalAnchor::installed()?,
        &directory.join("journal.json"),
    )?;
    image.recheck()?;
    history.recheck(&mut HistoryReader::new(&mut store, directory))?;
    let last = store.snapshot()?;
    last.clock.elapsed_since(first.clock)?;
    if last.head != first.head
        || last.deployment != first.deployment
        || context.events(&last, None)?.0 != expected
    {
        return Err("ASR current authority changed during physical qualification checks".into());
    }
    accounts.recheck()?;
    let sampled = client.current(&history)?;
    let live = client.project_after_checks(&history, &sampled, |_| Ok(()))?;
    proof.check(live.interval())
}

pub(crate) fn speech_qualification_observation(
    profile: &Profile,
    level: &str,
    report_sha256: &str,
) -> Result<QualificationEvidence> {
    crate::require_root()?;
    platform::require_installed()?;
    platform::require_production_activation()?;
    let image = platform::CatalogImage::capture(Path::new(DIRECTORY))?;
    if !image.production() {
        return Err("ASR exact-image qualification observation is production-only".into());
    }
    let catalog = catalog_state_optional()?.ok_or("ASR qualification requires Admin checkpoint")?;
    let release = catalog
        .release
        .as_ref()
        .and_then(|r| r.acknowledged.as_ref())
        .ok_or("ASR qualification requires acknowledged image")?;
    platform::check_governance_manifest(release)?;
    if profile.resource_binding()? != crate::model::speech::public_profile()?.resource_binding()? {
        return Err("ASR immutable qualification tuple changed".into());
    }
    let evidence = QualificationEvidence {
        schema_version: 1,
        level: level.into(),
        installation_sha256: catalog.registry()?.installation().into(),
        release_manifest_sha256: model_trust::digest(release)?,
        model_profile_sha256: profile.binding.profile_sha256.clone(),
        runtime_tuple_sha256: profile.binding.runtime_tuple_sha256.clone(),
        hardware: model_trust::MachineTuple::current()?,
        test_report_sha256: report_sha256.into(),
    };
    evidence.validate()?;
    image.recheck()?;
    if catalog_state_optional()?.as_ref() != Some(&catalog) {
        return Err("ASR qualification checkpoint changed".into());
    }
    Ok(evidence)
}
