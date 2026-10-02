//! Versioned native TPM sealed credential under the existing-owner parent.
//! The parent is a fixed persistent TPM object; normal unlock never needs the
//! custodian's owner authorization. PCR7 is fixed and PCR11 is signer-approved.
use crate::{
    sealed_credential::{self, Secret},
    tpm::{self, CredentialDevice},
    Result,
};
use serde::Deserialize;

const MAGIC: &[u8; 16] = b"LUMAOWNERSEALv1!";
const HEADER: usize = 118;
const MAX_BLOB: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signatures {
    sha256: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    pcrs: Vec<u8>,
    pkfp: String,
    pol: String,
    sig: String,
}

struct Policy {
    digest: [u8; 32],
    signature: [u8; 256],
}

fn current_policy(
    device: &mut CredentialDevice,
    public_pem: &[u8],
    signature_json: &[u8],
) -> Result<Policy> {
    if signature_json.is_empty() || signature_json.len() > MAX_BLOB {
        return Err("signed PCR policy outside bound".into());
    }
    let file: Signatures = serde_json::from_slice(signature_json)?;
    if file.sha256.is_empty() || file.sha256.len() > 32 {
        return Err("signed PCR policy entry count outside bound".into());
    }
    let signer = tpm::credential_fingerprint(public_pem)?;
    let current = device.current_policy11()?;
    let mut selected = None;
    for entry in file.sha256 {
        let fingerprint = tpm::decode::<32>(&entry.pkfp)?;
        let digest = tpm::decode::<32>(&entry.pol)?;
        let signature: [u8; 256] = sealed_credential::decode_blob(entry.sig.as_bytes())?
            .try_into()
            .map_err(|_| "signed PCR policy signature must be RSA-2048")?;
        if entry.pcrs == [11] && fingerprint == signer && digest == current {
            if selected.is_some() {
                return Err("ambiguous matching signed PCR policy".into());
            }
            selected = Some(Policy { digest, signature });
        }
    }
    selected.ok_or_else(|| "no signed PCR11 policy matches the current TPM and image key".into())
}

fn encode(
    deployment: &str,
    parent_name: &[u8; 34],
    fingerprint: &[u8; 32],
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<Vec<u8>> {
    let domain = tpm::decode::<32>(deployment)?;
    if public_blob.is_empty()
        || public_blob.len() > 4096
        || private_blob.is_empty()
        || private_blob.len() > 4096
    {
        return Err("native sealed child size outside bound".into());
    }
    let mut blob = Vec::with_capacity(HEADER + public_blob.len() + private_blob.len());
    blob.extend(MAGIC);
    blob.extend(parent_name);
    blob.extend(domain);
    blob.extend(fingerprint);
    blob.extend((public_blob.len() as u16).to_be_bytes());
    blob.extend((private_blob.len() as u16).to_be_bytes());
    blob.extend(public_blob);
    blob.extend(private_blob);
    if blob.len() > MAX_BLOB {
        return Err("native credential outside bound".into());
    }
    Ok(blob)
}

fn decode<'a>(
    deployment: &str,
    parent_name: &[u8; 34],
    fingerprint: &[u8; 32],
    blob: &'a [u8],
) -> Result<(&'a [u8], &'a [u8])> {
    let domain = tpm::decode::<32>(deployment)?;
    if blob.len() < HEADER + 2 || blob.len() > MAX_BLOB || &blob[..16] != MAGIC {
        return Err("native credential header/version invalid".into());
    }
    if &blob[16..50] != parent_name || blob[50..82] != domain || &blob[82..114] != fingerprint {
        return Err("native credential parent, signer or deployment mismatch".into());
    }
    let public_size = u16::from_be_bytes(blob[114..116].try_into()?) as usize;
    let private_size = u16::from_be_bytes(blob[116..118].try_into()?) as usize;
    if public_size == 0
        || public_size > 4096
        || private_size == 0
        || private_size > 4096
        || HEADER + public_size + private_size != blob.len()
    {
        return Err("native credential payload length invalid".into());
    }
    Ok((
        &blob[HEADER..HEADER + public_size],
        &blob[HEADER + public_size..],
    ))
}

pub(crate) fn verify_boot(public_pem: &[u8], signature_json: &[u8]) -> Result<()> {
    let mut device = CredentialDevice::local()?;
    let policy = current_policy(&mut device, public_pem, signature_json)?;
    device.verify_policy11(public_pem, &policy.digest, &policy.signature)
}

pub(crate) fn seal(
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    secret: &Secret,
) -> Result<Vec<u8>> {
    let mut device = CredentialDevice::local()?;
    seal_with(&mut device, deployment, parent_name, public_pem, secret)
}

fn seal_with(
    device: &mut CredentialDevice,
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    secret: &Secret,
) -> Result<Vec<u8>> {
    let fingerprint = tpm::credential_fingerprint(public_pem)?;
    let (public_blob, private_blob) = device.seal_child(parent_name, public_pem, secret)?;
    encode(
        deployment,
        parent_name,
        &fingerprint,
        &public_blob,
        &private_blob,
    )
}

pub(crate) fn unseal(
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    blob: &[u8],
    signature_json: &[u8],
) -> Result<Secret> {
    let mut device = CredentialDevice::local()?;
    unseal_with(
        &mut device,
        deployment,
        parent_name,
        public_pem,
        blob,
        signature_json,
    )
}

fn unseal_with(
    device: &mut CredentialDevice,
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    blob: &[u8],
    signature_json: &[u8],
) -> Result<Secret> {
    let fingerprint = tpm::credential_fingerprint(public_pem)?;
    let (public_blob, private_blob) = decode(deployment, parent_name, &fingerprint, blob)?;
    let policy = current_policy(device, public_pem, signature_json)?;
    device.unseal_child(
        parent_name,
        public_pem,
        public_blob,
        private_blob,
        &policy.digest,
        &policy.signature,
    )
}

#[cfg(test)]
pub(crate) fn fixture_verify_boot(
    directory: &std::path::Path,
    public_pem: &[u8],
    signature_json: &[u8],
) -> Result<()> {
    let mut device = CredentialDevice::fixture(directory)?;
    let policy = current_policy(&mut device, public_pem, signature_json)?;
    device.verify_policy11(public_pem, &policy.digest, &policy.signature)
}

#[cfg(test)]
pub(crate) fn fixture_seal(
    directory: &std::path::Path,
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    secret: &Secret,
) -> Result<Vec<u8>> {
    seal_with(
        &mut CredentialDevice::fixture(directory)?,
        deployment,
        parent_name,
        public_pem,
        secret,
    )
}

#[cfg(test)]
pub(crate) fn fixture_unseal(
    directory: &std::path::Path,
    deployment: &str,
    parent_name: &[u8; 34],
    public_pem: &[u8],
    blob: &[u8],
    signature_json: &[u8],
) -> Result<Secret> {
    unseal_with(
        &mut CredentialDevice::fixture(directory)?,
        deployment,
        parent_name,
        public_pem,
        blob,
        signature_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    #[test]
    fn envelope_binds_domain_parent_and_signer() {
        let parent = [0x33; 34];
        let signer = [0x44; 32];
        let blob = encode(&"ab".repeat(32), &parent, &signer, b"public", b"private").unwrap();
        assert_eq!(
            decode(&"ab".repeat(32), &parent, &signer, &blob).unwrap(),
            (&b"public"[..], &b"private"[..])
        );
        assert!(decode(&"cd".repeat(32), &parent, &signer, &blob).is_err());
        let mut changed = parent;
        changed[8] ^= 1;
        assert!(decode(&"ab".repeat(32), &changed, &signer, &blob).is_err());
        for offset in [0, 16, 50, 82, 114, 116] {
            let mut altered = blob.clone();
            altered[offset] ^= 1;
            assert!(
                decode(&"ab".repeat(32), &parent, &signer, &altered).is_err(),
                "{offset}"
            );
        }
        assert!(decode(&"ab".repeat(32), &parent, &signer, &blob[..blob.len() - 1]).is_err());
    }

    #[test]
    #[ignore = "requires isolated existing-owner TPM with signed PCR11 fixture"]
    fn emulator_native_envelope() {
        assert!(Path::new("/.dockerenv").is_file());
        assert!(!Path::new("/dev/tpm0").exists() && !Path::new("/dev/tpmrm0").exists());
        let directory = std::path::PathBuf::from(std::env::var("LUMA_TPM_TEST_DIRECTORY").unwrap());
        assert_eq!(directory.parent(), Some(Path::new("/tmp")));
        assert!(directory
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("luma-tpm-"));
        let name: [u8; 34] = fs::read(directory.join("parent.name"))
            .unwrap()
            .try_into()
            .unwrap();
        let public = fs::read(directory.join("pcr-public.pem")).unwrap();
        let signature = fs::read(directory.join("pcr-signature.json")).unwrap();
        let deployment = "ab".repeat(32);
        let mode = std::env::var("LUMA_TPM_TEST_NATIVE_MODE").unwrap();
        if mode == "seal" {
            fixture_verify_boot(&directory, &public, &signature).unwrap();
            let secret = Secret::generate().unwrap();
            let blob = fixture_seal(&directory, &deployment, &name, &public, &secret).unwrap();
            fs::write(directory.join("native-envelope.cred"), blob).unwrap();
            fs::write(
                directory.join("native-envelope.fixture-secret"),
                secret.bytes(),
            )
            .unwrap();
            return;
        }
        let blob = fs::read(directory.join("native-envelope.cred")).unwrap();
        match mode.as_str() {
            "allow" => {
                let secret =
                    fixture_unseal(&directory, &deployment, &name, &public, &blob, &signature)
                        .unwrap();
                assert_eq!(
                    &secret.bytes()[..],
                    fs::read(directory.join("native-envelope.fixture-secret")).unwrap()
                );
            }
            "deny" => {
                assert!(
                    fixture_unseal(&directory, &deployment, &name, &public, &blob, &signature,)
                        .is_err()
                )
            }
            "wrong-name" => {
                let mut changed = name;
                changed[20] ^= 1;
                assert!(fixture_unseal(
                    &directory,
                    &deployment,
                    &changed,
                    &public,
                    &blob,
                    &signature,
                )
                .is_err());
            }
            "tamper" => {
                let mut changed = blob;
                let midpoint = changed.len() / 2;
                changed[midpoint] ^= 1;
                assert!(fixture_unseal(
                    &directory,
                    &deployment,
                    &name,
                    &public,
                    &changed,
                    &signature,
                )
                .is_err());
            }
            _ => panic!("invalid native envelope fixture mode"),
        }
    }
}
