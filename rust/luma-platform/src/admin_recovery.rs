//! Offline credential custody. A verifier is inert until checkpoint adoption.
//! Only the governed recovery composition may consume the nonserializable secret.
use crate::{authentication, bundle, sealed_credential::PrivateBuffer, tpm, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

const TOKEN_BYTES: usize = 32;
const HEX_BYTES: usize = TOKEN_BYTES * 2;
const DOMAIN: &[u8] = b"luma-offline-admin-recovery-v1\0";

// The image already links packaged libcrypto through the TPM ABI shim.
extern "C" {
    fn CRYPTO_memcmp(
        left: *const libc::c_void,
        right: *const libc::c_void,
        size: usize,
    ) -> libc::c_int;
    fn SHA256(input: *const u8, size: usize, output: *mut u8) -> *mut u8;
}

pub(crate) struct Credential(PrivateBuffer);

impl Credential {
    #[cfg(test)]
    pub(crate) fn fixture(byte: u8) -> Self {
        let mut value = PrivateBuffer::new(TOKEN_BYTES).unwrap();
        value.bytes_mut().fill(byte);
        Self(value)
    }
    fn generate() -> Result<Self> {
        crate::require_root()?;
        let mut value = PrivateBuffer::new(TOKEN_BYTES)?;
        File::open("/dev/urandom")?.read_exact(value.bytes_mut())?;
        Ok(Self(value))
    }

    fn decode(encoded: &PrivateBuffer) -> Result<Self> {
        if encoded.bytes().len() <= HEX_BYTES
            || encoded.bytes()[HEX_BYTES..].iter().any(|byte| *byte != 0)
        {
            return Err(
                "recovery credential must contain exactly 64 lowercase hex characters".into(),
            );
        }
        let mut value = PrivateBuffer::new(TOKEN_BYTES)?;
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("invalid recovery credential encoding"),
        };
        for (out, pair) in value
            .bytes_mut()
            .iter_mut()
            .zip(encoded.bytes()[..HEX_BYTES].chunks_exact(2))
        {
            *out = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Ok(Self(value))
    }

    pub(crate) fn read() -> Result<Self> {
        let encoded = authentication::hidden_from(
            terminal()?,
            "Offline Admin recovery credential (hidden):",
        )?;
        Self::decode(&encoded)
    }

    /// The only plaintext output is the separately opened controlling terminal.
    /// Never use stdout, a String/Vec, a file path supplied by a caller, or JSON.
    pub(crate) fn generate_confirmed() -> Result<Self> {
        let value = Self::generate()?;
        let mut encoded = PrivateBuffer::new(HEX_BYTES + 1)?;
        let digits = b"0123456789abcdef";
        for (index, byte) in value.0.bytes().iter().enumerate() {
            encoded.bytes_mut()[index * 2] = digits[(byte >> 4) as usize];
            encoded.bytes_mut()[index * 2 + 1] = digits[(byte & 15) as usize];
        }
        let mut tty = terminal()?;
        writeln!(tty, "Record this NEW offline Admin recovery credential outside this machine. It is NOT the disk recovery passphrase. No copy is stored by Luma:")?;
        tty.write_all(&encoded.bytes()[..HEX_BYTES])?;
        tty.write_all(b"\n")?;
        tty.flush()?;
        drop(tty);
        let confirmation = authentication::hidden_from(
            terminal()?,
            "Re-enter the NEW offline Admin recovery credential to confirm custody (hidden):",
        )?;
        let confirmation = Self::decode(&confirmation)?;
        if !equal(value.0.bytes(), confirmation.0.bytes()) {
            return Err("offline Admin recovery credential confirmation differs".into());
        }
        Ok(value)
    }
}

fn terminal() -> Result<File> {
    crate::require_root()?;
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?)
}

fn equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    unsafe { CRYPTO_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) == 0 }
}

/// Public commitment only. No credential bytes or authentication proof.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Verifier {
    schema_version: u32,
    installation: String,
    principal: String,
    uid: u32,
    pub(crate) generation: u64,
    salt: String,
    commitment_sha256: String,
}

impl Verifier {
    pub(crate) fn create(
        credential: &Credential,
        installation: &str,
        principal: &str,
        generation: u64,
    ) -> Result<Self> {
        let mut salt = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut salt)?;
        let mut verifier = Self {
            schema_version: 1,
            installation: installation.into(),
            principal: principal.into(),
            uid: 1001,
            generation,
            salt: bundle::hex(&salt),
            commitment_sha256: "00".repeat(32),
        };
        verifier.validate(installation, principal)?;
        verifier.commitment_sha256 = bundle::hex(&verifier.digest(credential)?);
        Ok(verifier)
    }

    pub(crate) fn validate(&self, installation: &str, principal: &str) -> Result<()> {
        for value in [
            &self.installation,
            &self.principal,
            &self.salt,
            &self.commitment_sha256,
        ] {
            tpm::decode::<32>(value)?;
        }
        if self.schema_version != 1
            || self.uid != 1001
            || self.generation == 0
            || self.installation == self.principal
            || self.installation != installation
            || self.principal != principal
        {
            return Err("recovery verifier does not bind the original installation Admin".into());
        }
        Ok(())
    }

    fn digest(&self, credential: &Credential) -> Result<[u8; 32]> {
        self.validate(&self.installation, &self.principal)?;
        // Assemble the complete preimage in locked/wiped memory. In particular,
        // no Rust digest block buffer or ordinary Vec retains credential bytes.
        let mut preimage = PrivateBuffer::new(DOMAIN.len() + 32 + 32 + 4 + 8 + 32 + TOKEN_BYTES)?;
        let mut remaining = preimage.bytes_mut();
        for part in [
            DOMAIN,
            &tpm::decode::<32>(&self.installation)?,
            &tpm::decode::<32>(&self.principal)?,
            &self.uid.to_be_bytes(),
            &self.generation.to_be_bytes(),
            &tpm::decode::<32>(&self.salt)?,
            credential.0.bytes(),
        ] {
            let (output, rest) = remaining.split_at_mut(part.len());
            output.copy_from_slice(part);
            remaining = rest;
        }
        let mut result = [0; 32];
        if unsafe {
            SHA256(
                preimage.bytes().as_ptr(),
                preimage.bytes().len(),
                result.as_mut_ptr(),
            )
        }
        .is_null()
        {
            return Err("recovery verifier digest computation failed".into());
        }
        Ok(result)
    }

    pub(crate) fn verify(&self, credential: &Credential) -> Result<()> {
        let expected = tpm::decode::<32>(&self.commitment_sha256)?;
        if !equal(&expected, &self.digest(credential)?) {
            return Err("offline Admin recovery authentication refused".into());
        }
        Ok(())
    }

    pub(crate) fn successor(&self, replacement: &Self) -> Result<()> {
        replacement.validate(&self.installation, &self.principal)?;
        if replacement.generation
            != self
                .generation
                .checked_add(1)
                .ok_or("recovery credential generation exhausted")?
            || replacement.salt == self.salt
            || replacement.commitment_sha256 == self.commitment_sha256
        {
            return Err("recovery requires a fresh next-generation verifier".into());
        }
        Ok(())
    }
}

pub(crate) fn review(digest: &str) -> Result<()> {
    tpm::decode::<32>(digest)?;
    let response = authentication::hidden_from(terminal()?, &format!("Type the exact recovery review SHA256 {digest} to commit (hidden; anything else refuses):"))?;
    if response.bytes().len() <= HEX_BYTES
        || response.bytes()[HEX_BYTES..].iter().any(|byte| *byte != 0)
        || !equal(&response.bytes()[..HEX_BYTES], digest.as_bytes())
    {
        return Err("Admin recovery review was not confirmed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(byte: u8) -> Credential {
        Credential::fixture(byte)
    }

    #[test]
    fn exact_bounded_encoding_and_private_secret() {
        for value in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let mut encoded = PrivateBuffer::new(1025).unwrap();
            encoded.bytes_mut()[..value.len()].copy_from_slice(value.as_bytes());
            assert!(Credential::decode(&encoded).is_err());
        }
        let mut encoded = PrivateBuffer::new(1025).unwrap();
        encoded.bytes_mut()[..64].fill(b'a');
        let decoded = Credential::decode(&encoded).unwrap();
        assert_eq!(decoded.0.bytes(), &[0xaa; 32]);
        encoded.bytes_mut()[1000] = 1;
        assert!(Credential::decode(&encoded).is_err());
    }

    #[test]
    fn verifier_is_domain_principal_installation_and_generation_bound() {
        let secret = credential(0x42);
        let verifier = Verifier::create(&secret, &"ab".repeat(32), &"cd".repeat(32), 1).unwrap();
        verifier.verify(&secret).unwrap();
        assert!(verifier.verify(&credential(0x43)).is_err());
        for field in ["installation", "principal", "salt"] {
            let mut changed = serde_json::to_value(&verifier).unwrap();
            changed[field] = serde_json::json!("ef".repeat(32));
            let changed: Verifier = serde_json::from_value(changed).unwrap();
            assert!(changed.verify(&secret).is_err());
        }
        let mut changed = verifier.clone();
        changed.generation = 2;
        assert!(changed.verify(&secret).is_err());
        changed = verifier.clone();
        changed.uid = 0;
        assert!(changed.verify(&secret).is_err());
        assert!(verifier
            .validate(&"ef".repeat(32), &"cd".repeat(32))
            .is_err());
        assert!(verifier
            .validate(&"ab".repeat(32), &"ef".repeat(32))
            .is_err());
        let serialized = serde_json::to_string(&verifier).unwrap();
        assert!(!serialized.contains(&"42".repeat(32)));
        let mut value = serde_json::to_value(&verifier).unwrap();
        value["force"] = true.into();
        assert!(serde_json::from_value::<Verifier>(value).is_err());
    }

    #[test]
    fn rotation_never_accepts_old_or_substituted_verifiers() {
        let original = credential(0x42);
        let replacement = credential(0x43);
        let first = Verifier::create(&original, &"ab".repeat(32), &"cd".repeat(32), 1).unwrap();
        let second = Verifier::create(&replacement, &"ab".repeat(32), &"cd".repeat(32), 2).unwrap();
        first.successor(&second).unwrap();
        second.verify(&replacement).unwrap();
        assert!(second.verify(&original).is_err());
        assert!(first.successor(&first).is_err());
        assert!(second.successor(&first).is_err());
        for (installation, principal, generation) in
            [("ef", "cd", 2), ("ab", "ef", 2), ("ab", "cd", 3)]
        {
            let wrong = Verifier::create(
                &replacement,
                &installation.repeat(32),
                &principal.repeat(32),
                generation,
            )
            .unwrap();
            assert!(first.successor(&wrong).is_err());
        }
        let mut exhausted = first;
        exhausted.generation = u64::MAX;
        assert!(exhausted.successor(&second).is_err());
    }
}
