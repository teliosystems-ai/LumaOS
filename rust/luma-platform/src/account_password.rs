//! Local secret entry and the distribution's yescrypt implementation.
//! Passwords and crypt output have no JSON, Debug, Clone, argv or environment form.
use crate::{sealed_credential::PrivateBuffer, Result};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

extern "C" {
    fn luma_password_context_size() -> usize;
    fn luma_password_hash(
        password: *const u8,
        entropy: *const u8,
        context: *mut u8,
        context_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> libc::c_int;
    fn luma_password_verify(
        password: *const u8,
        hash: *const u8,
        context: *mut u8,
        context_len: usize,
    ) -> libc::c_int;
}

pub(crate) struct Password(PrivateBuffer);
pub(crate) struct Hash(PrivateBuffer);

fn password_length(buffer: &PrivateBuffer) -> Result<usize> {
    let length = buffer
        .bytes()
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("unterminated account secret")?;
    let text = std::str::from_utf8(&buffer.bytes()[..length])
        .map_err(|_| "invalid account secret encoding")?;
    if length > 256
        || text.chars().count() < 12
        || text.chars().any(char::is_control)
        || buffer.bytes()[length..].iter().any(|&byte| byte != 0)
    {
        return Err("new account secret requires 12 or more printable characters and at most 256 UTF-8 bytes".into());
    }
    Ok(length)
}

impl Password {
    pub(crate) fn local_confirmed() -> Result<Self> {
        let terminal = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/dev/tty")
        };
        let first = crate::authentication::hidden_from(terminal()?, "New account password:")?;
        let second =
            crate::authentication::hidden_from(terminal()?, "Confirm new account password:")?;
        password_length(&first)?;
        password_length(&second)?;
        let difference = first
            .bytes()
            .iter()
            .zip(second.bytes())
            .fold(0u8, |value, (a, b)| value | (a ^ b));
        if difference != 0 {
            return Err("new account password confirmation differs".into());
        }
        Ok(Self(first))
    }

    pub(crate) fn hash(&self) -> Result<Hash> {
        password_length(&self.0)?;
        let mut entropy = PrivateBuffer::new(32)?;
        File::open("/dev/urandom")?.read_exact(entropy.bytes_mut())?;
        let length = unsafe { luma_password_context_size() };
        let mut context = PrivateBuffer::password_context(length)?;
        let mut output = PrivateBuffer::new(384)?;
        let status = unsafe {
            luma_password_hash(
                self.0.bytes().as_ptr(),
                entropy.bytes().as_ptr(),
                context.bytes_mut().as_mut_ptr(),
                length,
                output.bytes_mut().as_mut_ptr(),
                output.bytes().len(),
            )
        };
        if status != 0 {
            return Err("distribution account password hashing failed; no fallback".into());
        }
        let result = Hash(output);
        result.bytes()?;
        result.verify(self)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn fixture(buffer: &PrivateBuffer) -> Result<Self> {
        password_length(buffer)?;
        let mut secret = PrivateBuffer::new(buffer.bytes().len())?;
        secret.bytes_mut().copy_from_slice(buffer.bytes());
        Ok(Self(secret))
    }
}

impl Hash {
    pub(crate) fn bytes(&self) -> Result<&[u8]> {
        let length = self
            .0
            .bytes()
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("unterminated account hash")?;
        let value = &self.0.bytes()[..length];
        validate_hash(value)?;
        Ok(value)
    }

    fn verify(&self, password: &Password) -> Result<()> {
        let length = unsafe { luma_password_context_size() };
        let mut context = PrivateBuffer::password_context(length)?;
        if unsafe {
            luma_password_verify(
                password.0.bytes().as_ptr(),
                self.0.bytes().as_ptr(),
                context.bytes_mut().as_mut_ptr(),
                length,
            )
        } != 0
        {
            return Err("distribution account hash verification failed".into());
        }
        Ok(())
    }
}

pub(crate) fn validate_hash(value: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(value).map_err(|_| "invalid account hash encoding")?;
    let fields: Vec<_> = text.split('$').collect();
    if value.len() > 192
        || fields.len() != 5
        || fields[0] != ""
        || fields[1] != "y"
        || fields[2] != "j9T"
        || !(16..=86).contains(&fields[3].len())
        || fields[4].len() != 43
        || fields[2..].iter().any(|field| {
            !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"./".contains(&byte))
        })
    {
        return Err("account hash is not the fixed distribution yescrypt profile".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn secret(value: &[u8]) -> PrivateBuffer {
        let mut result = PrivateBuffer::new(1025).unwrap();
        result.bytes_mut()[..value.len()].copy_from_slice(value);
        result
    }
    #[test]
    fn yescrypt_round_trip_uses_fresh_salt_and_rejects_other_password() {
        let password = Password::fixture(&secret(b"Strong local fixture password 42")).unwrap();
        let first = password.hash().unwrap();
        let second = password.hash().unwrap();
        assert_ne!(first.bytes().unwrap(), second.bytes().unwrap());
        first.verify(&password).unwrap();
        let other = Password::fixture(&secret(b"Other strong fixture password 43")).unwrap();
        assert!(first.verify(&other).is_err());
    }
    #[test]
    fn strength_framing_and_foreign_hashes_refuse_without_exposure() {
        for value in [
            b"short".as_slice(),
            b"control\npassword-long",
            b"invalid\xffpassword-long",
        ] {
            assert!(Password::fixture(&secret(value)).is_err());
        }
        let mut invalid = secret(b"Strong fixture password 44");
        invalid.bytes_mut()[100] = b'x';
        assert!(Password::fixture(&invalid).is_err());
        for value in [
            b"$6$old$hash".as_slice(),
            b"!$y$j9T$salt$hash",
            b"$y$j8T$salt$hash",
            b"plain-secret",
        ] {
            assert!(validate_hash(value).is_err());
        }
    }
}
