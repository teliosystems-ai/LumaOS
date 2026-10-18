//! One strict portable governed-ciphertext reader. Verification authenticates
//! only the independently pinned origin's signed commitments; historical
//! delivery leases and archive-supplied identities never become live authority.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) struct VerifiedCiphertext {
    pub(crate) receipt: crate::content_checkpoint::custody::BackupReceipt,
    pub(crate) ciphertext: Vec<u8>,
}

fn read_checked(
    reader: &mut impl Read,
    mut output: &mut [u8],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    while !output.is_empty() {
        check()?;
        let count = output.len().min(32768);
        match reader.read(&mut output[..count]) {
            Ok(0) => return Err("truncated governed ciphertext capsule".into()),
            Ok(count) => output = &mut output[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        check()?;
    }
    Ok(())
}

pub(crate) fn inspect(
    reader: &mut impl Read,
    expected_origin: &str,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<VerifiedCiphertext> {
    check()?;
    if !io::hash(expected_origin) || expected_origin == "00".repeat(32) {
        return Err("an independently selected nonzero origin SPKI pin is required".into());
    }
    let mut header = [0u8; 20];
    read_checked(reader, &mut header, check)?;
    if &header[..16] != MAGIC {
        return Err("input is not the governed portable capsule format".into());
    }
    let length = u32::from_be_bytes(header[16..].try_into()?) as usize;
    if length == 0 || length > MAX_META {
        return Err("capsule metadata exceeds fixed bound".into());
    }
    let mut bytes = vec![0; length];
    read_checked(reader, &mut bytes, check)?;
    let metadata: Metadata = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&metadata)? != bytes {
        return Err("capsule metadata is not closed canonical data".into());
    }
    let receipt = metadata
        .custody_receipt
        .as_ref()
        .ok_or("capsule lacks governed origin receipt")?;
    let input = &receipt.body.input;
    validate_encryption(&metadata.encryption, input)?;
    receipt.check_data(input, &metadata.encryption)?;
    if input.custody_generation()?.is_none()
        || metadata.schema_version != 1
        || metadata.request_sha256 != io::digest(&serde_json::to_vec(input)?)
        || metadata.binding != receipt.export_binding()?
        || metadata.review_sha256 != input.review.review_sha256
        || !crate::workflow_resource::token_valid(&metadata.lease)
        || !metadata.recipient_custody_qualified
        || !metadata.sender_authenticated
        || metadata.production_qualified
        || metadata.restore_permitted
    {
        return Err(
            "capsule framing substitutes signed origin data or restoration authority".into(),
        );
    }
    // Perform independent origin verification before allocating ciphertext.
    receipt.verify_origin(expected_origin, check)?;
    let length = usize::try_from(metadata.encryption.cms_bytes)?;
    if length == 0 || length > crypto::MAX_ENCRYPTED_BACKUP_BYTES {
        return Err("capsule ciphertext exceeds finite memory bound".into());
    }
    check()?;
    let mut ciphertext = Vec::new();
    ciphertext.try_reserve_exact(length)?;
    ciphertext.resize(length, 0);
    let mut digest = Sha256::new();
    for block in ciphertext.chunks_mut(32768) {
        read_checked(reader, block, check)?;
        digest.update(block);
    }
    check()?;
    let mut extra = [0u8; 1];
    loop {
        check()?;
        match reader.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err("capsule has trailing uncommitted data".into()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    if crate::bundle::hex(&digest.finalize()) != metadata.encryption.cms_sha256 {
        return Err(
            "capsule ciphertext differs from independently authenticated commitment".into(),
        );
    }
    check()?;
    Ok(VerifiedCiphertext {
        receipt: receipt.clone(),
        ciphertext,
    })
}

pub(crate) fn verify_stdin(expected_origin: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let capsule = inspect(&mut std::io::stdin().lock(), expected_origin, &mut || {
        if Instant::now() >= deadline {
            return Err("public capsule verification expired".into());
        }
        Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"origin_signature_valid":true,
        "ciphertext_commitment_valid":true,"cms_bytes":capsule.ciphertext.len(),
        "cms_sha256":capsule.receipt.body.encryption.cms_sha256,
        "archive_sha256":capsule.receipt.body.encryption.archive_sha256,
        "binding":capsule.receipt.body.input.binding,
        "outer_delivery_lease_authenticated":false,"current_custody_qualified":false,
        "archive_validated":false,"archive_decrypted":false,"restore_permitted":false,
        "authority_returned":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_refuses_raw_cms_unknown_format_invalid_bounds_and_revocation_before_input() {
        for bytes in [Vec::new(), b"raw CMS is not a signed capsule".to_vec(), {
            let mut v = MAGIC.to_vec();
            v.extend((MAX_META as u32 + 1).to_be_bytes());
            v
        }] {
            assert!(inspect(
                &mut std::io::Cursor::new(bytes),
                &"11".repeat(32),
                &mut || Ok(())
            )
            .is_err());
        }
        let mut input = std::io::Cursor::new(vec![0; 20]);
        assert!(inspect(&mut input, &"11".repeat(32), &mut || Err(
            "explicit fixture revocation".into()
        ))
        .is_err());
        assert_eq!(input.position(), 0);
    }
    #[test]
    fn actual_origin_signed_byte_capsule_requires_exact_ciphertext_and_no_trailing_data() {
        let receipt = crate::content_checkpoint::custody::test_signed_receipt();
        let pin = receipt.body.origin_spki_sha256.clone();
        let metadata = Metadata {
            schema_version: 1,
            request_sha256: io::digest(&serde_json::to_vec(&receipt.body.input).unwrap()),
            binding: receipt.export_binding().unwrap(),
            lease: crate::resources::Token {
                manager_epoch: "ab".repeat(16),
                lease_id: "cd".repeat(16),
                generation: 1,
            },
            review_sha256: receipt.body.input.review.review_sha256.clone(),
            encryption: receipt.body.encryption.clone(),
            custody_receipt: Some(receipt),
            recipient_custody_qualified: true,
            sender_authenticated: true,
            production_qualified: false,
            restore_permitted: false,
        };
        let meta = serde_json::to_vec(&metadata).unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend((meta.len() as u32).to_be_bytes());
        bytes.extend(meta);
        // Inert bytes test frame/hash/signature composition, not CMS parsing;
        // real OpenSSL CMS/recipient round trips have their own finite tests.
        bytes.extend(b"ciphertext");
        let actual = inspect(&mut std::io::Cursor::new(&bytes), &pin, &mut || Ok(())).unwrap();
        assert_eq!(actual.ciphertext, b"ciphertext");
        assert_eq!(actual.receipt.body.encryption, metadata.encryption);
        assert!(inspect(
            &mut std::io::Cursor::new(&bytes),
            &"ff".repeat(32),
            &mut || Ok(())
        )
        .is_err());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(inspect(&mut std::io::Cursor::new(changed), &pin, &mut || Ok(())).is_err());
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(inspect(&mut std::io::Cursor::new(changed), &pin, &mut || Ok(())).is_err());
        bytes.pop();
        assert!(inspect(&mut std::io::Cursor::new(bytes), &pin, &mut || Ok(())).is_err());
    }
}
