//! Typed current/live artifact proof DATA. Retaining verified Merkle bytes
//! avoids recursive observer RPCs while a chunk's original check is running.
//! No live C/NV/account/grant/lease observation is retained or manufactured.
use super::*;
use crate::corpus_index::CorpusRecord;
use crate::v2::head::OwnerHeadV2;
use crate::v2::lifecycle::LifecycleState;
use crate::v2::owner::ArtifactValue;
use luma_content::{ArtifactVersion, VersionReference};

pub trait CurrentOwnerReadBoundary: MapCursorBoundary {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()>;
}

/// Descriptive proof bytes only. This type cannot replace current C selection.
/// It has no decoder/Clone; callers cannot accidentally decode it as a grant.
pub struct CurrentArtifactProofData {
    head_sha256: String,
    expected: VersionReference,
    artifacts: LookupProof,
    artifact_value: Vec<u8>,
    lifecycle: LookupProof,
    lifecycle_value: Vec<u8>,
    corpus: LookupProof,
}
/// Independently reverified DATA. Only the caller's fresh original boundary
/// decides whether the selected owner/reference may actually be read.
pub struct CurrentArtifactData {
    pub reference: VersionReference,
    pub payload: BlobReference,
    pub lifecycle: LifecycleState,
    pub corpus: CorpusRecord,
}
fn member<T: for<'de> Deserialize<'de> + Serialize>(
    proof: &LookupProof,
    root: &MapRoot,
    key: &str,
) -> Result<T> {
    if proof.key != key {
        return Err("current artifact proof retargets selected map key".into());
    }
    let bytes = proof
        .verify(root)?
        .ok_or("selected current artifact member missing")?;
    canonical(&bytes, MAX_VALUE_BYTES)
}
impl CurrentArtifactProofData {
    pub fn from_proofs(
        head: &OwnerHeadV2,
        expected: &VersionReference,
        artifacts: LookupProof,
        artifact_value: Vec<u8>,
        lifecycle: LookupProof,
        lifecycle_value: Vec<u8>,
        corpus: LookupProof,
    ) -> Result<Self> {
        let value = Self {
            head_sha256: head.sha256()?,
            expected: expected.clone(),
            artifacts,
            artifact_value,
            lifecycle,
            lifecycle_value,
            corpus,
        };
        value.verify_data_for_head(head)?;
        Ok(value)
    }
    pub fn reference(&self) -> &VersionReference {
        &self.expected
    }
    /// Pure verification, NOT current selection. Runtime adapters must pass the
    /// freshly selected C head and retain original authorization around this.
    pub fn verify_data_for_head(&self, head: &OwnerHeadV2) -> Result<CurrentArtifactData> {
        head.validate()?;
        crate::collections::reference(&self.expected)?;
        if head.sha256()? != self.head_sha256 {
            return Err("retained artifact proof is stale for current C head".into());
        }
        let artifact = &self.expected.artifact_id;
        let semantic = |proof: &LookupProof, root: &MapRoot, bytes: &[u8]| -> Result<Vec<u8>> {
            if proof.key != root.key(artifact.as_bytes())? {
                return Err("semantic owner proof retargets artifact key".into());
            }
            let reference_bytes = proof
                .verify(root)?
                .ok_or("selected semantic member absent")?;
            let _: crate::v2::owner::ValueRef = canonical(&reference_bytes, MAX_VALUE_BYTES)?;
            // decode_semantic_value supplies the SAME local owner's parser.
            if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
                return Err("semantic member exceeds bounded page".into());
            }
            Ok(reference_bytes)
        };
        let current: ArtifactValue = crate::v2::owner::decode_semantic_value(
            &semantic(&self.artifacts, &head.roots.artifacts, &self.artifact_value)?,
            &self.artifact_value,
        )?;
        let lifecycle: LifecycleState = crate::v2::owner::decode_semantic_value(
            &semantic(
                &self.lifecycle,
                &head.roots.lifecycle,
                &self.lifecycle_value,
            )?,
            &self.lifecycle_value,
        )?;
        let corpus: CorpusRecord = member(
            &self.corpus,
            &head.roots.corpus,
            &head.roots.corpus.corpus_key(artifact)?,
        )?;
        current.payload.validate()?;
        lifecycle.validate()?;
        corpus.validate()?;
        if current.reference != self.expected
            || current.payload.binding != head.binding
            || current.payload.bytes > luma_content::MAX_ENVELOPE_BYTES as u64
            || lifecycle.version != self.expected
            || lifecycle.status != crate::LifecycleStatus::Live
            || corpus.reference != self.expected
            || corpus.lifecycle_revision != lifecycle.revision
            || corpus.lifecycle_state_sha256 != lifecycle.state_sha256
        {
            return Err("current artifact/corpus/live-lifecycle/blob descriptors disagree".into());
        }
        Ok(CurrentArtifactData {
            reference: current.reference,
            payload: current.payload,
            lifecycle,
            corpus,
        })
    }
    /// Reopens actual complete envelope bytes and checks their native reference,
    /// owner, format, content length and corpus commitments. Still returns DATA.
    pub fn reopen_data_for_head(
        &self,
        head: &OwnerHeadV2,
        bytes: &[u8],
    ) -> Result<ArtifactVersion> {
        let current = self.verify_data_for_head(head)?;
        if bytes.len() as u64 != current.payload.bytes
            || luma_content::sha256(bytes) != current.payload.sha256
        {
            return Err("observed artifact envelope differs from selected blob".into());
        }
        let version = luma_content::reopen(bytes, &head.binding)?;
        if version.reference()? != current.reference
            || version.receipt().format != current.corpus.format
            || version.content().len() as u64 != current.corpus.content_bytes
        {
            return Err(
                "observed artifact envelope does not reconstruct selected corpus/reference".into(),
            );
        }
        Ok(version)
    }
}
fn current(head: &OwnerHeadV2, boundary: &mut impl CurrentOwnerReadBoundary) -> Result<()> {
    boundary.current_owner_head(head)?;
    boundary.check(Access::Inspect {
        binding: &head.binding,
    })?;
    boundary.current_owner_head(head)
}
/// Reads three exact paths plus two indirection members, charging the total
/// reservation. No whole-corpus scan, guessed latest or automatic renewal.
pub fn resolve_current(
    head: &OwnerHeadV2,
    expected: &VersionReference,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl CurrentOwnerReadBoundary,
) -> Result<CurrentArtifactProofData> {
    head.validate()?;
    crate::collections::reference(expected)?;
    budget.validate()?;
    if budget.write_bytes != 0 || budget.new_files != 0 {
        return Err("current artifact resolution is strictly read-only".into());
    }
    current(head, boundary)?;
    let artifact = &expected.artifact_id;
    let mut charged = 0_u64;
    let mut read = |root: &MapRoot, key: String| -> Result<LookupProof> {
        current(head, boundary)?;
        let remaining = budget
            .read_bytes
            .checked_sub(charged)
            .filter(|n| *n > 0)
            .ok_or("current artifact proof budget exhausted before observer I/O")?;
        let proof = lookup_current(
            root,
            &key,
            IoBudget {
                read_bytes: remaining,
                write_bytes: 0,
                new_files: 0,
            },
            reader,
            boundary,
        )?;
        charged = charged
            .checked_add(
                (proof.pages.len() as u64)
                    .checked_mul(MAX_PAGE_BYTES as u64 + 1)
                    .ok_or("current artifact proof charge overflow")?,
            )
            .ok_or("current artifact proof charge overflow")?;
        if charged > budget.read_bytes {
            return Err("current artifact proof exceeded total read reservation".into());
        }
        current(head, boundary)?;
        Ok(proof)
    };
    let artifacts = read(
        &head.roots.artifacts,
        head.roots.artifacts.key(artifact.as_bytes())?,
    )?;
    let lifecycle = read(
        &head.roots.lifecycle,
        head.roots.lifecycle.key(artifact.as_bytes())?,
    )?;
    let corpus = read(&head.roots.corpus, head.roots.corpus.corpus_key(artifact)?)?;
    let mut semantic_read = |proof: &LookupProof, root: &MapRoot| -> Result<Vec<u8>> {
        let reference: crate::v2::owner::ValueRef =
            member(proof, root, &root.key(artifact.as_bytes())?)?;
        digest(&reference.sha256)?;
        charged = charged
            .checked_add(MAX_PAGE_BYTES as u64 + 1)
            .ok_or("selected semantic read charge overflow")?;
        if charged > budget.read_bytes {
            return Err("selected semantic read reservation exhausted before I/O".into());
        }
        current(head, boundary)?;
        let mut check = || current(head, boundary);
        let bytes = reader.read_observed_page(
            &head.binding,
            &reference.sha256,
            MAX_PAGE_BYTES,
            &mut check,
        )?;
        check()?;
        if bytes.is_empty()
            || bytes.len() > MAX_PAGE_BYTES
            || luma_content::sha256(&bytes) != reference.sha256
        {
            return Err("observed semantic member differs from selected ValueRef".into());
        }
        Ok(bytes)
    };
    let artifact_value = semantic_read(&artifacts, &head.roots.artifacts)?;
    let lifecycle_value = semantic_read(&lifecycle, &head.roots.lifecycle)?;
    let value = CurrentArtifactProofData::from_proofs(
        head,
        expected,
        artifacts,
        artifact_value,
        lifecycle,
        lifecycle_value,
        corpus,
    )?;
    current(head, boundary)?;
    Ok(value)
}

#[cfg(test)]
mod tests;
