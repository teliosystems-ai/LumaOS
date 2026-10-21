//! Bounded blob verification over the fixed observer transport. The original
//! operation boundary, not the observer or any serialized descriptor, selects
//! the exact current source and authorizes every read.
use super::*;

pub trait CurrentBlobBoundary: Boundary {
    /// Must independently verify this exact descriptor against the selected
    /// owner/corpus/lifecycle state and original live Read grants. No cached
    /// receipt, hash equality alone or caller JSON may supply that decision.
    fn current_blob(&mut self, reference: &BlobReference) -> Result<()>;
}

fn current(reference: &BlobReference, boundary: &mut impl CurrentBlobBoundary) -> Result<()> {
    boundary.current_blob(reference)?;
    boundary.check(Access::Inspect {
        binding: &reference.binding,
    })?;
    boundary.current_blob(reference)
}

/// Verifies the complete source content SHA in addition to each Merkle member.
/// Successful bytes remain DATA; this API does not publish a head or release a
/// storage reservation. Empty sources still require fresh selected authority.
pub fn read_current(
    reference: &BlobReference,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl CurrentBlobBoundary,
) -> Result<Vec<u8>> {
    let bytes = read(reference, 0, reference.bytes, budget, reader, boundary)?;
    if luma_content::sha256(&bytes) != reference.sha256 {
        return Err("observed whole blob content commitment differs".into());
    }
    current(reference, boundary)?;
    Ok(bytes)
}

/// Exact snippet range, at most one page. This proves the selected Merkle path,
/// not the whole-source SHA: callers requiring whole-source Read use read_current.
pub fn read_range_current(
    reference: &BlobReference,
    offset: u64,
    length: u64,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl CurrentBlobBoundary,
) -> Result<Vec<u8>> {
    if length > MAX_PAGE_BYTES as u64 {
        return Err("observed snippet range exceeds one page".into());
    }
    read(reference, offset, length, budget, reader, boundary)
}

fn read(
    reference: &BlobReference,
    offset: u64,
    length: u64,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl CurrentBlobBoundary,
) -> Result<Vec<u8>> {
    reference.validate()?;
    budget.validate()?;
    if budget.write_bytes != 0
        || budget.new_files != 0
        || offset
            .checked_add(length)
            .map_or(true, |n| n > reference.bytes)
    {
        return Err("observed blob requires an exact read-only range/budget".into());
    }
    current(reference, boundary)?;
    boundary.admit(
        &reference.binding,
        ResourceBudget {
            memory_bytes: length
                .checked_add(1024 * 1024)
                .ok_or("observed blob memory overflow")?,
            tasks: 1,
            read_bytes: budget.read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    current(reference, boundary)?;
    let mut reserved = 0_u64;
    let bytes = super::super::objects::collect_blob_range(reference, offset, length, |sha| {
        reserved = reserved
            .checked_add(MAX_PAGE_BYTES as u64 + 1)
            .ok_or("observed blob read reservation overflow")?;
        if reserved > budget.read_bytes {
            return Err("observed blob read reservation exhausted before I/O".into());
        }
        current(reference, boundary)?;
        let mut check = || current(reference, boundary);
        let bytes =
            reader.read_observed_page(&reference.binding, sha, MAX_PAGE_BYTES, &mut check)?;
        check()?;
        Ok(bytes)
    })?;
    current(reference, boundary)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
