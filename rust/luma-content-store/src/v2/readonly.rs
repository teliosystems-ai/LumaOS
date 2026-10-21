//! Read-only Merkle lookup through an independently confined byte observer.
//! Returned bytes/proofs are DATA. The caller must select the root through its
//! genuine current boundary; an observer never supplies a semantic success bit.
use super::cursor::MapCursorBoundary;
use super::page::{Body, Page};
use super::*;

pub mod blob;
pub mod delta;
pub mod selection;

/// Implementations must retain their actual authenticated fixed transport and
/// invoke `check` during bounded waits and I/O. No generic path, write, signing,
/// root-selection or default-success operation is part of this interface.
pub trait ObservedPageReader {
    fn read_observed_page(
        &mut self,
        binding: &OwnerBinding,
        sha256: &str,
        maximum_bytes: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>>;
}

/// Collects and independently decodes precisely one Merkle search path. Local
/// held-filesystem lookup and the external observer use the identical parser.
pub(super) fn collect_lookup(
    root: &MapRoot,
    key: &str,
    mut read: impl FnMut(&PageRef) -> Result<Vec<u8>>,
) -> Result<LookupProof> {
    root.validate()?;
    digest(key)?;
    let mut pages = Vec::new();
    let mut next = root.page.clone();
    while let Some(reference) = next {
        if pages.len() >= usize::from(MAX_MAP_HEIGHT) + 1 {
            return Err("read-only Merkle lookup exceeds its finite depth".into());
        }
        let bytes = read(&reference)?;
        let page = Page::decode(&bytes, &root.binding, root.kind, &reference)?;
        let leaf = matches!(page.body, Body::Leaf { .. });
        next = match page.body {
            Body::Leaf { .. } => None,
            Body::Branch { children } => children
                .into_iter()
                .find(|p| p.first_key.as_str() <= key && key <= p.last_key.as_str()),
        };
        pages.push(bytes);
        if leaf {
            break;
        }
    }
    let proof = LookupProof {
        root: root.clone(),
        key: key.into(),
        pages,
    };
    proof.verify(root)?;
    Ok(proof)
}

fn current(root: &MapRoot, boundary: &mut impl MapCursorBoundary) -> Result<()> {
    boundary.current_map(root)?;
    boundary.check(Access::Inspect {
        binding: &root.binding,
    })?;
    boundary.current_map(root)
}

/// A bounded DATA proof only. Checks refresh the exact selected map, original
/// subject/grants and live resource context before/after admission, every reader
/// call and completion. The observer may not replace or authenticate the root.
pub fn lookup_current(
    root: &MapRoot,
    key: &str,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl MapCursorBoundary,
) -> Result<LookupProof> {
    root.validate()?;
    digest(key)?;
    budget.validate()?;
    if budget.write_bytes != 0 || budget.new_files != 0 {
        return Err("observed Merkle lookup cannot acquire write capacity".into());
    }
    current(root, boundary)?;
    boundary.admit(
        &root.binding,
        ResourceBudget {
            memory_bytes: 1024 * 1024,
            tasks: 1,
            read_bytes: budget.read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    current(root, boundary)?;
    let mut reserved = 0_u64;
    let proof = collect_lookup(root, key, |reference| {
        // Reserve a whole bounded response and its EOF probe BEFORE asking the
        // observer to read. Unused allowance is not a resource-release receipt.
        reserved = reserved
            .checked_add(MAX_PAGE_BYTES as u64 + 1)
            .ok_or("observed lookup read reservation overflow")?;
        if reserved > budget.read_bytes {
            return Err("observed lookup read reservation exhausted before I/O".into());
        }
        current(root, boundary)?;
        let mut check = || current(root, boundary);
        let bytes = reader.read_observed_page(
            &root.binding,
            &reference.sha256,
            MAX_PAGE_BYTES,
            &mut check,
        )?;
        check()?;
        if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
            return Err("observed page exceeds its exact bounded response".into());
        }
        Ok(bytes)
    })?;
    current(root, boundary)?;
    Ok(proof)
}

#[cfg(test)]
mod tests;
