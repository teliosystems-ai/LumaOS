//! Deterministic read-only map-delta replay through confined byte observation.
//! Reuses the exact local writer's split/packing/CAS algorithm. Proposed roots
//! and returned results remain DATA, never current publication or allocation.
use super::super::map::{derive_delta, MapIo};
use super::*;

pub trait CurrentDeltaBoundary: MapCursorBoundary {
    /// Independently check the original reviewed operation, exact base and
    /// proposed edits/root, live subject/grants and resource generation. The
    /// proposed next root is NOT selected merely by passing this check.
    fn current_delta(
        &mut self,
        base: &MapRoot,
        edits: &[MapEdit],
        proposed: &MapRoot,
    ) -> Result<()>;
}

struct ObservedDelta<'a, R: ObservedPageReader, B: CurrentDeltaBoundary> {
    base: &'a MapRoot,
    proposed: &'a MapRoot,
    edits: &'a [MapEdit],
    reader: &'a mut R,
    boundary: &'a mut B,
    reserved: u64,
    maximum: u64,
}
impl<R: ObservedPageReader, B: CurrentDeltaBoundary> MapIo for ObservedDelta<'_, R, B> {
    fn check(&mut self) -> Result<()> {
        self.boundary
            .current_delta(self.base, self.edits, self.proposed)?;
        self.boundary.current_map(self.base)?;
        self.boundary.check(Access::Inspect {
            binding: &self.base.binding,
        })?;
        self.boundary.current_map(self.base)?;
        self.boundary
            .current_delta(self.base, self.edits, self.proposed)
    }
    fn read(&mut self, sha: &str) -> Result<Vec<u8>> {
        digest(sha)?;
        self.reserved = self
            .reserved
            .checked_add(MAX_PAGE_BYTES as u64 + 1)
            .ok_or("observed delta reservation overflow")?;
        if self.reserved > self.maximum {
            return Err("observed delta reservation exhausted before I/O".into());
        }
        self.check()?;
        let Self {
            base,
            proposed,
            edits,
            reader,
            boundary,
            ..
        } = self;
        let mut check = || {
            boundary.current_delta(base, edits, proposed)?;
            boundary.current_map(base)?;
            boundary.check(Access::Inspect {
                binding: &base.binding,
            })?;
            boundary.current_map(base)?;
            boundary.current_delta(base, edits, proposed)
        };
        let bytes = reader.read_observed_page(&base.binding, sha, MAX_PAGE_BYTES, &mut check)?;
        check()?;
        if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES || luma_content::sha256(&bytes) != sha {
            return Err("observed map delta member hash/length differs".into());
        }
        Ok(bytes)
    }
    fn write(&mut self, _bytes: &[u8]) -> Result<()> {
        Err("observed map delta verifier cannot write private content".into())
    }
}

pub fn verify_current(
    base: &MapRoot,
    edits: &[MapEdit],
    proposed: &MapRoot,
    budget: IoBudget,
    reader: &mut impl ObservedPageReader,
    boundary: &mut impl CurrentDeltaBoundary,
) -> Result<MapRoot> {
    base.validate()?;
    proposed.validate()?;
    budget.validate()?;
    if budget.write_bytes != 0
        || budget.new_files != 0
        || proposed.binding != base.binding
        || proposed.kind != base.kind
        || edits.is_empty()
        || edits.len() > MAX_MAP_EDITS
    {
        return Err("observed delta retargets its owner/map or read-only profile".into());
    }
    let mut io = ObservedDelta {
        base,
        proposed,
        edits,
        reader,
        boundary,
        reserved: 0,
        maximum: budget.read_bytes,
    };
    io.check()?;
    io.boundary.admit(
        &base.binding,
        ResourceBudget {
            memory_bytes: 192 * 1024 * 1024,
            tasks: 1,
            read_bytes: budget.read_bytes,
            write_bytes: 0,
            additional_storage_bytes: 0,
        },
    )?;
    io.check()?;
    // This includes actual readback of EVERY derived page, even an intermediate
    // or split sibling containing only old keys, not just the final root path.
    let derived = derive_delta(base, edits, &mut io, false, true)?;
    if derived != *proposed {
        return Err("observed map delta differs from the exact reviewed proposal".into());
    }
    io.check()?;
    Ok(derived)
}

#[cfg(test)]
mod tests;
