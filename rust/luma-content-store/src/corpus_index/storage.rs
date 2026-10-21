//! Shared algorithm read seam. The remote backend has no path, creator,
//! reservation-release or write operation. Every returned member is rehashed
//! under the original live boundary, including every parsed-cache reuse.
use super::*;
use crate::v2::readonly::ObservedPageReader;
use crate::v2::{
    cursor::{CursorPages, MapCursor, MapCursorBoundary, MapWindow},
    BlobReference, LookupProof, PageObservation,
};
use std::cell::RefCell;

/// An observation is DATA, not a current selector or authority. In particular a
/// remote read never fabricates the filesystem-only held-descriptor proof.
pub struct IndexObservation {
    kind: Observation,
}
enum Observation {
    Filesystem(PageObservation),
    Observed {
        binding: luma_content::OwnerBinding,
        sha256: String,
        bytes: u64,
    },
}

/// Read-only algorithm interface. Preparation still requires a real ObjectStore
/// and its original mutation/allocation boundary; no remote writer exists.
pub trait IndexReadStore {
    fn read_page(
        &self,
        sha256: &str,
        budget: IoBudget,
        boundary: &mut dyn Boundary,
    ) -> Result<Vec<u8>>;
    fn read_page_observed(
        &self,
        sha256: &str,
        budget: IoBudget,
        boundary: &mut dyn Boundary,
    ) -> Result<(Vec<u8>, IndexObservation)>;
    fn check_page_observation(
        &self,
        observation: &IndexObservation,
        budget: IoBudget,
        boundary: &mut dyn Boundary,
    ) -> Result<u64>;
    fn read_blob(
        &self,
        reference: &BlobReference,
        budget: IoBudget,
        boundary: &mut dyn Boundary,
    ) -> Result<Vec<u8>>;
    fn lookup_map(
        &self,
        root: &MapRoot,
        key: &str,
        budget: IoBudget,
        boundary: &mut dyn Boundary,
    ) -> Result<LookupProof>;
    fn scan_map_window(
        &self,
        root: &MapRoot,
        cursor: &MapCursor,
        maximum: usize,
        budget: IoBudget,
        boundary: &mut dyn MapCursorBoundary,
    ) -> Result<MapWindow>;
}
struct Forward<'a>(&'a mut dyn Boundary);
impl Boundary for Forward<'_> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        self.0.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.0.check(access)
    }
}
struct ForwardMap<'a>(&'a mut dyn MapCursorBoundary);
impl Boundary for ForwardMap<'_> {
    fn admit(
        &mut self,
        binding: &luma_content::OwnerBinding,
        budget: ResourceBudget,
    ) -> Result<()> {
        self.0.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.0.check(access)
    }
}
impl MapCursorBoundary for ForwardMap<'_> {
    fn current_map(&mut self, root: &MapRoot) -> Result<()> {
        self.0.current_map(root)
    }
}
impl IndexReadStore for ObjectStore {
    fn read_page(&self, sha: &str, budget: IoBudget, b: &mut dyn Boundary) -> Result<Vec<u8>> {
        ObjectStore::read_page(self, sha, budget, &mut Forward(b))
    }
    fn read_page_observed(
        &self,
        sha: &str,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<(Vec<u8>, IndexObservation)> {
        let (bytes, pin) = ObjectStore::read_page_observed(self, sha, budget, &mut Forward(b))?;
        Ok((
            bytes,
            IndexObservation {
                kind: Observation::Filesystem(pin),
            },
        ))
    }
    fn check_page_observation(
        &self,
        pin: &IndexObservation,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<u64> {
        match &pin.kind {
            Observation::Filesystem(pin) => {
                ObjectStore::check_page_observation(self, pin, budget, &mut Forward(b))
            }
            Observation::Observed { .. } => {
                Err("remote DATA cannot stand in for a held filesystem observation".into())
            }
        }
    }
    fn read_blob(
        &self,
        reference: &BlobReference,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<Vec<u8>> {
        ObjectStore::read_blob(self, reference, budget, &mut Forward(b))
    }
    fn lookup_map(
        &self,
        root: &MapRoot,
        key: &str,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<LookupProof> {
        ObjectStore::lookup_map(self, root, key, budget, &mut Forward(b))
    }
    fn scan_map_window(
        &self,
        root: &MapRoot,
        cursor: &MapCursor,
        maximum: usize,
        budget: IoBudget,
        b: &mut dyn MapCursorBoundary,
    ) -> Result<MapWindow> {
        ObjectStore::scan_map_window(self, root, cursor, maximum, budget, &mut ForwardMap(b))
    }
}

/// The reader must be the actual independently confined fixed observer. This
/// object retains no authorization and performs no current-root selection.
pub struct ObservedIndexStore<R: ObservedPageReader> {
    binding: luma_content::OwnerBinding,
    reader: RefCell<R>,
}
impl<R: ObservedPageReader> ObservedIndexStore<R> {
    pub fn new(binding: &luma_content::OwnerBinding, reader: R) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            binding: binding.clone(),
            reader: RefCell::new(reader),
        })
    }
    fn readonly(&self, budget: IoBudget, b: &mut dyn Boundary, memory: u64) -> Result<()> {
        budget.validate()?;
        if budget.write_bytes != 0 || budget.new_files != 0 {
            return Err("observer index storage cannot allocate or write".into());
        }
        b.check(Access::Inspect {
            binding: &self.binding,
        })?;
        b.admit(
            &self.binding,
            ResourceBudget {
                memory_bytes: memory,
                tasks: 1,
                read_bytes: budget.read_bytes,
                write_bytes: 0,
                additional_storage_bytes: 0,
            },
        )?;
        b.check(Access::Inspect {
            binding: &self.binding,
        })
    }
    fn member(&self, sha: &str, remaining: &mut u64, b: &mut dyn Boundary) -> Result<Vec<u8>> {
        hash(sha)?;
        let reserve = MAX_INDEX_PAGE_BYTES as u64 + 1;
        if *remaining < reserve {
            return Err("observed index read exhausted before private I/O".into());
        }
        b.check(Access::Inspect {
            binding: &self.binding,
        })?;
        let mut check = || {
            b.check(Access::Inspect {
                binding: &self.binding,
            })
        };
        let bytes = self
            .reader
            .try_borrow_mut()
            .map_err(|_| "recursive observer index read is forbidden")?
            .read_observed_page(&self.binding, sha, MAX_INDEX_PAGE_BYTES, &mut check)?;
        check()?;
        if bytes.is_empty()
            || bytes.len() > MAX_INDEX_PAGE_BYTES
            || luma_content::sha256(&bytes) != sha
        {
            return Err("actual observed index member length/hash differs".into());
        }
        *remaining = remaining
            .checked_sub(bytes.len() as u64 + 1)
            .ok_or("observed index read debit overflow")?;
        Ok(bytes)
    }
}
impl<R: ObservedPageReader> IndexReadStore for ObservedIndexStore<R> {
    fn read_page(&self, sha: &str, budget: IoBudget, b: &mut dyn Boundary) -> Result<Vec<u8>> {
        self.readonly(budget, b, 1024 * 1024)?;
        let mut remaining = budget.read_bytes;
        let bytes = self.member(sha, &mut remaining, b)?;
        b.check(Access::Inspect {
            binding: &self.binding,
        })?;
        Ok(bytes)
    }
    fn read_page_observed(
        &self,
        sha: &str,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<(Vec<u8>, IndexObservation)> {
        let bytes = self.read_page(sha, budget, b)?;
        let pin = IndexObservation {
            kind: Observation::Observed {
                binding: self.binding.clone(),
                sha256: sha.into(),
                bytes: bytes.len() as u64,
            },
        };
        Ok((bytes, pin))
    }
    fn check_page_observation(
        &self,
        pin: &IndexObservation,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<u64> {
        let Observation::Observed {
            binding,
            sha256,
            bytes: expected,
        } = &pin.kind
        else {
            return Err("filesystem observation is not an observed-reader cache member".into());
        };
        if *binding != self.binding {
            return Err("observed cached member belongs to another owner".into());
        }
        let bytes = self.read_page(sha256, budget, b)?;
        if bytes.len() as u64 != *expected {
            return Err("observed cached member length changed".into());
        }
        Ok(bytes.len() as u64 + 1)
    }
    fn read_blob(
        &self,
        reference: &BlobReference,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<Vec<u8>> {
        reference.validate()?;
        if reference.binding != self.binding {
            return Err("observed index blob owner differs".into());
        }
        self.readonly(
            budget,
            b,
            reference
                .bytes
                .checked_add(1024 * 1024)
                .ok_or("observed blob memory overflow")?,
        )?;
        let mut remaining = budget.read_bytes;
        let bytes =
            crate::v2::readonly::blob::collect_range_data(reference, 0, reference.bytes, |sha| {
                self.member(sha, &mut remaining, b)
            })?;
        if luma_content::sha256(&bytes) != reference.sha256 {
            return Err("observed index whole-blob commitment differs".into());
        }
        b.check(Access::Inspect {
            binding: &self.binding,
        })?;
        Ok(bytes)
    }
    fn lookup_map(
        &self,
        root: &MapRoot,
        key: &str,
        budget: IoBudget,
        b: &mut dyn Boundary,
    ) -> Result<LookupProof> {
        root.validate()?;
        if root.binding != self.binding {
            return Err("observed index map owner differs".into());
        }
        self.readonly(budget, b, 4 * 1024 * 1024)?;
        let mut remaining = budget.read_bytes;
        let proof = crate::v2::readonly::collect_lookup(root, key, |reference| {
            self.member(&reference.sha256, &mut remaining, b)
        })?;
        b.check(Access::Inspect {
            binding: &self.binding,
        })?;
        Ok(proof)
    }
    fn scan_map_window(
        &self,
        root: &MapRoot,
        cursor: &MapCursor,
        maximum: usize,
        budget: IoBudget,
        b: &mut dyn MapCursorBoundary,
    ) -> Result<MapWindow> {
        root.validate()?;
        if root.binding != self.binding {
            return Err("observed index cursor owner differs".into());
        }
        b.current_map(root)?;
        let mut forwarded = ForwardMap(b);
        self.readonly(budget, &mut forwarded, 4 * 1024 * 1024)?;
        struct Pages<'a, 'b, R: ObservedPageReader> {
            store: &'a ObservedIndexStore<R>,
            root: &'a MapRoot,
            b: &'b mut dyn MapCursorBoundary,
            remaining: u64,
        }
        impl<R: ObservedPageReader> crate::v2::cursor::CursorPages for Pages<'_, '_, R> {
            fn check(&mut self) -> Result<()> {
                self.b.current_map(self.root)?;
                self.b.check(Access::Inspect {
                    binding: &self.root.binding,
                })?;
                self.b.current_map(self.root)
            }
            fn read(&mut self, reference: &crate::v2::PageRef) -> Result<Vec<u8>> {
                self.check()?;
                let bytes = self.store.member(
                    &reference.sha256,
                    &mut self.remaining,
                    &mut ForwardMap(self.b),
                )?;
                self.check()?;
                Ok(bytes)
            }
        }
        let mut pages = Pages {
            store: self,
            root,
            b: forwarded.0,
            remaining: budget.read_bytes,
        };
        let window = crate::v2::cursor::collect_window(root, cursor, maximum, &mut pages)?;
        pages.check()?;
        Ok(window)
    }
}
