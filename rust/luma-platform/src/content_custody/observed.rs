//! Read-only native C/observer composition. No prepared-root publisher,
//! attester, signing API or conversion from JSON into original authority.
use super::protocol::{OriginalCOperation, SourcePurpose};
use super::v2_publication::{PagedStore, SelectedOwner};
use super::*;
use crate::content_governed::observed_read::PageSource;
use luma_content_store::v2::{
    cursor::MapCursorBoundary,
    head::OwnerHeadV2,
    readonly::{
        self,
        blob::CurrentBlobBoundary,
        selection::{CurrentArtifactProofData, CurrentOwnerReadBoundary},
    },
    BlobReference, IoBudget, PhysicalInventory,
};
use luma_content_store::{Access, Boundary, ResourceBudget};
use std::cell::RefCell;
#[path = "observed/record.rs"]
mod record;
pub(super) fn require_output_observation(
    descriptor: &crate::service::content_output::Descriptor,
    audit: &Audit,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    record::require(descriptor, audit, check)
}

const PROOF_READ_BYTES: u64 = (3 * (luma_content_store::v2::MAX_MAP_HEIGHT as u64 + 1) + 2)
    * (luma_content_store::v2::MAX_PAGE_BYTES as u64 + 1);

#[derive(Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PageReply {
    Legacy {
        state: VerifiedState,
    },
    Paged {
        head_sha256: String,
        result: serde_json::Value,
    },
}

struct Current<'a, 'b, A: Checkpoint> {
    store: PagedStore<A>,
    original: &'a mut OriginalCOperation<'b>,
    source: PageSource,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
}
impl<A: Checkpoint> Current<'_, '_, A> {
    fn check(&mut self) -> Result<()> {
        self.original.check()?;
        self.source.check_original(self.original.audit())?;
        let source = self.original.source_binding();
        if source.purpose != SourcePurpose::ObservedRead
            || source.binding != *self.source.binding()
            || source.profile != self.source.profile()
            || source.storage_device != self.source.device()
            || crate::content_governed::source_digest(&source.profile)?
                != self.source.source_sha256()
            || source.worker_label != "luma-acquisition (enforce)"
        {
            return Err("observed read cannot borrow a different original C purpose/source".into());
        }
        let (store, original) = (&mut self.store, &mut self.original);
        match store.selected_owner(self.source.binding(), &mut || original.check())? {
            SelectedOwner::Paged { head, physical }
                if head == self.head && physical == self.physical =>
            {
                ()
            }
            _ => {
                return Err("observed read exact current C owner/physical selection changed".into())
            }
        }
        self.original.check()
    }
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.check()?;
        if binding != self.source.binding()
            || budget.tasks != 1
            || budget.memory_bytes > 64 * 1024 * 1024
            || budget.read_bytes > self.source.read_ceiling()
            || budget.write_bytes != 0
            || budget.additional_storage_bytes != 0
        {
            return Err("observed Page exceeds original finite readonly source/profile".into());
        }
        self.check()
    }
}
struct Maps<'s, 'a, 'b, A: Checkpoint> {
    shared: &'s RefCell<Current<'a, 'b, A>>,
}
impl<A: Checkpoint> Boundary for Maps<'_, '_, '_, A> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed C admission")?
            .admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        let mut current = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed C original check")?;
        current.check()?;
        match access {
            Access::Inspect { binding } if binding == current.source.binding() => current.check(),
            _ => Err("query-only C facade cannot mutate/recover or change owner".into()),
        }
    }
}
impl<A: Checkpoint> MapCursorBoundary for Maps<'_, '_, '_, A> {
    fn current_map(&mut self, root: &luma_content_store::v2::MapRoot) -> Result<()> {
        let mut current = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed C map selection")?;
        current.check()?;
        if !current.head.roots.all().contains(&root) {
            return Err("observed lookup root is not exact selected owner root".into());
        }
        current.check()
    }
}
impl<A: Checkpoint> CurrentOwnerReadBoundary for Maps<'_, '_, '_, A> {
    fn current_owner_head(&mut self, head: &OwnerHeadV2) -> Result<()> {
        let mut current = self
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed C owner selection")?;
        current.check()?;
        if head != &current.head {
            return Err("observed artifact proof substitutes selected owner head".into());
        }
        current.check()
    }
}
struct Blob<'s, 'a, 'b, A: Checkpoint> {
    maps: Maps<'s, 'a, 'b, A>,
    proof: &'s CurrentArtifactProofData,
}
impl<A: Checkpoint> Boundary for Blob<'_, '_, '_, A> {
    fn admit(&mut self, binding: &OwnerBinding, budget: ResourceBudget) -> Result<()> {
        self.maps.admit(binding, budget)
    }
    fn check(&mut self, access: Access<'_>) -> Result<()> {
        self.maps.check(access)
    }
}
impl<A: Checkpoint> CurrentBlobBoundary for Blob<'_, '_, '_, A> {
    fn current_blob(&mut self, reference: &BlobReference) -> Result<()> {
        let mut current = self
            .maps
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed C blob selection")?;
        current.check()?;
        // Reverify actual Merkle path and semantic object bytes against the
        // freshly C-selected head. Never recursively query the active reader.
        let selected = self.proof.verify_data_for_head(&current.head)?;
        if &selected.payload != reference || &selected.reference != current.source.expected() {
            return Err("observed blob is not original selected live artifact".into());
        }
        current.check()
    }
}

pub(super) fn with_page<T>(
    original: &mut OriginalCOperation<'_>,
    bytes: &[u8],
    deliver: impl FnOnce(PageReply, &mut dyn FnMut() -> Result<()>) -> Result<T>,
) -> Result<T> {
    original.check()?;
    let source = original.source_binding();
    if source.purpose != SourcePurpose::ObservedRead
        || source.worker_label != "luma-acquisition (enforce)"
    {
        return Err("observed Page requires actual original acquisition query".into());
    }
    let page = PageSource::parse(
        bytes,
        &source.profile,
        &source.storage_device,
        &source.binding,
    )?;
    page.check_original(original.audit())?;
    let mut live = || original.check();
    if format::probe(&Files::installed(), &mut live)? == format::Layout::Legacy {
        let mut legacy = Store::installed(&mut live)?;
        let state = legacy.selected(page.binding(), &mut live)?;
        let mut current = || {
            live()?;
            if legacy.selected(page.binding(), &mut live)? != state {
                return Err("legacy Page current C cut changed during reply".into());
            }
            live()
        };
        current()?;
        let result = deliver(
            PageReply::Legacy {
                state: state.clone(),
            },
            &mut current,
        )?;
        current()?;
        return Ok(result);
    }
    // An existing/damaged/partial paged namespace never falls back to V1.
    let mut store = PagedStore::installed(&mut live)?;
    let (head, physical) = match store.selected_owner(page.binding(), &mut live)? {
        SelectedOwner::Paged { head, physical } => (head, physical),
        _ => return Err("paged C Page requires a completed typed V2 owner selection".into()),
    };
    original.check()?;
    let context = crate::content_data_observer::Context {
        schema_version: 1,
        binding: head.binding.clone(),
        source_request_sha256: original.source_binding().request_sha256.clone(),
        source_profile: page.profile().into(),
        selected_before: head.clone(),
        selected_before_sha256: head.sha256()?,
        lease: original.source_binding().lease.clone(),
    };
    let expected = page.expected().clone();
    let read_ceiling = page.read_ceiling();
    let shared = RefCell::new(Current {
        store,
        original,
        source: page,
        head: head.clone(),
        physical,
    });
    let mut original_check = || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observer original callback")?
            .check()
    };
    let mut reader = crate::content_data_observer::Client::begin(context, &mut original_check)?;
    let mut maps = Maps { shared: &shared };
    let proof = readonly::selection::resolve_current(
        &head,
        &expected,
        IoBudget {
            read_bytes: PROOF_READ_BYTES,
            write_bytes: 0,
            new_files: 0,
        },
        &mut reader,
        &mut maps,
    )?;
    let selected = proof.verify_data_for_head(&head)?;
    let remaining = read_ceiling
        .checked_sub(PROOF_READ_BYTES)
        .filter(|n| *n > 0)
        .ok_or("observed Page has no remaining finite source reservation")?;
    let mut blob = Blob {
        maps: Maps { shared: &shared },
        proof: &proof,
    };
    let envelope = readonly::blob::read_current(
        &selected.payload,
        IoBudget {
            read_bytes: remaining,
            write_bytes: 0,
            new_files: 0,
        },
        &mut reader,
        &mut blob,
    )?;
    let version = proof.reopen_data_for_head(&head, &envelope)?;
    reader.finish(&mut || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observer End check")?
            .check()
    })?;
    let mut current = shared
        .try_borrow_mut()
        .map_err(|_| "reentrant observed result")?;
    current.check()?;
    let result = current.source.result(&version)?;
    current.check()?;
    record::remember(&mut current, &result)?;
    current.check()?;
    drop(current);
    let mut check = || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant observed Page reply fence")?
            .check()
    };
    check()?;
    let value = deliver(
        PageReply::Paged {
            head_sha256: head.sha256()?,
            result,
        },
        &mut check,
    )?;
    check()?;
    Ok(value)
}
