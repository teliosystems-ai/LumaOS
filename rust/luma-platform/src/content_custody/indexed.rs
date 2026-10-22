//! Actual C-selected owner index inspection, query and effect REVIEW only.
//! No write, reservation release, C selection or grant can originate here.
use super::protocol::{OriginalCOperation, SourcePurpose};
use super::v2_publication::{
    index::{Leaf, Selection},
    PagedStore,
};
use super::*;
use crate::content_data_observer::{Client, Context};
use crate::content_index::{
    self,
    builder::FixedBuilder,
    phase,
    request::{Input, Mode, Operation},
    state::{Job, Stage},
};
use luma_content_store::corpus_index::{
    storage::{IndexReadStore, ObservedIndexStore},
    BuilderIdentity, CorpusContent, CorpusIndexBoundary, CorpusRecord,
};
use luma_content_store::v2::{
    head::OwnerHeadV2,
    readonly::{
        blob::{self, CurrentBlobBoundary},
        selection::{self, CurrentArtifactProofData, CurrentOwnerReadBoundary},
        ObservedPageReader,
    },
    IoBudget, MapRoot, PhysicalInventory,
};
use luma_content_store::{Access, Boundary, ResourceBudget};
use std::cell::RefCell;
#[path = "indexed/boundary.rs"]
mod boundary;
#[path = "indexed/compute.rs"]
mod compute;
#[cfg(test)]
#[path = "indexed/tests.rs"]
mod tests;
use boundary::Gate;

const PROOF_READ: u64 = 32 * 1024 * 1024;
struct ReturnUnusedHeap;
impl Drop for ReturnUnusedHeap {
    fn drop(&mut self) {
        // Same-process allocator hint only: it cannot acknowledge a drain or
        // release any reservation. Manager's actual cgroup readback is sole
        // evidence that the temporary 256MiB allowance can return to128MiB.
        unsafe {
            libc::malloc_trim(0);
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexReply {
    pub(super) selection_sha256: String,
    pub(super) result: serde_json::Value,
}

pub(super) fn selection_sha256(value: &Selection) -> Result<String> {
    digest(&value.descriptor_sha256)?;
    Ok(luma_content::sha256(&serde_json::to_vec(&(
        "luma-native-current-owner-index-v2",
        value.owner.sha256()?,
        value.leaf.as_ref().map(Leaf::sha256).transpose()?,
    ))?))
}

struct Current<'a, 'b, A: Checkpoint> {
    store: PagedStore<A>,
    original: &'a mut OriginalCOperation<'b>,
    input: Input,
    profile: String,
    head: OwnerHeadV2,
    physical: PhysicalInventory,
    leaf: Option<Leaf>,
    selection_sha256: String,
    builder: FixedBuilder,
    job: Option<Job>,
    remaining_read: u64,
}
impl<A: Checkpoint> Current<'_, '_, A> {
    fn check(&mut self) -> Result<()> {
        require_original_source(self.original, &self.input, &self.profile)?;
        self.builder.check(|| self.original.check())?;
        let (store, original) = (&mut self.store, &mut self.original);
        let selected = store.selected_index(&self.input.binding, &mut || original.check())?;
        if selected.owner != self.head
            || selected.physical != self.physical
            || selected.leaf != self.leaf
            || selection_sha256(&selected)? != self.selection_sha256
        {
            return Err("index current owner/physical/generation/job/preparation changed".into());
        }
        self.original.check()
    }
    fn spend(&mut self, bytes: u64) -> Result<()> {
        self.check()?;
        reserve_read(&mut self.remaining_read, bytes)?;
        self.check()
    }
}
fn reserve_read(remaining: &mut u64, bytes: u64) -> Result<()> {
    if bytes == 0 || bytes > 16385 {
        return Err("index actual read reserve is not one bounded page plus EOF".into());
    }
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or("aggregate original index read reservation exhausted before private IO")?;
    Ok(())
}
type Shared<'a, 'b, A> = RefCell<Current<'a, 'b, A>>;

fn require_original_source(
    original: &mut OriginalCOperation<'_>,
    input: &Input,
    profile: &str,
) -> Result<crate::finite_grants::Use> {
    original.check()?;
    let source = original.source_binding();
    let selected = content_index::request::parse_profile(profile)?;
    let expected = content_index::scope::original_usage(
        profile,
        &source.storage_device,
        &input.binding,
        &input.sha256()?,
        true,
    )?;
    original.audit().validate()?;
    if source.purpose != SourcePurpose::IndexRead
        || source.binding != input.binding
        || source.profile != profile
        || source.worker_label != "luma-acquisition (enforce)"
        || selected.mode.mutates()
        || original.audit().usage != expected
        || original.audit().subject != input.binding.owner
        || original.audit().subject_generation != input.binding.owner_generation
        || original.audit().operation_id.is_none()
    {
        return Err("index read loses genuine original finite subject/source/profile".into());
    }
    original.check()?;
    Ok(expected)
}

struct Reader<'s, 'a, 'b, 'c, A: Checkpoint> {
    shared: &'s Shared<'a, 'b, A>,
    client: &'s RefCell<Client<'c>>,
}
impl<A: Checkpoint> ObservedPageReader for Reader<'_, '_, '_, '_, A> {
    fn read_observed_page(
        &mut self,
        binding: &OwnerBinding,
        sha256: &str,
        maximum: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        {
            let mut current = self
                .shared
                .try_borrow_mut()
                .map_err(|_| "reentrant original index read reservation")?;
            if binding != &current.head.binding || maximum == 0 || maximum > 16384 {
                return Err(
                    "index observer read changes selected owner or finite page bound".into(),
                );
            }
            current.spend(maximum as u64 + 1)?;
        }
        let mut actual = self
            .client
            .try_borrow_mut()
            .map_err(|_| "reentrant actual index observer")?;
        let bytes = actual.read_observed_page(binding, sha256, maximum, check)?;
        drop(actual);
        self.shared
            .try_borrow_mut()
            .map_err(|_| "reentrant index post-read fence")?
            .check()?;
        check()?;
        Ok(bytes)
    }
}

fn proof<'s, 'a, 'b, 'c, A: Checkpoint>(
    gate: &mut Gate<'s, 'a, 'b, 'c, A>,
    expected: &VersionReference,
) -> Result<CurrentArtifactProofData> {
    let head = {
        let mut c = gate
            .shared
            .try_borrow_mut()
            .map_err(|_| "reentrant index source proof")?;
        c.check()?;
        c.head.clone()
    };
    let mut reader = Reader {
        shared: gate.shared,
        client: gate.client,
    };
    selection::resolve_current(
        &head,
        expected,
        IoBudget {
            read_bytes: PROOF_READ,
            write_bytes: 0,
            new_files: 0,
        },
        &mut reader,
        gate,
    )
}

struct Content<'s, 'a, 'b, 'c, A: Checkpoint> {
    gate: Gate<'s, 'a, 'b, 'c, A>,
}
struct Artifact<'s, 'p, 'a, 'b, 'c, A: Checkpoint> {
    gate: Gate<'s, 'a, 'b, 'c, A>,
    proof: &'p CurrentArtifactProofData,
}
impl<A: Checkpoint> Boundary for Artifact<'_, '_, '_, '_, '_, A> {
    fn admit(&mut self, b: &OwnerBinding, r: ResourceBudget) -> Result<()> {
        self.gate.admit(b, r)
    }
    fn check(&mut self, a: Access<'_>) -> Result<()> {
        self.gate.check(a)
    }
}
impl<A: Checkpoint> CurrentBlobBoundary for Artifact<'_, '_, '_, '_, '_, A> {
    fn current_blob(&mut self, reference: &luma_content_store::v2::BlobReference) -> Result<()> {
        self.gate.current(|c| {
            if self.proof.verify_data_for_head(&c.head)?.payload != *reference {
                return Err(
                    "index source bytes are not the current C-selected live artifact".into(),
                );
            }
            Ok(())
        })
    }
}
impl<A: Checkpoint> CorpusContent for Content<'_, '_, '_, '_, A> {
    fn read_content<B: CorpusIndexBoundary>(
        &mut self,
        record: &CorpusRecord,
        b: &mut B,
    ) -> Result<Vec<u8>> {
        let root = self.gate.head()?.roots.corpus;
        b.current_candidate(&root, record)?;
        let proof = proof(&mut self.gate, &record.reference)?;
        let head = self.gate.head()?;
        let selected = proof.verify_data_for_head(&head)?;
        if selected.corpus != *record {
            return Err(
                "index source record differs from exact C corpus/lifecycle/reference".into(),
            );
        }
        let credit = selected
            .payload
            .bytes
            .checked_mul(2)
            .and_then(|v| v.checked_add(1024 * 1024))
            .filter(|v| *v <= 128 * 1024 * 1024)
            .ok_or("index source blob exceeds finite read envelope")?;
        let mut reader = Reader {
            shared: self.gate.shared,
            client: self.gate.client,
        };
        let bytes = blob::read_current(
            &selected.payload,
            IoBudget {
                read_bytes: credit,
                write_bytes: 0,
                new_files: 0,
            },
            &mut reader,
            &mut Artifact {
                gate: Gate {
                    shared: self.gate.shared,
                    client: self.gate.client,
                },
                proof: &proof,
            },
        )?;
        let version = proof.reopen_data_for_head(&self.gate.head()?, &bytes)?;
        b.current_candidate(&root, record)?;
        self.gate.current(|_| Ok(()))?;
        Ok(version.content().to_vec())
    }
}

pub(super) fn with_index<T>(
    original: &mut OriginalCOperation<'_>,
    source: &[u8],
    deliver: impl FnOnce(IndexReply, &mut dyn FnMut() -> Result<()>) -> Result<T>,
) -> Result<T> {
    // Declared first, so every private reader/job/result buffer drops before
    // this optional allocator hint on both success and refusal paths.
    let _return_unused_heap = ReturnUnusedHeap;
    original.check()?;
    let actual = original.source_binding().clone();
    if actual.purpose != SourcePurpose::IndexRead {
        return Err("index queries require genuine original IndexRead purpose".into());
    }
    let profile = actual.profile.clone();
    let input = content_index::scope::verify_input(&profile, source)?;
    let mode = content_index::request::parse_profile(&profile)?.mode;
    if !matches!(mode, Mode::Status | Mode::Query | Mode::Review) {
        return Err("IndexRead does not authorize effects".into());
    }
    let usage = require_original_source(original, &input, &profile)?;
    let mut store = PagedStore::installed(&mut || original.check())?;
    let selected = store.selected_index(&input.binding, &mut || original.check())?;
    let digest = selection_sha256(&selected)?;
    let builder = FixedBuilder::installed(|| original.check())?;
    let context = Context {
        schema_version: 1,
        binding: input.binding.clone(),
        source_request_sha256: actual.request_sha256.clone(),
        source_profile: profile.clone(),
        selected_before: selected.owner.clone(),
        selected_before_sha256: selected.owner.sha256()?,
        lease: actual.lease.clone(),
    };
    let shared = RefCell::new(Current {
        store,
        original,
        input: input.clone(),
        profile,
        head: selected.owner,
        physical: selected.physical,
        leaf: selected.leaf,
        selection_sha256: digest.clone(),
        builder,
        job: None,
        remaining_read: usage.input_bytes,
    });
    shared.borrow_mut().check()?;
    let mut original_check = || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant original index observer fence")?
            .check()
    };
    let client = RefCell::new(Client::begin(context, &mut original_check)?);
    let mut gate = Gate {
        shared: &shared,
        client: &client,
    };
    let storage = ObservedIndexStore::new(
        &input.binding,
        Reader {
            shared: &shared,
            client: &client,
        },
    )?;
    let mut result = compute::run(&storage, &input, &mut gate)?;
    gate.current(|_| Ok(()))?;
    let object = result
        .as_object_mut()
        .ok_or("actual index result is not the closed result object")?;
    if object.contains_key("selection_sha256") {
        return Err("actual index result already labels a selection; refusing overwrite".into());
    }
    object.insert("selection_sha256".into(), digest.clone().into());
    if serde_json::to_vec(&result)?.len() > content_index::MAX_OUTPUT as usize {
        return Err("selected index result exceeds original output reservation".into());
    }
    drop(storage);
    drop(gate);
    client.into_inner().finish(&mut || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant actual observer End fence")?
            .check()
    })?;
    let mut current = shared
        .try_borrow_mut()
        .map_err(|_| "reentrant index result fence")?;
    current.check()?;
    super::indexed_output::remember(current.original, &input, &digest, &result)?;
    current.check()?;
    drop(current);
    let mut check = || {
        shared
            .try_borrow_mut()
            .map_err(|_| "reentrant index reply fence")?
            .check()
    };
    check()?;
    let reply = IndexReply {
        selection_sha256: digest,
        result,
    };
    if serde_json::to_vec(&reply)?.len() > content_index::MAX_OUTPUT as usize {
        return Err("entire index reply exceeds original finite output reservation".into());
    }
    let value = deliver(reply, &mut check)?;
    check()?;
    Ok(value)
}
