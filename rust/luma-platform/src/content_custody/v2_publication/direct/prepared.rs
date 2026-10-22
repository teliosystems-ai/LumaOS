//! Actual original V1 semantic reconstruction and bounded operation-local map
//! preparation. There is no physical write, NV handle, decoded permission or
//! generic new-root constructor. The direct publisher can consume only this
//! nonserializable result plus independently verified actual allocations.
use super::super::*;

const CACHE_BYTES: usize = 4 * 1024 * 1024;
const CACHE_PAGES: usize = 256;

pub(super) enum Outcome {
    AlreadySelected(VerifiedState),
    Prepared(PreparedV1),
}
pub(super) struct PreparedV1 {
    base: Selector,
    binding: OwnerBinding,
    next_state: VerifiedState,
    review_sha256: String,
    source_sha256: String,
    original_request_sha256: String,
    record: RecordNode,
    record_bytes: Vec<u8>,
    next_owner_leaf: OwnerLeaf,
    next_owner_root: map::Root,
    edits: Vec<map::Edit>,
    context: map::Context,
    pages: BTreeMap<String, Vec<u8>>,
}
/// Actual newly sealed physical objects only; the native implementation must
/// retain their selected original slot membership and held inode observations.
/// This interface cannot select a current owner or extend a checkpoint.
pub(super) trait SealedObjects {
    fn check(&mut self) -> Result<()>;
    fn read_new(&mut self, sha256: &str, maximum: usize) -> Result<Vec<u8>>;
}
pub(super) struct WrittenV1 {
    prepared: PreparedV1,
}
impl WrittenV1 {
    pub fn into_prepared(self) -> PreparedV1 {
        self.prepared
    }
}
struct Cache<'a, 'b, 'c, A: Checkpoint> {
    store: &'a mut PagedStore<A>,
    original: COperation<'b, 'c>,
    pages: BTreeMap<String, Vec<u8>>,
    bytes: usize,
    readonly: bool,
}
impl<A: Checkpoint> map::CustodyIo for Cache<'_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        budget.validate()?;
        if self.readonly && (budget.write_bytes != 0 || budget.new_files != 0)
            || budget.write_bytes > CACHE_BYTES as u64
            || budget.new_files > CACHE_PAGES as u32
        {
            return Err(
                "direct semantic preparation exceeds its fixed cache/no-write admission".into(),
            );
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        context.validate()?;
        self.original.check()?;
        if context != &self.store.context(context.review_sha256.clone()) {
            return Err("direct semantic preparation changed current C context".into());
        }
        let review = context
            .review_sha256
            .as_deref()
            .ok_or("direct preparation lacks exact original review")?;
        match &self.original {
            COperation::Worker(original) => {
                let source = original.source_binding();
                if source.purpose != SourcePurpose::Publish
                    || original.audit().usage
                        != crate::content_governed::custody_usage(
                            &source.profile,
                            &source.storage_device,
                            &source.binding,
                            review,
                        )?
                {
                    return Err(
                        "direct preparation differs from actual original finite source/grant"
                            .into(),
                    );
                }
            }
            COperation::Admin(original) => {
                let source = original.source_binding();
                let control = source
                    .paged_control
                    .as_ref()
                    .ok_or("direct bootstrap preparation lacks authenticated control DATA")?;
                control.validate()?;
                let opaque = tpm::decode::<16>(&source.job)?;
                if source.command != "content-custody-paged-bootstrap"
                    || source.installation != self.store.descriptor.binding.installation
                    || opaque == [0; 16]
                    || source.job != bundle::hex(&opaque)
                    || control.stable_review_sha256 != self.store.descriptor.phase.review_sha256
                    || control.expected_window_sha256 != review
                    || control.expected_selected_descriptor_sha256.as_deref()
                        != Some(self.store.selected.descriptor_sha256.as_str())
                    || control.attempt_sha256.is_some()
                    || source.usage != original.audit().usage
                    || source.usage.selector.digest != review
                {
                    return Err("direct bootstrap cache lacks its exact original independently authenticated Admin window".into());
                }
            }
        }
        self.store.live(&mut || self.original.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum != PAGE_BYTES {
            return Err("direct semantic map read bound changed".into());
        }
        // This private cache contains only bytes generated by THIS exact
        // original operation. Ordinary current-state readers cannot consult it.
        let result = match self.pages.get(sha) {
            Some(bytes) => bytes.clone(),
            None => self
                .store
                .pages
                .read_page(sha, &mut || self.original.check())?,
        };
        if result.len() > maximum || hash(&result) != sha {
            return Err("direct semantic prepared page differs".into());
        }
        self.check_current(context)?;
        Ok(result)
    }
    fn write_page(&mut self, context: &map::Context, bytes: &[u8]) -> Result<()> {
        self.check_current(context)?;
        if self.readonly {
            return Err("independent direct semantic replay cannot write".into());
        }
        if bytes.is_empty() || bytes.len() > PAGE_BYTES {
            return Err("prepared semantic page exceeds fixed slot capacity".into());
        }
        let sha = hash(bytes);
        if let Some(existing) = self.pages.get(&sha) {
            if existing != bytes {
                return Err("prepared semantic page digest collision".into());
            }
        } else {
            let next = self
                .bytes
                .checked_add(bytes.len())
                .ok_or("prepared cache size overflow")?;
            if next > CACHE_BYTES || self.pages.len() >= CACHE_PAGES {
                return Err("prepared semantic page cache exhausted before allocation".into());
            }
            self.pages.insert(sha, bytes.to_vec());
            self.bytes = next;
        }
        self.check_current(context)
    }
}

pub(super) fn prepare_v1<A: Checkpoint>(
    store: &mut PagedStore<A>,
    commitment: &[u8],
    record: &[u8],
    original: &mut OriginalCOperation<'_>,
) -> Result<Outcome> {
    let held = HeldPublication::parse(commitment)?;
    store.exact_v1_authority(&held, original)?;
    let (current, closure) = match store.owner_leaf(&held.binding, &mut || original.check())? {
        Some(OwnerLeaf::V1 {
            state,
            records,
            migration_prefix,
        }) => {
            if migration_prefix.is_some() {
                return Err("direct V1 preparation cannot bypass selected owner migration".into());
            }
            (state, records)
        }
        Some(OwnerLeaf::V2 { .. }) => {
            return Err("direct V1 preparation cannot downgrade selected V2 owner".into())
        }
        None => (
            VerifiedState::empty(&held.binding)?,
            LegacyRecordClosure {
                legacy_journal_sha256: store.descriptor.legacy.journal_sha256.clone(),
                legacy_owner_record_count: 0,
                latest_suffix: None,
                suffix_count: 0,
            },
        ),
    };
    let history = store.publication_history(&held.binding, &closure, &mut || original.check())?;
    if let Some(prior) = history.iter().find(|prior| {
        prior
            .validate()
            .is_ok_and(|entry| entry.request_id == held.request_id)
    }) {
        let prior_held = prior.validate()?;
        if current != held.outcome()
            || prior_held.review_sha256 != held.review_sha256
            || prior_held.decision != held.decision
            || prior_held.resulting != held.resulting
            || prior.record.as_bytes() != record
            || prior.original_authority.usage != original.audit().usage
            || prior_held.members.len() != held.members.len()
            || prior_held
                .members
                .iter()
                .zip(&held.members)
                .any(|(a, b)| a.name != b.name || a.bytes != b.bytes || a.sha256 != b.sha256)
        {
            return Err("direct V1 retry substitutes selected immutable original operation".into());
        }
        store.live(&mut || original.check())?;
        return Ok(Outcome::AlreadySelected(current));
    }
    if held.already_published || current != held.base() {
        return Err("direct V1 preparation does not extend actual selected owner".into());
    }
    let publication = Publication {
        schema_version: 1,
        purpose: "luma-content-custody-publication-v1".into(),
        commitment: std::str::from_utf8(commitment)?.into(),
        record: std::str::from_utf8(record)?.into(),
        profile: original.source_binding().profile.clone(),
        storage_device: original.source_binding().storage_device.clone(),
        original_authority: original.audit().clone(),
    };
    publication.validate()?;
    let semantics = store.verify_typed_event(
        Event::Publication(publication.clone()),
        &mut COperation::Worker(original),
    )?;
    if semantics.base != store.selected
        || semantics.binding.as_ref() != Some(&held.binding)
        || semantics.state.owners.get(&owner_key(&held.binding)?) != Some(&held.outcome())
    {
        return Err(
            "direct V1 preparation lost independently reconstructed original semantic outcome"
                .into(),
        );
    }
    let sequence = closure
        .suffix_count
        .checked_add(1)
        .ok_or("direct V1 suffix overflow")?;
    if sequence > SUFFIX_LIMIT {
        return Err(
            "direct V1 suffix bound is unchanged; explicit owner migration required".into(),
        );
    }
    let node = RecordNode {
        schema_version: 3,
        binding: held.binding.clone(),
        legacy_journal_sha256: closure.legacy_journal_sha256.clone(),
        sequence,
        previous: closure.latest_suffix.clone(),
        publication,
    };
    let record_bytes = serde_json::to_vec(&node)?;
    if record_bytes.len() > super::super::super::paged::FILE_BYTES {
        return Err("direct V1 record exceeds existing fixed record slot".into());
    }
    let reference = RecordRef {
        sha256: hash(&record_bytes),
        bytes: record_bytes.len() as u64,
    };
    let next_leaf = OwnerLeaf::V1 {
        state: held.outcome(),
        migration_prefix: None,
        records: LegacyRecordClosure {
            latest_suffix: Some(reference),
            suffix_count: sequence,
            ..closure
        },
    };
    next_leaf.validate(&held.binding.installation, &store.descriptor.legacy)?;
    let root = store.descriptor.roots.owners.clone();
    let literal = owner_key(&held.binding)?;
    let before = store.value(&root, literal.as_bytes(), &mut || original.check())?;
    let edits = vec![map::Edit {
        key: root.key(literal.as_bytes())?,
        expected_value_sha256: before.as_ref().map(|bytes| hash(bytes)),
        value: Some(serde_json::to_vec(&next_leaf)?),
    }];
    let context = store.context(Some(held.review_sha256.clone()));
    let original_request_sha256 = original.source_binding().request_sha256.clone();
    let mut cache = Cache {
        store,
        original: COperation::Worker(original),
        pages: BTreeMap::new(),
        bytes: 0,
        readonly: false,
    };
    let next_root = map::prepare_update(
        &root,
        &edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: CACHE_BYTES as u64,
            new_files: CACHE_PAGES as u32,
        },
        &mut cache,
    )?;
    cache.readonly = true;
    map::verify_update(
        &root,
        &next_root,
        &edits,
        &context,
        map::Budget {
            read_bytes: READ_BUDGET,
            write_bytes: 0,
            new_files: 0,
        },
        &mut cache,
    )?;
    cache.store.live(&mut || cache.original.check())?;
    if cache.store.selected != semantics.base {
        return Err(
            "actual C selection changed after independent direct semantic map replay".into(),
        );
    }
    Ok(Outcome::Prepared(PreparedV1 {
        base: semantics.base,
        binding: held.binding.clone(),
        next_state: held.outcome(),
        review_sha256: held.review_sha256.clone(),
        source_sha256: semantics.source_sha256,
        original_request_sha256,
        record: node,
        record_bytes,
        next_owner_leaf: next_leaf,
        next_owner_root: next_root,
        edits,
        context,
        pages: cache.pages,
    }))
}

#[cfg(test)]
#[path = "prepared/tests.rs"]
mod tests;

impl PreparedV1 {
    pub fn base(&self) -> &Selector {
        &self.base
    }
    pub fn binding(&self) -> &OwnerBinding {
        &self.binding
    }
    pub fn state(&self) -> &VerifiedState {
        &self.next_state
    }
    pub fn review_sha256(&self) -> &str {
        &self.review_sha256
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn request_sha256(&self) -> &str {
        &self.original_request_sha256
    }
    pub fn record(&self) -> &RecordNode {
        &self.record
    }
    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }
    pub fn next_owner_leaf(&self) -> &OwnerLeaf {
        &self.next_owner_leaf
    }
    pub fn next_owner_root(&self) -> &map::Root {
        &self.next_owner_root
    }
    pub fn pages(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.pages
    }
    /// Independent post-write validation uses actual new object reads, NOT the
    /// preparation cache. The old map side still reads only the current C cut.
    /// This result remains insufficient without the native allocation proof.
    pub fn verify_written<A: Checkpoint>(
        self,
        store: &mut PagedStore<A>,
        objects: &mut impl SealedObjects,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<WrittenV1> {
        original.check()?;
        objects.check()?;
        store.live(&mut || original.check())?;
        if store.selected != self.base
            || original.source_binding().request_sha256 != self.original_request_sha256
            || original.source_binding().binding != self.binding
        {
            return Err(
                "direct physical replay differs from original prepared C source/base".into(),
            );
        }
        let record_sha = hash(&self.record_bytes);
        if objects.read_new(&record_sha, super::super::super::paged::FILE_BYTES)?
            != self.record_bytes
        {
            return Err("actual sealed direct V1 record differs from independently reconstructed typed event".into());
        }
        for (sha, expected) in &self.pages {
            original.check()?;
            objects.check()?;
            if objects.read_new(sha, PAGE_BYTES)? != *expected {
                return Err(
                    "actual sealed semantic page differs from exact original map preparation"
                        .into(),
                );
            }
        }
        struct Actual<'a, 'b, 'c, 'd, A: Checkpoint, T: SealedObjects> {
            store: &'a mut PagedStore<A>,
            original: &'b mut OriginalCOperation<'c>,
            objects: &'d mut T,
            expected: &'a BTreeMap<String, Vec<u8>>,
        }
        impl<A: Checkpoint, T: SealedObjects> map::CustodyIo for Actual<'_, '_, '_, '_, A, T> {
            fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
                budget.validate()?;
                if budget.write_bytes != 0 || budget.new_files != 0 {
                    return Err("actual direct semantic verification cannot write".into());
                }
                self.check_current(context)
            }
            fn check_current(&mut self, context: &map::Context) -> Result<()> {
                context.validate()?;
                self.original.check()?;
                self.objects.check()?;
                if context != &self.store.context(context.review_sha256.clone()) {
                    return Err(
                        "actual direct semantic verification changed current selection context"
                            .into(),
                    );
                }
                self.store.live(&mut || self.original.check())
            }
            fn read_page(
                &mut self,
                context: &map::Context,
                sha: &str,
                maximum: usize,
            ) -> Result<Vec<u8>> {
                self.check_current(context)?;
                if maximum != PAGE_BYTES {
                    return Err("actual direct semantic verifier changed page bound".into());
                }
                let bytes = if self.expected.contains_key(sha) {
                    self.objects.read_new(sha, PAGE_BYTES)?
                } else {
                    self.store
                        .pages
                        .read_page(sha, &mut || self.original.check())?
                };
                if bytes.is_empty() || bytes.len() > PAGE_BYTES || hash(&bytes) != sha {
                    return Err(
                        "actual direct semantic verifier received incomplete/hash-substituted page"
                            .into(),
                    );
                }
                self.check_current(context)?;
                Ok(bytes)
            }
            fn write_page(&mut self, _: &map::Context, _: &[u8]) -> Result<()> {
                Err("actual direct semantic verification refuses write effects".into())
            }
        }
        let old = store.descriptor.roots.owners.clone();
        map::verify_update(
            &old,
            &self.next_owner_root,
            &self.edits,
            &self.context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut Actual {
                store,
                original,
                objects,
                expected: &self.pages,
            },
        )?;
        original.check()?;
        objects.check()?;
        store.live(&mut || original.check())?;
        if store.selected != self.base {
            return Err("actual C changed after complete physical direct semantic replay".into());
        }
        Ok(WrittenV1 { prepared: self })
    }
}
