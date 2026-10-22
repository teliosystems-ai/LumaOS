//! Private cold direct-storage reader. A mutable selector, directory name,
//! optional descriptor or valid slot checksum is never enough to open it.
//! The existing held C anchor selects one complete independently verified cut.
use super::super::super::paged::slots;
use super::super::*;

pub(in crate::content_checkpoint::custody) struct Backend<A: Checkpoint> {
    anchor: A,
    files: Files,
    pages: PageStore,
    descriptor: Descriptor,
    descriptor_sha256: String,
    descriptor_frame_sha256: String,
    nv: [u8; 32],
    selection: super::reader::ReadSelection,
    immutable: Vec<super::pinned::Pinned>,
    poisoned: bool,
}
/// Move-only current-cut carrier for the actual bootstrap publisher. It is
/// obtained from a verified completed reader and fresh original Admin scope,
/// never a serialized head or caller-selected collection of roots.
pub(in crate::content_checkpoint::custody) struct ProgressBase<A: Checkpoint> {
    pub anchor: A,
    pub files: Files,
    pub pages: PageStore,
    pub descriptor: Descriptor,
    pub cell: control::Cell,
    pub index: u8,
    pub source_sha256: String,
    pub request_sha256: String,
    source_binding_sha256: String,
}
impl<A: Checkpoint> ProgressBase<A> {
    pub(in crate::content_checkpoint::custody) fn check_source(
        &self,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<()> {
        authority.check()?;
        let actual_source = hash(&COperation::Admin(authority).source_bytes()?);
        if self.source_binding_sha256 != actual_source
            || self.request_sha256 != authority.source_binding().request_sha256
        {
            return Err("move-only direct progress base changed its actual original source".into());
        }
        authority.check()
    }
}
impl Backend<crate::content_checkpoint::ContentAnchor> {
    pub(in crate::content_checkpoint::custody) fn installed(
        original: &mut COperation<'_, '_>,
    ) -> Result<Self> {
        original.check()?;
        let anchor = crate::content_checkpoint::ContentAnchor::installed()?;
        let binding = map::CustodyBinding {
            installation: anchor.installation().into(),
            sealed_genesis_sha256: bundle::hex(&anchor.genesis_event()),
        };
        Self::open(anchor, Files::installed(), binding, &mut || {
            original.check()
        })
    }
}
impl<A: Checkpoint> Backend<A> {
    pub(in crate::content_checkpoint::custody) fn open(
        mut anchor: A,
        files: Files,
        binding: map::CustodyBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        check()?;
        if super::super::super::format::probe(&files, check)?
            != super::super::super::format::Layout::Paged
        {
            return Err("direct reader cannot adopt a missing or legacy namespace".into());
        }
        validate_genesis_at(
            &files.root,
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256)?,
        )?;
        let pages = PageStore::open(&files.root, binding.clone(), check)?;
        // The original mutable hash selector is not a second parser or fallback.
        if !pages.absent("selected.json")? || !pages.absent("pending.json")? {
            return Err("direct reader refuses mixed hashed/direct control formats".into());
        }
        let candidate = super::reader::observe(&mut anchor, &pages, &binding, check)?;
        let expected = candidate.descriptor().bytes()?;
        let cut = if candidate.descriptor().sequence > 1 {
            let control::Cell::Selected {
                descriptor: location,
                ..
            } = candidate.cell()
            else {
                return Err("cold progress selected an empty cell".into());
            };
            let expected_nv = tpm::decode::<32>(&candidate.descriptor().selected_nv_head)?;
            bootstrap::direct_progress::verify_selected(
                &files,
                &pages,
                candidate.descriptor(),
                location,
                &mut || {
                    check()?;
                    if anchor.read()? != expected_nv {
                        return Err(
                            "actual C changed during cold current transition verification".into(),
                        );
                    }
                    check()
                },
            )?;
            candidate
        } else {
            match &candidate.descriptor().operation {
            OperationData::BootstrapProgress{previous_retirement:None,..}=>{
                let reviewed=super::initial::recovery_review(&mut anchor,&files,&pages,&binding,check)?;
                let physical=pages.inventory(check)?;
                if physical.files!=8 || physical.directories!=7 || physical.interrupted_files!=0
                    || reviewed["actual_nv_head"].as_str()!=Some(candidate.descriptor().selected_nv_head.as_str())
                {return Err("initial direct namespace contains unknown or changed allocation membership".into());}
                super::reader::observe(&mut anchor,&pages,&binding,check)?
            }
            OperationData::BootstrapProgress{previous_retirement:Some(_),..}=>
                super::resume::verify_current(&mut anchor,&files,&pages,&binding,check)?.0,
            OperationData::V1Publication{..}=>return Err("direct reader requires independent publication lineage before selecting this event class".into()),
            OperationData::IndexPreparation{..}=>return Err("direct reader requires independently reconstructed index preparation lineage before selecting this event class".into()),
        }
        };
        if cut.descriptor().bytes()? != expected {
            return Err(
                "direct selected cut changed between control and independent semantic validation"
                    .into(),
            );
        }
        let descriptor = cut.descriptor().clone();
        let control::Cell::Selected {
            descriptor: descriptor_location,
            ..
        } = cut.cell()
        else {
            return Err("completed direct cut has no descriptor inode".into());
        };
        let descriptor_location = descriptor_location.clone();
        let selection = cut.completed_read()?;
        let retained = files.read(JOURNAL, check)?;
        let genesis = files.read("genesis.json", check)?;
        if retained.len() as u64 != descriptor.legacy.journal_bytes
            || hash(&retained) != descriptor.legacy.journal_sha256
        {
            return Err(
                "direct retained observation differs from the exact C-selected legacy DATA".into(),
            );
        }
        let mut immutable = vec![
            super::pinned::Pinned::capture(files.root.join(JOURNAL), &retained, 0o400, check)?,
            super::pinned::Pinned::capture(
                files.root.join("genesis.json"),
                &genesis,
                0o400,
                check,
            )?,
        ];
        let descriptor_directory =
            slots::Directory::at_reference(&pages, &descriptor_location.slot, check)?;
        let descriptor_parent = pages.root.join("tails").join(&descriptor_location.slot.job);
        immutable.push(super::pinned::Pinned::capture(
            descriptor_parent.join("identity.json"),
            &serde_json::to_vec(descriptor_directory.plan())?,
            0o400,
            check,
        )?);
        immutable.push(super::pinned::Pinned::capture(
            descriptor_parent.join(format!("{:08x}", descriptor_location.slot.number)),
            &descriptor.slot_frame()?,
            0o400,
            check,
        )?);
        drop(descriptor_directory);
        let storage = descriptor
            .storage
            .as_ref()
            .ok_or("direct selected storage absent")?;
        let controls = super::super::super::paged::cells::Files::open(
            &pages,
            storage.controls.clone(),
            check,
        )?;
        for (index, name) in ["selector-0", "selector-1", "pending"].iter().enumerate() {
            let snapshot = controls.read(index, check)?;
            immutable.push(super::pinned::Pinned::capture(
                pages.root.join("controls").join(name),
                snapshot.bytes(),
                0o600,
                check,
            )?);
        }
        drop(controls);
        // Pin capture is not selection. Rejoin the actual C after all complete
        // control observations, then bracket that join with the retained pins.
        let final_cut = super::reader::observe(&mut anchor, &pages, &binding, check)?;
        if final_cut.descriptor().bytes()? != descriptor.bytes()? {
            return Err("direct C changed while retaining immutable operation observations".into());
        }
        final_cut.completed_read()?;
        validate_genesis_at(
            &files.root,
            &binding.installation,
            tpm::decode(&binding.sealed_genesis_sha256)?,
        )?;
        for pin in &immutable {
            pin.check(check)?;
        }
        let mut store = Self {
            anchor,
            files,
            pages,
            descriptor_sha256: hash(&descriptor.bytes()?),
            descriptor_frame_sha256: hash(&descriptor.slot_frame()?),
            nv: tpm::decode(&descriptor.selected_nv_head)?,
            descriptor,
            selection,
            immutable,
            poisoned: false,
        };
        store.live(check)?;
        Ok(store)
    }
    pub(in crate::content_checkpoint::custody) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub(in crate::content_checkpoint::custody) fn into_progress(
        mut self,
        window: &str,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<ProgressBase<A>> {
        self.live(&mut || authority.check())?;
        if self.descriptor.phase.state != bootstrap::State::Pending {
            return Err("completed C bootstrap cannot restart a progress operation".into());
        }
        let selected = hash(&self.descriptor.bytes()?);
        bootstrap::require_admin(
            authority,
            &self.descriptor.binding,
            &self.descriptor.phase,
            window,
            Some(&selected),
            None,
        )?;
        let cut = super::reader::observe(
            &mut self.anchor,
            &self.pages,
            &self.descriptor.binding,
            &mut || authority.check(),
        )?;
        if cut.descriptor().bytes()? != self.descriptor.bytes()? {
            return Err("direct progress base changed after original Admin admission".into());
        }
        let cell = cut.cell().clone();
        let index = u8::try_from(cut.index())?;
        cut.completed_read()?;
        let source = hash(&COperation::Admin(authority).source_bytes()?);
        let request = authority.source_binding().request_sha256.clone();
        authority.check()?;
        Ok(ProgressBase {
            anchor: self.anchor,
            files: self.files,
            pages: self.pages,
            descriptor: self.descriptor,
            cell,
            index,
            source_sha256: source.clone(),
            request_sha256: request,
            source_binding_sha256: source,
        })
    }
    pub(in crate::content_checkpoint::custody) fn context(&self) -> Result<map::Context> {
        Ok(map::Context {
            binding: self.descriptor.binding.clone(),
            selected_descriptor_sha256: self.descriptor_sha256.clone(),
            selected_nv_head: self.descriptor.selected_nv_head.clone(),
            review_sha256: None,
        })
    }
    pub(in crate::content_checkpoint::custody) fn legacy_data(
        &mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Journal> {
        self.live(check)?;
        let bytes = self.files.read(JOURNAL, check)?;
        if bytes.len() as u64 != self.descriptor.legacy.journal_bytes
            || hash(&bytes) != self.descriptor.legacy.journal_sha256
        {
            return Err("direct planner lost exact C-selected retained legacy DATA".into());
        }
        let journal: Journal = canonical(&bytes, MAX_JOURNAL)?;
        journal.require_identity(
            &self.descriptor.binding.installation,
            tpm::decode(&self.descriptor.binding.sealed_genesis_sha256)?,
        )?;
        let state = journal.validate()?;
        if journal.events.len() as u64 != self.descriptor.legacy.events
            || bundle::hex(&state.checkpoint) != self.descriptor.legacy.nv_head
        {
            return Err("direct retained legacy typed event closure differs".into());
        }
        self.live(check)?;
        Ok(journal)
    }
    pub(in crate::content_checkpoint::custody) fn live(
        &mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if self.poisoned {
            return Err("direct reader remains fenced after a changed or uncertain cut".into());
        }
        let result = (|| -> Result<()> {
            check()?;
            self.pages.check()?;
            if !self.pages.absent("selected.json")? || !self.pages.absent("pending.json")? {
                return Err("direct reader detected a conflicting format without fallback".into());
            }
            if self.anchor.read()? != self.nv {
                return Err(
                    "direct current descriptor changed under the original held reader".into(),
                );
            }
            for pin in &self.immutable {
                pin.check(check)?;
            }
            self.selection.check_data(
                &self.descriptor.binding,
                &self.descriptor_frame_sha256,
                &self.descriptor.selected_nv_head,
            )?;
            check()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn verify_operation_data(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.live(check)?;
        let expected = self.nv;
        let anchor = &mut self.anchor;
        let mut current = || -> Result<()> {
            check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during whole operation DATA verification".into());
            }
            check()
        };
        let result = self
            .immutable
            .iter()
            .try_for_each(|pin| pin.verify(&mut current));
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        self.live(check)
    }
    /// This is C-internal immutable DATA, not FileExport or a user grant. The
    /// caller supplies a genuine current original operation at every boundary.
    pub(in crate::content_checkpoint::custody) fn read_immutable(
        &mut self,
        sha: &str,
        kind: slots::Kind,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>> {
        original.check()?;
        if matches!(original, COperation::Worker(_)) {
            self.descriptor.phase.require_ready()?;
        }
        self.verify_operation_data(&mut || original.check())?;
        let bytes = self
            .selection
            .read(&mut self.anchor, &self.pages, sha, kind, &mut || {
                original.check()
            });
        if bytes.is_err() {
            self.poisoned = true;
        }
        let bytes = bytes?;
        self.verify_operation_data(&mut || original.check())?;
        Ok(bytes)
    }
    /// Read-only structural DATA for a C-Admin planner walking an independently
    /// authenticated current tree. Structural index nodes are committed by
    /// their ancestors, not entered recursively into their own hash resolver.
    pub(in crate::content_checkpoint::custody) fn read_structural(
        &mut self,
        reference: &slots::SealedReference,
        authority: &mut OriginalCAdminOperation<'_>,
    ) -> Result<Vec<u8>> {
        self.live(&mut || authority.check())?;
        let expected = tpm::decode::<32>(&self.descriptor.selected_nv_head)?;
        let anchor = &mut self.anchor;
        let pages = &self.pages;
        let mut live = || -> Result<()> {
            authority.check()?;
            pages.check()?;
            if anchor.read()? != expected {
                return Err("actual C changed during original Admin structural read".into());
            }
            authority.check()
        };
        let result = (|| -> Result<Vec<u8>> {
            let directory = slots::Directory::at_reference(pages, &reference.slot, &mut live)?;
            let bytes = directory.read(reference, &mut live)?;
            live()?;
            Ok(bytes)
        })();
        drop(live);
        if result.is_err() {
            self.poisoned = true;
        }
        let bytes = result?;
        self.live(&mut || authority.check())?;
        Ok(bytes)
    }
    pub(super) fn lookup(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        original: &mut COperation<'_, '_>,
    ) -> Result<Option<Vec<u8>>> {
        self.descriptor.phase.require_ready()?;
        let roots = self.descriptor.roots.all();
        if !roots.iter().any(|selected| *selected == root) {
            return Err("direct map reader refuses an unselected role/root".into());
        }
        let context = self.context()?;
        let key = root.key(literal)?;
        let proof = map::lookup(
            root,
            &key,
            &context,
            map::Budget {
                read_bytes: READ_BUDGET,
                write_bytes: 0,
                new_files: 0,
            },
            &mut MapRead {
                store: self,
                original,
            },
        )?;
        if proof.key != key {
            return Err("direct map proof substitutes requested logical key".into());
        }
        proof.verify_data(root)
    }
}
struct MapRead<'a, 'b, 'c, 'd, A: Checkpoint> {
    store: &'a mut Backend<A>,
    original: &'b mut COperation<'c, 'd>,
}
impl<A: Checkpoint> map::CustodyIo for MapRead<'_, '_, '_, '_, A> {
    fn admit(&mut self, context: &map::Context, budget: map::Budget) -> Result<()> {
        context.validate()?;
        budget.validate()?;
        if budget.write_bytes != 0 || budget.new_files != 0 || budget.read_bytes > READ_BUDGET {
            return Err("direct immutable map reader cannot reserve writes".into());
        }
        self.check_current(context)
    }
    fn check_current(&mut self, context: &map::Context) -> Result<()> {
        self.original.check()?;
        if context != &self.store.context()? {
            return Err("direct map context substitutes original current selection".into());
        }
        self.store.live(&mut || self.original.check())
    }
    fn read_page(&mut self, context: &map::Context, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check_current(context)?;
        if maximum == 0 || maximum > PAGE_BYTES {
            return Err("direct map page bound is invalid".into());
        }
        let bytes = self
            .store
            .read_immutable(sha, slots::Kind::Page, self.original)?;
        if bytes.len() > maximum {
            return Err("direct immutable page exceeds selected page reference".into());
        }
        self.check_current(context)?;
        Ok(bytes)
    }
    fn write_page(&mut self, _: &map::Context, _: &[u8]) -> Result<()> {
        Err("direct current read adapter has no publication or allocation entry point".into())
    }
}
