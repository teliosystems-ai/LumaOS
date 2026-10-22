//! Actual root-only ext4 control/slot I/O plus explicitly software C NV. These
//! fixtures prove no installed principal, TPM, PAM, LSM or publication grant.
use super::*;
use std::cell::Cell;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone)]
struct Memory(Rc<Cell<[u8; 32]>>);
impl Checkpoint for Memory {
    fn read(&mut self) -> Result<[u8; 32]> {
        Ok(self.0.get())
    }
    fn clock(&mut self) -> Result<tpm::Clock> {
        Ok(tpm::Clock {
            milliseconds: 1,
            reset_count: 1,
            restart_count: 1,
        })
    }
    fn advance(&mut self, old: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        if old != self.0.get() {
            return Err("software C conflict".into());
        }
        let next = tpm::extend_value(old, event);
        self.0.set(next);
        Ok(next)
    }
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
    pages: PageStore,
    descriptor: Descriptor,
    pending: control::PendingCell,
    memory: Memory,
    payload: Vec<u8>,
    payload_slot: slots::SealedReference,
}
impl Fixture {
    fn new(complete: bool) -> Self {
        assert!(std::path::Path::new("/.dockerenv").is_file());
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            !std::path::Path::new("/dev/tpm0").exists()
                && !std::path::Path::new("/dev/tpmrm0").exists()
        );
        let base = PathBuf::from(
            std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("explicit disposable ext4 root required"),
        );
        assert_eq!(fs::canonicalize(&base).unwrap(), base);
        let root = base.join(format!(
            "luma-tpm-direct-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut descriptor = super::super::super::tests::initial();
        let pages = PageStore::create(&root, descriptor.binding.clone(), &mut || Ok(())).unwrap();
        pages
            .admit_writes(16 * 1024 * 1024, 64, 8, &mut || Ok(()))
            .unwrap();
        let empty = control::Cell::empty_data(&descriptor.binding)
            .unwrap()
            .frame()
            .unwrap();
        let pending_empty = control::PendingFrame::empty_data(&descriptor.binding)
            .unwrap()
            .frame()
            .unwrap();
        let controls =
            cells::Files::create(&pages, [&empty, &empty, &pending_empty], &mut || Ok(())).unwrap();
        let plan = slots::Plan::exact(
            &descriptor.binding,
            &"77".repeat(32),
            vec![
                slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Page, 64)
                    .unwrap(),
                slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Page, 4096)
                    .unwrap(),
                slots::ExactSlot::for_bytes(
                    slots::Pool::Publication(0),
                    slots::Kind::Page,
                    PAGE_BYTES as u64,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let directory = slots::Directory::create(&pages, plan, &mut || Ok(())).unwrap();
        let refs = directory.allocate_window(0, 3, &mut || Ok(())).unwrap();
        assert_eq!(
            refs.iter().map(|r| r.capacity).collect::<Vec<_>>(),
            vec![4096, 4096, PAGE_BYTES as u64]
        );
        assert!(refs.iter().all(|r| r.allocated_bytes == r.capacity));
        let payload = b"full actual current-C-selected immutable DATA".to_vec();
        let payload_slot = directory
            .fill(&refs[0], slots::Pool::Publication(0), &payload, &mut || {
                Ok(())
            })
            .unwrap();
        struct Build<'a, 'b> {
            directory: &'a slots::Directory<'b>,
            index: slots::Reference,
        }
        impl locations::Io for Build<'_, '_> {
            fn check(&mut self) -> Result<()> {
                Ok(())
            }
            fn read(&mut self, reference: &slots::SealedReference) -> Result<Vec<u8>> {
                self.directory.read(reference, &mut || Ok(()))
            }
            fn seal_node(&mut self, bytes: &[u8]) -> Result<slots::SealedReference> {
                self.directory
                    .fill(&self.index, slots::Pool::Publication(0), bytes, &mut || {
                        Ok(())
                    })
            }
        }
        let locations = locations::insert(
            &locations::Root::empty_data(&descriptor.binding).unwrap(),
            &[locations::Insertion {
                sha256: payload_slot.sha256.clone(),
                location: payload_slot.clone(),
            }],
            &mut Build {
                directory: &directory,
                index: refs[1].clone(),
            },
        )
        .unwrap();
        let mut physical = pages.inventory(&mut || Ok(())).unwrap();
        assert_eq!(physical.interrupted_files, 1);
        physical.interrupted_files = 0;
        physical.logical_bytes += PAGE_BYTES as u64;
        descriptor.storage = Some(StorageSelection {
            schema_version: 1,
            jobs: None,
            controls: controls.selection().clone(),
            locations,
            descriptor_slot: refs[2].clone(),
            post_allocation: physical.clone(),
            parent_allocation: None,
        });
        descriptor = descriptor.seal().unwrap();
        let descriptor_slot = directory
            .fill(
                &refs[2],
                slots::Pool::Publication(0),
                &descriptor.slot_frame().unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), physical);
        let next = control::Cell::for_descriptor(&descriptor, descriptor_slot).unwrap();
        let pending = control::PendingCell {
            schema_version: 3,
            domain: "luma-c-direct-slot-pending-v3".into(),
            binding: descriptor.binding.clone(),
            base: control::Base::Legacy {
                binding: descriptor.binding.clone(),
                cut: descriptor.legacy.clone(),
            },
            inactive_index: 0,
            next: next.clone(),
            event_sha256: descriptor.event_sha256.clone(),
            operation_sha256: hash(&serde_json::to_vec(&descriptor.operation).unwrap()),
        };
        pending.verify_descriptors(None, &descriptor).unwrap();
        let initial = controls.read(2, &mut || Ok(())).unwrap();
        controls
            .rewrite(
                &initial,
                &control::PendingFrame::Prepared {
                    pending: pending.clone(),
                }
                .frame()
                .unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        let initial = controls.read(0, &mut || Ok(())).unwrap();
        controls
            .rewrite(&initial, &next.frame().unwrap(), &mut || Ok(()))
            .unwrap();
        let mut memory = Memory(Rc::new(Cell::new(
            tpm::decode(&descriptor.previous_nv_head).unwrap(),
        )));
        assert_eq!(
            memory
                .advance(
                    tpm::decode(&descriptor.previous_nv_head).unwrap(),
                    descriptor.event_digest().unwrap()
                )
                .unwrap(),
            tpm::decode(&descriptor.selected_nv_head).unwrap()
        );
        if complete {
            let before = controls.read(2, &mut || Ok(())).unwrap();
            controls
                .rewrite(
                    &before,
                    &control::PendingFrame::Completed {
                        pending: pending.clone(),
                    }
                    .frame()
                    .unwrap(),
                    &mut || Ok(()),
                )
                .unwrap();
        }
        drop(directory);
        drop(controls);
        Self {
            base,
            root,
            pages,
            descriptor,
            pending,
            memory,
            payload,
            payload_slot,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(fs::canonicalize(&self.root).unwrap(), self.root);
        assert_eq!(self.root.parent(), Some(self.base.as_path()));
        assert!(self
            .root
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("luma-tpm-direct-reader-"));
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn actual_complete_control_and_nv_join_reads_only_whole_selected_slot_addresses() {
    let mut fixture = Fixture::new(true);
    let cut = observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(cut.index(), 0);
    assert_eq!(
        cut.descriptor().bytes().unwrap(),
        fixture.descriptor.bytes().unwrap()
    );
    let reader = cut.completed_read().unwrap();
    reader
        .check_data(
            &fixture.descriptor.binding,
            &hash(&fixture.descriptor.slot_frame().unwrap()),
            &fixture.descriptor.selected_nv_head,
        )
        .unwrap();
    assert_eq!(
        reader
            .read(
                &mut fixture.memory,
                &fixture.pages,
                &fixture.payload_slot.sha256,
                slots::Kind::Page,
                &mut || Ok(())
            )
            .unwrap(),
        fixture.payload
    );
    assert!(reader
        .read(
            &mut fixture.memory,
            &fixture.pages,
            &"aa".repeat(32),
            slots::Kind::Page,
            &mut || Ok(())
        )
        .is_err());
    assert!(reader
        .read(
            &mut fixture.memory,
            &fixture.pages,
            &fixture.payload_slot.sha256,
            slots::Kind::Record,
            &mut || Ok(())
        )
        .is_err());
}
#[test]
fn lost_completion_remains_uncertain_and_third_actual_nv_never_selects_a_cut() {
    let mut fixture = Fixture::new(false);
    let observed = observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(()),
    )
    .unwrap();
    assert!(observed.completed_read().is_err());
    fixture.memory.0.set([0xee; 32]);
    assert!(observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(())
    )
    .is_err());
    fixture
        .memory
        .0
        .set(tpm::decode(&fixture.descriptor.previous_nv_head).unwrap());
    assert!(observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(())
    )
    .is_err());
    assert_eq!(
        fixture.pending.event_sha256,
        fixture.descriptor.event_sha256
    );
}
#[test]
fn actual_nv_change_midread_and_original_refusal_deliver_no_unverified_data() {
    let mut fixture = Fixture::new(true);
    let reader = observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(()),
    )
    .unwrap()
    .completed_read()
    .unwrap();
    let mut refused = || Err("software original read authority revoked".into());
    assert!(reader
        .read(
            &mut fixture.memory,
            &fixture.pages,
            &fixture.payload_slot.sha256,
            slots::Kind::Page,
            &mut refused
        )
        .is_err());
    let state = fixture.memory.0.clone();
    let calls = Cell::new(0);
    let mut changed = || {
        let current = calls.get() + 1;
        calls.set(current);
        if current == 8 {
            state.set([0xee; 32]);
        }
        Ok(())
    };
    assert!(reader
        .read(
            &mut fixture.memory,
            &fixture.pages,
            &fixture.payload_slot.sha256,
            slots::Kind::Page,
            &mut changed
        )
        .is_err());
    assert!(calls.get() >= 8);
}
#[test]
fn byte_identical_recreated_slot_cannot_replace_the_actual_c_selected_inode() {
    let mut fixture = Fixture::new(true);
    let reader = observe(
        &mut fixture.memory,
        &fixture.pages,
        &fixture.descriptor.binding,
        &mut || Ok(()),
    )
    .unwrap()
    .completed_read()
    .unwrap();
    let path = fixture.pages.root.join(format!(
        "tails/{}/{:08x}",
        fixture.payload_slot.slot.job, fixture.payload_slot.slot.number
    ));
    let moved = path.with_file_name("retained-old-slot");
    fs::rename(&path, &moved).unwrap();
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(&fixture.payload).unwrap();
    file.sync_all().unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .unwrap();
    drop(file);
    assert!(reader
        .read(
            &mut fixture.memory,
            &fixture.pages,
            &fixture.payload_slot.sha256,
            slots::Kind::Page,
            &mut || Ok(())
        )
        .is_err());
}
#[test]
fn actual_exact_job_manifest_accounts_all_slots_and_closes_unused_capacity_without_reuse() {
    use super::super::jobs::{self, Disposition, Manifest, Member, Role};
    let fixture = Fixture::new(true);
    let specifications = vec![
        slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Record, 13).unwrap(),
        slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Record, 16 * 1024)
            .unwrap(),
        slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Page, 1).unwrap(),
        slots::ExactSlot::for_bytes(slots::Pool::Terminal, slots::Kind::Record, 16 * 1024).unwrap(),
        slots::ExactSlot::for_bytes(slots::Pool::Terminal, slots::Kind::Control, 1).unwrap(),
    ];
    let plan = slots::Plan::exact(
        &fixture.descriptor.binding,
        &"88".repeat(32),
        specifications,
    )
    .unwrap();
    let directory = slots::Directory::create(&fixture.pages, plan.clone(), &mut || Ok(())).unwrap();
    let references = directory.allocate_window(0, 5, &mut || Ok(())).unwrap();
    let before = fixture.pages.inventory(&mut || Ok(())).unwrap();
    let source = directory
        .fill(
            &references[0],
            slots::Pool::Publication(0),
            b"exact source",
            &mut || Ok(()),
        )
        .unwrap();
    let metadata = directory
        .fill(
            &references[2],
            slots::Pool::Publication(0),
            b"fixture metadata DATA, not a descriptor authority",
            &mut || Ok(()),
        )
        .unwrap();
    let namespace = directory.observe_namespace(&mut || Ok(())).unwrap();
    let allocated = references.iter().map(|r| r.allocated_bytes).sum::<u64>()
        + namespace.allocated_bytes
        + namespace.identity_allocated_bytes;
    let members = references
        .iter()
        .enumerate()
        .map(|(index, slot)| Member {
            slot: slot.clone(),
            role: [
                Role::SemanticRecord,
                Role::Manifest,
                Role::Descriptor,
                Role::Manifest,
                Role::ClosingControl,
            ][index],
            disposition: match index {
                0 => Disposition::Sealed {
                    value: source.clone(),
                },
                1 | 2 => Disposition::BoundMetadata,
                _ => Disposition::Available,
            },
        })
        .collect();
    let manifest = Manifest {
        schema_version: 4,
        domain: "luma-c-reviewed-job-allocation-v4".into(),
        binding: fixture.descriptor.binding.clone(),
        job: plan.job.clone(),
        base_descriptor_sha256: "11".repeat(32),
        original_request_sha256: "22".repeat(32),
        review_sha256: "33".repeat(32),
        source_sha256: "44".repeat(32),
        previous: None,
        own_slot: 1,
        layout: plan,
        namespace,
        members,
        allocated_bytes: allocated,
    };
    let first = directory
        .fill(
            &references[1],
            slots::Pool::Publication(0),
            &manifest.canonical_bytes().unwrap(),
            &mut || Ok(()),
        )
        .unwrap();
    let mut seals = BTreeMap::from([(1, first.clone()), (2, metadata.clone())]);
    let observed = jobs::observe(&fixture.pages, &first, &seals, &mut || Ok(())).unwrap();
    assert_eq!(observed.manifest(), &manifest);
    assert_eq!(observed.location(), &first);
    assert_eq!(observed.physical().allocated_bytes, allocated);
    assert_eq!(
        observed.physical().interrupted_files,
        2,
        "all actual zero-length reserved inodes remain counted"
    );
    assert!(!observed.manifest().closed().unwrap());
    let mut next = manifest.clone();
    next.previous = Some(first.clone());
    next.own_slot = 3;
    next.original_request_sha256 = "55".repeat(32);
    next.base_descriptor_sha256 = "66".repeat(32);
    next.members[3].disposition = Disposition::BoundMetadata;
    next.members[4].disposition = Disposition::RetiredUnwritten {
        operation_sha256: "77".repeat(32),
        review_sha256: "99".repeat(32),
    };
    next.validate_successor(&manifest, &first).unwrap();
    let second = directory
        .fill(
            &references[3],
            slots::Pool::Terminal,
            &next.canonical_bytes().unwrap(),
            &mut || Ok(()),
        )
        .unwrap();
    seals.insert(3, second.clone());
    let closed = jobs::observe(&fixture.pages, &second, &seals, &mut || Ok(())).unwrap();
    assert!(closed.manifest().closed().unwrap());
    assert_eq!(
        closed.physical().allocated_bytes,
        allocated,
        "closing never releases promised extents/inodes or pretends they are free"
    );
    assert_eq!(closed.physical().interrupted_files, 1);
    let after = fixture.pages.inventory(&mut || Ok(())).unwrap();
    assert_eq!(
        (before.files, before.directories, before.allocated_bytes),
        (after.files, after.directories, after.allocated_bytes)
    );
    assert!(
        fixture
            .pages
            .admit_writes(4096, 1, 0, &mut || Ok(()))
            .is_err(),
        "generic admission cannot adopt zero-length reservation DATA as ordinary clean state"
    );
    let mut reactivated = next.clone();
    reactivated.members[0].disposition = Disposition::Available;
    assert!(reactivated.validate_successor(&manifest, &first).is_err());
    let mut alias = next.clone();
    alias.members[4].slot = alias.members[0].slot.clone();
    assert!(alias.validate().is_err());
    seals.remove(&2);
    assert!(
        jobs::observe(&fixture.pages, &second, &seals, &mut || Ok(())).is_err(),
        "every metadata inode needs its actual full ancestor-bound bytes"
    );
    let nv = fixture.memory.0.get();
    assert_eq!(
        bundle::hex(&nv),
        fixture.descriptor.selected_nv_head,
        "physical job validation never dispatches C"
    );
}

#[test]
fn exact_layout_refuses_unreviewed_slot_and_existing_inode_allocation_before_overwrite() {
    let fixture = Fixture::new(true);
    let plan = slots::Plan::exact(
        &fixture.descriptor.binding,
        &"aa".repeat(32),
        vec![
            slots::ExactSlot::for_bytes(slots::Pool::Publication(0), slots::Kind::Record, 7)
                .unwrap(),
        ],
    )
    .unwrap();
    let directory = slots::Directory::create(&fixture.pages, plan, &mut || Ok(())).unwrap();
    let refs = directory.allocate_window(0, 1, &mut || Ok(())).unwrap();
    let before = fixture.pages.inventory(&mut || Ok(())).unwrap();
    assert!(directory.allocate_window(1, 1, &mut || Ok(())).is_err());
    assert!(directory
        .fill(
            &refs[0],
            slots::Pool::Publication(0),
            &vec![1; 4097],
            &mut || Ok(())
        )
        .is_err());
    assert!(directory.allocate_window(0, 1, &mut || Ok(())).is_err());
    directory
        .require_unfilled(&refs[0], &mut || Ok(()))
        .unwrap();
    assert_eq!(fixture.pages.inventory(&mut || Ok(())).unwrap(), before);
}
