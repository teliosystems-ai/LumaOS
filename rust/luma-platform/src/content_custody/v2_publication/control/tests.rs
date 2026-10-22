//! Closed DATA framing/selection fixtures, not physical allocation witnesses.
use super::super::super::paged::{cells, slots};
use super::*;
struct Memory {
    data: BTreeMap<String, Vec<u8>>,
    refuse: bool,
    reads: usize,
}
impl Reader for Memory {
    fn check(&mut self) -> Result<()> {
        if self.refuse {
            Err("software readonly descriptor observer revoked".into())
        } else {
            Ok(())
        }
    }
    fn read_descriptor(&mut self, reference: &SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        self.reads += 1;
        self.data
            .get(&reference.sha256)
            .cloned()
            .ok_or_else(|| "software immutable descriptor absent".into())
    }
    fn read_descriptor_original(
        &mut self,
        reference: &SealedReference,
        original: &mut COperation<'_, '_>,
    ) -> Result<Vec<u8>> {
        original.check()?;
        let bytes = self.read_descriptor(reference)?;
        original.check()?;
        Ok(bytes)
    }
}
fn physical(binding: &map::CustodyBinding) -> cells::Selection {
    cells::Selection {
        schema_version: 3,
        domain: "luma-c-fixed-control-inodes-v3".into(),
        binding: binding.clone(),
        cells: std::array::from_fn(|index| cells::Reference {
            index: index as u8,
            device: 1,
            inode: index as u64 + 10,
            mount: 1,
            allocated_bytes: CONTROL_BYTES as u64,
            instance_id: format!("{:064x}", index + 1),
        }),
    }
}
fn slot(number: u32) -> slots::Reference {
    slots::Reference {
        schema_version: 3,
        job: "88".repeat(32),
        number,
        pool: slots::Pool::Publication(0),
        kind: slots::Kind::Page,
        capacity: PAGE_BYTES as u64,
        device: 1,
        inode: number as u64 + 100,
        mount: 1,
        allocated_bytes: PAGE_BYTES as u64,
        instance_id: format!("{:064x}", number + 10),
        created_ctime_seconds: 1,
        created_ctime_nanoseconds: 0,
    }
}
fn descriptor() -> Descriptor {
    let mut value = super::super::tests::initial();
    value.storage = Some(StorageSelection {
        schema_version: 1,
        jobs: None,
        controls: physical(&value.binding),
        locations: locations::Root::empty_data(&value.binding).unwrap(),
        descriptor_slot: slot(0),
        parent_allocation: None,
        post_allocation: super::super::super::paged::PhysicalInventory {
            files: 4,
            directories: 5,
            logical_bytes: 4 * CONTROL_BYTES as u64,
            allocated_bytes: 4 * CONTROL_BYTES as u64,
            interrupted_files: 0,
        },
    });
    value.seal().unwrap()
}
fn register(value: &Descriptor, reader: &mut Memory) -> Cell {
    let bytes = value.slot_frame().unwrap();
    let reference = SealedReference {
        slot: value.storage.as_ref().unwrap().descriptor_slot.clone(),
        bytes: bytes.len() as u64,
        sha256: hash(&bytes),
        sealed_ctime_seconds: 2,
        sealed_ctime_nanoseconds: 0,
    };
    reader.data.insert(reference.sha256.clone(), bytes);
    Cell::for_descriptor(value, reference).unwrap()
}
fn reader() -> Memory {
    Memory {
        data: BTreeMap::new(),
        refuse: false,
        reads: 0,
    }
}
fn pending(base: Base, next: Cell, value: &Descriptor, inactive_index: u8) -> PendingCell {
    PendingCell {
        schema_version: 3,
        domain: "luma-c-direct-slot-pending-v3".into(),
        binding: value.binding.clone(),
        base,
        inactive_index,
        next,
        event_sha256: value.event_sha256.clone(),
        operation_sha256: hash(&serde_json::to_vec(&value.operation).unwrap()),
    }
}
#[test]
fn actual_nv_selects_exactly_one_whole_descriptor_never_empty_or_duplicate_cells() {
    let value = descriptor();
    let mut input = reader();
    let selected = register(&value, &mut input);
    let empty = Cell::empty_data(&value.binding).unwrap();
    let current = tpm::decode(&value.selected_nv_head).unwrap();
    let (index, parsed) = select(&value.binding, current, [&selected, &empty], &mut input).unwrap();
    assert_eq!(index, 0);
    assert_eq!(parsed.bytes().unwrap(), value.bytes().unwrap());
    assert!(select(&value.binding, current, [&empty, &empty], &mut input).is_err());
    assert!(select(&value.binding, current, [&selected, &selected], &mut input).is_err());
    assert!(select(&value.binding, [0xee; 32], [&selected, &empty], &mut input).is_err());
    let mut foreign = empty.clone();
    if let Cell::Empty { binding, .. } = &mut foreign {
        binding.installation = "99".repeat(32);
    }
    assert!(select(&value.binding, current, [&selected, &foreign], &mut input).is_err());
    let key = match &selected {
        Cell::Selected { descriptor, .. } => descriptor.sha256.clone(),
        _ => unreachable!(),
    };
    input.data.get_mut(&key).unwrap()[PAGE_BYTES - 1] = 1;
    assert!(select(&value.binding, current, [&selected, &empty], &mut input).is_err());
}
#[test]
fn fixed_frames_reject_partial_trailing_noncanonical_and_cross_type_data() {
    let value = descriptor();
    let mut input = reader();
    let cell = register(&value, &mut input);
    let bytes = cell.frame().unwrap();
    assert_eq!(Cell::from_frame(&bytes).unwrap(), cell);
    assert!(Cell::from_frame(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = bytes.clone();
    bad[CONTROL_BYTES - 1] = 1;
    assert!(Cell::from_frame(&bad).is_err());
    let mut bad = bytes.clone();
    bad[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Cell::from_frame(&bad).is_err());
    let empty = PendingFrame::empty_data(&value.binding)
        .unwrap()
        .frame()
        .unwrap();
    assert!(Cell::from_frame(&empty).is_err());
    assert!(PendingFrame::from_frame(&bytes).is_err());
    let mut partial = empty.clone();
    partial[100] = if partial[100] == b'x' { b'y' } else { b'x' };
    assert!(PendingFrame::from_frame(&partial).is_err());
    let mut framed = value.slot_frame().unwrap();
    framed[PAGE_BYTES - 1] = 1;
    assert!(Descriptor::from_slot_frame(&framed).is_err());
    let mut ordinary = value.clone();
    ordinary.storage = None;
    ordinary = ordinary.seal().unwrap();
    assert!(ordinary.slot_frame().is_err());
}
#[test]
fn pending_first_and_successor_bind_one_extension_and_cannot_overwrite_current_selector() {
    let first = descriptor();
    let mut input = reader();
    let first_cell = register(&first, &mut input);
    let begin = pending(
        Base::Legacy {
            binding: first.binding.clone(),
            cut: first.legacy.clone(),
        },
        first_cell.clone(),
        &first,
        0,
    );
    begin.verify_descriptors(None, &first).unwrap();
    PendingCell::from_frame(&begin.frame().unwrap()).unwrap();
    let mut second = first.clone();
    second.sequence += 1;
    second.global_ordinal += 1;
    second.previous_descriptor_sha256 = Some(hash(&first.slot_frame().unwrap()));
    second.previous_nv_head = first.selected_nv_head.clone();
    second.phase.state = bootstrap::State::Ready;
    second.storage.as_mut().unwrap().descriptor_slot = slot(1);
    second = second.seal().unwrap();
    let second_cell = register(&second, &mut input);
    let transition = pending(
        Base::Slot {
            index: 0,
            cell: first_cell.clone(),
        },
        second_cell.clone(),
        &second,
        1,
    );
    transition
        .verify_descriptors(Some(&first), &second)
        .unwrap();
    let mut bad = transition.clone();
    bad.inactive_index = 0;
    assert!(bad.frame().is_err());
    let mut bad = transition.clone();
    bad.event_sha256 = "99".repeat(32);
    assert!(bad.frame().is_err());
    let mut bad = transition.clone();
    bad.operation_sha256 = "99".repeat(32);
    assert!(bad.verify_descriptors(Some(&first), &second).is_err());
    let mut replaced = second.clone();
    replaced.storage.as_mut().unwrap().controls.cells[0].inode += 1000;
    replaced = replaced.seal().unwrap();
    assert!(transition
        .verify_descriptors(Some(&first), &replaced)
        .is_err());
    let current = tpm::decode(&second.selected_nv_head).unwrap();
    assert_eq!(
        select(
            &second.binding,
            current,
            [&first_cell, &second_cell],
            &mut input
        )
        .unwrap()
        .0,
        1
    );
}
#[test]
fn original_readonly_observer_refusal_precedes_descriptor_access() {
    let value = descriptor();
    let mut input = reader();
    let selected = register(&value, &mut input);
    let empty = Cell::empty_data(&value.binding).unwrap();
    input.refuse = true;
    assert!(select(
        &value.binding,
        tpm::decode(&value.selected_nv_head).unwrap(),
        [&selected, &empty],
        &mut input
    )
    .is_err());
    assert_eq!(input.reads, 0);
}
#[test]
fn fixed_pending_completion_is_explicit_data_and_never_an_empty_or_prepared_fallback() {
    let value = descriptor();
    let mut input = reader();
    let next = register(&value, &mut input);
    let prepared = pending(
        Base::Legacy {
            binding: value.binding.clone(),
            cut: value.legacy.clone(),
        },
        next,
        &value,
        0,
    );
    let first = PendingFrame::Prepared {
        pending: prepared.clone(),
    }
    .frame()
    .unwrap();
    let completed = PendingFrame::Completed { pending: prepared }
        .frame()
        .unwrap();
    assert_ne!(first, completed);
    assert!(matches!(
        PendingFrame::from_frame(&first).unwrap(),
        PendingFrame::Prepared { .. }
    ));
    assert!(matches!(
        PendingFrame::from_frame(&completed).unwrap(),
        PendingFrame::Completed { .. }
    ));
    assert!(PendingFrame::from_frame(&completed[..completed.len() - 1]).is_err());
    let mut partial = completed;
    partial[CONTROL_BYTES - 1] = 1;
    assert!(PendingFrame::from_frame(&partial).is_err());
}
