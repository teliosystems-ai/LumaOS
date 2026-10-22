//! Software DATA fixtures. They are not physical current-C reservation proof.
use super::super::super::super::paged::slots::Pool;
use super::*;
#[derive(Default)]
struct Memory {
    next: u32,
    objects: BTreeMap<u32, (SealedReference, Vec<u8>)>,
    witnesses: Vec<SealedReference>,
    writes: usize,
    reads: usize,
    refused: bool,
}
fn reference(count: u32) -> Reference {
    let ordinal = count / 128;
    let number = ordinal * 138 + count % 128;
    Reference {
        schema_version: 3,
        job: "66".repeat(32),
        number,
        pool: Pool::Publication(ordinal),
        kind: SlotKind::Page,
        capacity: PAGE_BYTES as u64,
        device: 1,
        inode: count as u64 + 100,
        mount: 1,
        allocated_bytes: PAGE_BYTES as u64,
        instance_id: hash(&count.to_be_bytes()),
        created_ctime_seconds: 1,
        created_ctime_nanoseconds: 0,
    }
}
impl Io for Memory {
    fn check(&mut self) -> Result<()> {
        if self.refused {
            Err("software original-boundary refusal".into())
        } else {
            Ok(())
        }
    }
    fn read(&mut self, reference: &SealedReference) -> Result<Vec<u8>> {
        self.check()?;
        self.reads += 1;
        let (actual, bytes) = self
            .objects
            .get(&reference.slot.number)
            .ok_or("software ledger slot absent")?;
        if actual != reference {
            return Err("software ledger actual held allocation differs".into());
        }
        Ok(bytes.clone())
    }
    fn seal_node(&mut self, bytes: &[u8]) -> Result<SealedReference> {
        self.check()?;
        let slot = reference(self.next);
        self.next += 1;
        self.writes += 1;
        let sealed = SealedReference {
            slot,
            bytes: bytes.len() as u64,
            sha256: hash(bytes),
            sealed_ctime_seconds: 2,
            sealed_ctime_nanoseconds: 0,
        };
        self.objects
            .insert(sealed.slot.number, (sealed.clone(), bytes.to_vec()));
        self.witnesses.push(sealed.clone());
        Ok(sealed)
    }
}
fn binding() -> map::CustodyBinding {
    map::CustodyBinding {
        installation: "11".repeat(32),
        sealed_genesis_sha256: "22".repeat(32),
    }
}
fn additions(n: u32) -> Vec<Edit> {
    (0..n)
        .map(|number| {
            let mut slot = reference(number);
            slot.job = "77".repeat(32);
            slot.inode += 10_000;
            let next = Entry {
                slot,
                state: State::Available,
            };
            Edit {
                key: next.key().unwrap(),
                expected_sha256: None,
                next,
            }
        })
        .collect()
}
#[test]
fn direct_ledger_selects_exact_addresses_and_counts_capacity_without_self_hashes() {
    let root = Root::empty_data(&binding()).unwrap();
    let mut io = Memory::default();
    let edits = additions(40);
    let next = prepare(&root, &edits, &mut io).unwrap();
    assert_eq!((next.entries, next.available), (40, 40));
    assert_eq!(next.available_bytes, 40 * PAGE_BYTES as u64);
    assert!(next.page.as_ref().unwrap().height > 0);
    for edit in &edits {
        assert_eq!(
            lookup(&next, &edit.key, &mut io).unwrap(),
            Some(edit.next.clone())
        );
    }
    let witnesses = io.witnesses.clone();
    let writes = io.writes;
    verify(&root, &next, &edits, &witnesses, &mut io).unwrap();
    assert_eq!(io.writes, writes);
    let mut spent = edits[..3].to_vec();
    for edit in &mut spent {
        edit.expected_sha256 = Some(edit.next.sha256().unwrap());
        edit.next.state = State::Spent {
            operation_sha256: "55".repeat(32),
            purpose: Purpose::ReservationIndex,
        };
    }
    io.witnesses.clear();
    let final_root = prepare(&next, &spent, &mut io).unwrap();
    assert_eq!((final_root.entries, final_root.available), (40, 37));
    assert_eq!(final_root.available_bytes, 37 * PAGE_BYTES as u64);
    let proof = io.witnesses.clone();
    verify(&next, &final_root, &spent, &proof, &mut io).unwrap();
    assert_eq!(
        lookup(&final_root, &edits[3].key, &mut io).unwrap(),
        Some(edits[3].next.clone())
    );
}
#[test]
fn consumed_addresses_cannot_reappear_redirect_or_change_the_exact_cas() {
    let root = Root::empty_data(&binding()).unwrap();
    let mut io = Memory::default();
    let edits = additions(1);
    let next = prepare(&root, &edits, &mut io).unwrap();
    let mut spent = edits[0].clone();
    spent.expected_sha256 = Some(spent.next.sha256().unwrap());
    spent.next.state = State::Spent {
        operation_sha256: "55".repeat(32),
        purpose: Purpose::Descriptor,
    };
    let mut redirected = spent.clone();
    redirected.next.slot.inode += 1;
    assert!(prepare(&next, &[redirected], &mut io).is_err());
    let mut wrong = spent.clone();
    wrong.expected_sha256 = Some("99".repeat(32));
    assert!(prepare(&next, &[wrong], &mut io).is_err());
    let consumed = prepare(&next, &[spent.clone()], &mut io).unwrap();
    let mut reuse = edits[0].clone();
    reuse.expected_sha256 = Some(spent.next.sha256().unwrap());
    assert!(prepare(&consumed, &[reuse], &mut io).is_err());
    assert!(prepare(&consumed, &[spent], &mut io).is_err());
    let mut wrong_class = edits[0].clone();
    wrong_class.expected_sha256 = Some(wrong_class.next.sha256().unwrap());
    wrong_class.next.state = State::Spent {
        operation_sha256: "55".repeat(32),
        purpose: Purpose::SemanticRecord,
    };
    assert!(wrong_class.validate().is_err());
    assert!(prepare(&root, &[edits[0].clone(), edits[0].clone()], &mut io).is_err());
}
#[test]
fn ordered_physical_witness_replay_rejects_missing_extra_reordered_and_aliased_slots() {
    let root = Root::empty_data(&binding()).unwrap();
    let mut io = Memory::default();
    let edits = additions(40);
    let next = prepare(&root, &edits, &mut io).unwrap();
    let proof = io.witnesses.clone();
    assert!(verify(&root, &next, &edits, &proof[..proof.len() - 1], &mut io).is_err());
    let mut reordered = proof.clone();
    reordered.swap(0, 1);
    assert!(verify(&root, &next, &edits, &reordered, &mut io).is_err());
    let mut alias = proof.clone();
    alias[1] = alias[0].clone();
    let reads = io.reads;
    assert!(verify(&root, &next, &edits, &alias, &mut io).is_err());
    assert_eq!(reads, io.reads);
    let mut extra = proof.clone();
    extra.push(io.seal_node(b"extra actual DATA slot").unwrap());
    assert!(verify(&root, &next, &edits, &extra, &mut io).is_err());
}
#[test]
fn bound_and_current_context_failures_precede_backing_storage_access() {
    let root = Root::empty_data(&binding()).unwrap();
    let mut io = Memory::default();
    let large = additions(MAX_EDITS as u32 + 1);
    assert!(prepare(&root, &large, &mut io).is_err());
    assert_eq!((io.reads, io.writes), (0, 0));
    io.refused = true;
    assert!(prepare(&root, &additions(1), &mut io).is_err());
    assert_eq!((io.reads, io.writes), (0, 0));
    assert!(lookup(&root, &format!("{}00000000", "77".repeat(32)), &mut io).is_err());
    io.refused = false;
    let next = prepare(&root, &additions(1), &mut io).unwrap();
    let mut other = next.clone();
    other.binding.installation = "33".repeat(32);
    assert!(lookup(&other, &additions(1)[0].key, &mut io).is_err());
    let mut malformed = next.clone();
    malformed.available_bytes += 1;
    assert!(malformed.validate().is_err());
}
#[test]
fn canonical_direct_pages_refuse_unknown_duplicate_and_padded_data_even_after_rehash() {
    let root = Root::empty_data(&binding()).unwrap();
    let mut io = Memory::default();
    let edits = additions(1);
    let next = prepare(&root, &edits, &mut io).unwrap();
    let reference = next.page.as_ref().unwrap();
    let original = String::from_utf8(io.read(&reference.location).unwrap()).unwrap();
    for raw in [
        format!("{original}\n"),
        original.replacen(
            "\"schema_version\":3",
            "\"schema_version\":3,\"schema_version\":3",
            1,
        ),
        original.replacen(
            "\"schema_version\":3",
            "\"schema_version\":3,\"authority\":true",
            1,
        ),
    ] {
        let mut forged = next.clone();
        forged.page.as_mut().unwrap().location = io.seal_node(raw.as_bytes()).unwrap();
        assert!(lookup(&forged, &edits[0].key, &mut io).is_err());
    }
}
