//! Fixtures are explicit DATA, not native PAM/C selection or creator evidence.
use super::job::JobReservation;
use super::*;
use crate::content_checkpoint::custody::indexed::selection_data_sha256;
use crate::content_checkpoint::custody::paged::{self, cells, slots};
use crate::content_checkpoint::custody::protocol::{
    software_worker_operation, TypedOperationSource,
};
use crate::content_checkpoint::custody::v2_publication as publication;
use luma_content_store::corpus_index::{BuilderIdentity, CorpusIndexLimits};
use std::cell::Cell;
use std::collections::BTreeMap;
fn binding() -> OwnerBinding {
    OwnerBinding {
        installation: "1".repeat(64),
        owner: "2".repeat(64),
        owner_generation: 7,
    }
}
fn input() -> request::Input {
    request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding(),
        request_id: "a".repeat(32),
        operation: request::Operation::Step {
            job_id: "b".repeat(32),
            expected_job_sha256: "3".repeat(64),
            window: request::Window {
                maximum: 1,
                read_bytes: 1024 * 1024,
                write_bytes: 1024 * 1024,
            },
        },
    }
}
fn base() -> Base {
    Base {
        binding: binding(),
        descriptor_sha256: "4".repeat(64),
        nv_head: "5".repeat(64),
        owner_sha256: "6".repeat(64),
        physical: PhysicalInventory {
            regular_files: 20,
            directories: 10,
            allocated_bytes: 81920,
            logical_bytes: 5000,
            incomplete_objects: 0,
        },
        segments: 1,
        index_sha256: Some("7".repeat(64)),
    }
}
fn objects() -> Vec<ObjectWriteSpec> {
    vec![ObjectWriteSpec {
        sha256: "8".repeat(64),
        bytes: 500,
    }]
}
fn review(input: &request::Input, objects: &[ObjectWriteSpec]) -> phase::WindowReview {
    let mut r = phase::WindowReview {
        schema_version: 2,
        input_sha256: input.sha256().unwrap(),
        base_sha256: "3".repeat(64),
        phase: "ingest".into(),
        review_sha256: String::new(),
        core_review_sha256: "9".repeat(64),
        planned_objects_sha256: hash(&serde_json::to_vec(objects).unwrap()),
        builder: luma_content_store::corpus_index::BuilderIdentity {
            source_sha256: "a".repeat(64),
            runtime_sha256: "b".repeat(64),
        },
        policy_sha256: policy::sha256().unwrap(),
        metadata_maximum: phase::MetadataMaximum::compiled(),
        source_bytes: 100,
        maximum_read_bytes: 1024 * 1024,
        maximum_write_bytes: 1024 * 1024,
    };
    // Exact fixture of the public closed WindowReview canonical tuple. It is
    // checked by the real validator; no fake Plan or native authority is made.
    r.review_sha256 = hash(
        &serde_json::to_vec(&(
            "luma-native-index-window-review-v2",
            r.schema_version,
            &r.input_sha256,
            &r.base_sha256,
            &r.phase,
            &r.core_review_sha256,
            &r.planned_objects_sha256,
            &r.builder,
            &r.policy_sha256,
            &r.metadata_maximum,
            r.source_bytes,
            r.maximum_read_bytes,
            r.maximum_write_bytes,
        ))
        .unwrap(),
    );
    r.validate().unwrap();
    r
}
fn attributed(input: &request::Input, review: &str) -> Attribution {
    let profile = input.effect_profile(review).unwrap();
    let storage = "8:1";
    Attribution {
        rpc_sha256: "c".repeat(64),
        profile: profile.clone(),
        storage_device: storage.into(),
        worker_pid: 123,
        worker_start: 456,
        worker_label: "luma-acquisition (enforce)".into(),
        lease: crate::resources::Token {
            lease_id: "d".repeat(32),
            generation: 1,
            manager_epoch: "e".repeat(32),
        },
        paired_read: crate::content_index::scope::original_usage(
            &profile,
            storage,
            &input.binding,
            &input.sha256().unwrap(),
            true,
        )
        .unwrap(),
        effect: Audit {
            subject: input.binding.owner.clone(),
            subject_generation: input.binding.owner_generation,
            grant_id: "effect-grant".into(),
            grant_version: 1,
            checkpoint_head: "f".repeat(64),
            operation_id: Some("a".repeat(32)),
            usage: crate::content_index::scope::original_usage(
                &profile,
                storage,
                &input.binding,
                &input.sha256().unwrap(),
                false,
            )
            .unwrap(),
        },
    }
}
fn prepared() -> (Preparation, InventoryPlan) {
    let input = input();
    let objects = objects();
    let review = review(&input, &objects);
    Preparation::data(
        &base(),
        &input,
        &review,
        &objects,
        &attributed(&input, &review.review_sha256),
        &mut || Ok(()),
    )
    .unwrap()
}
#[test]
fn canonical_reservation_preserves_actual_physical_and_exact_finite_liability() {
    let (p, inventory) = prepared();
    let bytes = p.bytes().unwrap();
    assert!(bytes.len() < PREPARATION_BYTES as usize);
    assert_eq!(Preparation::parse(&bytes).unwrap(), p);
    assert_eq!(p.base.physical, base().physical);
    assert!(p.liability.allocated_bytes > p.base.physical.allocated_bytes);
    assert_eq!(inventory.root(), &p.inventory);
    assert_eq!(inventory.root().object_count(), 1);
    assert_eq!(inventory.root().object_bytes(), 500);
    assert!(inventory.root().closure_bytes() > 0);
    assert_eq!(inventory.root().page_count(), 1);
    assert_eq!(inventory.root().sha256().unwrap().len(), 64);
    assert!(Preparation::parse(serde_json::to_string_pretty(&p).unwrap().as_bytes()).is_err());
    let mut value = serde_json::to_value(&p).unwrap();
    value["go"] = serde_json::Value::Bool(true);
    assert!(Preparation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn independent_replay_refuses_changed_before_source_review_inventory_and_current_callback() {
    let (p, _) = prepared();
    let mut before = base();
    before.physical.allocated_bytes += 4096;
    assert!(p
        .replay_data(
            &before,
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut before = base();
    before.descriptor_sha256 = "d".repeat(64);
    assert!(p
        .replay_data(
            &before,
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut input = p.input.clone();
    input.request_id = "e".repeat(32);
    assert!(p
        .replay_data(
            &base(),
            &input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut values = objects();
    values[0].bytes += 1;
    assert!(p
        .replay_data(
            &base(),
            &p.input,
            &p.review,
            &values,
            &p.original,
            &mut || Ok(())
        )
        .is_err());
    let mut r = p.review.clone();
    r.policy_sha256 = "f".repeat(64);
    assert!(p
        .replay_data(&base(), &p.input, &r, &objects(), &p.original, &mut || Ok(
            ()
        ))
        .is_err());
    assert!(p
        .replay_data(
            &base(),
            &p.input,
            &p.review,
            &objects(),
            &p.original,
            &mut || Err("fixture revoked".into())
        )
        .is_err());
}
#[test]
fn attribution_data_cannot_relabel_read_as_write_or_other_worker_lease_source() {
    let (p, _) = prepared();
    for field in 0..7 {
        let mut a = p.original.clone();
        match field {
            0 => a.effect.usage = a.paired_read.clone(),
            1 => a.profile = p.input.profile().unwrap(),
            2 => a.worker_label = "unconfined".into(),
            3 => a.worker_start = 0,
            4 => a.lease.generation = 0,
            5 => a.effect.subject_generation += 1,
            6 => a.paired_read.selector.digest = "9".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            a.validate(&p.input, &p.review.review_sha256).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn impossible_or_uncovered_budget_refuses_instead_of_claiming_reserved_capacity() {
    let (p, _) = prepared();
    let mut b = base();
    b.physical.allocated_bytes = 64 * 1024 * 1024 * 1024;
    assert!(Preparation::data(
        &b,
        &p.input,
        &p.review,
        &objects(),
        &p.original,
        &mut || Ok(())
    )
    .is_err());
    let mut r = p.review.clone();
    r.maximum_write_bytes = 128 * 1024 * 1024;
    // The original review hash is now wrong even before the unchanged effect
    // ceiling independently rejects derivative plus metadata liability.
    assert!(
        Preparation::data(&base(), &p.input, &r, &objects(), &p.original, &mut || Ok(
            ()
        ))
        .is_err()
    );
    let mut altered = p.clone();
    altered.capacity = policy::Policy::compiled()
        .admit_data(
            &base().physical,
            base().segments,
            [],
            &policy::Liability::default(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(altered.validate_data().is_err());
    let mut understated = p.clone();
    understated.liability.allocated_bytes -= 1;
    understated.capacity = policy::Policy::compiled()
        .admit_data(
            &base().physical,
            base().segments,
            [],
            &understated.liability,
            &mut || Ok(()),
        )
        .unwrap();
    assert!(understated.validate_data().is_err());
}
#[test]
fn retain_is_distinct_finite_action_preserving_every_byte_and_inode_liability() {
    let (p, _) = prepared();
    let input = request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding(),
        request_id: "f".repeat(32),
        operation: request::Operation::Retain {
            job_id: "b".repeat(32),
            expected_job_sha256: p.review.base_sha256.clone(),
            preparation_sha256: hash(&p.bytes().unwrap()),
            retained_inventory_sha256: "a".repeat(64),
            review_sha256: "b".repeat(64),
        },
    };
    let a = attributed(&input, &"b".repeat(64));
    let retained = RetainedPreparation::data(&p, &input, &a).unwrap();
    assert_eq!(retained.liability, p.liability);
    assert!(retained.bytes(&p).unwrap().len() < PREPARATION_BYTES as usize);
    let mut changed = retained.clone();
    changed.liability.allocated_bytes -= 1;
    assert!(changed.validate_against(&p).is_err());
    let mut changed = retained.clone();
    changed.liability.regular_files -= 1;
    assert!(changed.validate_against(&p).is_err());
    assert!(RetainedPreparation::data(&p, &p.input, &p.original).is_err());
    let mut wrong = input;
    wrong.binding.owner_generation += 1;
    assert!(RetainedPreparation::data(&p, &wrong, &a).is_err());
}

// Start reservation fixtures: an explicit empty owner head, fixed builder
// identity and software original operation. None is native selection.
fn builder() -> BuilderIdentity {
    BuilderIdentity {
        source_sha256: "d".repeat(64),
        runtime_sha256: "e".repeat(64),
    }
}
fn owner() -> OwnerHeadV2 {
    OwnerHeadV2::empty_data(&binding(), PhysicalInventory::default()).unwrap()
}
fn start_input(owner: &OwnerHeadV2) -> request::Input {
    request::Input {
        schema_version: 1,
        login: "admin".into(),
        binding: binding(),
        request_id: "1".repeat(32),
        operation: request::Operation::Start {
            expected_owner_sha256: owner.sha256().unwrap(),
            expected_selection_sha256: selection_data_sha256(owner, None).unwrap(),
            job_id: "2".repeat(32),
            dimensions: 8,
            limits: CorpusIndexLimits {
                read_bytes: 128 * 1024 * 1024,
                write_bytes: 64 * 1024 * 1024,
                source_bytes: 4 * 1024 * 1024,
                postings: 65536,
                floating_operations: 100_000_000,
            },
        },
    }
}
fn start_base(owner: &OwnerHeadV2) -> Base {
    Base {
        owner_sha256: owner.sha256().unwrap(),
        segments: owner.history.segments,
        index_sha256: None,
        ..base()
    }
}
fn reserved() -> (JobReservation, OwnerHeadV2, request::Input, Base) {
    let owner = owner();
    let start = start_input(&owner);
    let before = start_base(&owner);
    let transition =
        JobReservation::transition_data(&before, &owner, &start, &builder(), &mut || Ok(()))
            .unwrap();
    let original = attributed(&start, &transition.review_sha256);
    let value = JobReservation::data(&before, &owner, &start, &builder(), &original, &mut || {
        Ok(())
    })
    .unwrap();
    (value, owner, start, before)
}
/// Raises the first decimal `field` after the one `section` marker by one.
/// The bytes stay canonical JSON, so only the semantic validator can refuse.
fn bump(bytes: &[u8], section: &str, field: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(section).count(), 1, "{section}");
    let key = format!("\"{field}\":");
    let start = text.find(section).unwrap() + section.len();
    let at = start + text[start..].find(&key).unwrap() + key.len();
    let end = at + text[at..].find(|c: char| !c.is_ascii_digit()).unwrap();
    let value: u64 = text[at..end].parse().unwrap();
    format!("{}{}{}", &text[..at], value + 1, &text[end..]).into_bytes()
}
#[test]
fn start_reservation_is_canonical_closed_data_with_exact_metadata_liability() {
    let (r, owner, start, before) = reserved();
    let bytes = r.bytes().unwrap();
    assert!(bytes.len() < PREPARATION_BYTES as usize);
    assert_eq!(JobReservation::parse(&bytes).unwrap(), r);
    assert_eq!(r.base(), &before);
    assert_eq!(r.input(), &start);
    assert_eq!(r.builder(), &builder());
    let transition =
        JobReservation::transition_data(&before, &owner, &start, &builder(), &mut || Ok(()))
            .unwrap();
    assert_eq!(r.original(), &attributed(&start, &transition.review_sha256));
    assert!(JobReservation::parse(serde_json::to_string_pretty(&r).unwrap().as_bytes()).is_err());
    let mut extra = bytes.clone();
    assert_eq!(extra.pop(), Some(b'}'));
    extra.extend_from_slice(b",\"go\":true}");
    assert!(JobReservation::parse(&extra).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with("{\"schema_version\":1,"));
    assert_eq!(text.matches("luma-c-index-job-reservation-v1").count(), 1);
    let mut tampered = vec![
        text.replacen("{\"schema_version\":1,", "{\"schema_version\":2,", 1)
            .into_bytes(),
        text.replacen(
            "luma-c-index-job-reservation-v1",
            "luma-c-index-job-reservation-v2",
            1,
        )
        .into_bytes(),
    ];
    for (section, field) in [
        ("\"liability\":{", "allocated_bytes"),
        ("\"liability\":{", "regular_files"),
        ("\"capacity\":{", "retained_records"),
        ("\"base\":{", "segments"),
        ("\"base\":{", "allocated_bytes"),
        ("\"input\":{", "owner_generation"),
    ] {
        tampered.push(bump(&bytes, section, field));
    }
    for (case, changed) in tampered.iter().enumerate() {
        assert_ne!(changed, &bytes, "case {case}");
        // Still well-formed canonical DATA: the refusal below is semantic.
        let value: JobReservation = serde_json::from_slice(changed).unwrap();
        assert_eq!(&serde_json::to_vec(&value).unwrap(), changed, "case {case}");
        assert!(JobReservation::parse(changed).is_err(), "case {case}");
    }
}
#[test]
fn start_replay_refuses_changed_builder_before_input_and_current_callback() {
    let (r, owner, start, before) = reserved();
    let original = r.original().clone();
    let replay = |base: &Base, request: &request::Input, identity: &BuilderIdentity| {
        r.replay_data(base, &owner, request, identity, &original, &mut || Ok(()))
    };
    replay(&before, &start, &builder()).unwrap();
    let mut other = builder();
    other.runtime_sha256 = "f".repeat(64);
    assert!(replay(&before, &start, &other).is_err());
    for field in 0..3 {
        let mut changed = before.clone();
        match field {
            0 => changed.physical.allocated_bytes += 4096,
            1 => changed.nv_head = "d".repeat(64),
            _ => changed.descriptor_sha256 = "d".repeat(64),
        }
        assert!(
            replay(&changed, &start, &builder()).is_err(),
            "field {field}"
        );
    }
    let mut changed = start.clone();
    changed.request_id = "e".repeat(32);
    assert!(replay(&before, &changed, &builder()).is_err());
    let mut revoke = || -> Result<()> { Err("fixture revoked".into()) };
    assert!(r
        .replay_data(&before, &owner, &start, &builder(), &original, &mut revoke)
        .is_err());
}
#[test]
fn start_transition_requires_exact_selected_owner_without_index_leaf() {
    let owner = owner();
    let start = start_input(&owner);
    let before = start_base(&owner);
    let transition = |base: &Base, request: &request::Input| {
        JobReservation::transition_data(base, &owner, request, &builder(), &mut || Ok(()))
    };
    transition(&before, &start).unwrap();
    assert!(transition(&before, &input()).is_err());
    let mut stale = start.clone();
    if let request::Operation::Start {
        expected_selection_sha256,
        ..
    } = &mut stale.operation
    {
        *expected_selection_sha256 = "c".repeat(64);
    }
    assert!(transition(&before, &stale).is_err());
    for field in 0..4 {
        let mut changed = before.clone();
        match field {
            0 => changed.index_sha256 = Some("7".repeat(64)),
            1 => changed.segments += 1,
            2 => changed.owner_sha256 = "6".repeat(64),
            _ => changed.binding.owner_generation += 1,
        }
        assert!(transition(&changed, &start).is_err(), "field {field}");
    }
}
#[test]
fn start_reservation_refuses_relabelled_attribution_and_uncovered_capacity() {
    let (r, owner, start, before) = reserved();
    let reserve = |base: &Base, original: &Attribution| {
        JobReservation::data(base, &owner, &start, &builder(), original, &mut || Ok(()))
    };
    assert_eq!(reserve(&before, r.original()).unwrap(), r);
    assert!(reserve(&before, &attributed(&start, &"9".repeat(64))).is_err());
    // The compiled quota is inclusive; the reservation's own metadata must fit.
    let mut full = before.clone();
    full.physical.allocated_bytes = 64 * 1024 * 1024 * 1024;
    assert!(reserve(&full, r.original()).is_err());
    let mut revoke = || -> Result<()> { Err("fixture revoked".into()) };
    assert!(JobReservation::data(
        &before,
        &owner,
        &start,
        &builder(),
        r.original(),
        &mut revoke
    )
    .is_err());
}

fn storage(files: u64, binding: &map::CustodyBinding) -> publication::StorageSelection {
    let control = publication::CONTROL_BYTES as u64;
    publication::StorageSelection {
        schema_version: 1,
        jobs: None,
        controls: cells::Selection {
            schema_version: 3,
            domain: "luma-c-fixed-control-inodes-v3".into(),
            binding: binding.clone(),
            cells: std::array::from_fn(|index| cells::Reference {
                index: index as u8,
                device: 1,
                inode: index as u64 + 10,
                mount: 1,
                allocated_bytes: control,
                instance_id: format!("{:064x}", index + 1),
            }),
        },
        locations: publication::locations::Root::empty_data(binding).unwrap(),
        descriptor_slot: slots::Reference {
            schema_version: 3,
            job: "88".repeat(32),
            number: 0,
            pool: slots::Pool::Publication(0),
            kind: slots::Kind::Page,
            capacity: PAGE_BYTES as u64,
            device: 1,
            inode: 100,
            mount: 1,
            allocated_bytes: PAGE_BYTES as u64,
            instance_id: format!("{:064x}", 10),
            created_ctime_seconds: 1,
            created_ctime_nanoseconds: 0,
        },
        parent_allocation: None,
        post_allocation: paged::PhysicalInventory {
            files,
            directories: 5,
            logical_bytes: 4 * control,
            allocated_bytes: 4 * control,
            interrupted_files: 0,
        },
    }
}
/// A sealed Ready successor of the bootstrap fixture, with direct-slot
/// storage DATA when `files` is given and a hash backend otherwise.
fn ready(files: Option<u64>) -> Descriptor {
    let base = publication::tests::initial();
    let selected = Selector::for_descriptor(&base).unwrap();
    Descriptor {
        sequence: 2,
        global_ordinal: 3,
        previous_descriptor_sha256: Some(selected.descriptor_sha256),
        previous_nv_head: selected.nv_head,
        phase: publication::bootstrap::Phase {
            state: publication::bootstrap::State::Ready,
            ..base.phase.clone()
        },
        storage: files.map(|files| storage(files, &base.binding)),
        ..base
    }
    .seal()
    .unwrap()
}
fn owner_leaf(binding: OwnerBinding, head: &OwnerHeadV2) -> Vec<u8> {
    let bytes = head.canonical_bytes().unwrap();
    serde_json::to_vec(&OwnerLeaf::V2 {
        binding,
        head: RecordRef {
            sha256: hash(&bytes),
            bytes: bytes.len() as u64,
        },
        physical: base().physical,
    })
    .unwrap()
}
/// Software C reads: one selected descriptor (optionally replaced after the
/// first observation), the three role values and immutable records by digest.
struct View {
    descriptor: Descriptor,
    later: Option<Descriptor>,
    calls: usize,
    unavailable: Option<Vec<u8>>,
    owner: Option<Vec<u8>>,
    index: Option<Vec<u8>>,
    records: BTreeMap<String, Vec<u8>>,
}
impl View {
    fn new(descriptor: Descriptor, head: &OwnerHeadV2) -> Self {
        let bytes = head.canonical_bytes().unwrap();
        Self {
            descriptor,
            later: None,
            calls: 0,
            unavailable: None,
            owner: Some(owner_leaf(binding(), head)),
            index: None,
            records: BTreeMap::from([(hash(&bytes), bytes)]),
        }
    }
}
impl PreparationView for View {
    fn current(&mut self, original: &mut OriginalCOperation<'_>) -> Result<(Selector, Descriptor)> {
        original.check()?;
        self.calls += 1;
        let value = match &self.later {
            Some(later) if self.calls > 1 => later.clone(),
            _ => self.descriptor.clone(),
        };
        Ok((Selector::for_descriptor(&value)?, value))
    }
    fn value(
        &mut self,
        root: &map::Root,
        literal: &[u8],
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Option<Vec<u8>>> {
        original.check()?;
        if literal != owner_key(&binding())?.as_bytes() {
            return Err("fixture view reads only the fixture owner key".into());
        }
        match root.kind {
            map::Kind::Unavailable => Ok(self.unavailable.clone()),
            map::Kind::OwnerStates => Ok(self.owner.clone()),
            map::Kind::IndexGenerations => Ok(self.index.clone()),
            _ => Err("fixture view reads only the three Start roles".into()),
        }
    }
    fn read_record(
        &mut self,
        reference: &RecordRef,
        _maximum: usize,
        original: &mut OriginalCOperation<'_>,
    ) -> Result<Vec<u8>> {
        original.check()?;
        self.records
            .get(&reference.sha256)
            .cloned()
            .ok_or_else(|| "fixture immutable record absent".into())
    }
}
/// The fixed builder as re-proved by each check; it reports the second
/// identity once more than `switch_after` checks have run.
struct Builder {
    identities: [BuilderIdentity; 2],
    checks: Cell<usize>,
    switch_after: usize,
}
impl Builder {
    fn fixed() -> Self {
        Self {
            identities: [builder(), builder()],
            checks: Cell::new(0),
            switch_after: usize::MAX,
        }
    }
}
impl CurrentBuilder for Builder {
    fn identity(&self) -> &BuilderIdentity {
        &self.identities[usize::from(self.checks.get() > self.switch_after)]
    }
    fn check(&self, original: &mut OriginalCOperation<'_>) -> Result<()> {
        original.check()?;
        self.checks.set(self.checks.get() + 1);
        Ok(())
    }
}
fn source(a: &Attribution, purpose: SourcePurpose) -> TypedOperationSource {
    TypedOperationSource {
        schema_version: 1,
        request_sha256: a.rpc_sha256.clone(),
        purpose,
        profile: a.profile.clone(),
        storage_device: a.storage_device.clone(),
        binding: binding(),
        worker_pid: a.worker_pid,
        worker_start: a.worker_start,
        worker_label: a.worker_label.clone(),
        lease: a.lease.clone(),
    }
}
/// Runs the verifier under a software original operation whose check is
/// revoked after `allowed` calls; returns the result and the calls made.
fn verify(
    view: &mut View,
    start: &request::Input,
    builder: &Builder,
    a: &Attribution,
    purpose: SourcePurpose,
    allowed: usize,
) -> (Result<VerifiedIndexPreparation>, usize) {
    let mut calls = 0_usize;
    let mut check = || -> Result<()> {
        calls += 1;
        if calls > allowed {
            Err("fixture original operation revoked".into())
        } else {
            Ok(())
        }
    };
    let mut original = software_worker_operation(&a.effect, source(a, purpose), &mut check);
    let result = verify_index_start(view, start, builder, &mut original);
    drop(original);
    (result, calls)
}
fn refusal(result: Result<VerifiedIndexPreparation>) -> String {
    match result {
        Ok(_) => panic!("fixture Start reservation was not refused"),
        Err(error) => error.to_string(),
    }
}
#[test]
fn start_verifier_reconstructs_reservation_from_selected_owner_and_fixed_builder() {
    let (expected, owner, start, _) = reserved();
    let a = expected.original().clone();
    let descriptor = ready(Some(4));
    let mut view = View::new(descriptor.clone(), &owner);
    let current = Builder::fixed();
    let (result, _) = verify(
        &mut view,
        &start,
        &current,
        &a,
        SourcePurpose::IndexPrepare,
        usize::MAX,
    );
    let parts = match result {
        Ok(proof) => proof.into_parts(),
        Err(error) => panic!("{error}"),
    };
    let selected = Selector::for_descriptor(&descriptor).unwrap();
    assert_eq!(parts.kind, PreparedKind::Start);
    assert_eq!(parts.base, selected);
    assert_eq!(parts.owner_root, descriptor.roots.owners);
    assert_eq!(parts.index_root, descriptor.roots.index_generations);
    assert_eq!(
        parts.owner_literal,
        owner_key(&binding()).unwrap().into_bytes()
    );
    assert_eq!(Some(parts.expected_owner_value.clone()), view.owner);
    assert_eq!(parts.expected_index_value, None);
    assert_eq!(parts.records.len(), 2);
    let (reference, bytes) = &parts.records[0];
    assert_eq!(reference, &parts.preparation);
    assert_eq!(reference.sha256, hash(bytes));
    assert_eq!(reference.bytes, bytes.len() as u64);
    let reservation = JobReservation::parse(bytes).unwrap();
    assert_eq!(reservation.original(), expected.original());
    assert_eq!(reservation.input(), &start);
    assert_eq!(reservation.builder(), &builder());
    assert_eq!(
        reservation.base().descriptor_sha256,
        selected.descriptor_sha256
    );
    assert_eq!(reservation.base().nv_head, selected.nv_head);
    assert_eq!(reservation.base().physical, base().physical);
    assert_eq!(reservation.base().index_sha256, None);
    assert_eq!(
        reservation,
        JobReservation::data(
            reservation.base(),
            &owner,
            &start,
            &builder(),
            expected.original(),
            &mut || Ok(())
        )
        .unwrap()
    );
    let (leaf_reference, leaf_bytes) = &parts.records[1];
    assert_eq!(leaf_reference.sha256, hash(leaf_bytes));
    let leaf = Leaf::parse(leaf_bytes, &binding()).unwrap();
    assert_eq!(leaf.preparation, Some(parts.preparation.clone()));
    assert!(leaf.current_job.is_none() && leaf.current_generation.is_none());
    assert_eq!(
        &Reference::parse(&parts.replacement_index_value, &binding())
            .unwrap()
            .record,
        leaf_reference
    );
    assert_eq!(parts.binding, binding());
    assert_eq!(parts.input_sha256, start.sha256().unwrap());
    assert_eq!(
        parts.source_sha256,
        hash(
            &serde_json::to_vec(&(
                "luma-c-original-worker-source-v1",
                source(&a, SourcePurpose::IndexPrepare)
            ))
            .unwrap()
        )
    );
    assert_eq!(parts.original_authority, a.effect);
    assert_eq!(current.checks.get(), 2);
    assert_eq!(view.calls, 2);
}
#[test]
fn start_verifier_refuses_selected_leaf_stale_owner_purpose_builder_and_c_cut() {
    let (r, owner, start, _) = reserved();
    let a = r.original().clone();
    let fresh = || View::new(ready(Some(4)), &owner);
    let run = |mut view: View, request: &request::Input, builder: Builder, purpose| {
        refusal(verify(&mut view, request, &builder, &a, purpose, usize::MAX).0)
    };
    let index = SourcePurpose::IndexPrepare;
    let mut cases: Vec<(String, &str)> = Vec::new();
    let mut view = fresh();
    view.index = Some(b"{}".to_vec());
    cases.push((
        run(view, &start, Builder::fixed(), index.clone()),
        "owner without a C-selected index leaf",
    ));
    for field in 0..2 {
        let mut stale = start.clone();
        if let request::Operation::Start {
            expected_owner_sha256,
            expected_selection_sha256,
            ..
        } = &mut stale.operation
        {
            match field {
                0 => *expected_selection_sha256 = "c".repeat(64),
                _ => *expected_owner_sha256 = "c".repeat(64),
            }
        }
        cases.push((
            run(fresh(), &stale, Builder::fixed(), index.clone()),
            "index start source/owner/selected generation changed",
        ));
    }
    cases.push((
        run(fresh(), &input(), Builder::fixed(), index.clone()),
        "requires an exact Start request",
    ));
    cases.push((
        run(fresh(), &start, Builder::fixed(), SourcePurpose::Select),
        "genuine original IndexPrepare purpose/source",
    ));
    let mut other = builder();
    other.runtime_sha256 = "f".repeat(64);
    let switching = Builder {
        identities: [builder(), other],
        checks: Cell::new(0),
        switch_after: 1,
    };
    cases.push((
        run(fresh(), &start, switching, index.clone()),
        "fixed index builder changed during Start reservation",
    ));
    cases.push((
        run(
            View::new(publication::tests::initial(), &owner),
            &start,
            Builder::fixed(),
            index.clone(),
        ),
        "global C bootstrap is pending",
    ));
    cases.push((
        run(
            View::new(ready(None), &owner),
            &start,
            Builder::fixed(),
            index.clone(),
        ),
        "cannot use a hash backend, stale C cut or another installation",
    ));
    let mut elsewhere = start.clone();
    elsewhere.binding.installation = "3".repeat(64);
    cases.push((
        run(fresh(), &elsewhere, Builder::fixed(), index.clone()),
        "cannot use a hash backend, stale C cut or another installation",
    ));
    let mut view = fresh();
    view.later = Some(ready(Some(5)));
    cases.push((
        run(view, &start, Builder::fixed(), index.clone()),
        "C selection changed before preparation semantic proof delivery",
    ));
    let mut view = fresh();
    view.unavailable = Some(b"{}".to_vec());
    cases.push((
        run(view, &start, Builder::fixed(), index.clone()),
        "owner is C-selected unavailable",
    ));
    let mut view = fresh();
    view.owner = None;
    cases.push((
        run(view, &start, Builder::fixed(), index.clone()),
        "requires an existing C-selected paged owner",
    ));
    let mut view = fresh();
    view.owner = Some(owner_leaf(
        OwnerBinding {
            owner_generation: 8,
            ..binding()
        },
        &owner,
    ));
    cases.push((
        run(view, &start, Builder::fixed(), index.clone()),
        "cannot downgrade or invent a paged owner",
    ));
    let mut view = fresh();
    let head = owner.canonical_bytes().unwrap();
    let substitute = OwnerHeadV2::empty_data(
        &OwnerBinding {
            owner_generation: 8,
            ..binding()
        },
        PhysicalInventory::default(),
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    assert_ne!(substitute, head);
    view.records.insert(hash(&head), substitute);
    cases.push((
        run(view, &start, Builder::fixed(), index),
        "index semantic C record changes selected full bytes",
    ));
    for (actual, expected) in cases {
        assert!(actual.contains(expected), "{actual} / {expected}");
    }
}
#[test]
fn start_verifier_fails_closed_at_every_original_operation_check() {
    let (r, owner, start, _) = reserved();
    let a = r.original().clone();
    let (result, total) = verify(
        &mut View::new(ready(Some(4)), &owner),
        &start,
        &Builder::fixed(),
        &a,
        SourcePurpose::IndexPrepare,
        usize::MAX,
    );
    assert!(result.is_ok());
    assert!(total > 10, "{total}");
    for allowed in 0..total {
        let (result, calls) = verify(
            &mut View::new(ready(Some(4)), &owner),
            &start,
            &Builder::fixed(),
            &a,
            SourcePurpose::IndexPrepare,
            allowed,
        );
        let error = refusal(result);
        assert!(
            error.contains("fixture original operation revoked"),
            "check {allowed}: {error}"
        );
        assert_eq!(calls, allowed + 1, "check {allowed}");
    }
}
