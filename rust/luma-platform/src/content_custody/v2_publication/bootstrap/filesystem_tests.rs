//! Actual native files, preallocation, map writes and publication algorithm.
//! Only NV and original-client authentication are explicit software fixtures.
//! No installed PAM, TPM, AppArmor, fs-verity or production claim is made.
use super::super::super::protocol::{self, TypedAdminOperationSource, TypedOperationSource};
use super::*;
use crate::finite_grants::{Action, Kind, Selector as GrantSelector, Use};
use crate::resources::Token;
use luma_content::{EditOrigin, Format, Provenance};
use luma_content_store::{Access, Boundary, Plan as ContentPlan, Repository, ResourceBudget};
use std::cell::{Cell, RefCell};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Old,
    LostReply,
    Third,
}
struct Nv {
    head: [u8; 32],
    calls: u64,
    fault: Fault,
}
#[derive(Clone)]
struct Memory(Rc<RefCell<Nv>>);
impl Checkpoint for Memory {
    fn read(&mut self) -> Result<[u8; 32]> {
        Ok(self.0.borrow().head)
    }
    fn clock(&mut self) -> Result<tpm::Clock> {
        Ok(tpm::Clock {
            milliseconds: 1,
            reset_count: 1,
            restart_count: 1,
        })
    }
    fn advance(&mut self, expected: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        let mut state = self.0.borrow_mut();
        if state.head != expected {
            return Err("software checkpoint conflict".into());
        }
        state.calls += 1;
        let fault = std::mem::replace(&mut state.fault, Fault::None);
        if fault == Fault::Old {
            return Err("software dispatch refused before NV change".into());
        }
        state.head = if fault == Fault::Third {
            [0xee; 32]
        } else {
            tpm::extend_value(expected, event)
        };
        if fault != Fault::None {
            return Err("software dispatch reply lost".into());
        }
        Ok(state.head)
    }
}
struct Fixture {
    root: PathBuf,
    data: PathBuf,
    binding: map::CustodyBinding,
    owner: OwnerBinding,
    memory: Memory,
    genesis: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        assert!(
            std::path::Path::new("/.dockerenv").is_file(),
            "disposable Linux container required"
        );
        assert!(
            !std::path::Path::new("/dev/tpm0").exists()
                && !std::path::Path::new("/dev/tpmrm0").exists()
        );
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = PathBuf::from(
            std::env::var("LUMA_STORAGE_TEST_ROOT")
                .expect("explicit disposable ext4 data root required"),
        );
        assert_eq!(fs::canonicalize(&base).unwrap(), base);
        let root = base.join(format!(
            "luma-tpm-paged-filesystem-{}-{serial}",
            std::process::id()
        ));
        let data = base.join(format!("paged-native-data-{}-{serial}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
        assert_eq!(fs::canonicalize(&root).unwrap(), root);
        assert_eq!(fs::canonicalize(&data).unwrap(), data);
        let metadata = fs::metadata(&data).unwrap();
        let installation = "11".repeat(32);
        let genesis=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"luma-content-explicit-empty-genesis-v1","installation":installation,
            "namespace":"/var/lib/luma-os/content-store","identity":{"device":metadata.dev().to_string(),"inode":metadata.ino().to_string(),"uid":0,"gid":metadata.gid(),"mode":libc::S_IFDIR|0o700},"domains":[]})).unwrap();
        let binding = map::CustodyBinding {
            installation: installation.clone(),
            sealed_genesis_sha256: hash(&genesis),
        };
        let journal = Journal::empty(
            &installation,
            tpm::decode(&binding.sealed_genesis_sha256).unwrap(),
        )
        .unwrap();
        let memory = Memory(Rc::new(RefCell::new(Nv {
            head: journal.validate().unwrap().checkpoint,
            calls: 0,
            fault: Fault::None,
        })));
        let files = Files { root: root.clone() };
        files
            .create(JOURNAL, &journal.bytes().unwrap(), &mut || Ok(()))
            .unwrap();
        files
            .create("genesis.json", &genesis, &mut || Ok(()))
            .unwrap();
        Self {
            root,
            data,
            binding,
            owner: OwnerBinding {
                installation,
                owner: "22".repeat(32),
                owner_generation: 1,
            },
            memory,
            genesis,
        }
    }
    fn files(&self) -> Files {
        Files {
            root: self.root.clone(),
        }
    }
    fn store(&self) -> Store<Memory> {
        let mut store = Store::open(self.memory.clone(), self.files(), &mut || Ok(())).unwrap();
        store.genesis_proof = Some(self.genesis.clone());
        store
    }
    fn initial(&self) -> (String, String) {
        let mut store = self.store();
        let (binding, cut, blueprint) = legacy_snapshot(&mut store, &mut || Ok(())).unwrap();
        let phase = blueprint.initial_phase().unwrap();
        let base = BaseSnapshot::Legacy { binding, cut }.selector().unwrap();
        (
            hash(&blueprint.next_window_intent(&phase, &base).unwrap()),
            phase.review_sha256,
        )
    }
    fn admin(
        &self,
        command: &str,
        job: &str,
        digest: &str,
        number: u64,
    ) -> (Audit, TypedAdminOperationSource) {
        let (action, id) = if command == "content-custody-paged-bootstrap" {
            (
                Action::ProvisionResource,
                "content-custody-paged-bootstrap-v3",
            )
        } else {
            assert_eq!(command, "content-custody-paged-reconcile");
            (
                Action::RecoverResource,
                "content-custody-paged-reconcile-v3",
            )
        };
        let usage = Use {
            action,
            selector: GrantSelector {
                kind: Kind::Resource,
                id: id.into(),
                generation: 1,
                digest: digest.into(),
            },
            input_bytes: 0,
            output_bytes: 8192,
            units: 1,
        };
        let audit = self.audit(usage.clone(), number);
        let control = if command == "content-custody-paged-bootstrap" {
            super::super::super::paged_admin::Source::software_fixture(job, digest, None, None)
        } else {
            let (pending, _) = self.pending();
            let pages = PageStore::open(&self.root, self.binding.clone(), &mut || Ok(())).unwrap();
            let next: Descriptor = canonical(
                &pages
                    .read(
                        &format!("attempts/{}/next.json", pending.attempt),
                        PAGE_BYTES,
                        &mut || Ok(()),
                    )
                    .unwrap(),
                PAGE_BYTES,
            )
            .unwrap();
            super::super::super::paged_admin::Source::software_fixture(
                &next.phase.review_sha256,
                digest,
                Some(&pending.base.descriptor_sha256),
                Some(&pending.attempt),
            )
        };
        let source = TypedAdminOperationSource {
            schema_version: 1,
            request_sha256: hash(
                &serde_json::to_vec(&(command, &usage, &self.binding.installation, job)).unwrap(),
            ),
            command: command.into(),
            usage,
            installation: self.binding.installation.clone(),
            job: format!("{number:032x}"),
            client_pid: std::process::id(),
            client_start: 1,
            client_label: "software-original-admin-fixture".into(),
            paged_control: Some(control),
        };
        let mut source = source;
        Self::rebind_source(&mut source);
        (audit, source)
    }
    fn rebind_source(source: &mut TypedAdminOperationSource) {
        source.request_sha256 = hash(
            &serde_json::to_vec(&(
                "explicit-software-original-control-request",
                &source.command,
                &source.usage,
                &source.installation,
                &source.job,
                &source.paged_control,
            ))
            .unwrap(),
        );
    }
    fn audit(&self, usage: Use, number: u64) -> Audit {
        Audit {
            subject: self.owner.owner.clone(),
            subject_generation: 1,
            grant_id: "software-only-native-paged".into(),
            grant_version: 1,
            checkpoint_head: "33".repeat(32),
            operation_id: Some(format!("{number:032x}")),
            usage,
        }
    }
    fn begin(&self) -> PagedStore<Memory> {
        let (intent, job) = self.initial();
        let (audit, source) = self.admin("content-custody-paged-bootstrap", &job, &intent, 1);
        let mut check = || Ok(());
        let mut authority = protocol::software_admin_operation(&audit, source, &mut check);
        software_begin(self.store(), &intent, &mut authority).unwrap()
    }
    fn window(&self, store: &mut PagedStore<Memory>, number: u64) {
        let review = store.bootstrap_review(&mut || Ok(())).unwrap();
        let intent = review["window_intent_sha256"].as_str().unwrap();
        let job = store.descriptor.phase.review_sha256.clone();
        let (audit, mut source) =
            self.admin("content-custody-paged-bootstrap", &job, intent, number);
        source
            .paged_control
            .as_mut()
            .unwrap()
            .expected_selected_descriptor_sha256 = Some(store.selected.descriptor_sha256.clone());
        Self::rebind_source(&mut source);
        let mut check = || Ok(());
        let mut authority = protocol::software_admin_operation(&audit, source, &mut check);
        store.bootstrap_window(intent, &mut authority).unwrap();
    }
    fn pending(&self) -> (Pending, String) {
        let pages = PageStore::open(&self.root, self.binding.clone(), &mut || Ok(())).unwrap();
        let pending: Pending = canonical(
            &pages
                .read("pending.json", CONTROL_BYTES, &mut || Ok(()))
                .unwrap(),
            CONTROL_BYTES,
        )
        .unwrap();
        let prefix = format!("attempts/{}", pending.attempt);
        let base: BaseSnapshot = canonical(
            &pages
                .read(
                    &format!("{prefix}/base.json"),
                    CONTROL_BYTES,
                    &mut || Ok(()),
                )
                .unwrap(),
            CONTROL_BYTES,
        )
        .unwrap();
        let next: Descriptor = canonical(
            &pages
                .read(&format!("{prefix}/next.json"), PAGE_BYTES, &mut || Ok(()))
                .unwrap(),
            PAGE_BYTES,
        )
        .unwrap();
        let selected: Selector = canonical(
            &pages.read("selected.json", 4096, &mut || Ok(())).unwrap(),
            4096,
        )
        .unwrap();
        let review = hash(
            &serde_json::to_vec(&(
                "luma-paged-c-reconciliation-v3",
                &self.binding,
                &pending,
                &base,
                &next,
                bundle::hex(&self.memory.0.borrow().head),
                &selected,
            ))
            .unwrap(),
        );
        (pending, review)
    }
    fn reconcile(&self, number: u64) -> Result<PagedStore<Memory>> {
        let (pending, review) = self.pending();
        let (audit, source) = self.admin(
            "content-custody-paged-reconcile",
            &pending.attempt,
            &review,
            number,
        );
        let mut check = || Ok(());
        let mut authority = protocol::software_admin_operation(&audit, source, &mut check);
        PagedStore::reconcile_from_anchor(
            self.memory.clone(),
            self.files(),
            self.binding.clone(),
            &review,
            &mut authority,
        )
    }
    fn prepared(&self, owner: &OwnerBinding, number: u64) -> Prepared {
        let body = b"actual bounded source in disposable software fixture";
        let plan = ContentPlan::capture(
            owner.clone(),
            "document",
            Format::Utf8Text,
            body,
            Provenance {
                request_id: format!("paged-fixture-{number}"),
                workflow_sha256: "44".repeat(32),
                source_sha256: hash(body),
                origin: EditOrigin::Managed,
            },
        )
        .unwrap();
        let mut guard = ContentGuard {
            owner: owner.clone(),
            review: plan.review_sha256().into(),
        };
        let mut repository = Repository::create_at(&self.data, &plan, &mut guard).unwrap();
        let held = repository.prepare(&plan, body, &mut guard).unwrap();
        let commitment = held.commitment().canonical_bytes().unwrap();
        let record = held.record_bytes().to_vec();
        drop(held);
        let profile = format!(
            "content-v1-write-{}-{}-{}",
            owner.owner_generation,
            "77".repeat(32),
            plan.review_sha256()
        );
        let mut audit = self.audit(
            crate::content_governed::custody_usage(&profile, "8:1", owner, plan.review_sha256())
                .unwrap(),
            number,
        );
        audit.subject = owner.owner.clone();
        audit.subject_generation = owner.owner_generation;
        Prepared {
            repository,
            commitment,
            record,
            profile,
            audit,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(std::path::Path::new("/.dockerenv").is_file());
        let base = PathBuf::from(std::env::var("LUMA_STORAGE_TEST_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&base).unwrap(), base);
        assert_eq!(self.root.parent(), Some(base.as_path()));
        assert_eq!(self.data.parent(), Some(base.as_path()));
        assert!(self
            .root
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("luma-tpm-paged-filesystem-"));
        assert_eq!(fs::canonicalize(&self.root).unwrap(), self.root);
        assert_eq!(fs::canonicalize(&self.data).unwrap(), self.data);
        assert!(self
            .data
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("paged-native-data-"));
        fs::remove_dir_all(&self.root).unwrap();
        fs::remove_dir_all(&self.data).unwrap();
    }
}
struct ContentGuard {
    owner: OwnerBinding,
    review: String,
}
impl Boundary for ContentGuard {
    fn admit(
        &mut self,
        owner: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if owner != &self.owner
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.tasks != 1
        {
            return Err("explicit software resource-boundary refusal".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.owner => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.owner && review_sha256 == self.review => Ok(()),
            _ => Err("explicit software content-boundary refusal".into()),
        }
    }
}
struct Prepared {
    repository: Repository,
    commitment: Vec<u8>,
    record: Vec<u8>,
    profile: String,
    audit: Audit,
}
impl Prepared {
    fn source(&self) -> TypedOperationSource {
        let held = HeldPublication::parse(&self.commitment).unwrap();
        TypedOperationSource {
            schema_version: 1,
            request_sha256: hash(
                &serde_json::to_vec(&(
                    "software-publish-source",
                    &self.profile,
                    &self.commitment,
                    &self.record,
                ))
                .unwrap(),
            ),
            purpose: SourcePurpose::Publish,
            profile: self.profile.clone(),
            storage_device: "8:1".into(),
            binding: held.binding,
            worker_pid: std::process::id(),
            worker_start: 1,
            worker_label: "software-owned-worker-fixture".into(),
            lease: Token {
                lease_id: "11".repeat(16),
                generation: 1,
                manager_epoch: "22".repeat(16),
            },
        }
    }
    fn publish(&self, store: &mut PagedStore<Memory>) -> Result<VerifiedState> {
        let mut check = || Ok(());
        let mut original =
            protocol::software_worker_operation(&self.audit, self.source(), &mut check);
        store.publish_v1(&self.commitment, &self.record, &mut original)
    }
}

#[test]
fn actual_bootstrap_and_publication_write_real_files_with_one_extend_each() {
    let fixture = Fixture::new();
    let mut store = fixture.begin();
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert!(store
        .selected_owner(&fixture.owner, &mut || Ok(()))
        .is_err());
    fixture.window(&mut store, 2);
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    store.descriptor.phase.require_ready().unwrap();
    let prepared = fixture.prepared(&fixture.owner, 3);
    let wanted = HeldPublication::parse(&prepared.commitment)
        .unwrap()
        .outcome();
    assert_eq!(prepared.publish(&mut store).unwrap(), wanted);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
    assert_eq!(prepared.publish(&mut store).unwrap(), wanted);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
    drop(store);
    let mut reopened = PagedStore::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        reopened
            .selected_v1(&fixture.owner, &mut || Ok(()))
            .unwrap(),
        wanted
    );
    drop(prepared.repository);
}
#[test]
fn actual_bootstrap_rejects_phase_hash_as_registry_job_and_mismatched_control_before_creation() {
    for change in 0..6 {
        let fixture = Fixture::new();
        let (intent, stable) = fixture.initial();
        let (audit, mut source) =
            fixture.admin("content-custody-paged-bootstrap", &stable, &intent, 1);
        assert_eq!(source.job.len(), 32);
        match change {
            0 => source.job = stable.clone(),
            1 => source.paged_control = None,
            2 => source.paged_control.as_mut().unwrap().stable_review_sha256 = "ab".repeat(32),
            3 => {
                source
                    .paged_control
                    .as_mut()
                    .unwrap()
                    .expected_window_sha256 = "bc".repeat(32)
            }
            4 => {
                source
                    .paged_control
                    .as_mut()
                    .unwrap()
                    .expected_selected_descriptor_sha256 = Some("cd".repeat(32))
            }
            _ => source.paged_control.as_mut().unwrap().attempt_sha256 = Some("de".repeat(32)),
        }
        Fixture::rebind_source(&mut source);
        let mut check = || Ok(());
        let mut original = protocol::software_admin_operation(&audit, source, &mut check);
        assert!(software_begin(fixture.store(), &intent, &mut original).is_err());
        assert!(!fixture.root.join("paged-v3").exists());
        assert_eq!(fixture.memory.0.borrow().calls, 0);
    }
}
fn recovery_observation(
    fixture: &Fixture,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    super::super::admin_review::recovery_review_at(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        check,
    )
}
#[test]
fn actual_readonly_recovery_observation_matches_old_and_lost_reply_new_cuts_without_dispatch() {
    for fault in [Fault::Old, Fault::LostReply] {
        let fixture = Fixture::new();
        let (intent, stable) = fixture.initial();
        let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &stable, &intent, 1);
        fixture.memory.0.borrow_mut().fault = fault;
        let mut check = || Ok(());
        let mut original = protocol::software_admin_operation(&audit, source, &mut check);
        assert!(software_begin(fixture.store(), &intent, &mut original).is_err());
        let before = fs::read(fixture.root.join("paged-v3/pending.json")).unwrap();
        let (pending, expected) = fixture.pending();
        let value = recovery_observation(&fixture, &mut || Ok(())).unwrap();
        assert_eq!(value["review_sha256"].as_str(), Some(expected.as_str()));
        assert_eq!(
            value["attempt_sha256"].as_str(),
            Some(pending.attempt.as_str())
        );
        assert_eq!(
            value["expected_selected_descriptor_sha256"].as_str(),
            Some(pending.base.descriptor_sha256.as_str())
        );
        assert_eq!(
            value["stable_review_sha256"].as_str(),
            Some(stable.as_str())
        );
        assert_eq!(
            value["nv_is_old"].as_bool(),
            Some(matches!(fault, Fault::Old))
        );
        assert_eq!(
            value["nv_is_new"].as_bool(),
            Some(matches!(fault, Fault::LostReply))
        );
        assert_eq!(value["TPM_extended"].as_bool(), Some(false));
        assert_eq!(fixture.memory.0.borrow().calls, 1);
        assert_eq!(
            fs::read(fixture.root.join("paged-v3/pending.json")).unwrap(),
            before
        );
    }
}
#[test]
fn actual_readonly_recovery_observation_refuses_third_nv_and_revocation_without_mutation() {
    let fixture = Fixture::new();
    let (intent, stable) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &stable, &intent, 1);
    fixture.memory.0.borrow_mut().fault = Fault::LostReply;
    let mut check = || Ok(());
    let mut original = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(software_begin(fixture.store(), &intent, &mut original).is_err());
    let selected = fs::read(fixture.root.join("paged-v3/selected.json")).unwrap();
    assert!(recovery_observation(&fixture, &mut || Err(
        "software original Admin read revoked".into()
    ))
    .is_err());
    fixture.memory.0.borrow_mut().head = [0xee; 32];
    assert!(recovery_observation(&fixture, &mut || Ok(())).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert_eq!(
        fs::read(fixture.root.join("paged-v3/selected.json")).unwrap(),
        selected
    );
}
#[test]
fn actual_readonly_recovery_observation_rejects_tampered_immutable_dispatch_data() {
    let fixture = Fixture::new();
    let (intent, stable) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &stable, &intent, 1);
    fixture.memory.0.borrow_mut().fault = Fault::LostReply;
    let mut check = || Ok(());
    let mut original = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(software_begin(fixture.store(), &intent, &mut original).is_err());
    let (pending, _) = fixture.pending();
    let path = fixture.root.join(format!(
        "paged-v3/attempts/{}/dispatch.json",
        pending.attempt
    ));
    let before = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"tampered").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(recovery_observation(&fixture, &mut || Ok(())).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert_ne!(
        fs::read(&path).unwrap(),
        before,
        "the observer never repairs or overwrites tampered evidence"
    );
}
#[test]
fn lost_first_dispatch_reply_reconciles_new_nv_without_another_extend() {
    let fixture = Fixture::new();
    let (intent, job) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    fixture.memory.0.borrow_mut().fault = Fault::LostReply;
    let mut check = || Ok(());
    let mut authority = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(begin_from_original_store(fixture.store(), &intent, &mut authority).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert!(PagedStore::open(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(())
    )
    .is_err());
    let mut selected = fixture.reconcile(2).unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert!(selected
        .selected_owner(&fixture.owner, &mut || Ok(()))
        .is_err());
    fixture.window(&mut selected, 3);
    assert_eq!(fixture.memory.0.borrow().calls, 2);
}
#[test]
fn refused_first_dispatch_retires_only_with_fresh_recovery_and_resumes_in_new_window() {
    let fixture = Fixture::new();
    let (intent, job) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    let old_source = source.clone();
    fixture.memory.0.borrow_mut().fault = Fault::Old;
    let mut check = || Ok(());
    let mut authority = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(begin_from_original_store(fixture.store(), &intent, &mut authority).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert!(fixture.reconcile(2).is_err());
    assert!(fixture.root.join("paged-v3/pending.json").is_file());
    let loaded = initial::software_load_initial(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    let attempt = loaded.1.attempt.clone();
    let review = loaded.3.clone();
    let (recovery, mut source) =
        fixture.admin("content-custody-paged-reconcile", &attempt, &review, 2);
    source
        .paged_control
        .as_mut()
        .unwrap()
        .expected_selected_descriptor_sha256 = None;
    Fixture::rebind_source(&mut source);
    let mut live = || Ok(());
    let mut original = protocol::software_admin_operation(&recovery, source, &mut live);
    let mut retired = initial::software_retire_initial(loaded, &review, &mut original).unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    let resume = retired.review(&mut || Ok(())).unwrap();
    let next = resume["window_intent_sha256"].as_str().unwrap().to_string();
    assert_ne!(next, intent);
    let mut live = || Ok(());
    let mut replay = protocol::software_admin_operation(&audit, old_source, &mut live);
    assert!(retired.resume(&next, &mut replay).is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    let retired = initial::software_open_retired(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &attempt,
        &mut || Ok(()),
    )
    .unwrap();
    let (fresh, mut source) = fixture.admin("content-custody-paged-bootstrap", &job, &next, 3);
    source.paged_control.as_mut().unwrap().attempt_sha256 = Some(attempt.clone());
    Fixture::rebind_source(&mut source);
    assert_ne!(
        source.request_sha256,
        replay.source_binding().request_sha256
    );
    let mut live = || Ok(());
    let mut original = protocol::software_admin_operation(&fresh, source, &mut live);
    let mut selected = retired.resume(&next, &mut original).unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 2);
    assert!(fixture
        .root
        .join(format!("paged-v3/attempts/{attempt}/retired.json"))
        .is_file());
    fixture.window(&mut selected, 4);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
}
#[test]
fn third_nv_preserves_pending_and_refuses_both_reconciliation_and_old_parser() {
    let fixture = Fixture::new();
    let (intent, job) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    fixture.memory.0.borrow_mut().fault = Fault::Third;
    let mut check = || Ok(());
    let mut original = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(begin_from_original_store(fixture.store(), &intent, &mut original).is_err());
    assert!(fixture.reconcile(2).is_err());
    assert!(initial::software_load_initial(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(())
    )
    .is_err());
    assert!(Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err());
    assert!(fixture.root.join("paged-v3/pending.json").is_file());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}
#[test]
fn missing_preallocated_next_refuses_before_dispatch_and_is_not_regenerated() {
    let fixture = Fixture::new();
    let (intent, job) = fixture.initial();
    let (audit, source) = fixture.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    let removed = Cell::new(false);
    let mut check = || {
        let path = fixture.root.join("paged-v3/pending.json");
        if path.is_file() && !removed.replace(true) {
            let pending: Pending = canonical(&fs::read(&path)?, CONTROL_BYTES)?;
            let target = fixture
                .root
                .join(format!("paged-v3/attempts/{}/next.json", pending.attempt));
            assert!(target.starts_with(&fixture.root));
            fs::remove_file(target)?;
        }
        Ok(())
    };
    let mut original = protocol::software_admin_operation(&audit, source, &mut check);
    assert!(begin_from_original_store(fixture.store(), &intent, &mut original).is_err());
    assert!(removed.get());
    assert_eq!(fixture.memory.0.borrow().calls, 0);
    assert!(fixture.root.join("paged-v3/pending.json").is_file());
    assert!(initial::software_load_initial(
        fixture.memory.clone(),
        fixture.files(),
        fixture.binding.clone(),
        &mut || Ok(())
    )
    .is_err());
}
#[test]
fn original_revocation_before_or_after_dispatch_never_extends_twice() {
    let before = Fixture::new();
    let (intent, job) = before.initial();
    let (audit, source) = before.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    let mut revoked = || Err("software original revoked before any stage".into());
    let mut original = protocol::software_admin_operation(&audit, source, &mut revoked);
    assert!(begin_from_original_store(before.store(), &intent, &mut original).is_err());
    assert_eq!(before.memory.0.borrow().calls, 0);
    assert!(!before.root.join("paged-v3").exists());
    let after = Fixture::new();
    let (intent, job) = after.initial();
    let (audit, source) = after.admin("content-custody-paged-bootstrap", &job, &intent, 1);
    let mut revoked = || {
        if after.memory.0.borrow().calls != 0 {
            return Err("software original revoked after NV".into());
        }
        Ok(())
    };
    let mut original = protocol::software_admin_operation(&audit, source, &mut revoked);
    assert!(begin_from_original_store(after.store(), &intent, &mut original).is_err());
    assert_eq!(after.memory.0.borrow().calls, 1);
    assert!(after.root.join("paged-v3/pending.json").is_file());
    assert!(after.reconcile(2).is_ok());
    assert_eq!(after.memory.0.borrow().calls, 1);
}
#[test]
fn actual_owner_map_publication_lost_reply_recovers_real_record_without_redispatch() {
    let fixture = Fixture::new();
    let mut store = fixture.begin();
    fixture.window(&mut store, 2);
    let prepared = fixture.prepared(&fixture.owner, 3);
    fixture.memory.0.borrow_mut().fault = Fault::LostReply;
    assert!(prepared.publish(&mut store).is_err());
    assert!(store.poisoned);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
    drop(store);
    let mut store = fixture.reconcile(4).unwrap();
    let wanted = HeldPublication::parse(&prepared.commitment)
        .unwrap()
        .outcome();
    assert_eq!(
        store.selected_v1(&fixture.owner, &mut || Ok(())).unwrap(),
        wanted
    );
    assert_eq!(prepared.publish(&mut store).unwrap(), wanted);
    assert_eq!(fixture.memory.0.borrow().calls, 3);
}
#[test]
fn real_partial_bootstrap_blocks_an_existing_publication_retry_acknowledgement() {
    let fixture = Fixture::new();
    let mut legacy = fixture.store();
    let mut prepared = Vec::new();
    for index in 1..=17_u64 {
        let owner = OwnerBinding {
            owner: format!("{index:064x}"),
            ..fixture.owner.clone()
        };
        let entry = fixture.prepared(&owner, index);
        legacy
            .publish(
                &entry.commitment,
                &entry.record,
                &entry.profile,
                "8:1",
                &entry.audit,
                &mut || Ok(()),
            )
            .unwrap();
        prepared.push(entry);
    }
    drop(legacy);
    let mut store = fixture.begin();
    fixture.window(&mut store, 21);
    assert_eq!(store.descriptor.phase.state, State::Pending);
    assert_eq!(store.descriptor.phase.copied_entries, 16);
    let (journal, _) = store.legacy(&mut || Ok(())).unwrap();
    let blueprint = Blueprint::verified_legacy(
        &store.descriptor.binding,
        &store.descriptor.legacy,
        &journal,
    )
    .unwrap();
    let leaf: OwnerLeaf = canonical(&blueprint.rows[0].value, map::MAX_VALUE_BYTES).unwrap();
    let owner = match leaf {
        OwnerLeaf::V1 { state, .. } => state.binding,
        _ => panic!("legacy projection changed format"),
    };
    let existing = prepared
        .iter()
        .find(|entry| HeldPublication::parse(&entry.commitment).unwrap().binding == owner)
        .unwrap();
    let before = fixture.memory.0.borrow().calls;
    let error = existing.publish(&mut store).unwrap_err();
    assert!(error.to_string().contains("bootstrap is pending"));
    assert_eq!(fixture.memory.0.borrow().calls, before);
    fixture.window(&mut store, 22);
    assert_eq!(store.descriptor.phase.state, State::Ready);
    assert!(existing.publish(&mut store).is_ok());
    assert_eq!(fixture.memory.0.borrow().calls, before + 1);
}
