//! Genuine native filesystem/original-scope algorithms with explicit software
//! NV and authentication fixtures. No installed TPM/PAM/LSM claim is made.
use super::super::super::super::protocol::{
    software_admin_operation, software_worker_operation, TypedAdminOperationSource,
    TypedOperationSource,
};
use super::*;
use crate::finite_grants::{Action, Kind, Selector as GrantSelector, Use};
use luma_content::{EditOrigin, Format, Provenance};
use luma_content_store::{Access, Boundary, Plan, Repository, ResourceBudget};
use std::cell::Cell;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone)]
struct Memory {
    head: Rc<Cell<[u8; 32]>>,
    calls: Rc<Cell<u64>>,
}
impl Checkpoint for Memory {
    fn read(&mut self) -> Result<[u8; 32]> {
        Ok(self.head.get())
    }
    fn clock(&mut self) -> Result<tpm::Clock> {
        Ok(tpm::Clock {
            milliseconds: 1,
            reset_count: 1,
            restart_count: 1,
        })
    }
    fn advance(&mut self, old: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        if old != self.head.get() {
            return Err("software NV conflict".into());
        }
        let next = tpm::extend_value(old, event);
        self.head.set(next);
        self.calls.set(self.calls.get() + 1);
        Ok(next)
    }
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
    data: PathBuf,
    binding: OwnerBinding,
    store: PagedStore<Memory>,
    memory: Memory,
}
fn audit(binding: &OwnerBinding, usage: Use, number: u64) -> Audit {
    Audit {
        subject: binding.owner.clone(),
        subject_generation: binding.owner_generation,
        grant_id: "direct-preparation-software-fixture".into(),
        grant_version: 1,
        checkpoint_head: "44".repeat(32),
        operation_id: Some(format!("{number:032x}")),
        usage,
    }
}
fn admin(
    binding: &OwnerBinding,
    job: &str,
    intent: &str,
    number: u64,
) -> (Audit, TypedAdminOperationSource) {
    let usage = Use {
        action: Action::ProvisionResource,
        selector: GrantSelector {
            kind: Kind::Resource,
            id: "content-custody-paged-bootstrap-v3".into(),
            generation: 1,
            digest: intent.into(),
        },
        input_bytes: 0,
        output_bytes: 8192,
        units: 1,
    };
    let source = TypedAdminOperationSource {
        schema_version: 1,
        request_sha256: hash(&serde_json::to_vec(&(job, &usage)).unwrap()),
        command: "content-custody-paged-bootstrap".into(),
        usage: usage.clone(),
        installation: binding.installation.clone(),
        job: format!("{number:032x}"),
        client_pid: std::process::id(),
        client_start: 1,
        client_label: "software-only-original-admin".into(),
        paged_control: Some(
            super::super::super::super::paged_admin::Source::software_fixture(
                job, intent, None, None,
            ),
        ),
    };
    (audit(binding, usage, number), source)
}
impl Fixture {
    fn new() -> Self {
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
        let number = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!(
            "luma-tpm-direct-prepare-authority-{}-{number}",
            std::process::id()
        ));
        let data = base.join(format!(
            "direct-prepare-data-{}-{number}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
        let binding = OwnerBinding {
            installation: "11".repeat(32),
            owner: "22".repeat(32),
            owner_generation: 1,
        };
        let metadata = fs::metadata(&data).unwrap();
        let genesis=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"luma-content-explicit-empty-genesis-v1","installation":binding.installation,"namespace":"/var/lib/luma-os/content-store","identity":{"device":metadata.dev().to_string(),"inode":metadata.ino().to_string(),"uid":0,"gid":metadata.gid(),"mode":libc::S_IFDIR|0o700},"domains":[]})).unwrap();
        let c_binding = map::CustodyBinding {
            installation: binding.installation.clone(),
            sealed_genesis_sha256: hash(&genesis),
        };
        let journal = Journal::empty(
            &binding.installation,
            tpm::decode(&c_binding.sealed_genesis_sha256).unwrap(),
        )
        .unwrap();
        let state = journal.validate().unwrap();
        let memory = Memory {
            head: Rc::new(Cell::new(state.checkpoint)),
            calls: Rc::new(Cell::new(0)),
        };
        let files = Files { root: root.clone() };
        files
            .create(JOURNAL, &journal.bytes().unwrap(), &mut || Ok(()))
            .unwrap();
        files
            .create("genesis.json", &genesis, &mut || Ok(()))
            .unwrap();
        let mut old = Store::open(memory.clone(), files, &mut || Ok(())).unwrap();
        old.genesis_proof = Some(genesis);
        let legacy = LegacyCut {
            journal_sha256: hash(&old.bytes),
            journal_bytes: old.bytes.len() as u64,
            events: 0,
            nv_head: bundle::hex(&state.checkpoint),
        };
        let blueprint =
            bootstrap::Blueprint::verified_legacy(&c_binding, &legacy, &journal).unwrap();
        let phase = blueprint.initial_phase().unwrap();
        let selected = BaseSnapshot::Legacy {
            binding: c_binding,
            cut: legacy,
        }
        .selector()
        .unwrap();
        let intent = hash(&blueprint.next_window_intent(&phase, &selected).unwrap());
        let (admin_audit, source) = admin(&binding, &phase.review_sha256, &intent, 1);
        let mut check = || Ok(());
        let mut original = software_admin_operation(&admin_audit, source, &mut check);
        let mut store = bootstrap::software_begin(old, &intent, &mut original).unwrap();
        let review = store.bootstrap_review(&mut || Ok(())).unwrap();
        let window = review["window_intent_sha256"].as_str().unwrap();
        let (admin_audit, mut source) = admin(&binding, &phase.review_sha256, window, 2);
        source
            .paged_control
            .as_mut()
            .unwrap()
            .expected_selected_descriptor_sha256 = Some(store.selected.descriptor_sha256.clone());
        source.request_sha256 = hash(
            &serde_json::to_vec(&(
                "explicit-software-original-control-request",
                &source.command,
                &source.usage,
                &source.job,
                &source.paged_control,
            ))
            .unwrap(),
        );
        let mut check = || Ok(());
        let mut original = software_admin_operation(&admin_audit, source, &mut check);
        store.bootstrap_window(window, &mut original).unwrap();
        Self {
            base,
            root,
            data,
            binding,
            store,
            memory,
        }
    }
    fn publication(&self) -> PublicationFixture {
        let source = b"actual source for direct semantic preparation";
        let plan = Plan::capture(
            self.binding.clone(),
            "document",
            Format::Utf8Text,
            source,
            Provenance {
                request_id: "direct.preparation.one".into(),
                workflow_sha256: "55".repeat(32),
                source_sha256: hash(source),
                origin: EditOrigin::Managed,
            },
        )
        .unwrap();
        let mut guard = Guard {
            binding: self.binding.clone(),
            review: plan.review_sha256().into(),
        };
        let mut repository = Repository::create_at(&self.data, &plan, &mut guard).unwrap();
        let held = repository.prepare(&plan, source, &mut guard).unwrap();
        let commitment = held.commitment().canonical_bytes().unwrap();
        let record = held.record_bytes().to_vec();
        drop(held);
        let profile = format!(
            "content-v1-write-1-{}-{}",
            "77".repeat(32),
            plan.review_sha256()
        );
        let audit = audit(
            &self.binding,
            crate::content_governed::custody_usage(
                &profile,
                "8:1",
                &self.binding,
                plan.review_sha256(),
            )
            .unwrap(),
            3,
        );
        let source = TypedOperationSource {
            schema_version: 1,
            request_sha256: hash(&commitment),
            purpose: SourcePurpose::Publish,
            profile,
            storage_device: "8:1".into(),
            binding: self.binding.clone(),
            worker_pid: std::process::id(),
            worker_start: 1,
            worker_label: "software-fixed-worker".into(),
            lease: crate::resources::Token {
                lease_id: "88".repeat(16),
                generation: 1,
                manager_epoch: "99".repeat(16),
            },
        };
        PublicationFixture {
            _repository: repository,
            commitment,
            record,
            audit,
            source,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(fs::canonicalize(&self.root).unwrap(), self.root);
        assert_eq!(fs::canonicalize(&self.data).unwrap(), self.data);
        assert_eq!(self.root.parent(), Some(self.base.as_path()));
        assert_eq!(self.data.parent(), Some(self.base.as_path()));
        fs::remove_dir_all(&self.root).unwrap();
        fs::remove_dir_all(&self.data).unwrap();
    }
}
struct Guard {
    binding: OwnerBinding,
    review: String,
}
impl Boundary for Guard {
    fn admit(
        &mut self,
        binding: &OwnerBinding,
        budget: ResourceBudget,
    ) -> luma_content_store::Result<()> {
        if binding != &self.binding || budget.tasks != 1 || budget.memory_bytes > 256 * 1024 * 1024
        {
            return Err("software allocation refusal".into());
        }
        Ok(())
    }
    fn check(&mut self, access: Access<'_>) -> luma_content_store::Result<()> {
        match access {
            Access::Inspect { binding } if binding == &self.binding => Ok(()),
            Access::Mutate {
                binding,
                review_sha256,
                ..
            } if binding == &self.binding && review_sha256 == self.review => Ok(()),
            _ => Err("software exact original mutation refusal".into()),
        }
    }
}
struct PublicationFixture {
    _repository: Repository,
    commitment: Vec<u8>,
    record: Vec<u8>,
    audit: Audit,
    source: TypedOperationSource,
}
struct Actual {
    pages: PageStore,
    record: String,
    known: BTreeSet<String>,
    refused: bool,
}
impl SealedObjects for Actual {
    fn check(&mut self) -> Result<()> {
        if self.refused {
            return Err("software sealed-data observation revoked".into());
        }
        self.pages.check()
    }
    fn read_new(&mut self, sha: &str, maximum: usize) -> Result<Vec<u8>> {
        self.check()?;
        if sha == self.record && maximum == super::super::super::super::paged::FILE_BYTES {
            self.pages.read_record(sha, &mut || Ok(()))
        } else if self.known.contains(sha) && maximum == PAGE_BYTES {
            self.pages.read_page(sha, &mut || Ok(()))
        } else {
            Err("new object is not in this original prepared set".into())
        }
    }
}
fn stage(fixture: &Fixture, prepared: &PreparedV1) -> Actual {
    let pages = PageStore::open(
        &fixture.root,
        fixture.store.descriptor.binding.clone(),
        &mut || Ok(()),
    )
    .unwrap();
    pages
        .admit_writes(16 * 1024 * 1024, 1024, 1024, &mut || Ok(()))
        .unwrap();
    let record = pages
        .write_record(prepared.record_bytes(), &mut || Ok(()))
        .unwrap();
    let mut known = BTreeSet::new();
    for (sha, bytes) in prepared.pages() {
        assert_eq!(pages.write_page(bytes, &mut || Ok(())).unwrap(), *sha);
        known.insert(sha.clone());
    }
    Actual {
        pages,
        record,
        known,
        refused: false,
    }
}
#[test]
fn genuine_original_semantic_preparation_has_no_filesystem_or_nv_effect() {
    let mut fixture = Fixture::new();
    let publication = fixture.publication();
    let before = fixture.store.pages.inventory(&mut || Ok(())).unwrap();
    let calls = fixture.memory.calls.get();
    let mut check = || Ok(());
    let mut original =
        software_worker_operation(&publication.audit, publication.source, &mut check);
    let Outcome::Prepared(prepared) = prepare_v1(
        &mut fixture.store,
        &publication.commitment,
        &publication.record,
        &mut original,
    )
    .unwrap() else {
        panic!("fresh publication was not prepared")
    };
    assert_eq!(prepared.state().outcome_count, 1);
    assert!(!prepared.pages().is_empty());
    assert_eq!(fixture.memory.calls.get(), calls);
    assert_eq!(
        fixture.store.pages.inventory(&mut || Ok(())).unwrap(),
        before
    );
}
#[test]
fn independent_actual_new_file_replay_binds_full_record_and_pages_without_advancing_nv() {
    let mut fixture = Fixture::new();
    let publication = fixture.publication();
    let mut check = || Ok(());
    let mut original =
        software_worker_operation(&publication.audit, publication.source, &mut check);
    let Outcome::Prepared(prepared) = prepare_v1(
        &mut fixture.store,
        &publication.commitment,
        &publication.record,
        &mut original,
    )
    .unwrap() else {
        panic!("fresh publication not prepared")
    };
    let calls = fixture.memory.calls.get();
    let mut actual = stage(&fixture, &prepared);
    let verified = prepared
        .verify_written(&mut fixture.store, &mut actual, &mut original)
        .unwrap();
    assert_eq!(verified.into_prepared().state().outcome_count, 1);
    assert_eq!(fixture.memory.calls.get(), calls);
    assert_eq!(
        fixture
            .store
            .selected_v1(&fixture.binding, &mut || Ok(()))
            .unwrap()
            .outcome_count,
        0
    );
}
#[test]
fn changed_actual_sealed_data_and_wrong_original_source_refuse_without_checkpoint_effect() {
    let mut fixture = Fixture::new();
    let publication = fixture.publication();
    let calls = fixture.memory.calls.get();
    let mut wrong = publication.source.clone();
    wrong.purpose = SourcePurpose::Select;
    let mut check = || Ok(());
    let mut original = software_worker_operation(&publication.audit, wrong, &mut check);
    assert!(prepare_v1(
        &mut fixture.store,
        &publication.commitment,
        &publication.record,
        &mut original
    )
    .is_err());
    assert_eq!(fixture.memory.calls.get(), calls);
    let mut check = || Ok(());
    let mut original =
        software_worker_operation(&publication.audit, publication.source, &mut check);
    let Outcome::Prepared(prepared) = prepare_v1(
        &mut fixture.store,
        &publication.commitment,
        &publication.record,
        &mut original,
    )
    .unwrap() else {
        panic!("fresh publication not prepared")
    };
    let mut actual = stage(&fixture, &prepared);
    let sha = prepared.pages().keys().next().unwrap();
    let path = actual.pages.root.join(PageStore::page_name(sha).unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"x").unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(prepared
        .verify_written(&mut fixture.store, &mut actual, &mut original)
        .is_err());
    assert_eq!(fixture.memory.calls.get(), calls);
}
