//! Real fixed-inode filesystem publication with explicit software C and Admin
//! attribution. No TPM, PAM, installed confinement or production qualification.
use super::super::super::super::protocol::{software_admin_operation, TypedAdminOperationSource};
use super::*;
use crate::finite_grants::{Action, Kind, Selector, Use};
use std::cell::{Cell, RefCell};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[path = "tests/progress.rs"]
mod progress_cases;
#[path = "tests/resume.rs"]
mod resume_cases;
#[path = "tests/worker.rs"]
mod worker_cases;
#[derive(Clone, Copy)]
enum Fault {
    None,
    Old,
    Lost,
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
    fn advance(&mut self, old: [u8; 32], event: [u8; 32]) -> Result<[u8; 32]> {
        let mut state = self.0.borrow_mut();
        if state.head != old {
            return Err("software C conflict".into());
        }
        state.calls += 1;
        match std::mem::replace(&mut state.fault, Fault::None) {
            Fault::Old => Err("software original dispatch rejected before NV".into()),
            Fault::Third => {
                state.head = [0xee; 32];
                Err("software third NV".into())
            }
            Fault::Lost => {
                state.head = tpm::extend_value(old, event);
                Err("software lost actual reply".into())
            }
            Fault::None => {
                state.head = tpm::extend_value(old, event);
                Ok(state.head)
            }
        }
    }
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
    data: PathBuf,
    binding: map::CustodyBinding,
    memory: Memory,
    genesis: Vec<u8>,
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
            std::env::var("LUMA_STORAGE_TEST_ROOT").expect("explicit private ext4 root required"),
        );
        assert_eq!(fs::canonicalize(&base).unwrap(), base);
        let number = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!(
            "luma-tpm-direct-start-{}-{number}",
            std::process::id()
        ));
        let data = base.join(format!("direct-start-data-{}-{number}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
        let metadata = fs::metadata(&data).unwrap();
        let installation = "11".repeat(32);
        let genesis=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"luma-content-explicit-empty-genesis-v1","installation":installation,"namespace":"/var/lib/luma-os/content-store","identity":{"device":metadata.dev().to_string(),"inode":metadata.ino().to_string(),"uid":0,"gid":metadata.gid(),"mode":libc::S_IFDIR|0o700},"domains":[]})).unwrap();
        let binding = map::CustodyBinding {
            installation,
            sealed_genesis_sha256: hash(&genesis),
        };
        let journal = Journal::empty(
            &binding.installation,
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
            base,
            root,
            data,
            binding,
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
        let mut value = Store::open(self.memory.clone(), self.files(), &mut || Ok(())).unwrap();
        value.genesis_proof = Some(self.genesis.clone());
        value
    }
    fn pages(&self) -> PageStore {
        PageStore::open(&self.root, self.binding.clone(), &mut || Ok(())).unwrap()
    }
    fn source(
        &self,
        recovery: bool,
        proposal: &serde_json::Value,
        number: u64,
    ) -> (Audit, TypedAdminOperationSource) {
        let window = proposal[if recovery {
            "review_sha256"
        } else {
            "window_intent_sha256"
        }]
        .as_str()
        .unwrap();
        let stable = proposal["stable_review_sha256"].as_str().unwrap();
        let usage = Use {
            action: if recovery {
                Action::RecoverResource
            } else {
                Action::ProvisionResource
            },
            selector: Selector {
                kind: Kind::Resource,
                id: if recovery {
                    "content-custody-paged-reconcile-v3"
                } else {
                    "content-custody-paged-bootstrap-v3"
                }
                .into(),
                generation: 1,
                digest: window.into(),
            },
            input_bytes: 0,
            output_bytes: 8192,
            units: 1,
        };
        let audit = Audit {
            subject: "22".repeat(32),
            subject_generation: 1,
            grant_id: "explicit-software-direct-initial-admin".into(),
            grant_version: 1,
            checkpoint_head: "33".repeat(32),
            operation_id: Some(format!("{number:032x}")),
            usage: usage.clone(),
        };
        let source = TypedAdminOperationSource {
            schema_version: 1,
            request_sha256: hash(
                &serde_json::to_vec(&(
                    "explicit-software-original-request",
                    number,
                    &usage,
                    proposal,
                ))
                .unwrap(),
            ),
            command: if recovery {
                "content-custody-paged-reconcile"
            } else {
                "content-custody-paged-bootstrap"
            }
            .into(),
            usage,
            installation: self.binding.installation.clone(),
            job: format!("{number:032x}"),
            client_pid: std::process::id(),
            client_start: 1,
            client_label: "explicit-software-admin-not-authenticated".into(),
            paged_control: Some(
                super::super::super::super::paged_admin::Source::software_fixture(
                    stable,
                    window,
                    if recovery {
                        proposal["expected_selected_descriptor_sha256"].as_str()
                    } else {
                        None
                    },
                    if recovery {
                        proposal["attempt_sha256"].as_str()
                    } else {
                        None
                    },
                ),
            ),
        };
        (audit, source)
    }
    fn intent(&self) -> serde_json::Value {
        review(&mut self.store(), &mut || Ok(())).unwrap()
    }
    fn dispatch(&self) -> Result<Current<Memory>> {
        let proposal = self.intent();
        let expected = proposal["window_intent_sha256"].as_str().unwrap();
        let (audit, source) = self.source(false, &proposal, 1);
        let mut check = || Ok(());
        let mut original = software_admin_operation(&audit, source, &mut check);
        begin(self.store(), expected, &mut original)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for (path, prefix) in [
            (&self.root, "luma-tpm-direct-start-"),
            (&self.data, "direct-start-data-"),
        ] {
            assert_eq!(fs::canonicalize(path).unwrap(), *path);
            assert_eq!(path.parent(), Some(self.base.as_path()));
            assert!(path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(prefix));
            fs::remove_dir_all(path).unwrap();
        }
    }
}
#[test]
fn actual_direct_initial_allocates_and_verifies_everything_before_exactly_one_dispatch() {
    let fixture = Fixture::new();
    let current = fixture.dispatch().unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert_eq!(current.descriptor.phase.state, bootstrap::State::Pending);
    assert_eq!(current.descriptor.phase.copied_entries, 0);
    let storage = current.descriptor.storage.as_ref().unwrap();
    assert_eq!(storage.schema_version, 2);
    assert_eq!(storage.jobs.as_ref().unwrap().entries(), 1);
    assert_eq!(
        current.pages.inventory(&mut || Ok(())).unwrap(),
        storage.post_allocation
    );
    assert_eq!(
        current.files.read("genesis.json", &mut || Ok(())).unwrap(),
        fixture.genesis
    );
    assert!(
        !fixture.root.join("paged-v3/selected.json").exists(),
        "no mutable hash selector is created as another source of authority"
    );
}
#[test]
fn lost_actual_reply_requires_fresh_reviewed_completion_without_another_advance() {
    let fixture = Fixture::new();
    fixture.memory.0.borrow_mut().fault = Fault::Lost;
    assert!(fixture.dispatch().is_err());
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    let pages = fixture.pages();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    let mut anchor = fixture.memory.clone();
    let proposal = recovery_review(
        &mut anchor,
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    let (audit, source) = fixture.source(true, &proposal, 2);
    let mut check = || Ok(());
    let mut original = software_admin_operation(&audit, source, &mut check);
    let current = reconcile(
        fixture.memory.clone(),
        fixture.files(),
        pages,
        fixture.binding.clone(),
        proposal["review_sha256"].as_str().unwrap(),
        &mut original,
    )
    .unwrap();
    assert_eq!(fixture.memory.0.borrow().calls, 1);
    assert_eq!(current.pages.inventory(&mut || Ok(())).unwrap(), before);
    let mut anchor = fixture.memory.clone();
    let cut = super::super::reader::observe(
        &mut anchor,
        &current.pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    assert!(cut.completed_read().is_ok());
}
#[test]
fn old_and_third_nv_preserve_evidence_and_never_adopt_or_redispatch() {
    for fault in [Fault::Old, Fault::Third] {
        let fixture = Fixture::new();
        fixture.memory.0.borrow_mut().fault = fault;
        assert!(fixture.dispatch().is_err());
        assert_eq!(fixture.memory.0.borrow().calls, 1);
        let pages = fixture.pages();
        let before = pages.inventory(&mut || Ok(())).unwrap();
        let mut anchor = fixture.memory.clone();
        assert!(recovery_review(
            &mut anchor,
            &fixture.files(),
            &pages,
            &fixture.binding,
            &mut || Ok(())
        )
        .is_err());
        assert!(Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err());
        assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 1);
    }
}
#[test]
fn original_revocation_before_and_after_dispatch_cannot_yield_success_or_renewal() {
    for after in [false, true] {
        let fixture = Fixture::new();
        let proposal = fixture.intent();
        let (audit, source) = fixture.source(false, &proposal, 1);
        let mut check = || {
            if !after || fixture.memory.0.borrow().calls != 0 {
                Err("explicit software original revoked".into())
            } else {
                Ok(())
            }
        };
        let mut original = software_admin_operation(&audit, source, &mut check);
        assert!(begin(
            fixture.store(),
            proposal["window_intent_sha256"].as_str().unwrap(),
            &mut original
        )
        .is_err());
        assert_eq!(fixture.memory.0.borrow().calls, u64::from(after));
        if !after {
            assert!(!fixture.root.join("paged-v3").exists());
        }
    }
}

#[test]
fn old_nv_retirement_changes_only_fixed_pending_after_fresh_original_recovery() {
    let fixture = Fixture::new();
    fixture.memory.0.borrow_mut().fault = Fault::Old;
    assert!(fixture.dispatch().is_err());
    let pages = fixture.pages();
    let before = pages.inventory(&mut || Ok(())).unwrap();
    let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
    let selectors = [
        controls.read(0, &mut || Ok(())).unwrap().bytes().to_vec(),
        controls.read(1, &mut || Ok(())).unwrap().bytes().to_vec(),
    ];
    let mut anchor = fixture.memory.clone();
    let proposal = super::super::retired::review(
        &mut anchor,
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(proposal["actual_nv_is_old"], true);
    assert_eq!(proposal["already_retired"], false);
    let (audit, source) = fixture.source(true, &proposal, 2);
    let mut check = || Ok(());
    let mut authority = software_admin_operation(&audit, source, &mut check);
    let retired = super::super::retired::retire(
        &mut anchor,
        &fixture.files(),
        &pages,
        &fixture.binding,
        proposal["review_sha256"].as_str().unwrap(),
        &mut authority,
    )
    .unwrap();
    assert_eq!(
        retired.review_sha256,
        proposal["review_sha256"].as_str().unwrap()
    );
    assert_eq!(
        fixture.memory.0.borrow().calls,
        1,
        "retirement never dispatches NV"
    );
    assert_eq!(
        pages.inventory(&mut || Ok(())).unwrap(),
        before,
        "failed allocations remain fully charged"
    );
    for (index, bytes) in selectors.iter().enumerate() {
        assert_eq!(controls.read(index, &mut || Ok(())).unwrap().bytes(), bytes);
    }
    assert!(matches!(
        control::PendingFrame::from_frame(controls.read(2, &mut || Ok(())).unwrap().bytes())
            .unwrap(),
        control::PendingFrame::RetiredInitial { .. }
    ));
    let again = super::super::retired::review(
        &mut anchor,
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(again["review_sha256"], proposal["review_sha256"]);
    assert_eq!(again["already_retired"], true);
    assert!(super::super::retired::retire(
        &mut anchor,
        &fixture.files(),
        &pages,
        &fixture.binding,
        proposal["review_sha256"].as_str().unwrap(),
        &mut authority
    )
    .is_err());
    assert!(
        Store::open(fixture.memory.clone(), fixture.files(), &mut || Ok(())).is_err(),
        "retirement is not old-writer authority or namespace absence"
    );
}

#[test]
fn old_nv_retirement_refuses_new_third_or_damaged_actual_cut_without_any_write() {
    for fault in [Fault::Lost, Fault::Third] {
        let fixture = Fixture::new();
        fixture.memory.0.borrow_mut().fault = fault;
        assert!(fixture.dispatch().is_err());
        let pages = fixture.pages();
        let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
        let pending = controls.read(2, &mut || Ok(())).unwrap().bytes().to_vec();
        let before = pages.inventory(&mut || Ok(())).unwrap();
        assert!(super::super::retired::review(
            &mut fixture.memory.clone(),
            &fixture.files(),
            &pages,
            &fixture.binding,
            &mut || Ok(())
        )
        .is_err());
        assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), pending);
        assert_eq!(pages.inventory(&mut || Ok(())).unwrap(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 1);
    }
    let fixture = Fixture::new();
    fixture.memory.0.borrow_mut().fault = Fault::Old;
    assert!(fixture.dispatch().is_err());
    let pages = fixture.pages();
    let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
    let pending = controls.read(2, &mut || Ok(())).unwrap().bytes().to_vec();
    let control::PendingFrame::Prepared { pending: old } =
        control::PendingFrame::from_frame(&pending).unwrap()
    else {
        panic!("actual failed prepared controls required")
    };
    let control::Cell::Selected { descriptor, .. } = old.next else {
        panic!("actual immutable descriptor required")
    };
    let directory =
        slots::Directory::at_reference(&pages, &descriptor.slot, &mut || Ok(())).unwrap();
    let source = directory.read(&descriptor, &mut || Ok(())).unwrap();
    let path = fixture
        .root
        .join("paged-v3/tails")
        .join(&descriptor.slot.job)
        .join(format!("{:08x}", descriptor.slot.number));
    let mut changed = source;
    changed[0] ^= 1;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &changed).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(super::super::retired::review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(())
    )
    .is_err());
    assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), pending);
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}

#[test]
fn old_nv_retirement_rejects_reused_original_operation_scope_and_revocation() {
    let fixture = Fixture::new();
    let initial = fixture.intent();
    let (old_audit, old_source) = fixture.source(false, &initial, 1);
    fixture.memory.0.borrow_mut().fault = Fault::Old;
    assert!(fixture.dispatch().is_err());
    let pages = fixture.pages();
    let controls = cells::Files::observe(&pages, &mut || Ok(())).unwrap();
    let before = controls.read(2, &mut || Ok(())).unwrap().bytes().to_vec();
    let proposal = super::super::retired::review(
        &mut fixture.memory.clone(),
        &fixture.files(),
        &pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    for case in 0..6 {
        let (mut audit, mut source) = fixture.source(true, &proposal, 2);
        match case {
            0 => audit.operation_id = old_audit.operation_id.clone(),
            1 => source.request_sha256 = old_source.request_sha256.clone(),
            2 => source.paged_control.as_mut().unwrap().attempt_sha256 = Some("dd".repeat(32)),
            3 => {
                source
                    .paged_control
                    .as_mut()
                    .unwrap()
                    .expected_selected_descriptor_sha256 = Some("dd".repeat(32))
            }
            4 => source.job = "dd".repeat(32),
            _ => {}
        }
        let mut check = || {
            if case == 5 {
                Err("explicit software original recovery revoked".into())
            } else {
                Ok(())
            }
        };
        let mut authority = software_admin_operation(&audit, source, &mut check);
        assert!(super::super::retired::retire(
            &mut fixture.memory.clone(),
            &fixture.files(),
            &pages,
            &fixture.binding,
            proposal["review_sha256"].as_str().unwrap(),
            &mut authority
        )
        .is_err());
        assert_eq!(controls.read(2, &mut || Ok(())).unwrap().bytes(), before);
        assert_eq!(fixture.memory.0.borrow().calls, 1);
    }
}
#[test]
fn removing_the_actual_sealed_descriptor_refuses_before_any_dispatch() {
    let fixture = Fixture::new();
    let proposal = fixture.intent();
    let (audit, source) = fixture.source(false, &proposal, 1);
    let removed = Cell::new(false);
    let mut check = || {
        let tails = fixture.root.join("paged-v3/tails");
        if tails.is_dir() {
            for item in fs::read_dir(tails)? {
                let path = item?.path().join("00000002");
                if path.is_file()
                    && fs::metadata(&path)?.len() == PAGE_BYTES as u64
                    && !removed.replace(true)
                {
                    fs::remove_file(path)?;
                }
            }
        }
        Ok(())
    };
    let mut original = software_admin_operation(&audit, source, &mut check);
    assert!(begin(
        fixture.store(),
        proposal["window_intent_sha256"].as_str().unwrap(),
        &mut original
    )
    .is_err());
    assert!(removed.get());
    assert_eq!(fixture.memory.0.borrow().calls, 0);
}
#[test]
fn original_authorization_is_rechecked_inside_actual_descriptor_io_not_only_around_it() {
    let fixture = Fixture::new();
    let proposal = fixture.intent();
    let current = fixture.dispatch().unwrap();
    let mut anchor = fixture.memory.clone();
    let cut = super::super::reader::observe(
        &mut anchor,
        &current.pages,
        &fixture.binding,
        &mut || Ok(()),
    )
    .unwrap();
    let control::Cell::Selected {
        descriptor: reference,
        ..
    } = cut.cell()
    else {
        panic!("actual selected descriptor required")
    };
    let reference = reference.clone();
    let before = current.pages.inventory(&mut || Ok(())).unwrap();
    let (audit, source) = fixture.source(false, &proposal, 2);
    let calls = Cell::new(0);
    let mut check = || {
        let next = calls.get() + 1;
        calls.set(next);
        if next >= 12 {
            Err("software original revoked INSIDE bounded descriptor I/O".into())
        } else {
            Ok(())
        }
    };
    let mut original = software_admin_operation(&audit, source, &mut check);
    let mut operation = COperation::Admin(&mut original);
    let old = tpm::decode(&current.descriptor.selected_nv_head).unwrap();
    let mut raw = Raw {
        pages: &current.pages,
        anchor: &mut anchor,
        old,
    };
    assert!(
        control::Reader::read_descriptor_original(&mut raw, &reference, &mut operation).is_err()
    );
    assert!(
        calls.get() >= 12,
        "outer-only authorization would not reach this deterministic revocation boundary"
    );
    assert_eq!(current.pages.inventory(&mut || Ok(())).unwrap(), before);
    assert_eq!(fixture.memory.0.borrow().calls, 1);
}
