use super::*;
use std::os::unix::fs::MetadataExt;

// Disposable fixtures only. No permissive Export implementation is supplied
// by the library; installed callers must enforce actual finite authorization.
struct ExportGuard {
    binding: OwnerBinding,
    checks: usize,
    refuse_at: usize,
    refuse_resources: bool,
    exact_manifest: Option<String>,
    completed_manifests: Vec<String>,
}
impl ExportGuard {
    fn new() -> Self {
        Self {
            binding: binding(),
            checks: 0,
            refuse_at: usize::MAX,
            refuse_resources: false,
            exact_manifest: None,
            completed_manifests: Vec::new(),
        }
    }
}
impl BackupBoundary for ExportGuard {
    fn admit(&mut self, owner: &OwnerBinding, budget: BackupBudget) -> Result<()> {
        if self.refuse_resources
            || owner != &self.binding
            || budget.memory_bytes > 256 * 1024 * 1024
            || budget.read_bytes > 256 * 1024 * 1024
            || budget.archive_bytes > MAX_CONTENT_BACKUP_BYTES as u64
            || budget.archive_bytes == 0
            || budget.tasks != 1
        {
            return Err("fixture independent Export resource admission refused".into());
        }
        Ok(())
    }
    fn check(&mut self, owner: &OwnerBinding, manifest: Option<&str>) -> Result<()> {
        self.checks += 1;
        if self.checks >= self.refuse_at
            || owner != &self.binding
            || manifest.is_some_and(|hash| {
                self.exact_manifest
                    .as_deref()
                    .is_some_and(|expected| hash != expected)
            })
        {
            return Err("fixture independent finite Export scope revoked or substituted".into());
        }
        if let Some(hash) = manifest {
            self.completed_manifests.push(hash.into());
        }
        Ok(())
    }
}

fn repository() -> (Fixture, Repository) {
    let fixture = Fixture::new();
    let plan = capture("first", "document", b"Original\r\nsource");
    let mut repository =
        Repository::create_at(&fixture.path, &plan, &mut Guard::write(&plan)).unwrap();
    repository
        .apply(&plan, b"Original\r\nsource", &mut Guard::write(&plan))
        .unwrap();
    (fixture, repository)
}
fn backup(repository: &Repository) -> ContentBackup {
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    repository
        .backup_data(&reviewed, &mut Guard::read(), &mut ExportGuard::new())
        .unwrap()
}
fn split(bytes: &[u8]) -> (BackupManifest, Vec<u8>) {
    let length = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
    (
        serde_json::from_slice(&bytes[20..20 + length]).unwrap(),
        bytes[20 + length..].to_vec(),
    )
}
fn assemble(manifest: &BackupManifest, data: &[u8]) -> Vec<u8> {
    let encoded = serde_json::to_vec(manifest).unwrap();
    let mut bytes = b"LUMACONTENTBK01\n".to_vec();
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(data);
    bytes
}
fn member<'a>(
    manifest: &BackupManifest,
    data: &'a [u8],
    area: BackupArea,
    name: &str,
    member_name: &str,
) -> &'a [u8] {
    let mut at = 0;
    for directory in &manifest.directories {
        for entry in &directory.members {
            let end = at + entry.bytes as usize;
            if directory.area == area && directory.name == name && entry.name == member_name {
                return &data[at..end];
            }
            at = end;
        }
    }
    panic!("fixture exact backup member missing");
}

#[test]
fn exact_backup_data_is_deterministic_read_only_and_never_restore_authority() {
    let (fixture, repository) = repository();
    let before = fs::read_dir(fixture.root(&binding())).unwrap().count();
    let mut exporter = ExportGuard::new();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let first = repository
        .backup_data(&reviewed, &mut Guard::read(), &mut exporter)
        .unwrap();
    let second = backup(&repository);
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.sha256(), luma_content::sha256(first.bytes()));
    let inspected = inspect_backup_data(first.bytes()).unwrap();
    assert_eq!(&inspected, first.inspection());
    assert!(
        !inspected.authority_returned
            && !inspected.filesystem_changed
            && !inspected.restore_permitted
    );
    assert_eq!(inspected.manifest.binding, binding());
    assert_eq!(inspected.manifest.committed_outcomes, 1);
    assert_eq!(
        inspected.current,
        [repository
            .current_reference("document", &mut Guard::read())
            .unwrap()]
    );
    assert_eq!(
        exporter.completed_manifests,
        vec![inspected.manifest_sha256.clone(); exporter.checks]
    );
    assert!(exporter.checks > 30);
    let (manifest, data) = split(first.bytes());
    assert_eq!(
        member(
            &manifest,
            &data,
            BackupArea::Committed,
            &luma_content::sha256(b"first"),
            "source.bin"
        ),
        b"Original\r\nsource"
    );
    assert_eq!(
        fs::read_dir(fixture.root(&binding())).unwrap().count(),
        before
    );
    assert!(!fixture.root(&binding()).join("quarantine").exists());
}

#[test]
fn prior_review_returns_only_validated_commitments_and_needs_no_exporter() {
    let (fixture, repository) = repository();
    let before = fs::read_dir(fixture.root(&binding())).unwrap().count();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    reviewed.validate().unwrap();
    let json = serde_json::to_string(&reviewed).unwrap();
    assert!(json.len() <= MAX_BACKUP_REVIEW_BYTES);
    assert!(
        !json.contains("Original") && !json.contains("source_hex") && !json.contains("payload_hex")
    );
    assert_eq!(
        reviewed,
        repository.review_backup_data(&mut Guard::read()).unwrap()
    );
    assert_eq!(reviewed.archive_sha256, backup(&repository).sha256());
    assert_eq!(
        fs::read_dir(fixture.root(&binding())).unwrap().count(),
        before
    );
    let mut changed = reviewed.clone();
    changed.archive_bytes += 1;
    let mut reader = Guard::read();
    let mut exporter = ExportGuard::new();
    assert!(changed.validate().is_err());
    assert!(repository
        .backup_data(&changed, &mut reader, &mut exporter)
        .is_err());
    assert_eq!(reader.checks, 0);
    assert_eq!(exporter.checks, 0);
}

#[test]
fn initialized_empty_repository_has_an_explicit_zero_outcome_backup() {
    let fixture = Fixture::new();
    let initial = capture("not-published", "document", b"not-published source");
    let repository =
        Repository::create_at(&fixture.path, &initial, &mut Guard::write(&initial)).unwrap();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    assert_eq!(reviewed.committed_outcomes, 0);
    assert_eq!(reviewed.data_bytes, 0);
    assert!(reviewed
        .areas
        .iter()
        .all(|area| area.directories == 0 && area.members == 0 && area.bytes == 0));
    let backup = repository
        .backup_data(&reviewed, &mut Guard::read(), &mut ExportGuard::new())
        .unwrap();
    let inspected = inspect_backup_data(backup.bytes()).unwrap();
    assert!(inspected.manifest.directories.is_empty() && inspected.current.is_empty());
    assert!(!inspected.restore_permitted);
}

#[test]
fn every_read_only_review_checkpoint_refuses_revocation_without_creating_data() {
    let (fixture, repository) = repository();
    let mut baseline = Guard::read();
    repository.review_backup_data(&mut baseline).unwrap();
    for at in 1..=baseline.checks {
        let mut revoked = Guard::read();
        revoked.refuse_at = at;
        assert!(
            repository.review_backup_data(&mut revoked).is_err(),
            "review Read revocation {at}"
        );
        assert_eq!(revoked.checks, at);
    }
    assert_eq!(fs::read_dir(fixture.root(&binding())).unwrap().count(), 3);
}

#[test]
fn changed_head_pending_or_same_byte_inode_cannot_reuse_a_prior_review() {
    for mutation in 0..3 {
        let (fixture, mut repository) = repository();
        let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
        match mutation {
            0 => {
                let fresh = capture("later", "other-document", b"later source");
                repository
                    .apply(&fresh, b"later source", &mut Guard::write(&fresh))
                    .unwrap();
            }
            1 => {
                storage::mkdir(&repository.pending, &luma_content::sha256(b"later-pending"))
                    .unwrap();
            }
            _ => {
                let path = fixture
                    .root(&binding())
                    .join("outcomes")
                    .join(luma_content::sha256(b"first"))
                    .join("source.bin");
                let replacement = fixture.root(&binding()).join("replacement");
                fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
                fs::rename(&replacement, &path).unwrap();
            }
        }
        assert!(repository
            .backup_data(&reviewed, &mut Guard::read(), &mut ExportGuard::new())
            .is_err());
        assert_ne!(
            reviewed,
            repository.review_backup_data(&mut Guard::read()).unwrap()
        );
    }
}

#[test]
fn independent_export_and_resource_authority_are_required_before_private_reads() {
    let (_fixture, repository) = repository();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let mut reader = Guard::read();
    let mut exporter = ExportGuard::new();
    exporter.refuse_resources = true;
    assert!(repository
        .backup_data(&reviewed, &mut reader, &mut exporter)
        .is_err());
    assert_eq!(reader.checks, 0);
    let mut exporter = ExportGuard::new();
    exporter.refuse_at = 1;
    assert!(repository
        .backup_data(&reviewed, &mut reader, &mut exporter)
        .is_err());
    assert_eq!(reader.checks, 0);
    let mut exporter = ExportGuard::new();
    exporter.binding.owner_generation += 1;
    assert!(repository
        .backup_data(&reviewed, &mut reader, &mut exporter)
        .is_err());
    let mut reader = Guard::read();
    reader.refuse_resources = true;
    assert!(repository
        .backup_data(&reviewed, &mut reader, &mut ExportGuard::new())
        .is_err());
}

#[test]
fn every_independent_export_checkpoint_discards_revoked_plaintext_without_writes() {
    let (fixture, repository) = repository();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let mut baseline = ExportGuard::new();
    repository
        .backup_data(&reviewed, &mut Guard::read(), &mut baseline)
        .unwrap();
    for at in 1..=baseline.checks {
        let mut exporter = ExportGuard::new();
        exporter.refuse_at = at;
        assert!(
            repository
                .backup_data(&reviewed, &mut Guard::read(), &mut exporter)
                .is_err(),
            "Export revocation {at}"
        );
        assert_eq!(exporter.checks, at, "no checks after an Export refusal");
    }
    assert_eq!(fs::read_dir(fixture.root(&binding())).unwrap().count(), 3);
    assert_eq!(repository.inventory(&mut Guard::read()).unwrap().len(), 1);
}

#[test]
fn every_read_checkpoint_remains_live_in_addition_to_export_authority() {
    let (_fixture, repository) = repository();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let mut baseline = Guard::read();
    repository
        .backup_data(&reviewed, &mut baseline, &mut ExportGuard::new())
        .unwrap();
    for at in 1..=baseline.checks {
        let mut revoked = Guard::read();
        revoked.refuse_at = at;
        assert!(
            repository
                .backup_data(&reviewed, &mut revoked, &mut ExportGuard::new())
                .is_err(),
            "Read revocation {at}"
        );
        assert_eq!(revoked.checks, at);
    }
}

#[test]
fn completed_manifest_must_match_its_independent_exact_export_scope() {
    let (_fixture, repository) = repository();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let mut exporter = ExportGuard::new();
    exporter.exact_manifest = Some("f".repeat(64));
    assert!(repository
        .backup_data(&reviewed, &mut Guard::read(), &mut exporter)
        .is_err());
    let expected = backup(&repository).inspection().manifest_sha256.clone();
    let mut exporter = ExportGuard::new();
    exporter.exact_manifest = Some(expected);
    assert!(repository
        .backup_data(&reviewed, &mut Guard::read(), &mut exporter)
        .is_ok());
}

#[test]
fn full_history_keeps_conflicts_no_change_and_exact_original_sources() {
    let (_fixture, mut repository) = repository();
    let initial = repository
        .current_reference("document", &mut Guard::read())
        .unwrap();
    for (request, expected, bytes) in [
        ("second", initial.clone(), b"Changed\r\nsource".as_slice()),
        ("stale", initial.clone(), b"Conflicting source".as_slice()),
    ] {
        let plan = repository
            .plan_external_edit(
                "document",
                expected,
                bytes,
                provenance(request, bytes, EditOrigin::External),
                &mut Guard::read(),
            )
            .unwrap();
        repository
            .apply(&plan, bytes, &mut Guard::write(&plan))
            .unwrap();
    }
    let current = repository
        .current_reference("document", &mut Guard::read())
        .unwrap();
    let plan = repository
        .plan_external_edit(
            "document",
            current.clone(),
            b"Changed\nsource",
            provenance("same", b"Changed\nsource", EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    assert_eq!(plan.decision(), DecisionKind::NoChangeRetained);
    repository
        .apply(&plan, b"Changed\nsource", &mut Guard::write(&plan))
        .unwrap();
    let backup = backup(&repository);
    let inspected = inspect_backup_data(backup.bytes()).unwrap();
    assert_eq!(inspected.manifest.committed_outcomes, 4);
    assert_eq!(inspected.current, [current]);
    let (manifest, data) = split(backup.bytes());
    for (request, bytes) in [
        ("first", b"Original\r\nsource".as_slice()),
        ("second", b"Changed\r\nsource".as_slice()),
        ("stale", b"Conflicting source".as_slice()),
        ("same", b"Changed\nsource".as_slice()),
    ] {
        assert_eq!(
            member(
                &manifest,
                &data,
                BackupArea::Committed,
                &luma_content::sha256(request.as_bytes()),
                "source.bin"
            ),
            bytes
        );
    }
}

#[test]
fn managed_table_render_and_collection_histories_use_the_shared_reconstruction() {
    let fixture = Fixture::new();
    let csv = b"name,value\r\na,1\r\n";
    let initial = Plan::capture(
        binding(),
        "table",
        Format::Csv,
        csv,
        provenance("table-first", csv, EditOrigin::Managed),
    )
    .unwrap();
    let mut repository =
        Repository::create_at(&fixture.path, &initial, &mut Guard::write(&initial)).unwrap();
    let first = repository
        .apply(&initial, csv, &mut Guard::write(&initial))
        .unwrap();
    let request = luma_content::table::TableEditRequest {
        binding: binding(),
        expected: first.resulting,
        metadata: luma_content::table::EditMetadata {
            request_id: "table-edit".into(),
            workflow_sha256: "c".repeat(64),
        },
        operations: vec![luma_content::table::Operation::SetCell {
            row: 1,
            column: 1,
            value: "2".into(),
        }],
    };
    let plan = repository
        .plan_table_edit(&request, &mut Guard::read())
        .unwrap();
    repository
        .apply(
            &plan,
            &request.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    let rendered = luma_content::rendered::Request {
        binding: binding(),
        artifact_id: "rendered".into(),
        expected: None,
        metadata: luma_content::table::EditMetadata {
            request_id: "rendered-first".into(),
            workflow_sha256: "c".repeat(64),
        },
        engine: luma_content::rendered::Engine::Spreadsheet,
        source: serde_json::to_string(
            &serde_json::json!({"schema_version":1,"rows":[[{"kind":"number","value":"2"}]]}),
        )
        .unwrap(),
    };
    let plan = repository
        .plan_render(&rendered, &mut Guard::read())
        .unwrap();
    repository
        .apply(
            &plan,
            &rendered.canonical_bytes().unwrap(),
            &mut Guard::write(&plan),
        )
        .unwrap();
    let rendered_reference = repository
        .current_reference("rendered", &mut Guard::read())
        .unwrap();
    let collection = CollectionSource {
        schema_version: 1,
        kind: "luma-explicit-collection-v1".into(),
        collection_id: "work".into(),
        name: "Work".into(),
        members: vec![rendered_reference],
    };
    let source = collection.canonical_bytes().unwrap();
    let plan = repository
        .plan_collection(
            &collection,
            None,
            provenance("collection-first", &source, EditOrigin::External),
            &mut Guard::read(),
        )
        .unwrap();
    repository
        .apply_collection(&plan, &source, &mut Guard::write(&plan))
        .unwrap();
    let backup = backup(&repository);
    let inspected = inspect_backup_data(backup.bytes()).unwrap();
    assert_eq!(inspected.manifest.committed_outcomes, 4);
    assert_eq!(inspected.current.len(), 3);
    let (manifest, data) = split(backup.bytes());
    assert_eq!(
        member(
            &manifest,
            &data,
            BackupArea::Committed,
            &luma_content::sha256(b"table-edit"),
            "source.bin"
        ),
        request.canonical_bytes().unwrap()
    );
    assert_eq!(
        member(
            &manifest,
            &data,
            BackupArea::Committed,
            &luma_content::sha256(b"rendered-first"),
            "source.bin"
        ),
        rendered.canonical_bytes().unwrap()
    );
}

#[test]
fn empty_pending_and_binary_quarantine_evidence_are_separate_opaque_data() {
    let (_fixture, mut repository) = repository();
    let pending_name = luma_content::sha256(b"empty-pending");
    storage::mkdir(&repository.pending, &pending_name).unwrap();
    let quarantine = storage::mkdir(&repository.root, "quarantine").unwrap();
    let quarantined_name = luma_content::sha256(b"damaged-preparation");
    let prepared = storage::mkdir(&quarantine, &quarantined_name).unwrap();
    storage::write(&prepared, "record.json", &[0, 255, 1, 2], &mut || Ok(())).unwrap();
    repository.quarantine = Some(quarantine);
    let backup = backup(&repository);
    let (manifest, data) = split(backup.bytes());
    assert_eq!(
        manifest
            .directories
            .iter()
            .filter(|entry| entry.area == BackupArea::Pending)
            .count(),
        1
    );
    assert_eq!(
        manifest
            .directories
            .iter()
            .find(|entry| entry.name == pending_name)
            .unwrap()
            .members
            .len(),
        0
    );
    assert_eq!(
        member(
            &manifest,
            &data,
            BackupArea::Quarantined,
            &quarantined_name,
            "record.json"
        ),
        [0, 255, 1, 2]
    );
    assert_eq!(
        inspect_backup_data(backup.bytes())
            .unwrap()
            .manifest
            .committed_outcomes,
        1
    );
}

#[test]
fn empty_optional_quarantine_namespace_is_explicit_and_cannot_be_dropped_silently() {
    let (_fixture, mut repository) = repository();
    let without = backup(&repository);
    repository.quarantine = Some(storage::mkdir(&repository.root, "quarantine").unwrap());
    let with = backup(&repository);
    assert!(without.manifest().source_namespace.quarantined.is_none());
    assert!(with.manifest().source_namespace.quarantined.is_some());
    assert_ne!(with.sha256(), without.sha256());
    assert!(inspect_backup_data(with.bytes()).is_ok());
}

#[test]
fn malformed_magic_header_lengths_truncation_trailing_bytes_and_digest_changes_refuse() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    for length in [0, 1, 15, 19, 20, backup.bytes().len() - 1] {
        assert!(inspect_backup_data(&backup.bytes()[..length]).is_err());
    }
    let mut wrong = backup.bytes().to_vec();
    wrong[0] ^= 1;
    assert!(inspect_backup_data(&wrong).is_err());
    for length in [0_u32, (MAX_BACKUP_MANIFEST_BYTES + 1) as u32, u32::MAX] {
        let mut wrong = backup.bytes().to_vec();
        wrong[16..20].copy_from_slice(&length.to_be_bytes());
        assert!(inspect_backup_data(&wrong).is_err());
    }
    let mut trailing = backup.bytes().to_vec();
    trailing.push(0);
    assert!(inspect_backup_data(&trailing).is_err());
    let mut wrong = backup.bytes().to_vec();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(inspect_backup_data(&wrong).is_err());
}

#[test]
fn noncanonical_duplicate_unknown_or_nested_manifest_fields_are_not_dropped() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    let (manifest, data) = split(backup.bytes());
    let canonical = serde_json::to_string(&manifest).unwrap();
    let mut unknown = serde_json::to_value(&manifest).unwrap();
    unknown["authority"] = true.into();
    let mut member_unknown = serde_json::to_value(&manifest).unwrap();
    member_unknown["directories"][0]["members"][0]["extract_to"] = "/etc/shadow".into();
    for malformed in [
        format!(" {canonical}"),
        canonical.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
        serde_json::to_string(&unknown).unwrap(),
        serde_json::to_string(&member_unknown).unwrap(),
    ] {
        let mut bytes = b"LUMACONTENTBK01\n".to_vec();
        bytes.extend_from_slice(&(malformed.len() as u32).to_be_bytes());
        bytes.extend_from_slice(malformed.as_bytes());
        bytes.extend_from_slice(&data);
        assert!(inspect_backup_data(&bytes).is_err());
    }
}

#[test]
fn unknown_paths_duplicate_members_and_unordered_or_overlapping_directories_refuse() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    let (manifest, data) = split(backup.bytes());
    for path in [
        "../source.bin",
        "/etc/shadow",
        "identity.json",
        "source.bin/extra",
        "",
    ] {
        let mut changed = manifest.clone();
        changed.directories[0].members[0].name = path.into();
        assert!(inspect_backup_data(&assemble(&changed, &data)).is_err());
    }
    let mut changed = manifest.clone();
    changed.directories[0].members.swap(0, 1);
    assert!(inspect_backup_data(&assemble(&changed, &data)).is_err());
    let mut changed = manifest.clone();
    changed.directories[0].members[1] = changed.directories[0].members[0].clone();
    assert!(inspect_backup_data(&assemble(&changed, &data)).is_err());
    let mut changed = manifest.clone();
    let mut overlap = changed.directories[0].clone();
    overlap.area = BackupArea::Pending;
    changed.directories.push(overlap);
    assert!(inspect_backup_data(&assemble(&changed, &data)).is_err());
}

#[test]
fn source_identity_bounds_owner_substitution_and_manifest_counts_are_closed() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    let (manifest, data) = split(backup.bytes());
    let mut mutations = Vec::new();
    let mut changed = manifest.clone();
    changed.binding.owner_generation += 1;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.committed_outcomes += 1;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.data_bytes += 1;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.schema_version = 2;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.directories[0].members[0].bytes = MAX_PAYLOAD + 1;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.directories[0].members[0].source_identity.links = 2;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.directories[0].members[0].source_identity.mode = libc::S_IFREG | 0o600;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.directories[0].members[0]
        .source_identity
        .changed_nanoseconds = 1_000_000_000;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.committed_head_sha256 = "f".repeat(64);
    mutations.push(changed);
    for changed in mutations {
        assert!(inspect_backup_data(&assemble(&changed, &data)).is_err());
    }
}

#[test]
fn coherently_rehashed_false_sequence_is_rejected_by_real_history_reconstruction() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    let (mut manifest, mut data) = split(backup.bytes());
    let mut at = 0;
    let mut record_after = None;
    for entry in &mut manifest.directories[0].members {
        let end = at + entry.bytes as usize;
        if entry.name == "record.json" {
            let mut record: Record = serde_json::from_slice(&data[at..end]).unwrap();
            record.sequence = 2;
            let encoded = serde_json::to_vec(&record).unwrap();
            assert_eq!(encoded.len(), entry.bytes as usize);
            data[at..end].copy_from_slice(&encoded);
            entry.sha256 = luma_content::sha256(&encoded);
            record_after = Some(record);
        }
        at = end;
    }
    manifest.committed_head_sha256 = luma_content::sha256(
        &serde_json::to_vec(&(
            "luma-content-verified-outcome-history-v1",
            &manifest.binding,
            vec![record_after.unwrap()],
        ))
        .unwrap(),
    );
    assert!(inspect_backup_data(&assemble(&manifest, &data)).is_err());
}

#[test]
fn coherent_record_schema_or_plan_substitution_does_not_become_trusted_by_rehashing() {
    let (_fixture, repository) = repository();
    let backup = backup(&repository);
    for mutation in 0..3 {
        let (mut manifest, mut data) = split(backup.bytes());
        let mut at = 0;
        let mut record_after = None;
        for entry in &mut manifest.directories[0].members {
            let end = at + entry.bytes as usize;
            if entry.name == "record.json" {
                let mut record: Record = serde_json::from_slice(&data[at..end]).unwrap();
                match mutation {
                    0 => record.plan.binding.owner = "d".repeat(64),
                    1 => record.review_sha256 = "e".repeat(64),
                    _ => record.plan.provenance.workflow_sha256 = "f".repeat(64),
                }
                let encoded = serde_json::to_vec(&record).unwrap();
                assert_eq!(encoded.len(), entry.bytes as usize);
                data[at..end].copy_from_slice(&encoded);
                entry.sha256 = luma_content::sha256(&encoded);
                record_after = Some(record);
            }
            at = end;
        }
        manifest.committed_head_sha256 = luma_content::sha256(
            &serde_json::to_vec(&(
                "luma-content-verified-outcome-history-v1",
                &manifest.binding,
                vec![record_after.unwrap()],
            ))
            .unwrap(),
        );
        assert!(inspect_backup_data(&assemble(&manifest, &data)).is_err());
    }
}

#[test]
fn unsafe_or_damaged_source_layout_is_preserved_and_never_exported() {
    for kind in 0..3 {
        let (fixture, repository) = repository();
        let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
        let directory = fixture
            .root(&binding())
            .join("outcomes")
            .join(luma_content::sha256(b"first"));
        let source = directory.join("source.bin");
        match kind {
            0 => {
                fs::write(directory.join("extra"), b"evidence").unwrap();
            }
            1 => {
                fs::hard_link(&source, fixture.path.join("hardlink")).unwrap();
            }
            _ => {
                fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        assert!(repository
            .backup_data(&reviewed, &mut Guard::read(), &mut ExportGuard::new())
            .is_err());
        assert!(source.exists());
    }
}

#[test]
fn namespace_descriptor_replacement_is_not_followed_during_backup_creation() {
    let (fixture, repository) = repository();
    let reviewed = repository.review_backup_data(&mut Guard::read()).unwrap();
    let outcomes = fixture.root(&binding()).join("outcomes");
    let retained = fixture.root(&binding()).join("moved-outcomes");
    let original_inode = fs::metadata(&outcomes).unwrap().ino();
    fs::rename(&outcomes, &retained).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&outcomes).unwrap();
    assert!(repository
        .backup_data(&reviewed, &mut Guard::read(), &mut ExportGuard::new())
        .is_err());
    assert_eq!(fs::metadata(&retained).unwrap().ino(), original_inode);
    assert!(retained
        .join(luma_content::sha256(b"first"))
        .join("source.bin")
        .exists());
}
