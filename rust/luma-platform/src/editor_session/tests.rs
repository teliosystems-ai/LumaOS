use super::*;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

fn request() -> StartRequest {
    StartRequest {
        schema_version: 1,
        binding: OwnerBinding {
            installation: "1".repeat(64),
            owner: "2".repeat(64),
            owner_generation: 1,
        },
        session_id: "3".repeat(32),
        checkpoint_artifact_id: "Draft-1".into(),
        document: document::Source {
            schema_version: 1,
            title: "Draft".into(),
            blocks: vec![document::Block::Paragraph {
                runs: vec![document::Inline::Text {
                    text: "literal source".into(),
                }],
            }],
        },
        resume: None,
    }
}
fn operation(editor: &protocol::Editor, operation: protocol::Edit) -> protocol::Command {
    let view = editor.view().unwrap();
    protocol::Command {
        sequence: view.sequence + 1,
        expected_source_sha256: view.source_sha256,
        operation,
    }
}
#[test]
fn canonical_request_refuses_aliases_duplicates_unknown_fields_and_bounds() {
    let r = request();
    let bytes = serde_json::to_vec(&r).unwrap();
    assert_eq!(parse(&bytes).unwrap(), r);
    for mutation in [
        format!(" {}", String::from_utf8(bytes.clone()).unwrap()),
        String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
        String::from_utf8(bytes).unwrap().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"authority\":true",
            1,
        ),
    ] {
        assert!(parse(mutation.as_bytes()).is_err());
    }
    for case in 0..5 {
        let mut r = request();
        match case {
            0 => r.document.title = "x".repeat(4097),
            1 => r.document.title = "\u{1b}[31m".into(),
            2 => r.session_id = "0".repeat(32),
            3 => r.checkpoint_artifact_id = "../draft".into(),
            _ => {
                r.document.blocks = vec![
                    document::Block::Code {
                        text: "x".repeat(4096)
                    };
                    5
                ]
            }
        };
        assert!(r.validate().is_err());
    }
}
#[test]
fn edit_cas_prevents_stale_commands_and_mutations_are_atomic() {
    let mut e = protocol::Editor::new(request()).unwrap();
    let before = serde_json::to_vec(&e.view().unwrap()).unwrap();
    let mut cmd = operation(&e, protocol::Edit::Title { text: "new".into() });
    cmd.sequence += 1;
    assert!(e.apply(cmd).is_err());
    let mut cmd = operation(&e, protocol::Edit::Title { text: "new".into() });
    cmd.expected_source_sha256 = "a".repeat(64);
    assert!(e.apply(cmd).is_err());
    for op in [
        protocol::Edit::Insert {
            index: 99,
            block: document::Block::Rule,
        },
        protocol::Edit::Replace {
            index: 99,
            block: document::Block::Rule,
        },
        protocol::Edit::Remove { index: 99 },
        protocol::Edit::Title {
            text: "bad\rcontrol".into(),
        },
    ] {
        let cmd = operation(&e, op);
        assert!(e.apply(cmd).is_err());
        assert_eq!(serde_json::to_vec(&e.view().unwrap()).unwrap(), before);
    }
    let cmd = operation(&e, protocol::Edit::Title { text: "new".into() });
    assert!(e.apply(cmd).unwrap().is_none());
    assert_eq!(e.view().unwrap().sequence, 1);
    assert_eq!(e.view().unwrap().document.title, "new");
}
#[test]
fn all_typed_edits_preserve_source_and_freeze_is_terminal_not_saved() {
    let r = request();
    let mut e = protocol::Editor::new(r.clone()).unwrap();
    for op in [
        protocol::Edit::Insert {
            index: 1,
            block: document::Block::Code {
                text: "<literal>&".into(),
            },
        },
        protocol::Edit::Replace {
            index: 0,
            block: document::Block::Heading {
                level: 2,
                text: "replacement".into(),
            },
        },
        protocol::Edit::Remove { index: 1 },
        protocol::Edit::Preview {},
    ] {
        let cmd = operation(&e, op);
        assert!(e.apply(cmd).unwrap().is_none());
    }
    let cmd = operation(&e, protocol::Edit::Freeze {});
    let checkpoint = e.apply(cmd).unwrap().unwrap();
    checkpoint.validate().unwrap();
    assert_eq!(checkpoint.binding, r.binding);
    assert_eq!(checkpoint.document, e.view().unwrap().document);
    assert!(!e.view().unwrap().saved);
    let cmd = operation(
        &e,
        protocol::Edit::Title {
            text: "too late".into(),
        },
    );
    assert!(e.apply(cmd).is_err());
}
#[test]
fn cancellation_and_budget_exhaustion_never_produce_checkpoint() {
    let mut e = protocol::Editor::new(request()).unwrap();
    let cmd = operation(&e, protocol::Edit::Cancel {});
    assert!(e.apply(cmd).is_err());
    let cmd = operation(&e, protocol::Edit::Freeze {});
    assert!(e.apply(cmd).is_err());
    let mut e = protocol::Editor::new(request()).unwrap();
    for _ in 0..MAX_COMMANDS {
        let cmd = operation(&e, protocol::Edit::Preview {});
        assert!(e.apply(cmd).unwrap().is_none());
    }
    let cmd = operation(&e, protocol::Edit::Freeze {});
    assert!(e.apply(cmd).is_err());
}
#[test]
fn checkpoint_integrity_and_resume_reference_are_closed_data_not_authentication() {
    let r = request();
    let checkpoint = Checkpoint::new(&r, r.document.clone()).unwrap();
    checkpoint.validate().unwrap();
    for case in 0..4 {
        let mut c = checkpoint.clone();
        match case {
            0 => c.document.title = "tampered".into(),
            1 => c.source_sha256 = "f".repeat(64),
            2 => c.profile = "native-authority".into(),
            _ => c.binding.owner_generation = 0,
        };
        assert!(c.validate().is_err());
    }
    let mut r = request();
    r.resume = Some(VersionReference {
        artifact_id: r.checkpoint_artifact_id.clone(),
        version: 1,
        content_sha256: "4".repeat(64),
        receipt_sha256: "5".repeat(64),
    });
    r.validate().unwrap();
    r.resume.as_mut().unwrap().artifact_id = "Other".into();
    assert!(r.validate().is_err());
    let bytes = checkpoint.canonical_bytes().unwrap();
    let version = luma_content::capture(
        checkpoint.binding.clone(),
        "Draft-1",
        luma_content::Format::Json,
        &bytes,
        luma_content::Provenance {
            request_id: "checkpoint-fixture".into(),
            workflow_sha256: "6".repeat(64),
            source_sha256: io::digest(&bytes),
            origin: luma_content::EditOrigin::Managed,
        },
    )
    .unwrap();
    assert_eq!(version.content(), bytes);
    let recovered: Checkpoint = serde_json::from_slice(version.content()).unwrap();
    assert_eq!(recovered, checkpoint);
}
#[test]
fn reopened_checkpoint_requires_actual_json_receipt_even_with_identical_text_bytes() {
    let start = request();
    let checkpoint = Checkpoint::new(&start, start.document.clone()).unwrap();
    let bytes = checkpoint.canonical_bytes().unwrap();
    let capture = |format, binding| {
        luma_content::capture(
            binding,
            "Draft-1",
            format,
            &bytes,
            luma_content::Provenance {
                request_id: "typed-resume-fixture".into(),
                workflow_sha256: "6".repeat(64),
                source_sha256: io::digest(&bytes),
                origin: luma_content::EditOrigin::External,
            },
        )
        .unwrap()
    };
    let json = capture(luma_content::Format::Json, start.binding.clone());
    let text = capture(luma_content::Format::Utf8Text, start.binding.clone());
    assert_eq!(json.content(), text.content());
    let mut selected = start.clone();
    selected.resume = Some(json.reference().unwrap());
    assert_eq!(
        validate_reopened_checkpoint(&json, &selected).unwrap(),
        checkpoint
    );
    selected.resume = Some(text.reference().unwrap());
    assert!(validate_reopened_checkpoint(&text, &selected).is_err());
    let mut foreign = start.binding.clone();
    foreign.owner = "a".repeat(64);
    let other = capture(luma_content::Format::Json, foreign);
    selected.resume = Some(other.reference().unwrap());
    assert!(validate_reopened_checkpoint(&other, &selected).is_err());
    assert!(validate_reopened_checkpoint(&json, &start).is_err());
}
#[test]
fn profile_binding_covers_request_storage_and_limits_without_new_domain() {
    let bytes = serde_json::to_vec(&request()).unwrap();
    let p = profile(&bytes).unwrap();
    assert!(is_profile(&p));
    assert_eq!(source_digest(&p).unwrap(), io::digest(&bytes));
    assert_ne!(binding(&p, "253:0").unwrap(), binding(&p, "253:1").unwrap());
    let mut changed = request();
    changed.session_id = "6".repeat(32);
    assert_ne!(p, profile(&serde_json::to_vec(&changed).unwrap()).unwrap());
    assert!(source_digest("editor-v1-no").is_err());
    assert!(source_digest(&format!("{PREFIX}{}", "G".repeat(64))).is_err());
}
#[test]
fn framed_actual_kernel_transport_is_exact_and_cancellable_between_partial_reads() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    protocol::nonblocking(writer.as_raw_fd()).unwrap();
    protocol::nonblocking(reader.as_raw_fd()).unwrap();
    let bytes = serde_json::to_vec(&request()).unwrap();
    protocol::send(&mut writer, &bytes, &mut || Ok(())).unwrap();
    assert_eq!(
        protocol::receive(&mut reader, &mut || Ok(())).unwrap(),
        bytes
    );
    writer.write_all(&10u32.to_be_bytes()).unwrap();
    writer.write_all(b"part").unwrap();
    let mut checks = 0;
    let result = protocol::receive(&mut reader, &mut || {
        checks += 1;
        if checks > 3 {
            Err("original authorization revoked".into())
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert!(checks > 3);
}
#[test]
fn framed_transport_refuses_oversized_truncated_and_duplicate_command_data() {
    for header in [0, protocol::MAX_FRAME as u32 + 1] {
        let (mut w, mut r) = UnixStream::pair().unwrap();
        w.write_all(&header.to_be_bytes()).unwrap();
        assert!(protocol::receive(&mut r, &mut || Ok(())).is_err());
    }
    let (mut w, mut r) = UnixStream::pair().unwrap();
    w.write_all(&20u32.to_be_bytes()).unwrap();
    w.write_all(b"short").unwrap();
    drop(w);
    assert!(protocol::receive(&mut r, &mut || Ok(())).is_err());
    let mut e = protocol::Editor::new(request()).unwrap();
    let cmd = operation(&e, protocol::Edit::Preview {});
    let b = serde_json::to_vec(&cmd).unwrap();
    let parsed = protocol::parse_command(&b).unwrap();
    assert!(e.apply(parsed).unwrap().is_none());
    assert!(protocol::parse_command(
        String::from_utf8(b)
            .unwrap()
            .replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":1", 1)
            .as_bytes()
    )
    .is_err());
}
#[test]
fn actual_harmless_child_roundtrip_preserves_framing_without_claiming_worker_authority() {
    let mut child = std::process::Command::new("/bin/cat")
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    protocol::nonblocking(input.as_raw_fd()).unwrap();
    protocol::nonblocking(output.as_raw_fd()).unwrap();
    let data = serde_json::to_vec(&request()).unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut check = || {
        if std::time::Instant::now() < until {
            Ok(())
        } else {
            Err("child transport deadline".into())
        }
    };
    protocol::send(&mut input, &data, &mut check).unwrap();
    assert_eq!(protocol::receive(&mut output, &mut check).unwrap(), data);
    drop(input);
    assert!(child.wait().unwrap().success());
}
#[test]
fn actual_child_terminal_output_requires_eof_not_trailing_byte_or_second_frame() {
    for suffix in [vec![], vec![b'x'], [&1u32.to_be_bytes()[..], b"x"].concat()] {
        let mut child = std::process::Command::new("/bin/cat")
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        protocol::nonblocking(output.as_raw_fd()).unwrap();
        let terminal = br#"{"kind":"frozen","saved":false}"#;
        input
            .write_all(&(terminal.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(terminal).unwrap();
        input.write_all(&suffix).unwrap();
        drop(input);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut check = || {
            if std::time::Instant::now() < until {
                Ok(())
            } else {
                Err("terminal protocol fixture deadline".into())
            }
        };
        assert_eq!(
            protocol::receive(&mut output, &mut check).unwrap(),
            terminal
        );
        assert!(child.wait().unwrap().success());
        assert_eq!(
            protocol::require_eof(&mut output, &mut check).is_ok(),
            suffix.is_empty()
        );
    }
}
#[test]
fn original_resume_and_start_positions_refuse_receipt_or_arbitrary_command_authority() {
    let args = [
        "/usr/libexec/luma-os/luma-platform",
        "editor-run",
        "admin",
        "StartGrant",
        "ReadGrant",
        "/run/luma-granted-client/requests/11111111111111111111111111111111/editor.json",
        "",
    ];
    assert_eq!(original_arguments(&args).unwrap(), args[5]);
    for index in [0, 1, 2, 3, 6] {
        let mut other = args;
        other[index] = if index == 6 { "extra" } else { "" };
        assert!(original_arguments(&other).is_err());
    }
    assert!(check_client_arguments(&args, "editor-v1-not-a-hash", None).is_err());
}
#[test]
fn aggregate_transport_caps_cannot_be_reset_by_another_frame() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let mut writer = protocol::Bounded::new(&mut writer, 10);
    writer.write_all(b"1234567890").unwrap();
    assert!(writer.write_all(b"1").is_err());
    let mut reader = protocol::Bounded::new(&mut reader, 5);
    let mut bytes = [0; 5];
    std::io::Read::read_exact(&mut reader, &mut bytes).unwrap();
    assert_eq!(&bytes, b"12345");
    assert!(std::io::Read::read(&mut reader, &mut bytes).is_err());
    assert_eq!(MAX_WIRE_INPUT, (MAX_REQUEST + 4) * 65);
    assert_eq!(MAX_WIRE_OUTPUT, (protocol::MAX_FRAME + 4) * 65);
}
#[test]
fn pure_editor_preparation_is_canonical_data_without_lease_or_saved_claim() {
    let value = prepare(
        "editor-request",
        &serde_json::to_vec_pretty(&request()).unwrap(),
    )
    .unwrap();
    let canonical = value["canonical_request"].as_str().unwrap();
    assert_eq!(parse(canonical.as_bytes()).unwrap(), request());
    assert_eq!(value["request_sha256"], io::digest(canonical.as_bytes()));
    assert_eq!(value["session_lease_held"], false);
    assert_eq!(value["saved"], false);
    assert_eq!(value["authority_returned"], false);
    assert!(prepare("editor-run", b"{}").is_err());
}
#[test]
fn checkpoint_proposal_uses_exact_frozen_source_and_expected_cas_but_mints_no_publication() {
    let start = request();
    let checkpoint = Checkpoint::new(&start, start.document.clone()).unwrap();
    let frozen = worker::Frozen {
        schema_version: 1,
        request_sha256: io::digest(&serde_json::to_vec(&start).unwrap()),
        binding: "8".repeat(64),
        lease: crate::resources::Token {
            lease_id: "9".repeat(32),
            generation: 1,
            manager_epoch: "a".repeat(32),
        },
        checkpoint,
        saved: false,
    };
    let input = serde_json::json!({"schema_version":1,"login":"admin","request_id":"save-one","start":start,"frozen":frozen});
    let result = prepare(
        "editor-checkpoint-request",
        &serde_json::to_vec(&input).unwrap(),
    )
    .unwrap();
    let canonical = result["canonical_request"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(canonical).unwrap();
    assert_eq!(parsed["operation"]["kind"], "capture");
    assert_eq!(parsed["operation"]["format"], "json");
    assert_eq!(result["saved"], false);
    let mut resumed = input.clone();
    let expected = serde_json::json!({"artifact_id":"Draft-1","version":2,"content_sha256":"b".repeat(64),"receipt_sha256":"c".repeat(64)});
    resumed["start"]["resume"] = expected.clone();
    let typed: StartRequest = serde_json::from_value(resumed["start"].clone()).unwrap();
    resumed["frozen"]["request_sha256"] = io::digest(&serde_json::to_vec(&typed).unwrap()).into();
    resumed["frozen"]["checkpoint"]["previous_checkpoint"] = expected.clone();
    let result = prepare(
        "editor-checkpoint-request",
        &serde_json::to_vec(&resumed).unwrap(),
    )
    .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(result["canonical_request"].as_str().unwrap()).unwrap();
    assert_eq!(parsed["operation"]["kind"], "external");
    assert_eq!(parsed["operation"]["expected"], expected);
    for case in 0..4 {
        let mut bad = input.clone();
        match case {
            0 => bad["frozen"]["saved"] = true.into(),
            1 => bad["frozen"]["request_sha256"] = "f".repeat(64).into(),
            2 => bad["frozen"]["checkpoint"]["document"]["title"] = "mutation".into(),
            _ => bad["start"]["binding"]["owner_generation"] = 2.into(),
        };
        assert!(prepare(
            "editor-checkpoint-request",
            &serde_json::to_vec(&bad).unwrap()
        )
        .is_err());
    }
}
