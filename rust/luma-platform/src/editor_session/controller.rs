use super::*;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

fn terminal() -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/dev/tty")?;
    if unsafe { libc::isatty(f.as_raw_fd()) } != 1 {
        return Err("editor requires original controlling terminal".into());
    }
    Ok(f)
}
fn line(tty: &mut File, check: &mut impl FnMut() -> Result<()>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        check()?;
        let mut poll = libc::pollfd {
            fd: tty.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut poll, 1, 100) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("original editor terminal closed; draft not saved".into());
        }
        if poll.revents & libc::POLLIN == 0 {
            continue;
        }
        let mut b = [0];
        match tty.read(&mut b) {
            Ok(1) if b[0] == b'\n' => return Ok(bytes),
            Ok(1) => {
                if bytes.len() >= MAX_REQUEST {
                    return Err("editor literal command exceeds bound".into());
                }
                bytes.push(b[0]);
            }
            Ok(_) => return Err("editor original terminal ended".into()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e.into()),
        }
    }
}
fn display(
    tty: &mut File,
    view: &protocol::View,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let json = serde_json::to_string(view)?;
    // Keep terminal controls and Unicode presentation controls literal. The
    // actual source bytes remain unchanged in the typed private checkpoint.
    let mut literal = String::new();
    for c in json.chars() {
        if (' '..='~').contains(&c) {
            literal.push(c);
        } else {
            use std::fmt::Write as _;
            write!(&mut literal, "\\u{{{:x}}}", c as u32)?;
        }
    }
    literal.push('\n');
    let mut bytes = literal.as_bytes();
    while !bytes.is_empty() {
        check()?;
        let mut poll = libc::pollfd {
            fd: tty.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut poll, 1, 100) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err("editor display disconnected; draft not saved".into());
        }
        if poll.revents & libc::POLLOUT == 0 {
            continue;
        }
        check()?;
        match tty.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err("editor display closed".into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(e) => return Err(e.into()),
        }
    }
    check()
}
fn transport(
    selected: &str,
    bytes: &[u8],
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<worker::Frozen> {
    let mut tty = terminal()?;
    writeln!(tty,"Editor: original 30-second session, no renewal or automatic save. Enter one canonical JSON operation per line: title, insert, replace, remove, preview, freeze, cancel. Freeze drains this edit period; its output is NOT Saved. Timeout/cancellation discards the memory draft.")?;
    tty.flush()?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args(crate::acquisition::arguments(
            Path::new("/var"),
            selected,
            "editor",
        )?)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let result = (|| {
        let mut input = protocol::Bounded::new(
            child
                .stdin
                .take()
                .ok_or("editor controller input missing")?,
            MAX_WIRE_INPUT,
        );
        let mut output = protocol::Bounded::new(
            child
                .stdout
                .take()
                .ok_or("editor controller output missing")?,
            MAX_WIRE_OUTPUT,
        );
        protocol::nonblocking(input.as_raw_fd())?;
        protocol::nonblocking(output.as_raw_fd())?;
        let mut check = || check();
        protocol::send(&mut input, bytes, &mut check)?;
        let mut expected_sequence = 0;
        let mut editor = protocol::Editor::new(parse(bytes)?)?;
        let mut frozen: Option<Checkpoint> = None;
        loop {
            let bytes = protocol::receive(&mut output, &mut check)?;
            let frame: worker::Frame = serde_json::from_slice(&bytes)?;
            if serde_json::to_vec(&frame)? != bytes {
                return Err("editor worker output is not exact closed canonical data".into());
            }
            match frame {
                worker::Frame::View { view } => {
                    if frozen.is_some()
                        || view.schema_version != 1
                        || view.sequence != expected_sequence
                        || view.frozen
                        || view.saved
                        || serde_json::to_vec(&view)? != serde_json::to_vec(&editor.view()?)?
                    {
                        return Err(
                            "editor worker view differs from current typed sequence/source".into(),
                        );
                    }
                    display(&mut tty, &view, &mut check)?;
                    let operation_bytes = line(&mut tty, &mut check)?;
                    let operation: protocol::Edit = serde_json::from_slice(&operation_bytes)?;
                    if serde_json::to_vec(&operation)? != operation_bytes {
                        return Err("editor operation requires exact closed canonical JSON".into());
                    }
                    expected_sequence = expected_sequence
                        .checked_add(1)
                        .ok_or("editor sequence overflow")?;
                    if expected_sequence > MAX_COMMANDS {
                        return Err("editor command budget exhausted; no hidden renewal".into());
                    }
                    let command = protocol::Command {
                        sequence: expected_sequence,
                        expected_source_sha256: view.source_sha256,
                        operation,
                    };
                    let command_bytes = serde_json::to_vec(&command)?;
                    let cancelled = matches!(command.operation, protocol::Edit::Cancel {});
                    if !cancelled {
                        frozen = editor.apply(command)?;
                    }
                    protocol::send(&mut input, &command_bytes, &mut check)?;
                    if cancelled {
                        return Err("editor explicitly cancelled; draft not saved".into());
                    }
                }
                worker::Frame::Frozen { result } => {
                    check()?;
                    if frozen.as_ref() != Some(&result.checkpoint) {
                        return Err(
                            "editor returned a checkpoint without exact human Freeze/source".into(),
                        );
                    }
                    // Closing the inherited command pipe prevents additional
                    // edits. Successful output still requires child exit and
                    // broker-proven physical drainage before it is returned.
                    drop(input);
                    let until = resource_manager::now()?
                        .checked_add(3000)
                        .ok_or("editor child exit deadline overflow")?;
                    loop {
                        check()?;
                        if let Some(status) = child.try_wait()? {
                            if !status.success() {
                                return Err("editor worker did not complete freeze".into());
                            }
                            break;
                        }
                        if resource_manager::now()? >= until {
                            return Err("editor worker exit after freeze is unconfirmed".into());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    protocol::require_eof(&mut output, &mut check)?;
                    return Ok(result);
                }
            }
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    binding: String,
    output_sha256: String,
    output_domain_epochs: std::collections::BTreeMap<String, crate::resources::OutputEpoch>,
    lease: crate::resources::Token,
    state: crate::resources::State,
    physical_release_granted: bool,
}
fn verify_result(
    result: &worker::Frozen,
    request: &StartRequest,
    bytes: &[u8],
    selected: &str,
) -> Result<()> {
    result.checkpoint.validate()?;
    if serde_json::to_vec(result)?.len() > MAX_FINAL_OUTPUT
        || result.schema_version != 1
        || result.saved
        || result.request_sha256 != io::digest(bytes)
        || result.binding != acquisition_usage(selected)?.selector.digest
        || !crate::workflow_resource::token_valid(&result.lease)
        || result.checkpoint.binding != request.binding
        || result.checkpoint.previous_checkpoint != request.resume
    {
        return Err(
            "editor frozen data differs from exact original request/binding/generation".into(),
        );
    }
    let mut query = resource_manager::request("resource-output-receipt")?;
    query.lease = Some(result.lease.clone());
    let receipt: Receipt = serde_json::from_value(
        crate::service::resource_exchange(&query)?
            .status
            .ok_or("editor actual output receipt missing")?,
    )?;
    if receipt.binding != result.binding
        || receipt.lease != result.lease
        || receipt.output_sha256 != io::digest(&serde_json::to_vec(&result.checkpoint)?)
        || receipt.physical_release_granted
        || receipt
            .output_domain_epochs
            .keys()
            .map(String::as_str)
            .ne(resource_manager::invoice_output_domains())
        || receipt.output_domain_epochs.values().any(|e| e.0 == 0)
    {
        return Err("editor lacks unfenced exact physical output generation".into());
    }
    match receipt.state {
        crate::resources::State::Active
        | crate::resources::State::Draining
        | crate::resources::State::Released => Ok(()),
    }
}
fn subject(
    login: &str,
    binding: &OwnerBinding,
    guard: &mut crate::admin_governance::GrantBoundary<'_>,
) -> Result<()> {
    guard.check()?;
    let (registry, account, installation) = crate::admin_governance::current_principal(login)?;
    registry.current()?;
    if installation != binding.installation
        || account.id != binding.owner
        || account.generation != binding.owner_generation
        || guard.subject()? != account.id
        || guard.subject_generation()? != account.generation
        || guard.subject_uid()? != account.uid
    {
        return Err(
            "editor session belongs to a different current authenticated human principal".into(),
        );
    }
    Ok(())
}
pub(super) fn command(args: &[String]) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    match args.first().map(String::as_str) {
        Some("editor-resource-worker") if args.len()==2=>worker::run(&args[1]),
        Some("editor-review") if args.len()==3=> {
            let bytes=read_request(Path::new(&args[2]))?;
            let request=parse(&bytes)?;
            let read_usage=if let Some(expected)=&request.resume {Some(crate::content_governed::acquisition_usage(&crate::content_governed::editor_checkpoint_profile(&crate::content_governed::editor_checkpoint_input(&args[1],&request.binding,expected)?)?)?)}else{None};
            println!("{}",serde_json::json!({"schema_version":1,"start_usage":acquisition_usage(&profile(&bytes)?)?,"checkpoint_read_usage":read_usage,"request":request,"authority_returned":false,"saved":false}));
            Ok(())
        }
        Some("editor-run") if args.len()==5=> {
            let path=Path::new(&args[4]);let bytes=read_request(path)?;let request=parse(&bytes)?;let selected=profile(&bytes)?;
            verify_client_request(path,&selected)?;
            let claim=crate::platform::InstalledDataClaim::capture()?;
            if let Some(expected)=&request.resume {
                let version=crate::content_governed::editor_checkpoint_read(&args[1],&request.binding,expected,&args[3],&path.with_file_name("content.json"))?;
                validate_reopened_checkpoint(&version,&request)?;
            } else if args[3]!="none" {return Err("new editor source cannot borrow a checkpoint Read grant".into());}
            crate::acquisition::await_drainage()?;claim.recheck()?;
            let usage=acquisition_usage(&selected)?;
            crate::admin_governance::with_grant(&args[1],&args[2],&usage,|guard| {
                subject(&args[1],&request.binding,guard)?;claim.recheck()?;
                if guard.session_purpose()!=crate::authentication::SessionPurpose::Standard {return Err("editor cannot borrow extended purpose authorization".into());}
                let effect=guard.effect_begin(&io::digest(&bytes),crate::policy_decisions::EffectKind::WorkerAdmission)?;
                let result=crate::service::granted_acquisition::run_editor(&selected,&usage,guard,|check|transport(&selected,&bytes,check))?;
                subject(&args[1],&request.binding,guard)?;claim.recheck()?;verify_result(&result,&request,&bytes,&selected)?;
                guard.effect_complete(effect,&io::digest(&serde_json::to_vec(&result)?))?;
                crate::content_governed::deliver_editor_result(&serde_json::to_value(&result)?,|| {
                    subject(&args[1],&request.binding,guard)?;claim.recheck()?;verify_result(&result,&request,&bytes,&selected)
                })?;
                Ok(())
            })
        }
        _=>Err("editor accepts exact review/run commands; checkpoint output is not Saved or resume authority".into()),
    }
}
