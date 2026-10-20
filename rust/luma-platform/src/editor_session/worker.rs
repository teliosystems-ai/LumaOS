use super::*;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileTypeExt;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frozen {
    pub schema_version: u32,
    pub request_sha256: String,
    pub binding: String,
    pub lease: crate::resources::Token,
    pub checkpoint: Checkpoint,
    pub saved: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Frame {
    View { view: protocol::View },
    Frozen { result: Frozen },
}

pub(super) fn run(selected: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    source_digest(selected)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-editor (enforce)\n"
    {
        return Err("editor requires actual fixed enforcing acquisition worker".into());
    }
    let claim = crate::platform::InstalledDataClaim::capture()?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(selected, Path::new("/var"))?;
    let until = resource_manager::now()?
        .checked_add(30_000)
        .ok_or("editor deadline overflow")?;
    let mut check = || {
        lease.check()?;
        claim.recheck()?;
        if resource_manager::now()? >= until {
            return Err("editor period expired; memory draft is not saved".into());
        }
        Ok(())
    };
    // Only the fixed inherited pipes are used. No terminal, caller-selected
    // path, socket endpoint, content store or publication credential is opened.
    let duplicate = |fd| -> Result<File> {
        let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copied < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(copied) })
    };
    let mut input = protocol::Bounded::new(duplicate(0)?, MAX_WIRE_INPUT);
    let mut output = protocol::Bounded::new(duplicate(1)?, MAX_WIRE_OUTPUT);
    for fd in [input.as_raw_fd(), output.as_raw_fd()] {
        let file = duplicate(fd)?;
        if !file.metadata()?.file_type().is_fifo() {
            return Err("editor accepts only fixed inherited private pipes, never caller files or terminals".into());
        }
    }
    protocol::nonblocking(input.as_raw_fd())?;
    protocol::nonblocking(output.as_raw_fd())?;
    let bytes = protocol::receive(&mut input, &mut check)?;
    if profile(&bytes)? != selected {
        return Err("editor initial bytes differ from actual admitted resource request".into());
    }
    let request = parse(&bytes)?;
    let mut editor = protocol::Editor::new(request)?;
    protocol::send(
        &mut output,
        &serde_json::to_vec(&Frame::View {
            view: editor.view()?,
        })?,
        &mut check,
    )?;
    loop {
        let bytes = protocol::receive(&mut input, &mut check)?;
        let command = protocol::parse_command(&bytes)?;
        check()?;
        if let Some(checkpoint) = editor.apply(command)? {
            check()?;
            checkpoint.validate()?;
            let hash = io::digest(&serde_json::to_vec(&checkpoint)?);
            lease.complete_output(&hash)?;
            lease.check_local()?;
            let frozen = Frozen {
                schema_version: 1,
                request_sha256: source_digest(selected)?.into(),
                binding: binding(
                    selected,
                    &resource_manager::storage_device(Path::new("/var"))?,
                )?,
                lease: lease.token().clone(),
                checkpoint,
                saved: false,
            };
            protocol::send(
                &mut output,
                &serde_json::to_vec(&Frame::Frozen { result: frozen })?,
                &mut check,
            )?;
            output.flush()?;
            return Ok(());
        }
        protocol::send(
            &mut output,
            &serde_json::to_vec(&Frame::View {
                view: editor.view()?,
            })?,
            &mut check,
        )?;
    }
}
