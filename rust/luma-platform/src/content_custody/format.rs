//! Disk layout is a parser discriminator, never a checkpoint or a permission.
//! In particular, an interrupted paged migration must not fall back to the old
//! journal simply because its final selector is absent or unreadable.
use super::*;
use std::fs::File;
use std::os::unix::fs::MetadataExt;

const PAGED: &str = "paged-v3";

/// Closed scope DATA only. Recognizing it does not add a command dispatcher,
/// create a grant or permit legacy Store to enter a staged paged namespace.
pub(super) fn paged_admin_scope(
    command: &str,
    usage: &crate::finite_grants::Use,
) -> Option<Result<()>> {
    use crate::finite_grants::{Action, Kind};
    let (action, selector) = match command {
        "content-custody-paged-review" => (Action::Read, "content-custody-paged-read-v3"),
        "content-custody-paged-bootstrap" => (
            Action::ProvisionResource,
            "content-custody-paged-bootstrap-v3",
        ),
        "content-custody-paged-reconcile" => (
            Action::RecoverResource,
            "content-custody-paged-reconcile-v3",
        ),
        _ => return None,
    };
    Some((|| {
        usage.validate()?;
        digest(&usage.selector.digest)?;
        if usage.action != action
            || usage.selector.kind
                != if action == Action::Read {
                    Kind::File
                } else {
                    Kind::Resource
                }
            || usage.selector.id != selector
            || usage.selector.generation != 1
            || usage.input_bytes != 0
            || usage.output_bytes != 8192
            || usage.units != 1
        {
            return Err("paged custody control differs from its exact finite Admin scope".into());
        }
        Ok(())
    })())
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::finite_grants::{Action, Kind, Selector, Use};
    #[test]
    fn paged_scopes_are_exact_data_not_fallback_dispatch_or_generic_admin_permission() {
        for (command, action, id) in [
            (
                "content-custody-paged-review",
                Action::Read,
                "content-custody-paged-read-v3",
            ),
            (
                "content-custody-paged-bootstrap",
                Action::ProvisionResource,
                "content-custody-paged-bootstrap-v3",
            ),
            (
                "content-custody-paged-reconcile",
                Action::RecoverResource,
                "content-custody-paged-reconcile-v3",
            ),
        ] {
            let usage = Use {
                action,
                selector: Selector {
                    kind: if action == Action::Read {
                        Kind::File
                    } else {
                        Kind::Resource
                    },
                    id: id.into(),
                    generation: 1,
                    digest: "a".repeat(64),
                },
                input_bytes: 0,
                output_bytes: 8192,
                units: 1,
            };
            paged_admin_scope(command, &usage).unwrap().unwrap();
            let mut changed = usage.clone();
            changed.selector.generation += 1;
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.input_bytes = 1;
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.output_bytes -= 1;
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.units += 1;
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.action = if action == Action::Read {
                Action::ProvisionResource
            } else {
                Action::Read
            };
            changed.selector.kind = if action == Action::Read {
                Kind::Resource
            } else {
                Kind::File
            };
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.selector.id.push_str("-extra");
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            changed = usage.clone();
            changed.selector.digest = "0".repeat(64);
            assert!(paged_admin_scope(command, &changed).unwrap().is_err());
            assert!(paged_admin_scope(&format!("{command}-extra"), &usage).is_none());
            assert!(paged_admin_scope("content-unrecognized", &usage).is_none());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Layout {
    Legacy,
    Paged,
}

fn classify(value: Option<&fs::Metadata>, parent: &fs::Metadata) -> Result<Layout> {
    let Some(value) = value else {
        return Ok(Layout::Legacy);
    };
    if !value.is_dir()
        || value.uid() != 0
        || value.mode() & 0o7777 != 0o700
        || value.dev() != parent.dev()
    {
        return Err(
            "invalid paged C namespace; preserve migration evidence, never use legacy fallback"
                .into(),
        );
    }
    Ok(Layout::Paged)
}

/// Observe the exact closed child through the held original C parent. The
/// paged opener must still prove sealed identity, descriptor closure and NV.
pub(super) fn probe(files: &Files, check: &mut impl FnMut() -> Result<()>) -> Result<Layout> {
    check()?;
    let path = files.root.join(PAGED);
    let parent = MemberParent::capture(&path)?;
    parent.check()?;
    let before = parent.file.metadata()?;
    let name = std::ffi::CString::new(PAGED)?;
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let found = unsafe {
        libc::fstatat(
            parent.file.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let (layout, pin): (Layout, Option<File>) = if found == 0 {
        // Opening relative to the retained parent prevents a renamed path or
        // substituted symlink from choosing a different parser.
        let held = parent.open(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let metadata = held.metadata()?;
        if metadata.dev() != status.st_dev
            || metadata.ino() != status.st_ino
            || metadata.mode() != status.st_mode
            || metadata.uid() != status.st_uid
            || metadata.gid() != status.st_gid
        {
            return Err("C format directory changed during selection".into());
        }
        (classify(Some(&metadata), &before)?, Some(held))
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
        (classify(None, &before)?, None)
    };
    check()?;
    parent.check()?;
    if file_identity(&parent.file.metadata()?) != file_identity(&before) {
        return Err("C parent changed during disk-format observation".into());
    }
    match pin {
        Some(held) => {
            let again = parent.open(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            if file_identity(&held.metadata()?) != file_identity(&again.metadata()?) {
                return Err("C format directory changed after observation".into());
            }
        }
        None => {
            let observed = unsafe {
                libc::fstatat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    &mut status,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if observed == 0 {
                return Err("paged migration appeared during legacy format observation".into());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
    }
    check()?;
    Ok(layout)
}

pub(super) fn require_legacy(files: &Files, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    if probe(files, check)? != Layout::Legacy {
        return Err("paged C migration exists; legacy parser and NV publication are fenced".into());
    }
    Ok(())
}
