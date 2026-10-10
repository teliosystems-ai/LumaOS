//! Explicit, grant-governed input namespace provisioning. No DAC capability,
//! arbitrary folder delegation, account creation, or implicit grant issuance.
use crate::{
    artifacts as io,
    finite_grants::{Action, Kind, Selector, Use},
    principal, scoped_read, Result,
};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const BASE: &str = "/var/lib/luma-os/workflow-inputs";

fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permission, id) in entries {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&permission.to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

fn attribute(directory: &File, name: &str, expected: &[u8], set: bool) -> Result<()> {
    let name = CString::new(name)?;
    if set
        && unsafe {
            libc::fsetxattr(
                directory.as_raw_fd(),
                name.as_ptr(),
                expected.as_ptr().cast(),
                expected.len(),
                libc::XATTR_CREATE,
            )
        } != 0
    {
        return Err("input ACL publication uncertain; preserve directory".into());
    }
    let mut observed = vec![0u8; expected.len() + 1];
    let count = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            name.as_ptr(),
            observed.as_mut_ptr().cast(),
            observed.len(),
        )
    };
    if count < 0 || count as usize != expected.len() || observed[..expected.len()] != *expected {
        return Err("input ACL readback differs; preserve directory".into());
    }
    Ok(())
}

fn access(uid: u32) -> Vec<u8> {
    acl(&[
        (1, 7, u32::MAX),
        (2, 7, uid),
        (4, 0, u32::MAX),
        (16, 7, u32::MAX),
        (32, 0, u32::MAX),
    ])
}
fn inherited() -> Vec<u8> {
    // Children remain human-owned. Root gets read/search, not write; the
    // human may deliberately remove this access, which makes admission refuse.
    acl(&[
        (1, 7, u32::MAX),
        (2, 5, 0),
        (4, 0, u32::MAX),
        (16, 5, u32::MAX),
        (32, 0, u32::MAX),
    ])
}

fn validate(directory: &File, uid: u32) -> Result<()> {
    let meta = directory.metadata()?;
    if !meta.is_dir() || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o7777 != 0o770 {
        return Err("input domain ownership or mode differs".into());
    }
    attribute(directory, "system.posix_acl_access", &access(uid), false)?;
    attribute(directory, "system.posix_acl_default", &inherited(), false)
}

fn provision(
    base: &File,
    name: &str,
    uid: u32,
    mut check: impl FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    if !io::hash(name) || uid < 1000 {
        return Err("invalid input namespace identity".into());
    }
    if unsafe { libc::flock(base.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("input namespace provisioning is busy".into());
    }
    let names = io::names(base, 1024)?;
    if names.iter().any(|n| !io::hash(n)) {
        return Err("unknown input domain; preserve state".into());
    }
    let exists = names.iter().any(|n| n == name);
    check()?;
    if !exists {
        if names.len() >= 1024 {
            return Err("input namespace capacity exhausted".into());
        }
        let directory = io::mkdir_at(base, name)?;
        attribute(&directory, "system.posix_acl_access", &access(uid), true)?;
        check()?;
        attribute(&directory, "system.posix_acl_default", &inherited(), true)?;
        directory.sync_all()?;
        base.sync_all()?;
    }
    let directory = io::open_at(base, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    validate(&directory, uid)?;
    check()?;
    let current = io::open_at(base, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?.metadata()?;
    let retained = directory.metadata()?;
    if (current.dev(), current.ino()) != (retained.dev(), retained.ino()) {
        return Err("input namespace replaced during publication".into());
    }
    Ok(
        serde_json::json!({"schema_version":1,"domain":name,"uid":uid,
        "device":retained.dev(),"inode":retained.ino(),"replayed":exists,
        "root_read_only_children":true,"grant_issued":false}),
    )
}

fn proposal(
    login: &str,
) -> Result<(
    principal::RegistryBinding,
    principal::Principal,
    Use,
    String,
)> {
    let (binding, account, installation) = crate::admin_governance::current_principal(login)?;
    if account.uid < 1000 {
        return Err("service account cannot own product inputs".into());
    }
    let digest = io::digest(&serde_json::to_vec(
        &serde_json::json!({"schema_version":1,
        "purpose":"workflow-inputs-provision","installation":installation,
        "principal":account.id,"generation":account.generation,"uid":account.uid,
        "access_acl_sha256":io::digest(&access(account.uid)),"default_acl_sha256":io::digest(&inherited())}),
    )?);
    let usage = Use {
        action: Action::Execute,
        selector: Selector {
            kind: Kind::Workflow,
            id: "workflow-inputs".into(),
            generation: account.generation,
            digest: digest.clone(),
        },
        input_bytes: 0,
        output_bytes: 0,
        units: 1,
    };
    usage.validate()?;
    Ok((binding, account, usage, digest))
}

pub(crate) fn review(login: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let (binding, account, usage, digest) = proposal(login)?;
    binding.current()?;
    println!(
        "{}",
        serde_json::json!({"usage":usage,"review_sha256":digest,
        "root":format!("{BASE}/{}",io::digest(account.id.as_bytes())),"effect_executed":false,"grant_issued":false})
    );
    Ok(())
}

pub(crate) fn initialize(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err("expected workflow-inputs-init LOGIN EXECUTE-GRANT REVIEW-SHA256".into());
    }
    crate::require_root()?;
    crate::platform::require_installed()?;
    let (binding, account, usage, review) = proposal(&args[1])?;
    if args[3] != review {
        return Err("input namespace review changed".into());
    }
    let base = scoped_read::open_directory(Path::new(BASE))?;
    crate::artifact_catalog::safe_path(Path::new(BASE))?;
    crate::artifact_catalog::ext4(&base)?;
    let meta = base.metadata()?;
    if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o7777 != 0o711 {
        return Err("input namespace base must be protected mode0711".into());
    }
    let result = crate::admin_governance::with_grant(&args[1], &args[2], &usage, |boundary| {
        let pending = boundary.effect_begin(
            "workflow-inputs",
            crate::policy_decisions::EffectKind::Checkpoint,
        )?;
        let result = provision(
            &base,
            &io::digest(account.id.as_bytes()),
            account.uid,
            || {
                boundary.check()?;
                binding.current()?;
                if boundary.subject()? != account.id
                    || boundary.subject_generation()? != account.generation
                    || boundary.subject_uid()? != account.uid
                {
                    return Err("input namespace grant subject changed".into());
                }
                Ok(())
            },
        )?;
        boundary.effect_complete(pending, &io::digest(&serde_json::to_vec(&result)?))?;
        Ok(result)
    })?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::process::CommandExt;

    fn no_capabilities() -> std::io::Result<()> {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        // Confined child only: retain UID0 to test the named root ACL while
        // removing every possible DAC bypass and exec-time capability regain.
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for capability in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINVAL) {
                        return Err(error);
                    }
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let data = [
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[test]
    fn real_acl_provisioning_replays_exactly_and_preserves_partial_or_damaged_directories() {
        let path = std::env::temp_dir().join(format!("luma-input-acl-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let base = scoped_read::open_directory(&path).unwrap();
        let name = "a".repeat(64);
        let first = provision(&base, &name, 1001, || Ok(())).unwrap();
        assert_eq!(first["replayed"], false);
        let second = provision(&base, &name, 1001, || Ok(())).unwrap();
        assert_eq!(second["replayed"], true);
        assert_eq!(first["inode"], second["inode"]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).unwrap();
        let domain = path.join(&name);
        let child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import os,sys; os.umask(0);\nfor name,mode in [('normal.csv',0o666),('restrictive.csv',0o600)]:\n f=os.open(sys.argv[1]+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode); os.write(f,b'value\\n'); os.close(f)"])
            .arg(&domain)
            .uid(1001).gid(1001).env_clear().output().unwrap();
        assert!(
            child.status.success(),
            "human input creation refused: {:?}",
            child.status
        );
        let normal = domain.join("normal.csv");
        let restrictive = domain.join("restrictive.csv");
        assert_eq!(fs::metadata(&normal).unwrap().uid(), 1001);
        assert_eq!(fs::metadata(&normal).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(&restrictive).unwrap().uid(), 1001);
        // A caller's restrictive creation mode can remove the inherited mask:
        // that is a refusal, not permission for the runtime to bypass DAC.
        assert_eq!(fs::metadata(&restrictive).unwrap().mode() & 0o777, 0o600);
        let mut reader = std::process::Command::new("/usr/bin/python3");
        reader.args(["-I", "-c", "import os,sys; assert os.geteuid()==0; status=dict(line.split(':',1) for line in open('/proc/self/status'));\nfor key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']: assert int(status[key].strip(),16)==0,(key,status[key]);\nassert int(status['NoNewPrivs'])==1; assert open(sys.argv[1]+'/normal.csv','rb').read()==b'value\\n';\ntry:\n open(sys.argv[1]+'/restrictive.csv','rb')\nexcept PermissionError:\n pass\nelse:\n raise AssertionError('restrictive ACL was bypassed')"])
            .arg(&domain).uid(0).gid(0).env_clear();
        unsafe {
            reader.pre_exec(no_capabilities);
        }
        let readback = reader.output().unwrap();
        assert!(
            readback.status.success(),
            "capability-free root ACL readback refused: {}",
            String::from_utf8_lossy(&readback.stderr)
        );
        let stranger = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import os,sys;\nfor operation in [lambda: os.listdir(sys.argv[1]),lambda: open(sys.argv[1]+'/normal.csv','rb'),lambda: open(sys.argv[1]+'/restrictive.csv','rb')]:\n try:\n  operation()\n except PermissionError:\n  pass\n else:\n  raise AssertionError('another principal accessed input domain')"])
            .arg(&domain)
            .uid(1002)
            .gid(1002)
            .env_clear()
            .output()
            .unwrap();
        assert!(
            stranger.status.success(),
            "cross-principal input ACL refusal failed: {}",
            String::from_utf8_lossy(&stranger.stderr)
        );
        assert!(provision(&base, &name, 1002, || Ok(())).is_err());
        fs::set_permissions(path.join(&name), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(provision(&base, &name, 1001, || Ok(())).is_err());
        let partial = "b".repeat(64);
        io::mkdir_at(&base, &partial).unwrap();
        assert!(provision(&base, &partial, 1001, || Ok(())).is_err());
        drop(base);
        fs::remove_dir_all(path).unwrap();
    }
}
