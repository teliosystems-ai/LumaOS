//! Current kernel credentials and fixed confinement are part of a live peer
//! generation. Connection-time SO_PEERCRED alone is not a current-UID proof.
use super::*;

const STATUS_BYTES: u64 = 65_536;

fn field<'a>(status: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}:");
    let mut lines = status.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = lines.next().ok_or("missing kernel credential field")?;
    if lines.next().is_some() {
        return Err("ambiguous kernel credential field".into());
    }
    Ok(value.trim())
}

fn uid_status(status: &str, uid: u32) -> Result<()> {
    let values: Vec<_> = field(status, "Uid")?.split_whitespace().collect();
    if values.len() != 4
        || values.iter().any(|value| {
            number(value).map_or(true, |actual| {
                actual != u64::from(uid) || actual.to_string() != *value
            })
        })
    {
        return Err("peer current real/effective/saved/filesystem credentials differ".into());
    }
    Ok(())
}

fn capabilities(status: &str, name: &str, expected: u64) -> Result<()> {
    let value = field(status, name)?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || u64::from_str_radix(value, 16)? != expected
    {
        return Err("worker capabilities differ from the fixed native plan".into());
    }
    Ok(())
}

fn confined_status(status: &str, uid: u32, mask: u64) -> Result<()> {
    uid_status(status, uid)?;
    if field(status, "NoNewPrivs")? != "1" || field(status, "Seccomp")? != "2" {
        return Err("worker privilege/filter enforcement unavailable".into());
    }
    for name in ["CapPrm", "CapEff", "CapBnd"] {
        capabilities(status, name, mask)?;
    }
    for name in ["CapInh", "CapAmb"] {
        capabilities(status, name, 0)?;
    }
    Ok(())
}

fn worker_status(status: &str, kind: Kind, uid: u32) -> Result<()> {
    // The root acquisition supervisor retains only credential-drop and owned
    // child termination capabilities; its UID-988 child is a separate process.
    let mask = match kind {
        Kind::Model => 0,
        Kind::Acquisition => (1u64 << 7) | (1u64 << 6) | (1u64 << 5),
    };
    confined_status(status, uid, mask)
}

fn generated_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "generated-resource-worker"
        || !parts[3].is_empty()
        || crate::generated_runtime::source_digest(parts[2]).is_err()
    {
        return Err("extra capability is restricted to the exact generated supervisor".into());
    }
    confined_status(
        status,
        uid,
        (1u64 << 7) | (1u64 << 6) | (1u64 << 5) | (1u64 << 8),
    )
}

fn qa_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "model-qa-worker"
        || !parts[4].is_empty()
        || crate::model::qa::parse_profile(parts[2]).is_err()
        || crate::tpm::decode::<16>(parts[3]).is_err()
    {
        return Err(
            "QA observation capabilities require the exact isolated supervisor command".into(),
        );
    }
    confined_status(
        status,
        uid,
        (1u64 << 0) | (1u64 << 7) | (1u64 << 6) | (1u64 << 5) | (1u64 << 8) | (1u64 << 19),
    )
}

fn backup_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if uid != 0
        || parts.len() != 4
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "content-backup-resource-worker"
        || !parts[3].is_empty()
        || crate::content_backup::source_digest(parts[2]).is_err()
    {
        return Err("locked backup memory requires the exact capability-free export worker".into());
    }
    confined_status(status, uid, 0)
}

fn office_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if uid != 0
        || parts.len() != 4
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "content-office-resource-worker"
        || !parts[3].is_empty()
        || crate::office_export::source_digest(parts[2]).is_err()
    {
        return Err(
            "Office credential-drop capabilities require its exact fixed export supervisor".into(),
        );
    }
    confined_status(
        status,
        uid,
        (1u64 << 0) | (1u64 << 7) | (1u64 << 6) | (1u64 << 5),
    )
}

fn restore_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if uid != 0
        || parts.len() != 5
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "content-restore-resource-worker"
        || crate::content_restore::source_digest(parts[2]).is_err()
        || !parts[4].is_empty()
    {
        return Err("restore requires exact capability-free worker and staged request".into());
    }
    let suffix = parts[3]
        .strip_prefix("/run/luma-granted-client/requests/")
        .and_then(|s| s.strip_suffix("/content-restore.json"))
        .ok_or("restore request is outside fixed original-client staging")?;
    crate::tpm::decode::<16>(suffix)?;
    confined_status(status, uid, 0)
}

fn content_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if uid != 0
        || parts.len() != 4
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || !parts[3].is_empty()
        || match parts[1] {
            "content-resource-worker" => crate::content_governed::source_digest(parts[2]).is_err(),
            "index-resource-worker" => {
                crate::content_index::request::parse_profile(parts[2]).is_err()
            }
            _ => true,
        }
    {
        return Err("zero-capability content admission requires the exact governed worker".into());
    }
    confined_status(status, uid, 0)
}
fn editor_status(status: &str, uid: u32, cmdline: &str) -> Result<()> {
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if uid != 0
        || parts.len() != 4
        || parts[0] != "/usr/libexec/luma-os/luma-platform"
        || parts[1] != "editor-resource-worker"
        || !parts[3].is_empty()
        || crate::editor_session::source_digest(parts[2]).is_err()
    {
        return Err("editor admission requires its exact capability-free fixed worker".into());
    }
    confined_status(status, uid, 0)
}

fn locked_memory(limits: &str) -> Result<()> {
    locked_memory_bound(limits, 0)
}

fn locked_memory_bound(limits: &str, expected: u64) -> Result<()> {
    let mut lines = limits
        .lines()
        .filter(|line| line.starts_with("Max locked memory"));
    let line = lines.next().ok_or("missing pinned-memory ceiling")?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if lines.next().is_some()
        || fields.len() != 6
        || fields[3] != expected.to_string()
        || fields[4] != expected.to_string()
        || fields[5] != "bytes"
    {
        return Err("worker pinned memory differs from its exact execution ceiling".into());
    }
    Ok(())
}

pub(super) fn worker_generation(
    kind: Kind,
    uid: u32,
    mut read: impl FnMut(&str, u64) -> Result<String>,
) -> Result<u64> {
    if Kind::peer(uid)? != kind {
        return Err("worker UID does not match the fixed execution domain".into());
    }
    let start = start_ticks(&read("stat", 4096)?)?;
    let initial_profile = read("attr/current", 128)?;
    let qa = kind == Kind::Acquisition && initial_profile == "luma-qa-supervisor (enforce)\n";
    let backup = kind == Kind::Acquisition && initial_profile == "luma-content-backup (enforce)\n";
    let office = kind == Kind::Acquisition && initial_profile == "luma-office-export (enforce)\n";
    let restore =
        kind == Kind::Acquisition && initial_profile == "luma-content-restore (enforce)\n";
    let editor = kind == Kind::Acquisition && initial_profile == "luma-editor (enforce)\n";
    let normal = match kind {
        Kind::Model => "luma-model (enforce)\n",
        Kind::Acquisition => "luma-acquisition (enforce)\n",
    };
    if !qa && !backup && !office && !restore && !editor && initial_profile != normal {
        return Err("initial worker confinement observation is unsupported or changed".into());
    }
    let profile = if editor {
        "luma-editor (enforce)\n"
    } else if restore {
        "luma-content-restore (enforce)\n"
    } else if office {
        "luma-office-export (enforce)\n"
    } else if backup {
        "luma-content-backup (enforce)\n"
    } else if qa {
        "luma-qa-supervisor (enforce)\n"
    } else {
        match kind {
            Kind::Model => "luma-model (enforce)\n",
            Kind::Acquisition => "luma-acquisition (enforce)\n",
        }
    };
    for _ in 0..2 {
        if read("cgroup", 4096)? != format!("0::{}\n", kind.leaf())
            || read("attr/current", 128)? != profile
        {
            return Err("worker group or enforcing AppArmor generation differs".into());
        }
        let status = read("status", STATUS_BYTES)?;
        if editor {
            editor_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if restore {
            restore_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if office {
            office_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if backup {
            backup_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if qa {
            qa_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if kind == Kind::Acquisition && field(&status, "CapBnd")? == "00000000000001e0" {
            generated_status(&status, uid, &read("cmdline", 4096)?)?;
        } else if kind == Kind::Acquisition && field(&status, "CapBnd")? == "0000000000000000" {
            content_status(&status, uid, &read("cmdline", 4096)?)?;
        } else {
            worker_status(&status, kind, uid)?;
        }
        if restore {
            locked_memory_bound(&read("limits", 8192)?, crate::content_restore::LOCKED)?;
        } else if backup {
            locked_memory_bound(&read("limits", 8192)?, crate::content_backup::LOCKED)?;
        } else {
            locked_memory(&read("limits", 8192)?)?;
        }
        if start_ticks(&read("stat", 4096)?)? != start {
            return Err("worker process generation changed during observation".into());
        }
    }
    Ok(start)
}

fn reference_generation(mut read: impl FnMut(&str, u64) -> Result<String>) -> Result<u64> {
    let start = start_ticks(&read("stat", 4096)?)?;
    for _ in 0..2 {
        if read("cgroup", 4096)? != "0::/system.slice/luma-reference.service\n"
            || read("attr/current", 128)? != "luma-reference (enforce)\n"
        {
            return Err("reference caller group or enforcing AppArmor generation differs".into());
        }
        confined_status(&read("status", STATUS_BYTES)?, 990, 0)?;
        locked_memory(&read("limits", 8192)?)?;
        if start_ticks(&read("stat", 4096)?)? != start {
            return Err("reference caller process generation changed during observation".into());
        }
    }
    Ok(start)
}

pub(super) fn custody_generation(mut read: impl FnMut(&str, u64) -> Result<String>) -> Result<u64> {
    let start = start_ticks(&read("stat", 4096)?)?;
    for _ in 0..2 {
        if read("cgroup", 4096)? != format!("0::{}\n", CUSTODY_LEAF)
            || read("attr/current", 128)? != "luma-content-custody (enforce)\n"
            || read("cmdline", 4096)?
                != "/usr/libexec/luma-os/luma-platform\0content-custody-service\0"
        {
            return Err("content custody guard caller is not the fixed enforcing service".into());
        }
        confined_status(&read("status", STATUS_BYTES)?, 0, 0)?;
        locked_memory_bound(&read("limits", 8192)?, 96 * 1024 * 1024)?;
        if start_ticks(&read("stat", 4096)?)? != start {
            return Err("content custody service generation changed".into());
        }
    }
    Ok(start)
}

pub(super) fn live_generation(peer: libc::ucred, pin: &File) -> Result<(u64, String)> {
    if peer.pid <= 0 || !pidfd_alive(pin)? {
        return Err("peer process handle is no longer live".into());
    }
    let handle = safe_text(
        &Path::new("/proc/self/fdinfo").join(pin.as_raw_fd().to_string()),
        4096,
    )?;
    if field(&handle, "Pid")? != peer.pid.to_string() {
        return Err("peer process handle does not bind the asserted process".into());
    }
    let path = Path::new("/proc").join(peer.pid.to_string());
    let start = if peer.uid == 990 {
        reference_generation(|member, maximum| safe_text(&path.join(member), maximum))?
    } else {
        start_ticks(&safe_text(&path.join("stat"), 4096)?)?
    };
    uid_status(&safe_text(&path.join("status"), STATUS_BYTES)?, peer.uid)?;
    let boot = boot_identity()?;
    if !pidfd_alive(pin)?
        || start_ticks(&safe_text(&path.join("stat"), 4096)?)? != start
        || fs::metadata(&path)?.uid() != peer.uid
    {
        return Err("peer generation changed during credential observation".into());
    }
    uid_status(&safe_text(&path.join("status"), STATUS_BYTES)?, peer.uid)?;
    if peer.uid == 990
        && reference_generation(|member, maximum| safe_text(&path.join(member), maximum))? != start
    {
        return Err("reference caller confinement changed before acknowledgement".into());
    }
    if !pidfd_alive(pin)? {
        return Err("peer exited during credential observation".into());
    }
    Ok((start, boot))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum HardwareCommand {
    Console,
    Cleanup(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HardwarePeer {
    pub pid: u32,
    pub start: u64,
    pub boot: String,
    pub unit: String,
    pub command: HardwareCommand,
}
pub(super) fn hardware_generation(peer: libc::ucred, pin: &File) -> Result<HardwarePeer> {
    if peer.uid != 0 || peer.gid != 0 {
        return Err("hardware handoff requires its capability-free root controller".into());
    }
    let (start, boot) = live_generation(peer, pin)?;
    let process = Path::new("/proc").join(peer.pid.to_string());
    let cgroup = safe_text(&process.join("cgroup"), 4096)?;
    let unit = cgroup
        .strip_prefix("0::/system.slice/luma-hardware-")
        .and_then(|value| value.strip_suffix(".service\n"))
        .ok_or("hardware caller is not a fixed transient hardware unit")?;
    if crate::tpm::decode::<16>(unit)? == [0; 16] {
        return Err("hardware unit identity is zero".into());
    }
    let unit = format!("luma-hardware-{unit}.service");
    let cmdline = safe_text(&process.join("cmdline"), 4096)?;
    let parts = cmdline.split('\0').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "/usr/libexec/luma-os/luma-platform" || !parts[3].is_empty()
    {
        return Err("hardware process is not its fixed native console/cleanup entrypoint".into());
    }
    let command = match parts[1] {
        "hardware-console"
            if parts[2].len() <= 32
                && !parts[2].is_empty()
                && parts[2].as_bytes()[0].is_ascii_lowercase()
                && parts[2].bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                }) =>
        {
            HardwareCommand::Console
        }
        "hardware-cleanup" if crate::admin_roles::identifier(parts[2]) => {
            HardwareCommand::Cleanup(parts[2].into())
        }
        _ => return Err("hardware process arguments exceed the closed native entrypoint".into()),
    };
    let executable = fs::metadata(process.join("exe"))?;
    let installed = fs::symlink_metadata("/usr/libexec/luma-os/luma-platform")?;
    if executable.dev() != installed.dev()
        || executable.ino() != installed.ino()
        || !installed.is_file()
        || installed.uid() != 0
        || installed.mode() & 0o022 != 0
    {
        return Err("hardware controller is not the immutable installed native binary".into());
    }
    for _ in 0..2 {
        confined_status(&safe_text(&process.join("status"), STATUS_BYTES)?, 0, 0)?;
        locked_memory_bound(&safe_text(&process.join("limits"), 8192)?, 262_144)?;
        let group = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
        if safe_text(&process.join("attr/current"), 128)? != "luma-hardware (enforce)\n"
            || safe_text(&process.join("cgroup"), 4096)? != cgroup
            || safe_text(&process.join("cmdline"), 4096)? != cmdline
            || number(&safe_text(&group.join("memory.max"), 64)?)? != 268_435_456
            || number(&safe_text(&group.join("memory.swap.max"), 64)?)? != 0
            || number(&safe_text(&group.join("pids.max"), 64)?)? != 16
            || live_generation(peer, pin)? != (start, boot.clone())
        {
            return Err("hardware controller lost its fixed process/confinement generation".into());
        }
    }
    Ok(HardwarePeer {
        pid: peer.pid.try_into()?,
        start,
        boot,
        unit,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn editor_status_requires_actual_capability_free_fixed_command_and_no_content_impersonation() {
        let selected = format!("{}{}", crate::editor_session::PREFIX, "1".repeat(64));
        let exact =
            format!("/usr/libexec/luma-os/luma-platform\0editor-resource-worker\0{selected}\0");
        let status = status(Kind::Model, 0);
        editor_status(&status, 0, &exact).unwrap();
        for command in [
            exact.replace("editor-resource-worker", "content-resource-worker"),
            format!("{exact}extra\0"),
            exact.replace(&selected, "qwen3-4b-q4-k-m"),
        ] {
            assert!(editor_status(&status, 0, &command).is_err());
        }
        assert!(editor_status(&status, 988, &exact).is_err());
        assert!(editor_status(&status.replace("Seccomp:\t2", "Seccomp:\t0"), 0, &exact).is_err());
    }
    #[test]
    fn capability_free_content_worker_cannot_borrow_model_or_generic_acquisition_identity() {
        let status = status(Kind::Model, 0);
        let id = format!("content-v1-write-1-{}-{}", "a".repeat(64), "b".repeat(64));
        let exact = format!("/usr/libexec/luma-os/luma-platform\0content-resource-worker\0{id}\0");
        content_status(&status, 0, &exact).unwrap();
        for invalid in [
            exact.replace("content-resource-worker", "model-acquisition-worker"),
            exact.replace("/usr/libexec/luma-os/luma-platform", "/tmp/luma-platform"),
            format!("{exact}extra\0"),
            exact.replace("content-v1-write-1", "content-v1-write-0"),
            exact.trim_end_matches('\0').to_string(),
        ] {
            assert!(content_status(&status, 0, &invalid).is_err());
        }
        assert!(content_status(
            &status.replace("0000000000000000", "00000000000000e0"),
            0,
            &exact
        )
        .is_err());
        assert!(content_status(&status, 988, &exact).is_err());
    }
    #[test]
    fn capability_free_index_worker_requires_exact_profile_and_cannot_borrow_content_identity() {
        let status = status(Kind::Model, 0);
        for mode in [
            "review", "status", "query", "start", "step", "advance", "publish", "retain",
        ] {
            let selected = format!("index-v2-{mode}-7-{}-{}", "a".repeat(64), "a".repeat(64));
            let exact =
                format!("/usr/libexec/luma-os/luma-platform\0index-resource-worker\0{selected}\0");
            content_status(&status, 0, &exact).unwrap();
            for invalid in [
                exact.replace("index-resource-worker", "content-resource-worker"),
                exact.replace("index-resource-worker", "model-acquisition-worker"),
                exact.replace("/usr/libexec/luma-os/luma-platform", "/tmp/luma-platform"),
                exact.replace("-7-", "-07-"),
                format!("{exact}extra\0"),
                exact.trim_end_matches('\0').to_owned(),
            ] {
                assert!(content_status(&status, 0, &invalid).is_err());
            }
            assert!(content_status(&status, 988, &exact).is_err());
            assert!(
                content_status(&status.replace("Seccomp:\t2", "Seccomp:\t0"), 0, &exact).is_err()
            );
            assert!(content_status(
                &status.replace("0000000000000000", "00000000000000e0"),
                0,
                &exact
            )
            .is_err());
        }
    }
    #[test]
    fn generated_extra_capability_requires_exact_closed_supervisor_argv() {
        let status = status(Kind::Acquisition, 0).replace("00000000000000e0", "00000000000001e0");
        let profile = format!("generated-v1-{}", "a".repeat(64));
        let exact =
            format!("/usr/libexec/luma-os/luma-platform\0generated-resource-worker\0{profile}\0");
        generated_status(&status, 0, &exact).unwrap();
        for altered in [
            exact.replace("generated-resource-worker", "model-acquisition-worker"),
            exact.replace("/usr/libexec/luma-os/luma-platform", "/tmp/luma-platform"),
            format!("{exact}extra\0"),
            exact.trim_end_matches('\0').to_owned(),
            exact.replace(&profile, "generated-v1-invalid"),
        ] {
            assert!(generated_status(&status, 0, &altered).is_err());
        }
        assert!(worker_status(&status, Kind::Acquisition, 0).is_err());
        assert!(generated_status(&status, 989, &exact).is_err());
    }

    fn status(kind: Kind, uid: u32) -> String {
        let mask = if kind == Kind::Model { 0 } else { 0xe0 };
        format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapInh:\t0000000000000000\nCapPrm:\t{mask:016x}\nCapEff:\t{mask:016x}\nCapBnd:\t{mask:016x}\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
    }

    fn stat(start: u64) -> String {
        format!("10 (worker) S {} {start}\n", vec!["0"; 18].join(" "))
    }

    fn observe(
        kind: Kind,
        uid: u32,
        mut mutate: impl FnMut(&str, usize, &mut String),
    ) -> Result<u64> {
        let mut counts = BTreeMap::<String, usize>::new();
        worker_generation(kind, uid, |name, maximum| {
            let mut value = match name {
                "stat" => stat(7),
                "status" => status(kind, uid),
                "cgroup" => format!("0::{}\n", kind.leaf()),
                "attr/current" => match kind {
                    Kind::Model => "luma-model (enforce)\n".into(),
                    Kind::Acquisition => "luma-acquisition (enforce)\n".into(),
                },
                "limits" => {
                    "Max locked memory         0                    0                    bytes\n"
                        .into()
                }
                _ => panic!("unexpected observation"),
            };
            let count = counts.entry(name.into()).or_default();
            mutate(name, *count, &mut value);
            *count += 1;
            assert!(value.len() as u64 <= maximum);
            Ok(value)
        })
    }

    fn reference(mut mutate: impl FnMut(&str, usize, &mut String)) -> Result<u64> {
        let mut counts = BTreeMap::<String, usize>::new();
        reference_generation(|name, maximum| {
            let mut value = match name {
                "stat" => stat(7),
                "status" => status(Kind::Model, 990),
                "cgroup" => "0::/system.slice/luma-reference.service\n".into(),
                "attr/current" => "luma-reference (enforce)\n".into(),
                "limits" => "Max locked memory 0 0 bytes\n".into(),
                _ => panic!("unexpected reference observation"),
            };
            let count = counts.entry(name.into()).or_default();
            mutate(name, *count, &mut value);
            *count += 1;
            assert!(value.len() as u64 <= maximum);
            Ok(value)
        })
    }

    fn backup(mut mutate: impl FnMut(&str, usize, &mut String)) -> Result<u64> {
        let mut counts = BTreeMap::<String, usize>::new();
        let id = format!("backup-export-v1-7-4096-{}", "a".repeat(64));
        worker_generation(Kind::Acquisition, 0, |name, maximum| {
            let mut value = match name {
                "stat" => stat(7),
                "status" => status(Kind::Model, 0),
                "cgroup" => format!("0::{}\n", Kind::Acquisition.leaf()),
                "attr/current" => "luma-content-backup (enforce)\n".into(),
                "cmdline" => format!(
                    "/usr/libexec/luma-os/luma-platform\0content-backup-resource-worker\0{id}\0"
                ),
                "limits" => format!(
                    "Max locked memory {} {} bytes\n",
                    crate::content_backup::LOCKED,
                    crate::content_backup::LOCKED
                ),
                _ => panic!("unexpected backup kernel observation"),
            };
            let count = counts.entry(name.into()).or_default();
            mutate(name, *count, &mut value);
            *count += 1;
            assert!(value.len() as u64 <= maximum);
            Ok(value)
        })
    }

    fn restore(mut mutate: impl FnMut(&str, usize, &mut String)) -> Result<u64> {
        let mut counts = BTreeMap::<String, usize>::new();
        let id = format!("content-restore-v1-r-7-8-4096-0-{}", "a".repeat(64));
        let stage = format!(
            "/run/luma-granted-client/requests/{}/content-restore.json",
            "b".repeat(32)
        );
        worker_generation(Kind::Acquisition, 0, |name, maximum| {
            let mut value = match name {
                "stat" => stat(7),
                "status" => status(Kind::Model, 0),
                "cgroup" => format!("0::{}\n", Kind::Acquisition.leaf()),
                "attr/current" => "luma-content-restore (enforce)\n".into(),
                "cmdline" => format!("/usr/libexec/luma-os/luma-platform\0content-restore-resource-worker\0{id}\0{stage}\0"),
                "limits" => format!("Max locked memory {} {} bytes\n", crate::content_restore::LOCKED, crate::content_restore::LOCKED),
                _ => panic!("unexpected restore kernel observation"),
            };
            let count = counts.entry(name.into()).or_default();
            mutate(name, *count, &mut value);
            *count += 1;
            assert!(value.len() as u64 <= maximum);
            Ok(value)
        })
    }

    #[test]
    fn restore_private_key_budget_requires_exact_worker_stage_and_continuously_pinned_generation() {
        assert_eq!(restore(|_, _, _| ()).unwrap(), 7);
        let id = format!("content-restore-v1-r-7-8-4096-0-{}", "a".repeat(64));
        let stage = format!(
            "/run/luma-granted-client/requests/{}/content-restore.json",
            "b".repeat(32)
        );
        let exact = format!(
            "/usr/libexec/luma-os/luma-platform\0content-restore-resource-worker\0{id}\0{stage}\0"
        );
        for changed in [
            exact.replace("content-restore-resource-worker", "content-resource-worker"),
            exact.replace("/usr/libexec/luma-os/luma-platform", "/tmp/luma-platform"),
            exact.replace(&stage, "/tmp/content-restore.json"),
            exact.replace("content-restore.json", "content-restore.cms"),
            exact.replace(&"b".repeat(32), &"b".repeat(31)),
            format!("{exact}private-key-path\0"),
            exact.trim_end_matches('\0').into(),
        ] {
            assert!(restore_status(&status(Kind::Model, 0), 0, &changed).is_err());
        }
        assert!(restore_status(&status(Kind::Acquisition, 0), 0, &exact).is_err());
        assert!(restore_status(&status(Kind::Model, 989), 989, &exact).is_err());
        for (name, changed) in [
            ("attr/current", "luma-content-restore (complain)\n".into()),
            ("status", status(Kind::Acquisition, 0)),
            ("limits", "Max locked memory 0 0 bytes\n".into()),
            (
                "cmdline",
                exact.replace("content-restore.json", "arbitrary.json"),
            ),
            (
                "cgroup",
                "0::/other.slice/luma-acquisition.service\n".into(),
            ),
        ] {
            for round in 0..2 {
                assert!(
                    restore(|field, observed, value| {
                        if field == name && observed == round {
                            *value = changed.clone();
                        }
                    })
                    .is_err(),
                    "{name} round {round}"
                );
            }
        }
        assert!(restore(|name, observed, value| {
            if name == "stat" && observed > 0 {
                *value = stat(8);
            }
        })
        .is_err());
    }

    #[test]
    fn backup_locked_memory_is_exclusive_to_exact_zero_capability_export_worker() {
        assert_eq!(backup(|_, _, _| ()).unwrap(), 7);
        let limit = crate::content_backup::LOCKED;
        assert!(observe(Kind::Acquisition, 0, |name, _, value| {
            if name == "limits" {
                *value = format!("Max locked memory {limit} {limit} bytes\n");
            }
        })
        .is_err());
        let id = format!("backup-export-v1-7-4096-{}", "a".repeat(64));
        let exact =
            format!("/usr/libexec/luma-os/luma-platform\0content-backup-resource-worker\0{id}\0");
        for changed in [
            exact.replace("content-backup-resource-worker", "content-resource-worker"),
            exact.replace("content-backup-resource-worker", "luma-backup-crypto"),
            exact.replace("/usr/libexec/luma-os/luma-platform", "/tmp/luma-platform"),
            exact.replace(&id, "backup-export-v1-7-0-invalid"),
            exact.trim_end_matches('\0').into(),
            format!("{exact}extra\0"),
        ] {
            assert!(backup_status(&status(Kind::Model, 0), 0, &changed).is_err());
        }
        assert!(backup_status(&status(Kind::Acquisition, 0), 0, &exact).is_err());
        assert!(backup_status(&status(Kind::Model, 989), 989, &exact).is_err());
        for (name, changed) in [
            ("attr/current", "luma-content-backup (complain)\n".into()),
            ("attr/current", "luma-acquisition (enforce)\n".into()),
            ("status", status(Kind::Acquisition, 0)),
            ("limits", "Max locked memory 0 0 bytes\n".into()),
            ("limits", format!("Max locked memory {limit} {} bytes\n", limit + 1)),
            ("limits", format!("Max locked memory 0{limit} {limit} bytes\n")),
            ("limits", format!("Max locked memory {limit} {limit} bytes\nMax locked memory {limit} {limit} bytes\n")),
            ("cgroup", "0::/other.slice/luma-acquisition.service\n".into()),
        ] {
            for round in 0..2 {
                assert!(backup(|field, count, value| {
                    if field == name && count == round { *value = changed.clone(); }
                }).is_err(), "{name} round {round}");
            }
        }
        for round in 0..2 {
            assert!(backup(|field, count, value| {
                if field == "cmdline" && count == round {
                    *value = format!("{exact}extra\0");
                }
            })
            .is_err());
        }
    }

    #[test]
    fn reference_uid_alone_never_substitutes_for_the_installed_confined_service() {
        assert_eq!(reference(|_, _, _| ()).unwrap(), 7);
        for (field, value) in [
            ("cgroup", "0::/user.slice/reference.service\n"),
            (
                "cgroup",
                "0::/system.slice/luma-reference.service/descendant\n",
            ),
            (
                "cgroup",
                "0::/system.slice/luma-reference.service\n1:cpu:/other\n",
            ),
            ("attr/current", "unconfined\n"),
            ("attr/current", "luma-reference (complain)\n"),
            ("attr/current", "luma-reference//&another (enforce)\n"),
            ("limits", "Max locked memory 0 1 bytes\n"),
        ] {
            for round in 0..2 {
                assert!(
                    reference(|name, count, observed| {
                        if name == field && count == round {
                            *observed = value.into();
                        }
                    })
                    .is_err(),
                    "{field} round {round}"
                );
            }
        }
        for field in [
            "Uid",
            "NoNewPrivs",
            "Seccomp",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapInh",
            "CapAmb",
        ] {
            let original = status(Kind::Model, 990);
            let changed = original
                .lines()
                .map(|line| {
                    if line.starts_with(&format!("{field}:")) {
                        format!("{field}: unavailable")
                    } else {
                        line.into()
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");
            for round in 0..2 {
                assert!(reference(|name, count, observed| {
                    if name == "status" && count == round {
                        *observed = changed.clone();
                    }
                })
                .is_err());
            }
        }
        for round in 1..3 {
            assert!(reference(|name, count, observed| {
                if name == "stat" && count == round {
                    *observed = stat(8);
                }
            })
            .is_err());
        }
    }

    #[test]
    fn missing_reference_kernel_observations_never_accept_partial_confinement() {
        for missing in ["stat", "status", "cgroup", "attr/current", "limits"] {
            let result = reference_generation(|field, _| {
                if field == missing {
                    return Err("trusted kernel observation missing".into());
                }
                Ok(match field {
                    "stat" => stat(7),
                    "status" => status(Kind::Model, 990),
                    "cgroup" => "0::/system.slice/luma-reference.service\n".into(),
                    "attr/current" => "luma-reference (enforce)\n".into(),
                    "limits" => "Max locked memory 0 0 bytes\n".into(),
                    _ => panic!("unexpected observation"),
                })
            });
            assert!(result.is_err(), "missing {missing}");
        }
    }

    #[test]
    fn real_live_reference_uid_outside_its_service_is_refused() {
        use std::os::unix::process::CommandExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .uid(990)
            .gid(990)
            .spawn()
            .unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(raw >= 0);
        let pin = unsafe { File::from_raw_fd(raw as i32) };
        let result = live_generation(
            libc::ucred {
                pid: child.id() as i32,
                uid: 990,
                gid: 990,
            },
            &pin,
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn both_fixed_worker_plans_require_exact_current_enforcement() {
        for (kind, uid) in [(Kind::Model, 989), (Kind::Acquisition, 0)] {
            assert_eq!(observe(kind, uid, |_, _, _| {}).unwrap(), 7);
            for (name, changed) in [
                ("attr/current", "unconfined\n"),
                ("attr/current", "luma-model (complain)\n"),
                ("attr/current", "luma-acquisition (complain)\n"),
                ("attr/current", "luma-model//&other (enforce)\n"),
                ("cgroup", "0::/other.service\n"),
                ("limits", "Max locked memory 0 1 bytes\n"),
                (
                    "limits",
                    "Max locked memory 0 0 bytes\nMax locked memory 0 0 bytes\n",
                ),
            ] {
                assert!(
                    observe(kind, uid, |field, _, value| {
                        if field == name {
                            *value = changed.into();
                        }
                    })
                    .is_err(),
                    "{kind:?}: {name}={changed}"
                );
            }
        }
        assert!(worker_generation(Kind::Model, 0, |_, _| panic!("wrong domain")).is_err());
    }

    #[test]
    fn changed_or_ambiguous_kernel_uid_and_privilege_fields_refuse() {
        for (kind, uid) in [(Kind::Model, 989), (Kind::Acquisition, 0)] {
            let original = status(kind, uid);
            for name in [
                "Uid",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
                "NoNewPrivs",
                "Seccomp",
            ] {
                let line = original
                    .lines()
                    .find(|line| line.starts_with(&format!("{name}:")))
                    .unwrap();
                let removed = original.replace(&format!("{line}\n"), "");
                assert!(worker_status(&removed, kind, uid).is_err());
                let duplicate = format!("{original}{line}\n");
                assert!(worker_status(&duplicate, kind, uid).is_err());
                let altered = original.replace(line, &format!("{name}: invalid"));
                assert!(worker_status(&altered, kind, uid).is_err());
            }
            for nnp in ["0", "2", "01"] {
                assert!(worker_status(
                    &original.replace("NoNewPrivs:\t1", &format!("NoNewPrivs:\t{nnp}")),
                    kind,
                    uid
                )
                .is_err());
            }
            for seccomp in ["0", "1", "3", "02"] {
                assert!(worker_status(
                    &original.replace("Seccomp:\t2", &format!("Seccomp:\t{seccomp}")),
                    kind,
                    uid
                )
                .is_err());
            }
            for name in ["CapPrm", "CapEff", "CapBnd"] {
                let old = field(&original, name).unwrap();
                let changed = original.replace(
                    &format!("{name}:\t{old}"),
                    &format!("{name}:\t0000000000000100"),
                );
                assert!(worker_status(&changed, kind, uid).is_err());
            }
        }
    }

    #[test]
    fn every_real_effective_saved_and_filesystem_uid_is_current_and_canonical() {
        for uid in [0, 989, 990] {
            uid_status(&format!("Uid: {uid} {uid} {uid} {uid}\n"), uid).unwrap();
            for index in 0..4 {
                let mut values = vec![uid.to_string(); 4];
                for altered in [
                    (u64::from(uid) + 1).to_string(),
                    "-1".into(),
                    "00".into(),
                    "4294967296".into(),
                    "unavailable".into(),
                ] {
                    values[index] = altered;
                    assert!(uid_status(&format!("Uid: {}\n", values.join(" ")), uid).is_err());
                }
            }
        }
        for bad in [
            "",
            "Uid: 0 0 0\n",
            "Uid: 0 0 0 0 0\n",
            "Uid: 0 0 0 0\nUid: 0 0 0 0\n",
        ] {
            assert!(uid_status(bad, 0).is_err());
        }
    }

    #[test]
    fn changes_during_either_enforcement_snapshot_cannot_acknowledge_a_generation() {
        for (kind, uid) in [(Kind::Model, 989), (Kind::Acquisition, 0)] {
            for name in ["attr/current", "cgroup", "status", "limits"] {
                for round in 0..2 {
                    assert!(observe(kind, uid, |field, count, value| {
                        if field == name && count == round {
                            *value = "changed".into();
                        }
                    })
                    .is_err());
                }
            }
            for round in 1..3 {
                assert!(observe(kind, uid, |field, count, value| {
                    if field == "stat" && count == round {
                        *value = stat(8);
                    }
                })
                .is_err());
            }
            for name in ["stat", "status", "cgroup", "attr/current", "limits"] {
                assert!(worker_generation(kind, uid, |field, _| {
                    if field == name {
                        Err("trusted observation unavailable".into())
                    } else {
                        Ok(match field {
                            "stat" => stat(7),
                            "cgroup" => format!("0::{}\n", kind.leaf()),
                            "status" => status(kind, uid),
                            "attr/current" => {
                                if kind == Kind::Model {
                                    "luma-model (enforce)\n".into()
                                } else {
                                    "luma-acquisition (enforce)\n".into()
                                }
                            }
                            "limits" => "Max locked memory 0 0 bytes\n".into(),
                            _ => panic!("unknown field"),
                        })
                    }
                })
                .is_err());
            }
        }
    }

    #[test]
    fn live_peer_proof_uses_the_exact_kernel_handle_not_another_live_root_process() {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(raw >= 0);
        let pin = unsafe { File::from_raw_fd(raw as i32) };
        let peer = libc::ucred {
            pid: std::process::id() as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        assert!(live_generation(peer, &pin).is_ok());
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let foreign = live_generation(
            libc::ucred {
                pid: child.id() as i32,
                ..peer
            },
            &pin,
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(foreign.is_err());
        assert!(live_generation(libc::ucred { pid: 0, ..peer }, &pin).is_err());
        assert!(live_generation(
            libc::ucred {
                uid: peer.uid + 1,
                ..peer
            },
            &pin
        )
        .is_err());
        assert!(live_generation(peer, &File::open("/dev/null").unwrap()).is_err());
    }
}
