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

fn worker_status(status: &str, kind: Kind, uid: u32) -> Result<()> {
    uid_status(status, uid)?;
    if field(status, "NoNewPrivs")? != "1" || field(status, "Seccomp")? != "2" {
        return Err("worker privilege/filter enforcement unavailable".into());
    }
    // The root acquisition supervisor retains only credential-drop and owned
    // child termination capabilities; its UID-988 child is a separate process.
    let mask = match kind {
        Kind::Model => 0,
        Kind::Acquisition => (1u64 << 7) | (1u64 << 6) | (1u64 << 5),
    };
    for name in ["CapPrm", "CapEff", "CapBnd"] {
        capabilities(status, name, mask)?;
    }
    for name in ["CapInh", "CapAmb"] {
        capabilities(status, name, 0)?;
    }
    Ok(())
}

fn locked_memory(limits: &str) -> Result<()> {
    let mut lines = limits
        .lines()
        .filter(|line| line.starts_with("Max locked memory"));
    let line = lines.next().ok_or("missing pinned-memory ceiling")?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if lines.next().is_some()
        || fields.len() != 6
        || fields[3] != "0"
        || fields[4] != "0"
        || fields[5] != "bytes"
    {
        return Err("CPU worker pinned memory is not disabled".into());
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
    let profile = match kind {
        Kind::Model => "luma-model (enforce)\n",
        Kind::Acquisition => "luma-acquisition (enforce)\n",
    };
    for _ in 0..2 {
        if read("cgroup", 4096)? != format!("0::{}\n", kind.leaf())
            || read("attr/current", 128)? != profile
        {
            return Err("worker group or enforcing AppArmor generation differs".into());
        }
        worker_status(&read("status", STATUS_BYTES)?, kind, uid)?;
        locked_memory(&read("limits", 8192)?)?;
        if start_ticks(&read("stat", 4096)?)? != start {
            return Err("worker process generation changed during observation".into());
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
    let start = start_ticks(&safe_text(&path.join("stat"), 4096)?)?;
    uid_status(&safe_text(&path.join("status"), STATUS_BYTES)?, peer.uid)?;
    let boot = boot_identity()?;
    if !pidfd_alive(pin)?
        || start_ticks(&safe_text(&path.join("stat"), 4096)?)? != start
        || fs::metadata(&path)?.uid() != peer.uid
    {
        return Err("peer generation changed during credential observation".into());
    }
    uid_status(&safe_text(&path.join("status"), STATUS_BYTES)?, peer.uid)?;
    if !pidfd_alive(pin)? {
        return Err("peer exited during credential observation".into());
    }
    Ok((start, boot))
}

#[cfg(test)]
mod tests {
    use super::*;

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
