//! Reviewed offline repair of a genuinely absent model exclusion inode.
//! Does not initialize, reset, migrate or release resource authority.
use super::*;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

const UNITS: [&str; 3] = [
    "luma-model.service",
    "luma-broker.service",
    "luma-acquisition.service",
];
const MAX_TASKS: usize = 32_768;
const MAX_STATUS: u64 = 65_536;

#[derive(Clone, Serialize)]
struct Observation {
    schema_version: u32,
    boot: String,
    catalog: String,
    ledger_review: Option<String>,
    state_identity: (String, String),
    model_identity: (String, String),
    acquisition_identity: (String, String),
    masks: BTreeMap<String, (String, String, String, String)>,
    runtime_lock_absent: bool,
}
impl Observation {
    fn review(&self) -> Result<String> {
        Ok(crate::bundle::hex(&Sha256::digest(serde_json::to_vec(
            self,
        )?)))
    }
}

fn trusted_directory(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("unsafe offline recovery directory".into());
    }
    Ok(metadata)
}

fn masks_at(directory: &Path) -> Result<BTreeMap<String, (String, String, String, String)>> {
    trusted_directory(directory)?;
    let mut masks = BTreeMap::new();
    for name in UNITS {
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || fs::read_link(&path)? != Path::new("/dev/null")
        {
            return Err("all three worker/broker units require trusted runtime masks".into());
        }
        masks.insert(
            name.into(),
            (
                metadata.dev().to_string(),
                metadata.ino().to_string(),
                metadata.ctime().to_string(),
                metadata.ctime_nsec().to_string(),
            ),
        );
    }
    Ok(masks)
}

fn inactive_masked_unit(text: &str) -> Result<()> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("invalid systemd recovery observation")?;
        if !matches!(key, "LoadState" | "ActiveState" | "SubState" | "Job")
            || values.insert(key, value).is_some()
        {
            return Err("unexpected or duplicate systemd recovery observation".into());
        }
    }
    if values.len() != 4
        || values.get("LoadState") != Some(&"masked")
        || values.get("Job") != Some(&"")
        || !matches!(
            (values.get("ActiveState"), values.get("SubState")),
            (Some(&"inactive"), Some(&"dead")) | (Some(&"failed"), Some(&"failed"))
        )
    {
        return Err("systemd has not loaded an idle mask; no future-admission exclusion".into());
    }
    Ok(())
}

fn manager_masks() -> Result<()> {
    for name in UNITS {
        let mut command = std::process::Command::new("/usr/bin/systemctl");
        command.args([
            "--no-ask-password",
            "--no-pager",
            "show",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Job",
            name,
        ]);
        inactive_masked_unit(&bounded_observer(command, 5_000)?)?;
    }
    Ok(())
}

fn bounded_observer(mut command: std::process::Command, budget_ms: u64) -> Result<String> {
    use std::io::{Seek, SeekFrom};
    if budget_ms == 0 || budget_ms > 5_000 {
        return Err("invalid recovery observer budget".into());
    }
    let label = CString::new("luma-resource-recovery-status")?;
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, label.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut output = unsafe { File::from_raw_fd(fd as i32) };
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(output.try_clone()?));
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 8192,
                rlim_max: 8192,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let deadline = now()?
        .checked_add(budget_ms)
        .ok_or("recovery observer deadline overflow")?;
    model::supervise_owned_controller(&mut command, || {
        if now()? >= deadline || output.metadata()?.len() >= 8192 {
            return Err("bounded systemd recovery observation unavailable".into());
        }
        Ok(())
    })?;
    output.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    output.take(8193).read_to_string(&mut text)?;
    if text.len() >= 8192 {
        return Err("oversized systemd recovery observation".into());
    }
    Ok(text)
}

fn proc_open(directory: &File, name: &str, is_directory: bool) -> std::io::Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if is_directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn task_uid(text: &str) -> Result<[u32; 4]> {
    let mut found = None;
    for line in text.lines().filter_map(|line| line.strip_prefix("Uid:")) {
        if found.is_some() {
            return Err("duplicate process credential observation".into());
        }
        let values: Result<Vec<u32>> = line
            .split_whitespace()
            .map(|s| {
                let uid = number(s)?;
                if uid.to_string() != s {
                    return Err("noncanonical process UID observation".into());
                }
                uid.try_into()
                    .map_err(|_| "process UID exceeds kernel contract".into())
            })
            .collect();
        found = Some(
            values?
                .try_into()
                .map_err(|_| "invalid process UID tuple")?,
        );
    }
    found.ok_or_else(|| "missing process credentials; no exclusion proof".into())
}

fn gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

fn process_entries(directory: &File) -> Result<fs::ReadDir> {
    // This fixed kernel FD alias enumerates the pinned proc directory. No
    // caller pathname or user-controlled symbolic link participates.
    Ok(fs::read_dir(format!(
        "/proc/self/fd/{}",
        directory.as_raw_fd()
    ))?)
}

fn numeric_task(name: &std::ffi::OsStr) -> Result<Option<String>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if !bytes.iter().all(u8::is_ascii_digit) || bytes.is_empty() {
        return Ok(None);
    }
    let name = std::str::from_utf8(bytes)?;
    let value = number(name)?;
    if value == 0 || value > u64::from(u32::MAX) || value.to_string() != name {
        return Err("invalid proc task identity".into());
    }
    Ok(Some(name.into()))
}

fn check_budget(started: Instant, count: &mut usize) -> Result<()> {
    *count = count.checked_add(1).ok_or("process census overflow")?;
    if *count > MAX_TASKS || started.elapsed() >= Duration::from_secs(5) {
        return Err("complete process census exceeds recovery bound".into());
    }
    Ok(())
}

fn no_model_tasks(proc: &File) -> Result<()> {
    let started = Instant::now();
    let mut count = 0;
    for process in process_entries(proc)? {
        let Some(pid) = numeric_task(&process?.file_name())? else {
            continue;
        };
        check_budget(started, &mut count)?;
        let process = match proc_open(proc, &pid, true) {
            Ok(file) => file,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let tasks = match proc_open(&process, "task", true) {
            Ok(file) => file,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        for task in process_entries(&tasks)? {
            let Some(tid) = numeric_task(&task?.file_name())? else {
                continue;
            };
            check_budget(started, &mut count)?;
            let task = match proc_open(&tasks, &tid, true) {
                Ok(file) => file,
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let file = match proc_open(&task, "status", false) {
                Ok(file) => file,
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let mut text = String::new();
            match file.take(MAX_STATUS + 1).read_to_string(&mut text) {
                Ok(_) => (),
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error.into()),
            }
            if text.len() as u64 > MAX_STATUS || task_uid(&text)?.contains(&989) {
                return Err(
                    "model credential survives outside verified drainage; preserve exclusion"
                        .into(),
                );
            }
        }
    }
    if started.elapsed() >= Duration::from_secs(5) {
        return Err("complete process census exceeded recovery deadline".into());
    }
    Ok(())
}

fn trusted_proc() -> Result<File> {
    let proc = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/proc")?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0
        || info.f_type != 0x9fa0
        || fs::read_link("/proc/self/ns/pid")? != fs::read_link("/proc/1/ns/pid")?
        || safe_text(Path::new("/proc/1/comm"), 64)?.trim() != "systemd"
    {
        return Err("offline recovery requires the installed systemd PID namespace".into());
    }
    visible_proc_mount(&safe_text(Path::new("/proc/self/mountinfo"), 1024 * 1024)?)?;
    Ok(proc)
}

fn visible_proc_mount(text: &str) -> Result<()> {
    let mut found = false;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(4) != Some(&"/proc") {
            continue;
        }
        let separator = fields
            .iter()
            .position(|v| *v == "-")
            .ok_or("invalid proc mount observation")?;
        if separator < 6
            || found
            || fields.get(3) != Some(&"/")
            || fields.get(separator + 1) != Some(&"proc")
            || fields.len() != separator + 4
        {
            return Err("unsupported proc mount visibility".into());
        }
        for options in [fields[5], fields[separator + 3]] {
            if options.split(',').any(|option| {
                option.starts_with("hidepid=") && option != "hidepid=0"
                    || option.starts_with("subset=")
            }) {
                return Err(
                    "hidden or subset proc tasks cannot prove whole-identity exclusion".into(),
                );
            }
        }
        found = true;
    }
    if !found {
        return Err("proc mount identity missing".into());
    }
    Ok(())
}

fn observe(store: Option<&Store>) -> Result<Observation> {
    let state = Path::new("/var/lib/luma-os");
    for path in ["/var", "/var/lib", "/run", "/run/systemd"] {
        trusted_directory(Path::new(path))?;
    }
    let parent = trusted_directory(state)?;
    let masks = masks_at(Path::new("/run/systemd/system"))?;
    manager_masks()?;
    let model = Group::open()?;
    let acquisition = Group::for_kind(Kind::Acquisition)?;
    if model.populated()? || acquisition.populated()? {
        return Err("offline recovery requires both worker slices drained".into());
    }
    no_model_tasks(&trusted_proc()?)?;
    let ledger_review = match store {
        Some(store) => {
            let ledger = store.read()?;
            if ledger
                .leases
                .iter()
                .any(|lease| lease.state != State::Released)
            {
                return Err("outstanding generations cannot recover an exclusion inode".into());
            }
            Some(ledger.review()?)
        }
        None => {
            match fs::symlink_metadata(resources::DIRECTORY) {
                Err(error) if gone(&error) => (),
                _ => return Err("resource state appeared or is uncertain; preserve state".into()),
            }
            None
        }
    };
    let absent = match fs::symlink_metadata(state.join("model-runtime.lock")) {
        Err(error) if gone(&error) => true,
        Ok(_) => {
            let _idle = model::resource_idle()?;
            false
        }
        Err(error) => return Err(error.into()),
    };
    let identity = |m: (u64, u64)| (m.0.to_string(), m.1.to_string());
    Ok(Observation {
        schema_version: 1,
        boot: boot_identity()?,
        catalog: model::resource_catalog_binding()?,
        ledger_review,
        state_identity: (parent.dev().to_string(), parent.ino().to_string()),
        model_identity: identity(model.identity()?),
        acquisition_identity: identity(acquisition.identity()?),
        masks,
        runtime_lock_absent: absent,
    })
}

fn offline_store() -> Result<Option<Store>> {
    trusted_directory(Path::new("/var/lib/luma-broker"))?;
    match fs::symlink_metadata(resources::DIRECTORY) {
        Err(error) if gone(&error) => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            // Opening the normal store validates all retained archives and takes
            // its lifetime exclusion. Require its existing lock: inspection must
            // not manufacture a missing authority artifact in damaged state.
            let path = Path::new(resources::DIRECTORY).join("ledger.lock");
            crate::tpm::private_read(&path, 0)?;
            Ok(Some(Store::open(Path::new(resources::DIRECTORY))?))
        }
    }
}

pub(crate) fn status() -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let _operation = model::resource_recovery_exclusion()?;
    let store = offline_store()?;
    let observed = observe(store.as_ref())?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version":1, "review_sha256":observed.review()?,
            "runtime_lock_absent":observed.runtime_lock_absent,
            "recoverable":observed.runtime_lock_absent,
            "ledger_present":observed.ledger_review.is_some(),
            "service_masks_retained":true, "ledger_changed":false,
            "worker_started":false, "resources_released":false,
            "product_admin_authorization":false,
        })
    );
    Ok(())
}

fn reviewed_create(
    reviewed: &str,
    mut observation: impl FnMut() -> Result<Observation>,
    create: impl FnOnce() -> Result<File>,
) -> Result<File> {
    if reviewed.len() != 64
        || !reviewed
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid offline exclusion review".into());
    }
    let prior = observation()?;
    if !prior.runtime_lock_absent || prior.review()? != reviewed {
        return Err("offline exclusion review changed or inode already exists".into());
    }
    // Recheck masks, every live task and ledger while both durable exclusions
    // remain held. There is no inference from a successful systemctl exit.
    if observation()?.review()? != reviewed {
        return Err("offline exclusion proof changed before publication".into());
    }
    create()
}

pub(crate) fn recover(reviewed: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let _operation = model::resource_recovery_exclusion()?;
    let store = offline_store()?;
    let _idle = reviewed_create(
        reviewed,
        || observe(store.as_ref()),
        model::recover_missing_runtime_lock,
    )?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version":1,"runtime_lock_created":true,
            "service_masks_retained":true,"ledger_changed":false,
            "worker_started":false,"resources_released":false,
            "product_admin_authorization":false,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
    fn observation() -> Observation {
        Observation {
            schema_version: 1,
            boot: "boot-fixture".into(),
            catalog: "a".repeat(64),
            ledger_review: Some("b".repeat(64)),
            state_identity: ("2".into(), "3".into()),
            model_identity: ("4".into(), "5".into()),
            acquisition_identity: ("4".into(), "6".into()),
            masks: BTreeMap::from([(
                "luma-model.service".into(),
                ("7".into(), "8".into(), "9".into(), "0".into()),
            )]),
            runtime_lock_absent: true,
        }
    }
    #[test]
    fn process_credential_parser_checks_all_four_ids_and_rejects_uncertainty() {
        assert_eq!(
            task_uid("Name:\tx\nUid:\t0\t989\t0\t0\n").unwrap(),
            [0, 989, 0, 0]
        );
        for text in [
            "",
            "Uid: 0 0 0",
            "Uid: 0 0 0 0 0",
            "Uid: 0 0 0 4294967296",
            "Uid: 0 0 0 0\nUid: 0 0 0 0",
            "Uid: 0 0 -1 0",
            "Uid: 00 0 0 0",
        ] {
            assert!(task_uid(text).is_err(), "{text:?}");
        }
    }
    #[test]
    fn masks_must_be_loaded_by_systemd_with_no_job_or_active_control_state() {
        for valid in [
            "LoadState=masked\nActiveState=inactive\nSubState=dead\nJob=\n",
            "LoadState=masked\nActiveState=failed\nSubState=failed\nJob=\n",
        ] {
            inactive_masked_unit(valid).unwrap();
            for (from, to) in [
                ("masked", "loaded"),
                ("Job=", "Job=123"),
                ("SubState=", "Unknown="),
                ("LoadState=masked\n", ""),
                ("Job=\n", "Job=\nJob=\n"),
            ] {
                assert!(inactive_masked_unit(&valid.replace(from, to)).is_err());
            }
        }
        assert!(inactive_masked_unit(
            "LoadState=masked\nActiveState=active\nSubState=running\nJob=\n"
        )
        .is_err());
        assert!(inactive_masked_unit(
            "LoadState=masked\nActiveState=inactive\nSubState=failed\nJob=\n"
        )
        .is_err());
    }
    #[test]
    fn real_observer_has_kernel_output_ceiling_and_owned_deadline_teardown() {
        let expected = "LoadState=masked\nActiveState=inactive\nSubState=dead\nJob=\n";
        let mut command = std::process::Command::new("/usr/bin/printf");
        command.arg("%s").arg(expected);
        assert_eq!(bounded_observer(command, 5_000).unwrap(), expected);
        let command = std::process::Command::new("/usr/bin/false");
        assert!(bounded_observer(command, 5_000).is_err());
        let mut command = std::process::Command::new("/usr/bin/python3");
        command.args(["-I", "-c", "import os; os.write(1, b'x' * 8193)"]);
        assert!(bounded_observer(command, 5_000).is_err());
        let mut command = std::process::Command::new("/usr/bin/sleep");
        command.arg("10");
        let started = Instant::now();
        assert!(bounded_observer(command, 100).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        for budget in [0, 5_001, u64::MAX] {
            assert!(bounded_observer(std::process::Command::new("/usr/bin/true"), budget).is_err());
        }
    }
    #[test]
    fn hidden_subset_bind_or_ambiguous_proc_mounts_are_not_exclusion_proofs() {
        let valid = "36 20 0:5 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
        visible_proc_mount(valid).unwrap();
        visible_proc_mount(&valid.replace("proc rw", "proc rw,hidepid=0")).unwrap();
        for option in [
            "hidepid=1",
            "hidepid=2",
            "hidepid=invisible",
            "hidepid=noaccess",
            "subset=pid",
        ] {
            assert!(
                visible_proc_mount(&valid.replace("proc rw", &format!("proc rw,{option}")))
                    .is_err()
            );
        }
        assert!(visible_proc_mount("").is_err());
        assert!(visible_proc_mount(&(valid.to_owned() + valid)).is_err());
        assert!(visible_proc_mount(&valid.replace("/ /proc", "/123 /proc")).is_err());
        assert!(visible_proc_mount(&valid.replace("- proc", "- tmpfs")).is_err());
        assert!(visible_proc_mount("a - proc / /proc").is_err());
    }
    #[test]
    fn review_binds_each_exclusion_and_does_not_publish_after_any_drift() {
        let review = observation().review().unwrap();
        for field in 0..8 {
            let mut next = observation();
            match field {
                0 => next.boot.push('x'),
                1 => next.catalog = "c".repeat(64),
                2 => next.ledger_review = None,
                3 => next.state_identity.1 = "10".into(),
                4 => next.model_identity.1 = "10".into(),
                5 => next.acquisition_identity.1 = "10".into(),
                6 => next.masks.clear(),
                _ => next.runtime_lock_absent = false,
            }
            let invoked = Cell::new(0);
            let mut calls = 0;
            assert!(reviewed_create(
                &review,
                || {
                    calls += 1;
                    Ok(if calls == 1 {
                        observation()
                    } else {
                        next.clone()
                    })
                },
                || {
                    invoked.set(invoked.get() + 1);
                    File::open("/dev/null").map_err(Into::into)
                }
            )
            .is_err());
            assert_eq!(invoked.get(), 0);
        }
    }
    #[test]
    fn stale_malformed_existing_or_failed_observation_never_creates() {
        for review in ["", "A", &"A".repeat(64), &"d".repeat(64)] {
            let invoked = Cell::new(false);
            assert!(reviewed_create(
                review,
                || Ok(observation()),
                || {
                    invoked.set(true);
                    File::open("/dev/null").map_err(Into::into)
                }
            )
            .is_err());
            assert!(!invoked.get());
        }
        let mut existing = observation();
        existing.runtime_lock_absent = false;
        let review = existing.review().unwrap();
        assert!(reviewed_create(
            &review,
            || {
                let mut o = observation();
                o.runtime_lock_absent = false;
                Ok(o)
            },
            || panic!("existing lock cannot be created")
        )
        .is_err());
        assert!(reviewed_create(
            &observation().review().unwrap(),
            || Err("census unavailable".into()),
            || panic!("no exclusion proof")
        )
        .is_err());
    }
    #[test]
    fn exact_review_invokes_creation_once_and_propagates_uncertain_publication() {
        let calls = Cell::new(0);
        let created = reviewed_create(
            &observation().review().unwrap(),
            || {
                calls.set(calls.get() + 1);
                Ok(observation())
            },
            || File::open("/dev/null").map_err(Into::into),
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        drop(created);
        assert!(reviewed_create(
            &observation().review().unwrap(),
            || Ok(observation()),
            || Err("directory synchronization unavailable".into())
        )
        .is_err());
    }
    #[test]
    fn runtime_masks_require_exact_root_owned_null_links_for_all_units() {
        let directory =
            std::env::temp_dir().join(format!("luma-resource-masks-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for name in UNITS {
            std::os::unix::fs::symlink("/dev/null", directory.join(name)).unwrap();
        }
        assert_eq!(masks_at(&directory).unwrap().len(), 3);
        let first = directory.join(UNITS[0]);
        fs::remove_file(&first).unwrap();
        assert!(masks_at(&directory).is_err());
        std::os::unix::fs::symlink("/tmp/dev-null", &first).unwrap();
        assert!(masks_at(&directory).is_err());
        fs::remove_file(&first).unwrap();
        fs::write(&first, b"/dev/null").unwrap();
        assert!(masks_at(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn census_and_identity_bounds_never_claim_partial_inspection() {
        assert!(numeric_task(std::ffi::OsStr::new("0")).is_err());
        assert!(numeric_task(std::ffi::OsStr::new("4294967296")).is_err());
        assert!(numeric_task(std::ffi::OsStr::new("self"))
            .unwrap()
            .is_none());
        let mut count = MAX_TASKS;
        assert!(check_budget(Instant::now(), &mut count).is_err());
        let mut count = 0;
        assert!(check_budget(Instant::now() - Duration::from_secs(5), &mut count).is_err());
        let proc = File::open("/proc").unwrap();
        no_model_tasks(&proc).unwrap();
    }
    #[test]
    fn real_off_group_model_credential_refuses_until_the_owned_child_is_reaped() {
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let proc = File::open("/proc").unwrap();
        no_model_tasks(&proc).unwrap();
        let mut child = Owned(
            std::process::Command::new("/usr/bin/sleep")
                .arg("10")
                .uid(989)
                .gid(989)
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(no_model_tasks(&proc).is_err());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        no_model_tasks(&proc).unwrap();
    }
}
