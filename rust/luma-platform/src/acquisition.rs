//! Fixed, broker-leased native model acquisition. No user-selected executable,
//! cgroup, budget, URL, model manifest or resource authority is accepted.
use crate::{model, platform, resource_manager, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const UNIT: &str = "luma-acquisition.service";
const LEAF: &str = "0::/lumaacquisition.slice/luma-acquisition.service\n";

fn verification_target(at: &Path, id: &str) -> Result<PathBuf> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("invalid verification profile identity".into());
    }
    let suffix = format!("/lib/luma-os/models/{id}.gguf");
    let text = at.to_str().ok_or("invalid verification path encoding")?;
    let parent = text
        .strip_suffix(&suffix)
        .ok_or("verification is not the exact catalog model path")?;
    let target = PathBuf::from(parent);
    if !target_shape(&target, true) && !target_shape(&target, false) {
        return Err("verification target is not a supported native data mount".into());
    }
    Ok(target)
}

pub(crate) fn verify_path(at: &Path, profile: &model::Profile) -> Result<()> {
    run(&verification_target(at, &profile.id)?, profile, "verify")
}

fn target_shape(target: &Path, installed: bool) -> bool {
    let Some(text) = target.to_str() else {
        return false;
    };
    if installed {
        return text == "/var";
    }
    let Some(name) = text
        .strip_prefix("/var/lib/luma-os/staging/install-")
        .and_then(|s| s.strip_suffix("/data"))
    else {
        return false;
    };
    name.len() == 32
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn target(target: &Path) -> Result<()> {
    let installed = platform::require_installed().is_ok();
    if !installed {
        platform::require_live()?;
    }
    if !target_shape(target, installed) {
        return Err("unsupported acquisition target".into());
    }
    let mut current = std::path::PathBuf::from("/");
    for component in target.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => current.push(name),
            _ => return Err("invalid acquisition target component".into()),
        }
        let m = fs::symlink_metadata(&current)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unsafe acquisition target ancestor".into());
        }
    }
    if resource_manager::storage_device(target)?.starts_with("0:") {
        return Err("acquisition requires the mounted encrypted block-backed target".into());
    }
    Ok(())
}

pub(crate) fn arguments(target: &Path, profile: &str, action: &str) -> Result<Vec<String>> {
    let text = target
        .to_str()
        .ok_or("invalid acquisition target encoding")?;
    if !matches!(action, "prepare" | "verify" | "invoice") {
        return Err("invalid acquisition action".into());
    }
    let mut args = vec![
        "--quiet".into(),
        "--no-ask-password".into(),
        "--wait".into(),
        "--collect".into(),
        "--pipe".into(),
        "--service-type=exec".into(),
        "--expand-environment=no".into(),
        format!("--unit={UNIT}"),
        "--slice=lumaacquisition.slice".into(),
    ];
    for property in [
        "User=root",
        "Group=root",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "AppArmorProfile=luma-acquisition",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictNamespaces=yes",
        "LockPersonality=yes",
        "MemoryDenyWriteExecute=yes",
        "SystemCallArchitectures=native",
        "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL",
        "MemoryHigh=384M",
        "MemoryMax=512M",
        "MemorySwapMax=0",
        "OOMPolicy=kill",
        "TasksMax=16",
        "CPUQuota=200%",
        "LimitMEMLOCK=0",
        "LimitCORE=0",
        "DevicePolicy=closed",
        "KillMode=control-group",
        "TimeoutStopSec=15",
        "Restart=no",
        "Requires=luma-broker.service",
        "After=luma-broker.service",
        "BindsTo=luma-broker.service",
        "Conflicts=sleep.target",
        "Before=sleep.target",
        "InaccessiblePaths=/var/lib/luma-broker",
    ] {
        args.push(format!("--property={property}"));
    }
    if action == "invoice" {
        if target != Path::new("/var") {
            return Err("workflow calculation requires the installed data mount".into());
        }
        crate::workflow_resource::source_digest(profile)?;
        for property in [
            "RestrictAddressFamilies=AF_UNIX",
            "RuntimeMaxSec=30",
            "LimitFSIZE=4M",
        ] {
            args.push(format!("--property={property}"));
        }
    } else {
        args.push("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".into());
        args.push("--property=RuntimeMaxSec=3700".into());
        args.push(format!("--property=ReadWritePaths={text}/lib/luma-os"));
    }
    for property in [
        format!("IOReadBandwidthMax={text} 64M"),
        format!("IOWriteBandwidthMax={text} 64M"),
    ] {
        args.push(format!("--property={property}"));
    }
    if action == "invoice" {
        args.extend([
            "--".into(),
            "/usr/libexec/luma-os/luma-platform".into(),
            "workflow-resource-worker".into(),
            profile.into(),
        ]);
        return Ok(args);
    }
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "model-acquisition-worker".into(),
        action.into(),
        profile.into(),
        text.into(),
    ]);
    Ok(args)
}

fn available(status: &serde_json::Value) -> Result<bool> {
    for domain in ["host-memory", "acquisition-executions"] {
        if status["domains"][domain]["quarantined"]
            .as_bool()
            .ok_or("missing domain fence")?
        {
            return Err("acquisition domain quarantined; reviewed reconciliation required".into());
        }
    }
    let pressure = status["domains"]["acquisition-executions"]["pressure"]
        .as_bool()
        .ok_or("missing acquisition pressure")?;
    let populated = status["workers"]["acquisition_populated"]
        .as_bool()
        .ok_or("missing acquisition kernel observation")?;
    let retained_text = status["workers"]["acquisition_retained_bytes"]
        .as_str()
        .ok_or("missing acquisition retained-byte observation")?;
    let retained: u64 = retained_text.parse()?;
    if retained.to_string() != retained_text {
        return Err("noncanonical acquisition retained bytes".into());
    }
    let outstanding = status["outstanding"]
        .as_array()
        .ok_or("missing outstanding leases")?;
    if outstanding.len() > 16 {
        return Err("oversized resource inventory".into());
    }
    let mut allocated = false;
    for lease in outstanding {
        let uid = lease["owner"]["uid"]
            .as_u64()
            .ok_or("missing kernel owner identity")?;
        if ![0, 989].contains(&uid) {
            return Err("unsupported resource owner in inventory".into());
        }
        allocated |= uid == 0;
    }
    Ok(!populated && !allocated && !pressure && retained <= 16 * 1024 * 1024)
}

pub(crate) fn await_drainage() -> Result<()> {
    let deadline = resource_manager::now()?
        .checked_add(30_000)
        .ok_or("drainage deadline overflow")?;
    loop {
        let status = resource_manager::acquisition_status()?;
        if resource_manager::now()? >= deadline {
            return Err("prior acquisition drainage unconfirmed".into());
        }
        if available(&status)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub(crate) fn run(target_path: &Path, profile: &model::Profile, action: &str) -> Result<()> {
    crate::require_root()?;
    target(target_path)?;
    // Resolve only the immutable image catalog; never serialize a supplied
    // model URL or runtime command across the launch boundary.
    if model::profile(&profile.id)?.resource_binding()? != profile.resource_binding()? {
        return Err("acquisition profile differs from the pinned catalog".into());
    }
    // Do not populate a recycled unit before the broker has observed the old
    // owner gone, the slice empty and its residual charge retained. A unit's
    // successful exit alone is not the corresponding allocation receipt.
    await_drainage()?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args(arguments(target_path, &profile.id, action)?)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let deadline = resource_manager::now()?
        .checked_add(3_740_000)
        .ok_or("acquisition controller deadline overflow")?;
    // Reaping systemd-run is NOT a service drainage receipt. On interrupted
    // observation the service/lease can remain live; no automatic name-based
    // stop is sent to a possibly newer invocation. Broker token revocation and
    // the finite service lifetime retain exact-generation control instead.
    model::supervise_owned_controller(&mut command, || {
        if resource_manager::now()? >= deadline {
            return Err("acquisition controller timed out; service outcome uncertain".into());
        }
        Ok(())
    })?;
    // The controller waits for an observed handoff, not just process exit.
    // Residual kernel bytes remain charged; no zero-byte cleanup is inferred.
    await_drainage()
}

pub(crate) fn worker(action: &str, id: &str, target_path: &Path) -> Result<()> {
    crate::require_root()?;
    target(target_path)?;
    if fs::read_to_string("/proc/self/cgroup")? != LEAF {
        return Err("acquisition must run in its fixed isolated unit".into());
    }
    if fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n" {
        return Err("acquisition confinement is not enforcing".into());
    }
    let profile = model::profile(id)?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(id, target_path)?;
    lease.check()?;
    match action {
        "prepare" => model::prepare_model_contents(target_path, &profile, || lease.check_local())?,
        "verify" => model::verify_acquired_model(target_path, &profile, || lease.check_local())?,
        _ => return Err("invalid acquisition worker action".into()),
    }
    lease.check()?;
    // Exit and heartbeat drop do not free bytes. The broker observes the
    // entire slice, surviving cache and this exact kernel owner generation.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_has_no_unleased_or_arbitrary_path_fallback() {
        let id = "qwen3-4b-q4-k-m";
        assert_eq!(
            verification_target(Path::new(&format!("/var/lib/luma-os/models/{id}.gguf")), id)
                .unwrap(),
            Path::new("/var")
        );
        let live = format!("/var/lib/luma-os/staging/install-{}/data", "a".repeat(32));
        assert_eq!(
            verification_target(
                Path::new(&format!("{live}/lib/luma-os/models/{id}.gguf")),
                id
            )
            .unwrap(),
            Path::new(&live)
        );
        for path in [
            "/tmp/model.gguf",
            "/var/lib/luma-os/models/other.gguf",
            "/var//lib/luma-os/models/qwen3-4b-q4-k-m.gguf",
            "/var/lib/luma-os/models/../qwen3-4b-q4-k-m.gguf",
        ] {
            assert!(verification_target(Path::new(path), id).is_err());
        }
        assert!(verification_target(
            Path::new("/var/lib/luma-os/models/../secret.gguf"),
            "../secret"
        )
        .is_err());
        let p = model::profile(id).unwrap();
        assert!(verify_path(Path::new("/tmp/model.gguf"), &p).is_err());
    }
    #[test]
    fn handoff_requires_kernel_emptiness_retained_bound_and_no_outstanding_generation() {
        let clean = serde_json::json!({"domains":{"host-memory":{"quarantined":false},
            "acquisition-executions":{"quarantined":false,"pressure":false}},
            "workers":{"acquisition_populated":false,"acquisition_retained_bytes":"16777216"},
            "outstanding":[]});
        assert!(available(&clean).unwrap());
        let mut occupied = clean.clone();
        occupied["outstanding"] = serde_json::json!([{"owner":{"uid":0}}]);
        assert!(!available(&occupied).unwrap());
        occupied["outstanding"] = serde_json::json!([{"owner":{"uid":989}}]);
        assert!(available(&occupied).unwrap());
        occupied["workers"]["acquisition_populated"] = serde_json::json!(true);
        assert!(!available(&occupied).unwrap());
        occupied = clean.clone();
        occupied["workers"]["acquisition_retained_bytes"] = serde_json::json!("16777217");
        assert!(!available(&occupied).unwrap());
        for bytes in [
            serde_json::json!(1),
            serde_json::json!("01"),
            serde_json::json!("-1"),
            serde_json::json!("18446744073709551616"),
        ] {
            let mut malformed = clean.clone();
            malformed["workers"]["acquisition_retained_bytes"] = bytes;
            assert!(available(&malformed).is_err());
        }
        occupied = clean.clone();
        occupied["domains"]["acquisition-executions"]["quarantined"] = serde_json::json!(true);
        assert!(available(&occupied).is_err());
        assert!(available(&serde_json::json!({})).is_err());
    }
    #[test]
    fn targets_are_exact_installed_or_private_live_shapes() {
        assert!(target_shape(Path::new("/var"), true));
        assert!(!target_shape(Path::new("/var/"), true));
        let live = format!("/var/lib/luma-os/staging/install-{}/data", "a".repeat(32));
        assert!(target_shape(Path::new(&live), false));
        for path in [
            "/var",
            "/tmp/data",
            "/var/lib/luma-os/staging/install-a/data",
            "/var/lib/luma-os/staging/install-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/data",
            "/var/lib/luma-os/staging/install-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/../data",
        ] {
            assert!(!target_shape(Path::new(path), false));
        }
        assert!(!target_shape(Path::new(&live), true));
    }
    #[test]
    fn launch_has_only_fixed_command_and_bounded_properties_with_no_shell() {
        let args = arguments(Path::new("/var"), "qwen3-4b-q4-k-m", "prepare").unwrap();
        for expected in [
            "--wait",
            "--collect",
            "--expand-environment=no",
            "--unit=luma-acquisition.service",
            "--slice=lumaacquisition.slice",
            "--property=MemoryMax=512M",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=16",
            "--property=LimitMEMLOCK=0",
            "--property=IOWriteBandwidthMax=/var 64M",
            "--property=InaccessiblePaths=/var/lib/luma-broker",
        ] {
            assert!(args.iter().any(|a| a == expected), "{expected}");
        }
        assert_eq!(
            &args[args.len() - 5..],
            [
                "/usr/libexec/luma-os/luma-platform",
                "model-acquisition-worker",
                "prepare",
                "qwen3-4b-q4-k-m",
                "/var"
            ]
        );
        assert!(arguments(Path::new("/var"), "qwen3-4b-q4-k-m", "shell").is_err());
    }
}
