//! Fixed, broker-leased native model acquisition. No user-selected executable,
//! cgroup, budget, URL, model manifest or resource authority is accepted.
use crate::{model, platform, resource_manager, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const UNIT: &str = "luma-acquisition.service";
const LEAF: &str = "0::/lumaacquisition.slice/luma-acquisition.service\n";

/// Installer byte staging is a separate, finite data-only cgroup. It has no
/// installed broker connection, resource ledger, serving or trust capability.
pub(crate) fn installer_staging_arguments(
    root: &Path,
    data: &Path,
    request: &Path,
    sha: &str,
    bytes: u64,
) -> Result<Vec<String>> {
    if !target_shape(data, false)
        || root != data.parent().ok_or("installer mount parent")?.join("root")
        || request.parent() != data.parent()
        || !crate::artifacts::hash(sha)
        || bytes == 0
        || bytes > 64 * 1024 * 1024 * 1024
    {
        return Err("invalid closed installer staging arguments".into());
    }
    let data = data.to_str().ok_or("installer data encoding")?;
    let mut args = vec![
        "--quiet".into(),
        "--wait".into(),
        "--collect".into(),
        "--service-type=exec".into(),
        "--expand-environment=no".into(),
        "--unit=luma-installer-model-stage.service".into(),
        "--slice=lumainstallerstage.slice".into(),
    ];
    for property in ["User=root","Group=root","UMask=0077","NoNewPrivileges=yes","ProtectSystem=strict","ProtectHome=yes","PrivateTmp=yes","ProtectKernelTunables=yes","ProtectKernelModules=yes","ProtectControlGroups=yes","RestrictNamespaces=yes","LockPersonality=yes","MemoryDenyWriteExecute=yes","SystemCallArchitectures=native","AppArmorProfile=luma-installer-model-stage","MemoryHigh=384M","MemoryMax=512M","MemorySwapMax=0","OOMPolicy=kill","TasksMax=16","CPUQuota=200%","LimitMEMLOCK=0","LimitCORE=0","DevicePolicy=closed","KillMode=control-group","TimeoutStopSec=15","Restart=no","RuntimeMaxSec=3700","RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6","CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_PTRACE","SystemCallFilter=~ptrace process_vm_readv process_vm_writev","InaccessiblePaths=/var/lib/luma-broker /var/lib/luma-os/admin /var/lib/luma-os/model-qualifications"] { args.push(format!("--property={property}")); }
    for property in [format!("ReadWritePaths={data}/lib/luma-os/models {data}/lib/luma-os/model-packs {data}/lib/luma-os/installer-model-staging {data}/lib/luma-os/model.lock"),format!("IOReadBandwidthMax={data} 64M"),format!("IOWriteBandwidthMax={data} 64M"),format!("LimitFSIZE={bytes}")] {args.push(format!("--property={property}"));}
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "installer-model-stage-worker".into(),
        request.to_str().ok_or("installer request encoding")?.into(),
        sha.into(),
    ]);
    Ok(args)
}
pub(crate) fn installer_staging_drain() -> Result<()> {
    // The controller holds the private fixed-domain lock before launching.
    // Stop the entire owned cgroup, never reclaim capacity from an exit code.
    let at =
        Path::new("/sys/fs/cgroup/lumainstallerstage.slice/luma-installer-model-stage.service");
    match fs::symlink_metadata(at) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    };
    crate::disk::command(
        "/usr/bin/systemctl",
        &["stop", "luma-installer-model-stage.service"],
    )?;
    let started = resource_manager::now()?;
    loop {
        match fs::read_to_string(at.join("cgroup.events")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(text) if text.lines().any(|line| line == "populated 0") => return Ok(()),
            Ok(_) => (),
        }
        if resource_manager::now()?
            .checked_sub(started)
            .ok_or("installer drainage clock regressed")?
            >= 20_000
        {
            return Err(
                "installer worker drainage is uncertain; preserve target pending state".into(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

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

pub(crate) fn target(target: &Path) -> Result<()> {
    target_context(target, true)
}

fn target_context(target: &Path, controller: bool) -> Result<()> {
    let installed = platform::require_installed().is_ok();
    if installed && controller {
        platform::require_production_activation()?;
    }
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
    if action == "content-restore" {
        return restore_arguments(target, profile);
    }
    if action == "office-export" {
        return office_arguments(target, profile);
    }
    if action == "backup-export" {
        return backup_arguments(target, profile);
    }
    let text = target
        .to_str()
        .ok_or("invalid acquisition target encoding")?;
    if !matches!(
        action,
        "prepare" | "verify" | "invoice" | "generated" | "speech" | "speech-import" | "content"
    ) {
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
    args.push(if matches!(action, "content" | "speech-import") {
        "--property=CapabilityBoundingSet=".into()
    } else if matches!(action, "generated" | "speech") {
        "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_SETPCAP".into()
    } else {
        "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL".into()
    });
    if matches!(action, "invoice" | "generated" | "speech" | "speech-import" | "content") {
        if target != Path::new("/var") {
            return Err("workflow calculation requires the installed data mount".into());
        }
        if action == "invoice" {
            crate::workflow_resource::source_digest(profile)?;
        } else if action == "generated" {
            crate::generated_runtime::source_digest(profile)?;
            args.push("--property=BindPaths=/dev/kvm".into());
            args.push("--property=DeviceAllow=/dev/kvm rw".into());
        } else if action == "speech" {
            crate::speech::source_digest(profile)?;
        } else if action == "speech-import" {
            if profile != model::speech::ID {return Err("auxiliary image import accepts only exact ASR profile".into());}
            model::speech::public_profile()?;
            args.push("--property=ReadWritePaths=/var/lib/luma-os/model-packs".into());
        } else {
            crate::content_governed::source_digest(profile)?;
            args.push(if crate::content_governed::query_profile(profile)? {
                "--property=ReadOnlyPaths=/var/lib/luma-os/content-store".into()
            } else {
                "--property=ReadWritePaths=/var/lib/luma-os/content-store".into()
            });
        }
        for property in [
            "RestrictAddressFamilies=AF_UNIX",
            "RuntimeMaxSec=30",
            if action == "speech-import" {
                "LimitFSIZE=128M"
            } else if action == "content" {
                "LimitFSIZE=16M"
            } else {
                "LimitFSIZE=4M"
            },
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
    if matches!(action, "invoice" | "generated" | "speech" | "speech-import" | "content") {
        args.extend([
            "--".into(),
            "/usr/libexec/luma-os/luma-platform".into(),
            if action == "invoice" {
                "workflow-resource-worker".into()
            } else if action == "generated" {
                "generated-resource-worker".into()
            } else if action == "speech" {
                "speech-resource-worker".into()
            } else if action == "speech-import" {
                "speech-import-resource-worker".into()
            } else {
                "content-resource-worker".into()
            },
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

fn office_arguments(target: &Path, profile: &str) -> Result<Vec<String>> {
    if target != Path::new("/var") {
        return Err("Office export requires fixed installed block-backed data mount".into());
    }
    crate::office_export::source_digest(profile)?;
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
    for property in ["User=root","Group=root","UMask=0077","NoNewPrivileges=yes","ProtectSystem=strict","ProtectHome=yes",
        "PrivateTmp=yes","PrivateDevices=yes","ProtectKernelTunables=yes","ProtectKernelModules=yes","ProtectControlGroups=yes",
        "RestrictNamespaces=user mnt pid net ipc uts cgroup","LockPersonality=yes","MemoryDenyWriteExecute=yes","SystemCallArchitectures=native",
        "AppArmorProfile=luma-office-export","MemoryHigh=896M","MemoryMax=1024M","MemorySwapMax=0","OOMPolicy=kill","TasksMax=32",
        "CPUQuota=200%","LimitCORE=0","LimitFSIZE=17M","DevicePolicy=closed","KillMode=control-group",
        "TimeoutStopSec=15","Restart=no","RuntimeMaxSec=1800","Requires=luma-broker.service","After=luma-broker.service","BindsTo=luma-broker.service",
        "Conflicts=sleep.target","Before=sleep.target","CapabilityBoundingSet=CAP_CHOWN CAP_SETUID CAP_SETGID CAP_KILL",
        "RestrictAddressFamilies=AF_UNIX","SystemCallFilter=~ptrace process_vm_readv process_vm_writev",
        "RuntimeDirectory=luma-office-export","RuntimeDirectoryMode=0711","ReadWritePaths=/run/luma-office-export",
        "ReadOnlyPaths=/var/lib/luma-os/content-store /var/lib/luma-os/principals",
        "InaccessiblePaths=/var/lib/luma-broker /var/lib/luma-os/admin /var/lib/luma-os/identity /var/lib/luma-os/models /var/lib/luma-os/model-packs /var/lib/luma-os/resource-checkpoint /var/lib/luma-os/content-checkpoint /run/luma-admin /run/luma-resource-checkpoint /run/luma-content-checkpoint",
        "IOReadBandwidthMax=/var 64M","IOWriteBandwidthMax=/var 64M"] {args.push(format!("--property={property}"));}
    args.push(format!(
        "--property=LimitMEMLOCK={}",
        crate::office_export::LOCKED
    ));
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "content-office-resource-worker".into(),
        profile.into(),
    ]);
    Ok(args)
}

fn restore_arguments(target: &Path, profile: &str) -> Result<Vec<String>> {
    if target != Path::new("/var") {
        return Err("restore requires the fixed installed encrypted data mount".into());
    }
    let (mode, _, _, _, _, _) = crate::content_restore::parse_profile(profile)?;
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
        "User=root", "Group=root", "UMask=0077", "NoNewPrivileges=yes",
        "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
        "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
        "RestrictNamespaces=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
        "SystemCallArchitectures=native", "AppArmorProfile=luma-content-restore",
        "Environment=PATH=/usr/bin LANG=C LC_ALL=C OPENSSL_CONF=/dev/null",
        "UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT OPENSSL_MODULES SSLKEYLOGFILE PYTHONHOME PYTHONPATH",
        "MemoryHigh=896M", "MemoryMax=960M", "MemorySwapMax=0", "OOMPolicy=kill",
        "TasksMax=4", "CPUQuota=200%", "LimitMEMLOCK=640M", "LimitCORE=0",
        "LimitFSIZE=66M", "DevicePolicy=closed", "KillMode=control-group",
        "TimeoutStopSec=15", "Restart=no", "RuntimeMaxSec=1800",
        "Requires=luma-broker.service", "After=luma-broker.service", "BindsTo=luma-broker.service",
        "Conflicts=sleep.target", "Before=sleep.target", "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_UNIX", "SystemCallFilter=~ptrace process_vm_readv process_vm_writev",
        "ReadOnlyPaths=/var/lib/luma-os/principals",
        "InaccessiblePaths=/var/lib/luma-broker /var/lib/luma-os/admin /var/lib/luma-os/identity /var/lib/luma-os/models /var/lib/luma-os/model-packs /var/lib/luma-os/resource-checkpoint /var/lib/luma-os/content-checkpoint /var/lib/luma-os/utc-windows /var/lib/luma-os/utc-windows-checkpoint /run/luma-admin /run/luma-resource-checkpoint /run/luma-content-checkpoint /run/luma-utc-windows-checkpoint",
        "IOReadBandwidthMax=/var 64M", "IOWriteBandwidthMax=/var 64M",
    ] { args.push(format!("--property={property}")); }
    args.push(if mode == 'r' {
        "--property=ReadOnlyPaths=/var/lib/luma-os/content-store".into()
    } else {
        "--property=ReadWritePaths=/var/lib/luma-os/content-store".into()
    });
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "content-restore-resource-worker".into(),
        profile.into(),
    ]);
    // The caller adds only its exact pinned public InputStage path. Secret
    // PKCS8 bytes travel through locked stdin, never argv or a staged file.
    Ok(args)
}

fn backup_arguments(target: &Path, profile: &str) -> Result<Vec<String>> {
    if target != Path::new("/var") {
        return Err("encrypted backup requires the fixed installed data mount".into());
    }
    crate::content_backup::source_digest(profile)?;
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
        "User=root", "Group=root", "UMask=0077", "NoNewPrivileges=yes",
        "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
        "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
        "RestrictNamespaces=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
        "SystemCallArchitectures=native", "AppArmorProfile=luma-content-backup",
        "MemoryHigh=896M", "MemoryMax=960M", "MemorySwapMax=0", "OOMPolicy=kill",
        "TasksMax=4", "CPUQuota=200%", "LimitMEMLOCK=640M", "LimitCORE=0",
        "LimitFSIZE=66M", "DevicePolicy=closed", "KillMode=control-group",
        "TimeoutStopSec=15", "Restart=no", "RuntimeMaxSec=1800",
        "Requires=luma-broker.service", "After=luma-broker.service", "BindsTo=luma-broker.service",
        "Conflicts=sleep.target", "Before=sleep.target", "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_UNIX",
        "SystemCallFilter=~ptrace process_vm_readv process_vm_writev",
        "ReadOnlyPaths=/var/lib/luma-os/content-store /var/lib/luma-os/principals",
        "InaccessiblePaths=/var/lib/luma-broker /var/lib/luma-os/admin /var/lib/luma-os/identity /var/lib/luma-os/models /var/lib/luma-os/model-packs /var/lib/luma-os/resource-checkpoint /run/luma-admin /run/luma-resource-checkpoint",
        "IOReadBandwidthMax=/var 64M", "IOWriteBandwidthMax=/var 64M",
    ] { args.push(format!("--property={property}")); }
    args.extend([
        "--".into(),
        "/usr/libexec/luma-os/luma-platform".into(),
        "content-backup-resource-worker".into(),
        profile.into(),
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
    await_drainage_checked(&mut || Ok(()))
}
pub(crate) fn await_drainage_checked(check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    let deadline = resource_manager::now()?
        .checked_add(30_000)
        .ok_or("drainage deadline overflow")?;
    loop {
        check()?;
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
    run_checked(target_path, profile, action, || Ok(()))
}
pub(crate) fn run_checked(
    target_path: &Path,
    profile: &model::Profile,
    action: &str,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    crate::require_root()?;
    target(target_path)?;
    // Resolve only the immutable image catalog; never serialize a supplied
    // model URL or runtime command across the launch boundary.
    if model::public_profile(&profile.id)?.resource_binding()? != profile.resource_binding()? {
        return Err("acquisition profile differs from the pinned catalog".into());
    }
    if target_path == Path::new("/var") {
        crate::admin_governance::pack_preparation_authority(profile)?;
    } else {
        let image = crate::platform::CatalogImage::capture(Path::new("/var/lib/luma-os/admin"))?;
        if image.production() || profile.governed.is_some() {
            return Err("governed pack preparation requires installed release/TPM/UTC bootstrap; installer remains manual-only".into());
        }
        image.recheck()?;
    }
    // Do not populate a recycled unit before the broker has observed the old
    // owner gone, the slice empty and its residual charge retained. A unit's
    // successful exit alone is not the corresponding allocation receipt.
    await_drainage_checked(&mut check)?;
    check()?;
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
        check()?;
        if resource_manager::now()? >= deadline {
            return Err("acquisition controller timed out; service outcome uncertain".into());
        }
        Ok(())
    })?;
    // The controller waits for an observed handoff, not just process exit.
    // Residual kernel bytes remain charged; no zero-byte cleanup is inferred.
    await_drainage_checked(&mut check)
}

pub(crate) fn worker(action: &str, id: &str, target_path: &Path) -> Result<()> {
    crate::require_root()?;
    // The confined acquisition worker has no TPM or Admin credentials. Its
    // live broker lease supplies activation/trust checks; this path checks
    // only exact installed/live mount shape and effective block storage.
    target_context(target_path, false)?;
    if fs::read_to_string("/proc/self/cgroup")? != LEAF {
        return Err("acquisition must run in its fixed isolated unit".into());
    }
    if fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n" {
        return Err("acquisition confinement is not enforcing".into());
    }
    let profile = model::public_profile(id)?;
    let lease = resource_manager::WorkerLease::acquire_acquisition(id, target_path)?;
    lease.check()?;
    match action {
        "prepare" => model::prepare_model_contents(target_path, &profile, || lease.check_local())?,
        "verify" => model::verify_acquired_model(target_path, &profile, || lease.check_local())?,
        _ => return Err("invalid acquisition worker action".into()),
    }
    lease.check()?;
    lease.complete_output(&model::pack_completion(&profile, action)?)?;
    lease.check()?;
    // Exit and heartbeat drop do not free bytes. The broker observes the
    // entire slice, surviving cache and this exact kernel owner generation.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inert_installer_helper_has_bounded_separate_domain_and_no_broker_or_serving_route() {
        let base = PathBuf::from(format!(
            "/var/lib/luma-os/staging/install-{}",
            "a".repeat(32)
        ));
        let args = installer_staging_arguments(
            &base.join("root"),
            &base.join("data"),
            &base.join("model.json"),
            &"b".repeat(64),
            4096,
        )
        .unwrap();
        for bound in [
            "--property=MemoryMax=512M",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=16",
            "--property=RuntimeMaxSec=3700",
            "--property=DevicePolicy=closed",
            "--slice=lumainstallerstage.slice",
        ] {
            assert!(args.iter().any(|arg| arg == bound));
        }
        assert!(args.iter().any(|arg| arg == "installer-model-stage-worker"));
        assert!(!args.iter().any(|arg| arg.contains("BindsTo=luma-broker")
            || arg.contains("Requires=luma-broker")
            || arg == "model-serve"));
        assert!(installer_staging_arguments(
            Path::new("/tmp/root"),
            &base.join("data"),
            &base.join("model.json"),
            &"b".repeat(64),
            4096
        )
        .is_err());
        assert!(installer_staging_arguments(
            &base.join("root"),
            Path::new("/var"),
            &base.join("model.json"),
            &"b".repeat(64),
            4096
        )
        .is_err());
        assert!(installer_staging_arguments(
            &base.join("root"),
            &base.join("data"),
            &base.join("model.json"),
            "wrong",
            4096
        )
        .is_err());
    }
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
        let p = model::public_profile(id).unwrap();
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
    #[test]
    fn content_query_launch_never_makes_the_private_store_writable() {
        let digest = "a".repeat(64);
        let profile = format!("content-v1-query-7-{digest}-{digest}");
        let args = arguments(Path::new("/var"), &profile, "content").unwrap();
        assert!(args
            .iter()
            .any(|arg| arg == "--property=ReadOnlyPaths=/var/lib/luma-os/content-store"));
        assert!(!args
            .iter()
            .any(|arg| arg.starts_with("--property=ReadWritePaths=")));
        assert!(args
            .iter()
            .any(|arg| arg == "--property=CapabilityBoundingSet="));
        assert!(args
            .iter()
            .any(|arg| arg == "--property=RestrictAddressFamilies=AF_UNIX"));
        assert!(arguments(Path::new("/tmp"), &profile, "content").is_err());
    }

    #[test]
    fn encrypted_backup_has_its_own_exact_locked_read_only_finite_worker_plan() {
        let id = format!("backup-export-v1-7-4096-{}", "a".repeat(64));
        let args = arguments(Path::new("/var"), &id, "backup-export").unwrap();
        for expected in [
            "--property=MemoryMax=960M",
            "--property=TasksMax=4",
            "--property=LimitMEMLOCK=640M",
            "--property=RuntimeMaxSec=1800",
            "--property=MemorySwapMax=0",
            "--property=CapabilityBoundingSet=",
            "--property=PrivateDevices=yes",
            "--property=DevicePolicy=closed",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=LimitFSIZE=66M",
            "--property=AppArmorProfile=luma-content-backup",
            "--property=ReadOnlyPaths=/var/lib/luma-os/content-store /var/lib/luma-os/principals",
        ] {
            assert!(args.iter().any(|value| value == expected), "{expected}");
        }
        assert_eq!(
            &args[args.len() - 3..],
            [
                "/usr/libexec/luma-os/luma-platform",
                "content-backup-resource-worker",
                &id,
            ]
        );
        assert!(!args
            .iter()
            .any(|value| value.starts_with("--property=ReadWritePaths=")
                || value.contains("CAP_")
                || value.contains("AF_INET")
                || value.starts_with("--property=DeviceAllow=")));
        assert!(arguments(Path::new("/tmp"), &id, "backup-export").is_err());
        for invalid in [
            id.replace("-4096-", "-0-"),
            id.replace("-7-", "-07-"),
            "qwen3-4b-q4-k-m".into(),
            format!("{id}-extra"),
        ] {
            assert!(arguments(Path::new("/var"), &invalid, "backup-export").is_err());
        }
        assert!(arguments(Path::new("/var"), &id, "content").is_err());
    }

    #[test]
    fn restore_modes_have_exact_capability_free_budgets_and_only_write_can_mutate_content() {
        for (mode, steps) in [('r', 0), ('w', 2)] {
            let id = format!(
                "content-restore-v1-{mode}-7-8-4096-{steps}-{}",
                "a".repeat(64)
            );
            let args = arguments(Path::new("/var"), &id, "content-restore").unwrap();
            for property in [
                "--property=MemoryMax=960M",
                "--property=TasksMax=4",
                "--property=LimitMEMLOCK=640M",
                "--property=MemorySwapMax=0",
                "--property=CapabilityBoundingSet=",
                "--property=PrivateDevices=yes",
                "--property=DevicePolicy=closed",
                "--property=RestrictAddressFamilies=AF_UNIX",
                "--property=AppArmorProfile=luma-content-restore",
            ] {
                assert!(args.iter().any(|arg| arg == property), "{property}");
            }
            let effect = if mode == 'r' {
                "ReadOnlyPaths"
            } else {
                "ReadWritePaths"
            };
            assert!(args.contains(&format!(
                "--property={effect}=/var/lib/luma-os/content-store"
            )));
            assert_eq!(
                &args[args.len() - 3..],
                [
                    "/usr/libexec/luma-os/luma-platform",
                    "content-restore-resource-worker",
                    &id
                ]
            );
            assert!(!args.iter().any(|arg| arg.contains("CAP_")
                || arg.contains("AF_INET")
                || arg.starts_with("--property=DeviceAllow=")));
            assert!(arguments(Path::new("/tmp"), &id, "content-restore").is_err());
            assert!(arguments(Path::new("/var"), &id, "backup-export").is_err());
            assert!(arguments(Path::new("/var"), &id, "content").is_err());
        }
        for id in [
            format!("content-restore-v1-r-7-8-4096-1-{}", "a".repeat(64)),
            format!("content-restore-v1-w-7-8-4096-0-{}", "a".repeat(64)),
            format!("content-restore-v1-w-7-8-4096-257-{}", "a".repeat(64)),
        ] {
            assert!(arguments(Path::new("/var"), &id, "content-restore").is_err());
        }
    }

    #[test]
    fn generated_launch_alone_exposes_fixed_kvm_device_and_setpcap() {
        let profile = format!("generated-v1-{}", "a".repeat(64));
        let args = arguments(Path::new("/var"), &profile, "generated").unwrap();
        for expected in [
            "--property=BindPaths=/dev/kvm",
            "--property=DeviceAllow=/dev/kvm rw",
            "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_SETPCAP",
            "--property=RuntimeMaxSec=30",
            "--property=RestrictAddressFamilies=AF_UNIX",
        ] {
            assert!(args.iter().any(|a| a == expected), "{expected}");
        }
        let model = arguments(Path::new("/var"), "qwen3-4b-q4-k-m", "prepare").unwrap();
        assert!(model
            .iter()
            .all(|a| !a.contains("/dev/kvm") && !a.contains("SETPCAP")));
        assert!(arguments(Path::new("/tmp"), &profile, "generated").is_err());
    }

    #[test]
    fn speech_reuses_fixed_physical_pool_without_network_or_kvm_and_separate_import_scope() {
        let profile=format!("speech-asr-v1-{}","a".repeat(64));
        let args=arguments(Path::new("/var"),&profile,"speech").unwrap();
        for expected in ["--property=MemoryMax=512M","--property=MemorySwapMax=0","--property=TasksMax=16",
            "--property=CPUQuota=200%","--property=RuntimeMaxSec=30","--property=PrivateDevices=yes",
            "--property=DevicePolicy=closed","--property=RestrictAddressFamilies=AF_UNIX",
            "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_SETPCAP"] {
            assert!(args.iter().any(|a|a==expected),"{expected}");
        }
        assert_eq!(&args[args.len()-3..],["/usr/libexec/luma-os/luma-platform","speech-resource-worker",&profile]);
        assert!(args.iter().all(|a|!a.contains("/dev/kvm")&&!a.contains("AF_INET")&&!a.starts_with("--property=DeviceAllow=")));
        assert!(arguments(Path::new("/tmp"),&profile,"speech").is_err());
        assert!(arguments(Path::new("/var"),&profile,"speech-import").is_err());
        assert!(arguments(Path::new("/var"),crate::model::speech::ID,"speech").is_err());
        assert!(arguments(Path::new("/var"),"speech-asr-v1-bad","speech").is_err());
    }
}
