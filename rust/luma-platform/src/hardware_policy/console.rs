//! Original-terminal hardware journeys. Typed input is inert; only the genuine
//! original PAM session and independent current finite grants admit effects.
use super::console_input::{Envelope, Inspection, Stage, Task, MAX_INPUT};
use super::*;
use crate::admin_governance::HardwareSession;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

const EXE: &str = "/usr/libexec/luma-os/luma-platform";
fn confinement() -> Result<()> {
    if std::fs::read_to_string("/proc/self/attr/current")? != "luma-hardware (enforce)\n" {
        return Err("hardware operation is not in its fixed enforcing controller profile".into());
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or("hardware capability evidence absent")?
            .trim();
        if u64::from_str_radix(line, 16)? != 0 {
            return Err("hardware controller has an unexpected capability".into());
        }
    }
    for (field, expected) in [("NoNewPrivs:", "1"), ("Seccomp:", "2")] {
        if status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map(str::trim)
            != Some(expected)
        {
            return Err("hardware controller lost its no-new-privileges/seccomp boundary".into());
        }
    }
    let group = std::fs::read_to_string("/proc/self/cgroup")?;
    let nonce = group
        .strip_prefix("0::/system.slice/luma-hardware-")
        .and_then(|value| value.strip_suffix(".service\n"))
        .filter(|value| generation(value))
        .ok_or("hardware controller has no exact transient-unit identity")?;
    for (name, expected) in [
        ("memory.max", 268_435_456u64),
        ("memory.swap.max", 0),
        ("pids.max", 16),
    ] {
        let text = std::fs::read_to_string(format!(
            "/sys/fs/cgroup/system.slice/luma-hardware-{nonce}.service/{name}"
        ))?;
        if text != format!("{expected}\n") {
            return Err("hardware controller lost fixed worker resource bounds".into());
        }
    }
    Ok(())
}
enum Native<'image> {
    Scalar(cgroup::Control),
    Network(network::Control<'image>),
    Backlight(backlight::Control<'image>),
    Power(power::Control<'image>),
}
impl<'image> Native<'image> {
    fn open(adapter: Adapter, worker: Option<Worker>, image: &'image image::Image) -> Result<Self> {
        match (adapter, worker) {
            (Adapter::Backlight, None) => Ok(Self::Backlight(backlight::Control::open(image)?)),
            (Adapter::PowerProfiles, None) => Ok(Self::Power(power::Control::open(image)?)),
            (Adapter::WorkerNetwork, Some(worker)) => {
                Ok(Self::Network(network::Control::open(worker, image)?))
            }
            (
                Adapter::CpuQuota
                | Adapter::CpuWeight
                | Adapter::MemoryProfile
                | Adapter::StorageRate,
                Some(worker),
            ) => Ok(Self::Scalar(cgroup::Control::open(worker)?)),
            _ => Err("hardware request substitutes a compiled global/worker adapter".into()),
        }
    }
    fn target(&self, adapter: Adapter, binding: Option<ResourceBinding>) -> Result<Target> {
        match self {
            Self::Scalar(control) => {
                control.target(adapter, binding.ok_or("worker binding absent")?)
            }
            Self::Network(control) => {
                control.target(binding.ok_or("network worker binding absent")?)
            }
            Self::Backlight(control) if binding.is_none() => control.target(),
            Self::Power(control) if binding.is_none() => control.target(),
            _ => Err("global device cannot borrow resource-manager authority".into()),
        }
    }
    fn setting(&self, adapter: Adapter) -> Result<Setting> {
        match self {
            Self::Scalar(control) => control.observe(adapter),
            Self::Network(control) => control.observe(),
            Self::Backlight(control) => control.observe(),
            Self::Power(control) => control.observe(),
        }
    }
    fn witness(&self) -> Result<Option<DispatchWitness>> {
        match self {
            Self::Scalar(_) => Ok(None),
            Self::Network(control) => control.dispatch_witness(),
            Self::Backlight(control) => control.dispatch_witness(),
            Self::Power(control) => control.dispatch_witness(),
        }
    }
    fn write(
        &self,
        value: &Transition,
        kind: WriteKind,
        handoff: Option<&crate::service::hardware::Handoff>,
    ) -> Result<Observation> {
        match self {
            Self::Scalar(control) => control.compare_write(
                value,
                kind,
                handoff.ok_or("scalar write lacks original Manager exclusion")?,
            ),
            Self::Network(control) => control.compare_write(
                value,
                kind,
                handoff.ok_or("network write lacks original Manager exclusion")?,
            ),
            Self::Backlight(control) if handoff.is_none() => control.compare_write(value, kind),
            Self::Power(control) if handoff.is_none() => control.compare_write(value, kind),
            _ => Err("global write cannot borrow a worker handoff".into()),
        }
    }
    fn observation(
        &self,
        adapter: Adapter,
        binding: Option<ResourceBinding>,
    ) -> Result<Observation> {
        let target = self.target(adapter, binding.clone())?;
        let setting = self.setting(adapter)?;
        if self.target(adapter, binding)? != target {
            return Err("device generation changed during inspection".into());
        }
        let observation = Observation {
            enforcement_sha256: hash(&(
                "luma-native-manual-hardware-readback-v1",
                &target,
                &setting,
            ))?,
            target,
            setting,
            observed_ms: crate::resource_manager::now()?,
        };
        observation.validate()?;
        Ok(observation)
    }
}
fn tty() -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/dev/tty")?;
    if unsafe { libc::isatty(file.as_raw_fd()) } != 1 {
        return Err("hardware control requires the original controlling terminal".into());
    }
    Ok(file)
}
fn line(terminal: &mut File, maximum: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    loop {
        let mut poll = libc::pollfd {
            fd: terminal.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 1000) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err("original hardware terminal disconnected".into());
        }
        if poll.revents & libc::POLLIN == 0 {
            continue;
        }
        let mut byte = [0u8];
        match terminal.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => return Ok(result),
            Ok(1) => {
                if result.len() >= maximum {
                    return Err("hardware terminal line exceeds bound; no dispatch".into());
                }
                result.push(byte[0]);
            }
            Ok(_) => return Err("hardware terminal closed".into()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error.into()),
        }
    }
}
fn confirm(terminal: &mut File, transaction: &str) -> Result<()> {
    writeln!(terminal,"Finite hardware policy {transaction}: exact baseline, requested value, lifetime and undo are printed below. Type APPLY to authenticate and dispatch; anything else cancels.")?;
    terminal.flush()?;
    if line(terminal, 16)? != b"APPLY" {
        return Err("hardware request cancelled before authentication or physical dispatch".into());
    }
    Ok(())
}
fn binding(worker: Worker) -> Result<ResourceBinding> {
    // Current broker status is discovery data, not permission. The actual
    // Manager re-admits the exact tuple and transfers a live EX description.
    let status = crate::resource_manager::acquisition_status()?;
    let epoch = status
        .get("manager_epoch")
        .and_then(|value| value.as_str())
        .filter(|value| generation(value))
        .ok_or("hardware discovery lacks actual current Manager epoch")?;
    let uid = match worker {
        Worker::Model => 989,
        Worker::Acquisition => 0,
    };
    let outstanding = status
        .get("outstanding")
        .and_then(|value| value.as_array())
        .ok_or("hardware worker inventory absent")?;
    let mut leases = Vec::new();
    for entry in outstanding {
        let owner: resources::Owner =
            serde_json::from_value(entry.get("owner").ok_or("worker owner absent")?.clone())?;
        if owner.uid == uid {
            if !matches!(
                entry.get("state").and_then(|value| value.as_str()),
                Some("active" | "draining")
            ) {
                return Err("worker has an unknown nonterminal allocation state".into());
            }
            let lease: resources::Token =
                serde_json::from_value(entry.get("lease").ok_or("worker token absent")?.clone())?;
            if lease.manager_epoch != epoch {
                return Err("worker belongs to another Manager generation".into());
            }
            leases.push(lease);
        }
    }
    if leases.len() > 1 {
        return Err("hardware discovery cannot choose among multiple worker allocations".into());
    }
    Ok(ResourceBinding {
        manager_epoch: epoch.into(),
        lease: leases.pop(),
    })
}
fn require_absent(adapter: Adapter, worker: Option<Worker>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (root,path,magic)=match (adapter,worker) {
        (Adapter::Backlight,None)=>("/sys","/sys/class/backlight/intel_backlight",0x62656572u64),
        (Adapter::CpuQuota|Adapter::CpuWeight|Adapter::MemoryProfile|Adapter::StorageRate|Adapter::WorkerNetwork,Some(Worker::Model))=>
            ("/sys/fs/cgroup","/sys/fs/cgroup/lumamodel.slice",0x63677270u64),
        (Adapter::CpuQuota|Adapter::CpuWeight|Adapter::StorageRate|Adapter::WorkerNetwork,Some(Worker::Acquisition))=>
            ("/sys/fs/cgroup","/sys/fs/cgroup/lumaacquisition.slice",0x63677270u64),
        _=>return Err("this adapter has no qualified device-absence probe; daemon/permission/driver errors are not absence".into()),
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    let metadata = directory.metadata()?;
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != magic
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "device absence is not observed under the actual protected kernel filesystem".into(),
        );
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>Ok(()),
        Err(error)=>Err(error.into()),
        Ok(_)=>Err("the fixed hardware device still exists; do not reinterpret unsupported or changed state as absence".into()),
    }
}
fn inspect(
    image: &image::Image,
    login: &str,
    request: &Inspection,
    grant: &str,
) -> Result<(crate::admin_governance::HardwareProjection, Observation)> {
    request.validate()?;
    if request.boot != current_boot()? {
        return Err("inspection belongs to another actual boot".into());
    }
    let mut session = HardwareSession::open(login, vec![(grant.into(), request.usage()?)], image)?;
    let control = Native::open(request.adapter, request.worker, image)?;
    let resource = request.worker.map(binding).transpose()?;
    let observation = control.observation(request.adapter, resource)?;
    let projection = session.project()?;
    Ok((projection, observation))
}
fn begin_dispatch(
    session: &mut HardwareSession<'_>,
    transition: &Transition,
    kind: WriteKind,
    control: &Native<'_>,
) -> Result<Transition> {
    session.commit(
        Event::DispatchStarted {
            transaction: transition.intent.transaction.clone(),
            expected_revision: transition.revision,
            dispatch: Dispatch {
                kind,
                witness: control.witness()?,
                started_ms: crate::resource_manager::now()?,
            },
        },
        None,
    )
}
fn output(value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() >= 65_536 {
        return Err(
            "hardware response exceeds its finite output scope; no truncated output is emitted"
                .into(),
        );
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn apply(image: &image::Image, login: &str, plan: &Plan, terminal: &mut File) -> Result<()> {
    plan.validate()?;
    writeln!(terminal, "{}", serde_json::to_string(plan)?)?;
    confirm(terminal, &plan.transaction)?;
    let _model = if plan.target.worker == Some(Worker::Model) {
        Some(crate::model::resource_recovery_exclusion()?)
    } else {
        None
    };
    let control = Native::open(plan.target.adapter, plan.target.worker, image)?;
    if control.target(plan.target.adapter, plan.target.resource.clone())? != plan.target
        || control.setting(plan.target.adapter)? != plan.before
    {
        return Err("reviewed hardware baseline or exact device generation changed; obtain a new review and grants".into());
    }
    let mut session = HardwareSession::open(
        login,
        vec![
            (
                plan.apply_grant.clone(),
                plan.usage(finite_grants::Action::ApplyHardware)?,
            ),
            (
                plan.restore_grant.clone(),
                plan.usage(finite_grants::Action::RestoreHardware)?,
            ),
        ],
        image,
    )?;
    let mut transition = session.prepare(plan.clone())?;
    if transition.intent.digest()? != plan.digest()? {
        return Err(
            "prepared hardware intent no longer binds the exact human-reviewed plan".into(),
        );
    }
    let handoff = if plan.target.worker.is_some() {
        Some(crate::service::hardware::Handoff::open(
            &transition.intent,
            handoff::Purpose::Apply,
        )?)
    } else {
        None
    };
    transition = begin_dispatch(&mut session, &transition, WriteKind::Apply, &control)?;
    let outcome = (|| -> Result<()> {
        let observed = session.dispatch(
            &plan.transaction,
            transition.revision,
            WriteKind::Apply,
            |value| control.write(value, WriteKind::Apply, handoff.as_ref()),
        )?;
        transition = session.commit(
            Event::Applied {
                transaction: plan.transaction.clone(),
                expected_revision: transition.revision,
                observation: observed,
            },
            None,
        )?;
        writeln!(terminal,"Applied and independently read back. Enter q then Enter to restore early. Authorization and original allocation remain continuously checked.")?;
        loop {
            if crate::resource_manager::now()? >= transition.intent.deadline_ms {
                break;
            }
            if let Some(value) = &handoff {
                if value.check(&transition.intent).is_err() {
                    break;
                }
            }
            session.project()?;
            if control.target(plan.target.adapter, plan.target.resource.clone())? != plan.target
                || control.setting(plan.target.adapter)? != plan.after
            {
                return Err(
                    "hardware state changed outside this policy; no blind restoration".into(),
                );
            }
            let mut poll = libc::pollfd {
                fd: terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 100) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err("original hardware terminal lost".into());
            }
            if poll.revents & libc::POLLIN != 0 {
                let mut bytes = [0u8; 64];
                let count = terminal.read(&mut bytes)?;
                if count == 0 {
                    return Err("original hardware terminal closed".into());
                }
                if bytes[..count].contains(&b'q') || bytes[..count].contains(&b'Q') {
                    break;
                }
            }
        }
        transition = begin_dispatch(&mut session, &transition, WriteKind::Restore, &control)?;
        let observed = session.dispatch(
            &plan.transaction,
            transition.revision,
            WriteKind::Restore,
            |value| control.write(value, WriteKind::Restore, handoff.as_ref()),
        )?;
        transition = session.commit(
            Event::Restored {
                transaction: plan.transaction.clone(),
                expected_revision: transition.revision,
                observation: observed,
            },
            None,
        )?;
        Ok(())
    })();
    if outcome.is_ok() {
        if let Some(value) = handoff {
            value.finish()?;
        }
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"transaction":plan.transaction,"phase":"restored","revision":transition.revision,"resource_released":false,"native_qualified":false})
        );
    } else {
        // No new PAM/grant and no new external message after an uncertain
        // dispatch. Scalar precommitted cleanup is independently current-NV
        // verified; a queued daemon effect remains fenced for fresh recovery.
        let cleanup =
            crate::admin_governance::with_hardware_cleanup(image, &plan.transaction, |value| {
                control.write(value, WriteKind::Restore, handoff.as_ref())
            });
        writeln!(terminal,"Policy not terminally completed. Current-NV precommitted cleanup readback: {}. Protected obligation and any physical charges remain until explicit Admin reconciliation.",if cleanup.is_ok(){"baseline observed"}else{"not established; do not assume restored"})?;
    }
    outcome
}
pub(crate) fn run(login: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    confinement()?;
    let stage = Stage::current(login)?;
    let image = image::Image::preflight()?;
    let mut terminal = tty()?;
    stage.check()?;
    match &stage.envelope.task {
        Task::ReviewInspection { inspection } => output(&inspection.usage()?)?,
        Task::ReviewPlan { plan } => output(
            &serde_json::json!({"plan_sha256":plan.digest()?,"independent_scopes":[plan.usage(finite_grants::Action::ApplyHardware)?,plan.usage(finite_grants::Action::RestoreHardware)?],"authority":false}),
        )?,
        Task::Inspect { inspection, grant } => {
            let (projection, observation) = inspect(&image, login, inspection, grant)?;
            let key = observation.target.key()?;
            let mut latest: Option<&Transition> = None;
            for value in projection.state.transactions.values() {
                if value.intent.target.key()? == key
                    && latest.map_or(true, |prior| value.revision > prior.revision)
                {
                    latest = Some(value);
                }
            }
            output(
                &serde_json::json!({"schema_version":1,"observation":observation,"subject":projection.subject,"subject_generation":projection.subject_generation,"latest_policy":latest,"image_manifest_sha256":image.manifest_sha256,"authority":false,"native_qualified":false}),
            )?;
        }
        Task::Apply { plan } => apply(&image, login, plan, &mut terminal)?,
        Task::ReviewReconciliation {
            inspection,
            grant,
            transaction,
            disposition,
        } => {
            let (projection, observation) = if *disposition == Reconciliation::DeviceUnavailable {
                if inspection.boot != current_boot()? {
                    return Err("absence inspection belongs to another boot".into());
                }
                let mut session = HardwareSession::open(
                    login,
                    vec![(grant.clone(), inspection.usage()?)],
                    &image,
                )?;
                require_absent(inspection.adapter, inspection.worker)?;
                (session.project()?, None)
            } else {
                let (projection, observation) = inspect(&image, login, inspection, grant)?;
                (projection, Some(observation))
            };
            let old = projection
                .state
                .transactions
                .get(transaction)
                .ok_or("unknown protected hardware transaction")?;
            if old.intent.target.adapter != inspection.adapter
                || old.intent.target.worker != inspection.worker
            {
                return Err(
                    "reconciliation inspection substitutes the original fixed adapter/worker"
                        .into(),
                );
            }
            if let Some(witness) = old.ambiguous_external_dispatch() {
                witness.require_exited(&old.intent.target.boot)?;
            }
            let plan = ReconciliationPlan {
                schema_version: 1,
                transaction: transaction.clone(),
                expected_revision: old.revision,
                disposition: *disposition,
                observation: observation.map(|value| ReviewedObservation {
                    target: value.target,
                    setting: value.setting,
                }),
            };
            let usage = plan.usage(&old.intent)?;
            output(
                &serde_json::json!({"schema_version":1,"plan":plan,"fresh_restore_scope":usage,"authority":false}),
            )?;
        }
        Task::Reconcile { plan, grant } => {
            let state = crate::admin_governance::current_hardware_state()?;
            let old = state
                .transactions
                .get(&plan.transaction)
                .ok_or("unknown protected hardware transaction")?;
            let mut session = HardwareSession::open(
                login,
                vec![(grant.clone(), plan.usage(&old.intent)?)],
                &image,
            )?;
            let observed = match &plan.observation {
                Some(reviewed) => {
                    let control =
                        Native::open(reviewed.target.adapter, reviewed.target.worker, &image)?;
                    let observed = control.observation(
                        reviewed.target.adapter,
                        reviewed.target.worker.map(binding).transpose()?,
                    )?;
                    if observed.target != reviewed.target || observed.setting != reviewed.setting {
                        return Err("reconciliation device/state changed after review; obtain a new finite scope".into());
                    }
                    Some(observed)
                }
                None => {
                    require_absent(old.intent.target.adapter, old.intent.target.worker)?;
                    None
                }
            };
            let value = session.commit(
                Event::Reconciled {
                    transaction: plan.transaction.clone(),
                    expected_revision: plan.expected_revision,
                    disposition: plan.disposition,
                    observation: observed,
                },
                Some(grant),
            )?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"phase":"reconciled","revision":value.revision,"resource_released":false,"native_qualified":false})
            );
        }
    }
    stage.check()
}
pub(crate) fn cleanup(transaction: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    confinement()?;
    let image = image::Image::preflight()?;
    let state = crate::admin_governance::current_hardware_state()?;
    let value = state
        .transactions
        .get(transaction)
        .ok_or("no protected hardware cleanup obligation")?;
    if matches!(value.phase, Phase::Restored | Phase::Reconciled) {
        return Ok(());
    }
    let _model = if value.intent.target.worker == Some(Worker::Model) {
        Some(crate::model::resource_recovery_exclusion()?)
    } else {
        None
    };
    let control = Native::open(
        value.intent.target.adapter,
        value.intent.target.worker,
        &image,
    )?;
    let handoff = if value.intent.target.worker.is_some() {
        Some(crate::service::hardware::Handoff::open(
            &value.intent,
            handoff::Purpose::CommittedCleanup,
        )?)
    } else {
        None
    };
    crate::admin_governance::with_hardware_cleanup(&image, transaction, |current| {
        control.write(current, WriteKind::Restore, handoff.as_ref())
    })?;
    println!(
        "{}",
        serde_json::json!({"schema_version":1,"transaction":transaction,"baseline_observed":true,"journal_resolved":false,"resource_released":false})
    );
    Ok(())
}
pub(crate) fn launch(login: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let mut terminal = tty()?;
    writeln!(terminal,"Enter one bounded typed hardware Task JSON line. This does not grant authority; inspection/apply/recovery require their separately issued finite scopes.")?;
    let task = Task::parse(&line(&mut terminal, MAX_INPUT)?)?;
    let stage = Stage::capture(login, task)?;
    let arguments = launch_arguments(&stage.envelope)?;
    stage.check()?;
    let status = Command::new("/usr/bin/systemd-run")
        .args(&arguments)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::from(terminal.try_clone()?))
        .stdout(Stdio::from(terminal.try_clone()?))
        .stderr(Stdio::from(terminal))
        .status()?;
    stage.check()?;
    if !status.success() {
        return Err("bounded hardware service refused or stopped; inspect protected obligation before retrying".into());
    }
    Ok(())
}
fn launch_arguments(envelope: &Envelope) -> Result<Vec<String>> {
    envelope.validate()?;
    let mut arguments = vec![
        "--pty",
        "--wait",
        "--collect",
        "--quiet",
        "--service-type=exec",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    arguments.push(format!("--unit=luma-hardware-{}", envelope.unit));
    for property in ["User=root","Group=root","AppArmorProfile=luma-hardware","NoNewPrivileges=yes","CapabilityBoundingSet=","AmbientCapabilities=","UMask=0077",
        "ProtectSystem=strict","ProtectHome=yes","PrivateTmp=yes","PrivateDevices=no","ProtectKernelModules=yes","RestrictAddressFamilies=AF_UNIX","RestrictNamespaces=yes",
        "LockPersonality=yes","MemoryDenyWriteExecute=yes","SystemCallArchitectures=native","SystemCallFilter=@system-service @memlock","SystemCallFilter=~@mount @raw-io @reboot @swap @obsolete @debug",
        "LimitCORE=0","LimitNOFILE=512","LimitMEMLOCK=262144","MemoryMax=268435456","MemorySwapMax=0","TasksMax=16","CPUQuota=50%","RuntimeMaxSec=40","TimeoutStopSec=6","KillMode=control-group",
        "ReadWritePaths=/run/luma-hardware /run/luma-admin /var/lib/luma-os/admin /var/lib/luma-os/policy-decisions /var/lib/luma-os/model.lock /sys/fs/cgroup/lumamodel.slice /sys/fs/cgroup/lumaacquisition.slice -/sys/class/backlight/intel_backlight/brightness"] {
        arguments.push(format!("--property={property}"));
    }
    if let Some(transaction) = envelope.task.cleanup_transaction() {
        arguments.push(format!(
            "--property=ExecStopPost={EXE} hardware-cleanup {transaction}"
        ));
    }
    arguments.extend([
        EXE.into(),
        "hardware-console".into(),
        envelope.login.clone(),
    ]);
    Ok(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn envelope() -> Envelope {
        Envelope {
            schema_version: 1,
            unit: "ab".repeat(16),
            login: "admin".into(),
            task: Task::ReviewInspection {
                inspection: Inspection {
                    schema_version: 1,
                    adapter: Adapter::Backlight,
                    worker: None,
                    boot: "cd".repeat(16),
                },
            },
        }
    }
    #[test]
    fn actual_launch_contract_is_closed_capability_free_and_original_pty_only() {
        let envelope = envelope();
        let arguments = launch_arguments(&envelope).unwrap();
        for expected in [
            "--pty",
            "--wait",
            "--property=AppArmorProfile=luma-hardware",
            "--property=CapabilityBoundingSet=",
            "--property=NoNewPrivileges=yes",
            "--property=MemoryMax=268435456",
            "--property=TasksMax=16",
            "--property=LimitMEMLOCK=262144",
        ] {
            assert!(arguments.contains(&expected.into()));
        }
        assert_eq!(
            &arguments[arguments.len() - 3..],
            &[EXE.to_owned(), "hardware-console".into(), "admin".into()]
        );
        assert!(!arguments.iter().any(|value| value.contains("ExecStopPost")));
        let mut changed = envelope;
        changed.login = "admin --property=User=other".into();
        assert!(launch_arguments(&changed).is_err());
    }
    #[test]
    fn cleanup_target_is_only_the_exact_precommitted_literal_transaction() {
        let mut value = envelope();
        value.task = Task::Apply {
            plan: super::super::tests::intent().plan().unwrap(),
        };
        let arguments = launch_arguments(&value).unwrap();
        assert!(arguments.contains(&format!(
            "--property=ExecStopPost={EXE} hardware-cleanup cpu-policy-one"
        )));
        if let Task::Apply { plan } = &mut value.task {
            plan.transaction = "cpu-policy;rm".into();
        }
        assert!(launch_arguments(&value).is_err());
    }
    #[test]
    fn finite_output_budget_includes_its_literal_terminal_line_terminator() {
        // JSON adds two quote bytes; a further newline would exceed 65,536.
        assert!(output(&"x".repeat(65_534)).is_err());
        assert!(output(&"x".repeat(65_535)).is_err());
    }
}
