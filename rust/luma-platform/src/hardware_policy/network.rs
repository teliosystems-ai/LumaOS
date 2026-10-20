//! Fixed, fully-drained worker-slice network policy. Only the current image's
//! PID1 may replace IPAddressAllow; IPAddressDeny=any remains immutable. Actual
//! attached/effective BPF IDs are queried independently before and after the
//! one typed call. This is not proof that other network/LSM layers allow data.
use super::daemon_observer::{Proof, Role};
use super::sd_bus::{Budget, Bus, Message, Owner};
use super::{cgroup, daemon_observer, network_query};
use super::{
    hash, DispatchWitness, NetworkProfile, Observation, Phase, ResourceBinding, Result, Setting,
    Target, Transition, Worker, WriteKind,
};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};

const SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER: &str = "/org/freedesktop/systemd1";
const SLICE: &str = "org.freedesktop.systemd1.Slice";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const VERSION: &str = "255.4-1ubuntu8.17";
type Address = (i32, Vec<u8>, u32);
fn names(worker: Worker) -> (&'static str, &'static str, &'static str) {
    match worker {
        Worker::Model => (
            "lumamodel.slice",
            "/org/freedesktop/systemd1/unit/lumamodel_2eslice",
            "/lumamodel.slice",
        ),
        Worker::Acquisition => (
            "lumaacquisition.slice",
            "/org/freedesktop/systemd1/unit/lumaacquisition_2eslice",
            "/lumaacquisition.slice",
        ),
    }
}
fn any() -> Vec<Address> {
    vec![
        (libc::AF_INET, vec![0; 4], 0),
        (libc::AF_INET6, vec![0; 16], 0),
    ]
}
fn localhost() -> Vec<Address> {
    let mut v6 = vec![0; 16];
    v6[15] = 1;
    vec![
        (libc::AF_INET, vec![127, 0, 0, 0], 8),
        (libc::AF_INET6, v6, 128),
    ]
}
fn canonical(mut addresses: Vec<Address>) -> Result<Vec<Address>> {
    if addresses.len() > 2 {
        return Err("network prefix list exceeds the two compiled families".into());
    }
    for (family, bytes, prefix) in &addresses {
        let size = match *family {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => return Err("network family is not IPv4 or IPv6".into()),
        };
        if bytes.len() != size || *prefix > size as u32 * 8 {
            return Err("network address/prefix has no exact bounded family shape".into());
        }
    }
    addresses.sort();
    if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate network prefix cannot be adopted".into());
    }
    Ok(addresses)
}
fn setting(deny: Vec<Address>, allow: Vec<Address>) -> Result<Setting> {
    if canonical(deny)? != canonical(any())? {
        return Err("the fixed slice no longer denies all IPv4/IPv6 by default".into());
    }
    let allow = canonical(allow)?;
    let profile = if allow.is_empty() {
        NetworkProfile::DenyAll
    } else if allow == canonical(localhost())? {
        NetworkProfile::LoopbackOnly
    } else {
        return Err("network allow prefixes are outside the exact localhost/empty contract".into());
    };
    Ok(Setting::WorkerNetwork { profile })
}
fn prefixes(setting: &Setting) -> Result<Vec<Address>> {
    match setting {
        Setting::WorkerNetwork {
            profile: NetworkProfile::DenyAll,
        } => Ok(Vec::new()),
        Setting::WorkerNetwork {
            profile: NetworkProfile::LoopbackOnly,
        } => Ok(localhost()),
        _ => Err("network adapter cannot select an unrestricted or caller-chosen prefix".into()),
    }
}
fn enter(message: &mut Message<'_>, kind: u8, signature: &str) -> Result<()> {
    if !message.enter(kind, signature)? {
        return Err("network property lacks its exact typed container".into());
    }
    Ok(())
}
fn read_addresses(message: &mut Message<'_>) -> Result<Vec<Address>> {
    enter(message, b'v', "a(iayu)")?;
    enter(message, b'a', "(iayu)")?;
    let mut addresses = Vec::new();
    while !message.at_end()? {
        if addresses.len() >= 2 {
            return Err("network property has more than two address families".into());
        }
        enter(message, b'r', "iayu")?;
        let family = message.read_i32()?;
        enter(message, b'a', "y")?;
        let mut bytes = Vec::new();
        while !message.at_end()? {
            if bytes.len() >= 16 {
                return Err("network address exceeds IPv6 bound".into());
            }
            bytes.push(message.read_u8()?);
        }
        message.exit()?;
        let prefix = message.read_u32()?;
        message.exit()?;
        addresses.push((family, bytes, prefix));
    }
    message.exit()?;
    message.exit()?;
    message.end()?;
    canonical(addresses)
}
fn append_addresses(message: &mut Message<'_>, addresses: &[Address]) -> Result<()> {
    message.open(b'v', "a(iayu)")?;
    message.open(b'a', "(iayu)")?;
    for (family, bytes, prefix) in addresses {
        message.open(b'r', "iayu")?;
        message.append_i32(*family)?;
        message.open(b'a', "y")?;
        for byte in bytes {
            message.append_u8(*byte)?;
        }
        message.close()?;
        message.append_u32(*prefix)?;
        message.close()?;
    }
    message.close()?;
    message.close()
}
fn string(
    bus: &Bus,
    owner: &Owner,
    path: &str,
    interface: &str,
    name: &str,
    budget: &Budget,
) -> Result<String> {
    let mut reply = bus.property(owner, path, interface, name, budget)?;
    enter(&mut reply, b'v', "s")?;
    let value = reply.read_string(128)?;
    reply.exit()?;
    reply.end()?;
    budget.check()?;
    Ok(value)
}
fn ancestors(direction: &network_query::Direction) -> Vec<u32> {
    let mut values = direction
        .effective_ids
        .iter()
        .copied()
        .filter(|value| !direction.direct_ids.contains(value))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}
fn same_ancestors(first: &network_query::Reply, second: &network_query::Reply) -> Result<()> {
    first.preserved_ancestors(second)
}
fn own_programs(reply: &network_query::Reply) -> Result<()> {
    for direction in [&reply.ingress, &reply.egress] {
        if direction.direct_flags != 2
            || direction.direct_ids.len() != 1
            || direction.direct_ids[0] == 0
            || !direction.effective_ids.contains(&direction.direct_ids[0])
        {
            return Err(
                "fixed slice lacks its one actual multi-attach own IP filter per direction".into(),
            );
        }
    }
    if reply.ingress.direct_ids == reply.egress.direct_ids {
        return Err("ingress/egress do not expose independently compiled own programs".into());
    }
    Ok(())
}
fn replaced_programs(before: &network_query::Reply, after: &network_query::Reply) -> Result<()> {
    own_programs(before)?;
    own_programs(after)?;
    same_ancestors(before, after)?;
    for old in before
        .ingress
        .direct_ids
        .iter()
        .chain(&before.egress.direct_ids)
    {
        if after.ingress.effective_ids.contains(old) || after.egress.effective_ids.contains(old) {
            return Err("changed IP properties retained an old effective own filter; do not claim kernel policy replacement".into());
        }
    }
    Ok(())
}
fn require_dispatch(
    transition: &Transition,
    kind: WriteKind,
    witness: &DispatchWitness,
    unwritten: bool,
) -> Result<()> {
    if unwritten {
        if transition.phase != Phase::Prepared || !transition.dispatches.is_empty() {
            return Err("network baseline cannot erase a possibly queued external dispatch".into());
        }
        return Ok(());
    }
    if transition.dispatches.len()
        != match kind {
            WriteKind::Apply => 1,
            WriteKind::Restore => 2,
        }
        || kind == WriteKind::Restore && transition.phase != Phase::Applied
        || transition
            .dispatches
            .iter()
            .any(|dispatch| dispatch.witness.as_ref() != Some(witness))
        || transition.dispatches.last().map(|dispatch| dispatch.kind) != Some(kind)
    {
        return Err("network Set lacks the exact durable dispatch and pinned PID1 witness".into());
    }
    Ok(())
}
pub(crate) struct Control<'image> {
    image: &'image super::image::Image,
    cgroup: cgroup::Control,
    bus: Bus,
    owner: Owner,
    pin: File,
    process: Proof,
    baseline: network_query::Reply,
}
impl<'image> Control<'image> {
    pub(crate) fn open(worker: Worker, image: &'image super::image::Image) -> Result<Self> {
        let budget = Budget::new()?;
        image.check()?;
        let cgroup = cgroup::Control::open(worker)?;
        cgroup.drained()?;
        budget.check()?;
        let bus = Bus::open(&budget)?;
        let owner = bus.owner(SERVICE, &budget)?;
        if owner.pid != 1 || owner.uid != 0 {
            return Err("fixed systemd Manager is not actual native PID1".into());
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, 1, 0) } as i32;
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pin = unsafe { File::from_raw_fd(fd) };
        let process = daemon_observer::verify(Role::SystemdManager, &pin, &budget)?;
        if process.pid != owner.pid
            || process.start_ticks != owner.start_ticks
            || process.uid != owner.uid
        {
            return Err("actual Manager name and process proofs disagree".into());
        }
        let baseline = network_query::query(cgroup.descriptor(), worker, &budget)?;
        own_programs(&baseline)?;
        let result = Self {
            image,
            cgroup,
            bus,
            owner,
            pin,
            process,
            baseline,
        };
        result.observe_with(&budget)?;
        result.verify_proofs(&budget)?;
        Ok(result)
    }
    fn check(&self, budget: &Budget) -> Result<()> {
        budget.check()?;
        self.image.check()?;
        self.cgroup.check()?;
        self.cgroup.drained()?;
        self.bus.check_owner(SERVICE, &self.owner, budget)?;
        let mut poll = libc::pollfd {
            fd: self.pin.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            return Err("original PID1 exited or is unobserved".into());
        }
        if string(&self.bus, &self.owner, MANAGER, SERVICE, "Version", budget)? != VERSION {
            return Err(
                "systemd Manager version differs from the pinned Ubuntu255.4 package".into(),
            );
        }
        let (unit, path, cgroup) = names(self.cgroup.worker());
        let mut lookup = self
            .bus
            .method(&self.owner.unique_name, MANAGER, SERVICE, "GetUnit")?;
        lookup.append_string(unit)?;
        let mut reply = lookup.call(budget)?;
        if reply.read_object_path()? != path {
            return Err("fixed slice resolves to another Manager object".into());
        }
        reply.end()?;
        for (name, expected) in [
            ("Id", unit),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "active"),
        ] {
            if string(&self.bus, &self.owner, path, UNIT, name, budget)? != expected {
                return Err("fixed native slice identity/load/lifecycle changed".into());
            }
        }
        if string(&self.bus, &self.owner, path, SLICE, "ControlGroup", budget)? != cgroup {
            return Err("Manager slice no longer names the held cgroup directory".into());
        }
        for name in ["IPIngressFilterPath", "IPEgressFilterPath"] {
            let mut reply = self.bus.property(&self.owner, path, SLICE, name, budget)?;
            enter(&mut reply, b'v', "as")?;
            enter(&mut reply, b'a', "s")?;
            if !reply.at_end()? {
                return Err(
                    "custom IP filter paths cannot be adopted as the fixed built-in own programs"
                        .into(),
                );
            }
            reply.exit()?;
            reply.exit()?;
            reply.end()?;
        }
        let mut reply = self.bus.property(&self.owner, path, UNIT, "Job", budget)?;
        enter(&mut reply, b'v', "(uo)")?;
        enter(&mut reply, b'r', "uo")?;
        if reply.read_u32()? != 0 || reply.read_object_path()? != "/" {
            return Err("network slice has a queued/in-progress systemd job".into());
        }
        reply.exit()?;
        reply.exit()?;
        reply.end()?;
        budget.check()
    }
    fn verify_proofs(&self, budget: &Budget) -> Result<()> {
        self.check(budget)?;
        self.bus.verify_proofs(budget)?;
        if daemon_observer::verify(Role::SystemdManager, &self.pin, budget)? != self.process {
            return Err(
                "PID1 executable/credentials changed despite retained process generation".into(),
            );
        }
        self.check(budget)
    }
    fn observe_with(&self, budget: &Budget) -> Result<Setting> {
        self.check(budget)?;
        let path = names(self.cgroup.worker()).1;
        let mut deny = self
            .bus
            .property(&self.owner, path, SLICE, "IPAddressDeny", budget)?;
        let deny = read_addresses(&mut deny)?;
        let mut allow = self
            .bus
            .property(&self.owner, path, SLICE, "IPAddressAllow", budget)?;
        let allow = read_addresses(&mut allow)?;
        let value = setting(deny, allow)?;
        budget.check()?;
        Ok(value)
    }
    fn query(&self, budget: &Budget) -> Result<network_query::Reply> {
        let reply = network_query::query(self.cgroup.descriptor(), self.cgroup.worker(), budget)?;
        own_programs(&reply)?;
        same_ancestors(&self.baseline, &reply)?;
        Ok(reply)
    }
    fn target_with(&self, resource: ResourceBinding, budget: &Budget) -> Result<Target> {
        if resource.lease.is_some() {
            return Err("network changes require actual complete drainage, never an active allocation lease".into());
        }
        self.check(budget)?;
        let mut target = self.cgroup.network_base(resource)?;
        let attached = self.query(budget)?;
        target.capability_sha256 = hash(&(
            "luma-fixed-systemd-worker-network-capability-v1",
            &target.capability_sha256,
            &self.process,
            &self.owner.unique_name,
            self.bus.generation(),
            VERSION,
            &self.image.closure_sha256,
            ancestors(&attached.ingress),
            ancestors(&attached.egress),
            attached.ingress.effective_flags,
            attached.egress.effective_flags,
        ))?;
        target.adapter_sha256 = hash(&(
            "luma-native-systemd-worker-network-source-v1",
            include_bytes!("network.rs").as_slice(),
            include_bytes!("sd_bus.rs").as_slice(),
            include_bytes!("network_query.rs").as_slice(),
        ))?;
        target.validate()?;
        budget.check()?;
        Ok(target)
    }
    pub(crate) fn target(&self, resource: ResourceBinding) -> Result<Target> {
        let budget = Budget::new()?;
        self.verify_proofs(&budget)?;
        let target = self.target_with(resource, &budget)?;
        self.verify_proofs(&budget)?;
        Ok(target)
    }
    pub(crate) fn observe(&self) -> Result<Setting> {
        let budget = Budget::new()?;
        self.verify_proofs(&budget)?;
        let value = self.observe_with(&budget)?;
        self.query(&budget)?;
        self.verify_proofs(&budget)?;
        Ok(value)
    }
    fn witness(&self) -> DispatchWitness {
        DispatchWitness {
            pid: self.owner.pid,
            start_ticks: self.owner.start_ticks,
            unique_name: self.owner.unique_name.clone(),
            exe_sha256: self.process.exe_sha256.clone(),
        }
    }
    pub(crate) fn dispatch_witness(&self) -> Result<Option<DispatchWitness>> {
        self.verify_proofs(&Budget::new()?)?;
        Ok(Some(self.witness()))
    }
    pub(crate) fn compare_write(
        &self,
        transition: &Transition,
        kind: WriteKind,
        handoff: &crate::service::hardware::Handoff,
    ) -> Result<Observation> {
        let budget = Budget::new()?;
        let intent = &transition.intent;
        intent.validate()?;
        if kind == WriteKind::Apply && transition.phase != Phase::Prepared
            || kind == WriteKind::Restore
                && !matches!(transition.phase, Phase::Prepared | Phase::Applied)
        {
            return Err("network write is outside its exact prepared/applied lifecycle".into());
        }
        let check_handoff = || match kind {
            WriteKind::Apply => handoff.check(intent),
            WriteKind::Restore => handoff.check_restore(intent),
        };
        check_handoff()?;
        self.verify_proofs(&budget)?;
        if self.target_with(
            intent
                .target
                .resource
                .clone()
                .ok_or("network resource epoch absent")?,
            &budget,
        )? != intent.target
        {
            return Err(
                "network target is not the current drained worker/daemon/filter generation".into(),
            );
        }
        let observed = self.observe_with(&budget)?;
        let unwritten = kind == WriteKind::Restore
            && transition.phase == Phase::Prepared
            && observed == intent.before;
        let (expected, replacement) = match kind {
            WriteKind::Apply => (&intent.before, &intent.after),
            WriteKind::Restore => (&intent.after, &intent.before),
        };
        prefixes(&intent.before)?;
        let addresses = prefixes(replacement)?;
        if !unwritten && observed != *expected {
            return Err("network external drift prevents exact apply/undo; no retry".into());
        }
        require_dispatch(transition, kind, &self.witness(), unwritten)?;
        let before = self.query(&budget)?;
        if !unwritten {
            check_handoff()?;
            self.check(&budget)?;
            let mut request = self.bus.method(
                &self.owner.unique_name,
                MANAGER,
                SERVICE,
                "SetUnitProperties",
            )?;
            request.append_string(names(self.cgroup.worker()).0)?;
            request.append_bool(true)?;
            request.open(b'a', "(sv)")?;
            request.open(b'r', "sv")?;
            request.append_string("IPAddressAllow")?;
            append_addresses(&mut request, &addresses)?;
            request.close()?;
            request.close()?;
            // One request only. Timeout cannot revoke a message already queued
            // in PID1: durable DispatchStarted leaves ambiguity fenced until
            // the old exact daemon exits and fresh Admin reconciliation.
            request.call(&budget)?.end()?;
        }
        let actual = self.observe_with(&budget)?;
        if actual != *replacement {
            return Err(
                "network policy failed exact complete readback; preserve obligation".into(),
            );
        }
        let after = self.query(&budget)?;
        if unwritten {
            same_ancestors(&before, &after)?;
        } else {
            replaced_programs(&before, &after)?;
        }
        self.verify_proofs(&budget)?;
        check_handoff()?;
        let observation = Observation {
            target: intent.target.clone(),
            setting: actual,
            observed_ms: crate::resource_manager::now()?,
            enforcement_sha256: hash(&(
                if unwritten {
                    "luma-network-prepared-baseline-observed-no-write-v1"
                } else {
                    "luma-network-one-runtime-set-actual-effective-bpf-v1"
                },
                &intent.target,
                &before,
                &after,
                replacement,
            ))?,
        };
        observation.validate()?;
        budget.check()?;
        Ok(observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_fixed_ipv4_ipv6_denyall_or_complete_localhost_are_adopted() {
        assert_eq!(
            setting(any(), Vec::new()).unwrap(),
            Setting::WorkerNetwork {
                profile: NetworkProfile::DenyAll
            }
        );
        assert_eq!(
            setting(any(), localhost()).unwrap(),
            Setting::WorkerNetwork {
                profile: NetworkProfile::LoopbackOnly
            }
        );
        let mut reversed = localhost();
        reversed.reverse();
        assert_eq!(
            setting(any(), reversed).unwrap(),
            Setting::WorkerNetwork {
                profile: NetworkProfile::LoopbackOnly
            }
        );
        for allow in [
            vec![(libc::AF_INET, vec![127, 0, 0, 1], 32)],
            vec![(libc::AF_INET, vec![0; 4], 0)],
            localhost()[..1].to_vec(),
            vec![(libc::AF_INET, vec![127, 0, 0, 0], 8); 2],
        ] {
            assert!(setting(any(), allow).is_err());
        }
        assert!(setting(Vec::new(), localhost()).is_err());
        assert!(setting(any()[..1].to_vec(), localhost()).is_err());
        assert!(prefixes(&Setting::WorkerNetwork {
            profile: NetworkProfile::UnrestrictedBaseline
        })
        .is_err());
        for address in [
            (libc::AF_UNIX, vec![0; 4], 0),
            (libc::AF_INET, vec![0; 16], 0),
            (libc::AF_INET6, vec![0; 16], 129),
        ] {
            assert!(canonical(vec![address]).is_err());
        }
    }
    #[test]
    fn actual_library_network_prefix_variant_is_whole_exact_and_bounded() {
        let bus = Bus::fixture().unwrap();
        for addresses in [any(), localhost(), Vec::new()] {
            let mut message = bus
                .method(":1.23", MANAGER, SERVICE, "SetUnitProperties")
                .unwrap();
            append_addresses(&mut message, &addresses).unwrap();
            message.freeze_fixture().unwrap();
            assert_eq!(
                read_addresses(&mut message).unwrap(),
                canonical(addresses).unwrap()
            );
        }
        let mut message = bus
            .method(":1.23", MANAGER, SERVICE, "SetUnitProperties")
            .unwrap();
        append_addresses(&mut message, &localhost()).unwrap();
        message.append_u32(1).unwrap();
        message.freeze_fixture().unwrap();
        assert!(read_addresses(&mut message).is_err());
        let mut message = bus
            .method(":1.23", MANAGER, SERVICE, "SetUnitProperties")
            .unwrap();
        append_addresses(&mut message, &vec![(libc::AF_INET, vec![0; 17], 0)]).unwrap();
        message.freeze_fixture().unwrap();
        assert!(read_addresses(&mut message).is_err());
    }
    #[test]
    fn no_addressable_unit_or_cgroup_path_is_caller_selected() {
        assert_eq!(
            names(Worker::Model),
            (
                "lumamodel.slice",
                "/org/freedesktop/systemd1/unit/lumamodel_2eslice",
                "/lumamodel.slice"
            )
        );
        assert_eq!(
            names(Worker::Acquisition),
            (
                "lumaacquisition.slice",
                "/org/freedesktop/systemd1/unit/lumaacquisition_2eslice",
                "/lumaacquisition.slice"
            )
        );
        assert_ne!(names(Worker::Model), names(Worker::Acquisition));
    }
    #[test]
    fn ambiguous_pid1_requests_cannot_replay_or_claim_an_untouched_baseline() {
        let witness = DispatchWitness {
            pid: 1,
            start_ticks: 23,
            unique_name: ":1.0".into(),
            exe_sha256: "12".repeat(32),
        };
        let mut transition = Transition {
            intent: super::super::tests::intent(),
            revision: 1,
            phase: Phase::Prepared,
            observation: None,
            fence: None,
            reconciliation: None,
            dispatches: Vec::new(),
        };
        require_dispatch(&transition, WriteKind::Restore, &witness, true).unwrap();
        assert!(require_dispatch(&transition, WriteKind::Apply, &witness, false).is_err());
        transition.dispatches.push(super::super::Dispatch {
            kind: WriteKind::Apply,
            witness: Some(witness.clone()),
            started_ms: 1,
        });
        require_dispatch(&transition, WriteKind::Apply, &witness, false).unwrap();
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, true).is_err());
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
        transition.phase = Phase::Applied;
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
        transition.dispatches.push(super::super::Dispatch {
            kind: WriteKind::Restore,
            witness: Some(witness.clone()),
            started_ms: 2,
        });
        require_dispatch(&transition, WriteKind::Restore, &witness, false).unwrap();
        let mut changed = witness.clone();
        changed.unique_name = ":1.1".into();
        assert!(require_dispatch(&transition, WriteKind::Restore, &changed, false).is_err());
        transition.dispatches[0].witness = None;
        assert!(require_dispatch(&transition, WriteKind::Restore, &witness, false).is_err());
    }
    #[test]
    fn property_changes_require_replacement_of_both_actual_own_filters_not_stale_attached_ids() {
        let direction = |own, ancestor| network_query::Direction {
            direct_flags: 2,
            direct_ids: vec![own],
            effective_flags: 0,
            effective_ids: vec![ancestor, own],
        };
        let before = network_query::Reply {
            schema_version: 1,
            nonce: "12".repeat(32),
            boot: "23".repeat(16),
            device: 1,
            inode: 2,
            worker: Worker::Model,
            ingress: direction(20, 10),
            egress: direction(21, 11),
        };
        let mut after = before.clone();
        after.ingress = direction(30, 10);
        after.egress = direction(31, 11);
        replaced_programs(&before, &after).unwrap();
        assert!(replaced_programs(&before, &before).is_err());
        for index in 0..8 {
            let mut changed = after.clone();
            match index {
                0 => changed.ingress = before.ingress.clone(),
                1 => changed.egress = before.egress.clone(),
                2 => changed.ingress.effective_ids.push(20),
                3 => changed.egress.effective_ids.push(21),
                4 => changed.ingress.direct_flags = 0,
                5 => changed.egress.direct_ids.push(32),
                6 => changed.ingress.effective_ids = vec![12, 30],
                _ => changed.egress = changed.ingress.clone(),
            }
            assert!(replaced_programs(&before, &changed).is_err(), "{index}");
        }
    }
}
