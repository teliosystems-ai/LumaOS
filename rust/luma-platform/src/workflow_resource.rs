//! Broker-leased calculation for the closed native invoice workflow. The fixed
//! helper pool is shared with model verification; neither result grants effects.
use crate::{
    acquisition, artifacts as io, calculation, model, resource_manager, resources, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Command, Stdio};

const MAX_SOURCE: usize = 1024 * 1024;
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
const PREFIX: &str = "invoice-v1-";
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub(crate) fn token_valid(token: &resources::Token) -> bool {
    token.generation > 0
        && [&token.lease_id, &token.manager_epoch].iter().all(|v| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub(crate) fn committed_receipt(
    ledger: &resources::Ledger,
    token: &resources::Token,
) -> Result<serde_json::Value> {
    ledger.validate()?;
    let receipt = ledger
        .leases
        .iter()
        .find(|l| &l.token == token)
        .ok_or("computation receipt unavailable; no fabricated provenance")?;
    let epochs = receipt
        .output_domain_epochs
        .as_ref()
        .ok_or("computation domain provenance unavailable; recompute in a fresh generation")?;
    if receipt.owner.uid != 0
        || receipt.output_sha256.is_none()
        || token.manager_epoch != ledger.manager_epoch
        || receipt
            .reservations
            .iter()
            .any(|r| ledger.domains[&r.domain].quarantined)
        || epochs
            .iter()
            .any(|(id, epoch)| ledger.domains[id].epoch != epoch.0)
        || receipt.output_fenced
    {
        return Err("computation receipt belongs to an interrupted or fenced generation".into());
    }
    Ok(
        serde_json::json!({"binding":receipt.binding,"output_sha256":receipt.output_sha256,
        "output_domain_epochs":epochs,
        "lease":receipt.token,"state":receipt.state,"physical_release_granted":false}),
    )
}

pub(crate) fn source_digest(profile: &str) -> Result<&str> {
    let digest = profile
        .strip_prefix(PREFIX)
        .ok_or("unknown calculation profile")?;
    if !io::hash(digest) {
        return Err("invalid calculation source identity".into());
    }
    Ok(digest)
}

fn binding_for(profile: &str, device: &str, installation: &str) -> Result<String> {
    source_digest(profile)?;
    let Some((major, minor)) = device.split_once(':') else {
        return Err("invalid calculation storage identity".into());
    };
    if [major, minor]
        .iter()
        .any(|v| v.parse::<u32>().map_or(true, |n| n.to_string() != *v))
        || major == "0"
        || !io::hash(installation)
    {
        return Err("invalid calculation installation or storage".into());
    }
    let graph = io::digest(include_bytes!(
        "../../../native/image/overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json"
    ));
    Ok(io::digest(&serde_json::to_vec(&(
        "luma-native-invoice-resource-v1",
        installation,
        graph,
        profile,
        device,
    ))?))
}

pub(crate) fn binding(profile: &str, device: &str) -> Result<String> {
    binding_for(profile, device, &io::installation()?)
}

fn anonymous(name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn seal(file: &File) -> Result<()> {
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err("calculation descriptor cannot be sealed".into());
    }
    Ok(())
}

fn sealed_source(mut source: File, expected: &str) -> Result<Vec<u8>> {
    if unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GET_SEALS) } != SEALS
        || !source.metadata()?.is_file()
        || source.metadata()?.len() > MAX_SOURCE as u64
    {
        return Err("calculation requires a bounded immutable input descriptor".into());
    }
    source.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    source.take(MAX_SOURCE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_SOURCE || io::digest(&bytes) != expected {
        return Err("calculation source differs from the leased input".into());
    }
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema_version: u32,
    source_sha256: String,
    lease: resources::Token,
    report: String,
}

fn parse_output(bytes: &[u8], expected: &str) -> Result<Output> {
    if bytes.is_empty() || bytes.len() as u64 >= MAX_OUTPUT {
        return Err("calculation output exceeds its fixed bound".into());
    }
    let output: Output = serde_json::from_slice(bytes)
        .map_err(|_| "calculation output is not a closed receipt envelope")?;
    if output.schema_version != 1
        || output.source_sha256 != expected
        || output.report.is_empty()
        || output.report.len() > 2 * MAX_SOURCE
        || !token_valid(&output.lease)
        || serde_json::to_vec(&output)? != bytes
    {
        return Err("calculation output identity or canonical encoding differs".into());
    }
    let report: serde_json::Value =
        serde_json::from_str(&output.report).map_err(|_| "calculation report is not JSON")?;
    if report["schema_version"] != 1
        || report["report_type"] != "invoice-summary-v1"
        || report["source_sha256"] != expected
        || !report["groups"].is_array()
    {
        return Err("calculation report provenance differs".into());
    }
    Ok(output)
}

fn verify_receipt(output: &Output, expected_binding: &str, value: serde_json::Value) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt {
        binding: String,
        output_sha256: String,
        output_domain_epochs: BTreeMap<String, resources::OutputEpoch>,
        lease: resources::Token,
        state: resources::State,
        physical_release_granted: bool,
    }
    let receipt: Receipt = serde_json::from_value(value)
        .map_err(|_| "calculation receipt is not the closed broker contract")?;
    if receipt.binding != expected_binding
        || receipt.lease != output.lease
        || receipt.output_sha256 != io::digest(output.report.as_bytes())
        || receipt.physical_release_granted
        || receipt
            .output_domain_epochs
            .keys()
            .map(String::as_str)
            .ne(resource_manager::invoice_output_domains())
        || receipt
            .output_domain_epochs
            .values()
            .any(|epoch| epoch.0 == 0)
    {
        return Err("calculation result has no matching durable generation receipt".into());
    }
    // A completed result is immutable history, not resumed worker authority.
    // All three states retain the same receipt; only the broker proves drainage.
    match receipt.state {
        resources::State::Active | resources::State::Draining | resources::State::Released => {
            Ok(())
        }
    }
}

pub(crate) struct Calculation {
    pub report: Vec<u8>,
    pub lease: resources::Token,
}

impl Calculation {
    /// Revalidate immutable output at the effect boundary. A saved token is not
    /// a grant: the current broker epoch, storage and fence state must agree.
    pub(crate) fn recheck(&self, source: &[u8], installation: &str) -> Result<()> {
        if source.is_empty() || source.len() > MAX_SOURCE {
            return Err("calculation source size changed before publication".into());
        }
        recheck_report(&self.lease, &io::digest(source), &self.report, installation)
    }
}

pub(crate) fn recheck_report(
    lease: &resources::Token,
    source_hash: &str,
    report: &[u8],
    installation: &str,
) -> Result<()> {
    if !io::hash(source_hash)
        || report.is_empty()
        || report.len() > 2 * MAX_SOURCE
        || !token_valid(lease)
        || io::installation()? != installation
    {
        return Err("calculation identity changed before publication".into());
    }
    let output = Output {
        schema_version: 1,
        source_sha256: source_hash.into(),
        lease: lease.clone(),
        report: String::from_utf8(report.to_vec())?,
    };
    let output = parse_output(&serde_json::to_vec(&output)?, &source_hash)?;
    let profile = format!("{PREFIX}{source_hash}");
    let expected_binding = binding(
        &profile,
        &resource_manager::storage_device(Path::new("/var"))?,
    )?;
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(lease.clone());
    let reply = crate::service::resource_exchange(&request)?;
    verify_receipt(
        &output,
        &expected_binding,
        reply
            .status
            .ok_or("calculation receipt missing before publication")?,
    )
}

pub(crate) fn calculate(bytes: &[u8]) -> Result<Calculation> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    if bytes.is_empty() || bytes.len() > MAX_SOURCE {
        return Err("calculation source size denied before launch".into());
    }
    let source_hash = io::digest(bytes);
    let profile = format!("{PREFIX}{source_hash}");
    let device = resource_manager::storage_device(Path::new("/var"))?;
    let expected_binding = binding(&profile, &device)?;
    acquisition::await_drainage()?;
    let mut input = anonymous("luma-workflow-input")?;
    input.write_all(bytes)?;
    input.seek(SeekFrom::Start(0))?;
    seal(&input)?;
    let mut output = anonymous("luma-workflow-output")?;
    let deadline = resource_manager::now()?
        .checked_add(45_000)
        .ok_or("calculation controller deadline overflow")?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args(acquisition::arguments(
            Path::new("/var"),
            &profile,
            "invoice",
        )?)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::null());
    model::supervise_owned_controller(&mut command, || {
        if resource_manager::now()? >= deadline || output.metadata()?.len() >= MAX_OUTPUT {
            return Err("calculation controller deadline or output bound exceeded".into());
        }
        Ok(())
    })?;
    // The unit/controller may have exited, but no capacity is returned here.
    // Drainage and retained cache are observed through the existing helper pool.
    acquisition::await_drainage()?;
    seal(&output)?;
    output.seek(SeekFrom::Start(0))?;
    let mut contents = Vec::new();
    output.take(MAX_OUTPUT + 1).read_to_end(&mut contents)?;
    let output = parse_output(&contents, &source_hash)?;
    if binding(
        &profile,
        &resource_manager::storage_device(Path::new("/var"))?,
    )? != expected_binding
    {
        return Err("calculation installation or storage changed during execution".into());
    }
    let mut request = resource_manager::request("resource-output-receipt")?;
    request.lease = Some(output.lease.clone());
    let reply = crate::service::resource_exchange(&request)?;
    verify_receipt(
        &output,
        &expected_binding,
        reply.status.ok_or("calculation receipt missing")?,
    )?;
    Ok(Calculation {
        report: output.report.into_bytes(),
        lease: output.lease,
    })
}

pub(crate) fn worker(profile: &str) -> Result<()> {
    crate::require_root()?;
    crate::platform::require_installed()?;
    let expected = source_digest(profile)?;
    if std::fs::read_to_string("/proc/self/cgroup")?
        != "0::/lumaacquisition.slice/luma-acquisition.service\n"
        || std::fs::read_to_string("/proc/self/attr/current")? != "luma-acquisition (enforce)\n"
    {
        return Err("calculation requires its fixed confined helper generation".into());
    }
    // Admission precedes every source read and parse; no bare-stdin fallback.
    let lease = resource_manager::WorkerLease::acquire_acquisition(profile, Path::new("/var"))?;
    lease.check()?;
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let bytes = sealed_source(unsafe { File::from_raw_fd(fd) }, expected)?;
    lease.check_local()?;
    let report = calculation::report_bytes(&bytes)?;
    lease.check()?;
    lease.complete_output(&io::digest(&report))?;
    let output = Output {
        schema_version: 1,
        source_sha256: expected.into(),
        lease: lease.token().clone(),
        report: String::from_utf8(report)?,
    };
    let encoded = serde_json::to_vec(&output)?;
    if encoded.len() as u64 >= MAX_OUTPUT {
        return Err("calculation output exceeds fixed bound".into());
    }
    lease.check_local()?;
    std::io::stdout().lock().write_all(&encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn released_result() -> (resources::Ledger, resources::Token) {
        use resources::{Domain, Owner, Reservation};
        let mut ledger = resources::Ledger::fresh_for_test();
        ledger
            .restart(
                "a".repeat(32),
                BTreeMap::from([("host".into(), Domain::new(1000, 100, 950, 800).unwrap())]),
            )
            .unwrap();
        let owner = Owner {
            uid: 0,
            pid: 1,
            start_ticks: 1,
            boot: "boot".into(),
            cgroup_device: 1,
            cgroup_inode: 1,
        };
        let token = ledger
            .admit(
                owner.clone(),
                "invoice".into(),
                "c".repeat(64),
                vec![Reservation {
                    domain: "host".into(),
                    loading: 40,
                    serving: 40,
                }],
                1,
                100,
            )
            .unwrap();
        ledger
            .complete_output(&token, &owner, 2, &"d".repeat(64))
            .unwrap();
        ledger.revoke(&token, "owner-lost").unwrap();
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 7)]))
            .unwrap();
        (ledger, token)
    }

    #[test]
    fn released_result_never_reactivates_after_operator_revocation_or_domain_recovery() {
        let (ledger, token) = released_result();
        assert_eq!(
            committed_receipt(&ledger, &token).unwrap()["output_domain_epochs"],
            serde_json::json!({"host":"1"})
        );
        for mode in 0..3 {
            let mut changed = ledger.clone();
            match mode {
                0 => changed.revoke(&token, "operator-revoked").unwrap(),
                1 => changed.quarantine("host", "worker-oom").unwrap(),
                _ => changed
                    .clear_quarantine(&changed.review().unwrap(), ledger.domains.clone())
                    .unwrap(),
            }
            assert!(committed_receipt(&changed, &token).is_err());
            let review = changed.review().unwrap();
            changed
                .clear_quarantine(&review, ledger.domains.clone())
                .unwrap();
            assert!(committed_receipt(&changed, &token).is_err());
            assert_eq!(changed.charged("host").unwrap(), 7);
            assert_eq!(changed.leases[0].state, resources::State::Released);
        }
    }

    #[test]
    fn missing_or_stale_domain_provenance_is_not_reconstructed_from_current_inventory() {
        let (ledger, token) = released_result();
        let mut legacy = ledger.clone();
        legacy.leases[0].output_domain_epochs = None;
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let restored: resources::Ledger = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        assert!(committed_receipt(&restored, &token).is_err());
        assert_eq!(restored, legacy);
        let mut stale = ledger.clone();
        stale
            .clear_quarantine(&stale.review().unwrap(), ledger.domains.clone())
            .unwrap();
        // Defense against an older serialized result that lacks a sticky fence:
        // a current domain flag cannot stand in for its original epoch snapshot.
        stale.leases[0].output_fenced = false;
        stale.validate().unwrap();
        assert!(committed_receipt(&stale, &token).is_err());
        assert_eq!(
            stale.leases[0].output_domain_epochs,
            ledger.leases[0].output_domain_epochs
        );
    }

    #[test]
    fn restarting_to_a_previously_used_manager_name_cannot_revive_a_released_result() {
        let (mut ledger, token) = released_result();
        let inventory = ledger.domains.clone();
        ledger.restart("b".repeat(32), inventory.clone()).unwrap();
        ledger.restart("a".repeat(32), inventory).unwrap();
        assert!(ledger.leases[0].output_fenced);
        assert!(committed_receipt(&ledger, &token).is_err());
        assert_eq!(ledger.charged("host").unwrap(), 7);
    }

    #[test]
    fn retrieval_refuses_revocation_expiry_quarantine_restart_and_missing_output() {
        use resources::{Domain, Owner, Reservation, State};
        use std::collections::BTreeMap;
        let mut ledger = resources::Ledger::fresh_for_test();
        ledger
            .restart(
                "a".repeat(32),
                BTreeMap::from([("host".into(), Domain::new(1000, 100, 950, 800).unwrap())]),
            )
            .unwrap();
        let who = Owner {
            uid: 0,
            pid: 1,
            start_ticks: 1,
            boot: "boot".into(),
            cgroup_device: 1,
            cgroup_inode: 1,
        };
        let token = ledger
            .admit(
                who.clone(),
                "request".into(),
                "c".repeat(64),
                vec![Reservation {
                    domain: "host".into(),
                    loading: 40,
                    serving: 40,
                }],
                1,
                100,
            )
            .unwrap();
        assert!(committed_receipt(&ledger, &token).is_err());
        ledger
            .complete_output(&token, &who, 2, &"d".repeat(64))
            .unwrap();
        committed_receipt(&ledger, &token).unwrap();
        for reason in [
            "operator-revoked",
            "worker-oom",
            "expired",
            "critical-host-pressure",
        ] {
            let mut fenced = ledger.clone();
            fenced.revoke(&token, reason).unwrap();
            assert!(committed_receipt(&fenced, &token).is_err());
            fenced
                .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
                .unwrap();
            assert!(fenced.leases[0].output_fenced);
            assert!(committed_receipt(&fenced, &token).is_err());
        }
        let mut fenced = ledger.clone();
        fenced.quarantine("host", "worker-oom").unwrap();
        assert!(committed_receipt(&fenced, &token).is_err());
        let mut fenced = ledger.clone();
        fenced
            .restart("b".repeat(32), ledger.domains.clone())
            .unwrap();
        assert!(committed_receipt(&fenced, &token).is_err());
        ledger.revoke(&token, "owner-lost").unwrap();
        committed_receipt(&ledger, &token).unwrap();
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
            .unwrap();
        assert_eq!(ledger.leases[0].state, State::Released);
        committed_receipt(&ledger, &token).unwrap();
    }
    #[test]
    fn input_is_sealed_and_bound_before_parse() {
        let bytes = b"invoice_date,amount,currency\n2026-10-01,1.25,USD\n";
        let mut input = anonymous("luma-workflow-input").unwrap();
        input.write_all(bytes).unwrap();
        let expected = io::digest(bytes);
        assert!(sealed_source(input.try_clone().unwrap(), &expected).is_err());
        seal(&input).unwrap();
        assert!(input.write_all(b"changed").is_err());
        assert!(sealed_source(input.try_clone().unwrap(), &"a".repeat(64)).is_err());
        assert_eq!(sealed_source(input, &expected).unwrap(), bytes);
    }
    #[test]
    fn calculation_plan_binds_source_storage_installation_and_fixed_graph() {
        let profile = format!("{PREFIX}{}", "a".repeat(64));
        let binding = binding_for(&profile, "253:0", &"b".repeat(64)).unwrap();
        assert_ne!(
            binding,
            binding_for(&profile, "253:1", &"b".repeat(64)).unwrap()
        );
        assert_ne!(
            binding,
            binding_for(&profile, "253:0", &"c".repeat(64)).unwrap()
        );
        assert_ne!(
            binding,
            binding_for(
                &format!("{PREFIX}{}", "d".repeat(64)),
                "253:0",
                &"b".repeat(64)
            )
            .unwrap()
        );
        for id in [
            "invoice-v1-a",
            "invoice-v2-a",
            "invoice-v1-",
            "qwen3-4b-q4-k-m",
        ] {
            assert!(source_digest(id).is_err());
        }
        for device in ["0:1", "253:01", "0253:0", "253:-1", "253:0:1"] {
            assert!(binding_for(&profile, device, &"b".repeat(64)).is_err());
        }
        let args = acquisition::arguments(Path::new("/var"), &profile, "invoice").unwrap();
        for required in [
            "--property=MemoryMax=512M",
            "--property=RuntimeMaxSec=30",
            "--property=LimitFSIZE=4M",
            "--property=RestrictAddressFamilies=AF_UNIX",
        ] {
            assert!(args.iter().any(|v| v == required));
        }
        assert!(!args
            .iter()
            .any(|v| v.contains("ReadWritePaths=") || v.contains("AF_INET")));
        assert_eq!(
            &args[args.len() - 3..],
            [
                "/usr/libexec/luma-os/luma-platform",
                "workflow-resource-worker",
                &profile
            ]
        );
    }
    #[test]
    fn canonical_result_and_receipt_must_match_the_exact_generation_and_input() {
        let source = b"invoice_date,amount,currency\n2026-10-01,1.25,USD\n";
        let output = Output {
            schema_version: 1,
            source_sha256: io::digest(source),
            lease: resources::Token {
                lease_id: "a".repeat(32),
                manager_epoch: "b".repeat(32),
                generation: 7,
            },
            report: String::from_utf8(calculation::report_bytes(source).unwrap()).unwrap(),
        };
        let encoded = serde_json::to_vec(&output).unwrap();
        parse_output(&encoded, &output.source_sha256).unwrap();
        assert!(parse_output(&encoded, &"f".repeat(64)).is_err());
        let mut changed = encoded.clone();
        changed.push(b'\n');
        assert!(parse_output(&changed, &output.source_sha256).is_err());
        let binding = "c".repeat(64);
        let receipt = serde_json::json!({"binding":binding,"lease":output.lease,
            "output_sha256":io::digest(output.report.as_bytes()),
            "output_domain_epochs":{"acquisition-executions":"1","host-memory":"1","worker-processes":"1"},
            "state":"released","physical_release_granted":false});
        verify_receipt(&output, &binding, receipt.clone()).unwrap();
        let mut full_width = receipt.clone();
        full_width["output_domain_epochs"]["host-memory"] = serde_json::json!(u64::MAX.to_string());
        verify_receipt(&output, &binding, full_width).unwrap();
        for (key, value) in [
            ("binding", serde_json::json!("d".repeat(64))),
            ("output_sha256", serde_json::json!("e".repeat(64))),
            ("physical_release_granted", serde_json::json!(true)),
            ("authority", serde_json::json!(true)),
            ("output_domain_epochs", serde_json::json!({})),
            ("output_domain_epochs", serde_json::json!({"host":"0"})),
            ("output_domain_epochs", serde_json::json!({"host":1})),
            ("output_domain_epochs", serde_json::json!({"host":"01"})),
            ("output_domain_epochs", serde_json::json!({"../host":"1"})),
        ] {
            let mut changed = receipt.clone();
            changed[key] = value;
            assert!(verify_receipt(&output, &binding, changed).is_err());
        }
        let mut changed = receipt;
        for field in ["acquisition-executions", "host-memory", "worker-processes"] {
            for invalid in [
                serde_json::json!("0"),
                serde_json::json!("01"),
                serde_json::json!(1),
                serde_json::json!(true),
            ] {
                let mut malformed = changed.clone();
                malformed["output_domain_epochs"][field] = invalid;
                assert!(verify_receipt(&output, &binding, malformed).is_err());
            }
            let mut partial = changed.clone();
            partial["output_domain_epochs"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(verify_receipt(&output, &binding, partial).is_err());
        }
        let mut legacy = changed.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("output_domain_epochs");
        assert!(verify_receipt(&output, &binding, legacy).is_err());
        changed["lease"]["generation"] = serde_json::json!("8");
        assert!(verify_receipt(&output, &binding, changed).is_err());
    }
}
