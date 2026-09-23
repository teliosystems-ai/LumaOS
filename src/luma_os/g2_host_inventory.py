"""Read-only host observations for G2 Ubuntu qualification preparation.

The collector deliberately does not decide that a disk is disposable, select an
installation target, enroll firmware keys, unlock storage, or mutate the host.
Its output is an inventory input to a separately authorized physical test run;
it is never gate-closing evidence by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
from typing import Callable, Mapping, Sequence


COLLECTOR_VERSION = "1.1"
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_ACCELERATOR_DEVICE_NODES = 128
_ENVIRONMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EXECUTABLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
TRUSTED_SYSTEM_COMMAND_ROOTS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
WSL_NVIDIA_COMMAND_ROOTS = ("/usr/lib/wsl/lib",)


@dataclass(frozen=True)
class PathProvenanceObservation:
    """Ownership and mode facts for an executable or one of its parents."""

    path: str
    kind: str
    owner_uid: int
    owner_gid: int
    mode: int
    size_bytes: int


@dataclass(frozen=True)
class ResolvedExecutable:
    """Fail-closed resolution result for one allow-listed command name."""

    status: str
    path: str | None = None
    sha256: str | None = None
    provenance: tuple[PathProvenanceObservation, ...] = ()


@dataclass(frozen=True)
class CommandObservation:
    """Bounded result of one allow-listed, non-mutating command."""

    argv: tuple[str, ...]
    status: str
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    resolved_executable_path: str | None = None
    resolved_executable_sha256: str | None = None
    executable_provenance_status: str = "injected-not-recorded"
    executable_provenance: tuple[PathProvenanceObservation, ...] = ()


@dataclass(frozen=True)
class AcceleratorDeviceObservation:
    """One bounded character-device observation from an exact /dev allowlist."""

    kind: str
    path: str
    major: int
    minor: int
    mode: str
    owner_uid: int
    owner_gid: int
    readable_by_collector: bool
    writable_by_collector: bool


@dataclass(frozen=True)
class HostObservations:
    """Injectable raw observations used to construct the stable evidence JSON."""

    collected_at: datetime
    machine: str
    files: Mapping[str, bytes]
    present_paths: frozenset[str]
    commands: Mapping[str, CommandObservation]
    accelerator_device_nodes: tuple[AcceleratorDeviceObservation, ...] = ()
    accelerator_scan_truncated: bool = False


READ_ONLY_COMMANDS: Mapping[str, tuple[str, ...]] = {
    "virtualization": ("systemd-detect-virt",),
    "secure_boot": ("mokutil", "--sb-state"),
    "root_mount": ("findmnt", "--json", "--bytes", "--output", "SOURCE,FSTYPE,OPTIONS", "/"),
    "block_devices": (
        "lsblk",
        "--json",
        "--bytes",
        "--output",
        "KNAME,PATH,TYPE,SIZE,RO,RM,MODEL,SERIAL,WWN,TRAN,FSTYPE,MOUNTPOINTS,PKNAME",
    ),
    "nvidia": (
        "nvidia-smi",
        "--query-gpu=name,uuid,driver_version,memory.total,pci.bus_id",
        "--format=csv,noheader,nounits",
    ),
    "bootctl": ("bootctl", "status", "--no-pager"),
    "verity": ("dmsetup", "ls", "--target", "verity", "--noheadings"),
    "packages": (
        "dpkg-query",
        "-W",
        "-f=${Package}=${Version}\\n",
        "linux-image-generic",
        "shim-signed",
        "systemd",
        "cryptsetup",
        "apparmor",
    ),
}

READ_PATHS = (
    "/etc/os-release",
    "/proc/sys/kernel/osrelease",
    "/proc/cmdline",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/proc/self/status",
    "/etc/machine-id",
    "/sys/module/apparmor/parameters/enabled",
    "/sys/kernel/security/lsm",
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/product_version",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/board_name",
    "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/bios_version",
    "/sys/class/dmi/id/bios_date",
    "/sys/fs/cgroup/cgroup.controllers",
)

PRESENCE_PATHS = (
    "/sys/firmware/efi",
    "/sys/firmware/efi/efivars",
    "/sys/fs/cgroup/cgroup.controllers",
    "/dev/kvm",
    "/dev/tpm0",
    "/dev/tpmrm0",
    "/dev/dxg",
    "/sys/kernel/iommu_groups",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(files: Mapping[str, bytes], path: str) -> str:
    raw = files.get(path, b"")
    return raw.decode("utf-8", errors="replace").strip()


def _key_values(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in value.splitlines():
        key, separator, raw = line.partition("=")
        if not separator:
            continue
        item = raw.strip()
        if len(item) >= 2 and item[0] == item[-1] == '"':
            item = item[1:-1]
        fields[key] = item
    return fields


def _integer_field(lines: str, name: str, *, multiplier: int = 1) -> int | None:
    for line in lines.splitlines():
        field, separator, raw = line.partition(":")
        if separator and field == name:
            match = re.match(r"\s*([0-9]+)", raw)
            if match:
                return int(match.group(1)) * multiplier
    return None


def _environment_kind(observations: HostObservations) -> tuple[str, str]:
    kernel = _text(observations.files, "/proc/sys/kernel/osrelease").lower()
    if "microsoft" in kernel or "/dev/dxg" in observations.present_paths:
        return "wsl2", "kernel-or-dxg"
    detected = observations.commands.get("virtualization")
    if detected and detected.stdout.strip().lower() in {"wsl", "wsl2"}:
        return "wsl2", "systemd-detect-virt"
    if detected:
        value = detected.stdout.strip().lower()
        # systemd-detect-virt intentionally exits non-zero when no
        # virtualization is detected while reporting ``none``.  That exact
        # output is a native-host observation, not a probe failure.
        if value == "none" and detected.status in {"ok", "nonzero"}:
            return "native", "systemd-detect-virt"
    if detected and detected.status == "ok":
        value = detected.stdout.strip().lower()
        if value in {"docker", "podman", "lxc", "lxc-libvirt", "systemd-nspawn", "container-other"}:
            return "container", "systemd-detect-virt"
        if value and value != "none":
            return "virtual-machine", "systemd-detect-virt"
    return "unknown", "insufficient-observation"


def _secure_boot(observations: HostObservations) -> dict[str, str]:
    for path, raw in observations.files.items():
        if (
            path.startswith("/sys/firmware/efi/efivars/SecureBoot-")
            and len(raw) >= 5
            and raw[4] in {0, 1}
        ):
            return {
                "state": "enabled" if raw[4] == 1 else "disabled",
                "source": "efi-variable",
            }
    command = observations.commands.get("secure_boot")
    # A failed mokutil invocation can echo stale, diagnostic, or adversarial
    # text.  Only a successful probe is admissible as a state observation.
    if command and command.status == "ok":
        output = f"{command.stdout}\n{command.stderr}".lower()
        if "secureboot enabled" in output or "secure boot enabled" in output:
            return {"state": "enabled", "source": "mokutil"}
        if "secureboot disabled" in output or "secure boot disabled" in output:
            return {"state": "disabled", "source": "mokutil"}
    return {"state": "unknown", "source": "unavailable"}


def _seccomp_mode(status: str) -> str:
    value = _integer_field(status, "Seccomp")
    return {0: "disabled", 1: "strict", 2: "filter"}.get(value, "unknown")


def _safe_identity_digest(*values: object) -> str | None:
    normalized = [str(value).strip() for value in values if str(value).strip()]
    if not normalized:
        return None
    material = "luma-g2-device-identity-v1\0" + "\0".join(normalized)
    return _sha256_bytes(material.encode("utf-8"))


def _block_devices(
    observation: CommandObservation | None,
    *,
    include_sensitive_identifiers: bool,
) -> list[dict[str, object]]:
    if not observation or observation.status != "ok":
        return []
    try:
        raw_devices = json.loads(observation.stdout).get("blockdevices", [])
    except (json.JSONDecodeError, AttributeError):
        return []
    devices: list[dict[str, object]] = []

    def visit(items: Sequence[object]) -> None:
        for raw in items:
            if not isinstance(raw, dict):
                continue
            serial = str(raw.get("serial") or "").strip()
            wwn = str(raw.get("wwn") or "").strip()
            path = str(raw.get("path") or "").strip()
            kname = str(raw.get("kname") or "").strip()
            if wwn or serial:
                identity = _safe_identity_digest(
                    f"wwn:{wwn}" if wwn else "",
                    f"serial:{serial}" if serial else "",
                )
                identity_basis = "hardware-reported-wwn-or-serial"
                identity_limitations = (
                    "Pseudonymous comparison aid only; raw identifiers and current physical observation "
                    "remain mandatory for destructive authorization."
                )
            else:
                identity = _safe_identity_digest(f"path:{path}", f"kname:{kname}")
                identity_basis = "path-and-kernel-name-fallback"
                identity_limitations = (
                    "No WWN or serial was reported; this fallback can change across boots and must not "
                    "authorize destructive execution."
                )
            record: dict[str, object] = {
                "kernel_name": kname,
                "path": path,
                "type": str(raw.get("type") or "unknown"),
                "size_bytes": int(raw.get("size") or 0),
                "read_only": bool(raw.get("ro")),
                "removable": bool(raw.get("rm")),
                "model": str(raw.get("model") or "").strip() or None,
                "transport": str(raw.get("tran") or "").strip() or None,
                "filesystem": str(raw.get("fstype") or "").strip() or None,
                "mountpoints": [
                    str(item) for item in (raw.get("mountpoints") or []) if item is not None
                ],
                "parent_kernel_name": str(raw.get("pkname") or "").strip() or None,
                "stable_identity_sha256": identity,
                "identity_basis": identity_basis,
                "identity_limitations": identity_limitations,
                "operator_disposition": "unclassified-never-auto-selected",
            }
            if include_sensitive_identifiers:
                record["serial"] = serial or None
                record["wwn"] = wwn or None
            devices.append(record)
            children = raw.get("children")
            if isinstance(children, list):
                visit(children)

    if isinstance(raw_devices, list):
        visit(raw_devices)
    return devices


def _root_mount(observation: CommandObservation | None) -> dict[str, object]:
    result: dict[str, object] = {"source": None, "filesystem": None, "options": []}
    if not observation or observation.status != "ok":
        return result
    try:
        filesystems = json.loads(observation.stdout).get("filesystems", [])
        first = filesystems[0]
        result["source"] = first.get("source")
        result["filesystem"] = first.get("fstype")
        options = first.get("options") or ""
        result["options"] = sorted(item for item in str(options).split(",") if item)
    except (json.JSONDecodeError, AttributeError, IndexError, TypeError):
        pass
    return result


def _accelerators(
    observation: CommandObservation | None,
    device_nodes: Sequence[AcceleratorDeviceObservation],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    if observation and observation.status == "ok":
        for line in observation.stdout.splitlines():
            fields = [field.strip() for field in line.split(",")]
            if len(fields) != 5:
                continue
            name, uuid, driver, memory_mib, bus_id = fields
            try:
                memory_bytes: int | None = int(memory_mib) * 1024 * 1024
            except ValueError:
                memory_bytes = None
            result.append(
                {
                    "kind": "nvidia-smi",
                    "source": "nvidia-smi",
                    "vendor": "nvidia",
                    "name": name,
                    "device_path": None,
                    "device_identity_sha256": _safe_identity_digest(uuid, bus_id),
                    "identity_basis": "nvidia-uuid-and-pci-bus-observation",
                    "driver_version": driver or None,
                    "memory_bytes": memory_bytes,
                    "major": None,
                    "minor": None,
                    "mode": None,
                    "owner_uid": None,
                    "owner_gid": None,
                    "readable_by_collector": None,
                    "writable_by_collector": None,
                }
            )
    for node in sorted(device_nodes, key=lambda item: (item.path, item.kind)):
        result.append(
            {
                "kind": node.kind,
                "source": "device-node",
                "vendor": None,
                "name": Path(node.path).name,
                "device_path": node.path,
                "device_identity_sha256": _safe_identity_digest(
                    node.kind,
                    node.path,
                    f"{node.major}:{node.minor}",
                ),
                "identity_basis": "device-kind-path-and-major-minor-observation",
                "driver_version": None,
                "memory_bytes": None,
                "major": node.major,
                "minor": node.minor,
                "mode": node.mode,
                "owner_uid": node.owner_uid,
                "owner_gid": node.owner_gid,
                "readable_by_collector": node.readable_by_collector,
                "writable_by_collector": node.writable_by_collector,
            }
        )
    return result


def _probe_records(commands: Mapping[str, CommandObservation]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for probe_id in sorted(READ_ONLY_COMMANDS):
        observation = commands[probe_id]
        records.append(
            {
                "probe_id": probe_id,
                "argv": list(observation.argv),
                "status": observation.status,
                "returncode": observation.returncode,
                "stdout_sha256": _sha256_bytes(observation.stdout.encode("utf-8")),
                "stderr_sha256": _sha256_bytes(observation.stderr.encode("utf-8")),
                "resolved_executable_path": observation.resolved_executable_path,
                "resolved_executable_sha256": observation.resolved_executable_sha256,
                "executable_provenance_status": observation.executable_provenance_status,
                "executable_provenance": [
                    {
                        "path": item.path,
                        "kind": item.kind,
                        "owner_uid": item.owner_uid,
                        "owner_gid": item.owner_gid,
                        "mode": f"{item.mode:04o}",
                        "size_bytes": item.size_bytes,
                    }
                    for item in observation.executable_provenance
                ],
            }
        )
    return records


def _finding(
    finding_id: str,
    status: str,
    required_for: Sequence[str],
    detail: str,
) -> dict[str, object]:
    return {
        "id": finding_id,
        "status": status,
        "required_for": list(required_for),
        "detail": detail,
    }


def build_inventory(
    observations: HostObservations,
    *,
    environment_id: str,
    include_sensitive_identifiers: bool = False,
) -> dict[str, object]:
    """Build a stable, schema-v1 inventory from injected observations."""

    if not _ENVIRONMENT_ID.fullmatch(environment_id):
        raise ValueError("environment_id must be 1-64 portable identifier characters")
    if observations.collected_at.tzinfo is None:
        raise ValueError("collected_at must be timezone-aware")

    os_release = _key_values(_text(observations.files, "/etc/os-release"))
    kernel_release = _text(observations.files, "/proc/sys/kernel/osrelease")
    machine = observations.machine.lower()
    kind, detection_source = _environment_kind(observations)
    secure_boot = _secure_boot(observations)
    native_ubuntu_2404 = (
        kind == "native"
        and os_release.get("ID", "").lower() == "ubuntu"
        and os_release.get("VERSION_ID") == "24.04"
        and machine in {"x86_64", "amd64"}
    )

    meminfo = _text(observations.files, "/proc/meminfo")
    cpuinfo = _text(observations.files, "/proc/cpuinfo")
    cpu_model = None
    for name in ("model name", "Hardware", "Processor"):
        for line in cpuinfo.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() == name:
                cpu_model = value.strip()
                break
        if cpu_model:
            break
    logical_processors = sum(
        1 for line in cpuinfo.splitlines() if line.partition(":")[0].strip() == "processor"
    )

    cgroup_controllers = sorted(
        set(_text(observations.files, "/sys/fs/cgroup/cgroup.controllers").split())
    )
    apparmor_value = _text(observations.files, "/sys/module/apparmor/parameters/enabled")
    apparmor_enabled = apparmor_value.lower() in {"y", "yes", "1"}
    lsm = _text(observations.files, "/sys/kernel/security/lsm")
    lsm_modules = [item.strip() for item in lsm.split(",") if item.strip()]
    seccomp_mode = _seccomp_mode(_text(observations.files, "/proc/self/status"))
    root_mount = _root_mount(observations.commands.get("root_mount"))
    devices = _block_devices(
        observations.commands.get("block_devices"),
        include_sensitive_identifiers=include_sensitive_identifiers,
    )
    accelerators = _accelerators(
        observations.commands.get("nvidia"),
        observations.accelerator_device_nodes,
    )
    cmdline = _text(observations.files, "/proc/cmdline")
    selected_cmdline = sorted(
        token
        for token in cmdline.split()
        if token.startswith(("apparmor=", "security=", "iommu=", "amd_iommu=", "intel_iommu="))
        or token == "ro"
        or token.startswith("roothash=")
        or token.startswith("systemd.verity")
    )
    machine_id = _text(observations.files, "/etc/machine-id")
    host_identity = (
        _sha256_bytes(f"luma-g2-host-id-v1\0{machine_id}".encode("utf-8"))
        if machine_id
        else None
    )

    security = {
        "cgroup_v2": {
            "available": "/sys/fs/cgroup/cgroup.controllers" in observations.present_paths,
            "controllers": cgroup_controllers,
        },
        "apparmor": {
            "kernel_enabled": apparmor_enabled,
            "listed_by_lsm": "apparmor" in lsm_modules,
        },
        "seccomp": {"collector_process_mode": seccomp_mode},
        "kvm": {"device_present": "/dev/kvm" in observations.present_paths},
        "tpm": {
            "device_present": any(
                path in observations.present_paths for path in ("/dev/tpm0", "/dev/tpmrm0")
            )
        },
        "iommu": {
            "groups_path_present": "/sys/kernel/iommu_groups" in observations.present_paths,
            "selected_kernel_arguments": [
                token for token in selected_cmdline if "iommu" in token
            ],
        },
        "lsm_modules": lsm_modules,
    }

    findings = [
        _finding(
            "G2-HOST-NATIVE-UBUNTU-24-04",
            "pass" if native_ubuntu_2404 else "block",
            ("T01", "T45", "physical G2"),
            "Native Ubuntu 24.04 amd64 candidate observed."
            if native_ubuntu_2404
            else f"Observed {kind}, {os_release.get('ID', 'unknown')} {os_release.get('VERSION_ID', 'unknown')} {machine}; this cannot close the physical Ubuntu 24.04 gate.",
        ),
        _finding(
            "G2-HOST-SECURE-BOOT",
            "pass" if secure_boot["state"] == "enabled" else "block",
            ("T04", "T46"),
            f"Secure Boot state is {secure_boot['state']} from {secure_boot['source']}; signed-component tamper tests are still required.",
        ),
        _finding(
            "G2-HOST-CGROUP-V2",
            "pass" if security["cgroup_v2"]["available"] else "block",
            ("T13", "T15", "T50"),
            "cgroup v2 controllers are observable; enforcement under saturation is not established."
            if security["cgroup_v2"]["available"]
            else "cgroup v2 controller interface was not observed.",
        ),
        _finding(
            "G2-HOST-APPARMOR",
            "pass" if apparmor_enabled and "apparmor" in lsm_modules else "block",
            ("T29", "T50", "T62"),
            "AppArmor is enabled in the kernel and LSM list; required profiles must still be proven enforcing."
            if apparmor_enabled and "apparmor" in lsm_modules
            else "AppArmor was not proven enabled in both the kernel parameter and active LSM list.",
        ),
        _finding(
            "G2-HOST-KVM",
            "pass" if security["kvm"]["device_present"] else "review",
            ("T29", "T62"),
            "/dev/kvm is present; access and microVM isolation remain unqualified."
            if security["kvm"]["device_present"]
            else "No /dev/kvm was observed; native generated code must remain denied unless a separately qualified constrained runtime is approved.",
        ),
        _finding(
            "G2-HOST-ACCELERATOR-VISIBILITY",
            (
                "review"
                if kind == "wsl2" and accelerators
                else "pass"
                if accelerators and not observations.accelerator_scan_truncated
                else "review"
                if observations.accelerator_scan_truncated
                else "block"
            ),
            ("T01", "T15", "T51"),
            (
                f"{len(accelerators)} accelerator visibility record(s) observed from bounded "
                "NVIDIA and generic device-node probes; visibility does not qualify a driver, "
                "runtime, memory size, reset behavior, isolation, or model profile."
            ),
        ),
        _finding(
            "G2-HOST-DISPOSABLE-DISK",
            "operator-action-required",
            ("T01", "T47", "T48"),
            f"{sum(1 for item in devices if item.get('type') == 'disk')} disk(s) inventoried; the collector never declares a disk disposable or selects a target.",
        ),
    ]

    timestamp = observations.collected_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "record_type": "luma-os-g2-host-inventory",
        "record_id": f"G2-HOST-{environment_id}-{timestamp.replace(':', '').replace('-', '')}",
        "collected_at_utc": timestamp,
        "environment_id": environment_id,
        "collector": {
            "name": "scripts/collect_g2_host.py",
            "version": COLLECTOR_VERSION,
            "host_mutation_performed": False,
            "commands_are_allowlisted_and_shell_free": True,
            "ambient_path_used": False,
            "ambient_environment_inherited": False,
            "trusted_command_roots": [
                *TRUSTED_SYSTEM_COMMAND_ROOTS,
                *(WSL_NVIDIA_COMMAND_ROOTS if kind == "wsl2" else ()),
            ],
            "sensitive_identifiers_included": include_sensitive_identifiers,
        },
        "evidence_boundary": {
            "gate_closing": False,
            "classification": (
                "physical-candidate-inventory-non-closing"
                if native_ubuntu_2404
                else "development-or-ineligible-inventory-non-closing"
            ),
            "reason": "Inventory alone does not execute installation, boot tamper, recovery, confinement, power-loss, lifecycle, or performance acceptance procedures.",
        },
        "system": {
            "environment_kind": kind,
            "environment_detection_source": detection_source,
            "native_ubuntu_24_04_amd64_candidate": native_ubuntu_2404,
            "pseudonymous_host_identity_sha256": host_identity,
            "pseudonymous_host_identity_basis": "domain-separated-sha256-of-etc-machine-id",
            "pseudonymous_host_identity_limitations": (
                "Binds evidence to the observed OS installation only; machine-id can be cloned "
                "or reset and is not physical-board attestation."
            ),
            "os": {
                "id": os_release.get("ID"),
                "name": os_release.get("NAME"),
                "version_id": os_release.get("VERSION_ID"),
                "version_codename": os_release.get("VERSION_CODENAME"),
                "architecture": machine,
            },
            "kernel": {
                "release": kernel_release,
                "selected_command_line": selected_cmdline,
                "full_command_line_sha256": _sha256_bytes(cmdline.encode("utf-8")),
            },
            "firmware": {
                "uefi_present": "/sys/firmware/efi" in observations.present_paths,
                "efivars_present": "/sys/firmware/efi/efivars" in observations.present_paths,
                "secure_boot": secure_boot,
                "dmi": {
                    "system_vendor": _text(observations.files, "/sys/class/dmi/id/sys_vendor") or None,
                    "product_name": _text(observations.files, "/sys/class/dmi/id/product_name") or None,
                    "product_version": _text(observations.files, "/sys/class/dmi/id/product_version") or None,
                    "board_vendor": _text(observations.files, "/sys/class/dmi/id/board_vendor") or None,
                    "board_name": _text(observations.files, "/sys/class/dmi/id/board_name") or None,
                    "bios_vendor": _text(observations.files, "/sys/class/dmi/id/bios_vendor") or None,
                    "bios_version": _text(observations.files, "/sys/class/dmi/id/bios_version") or None,
                    "bios_date": _text(observations.files, "/sys/class/dmi/id/bios_date") or None,
                },
            },
            "cpu": {
                "model": cpu_model,
                "logical_processors": logical_processors,
            },
            "memory": {
                "total_bytes": _integer_field(meminfo, "MemTotal", multiplier=1024),
                "available_bytes": _integer_field(meminfo, "MemAvailable", multiplier=1024),
            },
            "security_controls": security,
            "storage": {
                "root_mount": root_mount,
                "block_devices": devices,
                "verity_probe_status": observations.commands["verity"].status,
            },
            "accelerators": accelerators,
            "accelerator_device_scan": {
                "allowlisted_roots": ["/dev/dri/renderD[0-9]+", "/dev/accel/accel[0-9]+", "/dev/dxg"],
                "maximum_nodes": MAX_ACCELERATOR_DEVICE_NODES,
                "truncated": observations.accelerator_scan_truncated,
                "recursive": False,
                "symlinks_followed": False,
            },
            "package_versions": sorted(
                line.strip()
                for line in observations.commands["packages"].stdout.splitlines()
                if line.strip()
            ),
        },
        "probe_results": _probe_records(observations.commands),
        "findings": findings,
    }


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(MAX_CAPTURE_BYTES + 1)[:MAX_CAPTURE_BYTES]
    except OSError:
        return b""


def _device_node_observation(
    path: str,
    kind: str,
    metadata: os.stat_result,
) -> AcceleratorDeviceObservation:
    try:
        readable = os.access(path, os.R_OK, follow_symlinks=False)
        writable = os.access(path, os.W_OK, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        readable = False
        writable = False
    return AcceleratorDeviceObservation(
        kind=kind,
        path=path,
        major=os.major(metadata.st_rdev),
        minor=os.minor(metadata.st_rdev),
        mode=f"{stat.S_IMODE(metadata.st_mode):04o}",
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        readable_by_collector=readable,
        writable_by_collector=writable,
    )


def _collect_accelerator_device_nodes() -> tuple[tuple[AcceleratorDeviceObservation, ...], bool]:
    """Inspect only exact accelerator directories, without recursion or symlink following."""

    observations: list[AcceleratorDeviceObservation] = []
    truncated = False
    roots = (
        ("/dev/dri", re.compile(r"renderD[0-9]{1,6}"), "drm-render"),
        ("/dev/accel", re.compile(r"accel[0-9]{1,6}"), "accel"),
    )
    for root, allowed_name, kind in roots:
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if not allowed_name.fullmatch(entry.name):
                        continue
                    if len(observations) >= MAX_ACCELERATOR_DEVICE_NODES:
                        truncated = True
                        break
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISCHR(metadata.st_mode):
                        continue
                    # entry.path is confined to an exact allow-listed parent and
                    # a fully matched basename. Symlinks are rejected above.
                    observations.append(_device_node_observation(entry.path, kind, metadata))
        except OSError:
            continue
    dxg_path = "/dev/dxg"
    if len(observations) < MAX_ACCELERATOR_DEVICE_NODES:
        try:
            metadata = os.lstat(dxg_path)
        except OSError:
            metadata = None
        if metadata is not None and stat.S_ISCHR(metadata.st_mode):
            observations.append(_device_node_observation(dxg_path, "wsl-dxg", metadata))
    else:
        try:
            dxg_metadata = os.lstat(dxg_path)
        except OSError:
            dxg_metadata = None
        if dxg_metadata is not None and stat.S_ISCHR(dxg_metadata.st_mode):
            truncated = True
    return tuple(sorted(observations, key=lambda item: item.path)), truncated


def executable_provenance_is_trusted(
    provenance: Sequence[PathProvenanceObservation],
) -> bool:
    """Validate injected executable/ancestor facts without consulting the host."""

    if not provenance or provenance[0].kind != "regular-file":
        return False
    executable = provenance[0]
    if executable.size_bytes < 1 or executable.size_bytes > MAX_EXECUTABLE_BYTES:
        return False
    if not executable.mode & 0o111:
        return False
    for item in provenance:
        if item.owner_uid != 0 or item.mode & 0o022:
            return False
        if item.kind not in {"regular-file", "directory"}:
            return False
    return all(item.kind == "directory" for item in provenance[1:])


def _path_provenance(path: Path, metadata: os.stat_result) -> PathProvenanceObservation:
    kind = "regular-file" if stat.S_ISREG(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode) else "other"
    return PathProvenanceObservation(
        path=str(path),
        kind=kind,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
        size_bytes=metadata.st_size,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_trusted_executable(
    name: str,
    *,
    additional_roots: Sequence[str] = (),
) -> ResolvedExecutable:
    """Resolve a command only through fixed root-owned Linux directories."""

    if not _EXECUTABLE_NAME.fullmatch(name):
        return ResolvedExecutable("rejected")
    roots: list[Path] = []
    for raw_root in (*TRUSTED_SYSTEM_COMMAND_ROOTS, *additional_roots):
        try:
            root = Path(raw_root).resolve(strict=True)
        except OSError:
            continue
        if root not in roots:
            roots.append(root)
    saw_candidate = False
    rejected_provenance: tuple[PathProvenanceObservation, ...] = ()
    for root in roots:
        candidate = root / name
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        saw_candidate = True
        try:
            if not resolved.is_relative_to(root):
                continue
            executable_stat = resolved.stat(follow_symlinks=False)
            provenance = [_path_provenance(resolved, executable_stat)]
            parent = resolved.parent
            while True:
                parent_stat = parent.stat(follow_symlinks=False)
                provenance.append(_path_provenance(parent, parent_stat))
                if parent == parent.parent:
                    break
                parent = parent.parent
        except OSError:
            continue
        rejected_provenance = tuple(provenance)
        if not executable_provenance_is_trusted(provenance):
            continue
        try:
            executable_sha256 = _sha256_file(resolved)
        except OSError:
            continue
        return ResolvedExecutable(
            status="trusted",
            path=str(resolved),
            sha256=executable_sha256,
            provenance=tuple(provenance),
        )
    return ResolvedExecutable(
        status="rejected" if saw_candidate else "not-found",
        provenance=rejected_provenance,
    )


def _run_read_only(
    argv: tuple[str, ...],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    additional_roots: Sequence[str] = (),
    resolver: Callable[[str, Sequence[str]], ResolvedExecutable] | None = None,
) -> CommandObservation:
    executable = (
        resolver(argv[0], additional_roots)
        if resolver is not None
        else _resolve_trusted_executable(argv[0], additional_roots=additional_roots)
    )
    if executable.status != "trusted" or executable.path is None:
        return CommandObservation(
            argv,
            executable.status,
            None,
            resolved_executable_path=executable.path,
            resolved_executable_sha256=executable.sha256,
            executable_provenance_status=executable.status,
            executable_provenance=executable.provenance,
        )
    absolute_argv = (executable.path, *argv[1:])
    try:
        completed = runner(
            absolute_argv,
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            # Do not inherit PATH, loader injection, Python, shell, or locale
            # variables from the invoking account.  The executable itself is
            # absolute and any helper lookup remains constrained to system
            # directories.
            env={
                "LC_ALL": "C",
                "LANG": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "TZ": "UTC",
            },
            shell=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandObservation(
            argv,
            "timeout",
            None,
            str(exc.stdout or ""),
            str(exc.stderr or ""),
            executable.path,
            executable.sha256,
            executable.status,
            executable.provenance,
        )
    except OSError as exc:
        return CommandObservation(
            argv,
            "error",
            None,
            "",
            str(exc),
            executable.path,
            executable.sha256,
            executable.status,
            executable.provenance,
        )
    stdout = completed.stdout[:MAX_CAPTURE_BYTES]
    stderr = completed.stderr[:MAX_CAPTURE_BYTES]
    status = "ok" if completed.returncode == 0 else "nonzero"
    return CommandObservation(
        argv,
        status,
        completed.returncode,
        stdout,
        stderr,
        executable.path,
        executable.sha256,
        executable.status,
        executable.provenance,
    )


def collect_observations(*, now: datetime | None = None) -> HostObservations:
    """Collect bounded read-only facts from Linux; WSL is intentionally supported."""

    if os.name != "posix" or not platform.system().lower().startswith("linux"):
        raise RuntimeError("G2 host inventory collection requires Linux or Ubuntu WSL")
    files = {path: _read_bounded(Path(path)) for path in READ_PATHS}
    efivar_root = Path("/sys/firmware/efi/efivars")
    try:
        secure_boot_variables = sorted(efivar_root.glob("SecureBoot-*"))
    except OSError:
        secure_boot_variables = []
    for path in secure_boot_variables[:1]:
        files[str(path)] = _read_bounded(path)
    present = frozenset(path for path in PRESENCE_PATHS if Path(path).exists())
    accelerator_nodes, accelerator_scan_truncated = _collect_accelerator_device_nodes()
    wsl_observed = (
        "microsoft" in _text(files, "/proc/sys/kernel/osrelease").lower()
        or "/dev/dxg" in present
    )
    commands = {
        probe_id: _run_read_only(
            argv,
            additional_roots=(
                WSL_NVIDIA_COMMAND_ROOTS
                if probe_id == "nvidia" and wsl_observed
                else ()
            ),
        )
        for probe_id, argv in READ_ONLY_COMMANDS.items()
    }
    return HostObservations(
        collected_at=now or datetime.now(UTC),
        machine=platform.machine(),
        files=files,
        present_paths=present,
        commands=commands,
        accelerator_device_nodes=accelerator_nodes,
        accelerator_scan_truncated=accelerator_scan_truncated,
    )
