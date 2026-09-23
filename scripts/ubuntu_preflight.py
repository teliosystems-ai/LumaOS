#!/usr/bin/env python3
"""Read-only Ubuntu/WSL readiness probe for the Luma OS developer runtime.

The probe deliberately does not install packages, create files, request sudo,
change services, inspect model contents, or touch disks.  Its native-candidate
mode is only an admission check for later lab work; it is never certification
evidence by itself.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
from typing import Callable, Mapping, Sequence


GIB = 1024**3
MAX_NATIVE_INVENTORY_AGE_SECONDS = 15 * 60
MAX_INVENTORY_FUTURE_SKEW_SECONDS = 5 * 60
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ENVIRONMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TRUSTED_COMMAND_ROOTS = {
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/lib/wsl/lib",
}
SUPPORTED_ARCHITECTURES = {"x86_64", "amd64"}
LOCAL_LINUX_FILESYSTEMS = {"btrfs", "ext2", "ext3", "ext4", "f2fs", "xfs", "zfs"}
WINDOWS_OR_REMOTE_FILESYSTEMS = {
    "9p",
    "cifs",
    "drvfs",
    "fuseblk",
    "nfs",
    "nfs4",
    "smb3",
}
REQUIRED_PROJECT_PATHS = (
    "README.md",
    "RELEASE_MANIFEST.json",
    "scripts/run.sh",
    "src/luma_os/cli.py",
    "web/index.html",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


@dataclass(frozen=True)
class ProbeAccess:
    """Injectable, read-only host access used by collection and tests."""

    read_text: Callable[[Path], str]
    exists: Callable[[Path], bool]
    run_command: Callable[[Sequence[str]], CommandResult]
    disk_usage: Callable[[Path], tuple[int, int, int]]
    machine: Callable[[], str]
    effective_uid: Callable[[], int | None]
    python_version: tuple[int, int, int]
    now_utc: Callable[[], datetime]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _run_command(arguments: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(127, "", str(exc))
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _disk_usage(path: Path) -> tuple[int, int, int]:
    usage = shutil.disk_usage(path)
    return usage.total, usage.used, usage.free


def default_access() -> ProbeAccess:
    return ProbeAccess(
        read_text=_read_text,
        exists=Path.exists,
        run_command=_run_command,
        disk_usage=_disk_usage,
        machine=platform.machine,
        effective_uid=lambda: os.geteuid() if hasattr(os, "geteuid") else None,
        python_version=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        now_utc=lambda: datetime.now(timezone.utc),
    )


def parse_os_release(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def parse_meminfo_bytes(content: str, field: str = "MemTotal") -> int | None:
    for line in content.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip() == field:
            parts = value.split()
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].lower() == "kb":
                return int(parts[0]) * 1024
    return None


def _safe_read(access: ProbeAccess, path: Path) -> str | None:
    try:
        return access.read_text(path)
    except (OSError, UnicodeError):
        return None


def _safe_exists(access: ProbeAccess, path: Path) -> bool:
    try:
        return access.exists(path)
    except OSError:
        return False


def _command(access: ProbeAccess, arguments: Sequence[str]) -> CommandResult:
    try:
        return access.run_command(arguments)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(127, "", str(exc))


def _normalize_architecture(value: str) -> str:
    return value.strip().lower()


def load_host_inventory(path: Path) -> tuple[dict[str, object], str]:
    """Load a bounded authoritative collector record without modifying it."""

    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read host inventory: {exc}") from exc
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("host inventory exceeds the 2 MiB input limit")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("host inventory is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("host inventory must be a JSON object")
    return document, hashlib.sha256(payload).hexdigest()


def validate_host_inventory(document: Mapping[str, object]) -> list[str]:
    """Validate the stable collector structure consumed by this probe.

    This is deliberately stricter than a shallow type check.  It is not a
    replacement for validating the complete JSON Schema in the evidence
    pipeline, but every value trusted or compared below is required here.
    """

    errors: list[str] = []

    def require_object(parent: Mapping[str, object], name: str, path: str) -> dict[str, object]:
        value = parent.get(name)
        if not isinstance(value, dict):
            errors.append(f"{path} must be an object")
            return {}
        return value

    def require_text(parent: Mapping[str, object], name: str, path: str) -> str:
        value = parent.get(name)
        if not isinstance(value, str) or not value:
            errors.append(f"{path} must be a non-empty string")
            return ""
        return value

    top_level_required = {
        "schema_version",
        "record_type",
        "record_id",
        "collected_at_utc",
        "environment_id",
        "collector",
        "evidence_boundary",
        "system",
        "probe_results",
        "findings",
    }
    missing_top_level = sorted(top_level_required - set(document))
    if missing_top_level:
        errors.append(f"missing top-level fields: {missing_top_level}")

    if document.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if document.get("record_type") != "luma-os-g2-host-inventory":
        errors.append("record_type must be luma-os-g2-host-inventory")
    require_text(document, "record_id", "record_id")
    collected_at = require_text(document, "collected_at_utc", "collected_at_utc")
    if collected_at and _parse_utc_timestamp(collected_at) is None:
        errors.append("collected_at_utc must be a timezone-aware RFC 3339 timestamp")
    environment_id = require_text(document, "environment_id", "environment_id")
    if environment_id and not ENVIRONMENT_ID_PATTERN.fullmatch(environment_id):
        errors.append("environment_id is invalid")

    collector = require_object(document, "collector", "collector")
    if collector:
        if collector.get("name") != "scripts/collect_g2_host.py":
            errors.append("collector.name is invalid")
        require_text(collector, "version", "collector.version")
        if collector.get("host_mutation_performed") is not False:
            errors.append("collector.host_mutation_performed must be false")
        if collector.get("commands_are_allowlisted_and_shell_free") is not True:
            errors.append("collector.commands_are_allowlisted_and_shell_free must be true")
        if collector.get("ambient_path_used") is not False:
            errors.append("collector.ambient_path_used must be false")
        if collector.get("ambient_environment_inherited") is not False:
            errors.append("collector.ambient_environment_inherited must be false")
        trusted_roots = collector.get("trusted_command_roots")
        if (
            not isinstance(trusted_roots, list)
            or not {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}.issubset(
                trusted_roots
            )
            or not set(trusted_roots).issubset(TRUSTED_COMMAND_ROOTS)
        ):
            errors.append("collector.trusted_command_roots is invalid")
        if not isinstance(collector.get("sensitive_identifiers_included"), bool):
            errors.append("collector.sensitive_identifiers_included must be boolean")

    boundary = require_object(document, "evidence_boundary", "evidence_boundary")
    if boundary:
        if boundary.get("gate_closing") is not False:
            errors.append("evidence_boundary.gate_closing must be false")
        if boundary.get("classification") not in {
            "physical-candidate-inventory-non-closing",
            "development-or-ineligible-inventory-non-closing",
        }:
            errors.append("evidence_boundary.classification is invalid")
        require_text(boundary, "reason", "evidence_boundary.reason")

    system = require_object(document, "system", "system")
    if not system:
        return errors
    required_system_fields = {
        "environment_kind",
        "environment_detection_source",
        "native_ubuntu_24_04_amd64_candidate",
        "pseudonymous_host_identity_sha256",
        "pseudonymous_host_identity_basis",
        "pseudonymous_host_identity_limitations",
        "os",
        "kernel",
        "firmware",
        "cpu",
        "memory",
        "security_controls",
        "storage",
        "accelerators",
        "accelerator_device_scan",
        "package_versions",
    }
    missing_system_fields = sorted(required_system_fields - set(system))
    if missing_system_fields:
        errors.append(f"system is missing stable fields: {missing_system_fields}")
    if system.get("environment_kind") not in {
        "native",
        "wsl2",
        "virtual-machine",
        "container",
        "unknown",
    }:
        errors.append("system.environment_kind is invalid")
    require_text(
        system, "environment_detection_source", "system.environment_detection_source"
    )
    if not isinstance(system.get("native_ubuntu_24_04_amd64_candidate"), bool):
        errors.append("system.native_ubuntu_24_04_amd64_candidate must be boolean")
    identity = system.get("pseudonymous_host_identity_sha256")
    if not isinstance(identity, str) or not SHA256_PATTERN.fullmatch(identity):
        errors.append("system.pseudonymous_host_identity_sha256 must be SHA-256")
    if (
        system.get("pseudonymous_host_identity_basis")
        != "domain-separated-sha256-of-etc-machine-id"
    ):
        errors.append("system.pseudonymous_host_identity_basis is invalid")
    require_text(
        system,
        "pseudonymous_host_identity_limitations",
        "system.pseudonymous_host_identity_limitations",
    )

    os_record = require_object(system, "os", "system.os")
    if os_record:
        missing_os_fields = {
            "id",
            "name",
            "version_id",
            "version_codename",
            "architecture",
        } - set(os_record)
        if missing_os_fields:
            errors.append(f"system.os is missing fields: {sorted(missing_os_fields)}")
        require_text(os_record, "architecture", "system.os.architecture")
    kernel = require_object(system, "kernel", "system.kernel")
    if kernel:
        require_text(kernel, "release", "system.kernel.release")
        if not isinstance(kernel.get("selected_command_line"), list):
            errors.append("system.kernel.selected_command_line must be an array")
        kernel_digest = kernel.get("full_command_line_sha256")
        if not isinstance(kernel_digest, str) or not SHA256_PATTERN.fullmatch(
            kernel_digest
        ):
            errors.append("system.kernel.full_command_line_sha256 must be SHA-256")

    cpu = require_object(system, "cpu", "system.cpu")
    if cpu:
        if "model" not in cpu:
            errors.append("system.cpu.model is required")
        logical_processors = cpu.get("logical_processors")
        if (
            not isinstance(logical_processors, int)
            or isinstance(logical_processors, bool)
            or logical_processors < 0
        ):
            errors.append("system.cpu.logical_processors is invalid")

    memory = require_object(system, "memory", "system.memory")
    if memory:
        total = memory.get("total_bytes")
        available = memory.get("available_bytes")
        if total is not None and (
            not isinstance(total, int) or isinstance(total, bool) or total < 0
        ):
            errors.append("system.memory.total_bytes is invalid")
        if (
            available is not None
            and (
                not isinstance(available, int)
                or isinstance(available, bool)
                or available < 0
                or isinstance(total, int)
                and available > total
            )
        ):
            errors.append("system.memory.available_bytes is invalid")

    firmware = require_object(system, "firmware", "system.firmware")
    if firmware:
        for name in ("uefi_present", "efivars_present"):
            if not isinstance(firmware.get(name), bool):
                errors.append(f"system.firmware.{name} must be boolean")
        secure_boot = require_object(
            firmware, "secure_boot", "system.firmware.secure_boot"
        )
        if secure_boot:
            if secure_boot.get("state") not in {"enabled", "disabled", "unknown"}:
                errors.append("system.firmware.secure_boot.state is invalid")
            require_text(
                secure_boot, "source", "system.firmware.secure_boot.source"
            )
        dmi = require_object(firmware, "dmi", "system.firmware.dmi")
        required_dmi_fields = {
            "system_vendor",
            "product_name",
            "product_version",
            "board_vendor",
            "board_name",
            "bios_vendor",
            "bios_version",
            "bios_date",
        }
        if dmi and required_dmi_fields - set(dmi):
            errors.append("system.firmware.dmi is incomplete")

    security = require_object(system, "security_controls", "system.security_controls")
    if security:
        missing_security_fields = {
            "cgroup_v2",
            "apparmor",
            "seccomp",
            "kvm",
            "tpm",
            "iommu",
            "lsm_modules",
        } - set(security)
        if missing_security_fields:
            errors.append(
                f"system.security_controls is missing fields: {sorted(missing_security_fields)}"
            )
        cgroup = require_object(
            security, "cgroup_v2", "system.security_controls.cgroup_v2"
        )
        apparmor = require_object(
            security, "apparmor", "system.security_controls.apparmor"
        )
        seccomp = require_object(
            security, "seccomp", "system.security_controls.seccomp"
        )
        if cgroup and not isinstance(cgroup.get("available"), bool):
            errors.append("system.security_controls.cgroup_v2.available must be boolean")
        if apparmor:
            for name in ("kernel_enabled", "listed_by_lsm"):
                if not isinstance(apparmor.get(name), bool):
                    errors.append(
                        f"system.security_controls.apparmor.{name} must be boolean"
                    )
        if seccomp and seccomp.get("collector_process_mode") not in {
            "disabled",
            "strict",
            "filter",
            "unknown",
        }:
            errors.append(
                "system.security_controls.seccomp.collector_process_mode is invalid"
            )
        for name in ("kvm", "tpm"):
            control = require_object(
                security, name, f"system.security_controls.{name}"
            )
            if control and not isinstance(control.get("device_present"), bool):
                errors.append(
                    f"system.security_controls.{name}.device_present must be boolean"
                )
        iommu = require_object(
            security, "iommu", "system.security_controls.iommu"
        )
        if iommu and (
            not isinstance(iommu.get("groups_path_present"), bool)
            or not isinstance(iommu.get("selected_kernel_arguments"), list)
        ):
            errors.append("system.security_controls.iommu is invalid")
        if not isinstance(security.get("lsm_modules"), list):
            errors.append("system.security_controls.lsm_modules must be an array")

    accelerators = system.get("accelerators")
    if not isinstance(accelerators, list):
        errors.append("system.accelerators must be an array")
    else:
        accelerator_fields = {
            "kind",
            "source",
            "vendor",
            "name",
            "device_path",
            "device_identity_sha256",
            "identity_basis",
            "driver_version",
            "memory_bytes",
            "major",
            "minor",
            "mode",
            "owner_uid",
            "owner_gid",
            "readable_by_collector",
            "writable_by_collector",
        }
        for index, accelerator in enumerate(accelerators):
            if not isinstance(accelerator, dict):
                errors.append(f"system.accelerators[{index}] must be an object")
                continue
            if accelerator_fields - set(accelerator):
                errors.append(f"system.accelerators[{index}] is incomplete")
            if accelerator.get("kind") not in {
                "nvidia-smi",
                "drm-render",
                "accel",
                "wsl-dxg",
            }:
                errors.append(f"system.accelerators[{index}].kind is invalid")
            if accelerator.get("source") not in {"nvidia-smi", "device-node"}:
                errors.append(f"system.accelerators[{index}].source is invalid")
            require_text(
                accelerator, "name", f"system.accelerators[{index}].name"
            )

    accelerator_scan = require_object(
        system, "accelerator_device_scan", "system.accelerator_device_scan"
    )
    if accelerator_scan and (
        accelerator_scan.get("allowlisted_roots")
        != ["/dev/dri/renderD[0-9]+", "/dev/accel/accel[0-9]+", "/dev/dxg"]
        or accelerator_scan.get("maximum_nodes") != 128
        or not isinstance(accelerator_scan.get("truncated"), bool)
        or accelerator_scan.get("recursive") is not False
        or accelerator_scan.get("symlinks_followed") is not False
    ):
        errors.append("system.accelerator_device_scan is invalid")
    if not isinstance(system.get("package_versions"), list):
        errors.append("system.package_versions must be an array")

    storage = require_object(system, "storage", "system.storage")
    if storage:
        root_mount = require_object(storage, "root_mount", "system.storage.root_mount")
        if root_mount and (
            "source" not in root_mount
            or "filesystem" not in root_mount
            or not isinstance(root_mount.get("options"), list)
        ):
            errors.append("system.storage.root_mount is invalid")
        if not isinstance(storage.get("verity_probe_status"), str):
            errors.append("system.storage.verity_probe_status is invalid")
    devices = storage.get("block_devices") if storage else None
    if not isinstance(devices, list):
        errors.append("system.storage.block_devices must be an array")
    elif any(
        not isinstance(device, dict)
        or device.get("operator_disposition") != "unclassified-never-auto-selected"
        for device in devices
    ):
        errors.append("collector disks must remain unclassified-never-auto-selected")

    probe_results = document.get("probe_results")
    if not isinstance(probe_results, list) or not probe_results:
        errors.append("probe_results must be a non-empty array")
    elif any(
        not isinstance(item, dict)
        or not isinstance(item.get("probe_id"), str)
        or not isinstance(item.get("status"), str)
        for item in probe_results
    ):
        errors.append("probe_results entries are invalid")
    else:
        for index, probe in enumerate(probe_results):
            assert isinstance(probe, dict)
            resolved_path = probe.get("resolved_executable_path")
            resolved_sha256 = probe.get("resolved_executable_sha256")
            provenance_status = probe.get("executable_provenance_status")
            provenance = probe.get("executable_provenance")
            if resolved_path is not None and (
                not isinstance(resolved_path, str)
                or not resolved_path.startswith("/")
                or str(PurePosixPath(resolved_path).parent) not in TRUSTED_COMMAND_ROOTS
            ):
                errors.append(f"probe_results[{index}] resolved path is invalid")
            if resolved_sha256 is not None and (
                not isinstance(resolved_sha256, str)
                or not SHA256_PATTERN.fullmatch(resolved_sha256)
            ):
                errors.append(f"probe_results[{index}] executable digest is invalid")
            if provenance_status not in {
                "trusted",
                "not-found",
                "rejected",
                "injected-not-recorded",
            }:
                errors.append(f"probe_results[{index}] provenance status is invalid")
            if not isinstance(provenance, list) or any(
                not isinstance(entry, dict)
                or not {
                    "path",
                    "kind",
                    "owner_uid",
                    "owner_gid",
                    "mode",
                    "size_bytes",
                }.issubset(entry)
                for entry in provenance
            ):
                errors.append(f"probe_results[{index}] provenance is invalid")
            if provenance_status == "trusted" and (
                resolved_path is None or resolved_sha256 is None or not provenance
            ):
                errors.append(f"probe_results[{index}] trusted provenance is incomplete")
        probe_ids = {str(item.get("probe_id")) for item in probe_results}
        required_probe_ids = {
            "virtualization",
            "secure_boot",
            "root_mount",
            "block_devices",
            "nvidia",
            "bootctl",
            "verity",
            "packages",
        }
        if not required_probe_ids.issubset(probe_ids):
            errors.append("probe_results omits an authoritative collector probe")
    findings = document.get("findings")
    if not isinstance(findings, list) or not findings:
        errors.append("findings must be a non-empty array")
    elif any(
        not isinstance(item, dict)
        or not isinstance(item.get("id"), str)
        or not isinstance(item.get("status"), str)
        for item in findings
    ):
        errors.append("findings entries are invalid")
    return errors


def _parse_utc_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _is_wsl(kernel_release: str, kernel_version: str) -> tuple[bool, int | None]:
    combined = f"{kernel_release}\n{kernel_version}".lower()
    if "microsoft" not in combined and "wsl" not in combined:
        return False, None
    return True, 2 if "wsl2" in combined or "microsoft-standard" in combined else 1


def _check(
    checks: list[dict[str, object]],
    *,
    check_id: str,
    passed: bool,
    required: bool,
    detail: str,
    observed: object = None,
) -> None:
    item: dict[str, object] = {
        "id": check_id,
        "status": "pass" if passed else ("fail" if required else "warning"),
        "required": required,
        "detail": detail,
    }
    if observed is not None:
        item["observed"] = observed
    checks.append(item)


def collect_preflight(
    *,
    mode: str,
    project_root: Path,
    hardware_class: str = "none",
    access: ProbeAccess | None = None,
    host_inventory: Mapping[str, object] | None = None,
    host_inventory_sha256: str | None = None,
) -> dict[str, object]:
    """Collect a read-only readiness record.

    ``development`` admits native Ubuntu or WSL2 for source tests.  The stricter
    ``native-candidate`` mode admits only a physical-candidate Ubuntu 24.04 host
    with visible baseline controls.  Even a pass remains non-closing evidence.
    """

    if mode not in {"development", "native-candidate"}:
        raise ValueError("mode must be development or native-candidate")
    if hardware_class not in {"none", "e1", "e2"}:
        raise ValueError("hardware_class must be none, e1, or e2")

    access = access or default_access()
    native_candidate = mode == "native-candidate"
    checks: list[dict[str, object]] = []
    observed_now = access.now_utc()
    if observed_now.tzinfo is None:
        raise ValueError("probe clock must be timezone-aware")
    observed_now = observed_now.astimezone(timezone.utc)

    _check(
        checks,
        check_id="hardware-class-selected",
        passed=not native_candidate or hardware_class in {"e1", "e2"},
        required=native_candidate,
        detail="Native-candidate mode requires an explicit e1 or e2 hardware class.",
        observed=hardware_class,
    )

    inventory_errors = (
        validate_host_inventory(host_inventory) if host_inventory is not None else []
    )
    inventory_valid = host_inventory is not None and not inventory_errors
    _check(
        checks,
        check_id="authoritative-host-inventory",
        passed=inventory_valid if host_inventory is not None else not native_candidate,
        required=native_candidate or host_inventory is not None,
        detail=(
            "Native-candidate admission consumes the read-only "
            "scripts/collect_g2_host.py record and never selects or reclassifies disks."
        ),
        observed={
            "supplied": host_inventory is not None,
            "errors": inventory_errors,
            "record_id": host_inventory.get("record_id") if inventory_valid else None,
            "environment_id": (
                host_inventory.get("environment_id") if inventory_valid else None
            ),
            "sha256": host_inventory_sha256,
        },
    )
    inventory_digest_valid = (
        isinstance(host_inventory_sha256, str)
        and SHA256_PATTERN.fullmatch(host_inventory_sha256) is not None
    )
    _check(
        checks,
        check_id="host-inventory-digest",
        passed=(
            inventory_digest_valid
            if host_inventory is not None
            else not native_candidate
        ),
        required=native_candidate,
        detail="Native admission binds the exact collector JSON bytes by SHA-256.",
        observed=host_inventory_sha256,
    )
    inventory_collected_at = (
        _parse_utc_timestamp(str(host_inventory.get("collected_at_utc")))
        if inventory_valid
        else None
    )
    inventory_age_seconds = (
        (observed_now - inventory_collected_at).total_seconds()
        if inventory_collected_at is not None
        else None
    )
    inventory_fresh = (
        inventory_age_seconds is not None
        and -MAX_INVENTORY_FUTURE_SKEW_SECONDS
        <= inventory_age_seconds
        <= MAX_NATIVE_INVENTORY_AGE_SECONDS
    )
    _check(
        checks,
        check_id="host-inventory-freshness",
        passed=(
            inventory_fresh
            if host_inventory is not None
            else not native_candidate
        ),
        required=native_candidate,
        detail=(
            "Native admission requires a collector record no older than 15 minutes "
            "and no more than five minutes ahead of the probe clock."
        ),
        observed={
            "collected_at_utc": (
                inventory_collected_at.isoformat().replace("+00:00", "Z")
                if inventory_collected_at is not None
                else None
            ),
            "age_seconds": inventory_age_seconds,
            "maximum_age_seconds": MAX_NATIVE_INVENTORY_AGE_SECONDS,
            "maximum_future_skew_seconds": MAX_INVENTORY_FUTURE_SKEW_SECONDS,
        },
    )

    os_release_text = _safe_read(access, Path("/etc/os-release")) or ""
    os_release = parse_os_release(os_release_text)
    os_id = os_release.get("ID", "unknown").lower()
    os_version = os_release.get("VERSION_ID", "unknown")
    os_name = os_release.get("PRETTY_NAME", os_release.get("NAME", "unknown"))

    kernel_release = (_safe_read(access, Path("/proc/sys/kernel/osrelease")) or "").strip()
    kernel_version = (_safe_read(access, Path("/proc/version")) or "").strip()
    wsl, wsl_version = _is_wsl(kernel_release, kernel_version)
    environment_kind = "wsl2" if wsl and wsl_version == 2 else "wsl1" if wsl else "native"
    architecture = _normalize_architecture(access.machine())
    live_facts = {
        "environment_kind": environment_kind,
        "os_id": os_id,
        "os_version": os_version,
        "architecture": architecture,
    }
    machine_id = (_safe_read(access, Path("/etc/machine-id")) or "").strip()
    live_host_identity = (
        hashlib.sha256(
            f"luma-g2-host-id-v1\0{machine_id}".encode("utf-8")
        ).hexdigest()
        if machine_id
        else None
    )
    inventory_system: Mapping[str, object] = {}
    inventory_probes: dict[str, Mapping[str, object]] = {}
    if inventory_valid:
        raw_system = host_inventory.get("system")
        assert isinstance(raw_system, dict)
        inventory_system = raw_system
        raw_probes = host_inventory.get("probe_results")
        assert isinstance(raw_probes, list)
        inventory_probes = {
            str(probe["probe_id"]): probe
            for probe in raw_probes
            if isinstance(probe, dict)
        }
    required_trusted_probes = {
        "virtualization",
        "secure_boot",
        "root_mount",
        "block_devices",
    }
    if inventory_valid and any(
        isinstance(item, dict) and str(item.get("vendor") or "").lower() == "nvidia"
        for item in inventory_system.get("accelerators", [])
    ):
        required_trusted_probes.add("nvidia")
    untrusted_probes = sorted(
        probe_id
        for probe_id in required_trusted_probes
        if probe_id not in inventory_probes
        or inventory_probes[probe_id].get("executable_provenance_status") != "trusted"
        or not isinstance(
            inventory_probes[probe_id].get("resolved_executable_path"), str
        )
        or not isinstance(
            inventory_probes[probe_id].get("resolved_executable_sha256"), str
        )
        or (
            inventory_probes[probe_id].get("status") != "ok"
            if probe_id != "virtualization"
            else inventory_probes[probe_id].get("status") not in {"ok", "nonzero"}
        )
    )
    _check(
        checks,
        check_id="trusted-probe-executables",
        passed=not untrusted_probes if host_inventory is not None else not native_candidate,
        required=native_candidate,
        detail=(
            "Native positive security, storage, virtualization, and accelerator "
            "observations require root-owned trusted executable provenance."
        ),
        observed={"untrusted_or_missing": untrusted_probes},
    )

    def probe_argv(probe_id: str, arguments: tuple[str, ...]) -> tuple[str, ...]:
        probe = inventory_probes.get(probe_id)
        if probe is not None and probe.get("executable_provenance_status") == "trusted":
            resolved = probe.get("resolved_executable_path")
            if isinstance(resolved, str):
                return (resolved, *arguments[1:])
        if host_inventory is not None:
            return (f"/luma-invalid-untrusted-probe/{probe_id}", *arguments[1:])
        return arguments
    inventory_matches_live_host = host_inventory is None and not native_candidate
    inventory_comparison: dict[str, object] = {"performed": False}
    if inventory_valid:
        inventory_identity = inventory_system.get("pseudonymous_host_identity_sha256")
        inventory_os = inventory_system.get("os")
        inventory_kernel = inventory_system.get("kernel")
        assert isinstance(inventory_os, dict)
        assert isinstance(inventory_kernel, dict)
        inventory_facts = {
            "environment_kind": inventory_system.get("environment_kind"),
            "os_id": str(inventory_os.get("id") or "unknown").lower(),
            "os_version": str(inventory_os.get("version_id") or "unknown"),
            "architecture": _normalize_architecture(
                str(inventory_os.get("architecture") or "unknown")
            ),
        }
        inventory_comparison = {
            "performed": True,
            "live_facts": live_facts,
            "inventory_facts": inventory_facts,
            "kernel_release_match": inventory_kernel.get("release") == kernel_release,
            "pseudonymous_identity_match": (
                bool(live_host_identity)
                and live_host_identity == inventory_identity
            ),
        }
        inventory_matches_live_host = (
            live_facts == inventory_facts
            and inventory_comparison["kernel_release_match"] is True
            and inventory_comparison["pseudonymous_identity_match"] is True
        )
    _check(
        checks,
        check_id="host-inventory-current-host-binding",
        passed=inventory_matches_live_host,
        required=native_candidate or host_inventory is not None,
        detail="The collector record must describe the same currently running host.",
        observed=inventory_comparison,
    )
    inventory_native_classification = (
        inventory_valid
        and inventory_system.get("native_ubuntu_24_04_amd64_candidate") is True
    )
    _check(
        checks,
        check_id="host-inventory-native-classification",
        passed=inventory_native_classification if native_candidate else True,
        required=native_candidate,
        detail=(
            "The fresh collector record must itself classify this exact host as a "
            "native Ubuntu 24.04 amd64 candidate."
        ),
        observed=(
            inventory_system.get("native_ubuntu_24_04_amd64_candidate")
            if inventory_valid
            else None
        ),
    )
    python_version = access.python_version
    effective_uid = access.effective_uid()

    _check(
        checks,
        check_id="ubuntu-os",
        passed=os_id == "ubuntu",
        required=True,
        detail="The developer runtime requires an Ubuntu userspace.",
        observed={"id": os_id, "version_id": os_version, "name": os_name},
    )
    _check(
        checks,
        check_id="wsl2-or-native",
        passed=not wsl or wsl_version == 2,
        required=True,
        detail="WSL1 is unsupported; use native Ubuntu or WSL2.",
        observed={"environment_kind": environment_kind, "kernel_release": kernel_release},
    )
    _check(
        checks,
        check_id="native-ubuntu",
        passed=not wsl,
        required=native_candidate,
        detail=(
            "Native-candidate mode cannot be satisfied by WSL."
            if native_candidate
            else "WSL2 is accepted only for non-closing development tests."
        ),
        observed=environment_kind,
    )
    _check(
        checks,
        check_id="ubuntu-24.04-baseline",
        passed=os_version == "24.04",
        required=native_candidate,
        detail=(
            "Formal native-candidate admission is pinned to Ubuntu 24.04."
            if native_candidate
            else "Other Ubuntu releases are development-only until separately qualified."
        ),
        observed=os_version,
    )
    _check(
        checks,
        check_id="architecture",
        passed=architecture in SUPPORTED_ARCHITECTURES,
        required=True,
        detail="The current A1 reference-board baseline is x86-64.",
        observed=architecture,
    )
    _check(
        checks,
        check_id="python-version",
        passed=python_version >= (3, 11, 0),
        required=True,
        detail="Python 3.11 or newer is required.",
        observed=".".join(str(part) for part in python_version),
    )
    _check(
        checks,
        check_id="unprivileged-user",
        passed=effective_uid not in {None, 0},
        required=True,
        detail="Run the source runtime and user installer without root or sudo.",
        observed=effective_uid,
    )

    missing_project_paths = [
        relative
        for relative in REQUIRED_PROJECT_PATHS
        if not _safe_exists(access, project_root / relative)
    ]
    _check(
        checks,
        check_id="source-layout",
        passed=not missing_project_paths,
        required=True,
        detail="The checkout or extracted source archive must contain all runtime inputs.",
        observed={"project_root": str(project_root), "missing": missing_project_paths},
    )

    findmnt = _command(
        access,
        probe_argv(
            "root_mount",
            ("findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(project_root)),
        ),
    )
    filesystem_type = findmnt.stdout.strip().splitlines()[0].strip().lower() if findmnt.stdout.strip() else "unknown"
    local_filesystem = filesystem_type in LOCAL_LINUX_FILESYSTEMS
    windows_or_remote = filesystem_type in WINDOWS_OR_REMOTE_FILESYSTEMS
    _check(
        checks,
        check_id="linux-local-filesystem",
        passed=local_filesystem,
        required=native_candidate,
        detail=(
            "Use a native Linux filesystem for qualification; Windows-mounted and remote paths do not prove Linux permission or durability semantics."
        ),
        observed={"filesystem_type": filesystem_type, "windows_or_remote": windows_or_remote},
    )

    meminfo = _safe_read(access, Path("/proc/meminfo")) or ""
    memory_bytes = parse_meminfo_bytes(meminfo)
    memory_floor = 15 * GIB if hardware_class == "e1" else 30 * GIB if hardware_class == "e2" else 0
    _check(
        checks,
        check_id="reported-memory",
        passed=memory_bytes is not None and memory_bytes >= memory_floor,
        required=native_candidate and hardware_class != "none",
        detail=(
            "Reported usable memory is only an admission signal; independently inventory installed physical memory."
        ),
        observed={"bytes": memory_bytes, "hardware_class": hardware_class, "required_floor_bytes": memory_floor},
    )
    try:
        disk_total, _disk_used, disk_free = access.disk_usage(project_root)
    except OSError:
        disk_total, disk_free = None, None
    _check(
        checks,
        check_id="filesystem-capacity-observed",
        passed=disk_total is not None,
        required=True,
        detail="Capacity is recorded only; the selected model profile performs its own exact storage check.",
        observed={"total_bytes": disk_total, "free_bytes": disk_free},
    )

    pid1_comm = (_safe_read(access, Path("/proc/1/comm")) or "").strip()
    _check(
        checks,
        check_id="systemd-pid1",
        passed=pid1_comm == "systemd",
        required=native_candidate,
        detail="Native qualification requires the retained systemd boot and service environment.",
        observed=pid1_comm or "unknown",
    )
    security_controls = inventory_system.get("security_controls") if inventory_valid else {}
    if not isinstance(security_controls, dict):
        security_controls = {}
    inventory_cgroup = security_controls.get("cgroup_v2")
    inventory_apparmor = security_controls.get("apparmor")
    inventory_seccomp = security_controls.get("seccomp")
    cgroup_available = _safe_exists(
        access, Path("/sys/fs/cgroup/cgroup.controllers")
    )
    _check(
        checks,
        check_id="cgroup-v2",
        passed=cgroup_available,
        required=native_candidate,
        detail="A visible cgroup v2 hierarchy is required before enforcement qualification.",
        observed={
            "live_available": cgroup_available,
            "inventory": inventory_cgroup,
        },
    )
    apparmor = (_safe_read(access, Path("/sys/module/apparmor/parameters/enabled")) or "").strip().lower()
    live_lsm_modules = {
        item.strip()
        for item in (
            _safe_read(access, Path("/sys/kernel/security/lsm")) or ""
        ).split(",")
        if item.strip()
    }
    apparmor_available = (
        apparmor in {"y", "yes", "1"} and "apparmor" in live_lsm_modules
    )
    _check(
        checks,
        check_id="apparmor-kernel-enabled",
        passed=apparmor_available,
        required=native_candidate,
        detail="This checks kernel enablement only; loaded enforcing Luma policy must be proven separately.",
        observed={
            "live_kernel_enabled": apparmor in {"y", "yes", "1"},
            "live_listed_by_lsm": "apparmor" in live_lsm_modules,
            "inventory": inventory_apparmor,
        },
    )
    seccomp_actions = (_safe_read(access, Path("/proc/sys/kernel/seccomp/actions_avail")) or "").strip()
    seccomp_available = bool(seccomp_actions)
    _check(
        checks,
        check_id="seccomp-kernel-interface",
        passed=seccomp_available,
        required=native_candidate,
        detail="This checks kernel availability only; the Luma worker policy must be tested separately.",
        observed={
            "kernel_actions": seccomp_actions or "unknown",
            "collector_process": (
                inventory_seccomp if isinstance(inventory_seccomp, dict) else None
            ),
        },
    )
    firmware = inventory_system.get("firmware") if inventory_valid else {}
    if not isinstance(firmware, dict):
        firmware = {}
    live_uefi_present = _safe_exists(access, Path("/sys/firmware/efi"))
    live_efivars_present = _safe_exists(access, Path("/sys/firmware/efi/efivars"))
    uefi_present = live_uefi_present and live_efivars_present
    _check(
        checks,
        check_id="uefi-runtime",
        passed=uefi_present,
        required=native_candidate,
        detail="Native Secure Boot and recovery qualification requires a UEFI booted system.",
        observed={
            "live_uefi_present": live_uefi_present,
            "live_efivars_present": live_efivars_present,
            "inventory_uefi_present": firmware.get("uefi_present"),
            "inventory_efivars_present": firmware.get("efivars_present"),
        },
    )
    inventory_secure_boot = firmware.get("secure_boot")
    secure_boot = _command(
        access, probe_argv("secure_boot", ("mokutil", "--sb-state"))
    )
    secure_boot_output = f"{secure_boot.stdout}\n{secure_boot.stderr}".strip()
    secure_boot_enabled = (
        secure_boot.returncode == 0
        and "secureboot enabled" in secure_boot_output.lower()
    )
    _check(
        checks,
        check_id="secure-boot-enabled",
        passed=secure_boot_enabled,
        required=native_candidate,
        detail="Secure Boot must be enabled for native image and tamper qualification.",
        observed={
            "live": secure_boot_output or "mokutil unavailable or returned no state",
            "inventory": inventory_secure_boot,
        },
    )

    virtualization = _command(
        access,
        probe_argv("virtualization", ("systemd-detect-virt", "--vm")),
    )
    virtualization_name = virtualization.stdout.strip().lower()
    appears_physical = (
        virtualization.returncode != 0 and virtualization_name in {"", "none"}
    )
    _check(
        checks,
        check_id="physical-host-candidate",
        passed=appears_physical and not wsl,
        required=native_candidate,
        detail="A VM or WSL guest cannot satisfy either physical A1 board slot.",
        observed=virtualization_name or "none-detected",
    )

    accelerator_paths = {
        "nvidia": Path("/dev/nvidia0"),
        "drm_render": Path("/dev/dri/renderD128"),
        "accel": Path("/dev/accel/accel0"),
        "wsl_dxg": Path("/dev/dxg"),
    }
    visible_accelerator_paths = [
        name for name, path in accelerator_paths.items() if _safe_exists(access, path)
    ]
    nvidia_live = _command(
        access,
        probe_argv(
            "nvidia",
            (
                "nvidia-smi",
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader,nounits",
            ),
        ),
    )
    live_nvidia_names = [
        line.split(",", 1)[0].strip()
        for line in nvidia_live.stdout.splitlines()
        if nvidia_live.returncode == 0 and line.strip()
    ]
    visible_accelerators = sorted(
        set(visible_accelerator_paths + live_nvidia_names)
    )
    raw_accelerators = inventory_system.get("accelerators") if inventory_valid else []
    if not isinstance(raw_accelerators, list):
        raw_accelerators = []
    require_accelerator = native_candidate and hardware_class in {"e1", "e2"}
    _check(
        checks,
        check_id="accelerator-device-visible",
        passed=bool(visible_accelerators) and (not wsl or visible_accelerators != ["wsl_dxg"]),
        required=require_accelerator,
        detail="Device visibility is not driver, isolation, reset, or model-runtime qualification.",
        observed={
            "live": visible_accelerators,
            "inventory_count": len(raw_accelerators),
        },
    )

    inventory_corroboration_mismatches: list[str] = []
    if inventory_valid:
        inventory_memory = inventory_system.get("memory")
        assert isinstance(inventory_memory, dict)
        if inventory_memory.get("total_bytes") != memory_bytes:
            inventory_corroboration_mismatches.append("memory.total_bytes")
        if not isinstance(inventory_cgroup, dict) or (
            inventory_cgroup.get("available") is not cgroup_available
        ):
            inventory_corroboration_mismatches.append("security.cgroup_v2")
        if not isinstance(inventory_apparmor, dict) or (
            inventory_apparmor.get("kernel_enabled")
            is not (apparmor in {"y", "yes", "1"})
            or inventory_apparmor.get("listed_by_lsm")
            is not ("apparmor" in live_lsm_modules)
        ):
            inventory_corroboration_mismatches.append("security.apparmor")
        if (
            firmware.get("uefi_present") is not live_uefi_present
            or firmware.get("efivars_present") is not live_efivars_present
        ):
            inventory_corroboration_mismatches.append("firmware.uefi")
        live_secure_boot_state = (
            "enabled"
            if secure_boot_enabled
            else "disabled"
            if secure_boot.returncode == 0
            and "secureboot disabled" in secure_boot_output.lower()
            else "unknown"
        )
        if (
            not isinstance(inventory_secure_boot, dict)
            or inventory_secure_boot.get("state") != live_secure_boot_state
        ):
            inventory_corroboration_mismatches.append("firmware.secure_boot")

        live_accelerator_present = bool(visible_accelerators)
        inventory_accelerator_present = bool(raw_accelerators)
        if live_accelerator_present != inventory_accelerator_present:
            inventory_corroboration_mismatches.append("accelerators.presence")
        for index, accelerator in enumerate(raw_accelerators):
            assert isinstance(accelerator, dict)
            device_path = accelerator.get("device_path")
            vendor = str(accelerator.get("vendor") or "").lower()
            name = str(accelerator.get("name") or "")
            correlated = False
            if isinstance(device_path, str) and device_path.startswith("/dev/"):
                correlated = _safe_exists(access, Path(device_path))
            if not correlated and vendor == "nvidia":
                correlated = bool(live_nvidia_names) and (
                    not name or name in live_nvidia_names
                )
            if not correlated and vendor != "nvidia":
                correlated = bool(visible_accelerator_paths)
            if not correlated:
                inventory_corroboration_mismatches.append(
                    f"accelerators[{index}]"
                )
    _check(
        checks,
        check_id="host-inventory-live-corroboration",
        passed=(
            not inventory_corroboration_mismatches
            if host_inventory is not None
            else not native_candidate
        ),
        required=native_candidate or host_inventory is not None,
        detail=(
            "Inventory security, firmware, memory, and accelerator claims must "
            "match independent live probes and can never make a live check pass."
        ),
        observed={"mismatches": inventory_corroboration_mismatches},
    )

    failures = [str(item["id"]) for item in checks if item["status"] == "fail"]
    warnings = [str(item["id"]) for item in checks if item["status"] == "warning"]
    result = (
        "fail-prerequisites"
        if failures
        else "pass-native-candidate-preflight"
        if native_candidate
        else "pass-development-preflight"
    )

    return {
        "schema_version": 1,
        "tool": "luma-os-ubuntu-preflight",
        "observed_at": observed_now.isoformat().replace("+00:00", "Z"),
        "mode": mode,
        "hardware_class": hardware_class,
        "read_only": True,
        "result": result,
        "exit_ready": not failures,
        "certification_closing": False,
        "environment": {
            "kind": environment_kind,
            "wsl_version": wsl_version,
            "os_id": os_id,
            "os_version": os_version,
            "os_name": os_name,
            "kernel_release": kernel_release,
            "architecture": architecture,
            "python_version": ".".join(str(part) for part in python_version),
            "effective_uid": effective_uid,
            "project_root": str(project_root),
            "project_filesystem": filesystem_type,
            "reported_memory_bytes": memory_bytes,
            "filesystem_total_bytes": disk_total,
            "filesystem_free_bytes": disk_free,
            "visible_accelerator_devices": visible_accelerators,
        },
        "host_inventory": {
            "supplied": host_inventory is not None,
            "valid": inventory_valid,
            "record_id": host_inventory.get("record_id") if inventory_valid else None,
            "environment_id": (
                host_inventory.get("environment_id") if inventory_valid else None
            ),
            "sha256": host_inventory_sha256,
            "age_seconds": inventory_age_seconds,
            "fresh_for_native_admission": inventory_fresh,
            "disk_disposition": "unclassified-never-auto-selected",
        },
        "checks": checks,
        "missing_prerequisites": failures,
        "warnings": warnings,
        "unresolved_qualification_work": [
            "independently designate and inventory separate E1 and E2 physical boards",
            "use separately identified disposable target disks and preserve before/after inventories",
            "verify signed release, model catalog, runtime, UKI, recovery media, and trust-root custody",
            "execute destructive install, LUKS2 recovery, dm-verity, A/B fallback, tamper, and power-loss tests",
            "prove enforcing cgroup, AppArmor, seccomp, device, peer-credential, and generated-code isolation",
            "complete both-board lifecycle, pressure, performance, security, recovery, and vertical-workflow suites",
        ],
        "claim_boundary": (
            "A passing result admits the host to the next documented development or lab step only. "
            "It does not certify hardware, installation, boot, encryption, isolation, model quality, or recovery."
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Luma OS readiness probe for Ubuntu and Ubuntu under WSL2."
    )
    parser.add_argument(
        "--mode",
        choices=("development", "native-candidate"),
        default="development",
        help="development admits WSL2; native-candidate never does",
    )
    parser.add_argument(
        "--hardware-class",
        choices=("none", "e1", "e2"),
        default="none",
        help="apply the reported-memory and accelerator admission checks for E1 or E2",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="checkout or extracted source root to inspect",
    )
    parser.add_argument(
        "--host-inventory",
        type=Path,
        help="JSON from scripts/collect_g2_host.py; required by native-candidate admission",
    )
    parser.add_argument("--pretty", action="store_true", help="indent the JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    host_inventory = None
    host_inventory_sha256 = None
    if arguments.host_inventory is not None:
        try:
            host_inventory, host_inventory_sha256 = load_host_inventory(
                arguments.host_inventory
            )
        except ValueError as exc:
            build_parser().error(str(exc))
    record = collect_preflight(
        mode=arguments.mode,
        project_root=arguments.project_root.resolve(),
        hardware_class=arguments.hardware_class,
        host_inventory=host_inventory,
        host_inventory_sha256=host_inventory_sha256,
    )
    json.dump(record, sys.stdout, indent=2 if arguments.pretty else None, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if record["exit_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
