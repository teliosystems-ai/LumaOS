from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ubuntu_preflight import (  # noqa: E402
    CommandResult,
    GIB,
    ProbeAccess,
    collect_preflight,
    main,
    parse_meminfo_bytes,
    parse_os_release,
)


PROJECT_ROOT = Path("/workspace/luma-os")
MACHINE_ID = "0123456789abcdef0123456789abcdef"
MACHINE_ID_SHA256 = hashlib.sha256(
    f"luma-g2-host-id-v1\0{MACHINE_ID}".encode("utf-8")
).hexdigest()
PROBE_EXECUTABLES = {
    "virtualization": "systemd-detect-virt",
    "secure_boot": "mokutil",
    "root_mount": "findmnt",
    "block_devices": "lsblk",
    "nvidia": "nvidia-smi",
    "bootctl": "bootctl",
    "verity": "dmsetup",
    "packages": "dpkg-query",
}


def fake_inventory(
    *,
    wsl: bool = False,
    collected_at: str = "2026-09-23T11:55:00Z",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "record_type": "luma-os-g2-host-inventory",
        "record_id": "G2-HOST-E2-TEST",
        "collected_at_utc": collected_at,
        "environment_id": "DEV-WSL" if wsl else "E2",
        "collector": {
            "name": "scripts/collect_g2_host.py",
            "version": "1.0",
            "host_mutation_performed": False,
            "commands_are_allowlisted_and_shell_free": True,
            "ambient_path_used": False,
            "ambient_environment_inherited": False,
            "trusted_command_roots": ["/usr/sbin", "/usr/bin", "/sbin", "/bin"],
            "sensitive_identifiers_included": False,
        },
        "evidence_boundary": {
            "gate_closing": False,
            "classification": (
                "development-or-ineligible-inventory-non-closing"
                if wsl
                else "physical-candidate-inventory-non-closing"
            ),
            "reason": "fixture remains non-closing",
        },
        "system": {
            "environment_kind": "wsl2" if wsl else "native",
            "environment_detection_source": "fixture",
            "native_ubuntu_24_04_amd64_candidate": not wsl,
            "pseudonymous_host_identity_sha256": MACHINE_ID_SHA256,
            "pseudonymous_host_identity_basis": (
                "domain-separated-sha256-of-etc-machine-id"
            ),
            "pseudonymous_host_identity_limitations": (
                "Fixture identity is host-local and non-secret."
            ),
            "os": {
                "id": "ubuntu",
                "name": "Ubuntu",
                "version_id": "24.04",
                "version_codename": "noble",
                "architecture": "x86_64",
            },
            "kernel": {
                "release": (
                    "6.18.33.2-microsoft-standard-WSL2"
                    if wsl
                    else "6.8.0-48-generic"
                ),
                "selected_command_line": [],
                "full_command_line_sha256": "c" * 64,
            },
            "cpu": {"model": "fixture-cpu", "logical_processors": 8},
            "memory": {"total_bytes": 32 * GIB, "available_bytes": 24 * GIB},
            "firmware": {
                "uefi_present": not wsl,
                "efivars_present": not wsl,
                "secure_boot": {
                    "state": "enabled" if not wsl else "unknown",
                    "source": "mokutil" if not wsl else "unavailable",
                },
                "dmi": {
                    "system_vendor": None,
                    "product_name": None,
                    "product_version": None,
                    "board_vendor": None,
                    "board_name": None,
                    "bios_vendor": None,
                    "bios_version": None,
                    "bios_date": None,
                },
            },
            "security_controls": {
                "cgroup_v2": {"available": True, "controllers": ["memory"]},
                "apparmor": {"kernel_enabled": True, "listed_by_lsm": True},
                "seccomp": {"collector_process_mode": "filter"},
                "kvm": {"device_present": False},
                "tpm": {"device_present": False},
                "iommu": {
                    "groups_path_present": False,
                    "selected_kernel_arguments": [],
                },
                "lsm_modules": ["apparmor"],
            },
            "accelerators": (
                []
                if wsl
                else [
                    {
                        "vendor": "nvidia",
                        "name": "test-gpu",
                        "kind": "nvidia-smi",
                        "source": "nvidia-smi",
                        "device_path": None,
                        "device_identity_sha256": "d" * 64,
                        "identity_basis": "fixture identity",
                        "driver_version": "999.1",
                        "memory_bytes": 4 * GIB,
                        "major": None,
                        "minor": None,
                        "mode": None,
                        "owner_uid": None,
                        "owner_gid": None,
                        "readable_by_collector": None,
                        "writable_by_collector": None,
                    }
                ]
            ),
            "storage": {
                "root_mount": {
                    "source": "/dev/fixture",
                    "filesystem": "ext4",
                    "options": ["rw"],
                },
                "block_devices": [
                    {"operator_disposition": "unclassified-never-auto-selected"}
                ],
                "verity_probe_status": "ok",
            },
            "accelerator_device_scan": {
                "allowlisted_roots": [
                    "/dev/dri/renderD[0-9]+",
                    "/dev/accel/accel[0-9]+",
                    "/dev/dxg",
                ],
                "maximum_nodes": 128,
                "truncated": False,
                "recursive": False,
                "symlinks_followed": False,
            },
            "package_versions": [],
        },
        "probe_results": [
            {
                "probe_id": probe_id,
                "argv": [executable],
                "status": "ok",
                "returncode": 0,
                "stdout_sha256": "e" * 64,
                "stderr_sha256": "f" * 64,
                "resolved_executable_path": f"/usr/bin/{executable}",
                "resolved_executable_sha256": "a" * 64,
                "executable_provenance_status": "trusted",
                "executable_provenance": [
                    {
                        "path": f"/usr/bin/{executable}",
                        "kind": "regular-file",
                        "owner_uid": 0,
                        "owner_gid": 0,
                        "mode": "0755",
                        "size_bytes": 1024,
                    }
                ],
            }
            for probe_id, executable in PROBE_EXECUTABLES.items()
        ],
        "findings": [{"id": "fixture", "status": "pass"}],
    }


def fake_access(
    *,
    wsl: bool = False,
    ubuntu_version: str = "24.04",
    euid: int | None = 1000,
    filesystem: str = "ext4",
    memory_bytes: int = 32 * GIB,
    missing: set[str] | None = None,
    virtual: bool = False,
    secure_boot_enabled: bool = True,
    nvidia_available: bool = True,
) -> ProbeAccess:
    missing = missing or set()
    kernel = "6.8.0-48-generic"
    if wsl:
        kernel = "6.18.33.2-microsoft-standard-WSL2"
    files = {
        "/etc/os-release": (
            "ID=ubuntu\n"
            f'VERSION_ID="{ubuntu_version}"\n'
            f'PRETTY_NAME="Ubuntu {ubuntu_version} LTS"\n'
        ),
        "/proc/sys/kernel/osrelease": kernel,
        "/proc/version": f"Linux version {kernel}",
        "/proc/meminfo": f"MemTotal:       {memory_bytes // 1024} kB\n",
        "/proc/1/comm": "systemd\n",
        "/sys/module/apparmor/parameters/enabled": "Y\n",
        "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n",
        "/proc/sys/kernel/seccomp/actions_avail": "kill_process kill_thread trap errno log allow\n",
        "/etc/machine-id": f"{MACHINE_ID}\n",
    }

    required_project_names = {
        "README.md",
        "RELEASE_MANIFEST.json",
        "run.sh",
        "cli.py",
        "index.html",
    }
    device_paths = {
        "/sys/fs/cgroup/cgroup.controllers",
        "/sys/firmware/efi",
        "/sys/firmware/efi/efivars",
        "/dev/nvidia0",
    }
    if wsl:
        device_paths = {"/sys/fs/cgroup/cgroup.controllers", "/dev/dxg"}

    def read_text(path: Path) -> str:
        key = path.as_posix()
        if key not in files or key in missing:
            raise FileNotFoundError(key)
        return files[key]

    def exists(path: Path) -> bool:
        key = path.as_posix()
        if key in missing or path.name in missing:
            return False
        return key in device_paths or path.name in required_project_names

    def run_command(arguments: tuple[str, ...] | list[str]) -> CommandResult:
        command = tuple(arguments)
        if command[0].startswith("/luma-invalid-untrusted-probe/"):
            return CommandResult(127, "", "untrusted probe denied")
        executable = Path(command[0]).name
        if executable == "findmnt":
            return CommandResult(0, f"{filesystem}\n")
        if executable == "mokutil":
            return CommandResult(
                0,
                "SecureBoot enabled\n"
                if secure_boot_enabled
                else "SecureBoot disabled\n",
            )
        if executable == "systemd-detect-virt":
            return CommandResult(0, "kvm\n") if virtual else CommandResult(1, "none\n")
        if executable == "nvidia-smi":
            return (
                CommandResult(0, "test-gpu, 999.1, 4096\n")
                if nvidia_available
                else CommandResult(1, "", "NVIDIA device unavailable")
            )
        raise AssertionError(f"unexpected command: {command}")

    return ProbeAccess(
        read_text=read_text,
        exists=exists,
        run_command=run_command,
        disk_usage=lambda _path: (500 * GIB, 100 * GIB, 400 * GIB),
        machine=lambda: "x86_64",
        effective_uid=lambda: euid,
        python_version=(3, 12, 3),
        now_utc=lambda: datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
    )


class UbuntuPreflightTests(unittest.TestCase):
    def test_parsers_handle_quoted_os_release_and_kibibytes(self) -> None:
        self.assertEqual(
            {"ID": "ubuntu", "VERSION_ID": "24.04", "NAME": "Ubuntu Linux"},
            parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\nNAME="Ubuntu Linux"\n'),
        )
        self.assertEqual(16 * GIB, parse_meminfo_bytes("MemTotal: 16777216 kB\n"))
        self.assertIsNone(parse_meminfo_bytes("MemFree: 123 kB\n"))

    def test_wsl2_passes_development_but_is_explicitly_non_closing(self) -> None:
        record = collect_preflight(
            mode="development",
            project_root=PROJECT_ROOT,
            access=fake_access(wsl=True, ubuntu_version="26.04", filesystem="9p"),
        )

        self.assertEqual("pass-development-preflight", record["result"])
        self.assertTrue(record["exit_ready"])
        self.assertFalse(record["certification_closing"])
        self.assertEqual("wsl2", record["environment"]["kind"])
        self.assertIn("native-ubuntu", record["warnings"])
        self.assertIn("ubuntu-24.04-baseline", record["warnings"])
        self.assertIn("linux-local-filesystem", record["warnings"])

    def test_wsl2_can_never_pass_native_candidate_mode(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e1",
            access=fake_access(wsl=True, ubuntu_version="24.04"),
        )

        self.assertEqual("fail-prerequisites", record["result"])
        self.assertFalse(record["exit_ready"])
        self.assertIn("native-ubuntu", record["missing_prerequisites"])
        self.assertIn("physical-host-candidate", record["missing_prerequisites"])

    def test_native_candidate_pass_remains_admission_only(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e2",
            access=fake_access(),
            host_inventory=fake_inventory(),
            host_inventory_sha256="a" * 64,
        )

        self.assertEqual("pass-native-candidate-preflight", record["result"])
        self.assertTrue(record["exit_ready"])
        self.assertFalse(record["certification_closing"])
        self.assertEqual([], record["missing_prerequisites"])
        self.assertTrue(record["host_inventory"]["valid"])
        self.assertEqual(
            "unclassified-never-auto-selected",
            record["host_inventory"]["disk_disposition"],
        )
        self.assertGreaterEqual(len(record["unresolved_qualification_work"]), 6)

    def test_native_candidate_requires_explicit_hardware_class(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            access=fake_access(),
            host_inventory=fake_inventory(),
        )

        self.assertFalse(record["exit_ready"])
        self.assertIn("hardware-class-selected", record["missing_prerequisites"])

    def test_native_candidate_rejects_stale_inventory(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e2",
            access=fake_access(),
            host_inventory=fake_inventory(collected_at="2026-09-23T10:00:00Z"),
        )

        self.assertFalse(record["exit_ready"])
        self.assertIn("host-inventory-freshness", record["missing_prerequisites"])

    def test_native_candidate_rejects_malformed_inventory(self) -> None:
        inventory = fake_inventory()
        del inventory["collector"]
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e2",
            access=fake_access(),
            host_inventory=inventory,
        )

        self.assertFalse(record["exit_ready"])
        self.assertIn("authoritative-host-inventory", record["missing_prerequisites"])

    def test_forged_inventory_security_claims_cannot_override_live_probes(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e2",
            access=fake_access(
                secure_boot_enabled=False,
                nvidia_available=False,
                missing={
                    "/sys/fs/cgroup/cgroup.controllers",
                    "/sys/firmware/efi",
                    "/sys/firmware/efi/efivars",
                    "/sys/module/apparmor/parameters/enabled",
                    "/sys/kernel/security/lsm",
                    "/dev/nvidia0",
                },
            ),
            host_inventory=fake_inventory(),
        )

        self.assertFalse(record["exit_ready"])
        self.assertTrue(
            {
                "cgroup-v2",
                "apparmor-kernel-enabled",
                "uefi-runtime",
                "secure-boot-enabled",
                "accelerator-device-visible",
                "host-inventory-live-corroboration",
            }.issubset(record["missing_prerequisites"])
        )

    def test_forged_host_identity_is_rejected(self) -> None:
        inventory = fake_inventory()
        inventory["system"]["pseudonymous_host_identity_sha256"] = "b" * 64
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e2",
            access=fake_access(),
            host_inventory=inventory,
        )

        self.assertFalse(record["exit_ready"])
        self.assertIn(
            "host-inventory-current-host-binding", record["missing_prerequisites"]
        )

    def test_root_virtual_host_and_missing_controls_fail_closed(self) -> None:
        record = collect_preflight(
            mode="native-candidate",
            project_root=PROJECT_ROOT,
            hardware_class="e1",
            access=fake_access(
                euid=0,
                virtual=True,
                missing={
                    "/sys/fs/cgroup/cgroup.controllers",
                    "/sys/module/apparmor/parameters/enabled",
                    "/proc/sys/kernel/seccomp/actions_avail",
                },
            ),
        )

        self.assertFalse(record["exit_ready"])
        self.assertTrue(
            {
                "unprivileged-user",
                "cgroup-v2",
                "apparmor-kernel-enabled",
                "seccomp-kernel-interface",
                "physical-host-candidate",
            }.issubset(record["missing_prerequisites"])
        )

    def test_main_prints_machine_readable_json_and_returns_gate_status(self) -> None:
        output = io.StringIO()
        access = fake_access(wsl=True, ubuntu_version="26.04", filesystem="9p")
        with patch("scripts.ubuntu_preflight.default_access", return_value=access), patch(
            "sys.stdout", output
        ):
            returncode = main(
                ["--mode", "development", "--project-root", str(PROJECT_ROOT)]
            )

        self.assertEqual(0, returncode)
        record = json.loads(output.getvalue())
        self.assertEqual("luma-os-ubuntu-preflight", record["tool"])
        self.assertTrue(record["read_only"])


if __name__ == "__main__":
    unittest.main()
