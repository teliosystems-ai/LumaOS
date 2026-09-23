from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from luma_os.g2_host_inventory import (  # noqa: E402
    AcceleratorDeviceObservation,
    CommandObservation,
    HostObservations,
    PathProvenanceObservation,
    READ_ONLY_COMMANDS,
    ResolvedExecutable,
    _run_read_only,
    build_inventory,
    executable_provenance_is_trusted,
)


def _commands(*, virtualization: CommandObservation) -> dict[str, CommandObservation]:
    commands = {
        probe_id: CommandObservation(argv, "not-found", None)
        for probe_id, argv in READ_ONLY_COMMANDS.items()
    }
    commands["virtualization"] = virtualization
    commands["root_mount"] = CommandObservation(
        READ_ONLY_COMMANDS["root_mount"],
        "ok",
        0,
        json.dumps(
            {
                "filesystems": [
                    {
                        "source": "/dev/mapper/luma-data",
                        "fstype": "ext4",
                        "options": "rw,relatime",
                    }
                ]
            }
        ),
    )
    commands["block_devices"] = CommandObservation(
        READ_ONLY_COMMANDS["block_devices"],
        "ok",
        0,
        json.dumps(
            {
                "blockdevices": [
                    {
                        "kname": "nvme0n1",
                        "path": "/dev/nvme0n1",
                        "type": "disk",
                        "size": 512_000_000_000,
                        "ro": False,
                        "rm": False,
                        "model": "Fixture Disk",
                        "serial": "PRIVATE-SERIAL-1",
                        "wwn": "PRIVATE-WWN-1",
                        "tran": "nvme",
                        "fstype": None,
                        "mountpoints": [None],
                        "pkname": None,
                    }
                ]
            }
        ),
    )
    commands["nvidia"] = CommandObservation(
        READ_ONLY_COMMANDS["nvidia"],
        "ok",
        0,
        "Fixture GPU, GPU-PRIVATE-UUID, 999.1, 16384, 00000000:01:00.0\n",
    )
    commands["verity"] = CommandObservation(READ_ONLY_COMMANDS["verity"], "nonzero", 1)
    commands["packages"] = CommandObservation(
        READ_ONLY_COMMANDS["packages"], "ok", 0, "systemd=255.4\napparmor=4.0\n"
    )
    return commands


def _native_observations() -> HostObservations:
    files = {
        "/etc/os-release": b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n',
        "/proc/sys/kernel/osrelease": b"6.8.0-100-generic\n",
        "/proc/cmdline": b"BOOT_IMAGE=/vmlinuz ro quiet security=apparmor iommu=on roothash=abc\n",
        "/proc/meminfo": b"MemTotal:       32768000 kB\nMemAvailable:   24576000 kB\n",
        "/proc/cpuinfo": (
            b"processor : 0\nmodel name : Fixture CPU\n"
            b"processor : 1\nmodel name : Fixture CPU\n"
        ),
        "/proc/self/status": b"Name:\tpython3\nSeccomp:\t2\n",
        "/etc/machine-id": b"0123456789abcdef0123456789abcdef\n",
        "/sys/module/apparmor/parameters/enabled": b"Y\n",
        "/sys/kernel/security/lsm": b"lockdown,capability,landlock,yama,apparmor,bpf\n",
        "/sys/fs/cgroup/cgroup.controllers": b"cpuset cpu io memory hugetlb pids\n",
        "/sys/firmware/efi/efivars/SecureBoot-fixture": b"\x07\x00\x00\x00\x01",
        "/sys/class/dmi/id/sys_vendor": b"Fixture Vendor\n",
        "/sys/class/dmi/id/product_name": b"Fixture E2\n",
        "/sys/class/dmi/id/product_version": b"1\n",
        "/sys/class/dmi/id/board_vendor": b"Fixture Vendor\n",
        "/sys/class/dmi/id/board_name": b"Fixture Board\n",
        "/sys/class/dmi/id/bios_vendor": b"Fixture Firmware\n",
        "/sys/class/dmi/id/bios_version": b"1.2.3\n",
        "/sys/class/dmi/id/bios_date": b"01/02/2026\n",
    }
    return HostObservations(
        collected_at=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        machine="x86_64",
        files=files,
        present_paths=frozenset(
            {
                "/sys/firmware/efi",
                "/sys/firmware/efi/efivars",
                "/sys/fs/cgroup/cgroup.controllers",
                "/dev/kvm",
                "/dev/tpmrm0",
                "/sys/kernel/iommu_groups",
            }
        ),
        # A physical host is the documented non-zero/"none" behavior of
        # systemd-detect-virt.  This must not be mistaken for probe failure.
        commands=_commands(
            virtualization=CommandObservation(
                READ_ONLY_COMMANDS["virtualization"], "nonzero", 1, "none\n"
            )
        ),
        accelerator_device_nodes=(
            AcceleratorDeviceObservation(
                kind="drm-render",
                path="/dev/dri/renderD128",
                major=226,
                minor=128,
                mode="0660",
                owner_uid=0,
                owner_gid=107,
                readable_by_collector=True,
                writable_by_collector=True,
            ),
        ),
    )


class G2HostInventoryTests(unittest.TestCase):
    def test_native_candidate_is_detected_without_claiming_gate_closure(self) -> None:
        inventory = build_inventory(_native_observations(), environment_id="E2")

        self.assertEqual("native", inventory["system"]["environment_kind"])
        self.assertTrue(inventory["system"]["native_ubuntu_24_04_amd64_candidate"])
        self.assertFalse(inventory["evidence_boundary"]["gate_closing"])
        self.assertEqual(
            "physical-candidate-inventory-non-closing",
            inventory["evidence_boundary"]["classification"],
        )
        findings = {item["id"]: item for item in inventory["findings"]}
        self.assertEqual("pass", findings["G2-HOST-NATIVE-UBUNTU-24-04"]["status"])
        self.assertEqual("pass", findings["G2-HOST-SECURE-BOOT"]["status"])
        self.assertEqual("pass", findings["G2-HOST-CGROUP-V2"]["status"])
        self.assertEqual("pass", findings["G2-HOST-APPARMOR"]["status"])
        self.assertEqual(
            "operator-action-required",
            findings["G2-HOST-DISPOSABLE-DISK"]["status"],
        )

    def test_default_output_hashes_hardware_identifiers_and_never_selects_disk(self) -> None:
        inventory = build_inventory(_native_observations(), environment_id="E1")

        disk = inventory["system"]["storage"]["block_devices"][0]
        accelerator = inventory["system"]["accelerators"][0]
        serialized = json.dumps(inventory, sort_keys=True)
        self.assertNotIn("PRIVATE-SERIAL-1", serialized)
        self.assertNotIn("PRIVATE-WWN-1", serialized)
        self.assertNotIn("GPU-PRIVATE-UUID", serialized)
        self.assertRegex(disk["stable_identity_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(accelerator["device_identity_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual("hardware-reported-wwn-or-serial", disk["identity_basis"])
        self.assertEqual("unclassified-never-auto-selected", disk["operator_disposition"])
        self.assertFalse(inventory["collector"]["sensitive_identifiers_included"])
        self.assertIn(
            "not physical-board attestation",
            inventory["system"]["pseudonymous_host_identity_limitations"],
        )

    def test_sensitive_disk_identifiers_require_explicit_opt_in(self) -> None:
        inventory = build_inventory(
            _native_observations(),
            environment_id="E1",
            include_sensitive_identifiers=True,
        )
        disk = inventory["system"]["storage"]["block_devices"][0]
        self.assertEqual("PRIVATE-SERIAL-1", disk["serial"])
        self.assertEqual("PRIVATE-WWN-1", disk["wwn"])
        self.assertTrue(inventory["collector"]["sensitive_identifiers_included"])

    def test_wsl_is_explicitly_non_closing_even_with_ubuntu_and_security_features(self) -> None:
        native = _native_observations()
        files = dict(native.files)
        files["/etc/os-release"] = (
            b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n'
        )
        files["/proc/sys/kernel/osrelease"] = b"6.18.0-microsoft-standard-WSL2\n"
        observations = HostObservations(
            collected_at=native.collected_at,
            machine=native.machine,
            files=files,
            present_paths=frozenset({*native.present_paths, "/dev/dxg"}),
            commands=native.commands,
        )

        inventory = build_inventory(observations, environment_id="DEV-WSL-01")

        self.assertEqual("wsl2", inventory["system"]["environment_kind"])
        self.assertFalse(inventory["system"]["native_ubuntu_24_04_amd64_candidate"])
        self.assertFalse(inventory["evidence_boundary"]["gate_closing"])
        finding = next(
            item
            for item in inventory["findings"]
            if item["id"] == "G2-HOST-NATIVE-UBUNTU-24-04"
        )
        self.assertEqual("block", finding["status"])

    def test_unknown_virtualization_probe_is_not_assumed_native(self) -> None:
        native = _native_observations()
        commands = dict(native.commands)
        commands["virtualization"] = CommandObservation(
            READ_ONLY_COMMANDS["virtualization"], "not-found", None
        )
        observations = HostObservations(
            collected_at=native.collected_at,
            machine=native.machine,
            files=native.files,
            present_paths=native.present_paths,
            commands=commands,
        )
        inventory = build_inventory(observations, environment_id="E1")
        self.assertEqual("unknown", inventory["system"]["environment_kind"])
        self.assertFalse(inventory["system"]["native_ubuntu_24_04_amd64_candidate"])

    def test_failed_mokutil_output_cannot_forge_secure_boot_state(self) -> None:
        native = _native_observations()
        files = {
            path: value
            for path, value in native.files.items()
            if not path.startswith("/sys/firmware/efi/efivars/SecureBoot-")
        }
        commands = dict(native.commands)
        commands["secure_boot"] = CommandObservation(
            READ_ONLY_COMMANDS["secure_boot"],
            "nonzero",
            1,
            "SecureBoot enabled\n",
            "probe failed\n",
        )
        observations = HostObservations(
            collected_at=native.collected_at,
            machine=native.machine,
            files=files,
            present_paths=native.present_paths,
            commands=commands,
        )
        inventory = build_inventory(observations, environment_id="E1")
        self.assertEqual(
            {"state": "unknown", "source": "unavailable"},
            inventory["system"]["firmware"]["secure_boot"],
        )

        commands["secure_boot"] = CommandObservation(
            READ_ONLY_COMMANDS["secure_boot"], "ok", 0, "SecureBoot enabled\n"
        )
        accepted = build_inventory(
            HostObservations(
                collected_at=native.collected_at,
                machine=native.machine,
                files=files,
                present_paths=native.present_paths,
                commands=commands,
            ),
            environment_id="E1",
        )
        self.assertEqual(
            {"state": "enabled", "source": "mokutil"},
            accepted["system"]["firmware"]["secure_boot"],
        )

    def test_generic_accelerator_node_is_visible_without_nvidia(self) -> None:
        native = _native_observations()
        commands = dict(native.commands)
        commands["nvidia"] = CommandObservation(
            READ_ONLY_COMMANDS["nvidia"], "not-found", None
        )
        observations = HostObservations(
            collected_at=native.collected_at,
            machine=native.machine,
            files=native.files,
            present_paths=native.present_paths,
            commands=commands,
            accelerator_device_nodes=(
                AcceleratorDeviceObservation(
                    kind="accel",
                    path="/dev/accel/accel0",
                    major=261,
                    minor=0,
                    mode="0660",
                    owner_uid=0,
                    owner_gid=109,
                    readable_by_collector=True,
                    writable_by_collector=False,
                ),
            ),
        )
        inventory = build_inventory(observations, environment_id="E2")
        self.assertEqual(1, len(inventory["system"]["accelerators"]))
        accelerator = inventory["system"]["accelerators"][0]
        self.assertEqual("accel", accelerator["kind"])
        self.assertEqual("/dev/accel/accel0", accelerator["device_path"])
        self.assertIsNone(accelerator["vendor"])
        finding = next(
            item
            for item in inventory["findings"]
            if item["id"] == "G2-HOST-ACCELERATOR-VISIBILITY"
        )
        self.assertEqual("pass", finding["status"])

    def test_trusted_command_provenance_is_injected_and_absolute(self) -> None:
        trusted = (
            PathProvenanceObservation(
                "/usr/bin/mokutil", "regular-file", 0, 0, 0o755, 4096
            ),
            PathProvenanceObservation("/usr/bin", "directory", 0, 0, 0o755, 4096),
            PathProvenanceObservation("/usr", "directory", 0, 0, 0o755, 4096),
            PathProvenanceObservation("/", "directory", 0, 0, 0o755, 4096),
        )
        self.assertTrue(executable_provenance_is_trusted(trusted))
        self.assertFalse(
            executable_provenance_is_trusted(
                (
                    PathProvenanceObservation(
                        "/usr/bin/mokutil", "regular-file", 1000, 1000, 0o755, 4096
                    ),
                    *trusted[1:],
                )
            )
        )
        self.assertFalse(
            executable_provenance_is_trusted(
                (
                    trusted[0],
                    PathProvenanceObservation(
                        "/usr/bin", "directory", 0, 0, 0o775, 4096
                    ),
                    *trusted[2:],
                )
            )
        )

        executed: list[tuple[str, ...]] = []

        def resolver(name: str, additional_roots: object) -> ResolvedExecutable:
            self.assertEqual("mokutil", name)
            self.assertEqual((), additional_roots)
            return ResolvedExecutable("trusted", "/usr/bin/mokutil", "a" * 64, trusted)

        def runner(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
            executed.append(argv)
            self.assertFalse(bool(kwargs["shell"]))
            self.assertEqual(
                {
                    "LC_ALL": "C",
                    "LANG": "C",
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "TZ": "UTC",
                },
                kwargs["env"],
            )
            return subprocess.CompletedProcess(argv, 0, "SecureBoot enabled\n", "")

        observation = _run_read_only(
            READ_ONLY_COMMANDS["secure_boot"], runner=runner, resolver=resolver
        )
        self.assertEqual([("/usr/bin/mokutil", "--sb-state")], executed)
        self.assertEqual("trusted", observation.executable_provenance_status)
        self.assertEqual("/usr/bin/mokutil", observation.resolved_executable_path)
        self.assertEqual("a" * 64, observation.resolved_executable_sha256)

        def rejected(name: str, additional_roots: object) -> ResolvedExecutable:
            return ResolvedExecutable("rejected", provenance=trusted)

        denied = _run_read_only(
            READ_ONLY_COMMANDS["secure_boot"],
            runner=lambda *args, **kwargs: self.fail("rejected command must not execute"),
            resolver=rejected,
        )
        self.assertEqual("rejected", denied.status)
        self.assertEqual("rejected", denied.executable_provenance_status)

    def test_environment_and_timestamp_inputs_are_bounded(self) -> None:
        observations = _native_observations()
        with self.assertRaises(ValueError):
            build_inventory(observations, environment_id="E1;rm -rf")
        naive = HostObservations(
            collected_at=datetime(2026, 9, 23, 12, 0),
            machine=observations.machine,
            files=observations.files,
            present_paths=observations.present_paths,
            commands=observations.commands,
        )
        with self.assertRaises(ValueError):
            build_inventory(naive, environment_id="E1")


if __name__ == "__main__":
    unittest.main()
