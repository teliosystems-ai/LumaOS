from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.platform_adapter import (  # noqa: E402
    FakePlatformAdapter,
    LinuxPlatformAdapter,
    PlatformAdapterError,
    PlatformContractError,
    PlatformDescription,
    run_t40_contract,
)


class PlatformAdapterContractTests(unittest.TestCase):
    def test_t40_scaffold_passes_fake_without_claiming_closure(self) -> None:
        adapter = FakePlatformAdapter(((1024, 512), (1024, 500)))
        report = run_t40_contract(adapter)
        self.assertTrue(report.passed)
        self.assertFalse(report.closing_evidence)
        self.assertEqual("T40-SCAFFOLD", report.test_id)
        self.assertEqual(4, len(report.checks))

    def test_invalid_identity_and_non_monotonic_adapter_fail_contract(self) -> None:
        with self.assertRaises(PlatformContractError):
            PlatformDescription(1, "fake", "fake", "1", "x86_64", "none", ("z", "a"))

        class BrokenAdapter:
            description = PlatformDescription(
                1, "broken", "fake", "1", "x86_64", "simulated", ()
            )

            def describe(self):
                return self.description

            def sample_host_memory(self):
                from luma_os.platform_adapter import HostMemoryObservation

                return HostMemoryObservation(1, 1024, 512)

        with self.assertRaises(PlatformContractError):
            run_t40_contract(BrokenAdapter())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux adapter requires Linux")
    def test_linux_adapter_uses_declared_files_and_detects_wsl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os_release = root / "os-release"
            meminfo = root / "meminfo"
            kernel = root / "osrelease"
            os_release.write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
            meminfo.write_text(
                "MemTotal:       1024 kB\nMemAvailable:    256 kB\n",
                encoding="ascii",
            )
            kernel.write_text("6.8.0-microsoft-standard-WSL2\n", encoding="ascii")
            adapter = LinuxPlatformAdapter(
                os_release_path=os_release,
                meminfo_path=meminfo,
                kernel_release_path=kernel,
            )
            report = run_t40_contract(adapter)
            self.assertTrue(report.passed)
            self.assertIn("wsl2", report.platform_id)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux adapter requires Linux")
    def test_linux_adapter_rejects_malformed_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os_release = root / "os-release"
            meminfo = root / "meminfo"
            kernel = root / "osrelease"
            os_release.write_text("VERSION_ID=24.04\n", encoding="utf-8")
            meminfo.write_text("MemTotal: nope kB\n", encoding="ascii")
            kernel.write_text("6.8.0\n", encoding="ascii")
            adapter = LinuxPlatformAdapter(
                os_release_path=os_release,
                meminfo_path=meminfo,
                kernel_release_path=kernel,
            )
            with self.assertRaises(PlatformAdapterError):
                adapter.sample_host_memory()


if __name__ == "__main__":
    unittest.main()
