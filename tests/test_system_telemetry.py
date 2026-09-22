from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.resources import ResourceLedgerError, ResourceValidationError  # noqa: E402
from luma_os.system_telemetry import SystemTelemetryAdapter  # noqa: E402


class SystemTelemetryTests(unittest.TestCase):
    def test_linux_host_samples_are_monotonic_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            meminfo = Path(temporary) / "meminfo"
            meminfo.write_text(
                "MemTotal:       8000000 kB\nMemAvailable:   3000000 kB\n",
                encoding="ascii",
            )
            adapter = SystemTelemetryAdapter(meminfo_path=meminfo)
            first = adapter.sample("host")
            second = adapter.sample("host")

        self.assertEqual(1, first.sequence)
        self.assertEqual(2, second.sequence)
        self.assertEqual(8_000_000 * 1024, first.total_bytes)
        self.assertEqual(5_000_000 * 1024, first.used_bytes)

    def test_nvidia_output_is_parsed_without_a_shell(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append((arguments, kwargs))
            return subprocess.CompletedProcess(arguments, 0, "0, 1024, 4096\n", "")

        adapter = SystemTelemetryAdapter(meminfo_path="missing", runner=runner)
        sample = adapter.sample("gpu0")

        self.assertEqual(1024 * 1024 * 1024, sample.used_bytes)
        self.assertEqual(4096 * 1024 * 1024, sample.total_bytes)
        self.assertNotIn("shell", calls[0][1])
        self.assertEqual("nvidia-smi", calls[0][0][0])

    def test_unknown_and_malformed_domains_fail_closed(self) -> None:
        adapter = SystemTelemetryAdapter(meminfo_path="missing")
        with self.assertRaises(ResourceValidationError):
            adapter.sample("gpu-x")

        def missing_gpu(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(arguments, 0, "1, 10, 20\n", "")

        adapter = SystemTelemetryAdapter(meminfo_path="missing", runner=missing_gpu)
        with self.assertRaises(ResourceLedgerError):
            adapter.sample("gpu0")


if __name__ == "__main__":
    unittest.main()
