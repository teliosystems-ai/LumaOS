"""Read-only host and NVIDIA telemetry adapter for resource admission."""

from __future__ import annotations

import ctypes
from pathlib import Path
import subprocess
import threading
from typing import Callable

from .resources import ResourceLedgerError, ResourceValidationError, TelemetrySample, checked_u64


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
_MIB = 1024 * 1024


class SystemTelemetryAdapter:
    """Collect monotonically sequenced physical observations.

    Host memory comes from ``/proc/meminfo`` on Linux/WSL and
    ``GlobalMemoryStatusEx`` on native Windows. NVIDIA memory is queried with a
    fixed ``nvidia-smi`` argument vector and never through a shell.
    """

    def __init__(
        self,
        *,
        meminfo_path: str | Path = "/proc/meminfo",
        runner: CommandRunner = subprocess.run,
        timeout: float = 3.0,
    ) -> None:
        if timeout <= 0:
            raise ResourceValidationError("telemetry timeout must be positive")
        self._meminfo_path = Path(meminfo_path)
        self._runner = runner
        self._timeout = float(timeout)
        self._sequences: dict[str, int] = {}
        self._lock = threading.Lock()

    def sample(self, domain_id: str) -> TelemetrySample:
        with self._lock:
            sequence = self._sequences.get(domain_id, 0) + 1
            if domain_id == "host":
                used, total = self._host_memory()
            elif domain_id.startswith("gpu") and domain_id[3:].isdigit():
                used, total = self._nvidia_memory(int(domain_id[3:]))
            else:
                raise ResourceValidationError(f"unsupported telemetry domain: {domain_id}")
            self._sequences[domain_id] = sequence
            return TelemetrySample(
                domain_id=domain_id,
                sequence=sequence,
                used_bytes=used,
                total_bytes=total,
            )

    def _host_memory(self) -> tuple[int, int]:
        if self._meminfo_path.is_file():
            values: dict[str, int] = {}
            try:
                for line in self._meminfo_path.read_text(encoding="ascii").splitlines():
                    name, separator, raw = line.partition(":")
                    if not separator:
                        continue
                    fields = raw.split()
                    if len(fields) >= 2 and fields[1] == "kB":
                        values[name] = int(fields[0]) * 1024
            except (OSError, UnicodeError, ValueError) as exc:
                raise ResourceLedgerError("host memory telemetry is malformed") from exc
            total = values.get("MemTotal")
            available = values.get("MemAvailable")
            if total is None or available is None or total <= 0 or not 0 <= available <= total:
                raise ResourceLedgerError("host memory telemetry lacks valid total/available values")
            return total - available, total
        return self._windows_memory()

    @staticmethod
    def _windows_memory() -> tuple[int, int]:
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        try:
            succeeded = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # type: ignore[attr-defined]
        except (AttributeError, OSError) as exc:
            raise ResourceLedgerError("host memory telemetry is unavailable") from exc
        if not succeeded or status.total_physical == 0 or status.available_physical > status.total_physical:
            raise ResourceLedgerError("native Windows returned invalid memory telemetry")
        return int(status.total_physical - status.available_physical), int(status.total_physical)

    def _nvidia_memory(self, index: int) -> tuple[int, int]:
        try:
            result = self._runner(
                [
                    "nvidia-smi",
                    "--query-gpu=index,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResourceLedgerError("NVIDIA telemetry command failed") from exc
        if result.returncode:
            raise ResourceLedgerError("NVIDIA telemetry command returned an error")
        for line in result.stdout.splitlines():
            fields = [field.strip() for field in line.split(",")]
            if len(fields) != 3:
                continue
            try:
                observed_index, used_mib, total_mib = (int(field) for field in fields)
            except ValueError:
                continue
            if observed_index != index:
                continue
            used = checked_u64(used_mib * _MIB, field="gpu used bytes")
            total = checked_u64(total_mib * _MIB, field="gpu total bytes")
            if total == 0 or used > total:
                raise ResourceLedgerError("NVIDIA telemetry returned invalid memory values")
            return used, total
        raise ResourceLedgerError(f"NVIDIA telemetry did not report GPU index {index}")
