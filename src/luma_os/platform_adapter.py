"""Versioned platform adapter and deterministic T40 contract scaffold."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import platform
import sys
import threading
from typing import Final, Protocol

from .resources import checked_u64


PLATFORM_ADAPTER_API: Final[int] = 1


class PlatformAdapterError(RuntimeError):
    """The platform could not provide a required observation."""


class PlatformContractError(ValueError):
    """A platform adapter violated the versioned interface contract."""


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise PlatformContractError(f"{field} must be a non-empty trimmed string")
    if "\x00" in value:
        raise PlatformContractError(f"{field} cannot contain NUL")
    return value


@dataclass(frozen=True, slots=True)
class PlatformDescription:
    api_version: int
    platform_id: str
    os_family: str
    release: str
    architecture: str
    virtualization: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.api_version != PLATFORM_ADAPTER_API:
            raise PlatformContractError(
                f"unsupported platform adapter API version: {self.api_version}"
            )
        for field in ("platform_id", "os_family", "release", "architecture", "virtualization"):
            _text(getattr(self, field), field)
        capabilities = tuple(self.capabilities)
        for capability in capabilities:
            _text(capability, "capability")
        if capabilities != tuple(sorted(set(capabilities))):
            raise PlatformContractError("capabilities must be unique and sorted")
        object.__setattr__(self, "capabilities", capabilities)


@dataclass(frozen=True, slots=True)
class HostMemoryObservation:
    sequence: int
    total_bytes: int
    available_bytes: int

    def __post_init__(self) -> None:
        sequence = checked_u64(self.sequence, field="sequence")
        total = checked_u64(self.total_bytes, field="total_bytes")
        available = checked_u64(self.available_bytes, field="available_bytes")
        if sequence == 0:
            raise PlatformContractError("memory sequence must be positive")
        if total == 0 or available > total:
            raise PlatformContractError("memory observation must satisfy 0 <= available <= total")


class PlatformAdapter(Protocol):
    """Stable G1 platform boundary used by the T40 scaffold."""

    def describe(self) -> PlatformDescription: ...

    def sample_host_memory(self) -> HostMemoryObservation: ...


@dataclass(frozen=True, slots=True)
class PlatformConformanceReport:
    test_id: str
    adapter_api: int
    platform_id: str
    checks: tuple[str, ...]
    passed: bool
    closing_evidence: bool = False


def run_t40_contract(adapter: PlatformAdapter) -> PlatformConformanceReport:
    """Exercise the provisional T40 invariants without claiming gate closure.

    The governing requirements that define authoritative T40 semantics are not
    present in this checkout.  This function is therefore a deterministic
    conformance scaffold and marks its result as non-closing evidence.
    """

    first_description = adapter.describe()
    second_description = adapter.describe()
    if not isinstance(first_description, PlatformDescription) or not isinstance(
        second_description, PlatformDescription
    ):
        raise PlatformContractError("adapter describe() returned the wrong contract type")
    if first_description != second_description:
        raise PlatformContractError("platform identity changed during conformance run")
    first_memory = adapter.sample_host_memory()
    second_memory = adapter.sample_host_memory()
    if not isinstance(first_memory, HostMemoryObservation) or not isinstance(
        second_memory, HostMemoryObservation
    ):
        raise PlatformContractError("adapter memory sample returned the wrong contract type")
    if second_memory.sequence <= first_memory.sequence:
        raise PlatformContractError("memory observation sequence did not increase")
    return PlatformConformanceReport(
        test_id="T40-SCAFFOLD",
        adapter_api=first_description.api_version,
        platform_id=first_description.platform_id,
        checks=(
            "version-negotiation",
            "stable-platform-identity",
            "bounded-host-memory",
            "monotonic-observation-sequence",
        ),
        passed=True,
        closing_evidence=False,
    )


class FakePlatformAdapter:
    """Deterministic adapter for contract, failure, and recovery tests."""

    def __init__(
        self,
        observations: Iterable[tuple[int, int]],
        *,
        platform_id: str = "fake-platform-1",
    ) -> None:
        prepared = tuple(observations)
        if len(prepared) < 2:
            raise PlatformContractError("fake adapter needs at least two memory observations")
        self._description = PlatformDescription(
            api_version=PLATFORM_ADAPTER_API,
            platform_id=platform_id,
            os_family="fake",
            release="1",
            architecture="x86_64",
            virtualization="simulated",
            capabilities=("host-memory-telemetry",),
        )
        self._observations = prepared
        self._position = 0
        self._lock = threading.Lock()

    def describe(self) -> PlatformDescription:
        return self._description

    def sample_host_memory(self) -> HostMemoryObservation:
        with self._lock:
            if self._position >= len(self._observations):
                raise PlatformAdapterError("fake platform observation script exhausted")
            total, available = self._observations[self._position]
            self._position += 1
            return HostMemoryObservation(self._position, total, available)


class LinuxPlatformAdapter:
    """Read-only Linux/WSL implementation of the versioned adapter."""

    def __init__(
        self,
        *,
        os_release_path: str | Path = "/etc/os-release",
        meminfo_path: str | Path = "/proc/meminfo",
        kernel_release_path: str | Path = "/proc/sys/kernel/osrelease",
    ) -> None:
        self._os_release_path = Path(os_release_path)
        self._meminfo_path = Path(meminfo_path)
        self._kernel_release_path = Path(kernel_release_path)
        self._sequence = 0
        self._lock = threading.Lock()

    def describe(self) -> PlatformDescription:
        if not sys.platform.startswith("linux"):
            raise PlatformAdapterError("Linux platform adapter requires Linux")
        os_release = self._read_key_values(self._os_release_path)
        release = os_release.get("VERSION_ID") or os_release.get("VERSION")
        if not release:
            raise PlatformAdapterError("os-release does not contain a version")
        try:
            kernel = self._kernel_release_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise PlatformAdapterError("Linux kernel release is unavailable") from exc
        virtualization = "wsl2" if "microsoft" in kernel.lower() else "native-or-other"
        platform_id = f"linux-{platform.machine().lower()}-{release}-{virtualization}"
        return PlatformDescription(
            api_version=PLATFORM_ADAPTER_API,
            platform_id=platform_id,
            os_family="linux",
            release=release,
            architecture=platform.machine().lower(),
            virtualization=virtualization,
            capabilities=("host-memory-telemetry", "posix-filesystem"),
        )

    def sample_host_memory(self) -> HostMemoryObservation:
        if not sys.platform.startswith("linux"):
            raise PlatformAdapterError("Linux platform adapter requires Linux")
        try:
            fields = self._meminfo_path.read_text(encoding="ascii").splitlines()
            values = {
                name: int(raw.split()[0]) * 1024
                for line in fields
                for name, separator, raw in (line.partition(":"),)
                if separator and raw.split() and raw.split()[-1] == "kB"
            }
            total = values["MemTotal"]
            available = values["MemAvailable"]
        except (OSError, UnicodeError, ValueError, KeyError) as exc:
            raise PlatformAdapterError("Linux memory telemetry is malformed") from exc
        with self._lock:
            self._sequence += 1
            return HostMemoryObservation(self._sequence, total, available)

    @staticmethod
    def _read_key_values(path: Path) -> dict[str, str]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise PlatformAdapterError("os-release is unavailable") from exc
        values: dict[str, str] = {}
        for line in lines:
            name, separator, raw = line.partition("=")
            if not separator:
                continue
            value = raw.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            values[name] = value
        return values
