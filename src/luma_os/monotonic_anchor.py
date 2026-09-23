"""Typed monotonic digest-anchor contracts.

The in-memory implementation in this module exists only for deterministic
development tests.  It is not durable, external, or rollback resistant and
must never be treated as production evidence.  Production callers must supply
an independently protected implementation of :class:`ExternalDigestAnchor`.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Protocol


JSON_SAFE_INTEGER_MAX = (1 << 53) - 1


class MonotonicAnchorError(RuntimeError):
    """Base class for digest-anchor failures."""


class MonotonicAnchorValidationError(ValueError):
    """An anchor namespace or checkpoint is malformed."""


class MonotonicAnchorConflict(MonotonicAnchorError):
    """The external anchor changed or rejected a compare-and-swap."""


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise MonotonicAnchorValidationError(
            f"{field} must be a non-empty trimmed printable ASCII identifier"
        )
    return value


def _positive_integer(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > JSON_SAFE_INTEGER_MAX
    ):
        raise MonotonicAnchorValidationError(
            f"{field} must be a positive JSON-safe integer"
        )
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MonotonicAnchorValidationError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


@dataclass(frozen=True, slots=True)
class DigestCheckpoint:
    """One externally protected namespace/sequence/digest commitment."""

    namespace: str
    generation: int
    sequence: int
    artifact_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.namespace, "checkpoint namespace")
        _positive_integer(self.generation, "checkpoint generation")
        _positive_integer(self.sequence, "checkpoint sequence")
        _sha256(self.artifact_sha256, "checkpoint artifact_sha256")


class ExternalDigestAnchor(Protocol):
    """External compare-and-swap store for monotonic digest checkpoints."""

    def read(self, namespace: str) -> DigestCheckpoint | None: ...

    def compare_and_swap(
        self,
        *,
        expected: DigestCheckpoint | None,
        replacement: DigestCheckpoint,
    ) -> bool: ...


class InMemoryDigestAnchor:
    """Thread-safe development/test fake; never production rollback evidence."""

    def __init__(self) -> None:
        self._values: dict[str, DigestCheckpoint] = {}
        self._lock = threading.RLock()

    def read(self, namespace: str) -> DigestCheckpoint | None:
        checked = _identifier(namespace, "anchor namespace")
        with self._lock:
            return self._values.get(checked)

    def compare_and_swap(
        self,
        *,
        expected: DigestCheckpoint | None,
        replacement: DigestCheckpoint,
    ) -> bool:
        if not isinstance(replacement, DigestCheckpoint):
            raise MonotonicAnchorValidationError(
                "replacement must be a DigestCheckpoint"
            )
        if expected is not None and not isinstance(expected, DigestCheckpoint):
            raise MonotonicAnchorValidationError(
                "expected must be a DigestCheckpoint or None"
            )
        if expected is not None and expected.namespace != replacement.namespace:
            raise MonotonicAnchorValidationError(
                "expected and replacement namespaces differ"
            )
        with self._lock:
            current = self._values.get(replacement.namespace)
            if current != expected:
                return False
            expected_generation = 1 if current is None else current.generation + 1
            if replacement.generation != expected_generation:
                raise MonotonicAnchorValidationError(
                    "replacement generation must advance exactly once"
                )
            if current is None:
                if replacement.sequence != 1:
                    raise MonotonicAnchorValidationError(
                        "a new namespace must begin at sequence one"
                    )
            elif replacement.sequence <= current.sequence:
                raise MonotonicAnchorValidationError(
                    "replacement sequence must advance monotonically"
                )
            self._values[replacement.namespace] = replacement
            return True
