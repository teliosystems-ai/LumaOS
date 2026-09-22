"""Placement, runtime-profile, allocation, and isolated-cache contracts."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import threading

from .resources import (
    MemoryReservation,
    ResourceLease,
    ResourceLedger,
    ResourceValidationError,
    checked_add_bytes,
    checked_sub_bytes,
    checked_u64,
)


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise ResourceValidationError(f"{field} must be a non-empty trimmed string")
    if "\x00" in value:
        raise ResourceValidationError(f"{field} cannot contain NUL")
    return value


def _sha256(value: str, field: str) -> str:
    _identifier(value, field)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ResourceValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    profile_id: str
    model_id: str
    model_manifest_sha256: str
    tokenizer_sha256: str
    template_sha256: str
    backend: str
    backend_version: str
    context_tokens: int
    max_output_tokens: int
    max_concurrent_requests: int
    remote_fallback: bool = False

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "profile_id")
        _identifier(self.model_id, "model_id")
        _sha256(self.model_manifest_sha256, "model_manifest_sha256")
        _sha256(self.tokenizer_sha256, "tokenizer_sha256")
        _sha256(self.template_sha256, "template_sha256")
        _identifier(self.backend, "backend")
        _identifier(self.backend_version, "backend_version")
        for field in ("context_tokens", "max_output_tokens", "max_concurrent_requests"):
            value = checked_u64(getattr(self, field), field=field)
            if value == 0:
                raise ResourceValidationError(f"{field} must be positive")
        if self.remote_fallback is not False:
            raise ResourceValidationError("G1 runtime profiles must deny remote fallback")


@dataclass(frozen=True, slots=True)
class PlacementPlan:
    plan_id: str
    runtime_profile_id: str
    reservations: tuple[MemoryReservation, ...]

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "plan_id")
        _identifier(self.runtime_profile_id, "runtime_profile_id")
        reservations = tuple(self.reservations)
        if not reservations:
            raise ResourceValidationError("placement plan requires at least one reservation")
        if reservations != tuple(sorted(reservations)):
            raise ResourceValidationError("placement reservations must use canonical domain order")
        if len({item.domain_id for item in reservations}) != len(reservations):
            raise ResourceValidationError("placement reservations must use unique domains")
        object.__setattr__(self, "reservations", reservations)

    @property
    def reservation_map(self) -> dict[str, int]:
        return {item.domain_id: item.bytes for item in self.reservations}


@dataclass(frozen=True, slots=True)
class ResourceAllocation:
    plan_id: str
    runtime_profile_id: str
    lease: ResourceLease

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "plan_id")
        _identifier(self.runtime_profile_id, "runtime_profile_id")
        if not isinstance(self.lease, ResourceLease):
            raise ResourceValidationError("lease must be a ResourceLease")


def admit_placement(
    ledger: ResourceLedger,
    *,
    owner_id: str,
    profile: RuntimeProfile,
    plan: PlacementPlan,
    idempotency_key: str,
) -> ResourceAllocation:
    if plan.runtime_profile_id != profile.profile_id:
        raise ResourceValidationError("placement plan refers to a different runtime profile")
    lease = ledger.admit(owner_id, plan.reservations, idempotency_key=idempotency_key)
    if lease.reservations != plan.reservations:
        raise ResourceValidationError("resource ledger returned a non-matching allocation")
    return ResourceAllocation(plan.plan_id, profile.profile_id, lease)


class CacheIsolationError(RuntimeError):
    """A caller crossed a cache ownership boundary."""


class CacheItemTooLarge(RuntimeError):
    """One item cannot fit in the cache partition."""


@dataclass(frozen=True, slots=True)
class CachePutResult:
    key: str
    used_bytes: int
    evicted_keys: tuple[str, ...]


class IsolatedByteCache:
    """Owner-bound deterministic LRU cache with exact byte accounting."""

    def __init__(self, *, owner_id: str, quota_bytes: int) -> None:
        self.owner_id = _identifier(owner_id, "owner_id")
        self.quota_bytes = checked_u64(quota_bytes, field="quota_bytes")
        if self.quota_bytes == 0:
            raise ResourceValidationError("quota_bytes must be positive")
        self._items: OrderedDict[str, bytes] = OrderedDict()
        self._used_bytes = 0
        self._lock = threading.RLock()

    @property
    def used_bytes(self) -> int:
        with self._lock:
            return self._used_bytes

    def keys(self, *, owner_id: str) -> tuple[str, ...]:
        self._require_owner(owner_id)
        with self._lock:
            return tuple(self._items)

    def get(self, owner_id: str, key: str) -> bytes | None:
        self._require_owner(owner_id)
        key = _identifier(key, "key")
        with self._lock:
            value = self._items.get(key)
            if value is None:
                return None
            self._items.move_to_end(key)
            return value

    def put(self, owner_id: str, key: str, value: bytes) -> CachePutResult:
        self._require_owner(owner_id)
        key = _identifier(key, "key")
        if not isinstance(value, bytes):
            raise ResourceValidationError("cache values must be immutable bytes")
        size = checked_u64(len(value), field="value size")
        if size > self.quota_bytes:
            raise CacheItemTooLarge("cache item exceeds its partition quota")
        with self._lock:
            previous = self._items.pop(key, None)
            if previous is not None:
                self._used_bytes = checked_sub_bytes(self._used_bytes, len(previous))
            evicted: list[str] = []
            while self._items and size > checked_sub_bytes(self.quota_bytes, self._used_bytes):
                old_key, old_value = self._items.popitem(last=False)
                self._used_bytes = checked_sub_bytes(self._used_bytes, len(old_value))
                evicted.append(old_key)
            self._items[key] = value
            self._used_bytes = checked_add_bytes(self._used_bytes, size)
            return CachePutResult(key, self._used_bytes, tuple(evicted))

    def clear(self, *, owner_id: str) -> None:
        self._require_owner(owner_id)
        with self._lock:
            self._items.clear()
            self._used_bytes = 0

    def _require_owner(self, owner_id: str) -> None:
        if _identifier(owner_id, "owner_id") != self.owner_id:
            raise CacheIsolationError("cache partition belongs to another owner")
