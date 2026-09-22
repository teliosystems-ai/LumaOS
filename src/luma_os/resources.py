"""Checked, dependency-free resource admission primitives.

This module intentionally keeps policy separate from physical allocation.  A
successful admission is an accounting lease, not proof that an operating-system
or accelerator allocation succeeded.  Runtime adapters must keep the lease
active for the full lifetime of the corresponding physical resources.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import threading
from types import MappingProxyType
from typing import Final, Protocol
from uuid import uuid4


MAX_U64: Final[int] = (1 << 64) - 1


class ResourceLedgerError(RuntimeError):
    """Base class for expected resource-ledger failures."""


class ResourceValidationError(ValueError):
    """A resource contract contained an invalid value."""


class ByteArithmeticError(ResourceValidationError):
    """Unsigned 64-bit byte arithmetic overflowed or underflowed."""


class AdmissionDenied(ResourceLedgerError):
    """The requested reservation cannot be admitted at this time."""

    def __init__(self, reason: str, *, domain_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.domain_id = domain_id


class IdempotencyConflict(ResourceLedgerError):
    """An idempotency key was reused for a different reservation."""


class StaleLeaseError(ResourceLedgerError):
    """A lease token is unknown, inactive, or carries an old generation."""


class LeaseOwnershipError(ResourceLedgerError):
    """A caller attempted to use a lease owned by another principal."""


class StaleTelemetryError(ResourceLedgerError):
    """A telemetry sequence moved backwards or was reused with new data."""


class TelemetryAdapter(Protocol):
    """Version-neutral telemetry boundary used by the resource ledger."""

    def sample(self, domain_id: str) -> "TelemetrySample": ...


def checked_u64(value: int, *, field: str = "value") -> int:
    """Return *value* after enforcing the unsigned 64-bit contract.

    ``bool`` is rejected even though it is an ``int`` subclass: accepting it in
    a byte field tends to hide serialization and schema bugs.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceValidationError(f"{field} must be an integer")
    if value < 0 or value > MAX_U64:
        raise ResourceValidationError(f"{field} must be between 0 and {MAX_U64}")
    return value


def checked_add_bytes(left: int, right: int) -> int:
    """Add two unsigned 64-bit byte counts without wrapping."""

    left = checked_u64(left, field="left")
    right = checked_u64(right, field="right")
    if left > MAX_U64 - right:
        raise ByteArithmeticError("unsigned 64-bit byte addition overflow")
    return left + right


def checked_sub_bytes(left: int, right: int) -> int:
    """Subtract two unsigned 64-bit byte counts without wrapping."""

    left = checked_u64(left, field="left")
    right = checked_u64(right, field="right")
    if right > left:
        raise ByteArithmeticError("unsigned 64-bit byte subtraction underflow")
    return left - right


def checked_sum_bytes(values: Iterable[int]) -> int:
    """Sum unsigned 64-bit byte counts, failing before any wraparound."""

    total = 0
    for value in values:
        total = checked_add_bytes(total, value)
    return total


def _identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ResourceValidationError(f"{field} must be a non-empty, trimmed string")
    if len(value) > 256:
        raise ResourceValidationError(f"{field} must not exceed 256 characters")
    return value


@dataclass(frozen=True, slots=True)
class MemoryDomain:
    """A bounded memory accounting domain.

    ``budget_bytes`` is the hard ceiling.  ``reserved_bytes`` is held back for
    the OS, display, driver, or another non-ledger consumer.  Pressure
    watermarks are expressed as total domain consumption, including that
    reservation.  The lower exit watermark gives pressure recovery hysteresis.
    """

    domain_id: str
    budget_bytes: int
    reserved_bytes: int = 0
    pressure_enter_bytes: int | None = None
    pressure_exit_bytes: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.domain_id, field="domain_id")
        budget = checked_u64(self.budget_bytes, field="budget_bytes")
        reserved = checked_u64(self.reserved_bytes, field="reserved_bytes")
        if budget == 0:
            raise ResourceValidationError("budget_bytes must be greater than zero")
        if reserved >= budget:
            raise ResourceValidationError("reserved_bytes must be less than budget_bytes")

        enter = budget if self.pressure_enter_bytes is None else checked_u64(
            self.pressure_enter_bytes, field="pressure_enter_bytes"
        )
        exit_at = enter if self.pressure_exit_bytes is None else checked_u64(
            self.pressure_exit_bytes, field="pressure_exit_bytes"
        )
        if enter <= reserved or enter > budget:
            raise ResourceValidationError(
                "pressure_enter_bytes must be greater than reserved_bytes and no greater than budget_bytes"
            )
        if exit_at < reserved or exit_at > enter:
            raise ResourceValidationError(
                "pressure_exit_bytes must be between reserved_bytes and pressure_enter_bytes"
            )
        object.__setattr__(self, "pressure_enter_bytes", enter)
        object.__setattr__(self, "pressure_exit_bytes", exit_at)

    @property
    def allocatable_bytes(self) -> int:
        return checked_sub_bytes(self.budget_bytes, self.reserved_bytes)

    def as_dict(self) -> dict[str, int | str]:
        return {
            "domain_id": self.domain_id,
            "budget_bytes": self.budget_bytes,
            "reserved_bytes": self.reserved_bytes,
            "allocatable_bytes": self.allocatable_bytes,
            "pressure_enter_bytes": self.pressure_enter_bytes,
            "pressure_exit_bytes": self.pressure_exit_bytes,
        }


@dataclass(frozen=True, slots=True, order=True)
class MemoryReservation:
    domain_id: str
    bytes: int

    def __post_init__(self) -> None:
        _identifier(self.domain_id, field="domain_id")
        checked_u64(self.bytes, field="bytes")
        if self.bytes == 0:
            raise ResourceValidationError("reservation bytes must be greater than zero")

    def as_dict(self) -> dict[str, int | str]:
        return {"domain_id": self.domain_id, "bytes": self.bytes}


class LeaseStatus(str, Enum):
    ACTIVE = "active"
    RELEASED = "released"
    REVOKED = "revoked"


class DomainState(str, Enum):
    HEALTHY = "healthy"
    PRESSURE = "pressure"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class ResourceLease:
    """Immutable fencing token returned by an atomic admission."""

    lease_id: str
    generation: int
    owner_id: str
    idempotency_key: str
    reservations: tuple[MemoryReservation, ...]

    def __post_init__(self) -> None:
        _identifier(self.lease_id, field="lease_id")
        generation = checked_u64(self.generation, field="generation")
        if generation == 0:
            raise ResourceValidationError("generation must be greater than zero")
        _identifier(self.owner_id, field="owner_id")
        _identifier(self.idempotency_key, field="idempotency_key")
        if not self.reservations:
            raise ResourceValidationError("a lease must contain at least one reservation")
        if tuple(sorted(self.reservations)) != self.reservations:
            raise ResourceValidationError("lease reservations must be in canonical domain order")
        domain_ids = [item.domain_id for item in self.reservations]
        if len(domain_ids) != len(set(domain_ids)):
            raise ResourceValidationError("lease reservations must have unique domains")
        checked_sum_bytes(item.bytes for item in self.reservations)

    @property
    def total_bytes(self) -> int:
        return checked_sum_bytes(item.bytes for item in self.reservations)

    def bytes_for(self, domain_id: str) -> int:
        for reservation in self.reservations:
            if reservation.domain_id == domain_id:
                return reservation.bytes
        return 0

    def as_dict(self) -> dict[str, object]:
        return {
            "lease_id": self.lease_id,
            "generation": self.generation,
            "owner_id": self.owner_id,
            "idempotency_key": self.idempotency_key,
            "reservations": [item.as_dict() for item in self.reservations],
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class TelemetrySample:
    """A monotonically sequenced physical-domain observation."""

    domain_id: str
    sequence: int
    used_bytes: int
    total_bytes: int
    device_error: bool = False

    def __post_init__(self) -> None:
        _identifier(self.domain_id, field="domain_id")
        sequence = checked_u64(self.sequence, field="sequence")
        if sequence == 0:
            raise ResourceValidationError("telemetry sequence must be greater than zero")
        used = checked_u64(self.used_bytes, field="used_bytes")
        total = checked_u64(self.total_bytes, field="total_bytes")
        if total == 0 or used > total:
            raise ResourceValidationError("telemetry must satisfy 0 <= used_bytes <= total_bytes")
        if not isinstance(self.device_error, bool):
            raise ResourceValidationError("device_error must be a boolean")

    @property
    def available_bytes(self) -> int:
        return checked_sub_bytes(self.total_bytes, self.used_bytes)


@dataclass(frozen=True, slots=True)
class DomainSnapshot:
    domain: MemoryDomain
    allocated_bytes: int
    observed_used_bytes: int | None
    state: DomainState
    quarantine_epoch: int
    state_reason: str | None

    @property
    def available_bytes(self) -> int:
        return checked_sub_bytes(self.domain.allocatable_bytes, self.allocated_bytes)

    def as_dict(self) -> dict[str, object]:
        return {
            **self.domain.as_dict(),
            "allocated_bytes": self.allocated_bytes,
            "available_bytes": self.available_bytes,
            "observed_used_bytes": self.observed_used_bytes,
            "state": self.state.value,
            "quarantine_epoch": self.quarantine_epoch,
            "state_reason": self.state_reason,
        }


@dataclass(slots=True)
class _DomainRecord:
    domain: MemoryDomain
    allocated_bytes: int = 0
    observed_used_bytes: int | None = None
    state: DomainState = DomainState.HEALTHY
    quarantine_epoch: int = 0
    state_reason: str | None = None
    last_telemetry: TelemetrySample | None = None


@dataclass(slots=True)
class _LeaseRecord:
    lease: ResourceLease
    status: LeaseStatus = LeaseStatus.ACTIVE
    terminal_reason: str | None = None


class ResourceLedger:
    """Thread-safe, atomic resource admission with generation fencing."""

    def __init__(
        self,
        domains: Iterable[MemoryDomain],
        *,
        id_factory: Callable[[], str] | None = None,
        initial_generation: int = 1,
    ) -> None:
        records: dict[str, _DomainRecord] = {}
        for domain in domains:
            if not isinstance(domain, MemoryDomain):
                raise ResourceValidationError("domains must contain MemoryDomain instances")
            if domain.domain_id in records:
                raise ResourceValidationError(f"duplicate memory domain: {domain.domain_id}")
            records[domain.domain_id] = _DomainRecord(domain=domain)
        if not records:
            raise ResourceValidationError("at least one memory domain is required")
        generation = checked_u64(initial_generation, field="initial_generation")
        if generation == 0:
            raise ResourceValidationError("initial_generation must be greater than zero")
        self._domains = records
        self._leases: dict[str, _LeaseRecord] = {}
        self._idempotency: dict[tuple[str, str], tuple[tuple[MemoryReservation, ...], str]] = {}
        self._next_generation: int | None = generation
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self._lock = threading.RLock()

    @property
    def domain_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._domains))

    def admit(
        self,
        owner_id: str,
        reservations: Mapping[str, int] | Iterable[MemoryReservation],
        *,
        idempotency_key: str,
    ) -> ResourceLease:
        """Atomically admit every reservation or mutate nothing.

        Idempotency keys are scoped by owner and retained after release or
        revocation.  Replaying the same request returns the original lease token
        without reacquiring capacity; changing the request raises a conflict.
        """

        owner_id = _identifier(owner_id, field="owner_id")
        idempotency_key = _identifier(idempotency_key, field="idempotency_key")
        canonical = self._canonical_reservations(reservations)
        key = (owner_id, idempotency_key)
        with self._lock:
            replay = self._idempotency.get(key)
            if replay is not None:
                original, lease_id = replay
                if original != canonical:
                    raise IdempotencyConflict(
                        "idempotency key was already used with different reservations"
                    )
                return self._leases[lease_id].lease

            prospective: dict[str, int] = {}
            for reservation in canonical:
                record = self._domains.get(reservation.domain_id)
                if record is None:
                    raise AdmissionDenied(
                        "reservation refers to an unknown memory domain",
                        domain_id=reservation.domain_id,
                    )
                self._recompute_state_locked(record)
                if record.state is DomainState.QUARANTINED:
                    raise AdmissionDenied(
                        "memory domain is quarantined", domain_id=reservation.domain_id
                    )
                if record.state is DomainState.PRESSURE:
                    raise AdmissionDenied(
                        "memory domain is under pressure", domain_id=reservation.domain_id
                    )
                new_allocated = checked_add_bytes(record.allocated_bytes, reservation.bytes)
                if new_allocated > record.domain.allocatable_bytes:
                    raise AdmissionDenied(
                        "reservation exceeds the memory domain budget",
                        domain_id=reservation.domain_id,
                    )
                prospective[reservation.domain_id] = new_allocated

            generation = self._take_generation_locked()
            lease_id = self._new_lease_id_locked()
            lease = ResourceLease(
                lease_id=lease_id,
                generation=generation,
                owner_id=owner_id,
                idempotency_key=idempotency_key,
                reservations=canonical,
            )
            for domain_id, allocated in prospective.items():
                self._domains[domain_id].allocated_bytes = allocated
            self._leases[lease_id] = _LeaseRecord(lease=lease)
            self._idempotency[key] = (canonical, lease_id)
            for domain_id in prospective:
                self._recompute_state_locked(self._domains[domain_id])
            return lease

    def release(
        self,
        lease: ResourceLease | str,
        generation: int | None = None,
        *,
        owner_id: str | None = None,
    ) -> bool:
        """Release an active lease; exact duplicate releases are harmless.

        Returns ``True`` only for the transition from active to released.
        Unknown IDs, wrong generations, revoked leases, and forged tokens are
        rejected instead of being treated as successful cleanup.
        """

        with self._lock:
            record = self._lookup_locked(lease, generation, owner_id=owner_id)
            if record.status is LeaseStatus.RELEASED:
                return False
            if record.status is not LeaseStatus.ACTIVE:
                raise StaleLeaseError("lease is no longer active")
            self._terminalize_locked(record, LeaseStatus.RELEASED, "released")
            return True

    def assert_active(
        self,
        lease: ResourceLease | str,
        generation: int | None = None,
        *,
        owner_id: str | None = None,
    ) -> ResourceLease:
        """Validate a fencing token and return the canonical stored lease."""

        with self._lock:
            record = self._lookup_locked(lease, generation, owner_id=owner_id)
            if record.status is not LeaseStatus.ACTIVE:
                raise StaleLeaseError("lease is no longer active")
            return record.lease

    @contextmanager
    def hold(
        self,
        lease: ResourceLease | str,
        generation: int | None = None,
        *,
        owner_id: str | None = None,
    ) -> Iterator[ResourceLease]:
        """Hold the ledger lock while an adapter starts a leased operation.

        This closes the check/release race for short admission-bound operations.
        Long-running runtimes should use their own lifecycle lock and release the
        ledger lease only after process/device cleanup is complete.
        """

        with self._lock:
            record = self._lookup_locked(lease, generation, owner_id=owner_id)
            if record.status is not LeaseStatus.ACTIVE:
                raise StaleLeaseError("lease is no longer active")
            yield record.lease

    def lease_status(
        self, lease: ResourceLease | str, generation: int | None = None
    ) -> LeaseStatus:
        with self._lock:
            return self._lookup_locked(lease, generation).status

    def domain_snapshot(self, domain_id: str) -> DomainSnapshot:
        domain_id = _identifier(domain_id, field="domain_id")
        with self._lock:
            record = self._domains.get(domain_id)
            if record is None:
                raise ResourceValidationError(f"unknown memory domain: {domain_id}")
            self._recompute_state_locked(record)
            return self._snapshot_locked(record)

    def snapshots(self) -> Mapping[str, DomainSnapshot]:
        """Return an immutable point-in-time view of every domain."""

        with self._lock:
            result: dict[str, DomainSnapshot] = {}
            for domain_id in sorted(self._domains):
                record = self._domains[domain_id]
                self._recompute_state_locked(record)
                result[domain_id] = self._snapshot_locked(record)
            return MappingProxyType(result)

    def update_telemetry(self, sample: TelemetrySample) -> DomainSnapshot:
        """Apply a monotonic telemetry observation and update domain health."""

        if not isinstance(sample, TelemetrySample):
            raise ResourceValidationError("sample must be a TelemetrySample")
        with self._lock:
            record = self._domains.get(sample.domain_id)
            if record is None:
                raise ResourceValidationError(f"unknown memory domain: {sample.domain_id}")
            previous = record.last_telemetry
            if previous is not None:
                if sample.sequence < previous.sequence:
                    raise StaleTelemetryError("telemetry sequence moved backwards")
                if sample.sequence == previous.sequence:
                    if sample != previous:
                        raise StaleTelemetryError(
                            "telemetry sequence was reused with different data"
                        )
                    return self._snapshot_locked(record)

            record.last_telemetry = sample
            record.observed_used_bytes = sample.used_bytes
            if sample.total_bytes < record.domain.budget_bytes:
                self._quarantine_locked(
                    record,
                    "telemetry capacity is below the configured memory-domain budget",
                )
            elif sample.device_error:
                self._quarantine_locked(record, "telemetry reported a device error")
            else:
                self._recompute_state_locked(record)
            return self._snapshot_locked(record)

    def refresh_telemetry(
        self, adapter: TelemetryAdapter, domain_ids: Iterable[str] | None = None
    ) -> Mapping[str, DomainSnapshot]:
        selected = self.domain_ids if domain_ids is None else tuple(domain_ids)
        refreshed: dict[str, DomainSnapshot] = {}
        for domain_id in selected:
            sample = adapter.sample(domain_id)
            refreshed[domain_id] = self.update_telemetry(sample)
        return MappingProxyType(refreshed)

    def quarantine(self, domain_id: str, *, reason: str) -> tuple[ResourceLease, ...]:
        """Quarantine a domain and atomically revoke every touching lease.

        A multi-domain lease is revoked in full so that its other reservations
        cannot be mistaken for a usable partial placement.
        """

        domain_id = _identifier(domain_id, field="domain_id")
        reason = _identifier(reason, field="reason")
        with self._lock:
            record = self._domains.get(domain_id)
            if record is None:
                raise ResourceValidationError(f"unknown memory domain: {domain_id}")
            return self._quarantine_locked(record, reason)

    def clear_quarantine(self, domain_id: str, *, expected_epoch: int) -> DomainSnapshot:
        """Clear quarantine using an epoch-fenced administrative decision."""

        domain_id = _identifier(domain_id, field="domain_id")
        expected_epoch = checked_u64(expected_epoch, field="expected_epoch")
        with self._lock:
            record = self._domains.get(domain_id)
            if record is None:
                raise ResourceValidationError(f"unknown memory domain: {domain_id}")
            if record.state is not DomainState.QUARANTINED:
                raise ResourceLedgerError("memory domain is not quarantined")
            if expected_epoch != record.quarantine_epoch:
                raise StaleLeaseError("quarantine epoch does not match")
            record.state = DomainState.HEALTHY
            record.state_reason = None
            self._recompute_state_locked(record)
            return self._snapshot_locked(record)

    def _canonical_reservations(
        self, reservations: Mapping[str, int] | Iterable[MemoryReservation]
    ) -> tuple[MemoryReservation, ...]:
        if isinstance(reservations, Mapping):
            items = tuple(
                MemoryReservation(domain_id=domain_id, bytes=size)
                for domain_id, size in reservations.items()
            )
        else:
            try:
                items = tuple(reservations)
            except TypeError as exc:
                raise ResourceValidationError(
                    "reservations must be a mapping or iterable of MemoryReservation"
                ) from exc
            if any(not isinstance(item, MemoryReservation) for item in items):
                raise ResourceValidationError(
                    "reservation iterable must contain MemoryReservation instances"
                )
        if not items:
            raise ResourceValidationError("at least one reservation is required")
        canonical = tuple(sorted(items))
        domain_ids = [item.domain_id for item in canonical]
        if len(domain_ids) != len(set(domain_ids)):
            raise ResourceValidationError("reservations must have unique domains")
        checked_sum_bytes(item.bytes for item in canonical)
        return canonical

    def _take_generation_locked(self) -> int:
        generation = self._next_generation
        if generation is None:
            raise ByteArithmeticError("lease generation space is exhausted")
        self._next_generation = None if generation == MAX_U64 else generation + 1
        return generation

    def _new_lease_id_locked(self) -> str:
        for _ in range(32):
            candidate = _identifier(self._id_factory(), field="generated lease_id")
            if candidate not in self._leases:
                return candidate
        raise ResourceLedgerError("lease ID factory repeatedly produced collisions")

    def _lookup_locked(
        self,
        lease: ResourceLease | str,
        generation: int | None,
        *,
        owner_id: str | None = None,
    ) -> _LeaseRecord:
        supplied: ResourceLease | None
        if isinstance(lease, ResourceLease):
            if generation is not None and generation != lease.generation:
                raise StaleLeaseError("conflicting lease generations were supplied")
            lease_id = lease.lease_id
            wanted_generation = lease.generation
            supplied = lease
        elif isinstance(lease, str):
            lease_id = _identifier(lease, field="lease_id")
            if generation is None:
                raise ResourceValidationError("generation is required with a lease ID")
            wanted_generation = checked_u64(generation, field="generation")
            supplied = None
        else:
            raise ResourceValidationError("lease must be a ResourceLease or lease ID")
        record = self._leases.get(lease_id)
        if record is None or record.lease.generation != wanted_generation:
            raise StaleLeaseError("lease ID or generation is stale")
        if supplied is not None and supplied != record.lease:
            raise StaleLeaseError("lease token does not match the admitted lease")
        if owner_id is not None:
            owner_id = _identifier(owner_id, field="owner_id")
            if owner_id != record.lease.owner_id:
                raise LeaseOwnershipError("lease belongs to another owner")
        return record

    def _terminalize_locked(
        self, record: _LeaseRecord, status: LeaseStatus, reason: str
    ) -> None:
        if record.status is not LeaseStatus.ACTIVE:
            raise StaleLeaseError("lease is no longer active")
        changed: set[str] = set()
        new_values: dict[str, int] = {}
        for reservation in record.lease.reservations:
            domain = self._domains[reservation.domain_id]
            new_values[reservation.domain_id] = checked_sub_bytes(
                domain.allocated_bytes, reservation.bytes
            )
            changed.add(reservation.domain_id)
        for domain_id, value in new_values.items():
            self._domains[domain_id].allocated_bytes = value
        record.status = status
        record.terminal_reason = reason
        for domain_id in changed:
            self._recompute_state_locked(self._domains[domain_id])

    def _quarantine_locked(
        self, target: _DomainRecord, reason: str
    ) -> tuple[ResourceLease, ...]:
        if target.state is DomainState.QUARANTINED:
            return ()
        if target.quarantine_epoch == MAX_U64:
            raise ByteArithmeticError("quarantine epoch space is exhausted")
        target.quarantine_epoch += 1
        target.state = DomainState.QUARANTINED
        target.state_reason = reason
        affected = [
            record
            for record in self._leases.values()
            if record.status is LeaseStatus.ACTIVE
            and any(
                reservation.domain_id == target.domain.domain_id
                for reservation in record.lease.reservations
            )
        ]
        for record in affected:
            self._terminalize_locked(
                record,
                LeaseStatus.REVOKED,
                f"domain {target.domain.domain_id} quarantined: {reason}",
            )
        # terminalization deliberately cannot clear the target quarantine.
        target.state = DomainState.QUARANTINED
        target.state_reason = reason
        return tuple(record.lease for record in affected)

    def _recompute_state_locked(self, record: _DomainRecord) -> None:
        if record.state is DomainState.QUARANTINED:
            return
        accounted = checked_add_bytes(record.domain.reserved_bytes, record.allocated_bytes)
        load = (
            accounted
            if record.observed_used_bytes is None
            else max(accounted, record.observed_used_bytes)
        )
        if record.state is DomainState.PRESSURE:
            under_pressure = load > record.domain.pressure_exit_bytes
        else:
            under_pressure = load >= record.domain.pressure_enter_bytes
        if under_pressure:
            record.state = DomainState.PRESSURE
            record.state_reason = "memory use crossed the pressure watermark"
        else:
            record.state = DomainState.HEALTHY
            record.state_reason = None

    @staticmethod
    def _snapshot_locked(record: _DomainRecord) -> DomainSnapshot:
        return DomainSnapshot(
            domain=record.domain,
            allocated_bytes=record.allocated_bytes,
            observed_used_bytes=record.observed_used_bytes,
            state=record.state,
            quarantine_epoch=record.quarantine_epoch,
            state_reason=record.state_reason,
        )


class FakeTelemetryAdapter:
    """Thread-safe scripted telemetry with no clock or hardware dependency."""

    def __init__(
        self,
        scripts: Mapping[str, Iterable[TelemetrySample]],
        *,
        repeat_last: bool = True,
    ) -> None:
        if not isinstance(repeat_last, bool):
            raise ResourceValidationError("repeat_last must be a boolean")
        prepared: dict[str, tuple[TelemetrySample, ...]] = {}
        for domain_id, samples in scripts.items():
            _identifier(domain_id, field="domain_id")
            sequence = tuple(samples)
            if not sequence:
                raise ResourceValidationError(f"telemetry script is empty: {domain_id}")
            if any(sample.domain_id != domain_id for sample in sequence):
                raise ResourceValidationError(
                    f"telemetry sample domain does not match script: {domain_id}"
                )
            previous = 0
            for sample in sequence:
                if sample.sequence <= previous:
                    raise ResourceValidationError(
                        f"telemetry script sequences must increase: {domain_id}"
                    )
                previous = sample.sequence
            prepared[domain_id] = sequence
        if not prepared:
            raise ResourceValidationError("at least one telemetry script is required")
        self._scripts = prepared
        self._positions = {domain_id: 0 for domain_id in prepared}
        self._repeat_last = repeat_last
        self._lock = threading.Lock()

    def sample(self, domain_id: str) -> TelemetrySample:
        domain_id = _identifier(domain_id, field="domain_id")
        with self._lock:
            script = self._scripts.get(domain_id)
            if script is None:
                raise ResourceValidationError(f"no telemetry script for domain: {domain_id}")
            position = self._positions[domain_id]
            if position >= len(script):
                if not self._repeat_last:
                    raise ResourceLedgerError(f"telemetry script exhausted: {domain_id}")
                return script[-1]
            self._positions[domain_id] = position + 1
            return script[position]
