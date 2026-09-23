"""Pure installer preflight and destructive-action authorization contracts.

This module deliberately does not discover hardware, resolve device paths, or
run an installer.  Trusted platform adapters provide immutable inventory
snapshots and an executor is injected only after the contract has revalidated
the selected disk and consumed an explicit, short-lived confirmation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import re
import threading
from typing import Protocol, TypeVar

from .model_selection import (
    ModelHardwareSnapshot,
    ModelProfileCatalog,
    ModelSelection,
    ModelSelectionAssessment,
    ModelSelectionDenied,
    ModelSelectionError,
    assess_model_selection,
    select_model_profile,
)


U64_MAX = (1 << 64) - 1
INSTALL_ALIGNMENT_BYTES = 1024 * 1024
LEADING_METADATA_BYTES = INSTALL_ALIGNMENT_BYTES
TRAILING_METADATA_BYTES = INSTALL_ALIGNMENT_BYTES
CONFIRM_INSTALL_ACTIVITY = "installer.plan.confirm"
EXECUTE_INSTALL_ACTIVITY = "installer.disk.mutate"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}\Z")
_STABLE_DISK_ID = re.compile(r"(?:wwn|serial|uuid):[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class InstallerError(RuntimeError):
    """Base class for installer contract failures."""


class InstallerValidationError(ValueError):
    """An installer input is malformed or non-canonical."""


class InventoryStale(InstallerError):
    """An inventory snapshot is too old or is dated in the future."""


class PreflightDenied(InstallerError):
    """The selected edition cannot safely be installed on the inventory."""

    def __init__(self, assessment: HardwareAssessment) -> None:
        self.assessment = assessment
        reasons = ", ".join(assessment.reasons) or "preflight policy denied installation"
        super().__init__(reasons)


class ConfirmationDenied(InstallerError):
    """A destructive installation was not explicitly and currently authorized."""


class ConfirmationReplay(ConfirmationDenied):
    """A confirmation or plan has already reached the execution boundary."""


class InventoryChanged(ConfirmationDenied):
    """Fresh hardware state does not match the state that was confirmed."""


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise InstallerValidationError(f"{field} must be a canonical safe identifier")
    return value


def _token(value: object, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise InstallerValidationError(f"{field} must be a lowercase canonical token")
    return value


def _stable_disk_id(value: object, field: str = "stable_id") -> str:
    if not isinstance(value, str) or not _STABLE_DISK_ID.fullmatch(value):
        raise InstallerValidationError(
            f"{field} must use a wwn:, serial:, or uuid: stable identity"
        )
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise InstallerValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _u64(value: object, field: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InstallerValidationError(f"{field} must be an integer, not a boolean")
    if value < 0 or value > U64_MAX or (positive and value == 0):
        qualifier = "positive " if positive else ""
        raise InstallerValidationError(f"{field} must be a {qualifier}unsigned 64-bit integer")
    return value


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise InstallerValidationError(f"{field} must be a boolean")
    return value


def _aware_utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise InstallerValidationError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _parse_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise InstallerValidationError(f"{field} must be an RFC 3339 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise InstallerValidationError(f"{field} must be an RFC 3339 datetime") from exc
    return _aware_utc(parsed, field)


def _canonical_datetime(value: datetime) -> str:
    return _aware_utc(value, "datetime").isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _checked_sum(values: Sequence[int], field: str) -> int:
    total = 0
    for value in values:
        total += _u64(value, field)
        if total > U64_MAX:
            raise InstallerValidationError(f"{field} exceeds unsigned 64-bit capacity")
    return total


def _strict_mapping(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    field: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InstallerValidationError(f"{field} must be an object")
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise InstallerValidationError(f"{field} keys must be strings")
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise InstallerValidationError(f"{field} is missing fields: {sorted(missing)}")
    if unknown:
        raise InstallerValidationError(f"{field} has unknown fields: {sorted(unknown)}")
    return value


T = TypeVar("T")


def _typed_items(value: object, item_type: type[T], field: str) -> tuple[T, ...]:
    if not isinstance(value, (list, tuple)):
        raise InstallerValidationError(f"{field} must be an array")
    result = tuple(value)
    if any(not isinstance(item, item_type) for item in result):
        raise InstallerValidationError(f"{field} contains an invalid item")
    return result


def _canonical_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class DiskRecord:
    """A stable disk identity plus the state that makes a plan safe to reuse."""

    stable_id: str
    device_fingerprint: str
    capacity_bytes: int
    logical_sector_bytes: int
    layout_sha256: str
    read_only: bool = False

    def __post_init__(self) -> None:
        _stable_disk_id(self.stable_id)
        _sha256(self.device_fingerprint, "device_fingerprint")
        capacity = _u64(self.capacity_bytes, "capacity_bytes", positive=True)
        sector = _u64(self.logical_sector_bytes, "logical_sector_bytes", positive=True)
        if sector < 512 or sector > 65536 or sector & (sector - 1):
            raise InstallerValidationError(
                "logical_sector_bytes must be a power of two from 512 through 65536"
            )
        if capacity % sector:
            raise InstallerValidationError("capacity_bytes must be sector aligned")
        _sha256(self.layout_sha256, "layout_sha256")
        _strict_bool(self.read_only, "read_only")

    @classmethod
    def from_mapping(cls, value: object) -> DiskRecord:
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "stable_id",
                    "device_fingerprint",
                    "capacity_bytes",
                    "logical_sector_bytes",
                    "layout_sha256",
                }
            ),
            optional=frozenset({"read_only"}),
            field="disk",
        )
        return cls(
            stable_id=data["stable_id"],  # type: ignore[arg-type]
            device_fingerprint=data["device_fingerprint"],  # type: ignore[arg-type]
            capacity_bytes=data["capacity_bytes"],  # type: ignore[arg-type]
            logical_sector_bytes=data["logical_sector_bytes"],  # type: ignore[arg-type]
            layout_sha256=data["layout_sha256"],  # type: ignore[arg-type]
            read_only=data.get("read_only", False),  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "capacity_bytes": self.capacity_bytes,
            "device_fingerprint": self.device_fingerprint,
            "layout_sha256": self.layout_sha256,
            "logical_sector_bytes": self.logical_sector_bytes,
            "read_only": self.read_only,
            "stable_id": self.stable_id,
        }

    @property
    def identity_sha256(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class HardwareDevice:
    """One stable inventory entry, including its driver-support assessment."""

    stable_id: str
    device_class: str
    support_status: str
    memory_bytes: int = 0

    def __post_init__(self) -> None:
        _identifier(self.stable_id, "device stable_id")
        _token(self.device_class, "device_class")
        if self.support_status not in {"certified", "degraded", "unsupported"}:
            raise InstallerValidationError(
                "support_status must be certified, degraded, or unsupported"
            )
        _u64(self.memory_bytes, "device memory_bytes")

    @classmethod
    def from_mapping(cls, value: object) -> HardwareDevice:
        data = _strict_mapping(
            value,
            required=frozenset({"stable_id", "device_class", "support_status"}),
            optional=frozenset({"memory_bytes"}),
            field="device",
        )
        return cls(
            stable_id=data["stable_id"],  # type: ignore[arg-type]
            device_class=data["device_class"],  # type: ignore[arg-type]
            support_status=data["support_status"],  # type: ignore[arg-type]
            memory_bytes=data.get("memory_bytes", 0),  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "device_class": self.device_class,
            "memory_bytes": self.memory_bytes,
            "stable_id": self.stable_id,
            "support_status": self.support_status,
        }


@dataclass(frozen=True, slots=True)
class HardwareInventory:
    """An immutable result from a platform-specific, trusted inventory adapter."""

    snapshot_id: str
    hardware_fingerprint: str
    architecture: str
    usable_ram_bytes: int
    disks: tuple[DiskRecord, ...]
    devices: tuple[HardwareDevice, ...]
    captured_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.snapshot_id, "snapshot_id")
        _sha256(self.hardware_fingerprint, "hardware_fingerprint")
        _token(self.architecture, "architecture")
        _u64(self.usable_ram_bytes, "usable_ram_bytes")
        disks = _typed_items(self.disks, DiskRecord, "disks")
        devices = _typed_items(self.devices, HardwareDevice, "devices")
        object.__setattr__(self, "disks", disks)
        object.__setattr__(self, "devices", devices)
        object.__setattr__(self, "captured_at", _aware_utc(self.captured_at, "captured_at"))

        stable_ids = [disk.stable_id.casefold() for disk in disks]
        fingerprints = [disk.device_fingerprint for disk in disks]
        if len(stable_ids) != len(set(stable_ids)):
            raise InstallerValidationError("disk stable identities must be unique")
        if len(fingerprints) != len(set(fingerprints)):
            raise InstallerValidationError("disk device fingerprints must be unique")
        device_ids = [device.stable_id.casefold() for device in devices]
        if len(device_ids) != len(set(device_ids)):
            raise InstallerValidationError("device stable identities must be unique")

    @classmethod
    def from_mapping(cls, value: object) -> HardwareInventory:
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "snapshot_id",
                    "hardware_fingerprint",
                    "architecture",
                    "usable_ram_bytes",
                    "disks",
                    "devices",
                    "captured_at",
                }
            ),
            field="inventory",
        )
        raw_disks = data["disks"]
        raw_devices = data["devices"]
        if not isinstance(raw_disks, (list, tuple)) or not isinstance(
            raw_devices, (list, tuple)
        ):
            raise InstallerValidationError("inventory disks and devices must be arrays")
        return cls(
            snapshot_id=data["snapshot_id"],  # type: ignore[arg-type]
            hardware_fingerprint=data["hardware_fingerprint"],  # type: ignore[arg-type]
            architecture=data["architecture"],  # type: ignore[arg-type]
            usable_ram_bytes=data["usable_ram_bytes"],  # type: ignore[arg-type]
            disks=tuple(DiskRecord.from_mapping(item) for item in raw_disks),
            devices=tuple(HardwareDevice.from_mapping(item) for item in raw_devices),
            captured_at=_parse_datetime(data["captured_at"], "captured_at"),
        )

    def disk(self, stable_id: str) -> DiskRecord | None:
        requested = _stable_disk_id(stable_id).casefold()
        return next((disk for disk in self.disks if disk.stable_id.casefold() == requested), None)

    def state_payload(self) -> dict[str, object]:
        """Return hardware state without per-scan metadata."""

        return {
            "architecture": self.architecture,
            "devices": [item.canonical_payload() for item in sorted(self.devices, key=lambda x: x.stable_id)],
            "disks": [item.canonical_payload() for item in sorted(self.disks, key=lambda x: x.stable_id)],
            "hardware_fingerprint": self.hardware_fingerprint,
            "usable_ram_bytes": self.usable_ram_bytes,
        }

    @property
    def state_sha256(self) -> str:
        return _canonical_digest(self.state_payload())


@dataclass(frozen=True, slots=True)
class PartitionSpec:
    purpose: str
    label: str
    filesystem: str
    size_bytes: int

    def __post_init__(self) -> None:
        if self.purpose not in {"boot", "system", "recovery", "models", "data", "swap"}:
            raise InstallerValidationError("partition purpose is not supported")
        _identifier(self.label, "partition label")
        if self.filesystem not in {"fat32", "ext4", "btrfs", "xfs", "swap", "raw"}:
            raise InstallerValidationError("partition filesystem is not supported")
        size = _u64(self.size_bytes, "partition size_bytes", positive=True)
        if size % INSTALL_ALIGNMENT_BYTES:
            raise InstallerValidationError("partition size_bytes must be MiB aligned")

    @classmethod
    def from_mapping(cls, value: object) -> PartitionSpec:
        data = _strict_mapping(
            value,
            required=frozenset({"purpose", "label", "filesystem", "size_bytes"}),
            field="partition",
        )
        return cls(
            purpose=data["purpose"],  # type: ignore[arg-type]
            label=data["label"],  # type: ignore[arg-type]
            filesystem=data["filesystem"],  # type: ignore[arg-type]
            size_bytes=data["size_bytes"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class EditionSpec:
    edition_id: str
    policy_version: int
    payload_sha256: str
    release_sha256: str
    supported_architectures: tuple[str, ...]
    minimum_ram_bytes: int
    partitions: tuple[PartitionSpec, ...]
    required_device_classes: tuple[str, ...] = ()
    minimum_accelerator_memory_bytes: int = 0
    allow_degraded_devices: bool = False

    def __post_init__(self) -> None:
        _identifier(self.edition_id, "edition_id")
        _u64(self.policy_version, "policy_version", positive=True)
        _sha256(self.payload_sha256, "payload_sha256")
        _sha256(self.release_sha256, "release_sha256")
        if not isinstance(self.supported_architectures, (list, tuple)):
            raise InstallerValidationError("supported_architectures must be an array")
        architectures = tuple(_token(item, "supported architecture") for item in self.supported_architectures)
        if not architectures or len(architectures) != len(set(architectures)):
            raise InstallerValidationError("supported_architectures must be non-empty and unique")
        partitions = _typed_items(self.partitions, PartitionSpec, "partitions")
        if not isinstance(self.required_device_classes, (list, tuple)):
            raise InstallerValidationError("required_device_classes must be an array")
        required_classes = tuple(
            _token(item, "required device class") for item in self.required_device_classes
        )
        if len(required_classes) != len(set(required_classes)):
            raise InstallerValidationError("required_device_classes must be unique")
        purposes = [partition.purpose for partition in partitions]
        if len(purposes) != len(set(purposes)):
            raise InstallerValidationError("partition purposes must be unique")
        required_purposes = {"boot", "system", "recovery", "models"}
        if not required_purposes.issubset(purposes):
            raise InstallerValidationError(
                "edition partitions must include boot, system, recovery, and models"
            )
        labels = [partition.label.casefold() for partition in partitions]
        if len(labels) != len(set(labels)):
            raise InstallerValidationError("partition labels must be unique")
        _u64(self.minimum_ram_bytes, "minimum_ram_bytes", positive=True)
        _u64(
            self.minimum_accelerator_memory_bytes,
            "minimum_accelerator_memory_bytes",
        )
        _strict_bool(self.allow_degraded_devices, "allow_degraded_devices")
        _checked_sum(
            [
                LEADING_METADATA_BYTES,
                *(partition.size_bytes for partition in partitions),
                TRAILING_METADATA_BYTES,
            ],
            "edition disk capacity",
        )
        object.__setattr__(self, "supported_architectures", architectures)
        object.__setattr__(self, "partitions", partitions)
        object.__setattr__(self, "required_device_classes", required_classes)

    @classmethod
    def from_mapping(cls, value: object) -> EditionSpec:
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "edition_id",
                    "policy_version",
                    "payload_sha256",
                    "release_sha256",
                    "supported_architectures",
                    "minimum_ram_bytes",
                    "partitions",
                }
            ),
            optional=frozenset(
                {
                    "required_device_classes",
                    "minimum_accelerator_memory_bytes",
                    "allow_degraded_devices",
                }
            ),
            field="edition",
        )
        raw_partitions = data["partitions"]
        if not isinstance(raw_partitions, (list, tuple)):
            raise InstallerValidationError("edition partitions must be an array")
        return cls(
            edition_id=data["edition_id"],  # type: ignore[arg-type]
            policy_version=data["policy_version"],  # type: ignore[arg-type]
            payload_sha256=data["payload_sha256"],  # type: ignore[arg-type]
            release_sha256=data["release_sha256"],  # type: ignore[arg-type]
            supported_architectures=data["supported_architectures"],  # type: ignore[arg-type]
            minimum_ram_bytes=data["minimum_ram_bytes"],  # type: ignore[arg-type]
            partitions=tuple(PartitionSpec.from_mapping(item) for item in raw_partitions),
            required_device_classes=data.get("required_device_classes", ()),  # type: ignore[arg-type]
            minimum_accelerator_memory_bytes=data.get(
                "minimum_accelerator_memory_bytes", 0
            ),  # type: ignore[arg-type]
            allow_degraded_devices=data.get("allow_degraded_devices", False),  # type: ignore[arg-type]
        )

    @property
    def required_disk_bytes(self) -> int:
        return _checked_sum(
            [
                LEADING_METADATA_BYTES,
                *(partition.size_bytes for partition in self.partitions),
                TRAILING_METADATA_BYTES,
            ],
            "edition disk capacity",
        )


@dataclass(frozen=True, slots=True)
class HardwareAssessment:
    support_status: str
    reasons: tuple[str, ...]
    selected_disk_id: str
    selected_disk_capacity_bytes: int
    required_disk_bytes: int
    degraded_install_allowed: bool
    model_selection_assessment: ModelSelectionAssessment | None = None

    def __post_init__(self) -> None:
        if self.support_status not in {"certified", "degraded", "unsupported"}:
            raise InstallerValidationError("invalid hardware assessment status")
        _stable_disk_id(self.selected_disk_id, "selected_disk_id")
        _u64(self.selected_disk_capacity_bytes, "selected_disk_capacity_bytes")
        _u64(self.required_disk_bytes, "required_disk_bytes", positive=True)
        _strict_bool(self.degraded_install_allowed, "degraded_install_allowed")
        if self.model_selection_assessment is not None and not isinstance(
            self.model_selection_assessment, ModelSelectionAssessment
        ):
            raise InstallerValidationError(
                "model_selection_assessment must be a ModelSelectionAssessment"
            )

    @property
    def installation_permitted(self) -> bool:
        hardware_permitted = self.support_status == "certified" or (
            self.support_status == "degraded" and self.degraded_install_allowed
        )
        return hardware_permitted and (
            self.model_selection_assessment is None
            or self.model_selection_assessment.selection_permitted
        )


@dataclass(frozen=True, slots=True)
class MutationEffect:
    action: str
    partition_number: int | None
    start_bytes: int
    size_bytes: int
    purpose: str | None = None
    label: str | None = None
    filesystem: str | None = None

    def __post_init__(self) -> None:
        if self.action not in {"replace_partition_table", "create_partition"}:
            raise InstallerValidationError("unsupported mutation action")
        start = _u64(self.start_bytes, "mutation start_bytes")
        size = _u64(self.size_bytes, "mutation size_bytes", positive=True)
        if self.action == "replace_partition_table":
            if self.partition_number is not None or any(
                value is not None for value in (self.purpose, self.label, self.filesystem)
            ):
                raise InstallerValidationError("partition-table replacement has no partition fields")
            if start != 0:
                raise InstallerValidationError("partition-table replacement must start at byte zero")
            return
        number = _u64(self.partition_number, "partition_number", positive=True)
        if number > 128:
            raise InstallerValidationError("partition_number exceeds the safe contract limit")
        if start % INSTALL_ALIGNMENT_BYTES or size % INSTALL_ALIGNMENT_BYTES:
            raise InstallerValidationError("partition mutations must be MiB aligned")
        PartitionSpec(
            purpose=self.purpose,  # type: ignore[arg-type]
            label=self.label,  # type: ignore[arg-type]
            filesystem=self.filesystem,  # type: ignore[arg-type]
            size_bytes=size,
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "action": self.action,
            "filesystem": self.filesystem,
            "label": self.label,
            "partition_number": self.partition_number,
            "purpose": self.purpose,
            "size_bytes": self.size_bytes,
            "start_bytes": self.start_bytes,
        }


@dataclass(frozen=True, slots=True)
class InstallationPlan:
    schema_version: int
    issuer_id: str
    contract_policy_version: int
    edition_id: str
    edition_policy_version: int
    payload_sha256: str
    release_sha256: str
    hardware_fingerprint: str
    architecture: str
    inventory_snapshot_id: str
    inventory_captured_at: datetime
    inventory_state_sha256: str
    selected_disk: DiskRecord
    required_disk_bytes: int
    effects: tuple[MutationEffect, ...]
    created_at: datetime
    model_selection: ModelSelection | None = None

    def __post_init__(self) -> None:
        if self.schema_version not in {1, 2} or isinstance(self.schema_version, bool):
            raise InstallerValidationError("installation plan schema_version must be 1 or 2")
        if self.schema_version == 1 and self.model_selection is not None:
            raise InstallerValidationError(
                "schema-version-1 installation plans cannot bind model selection"
            )
        if self.schema_version == 2 and not isinstance(
            self.model_selection, ModelSelection
        ):
            raise InstallerValidationError(
                "schema-version-2 installation plans require model selection"
            )
        _identifier(self.issuer_id, "issuer_id")
        _u64(self.contract_policy_version, "contract_policy_version", positive=True)
        _identifier(self.edition_id, "edition_id")
        _u64(self.edition_policy_version, "edition_policy_version", positive=True)
        _sha256(self.payload_sha256, "payload_sha256")
        _sha256(self.release_sha256, "release_sha256")
        _sha256(self.hardware_fingerprint, "hardware_fingerprint")
        _token(self.architecture, "architecture")
        _identifier(self.inventory_snapshot_id, "inventory_snapshot_id")
        object.__setattr__(
            self,
            "inventory_captured_at",
            _aware_utc(self.inventory_captured_at, "inventory_captured_at"),
        )
        _sha256(self.inventory_state_sha256, "inventory_state_sha256")
        if not isinstance(self.selected_disk, DiskRecord):
            raise InstallerValidationError("selected_disk must be a DiskRecord")
        required = _u64(self.required_disk_bytes, "required_disk_bytes", positive=True)
        effects = _typed_items(self.effects, MutationEffect, "effects")
        object.__setattr__(self, "effects", effects)
        object.__setattr__(self, "created_at", _aware_utc(self.created_at, "created_at"))
        if len(effects) < 2 or effects[0].action != "replace_partition_table":
            raise InstallerValidationError(
                "plan must replace the table and create at least one partition"
            )
        if effects[0].size_bytes != self.selected_disk.capacity_bytes:
            raise InstallerValidationError("table replacement must bind the full selected disk")
        cursor = LEADING_METADATA_BYTES
        for expected_number, effect in enumerate(effects[1:], start=1):
            if effect.action != "create_partition":
                raise InstallerValidationError("only the first effect may replace the table")
            if effect.partition_number != expected_number or effect.start_bytes != cursor:
                raise InstallerValidationError("partition effects must be contiguous and ordered")
            cursor = _checked_sum([cursor, effect.size_bytes], "partition end")
        calculated_required = _checked_sum(
            [cursor, TRAILING_METADATA_BYTES], "required disk capacity"
        )
        if calculated_required != required:
            raise InstallerValidationError("required_disk_bytes does not match the exact effects")
        if required > self.selected_disk.capacity_bytes:
            raise InstallerValidationError("plan effects exceed selected disk capacity")

    def canonical_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "architecture": self.architecture,
            "contract_policy_version": self.contract_policy_version,
            "created_at": _canonical_datetime(self.created_at),
            "edition_id": self.edition_id,
            "edition_policy_version": self.edition_policy_version,
            "effects": [effect.canonical_payload() for effect in self.effects],
            "hardware_fingerprint": self.hardware_fingerprint,
            "inventory_captured_at": _canonical_datetime(self.inventory_captured_at),
            "inventory_snapshot_id": self.inventory_snapshot_id,
            "inventory_state_sha256": self.inventory_state_sha256,
            "issuer_id": self.issuer_id,
            "payload_sha256": self.payload_sha256,
            "release_sha256": self.release_sha256,
            "required_disk_bytes": self.required_disk_bytes,
            "schema_version": self.schema_version,
            "selected_disk": self.selected_disk.canonical_payload(),
        }
        if self.schema_version == 2:
            if self.model_selection is None:  # Defensive narrowing after validation.
                raise InstallerValidationError(
                    "schema-version-2 plan lost its model selection"
                )
            payload["model_selection"] = self.model_selection.canonical_payload()
        return payload

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PreflightResult:
    assessment: HardwareAssessment
    plan: InstallationPlan

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, HardwareAssessment) or not isinstance(
            self.plan, InstallationPlan
        ):
            raise InstallerValidationError("preflight result contains invalid contracts")
        if not self.assessment.installation_permitted:
            raise InstallerValidationError("a denied assessment cannot contain a plan")


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Authenticated product identity and the authority state it observed."""

    principal_id: str
    session_id: str
    authority_generation: int

    def __post_init__(self) -> None:
        _identifier(self.principal_id, "principal_id")
        _identifier(self.session_id, "session_id")
        _u64(self.authority_generation, "authority_generation", positive=True)


@dataclass(frozen=True, slots=True)
class InstallationConfirmation:
    confirmation_id: str
    plan_digest: str
    disk_stable_id: str
    disk_identity_sha256: str
    authorization: AuthorizationContext
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.confirmation_id, "confirmation_id")
        _sha256(self.plan_digest, "plan_digest")
        _stable_disk_id(self.disk_stable_id, "disk_stable_id")
        _sha256(self.disk_identity_sha256, "disk_identity_sha256")
        if not isinstance(self.authorization, AuthorizationContext):
            raise InstallerValidationError("authorization must be an AuthorizationContext")
        issued = _aware_utc(self.issued_at, "issued_at")
        expires = _aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise InstallerValidationError("confirmation expires_at must be after issued_at")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)


@dataclass(frozen=True, slots=True)
class VerifiedDeviceCapability:
    """Opaque binder result that keeps device identity stable through execution."""

    capability_id: str
    plan_digest: str
    disk_stable_id: str
    disk_identity_sha256: str
    inventory_snapshot_id: str
    opaque_handle: object

    def __post_init__(self) -> None:
        _identifier(self.capability_id, "capability_id")
        _sha256(self.plan_digest, "plan_digest")
        _stable_disk_id(self.disk_stable_id, "disk_stable_id")
        _sha256(self.disk_identity_sha256, "disk_identity_sha256")
        _identifier(self.inventory_snapshot_id, "inventory_snapshot_id")
        if self.opaque_handle is None or isinstance(
            self.opaque_handle, (str, bytes, bytearray, int, float, bool)
        ) or hasattr(self.opaque_handle, "__fspath__"):
            raise InstallerValidationError(
                "opaque_handle must be a non-path device capability object"
            )


@dataclass(frozen=True, slots=True)
class InstallationAttempt:
    """Durable fail-closed marker written before the executor is entered."""

    plan_digest: str
    confirmation_id: str
    capability_id: str
    authorization: AuthorizationContext
    state: str
    started_at: datetime
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _sha256(self.plan_digest, "plan_digest")
        _identifier(self.confirmation_id, "confirmation_id")
        _identifier(self.capability_id, "capability_id")
        if not isinstance(self.authorization, AuthorizationContext):
            raise InstallerValidationError("authorization must be an AuthorizationContext")
        if self.state not in {"in_doubt", "completed"}:
            raise InstallerValidationError("attempt state must be in_doubt or completed")
        started = _aware_utc(self.started_at, "started_at")
        object.__setattr__(self, "started_at", started)
        if self.completed_at is not None:
            completed = _aware_utc(self.completed_at, "completed_at")
            if self.state != "completed" or completed < started:
                raise InstallerValidationError("completed attempt timestamps are inconsistent")
            object.__setattr__(self, "completed_at", completed)
        elif self.state == "completed":
            raise InstallerValidationError("completed attempt requires completed_at")


class EffectAuthorizer(Protocol):
    """Adapter that checks session activity and returns current authority generation."""

    def __call__(
        self, authorization: AuthorizationContext, activity: str
    ) -> int: ...


class DeviceCapabilityBinder(Protocol):
    """Resolve, exclusively lock, and retain the exact device for execution.

    A platform implementation must re-identify the opened device, reject
    aliases or replacements, and keep the opaque handle and exclusive lock
    valid until the injected executor returns.
    """

    def __call__(
        self, plan: InstallationPlan, inventory: HardwareInventory
    ) -> VerifiedDeviceCapability: ...


class AttemptJournal(Protocol):
    """Durable journal; ``begin`` must atomically create only when absent."""

    def load(self, plan_digest: str) -> InstallationAttempt | None: ...

    def begin(self, attempt: InstallationAttempt) -> bool: ...

    def complete(
        self, plan_digest: str, confirmation_id: str, completed_at: datetime
    ) -> None: ...


class InstallerContract:
    """Thread-safe preflight, confirmation, and one-shot execution boundary."""

    def __init__(
        self,
        *,
        issuer_id: str,
        contract_policy_version: int,
        effect_authorizer: EffectAuthorizer,
        device_binder: DeviceCapabilityBinder,
        attempt_journal: AttemptJournal,
        clock: Callable[[], datetime] | None = None,
        inventory_max_age_seconds: int = 300,
        confirmation_max_lifetime_seconds: int = 120,
    ) -> None:
        self._issuer_id = _identifier(issuer_id, "issuer_id")
        self._contract_policy_version = _u64(
            contract_policy_version, "contract_policy_version", positive=True
        )
        if not callable(effect_authorizer) or not callable(device_binder):
            raise InstallerValidationError(
                "effect_authorizer and device_binder must be callable"
            )
        if any(
            not callable(getattr(attempt_journal, method, None))
            for method in ("load", "begin", "complete")
        ):
            raise InstallerValidationError("attempt_journal does not implement its contract")
        self._effect_authorizer = effect_authorizer
        self._device_binder = device_binder
        self._attempt_journal = attempt_journal
        self._clock = clock or (lambda: datetime.now(UTC))
        self._inventory_max_age_seconds = _u64(
            inventory_max_age_seconds, "inventory_max_age_seconds", positive=True
        )
        self._confirmation_max_lifetime_seconds = _u64(
            confirmation_max_lifetime_seconds,
            "confirmation_max_lifetime_seconds",
            positive=True,
        )
        self._issued_plans: dict[str, InstallationPlan] = {}
        self._issued_confirmations: dict[str, InstallationConfirmation] = {}
        self._lock = threading.RLock()

    def assess(
        self,
        inventory: HardwareInventory,
        edition: EditionSpec,
        *,
        selected_disk_id: str,
        model_catalog: ModelProfileCatalog | None = None,
        model_hardware: ModelHardwareSnapshot | None = None,
        selected_model_profile_id: str | None = None,
    ) -> HardwareAssessment:
        if not isinstance(inventory, HardwareInventory):
            raise InstallerValidationError("inventory must be a HardwareInventory")
        if not isinstance(edition, EditionSpec):
            raise InstallerValidationError("edition must be an EditionSpec")
        selected_disk_id = _stable_disk_id(selected_disk_id, "selected_disk_id")
        model_inputs = (model_catalog, model_hardware, selected_model_profile_id)
        if any(value is not None for value in model_inputs) and not all(
            value is not None for value in model_inputs
        ):
            raise InstallerValidationError(
                "model_catalog, model_hardware, and selected_model_profile_id "
                "must be supplied together"
            )
        if model_catalog is not None and not isinstance(
            model_catalog, ModelProfileCatalog
        ):
            raise InstallerValidationError(
                "model_catalog must be a ModelProfileCatalog"
            )
        if model_hardware is not None and not isinstance(
            model_hardware, ModelHardwareSnapshot
        ):
            raise InstallerValidationError(
                "model_hardware must be a ModelHardwareSnapshot"
            )
        disk = inventory.disk(selected_disk_id)
        reasons: list[str] = []
        unsupported = False
        degraded = False

        if inventory.architecture not in edition.supported_architectures:
            unsupported = True
            reasons.append("architecture:unsupported")
        if inventory.usable_ram_bytes < edition.minimum_ram_bytes:
            unsupported = True
            reasons.append("memory:insufficient")

        required_classes = set(edition.required_device_classes)
        if edition.minimum_accelerator_memory_bytes:
            required_classes.add("accelerator")
        for required_class in sorted(required_classes):
            minimum_memory = (
                edition.minimum_accelerator_memory_bytes
                if required_class == "accelerator"
                else 0
            )
            candidates = [
                device
                for device in inventory.devices
                if device.device_class == required_class
                and device.memory_bytes >= minimum_memory
            ]
            if not candidates or all(
                device.support_status == "unsupported" for device in candidates
            ):
                unsupported = True
                reason = (
                    "accelerator-memory:insufficient-or-unsupported"
                    if minimum_memory
                    else f"device:{required_class}:unsupported-or-missing"
                )
                reasons.append(reason)
            elif not any(device.support_status == "certified" for device in candidates):
                degraded = True
                reasons.append(f"device:{required_class}:degraded")

        model_assessment: ModelSelectionAssessment | None = None
        if model_catalog is not None and model_hardware is not None:
            try:
                model_assessment = assess_model_selection(
                    model_catalog,
                    model_hardware,
                    profile_id=selected_model_profile_id,  # type: ignore[arg-type]
                )
            except ModelSelectionError as exc:
                raise InstallerValidationError(
                    "model selection inputs are invalid"
                ) from exc
            if not model_assessment.selection_permitted:
                unsupported = True
                reasons.extend(
                    f"model-selection:{reason}"
                    for reason in model_assessment.reasons
                )

        capacity = 0
        if disk is None:
            unsupported = True
            reasons.append("disk:not-found")
        else:
            capacity = disk.capacity_bytes
            if disk.read_only:
                unsupported = True
                reasons.append("disk:read-only")
            if disk.capacity_bytes < edition.required_disk_bytes:
                unsupported = True
                reasons.append("disk:insufficient-capacity")
            if any(partition.size_bytes % disk.logical_sector_bytes for partition in edition.partitions):
                unsupported = True
                reasons.append("disk:partition-sector-misalignment")

        status = "unsupported" if unsupported else "degraded" if degraded else "certified"
        return HardwareAssessment(
            support_status=status,
            reasons=tuple(reasons),
            selected_disk_id=selected_disk_id,
            selected_disk_capacity_bytes=capacity,
            required_disk_bytes=edition.required_disk_bytes,
            degraded_install_allowed=edition.allow_degraded_devices,
            model_selection_assessment=model_assessment,
        )

    def preflight(
        self,
        inventory: HardwareInventory,
        edition: EditionSpec,
        *,
        selected_disk_id: str,
        model_catalog: ModelProfileCatalog | None = None,
        model_hardware: ModelHardwareSnapshot | None = None,
        selected_model_profile_id: str | None = None,
    ) -> PreflightResult:
        now = self._now()
        self._require_fresh(inventory, now)
        assessment = self.assess(
            inventory,
            edition,
            selected_disk_id=selected_disk_id,
            model_catalog=model_catalog,
            model_hardware=model_hardware,
            selected_model_profile_id=selected_model_profile_id,
        )
        if not assessment.installation_permitted:
            raise PreflightDenied(assessment)
        disk = inventory.disk(selected_disk_id)
        if disk is None:  # Kept explicit for type narrowing and fail-closed behavior.
            raise PreflightDenied(assessment)

        model_selection: ModelSelection | None = None
        if model_catalog is not None and model_hardware is not None:
            try:
                model_selection = select_model_profile(
                    model_catalog,
                    model_hardware,
                    profile_id=selected_model_profile_id,  # type: ignore[arg-type]
                )
            except ModelSelectionDenied as exc:
                raise PreflightDenied(assessment) from exc
            except ModelSelectionError as exc:
                raise InstallerValidationError(
                    "model selection inputs are invalid"
                ) from exc

        effects: list[MutationEffect] = [
            MutationEffect(
                action="replace_partition_table",
                partition_number=None,
                start_bytes=0,
                size_bytes=disk.capacity_bytes,
            )
        ]
        cursor = LEADING_METADATA_BYTES
        for number, partition in enumerate(edition.partitions, start=1):
            effects.append(
                MutationEffect(
                    action="create_partition",
                    partition_number=number,
                    start_bytes=cursor,
                    size_bytes=partition.size_bytes,
                    purpose=partition.purpose,
                    label=partition.label,
                    filesystem=partition.filesystem,
                )
            )
            cursor = _checked_sum([cursor, partition.size_bytes], "partition end")
        plan = InstallationPlan(
            schema_version=2 if model_selection is not None else 1,
            issuer_id=self._issuer_id,
            contract_policy_version=self._contract_policy_version,
            edition_id=edition.edition_id,
            edition_policy_version=edition.policy_version,
            payload_sha256=edition.payload_sha256,
            release_sha256=edition.release_sha256,
            hardware_fingerprint=inventory.hardware_fingerprint,
            architecture=inventory.architecture,
            inventory_snapshot_id=inventory.snapshot_id,
            inventory_captured_at=inventory.captured_at,
            inventory_state_sha256=inventory.state_sha256,
            selected_disk=disk,
            required_disk_bytes=edition.required_disk_bytes,
            effects=tuple(effects),
            created_at=now,
            model_selection=model_selection,
        )
        with self._lock:
            self._issued_plans[plan.digest] = plan
        return PreflightResult(assessment=assessment, plan=plan)

    def confirm(
        self,
        plan: InstallationPlan,
        *,
        confirmation_id: str,
        authorization: AuthorizationContext,
        acknowledged_plan_digest: str,
        acknowledged_disk_id: str,
        acknowledged_disk_identity_sha256: str,
        expires_at: datetime,
    ) -> InstallationConfirmation:
        if not isinstance(plan, InstallationPlan):
            raise InstallerValidationError("plan must be an InstallationPlan")
        if not isinstance(authorization, AuthorizationContext):
            raise InstallerValidationError("authorization must be an AuthorizationContext")
        self._require_issued_plan(plan)
        confirmation_id = _identifier(confirmation_id, "confirmation_id")
        _sha256(acknowledged_plan_digest, "acknowledged_plan_digest")
        _stable_disk_id(acknowledged_disk_id, "acknowledged_disk_id")
        _sha256(
            acknowledged_disk_identity_sha256,
            "acknowledged_disk_identity_sha256",
        )
        if acknowledged_plan_digest != plan.digest:
            raise ConfirmationDenied("acknowledged plan digest does not match the exact plan")
        if acknowledged_disk_id != plan.selected_disk.stable_id:
            raise ConfirmationDenied("acknowledged disk identity does not match the plan")
        if acknowledged_disk_identity_sha256 != plan.selected_disk.identity_sha256:
            raise ConfirmationDenied("acknowledged disk state does not match the plan")

        self._authorize(authorization, CONFIRM_INSTALL_ACTIVITY)
        now = self._now()
        expires = _aware_utc(expires_at, "expires_at")
        lifetime = (expires - now).total_seconds()
        if lifetime <= 0 or lifetime > self._confirmation_max_lifetime_seconds:
            raise ConfirmationDenied("confirmation expiry is invalid or exceeds its maximum lifetime")
        if self._load_attempt(plan.digest) is not None:
            raise ConfirmationReplay("the plan already has durable attempt state")
        confirmation = InstallationConfirmation(
            confirmation_id=confirmation_id,
            plan_digest=plan.digest,
            disk_stable_id=plan.selected_disk.stable_id,
            disk_identity_sha256=plan.selected_disk.identity_sha256,
            authorization=authorization,
            issued_at=now,
            expires_at=expires,
        )
        with self._lock:
            if confirmation_id in self._issued_confirmations:
                raise ConfirmationDenied("confirmation_id has already been issued")
            self._issued_confirmations[confirmation_id] = confirmation
        return confirmation

    def execute(
        self,
        plan: InstallationPlan,
        confirmation: InstallationConfirmation,
        *,
        authorization: AuthorizationContext,
        inventory_provider: Callable[[], HardwareInventory],
        executor: Callable[[InstallationPlan, VerifiedDeviceCapability], T],
        model_catalog_provider: Callable[[], ModelProfileCatalog] | None = None,
        model_hardware_provider: Callable[[], ModelHardwareSnapshot] | None = None,
    ) -> T:
        if not isinstance(plan, InstallationPlan):
            raise InstallerValidationError("plan must be an InstallationPlan")
        if not isinstance(confirmation, InstallationConfirmation):
            raise InstallerValidationError(
                "confirmation must be an InstallationConfirmation"
            )
        if not isinstance(authorization, AuthorizationContext):
            raise InstallerValidationError("authorization must be an AuthorizationContext")
        if not callable(inventory_provider) or not callable(executor):
            raise InstallerValidationError("inventory_provider and executor must be callable")
        if plan.schema_version == 2:
            if not callable(model_catalog_provider) or not callable(
                model_hardware_provider
            ):
                raise InstallerValidationError(
                    "schema-version-2 execution requires model catalog and hardware providers"
                )
        elif model_catalog_provider is not None or model_hardware_provider is not None:
            raise InstallerValidationError(
                "schema-version-1 execution cannot accept model revalidation providers"
            )
        self._require_issued_plan(plan)
        with self._lock:
            recorded = self._issued_confirmations.get(confirmation.confirmation_id)
            if recorded != confirmation:
                raise ConfirmationDenied("confirmation was not issued by this contract")
            self._require_confirmation_binding(plan, confirmation)
            if authorization != confirmation.authorization:
                raise ConfirmationDenied(
                    "execution principal, session, or authority generation changed"
                )
        if self._load_attempt(plan.digest) is not None:
            raise ConfirmationReplay("installation plan already has durable attempt state")
        self._require_confirmation_time(confirmation, self._now())

        fresh = inventory_provider()
        discovery_completed_at = self._now()
        if not isinstance(fresh, HardwareInventory):
            raise InventoryChanged("inventory provider returned an invalid snapshot")
        self._require_confirmation_time(confirmation, discovery_completed_at)
        self._require_fresh(fresh, discovery_completed_at)
        self._require_revalidated(plan, fresh)

        if plan.schema_version == 2:
            # Callability was checked above; these assertions are only for type narrowing.
            if model_catalog_provider is None or model_hardware_provider is None:
                raise InstallerValidationError(
                    "schema-version-2 model providers are missing"
                )
            fresh_model_catalog = model_catalog_provider()
            fresh_model_hardware = model_hardware_provider()
            model_discovery_completed_at = self._now()
            self._require_confirmation_time(
                confirmation, model_discovery_completed_at
            )
            self._require_fresh(fresh, model_discovery_completed_at)
            self._require_model_revalidated(
                plan, fresh_model_catalog, fresh_model_hardware
            )

        capability = self._device_binder(plan, fresh)
        self._require_capability_binding(plan, fresh, capability)
        attempt = InstallationAttempt(
            plan_digest=plan.digest,
            confirmation_id=confirmation.confirmation_id,
            capability_id=capability.capability_id,
            authorization=authorization,
            state="in_doubt",
            started_at=self._now(),
        )
        if self._attempt_journal.begin(attempt) is not True:
            raise ConfirmationReplay("installation attempt was already recorded")
        if self._load_attempt(plan.digest) != attempt:
            raise ConfirmationDenied("attempt journal did not durably retain the exact marker")

        # These are deliberately the final checks.  A slow inventory provider,
        # capability binder, or journal cannot extend a confirmation or snapshot
        # past its freshness window, and authorization is checked at effect time.
        if plan.schema_version == 2:
            if model_catalog_provider is None or model_hardware_provider is None:
                raise InstallerValidationError(
                    "schema-version-2 model providers are missing"
                )
            effect_model_catalog = model_catalog_provider()
            effect_model_hardware = model_hardware_provider()
            model_effect_time = self._now()
            self._require_confirmation_time(confirmation, model_effect_time)
            self._require_fresh(fresh, model_effect_time)
            self._require_model_revalidated(
                plan, effect_model_catalog, effect_model_hardware
            )

        self._authorize(authorization, EXECUTE_INSTALL_ACTIVITY)
        execution_time = self._now()
        self._require_confirmation_time(confirmation, execution_time)
        self._require_fresh(fresh, execution_time)

        result = executor(plan, capability)
        completed_at = self._now()
        self._attempt_journal.complete(
            plan.digest, confirmation.confirmation_id, completed_at
        )
        completed = self._load_attempt(plan.digest)
        if (
            completed is None
            or completed.state != "completed"
            or completed.confirmation_id != confirmation.confirmation_id
        ):
            raise ConfirmationDenied("attempt journal did not durably retain completion")
        return result

    def _require_issued_plan(self, plan: InstallationPlan) -> None:
        if (
            plan.issuer_id != self._issuer_id
            or plan.contract_policy_version != self._contract_policy_version
        ):
            raise ConfirmationDenied("plan issuer or contract policy version is not current")
        with self._lock:
            if self._issued_plans.get(plan.digest) is not plan:
                raise ConfirmationDenied("plan was not issued by this contract instance")

    def _load_attempt(self, plan_digest: str) -> InstallationAttempt | None:
        attempt = self._attempt_journal.load(plan_digest)
        if attempt is None:
            return None
        if not isinstance(attempt, InstallationAttempt) or attempt.plan_digest != plan_digest:
            raise ConfirmationDenied("attempt journal returned invalid state")
        return attempt

    def _authorize(self, authorization: AuthorizationContext, activity: str) -> None:
        observed = self._effect_authorizer(authorization, activity)
        try:
            generation = _u64(observed, "observed authority generation", positive=True)
        except InstallerValidationError as exc:
            raise ConfirmationDenied("authorizer returned an invalid generation") from exc
        if generation != authorization.authority_generation:
            raise ConfirmationDenied("authority generation changed")

    @staticmethod
    def _require_confirmation_time(
        confirmation: InstallationConfirmation, now: datetime
    ) -> None:
        if now < confirmation.issued_at or now >= confirmation.expires_at:
            raise ConfirmationDenied("confirmation is not currently valid")

    @staticmethod
    def _require_capability_binding(
        plan: InstallationPlan,
        fresh: HardwareInventory,
        capability: object,
    ) -> None:
        if not isinstance(capability, VerifiedDeviceCapability):
            raise InventoryChanged("device binder returned no verified capability")
        if (
            capability.plan_digest != plan.digest
            or capability.disk_stable_id != plan.selected_disk.stable_id
            or capability.disk_identity_sha256 != plan.selected_disk.identity_sha256
            or capability.inventory_snapshot_id != fresh.snapshot_id
        ):
            raise InventoryChanged("bound device capability indicates an identity swap")

    def _require_confirmation_binding(
        self, plan: InstallationPlan, confirmation: InstallationConfirmation
    ) -> None:
        if confirmation.plan_digest != plan.digest:
            raise ConfirmationDenied("confirmation is bound to another plan")
        if confirmation.disk_stable_id != plan.selected_disk.stable_id:
            raise ConfirmationDenied("confirmation is bound to another disk")
        if confirmation.disk_identity_sha256 != plan.selected_disk.identity_sha256:
            raise ConfirmationDenied("confirmation is bound to another disk state")

    def _require_revalidated(
        self, plan: InstallationPlan, fresh: HardwareInventory
    ) -> None:
        if fresh.snapshot_id == plan.inventory_snapshot_id:
            raise InventoryChanged("execution requires a new inventory snapshot")
        if fresh.captured_at <= plan.inventory_captured_at:
            raise InventoryChanged("revalidation snapshot is not newer than preflight")
        if fresh.hardware_fingerprint != plan.hardware_fingerprint:
            raise InventoryChanged("hardware identity changed after confirmation")
        if fresh.state_sha256 != plan.inventory_state_sha256:
            raise InventoryChanged("hardware or disk state changed after confirmation")
        disk = fresh.disk(plan.selected_disk.stable_id)
        if disk is None or disk.identity_sha256 != plan.selected_disk.identity_sha256:
            raise InventoryChanged("selected disk identity changed after confirmation")

    @staticmethod
    def _require_model_revalidated(
        plan: InstallationPlan,
        fresh_catalog: object,
        fresh_hardware: object,
    ) -> None:
        if plan.schema_version != 2 or not isinstance(
            plan.model_selection, ModelSelection
        ):
            raise InventoryChanged("installation plan has no model selection binding")
        if not isinstance(fresh_catalog, ModelProfileCatalog):
            raise InventoryChanged("model catalog provider returned an invalid catalog")
        if not isinstance(fresh_hardware, ModelHardwareSnapshot):
            raise InventoryChanged("model hardware provider returned an invalid snapshot")
        try:
            fresh_selection = select_model_profile(
                fresh_catalog,
                fresh_hardware,
                profile_id=plan.model_selection.profile_id,
            )
        except (ModelSelectionDenied, ModelSelectionError) as exc:
            raise InventoryChanged(
                "selected model profile no longer passes resource or policy checks"
            ) from exc
        if fresh_selection.digest != plan.model_selection.digest:
            raise InventoryChanged(
                "model catalog, profile, runtime, accelerator, or resources changed "
                "after confirmation"
            )

    def _require_fresh(self, inventory: HardwareInventory, now: datetime) -> None:
        if not isinstance(inventory, HardwareInventory):
            raise InstallerValidationError("inventory must be a HardwareInventory")
        age = (now - inventory.captured_at).total_seconds()
        if age < 0:
            raise InventoryStale("inventory captured_at is in the future")
        if age > self._inventory_max_age_seconds:
            raise InventoryStale("inventory snapshot is stale")

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), "clock result")


__all__ = [
    "AttemptJournal",
    "AuthorizationContext",
    "ConfirmationDenied",
    "ConfirmationReplay",
    "DeviceCapabilityBinder",
    "DiskRecord",
    "EditionSpec",
    "EffectAuthorizer",
    "HardwareAssessment",
    "HardwareDevice",
    "HardwareInventory",
    "InstallationAttempt",
    "InstallationConfirmation",
    "InstallationPlan",
    "InstallerContract",
    "InstallerError",
    "InstallerValidationError",
    "InventoryChanged",
    "InventoryStale",
    "MutationEffect",
    "PartitionSpec",
    "PreflightDenied",
    "PreflightResult",
    "VerifiedDeviceCapability",
]
