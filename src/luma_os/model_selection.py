"""Immutable install-time model selection and hardware-fit contracts.

The contract is deliberately platform neutral.  Trusted adapters provide an
effective hardware snapshot (for example, the WSL guest limit rather than the
Windows host's physical memory), while a release-controlled catalog describes
exact model/runtime/resource profiles.  Selection never downloads a model,
probes hardware, starts a runtime, or silently substitutes another profile.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import TypeAlias

from .model_pack import ModelManifest, ModelPackState, ModelPackVerification


JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
MANUAL_ONLY_PROFILE_ID = "manual-only"
MAX_CATALOG_PROFILES = 256


class ModelSelectionError(ValueError):
    """A model-selection contract is malformed or internally inconsistent."""


class ModelSelectionDenied(RuntimeError):
    """The requested profile did not pass the immutable hardware assessment."""

    def __init__(self, assessment: "ModelSelectionAssessment") -> None:
        self.assessment = assessment
        reasons = ", ".join(assessment.reasons) or "selection denied"
        super().__init__(f"model profile {assessment.requested_profile_id!r} denied: {reasons}")


def _strict_mapping(
    value: object,
    *,
    required: frozenset[str],
    field: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ModelSelectionError(f"{field} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ModelSelectionError(f"{field} keys must be strings")
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        unexpected = sorted(keys - required)
        raise ModelSelectionError(
            f"{field} fields differ; missing={missing}, unexpected={unexpected}"
        )
    return value


def _ascii_text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ModelSelectionError(f"{field} must be non-empty trimmed printable ASCII")
    return value


def _u64(value: object, field: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ModelSelectionError(f"{field} must be an integer")
    if value < 0 or value > JSON_SAFE_INTEGER_MAX or (positive and value == 0):
        qualifier = "positive " if positive else ""
        raise ModelSelectionError(
            f"{field} must be a {qualifier}unsigned JSON-safe integer"
        )
    return value


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ModelSelectionError(f"{field} must be a boolean")
    return value


def _sha256(value: object, field: str) -> str:
    digest = _ascii_text(value, field, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ModelSelectionError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ModelSelectionError(f"{field} must be an array")
    digests = tuple(_sha256(item, f"{field}[]") for item in value)
    if len(digests) != len(set(digests)):
        raise ModelSelectionError(f"{field} must not contain duplicates")
    return tuple(sorted(digests))


@dataclass(frozen=True, slots=True, order=True)
class ResourceReservation:
    """One phase-specific reservation against a logical memory domain."""

    domain: str
    bytes: int

    def __post_init__(self) -> None:
        if self.domain not in {"accelerator", "host"}:
            raise ModelSelectionError("reservation domain must be accelerator or host")
        _u64(self.bytes, "reservation bytes", positive=True)

    @classmethod
    def from_mapping(cls, value: object) -> "ResourceReservation":
        data = _strict_mapping(
            value,
            required=frozenset({"domain", "bytes"}),
            field="reservation",
        )
        return cls(domain=data["domain"], bytes=data["bytes"])  # type: ignore[arg-type]

    def canonical_payload(self) -> dict[str, object]:
        return {"bytes": self.bytes, "domain": self.domain}


def _reservations(
    value: object,
    field: str,
) -> tuple[ResourceReservation, ...]:
    if not isinstance(value, (list, tuple)):
        raise ModelSelectionError(f"{field} must be an array")
    items = tuple(
        item if isinstance(item, ResourceReservation) else ResourceReservation.from_mapping(item)
        for item in value
    )
    if not items:
        raise ModelSelectionError(f"{field} must not be empty")
    domains = [item.domain for item in items]
    if len(domains) != len(set(domains)):
        raise ModelSelectionError(f"{field} must use each domain at most once")
    return tuple(sorted(items))


@dataclass(frozen=True, slots=True)
class ManualOnlyProfile:
    """Explicit model-free operation; this is never an implicit fallback."""

    profile_id: str = MANUAL_ONLY_PROFILE_ID
    kind: str = "manual-only"
    remote_fallback: bool = False

    def __post_init__(self) -> None:
        if self.profile_id != MANUAL_ONLY_PROFILE_ID:
            raise ModelSelectionError("manual-only profile_id must be manual-only")
        if self.kind != "manual-only":
            raise ModelSelectionError("manual-only profile kind must be manual-only")
        if self.remote_fallback is not False:
            raise ModelSelectionError("remote fallback must be false")

    @classmethod
    def from_mapping(cls, value: object) -> "ManualOnlyProfile":
        data = _strict_mapping(
            value,
            required=frozenset({"kind", "profile_id", "remote_fallback"}),
            field="manual-only profile",
        )
        _strict_bool(data["remote_fallback"], "remote_fallback")
        return cls(
            profile_id=data["profile_id"],  # type: ignore[arg-type]
            kind=data["kind"],  # type: ignore[arg-type]
            remote_fallback=data["remote_fallback"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "profile_id": self.profile_id,
            "remote_fallback": self.remote_fallback,
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class ModelProfile:
    """One exact model, runtime, context, execution-mode, and resource tuple."""

    profile_id: str
    parameter_total: int
    parameter_active_min: int
    parameter_active_max: int
    model_pack_manifest_sha256: str
    runtime_tuple_sha256: str
    install_bytes: int
    storage_peak_bytes: int
    minimum_host_ram_bytes: int
    minimum_accelerator_memory_bytes: int
    load_reservations: tuple[ResourceReservation, ...]
    serve_reservations: tuple[ResourceReservation, ...]
    context_tokens: int
    execution_mode: str
    availability: str
    verification_state: str
    development_state: str
    certification_state: str
    remote_fallback: bool = False
    kind: str = "model"

    def __post_init__(self) -> None:
        _ascii_text(self.profile_id, "profile_id")
        if self.profile_id == MANUAL_ONLY_PROFILE_ID:
            raise ModelSelectionError("model profile_id cannot be manual-only")
        if self.kind != "model":
            raise ModelSelectionError("model profile kind must be model")

        total = _u64(self.parameter_total, "parameter_total", positive=True)
        active_min = _u64(self.parameter_active_min, "parameter_active_min", positive=True)
        active_max = _u64(self.parameter_active_max, "parameter_active_max", positive=True)
        if active_min > active_max or active_max > total:
            raise ModelSelectionError(
                "active parameter bounds must satisfy min <= max <= total"
            )
        _sha256(self.model_pack_manifest_sha256, "model_pack_manifest_sha256")
        _sha256(self.runtime_tuple_sha256, "runtime_tuple_sha256")
        install = _u64(self.install_bytes, "install_bytes", positive=True)
        storage_peak = _u64(self.storage_peak_bytes, "storage_peak_bytes", positive=True)
        if storage_peak < install:
            raise ModelSelectionError("storage_peak_bytes must include install_bytes")
        host_minimum = _u64(
            self.minimum_host_ram_bytes,
            "minimum_host_ram_bytes",
            positive=True,
        )
        accelerator_minimum = _u64(
            self.minimum_accelerator_memory_bytes,
            "minimum_accelerator_memory_bytes",
        )
        _u64(self.context_tokens, "context_tokens", positive=True)

        load = _reservations(self.load_reservations, "load_reservations")
        serve = _reservations(self.serve_reservations, "serve_reservations")
        object.__setattr__(self, "load_reservations", load)
        object.__setattr__(self, "serve_reservations", serve)

        load_map = {item.domain: item.bytes for item in load}
        serve_map = {item.domain: item.bytes for item in serve}
        if "host" not in load_map or "host" not in serve_map:
            raise ModelSelectionError("load and serve reservations must include host memory")
        if host_minimum < max(load_map["host"], serve_map["host"]):
            raise ModelSelectionError(
                "minimum_host_ram_bytes must cover load and serve host reservations"
            )

        if self.execution_mode not in {"cpu", "cuda"}:
            raise ModelSelectionError("execution_mode must be cpu or cuda")
        if self.execution_mode == "cpu":
            if accelerator_minimum or "accelerator" in load_map or "accelerator" in serve_map:
                raise ModelSelectionError(
                    "CPU profiles cannot require accelerator memory or reservations"
                )
        else:
            if accelerator_minimum == 0:
                raise ModelSelectionError("CUDA profiles require accelerator memory")
            if "accelerator" not in load_map or "accelerator" not in serve_map:
                raise ModelSelectionError(
                    "CUDA load and serve reservations must include accelerator memory"
                )
            if accelerator_minimum < max(
                load_map["accelerator"], serve_map["accelerator"]
            ):
                raise ModelSelectionError(
                    "minimum_accelerator_memory_bytes must cover accelerator reservations"
                )

        if self.availability not in {"available", "unavailable"}:
            raise ModelSelectionError("availability must be available or unavailable")
        if self.verification_state not in {"verified", "unverified"}:
            raise ModelSelectionError(
                "verification_state must be verified or unverified"
            )
        if self.development_state not in {"untested", "development-tested"}:
            raise ModelSelectionError(
                "development_state must be untested or development-tested"
            )
        if self.certification_state not in {
            "not-certified",
            "execution-certified",
            "interactive-certified",
        }:
            raise ModelSelectionError("unsupported certification_state")
        if self.verification_state != "verified" and self.certification_state != "not-certified":
            raise ModelSelectionError("an unverified profile cannot be certified")
        if self.development_state != "development-tested" and self.certification_state != "not-certified":
            raise ModelSelectionError("an untested profile cannot be certified")
        if self.remote_fallback is not False:
            raise ModelSelectionError("remote fallback must be false")

    @classmethod
    def from_mapping(cls, value: object) -> "ModelProfile":
        fields = frozenset(
            {
                "availability",
                "certification_state",
                "context_tokens",
                "development_state",
                "execution_mode",
                "install_bytes",
                "kind",
                "load_reservations",
                "minimum_accelerator_memory_bytes",
                "minimum_host_ram_bytes",
                "model_pack_manifest_sha256",
                "parameter_active_max",
                "parameter_active_min",
                "parameter_total",
                "profile_id",
                "remote_fallback",
                "runtime_tuple_sha256",
                "serve_reservations",
                "storage_peak_bytes",
                "verification_state",
            }
        )
        data = _strict_mapping(value, required=fields, field="model profile")
        _strict_bool(data["remote_fallback"], "remote_fallback")
        return cls(
            profile_id=data["profile_id"],  # type: ignore[arg-type]
            parameter_total=data["parameter_total"],  # type: ignore[arg-type]
            parameter_active_min=data["parameter_active_min"],  # type: ignore[arg-type]
            parameter_active_max=data["parameter_active_max"],  # type: ignore[arg-type]
            model_pack_manifest_sha256=data["model_pack_manifest_sha256"],  # type: ignore[arg-type]
            runtime_tuple_sha256=data["runtime_tuple_sha256"],  # type: ignore[arg-type]
            install_bytes=data["install_bytes"],  # type: ignore[arg-type]
            storage_peak_bytes=data["storage_peak_bytes"],  # type: ignore[arg-type]
            minimum_host_ram_bytes=data["minimum_host_ram_bytes"],  # type: ignore[arg-type]
            minimum_accelerator_memory_bytes=data[
                "minimum_accelerator_memory_bytes"
            ],  # type: ignore[arg-type]
            load_reservations=_reservations(
                data["load_reservations"], "load_reservations"
            ),
            serve_reservations=_reservations(
                data["serve_reservations"], "serve_reservations"
            ),
            context_tokens=data["context_tokens"],  # type: ignore[arg-type]
            execution_mode=data["execution_mode"],  # type: ignore[arg-type]
            availability=data["availability"],  # type: ignore[arg-type]
            verification_state=data["verification_state"],  # type: ignore[arg-type]
            development_state=data["development_state"],  # type: ignore[arg-type]
            certification_state=data["certification_state"],  # type: ignore[arg-type]
            remote_fallback=data["remote_fallback"],  # type: ignore[arg-type]
            kind=data["kind"],  # type: ignore[arg-type]
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "availability": self.availability,
            "certification_state": self.certification_state,
            "context_tokens": self.context_tokens,
            "development_state": self.development_state,
            "execution_mode": self.execution_mode,
            "install_bytes": self.install_bytes,
            "kind": self.kind,
            "load_reservations": [item.canonical_payload() for item in self.load_reservations],
            "minimum_accelerator_memory_bytes": self.minimum_accelerator_memory_bytes,
            "minimum_host_ram_bytes": self.minimum_host_ram_bytes,
            "model_pack_manifest_sha256": self.model_pack_manifest_sha256,
            "parameter_active_max": self.parameter_active_max,
            "parameter_active_min": self.parameter_active_min,
            "parameter_total": self.parameter_total,
            "profile_id": self.profile_id,
            "remote_fallback": self.remote_fallback,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "serve_reservations": [item.canonical_payload() for item in self.serve_reservations],
            "storage_peak_bytes": self.storage_peak_bytes,
            "verification_state": self.verification_state,
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


SelectableProfile: TypeAlias = ManualOnlyProfile | ModelProfile


@dataclass(frozen=True, slots=True)
class ModelProfileCatalog:
    schema_version: int
    catalog_id: str
    profiles: tuple[SelectableProfile, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise ModelSelectionError("catalog schema_version must be 1")
        _ascii_text(self.catalog_id, "catalog_id")
        if not isinstance(self.profiles, (list, tuple)):
            raise ModelSelectionError("profiles must be an array")
        profiles = tuple(self.profiles)
        if not profiles or any(
            not isinstance(item, (ManualOnlyProfile, ModelProfile)) for item in profiles
        ):
            raise ModelSelectionError("profiles must contain selectable profile contracts")
        if len(profiles) > MAX_CATALOG_PROFILES:
            raise ModelSelectionError(
                f"catalog cannot contain more than {MAX_CATALOG_PROFILES} profiles"
            )
        profile_ids = [item.profile_id for item in profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ModelSelectionError("profile IDs must be unique")
        if sum(isinstance(item, ManualOnlyProfile) for item in profiles) != 1:
            raise ModelSelectionError("catalog must contain exactly one manual-only profile")
        object.__setattr__(self, "profiles", tuple(sorted(profiles, key=lambda item: item.profile_id)))

    @classmethod
    def from_mapping(cls, value: object) -> "ModelProfileCatalog":
        data = _strict_mapping(
            value,
            required=frozenset({"schema_version", "catalog_id", "profiles"}),
            field="model profile catalog",
        )
        raw_profiles = data["profiles"]
        if not isinstance(raw_profiles, list):
            raise ModelSelectionError("profiles must be an array")
        if len(raw_profiles) > MAX_CATALOG_PROFILES:
            raise ModelSelectionError(
                f"catalog cannot contain more than {MAX_CATALOG_PROFILES} profiles"
            )
        profiles: list[SelectableProfile] = []
        for index, raw_profile in enumerate(raw_profiles):
            if not isinstance(raw_profile, Mapping):
                raise ModelSelectionError(f"profiles[{index}] must be an object")
            kind = raw_profile.get("kind")
            if kind == "manual-only":
                profiles.append(ManualOnlyProfile.from_mapping(raw_profile))
            elif kind == "model":
                profiles.append(ModelProfile.from_mapping(raw_profile))
            else:
                raise ModelSelectionError(f"profiles[{index}].kind is unsupported")
        return cls(
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            catalog_id=data["catalog_id"],  # type: ignore[arg-type]
            profiles=tuple(profiles),
        )

    def profile(self, profile_id: str) -> SelectableProfile | None:
        requested = _ascii_text(profile_id, "profile_id")
        return next((item for item in self.profiles if item.profile_id == requested), None)

    def canonical_payload(self) -> dict[str, object]:
        return {
            "catalog_id": self.catalog_id,
            "profiles": [item.canonical_payload() for item in self.profiles],
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())

    @property
    def profiles_by_id(self) -> Mapping[str, SelectableProfile]:
        return MappingProxyType({item.profile_id: item for item in self.profiles})


@dataclass(frozen=True, slots=True)
class AcceleratorDevice:
    device_id: str
    memory_bytes: int
    supported_runtime_tuple_digests: tuple[str, ...]
    verified: bool
    available: bool

    def __post_init__(self) -> None:
        _ascii_text(self.device_id, "accelerator device_id")
        _u64(self.memory_bytes, "accelerator memory_bytes")
        object.__setattr__(
            self,
            "supported_runtime_tuple_digests",
            _digest_tuple(
                self.supported_runtime_tuple_digests,
                "accelerator supported_runtime_tuple_digests",
            ),
        )
        _strict_bool(self.verified, "accelerator verified")
        _strict_bool(self.available, "accelerator available")

    @classmethod
    def from_mapping(cls, value: object) -> "AcceleratorDevice":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "available",
                    "device_id",
                    "memory_bytes",
                    "supported_runtime_tuple_digests",
                    "verified",
                }
            ),
            field="accelerator",
        )
        return cls(
            device_id=data["device_id"],  # type: ignore[arg-type]
            memory_bytes=data["memory_bytes"],  # type: ignore[arg-type]
            supported_runtime_tuple_digests=_digest_tuple(
                data["supported_runtime_tuple_digests"],
                "accelerator supported_runtime_tuple_digests",
            ),
            verified=_strict_bool(data["verified"], "accelerator verified"),
            available=_strict_bool(data["available"], "accelerator available"),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "available": self.available,
            "device_id": self.device_id,
            "memory_bytes": self.memory_bytes,
            "supported_runtime_tuple_digests": list(self.supported_runtime_tuple_digests),
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class ModelHardwareSnapshot:
    """Effective capacity supplied by a trusted platform adapter.

    Swap is intentionally absent.  Virtualized environments must report their
    effective guest RAM and storage rather than adding host capacity.
    """

    effective_host_ram_bytes: int
    model_storage_bytes: int
    supported_runtime_tuple_digests: tuple[str, ...]
    accelerators: tuple[AcceleratorDevice, ...] = ()

    def __post_init__(self) -> None:
        _u64(self.effective_host_ram_bytes, "effective_host_ram_bytes")
        _u64(self.model_storage_bytes, "model_storage_bytes")
        object.__setattr__(
            self,
            "supported_runtime_tuple_digests",
            _digest_tuple(
                self.supported_runtime_tuple_digests,
                "supported_runtime_tuple_digests",
            ),
        )
        if not isinstance(self.accelerators, (list, tuple)):
            raise ModelSelectionError("accelerators must be an array")
        accelerators = tuple(self.accelerators)
        if any(not isinstance(item, AcceleratorDevice) for item in accelerators):
            raise ModelSelectionError("accelerators must contain accelerator contracts")
        device_ids = [item.device_id for item in accelerators]
        if len(device_ids) != len(set(device_ids)):
            raise ModelSelectionError("accelerator device IDs must be unique")
        object.__setattr__(
            self,
            "accelerators",
            tuple(sorted(accelerators, key=lambda item: item.device_id)),
        )

    @classmethod
    def from_mapping(cls, value: object) -> "ModelHardwareSnapshot":
        data = _strict_mapping(
            value,
            required=frozenset(
                {
                    "accelerators",
                    "effective_host_ram_bytes",
                    "model_storage_bytes",
                    "supported_runtime_tuple_digests",
                }
            ),
            field="hardware snapshot",
        )
        raw_accelerators = data["accelerators"]
        if not isinstance(raw_accelerators, list):
            raise ModelSelectionError("accelerators must be an array")
        return cls(
            effective_host_ram_bytes=data["effective_host_ram_bytes"],  # type: ignore[arg-type]
            model_storage_bytes=data["model_storage_bytes"],  # type: ignore[arg-type]
            supported_runtime_tuple_digests=_digest_tuple(
                data["supported_runtime_tuple_digests"],
                "supported_runtime_tuple_digests",
            ),
            accelerators=tuple(AcceleratorDevice.from_mapping(item) for item in raw_accelerators),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "accelerators": [item.canonical_payload() for item in self.accelerators],
            "effective_host_ram_bytes": self.effective_host_ram_bytes,
            "model_storage_bytes": self.model_storage_bytes,
            "supported_runtime_tuple_digests": list(
                self.supported_runtime_tuple_digests
            ),
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class ModelSelectionAssessment:
    requested_profile_id: str
    status: str
    reasons: tuple[str, ...]
    catalog_sha256: str
    hardware_snapshot_sha256: str
    profile_sha256: str | None
    execution_mode: str | None
    selected_accelerator_id: str | None

    def __post_init__(self) -> None:
        _ascii_text(self.requested_profile_id, "requested_profile_id")
        if self.status not in {"permitted", "denied"}:
            raise ModelSelectionError("assessment status must be permitted or denied")
        if not isinstance(self.reasons, tuple) or any(
            not isinstance(item, str) or not item for item in self.reasons
        ):
            raise ModelSelectionError("assessment reasons must be a tuple of reason codes")
        if len(self.reasons) != len(set(self.reasons)):
            raise ModelSelectionError("assessment reason codes must be unique")
        if (self.status == "permitted") != (not self.reasons):
            raise ModelSelectionError("permitted assessments have no denial reasons")
        _sha256(self.catalog_sha256, "catalog_sha256")
        _sha256(self.hardware_snapshot_sha256, "hardware_snapshot_sha256")
        if self.profile_sha256 is not None:
            _sha256(self.profile_sha256, "profile_sha256")
        if self.execution_mode not in {None, "manual-only", "cpu", "cuda"}:
            raise ModelSelectionError("assessment execution_mode is unsupported")
        if self.selected_accelerator_id is not None:
            _ascii_text(self.selected_accelerator_id, "selected_accelerator_id")
        if self.status == "permitted" and (
            self.profile_sha256 is None or self.execution_mode is None
        ):
            raise ModelSelectionError("permitted assessment must identify the exact profile")
        if (
            self.status == "permitted"
            and self.execution_mode == "cuda"
            and self.selected_accelerator_id is None
        ):
            raise ModelSelectionError(
                "permitted CUDA assessment must identify one accelerator"
            )
        if self.execution_mode != "cuda" and self.selected_accelerator_id is not None:
            raise ModelSelectionError("only CUDA assessment may select an accelerator")

    @property
    def selection_permitted(self) -> bool:
        return self.status == "permitted"


@dataclass(frozen=True, slots=True)
class ModelSelection:
    profile_id: str
    profile_sha256: str
    catalog_sha256: str
    hardware_snapshot_sha256: str
    execution_mode: str
    selected_accelerator_id: str | None
    model_pack_manifest_sha256: str | None
    runtime_tuple_sha256: str | None

    def __post_init__(self) -> None:
        _ascii_text(self.profile_id, "profile_id")
        _sha256(self.profile_sha256, "profile_sha256")
        _sha256(self.catalog_sha256, "catalog_sha256")
        _sha256(self.hardware_snapshot_sha256, "hardware_snapshot_sha256")
        if self.execution_mode not in {"manual-only", "cpu", "cuda"}:
            raise ModelSelectionError("selection execution_mode is unsupported")
        if self.execution_mode == "manual-only":
            if (
                self.profile_id != MANUAL_ONLY_PROFILE_ID
                or self.selected_accelerator_id is not None
                or self.model_pack_manifest_sha256 is not None
                or self.runtime_tuple_sha256 is not None
            ):
                raise ModelSelectionError("manual-only selection cannot bind model assets")
        else:
            _sha256(self.model_pack_manifest_sha256, "model_pack_manifest_sha256")
            _sha256(self.runtime_tuple_sha256, "runtime_tuple_sha256")
            if self.execution_mode == "cuda":
                _ascii_text(self.selected_accelerator_id, "selected_accelerator_id")
            elif self.selected_accelerator_id is not None:
                raise ModelSelectionError("CPU selection cannot bind an accelerator")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "catalog_sha256": self.catalog_sha256,
            "execution_mode": self.execution_mode,
            "hardware_snapshot_sha256": self.hardware_snapshot_sha256,
            "model_pack_manifest_sha256": self.model_pack_manifest_sha256,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "selected_accelerator_id": self.selected_accelerator_id,
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


def model_profile_from_verified_pack(
    manifest: ModelManifest,
    verification: ModelPackVerification,
    *,
    installation_profile_id: str,
    storage_peak_bytes: int,
    load_reservations: tuple[ResourceReservation, ...],
    serve_reservations: tuple[ResourceReservation, ...],
    context_tokens: int,
    development_state: str,
    availability: str = "available",
) -> ModelProfile:
    """Build a selectable profile whose identity cannot drift from a verified pack."""

    if not isinstance(manifest, ModelManifest):
        raise ModelSelectionError("manifest must be a ModelManifest")
    if not isinstance(verification, ModelPackVerification):
        raise ModelSelectionError("verification must be a ModelPackVerification")
    if verification.state < ModelPackState.LOADABLE:
        raise ModelSelectionError("model pack must be loadable before catalog binding")
    manifest_sha256 = hashlib.sha256(manifest.canonical_bytes).hexdigest()
    if (
        verification.pack_id != manifest.pack_id
        or verification.pack_version != manifest.pack_version
        or verification.manifest_sha256 != manifest_sha256
    ):
        raise ModelSelectionError("verification does not bind the exact model manifest")

    requested_profile_id = _ascii_text(
        installation_profile_id, "installation_profile_id"
    )
    pack_profile = next(
        (
            item
            for item in manifest.installation_profiles
            if item.profile_id == requested_profile_id
        ),
        None,
    )
    if pack_profile is None:
        raise ModelSelectionError("installation profile is not declared by the model pack")
    if verification.runtime_tuple.digest != pack_profile.runtime_tuple_sha256:
        raise ModelSelectionError(
            "verification runtime tuple differs from the installation profile"
        )
    requested_context = _u64(context_tokens, "context_tokens", positive=True)
    if requested_context > min(
        pack_profile.maximum_context_tokens,
        manifest.maximum_context_tokens,
    ):
        raise ModelSelectionError("context_tokens exceeds the verified pack profile")

    certification_state = {
        ModelPackState.LOADABLE: "not-certified",
        ModelPackState.EXECUTION_CERTIFIED: "execution-certified",
        ModelPackState.INTERACTIVE_CERTIFIED: "interactive-certified",
    }.get(verification.state)
    if certification_state is None:
        raise ModelSelectionError("unsupported model-pack lifecycle state")

    return ModelProfile(
        profile_id=pack_profile.profile_id,
        parameter_total=manifest.total_parameters,
        parameter_active_min=manifest.active_parameters_min,
        parameter_active_max=manifest.active_parameters_max,
        model_pack_manifest_sha256=manifest_sha256,
        runtime_tuple_sha256=pack_profile.runtime_tuple_sha256,
        install_bytes=pack_profile.minimum_model_storage_bytes,
        storage_peak_bytes=storage_peak_bytes,
        minimum_host_ram_bytes=pack_profile.minimum_host_ram_bytes,
        minimum_accelerator_memory_bytes=(
            pack_profile.minimum_accelerator_memory_bytes
        ),
        load_reservations=load_reservations,
        serve_reservations=serve_reservations,
        context_tokens=requested_context,
        execution_mode=pack_profile.execution_mode,
        availability=availability,
        verification_state="verified",
        development_state=development_state,
        certification_state=certification_state,
    )


def assess_model_selection(
    catalog: ModelProfileCatalog,
    hardware: ModelHardwareSnapshot,
    *,
    profile_id: str,
) -> ModelSelectionAssessment:
    """Assess exactly the requested profile without trying another profile."""

    if not isinstance(catalog, ModelProfileCatalog):
        raise ModelSelectionError("catalog must be a ModelProfileCatalog")
    if not isinstance(hardware, ModelHardwareSnapshot):
        raise ModelSelectionError("hardware must be a ModelHardwareSnapshot")
    requested = _ascii_text(profile_id, "profile_id")
    profile = catalog.profile(requested)
    common = {
        "requested_profile_id": requested,
        "catalog_sha256": catalog.digest,
        "hardware_snapshot_sha256": hardware.digest,
    }
    if profile is None:
        return ModelSelectionAssessment(
            **common,
            status="denied",
            reasons=("profile:unknown",),
            profile_sha256=None,
            execution_mode=None,
            selected_accelerator_id=None,
        )
    if isinstance(profile, ManualOnlyProfile):
        return ModelSelectionAssessment(
            **common,
            status="permitted",
            reasons=(),
            profile_sha256=profile.digest,
            execution_mode="manual-only",
            selected_accelerator_id=None,
        )
    if profile.availability != "available":
        return ModelSelectionAssessment(
            **common,
            status="denied",
            reasons=("profile:unavailable",),
            profile_sha256=profile.digest,
            execution_mode=profile.execution_mode,
            selected_accelerator_id=None,
        )
    if profile.verification_state != "verified":
        return ModelSelectionAssessment(
            **common,
            status="denied",
            reasons=("profile:unverified",),
            profile_sha256=profile.digest,
            execution_mode=profile.execution_mode,
            selected_accelerator_id=None,
        )

    reasons: list[str] = []
    if profile.runtime_tuple_sha256 not in hardware.supported_runtime_tuple_digests:
        reasons.append("runtime-tuple:unsupported")
    if hardware.effective_host_ram_bytes < profile.minimum_host_ram_bytes:
        reasons.append("host-memory:insufficient")
    if hardware.model_storage_bytes < profile.storage_peak_bytes:
        reasons.append("model-storage:insufficient")

    selected_accelerator_id: str | None = None
    if profile.execution_mode == "cuda":
        qualifying = [
            device
            for device in hardware.accelerators
            if device.available
            and device.verified
            and profile.runtime_tuple_sha256
            in device.supported_runtime_tuple_digests
            and device.memory_bytes >= profile.minimum_accelerator_memory_bytes
        ]
        if qualifying:
            selected_accelerator_id = qualifying[0].device_id
        else:
            available = [device for device in hardware.accelerators if device.available]
            verified = [device for device in available if device.verified]
            compatible = [
                device
                for device in verified
                if profile.runtime_tuple_sha256
                in device.supported_runtime_tuple_digests
            ]
            if not available:
                reasons.append("accelerator:unavailable")
            elif not verified:
                reasons.append("accelerator:unverified")
            elif not compatible:
                reasons.append("accelerator:runtime-unsupported")
            elif all(
                device.memory_bytes < profile.minimum_accelerator_memory_bytes
                for device in compatible
            ):
                reasons.append("accelerator-memory:insufficient")
            reasons.append("accelerator:no-single-qualifying-device")

    return ModelSelectionAssessment(
        **common,
        status="denied" if reasons else "permitted",
        reasons=tuple(reasons),
        profile_sha256=profile.digest,
        execution_mode=profile.execution_mode,
        selected_accelerator_id=selected_accelerator_id,
    )


def select_model_profile(
    catalog: ModelProfileCatalog,
    hardware: ModelHardwareSnapshot,
    *,
    profile_id: str,
) -> ModelSelection:
    """Return a digest-bound selection or raise with the complete assessment."""

    assessment = assess_model_selection(catalog, hardware, profile_id=profile_id)
    if not assessment.selection_permitted:
        raise ModelSelectionDenied(assessment)
    profile = catalog.profile(profile_id)
    if profile is None:  # Defensive narrowing; a permitted unknown profile is impossible.
        raise ModelSelectionError("permitted assessment lost its catalog profile")
    if isinstance(profile, ManualOnlyProfile):
        model_pack_manifest_sha256 = None
        runtime_tuple_sha256 = None
    else:
        model_pack_manifest_sha256 = profile.model_pack_manifest_sha256
        runtime_tuple_sha256 = profile.runtime_tuple_sha256
    return ModelSelection(
        profile_id=profile.profile_id,
        profile_sha256=profile.digest,
        catalog_sha256=catalog.digest,
        hardware_snapshot_sha256=hardware.digest,
        execution_mode=assessment.execution_mode or "manual-only",
        selected_accelerator_id=assessment.selected_accelerator_id,
        model_pack_manifest_sha256=model_pack_manifest_sha256,
        runtime_tuple_sha256=runtime_tuple_sha256,
    )
