"""Fail-closed contracts for a finite privileged-helper boundary.

This reference module performs no privileged operation. Platform adapters
provide authenticated peer evidence, trusted attestors, a durable bounded
journal, and a typed idempotent executor. Callers cannot select commands,
executables, argv, shells, registry keys, or raw device handles.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
import hashlib
import json
import re
from typing import Callable, Mapping, Protocol, TypeAlias
import uuid


MAX_REQUEST_BYTES = 64 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_VALUES = 256


class HelperError(RuntimeError):
    """Base class for expected helper failures."""


class HelperValidationError(ValueError):
    """Untrusted input violates the closed wire contract."""


class DenialReason(str, Enum):
    PEER_AUTHENTICATION_FAILED = "peer_authentication_failed"
    PEER_IDENTITY_MISMATCH = "peer_identity_mismatch"
    REQUEST_EXPIRED = "request_expired"
    REQUEST_STALE = "request_stale"
    REQUEST_FROM_FUTURE = "request_from_future"
    REPLAY_CONFLICT = "replay_conflict"
    REQUEST_IN_PROGRESS = "request_in_progress"
    FAILED_UNKNOWN = "failed_unknown"
    REENTRANT_DISPATCH = "reentrant_dispatch"
    JOURNAL_UNAVAILABLE = "journal_unavailable"
    CONFINEMENT_NOT_ENFORCING = "confinement_not_enforcing"
    CONFINEMENT_UNTRUSTED = "confinement_untrusted"
    CONFINEMENT_INVALIDATED = "confinement_invalidated"
    CONFINEMENT_BINDING_MISMATCH = "confinement_binding_mismatch"
    NATIVE_CODE_CONFINEMENT_REQUIRED = "native_code_confinement_required"
    AUTHORITY_DENIED = "authority_denied"
    AUTHORITY_REVOKED = "authority_revoked"
    AUTHORITY_STALE = "authority_stale"
    AUTHORITY_EXPIRED = "authority_expired"
    AUTHORITY_BINDING_MISMATCH = "authority_binding_mismatch"
    DEVICE_BINDING_DENIED = "device_binding_denied"
    DEVICE_BINDING_MISMATCH = "device_binding_mismatch"
    DEVICE_CAPABILITY_EXPIRED = "device_capability_expired"
    DRIVER_CERTIFICATE_MISMATCH = "driver_certificate_mismatch"
    DRIVER_CERTIFICATE_EXPIRED = "driver_certificate_expired"
    DRIVER_CERTIFICATE_UNTRUSTED = "driver_certificate_untrusted"
    DRIVER_CERTIFICATE_INVALIDATED = "driver_certificate_invalidated"


class HelperDenied(HelperError):
    def __init__(self, reason: DenialReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class HelperReplayConflict(HelperDenied):
    """A request identifier was reused with different authenticated bytes."""


class HelperExecutionError(HelperError):
    """An effect failed or its outcome could not be safely established."""


class HelperAction(str, Enum):
    ACTIVATE_STAGED_RELEASE = "activate_staged_release"
    SET_RECOVERY_BOOT_ONCE = "set_recovery_boot_once"
    ASSIGN_MODEL_DEVICE = "assign_model_device"
    START_GENERATED_WORKER = "start_generated_worker"


class PeerTransport(str, Enum):
    UNIX_PEER_CREDENTIALS = "unix_peer_credentials"
    WINDOWS_NAMED_PIPE = "windows_named_pipe"


class ConfinementMode(str, Enum):
    PROCESS_SANDBOX = "process_sandbox"
    KVM_MICROVM = "kvm_microvm"
    QUALIFIED_CONSTRAINED_RUNTIME = "qualified_constrained_runtime"


class GeneratedCodeKind(str, Enum):
    NATIVE = "native"
    CONSTRAINED_BYTECODE = "constrained_bytecode"


class RecoverySlot(str, Enum):
    A = "A"
    B = "B"


class DeviceType(str, Enum):
    NVIDIA_COMPUTE = "nvidia_compute"
    NVIDIA_CONTROL = "nvidia_control"
    NVIDIA_UVM = "nvidia_uvm"
    DRM_RENDER = "drm_render"
    AMD_KFD = "amd_kfd"


class JournalState(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED_UNKNOWN = "failed_unknown"


class ReconciliationState(str, Enum):
    NOT_FOUND = "not_found"
    COMPLETED = "completed"
    UNKNOWN = "unknown"


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_DEVICE_PATH = {
    DeviceType.NVIDIA_COMPUTE: re.compile(r"/dev/nvidia[0-9]+\Z"),
    DeviceType.NVIDIA_CONTROL: re.compile(r"/dev/nvidiactl\Z"),
    DeviceType.NVIDIA_UVM: re.compile(r"/dev/nvidia-uvm\Z"),
    DeviceType.DRM_RENDER: re.compile(r"/dev/dri/renderD[0-9]+\Z"),
    DeviceType.AMD_KFD: re.compile(r"/dev/kfd\Z"),
}


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise HelperValidationError(f"{field} is not a valid identifier")
    return value


def _version(value: object, field: str) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise HelperValidationError(f"{field} is not a valid version token")
    return value


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise HelperValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _signature(value: object, field: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != 128
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise HelperValidationError(f"{field} must be a lowercase 64-byte signature")
    return bytes.fromhex(value)


def _positive(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value < (1 << 63):
        raise HelperValidationError(f"{field} must be a positive integer")
    return value


def _nonnegative(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 31):
        raise HelperValidationError(f"{field} must be a non-negative integer")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise HelperValidationError(f"{field} must be a boolean")
    return value


def _aware(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HelperValidationError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise HelperValidationError(f"{field} must be canonical RFC3339 UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise HelperValidationError(f"{field} must be canonical RFC3339 UTC") from exc
    if _format_time(parsed) != value:
        raise HelperValidationError(f"{field} must round-trip as canonical RFC3339 UTC")
    return parsed


def _format_time(value: datetime) -> str:
    normalized = _aware(value, "time")
    if normalized.microsecond:
        raise HelperValidationError("wire times must have second resolution")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _enum(kind: type[Enum], value: object, field: str) -> Enum:
    if not isinstance(value, str):
        raise HelperValidationError(f"{field} is unsupported")
    try:
        return kind(value)
    except ValueError as exc:
        raise HelperValidationError(f"{field} is unsupported") from exc


def _expect(value: object, field: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise HelperValidationError(f"{field} must be an object")
    if set(value) != keys:
        raise HelperValidationError(
            f"{field} keys differ; missing={sorted(keys-set(value))}, "
            f"unknown={sorted(set(value)-keys)}"
        )
    return value


def _json_limits(root: object) -> None:
    stack = [(root, 1)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_VALUES:
            raise HelperValidationError("request JSON exceeds structural limits")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif not isinstance(value, (str, int, bool, type(None))):
            raise HelperValidationError("request contains an unsupported JSON value")


def _canonical(value: object) -> bytes:
    _json_limits(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise HelperValidationError("value is outside the canonical JSON domain") from exc


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HelperValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise HelperValidationError(f"unsupported JSON constant: {value}")


@dataclass(frozen=True, slots=True)
class AuthenticatedPeer:
    principal: str
    transport: PeerTransport
    transport_identity: str
    session_id: str
    credential_sha256: str
    authenticated: bool

    def __post_init__(self) -> None:
        _identifier(self.principal, "peer.principal")
        if not isinstance(self.transport, PeerTransport):
            raise HelperValidationError("peer.transport must be a PeerTransport")
        if (
            not isinstance(self.transport_identity, str)
            or not 1 <= len(self.transport_identity) <= 512
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.transport_identity)
        ):
            raise HelperValidationError("peer.transport_identity is invalid")
        _identifier(self.session_id, "peer.session_id")
        _digest(self.credential_sha256, "peer.credential_sha256")
        _boolean(self.authenticated, "peer.authenticated")

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(
            _canonical(
                {
                    "credential_sha256": self.credential_sha256,
                    "principal": self.principal,
                    "session_id": self.session_id,
                    "transport": self.transport.value,
                    "transport_identity": self.transport_identity,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ConfinementClaim:
    mode: ConfinementMode
    profile_id: str
    profile_version: int
    profile_sha256: str
    qualification_id: str
    signer_key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.mode, ConfinementMode):
            raise HelperValidationError("confinement mode is invalid")
        _identifier(self.profile_id, "confinement.profile_id")
        _positive(self.profile_version, "confinement.profile_version")
        _digest(self.profile_sha256, "confinement.profile_sha256")
        _identifier(self.qualification_id, "confinement.qualification_id")
        _identifier(self.signer_key_id, "confinement.signer_key_id")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise HelperValidationError("confinement.signature must be 64 bytes")


@dataclass(frozen=True, slots=True)
class DeviceSelector:
    device_type: DeviceType
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.device_type, DeviceType):
            raise HelperValidationError("device selector type is invalid")
        if (
            not isinstance(self.path, str)
            or "//" in self.path
            or "\\" in self.path
            or "/./" in self.path
            or "/../" in self.path
            or _DEVICE_PATH[self.device_type].fullmatch(self.path) is None
        ):
            raise HelperValidationError("device selector is not a canonical direct device path")


@dataclass(frozen=True, slots=True)
class DeviceAssignment:
    assignment_id: str
    worker_id: str
    selectors: tuple[DeviceSelector, ...]
    exclusive: bool
    generation: int

    def __post_init__(self) -> None:
        _identifier(self.assignment_id, "device_assignment.assignment_id")
        _identifier(self.worker_id, "device_assignment.worker_id")
        if not self.selectors or len(self.selectors) > 16:
            raise HelperValidationError("device assignment needs 1 to 16 selectors")
        order = tuple((item.device_type.value, item.path) for item in self.selectors)
        if not all(isinstance(item, DeviceSelector) for item in self.selectors) or order != tuple(
            sorted(set(order))
        ):
            raise HelperValidationError("device selectors must be valid, unique, and sorted")
        if self.exclusive is not True:
            raise HelperValidationError("device assignment must be exclusive")
        _positive(self.generation, "device_assignment.generation")


@dataclass(frozen=True, slots=True)
class DriverRuntimeCertificate:
    certificate_id: str
    device_identity_sha256s: tuple[str, ...]
    driver_name: str
    driver_version: str
    driver_module_sha256: str
    runtime_name: str
    runtime_version: str
    runtime_sha256: str
    qualification_id: str
    signer_key_id: str
    not_before: datetime
    not_after: datetime
    signature: bytes

    def __post_init__(self) -> None:
        for field in ("certificate_id", "driver_name", "runtime_name", "qualification_id", "signer_key_id"):
            _identifier(getattr(self, field), f"certificate.{field}")
        _version(self.driver_version, "certificate.driver_version")
        _version(self.runtime_version, "certificate.runtime_version")
        identities = tuple(_digest(item, "certificate.device_identity[]") for item in self.device_identity_sha256s)
        if not identities or identities != tuple(sorted(set(identities))):
            raise HelperValidationError("certificate device identities must be unique and sorted")
        object.__setattr__(self, "device_identity_sha256s", identities)
        _digest(self.driver_module_sha256, "certificate.driver_module_sha256")
        _digest(self.runtime_sha256, "certificate.runtime_sha256")
        start, end = _aware(self.not_before, "certificate.not_before"), _aware(
            self.not_after, "certificate.not_after"
        )
        if end <= start:
            raise HelperValidationError("certificate validity interval is empty")
        object.__setattr__(self, "not_before", start)
        object.__setattr__(self, "not_after", end)
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise HelperValidationError("certificate.signature must be 64 bytes")

    @property
    def signed_bytes(self) -> bytes:
        return _canonical(
            {
                "certificate_id": self.certificate_id,
                "device_identity_sha256s": list(self.device_identity_sha256s),
                "driver_module_sha256": self.driver_module_sha256,
                "driver_name": self.driver_name,
                "driver_version": self.driver_version,
                "not_after": _format_time(self.not_after),
                "not_before": _format_time(self.not_before),
                "qualification_id": self.qualification_id,
                "runtime_name": self.runtime_name,
                "runtime_sha256": self.runtime_sha256,
                "runtime_version": self.runtime_version,
                "signer_key_id": self.signer_key_id,
            }
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.signed_bytes + self.signature).hexdigest()


@dataclass(frozen=True, slots=True)
class ActivateReleaseParameters:
    release_sha256: str


@dataclass(frozen=True, slots=True)
class RecoveryBootParameters:
    slot: RecoverySlot


@dataclass(frozen=True, slots=True)
class AssignDeviceParameters:
    worker_id: str
    assignment_id: str


@dataclass(frozen=True, slots=True)
class StartGeneratedWorkerParameters:
    worker_id: str
    workload_id: str
    artifact_sha256: str
    code_kind: GeneratedCodeKind
    assignment_id: str | None


HelperParameters: TypeAlias = (
    ActivateReleaseParameters | RecoveryBootParameters | AssignDeviceParameters | StartGeneratedWorkerParameters
)


@dataclass(frozen=True, slots=True)
class HelperRequest:
    request_id: str
    subject: str
    peer_identity_sha256: str
    action: HelperAction
    issued_at: datetime
    deadline: datetime
    authority_id: str
    authority_generation: int
    parameters: HelperParameters
    confinement: ConfinementClaim
    device_assignment: DeviceAssignment | None
    driver_runtime_certificate: DriverRuntimeCertificate | None
    request_sha256: str

    @property
    def worker_id(self) -> str | None:
        return getattr(self.parameters, "worker_id", None)

    @property
    def artifact_sha256(self) -> str | None:
        return getattr(self.parameters, "artifact_sha256", None)

    @property
    def idempotency_key(self) -> str:
        return hashlib.sha256(
            f"luma-helper-v1:{self.request_id}:{self.request_sha256}".encode("ascii")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ConfinementAttestation:
    attestation_id: str
    request_sha256: str
    peer_identity_sha256: str
    action: HelperAction
    worker_id: str | None
    artifact_sha256: str | None
    mode: ConfinementMode
    profile_id: str
    profile_version: int
    profile_sha256: str
    enforcing: bool
    qualification_id: str
    attested_at: datetime
    valid_until: datetime
    signer_key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        _identifier(self.attestation_id, "attestation.attestation_id")
        _digest(self.request_sha256, "attestation.request_sha256")
        _digest(self.peer_identity_sha256, "attestation.peer_identity_sha256")
        if not isinstance(self.action, HelperAction) or not isinstance(self.mode, ConfinementMode):
            raise HelperValidationError("attestation enum is invalid")
        if self.worker_id is not None:
            _identifier(self.worker_id, "attestation.worker_id")
        if self.artifact_sha256 is not None:
            _digest(self.artifact_sha256, "attestation.artifact_sha256")
        _identifier(self.profile_id, "attestation.profile_id")
        _positive(self.profile_version, "attestation.profile_version")
        _digest(self.profile_sha256, "attestation.profile_sha256")
        _boolean(self.enforcing, "attestation.enforcing")
        _identifier(self.qualification_id, "attestation.qualification_id")
        start, end = _aware(self.attested_at, "attestation.attested_at"), _aware(
            self.valid_until, "attestation.valid_until"
        )
        if end <= start:
            raise HelperValidationError("attestation validity interval is empty")
        object.__setattr__(self, "attested_at", start)
        object.__setattr__(self, "valid_until", end)
        _identifier(self.signer_key_id, "attestation.signer_key_id")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise HelperValidationError("attestation.signature must be 64 bytes")

    @property
    def signed_bytes(self) -> bytes:
        return _canonical(
            {
                "action": self.action.value,
                "artifact_sha256": self.artifact_sha256,
                "attestation_id": self.attestation_id,
                "attested_at": _format_time(self.attested_at),
                "enforcing": self.enforcing,
                "mode": self.mode.value,
                "peer_identity_sha256": self.peer_identity_sha256,
                "profile_id": self.profile_id,
                "profile_sha256": self.profile_sha256,
                "profile_version": self.profile_version,
                "qualification_id": self.qualification_id,
                "request_sha256": self.request_sha256,
                "signer_key_id": self.signer_key_id,
                "valid_until": _format_time(self.valid_until),
                "worker_id": self.worker_id,
            }
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.signed_bytes + self.signature).hexdigest()


@dataclass(frozen=True, slots=True)
class BoundDevice:
    device_type: DeviceType
    major: int
    minor: int
    host_identity_sha256: str
    stable_identity_sha256: str
    safe_handle_token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.device_type, DeviceType):
            raise HelperValidationError("bound device type is invalid")
        _nonnegative(self.major, "bound_device.major")
        _nonnegative(self.minor, "bound_device.minor")
        _digest(self.host_identity_sha256, "bound_device.host_identity_sha256")
        expected = hashlib.sha256(
            _canonical(
                {
                    "device_type": self.device_type.value,
                    "host_identity_sha256": self.host_identity_sha256,
                    "major": self.major,
                    "minor": self.minor,
                }
            )
        ).hexdigest()
        if _digest(self.stable_identity_sha256, "bound_device.stable_identity_sha256") != expected:
            raise HelperValidationError("bound device stable identity is inconsistent")
        if not isinstance(self.safe_handle_token, str) or _HANDLE.fullmatch(self.safe_handle_token) is None:
            raise HelperValidationError("bound device safe handle token is invalid")


@dataclass(frozen=True, slots=True)
class DeviceCapability:
    capability_id: str
    request_sha256: str
    peer_identity_sha256: str
    assignment_id: str
    assignment_generation: int
    worker_id: str
    exclusive: bool
    devices: tuple[BoundDevice, ...]
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _identifier(self.capability_id, "device_capability.capability_id")
        _digest(self.request_sha256, "device_capability.request_sha256")
        _digest(self.peer_identity_sha256, "device_capability.peer_identity_sha256")
        _identifier(self.assignment_id, "device_capability.assignment_id")
        _positive(self.assignment_generation, "device_capability.assignment_generation")
        _identifier(self.worker_id, "device_capability.worker_id")
        if self.exclusive is not True or not self.devices or len(self.devices) > 16:
            raise HelperValidationError("device capability must be exclusive and non-empty")
        identities = tuple(item.stable_identity_sha256 for item in self.devices)
        if not all(isinstance(item, BoundDevice) for item in self.devices) or identities != tuple(
            sorted(set(identities))
        ):
            raise HelperValidationError("bound devices must be valid, unique, and identity-sorted")
        start, end = _aware(self.issued_at, "device_capability.issued_at"), _aware(
            self.valid_until, "device_capability.valid_until"
        )
        if end <= start:
            raise HelperValidationError("device capability validity interval is empty")
        object.__setattr__(self, "issued_at", start)
        object.__setattr__(self, "valid_until", end)

    @property
    def digest(self) -> str:
        devices = [
            {
                "device_type": item.device_type.value,
                "host_identity_sha256": item.host_identity_sha256,
                "major": item.major,
                "minor": item.minor,
                "safe_handle_token": item.safe_handle_token,
                "stable_identity_sha256": item.stable_identity_sha256,
            }
            for item in self.devices
        ]
        return hashlib.sha256(
            _canonical(
                {
                    "assignment_generation": self.assignment_generation,
                    "assignment_id": self.assignment_id,
                    "capability_id": self.capability_id,
                    "devices": devices,
                    "exclusive": self.exclusive,
                    "issued_at": _format_time(self.issued_at),
                    "peer_identity_sha256": self.peer_identity_sha256,
                    "request_sha256": self.request_sha256,
                    "valid_until": _format_time(self.valid_until),
                    "worker_id": self.worker_id,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    decision_id: str
    allowed: bool
    authority_id: str
    authority_generation: int
    subject: str
    peer_identity_sha256: str
    action: HelperAction
    request_sha256: str
    capability_sha256: str
    expires_at: datetime
    revoked: bool = False

    def __post_init__(self) -> None:
        _identifier(self.decision_id, "decision.decision_id")
        _boolean(self.allowed, "decision.allowed")
        _identifier(self.authority_id, "decision.authority_id")
        _positive(self.authority_generation, "decision.authority_generation")
        _identifier(self.subject, "decision.subject")
        _digest(self.peer_identity_sha256, "decision.peer_identity_sha256")
        if not isinstance(self.action, HelperAction):
            raise HelperValidationError("decision.action is invalid")
        _digest(self.request_sha256, "decision.request_sha256")
        _digest(self.capability_sha256, "decision.capability_sha256")
        object.__setattr__(self, "expires_at", _aware(self.expires_at, "decision.expires_at"))
        _boolean(self.revoked, "decision.revoked")


@dataclass(frozen=True, slots=True)
class AuthorizedEffect:
    request_id: str
    request_sha256: str
    idempotency_key: str
    subject: str
    action: HelperAction
    parameters: HelperParameters
    peer: AuthenticatedPeer
    authority: AuthorityDecision
    confinement: ConfinementAttestation
    device_capability: DeviceCapability | None
    driver_certificate_sha256: str | None


@dataclass(frozen=True, slots=True)
class EffectResult:
    result_code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.result_code, "result.result_code")
        _digest(self.evidence_sha256, "result.evidence_sha256")


@dataclass(frozen=True, slots=True)
class EffectReceipt:
    request_id: str
    request_sha256: str
    idempotency_key: str
    subject: str
    action: HelperAction
    decision_id: str
    authority_generation: int
    capability_sha256: str
    result_code: str
    evidence_sha256: str
    executed_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.request_id, "receipt.request_id")
        _digest(self.request_sha256, "receipt.request_sha256")
        _digest(self.idempotency_key, "receipt.idempotency_key")
        _identifier(self.subject, "receipt.subject")
        if not isinstance(self.action, HelperAction):
            raise HelperValidationError("receipt.action is invalid")
        _identifier(self.decision_id, "receipt.decision_id")
        _positive(self.authority_generation, "receipt.authority_generation")
        _digest(self.capability_sha256, "receipt.capability_sha256")
        _identifier(self.result_code, "receipt.result_code")
        _digest(self.evidence_sha256, "receipt.evidence_sha256")
        object.__setattr__(self, "executed_at", _aware(self.executed_at, "receipt.executed_at"))


@dataclass(frozen=True, slots=True)
class ExecutorCompletion:
    request_id: str
    request_sha256: str
    idempotency_key: str
    subject: str
    action: HelperAction
    decision_id: str
    authority_generation: int
    capability_sha256: str
    result: EffectResult
    executed_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.request_id, "completion.request_id")
        _digest(self.request_sha256, "completion.request_sha256")
        _digest(self.idempotency_key, "completion.idempotency_key")
        _identifier(self.subject, "completion.subject")
        if not isinstance(self.action, HelperAction):
            raise HelperValidationError("completion.action is invalid")
        _identifier(self.decision_id, "completion.decision_id")
        _positive(self.authority_generation, "completion.authority_generation")
        _digest(self.capability_sha256, "completion.capability_sha256")
        if not isinstance(self.result, EffectResult):
            raise HelperValidationError("completion.result is invalid")
        object.__setattr__(
            self, "executed_at", _aware(self.executed_at, "completion.executed_at")
        )


@dataclass(frozen=True, slots=True)
class ExecutorReconciliation:
    state: ReconciliationState
    completion: ExecutorCompletion | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ReconciliationState) or (
            (self.state is ReconciliationState.COMPLETED) != (self.completion is not None)
        ):
            raise HelperValidationError("reconciliation state/completion is inconsistent")


@dataclass(frozen=True, slots=True)
class JournalRecord:
    request_id: str
    request_sha256: str
    state: JournalState
    owner_token: str | None
    receipt: EffectReceipt | None

    def __post_init__(self) -> None:
        _identifier(self.request_id, "journal.request_id")
        _digest(self.request_sha256, "journal.request_sha256")
        if not isinstance(self.state, JournalState):
            raise HelperValidationError("journal state is invalid")
        if self.owner_token is not None:
            _identifier(self.owner_token, "journal.owner_token")
        if self.state is JournalState.PENDING:
            if self.owner_token is None or self.receipt is not None:
                raise HelperValidationError("pending journal record is inconsistent")
        elif self.state is JournalState.COMPLETED:
            if self.owner_token is not None or not isinstance(self.receipt, EffectReceipt):
                raise HelperValidationError("completed journal record is inconsistent")
        elif self.owner_token is not None or self.receipt is not None:
            raise HelperValidationError("failed-unknown journal record is inconsistent")


@dataclass(frozen=True, slots=True)
class JournalReservation:
    record: JournalRecord
    acquired: bool

    def __post_init__(self) -> None:
        if not isinstance(self.record, JournalRecord) or not isinstance(self.acquired, bool):
            raise HelperValidationError("journal reservation is invalid")
        if self.acquired and self.record.state is not JournalState.PENDING:
            raise HelperValidationError("only a pending journal record can be acquired")


class RequestJournal(Protocol):
    persistent: bool
    capacity: int
    retention: timedelta

    def reserve(
        self,
        request_id: str,
        request_sha256: str,
        owner_token: str,
        observed_at: datetime,
        lease_until: datetime,
    ) -> JournalReservation: ...

    def complete(
        self,
        request_id: str,
        request_sha256: str,
        owner_token: str | None,
        receipt: EffectReceipt,
    ) -> None: ...

    def mark_failed_unknown(
        self, request_id: str, request_sha256: str, owner_token: str
    ) -> None: ...


class EffectExecutor(Protocol):
    def execute(self, effect: AuthorizedEffect) -> EffectResult: ...

    def reconcile(
        self, idempotency_key: str, request_sha256: str
    ) -> ExecutorReconciliation: ...


PeerAuthenticator: TypeAlias = Callable[[AuthenticatedPeer, datetime], bool]
ConfinementAttestor: TypeAlias = Callable[
    [AuthenticatedPeer, HelperRequest, datetime], ConfinementAttestation
]
ConfinementVerifier: TypeAlias = Callable[[ConfinementAttestation, datetime], bool]
ConfinementInvalidator: TypeAlias = Callable[[ConfinementAttestation], bool]
DeviceBinder: TypeAlias = Callable[
    [DeviceAssignment, AuthenticatedPeer, HelperRequest, datetime], DeviceCapability
]
CertificateVerifier: TypeAlias = Callable[[DriverRuntimeCertificate, datetime], bool]
CertificateInvalidator: TypeAlias = Callable[[DriverRuntimeCertificate], bool]
PolicyAuthorizer: TypeAlias = Callable[
    [AuthenticatedPeer, HelperRequest, str, datetime], AuthorityDecision
]


_REQUEST_KEYS = {
    "schema_version", "request_id", "subject", "peer_identity_sha256", "action",
    "issued_at", "deadline", "authority", "parameters", "confinement",
    "device_assignment", "driver_runtime_certificate", "request_sha256",
}


def calculate_request_sha256(document: Mapping[str, object]) -> str:
    value = dict(document)
    _expect(value, "unsigned request", _REQUEST_KEYS - {"request_sha256"})
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_parameters(action: HelperAction, value: object) -> HelperParameters:
    if action is HelperAction.ACTIVATE_STAGED_RELEASE:
        item = _expect(value, "parameters", {"release_sha256"})
        return ActivateReleaseParameters(_digest(item["release_sha256"], "parameters.release_sha256"))
    if action is HelperAction.SET_RECOVERY_BOOT_ONCE:
        item = _expect(value, "parameters", {"slot"})
        return RecoveryBootParameters(_enum(RecoverySlot, item["slot"], "parameters.slot"))  # type: ignore[arg-type]
    if action is HelperAction.ASSIGN_MODEL_DEVICE:
        item = _expect(value, "parameters", {"worker_id", "assignment_id"})
        return AssignDeviceParameters(
            _identifier(item["worker_id"], "parameters.worker_id"),
            _identifier(item["assignment_id"], "parameters.assignment_id"),
        )
    item = _expect(
        value, "parameters",
        {"worker_id", "workload_id", "artifact_sha256", "code_kind", "assignment_id"},
    )
    assignment = item["assignment_id"]
    return StartGeneratedWorkerParameters(
        _identifier(item["worker_id"], "parameters.worker_id"),
        _identifier(item["workload_id"], "parameters.workload_id"),
        _digest(item["artifact_sha256"], "parameters.artifact_sha256"),
        _enum(GeneratedCodeKind, item["code_kind"], "parameters.code_kind"),  # type: ignore[arg-type]
        None if assignment is None else _identifier(assignment, "parameters.assignment_id"),
    )


def _parse_confinement(value: object) -> ConfinementClaim:
    item = _expect(
        value, "confinement",
        {"mode", "profile_id", "profile_version", "profile_sha256", "qualification_id", "signer_key_id", "signature"},
    )
    return ConfinementClaim(
        _enum(ConfinementMode, item["mode"], "confinement.mode"),  # type: ignore[arg-type]
        _identifier(item["profile_id"], "confinement.profile_id"),
        _positive(item["profile_version"], "confinement.profile_version"),
        _digest(item["profile_sha256"], "confinement.profile_sha256"),
        _identifier(item["qualification_id"], "confinement.qualification_id"),
        _identifier(item["signer_key_id"], "confinement.signer_key_id"),
        _signature(item["signature"], "confinement.signature"),
    )


def _parse_assignment(value: object) -> DeviceAssignment | None:
    if value is None:
        return None
    item = _expect(
        value, "device_assignment",
        {"assignment_id", "worker_id", "selectors", "exclusive", "generation"},
    )
    raw_selectors = item["selectors"]
    if not isinstance(raw_selectors, list):
        raise HelperValidationError("device_assignment.selectors must be an array")
    selectors = []
    for index, raw in enumerate(raw_selectors):
        selector = _expect(raw, f"selectors[{index}]", {"device_type", "path"})
        selectors.append(
            DeviceSelector(
                _enum(DeviceType, selector["device_type"], f"selectors[{index}].device_type"),  # type: ignore[arg-type]
                selector["path"] if isinstance(selector["path"], str) else "",
            )
        )
    return DeviceAssignment(
        _identifier(item["assignment_id"], "device_assignment.assignment_id"),
        _identifier(item["worker_id"], "device_assignment.worker_id"),
        tuple(selectors),
        _boolean(item["exclusive"], "device_assignment.exclusive"),
        _positive(item["generation"], "device_assignment.generation"),
    )


def _parse_certificate(value: object) -> DriverRuntimeCertificate | None:
    if value is None:
        return None
    item = _expect(
        value, "driver_runtime_certificate",
        {"certificate_id", "device_identity_sha256s", "driver_name", "driver_version",
         "driver_module_sha256", "runtime_name", "runtime_version", "runtime_sha256",
         "qualification_id", "signer_key_id", "not_before", "not_after", "signature"},
    )
    identities = item["device_identity_sha256s"]
    if not isinstance(identities, list):
        raise HelperValidationError("certificate.device_identity_sha256s must be an array")
    return DriverRuntimeCertificate(
        _identifier(item["certificate_id"], "certificate.certificate_id"),
        tuple(_digest(entry, "certificate.device_identity[]") for entry in identities),
        _identifier(item["driver_name"], "certificate.driver_name"),
        _version(item["driver_version"], "certificate.driver_version"),
        _digest(item["driver_module_sha256"], "certificate.driver_module_sha256"),
        _identifier(item["runtime_name"], "certificate.runtime_name"),
        _version(item["runtime_version"], "certificate.runtime_version"),
        _digest(item["runtime_sha256"], "certificate.runtime_sha256"),
        _identifier(item["qualification_id"], "certificate.qualification_id"),
        _identifier(item["signer_key_id"], "certificate.signer_key_id"),
        _parse_time(item["not_before"], "certificate.not_before"),
        _parse_time(item["not_after"], "certificate.not_after"),
        _signature(item["signature"], "certificate.signature"),
    )


def parse_helper_request(raw: bytes) -> HelperRequest:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise HelperValidationError("request size is outside the accepted bounds")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
        _json_limits(document)
    except HelperValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        raise HelperValidationError("request must be bounded UTF-8 JSON") from exc
    root = _expect(document, "request", _REQUEST_KEYS)
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise HelperValidationError("unsupported request schema_version")
    claimed = _digest(root["request_sha256"], "request.request_sha256")
    unsigned = {key: value for key, value in root.items() if key != "request_sha256"}
    if claimed != calculate_request_sha256(unsigned):
        raise HelperValidationError("request_sha256 does not match the request")
    action = _enum(HelperAction, root["action"], "request.action")
    authority = _expect(root["authority"], "authority", {"id", "generation"})
    issued = _parse_time(root["issued_at"], "request.issued_at")
    deadline = _parse_time(root["deadline"], "request.deadline")
    if deadline <= issued:
        raise HelperValidationError("request deadline must be later than issue time")
    request = HelperRequest(
        _identifier(root["request_id"], "request.request_id"),
        _identifier(root["subject"], "request.subject"),
        _digest(root["peer_identity_sha256"], "request.peer_identity_sha256"),
        action,  # type: ignore[arg-type]
        issued,
        deadline,
        _identifier(authority["id"], "authority.id"),
        _positive(authority["generation"], "authority.generation"),
        _parse_parameters(action, root["parameters"]),  # type: ignore[arg-type]
        _parse_confinement(root["confinement"]),
        _parse_assignment(root["device_assignment"]),
        _parse_certificate(root["driver_runtime_certificate"]),
        claimed,
    )
    assignment_id = getattr(request.parameters, "assignment_id", None)
    if assignment_id is None and request.device_assignment is not None:
        raise HelperValidationError("device assignment is unexpected for the action")
    if assignment_id is not None and (
        request.device_assignment is None
        or request.device_assignment.assignment_id != assignment_id
        or request.device_assignment.worker_id != request.worker_id
    ):
        raise HelperValidationError("parameters and device assignment do not match")
    if (request.device_assignment is None) != (request.driver_runtime_certificate is None):
        raise HelperValidationError("device assignment and driver certificate must appear together")
    return request


@dataclass(frozen=True, slots=True)
class _TrustSnapshot:
    confinement: ConfinementAttestation
    device: DeviceCapability | None
    certificate: DriverRuntimeCertificate | None
    capability_sha256: str
    authority: AuthorityDecision


_ACTIVE: ContextVar[frozenset[str]] = ContextVar("luma_helper_active", default=frozenset())


class PrivilegedHelper:
    """Dispatch finite request-bound effects without holding locks across adapters."""

    def __init__(
        self,
        *,
        peer_authenticator: PeerAuthenticator,
        confinement_attestor: ConfinementAttestor,
        confinement_verifier: ConfinementVerifier,
        confinement_invalidated: ConfinementInvalidator,
        device_binder: DeviceBinder,
        driver_certificate_verifier: CertificateVerifier,
        driver_certificate_invalidated: CertificateInvalidator,
        policy_authorizer: PolicyAuthorizer,
        journal: RequestJournal,
        executor: EffectExecutor,
        clock: Callable[[], datetime] | None = None,
        owner_token_factory: Callable[[], str] | None = None,
        max_request_age: timedelta = timedelta(minutes=5),
        reservation_lease: timedelta = timedelta(seconds=30),
        max_future_skew: timedelta = timedelta(seconds=5),
    ) -> None:
        callbacks = (
            peer_authenticator, confinement_attestor, confinement_verifier,
            confinement_invalidated, device_binder, driver_certificate_verifier,
            driver_certificate_invalidated, policy_authorizer,
        )
        if not all(callable(item) for item in callbacks):
            raise TypeError("all trust adapters must be callable")
        if not callable(getattr(executor, "execute", None)) or not callable(
            getattr(executor, "reconcile", None)
        ):
            raise TypeError("executor must implement execute and reconcile")
        if (
            getattr(journal, "persistent", None) is not True
            or type(getattr(journal, "capacity", None)) is not int
            or journal.capacity < 1
            or not isinstance(getattr(journal, "retention", None), timedelta)
            or journal.retention < max_request_age
        ):
            raise ValueError("journal must be persistent, bounded, and retained through request age")
        if max_request_age <= timedelta(0) or reservation_lease <= timedelta(0) or max_future_skew < timedelta(0):
            raise ValueError("helper time bounds are invalid")
        self._peer_authenticator = peer_authenticator
        self._confinement_attestor = confinement_attestor
        self._confinement_verifier = confinement_verifier
        self._confinement_invalidated = confinement_invalidated
        self._device_binder = device_binder
        self._certificate_verifier = driver_certificate_verifier
        self._certificate_invalidated = driver_certificate_invalidated
        self._policy_authorizer = policy_authorizer
        self._journal = journal
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._owner_token_factory = owner_token_factory or (lambda: uuid.uuid4().hex)
        self._max_request_age = max_request_age
        self._reservation_lease = reservation_lease
        self._max_future_skew = max_future_skew

    def _now(self) -> datetime:
        return _aware(self._clock(), "clock result")

    @staticmethod
    def _bool_hook(callback: Callable[..., bool], reason: DenialReason, *args: object) -> None:
        try:
            result = callback(*args)
        except Exception as exc:
            raise HelperDenied(reason) from exc
        if result is not True:
            raise HelperDenied(reason)

    def _fresh(self, request: HelperRequest, now: datetime) -> None:
        if request.issued_at > now + self._max_future_skew:
            raise HelperDenied(DenialReason.REQUEST_FROM_FUTURE)
        if now - request.issued_at > self._max_request_age:
            raise HelperDenied(DenialReason.REQUEST_STALE)
        if request.deadline > request.issued_at + self._max_request_age:
            raise HelperDenied(DenialReason.REQUEST_STALE)
        if now >= request.deadline:
            raise HelperDenied(DenialReason.REQUEST_EXPIRED)

    def _attest_confinement(
        self, request: HelperRequest, peer: AuthenticatedPeer, now: datetime
    ) -> ConfinementAttestation:
        try:
            evidence = self._confinement_attestor(peer, request, now)
        except Exception as exc:
            raise HelperDenied(DenialReason.CONFINEMENT_UNTRUSTED) from exc
        if not isinstance(evidence, ConfinementAttestation):
            raise HelperDenied(DenialReason.CONFINEMENT_UNTRUSTED)
        claim = request.confinement
        if (
            evidence.request_sha256 != request.request_sha256
            or evidence.peer_identity_sha256 != peer.identity_sha256
            or evidence.action is not request.action
            or evidence.worker_id != request.worker_id
            or evidence.artifact_sha256 != request.artifact_sha256
            or evidence.mode is not claim.mode
            or evidence.profile_id != claim.profile_id
            or evidence.profile_version != claim.profile_version
            or evidence.profile_sha256 != claim.profile_sha256
            or evidence.qualification_id != claim.qualification_id
        ):
            raise HelperDenied(DenialReason.CONFINEMENT_BINDING_MISMATCH)
        if not evidence.enforcing:
            raise HelperDenied(DenialReason.CONFINEMENT_NOT_ENFORCING)
        try:
            invalidated = self._confinement_invalidated(evidence)
        except Exception as exc:
            raise HelperDenied(DenialReason.CONFINEMENT_INVALIDATED) from exc
        if invalidated is not False:
            raise HelperDenied(DenialReason.CONFINEMENT_INVALIDATED)
        self._bool_hook(self._confinement_verifier, DenialReason.CONFINEMENT_UNTRUSTED, evidence, now)
        if not evidence.attested_at <= now < evidence.valid_until:
            raise HelperDenied(DenialReason.CONFINEMENT_UNTRUSTED)
        if (
            isinstance(request.parameters, StartGeneratedWorkerParameters)
            and request.parameters.code_kind is GeneratedCodeKind.NATIVE
            and evidence.mode not in {
                ConfinementMode.KVM_MICROVM,
                ConfinementMode.QUALIFIED_CONSTRAINED_RUNTIME,
            }
        ):
            raise HelperDenied(DenialReason.NATIVE_CODE_CONFINEMENT_REQUIRED)
        return evidence

    def _bind_device(
        self, request: HelperRequest, peer: AuthenticatedPeer, now: datetime
    ) -> tuple[DeviceCapability | None, DriverRuntimeCertificate | None]:
        assignment, certificate = request.device_assignment, request.driver_runtime_certificate
        if assignment is None:
            return None, None
        if certificate is None:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_MISMATCH)
        try:
            capability = self._device_binder(assignment, peer, request, now)
        except Exception as exc:
            raise HelperDenied(DenialReason.DEVICE_BINDING_DENIED) from exc
        if not isinstance(capability, DeviceCapability):
            raise HelperDenied(DenialReason.DEVICE_BINDING_DENIED)
        expected_types = sorted(item.device_type.value for item in assignment.selectors)
        bound_types = sorted(item.device_type.value for item in capability.devices)
        if (
            capability.request_sha256 != request.request_sha256
            or capability.peer_identity_sha256 != peer.identity_sha256
            or capability.assignment_id != assignment.assignment_id
            or capability.assignment_generation != assignment.generation
            or capability.worker_id != assignment.worker_id
            or capability.exclusive is not True
            or bound_types != expected_types
        ):
            raise HelperDenied(DenialReason.DEVICE_BINDING_MISMATCH)
        if not capability.issued_at <= now < capability.valid_until:
            raise HelperDenied(DenialReason.DEVICE_CAPABILITY_EXPIRED)
        identities = tuple(item.stable_identity_sha256 for item in capability.devices)
        if certificate.device_identity_sha256s != identities:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_MISMATCH)
        if not certificate.not_before <= now < certificate.not_after:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_EXPIRED)
        try:
            invalidated = self._certificate_invalidated(certificate)
        except Exception as exc:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_INVALIDATED) from exc
        if invalidated is not False:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_INVALIDATED)
        self._bool_hook(
            self._certificate_verifier, DenialReason.DRIVER_CERTIFICATE_UNTRUSTED, certificate, now
        )
        return capability, certificate

    def _authorize(
        self, request: HelperRequest, peer: AuthenticatedPeer, capability_sha256: str, now: datetime
    ) -> AuthorityDecision:
        try:
            decision = self._policy_authorizer(peer, request, capability_sha256, now)
        except Exception as exc:
            raise HelperDenied(DenialReason.AUTHORITY_DENIED) from exc
        if not isinstance(decision, AuthorityDecision):
            raise HelperDenied(DenialReason.AUTHORITY_DENIED)
        if decision.revoked:
            raise HelperDenied(DenialReason.AUTHORITY_REVOKED)
        if (
            decision.authority_id != request.authority_id
            or decision.authority_generation != request.authority_generation
        ):
            raise HelperDenied(DenialReason.AUTHORITY_STALE)
        if (
            decision.subject != request.subject
            or decision.peer_identity_sha256 != peer.identity_sha256
            or decision.action is not request.action
            or decision.request_sha256 != request.request_sha256
            or decision.capability_sha256 != capability_sha256
        ):
            raise HelperDenied(DenialReason.AUTHORITY_BINDING_MISMATCH)
        if now >= decision.expires_at:
            raise HelperDenied(DenialReason.AUTHORITY_EXPIRED)
        if not decision.allowed:
            raise HelperDenied(DenialReason.AUTHORITY_DENIED)
        return decision

    def _snapshot(self, request: HelperRequest, peer: AuthenticatedPeer, now: datetime) -> _TrustSnapshot:
        confinement = self._attest_confinement(request, peer, now)
        device, certificate = self._bind_device(request, peer, now)
        capability_sha256 = hashlib.sha256(
            _canonical(
                {
                    "confinement_attestation_sha256": confinement.digest,
                    "device_capability_sha256": device.digest if device else None,
                    "driver_certificate_sha256": certificate.digest if certificate else None,
                    "request_sha256": request.request_sha256,
                }
            )
        ).hexdigest()
        authority = self._authorize(request, peer, capability_sha256, now)
        return _TrustSnapshot(confinement, device, certificate, capability_sha256, authority)

    def _final_temporal(self, request: HelperRequest, snapshot: _TrustSnapshot, now: datetime) -> None:
        self._fresh(request, now)
        if not snapshot.confinement.attested_at <= now < snapshot.confinement.valid_until:
            raise HelperDenied(DenialReason.CONFINEMENT_UNTRUSTED)
        if snapshot.device and not snapshot.device.issued_at <= now < snapshot.device.valid_until:
            raise HelperDenied(DenialReason.DEVICE_CAPABILITY_EXPIRED)
        if snapshot.certificate and not snapshot.certificate.not_before <= now < snapshot.certificate.not_after:
            raise HelperDenied(DenialReason.DRIVER_CERTIFICATE_EXPIRED)
        if now >= snapshot.authority.expires_at:
            raise HelperDenied(DenialReason.AUTHORITY_EXPIRED)

    @staticmethod
    def _receipt_from_completion(request: HelperRequest, completion: ExecutorCompletion) -> EffectReceipt:
        if (
            completion.request_id != request.request_id
            or completion.request_sha256 != request.request_sha256
            or completion.idempotency_key != request.idempotency_key
            or completion.subject != request.subject
            or completion.action is not request.action
            or completion.authority_generation != request.authority_generation
        ):
            raise HelperExecutionError("executor reconciliation binding mismatch")
        return EffectReceipt(
            completion.request_id, completion.request_sha256, completion.idempotency_key,
            completion.subject, completion.action, completion.decision_id,
            completion.authority_generation, completion.capability_sha256,
            completion.result.result_code, completion.result.evidence_sha256,
            _aware(completion.executed_at, "completion.executed_at"),
        )

    def _reconcile(self, request: HelperRequest) -> EffectReceipt | None:
        try:
            outcome = self._executor.reconcile(request.idempotency_key, request.request_sha256)
        except Exception as exc:
            raise HelperDenied(DenialReason.FAILED_UNKNOWN) from exc
        if not isinstance(outcome, ExecutorReconciliation):
            raise HelperDenied(DenialReason.FAILED_UNKNOWN)
        if outcome.state is ReconciliationState.COMPLETED:
            if outcome.completion is None:
                raise HelperDenied(DenialReason.FAILED_UNKNOWN)
            return self._receipt_from_completion(request, outcome.completion)
        if outcome.state is ReconciliationState.UNKNOWN:
            raise HelperDenied(DenialReason.FAILED_UNKNOWN)
        return None

    def _reserve(self, request: HelperRequest, owner: str, now: datetime) -> JournalReservation:
        try:
            reservation = self._journal.reserve(
                request.request_id, request.request_sha256, owner, now, now + self._reservation_lease
            )
        except HelperReplayConflict:
            raise
        except Exception as exc:
            raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE) from exc
        if not isinstance(reservation, JournalReservation):
            raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE)
        record = reservation.record
        if record.request_id != request.request_id:
            raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE)
        if record.request_sha256 != request.request_sha256:
            raise HelperReplayConflict(DenialReason.REPLAY_CONFLICT)
        if record.state is JournalState.COMPLETED:
            receipt = record.receipt
            if (
                receipt is None
                or receipt.request_id != request.request_id
                or receipt.request_sha256 != request.request_sha256
                or receipt.idempotency_key != request.idempotency_key
                or receipt.subject != request.subject
                or receipt.action is not request.action
            ):
                raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE)
        elif record.receipt is not None:
            raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE)
        return reservation

    def handle(self, raw: bytes, *, peer: AuthenticatedPeer) -> EffectReceipt:
        if not isinstance(peer, AuthenticatedPeer):
            raise TypeError("peer must be transport-authenticated evidence")
        request = parse_helper_request(raw)
        if (
            not peer.authenticated
            or request.subject != peer.principal
            or request.peer_identity_sha256 != peer.identity_sha256
        ):
            raise HelperDenied(DenialReason.PEER_IDENTITY_MISMATCH)
        if _ACTIVE.get():
            raise HelperDenied(DenialReason.REENTRANT_DISPATCH)
        active = _ACTIVE.set(_ACTIVE.get() | {request.request_id})
        try:
            # The guard is active before every injected callback, including
            # the clock and transport authenticator.
            first_now = self._now()
            self._bool_hook(
                self._peer_authenticator,
                DenialReason.PEER_AUTHENTICATION_FAILED,
                peer,
                first_now,
            )
            owner = _identifier(self._owner_token_factory(), "owner_token")
            reservation = self._reserve(request, owner, first_now)
            record = reservation.record
            if record.state is JournalState.COMPLETED:
                if record.receipt is None:
                    raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE)
                return record.receipt  # safe authenticated replay, even after deadline
            if not reservation.acquired or record.state is JournalState.FAILED_UNKNOWN:
                reconciled = self._reconcile(request)
                if reconciled is not None:
                    try:
                        self._journal.complete(request.request_id, request.request_sha256, None, reconciled)
                    except Exception as exc:
                        raise HelperDenied(DenialReason.JOURNAL_UNAVAILABLE) from exc
                    return reconciled
                if record.state is JournalState.FAILED_UNKNOWN:
                    raise HelperDenied(DenialReason.FAILED_UNKNOWN)
                if not reservation.acquired:
                    raise HelperDenied(DenialReason.REQUEST_IN_PROGRESS)

            self._fresh(request, self._now())
            self._snapshot(request, peer, self._now())  # initial trust probe
            snapshot = self._snapshot(request, peer, self._now())  # effect-time revalidation
            final_peer_time = self._now()
            self._bool_hook(
                self._peer_authenticator,
                DenialReason.PEER_AUTHENTICATION_FAILED,
                peer,
                final_peer_time,
            )
            dispatch_at = self._now()
            self._final_temporal(request, snapshot, dispatch_at)
            effect = AuthorizedEffect(
                request.request_id, request.request_sha256, request.idempotency_key,
                request.subject, request.action, request.parameters, peer, snapshot.authority,
                snapshot.confinement, snapshot.device,
                snapshot.certificate.digest if snapshot.certificate else None,
            )
            try:
                result = self._executor.execute(effect)
                if not isinstance(result, EffectResult):
                    raise TypeError("executor returned an invalid result")
                completed_at = self._now()
                receipt = EffectReceipt(
                    request.request_id, request.request_sha256, request.idempotency_key,
                    request.subject, request.action, snapshot.authority.decision_id,
                    snapshot.authority.authority_generation, snapshot.capability_sha256,
                    result.result_code, result.evidence_sha256, completed_at,
                )
            except Exception as exc:
                try:
                    reconciled = self._reconcile(request)
                except HelperDenied:
                    reconciled = None
                if reconciled is not None:
                    receipt = reconciled
                else:
                    try:
                        self._journal.mark_failed_unknown(
                            request.request_id, request.request_sha256, owner
                        )
                    except Exception as journal_exc:
                        raise HelperExecutionError(
                            "effect outcome and journal state are both unknown"
                        ) from journal_exc
                    raise HelperExecutionError("effect outcome is unknown and fenced") from exc
            try:
                self._journal.complete(request.request_id, request.request_sha256, owner, receipt)
            except Exception as exc:
                raise HelperExecutionError("effect completed but receipt was not committed") from exc
            return receipt
        finally:
            _ACTIVE.reset(active)
