"""Pure A/B release and trial-boot control contracts.

This module models durable decisions only. It never reads a disk, changes a
firmware variable, selects a real boot entry, or creates cryptographic trust.
State authentication, a non-rollback monotonic anchor, persisted boot
attestation, and durable-data/readability evidence are mandatory injected
dependencies. Concrete platform adapters and destructive qualification remain
final-hardware certification work.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Protocol


MAX_TRIAL_FAILURES = 3
_CHAIN_ORIGIN = "0" * 64


class BootControlError(RuntimeError):
    """Base class for rejected boot-control operations."""


class BootControlValidationError(ValueError):
    """An immutable boot-control value is malformed or inconsistent."""


class InvalidTransition(BootControlError):
    """A command is not valid in the current update phase."""


class StaleGeneration(BootControlError):
    """A command was prepared against an obsolete durable generation."""


class FenceRejected(BootControlError):
    """A command came from a controller that does not own the current fence."""


class IdempotencyConflict(BootControlError):
    """An operation identifier was reused for different command content."""


class TamperRejected(BootControlError):
    """Conflicting trusted content or acknowledged data was rejected."""


class StateAuthenticationRejected(BootControlError):
    """The durable state authentication tag was absent or invalid."""


class MonotonicAnchorRejected(BootControlError):
    """The external anchor rejected restored, truncated, or forked state."""


class ExternalEvidenceRejected(BootControlError):
    """An injected trusted evidence provider rejected an assertion."""


class FallbackReadabilityRejected(BootControlError):
    """The retained release was not proven able to read acknowledged data."""


class SlotName(str, Enum):
    A = "A"
    B = "B"


class SignatureStatus(str, Enum):
    MISSING = "missing"
    UNTRUSTED = "untrusted"
    TRUSTED = "trusted"


class IntegrityStatus(str, Enum):
    UNKNOWN = "unknown"
    MISMATCH = "mismatch"
    VERIFIED = "verified"


class SlotStatus(str, Enum):
    EMPTY = "empty"
    ACTIVE = "active"
    STAGED = "staged"
    RETAINED = "retained"
    REJECTED = "rejected"


class UpdatePhase(str, Enum):
    IDLE = "idle"
    DOWNLOAD = "download"
    VERIFY = "verify"
    WRITE = "write"
    SELECT = "select"
    FIRST_BOOT = "first-boot"


class CommandKind(str, Enum):
    BEGIN_DOWNLOAD = "begin-download"
    DOWNLOAD_COMPLETE = "download-complete"
    VERIFY_COMPLETE = "verify-complete"
    WRITE_COMPLETE = "write-complete"
    SELECT_TRIAL = "select-trial"
    BEGIN_FIRST_BOOT = "begin-first-boot"
    RECORD_BOOT_OBSERVATION = "record-boot-observation"
    TRIAL_FAILURE = "trial-failure"
    ACK_ESSENTIAL_HEALTH = "ack-essential-health"
    COMMIT_TRIAL = "commit-trial"
    ACK_DATA_CHECKPOINT = "ack-data-checkpoint"
    RECONCILE_POWER_LOSS = "reconcile-power-loss"
    ROTATE_FENCE = "rotate-fence"


def _text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise BootControlValidationError(f"{field} must be non-empty printable ASCII")
    return value


def _digest(value: object, field: str) -> str:
    text = _text(value, field, maximum=64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise BootControlValidationError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _nonnegative(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > (1 << 63) - 1
    ):
        raise BootControlValidationError(f"{field} must be a non-negative signed 64-bit integer")
    return value


def _positive(value: object, field: str) -> int:
    number = _nonnegative(value, field)
    if number == 0:
        raise BootControlValidationError(f"{field} must be positive")
    return number


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    """Content- and order-bound immutable release identity."""

    release_id: str
    version: str
    release_sequence: int
    manifest_sha256: str
    root_sha256: str
    signer_key_id: str
    data_compatibility_id: str

    def __post_init__(self) -> None:
        _text(self.release_id, "release_id")
        _text(self.version, "version")
        _positive(self.release_sequence, "release_sequence")
        _digest(self.manifest_sha256, "manifest_sha256")
        _digest(self.root_sha256, "root_sha256")
        _text(self.signer_key_id, "signer_key_id")
        _text(self.data_compatibility_id, "data_compatibility_id")


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    """A release identity plus assertions produced by an external verifier."""

    identity: ReleaseIdentity
    signature_status: SignatureStatus
    integrity_status: IntegrityStatus

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ReleaseIdentity):
            raise BootControlValidationError("artifact identity must be a ReleaseIdentity")
        if not isinstance(self.signature_status, SignatureStatus):
            raise BootControlValidationError("signature_status must be a SignatureStatus")
        if not isinstance(self.integrity_status, IntegrityStatus):
            raise BootControlValidationError("integrity_status must be an IntegrityStatus")

    @property
    def trusted_and_verified(self) -> bool:
        return (
            self.signature_status is SignatureStatus.TRUSTED
            and self.integrity_status is IntegrityStatus.VERIFIED
        )


@dataclass(frozen=True, slots=True)
class SlotIdentity:
    """Stable logical and physical identity for one root slot."""

    name: SlotName
    stable_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, SlotName):
            raise BootControlValidationError("slot name must be a SlotName")
        _text(self.stable_id, "stable_id")


@dataclass(frozen=True, slots=True)
class SlotRecord:
    identity: SlotIdentity
    artifact: ReleaseArtifact | None
    status: SlotStatus

    def __post_init__(self) -> None:
        if not isinstance(self.identity, SlotIdentity):
            raise BootControlValidationError("slot identity must be a SlotIdentity")
        if not isinstance(self.status, SlotStatus):
            raise BootControlValidationError("slot status must be a SlotStatus")
        if self.status is SlotStatus.EMPTY:
            if self.artifact is not None:
                raise BootControlValidationError("an empty slot cannot contain a release")
            return
        if not isinstance(self.artifact, ReleaseArtifact):
            raise BootControlValidationError("a non-empty slot requires a release artifact")
        if self.status in {SlotStatus.ACTIVE, SlotStatus.STAGED, SlotStatus.RETAINED}:
            if not self.artifact.trusted_and_verified:
                raise BootControlValidationError("bootable slot state requires trusted verified content")


@dataclass(frozen=True, slots=True)
class DataCheckpoint:
    """Externally receipted shared-data generation and its writer binding."""

    generation: int
    sha256: str
    schema_id: str
    writer_release_manifest_sha256: str
    writer_fence_epoch: int
    writer_owner_token: str
    durability_receipt_sha256: str

    def __post_init__(self) -> None:
        _nonnegative(self.generation, "data checkpoint generation")
        _digest(self.sha256, "data checkpoint sha256")
        _text(self.schema_id, "schema_id")
        _digest(self.writer_release_manifest_sha256, "writer release manifest")
        _positive(self.writer_fence_epoch, "writer fence epoch")
        _text(self.writer_owner_token, "writer owner token")
        _digest(self.durability_receipt_sha256, "durability receipt")


@dataclass(frozen=True, slots=True)
class BootObservation:
    """Persisted platform observation for one unique boot attempt."""

    attempt_nonce: str
    actual_slot: SlotName
    release_manifest_sha256: str
    release_root_sha256: str
    signature_status: SignatureStatus
    integrity_status: IntegrityStatus
    fence_epoch: int
    fence_owner_token: str
    persistence_receipt_sha256: str

    def __post_init__(self) -> None:
        _text(self.attempt_nonce, "attempt_nonce")
        if not isinstance(self.actual_slot, SlotName):
            raise BootControlValidationError("actual_slot must be a SlotName")
        _digest(self.release_manifest_sha256, "observed release manifest")
        _digest(self.release_root_sha256, "observed release root")
        if not isinstance(self.signature_status, SignatureStatus):
            raise BootControlValidationError("observed signature status is invalid")
        if not isinstance(self.integrity_status, IntegrityStatus):
            raise BootControlValidationError("observed integrity status is invalid")
        _positive(self.fence_epoch, "observation fence epoch")
        _text(self.fence_owner_token, "observation fence owner")
        _digest(self.persistence_receipt_sha256, "observation persistence receipt")

    @property
    def trusted_and_verified(self) -> bool:
        return (
            self.signature_status is SignatureStatus.TRUSTED
            and self.integrity_status is IntegrityStatus.VERIFIED
        )


@dataclass(frozen=True, slots=True)
class EssentialHealthAcknowledgement:
    attempt_nonce: str
    slot: SlotName
    release_manifest_sha256: str
    observation_receipt_sha256: str
    healthy_services: tuple[str, ...]
    acknowledged_at_generation: int

    def __post_init__(self) -> None:
        _text(self.attempt_nonce, "health attempt nonce")
        if not isinstance(self.slot, SlotName):
            raise BootControlValidationError("health slot must be a SlotName")
        _digest(self.release_manifest_sha256, "health release manifest")
        _digest(self.observation_receipt_sha256, "health observation receipt")
        if not isinstance(self.healthy_services, tuple) or not self.healthy_services:
            raise BootControlValidationError("health services must be a non-empty tuple")
        normalized = tuple(sorted({_text(value, "healthy service") for value in self.healthy_services}))
        if normalized != self.healthy_services:
            raise BootControlValidationError("healthy services must be sorted and unique")
        _nonnegative(self.acknowledged_at_generation, "health acknowledgement generation")


@dataclass(frozen=True, slots=True)
class TamperObservation:
    """Trusted evidence of content differing from the expected release."""

    operation_id: str
    phase: UpdatePhase
    target_slot: SlotName
    attempt_nonce: str | None
    expected_manifest_sha256: str
    expected_root_sha256: str
    observed_manifest_sha256: str
    observed_root_sha256: str
    observed_signature_status: SignatureStatus
    observed_integrity_status: IntegrityStatus
    fence_epoch: int
    reason: str

    def __post_init__(self) -> None:
        _text(self.operation_id, "tamper operation_id")
        if self.phase not in {UpdatePhase.VERIFY, UpdatePhase.FIRST_BOOT}:
            raise BootControlValidationError("tamper phase must be verify or first-boot")
        if not isinstance(self.target_slot, SlotName):
            raise BootControlValidationError("tamper target must be a SlotName")
        if self.attempt_nonce is not None:
            _text(self.attempt_nonce, "tamper attempt nonce")
        _digest(self.expected_manifest_sha256, "expected manifest")
        _digest(self.expected_root_sha256, "expected root")
        _digest(self.observed_manifest_sha256, "observed manifest")
        _digest(self.observed_root_sha256, "observed root")
        if not isinstance(self.observed_signature_status, SignatureStatus):
            raise BootControlValidationError("tamper signature status is invalid")
        if not isinstance(self.observed_integrity_status, IntegrityStatus):
            raise BootControlValidationError("tamper integrity status is invalid")
        _positive(self.fence_epoch, "tamper fence epoch")
        _text(self.reason, "tamper reason")


def _operation_record_digest(
    operation_id: str,
    kind: CommandKind,
    request_sha256: str,
    applied_generation: int,
    outcome: str,
    previous_record_sha256: str,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "applied_generation": applied_generation,
                "kind": kind.value,
                "operation_id": operation_id,
                "outcome": outcome,
                "previous_record_sha256": previous_record_sha256,
                "request_sha256": request_sha256,
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class OperationRecord:
    operation_id: str
    kind: CommandKind
    request_sha256: str
    applied_generation: int
    outcome: str
    previous_record_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        _text(self.operation_id, "operation_id")
        if not isinstance(self.kind, CommandKind):
            raise BootControlValidationError("operation kind must be a CommandKind")
        _digest(self.request_sha256, "request_sha256")
        _positive(self.applied_generation, "applied_generation")
        _text(self.outcome, "outcome")
        _digest(self.previous_record_sha256, "previous_record_sha256")
        _digest(self.record_sha256, "record_sha256")
        expected = _operation_record_digest(
            self.operation_id,
            self.kind,
            self.request_sha256,
            self.applied_generation,
            self.outcome,
            self.previous_record_sha256,
        )
        if self.record_sha256 != expected:
            raise BootControlValidationError("operation record hash is invalid")


@dataclass(frozen=True, slots=True)
class BootState:
    """Complete authenticated durable state for the abstract A/B controller."""

    controller_id: str
    slots: tuple[SlotRecord, SlotRecord]
    active_slot: SlotName
    selected_slot: SlotName
    phase: UpdatePhase
    candidate: ReleaseArtifact | None
    target_slot: SlotName | None
    minimum_release_sequence: int
    trial_failures: int
    essential_services: tuple[str, ...]
    current_attempt_nonce: str | None
    used_attempt_nonces: tuple[str, ...]
    boot_observation: BootObservation | None
    health_acknowledgement: EssentialHealthAcknowledgement | None
    data_checkpoint: DataCheckpoint
    fence_epoch: int
    fence_owner_token: str
    retired_fence_owner_tokens: tuple[str, ...]
    tamper_observations: tuple[TamperObservation, ...]
    generation: int = 0
    operations: tuple[OperationRecord, ...] = ()
    authentication_tag: str = "pending"

    def __post_init__(self) -> None:
        _text(self.controller_id, "controller_id")
        _text(self.authentication_tag, "authentication_tag", maximum=1024)
        if not isinstance(self.phase, UpdatePhase):
            raise BootControlValidationError("phase must be an UpdatePhase")
        if not isinstance(self.active_slot, SlotName) or not isinstance(self.selected_slot, SlotName):
            raise BootControlValidationError("active and selected slots must be SlotName values")
        if not isinstance(self.slots, tuple) or any(
            not isinstance(slot, SlotRecord) for slot in self.slots
        ):
            raise BootControlValidationError("slots must be an immutable SlotRecord tuple")
        if len(self.slots) != 2 or {slot.identity.name for slot in self.slots} != set(SlotName):
            raise BootControlValidationError("state must contain exactly one logical A and B slot")
        if len({slot.identity.stable_id for slot in self.slots}) != 2:
            raise BootControlValidationError("A and B cannot alias the same physical stable ID")
        by_name = {slot.identity.name: slot for slot in self.slots}
        active = by_name[self.active_slot]
        if active.status is not SlotStatus.ACTIVE or active.artifact is None:
            raise BootControlValidationError("active_slot must identify the sole active release")
        if sum(slot.status is SlotStatus.ACTIVE for slot in self.slots) != 1:
            raise BootControlValidationError("state must have exactly one active slot")
        floor = _positive(self.minimum_release_sequence, "minimum_release_sequence")
        if active.artifact.identity.release_sequence < floor:
            raise BootControlValidationError("active release is below the anti-downgrade floor")

        if not isinstance(self.essential_services, tuple):
            raise BootControlValidationError("essential services must be an immutable tuple")
        services = tuple(sorted({_text(value, "essential service") for value in self.essential_services}))
        if not services or services != self.essential_services:
            raise BootControlValidationError("essential services must be non-empty, sorted, and unique")
        if not isinstance(self.data_checkpoint, DataCheckpoint):
            raise BootControlValidationError("data_checkpoint must be a DataCheckpoint")
        epoch = _positive(self.fence_epoch, "fence_epoch")
        _text(self.fence_owner_token, "fence_owner_token")
        if not isinstance(self.retired_fence_owner_tokens, tuple):
            raise BootControlValidationError("retired fence owners must be an immutable tuple")
        retired = tuple(_text(value, "retired fence owner") for value in self.retired_fence_owner_tokens)
        if len(retired) != len(set(retired)) or self.fence_owner_token in retired:
            raise BootControlValidationError("fence owner history is ambiguous or reuses an active token")
        generation = _nonnegative(self.generation, "generation")
        failures = _nonnegative(self.trial_failures, "trial_failures")
        if failures > MAX_TRIAL_FAILURES:
            raise BootControlValidationError("trial failures exceed the automatic-fallback bound")

        if not isinstance(self.operations, tuple) or any(
            not isinstance(record, OperationRecord) for record in self.operations
        ):
            raise BootControlValidationError("operations must be an immutable OperationRecord tuple")
        if len({record.operation_id for record in self.operations}) != len(self.operations):
            raise BootControlValidationError("operation identifiers must be unique")
        if tuple(record.applied_generation for record in self.operations) != tuple(
            range(1, generation + 1)
        ):
            raise BootControlValidationError("operation ledger must cover every durable generation")
        previous = _CHAIN_ORIGIN
        for record in self.operations:
            if record.previous_record_sha256 != previous:
                raise BootControlValidationError("operation record chain is broken")
            previous = record.record_sha256

        if not isinstance(self.used_attempt_nonces, tuple):
            raise BootControlValidationError("used boot nonces must be an immutable tuple")
        nonces = tuple(_text(value, "used boot nonce") for value in self.used_attempt_nonces)
        if len(nonces) != len(set(nonces)):
            raise BootControlValidationError("a boot-attempt nonce can never be reused")
        if not isinstance(self.tamper_observations, tuple) or any(
            not isinstance(item, TamperObservation) for item in self.tamper_observations
        ):
            raise BootControlValidationError("tamper observations must be an immutable tuple")

        if self.phase is UpdatePhase.IDLE:
            if self.candidate is not None or self.target_slot is not None:
                raise BootControlValidationError("idle state cannot retain an in-flight candidate")
            if self.selected_slot is not self.active_slot:
                raise BootControlValidationError("idle state must select its active slot")
            if any(
                value is not None
                for value in (
                    self.current_attempt_nonce,
                    self.boot_observation,
                    self.health_acknowledgement,
                )
            ):
                raise BootControlValidationError("idle state cannot retain trial evidence")
            return

        if not isinstance(self.candidate, ReleaseArtifact) or not isinstance(
            self.target_slot, SlotName
        ):
            raise BootControlValidationError("an update phase requires a candidate and target slot")
        if self.target_slot is self.active_slot:
            raise BootControlValidationError("the active slot can never be an update target")
        if self.phase in {UpdatePhase.DOWNLOAD, UpdatePhase.VERIFY, UpdatePhase.WRITE}:
            if self.selected_slot is not self.active_slot:
                raise BootControlValidationError("pre-selection phases must retain the active selection")
        if self.phase is UpdatePhase.SELECT:
            if self.selected_slot not in {self.active_slot, self.target_slot}:
                raise BootControlValidationError("selection phase chose an unrelated slot")
            target = by_name[self.target_slot]
            if target.status is not SlotStatus.STAGED or target.artifact != self.candidate:
                raise BootControlValidationError("selection requires the verified candidate in the target")
        if self.phase is UpdatePhase.FIRST_BOOT:
            if self.selected_slot is not self.target_slot:
                raise BootControlValidationError("first boot must select the trial target")
            target = by_name[self.target_slot]
            if target.status is not SlotStatus.STAGED or target.artifact != self.candidate:
                raise BootControlValidationError("first boot requires the staged candidate")

        if self.phase is not UpdatePhase.FIRST_BOOT:
            if any(
                value is not None
                for value in (
                    self.current_attempt_nonce,
                    self.boot_observation,
                    self.health_acknowledgement,
                )
            ):
                raise BootControlValidationError("boot evidence is valid only during first boot")
        else:
            if self.current_attempt_nonce is None or self.current_attempt_nonce not in nonces:
                raise BootControlValidationError("first boot requires a unique recorded attempt nonce")
            if self.boot_observation is not None:
                observation = self.boot_observation
                if (
                    observation.attempt_nonce != self.current_attempt_nonce
                    or observation.actual_slot is not self.target_slot
                    or observation.release_manifest_sha256
                    != self.candidate.identity.manifest_sha256
                    or observation.release_root_sha256 != self.candidate.identity.root_sha256
                    or not observation.trusted_and_verified
                    or observation.fence_epoch != epoch
                    or observation.fence_owner_token != self.fence_owner_token
                ):
                    raise BootControlValidationError("stored boot observation does not bind this attempt")
            if self.health_acknowledgement is not None:
                acknowledgement = self.health_acknowledgement
                observation = self.boot_observation
                if (
                    observation is None
                    or acknowledgement.attempt_nonce != self.current_attempt_nonce
                    or acknowledgement.slot is not self.target_slot
                    or acknowledgement.release_manifest_sha256
                    != self.candidate.identity.manifest_sha256
                    or acknowledgement.observation_receipt_sha256
                    != observation.persistence_receipt_sha256
                    or acknowledgement.healthy_services != self.essential_services
                    or acknowledgement.acknowledged_at_generation > generation
                ):
                    raise BootControlValidationError("health acknowledgement does not bind this boot attempt")

    def slot(self, name: SlotName) -> SlotRecord:
        return next(slot for slot in self.slots if slot.identity.name is name)

    @property
    def authenticated_bytes(self) -> bytes:
        return _canonical_state(self)

    @property
    def commitment_sha256(self) -> str:
        return hashlib.sha256(self.authenticated_bytes).hexdigest()


class StateAuthenticator(Protocol):
    def verify(self, payload: bytes, authentication_tag: str) -> bool: ...

    def seal(self, payload: bytes) -> str: ...


class MonotonicAnchor(Protocol):
    def is_current(
        self,
        *,
        controller_id: str,
        generation: int,
        state_commitment_sha256: str,
    ) -> bool: ...


class BootObservationVerifier(Protocol):
    def verify_persisted(self, observation: BootObservation) -> bool: ...


class DataCheckpointOracle(Protocol):
    def verify_durable(self, checkpoint: DataCheckpoint) -> bool: ...

    def is_readable(self, checkpoint: DataCheckpoint, release: ReleaseIdentity) -> bool: ...


@dataclass(frozen=True, slots=True)
class TransitionGuards:
    state_authenticator: StateAuthenticator
    monotonic_anchor: MonotonicAnchor
    boot_observation_verifier: BootObservationVerifier
    data_checkpoint_oracle: DataCheckpointOracle

    def __post_init__(self) -> None:
        requirements = (
            (self.state_authenticator, ("verify", "seal")),
            (self.monotonic_anchor, ("is_current",)),
            (self.boot_observation_verifier, ("verify_persisted",)),
            (self.data_checkpoint_oracle, ("verify_durable", "is_readable")),
        )
        if any(
            not all(callable(getattr(item, name, None)) for name in methods)
            for item, methods in requirements
        ):
            raise BootControlValidationError("transition guards lack required trust methods")


@dataclass(frozen=True, slots=True)
class BootCommand:
    """One fenced, generation-checked, idempotent transition request."""

    kind: CommandKind
    operation_id: str
    expected_generation: int
    fence_epoch: int
    fence_owner_token: str
    target_slot: SlotName | None = None
    artifact: ReleaseArtifact | None = None
    data_checkpoint: DataCheckpoint | None = None
    healthy_services: tuple[str, ...] = ()
    attempt_nonce: str | None = None
    boot_observation: BootObservation | None = None
    new_fence_epoch: int | None = None
    new_fence_owner_token: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CommandKind):
            raise BootControlValidationError("command kind must be a CommandKind")
        _text(self.operation_id, "operation_id")
        _nonnegative(self.expected_generation, "expected_generation")
        _positive(self.fence_epoch, "command fence epoch")
        _text(self.fence_owner_token, "command fence owner")
        if self.target_slot is not None and not isinstance(self.target_slot, SlotName):
            raise BootControlValidationError("target_slot must be a SlotName")
        if self.artifact is not None and not isinstance(self.artifact, ReleaseArtifact):
            raise BootControlValidationError("artifact must be a ReleaseArtifact")
        if self.data_checkpoint is not None and not isinstance(self.data_checkpoint, DataCheckpoint):
            raise BootControlValidationError("data_checkpoint must be a DataCheckpoint")
        services = tuple(sorted({_text(value, "healthy service") for value in self.healthy_services}))
        object.__setattr__(self, "healthy_services", services)
        if self.attempt_nonce is not None:
            _text(self.attempt_nonce, "attempt_nonce")
        if self.boot_observation is not None and not isinstance(
            self.boot_observation, BootObservation
        ):
            raise BootControlValidationError("boot_observation must be a BootObservation")
        if self.new_fence_epoch is not None:
            _positive(self.new_fence_epoch, "new_fence_epoch")
        if self.new_fence_owner_token is not None:
            _text(self.new_fence_owner_token, "new_fence_owner_token")
        _validate_command_shape(self)

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(_canonical_command(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class MonotonicAnchorUpdate:
    controller_id: str
    expected_generation: int
    expected_commitment_sha256: str
    new_generation: int
    new_commitment_sha256: str


@dataclass(frozen=True, slots=True)
class TransitionReceipt:
    operation_id: str
    kind: CommandKind
    applied_generation: int
    outcome: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class TransitionResult:
    state: BootState
    receipt: TransitionReceipt
    anchor_update: MonotonicAnchorUpdate | None


def initial_boot_state(
    active_release: ReleaseArtifact,
    *,
    controller_id: str,
    active_slot: SlotName = SlotName.A,
    slot_a_stable_id: str = "root-a",
    slot_b_stable_id: str = "root-b",
    data_checkpoint: DataCheckpoint,
    fence_epoch: int,
    fence_owner_token: str,
    guards: TransitionGuards,
    essential_services: tuple[str, ...] = ("control-plane", "state-store"),
) -> BootState:
    """Create and authenticate generation zero for external anchor enrollment."""

    if not isinstance(active_release, ReleaseArtifact) or not active_release.trusted_and_verified:
        raise BootControlValidationError("the initial active release must be trusted and verified")
    if not isinstance(active_slot, SlotName):
        raise BootControlValidationError("active_slot must be a SlotName")
    if slot_a_stable_id == slot_b_stable_id:
        raise BootControlValidationError("A and B cannot alias the same physical stable ID")
    if not isinstance(guards, TransitionGuards):
        raise BootControlValidationError("initial state requires explicit trusted guards")
    if not isinstance(data_checkpoint, DataCheckpoint):
        raise BootControlValidationError("initial data checkpoint must be a DataCheckpoint")
    identity = active_release.identity
    if (
        data_checkpoint.writer_release_manifest_sha256 != identity.manifest_sha256
        or data_checkpoint.schema_id != identity.data_compatibility_id
        or data_checkpoint.writer_fence_epoch != fence_epoch
        or data_checkpoint.writer_owner_token != fence_owner_token
    ):
        raise ExternalEvidenceRejected(
            "initial checkpoint is not bound to the active release, schema, and fence"
        )
    if not guards.data_checkpoint_oracle.verify_durable(data_checkpoint):
        raise ExternalEvidenceRejected("initial checkpoint durability receipt is not trusted")
    if not guards.data_checkpoint_oracle.is_readable(data_checkpoint, identity):
        raise ExternalEvidenceRejected("active release cannot read the initial checkpoint")
    services = tuple(sorted({_text(value, "essential service") for value in essential_services}))
    records = []
    for name, stable_id in (
        (SlotName.A, slot_a_stable_id),
        (SlotName.B, slot_b_stable_id),
    ):
        identity = SlotIdentity(name, stable_id)
        records.append(
            SlotRecord(
                identity,
                active_release if name is active_slot else None,
                SlotStatus.ACTIVE if name is active_slot else SlotStatus.EMPTY,
            )
        )
    state = BootState(
        controller_id=controller_id,
        slots=(records[0], records[1]),
        active_slot=active_slot,
        selected_slot=active_slot,
        phase=UpdatePhase.IDLE,
        candidate=None,
        target_slot=None,
        minimum_release_sequence=active_release.identity.release_sequence,
        trial_failures=0,
        essential_services=services,
        current_attempt_nonce=None,
        used_attempt_nonces=(),
        boot_observation=None,
        health_acknowledgement=None,
        data_checkpoint=data_checkpoint,
        fence_epoch=fence_epoch,
        fence_owner_token=fence_owner_token,
        retired_fence_owner_tokens=(),
        tamper_observations=(),
    )
    tag = guards.state_authenticator.seal(state.authenticated_bytes)
    _text(tag, "authentication tag", maximum=1024)
    authenticated = replace(state, authentication_tag=tag)
    if not guards.state_authenticator.verify(
        authenticated.authenticated_bytes, authenticated.authentication_tag
    ):
        raise StateAuthenticationRejected("state authenticator did not verify the initial seal")
    return authenticated


def transition(
    state: BootState,
    command: BootCommand,
    *,
    guards: TransitionGuards,
) -> TransitionResult:
    """Apply one command after all external anti-rollback preconditions pass.

    The returned anchor update must be committed by a platform adapter after
    atomically persisting the authenticated state. A subsequent transition
    fails until the external anchor represents the returned commitment.
    """

    if not isinstance(state, BootState) or not isinstance(command, BootCommand):
        raise BootControlValidationError("transition requires BootState and BootCommand values")
    if not isinstance(guards, TransitionGuards):
        raise BootControlValidationError("transition requires explicit trusted guards")
    if not guards.state_authenticator.verify(state.authenticated_bytes, state.authentication_tag):
        raise StateAuthenticationRejected("durable boot state authentication failed")
    if not guards.monotonic_anchor.is_current(
        controller_id=state.controller_id,
        generation=state.generation,
        state_commitment_sha256=state.commitment_sha256,
    ):
        raise MonotonicAnchorRejected("durable boot state does not match the external anchor")

    for record in state.operations:
        if record.operation_id == command.operation_id:
            if record.kind is not command.kind or record.request_sha256 != command.request_sha256:
                raise IdempotencyConflict("operation_id was already used by a different request")
            return TransitionResult(
                state,
                TransitionReceipt(
                    record.operation_id,
                    record.kind,
                    record.applied_generation,
                    record.outcome,
                    True,
                ),
                None,
            )
    if (
        command.fence_epoch != state.fence_epoch
        or command.fence_owner_token != state.fence_owner_token
    ):
        raise FenceRejected("command fence does not own the durable boot state")
    if command.expected_generation != state.generation:
        raise StaleGeneration(
            f"expected generation {command.expected_generation}, current generation {state.generation}"
        )

    changed, outcome = _dispatch(state, command, guards)
    applied_generation = state.generation + 1
    previous_hash = state.operations[-1].record_sha256 if state.operations else _CHAIN_ORIGIN
    record_hash = _operation_record_digest(
        command.operation_id,
        command.kind,
        command.request_sha256,
        applied_generation,
        outcome,
        previous_hash,
    )
    record = OperationRecord(
        command.operation_id,
        command.kind,
        command.request_sha256,
        applied_generation,
        outcome,
        previous_hash,
        record_hash,
    )
    unsigned = replace(
        changed,
        generation=applied_generation,
        operations=state.operations + (record,),
    )
    tag = guards.state_authenticator.seal(unsigned.authenticated_bytes)
    _text(tag, "authentication tag", maximum=1024)
    durable = replace(unsigned, authentication_tag=tag)
    if not guards.state_authenticator.verify(durable.authenticated_bytes, durable.authentication_tag):
        raise StateAuthenticationRejected("state authenticator did not verify its new seal")
    anchor_update = MonotonicAnchorUpdate(
        state.controller_id,
        state.generation,
        state.commitment_sha256,
        durable.generation,
        durable.commitment_sha256,
    )
    return TransitionResult(
        durable,
        TransitionReceipt(command.operation_id, command.kind, applied_generation, outcome, False),
        anchor_update,
    )


def _command_artifact(command: BootCommand) -> ReleaseArtifact:
    if command.artifact is None:
        raise BootControlValidationError("validated command is missing its release artifact")
    return command.artifact


def _command_target(command: BootCommand) -> SlotName:
    if command.target_slot is None:
        raise BootControlValidationError("validated command is missing its target slot")
    return command.target_slot


def _update_fields(state: BootState) -> tuple[SlotName, ReleaseArtifact]:
    if state.target_slot is None or state.candidate is None:
        raise BootControlValidationError("durable update state is missing target or candidate")
    return state.target_slot, state.candidate


def _slot_artifact(state: BootState, slot: SlotName) -> ReleaseArtifact:
    artifact = state.slot(slot).artifact
    if artifact is None:
        raise BootControlValidationError("referenced boot slot has no release artifact")
    return artifact


def _command_attempt_nonce(command: BootCommand) -> str:
    if command.attempt_nonce is None:
        raise BootControlValidationError("validated command is missing its boot-attempt nonce")
    return command.attempt_nonce


def _current_attempt_nonce(state: BootState) -> str:
    if state.current_attempt_nonce is None:
        raise BootControlValidationError("first-boot state is missing its attempt nonce")
    return state.current_attempt_nonce


def _command_boot_observation(command: BootCommand) -> BootObservation:
    if command.boot_observation is None:
        raise BootControlValidationError("validated command is missing its boot observation")
    return command.boot_observation


def _command_checkpoint(command: BootCommand) -> DataCheckpoint:
    if command.data_checkpoint is None:
        raise BootControlValidationError("validated command is missing its data checkpoint")
    return command.data_checkpoint


def _fence_rotation(command: BootCommand) -> tuple[int, str]:
    if command.new_fence_epoch is None or command.new_fence_owner_token is None:
        raise BootControlValidationError("validated fence rotation is missing epoch or owner")
    return command.new_fence_epoch, command.new_fence_owner_token


def _dispatch(
    state: BootState,
    command: BootCommand,
    guards: TransitionGuards,
) -> tuple[BootState, str]:
    kind = command.kind
    if kind is CommandKind.BEGIN_DOWNLOAD:
        _require_phase(state, UpdatePhase.IDLE)
        target_slot = _command_target(command)
        artifact = _command_artifact(command)
        if target_slot is state.active_slot:
            raise InvalidTransition("updates may target only the inactive root slot")
        active_artifact = _slot_artifact(state, state.active_slot)
        if artifact.identity == active_artifact.identity:
            raise InvalidTransition("candidate must identify a release other than the active release")
        return (
            replace(
                state,
                phase=UpdatePhase.DOWNLOAD,
                candidate=artifact,
                target_slot=target_slot,
                trial_failures=0,
            ),
            "download-started",
        )

    if kind is CommandKind.DOWNLOAD_COMPLETE:
        _require_phase(state, UpdatePhase.DOWNLOAD)
        return replace(state, phase=UpdatePhase.VERIFY), "download-complete"

    if kind is CommandKind.VERIFY_COMPLETE:
        _require_phase(state, UpdatePhase.VERIFY)
        artifact = _command_artifact(command)
        _target_slot, candidate = _update_fields(state)
        active = _slot_artifact(state, state.active_slot)
        if artifact.identity != candidate.identity or not artifact.trusted_and_verified:
            tamper = _verification_tamper(state, command)
            return (
                replace(
                    _abort_before_write(state),
                    tamper_observations=state.tamper_observations + (tamper,),
                ),
                "tampered-release-rejected",
            )
        identity = artifact.identity
        if (
            identity.data_compatibility_id != active.identity.data_compatibility_id
            or identity.data_compatibility_id != state.data_checkpoint.schema_id
            or identity.release_sequence <= active.identity.release_sequence
            or identity.release_sequence <= state.minimum_release_sequence
        ):
            return _abort_before_write(state), "release-policy-or-downgrade-rejected"
        return replace(state, phase=UpdatePhase.WRITE, candidate=artifact), "release-verified"

    if kind is CommandKind.WRITE_COMPLETE:
        _require_phase(state, UpdatePhase.WRITE)
        target_slot, candidate = _update_fields(state)
        if not candidate.trusted_and_verified:
            raise TamperRejected("unverified candidate cannot enter a root slot")
        target = state.slot(target_slot)
        staged = SlotRecord(target.identity, candidate, SlotStatus.STAGED)
        return (
            replace(state, slots=_replace_slot(state, staged), phase=UpdatePhase.SELECT),
            "inactive-slot-write-complete",
        )

    if kind is CommandKind.SELECT_TRIAL:
        _require_phase(state, UpdatePhase.SELECT)
        target_slot, _candidate = _update_fields(state)
        if state.selected_slot is target_slot:
            raise InvalidTransition("trial target is already selected")
        return replace(state, selected_slot=target_slot), "trial-selected"

    if kind is CommandKind.BEGIN_FIRST_BOOT:
        _require_phase(state, UpdatePhase.SELECT)
        target_slot, _candidate = _update_fields(state)
        attempt_nonce = _command_attempt_nonce(command)
        if state.selected_slot is not target_slot:
            raise InvalidTransition("trial slot must be selected before its first boot")
        if attempt_nonce in state.used_attempt_nonces:
            raise InvalidTransition("boot-attempt nonce has already been used")
        return (
            replace(
                state,
                phase=UpdatePhase.FIRST_BOOT,
                current_attempt_nonce=attempt_nonce,
                used_attempt_nonces=state.used_attempt_nonces + (attempt_nonce,),
            ),
            "first-boot-attempt-recorded",
        )

    if kind is CommandKind.RECORD_BOOT_OBSERVATION:
        _require_phase(state, UpdatePhase.FIRST_BOOT)
        if state.boot_observation is not None:
            raise InvalidTransition("this boot attempt already has a persisted observation")
        observation = _command_boot_observation(command)
        if not guards.boot_observation_verifier.verify_persisted(observation):
            raise ExternalEvidenceRejected("boot observation is not trusted and durably persisted")
        target_slot, candidate = _update_fields(state)
        matches = (
            observation.attempt_nonce == state.current_attempt_nonce
            and observation.actual_slot is target_slot
            and observation.release_manifest_sha256 == candidate.identity.manifest_sha256
            and observation.release_root_sha256 == candidate.identity.root_sha256
            and observation.trusted_and_verified
            and observation.fence_epoch == state.fence_epoch
            and observation.fence_owner_token == state.fence_owner_token
        )
        if not matches:
            _ensure_fallback_readable(state, guards)
            tamper = _boot_tamper(state, command)
            fallen_back = _automatic_fallback(state, failures=state.trial_failures)
            return (
                replace(
                    fallen_back,
                    tamper_observations=state.tamper_observations + (tamper,),
                ),
                "tampered-boot-observation-rejected-and-fallback-selected",
            )
        return replace(state, boot_observation=observation), "boot-observation-persisted"

    if kind is CommandKind.TRIAL_FAILURE:
        _require_phase(state, UpdatePhase.FIRST_BOOT)
        return _record_trial_failure(state, guards)

    if kind is CommandKind.ACK_ESSENTIAL_HEALTH:
        _require_phase(state, UpdatePhase.FIRST_BOOT)
        if state.boot_observation is None:
            raise InvalidTransition("trusted persisted boot observation is required before health")
        if command.healthy_services != state.essential_services:
            raise InvalidTransition("all and only configured essential services must be acknowledged")
        target_slot, candidate = _update_fields(state)
        attempt_nonce = _current_attempt_nonce(state)
        acknowledgement = EssentialHealthAcknowledgement(
            attempt_nonce,
            target_slot,
            candidate.identity.manifest_sha256,
            state.boot_observation.persistence_receipt_sha256,
            state.essential_services,
            state.generation,
        )
        return replace(state, health_acknowledgement=acknowledgement), "essential-health-acknowledged"

    if kind is CommandKind.COMMIT_TRIAL:
        _require_phase(state, UpdatePhase.FIRST_BOOT)
        if state.boot_observation is None or state.health_acknowledgement is None:
            raise InvalidTransition("persisted boot observation and bound health are required")
        attempt_nonce = _current_attempt_nonce(state)
        target_slot, _candidate = _update_fields(state)
        if (
            state.health_acknowledgement.attempt_nonce != attempt_nonce
            or state.boot_observation.attempt_nonce != attempt_nonce
        ):
            raise InvalidTransition("boot observation and health must bind the current attempt")
        target = state.slot(target_slot)
        target_artifact = _slot_artifact(state, target_slot)
        if not guards.data_checkpoint_oracle.is_readable(
            state.data_checkpoint, target_artifact.identity
        ):
            raise ExternalEvidenceRejected("trial release cannot read the acknowledged checkpoint")
        old_active = state.slot(state.active_slot)
        retained = SlotRecord(old_active.identity, old_active.artifact, SlotStatus.RETAINED)
        activated = SlotRecord(target.identity, target_artifact, SlotStatus.ACTIVE)
        slots = _replace_slot_tuple(_replace_slot(state, retained), activated)
        return (
            replace(
                state,
                slots=slots,
                active_slot=target_slot,
                selected_slot=target_slot,
                phase=UpdatePhase.IDLE,
                candidate=None,
                target_slot=None,
                minimum_release_sequence=target_artifact.identity.release_sequence,
                trial_failures=0,
                current_attempt_nonce=None,
                boot_observation=None,
                health_acknowledgement=None,
            ),
            "trial-committed",
        )

    if kind is CommandKind.ACK_DATA_CHECKPOINT:
        proposed = _command_checkpoint(command)
        current = state.data_checkpoint
        writer = _observed_running_release(state)
        if proposed.generation < current.generation:
            raise StaleGeneration("acknowledged data generation cannot move backwards")
        if proposed.generation == current.generation and proposed.sha256 != current.sha256:
            raise TamperRejected("an acknowledged data generation cannot change digest")
        if (
            proposed.writer_fence_epoch != state.fence_epoch
            or proposed.writer_owner_token != state.fence_owner_token
            or proposed.writer_release_manifest_sha256 != writer.manifest_sha256
            or proposed.schema_id != writer.data_compatibility_id
        ):
            raise ExternalEvidenceRejected("checkpoint is not bound to the current writer and fence")
        if not guards.data_checkpoint_oracle.verify_durable(proposed):
            raise ExternalEvidenceRejected("checkpoint durability receipt is not trusted")
        if state.phase is UpdatePhase.FIRST_BOOT:
            retained = _slot_artifact(state, state.active_slot)
            if not guards.data_checkpoint_oracle.is_readable(proposed, retained.identity):
                raise FallbackReadabilityRejected(
                    "retained release cannot read the proposed trial checkpoint"
                )
        return replace(state, data_checkpoint=proposed), "durable-data-checkpoint-acknowledged"

    if kind is CommandKind.RECONCILE_POWER_LOSS:
        return _reconcile_power_loss(state, guards)

    if kind is CommandKind.ROTATE_FENCE:
        _require_phase(state, UpdatePhase.IDLE)
        new_epoch, new_owner = _fence_rotation(command)
        if new_epoch != state.fence_epoch + 1:
            raise FenceRejected("fence epoch must advance by exactly one")
        if new_owner in (
            state.fence_owner_token,
            *state.retired_fence_owner_tokens,
        ):
            raise FenceRejected("fence owner token cannot be reused (ABA)")
        return (
            replace(
                state,
                fence_epoch=new_epoch,
                fence_owner_token=new_owner,
                retired_fence_owner_tokens=state.retired_fence_owner_tokens
                + (state.fence_owner_token,),
            ),
            "fence-rotated",
        )

    raise BootControlValidationError(f"unsupported command: {kind}")


def _record_trial_failure(
    state: BootState, guards: TransitionGuards
) -> tuple[BootState, str]:
    failures = state.trial_failures + 1
    if failures >= MAX_TRIAL_FAILURES:
        _ensure_fallback_readable(state, guards)
        return (
            _automatic_fallback(state, failures=failures),
            "trial-failed-automatic-fallback",
        )
    return (
        replace(
            state,
            phase=UpdatePhase.SELECT,
            trial_failures=failures,
            current_attempt_nonce=None,
            boot_observation=None,
            health_acknowledgement=None,
        ),
        "trial-failed-retry-retained",
    )


def _reconcile_power_loss(
    state: BootState, guards: TransitionGuards
) -> tuple[BootState, str]:
    if state.phase is UpdatePhase.IDLE:
        return state, "power-loss-already-stable"
    if state.phase in {UpdatePhase.DOWNLOAD, UpdatePhase.VERIFY}:
        boundary = state.phase.value
        return _abort_before_write(state), f"power-loss-{boundary}-active-retained"
    if state.phase is UpdatePhase.WRITE:
        target_slot, candidate = _update_fields(state)
        target = state.slot(target_slot)
        rejected = SlotRecord(target.identity, candidate, SlotStatus.REJECTED)
        return (
            replace(
                state,
                slots=_replace_slot(state, rejected),
                selected_slot=state.active_slot,
                phase=UpdatePhase.IDLE,
                candidate=None,
                target_slot=None,
            ),
            "power-loss-write-partial-target-rejected",
        )
    if state.phase is UpdatePhase.SELECT:
        _ensure_fallback_readable(state, guards)
        return (
            replace(
                state,
                selected_slot=state.active_slot,
                phase=UpdatePhase.IDLE,
                candidate=None,
                target_slot=None,
            ),
            "power-loss-select-active-restored",
        )
    if state.phase is UpdatePhase.FIRST_BOOT:
        next_state, outcome = _record_trial_failure(state, guards)
        return next_state, f"power-loss-first-boot-{outcome}"
    raise BootControlValidationError(f"unhandled power-loss phase: {state.phase}")


def _observed_running_release(state: BootState) -> ReleaseIdentity:
    if state.phase is UpdatePhase.FIRST_BOOT:
        if state.boot_observation is None or state.candidate is None:
            raise InvalidTransition(
                "trial data acknowledgement requires a trusted persisted boot observation"
            )
        return state.candidate.identity
    return _slot_artifact(state, state.active_slot).identity


def _ensure_fallback_readable(state: BootState, guards: TransitionGuards) -> None:
    active = _slot_artifact(state, state.active_slot)
    if not guards.data_checkpoint_oracle.is_readable(state.data_checkpoint, active.identity):
        raise FallbackReadabilityRejected(
            "retained active release cannot read the acknowledged data checkpoint"
        )


def _verification_tamper(state: BootState, command: BootCommand) -> TamperObservation:
    target_slot, candidate = _update_fields(state)
    artifact = _command_artifact(command)
    return TamperObservation(
        command.operation_id,
        UpdatePhase.VERIFY,
        target_slot,
        None,
        candidate.identity.manifest_sha256,
        candidate.identity.root_sha256,
        artifact.identity.manifest_sha256,
        artifact.identity.root_sha256,
        artifact.signature_status,
        artifact.integrity_status,
        state.fence_epoch,
        "verification-content-or-trust-mismatch",
    )


def _boot_tamper(state: BootState, command: BootCommand) -> TamperObservation:
    target_slot, candidate = _update_fields(state)
    observation = _command_boot_observation(command)
    return TamperObservation(
        command.operation_id,
        UpdatePhase.FIRST_BOOT,
        target_slot,
        observation.attempt_nonce,
        candidate.identity.manifest_sha256,
        candidate.identity.root_sha256,
        observation.release_manifest_sha256,
        observation.release_root_sha256,
        observation.signature_status,
        observation.integrity_status,
        state.fence_epoch,
        "boot-slot-release-or-fence-mismatch",
    )


def _abort_before_write(state: BootState) -> BootState:
    return replace(
        state,
        selected_slot=state.active_slot,
        phase=UpdatePhase.IDLE,
        candidate=None,
        target_slot=None,
        current_attempt_nonce=None,
        boot_observation=None,
        health_acknowledgement=None,
    )


def _automatic_fallback(state: BootState, *, failures: int) -> BootState:
    """Reject selection while preserving the actual artifact staged in the slot."""

    target_slot, _candidate = _update_fields(state)
    target = state.slot(target_slot)
    if target.artifact is None:
        raise BootControlValidationError("automatic fallback requires a staged target artifact")
    rejected = SlotRecord(target.identity, target.artifact, SlotStatus.REJECTED)
    return replace(
        state,
        slots=_replace_slot(state, rejected),
        selected_slot=state.active_slot,
        phase=UpdatePhase.IDLE,
        candidate=None,
        target_slot=None,
        trial_failures=failures,
        current_attempt_nonce=None,
        boot_observation=None,
        health_acknowledgement=None,
    )


def _require_phase(state: BootState, expected: UpdatePhase) -> None:
    if state.phase is not expected:
        raise InvalidTransition(f"{expected.value} phase required; current phase is {state.phase.value}")


def _replace_slot(state: BootState, replacement: SlotRecord) -> tuple[SlotRecord, SlotRecord]:
    return _replace_slot_tuple(state.slots, replacement)


def _replace_slot_tuple(
    slots: tuple[SlotRecord, SlotRecord], replacement: SlotRecord
) -> tuple[SlotRecord, SlotRecord]:
    values = tuple(
        replacement if slot.identity.name is replacement.identity.name else slot for slot in slots
    )
    return (values[0], values[1])


def _validate_command_shape(command: BootCommand) -> None:
    allowed: dict[CommandKind, set[str]] = {
        CommandKind.BEGIN_DOWNLOAD: {"target_slot", "artifact"},
        CommandKind.VERIFY_COMPLETE: {"artifact"},
        CommandKind.BEGIN_FIRST_BOOT: {"attempt_nonce"},
        CommandKind.RECORD_BOOT_OBSERVATION: {"boot_observation"},
        CommandKind.ACK_ESSENTIAL_HEALTH: {"healthy_services"},
        CommandKind.ACK_DATA_CHECKPOINT: {"data_checkpoint"},
        CommandKind.ROTATE_FENCE: {"new_fence_epoch", "new_fence_owner_token"},
    }
    present: set[str] = set()
    for field, value in (
        ("target_slot", command.target_slot),
        ("artifact", command.artifact),
        ("data_checkpoint", command.data_checkpoint),
        ("attempt_nonce", command.attempt_nonce),
        ("boot_observation", command.boot_observation),
        ("new_fence_epoch", command.new_fence_epoch),
        ("new_fence_owner_token", command.new_fence_owner_token),
    ):
        if value is not None:
            present.add(field)
    if command.healthy_services:
        present.add("healthy_services")
    expected = allowed.get(command.kind, set())
    if present != expected:
        raise BootControlValidationError(
            f"{command.kind.value} payload differs; expected={sorted(expected)}, present={sorted(present)}"
        )


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _identity_document(identity: ReleaseIdentity) -> dict[str, object]:
    return {
        "data_compatibility_id": identity.data_compatibility_id,
        "manifest_sha256": identity.manifest_sha256,
        "release_id": identity.release_id,
        "release_sequence": identity.release_sequence,
        "root_sha256": identity.root_sha256,
        "signer_key_id": identity.signer_key_id,
        "version": identity.version,
    }


def _artifact_document(artifact: ReleaseArtifact | None) -> dict[str, object] | None:
    if artifact is None:
        return None
    return {
        "identity": _identity_document(artifact.identity),
        "integrity_status": artifact.integrity_status.value,
        "signature_status": artifact.signature_status.value,
    }


def _checkpoint_document(checkpoint: DataCheckpoint | None) -> dict[str, object] | None:
    if checkpoint is None:
        return None
    return {
        "durability_receipt_sha256": checkpoint.durability_receipt_sha256,
        "generation": checkpoint.generation,
        "schema_id": checkpoint.schema_id,
        "sha256": checkpoint.sha256,
        "writer_fence_epoch": checkpoint.writer_fence_epoch,
        "writer_owner_token": checkpoint.writer_owner_token,
        "writer_release_manifest_sha256": checkpoint.writer_release_manifest_sha256,
    }


def _observation_document(observation: BootObservation | None) -> dict[str, object] | None:
    if observation is None:
        return None
    return {
        "actual_slot": observation.actual_slot.value,
        "attempt_nonce": observation.attempt_nonce,
        "fence_epoch": observation.fence_epoch,
        "fence_owner_token": observation.fence_owner_token,
        "integrity_status": observation.integrity_status.value,
        "persistence_receipt_sha256": observation.persistence_receipt_sha256,
        "release_manifest_sha256": observation.release_manifest_sha256,
        "release_root_sha256": observation.release_root_sha256,
        "signature_status": observation.signature_status.value,
    }


def _canonical_command(command: BootCommand) -> bytes:
    return _canonical_json(
        {
            "artifact": _artifact_document(command.artifact),
            "attempt_nonce": command.attempt_nonce,
            "boot_observation": _observation_document(command.boot_observation),
            "data_checkpoint": _checkpoint_document(command.data_checkpoint),
            "expected_generation": command.expected_generation,
            "fence_epoch": command.fence_epoch,
            "fence_owner_token": command.fence_owner_token,
            "healthy_services": list(command.healthy_services),
            "kind": command.kind.value,
            "new_fence_epoch": command.new_fence_epoch,
            "new_fence_owner_token": command.new_fence_owner_token,
            "operation_id": command.operation_id,
            "target_slot": command.target_slot.value if command.target_slot is not None else None,
        }
    )


def _canonical_state(state: BootState) -> bytes:
    health = state.health_acknowledgement
    return _canonical_json(
        {
            "active_slot": state.active_slot.value,
            "boot_observation": _observation_document(state.boot_observation),
            "candidate": _artifact_document(state.candidate),
            "controller_id": state.controller_id,
            "current_attempt_nonce": state.current_attempt_nonce,
            "data_checkpoint": _checkpoint_document(state.data_checkpoint),
            "essential_services": list(state.essential_services),
            "fence_epoch": state.fence_epoch,
            "fence_owner_token": state.fence_owner_token,
            "generation": state.generation,
            "health_acknowledgement": None
            if health is None
            else {
                "acknowledged_at_generation": health.acknowledged_at_generation,
                "attempt_nonce": health.attempt_nonce,
                "healthy_services": list(health.healthy_services),
                "observation_receipt_sha256": health.observation_receipt_sha256,
                "release_manifest_sha256": health.release_manifest_sha256,
                "slot": health.slot.value,
            },
            "minimum_release_sequence": state.minimum_release_sequence,
            "operations": [
                {
                    "applied_generation": item.applied_generation,
                    "kind": item.kind.value,
                    "operation_id": item.operation_id,
                    "outcome": item.outcome,
                    "previous_record_sha256": item.previous_record_sha256,
                    "record_sha256": item.record_sha256,
                    "request_sha256": item.request_sha256,
                }
                for item in state.operations
            ],
            "phase": state.phase.value,
            "retired_fence_owner_tokens": list(state.retired_fence_owner_tokens),
            "selected_slot": state.selected_slot.value,
            "slots": [
                {
                    "artifact": _artifact_document(slot.artifact),
                    "name": slot.identity.name.value,
                    "stable_id": slot.identity.stable_id,
                    "status": slot.status.value,
                }
                for slot in state.slots
            ],
            "tamper_observations": [
                {
                    "attempt_nonce": item.attempt_nonce,
                    "expected_manifest_sha256": item.expected_manifest_sha256,
                    "expected_root_sha256": item.expected_root_sha256,
                    "fence_epoch": item.fence_epoch,
                    "observed_integrity_status": item.observed_integrity_status.value,
                    "observed_manifest_sha256": item.observed_manifest_sha256,
                    "observed_root_sha256": item.observed_root_sha256,
                    "observed_signature_status": item.observed_signature_status.value,
                    "operation_id": item.operation_id,
                    "phase": item.phase.value,
                    "reason": item.reason,
                    "target_slot": item.target_slot.value,
                }
                for item in state.tamper_observations
            ],
            "target_slot": state.target_slot.value if state.target_slot is not None else None,
            "trial_failures": state.trial_failures,
            "used_attempt_nonces": list(state.used_attempt_nonces),
        }
    )
