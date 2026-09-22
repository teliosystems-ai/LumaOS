"""Deny-by-default typed capability policy reference contract."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import threading
from typing import Callable
import uuid


class PolicyError(RuntimeError):
    """Base class for expected policy failures."""


class PolicyValidationError(ValueError):
    """A grant or request is malformed."""


class PolicyConflict(PolicyError):
    """A policy update conflicts with the installed version."""


class PolicyDenied(PolicyError):
    """No current capability grant authorizes an effect."""

    def __init__(self, decision: "PolicyDecision") -> None:
        super().__init__(decision.reason_code.value)
        self.decision = decision


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ReasonCode(str, Enum):
    ALLOWED = "allowed"
    NO_MATCHING_GRANT = "no_matching_grant"
    SUBJECT_MISMATCH = "subject_mismatch"
    CAPABILITY_MISMATCH = "capability_mismatch"
    RESOURCE_MISMATCH = "resource_mismatch"
    OPERATION_DENIED = "operation_denied"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    STALE_VERSION = "stale_version"


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise PolicyValidationError(f"{field} must be a non-empty trimmed string up to 256 characters")
    if "\x00" in value or "*" in value:
        raise PolicyValidationError(f"{field} cannot contain NUL or wildcard characters")
    return value


def _aware_utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PolicyValidationError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    grant_id: str
    subject: str
    capability: str
    resource_kind: str
    resource_id: str
    operations: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    version: int = 1
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        for field in ("grant_id", "subject", "capability", "resource_kind", "resource_id"):
            _identifier(getattr(self, field), field)
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise PolicyValidationError("version must be a positive integer")
        operations = tuple(sorted({_identifier(item, "operation") for item in self.operations}))
        if not operations:
            raise PolicyValidationError("at least one operation is required")
        object.__setattr__(self, "operations", operations)
        issued = _aware_utc(self.issued_at, "issued_at")
        expires = _aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise PolicyValidationError("expires_at must be later than issued_at")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", _aware_utc(self.revoked_at, "revoked_at"))


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    subject: str
    capability: str
    resource_kind: str
    resource_id: str
    operation: str
    expected_grant_id: str | None = None
    expected_grant_version: int | None = None

    def __post_init__(self) -> None:
        for field in ("subject", "capability", "resource_kind", "resource_id", "operation"):
            _identifier(getattr(self, field), field)
        if self.expected_grant_id is not None:
            _identifier(self.expected_grant_id, "expected_grant_id")
        if self.expected_grant_version is not None and (
            not isinstance(self.expected_grant_version, int)
            or isinstance(self.expected_grant_version, bool)
            or self.expected_grant_version < 1
        ):
            raise PolicyValidationError("expected_grant_version must be a positive integer")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision_id: str
    policy_version: int
    policy_digest: str
    outcome: DecisionOutcome
    reason_code: ReasonCode
    subject: str
    capability: str
    resource_kind: str
    resource_id: str
    operation: str
    evaluated_at: datetime
    grant_id: str | None = None
    grant_version: int | None = None
    evaluated_constraints: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.outcome is DecisionOutcome.ALLOW


class PolicyBroker:
    """Thread-safe reference broker that re-evaluates a grant per effect."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        grant_mutation_authorizer: Callable[[str, str], None] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self._grant_mutation_authorizer = grant_mutation_authorizer
        self._grants: dict[str, CapabilityGrant] = {}
        self._policy_version = 0
        self._lock = threading.RLock()

    @property
    def policy_version(self) -> int:
        with self._lock:
            return self._policy_version

    def install(self, grant: CapabilityGrant, *, actor: str | None = None) -> CapabilityGrant:
        if not isinstance(grant, CapabilityGrant):
            raise PolicyValidationError("grant must be a CapabilityGrant")
        self._authorize_grant_mutation(actor, "policy.grant.install")
        with self._lock:
            existing = self._grants.get(grant.grant_id)
            if existing is not None and grant.version <= existing.version:
                if grant == existing:
                    return existing
                raise PolicyConflict("grant update must advance its version")
            self._grants[grant.grant_id] = grant
            self._policy_version += 1
            return grant

    def revoke(
        self,
        grant_id: str,
        *,
        expected_version: int,
        actor: str | None = None,
    ) -> CapabilityGrant:
        _identifier(grant_id, "grant_id")
        self._authorize_grant_mutation(actor, "policy.grant.revoke")
        with self._lock:
            current = self._grants.get(grant_id)
            if current is None:
                raise PolicyConflict("grant does not exist")
            if current.version != expected_version:
                raise PolicyConflict("grant version changed")
            if current.revoked_at is not None:
                return current
            revoked = replace(
                current,
                version=current.version + 1,
                revoked_at=_aware_utc(self._clock(), "clock result"),
            )
            self._grants[grant_id] = revoked
            self._policy_version += 1
            return revoked

    def _authorize_grant_mutation(self, actor: str | None, activity: str) -> None:
        if self._grant_mutation_authorizer is None:
            return
        if actor is None:
            raise PolicyDenied(
                self._administrative_denial(activity, ReasonCode.NO_MATCHING_GRANT)
            )
        _identifier(actor, "actor")
        try:
            self._grant_mutation_authorizer(actor, activity)
        except Exception as exc:
            raise PolicyDenied(
                self._administrative_denial(activity, ReasonCode.NO_MATCHING_GRANT, actor=actor)
            ) from exc

    def _administrative_denial(
        self,
        activity: str,
        reason: ReasonCode,
        *,
        actor: str = "unauthenticated",
    ) -> PolicyDecision:
        now = _aware_utc(self._clock(), "clock result")
        with self._lock:
            version = self._policy_version
            digest = self._digest_locked()
        return PolicyDecision(
            decision_id=_identifier(self._id_factory(), "decision_id"),
            policy_version=version,
            policy_digest=digest,
            outcome=DecisionOutcome.DENY,
            reason_code=reason,
            subject=actor,
            capability="policy.administration",
            resource_kind="policy-store",
            resource_id="capability-grants",
            operation=activity,
            evaluated_at=now,
            evaluated_constraints=("authenticated-admin-activity",),
        )

    def decide(self, request: PolicyRequest, *, at: datetime | None = None) -> PolicyDecision:
        if not isinstance(request, PolicyRequest):
            raise PolicyValidationError("request must be a PolicyRequest")
        now = _aware_utc(at or self._clock(), "decision time")
        with self._lock:
            candidates = list(self._grants.values())
            policy_version = self._policy_version
            policy_digest = self._digest_locked()

        selected: CapabilityGrant | None = None
        reason = ReasonCode.NO_MATCHING_GRANT
        if request.expected_grant_id is not None:
            selected = next((item for item in candidates if item.grant_id == request.expected_grant_id), None)
            if selected is None:
                reason = ReasonCode.NO_MATCHING_GRANT
        else:
            selected = next(
                (
                    item
                    for item in candidates
                    if item.subject == request.subject
                    and item.capability == request.capability
                    and item.resource_kind == request.resource_kind
                    and item.resource_id == request.resource_id
                    and request.operation in item.operations
                ),
                None,
            )

        if selected is not None:
            if selected.subject != request.subject:
                reason = ReasonCode.SUBJECT_MISMATCH
            elif selected.capability != request.capability:
                reason = ReasonCode.CAPABILITY_MISMATCH
            elif selected.resource_kind != request.resource_kind or selected.resource_id != request.resource_id:
                reason = ReasonCode.RESOURCE_MISMATCH
            elif request.operation not in selected.operations:
                reason = ReasonCode.OPERATION_DENIED
            elif request.expected_grant_version is not None and request.expected_grant_version != selected.version:
                reason = ReasonCode.STALE_VERSION
            elif selected.revoked_at is not None:
                reason = ReasonCode.REVOKED
            elif now < selected.issued_at:
                reason = ReasonCode.NOT_YET_VALID
            elif now >= selected.expires_at:
                reason = ReasonCode.EXPIRED
            else:
                reason = ReasonCode.ALLOWED

        allowed = reason is ReasonCode.ALLOWED
        return PolicyDecision(
            decision_id=_identifier(self._id_factory(), "decision_id"),
            policy_version=policy_version,
            policy_digest=policy_digest,
            outcome=DecisionOutcome.ALLOW if allowed else DecisionOutcome.DENY,
            reason_code=reason,
            subject=request.subject,
            capability=request.capability,
            resource_kind=request.resource_kind,
            resource_id=request.resource_id,
            operation=request.operation,
            evaluated_at=now,
            grant_id=selected.grant_id if selected else None,
            grant_version=selected.version if selected else None,
            evaluated_constraints=(
                "subject",
                "capability",
                "resource",
                "operation",
                "grant-version",
                "validity-window",
                "revocation",
            ),
        )

    def require(self, request: PolicyRequest, *, at: datetime | None = None) -> PolicyDecision:
        decision = self.decide(request, at=at)
        if not decision.allowed:
            raise PolicyDenied(decision)
        return decision

    def _digest_locked(self) -> str:
        grants = [
            {
                "grant_id": grant.grant_id,
                "subject": grant.subject,
                "capability": grant.capability,
                "resource_kind": grant.resource_kind,
                "resource_id": grant.resource_id,
                "operations": list(grant.operations),
                "issued_at": grant.issued_at.isoformat(),
                "expires_at": grant.expires_at.isoformat(),
                "version": grant.version,
                "revoked_at": grant.revoked_at.isoformat() if grant.revoked_at else None,
            }
            for grant in sorted(self._grants.values(), key=lambda item: item.grant_id)
        ]
        encoded = json.dumps(
            {"policy_version": self._policy_version, "grants": grants},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
