"""Admin-rooted, auditable role and activity delegation.

``Admin`` is a Luma OS control-plane role.  It is deliberately distinct from
the host's root/Administrator account and from an ambient runtime capability.
Only finite activities registered in this authority can be delegated.  The
policy broker still performs its normal resource and operation checks for each
effect.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
import hashlib
import json
import threading
from typing import Callable, Iterable
import uuid


ADMIN_ROLE = "Admin"


class AdministrationError(RuntimeError):
    """Base class for administrative control-plane failures."""


class AdministrationDenied(AdministrationError):
    """The actor does not currently hold the required activity."""


class AdministrationConflict(AdministrationError):
    """A requested update conflicts with current versioned state."""


class AdministrationValidationError(ValueError):
    """A role, activity, subject, or assignment is malformed."""


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise AdministrationValidationError(
            f"{field} must be a non-empty trimmed string up to 256 characters"
        )
    if "\x00" in value or "*" in value:
        raise AdministrationValidationError(f"{field} cannot contain NUL or wildcard characters")
    return value


def _aware_utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AdministrationValidationError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    name: str
    activities: tuple[str, ...]
    version: int = 1

    def __post_init__(self) -> None:
        _identifier(self.name, "role")
        if self.name == ADMIN_ROLE:
            raise AdministrationValidationError("Admin is the fixed root role")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise AdministrationValidationError("role version must be a positive integer")
        activities = tuple(sorted({_identifier(item, "activity") for item in self.activities}))
        if not activities:
            raise AdministrationValidationError("a delegated role needs at least one activity")
        object.__setattr__(self, "activities", activities)


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    assignment_id: str
    subject: str
    role: str
    role_version: int
    activities: tuple[str, ...]
    assigned_by: str
    issued_at: datetime
    expires_at: datetime
    version: int = 1
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        for field in ("assignment_id", "subject", "role", "assigned_by"):
            _identifier(getattr(self, field), field)
        if self.role == ADMIN_ROLE:
            raise AdministrationValidationError(
                "the Admin root cannot be delegated through an ordinary role assignment"
            )
        if (
            not isinstance(self.role_version, int)
            or isinstance(self.role_version, bool)
            or self.role_version < 1
        ):
            raise AdministrationValidationError("role_version must be a positive integer")
        activities = tuple(sorted({_identifier(item, "activity") for item in self.activities}))
        if not activities:
            raise AdministrationValidationError("an assignment needs a finite activity snapshot")
        object.__setattr__(self, "activities", activities)
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise AdministrationValidationError("assignment version must be a positive integer")
        issued = _aware_utc(self.issued_at, "issued_at")
        expires = _aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise AdministrationValidationError("expires_at must be later than issued_at")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", _aware_utc(self.revoked_at, "revoked_at"))

    @property
    def activity_set_digest(self) -> str:
        """Bind an assignment to the exact delegated role revision and activities."""

        payload = {
            "activities": list(self.activities),
            "role": self.role,
            "role_version": self.role_version,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class DelegationReceipt:
    receipt_id: str
    sequence: int
    action: str
    actor: str
    target: str
    state_version: int
    occurred_at: datetime
    previous_digest: str | None
    digest: str


class AdminAuthority:
    """Thread-safe reference authority for the product ``Admin`` role.

    The bootstrap subject is the sole root in this reference contract.  Admin
    implicitly holds every registered activity and may define finite roles,
    assign them to subjects, and revoke those assignments.  It cannot mint
    wildcard activities or pass the Admin root to a model or worker.
    """

    CONTROL_ACTIVITIES = (
        "admin.activity.register",
        "admin.role.define",
        "admin.role.assign",
        "admin.role.revoke",
    )

    def __init__(
        self,
        bootstrap_admin: str,
        *,
        activities: Iterable[str] = (),
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._bootstrap_admin = _identifier(bootstrap_admin, "bootstrap_admin")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self._activities = {
            _identifier(activity, "activity") for activity in (*self.CONTROL_ACTIVITIES, *activities)
        }
        self._roles: dict[str, RoleDefinition] = {}
        self._assignments: dict[str, RoleAssignment] = {}
        self._receipts: list[DelegationReceipt] = []
        self._state_version = 1
        self._lock = threading.RLock()

    @property
    def bootstrap_admin(self) -> str:
        return self._bootstrap_admin

    @property
    def state_version(self) -> int:
        with self._lock:
            return self._state_version

    @property
    def activities(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._activities))

    @property
    def receipts(self) -> tuple[DelegationReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def register_activity(self, actor: str, activity: str) -> str:
        activity = _identifier(activity, "activity")
        with self._lock:
            self.require_activity(actor, "admin.activity.register")
            if activity in self._activities:
                return activity
            self._activities.add(activity)
            self._state_version += 1
            self._record_locked("activity.register", actor, activity)
            return activity

    def define_role(
        self,
        actor: str,
        role: str,
        activities: Iterable[str],
        *,
        expected_version: int | None = None,
    ) -> RoleDefinition:
        candidate = RoleDefinition(role, tuple(activities))
        with self._lock:
            self.require_activity(actor, "admin.role.define")
            unknown = set(candidate.activities) - self._activities
            if unknown:
                raise AdministrationValidationError(
                    f"role refers to unregistered activities: {sorted(unknown)}"
                )
            current = self._roles.get(candidate.name)
            if current is None:
                if expected_version is not None:
                    raise AdministrationConflict("new role must not specify an expected version")
                updated = candidate
            else:
                if expected_version != current.version:
                    raise AdministrationConflict("role version changed")
                updated = replace(candidate, version=current.version + 1)
                if updated.activities == current.activities:
                    return current
            self._roles[updated.name] = updated
            self._state_version += 1
            self._record_locked("role.define", actor, f"{updated.name}@{updated.version}")
            return updated

    def assign_role(
        self,
        actor: str,
        subject: str,
        role: str,
        *,
        expires_at: datetime,
    ) -> RoleAssignment:
        subject = _identifier(subject, "subject")
        role = _identifier(role, "role")
        if role == ADMIN_ROLE:
            raise AdministrationDenied("Admin root delegation is not an ordinary assignable activity")
        expires = _aware_utc(expires_at, "expires_at")
        with self._lock:
            self.require_activity(actor, "admin.role.assign")
            now = _aware_utc(self._clock(), "clock result")
            if role not in self._roles:
                raise AdministrationValidationError("role is not defined")
            role_definition = self._roles[role]
            assignment = RoleAssignment(
                assignment_id=_identifier(self._id_factory(), "assignment_id"),
                subject=subject,
                role=role,
                role_version=role_definition.version,
                activities=role_definition.activities,
                assigned_by=actor,
                issued_at=now,
                expires_at=expires,
            )
            self._assignments[assignment.assignment_id] = assignment
            self._state_version += 1
            self._record_locked(
                "role.assign",
                actor,
                (
                    f"{assignment.assignment_id}:{subject}:{role}"
                    f"@{assignment.role_version}:{assignment.activity_set_digest}"
                ),
            )
            return assignment

    def revoke_assignment(
        self,
        actor: str,
        assignment_id: str,
        *,
        expected_version: int,
    ) -> RoleAssignment:
        assignment_id = _identifier(assignment_id, "assignment_id")
        with self._lock:
            self.require_activity(actor, "admin.role.revoke")
            current = self._assignments.get(assignment_id)
            if current is None:
                raise AdministrationConflict("assignment does not exist")
            if current.version != expected_version:
                raise AdministrationConflict("assignment version changed")
            if current.revoked_at is not None:
                return current
            revoked = replace(
                current,
                version=current.version + 1,
                revoked_at=_aware_utc(self._clock(), "clock result"),
            )
            self._assignments[assignment_id] = revoked
            self._state_version += 1
            self._record_locked("role.revoke", actor, f"{assignment_id}@{revoked.version}")
            return revoked

    def has_activity(
        self,
        subject: str,
        activity: str,
        *,
        at: datetime | None = None,
    ) -> bool:
        subject = _identifier(subject, "subject")
        activity = _identifier(activity, "activity")
        now = _aware_utc(at or self._clock(), "authorization time")
        with self._lock:
            if activity not in self._activities:
                return False
            if subject == self._bootstrap_admin:
                return True
            for assignment in self._assignments.values():
                if (
                    assignment.subject == subject
                    and assignment.revoked_at is None
                    and assignment.issued_at <= now < assignment.expires_at
                ):
                    if activity in assignment.activities:
                        return True
            return False

    def get_assignment(self, assignment_id: str) -> RoleAssignment | None:
        """Return the immutable activity snapshot for an exact assignment ID."""

        assignment_id = _identifier(assignment_id, "assignment_id")
        with self._lock:
            return self._assignments.get(assignment_id)

    def require_activity(self, subject: str, activity: str) -> None:
        if not self.has_activity(subject, activity):
            raise AdministrationDenied(f"{subject!r} lacks administrative activity {activity!r}")

    def _record_locked(self, action: str, actor: str, target: str) -> None:
        occurred = _aware_utc(self._clock(), "clock result")
        previous = self._receipts[-1].digest if self._receipts else None
        sequence = len(self._receipts) + 1
        receipt_id = _identifier(self._id_factory(), "receipt_id")
        payload = {
            "action": action,
            "actor": actor,
            "occurred_at": occurred.isoformat(),
            "previous_digest": previous,
            "receipt_id": receipt_id,
            "sequence": sequence,
            "state_version": self._state_version,
            "target": target,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._receipts.append(
            DelegationReceipt(
                receipt_id=receipt_id,
                sequence=sequence,
                action=action,
                actor=actor,
                target=target,
                state_version=self._state_version,
                occurred_at=occurred,
                previous_digest=previous,
                digest=digest,
            )
        )
