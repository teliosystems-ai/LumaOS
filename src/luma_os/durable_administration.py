"""Integrity-protected durable Admin authorization event log for signed catalogs.

The database is an append-only convenience copy, not a rollback authority.
Every event is canonical ASCII JSON, chained by SHA-256, authenticated with an
injected HMAC-SHA256 secret that is never stored in SQLite, and committed to an
independent :class:`~luma_os.monotonic_anchor.ExternalDigestAnchor`.  HMAC
proves at-rest integrity and that this store accepted the event; it does not
authenticate the human or service that originated it.  A mandatory injected
``AdminEventWriterAuthorizer`` delegates that identity, policy, and exact
receipt check to an external authenticated Admin service immediately before
append.  Production process isolation and a concrete OS-authenticated Admin
service adapter remain platform responsibilities.

Reads and authorization checks fail closed unless the database head exactly
matches the external checkpoint.  The strength and durability of rollback
protection are therefore those of the injected anchor;
``InMemoryDigestAnchor`` is suitable only for tests and development.

No private signing key, key generation, or privileged host operation is part
of this module.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Callable, Iterator, Mapping, Protocol

from .administration import RoleAssignment
from .model_catalog_signing import (
    CatalogApproval,
    CatalogAuthorizationVerifier,
    CatalogSignatureStatement,
    canonical_json_bytes,
)
from .monotonic_anchor import DigestCheckpoint, ExternalDigestAnchor


SCHEMA_VERSION = 1
APPLICATION_ID = 0x4C554D41
ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE = "luma-os/admin-authorization-events/v1"
MAX_EVENT_BYTES = 128 * 1024
MAX_EVENTS = 10_000
MAX_ACTIVITIES_PER_ASSIGNMENT = 128
MAX_CATALOG_AUTHORIZATION_BATCH_APPROVALS = 16
MAX_DATABASE_BYTES = 512 * 1024 * 1024
JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
_HMAC_DOMAIN = b"LUMA-OS-ADMIN-AUTHORIZATION-EVENT-HMAC-SHA256-V1\x00"
_EVENT_TYPES = frozenset(
    {
        "assignment-grant",
        "assignment-revoke",
        "catalog-approval-authorization",
        "catalog-signing-authorization",
    }
)


class DurableAdministrationError(RuntimeError):
    """Base class for durable Admin authorization failures."""


class DurableAdministrationValidationError(ValueError):
    """A caller value is outside the closed durable contract."""


class DurableAdministrationIntegrityError(DurableAdministrationError):
    """Stored bytes, schema, chain, or authentication cannot be trusted."""


class DurableAdministrationDenied(DurableAdministrationError):
    """An event is not authorized by the exact assignment snapshot."""


class DurableAdministrationAnchorConflict(DurableAdministrationIntegrityError):
    """The external rollback checkpoint differs or rejected an update."""


class DurableAdministrationReconciliationRequired(
    DurableAdministrationAnchorConflict
):
    """SQLite and the external anchor may differ; no authority may be used.

    SQLite commit and external CAS are intentionally not described as one
    atomic transaction.  This state is never auto-replayed or silently rolled
    back because either side may already be durable.
    """


class DurableAdministrationClockRollback(DurableAdministrationIntegrityError):
    """The observed clock is behind the durable recorded-time high-water mark."""


class DurableAdministrationCapacityExceeded(DurableAdministrationError):
    """The configured hard event bound has been reached."""


class AdminEventWriterAuthorizer(Protocol):
    """External authenticated Admin-service boundary for exact append intent.

    Implementations must authenticate their caller and validate the complete
    immutable object and receipt arguments.  Returning a merely role-wide or
    principal-wide decision is insufficient.
    """

    def assignment_grant_is_authorized(
        self,
        assignment: RoleAssignment,
        *,
        assignment_receipt_sha256: str,
        at: datetime,
    ) -> bool: ...

    def assignment_revoke_is_authorized(
        self,
        assignment: RoleAssignment,
        *,
        revocation_receipt_sha256: str,
        revoked_by: str,
        at: datetime,
    ) -> bool: ...

    def catalog_approval_is_authorized(
        self,
        approval: CatalogApproval,
        *,
        at: datetime,
    ) -> bool: ...

    def catalog_signing_is_authorized(
        self,
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class AdminAuthorizationEventReceipt:
    """Receipt returned only after SQLite durability and external anchoring."""

    sequence: int
    event_type: str
    occurred_at: datetime
    recorded_at: datetime
    previous_event_sha256: str | None
    event_sha256: str
    event_hmac_sha256: str
    anchor_checkpoint: DigestCheckpoint


@dataclass(slots=True)
class _AssignmentState:
    assignment: RoleAssignment
    grant_receipt_sha256: str
    revoke_receipt_sha256: str | None = None


@dataclass(slots=True)
class _VerifiedState:
    assignments: dict[str, _AssignmentState]
    assignment_receipts: set[str]
    approval_payload_sha256: set[str]
    approval_decision_receipts: set[str]
    signing_statement_sha256: set[str]
    count: int = 0
    head_sha256: str | None = None
    last_occurred_at: datetime | None = None
    last_recorded_at: datetime | None = None

    @property
    def checkpoint(self) -> DigestCheckpoint | None:
        if self.count == 0:
            return None
        if self.head_sha256 is None:
            raise DurableAdministrationIntegrityError(
                "non-empty Admin event state has no head digest"
            )
        return DigestCheckpoint(
            namespace=ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE,
            generation=self.count,
            sequence=self.count,
            artifact_sha256=self.head_sha256,
        )


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or "*" in value
    ):
        raise DurableAdministrationValidationError(
            f"{field} must be non-empty trimmed printable ASCII without wildcards"
        )
    return value


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DurableAdministrationValidationError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_integer(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= JSON_SAFE_INTEGER_MAX
    ):
        raise DurableAdministrationValidationError(
            f"{field} must be a positive JSON-safe integer"
        )
    return value


def _aware_second(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DurableAdministrationValidationError(f"{field} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        raise DurableAdministrationValidationError(
            f"{field} must use second precision"
        )
    return normalized


def _timestamp(value: object, field: str) -> str:
    return _aware_second(value, field).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) != 20:
        raise DurableAdministrationIntegrityError(
            f"stored {field} is not second-precision UTC"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DurableAdministrationIntegrityError(
            f"stored {field} is not second-precision UTC"
        ) from exc
    return parsed


def _strict_mapping(
    value: object,
    *,
    required: frozenset[str],
    field: str,
    stored: bool,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        error = (
            DurableAdministrationIntegrityError
            if stored
            else DurableAdministrationValidationError
        )
        raise error(f"{field} must be an object with string keys")
    keys = set(value)
    if keys != required:
        error = (
            DurableAdministrationIntegrityError
            if stored
            else DurableAdministrationValidationError
        )
        raise error(
            f"{field} fields differ; missing={sorted(required - keys)}, "
            f"unexpected={sorted(keys - required)}"
        )
    return value


def _validate_json_domain(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > 16 or nodes > 8192:
            raise DurableAdministrationValidationError(
                "Admin event exceeds structural JSON limits"
            )
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int) and not isinstance(current, bool):
            if abs(current) > JSON_SAFE_INTEGER_MAX:
                raise DurableAdministrationValidationError(
                    "Admin event integer is outside the JSON-safe range"
                )
            continue
        if isinstance(current, str):
            if any(ord(character) < 0x20 or ord(character) > 0x7E for character in current):
                raise DurableAdministrationValidationError(
                    "Admin event strings must use printable ASCII"
                )
            continue
        if isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, Mapping):
            if any(not isinstance(key, str) for key in current):
                raise DurableAdministrationValidationError(
                    "Admin event object keys must be strings"
                )
            stack.extend((key, depth + 1) for key in current)
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise DurableAdministrationValidationError(
            "Admin event contains an unsupported JSON value"
        )


def canonical_admin_event_bytes(value: Mapping[str, object]) -> bytes:
    """Return the closed canonical ASCII representation used by this log."""

    _validate_json_domain(value)
    try:
        result = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DurableAdministrationValidationError(
            "Admin event cannot be canonically encoded"
        ) from exc
    if not result or len(result) > MAX_EVENT_BYTES:
        raise DurableAdministrationValidationError(
            "Admin event exceeds the canonical byte limit"
        )
    return result


def _parse_canonical_event(raw: object) -> Mapping[str, object]:
    if not isinstance(raw, str):
        raise DurableAdministrationIntegrityError(
            "stored Admin event must be canonical ASCII text"
        )
    try:
        encoded = raw.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DurableAdministrationIntegrityError(
            "stored Admin event is not ASCII"
        ) from exc
    if not encoded or len(encoded) > MAX_EVENT_BYTES:
        raise DurableAdministrationIntegrityError(
            "stored Admin event exceeds its byte bound"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise DurableAdministrationIntegrityError(
                    "stored Admin event contains a duplicate key"
                )
            result[key] = item
        return result

    def parse_integer(token: str) -> int:
        if len(token.lstrip("-")) > 16:
            raise DurableAdministrationIntegrityError(
                "stored Admin event integer token is too long"
            )
        number = int(token)
        if abs(number) > JSON_SAFE_INTEGER_MAX:
            raise DurableAdministrationIntegrityError(
                "stored Admin event integer is outside the JSON-safe range"
            )
        return number

    def reject_number(token: str) -> object:
        raise DurableAdministrationIntegrityError(
            f"stored Admin event contains unsupported number {token!r}"
        )

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_int=parse_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except DurableAdministrationIntegrityError:
        raise
    except (ValueError, RecursionError, MemoryError) as exc:
        raise DurableAdministrationIntegrityError(
            "stored Admin event is not valid JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise DurableAdministrationIntegrityError(
            "stored Admin event must contain an object"
        )
    try:
        canonical = canonical_admin_event_bytes(value)
    except DurableAdministrationValidationError as exc:
        raise DurableAdministrationIntegrityError(str(exc)) from exc
    if not hmac.compare_digest(canonical, encoded):
        raise DurableAdministrationIntegrityError(
            "stored Admin event is not canonical"
        )
    return value


def _assignment_payload(assignment: RoleAssignment) -> dict[str, object]:
    if not isinstance(assignment, RoleAssignment):
        raise DurableAdministrationValidationError(
            "assignment must be a RoleAssignment snapshot"
        )
    for field_name in ("assignment_id", "subject", "role", "assigned_by"):
        _identifier(getattr(assignment, field_name), f"assignment.{field_name}")
    _positive_integer(assignment.role_version, "assignment.role_version")
    _positive_integer(assignment.version, "assignment.version")
    if (
        not isinstance(assignment.activities, tuple)
        or not assignment.activities
        or len(assignment.activities) > MAX_ACTIVITIES_PER_ASSIGNMENT
    ):
        raise DurableAdministrationValidationError(
            "assignment activities exceed the finite activity bound"
        )
    activities = tuple(
        _identifier(item, "assignment activity") for item in assignment.activities
    )
    if activities != tuple(sorted(set(activities))):
        raise DurableAdministrationValidationError(
            "assignment activities must be unique and canonically ordered"
        )
    issued_at = _aware_second(assignment.issued_at, "assignment.issued_at")
    expires_at = _aware_second(assignment.expires_at, "assignment.expires_at")
    if expires_at <= issued_at:
        raise DurableAdministrationValidationError(
            "assignment expires_at must follow issued_at"
        )
    revoked_at = (
        _aware_second(assignment.revoked_at, "assignment.revoked_at")
        if assignment.revoked_at is not None
        else None
    )
    if revoked_at is not None and revoked_at < issued_at:
        raise DurableAdministrationValidationError(
            "assignment revoked_at cannot precede issued_at"
        )
    return {
        "activities": list(activities),
        "activity_set_sha256": assignment.activity_set_digest,
        "assigned_by": assignment.assigned_by,
        "assignment_id": assignment.assignment_id,
        "expires_at": _timestamp(expires_at, "assignment.expires_at"),
        "issued_at": _timestamp(issued_at, "assignment.issued_at"),
        "revoked_at": (
            _timestamp(revoked_at, "assignment.revoked_at")
            if revoked_at is not None
            else None
        ),
        "role": assignment.role,
        "role_version": assignment.role_version,
        "subject": assignment.subject,
        "version": assignment.version,
    }


def _assignment_from_payload(value: object) -> RoleAssignment:
    data = _strict_mapping(
        value,
        required=frozenset(
            {
                "activities",
                "activity_set_sha256",
                "assigned_by",
                "assignment_id",
                "expires_at",
                "issued_at",
                "revoked_at",
                "role",
                "role_version",
                "subject",
                "version",
            }
        ),
        field="stored assignment",
        stored=True,
    )
    activities = data["activities"]
    if not isinstance(activities, list):
        raise DurableAdministrationIntegrityError(
            "stored assignment activities must be an array"
        )
    revoked = data["revoked_at"]
    try:
        assignment = RoleAssignment(
            assignment_id=data["assignment_id"],  # type: ignore[arg-type]
            subject=data["subject"],  # type: ignore[arg-type]
            role=data["role"],  # type: ignore[arg-type]
            role_version=data["role_version"],  # type: ignore[arg-type]
            activities=tuple(activities),
            assigned_by=data["assigned_by"],  # type: ignore[arg-type]
            issued_at=_parse_timestamp(data["issued_at"], "assignment.issued_at"),
            expires_at=_parse_timestamp(data["expires_at"], "assignment.expires_at"),
            version=data["version"],  # type: ignore[arg-type]
            revoked_at=(
                _parse_timestamp(revoked, "assignment.revoked_at")
                if revoked is not None
                else None
            ),
        )
        canonical = _assignment_payload(assignment)
    except DurableAdministrationIntegrityError:
        raise
    except Exception as exc:
        raise DurableAdministrationIntegrityError(
            "stored assignment snapshot is invalid"
        ) from exc
    if canonical != dict(data):
        raise DurableAdministrationIntegrityError(
            "stored assignment snapshot is not canonical or digest-bound"
        )
    return assignment


def _validate_database_path(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise DurableAdministrationValidationError(
            "durable Admin database path must be absolute"
        )
    parent = candidate.parent
    if not parent.exists() or not parent.is_dir():
        raise DurableAdministrationValidationError(
            "durable Admin database parent must already exist"
        )

    def is_link_or_reparse(item: Path) -> bool:
        details = item.lstat()
        attributes = getattr(details, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return item.is_symlink() or bool(attributes & reparse)

    cursor = parent
    while True:
        if cursor.exists() and is_link_or_reparse(cursor):
            raise DurableAdministrationValidationError(
                "durable Admin database path cannot traverse a link or reparse point"
            )
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    if candidate.exists() and (
        is_link_or_reparse(candidate) or not candidate.is_file()
    ):
        raise DurableAdministrationValidationError(
            "durable Admin database must be a regular non-link file"
        )
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(candidate) + suffix)
        if sidecar.exists() and (is_link_or_reparse(sidecar) or not sidecar.is_file()):
            raise DurableAdministrationValidationError(
                "durable Admin database sidecars must be regular non-link files"
            )
    if os.name == "posix" and stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise DurableAdministrationValidationError(
            "durable Admin database parent must not grant group/other access"
        )
    return candidate


_CREATE_STATEMENTS = (
    """
    CREATE TABLE admin_authorization_events (
        sequence INTEGER PRIMARY KEY CHECK (
            sequence >= 1 AND sequence <= 9007199254740991
        ),
        event_type TEXT NOT NULL CHECK (
            event_type IN (
                'assignment-grant',
                'assignment-revoke',
                'catalog-approval-authorization',
                'catalog-signing-authorization'
            )
        ),
        occurred_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_sha256 TEXT NOT NULL UNIQUE,
        auth_tag TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX admin_authorization_events_type_sequence
    ON admin_authorization_events(event_type, sequence)
    """,
)

_EXPECTED_COLUMNS = (
    ("sequence", "INTEGER", 0, 1),
    ("event_type", "TEXT", 1, 0),
    ("occurred_at", "TEXT", 1, 0),
    ("recorded_at", "TEXT", 1, 0),
    ("event_json", "TEXT", 1, 0),
    ("event_sha256", "TEXT", 1, 0),
    ("auth_tag", "TEXT", 1, 0),
)

_EXPECTED_SCHEMA_OBJECTS = frozenset(
    {
        (
            "index",
            "admin_authorization_events_type_sequence",
            "admin_authorization_events",
        ),
        (
            "index",
            "sqlite_autoindex_admin_authorization_events_1",
            "admin_authorization_events",
        ),
        (
            "table",
            "admin_authorization_events",
            "admin_authorization_events",
        ),
    }
)

_EXPECTED_INDEXES = {
    "admin_authorization_events_type_sequence": (
        0,
        "c",
        0,
        ("event_type", "sequence"),
    ),
    "sqlite_autoindex_admin_authorization_events_1": (
        1,
        "u",
        0,
        ("event_sha256",),
    ),
}


class DurableAdminAuthorizationStore:
    """Append-only catalog authorization events with an external exact head.

    Each successful mutation commits the SQLite row with ``synchronous=FULL``
    before advancing ``anchor`` by compare-and-swap.  If the external step is
    rejected or its result cannot be read back exactly, the instance fences
    itself and returns no receipt.  A reopened store is usable only when its
    complete authenticated log and the external checkpoint agree exactly.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        integrity_secret: bytes,
        anchor: ExternalDigestAnchor,
        writer_authorizer: AdminEventWriterAuthorizer,
        clock: Callable[[], datetime] | None = None,
        capacity: int = MAX_EVENTS,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        self.path = _validate_database_path(path)
        if (
            not isinstance(integrity_secret, bytes)
            or not 32 <= len(integrity_secret) <= 4096
        ):
            raise DurableAdministrationValidationError(
                "integrity_secret must contain 32 to 4096 bytes"
            )
        if not callable(getattr(anchor, "read", None)) or not callable(
            getattr(anchor, "compare_and_swap", None)
        ):
            raise DurableAdministrationValidationError(
                "anchor must provide read and compare_and_swap operations"
            )
        writer_methods = (
            "assignment_grant_is_authorized",
            "assignment_revoke_is_authorized",
            "catalog_approval_is_authorized",
            "catalog_signing_is_authorized",
        )
        if any(
            not callable(getattr(writer_authorizer, method, None))
            for method in writer_methods
        ):
            raise DurableAdministrationValidationError(
                "writer_authorizer must implement every exact Admin event check"
            )
        if clock is not None and not callable(clock):
            raise DurableAdministrationValidationError("clock must be callable")
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or not 1 <= capacity <= MAX_EVENTS
        ):
            raise DurableAdministrationValidationError(
                f"capacity must be between 1 and {MAX_EVENTS}"
            )
        if (
            not isinstance(busy_timeout_seconds, (int, float))
            or isinstance(busy_timeout_seconds, bool)
            or not 0 < busy_timeout_seconds <= 60
        ):
            raise DurableAdministrationValidationError(
                "busy_timeout_seconds must be greater than zero and at most 60"
            )
        self._secret = bytes(integrity_secret)
        self._anchor = anchor
        self._writer_authorizer = writer_authorizer
        self._clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))
        self._capacity = capacity
        self._busy_timeout_ms = max(1, int(float(busy_timeout_seconds) * 1000))
        self._lock = threading.RLock()
        self._closed = False
        self._fenced = False
        self._initialize()

    def __enter__(self) -> "DurableAdminAuthorizationStore":
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._secret = b""

    @property
    def anchor_namespace(self) -> str:
        return ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE

    @property
    def checkpoint(self) -> DigestCheckpoint | None:
        """Return the exact externally confirmed head after full verification."""

        with self._lock:
            state = self._verified_state_locked()
            return state.checkpoint

    def authorization_verifier(self) -> "DurableCatalogAuthorizationVerifier":
        return DurableCatalogAuthorizationVerifier(self)

    def integrity_check(self) -> None:
        with self._lock:
            self._verified_state_locked()

    def _ensure_open(self) -> None:
        if self._closed:
            raise DurableAdministrationIntegrityError(
                "durable Admin authorization store is closed"
            )
        if self._fenced:
            raise DurableAdministrationReconciliationRequired(
                "durable Admin authorization store is fenced pending explicit reconciliation"
            )

    def _now(self) -> datetime:
        return _aware_second(self._clock(), "clock result")

    def _check_file_bounds(self) -> None:
        total = 0
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                try:
                    total += candidate.stat().st_size
                except OSError as exc:
                    raise DurableAdministrationIntegrityError(
                        "durable Admin database size cannot be inspected"
                    ) from exc
        if total > MAX_DATABASE_BYTES:
            raise DurableAdministrationIntegrityError(
                "durable Admin database exceeds its byte bound"
            )

    def _connect(self) -> sqlite3.Connection:
        try:
            _validate_database_path(self.path)
        except DurableAdministrationValidationError as exc:
            raise DurableAdministrationIntegrityError(
                "durable Admin database path is no longer trustworthy"
            ) from exc
        self._check_file_bounds()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            if hasattr(connection, "setlimit"):
                connection.setlimit(
                    sqlite3.SQLITE_LIMIT_LENGTH,
                    MAX_EVENT_BYTES + 64 * 1024,
                )
                connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.close()
            raise DurableAdministrationIntegrityError(
                "cannot open durable Admin SQLite store"
            ) from exc

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        began = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            began = True
            yield connection
            connection.execute("COMMIT")
        except DurableAdministrationError:
            if began:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if began:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise DurableAdministrationIntegrityError(
                "durable Admin SQLite transaction failed"
            ) from exc
        except Exception:
            if began:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise DurableAdministrationIntegrityError(
                    "SQLite WAL mode is unavailable"
                )
            connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                application_id = int(
                    connection.execute("PRAGMA application_id").fetchone()[0]
                )
                if version == 0:
                    if application_id not in (0, APPLICATION_ID):
                        raise DurableAdministrationIntegrityError(
                            "SQLite file belongs to another application"
                        )
                    for statement in _CREATE_STATEMENTS:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version != SCHEMA_VERSION or application_id != APPLICATION_ID:
                    raise DurableAdministrationIntegrityError(
                        "unsupported durable Admin database schema"
                    )
                self._verify_schema(connection)
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check is None or check[0] != "ok":
                raise DurableAdministrationIntegrityError(
                    "durable Admin database integrity check failed"
                )
        except DurableAdministrationError:
            raise
        except sqlite3.Error as exc:
            raise DurableAdministrationIntegrityError(
                "cannot initialize durable Admin SQLite store"
            ) from exc
        finally:
            connection.close()
        try:
            if os.name == "posix":
                self.path.chmod(0o600)
            _validate_database_path(self.path)
        except OSError as exc:
            raise DurableAdministrationIntegrityError(
                "cannot secure durable Admin database path"
            ) from exc
        with self._lock:
            self._verified_state_locked()

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        schema_objects = frozenset(
            (str(row[0]), str(row[1]), str(row[2]))
            for row in connection.execute(
                "SELECT type,name,tbl_name FROM sqlite_master"
            ).fetchall()
        )
        if schema_objects != _EXPECTED_SCHEMA_OBJECTS:
            raise DurableAdministrationIntegrityError(
                "durable Admin SQLite schema contains missing or unexpected objects"
            )
        temporary_objects = connection.execute(
            "SELECT type,name,tbl_name FROM sqlite_temp_master"
        ).fetchall()
        if temporary_objects:
            raise DurableAdministrationIntegrityError(
                "durable Admin SQLite connection contains temporary schema objects"
            )
        columns = connection.execute(
            "PRAGMA table_info(admin_authorization_events)"
        ).fetchall()
        observed = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in columns
        )
        if observed != _EXPECTED_COLUMNS:
            raise DurableAdministrationIntegrityError(
                "Admin authorization event table shape differs"
            )
        indexes = {}
        for row in connection.execute(
            "PRAGMA index_list(admin_authorization_events)"
        ).fetchall():
            name = str(row[1])
            index_columns = tuple(
                str(column[2])
                for column in connection.execute(
                    f'PRAGMA index_info("{name}")'
                ).fetchall()
            )
            indexes[name] = (
                int(row[2]),
                str(row[3]),
                int(row[4]),
                index_columns,
            )
        if indexes != _EXPECTED_INDEXES:
            raise DurableAdministrationIntegrityError(
                "Admin authorization event indexes differ"
            )

    def _event_hmac(self, raw: bytes) -> str:
        return hmac.new(
            self._secret,
            _HMAC_DOMAIN + raw,
            hashlib.sha256,
        ).hexdigest()

    def _read_anchor(self) -> DigestCheckpoint | None:
        try:
            checkpoint = self._anchor.read(
                ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE
            )
        except Exception as exc:
            raise DurableAdministrationAnchorConflict(
                "external Admin authorization anchor is unavailable"
            ) from exc
        if checkpoint is not None and not isinstance(checkpoint, DigestCheckpoint):
            raise DurableAdministrationAnchorConflict(
                "external Admin authorization anchor returned an invalid checkpoint"
            )
        if (
            checkpoint is not None
            and checkpoint.namespace != ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE
        ):
            raise DurableAdministrationAnchorConflict(
                "external Admin authorization checkpoint uses the wrong namespace"
            )
        return checkpoint

    def _verify_anchor(self, state: _VerifiedState) -> DigestCheckpoint | None:
        expected = state.checkpoint
        observed = self._read_anchor()
        if observed != expected:
            raise DurableAdministrationReconciliationRequired(
                "SQLite Admin event head and external checkpoint differ"
            )
        return observed

    def _database_checkpoint(
        self,
        connection: sqlite3.Connection,
    ) -> DigestCheckpoint | None:
        summary = connection.execute(
            "SELECT COUNT(*),MIN(sequence),MAX(sequence),"
            "(SELECT event_sha256 FROM admin_authorization_events "
            "ORDER BY sequence DESC LIMIT 1) "
            "FROM admin_authorization_events"
        ).fetchone()
        if summary is None:
            raise DurableAdministrationIntegrityError(
                "Admin authorization database head is unavailable"
            )
        count = int(summary[0])
        if count < 0 or count > self._capacity or count > MAX_EVENTS:
            raise DurableAdministrationIntegrityError(
                "Admin authorization database head exceeds its event bound"
            )
        if count == 0:
            if any(value is not None for value in summary[1:]):
                raise DurableAdministrationIntegrityError(
                    "empty Admin authorization database head is inconsistent"
                )
            return None
        if int(summary[1]) != 1 or int(summary[2]) != count:
            raise DurableAdministrationIntegrityError(
                "Admin authorization database head contains a sequence gap"
            )
        return DigestCheckpoint(
            namespace=ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE,
            generation=count,
            sequence=count,
            artifact_sha256=self._stored_digest(
                summary[3],
                "stored Admin authorization database head",
            ),
        )

    @staticmethod
    def _data_version(connection: sqlite3.Connection) -> int:
        row = connection.execute("PRAGMA data_version").fetchone()
        if row is None:
            raise DurableAdministrationIntegrityError(
                "Admin authorization SQLite data version is unavailable"
            )
        value = int(row[0])
        if value < 0:
            raise DurableAdministrationIntegrityError(
                "Admin authorization SQLite data version is invalid"
            )
        return value

    @staticmethod
    def _stored_digest(value: object, field: str) -> str:
        try:
            return _digest(value, field)
        except DurableAdministrationValidationError as exc:
            raise DurableAdministrationIntegrityError(str(exc)) from exc

    @staticmethod
    def _stored_positive(value: object, field: str) -> int:
        try:
            return _positive_integer(value, field)
        except DurableAdministrationValidationError as exc:
            raise DurableAdministrationIntegrityError(str(exc)) from exc

    @staticmethod
    def _approval_payload_sha256(approval: CatalogApproval) -> str:
        return hashlib.sha256(
            canonical_json_bytes(approval.canonical_payload())
        ).hexdigest()

    @staticmethod
    def _assignment_authorizes(
        state: _VerifiedState,
        *,
        assignment_id: str,
        assignment_receipt_sha256: str,
        subject: str,
        activity: str,
        at: datetime,
    ) -> bool:
        record = state.assignments.get(assignment_id)
        if record is None:
            return False
        assignment = record.assignment
        return (
            hmac.compare_digest(
                record.grant_receipt_sha256,
                assignment_receipt_sha256,
            )
            and assignment.subject == subject
            and activity in assignment.activities
            and assignment.issued_at <= at < assignment.expires_at
            and (
                assignment.revoked_at is None
                or at < assignment.revoked_at
            )
        )

    @staticmethod
    def _same_assignment_identity(
        current: RoleAssignment,
        replacement: RoleAssignment,
    ) -> bool:
        return (
            current.assignment_id == replacement.assignment_id
            and current.subject == replacement.subject
            and current.role == replacement.role
            and current.role_version == replacement.role_version
            and current.activities == replacement.activities
            and current.assigned_by == replacement.assigned_by
            and current.issued_at == replacement.issued_at
            and current.expires_at == replacement.expires_at
        )

    def _apply_event_payload(
        self,
        state: _VerifiedState,
        *,
        event_type: str,
        payload: object,
        occurred_at: datetime,
        stored: bool,
    ) -> None:
        def reject(message: str) -> None:
            error = (
                DurableAdministrationIntegrityError
                if stored
                else DurableAdministrationDenied
            )
            raise error(message)

        if event_type == "assignment-grant":
            data = _strict_mapping(
                payload,
                required=frozenset(
                    {"assignment", "assignment_receipt_sha256"}
                ),
                field="assignment-grant payload",
                stored=stored,
            )
            assignment = _assignment_from_payload(data["assignment"])
            try:
                receipt = _digest(
                    data["assignment_receipt_sha256"],
                    "assignment grant receipt",
                )
            except DurableAdministrationValidationError as exc:
                if stored:
                    raise DurableAdministrationIntegrityError(str(exc)) from exc
                raise
            if assignment.version != 1 or assignment.revoked_at is not None:
                reject("assignment grant must contain an unrevoked version-one snapshot")
            if assignment.issued_at != occurred_at:
                reject("assignment grant occurrence must equal assignment issued_at")
            if assignment.assignment_id in state.assignments:
                reject("assignment ID is already present in the authenticated log")
            if receipt in state.assignment_receipts:
                reject("assignment receipt digest is already present in the authenticated log")
            state.assignments[assignment.assignment_id] = _AssignmentState(
                assignment=assignment,
                grant_receipt_sha256=receipt,
            )
            state.assignment_receipts.add(receipt)
            return

        if event_type == "assignment-revoke":
            data = _strict_mapping(
                payload,
                required=frozenset(
                    {
                        "assignment",
                        "revocation_receipt_sha256",
                        "revoked_by",
                    }
                ),
                field="assignment-revoke payload",
                stored=stored,
            )
            assignment = _assignment_from_payload(data["assignment"])
            try:
                receipt = _digest(
                    data["revocation_receipt_sha256"],
                    "assignment revocation receipt",
                )
                _identifier(data["revoked_by"], "assignment revoked_by")
            except DurableAdministrationValidationError as exc:
                if stored:
                    raise DurableAdministrationIntegrityError(str(exc)) from exc
                raise
            current = state.assignments.get(assignment.assignment_id)
            if current is None:
                reject("assignment revocation has no authenticated grant")
            if current.assignment.revoked_at is not None:
                reject("assignment has already been revoked")
            if assignment.revoked_at is None or assignment.revoked_at != occurred_at:
                reject("assignment revoke occurrence must equal revoked_at")
            if assignment.version != current.assignment.version + 1:
                reject("assignment revocation must advance the snapshot version once")
            if not self._same_assignment_identity(current.assignment, assignment):
                reject("assignment revocation changed immutable grant fields")
            if receipt in state.assignment_receipts:
                reject("assignment receipt digest is already present in the authenticated log")
            current.assignment = assignment
            current.revoke_receipt_sha256 = receipt
            state.assignment_receipts.add(receipt)
            return

        if event_type == "catalog-approval-authorization":
            data = _strict_mapping(
                payload,
                required=frozenset({"approval"}),
                field="catalog-approval-authorization payload",
                stored=stored,
            )
            try:
                approval = CatalogApproval.from_mapping(data["approval"])
            except Exception as exc:
                error = (
                    DurableAdministrationIntegrityError
                    if stored
                    else DurableAdministrationValidationError
                )
                raise error("catalog approval authorization is invalid") from exc
            if approval.canonical_payload() != data["approval"]:
                reject("catalog approval authorization is not canonical")
            if approval.approved_at != occurred_at:
                reject("catalog approval occurrence must equal approved_at")
            payload_sha256 = self._approval_payload_sha256(approval)
            if payload_sha256 in state.approval_payload_sha256:
                reject("catalog approval authorization is already recorded")
            if (
                approval.approval_decision_receipt_sha256
                in state.approval_decision_receipts
            ):
                reject("catalog approval decision receipt is already recorded")
            if not self._assignment_authorizes(
                state,
                assignment_id=approval.assignment_id,
                assignment_receipt_sha256=approval.assignment_receipt_sha256,
                subject=approval.principal_id,
                activity=approval.activity,
                at=approval.approved_at,
            ):
                reject("catalog approval lacks its exact active assignment snapshot")
            state.approval_payload_sha256.add(payload_sha256)
            state.approval_decision_receipts.add(
                approval.approval_decision_receipt_sha256
            )
            return

        if event_type == "catalog-signing-authorization":
            data = _strict_mapping(
                payload,
                required=frozenset({"statement"}),
                field="catalog-signing-authorization payload",
                stored=stored,
            )
            try:
                statement = CatalogSignatureStatement.from_mapping(
                    data["statement"]
                )
            except Exception as exc:
                error = (
                    DurableAdministrationIntegrityError
                    if stored
                    else DurableAdministrationValidationError
                )
                raise error("catalog signing authorization is invalid") from exc
            if statement.canonical_payload() != data["statement"]:
                reject("catalog signing authorization is not canonical")
            if statement.signed_at != occurred_at:
                reject("catalog signing occurrence must equal signed_at")
            if statement.digest in state.signing_statement_sha256:
                reject("catalog signing authorization is already recorded")
            if not self._assignment_authorizes(
                state,
                assignment_id=statement.signing_assignment_id,
                assignment_receipt_sha256=(
                    statement.signing_assignment_receipt_sha256
                ),
                subject=statement.signing_principal_id,
                activity=statement.signing_activity,
                at=statement.signed_at,
            ):
                reject("catalog signing lacks its exact active assignment snapshot")
            state.signing_statement_sha256.add(statement.digest)
            return

        reject("stored Admin event type is unsupported")

    def _load_verified_state(
        self,
        connection: sqlite3.Connection,
    ) -> _VerifiedState:
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if (
                mode is None
                or str(mode[0]).lower() != "wal"
                or synchronous is None
                or int(synchronous[0]) != 2
            ):
                raise DurableAdministrationIntegrityError(
                    "durable Admin SQLite safety pragmas are not active"
                )
            self._verify_schema(connection)
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check is None or check[0] != "ok":
                raise DurableAdministrationIntegrityError(
                    "durable Admin database integrity check failed"
                )
            summary = connection.execute(
                "SELECT COUNT(*), MIN(sequence), MAX(sequence) "
                "FROM admin_authorization_events"
            ).fetchone()
            if summary is None:
                raise DurableAdministrationIntegrityError(
                    "Admin authorization event count is unavailable"
                )
            count = int(summary[0])
            if count < 0 or count > self._capacity or count > MAX_EVENTS:
                raise DurableAdministrationIntegrityError(
                    "Admin authorization event count exceeds its configured bound"
                )
            if count == 0:
                if summary[1] is not None or summary[2] is not None:
                    raise DurableAdministrationIntegrityError(
                        "empty Admin event sequence metadata is inconsistent"
                    )
            elif int(summary[1]) != 1 or int(summary[2]) != count:
                raise DurableAdministrationIntegrityError(
                    "Admin authorization event sequence contains a gap"
                )

            state = _VerifiedState(
                assignments={},
                assignment_receipts=set(),
                approval_payload_sha256=set(),
                approval_decision_receipts=set(),
                signing_statement_sha256=set(),
            )
            cursor = connection.execute(
                "SELECT sequence,event_type,occurred_at,recorded_at,event_json,"
                "event_sha256,auth_tag FROM admin_authorization_events "
                "ORDER BY sequence"
            )
            expected_sequence = 1
            previous_digest: str | None = None
            observed_rows = 0
            while True:
                rows = cursor.fetchmany(128)
                if not rows:
                    break
                for row in rows:
                    observed_rows += 1
                    if observed_rows > self._capacity or observed_rows > MAX_EVENTS:
                        raise DurableAdministrationIntegrityError(
                            "Admin authorization event read exceeded its bound"
                        )
                    sequence = row["sequence"]
                    if not isinstance(sequence, int) or isinstance(sequence, bool):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event sequence has the wrong type"
                        )
                    self._stored_positive(sequence, "stored event sequence")
                    if sequence != expected_sequence:
                        raise DurableAdministrationIntegrityError(
                            "Admin authorization event sequence contains a gap"
                        )
                    raw_text = row["event_json"]
                    event = _parse_canonical_event(raw_text)
                    event_data = _strict_mapping(
                        event,
                        required=frozenset(
                            {
                                "artifact_type",
                                "event_type",
                                "occurred_at",
                                "payload",
                                "previous_event_sha256",
                                "recorded_at",
                                "schema_version",
                                "sequence",
                            }
                        ),
                        field="stored Admin event",
                        stored=True,
                    )
                    if (
                        event_data["artifact_type"]
                        != "luma-os-admin-authorization-event"
                        or event_data["schema_version"] != SCHEMA_VERSION
                    ):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event version or artifact type is unsupported"
                        )
                    if event_data["sequence"] != sequence:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event sequence differs from its row"
                        )
                    event_type = event_data["event_type"]
                    if event_type not in _EVENT_TYPES or row["event_type"] != event_type:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event type differs or is unsupported"
                        )
                    if event_data["previous_event_sha256"] != previous_digest:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event hash chain is broken"
                        )
                    if row["occurred_at"] != event_data["occurred_at"]:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event occurrence differs from its row"
                        )
                    if row["recorded_at"] != event_data["recorded_at"]:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event recording time differs from its row"
                        )
                    occurred_at = _parse_timestamp(
                        event_data["occurred_at"],
                        "event.occurred_at",
                    )
                    recorded_at = _parse_timestamp(
                        event_data["recorded_at"],
                        "event.recorded_at",
                    )
                    if occurred_at > recorded_at:
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event occurrence postdates recording"
                        )
                    if (
                        state.last_occurred_at is not None
                        and occurred_at < state.last_occurred_at
                    ):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event occurrence time moved backward"
                        )
                    if (
                        state.last_recorded_at is not None
                        and recorded_at < state.last_recorded_at
                    ):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event recording time moved backward"
                        )

                    raw = str(raw_text).encode("ascii")
                    event_sha256 = self._stored_digest(
                        row["event_sha256"],
                        "stored event_sha256",
                    )
                    calculated_digest = hashlib.sha256(raw).hexdigest()
                    if not hmac.compare_digest(event_sha256, calculated_digest):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event digest authentication failed"
                        )
                    auth_tag = self._stored_digest(
                        row["auth_tag"],
                        "stored event auth_tag",
                    )
                    if not hmac.compare_digest(auth_tag, self._event_hmac(raw)):
                        raise DurableAdministrationIntegrityError(
                            "stored Admin event HMAC authentication failed"
                        )
                    self._apply_event_payload(
                        state,
                        event_type=event_type,
                        payload=event_data["payload"],
                        occurred_at=occurred_at,
                        stored=True,
                    )
                    state.count = sequence
                    state.head_sha256 = event_sha256
                    state.last_occurred_at = occurred_at
                    state.last_recorded_at = recorded_at
                    previous_digest = event_sha256
                    expected_sequence += 1
            if observed_rows != count:
                raise DurableAdministrationIntegrityError(
                    "Admin authorization event count changed during bounded read"
                )
            return state
        except DurableAdministrationError:
            raise
        except sqlite3.Error as exc:
            raise DurableAdministrationIntegrityError(
                "cannot verify durable Admin authorization events"
            ) from exc

    def _verified_state_locked(self) -> _VerifiedState:
        self._ensure_open()
        connection = self._connect()
        try:
            state = self._load_verified_state(connection)
        finally:
            connection.close()
        now = self._now()
        if state.last_recorded_at is not None and now < state.last_recorded_at:
            raise DurableAdministrationClockRollback(
                "UTC clock moved behind the durable Admin event high-water mark"
            )
        self._verify_anchor(state)
        return state

    def _verify_committed_append(
        self,
        *,
        expected_state: _VerifiedState,
        expected_row: tuple[object, ...],
    ) -> None:
        """Authenticate an exact committed append before advancing the anchor."""

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            observed_state = self._load_verified_state(connection)
            observed_row = connection.execute(
                "SELECT sequence,event_type,occurred_at,recorded_at,event_json,"
                "event_sha256,auth_tag FROM admin_authorization_events "
                "WHERE sequence=?",
                (expected_state.count,),
            ).fetchone()
            if (
                observed_row is None
                or tuple(observed_row) != expected_row
                or observed_state != expected_state
            ):
                raise DurableAdministrationIntegrityError(
                    "committed Admin authorization event differs from the exact append"
                )
            connection.execute("COMMIT")
        finally:
            connection.close()

    def _append_event(
        self,
        *,
        event_type: str,
        occurred_at: datetime,
        payload: Mapping[str, object],
        writer_check: Callable[[datetime], bool],
    ) -> AdminAuthorizationEventReceipt:
        if event_type not in _EVENT_TYPES:
            raise DurableAdministrationValidationError(
                "Admin authorization event type is unsupported"
            )
        occurred = _aware_second(occurred_at, "event occurred_at")
        with self._lock:
            self._ensure_open()
            recorded = self._now()
            if occurred > recorded:
                raise DurableAdministrationValidationError(
                    "Admin authorization event cannot occur in the future"
                )
            with self._transaction() as connection:
                state = self._load_verified_state(connection)
                if (
                    state.last_recorded_at is not None
                    and recorded < state.last_recorded_at
                ):
                    raise DurableAdministrationClockRollback(
                        "UTC clock moved behind the durable Admin event high-water mark"
                    )
                if (
                    state.last_occurred_at is not None
                    and occurred < state.last_occurred_at
                ):
                    raise DurableAdministrationValidationError(
                        "Admin authorization occurrence time cannot move backward"
                    )
                if state.count >= self._capacity:
                    raise DurableAdministrationCapacityExceeded(
                        "durable Admin authorization event capacity is exhausted"
                    )
                expected_checkpoint = self._verify_anchor(state)
                try:
                    writer_allowed = writer_check(recorded)
                except Exception as exc:
                    raise DurableAdministrationDenied(
                        "external Admin writer authorization failed closed"
                    ) from exc
                if writer_allowed is not True:
                    raise DurableAdministrationDenied(
                        "external Admin writer did not authorize the exact event"
                    )
                sequence = state.count + 1
                document: dict[str, object] = {
                    "artifact_type": "luma-os-admin-authorization-event",
                    "event_type": event_type,
                    "occurred_at": _timestamp(occurred, "event occurred_at"),
                    "payload": dict(payload),
                    "previous_event_sha256": state.head_sha256,
                    "recorded_at": _timestamp(recorded, "event recorded_at"),
                    "schema_version": SCHEMA_VERSION,
                    "sequence": sequence,
                }
                raw = canonical_admin_event_bytes(document)
                event_sha256 = hashlib.sha256(raw).hexdigest()
                auth_tag = self._event_hmac(raw)
                self._apply_event_payload(
                    state,
                    event_type=event_type,
                    payload=document["payload"],
                    occurred_at=occurred,
                    stored=False,
                )
                connection.execute(
                    "INSERT INTO admin_authorization_events("
                    "sequence,event_type,occurred_at,recorded_at,event_json,"
                    "event_sha256,auth_tag) VALUES (?,?,?,?,?,?,?)",
                    (
                        sequence,
                        event_type,
                        document["occurred_at"],
                        document["recorded_at"],
                        raw.decode("ascii"),
                        event_sha256,
                        auth_tag,
                    ),
                )

                state.count = sequence
                state.head_sha256 = event_sha256
                state.last_occurred_at = occurred
                state.last_recorded_at = recorded
                expected_row = (
                    sequence,
                    event_type,
                    document["occurred_at"],
                    document["recorded_at"],
                    raw.decode("ascii"),
                    event_sha256,
                    auth_tag,
                )

            try:
                self._verify_committed_append(
                    expected_state=state,
                    expected_row=expected_row,
                )
            except Exception as exc:
                self._fenced = True
                raise DurableAdministrationReconciliationRequired(
                    "SQLite committed but the exact Admin event could not be "
                    "confirmed before anchoring"
                ) from exc

            replacement = DigestCheckpoint(
                namespace=ADMIN_AUTHORIZATION_ANCHOR_NAMESPACE,
                generation=(
                    1
                    if expected_checkpoint is None
                    else expected_checkpoint.generation + 1
                ),
                sequence=sequence,
                artifact_sha256=event_sha256,
            )
            try:
                changed = self._anchor.compare_and_swap(
                    expected=expected_checkpoint,
                    replacement=replacement,
                )
            except Exception as exc:
                self._fenced = True
                raise DurableAdministrationReconciliationRequired(
                    "SQLite committed but external Admin anchor outcome is unknown"
                ) from exc
            if changed is not True:
                self._fenced = True
                raise DurableAdministrationReconciliationRequired(
                    "SQLite committed but external Admin anchor rejected compare-and-swap"
                )
            try:
                retained = self._read_anchor()
            except DurableAdministrationError as exc:
                self._fenced = True
                raise DurableAdministrationReconciliationRequired(
                    "external Admin checkpoint cannot be confirmed after SQLite commit"
                ) from exc
            if retained != replacement:
                self._fenced = True
                raise DurableAdministrationReconciliationRequired(
                    "external Admin checkpoint did not retain the committed head"
                )
            return AdminAuthorizationEventReceipt(
                sequence=sequence,
                event_type=event_type,
                occurred_at=occurred,
                recorded_at=recorded,
                previous_event_sha256=(
                    None
                    if expected_checkpoint is None
                    else expected_checkpoint.artifact_sha256
                ),
                event_sha256=event_sha256,
                event_hmac_sha256=auth_tag,
                anchor_checkpoint=replacement,
            )

    def record_assignment_grant(
        self,
        assignment: RoleAssignment,
        *,
        assignment_receipt_sha256: str,
    ) -> AdminAuthorizationEventReceipt:
        snapshot = _assignment_payload(assignment)
        receipt = _digest(
            assignment_receipt_sha256,
            "assignment_receipt_sha256",
        )
        if assignment.version != 1 or assignment.revoked_at is not None:
            raise DurableAdministrationValidationError(
                "assignment grant requires an unrevoked version-one snapshot"
            )
        return self._append_event(
            event_type="assignment-grant",
            occurred_at=assignment.issued_at,
            payload={
                "assignment": snapshot,
                "assignment_receipt_sha256": receipt,
            },
            writer_check=lambda at: (
                self._writer_authorizer.assignment_grant_is_authorized(
                    assignment,
                    assignment_receipt_sha256=receipt,
                    at=at,
                )
            ),
        )

    def record_assignment_revoke(
        self,
        assignment: RoleAssignment,
        *,
        revocation_receipt_sha256: str,
        revoked_by: str,
    ) -> AdminAuthorizationEventReceipt:
        snapshot = _assignment_payload(assignment)
        receipt = _digest(
            revocation_receipt_sha256,
            "revocation_receipt_sha256",
        )
        actor = _identifier(revoked_by, "revoked_by")
        if assignment.revoked_at is None:
            raise DurableAdministrationValidationError(
                "assignment revoke requires a revoked snapshot"
            )
        return self._append_event(
            event_type="assignment-revoke",
            occurred_at=assignment.revoked_at,
            payload={
                "assignment": snapshot,
                "revocation_receipt_sha256": receipt,
                "revoked_by": actor,
            },
            writer_check=lambda at: (
                self._writer_authorizer.assignment_revoke_is_authorized(
                    assignment,
                    revocation_receipt_sha256=receipt,
                    revoked_by=actor,
                    at=at,
                )
            ),
        )

    def record_catalog_approval_authorization(
        self,
        approval: CatalogApproval,
    ) -> AdminAuthorizationEventReceipt:
        if not isinstance(approval, CatalogApproval):
            raise DurableAdministrationValidationError(
                "approval must be a CatalogApproval"
            )
        return self._append_event(
            event_type="catalog-approval-authorization",
            occurred_at=approval.approved_at,
            payload={"approval": approval.canonical_payload()},
            writer_check=lambda at: (
                self._writer_authorizer.catalog_approval_is_authorized(
                    approval,
                    at=at,
                )
            ),
        )

    def record_catalog_signing_authorization(
        self,
        statement: CatalogSignatureStatement,
    ) -> AdminAuthorizationEventReceipt:
        if not isinstance(statement, CatalogSignatureStatement):
            raise DurableAdministrationValidationError(
                "statement must be a CatalogSignatureStatement"
            )
        return self._append_event(
            event_type="catalog-signing-authorization",
            occurred_at=statement.signed_at,
            payload={"statement": statement.canonical_payload()},
            writer_check=lambda at: (
                self._writer_authorizer.catalog_signing_is_authorized(
                    statement,
                    at=at,
                )
            ),
        )

    def _approval_is_authorized(
        self,
        approval: CatalogApproval,
        *,
        at: datetime,
    ) -> bool:
        if not isinstance(approval, CatalogApproval):
            return False
        observed = _aware_second(at, "authorization time")
        with self._lock:
            state = self._verified_state_locked()
            return self._approval_is_authorized_in_state(
                state,
                approval,
                at=observed,
            )

    def _approval_is_authorized_in_state(
        self,
        state: _VerifiedState,
        approval: CatalogApproval,
        *,
        at: datetime,
    ) -> bool:
        if at < approval.approved_at:
            return False
        if (
            self._approval_payload_sha256(approval)
            not in state.approval_payload_sha256
        ):
            return False
        return self._assignment_authorizes(
            state,
            assignment_id=approval.assignment_id,
            assignment_receipt_sha256=approval.assignment_receipt_sha256,
            subject=approval.principal_id,
            activity=approval.activity,
            at=at,
        )

    def _signer_is_authorized(
        self,
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool:
        if not isinstance(statement, CatalogSignatureStatement):
            return False
        observed = _aware_second(at, "authorization time")
        with self._lock:
            state = self._verified_state_locked()
            return self._signer_is_authorized_in_state(
                state,
                statement,
                at=observed,
            )

    def _signer_is_authorized_in_state(
        self,
        state: _VerifiedState,
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool:
        if at < statement.signed_at:
            return False
        if statement.digest not in state.signing_statement_sha256:
            return False
        return self._assignment_authorizes(
            state,
            assignment_id=statement.signing_assignment_id,
            assignment_receipt_sha256=(
                statement.signing_assignment_receipt_sha256
            ),
            subject=statement.signing_principal_id,
            activity=statement.signing_activity,
            at=at,
        )

    def _catalog_is_authorized(
        self,
        approvals: tuple[CatalogApproval, ...],
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool:
        if (
            not isinstance(approvals, tuple)
            or not 1 <= len(approvals) <= MAX_CATALOG_AUTHORIZATION_BATCH_APPROVALS
            or any(not isinstance(item, CatalogApproval) for item in approvals)
            or not isinstance(statement, CatalogSignatureStatement)
        ):
            return False
        observed = _aware_second(at, "catalog authorization batch time")
        with self._lock:
            self._ensure_open()
            connection = self._connect()
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                initial_data_version = self._data_version(connection)
                state = self._load_verified_state(connection)
                now = self._now()
                if state.last_recorded_at is not None and now < state.last_recorded_at:
                    raise DurableAdministrationClockRollback(
                        "UTC clock moved behind the durable Admin event high-water mark"
                    )
                checkpoint = self._verify_anchor(state)
                authorized = all(
                    self._approval_is_authorized_in_state(
                        state,
                        approval,
                        at=approval.approved_at,
                    )
                    and self._approval_is_authorized_in_state(
                        state,
                        approval,
                        at=observed,
                    )
                    for approval in approvals
                ) and self._signer_is_authorized_in_state(
                    state,
                    statement,
                    at=statement.signed_at,
                ) and self._signer_is_authorized_in_state(
                    state,
                    statement,
                    at=observed,
                )
                if self._database_checkpoint(connection) != checkpoint:
                    raise DurableAdministrationReconciliationRequired(
                        "Admin authorization database changed during batch verification"
                    )
                if self._read_anchor() != checkpoint:
                    raise DurableAdministrationReconciliationRequired(
                        "Admin authorization anchor changed during batch verification"
                    )
                connection.execute("COMMIT")
                began = False

                # These post-lock observations close ordinary cross-process
                # SQLite append races.  Hostile raw filesystem mutation and
                # native lock/latency behavior still require platform testing.
                if (
                    self._data_version(connection) != initial_data_version
                    or self._database_checkpoint(connection) != checkpoint
                    or self._read_anchor() != checkpoint
                    or self._data_version(connection) != initial_data_version
                    or self._database_checkpoint(connection) != checkpoint
                ):
                    raise DurableAdministrationReconciliationRequired(
                        "Admin authorization checkpoint changed as the batch completed"
                    )
                return authorized
            except DurableAdministrationError:
                if began:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise
            except sqlite3.Error as exc:
                if began:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise DurableAdministrationIntegrityError(
                    "durable Admin authorization batch verification failed"
                ) from exc
            finally:
                connection.close()


class DurableCatalogAuthorizationVerifier(CatalogAuthorizationVerifier):
    """Fail-closed adapter with one authenticated replay per catalog batch.

    The batch removes repeated Python/HMAC replays within one catalog
    verification.  Maximum-capacity latency, filesystem behavior, and lock
    contention still require qualification on the target native Ubuntu host;
    this is not performance certification for production hardware.
    """

    def __init__(self, store: DurableAdminAuthorizationStore) -> None:
        if not isinstance(store, DurableAdminAuthorizationStore):
            raise DurableAdministrationValidationError(
                "store must be a DurableAdminAuthorizationStore"
            )
        self._store = store

    def approval_is_authorized(
        self,
        approval: CatalogApproval,
        *,
        at: datetime,
    ) -> bool:
        try:
            return self._store._approval_is_authorized(approval, at=at)
        except Exception:
            return False

    def signer_is_authorized(
        self,
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool:
        try:
            return self._store._signer_is_authorized(statement, at=at)
        except Exception:
            return False

    def catalog_is_authorized(
        self,
        approvals: tuple[CatalogApproval, ...],
        statement: CatalogSignatureStatement,
        *,
        at: datetime,
    ) -> bool:
        try:
            return self._store._catalog_is_authorized(
                approvals,
                statement,
                at=at,
            )
        except Exception:
            return False
