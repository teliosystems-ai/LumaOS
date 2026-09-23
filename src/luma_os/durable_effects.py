"""Durable, fail-closed adapters for the privileged-helper contracts.

The module deliberately performs no privileged host operation.  It provides a
bounded SQLite request journal and an idempotent effect coordinator.  Concrete
effect adapters are fixed at construction time and receive only typed
``AuthorizedEffect`` values; callers cannot select commands, shells, argv, or
executables.

SQLite durability cannot make an external host mutation transactional.  The
coordinator therefore records ``APPLYING`` before calling an adapter and treats
every interrupted or exceptional application as ``FAILED_UNKNOWN``.  Such an
effect is never automatically dispatched again.  Only the action-specific
adapter may reconcile it to a durable completion.

The database must live in a dedicated, access-controlled directory on the
platform's native filesystem.  Do not share one live database between Windows
and WSL through a mounted Windows path.  The supplied integrity key detects
record editing, but key custody, encrypted storage, ACL/DACL enforcement, and
rollback-resistant external anchoring remain platform responsibilities. Safe
device handles must be CSPRNG-issued 256-bit capabilities whose provenance and
liveness are rechecked by the mandatory dispatch validator; this makes their
persisted one-way authorization digests resistant to offline guessing.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
from types import MappingProxyType
from typing import Callable, Iterator, Mapping, Protocol
import uuid

from .privileged_helper import (
    ActivateReleaseParameters,
    AuthenticatedPeer,
    AuthorizedEffect,
    AuthorityDecision,
    BoundDevice,
    ConfinementAttestation,
    DeviceCapability,
    DeviceType,
    EffectReceipt,
    EffectResult,
    ExecutorCompletion,
    ExecutorReconciliation,
    GeneratedCodeKind,
    HelperAction,
    HelperEffectNotApplied,
    HelperExecutionError,
    HelperReplayConflict,
    JournalRecord,
    JournalReservation,
    JournalState,
    PeerTransport,
    ReconciliationState,
    RecoveryBootParameters,
    StartGeneratedWorkerParameters,
    AssignDeviceParameters,
    DenialReason,
)


SCHEMA_VERSION = 1
MAX_CANONICAL_BYTES = 256 * 1024
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class DurableEffectsError(RuntimeError):
    """Base class for durable-backend failures."""


class DurableValidationError(ValueError):
    """A constructor argument or stored value violates the closed contract."""


class DurableStoreUnavailable(DurableEffectsError):
    """The durable store cannot be trusted or updated safely."""


class DurableStoreBusy(DurableStoreUnavailable):
    """The durable store could not acquire its writer lock immediately."""


class DurableCapacityExceeded(DurableStoreUnavailable):
    """The configured hard record bound was reached."""


class DurableClockRollback(DurableStoreUnavailable):
    """The observed UTC clock moved behind the durable high-water mark."""


class DurableEffectConflict(HelperExecutionError):
    """An idempotency key was reused for different effect bytes."""


class DurableEffectInProgress(HelperExecutionError):
    """Another owner holds a live preparation lease."""


class DurableEffectUnknown(HelperExecutionError):
    """An effect may have occurred and is fenced pending reconciliation."""


class EffectLedgerState(str, Enum):
    PREPARED = "prepared"
    APPLYING = "applying"
    COMPLETED = "completed"
    FAILED_UNKNOWN = "failed_unknown"


@dataclass(frozen=True, slots=True)
class StoredEffect:
    """Canonical persisted effect passed to a trusted reconciler."""

    idempotency_key: str
    request_id: str
    request_sha256: str
    action: HelperAction
    effect_sha256: str
    state: EffectLedgerState
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        _digest(self.idempotency_key, "stored_effect.idempotency_key")
        _identifier(self.request_id, "stored_effect.request_id")
        _digest(self.request_sha256, "stored_effect.request_sha256")
        if not isinstance(self.action, HelperAction):
            raise DurableValidationError("stored effect action is invalid")
        _digest(self.effect_sha256, "stored_effect.effect_sha256")
        if not isinstance(self.state, EffectLedgerState):
            raise DurableValidationError("stored effect state is invalid")
        if not isinstance(self.document, Mapping):
            raise DurableValidationError("stored effect document must be a mapping")
        object.__setattr__(self, "document", MappingProxyType(dict(self.document)))


@dataclass(frozen=True, slots=True)
class EffectAdapterReconciliation:
    """Result returned by an action-specific external-effect reconciler."""

    state: ReconciliationState
    result: EffectResult | None = None
    executed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ReconciliationState):
            raise DurableValidationError("adapter reconciliation state is invalid")
        completed = self.state is ReconciliationState.COMPLETED
        if completed != (isinstance(self.result, EffectResult) and self.executed_at is not None):
            raise DurableValidationError("completed reconciliation needs result and execution time")
        if not completed and (self.result is not None or self.executed_at is not None):
            raise DurableValidationError("non-completed reconciliation cannot carry a result")
        if self.executed_at is not None:
            object.__setattr__(
                self, "executed_at", _aware(self.executed_at, "reconciliation.executed_at")
            )


class TypedEffectAdapter(Protocol):
    """Fixed trusted implementation for one enumerated helper action."""

    def apply(self, effect: AuthorizedEffect) -> EffectResult: ...

    def reconcile(self, effect: StoredEffect) -> EffectAdapterReconciliation: ...


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise DurableValidationError(f"{field} is not a bounded printable identifier")
    return value


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DurableValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value < (1 << 63):
        raise DurableValidationError(f"{field} must be a positive signed 64-bit integer")
    return value


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DurableValidationError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _time_text(value: object, field: str) -> str:
    normalized = _aware(value, field)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DurableStoreUnavailable(f"{field} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise DurableStoreUnavailable(f"{field} is not canonical UTC") from exc
    if _time_text(parsed, field) != value:
        raise DurableStoreUnavailable(f"{field} is not canonical UTC")
    return parsed


def _json_limits(value: object) -> None:
    stack = [(value, 1)]
    count = 0
    while stack:
        current, depth = stack.pop()
        count += 1
        if depth > 16 or count > 1024:
            raise DurableValidationError("canonical value exceeds structural bounds")
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise DurableValidationError("canonical object keys must be strings")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)
        elif not isinstance(current, (str, int, bool, type(None))):
            raise DurableValidationError("canonical value contains an unsupported type")


def _canonical_bytes(value: object) -> bytes:
    _json_limits(value)
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DurableValidationError("value is outside the canonical JSON domain") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise DurableValidationError("canonical value exceeds the byte limit")
    return encoded


def _canonical_text(value: object) -> str:
    return _canonical_bytes(value).decode("ascii")


def _parse_canonical_json(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise DurableStoreUnavailable(f"{field} is not bounded canonical JSON")
    try:
        decoded = json.loads(value)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise DurableStoreUnavailable(f"{field} is not valid JSON") from exc
    if not isinstance(decoded, dict) or _canonical_text(decoded) != value:
        raise DurableStoreUnavailable(f"{field} is not canonical JSON")
    return decoded


def _sqlite_busy(error: sqlite3.Error) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    return code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} or any(
        token in str(error).lower() for token in ("busy", "locked")
    )


def _is_reparse(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError as exc:
        raise DurableStoreUnavailable(f"cannot inspect durable path component: {path}") from exc
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _validate_database_path(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise DurableValidationError("durable database path must be absolute")
    parent = candidate.parent
    if not parent.exists() or not parent.is_dir():
        raise DurableValidationError("durable database parent must already exist")

    existing: list[Path] = []
    cursor = parent
    while True:
        if cursor.exists():
            existing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    for component in reversed(existing):
        if _is_reparse(component):
            raise DurableValidationError("durable database path cannot traverse a link or reparse point")
    if candidate.exists():
        if _is_reparse(candidate) or not candidate.is_file():
            raise DurableValidationError("durable database must be a regular non-link file")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(candidate) + suffix)
        if sidecar.exists() and (_is_reparse(sidecar) or not sidecar.is_file()):
            raise DurableValidationError("durable database sidecars must be regular non-link files")

    if os.name == "posix":
        mode = stat.S_IMODE(parent.stat().st_mode)
        if mode & 0o077:
            raise DurableValidationError("durable database parent must not grant group/other access")
    return candidate


_SCHEMA = """
CREATE TABLE IF NOT EXISTS durable_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    max_observed_at TEXT NOT NULL,
    auth_tag TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_journal (
    request_id TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','completed','failed_unknown')),
    owner_token TEXT,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    lease_until TEXT,
    receipt_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    CHECK (
        (state = 'pending' AND owner_token IS NOT NULL AND lease_until IS NOT NULL AND receipt_json IS NULL)
        OR (state = 'completed' AND owner_token IS NULL AND lease_until IS NULL AND receipt_json IS NOT NULL)
        OR (state = 'failed_unknown' AND owner_token IS NULL AND lease_until IS NULL AND receipt_json IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS effect_ledger (
    idempotency_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    action TEXT NOT NULL,
    effect_sha256 TEXT NOT NULL,
    effect_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','applying','completed','failed_unknown')),
    owner_token TEXT,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    lease_until TEXT,
    completion_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    CHECK (
        (state = 'prepared' AND owner_token IS NOT NULL AND lease_until IS NOT NULL AND completion_json IS NULL)
        OR (state = 'applying' AND owner_token IS NOT NULL AND lease_until IS NULL AND completion_json IS NULL)
        OR (state = 'completed' AND owner_token IS NULL AND lease_until IS NULL AND completion_json IS NOT NULL)
        OR (state = 'failed_unknown' AND owner_token IS NULL AND lease_until IS NULL AND completion_json IS NULL)
    )
);

CREATE TRIGGER IF NOT EXISTS request_completed_immutable
BEFORE UPDATE ON request_journal
WHEN OLD.state = 'completed'
BEGIN
    SELECT RAISE(ABORT, 'completed request receipt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS request_completed_no_delete
BEFORE DELETE ON request_journal
WHEN OLD.state = 'completed'
BEGIN
    SELECT RAISE(ABORT, 'completed request receipt cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS effect_completed_immutable
BEFORE UPDATE ON effect_ledger
WHEN OLD.state = 'completed'
BEGIN
    SELECT RAISE(ABORT, 'completed effect is immutable');
END;

CREATE TRIGGER IF NOT EXISTS effect_terminal_no_delete
BEFORE DELETE ON effect_ledger
WHEN OLD.state IN ('completed','applying','failed_unknown')
BEGIN
    SELECT RAISE(ABORT, 'effect history cannot be deleted');
END;
"""


class _SQLiteDurableBase:
    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        integrity_key: bytes,
        capacity: int,
        clock: Callable[[], datetime] | None,
        busy_timeout: timedelta,
    ) -> None:
        self.path = _validate_database_path(path)
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise DurableValidationError("integrity_key must contain at least 32 bytes")
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise DurableValidationError("capacity must be a positive integer")
        if not isinstance(busy_timeout, timedelta) or not timedelta(0) < busy_timeout <= timedelta(minutes=1):
            raise DurableValidationError("busy_timeout must be between zero and one minute")
        if clock is not None and not callable(clock):
            raise DurableValidationError("clock must be callable")
        self._key = bytes(integrity_key)
        self.capacity = capacity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._busy_ms = max(1, int(busy_timeout.total_seconds() * 1000))
        self._initialize()

    def close(self) -> None:
        """Connections are operation-scoped; close exists for adapter symmetry."""

    def _now(self) -> datetime:
        return _aware(self._clock(), "clock result")

    def _tag(self, domain: str, document: Mapping[str, object]) -> str:
        payload = domain.encode("ascii") + b"\x00" + _canonical_bytes(dict(document))
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _verify_tag(
        self, domain: str, document: Mapping[str, object], observed: object
    ) -> None:
        if not isinstance(observed, str) or not hmac.compare_digest(
            self._tag(domain, document), observed
        ):
            raise DurableStoreUnavailable(f"{domain} authentication failed")

    def _connect(self, *, busy_timeout_ms: int | None = None) -> sqlite3.Connection:
        effective_busy_ms = (
            self._busy_ms if busy_timeout_ms is None else busy_timeout_ms
        )
        if (
            not isinstance(effective_busy_ms, int)
            or isinstance(effective_busy_ms, bool)
            or effective_busy_ms < 0
        ):
            raise DurableValidationError("SQLite busy timeout must be nonnegative")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=effective_busy_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {effective_busy_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            if _sqlite_busy(exc):
                raise DurableStoreBusy("durable SQLite store is busy") from exc
            raise DurableStoreUnavailable("cannot open durable SQLite store") from exc

    @contextmanager
    def _transaction(
        self, *, busy_timeout_ms: int | None = None
    ) -> Iterator[sqlite3.Connection]:
        connection = self._connect(busy_timeout_ms=busy_timeout_ms)
        began = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
            except sqlite3.Error as exc:
                if _sqlite_busy(exc):
                    raise DurableStoreBusy(
                        "durable SQLite writer lock is busy"
                    ) from exc
                raise DurableStoreUnavailable(
                    "cannot begin durable SQLite transaction"
                ) from exc
            yield connection
            connection.execute("COMMIT")
        except DurableEffectsError:
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
            raise DurableStoreUnavailable("durable SQLite transaction failed") from exc
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
                raise DurableStoreUnavailable("SQLite WAL mode is unavailable")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise DurableStoreUnavailable("durable database schema is newer than this build")
            if version == 0:
                connection.executescript(_SCHEMA)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                meta_document = {"max_observed_at": _time_text(_EPOCH, "epoch")}
                connection.execute(
                    "INSERT OR IGNORE INTO durable_meta(singleton,max_observed_at,auth_tag) VALUES (1,?,?)",
                    (meta_document["max_observed_at"], self._tag("clock", meta_document)),
                )
                connection.execute("COMMIT")
            elif version != SCHEMA_VERSION:
                raise DurableStoreUnavailable("unsupported durable database schema")
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check is None or check[0] != "ok":
                raise DurableStoreUnavailable("durable database integrity check failed")
            meta = connection.execute(
                "SELECT max_observed_at,auth_tag FROM durable_meta WHERE singleton=1"
            ).fetchone()
            if meta is None:
                raise DurableStoreUnavailable("durable clock metadata is missing")
            document = {"max_observed_at": meta["max_observed_at"]}
            self._verify_tag("clock", document, meta["auth_tag"])
            _parse_time(meta["max_observed_at"], "clock.max_observed_at")
        except DurableEffectsError:
            raise
        except sqlite3.Error as exc:
            raise DurableStoreUnavailable("cannot initialize durable SQLite store") from exc
        finally:
            connection.close()
        try:
            if os.name == "posix":
                self.path.chmod(0o600)
            _validate_database_path(self.path)
        except OSError as exc:
            raise DurableStoreUnavailable("cannot secure durable database path") from exc

    def integrity_check(self) -> None:
        connection = self._connect()
        try:
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check is None or check[0] != "ok":
                raise DurableStoreUnavailable("durable database integrity check failed")
            for row in connection.execute("SELECT * FROM request_journal"):
                self._verify_request_row(row)
            for row in connection.execute("SELECT * FROM effect_ledger"):
                self._verify_effect_row(row)
        except DurableEffectsError:
            raise
        except sqlite3.Error as exc:
            raise DurableStoreUnavailable("cannot inspect durable SQLite store") from exc
        finally:
            connection.close()

    def _observe_clock(self, connection: sqlite3.Connection, observed: datetime) -> str:
        now_text = _time_text(observed, "observed_at")
        row = connection.execute(
            "SELECT max_observed_at,auth_tag FROM durable_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise DurableStoreUnavailable("durable clock metadata is missing")
        document = {"max_observed_at": row["max_observed_at"]}
        self._verify_tag("clock", document, row["auth_tag"])
        previous = _parse_time(row["max_observed_at"], "clock.max_observed_at")
        if observed < previous:
            raise DurableClockRollback("UTC clock moved behind the durable high-water mark")
        if observed > previous:
            replacement = {"max_observed_at": now_text}
            changed = connection.execute(
                "UPDATE durable_meta SET max_observed_at=?,auth_tag=? "
                "WHERE singleton=1 AND max_observed_at=? AND auth_tag=?",
                (
                    now_text,
                    self._tag("clock", replacement),
                    row["max_observed_at"],
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("durable clock compare-and-swap failed")
        return now_text

    @staticmethod
    def _request_document_from_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "created_at": row["created_at"],
            "generation": int(row["generation"]),
            "lease_until": row["lease_until"],
            "owner_token": row["owner_token"],
            "receipt_json": row["receipt_json"],
            "request_id": row["request_id"],
            "request_sha256": row["request_sha256"],
            "state": row["state"],
            "updated_at": row["updated_at"],
        }

    def _verify_request_row(self, row: sqlite3.Row) -> dict[str, object]:
        document = self._request_document_from_row(row)
        self._verify_tag("request", document, row["auth_tag"])
        _identifier(document["request_id"], "stored request_id")
        _digest(document["request_sha256"], "stored request_sha256")
        _positive(document["generation"], "stored request generation")
        _parse_time(document["created_at"], "request.created_at")
        _parse_time(document["updated_at"], "request.updated_at")
        if document["lease_until"] is not None:
            _parse_time(document["lease_until"], "request.lease_until")
        try:
            state = JournalState(document["state"])
        except (TypeError, ValueError) as exc:
            raise DurableStoreUnavailable("stored request state is invalid") from exc
        if state is JournalState.PENDING:
            _identifier(document["owner_token"], "stored owner token")
            if document["receipt_json"] is not None or document["lease_until"] is None:
                raise DurableStoreUnavailable("pending request row is inconsistent")
        elif state is JournalState.COMPLETED:
            if (
                document["owner_token"] is not None
                or document["lease_until"] is not None
                or document["receipt_json"] is None
            ):
                raise DurableStoreUnavailable("completed request row is inconsistent")
            _deserialize_receipt(document["receipt_json"])
        elif any(
            document[field] is not None
            for field in ("owner_token", "lease_until", "receipt_json")
        ):
            raise DurableStoreUnavailable("failed-unknown request row is inconsistent")
        return document

    @staticmethod
    def _effect_document_from_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "action": row["action"],
            "completion_json": row["completion_json"],
            "created_at": row["created_at"],
            "effect_json": row["effect_json"],
            "effect_sha256": row["effect_sha256"],
            "generation": int(row["generation"]),
            "idempotency_key": row["idempotency_key"],
            "lease_until": row["lease_until"],
            "owner_token": row["owner_token"],
            "request_id": row["request_id"],
            "request_sha256": row["request_sha256"],
            "state": row["state"],
            "updated_at": row["updated_at"],
        }

    def _verify_effect_row(self, row: sqlite3.Row) -> dict[str, object]:
        document = self._effect_document_from_row(row)
        self._verify_tag("effect", document, row["auth_tag"])
        _digest(document["idempotency_key"], "stored idempotency_key")
        _identifier(document["request_id"], "stored effect request_id")
        _digest(document["request_sha256"], "stored effect request_sha256")
        _digest(document["effect_sha256"], "stored effect digest")
        _positive(document["generation"], "stored effect generation")
        try:
            HelperAction(document["action"])
            state = EffectLedgerState(document["state"])
        except (TypeError, ValueError) as exc:
            raise DurableStoreUnavailable("stored effect enum is invalid") from exc
        effect_body = _parse_canonical_json(document["effect_json"], "effect.effect_json")
        if hashlib.sha256(_canonical_bytes(effect_body)).hexdigest() != document["effect_sha256"]:
            raise DurableStoreUnavailable("stored effect digest does not match its document")
        _validate_persisted_effect_binding(document, effect_body)
        _parse_time(document["created_at"], "effect.created_at")
        _parse_time(document["updated_at"], "effect.updated_at")
        if document["lease_until"] is not None:
            _parse_time(document["lease_until"], "effect.lease_until")
        if state is EffectLedgerState.PREPARED:
            _identifier(document["owner_token"], "stored effect owner")
            if document["lease_until"] is None or document["completion_json"] is not None:
                raise DurableStoreUnavailable("prepared effect row is inconsistent")
        elif state is EffectLedgerState.APPLYING:
            _identifier(document["owner_token"], "stored effect owner")
            if document["lease_until"] is not None or document["completion_json"] is not None:
                raise DurableStoreUnavailable("applying effect row is inconsistent")
        elif state is EffectLedgerState.COMPLETED:
            if (
                document["owner_token"] is not None
                or document["lease_until"] is not None
                or document["completion_json"] is None
            ):
                raise DurableStoreUnavailable("completed effect row is inconsistent")
            completion = _deserialize_completion(document["completion_json"])
            _validate_completion_binding(effect_body, completion)
        elif any(
            document[field] is not None
            for field in ("owner_token", "lease_until", "completion_json")
        ):
            raise DurableStoreUnavailable("failed-unknown effect row is inconsistent")
        return document


def _parameter_document(effect: AuthorizedEffect) -> dict[str, object]:
    parameters = effect.parameters
    if effect.action is HelperAction.ACTIVATE_STAGED_RELEASE and isinstance(
        parameters, ActivateReleaseParameters
    ):
        return {"release_sha256": parameters.release_sha256}
    if effect.action is HelperAction.SET_RECOVERY_BOOT_ONCE and isinstance(
        parameters, RecoveryBootParameters
    ):
        return {"slot": parameters.slot.value}
    if effect.action is HelperAction.ASSIGN_MODEL_DEVICE and isinstance(
        parameters, AssignDeviceParameters
    ):
        return {
            "assignment_id": parameters.assignment_id,
            "worker_id": parameters.worker_id,
        }
    if effect.action is HelperAction.START_GENERATED_WORKER and isinstance(
        parameters, StartGeneratedWorkerParameters
    ):
        return {
            "artifact_sha256": parameters.artifact_sha256,
            "assignment_id": parameters.assignment_id,
            "code_kind": parameters.code_kind.value,
            "worker_id": parameters.worker_id,
            "workload_id": parameters.workload_id,
        }
    raise DurableValidationError("effect action and typed parameters do not match")


def _peer_document(peer: AuthenticatedPeer) -> dict[str, object]:
    if not isinstance(peer, AuthenticatedPeer):
        raise DurableValidationError("effect peer is invalid")
    return {
        "authenticated": peer.authenticated,
        "credential_sha256": peer.credential_sha256,
        "principal": peer.principal,
        "session_id": peer.session_id,
        "transport": peer.transport.value,
        "transport_identity": peer.transport_identity,
    }


def _authority_document(decision: AuthorityDecision) -> dict[str, object]:
    if not isinstance(decision, AuthorityDecision):
        raise DurableValidationError("effect authority is invalid")
    return {
        "action": decision.action.value,
        "allowed": decision.allowed,
        "authority_generation": decision.authority_generation,
        "authority_id": decision.authority_id,
        "capability_sha256": decision.capability_sha256,
        "decision_id": decision.decision_id,
        "expires_at": _time_text(decision.expires_at, "authority.expires_at"),
        "peer_identity_sha256": decision.peer_identity_sha256,
        "request_sha256": decision.request_sha256,
        "revoked": decision.revoked,
        "subject": decision.subject,
    }


def _confinement_document(evidence: ConfinementAttestation) -> dict[str, object]:
    if not isinstance(evidence, ConfinementAttestation):
        raise DurableValidationError("effect confinement attestation is invalid")
    return {
        "action": evidence.action.value,
        "artifact_sha256": evidence.artifact_sha256,
        "attestation_id": evidence.attestation_id,
        "attested_at": _time_text(evidence.attested_at, "confinement.attested_at"),
        "enforcing": evidence.enforcing,
        "mode": evidence.mode.value,
        "peer_identity_sha256": evidence.peer_identity_sha256,
        "profile_id": evidence.profile_id,
        "profile_sha256": evidence.profile_sha256,
        "profile_version": evidence.profile_version,
        "qualification_id": evidence.qualification_id,
        "request_sha256": evidence.request_sha256,
        "signature": evidence.signature.hex(),
        "signer_key_id": evidence.signer_key_id,
        "valid_until": _time_text(evidence.valid_until, "confinement.valid_until"),
        "worker_id": evidence.worker_id,
    }


def _device_document(
    capability: DeviceCapability | None,
    safe_handle_commitment: Callable[[str], str] | None,
) -> dict[str, object] | None:
    if capability is None:
        return None
    if not isinstance(capability, DeviceCapability):
        raise DurableValidationError("effect device capability is invalid")
    if safe_handle_commitment is None:
        raise DurableValidationError(
            "device effects require a keyed safe-handle commitment"
        )
    return {
        "assignment_generation": capability.assignment_generation,
        "assignment_id": capability.assignment_id,
        "capability_id": capability.capability_id,
        "devices": [
            {
                "device_type": item.device_type.value,
                "host_identity_sha256": item.host_identity_sha256,
                "major": item.major,
                "minor": item.minor,
                "safe_handle_token_hmac_sha256": _digest(
                    safe_handle_commitment(item.safe_handle_token),
                    "safe handle commitment",
                ),
                "stable_identity_sha256": item.stable_identity_sha256,
            }
            for item in capability.devices
        ],
        "exclusive": capability.exclusive,
        "issued_at": _time_text(capability.issued_at, "device.issued_at"),
        "peer_identity_sha256": capability.peer_identity_sha256,
        "request_sha256": capability.request_sha256,
        "valid_until": _time_text(capability.valid_until, "device.valid_until"),
        "worker_id": capability.worker_id,
    }


def canonical_effect_document(
    effect: AuthorizedEffect,
    *,
    safe_handle_commitment: Callable[[str], str] | None = None,
) -> dict[str, object]:
    """Return the exact security-relevant document committed before dispatch."""

    if not isinstance(effect, AuthorizedEffect):
        raise DurableValidationError("executor requires an AuthorizedEffect")
    document = {
        "action": effect.action.value,
        "authority": _authority_document(effect.authority),
        "confinement": _confinement_document(effect.confinement),
        "device_capability": _device_document(
            effect.device_capability, safe_handle_commitment
        ),
        "driver_certificate_sha256": effect.driver_certificate_sha256,
        "idempotency_key": effect.idempotency_key,
        "parameters": _parameter_document(effect),
        "peer": _peer_document(effect.peer),
        "request_id": effect.request_id,
        "request_sha256": effect.request_sha256,
        "schema_version": 1,
        "subject": effect.subject,
    }
    encoded = _canonical_bytes(document)
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise DurableValidationError("effect document exceeds the durable limit")
    return document


def validate_authorized_effect(effect: AuthorizedEffect, observed_at: datetime) -> None:
    """Validate every binding available at the executor trust boundary.

    Signature, revocation, transport, device-handle, and certificate liveness
    are deliberately left to the mandatory injected dispatch validator.  This
    pure validator rejects malformed, cross-bound, or temporally stale values
    even when a caller constructs ``AuthorizedEffect`` directly.
    """

    if not isinstance(effect, AuthorizedEffect):
        raise DurableValidationError("executor requires an AuthorizedEffect")
    now = _aware(observed_at, "effect validation time")
    request_id = _identifier(effect.request_id, "effect.request_id")
    request_sha256 = _digest(effect.request_sha256, "effect.request_sha256")
    expected_idempotency = hashlib.sha256(
        f"luma-helper-v1:{request_id}:{request_sha256}".encode("ascii")
    ).hexdigest()
    if _digest(effect.idempotency_key, "effect.idempotency_key") != expected_idempotency:
        raise DurableValidationError("effect idempotency key is not request-derived")
    subject = _identifier(effect.subject, "effect.subject")
    if not isinstance(effect.action, HelperAction):
        raise DurableValidationError("effect action is invalid")
    _parameter_document(effect)

    peer = effect.peer
    if not isinstance(peer, AuthenticatedPeer) or peer.authenticated is not True:
        raise DurableValidationError("effect peer is not authenticated")
    if peer.principal != subject:
        raise DurableValidationError("effect subject is not bound to the peer")
    peer_sha256 = peer.identity_sha256

    authority = effect.authority
    if not isinstance(authority, AuthorityDecision):
        raise DurableValidationError("effect authority is invalid")
    if authority.allowed is not True or authority.revoked is not False:
        raise DurableValidationError("effect authority is denied or revoked")
    if (
        authority.subject != subject
        or authority.peer_identity_sha256 != peer_sha256
        or authority.action is not effect.action
        or authority.request_sha256 != request_sha256
    ):
        raise DurableValidationError("effect authority binding is inconsistent")
    if now >= _aware(authority.expires_at, "authority.expires_at"):
        raise DurableValidationError("effect authority is expired")

    confinement = effect.confinement
    if not isinstance(confinement, ConfinementAttestation):
        raise DurableValidationError("effect confinement attestation is invalid")
    worker_id = getattr(effect.parameters, "worker_id", None)
    artifact_sha256 = getattr(effect.parameters, "artifact_sha256", None)
    if (
        confinement.request_sha256 != request_sha256
        or confinement.peer_identity_sha256 != peer_sha256
        or confinement.action is not effect.action
        or confinement.worker_id != worker_id
        or confinement.artifact_sha256 != artifact_sha256
        or confinement.enforcing is not True
    ):
        raise DurableValidationError("effect confinement binding is inconsistent")
    if not (
        _aware(confinement.attested_at, "confinement.attested_at")
        <= now
        < _aware(confinement.valid_until, "confinement.valid_until")
    ):
        raise DurableValidationError("effect confinement attestation is not current")
    if (
        isinstance(effect.parameters, StartGeneratedWorkerParameters)
        and effect.parameters.code_kind is GeneratedCodeKind.NATIVE
        and confinement.mode.value
        not in {"kvm_microvm", "qualified_constrained_runtime"}
    ):
        raise DurableValidationError("native code lacks qualified confinement")

    assignment_id = getattr(effect.parameters, "assignment_id", None)
    capability = effect.device_capability
    if assignment_id is None:
        if capability is not None or effect.driver_certificate_sha256 is not None:
            raise DurableValidationError("effect has unexpected device authority")
    else:
        if capability is None or effect.driver_certificate_sha256 is None:
            raise DurableValidationError("effect device authority is incomplete")
        _digest(effect.driver_certificate_sha256, "driver_certificate_sha256")
        if (
            capability.request_sha256 != request_sha256
            or capability.peer_identity_sha256 != peer_sha256
            or capability.assignment_id != assignment_id
            or capability.worker_id != worker_id
            or capability.exclusive is not True
        ):
            raise DurableValidationError("effect device capability binding is inconsistent")
        if not (
            _aware(capability.issued_at, "device.issued_at")
            <= now
            < _aware(capability.valid_until, "device.valid_until")
        ):
            raise DurableValidationError("effect device capability is not current")

    capability_sha256 = hashlib.sha256(
        _canonical_bytes(
            {
                "confinement_attestation_sha256": confinement.digest,
                "device_capability_sha256": capability.digest if capability else None,
                "driver_certificate_sha256": effect.driver_certificate_sha256,
                "request_sha256": request_sha256,
            }
        )
    ).hexdigest()
    if authority.capability_sha256 != capability_sha256:
        raise DurableValidationError("effect capability digest is inconsistent")


_EFFECT_FIELDS = {
    "action",
    "authority",
    "confinement",
    "device_capability",
    "driver_certificate_sha256",
    "idempotency_key",
    "parameters",
    "peer",
    "request_id",
    "request_sha256",
    "schema_version",
    "subject",
}


def _validate_persisted_effect_binding(
    row_document: Mapping[str, object], effect_document: Mapping[str, object]
) -> None:
    _exact_keys(effect_document, _EFFECT_FIELDS, "effect document")
    if type(effect_document["schema_version"]) is not int or effect_document["schema_version"] != 1:
        raise DurableStoreUnavailable("effect document schema version is unsupported")
    for field in ("request_id", "request_sha256", "idempotency_key", "action"):
        if effect_document[field] != row_document[field]:
            raise DurableStoreUnavailable(
                f"effect document {field} does not bind its ledger row"
            )
    _identifier(effect_document["subject"], "stored effect subject")

    authority = effect_document["authority"]
    if not isinstance(authority, dict):
        raise DurableStoreUnavailable("stored effect authority is invalid")
    _exact_keys(
        authority,
        {
            "action",
            "allowed",
            "authority_generation",
            "authority_id",
            "capability_sha256",
            "decision_id",
            "expires_at",
            "peer_identity_sha256",
            "request_sha256",
            "revoked",
            "subject",
        },
        "effect authority",
    )
    if (
        authority["action"] != effect_document["action"]
        or authority["request_sha256"] != effect_document["request_sha256"]
        or authority["subject"] != effect_document["subject"]
        or authority["allowed"] is not True
        or authority["revoked"] is not False
    ):
        raise DurableStoreUnavailable("stored effect authority is not cross-bound")
    _identifier(authority["decision_id"], "stored authority decision_id")
    _positive(authority["authority_generation"], "stored authority generation")
    _digest(authority["capability_sha256"], "stored authority capability digest")
    _parse_time(authority["expires_at"], "stored authority expiry")

    peer = effect_document["peer"]
    confinement = effect_document["confinement"]
    if not isinstance(peer, dict) or not isinstance(confinement, dict):
        raise DurableStoreUnavailable("stored peer or confinement document is invalid")
    if (
        peer.get("authenticated") is not True
        or peer.get("principal") != effect_document["subject"]
        or confinement.get("action") != effect_document["action"]
        or confinement.get("request_sha256") != effect_document["request_sha256"]
        or confinement.get("enforcing") is not True
        or authority["peer_identity_sha256"] != confinement.get("peer_identity_sha256")
    ):
        raise DurableStoreUnavailable("stored peer/confinement binding is inconsistent")

    device = effect_document["device_capability"]
    if device is not None:
        if not isinstance(device, dict) or not isinstance(device.get("devices"), list):
            raise DurableStoreUnavailable("stored device capability is invalid")
        for item in device["devices"]:
            if not isinstance(item, dict) or set(item) != {
                "device_type",
                "host_identity_sha256",
                "major",
                "minor",
                "safe_handle_token_hmac_sha256",
                "stable_identity_sha256",
            }:
                raise DurableStoreUnavailable("stored device projection is invalid")
            _digest(
                item["safe_handle_token_hmac_sha256"],
                "stored safe-handle commitment",
            )
        if effect_document["driver_certificate_sha256"] is None:
            raise DurableStoreUnavailable("stored device effect lacks a certificate digest")
    elif effect_document["driver_certificate_sha256"] is not None:
        raise DurableStoreUnavailable("stored certificate digest lacks a device capability")


def _validate_completion_binding(
    effect_document: Mapping[str, object], completion: ExecutorCompletion
) -> None:
    authority = effect_document.get("authority")
    if not isinstance(authority, dict):
        raise DurableStoreUnavailable("stored effect authority is invalid")
    expected = (
        (completion.request_id, effect_document.get("request_id")),
        (completion.request_sha256, effect_document.get("request_sha256")),
        (completion.idempotency_key, effect_document.get("idempotency_key")),
        (completion.subject, effect_document.get("subject")),
        (completion.action.value, effect_document.get("action")),
        (completion.decision_id, authority.get("decision_id")),
        (completion.authority_generation, authority.get("authority_generation")),
        (completion.capability_sha256, authority.get("capability_sha256")),
    )
    if any(observed != wanted for observed, wanted in expected):
        raise DurableStoreUnavailable("completion does not bind the stored effect")


def _prepared_request_identity(
    effect_document: Mapping[str, object],
) -> dict[str, object]:
    """Project the immutable request identity from a validated effect.

    A PREPARED row proves that no adapter was entered. A retry may therefore
    replace short-lived authorization evidence, but it must not change the
    typed request, authenticated peer, authority generation, confinement
    claim, or stable device selection carried by the original request.
    """

    _exact_keys(effect_document, _EFFECT_FIELDS, "prepared effect document")
    authority = effect_document.get("authority")
    confinement = effect_document.get("confinement")
    device = effect_document.get("device_capability")
    if not isinstance(authority, dict) or not isinstance(confinement, dict):
        raise DurableStoreUnavailable(
            "prepared effect lacks authority or confinement identity"
        )
    device_identity: dict[str, object] | None = None
    if device is not None:
        if not isinstance(device, dict) or not isinstance(device.get("devices"), list):
            raise DurableStoreUnavailable("prepared device capability is invalid")
        stable_devices: list[dict[str, object]] = []
        for item in device["devices"]:
            if not isinstance(item, dict):
                raise DurableStoreUnavailable("prepared device identity is invalid")
            stable_devices.append(
                {
                    "device_type": item.get("device_type"),
                    "host_identity_sha256": item.get("host_identity_sha256"),
                    "major": item.get("major"),
                    "minor": item.get("minor"),
                    "stable_identity_sha256": item.get("stable_identity_sha256"),
                }
            )
        device_identity = {
            "assignment_generation": device.get("assignment_generation"),
            "assignment_id": device.get("assignment_id"),
            "devices": stable_devices,
            "exclusive": device.get("exclusive"),
            "peer_identity_sha256": device.get("peer_identity_sha256"),
            "request_sha256": device.get("request_sha256"),
            "worker_id": device.get("worker_id"),
        }
    return {
        "action": effect_document.get("action"),
        "authority_generation": authority.get("authority_generation"),
        "authority_id": authority.get("authority_id"),
        "confinement_claim": {
            "action": confinement.get("action"),
            "artifact_sha256": confinement.get("artifact_sha256"),
            "mode": confinement.get("mode"),
            "peer_identity_sha256": confinement.get("peer_identity_sha256"),
            "profile_id": confinement.get("profile_id"),
            "profile_sha256": confinement.get("profile_sha256"),
            "profile_version": confinement.get("profile_version"),
            "qualification_id": confinement.get("qualification_id"),
            "request_sha256": confinement.get("request_sha256"),
            "worker_id": confinement.get("worker_id"),
        },
        "device_identity": device_identity,
        "driver_certificate_sha256": effect_document.get(
            "driver_certificate_sha256"
        ),
        "idempotency_key": effect_document.get("idempotency_key"),
        "parameters": effect_document.get("parameters"),
        "peer_identity_sha256": authority.get("peer_identity_sha256"),
        "request_id": effect_document.get("request_id"),
        "request_sha256": effect_document.get("request_sha256"),
        "schema_version": effect_document.get("schema_version"),
        "subject": effect_document.get("subject"),
    }


def _result_document(result: EffectResult) -> dict[str, object]:
    if not isinstance(result, EffectResult):
        raise DurableValidationError("effect result is invalid")
    return {
        "evidence_sha256": result.evidence_sha256,
        "result_code": result.result_code,
    }


def _serialize_receipt(receipt: EffectReceipt) -> str:
    if not isinstance(receipt, EffectReceipt):
        raise DurableValidationError("receipt must be an EffectReceipt")
    return _canonical_text(
        {
            "action": receipt.action.value,
            "authority_generation": receipt.authority_generation,
            "capability_sha256": receipt.capability_sha256,
            "decision_id": receipt.decision_id,
            "evidence_sha256": receipt.evidence_sha256,
            "executed_at": _time_text(receipt.executed_at, "receipt.executed_at"),
            "idempotency_key": receipt.idempotency_key,
            "request_id": receipt.request_id,
            "request_sha256": receipt.request_sha256,
            "result_code": receipt.result_code,
            "schema_version": 1,
            "subject": receipt.subject,
        }
    )


def _exact_keys(document: Mapping[str, object], expected: set[str], field: str) -> None:
    if set(document) != expected:
        raise DurableStoreUnavailable(f"{field} has unexpected fields")


def _deserialize_receipt(value: object) -> EffectReceipt:
    document = _parse_canonical_json(value, "receipt_json")
    fields = {
        "action",
        "authority_generation",
        "capability_sha256",
        "decision_id",
        "evidence_sha256",
        "executed_at",
        "idempotency_key",
        "request_id",
        "request_sha256",
        "result_code",
        "schema_version",
        "subject",
    }
    _exact_keys(document, fields, "receipt")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise DurableStoreUnavailable("receipt schema version is unsupported")
    try:
        return EffectReceipt(
            request_id=document["request_id"],  # type: ignore[arg-type]
            request_sha256=document["request_sha256"],  # type: ignore[arg-type]
            idempotency_key=document["idempotency_key"],  # type: ignore[arg-type]
            subject=document["subject"],  # type: ignore[arg-type]
            action=HelperAction(document["action"]),  # type: ignore[arg-type]
            decision_id=document["decision_id"],  # type: ignore[arg-type]
            authority_generation=document["authority_generation"],  # type: ignore[arg-type]
            capability_sha256=document["capability_sha256"],  # type: ignore[arg-type]
            result_code=document["result_code"],  # type: ignore[arg-type]
            evidence_sha256=document["evidence_sha256"],  # type: ignore[arg-type]
            executed_at=_parse_time(document["executed_at"], "receipt.executed_at"),
        )
    except (TypeError, ValueError) as exc:
        raise DurableStoreUnavailable("stored receipt is invalid") from exc


def _serialize_completion(completion: ExecutorCompletion) -> str:
    if not isinstance(completion, ExecutorCompletion):
        raise DurableValidationError("completion must be an ExecutorCompletion")
    return _canonical_text(
        {
            "action": completion.action.value,
            "authority_generation": completion.authority_generation,
            "capability_sha256": completion.capability_sha256,
            "decision_id": completion.decision_id,
            "executed_at": _time_text(completion.executed_at, "completion.executed_at"),
            "idempotency_key": completion.idempotency_key,
            "request_id": completion.request_id,
            "request_sha256": completion.request_sha256,
            "result": _result_document(completion.result),
            "schema_version": 1,
            "subject": completion.subject,
        }
    )


def _deserialize_completion(value: object) -> ExecutorCompletion:
    document = _parse_canonical_json(value, "completion_json")
    fields = {
        "action",
        "authority_generation",
        "capability_sha256",
        "decision_id",
        "executed_at",
        "idempotency_key",
        "request_id",
        "request_sha256",
        "result",
        "schema_version",
        "subject",
    }
    _exact_keys(document, fields, "completion")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise DurableStoreUnavailable("completion schema version is unsupported")
    result_document = document["result"]
    if not isinstance(result_document, dict):
        raise DurableStoreUnavailable("completion result is invalid")
    _exact_keys(result_document, {"evidence_sha256", "result_code"}, "completion result")
    try:
        result = EffectResult(
            result_code=result_document["result_code"],  # type: ignore[arg-type]
            evidence_sha256=result_document["evidence_sha256"],  # type: ignore[arg-type]
        )
        return ExecutorCompletion(
            request_id=document["request_id"],  # type: ignore[arg-type]
            request_sha256=document["request_sha256"],  # type: ignore[arg-type]
            idempotency_key=document["idempotency_key"],  # type: ignore[arg-type]
            subject=document["subject"],  # type: ignore[arg-type]
            action=HelperAction(document["action"]),  # type: ignore[arg-type]
            decision_id=document["decision_id"],  # type: ignore[arg-type]
            authority_generation=document["authority_generation"],  # type: ignore[arg-type]
            capability_sha256=document["capability_sha256"],  # type: ignore[arg-type]
            result=result,
            executed_at=_parse_time(document["executed_at"], "completion.executed_at"),
        )
    except (TypeError, ValueError) as exc:
        raise DurableStoreUnavailable("stored completion is invalid") from exc


def _completion_from_effect(
    effect_document: Mapping[str, object], result: EffectResult, executed_at: datetime
) -> ExecutorCompletion:
    try:
        authority = effect_document["authority"]
        if not isinstance(authority, dict):
            raise DurableStoreUnavailable("stored effect authority is invalid")
        return ExecutorCompletion(
            request_id=effect_document["request_id"],  # type: ignore[arg-type]
            request_sha256=effect_document["request_sha256"],  # type: ignore[arg-type]
            idempotency_key=effect_document["idempotency_key"],  # type: ignore[arg-type]
            subject=effect_document["subject"],  # type: ignore[arg-type]
            action=HelperAction(effect_document["action"]),  # type: ignore[arg-type]
            decision_id=authority["decision_id"],  # type: ignore[arg-type]
            authority_generation=authority["authority_generation"],  # type: ignore[arg-type]
            capability_sha256=authority["capability_sha256"],  # type: ignore[arg-type]
            result=result,
            executed_at=executed_at,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DurableStoreUnavailable("stored effect cannot produce a completion") from exc


class SQLiteRequestJournal(_SQLiteDurableBase):
    """Persistent bounded implementation of ``RequestJournal``.

    ``retention`` is the minimum advertised retention interval, not an
    automatic deletion policy.  Request identities and terminal receipts are
    intentionally retained for the lifetime of this database so replay
    conflicts remain permanent.  Reaching the hard capacity fails closed and
    requires an explicit, externally audited database rotation.

    Expired pending reservations may be acquired by a new owner.  Safe use of
    that liveness path requires the paired idempotent executor, whose own
    durable CAS prevents a second adapter invocation.  A stale owner cannot
    complete after the journal generation and owner token have changed.
    """

    persistent = True

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        integrity_key: bytes,
        capacity: int = 10_000,
        retention: timedelta = timedelta(days=30),
        clock: Callable[[], datetime] | None = None,
        busy_timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        if not isinstance(retention, timedelta) or retention <= timedelta(0):
            raise DurableValidationError("retention must be positive")
        self.retention = retention
        super().__init__(
            path,
            integrity_key=integrity_key,
            capacity=capacity,
            clock=clock,
            busy_timeout=busy_timeout,
        )

    @staticmethod
    def _record(document: Mapping[str, object]) -> JournalRecord:
        state = JournalState(document["state"])
        receipt = (
            _deserialize_receipt(document["receipt_json"])
            if document["receipt_json"] is not None
            else None
        )
        return JournalRecord(
            request_id=document["request_id"],  # type: ignore[arg-type]
            request_sha256=document["request_sha256"],  # type: ignore[arg-type]
            state=state,
            generation=document["generation"],  # type: ignore[arg-type]
            owner_token=document["owner_token"],  # type: ignore[arg-type]
            receipt=receipt,
        )

    def reserve(
        self,
        request_id: str,
        request_sha256: str,
        owner_token: str,
        observed_at: datetime,
        lease_until: datetime,
    ) -> JournalReservation:
        request_id = _identifier(request_id, "request_id")
        request_sha256 = _digest(request_sha256, "request_sha256")
        owner_token = _identifier(owner_token, "owner_token")
        observed = _aware(observed_at, "observed_at")
        lease = _aware(lease_until, "lease_until")
        if lease <= observed:
            raise DurableValidationError("reservation lease must end after observation time")
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, observed)
            row = connection.execute(
                "SELECT * FROM request_journal WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                count = int(connection.execute("SELECT COUNT(*) FROM request_journal").fetchone()[0])
                if count >= self.capacity:
                    raise DurableCapacityExceeded("request journal capacity is exhausted")
                document: dict[str, object] = {
                    "created_at": now_text,
                    "generation": 1,
                    "lease_until": _time_text(lease, "lease_until"),
                    "owner_token": owner_token,
                    "receipt_json": None,
                    "request_id": request_id,
                    "request_sha256": request_sha256,
                    "state": JournalState.PENDING.value,
                    "updated_at": now_text,
                }
                connection.execute(
                    "INSERT INTO request_journal("
                    "request_id,request_sha256,state,owner_token,generation,lease_until,receipt_json,"
                    "created_at,updated_at,auth_tag) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        request_id,
                        request_sha256,
                        document["state"],
                        owner_token,
                        1,
                        document["lease_until"],
                        None,
                        now_text,
                        now_text,
                        self._tag("request", document),
                    ),
                )
                return JournalReservation(self._record(document), True)

            document = self._verify_request_row(row)
            if document["request_sha256"] != request_sha256:
                raise HelperReplayConflict(DenialReason.REPLAY_CONFLICT)
            state = JournalState(document["state"])
            if state is not JournalState.PENDING:
                return JournalReservation(self._record(document), False)
            existing_lease = _parse_time(document["lease_until"], "request.lease_until")
            if existing_lease > observed:
                return JournalReservation(self._record(document), False)

            previous_generation = int(document["generation"])
            replacement = dict(document)
            replacement.update(
                {
                    "generation": previous_generation + 1,
                    "lease_until": _time_text(lease, "lease_until"),
                    "owner_token": owner_token,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE request_journal SET owner_token=?,generation=?,lease_until=?,updated_at=?,auth_tag=? "
                "WHERE request_id=? AND request_sha256=? AND state='pending' "
                "AND owner_token=? AND generation=? AND auth_tag=?",
                (
                    owner_token,
                    replacement["generation"],
                    replacement["lease_until"],
                    now_text,
                    self._tag("request", replacement),
                    request_id,
                    request_sha256,
                    document["owner_token"],
                    previous_generation,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("request reservation compare-and-swap failed")
            return JournalReservation(self._record(replacement), True)

    def complete(
        self,
        request_id: str,
        request_sha256: str,
        owner_token: str | None,
        generation: int,
        receipt: EffectReceipt,
    ) -> None:
        request_id = _identifier(request_id, "request_id")
        request_sha256 = _digest(request_sha256, "request_sha256")
        if owner_token is not None:
            owner_token = _identifier(owner_token, "owner_token")
        generation = _positive(generation, "generation")
        receipt_json = _serialize_receipt(receipt)
        if receipt.request_id != request_id or receipt.request_sha256 != request_sha256:
            raise DurableValidationError("receipt does not bind the completed request")
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM request_journal WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("cannot complete a missing request reservation")
            document = self._verify_request_row(row)
            if document["request_sha256"] != request_sha256:
                raise HelperReplayConflict(DenialReason.REPLAY_CONFLICT)
            if document["generation"] != generation:
                raise DurableStoreUnavailable("stale request generation cannot complete")
            if JournalState(document["state"]) is JournalState.COMPLETED:
                if document["receipt_json"] != receipt_json:
                    raise DurableStoreUnavailable("completed request receipt is immutable")
                return
            if owner_token is not None and document["owner_token"] != owner_token:
                raise DurableStoreUnavailable("stale request owner cannot complete")
            if JournalState(document["state"]) is JournalState.FAILED_UNKNOWN and owner_token is not None:
                raise DurableStoreUnavailable("failed-unknown request needs reconciled completion")

            replacement = dict(document)
            replacement.update(
                {
                    "lease_until": None,
                    "owner_token": None,
                    "receipt_json": receipt_json,
                    "state": JournalState.COMPLETED.value,
                    "updated_at": now_text,
                }
            )
            where_owner = document["owner_token"]
            changed = connection.execute(
                "UPDATE request_journal SET state='completed',owner_token=NULL,lease_until=NULL,"
                "receipt_json=?,updated_at=?,auth_tag=? WHERE request_id=? AND request_sha256=? "
                "AND state=? AND generation=? AND owner_token IS ? AND auth_tag=?",
                (
                    receipt_json,
                    now_text,
                    self._tag("request", replacement),
                    request_id,
                    request_sha256,
                    document["state"],
                    generation,
                    where_owner,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("request completion compare-and-swap failed")

    def mark_failed_unknown(
        self,
        request_id: str,
        request_sha256: str,
        owner_token: str,
        generation: int,
    ) -> None:
        request_id = _identifier(request_id, "request_id")
        request_sha256 = _digest(request_sha256, "request_sha256")
        owner_token = _identifier(owner_token, "owner_token")
        generation = _positive(generation, "generation")
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM request_journal WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("cannot fence a missing request reservation")
            document = self._verify_request_row(row)
            if document["request_sha256"] != request_sha256:
                raise HelperReplayConflict(DenialReason.REPLAY_CONFLICT)
            if document["generation"] != generation:
                raise DurableStoreUnavailable("stale request generation cannot fence outcome")
            state = JournalState(document["state"])
            if state is JournalState.FAILED_UNKNOWN:
                return
            if state is not JournalState.PENDING or document["owner_token"] != owner_token:
                raise DurableStoreUnavailable("stale request owner cannot fence outcome")
            replacement = dict(document)
            replacement.update(
                {
                    "lease_until": None,
                    "owner_token": None,
                    "state": JournalState.FAILED_UNKNOWN.value,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE request_journal SET state='failed_unknown',owner_token=NULL,lease_until=NULL,"
                "updated_at=?,auth_tag=? WHERE request_id=? AND request_sha256=? "
                "AND state='pending' AND owner_token=? AND generation=? AND auth_tag=?",
                (
                    now_text,
                    self._tag("request", replacement),
                    request_id,
                    request_sha256,
                    owner_token,
                    generation,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("request fencing compare-and-swap failed")


class SQLiteIdempotentEffectExecutor(_SQLiteDurableBase):
    """Persistent fixed-registry implementation of ``EffectExecutor``.

    ``PREPARED`` means the action adapter has not been entered and can be
    safely claimed immediately through an owner/generation CAS. ``APPLYING`` is committed before
    adapter entry; a process loss from that point onward is ambiguous and is
    never automatically redispatched.  Only the fixed action adapter's
    reconciler can convert ambiguity into a durable completion.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        integrity_key: bytes,
        adapters: Mapping[HelperAction, TypedEffectAdapter],
        dispatch_validator: Callable[[AuthorizedEffect, datetime], bool],
        capacity: int = 10_000,
        preparation_lease: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] | None = None,
        owner_token_factory: Callable[[], str] | None = None,
        busy_timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        if not isinstance(adapters, Mapping):
            raise DurableValidationError("adapters must be a mapping")
        copied: dict[HelperAction, TypedEffectAdapter] = {}
        for action, adapter in adapters.items():
            if not isinstance(action, HelperAction):
                raise DurableValidationError("adapter keys must be HelperAction values")
            if not callable(getattr(adapter, "apply", None)) or not callable(
                getattr(adapter, "reconcile", None)
            ):
                raise DurableValidationError("each typed adapter must implement apply and reconcile")
            copied[action] = adapter
        if not copied:
            raise DurableValidationError("at least one fixed typed adapter is required")
        if not callable(dispatch_validator):
            raise DurableValidationError("dispatch_validator must be callable")
        if not isinstance(preparation_lease, timedelta) or preparation_lease <= timedelta(0):
            raise DurableValidationError("preparation_lease must be positive")
        if owner_token_factory is not None and not callable(owner_token_factory):
            raise DurableValidationError("owner_token_factory must be callable")
        self._adapters = MappingProxyType(copied)
        self._dispatch_validator = dispatch_validator
        self._preparation_lease = preparation_lease
        self._owner_token_factory = owner_token_factory or (lambda: uuid.uuid4().hex)
        super().__init__(
            path,
            integrity_key=integrity_key,
            capacity=capacity,
            clock=clock,
            busy_timeout=busy_timeout,
        )

    @property
    def actions(self) -> tuple[HelperAction, ...]:
        return tuple(sorted(self._adapters, key=lambda item: item.value))

    def _owner(self) -> str:
        return _identifier(self._owner_token_factory(), "effect owner token")

    def _safe_handle_commitment(self, token: str) -> str:
        return hmac.new(
            self._key,
            b"safe-handle-token\x00" + token.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _effect_document(self, effect: AuthorizedEffect) -> dict[str, object]:
        return canonical_effect_document(
            effect, safe_handle_commitment=self._safe_handle_commitment
        )

    def _validate_dispatch(self, effect: AuthorizedEffect, observed_at: datetime) -> None:
        validate_authorized_effect(effect, observed_at)
        try:
            allowed = self._dispatch_validator(effect, observed_at)
        except Exception as exc:
            raise DurableValidationError("dispatch validator failed closed") from exc
        if allowed is not True:
            raise DurableValidationError("dispatch validator denied current effect state")

    @staticmethod
    def _validate_replay_identity(effect: AuthorizedEffect) -> None:
        if not isinstance(effect, AuthorizedEffect):
            raise DurableValidationError("executor requires an AuthorizedEffect")
        request_id = _identifier(effect.request_id, "effect.request_id")
        request_sha256 = _digest(effect.request_sha256, "effect.request_sha256")
        expected = hashlib.sha256(
            f"luma-helper-v1:{request_id}:{request_sha256}".encode("ascii")
        ).hexdigest()
        if _digest(effect.idempotency_key, "effect.idempotency_key") != expected:
            raise DurableValidationError("effect idempotency key is not request-derived")
        if not isinstance(effect.action, HelperAction):
            raise DurableValidationError("effect action is invalid")

    def _completed_replay(
        self, effect: AuthorizedEffect
    ) -> ExecutorCompletion | None:
        self._validate_replay_identity(effect)
        with self._transaction() as connection:
            self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?",
                (effect.idempotency_key,),
            ).fetchone()
            if row is None:
                return None
            document = self._verify_effect_row(row)
            if (
                document["request_id"] != effect.request_id
                or document["request_sha256"] != effect.request_sha256
                or document["action"] != effect.action.value
            ):
                raise DurableEffectConflict("idempotency key was reused for another request")
            if EffectLedgerState(document["state"]) is not EffectLedgerState.COMPLETED:
                return None
            replay_json = _canonical_text(self._effect_document(effect))
            if document["effect_json"] != replay_json:
                raise DurableEffectConflict(
                    "idempotency key was reused for different effect bytes"
                )
            return _deserialize_completion(document["completion_json"])

    @staticmethod
    def _stored_effect(document: Mapping[str, object]) -> StoredEffect:
        effect_body = _parse_canonical_json(document["effect_json"], "effect.effect_json")
        return StoredEffect(
            idempotency_key=document["idempotency_key"],  # type: ignore[arg-type]
            request_id=document["request_id"],  # type: ignore[arg-type]
            request_sha256=document["request_sha256"],  # type: ignore[arg-type]
            action=HelperAction(document["action"]),  # type: ignore[arg-type]
            effect_sha256=document["effect_sha256"],  # type: ignore[arg-type]
            state=EffectLedgerState(document["state"]),  # type: ignore[arg-type]
            document=effect_body,
        )

    def _prepare(
        self,
        effect: AuthorizedEffect,
        effect_json: str,
        effect_sha256: str,
        owner: str,
    ) -> tuple[int, ExecutorCompletion | None]:
        expected_json = _canonical_text(self._effect_document(effect))
        expected_sha256 = hashlib.sha256(expected_json.encode("ascii")).hexdigest()
        if effect_json != expected_json or effect_sha256 != expected_sha256:
            raise DurableValidationError(
                "prepared effect encoding does not match the authorized effect"
            )
        incoming_effect = _parse_canonical_json(effect_json, "effect.effect_json")
        try:
            now = self._now()
        except Exception as exc:
            raise HelperEffectNotApplied(
                "effect preparation clock was unavailable"
            ) from exc
        with self._transaction() as connection:
            try:
                now_text = self._observe_clock(connection, now)
            except DurableClockRollback as exc:
                raise HelperEffectNotApplied(
                    "effect was not prepared after clock rollback"
                ) from exc
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?",
                (effect.idempotency_key,),
            ).fetchone()
            if row is None:
                count = int(connection.execute("SELECT COUNT(*) FROM effect_ledger").fetchone()[0])
                if count >= self.capacity:
                    raise DurableCapacityExceeded("effect ledger capacity is exhausted")
                lease_text = _time_text(now + self._preparation_lease, "effect.lease_until")
                document: dict[str, object] = {
                    "action": effect.action.value,
                    "completion_json": None,
                    "created_at": now_text,
                    "effect_json": effect_json,
                    "effect_sha256": effect_sha256,
                    "generation": 1,
                    "idempotency_key": effect.idempotency_key,
                    "lease_until": lease_text,
                    "owner_token": owner,
                    "request_id": effect.request_id,
                    "request_sha256": effect.request_sha256,
                    "state": EffectLedgerState.PREPARED.value,
                    "updated_at": now_text,
                }
                connection.execute(
                    "INSERT INTO effect_ledger("
                    "idempotency_key,request_id,request_sha256,action,effect_sha256,effect_json,"
                    "state,owner_token,generation,lease_until,completion_json,created_at,updated_at,auth_tag"
                    ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        effect.idempotency_key,
                        effect.request_id,
                        effect.request_sha256,
                        effect.action.value,
                        effect_sha256,
                        effect_json,
                        EffectLedgerState.PREPARED.value,
                        owner,
                        1,
                        lease_text,
                        None,
                        now_text,
                        now_text,
                        self._tag("effect", document),
                    ),
                )
                return 1, None

            document = self._verify_effect_row(row)
            if (
                document["request_id"] != effect.request_id
                or document["request_sha256"] != effect.request_sha256
                or document["action"] != effect.action.value
            ):
                raise DurableEffectConflict("idempotency key was reused for another effect")
            stored_effect = _parse_canonical_json(
                document["effect_json"], "effect.effect_json"
            )
            if _prepared_request_identity(stored_effect) != _prepared_request_identity(
                incoming_effect
            ):
                raise DurableEffectConflict(
                    "idempotency key was reused for different request semantics"
                )
            state = EffectLedgerState(document["state"])
            same_effect = (
                document["effect_sha256"] == effect_sha256
                and document["effect_json"] == effect_json
            )
            if state is not EffectLedgerState.PREPARED and not same_effect:
                raise DurableEffectConflict(
                    "idempotency key was reused for different effect bytes"
                )
            if state is EffectLedgerState.COMPLETED:
                completion = _deserialize_completion(document["completion_json"])
                return int(document["generation"]), completion
            if state in {EffectLedgerState.APPLYING, EffectLedgerState.FAILED_UNKNOWN}:
                raise DurableEffectUnknown("effect outcome is ambiguous and fenced")

            # PREPARED proves no adapter entry occurred.  It is therefore safe
            # to steal immediately; owner/generation CAS ensures exactly one
            # contender can subsequently enter APPLYING.
            generation = int(document["generation"]) + 1
            replacement = dict(document)
            replacement.update(
                {
                    "effect_json": effect_json,
                    "effect_sha256": effect_sha256,
                    "generation": generation,
                    "lease_until": _time_text(
                        now + self._preparation_lease, "effect.lease_until"
                    ),
                    "owner_token": owner,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE effect_ledger SET effect_sha256=?,effect_json=?,owner_token=?,generation=?,"
                "lease_until=?,updated_at=?,auth_tag=? "
                "WHERE idempotency_key=? AND state='prepared' AND owner_token=? "
                "AND generation=? AND auth_tag=?",
                (
                    effect_sha256,
                    effect_json,
                    owner,
                    generation,
                    replacement["lease_until"],
                    now_text,
                    self._tag("effect", replacement),
                    effect.idempotency_key,
                    document["owner_token"],
                    document["generation"],
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("effect preparation compare-and-swap failed")
            return generation, None

    def _begin_apply(
        self,
        idempotency_key: str,
        request_sha256: str,
        owner: str,
        generation: int,
        transition_at: datetime,
    ) -> None:
        try:
            self._begin_apply_once(
                idempotency_key,
                request_sha256,
                owner,
                generation,
                transition_at,
            )
        except DurableStoreBusy as exc:
            raise HelperEffectNotApplied(
                "effect APPLYING transition was contended and not attempted"
            ) from exc

    def _begin_apply_once(
        self,
        idempotency_key: str,
        request_sha256: str,
        owner: str,
        generation: int,
        transition_at: datetime,
    ) -> None:
        # The current-state validator has already run. Never wait for another
        # writer here: a wait would widen the revocation/expiry-to-effect gap.
        with self._transaction(busy_timeout_ms=0) as connection:
            try:
                now_text = self._observe_clock(connection, transition_at)
            except DurableClockRollback as exc:
                raise HelperEffectNotApplied(
                    "effect was not applied after clock rollback"
                ) from exc
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("prepared effect disappeared")
            document = self._verify_effect_row(row)
            if document["request_sha256"] != request_sha256:
                raise DurableEffectConflict("effect request digest changed")
            replacement = dict(document)
            replacement.update(
                {
                    "lease_until": None,
                    "state": EffectLedgerState.APPLYING.value,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE effect_ledger SET state='applying',lease_until=NULL,updated_at=?,auth_tag=? "
                "WHERE idempotency_key=? AND request_sha256=? AND state='prepared' "
                "AND owner_token=? AND generation=? AND auth_tag=?",
                (
                    now_text,
                    self._tag("effect", replacement),
                    idempotency_key,
                    request_sha256,
                    owner,
                    generation,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableEffectInProgress("effect preparation ownership was lost")

    def _restore_prepared(
        self,
        idempotency_key: str,
        request_sha256: str,
        owner: str,
        generation: int,
        transition_at: datetime,
    ) -> None:
        """Restore a known-not-applied post-CAS validation failure.

        The caller may use this only before adapter entry.  Failure to prove
        the owner/generation transition leaves ``APPLYING`` fenced because the
        durable outcome can no longer be established safely.
        """

        with self._transaction() as connection:
            now = _aware(transition_at, "effect restore time")
            now_text = self._observe_clock(connection, now)
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("applying effect disappeared before restoration")
            document = self._verify_effect_row(row)
            if document["request_sha256"] != request_sha256:
                raise DurableEffectConflict("effect request digest changed")
            replacement = dict(document)
            replacement.update(
                {
                    "lease_until": _time_text(
                        now + self._preparation_lease, "effect.lease_until"
                    ),
                    "state": EffectLedgerState.PREPARED.value,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE effect_ledger SET state='prepared',lease_until=?,updated_at=?,auth_tag=? "
                "WHERE idempotency_key=? AND request_sha256=? AND state='applying' "
                "AND owner_token=? AND generation=? AND auth_tag=?",
                (
                    replacement["lease_until"],
                    now_text,
                    self._tag("effect", replacement),
                    idempotency_key,
                    request_sha256,
                    owner,
                    generation,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable(
                    "effect restoration compare-and-swap failed"
                )

    def _mark_effect_unknown(
        self, idempotency_key: str, request_sha256: str, owner: str, generation: int
    ) -> None:
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("applying effect disappeared")
            document = self._verify_effect_row(row)
            if EffectLedgerState(document["state"]) is EffectLedgerState.FAILED_UNKNOWN:
                return
            replacement = dict(document)
            replacement.update(
                {
                    "owner_token": None,
                    "state": EffectLedgerState.FAILED_UNKNOWN.value,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE effect_ledger SET state='failed_unknown',owner_token=NULL,updated_at=?,auth_tag=? "
                "WHERE idempotency_key=? AND request_sha256=? AND state='applying' "
                "AND owner_token=? AND generation=? AND auth_tag=?",
                (
                    now_text,
                    self._tag("effect", replacement),
                    idempotency_key,
                    request_sha256,
                    owner,
                    generation,
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("effect ambiguity fencing compare-and-swap failed")

    def _complete_effect(
        self,
        idempotency_key: str,
        request_sha256: str,
        owner: str | None,
        generation: int,
        completion: ExecutorCompletion,
        allowed_states: tuple[EffectLedgerState, ...],
    ) -> None:
        completion_json = _serialize_completion(completion)
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("effect disappeared before completion")
            document = self._verify_effect_row(row)
            if document["request_sha256"] != request_sha256:
                raise DurableEffectConflict("effect request digest changed")
            effect_document = _parse_canonical_json(
                document["effect_json"], "effect.effect_json"
            )
            _validate_completion_binding(effect_document, completion)
            state = EffectLedgerState(document["state"])
            if state is EffectLedgerState.COMPLETED:
                if document["completion_json"] != completion_json:
                    raise DurableStoreUnavailable("completed effect is immutable")
                return
            if state not in allowed_states:
                raise DurableEffectUnknown("effect cannot complete from its current state")
            if owner is not None and document["owner_token"] != owner:
                raise DurableEffectUnknown("stale effect owner cannot complete")
            replacement = dict(document)
            replacement.update(
                {
                    "completion_json": completion_json,
                    "lease_until": None,
                    "owner_token": None,
                    "state": EffectLedgerState.COMPLETED.value,
                    "updated_at": now_text,
                }
            )
            placeholders = ",".join("?" for _ in allowed_states)
            parameters: list[object] = [
                completion_json,
                now_text,
                self._tag("effect", replacement),
                idempotency_key,
                request_sha256,
                generation,
                *[item.value for item in allowed_states],
            ]
            owner_clause = ""
            if owner is not None:
                owner_clause = " AND owner_token=?"
                parameters.append(owner)
            parameters.append(row["auth_tag"])
            changed = connection.execute(
                "UPDATE effect_ledger SET state='completed',owner_token=NULL,lease_until=NULL,"
                "completion_json=?,updated_at=?,auth_tag=? WHERE idempotency_key=? "
                "AND request_sha256=? AND generation=? "
                f"AND state IN ({placeholders}){owner_clause} AND auth_tag=?",
                tuple(parameters),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("effect completion compare-and-swap failed")

    def execute(self, effect: AuthorizedEffect) -> ExecutorCompletion:
        replay = self._completed_replay(effect)
        if replay is not None:
            return replay
        adapter = self._adapters.get(effect.action)
        if adapter is None:
            raise HelperEffectNotApplied(
                "no fixed adapter is registered for this action"
            )
        try:
            self._validate_dispatch(effect, self._now())
            document = self._effect_document(effect)
            effect_json = _canonical_text(document)
            effect_sha256 = hashlib.sha256(effect_json.encode("ascii")).hexdigest()
            owner = self._owner()
        except Exception as exc:
            raise HelperEffectNotApplied(
                "effect was rejected before durable preparation"
            ) from exc
        try:
            generation, completed = self._prepare(
                effect, effect_json, effect_sha256, owner
            )
        except DurableCapacityExceeded as exc:
            # Capacity is checked only after observing that no row exists and
            # before INSERT/APPLYING/adapter entry.  Preserve that proven
            # known-not-applied result for the request journal.
            raise HelperEffectNotApplied(
                "effect ledger capacity was exhausted before preparation"
            ) from exc
        if completed is not None:
            return completed
        try:
            final_validation_at = self._now()
            self._validate_dispatch(effect, final_validation_at)
        except Exception as exc:
            raise HelperEffectNotApplied(
                "effect was rejected before adapter entry"
            ) from exc
        self._begin_apply(
            effect.idempotency_key,
            effect.request_sha256,
            owner,
            generation,
            final_validation_at,
        )
        adapter_entry_at = final_validation_at
        try:
            # Re-sample after the durable CAS.  The process may have been
            # suspended between the pre-CAS check and this point even when no
            # competing database writer advanced the clock high-water mark.
            adapter_entry_at = self._now()
            self._validate_dispatch(effect, adapter_entry_at)
        except Exception as validation_exc:
            try:
                self._restore_prepared(
                    effect.idempotency_key,
                    effect.request_sha256,
                    owner,
                    generation,
                    adapter_entry_at,
                )
            except Exception as restore_exc:
                raise DurableEffectUnknown(
                    "post-CAS validation failed and known-not-applied state "
                    "could not be restored"
                ) from restore_exc
            raise HelperEffectNotApplied(
                "effect was rejected at adapter entry"
            ) from validation_exc
        try:
            # This is the last in-process current-state check before entering
            # the fixed adapter. Production adapters must additionally enforce
            # their OS capability at the physical-effect boundary.
            result = adapter.apply(effect)
            if not isinstance(result, EffectResult):
                raise TypeError("typed effect adapter returned an invalid result")
        except Exception as exc:
            try:
                self._mark_effect_unknown(
                    effect.idempotency_key, effect.request_sha256, owner, generation
                )
            except Exception as fence_exc:
                raise DurableStoreUnavailable(
                    "effect failed and durable ambiguity fencing also failed"
                ) from fence_exc
            raise DurableEffectUnknown("effect application outcome is unknown") from exc
        completed_at = self._now()
        completion = _completion_from_effect(document, result, completed_at)
        try:
            self._complete_effect(
                effect.idempotency_key,
                effect.request_sha256,
                owner,
                generation,
                completion,
                (EffectLedgerState.APPLYING,),
            )
        except Exception as exc:
            raise DurableEffectUnknown(
                "effect returned but durable completion could not be committed"
            ) from exc
        return completion

    def reconcile(
        self, idempotency_key: str, request_sha256: str
    ) -> ExecutorReconciliation:
        idempotency_key = _digest(idempotency_key, "idempotency_key")
        request_sha256 = _digest(request_sha256, "request_sha256")
        with self._transaction() as connection:
            self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is None:
                return ExecutorReconciliation(ReconciliationState.NOT_FOUND)
            document = self._verify_effect_row(row)
        if document["request_sha256"] != request_sha256:
            raise DurableEffectConflict("idempotency key request digest does not match")
        state = EffectLedgerState(document["state"])
        if state is EffectLedgerState.COMPLETED:
            return ExecutorReconciliation(
                ReconciliationState.COMPLETED,
                _deserialize_completion(document["completion_json"]),
            )
        if state is EffectLedgerState.PREPARED:
            return ExecutorReconciliation(ReconciliationState.NOT_FOUND)

        adapter = self._adapters.get(HelperAction(document["action"]))
        if adapter is None:
            return ExecutorReconciliation(ReconciliationState.UNKNOWN)
        stored = self._stored_effect(document)
        try:
            outcome = adapter.reconcile(stored)
        except Exception:
            outcome = EffectAdapterReconciliation(ReconciliationState.UNKNOWN)
        if not isinstance(outcome, EffectAdapterReconciliation):
            outcome = EffectAdapterReconciliation(ReconciliationState.UNKNOWN)
        if outcome.state is not ReconciliationState.COMPLETED:
            # APPLYING is already a durable no-redispatch fence.  Do not turn
            # a concurrent observer's UNKNOWN result into FAILED_UNKNOWN: the
            # original owner may still be able to commit its completion.
            return ExecutorReconciliation(ReconciliationState.UNKNOWN)

        if outcome.result is None or outcome.executed_at is None:
            return ExecutorReconciliation(ReconciliationState.UNKNOWN)
        effect_body = _parse_canonical_json(document["effect_json"], "effect.effect_json")
        completion = _completion_from_effect(effect_body, outcome.result, outcome.executed_at)
        self._complete_effect(
            idempotency_key,
            request_sha256,
            None,
            int(document["generation"]),
            completion,
            (EffectLedgerState.APPLYING, EffectLedgerState.FAILED_UNKNOWN),
        )
        return ExecutorReconciliation(ReconciliationState.COMPLETED, completion)

    def _reconciliation_fence_unknown(self, document: Mapping[str, object]) -> None:
        with self._transaction() as connection:
            now_text = self._observe_clock(connection, self._now())
            row = connection.execute(
                "SELECT * FROM effect_ledger WHERE idempotency_key=?",
                (document["idempotency_key"],),
            ).fetchone()
            if row is None:
                raise DurableStoreUnavailable("effect disappeared during reconciliation")
            current = self._verify_effect_row(row)
            if EffectLedgerState(current["state"]) is EffectLedgerState.FAILED_UNKNOWN:
                return
            replacement = dict(current)
            replacement.update(
                {
                    "owner_token": None,
                    "state": EffectLedgerState.FAILED_UNKNOWN.value,
                    "updated_at": now_text,
                }
            )
            changed = connection.execute(
                "UPDATE effect_ledger SET state='failed_unknown',owner_token=NULL,updated_at=?,auth_tag=? "
                "WHERE idempotency_key=? AND request_sha256=? AND state='applying' "
                "AND generation=? AND auth_tag=?",
                (
                    now_text,
                    self._tag("effect", replacement),
                    current["idempotency_key"],
                    current["request_sha256"],
                    current["generation"],
                    row["auth_tag"],
                ),
            ).rowcount
            if changed != 1:
                raise DurableStoreUnavailable("reconciliation fencing compare-and-swap failed")


__all__ = [
    "DurableCapacityExceeded",
    "DurableClockRollback",
    "DurableEffectConflict",
    "DurableEffectInProgress",
    "DurableEffectUnknown",
    "DurableEffectsError",
    "DurableStoreBusy",
    "DurableStoreUnavailable",
    "DurableValidationError",
    "EffectAdapterReconciliation",
    "EffectLedgerState",
    "SQLiteIdempotentEffectExecutor",
    "SQLiteRequestJournal",
    "StoredEffect",
    "TypedEffectAdapter",
    "canonical_effect_document",
]
