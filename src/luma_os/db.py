"""SQLite durable control-plane store and schema migrations."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
from typing import Iterator


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


MIGRATION_1 = r"""
CREATE TABLE folder_grants (
    grant_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    root_path TEXT NOT NULL,
    root_device INTEGER NOT NULL,
    root_inode INTEGER NOT NULL,
    display_name TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('read', 'read_write')),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(owner, root_path)
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    filename TEXT NOT NULL,
    media_type TEXT NOT NULL,
    current_version INTEGER NOT NULL CHECK (current_version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE artifact_versions (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    version INTEGER NOT NULL CHECK (version >= 1),
    content_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    storage_path TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (artifact_id, version)
);

CREATE TABLE workflows (
    workflow_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    workflow_type TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    manual_input_json TEXT,
    result_json TEXT,
    error_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner, workflow_type, idempotency_key)
);

CREATE TABLE workflow_steps (
    workflow_id TEXT NOT NULL REFERENCES workflows(workflow_id),
    step_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    state TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    error_json TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workflow_id, step_id)
);

CREATE TABLE effect_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL,
    workflow_id TEXT,
    step_id TEXT,
    idempotency_key TEXT NOT NULL,
    effect_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(owner, idempotency_key)
);

CREATE INDEX idx_artifacts_owner ON artifacts(owner, updated_at DESC);
CREATE INDEX idx_workflows_owner ON workflows(owner, updated_at DESC);
CREATE INDEX idx_receipts_owner ON effect_receipts(owner, sequence DESC);

CREATE TRIGGER effect_receipts_no_update
BEFORE UPDATE ON effect_receipts
BEGIN
    SELECT RAISE(ABORT, 'effect receipts are append-only');
END;

CREATE TRIGGER effect_receipts_no_delete
BEFORE DELETE ON effect_receipts
BEGIN
    SELECT RAISE(ABORT, 'effect receipts are append-only');
END;
"""


MIGRATION_2 = r"""
CREATE TABLE state_maintenance_runs (
    run_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation IN ('object_retention')),
    mode TEXT NOT NULL CHECK (mode IN ('dry_run', 'applied')),
    object_count INTEGER NOT NULL CHECK (object_count >= 0),
    reclaimable_bytes INTEGER NOT NULL CHECK (reclaimable_bytes >= 0),
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_state_maintenance_created ON state_maintenance_runs(created_at DESC);
"""


class LumaStore:
    """Small SQLite store using one connection per transaction."""

    latest_schema_version = 2

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._migrate()
        try:
            self.db_path.chmod(0o600)
        except PermissionError:
            # The containing directory is already private; unusual managed
            # filesystems may not support chmod.
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _migrate(self) -> None:
        with self.transaction() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            rows = connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
            applied = {int(row[0]) for row in rows}
            if any(version > self.latest_schema_version for version in applied):
                raise RuntimeError("Database schema is newer than this Luma OS build")
            if 1 not in applied:
                timestamp_literal = connection.execute("SELECT quote(?)", (utc_now(),)).fetchone()[0]
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + MIGRATION_1
                    + f"\nINSERT INTO schema_migrations(version, applied_at) VALUES (1, {timestamp_literal});\n"
                    + "COMMIT;"
                )
                applied.add(1)
            if 2 not in applied:
                timestamp_literal = connection.execute("SELECT quote(?)", (utc_now(),)).fetchone()[0]
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + MIGRATION_2
                    + f"\nINSERT INTO schema_migrations(version, applied_at) VALUES (2, {timestamp_literal});\n"
                    + "COMMIT;"
                )

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def counts(self) -> dict[str, int]:
        with self.transaction() as connection:
            return {
                "active_grants": int(connection.execute("SELECT COUNT(*) FROM folder_grants WHERE revoked_at IS NULL").fetchone()[0]),
                "artifacts": int(connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]),
                "workflows": int(connection.execute("SELECT COUNT(*) FROM workflows").fetchone()[0]),
                "receipts": int(connection.execute("SELECT COUNT(*) FROM effect_receipts").fetchone()[0]),
            }
