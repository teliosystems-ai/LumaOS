"""Durable, replay-safe invoice-to-report developer workflow."""

from __future__ import annotations

import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePath
import re
import threading
import time
from typing import Any, Iterable
import uuid

from .artifacts import ArtifactService
from .db import LumaStore, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .grants import FolderGrantService


WORKFLOW_TYPE = "invoice_report.v1"
STEP_IDS = ("read_sources", "extract_rows", "aggregate", "publish_csv", "publish_report")
TERMINAL_STATES = {"SUCCEEDED", "FAILED", "CANCELLED"}


# All LumaService instances in one process share these fences.  SQLite guards
# every durable state transition; the fence additionally closes the small gap
# between checking RUNNING and committing an artifact through ArtifactService,
# which owns its own transaction.
_RUNTIME_REGISTRY_LOCK = threading.Lock()
_WORKFLOW_FENCES: dict[tuple[str, str], threading.RLock] = {}
_CANCELLATION_SIGNALS: dict[tuple[str, str], threading.Event] = {}
_ACTIVE_RUNS: set[tuple[str, str]] = set()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class NeedsManualInput(Exception):
    def __init__(self, issues: list[dict[str, str]]) -> None:
        super().__init__("Invoice data needs manual review")
        self.issues = issues


class _WorkflowStopped(Exception):
    """Internal control flow for a workflow stopped by a concurrent cancel."""


class _WorkflowProcessLock:
    """Portable advisory lock used for run leases and durable-effect fences."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    @classmethod
    def acquire(cls, path: Path, *, blocking: bool = False) -> _WorkflowProcessLock | None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stream = path.open("a+b")
        try:
            os.set_inheritable(stream.fileno(), False)
            try:
                path.chmod(0o600)
            except PermissionError:
                pass
            if os.name == "nt":
                import msvcrt

                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"\0")
                    stream.flush()
                while True:
                    stream.seek(0)
                    try:
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, errno.EDEADLK}:
                            raise
                        if not blocking:
                            stream.close()
                            return None
                        time.sleep(0.05)
            else:
                import fcntl

                flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
                try:
                    fcntl.flock(stream.fileno(), flags)
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                        raise
                    stream.close()
                    return None
        except BaseException:
            if not stream.closed:
                stream.close()
            raise
        return cls(stream)

    def release(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


class InvoiceWorkflowService:
    """Service layer suitable for CLI or HTTP adapters.

    Model output is not used for totals or completion. Parsing, arithmetic,
    artifact commits, and state transitions remain deterministic.
    """

    def __init__(self, store: LumaStore, grants: FolderGrantService, artifacts: ArtifactService) -> None:
        self.store = store
        self.grants = grants
        self.artifacts = artifacts
        self._recover_interrupted()

    def _recover_interrupted(self) -> None:
        """Recover RUNNING work only when no process still owns its execution lock."""

        with self.store.transaction() as connection:
            workflow_ids = [
                str(row[0])
                for row in connection.execute("SELECT workflow_id FROM workflows WHERE state='RUNNING'").fetchall()
            ]
        for workflow_id in workflow_ids:
            key = self._runtime_key(workflow_id)
            with self._fence(workflow_id):
                with _RUNTIME_REGISTRY_LOCK:
                    if key in _ACTIVE_RUNS:
                        continue
                process_lock = self._process_lock(workflow_id)
                if process_lock is None:
                    continue
                try:
                    # The state is rechecked by the compare-and-set after the
                    # process lock proves that no conforming runner is live.
                    self._recover_workflow(workflow_id)
                finally:
                    process_lock.release()

    def submit(
        self,
        owner: str,
        *,
        grant_id: str | None = None,
        files: list[str] | None = None,
        source_text: str | None = None,
        source_format: str = "text",
        source_name: str = "pasted-invoices.txt",
        currency: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        owner = owner.strip()
        if not owner:
            raise ValidationError("Owner is required")
        source_files = files or []
        if len(source_files) > 100:
            raise ValidationError("A workflow can include at most 100 files")
        if source_files and not grant_id:
            raise ValidationError("grant_id is required when files are provided")
        if not source_files and source_text is None:
            raise ValidationError("Provide enrolled files or pasted invoice text")
        if source_text is not None and not source_text.strip():
            raise ValidationError("Pasted invoice text cannot be empty")
        if source_text is not None and len(source_text.encode("utf-8")) > self.grants.max_source_bytes:
            raise ValidationError("Pasted invoice text exceeds the configured size limit")
        if source_format not in {"text", "csv"}:
            raise ValidationError("source_format must be 'text' or 'csv'")
        if "/" in source_name or "\\" in source_name or source_name in {"", ".", ".."}:
            raise ValidationError("source_name must be a simple filename")
        if currency is not None:
            currency = self._currency(currency)

        normalized_files: list[str] = []
        if grant_id:
            self.grants.get(owner, grant_id)
        for relative_path in source_files:
            inspected = self.grants.inspect_file(owner, str(grant_id), relative_path)
            normalized_files.append(str(inspected["relative_path"]))

        request: dict[str, Any] = {
            "grant_id": grant_id,
            "files": normalized_files,
            "currency": currency,
        }
        if source_text is not None:
            request["inline_source"] = {
                "text": source_text,
                "format": source_format,
                "name": source_name,
                "sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            }
        request_json = _json(request)
        request_hash = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        key = (idempotency_key or str(uuid.uuid4())).strip()
        if not key or len(key) > 250:
            raise ValidationError("Idempotency key must be between 1 and 250 characters")

        now = utc_now()
        with self.store.transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT workflow_id,request_hash FROM workflows WHERE owner=? AND workflow_type=? AND idempotency_key=?",
                (owner, WORKFLOW_TYPE, key),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise ConflictError("Idempotency key was already used with a different workflow request")
                workflow_id = existing["workflow_id"]
            else:
                workflow_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO workflows(workflow_id,owner,workflow_type,idempotency_key,request_hash,request_json,state,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,'VALIDATED',?,?)",
                    (workflow_id, owner, WORKFLOW_TYPE, key, request_hash, request_json, now, now),
                )
                connection.executemany(
                    "INSERT INTO workflow_steps(workflow_id,step_id,position,state,updated_at) VALUES (?,?,?,'PENDING',?)",
                    [(workflow_id, step, position, now) for position, step in enumerate(STEP_IDS)],
                )
        return self.get(owner, workflow_id)

    def run(self, owner: str, workflow_id: str) -> dict[str, Any]:
        key = self._runtime_key(workflow_id)
        cancellation = self._cancellation_signal(workflow_id)
        process_lock: _WorkflowProcessLock | None = None
        with self._fence(workflow_id):
            workflow = self.get(owner, workflow_id)
            if workflow["state"] == "SUCCEEDED":
                return workflow
            if workflow["state"] == "CANCELLED":
                raise ConflictError("Cancelled workflow cannot be run")
            if workflow["state"] == "WAITING_USER" and workflow.get("manual_input") is None:
                return workflow
            if cancellation.is_set():
                self._mark_cancelled(owner, workflow_id)
                raise ConflictError("Cancelled workflow cannot be run")
            process_lock = self._process_lock(workflow_id)
            if process_lock is None:
                current = self.get(owner, workflow_id)
                if current["state"] == "SUCCEEDED":
                    return current
                if current["state"] == "CANCELLED":
                    raise ConflictError("Cancelled workflow cannot be run")
                if current["state"] == "WAITING_USER" and current.get("manual_input") is None:
                    return current
                raise ConflictError("Workflow is already running")
            try:
                with _RUNTIME_REGISTRY_LOCK:
                    if key in _ACTIVE_RUNS:
                        raise ConflictError("Workflow is already running")
                if workflow["state"] == "RUNNING":
                    self._recover_workflow(workflow_id)
                claim = self._claim_run(owner, workflow_id)
                if claim != "CLAIMED":
                    if claim == "CANCELLED":
                        raise ConflictError("Cancelled workflow cannot be run")
                    if claim == "RUNNING":
                        raise ConflictError("Workflow is already running")
                    current = self.get(owner, workflow_id)
                    process_lock.release()
                    process_lock = None
                    return current
                with _RUNTIME_REGISTRY_LOCK:
                    _ACTIVE_RUNS.add(key)
            except BaseException:
                process_lock.release()
                process_lock = None
                raise

        try:
            workflow = self.get(owner, workflow_id)
            request = workflow["request"]
            manual = workflow.get("manual_input")
            self._step(workflow_id, "read_sources", "RUNNING", increment=True)
            sources = self._read_sources(owner, request)
            self._step(workflow_id, "read_sources", "SUCCEEDED")

            self._step(workflow_id, "extract_rows", "RUNNING", increment=True)
            if manual is not None:
                rows = [self._normalize_manual_row(row, index) for index, row in enumerate(manual["rows"])]
            else:
                rows = self._extract_sources(sources, requested_currency=request.get("currency"))
            self._step(workflow_id, "extract_rows", "SUCCEEDED")

            self._step(workflow_id, "aggregate", "RUNNING", increment=True)
            aggregates = self._aggregate(rows)
            self._step(workflow_id, "aggregate", "SUCCEEDED")

            provenance = {
                "workflow_id": workflow_id,
                "workflow_type": WORKFLOW_TYPE,
                "source_refs": [source["reference"] for source in sources],
                "row_count": len(rows),
                "manual_input": manual is not None,
            }
            with self._fence(workflow_id):
                effect_lock = self._effect_lock(workflow_id)
                try:
                    self._require_running(owner, workflow_id)
                    self._step(workflow_id, "publish_csv", "RUNNING", increment=True)
                    csv_artifact = self.artifacts.create_text(
                        owner,
                        self._report_csv(aggregates),
                        filename="invoice-summary.csv",
                        media_type="text/csv; charset=utf-8",
                        provenance=provenance,
                        idempotency_key=f"workflow:{workflow_id}:invoice-summary-csv:v1",
                        workflow_id=workflow_id,
                        step_id="publish_csv",
                    )
                    self._step(workflow_id, "publish_csv", "SUCCEEDED")
                    if cancellation.is_set():
                        self._mark_cancelled(owner, workflow_id)
                        raise _WorkflowStopped
                finally:
                    effect_lock.release()

            # The final artifact and SUCCEEDED compare-and-set share one fence.
            # Cancellation either wins before this boundary, or observes a
            # completed workflow; it can never change CANCELLED back to success.
            with self._fence(workflow_id):
                effect_lock = self._effect_lock(workflow_id)
                try:
                    self._require_running(owner, workflow_id)
                    self._step(workflow_id, "publish_report", "RUNNING", increment=True)
                    report_artifact = self.artifacts.create_text(
                        owner,
                        self._report_markdown(rows, aggregates),
                        filename="invoice-report.md",
                        media_type="text/markdown; charset=utf-8",
                        provenance=provenance,
                        idempotency_key=f"workflow:{workflow_id}:invoice-report-md:v1",
                        workflow_id=workflow_id,
                        step_id="publish_report",
                    )
                    self._step(workflow_id, "publish_report", "SUCCEEDED")
                    result = {
                        "row_count": len(rows),
                        "summary": aggregates,
                        "artifacts": [csv_artifact, report_artifact],
                    }
                    with self.store.transaction(write=True) as connection:
                        changed = connection.execute(
                            "UPDATE workflows SET state='SUCCEEDED',result_json=?,error_json=NULL,updated_at=? "
                            "WHERE workflow_id=? AND owner=? AND state='RUNNING'",
                            (_json(result), utc_now(), workflow_id, owner),
                        ).rowcount
                    if not changed:
                        raise _WorkflowStopped
                    cancellation.clear()
                    return self.get(owner, workflow_id)
                finally:
                    effect_lock.release()
        except _WorkflowStopped:
            with self._fence(workflow_id):
                if cancellation.is_set():
                    self._mark_cancelled(owner, workflow_id)
                return self.get(owner, workflow_id)
        except NeedsManualInput as exc:
            fallback = {
                "message": "Some invoice data could not be parsed deterministically. Review and submit explicit rows.",
                "issues": exc.issues,
                "required_fields": ["date", "amount"],
                "optional_fields": ["currency", "vendor", "source"],
            }
            try:
                with self._fence(workflow_id):
                    if cancellation.is_set():
                        self._mark_cancelled(owner, workflow_id)
                        return self.get(owner, workflow_id)
                    self._require_running(owner, workflow_id)
                    self._step(workflow_id, "extract_rows", "WAITING_USER", error={"issues": exc.issues})
                    with self.store.transaction(write=True) as connection:
                        changed = connection.execute(
                            "UPDATE workflows SET state='WAITING_USER',result_json=?,error_json=?,updated_at=? "
                            "WHERE workflow_id=? AND owner=? AND state='RUNNING'",
                            (
                                _json({"manual_fallback": fallback}),
                                _json({"code": "manual_input_required"}),
                                utc_now(),
                                workflow_id,
                                owner,
                            ),
                        ).rowcount
                    if not changed:
                        return self.get(owner, workflow_id)
                    return self.get(owner, workflow_id)
            except _WorkflowStopped:
                if cancellation.is_set():
                    self._mark_cancelled(owner, workflow_id)
                return self.get(owner, workflow_id)
        except Exception as exc:
            error = {"code": "workflow_failed", "message": str(exc)}
            with self._fence(workflow_id):
                if cancellation.is_set():
                    self._mark_cancelled(owner, workflow_id)
                    return self.get(owner, workflow_id)
                with self.store.transaction(write=True) as connection:
                    changed = connection.execute(
                        "UPDATE workflows SET state='FAILED',error_json=?,updated_at=? "
                        "WHERE workflow_id=? AND owner=? AND state='RUNNING'",
                        (_json(error), utc_now(), workflow_id, owner),
                    ).rowcount
                    if changed:
                        connection.execute(
                            "UPDATE workflow_steps SET state='FAILED',error_json=?,updated_at=? "
                            "WHERE workflow_id=? AND state='RUNNING'",
                            (_json(error), utc_now(), workflow_id),
                        )
                if not changed:
                    return self.get(owner, workflow_id)
            raise
        finally:
            with _RUNTIME_REGISTRY_LOCK:
                _ACTIVE_RUNS.discard(key)
            if process_lock is not None:
                process_lock.release()

    def _runtime_key(self, workflow_id: str) -> tuple[str, str]:
        return (str(self.store.db_path.resolve()), workflow_id)

    def _fence(self, workflow_id: str) -> threading.RLock:
        key = self._runtime_key(workflow_id)
        with _RUNTIME_REGISTRY_LOCK:
            return _WORKFLOW_FENCES.setdefault(key, threading.RLock())

    def _cancellation_signal(self, workflow_id: str) -> threading.Event:
        key = self._runtime_key(workflow_id)
        with _RUNTIME_REGISTRY_LOCK:
            return _CANCELLATION_SIGNALS.setdefault(key, threading.Event())

    def _process_lock(self, workflow_id: str, *, blocking: bool = False) -> _WorkflowProcessLock | None:
        digest = self._lock_digest(workflow_id)
        path = self.store.db_path.parent / "workflow-locks" / f"{digest}.lock"
        return _WorkflowProcessLock.acquire(path, blocking=blocking)

    def _effect_lock(self, workflow_id: str) -> _WorkflowProcessLock:
        digest = self._lock_digest(workflow_id)
        path = self.store.db_path.parent / "workflow-effect-locks" / f"{digest}.lock"
        process_lock = _WorkflowProcessLock.acquire(path, blocking=True)
        if process_lock is None:  # pragma: no cover - blocking acquisition either succeeds or raises
            raise RuntimeError("Could not acquire the workflow effect lock")
        return process_lock

    def _lock_digest(self, workflow_id: str) -> str:
        identity = f"{self.store.db_path.resolve()}\0{workflow_id}".encode("utf-8")
        return hashlib.sha256(identity).hexdigest()

    def _recover_workflow(self, workflow_id: str) -> bool:
        recovered = _json({"code": "interrupted", "message": "Previous execution stopped and is safe to retry."})
        now = utc_now()
        with self.store.transaction(write=True) as connection:
            changed = connection.execute(
                "UPDATE workflows SET state='VALIDATED',error_json=?,updated_at=? "
                "WHERE workflow_id=? AND state='RUNNING'",
                (recovered, now, workflow_id),
            ).rowcount
            if changed:
                connection.execute(
                    "UPDATE workflow_steps SET state='PENDING',error_json=?,updated_at=? "
                    "WHERE workflow_id=? AND state='RUNNING'",
                    (recovered, now, workflow_id),
                )
        return bool(changed)

    def _claim_run(self, owner: str, workflow_id: str) -> str:
        """Atomically claim an executable workflow and return its prior state."""

        with self.store.transaction(write=True) as connection:
            row = connection.execute(
                "SELECT state,manual_input_json FROM workflows WHERE workflow_id=? AND owner=?",
                (workflow_id, owner),
            ).fetchone()
            if row is None:
                raise NotFoundError("Workflow was not found")
            state = str(row["state"])
            if state in {"SUCCEEDED", "RUNNING", "CANCELLED"}:
                return state
            if state == "WAITING_USER" and row["manual_input_json"] is None:
                return state
            if state not in {"VALIDATED", "FAILED", "WAITING_USER"}:
                raise ConflictError("Workflow cannot run in its current state", details={"state": state})
            changed = connection.execute(
                "UPDATE workflows SET state='RUNNING',attempt=attempt+1,error_json=NULL,updated_at=? "
                "WHERE workflow_id=? AND owner=? AND state=?",
                (utc_now(), workflow_id, owner, state),
            ).rowcount
            return "CLAIMED" if changed else "CHANGED"

    def _mark_cancelled(self, owner: str, workflow_id: str) -> None:
        """Compare-and-set cancellation without overwriting a completed run."""

        now = utc_now()
        with self.store.transaction(write=True) as connection:
            row = connection.execute(
                "SELECT state FROM workflows WHERE workflow_id=? AND owner=?",
                (workflow_id, owner),
            ).fetchone()
            if row is None:
                raise NotFoundError("Workflow was not found")
            state = str(row["state"])
            if state == "SUCCEEDED":
                raise ConflictError("Completed workflow cannot be cancelled")
            if state == "CANCELLED":
                return
            changed = connection.execute(
                "UPDATE workflows SET state='CANCELLED',updated_at=? "
                "WHERE workflow_id=? AND owner=? AND state=?",
                (now, workflow_id, owner, state),
            ).rowcount
            if not changed:
                raise ConflictError("Workflow changed while cancellation was being applied")
            connection.execute(
                "UPDATE workflow_steps SET state='CANCELLED',updated_at=? "
                "WHERE workflow_id=? AND state IN ('PENDING','RUNNING','WAITING_USER')",
                (now, workflow_id),
            )

    def _require_running(self, owner: str, workflow_id: str) -> None:
        if self._cancellation_signal(workflow_id).is_set():
            self._mark_cancelled(owner, workflow_id)
            raise _WorkflowStopped
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT state FROM workflows WHERE workflow_id=? AND owner=?",
                (workflow_id, owner),
            ).fetchone()
        if row is None:
            raise NotFoundError("Workflow was not found")
        if row["state"] != "RUNNING":
            raise _WorkflowStopped

    def provide_manual_rows(self, owner: str, workflow_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows or len(rows) > 10_000:
            raise ValidationError("Provide between 1 and 10,000 invoice rows")
        normalized = [self._normalize_manual_row(row, index) for index, row in enumerate(rows)]
        with self._fence(workflow_id):
            with self.store.transaction(write=True) as connection:
                row = connection.execute(
                    "SELECT state FROM workflows WHERE workflow_id=? AND owner=?",
                    (workflow_id, owner),
                ).fetchone()
                if row is None:
                    raise NotFoundError("Workflow was not found")
                if row["state"] not in {"WAITING_USER", "FAILED", "VALIDATED"}:
                    raise ConflictError("Manual rows can only be supplied before a workflow succeeds")
                durable_effect = connection.execute(
                    "SELECT 1 FROM effect_receipts WHERE workflow_id=? LIMIT 1",
                    (workflow_id,),
                ).fetchone()
                if durable_effect is not None:
                    raise ConflictError(
                        "Manual rows cannot replace inputs after a durable workflow effect; create a new workflow"
                    )
                changed = connection.execute(
                    "UPDATE workflows SET manual_input_json=?,state='VALIDATED',result_json=NULL,error_json=NULL,updated_at=? "
                    "WHERE workflow_id=? AND owner=? AND state=?",
                    (_json({"rows": normalized}), utc_now(), workflow_id, owner, row["state"]),
                ).rowcount
                if not changed:
                    raise ConflictError("Workflow changed while manual rows were being supplied")
                connection.execute(
                    "UPDATE workflow_steps SET state='PENDING',error_json=NULL,updated_at=? "
                    "WHERE workflow_id=? AND step_id IN ('extract_rows','aggregate','publish_csv','publish_report')",
                    (utc_now(), workflow_id),
                )
        return self.get(owner, workflow_id)

    def cancel(self, owner: str, workflow_id: str) -> dict[str, Any]:
        # Authenticate ownership before publishing a process-wide signal.  The
        # signal is intentionally raised before taking the effect fence so an
        # in-flight runner can observe it at the next durable boundary.
        self.get(owner, workflow_id)
        cancellation = self._cancellation_signal(workflow_id)
        cancellation.set()
        try:
            with self._fence(workflow_id):
                effect_lock = self._effect_lock(workflow_id)
                try:
                    self._mark_cancelled(owner, workflow_id)
                    return self.get(owner, workflow_id)
                finally:
                    effect_lock.release()
        except BaseException:
            cancellation.clear()
            raise

    def get(self, owner: str, workflow_id: str) -> dict[str, Any]:
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM workflows WHERE workflow_id=? AND owner=?", (workflow_id, owner)
            ).fetchone()
            if row is None:
                raise NotFoundError("Workflow was not found")
            steps = connection.execute(
                "SELECT * FROM workflow_steps WHERE workflow_id=? ORDER BY position", (workflow_id,)
            ).fetchall()
        return self._workflow_row(row, steps)

    def list(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM workflows WHERE owner=? ORDER BY updated_at DESC LIMIT ?", (owner, limit)
            ).fetchall()
        return [self._workflow_row(row, []) for row in rows]

    def _read_sources(self, owner: str, request: dict[str, Any]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        grant_id = request.get("grant_id")
        for path in request.get("files", []):
            safe_file = self.grants.read_file(owner, grant_id, path)
            sources.append(
                {
                    "name": PurePath(path).name,
                    "format": "csv" if path.lower().endswith(".csv") else "text",
                    "content": safe_file.content,
                    "reference": {
                        "grant_id": grant_id,
                        "relative_path": path,
                        "sha256": hashlib.sha256(safe_file.content).hexdigest(),
                        "size_bytes": safe_file.size_bytes,
                    },
                }
            )
        inline = request.get("inline_source")
        if inline:
            content = inline["text"].encode("utf-8")
            sources.append(
                {
                    "name": inline["name"],
                    "format": inline["format"],
                    "content": content,
                    "reference": {
                        "inline_name": inline["name"],
                        "sha256": inline["sha256"],
                        "size_bytes": len(content),
                    },
                }
            )
        return sources

    def _extract_sources(self, sources: list[dict[str, Any]], *, requested_currency: str | None) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        issues: list[dict[str, str]] = []
        for source in sources:
            try:
                text = source["content"].decode("utf-8-sig")
                if source["format"] == "csv":
                    rows.extend(self._parse_csv(text, source["name"], requested_currency))
                else:
                    rows.append(self._parse_text(text, source["name"], requested_currency))
            except (UnicodeDecodeError, ValidationError) as exc:
                issues.append({"source": source["name"], "message": str(exc)})
        if issues:
            raise NeedsManualInput(issues)
        if not rows:
            raise NeedsManualInput([{"source": "input", "message": "No invoice rows were found"}])
        return rows

    def _parse_csv(self, text: str, source: str, requested_currency: str | None) -> list[dict[str, str]]:
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise ValidationError("CSV is missing a header row")
        header_map = {self._header(name): name for name in reader.fieldnames if name is not None}
        date_field = self._pick(header_map, "invoice_date", "billing_date", "date", "month")
        amount_field = self._pick(header_map, "invoice_total", "total_amount", "amount", "total", "cost")
        currency_field = self._pick(header_map, "currency", "currency_code", required=False)
        vendor_field = self._pick(header_map, "vendor", "supplier", "merchant", "company", required=False)
        parsed: list[dict[str, str]] = []
        for row_number, raw in enumerate(reader, start=2):
            if not any(str(value or "").strip() for value in raw.values()):
                continue
            try:
                date_value = self._date(str(raw.get(date_field, "")))
                amount_value, inferred = self._amount(str(raw.get(amount_field, "")))
                detected_currency = (
                    self._currency(str(raw.get(currency_field, "")))
                    if currency_field and str(raw.get(currency_field, "")).strip()
                    else inferred
                )
                if requested_currency and detected_currency and requested_currency != detected_currency:
                    raise ValidationError("Currency conversion is not supported; source and requested currencies differ")
                currency_value = detected_currency or requested_currency or "USD"
            except ValidationError as exc:
                raise ValidationError(f"CSV row {row_number}: {exc}") from exc
            parsed.append(
                {
                    "date": date_value,
                    "month": date_value[:7],
                    "amount": format(amount_value, "f"),
                    "currency": currency_value,
                    "vendor": str(raw.get(vendor_field, "")).strip() if vendor_field else "",
                    "source": f"{source}:row-{row_number}",
                }
            )
        if not parsed:
            raise ValidationError("CSV contains no invoice records")
        return parsed

    def _parse_text(self, text: str, source: str, requested_currency: str | None) -> dict[str, str]:
        fields: dict[str, str] = {}
        aliases = {
            "date": r"(?:invoice\s+date|billing\s+date|date|month)",
            "amount": r"(?:invoice\s+total|total\s+amount|amount|total|cost)",
            "currency": r"(?:currency|currency\s+code)",
            "vendor": r"(?:vendor|supplier|merchant|company)",
        }
        for field, alias in aliases.items():
            match = re.search(rf"(?im)^\s*{alias}\s*[:=]\s*(.+?)\s*$", text)
            if match:
                fields[field] = match.group(1).strip()
        if "date" not in fields or "amount" not in fields:
            raise ValidationError("Text invoice requires labelled Date and Amount fields")
        date_value = self._date(fields["date"])
        amount, inferred = self._amount(fields["amount"])
        detected_currency = self._currency(fields["currency"]) if fields.get("currency") else inferred
        if requested_currency and detected_currency and requested_currency != detected_currency:
            raise ValidationError("Currency conversion is not supported; source and requested currencies differ")
        currency = detected_currency or requested_currency or "USD"
        return {
            "date": date_value,
            "month": date_value[:7],
            "amount": format(amount, "f"),
            "currency": currency,
            "vendor": fields.get("vendor", ""),
            "source": source,
        }

    def _normalize_manual_row(self, row: dict[str, Any], index: int) -> dict[str, str]:
        if not isinstance(row, dict):
            raise ValidationError(f"Manual row {index + 1} must be an object")
        date_value = self._date(str(row.get("date", "")))
        amount, inferred = self._amount(str(row.get("amount", "")))
        currency = self._currency(str(row.get("currency") or inferred or "USD"))
        return {
            "date": date_value,
            "month": date_value[:7],
            "amount": format(amount, "f"),
            "currency": currency,
            "vendor": str(row.get("vendor", "")).strip()[:300],
            "source": str(row.get("source", f"manual-row-{index + 1}")).strip()[:500],
        }

    @staticmethod
    def _date(raw: str) -> str:
        value = raw.strip()
        formats = ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%B %Y", "%b %Y")
        for date_format in formats:
            try:
                parsed = datetime.strptime(value, date_format)
                return parsed.strftime("%Y-%m-%d") if "%d" in date_format else parsed.strftime("%Y-%m-01")
            except ValueError:
                pass
        numeric = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", value)
        if numeric:
            first, second = int(numeric.group(1)), int(numeric.group(2))
            if first <= 12 and second <= 12:
                raise ValidationError("Ambiguous numeric date; use YYYY-MM-DD")
            date_format = "%d/%m/%Y" if first > 12 else "%m/%d/%Y"
            try:
                return datetime.strptime(value, date_format).strftime("%Y-%m-%d")
            except ValueError:
                pass
        raise ValidationError("Date must be an unambiguous date such as YYYY-MM-DD")

    @staticmethod
    def _amount(raw: str) -> tuple[Decimal, str | None]:
        value = raw.strip()
        currency_codes = {code.upper() for code in re.findall(r"(?i)\b(USD|EUR|GBP|CAD|AUD|JPY|CHF)\b", value)}
        if len(currency_codes) > 1:
            raise ValidationError("Amount contains multiple currency codes")
        inferred = next(iter(currency_codes)) if currency_codes else (
            "USD" if "$" in value else "EUR" if "€" in value else "GBP" if "£" in value else None
        )
        value = re.sub(r"(?i)\b(?:USD|EUR|GBP|CAD|AUD|JPY|CHF)\b", "", value)
        value = value.replace("$", "").replace("€", "").replace("£", "").replace(" ", "")
        negative = value.startswith("(") and value.endswith(")")
        value = value.strip("()")
        if "," in value and "." in value:
            if value.rfind(",") > value.rfind("."):
                value = value.replace(".", "").replace(",", ".")
            else:
                value = value.replace(",", "")
        elif "," in value:
            suffix = value.rsplit(",", 1)[1]
            value = value.replace(",", ".") if len(suffix) in {1, 2} else value.replace(",", "")
        if negative:
            value = "-" + value
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise ValidationError("Amount is not a valid decimal number") from exc
        if not amount.is_finite():
            raise ValidationError("Amount must be finite")
        return amount.quantize(Decimal("0.01")), inferred

    @staticmethod
    def _currency(raw: str) -> str:
        value = raw.strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", value):
            raise ValidationError("Currency must be a three-letter code")
        return value

    @staticmethod
    def _header(raw: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", raw.strip().lower()).strip("_")

    @staticmethod
    def _pick(headers: dict[str, str], *names: str, required: bool = True) -> str | None:
        for name in names:
            if name in headers:
                return headers[name]
        if required:
            raise ValidationError(f"CSV requires one of these columns: {', '.join(names)}")
        return None

    @staticmethod
    def _aggregate(rows: Iterable[dict[str, str]]) -> list[dict[str, Any]]:
        values: dict[tuple[str, str], tuple[int, Decimal]] = {}
        for row in rows:
            key = (row["month"], row["currency"])
            count, total = values.get(key, (0, Decimal("0")))
            values[key] = (count + 1, total + Decimal(row["amount"]))
        return [
            {"month": month, "currency": currency, "invoice_count": count, "total": format(total, ".2f")}
            for (month, currency), (count, total) in sorted(values.items())
        ]

    @staticmethod
    def _report_csv(aggregates: list[dict[str, Any]]) -> str:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["month", "currency", "invoice_count", "total"])
        for row in aggregates:
            writer.writerow([row["month"], row["currency"], row["invoice_count"], row["total"]])
        return stream.getvalue()

    @staticmethod
    def _report_markdown(rows: list[dict[str, str]], aggregates: list[dict[str, Any]]) -> str:
        lines = [
            "# Invoice report",
            "",
            f"Processed {len(rows)} invoice record{'s' if len(rows) != 1 else ''}.",
            "",
            "| Month | Currency | Invoices | Total |",
            "|---|---:|---:|---:|",
        ]
        lines.extend(
            f"| {row['month']} | {row['currency']} | {row['invoice_count']} | {row['total']} |"
            for row in aggregates
        )
        lines.extend(["", "## Sources", ""])
        for row in rows:
            vendor = f" — {row['vendor']}" if row["vendor"] else ""
            lines.append(f"- {row['date']}: {row['currency']} {row['amount']}{vendor} ({row['source']})")
        lines.append("")
        return "\n".join(lines)

    def _step(
        self,
        workflow_id: str,
        step_id: str,
        state: str,
        *,
        increment: bool = False,
        error: dict[str, Any] | None = None,
    ) -> None:
        expected_states = {
            "RUNNING": ("PENDING", "SUCCEEDED", "FAILED", "WAITING_USER"),
            "SUCCEEDED": ("RUNNING",),
            "WAITING_USER": ("RUNNING",),
            "FAILED": ("RUNNING",),
        }
        allowed = expected_states.get(state)
        if allowed is None:
            raise RuntimeError(f"Unsupported workflow step transition target: {state}")
        placeholders = ",".join("?" for _ in allowed)
        with self.store.transaction(write=True) as connection:
            changed = connection.execute(
                "UPDATE workflow_steps SET state=?,attempt=attempt+?,error_json=?,updated_at=? "
                f"WHERE workflow_id=? AND step_id=? AND state IN ({placeholders}) "
                "AND EXISTS (SELECT 1 FROM workflows WHERE workflow_id=? AND state='RUNNING')",
                (
                    state,
                    1 if increment else 0,
                    _json(error) if error else None,
                    utc_now(),
                    workflow_id,
                    step_id,
                    *allowed,
                    workflow_id,
                ),
            ).rowcount
            if changed:
                return
            workflow = connection.execute(
                "SELECT state FROM workflows WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()
            if workflow is not None and workflow["state"] != "RUNNING":
                raise _WorkflowStopped
            raise ConflictError(
                "Workflow step changed while execution was in progress",
                details={"step_id": step_id, "target_state": state},
            )

    @staticmethod
    def _workflow_row(row: object, steps: Iterable[object]) -> dict[str, Any]:
        return {
            "workflow_id": row["workflow_id"],  # type: ignore[index]
            "id": row["workflow_id"],  # type: ignore[index]
            "owner": row["owner"],  # type: ignore[index]
            "type": row["workflow_type"],  # type: ignore[index]
            "kind": row["workflow_type"],  # type: ignore[index]
            "idempotency_key": row["idempotency_key"],  # type: ignore[index]
            "state": row["state"],  # type: ignore[index]
            "attempt": int(row["attempt"]),  # type: ignore[index]
            "request": json.loads(row["request_json"]),  # type: ignore[index]
            "manual_input": json.loads(row["manual_input_json"]) if row["manual_input_json"] else None,  # type: ignore[index]
            "result": json.loads(row["result_json"]) if row["result_json"] else None,  # type: ignore[index]
            "error": json.loads(row["error_json"]) if row["error_json"] else None,  # type: ignore[index]
            "created_at": row["created_at"],  # type: ignore[index]
            "updated_at": row["updated_at"],  # type: ignore[index]
            "steps": [
                {
                    "step_id": step["step_id"],
                    "position": int(step["position"]),
                    "state": step["state"],
                    "attempt": int(step["attempt"]),
                    "error": json.loads(step["error_json"]) if step["error_json"] else None,
                    "updated_at": step["updated_at"],
                }
                for step in steps
            ],
        }
